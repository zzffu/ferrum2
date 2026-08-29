import unittest
from pathlib import Path

from tests.performance_rule._fixture import SCENARIO_SUITES, report
from tools.performance_rule.pairing import (
    calibrated_limits,
    calibration_ceiling_limits,
    pair_execution_order,
    summarize,
)
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CANDIDATE_WIN,
    REGRESSION,
    WITHIN_CALIBRATED_BAND,
    ControlError,
)


class PairingAndPolicyTests(unittest.TestCase):
    def test_pair_order_alternates_roles(self):
        parent = Path("parent")
        candidate = Path("candidate")
        self.assertEqual(
            [role for role, _ in pair_execution_order(0, parent, candidate)],
            ["parent", "candidate"],
        )
        self.assertEqual(
            [role for role, _ in pair_execution_order(1, parent, candidate)],
            ["candidate", "parent"],
        )

    def test_current_aa_observation_never_self_approves_calibration(self):
        pairs = [
            {
                "parent": report("same", value=100),
                "candidate": report("same", value=104),
            }
            for _ in range(6)
        ]
        rows = summarize(
            SCENARIO_SUITES,
            pairs,
            True,
            calibration_ceiling_limits(),
        )
        limits = calibrated_limits(rows)
        policy = threshold_policy(rows, limits, None, None, reviewed=False)
        self.assertEqual(policy["status"], CALIBRATION_REQUIRED)
        self.assertFalse(policy["reviewed"])
        self.assertFalse(policy["enforced"])
        self.assertFalse(policy["gate_passed"])

    def test_reviewed_policy_distinguishes_band_and_regression(self):
        for candidate_value, expected in (
            (84, CANDIDATE_WIN),
            (110, WITHIN_CALIBRATED_BAND),
            (116, REGRESSION),
        ):
            with self.subTest(candidate_value=candidate_value):
                pairs = [
                    {
                        "parent": report("p", value=100),
                        "candidate": report("c", value=candidate_value),
                    }
                    for _ in range(6)
                ]
                rows = summarize(
                    SCENARIO_SUITES,
                    pairs,
                    False,
                    {"match_set": 10.0, "snapshot_registry": 10.0},
                )
                policy = threshold_policy(
                    rows,
                    {"match_set": 10.0, "snapshot_registry": 10.0},
                    "reviewed.json",
                    "b" * 64,
                    reviewed=True,
                )
                self.assertEqual(policy["status"], expected)

    def test_snapshot_registry_aa_noise_has_an_independent_limit(self):
        parent_values = {identifier: 100 for identifier in SCENARIO_SUITES}
        candidate_values = dict(parent_values)
        candidate_values["match_set/one"] = 104
        for identifier in candidate_values:
            if identifier.startswith("snapshot_registry/"):
                candidate_values[identifier] = 108
        pairs = [
            {
                "parent": report("same", value=parent_values),
                "candidate": report("same", value=candidate_values),
            }
            for _ in range(6)
        ]
        rows = summarize(
            SCENARIO_SUITES,
            pairs,
            True,
            calibration_ceiling_limits(),
        )
        self.assertEqual(
            calibrated_limits(rows),
            {"match_set": 5.0, "snapshot_registry": 8.0},
        )

    def test_each_calibrated_suite_rejects_noise_above_the_ceiling(self):
        for noisy_suite in ("match_set", "snapshot_registry"):
            with self.subTest(noisy_suite=noisy_suite):
                parent_values = {identifier: 100 for identifier in SCENARIO_SUITES}
                candidate_values = {identifier: 104 for identifier in SCENARIO_SUITES}
                for identifier, suite in SCENARIO_SUITES.items():
                    if suite == noisy_suite:
                        candidate_values[identifier] = 111
                pairs = [
                    {
                        "parent": report("same", value=parent_values),
                        "candidate": report("same", value=candidate_values),
                    }
                    for _ in range(6)
                ]
                rows = summarize(
                    SCENARIO_SUITES,
                    pairs,
                    True,
                    calibration_ceiling_limits(),
                )
                with self.assertRaisesRegex(ControlError, noisy_suite):
                    calibrated_limits(rows)

    def test_snapshot_registry_gate_requires_atomic_candidate_feature(self):
        parent_values = {identifier: 100 for identifier in SCENARIO_SUITES}
        candidate_values = dict(parent_values)
        for identifier in candidate_values:
            if identifier.startswith("snapshot_registry/"):
                candidate_values[identifier] = 130
        limits = {"match_set": 5.0, "snapshot_registry": 8.0}

        for features, expected_status, expected_applicable in (
            (("candidate-domain-suffix-trie",), WITHIN_CALIBRATED_BAND, False),
            (("candidate-cidr-radix",), WITHIN_CALIBRATED_BAND, False),
            (("candidate-atomic-snapshot",), REGRESSION, True),
            (
                (
                    "candidate-atomic-snapshot",
                    "candidate-cidr-radix",
                    "candidate-domain-suffix-trie",
                ),
                REGRESSION,
                True,
            ),
        ):
            with self.subTest(features=features):
                pairs = [
                    {
                        "parent": report("parent", value=parent_values),
                        "candidate": report(
                            "candidate",
                            value=candidate_values,
                            enabled_features=features,
                        ),
                    }
                    for _ in range(6)
                ]
                rows = summarize(SCENARIO_SUITES, pairs, False, limits)
                snapshot_rows = [
                    row for row in rows if row["suite"] == "snapshot_registry"
                ]
                self.assertTrue(snapshot_rows)
                self.assertTrue(
                    all(
                        row["median_gate_applicable"] is expected_applicable
                        for row in snapshot_rows
                    )
                )
                policy = threshold_policy(
                    rows,
                    limits,
                    "reviewed.json",
                    "b" * 64,
                    reviewed=True,
                )
                self.assertEqual(policy["status"], expected_status)

    def test_atomic_snapshot_uses_snapshot_limit_not_match_set_limit(self):
        parent_values = {identifier: 100 for identifier in SCENARIO_SUITES}
        candidate_values = dict(parent_values)
        for identifier in candidate_values:
            if identifier.startswith("snapshot_registry/"):
                candidate_values[identifier] = 107
        pairs = [
            {
                "parent": report("parent", value=parent_values),
                "candidate": report(
                    "candidate",
                    value=candidate_values,
                    enabled_features=("candidate-atomic-snapshot",),
                ),
            }
            for _ in range(6)
        ]
        limits = {"match_set": 5.0, "snapshot_registry": 8.0}
        rows = summarize(SCENARIO_SUITES, pairs, False, limits)
        policy = threshold_policy(
            rows,
            limits,
            "reviewed.json",
            "b" * 64,
            reviewed=True,
        )
        self.assertEqual(policy["status"], WITHIN_CALIBRATED_BAND)
        self.assertTrue(
            all(
                row["median_limit_percent"] == 8.0
                for row in rows
                if row["suite"] == "snapshot_registry"
            )
        )

    def test_candidate_feature_identity_cannot_change_between_pairs(self):
        pairs = [
            {"parent": report("parent"), "candidate": report("candidate")}
            for _ in range(6)
        ]
        pairs[-1]["candidate"]["candidate"]["enabled_features"] = [
            "candidate-atomic-snapshot"
        ]
        with self.assertRaisesRegex(ControlError, "changed between pairs"):
            summarize(
                SCENARIO_SUITES,
                pairs,
                False,
                {"match_set": 5.0, "snapshot_registry": 5.0},
            )
