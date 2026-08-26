import unittest
from pathlib import Path

from tests.performance_rule._fixture import SCENARIO_SUITES, report
from tools.performance_rule.pairing import (
    calibrated_limit,
    pair_execution_order,
    summarize,
)
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CANDIDATE_WIN,
    REGRESSION,
    WITHIN_CALIBRATED_BAND,
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
            {"parent": report("same", value=100), "candidate": report("same", value=104)}
            for _ in range(6)
        ]
        rows = summarize(SCENARIO_SUITES, pairs, True, 10.0)
        limit = calibrated_limit(rows)
        policy = threshold_policy(rows, limit, None, None, reviewed=False)
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
                rows = summarize(SCENARIO_SUITES, pairs, False, 10.0)
                policy = threshold_policy(
                    rows, 10.0, "reviewed.json", "b" * 64, reviewed=True
                )
                self.assertEqual(policy["status"], expected)
