import copy
import pathlib
import tempfile
import unittest

from tests.performance_candidate._shared_fixture import POLICY_PATH, synthetic_policy
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy

class DecisionPolicyTests(unittest.TestCase):
    def test_repository_policy_contains_reviewed_tcp_calibration(self) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        self.assertEqual(policy["schema_version"], 2)
        self.assertRegex(policy["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            policy["policy_id"],
            "github-hosted-ubuntu-24.04-profiling-v2-reviewed-aa-fbc4c5cad012",
        )
        self.assertEqual(set(policy["scenarios"]), set(linux_catalog.SCENARIO_CATALOG))

        expected_tcp_thresholds = {
            "tcp-bulk": (1.5, 1.9),
            "tcp-request-16k": (1.6, 2.0),
            "tcp-request-1k": (1.0, 1.3),
            "tcp-request-4k": (0.6, 0.8),
            "tcp-stream-64k": (1.3, 1.7),
        }
        calibrated_fields = (
            "noise_band_percent",
            "regression_threshold_percent",
            "adoption_threshold_percent",
            "minimum_pairs",
            "minimum_wins",
            "minimum_losses",
            "calibration_source",
            "calibration_environment",
        )
        for scenario, entry in policy["scenarios"].items():
            with self.subTest(scenario=scenario):
                calibrated = [entry[field] for field in calibrated_fields]
                if scenario not in expected_tcp_thresholds:
                    self.assertTrue(all(value is None for value in calibrated))
                    continue

                noise_band, adoption_threshold = expected_tcp_thresholds[scenario]
                self.assertTrue(all(value is not None for value in calibrated))
                self.assertEqual(entry["noise_band_percent"], noise_band)
                self.assertEqual(
                    entry["regression_threshold_percent"], -adoption_threshold
                )
                self.assertEqual(
                    entry["adoption_threshold_percent"], adoption_threshold
                )
                self.assertEqual(entry["minimum_pairs"], 6)
                self.assertEqual(entry["minimum_wins"], 5)
                self.assertEqual(entry["minimum_losses"], 4)
                self.assertIn(
                    "/runs/33476895420/artifacts/9789589781/",
                    entry["calibration_source"],
                )
                environment = entry["calibration_environment"]
                self.assertEqual(environment["runner_image"], "ubuntu-24.04")
                self.assertEqual(environment["pair_schedule"], "abba-six-pairs")
                self.assertEqual(environment["warmup_seconds"], 3)
                self.assertEqual(environment["active_seconds"], 30)

    def test_repository_policy_enables_only_calibrated_six_pair_qualification(
        self,
    ) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        expected_eligibility = {
            "tcp-frame-capacity": True,
            "udp-payload-matrix": False,
            "udp-direct-payload-bounds": False,
        }
        for selection, eligible in expected_eligibility.items():
            with self.subTest(selection=selection):
                plan = linux_plan.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="3",
                    active_seconds="30",
                    pairs="6",
                    decision_policy=policy,
                )
                self.assertEqual(plan["adoption_eligible"], eligible)
                for scenario in plan["scenarios"]:
                    contract = scenario["evidence_contract"]
                    for field in (
                        "producer_source_sha256",
                        "controller_source_sha256",
                        "semantic_recipe_sha256",
                        "evidence_bundle_sha256",
                    ):
                        self.assertRegex(contract[field], r"^[0-9a-f]{64}$")

    def test_policy_schema_rejects_shape_identity_and_partial_calibration_errors(
        self,
    ) -> None:
        mutations = {
            "missing scenario": lambda policy: policy["scenarios"].pop("tcp-bulk"),
            "wrong metric": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                metric="p99_nanoseconds"
            ),
            "partial calibration": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(calibration_source=None),
            "threshold inside noise": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(regression_threshold_percent=-1.0),
            "boolean count": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                minimum_wins=True
            ),
            "boolean recipe": lambda policy: policy["scenarios"]["tcp-bulk"][
                "calibration_environment"
            ].update(warmup_seconds=True),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                policy = synthetic_policy()
                mutation(policy)
                with self.assertRaises(json_contract.CandidateControlError):
                    linux_policy.validate_decision_policy(policy)

    def test_policy_loader_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-json-") as directory:
            root = pathlib.Path(directory)
            for name, text in (
                ("duplicate", '{"schema_version":2,"schema_version":2}'),
                (
                    "non-finite",
                    '{"schema_version":2,"policy_id":"x","scenarios":NaN}',
                ),
            ):
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(json_contract.CandidateControlError):
                        linux_policy.load_decision_policy(path)

    def test_canonical_plan_rejects_policy_digest_or_threshold_tampering(self) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        plan = linux_plan.create_plan(
            mode="qualification",
            selection="tcp-stream-64k",
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            decision_policy=policy,
        )
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-plan-") as directory:
            path = pathlib.Path(directory) / "plan.json"
            for name, mutate in (
                (
                    "schema version",
                    lambda value: value.update(schema_version=3),
                ),
                (
                    "digest",
                    lambda value: value["decision_policy"].update(
                        policy_sha256="0" * 64
                    ),
                ),
                (
                    "threshold",
                    lambda value: value["decision_policy"]["scenarios"][
                        "tcp-bulk"
                    ].update(noise_band_percent=2.0),
                ),
            ):
                with self.subTest(name=name):
                    tampered = copy.deepcopy(plan)
                    mutate(tampered)
                    linux_plan.write_plan(path, tampered)
                    with self.assertRaises(json_contract.CandidateControlError):
                        linux_plan.load_plan(path, decision_policy=policy)
