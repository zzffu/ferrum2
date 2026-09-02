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
    def test_repository_policy_explicitly_requires_new_calibration(self) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        self.assertEqual(policy["schema_version"], 3)
        self.assertRegex(policy["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            policy["policy_id"],
            "github-hosted-ubuntu-24.04-profiling-v3-calibration-required",
        )
        self.assertEqual(set(policy["scenarios"]), set(linux_catalog.SCENARIO_CATALOG))
        for scenario, entry in policy["scenarios"].items():
            with self.subTest(scenario=scenario):
                calibrated = [
                    entry[field]
                    for field in (
                        "noise_band_percent",
                        "regression_threshold_percent",
                        "adoption_threshold_percent",
                        "minimum_pairs",
                        "minimum_wins",
                        "minimum_losses",
                        "calibration_source",
                        "calibration_environment",
                    )
                ]
                self.assertTrue(all(value is None for value in calibrated))

    def test_repository_policy_cannot_accept_six_pair_qualification_before_calibration(
        self,
    ) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        for selection in (
            "tcp-frame-capacity",
            "udp-payload-matrix",
            "udp-direct-payload-bounds",
        ):
            with self.subTest(selection=selection):
                plan = linux_plan.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="3",
                    active_seconds="30",
                    pairs="6",
                    decision_policy=policy,
                )
                self.assertFalse(plan["adoption_eligible"])
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
