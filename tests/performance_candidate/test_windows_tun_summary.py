import copy
import hashlib
import json
import pathlib
import re
import tempfile

from tests.performance_candidate._shared_fixture import WINDOWS_TUN_POLICY_PATH
from tests.performance_candidate._windows_tun_trial_support import WindowsTunTrialSupport
from tools.performance_candidate import cli as controller_cli
from tools.performance_candidate import json_contract
from tools.performance_candidate.windows_tun import network_model_lifecycle
from tools.performance_candidate.windows_tun import plan as windows_plan
from tools.performance_candidate.windows_tun import policy as windows_policy
from tools.performance_candidate.windows_tun import recipe as windows_recipe
from tools.performance_candidate.windows_tun import summary as windows_summary
from tools.performance_candidate.windows_tun import trial as windows_trial


class WindowsTunSummaryTests(WindowsTunTrialSupport):
    def test_repository_policy_and_plan_are_closed_and_uncalibrated(self) -> None:
        policy = self.policy()
        self.assertEqual(policy["schema_version"], 4)
        self.assertFalse(
            windows_policy.windows_tun_policy_is_calibrated(
                policy, controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256
            )
        )
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy,
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        self.assertEqual(plan["schema_version"], 5)
        self.assertEqual(plan["pairs"], 6)
        self.assertEqual(plan["pair_schedule"], "abba-six-pairs")
        self.assertEqual(set(plan["scenarios"]), set(windows_recipe.scenario_catalog()))
        self.assertEqual(len(plan["scenarios"]), 9)
        self.assertEqual(len(plan["trials"]), 108)
        self.assertFalse(plan["calibration_complete"])
        self.assertFalse(plan["adoption_eligible"])
        for scenario in plan["scenarios"]:
            trials = [row for row in plan["trials"] if row["scenario"] == scenario]
            self.assertEqual(len(trials), 12)
            self.assertEqual({row["pair"] for row in trials}, set(range(1, 7)))
            self.assertEqual({row["member"] for row in trials}, {"parent", "candidate"})
        self.assertRegex(windows_recipe.m4_windows_tun_bundle_sha256(), r"^[0-9a-f]{64}$")
        self.assertRegex(windows_recipe.network_model_bundle_sha256(), r"^[0-9a-f]{64}$")
        self.assertRegex(windows_recipe.performance_source_bundle_sha256(), r"^[0-9a-f]{64}$")
        performance_bundle = json.loads(
            windows_recipe.source_paths()["performance_bundle"].read_text(encoding="utf-8")
        )
        self.assertEqual(len(performance_bundle["files"]), 42)
        self.assertTrue(
            {
                "tools/powershell/Ferrum2.Qualification.Common/Ferrum2.Qualification.Common.psd1",
                "tools/powershell/Ferrum2.Qualification.Evidence/Ferrum2.Qualification.Evidence.psd1",
                "tools/powershell/Ferrum2.Qualification.HostHyperV/private/Facade.ps1",
            }.issubset({row["path"] for row in performance_bundle["files"]})
        )
        identities = windows_recipe.source_identities()
        self.assertEqual(
            identities["runner_source_sha256"],
            identities["performance_source_bundle_sha256"],
        )
        self.assertTrue(identities)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in identities.values()))

    def test_udp_diagnostic_profile_resolves_by_stable_trial_identity(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="calibration-aa",
            decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        matching_trial = windows_plan.resolve_windows_tun_diagnostic_profile(
            plan, "UdpFlowBoundary"
        )
        self.assertEqual(
            {
                field: matching_trial[field]
                for field in ("scenario", "member", "pair", "order")
            },
            {
                "scenario": "udp-8192-association-lookup-expiry",
                "member": "parent",
                "pair": 1,
                "order": 1,
            },
        )
        self.assertGreater(matching_trial["sequence"], 0)

        plan["diagnostic_profiles"]["UdpFlowBoundary"]["pair"] = 2
        plan["diagnostic_profiles"]["UdpFlowBoundary"]["order"] = 2
        moved_trial = windows_plan.resolve_windows_tun_diagnostic_profile(
            plan, "UdpFlowBoundary"
        )
        self.assertEqual(
            {field: moved_trial[field] for field in ("member", "pair", "order")},
            {"member": "parent", "pair": 2, "order": 2},
        )
        self.assertNotEqual(moved_trial["sequence"], matching_trial["sequence"])
        plan["trials"].append(copy.deepcopy(moved_trial))
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "does not resolve to one"
        ):
            windows_plan.resolve_windows_tun_diagnostic_profile(
                plan, "UdpFlowBoundary"
            )
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "unsupported"
        ):
            windows_plan.resolve_windows_tun_diagnostic_profile(plan, "Unknown")

    def test_serialized_windows_tun_plan_preserves_the_trial_schedule(self) -> None:
        policy = self.policy()
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy,
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "plan.json"
            path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
            loaded = windows_plan.load_windows_tun_plan(
                path,
                decision_policy=policy,
                controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
            )
            tampered_controller = copy.deepcopy(plan)
            tampered_controller["controller_bundle_sha256"] = "d" * 64
            tampered_controller["recipe_sha256"] = windows_recipe.recipe_sha256(
                "d" * 64
            )
            path.write_text(
                json.dumps(tampered_controller, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "canonical recipe"
            ):
                windows_plan.load_windows_tun_plan(
                    path,
                    decision_policy=policy,
                    controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
                )
            for sequence in (True, 1.0, "1"):
                with self.subTest(sequence=sequence):
                    tampered = copy.deepcopy(plan)
                    tampered["trials"][0]["sequence"] = sequence
                    path.write_text(
                        json.dumps(tampered, sort_keys=True), encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        json_contract.CandidateControlError, "canonical recipe"
                    ):
                        windows_plan.load_windows_tun_plan(
                            path,
                            decision_policy=policy,
                            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
                        )
            for field, value in (
                ("bootstrap_pacing_associations", 8),
                ("bootstrap_pacing_delay_ms", 25),
                ("canonical_source_ipv4", "198.18.0.3"),
                ("canonical_source_port_first", 20_001),
                ("canonical_source_port_last", 28_192),
                ("diagnostic_source_ipv4", "198.18.0.3"),
                ("diagnostic_source_port_first", 20_001),
                ("diagnostic_source_port_last", 28_192),
                ("diagnostic_collector_source_sha256", "0" * 64),
                ("canonical_source_port_strategy", "wildcard_ephemeral"),
            ):
                with self.subTest(recipe_field=field):
                    tampered = copy.deepcopy(plan)
                    recipe = tampered["scenarios"][
                        "udp-8192-association-lookup-expiry"
                    ]["recipe"]
                    recipe[field] = value
                    tampered["recipe_sha256"] = hashlib.sha256(
                        json_contract._canonical_json_bytes(tampered["scenarios"])
                    ).hexdigest()
                    path.write_text(
                        json.dumps(tampered, sort_keys=True), encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        json_contract.CandidateControlError, "canonical recipe"
                    ):
                        windows_plan.load_windows_tun_plan(
                            path,
                            decision_policy=policy,
                            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
                        )
        self.assertEqual(loaded["trials"], plan["trials"])
        self.assertEqual(loaded["trials"][48]["sequence"], 49)
        self.assertEqual(
            loaded["trials"][48]["scenario"],
            "fragment-reassembly-throughput",
        )

    def test_policy_rejects_partial_or_unbound_calibration(self) -> None:
        policy = self.policy()
        first_scenario = next(iter(policy["scenarios"].values()))
        first_metric = next(iter(first_scenario["metrics"].values()))
        first_metric["noise_band_percent"] = 2.0
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "complete or entirely null"
        ):
            windows_policy.validate_windows_tun_policy(
                policy, controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256
            )
        calibrated = self.policy(calibrated=True)
        first_scenario = next(iter(calibrated["scenarios"].values()))
        first_metric = next(iter(first_scenario["metrics"].values()))
        first_metric["calibration_artifact_sha256"] = "8" * 64
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "bind one SHA-256"
        ):
            windows_policy.validate_windows_tun_policy(
                calibrated, controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256
            )
        for field, value in (
            ("regression_threshold_percent", -100.001),
            ("adoption_threshold_percent", 100.001),
        ):
            with self.subTest(zero_capable_threshold=field):
                out_of_range = self.policy(calibrated=True)
                out_of_range["scenarios"]["wintun-ring-full-drop-rate"][
                    "metrics"
                ]["drop_rate"][field] = value
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError, "zero-capable.*sentinel"
                ):
                    windows_policy.validate_windows_tun_policy(
                        out_of_range,
                        controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
                    )

    def test_aa_evidence_produces_separate_non_adoptable_calibration_artifact(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="calibration-aa", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.AA_SHA,
                candidate_sha=self.AA_SHA,
            )
            summary = windows_summary.summarize_windows_tun_evidence(
                plan=plan,
                evidence_root=root,
                parent_sha=self.AA_SHA,
                candidate_sha=self.AA_SHA,
            )
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_eligible"])
        artifact = windows_summary.windows_tun_calibration_artifact(summary)
        self.assertFalse(artifact["adoption_eligible"])
        self.assertFalse(artifact["thresholds_reviewed"])
        self.assertRegex(artifact["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(artifact["observations"]), set(windows_recipe.scenario_catalog()))
        self.assertEqual(len(artifact["evidence_files"]), 132)
        self.assertEqual(
            artifact["network_model"]["raw_observations"],
            windows_recipe.WINDOWS_TUN_PAIR_COUNT * 2 * 2,
        )

    def test_uncalibrated_comparison_is_fail_closed(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            summary = windows_summary.summarize_windows_tun_evidence(
                plan=plan,
                evidence_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_eligible"])
        self.assertTrue(summary["correctness_complete"])

    def test_uncalibrated_comparison_cli_returns_non_success(self) -> None:
        policy = self.policy()
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=policy,
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            self.evidence(
                evidence,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            plan_path = root / "plan.json"
            output = root / "summary.json"
            markdown = root / "summary.md"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            status = controller_cli.main(
                [
                    "windows-tun-summarize",
                    "--plan",
                    str(plan_path),
                    "--evidence-root",
                    str(evidence),
                    "--parent-sha",
                    self.PARENT_SHA,
                    "--candidate-sha",
                    self.CANDIDATE_SHA,
                    "--policy",
                    str(WINDOWS_TUN_POLICY_PATH),
                    "--output",
                    str(output),
                    "--markdown",
                    str(markdown),
                    "--controller-bundle-sha256",
                    self.CONTROLLER_BUNDLE_SHA256,
                ]
            )
            summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 4)
        self.assertEqual(summary["status"], "CALIBRATION_REQUIRED")
        self.assertFalse(summary["adoption_eligible"])

    def test_evidence_rejects_claimed_order_when_trials_overlap(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            second = root / "tcp-single-flow-1-candidate.json"
            row = json.loads(second.read_text(encoding="utf-8"))
            row["started_utc"] = "2026-08-22T00:00:02.5000000Z"
            second.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "overlap.*planned order"
            ):
                windows_summary.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_lifecycle_sidecar_is_hash_bound_and_reduced_from_raw_cycles(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            trial_path = root / "network-lifecycle-1-parent.json"
            row = json.loads(trial_path.read_text(encoding="utf-8"))
            observation_path = (
                root
                / "network-model"
                / row["network_model_evidence"]["observation_file"]
            )
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            observation["cycles"][499]["elapsed_nanoseconds"] += 1
            encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
            observation_path.write_bytes(encoded)
            row["network_model_evidence"]["observation_sha256"] = hashlib.sha256(
                encoded
            ).hexdigest()
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "not recomputed from raw evidence"
            ):
                windows_summary.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_lifecycle_pins_collector_and_exact_measured_reset_coverage(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="network-lifecycle",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        windows_trial.validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = []
        wrong_collector = copy.deepcopy(row)
        wrong_collector["network_model_evidence"]["collector_sha256"] = "0" * 64
        cases.append((wrong_collector, "collector identity mismatch"))
        warmup_counted_as_measured = copy.deepcopy(row)
        warmup_counted_as_measured["correctness"]["checked_units"] = (
            network_model_lifecycle.TOTAL_RESET_CYCLES
        )
        cases.append((warmup_counted_as_measured, "exactly 1000 measured resets"))
        for invalid, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(json_contract.CandidateControlError, message):
                    windows_trial.validate_windows_tun_trial(
                        invalid,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_route_once_sidecar_is_hash_bound_and_reduced_from_raw_counters(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.evidence(
                root,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
            trial_path = root / "udp-route-once-1-parent.json"
            row = json.loads(trial_path.read_text(encoding="utf-8"))
            observation_path = (
                root
                / "network-model"
                / row["network_model_evidence"]["observation_file"]
            )
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            observation["elapsed_nanoseconds"] += 1
            encoded = json.dumps(observation, sort_keys=True).encode("utf-8")
            observation_path.write_bytes(encoded)
            row["network_model_evidence"]["observation_sha256"] = hashlib.sha256(
                encoded
            ).hexdigest()
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "route-once measurements were not recomputed"
            ):
                windows_summary.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )

    def test_calibrated_comparison_detects_clear_and_regression(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(calibrated=True),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        self.assertTrue(plan["calibration_complete"])
        self.assertFalse(plan["adoption_eligible"])
        for regression, expected, eligible in (
            (False, "WITHIN_CALIBRATED_BAND", True),
            (True, "REGRESSION", False),
        ):
            with self.subTest(regression=regression), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.evidence(
                    root,
                    plan=plan,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                    regression=regression,
                )
                summary = windows_summary.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )
                self.assertEqual(summary["status"], expected)
                self.assertEqual(summary["adoption_eligible"], eligible)
