from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.calibration import create_calibration_candidate
from tools.performance_candidate.linux.plan import PLAN_SCHEMA_VERSION, create_plan


class LinuxCalibrationTests(unittest.TestCase):
    @staticmethod
    def _workflow() -> str:
        return (
            pathlib.Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "performance-candidate.yml"
        ).read_text(encoding="utf-8")

    def test_aa_workflow_executes_one_exact_binary_identity_for_both_members(
        self,
    ) -> None:
        workflow = self._workflow()
        calibration_block = workflow.split(
            "# A/A measures scheduling and runner noise", 1
        )[1].split("\n          fi", 1)[0]
        for binary in ("ferrum2-client", "ferrum2-server"):
            self.assertIn(
                f'"$CANDIDATE_DIR/target/profiling/{binary}"', calibration_block
            )
            self.assertIn(
                f'"$PARENT_DIR/target/profiling/{binary}"', calibration_block
            )
        self.assertEqual(calibration_block.count("install -m 0755"), 2)
        self.assertEqual(calibration_block.count("cmp \\"), 2)

    def test_workflow_runs_two_aa_rounds_and_one_comparison_round(self) -> None:
        workflow = self._workflow()
        self.assertIn("timeout-minutes: 240", workflow)
        self.assertEqual(
            workflow.count("calibration-aa) RUN_ROUNDS=2 ;;"),
            1,
        )
        self.assertEqual(workflow.count("comparison) RUN_ROUNDS=1 ;;"), 1)
        self.assertIn(
            'test "$MODE/$WARMUP_SECONDS/$ACTIVE_SECONDS/$PAIRS" = \\\n'
            '              "qualification/3/30/6"',
            workflow,
        )
        self.assertEqual(
            workflow.count('for round in $(seq 1 "$RUN_ROUNDS"); do'),
            2,
        )
        self.assertIn('for pair in $(seq 1 "$PAIRS"); do', workflow)
        self.assertIn('options: ["6"]', workflow)

        schedule = """if ((pair % 2 == 1)); then
                  run_member "$scenario" parent "$pair" 1 "$round"
                  run_member "$scenario" candidate "$pair" 2 "$round"
                else
                  run_member "$scenario" candidate "$pair" 1 "$round"
                  run_member "$scenario" parent "$pair" 2 "$round"
                fi"""
        self.assertIn(schedule, workflow)

    def test_workflow_preflights_reviewed_comparison_host_before_build(self) -> None:
        workflow = self._workflow()
        amd_name = "- name: Require preferred AMD performance host"
        bind_name = "- name: Bind exact parent and runner identity"
        preflight_name = "- name: Preflight reviewed comparison host applicability"
        build_name = "- name: Prove parent and candidate correctness and build identities"
        self.assertLess(workflow.index(amd_name), workflow.index(bind_name))
        self.assertLess(workflow.index(preflight_name), workflow.index(build_name))

        amd_gate = workflow.split(amd_name, 1)[1].split(bind_name, 1)[0]
        self.assertIn("/proc/cpuinfo", amd_gate)
        self.assertIn("AuthenticAMD", amd_gate)
        self.assertIn("exit 1", amd_gate)

        preflight = workflow.split(preflight_name, 1)[1].split(build_name, 1)[0]
        self.assertIn(
            "if: ${{ inputs.run_kind == 'comparison' && "
            "inputs.selection != 'tcp-scale-10k' }}",
            preflight,
        )
        self.assertIn("python3 -B -m tools.performance_candidate plan", preflight)
        for value in (
            '"$MODE"',
            '"$SELECTION"',
            '"$WARMUP_SECONDS"',
            '"$ACTIVE_SECONDS"',
            '"$PAIRS"',
            '"$PERFORMANCE_POLICY"',
            '"$PERFORMANCE_PLAN"',
        ):
            self.assertIn(value, preflight)
        self.assertIn(
            "from tools.performance_candidate.linux.policy import (\n"
            "              _scenario_policy_is_applicable,",
            preflight,
        )
        self.assertIn("/proc/cpuinfo", preflight)
        self.assertIn("/proc/meminfo", preflight)
        self.assertIn("os.cpu_count()", preflight)
        self.assertIn('["rustc", "+1.97.1", "-V"]', preflight)
        self.assertIn('["uname", "-srvmo"]', preflight)
        self.assertIn("observed_environment=observed_environment", preflight)
        self.assertIn('entry["calibration_environment"]', preflight)
        self.assertNotIn("memory_capacity_class", preflight)
        self.assertIn("sys.exit(1)", preflight)

    def test_workflow_isolates_raw_evidence_and_summarizes_each_round(self) -> None:
        workflow = self._workflow()
        for argument in ("--ready-file", "--output"):
            self.assertIn(
                f'{argument} "profiles/paired/round-$round/'
                '$scenario-$member-$pair.',
                workflow,
            )
        self.assertIn(
            '--parent-root "$PARENT_DIR/profiles/paired/round-$round"', workflow
        )
        self.assertIn(
            '--candidate-root "$CANDIDATE_DIR/profiles/paired/round-$round"',
            workflow,
        )
        self.assertIn(
            'round_summary="$RUNNER_TEMP/performance-summary-round-$round.json"',
            workflow,
        )
        self.assertIn(
            'round_markdown="$RUNNER_TEMP/performance-summary-round-$round.md"',
            workflow,
        )

    def test_workflow_aggregates_two_aa_summaries_and_uploads_all_evidence(
        self,
    ) -> None:
        workflow = self._workflow()
        summary_block = workflow.split(
            "- name: Summarize paired performance evidence", 1
        )[1].split("- name: Upload paired raw evidence", 1)[0]
        aggregate_guard = (
            'if [ "$RUN_KIND" = calibration-aa ] \\\n'
            '            && [ "$summary_status" -eq 0 ]; then'
        )
        self.assertIn(aggregate_guard, summary_block)
        aggregate_block = summary_block.split(aggregate_guard, 1)[1].split(
            "\n          fi", 1
        )[0]
        self.assertEqual(aggregate_block.count("--summary"), 2)
        for round_number in (1, 2):
            self.assertIn(
                f'--summary "$RUNNER_TEMP/performance-summary-round-{round_number}.json"',
                aggregate_block,
            )
        self.assertIn("linux-calibration-candidate", aggregate_block)
        self.assertIn(
            '--output "$PERFORMANCE_CALIBRATION_CANDIDATE"', aggregate_block
        )

        artifact_block = workflow.split(
            "- name: Upload paired raw evidence", 1
        )[1].split("- name: Reap processes", 1)[0]
        for path in (
            "${{ github.workspace }}/profiles/paired/**/*.jsonl",
            "${{ runner.temp }}/ferrum2-parent/profiles/paired/**/*.jsonl",
            "${{ runner.temp }}/performance-summary-round-*.json",
            "${{ runner.temp }}/performance-summary-round-*.md",
            "${{ runner.temp }}/linux-calibration-candidate.json",
        ):
            self.assertIn(path, artifact_block)

    def test_calibration_rejects_build_or_evidence_contract_drift(self) -> None:
        mutations = (
            ({"runner_sha256": "b" * 64}, None, None, "full build identities"),
            ({"sha": "f" * 40}, None, None, "full build identities"),
            ({"unexpected": "value"}, None, None, "full build identities"),
            (
                None,
                {"semantic_recipe_sha256": "d" * 64},
                None,
                "scenario evidence contracts",
            ),
            (
                None,
                {"unexpected": "value"},
                None,
                "scenario evidence contracts",
            ),
            (None, None, {"policy_sha256": "f" * 64}, "full decision policy"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "round-1.json"
            self._write_summary(first, [0.0] * 6)
            for index, (
                build_updates,
                contract_updates,
                decision_policy_updates,
                expected_error,
            ) in enumerate(mutations, start=2):
                with self.subTest(expected_error=expected_error):
                    changed = root / f"round-{index}.json"
                    self._write_summary(
                        changed,
                        [0.0] * 6,
                        build_identity_updates=build_updates,
                        evidence_contract_updates=contract_updates,
                        decision_policy_updates=decision_policy_updates,
                    )
                    with self.assertRaisesRegex(
                        CandidateControlError, expected_error
                    ):
                        create_calibration_candidate([first, changed])

    def test_calibration_plan_is_same_source_measurement_and_never_adoption_eligible(
        self,
    ) -> None:
        plan = create_plan(
            mode="qualification",
            selection="udp-small-high",
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            run_kind="calibration-aa",
        )
        self.assertEqual(plan["schema_version"], PLAN_SCHEMA_VERSION)
        self.assertEqual(plan["run_kind"], "calibration-aa")
        self.assertFalse(plan["adoption_eligible"])
        with self.assertRaisesRegex(CandidateControlError, "qualification mode"):
            create_plan(
                mode="diagnostic",
                selection="udp-small-high",
                warmup_seconds="3",
                active_seconds="30",
                pairs="6",
                run_kind="calibration-aa",
            )

    def test_two_six_pair_rounds_produce_review_only_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "round-1.json"
            second = root / "round-2.json"
            self._write_summary(first, [-1.0, 0.5, 1.0, -0.5, 0.0, 2.0])
            self._write_summary(second, [-2.0, 0.25, 0.75, -0.25, 0.0, 1.5])

            candidate = create_calibration_candidate([first, second])

        self.assertEqual(candidate["kind"], "linux_performance_calibration_candidate")
        self.assertEqual(candidate["rounds"], 2)
        self.assertFalse(candidate["thresholds_adopted"])
        scenario = candidate["scenarios"]["udp-small-high"]
        self.assertEqual(scenario["samples"], 12)
        self.assertEqual(scenario["p95_absolute_delta_percent"], 2.0)
        self.assertTrue(scenario["review_required"])

    def test_calibration_rejects_mixed_commit_or_non_aa_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "round-1.json"
            second = root / "round-2.json"
            self._write_summary(first, [0.0] * 6)
            self._write_summary(second, [0.0] * 6, run_kind="comparison")
            with self.assertRaisesRegex(CandidateControlError, "calibration-aa summaries"):
                create_calibration_candidate([first, second])

    def test_calibration_rejects_a_repeated_round(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = pathlib.Path(directory) / "round.json"
            self._write_summary(summary, [0.0] * 6)
            with self.assertRaisesRegex(CandidateControlError, "distinct A/A"):
                create_calibration_candidate([summary, summary])

    def test_calibration_uses_one_nearest_memory_capacity_class(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            anchor = 1_048_576
            lower = root / "round-lower.json"
            upper = root / "round-upper.json"
            below = root / "round-below.json"
            outside = root / "round-outside.json"
            self._write_summary(
                lower,
                [0.0] * 6,
                memory_kib=anchor - 32_768,
            )
            self._write_summary(
                upper,
                [0.0] * 6,
                memory_kib=anchor + 32_767,
            )
            self._write_summary(
                below,
                [0.0] * 6,
                memory_kib=anchor - 32_769,
            )
            self._write_summary(
                outside,
                [0.0] * 6,
                memory_kib=anchor + 32_768,
            )

            candidate = create_calibration_candidate([upper, lower])

            self.assertEqual(candidate["schema_version"], 2)
            self.assertEqual(candidate["environment_identity"]["memory_kib"], anchor)
            self.assertEqual(candidate["memory_capacity_quantum_kib"], 65_536)
            self.assertEqual(
                candidate["memory_observations_kib"],
                [anchor - 32_768, anchor + 32_767],
            )
            self.assertEqual(
                json.loads(upper.read_text(encoding="utf-8"))["environment_identity"][
                    "memory_kib"
                ],
                anchor + 32_767,
            )
            with self.assertRaisesRegex(CandidateControlError, "share commit, environment"):
                create_calibration_candidate([lower, below])
            with self.assertRaisesRegex(CandidateControlError, "share commit, environment"):
                create_calibration_candidate([upper, outside])

    def test_calibration_preserves_real_runner_memory_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "round-1.json"
            second = root / "round-2.json"
            self._write_summary(first, [0.0] * 6, memory_kib=16_373_452)
            self._write_summary(second, [0.0] * 6, memory_kib=16_377_684)

            candidate = create_calibration_candidate([first, second])

            self.assertEqual(
                candidate["environment_identity"]["memory_kib"], 16_384_000
            )
            self.assertEqual(
                candidate["memory_observations_kib"], [16_373_452, 16_377_684]
            )
            self.assertEqual(
                [
                    json.loads(path.read_text(encoding="utf-8"))[
                        "environment_identity"
                    ]["memory_kib"]
                    for path in (first, second)
                ],
                [16_373_452, 16_377_684],
            )

    def test_calibration_rejects_non_memory_or_key_set_drift(self) -> None:
        mutations = (
            {"cpu_model": "different-cpu"},
            {"kernel": "different-kernel"},
            {"unexpected": "field"},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "round-1.json"
            self._write_summary(first, [0.0] * 6)
            for index, updates in enumerate(mutations, start=2):
                with self.subTest(updates=updates):
                    changed = root / f"round-{index}.json"
                    self._write_summary(
                        changed,
                        [0.0] * 6,
                        environment_updates=updates,
                    )
                    with self.assertRaisesRegex(
                        CandidateControlError, "share commit, environment"
                    ):
                        create_calibration_candidate([first, changed])

            missing = root / "round-missing.json"
            self._write_summary(
                missing,
                [0.0] * 6,
                removed_environment_field="kernel",
            )
            with self.assertRaisesRegex(CandidateControlError, "share commit, environment"):
                create_calibration_candidate([first, missing])

    @staticmethod
    def _write_summary(
        path: pathlib.Path,
        improvements: list[float],
        *,
        run_kind: str = "calibration-aa",
        memory_kib: int = 1_048_576,
        environment_updates: dict[str, object] | None = None,
        removed_environment_field: str | None = None,
        build_identity_updates: dict[str, object] | None = None,
        evidence_contract_updates: dict[str, object] | None = None,
        decision_policy_updates: dict[str, object] | None = None,
    ) -> None:
        sha = "a" * 40
        environment = {
            "runner_image": "ubuntu-24.04",
            "rustc": "rustc 1.97.1",
            "kernel": "test",
            "cpu_model": "test",
            "cpu_count": 4,
            "memory_kib": memory_kib,
            "build_profile": "current",
        }
        if environment_updates is not None:
            environment.update(environment_updates)
        if removed_environment_field is not None:
            environment.pop(removed_environment_field)
        build_identity = {
            "sha": sha,
            "tree": "b" * 40,
            "runner_sha256": "c" * 64,
            "client_sha256": "d" * 64,
            "server_sha256": "e" * 64,
        }
        if build_identity_updates is not None:
            build_identity.update(build_identity_updates)
        evidence_contract = {
            "schema_version": 3,
            "trial_schema_version": 6,
            "unit": "bytes_per_second",
            "runner_image": "ubuntu-24.04",
            "producer_source_sha256": "1" * 64,
            "controller_source_sha256": "2" * 64,
            "semantic_recipe_sha256": "3" * 64,
            "evidence_bundle_sha256": "4" * 64,
            "cleanup_contract": {
                "active_processes": 0,
                "active_workers": 0,
                "ready_file_removed": True,
                "status": "PASS",
            },
        }
        if evidence_contract_updates is not None:
            evidence_contract.update(evidence_contract_updates)
        decision_policy = {
            "schema_version": 3,
            "policy_id": "test-policy",
            "policy_sha256": "5" * 64,
            "scenarios": {"udp-small-high": {}},
        }
        if decision_policy_updates is not None:
            decision_policy.update(decision_policy_updates)
        value = {
            "kind": "performance_candidate_summary",
            "run_kind": run_kind,
            "parent_sha": sha,
            "candidate_sha": sha,
            "build_identities": {
                "parent": copy.deepcopy(build_identity),
                "candidate": copy.deepcopy(build_identity),
            },
            "decision_policy": decision_policy,
            "status": "CALIBRATION_REQUIRED",
            "adoption_claim": False,
            "workflow_failure_reason": None,
            "environment_identity": environment,
            "pairs": 6,
            "selection": "udp-small-high",
            "scenarios": [
                {
                    "scenario": "udp-small-high",
                    "evidence_contract": evidence_contract,
                    "pairs": [
                        {"improvement_percent": improvement}
                        for improvement in improvements
                    ],
                }
            ],
        }
        path.write_text(
            json.dumps(value, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
