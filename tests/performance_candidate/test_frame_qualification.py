import copy
import json
import pathlib
import unittest
from unittest import mock

from tests.performance_candidate._linux_summary_support import structural_metrics
from tests.performance_candidate._shared_fixture import synthetic_scale_row
from tests.performance_candidate.test_build_experiment import (
    SOURCE_SHA,
    SOURCE_TREE,
    BuildExperimentFixture,
)
from tools.performance_candidate import build_experiment, frame_qualification
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.evidence_contract import (
    _DIAGNOSTIC_BEGIN,
    _DIAGNOSTIC_END,
    _TIMED_V6_EXCLUDED_CONTROLLER_FILES,
)
from tools.performance_candidate.linux.trial import PROFILE_TRIAL_SCHEMA_VERSION


class FrameQualificationTests(BuildExperimentFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy = (
            pathlib.Path(__file__).resolve().parents[2]
            / "tools"
            / "performance_frame_policy.json"
        )

    def github_environment(self) -> dict[str, object]:
        machine = self.machine()
        machine["cpu_model"] = {
            "source": "/proc/cpuinfo",
            "status": "captured",
            "value": "AMD EPYC fixture",
        }
        with (
            mock.patch.object(
                build_experiment, "_bounded_command", side_effect=self.command_result
            ),
            mock.patch.object(
                build_experiment,
                "_capture_machine_identity",
                return_value=(machine, self.background()),
            ),
            mock.patch.object(
                build_experiment, "_utc_now", return_value="2026-08-29T00:00:00Z"
            ),
        ):
            return build_experiment.capture_environment(
                repository=self.repository,
                source_sha=SOURCE_SHA,
                environment_kind="github-hosted",
                runner_image="ubuntu-24.04",
            )

    def plan(self) -> tuple[pathlib.Path, dict[str, object], dict[str, object]]:
        environment = self.github_environment()
        environment_path = self.write_json("frame-environment.json", environment)
        plan = frame_qualification.create_plan(
            environment_path=environment_path,
            policy_path=self.policy,
            target_root=self.root / "frame-targets",
        )
        return self.write_json("frame-plan.json", plan), plan, environment

    def build_record(
        self,
        plan_path: pathlib.Path,
        plan: dict[str, object],
        environment: dict[str, object],
        variant: str,
    ) -> pathlib.Path:
        selected = next(
            row for row in plan["variants"] if row["axis"]["name"] == variant
        )

        def executor(argv, cwd, env, log):
            self.assertEqual(argv, selected["argv"])
            self.assertEqual(pathlib.Path(cwd), self.repository)
            for name, path_value in selected["artifact_paths"].items():
                path = pathlib.Path(path_value)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"{variant}-{name}".encode("ascii"))
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_bytes(b"closed fixture build")
            return 0

        with mock.patch.object(
            build_experiment, "capture_environment", return_value=environment
        ):
            record, status = frame_qualification.run_build(
                plan_path=plan_path,
                variant_name=variant,
                log_path=self.root / "logs" / f"{variant}.log",
                executor=executor,
                clock=iter((10, 20)).__next__,
            )
        self.assertEqual(status, 0)
        return self.write_json(f"frame-build-{variant}.json", record)

    @staticmethod
    def _environment() -> dict[str, object]:
        return {
            "runner_image": "ubuntu-24.04",
            "rustc": "rustc 1.97.1 fixture",
            "kernel": "Linux fixture",
            "cpu_model": "AMD EPYC fixture",
            "cpu_count": 8,
            "memory_kib": 32_000_000,
            "build_profile": "current",
        }

    def trial_row(
        self,
        *,
        plan: dict[str, object],
        scenario_name: str,
        member: str,
        pair: int,
        build_record: dict[str, object],
    ) -> dict[str, object]:
        scenario = next(
            row for row in plan["scenarios"] if row["name"] == scenario_name
        )
        contract = scenario["evidence_contract"]
        if scenario_name == "tcp-scale-10k":
            row = synthetic_scale_row(pair=pair, member=member)
        else:
            value = 100 if member == "parent" else 105
            row = {
                "schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
                "kind": "m18_profile_trial",
                "parent_sha": SOURCE_SHA,
                "candidate_sha": SOURCE_SHA,
                "member": member,
                "pair": pair,
                "order": 1 if (pair % 2 == 1) == (member == "parent") else 2,
                "build_profile": "current",
                "scenario": scenario_name,
                "warmup_seconds": scenario["warmup_seconds"],
                "active_seconds": scenario["active_seconds"],
                "topology": scenario["topology"],
                "application_payload_bytes": scenario["application_payload_bytes"],
                "workload_scale": scenario["workload_scale"],
                "socks_datagram_bytes": scenario["socks_datagram_bytes"],
                "upstream_wire_bytes": scenario["upstream_wire_bytes"],
                "sha": SOURCE_SHA,
                "tree": SOURCE_TREE,
                "runner_sha256": "0" * 64,
                "client_sha256": "0" * 64,
                "server_sha256": "0" * 64,
                "rustc": self._environment()["rustc"],
                "kernel": self._environment()["kernel"],
                "cpu_model": self._environment()["cpu_model"],
                "cpu_count": self._environment()["cpu_count"],
                "memory_kib": self._environment()["memory_kib"],
                "metric": scenario["metric"],
                "unit": contract["unit"],
                "value": value,
                "checked_units": 1_000,
                "p99_nanoseconds": (
                    value if scenario["metric"] == "p99_nanoseconds" else None
                ),
                "io_completions": 2_000,
                "scale": None,
                "structural_metrics": structural_metrics(scenario_name),
                "producer_source_sha256": contract["producer_source_sha256"],
                "controller_source_sha256": contract["controller_source_sha256"],
                "semantic_recipe_sha256": contract["semantic_recipe_sha256"],
                "evidence_bundle_sha256": contract["evidence_bundle_sha256"],
                "environment_identity": self._environment(),
                "cleanup": copy.deepcopy(contract["cleanup_contract"]),
                "correctness": "PASS",
                "status": "PASS",
            }
        artifacts = {item["name"]: item for item in build_record["artifacts"]}
        row.update(
            {
                "parent_sha": SOURCE_SHA,
                "candidate_sha": SOURCE_SHA,
                "sha": SOURCE_SHA,
                "tree": SOURCE_TREE,
                "runner_sha256": artifacts["m4-qualification"]["sha256"],
                "client_sha256": artifacts["ferrum2-client"]["sha256"],
                "server_sha256": artifacts["ferrum2-server"]["sha256"],
                "rustc": self._environment()["rustc"],
                "kernel": self._environment()["kernel"],
                "cpu_model": self._environment()["cpu_model"],
                "cpu_count": self._environment()["cpu_count"],
                "memory_kib": self._environment()["memory_kib"],
                "environment_identity": self._environment(),
                "producer_source_sha256": contract["producer_source_sha256"],
                "controller_source_sha256": contract["controller_source_sha256"],
                "semantic_recipe_sha256": contract["semantic_recipe_sha256"],
                "evidence_bundle_sha256": contract["evidence_bundle_sha256"],
                "cleanup": copy.deepcopy(contract["cleanup_contract"]),
            }
        )
        return row

    def evidence_root(
        self,
        *,
        name: str,
        plan: dict[str, object],
        parent_build: dict[str, object],
        candidate_build: dict[str, object],
    ) -> pathlib.Path:
        root = self.root / name
        for member, build in (
            ("parent", parent_build),
            ("candidate", candidate_build),
        ):
            member_root = root / member
            member_root.mkdir(parents=True)
            for scenario in plan["scenarios"]:
                for pair in range(1, 7):
                    row = self.trial_row(
                        plan=plan,
                        scenario_name=scenario["name"],
                        member=member,
                        pair=pair,
                        build_record=build,
                    )
                    (member_root / f"{scenario['name']}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
                    )
        return root

    def prepared(self):
        plan_path, plan, environment = self.plan()
        baseline_path = self.build_record(
            plan_path, plan, environment, "default32"
        )
        candidate_path = self.build_record(
            plan_path, plan, environment, "adaptive"
        )
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        aa1 = self.evidence_root(
            name="aa-1",
            plan=plan,
            parent_build=candidate,
            candidate_build=candidate,
        )
        aa2 = self.evidence_root(
            name="aa-2",
            plan=plan,
            parent_build=candidate,
            candidate_build=candidate,
        )
        comparison = self.evidence_root(
            name="comparison",
            plan=plan,
            parent_build=baseline,
            candidate_build=candidate,
        )
        return plan_path, plan, baseline_path, candidate_path, aa1, aa2, comparison

    def test_plan_closes_four_mutually_exclusive_same_source_build_identities(self):
        plan_path, plan, _environment = self.plan()
        loaded, _ = frame_qualification._load_plan(plan_path)
        self.assertEqual(
            [row["axis"]["name"] for row in loaded["variants"]],
            list(frame_qualification.AXIS_NAMES),
        )
        self.assertEqual(len({row["variant_id"] for row in loaded["variants"]}), 4)
        for variant in loaded["variants"]:
            features = variant["axis"]["cargo_features"]
            self.assertIn(len(features), {0, 2})
            self.assertEqual(variant["source_identity"], plan["source_identity"])

        mutated = copy.deepcopy(plan)
        mutated["variants"][1]["axis"]["cargo_features"] = []
        material = dict(mutated)
        material.pop("plan_id")
        material.pop("generated_at_utc")
        mutated["plan_id"] = build_experiment._json_sha256(material)
        mutated_path = self.write_json("mutated-frame-plan.json", mutated)
        with self.assertRaisesRegex(CandidateControlError, "variants changed"):
            frame_qualification._load_plan(mutated_path)

    def test_same_source_aa_abba_throughput_p99_and_fairness_remain_provisional(self):
        plan, _row, baseline, candidate, aa1, aa2, comparison = self.prepared()
        qualification = frame_qualification.create_qualification(
            plan_path=plan,
            axis="adaptive",
            baseline_build_path=baseline,
            candidate_build_path=candidate,
            a_a_roots=[aa1, aa2],
            comparison_root=comparison,
        )
        self.assertEqual(qualification["status"], "PASS")
        self.assertEqual(
            qualification["adoption_decision"],
            "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        )
        self.assertFalse(qualification["performance_authoritative"])
        self.assertFalse(qualification["bare_metal_gate_satisfied"])
        self.assertFalse(qualification["durable_evidence_gate_satisfied"])
        self.assertEqual(len(qualification["a_a_rounds"]), 2)
        fields = {
            (row["scenario"], row["field"])
            for row in qualification["comparison"]["observations"]
        }
        self.assertEqual(
            fields,
            {
                ("tcp-bulk", "value"),
                ("tcp-request-1k", "value"),
                ("tcp-scale-10k", "value"),
                ("tcp-scale-10k", "scale.fairness.jain_ppb"),
                ("tcp-scale-10k", "scale.fairness.p01_to_median_ppm"),
            },
        )

    def test_artifact_pair_schedule_host_and_schema_mutations_fail_closed(self):
        plan, _row, baseline, candidate, aa1, aa2, comparison = self.prepared()
        candidate_row = json.loads(candidate.read_text(encoding="utf-8"))
        pathlib.Path(candidate_row["artifacts"][0]["path"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(CandidateControlError, "changed after build"):
            frame_qualification.create_qualification(
                plan_path=plan,
                axis="adaptive",
                baseline_build_path=baseline,
                candidate_build_path=candidate,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
            )

        # Restore the artifact, then reject a claimed order and host mutation.
        pathlib.Path(candidate_row["artifacts"][0]["path"]).write_bytes(
            b"adaptive-ferrum2-client"
        )
        path = next((comparison / "parent").glob("tcp-bulk-*.jsonl"))
        row = json.loads(path.read_text(encoding="utf-8"))
        row["order"] = 2 if row["order"] == 1 else 1
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "trial identity"):
            frame_qualification.create_qualification(
                plan_path=plan,
                axis="adaptive",
                baseline_build_path=baseline,
                candidate_build_path=candidate,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
            )
        row["order"] = 1 if row["pair"] % 2 == 1 else 2
        row["cpu_model"] = "Intel fixture"
        row["environment_identity"]["cpu_model"] = "Intel fixture"
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CandidateControlError, "AMD"):
            frame_qualification.create_qualification(
                plan_path=plan,
                axis="adaptive",
                baseline_build_path=baseline,
                candidate_build_path=candidate,
                a_a_roots=[aa1, aa2],
                comparison_root=comparison,
            )

        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["schema_version"] = "ferrum2-performance-frame-policy-v0"
        with self.assertRaisesRegex(CandidateControlError, "unsupported"):
            frame_qualification._load_policy(self.write_json("old-policy.json", policy))

    def test_independent_owner_is_excluded_without_changing_marker_count(self):
        self.assertIn(
            "frame_qualification.py", _TIMED_V6_EXCLUDED_CONTROLLER_FILES
        )
        cli = pathlib.Path("tools/performance_candidate/cli.py").read_bytes()
        self.assertEqual(cli.count(_DIAGNOSTIC_BEGIN), 3)
        self.assertEqual(cli.count(_DIAGNOSTIC_END), 3)

    def test_reusable_workflow_is_amd_fail_closed_and_uploads_before_enforcement(self):
        workflow = pathlib.Path(
            ".github/workflows/performance-frame.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("  workflow_call:\n", workflow)
        self.assertIn("      axis:\n", workflow)
        self.assertIn("vendor_id\" != AuthenticAMD", workflow)
        self.assertIn('["default32","frame16k","frame65535","adaptive"]', workflow)
        self.assertIn(
            'run_schedule "$FRAME_PROFILE_ROOT/aa-1" "$candidate_bin" "$candidate_bin"',
            workflow,
        )
        self.assertIn(
            'run_schedule "$FRAME_PROFILE_ROOT/aa-2" "$candidate_bin" "$candidate_bin"',
            workflow,
        )
        self.assertIn(
            'run_schedule "$FRAME_PROFILE_ROOT/comparison" "$baseline_bin" "$candidate_bin"',
            workflow,
        )
        self.assertIn("for pair in 1 2 3 4 5 6; do", workflow)
        self.assertIn("for scenario in tcp-bulk tcp-request-1k tcp-scale-10k; do", workflow)
        self.assertIn(
            'execution_dir="$GITHUB_WORKSPACE/target/profiling"', workflow
        )
        self.assertIn(
            'install -m 0755 "$source_dir/$artifact" "$FRAME_EXECUTION_DIR/$artifact"',
            workflow,
        )
        self.assertIn(
            'cmp -s "$source_dir/$artifact" "$FRAME_EXECUTION_DIR/$artifact"',
            workflow,
        )
        self.assertIn(
            '"$FRAME_EXECUTION_DIR/m4-qualification" profile-workload', workflow
        )
        self.assertIn('--binary-dir "$FRAME_EXECUTION_DIR"', workflow)
        self.assertNotIn('--binary-dir "$binary_dir"', workflow)
        upload = workflow.index("- name: Upload provisional AMD frame evidence")
        enforce = workflow.index("- name: Enforce non-authoritative hosted closure")
        self.assertLess(upload, enforce)


if __name__ == "__main__":
    unittest.main()
