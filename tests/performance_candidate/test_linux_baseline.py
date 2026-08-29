import json
import pathlib

from tests.performance_candidate._linux_summary_support import structural_metrics
from tests.performance_candidate.test_build_experiment import (
    BuildExperimentFixture,
    CANDIDATE_SHA,
    PARENT_SHA,
)
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate import cli
from tools.performance_candidate.linux import (
    baseline,
    plan as linux_plan,
    policy as linux_policy,
)
from tools.performance_candidate.linux.trial import PROFILE_TRIAL_SCHEMA_VERSION


class LinuxBaselineTests(BuildExperimentFixture):
    def environment_path(self) -> pathlib.Path:
        return self.commit_environment_path()

    def policy_path(self) -> pathlib.Path:
        return (
            pathlib.Path(__file__).resolve().parents[2]
            / "tools"
            / "performance_candidate_policy.json"
        )

    def plan_path(
        self, selection: str, *, mode: str = "diagnostic"
    ) -> tuple[pathlib.Path, dict[str, object]]:
        policy = linux_policy.load_decision_policy(self.policy_path())
        plan = linux_plan.create_plan(
            mode=mode,
            selection=selection,
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            decision_policy=policy,
        )
        path = self.root / f"{selection}-plan.json"
        linux_plan.write_plan(path, plan)
        return path, plan

    def matrix(self, selection: str = "dns-cache-size-64", *, mode: str = "diagnostic"):
        plan_path, plan = self.plan_path(selection, mode=mode)
        environment_path = self.environment_path()
        matrix = baseline.create_baseline_matrix(
            plan_path=plan_path,
            policy_path=self.policy_path(),
            environment_path=environment_path,
            parent_sha=PARENT_SHA,
            candidate_sha=CANDIDATE_SHA,
            build_profile="current",
        )
        matrix_path = self.write_json("baseline-matrix.json", matrix)
        return matrix, matrix_path, plan, plan_path, environment_path

    @staticmethod
    def raw_row(plan: dict[str, object], row: dict[str, object]) -> dict[str, object]:
        scenario = row["scenario"]
        scenario_plan = next(
            entry for entry in plan["scenarios"] if entry["scenario"] == scenario
        )
        contract = scenario_plan["evidence_contract"]
        metric = scenario_plan["metric"]
        value = 100
        return {
            "schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
            "kind": "m18_profile_trial",
            "parent_sha": PARENT_SHA,
            "candidate_sha": CANDIDATE_SHA,
            "member": row["member"],
            "pair": row["pair"],
            "order": row["order"],
            "build_profile": "current",
            "scenario": scenario,
            "warmup_seconds": plan["warmup_seconds"],
            "active_seconds": plan["active_seconds"],
            "topology": scenario_plan["topology"],
            "application_payload_bytes": scenario_plan["application_payload_bytes"],
            "workload_scale": scenario_plan["workload_scale"],
            "socks_datagram_bytes": scenario_plan["socks_datagram_bytes"],
            "upstream_wire_bytes": scenario_plan["upstream_wire_bytes"],
            "sha": row["sha"],
            "tree": ("3" if row["member"] == "parent" else "4") * 40,
            "runner_sha256": "a" * 64,
            "client_sha256": ("b" if row["member"] == "parent" else "c") * 64,
            "server_sha256": ("d" if row["member"] == "parent" else "e") * 64,
            "rustc": "rustc 1.97.1 fixture",
            "kernel": "fixture-kernel",
            "cpu_model": "fixture-cpu",
            "cpu_count": 8,
            "memory_kib": 16_777_216,
            "metric": metric,
            "unit": contract["unit"],
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": value if metric == "p99_nanoseconds" else None,
            "io_completions": 0 if scenario.startswith("dns-cache-size-") else 2_000,
            "scale": None,
            "structural_metrics": structural_metrics(scenario),
            "producer_source_sha256": contract["producer_source_sha256"],
            "controller_source_sha256": contract["controller_source_sha256"],
            "semantic_recipe_sha256": contract["semantic_recipe_sha256"],
            "evidence_bundle_sha256": contract["evidence_bundle_sha256"],
            "environment_identity": {
                "runner_image": contract["runner_image"],
                "rustc": "rustc 1.97.1 fixture",
                "kernel": "fixture-kernel",
                "cpu_model": "fixture-cpu",
                "cpu_count": 8,
                "memory_kib": 16_777_216,
                "build_profile": "current",
            },
            "cleanup": contract["cleanup_contract"],
            "correctness": "PASS",
            "status": "PASS",
        }

    def materialize_artifacts(
        self, matrix: dict[str, object], plan: dict[str, object]
    ) -> pathlib.Path:
        root = self.root / "artifacts"
        for row in matrix["rows"]:
            for kind, relative in row["artifacts"].items():
                path = root / pathlib.Path(*pathlib.PurePosixPath(relative).parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                value = (
                    self.raw_row(plan, row)
                    if kind == "raw_jsonl"
                    else {"kind": kind, "status": "captured"}
                )
                path.write_text(
                    json.dumps(value, sort_keys=True, allow_nan=False) + "\n",
                    encoding="utf-8",
                )
        return root

    def test_structural_group_matrix_binds_every_scale_pair_and_artifact_kind(
        self,
    ) -> None:
        matrix, _matrix_path, plan, _plan_path, _environment = self.matrix(
            "structural-baseline-matrix", mode="qualification"
        )

        self.assertEqual(len(plan["scenarios"]), 11)
        self.assertEqual(len(matrix["rows"]), 11 * 6 * 2)
        self.assertEqual(
            set(matrix["artifacts"]["kinds"]), set(baseline.ARTIFACT_FILES)
        )
        self.assertFalse(matrix["decision_contract"]["adoption_claim"])
        self.assertIsNone(matrix["decision_contract"]["performance_conclusion"])
        self.assertEqual(matrix["build"]["cargo_profile"], "profiling")
        self.assertEqual(matrix["build"]["evidence_build_profile"], "current")

    def test_report_validates_raw_trials_and_hashes_all_artifacts(self) -> None:
        matrix, matrix_path, plan, plan_path, environment = self.matrix()
        artifact_root = self.materialize_artifacts(matrix, plan)

        report = baseline.create_baseline_report(
            matrix_path=matrix_path,
            plan_path=plan_path,
            policy_path=self.policy_path(),
            environment_path=environment,
            artifact_root=artifact_root,
        )

        self.assertEqual(len(report["rows"]), 12)
        self.assertTrue(report["decision_contract"]["results_are_observations_only"])
        for row in report["rows"]:
            self.assertEqual(set(row["artifacts"]), set(baseline.ARTIFACT_FILES))
            self.assertTrue(
                all(
                    len(artifact["sha256"]) == 64
                    for artifact in row["artifacts"].values()
                )
            )

    def test_report_fails_closed_for_missing_or_semantically_wrong_raw_artifact(
        self,
    ) -> None:
        matrix, matrix_path, plan, plan_path, environment = self.matrix()
        artifact_root = self.materialize_artifacts(matrix, plan)
        first = matrix["rows"][0]
        missing = artifact_root / pathlib.Path(
            *pathlib.PurePosixPath(first["artifacts"]["perf_stat"]).parts
        )
        missing.unlink()
        with self.assertRaisesRegex(CandidateControlError, "unavailable"):
            baseline.create_baseline_report(
                matrix_path=matrix_path,
                plan_path=plan_path,
                policy_path=self.policy_path(),
                environment_path=environment,
                artifact_root=artifact_root,
            )

        self.materialize_artifacts(matrix, plan)
        raw = artifact_root / pathlib.Path(
            *pathlib.PurePosixPath(first["artifacts"]["raw_jsonl"]).parts
        )
        value = json.loads(raw.read_text(encoding="utf-8"))
        value["scenario"] = "tcp-bulk"
        raw.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaises(CandidateControlError):
            baseline.create_baseline_report(
                matrix_path=matrix_path,
                plan_path=plan_path,
                policy_path=self.policy_path(),
                environment_path=environment,
                artifact_root=artifact_root,
            )

    def test_cli_writes_matrix_and_report_without_running_a_workload(self) -> None:
        plan_path, plan = self.plan_path("dns-cache-size-64")
        environment = self.environment_path()
        matrix_path = self.root / "cli-matrix.json"
        self.assertEqual(
            cli.main(
                [
                    "linux-baseline-matrix",
                    "--plan",
                    str(plan_path),
                    "--policy",
                    str(self.policy_path()),
                    "--environment",
                    str(environment),
                    "--parent-sha",
                    PARENT_SHA,
                    "--candidate-sha",
                    CANDIDATE_SHA,
                    "--build-profile",
                    "current",
                    "--output",
                    str(matrix_path),
                ]
            ),
            0,
        )
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        artifact_root = self.materialize_artifacts(matrix, plan)
        report_path = self.root / "cli-report.json"
        self.assertEqual(
            cli.main(
                [
                    "linux-baseline-report",
                    "--matrix",
                    str(matrix_path),
                    "--plan",
                    str(plan_path),
                    "--policy",
                    str(self.policy_path()),
                    "--environment",
                    str(environment),
                    "--artifact-root",
                    str(artifact_root),
                    "--output",
                    str(report_path),
                ]
            ),
            0,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], baseline.REPORT_SCHEMA_VERSION)


if __name__ == "__main__":
    import unittest

    unittest.main()
