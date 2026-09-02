import copy
import hashlib
import pathlib

from tests.performance_candidate._linux_summary_support import LinuxSummaryFixture
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import calibration as linux_calibration
from tools.performance_candidate.linux import decision as linux_decision
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import schedule as linux_schedule


class RunCalibrationTests(LinuxSummaryFixture):
    def calibration_evidence(
        self, plan: dict[str, object]
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        root, left, right = self.roots()
        deltas = (10, -10, 20, -20, 0, 30)
        values: dict[tuple[str, int, str], object] = {}
        for scenario in plan["scenarios"]:
            name = scenario["scenario"]
            for pair, delta in enumerate(deltas, start=1):
                values[(name, pair, "parent")] = 10_000
                values[(name, pair, "candidate")] = 10_000 + delta
        self.populate(plan, left, right, values)
        for path in right.glob("*.jsonl"):
            self.rewrite(
                path,
                lambda row: row.update(
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.PARENT_SHA,
                    sha=self.PARENT_SHA,
                    tree="3" * 40,
                    runner_sha256="a" * 64,
                    client_sha256="c" * 64,
                    server_sha256="e" * 64,
                ),
            )
        for path in left.glob("*.jsonl"):
            self.rewrite(
                path,
                lambda row: row.update(candidate_sha=self.PARENT_SHA),
            )
        return root, left, right

    def test_same_job_calibration_derives_conservative_applicable_policy(self) -> None:
        plan = self.plan("qualification", "tcp-bulk")
        root, left, right = self.calibration_evidence(plan)
        report, policy = linux_calibration.derive_run_calibration(
            plan=plan,
            left_root=left,
            right_root=right,
            baseline_sha=self.PARENT_SHA,
            source="artifact:github-actions/runs/123/attempts/1/self-calibration",
        )

        self.assertEqual(report["kind"], "performance_candidate_run_calibration")
        self.assertEqual(report["baseline_sha"], self.PARENT_SHA)
        self.assertEqual(len(report["scenarios"]), 2)
        for scenario in report["scenarios"]:
            self.assertEqual(scenario["noise_band_percent"], 0.5)
            self.assertEqual(scenario["adoption_threshold_percent"], 0.7)
            self.assertEqual(scenario["regression_threshold_percent"], -0.7)
            self.assertEqual(scenario["minimum_wins"], 5)
            self.assertEqual(scenario["minimum_losses"], 4)

        report_path = root / "calibration.json"
        policy_path = root / "policy.json"
        linux_calibration.write_run_calibration(
            report=report,
            policy=policy,
            report_output=report_path,
            policy_output=policy_path,
        )
        report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        loaded_policy = linux_policy.load_decision_policy(policy_path)
        for scenario in plan["scenarios"]:
            entry = loaded_policy["scenarios"][scenario["scenario"]]
            self.assertEqual(
                entry["calibration_source"],
                "artifact:github-actions/runs/123/attempts/1/self-calibration"
                f"@sha256:{report_sha}",
            )

        qualified_plan = self.plan(
            "qualification", "tcp-bulk", decision_policy=loaded_policy
        )
        _, parent, candidate = self.roots()
        self.populate(qualified_plan, parent, candidate)
        summary = linux_decision.summarize_evidence(
            plan=qualified_plan,
            parent_root=parent,
            candidate_root=candidate,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        self.assertEqual(summary["status"], "CANDIDATE_WIN")
        self.assertTrue(summary["adoption_claim"])

    def test_self_calibrated_schedule_interleaves_aa_and_ab_symmetrically(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-bulk")
        operations = linux_schedule.scenario_schedule(
            plan=plan,
            scenario="tcp-bulk",
            self_calibrated=True,
        )
        self.assertEqual(len(operations), 24)
        self.assertEqual(
            [
                (
                    operation["source"],
                    operation["evidence_directory"],
                    operation["member"],
                    operation["pair"],
                    operation["order"],
                    operation["comparison"],
                )
                for operation in operations[:8]
            ],
            [
                ("parent", "calibration-left", "parent", 1, 1, "aa"),
                ("parent", "calibration-right", "candidate", 1, 2, "aa"),
                ("parent", "paired", "parent", 1, 1, "ab"),
                ("candidate", "paired", "candidate", 1, 2, "ab"),
                ("candidate", "paired", "candidate", 2, 1, "ab"),
                ("parent", "paired", "parent", 2, 2, "ab"),
                ("parent", "calibration-right", "candidate", 2, 1, "aa"),
                ("parent", "calibration-left", "parent", 2, 2, "aa"),
            ],
        )
        ordinary = linux_schedule.scenario_schedule(
            plan=plan,
            scenario="tcp-bulk",
            self_calibrated=False,
        )
        self.assertEqual(len(ordinary), 12)
        self.assertTrue(
            all(operation["comparison"] == "ab" for operation in ordinary)
        )

    def test_calibration_rejects_changed_build_identity_and_environment(self) -> None:
        plan = self.plan("qualification", "tcp-bulk")
        _, left, right = self.calibration_evidence(plan)
        for path in right.glob("*.jsonl"):
            self.rewrite(path, lambda row: row.update(client_sha256="9" * 64))
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "identical build identities"
        ):
            linux_calibration.derive_run_calibration(
                plan=plan,
                left_root=left,
                right_root=right,
                baseline_sha=self.PARENT_SHA,
                source="artifact:test/calibration",
            )

        plan = self.plan("qualification", "tcp-bulk")
        _, left, right = self.calibration_evidence(plan)
        first = next(right.glob("*.jsonl"))
        self.rewrite(
            first,
            lambda row: (
                row.update(cpu_model="different-cpu"),
                row["environment_identity"].update(cpu_model="different-cpu"),
            ),
        )
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "runner environment changed"
        ):
            linux_calibration.derive_run_calibration(
                plan=plan,
                left_root=left,
                right_root=right,
                baseline_sha=self.PARENT_SHA,
                source="artifact:test/calibration",
            )

    def test_calibration_rejects_non_artifact_and_precalibrated_inputs(self) -> None:
        plan = self.plan("qualification", "tcp-bulk")
        _, left, right = self.calibration_evidence(plan)
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "artifact reference"
        ):
            linux_calibration.derive_run_calibration(
                plan=plan,
                left_root=left,
                right_root=right,
                baseline_sha=self.PARENT_SHA,
                source="local:test",
            )

        calibrated = copy.deepcopy(plan)
        calibrated["decision_policy"]["scenarios"]["udp-small-high"].update(
            {
                "noise_band_percent": 1.0,
                "regression_threshold_percent": -2.0,
                "adoption_threshold_percent": 2.0,
                "calibration_environment": {},
            }
        )
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "entirely uncalibrated"
        ):
            linux_calibration.derive_run_calibration(
                plan=calibrated,
                left_root=left,
                right_root=right,
                baseline_sha=self.PARENT_SHA,
                source="artifact:test/calibration",
            )
