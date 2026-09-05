import json
import copy
import shutil

from tests.performance_candidate._linux_summary_support import LinuxSummaryFixture
from tests.performance_candidate._shared_fixture import synthetic_policy
from tools.performance_candidate import json_contract
from tools.performance_candidate import cli
from tools.performance_candidate.linux import aggregate as linux_aggregate
from tools.performance_candidate.linux import catalog as linux_catalog


class FullNonTunAggregateTests(LinuxSummaryFixture):
    def aggregate(self, root, *, producer_result="success"):
        return linux_aggregate.aggregate_summaries(
            summary_root=root, parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA, producer_result=producer_result,
        )

    def test_unsuccessful_producer_cannot_promote_uploaded_success(self) -> None:
        root = self.summaries()
        self.assertEqual(self.aggregate(root)["status"], "CANDIDATE_WIN")
        for result in ("failure", "cancelled", "skipped", "", "unknown"):
            with self.subTest(result=result):
                output = root.parent / "aggregate.json"
                markdown = root.parent / "aggregate.md"
                exit_code = cli.main([
                    "aggregate", "--summary-root", str(root),
                    "--parent-sha", self.PARENT_SHA,
                    "--candidate-sha", self.CANDIDATE_SHA,
                    "--producer-result", result,
                    "--output", str(output), "--markdown", str(markdown),
                ])
                self.assertNotEqual(exit_code, 0)
                invalid = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual((invalid["status"], invalid["adoption_claim"]), ("INVALID", False))
                self.assertTrue(markdown.is_file())

    def test_missing_nested_fields_write_invalid_outputs(self) -> None:
        root = self.summaries()
        path = root / "tcp-frame-capacity" / linux_aggregate.SUMMARY_FILE_NAME
        self.rewrite(path, lambda row: row.pop("decision_reason"))
        output = root.parent / "aggregate.json"
        markdown = root.parent / "aggregate.md"
        self.assertNotEqual(cli.main([
            "aggregate", "--summary-root", str(root),
            "--parent-sha", self.PARENT_SHA, "--candidate-sha", self.CANDIDATE_SHA,
            "--producer-result", "success", "--output", str(output),
            "--markdown", str(markdown),
        ]), 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "INVALID")

    def test_coherent_per_group_builds_must_agree_across_matrix(self) -> None:
        root = self.summaries()
        group = root / "dns-udp-concurrency"
        for path in (group / "ab-candidate").glob("*.jsonl"):
            self.rewrite(path, lambda row: row.update(client_sha256="9" * 64))
        plan = json.loads((group / "performance-plan.json").read_text(encoding="utf-8"))
        summary = self.summarize(plan, group / "ab-parent", group / "ab-candidate")
        (group / linux_aggregate.SUMMARY_FILE_NAME).write_text(json.dumps(summary), encoding="utf-8")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "build identities differ"):
            self.aggregate(root)

    def test_raw_trials_and_canonical_plan_are_required(self) -> None:
        root = self.summaries()
        group = root / "tcp-frame-capacity"
        plan_path = group / "performance-plan.json"
        original = plan_path.read_bytes()
        plan = json.loads(original)
        plan["scenarios"].pop()
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        with self.assertRaises(json_contract.CandidateControlError):
            self.aggregate(root)
        plan_path.write_bytes(original)
        next((group / "ab-parent").glob("*.jsonl")).unlink()
        with self.assertRaisesRegex(json_contract.CandidateControlError, "incomplete"):
            self.aggregate(root)

    def test_aggregate_rejects_incomplete_or_inconsistent_summary(self) -> None:
        mutations = {
            "scenario closure": lambda row: (
                row["scenarios"].pop(), row["mandatory_scenarios"].pop()
            ),
            "nested schema": lambda row: row["scenarios"][0].pop("pairs"),
            "top schema": lambda row: row.update(unexpected=1),
            "typed boolean": lambda row: row.update(candidate_win_enabled=1),
            "derived decision": lambda row: row["scenarios"][0].update(status="REGRESSION"),
            "build identity": lambda row: row["build_identities"]["parent"].update(tree="9" * 40),
        }
        root = self.summaries()
        path = root / "tcp-frame-capacity" / linux_aggregate.SUMMARY_FILE_NAME
        original = json.loads(path.read_text(encoding="utf-8"))
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                row = copy.deepcopy(original)
                mutate(row)
                path.write_text(json.dumps(row), encoding="utf-8")
                with self.assertRaises(json_contract.CandidateControlError):
                    linux_aggregate.aggregate_summaries(
                        summary_root=root, parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                        producer_result="success",
                    )

    def summaries(self, *, neutral: set[str] | None = None):
        root, _, _ = self.roots()
        root = root / "matrix"
        root.mkdir()
        policy = synthetic_policy(minimum_wins=5)
        neutral = neutral or set()
        for selection in linux_catalog.FULL_NON_TUN_GROUPS:
            plan = self.plan(
                "qualification", selection, decision_policy=policy
            )
            _, parent, candidate = self.roots()
            values = {}
            if selection in neutral:
                for scenario in plan["scenarios"]:
                    for pair in range(1, 7):
                        values[(scenario["scenario"], pair, "parent")] = 100
                        values[(scenario["scenario"], pair, "candidate")] = 100
            self.populate(plan, parent, candidate, values)
            summary = self.summarize(plan, parent, candidate)
            destination = root / selection / linux_aggregate.SUMMARY_FILE_NAME
            destination.parent.mkdir()
            shutil.copytree(parent, destination.parent / "ab-parent")
            shutil.copytree(candidate, destination.parent / "ab-candidate")
            (destination.parent / "performance-plan.json").write_text(
                json.dumps(plan), encoding="utf-8"
            )
            destination.write_text(
                json.dumps(summary, sort_keys=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        return root

    def test_full_matrix_adopts_when_one_group_wins_and_others_pass(self) -> None:
        neutral = set(linux_catalog.FULL_NON_TUN_GROUPS[1:])
        root = self.summaries(neutral=neutral)
        summary = linux_aggregate.aggregate_summaries(
            summary_root=root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
            producer_result="success",
        )

        self.assertEqual(summary["status"], "CANDIDATE_WIN")
        self.assertTrue(summary["adoption_claim"])
        self.assertEqual(
            [group["selection"] for group in summary["groups"]],
            list(linux_catalog.FULL_NON_TUN_GROUPS),
        )

    def test_full_matrix_reports_neutral_and_regression(self) -> None:
        root = self.summaries(neutral=set(linux_catalog.FULL_NON_TUN_GROUPS))
        neutral = linux_aggregate.aggregate_summaries(
            summary_root=root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
            producer_result="success",
        )
        self.assertEqual(neutral["status"], "WITHIN_CALIBRATED_BAND")

        path = root / "dns-udp-concurrency" / linux_aggregate.SUMMARY_FILE_NAME
        for raw in (path.parent / "ab-candidate").glob("*.jsonl"):
            self.rewrite(raw, lambda row: row.update(value=50))
        plan = json.loads((path.parent / "performance-plan.json").read_text(encoding="utf-8"))
        document = self.summarize(plan, path.parent / "ab-parent", path.parent / "ab-candidate")
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        regressed = linux_aggregate.aggregate_summaries(
            summary_root=root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
            producer_result="success",
        )
        self.assertEqual(regressed["status"], "REGRESSION")

    def test_full_matrix_rejects_missing_or_duplicate_groups(self) -> None:
        root = self.summaries()
        missing = root / "dns-udp-concurrency" / linux_aggregate.SUMMARY_FILE_NAME
        missing.unlink()
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "unable to read"
        ):
            linux_aggregate.aggregate_summaries(
                summary_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
                producer_result="success",
            )

        duplicate = root / "duplicate" / linux_aggregate.SUMMARY_FILE_NAME
        duplicate.parent.mkdir()
        original = root / "tcp-frame-capacity" / linux_aggregate.SUMMARY_FILE_NAME
        duplicate.write_bytes(original.read_bytes())
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "exactly one"
        ):
            linux_aggregate.aggregate_summaries(
                summary_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
                producer_result="success",
            )
