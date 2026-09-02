import json

from tests.performance_candidate._linux_summary_support import LinuxSummaryFixture
from tests.performance_candidate._shared_fixture import synthetic_policy
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import aggregate as linux_aggregate
from tools.performance_candidate.linux import catalog as linux_catalog


class FullNonTunAggregateTests(LinuxSummaryFixture):
    def summaries(self, *, neutral: set[str] | None = None):
        root, _, _ = self.roots()
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
        )
        self.assertEqual(neutral["status"], "WITHIN_CALIBRATED_BAND")

        path = root / "dns-udp-concurrency" / linux_aggregate.SUMMARY_FILE_NAME
        document = json.loads(path.read_text(encoding="utf-8"))
        document["status"] = "REGRESSION"
        document["adoption_claim"] = False
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        regressed = linux_aggregate.aggregate_summaries(
            summary_root=root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        self.assertEqual(regressed["status"], "REGRESSION")

    def test_full_matrix_rejects_missing_or_duplicate_groups(self) -> None:
        root = self.summaries()
        missing = root / "dns-udp-concurrency" / linux_aggregate.SUMMARY_FILE_NAME
        missing.unlink()
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "exactly one"
        ):
            linux_aggregate.aggregate_summaries(
                summary_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

        duplicate = root / "duplicate" / linux_aggregate.SUMMARY_FILE_NAME
        duplicate.parent.mkdir()
        original = root / "tcp-frame-capacity" / linux_aggregate.SUMMARY_FILE_NAME
        duplicate.write_bytes(original.read_bytes())
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "duplicate selection"
        ):
            linux_aggregate.aggregate_summaries(
                summary_root=root,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )
