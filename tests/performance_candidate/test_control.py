#!/usr/bin/env python3
"""Behavior tests for the manual performance candidate control plane."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from decimal import Decimal

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "performance_candidate.py"
SPEC = importlib.util.spec_from_file_location("performance_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class MeasurementInputTests(unittest.TestCase):
    def test_every_workflow_choice_is_valid(self) -> None:
        for warmup in ("1", "3", "5", "10"):
            for active in ("15", "30", "60"):
                for pairs in ("3", "5"):
                    self.assertEqual(
                        CONTROL.validate_measurement_inputs(warmup, active, pairs),
                        (int(warmup), int(active), int(pairs)),
                    )

    def test_each_measurement_input_rejects_invalid_values_independently(self) -> None:
        cases = (
            ("2", "15", "3", "warmup_seconds"),
            ("1", "45", "3", "active_seconds"),
            ("1", "15", "4", "pairs"),
            ("01", "15", "3", "warmup_seconds"),
            ("one", "15", "3", "warmup_seconds"),
        )
        for warmup, active, pairs, field in cases:
            with self.subTest(field=field, value=(warmup, active, pairs)):
                with self.assertRaisesRegex(CONTROL.CandidateControlError, field):
                    CONTROL.validate_measurement_inputs(warmup, active, pairs)


class ScenarioPlanTests(unittest.TestCase):
    def plan(self, mode: str, scenario: str) -> dict[str, object]:
        return CONTROL.create_plan(
            mode=mode,
            scenario=scenario,
            warmup_seconds="3",
            active_seconds="30",
            pairs="3",
        )

    def entries(self, mode: str, scenario: str) -> list[tuple[str, str]]:
        return [
            (entry["scenario"], entry["role"])
            for entry in self.plan(mode, scenario)["scenarios"]
        ]

    def test_diagnostic_plan_contains_only_the_selected_scenario(self) -> None:
        for scenario in CONTROL.SCENARIO_CATALOG:
            with self.subTest(scenario=scenario):
                plan = self.plan("diagnostic", scenario)
                self.assertEqual(
                    self.entries("diagnostic", scenario),
                    [(scenario, "diagnostic")],
                )
                self.assertFalse(plan["adoption_eligible"])
                self.assertFalse(plan["decision_policy"]["candidate_win_enabled"])
                self.assertIsNone(plan["decision_policy"]["noise_threshold_percent"])

    def test_tcp_throughput_qualification_adds_the_other_guard(self) -> None:
        self.assertEqual(
            self.entries("qualification", "tcp-stream-64k"),
            [("tcp-stream-64k", "primary"), ("tcp-bulk", "guard")],
        )
        self.assertEqual(
            self.entries("qualification", "tcp-bulk"),
            [("tcp-bulk", "primary"), ("tcp-stream-64k", "guard")],
        )

    def test_tcp_request_qualification_runs_all_requests_and_bulk_guard(self) -> None:
        entries = self.entries("qualification", "tcp-request-4k")
        self.assertEqual(entries[0], ("tcp-request-4k", "primary"))
        self.assertEqual(
            set(entries[1:]),
            {
                ("tcp-request-1k", "guard"),
                ("tcp-request-16k", "guard"),
                ("tcp-bulk", "guard"),
            },
        )

    def test_udp_qualification_runs_both_udp_scenarios(self) -> None:
        self.assertEqual(
            self.entries("qualification", "udp-small-high"),
            [("udp-small-high", "primary"), ("udp-mtu-1200", "guard")],
        )

    def test_invalid_mode_and_scenario_are_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "mode"):
            self.plan("adopt", "tcp-bulk")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "scenario"):
            self.plan("qualification", "tcp-unknown")


class EvidenceSummaryTests(unittest.TestCase):
    PARENT_SHA = "1" * 40
    CANDIDATE_SHA = "2" * 40

    def setUp(self) -> None:
        self.owners: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for owner in reversed(self.owners):
            owner.cleanup()

    def plan(self, mode: str, scenario: str) -> dict[str, object]:
        return CONTROL.create_plan(
            mode=mode,
            scenario=scenario,
            warmup_seconds="3",
            active_seconds="30",
            pairs="3",
        )

    def roots(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        owner = tempfile.TemporaryDirectory(prefix="ferrum2-performance-evidence-")
        self.owners.append(owner)
        root = pathlib.Path(owner.name)
        parent = root / "parent"
        candidate = root / "candidate"
        parent.mkdir()
        candidate.mkdir()
        return root, parent, candidate

    def row(
        self,
        plan: dict[str, object],
        scenario: str,
        pair: int,
        member: str,
        *,
        value: object | None = None,
    ) -> dict[str, object]:
        metric, direction, _family = CONTROL.SCENARIO_CATALOG[scenario]
        if value is None:
            if member == "parent":
                value = 100
            else:
                value = 110 if direction == "higher_is_better" else 90
        order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        sha = self.PARENT_SHA if member == "parent" else self.CANDIDATE_SHA
        member_digit = "a" if member == "parent" else "b"
        return {
            "kind": "m18_profile_trial",
            "parent_sha": self.PARENT_SHA,
            "candidate_sha": self.CANDIDATE_SHA,
            "member": member,
            "pair": pair,
            "order": order,
            "build_profile": "current",
            "scenario": scenario,
            "warmup_seconds": plan["warmup_seconds"],
            "active_seconds": plan["active_seconds"],
            "sha": sha,
            "tree": ("3" if member == "parent" else "4") * 40,
            "runner_sha256": member_digit * 64,
            "client_sha256": ("c" if member == "parent" else "d") * 64,
            "server_sha256": ("e" if member == "parent" else "f") * 64,
            "rustc": "rustc 1.97.1 test",
            "kernel": "test-kernel",
            "cpu_model": "test-cpu",
            "cpu_count": 8,
            "memory_kib": 16_777_216,
            "metric": metric,
            "value": value,
            "checked_units": 1_000,
            "p99_nanoseconds": value if metric == "p99_nanoseconds" else None,
            "io_completions": 2_000,
            "correctness": "PASS",
            "status": "PASS",
        }

    def populate(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
        values: dict[tuple[str, int, str], object] | None = None,
    ) -> None:
        values = values or {}
        for scenario in plan["scenarios"]:
            name = scenario["scenario"]
            for pair in range(1, plan["pairs"] + 1):
                for member, root in (
                    ("parent", parent_root),
                    ("candidate", candidate_root),
                ):
                    value = values.get((name, pair, member))
                    row = self.row(plan, name, pair, member, value=value)
                    (root / f"{name}-{member}-{pair}.jsonl").write_text(
                        json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
                        encoding="utf-8",
                    )

    def summarize(
        self,
        plan: dict[str, object],
        parent_root: pathlib.Path,
        candidate_root: pathlib.Path,
    ) -> dict[str, object]:
        return CONTROL.summarize_evidence(
            plan=plan,
            parent_root=parent_root,
            candidate_root=candidate_root,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

    @staticmethod
    def rewrite(path: pathlib.Path, change) -> None:
        row = json.loads(path.read_text(encoding="utf-8"))
        change(row)
        path.write_text(
            json.dumps(row, sort_keys=True, allow_nan=True) + "\n",
            encoding="utf-8",
        )

    def fresh_diagnostic(self) -> tuple[dict[str, object], pathlib.Path, pathlib.Path]:
        plan = self.plan("diagnostic", "tcp-bulk")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        return plan, parent, candidate

    def test_diagnostic_dry_run_is_measured_without_adoption_claim(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertFalse(summary["adoption_claim"])
        self.assertEqual(summary["scenarios"][0]["median_improvement_percent"], 10.0)

    def test_diagnostic_regression_is_reported_as_measurement_not_adoption_decision(
        self,
    ) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair in range(1, plan["pairs"] + 1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row: row.update(value=10),
            )
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertEqual(summary["scenarios"][0]["losses"], 3)
        self.assertFalse(summary["adoption_claim"])

    def test_parent_then_candidate_and_candidate_then_parent_are_paired_by_member(
        self,
    ) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        pairs = self.summarize(plan, parent, candidate)["scenarios"][0]["pairs"]
        self.assertEqual(
            (pairs[0]["parent_order"], pairs[0]["candidate_order"]), (1, 2)
        )
        self.assertEqual(
            (pairs[1]["parent_order"], pairs[1]["candidate_order"]), (2, 1)
        )
        self.assertTrue(all(pair["improvement_percent"] == 10.0 for pair in pairs))

    def test_higher_and_lower_is_better_metrics_use_positive_for_improvement(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-request-1k")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summaries = {
            item["scenario"]: item
            for item in self.summarize(plan, parent, candidate)["scenarios"]
        }
        self.assertEqual(summaries["tcp-bulk"]["median_improvement_percent"], 10.0)
        self.assertEqual(
            summaries["tcp-request-1k"]["median_improvement_percent"], 10.0
        )

    def test_odd_pair_median_is_calculated_after_each_pair_delta(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair, value in enumerate((110, 130, 120), start=1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row, value=value: row.update(value=value),
            )
        scenario = self.summarize(plan, parent, candidate)["scenarios"][0]
        self.assertEqual(scenario["median_improvement_percent"], 20.0)
        self.assertEqual(scenario["minimum_improvement_percent"], 10.0)
        self.assertEqual(scenario["maximum_improvement_percent"], 30.0)

    def test_wins_losses_and_ties_use_unrounded_pair_deltas(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        for pair, value in enumerate((110, 90, 100), start=1):
            self.rewrite(
                candidate / f"tcp-bulk-candidate-{pair}.jsonl",
                lambda row, value=value: row.update(value=value),
            )
        scenario = self.summarize(plan, parent, candidate)["scenarios"][0]
        self.assertEqual(
            (scenario["wins"], scenario["losses"], scenario["ties"]),
            (1, 1, 1),
        )
        self.assertEqual(scenario["median_improvement_percent"], 0.0)

    def test_even_median_averages_the_two_middle_deltas(self) -> None:
        self.assertEqual(
            CONTROL._median(
                [Decimal("-10"), Decimal("40"), Decimal("20"), Decimal("30")]
            ),
            Decimal("25"),
        )

    def test_guard_regression_fails_qualification_even_when_primary_wins(self) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): 4 for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        scenarios = {item["scenario"]: item for item in summary["scenarios"]}
        self.assertEqual(summary["status"], "REGRESSION")
        self.assertEqual(scenarios["tcp-stream-64k"]["wins"], 3)
        self.assertEqual(scenarios["tcp-bulk"]["losses"], 3)
        self.assertEqual(scenarios["tcp-bulk"]["median_improvement_percent"], -96.0)

    def test_negative_guard_median_is_regression_even_with_one_positive_pair(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        _root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", 1, "candidate"): 4,
            ("tcp-bulk", 2, "candidate"): 4,
            ("tcp-bulk", 3, "candidate"): 101,
        }
        self.populate(plan, parent, candidate, values)
        summary = self.summarize(plan, parent, candidate)
        guard = next(
            item for item in summary["scenarios"] if item["scenario"] == "tcp-bulk"
        )
        self.assertEqual(summary["status"], "REGRESSION")
        self.assertEqual(guard["median_improvement_percent"], -96.0)

    def test_multi_scenario_qualification_dry_run_is_measured_without_threshold(
        self,
    ) -> None:
        plan = self.plan("qualification", "udp-small-high")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        summary = self.summarize(plan, parent, candidate)
        self.assertEqual(summary["status"], "MEASURED")
        self.assertFalse(summary["adoption_claim"])

    def test_missing_mandatory_guard_is_invalid(self) -> None:
        plan = self.plan("qualification", "udp-small-high")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        for root in (parent, candidate):
            for path in root.glob("udp-mtu-1200-*.jsonl"):
                path.unlink()
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "incomplete"):
            self.summarize(plan, parent, candidate)

    def test_missing_duplicate_mismatched_and_failed_rows_are_invalid(self) -> None:
        mutations = {
            "missing candidate": lambda _plan, _parent, candidate: (
                candidate / "tcp-bulk-candidate-1.jsonl"
            ).unlink(),
            "duplicate row": lambda _plan, parent, _candidate: (
                parent / "duplicate.jsonl"
            ).write_text(
                (parent / "tcp-bulk-parent-1.jsonl").read_text(encoding="utf-8"),
                encoding="utf-8",
            ),
            "wrong scenario": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(scenario="udp-small-high"),
            ),
            "wrong pair": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-2.jsonl",
                lambda row: row.update(pair=1),
            ),
            "correctness failure": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(correctness="FAIL"),
            ),
            "status failure": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(status="FAIL"),
            ),
            "same order": lambda _plan, _parent, candidate: self.rewrite(
                candidate / "tcp-bulk-candidate-1.jsonl",
                lambda row: row.update(order=1),
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                plan, parent, candidate = self.fresh_diagnostic()
                mutate(plan, parent, candidate)
                with self.assertRaises(CONTROL.CandidateControlError):
                    self.summarize(plan, parent, candidate)

    def test_zero_non_numeric_negative_and_non_finite_baselines_are_invalid(
        self,
    ) -> None:
        for value in (
            0,
            "100",
            True,
            -1,
            100.0,
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            with self.subTest(value=repr(value)):
                plan, parent, candidate = self.fresh_diagnostic()
                self.rewrite(
                    parent / "tcp-bulk-parent-1.jsonl",
                    lambda row, value=value: row.update(value=value),
                )
                with self.assertRaises(CONTROL.CandidateControlError):
                    self.summarize(plan, parent, candidate)

    def test_wrong_metric_and_request_p99_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        self.rewrite(
            candidate / "tcp-bulk-candidate-1.jsonl",
            lambda row: row.update(metric="p99_nanoseconds"),
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "metric"):
            self.summarize(plan, parent, candidate)

        plan = self.plan("diagnostic", "tcp-request-1k")
        _root, parent, candidate = self.roots()
        self.populate(plan, parent, candidate)
        self.rewrite(
            candidate / "tcp-request-1k-candidate-1.jsonl",
            lambda row: row.update(p99_nanoseconds=91),
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "p99"):
            self.summarize(plan, parent, candidate)

    def test_duplicate_json_keys_are_invalid(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        path = candidate / "tcp-bulk-candidate-1.jsonl"
        text = path.read_text(encoding="utf-8").strip()
        path.write_text(text[:-1] + ', "status": "PASS"}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            CONTROL.CandidateControlError, "duplicate JSON key"
        ):
            self.summarize(plan, parent, candidate)

    def test_summary_command_writes_outputs_before_invalid_evidence_failure(
        self,
    ) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        root, parent, candidate = self.roots()
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 2)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "INVALID_EVIDENCE")
        self.assertIn("INVALID_EVIDENCE", markdown.read_text(encoding="utf-8"))

    def test_summary_command_writes_valid_machine_and_markdown_results(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        root = parent.parent
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 0)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "MEASURED")
        self.assertIn("| tcp-bulk |", markdown.read_text(encoding="utf-8"))

    def test_summary_command_returns_nonzero_after_writing_regression(self) -> None:
        plan = self.plan("qualification", "tcp-stream-64k")
        root, parent, candidate = self.roots()
        values = {
            ("tcp-bulk", pair, "candidate"): 4 for pair in range(1, plan["pairs"] + 1)
        }
        self.populate(plan, parent, candidate, values)
        plan_path = root / "plan.json"
        output = root / "performance-summary.json"
        markdown = root / "performance-summary.md"
        CONTROL.write_plan(plan_path, plan)
        arguments = type(
            "Arguments",
            (),
            {
                "plan": plan_path,
                "parent_root": parent,
                "candidate_root": candidate,
                "parent_sha": self.PARENT_SHA,
                "candidate_sha": self.CANDIDATE_SHA,
                "output": output,
                "markdown": markdown,
            },
        )()
        self.assertEqual(CONTROL.run_summary_command(arguments), 3)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8"))["status"],
            "REGRESSION",
        )


class GitRelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ferrum2-performance-git-")
        self.repository = pathlib.Path(self.temporary.name)
        self._git("init", "--quiet", "--initial-branch=main")
        self._git("config", "user.name", "Performance Test")
        self._git("config", "user.email", "performance@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        self.base = self._commit("base")
        self.direct = self._commit("direct")
        self.multiple = self._commit("multiple")
        self._git("switch", "--quiet", "--orphan", "unrelated")
        self.unrelated = self._commit("unrelated")
        self._git("switch", "--quiet", "main")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def _commit(self, message: str) -> str:
        self._git("commit", "--quiet", "--allow-empty", "-m", message)
        return self._git("rev-parse", "HEAD")

    def test_direct_and_multi_commit_candidates_are_accepted(self) -> None:
        self.assertEqual(
            CONTROL.validate_git_relation(self.repository, self.base, self.direct),
            (self.base, self.direct),
        )
        self.assertEqual(
            CONTROL.validate_git_relation(self.repository, self.base, self.multiple),
            (self.base, self.multiple),
        )
        self.assertEqual(
            CONTROL.validate_git_relation(
                self.repository, self.base.upper(), self.multiple.upper()
            ),
            (self.base, self.multiple),
        )

    def test_same_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "different"):
            CONTROL.validate_git_relation(self.repository, self.base, self.base)

    def test_unrelated_history_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(self.repository, self.base, self.unrelated)

    def test_reverse_ancestry_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(self.repository, self.multiple, self.base)

    def test_missing_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "available commit"):
            CONTROL.validate_git_relation(self.repository, "f" * 40, self.multiple)

    def test_annotated_tag_object_is_not_accepted_as_a_commit_sha(self) -> None:
        self._git("tag", "--annotate", "candidate-tag", "--message", "candidate")
        tag_object = self._git("rev-parse", "candidate-tag")
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "available commit"):
            CONTROL.validate_git_relation(self.repository, self.base, tag_object)

    def test_shallow_history_without_parent_is_rejected(self) -> None:
        shallow_owner = tempfile.TemporaryDirectory(
            prefix="ferrum2-performance-shallow-"
        )
        self.addCleanup(shallow_owner.cleanup)
        shallow = pathlib.Path(shallow_owner.name) / "checkout"
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--depth=1",
                "--branch=main",
                self.repository.as_uri(),
                str(shallow),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "complete history"):
            CONTROL.validate_git_relation(shallow, self.base, self.multiple)


if __name__ == "__main__":
    unittest.main()
