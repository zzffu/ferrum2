#!/usr/bin/env python3
"""Behavior tests for the manual performance candidate control plane."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest


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
                self.assertIsNone(plan["decision_policy"])

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


class GitRelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ferrum2-performance-git-"
        )
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
            CONTROL.validate_git_relation(
                self.repository, self.base, self.direct
            ),
            (self.base, self.direct),
        )
        self.assertEqual(
            CONTROL.validate_git_relation(
                self.repository, self.base, self.multiple
            ),
            (self.base, self.multiple),
        )

    def test_same_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "different"):
            CONTROL.validate_git_relation(self.repository, self.base, self.base)

    def test_unrelated_history_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(
                self.repository, self.base, self.unrelated
            )

    def test_reverse_ancestry_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "not an ancestor"):
            CONTROL.validate_git_relation(
                self.repository, self.multiple, self.base
            )

    def test_missing_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(CONTROL.CandidateControlError, "available commit"):
            CONTROL.validate_git_relation(
                self.repository, "f" * 40, self.multiple
            )

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
