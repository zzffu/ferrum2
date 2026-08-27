from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from support import TemporaryRepository
from tools.ci import change_contract, git_changes


class ChangeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = TemporaryRepository()
        self.addCleanup(self.repository.close)
        self.base = self.repository.commit_file("README.md", "baseline\n")

    def classify(self, event_name: str, base_sha: str, head_sha: str):
        return change_contract.classify(
            event_name=event_name,
            base_sha=base_sha,
            head_sha=head_sha,
            repository=self.repository.root,
        )

    def test_markdown_only_diff_skips_ordinary_gates(self) -> None:
        head = self.repository.commit_file("docs/guide.md", "documentation\n")

        decision = self.classify("push", self.base, head)

        self.assertFalse(decision.run_expensive)
        self.assertEqual(decision.changed_path_count, 1)

    def test_executable_docs_fixture_runs_ordinary_gates(self) -> None:
        head = self.repository.commit_file("docs/fixture.json", "{}\n")

        decision = self.classify("pull_request", self.base, head)

        self.assertTrue(decision.run_expensive)
        self.assertIn("non-Markdown", decision.reason)

    def test_source_renamed_to_markdown_still_runs_ordinary_gates(self) -> None:
        source = "crates/example/src/lib.rs"
        destination = "docs/retired.md"
        base = self.repository.commit_file(source, "pub fn active() {}\n")
        (self.repository.root / destination).parent.mkdir(parents=True, exist_ok=True)
        self.repository.git("mv", "--", source, destination)
        self.repository.git("commit", "--quiet", "-m", "retire source as documentation")
        head = self.repository.git("rev-parse", "HEAD")

        decision = self.classify("push", base, head)

        self.assertTrue(decision.run_expensive)
        self.assertEqual(decision.changed_path_count, 2)
        self.assertIn("non-Markdown", decision.reason)

    def test_markdown_renamed_to_source_runs_ordinary_gates(self) -> None:
        source = "docs/design.md"
        destination = "crates/example/src/design.rs"
        base = self.repository.commit_file(source, "design notes\n")
        (self.repository.root / destination).parent.mkdir(parents=True, exist_ok=True)
        self.repository.git("mv", "--", source, destination)
        self.repository.git("commit", "--quiet", "-m", "promote documentation to source")
        head = self.repository.git("rev-parse", "HEAD")

        decision = self.classify("push", base, head)

        self.assertTrue(decision.run_expensive)
        self.assertEqual(decision.changed_path_count, 2)
        self.assertIn("non-Markdown", decision.reason)

    def test_empty_diff_runs_ordinary_gates(self) -> None:
        decision = self.classify("push", self.base, self.base)

        self.assertTrue(decision.run_expensive)
        self.assertIn("empty diff", decision.reason)

    def test_manual_unknown_and_missing_ranges_fail_closed(self) -> None:
        cases = [
            ("workflow_dispatch", "", self.base),
            ("schedule", self.base, self.base),
            ("push", "", self.base),
            ("push", self.base, ""),
            ("push", "0" * 40, self.base),
            ("push", self.base, "0" * 40),
            ("push", "not-a-revision", self.base),
            ("push", self.base, "not-a-revision"),
            ("push", "f" * 40, self.base),
            ("push", self.base, "f" * 40),
        ]
        for event_name, base_sha, head_sha in cases:
            with self.subTest(event_name=event_name, base_sha=base_sha, head_sha=head_sha):
                decision = self.classify(event_name, base_sha, head_sha)
                self.assertTrue(decision.run_expensive)
                self.assertIn("fail closed", decision.reason)

    def test_nul_delimited_paths_preserve_embedded_newlines(self) -> None:
        success = subprocess.CompletedProcess([], 0, b"", b"")
        diff = subprocess.CompletedProcess(
            [], 0, b"docs/line\nbreak.md\0docs/second.md\0", b""
        )
        with mock.patch.object(git_changes, "_git", side_effect=[success, success, diff]):
            changes = git_changes.discover_changed_paths(
                self.repository.root,
                git_changes.ChangeRequest("push", self.base, self.base),
            )

        self.assertTrue(changes.complete)
        self.assertEqual(changes.paths, ("docs/line\nbreak.md", "docs/second.md"))

    def test_git_diff_failure_fails_closed(self) -> None:
        success = subprocess.CompletedProcess([], 0, b"", b"")
        failure = subprocess.CompletedProcess([], 1, b"", b"diff failed")
        with mock.patch.object(git_changes, "_git", side_effect=[success, success, failure]):
            decision = self.classify("push", self.base, self.base)

        self.assertTrue(decision.run_expensive)
        self.assertIn("could not be determined", decision.reason)

    def test_cli_writes_boolean_output_and_summary(self) -> None:
        head = self.repository.commit_file("README.md", "updated\n")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "github-output"
        summary = Path(temporary.name) / "github-summary"

        result = change_contract.main(
            [
                "--repository",
                str(self.repository.root),
                "--event-name",
                "push",
                "--base-sha",
                self.base,
                "--head-sha",
                head,
                "--github-output",
                str(output),
                "--github-summary",
                str(summary),
            ]
        )

        self.assertEqual(result, 0)
        self.assertEqual(output.read_text(encoding="utf-8"), "run_expensive=false\n")
        self.assertIn("every changed path is Markdown", summary.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
