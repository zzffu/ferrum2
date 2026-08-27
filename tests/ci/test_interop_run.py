from __future__ import annotations

import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
import io
from pathlib import Path
from unittest import mock

from tools.ci import interop_run as subject


def completed(arguments: tuple[str, ...], status: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(arguments, status, f"status={status}\n")


class InteropRunTests(unittest.TestCase):
    def test_groups_share_one_runner_and_keep_distinct_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            calls: list[tuple[str, ...]] = []

            def execute(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                return completed(arguments, 0)

            with mock.patch.object(subject, "execute", side_effect=execute):
                with redirect_stdout(io.StringIO()):
                    results = subject.run_all(target)

        self.assertEqual([result.status for result in results], [0, 0])
        self.assertEqual(len(calls), 4)
        self.assertNotIn("--features", calls[0])
        self.assertEqual(calls[1][-1], str(target / "debug" / "m0-qualification"))
        self.assertIn("ferrum2-dns/__interop-test-root", calls[2])
        self.assertEqual(calls[3][-1], "--dns-only")

    def test_failure_is_row_local_and_later_group_still_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            statuses = iter((17, 0, 0))

            def execute(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
                return completed(arguments, next(statuses))

            with mock.patch.object(subject, "execute", side_effect=execute):
                with redirect_stdout(io.StringIO()):
                    results = subject.run_all(target)

        self.assertEqual(
            [(result.build_status, result.qualification_status) for result in results],
            [(17, subject.NOT_RUN), (0, 0)],
        )

    def test_missing_build_root_records_both_closed_failures(self) -> None:
        with mock.patch.object(subject, "execute") as execute:
            with redirect_stdout(io.StringIO()):
                results = subject.run_all(None)

        execute.assert_not_called()
        self.assertEqual([result.status for result in results], [subject.NOT_RUN] * 2)

    def test_github_environment_is_written_once_in_canonical_order(self) -> None:
        results = (
            subject.QualificationResult(subject.GROUPS[0], 0, 0),
            subject.QualificationResult(subject.GROUPS[1], 0, 23),
        )
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / "github-env"
            subject.write_github_environment(environment, results)
            lines = environment.read_text(encoding="utf-8").splitlines()

        self.assertEqual(
            lines,
            ["M3_INTEROP_TRANSPORT_STATUS=0", "M3_INTEROP_DNS_STATUS=23"],
        )


if __name__ == "__main__":
    unittest.main()
