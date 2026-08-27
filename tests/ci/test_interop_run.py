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
        self.assertEqual(calls[0][2:4], ("--target-dir", str(target)))
        self.assertNotIn("--features", calls[0])
        self.assertEqual(calls[1][0], str(target / "debug" / "m0-qualification"))
        self.assertEqual(calls[2][2:4], ("--target-dir", str(target)))
        self.assertIn("ferrum2-dns/__interop-test-root", calls[2])
        self.assertEqual(calls[3][0], str(target / "debug" / "m0-qualification"))
        self.assertEqual(calls[3][-1], "--dns-only")

    def test_main_returns_success_after_every_group_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)

            with mock.patch.object(subject, "execute", side_effect=lambda args: completed(args, 0)):
                with redirect_stdout(io.StringIO()):
                    status = subject.main(["--target-root", str(target)])

        self.assertEqual(status, 0)

    def test_mixed_failure_is_row_local_and_main_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            statuses = iter((17, 0, 0))
            calls: list[tuple[str, ...]] = []

            def execute(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                return completed(arguments, next(statuses))

            with mock.patch.object(subject, "execute", side_effect=execute):
                with redirect_stdout(io.StringIO()):
                    status = subject.main(["--target-root", str(target)])

        self.assertEqual(status, 1)
        self.assertEqual(len(calls), 3)
        self.assertIn("ferrum2-dns/__interop-test-root", calls[1])
        self.assertEqual(calls[2][0], str(target / "debug" / "m0-qualification"))

    def test_missing_build_root_returns_failure_without_starting_processes(self) -> None:
        with mock.patch.object(subject, "execute") as execute:
            with redirect_stdout(io.StringIO()):
                status = subject.main([])

        execute.assert_not_called()
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
