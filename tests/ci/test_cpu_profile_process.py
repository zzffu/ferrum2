"""Finite fake helpers only; never run CPU collectors or performance workloads."""

import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

from tools.cpu_profile.process import CleanupStatus, CommandStatus, ProcessOwner


@unittest.skipUnless(sys.platform == "linux", "Linux helper group ownership")
class CpuHelperProcessTests(unittest.TestCase):
    def run_helper(self, code, *, budget=2, byte_cap=128, interrupt_after=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        with ProcessOwner(cleanup_grace=0.15) as owner:
            result = owner.run(
                [sys.executable, "-c", code], deadline=time.monotonic() + budget,
                stdout=root / "out", stderr=root / "err", byte_cap=byte_cap,
                interrupt_after=interrupt_after,
            )
        return result, root

    def test_both_pipes_are_drained_without_exceeding_retention_cap(self):
        result, root = self.run_helper("import sys; print('x'*256); print('y'*256, file=sys.stderr)")
        self.assertEqual(result.status, CommandStatus.OUTPUT_LIMIT)
        self.assertLessEqual((root / "out").stat().st_size, 128)
        self.assertLessEqual((root / "err").stat().st_size, 128)

    def test_deadline_terminates_and_reaps_finite_helper(self):
        result, _root = self.run_helper("import time; time.sleep(1)", budget=0.05)
        self.assertEqual(result.status, CommandStatus.TIMED_OUT)
        self.assertIsNotNone(result.exit_code)

    def test_unreadable_process_table_keeps_timeout_and_cleanup_failure(self):
        with mock.patch("builtins.open", side_effect=PermissionError):
            result, _root = self.run_helper("import time; time.sleep(1)", budget=0.05)
        self.assertEqual(result.status, CommandStatus.TIMED_OUT)
        self.assertEqual(result.cleanup, CleanupStatus.UNCONFIRMED)

    def test_descendant_pipe_does_not_outlive_the_owner_deadline(self):
        result, _root = self.run_helper(
            "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(1)'])",
            budget=0.1,
        )
        self.assertEqual(result.status, CommandStatus.TIMED_OUT)
        self.assertIsNotNone(result.exit_code)

    def test_completed_helper_records_both_outputs(self):
        result, root = self.run_helper("import sys; print('out'); print('err', file=sys.stderr)")
        self.assertEqual(result.status, CommandStatus.COMPLETED)
        self.assertEqual((root / "out").read_bytes(), b"out\n")
        self.assertEqual((root / "err").read_bytes(), b"err\n")

    def test_wrapper_interruption_stops_its_helper(self):
        result, _root = self.run_helper(
            "import os,signal,time; os.kill(os.getppid(),signal.SIGTERM); time.sleep(1)"
        )
        self.assertEqual(result.status, CommandStatus.INTERRUPTED)
        self.assertIsNotNone(result.exit_code)

    def test_normal_collector_stop_is_distinct_from_deadline_failure(self):
        result, _root = self.run_helper(
            "import signal,sys,time; signal.signal(signal.SIGINT,lambda *args:sys.exit(0)); time.sleep(1)",
            interrupt_after=0.25,
        )
        self.assertEqual(result.status, CommandStatus.COMPLETED)
        self.assertEqual(result.exit_code, 0)


class CpuHelperAdmissionTests(unittest.TestCase):
    def test_cancelled_owner_does_not_start_a_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = ProcessOwner()
            owner.cancelled = True
            result = owner.run(
                [sys.executable, "-c", "raise AssertionError('must not run')"],
                deadline=time.monotonic() + 1, stdout=root / "out", stderr=root / "err",
            )
            self.assertEqual(result.status, CommandStatus.INTERRUPTED)
            self.assertEqual(list(root.iterdir()), [])

    def test_expired_deadline_does_not_start_a_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = ProcessOwner().run(
                [sys.executable, "-c", "raise AssertionError('must not run')"],
                deadline=time.monotonic() - 1, stdout=root / "out", stderr=root / "err",
            )
            self.assertEqual(result.status, CommandStatus.TIMED_OUT)
            self.assertEqual(list(root.iterdir()), [])
