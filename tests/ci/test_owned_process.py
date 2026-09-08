"""Finite offline children only; no host processes or networking."""
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tools.owned_process import ProcessTree, capture


class OwnedProcessTests(unittest.TestCase):
    def run_capture(self, code, *, budget=2, cap=1024):
        return capture([sys.executable, "-c", code], deadline=time.monotonic() + budget,
                       stdout_cap=cap, stderr_cap=cap, cleanup_grace=1)

    def test_parent_exit_without_pipes_still_terminates_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "escaped"
            child = f"import time,pathlib; time.sleep(0.8); pathlib.Path({str(marker)!r}).write_text('escaped')"
            parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            result = self.run_capture(parent)
            self.assertTrue(result.cleanup_confirmed)
            self.assertEqual(result.returncode, 0)
            time.sleep(0.9)
            self.assertFalse(marker.exists())

    def test_descendant_pipe_deadline_confirms_cleanup(self):
        result = self.run_capture("import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(2)'])", budget=0.2)
        self.assertEqual(result.failure, "timed_out")
        self.assertTrue(result.cleanup_confirmed)

    def test_output_overflow_is_bounded_and_cleanup_confirmed(self):
        result = self.run_capture("import sys; print('x'*10000); print('y'*10000,file=sys.stderr)", cap=64)
        self.assertEqual(result.failure, "output_limit")
        self.assertLessEqual(len(result.stdout), 64)
        self.assertLessEqual(len(result.stderr), 64)
        self.assertTrue(result.cleanup_confirmed)

    @unittest.skipUnless(sys.platform == "linux", "Linux retained leader identity")
    def test_final_group_signal_precedes_reap(self):
        tree = ProcessTree.spawn([sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        try:
            while not tree.exited() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(tree.exited())
            original = os.killpg
            signals = []
            def owned_signal(group, number):
                self.assertEqual(group, tree.process.pid)
                self.assertIsNone(tree.process.returncode)
                self.assertIsNotNone(os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT))
                signals.append(number)
                original(group, number)
            with mock.patch("tools.owned_process.os.killpg", side_effect=owned_signal):
                self.assertTrue(tree.close(1))
            self.assertEqual(signals, [signal.SIGKILL])
        finally:
            if tree.process.returncode is None:
                tree.close(1)

    @unittest.skipUnless(sys.platform == "linux", "Linux process-table confirmation")
    def test_confirmation_failure_does_not_hide_timeout(self):
        with mock.patch.object(ProcessTree, "_group_live", side_effect=PermissionError):
            result = self.run_capture("import time; time.sleep(2)", budget=0.1)
        self.assertEqual(result.failure, "timed_out")
        self.assertFalse(result.cleanup_confirmed)
