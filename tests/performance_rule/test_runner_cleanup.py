import sys
import unittest
from unittest import mock

from tools.owned_process import Capture
from tools.performance_rule.failure import Category, Failure, Stage
from tools.performance_rule import runner_report


class RunnerCleanupTests(unittest.TestCase):
    def test_timeout_preserves_unconfirmed_cleanup_without_content(self):
        result = Capture(None, b"sensitive", b"sensitive", "timed_out", False)
        with mock.patch.object(runner_report, "capture", return_value=result):
            with self.assertRaises(Failure) as raised:
                runner_report._run_bounded(["unused"], timeout_seconds=1, creation_flags=0)
        failure = raised.exception
        self.assertEqual((failure.stage, failure.category), (Stage.RUNNER_CAPTURE, Category.TIMEOUT))
        self.assertIn({"stage": "runner_capture", "category": "cleanup_unconfirmed"}, failure.secondary)
        self.assertNotIn("sensitive", str(failure.diagnostics))

    def test_descendant_pipe_is_bounded_after_leader_exit(self):
        with mock.patch.object(runner_report, "RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS", 1):
            with self.assertRaises(Failure) as raised:
                runner_report._run_bounded(
                    [sys.executable, "-c", "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(2)'])"],
                    timeout_seconds=0.2, creation_flags=0,
                )
        self.assertEqual(raised.exception.category, Category.TIMEOUT)
        self.assertEqual(raised.exception.secondary, [])
