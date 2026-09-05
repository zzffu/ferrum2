import io
import subprocess
import unittest
from unittest import mock

from tools.performance_rule.failure import Category, Failure, Stage
from tools.performance_rule import runner_report


class RunnerCleanupTests(unittest.TestCase):
    def check_cleanup(self, mode):
        process = mock.Mock()
        process.stdout, process.stderr = io.BytesIO(b"small"), io.BytesIO(b"small")
        timeout = subprocess.TimeoutExpired(["synthetic"], 1)
        waits = [0] if mode in ("start", "join") else [timeout, timeout if mode == "wait" else 0]

        def wait(*, timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, runner_report.RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS)
            result = waits.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        process.wait.side_effect = wait
        if mode == "kill":
            process.kill.side_effect = OSError("synthetic kill failure")
        threads = []

        class Reader:
            def __init__(self, *, target, args, daemon):
                self.target, self.args = target, args
                self.alive = False
                self.joins = []
                threads.append(self)

            def start(self):
                if mode == "start" and len(threads) == 2:
                    raise RuntimeError("synthetic second start failure")
                if mode == "join" and len(threads) == 1:
                    self.alive = True
                else:
                    self.target(*self.args)

            def join(self, timeout):
                self.joins.append(timeout)

            def is_alive(self):
                return self.alive

        with mock.patch("tools.performance_rule.runner_report.subprocess.Popen", return_value=process), mock.patch("tools.performance_rule.runner_report.threading.Thread", Reader), mock.patch("tools.performance_rule.runner_report.time.monotonic", side_effect=[10.0, 11.0, 12.0, 13.0, 14.0]):
            with self.assertRaises(Failure) as raised:
                runner_report._run_bounded(["synthetic"], timeout_seconds=1, creation_flags=0)
        failure = raised.exception
        if mode == "start":
            self.assertEqual((failure.stage, failure.category), (Stage.RUNNER_START, Category.INTERNAL))
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            self.assertTrue(threads[0].joins)
        else:
            self.assertEqual((failure.stage, failure.category), (Stage.RUNNER_CAPTURE, Category.TIMEOUT))
            self.assertIn({"stage": "runner_capture", "category": "cleanup_unconfirmed"}, failure.secondary)
        if mode == "join":
            self.assertNotIn("stdout", failure.diagnostics)
        for call in process.wait.call_args_list:
            self.assertEqual(call.args, ())
            self.assertEqual(set(call.kwargs), {"timeout"})
        remaining = [call.kwargs["timeout"] for call in process.wait.call_args_list[-1:]] if mode != "join" else []
        remaining.extend(value for reader in threads for value in reader.joins)
        self.assertEqual(remaining, sorted(remaining, reverse=True))

    def test_second_reader_start_failure_cleans_started_child_and_reader(self):
        self.check_cleanup("start")

    def test_kill_failure_preserves_timeout_and_reports_unconfirmed_cleanup(self):
        self.check_cleanup("kill")

    def test_second_wait_timeout_is_bounded_and_does_not_mask_primary(self):
        self.check_cleanup("wait")

    def test_incomplete_reader_join_never_reads_its_capture_slot(self):
        self.check_cleanup("join")
