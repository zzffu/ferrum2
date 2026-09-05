import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import RUNNER_ARGUMENTS
from tools.performance_rule import cli
from tools.performance_rule.failure import Category, Failure, Stage, classify
from tools.performance_rule.output import OutputCleanupFailures
from tools.performance_rule.runner_report import _run_bounded


SECRET = "synthetic-sensitive-sentinel-rtl6-7ce93"


class ClosedFailureTests(unittest.TestCase):
    def assert_redacted(self, stdout, stderr, root):
        for data in [stdout.getvalue().encode(), stderr.getvalue().encode(), *[p.read_bytes() for p in root.iterdir() if p.is_file()]]:
            self.assertNotIn(SECRET.encode(), data)
            self.assertNotIn(base64.b64encode(SECRET.encode()), data)

    def test_main_io_failure_does_not_echo_exception_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch("tools.performance_rule.cli.control", side_effect=OSError(5, SECRET)), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = cli.main(["run", "--parent", "unused", "--output", str(root / "out.json")])
            self.assertEqual(status, 2)
            self.assert_redacted(stdout, stderr, root)
            self.assertEqual(stderr.getvalue(), "rule qualification control failed: stage=preflight category=io\n")
            path, = root.glob("*.failure.*.json")
            document = json.loads(path.read_bytes())
            self.assertEqual(document["errno"], 5)
            self.assertEqual(path.name, "out.failure." + hashlib.sha256(path.read_bytes()).hexdigest() + ".json")
            self.assertEqual(set(document["diagnostics"]["exception"]), {"bytes", "sha256", "truncated"})

    def test_runner_stderr_and_invalid_report_remain_fingerprints(self):
        for returncode, raw, category in ((17, b"", "nonzero_exit"), (0, SECRET.encode(), "invalid_evidence")):
            with self.subTest(category=category), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                runner = root / "fake"
                runner.write_bytes(b"not executable")
                output = root / "out.json"
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch("tools.performance_rule.runner_report._run_bounded", return_value=(returncode, raw, SECRET.encode())), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    status = cli.main(["run", "--parent", str(runner), "--output", str(output), "--", *RUNNER_ARGUMENTS])
                self.assertEqual(status, 2)
                self.assert_redacted(stdout, stderr, root)
                path, = root.glob("*.failure.*.json")
                document = json.loads(path.read_bytes())
                self.assertEqual(document["category"], category)
                self.assertEqual(document["diagnostics"]["stderr"], {"bytes": len(SECRET), "sha256": hashlib.sha256(SECRET.encode()).hexdigest(), "truncated": False})
                self.assertEqual(document["identity"]["partial_report_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
                self.assertEqual(document["identity"]["runner_sha256"], hashlib.sha256(runner.read_bytes()).hexdigest())
                self.assertEqual((document["identity"]["pair"], document["identity"]["order"], document["identity"]["role"]), (1, 1, "parent"))

    def test_argparse_errors_do_not_reflect_arguments_and_help_still_works(self):
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            self.assertEqual(cli.main([SECRET]), 2)
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertNotIn(SECRET, stderr.getvalue() + stdout.getvalue())
        self.assertIn("usage:", stdout.getvalue())

    def test_no_output_does_not_persist_and_groups_are_closed(self):
        for error in (ExceptionGroup(SECRET, [OSError(SECRET)]), subprocess.TimeoutExpired([SECRET], 1)):
            with self.subTest(error=type(error).__name__), mock.patch("tools.performance_rule.cli.control", side_effect=error), mock.patch("tools.performance_rule.cli.persist_failure") as persist:
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(cli.main(["run", "--parent", "unused"]), 2)
                persist.assert_not_called()
                self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())

    def test_failure_artifact_write_error_preserves_primary_closed_category(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("tools.performance_rule.cli.control", side_effect=Failure(Stage.RUNNER_EXIT, Category.NONZERO_EXIT, exit_code=8)), mock.patch("tools.performance_rule.cli.persist_failure", side_effect=OSError(SECRET)), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(cli.main(["run", "--parent", "unused", "--output", "unused.json"]), 2)
        self.assertEqual(stderr.getvalue().splitlines(), ["rule qualification control failed: stage=runner_exit category=nonzero_exit", "rule qualification control failed: stage=output category=io"])

    def test_interruption_is_not_converted_to_an_internal_failure(self):
        for error in (KeyboardInterrupt(), BaseExceptionGroup(SECRET, [OSError(SECRET), KeyboardInterrupt()])):
            with mock.patch("tools.performance_rule.cli.control", side_effect=error):
                with self.assertRaises(KeyboardInterrupt):
                    cli.main(["run", "--parent", "unused"])

    def test_bounded_mock_capture_timeout_and_limit_have_closed_fingerprints(self):
        for timed_out in (False, True):
            process = mock.Mock()
            process.stdout = io.BytesIO(SECRET.encode())
            process.stderr = io.BytesIO(SECRET.encode())
            process.wait.side_effect = [subprocess.TimeoutExpired([SECRET], 1), 0] if timed_out else [0]
            with self.subTest(timed_out=timed_out), mock.patch("tools.performance_rule.runner_report.subprocess.Popen", return_value=process), mock.patch("tools.performance_rule.runner_report.RUNNER_STDOUT_MAX_BYTES", 8 if not timed_out else 128):
                with self.assertRaises(Failure) as raised:
                    _run_bounded(["mock"], timeout_seconds=1, creation_flags=0)
            self.assertEqual(raised.exception.stage, Stage.RUNNER_CAPTURE)
            self.assertEqual(raised.exception.category, Category.TIMEOUT if timed_out else Category.OUTPUT_LIMIT)
            self.assertNotIn(SECRET, str(raised.exception) + json.dumps(raised.exception.diagnostics))
            self.assertTrue(raised.exception.diagnostics["stdout"]["truncated"])

    def test_exception_fingerprint_is_bounded_and_marked_truncated(self):
        failure = classify(OSError("x" * 65_537), Stage.PREFLIGHT)
        self.assertEqual(failure.diagnostics["exception"], {"bytes": 65_536, "sha256": hashlib.sha256(b"x" * 65_536).hexdigest(), "truncated": True})

    def test_output_primary_and_owned_cleanup_remain_visible_without_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out.json"
            output.write_bytes(b"previous")
            real_replace, real_unlink = os.replace, os.unlink
            replace_calls, unlink_calls = 0, 0

            def replace(source, destination):
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 1:
                    raise OSError(SECRET)
                real_replace(source, destination)

            def unlink(path):
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_calls == 1:
                    raise OSError(SECRET)
                real_unlink(path)

            def fail_output(*args):
                cli._emit_result({"small": True}, output)

            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch("tools.performance_rule.cli.control", side_effect=fail_output), mock.patch("tools.performance_rule.output.os.replace", side_effect=replace), mock.patch("tools.performance_rule.output.os.unlink", side_effect=unlink), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(["run", "--parent", "unused", "--output", str(output)]), 2)
            self.assertEqual(output.read_bytes(), b"previous")
            self.assertEqual(stderr.getvalue().splitlines(), ["rule qualification control failed: stage=output category=io", "rule qualification control failed: stage=output category=cleanup_unconfirmed"])
            path, = root.glob("*.failure.*.json")
            document = json.loads(path.read_bytes())
            self.assertEqual((document["stage"], document["category"]), ("output", "io"))
            self.assertEqual(document["secondary"], [{"stage": "output", "category": "cleanup_unconfirmed"}])
            self.assert_redacted(stdout, stderr, root)

    def test_non_json_output_is_rejected_before_any_runner(self):
        with mock.patch("tools.performance_rule.cli.run_once") as runner:
            with self.assertRaises(Failure) as raised:
                cli.control(["run", "--parent", "unused", "--output", "wrong.txt"])
        runner.assert_not_called()
        self.assertEqual((raised.exception.stage, raised.exception.category), (Stage.ARGUMENTS, Category.INVALID_INPUT))

    def test_owned_cleanup_group_without_primary_keeps_output_stage(self):
        group = OutputCleanupFailures("output cleanup failed", [OSError(SECRET), OSError(SECRET)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch("tools.performance_rule.cli.control", side_effect=lambda *args: cli._emit_result({}, root / "out.json")), mock.patch("tools.performance_rule.cli.emit_result", side_effect=group), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(["run", "--parent", "unused", "--output", str(root / "out.json")]), 2)
            self.assertEqual(stderr.getvalue(), "rule qualification control failed: stage=output category=cleanup_unconfirmed\n")
            path, = root.glob("*.failure.*.json")
            document = json.loads(path.read_bytes())
            self.assertEqual((document["stage"], document["category"]), ("output", "cleanup_unconfirmed"))
            self.assert_redacted(stdout, stderr, root)
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with mock.patch("tools.performance_rule.cli.emit_result", side_effect=OutputCleanupFailures("output cleanup failed", [OSError(SECRET), interruption])):
                with self.assertRaises(type(interruption)) as raised:
                    cli._emit_result({}, None)
                self.assertIs(raised.exception, interruption)
