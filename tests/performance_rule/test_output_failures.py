import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.performance_rule.output import emit_result


class OutputFailureTests(unittest.TestCase):
    def test_fdopen_failure_closes_raw_descriptor_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.json"
            output.write_bytes(b"previous")
            captured = []
            failure = OSError("synthetic fdopen")

            def fail_open(handle, *args, **kwargs):
                captured.append(handle)
                raise failure

            try:
                with mock.patch("tools.performance_rule.output.os.fdopen", side_effect=fail_open), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(OSError) as raised:
                        emit_result({"small": True}, output)
                self.assertIs(raised.exception, failure)
                with self.assertRaises(OSError):
                    os.fstat(captured[0])
                self.assertEqual(output.read_bytes(), b"previous")
                self.assertEqual(list(Path(directory).iterdir()), [output])
            finally:
                # Avoid leaking the old implementation's descriptor in the red test.
                for handle in captured:
                    try:
                        os.close(handle)
                    except OSError:
                        pass
                for path in Path(directory).glob("*.tmp"):
                    path.unlink()

    def test_write_fsync_and_replace_failures_preserve_target_and_remove_temporary(self):
        real_fdopen = os.fdopen
        for operation in ("write", "fsync", "replace"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "out.json"
                output.write_bytes(b"previous")
                failure = OSError("synthetic " + operation)

                def open_failing_writer(*args, **kwargs):
                    stream = real_fdopen(*args, **kwargs)
                    stream.write = mock.Mock(side_effect=failure)
                    return stream

                patch = mock.patch("tools.performance_rule.output.os.fdopen", side_effect=open_failing_writer) if operation == "write" else mock.patch("tools.performance_rule.output.os." + operation, side_effect=failure)
                stdout = io.StringIO()
                with patch, contextlib.redirect_stdout(stdout):
                    with self.assertRaises(OSError) as raised:
                        emit_result({"small": True}, output)
                self.assertIs(raised.exception, failure)
                self.assertEqual(output.read_bytes(), b"previous")
                self.assertEqual(list(Path(directory).iterdir()), [output])
                self.assertEqual(stdout.getvalue(), "")

    def test_primary_and_cleanup_errors_are_both_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.json"
            primary, cleanup = OSError("synthetic replace"), OSError("synthetic unlink")
            with mock.patch("tools.performance_rule.output.os.replace", side_effect=primary), mock.patch("tools.performance_rule.output.os.unlink", side_effect=cleanup):
                with self.assertRaises(OSError) as raised:
                    emit_result({"small": True}, output)
            self.assertIs(raised.exception, primary)
            self.assertIn(cleanup, raised.exception.__cause__.exceptions)
