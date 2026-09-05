import pathlib
import tempfile
import unittest
from contextlib import nullcontext
from unittest import mock

from tools.performance_candidate import output


class AtomicOutputTests(unittest.TestCase):
    def test_failed_output_preserves_destination_and_removes_temporary(self) -> None:
        for operation in ("write", "flush", "fsync", "replace"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                destination = root / "result.json"
                destination.write_text("previous", encoding="utf-8")
                create = tempfile.NamedTemporaryFile

                def create_failing_file(**kwargs):
                    temporary = create(**kwargs)
                    if operation in {"write", "flush"}:
                        setattr(temporary, operation, mock.Mock(side_effect=OSError(operation)))
                    return temporary

                with mock.patch.object(output.tempfile, "NamedTemporaryFile", create_failing_file):
                    with mock.patch.object(output.os, operation, side_effect=OSError(operation)) \
                            if operation in {"fsync", "replace"} else nullcontext():
                        with self.assertRaises(OSError):
                            output._atomic_text(destination, "replacement")
                self.assertEqual(destination.read_text(encoding="utf-8"), "previous")
                self.assertEqual(list(root.iterdir()), [destination])

    def test_success_replaces_destination_without_temporary_residue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination = root / "result.json"
            output._atomic_text(destination, "new\n")
            self.assertEqual(destination.read_bytes(), b"new\n")
            self.assertEqual(list(root.iterdir()), [destination])
