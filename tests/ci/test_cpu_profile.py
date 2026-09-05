"""Offline CPU diagnostic contracts; never launch perf, Samply, or a workload."""

import gzip
import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import nullcontext
from unittest import mock

from tools.cpu_profile import evidence, record
from tools.cpu_profile.process import CleanupStatus, CommandResult, CommandStatus, private_file


class CpuEvidenceTests(unittest.TestCase):
    def test_fdopen_failure_closes_descriptor_and_removes_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact"
            descriptors = []
            real_open = os.open

            def acquire(*args):
                descriptor = real_open(*args)
                descriptors.append(descriptor)
                return descriptor

            with mock.patch("os.open", side_effect=acquire), mock.patch("os.fdopen", side_effect=OSError):
                with self.assertRaises(OSError):
                    private_file(path)
            self.assertFalse(path.exists())
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])

    def test_profile_container_is_not_sample_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "profile.gz"
            path.write_bytes(gzip.compress(b'{"threads":[]}'))
            result = evidence.validate_samply_container(path)
            self.assertEqual(result["sample_schema"], "unverified")
            self.assertEqual(result["container"], "gzip_json_object")

    def test_invalid_or_oversized_profile_container_is_rejected(self):
        cases = (
            b"fake-profile", b"\x1f\x8btruncated", gzip.compress(b"[]"),
            gzip.compress(b'{"x":1,"x":2}'), gzip.compress(b'{"x":NaN}'),
            gzip.compress(b'{"x":1e999}'), gzip.compress(b"\xff"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "profile.gz"
            for raw in cases:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.validate_samply_container(path)
            path.write_bytes(gzip.compress(b'{"payload":"123456789"}'))
            with self.assertRaisesRegex(evidence.EvidenceError, "decompressed_byte_limit"):
                evidence.validate_samply_container(path, decompressed_cap=8)
            with self.assertRaisesRegex(evidence.EvidenceError, "artifact_byte_limit"):
                evidence.validate_samply_container(path, compressed_cap=8)

    def test_perf_container_retains_unknown_schema_and_rejects_unavailable_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "perf.txt"
            path.write_text("1;task-clock\n", encoding="utf-8")
            self.assertEqual(evidence.validate_perf_container(path)["counter_schema"], "unverified")
            for raw in (b"", b"<not counted>;cycles:u", b"<not supported>;cycles:u", b"\xff"):
                path.write_bytes(raw)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_perf_container(path)


class FakeCollectors:
    def __init__(self, *, invalid_profile=False, fail_stage=None, cleanup=CleanupStatus.CONFIRMED):
        self.cancelled = False
        self.calls = []
        self.invalid_profile = invalid_profile
        self.fail_stage = fail_stage
        self.cleanup = cleanup

    def run(self, argv, *, deadline, stdout, stderr, **_options):
        self.calls.append(argv)
        text = b"tool identity\n"
        if argv[0] == "git" and "status" in argv:
            text = b""
        elif argv[:2] == ["samply", "--version"]:
            text = b"samply 0.13.1\n"
        elif "--help" in argv:
            text = b"--pid --duration --rate --save-only --output\n"
        elif argv[0] == "readelf":
            text = b"Build ID: 012345abcdef\n"
        elif argv[:2] == ["perf", "list"]:
            text = argv[-1].encode()
        elif argv[:2] == ["perf", "stat"] and "-o" in argv:
            with private_file(pathlib.Path(argv[argv.index("-o") + 1])) as stream:
                stream.write(b"1;task-clock\n")
        elif argv[:2] == ["samply", "record"]:
            with private_file(pathlib.Path(argv[argv.index("--output") + 1])) as stream:
                stream.write(b"fake-profile" if self.invalid_profile else gzip.compress(b'{"threads":[]}'))
        with private_file(stdout) as stream:
            stream.write(text)
        with private_file(stderr) as stream:
            stream.write(b"retained tool diagnostics")
        status = CommandStatus.TIMED_OUT if stdout.name.startswith(str(self.fail_stage) + ".") else CommandStatus.COMPLETED
        return CommandResult(status, 0, len(self.calls) * 10, len(self.calls) * 10 + 1, len(text), 25, cleanup=self.cleanup)


class CpuDiagnosticTests(unittest.TestCase):
    def collect(self, *, owner=None, observations=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        args = record.arguments([
            "--scenario", "tcp-bulk", "--role", "client", "--pid", "42",
            "--duration", "1", "--frequency", "99", "--output", "profiles/new",
        ])
        output = root / "output"
        output.mkdir()
        owner = owner or FakeCollectors()
        target = {"pid": 42, "start_ticks": 123, "exe_sha256": "a" * 64}
        modes = mock.patch.object(record.stat, "S_IMODE", return_value=0o600) if sys.platform != "linux" else nullcontext()
        with modes, mock.patch.object(record, "observe_target", side_effect=observations, return_value=target):
            result = record.capture(args, root, output, owner)
        return result, output, owner

    def test_completed_collection_is_explicitly_unverified(self):
        result, output, owner = self.collect()
        self.assertEqual(result["result"], "COLLECTED")
        self.assertEqual(result["evidence_validity"], "unverified")
        self.assertFalse(result["analysis_qualified"])
        self.assertFalse(result["adoption_claim"])
        self.assertIn("active_window_unbound", result["unverified_reasons"])
        self.assertEqual(json.loads((output / "metadata.json").read_text()), result)
        self.assertFalse((output / "metadata.txt").exists())
        self.assertNotIn("PASS", (output / "stage-status.txt").read_text())
        measured = [call[0] for call in owner.calls if "--output" in call or "-o" in call]
        self.assertEqual(measured, ["perf", "samply"])

    def test_fake_profile_cannot_be_collected_as_a_valid_container(self):
        result, output, _owner = self.collect(owner=FakeCollectors(invalid_profile=True))
        self.assertEqual((result["result"], result["error"]), ("FAILED", "invalid_gzip"))
        self.assertEqual((output / "samply.json.gz").read_bytes(), b"fake-profile")

    def test_helper_failure_keeps_error_evidence_and_stops_later_collectors(self):
        result, output, owner = self.collect(owner=FakeCollectors(fail_stage="perf-preflight"))
        self.assertEqual((result["result"], result["error"]), ("FAILED", "timed_out"))
        self.assertTrue((output / "perf-preflight.stderr.txt").is_file())
        self.assertFalse(any("--output" in call for call in owner.calls))

    def test_target_replacement_cannot_complete_collection(self):
        result, _output, owner = self.collect(observations=[{"pid": 42}, {"pid": 43}])
        self.assertEqual((result["result"], result["error"]), ("FAILED", "target_identity_changed"))
        self.assertFalse(any("-o" in call for call in owner.calls))

    def test_unconfirmed_cleanup_prevents_collection_without_erasing_primary_status(self):
        result, _output, _owner = self.collect(owner=FakeCollectors(cleanup=CleanupStatus.UNCONFIRMED))
        self.assertEqual((result["result"], result["error"]), ("FAILED", "cleanup_unconfirmed"))
        self.assertEqual((result["stages"][0]["status"], result["stages"][0]["cleanup"]),
                         ("completed", "unconfirmed"))
        timed_out, _output, _owner = self.collect(owner=FakeCollectors(
            fail_stage="git-head", cleanup=CleanupStatus.UNCONFIRMED,
        ))
        self.assertEqual(timed_out["error"], "timed_out")
        self.assertEqual((timed_out["stages"][0]["status"], timed_out["stages"][0]["cleanup"]),
                         ("timed_out", "unconfirmed"))

    def test_argument_overflow_is_rejected_before_any_collection(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            record.arguments([
                "--scenario", "tcp-bulk", "--role", "client", "--pid", "42",
                "--duration", "18446744073709551616", "--frequency", "1", "--output", "profiles/x",
            ])

    @unittest.skipUnless(sys.platform == "linux", "POSIX private mode contract")
    def test_output_is_new_private_and_confined_to_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = record.create_output(root, pathlib.Path("profiles/new"))
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for requested in (pathlib.Path("profiles/new"), pathlib.Path("../outside")):
                with self.assertRaises(evidence.EvidenceError):
                    record.create_output(root, requested)

    @unittest.skipUnless(sys.platform == "linux", "POSIX output ownership")
    def test_invalid_output_does_not_create_or_chmod_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with self.assertRaises(evidence.EvidenceError):
                record.create_output(root, root.parent / "outside-cpu-output")
            self.assertFalse((root / "profiles").exists())
            (root / "profiles").mkdir(mode=0o755)
            (root / "profiles").chmod(0o755)
            with self.assertRaises(evidence.EvidenceError):
                record.create_output(root, pathlib.Path("../outside-cpu-output"))
            self.assertEqual((root / "profiles").stat().st_mode & 0o777, 0o755)

    @unittest.skipUnless(sys.platform == "linux", "POSIX symlink ownership")
    def test_relative_dangling_output_link_is_resolved_against_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            profiles = root / "profiles"
            profiles.mkdir(mode=0o755)
            profiles.chmod(0o755)
            (profiles / "link").symlink_to("new-target", target_is_directory=True)
            with self.assertRaises(evidence.EvidenceError):
                record.create_output(root, pathlib.Path("profiles/link"))
            self.assertFalse((profiles / "new-target").exists())
            self.assertEqual(profiles.stat().st_mode & 0o777, 0o755)

    @unittest.skipUnless(sys.platform == "linux", "POSIX symlink ownership")
    def test_redirected_parent_cannot_create_an_external_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            root = base / "repo"
            root.mkdir()
            profiles = root / "profiles"
            profiles.mkdir(mode=0o755)
            profiles.chmod(0o755)
            outside = base / "external"
            outside.mkdir()
            (profiles / "parent").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(evidence.EvidenceError):
                record.create_output(root, profiles / "parent" / "new")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual(profiles.stat().st_mode & 0o777, 0o755)

    @unittest.skipUnless(sys.platform == "linux", "POSIX absolute output")
    def test_root_contained_absolute_output_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            requested = root / "profiles" / "new"
            self.assertEqual(record.create_output(root, requested), requested)
