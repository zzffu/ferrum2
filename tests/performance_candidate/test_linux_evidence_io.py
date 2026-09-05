import hashlib
import io
import json
import os
import pathlib
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from tests.performance_candidate._linux_summary_support import LinuxSummaryFixture
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import decision, trial


class LinuxEvidenceIoTests(LinuxSummaryFixture):
    def test_excess_evidence_stops_directory_iteration_and_closes_it(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        limit = len(plan["scenarios"]) * plan["pairs"]
        observed = []
        closed = []

        def entries():
            for index in range(limit + 1):
                observed.append(index)
                yield SimpleNamespace(name=f"trial-{index}.jsonl")
            self.fail("directory iteration continued after excess evidence")

        @contextmanager
        def scan(_path):
            try:
                yield entries()
            finally:
                closed.append(True)

        with mock.patch("os.scandir", scan):
            with self.assertRaisesRegex(json_contract.CandidateControlError, "too many JSONL"):
                self.summarize(plan, parent, candidate)
        self.assertEqual(observed, list(range(limit + 1)))
        self.assertEqual(closed, [True])

    def test_evidence_suffix_matching_preserves_host_case_semantics(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        path = parent / "tcp-bulk-parent-1.jsonl"
        path.rename(path.with_suffix(".JSONL"))
        if os.name == "nt":
            summary = self.summarize(plan, parent, candidate)
            self.assertIn("tcp-bulk-parent-1.JSONL",
                          [item["file"] for item in summary["evidence_files"]])
        else:
            with self.assertRaisesRegex(json_contract.CandidateControlError, "incomplete"):
                self.summarize(plan, parent, candidate)

    def test_extra_trial_files_fail_before_parsing(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        (parent / "extra.jsonl").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(json_contract.CandidateControlError, "too many JSONL"):
            self.summarize(plan, parent, candidate)

    def test_row_rejects_invalid_utf8_duplicate_keys_and_nonfinite_values(self) -> None:
        _root, parent, _candidate = self.roots()
        path = parent / "trial.jsonl"
        for raw in (b'\xff', b'{"x":1,"x":2}', b'{"x":NaN}', b'{}\n{}'):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(json_contract.CandidateControlError):
                    trial._read_trial(path)

    def test_summary_digest_binds_the_evaluated_bytes(self) -> None:
        plan, parent, candidate = self.fresh_diagnostic()
        path = candidate / "tcp-bulk-candidate-1.jsonl"
        original = path.read_bytes()
        validate = trial._validate_trial

        def validate_then_replace(row, **kwargs):
            result = validate(row, **kwargs)
            if result == ("tcp-bulk", 1, "candidate"):
                changed = json.loads(original)
                changed["value"] = 999
                path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
            return result

        with mock.patch.object(decision, "_validate_trial", validate_then_replace):
            summary = self.summarize(plan, parent, candidate)
        evidence = next(item for item in summary["evidence_files"]
                        if item["member"] == "candidate" and item["file"] == path.name)
        self.assertEqual(evidence["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(summary["scenarios"][0]["pairs"][0]["candidate_value"], 110)

    def test_growing_input_stops_at_the_read_cap(self) -> None:
        reads = []

        class GrowingFile(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)

        path = mock.Mock(spec=pathlib.Path)
        path.name = "trial.jsonl"
        path.stat.return_value = SimpleNamespace(st_size=1)
        path.open.return_value = GrowingFile(b" " * 20)
        path.read_bytes.return_value = b" " * 20
        with mock.patch.object(trial, "SCALE_TRIAL_MAX_BYTES", 8):
            with self.assertRaises(json_contract.CandidateControlError):
                trial._read_trial(path)
        self.assertEqual(reads, [10])  # Eight row bytes, optional newline, probe byte.

    def test_single_row_and_scenario_byte_caps_are_exact(self) -> None:
        _root, parent, _candidate = self.roots()
        path = parent / "trial.jsonl"
        row = {field: None for field in trial.PROFILE_FIELDS}
        row["scenario"] = "tcp-bulk"
        encoded = json.dumps(row).encode()
        with mock.patch.object(trial, "REGULAR_TRIAL_MAX_BYTES", len(encoded)):
            for ending in (b"", b"\n"):
                path.write_bytes(encoded + ending)
                parsed = trial._read_trial(path)
                self.assertEqual(parsed.value, row)
                self.assertEqual(parsed.sha256, hashlib.sha256(encoded + ending).hexdigest())
            for invalid in (encoded + b" \n", b"\n" + encoded,
                            encoded + b"\n\n", json.dumps(row, indent=2).encode()):
                path.write_bytes(invalid)
                with self.assertRaises(json_contract.CandidateControlError):
                    trial._read_trial(path)
