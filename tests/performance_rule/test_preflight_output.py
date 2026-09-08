import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import RUNNER_ARGUMENTS, RUNNER_SHA256, aa_source_report, write_json
from tools.performance_rule.cli import control, main
from tools.performance_rule.evidence import review_calibration_source
from tools.performance_rule.failure import Category, Failure, Stage
from tools.performance_rule.schema import ControlError
from tools.performance_rule.schema import sha256_file
from tools.performance_rule.validated_report import validate_report
from tests.performance_rule._fixture import report


class PreflightOutputTests(unittest.TestCase):
    def test_complete_calibration_preflight_rejects_without_runner(self):
        for failure in ("source_hash", "source_math", "arguments", "source_arguments", "priority", "source_priority", "runner", "threshold"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent, candidate = root / "parent", root / "candidate"
                parent.write_bytes(b"parent")
                candidate.write_bytes(b"candidate")
                source, calibration = root / "source.json", root / "calibration.json"
                raw = aa_source_report()
                raw["execution_policy"]["runner_process_priority"] = "normal"
                write_json(source, raw)
                reviewed = review_calibration_source(source, output_path=calibration, reviewed_by="synthetic", reviewed_utc="2026-09-05T00:00:00Z")
                arguments = list(RUNNER_ARGUMENTS)
                if failure == "source_hash":
                    raw["decision_reason"] = "changed"
                    write_json(source, raw)
                elif failure == "source_math":
                    raw["raw_pairs"][0]["parent"]["measurements"][0]["p50_ns_per_op"] += 1
                    write_json(source, raw)
                    reviewed["source_report_sha256"] = sha256_file(source)
                elif failure in ("arguments", "source_arguments"):
                    arguments = [*arguments, "--workspace-root", "different"]
                    if failure == "source_arguments":
                        reviewed["runner_arguments"] = arguments
                elif failure == "priority":
                    reviewed["execution_policy"]["runner_process_priority"] = "high"
                elif failure == "source_priority":
                    raw["execution_policy"]["runner_process_priority"] = "high"
                    write_json(source, raw)
                    reviewed["source_report_sha256"] = sha256_file(source)
                elif failure == "runner":
                    reviewed["runner_sha256"] = "c" * 64
                else:
                    reviewed["effective_median_limit_percent"] += 1
                write_json(calibration, reviewed)
                with mock.patch("tools.performance_rule.cli.sha256_file", side_effect=[RUNNER_SHA256, "b" * 64]), mock.patch("tools.performance_rule.cli.run_once") as runner:
                    with self.assertRaises(ControlError):
                        control(["run", "--parent", str(parent), "--candidate", str(candidate), "--calibration", str(calibration), "--runner-priority", "normal", "--", *arguments])
                    runner.assert_not_called()

    def test_first_runner_is_bound_to_calibration_source_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent, candidate = root / "parent", root / "candidate"
            parent.write_bytes(b"parent")
            candidate.write_bytes(b"candidate")
            source, calibration = root / "source.json", root / "calibration.json"
            raw = aa_source_report()
            raw["execution_policy"]["runner_process_priority"] = "normal"
            write_json(source, raw)
            write_json(calibration, review_calibration_source(source, output_path=calibration, reviewed_by="synthetic", reviewed_utc="2026-09-05T00:00:00Z"))
            changed = report(RUNNER_SHA256)
            changed["environment"]["cpu_model"] = "different"
            with mock.patch("tools.performance_rule.cli.sha256_file", side_effect=[RUNNER_SHA256, "b" * 64]), mock.patch("tools.performance_rule.cli.run_once", return_value=validate_report(changed, RUNNER_SHA256)) as runner, mock.patch("tools.performance_rule.cli.emit_result"):
                with self.assertRaises(Failure) as failure:
                    control(["run", "--parent", str(parent), "--candidate", str(candidate), "--calibration", str(calibration), "--runner-priority", "normal", "--", *RUNNER_ARGUMENTS])
                self.assertEqual(
                    (failure.exception.stage, failure.exception.category),
                    (Stage.RUNNER_REPORT, Category.INVALID_EVIDENCE),
                )
                self.assertEqual(runner.call_count, 1)

    def test_current_schema_unapproved_calibration_never_executes_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent, candidate, calibration = root / "parent", root / "candidate", root / "calibration.json"
            parent.write_bytes(b"parent")
            candidate.write_bytes(b"candidate")
            write_json(calibration, {"schema": "ferrum2.rule-qualification-calibration.v2"})
            with mock.patch("tools.performance_rule.cli.run_once", side_effect=AssertionError("runner executed")):
                with self.assertRaises(ControlError):
                    control(["run", "--parent", str(parent), "--candidate", str(candidate), "--calibration", str(calibration)])

    def test_review_in_another_directory_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            write_json(source, aa_source_report())
            output = root / "elsewhere" / "calibration.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main(["review-calibration", "--source-report", str(source), "--reviewed-by", "synthetic-review", "--reviewed-utc", "2026-09-05T00:00:00Z", "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())
