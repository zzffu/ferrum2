import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import RUNNER_ARGUMENTS, report
from tools.performance_rule.cli import control, emit_result
from tools.performance_rule.evidence import read_json_report, review_calibration_source
from tools.performance_rule.output import EvidenceLimit, encoded_size
from tools.performance_rule.schema import ControlError, INVALID, THRESHOLD_POLICY_VERSION
from tools.performance_rule.validated_report import validate_report


def run_checked(*args):
    return validate_report(report(args[4]), args[4])


def partial_report(result):
    result = copy.deepcopy(result)
    result.update(status=INVALID, decision_reason="evidence_budget_exceeded", comparisons=[])
    result["threshold_policy"] = {
        "version": THRESHOLD_POLICY_VERSION, "status": INVALID,
        "reviewed": False, "enforced": False, "gate_passed": False, "decision": "invalid",
    }
    return result


class EvidenceBudgetTests(unittest.TestCase):
    def test_output_checks_exact_bytes_before_replacing_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out.json"
            path.write_bytes(b"previous")
            value = {"synthetic": "small"}
            size = encoded_size(value)
            with mock.patch("tools.performance_rule.output.EVIDENCE_MAX_BYTES", size - 1), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(EvidenceLimit):
                    emit_result(value, path)
            self.assertEqual(path.read_bytes(), b"previous")
            stdout = io.StringIO()
            with mock.patch("tools.performance_rule.output.EVIDENCE_MAX_BYTES", size), contextlib.redirect_stdout(stdout):
                emit_result(value, path)
            self.assertEqual(path.read_bytes(), stdout.getvalue().encode("utf-8"))

    def test_collection_charges_each_report_and_retains_admitted_partial_evidence(self):
        self._check_collection(final_only=False)

    def test_final_summary_over_budget_preserves_all_collected_raw_reports(self):
        self._check_collection(final_only=True)

    def _check_collection(self, final_only):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-runner"
            executable.write_bytes(b"not executable")
            arguments = ["run", "--parent", str(executable), "--", *RUNNER_ARGUMENTS]
            with mock.patch("tools.performance_rule.cli.run_once", side_effect=run_checked), mock.patch("tools.performance_rule.cli.emit_result"):
                full = control(arguments)
            cap = encoded_size(partial_report(full)) if final_only else encoded_size(full) // 3
            output = root / "partial.json"
            arguments = ["run", "--parent", str(executable), "--output", str(output), "--", *RUNNER_ARGUMENTS]
            stdout = io.StringIO()
            with mock.patch("tools.performance_rule.output.EVIDENCE_MAX_BYTES", cap), mock.patch("tools.performance_rule.cli.run_once", side_effect=run_checked) as runner, contextlib.redirect_stdout(stdout):
                result = control(arguments)
            self.assertEqual(result["status"], INVALID)
            self.assertFalse(result["threshold_policy"]["enforced"])
            self.assertEqual(result["comparisons"], [])
            self.assertGreater(len(result["execution_trace"]), 0)
            retained = sum(len(pair) for pair in result["raw_pairs"])
            self.assertEqual(retained, len(result["execution_trace"]))
            if final_only:
                self.assertEqual((runner.call_count, retained), (12, 12))
            else:
                self.assertLess(runner.call_count, 12)
                self.assertEqual(runner.call_count, retained + 1)
            self.assertLessEqual(output.stat().st_size, cap)
            self.assertEqual(output.read_bytes(), stdout.getvalue().encode("utf-8"))
            self.assertEqual(read_json_report(output, "partial")[1], result)
            with self.assertRaises(ControlError):
                review_calibration_source(output, output_path=root / "reviewed.json", reviewed_by="synthetic", reviewed_utc="2026-09-05T00:00:00Z")

    def test_capture_limit_failure_keeps_previously_accepted_report(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / "fake"
            runner.write_bytes(b"not executable")
            calls = 0
            def bounded(*args):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise EvidenceLimit("synthetic capture limit")
                return run_checked(*args)
            with mock.patch("tools.performance_rule.cli.run_once", side_effect=bounded), mock.patch("tools.performance_rule.cli.emit_result") as emit:
                result = control(["run", "--parent", str(runner), "--", *RUNNER_ARGUMENTS])
            self.assertEqual(result["status"], INVALID)
            self.assertEqual(len(result["raw_pairs"][0]), 1)
            emit.assert_called_once_with(result, None)
