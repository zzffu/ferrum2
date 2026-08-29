import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import (
    RUNNER_ARGUMENTS,
    RUNNER_SHA256,
    SCENARIO_SUITES,
    aa_source_report,
    write_json,
)
from tools.performance_rule.cli import control
from tools.performance_rule.evidence import load_calibration, review_calibration_source
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CALIBRATION_SCHEMA,
    RUNNER_PRIORITY_HIGH,
    ControlError,
)


class CalibrationAndCliTests(unittest.TestCase):
    def test_review_cannot_approve_an_aa_suite_above_the_noise_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "noisy-aa-v7.json"
            report = aa_source_report()
            for pair in report["raw_pairs"]:
                for row in pair["candidate"]["measurements"]:
                    if row["suite"] == "snapshot_registry":
                        row["p50_ns_per_op"] = 111
            write_json(source, report)
            with self.assertRaisesRegex(ControlError, "snapshot_registry"):
                review_calibration_source(
                    source,
                    reviewed_by="test-reviewer",
                    reviewed_utc="2026-08-26T00:00:00Z",
                )

    def test_reviewed_calibration_is_separate_and_source_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "aa-v7.json"
            write_json(source, aa_source_report())
            calibration = root / "reviewed-calibration.json"
            write_json(
                calibration,
                {
                    "schema": CALIBRATION_SCHEMA,
                    "review_status": "APPROVED",
                    "reviewed_by": "test-reviewer",
                    "reviewed_utc": "2026-08-26T00:00:00Z",
                    "source_report": source.name,
                    "source_report_sha256": hashlib.sha256(
                        source.read_bytes()
                    ).hexdigest(),
                    "runner_sha256": RUNNER_SHA256,
                    "runner_arguments": RUNNER_ARGUMENTS,
                    "scenario_suites": SCENARIO_SUITES,
                    "execution_policy": {
                        "pair_order": "alternating_parent_candidate",
                        "raw_reports_retained": True,
                        "runner_process_priority": RUNNER_PRIORITY_HIGH,
                    },
                    "effective_median_limits_percent": {
                        "match_set": 5.0,
                        "snapshot_registry": 5.0,
                    },
                },
            )
            _, limit, digest = load_calibration(
                calibration,
                RUNNER_SHA256,
                SCENARIO_SUITES,
                RUNNER_ARGUMENTS,
                RUNNER_PRIORITY_HIGH,
            )
            self.assertEqual(
                limit,
                {"match_set": 5.0, "snapshot_registry": 5.0},
            )
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_ab_without_reviewed_calibration_stops_before_runner_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent.exe"
            candidate = root / "candidate.exe"
            parent.write_bytes(b"parent")
            candidate.write_bytes(b"candidate")
            with mock.patch(
                "tools.performance_rule.cli.run_once",
                side_effect=AssertionError("runner must not execute"),
            ):
                result = control(
                    [
                        "run",
                        "--parent",
                        str(parent),
                        "--candidate",
                        str(candidate),
                        "--pairs",
                        "6",
                    ]
                )
            self.assertEqual(result["status"], CALIBRATION_REQUIRED)
            self.assertEqual(result["raw_pairs"], [])
