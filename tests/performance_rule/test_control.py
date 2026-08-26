import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "performance_rule", ROOT / "tools" / "performance_rule.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTROL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTROL
SPEC.loader.exec_module(CONTROL)


IDENTIFIERS = (
    "dns_policy/one",
    "match_set/one",
    "route_program/one",
)
SCENARIO_SUITES = {identifier: identifier.split("/", 1)[0] for identifier in IDENTIFIERS}


def report(sha256, identifiers=IDENTIFIERS, value=10):
    return {
        "schema": CONTROL.RUNNER_SCHEMA,
        "runner": {"sha256": sha256},
        "correctness_passed": True,
        "allocation_gate_passed": True,
        "parity_gate_passed": True,
        "thresholds_passed": True,
        "measurement_policy": {
            "minimum_reported_batch_nanoseconds": 250_000,
            "thresholds_enforced_by_runner": True,
            "p99_parity_target_percent": 15.0,
        },
        "measurements": [
            {
                "id": identifier,
                "suite": identifier.split("/", 1)[0],
                "p50_ns_per_op": value,
                "p99_ns_per_op": value + 2,
                "samples_ns_per_op": [value] * 5,
                "requested_min_iterations_per_sample": 10,
                "actual_iterations_per_sample": [10] * 5,
                "sample_batch_nanoseconds": [250_000] * 5,
                "timing_pair_id": None,
                "paired_sample_order": None,
                "allocations_per_op": 0.0,
                "reallocations_per_op": 0.0,
                "bytes_allocated_per_op": 0.0,
                "bytes_deallocated_per_op": 0.0,
                "compiled_memory_bytes": 128,
                "compiled_bytes_per_entry": 128.0,
                "allocation_samples": [
                    {
                        "iterations": 1,
                        "allocations": 0,
                        "deallocations": 0,
                        "reallocations": 0,
                        "bytes_allocated": 0,
                        "bytes_deallocated": 0,
                    }
                ]
                * 5,
                "allocation_gate_applicable": True,
                "allocation_gate_passed": True,
            }
            for identifier in identifiers
        ],
    }


RUNNER_SHA256 = "a" * 64
RUNNER_ARGUMENTS = ["--profile", "smoke", "--samples", "501"]


def v4_aa_calibration():
    pairs = []
    execution_trace = []
    for pair_index in range(5):
        parent = report(RUNNER_SHA256, value=100)
        candidate = report(RUNNER_SHA256, value=100)
        for row in parent["measurements"]:
            row["p99_ns_per_op"] = 102
        for row in candidate["measurements"]:
            row["p50_ns_per_op"] = {
                "match_set": 104,
                "route_program": 107,
                "dns_policy": 106,
            }[row["suite"]]
            row["p99_ns_per_op"] = 142
        pairs.append({"parent": parent, "candidate": candidate})
        roles = (
            ("parent", "candidate")
            if pair_index % 2 == 0
            else ("candidate", "parent")
        )
        for order_index, role in enumerate(roles, 1):
            execution_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index,
                    "role": role,
                    "runner_sha256": RUNNER_SHA256,
                }
            )
    comparisons = CONTROL.summarize(SCENARIO_SUITES, pairs, True, 10.0)
    effective_limit = CONTROL.calibrated_limit(comparisons)
    return {
        "schema": CONTROL.CONTROL_SCHEMA,
        "generated_unix_millis": 1,
        "mode": "aa",
        "pairs": 5,
        "parent_runner_sha256": RUNNER_SHA256,
        "candidate_runner_sha256": RUNNER_SHA256,
        "runner_arguments": RUNNER_ARGUMENTS,
        "scenario_ids": sorted(SCENARIO_SUITES),
        "scenario_suites": dict(sorted(SCENARIO_SUITES.items())),
        "execution_policy": {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": CONTROL.RUNNER_PRIORITY_HIGH,
        },
        "execution_trace": execution_trace,
        "comparisons": comparisons,
        "threshold_policy": CONTROL.threshold_policy(
            comparisons, effective_limit, "current_aa_run", None
        ),
        "raw_pairs": pairs,
    }


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class PerformanceRuleControlTests(unittest.TestCase):
    def test_requires_at_least_five_pairs(self):
        with self.assertRaisesRegex(CONTROL.ControlError, "pairs"):
            CONTROL.validate_pairs(4)
        CONTROL.validate_pairs(5)

    def test_pair_order_alternates_roles(self):
        parent = Path("parent")
        candidate = Path("candidate")
        self.assertEqual(
            [role for role, _ in CONTROL.pair_execution_order(0, parent, candidate)],
            ["parent", "candidate"],
        )
        self.assertEqual(
            [role for role, _ in CONTROL.pair_execution_order(1, parent, candidate)],
            ["candidate", "parent"],
        )

    def test_high_priority_is_windows_only_and_never_realtime(self):
        self.assertEqual(
            CONTROL.runner_creation_flags(CONTROL.RUNNER_PRIORITY_NORMAL), 0
        )
        with mock.patch.object(CONTROL.sys, "platform", "not-windows"):
            with self.assertRaisesRegex(CONTROL.ControlError, "only on Windows"):
                CONTROL.runner_creation_flags(CONTROL.RUNNER_PRIORITY_HIGH)

        if sys.platform == "win32":
            flags = CONTROL.runner_creation_flags(CONTROL.RUNNER_PRIORITY_HIGH)
            self.assertEqual(flags, CONTROL.subprocess.HIGH_PRIORITY_CLASS)
            self.assertNotEqual(flags, CONTROL.subprocess.REALTIME_PRIORITY_CLASS)

    def test_runner_sha_and_measurement_shape_are_validated(self):
        self.assertEqual(CONTROL.validate_report(report("abc"), "abc"), SCENARIO_SUITES)
        with self.assertRaisesRegex(CONTROL.ControlError, "SHA-256"):
            CONTROL.validate_report(report("wrong"), "abc")
        malformed = report("abc")
        malformed["measurements"][0]["samples_ns_per_op"] = [1] * 4
        with self.assertRaisesRegex(CONTROL.ControlError, "too few"):
            CONTROL.validate_report(malformed, "abc")
        malformed = report("abc")
        malformed["measurements"][0]["suite"] = "unknown"
        with self.assertRaisesRegex(CONTROL.ControlError, "unsupported suite"):
            CONTROL.validate_report(malformed, "abc")
        malformed = report("abc")
        malformed["measurements"][0]["suite"] = "match_set"
        with self.assertRaisesRegex(CONTROL.ControlError, "does not match"):
            CONTROL.validate_report(malformed, "abc")

    def test_parent_and_candidate_must_have_identical_scenarios(self):
        expected = {"match_set/one": "match_set"}
        with self.assertRaisesRegex(CONTROL.ControlError, "catalog changed"):
            CONTROL.require_same_scenarios(
                expected, {"match_set/one": "route_program"}
            )

    def test_summary_gates_median_and_retains_p99_as_observed(self):
        pairs = [
            {"parent": report("p", value=100), "candidate": report("c", value=110)}
            for _ in range(5)
        ]
        for pair in pairs:
            for row in pair["candidate"]["measurements"]:
                row["p99_ns_per_op"] = 250
        rows = CONTROL.summarize(SCENARIO_SUITES, pairs, False, 10.0)
        by_suite = {row["suite"]: row for row in rows}
        match_set = by_suite["match_set"]
        self.assertEqual(match_set["median_p50_delta_percent"], 10.0)
        self.assertGreater(match_set["median_p99_delta_percent"], 100.0)
        self.assertEqual(match_set["median_decision"], "passed")
        self.assertEqual(match_set["p99_classification"], "observed_cross_process")
        self.assertFalse(match_set["p99_gate_applicable"])
        self.assertEqual(match_set["p99_decision"], "observed")
        self.assertEqual(match_set["decision"], "passed")
        self.assertIsNone(match_set["aa_noise_median_absolute_percent"])
        for suite in ("route_program", "dns_policy"):
            self.assertFalse(by_suite[suite]["median_gate_applicable"])
            self.assertIsNone(by_suite[suite]["median_limit_percent"])
            self.assertEqual(by_suite[suite]["median_decision"], "observed")
            self.assertEqual(by_suite[suite]["decision"], "observed")

        failing = [
            {"parent": report("p", value=100), "candidate": report("c", value=116)}
            for _ in range(5)
        ]
        rows = CONTROL.summarize(SCENARIO_SUITES, failing, False, 10.0)
        match_set = next(row for row in rows if row["suite"] == "match_set")
        self.assertEqual(match_set["median_decision"], "failed")
        self.assertEqual(match_set["decision"], "failed")

    def test_aa_noise_calibrates_between_local_and_noisy_limits(self):
        pairs = [
            {"parent": report("same", value=100), "candidate": report("same", value=107)}
            for _ in range(5)
        ]
        for pair in pairs:
            for row in pair["candidate"]["measurements"]:
                row["p99_ns_per_op"] = 300
        rows = CONTROL.summarize(SCENARIO_SUITES, pairs, True, 10.0)
        match_set = next(row for row in rows if row["suite"] == "match_set")
        self.assertEqual(match_set["decision"], "passed")
        self.assertGreater(
            match_set["aa_noise_median_absolute_p99_percent"], 100.0
        )
        self.assertEqual(match_set["p99_decision"], "observed")
        self.assertEqual(CONTROL.calibrated_limit(rows), 7.0)

    def test_calibration_requires_identical_runner_arguments_and_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "aa-v4.json"
            write_json(path, v4_aa_calibration())
            _, limit = CONTROL.load_calibration(
                path,
                RUNNER_SHA256,
                SCENARIO_SUITES,
                RUNNER_ARGUMENTS,
                CONTROL.RUNNER_PRIORITY_HIGH,
            )
            self.assertEqual(limit, 5.0)

            with self.assertRaisesRegex(CONTROL.ControlError, "arguments"):
                CONTROL.load_calibration(
                    path,
                    RUNNER_SHA256,
                    SCENARIO_SUITES,
                    ["--profile", "smoke", "--samples", "101"],
                    CONTROL.RUNNER_PRIORITY_HIGH,
                )
            with self.assertRaisesRegex(CONTROL.ControlError, "priority"):
                CONTROL.load_calibration(
                    path,
                    RUNNER_SHA256,
                    SCENARIO_SUITES,
                    RUNNER_ARGUMENTS,
                    CONTROL.RUNNER_PRIORITY_NORMAL,
                )
if __name__ == "__main__":
    unittest.main()
