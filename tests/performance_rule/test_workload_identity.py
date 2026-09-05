import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.performance_rule._fixture import (
    RUNNER_ARGUMENTS, RUNNER_SHA256, SCENARIO_SUITES, aa_source_report, report, write_json,
)
from tools.performance_rule.cli import control
from tools.performance_rule.evidence import (
    load_calibration, review_calibration_source, validate_control_raw_evidence,
)
from tools.performance_rule.schema import ControlError, RUNNER_PRIORITY_HIGH
from tools.performance_rule.validated_report import require_same_workload, validate_report


def fixture():
    return {
        "name": "bound.srs", "provenance": "pinned_repository_fixture",
        "bytes": 32, "sha256": "f" * 64, "srs_version": 2,
        "statistics": {"rules": 1, "exact_domains": 1, "domain_suffixes": 0, "domain_keywords": 0, "ip_cidrs": 0},
        "capabilities": {"exact_domain": True, "domain_suffix": False, "domain_keyword": False, "ip_cidr": False},
    }


class WorkloadIdentityTests(unittest.TestCase):
    def test_workload_excludes_measurements_and_intentionally_different_build_identity(self):
        baseline = report(RUNNER_SHA256, value=100)
        candidate = report("b" * 64, value=104)
        candidate["generated_unix_millis"] += 1
        candidate["repository"]["git_head"] = "e" * 40
        candidate["runner"]["bytes"] = 200
        for row in candidate["measurements"]:
            row["compiled_memory_bytes"] = 256
            row["compiled_bytes_per_entry"] = 256.0 / row["compiled_entries"]
        first = validate_report(baseline, RUNNER_SHA256)
        second = validate_report(candidate, "b" * 64)
        self.assertEqual(require_same_workload(first.workload_sha256, second.workload_sha256), first.workload_sha256)

    def test_workload_binds_fixture_configuration_policy_and_scenario(self):
        baseline = report(RUNNER_SHA256)
        baseline["fixtures"] = [fixture()]
        expected = validate_report(baseline, RUNNER_SHA256).workload_sha256
        for section, field, value in (
            ("configuration", "base_iterations_per_sample", 11),
            ("measurement_policy", "calibration", "different calibration"),
            ("environment", "rustc_version", "different toolchain"),
            ("fixture", "sha256", "e" * 64),
            ("fixture", "bytes", 33),
            ("scenario", "scenario", "different scenario"),
        ):
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(baseline)
                target = changed["fixtures"][0] if section == "fixture" else changed["measurements"][0] if section == "scenario" else changed[section]
                target[field] = value
                observed = validate_report(changed, RUNNER_SHA256).workload_sha256
                with self.assertRaisesRegex(ControlError, "workload identity"):
                    require_same_workload(expected, observed)

    def test_retained_pair_fixture_change_is_rejected(self):
        source = aa_source_report()
        for pair in source["raw_pairs"]:
            for raw in pair.values():
                raw["fixtures"] = [fixture()]
        source["raw_pairs"][3]["candidate"]["fixtures"][0]["sha256"] = "e" * 64
        with self.assertRaisesRegex(ControlError, "workload identity"):
            validate_control_raw_evidence(source, "aa")

    def test_calibration_applies_only_to_its_hash_bound_source_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            write_json(source, aa_source_report())
            calibration = Path(directory) / "calibration.json"
            write_json(calibration, review_calibration_source(source, reviewed_by="synthetic-test", reviewed_utc="2026-09-05T00:00:00Z"))
            current = report(RUNNER_SHA256)
            identity = validate_report(current, RUNNER_SHA256).workload_sha256
            load_calibration(calibration, RUNNER_SHA256, SCENARIO_SUITES, RUNNER_ARGUMENTS, RUNNER_PRIORITY_HIGH, identity)
            current["environment"]["logical_cpus"] = 2
            changed = validate_report(current, RUNNER_SHA256).workload_sha256
            with self.assertRaisesRegex(ControlError, "workload identity"):
                load_calibration(calibration, RUNNER_SHA256, SCENARIO_SUITES, RUNNER_ARGUMENTS, RUNNER_PRIORITY_HIGH, changed)

    def test_live_controller_rejects_changed_workload_with_mocked_runner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "synthetic-runner"
            executable.write_bytes(b"not executable")
            calls = 0

            def run(*args):
                nonlocal calls
                calls += 1
                raw = report(args[4])
                if calls == 12:
                    raw["environment"]["cpu_model"] = "changed"
                return validate_report(raw, args[4])

            with mock.patch("tools.performance_rule.cli.run_once", side_effect=run), mock.patch("tools.performance_rule.cli.emit_result"):
                with self.assertRaisesRegex(ControlError, "workload identity"):
                    control(["run", "--parent", str(executable)])
            self.assertEqual(calls, 12)


    def test_engine_mode_change_does_not_change_the_input_workload(self):
        baseline = report(RUNNER_SHA256)
        candidate = copy.deepcopy(baseline)
        candidate["measurements"][-1]["rule_program_mode"] = "indexed"
        before = validate_report(baseline, RUNNER_SHA256)
        after = validate_report(candidate, RUNNER_SHA256)
        self.assertEqual(before.workload_sha256, after.workload_sha256)
        self.assertEqual(after.report["measurements"][-1]["rule_program_mode"], "indexed")

    def test_boolean_schema_and_numeric_fields_are_rejected(self):
        for section, field in ((None, "schema"), ("configuration", "samples"), ("environment", "logical_cpus")):
            with self.subTest(section=section, field=field):
                data = report(RUNNER_SHA256)
                (data if section is None else data[section])[field] = True
                with self.assertRaises(ControlError):
                    validate_report(data, RUNNER_SHA256)
        data = report(RUNNER_SHA256)
        data["fixtures"] = [fixture()]
        data["fixtures"][0]["srs_version"] = True
        with self.assertRaises(ControlError):
            validate_report(data, RUNNER_SHA256)
