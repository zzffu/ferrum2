import unittest

from tests.performance_rule._fixture import RUNNER_SHA256, aa_source_report, report
from tools.performance_rule.evidence import validate_control_raw_evidence
from tools.performance_rule.validated_report import validate_report
from tools.performance_rule.schema import ControlError


class ReportConsistencyTests(unittest.TestCase):
    def test_consistent_report_returns_its_checked_scenarios(self):
        data = report(RUNNER_SHA256)
        checked = validate_report(data, RUNNER_SHA256)
        self.assertEqual(checked.report, data)
        self.assertEqual(checked.scenario_suites, {row["id"]: row["suite"] for row in data["measurements"]})

    def test_nearest_rank_uses_the_observed_tail_and_even_sample_median(self):
        data = report(RUNNER_SHA256)
        data["configuration"]["samples"] = 6
        for row in data["measurements"]:
            row["samples_ns_per_op"] = [10, 20, 30, 40, 50, 60]
            row["actual_iterations_per_sample"] = [320_000] * 6
            row["sample_batch_nanoseconds"] = [value * 320_000 for value in row["samples_ns_per_op"]]
            row["p50_ns_per_op"], row["p99_ns_per_op"] = 30, 60
            row["queries_per_second_from_p50"] = 1_000_000_000 / 30 if row["suite"] == "dns_policy" else None
            if row["paired_sample_order"] is not None:
                row["paired_sample_order"].append("candidate_first")
        validate_report(data, RUNNER_SHA256)
        data["measurements"][0]["p50_ns_per_op"] = 35
        with self.assertRaisesRegex(ControlError, "p50"):
            validate_report(data, RUNNER_SHA256)

    def test_paired_gate_scope_cannot_be_hidden_by_empty_observations(self):
        data = report(RUNNER_SHA256)
        data["parity_observations"] = []
        with self.assertRaisesRegex(ControlError, "parity observation count"):
            validate_report(data, RUNNER_SHA256)

    def test_math_tolerance_does_not_become_a_performance_allowance(self):
        data = report(RUNNER_SHA256)
        data["measurements"][0]["p50_ns_per_op"] += 1e-6
        with self.assertRaisesRegex(ControlError, "p50"):
            validate_report(data, RUNNER_SHA256)


    def test_derived_measurement_values_cannot_disagree_with_raw_samples(self):
        changes = [
            ("p50_ns_per_op", 99), ("p99_ns_per_op", 99),
            ("samples_ns_per_op", [99] * 5),
            ("allocations_per_op", 2), ("compiled_bytes_per_entry", 5),
            ("queries_per_second_from_p50", 5),
            ("correctness", "failed"),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                data = report(RUNNER_SHA256)
                data["measurements"][0][field] = value
                with self.assertRaises(ControlError):
                    validate_report(data, RUNNER_SHA256)

    def test_allocation_gate_is_derived_from_suite_and_five_regions(self):
        for change in ("scope", "count", "allocation"):
            with self.subTest(change=change):
                data = report(RUNNER_SHA256)
                row = data["measurements"][1]
                if change == "scope":
                    row["allocation_gate_applicable"] = False
                    row["allocation_gate_passed"] = None
                elif change == "count":
                    row["allocation_samples"].pop()
                else:
                    row["allocation_samples"][0]["allocations"] = 1
                with self.assertRaises(ControlError):
                    validate_report(data, RUNNER_SHA256)

    def test_pair_parity_must_be_reconstructed(self):
        for field, value in (("median_delta_percent", 1), ("decision", "failed")):
            with self.subTest(field=field):
                data = report(RUNNER_SHA256)
                data["parity_observations"][0][field] = value
                with self.assertRaises(ControlError):
                    validate_report(data, RUNNER_SHA256)

    def test_all_twelve_reports_must_describe_one_workload(self):
        for field, value in (("cpu_model", "different"), ("build_profile", "debug")):
            with self.subTest(field=field):
                data = aa_source_report()
                data["raw_pairs"][-1]["candidate"]["environment"][field] = value
                with self.assertRaises(ControlError):
                    validate_control_raw_evidence(data, "aa")


    def test_route_and_dns_paired_latency_remain_observations(self):
        for suite, first, second in (("route_program", "ordinary_only", "ruleset_only"), ("dns_policy", "ordinary_inline", "ruleset")):
            with self.subTest(suite=suite):
                data = report(RUNNER_SHA256)
                rows = data["measurements"][1:3]
                data["measurements"] = rows
                data["scenario_count"] = 2
                for row, source, value in zip(rows, (first, second), (10, 20)):
                    row.update(id=f"{suite}/{source}/1/probe", suite=suite, source=source, scenario="probe", scale=1, rule_program_mode="small_linear", compiled_entries=1, compiled_bytes_per_entry=128.0)
                    row["p50_ns_per_op"] = row["p99_ns_per_op"] = value
                    row["samples_ns_per_op"] = [value] * 5
                    row["sample_batch_nanoseconds"] = [320_000 * value] * 5
                    row["queries_per_second_from_p50"] = 1_000_000_000 / value if suite == "dns_policy" else None
                    row["allocation_gate_applicable"] = suite == "route_program"
                    row["allocation_gate_passed"] = True if suite == "route_program" else None
                rows[1]["rule_program_mode"] = "indexed"
                observation = data["parity_observations"][0]
                observation.update(suite=suite, scenario="probe", scale=1, baseline_id=rows[0]["id"], candidate_id=rows[1]["id"], median_delta_percent=100.0, p99_delta_percent=100.0, performance_gate_applicable=False, decision="observed")
                validate_report(data, RUNNER_SHA256)

    def test_match_set_regression_cannot_claim_a_passed_parity_gate(self):
        data = report(RUNNER_SHA256)
        row = data["measurements"][2]
        row["p50_ns_per_op"] = row["p99_ns_per_op"] = 20
        row["samples_ns_per_op"] = [20] * 5
        row["sample_batch_nanoseconds"] = [320_000 * 20] * 5
        data["parity_observations"][0].update(median_delta_percent=100.0, p99_delta_percent=100.0, decision="failed")
        with self.assertRaisesRegex(ControlError, "parity gate"):
            validate_report(data, RUNNER_SHA256)

    def test_counter_or_sample_configuration_cannot_change_independently(self):
        for change in ("samples", "iterations", "pair"):
            with self.subTest(change=change):
                data = report(RUNNER_SHA256)
                if change == "samples":
                    data["configuration"]["samples"] = 6
                elif change == "iterations":
                    data["measurements"][1]["actual_iterations_per_sample"][0] = 31
                else:
                    data["measurements"][2]["timing_pair_id"] = "different-pair"
                with self.assertRaises(ControlError):
                    validate_report(data, RUNNER_SHA256)
