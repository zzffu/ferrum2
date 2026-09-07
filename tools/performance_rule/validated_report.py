"""Validate current producer arithmetic and bind comparable workloads.

The returned identity binds fixtures, declared configuration, scenario metadata,
measurement policy, and every available producer environment field. It excludes
measured outcomes (including engine-selected program mode), timestamps and
intentionally changing source/runner hashes.
The current calibration schema needs no extra identity field: evidence.py derives
this identity from the calibration's byte-hash-bound source reports. Missing CPU
model/toolchain metadata remains missing evidence, not a claimed host identity.
No historical schema is accepted here.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from tools.performance_rule.json_contract import exact_fields
from tools.performance_rule.schema import (
    ControlError, LOCAL_TARGET_PERCENT, NOISY_GATE_CEILING_PERCENT,
    P99_TARGET_PERCENT, RUNNER_SCHEMA, SUITE_POLICY, canonical_json_sha256, is_sha256,
)

REPORT_FIELDS = frozenset(
    {
        "schema", "generated_unix_millis", "profile", "environment", "repository",
        "runner", "configuration", "measurement_policy", "fixtures", "measurements",
        "parity_observations", "scenario_count", "correctness_passed",
        "allocation_gate_passed", "parity_gate_passed", "thresholds_passed",
    }
)
ENVIRONMENT_FIELDS = frozenset(
    {"os", "architecture", "family", "logical_cpus", "cpu_model", "rustc_version", "timer", "build_profile"}
)
REPOSITORY_FIELDS = frozenset(
    {"git_head", "git_tree", "tree_state", "changed_entries", "status_sha256"}
)
RUNNER_FIELDS = frozenset({"sha256", "bytes"})
CONFIGURATION_FIELDS = frozenset(
    {"match_sizes", "route_sizes", "dns_rule_sizes", "samples", "base_iterations_per_sample", "includes_100k"}
)
MEASUREMENT_POLICY_FIELDS = frozenset(
    {
        "latency_source", "minimum_reported_batch_nanoseconds", "calibration",
        "warmup_batches", "paired_order", "retained_samples", "allocation_measurement",
        "compiled_memory_measurement", "local_parity_target_percent",
        "noisy_gate_ceiling_percent", "p99_parity_target_percent",
        "thresholds_enforced_by_runner", "parity_gate_scope", "paired_observation_scope",
        "allocation_gate_scope", "note",
    }
)
FIXTURE_FIELDS = frozenset(
    {"name", "provenance", "bytes", "sha256", "srs_version", "statistics", "capabilities"}
)
STATISTICS_FIELDS = frozenset(
    {"rules", "exact_domains", "domain_suffixes", "domain_keywords", "ip_cidrs"}
)
CAPABILITIES_FIELDS = frozenset(
    {"exact_domain", "domain_suffix", "domain_keyword", "ip_cidr"}
)
MEASUREMENT_FIELDS = frozenset(
    {
        "id", "suite", "source", "scenario", "scale", "fixture", "rule_program_mode",
        "query_candidate_visits", "requested_min_iterations_per_sample",
        "actual_iterations_per_sample", "sample_batch_nanoseconds", "timing_pair_id",
        "paired_sample_order", "samples_ns_per_op", "p50_ns_per_op", "p99_ns_per_op",
        "queries_per_second_from_p50", "build_nanoseconds", "compiled_allocations",
        "compiled_reallocations", "compiled_entries", "compiled_bytes_per_entry",
        "allocation_samples", "allocations_per_op", "reallocations_per_op",
        "bytes_allocated_per_op", "bytes_deallocated_per_op", "compiled_memory_bytes",
        "allocation_status", "compiled_memory_status", "allocation_gate_applicable",
        "allocation_gate_passed", "correctness", "outcome_checksum",
    }
)
ALLOCATION_SAMPLE_FIELDS = frozenset(
    {"iterations", "allocations", "deallocations", "reallocations", "bytes_allocated", "bytes_deallocated"}
)
PARITY_FIELDS = frozenset(
    {
        "suite", "scenario", "scale", "baseline_id", "candidate_id",
        "median_delta_percent", "p99_delta_percent", "median_limit_percent",
        "p99_limit_percent", "performance_gate_applicable", "decision",
    }
)


def _finite_number(value: Any, *, positive: bool) -> bool:
    return (
        type(value) in (int, float)
        and math.isfinite(value)
        and (value > 0 if positive else value >= 0)
    )


def _validate_closed_report_shape(report: Any) -> dict[str, Any]:
    report = exact_fields(report, REPORT_FIELDS, label="runner report")
    exact_fields(report["environment"], ENVIRONMENT_FIELDS, label="runner environment")
    exact_fields(report["repository"], REPOSITORY_FIELDS, label="runner repository")
    exact_fields(report["runner"], RUNNER_FIELDS, label="runner identity")
    exact_fields(report["configuration"], CONFIGURATION_FIELDS, label="runner configuration")
    exact_fields(
        report["measurement_policy"],
        MEASUREMENT_POLICY_FIELDS,
        label="runner measurement policy",
    )
    fixtures = report["fixtures"]
    if not isinstance(fixtures, list):
        raise ControlError("runner fixtures are not a list")
    for fixture in fixtures:
        exact_fields(fixture, FIXTURE_FIELDS, label="runner fixture")
        exact_fields(fixture["statistics"], STATISTICS_FIELDS, label="runner fixture statistics")
        exact_fields(fixture["capabilities"], CAPABILITIES_FIELDS, label="runner fixture capabilities")
    rows = report["measurements"]
    if not isinstance(rows, list):
        raise ControlError("runner measurements are not a list")
    for row in rows:
        exact_fields(row, MEASUREMENT_FIELDS, label="runner measurement")
        samples = row["allocation_samples"]
        if not isinstance(samples, list):
            raise ControlError("runner allocation samples are not a list")
        for sample in samples:
            exact_fields(sample, ALLOCATION_SAMPLE_FIELDS, label="runner allocation sample")
    parity = report["parity_observations"]
    if not isinstance(parity, list):
        raise ControlError("runner parity observations are not a list")
    for observation in parity:
        exact_fields(observation, PARITY_FIELDS, label="runner parity observation")
    return report


def _validate_shape_values(report: Any, expected_sha256: str) -> dict[str, str]:
    report = _validate_closed_report_shape(report)
    if type(report.get("schema")) is not str or report["schema"] != RUNNER_SCHEMA:
        raise ControlError("runner emitted an unsupported JSON schema")
    runner = report.get("runner")
    if not isinstance(runner, dict) or runner.get("sha256") != expected_sha256:
        raise ControlError("runner-reported SHA-256 does not match the executed binary")
    if report.get("correctness_passed") is not True:
        raise ControlError("runner did not report successful correctness checks")
    if report.get("allocation_gate_passed") is not True:
        raise ControlError("runner did not pass the allocation-free hot-path gate")
    if report.get("parity_gate_passed") is not True:
        raise ControlError("runner did not pass the local ordinary/RuleSet parity gate")
    if report.get("thresholds_passed") is not True:
        raise ControlError("runner did not pass its applicable performance thresholds")
    policy = report.get("measurement_policy")
    if not isinstance(policy, dict):
        raise ControlError("runner report has no measurement policy")
    minimum_batch_ns = policy.get("minimum_reported_batch_nanoseconds")
    if type(minimum_batch_ns) is not int or minimum_batch_ns < 100_000:
        raise ControlError("runner sample window is below 100 microseconds")
    if policy.get("thresholds_enforced_by_runner") is not True:
        raise ControlError("runner does not enforce its local parity threshold")
    p99_target = policy.get("p99_parity_target_percent")
    if p99_target != P99_TARGET_PERCENT:
        raise ControlError("runner p99 parity target is not 15 percent")
    rows = report.get("measurements")
    if not isinstance(rows, list) or not rows:
        raise ControlError("runner report has no measurements")
    scenario_suites: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ControlError("runner measurement is not an object")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ControlError("runner measurement id is invalid")
        if identifier in scenario_suites:
            raise ControlError("runner measurement ids are not unique")
        suite = row.get("suite")
        if not isinstance(suite, str) or suite not in SUITE_POLICY:
            raise ControlError(
                f"runner measurement {identifier} has an unsupported suite"
            )
        if not identifier.startswith(f"{suite}/"):
            raise ControlError(
                f"runner measurement {identifier} does not match its suite"
            )
        scenario_suites[identifier] = suite
        for metric in ("p50_ns_per_op", "p99_ns_per_op"):
            if not _finite_number(row.get(metric), positive=True):
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        samples = row.get("samples_ns_per_op")
        if not isinstance(samples, list) or len(samples) < 5:
            raise ControlError(f"runner measurement {identifier} has too few raw samples")
        if any(not _finite_number(value, positive=True) for value in samples):
            raise ControlError(f"runner measurement {identifier} has invalid raw samples")
        requested_iterations = row.get("requested_min_iterations_per_sample")
        if type(requested_iterations) is not int or requested_iterations <= 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid requested iterations"
            )
        actual_iterations = row.get("actual_iterations_per_sample")
        batch_nanoseconds = row.get("sample_batch_nanoseconds")
        if not isinstance(actual_iterations, list) or len(actual_iterations) != len(
            samples
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid actual iterations"
            )
        if not isinstance(batch_nanoseconds, list) or len(batch_nanoseconds) != len(
            samples
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid batch durations"
            )
        if any(type(value) is not int or value <= 0 for value in actual_iterations):
            raise ControlError(
                f"runner measurement {identifier} has non-positive actual iterations"
            )
        if any(
            type(value) is not int or value < minimum_batch_ns
            for value in batch_nanoseconds
        ):
            raise ControlError(
                f"runner measurement {identifier} retained a sub-window timing batch"
            )
        pair_id = row.get("timing_pair_id")
        pair_order = row.get("paired_sample_order")
        if pair_id is None:
            if pair_order is not None:
                raise ControlError(
                    f"runner measurement {identifier} has order without a timing pair"
                )
        elif (
            not isinstance(pair_id, str)
            or not pair_id
            or not isinstance(pair_order, list)
            or len(pair_order) != len(samples)
            or any(
                value not in ("baseline_first", "candidate_first")
                for value in pair_order
            )
        ):
            raise ControlError(
                f"runner measurement {identifier} has invalid paired timing evidence"
            )
        for metric in (
            "allocations_per_op",
            "reallocations_per_op",
            "bytes_allocated_per_op",
            "bytes_deallocated_per_op",
        ):
            value = row.get(metric)
            if not _finite_number(value, positive=False):
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        if type(row.get("compiled_memory_bytes")) is not int or row[
            "compiled_memory_bytes"
        ] < 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid compiled memory"
            )
        bytes_per_entry = row.get("compiled_bytes_per_entry")
        if bytes_per_entry is not None and not _finite_number(bytes_per_entry, positive=False):
            raise ControlError(
                f"runner measurement {identifier} has invalid memory per entry"
            )
        allocation_samples = row.get("allocation_samples")
        if not allocation_samples:
            raise ControlError(
                f"runner measurement {identifier} has invalid allocation samples"
            )
        for sample in allocation_samples:
            if not isinstance(sample, dict):
                raise ControlError(
                    f"runner measurement {identifier} has a malformed allocation sample"
                )
            for metric in (
                "iterations",
                "allocations",
                "deallocations",
                "reallocations",
                "bytes_allocated",
                "bytes_deallocated",
            ):
                if type(sample.get(metric)) is not int or sample[metric] < 0:
                    raise ControlError(
                        f"runner measurement {identifier} has an invalid allocation sample"
                    )
            if sample["iterations"] != 1:
                raise ControlError(
                    f"runner measurement {identifier} allocation sample is not per-operation"
                )
        if row.get("allocation_gate_applicable") is True and row.get(
            "allocation_gate_passed"
        ) is not True:
            raise ControlError(
                f"runner measurement {identifier} failed its allocation gate"
            )
    if type(report["scenario_count"]) is not int or report["scenario_count"] != len(rows):
        raise ControlError("runner scenario count does not match its measurements")
    return scenario_suites



@dataclass(frozen=True)
class ValidatedReport:
    report: dict[str, Any]
    scenario_suites: dict[str, str]
    workload_sha256: str


def require_same_workload(expected: str | None, observed: str) -> str:
    if expected is not None and observed != expected:
        raise ControlError("runner workload identity changed")
    return observed


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 2**64 - 1:
        raise ControlError(f"runner {label} is not a bounded integer")
    return value


def _number_equal(actual: Any, expected: float | None, label: str) -> None:
    if expected is None:
        if actual is not None:
            raise ControlError(f"runner {label} disagrees with raw evidence")
        return
    if type(actual) not in (int, float) or not math.isfinite(actual):
        raise ControlError(f"runner {label} is not finite")
    # Rust casts counters to f64 then performs ordinary IEEE-754 arithmetic.
    # JSON round-trips f64. Eight ULPs cover expression-rounding differences;
    # this is an arithmetic tolerance, never a percentage performance band.
    tolerance = 8 * math.ulp(max(abs(float(actual)), abs(expected), 1.0))
    if abs(actual - expected) > tolerance:
        raise ControlError(f"runner {label} disagrees with raw evidence")


def _rank(samples: list[float], percentile: int) -> float:
    return sorted(samples)[(percentile * len(samples) + 99) // 100 - 1]


def _validate_metadata(report: dict[str, Any]) -> None:
    configuration = report["configuration"]
    if report["profile"] not in ("smoke", "qualification"):
        raise ControlError("runner profile is invalid")
    samples = _integer(configuration["samples"], "sample count", 5)
    if samples > 1001:
        raise ControlError("runner sample count exceeds producer limit")
    base = _integer(configuration["base_iterations_per_sample"], "base iterations", 1)
    if base > 10_000_000 or type(configuration["includes_100k"]) is not bool:
        raise ControlError("runner configuration is invalid")
    for field in ("match_sizes", "route_sizes", "dns_rule_sizes"):
        sizes = configuration[field]
        if not isinstance(sizes, list) or not sizes:
            raise ControlError("runner configured scales are invalid")
        for size in sizes:
            _integer(size, "configured scale", 1)
        if len(set(sizes)) != len(sizes):
            raise ControlError("runner configured scales are duplicated")
    environment = report["environment"]
    _integer(environment["logical_cpus"], "logical CPUs", 1)
    for field in ("os", "architecture", "family", "timer", "build_profile"):
        if not isinstance(environment[field], str) or not environment[field]:
            raise ControlError("runner environment is invalid")
    for field in ("cpu_model", "rustc_version"):
        if environment[field] is not None and not isinstance(environment[field], str):
            raise ControlError("runner optional environment identity is invalid")
    if environment["timer"] != "std::time::Instant" or environment["build_profile"] not in ("debug", "release"):
        raise ControlError("runner measurement environment is unsupported")
    if not is_sha256(report["runner"]["sha256"]):
        raise ControlError("runner SHA-256 is invalid")
    _integer(report["runner"]["bytes"], "executable size", 1)
    policy = report["measurement_policy"]
    for field, expected in (
        ("local_parity_target_percent", LOCAL_TARGET_PERCENT),
        ("noisy_gate_ceiling_percent", NOISY_GATE_CEILING_PERCENT),
        ("p99_parity_target_percent", P99_TARGET_PERCENT),
    ):
        if type(policy[field]) not in (int, float) or policy[field] != expected:
            raise ControlError("runner parity policy changed")
    if policy["warmup_batches"] != 5 or type(policy["warmup_batches"]) is not int or policy["retained_samples"] is not True:
        raise ControlError("runner warmup or retained sample policy changed")
    for field in MEASUREMENT_POLICY_FIELDS - {
        "minimum_reported_batch_nanoseconds", "warmup_batches", "retained_samples",
        "local_parity_target_percent", "noisy_gate_ceiling_percent",
        "p99_parity_target_percent", "thresholds_enforced_by_runner",
    }:
        if not isinstance(policy[field], str) or not policy[field]:
            raise ControlError("runner measurement policy is invalid")
    if configuration["includes_100k"] != (100_000 in configuration["match_sizes"]):
        raise ControlError("runner opt-in scale differs from configuration")
    names = set()
    for fixture in report["fixtures"]:
        name = fixture["name"]
        if not isinstance(name, str) or not name or name in names:
            raise ControlError("runner fixture identity is invalid or duplicated")
        names.add(name)
        if not is_sha256(fixture["sha256"]):
            raise ControlError("runner fixture digest is invalid")
        _integer(fixture["bytes"], "fixture length", 1)
        if fixture["srs_version"] not in (1, 2, 3, 4) or type(fixture["srs_version"]) is not int:
            raise ControlError("runner fixture SRS version is invalid")
        if fixture["provenance"] not in ("pinned_repository_fixture", "deterministic_runner_generated_canonical_srs_v2"):
            raise ControlError("runner fixture provenance is invalid")
        counts = fixture["statistics"]
        for field, value in counts.items():
            _integer(value, "fixture statistics", 1 if field == "rules" else 0)
        for capability, count in (
            ("exact_domain", "exact_domains"), ("domain_suffix", "domain_suffixes"),
            ("domain_keyword", "domain_keywords"), ("ip_cidr", "ip_cidrs"),
        ):
            if fixture["capabilities"][capability] is not (counts[count] > 0):
                raise ControlError("runner fixture capabilities disagree with counts")


def _validate_measurement(row: dict[str, Any], report: dict[str, Any]) -> tuple[float, float]:
    samples = row["samples_ns_per_op"]
    if len(samples) != report["configuration"]["samples"]:
        raise ControlError("runner retained sample count differs from configuration")
    requested = _integer(row["requested_min_iterations_per_sample"], "requested iterations", 1)
    paired = row["timing_pair_id"] is not None
    rounds = 32 if paired else 1
    expected_samples = []
    for sample, duration, operations in zip(samples, row["sample_batch_nanoseconds"], row["actual_iterations_per_sample"]):
        _integer(duration, "batch duration", 1)
        _integer(operations, "operation count", requested * rounds)
        if operations > rounds * 1_000_000_000 or (paired and operations % 32):
            raise ControlError("runner paired operation count is invalid")
        expected = float(duration) / float(operations)
        _number_equal(sample, expected, "ns/op")
        expected_samples.append(expected)
    p50, p99 = _rank(expected_samples, 50), _rank(expected_samples, 99)
    _number_equal(row["p50_ns_per_op"], p50, "p50")
    _number_equal(row["p99_ns_per_op"], p99, "p99")
    _number_equal(row["queries_per_second_from_p50"], 1_000_000_000.0 / p50 if row["suite"] == "dns_policy" else None, "queries/second")
    allocation = row["allocation_samples"]
    if len(allocation) != 5:
        raise ControlError("runner requires five allocation regions")
    for sample in allocation:
        _integer(sample["deallocations"], "deallocation counter")
    for field in ("allocations", "reallocations", "bytes_allocated", "bytes_deallocated"):
        for sample in allocation:
            _integer(sample[field], "allocation counter")
        _number_equal(row[f"{field}_per_op"], float(sum(sample[field] for sample in allocation)) / 5.0, "allocation aggregate")
    applicable = row["suite"] in ("match_set", "route_program")
    passed = all(sample["allocations"] == 0 and sample["reallocations"] == 0 for sample in allocation)
    if row["allocation_gate_applicable"] is not applicable or row["allocation_gate_passed"] is not (passed if applicable else None):
        raise ControlError("runner allocation gate disagrees with raw evidence")
    if applicable and not passed:
        raise ControlError("runner failed its allocation gate")
    if row["allocation_status"] != "measured" or row["compiled_memory_status"] != "measured_net_retained_bytes" or row["correctness"] != "passed":
        raise ControlError("runner measurement status is invalid")
    for field in ("compiled_allocations", "compiled_reallocations", "compiled_memory_bytes", "outcome_checksum"):
        _integer(row[field], field)
    # Rust emits u128 build durations; the bounded JSON parser is the input envelope.
    if type(row["build_nanoseconds"]) is not int or row["build_nanoseconds"] < 0:
        raise ControlError("runner build duration is invalid")
    entries = row["compiled_entries"]
    if entries is not None:
        _integer(entries, "compiled entries")
    _number_equal(row["compiled_bytes_per_entry"], float(row["compiled_memory_bytes"]) / float(entries) if entries else None, "compiled bytes/entry")
    _integer(row["scale"], "scenario scale", 1)
    for field in ("source", "scenario"):
        if not isinstance(row[field], str) or not row[field]:
            raise ControlError("runner scenario metadata is invalid")
    sources = {
        "match_set": {"ordinary_inline", "synthetic_ruleset", "synthetic_srs", "binary_srs"},
        "route_program": {
            "ordinary_only", "ruleset_only", "mixed", "mixed_observed",
            "sparse_bitmap", "dense_bitmap", "sparse_continue", "dense_continue",
        },
        "dns_policy": {"ordinary_inline", "ruleset", "cache"},
    }
    if row["source"] not in sources[row["suite"]]:
        raise ControlError("runner scenario source is unsupported")
    if not row["id"].startswith(f'{row["suite"]}/{row["source"]}/'):
        raise ControlError("runner scenario source differs from identifier")
    fixture = row["fixture"]
    if fixture is not None:
        if not isinstance(fixture, str) or fixture not in {item["name"] for item in report["fixtures"]}:
            raise ControlError("runner scenario references an unknown fixture")
    configuration = report["configuration"]
    if row["suite"] == "match_set":
        if fixture is None:
            if row["scale"] not in configuration["match_sizes"]:
                raise ControlError("runner matcher scale is not configured")
            expected_entries = row["scale"]
        else:
            declared = next(item for item in report["fixtures"] if item["name"] == fixture)
            expected_entries = sum(value for key, value in declared["statistics"].items() if key != "rules")
            if row["scale"] != expected_entries:
                raise ControlError("runner fixture scale differs from entry counts")
        if entries != expected_entries:
            raise ControlError("runner compiled entries differ from matcher input")
    elif row["suite"] == "route_program":
        if row["scale"] not in configuration["route_sizes"] or entries != row["scale"]:
            raise ControlError("runner route scale or entry count is not configured")
    elif row["scale"] not in configuration["dns_rule_sizes"]:
        raise ControlError("runner DNS scale is not configured")
    mode = row["rule_program_mode"]
    if mode not in (None, "small_linear", "indexed"):
        raise ControlError("runner program mode is invalid")
    # Mode is selected by the engine, not requested by the workload. Keep its
    # closed observation without constraining the engine's indexing threshold.
    if row["query_candidate_visits"] is not None:
        _integer(row["query_candidate_visits"], "candidate visits")
    order = row["paired_sample_order"]
    if order is not None and any(left == right for left, right in zip(order, order[1:])):
        raise ControlError("runner paired sample order does not alternate")
    return p50, p99


def _validate_parity(report: dict[str, Any], quantiles: dict[str, tuple[float, float]]) -> None:
    rows = {row["id"]: row for row in report["measurements"]}
    expected_observations = []
    paired_ids = set()
    pair_names = set()
    for suite, baseline_source, candidate_source in (
        ("match_set", "ordinary_inline", "synthetic_ruleset"),
        ("match_set", "synthetic_srs", "binary_srs"),
        ("route_program", "ordinary_only", "ruleset_only"),
        ("dns_policy", "ordinary_inline", "ruleset"),
    ):
        for baseline in report["measurements"]:
            if (baseline["suite"], baseline["source"]) != (suite, baseline_source):
                continue
            candidate_id = baseline["id"].replace(f"/{baseline_source}/", f"/{candidate_source}/")
            candidate = rows.get(candidate_id)
            if candidate is None or candidate is baseline:
                raise ControlError("runner parity counterpart is missing")
            for field in ("suite", "scenario", "scale", "fixture", "requested_min_iterations_per_sample", "timing_pair_id", "paired_sample_order", "actual_iterations_per_sample"):
                if baseline[field] != candidate[field]:
                    raise ControlError("runner parity counterpart metadata differs")
            if baseline["timing_pair_id"] is None:
                raise ControlError("runner parity counterpart lacks paired timing")
            if baseline["timing_pair_id"] in pair_names:
                raise ControlError("runner timing pair identity is duplicated")
            pair_names.add(baseline["timing_pair_id"])
            paired_ids.update((baseline["id"], candidate_id))
            parent50, parent99 = quantiles[baseline["id"]]
            next50, next99 = quantiles[candidate_id]
            median = (next50 - parent50) * 100.0 / parent50
            tail = (next99 - parent99) * 100.0 / parent99
            applicable = suite == "match_set"
            passed = abs(median) <= LOCAL_TARGET_PERCENT and abs(tail) <= P99_TARGET_PERCENT
            expected_observations.append({
                "suite": suite, "scenario": baseline["scenario"], "scale": baseline["scale"],
                "baseline_id": baseline["id"], "candidate_id": candidate_id,
                "median_delta_percent": median, "p99_delta_percent": tail,
                "median_limit_percent": LOCAL_TARGET_PERCENT, "p99_limit_percent": P99_TARGET_PERCENT,
                "performance_gate_applicable": applicable,
                "decision": "observed" if not applicable else "passed" if passed else "failed",
            })
    for row in rows.values():
        if (row["timing_pair_id"] is not None or row["suite"] == "match_set" or row["source"] == "ruleset_only") and row["id"] not in paired_ids:
            raise ControlError("runner retained an unpaired measurement")
    observations = report["parity_observations"]
    if len(observations) != len(expected_observations):
        raise ControlError("runner parity observation count is inconsistent")
    for actual, expected in zip(observations, expected_observations):
        for field, value in expected.items():
            if field in ("median_delta_percent", "p99_delta_percent"):
                _number_equal(actual[field], value, "parity delta")
            elif type(actual[field]) is not type(value) or actual[field] != value:
                raise ControlError("runner parity observation disagrees with raw evidence")
    passed = all(not row["performance_gate_applicable"] or row["decision"] == "passed" for row in expected_observations)
    if report["parity_gate_passed"] is not passed or not passed:
        raise ControlError("runner parity gate disagrees with raw evidence")


def validate_report(report: Any, expected_sha256: str) -> ValidatedReport:
    scenarios = _validate_shape_values(report, expected_sha256)
    _validate_metadata(report)
    quantiles = {row["id"]: _validate_measurement(row, report) for row in report["measurements"]}
    _validate_parity(report, quantiles)
    metadata_fields = (
        "id", "suite", "source", "scenario", "scale", "fixture",
        "compiled_entries", "requested_min_iterations_per_sample", "timing_pair_id", "paired_sample_order",
    )
    workload = {
        "profile": report["profile"], "configuration": report["configuration"],
        "environment": report["environment"], "measurement_policy": report["measurement_policy"],
        "fixtures": sorted(report["fixtures"], key=lambda fixture: fixture["name"]),
        "scenarios": [{field: row[field] for field in metadata_fields} for row in sorted(report["measurements"], key=lambda row: row["id"])],
    }
    return ValidatedReport(report, scenarios, canonical_json_sha256(workload))
