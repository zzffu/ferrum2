#!/usr/bin/env python3
"""Alternate Ferrum2 rule qualification runners and retain all raw JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


RUNNER_SCHEMA = "ferrum2.rule-qualification.v1"
LEGACY_CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v2"
V3_CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v3"
CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v4"
LEGACY_THRESHOLD_POLICY_VERSION = "outer-median-and-p99-gates.v1"
V3_THRESHOLD_POLICY_VERSION = "outer-median-gates.v2"
THRESHOLD_POLICY_VERSION = "section-5.7-match-set-median-gates.v3"
MIN_PAIRS = 5
MAX_PAIRS = 50
LOCAL_TARGET_PERCENT = 5.0
NOISY_GATE_CEILING_PERCENT = 10.0
P99_TARGET_PERCENT = 15.0
P99_CLASSIFICATION = "observed_cross_process"
P99_GATE_OWNER = "final_candidate_in_process_paired_parity"
RUNNER_PRIORITY_NORMAL = "normal"
RUNNER_PRIORITY_HIGH = "high"
MATCH_SET_SUITE = "match_set"
ROUTE_PROGRAM_SUITE = "route_program"
DNS_POLICY_SUITE = "dns_policy"
SUITE_POLICY = {
    MATCH_SET_SUITE: {
        "scope_authority": "plan.section_5_7",
        "median_classification": "hard_gate",
    },
    ROUTE_PROGRAM_SUITE: {
        "scope_authority": "plan.section_17_2",
        "median_classification": "observed_cross_process",
    },
    DNS_POLICY_SUITE: {
        "scope_authority": "plan.section_17_3",
        "median_classification": "observed_cross_process",
    },
}


class ControlError(RuntimeError):
    """Closed controller input or evidence failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def pair_execution_order(
    pair_index: int, parent: Path, candidate: Path
) -> list[tuple[str, Path]]:
    if pair_index % 2 == 0:
        return [("parent", parent), ("candidate", candidate)]
    return [("candidate", candidate), ("parent", parent)]


def runner_creation_flags(priority: str) -> int:
    """Return a fail-closed, non-realtime process policy for runner children."""

    if priority == RUNNER_PRIORITY_NORMAL:
        return 0
    if priority != RUNNER_PRIORITY_HIGH:
        raise ControlError("runner process priority is invalid")
    if sys.platform != "win32":
        raise ControlError("--runner-priority high is supported only on Windows")
    high_priority = getattr(subprocess, "HIGH_PRIORITY_CLASS", None)
    if type(high_priority) is not int or high_priority <= 0:
        raise ControlError("Windows high-priority process creation is unavailable")
    return high_priority


def validate_pairs(pairs: int) -> None:
    if not MIN_PAIRS <= pairs <= MAX_PAIRS:
        raise ControlError(f"--pairs must be in {MIN_PAIRS}..={MAX_PAIRS}")


def validate_report(report: Any, expected_sha256: str) -> dict[str, str]:
    if not isinstance(report, dict) or report.get("schema") != RUNNER_SCHEMA:
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
        if suite not in SUITE_POLICY:
            raise ControlError(
                f"runner measurement {identifier} has an unsupported suite"
            )
        if not identifier.startswith(f"{suite}/"):
            raise ControlError(
                f"runner measurement {identifier} does not match its suite"
            )
        scenario_suites[identifier] = suite
        for metric in ("p50_ns_per_op", "p99_ns_per_op"):
            if type(row.get(metric)) not in (int, float) or row[metric] <= 0:
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        samples = row.get("samples_ns_per_op")
        if not isinstance(samples, list) or len(samples) < 5:
            raise ControlError(f"runner measurement {identifier} has too few raw samples")
        if any(type(value) not in (int, float) or value <= 0 for value in samples):
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
            if type(value) not in (int, float) or value < 0:
                raise ControlError(f"runner measurement {identifier} has invalid {metric}")
        if type(row.get("compiled_memory_bytes")) is not int or row[
            "compiled_memory_bytes"
        ] < 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid compiled memory"
            )
        bytes_per_entry = row.get("compiled_bytes_per_entry")
        if type(bytes_per_entry) not in (int, float) or bytes_per_entry < 0:
            raise ControlError(
                f"runner measurement {identifier} has invalid memory per entry"
            )
        allocation_samples = row.get("allocation_samples")
        if not isinstance(allocation_samples, list) or not allocation_samples:
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
    return scenario_suites


def require_same_scenarios(
    expected: dict[str, str] | None, observed: dict[str, str]
) -> dict[str, str]:
    if expected is None:
        return observed
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        raise ControlError(
            "runner scenario or suite catalog changed "
            f"(missing={missing[:3]}, extra={extra[:3]})"
        )
    return expected


def run_once(
    role: str,
    executable: Path,
    runner_arguments: list[str],
    timeout_seconds: int,
    expected_sha256: str,
    creation_flags: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    completed = subprocess.run(
        [str(executable), *runner_arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        encoding="utf-8",
        creationflags=creation_flags,
    )
    if completed.returncode != 0:
        stderr = completed.stderr[-2_000:].strip()
        raise ControlError(
            f"{role} runner exited {completed.returncode}: {stderr or '[no stderr]'}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ControlError(f"{role} runner stdout is not one JSON document") from error
    scenarios = validate_report(report, expected_sha256)
    return report, scenarios


def percent_delta(parent: float, candidate: float) -> float | None:
    if parent == 0:
        return None
    return (candidate - parent) * 100.0 / parent


def rows_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in report["measurements"]}


def collect_observations(
    scenario_suites: dict[str, str],
    paired_reports: list[dict[str, Any]],
    same_binary: bool,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for identifier in sorted(scenario_suites):
        parent_p50: list[float] = []
        parent_p99: list[float] = []
        candidate_p50: list[float] = []
        candidate_p99: list[float] = []
        pair_deltas: list[float | None] = []
        pair_p99_deltas: list[float | None] = []
        for pair in paired_reports:
            parent = rows_by_id(pair["parent"])[identifier]
            candidate = rows_by_id(pair["candidate"])[identifier]
            parent_p50.append(parent["p50_ns_per_op"])
            parent_p99.append(parent["p99_ns_per_op"])
            candidate_p50.append(candidate["p50_ns_per_op"])
            candidate_p99.append(candidate["p99_ns_per_op"])
            pair_deltas.append(
                percent_delta(parent["p50_ns_per_op"], candidate["p50_ns_per_op"])
            )
            pair_p99_deltas.append(
                percent_delta(parent["p99_ns_per_op"], candidate["p99_ns_per_op"])
            )
        parent_median = float(statistics.median(parent_p50))
        candidate_median = float(statistics.median(candidate_p50))
        parent_p99_median = float(statistics.median(parent_p99))
        candidate_p99_median = float(statistics.median(candidate_p99))
        absolute_deltas = [abs(value) for value in pair_deltas if value is not None]
        absolute_p99_deltas = [
            abs(value) for value in pair_p99_deltas if value is not None
        ]
        median_delta = percent_delta(parent_median, candidate_median)
        p99_delta = percent_delta(parent_p99_median, candidate_p99_median)
        aa_noise = (
            float(statistics.median(absolute_deltas))
            if same_binary and absolute_deltas
            else None
        )
        aa_p99_noise = (
            float(statistics.median(absolute_p99_deltas))
            if same_binary and absolute_p99_deltas
            else None
        )
        observations.append(
            {
                "id": identifier,
                "suite": scenario_suites[identifier],
                "parent_median_p50_ns_per_op": parent_median,
                "candidate_median_p50_ns_per_op": candidate_median,
                "median_p50_delta_percent": median_delta,
                "parent_median_p99_ns_per_op": parent_p99_median,
                "candidate_median_p99_ns_per_op": candidate_p99_median,
                "median_p99_delta_percent": p99_delta,
                "paired_p50_delta_percent": pair_deltas,
                "paired_p99_delta_percent": pair_p99_deltas,
                "aa_noise_median_absolute_percent": aa_noise,
                "aa_noise_median_absolute_p99_percent": aa_p99_noise,
            }
        )
    return observations


def summarize_v3(
    scenario_suites: dict[str, str],
    paired_reports: list[dict[str, Any]],
    same_binary: bool,
    median_limit_percent: float,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for observation in collect_observations(
        scenario_suites, paired_reports, same_binary
    ):
        if same_binary:
            median_passed = (
                observation["aa_noise_median_absolute_percent"] is not None
                and observation["aa_noise_median_absolute_percent"]
                <= NOISY_GATE_CEILING_PERCENT
            )
            median_gate_metric = "aa_pair_median_absolute_p50_delta_percent"
        else:
            median_delta = observation["median_p50_delta_percent"]
            median_passed = (
                median_delta is not None
                and abs(median_delta) <= median_limit_percent
            )
            median_gate_metric = "median_of_run_p50_delta_percent"
        summary = {key: value for key, value in observation.items() if key != "suite"}
        summary.update(
            {
                "median_limit_percent": (
                    NOISY_GATE_CEILING_PERCENT
                    if same_binary
                    else median_limit_percent
                ),
                "median_gate_metric": median_gate_metric,
                "median_gate_applicable": True,
                "median_decision": "passed" if median_passed else "failed",
                "p99_reference_percent": P99_TARGET_PERCENT,
                "p99_classification": P99_CLASSIFICATION,
                "p99_gate_applicable": False,
                "p99_decision": "observed",
                "decision": "passed" if median_passed else "failed",
            }
        )
        summaries.append(summary)
    return summaries


def summarize(
    scenario_suites: dict[str, str],
    paired_reports: list[dict[str, Any]],
    same_binary: bool,
    median_limit_percent: float,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for observation in collect_observations(
        scenario_suites, paired_reports, same_binary
    ):
        suite = observation["suite"]
        suite_policy = SUITE_POLICY[suite]
        hard_gate = suite_policy["median_classification"] == "hard_gate"
        if hard_gate and same_binary:
            aa_noise = observation["aa_noise_median_absolute_percent"]
            median_passed = (
                aa_noise is not None and aa_noise <= NOISY_GATE_CEILING_PERCENT
            )
            median_limit = NOISY_GATE_CEILING_PERCENT
            median_gate_metric = "aa_pair_median_absolute_p50_delta_percent"
        elif hard_gate:
            median_delta = observation["median_p50_delta_percent"]
            median_passed = (
                median_delta is not None
                and abs(median_delta) <= median_limit_percent
            )
            median_limit = median_limit_percent
            median_gate_metric = "median_of_run_p50_delta_percent"
        else:
            median_passed = None
            median_limit = None
            median_gate_metric = None
        decision = (
            "observed"
            if median_passed is None
            else ("passed" if median_passed else "failed")
        )
        summary = dict(observation)
        summary.update(
            {
                "scope_authority": suite_policy["scope_authority"],
                "median_classification": suite_policy["median_classification"],
                "median_limit_percent": median_limit,
                "median_gate_metric": median_gate_metric,
                "median_gate_applicable": hard_gate,
                "median_decision": decision,
                "p99_reference_percent": P99_TARGET_PERCENT,
                "p99_classification": P99_CLASSIFICATION,
                "p99_gate_applicable": False,
                "p99_decision": "observed",
                "decision": decision,
            }
        )
        summaries.append(summary)
    return summaries


def calibrated_limit(comparisons: list[dict[str, Any]]) -> float:
    applicable = [
        comparison["aa_noise_median_absolute_percent"]
        for comparison in comparisons
        if comparison.get("median_gate_applicable") is True
        and comparison.get("suite") == MATCH_SET_SUITE
    ]
    if not applicable or any(value is None for value in applicable):
        raise ControlError("A/A report has no complete match_set calibration evidence")
    observed = max(applicable)
    return max(LOCAL_TARGET_PERCENT, min(NOISY_GATE_CEILING_PERCENT, observed))


def calibrated_limit_v3(comparisons: list[dict[str, Any]]) -> float:
    observed = [
        comparison["aa_noise_median_absolute_percent"]
        for comparison in comparisons
    ]
    if not observed or any(value is None for value in observed):
        raise ControlError("v3 A/A report has incomplete calibration evidence")
    return max(
        LOCAL_TARGET_PERCENT,
        min(NOISY_GATE_CEILING_PERCENT, max(observed)),
    )


def threshold_policy_v3(
    comparisons: list[dict[str, Any]],
    effective_median_limit: float,
    calibration_source: str,
    calibration_sha256: str | None,
) -> dict[str, Any]:
    gate_passed = all(row["median_decision"] == "passed" for row in comparisons)
    return {
        "version": V3_THRESHOLD_POLICY_VERSION,
        "gate_metric": "cross_process_median_p50_only",
        "local_target_percent": LOCAL_TARGET_PERCENT,
        "noisy_gate_ceiling_percent": NOISY_GATE_CEILING_PERCENT,
        "p99_parity_target_percent": P99_TARGET_PERCENT,
        "p99_classification": P99_CLASSIFICATION,
        "p99_gate_applicable": False,
        "p99_gate_owner": P99_GATE_OWNER,
        "calibrated_median_limit_percent": effective_median_limit,
        "calibration_source": calibration_source,
        "calibration_sha256": calibration_sha256,
        "enforced": True,
        "gate_passed": gate_passed,
        "decision": "passed" if gate_passed else "failed",
    }


def max_absolute(rows: list[dict[str, Any]], field: str) -> float | None:
    values = [row[field] for row in rows if row.get(field) is not None]
    return max((abs(value) for value in values), default=None)


def observed_suite_summary(
    comparisons: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for suite in (ROUTE_PROGRAM_SUITE, DNS_POLICY_SUITE):
        rows = [row for row in comparisons if row.get("suite") == suite]
        result[suite] = {
            "comparison_count": len(rows),
            "max_absolute_median_p50_delta_percent": max_absolute(
                rows, "median_p50_delta_percent"
            ),
            "max_absolute_median_p99_delta_percent": max_absolute(
                rows, "median_p99_delta_percent"
            ),
            "max_aa_pair_median_absolute_p50_delta_percent": max_absolute(
                rows, "aa_noise_median_absolute_percent"
            ),
            "max_aa_pair_median_absolute_p99_delta_percent": max_absolute(
                rows, "aa_noise_median_absolute_p99_percent"
            ),
        }
    return result


def threshold_policy(
    comparisons: list[dict[str, Any]],
    effective_median_limit: float,
    calibration_source: str,
    calibration_sha256: str | None,
) -> dict[str, Any]:
    hard_gate_rows = [
        row for row in comparisons if row.get("median_gate_applicable") is True
    ]
    if not hard_gate_rows or any(
        row.get("suite") != MATCH_SET_SUITE for row in hard_gate_rows
    ):
        raise ControlError("outer median gate scope is not exactly match_set")
    observed_rows = [
        row for row in comparisons if row.get("median_gate_applicable") is False
    ]
    if any(row.get("decision") != "observed" for row in observed_rows):
        raise ControlError("observational suite produced a hard decision")
    gate_passed = all(row["median_decision"] == "passed" for row in hard_gate_rows)
    return {
        "version": THRESHOLD_POLICY_VERSION,
        "gate_metric": "cross_process_median_p50_match_set_only",
        "suite_policy": {
            suite: dict(policy) for suite, policy in SUITE_POLICY.items()
        },
        "hard_gate_suites": [MATCH_SET_SUITE],
        "observed_suites": [ROUTE_PROGRAM_SUITE, DNS_POLICY_SUITE],
        "hard_gate_comparison_count": len(hard_gate_rows),
        "observed_comparison_count": len(observed_rows),
        "observed_suite_summary": observed_suite_summary(comparisons),
        "local_target_percent": LOCAL_TARGET_PERCENT,
        "noisy_gate_ceiling_percent": NOISY_GATE_CEILING_PERCENT,
        "p99_parity_target_percent": P99_TARGET_PERCENT,
        "p99_classification": P99_CLASSIFICATION,
        "p99_gate_applicable": False,
        "p99_gate_owner": P99_GATE_OWNER,
        "calibrated_median_limit_percent": effective_median_limit,
        "calibration_source": calibration_source,
        "calibration_sha256": calibration_sha256,
        "enforced": True,
        "gate_passed": gate_passed,
        "decision": "passed" if gate_passed else "failed",
    }


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_control_raw_evidence(
    report: Any,
    expected_schema: str,
    expected_mode: str,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if (
        not isinstance(report, dict)
        or report.get("schema") != expected_schema
        or report.get("mode") != expected_mode
    ):
        raise ControlError("controller report mode or schema is invalid")
    pair_count = report.get("pairs")
    if type(pair_count) is not int:
        raise ControlError("controller report pair count is invalid")
    validate_pairs(pair_count)
    parent_sha256 = report.get("parent_runner_sha256")
    candidate_sha256 = report.get("candidate_runner_sha256")
    if not is_sha256(parent_sha256) or not is_sha256(candidate_sha256):
        raise ControlError("controller report runner SHA-256 is invalid")
    if expected_mode == "aa" and candidate_sha256 != parent_sha256:
        raise ControlError("A/A report does not use one runner SHA-256")
    if expected_mode == "parent_candidate" and candidate_sha256 == parent_sha256:
        raise ControlError("parent/candidate report uses one runner SHA-256")
    runner_arguments = report.get("runner_arguments")
    if not isinstance(runner_arguments, list) or any(
        not isinstance(value, str) for value in runner_arguments
    ):
        raise ControlError("controller report runner arguments are invalid")
    scenario_list = report.get("scenario_ids")
    if (
        not isinstance(scenario_list, list)
        or not scenario_list
        or any(not isinstance(value, str) or not value for value in scenario_list)
        or scenario_list != sorted(set(scenario_list))
    ):
        raise ControlError("controller report scenario ids are invalid")
    execution_policy = report.get("execution_policy")
    if (
        not isinstance(execution_policy, dict)
        or execution_policy.get("pair_order") != "alternating_parent_candidate"
        or execution_policy.get("raw_reports_retained") is not True
        or execution_policy.get("runner_process_priority")
        not in (RUNNER_PRIORITY_NORMAL, RUNNER_PRIORITY_HIGH)
    ):
        raise ControlError("controller report execution policy is invalid")
    expected_trace: list[dict[str, Any]] = []
    for pair_index in range(pair_count):
        roles = (
            ("parent", "candidate")
            if pair_index % 2 == 0
            else ("candidate", "parent")
        )
        for order_index, role in enumerate(roles, 1):
            expected_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index,
                    "role": role,
                    "runner_sha256": (
                        parent_sha256 if role == "parent" else candidate_sha256
                    ),
                }
            )
    if report.get("execution_trace") != expected_trace:
        raise ControlError("controller execution trace is not strictly alternating")
    raw_pairs = report.get("raw_pairs")
    if not isinstance(raw_pairs, list) or len(raw_pairs) != pair_count:
        raise ControlError("controller raw pair count is invalid")
    scenario_suites: dict[str, str] | None = None
    for pair in raw_pairs:
        if not isinstance(pair, dict) or set(pair) != {"parent", "candidate"}:
            raise ControlError("controller report contains a malformed raw pair")
        for role in ("parent", "candidate"):
            expected_sha256 = (
                parent_sha256 if role == "parent" else candidate_sha256
            )
            observed = validate_report(pair[role], expected_sha256)
            scenario_suites = require_same_scenarios(scenario_suites, observed)
    assert scenario_suites is not None
    if sorted(scenario_suites) != scenario_list:
        raise ControlError("controller scenario ids do not match retained raw reports")
    if expected_schema == CONTROL_SCHEMA and report.get(
        "scenario_suites"
    ) != scenario_suites:
        raise ControlError("v4 scenario suite catalog is missing or inconsistent")
    return scenario_suites, raw_pairs


def validate_aa_raw_evidence(
    report: Any, expected_schema: str
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    return validate_control_raw_evidence(report, expected_schema, "aa")


LEGACY_COMPARISON_OBSERVATION_FIELDS = (
    "id",
    "parent_median_p50_ns_per_op",
    "candidate_median_p50_ns_per_op",
    "median_p50_delta_percent",
    "parent_median_p99_ns_per_op",
    "candidate_median_p99_ns_per_op",
    "median_p99_delta_percent",
    "paired_p50_delta_percent",
    "paired_p99_delta_percent",
    "aa_noise_median_absolute_percent",
    "aa_noise_median_absolute_p99_percent",
)


def validate_legacy_comparisons(
    source_comparisons: Any,
    observations: list[dict[str, Any]],
) -> bool:
    if not isinstance(source_comparisons, list) or len(source_comparisons) != len(
        observations
    ):
        raise ControlError("legacy A/A comparison count is invalid")
    source_by_id: dict[str, dict[str, Any]] = {}
    for comparison in source_comparisons:
        if not isinstance(comparison, dict):
            raise ControlError("legacy A/A comparison is malformed")
        identifier = comparison.get("id")
        if not isinstance(identifier, str) or identifier in source_by_id:
            raise ControlError("legacy A/A comparison id is invalid")
        source_by_id[identifier] = comparison
    legacy_passed = True
    for observation in observations:
        source = source_by_id.get(observation["id"])
        if source is None:
            raise ControlError("legacy A/A comparison scenario set changed")
        for field in LEGACY_COMPARISON_OBSERVATION_FIELDS:
            if source.get(field) != observation.get(field):
                raise ControlError(
                    f"legacy A/A comparison {observation['id']} changed {field}"
                )
        if source.get("median_limit_percent") != NOISY_GATE_CEILING_PERCENT:
            raise ControlError("legacy A/A median limit is invalid")
        if source.get("p99_limit_percent") != P99_TARGET_PERCENT:
            raise ControlError("legacy A/A p99 limit is invalid")
        aa_noise = observation["aa_noise_median_absolute_percent"]
        aa_p99_noise = observation["aa_noise_median_absolute_p99_percent"]
        expected_passed = (
            aa_noise is not None
            and aa_noise <= NOISY_GATE_CEILING_PERCENT
            and aa_p99_noise is not None
            and aa_p99_noise <= P99_TARGET_PERCENT
        )
        expected_decision = "passed" if expected_passed else "failed"
        if source.get("decision") != expected_decision:
            raise ControlError(
                f"legacy A/A comparison {observation['id']} decision is inconsistent"
            )
        legacy_passed = legacy_passed and expected_passed
    return legacy_passed


def validate_legacy_threshold_policy(
    policy: Any,
    observations: list[dict[str, Any]],
    legacy_gate_passed: bool,
) -> float:
    if not isinstance(policy, dict):
        raise ControlError("legacy A/A threshold policy is missing")
    expected_fields = {
        "local_target_percent": LOCAL_TARGET_PERCENT,
        "noisy_gate_ceiling_percent": NOISY_GATE_CEILING_PERCENT,
        "p99_parity_target_percent": P99_TARGET_PERCENT,
        "calibration_source": "current_aa_run",
        "calibration_sha256": None,
        "enforced": True,
    }
    if any(policy.get(field) != value for field, value in expected_fields.items()):
        raise ControlError("legacy A/A threshold policy fields are invalid")
    expected_decision = "passed" if legacy_gate_passed else "failed"
    if (
        policy.get("gate_passed") is not legacy_gate_passed
        or policy.get("decision") != expected_decision
    ):
        raise ControlError("legacy A/A threshold decision is inconsistent")
    effective_limit = calibrated_limit_v3(observations)
    if policy.get("calibrated_median_limit_percent") != effective_limit:
        raise ControlError("legacy A/A calibrated median limit is inconsistent")
    return effective_limit


def validate_reclassification_provenance(
    report: dict[str, Any],
    observations: list[dict[str, Any]],
    raw_pairs: list[dict[str, Any]],
    source_directory: Path | None,
) -> None:
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise ControlError("reclassified A/A calibration has no provenance")
    expected_fields = {
        "derivation": "offline_policy_reclassification",
        "source_schema": LEGACY_CONTROL_SCHEMA,
        "source_threshold_policy_version": LEGACY_THRESHOLD_POLICY_VERSION,
        "source_threshold_policy_version_basis": "validated_control_v2_fields",
        "source_gate_passed": False,
        "source_decision": "failed",
        "raw_pairs_transform": "none",
        "raw_pairs_canonicalization": "json_sort_keys_compact_utf8",
    }
    if any(
        provenance.get(field) != value for field, value in expected_fields.items()
    ):
        raise ControlError("reclassified A/A provenance fields are invalid")
    if not is_sha256(provenance.get("source_report_sha256")):
        raise ControlError("reclassified A/A source report SHA-256 is invalid")
    source_artifact = provenance.get("source_report_artifact")
    if (
        not isinstance(source_artifact, str)
        or not source_artifact
        or Path(source_artifact).name != source_artifact
    ):
        raise ControlError("reclassified A/A source report artifact is invalid")
    if source_directory is not None:
        source_path = source_directory / source_artifact
        if not source_path.is_file() or sha256_file(source_path) != provenance.get(
            "source_report_sha256"
        ):
            raise ControlError(
                "reclassified A/A source report artifact is missing or changed"
            )
    raw_pairs_sha256 = canonical_json_sha256(raw_pairs)
    if (
        provenance.get("source_raw_pairs_sha256") != raw_pairs_sha256
        or provenance.get("reclassified_raw_pairs_sha256") != raw_pairs_sha256
    ):
        raise ControlError("reclassified A/A raw pairs do not match their source hash")
    source_comparisons = provenance.get("source_comparisons")
    if provenance.get("source_comparisons_sha256") != canonical_json_sha256(
        source_comparisons
    ):
        raise ControlError("reclassified A/A source comparisons hash is invalid")
    legacy_gate_passed = validate_legacy_comparisons(
        source_comparisons, observations
    )
    if legacy_gate_passed:
        raise ControlError("reclassified A/A provenance does not retain a failed gate")
    validate_legacy_threshold_policy(
        provenance.get("source_threshold_policy"),
        observations,
        legacy_gate_passed,
    )


def validate_v3_aa_calibration(
    calibration: dict[str, Any],
    source_directory: Path | None = None,
) -> tuple[dict[str, str], float]:
    scenario_suites, raw_pairs = validate_aa_raw_evidence(
        calibration, V3_CONTROL_SCHEMA
    )
    comparisons = summarize_v3(
        scenario_suites,
        raw_pairs,
        True,
        NOISY_GATE_CEILING_PERCENT,
    )
    if calibration.get("comparisons") != comparisons:
        raise ControlError("A/A calibration comparisons do not match retained raw pairs")
    effective_limit = calibrated_limit_v3(comparisons)
    policy = calibration.get("threshold_policy")
    if not isinstance(policy, dict):
        raise ControlError("A/A calibration threshold policy is missing")
    calibration_source = policy.get("calibration_source")
    if calibration_source not in (
        "current_aa_run",
        "reclassified_legacy_aa_raw_pairs",
    ):
        raise ControlError("A/A calibration source is invalid")
    expected_policy = threshold_policy_v3(
        comparisons,
        effective_limit,
        calibration_source,
        None,
    )
    if policy != expected_policy:
        raise ControlError("A/A calibration threshold policy is inconsistent")
    if policy["gate_passed"] is not True:
        raise ControlError("A/A calibration did not pass its median noise gate")
    if calibration_source == "reclassified_legacy_aa_raw_pairs":
        validate_reclassification_provenance(
            calibration,
            comparisons,
            raw_pairs,
            source_directory,
        )
    elif "provenance" in calibration:
        raise ControlError("direct A/A calibration must not claim reclassification")
    return scenario_suites, effective_limit


def load_v3_calibration(
    path: Path,
    parent_sha256: str,
    scenario_suites: dict[str, str],
    runner_arguments: list[str],
    runner_priority: str,
) -> tuple[dict[str, Any], float]:
    try:
        calibration = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ControlError("A/A calibration is not valid JSON") from error
    if not isinstance(calibration, dict):
        raise ControlError("--calibration must be an A/A controller report")
    calibrated_scenarios, limit = validate_v3_aa_calibration(
        calibration, path.resolve().parent
    )
    if calibration.get("parent_runner_sha256") != parent_sha256 or calibration.get(
        "candidate_runner_sha256"
    ) != parent_sha256:
        raise ControlError("A/A calibration runner SHA-256 does not match the parent")
    if calibrated_scenarios != scenario_suites:
        raise ControlError("A/A calibration scenario set does not match this run")
    if calibration.get("runner_arguments") != runner_arguments:
        raise ControlError("A/A calibration runner arguments do not match this run")
    execution_policy = calibration.get("execution_policy")
    if (
        not isinstance(execution_policy, dict)
        or execution_policy.get("pair_order") != "alternating_parent_candidate"
        or execution_policy.get("raw_reports_retained") is not True
        or execution_policy.get("runner_process_priority") != runner_priority
    ):
        raise ControlError("A/A calibration execution policy does not match this run")
    return calibration, float(limit)


def read_json_report(path: Path, label: str) -> tuple[Path, dict[str, Any], str]:
    resolved = path.resolve(strict=True)
    source_bytes = resolved.read_bytes()
    try:
        report = json.loads(source_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(report, dict):
        raise ControlError(f"{label} is not a JSON object")
    return resolved, report, hashlib.sha256(source_bytes).hexdigest()


def validate_v4_reclassification_provenance(
    report: dict[str, Any],
    scenario_suites: dict[str, str],
    raw_pairs: list[dict[str, Any]],
    source_directory: Path | None,
) -> None:
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise ControlError("reclassified v4 report has no provenance")
    expected_mode = report["mode"]
    expected_source_gate = expected_mode == "aa"
    expected_fields = {
        "derivation": "offline_scope_reclassification",
        "source_schema": V3_CONTROL_SCHEMA,
        "source_mode": expected_mode,
        "source_threshold_policy_version": V3_THRESHOLD_POLICY_VERSION,
        "source_gate_passed": expected_source_gate,
        "source_decision": "passed" if expected_source_gate else "failed",
        "raw_pairs_transform": "none",
        "raw_pairs_canonicalization": "json_sort_keys_compact_utf8",
    }
    if any(
        provenance.get(field) != value for field, value in expected_fields.items()
    ):
        raise ControlError("reclassified v4 provenance fields are invalid")
    source_artifact = provenance.get("source_report_artifact")
    if (
        not isinstance(source_artifact, str)
        or not source_artifact
        or Path(source_artifact).name != source_artifact
        or not is_sha256(provenance.get("source_report_sha256"))
    ):
        raise ControlError("reclassified v4 source report identity is invalid")
    if source_directory is not None:
        source_path = source_directory / source_artifact
        if not source_path.is_file() or sha256_file(source_path) != provenance.get(
            "source_report_sha256"
        ):
            raise ControlError("reclassified v4 source report is missing or changed")
    raw_pairs_sha256 = canonical_json_sha256(raw_pairs)
    if (
        provenance.get("source_raw_pairs_sha256") != raw_pairs_sha256
        or provenance.get("reclassified_raw_pairs_sha256") != raw_pairs_sha256
    ):
        raise ControlError("reclassified v4 raw pairs do not match their source hash")
    source_comparisons = provenance.get("source_comparisons")
    if provenance.get("source_comparisons_sha256") != canonical_json_sha256(
        source_comparisons
    ):
        raise ControlError("reclassified v4 source comparison hash is invalid")
    source_policy = provenance.get("source_threshold_policy")
    if not isinstance(source_policy, dict):
        raise ControlError("reclassified v4 source threshold policy is missing")
    same_binary = expected_mode == "aa"
    source_limit = source_policy.get("calibrated_median_limit_percent")
    if type(source_limit) not in (int, float):
        raise ControlError("reclassified v4 source median limit is invalid")
    expected_source_comparisons = summarize_v3(
        scenario_suites,
        raw_pairs,
        same_binary,
        float(source_limit),
    )
    if source_comparisons != expected_source_comparisons:
        raise ControlError("reclassified v4 source comparisons changed")
    expected_source_policy = threshold_policy_v3(
        source_comparisons,
        float(source_limit),
        source_policy.get("calibration_source"),
        source_policy.get("calibration_sha256"),
    )
    if source_policy != expected_source_policy:
        raise ControlError("reclassified v4 source policy is inconsistent")
    failed_ids = sorted(
        row["id"] for row in source_comparisons if row["decision"] == "failed"
    )
    if (
        provenance.get("source_failed_comparison_count") != len(failed_ids)
        or provenance.get("source_failed_comparison_ids") != failed_ids
    ):
        raise ControlError("reclassified v4 source failure set changed")
    if same_binary:
        if source_limit != calibrated_limit_v3(source_comparisons):
            raise ControlError("reclassified v4 A/A source calibration changed")
        if failed_ids:
            raise ControlError("reclassified v4 A/A source chain is incomplete")
    else:
        if not failed_ids:
            raise ControlError("reclassified v4 A/B source has no retained failures")
        source_calibration_artifact = provenance.get("source_calibration_artifact")
        if (
            not isinstance(source_calibration_artifact, str)
            or Path(source_calibration_artifact).name != source_calibration_artifact
            or provenance.get("source_calibration_sha256")
            != source_policy.get("calibration_sha256")
            or provenance.get("source_calibration_original_reference")
            != source_policy.get("calibration_source")
        ):
            raise ControlError("reclassified v4 source calibration identity is invalid")
        if source_directory is not None:
            source_calibration_path = source_directory / source_calibration_artifact
            if not source_calibration_path.is_file() or sha256_file(
                source_calibration_path
            ) != provenance.get("source_calibration_sha256"):
                raise ControlError(
                    "reclassified v4 source calibration is missing or changed"
                )
            _, validated_source_limit = load_v3_calibration(
                source_calibration_path,
                report["parent_runner_sha256"],
                scenario_suites,
                report["runner_arguments"],
                report["execution_policy"]["runner_process_priority"],
            )
            if source_limit != validated_source_limit:
                raise ControlError("reclassified v4 A/B source calibration changed")


def validate_v4_aa_calibration(
    calibration: dict[str, Any],
    source_directory: Path | None = None,
) -> tuple[dict[str, str], float]:
    scenario_suites, raw_pairs = validate_aa_raw_evidence(
        calibration,
        CONTROL_SCHEMA,
    )
    comparisons = summarize(
        scenario_suites,
        raw_pairs,
        True,
        NOISY_GATE_CEILING_PERCENT,
    )
    if calibration.get("comparisons") != comparisons:
        raise ControlError("v4 A/A comparisons do not match retained raw pairs")
    effective_limit = calibrated_limit(comparisons)
    policy = calibration.get("threshold_policy")
    if not isinstance(policy, dict):
        raise ControlError("v4 A/A threshold policy is missing")
    calibration_source = policy.get("calibration_source")
    if calibration_source not in ("current_aa_run", "reclassified_v3_aa_raw_pairs"):
        raise ControlError("v4 A/A calibration source is invalid")
    expected_policy = threshold_policy(
        comparisons,
        effective_limit,
        calibration_source,
        None,
    )
    if policy != expected_policy:
        raise ControlError("v4 A/A threshold policy is inconsistent")
    if policy["gate_passed"] is not True:
        raise ControlError("v4 A/A did not pass its match_set median noise gate")
    if calibration_source == "reclassified_v3_aa_raw_pairs":
        validate_v4_reclassification_provenance(
            calibration,
            scenario_suites,
            raw_pairs,
            source_directory,
        )
    elif "provenance" in calibration:
        raise ControlError("direct v4 A/A must not claim reclassification")
    return scenario_suites, effective_limit


def load_calibration(
    path: Path,
    parent_sha256: str,
    scenario_suites: dict[str, str],
    runner_arguments: list[str],
    runner_priority: str,
) -> tuple[dict[str, Any], float]:
    _, calibration, _ = read_json_report(path, "v4 A/A calibration")
    calibrated_scenarios, limit = validate_v4_aa_calibration(
        calibration,
        path.resolve().parent,
    )
    if calibration.get("parent_runner_sha256") != parent_sha256 or calibration.get(
        "candidate_runner_sha256"
    ) != parent_sha256:
        raise ControlError("v4 A/A runner SHA-256 does not match the parent")
    if calibrated_scenarios != scenario_suites:
        raise ControlError("v4 A/A scenario suite catalog does not match this run")
    if calibration.get("runner_arguments") != runner_arguments:
        raise ControlError("v4 A/A runner arguments do not match this run")
    if calibration["execution_policy"].get(
        "runner_process_priority"
    ) != runner_priority:
        raise ControlError("v4 A/A runner priority does not match this run")
    return calibration, float(limit)


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--parent", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--pairs", type=int, default=MIN_PAIRS)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument(
        "--runner-priority",
        choices=(RUNNER_PRIORITY_NORMAL, RUNNER_PRIORITY_HIGH),
        default=RUNNER_PRIORITY_NORMAL,
        help=(
            "runner child priority; 'high' uses Windows HIGH_PRIORITY_CLASS "
            "and fails closed on other platforms"
        ),
    )
    parser.add_argument(
        "--calibration",
        type=Path,
        help="passing A/A controller JSON; required for parent/candidate gating",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("runner_arguments", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(arguments)
    if parsed.runner_arguments[:1] == ["--"]:
        parsed.runner_arguments = parsed.runner_arguments[1:]
    return parsed


def emit_result(result: dict[str, Any], output: Path | None) -> None:
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output is not None:
        if output.suffix != ".json":
            raise ControlError("--output must have a .json extension")
        output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)


def control(arguments: list[str] | None = None) -> dict[str, Any]:
    args = parse_arguments(arguments)
    validate_pairs(args.pairs)
    if not 1 <= args.timeout_seconds <= 3_600:
        raise ControlError("--timeout-seconds must be in 1..=3600")
    assert args.parent is not None
    parent = args.parent.resolve(strict=True)
    candidate = (args.candidate or args.parent).resolve(strict=True)
    if not parent.is_file() or not candidate.is_file():
        raise ControlError("parent and candidate runners must be files")
    parent_sha = sha256_file(parent)
    candidate_sha = sha256_file(candidate)
    creation_flags = runner_creation_flags(args.runner_priority)
    expected_scenarios: dict[str, str] | None = None
    pairs: list[dict[str, Any]] = []
    execution_trace: list[dict[str, Any]] = []
    for pair_index in range(args.pairs):
        pair: dict[str, Any] = {}
        for order_index, (role, executable) in enumerate(
            pair_execution_order(pair_index, parent, candidate)
        ):
            expected_sha = parent_sha if role == "parent" else candidate_sha
            report, scenarios = run_once(
                role,
                executable,
                args.runner_arguments,
                args.timeout_seconds,
                expected_sha,
                creation_flags,
            )
            expected_scenarios = require_same_scenarios(expected_scenarios, scenarios)
            pair[role] = report
            execution_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index + 1,
                    "role": role,
                    "runner_sha256": expected_sha,
                }
            )
        pairs.append(pair)
    assert expected_scenarios is not None
    same_binary = parent_sha == candidate_sha
    if same_binary:
        comparisons = summarize(
            expected_scenarios,
            pairs,
            True,
            NOISY_GATE_CEILING_PERCENT,
        )
        calibration_source = "current_aa_run"
        calibration_sha256 = None
        effective_median_limit = calibrated_limit(comparisons)
    else:
        if args.calibration is None:
            raise ControlError(
                "parent/candidate gating requires --calibration from a passing A/A run"
            )
        calibration_path = args.calibration.resolve(strict=True)
        _, effective_median_limit = load_calibration(
            calibration_path,
            parent_sha,
            expected_scenarios,
            args.runner_arguments,
            args.runner_priority,
        )
        comparisons = summarize(
            expected_scenarios,
            pairs,
            False,
            effective_median_limit,
        )
        calibration_source = str(calibration_path)
        calibration_sha256 = sha256_file(calibration_path)
    result = {
        "schema": CONTROL_SCHEMA,
        "generated_unix_millis": time.time_ns() // 1_000_000,
        "mode": "aa" if same_binary else "parent_candidate",
        "pairs": args.pairs,
        "parent_runner_sha256": parent_sha,
        "candidate_runner_sha256": candidate_sha,
        "runner_arguments": args.runner_arguments,
        "scenario_ids": sorted(expected_scenarios),
        "scenario_suites": dict(sorted(expected_scenarios.items())),
        "execution_policy": {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": args.runner_priority,
        },
        "execution_trace": execution_trace,
        "comparisons": comparisons,
        "threshold_policy": threshold_policy(
            comparisons,
            effective_median_limit,
            calibration_source,
            calibration_sha256,
        ),
        "raw_pairs": pairs,
    }
    emit_result(result, args.output)
    return result


def main() -> int:
    try:
        result = control()
    except (ControlError, OSError, subprocess.TimeoutExpired) as error:
        print(f"rule qualification control failed: {error}", file=sys.stderr)
        return 1
    if result["threshold_policy"]["gate_passed"] is not True:
        print("rule qualification performance gate failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
