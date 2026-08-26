"""Alternating pair schedule, observations, and current-suite reductions."""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any

from tools.performance_rule.schema import (
    ControlError,
    DNS_POLICY_SUITE,
    LOCAL_TARGET_PERCENT,
    MATCH_SET_SUITE,
    NOISY_GATE_CEILING_PERCENT,
    P99_CLASSIFICATION,
    P99_TARGET_PERCENT,
    ROUTE_PROGRAM_SUITE,
    SUITE_POLICY,
)

def pair_execution_order(
    pair_index: int, parent: Path, candidate: Path
) -> list[tuple[str, Path]]:
    if pair_index % 2 == 0:
        return [("parent", parent), ("candidate", candidate)]
    return [("candidate", candidate), ("parent", parent)]


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
            median_passed = median_delta is not None and median_delta <= median_limit_percent
            median_limit = median_limit_percent
            median_gate_metric = "median_of_run_p50_delta_percent"
        else:
            median_passed = None
            median_limit = None
            median_gate_metric = None
        if median_passed is None:
            decision = "observed"
        elif not median_passed:
            decision = "failed"
        elif not same_binary and observation["median_p50_delta_percent"] < -median_limit:
            decision = "improved"
        else:
            decision = "passed"
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
