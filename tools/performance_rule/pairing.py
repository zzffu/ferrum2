"""Alternating pair schedule, observations, and current-suite reductions."""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any

from tools.performance_rule.schema import (
    ATOMIC_SNAPSHOT_FEATURE,
    ControlError,
    LOCAL_TARGET_PERCENT,
    MATCH_SET_SUITE,
    NOISY_GATE_CEILING_PERCENT,
    P99_CLASSIFICATION,
    P99_TARGET_PERCENT,
    SNAPSHOT_REGISTRY_SUITE,
    SUITE_POLICY,
)

CALIBRATED_SUITES = (MATCH_SET_SUITE, SNAPSHOT_REGISTRY_SUITE)


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


def candidate_features(paired_reports: list[dict[str, Any]]) -> frozenset[str]:
    expected: list[str] | None = None
    for pair in paired_reports:
        features = pair["candidate"]["candidate"]["enabled_features"]
        if not isinstance(features, list) or any(
            not isinstance(feature, str) for feature in features
        ):
            raise ControlError("candidate feature evidence is invalid")
        if expected is None:
            expected = features
        elif features != expected:
            raise ControlError("candidate feature evidence changed between pairs")
    if expected is None:
        raise ControlError("paired reports are empty")
    return frozenset(expected)


def calibration_ceiling_limits() -> dict[str, float]:
    return {suite: NOISY_GATE_CEILING_PERCENT for suite in CALIBRATED_SUITES}


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
    median_limits_percent: dict[str, float],
) -> list[dict[str, Any]]:
    features = candidate_features(paired_reports)
    summaries: list[dict[str, Any]] = []
    for observation in collect_observations(
        scenario_suites, paired_reports, same_binary
    ):
        suite = observation["suite"]
        suite_policy = SUITE_POLICY[suite]
        classification = suite_policy["median_classification"]
        conditional_feature = suite_policy.get("candidate_feature")
        conditional_enabled = (
            conditional_feature in features if conditional_feature is not None else None
        )
        hard_gate = classification == "hard_gate" or (
            classification == "candidate_conditional"
            and (same_binary or conditional_enabled is True)
        )
        if hard_gate and same_binary:
            aa_noise = observation["aa_noise_median_absolute_percent"]
            median_passed = (
                aa_noise is not None and aa_noise <= NOISY_GATE_CEILING_PERCENT
            )
            median_limit = NOISY_GATE_CEILING_PERCENT
            median_gate_metric = "aa_pair_median_absolute_p50_delta_percent"
        elif hard_gate:
            median_delta = observation["median_p50_delta_percent"]
            median_limit = median_limits_percent.get(suite)
            if type(median_limit) not in (int, float) or median_limit <= 0:
                raise ControlError(f"{suite} reviewed calibration limit is invalid")
            median_passed = median_delta is not None and median_delta <= median_limit
            median_gate_metric = "median_of_run_p50_delta_percent"
        else:
            median_passed = None
            median_limit = None
            median_gate_metric = None
        if median_passed is None:
            decision = "observed"
        elif not median_passed:
            decision = "failed"
        elif (
            not same_binary and observation["median_p50_delta_percent"] < -median_limit
        ):
            decision = "improved"
        else:
            decision = "passed"
        summary = dict(observation)
        summary.update(
            {
                "scope_authority": suite_policy["scope_authority"],
                "median_classification": classification,
                "conditional_gate_feature": conditional_feature,
                "conditional_gate_enabled": conditional_enabled,
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


def calibrated_limits(comparisons: list[dict[str, Any]]) -> dict[str, float]:
    limits: dict[str, float] = {}
    for suite in CALIBRATED_SUITES:
        applicable = [
            comparison["aa_noise_median_absolute_percent"]
            for comparison in comparisons
            if comparison.get("median_gate_applicable") is True
            and comparison.get("suite") == suite
        ]
        if not applicable or any(value is None for value in applicable):
            raise ControlError(
                f"A/A report has no complete {suite} calibration evidence"
            )
        if any(
            type(value) not in (int, float)
            or value < 0
            or value > NOISY_GATE_CEILING_PERCENT
            for value in applicable
        ):
            raise ControlError(f"A/A {suite} noise exceeds the reviewed ceiling")
        observed = max(applicable)
        limits[suite] = max(LOCAL_TARGET_PERCENT, observed)
    return limits
