"""Current reviewed threshold policy and qualification status owner."""

from __future__ import annotations

from typing import Any

from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CANDIDATE_WIN,
    DNS_POLICY_SUITE,
    LOCAL_TARGET_PERCENT,
    MATCH_SET_SUITE,
    NOISY_GATE_CEILING_PERCENT,
    P99_CLASSIFICATION,
    P99_GATE_OWNER,
    P99_TARGET_PERCENT,
    REGRESSION,
    ROUTE_PROGRAM_SUITE,
    SNAPSHOT_REGISTRY_SUITE,
    SUITE_POLICY,
    THRESHOLD_POLICY_VERSION,
    WITHIN_CALIBRATED_BAND,
    ControlError,
)


def _max_absolute(rows: list[dict[str, Any]], field: str) -> float | None:
    values = [row[field] for row in rows if row.get(field) is not None]
    return max((abs(value) for value in values), default=None)


def observed_suite_summary(
    comparisons: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for suite in (ROUTE_PROGRAM_SUITE, DNS_POLICY_SUITE, SNAPSHOT_REGISTRY_SUITE):
        rows = [row for row in comparisons if row.get("suite") == suite]
        result[suite] = {
            "comparison_count": len(rows),
            "max_absolute_median_p50_delta_percent": _max_absolute(
                rows, "median_p50_delta_percent"
            ),
            "max_absolute_median_p99_delta_percent": _max_absolute(
                rows, "median_p99_delta_percent"
            ),
            "max_aa_pair_median_absolute_p50_delta_percent": _max_absolute(
                rows, "aa_noise_median_absolute_percent"
            ),
            "max_aa_pair_median_absolute_p99_delta_percent": _max_absolute(
                rows, "aa_noise_median_absolute_p99_percent"
            ),
        }
    return result


def calibration_required_policy() -> dict[str, Any]:
    return {
        "version": THRESHOLD_POLICY_VERSION,
        "status": CALIBRATION_REQUIRED,
        "reviewed": False,
        "enforced": False,
        "gate_passed": False,
        "decision": "calibration_required",
    }


def threshold_policy(
    comparisons: list[dict[str, Any]],
    effective_median_limits: dict[str, float],
    calibration_source: str | None,
    calibration_sha256: str | None,
    *,
    reviewed: bool,
) -> dict[str, Any]:
    if set(effective_median_limits) != {
        MATCH_SET_SUITE,
        SNAPSHOT_REGISTRY_SUITE,
    } or any(
        type(limit) not in (int, float) or not 0 < limit <= NOISY_GATE_CEILING_PERCENT
        for limit in effective_median_limits.values()
    ):
        raise ControlError("reviewed median calibration limits are invalid")
    hard_gate_rows = [
        row for row in comparisons if row.get("median_gate_applicable") is True
    ]
    match_rows = [row for row in comparisons if row.get("suite") == MATCH_SET_SUITE]
    snapshot_rows = [
        row for row in comparisons if row.get("suite") == SNAPSHOT_REGISTRY_SUITE
    ]
    if (
        not match_rows
        or not snapshot_rows
        or any(row.get("median_gate_applicable") is not True for row in match_rows)
        or any(
            row.get("suite") not in {MATCH_SET_SUITE, SNAPSHOT_REGISTRY_SUITE}
            for row in hard_gate_rows
        )
    ):
        raise ControlError("outer median gate scope is incomplete")
    conditional_states = {row.get("conditional_gate_enabled") for row in snapshot_rows}
    if len(conditional_states) != 1 or not conditional_states.issubset({True, False}):
        raise ControlError("snapshot conditional feature evidence is inconsistent")
    snapshot_gate_expected = not reviewed or conditional_states == {True}
    if any(
        row.get("median_gate_applicable") is not snapshot_gate_expected
        or row.get("median_classification") != "candidate_conditional"
        for row in snapshot_rows
    ):
        raise ControlError("snapshot conditional gate applicability is invalid")
    observed_rows = [
        row for row in comparisons if row.get("median_gate_applicable") is False
    ]
    if any(row.get("decision") != "observed" for row in observed_rows):
        raise ControlError("observational suite produced a hard decision")
    observed_gate_passed = all(
        row["median_decision"] in {"passed", "improved"} for row in hard_gate_rows
    )
    observed_candidate_win = observed_gate_passed and any(
        row["median_decision"] == "improved" for row in hard_gate_rows
    )
    hard_gate_suites = [MATCH_SET_SUITE]
    if snapshot_gate_expected:
        hard_gate_suites.append(SNAPSHOT_REGISTRY_SUITE)
    observed_suites = [ROUTE_PROGRAM_SUITE, DNS_POLICY_SUITE]
    if not snapshot_gate_expected:
        observed_suites.append(SNAPSHOT_REGISTRY_SUITE)
    status = (
        CALIBRATION_REQUIRED
        if not reviewed
        else (
            REGRESSION
            if not observed_gate_passed
            else CANDIDATE_WIN if observed_candidate_win else WITHIN_CALIBRATED_BAND
        )
    )
    return {
        "version": THRESHOLD_POLICY_VERSION,
        "status": status,
        "reviewed": reviewed,
        "gate_metric": "cross_process_median_p50_by_reviewed_suite",
        "suite_policy": {suite: dict(policy) for suite, policy in SUITE_POLICY.items()},
        "hard_gate_suites": hard_gate_suites,
        "observed_suites": observed_suites,
        "hard_gate_comparison_count": len(hard_gate_rows),
        "observed_comparison_count": len(observed_rows),
        "observed_suite_summary": observed_suite_summary(comparisons),
        "local_target_percent": LOCAL_TARGET_PERCENT,
        "noisy_gate_ceiling_percent": NOISY_GATE_CEILING_PERCENT,
        "p99_parity_target_percent": P99_TARGET_PERCENT,
        "p99_classification": P99_CLASSIFICATION,
        "p99_gate_applicable": False,
        "p99_gate_owner": P99_GATE_OWNER,
        "calibrated_median_limits_percent": dict(
            sorted(effective_median_limits.items())
        ),
        "calibration_source": calibration_source,
        "calibration_sha256": calibration_sha256,
        "enforced": reviewed,
        "gate_passed": reviewed and observed_gate_passed,
        "decision": (
            "calibration_required"
            if not reviewed
            else (
                "improved"
                if observed_candidate_win
                else "passed" if observed_gate_passed else "failed"
            )
        ),
    }
