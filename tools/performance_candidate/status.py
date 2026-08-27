"""Closed performance states and process exit semantics."""

from __future__ import annotations


CANDIDATE_WIN = "CANDIDATE_WIN"
WITHIN_CALIBRATED_BAND = "WITHIN_CALIBRATED_BAND"
REGRESSION = "REGRESSION"
INCONCLUSIVE = "INCONCLUSIVE"
CALIBRATION_REQUIRED = "CALIBRATION_REQUIRED"
INVALID = "INVALID"

TERMINAL_STATUSES = frozenset(
    {
        CANDIDATE_WIN,
        WITHIN_CALIBRATED_BAND,
        REGRESSION,
        INCONCLUSIVE,
        CALIBRATION_REQUIRED,
        INVALID,
    }
)

QUALIFICATION_ACCEPTED_STATUSES = frozenset(
    {CANDIDATE_WIN, WITHIN_CALIBRATED_BAND}
)


def qualification_exit_code(status: str) -> int:
    """Map every closed status to the workflow's stable process exit contract."""

    if status not in TERMINAL_STATUSES:
        raise ValueError(f"unsupported performance status: {status}")
    if status in QUALIFICATION_ACCEPTED_STATUSES:
        return 0
    if status == INVALID:
        return 2
    if status == REGRESSION:
        return 3
    return 4


def summary_exit_code(*, mode: str, status: str) -> int:
    """Map a valid summary to its mode-specific workflow exit contract."""

    if mode == "qualification":
        return qualification_exit_code(status)
    if mode != "diagnostic":
        raise ValueError(f"unsupported performance mode: {mode}")
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"unsupported performance status: {status}")
    if status == INCONCLUSIVE:
        return 0
    if status == INVALID:
        return 2
    return 4
