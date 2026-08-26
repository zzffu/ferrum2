"""pairing owner."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from tools.performance_candidate.json_contract import CandidateControlError, _policy_percent

OUTLIER_MODIFIED_Z_THRESHOLD = Decimal("3.5")


MODIFIED_Z_SCALE = Decimal("0.6745")


HIGH_VARIANCE_MAD_MULTIPLIER = Decimal("6")


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    if not ordered:
        raise CandidateControlError("median requires at least one value")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def _improvement(
    parent: int,
    candidate: int,
    direction: str,
    *,
    allow_zero: bool = False,
) -> Decimal:
    if parent < 0 or candidate < 0:
        raise CandidateControlError("metric values must be non-negative")
    if parent == 0:
        if allow_zero and candidate == 0:
            return Decimal(0)
        if allow_zero:
            return Decimal(100 if direction == "higher_is_better" else -100)
        raise CandidateControlError("parent metric baseline must be positive")
    difference = (
        candidate - parent if direction == "higher_is_better" else parent - candidate
    )
    return Decimal(difference) * Decimal(100) / Decimal(parent)


def _display_decimal(value: Decimal) -> float:
    displayed = round(float(value), 9)
    return 0.0 if displayed == 0 else displayed


def _observed_direction(*, wins: int, losses: int) -> str:
    if wins and losses:
        return "mixed"
    if wins:
        return "positive"
    if losses:
        return "negative"
    return "neutral"


def _stability_warnings(
    improvements: Sequence[Decimal], *, noise_band: object
) -> tuple[Decimal, list[str]]:
    median = _median(improvements)
    minimum = min(improvements)
    maximum = max(improvements)
    spread = maximum - minimum
    deviations = [abs(value - median) for value in improvements]
    mad = _median(deviations)
    warnings = []
    if any(value > 0 for value in improvements) and any(
        value < 0 for value in improvements
    ):
        warnings.append("MIXED_DIRECTION")
    if mad > 0:
        minimum_z = MODIFIED_Z_SCALE * abs(minimum - median) / mad
        maximum_z = MODIFIED_Z_SCALE * abs(maximum - median) / mad
        if minimum < median and minimum_z > OUTLIER_MODIFIED_Z_THRESHOLD:
            warnings.append("EXTREME_NEGATIVE_PAIR")
        if maximum > median and maximum_z > OUTLIER_MODIFIED_Z_THRESHOLD:
            warnings.append("EXTREME_POSITIVE_PAIR")
    elif spread > 0:
        if minimum < median:
            warnings.append("EXTREME_NEGATIVE_PAIR")
        if maximum > median:
            warnings.append("EXTREME_POSITIVE_PAIR")
    if noise_band is not None:
        high_variance = spread > Decimal(2) * _policy_percent(
            noise_band, "noise_band_percent"
        )
    else:
        high_variance = (mad > 0 and spread > HIGH_VARIANCE_MAD_MULTIPLIER * mad) or (
            mad == 0 and spread > 0
        )
    if high_variance:
        warnings.append("HIGH_VARIANCE")
    return spread, warnings
