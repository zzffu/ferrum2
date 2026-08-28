"""Narrow environment matching for Linux calibration evidence."""

from __future__ import annotations


MEMORY_CAPACITY_QUANTUM_KIB = 64 * 1024
_MEMORY_CAPACITY_HALF_QUANTUM_KIB = MEMORY_CAPACITY_QUANTUM_KIB // 2


def memory_capacity_class(memory_kib: object) -> int | None:
    """Return the nearest 64 MiB capacity anchor for one exact observation."""

    if type(memory_kib) is not int or memory_kib <= 0:
        return None
    capacity = (
        (memory_kib + _MEMORY_CAPACITY_HALF_QUANTUM_KIB)
        // MEMORY_CAPACITY_QUANTUM_KIB
        * MEMORY_CAPACITY_QUANTUM_KIB
    )
    return capacity if capacity > 0 else None


def calibration_environments_match(
    reference: dict[str, object], observed: dict[str, object]
) -> bool:
    """Match calibration environments by one nearest host-memory capacity class.

    Separate GitHub-hosted runner allocations can report slightly different
    ``memory_kib`` values. Cross-round calibration and calibrated A/B policy
    applicability therefore compare nearest 64 MiB capacity anchors. Each class
    is the half-open interval ``[anchor - 32 MiB, anchor + 32 MiB)``. Both
    dictionaries must have the same keys and every other value must be exact.
    Trial validation deliberately does not use this class matcher.
    """

    if set(reference) != set(observed) or "memory_kib" not in reference:
        return False
    reference_capacity = memory_capacity_class(reference["memory_kib"])
    observed_capacity = memory_capacity_class(observed["memory_kib"])
    if reference_capacity is None or reference_capacity != observed_capacity:
        return False
    return all(
        reference[field] == observed[field]
        for field in reference
        if field != "memory_kib"
    )
