"""Deterministic Linux A/A and A/B execution schedule owner."""

from __future__ import annotations

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.scale import SCALE_SCENARIO


def scenario_schedule(
    *,
    plan: dict[str, object],
    scenario: str,
    self_calibrated: bool,
) -> list[dict[str, object]]:
    """Return the closed execution order for one planned scenario."""

    planned = {entry["scenario"] for entry in plan["scenarios"]}
    if scenario not in planned:
        raise CandidateControlError("schedule scenario is not in the canonical plan")
    if self_calibrated and (
        plan["mode"] != "qualification" or plan["selection"] == SCALE_SCENARIO
    ):
        raise CandidateControlError(
            "self-calibrated scheduling requires an ordinary qualification plan"
        )
    operations: list[dict[str, object]] = []
    for pair in range(1, int(plan["pairs"]) + 1):
        if pair % 2:
            ab = (
                ("parent", "paired", "parent", 1, "ab"),
                ("candidate", "paired", "candidate", 2, "ab"),
            )
            aa = (
                ("parent", "calibration-left", "parent", 1, "aa"),
                ("parent", "calibration-right", "candidate", 2, "aa"),
            )
        else:
            ab = (
                ("candidate", "paired", "candidate", 1, "ab"),
                ("parent", "paired", "parent", 2, "ab"),
            )
            aa = (
                ("parent", "calibration-right", "candidate", 1, "aa"),
                ("parent", "calibration-left", "parent", 2, "aa"),
            )
        ordered = (*aa, *ab) if pair % 2 else (*ab, *aa)
        for source, evidence_directory, member, order, comparison in (
            ordered if self_calibrated else ab
        ):
            operations.append(
                {
                    "scenario": scenario,
                    "source": source,
                    "evidence_directory": evidence_directory,
                    "member": member,
                    "pair": pair,
                    "order": order,
                    "comparison": comparison,
                }
            )
    return operations


def schedule_tsv(operations: list[dict[str, object]]) -> str:
    return "".join(
        "\t".join(
            str(operation[field])
            for field in (
                "source",
                "evidence_directory",
                "member",
                "pair",
                "order",
                "comparison",
            )
        )
        + "\n"
        for operation in operations
    )
