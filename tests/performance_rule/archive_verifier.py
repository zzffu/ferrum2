"""Test-owned verifier for external historical controller evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ARCHIVED_CONTROLLER_CONTRACTS = {
    "archived_v2_aa_diagnostic": (
        "ferrum2.rule-qualification-control.v2",
        "aa",
        None,
    ),
    "archived_v3_aa_calibration": (
        "ferrum2.rule-qualification-control.v3",
        "aa",
        "outer-median-gates.v2",
    ),
    "archived_v3_ab_diagnostic": (
        "ferrum2.rule-qualification-control.v3",
        "parent_candidate",
        "outer-median-gates.v2",
    ),
    "archived_v4_aa_calibration": (
        "ferrum2.rule-qualification-control.v4",
        "aa",
        "section-5.7-match-set-median-gates.v3",
    ),
    "archived_v4_ab_comparison": (
        "ferrum2.rule-qualification-control.v4",
        "parent_candidate",
        "section-5.7-match-set-median-gates.v3",
    ),
}


def _closed_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def validate_archived_controller(path: Path, role: str) -> None:
    try:
        schema, mode, policy_version = ARCHIVED_CONTROLLER_CONTRACTS[role]
    except KeyError as error:
        raise ValueError(f"unsupported archived controller role: {role}") from error
    report = _closed_json(path)
    if not isinstance(report, dict):
        raise ValueError(f"archived controller {path.name} is not an object")
    if report.get("schema") != schema or report.get("mode") != mode:
        raise ValueError(f"archived controller {path.name} schema or mode changed")
    pairs = report.get("pairs")
    raw_pairs = report.get("raw_pairs")
    if type(pairs) is not int or pairs < 5 or not isinstance(raw_pairs, list):
        raise ValueError(f"archived controller {path.name} pair evidence is invalid")
    if len(raw_pairs) != pairs:
        raise ValueError(f"archived controller {path.name} raw pairs are incomplete")
    execution = report.get("execution_policy")
    if (
        not isinstance(execution, dict)
        or execution.get("pair_order") != "alternating_parent_candidate"
        or execution.get("raw_reports_retained") is not True
    ):
        raise ValueError(f"archived controller {path.name} execution policy changed")
    policy = report.get("threshold_policy")
    if (
        not isinstance(policy, dict)
        or (policy_version is None and "version" in policy)
        or (policy_version is not None and policy.get("version") != policy_version)
    ):
        raise ValueError(f"archived controller {path.name} threshold policy changed")
