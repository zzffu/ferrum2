"""Full non-TUN Linux qualification aggregation owner."""

from __future__ import annotations

import json
import pathlib
import re

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux.catalog import (
    FULL_NON_TUN_GROUPS,
    SUMMARY_SCHEMA_VERSION,
)
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.status import (
    CALIBRATION_REQUIRED,
    CANDIDATE_WIN,
    INCONCLUSIVE,
    INVALID,
    REGRESSION,
    TERMINAL_STATUSES,
    WITHIN_CALIBRATED_BAND,
    qualification_exit_code,
)

AGGREGATE_SCHEMA_VERSION = 1
AGGREGATE_KIND = "performance_candidate_full_non_tun_summary"
SUMMARY_KIND = "performance_candidate_summary"
SUMMARY_FILE_NAME = "calibrated-summary.json"
SUMMARY_MAX_BYTES = 2 * 1024 * 1024
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def _validate_summary(
    value: object,
    *,
    path: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError(f"aggregate input {path} must be a JSON object")
    summary = value
    expected = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": SUMMARY_KIND,
        "mode": "qualification",
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "pairs": 6,
        "threshold_availability": "complete",
        "candidate_win_enabled": True,
    }
    for field, expected_value in expected.items():
        if summary.get(field) != expected_value:
            raise CandidateControlError(
                f"aggregate input {path} has invalid {field}"
            )
    selection = summary.get("selection")
    if selection not in FULL_NON_TUN_GROUPS:
        raise CandidateControlError(
            f"aggregate input {path} has an unexpected selection"
        )
    status = summary.get("status")
    if status not in TERMINAL_STATUSES:
        raise CandidateControlError(f"aggregate input {path} has an invalid status")
    if summary.get("adoption_claim") != (status == CANDIDATE_WIN):
        raise CandidateControlError(
            f"aggregate input {path} has an inconsistent adoption claim"
        )
    scenarios = summary.get("scenarios")
    mandatory = summary.get("mandatory_scenarios")
    if type(scenarios) is not list or type(mandatory) is not list or not scenarios:
        raise CandidateControlError(
            f"aggregate input {path} has invalid scenario results"
        )
    scenario_names = [entry.get("scenario") for entry in scenarios if type(entry) is dict]
    if len(scenario_names) != len(scenarios) or scenario_names != mandatory:
        raise CandidateControlError(
            f"aggregate input {path} has inconsistent mandatory scenarios"
        )
    return summary


def aggregate_summaries(
    *,
    summary_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    """Validate exactly one calibrated summary per full non-TUN group."""

    parent_sha = parent_sha.lower()
    candidate_sha = candidate_sha.lower()
    if (
        COMMIT_SHA.fullmatch(parent_sha) is None
        or COMMIT_SHA.fullmatch(candidate_sha) is None
        or parent_sha == candidate_sha
    ):
        raise CandidateControlError(
            "aggregate parent and candidate must be distinct full commit SHAs"
        )
    if not summary_root.is_dir() or summary_root.is_symlink():
        raise CandidateControlError("aggregate summary root is missing or unsafe")
    paths = sorted(summary_root.rglob(SUMMARY_FILE_NAME))
    if len(paths) != len(FULL_NON_TUN_GROUPS):
        raise CandidateControlError(
            "aggregate requires exactly one calibrated summary per full non-TUN group"
        )
    groups: dict[str, dict[str, object]] = {}
    for path in paths:
        if path.is_symlink():
            raise CandidateControlError(f"aggregate input {path} must not be a symlink")
        bounded = read_bounded_closed_json(
            path,
            maximum_bytes=SUMMARY_MAX_BYTES,
            source=f"aggregate input {path}",
        )
        summary = _validate_summary(
            bounded.value,
            path=path,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
        )
        selection = str(summary["selection"])
        if selection in groups:
            raise CandidateControlError(
                f"aggregate contains duplicate selection {selection}"
            )
        groups[selection] = {
            "selection": selection,
            "status": summary["status"],
            "adoption_claim": summary["adoption_claim"],
            "decision_reason": summary["decision_reason"],
            "summary_file": path.relative_to(summary_root).as_posix(),
            "summary_sha256": bounded.sha256,
            "scenarios": [
                {
                    "scenario": scenario["scenario"],
                    "role": scenario["role"],
                    "status": scenario["status"],
                    "median_improvement_percent": scenario[
                        "median_improvement_percent"
                    ],
                }
                for scenario in summary["scenarios"]
            ],
        }
    missing = sorted(set(FULL_NON_TUN_GROUPS) - set(groups))
    if missing:
        raise CandidateControlError(
            f"aggregate is missing full non-TUN groups: {', '.join(missing)}"
        )
    statuses = {entry["status"] for entry in groups.values()}
    if INVALID in statuses:
        status = INVALID
        reason = "at least one non-TUN group is invalid"
    elif REGRESSION in statuses:
        status = REGRESSION
        reason = "at least one non-TUN group regressed"
    elif CALIBRATION_REQUIRED in statuses:
        status = CALIBRATION_REQUIRED
        reason = "at least one non-TUN group lacks applicable calibration"
    elif INCONCLUSIVE in statuses:
        status = INCONCLUSIVE
        reason = "at least one non-TUN group is inconclusive"
    elif CANDIDATE_WIN in statuses:
        status = CANDIDATE_WIN
        reason = "at least one non-TUN group improved and every other group passed"
    else:
        status = WITHIN_CALIBRATED_BAND
        reason = "every non-TUN group remains within its calibrated acceptance band"
    return {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "kind": AGGREGATE_KIND,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "expected_groups": list(FULL_NON_TUN_GROUPS),
        "decision_reason": reason,
        "adoption_claim": status == CANDIDATE_WIN,
        "status": status,
        "groups": [groups[selection] for selection in FULL_NON_TUN_GROUPS],
    }


def _markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Full non-TUN performance candidate",
        "",
        f"- Status: `{summary['status']}`",
        f"- Parent: `{summary['parent_sha']}`",
        f"- Candidate: `{summary['candidate_sha']}`",
        f"- Decision: {summary['decision_reason']}",
        "",
        "| Group | Status |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| `{group['selection']}` | `{group['status']}` |"
        for group in summary.get("groups", [])
    )
    return "\n".join(lines) + "\n"


def run_aggregate_command(arguments: object) -> int:
    try:
        summary = aggregate_summaries(
            summary_root=arguments.summary_root,
            parent_sha=arguments.parent_sha,
            candidate_sha=arguments.candidate_sha,
        )
    except CandidateControlError as error:
        summary = {
            "schema_version": AGGREGATE_SCHEMA_VERSION,
            "kind": AGGREGATE_KIND,
            "parent_sha": arguments.parent_sha,
            "candidate_sha": arguments.candidate_sha,
            "expected_groups": list(FULL_NON_TUN_GROUPS),
            "decision_reason": str(error),
            "adoption_claim": False,
            "status": INVALID,
            "groups": [],
        }
    _atomic_text(
        arguments.output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(arguments.markdown, _markdown(summary))
    return qualification_exit_code(str(summary["status"]))
