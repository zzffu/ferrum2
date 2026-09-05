"""Full non-TUN Linux qualification aggregation owner."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    _canonical_json_bytes,
    read_bounded_closed_json,
)
from tools.ci.required_gate import GateMode, parse_results, validate_gate
from tools.performance_candidate.linux.decision import summarize_evidence
from tools.performance_candidate.linux.plan import PLAN_MAX_BYTES, validate_plan
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
    WITHIN_CALIBRATED_BAND,
    qualification_exit_code,
)

AGGREGATE_SCHEMA_VERSION = 2
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
    selection: str,
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
        if type(summary.get(field)) is not type(expected_value) or summary.get(field) != expected_value:
            raise CandidateControlError(
                f"aggregate input {path} has invalid {field}"
            )
    if summary.get("selection") != selection:
        raise CandidateControlError(
            f"aggregate input {path} has an unexpected selection"
        )
    return summary


def aggregate_summaries(
    *,
    summary_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
    producer_result: str,
) -> dict[str, object]:
    """Rebuild each canonical group's decision after its producing job succeeds."""

    try:
        validate_gate(
            GateMode.PERFORMANCE, True,
            parse_results([f"paired-profile={producer_result}"]),
        )
    except ValueError as error:
        raise CandidateControlError("aggregate requires a successful producing job") from error
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
    selections = set()
    try:
        with os.scandir(summary_root) as entries:
            for entry in entries:
                if (entry.name not in FULL_NON_TUN_GROUPS or entry.is_symlink()
                        or not entry.is_dir(follow_symlinks=False)):
                    raise CandidateControlError("aggregate requires exactly one canonical group directory")
                selections.add(entry.name)
    except OSError as error:
        raise CandidateControlError("unable to enumerate aggregate groups") from error
    if selections != set(FULL_NON_TUN_GROUPS):
        raise CandidateControlError(
            "aggregate requires exactly one calibrated summary per full non-TUN group"
        )
    groups: dict[str, dict[str, object]] = {}
    common_builds = None
    common_environment = None
    for selection in FULL_NON_TUN_GROUPS:
        path = summary_root / selection / SUMMARY_FILE_NAME
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
            selection=selection,
        )
        plan_path = path.parent / "performance-plan.json"
        parent_root = path.parent / "ab-parent"
        candidate_root = path.parent / "ab-candidate"
        if any(item.is_symlink() for item in (plan_path, parent_root, candidate_root)):
            raise CandidateControlError("aggregate group evidence must not be a symlink")
        loaded_plan = read_bounded_closed_json(
            plan_path, maximum_bytes=PLAN_MAX_BYTES, source="aggregate group plan",
        )
        plan = validate_plan(loaded_plan.value)
        if (plan["selection"] != selection or plan["mode"] != "qualification"
                or (plan["warmup_seconds"], plan["active_seconds"], plan["pairs"]) != (3, 30, 6)):
            raise CandidateControlError("aggregate group plan does not match the full non-TUN recipe")
        rebuilt = summarize_evidence(
            plan=plan, parent_root=parent_root, candidate_root=candidate_root,
            parent_sha=parent_sha, candidate_sha=candidate_sha,
        )
        if _canonical_json_bytes(summary) != _canonical_json_bytes(rebuilt):
            raise CandidateControlError("aggregate summary does not match its canonical plan and raw evidence")
        if common_builds is not None and common_builds != summary["build_identities"]:
            raise CandidateControlError("aggregate full build identities differ between groups")
        if common_environment is not None and common_environment != summary["environment_identity"]:
            raise CandidateControlError("aggregate environment identity differs between groups")
        common_builds = summary["build_identities"]
        common_environment = summary["environment_identity"]
        groups[selection] = {
            "selection": selection,
            "status": summary["status"],
            "adoption_claim": summary["adoption_claim"],
            "decision_reason": summary["decision_reason"],
            "summary_file": path.relative_to(summary_root).as_posix(),
            "summary_sha256": bounded.sha256,
            "plan_sha256": loaded_plan.sha256,
            "raw_manifest_sha256": hashlib.sha256(
                _canonical_json_bytes(rebuilt["evidence_files"])
            ).hexdigest(),
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
        "producer_result": producer_result,
        "build_identities": common_builds,
        "environment_identity": common_environment,
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
            producer_result=arguments.producer_result,
        )
    except CandidateControlError as error:
        summary = {
            "schema_version": AGGREGATE_SCHEMA_VERSION,
            "kind": AGGREGATE_KIND,
            "parent_sha": arguments.parent_sha,
            "candidate_sha": arguments.candidate_sha,
            "producer_result": arguments.producer_result,
            "build_identities": {},
            "environment_identity": {},
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
