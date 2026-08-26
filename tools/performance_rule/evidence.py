"""Current controller evidence and reviewed calibration contract owner."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from tools.performance_rule.json_contract import closed_json_bytes, exact_fields
from tools.performance_rule.pairing import calibrated_limit, summarize
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.runner_report import require_same_scenarios, validate_report
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CALIBRATION_SCHEMA,
    CONTROL_SCHEMA,
    RUNNER_PRIORITY_HIGH,
    RUNNER_PRIORITY_NORMAL,
    ControlError,
    is_sha256,
    sha256_file,
    validate_pairs,
)


EVIDENCE_MAX_BYTES = 64 * 1024 * 1024


def read_json_report(path: Path, label: str) -> tuple[Path, dict[str, Any], str]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > EVIDENCE_MAX_BYTES:
        raise ControlError(f"{label} exceeds the {EVIDENCE_MAX_BYTES}-byte bound")
    with resolved.open("rb") as source:
        source_bytes = source.read(EVIDENCE_MAX_BYTES + 1)
    report = closed_json_bytes(
        source_bytes, label=label, maximum_bytes=EVIDENCE_MAX_BYTES
    )
    if not isinstance(report, dict):
        raise ControlError(f"{label} is not a JSON object")
    return resolved, report, hashlib.sha256(source_bytes).hexdigest()


def validate_control_raw_evidence(
    report: Any, expected_mode: str
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    validate_control_document(report)
    if report.get("mode") != expected_mode:
        raise ControlError("controller report mode or current schema is invalid")
    pair_count = report.get("pairs")
    validate_pairs(pair_count)
    parent_sha256 = report.get("parent_runner_sha256")
    candidate_sha256 = report.get("candidate_runner_sha256")
    if not is_sha256(parent_sha256) or not is_sha256(candidate_sha256):
        raise ControlError("controller report runner SHA-256 is invalid")
    if expected_mode == "aa" and candidate_sha256 != parent_sha256:
        raise ControlError("A/A report does not use one runner SHA-256")
    if expected_mode == "parent_candidate" and candidate_sha256 == parent_sha256:
        raise ControlError("parent/candidate report uses one runner SHA-256")
    runner_arguments = report.get("runner_arguments")
    if not isinstance(runner_arguments, list) or any(
        not isinstance(value, str) for value in runner_arguments
    ):
        raise ControlError("controller report runner arguments are invalid")
    scenario_list = report.get("scenario_ids")
    if (
        not isinstance(scenario_list, list)
        or not scenario_list
        or any(not isinstance(value, str) or not value for value in scenario_list)
        or scenario_list != sorted(set(scenario_list))
    ):
        raise ControlError("controller report scenario ids are invalid")
    execution_policy = report.get("execution_policy")
    if (
        not isinstance(execution_policy, dict)
        or execution_policy.get("pair_order") != "alternating_parent_candidate"
        or execution_policy.get("raw_reports_retained") is not True
        or execution_policy.get("runner_process_priority")
        not in (RUNNER_PRIORITY_NORMAL, RUNNER_PRIORITY_HIGH)
    ):
        raise ControlError("controller report execution policy is invalid")
    expected_trace: list[dict[str, Any]] = []
    for pair_index in range(pair_count):
        roles = (
            ("parent", "candidate")
            if pair_index % 2 == 0
            else ("candidate", "parent")
        )
        for order_index, role in enumerate(roles, 1):
            expected_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index,
                    "role": role,
                    "runner_sha256": (
                        parent_sha256 if role == "parent" else candidate_sha256
                    ),
                }
            )
    if report.get("execution_trace") != expected_trace:
        raise ControlError("controller execution trace is not strictly alternating")
    raw_pairs = report.get("raw_pairs")
    if not isinstance(raw_pairs, list) or len(raw_pairs) != pair_count:
        raise ControlError("controller raw pair count is invalid")
    scenario_suites: dict[str, str] | None = None
    for pair in raw_pairs:
        if not isinstance(pair, dict) or set(pair) != {"parent", "candidate"}:
            raise ControlError("controller report contains a malformed raw pair")
        for role in ("parent", "candidate"):
            expected_sha = parent_sha256 if role == "parent" else candidate_sha256
            observed = validate_report(pair[role], expected_sha)
            scenario_suites = require_same_scenarios(scenario_suites, observed)
    assert scenario_suites is not None
    if sorted(scenario_suites) != scenario_list:
        raise ControlError("controller scenario ids do not match retained raw reports")
    if report.get("scenario_suites") != scenario_suites:
        raise ControlError("current scenario suite catalog is missing or inconsistent")
    return scenario_suites, raw_pairs


CONTROL_FIELDS = frozenset(
    {
        "schema",
        "generated_unix_millis",
        "mode",
        "status",
        "pairs",
        "parent_runner_sha256",
        "candidate_runner_sha256",
        "runner_arguments",
        "scenario_ids",
        "scenario_suites",
        "execution_policy",
        "execution_trace",
        "comparisons",
        "threshold_policy",
        "raw_pairs",
        "decision_reason",
    }
)
EXECUTION_POLICY_FIELDS = frozenset(
    {"pair_order", "raw_reports_retained", "runner_process_priority"}
)
EXECUTION_TRACE_FIELDS = frozenset({"pair", "order", "role", "runner_sha256"})
CALIBRATION_REQUIRED_POLICY_FIELDS = frozenset(
    {"version", "status", "reviewed", "enforced", "gate_passed", "decision"}
)


def validate_control_document(report: Any) -> dict[str, Any]:
    report = exact_fields(report, CONTROL_FIELDS, label="controller report")
    if report.get("schema") != CONTROL_SCHEMA:
        raise ControlError("controller report uses an unsupported schema")
    validate_pairs(report.get("pairs"))
    if report.get("mode") not in {"aa", "parent_candidate"}:
        raise ControlError("controller report mode is invalid")
    exact_fields(
        report["execution_policy"],
        EXECUTION_POLICY_FIELDS,
        label="controller execution policy",
    )
    trace = report["execution_trace"]
    if not isinstance(trace, list):
        raise ControlError("controller execution trace is not a list")
    for entry in trace:
        exact_fields(entry, EXECUTION_TRACE_FIELDS, label="controller execution trace row")
    if report["status"] == CALIBRATION_REQUIRED and not report["raw_pairs"]:
        exact_fields(
            report["threshold_policy"],
            CALIBRATION_REQUIRED_POLICY_FIELDS,
            label="controller calibration-required policy",
        )
    return report


def load_calibration(
    path: Path,
    parent_sha256: str,
    scenario_suites: dict[str, str],
    runner_arguments: list[str],
    runner_priority: str,
) -> tuple[dict[str, Any], float, str]:
    calibration_path, calibration, calibration_sha256 = read_json_report(
        path, "reviewed A/A calibration"
    )
    expected_fields = {
        "schema",
        "review_status",
        "reviewed_by",
        "reviewed_utc",
        "source_report",
        "source_report_sha256",
        "runner_sha256",
        "runner_arguments",
        "scenario_suites",
        "execution_policy",
        "effective_median_limit_percent",
    }
    if set(calibration) != expected_fields or calibration.get("schema") != CALIBRATION_SCHEMA:
        raise ControlError("reviewed calibration schema is invalid")
    if (
        calibration.get("review_status") != "APPROVED"
        or not isinstance(calibration.get("reviewed_by"), str)
        or not calibration["reviewed_by"].strip()
        or not isinstance(calibration.get("reviewed_utc"), str)
        or not calibration["reviewed_utc"].endswith("Z")
    ):
        raise ControlError("reviewed calibration approval is invalid")
    source_name = calibration.get("source_report")
    if not isinstance(source_name, str) or Path(source_name).name != source_name:
        raise ControlError("reviewed calibration source path is invalid")
    source_path = calibration_path.parent / source_name
    source_resolved, source_report, source_sha256 = read_json_report(
        source_path, "calibration source A/A report"
    )
    if (
        source_resolved.parent != calibration_path.parent
        or source_sha256 != calibration.get("source_report_sha256")
    ):
        raise ControlError("reviewed calibration source identity changed")
    source_suites, raw_pairs = validate_control_raw_evidence(source_report, "aa")
    comparisons = summarize(source_suites, raw_pairs, True, 10.0)
    effective_limit = calibrated_limit(comparisons)
    expected_source_policy = threshold_policy(
        comparisons, effective_limit, None, None, reviewed=False
    )
    if (
        source_report.get("status") != CALIBRATION_REQUIRED
        or source_report.get("comparisons") != comparisons
        or source_report.get("threshold_policy") != expected_source_policy
    ):
        raise ControlError("calibration source A/A derivation is inconsistent")
    if (
        calibration.get("runner_sha256") != parent_sha256
        or calibration.get("runner_sha256") != source_report["parent_runner_sha256"]
        or calibration.get("runner_arguments") != runner_arguments
        or calibration.get("scenario_suites") != scenario_suites
        or calibration.get("scenario_suites") != source_suites
        or calibration.get("execution_policy")
        != {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": runner_priority,
        }
        or calibration.get("effective_median_limit_percent") != effective_limit
    ):
        raise ControlError("reviewed calibration does not apply to this run")
    return calibration, float(effective_limit), calibration_sha256


def review_calibration_source(
    source_path: Path, *, reviewed_by: str, reviewed_utc: str
) -> dict[str, Any]:
    source_resolved, source_report, source_sha256 = read_json_report(
        source_path, "A/A calibration candidate"
    )
    scenario_suites, raw_pairs = validate_control_raw_evidence(source_report, "aa")
    comparisons = summarize(scenario_suites, raw_pairs, True, 10.0)
    effective_limit = calibrated_limit(comparisons)
    expected_policy = threshold_policy(
        comparisons, effective_limit, None, None, reviewed=False
    )
    if (
        source_report.get("status") != CALIBRATION_REQUIRED
        or source_report.get("comparisons") != comparisons
        or source_report.get("threshold_policy") != expected_policy
    ):
        raise ControlError("A/A calibration candidate derivation is inconsistent")
    if not reviewed_by.strip() or not reviewed_utc.endswith("Z"):
        raise ControlError("calibration review identity or UTC timestamp is invalid")
    return {
        "schema": CALIBRATION_SCHEMA,
        "review_status": "APPROVED",
        "reviewed_by": reviewed_by,
        "reviewed_utc": reviewed_utc,
        "source_report": source_resolved.name,
        "source_report_sha256": source_sha256,
        "runner_sha256": source_report["parent_runner_sha256"],
        "runner_arguments": source_report["runner_arguments"],
        "scenario_suites": source_report["scenario_suites"],
        "execution_policy": source_report["execution_policy"],
        "effective_median_limit_percent": effective_limit,
    }
