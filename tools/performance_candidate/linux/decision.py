"""linux decision owner."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from decimal import Decimal

from tools.performance_candidate.identity import COMMIT_SHA
from tools.performance_candidate.json_contract import CandidateControlError, _policy_percent
from tools.performance_candidate.linux.catalog import SUMMARY_SCHEMA_VERSION, WARNING_POLICY
from tools.performance_candidate.linux.policy import UNCALIBRATED_POLICY, _scenario_policy_is_applicable, load_decision_policy
from tools.performance_candidate.linux.scale import SCALE_SCENARIO, load_scale_safety_policy
from tools.performance_candidate.linux.scale_decision import _summarize_scale_evidence
from tools.performance_candidate.linux.scale_lineage import validate_scale_lineage_repository
from tools.performance_candidate.linux.trial import _read_trial, _validate_trial
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.pairing import _display_decimal, _improvement, _median, _observed_direction, _stability_warnings
from tools.performance_candidate.status import CALIBRATION_REQUIRED, CANDIDATE_WIN, INCONCLUSIVE, INVALID, REGRESSION, WITHIN_CALIBRATED_BAND, qualification_exit_code

def _scenario_threshold_decision(
    *,
    plan: dict[str, object],
    scenario_plan: dict[str, object],
    wins: int,
    losses: int,
    median_improvement: Decimal,
    observed_environment: dict[str, object],
) -> dict[str, object]:
    entry = plan["decision_policy"]["scenarios"][scenario_plan["scenario"]]
    common = {
        "noise_band_percent": entry["noise_band_percent"],
        "regression_threshold_percent": entry["regression_threshold_percent"],
        "adoption_threshold_percent": entry["adoption_threshold_percent"],
        "minimum_pairs": entry["minimum_pairs"],
        "minimum_wins": entry["minimum_wins"],
        "minimum_losses": entry["minimum_losses"],
        "threshold_source": entry["calibration_source"],
        "calibration_environment": entry["calibration_environment"],
    }
    if plan["mode"] == "diagnostic":
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "diagnostic mode reports measurements only",
            "threshold_decision": "DIAGNOSTIC_ONLY",
            "guard_passed": None,
            "status": INCONCLUSIVE,
        }
    if entry["calibration_environment"] is None:
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "no calibrated threshold for this scenario",
            "threshold_decision": "NO_CALIBRATION",
            "guard_passed": None,
            "status": CALIBRATION_REQUIRED,
        }
    if not _scenario_policy_is_applicable(
        entry=entry,
        scenario_plan=scenario_plan,
        warmup_seconds=plan["warmup_seconds"],
        active_seconds=plan["active_seconds"],
        pairs=plan["pairs"],
        observed_environment=observed_environment,
    ):
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "calibration recipe or minimum pair count does not match",
            "threshold_decision": "CALIBRATION_NOT_APPLICABLE",
            "guard_passed": None,
            "status": CALIBRATION_REQUIRED,
        }
    noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
    regression = _policy_percent(
        entry["regression_threshold_percent"], "regression_threshold_percent"
    )
    adoption = _policy_percent(
        entry["adoption_threshold_percent"], "adoption_threshold_percent"
    )
    if median_improvement <= regression:
        if losses >= entry["minimum_losses"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "median and loss count confirm calibrated regression",
                "threshold_decision": "CONFIRMED_REGRESSION",
                "guard_passed": False,
                "status": REGRESSION,
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "regression threshold crossed without enough confirming losses",
            "threshold_decision": "INSUFFICIENT_LOSSES",
            "guard_passed": False,
            "status": INCONCLUSIVE,
        }
    if scenario_plan["role"] == "guard":
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "guard remains above its calibrated regression threshold",
            "threshold_decision": "GUARD_CLEAR",
            "guard_passed": True,
            "status": WITHIN_CALIBRATED_BAND,
        }
    if median_improvement >= adoption:
        if wins >= entry["minimum_wins"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "adoption threshold and minimum wins are satisfied",
                "threshold_decision": "CANDIDATE_IMPROVEMENT",
                "guard_passed": None,
                "status": CANDIDATE_WIN,
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "adoption threshold crossed without enough wins",
            "threshold_decision": "INSUFFICIENT_WINS",
            "guard_passed": None,
            "status": INCONCLUSIVE,
        }
    if -noise <= median_improvement <= noise:
        reason = "median remains inside the calibrated noise band"
        threshold_decision = "WITHIN_NOISE"
    else:
        reason = "median does not cross a calibrated decision threshold"
        threshold_decision = "BETWEEN_THRESHOLDS"
    return {
        **common,
        "decision_enabled": True,
        "decision_reason": reason,
        "threshold_decision": threshold_decision,
        "guard_passed": None,
        "status": WITHIN_CALIBRATED_BAND,
    }


def summarize_evidence(
    *,
    plan: dict[str, object],
    parent_root: pathlib.Path,
    candidate_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
    repository: pathlib.Path | None = None,
) -> dict[str, object]:
    """Validate paired raw evidence and calculate per-pair directional deltas."""

    if (
        COMMIT_SHA.fullmatch(parent_sha) is None
        or COMMIT_SHA.fullmatch(candidate_sha) is None
    ):
        raise CandidateControlError("summary identities must be full commit SHAs")
    parent_sha = parent_sha.lower()
    candidate_sha = candidate_sha.lower()
    if parent_sha == candidate_sha:
        raise CandidateControlError("summary parent and candidate must be different")
    is_scale = plan["selection"] == SCALE_SCENARIO
    if is_scale:
        lineage = plan["scale_lineage"]
        if (
            lineage["parent_sha"] != parent_sha
            or lineage["candidate_sha"] != candidate_sha
        ):
            raise CandidateControlError("scale summary commits do not match the bound lineage")
        if repository is None:
            raise CandidateControlError("scale summary requires repository lineage verification")
        validate_scale_lineage_repository(repository, lineage)
    planned = {entry["scenario"]: entry for entry in plan["scenarios"]}
    rows: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, str]] = []
    identity_fields = (
        "sha",
        "tree",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
    )
    member_identity: dict[str, tuple[object, ...]] = {}
    environment_identity: tuple[object, ...] | None = None
    for member, root in (("parent", parent_root), ("candidate", candidate_root)):
        if not root.is_dir():
            raise CandidateControlError(
                f"{member} evidence directory is missing",
                missing_scenarios=list(planned),
            )
        files = sorted(root.glob("*.jsonl"))
        if not files:
            raise CandidateControlError(
                f"{member} evidence directory has no JSONL files",
                missing_scenarios=list(planned),
            )
        for path in files:
            row = _read_trial(path)
            scenario, pair, row_member = _validate_trial(
                row,
                source_member=member,
                plan=plan,
                planned=planned,
                parent_sha=parent_sha,
                candidate_sha=candidate_sha,
            )
            key = (scenario, pair, row_member)
            if key in rows:
                raise CandidateControlError(
                    f"duplicate evidence row for scenario={scenario}, pair={pair}, member={row_member}"
                )
            rows[key] = row
            if is_scale:
                lineage = plan["scale_lineage"]
                expected_identity = {
                    "sha": lineage[f"{member}_sha"],
                    "tree": lineage[f"{member}_tree"],
                    "runner_sha256": lineage["runner_sha256"],
                    "client_sha256": lineage[f"{member}_client_sha256"],
                    "server_sha256": lineage[f"{member}_server_sha256"],
                }
                for field, expected_value in expected_identity.items():
                    if row[field] != expected_value:
                        raise CandidateControlError(
                            f"scale {member} {field} does not match lineage"
                        )
            identity = tuple(row[field] for field in identity_fields)
            if member in member_identity and member_identity[member] != identity:
                raise CandidateControlError(
                    f"{member} build identity changed between trials"
                )
            member_identity[member] = identity
            environment = tuple(
                row[field]
                for field in (
                    "rustc",
                    "kernel",
                    "cpu_model",
                    "cpu_count",
                    "memory_kib",
                    "build_profile",
                )
            )
            if environment_identity is not None and environment_identity != environment:
                raise CandidateControlError("runner environment changed between trials")
            environment_identity = environment
            evidence_files.append(
                {
                    "member": member,
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    expected = {
        (scenario, pair, member)
        for scenario in planned
        for pair in range(1, plan["pairs"] + 1)
        for member in ("parent", "candidate")
    }
    if set(rows) != expected:
        missing = sorted(expected - set(rows))
        unexpected = sorted(set(rows) - expected)
        raise CandidateControlError(
            f"evidence set is incomplete: missing={missing}, unexpected={unexpected}",
            missing_scenarios=sorted({key[0] for key in missing}),
        )

    if is_scale:
        return _summarize_scale_evidence(
            plan=plan,
            rows=rows,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
            member_identity=member_identity,
            identity_fields=identity_fields,
            evidence_files=evidence_files,
        )

    scenario_summaries = []
    observed_environment = next(iter(rows.values()))["environment_identity"]
    for scenario, scenario_plan in planned.items():
        direction = scenario_plan["direction"]
        pair_summaries = []
        improvements = []
        for pair in range(1, plan["pairs"] + 1):
            parent = rows[(scenario, pair, "parent")]
            candidate = rows[(scenario, pair, "candidate")]
            if {parent["order"], candidate["order"]} != {1, 2}:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} must contain orders 1 and 2"
                )
            expected_parent_order = 1 if pair % 2 else 2
            if parent["order"] != expected_parent_order:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} does not alternate execution order"
                )
            parent_value = parent["value"]
            candidate_value = candidate["value"]
            improvement = _improvement(parent_value, candidate_value, direction)
            improvements.append(improvement)
            pair_summaries.append(
                {
                    "pair": pair,
                    "parent_order": parent["order"],
                    "candidate_order": candidate["order"],
                    "parent_value": parent_value,
                    "candidate_value": candidate_value,
                    "improvement_percent": _display_decimal(improvement),
                }
            )
        wins = sum(value > 0 for value in improvements)
        losses = sum(value < 0 for value in improvements)
        ties = len(improvements) - wins - losses
        median_improvement = _median(improvements)
        policy_entry = plan["decision_policy"]["scenarios"][scenario]
        spread, warnings = _stability_warnings(
            improvements,
            noise_band=policy_entry["noise_band_percent"],
        )
        threshold_decision = _scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=wins,
            losses=losses,
            median_improvement=median_improvement,
            observed_environment=observed_environment,
        )
        scenario_summaries.append(
            {
                "scenario": scenario,
                "role": scenario_plan["role"],
                "mandatory": scenario_plan["mandatory"],
                "metric": scenario_plan["metric"],
                "unit": scenario_plan["evidence_contract"]["unit"],
                "direction": direction,
                "topology": scenario_plan["topology"],
                "application_payload_bytes": scenario_plan[
                    "application_payload_bytes"
                ],
                "socks_datagram_bytes": scenario_plan["socks_datagram_bytes"],
                "upstream_wire_bytes": scenario_plan["upstream_wire_bytes"],
                "evidence_contract": copy.deepcopy(scenario_plan["evidence_contract"]),
                "pairs": pair_summaries,
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "median_improvement_percent": _display_decimal(median_improvement),
                "minimum_improvement_percent": _display_decimal(min(improvements)),
                "maximum_improvement_percent": _display_decimal(max(improvements)),
                "spread_percent": _display_decimal(spread),
                "observed_direction": _observed_direction(wins=wins, losses=losses),
                "outlier_warning": any(
                    warning.startswith("EXTREME_") for warning in warnings
                ),
                "warnings": warnings,
                **threshold_decision,
            }
        )
    enabled_count = sum(result["decision_enabled"] for result in scenario_summaries)
    if enabled_count == 0:
        threshold_availability = "none"
    elif enabled_count == len(scenario_summaries):
        threshold_availability = "complete"
    else:
        threshold_availability = "partial"
    if plan["mode"] == "diagnostic":
        status = INCONCLUSIVE
        decision_reason = "diagnostic mode reports measurements only"
    elif any(result["status"] == REGRESSION for result in scenario_summaries):
        status = REGRESSION
        decision_reason = "at least one calibrated mandatory scenario regressed"
    elif any(
        result["status"] == CALIBRATION_REQUIRED for result in scenario_summaries
    ):
        status = CALIBRATION_REQUIRED
        decision_reason = "applicable reviewed calibration is required"
    elif any(result["status"] == INCONCLUSIVE for result in scenario_summaries):
        status = INCONCLUSIVE
        decision_reason = "a calibrated threshold crossing lacks confirming pairs"
    else:
        primary_summaries = [
            result for result in scenario_summaries if result["role"] == "primary"
        ]
        guard_summaries = [
            result for result in scenario_summaries if result["role"] == "guard"
        ]
        if (
            threshold_availability == "complete"
            and all(result["status"] == CANDIDATE_WIN for result in primary_summaries)
            and all(result["guard_passed"] is True for result in guard_summaries)
        ):
            status = CANDIDATE_WIN
            decision_reason = (
                "all calibrated primaries and guards satisfy the adoption policy"
            )
        else:
            status = WITHIN_CALIBRATED_BAND
            decision_reason = (
                "all mandatory scenarios remain within their calibrated acceptance band"
            )
    primary_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "primary"
    ]
    guard_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "guard"
    ]
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    environment_fields = (
        "runner_image",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "build_profile",
    )
    first_row = next(iter(rows.values()))
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selection": plan["selection"],
        "selected_scenario": plan["selected_scenario"],
        "scenario_group": plan["scenario_group"],
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": build_identities,
        "environment_identity": {
            field: first_row["environment_identity"][field]
            for field in environment_fields
        },
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "scale_safety_policy": None,
        "scale_lineage": None,
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": enabled_count > 0,
        "candidate_win_enabled": threshold_availability == "complete",
        "decision_reason": decision_reason,
        "threshold_availability": threshold_availability,
        "adoption_claim": status == CANDIDATE_WIN,
        "status": status,
        "workflow_failure_reason": (
            decision_reason if status not in {CANDIDATE_WIN, WITHIN_CALIBRATED_BAND} else None
        ),
        "mandatory_scenarios": list(planned),
        "missing_scenarios": [],
        "primary_results": primary_results,
        "guard_results": guard_results,
        "scenarios": scenario_summaries,
        "scale_safety": None,
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }


def invalid_summary(
    *,
    parent_sha: str,
    candidate_sha: str,
    error: CandidateControlError,
    plan: dict[str, object] | None = None,
    decision_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    mandatory = (
        [entry["scenario"] for entry in plan["scenarios"]] if plan is not None else []
    )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"] if plan is not None else None,
        "selection": plan["selection"] if plan is not None else None,
        "selected_scenario": plan["selected_scenario"] if plan is not None else None,
        "scenario_group": plan["scenario_group"] if plan is not None else None,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": {},
        "environment_identity": {},
        "decision_policy": copy.deepcopy(
            plan["decision_policy"]
            if plan is not None
            else (UNCALIBRATED_POLICY if decision_policy is None else decision_policy)
        ),
        "scale_safety_policy": copy.deepcopy(
            plan.get("scale_safety_policy") if plan is not None else None
        ),
        "scale_lineage": copy.deepcopy(
            plan.get("scale_lineage") if plan is not None else None
        ),
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": False,
        "candidate_win_enabled": False,
        "decision_reason": "invalid evidence",
        "threshold_availability": "none",
        "adoption_claim": False,
        "status": INVALID,
        "workflow_failure_reason": str(error),
        "mandatory_scenarios": mandatory,
        "missing_scenarios": error.missing_scenarios,
        "primary_results": [],
        "guard_results": [],
        "error": str(error),
        "scenarios": [],
        "scale_safety": None,
        "evidence_files": [],
    }


def summary_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Performance candidate result",
        "",
        f"- Status: **{summary['status']}**",
        f"- Parent: `{summary['parent_sha']}`",
        f"- Candidate: `{summary['candidate_sha']}`",
        f"- Adoption claim: **{str(summary['adoption_claim']).lower()}**",
        "",
    ]
    if summary["status"] == INVALID:
        lines.extend(
            [
                f"- Mode: `{summary['mode']}`",
                f"- Scenario group: `{summary['scenario_group']}`",
                f"- Mandatory scenarios: `{', '.join(summary['mandatory_scenarios']) or '-'}`",
                f"- Missing scenarios: `{', '.join(summary['missing_scenarios']) or '-'}`",
                "",
                f"Evidence error: `{summary['error']}`",
                "",
            ]
        )
        return "\n".join(lines)
    if summary["selection"] == SCALE_SCENARIO:
        scale = summary["scale_safety"]
        lineage = summary["scale_lineage"]
        lines.extend(
            [
                f"- Mode: `{summary['mode']}`",
                f"- Scale safety: **{scale['status']}**",
                f"- Dedicated policy: `{summary['scale_safety_policy']['policy_id']}` "
                f"(`{summary['scale_safety_policy']['policy_sha256']}`)",
                f"- Decision: {summary['decision_reason']}",
                f"- Failures: `{', '.join(scale['failures']) or '-'}`",
                "- This qualification is a safety result, not an adoption claim.",
                "",
                "| Lineage member | Commit | Tree |",
                "|---|---|---|",
                f"| H / final tree | `{lineage['head_sha']}` | `{lineage['head_tree']}` |",
                f"| P16 / parent | `{lineage['parent_sha']}` | `{lineage['parent_tree']}` |",
                f"| C32 / candidate | `{lineage['candidate_sha']}` | `{lineage['candidate_tree']}` |",
                "",
                f"- Counterfactual patch SHA-256: `{lineage['counterfactual_patch_sha256']}`",
                f"- Candidate-built runner SHA-256: `{lineage['runner_sha256']}`",
                "",
                "| Pair | Parent/Candidate throughput B/s | Improvement % | Jain delta | p01/median delta | Client/Server/Combined page-touch GoG B/conn |",
                "|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for pair in scale["pairs"]:
            improvement = pair["throughput_improvement_percent"]
            lines.append(
                f"| {pair['pair']} | {pair['parent_throughput_bytes_per_second']} / "
                f"{pair['candidate_throughput_bytes_per_second']} | "
                f"{improvement if improvement is not None else '-'} | "
                f"{pair['jain_delta']} | {pair['p01_median_ratio_delta']} | "
                f"{pair['client_page_touch_growth_of_growth_bytes_per_connection']} / "
                f"{pair['server_page_touch_growth_of_growth_bytes_per_connection']} / "
                f"{pair['combined_page_touch_growth_of_growth_bytes_per_connection']} |"
            )
        lines.append("")
        return "\n".join(lines)
    lines.extend(
        [
            f"- Mode: `{summary['mode']}`",
            f"- Scenario group: `{summary['scenario_group']}`",
            f"- Policy: `{summary['decision_policy']['policy_id']}` "
            f"(`{summary['decision_policy']['policy_sha256'] or 'in-memory'}`)",
            f"- Threshold availability: `{summary['threshold_availability']}`",
            f"- Decision: {summary['decision_reason']}",
            "- Warnings are descriptive only and never change status or exit code.",
            "",
        ]
    )
    scenario_names = {scenario["scenario"] for scenario in summary["scenarios"]}
    if "udp-max-wire-65507" in scenario_names:
        lines.extend(
            [
                "- UDP bound: a 65,507-byte application payload is not representable "
                "through SOCKS/IPv4. The Shadowsocks maximum scenario carries 65,449 "
                "application bytes and fills the AES-2022 response wire to 65,507 bytes.",
                "",
            ]
        )
    if "udp-direct-max-65497" in scenario_names:
        lines.extend(
            [
                "- Direct UDP bound: 65,497 application bytes plus the 10-byte "
                "SOCKS/IPv4 header fill the 65,507-byte SOCKS datagram.",
                "",
            ]
        )
    lines.extend(
        [
            "| Member | Commit | Tree | Runner SHA-256 | Client SHA-256 | Server SHA-256 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for member in ("parent", "candidate"):
        identity = summary["build_identities"][member]
        lines.append(
            f"| {member} | `{identity['sha']}` | `{identity['tree']}` | "
            f"`{identity['runner_sha256']}` | `{identity['client_sha256']}` | "
            f"`{identity['server_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "| Scenario | Role | Topology | Application payload B | SOCKS datagram B | Upstream wire B | Metric | Direction | Observed | Wins | Losses | Ties | Median % | Min % | Max % | Spread % | Warnings | Threshold decision | Status |",
            "|---|---|---|---:|---:|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|",
        ]
    )
    for scenario in summary["scenarios"]:
        lines.append(
            f"| {scenario['scenario']} | {scenario['role']} | {scenario['topology']} | "
            f"{scenario['application_payload_bytes']} | "
            f"{scenario['socks_datagram_bytes'] if scenario['socks_datagram_bytes'] is not None else '-'} | "
            f"{scenario['upstream_wire_bytes'] if scenario['upstream_wire_bytes'] is not None else '-'} | "
            f"{scenario['metric']} | "
            f"{scenario['direction']} | {scenario['observed_direction']} | "
            f"{scenario['wins']} | {scenario['losses']} | "
            f"{scenario['ties']} | {scenario['median_improvement_percent']:.6f} | "
            f"{scenario['minimum_improvement_percent']:.6f} | "
            f"{scenario['maximum_improvement_percent']:.6f} | "
            f"{scenario['spread_percent']:.6f} | "
            f"{', '.join(scenario['warnings']) or '-'} | "
            f"{scenario['threshold_decision']} | {scenario['status']} |"
        )
    lines.extend(
        [
            "",
            "| Scenario | Pair | Parent order/value | Candidate order/value | Improvement % |",
            "|---|---:|---|---|---:|",
        ]
    )
    for scenario in summary["scenarios"]:
        for pair in scenario["pairs"]:
            lines.append(
                f"| {scenario['scenario']} | {pair['pair']} | "
                f"{pair['parent_order']} / {pair['parent_value']} | "
                f"{pair['candidate_order']} / {pair['candidate_value']} | "
                f"{pair['improvement_percent']:.6f} |"
            )
    lines.append("")
    return "\n".join(lines)


def write_summary_outputs(
    summary: dict[str, object], *, output: pathlib.Path, markdown: pathlib.Path
) -> None:
    _atomic_text(
        output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(markdown, summary_markdown(summary))


def run_summary_command(parsed: argparse.Namespace) -> int:
    from tools.performance_candidate.linux.plan import load_plan

    plan = None
    decision_policy = None
    try:
        decision_policy = load_decision_policy(parsed.policy)
        scale_policy_path = getattr(parsed, "scale_policy", None)
        scale_policy = (
            None
            if scale_policy_path is None
            else load_scale_safety_policy(scale_policy_path)
        )
        plan = load_plan(
            parsed.plan,
            decision_policy=decision_policy,
            scale_safety_policy=scale_policy,
        )
        summary = summarize_evidence(
            plan=plan,
            parent_root=parsed.parent_root,
            candidate_root=parsed.candidate_root,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            repository=getattr(parsed, "repository", None),
        )
    except CandidateControlError as error:
        summary = invalid_summary(
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            error=error,
            plan=plan,
            decision_policy=decision_policy,
        )
        write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
    write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
    exit_code = qualification_exit_code(summary["status"])
    if exit_code:
        print(
            f"performance-candidate: qualification status={summary['status']}",
            file=sys.stderr,
        )
    return exit_code
