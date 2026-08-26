"""windows tun summary owner."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from collections.abc import Sequence
from decimal import Decimal

from tools.performance_candidate.windows_tun import network_model_identity
from tools.performance_candidate.windows_tun.recipe import network_model_plan_sha256, recipe_sha256, scenario_catalog, scenario_contracts, source_identities
from tools.performance_candidate.json_contract import CandidateControlError, _canonical_json_bytes, _policy_percent
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.pairing import _display_decimal, _improvement, _median, _stability_warnings
from tools.performance_candidate.windows_tun.plan import load_windows_tun_plan
from tools.performance_candidate.windows_tun.policy import load_windows_tun_policy
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_PAIR_COUNT, WINDOWS_TUN_PAIR_SCHEDULE, WINDOWS_TUN_SELECTION
from tools.performance_candidate.windows_tun.trial import _read_windows_tun_rows
from tools.performance_candidate.windows_tun.udp_values import _windows_tun_required_digest
from tools.performance_candidate.status import CALIBRATION_REQUIRED, CANDIDATE_WIN, INCONCLUSIVE, INVALID, REGRESSION, WITHIN_CALIBRATED_BAND, qualification_exit_code

WINDOWS_TUN_SUMMARY_SCHEMA_VERSION = 4


WINDOWS_TUN_CALIBRATION_SCHEMA_VERSION = 4


def _windows_tun_policy_environment(
    environment: dict[str, object], *, recipe_sha256: str, controller_bundle_sha256: str
) -> dict[str, object]:
    return {
        **environment,
        "recipe_sha256": recipe_sha256,
        "controller_bundle_sha256": controller_bundle_sha256,
    }


def _windows_tun_metric_decision(
    *,
    entry: dict[str, object],
    observed_environment: dict[str, object],
    improvements: Sequence[Decimal],
) -> dict[str, object]:
    median = _median(improvements)
    wins = sum(value > 0 for value in improvements)
    losses = sum(value < 0 for value in improvements)
    common = {
        "noise_band_percent": entry["noise_band_percent"],
        "regression_threshold_percent": entry["regression_threshold_percent"],
        "adoption_threshold_percent": entry["adoption_threshold_percent"],
        "minimum_pairs": entry["minimum_pairs"],
        "minimum_wins": entry["minimum_wins"],
        "minimum_losses": entry["minimum_losses"],
        "calibration_source": entry["calibration_source"],
        "calibration_artifact_sha256": entry["calibration_artifact_sha256"],
    }
    if entry["calibration_environment"] is None:
        return {
            **common,
            "decision_enabled": False,
            "threshold_decision": "NO_CALIBRATION",
            "status": CALIBRATION_REQUIRED,
        }
    if entry["calibration_environment"] != observed_environment:
        return {
            **common,
            "decision_enabled": False,
            "threshold_decision": "CALIBRATION_ENVIRONMENT_MISMATCH",
            "status": CALIBRATION_REQUIRED,
        }
    regression = _policy_percent(
        entry["regression_threshold_percent"], "regression_threshold_percent"
    )
    adoption = _policy_percent(
        entry["adoption_threshold_percent"], "adoption_threshold_percent"
    )
    if median <= regression:
        if losses >= entry["minimum_losses"]:
            return {
                **common,
                "decision_enabled": True,
                "threshold_decision": "CONFIRMED_REGRESSION",
                "status": REGRESSION,
            }
        return {
            **common,
            "decision_enabled": True,
            "threshold_decision": "REGRESSION_WITHOUT_CONFIRMING_LOSSES",
            "status": INCONCLUSIVE,
        }
    if median >= adoption and wins >= entry["minimum_wins"]:
        return {
            **common,
            "decision_enabled": True,
            "threshold_decision": "CONFIRMED_IMPROVEMENT",
            "status": CANDIDATE_WIN,
        }
    return {
        **common,
        "decision_enabled": True,
        "threshold_decision": "WITHIN_CALIBRATED_BAND",
        "status": WITHIN_CALIBRATED_BAND,
    }


def summarize_windows_tun_evidence(
    *,
    plan: dict[str, object],
    evidence_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    _windows_tun_required_digest({"sha": parent_sha}, "sha", length=40)
    _windows_tun_required_digest({"sha": candidate_sha}, "sha", length=40)
    rows, evidence_files, member_identity, environment = _read_windows_tun_rows(
        evidence_root=evidence_root,
        plan=plan,
        parent_sha=parent_sha,
        candidate_sha=candidate_sha,
    )
    policy_environment = _windows_tun_policy_environment(
        environment,
        recipe_sha256=plan["recipe_sha256"],
        controller_bundle_sha256=plan["controller_bundle_sha256"],
    )
    scenario_summaries: list[dict[str, object]] = []
    flat_metric_summaries: list[dict[str, object]] = []
    for scenario, contract in scenario_catalog().items():
        metric_summaries: list[dict[str, object]] = []
        for metric, metric_contract in contract["metrics"].items():
            pair_summaries: list[dict[str, object]] = []
            improvements: list[Decimal] = []
            for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
                parent = rows[(scenario, pair, "parent")]
                candidate = rows[(scenario, pair, "candidate")]
                parent_value = parent["measurements"][metric]["value"]
                candidate_value = candidate["measurements"][metric]["value"]
                improvement = _improvement(
                    parent_value,
                    candidate_value,
                    metric_contract["direction"],
                    allow_zero=metric_contract.get("allow_zero", False),
                )
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
            policy_entry = plan["decision_policy"]["scenarios"][scenario][
                "metrics"
            ][metric]
            spread, warnings = _stability_warnings(
                improvements, noise_band=policy_entry["noise_band_percent"]
            )
            if plan["run_kind"] == "calibration-aa":
                decision = {
                    "noise_band_percent": None,
                    "regression_threshold_percent": None,
                    "adoption_threshold_percent": None,
                    "minimum_pairs": None,
                    "minimum_wins": None,
                    "minimum_losses": None,
                    "calibration_source": None,
                    "calibration_artifact_sha256": None,
                    "decision_enabled": False,
                    "threshold_decision": "A_A_OBSERVATION_ONLY",
                    "status": CALIBRATION_REQUIRED,
                }
            else:
                decision = _windows_tun_metric_decision(
                    entry=policy_entry,
                    observed_environment=policy_environment,
                    improvements=improvements,
                )
            metric_summary = {
                "scenario": scenario,
                "metric": metric,
                "unit": metric_contract["unit"],
                "direction": metric_contract["direction"],
                "pairs": pair_summaries,
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "median_improvement_percent": _display_decimal(
                    _median(improvements)
                ),
                "minimum_improvement_percent": _display_decimal(min(improvements)),
                "maximum_improvement_percent": _display_decimal(max(improvements)),
                "spread_percent": _display_decimal(spread),
                "warnings": warnings,
                **decision,
            }
            metric_summaries.append(metric_summary)
            flat_metric_summaries.append(metric_summary)
        scenario_statuses = {metric["status"] for metric in metric_summaries}
        if REGRESSION in scenario_statuses:
            scenario_status = REGRESSION
        elif CALIBRATION_REQUIRED in scenario_statuses:
            scenario_status = CALIBRATION_REQUIRED
        elif INCONCLUSIVE in scenario_statuses:
            scenario_status = INCONCLUSIVE
        elif plan["run_kind"] == "calibration-aa":
            scenario_status = CALIBRATION_REQUIRED
        else:
            scenario_status = WITHIN_CALIBRATED_BAND
        scenario_summaries.append(
            {
                "scenario": scenario,
                "recipe": scenario_contracts()[scenario]["recipe"],
                "checked_unit": contract["checked_unit"],
                "minimum_checked_units": contract["minimum_checked_units"],
                "status": scenario_status,
                "metrics": metric_summaries,
            }
        )
    if plan["run_kind"] == "calibration-aa":
        status = CALIBRATION_REQUIRED
        decision_reason = (
            "A/A evidence is measurement-only and must be reviewed into a separate policy"
        )
        adoption_eligible = False
    elif any(metric["status"] == REGRESSION for metric in flat_metric_summaries):
        status = REGRESSION
        decision_reason = "at least one calibrated Windows TUN metric regressed"
        adoption_eligible = False
    elif any(
        metric["status"] == CALIBRATION_REQUIRED
        for metric in flat_metric_summaries
    ):
        status = CALIBRATION_REQUIRED
        decision_reason = (
            "reviewed thresholds, artifact identity, or exact guest calibration are unavailable"
        )
        adoption_eligible = False
    elif any(metric["status"] == INCONCLUSIVE for metric in flat_metric_summaries):
        status = INCONCLUSIVE
        decision_reason = "a threshold crossing lacks the required confirming pair count"
        adoption_eligible = False
    else:
        if all(metric["status"] == CANDIDATE_WIN for metric in flat_metric_summaries):
            status = CANDIDATE_WIN
            decision_reason = "all calibrated Windows TUN metrics confirm candidate improvement"
        else:
            status = WITHIN_CALIBRATED_BAND
            decision_reason = "all Windows TUN metrics remain within calibrated acceptance bands"
        adoption_eligible = True
    identity_fields = ("sha", "tree", "client_sha256", "server_sha256")
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    return {
        "schema_version": WINDOWS_TUN_SUMMARY_SCHEMA_VERSION,
        "kind": "windows_tun_performance_summary",
        "selection": WINDOWS_TUN_SELECTION,
        "run_kind": plan["run_kind"],
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "pairs": WINDOWS_TUN_PAIR_COUNT,
        "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
        "recipe_sha256": plan["recipe_sha256"],
        "controller_bundle_sha256": plan["controller_bundle_sha256"],
        "network_model": {
            "schema_version": network_model_identity.SCHEMA_VERSION,
            "controller_sha256": source_identities()["network_model_controller_sha256"],
            "plan_sha256": network_model_plan_sha256(),
            "raw_observations": WINDOWS_TUN_PAIR_COUNT * 2 * 2,
        },
        "decision_policy": plan["decision_policy"],
        "calibration_complete": plan["calibration_complete"],
        "environment": environment,
        "build_identities": build_identities,
        "correctness_complete": True,
        "adoption_eligible": adoption_eligible,
        "performance_improvement_claim": adoption_eligible
        and all(metric["status"] == CANDIDATE_WIN for metric in flat_metric_summaries),
        "status": status,
        "decision_reason": decision_reason,
        "mandatory_scenarios": list(scenario_catalog()),
        "scenarios": scenario_summaries,
        "evidence_files": evidence_files,
    }


def windows_tun_calibration_artifact(
    summary: dict[str, object],
) -> dict[str, object]:
    if (
        summary.get("kind") != "windows_tun_performance_summary"
        or summary.get("run_kind") != "calibration-aa"
        or summary.get("status") != CALIBRATION_REQUIRED
        or summary.get("adoption_eligible") is not False
    ):
        raise CandidateControlError(
            "Windows TUN calibration artifact requires valid A/A evidence"
        )
    observations: dict[str, object] = {}
    for scenario in summary["scenarios"]:
        metric_observations: dict[str, object] = {}
        for metric in scenario["metrics"]:
            absolute = [
                abs(Decimal(str(pair["improvement_percent"])))
                for pair in metric["pairs"]
            ]
            metric_observations[metric["metric"]] = {
                "unit": metric["unit"],
                "direction": metric["direction"],
                "paired_improvement_percent": [
                    pair["improvement_percent"] for pair in metric["pairs"]
                ],
                "median_improvement_percent": metric[
                    "median_improvement_percent"
                ],
                "median_absolute_improvement_percent": _display_decimal(
                    _median(absolute)
                ),
                "maximum_absolute_improvement_percent": _display_decimal(max(absolute)),
                "spread_percent": metric["spread_percent"],
            }
        observations[scenario["scenario"]] = {"metrics": metric_observations}
    artifact = {
        "schema_version": WINDOWS_TUN_CALIBRATION_SCHEMA_VERSION,
        "kind": "windows_tun_performance_aa_calibration",
        "selection": WINDOWS_TUN_SELECTION,
        "source_summary_schema_version": summary["schema_version"],
        "recipe_sha256": summary["recipe_sha256"],
        "controller_bundle_sha256": summary["controller_bundle_sha256"],
        "network_model": summary["network_model"],
        "pairs": summary["pairs"],
        "pair_schedule": summary["pair_schedule"],
        "aa_sha": summary["parent_sha"],
        "build_identity": summary["build_identities"]["parent"],
        "environment": _windows_tun_policy_environment(
            summary["environment"],
            recipe_sha256=summary["recipe_sha256"],
            controller_bundle_sha256=summary["controller_bundle_sha256"],
        ),
        "evidence_files": summary["evidence_files"],
        "observations": observations,
        "adoption_eligible": False,
        "thresholds_reviewed": False,
        "policy_action": (
            "review repeated A/A artifacts, choose thresholds outside measured noise, "
            "then bind the reviewed artifact SHA-256 in the policy"
        ),
    }
    return {
        **artifact,
        "content_sha256": hashlib.sha256(_canonical_json_bytes(artifact)).hexdigest(),
    }


def windows_tun_summary_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Windows TUN paired performance",
        "",
        f"- Status: **{summary['status']}**",
        f"- Run kind: `{summary['run_kind']}`",
        f"- Recipe SHA-256: `{summary['recipe_sha256']}`",
        f"- Controller bundle SHA-256: `{summary['controller_bundle_sha256']}`",
        f"- Network-model plan SHA-256: `{summary['network_model']['plan_sha256']}`",
        f"- Adoption eligible: `{str(summary['adoption_eligible']).lower()}`",
        f"- Decision: {summary['decision_reason']}",
        "- Correctness and units are mandatory for every trial; GSO is disabled by recipe.",
        "",
    ]
    if summary["status"] == INVALID:
        lines.append(f"- Error: {summary['error']}")
        lines.append("")
        return "\n".join(lines)
    lines.extend(
        [
            "| Scenario | Metric | Unit | Median % | Wins | Losses | Decision |",
            "|---|---|---|---:|---:|---:|---|",
        ]
    )
    for scenario in summary["scenarios"]:
        for metric in scenario["metrics"]:
            lines.append(
                f"| {scenario['scenario']} | {metric['metric']} | {metric['unit']} | "
                f"{metric['median_improvement_percent']:.6f} | {metric['wins']} | "
                f"{metric['losses']} | {metric['threshold_decision']} |"
            )
    lines.append("")
    return "\n".join(lines)


def _write_windows_tun_outputs(
    summary: dict[str, object], *, output: pathlib.Path, markdown: pathlib.Path
) -> None:
    _atomic_text(
        output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(markdown, windows_tun_summary_markdown(summary))


def run_windows_tun_summary_command(parsed: argparse.Namespace) -> int:
    plan: dict[str, object] | None = None
    try:
        policy = load_windows_tun_policy(
            parsed.policy,
            controller_bundle_sha256=parsed.controller_bundle_sha256,
        )
        plan = load_windows_tun_plan(
            parsed.plan,
            decision_policy=policy,
            controller_bundle_sha256=parsed.controller_bundle_sha256,
        )
        if plan["run_kind"] == "calibration-aa" and parsed.calibration_output is None:
            raise CandidateControlError(
                "Windows TUN A/A requires --calibration-output"
            )
        if plan["run_kind"] == "comparison" and parsed.calibration_output is not None:
            raise CandidateControlError(
                "Windows TUN comparison cannot write a calibration artifact"
            )
        summary = summarize_windows_tun_evidence(
            plan=plan,
            evidence_root=parsed.evidence_root,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
        )
        if parsed.calibration_output is not None:
            calibration = windows_tun_calibration_artifact(summary)
            _atomic_text(
                parsed.calibration_output,
                json.dumps(calibration, sort_keys=True, indent=2, allow_nan=False)
                + "\n",
            )
    except CandidateControlError as error:
        summary = {
            "schema_version": WINDOWS_TUN_SUMMARY_SCHEMA_VERSION,
            "kind": "windows_tun_performance_summary",
            "selection": WINDOWS_TUN_SELECTION,
            "run_kind": None if plan is None else plan["run_kind"],
            "parent_sha": parsed.parent_sha,
            "candidate_sha": parsed.candidate_sha,
            "recipe_sha256": None if plan is None else plan["recipe_sha256"],
            "controller_bundle_sha256": parsed.controller_bundle_sha256,
            "network_model": {
                "schema_version": network_model_identity.SCHEMA_VERSION,
                "controller_sha256": None,
                "plan_sha256": None,
                "raw_observations": 0,
            },
            "adoption_eligible": False,
            "correctness_complete": False,
            "status": INVALID,
            "decision_reason": "invalid or incomplete Windows TUN evidence",
            "error": str(error),
        }
        _write_windows_tun_outputs(
            summary, output=parsed.output, markdown=parsed.markdown
        )
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
    _write_windows_tun_outputs(summary, output=parsed.output, markdown=parsed.markdown)
    exit_code = qualification_exit_code(summary["status"])
    if exit_code:
        print(
            f"performance-candidate: Windows TUN qualification status={summary['status']}",
            file=sys.stderr,
        )
    return exit_code
