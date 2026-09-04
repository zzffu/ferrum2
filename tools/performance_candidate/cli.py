"""cli owner."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Sequence

from tools.performance_candidate.identity import validate_git_relation
from tools.performance_candidate.json_contract import CandidateControlError, _strict_json
from tools.performance_candidate.linux.aggregate import run_aggregate_command
from tools.performance_candidate.linux.calibration import (
    derive_run_calibration,
    write_run_calibration,
)
from tools.performance_candidate.linux.decision import run_summary_command
from tools.performance_candidate.linux.policy import load_decision_policy
from tools.performance_candidate.linux.plan import create_plan, load_plan, validate_measurement_inputs, write_plan
from tools.performance_candidate.linux.schedule import scenario_schedule, schedule_tsv
from tools.performance_candidate.linux.scale import load_scale_safety_policy
from tools.performance_candidate.linux.scale_lineage import build_scale_lineage, load_scale_lineage, validate_scale_source_lineage
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.status import qualification_exit_code
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_MODES
from tools.performance_candidate.windows_tun.summary import (
    validate_windows_tun_host_evidence,
)

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-inputs", help="validate bounded workflow measurement inputs"
    )
    validate.add_argument("--warmup-seconds", required=True)
    validate.add_argument("--active-seconds", required=True)
    validate.add_argument("--pairs", required=True)
    relation = commands.add_parser(
        "validate-git", help="validate strict parent-to-candidate ancestry"
    )
    relation.add_argument("--repository", required=True, type=pathlib.Path)
    relation.add_argument("--parent-sha", required=True)
    relation.add_argument("--candidate-sha", required=True)
    plan = commands.add_parser("plan", help="write a canonical scenario plan")
    plan.add_argument("--mode", required=True)
    plan.add_argument("--selection", required=True)
    plan.add_argument("--warmup-seconds", required=True)
    plan.add_argument("--active-seconds", required=True)
    plan.add_argument("--pairs", required=True)
    plan.add_argument("--policy", required=True, type=pathlib.Path)
    plan.add_argument("--scale-policy", type=pathlib.Path)
    plan.add_argument("--scale-lineage", type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    scenarios = commands.add_parser(
        "scenarios", help="emit planned scenario names, one per line"
    )
    scenarios.add_argument("--plan", required=True, type=pathlib.Path)
    scenarios.add_argument("--policy", required=True, type=pathlib.Path)
    scenarios.add_argument("--scale-policy", type=pathlib.Path)
    schedule = commands.add_parser(
        "schedule", help="emit one deterministic scenario execution schedule"
    )
    schedule.add_argument("--plan", required=True, type=pathlib.Path)
    schedule.add_argument("--policy", required=True, type=pathlib.Path)
    schedule.add_argument("--scale-policy", type=pathlib.Path)
    schedule.add_argument("--scenario", required=True)
    schedule.add_argument("--self-calibrated", action="store_true")
    trial_contract = commands.add_parser(
        "linux-trial-contract",
        help="emit one plan-bound Linux producer/controller/recipe contract",
    )
    trial_contract.add_argument("--plan", required=True, type=pathlib.Path)
    trial_contract.add_argument("--policy", required=True, type=pathlib.Path)
    trial_contract.add_argument("--scale-policy", type=pathlib.Path)
    trial_contract.add_argument("--scenario", required=True)
    trial_contract.add_argument(
        "--output-format", choices=("json", "tsv"), default="json"
    )
    summary = commands.add_parser(
        "summarize", help="validate paired evidence and write machine/human summaries"
    )
    summary.add_argument("--plan", required=True, type=pathlib.Path)
    summary.add_argument("--parent-root", required=True, type=pathlib.Path)
    summary.add_argument("--candidate-root", required=True, type=pathlib.Path)
    summary.add_argument("--parent-sha", required=True)
    summary.add_argument("--candidate-sha", required=True)
    summary.add_argument("--policy", required=True, type=pathlib.Path)
    summary.add_argument("--scale-policy", type=pathlib.Path)
    summary.add_argument("--repository", type=pathlib.Path)
    summary.add_argument("--output", required=True, type=pathlib.Path)
    summary.add_argument("--markdown", required=True, type=pathlib.Path)
    calibration = commands.add_parser(
        "calibrate",
        help="validate same-binary evidence and write a run-scoped decision policy",
    )
    calibration.add_argument("--base-policy", required=True, type=pathlib.Path)
    calibration.add_argument("--plan", required=True, type=pathlib.Path)
    calibration.add_argument("--left-root", required=True, type=pathlib.Path)
    calibration.add_argument("--right-root", required=True, type=pathlib.Path)
    calibration.add_argument("--baseline-sha", required=True)
    calibration.add_argument("--source", required=True)
    calibration.add_argument("--policy", required=True, type=pathlib.Path)
    calibration.add_argument("--output", required=True, type=pathlib.Path)
    aggregate = commands.add_parser(
        "aggregate",
        help="validate and combine the full non-TUN qualification matrix",
    )
    aggregate.add_argument("--summary-root", required=True, type=pathlib.Path)
    aggregate.add_argument("--parent-sha", required=True)
    aggregate.add_argument("--candidate-sha", required=True)
    aggregate.add_argument("--output", required=True, type=pathlib.Path)
    aggregate.add_argument("--markdown", required=True, type=pathlib.Path)
    lineage = commands.add_parser(
        "scale-lineage", help="verify and bind H -> P16 -> C32 scale lineage"
    )
    lineage.add_argument("--repository", required=True, type=pathlib.Path)
    lineage.add_argument("--head-sha", required=True)
    lineage.add_argument("--parent-sha", required=True)
    lineage.add_argument("--candidate-sha", required=True)
    lineage.add_argument("--runner", required=True, type=pathlib.Path)
    lineage.add_argument("--parent-client", required=True, type=pathlib.Path)
    lineage.add_argument("--parent-server", required=True, type=pathlib.Path)
    lineage.add_argument("--candidate-client", required=True, type=pathlib.Path)
    lineage.add_argument("--candidate-server", required=True, type=pathlib.Path)
    lineage.add_argument("--output", required=True, type=pathlib.Path)
    source_lineage = commands.add_parser(
        "scale-source-lineage",
        help="verify exact H -> P16 -> C32 source lineage before compilation",
    )
    source_lineage.add_argument("--repository", required=True, type=pathlib.Path)
    source_lineage.add_argument("--head-sha", required=True)
    source_lineage.add_argument("--parent-sha", required=True)
    source_lineage.add_argument("--candidate-sha", required=True)
    windows_tun_validate = commands.add_parser(
        "windows-tun-validate-host-evidence",
        help="validate one cleanup-complete Windows-host TUN evidence bundle",
    )
    windows_tun_validate.add_argument(
        "--evidence-root", required=True, type=pathlib.Path
    )
    windows_tun_validate.add_argument("--baseline-sha", required=True)
    windows_tun_validate.add_argument("--candidate-sha", required=True)
    windows_tun_validate.add_argument(
        "--mode", required=True, choices=sorted(WINDOWS_TUN_MODES)
    )
    windows_tun_validate.add_argument(
        "--policy", required=True, type=pathlib.Path
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    if parsed.command == "summarize":
        return run_summary_command(parsed)
    if parsed.command == "aggregate":
        return run_aggregate_command(parsed)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        if parsed.command == "calibrate":
            decision_policy = load_decision_policy(parsed.base_policy)
            plan = load_plan(parsed.plan, decision_policy=decision_policy)
            report, policy = derive_run_calibration(
                plan=plan,
                left_root=parsed.left_root,
                right_root=parsed.right_root,
                baseline_sha=parsed.baseline_sha,
                source=parsed.source,
            )
            write_run_calibration(
                report=report,
                policy=policy,
                report_output=parsed.output,
                policy_output=parsed.policy,
            )
            return 0
        if parsed.command == "plan":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            scale_lineage = (
                None
                if parsed.scale_lineage is None
                else load_scale_lineage(parsed.scale_lineage)
            )
            plan = create_plan(
                mode=parsed.mode,
                selection=parsed.selection,
                warmup_seconds=parsed.warmup_seconds,
                active_seconds=parsed.active_seconds,
                pairs=parsed.pairs,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
                scale_lineage=scale_lineage,
            )
            write_plan(parsed.output, plan)
            return 0
        if parsed.command == "scenarios":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            plan = load_plan(
                parsed.plan,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
            )
            for scenario in plan["scenarios"]:
                print(scenario["scenario"])
            return 0
        if parsed.command == "schedule":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            plan = load_plan(
                parsed.plan,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
            )
            operations = scenario_schedule(
                plan=plan,
                scenario=parsed.scenario,
                self_calibrated=parsed.self_calibrated,
            )
            print(schedule_tsv(operations), end="")
            return 0
        if parsed.command == "linux-trial-contract":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            plan = load_plan(
                parsed.plan,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
            )
            matches = [
                entry for entry in plan["scenarios"]
                if entry["scenario"] == parsed.scenario
            ]
            if len(matches) != 1:
                raise CandidateControlError("scenario is not present exactly once in the plan")
            contract = matches[0]["evidence_contract"]
            if parsed.output_format == "json":
                print(json.dumps(contract, sort_keys=True, allow_nan=False))
            else:
                print(
                    "\t".join(
                        str(contract[field])
                        for field in (
                            "unit",
                            "runner_image",
                            "producer_source_sha256",
                            "controller_source_sha256",
                            "semantic_recipe_sha256",
                            "evidence_bundle_sha256",
                        )
                    )
                )
            return 0
        if parsed.command == "validate-git":
            validate_git_relation(
                parsed.repository, parsed.parent_sha, parsed.candidate_sha
            )
            return 0
        if parsed.command == "scale-lineage":
            lineage = build_scale_lineage(
                repository=parsed.repository,
                head_sha=parsed.head_sha,
                parent_sha=parsed.parent_sha,
                candidate_sha=parsed.candidate_sha,
                runner=parsed.runner,
                parent_client=parsed.parent_client,
                parent_server=parsed.parent_server,
                candidate_client=parsed.candidate_client,
                candidate_server=parsed.candidate_server,
            )
            _atomic_text(
                parsed.output,
                json.dumps(lineage, sort_keys=True, indent=2, allow_nan=False) + "\n",
            )
            return 0
        if parsed.command == "scale-source-lineage":
            validate_scale_source_lineage(
                parsed.repository,
                parsed.head_sha,
                parsed.parent_sha,
                parsed.candidate_sha,
            )
            return 0
        if parsed.command == "windows-tun-validate-host-evidence":
            report = validate_windows_tun_host_evidence(
                evidence_root=parsed.evidence_root,
                baseline_sha=parsed.baseline_sha,
                candidate_sha=parsed.candidate_sha,
                mode=parsed.mode,
                policy_path=parsed.policy,
            )
            print(json.dumps(report, sort_keys=True, allow_nan=False))
            return qualification_exit_code(report["status"])
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
