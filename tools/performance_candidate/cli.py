"""cli owner."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from collections.abc import Sequence

from tools.performance_candidate.identity import validate_git_relation
from tools.performance_candidate.json_contract import CandidateControlError, _strict_json
from tools.performance_candidate.linux.decision import run_summary_command
from tools.performance_candidate.linux.policy import load_decision_policy
from tools.performance_candidate.linux.plan import create_plan, load_plan, validate_measurement_inputs, write_plan
from tools.performance_candidate.linux.scale import load_scale_safety_policy
from tools.performance_candidate.linux.scale_lineage import build_scale_lineage, load_scale_lineage, validate_scale_source_lineage
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.windows_tun.plan import create_windows_tun_plan, load_windows_tun_plan
from tools.performance_candidate.windows_tun.policy import load_windows_tun_policy
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_RUN_KINDS
from tools.performance_candidate.windows_tun.summary import run_windows_tun_summary_command
from tools.performance_candidate.windows_tun.trial import WINDOWS_TUN_TRIAL_MAX_BYTES, validate_windows_tun_trial
from tools.performance_candidate.windows_tun.udp_diagnostic import validate_windows_tun_udp_diagnostic

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
    windows_tun_plan = commands.add_parser(
        "windows-tun-plan",
        help="write the fixed nine-scenario Windows TUN paired plan",
    )
    windows_tun_plan.add_argument(
        "--run-kind", required=True, choices=sorted(WINDOWS_TUN_RUN_KINDS)
    )
    windows_tun_plan.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_plan.add_argument("--output", required=True, type=pathlib.Path)
    windows_tun_trials = commands.add_parser(
        "windows-tun-trials",
        help="emit scenario/member/pair/order rows from a canonical Windows TUN plan",
    )
    windows_tun_trials.add_argument("--plan", required=True, type=pathlib.Path)
    windows_tun_trials.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_validate_trial = commands.add_parser(
        "windows-tun-validate-trial",
        help="validate one raw approved-guest Windows TUN trial",
    )
    windows_tun_validate_trial.add_argument(
        "--plan", required=True, type=pathlib.Path
    )
    windows_tun_validate_trial.add_argument(
        "--trial", required=True, type=pathlib.Path
    )
    windows_tun_validate_trial.add_argument("--parent-sha", required=True)
    windows_tun_validate_trial.add_argument("--candidate-sha", required=True)
    windows_tun_validate_trial.add_argument(
        "--policy", required=True, type=pathlib.Path
    )
    windows_tun_validate_udp_diagnostic = commands.add_parser(
        "windows-tun-validate-udp-diagnostic",
        help="validate one bounded non-qualification Windows TUN UDP diagnostic",
    )
    windows_tun_validate_udp_diagnostic.add_argument(
        "--plan", required=True, type=pathlib.Path
    )
    windows_tun_validate_udp_diagnostic.add_argument(
        "--evidence-root", required=True, type=pathlib.Path
    )
    windows_tun_validate_udp_diagnostic.add_argument("--parent-sha", required=True)
    windows_tun_validate_udp_diagnostic.add_argument("--candidate-sha", required=True)
    windows_tun_validate_udp_diagnostic.add_argument(
        "--policy", required=True, type=pathlib.Path
    )
    windows_tun_summary = commands.add_parser(
        "windows-tun-summarize",
        help="validate and summarize paired Windows TUN evidence",
    )
    windows_tun_summary.add_argument("--plan", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument(
        "--evidence-root", required=True, type=pathlib.Path
    )
    windows_tun_summary.add_argument("--parent-sha", required=True)
    windows_tun_summary.add_argument("--candidate-sha", required=True)
    windows_tun_summary.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument("--output", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument("--markdown", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument(
        "--calibration-output", type=pathlib.Path
    )
    for windows_command in (
        windows_tun_plan,
        windows_tun_trials,
        windows_tun_validate_trial,
        windows_tun_validate_udp_diagnostic,
        windows_tun_summary,
    ):
        windows_command.add_argument(
            "--controller-bundle-sha256", required=True
        )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    if parsed.command == "summarize":
        return run_summary_command(parsed)
    if parsed.command == "windows-tun-summarize":
        return run_windows_tun_summary_command(parsed)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
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
        if parsed.command == "windows-tun-plan":
            policy = load_windows_tun_policy(
                parsed.policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            plan = create_windows_tun_plan(
                run_kind=parsed.run_kind,
                decision_policy=policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            _atomic_text(
                parsed.output,
                json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
            )
            return 0
        if parsed.command == "windows-tun-trials":
            policy = load_windows_tun_policy(
                parsed.policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            plan = load_windows_tun_plan(
                parsed.plan,
                decision_policy=policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            for trial in plan["trials"]:
                print(
                    "\t".join(
                        str(trial[field])
                        for field in (
                            "sequence",
                            "scenario",
                            "member",
                            "pair",
                            "order",
                        )
                    )
                )
            return 0
        if parsed.command == "windows-tun-validate-trial":
            policy = load_windows_tun_policy(
                parsed.policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            plan = load_windows_tun_plan(
                parsed.plan,
                decision_policy=policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            try:
                raw = parsed.trial.read_bytes()
            except OSError as error:
                raise CandidateControlError(
                    "unable to read Windows TUN trial"
                ) from error
            if len(raw) > WINDOWS_TUN_TRIAL_MAX_BYTES:
                raise CandidateControlError("Windows TUN trial exceeds the size bound")
            try:
                row = _strict_json(
                    raw.decode("utf-8"), source="Windows TUN trial"
                )
            except UnicodeError as error:
                raise CandidateControlError(
                    "Windows TUN trial must be UTF-8"
                ) from error
            scenario, pair, member = validate_windows_tun_trial(
                row,
                plan=plan,
                parent_sha=parsed.parent_sha,
                candidate_sha=parsed.candidate_sha,
            )
            print(f"{scenario}\t{member}\t{pair}\t{row['order']}")
            return 0
        if parsed.command == "windows-tun-validate-udp-diagnostic":
            policy = load_windows_tun_policy(
                parsed.policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            plan = load_windows_tun_plan(
                parsed.plan,
                decision_policy=policy,
                controller_bundle_sha256=parsed.controller_bundle_sha256,
            )
            try:
                plan_sha256 = hashlib.sha256(parsed.plan.read_bytes()).hexdigest()
            except OSError as error:
                raise CandidateControlError("unable to hash Windows TUN plan") from error
            row = validate_windows_tun_udp_diagnostic(
                plan=plan,
                plan_sha256=plan_sha256,
                evidence_root=parsed.evidence_root,
                parent_sha=parsed.parent_sha,
                candidate_sha=parsed.candidate_sha,
            )
            trial = row["trial"]
            print(
                f"{trial['scenario']}\t{trial['member']}\t{trial['pair']}\t"
                f"{row['trial_status']}\t{row['evidence_status']}\tqualification=false"
            )
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
