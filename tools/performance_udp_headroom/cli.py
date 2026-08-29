"""CLI for the independently activatable UDP owned-headroom campaign."""

from __future__ import annotations

import argparse
import json
import pathlib
from collections.abc import Sequence

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.output import _atomic_text
from tools.performance_udp_headroom.build import (
    create_plan,
    load_plan,
    materialize,
    run_build,
)
from tools.performance_udp_headroom.contract import SCENARIO_NAMES, VARIANT_NAMES
from tools.performance_udp_headroom.evidence import create_qualification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.performance_udp_headroom")
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan")
    plan.add_argument("--environment", required=True, type=pathlib.Path)
    plan.add_argument("--policy", required=True, type=pathlib.Path)
    plan.add_argument("--target-root", required=True, type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)

    items = commands.add_parser("plan-items")
    items.add_argument("--plan", required=True, type=pathlib.Path)

    build = commands.add_parser("build")
    build.add_argument("--plan", required=True, type=pathlib.Path)
    build.add_argument("--variant", required=True, choices=VARIANT_NAMES)
    build.add_argument("--log", required=True, type=pathlib.Path)
    build.add_argument("--output", required=True, type=pathlib.Path)

    stage = commands.add_parser("materialize")
    stage.add_argument("--plan", required=True, type=pathlib.Path)
    stage.add_argument("--build", required=True, type=pathlib.Path)
    stage.add_argument("--variant", required=True, choices=VARIANT_NAMES)
    stage.add_argument("--destination", required=True, type=pathlib.Path)

    contract = commands.add_parser("trial-contract")
    contract.add_argument("--plan", required=True, type=pathlib.Path)
    contract.add_argument("--scenario", required=True, choices=SCENARIO_NAMES)

    diagnostic = commands.add_parser("diagnostic-contract")
    diagnostic.add_argument("--plan", required=True, type=pathlib.Path)

    qualify = commands.add_parser("qualify")
    qualify.add_argument("--plan", required=True, type=pathlib.Path)
    qualify.add_argument("--default-build", required=True, type=pathlib.Path)
    qualify.add_argument("--candidate-build", required=True, type=pathlib.Path)
    qualify.add_argument("--diagnostic-default-build", required=True, type=pathlib.Path)
    qualify.add_argument(
        "--diagnostic-candidate-build", required=True, type=pathlib.Path
    )
    qualify.add_argument(
        "--a-a-root", action="append", required=True, type=pathlib.Path
    )
    qualify.add_argument("--comparison-root", required=True, type=pathlib.Path)
    qualify.add_argument("--diagnostic-default", required=True, type=pathlib.Path)
    qualify.add_argument("--diagnostic-candidate", required=True, type=pathlib.Path)
    qualify.add_argument("--output", required=True, type=pathlib.Path)
    return parser


def _write(path: pathlib.Path, value: object) -> None:
    _atomic_text(
        path,
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )


def _contract_line(contract: dict[str, object]) -> str:
    return "\t".join(
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


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "plan":
            row = create_plan(
                environment_path=parsed.environment,
                policy_path=parsed.policy,
                target_root=parsed.target_root,
            )
            _write(parsed.output, row)
        elif parsed.command == "plan-items":
            plan, _ = load_plan(parsed.plan)
            print("\n".join(row["name"] for row in plan["variants"]))
            return 0
        elif parsed.command == "build":
            row, returncode = run_build(
                plan_path=parsed.plan,
                variant_name=parsed.variant,
                log_path=parsed.log,
            )
            _write(parsed.output, row)
            return returncode
        elif parsed.command == "materialize":
            row = materialize(
                plan_path=parsed.plan,
                build_path=parsed.build,
                variant_name=parsed.variant,
                destination=parsed.destination,
            )
        elif parsed.command == "trial-contract":
            plan, _ = load_plan(parsed.plan)
            matches = [
                row for row in plan["scenarios"] if row["name"] == parsed.scenario
            ]
            if len(matches) != 1:
                raise CandidateControlError(
                    "UDP headroom scenario is not present exactly once"
                )
            print(_contract_line(matches[0]["evidence_contract"]))
            return 0
        elif parsed.command == "diagnostic-contract":
            plan, _ = load_plan(parsed.plan)
            contract = plan["diagnostic_contract"]
            print(
                "\t".join(
                    str(contract[field])
                    for field in (
                        "runner_image",
                        "producer_source_sha256",
                        "controller_source_sha256",
                        "semantic_recipe_sha256",
                        "evidence_bundle_sha256",
                    )
                )
            )
            return 0
        else:
            row = create_qualification(
                plan_path=parsed.plan,
                default_build_path=parsed.default_build,
                candidate_build_path=parsed.candidate_build,
                diagnostic_default_build_path=parsed.diagnostic_default_build,
                diagnostic_candidate_build_path=parsed.diagnostic_candidate_build,
                a_a_roots=parsed.a_a_root,
                comparison_root=parsed.comparison_root,
                diagnostic_default_path=parsed.diagnostic_default,
                diagnostic_candidate_path=parsed.diagnostic_candidate,
            )
            _write(parsed.output, row)
        print(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except CandidateControlError as error:
        print(json.dumps({"error": str(error), "status": "FAIL"}, sort_keys=True))
        return 2
