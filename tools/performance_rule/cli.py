"""Canonical CLI and orchestration for Rule paired qualification evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from tools.performance_rule.evidence import (
    load_calibration,
    read_json_report,
    review_calibration_source,
)
from tools.performance_rule.pairing import (
    calibrated_limits,
    calibration_ceiling_limits,
    pair_execution_order,
    summarize,
)
from tools.performance_rule.policy import calibration_required_policy, threshold_policy
from tools.performance_rule.runner_report import require_same_scenarios, run_once
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CALIBRATION_SCHEMA,
    CONTROL_SCHEMA,
    INVALID,
    CANDIDATE_WIN,
    INCONCLUSIVE,
    PAIR_COUNT,
    REGRESSION,
    RUNNER_PRIORITY_HIGH,
    RUNNER_PRIORITY_NORMAL,
    WITHIN_CALIBRATED_BAND,
    ControlError,
    runner_creation_flags,
    sha256_file,
    validate_pairs,
)


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="collect paired A/A or reviewed A/B evidence")
    run.add_argument("--parent", required=True, type=Path)
    run.add_argument("--candidate", type=Path)
    run.add_argument("--pairs", type=int, default=PAIR_COUNT)
    run.add_argument("--timeout-seconds", type=int, default=900)
    run.add_argument(
        "--runner-priority",
        choices=(RUNNER_PRIORITY_NORMAL, RUNNER_PRIORITY_HIGH),
        default=RUNNER_PRIORITY_NORMAL,
    )
    run.add_argument(
        "--calibration",
        type=Path,
        help=f"reviewed {CALIBRATION_SCHEMA} artifact required for A/B gating",
    )
    run.add_argument("--output", type=Path)
    run.add_argument("runner_arguments", nargs=argparse.REMAINDER)
    review = commands.add_parser(
        "review-calibration",
        help="review one current-schema A/A source into a separate calibration artifact",
    )
    review.add_argument("--source-report", required=True, type=Path)
    review.add_argument("--reviewed-by", required=True)
    review.add_argument("--reviewed-utc", required=True)
    review.add_argument("--output", required=True, type=Path)
    parsed = parser.parse_args(arguments)
    if parsed.command == "run" and parsed.runner_arguments[:1] == ["--"]:
        parsed.runner_arguments = parsed.runner_arguments[1:]
    return parsed


def emit_result(result: dict[str, Any], output: Path | None) -> None:
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is not None:
        if output.suffix != ".json":
            raise ControlError("--output must have a .json extension")
        output.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as temporary:
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, output)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
    sys.stdout.write(encoded)


def _calibration_required_result(
    *,
    pairs: int,
    parent_sha: str,
    candidate_sha: str,
    runner_arguments: list[str],
    runner_priority: str,
) -> dict[str, Any]:
    return {
        "schema": CONTROL_SCHEMA,
        "generated_unix_millis": time.time_ns() // 1_000_000,
        "mode": "parent_candidate",
        "status": CALIBRATION_REQUIRED,
        "pairs": pairs,
        "parent_runner_sha256": parent_sha,
        "candidate_runner_sha256": candidate_sha,
        "runner_arguments": runner_arguments,
        "scenario_ids": [],
        "scenario_suites": {},
        "execution_policy": {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": runner_priority,
        },
        "execution_trace": [],
        "comparisons": [],
        "threshold_policy": calibration_required_policy(),
        "raw_pairs": [],
        "decision_reason": "a reviewed current-schema A/A calibration is required",
    }


def control(arguments: list[str] | None = None) -> dict[str, Any]:
    args = parse_arguments(arguments)
    if args.command != "run":
        raise ControlError("control requires the run command")
    validate_pairs(args.pairs)
    if not 1 <= args.timeout_seconds <= 3_600:
        raise ControlError("--timeout-seconds must be in 1..=3600")
    parent = args.parent.resolve(strict=True)
    candidate = (args.candidate or args.parent).resolve(strict=True)
    if not parent.is_file() or not candidate.is_file():
        raise ControlError("parent and candidate runners must be files")
    parent_sha = sha256_file(parent)
    candidate_sha = sha256_file(candidate)
    same_binary = parent_sha == candidate_sha
    if not same_binary and args.calibration is None:
        result = _calibration_required_result(
            pairs=args.pairs,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
            runner_arguments=args.runner_arguments,
            runner_priority=args.runner_priority,
        )
        emit_result(result, args.output)
        return result
    if not same_binary:
        _, calibration_document, _ = read_json_report(
            args.calibration, "reviewed A/A calibration"
        )
        if calibration_document.get("schema") != CALIBRATION_SCHEMA:
            raise ControlError(
                "only the current reviewed calibration schema is accepted"
            )

    creation_flags = runner_creation_flags(args.runner_priority)
    expected_scenarios: dict[str, str] | None = None
    pairs: list[dict[str, Any]] = []
    execution_trace: list[dict[str, Any]] = []
    for pair_index in range(args.pairs):
        pair: dict[str, Any] = {}
        for order_index, (role, executable) in enumerate(
            pair_execution_order(pair_index, parent, candidate)
        ):
            expected_sha = parent_sha if role == "parent" else candidate_sha
            report, scenarios = run_once(
                role,
                executable,
                args.runner_arguments,
                args.timeout_seconds,
                expected_sha,
                creation_flags,
            )
            expected_scenarios = require_same_scenarios(expected_scenarios, scenarios)
            pair[role] = report
            execution_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index + 1,
                    "role": role,
                    "runner_sha256": expected_sha,
                }
            )
        pairs.append(pair)
    assert expected_scenarios is not None

    if same_binary:
        comparisons = summarize(
            expected_scenarios,
            pairs,
            True,
            calibration_ceiling_limits(),
        )
        effective_limits = calibrated_limits(comparisons)
        calibration_source = None
        calibration_sha256 = None
        reviewed = False
    else:
        calibration_path = args.calibration.resolve(strict=True)
        _, effective_limits, calibration_sha256 = load_calibration(
            calibration_path,
            parent_sha,
            expected_scenarios,
            args.runner_arguments,
            args.runner_priority,
        )
        comparisons = summarize(
            expected_scenarios,
            pairs,
            False,
            effective_limits,
        )
        calibration_source = str(calibration_path)
        reviewed = True
    policy = threshold_policy(
        comparisons,
        effective_limits,
        calibration_source,
        calibration_sha256,
        reviewed=reviewed,
    )
    result = {
        "schema": CONTROL_SCHEMA,
        "generated_unix_millis": time.time_ns() // 1_000_000,
        "mode": "aa" if same_binary else "parent_candidate",
        "status": policy["status"],
        "pairs": args.pairs,
        "parent_runner_sha256": parent_sha,
        "candidate_runner_sha256": candidate_sha,
        "runner_arguments": args.runner_arguments,
        "scenario_ids": sorted(expected_scenarios),
        "scenario_suites": dict(sorted(expected_scenarios.items())),
        "execution_policy": {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": args.runner_priority,
        },
        "execution_trace": execution_trace,
        "comparisons": comparisons,
        "threshold_policy": policy,
        "raw_pairs": pairs,
        "decision_reason": (
            "A/A evidence requires explicit review into a separate calibration artifact"
            if not reviewed
            else "reviewed match_set and conditional snapshot_registry median gates evaluated"
        ),
    }
    emit_result(result, args.output)
    return result


def main(arguments: list[str] | None = None) -> int:
    try:
        parsed = parse_arguments(arguments)
        if parsed.command == "review-calibration":
            reviewed = review_calibration_source(
                parsed.source_report,
                reviewed_by=parsed.reviewed_by,
                reviewed_utc=parsed.reviewed_utc,
            )
            emit_result(reviewed, parsed.output)
            return 0
        result = control(arguments if arguments is not None else sys.argv[1:])
    except (ControlError, OSError, subprocess.TimeoutExpired) as error:
        print(f"rule qualification control failed: {error}", file=sys.stderr)
        return 2
    if result["status"] in {CANDIDATE_WIN, WITHIN_CALIBRATED_BAND}:
        return 0
    if result["status"] == REGRESSION:
        return 3
    if result["status"] in {CALIBRATION_REQUIRED, INCONCLUSIVE}:
        return 4
    if result["status"] == INVALID:
        return 2
    print("rule qualification control failed: unknown status", file=sys.stderr)
    return 2
