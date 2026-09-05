"""Canonical CLI and orchestration for Rule paired qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tools.performance_rule.evidence import (
    load_calibration,
    review_calibration_source,
)
from tools.performance_rule.failure import Category, Failure, Stage, classify, persist_failure
from tools.performance_rule.pairing import (
    calibrated_limit,
    pair_execution_order,
    summarize,
)
from tools.performance_rule.policy import calibration_required_policy, threshold_policy
from tools.performance_rule.output import EvidenceLimit, OutputCleanupFailures, emit_result, encoded_size, encode_result
from tools.performance_rule.runner_request import parse_runner_request
from tools.performance_rule.runner_report import run_once
from tools.performance_rule.validated_report import require_same_workload
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
    THRESHOLD_POLICY_VERSION,
    WITHIN_CALIBRATED_BAND,
    ControlError,
    runner_creation_flags,
    sha256_file,
    validate_pairs,
    canonical_json_sha256,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(Stage.ARGUMENTS, Category.INVALID_INPUT)


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if len(arguments) > 64 or sum(len(value) for value in arguments) > 65_536:
        raise Failure(Stage.ARGUMENTS, Category.INVALID_INPUT)
    parser = _Parser(description=__doc__)
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
    if parsed.output is not None and parsed.output.suffix != ".json":
        raise Failure(Stage.ARGUMENTS, Category.INVALID_INPUT)
    if parsed.command == "run" and parsed.runner_arguments[:1] == ["--"]:
        parsed.runner_arguments = parsed.runner_arguments[1:]
    return parsed


def _emit_result(result: dict[str, Any], output: Path | None) -> None:
    try:
        emit_result(result, output)
    except OutputCleanupFailures as error:
        interruptions, _ = error.split((KeyboardInterrupt, SystemExit))
        if interruptions is not None:
            interruption = interruptions
            while isinstance(interruption, BaseExceptionGroup):
                interruption = interruption.exceptions[0]
            raise interruption from None
        raise classify(error, Stage.OUTPUT) from None
    except Exception as error:
        raise classify(error, Stage.OUTPUT) from None


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
    request = parse_runner_request(args.runner_arguments)
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
        _emit_result(result, args.output)
        return result
    calibration = (
        load_calibration(args.calibration, parent_sha, args.runner_arguments, args.runner_priority)
        if not same_binary else None
    )
    creation_flags = runner_creation_flags(args.runner_priority)
    expected_scenarios = calibration.scenario_suites if calibration else None
    workload = calibration.workload_sha256 if calibration else None
    partial = _calibration_required_result(
        pairs=args.pairs, parent_sha=parent_sha, candidate_sha=candidate_sha,
        runner_arguments=args.runner_arguments, runner_priority=args.runner_priority,
    )
    partial.update(mode="aa" if same_binary else "parent_candidate", status=INVALID,
                   decision_reason="evidence_budget_exceeded")
    partial["threshold_policy"] = {
        "version": THRESHOLD_POLICY_VERSION, "status": INVALID, "reviewed": False,
        "enforced": False, "gate_passed": False, "decision": "invalid",
    }
    # Check fixed overhead before launching work; later charges include the
    # exact nesting, scenario catalog and execution trace, not just raw bytes.
    encoded_size(partial)
    pairs: list[dict[str, Any]] = []
    execution_trace: list[dict[str, Any]] = []
    for pair_index in range(args.pairs):
        pair: dict[str, Any] = {}
        for order_index, (role, executable) in enumerate(
            pair_execution_order(pair_index, parent, candidate)
        ):
            expected_sha = parent_sha if role == "parent" else candidate_sha
            try:
                validated = run_once(
                    role,
                    executable,
                    args.runner_arguments,
                    args.timeout_seconds,
                    expected_sha,
                    creation_flags,
                )
                request.validate_report(validated.report)
                workload = require_same_workload(workload, validated.workload_sha256)
            except EvidenceLimit:
                _emit_result(partial, args.output)
                return partial
            except Exception as error:
                partial["decision_reason"] = "runner_report_failed"
                failure = classify(error, Stage.RUNNER_REPORT)
                failure.identity = {
                    "parent_runner_sha256": parent_sha, "candidate_runner_sha256": candidate_sha,
                    "runner_sha256": expected_sha, "pair": pair_index + 1,
                    "order": order_index + 1, "role": role,
                    "runner_arguments_sha256": canonical_json_sha256(args.runner_arguments),
                    "partial_report_sha256": None,
                }
                try:
                    _emit_result(partial, args.output)
                    if args.output is not None:
                        failure.identity["partial_report_sha256"] = hashlib.sha256(encode_result(partial).encode("utf-8")).hexdigest()
                except Failure as output_failure:
                    failure.add_secondary(output_failure)
                raise failure from None
            expected_scenarios = validated.scenario_suites
            entry = {
                "pair": pair_index + 1, "order": order_index + 1, "role": role,
                "runner_sha256": expected_sha,
            }
            proposed = dict(partial)
            proposed.update(
                scenario_ids=sorted(expected_scenarios),
                scenario_suites=dict(sorted(expected_scenarios.items())),
                raw_pairs=[*pairs, {**pair, role: validated.report}],
                execution_trace=[*execution_trace, entry],
            )
            try:
                encoded_size(proposed)
            except EvidenceLimit:
                # Keep every already-admitted report. The report that cannot
                # fit is rejected, not silently dropped from a successful run.
                _emit_result(partial, args.output)
                return partial
            partial = proposed
            pair[role] = validated.report
            execution_trace.append(entry)
        pairs.append(pair)
    assert expected_scenarios is not None and workload is not None

    if same_binary:
        comparisons = summarize(expected_scenarios, pairs, True, 10.0)
        effective_limit = calibrated_limit(comparisons)
        calibration_source = None
        calibration_sha256 = None
        reviewed = False
    else:
        assert calibration is not None
        effective_limit = calibration.effective_limit
        calibration_sha256 = calibration.sha256
        comparisons = summarize(
            expected_scenarios, pairs, False, effective_limit
        )
        calibration_source = str(calibration.path)
        reviewed = True
    policy = threshold_policy(
        comparisons,
        effective_limit,
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
            else "reviewed match_set median gate evaluated"
        ),
    }
    try:
        encoded_size(result)
    except EvidenceLimit:
        _emit_result(partial, args.output)
        return partial
    _emit_result(result, args.output)
    return result


def main(arguments: list[str] | None = None) -> int:
    parsed = None
    stage = Stage.ARGUMENTS
    request_sha256 = None
    try:
        parsed = parse_arguments(arguments)
        request_sha256 = canonical_json_sha256(list(sys.argv[1:] if arguments is None else arguments))
        if parsed.command == "review-calibration":
            stage = Stage.CALIBRATION_REVIEW
            reviewed = review_calibration_source(
                parsed.source_report,
                output_path=parsed.output,
                reviewed_by=parsed.reviewed_by,
                reviewed_utc=parsed.reviewed_utc,
            )
            _emit_result(reviewed, parsed.output)
            return 0
        stage = Stage.PREFLIGHT
        result = control(arguments if arguments is not None else sys.argv[1:])
        if result["status"] == INVALID:
            failure = Failure(Stage.OUTPUT, Category.OUTPUT_LIMIT)
            failure.identity = {
                "parent_runner_sha256": result["parent_runner_sha256"],
                "candidate_runner_sha256": result["candidate_runner_sha256"],
                "partial_report_sha256": hashlib.sha256(encode_result(result).encode("utf-8")).hexdigest() if parsed.output is not None else None,
            }
            raise failure
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, BaseExceptionGroup):
            interruptions, _ = error.split((KeyboardInterrupt, SystemExit))
            if interruptions is not None:
                interruption = interruptions
                while isinstance(interruption, BaseExceptionGroup):
                    interruption = interruption.exceptions[0]
                raise interruption from None
        elif not isinstance(error, Exception):
            raise
        failure = classify(error, stage)
        if parsed is not None and parsed.output is not None:
            try:
                persist_failure(failure, parsed.output, request_sha256)
            except Exception as evidence_error:
                failure.add_secondary(classify(evidence_error, Stage.OUTPUT))
        print(f"rule qualification control failed: {failure}", file=sys.stderr)
        for secondary in failure.secondary:
            print(f"rule qualification control failed: stage={secondary['stage']} category={secondary['category']}", file=sys.stderr)
        return 2
    if result["status"] in {CANDIDATE_WIN, WITHIN_CALIBRATED_BAND}:
        return 0
    if result["status"] == REGRESSION:
        return 3
    if result["status"] in {CALIBRATION_REQUIRED, INCONCLUSIVE}:
        return 4
    if result["status"] == INVALID:
        return 2
    print("rule qualification control failed: stage=output category=invalid_evidence", file=sys.stderr)
    return 2
