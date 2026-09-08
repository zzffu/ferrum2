"""Bounded qualification-runner execution and validated result handoff."""

from __future__ import annotations

import time
from pathlib import Path

from tools.owned_process import capture

from tools.performance_rule.json_contract import closed_json_bytes
from tools.performance_rule.failure import Category, Failure, Stage, classify, fingerprint
from tools.performance_rule.output import EVIDENCE_MAX_BYTES
from tools.performance_rule.validated_report import ValidatedReport, validate_report

RUNNER_STDOUT_MAX_BYTES = EVIDENCE_MAX_BYTES
RUNNER_STDERR_MAX_BYTES = 64 * 1024
RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS = 5


def run_once(
    role: str,
    executable: Path,
    runner_arguments: list[str],
    timeout_seconds: int,
    expected_sha256: str,
    creation_flags: int,
) -> ValidatedReport:
    command = [str(executable), *runner_arguments]
    try:
        returncode, stdout, stderr = _run_bounded(
            command, timeout_seconds=timeout_seconds, creation_flags=creation_flags
        )
    except Exception as error:
        raise classify(error, Stage.RUNNER_START) from None
    if returncode != 0:
        raise Failure(Stage.RUNNER_EXIT, Category.NONZERO_EXIT, exit_code=returncode,
                      diagnostics={"stdout": fingerprint(stdout), "stderr": fingerprint(stderr)})
    try:
        report = closed_json_bytes(stdout, label="runner stdout", maximum_bytes=RUNNER_STDOUT_MAX_BYTES)
        return validate_report(report, expected_sha256)
    except Exception as error:
        failure = classify(error, Stage.RUNNER_REPORT)
        failure.diagnostics = {"stdout": fingerprint(stdout), "stderr": fingerprint(stderr)}
        raise failure from None


def _run_bounded(
    command: list[str], *, timeout_seconds: int, creation_flags: int
) -> tuple[int, bytes, bytes]:
    result = capture(
        command, deadline=time.monotonic() + timeout_seconds,
        stdout_cap=RUNNER_STDOUT_MAX_BYTES, stderr_cap=RUNNER_STDERR_MAX_BYTES,
        creationflags=creation_flags, cleanup_grace=RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS,
    )
    primary = None
    if result.failure:
        category = {"timed_out": Category.TIMEOUT, "output_limit": Category.OUTPUT_LIMIT,
                    "capture_failed": Category.IO, "start_failed": Category.INTERNAL}[result.failure]
        primary = Failure(Stage.RUNNER_START if result.failure == "start_failed" else Stage.RUNNER_CAPTURE, category)
    if not result.cleanup_confirmed:
        cleanup = Failure(Stage.RUNNER_CAPTURE, Category.CLEANUP_UNCONFIRMED)
        if primary is None:
            primary = cleanup
        else:
            primary.add_secondary(cleanup)
    if primary is not None:
        primary.diagnostics = {
            "stdout": fingerprint(result.stdout, truncated=result.failure is not None),
            "stderr": fingerprint(result.stderr, truncated=result.failure is not None),
        }
        raise primary from None
    return result.returncode, result.stdout, result.stderr
