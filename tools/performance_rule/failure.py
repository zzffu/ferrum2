"""Closed controller failures and content-addressed, content-free failure evidence."""

from __future__ import annotations

from enum import StrEnum
import hashlib
from pathlib import Path
import subprocess
from typing import Any

from tools.performance_rule.schema import ControlError


class Stage(StrEnum):
    ARGUMENTS = "arguments"
    PREFLIGHT = "preflight"
    RUNNER_START = "runner_start"
    RUNNER_CAPTURE = "runner_capture"
    RUNNER_EXIT = "runner_exit"
    RUNNER_REPORT = "runner_report"
    CALIBRATION_REVIEW = "calibration_review"
    OUTPUT = "output"


class Category(StrEnum):
    INVALID_INPUT = "invalid_input"
    INVALID_EVIDENCE = "invalid_evidence"
    IO = "io"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    NONZERO_EXIT = "nonzero_exit"
    INTERNAL = "internal"
    CLEANUP_UNCONFIRMED = "cleanup_unconfirmed"


def fingerprint(raw: bytes, *, truncated: bool = False) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "truncated": truncated}


class Failure(ControlError):
    """A closed failure; diagnostics contain fingerprints, never input content."""

    def __init__(self, stage: Stage, category: Category, *, diagnostics=None, exit_code=None, errno=None):
        super().__init__(f"stage={stage.value} category={category.value}")
        self.stage = stage
        self.category = category
        self.diagnostics = diagnostics or {}
        self.exit_code = exit_code if type(exit_code) is int and -(2**31) <= exit_code < 2**32 else None
        self.errno = errno if type(errno) is int and 0 <= errno < 2**31 else None
        self.identity: dict[str, Any] = {}
        self.secondary: list[dict[str, str]] = []

    def add_secondary(self, failure: Failure) -> None:
        if len(self.secondary) < 2:
            self.secondary.append({"stage": failure.stage.value, "category": failure.category.value})
        for secondary in failure.secondary[:2]:
            if len(self.secondary) < 2:
                self.secondary.append(secondary)


def classify(error: BaseException, stage: Stage) -> Failure:
    if isinstance(error, Failure):
        return error
    if isinstance(error, subprocess.TimeoutExpired):
        category = Category.TIMEOUT
    elif isinstance(error, OSError):
        category = Category.IO
    elif isinstance(error, ControlError):
        category = Category.INVALID_INPUT if stage == Stage.ARGUMENTS else Category.INVALID_EVIDENCE
    else:
        category = Category.INTERNAL
    # Hash at most 64 Ki characters of exception text. Never retain that text.
    message = str(error)
    raw = message[:65_536].encode("utf-8", errors="replace")
    failure = Failure(stage, category, diagnostics={"exception": fingerprint(raw, truncated=len(message) > 65_536)}, errno=getattr(error, "errno", None))
    if stage == Stage.OUTPUT:
        from tools.performance_rule.output import OutputCleanupFailures

        # Recognize only our own immediate cleanup marker. Do not traverse or
        # stringify arbitrary chained/grouped external exceptions.
        if isinstance(error, OutputCleanupFailures):
            failure = Failure(stage, Category.CLEANUP_UNCONFIRMED, diagnostics=failure.diagnostics)
        elif isinstance(error.__cause__, OutputCleanupFailures):
            failure.add_secondary(Failure(Stage.OUTPUT, Category.CLEANUP_UNCONFIRMED))
    return failure


def persist_failure(failure: Failure, output: Path, request_sha256: str | None) -> None:
    from tools.performance_rule.output import encode_result, write_encoded

    document = {
        "schema": "ferrum2.rule-qualification-failure.v1",
        "stage": failure.stage.value,
        "category": failure.category.value,
        "exit_code": failure.exit_code,
        "errno": failure.errno,
        "request_sha256": request_sha256,
        "identity": failure.identity,
        "diagnostics": failure.diagnostics,
        "secondary": failure.secondary,
    }
    encoded = encode_result(document)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    # The content hash binds this independent document; no user-controlled stem
    # or path is included in its contents or printed to the terminal.
    destination = output.with_name(f"{output.stem}.failure.{digest}.json")
    write_encoded(encoded, destination)
