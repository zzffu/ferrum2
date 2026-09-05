"""Bounded qualification-runner execution and validated result handoff."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

from tools.performance_rule.json_contract import closed_json_bytes
from tools.performance_rule.output import EVIDENCE_MAX_BYTES, EvidenceLimit
from tools.performance_rule.schema import ControlError
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
    returncode, stdout, stderr = _run_bounded(
        command, timeout_seconds=timeout_seconds, creation_flags=creation_flags
    )
    if returncode != 0:
        stderr = stderr[-2_000:].strip()
        raise ControlError(
            f"{role} runner exited {returncode}: {stderr or '[no stderr]'}"
        )
    report = closed_json_bytes(
        stdout.encode("utf-8"),
        label=f"{role} runner stdout",
        maximum_bytes=RUNNER_STDOUT_MAX_BYTES,
    )
    return validate_report(report, expected_sha256)


def _run_bounded(
    command: list[str], *, timeout_seconds: int, creation_flags: int
) -> tuple[int, str, str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )
    assert process.stdout is not None and process.stderr is not None
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    failures: list[ControlError] = []

    def drain(name: str, maximum_bytes: int) -> None:
        stream = process.stdout if name == "stdout" else process.stderr
        assert stream is not None
        try:
            while block := stream.read(64 * 1024):
                target = captured[name]
                if len(target) + len(block) > maximum_bytes:
                    failures.append(EvidenceLimit(f"runner {name} exceeds the {maximum_bytes}-byte bound"))
                    process.kill()
                    return
                target.extend(block)
        except OSError as error:
            failures.append(ControlError(f"unable to capture runner {name}: {error}"))
            process.kill()
        finally:
            stream.close()

    readers = [
        threading.Thread(
            target=drain,
            args=("stdout", RUNNER_STDOUT_MAX_BYTES),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", RUNNER_STDERR_MAX_BYTES),
            daemon=True,
        ),
    ]

    def join_readers() -> None:
        deadline = time.monotonic() + RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS
        for reader in readers:
            reader.join(max(0.0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            raise ControlError("runner output capture did not terminate")

    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        join_readers()
        raise subprocess.TimeoutExpired(command, timeout_seconds)
    join_readers()
    if failures:
        raise failures[0]
    try:
        stdout = bytes(captured["stdout"]).decode("utf-8")
        stderr = bytes(captured["stderr"]).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ControlError("runner output is not valid UTF-8") from error
    return returncode, stdout, stderr
