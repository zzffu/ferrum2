"""Bounded qualification-runner execution and validated result handoff."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

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
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )
    assert process.stdout is not None and process.stderr is not None
    # A reader publishes immutable bytes only after its stream cleanup. The
    # owner inspects its slot only after confirming that reader has terminated.
    completed: dict[str, tuple[bytes, Failure | None, bool]] = {}
    readers: list[tuple[str, threading.Thread]] = []
    started: set[str] = set()
    primary: Failure | None = None
    interruption: BaseException | None = None
    reaped = False
    returncode = None
    cleanup_unconfirmed = False

    def drain(name: str, maximum_bytes: int) -> None:
        stream = process.stdout if name == "stdout" else process.stderr
        target = bytearray()
        failure = None
        clean = True
        try:
            while block := stream.read(64 * 1024):
                if len(target) + len(block) > maximum_bytes:
                    failure = Failure(Stage.RUNNER_CAPTURE, Category.OUTPUT_LIMIT)
                    break
                target.extend(block)
        except Exception as error:
            failure = classify(error, Stage.RUNNER_CAPTURE)
        finally:
            if failure is not None:
                try:
                    process.kill()
                except Exception:
                    clean = False
            try:
                stream.close()
            except Exception:
                clean = False
            completed[name] = (bytes(target), failure, clean)

    try:
        for name, cap in (("stdout", RUNNER_STDOUT_MAX_BYTES), ("stderr", RUNNER_STDERR_MAX_BYTES)):
            reader = threading.Thread(target=drain, args=(name, cap), daemon=True)
            readers.append((name, reader))
            reader.start()
            started.add(name)
        try:
            returncode = process.wait(timeout=timeout_seconds)
            reaped = True
        except subprocess.TimeoutExpired:
            primary = Failure(Stage.RUNNER_CAPTURE, Category.TIMEOUT)
    except BaseException as error:
        if isinstance(error, Exception):
            primary = classify(error, Stage.RUNNER_START if len(started) != 2 else Stage.RUNNER_CAPTURE)
        else:
            interruption = error
    finally:
        # One deadline covers all post-failure waiting, including a failed kill.
        deadline = time.monotonic() + RUNNER_CAPTURE_DRAIN_TIMEOUT_SECONDS
        if not reaped:
            try:
                process.kill()
            except Exception:
                cleanup_unconfirmed = True
            try:
                returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
                reaped = True
            except Exception:
                cleanup_unconfirmed = True
        for name, reader in readers:
            try:
                active = reader.is_alive()
            except Exception:
                cleanup_unconfirmed = True
                continue
            if name in started or active:
                try:
                    reader.join(max(0.0, deadline - time.monotonic()))
                    active = reader.is_alive()
                except Exception:
                    cleanup_unconfirmed = True
                    active = True
                if active:
                    cleanup_unconfirmed = True
                    if primary is None:
                        primary = Failure(Stage.RUNNER_CAPTURE, Category.TIMEOUT)
                    continue
                result = completed.get(name)
                if result is None:
                    cleanup_unconfirmed = True
                    continue
                raw, failure, clean = result
                cleanup_unconfirmed |= not clean
                if primary is None and failure is not None:
                    primary = failure
                if primary is not None:
                    primary.diagnostics[name] = fingerprint(raw, truncated=failure is not None or primary.category == Category.TIMEOUT)
            else:
                stream = process.stdout if name == "stdout" else process.stderr
                try:
                    stream.close()
                except Exception:
                    cleanup_unconfirmed = True
        created = {name for name, _ in readers}
        for name in {"stdout", "stderr"} - created:
            try:
                (process.stdout if name == "stdout" else process.stderr).close()
            except Exception:
                cleanup_unconfirmed = True
    if interruption is not None:
        raise interruption from None
    if cleanup_unconfirmed:
        cleanup = Failure(Stage.RUNNER_CAPTURE, Category.CLEANUP_UNCONFIRMED)
        if primary is None:
            primary = cleanup
        else:
            primary.add_secondary(cleanup)
    if primary is not None:
        raise primary from None
    assert reaped and returncode is not None
    return returncode, completed["stdout"][0], completed["stderr"][0]
