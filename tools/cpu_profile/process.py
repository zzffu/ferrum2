"""Own one Linux profiler helper group, both pipes, and its cleanup deadline."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from tools.owned_process import ProcessTree


class CommandStatus(Enum):
    COMPLETED = "completed"
    FAILED = "command_failed"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"
    OUTPUT_LIMIT = "output_limit"


class CleanupStatus(Enum):
    NOT_STARTED = "not_started"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    exit_code: int | None
    started_ns: int
    ended_ns: int
    stdout_bytes: int
    stderr_bytes: int
    helper_pid: int | None = None
    cleanup: CleanupStatus = CleanupStatus.CONFIRMED


def private_file(path: Path):
    """Create a new private artifact; never replace evidence from a previous run."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        return os.fdopen(descriptor, "wb")
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            path.unlink(missing_ok=True)
        raise


class ProcessOwner:
    def __init__(self, *, cleanup_grace: float = 2.0):
        self.cancelled = False
        self.cleanup_grace = cleanup_grace
        self._handlers = {}

    def __enter__(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            self._handlers[number] = signal.signal(number, self._interrupt)
        return self

    def __exit__(self, *_error):
        for number, handler in self._handlers.items():
            signal.signal(number, handler)

    def _interrupt(self, _number, _frame):
        self.cancelled = True


    def run(
        self, argv: list[str], *, deadline: float, stdout: Path, stderr: Path,
        byte_cap: int = 65_536, interrupt_after: float | None = None,
    ) -> CommandResult:
        """Run an owned helper; cancellation signals only its newly created session.

        interrupt_after is the collector's normal stop request, unlike cancellation
        or the hard deadline. Both pipes keep draining after the retained byte cap.
        No target Ferrum PID is ever passed to the signal/reap operations.
        """
        started = time.monotonic_ns()
        if self.cancelled or time.monotonic() >= deadline:
            status = CommandStatus.INTERRUPTED if self.cancelled else CommandStatus.TIMED_OUT
            return CommandResult(
                status, None, started, time.monotonic_ns(), 0, 0,
                cleanup=CleanupStatus.NOT_STARTED,
            )
        counts = {"stdout": 0, "stderr": 0}
        status = CommandStatus.COMPLETED
        cleanup = CleanupStatus.CONFIRMED
        child = None
        stop_at = None
        requested_stop = False
        killed = False
        with private_file(stdout) as output, private_file(stderr) as errors:
            with selectors.DefaultSelector() as selector:
                try:
                    tree = ProcessTree.spawn(
                        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env={**os.environ, "LC_ALL": "C"},
                    )
                    child = tree.process
                    for name, stream, destination in (
                        ("stdout", child.stdout, output), ("stderr", child.stderr, errors),
                    ):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, (name, destination))
                    soft_stop = None if interrupt_after is None else time.monotonic() + interrupt_after
                    while True:
                        now = time.monotonic()
                        if self.cancelled and status is CommandStatus.COMPLETED:
                            status = CommandStatus.INTERRUPTED
                        if now >= deadline and status is CommandStatus.COMPLETED:
                            status = CommandStatus.TIMED_OUT
                        if status is not CommandStatus.COMPLETED and stop_at is None:
                            tree.signal(signal.SIGINT)
                            stop_at = now + self.cleanup_grace
                        if soft_stop is not None and now >= soft_stop and not requested_stop:
                            tree.signal(signal.SIGINT)
                            requested_stop = True
                        if stop_at is not None and now >= stop_at:
                            if not killed:
                                tree.signal(signal.SIGKILL)
                                killed = True
                                stop_at = now + self.cleanup_grace
                            else:
                                cleanup = CleanupStatus.UNCONFIRMED
                                break
                        for key, _events in selector.select(0.02):
                            chunk = os.read(key.fileobj.fileno(), 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                                continue
                            name, destination = key.data
                            remaining = max(0, byte_cap - counts[name])
                            destination.write(chunk[:remaining])
                            counts[name] += len(chunk)
                            if counts[name] > byte_cap and status is CommandStatus.COMPLETED:
                                status = CommandStatus.OUTPUT_LIMIT
                        # Observe exit without reaping the leader. Retaining its PID
                        # prevents process-group ID reuse before our final group signal.
                        if tree.exited() and not selector.get_map():
                            break
                except OSError:
                    if status is CommandStatus.COMPLETED:
                        status = CommandStatus.FAILED
                finally:
                    if child is not None:
                        # The group is owned even if its leader exited while a child
                        # retained a pipe. Never let closing the pipes substitute for reap.
                        if not tree.close(self.cleanup_grace):
                            cleanup = CleanupStatus.UNCONFIRMED
                        for stream in (child.stdout, child.stderr):
                            if stream is not None:
                                stream.close()
        code = None if child is None else child.returncode
        if status is CommandStatus.COMPLETED and code != 0:
            status = CommandStatus.FAILED
        return CommandResult(
            status, code, started, time.monotonic_ns(), counts["stdout"], counts["stderr"],
            None if child is None else child.pid,
            cleanup,
        )
