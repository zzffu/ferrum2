"""Typed, fail-closed discovery of changed Git paths for CI controllers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Sequence


KNOWN_EVENTS = frozenset({"pull_request", "push"})


@dataclass(frozen=True)
class ChangeRequest:
    event_name: str
    base_sha: str
    head_sha: str


@dataclass(frozen=True)
class ChangedPaths:
    paths: tuple[str, ...]
    complete: bool
    reason: str

    @classmethod
    def fail_closed(cls, reason: str) -> ChangedPaths:
        return cls((), False, reason)


def _git(repository: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return subprocess.CompletedProcess(arguments, 127, b"", b"git unavailable")


def _commit_exists(repository: Path, revision: str) -> bool:
    return _git(repository, ["cat-file", "-e", f"{revision}^{{commit}}"]).returncode == 0


def _valid_object_id(revision: str) -> bool:
    return len(revision) in {40, 64} and all(
        character in "0123456789abcdefABCDEF" for character in revision
    )


def discover_changed_paths(repository: Path, request: ChangeRequest) -> ChangedPaths:
    """Return an exact NUL-delimited diff, or an incomplete fail-closed result."""

    if request.event_name == "workflow_dispatch":
        return ChangedPaths.fail_closed("manual dispatch has no trusted comparison range")
    if request.event_name not in KNOWN_EVENTS:
        return ChangedPaths.fail_closed(
            f"unknown event {request.event_name!r} has no trusted comparison range"
        )
    if not request.base_sha or set(request.base_sha) == {"0"}:
        return ChangedPaths.fail_closed("comparison base is unavailable")
    if not request.head_sha or set(request.head_sha) == {"0"}:
        return ChangedPaths.fail_closed("comparison head is unavailable")
    if not _valid_object_id(request.base_sha):
        return ChangedPaths.fail_closed("comparison base is not a full object ID")
    if not _valid_object_id(request.head_sha):
        return ChangedPaths.fail_closed("comparison head is not a full object ID")
    if not _commit_exists(repository, request.base_sha):
        return ChangedPaths.fail_closed("comparison base is not present in the checkout")
    if not _commit_exists(repository, request.head_sha):
        return ChangedPaths.fail_closed("comparison head is not present in the checkout")

    separator = "..." if request.event_name == "pull_request" else ".."
    completed = _git(
        repository,
        [
            "diff",
            "--no-ext-diff",
            "--no-renames",
            "--name-only",
            "-z",
            "--diff-filter=ACDMRTUXB",
            f"{request.base_sha}{separator}{request.head_sha}",
        ],
    )
    if completed.returncode != 0:
        return ChangedPaths.fail_closed("changed paths could not be determined")

    paths = tuple(
        encoded.decode("utf-8", errors="surrogateescape")
        for encoded in completed.stdout.split(b"\0")
        if encoded
    )
    return ChangedPaths(paths, True, "changed paths were determined")
