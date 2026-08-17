#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from collections.abc import Sequence


WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")


class CandidateControlError(ValueError):
    """An invalid performance-candidate request or evidence set."""


def _allowed_integer(value: str, *, name: str, allowed: frozenset[int]) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CandidateControlError(f"{name} must be an integer") from error
    if str(parsed) != value or parsed not in allowed:
        choices = ", ".join(str(choice) for choice in sorted(allowed))
        raise CandidateControlError(f"{name} must be one of: {choices}")
    return parsed


def validate_measurement_inputs(
    warmup_seconds: str, active_seconds: str, pairs: str
) -> tuple[int, int, int]:
    """Validate each bounded measurement input independently."""

    return (
        _allowed_integer(
            warmup_seconds, name="warmup_seconds", allowed=WARMUP_SECONDS
        ),
        _allowed_integer(
            active_seconds, name="active_seconds", allowed=ACTIVE_SECONDS
        ),
        _allowed_integer(pairs, name="pairs", allowed=PAIR_COUNTS),
    )


def _git(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _require_commit(repository: pathlib.Path, sha: str, *, name: str) -> str:
    if COMMIT_SHA.fullmatch(sha) is None:
        raise CandidateControlError(f"{name} must be a full 40-character commit SHA")
    canonical = sha.lower()
    probe = _git(repository, "cat-file", "-e", f"{canonical}^{{commit}}")
    if probe.returncode != 0:
        raise CandidateControlError(
            f"{name} is not an available commit; fetch complete history before comparing"
        )
    return canonical


def validate_git_relation(
    repository: pathlib.Path, parent_sha: str, candidate_sha: str
) -> tuple[str, str]:
    """Require two available commits with parent strictly ancestral to candidate."""

    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("repository must be an existing directory")
    parent = _require_commit(repository, parent_sha, name="parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="candidate_sha")
    if parent == candidate:
        raise CandidateControlError("parent_sha and candidate_sha must be different commits")
    relation = _git(repository, "merge-base", "--is-ancestor", parent, candidate)
    if relation.returncode == 1:
        raise CandidateControlError("parent_sha is not an ancestor of candidate_sha")
    if relation.returncode != 0:
        raise CandidateControlError(
            "unable to confirm parent/candidate ancestry from the available history"
        )
    return parent, candidate


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
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        if parsed.command == "validate-git":
            validate_git_relation(
                parsed.repository, parsed.parent_sha, parsed.candidate_sha
            )
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
