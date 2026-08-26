"""identity owner."""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess

from tools.performance_candidate.json_contract import CandidateControlError

COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")


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


def _git_bytes(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_output(repository: pathlib.Path, *arguments: str) -> str:
    result = _git(repository, *arguments)
    if result.returncode != 0:
        raise CandidateControlError("unable to inspect scale lineage")
    return result.stdout.strip()


def _require_commit(repository: pathlib.Path, sha: str, *, name: str) -> str:
    if COMMIT_SHA.fullmatch(sha) is None:
        raise CandidateControlError(f"{name} must be a full 40-character commit SHA")
    canonical = sha.lower()
    probe = _git(repository, "cat-file", "-t", canonical)
    if probe.returncode != 0 or probe.stdout.strip() != "commit":
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
        raise CandidateControlError(
            "parent_sha and candidate_sha must be different commits"
        )
    relation = _git(repository, "merge-base", "--is-ancestor", parent, candidate)
    if relation.returncode == 1:
        raise CandidateControlError("parent_sha is not an ancestor of candidate_sha")
    if relation.returncode != 0:
        raise CandidateControlError(
            "unable to confirm parent/candidate ancestry from the available history"
        )
    return parent, candidate


def _git_blob(repository: pathlib.Path, sha: str, path: str) -> bytes:
    result = _git_bytes(repository, "show", f"{sha}:{path}")
    if result.returncode != 0:
        raise CandidateControlError(f"scale lineage blob is unavailable: {path}")
    return result.stdout


def _file_sha256(path: pathlib.Path, field: str) -> str:
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CandidateControlError(f"unable to hash {field}") from error
    return digest
