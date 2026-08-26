"""scale lineage owner."""

from __future__ import annotations

from tools.performance_candidate.identity import COMMIT_SHA, _file_sha256, _git_blob, _git_bytes, _git_output, _require_commit
from tools.performance_candidate.json_contract import CandidateControlError, read_bounded_closed_json

import hashlib
import pathlib

from tools.performance_candidate.linux.scale import SCALE_COUNTERFACTUAL_REPLACEMENTS, validate_scale_lineage_shape

SCALE_LINEAGE_MAX_BYTES = 64 * 1024

def _commit_parent(repository: pathlib.Path, sha: str) -> str:
    fields = _git_output(repository, "rev-list", "--parents", "-n", "1", sha).split()
    if len(fields) != 2 or fields[0] != sha:
        raise CandidateControlError("scale lineage member must be a single-parent commit")
    return fields[1]


def _commit_tree(repository: pathlib.Path, sha: str) -> str:
    tree = _git_output(repository, "rev-parse", f"{sha}^{{tree}}")
    if COMMIT_SHA.fullmatch(tree) is None:
        raise CandidateControlError("scale lineage tree identity is invalid")
    return tree


def _scale_patch_digest(repository: pathlib.Path, head: str, parent: str) -> str:
    paths = sorted(SCALE_COUNTERFACTUAL_REPLACEMENTS)
    result = _git_bytes(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-renames",
        head,
        parent,
        "--",
        *paths,
    )
    if result.returncode != 0:
        raise CandidateControlError("unable to derive scale counterfactual patch")
    return hashlib.sha256(result.stdout).hexdigest()


def _validate_scale_lineage_source_repository(
    repository: pathlib.Path, lineage: dict[str, object]
) -> None:
    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("scale lineage repository is missing")
    head = _require_commit(repository, lineage["head_sha"], name="scale head_sha")
    parent = _require_commit(repository, lineage["parent_sha"], name="scale parent_sha")
    candidate = _require_commit(
        repository, lineage["candidate_sha"], name="scale candidate_sha"
    )
    if _commit_parent(repository, parent) != head:
        raise CandidateControlError("scale 16 KiB parent is not a direct child of H")
    if _commit_parent(repository, candidate) != parent:
        raise CandidateControlError("scale 32 KiB candidate is not a direct child of P16")
    trees = {
        "head_tree": _commit_tree(repository, head),
        "parent_tree": _commit_tree(repository, parent),
        "candidate_tree": _commit_tree(repository, candidate),
    }
    for field, observed in trees.items():
        if lineage[field] != observed:
            raise CandidateControlError(f"scale lineage {field} does not match git")
    raw = _git_output(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "-r",
        "--no-renames",
        head,
        parent,
    )
    changed: dict[str, tuple[str, str, str]] = {}
    for line in raw.splitlines():
        try:
            metadata, path = line.split("\t", 1)
            old_mode, new_mode, _old_blob, _new_blob, status = metadata[1:].split()
        except ValueError as error:
            raise CandidateControlError("scale lineage raw diff is malformed") from error
        if path in changed:
            raise CandidateControlError("scale lineage path is duplicated")
        changed[path] = (old_mode, new_mode, status)
    if set(changed) != set(SCALE_COUNTERFACTUAL_REPLACEMENTS):
        raise CandidateControlError("scale lineage changes an unexpected path set")
    for path, replacements in SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
        old_mode, new_mode, status = changed[path]
        if old_mode != "100644" or new_mode != "100644" or status != "M":
            raise CandidateControlError("scale lineage changed mode, status, or rename shape")
        head_blob = _git_blob(repository, head, path)
        parent_blob = _git_blob(repository, parent, path)
        expected = head_blob
        for old_literal, new_literal in replacements:
            if expected.count(old_literal) != 1 or new_literal in expected:
                raise CandidateControlError(
                    f"scale head literal count is not exact for {path}"
                )
            expected = expected.replace(old_literal, new_literal, 1)
        if parent_blob != expected:
            raise CandidateControlError(
                f"scale parent blob is not the exact 16 KiB replacement for {path}"
            )
    if _scale_patch_digest(repository, head, parent) != lineage["counterfactual_patch_sha256"]:
        raise CandidateControlError("scale counterfactual patch digest does not match")


def validate_scale_lineage_repository(
    repository: pathlib.Path, lineage: dict[str, object]
) -> None:
    validate_scale_lineage_shape(lineage)
    _validate_scale_lineage_source_repository(repository, lineage)


def validate_scale_source_lineage(
    repository: pathlib.Path,
    head_sha: str,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    head = _require_commit(repository, head_sha, name="scale head_sha")
    parent = _require_commit(repository, parent_sha, name="scale parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="scale candidate_sha")
    source = {
        "head_sha": head,
        "head_tree": _commit_tree(repository, head),
        "parent_sha": parent,
        "parent_tree": _commit_tree(repository, parent),
        "candidate_sha": candidate,
        "candidate_tree": _commit_tree(repository, candidate),
        "counterfactual_patch_sha256": _scale_patch_digest(repository, head, parent),
    }
    if source["head_tree"] != source["candidate_tree"]:
        raise CandidateControlError("scale candidate tree must equal the final head tree")
    if source["parent_tree"] == source["head_tree"]:
        raise CandidateControlError("scale parent tree must be the 16 KiB counterfactual")
    _validate_scale_lineage_source_repository(repository, source)
    return source


def build_scale_lineage(
    *,
    repository: pathlib.Path,
    head_sha: str,
    parent_sha: str,
    candidate_sha: str,
    runner: pathlib.Path,
    parent_client: pathlib.Path,
    parent_server: pathlib.Path,
    candidate_client: pathlib.Path,
    candidate_server: pathlib.Path,
) -> dict[str, object]:
    source = validate_scale_source_lineage(
        repository, head_sha, parent_sha, candidate_sha
    )
    lineage = {
        "schema_version": 1,
        **source,
        "runner_sha256": _file_sha256(runner, "scale runner"),
        "parent_client_sha256": _file_sha256(parent_client, "scale parent client"),
        "parent_server_sha256": _file_sha256(parent_server, "scale parent server"),
        "candidate_client_sha256": _file_sha256(candidate_client, "scale candidate client"),
        "candidate_server_sha256": _file_sha256(candidate_server, "scale candidate server"),
    }
    validate_scale_lineage_repository(repository, lineage)
    return lineage


def load_scale_lineage(path: pathlib.Path) -> dict[str, object]:
    value = read_bounded_closed_json(
        path, maximum_bytes=SCALE_LINEAGE_MAX_BYTES, source="scale lineage"
    ).value
    if type(value) is not dict:
        raise CandidateControlError("scale lineage must be an object")
    validate_scale_lineage_shape(value)
    return value
