"""Observation-only Linux baseline matrix and artifact report."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

from tools.performance_candidate import build_experiment
from tools.performance_candidate.identity import COMMIT_SHA
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _canonical_json_bytes,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux.plan import load_plan
from tools.performance_candidate.linux.policy import load_decision_policy
from tools.performance_candidate.linux.trial import _read_trial, _validate_trial
from tools.performance_candidate.output import _atomic_text

MATRIX_SCHEMA_VERSION = "ferrum2-linux-baseline-matrix-v1"
REPORT_SCHEMA_VERSION = "ferrum2-linux-baseline-report-v1"
MATRIX_MAX_BYTES = 2 * 1024 * 1024
ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
COMMANDS = frozenset({"linux-baseline-matrix", "linux-baseline-report"})
ARTIFACT_FILES = {
    "raw_jsonl": "raw.jsonl",
    "perf_stat": "perf-stat.json",
    "rss": "rss.json",
    "allocator": "allocator.json",
}


def _sha256(path: pathlib.Path, *, field: str) -> str:
    return build_experiment._file_sha256(path, field=field)


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _validated_sha(value: str, field: str) -> str:
    value = value.lower()
    if COMMIT_SHA.fullmatch(value) is None:
        raise CandidateControlError(f"{field} must be a full commit SHA")
    return value


def create_baseline_matrix(
    *,
    plan_path: pathlib.Path,
    policy_path: pathlib.Path,
    environment_path: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
    build_profile: str,
) -> dict[str, object]:
    parent_sha = _validated_sha(parent_sha, "parent_sha")
    candidate_sha = _validated_sha(candidate_sha, "candidate_sha")
    if build_profile != "current":
        raise CandidateControlError("baseline build_profile must be current")
    policy = load_decision_policy(policy_path)
    plan = load_plan(plan_path, decision_policy=policy)
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    source = environment["source_identity"]
    if (
        source["parent_sha"] != parent_sha
        or source["candidate_sha"] != candidate_sha
        or source["run_kind"] != plan["run_kind"]
    ):
        raise CandidateControlError(
            "baseline environment source identity does not match the plan"
        )
    rows: list[dict[str, object]] = []
    for scenario in plan["scenarios"]:
        name = scenario["scenario"]
        for pair in range(1, plan["pairs"] + 1):
            for member in ("parent", "candidate"):
                order = 1 if (pair % 2 == 1) == (member == "parent") else 2
                directory = pathlib.PurePosixPath(
                    name, member, f"pair-{pair}-order-{order}"
                )
                rows.append(
                    {
                        "artifacts": {
                            kind: (directory / filename).as_posix()
                            for kind, filename in ARTIFACT_FILES.items()
                        },
                        "member": member,
                        "order": order,
                        "pair": pair,
                        "scenario": name,
                        "sha": parent_sha if member == "parent" else candidate_sha,
                    }
                )
    body = {
        "artifacts": {
            "kinds": sorted(ARTIFACT_FILES),
            "maximum_bytes_per_artifact": ARTIFACT_MAX_BYTES,
            "required_for_every_trial": True,
        },
        "build": {
            "build_identity_id": environment["build_identity_id"],
            "cargo_profile": environment["build_identity"]["profile"],
            "evidence_build_profile": build_profile,
            "locked_dependencies": environment["build_identity"][
                "locked_dependencies"
            ],
        },
        "candidate_sha": candidate_sha,
        "decision_contract": {
            "adoption_claim": False,
            "performance_conclusion": None,
            "results_are_observations_only": True,
            "threshold_source": "reviewed-policy-only",
        },
        "environment": {
            "artifact_sha256": environment_sha256,
            "environment_id": environment["environment_id"],
            "environment_kind": environment["environment_kind"],
            "runner_image": environment["runner_image"],
        },
        "parent_sha": parent_sha,
        "plan": {
            "artifact_sha256": _sha256(plan_path, field="baseline plan"),
            "run_kind": plan["run_kind"],
            "schema_version": plan["schema_version"],
            "selection": plan["selection"],
        },
        "policy": {
            "artifact_sha256": _sha256(policy_path, field="baseline policy"),
            "policy_id": policy["policy_id"],
            "policy_sha256": policy["policy_sha256"],
        },
        "rows": rows,
        "schema_version": MATRIX_SCHEMA_VERSION,
    }
    return {**body, "matrix_id": _identity(body)}


def _load_matrix(path: pathlib.Path) -> dict[str, object]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MATRIX_MAX_BYTES, source="baseline matrix"
    )
    matrix = bounded.value
    fields = frozenset(
        {
            "artifacts",
            "build",
            "candidate_sha",
            "decision_contract",
            "environment",
            "matrix_id",
            "parent_sha",
            "plan",
            "policy",
            "rows",
            "schema_version",
        }
    )
    if type(matrix) is not dict:
        raise CandidateControlError("baseline matrix must be an object")
    _exact_fields(matrix, fields, "baseline matrix")
    if matrix["schema_version"] != MATRIX_SCHEMA_VERSION:
        raise CandidateControlError("baseline matrix schema_version is invalid")
    for field, expected_fields in (
        (
            "artifacts",
            {"kinds", "maximum_bytes_per_artifact", "required_for_every_trial"},
        ),
        (
            "build",
            {
                "build_identity_id",
                "cargo_profile",
                "evidence_build_profile",
                "locked_dependencies",
            },
        ),
        (
            "decision_contract",
            {
                "adoption_claim",
                "performance_conclusion",
                "results_are_observations_only",
                "threshold_source",
            },
        ),
        (
            "environment",
            {"artifact_sha256", "environment_id", "environment_kind", "runner_image"},
        ),
        ("plan", {"artifact_sha256", "run_kind", "schema_version", "selection"}),
        ("policy", {"artifact_sha256", "policy_id", "policy_sha256"}),
    ):
        value = matrix[field]
        if type(value) is not dict:
            raise CandidateControlError(f"baseline matrix {field} must be an object")
        _exact_fields(value, frozenset(expected_fields), f"baseline matrix {field}")
    if matrix["artifacts"] != {
        "kinds": sorted(ARTIFACT_FILES),
        "maximum_bytes_per_artifact": ARTIFACT_MAX_BYTES,
        "required_for_every_trial": True,
    }:
        raise CandidateControlError("baseline matrix artifact contract is invalid")
    if matrix["decision_contract"] != {
        "adoption_claim": False,
        "performance_conclusion": None,
        "results_are_observations_only": True,
        "threshold_source": "reviewed-policy-only",
    }:
        raise CandidateControlError("baseline matrix decision contract is invalid")
    for field in ("parent_sha", "candidate_sha"):
        if type(matrix[field]) is not str or COMMIT_SHA.fullmatch(matrix[field]) is None:
            raise CandidateControlError(f"baseline matrix {field} is invalid")
    for field in ("build_identity_id",):
        value = matrix["build"][field]
        if type(value) is not str or SHA256.fullmatch(value) is None:
            raise CandidateControlError(f"baseline matrix build {field} is invalid")
    if (
        matrix["build"]["cargo_profile"] != "profiling"
        or matrix["build"]["evidence_build_profile"] != "current"
        or matrix["build"]["locked_dependencies"] is not True
    ):
        raise CandidateControlError("baseline matrix build contract is invalid")
    for owner in ("environment", "plan", "policy"):
        for field in ("artifact_sha256",):
            value = matrix[owner][field]
            if type(value) is not str or SHA256.fullmatch(value) is None:
                raise CandidateControlError(
                    f"baseline matrix {owner} artifact hash is invalid"
                )
    rows = matrix["rows"]
    if type(rows) is not list or not rows or len(rows) > 2_048:
        raise CandidateControlError("baseline matrix rows are invalid")
    for row in rows:
        if type(row) is not dict:
            raise CandidateControlError("baseline matrix row must be an object")
        _exact_fields(
            row,
            frozenset({"artifacts", "member", "order", "pair", "scenario", "sha"}),
            "baseline matrix row",
        )
        if (
            type(row["scenario"]) is not str
            or not row["scenario"]
            or row["member"] not in {"parent", "candidate"}
            or type(row["pair"]) is not int
            or row["pair"] < 1
            or row["order"] not in {1, 2}
            or type(row["sha"]) is not str
            or COMMIT_SHA.fullmatch(row["sha"]) is None
        ):
            raise CandidateControlError("baseline matrix row identity is invalid")
        directory = pathlib.PurePosixPath(
            row["scenario"],
            row["member"],
            f"pair-{row['pair']}-order-{row['order']}",
        )
        expected_artifacts = {
            kind: (directory / filename).as_posix()
            for kind, filename in ARTIFACT_FILES.items()
        }
        if row["artifacts"] != expected_artifacts:
            raise CandidateControlError("baseline matrix row artifacts are not canonical")
    body = {key: value for key, value in matrix.items() if key != "matrix_id"}
    if (
        type(matrix["matrix_id"]) is not str
        or SHA256.fullmatch(matrix["matrix_id"]) is None
        or matrix["matrix_id"] != _identity(body)
    ):
        raise CandidateControlError("baseline matrix identity does not reconstruct")
    return matrix


def create_baseline_report(
    *,
    matrix_path: pathlib.Path,
    plan_path: pathlib.Path,
    policy_path: pathlib.Path,
    environment_path: pathlib.Path,
    artifact_root: pathlib.Path,
) -> dict[str, object]:
    matrix = _load_matrix(matrix_path)
    policy = load_decision_policy(policy_path)
    plan = load_plan(plan_path, decision_policy=policy)
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    if matrix["plan"]["artifact_sha256"] != _sha256(
        plan_path, field="baseline plan"
    ):
        raise CandidateControlError("baseline matrix plan hash does not match")
    if matrix["policy"]["artifact_sha256"] != _sha256(
        policy_path, field="baseline policy"
    ):
        raise CandidateControlError("baseline matrix policy hash does not match")
    if (
        matrix["environment"]["artifact_sha256"] != environment_sha256
        or matrix["environment"]["environment_id"] != environment["environment_id"]
        or matrix["build"]["build_identity_id"]
        != environment["build_identity_id"]
    ):
        raise CandidateControlError("baseline matrix environment identity does not match")
    if (
        matrix["parent_sha"] != environment["source_identity"]["parent_sha"]
        or matrix["candidate_sha"]
        != environment["source_identity"]["candidate_sha"]
        or matrix["plan"]["run_kind"] != plan["run_kind"]
        or matrix["plan"]["schema_version"] != plan["schema_version"]
        or matrix["plan"]["selection"] != plan["selection"]
        or matrix["policy"]["policy_id"] != policy["policy_id"]
        or matrix["policy"]["policy_sha256"] != policy["policy_sha256"]
    ):
        raise CandidateControlError("baseline matrix bound identity does not match")
    planned = {entry["scenario"]: entry for entry in plan["scenarios"]}
    expected_rows = {
        (
            scenario,
            pair,
            member,
            1 if (pair % 2 == 1) == (member == "parent") else 2,
            matrix["parent_sha"] if member == "parent" else matrix["candidate_sha"],
        )
        for scenario in planned
        for pair in range(1, plan["pairs"] + 1)
        for member in ("parent", "candidate")
    }
    observed_rows = {
        (row["scenario"], row["pair"], row["member"], row["order"], row["sha"])
        for row in matrix["rows"]
    }
    if len(observed_rows) != len(matrix["rows"]) or observed_rows != expected_rows:
        raise CandidateControlError("baseline matrix trial schedule is incomplete")
    artifact_root = artifact_root.resolve()
    if not artifact_root.is_dir():
        raise CandidateControlError("baseline artifact root is unavailable")
    reported_rows = []
    for row in matrix["rows"]:
        artifacts = {}
        for kind, relative_text in row["artifacts"].items():
            if kind not in ARTIFACT_FILES or type(relative_text) is not str:
                raise CandidateControlError("baseline artifact declaration is invalid")
            relative = pathlib.PurePosixPath(relative_text)
            if relative.is_absolute() or ".." in relative.parts:
                raise CandidateControlError("baseline artifact path is unsafe")
            path = (artifact_root / pathlib.Path(*relative.parts)).resolve()
            if (
                not path.is_relative_to(artifact_root)
                or path.is_symlink()
                or not path.is_file()
            ):
                raise CandidateControlError(
                    f"baseline artifact is unavailable: {relative_text}"
                )
            size = path.stat().st_size
            if not 0 < size <= ARTIFACT_MAX_BYTES:
                raise CandidateControlError("baseline artifact size is invalid")
            artifacts[kind] = {
                "path": relative_text,
                "sha256": _sha256(path, field=f"baseline {kind} artifact"),
                "size_bytes": size,
            }
        if set(artifacts) != set(ARTIFACT_FILES):
            raise CandidateControlError("baseline artifact set is incomplete")
        raw_path = artifact_root / pathlib.Path(
            *pathlib.PurePosixPath(row["artifacts"]["raw_jsonl"]).parts
        )
        trial = _read_trial(raw_path)
        scenario, pair, member = _validate_trial(
            trial,
            source_member=row["member"],
            plan=plan,
            planned=planned,
            parent_sha=matrix["parent_sha"],
            candidate_sha=matrix["candidate_sha"],
        )
        if (
            scenario != row["scenario"]
            or pair != row["pair"]
            or member != row["member"]
            or trial["order"] != row["order"]
            or trial["sha"] != row["sha"]
        ):
            raise CandidateControlError("baseline raw trial does not match its matrix row")
        reported_rows.append({**row, "artifacts": artifacts})
    body = {
        "build": matrix["build"],
        "candidate_sha": matrix["candidate_sha"],
        "decision_contract": matrix["decision_contract"],
        "environment": matrix["environment"],
        "matrix_id": matrix["matrix_id"],
        "matrix_sha256": _sha256(matrix_path, field="baseline matrix"),
        "parent_sha": matrix["parent_sha"],
        "plan": matrix["plan"],
        "policy": matrix["policy"],
        "rows": reported_rows,
        "schema_version": REPORT_SCHEMA_VERSION,
    }
    return {**body, "report_id": _identity(body)}


def add_cli_commands(commands: argparse._SubParsersAction) -> None:
    matrix = commands.add_parser(
        "linux-baseline-matrix",
        help="write an observation-only raw/perf/RSS/allocator artifact matrix",
    )
    matrix.add_argument("--plan", required=True, type=pathlib.Path)
    matrix.add_argument("--policy", required=True, type=pathlib.Path)
    matrix.add_argument("--environment", required=True, type=pathlib.Path)
    matrix.add_argument("--parent-sha", required=True)
    matrix.add_argument("--candidate-sha", required=True)
    matrix.add_argument("--build-profile", required=True)
    matrix.add_argument("--output", required=True, type=pathlib.Path)
    report = commands.add_parser(
        "linux-baseline-report",
        help="hash and validate every artifact named by a baseline matrix",
    )
    report.add_argument("--matrix", required=True, type=pathlib.Path)
    report.add_argument("--plan", required=True, type=pathlib.Path)
    report.add_argument("--policy", required=True, type=pathlib.Path)
    report.add_argument("--environment", required=True, type=pathlib.Path)
    report.add_argument("--artifact-root", required=True, type=pathlib.Path)
    report.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    if parsed.command == "linux-baseline-matrix":
        value = create_baseline_matrix(
            plan_path=parsed.plan,
            policy_path=parsed.policy,
            environment_path=parsed.environment,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            build_profile=parsed.build_profile,
        )
    elif parsed.command == "linux-baseline-report":
        value = create_baseline_report(
            matrix_path=parsed.matrix,
            plan_path=parsed.plan,
            policy_path=parsed.policy,
            environment_path=parsed.environment,
            artifact_root=parsed.artifact_root,
        )
    else:
        raise AssertionError(f"unhandled baseline command: {parsed.command}")
    _atomic_text(
        parsed.output,
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return 0
