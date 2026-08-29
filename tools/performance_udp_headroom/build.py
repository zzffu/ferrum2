"""Same-source artifact planning, building, and M4-safe materialization."""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import time
from collections.abc import Callable, Sequence

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_udp_headroom.contract import (
    ARTIFACT_NAMES,
    AUTHORITY,
    BUILD_SCHEMA_VERSION,
    PLAN_SCHEMA_VERSION,
    RUNNER_IMAGE,
    TIMED_VARIANTS,
    VARIANT_NAMES,
    diagnostic_evidence_contract,
    load_policy,
    planned_scenarios,
)

CANDIDATE_FEATURES = (
    "ferrum2-client/candidate-udp-owned-headroom",
    "ferrum2-server/candidate-udp-owned-headroom",
)
STRUCTURAL_FEATURES = (
    "ferrum2-client/structural-metrics",
    "ferrum2-server/structural-metrics",
    "ferrum2-m4-qualification/structural-diagnostic",
)
DIAGNOSTIC_CANDIDATE_FEATURES = (
    "ferrum2-client/candidate-udp-owned-headroom",
    "ferrum2-client/structural-metrics",
    "ferrum2-server/candidate-udp-owned-headroom",
    "ferrum2-server/structural-metrics",
    "ferrum2-m4-qualification/structural-diagnostic",
)


def _features(name: str) -> tuple[str, ...]:
    if name == "default":
        return ()
    if name == "candidate":
        return CANDIDATE_FEATURES
    if name == "diagnostic-default":
        return STRUCTURAL_FEATURES
    if name == "diagnostic-candidate":
        return DIAGNOSTIC_CANDIDATE_FEATURES
    raise CandidateControlError("UDP headroom build variant is invalid")


def _build_variants(
    *,
    repository: pathlib.Path,
    target_root: pathlib.Path,
    source_identity: dict[str, object],
    build_identity_id: str,
) -> list[dict[str, object]]:
    variants = []
    for name in VARIANT_NAMES:
        target_dir = (target_root / name).resolve()
        argv = [
            "cargo",
            "build",
            "--package",
            "ferrum2-client",
            "--package",
            "ferrum2-server",
            "--package",
            "ferrum2-m4-qualification",
            "--locked",
            "--profile",
            "profiling",
            "--target-dir",
            str(target_dir),
        ]
        features = _features(name)
        if features:
            argv.extend(("--features", ",".join(features)))
        artifact_root = target_dir / "profiling"
        material = {
            "artifact_paths": {
                artifact: str((artifact_root / artifact).resolve())
                for artifact in ARTIFACT_NAMES
            },
            "argv": argv,
            "build_identity_id": build_identity_id,
            "environment_overrides": {
                "CARGO_INCREMENTAL": "0",
                "RUSTUP_TOOLCHAIN": build_experiment.PINNED_RUST_RELEASE,
            },
            "features": list(features),
            "instrumentation": (
                "none" if name in TIMED_VARIANTS else "structural-diagnostic"
            ),
            "name": name,
            "repository": str(repository),
            "source_identity": source_identity,
            "target_dir": str(target_dir),
            "timed": name in TIMED_VARIANTS,
        }
        variants.append(
            {**material, "variant_id": build_experiment._json_sha256(material)}
        )
    return variants


def create_plan(
    *,
    environment_path: pathlib.Path,
    policy_path: pathlib.Path,
    target_root: pathlib.Path,
) -> dict[str, object]:
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    if (
        environment["environment_kind"] != "github-hosted"
        or environment["runner_image"] != RUNNER_IMAGE
        or environment["source_identity"]["comparison_axis"] != "build-artifact"
    ):
        raise CandidateControlError(
            "UDP headroom plans require a GitHub-hosted same-source environment"
        )
    policy, policy_sha256 = load_policy(policy_path)
    repository = pathlib.Path(environment["repository"]).resolve()
    target_root = target_root.resolve()
    if (
        not repository.is_dir()
        or target_root == repository
        or target_root.is_relative_to(repository)
    ):
        raise CandidateControlError("UDP headroom build target root is invalid")
    variants = _build_variants(
        repository=repository,
        target_root=target_root,
        source_identity=environment["source_identity"],
        build_identity_id=environment["build_identity_id"],
    )
    material = {
        "authority": AUTHORITY,
        "diagnostic_contract": diagnostic_evidence_contract(),
        "environment": {
            "build_identity_id": environment["build_identity_id"],
            "environment_id": environment["environment_id"],
            "path": str(environment_path.resolve()),
            "sha256": environment_sha256,
        },
        "policy": {
            "path": str(policy_path.resolve()),
            "policy_id": policy["policy_id"],
            "sha256": policy_sha256,
        },
        "scenarios": planned_scenarios(policy),
        "schedule": policy["schedule"],
        "schema_version": PLAN_SCHEMA_VERSION,
        "source_identity": environment["source_identity"],
        "target_root": str(target_root),
        "variants": variants,
    }
    return {
        **material,
        "generated_at_utc": build_experiment._utc_now(),
        "plan_id": build_experiment._json_sha256(material),
    }


def load_plan(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="UDP headroom plan",
    )
    plan = bounded.value
    if type(plan) is not dict:
        raise CandidateControlError("UDP headroom plan must be an object")
    _exact_fields(
        plan,
        frozenset(
            {
                "authority",
                "diagnostic_contract",
                "environment",
                "generated_at_utc",
                "plan_id",
                "policy",
                "scenarios",
                "schedule",
                "schema_version",
                "source_identity",
                "target_root",
                "variants",
            }
        ),
        "UDP headroom plan",
    )
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise CandidateControlError("UDP headroom plan schema is unsupported")
    material = dict(plan)
    plan_id = material.pop("plan_id", None)
    generated = material.pop("generated_at_utc", None)
    if (
        type(plan_id) is not str
        or plan_id != build_experiment._json_sha256(material)
        or type(generated) is not str
        or not generated
    ):
        raise CandidateControlError("UDP headroom plan identity does not reconstruct")
    if type(plan["environment"]) is not dict or type(plan["policy"]) is not dict:
        raise CandidateControlError("UDP headroom plan references are invalid")
    environment_path = pathlib.Path(plan["environment"].get("path", ""))
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    policy_path = pathlib.Path(plan["policy"].get("path", ""))
    policy, policy_sha256 = load_policy(policy_path)
    if plan["environment"] != {
        "build_identity_id": environment["build_identity_id"],
        "environment_id": environment["environment_id"],
        "path": str(environment_path.resolve()),
        "sha256": environment_sha256,
    }:
        raise CandidateControlError("UDP headroom plan environment changed")
    if plan["policy"] != {
        "path": str(policy_path.resolve()),
        "policy_id": policy["policy_id"],
        "sha256": policy_sha256,
    }:
        raise CandidateControlError("UDP headroom plan policy changed")
    if (
        plan["authority"] != AUTHORITY
        or plan["diagnostic_contract"] != diagnostic_evidence_contract()
        or plan["scenarios"] != planned_scenarios(policy)
        or plan["schedule"] != policy["schedule"]
        or plan["source_identity"] != environment["source_identity"]
    ):
        raise CandidateControlError("UDP headroom plan contract changed")
    expected_variants = _build_variants(
        repository=pathlib.Path(environment["repository"]).resolve(),
        target_root=pathlib.Path(plan["target_root"]).resolve(),
        source_identity=environment["source_identity"],
        build_identity_id=environment["build_identity_id"],
    )
    if plan["variants"] != expected_variants:
        raise CandidateControlError("UDP headroom build variants changed")
    return plan, bounded.sha256


def variant(plan: dict[str, object], name: str) -> dict[str, object]:
    matches = [row for row in plan["variants"] if row["name"] == name]
    if len(matches) != 1:
        raise CandidateControlError("UDP headroom variant is not present exactly once")
    return matches[0]


def run_build(
    *,
    plan_path: pathlib.Path,
    variant_name: str,
    log_path: pathlib.Path,
    executor: Callable[
        [Sequence[str], pathlib.Path, dict[str, str], pathlib.Path], int
    ] = build_experiment._default_executor,
    clock: Callable[[], int] = time.perf_counter_ns,
) -> tuple[dict[str, object], int]:
    plan, plan_sha256 = load_plan(plan_path)
    selected = variant(plan, variant_name)
    environment_path = pathlib.Path(plan["environment"]["path"])
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    if environment_sha256 != plan["environment"]["sha256"]:
        raise CandidateControlError("UDP headroom build environment changed")
    current = build_experiment.capture_environment(
        repository=pathlib.Path(environment["repository"]),
        source_sha=environment["source_identity"]["source_sha"],
        environment_kind=environment["environment_kind"],
        runner_image=environment["runner_image"],
    )
    if (
        current["environment_id"] != environment["environment_id"]
        or current["build_identity_id"] != environment["build_identity_id"]
    ):
        raise CandidateControlError("UDP headroom build host or identity changed")
    target_dir = pathlib.Path(selected["target_dir"])
    if target_dir.exists():
        raise CandidateControlError("UDP headroom build target must be fresh")
    effective_environment = build_experiment._effective_environment(
        build_experiment.CONTROLLED_ENVIRONMENT_REMOVALS,
        build_experiment.CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS,
        selected["environment_overrides"],
    )
    started = clock()
    returncode = executor(
        selected["argv"],
        pathlib.Path(selected["repository"]),
        effective_environment,
        log_path,
    )
    elapsed = clock() - started
    if type(returncode) is not int or returncode != 0 or elapsed < 0:
        raise CandidateControlError("UDP headroom artifact build failed")
    artifacts = []
    for name in ARTIFACT_NAMES:
        path = pathlib.Path(selected["artifact_paths"][name]).resolve()
        if (
            not path.is_relative_to(target_dir)
            or not path.is_file()
            or path.is_symlink()
        ):
            raise CandidateControlError("UDP headroom artifact is unavailable")
        artifacts.append(
            {
                "name": name,
                "path": str(path),
                "sha256": build_experiment._file_sha256(
                    path, field=f"headroom artifact {name}"
                ),
                "size_bytes": path.stat().st_size,
            }
        )
    material = {
        "artifacts": artifacts,
        "build_identity_id": environment["build_identity_id"],
        "command": {
            "argv": selected["argv"],
            "environment_overrides": selected["environment_overrides"],
            "repository": selected["repository"],
            "target_dir": selected["target_dir"],
        },
        "elapsed_nanoseconds": elapsed,
        "environment_id": environment["environment_id"],
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "schema_version": BUILD_SCHEMA_VERSION,
        "source_identity": environment["source_identity"],
        "variant_id": selected["variant_id"],
        "variant_name": variant_name,
    }
    return {
        **material,
        "record_id": build_experiment._json_sha256(material),
    }, returncode


def load_build_record(
    path: pathlib.Path,
    *,
    plan: dict[str, object],
    plan_sha256: str,
    expected_variant: str,
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="UDP headroom build record",
    )
    record = bounded.value
    if type(record) is not dict:
        raise CandidateControlError("UDP headroom build record must be an object")
    _exact_fields(
        record,
        frozenset(
            {
                "artifacts",
                "build_identity_id",
                "command",
                "elapsed_nanoseconds",
                "environment_id",
                "plan_id",
                "plan_sha256",
                "record_id",
                "schema_version",
                "source_identity",
                "variant_id",
                "variant_name",
            }
        ),
        "UDP headroom build record",
    )
    selected = variant(plan, expected_variant)
    material = dict(record)
    record_id = material.pop("record_id", None)
    if (
        record["schema_version"] != BUILD_SCHEMA_VERSION
        or record["plan_id"] != plan["plan_id"]
        or record["plan_sha256"] != plan_sha256
        or record["variant_name"] != expected_variant
        or record["variant_id"] != selected["variant_id"]
        or record["source_identity"] != plan["source_identity"]
        or record["build_identity_id"] != plan["environment"]["build_identity_id"]
        or record["environment_id"] != plan["environment"]["environment_id"]
        or type(record["elapsed_nanoseconds"]) is not int
        or record["elapsed_nanoseconds"] < 0
        or type(record_id) is not str
        or record_id != build_experiment._json_sha256(material)
    ):
        raise CandidateControlError("UDP headroom build record identity is invalid")
    expected_command = {
        "argv": selected["argv"],
        "environment_overrides": selected["environment_overrides"],
        "repository": selected["repository"],
        "target_dir": selected["target_dir"],
    }
    if record["command"] != expected_command:
        raise CandidateControlError("UDP headroom build command changed")
    artifacts = record["artifacts"]
    if type(artifacts) is not list or len(artifacts) != len(ARTIFACT_NAMES):
        raise CandidateControlError("UDP headroom artifact set is incomplete")
    observed: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise CandidateControlError("UDP headroom artifact must be an object")
        _exact_fields(
            artifact,
            frozenset({"name", "path", "sha256", "size_bytes"}),
            "UDP headroom artifact",
        )
        name = artifact["name"]
        path_value = artifact["path"]
        if (
            name not in ARTIFACT_NAMES
            or name in observed
            or type(path_value) is not str
            or pathlib.Path(path_value).resolve()
            != pathlib.Path(selected["artifact_paths"][name]).resolve()
            or type(artifact["sha256"]) is not str
            or SHA256.fullmatch(artifact["sha256"]) is None
            or type(artifact["size_bytes"]) is not int
            or artifact["size_bytes"] <= 0
        ):
            raise CandidateControlError("UDP headroom artifact identity is invalid")
        artifact_path = pathlib.Path(path_value)
        if (
            not artifact_path.is_file()
            or artifact_path.is_symlink()
            or artifact_path.stat().st_size != artifact["size_bytes"]
            or build_experiment._file_sha256(
                artifact_path, field=f"headroom artifact {name}"
            )
            != artifact["sha256"]
        ):
            raise CandidateControlError("UDP headroom artifact changed after build")
        observed[name] = artifact
    if tuple(observed) != ARTIFACT_NAMES:
        raise CandidateControlError("UDP headroom artifact roles changed")
    return record, bounded.sha256


def artifact_map(record: dict[str, object]) -> dict[str, dict[str, object]]:
    return {row["name"]: row for row in record["artifacts"]}


def materialize(
    *,
    plan_path: pathlib.Path,
    build_path: pathlib.Path,
    variant_name: str,
    destination: pathlib.Path,
) -> dict[str, object]:
    plan, plan_sha256 = load_plan(plan_path)
    record, record_sha256 = load_build_record(
        build_path,
        plan=plan,
        plan_sha256=plan_sha256,
        expected_variant=variant_name,
    )
    selected = variant(plan, variant_name)
    repository = pathlib.Path(selected["repository"]).resolve()
    expected = repository / (
        "target/profiling" if selected["timed"] else "target/udp-worker/profiling"
    )
    destination_absolute = destination.absolute()
    expected_absolute = expected.absolute()
    ancestor = repository
    for part in expected_absolute.relative_to(repository).parts:
        ancestor /= part
        if ancestor.is_symlink():
            raise CandidateControlError(
                "UDP headroom materialization destination contains a symlink"
            )
    if destination_absolute != expected_absolute:
        raise CandidateControlError(
            "UDP headroom materialization destination is invalid"
        )
    destination = destination_absolute.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        raise CandidateControlError(
            "UDP headroom materialization destination is unavailable"
        )
    unexpected = {
        path.name
        for path in destination.iterdir()
        if path.name not in ARTIFACT_NAMES or path.is_dir() or path.is_symlink()
    }
    if unexpected:
        raise CandidateControlError(
            "UDP headroom materialization destination is not closed"
        )
    staged = []
    artifacts = artifact_map(record)
    for name in ARTIFACT_NAMES:
        source = pathlib.Path(artifacts[name]["path"])
        temporary = destination / f".{name}.udp-headroom.tmp"
        target = destination / name
        if temporary.exists() or temporary.is_symlink():
            raise CandidateControlError(
                "UDP headroom materialization temporary path exists"
            )
        try:
            shutil.copyfile(source, temporary)
            temporary.chmod(
                temporary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
            os.replace(temporary, target)
        except OSError as error:
            raise CandidateControlError(
                "UDP headroom artifact materialization failed"
            ) from error
        digest = build_experiment._file_sha256(
            target, field=f"materialized headroom {name}"
        )
        if (
            target.is_symlink()
            or target.stat().st_size != artifacts[name]["size_bytes"]
            or digest != artifacts[name]["sha256"]
        ):
            raise CandidateControlError(
                "UDP headroom materialized artifact does not match its record"
            )
        staged.append(
            {
                "name": name,
                "path": str(target),
                "sha256": digest,
                "size_bytes": target.stat().st_size,
            }
        )
    return {
        "artifacts": staged,
        "build_record_id": record["record_id"],
        "build_record_sha256": record_sha256,
        "destination": str(destination),
        "plan_id": plan["plan_id"],
        "variant_id": selected["variant_id"],
        "variant_name": variant_name,
    }
