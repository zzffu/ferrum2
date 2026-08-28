"""Reproducible build experiment manifests and measurement records."""

from __future__ import annotations

import argparse
import collections
import csv
import datetime
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence

from tools.performance_candidate.identity import validate_git_relation
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _canonical_json_bytes,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.output import _atomic_text

ENVIRONMENT_SCHEMA_VERSION = "ferrum2-build-environment-v1"
WORKLOAD_SCHEMA_VERSION = "ferrum2-build-workload-set-v1"
PLAN_SCHEMA_VERSION = "ferrum2-build-experiment-plan-v1"
RECORD_SCHEMA_VERSION = "ferrum2-build-experiment-record-v1"
COMMANDS = frozenset(
    {
        "build-environment",
        "build-experiment-plan",
        "build-experiment-run",
    }
)
EXPERIMENT_KINDS = (
    "thin-lto-cgu1",
    "target-cpu",
    "pgo",
    "panic-abort-strip",
)
ENVIRONMENT_KINDS = ("github-hosted", "self-hosted", "stable-bare-metal")
PINNED_RUST_RELEASE = "1.97.1"
MAX_JSON_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_BACKGROUND_PROCESSES = 32_768
MAX_PROCESS_KINDS = 64
MAX_ARTIFACTS = 32
GIT_OBJECT = re.compile(r"[0-9a-f]{40,64}")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
SAFE_TARGET_CPU = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}")
PGO_TRAINING_CATEGORIES = frozenset(
    {"tcp-request", "tcp-bulk", "udp-small", "udp-mtu", "dns", "rule"}
)
WORKLOAD_CATEGORIES = PGO_TRAINING_CATEGORIES | {"startup"}
VALIDATION_COVERAGE = frozenset(
    {"representative", "cold-path", "error-path", "different-cpu"}
)
CONTROLLED_ENVIRONMENT_REMOVALS = (
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
)
CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS = (
    "CARGO_PROFILE_",
    "CARGO_TARGET_",
)


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _file_sha256(path: pathlib.Path, *, field: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise CandidateControlError(f"unable to hash {field}") from error
    return digest.hexdigest()


def _bounded_command(
    argv: Sequence[str], *, cwd: pathlib.Path | None = None
) -> tuple[int, str]:
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                list(argv),
                cwd=cwd,
                check=False,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
            size = output.tell()
            if size > MAX_COMMAND_OUTPUT_BYTES:
                raise CandidateControlError(
                    f"command output exceeds {MAX_COMMAND_OUTPUT_BYTES} bytes"
                )
            output.seek(0)
            raw = output.read()
    except CandidateControlError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CandidateControlError(
            f"unable to run identity command: {argv[0]}"
        ) from error
    return result.returncode, raw.decode("utf-8", errors="replace").strip()


def _required_command_output(
    argv: Sequence[str], *, cwd: pathlib.Path | None = None, name: str
) -> str:
    returncode, output = _bounded_command(argv, cwd=cwd)
    if returncode != 0 or not output:
        raise CandidateControlError(f"unable to capture {name}")
    return output


def _bounded_text(
    path: pathlib.Path, *, maximum_bytes: int = 1024 * 1024
) -> str | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(maximum_bytes + 1)
    except OSError:
        return None
    if len(raw) > maximum_bytes:
        return None
    return raw.decode("utf-8", errors="replace")


def _probe_value(value: str | None, source: str) -> dict[str, object]:
    if value is None or not value.strip():
        return {"source": source, "status": "unavailable", "value": None}
    return {"source": source, "status": "captured", "value": value.strip()}


def _linux_cpu_identity() -> tuple[dict[str, object], dict[str, object]]:
    source = "/proc/cpuinfo"
    cpuinfo = _bounded_text(pathlib.Path(source))
    model: str | None = None
    microcode: str | None = None
    if cpuinfo is not None:
        for line in cpuinfo.splitlines():
            field, separator, value = line.partition(":")
            if not separator:
                continue
            if field.strip() in {"model name", "Hardware"} and model is None:
                model = value.strip()
            if field.strip() == "microcode" and microcode is None:
                microcode = value.strip()
            if model is not None and microcode is not None:
                break
    return _probe_value(model, source), _probe_value(microcode, source)


def _linux_governors() -> dict[str, object]:
    root = pathlib.Path("/sys/devices/system/cpu")
    paths: list[pathlib.Path] = []
    try:
        for path in root.glob("cpu[0-9]*/cpufreq/scaling_governor"):
            if len(paths) == 4096:
                return {
                    "source": str(root),
                    "status": "unavailable",
                    "values": [],
                }
            paths.append(path)
    except OSError:
        paths = []
    values = sorted(
        {
            value.strip()
            for path in paths
            if (value := _bounded_text(path, maximum_bytes=256)) is not None
            and value.strip()
        }
    )
    return {
        "source": str(root),
        "status": "captured" if values else "unavailable",
        "values": values,
    }


def _expand_linux_node_set(value: str) -> list[int] | None:
    nodes: set[int] = set()
    try:
        for item in value.strip().split(","):
            if not item:
                return None
            start_text, separator, end_text = item.partition("-")
            start = int(start_text, 10)
            end = int(end_text, 10) if separator else start
            if start < 0 or end < start or end - start > 4096:
                return None
            nodes.update(range(start, end + 1))
            if len(nodes) > 4096:
                return None
    except ValueError:
        return None
    return sorted(nodes)


def _linux_numa() -> dict[str, object]:
    source = "/sys/devices/system/node/online"
    value = _bounded_text(pathlib.Path(source), maximum_bytes=256)
    nodes = None if value is None else _expand_linux_node_set(value)
    return {
        "online_nodes": [] if nodes is None else nodes,
        "source": source,
        "status": "unavailable" if nodes is None else "captured",
    }


def _background_process_names(system: str) -> tuple[list[str], bool, str]:
    if system == "Linux":
        names: list[str] = []
        truncated = False
        source = "/proc/*/comm"
        try:
            paths = pathlib.Path("/proc").glob("[0-9]*/comm")
            for path in paths:
                if len(names) == MAX_BACKGROUND_PROCESSES:
                    truncated = True
                    break
                value = _bounded_text(path, maximum_bytes=512)
                if value is not None and value.strip():
                    names.append(value.strip())
        except OSError:
            return [], False, source
        return names, truncated, source
    if system == "Windows":
        returncode, output = _bounded_command(("tasklist", "/fo", "csv", "/nh"))
        if returncode != 0:
            return [], False, "tasklist"
        rows = csv.reader(io.StringIO(output))
        names = [row[0].strip() for row in rows if row and row[0].strip()]
        return (
            names[:MAX_BACKGROUND_PROCESSES],
            len(names) > MAX_BACKGROUND_PROCESSES,
            "tasklist",
        )
    return [], False, "unsupported-platform"


def _process_summary(system: str) -> dict[str, object]:
    names, truncated, source = _background_process_names(system)
    counts = collections.Counter(names)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    full_counts = [
        {"instances": count, "name": name} for name, count in sorted(counts.items())
    ]
    return {
        "distinct_names": len(counts),
        "snapshot_sha256": _json_sha256(full_counts) if names else None,
        "source": source,
        "status": "captured" if names else "unavailable",
        "top": [
            {"instances": count, "name": name}
            for name, count in ordered[:MAX_PROCESS_KINDS]
        ],
        "total_processes": len(names),
        "truncated": truncated,
    }


def _capture_machine_identity() -> tuple[dict[str, object], dict[str, object]]:
    system = platform.system() or "unknown"
    if system == "Linux":
        cpu_model, microcode = _linux_cpu_identity()
        governor = _linux_governors()
        numa = _linux_numa()
    else:
        cpu_model = _probe_value(platform.processor() or None, "platform.processor")
        microcode = _probe_value(None, "unsupported-platform")
        governor = {
            "source": "unsupported-platform",
            "status": "unavailable",
            "values": [],
        }
        numa = {
            "online_nodes": [],
            "source": "unsupported-platform",
            "status": "unavailable",
        }
    machine = {
        "architecture": platform.machine() or "unknown",
        "cpu_model": cpu_model,
        "frequency_governor": governor,
        "kernel": platform.release() or "unknown",
        "microcode": microcode,
        "numa": numa,
        "operating_system": system,
        "operating_system_version": platform.version() or "unknown",
    }
    return machine, _process_summary(system)


def _manifest_digests(repository: pathlib.Path) -> dict[str, str]:
    paths = {
        "cargo_lock_sha256": repository / "Cargo.lock",
        "cargo_manifest_sha256": repository / "Cargo.toml",
        "rust_toolchain_sha256": repository / "rust-toolchain.toml",
    }
    return {field: _file_sha256(path, field=field) for field, path in paths.items()}


def capture_environment(
    *,
    repository: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
    run_kind: str,
    environment_kind: str,
    runner_image: str,
) -> dict[str, object]:
    repository = repository.resolve()
    if environment_kind not in ENVIRONMENT_KINDS:
        raise CandidateControlError("environment_kind is invalid")
    if not runner_image.strip() or len(runner_image) > 256:
        raise CandidateControlError("runner_image must be a bounded non-empty string")
    parent, candidate = validate_git_relation(
        repository, parent_sha, candidate_sha, run_kind=run_kind
    )
    root = _required_command_output(
        ("git", "rev-parse", "--show-toplevel"), cwd=repository, name="repository root"
    )
    if pathlib.Path(root).resolve() != repository:
        raise CandidateControlError("repository must name the worktree root")
    head = _required_command_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, name="worktree HEAD"
    ).lower()
    if head != candidate:
        raise CandidateControlError(
            "candidate_sha must be the checked-out worktree HEAD"
        )
    status_returncode, status = _bounded_command(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=repository,
    )
    if status_returncode != 0:
        raise CandidateControlError("unable to capture worktree status")
    if status:
        raise CandidateControlError("build experiments require a clean worktree")
    parent_tree = _required_command_output(
        ("git", "rev-parse", f"{parent}^{{tree}}"),
        cwd=repository,
        name="parent tree",
    ).lower()
    candidate_tree = _required_command_output(
        ("git", "rev-parse", f"{candidate}^{{tree}}"),
        cwd=repository,
        name="candidate tree",
    ).lower()
    if (
        GIT_OBJECT.fullmatch(parent_tree) is None
        or GIT_OBJECT.fullmatch(candidate_tree) is None
    ):
        raise CandidateControlError("Git tree identity is invalid")
    rustc_verbose = _required_command_output(("rustc", "-vV"), name="rustc identity")
    release_lines = [
        line.removeprefix("release:").strip()
        for line in rustc_verbose.splitlines()
        if line.startswith("release:")
    ]
    if release_lines != [PINNED_RUST_RELEASE]:
        raise CandidateControlError(
            f"rustc release must be the pinned {PINNED_RUST_RELEASE}"
        )
    cargo_version = _required_command_output(("cargo", "-V"), name="cargo identity")
    source_identity = {
        "candidate_sha": candidate,
        "candidate_tree": candidate_tree,
        "parent_sha": parent,
        "parent_tree": parent_tree,
        "run_kind": run_kind,
        "worktree_clean": True,
    }
    build_identity = {
        "cargo_version": cargo_version,
        "locked_dependencies": True,
        **_manifest_digests(repository),
        "profile": "profiling",
        "rust_release": PINNED_RUST_RELEASE,
        "rustc_verbose": rustc_verbose,
    }
    machine_identity, background = _capture_machine_identity()
    environment_material = {
        "environment_kind": environment_kind,
        "machine_identity": machine_identity,
        "runner_image": runner_image,
    }
    build_material = {
        "build_identity": build_identity,
        "source_identity": source_identity,
    }
    return {
        "background_process_snapshot": background,
        "build_identity": build_identity,
        "build_identity_id": _json_sha256(build_material),
        "captured_at_utc": _utc_now(),
        "environment_id": _json_sha256(environment_material),
        "environment_kind": environment_kind,
        "machine_identity": machine_identity,
        "repository": str(repository),
        "runner_image": runner_image,
        "schema_version": ENVIRONMENT_SCHEMA_VERSION,
        "source_identity": source_identity,
    }


def _load_environment(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MAX_JSON_BYTES, source="build environment"
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("build environment must be a JSON object")
    _exact_fields(
        row,
        frozenset(
            {
                "background_process_snapshot",
                "build_identity",
                "build_identity_id",
                "captured_at_utc",
                "environment_id",
                "environment_kind",
                "machine_identity",
                "repository",
                "runner_image",
                "schema_version",
                "source_identity",
            }
        ),
        "build environment",
    )
    if row["schema_version"] != ENVIRONMENT_SCHEMA_VERSION:
        raise CandidateControlError("build environment schema_version is invalid")
    if row["environment_kind"] not in ENVIRONMENT_KINDS:
        raise CandidateControlError("build environment_kind is invalid")
    if (
        type(row["runner_image"]) is not str
        or not row["runner_image"]
        or type(row["repository"]) is not str
        or not row["repository"]
        or type(row["captured_at_utc"]) is not str
        or not row["captured_at_utc"]
    ):
        raise CandidateControlError("build environment scalar identity is invalid")
    source_identity = row["source_identity"]
    build_identity = row["build_identity"]
    machine_identity = row["machine_identity"]
    background = row["background_process_snapshot"]
    if type(source_identity) is not dict:
        raise CandidateControlError("build source_identity is invalid")
    _exact_fields(
        source_identity,
        frozenset(
            {
                "candidate_sha",
                "candidate_tree",
                "parent_sha",
                "parent_tree",
                "run_kind",
                "worktree_clean",
            }
        ),
        "build source_identity",
    )
    if (
        type(source_identity["candidate_sha"]) is not str
        or COMMIT_SHA.fullmatch(source_identity["candidate_sha"]) is None
        or type(source_identity["parent_sha"]) is not str
        or COMMIT_SHA.fullmatch(source_identity["parent_sha"]) is None
        or type(source_identity["candidate_tree"]) is not str
        or GIT_OBJECT.fullmatch(source_identity["candidate_tree"]) is None
        or type(source_identity["parent_tree"]) is not str
        or GIT_OBJECT.fullmatch(source_identity["parent_tree"]) is None
        or source_identity["run_kind"] not in {"comparison", "calibration-aa"}
        or source_identity["worktree_clean"] is not True
    ):
        raise CandidateControlError("build source_identity values are invalid")
    if type(build_identity) is not dict:
        raise CandidateControlError("build build_identity is invalid")
    _exact_fields(
        build_identity,
        frozenset(
            {
                "cargo_lock_sha256",
                "cargo_manifest_sha256",
                "cargo_version",
                "locked_dependencies",
                "profile",
                "rust_release",
                "rust_toolchain_sha256",
                "rustc_verbose",
            }
        ),
        "build build_identity",
    )
    if (
        build_identity["locked_dependencies"] is not True
        or build_identity["profile"] != "profiling"
        or build_identity["rust_release"] != PINNED_RUST_RELEASE
        or any(
            type(build_identity[field]) is not str
            or SHA256.fullmatch(build_identity[field]) is None
            for field in (
                "cargo_lock_sha256",
                "cargo_manifest_sha256",
                "rust_toolchain_sha256",
            )
        )
        or type(build_identity["cargo_version"]) is not str
        or not build_identity["cargo_version"]
        or type(build_identity["rustc_verbose"]) is not str
        or not build_identity["rustc_verbose"]
    ):
        raise CandidateControlError("build build_identity values are invalid")
    if type(machine_identity) is not dict or type(background) is not dict:
        raise CandidateControlError("build machine capture is invalid")
    _exact_fields(
        machine_identity,
        frozenset(
            {
                "architecture",
                "cpu_model",
                "frequency_governor",
                "kernel",
                "microcode",
                "numa",
                "operating_system",
                "operating_system_version",
            }
        ),
        "build machine_identity",
    )
    _exact_fields(
        background,
        frozenset(
            {
                "distinct_names",
                "snapshot_sha256",
                "source",
                "status",
                "top",
                "total_processes",
                "truncated",
            }
        ),
        "build background_process_snapshot",
    )
    for field in ("cpu_model", "microcode"):
        probe = machine_identity[field]
        if type(probe) is not dict:
            raise CandidateControlError(f"build machine_identity {field} is invalid")
        _exact_fields(
            probe,
            frozenset({"source", "status", "value"}),
            f"build machine_identity {field}",
        )
    governor = machine_identity["frequency_governor"]
    numa = machine_identity["numa"]
    if type(governor) is not dict or type(numa) is not dict:
        raise CandidateControlError("build machine topology capture is invalid")
    _exact_fields(
        governor,
        frozenset({"source", "status", "values"}),
        "build frequency_governor",
    )
    _exact_fields(
        numa,
        frozenset({"online_nodes", "source", "status"}),
        "build numa",
    )
    for field in ("environment_id", "build_identity_id"):
        if type(row[field]) is not str or SHA256.fullmatch(row[field]) is None:
            raise CandidateControlError(f"build environment {field} is invalid")
    environment_material = {
        "environment_kind": row["environment_kind"],
        "machine_identity": row["machine_identity"],
        "runner_image": row["runner_image"],
    }
    build_material = {
        "build_identity": row["build_identity"],
        "source_identity": row["source_identity"],
    }
    if row["environment_id"] != _json_sha256(environment_material):
        raise CandidateControlError("build environment_id does not reconstruct")
    if row["build_identity_id"] != _json_sha256(build_material):
        raise CandidateControlError("build build_identity_id does not reconstruct")
    return row, bounded.sha256


def _require_relative_directory(value: object, field: str) -> str:
    if type(value) is not str or not value or len(value) > 512 or "\x00" in value:
        raise CandidateControlError(f"{field} must be a bounded relative directory")
    path = pathlib.PurePath(value)
    if path.is_absolute() or ".." in path.parts:
        raise CandidateControlError(f"{field} must stay within the repository")
    return value


def _require_argv(value: object, field: str) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= 64:
        raise CandidateControlError(f"{field} must contain 1 to 64 arguments")
    if any(
        type(argument) is not str
        or not argument
        or len(argument) > 4096
        or "\x00" in argument
        for argument in value
    ):
        raise CandidateControlError(f"{field} contains an invalid argument")
    return list(value)


def _load_workload_set(
    path: pathlib.Path, *, expected_role: str
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MAX_JSON_BYTES, source=f"{expected_role} workload set"
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError(f"{expected_role} workload set must be an object")
    _exact_fields(
        row,
        frozenset({"role", "scenarios", "schema_version"}),
        f"{expected_role} workload set",
    )
    if row["schema_version"] != WORKLOAD_SCHEMA_VERSION or row["role"] != expected_role:
        raise CandidateControlError(f"{expected_role} workload identity is invalid")
    scenarios = row["scenarios"]
    if type(scenarios) is not list or not 1 <= len(scenarios) <= 64:
        raise CandidateControlError(
            f"{expected_role} workloads must contain 1 to 64 scenarios"
        )
    names: set[str] = set()
    total_weight = 0
    for index, scenario in enumerate(scenarios):
        name = f"{expected_role} scenario {index}"
        if type(scenario) is not dict:
            raise CandidateControlError(f"{name} must be an object")
        _exact_fields(
            scenario,
            frozenset(
                {
                    "argv",
                    "category",
                    "coverage",
                    "name",
                    "platforms",
                    "weight_basis_points",
                    "working_directory",
                }
            ),
            name,
        )
        scenario_name = scenario["name"]
        if type(scenario_name) is not str or SAFE_NAME.fullmatch(scenario_name) is None:
            raise CandidateControlError(f"{name} name is invalid")
        if scenario_name in names:
            raise CandidateControlError(f"duplicate {expected_role} scenario name")
        names.add(scenario_name)
        if scenario["category"] not in WORKLOAD_CATEGORIES:
            raise CandidateControlError(f"{name} category is invalid")
        _require_argv(scenario["argv"], f"{name} argv")
        _require_relative_directory(
            scenario["working_directory"], f"{name} working_directory"
        )
        platforms = scenario["platforms"]
        if (
            type(platforms) is not list
            or not 1 <= len(platforms) <= 16
            or any(
                type(item) is not str or SAFE_NAME.fullmatch(item) is None
                for item in platforms
            )
            or len(set(platforms)) != len(platforms)
        ):
            raise CandidateControlError(f"{name} platforms are invalid")
        weight = scenario["weight_basis_points"]
        if expected_role == "training":
            if type(weight) is not int or not 1 <= weight <= 10_000:
                raise CandidateControlError(f"{name} training weight is invalid")
            if scenario["coverage"] != "steady-state":
                raise CandidateControlError(f"{name} training coverage is invalid")
            total_weight += weight
        else:
            if weight is not None:
                raise CandidateControlError(f"{name} validation weight must be null")
            if scenario["coverage"] not in VALIDATION_COVERAGE:
                raise CandidateControlError(f"{name} validation coverage is invalid")
    if expected_role == "training" and total_weight != 10_000:
        raise CandidateControlError("training weights must total 10000 basis points")
    return row, bounded.sha256


def _workload_reference(
    path: pathlib.Path, row: dict[str, object], digest: str
) -> dict[str, object]:
    return {
        "path": str(path.resolve()),
        "scenarios": [scenario["name"] for scenario in row["scenarios"]],
        "sha256": digest,
    }


def _artifact_names(values: Sequence[str]) -> list[str]:
    if not 1 <= len(values) <= MAX_ARTIFACTS:
        raise CandidateControlError(
            f"artifact names must contain 1 to {MAX_ARTIFACTS} values"
        )
    if any(SAFE_NAME.fullmatch(value) is None for value in values):
        raise CandidateControlError("artifact name must be a plain file name")
    if len(set(values)) != len(values):
        raise CandidateControlError("artifact names must be unique")
    return sorted(values)


def _build_phase(
    *,
    name: str,
    profile: str,
    repository: pathlib.Path,
    target_dir: pathlib.Path,
    target_triple: str | None,
    artifact_names: Sequence[str],
    encoded_rustflags: Sequence[str] = (),
) -> dict[str, object]:
    argv = [
        "cargo",
        "build",
        "--workspace",
        "--bins",
        "--locked",
        "--profile",
        profile,
        "--target-dir",
        str(target_dir),
    ]
    artifact_root = pathlib.PurePath(profile)
    if target_triple is not None:
        argv.extend(("--target", target_triple))
        artifact_root = pathlib.PurePath(target_triple) / artifact_root
    overrides = {"CARGO_INCREMENTAL": "0", "RUSTUP_TOOLCHAIN": PINNED_RUST_RELEASE}
    if encoded_rustflags:
        overrides["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(encoded_rustflags)
    return {
        "artifacts": [str(artifact_root / artifact) for artifact in artifact_names],
        "argv": argv,
        "environment_overrides": overrides,
        "name": name,
        "phase_type": "build",
        "profile": profile,
        "repository": str(repository),
        "target_dir": str(target_dir),
    }


def _phase_target(root: pathlib.Path, name: str) -> pathlib.Path:
    return (root / name).resolve()


def _pgo_workload_commands(
    *,
    workload_set: dict[str, object],
    workload_sha256: str,
    phase: dict[str, object],
    artifact_names: Sequence[str],
    variant: str,
) -> list[dict[str, object]]:
    target_dir = pathlib.Path(phase["target_dir"]).resolve()
    artifact_map = {
        f"{{artifact:{name}}}": str((target_dir / relative).resolve())
        for name, relative in zip(artifact_names, phase["artifacts"], strict=True)
    }
    repository = pathlib.Path(phase["repository"]).resolve()
    commands: list[dict[str, object]] = []
    for scenario in workload_set["scenarios"]:
        used_tokens = {
            argument for argument in scenario["argv"] if argument in artifact_map
        }
        unknown_tokens = [
            argument
            for argument in scenario["argv"]
            if argument.startswith("{artifact:") and argument not in artifact_map
        ]
        if not used_tokens or unknown_tokens:
            raise CandidateControlError(
                f"PGO scenario {scenario['name']} must use a known artifact token"
            )
        working_directory = (repository / scenario["working_directory"]).resolve()
        if (
            not working_directory.is_relative_to(repository)
            or not working_directory.is_dir()
        ):
            raise CandidateControlError(
                f"PGO scenario {scenario['name']} working directory is unavailable"
            )
        command = {
            "argv": [
                artifact_map.get(argument, argument) for argument in scenario["argv"]
            ],
            "build_phase": phase["name"],
            "category": scenario["category"],
            "coverage": scenario["coverage"],
            "name": scenario["name"],
            "platforms": scenario["platforms"],
            "variant": variant,
            "weight_basis_points": scenario["weight_basis_points"],
            "working_directory": str(working_directory),
            "workload_set_sha256": workload_sha256,
        }
        commands.append({**command, "command_id": _json_sha256(command)})
    return commands


def create_experiment_plan(
    *,
    environment_path: pathlib.Path,
    validation_workloads_path: pathlib.Path,
    kind: str,
    target_root: pathlib.Path,
    artifact_names: Sequence[str],
    target_triple: str | None = None,
    training_workloads_path: pathlib.Path | None = None,
    target_cpu: str | None = None,
    deployment_id: str | None = None,
    acknowledge_nonportable: bool = False,
    llvm_profdata: pathlib.Path | None = None,
) -> dict[str, object]:
    if kind not in EXPERIMENT_KINDS:
        raise CandidateControlError("build experiment kind is invalid")
    environment, environment_sha256 = _load_environment(environment_path)
    repository_value = environment["repository"]
    if type(repository_value) is not str:
        raise CandidateControlError("build environment repository is invalid")
    repository = pathlib.Path(repository_value).resolve()
    if not repository.is_dir():
        raise CandidateControlError("build environment repository is unavailable")
    validation, validation_sha256 = _load_workload_set(
        validation_workloads_path, expected_role="validation"
    )
    validation_categories = {
        scenario["category"] for scenario in validation["scenarios"]
    }
    artifacts = _artifact_names(artifact_names)
    if target_triple is not None and SAFE_NAME.fullmatch(target_triple) is None:
        raise CandidateControlError("target_triple is invalid")
    target_root = target_root.resolve()
    phases = [
        _build_phase(
            name="baseline",
            profile="profiling",
            repository=repository,
            target_dir=_phase_target(target_root, "baseline"),
            target_triple=target_triple,
            artifact_names=artifacts,
        )
    ]
    pgo: dict[str, object] | None = None
    portability: dict[str, object] = {
        "deployment_id": None,
        "general_distribution_baseline_unchanged": True,
        "nonportable_opt_in": False,
        "target_cpu": None,
    }
    if kind in {"thin-lto-cgu1", "target-cpu"}:
        if not (
            validation_categories & {"tcp-request", "tcp-bulk"}
            and validation_categories & {"udp-small", "udp-mtu"}
        ):
            raise CandidateControlError(
                "ThinLTO and target-cpu validation must record TCP and UDP workloads"
            )
    if kind == "panic-abort-strip" and "startup" not in validation_categories:
        raise CandidateControlError(
            "panic-abort-strip validation must include a startup workload"
        )
    candidate_flags: tuple[str, ...] = ()
    candidate_profile = {
        "thin-lto-cgu1": "performance-thin-lto",
        "target-cpu": "profiling",
        "panic-abort-strip": "performance-panic-abort-strip",
    }.get(kind)
    if kind == "target-cpu":
        if (
            target_cpu is None
            or SAFE_TARGET_CPU.fullmatch(target_cpu) is None
            or target_cpu == "native"
        ):
            raise CandidateControlError(
                "target-cpu requires an explicit named CPU; native is not reproducible"
            )
        if (
            not acknowledge_nonportable
            or deployment_id is None
            or SAFE_NAME.fullmatch(deployment_id) is None
        ):
            raise CandidateControlError(
                "target-cpu requires a fixed deployment_id and nonportable acknowledgement"
            )
        candidate_flags = (f"-Ctarget-cpu={target_cpu}",)
        portability = {
            "deployment_id": deployment_id,
            "general_distribution_baseline_unchanged": True,
            "nonportable_opt_in": True,
            "target_cpu": target_cpu,
        }
    elif target_cpu is not None or deployment_id is not None or acknowledge_nonportable:
        raise CandidateControlError("target-cpu options are valid only for target-cpu")
    if kind == "pgo":
        if training_workloads_path is None or llvm_profdata is None:
            raise CandidateControlError(
                "PGO requires separate training workloads and llvm-profdata"
            )
        training, training_sha256 = _load_workload_set(
            training_workloads_path, expected_role="training"
        )
        training_categories = {
            scenario["category"] for scenario in training["scenarios"]
        }
        if not PGO_TRAINING_CATEGORIES <= training_categories:
            missing = sorted(PGO_TRAINING_CATEGORIES - training_categories)
            raise CandidateControlError(
                f"PGO training categories are missing: {missing}"
            )
        training_names = {scenario["name"] for scenario in training["scenarios"]}
        validation_names = {scenario["name"] for scenario in validation["scenarios"]}
        if training_names & validation_names:
            raise CandidateControlError(
                "PGO training and validation names must be disjoint"
            )
        validation_coverage = {
            scenario["coverage"] for scenario in validation["scenarios"]
        }
        if validation_coverage != VALIDATION_COVERAGE:
            missing = sorted(VALIDATION_COVERAGE - validation_coverage)
            raise CandidateControlError(
                f"PGO validation coverage is missing: {missing}"
            )
        llvm_profdata = llvm_profdata.resolve()
        if not llvm_profdata.is_file():
            raise CandidateControlError("llvm-profdata must be an existing file")
        raw_directory = _phase_target(target_root, "pgo-data") / "raw"
        merged_file = _phase_target(target_root, "pgo-data") / "merged.profdata"
        generate_phase = _build_phase(
            name="pgo-generate",
            profile="profiling",
            repository=repository,
            target_dir=_phase_target(target_root, "pgo-generate"),
            target_triple=target_triple,
            artifact_names=artifacts,
            encoded_rustflags=(f"-Cprofile-generate={raw_directory}",),
        )
        merge_phase = {
            "artifacts": [str(merged_file.relative_to(target_root))],
            "argv": [
                str(llvm_profdata),
                "merge",
                "-o",
                str(merged_file),
                str(raw_directory),
            ],
            "environment_overrides": {},
            "name": "pgo-merge",
            "phase_type": "profile-merge",
            "profile": None,
            "repository": str(repository),
            "target_dir": str(target_root),
        }
        use_phase = _build_phase(
            name="pgo-use",
            profile="profiling",
            repository=repository,
            target_dir=_phase_target(target_root, "pgo-use"),
            target_triple=target_triple,
            artifact_names=artifacts,
            encoded_rustflags=(
                f"-Cprofile-use={merged_file}",
                "-Cllvm-args=-pgo-warn-missing-function",
            ),
        )
        phases.extend((generate_phase, merge_phase, use_phase))
        pgo = {
            "execution_order": [
                "baseline",
                "pgo-generate",
                "external-training-workloads",
                "pgo-merge",
                "pgo-use",
                "external-validation-workloads",
            ],
            "llvm_profdata": {
                "path": str(llvm_profdata),
                "sha256": _file_sha256(llvm_profdata, field="llvm-profdata"),
            },
            "merged_profile": str(merged_file),
            "profile_input_contract": {
                "generate_requires_empty_raw_directory": True,
                "merge_requires_nonempty_profraw_set": True,
                "use_records_merged_profile_sha256": True,
            },
            "raw_profile_directory": str(raw_directory),
            "training_commands": _pgo_workload_commands(
                workload_set=training,
                workload_sha256=training_sha256,
                phase=generate_phase,
                artifact_names=artifacts,
                variant="instrumented-training",
            ),
            "training_workloads": _workload_reference(
                training_workloads_path, training, training_sha256
            ),
            "validation_commands": [
                *_pgo_workload_commands(
                    workload_set=validation,
                    workload_sha256=validation_sha256,
                    phase=phases[0],
                    artifact_names=artifacts,
                    variant="baseline-validation",
                ),
                *_pgo_workload_commands(
                    workload_set=validation,
                    workload_sha256=validation_sha256,
                    phase=use_phase,
                    artifact_names=artifacts,
                    variant="pgo-validation",
                ),
            ],
        }
    else:
        if training_workloads_path is not None or llvm_profdata is not None:
            raise CandidateControlError("PGO options are valid only for PGO")
        assert candidate_profile is not None
        phases.append(
            _build_phase(
                name=kind,
                profile=candidate_profile,
                repository=repository,
                target_dir=_phase_target(target_root, kind),
                target_triple=target_triple,
                artifact_names=artifacts,
                encoded_rustflags=candidate_flags,
            )
        )
    plan_without_id = {
        "controlled_environment_prefix_removals": list(
            CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS
        ),
        "controlled_environment_removals": list(CONTROLLED_ENVIRONMENT_REMOVALS),
        "environment": {
            "build_identity_id": environment["build_identity_id"],
            "environment_id": environment["environment_id"],
            "path": str(environment_path.resolve()),
            "sha256": environment_sha256,
        },
        "evidence_contract": {
            "cross_environment_mixing_forbidden": True,
            "performance_conclusions_recorded": False,
            "required_raw_artifact_kinds": [
                "allocator",
                "perf-stat",
                "raw-jsonl",
                "rss",
                "summary",
            ],
            "single_scenario_adoption_forbidden": True,
            "tcp_scale_10k_required_fields": [
                "fairness",
                "merged_per_connection_growth",
                "page_touched",
                "per_process_per_connection_growth",
            ],
        },
        "experiment_kind": kind,
        "generated_at_utc": _utc_now(),
        "operational_review": {
            "panic_backtrace_and_crash_diagnostics_review_required": (
                kind == "panic-abort-strip"
            ),
            "size_and_startup_are_primary": kind == "panic-abort-strip",
        },
        "pgo": pgo,
        "phases": phases,
        "portability": portability,
        "schema_version": PLAN_SCHEMA_VERSION,
        "target_triple": target_triple,
        "validation_workloads": _workload_reference(
            validation_workloads_path, validation, validation_sha256
        ),
    }
    plan_id_material = dict(plan_without_id)
    plan_id_material.pop("generated_at_utc")
    plan = {**plan_without_id, "plan_id": _json_sha256(plan_id_material)}
    if len(_canonical_json_bytes(plan)) > MAX_JSON_BYTES:
        raise CandidateControlError(
            "generated build experiment plan exceeds its size bound"
        )
    return plan


def _load_plan(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MAX_JSON_BYTES, source="build experiment plan"
    )
    plan = bounded.value
    if type(plan) is not dict:
        raise CandidateControlError("build experiment plan must be an object")
    _exact_fields(
        plan,
        frozenset(
            {
                "controlled_environment_prefix_removals",
                "controlled_environment_removals",
                "environment",
                "evidence_contract",
                "experiment_kind",
                "generated_at_utc",
                "operational_review",
                "pgo",
                "phases",
                "plan_id",
                "portability",
                "schema_version",
                "target_triple",
                "validation_workloads",
            }
        ),
        "build experiment plan",
    )
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise CandidateControlError("build experiment plan schema_version is invalid")
    if plan["experiment_kind"] not in EXPERIMENT_KINDS:
        raise CandidateControlError("build experiment kind is invalid")
    if plan["controlled_environment_removals"] != list(
        CONTROLLED_ENVIRONMENT_REMOVALS
    ) or plan["controlled_environment_prefix_removals"] != list(
        CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS
    ):
        raise CandidateControlError("build experiment environment control is invalid")
    environment = plan["environment"]
    if type(environment) is not dict:
        raise CandidateControlError("build experiment environment is invalid")
    _exact_fields(
        environment,
        frozenset({"build_identity_id", "environment_id", "path", "sha256"}),
        "build experiment environment",
    )
    if (
        any(
            type(environment[field]) is not str
            or SHA256.fullmatch(environment[field]) is None
            for field in ("build_identity_id", "environment_id", "sha256")
        )
        or type(environment["path"]) is not str
        or not environment["path"]
    ):
        raise CandidateControlError("build experiment environment identity is invalid")
    plan_id = plan["plan_id"]
    if type(plan_id) is not str or SHA256.fullmatch(plan_id) is None:
        raise CandidateControlError("build experiment plan_id is invalid")
    material = dict(plan)
    material.pop("plan_id")
    material.pop("generated_at_utc")
    if plan_id != _json_sha256(material):
        raise CandidateControlError("build experiment plan_id does not reconstruct")
    phases = plan["phases"]
    if type(phases) is not list or not 2 <= len(phases) <= 4:
        raise CandidateControlError("build experiment phases are invalid")
    names: set[str] = set()
    for phase in phases:
        if type(phase) is not dict:
            raise CandidateControlError("build experiment phase must be an object")
        _exact_fields(
            phase,
            frozenset(
                {
                    "artifacts",
                    "argv",
                    "environment_overrides",
                    "name",
                    "phase_type",
                    "profile",
                    "repository",
                    "target_dir",
                }
            ),
            "build experiment phase",
        )
        name = phase["name"]
        if type(name) is not str or SAFE_NAME.fullmatch(name) is None or name in names:
            raise CandidateControlError("build experiment phase name is invalid")
        names.add(name)
        _require_argv(phase["argv"], f"{name} argv")
        if phase["phase_type"] not in {"build", "profile-merge"}:
            raise CandidateControlError(f"{name} phase_type is invalid")
        artifacts = phase["artifacts"]
        if type(artifacts) is not list or not 1 <= len(artifacts) <= MAX_ARTIFACTS:
            raise CandidateControlError(f"{name} artifacts are invalid")
        for artifact in artifacts:
            _require_relative_directory(artifact, f"{name} artifact")
        overrides = phase["environment_overrides"]
        if type(overrides) is not dict or any(
            type(key) is not str
            or type(value) is not str
            or "\x00" in key
            or "\x00" in value
            for key, value in overrides.items()
        ):
            raise CandidateControlError(f"{name} environment overrides are invalid")
    return plan, bounded.sha256


def _effective_environment(
    removals: Sequence[str], prefix_removals: Sequence[str], overrides: dict[str, str]
) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in removals
        and not any(key.startswith(prefix) for prefix in prefix_removals)
    }
    environment.update(overrides)
    return environment


def _default_executor(
    argv: Sequence[str],
    cwd: pathlib.Path,
    environment: dict[str, str],
    log: pathlib.Path,
) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log.open("wb") as output:
            result = subprocess.run(
                list(argv),
                cwd=cwd,
                env=environment,
                check=False,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
    except OSError as error:
        raise CandidateControlError(
            "unable to execute build experiment phase"
        ) from error
    return result.returncode


def _profraw_input_snapshot(raw_directory: pathlib.Path) -> dict[str, object]:
    if not raw_directory.is_dir():
        raise CandidateControlError("PGO raw profile directory is unavailable")
    rows: list[dict[str, object]] = []
    try:
        for path in raw_directory.rglob("*.profraw"):
            if len(rows) == 65_536:
                raise CandidateControlError(
                    "PGO raw profile set exceeds its file bound"
                )
            if path.is_symlink() or not path.is_file():
                raise CandidateControlError(
                    "PGO raw profile set contains an invalid file"
                )
            resolved = path.resolve()
            if not resolved.is_relative_to(raw_directory):
                raise CandidateControlError("PGO raw profile escapes its directory")
            rows.append(
                {
                    "path": str(resolved.relative_to(raw_directory)),
                    "sha256": _file_sha256(resolved, field="PGO raw profile"),
                    "size_bytes": resolved.stat().st_size,
                }
            )
    except OSError as error:
        raise CandidateControlError("unable to inspect PGO raw profiles") from error
    rows.sort(key=lambda row: row["path"])
    if not rows:
        raise CandidateControlError("PGO merge requires at least one raw profile")
    return {
        "file_count": len(rows),
        "kind": "profraw-set",
        "sha256": _json_sha256(rows),
        "total_size_bytes": sum(row["size_bytes"] for row in rows),
    }


def _phase_inputs(plan: dict[str, object], phase_name: str) -> list[dict[str, object]]:
    pgo = plan["pgo"]
    if pgo is None:
        return []
    raw_directory = pathlib.Path(pgo["raw_profile_directory"]).resolve()
    merged_profile = pathlib.Path(pgo["merged_profile"]).resolve()
    if phase_name == "pgo-generate":
        if raw_directory.exists():
            if not raw_directory.is_dir():
                raise CandidateControlError("PGO raw profile path must be a directory")
            try:
                if next(raw_directory.iterdir(), None) is not None:
                    raise CandidateControlError(
                        "PGO generation requires an empty raw profile directory"
                    )
            except OSError as error:
                raise CandidateControlError(
                    "unable to inspect PGO raw profile directory"
                ) from error
        else:
            try:
                raw_directory.mkdir(parents=True)
            except OSError as error:
                raise CandidateControlError(
                    "unable to create PGO raw profile directory"
                ) from error
        return []
    if phase_name == "pgo-merge":
        if merged_profile.exists():
            raise CandidateControlError(
                "PGO merged profile already exists; use a fresh experiment target root"
            )
        return [_profraw_input_snapshot(raw_directory)]
    if phase_name == "pgo-use":
        if not merged_profile.is_file():
            raise CandidateControlError("PGO use requires the merged profile")
        return [
            {
                "kind": "merged-profdata",
                "path": str(merged_profile),
                "sha256": _file_sha256(
                    merged_profile, field="PGO merged profile input"
                ),
                "size_bytes": merged_profile.stat().st_size,
            }
        ]
    return []


def run_experiment_phase(
    *,
    plan_path: pathlib.Path,
    phase_name: str,
    log_path: pathlib.Path,
    executor: Callable[
        [Sequence[str], pathlib.Path, dict[str, str], pathlib.Path], int
    ] = _default_executor,
    clock: Callable[[], int] = time.perf_counter_ns,
) -> tuple[dict[str, object], int]:
    plan, plan_sha256 = _load_plan(plan_path)
    environment_reference = plan["environment"]
    environment_path = pathlib.Path(environment_reference["path"])
    captured_environment, environment_sha256 = _load_environment(environment_path)
    if (
        environment_sha256 != environment_reference["sha256"]
        or captured_environment["environment_id"]
        != environment_reference["environment_id"]
        or captured_environment["build_identity_id"]
        != environment_reference["build_identity_id"]
    ):
        raise CandidateControlError("build environment no longer matches the plan")
    source_identity = captured_environment["source_identity"]
    current_environment = capture_environment(
        repository=pathlib.Path(captured_environment["repository"]),
        parent_sha=source_identity["parent_sha"],
        candidate_sha=source_identity["candidate_sha"],
        run_kind=source_identity["run_kind"],
        environment_kind=captured_environment["environment_kind"],
        runner_image=captured_environment["runner_image"],
    )
    if (
        current_environment["environment_id"] != environment_reference["environment_id"]
        or current_environment["build_identity_id"]
        != environment_reference["build_identity_id"]
    ):
        raise CandidateControlError("current build environment differs from the plan")
    matching = [phase for phase in plan["phases"] if phase["name"] == phase_name]
    if len(matching) != 1:
        raise CandidateControlError("phase is not present exactly once in the plan")
    phase = matching[0]
    repository = pathlib.Path(phase["repository"]).resolve()
    target_dir = pathlib.Path(phase["target_dir"]).resolve()
    if not repository.is_dir():
        raise CandidateControlError("build phase repository is unavailable")
    environment = _effective_environment(
        plan["controlled_environment_removals"],
        plan["controlled_environment_prefix_removals"],
        phase["environment_overrides"],
    )
    inputs = _phase_inputs(plan, phase_name)
    started_at = _utc_now()
    started = clock()
    returncode = executor(phase["argv"], repository, environment, log_path)
    elapsed = clock() - started
    if type(returncode) is not int or returncode < 0 or elapsed < 0:
        raise CandidateControlError("build phase executor returned an invalid result")
    artifact_rows: list[dict[str, object]] = []
    if returncode == 0:
        for relative in phase["artifacts"]:
            artifact = (target_dir / relative).resolve()
            if not artifact.is_relative_to(target_dir) or not artifact.is_file():
                raise CandidateControlError(f"build artifact is missing: {relative}")
            artifact_rows.append(
                {
                    "path": str(artifact),
                    "sha256": _file_sha256(artifact, field=f"artifact {relative}"),
                    "size_bytes": artifact.stat().st_size,
                }
            )
    log_row: dict[str, object] | None = None
    if log_path.is_file():
        log_row = {
            "path": str(log_path.resolve()),
            "sha256": _file_sha256(log_path, field="build log"),
            "size_bytes": log_path.stat().st_size,
        }
    record = {
        "artifacts": artifact_rows,
        "build_identity_id": environment_reference["build_identity_id"],
        "command": {
            "argv": phase["argv"],
            "environment_overrides": phase["environment_overrides"],
            "repository": str(repository),
        },
        "elapsed_nanoseconds": elapsed,
        "environment_id": environment_reference["environment_id"],
        "exit_code": returncode,
        "finished_at_utc": _utc_now(),
        "inputs": inputs,
        "log": log_row,
        "phase": phase_name,
        "phase_type": phase["phase_type"],
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "schema_version": RECORD_SCHEMA_VERSION,
        "started_at_utc": started_at,
        "status": "succeeded" if returncode == 0 else "failed",
    }
    return record, returncode


def _write_json(path: pathlib.Path, value: object) -> None:
    _atomic_text(
        path,
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    environment = commands.add_parser(
        "build-environment",
        help="capture source, toolchain, machine, and background-process identity",
    )
    environment.add_argument("--repository", required=True, type=pathlib.Path)
    environment.add_argument("--parent-sha", required=True)
    environment.add_argument("--candidate-sha", required=True)
    environment.add_argument(
        "--run-kind", choices=("comparison", "calibration-aa"), default="comparison"
    )
    environment.add_argument(
        "--environment-kind", required=True, choices=ENVIRONMENT_KINDS
    )
    environment.add_argument("--runner-image", required=True)
    environment.add_argument("--output", required=True, type=pathlib.Path)

    plan = commands.add_parser(
        "build-experiment-plan",
        help="write a no-conclusion baseline/candidate build experiment manifest",
    )
    plan.add_argument("--environment", required=True, type=pathlib.Path)
    plan.add_argument("--validation-workloads", required=True, type=pathlib.Path)
    plan.add_argument("--training-workloads", type=pathlib.Path)
    plan.add_argument("--kind", required=True, choices=EXPERIMENT_KINDS)
    plan.add_argument("--target-root", required=True, type=pathlib.Path)
    plan.add_argument("--artifact-name", action="append", required=True)
    plan.add_argument("--target-triple")
    plan.add_argument("--target-cpu")
    plan.add_argument("--deployment-id")
    plan.add_argument("--acknowledge-nonportable", action="store_true")
    plan.add_argument("--llvm-profdata", type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)

    run = commands.add_parser(
        "build-experiment-run",
        help="execute one manifest phase and record time, size, hashes, and log",
    )
    run.add_argument("--plan", required=True, type=pathlib.Path)
    run.add_argument("--phase", required=True)
    run.add_argument("--log", required=True, type=pathlib.Path)
    run.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    if parsed.command == "build-environment":
        report = capture_environment(
            repository=parsed.repository,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            run_kind=parsed.run_kind,
            environment_kind=parsed.environment_kind,
            runner_image=parsed.runner_image,
        )
        _write_json(parsed.output, report)
        return 0
    if parsed.command == "build-experiment-plan":
        plan = create_experiment_plan(
            environment_path=parsed.environment,
            validation_workloads_path=parsed.validation_workloads,
            training_workloads_path=parsed.training_workloads,
            kind=parsed.kind,
            target_root=parsed.target_root,
            artifact_names=parsed.artifact_name,
            target_triple=parsed.target_triple,
            target_cpu=parsed.target_cpu,
            deployment_id=parsed.deployment_id,
            acknowledge_nonportable=parsed.acknowledge_nonportable,
            llvm_profdata=parsed.llvm_profdata,
        )
        _write_json(parsed.output, plan)
        return 0
    if parsed.command == "build-experiment-run":
        record, returncode = run_experiment_phase(
            plan_path=parsed.plan,
            phase_name=parsed.phase,
            log_path=parsed.log,
        )
        _write_json(parsed.output, record)
        return 0 if returncode == 0 else 2
    raise AssertionError(f"unhandled build experiment command: {parsed.command}")
