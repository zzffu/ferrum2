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
import sys
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

try:
    import resource as _resource
except ImportError:  # pragma: no cover - unavailable on Windows by design.
    _resource = None

ENVIRONMENT_SCHEMA_VERSION = "ferrum2-build-environment-v2"
WORKLOAD_SCHEMA_VERSION = "ferrum2-build-workload-set-v2"
PLAN_SCHEMA_VERSION = "ferrum2-build-experiment-plan-v2"
RECORD_SCHEMA_VERSION = "ferrum2-build-experiment-record-v2"
WORKLOAD_RECORD_SCHEMA_VERSION = "ferrum2-pgo-workload-record-v1"
VALIDATION_RECORD_SCHEMA_VERSION = "ferrum2-pgo-validation-record-v1"
COMMANDS = frozenset(
    {
        "build-environment",
        "build-experiment-plan",
        "build-experiment-run",
        "build-experiment-workload-run",
        "build-experiment-validation-run",
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
PGO_TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
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
PGO_TRAINING_REGISTRY = {
    "pgo-train-tcp-request": ("tcp-request", "m4-profile-workload"),
    "pgo-train-tcp-bulk": ("tcp-bulk", "m4-profile-workload"),
    "pgo-train-udp-small": ("udp-small", "m4-profile-workload"),
    "pgo-train-udp-mtu": ("udp-mtu", "m4-profile-workload"),
    "pgo-train-dns": ("dns", "m4-profile-workload"),
    "pgo-train-rule": ("rule", "rule-qualification"),
}
TRUSTED_WORKLOAD_PRODUCERS = frozenset(
    {"m4-profile-workload", "rule-qualification", "process-contract"}
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
    "LLVM_PROFILE_FILE",
    "LLVM_PROFILE_VERBOSE_ERRORS",
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
    source_sha: str | None = None,
    parent_sha: str | None = None,
    candidate_sha: str | None = None,
    run_kind: str | None = None,
    environment_kind: str,
    runner_image: str,
) -> dict[str, object]:
    repository = repository.resolve()
    if environment_kind not in ENVIRONMENT_KINDS:
        raise CandidateControlError("environment_kind is invalid")
    if not runner_image.strip() or len(runner_image) > 256:
        raise CandidateControlError("runner_image must be a bounded non-empty string")
    artifact_comparison = source_sha is not None
    if artifact_comparison:
        if parent_sha is not None or candidate_sha is not None or run_kind is not None:
            raise CandidateControlError(
                "build-artifact identity cannot mix commit comparison fields"
            )
        source = source_sha.strip().lower()
        if COMMIT_SHA.fullmatch(source) is None:
            raise CandidateControlError("source_sha must be a full Git commit SHA")
        parent = candidate = None
    else:
        if parent_sha is None or candidate_sha is None or run_kind is None:
            raise CandidateControlError(
                "commit comparison requires parent, candidate, and run_kind"
            )
        parent, candidate = validate_git_relation(
            repository, parent_sha, candidate_sha, run_kind=run_kind
        )
        source = candidate
    root = _required_command_output(
        ("git", "rev-parse", "--show-toplevel"), cwd=repository, name="repository root"
    )
    if pathlib.Path(root).resolve() != repository:
        raise CandidateControlError("repository must name the worktree root")
    head = _required_command_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, name="worktree HEAD"
    ).lower()
    if head != source:
        raise CandidateControlError("source_sha must be the checked-out worktree HEAD")
    status_returncode, status = _bounded_command(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=repository,
    )
    if status_returncode != 0:
        raise CandidateControlError("unable to capture worktree status")
    if status:
        raise CandidateControlError("build experiments require a clean worktree")
    source_tree = _required_command_output(
        ("git", "rev-parse", f"{source}^{{tree}}"),
        cwd=repository,
        name="source tree",
    ).lower()
    if GIT_OBJECT.fullmatch(source_tree) is None:
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
    if artifact_comparison:
        source_identity = {
            "comparison_axis": "build-artifact",
            "source_sha": source,
            "source_tree": source_tree,
            "worktree_clean": True,
        }
    else:
        assert parent is not None and candidate is not None and run_kind is not None
        parent_tree = _required_command_output(
            ("git", "rev-parse", f"{parent}^{{tree}}"),
            cwd=repository,
            name="parent tree",
        ).lower()
        if GIT_OBJECT.fullmatch(parent_tree) is None:
            raise CandidateControlError("parent Git tree identity is invalid")
        source_identity = {
            "candidate_sha": candidate,
            "candidate_tree": source_tree,
            "comparison_axis": "source-commit",
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
    axis = source_identity.get("comparison_axis")
    if axis == "build-artifact":
        _exact_fields(
            source_identity,
            frozenset(
                {"comparison_axis", "source_sha", "source_tree", "worktree_clean"}
            ),
            "build source_identity",
        )
        valid_source = (
            type(source_identity["source_sha"]) is str
            and COMMIT_SHA.fullmatch(source_identity["source_sha"]) is not None
            and type(source_identity["source_tree"]) is str
            and GIT_OBJECT.fullmatch(source_identity["source_tree"]) is not None
        )
    elif axis == "source-commit":
        _exact_fields(
            source_identity,
            frozenset(
                {
                    "candidate_sha",
                    "candidate_tree",
                    "comparison_axis",
                    "parent_sha",
                    "parent_tree",
                    "run_kind",
                    "worktree_clean",
                }
            ),
            "build source_identity",
        )
        valid_source = (
            all(
                type(source_identity[field]) is str
                and COMMIT_SHA.fullmatch(source_identity[field]) is not None
                for field in ("candidate_sha", "parent_sha")
            )
            and all(
                type(source_identity[field]) is str
                and GIT_OBJECT.fullmatch(source_identity[field]) is not None
                for field in ("candidate_tree", "parent_tree")
            )
            and source_identity["run_kind"] in {"comparison", "calibration-aa"}
        )
    else:
        valid_source = False
    if not valid_source or source_identity["worktree_clean"] is not True:
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
                    "producer",
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
        if scenario["producer"] not in TRUSTED_WORKLOAD_PRODUCERS:
            raise CandidateControlError(f"{name} producer is not trusted")
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
    raw_profile_directory: pathlib.Path | None = None,
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
            "producer": scenario["producer"],
            "variant": variant,
            "weight_basis_points": scenario["weight_basis_points"],
            "working_directory": str(working_directory),
            "workload_set_sha256": workload_sha256,
        }
        command_seed = _json_sha256(command)
        environment_overrides: dict[str, str] = {}
        if raw_profile_directory is not None:
            environment_overrides["LLVM_PROFILE_FILE"] = str(
                raw_profile_directory / f"{command_seed}-%p-%m.profraw"
            )
        command = {**command, "environment_overrides": environment_overrides}
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
    if environment["source_identity"]["comparison_axis"] != "build-artifact":
        raise CandidateControlError(
            "build experiment plans require a same-source build-artifact environment"
        )
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
        "fallback_phase": None,
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
            or target_cpu != "znver3"
        ):
            raise CandidateControlError(
                "target-cpu requires the reviewed named znver3 class; native is not reproducible"
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
            "fallback_phase": "baseline",
            "general_distribution_baseline_unchanged": True,
            "nonportable_opt_in": True,
            "target_cpu": target_cpu,
        }
    elif target_cpu is not None or deployment_id is not None or acknowledge_nonportable:
        raise CandidateControlError("target-cpu options are valid only for target-cpu")
    if kind == "pgo":
        if target_triple != PGO_TARGET_TRIPLE:
            raise CandidateControlError(
                "PGO requires the explicit x86_64-unknown-linux-gnu target to isolate "
                "profile flags from host build dependencies"
            )
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
        registered = {
            scenario["name"]: (scenario["category"], scenario["producer"])
            for scenario in training["scenarios"]
        }
        if registered != PGO_TRAINING_REGISTRY:
            raise CandidateControlError(
                "PGO training workloads must exactly match the trusted six-class registry"
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
        llvm_profdata_version = _required_command_output(
            (str(llvm_profdata), "--version"), name="llvm-profdata version"
        )
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
                "--failure-mode=all",
                "-o",
                str(merged_file),
                "{profraw-inventory}",
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
                "version": llvm_profdata_version,
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
                raw_profile_directory=raw_directory,
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
        "artifact_names": artifacts,
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
            "adoption_claim": False,
            "bare_metal_gate_satisfied": False,
            "cross_environment_mixing_forbidden": True,
            "durable_evidence_gate_satisfied": False,
            "performance_authoritative": False,
            "performance_conclusions_recorded": False,
            "required_raw_artifact_kinds": [
                "allocator",
                "perf-stat",
                "raw-jsonl",
                "rss",
                "summary",
            ],
            "single_scenario_adoption_forbidden": True,
            "scope": (
                "github-hosted-amd-provisional"
                if environment["environment_kind"] == "github-hosted"
                else "non-authoritative-build-experiment"
            ),
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
                "artifact_names",
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
    if plan["experiment_kind"] == "pgo" and plan["target_triple"] != PGO_TARGET_TRIPLE:
        raise CandidateControlError(
            "PGO plan must retain its explicit target isolation"
        )
    if _artifact_names(plan["artifact_names"]) != plan["artifact_names"]:
        raise CandidateControlError("build experiment artifact names are invalid")
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


def _child_resource_snapshot() -> dict[str, object]:
    if _resource is None:
        return {"peak_rss_kib": None, "status": "unavailable", "unit": "kibibytes"}
    usage = _resource.getrusage(_resource.RUSAGE_CHILDREN)
    peak = int(usage.ru_maxrss)
    if sys.platform == "darwin":
        peak //= 1024
    return {"peak_rss_kib": peak, "status": "captured", "unit": "kibibytes"}


def _profraw_inventory(raw_directory: pathlib.Path) -> list[dict[str, object]]:
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
    return rows


def _profraw_input_snapshot(raw_directory: pathlib.Path) -> dict[str, object]:
    rows = _profraw_inventory(raw_directory)
    if not rows:
        raise CandidateControlError("PGO merge requires at least one raw profile")
    return {
        "files": rows,
        "file_count": len(rows),
        "kind": "profraw-set",
        "sha256": _json_sha256(rows),
        "total_size_bytes": sum(row["size_bytes"] for row in rows),
    }


def _load_phase_record(
    path: pathlib.Path, *, plan_id: str, plan_sha256: str, phase: str
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MAX_JSON_BYTES, source="build phase record"
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("build phase record must be an object")
    required = {
        "artifacts",
        "build_identity_id",
        "command",
        "elapsed_nanoseconds",
        "environment_id",
        "exit_code",
        "finished_at_utc",
        "inputs",
        "log",
        "phase",
        "phase_type",
        "plan_id",
        "plan_sha256",
        "record_id",
        "resource_usage",
        "schema_version",
        "started_at_utc",
        "status",
    }
    _exact_fields(row, frozenset(required), "build phase record")
    if (
        row["schema_version"] != RECORD_SCHEMA_VERSION
        or row["plan_id"] != plan_id
        or row["plan_sha256"] != plan_sha256
        or row["phase"] != phase
        or row["status"] != "succeeded"
        or row["exit_code"] != 0
    ):
        raise CandidateControlError("build phase record identity is invalid")
    material = dict(row)
    record_id = material.pop("record_id")
    if type(record_id) is not str or record_id != _json_sha256(material):
        raise CandidateControlError("build phase record_id does not reconstruct")
    return row, bounded.sha256


def _load_workload_record(
    path: pathlib.Path, *, plan_id: str, plan_sha256: str
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path, maximum_bytes=MAX_JSON_BYTES, source="PGO workload record"
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("PGO workload record must be an object")
    fields = frozenset(
        {
            "command_id",
            "elapsed_nanoseconds",
            "exit_code",
            "finished_at_utc",
            "generate_phase_record_sha256",
            "inventory_after",
            "inventory_before",
            "log",
            "plan_id",
            "plan_sha256",
            "produced_profiles",
            "record_id",
            "schema_version",
            "started_at_utc",
            "status",
        }
    )
    _exact_fields(row, fields, "PGO workload record")
    if (
        row["schema_version"] != WORKLOAD_RECORD_SCHEMA_VERSION
        or row["plan_id"] != plan_id
        or row["plan_sha256"] != plan_sha256
        or row["status"] != "succeeded"
        or row["exit_code"] != 0
    ):
        raise CandidateControlError("PGO workload record identity is invalid")
    material = dict(row)
    record_id = material.pop("record_id")
    if type(record_id) is not str or record_id != _json_sha256(material):
        raise CandidateControlError("PGO workload record_id does not reconstruct")
    return row, bounded.sha256


def _closed_training_inventory(
    plan: dict[str, object], plan_sha256: str, record_paths: Sequence[pathlib.Path]
) -> dict[str, object]:
    pgo = plan["pgo"]
    if type(pgo) is not dict:
        raise CandidateControlError("training records are valid only for PGO")
    expected = {row["command_id"] for row in pgo["training_commands"]}
    records: dict[str, tuple[dict[str, object], str]] = {}
    produced: dict[str, dict[str, object]] = {}
    for path in record_paths:
        row, digest = _load_workload_record(
            path, plan_id=plan["plan_id"], plan_sha256=plan_sha256
        )
        command_id = row["command_id"]
        if command_id not in expected or command_id in records:
            raise CandidateControlError("PGO workload record set is not closed")
        records[command_id] = (row, digest)
        for profile in row["produced_profiles"]:
            if type(profile) is not dict:
                raise CandidateControlError("PGO produced profile is invalid")
            _exact_fields(
                profile,
                frozenset({"path", "producer_command_id", "sha256", "size_bytes"}),
                "PGO produced profile",
            )
            path_value = profile["path"]
            if (
                type(path_value) is not str
                or path_value in produced
                or profile["producer_command_id"] != command_id
                or type(profile["size_bytes"]) is not int
                or profile["size_bytes"] <= 0
                or type(profile["sha256"]) is not str
                or SHA256.fullmatch(profile["sha256"]) is None
            ):
                raise CandidateControlError("PGO produced profile identity is invalid")
            produced[path_value] = profile
    if set(records) != expected:
        raise CandidateControlError(
            "PGO merge requires one record for every training command"
        )
    raw_directory = pathlib.Path(pgo["raw_profile_directory"]).resolve()
    observed = _profraw_inventory(raw_directory)
    if {row["path"]: (row["sha256"], row["size_bytes"]) for row in observed} != {
        path: (row["sha256"], row["size_bytes"]) for path, row in produced.items()
    }:
        raise CandidateControlError(
            "PGO raw directory differs from the closed training records"
        )
    files = [produced[path] for path in sorted(produced)]
    return {
        "files": files,
        "file_count": len(files),
        "kind": "closed-profraw-inventory",
        "record_sha256": [records[key][1] for key in sorted(records)],
        "sha256": _json_sha256(files),
        "total_size_bytes": sum(row["size_bytes"] for row in files),
    }


def _phase_inputs(
    plan: dict[str, object],
    phase_name: str,
    *,
    plan_sha256: str | None = None,
    training_record_paths: Sequence[pathlib.Path] = (),
) -> list[dict[str, object]]:
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
        if not training_record_paths or plan_sha256 is None:
            raise CandidateControlError(
                "PGO merge requires the closed per-command training record set"
            )
        return [_closed_training_inventory(plan, plan_sha256, training_record_paths)]
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
    training_record_paths: Sequence[pathlib.Path] = (),
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
        source_sha=source_identity["source_sha"],
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
    inputs = _phase_inputs(
        plan,
        phase_name,
        plan_sha256=plan_sha256,
        training_record_paths=training_record_paths,
    )
    runtime_argv = list(phase["argv"])
    if phase_name == "pgo-merge":
        if runtime_argv.count("{profraw-inventory}") != 1:
            raise CandidateControlError(
                "PGO merge command inventory placeholder is invalid"
            )
        inventory_paths = [
            str(
                pathlib.Path(plan["pgo"]["raw_profile_directory"]).resolve()
                / row["path"]
            )
            for row in inputs[0]["files"]
        ]
        placeholder = runtime_argv.index("{profraw-inventory}")
        runtime_argv[placeholder : placeholder + 1] = inventory_paths
    started_at = _utc_now()
    started = clock()
    resource_before = _child_resource_snapshot()
    returncode = executor(runtime_argv, repository, environment, log_path)
    resource_after = _child_resource_snapshot()
    elapsed = clock() - started
    if type(returncode) is not int or returncode < 0 or elapsed < 0:
        raise CandidateControlError("build phase executor returned an invalid result")
    if phase_name == "pgo-generate" and _profraw_inventory(
        pathlib.Path(plan["pgo"]["raw_profile_directory"]).resolve()
    ):
        raise CandidateControlError(
            "PGO instrumented build polluted the external training profile inventory"
        )
    artifact_rows: list[dict[str, object]] = []
    if returncode == 0:
        output_names = (
            plan["artifact_names"]
            if phase["phase_type"] == "build"
            else ["merged.profdata"]
        )
        for artifact_name, relative in zip(
            output_names, phase["artifacts"], strict=True
        ):
            artifact = (target_dir / relative).resolve()
            if not artifact.is_relative_to(target_dir) or not artifact.is_file():
                raise CandidateControlError(f"build artifact is missing: {relative}")
            artifact_rows.append(
                {
                    "name": artifact_name,
                    "path": str(artifact),
                    "relative_path": relative,
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
            "argv": runtime_argv,
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
        "resource_usage": {
            "after": resource_after,
            "before": resource_before,
            "phase_peak_rss_upper_bound_kib": resource_after["peak_rss_kib"],
        },
        "schema_version": RECORD_SCHEMA_VERSION,
        "started_at_utc": started_at,
        "status": "succeeded" if returncode == 0 else "failed",
    }
    record["record_id"] = _json_sha256(record)
    return record, returncode


def _validate_generate_artifacts(
    plan: dict[str, object], phase_record: dict[str, object]
) -> None:
    artifacts = phase_record["artifacts"]
    if type(artifacts) is not list or len(artifacts) != len(plan["artifact_names"]):
        raise CandidateControlError("PGO generate phase artifact set is incomplete")
    names: set[str] = set()
    for row in artifacts:
        if type(row) is not dict:
            raise CandidateControlError("PGO generate artifact is invalid")
        _exact_fields(
            row,
            frozenset({"name", "path", "relative_path", "sha256", "size_bytes"}),
            "PGO generate artifact",
        )
        name = row["name"]
        path = pathlib.Path(row["path"])
        if (
            name not in plan["artifact_names"]
            or name in names
            or not path.is_file()
            or type(row["sha256"]) is not str
            or SHA256.fullmatch(row["sha256"]) is None
            or _file_sha256(path, field=f"PGO generate artifact {name}")
            != row["sha256"]
            or path.stat().st_size != row["size_bytes"]
        ):
            raise CandidateControlError("PGO generate artifact identity changed")
        names.add(name)
    if names != set(plan["artifact_names"]):
        raise CandidateControlError("PGO generate artifact names are not closed")


def run_pgo_workload_command(
    *,
    plan_path: pathlib.Path,
    command_id: str,
    generate_phase_record_path: pathlib.Path,
    log_path: pathlib.Path,
    executor: Callable[
        [Sequence[str], pathlib.Path, dict[str, str], pathlib.Path], int
    ] = _default_executor,
    clock: Callable[[], int] = time.perf_counter_ns,
) -> tuple[dict[str, object], int]:
    """Run one trusted PGO training command and bind its exact profile delta."""

    plan, plan_sha256 = _load_plan(plan_path)
    pgo = plan["pgo"]
    if type(pgo) is not dict:
        raise CandidateControlError("PGO workload execution requires a PGO plan")
    commands = [
        row for row in pgo["training_commands"] if row["command_id"] == command_id
    ]
    if len(commands) != 1:
        raise CandidateControlError("PGO training command is not present exactly once")
    command = commands[0]
    phase_record, phase_record_sha256 = _load_phase_record(
        generate_phase_record_path,
        plan_id=plan["plan_id"],
        plan_sha256=plan_sha256,
        phase="pgo-generate",
    )
    _validate_generate_artifacts(plan, phase_record)
    raw_directory = pathlib.Path(pgo["raw_profile_directory"]).resolve()
    raw_directory.mkdir(parents=True, exist_ok=True)
    before = _profraw_inventory(raw_directory)
    before_by_path = {row["path"]: row for row in before}
    environment = _effective_environment(
        plan["controlled_environment_removals"],
        plan["controlled_environment_prefix_removals"],
        command["environment_overrides"],
    )
    profile_template = command["environment_overrides"].get("LLVM_PROFILE_FILE")
    if type(profile_template) is not str or "%p" not in profile_template:
        raise CandidateControlError("PGO training command profile template is invalid")
    template_path = pathlib.Path(profile_template).resolve()
    if not template_path.is_relative_to(raw_directory):
        raise CandidateControlError("PGO profile template escapes the raw directory")
    profile_prefix = template_path.name.split("%", 1)[0]
    started_at = _utc_now()
    started = clock()
    returncode = executor(
        command["argv"],
        pathlib.Path(command["working_directory"]),
        environment,
        log_path,
    )
    elapsed = clock() - started
    if type(returncode) is not int or returncode < 0 or elapsed < 0:
        raise CandidateControlError("PGO workload executor returned an invalid result")
    after = _profraw_inventory(raw_directory)
    after_by_path = {row["path"]: row for row in after}
    for path, row in before_by_path.items():
        if after_by_path.get(path) != row:
            raise CandidateControlError("PGO workload modified an existing raw profile")
    produced_rows = [
        row for path, row in after_by_path.items() if path not in before_by_path
    ]
    if returncode == 0:
        if not produced_rows or any(
            row["size_bytes"] <= 0
            or not pathlib.PurePath(row["path"]).name.startswith(profile_prefix)
            for row in produced_rows
        ):
            raise CandidateControlError(
                "successful PGO workload must create a unique nonempty profile set"
            )
    produced = [
        {**row, "producer_command_id": command_id}
        for row in sorted(produced_rows, key=lambda row: row["path"])
    ]
    log_row: dict[str, object] | None = None
    if log_path.is_file():
        log_row = {
            "path": str(log_path.resolve()),
            "sha256": _file_sha256(log_path, field="PGO workload log"),
            "size_bytes": log_path.stat().st_size,
        }
    record = {
        "command_id": command_id,
        "elapsed_nanoseconds": elapsed,
        "exit_code": returncode,
        "finished_at_utc": _utc_now(),
        "generate_phase_record_sha256": phase_record_sha256,
        "inventory_after": after,
        "inventory_before": before,
        "log": log_row,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "produced_profiles": produced,
        "schema_version": WORKLOAD_RECORD_SCHEMA_VERSION,
        "started_at_utc": started_at,
        "status": "succeeded" if returncode == 0 else "failed",
    }
    record["record_id"] = _json_sha256(record)
    return record, returncode


def run_pgo_validation_command(
    *,
    plan_path: pathlib.Path,
    command_id: str,
    phase_record_path: pathlib.Path,
    log_path: pathlib.Path,
    executor: Callable[
        [Sequence[str], pathlib.Path, dict[str, str], pathlib.Path], int
    ] = _default_executor,
    clock: Callable[[], int] = time.perf_counter_ns,
) -> tuple[dict[str, object], int]:
    """Run one independent PGO validation command without profile generation."""

    plan, plan_sha256 = _load_plan(plan_path)
    pgo = plan["pgo"]
    if type(pgo) is not dict:
        raise CandidateControlError("PGO validation execution requires a PGO plan")
    commands = [
        row for row in pgo["validation_commands"] if row["command_id"] == command_id
    ]
    if len(commands) != 1:
        raise CandidateControlError(
            "PGO validation command is not present exactly once"
        )
    command = commands[0]
    phase = command["build_phase"]
    phase_record, phase_record_sha256 = _load_phase_record(
        phase_record_path,
        plan_id=plan["plan_id"],
        plan_sha256=plan_sha256,
        phase=phase,
    )
    _validate_generate_artifacts(plan, phase_record)
    environment = _effective_environment(
        plan["controlled_environment_removals"],
        plan["controlled_environment_prefix_removals"],
        command["environment_overrides"],
    )
    if "LLVM_PROFILE_FILE" in environment:
        raise CandidateControlError("PGO validation inherited profile generation state")
    started_at = _utc_now()
    started = clock()
    returncode = executor(
        command["argv"],
        pathlib.Path(command["working_directory"]),
        environment,
        log_path,
    )
    elapsed = clock() - started
    if type(returncode) is not int or returncode < 0 or elapsed < 0:
        raise CandidateControlError(
            "PGO validation executor returned an invalid result"
        )
    log_row: dict[str, object] | None = None
    if log_path.is_file():
        log_row = {
            "path": str(log_path.resolve()),
            "sha256": _file_sha256(log_path, field="PGO validation log"),
            "size_bytes": log_path.stat().st_size,
        }
    record = {
        "command_id": command_id,
        "elapsed_nanoseconds": elapsed,
        "external_requirement_satisfied": command["coverage"] != "different-cpu",
        "exit_code": returncode,
        "finished_at_utc": _utc_now(),
        "log": log_row,
        "phase_record_sha256": phase_record_sha256,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "schema_version": VALIDATION_RECORD_SCHEMA_VERSION,
        "started_at_utc": started_at,
        "status": "succeeded" if returncode == 0 else "failed",
        "validation_coverage": command["coverage"],
        "variant": command["variant"],
    }
    record["record_id"] = _json_sha256(record)
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
    environment.add_argument("--source-sha")
    environment.add_argument("--parent-sha")
    environment.add_argument("--candidate-sha")
    environment.add_argument("--run-kind", choices=("comparison", "calibration-aa"))
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
    run.add_argument("--training-record", action="append", type=pathlib.Path)
    run.add_argument("--log", required=True, type=pathlib.Path)
    run.add_argument("--output", required=True, type=pathlib.Path)

    workload = commands.add_parser(
        "build-experiment-workload-run",
        help="execute one trusted PGO training command and bind its profraw delta",
    )
    workload.add_argument("--plan", required=True, type=pathlib.Path)
    workload.add_argument("--command-id", required=True)
    workload.add_argument("--generate-phase-record", required=True, type=pathlib.Path)
    workload.add_argument("--log", required=True, type=pathlib.Path)
    workload.add_argument("--output", required=True, type=pathlib.Path)

    validation = commands.add_parser(
        "build-experiment-validation-run",
        help="execute one independent PGO validation command without profiling",
    )
    validation.add_argument("--plan", required=True, type=pathlib.Path)
    validation.add_argument("--command-id", required=True)
    validation.add_argument("--phase-record", required=True, type=pathlib.Path)
    validation.add_argument("--log", required=True, type=pathlib.Path)
    validation.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    if parsed.command == "build-environment":
        report = capture_environment(
            repository=parsed.repository,
            source_sha=parsed.source_sha,
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
            training_record_paths=parsed.training_record or (),
        )
        _write_json(parsed.output, record)
        return 0 if returncode == 0 else 2
    if parsed.command == "build-experiment-workload-run":
        record, returncode = run_pgo_workload_command(
            plan_path=parsed.plan,
            command_id=parsed.command_id,
            generate_phase_record_path=parsed.generate_phase_record,
            log_path=parsed.log,
        )
        _write_json(parsed.output, record)
        return 0 if returncode == 0 else 2
    if parsed.command == "build-experiment-validation-run":
        record, returncode = run_pgo_validation_command(
            plan_path=parsed.plan,
            command_id=parsed.command_id,
            phase_record_path=parsed.phase_record,
            log_path=parsed.log,
        )
        _write_json(parsed.output, record)
        return 0 if returncode == 0 else 2
    raise AssertionError(f"unhandled build experiment command: {parsed.command}")
