"""Deterministic control-plane helpers for build and conditional workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import sys

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.evidence_contract import (
    catalog_evidence_contract,
)

HOST_SCHEMA_VERSION = "ferrum2-github-amd-host-v1"
MANIFEST_SCHEMA_VERSION = "ferrum2-performance-build-artifact-manifest-v1"
EXPERIMENT_KINDS = frozenset({"thin-lto-cgu1", "pgo", "target-cpu"})
PROFILE_ARTIFACTS = (
    "ferrum2-client",
    "ferrum2-rule-qualification",
    "ferrum2-server",
    "m4-qualification",
)


def _write(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _cpu_fields(path: pathlib.Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise CandidateControlError("unable to read CPU identity") from error
    vendor = None
    model = None
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key.strip() == "vendor_id" and vendor is None:
            vendor = value.strip()
        if key.strip() == "model name" and model is None:
            model = value.strip()
    if not vendor or not model:
        raise CandidateControlError("CPU identity is incomplete")
    return vendor, model


def capture_amd_host(
    *,
    cpuinfo_path: pathlib.Path = pathlib.Path("/proc/cpuinfo"),
    runner_image: str,
) -> dict[str, object]:
    vendor, model = _cpu_fields(cpuinfo_path)
    if vendor != "AuthenticAMD":
        raise CandidateControlError(
            f"GitHub performance build requires AuthenticAMD, observed {vendor}"
        )
    if not runner_image or len(runner_image) > 256:
        raise CandidateControlError("runner image identity is invalid")
    material = {
        "cpu_count": os.cpu_count(),
        "cpu_model": model,
        "cpu_vendor": vendor,
        "kernel": platform.release(),
        "machine": platform.machine(),
        "runner_image": runner_image,
    }
    return {
        **material,
        "host_id": build_experiment._json_sha256(material),
        "schema_version": HOST_SCHEMA_VERSION,
    }


def prepare_paths(
    *, root: pathlib.Path, experiment_kind: str, github_env: pathlib.Path
) -> dict[str, str]:
    if experiment_kind not in EXPERIMENT_KINDS:
        raise CandidateControlError("performance build experiment kind is invalid")
    root = root.resolve()
    if root.parent == root or root.exists() or not root.parent.is_dir():
        raise CandidateControlError(
            "performance build requires one fresh experiment root"
        )
    root.mkdir()
    values = {
        "BUILD_EVIDENCE": str(root / "evidence"),
        "BUILD_ENVIRONMENT": str(root / "evidence" / "environment.json"),
        "BUILD_PLAN": str(root / "evidence" / "plan.json"),
        "BUILD_QUALIFICATION": str(root / "evidence" / "qualification.json"),
        "BUILD_ROOT": str(root),
        "BUILD_TARGET_ROOT": str(root / "targets"),
        "EXPERIMENT_KIND": experiment_kind,
        "PHASE_RECORD_ROOT": str(root / "evidence" / "phase-records"),
        "PGO_RECORD_ROOT": str(root / "evidence" / "pgo-records"),
        "PROFILE_ROOT": str(root / "evidence" / "profiles"),
    }
    for directory in (
        pathlib.Path(values["BUILD_EVIDENCE"]),
        pathlib.Path(values["PHASE_RECORD_ROOT"]),
        pathlib.Path(values["PGO_RECORD_ROOT"]),
        pathlib.Path(values["PROFILE_ROOT"]),
    ):
        directory.mkdir(parents=True)
    try:
        with github_env.open("a", encoding="utf-8", newline="\n") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")
    except OSError as error:
        raise CandidateControlError(
            "unable to initialize GitHub environment"
        ) from error
    return values


def plan_items(plan_path: pathlib.Path, kind: str) -> list[tuple[str, str]]:
    plan, _ = build_experiment._load_plan(plan_path)
    if kind == "phases":
        return [(row["name"], row["phase_type"]) for row in plan["phases"]]
    pgo = plan["pgo"]
    if type(pgo) is not dict:
        raise CandidateControlError(f"{kind} items require a PGO plan")
    if kind == "training":
        rows = pgo["training_commands"]
    elif kind == "validation":
        rows = pgo["validation_commands"]
    else:
        raise CandidateControlError("performance build plan item kind is invalid")
    return [(row["command_id"], row["build_phase"]) for row in rows]


def phase_artifact_directory(plan_path: pathlib.Path, phase_name: str) -> pathlib.Path:
    plan, _ = build_experiment._load_plan(plan_path)
    phases = [row for row in plan["phases"] if row["name"] == phase_name]
    if len(phases) != 1 or phases[0]["phase_type"] != "build":
        raise CandidateControlError("build artifact phase is not present exactly once")
    phase = phases[0]
    target_dir = pathlib.Path(phase["target_dir"]).resolve()
    artifacts = []
    for relative in phase["artifacts"]:
        path = (target_dir / relative).resolve()
        if (
            not path.is_relative_to(target_dir)
            or path.is_symlink()
            or not path.is_file()
            or path.stat().st_size <= 0
        ):
            raise CandidateControlError("build phase artifact is unavailable")
        artifacts.append(path)
    parents = {path.parent for path in artifacts}
    if len(parents) != 1:
        raise CandidateControlError("build phase artifacts do not share one directory")
    return parents.pop()


def trial_contract(scenario: str) -> dict[str, object]:
    return catalog_evidence_contract(
        scenario,
        warmup_seconds=1,
        active_seconds=15,
        pair_schedule="abba-six-pairs",
    )


def materialize_profile_artifacts(
    *, source_dir: pathlib.Path, repository: pathlib.Path
) -> pathlib.Path:
    """Materialize one artifact variant at the M4-owned target/profiling seam."""

    source_dir = source_dir.resolve()
    repository = repository.resolve()
    destination = repository / "target" / "profiling"
    if (
        not source_dir.is_dir()
        or not repository.is_dir()
        or source_dir == destination
        or (repository / "target").is_symlink()
        or destination.is_symlink()
    ):
        raise CandidateControlError(
            "profile artifact materialization paths are invalid"
        )
    sources = []
    for name in PROFILE_ARTIFACTS:
        source = source_dir / name
        if source.is_symlink() or not source.is_file() or source.stat().st_size <= 0:
            raise CandidateControlError(
                f"profile artifact source is unavailable: {name}"
            )
        sources.append((name, source))
    try:
        destination.mkdir(parents=True, exist_ok=True)
        for name, source in sources:
            target = destination / name
            if target.is_symlink():
                raise CandidateControlError(
                    f"profile artifact destination is a symlink: {name}"
                )
            shutil.copy2(source, target)
            if (
                target.stat().st_size != source.stat().st_size
                or build_experiment._file_sha256(
                    target, field=f"materialized profile artifact {name}"
                )
                != build_experiment._file_sha256(
                    source, field=f"source profile artifact {name}"
                )
            ):
                raise CandidateControlError(
                    f"profile artifact materialization changed bytes: {name}"
                )
    except OSError as error:
        raise CandidateControlError(
            "unable to materialize profile artifacts"
        ) from error
    return destination


def artifact_manifest(
    *,
    evidence_root: pathlib.Path,
    repository: str,
    run_id: str,
    run_attempt: str,
    source_sha: str,
) -> dict[str, object]:
    evidence_root = evidence_root.resolve()
    if (
        not evidence_root.is_dir()
        or not repository
        or not run_id.isdigit()
        or not run_attempt.isdigit()
        or build_experiment.COMMIT_SHA.fullmatch(source_sha) is None
    ):
        raise CandidateControlError(
            "performance build artifact manifest identity is invalid"
        )
    files = []
    for path in sorted(evidence_root.rglob("*")):
        if path.is_symlink():
            raise CandidateControlError(
                "performance build artifact set contains a symlink"
            )
        if not path.is_file() or path.name == "artifact-manifest.json":
            continue
        relative = path.relative_to(evidence_root).as_posix()
        if len(files) >= 65_536 or re.fullmatch(r"[A-Za-z0-9._/+-]+", relative) is None:
            raise CandidateControlError("performance build artifact set is invalid")
        files.append(
            {
                "path": relative,
                "sha256": build_experiment._file_sha256(
                    path, field="performance build artifact"
                ),
                "size_bytes": path.stat().st_size,
            }
        )
    if not files:
        raise CandidateControlError("performance build artifact set is empty")
    material = {
        "adoption_claim": False,
        "bare_metal_gate_satisfied": False,
        "durable_evidence_gate_satisfied": False,
        "files": files,
        "performance_authoritative": False,
        "repository": repository,
        "run_attempt": int(run_attempt),
        "run_id": int(run_id),
        "scope": "github-hosted-amd-provisional",
        "source_sha": source_sha,
    }
    return {
        **material,
        "manifest_id": build_experiment._json_sha256(material),
        "schema_version": MANIFEST_SCHEMA_VERSION,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    host = commands.add_parser("capture-host")
    host.add_argument(
        "--cpuinfo", type=pathlib.Path, default=pathlib.Path("/proc/cpuinfo")
    )
    host.add_argument("--runner-image", required=True)
    host.add_argument("--output", required=True, type=pathlib.Path)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--root", required=True, type=pathlib.Path)
    prepare.add_argument(
        "--experiment-kind", required=True, choices=sorted(EXPERIMENT_KINDS)
    )
    prepare.add_argument("--github-env", required=True, type=pathlib.Path)
    items = commands.add_parser("plan-items")
    items.add_argument("--plan", required=True, type=pathlib.Path)
    items.add_argument(
        "--kind", required=True, choices=("phases", "training", "validation")
    )
    contract = commands.add_parser("trial-contract")
    contract.add_argument("--scenario", required=True)
    materialize = commands.add_parser("materialize-profile-artifacts")
    materialize.add_argument("--source-dir", required=True, type=pathlib.Path)
    materialize.add_argument("--repository", required=True, type=pathlib.Path)
    artifact_directory = commands.add_parser("phase-artifact-directory")
    artifact_directory.add_argument("--plan", required=True, type=pathlib.Path)
    artifact_directory.add_argument("--phase", required=True)
    manifest = commands.add_parser("artifact-manifest")
    manifest.add_argument("--evidence-root", required=True, type=pathlib.Path)
    manifest.add_argument("--repository", required=True)
    manifest.add_argument("--run-id", required=True)
    manifest.add_argument("--run-attempt", required=True)
    manifest.add_argument("--source-sha", required=True)
    manifest.add_argument("--output", required=True, type=pathlib.Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    try:
        parsed = _parser().parse_args(arguments)
        if parsed.command == "capture-host":
            _write(
                parsed.output,
                capture_amd_host(
                    cpuinfo_path=parsed.cpuinfo, runner_image=parsed.runner_image
                ),
            )
        elif parsed.command == "prepare":
            prepare_paths(
                root=parsed.root,
                experiment_kind=parsed.experiment_kind,
                github_env=parsed.github_env,
            )
        elif parsed.command == "plan-items":
            for identity, phase in plan_items(parsed.plan, parsed.kind):
                print(f"{identity}\t{phase}")
        elif parsed.command == "trial-contract":
            contract = trial_contract(parsed.scenario)
            print(
                "\t".join(
                    str(contract[field])
                    for field in (
                        "unit",
                        "runner_image",
                        "producer_source_sha256",
                        "controller_source_sha256",
                        "semantic_recipe_sha256",
                        "evidence_bundle_sha256",
                    )
                )
            )
        elif parsed.command == "materialize-profile-artifacts":
            print(
                materialize_profile_artifacts(
                    source_dir=parsed.source_dir,
                    repository=parsed.repository,
                )
            )
        elif parsed.command == "phase-artifact-directory":
            print(phase_artifact_directory(parsed.plan, parsed.phase))
        elif parsed.command == "artifact-manifest":
            _write(
                parsed.output,
                artifact_manifest(
                    evidence_root=parsed.evidence_root,
                    repository=parsed.repository,
                    run_id=parsed.run_id,
                    run_attempt=parsed.run_attempt,
                    source_sha=parsed.source_sha,
                ),
            )
        else:
            raise AssertionError(f"unhandled command: {parsed.command}")
        return 0
    except CandidateControlError as error:
        print(f"performance-build-workflow: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
