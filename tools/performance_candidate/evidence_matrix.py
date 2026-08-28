"""Opt-in Phase 4 evidence-gated experiment matrix manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    _canonical_json_bytes,
)
from tools.performance_candidate.output import _atomic_text

SCHEMA_VERSION = "ferrum2-phase4-evidence-matrix-v1"
COMMANDS = frozenset({"phase4-experiment-plan"})
FAMILIES = ("metrics", "runtime", "allocator")
SAFE_FEATURE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
SAFE_ENVIRONMENT_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,127}")

COLLECTION_FIELDS = {
    "metrics": [
        "cache_line_bounces",
        "counter_contention",
        "counter_correctness",
        "cpu_utilization",
        "perf_c2c",
        "p99_latency",
        "throughput",
    ],
    "runtime": [
        "context_switches",
        "correctness",
        "cpu_utilization",
        "p99_latency",
        "throughput",
    ],
    "allocator": [
        "allocation_hotspots",
        "allocator_cpu_time",
        "allocator_lock_contention",
        "correctness",
        "fragmentation",
        "long_run_growth",
        "platform",
        "rss",
    ],
}

PREREQUISITES = {
    "metrics": [
        "counter-contention-or-cache-line-sharing-confirmed",
        "perf-c2c-or-equivalent-raw-evidence-retained",
    ],
    "runtime": [
        "global-lock-contention-addressed",
        "dns-and-codec-serialization-addressed",
        "waiter-thundering-herd-addressed",
    ],
    "allocator": [
        "known-tcp-udp-dns-and-transaction-allocations-addressed",
        "allocation-hotspots-reprofiled",
        "allocator-cpu-or-lock-cost-remains-material",
    ],
}
PREREQUISITE_EVIDENCE_KEYS = {
    "metrics": frozenset({"counter-contention", "perf-c2c"}),
    "runtime": frozenset(
        {"dns-codec-addressed", "locks-addressed", "waiter-herd-addressed"}
    ),
    "allocator": frozenset(
        {
            "allocation-hotspots",
            "allocator-cpu-lock",
            "known-allocations-addressed",
        }
    ),
}


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _safe_name(value: str | None, field: str) -> str:
    if value is None or build_experiment.SAFE_NAME.fullmatch(value) is None:
        raise CandidateControlError(f"{field} is invalid")
    return value


def _candidate_environment(values: list[str] | None) -> dict[str, str]:
    environment: dict[str, str] = {}
    for raw in values or ():
        key, separator, value = raw.partition("=")
        if (
            not separator
            or SAFE_ENVIRONMENT_KEY.fullmatch(key) is None
            or not value
            or len(value) > 4096
            or "\x00" in value
            or key in environment
        ):
            raise CandidateControlError(
                "candidate environment must use unique bounded NAME=VALUE entries"
            )
        environment[key] = value
    return environment


def _prerequisite_evidence(
    family: str, values: list[str] | None
) -> dict[str, dict[str, object]]:
    evidence: dict[str, dict[str, object]] = {}
    for raw in values or ():
        kind, separator, path_text = raw.partition("=")
        path = pathlib.Path(path_text).resolve()
        if (
            not separator
            or kind not in PREREQUISITE_EVIDENCE_KEYS[family]
            or kind in evidence
            or not path.is_file()
        ):
            raise CandidateControlError(
                f"{family} prerequisite evidence must use unique required KIND=PATH entries"
            )
        evidence[kind] = {
            "path": str(path),
            "sha256": build_experiment._file_sha256(
                path, field=f"{family} prerequisite evidence {kind}"
            ),
            "size_bytes": path.stat().st_size,
        }
    if set(evidence) != PREREQUISITE_EVIDENCE_KEYS[family]:
        missing = sorted(PREREQUISITE_EVIDENCE_KEYS[family] - set(evidence))
        raise CandidateControlError(
            f"{family} prerequisite evidence is missing: {missing}"
        )
    return evidence


def _artifact_path(
    *,
    target_dir: pathlib.Path,
    target_triple: str | None,
    artifact_name: str,
) -> pathlib.Path:
    relative = pathlib.Path("profiling") / artifact_name
    if target_triple is not None:
        relative = pathlib.Path(target_triple) / relative
    return (target_dir / relative).resolve()


def _build_command(
    *,
    name: str,
    repository: pathlib.Path,
    target_dir: pathlib.Path,
    package: str,
    binary_name: str,
    artifact_name: str,
    target_triple: str | None,
    feature: str | None,
) -> dict[str, object]:
    argv = [
        "cargo",
        "build",
        "--package",
        package,
        "--bin",
        binary_name,
        "--locked",
        "--profile",
        "profiling",
        "--target-dir",
        str(target_dir),
    ]
    if target_triple is not None:
        argv.extend(("--target", target_triple))
    if feature is not None:
        argv.extend(("--features", feature))
    command = {
        "argv": argv,
        "artifact": str(
            _artifact_path(
                target_dir=target_dir,
                target_triple=target_triple,
                artifact_name=artifact_name,
            )
        ),
        "environment_overrides": {
            "CARGO_INCREMENTAL": "0",
            "RUSTUP_TOOLCHAIN": build_experiment.PINNED_RUST_RELEASE,
        },
        "feature_opt_in": feature,
        "name": name,
        "repository": str(repository),
        "target_dir": str(target_dir),
    }
    return {**command, "command_id": _identity(command)}


def _replace_artifact(argv: list[str], artifact: str, scenario_name: str) -> list[str]:
    if argv.count("{artifact}") != 1:
        raise CandidateControlError(
            f"Phase 4 scenario {scenario_name} argv must contain one {{artifact}} token"
        )
    return [artifact if argument == "{artifact}" else argument for argument in argv]


def _run_rows(
    *,
    family: str,
    repository: pathlib.Path,
    evidence_root: pathlib.Path,
    validation: dict[str, object],
    validation_sha256: str,
    environment_id: str,
    build_identity_id: str,
    variants: list[dict[str, object]],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for variant in variants:
        for scenario in validation["scenarios"]:
            cwd = (repository / scenario["working_directory"]).resolve()
            if not cwd.is_relative_to(repository) or not cwd.is_dir():
                raise CandidateControlError(
                    f"Phase 4 scenario {scenario['name']} working directory is unavailable"
                )
            argv = _replace_artifact(
                scenario["argv"], variant["artifact"], scenario["name"]
            )
            evidence_directory = (
                evidence_root / family / variant["name"] / scenario["name"]
            ).resolve()
            identity_material = {
                "argv": argv,
                "build_identity_id": build_identity_id,
                "environment_id": environment_id,
                "family": family,
                "scenario": scenario["name"],
                "validation_workloads_sha256": validation_sha256,
                "variant_id": variant["variant_id"],
            }
            rows.append(
                {
                    "argv": argv,
                    "collection_fields": COLLECTION_FIELDS[family],
                    "environment_overrides": variant["run_environment_overrides"],
                    "evidence_directory": str(evidence_directory),
                    "result_identity_seed": _identity(identity_material),
                    "scenario": scenario["name"],
                    "variant": variant["name"],
                    "variant_id": variant["variant_id"],
                    "working_directory": str(cwd),
                }
            )
    return rows


def create_evidence_matrix(
    *,
    environment_path: pathlib.Path,
    validation_workloads_path: pathlib.Path,
    family: str,
    target_root: pathlib.Path,
    evidence_root: pathlib.Path,
    package: str,
    binary_name: str,
    artifact_name: str,
    target_triple: str | None = None,
    candidate_feature: str | None = None,
    candidate_environment: list[str] | None = None,
    candidate_allocator: str | None = None,
    physical_workers: int | None = None,
    reduced_workers: int | None = None,
    acknowledge_prerequisites: bool = False,
    prerequisite_evidence: list[str] | None = None,
) -> dict[str, object]:
    if family not in FAMILIES:
        raise CandidateControlError("Phase 4 experiment family is invalid")
    if not acknowledge_prerequisites:
        raise CandidateControlError(
            f"{family} experiment prerequisites require explicit acknowledgement"
        )
    package = _safe_name(package, "package")
    binary_name = _safe_name(binary_name, "binary_name")
    artifact_name = _safe_name(artifact_name, "artifact_name")
    if target_triple is not None:
        _safe_name(target_triple, "target_triple")
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    validation, validation_sha256 = build_experiment._load_workload_set(
        validation_workloads_path, expected_role="validation"
    )
    repository = pathlib.Path(environment["repository"]).resolve()
    target_root = target_root.resolve()
    evidence_root = evidence_root.resolve()
    requested_candidate_environment = _candidate_environment(candidate_environment)
    gate_evidence = _prerequisite_evidence(family, prerequisite_evidence)
    baseline_build = _build_command(
        name="baseline",
        repository=repository,
        target_dir=(target_root / "baseline").resolve(),
        package=package,
        binary_name=binary_name,
        artifact_name=artifact_name,
        target_triple=target_triple,
        feature=None,
    )
    build_commands = [baseline_build]
    variants: list[dict[str, object]] = []
    candidate_description: dict[str, object]
    if family == "runtime":
        if candidate_feature is not None or candidate_allocator is not None:
            raise CandidateControlError(
                "runtime does not accept feature or allocator options"
            )
        if requested_candidate_environment:
            raise CandidateControlError(
                "runtime worker environments are generated exactly"
            )
        if (
            type(physical_workers) is not int
            or type(reduced_workers) is not int
            or not 2 <= physical_workers <= 1024
            or not 1 <= reduced_workers < physical_workers
        ):
            raise CandidateControlError(
                "runtime requires explicit physical and lower worker counts"
            )
        worker_variants = (
            ("default", None, False),
            ("physical-cores", physical_workers, True),
            ("reduced", reduced_workers, True),
        )
        for name, worker_count, opt_in in worker_variants:
            environment_overrides = (
                {}
                if worker_count is None
                else {"TOKIO_WORKER_THREADS": str(worker_count)}
            )
            variant_material = {
                "artifact": baseline_build["artifact"],
                "build_command_id": baseline_build["command_id"],
                "name": name,
                "run_environment_overrides": environment_overrides,
            }
            variants.append(
                {
                    **variant_material,
                    "candidate_opt_in": opt_in,
                    "variant_id": _identity(variant_material),
                }
            )
        candidate_description = {
            "allocator": None,
            "cargo_feature": None,
            "runtime_worker_counts": {
                "default": None,
                "physical_cores": physical_workers,
                "reduced": reduced_workers,
            },
        }
    else:
        if physical_workers is not None or reduced_workers is not None:
            raise CandidateControlError("worker counts are valid only for runtime")
        if (
            candidate_feature is None
            or SAFE_FEATURE.fullmatch(candidate_feature) is None
        ):
            raise CandidateControlError(
                f"{family} candidate requires an explicit Cargo feature opt-in"
            )
        if candidate_feature == "default":
            raise CandidateControlError("candidate Cargo feature cannot be default")
        if family == "allocator":
            candidate_allocator = _safe_name(candidate_allocator, "candidate_allocator")
        elif candidate_allocator is not None:
            raise CandidateControlError(
                "candidate_allocator is valid only for allocator experiments"
            )
        candidate_build = _build_command(
            name="candidate",
            repository=repository,
            target_dir=(target_root / "candidate").resolve(),
            package=package,
            binary_name=binary_name,
            artifact_name=artifact_name,
            target_triple=target_triple,
            feature=candidate_feature,
        )
        build_commands.append(candidate_build)
        for name, build, opt_in, run_environment in (
            ("baseline", baseline_build, False, {}),
            ("candidate", candidate_build, True, requested_candidate_environment),
        ):
            variant_material = {
                "artifact": build["artifact"],
                "build_command_id": build["command_id"],
                "name": name,
                "run_environment_overrides": run_environment,
            }
            variants.append(
                {
                    **variant_material,
                    "candidate_opt_in": opt_in,
                    "variant_id": _identity(variant_material),
                }
            )
        candidate_description = {
            "allocator": candidate_allocator,
            "cargo_feature": candidate_feature,
            "runtime_worker_counts": None,
        }
    run_commands = _run_rows(
        family=family,
        repository=repository,
        evidence_root=evidence_root,
        validation=validation,
        validation_sha256=validation_sha256,
        environment_id=environment["environment_id"],
        build_identity_id=environment["build_identity_id"],
        variants=variants,
    )
    matrix_without_id = {
        "build_commands": build_commands,
        "candidate": candidate_description,
        "collection_fields": COLLECTION_FIELDS[family],
        "decision_contract": {
            "adoption_claim": False,
            "candidate_enabled_by_default": False,
            "performance_thresholds": None,
            "results_are_observations_only": True,
        },
        "controlled_environment_prefix_removals": list(
            build_experiment.CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS
        ),
        "controlled_environment_removals": list(
            build_experiment.CONTROLLED_ENVIRONMENT_REMOVALS
        ),
        "environment": {
            "build_identity_id": environment["build_identity_id"],
            "environment_id": environment["environment_id"],
            "path": str(environment_path.resolve()),
            "sha256": environment_sha256,
        },
        "evidence_gate": {
            "acknowledged": True,
            "evidence": gate_evidence,
            "prerequisites": PREREQUISITES[family],
        },
        "experiment_family": family,
        "generated_at_utc": build_experiment._utc_now(),
        "run_commands": run_commands,
        "result_identity_contract": {
            "algorithm": "sha256-canonical-json",
            "required_fields": [
                "artifact_sha256",
                "build_command_id",
                "build_identity_id",
                "environment_id",
                "matrix_id",
                "raw_result_sha256",
                "result_identity_seed",
                "scenario",
                "validation_workloads_sha256",
                "variant_id",
            ],
        },
        "schema_version": SCHEMA_VERSION,
        "validation_workloads": build_experiment._workload_reference(
            validation_workloads_path, validation, validation_sha256
        ),
        "variants": variants,
    }
    identity_material = dict(matrix_without_id)
    identity_material.pop("generated_at_utc")
    matrix = {**matrix_without_id, "matrix_id": _identity(identity_material)}
    if len(_canonical_json_bytes(matrix)) > build_experiment.MAX_JSON_BYTES:
        raise CandidateControlError("generated Phase 4 matrix exceeds its size bound")
    return matrix


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    plan = commands.add_parser(
        "phase4-experiment-plan",
        help="write an opt-in metrics, runtime, or allocator evidence matrix",
    )
    plan.add_argument("--environment", required=True, type=pathlib.Path)
    plan.add_argument("--validation-workloads", required=True, type=pathlib.Path)
    plan.add_argument("--family", required=True, choices=FAMILIES)
    plan.add_argument("--target-root", required=True, type=pathlib.Path)
    plan.add_argument("--evidence-root", required=True, type=pathlib.Path)
    plan.add_argument("--package", required=True)
    plan.add_argument("--binary-name", required=True)
    plan.add_argument("--artifact-name", required=True)
    plan.add_argument("--target-triple")
    plan.add_argument("--candidate-feature")
    plan.add_argument("--candidate-env", action="append")
    plan.add_argument("--candidate-allocator")
    plan.add_argument("--physical-workers", type=int)
    plan.add_argument("--reduced-workers", type=int)
    plan.add_argument("--acknowledge-prerequisites", action="store_true")
    plan.add_argument("--prerequisite-evidence", action="append", required=True)
    plan.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    matrix = create_evidence_matrix(
        environment_path=parsed.environment,
        validation_workloads_path=parsed.validation_workloads,
        family=parsed.family,
        target_root=parsed.target_root,
        evidence_root=parsed.evidence_root,
        package=parsed.package,
        binary_name=parsed.binary_name,
        artifact_name=parsed.artifact_name,
        target_triple=parsed.target_triple,
        candidate_feature=parsed.candidate_feature,
        candidate_environment=parsed.candidate_env,
        candidate_allocator=parsed.candidate_allocator,
        physical_workers=parsed.physical_workers,
        reduced_workers=parsed.reduced_workers,
        acknowledge_prerequisites=parsed.acknowledge_prerequisites,
        prerequisite_evidence=parsed.prerequisite_evidence,
    )
    _atomic_text(
        parsed.output,
        json.dumps(matrix, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return 0
