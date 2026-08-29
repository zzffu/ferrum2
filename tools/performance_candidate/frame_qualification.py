"""Closed same-source Shadowsocks frame-size build qualification."""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import time
from collections.abc import Callable, Sequence

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux import trial as linux_trial
from tools.performance_candidate.linux.catalog import (
    SCENARIO_EVIDENCE,
    SCENARIO_WORKLOAD_SCALE,
)
from tools.performance_candidate.linux.evidence_contract import (
    catalog_evidence_contract,
    scale_evidence_contract,
)
from tools.performance_candidate.linux.scale import SCALE_RECIPE, SCALE_SCENARIO
from tools.performance_candidate.output import _atomic_text

POLICY_SCHEMA_VERSION = "ferrum2-performance-frame-policy-v1"
PLAN_SCHEMA_VERSION = "ferrum2-performance-frame-plan-v1"
BUILD_RECORD_SCHEMA_VERSION = "ferrum2-performance-frame-build-v1"
QUALIFICATION_SCHEMA_VERSION = "ferrum2-performance-frame-qualification-v1"
COMMANDS = frozenset(
    {
        "frame-plan",
        "frame-plan-items",
        "frame-build-run",
        "frame-trial-contract",
        "frame-qualification",
    }
)
AXIS_NAMES = ("default32", "frame16k", "frame65535", "adaptive")
ARTIFACT_NAMES = ("ferrum2-client", "ferrum2-server", "m4-qualification")
SCENARIO_NAMES = ("tcp-bulk", "tcp-request-1k", SCALE_SCENARIO)
EXPECTED_AXES = {
    "default32": {
        "adaptive_after_bytes": None,
        "cargo_features": [],
        "initial_payload_bytes": 32_768,
        "maximum_payload_bytes": 32_768,
        "name": "default32",
    },
    "frame16k": {
        "adaptive_after_bytes": None,
        "cargo_features": [
            "ferrum2-client/__frame-size-16k",
            "ferrum2-server/__frame-size-16k",
        ],
        "initial_payload_bytes": 16_384,
        "maximum_payload_bytes": 16_384,
        "name": "frame16k",
    },
    "frame65535": {
        "adaptive_after_bytes": None,
        "cargo_features": [
            "ferrum2-client/__frame-size-65535",
            "ferrum2-server/__frame-size-65535",
        ],
        "initial_payload_bytes": 65_535,
        "maximum_payload_bytes": 65_535,
        "name": "frame65535",
    },
    "adaptive": {
        "adaptive_after_bytes": 512 * 1024,
        "cargo_features": [
            "ferrum2-client/__frame-size-adaptive",
            "ferrum2-server/__frame-size-adaptive",
        ],
        "initial_payload_bytes": 32_768,
        "maximum_payload_bytes": 65_535,
        "name": "adaptive",
    },
}
EXPECTED_SCENARIOS = {
    "tcp-bulk": {
        "active_seconds": 15,
        "direction": "higher_is_better",
        "metric": "bytes_per_second",
        "name": "tcp-bulk",
        "observation_fields": ["value"],
        "warmup_seconds": 1,
    },
    "tcp-request-1k": {
        "active_seconds": 15,
        "direction": "lower_is_better",
        "metric": "p99_nanoseconds",
        "name": "tcp-request-1k",
        "observation_fields": ["value"],
        "warmup_seconds": 1,
    },
    SCALE_SCENARIO: {
        "active_seconds": 30,
        "direction": "higher_is_better",
        "metric": "bytes_per_second",
        "name": SCALE_SCENARIO,
        "observation_fields": [
            "value",
            "scale.fairness.jain_ppb",
            "scale.fairness.p01_to_median_ppm",
        ],
        "warmup_seconds": 10,
    },
}
HOSTED_SCOPE = {
    "adoption_claim": False,
    "bare_metal_gate_satisfied": False,
    "durable_evidence_gate_satisfied": False,
    "performance_authoritative": False,
    "scope": "github-hosted-amd-provisional",
}


def _load_policy(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="performance frame policy",
    )
    policy = bounded.value
    if type(policy) is not dict:
        raise CandidateControlError("performance frame policy must be an object")
    _exact_fields(
        policy,
        frozenset(
            {
                "axes",
                "hosted_scope",
                "policy_id",
                "scenarios",
                "schedule",
                "schema_version",
            }
        ),
        "performance frame policy",
    )
    if policy["schema_version"] != POLICY_SCHEMA_VERSION:
        raise CandidateControlError("performance frame policy schema is unsupported")
    if (
        type(policy["policy_id"]) is not str
        or build_experiment.SAFE_NAME.fullmatch(policy["policy_id"]) is None
    ):
        raise CandidateControlError("performance frame policy_id is invalid")
    axes = policy["axes"]
    if type(axes) is not list or len(axes) != len(AXIS_NAMES):
        raise CandidateControlError("performance frame axes are incomplete")
    observed_axes: dict[str, dict[str, object]] = {}
    for row in axes:
        if type(row) is not dict:
            raise CandidateControlError("performance frame axis must be an object")
        _exact_fields(
            row,
            frozenset(
                {
                    "adaptive_after_bytes",
                    "cargo_features",
                    "initial_payload_bytes",
                    "maximum_payload_bytes",
                    "name",
                }
            ),
            "performance frame axis",
        )
        name = row["name"]
        if type(name) is not str or name in observed_axes:
            raise CandidateControlError("performance frame axis name is invalid")
        observed_axes[name] = row
    if list(observed_axes) != list(AXIS_NAMES) or observed_axes != EXPECTED_AXES:
        raise CandidateControlError("performance frame axis contract changed")
    scenarios = policy["scenarios"]
    if type(scenarios) is not list or len(scenarios) != len(SCENARIO_NAMES):
        raise CandidateControlError("performance frame scenarios are incomplete")
    observed_scenarios: dict[str, dict[str, object]] = {}
    for row in scenarios:
        if type(row) is not dict:
            raise CandidateControlError("performance frame scenario must be an object")
        _exact_fields(
            row,
            frozenset(
                {
                    "active_seconds",
                    "direction",
                    "metric",
                    "name",
                    "observation_fields",
                    "warmup_seconds",
                }
            ),
            "performance frame scenario",
        )
        name = row["name"]
        if type(name) is not str or name in observed_scenarios:
            raise CandidateControlError("performance frame scenario name is invalid")
        observed_scenarios[name] = row
    if (
        list(observed_scenarios) != list(SCENARIO_NAMES)
        or observed_scenarios != EXPECTED_SCENARIOS
    ):
        raise CandidateControlError("performance frame scenario contract changed")
    if policy["schedule"] != {
        "a_a_rounds": 2,
        "pair_count": 6,
        "pair_schedule": "abba-six-pairs",
    }:
        raise CandidateControlError("performance frame schedule is invalid")
    if policy["hosted_scope"] != HOSTED_SCOPE:
        raise CandidateControlError("performance frame scope must remain provisional")
    return policy, bounded.sha256


def _scenario_contract(row: dict[str, object]) -> dict[str, object]:
    name = row["name"]
    if name == SCALE_SCENARIO:
        evidence = scale_evidence_contract()
        topology = "shadowsocks"
        payload = SCALE_RECIPE["payload_bytes"]
        workload_scale = None
        socks_bytes = None
        upstream_bytes = None
    else:
        evidence = catalog_evidence_contract(
            name,
            warmup_seconds=row["warmup_seconds"],
            active_seconds=row["active_seconds"],
            pair_schedule="abba-six-pairs",
        )
        topology, payload, socks_bytes, upstream_bytes = SCENARIO_EVIDENCE[name]
        workload_scale = SCENARIO_WORKLOAD_SCALE.get(name)
    return {
        **row,
        "application_payload_bytes": payload,
        "evidence_contract": evidence,
        "socks_datagram_bytes": socks_bytes,
        "topology": topology,
        "upstream_wire_bytes": upstream_bytes,
        "workload_scale": workload_scale,
    }


def _build_variants(
    *,
    repository: pathlib.Path,
    target_root: pathlib.Path,
    source_identity: dict[str, object],
    build_identity_id: str,
    axes: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    variants = []
    for axis in axes:
        target_dir = (target_root / axis["name"]).resolve()
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
        features = axis["cargo_features"]
        if features:
            argv.extend(("--features", ",".join(features)))
        artifact_root = target_dir / "profiling"
        material = {
            "artifact_paths": {
                name: str((artifact_root / name).resolve()) for name in ARTIFACT_NAMES
            },
            "argv": argv,
            "axis": axis,
            "build_identity_id": build_identity_id,
            "environment_overrides": {
                "CARGO_INCREMENTAL": "0",
                "RUSTUP_TOOLCHAIN": build_experiment.PINNED_RUST_RELEASE,
            },
            "repository": str(repository),
            "source_identity": source_identity,
            "target_dir": str(target_dir),
        }
        variants.append({**material, "variant_id": build_experiment._json_sha256(material)})
    return variants


def create_plan(
    *,
    environment_path: pathlib.Path,
    policy_path: pathlib.Path,
    target_root: pathlib.Path,
) -> dict[str, object]:
    environment, environment_sha256 = build_experiment._load_environment(environment_path)
    if (
        environment["environment_kind"] != "github-hosted"
        or environment["runner_image"] != "ubuntu-24.04"
        or environment["source_identity"]["comparison_axis"] != "build-artifact"
    ):
        raise CandidateControlError(
            "performance frame plans require a GitHub-hosted same-source environment"
        )
    policy, policy_sha256 = _load_policy(policy_path)
    repository = pathlib.Path(environment["repository"]).resolve()
    target_root = target_root.resolve()
    if (
        not repository.is_dir()
        or target_root == repository
        or target_root.is_relative_to(repository)
    ):
        raise CandidateControlError("performance frame target root is invalid")
    variants = _build_variants(
        repository=repository,
        target_root=target_root,
        source_identity=environment["source_identity"],
        build_identity_id=environment["build_identity_id"],
        axes=policy["axes"],
    )
    material = {
        "environment": {
            "build_identity_id": environment["build_identity_id"],
            "environment_id": environment["environment_id"],
            "path": str(environment_path.resolve()),
            "sha256": environment_sha256,
        },
        "hosted_scope": HOSTED_SCOPE,
        "policy": {
            "path": str(policy_path.resolve()),
            "policy_id": policy["policy_id"],
            "sha256": policy_sha256,
        },
        "scenarios": [_scenario_contract(row) for row in policy["scenarios"]],
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


def _load_plan(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="performance frame plan",
    )
    plan = bounded.value
    if type(plan) is not dict:
        raise CandidateControlError("performance frame plan must be an object")
    _exact_fields(
        plan,
        frozenset(
            {
                "environment",
                "generated_at_utc",
                "hosted_scope",
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
        "performance frame plan",
    )
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise CandidateControlError("performance frame plan schema is unsupported")
    if (
        type(plan["generated_at_utc"]) is not str
        or not plan["generated_at_utc"]
        or type(plan["target_root"]) is not str
        or not plan["target_root"]
        or type(plan["source_identity"]) is not dict
        or type(plan["variants"]) is not list
        or type(plan["scenarios"]) is not list
    ):
        raise CandidateControlError("performance frame plan values are invalid")
    plan_id = plan["plan_id"]
    material = dict(plan)
    material.pop("plan_id")
    material.pop("generated_at_utc")
    if type(plan_id) is not str or plan_id != build_experiment._json_sha256(material):
        raise CandidateControlError("performance frame plan_id does not reconstruct")
    if type(plan["environment"]) is not dict or type(plan["policy"]) is not dict:
        raise CandidateControlError("performance frame plan references are invalid")
    environment_path = pathlib.Path(plan["environment"].get("path", ""))
    environment, environment_sha256 = build_experiment._load_environment(environment_path)
    policy_path = pathlib.Path(plan["policy"].get("path", ""))
    policy, policy_sha256 = _load_policy(policy_path)
    if plan["environment"] != {
        "build_identity_id": environment["build_identity_id"],
        "environment_id": environment["environment_id"],
        "path": str(environment_path.resolve()),
        "sha256": environment_sha256,
    }:
        raise CandidateControlError("performance frame plan environment changed")
    if plan["policy"] != {
        "path": str(policy_path.resolve()),
        "policy_id": policy["policy_id"],
        "sha256": policy_sha256,
    }:
        raise CandidateControlError("performance frame plan policy changed")
    if (
        plan["source_identity"] != environment["source_identity"]
        or plan["schedule"] != policy["schedule"]
        or plan["hosted_scope"] != HOSTED_SCOPE
        or plan["scenarios"]
        != [_scenario_contract(row) for row in policy["scenarios"]]
    ):
        raise CandidateControlError("performance frame plan contract changed")
    expected_variants = _build_variants(
        repository=pathlib.Path(environment["repository"]).resolve(),
        target_root=pathlib.Path(plan["target_root"]).resolve(),
        source_identity=environment["source_identity"],
        build_identity_id=environment["build_identity_id"],
        axes=policy["axes"],
    )
    if plan["variants"] != expected_variants:
        raise CandidateControlError("performance frame variants changed")
    return plan, bounded.sha256


def _variant(plan: dict[str, object], name: str) -> dict[str, object]:
    matches = [row for row in plan["variants"] if row["axis"]["name"] == name]
    if len(matches) != 1:
        raise CandidateControlError("performance frame variant is not present exactly once")
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
    plan, plan_sha256 = _load_plan(plan_path)
    variant = _variant(plan, variant_name)
    environment_path = pathlib.Path(plan["environment"]["path"])
    environment, environment_sha256 = build_experiment._load_environment(environment_path)
    if environment_sha256 != plan["environment"]["sha256"]:
        raise CandidateControlError("performance frame build environment changed")
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
        raise CandidateControlError("performance frame build host or identity changed")
    target_dir = pathlib.Path(variant["target_dir"])
    if target_dir.exists():
        raise CandidateControlError("performance frame build target must be fresh")
    effective_environment = build_experiment._effective_environment(
        build_experiment.CONTROLLED_ENVIRONMENT_REMOVALS,
        build_experiment.CONTROLLED_ENVIRONMENT_PREFIX_REMOVALS,
        variant["environment_overrides"],
    )
    started = clock()
    returncode = executor(
        variant["argv"],
        pathlib.Path(variant["repository"]),
        effective_environment,
        log_path,
    )
    elapsed = clock() - started
    if type(returncode) is not int or returncode != 0 or elapsed < 0:
        raise CandidateControlError("performance frame build failed")
    artifacts = []
    for name in ARTIFACT_NAMES:
        path = pathlib.Path(variant["artifact_paths"][name]).resolve()
        if not path.is_relative_to(target_dir) or not path.is_file() or path.is_symlink():
            raise CandidateControlError("performance frame artifact is unavailable")
        artifacts.append(
            {
                "name": name,
                "path": str(path),
                "sha256": build_experiment._file_sha256(path, field=f"frame artifact {name}"),
                "size_bytes": path.stat().st_size,
            }
        )
    material = {
        "artifacts": artifacts,
        "build_identity_id": environment["build_identity_id"],
        "command": {
            "argv": variant["argv"],
            "environment_overrides": variant["environment_overrides"],
            "repository": variant["repository"],
            "target_dir": variant["target_dir"],
        },
        "elapsed_nanoseconds": elapsed,
        "environment_id": environment["environment_id"],
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "schema_version": BUILD_RECORD_SCHEMA_VERSION,
        "source_identity": environment["source_identity"],
        "variant_id": variant["variant_id"],
        "variant_name": variant_name,
    }
    return {**material, "record_id": build_experiment._json_sha256(material)}, returncode


def _load_build_record(
    path: pathlib.Path,
    *,
    plan: dict[str, object],
    plan_sha256: str,
    expected_variant: str,
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="performance frame build record",
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("performance frame build record must be an object")
    _exact_fields(
        row,
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
        "performance frame build record",
    )
    material = dict(row)
    record_id = material.pop("record_id")
    variant = _variant(plan, expected_variant)
    if (
        row["schema_version"] != BUILD_RECORD_SCHEMA_VERSION
        or row["plan_id"] != plan["plan_id"]
        or row["plan_sha256"] != plan_sha256
        or row["variant_name"] != expected_variant
        or row["variant_id"] != variant["variant_id"]
        or row["source_identity"] != plan["source_identity"]
        or row["build_identity_id"] != plan["environment"]["build_identity_id"]
        or row["environment_id"] != plan["environment"]["environment_id"]
        or type(row["elapsed_nanoseconds"]) is not int
        or row["elapsed_nanoseconds"] < 0
        or type(record_id) is not str
        or record_id != build_experiment._json_sha256(material)
    ):
        raise CandidateControlError("performance frame build record identity is invalid")
    expected_command = {
        "argv": variant["argv"],
        "environment_overrides": variant["environment_overrides"],
        "repository": variant["repository"],
        "target_dir": variant["target_dir"],
    }
    if row["command"] != expected_command:
        raise CandidateControlError("performance frame build command changed")
    artifacts = row["artifacts"]
    if type(artifacts) is not list or len(artifacts) != len(ARTIFACT_NAMES):
        raise CandidateControlError("performance frame artifact set is incomplete")
    observed = {}
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise CandidateControlError("performance frame artifact must be an object")
        _exact_fields(
            artifact,
            frozenset({"name", "path", "sha256", "size_bytes"}),
            "performance frame artifact",
        )
        name = artifact["name"]
        path_value = artifact["path"]
        if (
            name not in ARTIFACT_NAMES
            or name in observed
            or type(path_value) is not str
            or pathlib.Path(path_value).resolve()
            != pathlib.Path(variant["artifact_paths"][name]).resolve()
            or type(artifact["sha256"]) is not str
            or SHA256.fullmatch(artifact["sha256"]) is None
            or type(artifact["size_bytes"]) is not int
            or artifact["size_bytes"] <= 0
        ):
            raise CandidateControlError("performance frame artifact identity is invalid")
        artifact_path = pathlib.Path(path_value)
        if (
            not artifact_path.is_file()
            or artifact_path.is_symlink()
            or artifact_path.stat().st_size != artifact["size_bytes"]
            or build_experiment._file_sha256(
                artifact_path, field=f"frame artifact {name}"
            )
            != artifact["sha256"]
        ):
            raise CandidateControlError("performance frame artifact changed after build")
        observed[name] = artifact
    if tuple(observed) != ARTIFACT_NAMES:
        raise CandidateControlError("performance frame artifact roles changed")
    return row, bounded.sha256


def _artifact_map(record: dict[str, object]) -> dict[str, dict[str, object]]:
    return {row["name"]: row for row in record["artifacts"]}


def _planned_scenario(plan: dict[str, object], name: str) -> dict[str, object]:
    matches = [row for row in plan["scenarios"] if row["name"] == name]
    if len(matches) != 1:
        raise CandidateControlError("performance frame scenario is not present exactly once")
    return matches[0]


def _trial_observation(row: dict[str, object], field: str) -> int:
    if field == "value":
        value = row["value"]
    elif field == "scale.fairness.jain_ppb":
        value = row["scale"]["fairness"]["jain_ppb"]
    elif field == "scale.fairness.p01_to_median_ppm":
        value = row["scale"]["fairness"]["p01_to_median_ppm"]
    else:
        raise CandidateControlError("performance frame observation field is invalid")
    if type(value) is not int or value < 0:
        raise CandidateControlError("performance frame observation value is invalid")
    return value


def _improvement(parent: int, candidate: int, direction: str) -> float:
    if parent <= 0:
        raise CandidateControlError("performance frame comparison baseline must be positive")
    if direction == "higher_is_better":
        return (candidate - parent) * 100.0 / parent
    if direction == "lower_is_better":
        return (parent - candidate) * 100.0 / parent
    raise CandidateControlError("performance frame metric direction is invalid")


def _validate_round(
    *,
    root: pathlib.Path,
    plan: dict[str, object],
    parent_record: dict[str, object],
    candidate_record: dict[str, object],
    round_kind: str,
) -> dict[str, object]:
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise CandidateControlError("performance frame evidence round is unavailable")
    directories = {path.name for path in root.iterdir() if path.is_dir()}
    if directories != {"parent", "candidate"} or any(
        path.is_symlink() for path in root.iterdir()
    ):
        raise CandidateControlError("performance frame evidence member directories changed")
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    if not paths or any(path.suffix != ".jsonl" or path.is_symlink() for path in paths):
        raise CandidateControlError("performance frame evidence file set is invalid")
    source = plan["source_identity"]
    artifact_records = {"parent": parent_record, "candidate": candidate_record}
    seen: dict[tuple[str, int, str], dict[str, object]] = {}
    environment_identity = None
    evidence_files = []
    for path in paths:
        member = path.parent.name
        if member not in artifact_records or path.parent.parent != root:
            raise CandidateControlError("performance frame evidence path escaped its member")
        row = linux_trial._read_trial(path)
        scenario_name = row.get("scenario")
        if scenario_name not in SCENARIO_NAMES:
            raise CandidateControlError("performance frame evidence scenario is invalid")
        scenario = _planned_scenario(plan, scenario_name)
        fake_plan = {
            "active_seconds": scenario["active_seconds"],
            "pairs": plan["schedule"]["pair_count"],
            "warmup_seconds": scenario["warmup_seconds"],
        }
        linux_trial._validate_trial(
            row,
            source_member=member,
            plan=fake_plan,
            planned={scenario_name: scenario},
            parent_sha=source["source_sha"],
            candidate_sha=source["source_sha"],
        )
        pair = row["pair"]
        expected_order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        artifacts = _artifact_map(artifact_records[member])
        key = (scenario_name, pair, member)
        if (
            key in seen
            or row["order"] != expected_order
            or row["tree"] != source["source_tree"]
            or row["runner_sha256"] != artifacts["m4-qualification"]["sha256"]
            or row["client_sha256"] != artifacts["ferrum2-client"]["sha256"]
            or row["server_sha256"] != artifacts["ferrum2-server"]["sha256"]
        ):
            raise CandidateControlError("performance frame trial identity is invalid")
        current_environment = row["environment_identity"]
        cpu_model = current_environment.get("cpu_model")
        if type(cpu_model) is not str or "AMD" not in cpu_model.upper():
            raise CandidateControlError("performance frame qualification requires an AMD host")
        if environment_identity is None:
            environment_identity = current_environment
        elif current_environment != environment_identity:
            raise CandidateControlError("performance frame host changed within a round")
        seen[key] = row
        evidence_files.append(
            {
                "member": member,
                "path": str(path),
                "sha256": build_experiment._file_sha256(path, field="frame trial"),
            }
        )
    expected = {
        (scenario, pair, member)
        for scenario in SCENARIO_NAMES
        for pair in range(1, 7)
        for member in ("parent", "candidate")
    }
    if set(seen) != expected:
        raise CandidateControlError("performance frame evidence round is incomplete")
    observations = []
    for scenario_name in SCENARIO_NAMES:
        scenario = _planned_scenario(plan, scenario_name)
        for field in scenario["observation_fields"]:
            deltas = [
                _improvement(
                    _trial_observation(seen[(scenario_name, pair, "parent")], field),
                    _trial_observation(seen[(scenario_name, pair, "candidate")], field),
                    scenario["direction"],
                )
                for pair in range(1, 7)
            ]
            observations.append(
                {
                    "direction": scenario["direction"],
                    "field": field,
                    "median_improvement_percent": statistics.median(deltas),
                    "pair_improvements_percent": deltas,
                    "scenario": scenario_name,
                }
            )
    return {
        "environment_identity": environment_identity,
        "evidence_files": evidence_files,
        "observations": observations,
        "round_kind": round_kind,
    }


def create_qualification(
    *,
    plan_path: pathlib.Path,
    axis: str,
    baseline_build_path: pathlib.Path,
    candidate_build_path: pathlib.Path,
    a_a_roots: Sequence[pathlib.Path],
    comparison_root: pathlib.Path,
) -> dict[str, object]:
    if axis not in AXIS_NAMES:
        raise CandidateControlError("performance frame axis is invalid")
    plan, plan_sha256 = _load_plan(plan_path)
    baseline, baseline_sha256 = _load_build_record(
        baseline_build_path,
        plan=plan,
        plan_sha256=plan_sha256,
        expected_variant="default32",
    )
    candidate, candidate_sha256 = _load_build_record(
        candidate_build_path,
        plan=plan,
        plan_sha256=plan_sha256,
        expected_variant=axis,
    )
    if len(a_a_roots) != plan["schedule"]["a_a_rounds"]:
        raise CandidateControlError("performance frame qualification requires two A/A rounds")
    a_a_rounds = [
        _validate_round(
            root=root,
            plan=plan,
            parent_record=candidate,
            candidate_record=candidate,
            round_kind=f"a-a-{index}",
        )
        for index, root in enumerate(a_a_roots, start=1)
    ]
    comparison = _validate_round(
        root=comparison_root,
        plan=plan,
        parent_record=baseline,
        candidate_record=candidate,
        round_kind="comparison",
    )
    environments = [row["environment_identity"] for row in a_a_rounds] + [
        comparison["environment_identity"]
    ]
    if any(environment != environments[0] for environment in environments[1:]):
        raise CandidateControlError("performance frame host changed between rounds")
    calibration = []
    for scenario_name in SCENARIO_NAMES:
        scenario = _planned_scenario(plan, scenario_name)
        for field in scenario["observation_fields"]:
            medians = [
                next(
                    observation["median_improvement_percent"]
                    for observation in round_row["observations"]
                    if observation["scenario"] == scenario_name
                    and observation["field"] == field
                )
                for round_row in a_a_rounds
            ]
            calibration.append(
                {
                    "field": field,
                    "max_absolute_a_a_delta_percent": max(abs(value) for value in medians),
                    "round_medians_percent": medians,
                    "scenario": scenario_name,
                }
            )
    material = {
        "a_a_rounds": a_a_rounds,
        "adoption_decision": "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        "axis": axis,
        "bare_metal_gate_satisfied": False,
        "build_records": {
            "baseline": {
                "path": str(baseline_build_path.resolve()),
                "record_id": baseline["record_id"],
                "sha256": baseline_sha256,
            },
            "candidate": {
                "path": str(candidate_build_path.resolve()),
                "record_id": candidate["record_id"],
                "sha256": candidate_sha256,
            },
        },
        "calibration_candidate": calibration,
        "comparison": comparison,
        "durable_evidence_gate_satisfied": False,
        "performance_authoritative": False,
        "plan": {
            "path": str(plan_path.resolve()),
            "plan_id": plan["plan_id"],
            "sha256": plan_sha256,
        },
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "scope": "github-hosted-amd-provisional",
        "source_identity": plan["source_identity"],
        "status": "PASS",
        "variants": {
            "baseline": baseline["variant_id"],
            "candidate": candidate["variant_id"],
        },
    }
    return {
        **material,
        "generated_at_utc": build_experiment._utc_now(),
        "record_id": build_experiment._json_sha256(material),
    }


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    plan = commands.add_parser(
        "frame-plan", help="write the closed same-source frame-size build plan"
    )
    plan.add_argument("--environment", required=True, type=pathlib.Path)
    plan.add_argument("--policy", required=True, type=pathlib.Path)
    plan.add_argument("--target-root", required=True, type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    items = commands.add_parser(
        "frame-plan-items", help="emit the exact closed frame axis names"
    )
    items.add_argument("--plan", required=True, type=pathlib.Path)
    build = commands.add_parser(
        "frame-build-run", help="run and record one exact frame-size artifact build"
    )
    build.add_argument("--plan", required=True, type=pathlib.Path)
    build.add_argument("--variant", required=True, choices=AXIS_NAMES)
    build.add_argument("--log", required=True, type=pathlib.Path)
    build.add_argument("--output", required=True, type=pathlib.Path)
    contract = commands.add_parser(
        "frame-trial-contract", help="emit one plan-bound frame trial contract"
    )
    contract.add_argument("--plan", required=True, type=pathlib.Path)
    contract.add_argument("--scenario", required=True, choices=SCENARIO_NAMES)
    qualification = commands.add_parser(
        "frame-qualification",
        help="validate two candidate A/A rounds and one same-source six-pair A/B round",
    )
    qualification.add_argument("--plan", required=True, type=pathlib.Path)
    qualification.add_argument("--axis", required=True, choices=AXIS_NAMES)
    qualification.add_argument(
        "--baseline-build", required=True, type=pathlib.Path
    )
    qualification.add_argument(
        "--candidate-build", required=True, type=pathlib.Path
    )
    qualification.add_argument(
        "--a-a-root", action="append", required=True, type=pathlib.Path
    )
    qualification.add_argument("--comparison-root", required=True, type=pathlib.Path)
    qualification.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    if parsed.command == "frame-plan":
        row = create_plan(
            environment_path=parsed.environment,
            policy_path=parsed.policy,
            target_root=parsed.target_root,
        )
        _atomic_text(
            parsed.output,
            json.dumps(row, sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        return 0
    if parsed.command == "frame-plan-items":
        plan, _ = _load_plan(parsed.plan)
        for row in plan["variants"]:
            print(row["axis"]["name"])
        return 0
    if parsed.command == "frame-build-run":
        row, returncode = run_build(
            plan_path=parsed.plan,
            variant_name=parsed.variant,
            log_path=parsed.log,
        )
        _atomic_text(
            parsed.output,
            json.dumps(row, sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        return returncode
    if parsed.command == "frame-trial-contract":
        plan, _ = _load_plan(parsed.plan)
        contract = _planned_scenario(plan, parsed.scenario)["evidence_contract"]
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
        return 0
    if parsed.command == "frame-qualification":
        row = create_qualification(
            plan_path=parsed.plan,
            axis=parsed.axis,
            baseline_build_path=parsed.baseline_build,
            candidate_build_path=parsed.candidate_build,
            a_a_roots=parsed.a_a_root,
            comparison_root=parsed.comparison_root,
        )
        _atomic_text(
            parsed.output,
            json.dumps(row, sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        return 0
    raise CandidateControlError("unsupported performance frame command")
