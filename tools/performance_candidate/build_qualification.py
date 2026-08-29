"""Same-source build-artifact qualification and provisional adoption records."""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
from collections.abc import Sequence

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import trial as linux_trial
from tools.performance_candidate.linux.evidence_contract import (
    catalog_evidence_contract,
)
from tools.performance_candidate.output import _atomic_text

POLICY_SCHEMA_VERSION = "ferrum2-performance-build-policy-v1"
QUALIFICATION_SCHEMA_VERSION = "ferrum2-build-qualification-v1"
COMMANDS = frozenset({"build-qualification"})
REQUIRED_ARTIFACTS = frozenset(
    {
        "ferrum2-client",
        "ferrum2-rule-qualification",
        "ferrum2-server",
        "m4-qualification",
    }
)
EXPERIMENT_CANDIDATE_PHASE = {
    "thin-lto-cgu1": "thin-lto-cgu1",
    "pgo": "pgo-use",
    "target-cpu": "target-cpu",
}


def _load_policy(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="performance build policy",
    )
    policy = bounded.value
    if type(policy) is not dict:
        raise CandidateControlError("performance build policy must be an object")
    _exact_fields(
        policy,
        frozenset(
            {
                "experiment_kinds",
                "hosted_scope",
                "policy_id",
                "scenarios",
                "schedule",
                "schema_version",
                "thresholds",
            }
        ),
        "performance build policy",
    )
    if policy["schema_version"] != POLICY_SCHEMA_VERSION:
        raise CandidateControlError("performance build policy schema is unsupported")
    if policy["experiment_kinds"] != sorted(EXPERIMENT_CANDIDATE_PHASE):
        raise CandidateControlError(
            "performance build policy experiment set is invalid"
        )
    schedule = policy["schedule"]
    if type(schedule) is not dict:
        raise CandidateControlError("performance build schedule is invalid")
    _exact_fields(
        schedule,
        frozenset(
            {
                "a_a_rounds",
                "active_seconds",
                "pair_count",
                "pair_schedule",
                "warmup_seconds",
            }
        ),
        "performance build schedule",
    )
    if (
        schedule["a_a_rounds"] != 2
        or schedule["pair_count"] != 6
        or schedule["pair_schedule"] != "abba-six-pairs"
        or type(schedule["warmup_seconds"]) is not int
        or schedule["warmup_seconds"] <= 0
        or type(schedule["active_seconds"]) is not int
        or schedule["active_seconds"] <= 0
    ):
        raise CandidateControlError("performance build schedule values are invalid")
    scope = policy["hosted_scope"]
    if type(scope) is not dict:
        raise CandidateControlError("performance build hosted scope is invalid")
    _exact_fields(
        scope,
        frozenset(
            {
                "adoption_claim",
                "bare_metal_gate_satisfied",
                "durable_evidence_gate_satisfied",
                "performance_authoritative",
                "scope",
            }
        ),
        "performance build hosted scope",
    )
    if scope != {
        "adoption_claim": False,
        "bare_metal_gate_satisfied": False,
        "durable_evidence_gate_satisfied": False,
        "performance_authoritative": False,
        "scope": "github-hosted-amd-provisional",
    }:
        raise CandidateControlError(
            "performance build hosted scope must remain provisional"
        )
    scenarios = policy["scenarios"]
    if type(scenarios) is not list or not 1 <= len(scenarios) <= 32:
        raise CandidateControlError("performance build scenarios are invalid")
    names: set[str] = set()
    for scenario in scenarios:
        if type(scenario) is not dict:
            raise CandidateControlError("performance build scenario must be an object")
        _exact_fields(
            scenario,
            frozenset({"direction", "metric", "name", "unit"}),
            "performance build scenario",
        )
        if (
            type(scenario["name"]) is not str
            or build_experiment.SAFE_NAME.fullmatch(scenario["name"]) is None
            or scenario["name"] in names
            or scenario["direction"] not in {"higher_is_better", "lower_is_better"}
            or type(scenario["metric"]) is not str
            or not scenario["metric"]
            or type(scenario["unit"]) is not str
            or not scenario["unit"]
        ):
            raise CandidateControlError("performance build scenario values are invalid")
        names.add(scenario["name"])
    thresholds = policy["thresholds"]
    if type(thresholds) is not dict:
        raise CandidateControlError("performance build thresholds are invalid")
    _exact_fields(
        thresholds,
        frozenset({"max_regression_percent", "minimum_beneficial_scenarios"}),
        "performance build thresholds",
    )
    if (
        type(thresholds["max_regression_percent"]) not in {int, float}
        or thresholds["max_regression_percent"] <= 0
        or type(thresholds["minimum_beneficial_scenarios"]) is not int
        or not 1 <= thresholds["minimum_beneficial_scenarios"] <= len(scenarios)
    ):
        raise CandidateControlError("performance build threshold values are invalid")
    if (
        type(policy["policy_id"]) is not str
        or build_experiment.SAFE_NAME.fullmatch(policy["policy_id"]) is None
    ):
        raise CandidateControlError("performance build policy_id is invalid")
    return policy, bounded.sha256


def _phase_records(
    plan: dict[str, object],
    plan_sha256: str,
    paths: Sequence[pathlib.Path],
) -> dict[str, tuple[dict[str, object], str]]:
    expected = {"baseline", EXPERIMENT_CANDIDATE_PHASE[plan["experiment_kind"]]}
    if plan["experiment_kind"] == "pgo":
        expected |= {"pgo-generate", "pgo-merge"}
    records: dict[str, tuple[dict[str, object], str]] = {}
    for path in paths:
        bounded = read_bounded_closed_json(
            path,
            maximum_bytes=build_experiment.MAX_JSON_BYTES,
            source="build phase record",
        )
        value = bounded.value
        if type(value) is not dict or type(value.get("phase")) is not str:
            raise CandidateControlError("build phase record phase is invalid")
        phase = value["phase"]
        if phase not in expected or phase in records:
            raise CandidateControlError("build phase record set is not closed")
        records[phase] = build_experiment._load_phase_record(
            path, plan_id=plan["plan_id"], plan_sha256=plan_sha256, phase=phase
        )
    if set(records) != expected:
        raise CandidateControlError("build phase record set is incomplete")
    return records


def _pgo_validation_records(
    plan: dict[str, object],
    plan_sha256: str,
    paths: Sequence[pathlib.Path],
) -> list[dict[str, object]]:
    if plan["experiment_kind"] != "pgo":
        if paths:
            raise CandidateControlError("PGO validation records apply only to PGO")
        return []
    expected = {row["command_id"] for row in plan["pgo"]["validation_commands"]}
    records: dict[str, dict[str, object]] = {}
    for path in paths:
        bounded = read_bounded_closed_json(
            path,
            maximum_bytes=build_experiment.MAX_JSON_BYTES,
            source="PGO validation record",
        )
        row = bounded.value
        fields = frozenset(
            {
                "command_id",
                "elapsed_nanoseconds",
                "external_requirement_satisfied",
                "exit_code",
                "finished_at_utc",
                "log",
                "phase_record_sha256",
                "plan_id",
                "plan_sha256",
                "record_id",
                "schema_version",
                "started_at_utc",
                "status",
                "validation_coverage",
                "variant",
            }
        )
        if type(row) is not dict:
            raise CandidateControlError("PGO validation record must be an object")
        _exact_fields(row, fields, "PGO validation record")
        command_id = row["command_id"]
        material = dict(row)
        record_id = material.pop("record_id")
        if (
            command_id not in expected
            or command_id in records
            or row["schema_version"]
            != build_experiment.VALIDATION_RECORD_SCHEMA_VERSION
            or row["plan_id"] != plan["plan_id"]
            or row["plan_sha256"] != plan_sha256
            or row["status"] != "succeeded"
            or row["exit_code"] != 0
            or record_id != build_experiment._json_sha256(material)
        ):
            raise CandidateControlError("PGO validation record identity is invalid")
        records[command_id] = {
            "command_id": command_id,
            "path": str(path.resolve()),
            "record_id": record_id,
            "sha256": bounded.sha256,
            "validation_coverage": row["validation_coverage"],
            "variant": row["variant"],
            "external_requirement_satisfied": row["external_requirement_satisfied"],
        }
    if set(records) != expected:
        raise CandidateControlError(
            "PGO independent validation record set is incomplete"
        )
    coverage = sorted(row["validation_coverage"] for row in records.values())
    if coverage != sorted(
        coverage_name
        for coverage_name in (
            "representative",
            "cold-path",
            "error-path",
            "different-cpu",
        )
        for _ in range(2)
    ):
        raise CandidateControlError("PGO validation coverage is incomplete")
    for row in records.values():
        expected_satisfied = row["validation_coverage"] != "different-cpu"
        if row["external_requirement_satisfied"] is not expected_satisfied:
            raise CandidateControlError("PGO external validation closure is invalid")
    return [records[key] for key in sorted(records)]


def _variant(
    *,
    name: str,
    source_identity: dict[str, object],
    plan: dict[str, object],
    phase: dict[str, object],
    phase_record: dict[str, object],
    phase_record_sha256: str,
) -> dict[str, object]:
    expected_command = {
        "argv": phase["argv"],
        "environment_overrides": phase["environment_overrides"],
        "repository": phase["repository"],
    }
    if (
        phase_record["build_identity_id"] != plan["environment"]["build_identity_id"]
        or phase_record["environment_id"] != plan["environment"]["environment_id"]
        or phase_record["phase_type"] != phase["phase_type"]
        or phase_record["command"] != expected_command
    ):
        raise CandidateControlError("build variant phase record differs from its plan")
    artifact_rows = phase_record["artifacts"]
    if type(artifact_rows) is not list:
        raise CandidateControlError("build variant artifacts are invalid")
    expected_artifacts = dict(
        zip(plan["artifact_names"], phase["artifacts"], strict=True)
    )
    target_dir = pathlib.Path(phase["target_dir"]).resolve()
    artifacts: dict[str, dict[str, object]] = {}
    for row in artifact_rows:
        if type(row) is not dict:
            raise CandidateControlError("build variant artifact must be an object")
        _exact_fields(
            row,
            frozenset({"name", "path", "relative_path", "sha256", "size_bytes"}),
            "build variant artifact",
        )
        artifact_name = row["name"]
        relative_path = row["relative_path"]
        path_value = row["path"]
        if type(relative_path) is not str or type(path_value) is not str:
            raise CandidateControlError("build variant artifact identity is invalid")
        artifact_path = pathlib.Path(path_value)
        resolved_path = artifact_path.resolve()
        if (
            artifact_name not in REQUIRED_ARTIFACTS
            or artifact_name in artifacts
            or relative_path != expected_artifacts.get(artifact_name)
            or resolved_path != (target_dir / relative_path).resolve()
            or not resolved_path.is_relative_to(target_dir)
            or artifact_path.is_symlink()
            or not resolved_path.is_file()
            or type(row["sha256"]) is not str
            or SHA256.fullmatch(row["sha256"]) is None
            or type(row["size_bytes"]) is not int
            or row["size_bytes"] <= 0
            or resolved_path.stat().st_size != row["size_bytes"]
            or build_experiment._file_sha256(
                resolved_path, field=f"build variant artifact {artifact_name}"
            )
            != row["sha256"]
        ):
            raise CandidateControlError("build variant artifact identity is invalid")
        artifacts[artifact_name] = {
            "path": str(resolved_path),
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
        }
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise CandidateControlError("build variant artifact roles are incomplete")
    rustflags = phase["environment_overrides"].get("CARGO_ENCODED_RUSTFLAGS", "")
    material = {
        "artifacts": {
            role: {key: row[key] for key in ("sha256", "size_bytes")}
            for role, row in sorted(artifacts.items())
        },
        "phase": phase["name"],
        "phase_record_sha256": phase_record_sha256,
        "plan_id": plan["plan_id"],
        "profile": phase["profile"],
        "rustflags": rustflags,
        "source_sha": source_identity["source_sha"],
        "source_tree": source_identity["source_tree"],
    }
    return {
        **material,
        "name": name,
        "variant_id": build_experiment._json_sha256(material),
    }


def _trial_delta(parent: int, candidate: int, direction: str) -> float:
    if parent <= 0 or candidate < 0:
        raise CandidateControlError("build trial metric value is invalid")
    if direction == "higher_is_better":
        return (candidate - parent) * 100.0 / parent
    return (parent - candidate) * 100.0 / parent


def _validate_evidence_round(
    *,
    root: pathlib.Path,
    source_identity: dict[str, object],
    variants: dict[str, dict[str, object]],
    member_variants: dict[str, str],
    policy: dict[str, object],
    round_kind: str,
) -> dict[str, object]:
    scenario_policy = {row["name"]: row for row in policy["scenarios"]}
    schedule = policy["schedule"]
    expected_source_contracts = {
        scenario: catalog_evidence_contract(
            scenario,
            warmup_seconds=schedule["warmup_seconds"],
            active_seconds=schedule["active_seconds"],
            pair_schedule=schedule["pair_schedule"],
        )
        for scenario in scenario_policy
    }
    seen: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, object]] = []
    environment_identity: dict[str, object] | None = None
    for member in ("parent", "candidate"):
        member_root = root / member
        try:
            paths = sorted(member_root.glob("*.jsonl"))
        except OSError as error:
            raise CandidateControlError("unable to enumerate build evidence") from error
        for path in paths:
            row = linux_trial._read_trial(path)
            scenario = row["scenario"]
            pair = row["pair"]
            key = (scenario, pair, member)
            if (
                row["schema_version"] != linux_trial.PROFILE_TRIAL_SCHEMA_VERSION
                or row["kind"] != "m18_profile_trial"
                or scenario not in scenario_policy
                or key in seen
                or row["member"] != member
                or type(pair) is not int
                or not 1 <= pair <= 6
                or row["parent_sha"] != source_identity["source_sha"]
                or row["candidate_sha"] != source_identity["source_sha"]
                or row["sha"] != source_identity["source_sha"]
                or row["tree"] != source_identity["source_tree"]
                or row["build_profile"] != "current"
                or row["warmup_seconds"] != schedule["warmup_seconds"]
                or row["active_seconds"] != schedule["active_seconds"]
                or row["metric"] != scenario_policy[scenario]["metric"]
                or row["unit"] != scenario_policy[scenario]["unit"]
                or row["correctness"] != "PASS"
                or row["status"] != "PASS"
                or type(row["value"]) is not int
                or row["value"] < 0
            ):
                raise CandidateControlError("build evidence trial identity is invalid")
            topology, payload, socks_bytes, upstream_bytes = (
                linux_catalog.SCENARIO_EVIDENCE[scenario]
            )
            if (
                row["topology"] != topology
                or row["application_payload_bytes"] != payload
                or row["workload_scale"]
                != linux_catalog.SCENARIO_WORKLOAD_SCALE.get(scenario)
                or row["socks_datagram_bytes"] != socks_bytes
                or row["upstream_wire_bytes"] != upstream_bytes
                or row["scale"] is not None
                or type(row["checked_units"]) is not int
                or row["checked_units"] <= 0
                or type(row["io_completions"]) is not int
                or row["io_completions"] < 0
            ):
                raise CandidateControlError(
                    "build evidence workload contract is invalid"
                )
            if row["metric"] == "p99_nanoseconds":
                if row["p99_nanoseconds"] != row["value"] or row["value"] <= 0:
                    raise CandidateControlError(
                        "build request latency evidence is invalid"
                    )
            elif row["p99_nanoseconds"] is not None:
                raise CandidateControlError("build throughput evidence has a p99 value")
            expected_contract = expected_source_contracts[scenario]
            if any(
                row[field] != expected_contract[field]
                for field in (
                    "producer_source_sha256",
                    "controller_source_sha256",
                    "semantic_recipe_sha256",
                    "evidence_bundle_sha256",
                )
            ):
                raise CandidateControlError("build evidence source contract is invalid")
            expected_order = 1 if (pair % 2 == 1) == (member == "parent") else 2
            if row["order"] != expected_order:
                raise CandidateControlError(
                    "build evidence does not follow six-pair ABBA"
                )
            variant = variants[member_variants[member]]
            artifacts = variant["artifacts"]
            if (
                row["runner_sha256"] != artifacts["m4-qualification"]["sha256"]
                or row["client_sha256"] != artifacts["ferrum2-client"]["sha256"]
                or row["server_sha256"] != artifacts["ferrum2-server"]["sha256"]
            ):
                raise CandidateControlError("build evidence does not match its variant")
            if row["cleanup"] != {
                "active_processes": 0,
                "active_workers": 0,
                "ready_file_removed": True,
                "status": "PASS",
            }:
                raise CandidateControlError("build evidence cleanup is incomplete")
            linux_trial._validate_structural_metrics(row, scenario)
            current_environment = row["environment_identity"]
            if type(current_environment) is not dict:
                raise CandidateControlError("build evidence environment is invalid")
            expected_environment = {
                "runner_image": "ubuntu-24.04",
                "rustc": row["rustc"],
                "kernel": row["kernel"],
                "cpu_model": row["cpu_model"],
                "cpu_count": row["cpu_count"],
                "memory_kib": row["memory_kib"],
                "build_profile": "current",
            }
            if current_environment != expected_environment:
                raise CandidateControlError(
                    "build evidence environment identity is invalid"
                )
            if environment_identity is None:
                environment_identity = current_environment
                cpu_model = current_environment.get("cpu_model")
                if type(cpu_model) is not str or "AMD" not in cpu_model.upper():
                    raise CandidateControlError("build evidence requires an AMD host")
            elif current_environment != environment_identity:
                raise CandidateControlError(
                    "build evidence environment changed within a round"
                )
            seen[key] = row
            evidence_files.append(
                {
                    "member": member,
                    "path": str(path.resolve()),
                    "sha256": build_experiment._file_sha256(
                        path, field="build evidence trial"
                    ),
                }
            )
    expected = {
        (scenario, pair, member)
        for scenario in scenario_policy
        for pair in range(1, 7)
        for member in ("parent", "candidate")
    }
    if set(seen) != expected:
        raise CandidateControlError("build evidence round is incomplete")
    observations: list[dict[str, object]] = []
    for scenario, scenario_contract in scenario_policy.items():
        deltas = [
            _trial_delta(
                seen[(scenario, pair, "parent")]["value"],
                seen[(scenario, pair, "candidate")]["value"],
                scenario_contract["direction"],
            )
            for pair in range(1, 7)
        ]
        observations.append(
            {
                "direction": scenario_contract["direction"],
                "median_delta_percent": statistics.median(deltas),
                "pair_deltas_percent": deltas,
                "scenario": scenario,
            }
        )
    return {
        "environment_identity": environment_identity,
        "evidence_files": evidence_files,
        "member_variants": member_variants,
        "observations": observations,
        "round_kind": round_kind,
    }


def create_qualification_record(
    *,
    environment_path: pathlib.Path,
    plan_path: pathlib.Path,
    phase_record_paths: Sequence[pathlib.Path],
    a_a_roots: Sequence[pathlib.Path],
    comparison_root: pathlib.Path,
    policy_path: pathlib.Path,
    rule_evidence_paths: Sequence[pathlib.Path] = (),
    pgo_validation_record_paths: Sequence[pathlib.Path] = (),
) -> dict[str, object]:
    environment, environment_sha256 = build_experiment._load_environment(
        environment_path
    )
    if environment["environment_kind"] != "github-hosted":
        raise CandidateControlError(
            "build qualification is scoped to GitHub-hosted AMD"
        )
    plan, plan_sha256 = build_experiment._load_plan(plan_path)
    if plan["experiment_kind"] not in EXPERIMENT_CANDIDATE_PHASE:
        raise CandidateControlError(
            "build qualification experiment kind is unsupported"
        )
    if set(plan["artifact_names"]) != REQUIRED_ARTIFACTS:
        raise CandidateControlError("build qualification requires all artifact roles")
    if (
        plan["environment"]["sha256"] != environment_sha256
        or plan["environment"]["environment_id"] != environment["environment_id"]
        or plan["environment"]["build_identity_id"] != environment["build_identity_id"]
    ):
        raise CandidateControlError("build qualification environment differs from plan")
    policy, policy_sha256 = _load_policy(policy_path)
    records = _phase_records(plan, plan_sha256, phase_record_paths)
    pgo_validation = _pgo_validation_records(
        plan, plan_sha256, pgo_validation_record_paths
    )
    phases = {row["name"]: row for row in plan["phases"]}
    source = environment["source_identity"]
    candidate_phase = EXPERIMENT_CANDIDATE_PHASE[plan["experiment_kind"]]
    baseline_record, baseline_record_sha256 = records["baseline"]
    candidate_record, candidate_record_sha256 = records[candidate_phase]
    variants = {
        "baseline": _variant(
            name="baseline",
            source_identity=source,
            plan=plan,
            phase=phases["baseline"],
            phase_record=baseline_record,
            phase_record_sha256=baseline_record_sha256,
        ),
        "candidate": _variant(
            name="candidate",
            source_identity=source,
            plan=plan,
            phase=phases[candidate_phase],
            phase_record=candidate_record,
            phase_record_sha256=candidate_record_sha256,
        ),
    }
    if variants["baseline"]["variant_id"] == variants["candidate"]["variant_id"]:
        raise CandidateControlError("build comparison variants must be distinct")
    if len(a_a_roots) != policy["schedule"]["a_a_rounds"]:
        raise CandidateControlError(
            "build qualification requires exactly two A/A rounds"
        )
    a_a_rounds = [
        _validate_evidence_round(
            root=root,
            source_identity=source,
            variants=variants,
            member_variants={"parent": "baseline", "candidate": "baseline"},
            policy=policy,
            round_kind=f"a-a-{index}",
        )
        for index, root in enumerate(a_a_roots, start=1)
    ]
    comparison = _validate_evidence_round(
        root=comparison_root,
        source_identity=source,
        variants=variants,
        member_variants={"parent": "baseline", "candidate": "candidate"},
        policy=policy,
        round_kind="comparison",
    )
    environments = [row["environment_identity"] for row in a_a_rounds] + [
        comparison["environment_identity"]
    ]
    if any(row != environments[0] for row in environments[1:]):
        raise CandidateControlError("build qualification host changed between rounds")
    calibration_candidate = []
    for scenario in (row["name"] for row in policy["scenarios"]):
        values = [
            next(
                observation["median_delta_percent"]
                for observation in round_row["observations"]
                if observation["scenario"] == scenario
            )
            for round_row in a_a_rounds
        ]
        calibration_candidate.append(
            {
                "max_absolute_a_a_delta_percent": max(abs(value) for value in values),
                "round_medians_percent": values,
                "scenario": scenario,
            }
        )
    noise_by_scenario = {
        row["scenario"]: row["max_absolute_a_a_delta_percent"]
        for row in calibration_candidate
    }
    comparison_by_scenario = {
        row["scenario"]: row["median_delta_percent"]
        for row in comparison["observations"]
    }
    beneficial = sorted(
        scenario
        for scenario, delta in comparison_by_scenario.items()
        if delta > noise_by_scenario[scenario]
    )
    regressions = sorted(
        scenario
        for scenario, delta in comparison_by_scenario.items()
        if delta <= -float(policy["thresholds"]["max_regression_percent"])
    )
    provisional_threshold_observation = {
        "beneficial_scenarios": beneficial,
        "minimum_beneficial_scenarios": policy["thresholds"][
            "minimum_beneficial_scenarios"
        ],
        "regression_scenarios": regressions,
        "review_threshold_observed": (
            len(beneficial) >= policy["thresholds"]["minimum_beneficial_scenarios"]
            and not regressions
        ),
        "used_for_adoption": False,
    }
    rule_evidence = []
    for path in rule_evidence_paths:
        if not path.is_file():
            raise CandidateControlError("rule evidence file is unavailable")
        rule_evidence.append(
            {
                "path": str(path.resolve()),
                "sha256": build_experiment._file_sha256(
                    path, field="build rule evidence"
                ),
                "size_bytes": path.stat().st_size,
            }
        )
    scope = policy["hosted_scope"]
    record = {
        "a_a_rounds": a_a_rounds,
        "adoption_decision": "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        "bare_metal_gate_satisfied": scope["bare_metal_gate_satisfied"],
        "build_cost": {
            "baseline_elapsed_nanoseconds": baseline_record["elapsed_nanoseconds"],
            "baseline_peak_rss_upper_bound_kib": baseline_record["resource_usage"][
                "phase_peak_rss_upper_bound_kib"
            ],
            "baseline_total_artifact_bytes": sum(
                row["size_bytes"] for row in variants["baseline"]["artifacts"].values()
            ),
            "candidate_elapsed_nanoseconds": candidate_record["elapsed_nanoseconds"],
            "candidate_peak_rss_upper_bound_kib": candidate_record["resource_usage"][
                "phase_peak_rss_upper_bound_kib"
            ],
            "candidate_total_artifact_bytes": sum(
                row["size_bytes"] for row in variants["candidate"]["artifacts"].values()
            ),
        },
        "calibration_candidate": calibration_candidate,
        "comparison": comparison,
        "durable_evidence_gate_satisfied": scope["durable_evidence_gate_satisfied"],
        "different_cpu_validation_satisfied": False,
        "environment": {
            "environment_id": environment["environment_id"],
            "path": str(environment_path.resolve()),
            "sha256": environment_sha256,
        },
        "experiment_kind": plan["experiment_kind"],
        "generated_at_utc": build_experiment._utc_now(),
        "performance_authoritative": scope["performance_authoritative"],
        "plan": {
            "path": str(plan_path.resolve()),
            "plan_id": plan["plan_id"],
            "sha256": plan_sha256,
        },
        "policy": {
            "path": str(policy_path.resolve()),
            "policy_id": policy["policy_id"],
            "sha256": policy_sha256,
        },
        "pgo_validation_records": pgo_validation,
        "provisional_threshold_observation": provisional_threshold_observation,
        "rule_evidence": rule_evidence,
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "scope": scope["scope"],
        "source_identity": source,
        "status": "PASS",
        "variants": variants,
    }
    record["record_id"] = build_experiment._json_sha256(record)
    return record


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    command = commands.add_parser(
        "build-qualification",
        help="validate two same-artifact A/A rounds and one same-source build A/B round",
    )
    command.add_argument("--environment", required=True, type=pathlib.Path)
    command.add_argument("--plan", required=True, type=pathlib.Path)
    command.add_argument(
        "--phase-record", action="append", required=True, type=pathlib.Path
    )
    command.add_argument(
        "--a-a-root", action="append", required=True, type=pathlib.Path
    )
    command.add_argument("--comparison-root", required=True, type=pathlib.Path)
    command.add_argument("--policy", required=True, type=pathlib.Path)
    command.add_argument("--rule-evidence", action="append", type=pathlib.Path)
    command.add_argument("--pgo-validation-record", action="append", type=pathlib.Path)
    command.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    record = create_qualification_record(
        environment_path=parsed.environment,
        plan_path=parsed.plan,
        phase_record_paths=parsed.phase_record,
        a_a_roots=parsed.a_a_root,
        comparison_root=parsed.comparison_root,
        policy_path=parsed.policy,
        rule_evidence_paths=parsed.rule_evidence or (),
        pgo_validation_record_paths=parsed.pgo_validation_record or (),
    )
    _atomic_text(
        parsed.output,
        json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return 0
