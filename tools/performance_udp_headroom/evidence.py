"""Fail-closed timed and structural evidence validation for Phase 7."""

from __future__ import annotations

import pathlib
import statistics
from collections.abc import Sequence

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux import trial as linux_trial
from tools.performance_udp_headroom.build import (
    artifact_map,
    load_build_record,
    load_plan,
    variant,
)
from tools.performance_udp_headroom.contract import (
    AUTHORITY,
    QUALIFICATION_SCHEMA_VERSION,
    SCENARIO_NAMES,
)
from tools.performance_udp_workers.contract import (
    STRUCTURAL_COUNTERS,
    UdpWorkerControlError,
)
from tools.performance_udp_workers.evidence import load_json as load_diagnostic_json
from tools.performance_udp_workers.evidence import (
    validate_trial as validate_diagnostic_trial,
)
from tools.performance_udp_workers.pairing import Trial

DIAGNOSTIC_OUTPUTS = {
    "diagnostic-default": "profiles/udp-headroom/diagnostic/default.json",
    "diagnostic-candidate": "profiles/udp-headroom/diagnostic/candidate.json",
}
DIAGNOSTIC_READIES = {
    "diagnostic-default": "profiles/udp-headroom/diagnostic/default.ready",
    "diagnostic-candidate": "profiles/udp-headroom/diagnostic/candidate.ready",
}


def diagnostic_trial(diagnostic_variant: str) -> Trial:
    if diagnostic_variant not in DIAGNOSTIC_OUTPUTS:
        raise CandidateControlError("UDP headroom diagnostic variant is invalid")
    return Trial(
        sequence=1,
        phase="calibration-aa",
        round=1,
        pair=1,
        order=1,
        member="baseline",
        comparison_receive_workers=1,
        server_receive_workers=1,
        session_topology="multi-session",
        logical_sessions=32,
        output=DIAGNOSTIC_OUTPUTS[diagnostic_variant],
        ready_file=DIAGNOSTIC_READIES[diagnostic_variant],
    )


def _planned_scenario(plan: dict[str, object], name: str) -> dict[str, object]:
    matches = [row for row in plan["scenarios"] if row["name"] == name]
    if len(matches) != 1:
        raise CandidateControlError("UDP headroom scenario is not present exactly once")
    return matches[0]


def _observation(row: dict[str, object]) -> int:
    value = row["value"]
    if type(value) is not int or value < 0:
        raise CandidateControlError("UDP headroom observation is invalid")
    return value


def _improvement(parent: int, candidate: int) -> float:
    if parent <= 0:
        raise CandidateControlError("UDP headroom comparison baseline must be positive")
    return (candidate - parent) * 100.0 / parent


def _expected_round_paths(root: pathlib.Path) -> set[pathlib.Path]:
    return {
        root / member / f"{scenario}-{pair}.jsonl"
        for member in ("parent", "candidate")
        for scenario in SCENARIO_NAMES
        for pair in range(1, 7)
    }


def _validate_round(
    *,
    root: pathlib.Path,
    plan: dict[str, object],
    parent_record: dict[str, object],
    candidate_record: dict[str, object],
    round_kind: str,
) -> dict[str, object]:
    root = root.absolute()
    if not root.is_dir() or root.is_symlink():
        raise CandidateControlError("UDP headroom evidence round is unavailable")
    expected_paths = _expected_round_paths(root)
    member_directories = {root / "parent", root / "candidate"}
    observed_paths = set(root.rglob("*"))
    if (
        observed_paths != expected_paths | member_directories
        or any(path.is_symlink() for path in observed_paths)
        or any(not path.is_file() for path in expected_paths)
        or any(not path.is_dir() for path in member_directories)
    ):
        raise CandidateControlError("UDP headroom evidence path set changed")
    source = plan["source_identity"]
    records = {"parent": parent_record, "candidate": candidate_record}
    seen: dict[tuple[str, int, str], dict[str, object]] = {}
    environment_identity = None
    evidence_files = []
    for path in sorted(expected_paths):
        member = path.parent.name
        row = linux_trial._read_trial(path)
        scenario_name = row.get("scenario")
        if scenario_name not in SCENARIO_NAMES:
            raise CandidateControlError("UDP headroom evidence scenario is invalid")
        scenario = _planned_scenario(plan, scenario_name)
        linux_trial._validate_trial(
            row,
            source_member=member,
            plan={
                "active_seconds": scenario["active_seconds"],
                "pairs": plan["schedule"]["pair_count"],
                "warmup_seconds": scenario["warmup_seconds"],
            },
            planned={scenario_name: scenario},
            parent_sha=source["source_sha"],
            candidate_sha=source["source_sha"],
        )
        pair = row["pair"]
        expected_order = 1 if (pair % 2 == 1) == (member == "parent") else 2
        artifacts = artifact_map(records[member])
        key = (scenario_name, pair, member)
        if (
            key in seen
            or row["order"] != expected_order
            or row["tree"] != source["source_tree"]
            or row["runner_sha256"] != artifacts["m4-qualification"]["sha256"]
            or row["client_sha256"] != artifacts["ferrum2-client"]["sha256"]
            or row["server_sha256"] != artifacts["ferrum2-server"]["sha256"]
        ):
            raise CandidateControlError("UDP headroom trial identity is invalid")
        current_environment = row["environment_identity"]
        cpu_model = current_environment.get("cpu_model")
        if type(cpu_model) is not str or "AMD" not in cpu_model.upper():
            raise CandidateControlError(
                "UDP headroom qualification requires an AMD host"
            )
        if environment_identity is None:
            environment_identity = current_environment
        elif environment_identity != current_environment:
            raise CandidateControlError("UDP headroom host changed within a round")
        seen[key] = row
        evidence_files.append(
            {
                "member": member,
                "path": str(path),
                "sha256": build_experiment._file_sha256(path, field="headroom trial"),
            }
        )
    expected_keys = {
        (scenario, pair, member)
        for scenario in SCENARIO_NAMES
        for pair in range(1, 7)
        for member in ("parent", "candidate")
    }
    if set(seen) != expected_keys:
        raise CandidateControlError("UDP headroom evidence round is incomplete")
    observations = []
    for scenario in SCENARIO_NAMES:
        deltas = [
            _improvement(
                _observation(seen[(scenario, pair, "parent")]),
                _observation(seen[(scenario, pair, "candidate")]),
            )
            for pair in range(1, 7)
        ]
        observations.append(
            {
                "median_improvement_percent": statistics.median(deltas),
                "pair_improvements_percent": deltas,
                "scenario": scenario,
            }
        )
    return {
        "environment_identity": environment_identity,
        "evidence_files": evidence_files,
        "observations": observations,
        "round_kind": round_kind,
    }


def _validate_diagnostic(
    *,
    plan: dict[str, object],
    diagnostic_variant: str,
    diagnostic_record: dict[str, object],
    diagnostic_path: pathlib.Path,
    timed_environment: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    repository = pathlib.Path(variant(plan, diagnostic_variant)["repository"]).resolve()
    expected_path = (repository / DIAGNOSTIC_OUTPUTS[diagnostic_variant]).absolute()
    diagnostic_absolute = diagnostic_path.absolute()
    ancestor = repository
    for part in expected_path.relative_to(repository).parts:
        ancestor /= part
        if ancestor.is_symlink():
            raise CandidateControlError(
                "UDP headroom diagnostic path contains a symlink"
            )
    if diagnostic_absolute != expected_path:
        raise CandidateControlError("UDP headroom diagnostic path changed")
    diagnostic_path = diagnostic_absolute
    try:
        record = load_diagnostic_json(diagnostic_path, "UDP headroom diagnostic")
        artifacts = artifact_map(diagnostic_record)
        validate_diagnostic_trial(
            record,
            diagnostic_trial(diagnostic_variant),
            candidate_sha=plan["source_identity"]["source_sha"],
            contract=plan["diagnostic_contract"],
            runner=pathlib.Path(artifacts["m4-qualification"]["path"]),
            client=pathlib.Path(artifacts["ferrum2-client"]["path"]),
            server=pathlib.Path(artifacts["ferrum2-server"]["path"]),
        )
    except UdpWorkerControlError as error:
        raise CandidateControlError(str(error)) from error
    if record["identity"]["tree"] != plan["source_identity"]["source_tree"]:
        raise CandidateControlError("UDP headroom diagnostic tree changed")
    structural = record["structural"]
    if structural["counter_count"] != 49 or len(STRUCTURAL_COUNTERS) != 49:
        raise CandidateControlError(
            "UDP headroom diagnostic is not the fixed 49-counter schema"
        )
    assertions = {}
    for endpoint in ("client", "server"):
        delta = structural[f"{endpoint}_delta"]
        copy_bytes = delta["udp_payload_to_wire_copy_bytes"]
        owned_hits = delta["udp_owned_fast_path_hits"]
        if diagnostic_variant == "diagnostic-default":
            if type(copy_bytes) is not int or copy_bytes <= 0:
                raise CandidateControlError(
                    f"UDP headroom default {endpoint} did not prove copied baseline activity"
                )
        elif copy_bytes != 0 or type(owned_hits) is not int or owned_hits <= 0:
            raise CandidateControlError(
                f"UDP headroom candidate {endpoint} did not prove zero-copy owned-path activity"
            )
        assertions[endpoint] = {
            "udp_owned_fast_path_hits": owned_hits,
            "udp_payload_to_wire_copy_bytes": copy_bytes,
        }
    diagnostic_environment = record["identity"]["environment"]
    common_fields = (
        "runner_image",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
    )
    if {field: diagnostic_environment[field] for field in common_fields} != {
        field: timed_environment[field] for field in common_fields
    }:
        raise CandidateControlError(
            "UDP headroom diagnostic host changed after timed trials"
        )
    workload_identity = {
        "axis": record["axis"],
        "comparison_receive_workers": record["comparison_receive_workers"],
        "member": record["member"],
        "order": record["order"],
        "pair": record["pair"],
        "phase": record["phase"],
        "round": record["round"],
    }
    return (
        {
            "assertions": assertions,
            "counter_count": structural["counter_count"],
            "path": str(diagnostic_path),
            "sha256": build_experiment._file_sha256(
                diagnostic_path, field="headroom diagnostic"
            ),
            "status": "PASS",
            "variant_name": diagnostic_variant,
        },
        diagnostic_environment,
        workload_identity,
    )


def create_qualification(
    *,
    plan_path: pathlib.Path,
    default_build_path: pathlib.Path,
    candidate_build_path: pathlib.Path,
    diagnostic_default_build_path: pathlib.Path,
    diagnostic_candidate_build_path: pathlib.Path,
    a_a_roots: Sequence[pathlib.Path],
    comparison_root: pathlib.Path,
    diagnostic_default_path: pathlib.Path,
    diagnostic_candidate_path: pathlib.Path,
) -> dict[str, object]:
    plan, plan_sha256 = load_plan(plan_path)
    builds = {}
    build_hashes = {}
    for name, path in (
        ("default", default_build_path),
        ("candidate", candidate_build_path),
        ("diagnostic-default", diagnostic_default_build_path),
        ("diagnostic-candidate", diagnostic_candidate_build_path),
    ):
        builds[name], build_hashes[name] = load_build_record(
            path,
            plan=plan,
            plan_sha256=plan_sha256,
            expected_variant=name,
        )
    if len(a_a_roots) != plan["schedule"]["a_a_rounds"]:
        raise CandidateControlError(
            "UDP headroom qualification requires two A/A rounds"
        )
    repository = pathlib.Path(variant(plan, "candidate")["repository"]).resolve()
    expected_roots = [
        repository / "profiles/udp-headroom/timed/aa-1",
        repository / "profiles/udp-headroom/timed/aa-2",
    ]
    if any(root.absolute().is_symlink() for root in a_a_roots) or [
        root.absolute() for root in a_a_roots
    ] != [root.absolute() for root in expected_roots]:
        raise CandidateControlError("UDP headroom A/A roots changed")
    expected_comparison = repository / "profiles/udp-headroom/timed/comparison"
    if (
        comparison_root.absolute().is_symlink()
        or comparison_root.absolute() != expected_comparison.absolute()
    ):
        raise CandidateControlError("UDP headroom comparison root changed")
    a_a_rounds = [
        _validate_round(
            root=root,
            plan=plan,
            parent_record=builds["candidate"],
            candidate_record=builds["candidate"],
            round_kind=f"a-a-{index}",
        )
        for index, root in enumerate(a_a_roots, start=1)
    ]
    comparison = _validate_round(
        root=comparison_root,
        plan=plan,
        parent_record=builds["default"],
        candidate_record=builds["candidate"],
        round_kind="comparison",
    )
    environments = [row["environment_identity"] for row in a_a_rounds] + [
        comparison["environment_identity"]
    ]
    if any(environment != environments[0] for environment in environments[1:]):
        raise CandidateControlError("UDP headroom host changed between timed rounds")
    diagnostic_default, default_environment, default_workload = _validate_diagnostic(
        plan=plan,
        diagnostic_variant="diagnostic-default",
        diagnostic_record=builds["diagnostic-default"],
        diagnostic_path=diagnostic_default_path,
        timed_environment=environments[0],
    )
    diagnostic_candidate, candidate_environment, candidate_workload = (
        _validate_diagnostic(
            plan=plan,
            diagnostic_variant="diagnostic-candidate",
            diagnostic_record=builds["diagnostic-candidate"],
            diagnostic_path=diagnostic_candidate_path,
            timed_environment=environments[0],
        )
    )
    if default_environment != candidate_environment:
        raise CandidateControlError(
            "UDP headroom diagnostic host changed between default and candidate"
        )
    if default_workload != candidate_workload:
        raise CandidateControlError(
            "UDP headroom diagnostic workload changed between default and candidate"
        )
    diagnostic = {
        "candidate": diagnostic_candidate,
        "counter_count": 49,
        "default": diagnostic_default,
        "same_host_same_workload": True,
        "status": "PASS",
        "workload_identity": default_workload,
    }
    calibration = []
    for scenario in SCENARIO_NAMES:
        medians = [
            next(
                observation["median_improvement_percent"]
                for observation in round_row["observations"]
                if observation["scenario"] == scenario
            )
            for round_row in a_a_rounds
        ]
        calibration.append(
            {
                "max_absolute_a_a_delta_percent": max(abs(value) for value in medians),
                "round_medians_percent": medians,
                "scenario": scenario,
            }
        )
    paths = {
        "default": default_build_path,
        "candidate": candidate_build_path,
        "diagnostic-default": diagnostic_default_build_path,
        "diagnostic-candidate": diagnostic_candidate_build_path,
    }
    material = {
        "a_a_rounds": a_a_rounds,
        "adoption_decision": "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        "authority": AUTHORITY,
        "build_records": {
            name: {
                "path": str(paths[name].resolve()),
                "record_id": builds[name]["record_id"],
                "sha256": build_hashes[name],
            }
            for name in (
                "default",
                "candidate",
                "diagnostic-default",
                "diagnostic-candidate",
            )
        },
        "calibration_candidate": calibration,
        "comparison": comparison,
        "diagnostic": diagnostic,
        "plan": {
            "path": str(plan_path.resolve()),
            "plan_id": plan["plan_id"],
            "sha256": plan_sha256,
        },
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "source_identity": plan["source_identity"],
        "status": "PASS",
        "timed_binaries_structural_metrics": False,
        "variants": {
            name: variant(plan, name)["variant_id"]
            for name in (
                "default",
                "candidate",
                "diagnostic-default",
                "diagnostic-candidate",
            )
        },
    }
    return {
        **material,
        "generated_at_utc": build_experiment._utc_now(),
        "record_id": build_experiment._json_sha256(material),
    }
