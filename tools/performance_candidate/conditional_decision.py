"""Typed prerequisites and provisional decisions for conditional optimizations."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
from collections.abc import Sequence

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.output import _atomic_text

PREREQUISITE_SCHEMA_VERSION = "ferrum2-conditional-prerequisite-v2"
DECISION_SCHEMA_VERSION = "ferrum2-conditional-decision-v2"
COMMANDS = frozenset({"conditional-prerequisite", "conditional-decision"})
SCOPE = "github-hosted-amd-provisional"
UDP_SYSCALL_TOPOLOGIES = {
    "m4-udp-small-high-full-round-trip-v1": {
        "recv_legs_per_datagram": 6,
        "send_legs_per_datagram": 6,
    }
}

ASSERTION_KINDS = frozenset(
    {
        "dns-codec-addressed",
        "exact-size-addressed",
        "global-locks-addressed",
        "known-allocations-addressed",
        "locks-addressed",
        "structural-metrics-complete",
        "udp-global-locks-addressed",
        "waiter-herd-addressed",
    }
)
TRIGGER_KINDS = frozenset(
    {
        "allocation-hotspots",
        "allocator-cpu-lock",
        "context-switch",
        "counter-contention",
        "perf-c2c",
        "udp-kernel-cpu",
        "udp-syscall",
    }
)
PREREQUISITE_KINDS = ASSERTION_KINDS | TRIGGER_KINDS
CONDITIONALS = {
    "UDP-14": {
        "required": frozenset(
            {
                "exact-size-addressed",
                "udp-global-locks-addressed",
                "udp-kernel-cpu",
                "udp-syscall",
            }
        ),
        "triggers": frozenset({"udp-kernel-cpu", "udp-syscall"}),
    },
    "OBS-01": {
        "required": frozenset(
            {"structural-metrics-complete", "counter-contention", "perf-c2c"}
        ),
        "triggers": frozenset({"counter-contention"}),
    },
    "BUILD-04": {
        "required": frozenset(
            {
                "known-allocations-addressed",
                "allocation-hotspots",
                "allocator-cpu-lock",
            }
        ),
        "triggers": frozenset({"allocator-cpu-lock"}),
    },
    "BUILD-05": {
        "required": frozenset(
            {
                "global-locks-addressed",
                "dns-codec-addressed",
                "waiter-herd-addressed",
                "context-switch",
            }
        ),
        "triggers": frozenset({"context-switch"}),
    },
}


def _number(value: object, field: str, *, positive: bool = False) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise CandidateControlError(f"{field} must be a finite number")
    result = float(value)
    if result < 0 or (positive and result <= 0):
        raise CandidateControlError(f"{field} is outside its allowed range")
    return result


def _validate_measurement(kind: str, measurement: object) -> None:
    if type(measurement) is not dict:
        raise CandidateControlError(f"{kind} measurement must be an object")
    if kind in ASSERTION_KINDS:
        _exact_fields(
            measurement,
            frozenset({"reason", "satisfied"}),
            f"{kind} measurement",
        )
        if (
            type(measurement["satisfied"]) is not bool
            or type(measurement["reason"]) is not str
            or not measurement["reason"]
            or len(measurement["reason"]) > 512
        ):
            raise CandidateControlError(f"{kind} assertion is invalid")
        return
    field_sets = {
        "udp-syscall": {
            "datagrams",
            "excess_recv_syscalls",
            "excess_send_syscalls",
            "expected_recv_syscalls",
            "expected_send_syscalls",
            "normalized_excess_syscalls_per_datagram",
            "recv_syscalls",
            "send_syscalls",
            "topology",
            "trigger_present",
            "trigger_threshold_excess_per_datagram",
        },
        "udp-kernel-cpu": {
            "kernel_cpu_share_percent",
            "kernel_cycles",
            "total_cycles",
            "trigger_present",
            "trigger_threshold_percent",
        },
        "counter-contention": {
            "contention_percent",
            "trigger_present",
            "trigger_threshold_percent",
        },
        "perf-c2c": {
            "cache_line_bounces",
            "trigger_minimum",
            "trigger_present",
        },
        "allocation-hotspots": {
            "hotspot_percent",
            "sample_count",
            "trigger_present",
            "trigger_threshold_percent",
        },
        "allocator-cpu-lock": {
            "allocator_cpu_percent",
            "lock_wait_nanoseconds",
            "trigger_present",
            "trigger_threshold_percent",
        },
        "context-switch": {
            "context_switches_per_second",
            "trigger_present",
            "trigger_threshold_per_second",
        },
    }
    _exact_fields(measurement, frozenset(field_sets[kind]), f"{kind} measurement")
    if type(measurement["trigger_present"]) is not bool:
        raise CandidateControlError(f"{kind} trigger_present must be boolean")
    if kind == "udp-syscall":
        topology = measurement["topology"]
        _exact_fields(
            topology,
            frozenset(
                {
                    "id",
                    "recv_legs_per_datagram",
                    "send_legs_per_datagram",
                }
            ),
            "udp-syscall topology",
        )
        topology_id = topology["id"]
        if (
            type(topology_id) is not str
            or topology_id not in UDP_SYSCALL_TOPOLOGIES
            or topology != {"id": topology_id, **UDP_SYSCALL_TOPOLOGIES[topology_id]}
        ):
            raise CandidateControlError("udp-syscall topology is not preregistered")
        for field in (
            "datagrams",
            "recv_syscalls",
            "send_syscalls",
            "expected_recv_syscalls",
            "expected_send_syscalls",
            "excess_recv_syscalls",
            "excess_send_syscalls",
        ):
            if type(measurement[field]) is not int or measurement[field] < 0:
                raise CandidateControlError(f"udp-syscall {field} is invalid")
        if measurement["datagrams"] <= 0:
            raise CandidateControlError("udp-syscall datagrams must be positive")
        expected_recv = measurement["datagrams"] * topology["recv_legs_per_datagram"]
        expected_send = measurement["datagrams"] * topology["send_legs_per_datagram"]
        excess_recv = max(0, measurement["recv_syscalls"] - expected_recv)
        excess_send = max(0, measurement["send_syscalls"] - expected_send)
        normalized_excess = (excess_recv + excess_send) / measurement["datagrams"]
        observed = _number(
            measurement["normalized_excess_syscalls_per_datagram"],
            "normalized_excess_syscalls_per_datagram",
        )
        threshold = _number(
            measurement["trigger_threshold_excess_per_datagram"],
            "trigger_threshold_excess_per_datagram",
            positive=True,
        )
        if (
            measurement["expected_recv_syscalls"] != expected_recv
            or measurement["expected_send_syscalls"] != expected_send
            or measurement["excess_recv_syscalls"] != excess_recv
            or measurement["excess_send_syscalls"] != excess_send
            or abs(observed - normalized_excess) > 1e-9
            or measurement["trigger_present"] != (observed >= threshold)
        ):
            raise CandidateControlError("udp-syscall trigger does not reconstruct")
        return
    if kind == "udp-kernel-cpu":
        total = _number(measurement["total_cycles"], "total_cycles", positive=True)
        kernel = _number(measurement["kernel_cycles"], "kernel_cycles")
        share = _number(
            measurement["kernel_cpu_share_percent"], "kernel_cpu_share_percent"
        )
        threshold = _number(
            measurement["trigger_threshold_percent"],
            "trigger_threshold_percent",
            positive=True,
        )
        observed = kernel * 100.0 / total
        if (
            kernel > total
            or share > 100.0
            or threshold > 100.0
            or abs(share - observed) > 1e-9
            or measurement["trigger_present"] != (share >= threshold)
        ):
            raise CandidateControlError("udp-kernel-cpu trigger does not reconstruct")
        return
    if kind == "counter-contention":
        value = _number(measurement["contention_percent"], "contention_percent")
        threshold = _number(
            measurement["trigger_threshold_percent"],
            "trigger_threshold_percent",
            positive=True,
        )
    elif kind == "perf-c2c":
        if (
            type(measurement["cache_line_bounces"]) is not int
            or measurement["cache_line_bounces"] < 0
            or type(measurement["trigger_minimum"]) is not int
            or measurement["trigger_minimum"] <= 0
        ):
            raise CandidateControlError("perf-c2c counts are invalid")
        value = float(measurement["cache_line_bounces"])
        threshold = float(measurement["trigger_minimum"])
    elif kind == "allocation-hotspots":
        if (
            type(measurement["sample_count"]) is not int
            or measurement["sample_count"] <= 0
        ):
            raise CandidateControlError("allocation sample_count is invalid")
        value = _number(measurement["hotspot_percent"], "hotspot_percent")
        threshold = _number(
            measurement["trigger_threshold_percent"],
            "trigger_threshold_percent",
            positive=True,
        )
    elif kind == "allocator-cpu-lock":
        value = _number(measurement["allocator_cpu_percent"], "allocator_cpu_percent")
        _number(measurement["lock_wait_nanoseconds"], "lock_wait_nanoseconds")
        threshold = _number(
            measurement["trigger_threshold_percent"],
            "trigger_threshold_percent",
            positive=True,
        )
    else:
        value = _number(
            measurement["context_switches_per_second"],
            "context_switches_per_second",
        )
        threshold = _number(
            measurement["trigger_threshold_per_second"],
            "trigger_threshold_per_second",
            positive=True,
        )
    if measurement["trigger_present"] != (value >= threshold):
        raise CandidateControlError(f"{kind} trigger does not reconstruct")


def create_prerequisite_record(
    *,
    kind: str,
    source_sha: str,
    source_tree: str,
    profiler_status: str,
    raw_artifact_path: pathlib.Path | None,
    measurement: dict[str, object] | None,
) -> dict[str, object]:
    if kind not in PREREQUISITE_KINDS:
        raise CandidateControlError("conditional prerequisite kind is invalid")
    if (
        type(source_sha) is not str
        or build_experiment.COMMIT_SHA.fullmatch(source_sha) is None
        or type(source_tree) is not str
        or build_experiment.GIT_OBJECT.fullmatch(source_tree) is None
    ):
        raise CandidateControlError(
            "conditional prerequisite source identity is invalid"
        )
    if profiler_status not in {"AVAILABLE", "UNAVAILABLE"}:
        raise CandidateControlError("conditional profiler_status is invalid")
    raw_artifact: dict[str, object] | None = None
    if profiler_status == "AVAILABLE":
        if (
            raw_artifact_path is None
            or raw_artifact_path.is_symlink()
            or not raw_artifact_path.is_file()
            or raw_artifact_path.stat().st_size <= 0
            or measurement is None
        ):
            raise CandidateControlError(
                "available prerequisite requires raw evidence and measurement"
            )
        _validate_measurement(kind, measurement)
        raw_artifact = {
            "path": str(raw_artifact_path.resolve()),
            "sha256": build_experiment._file_sha256(
                raw_artifact_path, field=f"{kind} raw evidence"
            ),
            "size_bytes": raw_artifact_path.stat().st_size,
        }
    elif raw_artifact_path is not None or measurement is not None:
        raise CandidateControlError("unavailable prerequisite cannot claim evidence")
    record = {
        "kind": kind,
        "measurement": measurement,
        "profiler_status": profiler_status,
        "raw_artifact": raw_artifact,
        "schema_version": PREREQUISITE_SCHEMA_VERSION,
        "source_identity": {
            "comparison_axis": "conditional-optimization",
            "source_sha": source_sha,
            "source_tree": source_tree,
        },
    }
    record["record_id"] = build_experiment._json_sha256(record)
    return record


def load_prerequisite_document(
    path: pathlib.Path,
    *,
    expected_kind: str | None = None,
    source_identity: dict[str, object] | None = None,
) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="conditional prerequisite evidence",
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("conditional prerequisite must be an object")
    _exact_fields(
        row,
        frozenset(
            {
                "kind",
                "measurement",
                "profiler_status",
                "raw_artifact",
                "record_id",
                "schema_version",
                "source_identity",
            }
        ),
        "conditional prerequisite",
    )
    if row["schema_version"] != PREREQUISITE_SCHEMA_VERSION:
        raise CandidateControlError("conditional prerequisite schema is unsupported")
    kind = row["kind"]
    if kind not in PREREQUISITE_KINDS or (
        expected_kind is not None and kind != expected_kind
    ):
        raise CandidateControlError("conditional prerequisite kind does not match")
    identity = row["source_identity"]
    if type(identity) is not dict:
        raise CandidateControlError("conditional prerequisite source is invalid")
    _exact_fields(
        identity,
        frozenset({"comparison_axis", "source_sha", "source_tree"}),
        "conditional prerequisite source",
    )
    if (
        identity["comparison_axis"] != "conditional-optimization"
        or type(identity["source_sha"]) is not str
        or build_experiment.COMMIT_SHA.fullmatch(identity["source_sha"]) is None
        or type(identity["source_tree"]) is not str
        or build_experiment.GIT_OBJECT.fullmatch(identity["source_tree"]) is None
    ):
        raise CandidateControlError(
            "conditional prerequisite source values are invalid"
        )
    if source_identity is not None and (
        identity["source_sha"] != source_identity["source_sha"]
        or identity["source_tree"] != source_identity["source_tree"]
    ):
        raise CandidateControlError(
            "conditional prerequisite source differs from experiment"
        )
    profiler_status = row["profiler_status"]
    if profiler_status == "AVAILABLE":
        _validate_measurement(kind, row["measurement"])
        artifact = row["raw_artifact"]
        if type(artifact) is not dict:
            raise CandidateControlError("conditional raw artifact is invalid")
        _exact_fields(
            artifact,
            frozenset({"path", "sha256", "size_bytes"}),
            "conditional raw artifact",
        )
        artifact_path_value = artifact["path"]
        if (
            type(artifact_path_value) is not str
            or type(artifact["size_bytes"]) is not int
            or artifact["size_bytes"] <= 0
            or type(artifact["sha256"]) is not str
            or SHA256.fullmatch(artifact["sha256"]) is None
        ):
            raise CandidateControlError("conditional raw artifact identity changed")
        artifact_path = pathlib.Path(artifact_path_value)
        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
            or build_experiment._file_sha256(
                artifact_path, field="conditional raw artifact"
            )
            != artifact["sha256"]
            or artifact_path.stat().st_size != artifact["size_bytes"]
        ):
            raise CandidateControlError("conditional raw artifact identity changed")
    elif profiler_status == "UNAVAILABLE":
        if row["measurement"] is not None or row["raw_artifact"] is not None:
            raise CandidateControlError("unavailable conditional evidence is not empty")
    else:
        raise CandidateControlError("conditional profiler_status is invalid")
    material = dict(row)
    record_id = material.pop("record_id")
    if type(record_id) is not str or record_id != build_experiment._json_sha256(
        material
    ):
        raise CandidateControlError(
            "conditional prerequisite record_id does not reconstruct"
        )
    return row, bounded.sha256


def create_conditional_decision(
    *,
    candidate: str,
    source_sha: str,
    source_tree: str,
    evidence_paths: Sequence[pathlib.Path],
) -> dict[str, object]:
    if candidate not in CONDITIONALS:
        raise CandidateControlError("conditional candidate is invalid")
    source_identity = {"source_sha": source_sha, "source_tree": source_tree}
    if (
        type(source_sha) is not str
        or build_experiment.COMMIT_SHA.fullmatch(source_sha) is None
        or type(source_tree) is not str
        or build_experiment.GIT_OBJECT.fullmatch(source_tree) is None
    ):
        raise CandidateControlError("conditional decision source is invalid")
    evidence: dict[str, dict[str, object]] = {}
    for path in evidence_paths:
        row, digest = load_prerequisite_document(path, source_identity=source_identity)
        kind = row["kind"]
        if kind in evidence:
            raise CandidateControlError("conditional prerequisite is duplicated")
        evidence[kind] = {
            "path": str(path.resolve()),
            "record": row,
            "sha256": digest,
        }
    contract = CONDITIONALS[candidate]
    unexpected = set(evidence) - contract["required"]
    if unexpected:
        raise CandidateControlError(
            f"conditional prerequisite set has unexpected kinds: {sorted(unexpected)}"
        )
    missing = sorted(contract["required"] - set(evidence))
    unavailable = sorted(
        kind
        for kind, value in evidence.items()
        if value["record"]["profiler_status"] == "UNAVAILABLE"
    )
    unsatisfied = sorted(
        kind
        for kind, value in evidence.items()
        if kind in ASSERTION_KINDS
        and value["record"]["measurement"]["satisfied"] is False
    )
    trigger_present = False
    trigger_kinds = sorted(contract["triggers"])
    trigger_measurements = [
        evidence[kind]["record"]["measurement"]
        for kind in trigger_kinds
        if kind in evidence and evidence[kind]["record"]["measurement"] is not None
    ]
    if len(trigger_measurements) == len(trigger_kinds):
        trigger_present = all(
            row["trigger_present"] is True for row in trigger_measurements
        )
    if missing or unsatisfied:
        status = "DEFERRED"
    elif unavailable:
        status = "INCONCLUSIVE"
    elif trigger_present:
        status = "TRIGGER_PRESENT"
    else:
        status = "NO_TRIGGER"
    record = {
        "adoption_decision": "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        "bare_metal_gate_satisfied": False,
        "candidate": candidate,
        "durable_evidence_gate_satisfied": False,
        "evidence": evidence,
        "generated_at_utc": build_experiment._utc_now(),
        "missing_prerequisites": missing,
        "performance_authoritative": False,
        "profiler_unavailable": unavailable,
        "schema_version": DECISION_SCHEMA_VERSION,
        "scope": SCOPE,
        "source_identity": {
            "comparison_axis": "conditional-optimization",
            **source_identity,
        },
        "status": status,
        "trigger_kinds": trigger_kinds,
        "trigger_present": trigger_present,
        "unsatisfied_prerequisites": unsatisfied,
    }
    record["record_id"] = build_experiment._json_sha256(record)
    return record


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    prerequisite = commands.add_parser(
        "conditional-prerequisite",
        help="bind one typed conditional-optimization prerequisite",
    )
    prerequisite.add_argument(
        "--kind", required=True, choices=sorted(PREREQUISITE_KINDS)
    )
    prerequisite.add_argument("--source-sha", required=True)
    prerequisite.add_argument("--source-tree", required=True)
    prerequisite.add_argument(
        "--profiler-status", required=True, choices=("AVAILABLE", "UNAVAILABLE")
    )
    prerequisite.add_argument("--raw-artifact", type=pathlib.Path)
    prerequisite.add_argument("--measurement", type=pathlib.Path)
    prerequisite.add_argument("--output", required=True, type=pathlib.Path)
    decision = commands.add_parser(
        "conditional-decision",
        help="write a closed provisional decision for one conditional optimization",
    )
    decision.add_argument("--candidate", required=True, choices=sorted(CONDITIONALS))
    decision.add_argument("--source-sha", required=True)
    decision.add_argument("--source-tree", required=True)
    decision.add_argument("--evidence", action="append", type=pathlib.Path)
    decision.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    if parsed.command == "conditional-prerequisite":
        measurement = None
        if parsed.measurement is not None:
            bounded = read_bounded_closed_json(
                parsed.measurement,
                maximum_bytes=build_experiment.MAX_JSON_BYTES,
                source="conditional measurement",
            )
            if type(bounded.value) is not dict:
                raise CandidateControlError("conditional measurement must be an object")
            measurement = bounded.value
        record = create_prerequisite_record(
            kind=parsed.kind,
            source_sha=parsed.source_sha,
            source_tree=parsed.source_tree,
            profiler_status=parsed.profiler_status,
            raw_artifact_path=parsed.raw_artifact,
            measurement=measurement,
        )
    elif parsed.command == "conditional-decision":
        record = create_conditional_decision(
            candidate=parsed.candidate,
            source_sha=parsed.source_sha,
            source_tree=parsed.source_tree,
            evidence_paths=parsed.evidence or (),
        )
    else:
        raise AssertionError(f"unhandled conditional command: {parsed.command}")
    _atomic_text(
        parsed.output,
        json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return 0
