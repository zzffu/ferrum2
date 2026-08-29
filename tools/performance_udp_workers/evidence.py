"""Strict raw-trial validation and provisional GATE-05 reductions."""

from __future__ import annotations

import json
import pathlib
import statistics
from typing import Any

from tools.performance_udp_workers.contract import (
    ACTIVE_SECONDS,
    AUTHORITY,
    BUILD_PROFILE,
    RUNNER_IMAGE,
    STRUCTURAL_AGGREGATION,
    STRUCTURAL_COUNTERS,
    STRUCTURAL_SCHEMA_VERSION,
    SUMMARY_SCHEMA_VERSION,
    TRIAL_KIND,
    TRIAL_SCHEMA_VERSION,
    UdpWorkerControlError,
    require_exact_keys,
    require_uint,
    sha256_file,
)
from tools.performance_udp_workers.pairing import Trial

TRIAL_KEYS = {
    "schema_version",
    "kind",
    "candidate_sha",
    "phase",
    "round",
    "pair",
    "order",
    "member",
    "comparison_receive_workers",
    "axis",
    "source_identity",
    "authority",
    "identity",
    "metrics",
    "hot_locks",
    "structural",
    "cleanup",
    "decision",
    "correctness",
    "status",
}


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 256 * 1024 or not raw.endswith(b"\n"):
            raise UdpWorkerControlError(f"{label} is empty, unbounded, or unterminated")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UdpWorkerControlError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise UdpWorkerControlError(f"{label} is not a JSON object")
    return value


def validate_trial(
    record: dict[str, Any],
    trial: Trial,
    *,
    candidate_sha: str,
    contract: dict[str, str | int],
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
) -> None:
    require_exact_keys(record, TRIAL_KEYS, "UDP worker trial")
    expected_scalars = {
        "schema_version": TRIAL_SCHEMA_VERSION,
        "kind": TRIAL_KIND,
        "candidate_sha": candidate_sha,
        "phase": trial.phase,
        "round": trial.round,
        "pair": trial.pair,
        "order": trial.order,
        "member": trial.member,
        "comparison_receive_workers": trial.comparison_receive_workers,
        "decision": "OBSERVATION_ONLY",
        "correctness": "PASS",
        "status": "PASS",
    }
    for key, expected in expected_scalars.items():
        if record[key] != expected:
            raise UdpWorkerControlError(f"UDP worker trial {key} is inconsistent")
    axis = require_exact_keys(
        record["axis"],
        {
            "scenario",
            "topology",
            "server_receive_workers",
            "session_topology",
            "logical_sessions",
            "application_payload_bytes",
            "warmup_seconds",
            "active_seconds",
            "unit",
            "config_axis",
        },
        "UDP worker axis",
    )
    expected_axis = {
        "scenario": "udp-small-high",
        "topology": "shadowsocks",
        "server_receive_workers": trial.server_receive_workers,
        "session_topology": trial.session_topology,
        "logical_sessions": trial.logical_sessions,
        "application_payload_bytes": 128,
        "warmup_seconds": 3,
        "active_seconds": ACTIVE_SECONDS,
        "unit": "datagrams_per_second",
        "config_axis": "server.udp.receive_workers",
    }
    if axis != expected_axis:
        raise UdpWorkerControlError("UDP worker trial axis changed")
    source = require_exact_keys(
        record["source_identity"],
        {
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
        },
        "UDP worker source identity",
    )
    if source != {
        key: contract[key]
        for key in (
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
        )
    }:
        raise UdpWorkerControlError("UDP worker source identity does not recompute")
    authority = require_exact_keys(
        record["authority"], set(AUTHORITY), "UDP worker authority"
    )
    if authority != AUTHORITY:
        raise UdpWorkerControlError("UDP worker authority was broadened")
    _validate_identity(record["identity"], candidate_sha, runner, client, server)
    _validate_metrics(record["metrics"])
    structural = _validate_structural(record["structural"])
    _validate_hot_locks(record["hot_locks"], structural["server_delta"])
    cleanup = require_exact_keys(
        record["cleanup"],
        {"active_processes", "active_workers", "ready_file_removed", "status"},
        "UDP worker cleanup",
    )
    if cleanup != {
        "active_processes": 0,
        "active_workers": 0,
        "ready_file_removed": True,
        "status": "PASS",
    }:
        raise UdpWorkerControlError("UDP worker cleanup evidence is incomplete")


def _validate_identity(
    value: Any,
    candidate_sha: str,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
) -> None:
    identity = require_exact_keys(
        value,
        {
            "sha",
            "tree",
            "runner_sha256",
            "client_sha256",
            "server_sha256",
            "environment",
        },
        "UDP worker identity",
    )
    if identity["sha"] != candidate_sha:
        raise UdpWorkerControlError("UDP worker checkout SHA changed")
    tree = identity["tree"]
    if (
        not isinstance(tree, str)
        or len(tree) != 40
        or any(byte not in "0123456789abcdef" for byte in tree)
    ):
        raise UdpWorkerControlError("UDP worker tree identity is malformed")
    expected_hashes = {
        "runner_sha256": sha256_file(runner),
        "client_sha256": sha256_file(client),
        "server_sha256": sha256_file(server),
    }
    for key, expected in expected_hashes.items():
        if identity[key] != expected:
            raise UdpWorkerControlError(f"UDP worker {key} does not match exact binary")
    environment = require_exact_keys(
        identity["environment"],
        {
            "runner_image",
            "rustc",
            "kernel",
            "cpu_vendor",
            "cpu_model",
            "cpu_count",
            "memory_kib",
            "build_profile",
        },
        "UDP worker environment",
    )
    if (
        environment["runner_image"] != RUNNER_IMAGE
        or environment["cpu_vendor"] != "AuthenticAMD"
        or environment["build_profile"] != BUILD_PROFILE
        or not isinstance(environment["rustc"], str)
        or not environment["rustc"].startswith("rustc 1.97.1 ")
        or not isinstance(environment["kernel"], str)
        or not environment["kernel"]
        or not isinstance(environment["cpu_model"], str)
        or not environment["cpu_model"]
    ):
        raise UdpWorkerControlError(
            "UDP worker environment is outside the closed AMD profile"
        )
    require_uint(environment["cpu_count"], "UDP worker CPU count", positive=True)
    require_uint(environment["memory_kib"], "UDP worker memory", positive=True)


def _validate_metrics(value: Any) -> None:
    metrics = require_exact_keys(
        value,
        {
            "datagrams_per_second",
            "validated_datagrams",
            "p99_nanoseconds",
            "p99_sample_count",
            "combined_cpu_nanoseconds",
            "combined_cpu_core_millis",
            "client",
            "server",
        },
        "UDP worker metrics",
    )
    for field in (
        "datagrams_per_second",
        "validated_datagrams",
        "p99_nanoseconds",
        "p99_sample_count",
        "combined_cpu_nanoseconds",
        "combined_cpu_core_millis",
    ):
        require_uint(metrics[field], f"UDP worker {field}", positive=True)
    if (
        metrics["p99_sample_count"] > metrics["validated_datagrams"]
        or metrics["p99_sample_count"] > 2_000_000
    ):
        raise UdpWorkerControlError("UDP worker p99 sample count is outside its bound")
    combined = 0
    for role in ("client", "server"):
        process = require_exact_keys(
            metrics[role],
            {
                "cpu_nanoseconds",
                "voluntary_context_switches",
                "involuntary_context_switches",
            },
            f"UDP worker {role} process metrics",
        )
        combined += require_uint(process["cpu_nanoseconds"], f"UDP worker {role} CPU")
        require_uint(
            process["voluntary_context_switches"],
            f"UDP worker {role} voluntary context switches",
        )
        require_uint(
            process["involuntary_context_switches"],
            f"UDP worker {role} involuntary context switches",
        )
    if combined != metrics["combined_cpu_nanoseconds"]:
        raise UdpWorkerControlError("UDP worker combined CPU evidence is inconsistent")


def _validate_structural(value: Any) -> dict[str, Any]:
    structural = require_exact_keys(
        value,
        {
            "schema_version",
            "aggregation",
            "counter_schema",
            "counter_count",
            "client_before",
            "client_after",
            "server_before",
            "server_after",
            "client_delta",
            "server_delta",
            "merged_delta",
        },
        "UDP worker structural evidence",
    )
    if (
        structural["schema_version"] != STRUCTURAL_SCHEMA_VERSION
        or structural["aggregation"] != STRUCTURAL_AGGREGATION
        or structural["counter_count"] != len(STRUCTURAL_COUNTERS)
    ):
        raise UdpWorkerControlError("UDP worker structural schema changed")
    expected = set(STRUCTURAL_COUNTERS)
    schema = structural["counter_schema"]
    if not isinstance(schema, dict) or set(schema) != expected:
        raise UdpWorkerControlError(
            "UDP worker structural counter schema is not closed"
        )
    for name, entry in schema.items():
        entry = require_exact_keys(
            entry, {"unit", "aggregation", "range"}, f"structural schema {name}"
        )
        bounds = require_exact_keys(
            entry["range"], {"minimum", "maximum"}, f"structural range {name}"
        )
        expected_unit = (
            "bytes"
            if name.endswith("_bytes")
            else "nanoseconds" if name.endswith("_nanoseconds") else "events"
        )
        if (
            entry["unit"] != expected_unit
            or entry["aggregation"] != STRUCTURAL_AGGREGATION
            or bounds != {"minimum": 0, "maximum": (1 << 64) - 1}
        ):
            raise UdpWorkerControlError(f"structural schema metadata changed: {name}")
    snapshots: dict[str, dict[str, int]] = {}
    for endpoint in ("client", "server"):
        for phase in ("before", "after"):
            key = f"{endpoint}_{phase}"
            snapshot = require_exact_keys(
                structural[key], {"values", "overflowed"}, f"structural {key}"
            )
            if snapshot["overflowed"] is not False:
                raise UdpWorkerControlError(
                    "structural overflow invalidates UDP worker evidence"
                )
            values = snapshot["values"]
            if not isinstance(values, dict) or set(values) != expected:
                raise UdpWorkerControlError(f"structural {key} is not closed")
            snapshots[key] = {
                name: require_uint(raw, f"structural {key} {name}")
                for name, raw in values.items()
            }
    deltas: dict[str, dict[str, int]] = {}
    for endpoint in ("client", "server"):
        key = f"{endpoint}_delta"
        raw_delta = structural[key]
        if not isinstance(raw_delta, dict) or set(raw_delta) != expected:
            raise UdpWorkerControlError(f"structural {key} is not closed")
        delta = {
            name: require_uint(raw, f"structural {key} {name}")
            for name, raw in raw_delta.items()
        }
        for name in expected:
            observed = (
                snapshots[f"{endpoint}_after"][name]
                - snapshots[f"{endpoint}_before"][name]
            )
            if observed < 0 or delta[name] != observed:
                raise UdpWorkerControlError(f"structural {key} does not recompute")
        deltas[key] = delta
    merged = structural["merged_delta"]
    if not isinstance(merged, dict) or set(merged) != expected:
        raise UdpWorkerControlError("structural merged delta is not closed")
    for name in expected:
        if require_uint(merged[name], f"structural merged {name}") != (
            deltas["client_delta"][name] + deltas["server_delta"][name]
        ):
            raise UdpWorkerControlError("structural merged delta does not recompute")
    return structural


def _validate_hot_locks(value: Any, server_delta: dict[str, int]) -> None:
    locks = require_exact_keys(
        value,
        {"aggregation", "admission", "udp_server_state", "udp_mappings_state"},
        "UDP worker hot locks",
    )
    if locks["aggregation"] != "server_checked_delta":
        raise UdpWorkerControlError("UDP worker lock aggregation changed")
    for output, prefix in (
        ("admission", "admission"),
        ("udp_server_state", "udp_server"),
        ("udp_mappings_state", "udp_mappings"),
    ):
        observed = require_exact_keys(
            locks[output],
            {"wait_nanoseconds", "hold_nanoseconds", "samples"},
            f"UDP worker {output} lock",
        )
        expected = {
            "wait_nanoseconds": server_delta[f"{prefix}_lock_wait_nanoseconds"],
            "hold_nanoseconds": server_delta[f"{prefix}_lock_hold_nanoseconds"],
            "samples": server_delta[f"{prefix}_lock_samples"],
        }
        if observed != expected:
            raise UdpWorkerControlError(f"UDP worker {output} lock does not recompute")


def load_and_validate_trials(
    root: pathlib.Path,
    trials: list[Trial],
    *,
    candidate_sha: str,
    contract: dict[str, str | int],
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    expected_paths = {root / trial.output for trial in trials}
    raw_root = root / "profiles/udp-workers/raw"
    observed_paths = (
        {path for path in raw_root.rglob("*") if path.is_file() or path.is_symlink()}
        if raw_root.is_dir() and not raw_root.is_symlink()
        else set()
    )
    if observed_paths != expected_paths:
        raise UdpWorkerControlError("UDP worker raw artifact set is not closed")
    for trial in trials:
        record = load_json(root / trial.output, "UDP worker raw trial")
        validate_trial(
            record,
            trial,
            candidate_sha=candidate_sha,
            contract=contract,
            runner=runner,
            client=client,
            server=server,
        )
        records.append(record)
    environments = [record["identity"]["environment"] for record in records]
    if any(environment != environments[0] for environment in environments[1:]):
        raise UdpWorkerControlError(
            "UDP worker environment changed between timed trials"
        )
    binary_identities = [
        {
            key: record["identity"][key]
            for key in (
                "sha",
                "tree",
                "runner_sha256",
                "client_sha256",
                "server_sha256",
            )
        }
        for record in records
    ]
    if any(identity != binary_identities[0] for identity in binary_identities[1:]):
        raise UdpWorkerControlError(
            "UDP worker exact binary identity changed between trials"
        )
    return records


def _pair_deltas(records: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(record["pair"], []).append(record)
    if set(grouped) != set(range(1, 7)):
        raise UdpWorkerControlError("UDP worker paired evidence is incomplete")
    deltas: list[dict[str, float | int]] = []
    for pair in range(1, 7):
        pair_records = grouped[pair]
        if len(pair_records) != 2 or {record["member"] for record in pair_records} != {
            "baseline",
            "variant",
        }:
            raise UdpWorkerControlError("UDP worker pair is not complete")
        by_member = {record["member"]: record for record in pair_records}
        baseline = by_member["baseline"]["metrics"]
        variant = by_member["variant"]["metrics"]

        def percent(field: str) -> float:
            return (variant[field] - baseline[field]) * 100.0 / baseline[field]

        deltas.append(
            {
                "pair": pair,
                "throughput_delta_percent": percent("datagrams_per_second"),
                "p99_delta_percent": percent("p99_nanoseconds"),
                "cpu_core_delta_percent": percent("combined_cpu_core_millis"),
            }
        )
    return deltas


def summarize(records: list[dict[str, Any]], candidate_sha: str) -> dict[str, object]:
    aa: list[dict[str, object]] = []
    comparisons: list[dict[str, object]] = []
    for topology in ("same-session", "multi-session"):
        topology_aa_noise: list[float] = []
        for round_number in (1, 2):
            selected = [
                record
                for record in records
                if record["phase"] == "calibration-aa"
                and record["round"] == round_number
                and record["axis"]["session_topology"] == topology
            ]
            deltas = _pair_deltas(selected)
            noise = statistics.median(
                abs(float(delta["throughput_delta_percent"])) for delta in deltas
            )
            topology_aa_noise.append(noise)
            aa.append(
                {
                    "session_topology": topology,
                    "round": round_number,
                    "pairs": deltas,
                    "throughput_median_absolute_noise_percent": noise,
                    "classification": "provisional_noise_observation",
                }
            )
        noise_floor = max(topology_aa_noise)
        candidates: list[tuple[int, float, float]] = []
        for workers in (2, 4, 8):
            selected = [
                record
                for record in records
                if record["phase"] == "comparison"
                and record["comparison_receive_workers"] == workers
                and record["axis"]["session_topology"] == topology
            ]
            deltas = _pair_deltas(selected)
            throughput = statistics.median(
                float(delta["throughput_delta_percent"]) for delta in deltas
            )
            p99 = statistics.median(
                float(delta["p99_delta_percent"]) for delta in deltas
            )
            cpu = statistics.median(
                float(delta["cpu_core_delta_percent"]) for delta in deltas
            )
            provisional_signal = (
                throughput > max(3.0, noise_floor * 2.0) and p99 <= 10.0
            )
            comparisons.append(
                {
                    "session_topology": topology,
                    "baseline_receive_workers": 1,
                    "variant_receive_workers": workers,
                    "pairs": deltas,
                    "median_throughput_delta_percent": throughput,
                    "median_p99_delta_percent": p99,
                    "median_cpu_core_delta_percent": cpu,
                    "aa_noise_floor_percent": noise_floor,
                    "provisional_signal": provisional_signal,
                    "classification": "github_hosted_amd_observation",
                }
            )
            if provisional_signal:
                candidates.append((workers, throughput, p99))
        recommendation = (
            max(candidates, key=lambda candidate: (candidate[1], -candidate[0]))[0]
            if candidates
            else 1
        )
        comparisons.append(
            {
                "session_topology": topology,
                "provisional_recommendation_receive_workers": recommendation,
                "decision": "DEFERRED",
                "reason": "hosted AMD observations cannot satisfy the bare-metal adoption gate",
            }
        )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "ferrum2_udp_worker_summary",
        "candidate_sha": candidate_sha,
        "trial_count": len(records),
        "aa_rounds": aa,
        "comparisons": comparisons,
        "default_receive_workers": 1,
        "default_changed": False,
        "decision": "DEFERRED",
        "authority": dict(AUTHORITY),
    }
