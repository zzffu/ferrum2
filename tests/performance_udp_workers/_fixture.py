from __future__ import annotations

import pathlib

from tools.performance_udp_workers.contract import (
    ACTIVE_SECONDS,
    AUTHORITY,
    BUILD_PROFILE,
    RUNNER_IMAGE,
    STRUCTURAL_AGGREGATION,
    STRUCTURAL_COUNTERS,
    STRUCTURAL_SCHEMA_VERSION,
    TRIAL_KIND,
    TRIAL_SCHEMA_VERSION,
    sha256_file,
)
from tools.performance_udp_workers.pairing import Trial


def valid_record(
    trial: Trial,
    *,
    candidate_sha: str,
    contract: dict[str, str | int],
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    throughput: int | None = None,
) -> dict[str, object]:
    before = {name: 1 for name in STRUCTURAL_COUNTERS}
    after = {name: 2 for name in STRUCTURAL_COUNTERS}
    delta = {name: 1 for name in STRUCTURAL_COUNTERS}
    throughput = throughput or 100_000 + trial.server_receive_workers * 1_000
    return {
        "schema_version": TRIAL_SCHEMA_VERSION,
        "kind": TRIAL_KIND,
        "candidate_sha": candidate_sha,
        "phase": trial.phase,
        "round": trial.round,
        "pair": trial.pair,
        "order": trial.order,
        "member": trial.member,
        "comparison_receive_workers": trial.comparison_receive_workers,
        "axis": {
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
        },
        "source_identity": {
            key: contract[key]
            for key in (
                "producer_source_sha256",
                "controller_source_sha256",
                "semantic_recipe_sha256",
                "evidence_bundle_sha256",
            )
        },
        "authority": dict(AUTHORITY),
        "identity": {
            "sha": candidate_sha,
            "tree": "b" * 40,
            "runner_sha256": sha256_file(runner),
            "client_sha256": sha256_file(client),
            "server_sha256": sha256_file(server),
            "environment": {
                "runner_image": RUNNER_IMAGE,
                "rustc": "rustc 1.97.1 (fixture)",
                "kernel": "Linux fixture",
                "cpu_vendor": "AuthenticAMD",
                "cpu_model": "AMD fixture",
                "cpu_count": 8,
                "memory_kib": 16_000_000,
                "build_profile": BUILD_PROFILE,
            },
        },
        "metrics": {
            "datagrams_per_second": throughput,
            "validated_datagrams": throughput * ACTIVE_SECONDS,
            "p99_nanoseconds": 10_000,
            "p99_sample_count": min(throughput * ACTIVE_SECONDS, 2_000_000),
            "combined_cpu_nanoseconds": 2_000,
            "combined_cpu_core_millis": 100,
            "client": {
                "cpu_nanoseconds": 1_000,
                "voluntary_context_switches": 2,
                "involuntary_context_switches": 1,
            },
            "server": {
                "cpu_nanoseconds": 1_000,
                "voluntary_context_switches": 2,
                "involuntary_context_switches": 1,
            },
        },
        "hot_locks": {
            "aggregation": "server_checked_delta",
            "admission": {"wait_nanoseconds": 1, "hold_nanoseconds": 1, "samples": 1},
            "udp_server_state": {
                "wait_nanoseconds": 1,
                "hold_nanoseconds": 1,
                "samples": 1,
            },
            "udp_mappings_state": {
                "wait_nanoseconds": 1,
                "hold_nanoseconds": 1,
                "samples": 1,
            },
        },
        "structural": {
            "schema_version": STRUCTURAL_SCHEMA_VERSION,
            "aggregation": STRUCTURAL_AGGREGATION,
            "counter_schema": {
                name: {
                    "unit": (
                        "bytes"
                        if name.endswith("_bytes")
                        else (
                            "nanoseconds" if name.endswith("_nanoseconds") else "events"
                        )
                    ),
                    "aggregation": STRUCTURAL_AGGREGATION,
                    "range": {"minimum": 0, "maximum": (1 << 64) - 1},
                }
                for name in STRUCTURAL_COUNTERS
            },
            "counter_count": len(STRUCTURAL_COUNTERS),
            "client_before": {"values": dict(before), "overflowed": False},
            "client_after": {"values": dict(after), "overflowed": False},
            "server_before": {"values": dict(before), "overflowed": False},
            "server_after": {"values": dict(after), "overflowed": False},
            "client_delta": dict(delta),
            "server_delta": dict(delta),
            "merged_delta": {name: 2 for name in STRUCTURAL_COUNTERS},
        },
        "cleanup": {
            "active_processes": 0,
            "active_workers": 0,
            "ready_file_removed": True,
            "status": "PASS",
        },
        "decision": "OBSERVATION_ONLY",
        "correctness": "PASS",
        "status": "PASS",
    }
