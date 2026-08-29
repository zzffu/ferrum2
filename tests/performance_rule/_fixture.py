from __future__ import annotations

import json
from pathlib import Path

from tools.performance_rule.pairing import (
    calibrated_limits,
    calibration_ceiling_limits,
    summarize,
)
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CONTROL_SCHEMA,
    RUNNER_PRIORITY_HIGH,
    RUNNER_SCHEMA,
    expected_profile_sizes,
)

IDENTIFIERS = (
    "dns_policy/one",
    "match_set/one",
    "route_program/one",
    "snapshot_registry/registry_publish/publish_under_readers",
    "snapshot_registry/registry_read/read_under_publish",
)
SCENARIO_SUITES = {
    identifier: identifier.split("/", 1)[0] for identifier in IDENTIFIERS
}
RUNNER_SHA256 = "a" * 64
RUNNER_ARGUMENTS = [
    "--profile",
    "qualification",
    "--samples",
    "101",
    "--workspace-root",
    ".",
]


def report(
    sha256: str,
    identifiers=IDENTIFIERS,
    value: int | dict[str, int] = 10,
    enabled_features: tuple[str, ...] = (),
):
    match_sizes, route_sizes, dns_rule_sizes = expected_profile_sizes(
        "qualification", False
    )
    return {
        "schema": RUNNER_SCHEMA,
        "generated_unix_millis": 1,
        "profile": "qualification",
        "environment": {
            "os": "test",
            "architecture": "x86_64",
            "family": "test",
            "logical_cpus": 1,
            "cpu_model": "synthetic",
            "rustc_version": "rustc 1.97.1 (synthetic)",
            "timer": "std::time::Instant",
            "build_profile": "release",
        },
        "repository": {
            "git_head": "b" * 40,
            "git_tree": "c" * 40,
            "tree_state": "clean",
            "changed_entries": 0,
            "status_sha256": "d" * 64,
        },
        "runner": {"sha256": sha256, "bytes": 1},
        "candidate": {
            "adoption_claim": False,
            "enabled_features": list(enabled_features),
        },
        "configuration": {
            "match_sizes": match_sizes,
            "route_sizes": route_sizes,
            "dns_rule_sizes": dns_rule_sizes,
            "snapshot_reader_threads": 4,
            "samples": 5,
            "base_iterations_per_sample": 10,
            "includes_100k": False,
        },
        "correctness_passed": True,
        "snapshot_lifecycle_passed": True,
        "allocation_gate_passed": True,
        "parity_gate_passed": True,
        "thresholds_passed": True,
        "measurement_policy": {
            "latency_source": "synthetic",
            "minimum_reported_batch_nanoseconds": 250_000,
            "calibration": "synthetic",
            "warmup_batches": 5,
            "paired_order": "synthetic",
            "retained_samples": True,
            "allocation_measurement": "synthetic",
            "compiled_memory_measurement": "synthetic",
            "local_parity_target_percent": 5.0,
            "noisy_gate_ceiling_percent": 10.0,
            "thresholds_enforced_by_runner": True,
            "p99_parity_target_percent": 15.0,
            "parity_gate_scope": "synthetic",
            "paired_observation_scope": "synthetic",
            "allocation_gate_scope": "synthetic",
            "note": "synthetic test fixture",
        },
        "fixtures": [],
        "measurements": [
            {
                "id": identifier,
                "suite": identifier.split("/", 1)[0],
                "source": (
                    "registry_read"
                    if "/registry_read/" in identifier
                    else (
                        "registry_publish"
                        if "/registry_publish/" in identifier
                        else "synthetic"
                    )
                ),
                "scenario": (
                    "read_under_publish"
                    if identifier.endswith("/read_under_publish")
                    else (
                        "publish_under_readers"
                        if identifier.endswith("/publish_under_readers")
                        else identifier
                    )
                ),
                "scale": 4 if identifier.startswith("snapshot_registry/") else 1,
                "fixture": None,
                "rule_program_mode": None,
                "query_candidate_visits": None,
                "p50_ns_per_op": (
                    value.get(identifier, 10) if isinstance(value, dict) else value
                ),
                "p99_ns_per_op": (
                    value.get(identifier, 10) if isinstance(value, dict) else value
                )
                + 2,
                "queries_per_second_from_p50": None,
                "build_nanoseconds": 1,
                "compiled_allocations": 0,
                "compiled_reallocations": 0,
                "compiled_entries": 1,
                "samples_ns_per_op": [
                    value.get(identifier, 10) if isinstance(value, dict) else value
                ]
                * 5,
                "requested_min_iterations_per_sample": 10,
                "actual_iterations_per_sample": [10] * 5,
                "sample_batch_nanoseconds": [250_000] * 5,
                "timing_pair_id": None,
                "paired_sample_order": None,
                "allocations_per_op": 0.0,
                "reallocations_per_op": 0.0,
                "bytes_allocated_per_op": 0.0,
                "bytes_deallocated_per_op": 0.0,
                "compiled_memory_bytes": 128,
                "compiled_bytes_per_entry": 128.0,
                "allocation_samples": [
                    {
                        "iterations": 1,
                        "allocations": 0,
                        "deallocations": 0,
                        "reallocations": 0,
                        "bytes_allocated": 0,
                        "bytes_deallocated": 0,
                    }
                ]
                * 5,
                "allocation_gate_applicable": identifier.startswith(
                    ("match_set/", "route_program/")
                ),
                "allocation_gate_passed": (
                    True
                    if identifier.startswith(("match_set/", "route_program/"))
                    else None
                ),
                "allocation_status": "measured",
                "compiled_memory_status": "measured",
                "correctness": "passed",
                "outcome_checksum": 1,
            }
            for identifier in identifiers
        ],
        "snapshot_lifecycle": {
            "reader_threads": 4,
            "initial_generation": 1,
            "published_generation": 2,
            "reader_generation": 1,
            "reader_action": 1,
            "fresh_generation": 2,
            "fresh_action": 0,
            "returned_old_generation": 1,
            "returned_old_matches_initial": True,
            "old_snapshot_alive_before_reader_release": True,
            "old_snapshot_released_after_reader_release": True,
            "generation_action_consistent": True,
            "publish_monotonic": True,
            "watch_observed_generation": 2,
            "watch_no_missed_publication": True,
        },
        "parity_observations": [],
        "scenario_count": len(identifiers),
    }


def aa_source_report() -> dict[str, object]:
    pairs = []
    execution_trace = []
    for pair_index in range(6):
        parent = report(RUNNER_SHA256, value=100)
        candidate = report(RUNNER_SHA256, value=104)
        pairs.append({"parent": parent, "candidate": candidate})
        roles = (
            ("parent", "candidate") if pair_index % 2 == 0 else ("candidate", "parent")
        )
        for order_index, role in enumerate(roles, 1):
            execution_trace.append(
                {
                    "pair": pair_index + 1,
                    "order": order_index,
                    "role": role,
                    "runner_sha256": RUNNER_SHA256,
                }
            )
    comparisons = summarize(
        SCENARIO_SUITES,
        pairs,
        True,
        calibration_ceiling_limits(),
    )
    limits = calibrated_limits(comparisons)
    return {
        "schema": CONTROL_SCHEMA,
        "generated_unix_millis": 1,
        "mode": "aa",
        "status": CALIBRATION_REQUIRED,
        "pairs": 6,
        "parent_runner_sha256": RUNNER_SHA256,
        "candidate_runner_sha256": RUNNER_SHA256,
        "runner_arguments": RUNNER_ARGUMENTS,
        "scenario_ids": sorted(SCENARIO_SUITES),
        "scenario_suites": dict(sorted(SCENARIO_SUITES.items())),
        "execution_policy": {
            "pair_order": "alternating_parent_candidate",
            "raw_reports_retained": True,
            "runner_process_priority": RUNNER_PRIORITY_HIGH,
        },
        "execution_trace": execution_trace,
        "comparisons": comparisons,
        "threshold_policy": threshold_policy(
            comparisons, limits, None, None, reviewed=False
        ),
        "raw_pairs": pairs,
        "decision_reason": "A/A evidence requires explicit review",
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
