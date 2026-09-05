from __future__ import annotations

import json
from pathlib import Path

from tools.performance_rule.pairing import calibrated_limit, summarize
from tools.performance_rule.policy import threshold_policy
from tools.performance_rule.schema import (
    CALIBRATION_REQUIRED,
    CONTROL_SCHEMA,
    RUNNER_PRIORITY_HIGH,
    RUNNER_SCHEMA,
)


IDENTIFIERS = (
    "dns_policy/cache/1/cache_hit",
    "match_set/ordinary_inline/100/exact/hit",
    "match_set/synthetic_ruleset/100/exact/hit",
    "route_program/mixed/1/small_linear/last",
)
SCENARIO_SUITES = {
    identifier: identifier.split("/", 1)[0] for identifier in IDENTIFIERS
}
RUNNER_SHA256 = "a" * 64
RUNNER_ARGUMENTS = ["--profile", "smoke", "--samples", "501"]


def report(sha256: str, identifiers=IDENTIFIERS, value: int = 10):
    return {
        "schema": RUNNER_SCHEMA,
        "generated_unix_millis": 1,
        "profile": "smoke",
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
        "configuration": {
            "match_sizes": [100],
            "route_sizes": [1],
            "dns_rule_sizes": [1],
            "samples": 5,
            "base_iterations_per_sample": 10,
            "includes_100k": False,
        },
        "correctness_passed": True,
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
                "source": identifier.split("/")[1],
                "scenario": "exact/hit" if identifier.startswith("match_set/") else identifier,
                "scale": 100 if identifier.startswith("match_set/") else 1,
                "fixture": None,
                "rule_program_mode": "small_linear" if identifier.startswith("route_program/") else None,
                "query_candidate_visits": None,
                "p50_ns_per_op": value,
                "p99_ns_per_op": value,
                "queries_per_second_from_p50": 1_000_000_000 / value if identifier.startswith("dns_policy/") else None,
                "build_nanoseconds": 1,
                "compiled_allocations": 0,
                "compiled_reallocations": 0,
                "compiled_entries": 100 if identifier.startswith("match_set/") else 1,
                "samples_ns_per_op": [value] * 5,
                "requested_min_iterations_per_sample": 10,
                "actual_iterations_per_sample": [320_000] * 5,
                "sample_batch_nanoseconds": [320_000 * value] * 5,
                "timing_pair_id": "match_set/100/exact/hit" if identifier.startswith("match_set/") else None,
                "paired_sample_order": ["baseline_first", "candidate_first", "baseline_first", "candidate_first", "baseline_first"] if identifier.startswith("match_set/") else None,
                "allocations_per_op": 0.0,
                "reallocations_per_op": 0.0,
                "bytes_allocated_per_op": 0.0,
                "bytes_deallocated_per_op": 0.0,
                "compiled_memory_bytes": 128,
                "compiled_bytes_per_entry": 1.28 if identifier.startswith("match_set/") else 128.0,
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
                "allocation_gate_applicable": not identifier.startswith("dns_policy/"),
                "allocation_gate_passed": None if identifier.startswith("dns_policy/") else True,
                "allocation_status": "measured",
                "compiled_memory_status": "measured_net_retained_bytes",
                "correctness": "passed",
                "outcome_checksum": 1,
            }
            for identifier in identifiers
        ],
        "parity_observations": [{
            "suite": "match_set", "scenario": "exact/hit", "scale": 100,
            "baseline_id": "match_set/ordinary_inline/100/exact/hit",
            "candidate_id": "match_set/synthetic_ruleset/100/exact/hit",
            "median_delta_percent": 0.0, "p99_delta_percent": 0.0,
            "median_limit_percent": 5.0, "p99_limit_percent": 15.0,
            "performance_gate_applicable": True, "decision": "passed",
        }] if "match_set/ordinary_inline/100/exact/hit" in identifiers else [],
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
            ("parent", "candidate")
            if pair_index % 2 == 0
            else ("candidate", "parent")
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
    comparisons = summarize(SCENARIO_SUITES, pairs, True, 10.0)
    limit = calibrated_limit(comparisons)
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
            comparisons, limit, None, None, reviewed=False
        ),
        "raw_pairs": pairs,
        "decision_reason": "A/A evidence requires explicit review",
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
