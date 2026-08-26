#!/usr/bin/env python3
"""Behavior tests for the manual performance candidate control plane."""

from __future__ import annotations

import copy
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "tools" / "performance_candidate_policy.json"
SCALE_POLICY_PATH = ROOT / "tools" / "performance_candidate_scale_safety_policy.json"
WINDOWS_TUN_POLICY_PATH = ROOT / "tools" / "windows_tun_performance_policy.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "performance-candidate.yml"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import evidence_contract
from tools.performance_candidate.linux import policy as linux_policy
from tools.performance_candidate.linux import scale as linux_scale
from tools.performance_candidate.linux import scale_trial
from tools.performance_candidate.linux import trial as linux_trial

def synthetic_policy(
    *,
    calibrated_scenarios: set[str] | None = None,
    noise: float = 2.0,
    regression: float = -5.0,
    adoption: float = 5.0,
    minimum_pairs: int = 6,
    minimum_wins: int = 4,
    minimum_losses: int = 4,
    warmup_seconds: int = 3,
    active_seconds: int = 30,
) -> dict[str, object]:
    policy = copy.deepcopy(linux_policy.UNCALIBRATED_POLICY)
    policy["policy_id"] = "synthetic-test-calibration"
    calibrated_scenarios = calibrated_scenarios or set(linux_catalog.SCENARIO_CATALOG)
    for scenario in calibrated_scenarios:
        contract = evidence_contract.catalog_evidence_contract(
            scenario,
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
            pair_schedule=linux_catalog.PAIR_SCHEDULE,
        )
        environment = {
            **linux_policy.MEASUREMENT_ENVIRONMENT,
            "warmup_seconds": warmup_seconds,
            "active_seconds": active_seconds,
            **{
                field: contract[field]
                for field in (
                    "producer_source_sha256",
                    "controller_source_sha256",
                    "semantic_recipe_sha256",
                    "evidence_bundle_sha256",
                )
            },
            "rustc": "rustc 1.97.1 test",
            "kernel": "test-kernel",
            "cpu_model": "test-cpu",
            "cpu_count": 8,
            "memory_kib": 16_777_216,
            "build_profile": "current",
        }
        policy["scenarios"][scenario].update(
            {
                "noise_band_percent": noise,
                "regression_threshold_percent": regression,
                "adoption_threshold_percent": adoption,
                "minimum_pairs": minimum_pairs,
                "minimum_wins": minimum_wins,
                "minimum_losses": minimum_losses,
                "calibration_source": "artifact:synthetic-test-only",
                "calibration_environment": dict(environment),
            }
        )
    linux_policy.validate_decision_policy(policy)
    return policy


def synthetic_scale_sample(
    *, active: int, client_smaps: int, server_smaps: int, harness: int = 100
) -> dict[str, int]:
    return {
        "client_active": active,
        "server_active": active,
        "client_fds": 20 if active else 10,
        "server_fds": 20 if active else 10,
        "client_tasks": 8 if active else 4,
        "server_tasks": 8 if active else 4,
        "client_rss_kib": client_smaps,
        "server_rss_kib": server_smaps,
        "client_smaps_rss_kib": client_smaps,
        "server_smaps_rss_kib": server_smaps,
        "client_anonymous_kib": client_smaps,
        "server_anonymous_kib": server_smaps,
        "client_anon_huge_pages_kib": 0,
        "server_anon_huge_pages_kib": 0,
        "harness_rss_kib": harness,
    }


def synthetic_scale_row(
    *,
    pair: int,
    member: str,
    full_completions: int = 100,
    starve_first: bool = False,
    client_touch_extra_kib: int = 0,
    server_touch_extra_kib: int = 0,
) -> dict[str, object]:
    payload = linux_scale.SCALE_RECIPE["payload_bytes"]
    completions = [full_completions] * 10_000
    if starve_first:
        completions[0] = 0
    full_bytes = [value * payload for value in completions]
    partial_bytes = [payload] * 1_000
    full_checked = sum(full_bytes)
    full_completion_sum = sum(completions)
    elapsed = 30_000_000_000
    fairness_derived = scale_trial._recompute_scale_fairness(full_bytes)
    fairness = {
        field: fairness_derived[field] for field in linux_scale.SCALE_FAIRNESS_FIELDS
    }
    established = synthetic_scale_sample(
        active=10_000, client_smaps=2_000, server_smaps=3_000
    )
    touched = synthetic_scale_sample(
        active=10_000,
        client_smaps=3_000 + client_touch_extra_kib,
        server_smaps=4_000 + server_touch_extra_kib,
    )
    quiet = synthetic_scale_sample(active=0, client_smaps=1_000, server_smaps=1_500)
    client_increment = scale_trial._truncating_division(
        (1_000 + client_touch_extra_kib) * 1_024, 10_000
    )
    server_increment = scale_trial._truncating_division(
        (1_000 + server_touch_extra_kib) * 1_024, 10_000
    )
    partial_completions = 1_000
    touch_completions = 20_000
    scale = {
        "schema_version": 1,
        "recipe": dict(linux_scale.SCALE_RECIPE),
        "correctness": {
            "target_accepted": 10_000,
            "client_active": 10_000,
            "server_active": 10_000,
            "touch_completed_flows": 10_000,
            "touch_completed_round_trips": touch_completions,
            "touch_checked_bytes": touch_completions * payload,
            "payload_checks": touch_completions
            + partial_completions
            + full_completion_sum,
            "partial_nonzero_flows": 1_000,
            "full_nonzero_flows": sum(value != 0 for value in full_bytes),
            "application_tasks_joined": 10_000,
            "target_tasks_joined": 10_000,
            "drain": "PASS",
            "rebind": "PASS",
            "cleanup": "PASS",
        },
        "traffic": {
            "partial_checked_bytes": sum(partial_bytes),
            "partial_io_completions": partial_completions,
            "partial_discarded_tail_completions": 0,
            "partial_flow_bytes": partial_bytes,
            "full_checked_bytes": full_checked,
            "full_io_completions": full_completion_sum,
            "full_discarded_tail_completions": 0,
            "full_elapsed_nanoseconds": elapsed,
            "full_flow_bytes": full_bytes,
            "full_flow_completions": completions,
            "aggregate_bytes_per_second": full_checked * 1_000_000_000 // elapsed,
        },
        "fairness": fairness,
        "resource": {
            "pre_load": [dict(quiet)],
            "established": [dict(established) for _ in range(5)],
            "touched": [dict(touched) for _ in range(5)],
            "partial_active": [dict(touched) for _ in range(5)],
            "full_active": [dict(touched) for _ in range(5)],
            "post_full": [dict(touched) for _ in range(5)],
            "drained": [dict(quiet)],
            "client_touched_increment_bytes_per_connection": client_increment,
            "server_touched_increment_bytes_per_connection": server_increment,
            "combined_touched_increment_bytes_per_connection": client_increment
            + server_increment,
            "harness_peak_rss_kib": 100,
            "memory_available_kib": 16_000_000,
            "nofile_soft": 65_536,
        },
    }
    parent = "1" * 40
    candidate = "2" * 40
    is_parent = member == "parent"
    contract = evidence_contract.scale_evidence_contract()
    return {
        "schema_version": linux_trial.PROFILE_TRIAL_SCHEMA_VERSION,
        "kind": "m18_profile_trial",
        "parent_sha": parent,
        "candidate_sha": candidate,
        "member": member,
        "pair": pair,
        "order": 1 if (pair % 2 == 1) == is_parent else 2,
        "build_profile": "current",
        "scenario": linux_scale.SCALE_SCENARIO,
        "warmup_seconds": 10,
        "active_seconds": 30,
        "topology": "shadowsocks",
        "application_payload_bytes": payload,
        "socks_datagram_bytes": None,
        "upstream_wire_bytes": None,
        "sha": parent if is_parent else candidate,
        "tree": ("3" if is_parent else "4") * 40,
        "runner_sha256": "a" * 64,
        "client_sha256": ("b" if is_parent else "c") * 64,
        "server_sha256": ("d" if is_parent else "e") * 64,
        "rustc": "rustc 1.97.1 test",
        "kernel": "test-kernel",
        "cpu_model": "test-cpu",
        "cpu_count": 8,
        "memory_kib": 32_000_000,
        "metric": "bytes_per_second",
        "unit": contract["unit"],
        "value": scale["traffic"]["aggregate_bytes_per_second"],
        "checked_units": full_checked,
        "p99_nanoseconds": None,
        "io_completions": full_completion_sum * 2,
        "scale": scale,
        "producer_source_sha256": contract["producer_source_sha256"],
        "controller_source_sha256": contract["controller_source_sha256"],
        "semantic_recipe_sha256": contract["semantic_recipe_sha256"],
        "evidence_bundle_sha256": contract["evidence_bundle_sha256"],
        "environment_identity": {
            "runner_image": contract["runner_image"],
            "rustc": "rustc 1.97.1 test",
            "kernel": "test-kernel",
            "cpu_model": "test-cpu",
            "cpu_count": 8,
            "memory_kib": 32_000_000,
            "build_profile": "current",
        },
        "cleanup": copy.deepcopy(contract["cleanup_contract"]),
        "correctness": "PASS",
        "status": "PASS",
    }


def rewrite_scale_full_completions(
    row: dict[str, object], completions: list[int]
) -> None:
    if len(completions) != linux_scale.SCALE_RECIPE["sessions"]:
        raise AssertionError("scale completion fixture must cover all sessions")
    scale = row["scale"]
    traffic = scale["traffic"]
    correctness = scale["correctness"]
    payload = linux_scale.SCALE_RECIPE["payload_bytes"]
    full_bytes = [value * payload for value in completions]
    full_checked = sum(full_bytes)
    full_completion_sum = sum(completions)
    traffic["full_flow_bytes"] = full_bytes
    traffic["full_flow_completions"] = list(completions)
    traffic["full_checked_bytes"] = full_checked
    traffic["full_io_completions"] = full_completion_sum
    traffic["aggregate_bytes_per_second"] = (
        full_checked * 1_000_000_000 // traffic["full_elapsed_nanoseconds"]
    )
    fairness = scale_trial._recompute_scale_fairness(full_bytes)
    scale["fairness"] = {
        field: fairness[field] for field in linux_scale.SCALE_FAIRNESS_FIELDS
    }
    correctness["full_nonzero_flows"] = sum(value != 0 for value in full_bytes)
    correctness["payload_checks"] = (
        correctness["touch_completed_round_trips"]
        + traffic["partial_io_completions"]
        + traffic["partial_discarded_tail_completions"]
        + full_completion_sum
        + traffic["full_discarded_tail_completions"]
    )
    row["value"] = traffic["aggregate_bytes_per_second"]
    row["checked_units"] = full_checked
    row["io_completions"] = full_completion_sum * 2


def rewrite_scale_resource_increments(row: dict[str, object]) -> None:
    resource = row["scale"]["resource"]
    sessions = linux_scale.SCALE_RECIPE["sessions"]
    increments = {}
    for side in ("client", "server"):
        field = f"{side}_smaps_rss_kib"
        established = scale_trial._scale_stage_median(resource["established"], field)
        touched = scale_trial._scale_stage_median(resource["touched"], field)
        increments[side] = scale_trial._truncating_division(
            (touched - established) * 1_024, sessions
        )
        resource[f"{side}_touched_increment_bytes_per_connection"] = increments[
            side
        ]
    resource["combined_touched_increment_bytes_per_connection"] = (
        increments["client"] + increments["server"]
    )


def synthetic_scale_lineage() -> dict[str, object]:
    return {
        "schema_version": 1,
        "head_sha": "0" * 40,
        "head_tree": "4" * 40,
        "parent_sha": "1" * 40,
        "parent_tree": "3" * 40,
        "candidate_sha": "2" * 40,
        "candidate_tree": "4" * 40,
        "counterfactual_patch_sha256": "f" * 64,
        "runner_sha256": "a" * 64,
        "parent_client_sha256": "b" * 64,
        "parent_server_sha256": "d" * 64,
        "candidate_client_sha256": "c" * 64,
        "candidate_server_sha256": "e" * 64,
    }
