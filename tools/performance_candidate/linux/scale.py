"""scale owner."""

from __future__ import annotations

from tools.performance_candidate.identity import COMMIT_SHA
from tools.performance_candidate.json_contract import CandidateControlError, SHA256, _exact_fields, _scale_decimal, read_bounded_closed_json
from tools.performance_candidate.linux.environment import (
    MEMORY_CAPACITY_QUANTUM_KIB,
    calibration_environments_match,
)

import pathlib
from decimal import Decimal


SCALE_TRIAL_MAX_BYTES = 512 * 1024
SCALE_SAFETY_POLICY_MAX_BYTES = 64 * 1024


SCALE_SCENARIO = "tcp-scale-10k"


SCALE_POLICY_SCHEMA_VERSION = 3


SCALE_OBSERVED_ENVIRONMENT_FIELDS = frozenset(
    {
        "runner_image",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "build_profile",
    }
)


SCALE_RECIPE = {
    "sessions": 10_000,
    "setup_workers": 256,
    "runtime_worker_threads": 4,
    "application_futures": 10_000,
    "target_futures": 10_000,
    "payload_bytes": 32_768,
    "touch_rounds": 2,
    "partial_active_flows": 1_000,
    "partial_selector_modulus": 10,
    "partial_selector_remainder": 0,
    "partial_seconds": 10,
    "full_seconds": 30,
    "resource_samples_per_phase": 5,
    "quiescent_sample_interval_milliseconds": 1_000,
    "active_sample_slot_denominator": 6,
}


SCALE_POLICY_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "calibration_source",
        "calibration_environment",
        "required_pairs",
        "required_sessions",
        "required_partial_active_sessions",
        "minimum_trial_jain_index",
        "minimum_trial_p01_median_ratio",
        "minimum_median_jain_delta",
        "minimum_median_p01_median_ratio_delta",
        "minimum_median_throughput_improvement_percent",
        "minimum_throughput_wins",
        "minimum_pair_throughput_improvement_percent",
        "maximum_post_full_percent_of_page_touched",
        "maximum_page_touch_growth_of_growth_kib_per_connection_per_process",
        "maximum_page_touch_growth_of_growth_kib_per_connection_combined",
    }
)


SCALE_POLICY_RUNTIME_FIELDS = frozenset(
    {*SCALE_POLICY_DOCUMENT_FIELDS, "policy_sha256"}
)


SCALE_LINEAGE_FIELDS = frozenset(
    {
        "schema_version",
        "head_sha",
        "head_tree",
        "parent_sha",
        "parent_tree",
        "candidate_sha",
        "candidate_tree",
        "counterfactual_patch_sha256",
        "runner_sha256",
        "parent_client_sha256",
        "parent_server_sha256",
        "candidate_client_sha256",
        "candidate_server_sha256",
    }
)


SCALE_FIELDS = frozenset(
    {"schema_version", "recipe", "correctness", "traffic", "fairness", "resource"}
)


SCALE_CORRECTNESS_FIELDS = frozenset(
    {
        "target_accepted",
        "client_active",
        "server_active",
        "touch_completed_flows",
        "touch_completed_round_trips",
        "touch_checked_bytes",
        "payload_checks",
        "partial_nonzero_flows",
        "full_nonzero_flows",
        "application_tasks_joined",
        "target_tasks_joined",
        "drain",
        "rebind",
        "cleanup",
    }
)


SCALE_TRAFFIC_FIELDS = frozenset(
    {
        "partial_checked_bytes",
        "partial_io_completions",
        "partial_discarded_tail_completions",
        "partial_flow_bytes",
        "full_checked_bytes",
        "full_io_completions",
        "full_discarded_tail_completions",
        "full_elapsed_nanoseconds",
        "full_flow_bytes",
        "full_flow_completions",
        "aggregate_bytes_per_second",
    }
)


SCALE_FAIRNESS_FIELDS = frozenset(
    {
        "jain_ppb",
        "minimum_bytes",
        "p01_bytes",
        "p05_bytes",
        "median_bytes",
        "p95_bytes",
        "p99_bytes",
        "maximum_bytes",
        "p01_to_median_ppm",
    }
)


SCALE_RESOURCE_FIELDS = frozenset(
    {
        "pre_load",
        "established",
        "touched",
        "partial_active",
        "full_active",
        "post_full",
        "drained",
        "client_touched_increment_bytes_per_connection",
        "server_touched_increment_bytes_per_connection",
        "combined_touched_increment_bytes_per_connection",
        "harness_peak_rss_kib",
        "memory_available_kib",
        "nofile_soft",
    }
)


SCALE_SAMPLE_FIELDS = frozenset(
    {
        "client_active",
        "server_active",
        "client_fds",
        "server_fds",
        "client_tasks",
        "server_tasks",
        "client_rss_kib",
        "server_rss_kib",
        "client_smaps_rss_kib",
        "server_smaps_rss_kib",
        "client_anonymous_kib",
        "server_anonymous_kib",
        "client_anon_huge_pages_kib",
        "server_anon_huge_pages_kib",
        "harness_rss_kib",
    }
)


SCALE_COUNTERFACTUAL_REPLACEMENTS = {
    "crates/ferrum2-runtime/src/relay.rs": ((
        b"pub const RELAY_BUFFER_BYTES: usize = 32_768;",
        b"pub const RELAY_BUFFER_BYTES: usize = 16_384;",
    ),),
    "crates/ferrum2-runtime/tests/backpressure.rs": ((
        b"assert_eq!(RELAY_BUFFER_BYTES, 32_768);",
        b"assert_eq!(RELAY_BUFFER_BYTES, 16_384);",
    ),),
    "crates/ferrum2-shadowsocks/src/lib.rs": ((
        b"pub const MAX_ENCODE_PAYLOAD_LEN: usize = 32_768;",
        b"pub const MAX_ENCODE_PAYLOAD_LEN: usize = 16_384;",
    ),),
    "crates/ferrum2-shadowsocks/tests/tcp_allocation_bounds.rs": (
        (
            b"assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 32_768);",
            b"assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 16_384);",
        ),
        (
            b"assert_eq!(frames.len(), 8);",
            b"assert_eq!(frames.len(), 16);",
        ),
    ),
}


def _scale_scenario_entry() -> dict[str, object]:
    return {
        "scenario": SCALE_SCENARIO,
        "role": "scale_safety",
        "mandatory": True,
        "metric": "bytes_per_second",
        "direction": "higher_is_better",
        "topology": "shadowsocks",
        "application_payload_bytes": SCALE_RECIPE["payload_bytes"],
        "workload_scale": None,
        "socks_datagram_bytes": None,
        "upstream_wire_bytes": None,
    }


def validate_scale_safety_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("scale safety policy must be a JSON object")
    _exact_fields(policy, SCALE_POLICY_RUNTIME_FIELDS, "scale safety policy")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCALE_POLICY_SCHEMA_VERSION
    ):
        raise CandidateControlError("scale safety policy schema_version is unsupported")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("scale safety policy_id must be non-empty")
    digest = policy["policy_sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise CandidateControlError("scale safety policy must have a SHA-256 identity")
    calibration_source = policy["calibration_source"]
    calibration_environment = policy["calibration_environment"]
    if (calibration_source is None) != (calibration_environment is None):
        raise CandidateControlError("scale calibration must be complete or entirely null")
    if calibration_source is not None:
        if type(calibration_source) is not str or not calibration_source.startswith("artifact:"):
            raise CandidateControlError("scale calibration_source is invalid")
        expected_fields = {
            "runner_image",
            "pair_schedule",
            "required_pairs",
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
            "rustc",
            "kernel",
            "cpu_model",
            "cpu_count",
            "memory_kib",
            "build_profile",
        }
        if type(calibration_environment) is not dict or set(calibration_environment) != expected_fields:
            raise CandidateControlError("scale calibration_environment is invalid")
        for field in (
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
        ):
            if type(calibration_environment[field]) is not str or SHA256.fullmatch(calibration_environment[field]) is None:
                raise CandidateControlError(f"scale calibration_environment {field} is invalid")
        for field in ("rustc", "kernel", "cpu_model", "build_profile"):
            if type(calibration_environment[field]) is not str or not calibration_environment[field]:
                raise CandidateControlError(f"scale calibration_environment {field} is invalid")
        for field in ("cpu_count", "memory_kib"):
            if type(calibration_environment[field]) is not int or calibration_environment[field] <= 0:
                raise CandidateControlError(f"scale calibration_environment {field} is invalid")
        if calibration_environment["memory_kib"] % MEMORY_CAPACITY_QUANTUM_KIB != 0:
            raise CandidateControlError(
                "scale calibration_environment memory_kib must be a 64 MiB capacity anchor"
            )
    exact_integers = {
        "required_pairs": 6,
        "required_sessions": 10_000,
        "required_partial_active_sessions": 1_000,
        "minimum_throughput_wins": 4,
    }
    for field, expected in exact_integers.items():
        if type(policy[field]) is not int or policy[field] != expected:
            raise CandidateControlError(f"scale safety policy {field} must be {expected}")
    minimums = {
        "minimum_trial_jain_index": Decimal("0.90"),
        "minimum_trial_p01_median_ratio": Decimal("0.50"),
        "minimum_median_jain_delta": Decimal("-0.01"),
        "minimum_median_p01_median_ratio_delta": Decimal("-0.05"),
        "minimum_median_throughput_improvement_percent": Decimal("0"),
        "minimum_pair_throughput_improvement_percent": Decimal("-10"),
    }
    for field, lower_bound in minimums.items():
        if _scale_decimal(policy[field], field) < lower_bound:
            raise CandidateControlError(f"scale safety policy {field} is too weak")
    maximums = {
        "maximum_post_full_percent_of_page_touched": Decimal("105"),
        "maximum_page_touch_growth_of_growth_kib_per_connection_per_process": Decimal("64"),
        "maximum_page_touch_growth_of_growth_kib_per_connection_combined": Decimal("128"),
    }
    for field, upper_bound in maximums.items():
        value = _scale_decimal(policy[field], field)
        if value < 0 or value > upper_bound:
            raise CandidateControlError(f"scale safety policy {field} is too weak")
    for field in (
        "minimum_trial_jain_index",
        "minimum_trial_p01_median_ratio",
    ):
        if _scale_decimal(policy[field], field) > 1:
            raise CandidateControlError(f"scale safety policy {field} exceeds one")


def scale_policy_is_applicable(
    policy: dict[str, object],
    scenario_plan: dict[str, object],
    observed_environment: dict[str, object],
) -> bool:
    validate_scale_safety_policy(policy)
    environment = policy["calibration_environment"]
    if (
        environment is None
        or type(observed_environment) is not dict
        or set(observed_environment) != SCALE_OBSERVED_ENVIRONMENT_FIELDS
    ):
        return False
    contract = scenario_plan["evidence_contract"]
    expected_environment = {
        "runner_image": contract["runner_image"],
        "pair_schedule": "abba-six-pairs",
        "required_pairs": 6,
        **{
            field: contract[field]
            for field in (
                "producer_source_sha256",
                "controller_source_sha256",
                "semantic_recipe_sha256",
                "evidence_bundle_sha256",
            )
        },
        **observed_environment,
    }
    return calibration_environments_match(environment, expected_environment)


def load_scale_safety_policy(path: pathlib.Path) -> dict[str, object]:
    loaded = read_bounded_closed_json(
        path,
        maximum_bytes=SCALE_SAFETY_POLICY_MAX_BYTES,
        source="scale safety policy",
    )
    document = loaded.value
    if type(document) is not dict:
        raise CandidateControlError("scale safety policy must be a JSON object")
    _exact_fields(document, SCALE_POLICY_DOCUMENT_FIELDS, "scale safety policy")
    policy = {
        **document,
        "policy_sha256": loaded.sha256,
    }
    validate_scale_safety_policy(policy)
    return policy


def validate_scale_lineage_shape(lineage: dict[str, object]) -> None:
    if type(lineage) is not dict:
        raise CandidateControlError("scale lineage must be a JSON object")
    _exact_fields(lineage, SCALE_LINEAGE_FIELDS, "scale lineage")
    if type(lineage["schema_version"]) is not int or lineage["schema_version"] != 1:
        raise CandidateControlError("scale lineage schema_version is unsupported")
    for field in (
        "head_sha",
        "head_tree",
        "parent_sha",
        "parent_tree",
        "candidate_sha",
        "candidate_tree",
    ):
        value = lineage[field]
        if type(value) is not str or COMMIT_SHA.fullmatch(value) is None:
            raise CandidateControlError(f"scale lineage {field} is invalid")
    for field in (
        "counterfactual_patch_sha256",
        "runner_sha256",
        "parent_client_sha256",
        "parent_server_sha256",
        "candidate_client_sha256",
        "candidate_server_sha256",
    ):
        value = lineage[field]
        if type(value) is not str or SHA256.fullmatch(value) is None:
            raise CandidateControlError(f"scale lineage {field} is invalid")
    if len(
        {
            lineage["head_sha"],
            lineage["parent_sha"],
            lineage["candidate_sha"],
        }
    ) != 3:
        raise CandidateControlError("scale lineage commits must be distinct")
    if lineage["head_tree"] != lineage["candidate_tree"]:
        raise CandidateControlError("scale candidate tree must equal the final head tree")
    if lineage["parent_tree"] == lineage["head_tree"]:
        raise CandidateControlError("scale parent tree must be the 16 KiB counterfactual")
