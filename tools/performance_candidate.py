#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction

WINDOWS_TUN_NETWORK_MODEL_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "tests"
    / "performance_candidate"
    / "windows_tun_network_model.py"
)
_WINDOWS_TUN_NETWORK_MODEL_SPEC = importlib.util.spec_from_file_location(
    "ferrum2_windows_tun_network_model", WINDOWS_TUN_NETWORK_MODEL_PATH
)
if (
    _WINDOWS_TUN_NETWORK_MODEL_SPEC is None
    or _WINDOWS_TUN_NETWORK_MODEL_SPEC.loader is None
):
    raise RuntimeError("unable to load the Windows TUN network-model controller")
WINDOWS_TUN_NETWORK_MODEL = importlib.util.module_from_spec(
    _WINDOWS_TUN_NETWORK_MODEL_SPEC
)
_WINDOWS_TUN_NETWORK_MODEL_SPEC.loader.exec_module(WINDOWS_TUN_NETWORK_MODEL)
WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256 = hashlib.sha256(
    WINDOWS_TUN_NETWORK_MODEL_PATH.read_bytes()
).hexdigest()
WINDOWS_TUN_NETWORK_MODEL_PLAN = WINDOWS_TUN_NETWORK_MODEL.create_local_hyperv_plan()
WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256 = hashlib.sha256(
    (
        json.dumps(WINDOWS_TUN_NETWORK_MODEL_PLAN, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
).hexdigest()
WINDOWS_TUN_REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
WINDOWS_TUN_RUNNER_PATH = (
    WINDOWS_TUN_REPOSITORY_ROOT / "tools" / "run_windows_tun_performance_hyperv.ps1"
)
WINDOWS_TUN_RUNNER_SOURCE_SHA256 = hashlib.sha256(
    WINDOWS_TUN_RUNNER_PATH.read_bytes()
).hexdigest()
WINDOWS_TUN_COLLECTOR_SOURCE_SHA256 = hashlib.sha256(
    (WINDOWS_TUN_REPOSITORY_ROOT / "tools" / "collect_windows_tun_performance_trial.ps1").read_bytes()
).hexdigest()
WINDOWS_TUN_HARNESS_SOURCE_SHA256 = hashlib.sha256(
    (
        WINDOWS_TUN_REPOSITORY_ROOT
        / "tools"
        / "ferrum2-m4-qualification"
        / "src"
        / "m4_support"
        / "windows_tun.rs"
    ).read_bytes()
).hexdigest()

WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
MODES = frozenset({"diagnostic", "qualification"})
PLAN_SCHEMA_VERSION = 5
PROFILE_TRIAL_SCHEMA_VERSION = 3
SUMMARY_SCHEMA_VERSION = 6
REGULAR_TRIAL_MAX_BYTES = 16 * 1024
SCALE_TRIAL_MAX_BYTES = 512 * 1024
SCALE_SCENARIO = "tcp-scale-10k"
SCALE_POLICY_SCHEMA_VERSION = 1
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
SCENARIO_CATALOG = {
    "tcp-bulk": ("bytes_per_second", "higher_is_better", "tcp-throughput"),
    "tcp-stream-64k": (
        "bytes_per_second",
        "higher_is_better",
        "tcp-throughput",
    ),
    "tcp-request-1k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-4k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-16k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "udp-small-high": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-established",
    ),
    "udp-mtu-1200": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-established",
    ),
    "udp-payload-1472": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-payload-1500": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-payload-8192": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-max-wire-65507": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-direct-small-128": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-direct",
    ),
    "udp-direct-max-65497": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-direct",
    ),
}
# For a UDP round trip, upstream_wire_bytes is the larger directional wire:
# the AES-2022 response for Shadowsocks and the target-facing payload for Direct.
SCENARIO_EVIDENCE = {
    "tcp-bulk": ("shadowsocks", 65_536, None, None),
    "tcp-stream-64k": ("shadowsocks", 65_536, None, None),
    "tcp-request-1k": ("shadowsocks", 1_024, None, None),
    "tcp-request-4k": ("shadowsocks", 4_096, None, None),
    "tcp-request-16k": ("shadowsocks", 16_384, None, None),
    "udp-small-high": ("shadowsocks", 128, 138, 186),
    "udp-mtu-1200": ("shadowsocks", 1_200, 1_210, 1_258),
    "udp-payload-1472": ("shadowsocks", 1_472, 1_482, 1_530),
    "udp-payload-1500": ("shadowsocks", 1_500, 1_510, 1_558),
    "udp-payload-8192": ("shadowsocks", 8_192, 8_202, 8_250),
    # 65,449 application bytes fill the AES-2022 response wire to 65,507 bytes.
    "udp-max-wire-65507": ("shadowsocks", 65_449, 65_459, 65_507),
    # SOCKS/IPv4 consumes 10 of its 65,507-byte UDP datagram bound.
    "udp-direct-small-128": ("direct", 128, 138, 128),
    "udp-direct-max-65497": ("direct", 65_497, 65_507, 65_497),
}
TCP_REQUEST_SCENARIOS = (
    "tcp-request-1k",
    "tcp-request-4k",
    "tcp-request-16k",
)
UDP_SS_PAYLOAD_MATRIX = (
    "udp-small-high",
    "udp-mtu-1200",
    "udp-payload-1472",
    "udp-payload-1500",
    "udp-payload-8192",
    "udp-max-wire-65507",
)
UDP_DIRECT_PAYLOAD_BOUNDS = (
    "udp-direct-small-128",
    "udp-direct-max-65497",
)
QUALIFICATION_GROUPS = frozenset(
    {"tcp-frame-capacity", "udp-payload-matrix", "udp-direct-payload-bounds"}
)
# These lifecycle selections remain correctness qualifications.  Do not use a
# prefix match here: windows-tun-m17 is a real paired performance selection with
# its own evidence and calibration contracts below.
QUALIFICATION_ONLY_SELECTIONS = frozenset(
    {
        "windows-tun-network-reset-10",
        "windows-tun-network-reset-100",
        "windows-tun-network-reset-1000",
        "windows-tun-restart-10",
        "windows-tun-restart-100",
        "windows-tun-restart-1000",
        "windows-tun-fragments",
        "windows-tun-dual-stack-dns",
        "windows-tun-udp-policy",
        "windows-tun-scheduler-ring-full",
    }
)
WINDOWS_TUN_SELECTION = "windows-tun-m17"
WINDOWS_TUN_RUN_KINDS = frozenset({"comparison", "calibration-aa"})
WINDOWS_TUN_PAIR_COUNT = 5
WINDOWS_TUN_PLAN_SCHEMA_VERSION = 2
WINDOWS_TUN_TRIAL_SCHEMA_VERSION = 3
WINDOWS_TUN_SUMMARY_SCHEMA_VERSION = 2
WINDOWS_TUN_CALIBRATION_SCHEMA_VERSION = 2
WINDOWS_TUN_POLICY_SCHEMA_VERSION = 2
WINDOWS_TUN_TRIAL_MAX_BYTES = 64 * 1024
WINDOWS_TUN_PAIR_SCHEDULE = "alternating-parent-candidate"
WINDOWS_TUN_GUEST = {
    "runner_os": "Windows",
    "runner_arch": "X64",
    "runner_label": "ferrum2-hyperv-guest",
    "vm_name": "Windows 10 MSIX packaging environment",
    "vm_id": "82e20295-1d30-48e7-a751-e21d35d872d4",
    "checkpoint_name": "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9",
    "checkpoint_id": "1e570209-faf7-4248-8167-aa0687cdb8cf",
    "rust_toolchain": "1.97.1",
    "cargo_profile": "profiling",
    "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
}
WINDOWS_TUN_RUNTIME_RECIPE = {
    "runner_source_sha256": WINDOWS_TUN_RUNNER_SOURCE_SHA256,
    "collector_source_sha256": WINDOWS_TUN_COLLECTOR_SOURCE_SHA256,
    "harness_source_sha256": WINDOWS_TUN_HARNESS_SOURCE_SHA256,
    "preflight_probe": {
        "tcp_payload_bytes": 1_024,
        "udp_payload_bytes": 1_024,
        "udp_target_slots": 4,
        "fragment_payload_bytes": 1_440,
        "fragment_datagrams": 1,
        "fragment_ack_bytes": 24,
    },
    "tun_mtu_bytes": 1_420,
    "support_underlay_minimum_ipv4_packet_bytes": 1_468,
    "tun_ring_capacity_bytes": 131_072,
    "tun_max_tcp_flows": 4_096,
    "tun_tcp_buffer_bytes": 32_768,
    "tun_max_udp_mappings": 8_192,
    "tun_udp_filtering": "endpoint_independent",
    "udp_max_sessions": 16_384,
    "udp_max_buffered_bytes": 268_435_456,
    "udp_idle_timeout_milliseconds": 60_000,
    "shadowsocks_method": "2022-blake3-aes-128-gcm",
    "gso": False,
}

# Each scenario owns a closed recipe, metric/unit set, and correctness check
# set.  Values are intentionally measurement-free: reviewed thresholds live in
# the policy and must come from an A/A artifact produced on the approved guest.
WINDOWS_TUN_SCENARIOS = {
    "tcp-single-flow": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-shadowsocks-external-echo",
            "warmup_seconds": 10,
            "active_seconds": 60,
            "flows": 1,
            "payload_bytes": 65_536,
            "cpu_measurement_window": "warmup_and_active",
        },
        "metrics": {
            "throughput": {
                "unit": "bytes_per_second",
                "direction": "higher_is_better",
            },
            "cpu_cost": {
                "unit": "cpu_nanoseconds_per_gibibyte",
                "direction": "lower_is_better",
            },
        },
        "checked_unit": "payload_bytes",
        "minimum_checked_units": 67_108_864,
        "correctness_checks": (
            "single_flow_only",
            "payload_exact",
            "no_gso",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "tcp-256-flow-fairness": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-shadowsocks-external-echo",
            "warmup_seconds": 10,
            "active_seconds": 30,
            "flows": 256,
            "payload_bytes": 16_384,
        },
        "metrics": {
            "fairness": {
                "unit": "jain_index_parts_per_billion",
                "direction": "higher_is_better",
            },
        },
        "checked_unit": "completed_flows",
        "minimum_checked_units": 256,
        "correctness_checks": (
            "all_256_flows_nonzero",
            "payload_exact",
            "no_gso",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "udp-packets-per-second": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "active_seconds": 30,
            "associations": 1,
            "batch_datagrams": 64,
            "payload_bytes": 1_200,
        },
        "metrics": {
            "packet_rate": {
                "unit": "datagrams_per_second",
                "direction": "higher_is_better",
            },
        },
        "checked_unit": "echoed_datagrams",
        "minimum_checked_units": 4_096,
        "correctness_checks": (
            "every_reply_accounted",
            "payload_exact",
            "no_gso",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "udp-8192-association-lookup-expiry": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "associations": 8_192,
            "batch_associations": 256,
            "lookup_rounds": 64,
            "expiry_rounds": 1,
            "payload_bytes": 32,
        },
        "metrics": {
            "lookup_rate": {
                "unit": "lookups_per_second",
                "direction": "higher_is_better",
            },
            "expiry_cost": {
                "unit": "nanoseconds_per_8192_expirations",
                "direction": "lower_is_better",
            },
        },
        "checked_unit": "association_lookups",
        "minimum_checked_units": 524_288,
        "correctness_checks": (
            "exactly_8192_associations",
            "all_lookups_hit",
            "all_associations_expired",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "fragment-reassembly-throughput": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-direct-external-fragment-ack",
            "warmup_seconds": 5,
            "active_seconds": 30,
            "ip_families": 1,
            "fragments_per_datagram": 2,
            "batch_datagrams": 8,
            "payload_bytes": 1_440,
            "ack_window_milliseconds": 500,
            "max_missing_per_batch": 1,
            "max_retransmissions_per_sequence": 1,
            "retry_budget_unique_datagrams": 1_000_000,
            "minimum_retry_budget": 1,
            "retry_scope": "missing-sequence-only",
        },
        "metrics": {
            "reassembly_rate": {
                "unit": "reassembled_payload_bytes_per_second",
                "direction": "higher_is_better",
            },
        },
        "checked_unit": "reassembled_datagrams",
        "minimum_checked_units": 4_096,
        "correctness_checks": (
            "fragment_packets_observed",
            "no_reassembly_drop",
            "payload_exact",
            "no_gso",
            "all_sequences_acknowledged",
            "bounded_retransmissions",
            "no_adapter_packet_loss",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "idle-cpu-wakeup": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-idle-no-traffic",
            "settle_seconds": 10,
            "active_seconds": 60,
            "sample_interval_milliseconds": 1_000,
            "expected_traffic_packets": 0,
        },
        "metrics": {
            "cpu_idle_cost": {
                "unit": "cpu_nanoseconds_per_second",
                "direction": "lower_is_better",
            },
            "wakeups": {
                "unit": "process_context_switches_per_second",
                "direction": "lower_is_better",
            },
        },
        "checked_unit": "idle_samples",
        "minimum_checked_units": 60,
        "correctness_checks": (
            "session_active_throughout",
            "zero_test_traffic",
            "no_busy_poll_fallback",
            "clean_drain",
        ),
    },
    "wintun-ring-full-drop-rate": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "burst_attempts": 1_000_000,
            "packets_per_event": 1,
            "payload_bytes": 1_200,
            "post_burst_settle_seconds": 5,
            "drop_rate_denominator": "tun_response_attempts",
        },
        "metrics": {
            "drop_rate": {
                "unit": "dropped_packets_per_million_responses",
                "direction": "lower_is_better",
            },
            "pending_response_peak": {
                "unit": "pending_udp_responses",
                "direction": "lower_is_better",
            },
        },
        "checked_unit": "ring_full_events",
        "minimum_checked_units": 1,
        "correctness_checks": (
            "ring_full_counter_increased",
            "drop_rate_denominator_bound",
            "no_ring_full_retry",
            "pending_response_peak_observed",
            "pending_response_baseline_and_drain",
            "no_network_reset_or_full_rebuild",
            "tun_path_observed",
        ),
    },
    "udp-route-once": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-mixed-direct-shadowsocks-external-echo",
            "network_model_schema_version": WINDOWS_TUN_NETWORK_MODEL.SCHEMA_VERSION,
            "network_model_controller_sha256": WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256,
            "network_model_plan_sha256": WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256,
            "generations": WINDOWS_TUN_NETWORK_MODEL.ROUTE_GENERATIONS,
            "source_slots": WINDOWS_TUN_NETWORK_MODEL.ROUTE_SOURCE_SLOTS,
            "target_slots": WINDOWS_TUN_NETWORK_MODEL.ROUTE_TARGET_SLOTS,
            "datagrams_per_target": WINDOWS_TUN_NETWORK_MODEL.ROUTE_DATAGRAMS_PER_TARGET,
            "payload_bytes": 32,
            "settle_seconds": 5,
            "required_outbounds": ["direct", "proxy"],
            "generation_transition": "guest_route_metric_reset_network",
        },
        "metrics": {
            "multi_target_packet_rate": {
                "unit": "multi_target_datagrams_per_second",
                "direction": "higher_is_better",
            },
            "association_creation_rate": {
                "unit": "associations_per_second",
                "direction": "higher_is_better",
            },
            "router_invocations_avoided": {
                "unit": "avoided_router_invocations",
                "direction": "higher_is_better",
            },
        },
        "checked_unit": "echoed_multi_target_datagrams",
        "minimum_checked_units": (
            WINDOWS_TUN_NETWORK_MODEL.ROUTE_GENERATIONS
            * WINDOWS_TUN_NETWORK_MODEL.ROUTE_SOURCE_SLOTS
            * WINDOWS_TUN_NETWORK_MODEL.ROUTE_TARGET_SLOTS
            * WINDOWS_TUN_NETWORK_MODEL.ROUTE_DATAGRAMS_PER_TARGET
        ),
        "correctness_checks": (
            "every_reply_accounted",
            "payload_exact",
            "direct_and_proxy_sources",
            "association_creation_counter_exact",
            "router_invocation_counter_exact",
            "post_reset_reroute_verified",
            "network_model_evidence_bound",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "network-lifecycle": {
        "recipe": {
            **WINDOWS_TUN_RUNTIME_RECIPE,
            "topology": "tun-mixed-direct-shadowsocks-external-echo",
            "network_model_schema_version": WINDOWS_TUN_NETWORK_MODEL.SCHEMA_VERSION,
            "network_model_controller_sha256": WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256,
            "network_model_plan_sha256": WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256,
            "reset_network_cycles": WINDOWS_TUN_NETWORK_MODEL.RESET_CYCLES,
            "full_rebuild_cycles": WINDOWS_TUN_NETWORK_MODEL.FULL_REBUILD_CYCLES,
            "full_rebuild_damage_reason": WINDOWS_TUN_NETWORK_MODEL.FULL_REBUILD_DAMAGE_REASON,
            "interface_switch_kind": "approved_underlay_disable_enable",
            "interface_switch_sequence": WINDOWS_TUN_NETWORK_MODEL.INTERFACE_SWITCH_SEQUENCE,
            "interface_resolver_probes": WINDOWS_TUN_NETWORK_MODEL.INTERFACE_RESOLVER_PROBES,
            "recovery_timeout_seconds": 30,
            "settle_seconds": 5,
            "recovery_probe": {
                "protocols": 2,
                "tcp_payload_bytes": 1_024,
                "udp_payload_bytes": 1_024,
                "udp_target_slots": 4,
                "fragment_payload_bytes": 1_440,
                "fragment_datagrams": 1,
                "fragment_ack_bytes": 24,
            },
        },
        "metrics": {
            "reset_p50": {
                "unit": "p50_reset_network_nanoseconds",
                "direction": "lower_is_better",
            },
            "reset_p95": {
                "unit": "p95_reset_network_nanoseconds",
                "direction": "lower_is_better",
            },
            "reset_p99": {
                "unit": "p99_reset_network_nanoseconds",
                "direction": "lower_is_better",
            },
            "full_rebuild_p50": {
                "unit": "p50_full_rebuild_nanoseconds",
                "direction": "lower_is_better",
            },
            "full_rebuild_p95": {
                "unit": "p95_full_rebuild_nanoseconds",
                "direction": "lower_is_better",
            },
            "full_rebuild_p99": {
                "unit": "p99_full_rebuild_nanoseconds",
                "direction": "lower_is_better",
            },
            "interface_switch_recovery": {
                "unit": "interface_switch_recovery_nanoseconds",
                "direction": "lower_is_better",
            },
            "interface_resolver_cache_hit": {
                "unit": "cache_hits_per_million_resolutions",
                "direction": "higher_is_better",
            },
        },
        "checked_unit": "successful_reset_network_cycles",
        "minimum_checked_units": WINDOWS_TUN_NETWORK_MODEL.RESET_CYCLES,
        "correctness_checks": (
            "same_process_all_cycles",
            "generation_advanced_once_per_cycle",
            "managed_identity_preserved_across_resets",
            "damage_only_full_rebuild",
            "reset_and_full_rebuild_metrics_are_exact",
            "resource_growth_zero_after_1000_resets",
            "tcp_and_udp_recovered_after_interface_switch",
            "interface_resolver_cache_hit_observed",
            "network_model_evidence_bound",
            "tun_path_observed",
            "clean_drain",
        ),
    },
}
WINDOWS_TUN_POLICY_DOCUMENT_FIELDS = frozenset(
    {"schema_version", "policy_id", "selection", "scenarios"}
)
WINDOWS_TUN_POLICY_RUNTIME_FIELDS = frozenset(
    {*WINDOWS_TUN_POLICY_DOCUMENT_FIELDS, "policy_sha256"}
)
WINDOWS_TUN_POLICY_SCENARIO_FIELDS = frozenset({"metrics"})
WINDOWS_TUN_POLICY_METRIC_FIELDS = frozenset(
    {
        "unit",
        "direction",
        "noise_band_percent",
        "regression_threshold_percent",
        "adoption_threshold_percent",
        "minimum_pairs",
        "minimum_wins",
        "minimum_losses",
        "calibration_source",
        "calibration_artifact_sha256",
        "calibration_environment",
    }
)
WINDOWS_TUN_CALIBRATION_ENVIRONMENT_FIELDS = frozenset(
    {
        *WINDOWS_TUN_GUEST,
        "recipe_sha256",
        "guest_build",
        "cpu_model",
        "cpu_count",
        "memory_bytes",
        "power_plan_guid",
    }
)
WINDOWS_TUN_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "selection",
        "run_kind",
        "pairs",
        "pair_schedule",
        "recipe_sha256",
        "scenarios",
        "trials",
        "decision_policy",
        "calibration_complete",
        "adoption_eligible",
    }
)
WINDOWS_TUN_TRIAL_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "selection",
        "run_kind",
        "scenario",
        "member",
        "pair",
        "order",
        "sequence",
        "started_utc",
        "finished_utc",
        "parent_sha",
        "candidate_sha",
        "sha",
        "tree",
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "recipe_sha256",
        "environment",
        "measurements",
        "correctness",
        "diagnostics",
        "network_model_evidence",
        "status",
    }
)
WINDOWS_TUN_ENVIRONMENT_FIELDS = frozenset(
    {
        *WINDOWS_TUN_GUEST,
        "guest_build",
        "cpu_model",
        "cpu_count",
        "memory_bytes",
        "power_plan_guid",
    }
)
WINDOWS_TUN_MEASUREMENT_FIELDS = frozenset({"unit", "value"})
WINDOWS_TUN_CORRECTNESS_FIELDS = frozenset(
    {"status", "checked_unit", "checked_units", "checks"}
)
WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_SCHEMA_VERSION = 2
WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS = frozenset(
    {
        "batch_datagrams",
        "ack_window_milliseconds",
        "max_missing_per_batch",
        "max_retransmissions_per_sequence",
        "retry_budget_unique_datagrams",
        "minimum_retry_budget",
        "retry_scope",
    }
)
WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        *WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS,
        "accounting",
        "packet_counter_deltas",
        "adapter_counter_deltas",
    }
)
WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS = frozenset(
    {
        "warmup_unique_datagrams",
        "warmup_request_attempts",
        "active_unique_datagrams",
        "active_request_attempts",
        "total_unique_datagrams",
        "total_request_attempts",
        "retransmissions",
        "ack_window_expirations",
        "duplicate_or_stale_acks",
        "retry_budget",
    }
)
WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS = frozenset(
    {
        "accepted_packets",
        "ingress_packets",
        "background_family_disabled",
        "background_invalid_destination",
        "background_packets",
    }
)
WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS = frozenset(
    {
        "ReceivedUnicastPackets",
        "ReceivedDiscardedPackets",
        "ReceivedPacketErrors",
        "SentUnicastPackets",
        "OutboundDiscardedPackets",
        "OutboundPacketErrors",
    }
)
WINDOWS_TUN_NETWORK_MODEL_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "controller_sha256",
        "collector_sha256",
        "plan_sha256",
        "observation_file",
        "observation_sha256",
    }
)
PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "parent_sha",
        "candidate_sha",
        "member",
        "pair",
        "order",
        "build_profile",
        "scenario",
        "warmup_seconds",
        "active_seconds",
        "topology",
        "application_payload_bytes",
        "socks_datagram_bytes",
        "upstream_wire_bytes",
        "sha",
        "tree",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "metric",
        "value",
        "checked_units",
        "p99_nanoseconds",
        "io_completions",
        "scale",
        "correctness",
        "status",
    }
)
SHA256 = re.compile(r"[0-9a-f]{64}")
U64_MAX = (1 << 64) - 1
OUTLIER_MODIFIED_Z_THRESHOLD = Decimal("3.5")
MODIFIED_Z_SCALE = Decimal("0.6745")
HIGH_VARIANCE_MAD_MULTIPLIER = Decimal("6")
WARNING_POLICY = {
    "decision_effect": "none",
    "outlier_method": "modified z-score using median absolute deviation",
    "outlier_modified_z_threshold": 3.5,
    "high_variance_rule": "spread exceeds six MADs, or a calibrated noise-band width",
}
MEASUREMENT_ENVIRONMENT = {
    "runner_image": "ubuntu-24.04",
    "runner_os": "Linux",
    "runner_arch": "X64",
    "rust_toolchain": "1.97.1",
    "cargo_profile": "profiling",
    "evidence_build_profile": "current",
    "pair_schedule": "alternating-parent-candidate",
}
POLICY_DOCUMENT_FIELDS = frozenset({"schema_version", "policy_id", "scenarios"})
POLICY_RUNTIME_FIELDS = frozenset(
    {"schema_version", "policy_id", "policy_sha256", "scenarios"}
)
THRESHOLD_FIELDS = frozenset(
    {
        "metric",
        "direction",
        "noise_band_percent",
        "regression_threshold_percent",
        "adoption_threshold_percent",
        "minimum_pairs",
        "minimum_wins",
        "minimum_losses",
        "calibration_source",
        "calibration_environment",
    }
)
SCALE_POLICY_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
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
CALIBRATION_ENVIRONMENT_FIELDS = frozenset(
    {
        *MEASUREMENT_ENVIRONMENT,
        "warmup_seconds",
        "active_seconds",
    }
)
UNCALIBRATED_POLICY = {
    "schema_version": 1,
    "policy_id": "in-memory-uncalibrated-policy",
    "policy_sha256": None,
    "scenarios": {
        scenario: {
            "metric": metric,
            "direction": direction,
            "noise_band_percent": None,
            "regression_threshold_percent": None,
            "adoption_threshold_percent": None,
            "minimum_pairs": None,
            "minimum_wins": None,
            "minimum_losses": None,
            "calibration_source": None,
            "calibration_environment": None,
        }
        for scenario, (metric, direction, _family) in SCENARIO_CATALOG.items()
    },
}


class CandidateControlError(ValueError):
    """An invalid performance-candidate request or evidence set."""

    def __init__(
        self, message: str, *, missing_scenarios: Sequence[str] | None = None
    ) -> None:
        super().__init__(message)
        self.missing_scenarios = sorted(set(missing_scenarios or ()))


def _allowed_integer(value: str, *, name: str, allowed: frozenset[int]) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CandidateControlError(f"{name} must be an integer") from error
    if str(parsed) != value or parsed not in allowed:
        choices = ", ".join(str(choice) for choice in sorted(allowed))
        raise CandidateControlError(f"{name} must be one of: {choices}")
    return parsed


def validate_measurement_inputs(
    warmup_seconds: str, active_seconds: str, pairs: str
) -> tuple[int, int, int]:
    """Validate each bounded measurement input independently."""

    return (
        _allowed_integer(warmup_seconds, name="warmup_seconds", allowed=WARMUP_SECONDS),
        _allowed_integer(active_seconds, name="active_seconds", allowed=ACTIVE_SECONDS),
        _allowed_integer(pairs, name="pairs", allowed=PAIR_COUNTS),
    )


def _git(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _git_bytes(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_output(repository: pathlib.Path, *arguments: str) -> str:
    result = _git(repository, *arguments)
    if result.returncode != 0:
        raise CandidateControlError("unable to inspect scale lineage")
    return result.stdout.strip()


def _require_commit(repository: pathlib.Path, sha: str, *, name: str) -> str:
    if COMMIT_SHA.fullmatch(sha) is None:
        raise CandidateControlError(f"{name} must be a full 40-character commit SHA")
    canonical = sha.lower()
    probe = _git(repository, "cat-file", "-t", canonical)
    if probe.returncode != 0 or probe.stdout.strip() != "commit":
        raise CandidateControlError(
            f"{name} is not an available commit; fetch complete history before comparing"
        )
    return canonical


def validate_git_relation(
    repository: pathlib.Path, parent_sha: str, candidate_sha: str
) -> tuple[str, str]:
    """Require two available commits with parent strictly ancestral to candidate."""

    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("repository must be an existing directory")
    parent = _require_commit(repository, parent_sha, name="parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="candidate_sha")
    if parent == candidate:
        raise CandidateControlError(
            "parent_sha and candidate_sha must be different commits"
        )
    relation = _git(repository, "merge-base", "--is-ancestor", parent, candidate)
    if relation.returncode == 1:
        raise CandidateControlError("parent_sha is not an ancestor of candidate_sha")
    if relation.returncode != 0:
        raise CandidateControlError(
            "unable to confirm parent/candidate ancestry from the available history"
        )
    return parent, candidate


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


def _commit_parent(repository: pathlib.Path, sha: str) -> str:
    fields = _git_output(repository, "rev-list", "--parents", "-n", "1", sha).split()
    if len(fields) != 2 or fields[0] != sha:
        raise CandidateControlError("scale lineage member must be a single-parent commit")
    return fields[1]


def _commit_tree(repository: pathlib.Path, sha: str) -> str:
    tree = _git_output(repository, "rev-parse", f"{sha}^{{tree}}")
    if COMMIT_SHA.fullmatch(tree) is None:
        raise CandidateControlError("scale lineage tree identity is invalid")
    return tree


def _git_blob(repository: pathlib.Path, sha: str, path: str) -> bytes:
    result = _git_bytes(repository, "show", f"{sha}:{path}")
    if result.returncode != 0:
        raise CandidateControlError(f"scale lineage blob is unavailable: {path}")
    return result.stdout


def _scale_patch_digest(repository: pathlib.Path, head: str, parent: str) -> str:
    paths = sorted(SCALE_COUNTERFACTUAL_REPLACEMENTS)
    result = _git_bytes(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-renames",
        head,
        parent,
        "--",
        *paths,
    )
    if result.returncode != 0:
        raise CandidateControlError("unable to derive scale counterfactual patch")
    return hashlib.sha256(result.stdout).hexdigest()


def _validate_scale_lineage_source_repository(
    repository: pathlib.Path, lineage: dict[str, object]
) -> None:
    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("scale lineage repository is missing")
    head = _require_commit(repository, lineage["head_sha"], name="scale head_sha")
    parent = _require_commit(repository, lineage["parent_sha"], name="scale parent_sha")
    candidate = _require_commit(
        repository, lineage["candidate_sha"], name="scale candidate_sha"
    )
    if _commit_parent(repository, parent) != head:
        raise CandidateControlError("scale 16 KiB parent is not a direct child of H")
    if _commit_parent(repository, candidate) != parent:
        raise CandidateControlError("scale 32 KiB candidate is not a direct child of P16")
    trees = {
        "head_tree": _commit_tree(repository, head),
        "parent_tree": _commit_tree(repository, parent),
        "candidate_tree": _commit_tree(repository, candidate),
    }
    for field, observed in trees.items():
        if lineage[field] != observed:
            raise CandidateControlError(f"scale lineage {field} does not match git")
    raw = _git_output(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "-r",
        "--no-renames",
        head,
        parent,
    )
    changed: dict[str, tuple[str, str, str]] = {}
    for line in raw.splitlines():
        try:
            metadata, path = line.split("\t", 1)
            old_mode, new_mode, _old_blob, _new_blob, status = metadata[1:].split()
        except ValueError as error:
            raise CandidateControlError("scale lineage raw diff is malformed") from error
        if path in changed:
            raise CandidateControlError("scale lineage path is duplicated")
        changed[path] = (old_mode, new_mode, status)
    if set(changed) != set(SCALE_COUNTERFACTUAL_REPLACEMENTS):
        raise CandidateControlError("scale lineage changes an unexpected path set")
    for path, replacements in SCALE_COUNTERFACTUAL_REPLACEMENTS.items():
        old_mode, new_mode, status = changed[path]
        if old_mode != "100644" or new_mode != "100644" or status != "M":
            raise CandidateControlError("scale lineage changed mode, status, or rename shape")
        head_blob = _git_blob(repository, head, path)
        parent_blob = _git_blob(repository, parent, path)
        expected = head_blob
        for old_literal, new_literal in replacements:
            if expected.count(old_literal) != 1 or new_literal in expected:
                raise CandidateControlError(
                    f"scale head literal count is not exact for {path}"
                )
            expected = expected.replace(old_literal, new_literal, 1)
        if parent_blob != expected:
            raise CandidateControlError(
                f"scale parent blob is not the exact 16 KiB replacement for {path}"
            )
    if _scale_patch_digest(repository, head, parent) != lineage["counterfactual_patch_sha256"]:
        raise CandidateControlError("scale counterfactual patch digest does not match")


def validate_scale_lineage_repository(
    repository: pathlib.Path, lineage: dict[str, object]
) -> None:
    validate_scale_lineage_shape(lineage)
    _validate_scale_lineage_source_repository(repository, lineage)


def validate_scale_source_lineage(
    repository: pathlib.Path,
    head_sha: str,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    head = _require_commit(repository, head_sha, name="scale head_sha")
    parent = _require_commit(repository, parent_sha, name="scale parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="scale candidate_sha")
    source = {
        "head_sha": head,
        "head_tree": _commit_tree(repository, head),
        "parent_sha": parent,
        "parent_tree": _commit_tree(repository, parent),
        "candidate_sha": candidate,
        "candidate_tree": _commit_tree(repository, candidate),
        "counterfactual_patch_sha256": _scale_patch_digest(repository, head, parent),
    }
    if source["head_tree"] != source["candidate_tree"]:
        raise CandidateControlError("scale candidate tree must equal the final head tree")
    if source["parent_tree"] == source["head_tree"]:
        raise CandidateControlError("scale parent tree must be the 16 KiB counterfactual")
    _validate_scale_lineage_source_repository(repository, source)
    return source


def _file_sha256(path: pathlib.Path, field: str) -> str:
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CandidateControlError(f"unable to hash {field}") from error
    return digest


def build_scale_lineage(
    *,
    repository: pathlib.Path,
    head_sha: str,
    parent_sha: str,
    candidate_sha: str,
    runner: pathlib.Path,
    parent_client: pathlib.Path,
    parent_server: pathlib.Path,
    candidate_client: pathlib.Path,
    candidate_server: pathlib.Path,
) -> dict[str, object]:
    source = validate_scale_source_lineage(
        repository, head_sha, parent_sha, candidate_sha
    )
    lineage = {
        "schema_version": 1,
        **source,
        "runner_sha256": _file_sha256(runner, "scale runner"),
        "parent_client_sha256": _file_sha256(parent_client, "scale parent client"),
        "parent_server_sha256": _file_sha256(parent_server, "scale parent server"),
        "candidate_client_sha256": _file_sha256(candidate_client, "scale candidate client"),
        "candidate_server_sha256": _file_sha256(candidate_server, "scale candidate server"),
    }
    validate_scale_lineage_repository(repository, lineage)
    return lineage


def load_scale_lineage(path: pathlib.Path) -> dict[str, object]:
    try:
        value = _strict_json(path.read_text(encoding="utf-8"), source="scale lineage")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read scale lineage") from error
    if type(value) is not dict:
        raise CandidateControlError("scale lineage must be an object")
    validate_scale_lineage_shape(value)
    return value


def _scenario_entry(scenario: str, role: str) -> dict[str, object]:
    metric, direction, _family = SCENARIO_CATALOG[scenario]
    topology, payload_bytes, socks_bytes, upstream_bytes = SCENARIO_EVIDENCE[scenario]
    return {
        "scenario": scenario,
        "role": role,
        "mandatory": True,
        "metric": metric,
        "direction": direction,
        "topology": topology,
        "application_payload_bytes": payload_bytes,
        "socks_datagram_bytes": socks_bytes,
        "upstream_wire_bytes": upstream_bytes,
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
        "socks_datagram_bytes": None,
        "upstream_wire_bytes": None,
    }


def _qualification_scenarios(
    selected: str,
) -> tuple[str, list[dict[str, object]]]:
    if selected == "tcp-frame-capacity":
        return (
            selected,
            [
                _scenario_entry("tcp-stream-64k", "primary"),
                _scenario_entry("tcp-bulk", "primary"),
                *(
                    _scenario_entry(scenario, "guard")
                    for scenario in TCP_REQUEST_SCENARIOS
                ),
            ],
        )
    if selected == "udp-payload-matrix":
        return (
            selected,
            [
                _scenario_entry(scenario, "primary" if index == 0 else "guard")
                for index, scenario in enumerate(UDP_SS_PAYLOAD_MATRIX)
            ],
        )
    if selected == "udp-direct-payload-bounds":
        return (
            selected,
            [
                _scenario_entry(scenario, "primary" if index == 0 else "guard")
                for index, scenario in enumerate(UDP_DIRECT_PAYLOAD_BOUNDS)
            ],
        )
    family = SCENARIO_CATALOG[selected][2]
    if family == "tcp-throughput":
        guard = "tcp-bulk" if selected == "tcp-stream-64k" else "tcp-stream-64k"
        return (
            "tcp-throughput",
            [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")],
        )
    if family == "tcp-request":
        scenarios = [_scenario_entry(selected, "primary")]
        scenarios.extend(
            _scenario_entry(scenario, "guard")
            for scenario in TCP_REQUEST_SCENARIOS
            if scenario != selected
        )
        scenarios.append(_scenario_entry("tcp-bulk", "guard"))
        return "tcp-request", scenarios
    if family == "udp-established":
        guard = "udp-mtu-1200" if selected == "udp-small-high" else "udp-small-high"
        return "udp", [
            _scenario_entry(selected, "primary"),
            _scenario_entry(guard, "guard"),
        ]
    if family == "udp-ss-payload":
        return "udp-ss-payload", [
            _scenario_entry(selected, "primary"),
            _scenario_entry("udp-small-high", "guard"),
        ]
    if family == "udp-direct":
        guard = next(scenario for scenario in UDP_DIRECT_PAYLOAD_BOUNDS if scenario != selected)
        return "udp-direct", [
            _scenario_entry(selected, "primary"),
            _scenario_entry(guard, "guard"),
        ]
    raise AssertionError(f"unhandled scenario family: {family}")


def create_plan(
    *,
    mode: str,
    selection: str,
    warmup_seconds: str,
    active_seconds: str,
    pairs: str,
    decision_policy: dict[str, object] | None = None,
    scale_safety_policy: dict[str, object] | None = None,
    scale_lineage: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the authoritative scenario plan for one manual workflow run."""

    if mode not in MODES:
        raise CandidateControlError("mode must be diagnostic or qualification")
    if selection in QUALIFICATION_ONLY_SELECTIONS:
        raise CandidateControlError(
            "Windows TUN lifecycle selection is qualification-only; use "
            "windows-tun-m17 for paired performance evidence"
        )
    if selection == WINDOWS_TUN_SELECTION:
        raise CandidateControlError(
            "windows-tun-m17 uses the dedicated windows-tun-plan command"
        )
    if mode == "diagnostic" and selection not in SCENARIO_CATALOG:
        raise CandidateControlError("diagnostic selection must be one profile workload")
    if mode == "qualification" and selection not in (
        set(SCENARIO_CATALOG) | set(QUALIFICATION_GROUPS) | {SCALE_SCENARIO}
    ):
        raise CandidateControlError("qualification selection is not supported")
    warmup, active, pair_count = validate_measurement_inputs(
        warmup_seconds, active_seconds, pairs
    )
    policy = copy.deepcopy(
        UNCALIBRATED_POLICY if decision_policy is None else decision_policy
    )
    validate_decision_policy(policy)
    is_scale = selection == SCALE_SCENARIO
    if is_scale:
        if mode != "qualification":
            raise CandidateControlError("tcp-scale-10k is qualification-only")
        if (warmup, active, pair_count) != (10, 30, 5):
            raise CandidateControlError("tcp-scale-10k requires the exact 10/30/5 recipe")
        if scale_safety_policy is None or scale_lineage is None:
            raise CandidateControlError(
                "tcp-scale-10k requires a reviewed scale policy and bound lineage"
            )
        validate_scale_safety_policy(scale_safety_policy)
        validate_scale_lineage_shape(scale_lineage)
        scenario_group = SCALE_SCENARIO
        scenarios = [_scale_scenario_entry()]
    elif scale_safety_policy is not None or scale_lineage is not None:
        raise CandidateControlError("scale policy and lineage are only valid for tcp-scale-10k")
    elif mode == "diagnostic":
        scenario_group = "diagnostic"
        scenarios = [_scenario_entry(selection, "diagnostic")]
    else:
        scenario_group, scenarios = _qualification_scenarios(selection)
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "mode": mode,
        "selection": selection,
        "selected_scenario": (
            selection if selection in SCENARIO_CATALOG or is_scale else None
        ),
        "scenario_group": scenario_group,
        "warmup_seconds": warmup,
        "active_seconds": active,
        "pairs": pair_count,
        "measurement_environment": dict(MEASUREMENT_ENVIRONMENT),
        "decision_policy": policy,
        "scale_safety_policy": copy.deepcopy(scale_safety_policy),
        "scale_lineage": copy.deepcopy(scale_lineage),
        "adoption_eligible": not is_scale
        and mode == "qualification"
        and _plan_has_complete_applicable_policy(
            scenarios=scenarios,
            policy=policy,
            warmup_seconds=warmup,
            active_seconds=active,
            pairs=pair_count,
        ),
        "scenarios": scenarios,
    }


def write_plan(path: pathlib.Path, plan: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _reject_json_constant(value: str) -> object:
    raise CandidateControlError(f"non-finite JSON number is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateControlError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _bounded_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 20:
        raise CandidateControlError("JSON integer exceeds the bounded integer envelope")
    return int(value, 10)


def _strict_json(text: str, *, source: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_int=_bounded_json_integer,
        )
    except CandidateControlError:
        raise
    except (ValueError, RecursionError) as error:
        raise CandidateControlError(f"{source} is not valid JSON") from error


def _exact_fields(
    value: dict[str, object], expected: frozenset[str], name: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise CandidateControlError(
            f"{name} schema mismatch: missing={missing}, unexpected={unexpected}"
        )


def _policy_percent(value: object, field: str) -> Decimal:
    if type(value) not in {int, float}:
        raise CandidateControlError(f"{field} must be a finite JSON number")
    parsed = Decimal(str(value))
    if not parsed.is_finite():
        raise CandidateControlError(f"{field} must be finite")
    return parsed


def _scale_decimal(value: object, field: str) -> Decimal:
    parsed = _policy_percent(value, field)
    return parsed


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
    exact_integers = {
        "required_pairs": 5,
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


def load_scale_safety_policy(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        document = _strict_json(raw.decode("utf-8"), source="scale safety policy")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read scale safety policy") from error
    if type(document) is not dict:
        raise CandidateControlError("scale safety policy must be a JSON object")
    _exact_fields(document, SCALE_POLICY_DOCUMENT_FIELDS, "scale safety policy")
    policy = {**document, "policy_sha256": hashlib.sha256(raw).hexdigest()}
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


def _calibration_environment_matches(
    environment: dict[str, object], *, warmup_seconds: int, active_seconds: int
) -> bool:
    expected = {
        **MEASUREMENT_ENVIRONMENT,
        "warmup_seconds": warmup_seconds,
        "active_seconds": active_seconds,
    }
    return environment == expected


def validate_decision_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(policy, POLICY_RUNTIME_FIELDS, "decision policy")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise CandidateControlError("decision policy schema_version must be 1")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("decision policy_id must be a non-empty string")
    digest = policy["policy_sha256"]
    if digest is not None and (
        type(digest) is not str or SHA256.fullmatch(digest) is None
    ):
        raise CandidateControlError("decision policy_sha256 must be a SHA-256 digest")
    scenarios = policy["scenarios"]
    if type(scenarios) is not dict or set(scenarios) != set(SCENARIO_CATALOG):
        raise CandidateControlError(
            "decision policy scenarios must exactly match the scenario catalog"
        )
    for scenario, entry in scenarios.items():
        if type(entry) is not dict:
            raise CandidateControlError(f"policy scenario {scenario} must be an object")
        _exact_fields(entry, THRESHOLD_FIELDS, f"policy scenario {scenario}")
        metric, direction, _family = SCENARIO_CATALOG[scenario]
        if entry["metric"] != metric or entry["direction"] != direction:
            raise CandidateControlError(
                f"policy scenario {scenario} metric or direction does not match the catalog"
            )
        calibrated_fields = (
            "noise_band_percent",
            "regression_threshold_percent",
            "adoption_threshold_percent",
            "minimum_pairs",
            "minimum_wins",
            "minimum_losses",
            "calibration_source",
            "calibration_environment",
        )
        values = [entry[field] for field in calibrated_fields]
        if all(value is None for value in values):
            continue
        if any(value is None for value in values):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration must be complete or entirely null"
            )
        noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
        regression = _policy_percent(
            entry["regression_threshold_percent"],
            "regression_threshold_percent",
        )
        adoption = _policy_percent(
            entry["adoption_threshold_percent"], "adoption_threshold_percent"
        )
        if noise < 0 or regression >= -noise or adoption <= noise:
            raise CandidateControlError(
                f"policy scenario {scenario} thresholds must lie outside the noise band"
            )
        minimum_pairs = entry["minimum_pairs"]
        minimum_wins = entry["minimum_wins"]
        minimum_losses = entry["minimum_losses"]
        if (
            type(minimum_pairs) is not int
            or minimum_pairs not in PAIR_COUNTS
            or type(minimum_wins) is not int
            or not 1 <= minimum_wins <= minimum_pairs
            or type(minimum_losses) is not int
            or not 1 <= minimum_losses <= minimum_pairs
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} minimum pair/win/loss counts are invalid"
            )
        if (
            type(entry["calibration_source"]) is not str
            or not entry["calibration_source"].strip()
            or re.fullmatch(r"(?:artifact|commit):\S+", entry["calibration_source"])
            is None
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration_source is required"
            )
        environment = entry["calibration_environment"]
        if type(environment) is not dict:
            raise CandidateControlError(
                f"policy scenario {scenario} calibration_environment is required"
            )
        _exact_fields(
            environment,
            CALIBRATION_ENVIRONMENT_FIELDS,
            f"policy scenario {scenario} calibration_environment",
        )
        for field, expected in MEASUREMENT_ENVIRONMENT.items():
            if environment[field] != expected:
                raise CandidateControlError(
                    f"policy scenario {scenario} calibration_environment {field} is unsupported"
                )
        if (
            type(environment["warmup_seconds"]) is not int
            or environment["warmup_seconds"] not in WARMUP_SECONDS
            or type(environment["active_seconds"]) is not int
            or environment["active_seconds"] not in ACTIVE_SECONDS
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration recipe is unsupported"
            )


def load_decision_policy(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        document = _strict_json(raw.decode("utf-8"), source="decision policy")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read decision policy") from error
    if type(document) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(document, POLICY_DOCUMENT_FIELDS, "decision policy document")
    policy = {
        **document,
        "policy_sha256": hashlib.sha256(raw).hexdigest(),
    }
    validate_decision_policy(policy)
    return policy


def _scenario_policy_is_applicable(
    *,
    entry: dict[str, object],
    warmup_seconds: int,
    active_seconds: int,
    pairs: int,
) -> bool:
    environment = entry["calibration_environment"]
    return (
        environment is not None
        and pairs >= entry["minimum_pairs"]
        and _calibration_environment_matches(
            environment,
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
        )
    )


def _plan_has_complete_applicable_policy(
    *,
    scenarios: list[dict[str, object]],
    policy: dict[str, object],
    warmup_seconds: int,
    active_seconds: int,
    pairs: int,
) -> bool:
    return all(
        _scenario_policy_is_applicable(
            entry=policy["scenarios"][scenario["scenario"]],
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
            pairs=pairs,
        )
        for scenario in scenarios
    )


def load_plan(
    path: pathlib.Path,
    decision_policy: dict[str, object] | None = None,
    scale_safety_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        plan = _strict_json(path.read_text(encoding="utf-8"), source="performance plan")
        if type(plan) is not dict:
            raise CandidateControlError("performance plan must be a JSON object")
        policy = plan["decision_policy"] if decision_policy is None else decision_policy
        validate_decision_policy(policy)
        selected_scale_policy = (
            plan.get("scale_safety_policy")
            if scale_safety_policy is None
            else scale_safety_policy
        )
        expected = create_plan(
            mode=plan["mode"],
            selection=plan["selection"],
            warmup_seconds=str(plan["warmup_seconds"]),
            active_seconds=str(plan["active_seconds"]),
            pairs=str(plan["pairs"]),
            decision_policy=policy,
            scale_safety_policy=selected_scale_policy,
            scale_lineage=plan.get("scale_lineage"),
        )
    except (OSError, KeyError, TypeError) as error:
        raise CandidateControlError("performance plan is invalid") from error
    if plan != expected:
        raise CandidateControlError(
            "performance plan does not match the canonical scenario set"
        )
    return plan


def _required_string(
    row: dict[str, object], field: str, *, expected: str | None = None
) -> str:
    value = row.get(field)
    if type(value) is not str or not value:
        raise CandidateControlError(f"{field} must be a non-empty string")
    if expected is not None and value != expected:
        raise CandidateControlError(f"{field} does not match the expected value")
    return value


def _required_u64(row: dict[str, object], field: str, *, positive: bool = False) -> int:
    value = row.get(field)
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise CandidateControlError(f"{field} must be an unsigned 64-bit integer")
    if positive and value == 0:
        raise CandidateControlError(f"{field} must be positive")
    return value


def _optional_u64(row: dict[str, object], field: str) -> int | None:
    value = row.get(field)
    if value is None:
        return None
    return _required_u64(row, field, positive=True)


def _require_pattern(value: str, pattern: re.Pattern[str], *, field: str) -> None:
    if pattern.fullmatch(value) is None:
        raise CandidateControlError(f"{field} has an invalid identity")


def _read_trial(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError) as error:
        raise CandidateControlError(
            f"unable to read evidence file {path.name}"
        ) from error
    if len(raw) > SCALE_TRIAL_MAX_BYTES + 1:
        raise CandidateControlError(
            f"evidence file {path.name} exceeds the scale byte bound"
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CandidateControlError(
            f"evidence file {path.name} is not UTF-8"
        ) from error
    if len(lines) != 1 or not lines[0]:
        raise CandidateControlError(
            f"evidence file {path.name} must contain exactly one JSON row"
        )
    row = _strict_json(lines[0], source=f"evidence file {path.name}")
    if type(row) is not dict:
        raise CandidateControlError(f"evidence file {path.name} must contain an object")
    if set(row) != PROFILE_FIELDS:
        missing = sorted(PROFILE_FIELDS - set(row))
        unexpected = sorted(set(row) - PROFILE_FIELDS)
        raise CandidateControlError(
            f"evidence schema mismatch in {path.name}: missing={missing}, unexpected={unexpected}"
        )
    line_bytes = len(lines[0].encode("utf-8"))
    limit = (
        SCALE_TRIAL_MAX_BYTES
        if row.get("scenario") == SCALE_SCENARIO
        else REGULAR_TRIAL_MAX_BYTES
    )
    if line_bytes > limit:
        raise CandidateControlError(
            f"evidence file {path.name} exceeds its scenario byte bound"
        )
    return row


def _required_i64(value: object, field: str) -> int:
    if type(value) is not int or not -(1 << 63) <= value <= (1 << 63) - 1:
        raise CandidateControlError(f"{field} must be a signed 64-bit integer")
    return value


def _scale_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise CandidateControlError(f"{field} must be an unsigned 64-bit integer")
    return value


def _scale_u64_vector(value: object, field: str, length: int) -> list[int]:
    if type(value) is not list or len(value) != length:
        raise CandidateControlError(f"{field} must contain exactly {length} values")
    return [_scale_u64(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _scale_u64_sum(values: Sequence[int], field: str) -> int:
    total = sum(values)
    if total > U64_MAX:
        raise CandidateControlError(f"{field} overflows u64")
    return total


def _scale_even_median(values: Sequence[int], field: str) -> int:
    if not values or len(values) % 2:
        raise CandidateControlError(f"{field} requires a nonempty even vector")
    ordered = sorted(values)
    upper = len(ordered) // 2
    total = ordered[upper - 1] + ordered[upper]
    if total > U64_MAX:
        raise CandidateControlError(f"{field} median sum overflows u64")
    return total // 2


def _scale_stage_median(samples: Sequence[dict[str, object]], field: str) -> int:
    if not samples:
        raise CandidateControlError("scale resource stage is empty")
    values = sorted(_scale_u64(sample[field], field) for sample in samples)
    return values[len(values) // 2]


def _truncating_division(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise AssertionError("positive denominator required")
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _scale_nearest_rank(ordered: Sequence[int], percentile: int) -> int:
    rank = (len(ordered) * percentile + 99) // 100
    return ordered[rank - 1]


def _recompute_scale_fairness(flow_bytes: Sequence[int]) -> dict[str, object]:
    if len(flow_bytes) != SCALE_RECIPE["sessions"]:
        raise CandidateControlError("scale fairness vector length is invalid")
    ordered = sorted(flow_bytes)
    total = sum(flow_bytes)
    square_sum = sum(value * value for value in flow_bytes)
    u128_max = (1 << 128) - 1
    if total > u128_max or square_sum > u128_max:
        raise CandidateControlError("scale fairness arithmetic exceeds u128")
    denominator = len(flow_bytes) * square_sum
    numerator = total * total
    if denominator > u128_max or numerator > u128_max:
        raise CandidateControlError("scale fairness aggregate exceeds u128")
    scaled_numerator = numerator * 1_000_000_000
    if scaled_numerator > u128_max:
        raise CandidateControlError("scale fairness scaled numerator exceeds u128")
    jain_ppb = 0 if denominator == 0 else scaled_numerator // denominator
    median_bytes = _scale_even_median(ordered, "scale fairness")
    p01 = _scale_nearest_rank(ordered, 1)
    ratio_numerator = p01 * 1_000_000
    if ratio_numerator > u128_max:
        raise CandidateControlError("scale fairness ratio exceeds u128")
    ratio_ppm = 0 if median_bytes == 0 else ratio_numerator // median_bytes
    return {
        "jain_ppb": jain_ppb,
        "minimum_bytes": ordered[0],
        "p01_bytes": p01,
        "p05_bytes": _scale_nearest_rank(ordered, 5),
        "median_bytes": median_bytes,
        "p95_bytes": _scale_nearest_rank(ordered, 95),
        "p99_bytes": _scale_nearest_rank(ordered, 99),
        "maximum_bytes": ordered[-1],
        "p01_to_median_ppm": ratio_ppm,
        "jain_fraction": Fraction(numerator, denominator) if denominator else Fraction(0),
        "p01_median_fraction": (
            Fraction(p01, median_bytes) if median_bytes else Fraction(0)
        ),
    }


def _validate_scale_sample(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError(f"{field} must be an object")
    _exact_fields(value, SCALE_SAMPLE_FIELDS, field)
    for key in SCALE_SAMPLE_FIELDS:
        _scale_u64(value[key], f"{field}.{key}")
    return value


def _validate_scale_evidence(row: dict[str, object]) -> dict[str, object]:
    scale = row["scale"]
    if type(scale) is not dict:
        raise CandidateControlError("tcp-scale-10k evidence requires a scale object")
    _exact_fields(scale, SCALE_FIELDS, "scale evidence")
    if _scale_u64(scale["schema_version"], "scale.schema_version") != 1:
        raise CandidateControlError("scale evidence schema_version is unsupported")

    recipe = scale["recipe"]
    if type(recipe) is not dict:
        raise CandidateControlError("scale recipe must be an object")
    _exact_fields(recipe, frozenset(SCALE_RECIPE), "scale recipe")
    for field, expected in SCALE_RECIPE.items():
        if _scale_u64(recipe[field], f"scale.recipe.{field}") != expected:
            raise CandidateControlError(f"scale recipe {field} does not match")

    correctness = scale["correctness"]
    if type(correctness) is not dict:
        raise CandidateControlError("scale correctness must be an object")
    _exact_fields(correctness, SCALE_CORRECTNESS_FIELDS, "scale correctness")
    numeric_correctness = SCALE_CORRECTNESS_FIELDS - {"drain", "rebind", "cleanup"}
    for field in numeric_correctness:
        _scale_u64(correctness[field], f"scale.correctness.{field}")
    for field in ("drain", "rebind", "cleanup"):
        if correctness[field] not in {"PASS", "FAIL"}:
            raise CandidateControlError(f"scale correctness {field} is invalid")

    traffic = scale["traffic"]
    if type(traffic) is not dict:
        raise CandidateControlError("scale traffic must be an object")
    _exact_fields(traffic, SCALE_TRAFFIC_FIELDS, "scale traffic")
    partial_bytes = _scale_u64_vector(
        traffic["partial_flow_bytes"],
        "scale.traffic.partial_flow_bytes",
        SCALE_RECIPE["partial_active_flows"],
    )
    full_bytes = _scale_u64_vector(
        traffic["full_flow_bytes"],
        "scale.traffic.full_flow_bytes",
        SCALE_RECIPE["sessions"],
    )
    full_completions = _scale_u64_vector(
        traffic["full_flow_completions"],
        "scale.traffic.full_flow_completions",
        SCALE_RECIPE["sessions"],
    )
    payload_bytes = SCALE_RECIPE["payload_bytes"]
    if any(value % payload_bytes for value in partial_bytes):
        raise CandidateControlError("scale partial bytes are not whole round trips")
    partial_completions = _scale_u64_sum(
        [value // payload_bytes for value in partial_bytes],
        "scale partial completions",
    )
    partial_checked = _scale_u64_sum(partial_bytes, "scale partial bytes")
    for field, expected in (
        ("partial_checked_bytes", partial_checked),
        ("partial_io_completions", partial_completions),
    ):
        if _scale_u64(traffic[field], f"scale.traffic.{field}") != expected:
            raise CandidateControlError(f"scale traffic {field} is inconsistent")
    partial_tails = _scale_u64(
        traffic["partial_discarded_tail_completions"],
        "scale.traffic.partial_discarded_tail_completions",
    )
    if partial_tails > SCALE_RECIPE["partial_active_flows"]:
        raise CandidateControlError("scale partial tail count exceeds one per flow")

    for index, (byte_count, completions) in enumerate(
        zip(full_bytes, full_completions, strict=True)
    ):
        product = completions * payload_bytes
        if product > U64_MAX or byte_count != product:
            raise CandidateControlError(
                f"scale full flow {index} byte/completion accounting is inconsistent"
            )
    full_checked = _scale_u64_sum(full_bytes, "scale full bytes")
    full_completion_sum = _scale_u64_sum(
        full_completions, "scale full completions"
    )
    for field, expected in (
        ("full_checked_bytes", full_checked),
        ("full_io_completions", full_completion_sum),
    ):
        if _scale_u64(traffic[field], f"scale.traffic.{field}") != expected:
            raise CandidateControlError(f"scale traffic {field} is inconsistent")
    full_tails = _scale_u64(
        traffic["full_discarded_tail_completions"],
        "scale.traffic.full_discarded_tail_completions",
    )
    if full_tails > SCALE_RECIPE["sessions"]:
        raise CandidateControlError("scale full tail count exceeds one per flow")
    elapsed = _scale_u64(
        traffic["full_elapsed_nanoseconds"],
        "scale.traffic.full_elapsed_nanoseconds",
    )
    expected_elapsed = SCALE_RECIPE["full_seconds"] * 1_000_000_000
    if elapsed != expected_elapsed:
        raise CandidateControlError("scale full elapsed window is not exact")
    rate = full_checked * 1_000_000_000 // elapsed
    if rate > U64_MAX or _scale_u64(
        traffic["aggregate_bytes_per_second"],
        "scale.traffic.aggregate_bytes_per_second",
    ) != rate:
        raise CandidateControlError("scale aggregate rate is inconsistent")

    fairness = scale["fairness"]
    if type(fairness) is not dict:
        raise CandidateControlError("scale fairness must be an object")
    _exact_fields(fairness, SCALE_FAIRNESS_FIELDS, "scale fairness")
    recomputed_fairness = _recompute_scale_fairness(full_bytes)
    for field in SCALE_FAIRNESS_FIELDS:
        if _scale_u64(fairness[field], f"scale.fairness.{field}") != recomputed_fairness[field]:
            raise CandidateControlError(f"scale fairness {field} is inconsistent")

    resource = scale["resource"]
    if type(resource) is not dict:
        raise CandidateControlError("scale resource must be an object")
    _exact_fields(resource, SCALE_RESOURCE_FIELDS, "scale resource")
    stage_lengths = {
        "pre_load": 1,
        "established": 5,
        "touched": 5,
        "partial_active": 5,
        "full_active": 5,
        "post_full": 5,
        "drained": 1,
    }
    samples: dict[str, list[dict[str, object]]] = {}
    for stage, expected_length in stage_lengths.items():
        value = resource[stage]
        if type(value) is not list or len(value) != expected_length:
            raise CandidateControlError(
                f"scale resource {stage} must contain {expected_length} samples"
            )
        samples[stage] = [
            _validate_scale_sample(sample, f"scale.resource.{stage}[{index}]")
            for index, sample in enumerate(value)
        ]
    all_samples = [sample for stage in samples.values() for sample in stage]
    peak = max(_scale_u64(sample["harness_rss_kib"], "harness_rss_kib") for sample in all_samples)
    if _scale_u64(resource["harness_peak_rss_kib"], "scale.resource.harness_peak_rss_kib") != peak:
        raise CandidateControlError("scale harness RSS peak is inconsistent")
    sessions = SCALE_RECIPE["sessions"]
    client_increment = _truncating_division(
        (
            _scale_stage_median(samples["touched"], "client_smaps_rss_kib")
            - _scale_stage_median(samples["established"], "client_smaps_rss_kib")
        )
        * 1024,
        sessions,
    )
    server_increment = _truncating_division(
        (
            _scale_stage_median(samples["touched"], "server_smaps_rss_kib")
            - _scale_stage_median(samples["established"], "server_smaps_rss_kib")
        )
        * 1024,
        sessions,
    )
    combined_increment = client_increment + server_increment
    for field, expected in (
        ("client_touched_increment_bytes_per_connection", client_increment),
        ("server_touched_increment_bytes_per_connection", server_increment),
        ("combined_touched_increment_bytes_per_connection", combined_increment),
    ):
        if _required_i64(resource[field], f"scale.resource.{field}") != expected:
            raise CandidateControlError(f"scale resource {field} is inconsistent")
    _scale_u64(resource["memory_available_kib"], "scale.resource.memory_available_kib")
    _scale_u64(resource["nofile_soft"], "scale.resource.nofile_soft")

    partial_nonzero = sum(value != 0 for value in partial_bytes)
    full_nonzero = sum(value != 0 for value in full_bytes)
    if correctness["partial_nonzero_flows"] != partial_nonzero:
        raise CandidateControlError("scale partial nonzero count is inconsistent")
    if correctness["full_nonzero_flows"] != full_nonzero:
        raise CandidateControlError("scale full nonzero count is inconsistent")
    touch_completions = _scale_u64(
        correctness["touch_completed_round_trips"],
        "scale.correctness.touch_completed_round_trips",
    )
    if correctness["touch_checked_bytes"] != touch_completions * payload_bytes:
        raise CandidateControlError("scale touch byte accounting is inconsistent")
    payload_checks = (
        touch_completions
        + partial_completions
        + partial_tails
        + full_completion_sum
        + full_tails
    )
    if payload_checks > U64_MAX or correctness["payload_checks"] != payload_checks:
        raise CandidateControlError("scale payload check accounting is inconsistent")

    if row["value"] != rate or row["checked_units"] != full_checked:
        raise CandidateControlError("scale top-level traffic values are inconsistent")
    if row["io_completions"] != full_completion_sum * 2:
        raise CandidateControlError("scale top-level I/O completions are inconsistent")
    return {
        "fairness": recomputed_fairness,
        "samples": samples,
        "partial_nonzero": partial_nonzero,
        "full_nonzero": full_nonzero,
    }


def _validate_trial(
    row: dict[str, object],
    *,
    source_member: str,
    plan: dict[str, object],
    planned: dict[str, dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[str, int, str]:
    if _required_u64(row, "schema_version", positive=True) != PROFILE_TRIAL_SCHEMA_VERSION:
        raise CandidateControlError("evidence schema_version is unsupported")
    _required_string(row, "kind", expected="m18_profile_trial")
    _required_string(row, "parent_sha", expected=parent_sha)
    _required_string(row, "candidate_sha", expected=candidate_sha)
    member = _required_string(row, "member")
    if member not in {"parent", "candidate"} or member != source_member:
        raise CandidateControlError(
            "evidence member does not match its source directory"
        )
    scenario = _required_string(row, "scenario")
    if scenario not in planned:
        raise CandidateControlError(f"unexpected scenario in evidence: {scenario}")
    pair = _required_u64(row, "pair", positive=True)
    if pair > plan["pairs"]:
        raise CandidateControlError("evidence pair is outside the planned range")
    order = _required_u64(row, "order", positive=True)
    if order not in {1, 2}:
        raise CandidateControlError("evidence order must be 1 or 2")
    _required_string(row, "build_profile", expected="current")
    if _required_u64(row, "warmup_seconds", positive=True) != plan["warmup_seconds"]:
        raise CandidateControlError("evidence warmup_seconds does not match the plan")
    if _required_u64(row, "active_seconds", positive=True) != plan["active_seconds"]:
        raise CandidateControlError("evidence active_seconds does not match the plan")
    if _required_string(row, "topology") != planned[scenario]["topology"]:
        raise CandidateControlError("evidence topology does not match the scenario")
    if (
        _required_u64(row, "application_payload_bytes", positive=True)
        != planned[scenario]["application_payload_bytes"]
    ):
        raise CandidateControlError(
            "evidence application_payload_bytes does not match the scenario"
        )
    for field in ("socks_datagram_bytes", "upstream_wire_bytes"):
        if _optional_u64(row, field) != planned[scenario][field]:
            raise CandidateControlError(f"evidence {field} does not match the scenario")
    expected_sha = parent_sha if member == "parent" else candidate_sha
    sha = _required_string(row, "sha", expected=expected_sha)
    tree = _required_string(row, "tree")
    _require_pattern(sha, COMMIT_SHA, field="sha")
    _require_pattern(tree, COMMIT_SHA, field="tree")
    for field in ("runner_sha256", "client_sha256", "server_sha256"):
        _require_pattern(_required_string(row, field), SHA256, field=field)
    for field in ("rustc", "kernel", "cpu_model"):
        _required_string(row, field)
    _required_u64(row, "cpu_count", positive=True)
    _required_u64(row, "memory_kib", positive=True)
    metric = _required_string(row, "metric", expected=planned[scenario]["metric"])
    value = _required_u64(row, "value")
    is_scale = scenario == SCALE_SCENARIO
    _required_u64(row, "checked_units", positive=not is_scale)
    _required_u64(row, "io_completions", positive=not is_scale)
    p99 = row.get("p99_nanoseconds")
    if metric == "p99_nanoseconds":
        if type(p99) is not int or p99 != value or value == 0:
            raise CandidateControlError(
                "request evidence requires positive matching value and p99_nanoseconds"
            )
    elif p99 is not None:
        raise CandidateControlError(
            "throughput evidence must have null p99_nanoseconds"
        )
    if is_scale:
        _validate_scale_evidence(row)
    elif row["scale"] is not None:
        raise CandidateControlError("ordinary profile evidence must have null scale")
    _required_string(row, "correctness", expected="PASS")
    _required_string(row, "status", expected="PASS")
    return scenario, pair, member


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    if not ordered:
        raise CandidateControlError("median requires at least one value")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def _improvement(parent: int, candidate: int, direction: str) -> Decimal:
    if parent <= 0:
        raise CandidateControlError("parent metric baseline must be positive")
    difference = (
        candidate - parent if direction == "higher_is_better" else parent - candidate
    )
    return Decimal(difference) * Decimal(100) / Decimal(parent)


def _display_decimal(value: Decimal) -> float:
    displayed = round(float(value), 9)
    return 0.0 if displayed == 0 else displayed


def _observed_direction(*, wins: int, losses: int) -> str:
    if wins and losses:
        return "mixed"
    if wins:
        return "positive"
    if losses:
        return "negative"
    return "neutral"


def _stability_warnings(
    improvements: Sequence[Decimal], *, noise_band: object
) -> tuple[Decimal, list[str]]:
    median = _median(improvements)
    minimum = min(improvements)
    maximum = max(improvements)
    spread = maximum - minimum
    deviations = [abs(value - median) for value in improvements]
    mad = _median(deviations)
    warnings = []
    if any(value > 0 for value in improvements) and any(
        value < 0 for value in improvements
    ):
        warnings.append("MIXED_DIRECTION")
    if mad > 0:
        minimum_z = MODIFIED_Z_SCALE * abs(minimum - median) / mad
        maximum_z = MODIFIED_Z_SCALE * abs(maximum - median) / mad
        if minimum < median and minimum_z > OUTLIER_MODIFIED_Z_THRESHOLD:
            warnings.append("EXTREME_NEGATIVE_PAIR")
        if maximum > median and maximum_z > OUTLIER_MODIFIED_Z_THRESHOLD:
            warnings.append("EXTREME_POSITIVE_PAIR")
    elif spread > 0:
        if minimum < median:
            warnings.append("EXTREME_NEGATIVE_PAIR")
        if maximum > median:
            warnings.append("EXTREME_POSITIVE_PAIR")
    if noise_band is not None:
        high_variance = spread > Decimal(2) * _policy_percent(
            noise_band, "noise_band_percent"
        )
    else:
        high_variance = (mad > 0 and spread > HIGH_VARIANCE_MAD_MULTIPLIER * mad) or (
            mad == 0 and spread > 0
        )
    if high_variance:
        warnings.append("HIGH_VARIANCE")
    return spread, warnings


def _scenario_threshold_decision(
    *,
    plan: dict[str, object],
    scenario_plan: dict[str, object],
    wins: int,
    losses: int,
    median_improvement: Decimal,
) -> dict[str, object]:
    entry = plan["decision_policy"]["scenarios"][scenario_plan["scenario"]]
    common = {
        "noise_band_percent": entry["noise_band_percent"],
        "regression_threshold_percent": entry["regression_threshold_percent"],
        "adoption_threshold_percent": entry["adoption_threshold_percent"],
        "minimum_pairs": entry["minimum_pairs"],
        "minimum_wins": entry["minimum_wins"],
        "minimum_losses": entry["minimum_losses"],
        "threshold_source": entry["calibration_source"],
        "calibration_environment": entry["calibration_environment"],
    }
    if plan["mode"] == "diagnostic":
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "diagnostic mode reports measurements only",
            "threshold_decision": "DIAGNOSTIC_ONLY",
            "guard_passed": None,
            "status": "MEASURED",
        }
    if entry["calibration_environment"] is None:
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "no calibrated threshold for this scenario",
            "threshold_decision": "NO_CALIBRATION",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    if not _scenario_policy_is_applicable(
        entry=entry,
        warmup_seconds=plan["warmup_seconds"],
        active_seconds=plan["active_seconds"],
        pairs=plan["pairs"],
    ):
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "calibration recipe or minimum pair count does not match",
            "threshold_decision": "CALIBRATION_NOT_APPLICABLE",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
    regression = _policy_percent(
        entry["regression_threshold_percent"], "regression_threshold_percent"
    )
    adoption = _policy_percent(
        entry["adoption_threshold_percent"], "adoption_threshold_percent"
    )
    if median_improvement <= regression:
        if losses >= entry["minimum_losses"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "median and loss count confirm calibrated regression",
                "threshold_decision": "CONFIRMED_REGRESSION",
                "guard_passed": False,
                "status": "REGRESSION",
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "regression threshold crossed without enough confirming losses",
            "threshold_decision": "INSUFFICIENT_LOSSES",
            "guard_passed": False,
            "status": "INCONCLUSIVE",
        }
    if scenario_plan["role"] == "guard":
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "guard remains above its calibrated regression threshold",
            "threshold_decision": "GUARD_CLEAR",
            "guard_passed": True,
            "status": "INCONCLUSIVE",
        }
    if median_improvement >= adoption:
        if wins >= entry["minimum_wins"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "adoption threshold and minimum wins are satisfied",
                "threshold_decision": "CANDIDATE_IMPROVEMENT",
                "guard_passed": None,
                "status": "CANDIDATE_WIN",
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "adoption threshold crossed without enough wins",
            "threshold_decision": "INSUFFICIENT_WINS",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    if -noise <= median_improvement <= noise:
        reason = "median remains inside the calibrated noise band"
        threshold_decision = "WITHIN_NOISE"
    else:
        reason = "median does not cross a calibrated decision threshold"
        threshold_decision = "BETWEEN_THRESHOLDS"
    return {
        **common,
        "decision_enabled": True,
        "decision_reason": reason,
        "threshold_decision": threshold_decision,
        "guard_passed": None,
        "status": "INCONCLUSIVE",
    }


def _fraction_from_policy(value: object, field: str) -> Fraction:
    decimal = _scale_decimal(value, field)
    return Fraction(decimal)


def _median_fraction(values: Sequence[Fraction]) -> Fraction:
    ordered = sorted(values)
    if not ordered:
        raise CandidateControlError("scale median requires values")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _fraction_display(value: Fraction) -> float:
    return _display_decimal(Decimal(value.numerator) / Decimal(value.denominator))


def _scale_trial_observation(
    row: dict[str, object], policy: dict[str, object]
) -> tuple[dict[str, object], list[str]]:
    derived = _validate_scale_evidence(row)
    scale = row["scale"]
    correctness = scale["correctness"]
    resource = scale["resource"]
    samples = derived["samples"]
    fairness = derived["fairness"]
    failures: list[str] = []
    if row["cpu_count"] < 4:
        failures.append("HOST_CPU_COUNT")
    if row["memory_kib"] < 15_000_000:
        failures.append("HOST_MEMORY_TOTAL")
    expected_correctness = {
        "target_accepted": 10_000,
        "client_active": 10_000,
        "server_active": 10_000,
        "touch_completed_flows": 10_000,
        "touch_completed_round_trips": 20_000,
        "touch_checked_bytes": 20_000 * 32_768,
        "partial_nonzero_flows": 1_000,
        "full_nonzero_flows": 10_000,
        "application_tasks_joined": 10_000,
        "target_tasks_joined": 10_000,
    }
    for field, expected in expected_correctness.items():
        if correctness[field] != expected:
            failures.append(f"CORRECTNESS_{field.upper()}")
    for field in ("drain", "rebind", "cleanup"):
        if correctness[field] != "PASS":
            failures.append(f"CORRECTNESS_{field.upper()}")
    if resource["memory_available_kib"] < 8_000_000:
        failures.append("HOST_MEMORY_AVAILABLE")
    if resource["nofile_soft"] < 65_536:
        failures.append("HOST_NOFILE")
    for stage in ("pre_load", "drained"):
        for sample in samples[stage]:
            if sample["client_active"] != 0 or sample["server_active"] != 0:
                failures.append(f"RESOURCE_{stage.upper()}_ACTIVE")
                break
    pre = samples["pre_load"][0]
    drained = samples["drained"][0]
    for field in ("client_fds", "server_fds", "client_tasks", "server_tasks"):
        if drained[field] != pre[field]:
            failures.append(f"RESOURCE_DRAINED_{field.upper()}")
    owner_fields = (
        "client_active",
        "client_fds",
        "client_tasks",
        "server_active",
        "server_fds",
        "server_tasks",
    )
    owner_tuple = tuple(samples["established"][0][field] for field in owner_fields)
    for stage in (
        "established",
        "touched",
        "partial_active",
        "full_active",
        "post_full",
    ):
        for sample in samples[stage]:
            if tuple(sample[field] for field in owner_fields) != owner_tuple:
                failures.append(f"RESOURCE_{stage.upper()}_OWNER_TUPLE")
                break
    if owner_tuple[0] != 10_000 or owner_tuple[3] != 10_000:
        failures.append("RESOURCE_ESTABLISHED_ACTIVE")
    jain = fairness["jain_fraction"]
    ratio = fairness["p01_median_fraction"]
    if jain < _fraction_from_policy(
        policy["minimum_trial_jain_index"], "minimum_trial_jain_index"
    ):
        failures.append("TRIAL_JAIN")
    if ratio < _fraction_from_policy(
        policy["minimum_trial_p01_median_ratio"],
        "minimum_trial_p01_median_ratio",
    ):
        failures.append("TRIAL_P01_MEDIAN_RATIO")
    if derived["partial_nonzero"] != 1_000:
        failures.append("PARTIAL_ALL_FLOWS_NONZERO")
    if derived["full_nonzero"] != 10_000:
        failures.append("FULL_ALL_FLOWS_NONZERO")
    post_limit = _scale_decimal(
        policy["maximum_post_full_percent_of_page_touched"],
        "maximum_post_full_percent_of_page_touched",
    )
    resource_medians: dict[str, int] = {}
    for side in ("client", "server"):
        field = f"{side}_smaps_rss_kib"
        established = _scale_stage_median(samples["established"], field)
        touched = _scale_stage_median(samples["touched"], field)
        post = _scale_stage_median(samples["post_full"], field)
        resource_medians[f"{side}_established_smaps_rss_kib"] = established
        resource_medians[f"{side}_touched_smaps_rss_kib"] = touched
        resource_medians[f"{side}_post_full_smaps_rss_kib"] = post
        if touched == 0:
            failures.append(f"{side.upper()}_TOUCHED_RSS_ZERO")
        elif Decimal(post) * 100 > Decimal(touched) * post_limit:
            failures.append(f"{side.upper()}_POST_FULL_RSS")
    observation = {
        "pair": row["pair"],
        "member": row["member"],
        "order": row["order"],
        "throughput_bytes_per_second": row["value"],
        "jain_index": _fraction_display(jain),
        "jain_numerator": jain.numerator,
        "jain_denominator": jain.denominator,
        "p01_median_ratio": _fraction_display(ratio),
        "p01_median_numerator": ratio.numerator,
        "p01_median_denominator": ratio.denominator,
        "partial_nonzero_flows": derived["partial_nonzero"],
        "full_nonzero_flows": derived["full_nonzero"],
        "client_touched_increment_bytes_per_connection": resource[
            "client_touched_increment_bytes_per_connection"
        ],
        "server_touched_increment_bytes_per_connection": resource[
            "server_touched_increment_bytes_per_connection"
        ],
        "combined_touched_increment_bytes_per_connection": resource[
            "combined_touched_increment_bytes_per_connection"
        ],
        **resource_medians,
        "failures": sorted(set(failures)),
    }
    return observation, failures


def _summarize_scale_evidence(
    *,
    plan: dict[str, object],
    rows: dict[tuple[str, int, str], dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
    member_identity: dict[str, tuple[object, ...]],
    identity_fields: tuple[str, ...],
    evidence_files: list[dict[str, str]],
) -> dict[str, object]:
    policy = plan["scale_safety_policy"]
    validate_scale_safety_policy(policy)
    failures: list[str] = []
    trial_observations: list[dict[str, object]] = []
    pair_observations: list[dict[str, object]] = []
    jain_deltas: list[Fraction] = []
    ratio_deltas: list[Fraction] = []
    throughput_improvements: list[Decimal] = []
    throughput_wins = 0
    maximum_process_gog = _scale_decimal(
        policy[
            "maximum_page_touch_growth_of_growth_kib_per_connection_per_process"
        ],
        "maximum_page_touch_growth_of_growth_kib_per_connection_per_process",
    )
    maximum_combined_gog = _scale_decimal(
        policy["maximum_page_touch_growth_of_growth_kib_per_connection_combined"],
        "maximum_page_touch_growth_of_growth_kib_per_connection_combined",
    )
    sessions = SCALE_RECIPE["sessions"]
    for pair in range(1, plan["pairs"] + 1):
        parent = rows[(SCALE_SCENARIO, pair, "parent")]
        candidate = rows[(SCALE_SCENARIO, pair, "candidate")]
        if {parent["order"], candidate["order"]} != {1, 2}:
            raise CandidateControlError(f"scale pair={pair} must contain orders 1 and 2")
        expected_parent_order = 1 if pair % 2 else 2
        if parent["order"] != expected_parent_order:
            raise CandidateControlError(f"scale pair={pair} does not alternate order")
        parent_observation, parent_failures = _scale_trial_observation(parent, policy)
        candidate_observation, candidate_failures = _scale_trial_observation(
            candidate, policy
        )
        trial_observations.extend((parent_observation, candidate_observation))
        failures.extend(f"PAIR_{pair}_PARENT_{failure}" for failure in parent_failures)
        failures.extend(
            f"PAIR_{pair}_CANDIDATE_{failure}" for failure in candidate_failures
        )
        parent_derived = _validate_scale_evidence(parent)
        candidate_derived = _validate_scale_evidence(candidate)
        jain_delta = (
            candidate_derived["fairness"]["jain_fraction"]
            - parent_derived["fairness"]["jain_fraction"]
        )
        ratio_delta = (
            candidate_derived["fairness"]["p01_median_fraction"]
            - parent_derived["fairness"]["p01_median_fraction"]
        )
        jain_deltas.append(jain_delta)
        ratio_deltas.append(ratio_delta)
        improvement: Decimal | None = None
        if parent["value"] == 0:
            failures.append(f"PAIR_{pair}_ZERO_PARENT_THROUGHPUT")
        else:
            improvement = _improvement(
                parent["value"], candidate["value"], "higher_is_better"
            )
            throughput_improvements.append(improvement)
            if improvement > 0:
                throughput_wins += 1
            if improvement < _scale_decimal(
                policy["minimum_pair_throughput_improvement_percent"],
                "minimum_pair_throughput_improvement_percent",
            ):
                failures.append(f"PAIR_{pair}_THROUGHPUT_FLOOR")
        growth_of_growth_kib: dict[str, int] = {}
        for side in ("client", "server"):
            field = f"{side}_smaps_rss_kib"
            parent_growth = _scale_stage_median(
                parent_derived["samples"]["touched"], field
            ) - _scale_stage_median(parent_derived["samples"]["established"], field)
            candidate_growth = _scale_stage_median(
                candidate_derived["samples"]["touched"], field
            ) - _scale_stage_median(
                candidate_derived["samples"]["established"], field
            )
            growth_of_growth_kib[side] = candidate_growth - parent_growth
        client_gog_kib = growth_of_growth_kib["client"]
        server_gog_kib = growth_of_growth_kib["server"]
        combined_gog_kib = client_gog_kib + server_gog_kib
        if Decimal(client_gog_kib) > maximum_process_gog * sessions:
            failures.append(f"PAIR_{pair}_CLIENT_PAGE_TOUCH_GOG")
        if Decimal(server_gog_kib) > maximum_process_gog * sessions:
            failures.append(f"PAIR_{pair}_SERVER_PAGE_TOUCH_GOG")
        if Decimal(combined_gog_kib) > maximum_combined_gog * sessions:
            failures.append(f"PAIR_{pair}_COMBINED_PAGE_TOUCH_GOG")
        client_gog_bytes = _truncating_division(client_gog_kib * 1024, sessions)
        server_gog_bytes = _truncating_division(server_gog_kib * 1024, sessions)
        combined_gog_bytes = _truncating_division(combined_gog_kib * 1024, sessions)
        pair_observations.append(
            {
                "pair": pair,
                "parent_order": parent["order"],
                "candidate_order": candidate["order"],
                "parent_throughput_bytes_per_second": parent["value"],
                "candidate_throughput_bytes_per_second": candidate["value"],
                "throughput_improvement_percent": (
                    None if improvement is None else _display_decimal(improvement)
                ),
                "jain_delta": _fraction_display(jain_delta),
                "p01_median_ratio_delta": _fraction_display(ratio_delta),
                "client_page_touch_growth_of_growth_bytes_per_connection": client_gog_bytes,
                "server_page_touch_growth_of_growth_bytes_per_connection": server_gog_bytes,
                "combined_page_touch_growth_of_growth_bytes_per_connection": combined_gog_bytes,
            }
        )
    median_jain_delta = _median_fraction(jain_deltas)
    median_ratio_delta = _median_fraction(ratio_deltas)
    if median_jain_delta < _fraction_from_policy(
        policy["minimum_median_jain_delta"], "minimum_median_jain_delta"
    ):
        failures.append("MEDIAN_JAIN_DELTA")
    if median_ratio_delta < _fraction_from_policy(
        policy["minimum_median_p01_median_ratio_delta"],
        "minimum_median_p01_median_ratio_delta",
    ):
        failures.append("MEDIAN_P01_MEDIAN_RATIO_DELTA")
    median_throughput: Decimal | None = None
    minimum_throughput: Decimal | None = None
    if len(throughput_improvements) != plan["pairs"]:
        failures.append("THROUGHPUT_PAIR_SET")
    else:
        median_throughput = _median(throughput_improvements)
        minimum_throughput = min(throughput_improvements)
        if median_throughput < _scale_decimal(
            policy["minimum_median_throughput_improvement_percent"],
            "minimum_median_throughput_improvement_percent",
        ):
            failures.append("MEDIAN_THROUGHPUT")
    if throughput_wins < policy["minimum_throughput_wins"]:
        failures.append("THROUGHPUT_WINS")
    failures = sorted(set(failures))
    passed = not failures
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    status = "SCALE_SAFETY_PASS" if passed else "SCALE_SAFETY_FAIL"
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selection": plan["selection"],
        "selected_scenario": SCALE_SCENARIO,
        "scenario_group": SCALE_SCENARIO,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": build_identities,
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "scale_safety_policy": policy,
        "scale_lineage": plan["scale_lineage"],
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": True,
        "candidate_win_enabled": False,
        "decision_reason": (
            "all dedicated tcp-scale safety gates passed"
            if passed
            else "one or more dedicated tcp-scale safety gates failed"
        ),
        "threshold_availability": "scale_safety",
        "adoption_claim": False,
        "status": status,
        "workflow_failure_reason": None if passed else "; ".join(failures),
        "mandatory_scenarios": [SCALE_SCENARIO],
        "missing_scenarios": [],
        "primary_results": [],
        "guard_results": [],
        "scenarios": [{"scenario": SCALE_SCENARIO, "status": status}],
        "scale_safety": {
            "schema_version": 1,
            "status": "PASS" if passed else "FAIL",
            "failures": failures,
            "throughput_wins": throughput_wins,
            "median_throughput_improvement_percent": (
                None
                if median_throughput is None
                else _display_decimal(median_throughput)
            ),
            "minimum_throughput_improvement_percent": (
                None
                if minimum_throughput is None
                else _display_decimal(minimum_throughput)
            ),
            "median_jain_delta": _fraction_display(median_jain_delta),
            "median_p01_median_ratio_delta": _fraction_display(median_ratio_delta),
            "trials": sorted(
                trial_observations, key=lambda item: (item["pair"], item["order"])
            ),
            "pairs": pair_observations,
        },
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }


def summarize_evidence(
    *,
    plan: dict[str, object],
    parent_root: pathlib.Path,
    candidate_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
    repository: pathlib.Path | None = None,
) -> dict[str, object]:
    """Validate paired raw evidence and calculate per-pair directional deltas."""

    if (
        COMMIT_SHA.fullmatch(parent_sha) is None
        or COMMIT_SHA.fullmatch(candidate_sha) is None
    ):
        raise CandidateControlError("summary identities must be full commit SHAs")
    parent_sha = parent_sha.lower()
    candidate_sha = candidate_sha.lower()
    if parent_sha == candidate_sha:
        raise CandidateControlError("summary parent and candidate must be different")
    is_scale = plan["selection"] == SCALE_SCENARIO
    if is_scale:
        lineage = plan["scale_lineage"]
        if (
            lineage["parent_sha"] != parent_sha
            or lineage["candidate_sha"] != candidate_sha
        ):
            raise CandidateControlError("scale summary commits do not match the bound lineage")
        if repository is None:
            raise CandidateControlError("scale summary requires repository lineage verification")
        validate_scale_lineage_repository(repository, lineage)
    planned = {entry["scenario"]: entry for entry in plan["scenarios"]}
    rows: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, str]] = []
    identity_fields = (
        "sha",
        "tree",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
    )
    member_identity: dict[str, tuple[object, ...]] = {}
    environment_identity: tuple[object, ...] | None = None
    for member, root in (("parent", parent_root), ("candidate", candidate_root)):
        if not root.is_dir():
            raise CandidateControlError(
                f"{member} evidence directory is missing",
                missing_scenarios=list(planned),
            )
        files = sorted(root.glob("*.jsonl"))
        if not files:
            raise CandidateControlError(
                f"{member} evidence directory has no JSONL files",
                missing_scenarios=list(planned),
            )
        for path in files:
            row = _read_trial(path)
            scenario, pair, row_member = _validate_trial(
                row,
                source_member=member,
                plan=plan,
                planned=planned,
                parent_sha=parent_sha,
                candidate_sha=candidate_sha,
            )
            key = (scenario, pair, row_member)
            if key in rows:
                raise CandidateControlError(
                    f"duplicate evidence row for scenario={scenario}, pair={pair}, member={row_member}"
                )
            rows[key] = row
            if is_scale:
                lineage = plan["scale_lineage"]
                expected_identity = {
                    "sha": lineage[f"{member}_sha"],
                    "tree": lineage[f"{member}_tree"],
                    "runner_sha256": lineage["runner_sha256"],
                    "client_sha256": lineage[f"{member}_client_sha256"],
                    "server_sha256": lineage[f"{member}_server_sha256"],
                }
                for field, expected_value in expected_identity.items():
                    if row[field] != expected_value:
                        raise CandidateControlError(
                            f"scale {member} {field} does not match lineage"
                        )
            identity = tuple(row[field] for field in identity_fields)
            if member in member_identity and member_identity[member] != identity:
                raise CandidateControlError(
                    f"{member} build identity changed between trials"
                )
            member_identity[member] = identity
            environment = tuple(
                row[field]
                for field in (
                    "rustc",
                    "kernel",
                    "cpu_model",
                    "cpu_count",
                    "memory_kib",
                    "build_profile",
                )
            )
            if environment_identity is not None and environment_identity != environment:
                raise CandidateControlError("runner environment changed between trials")
            environment_identity = environment
            evidence_files.append(
                {
                    "member": member,
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    expected = {
        (scenario, pair, member)
        for scenario in planned
        for pair in range(1, plan["pairs"] + 1)
        for member in ("parent", "candidate")
    }
    if set(rows) != expected:
        missing = sorted(expected - set(rows))
        unexpected = sorted(set(rows) - expected)
        raise CandidateControlError(
            f"evidence set is incomplete: missing={missing}, unexpected={unexpected}",
            missing_scenarios=sorted({key[0] for key in missing}),
        )

    if is_scale:
        return _summarize_scale_evidence(
            plan=plan,
            rows=rows,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
            member_identity=member_identity,
            identity_fields=identity_fields,
            evidence_files=evidence_files,
        )

    scenario_summaries = []
    for scenario, scenario_plan in planned.items():
        direction = scenario_plan["direction"]
        pair_summaries = []
        improvements = []
        for pair in range(1, plan["pairs"] + 1):
            parent = rows[(scenario, pair, "parent")]
            candidate = rows[(scenario, pair, "candidate")]
            if {parent["order"], candidate["order"]} != {1, 2}:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} must contain orders 1 and 2"
                )
            expected_parent_order = 1 if pair % 2 else 2
            if parent["order"] != expected_parent_order:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} does not alternate execution order"
                )
            parent_value = parent["value"]
            candidate_value = candidate["value"]
            improvement = _improvement(parent_value, candidate_value, direction)
            improvements.append(improvement)
            pair_summaries.append(
                {
                    "pair": pair,
                    "parent_order": parent["order"],
                    "candidate_order": candidate["order"],
                    "parent_value": parent_value,
                    "candidate_value": candidate_value,
                    "improvement_percent": _display_decimal(improvement),
                }
            )
        wins = sum(value > 0 for value in improvements)
        losses = sum(value < 0 for value in improvements)
        ties = len(improvements) - wins - losses
        median_improvement = _median(improvements)
        policy_entry = plan["decision_policy"]["scenarios"][scenario]
        spread, warnings = _stability_warnings(
            improvements,
            noise_band=policy_entry["noise_band_percent"],
        )
        threshold_decision = _scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=wins,
            losses=losses,
            median_improvement=median_improvement,
        )
        scenario_summaries.append(
            {
                "scenario": scenario,
                "role": scenario_plan["role"],
                "mandatory": scenario_plan["mandatory"],
                "metric": scenario_plan["metric"],
                "direction": direction,
                "topology": scenario_plan["topology"],
                "application_payload_bytes": scenario_plan[
                    "application_payload_bytes"
                ],
                "socks_datagram_bytes": scenario_plan["socks_datagram_bytes"],
                "upstream_wire_bytes": scenario_plan["upstream_wire_bytes"],
                "pairs": pair_summaries,
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "median_improvement_percent": _display_decimal(median_improvement),
                "minimum_improvement_percent": _display_decimal(min(improvements)),
                "maximum_improvement_percent": _display_decimal(max(improvements)),
                "spread_percent": _display_decimal(spread),
                "observed_direction": _observed_direction(wins=wins, losses=losses),
                "outlier_warning": any(
                    warning.startswith("EXTREME_") for warning in warnings
                ),
                "warnings": warnings,
                **threshold_decision,
            }
        )
    enabled_count = sum(result["decision_enabled"] for result in scenario_summaries)
    if enabled_count == 0:
        threshold_availability = "none"
    elif enabled_count == len(scenario_summaries):
        threshold_availability = "complete"
    else:
        threshold_availability = "partial"
    if plan["mode"] == "diagnostic":
        status = "MEASURED"
        decision_reason = "diagnostic mode reports measurements only"
    elif any(result["status"] == "REGRESSION" for result in scenario_summaries):
        status = "REGRESSION"
        decision_reason = "at least one calibrated mandatory scenario regressed"
    else:
        primary_summaries = [
            result for result in scenario_summaries if result["role"] == "primary"
        ]
        guard_summaries = [
            result for result in scenario_summaries if result["role"] == "guard"
        ]
        if (
            threshold_availability == "complete"
            and all(result["status"] == "CANDIDATE_WIN" for result in primary_summaries)
            and all(result["guard_passed"] is True for result in guard_summaries)
        ):
            status = "CANDIDATE_WIN"
            decision_reason = (
                "all calibrated primaries and guards satisfy the adoption policy"
            )
        else:
            status = "INCONCLUSIVE"
            decision_reason = (
                "calibrated thresholds are unavailable or adoption conditions are unmet"
            )
    primary_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "primary"
    ]
    guard_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "guard"
    ]
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selection": plan["selection"],
        "selected_scenario": plan["selected_scenario"],
        "scenario_group": plan["scenario_group"],
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": build_identities,
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "scale_safety_policy": None,
        "scale_lineage": None,
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": enabled_count > 0,
        "candidate_win_enabled": threshold_availability == "complete",
        "decision_reason": decision_reason,
        "threshold_availability": threshold_availability,
        "adoption_claim": status == "CANDIDATE_WIN",
        "status": status,
        "workflow_failure_reason": (
            decision_reason if status == "REGRESSION" else None
        ),
        "mandatory_scenarios": list(planned),
        "missing_scenarios": [],
        "primary_results": primary_results,
        "guard_results": guard_results,
        "scenarios": scenario_summaries,
        "scale_safety": None,
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }


def invalid_summary(
    *,
    parent_sha: str,
    candidate_sha: str,
    error: CandidateControlError,
    plan: dict[str, object] | None = None,
    decision_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    mandatory = (
        [entry["scenario"] for entry in plan["scenarios"]] if plan is not None else []
    )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"] if plan is not None else None,
        "selection": plan["selection"] if plan is not None else None,
        "selected_scenario": plan["selected_scenario"] if plan is not None else None,
        "scenario_group": plan["scenario_group"] if plan is not None else None,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": {},
        "decision_policy": copy.deepcopy(
            plan["decision_policy"]
            if plan is not None
            else (UNCALIBRATED_POLICY if decision_policy is None else decision_policy)
        ),
        "scale_safety_policy": copy.deepcopy(
            plan.get("scale_safety_policy") if plan is not None else None
        ),
        "scale_lineage": copy.deepcopy(
            plan.get("scale_lineage") if plan is not None else None
        ),
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": False,
        "candidate_win_enabled": False,
        "decision_reason": "invalid evidence",
        "threshold_availability": "none",
        "adoption_claim": False,
        "status": "INVALID_EVIDENCE",
        "workflow_failure_reason": str(error),
        "mandatory_scenarios": mandatory,
        "missing_scenarios": error.missing_scenarios,
        "primary_results": [],
        "guard_results": [],
        "error": str(error),
        "scenarios": [],
        "scale_safety": None,
        "evidence_files": [],
    }


def summary_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Performance candidate result",
        "",
        f"- Status: **{summary['status']}**",
        f"- Parent: `{summary['parent_sha']}`",
        f"- Candidate: `{summary['candidate_sha']}`",
        f"- Adoption claim: **{str(summary['adoption_claim']).lower()}**",
        "",
    ]
    if summary["status"] == "INVALID_EVIDENCE":
        lines.extend(
            [
                f"- Mode: `{summary['mode']}`",
                f"- Scenario group: `{summary['scenario_group']}`",
                f"- Mandatory scenarios: `{', '.join(summary['mandatory_scenarios']) or '-'}`",
                f"- Missing scenarios: `{', '.join(summary['missing_scenarios']) or '-'}`",
                "",
                f"Evidence error: `{summary['error']}`",
                "",
            ]
        )
        return "\n".join(lines)
    if summary["selection"] == SCALE_SCENARIO:
        scale = summary["scale_safety"]
        lineage = summary["scale_lineage"]
        lines.extend(
            [
                f"- Mode: `{summary['mode']}`",
                f"- Scale safety: **{scale['status']}**",
                f"- Dedicated policy: `{summary['scale_safety_policy']['policy_id']}` "
                f"(`{summary['scale_safety_policy']['policy_sha256']}`)",
                f"- Decision: {summary['decision_reason']}",
                f"- Failures: `{', '.join(scale['failures']) or '-'}`",
                "- This qualification is a safety result, not an adoption claim.",
                "",
                "| Lineage member | Commit | Tree |",
                "|---|---|---|",
                f"| H / final tree | `{lineage['head_sha']}` | `{lineage['head_tree']}` |",
                f"| P16 / parent | `{lineage['parent_sha']}` | `{lineage['parent_tree']}` |",
                f"| C32 / candidate | `{lineage['candidate_sha']}` | `{lineage['candidate_tree']}` |",
                "",
                f"- Counterfactual patch SHA-256: `{lineage['counterfactual_patch_sha256']}`",
                f"- Candidate-built runner SHA-256: `{lineage['runner_sha256']}`",
                "",
                "| Pair | Parent/Candidate throughput B/s | Improvement % | Jain delta | p01/median delta | Client/Server/Combined page-touch GoG B/conn |",
                "|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for pair in scale["pairs"]:
            improvement = pair["throughput_improvement_percent"]
            lines.append(
                f"| {pair['pair']} | {pair['parent_throughput_bytes_per_second']} / "
                f"{pair['candidate_throughput_bytes_per_second']} | "
                f"{improvement if improvement is not None else '-'} | "
                f"{pair['jain_delta']} | {pair['p01_median_ratio_delta']} | "
                f"{pair['client_page_touch_growth_of_growth_bytes_per_connection']} / "
                f"{pair['server_page_touch_growth_of_growth_bytes_per_connection']} / "
                f"{pair['combined_page_touch_growth_of_growth_bytes_per_connection']} |"
            )
        lines.append("")
        return "\n".join(lines)
    lines.extend(
        [
            f"- Mode: `{summary['mode']}`",
            f"- Scenario group: `{summary['scenario_group']}`",
            f"- Policy: `{summary['decision_policy']['policy_id']}` "
            f"(`{summary['decision_policy']['policy_sha256'] or 'in-memory'}`)",
            f"- Threshold availability: `{summary['threshold_availability']}`",
            f"- Decision: {summary['decision_reason']}",
            "- Warnings are descriptive only and never change status or exit code.",
            "",
        ]
    )
    scenario_names = {scenario["scenario"] for scenario in summary["scenarios"]}
    if "udp-max-wire-65507" in scenario_names:
        lines.extend(
            [
                "- UDP bound: a 65,507-byte application payload is not representable "
                "through SOCKS/IPv4. The Shadowsocks maximum scenario carries 65,449 "
                "application bytes and fills the AES-2022 response wire to 65,507 bytes.",
                "",
            ]
        )
    if "udp-direct-max-65497" in scenario_names:
        lines.extend(
            [
                "- Direct UDP bound: 65,497 application bytes plus the 10-byte "
                "SOCKS/IPv4 header fill the 65,507-byte SOCKS datagram.",
                "",
            ]
        )
    lines.extend(
        [
            "| Member | Commit | Tree | Runner SHA-256 | Client SHA-256 | Server SHA-256 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for member in ("parent", "candidate"):
        identity = summary["build_identities"][member]
        lines.append(
            f"| {member} | `{identity['sha']}` | `{identity['tree']}` | "
            f"`{identity['runner_sha256']}` | `{identity['client_sha256']}` | "
            f"`{identity['server_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "| Scenario | Role | Topology | Application payload B | SOCKS datagram B | Upstream wire B | Metric | Direction | Observed | Wins | Losses | Ties | Median % | Min % | Max % | Spread % | Warnings | Threshold decision | Status |",
            "|---|---|---|---:|---:|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|",
        ]
    )
    for scenario in summary["scenarios"]:
        lines.append(
            f"| {scenario['scenario']} | {scenario['role']} | {scenario['topology']} | "
            f"{scenario['application_payload_bytes']} | "
            f"{scenario['socks_datagram_bytes'] if scenario['socks_datagram_bytes'] is not None else '-'} | "
            f"{scenario['upstream_wire_bytes'] if scenario['upstream_wire_bytes'] is not None else '-'} | "
            f"{scenario['metric']} | "
            f"{scenario['direction']} | {scenario['observed_direction']} | "
            f"{scenario['wins']} | {scenario['losses']} | "
            f"{scenario['ties']} | {scenario['median_improvement_percent']:.6f} | "
            f"{scenario['minimum_improvement_percent']:.6f} | "
            f"{scenario['maximum_improvement_percent']:.6f} | "
            f"{scenario['spread_percent']:.6f} | "
            f"{', '.join(scenario['warnings']) or '-'} | "
            f"{scenario['threshold_decision']} | {scenario['status']} |"
        )
    lines.extend(
        [
            "",
            "| Scenario | Pair | Parent order/value | Candidate order/value | Improvement % |",
            "|---|---:|---|---|---:|",
        ]
    )
    for scenario in summary["scenarios"]:
        for pair in scenario["pairs"]:
            lines.append(
                f"| {scenario['scenario']} | {pair['pair']} | "
                f"{pair['parent_order']} / {pair['parent_value']} | "
                f"{pair['candidate_order']} / {pair['candidate_value']} | "
                f"{pair['improvement_percent']:.6f} |"
            )
    lines.append("")
    return "\n".join(lines)


def _atomic_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            pathlib.Path(temporary_name).unlink(missing_ok=True)


def write_summary_outputs(
    summary: dict[str, object], *, output: pathlib.Path, markdown: pathlib.Path
) -> None:
    _atomic_text(
        output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(markdown, summary_markdown(summary))


def run_summary_command(parsed: argparse.Namespace) -> int:
    plan = None
    decision_policy = None
    try:
        decision_policy = load_decision_policy(parsed.policy)
        scale_policy_path = getattr(parsed, "scale_policy", None)
        scale_policy = (
            None
            if scale_policy_path is None
            else load_scale_safety_policy(scale_policy_path)
        )
        plan = load_plan(
            parsed.plan,
            decision_policy=decision_policy,
            scale_safety_policy=scale_policy,
        )
        summary = summarize_evidence(
            plan=plan,
            parent_root=parsed.parent_root,
            candidate_root=parsed.candidate_root,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            repository=getattr(parsed, "repository", None),
        )
    except CandidateControlError as error:
        summary = invalid_summary(
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            error=error,
            plan=plan,
            decision_policy=decision_policy,
        )
        write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
    write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
    if summary["status"] in {
        "MEASURED",
        "INCONCLUSIVE",
        "CANDIDATE_WIN",
        "SCALE_SAFETY_PASS",
    }:
        return 0
    if summary["status"] in {"REGRESSION", "SCALE_SAFETY_FAIL"}:
        message = (
            "dedicated tcp-scale safety gate failed"
            if summary["status"] == "SCALE_SAFETY_FAIL"
            else "calibrated mandatory scenario regressed"
        )
        print(f"performance-candidate: {message}", file=sys.stderr)
        return 3
    print("performance-candidate: unknown summary status", file=sys.stderr)
    return 4


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def windows_tun_scenario_contracts() -> dict[str, object]:
    """Return the JSON-canonical nine-scenario recipe."""

    return json.loads(_canonical_json_bytes(WINDOWS_TUN_SCENARIOS).decode("ascii"))


def windows_tun_recipe_sha256() -> str:
    return hashlib.sha256(
        _canonical_json_bytes(windows_tun_scenario_contracts())
    ).hexdigest()


def _windows_tun_calibration_fields(entry: dict[str, object]) -> tuple[object, ...]:
    return tuple(
        entry[field]
        for field in (
            "noise_band_percent",
            "regression_threshold_percent",
            "adoption_threshold_percent",
            "minimum_pairs",
            "minimum_wins",
            "minimum_losses",
            "calibration_source",
            "calibration_artifact_sha256",
            "calibration_environment",
        )
    )


def validate_windows_tun_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("Windows TUN policy must be a JSON object")
    _exact_fields(policy, WINDOWS_TUN_POLICY_RUNTIME_FIELDS, "Windows TUN policy")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != WINDOWS_TUN_POLICY_SCHEMA_VERSION
    ):
        raise CandidateControlError("Windows TUN policy schema_version is unsupported")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("Windows TUN policy_id must be non-empty")
    if policy["selection"] != WINDOWS_TUN_SELECTION:
        raise CandidateControlError("Windows TUN policy selection is invalid")
    digest = policy["policy_sha256"]
    if digest is not None and (
        type(digest) is not str or SHA256.fullmatch(digest) is None
    ):
        raise CandidateControlError("Windows TUN policy SHA-256 is invalid")
    scenarios = policy["scenarios"]
    if type(scenarios) is not dict or set(scenarios) != set(WINDOWS_TUN_SCENARIOS):
        raise CandidateControlError(
            "Windows TUN policy scenarios must exactly match the nine-scenario catalog"
        )
    calibration_states: list[bool] = []
    calibration_identities: list[tuple[object, object, object]] = []
    expected_recipe_sha256 = windows_tun_recipe_sha256()
    for scenario, contract in WINDOWS_TUN_SCENARIOS.items():
        scenario_policy = scenarios[scenario]
        if type(scenario_policy) is not dict:
            raise CandidateControlError(
                f"Windows TUN policy scenario {scenario} must be an object"
            )
        _exact_fields(
            scenario_policy,
            WINDOWS_TUN_POLICY_SCENARIO_FIELDS,
            f"Windows TUN policy scenario {scenario}",
        )
        metrics = scenario_policy["metrics"]
        expected_metrics = contract["metrics"]
        if type(metrics) is not dict or set(metrics) != set(expected_metrics):
            raise CandidateControlError(
                f"Windows TUN policy scenario {scenario} metrics are incomplete"
            )
        for metric, metric_contract in expected_metrics.items():
            entry = metrics[metric]
            if type(entry) is not dict:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} must be an object"
                )
            _exact_fields(
                entry,
                WINDOWS_TUN_POLICY_METRIC_FIELDS,
                f"Windows TUN policy metric {scenario}/{metric}",
            )
            if (
                entry["unit"] != metric_contract["unit"]
                or entry["direction"] != metric_contract["direction"]
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} unit or direction mismatch"
                )
            calibrated = _windows_tun_calibration_fields(entry)
            if all(value is None for value in calibrated):
                calibration_states.append(False)
                continue
            if any(value is None for value in calibrated):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} calibration "
                    "must be complete or entirely null"
                )
            calibration_states.append(True)
            noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
            regression = _policy_percent(
                entry["regression_threshold_percent"],
                "regression_threshold_percent",
            )
            adoption = _policy_percent(
                entry["adoption_threshold_percent"],
                "adoption_threshold_percent",
            )
            if noise < 0 or regression >= -noise or adoption <= noise:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} thresholds "
                    "must lie outside the noise band"
                )
            if (
                type(entry["minimum_pairs"]) is not int
                or entry["minimum_pairs"] != WINDOWS_TUN_PAIR_COUNT
                or type(entry["minimum_wins"]) is not int
                or not 1 <= entry["minimum_wins"] <= WINDOWS_TUN_PAIR_COUNT
                or type(entry["minimum_losses"]) is not int
                or not 1 <= entry["minimum_losses"] <= WINDOWS_TUN_PAIR_COUNT
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} pair counts are invalid"
                )
            source = entry["calibration_source"]
            artifact_digest = entry["calibration_artifact_sha256"]
            if (
                type(source) is not str
                or re.fullmatch(r"artifact:\S+@sha256:[0-9a-f]{64}", source) is None
                or type(artifact_digest) is not str
                or SHA256.fullmatch(artifact_digest) is None
                or not source.endswith(f"@sha256:{artifact_digest}")
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} must bind one "
                    "SHA-256 identified calibration artifact"
                )
            environment = entry["calibration_environment"]
            if type(environment) is not dict:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} calibration "
                    "environment is invalid"
                )
            _exact_fields(
                environment,
                WINDOWS_TUN_CALIBRATION_ENVIRONMENT_FIELDS,
                f"Windows TUN policy metric {scenario}/{metric} environment",
            )
            for field, expected in WINDOWS_TUN_GUEST.items():
                if environment[field] != expected:
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is unsupported"
                    )
            if environment["recipe_sha256"] != expected_recipe_sha256:
                raise CandidateControlError(
                    "Windows TUN calibration recipe does not match this controller"
                )
            for field in ("guest_build", "cpu_model", "power_plan_guid"):
                if type(environment[field]) is not str or not environment[field].strip():
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is invalid"
                    )
            for field in ("cpu_count", "memory_bytes"):
                if type(environment[field]) is not int or environment[field] <= 0:
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is invalid"
                    )
            calibration_identities.append((source, artifact_digest, environment))
    if any(calibration_states) and not all(calibration_states):
        raise CandidateControlError(
            "Windows TUN policy cannot mix calibrated and uncalibrated metrics"
        )
    if calibration_identities and any(
        identity != calibration_identities[0] for identity in calibration_identities[1:]
    ):
        raise CandidateControlError(
            "Windows TUN policy metrics must share one calibration artifact and environment"
        )


def load_windows_tun_policy(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        document = _strict_json(raw.decode("utf-8"), source="Windows TUN policy")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read Windows TUN policy") from error
    if type(document) is not dict:
        raise CandidateControlError("Windows TUN policy must be a JSON object")
    _exact_fields(
        document,
        WINDOWS_TUN_POLICY_DOCUMENT_FIELDS,
        "Windows TUN policy document",
    )
    policy = {**document, "policy_sha256": hashlib.sha256(raw).hexdigest()}
    validate_windows_tun_policy(policy)
    return policy


def windows_tun_policy_is_calibrated(policy: dict[str, object]) -> bool:
    validate_windows_tun_policy(policy)
    first_scenario = next(iter(WINDOWS_TUN_SCENARIOS))
    first_metric = next(iter(WINDOWS_TUN_SCENARIOS[first_scenario]["metrics"]))
    entry = policy["scenarios"][first_scenario]["metrics"][first_metric]
    return entry["calibration_environment"] is not None


def create_windows_tun_plan(
    *, run_kind: str, decision_policy: dict[str, object]
) -> dict[str, object]:
    if run_kind not in WINDOWS_TUN_RUN_KINDS:
        raise CandidateControlError(
            "Windows TUN run_kind must be comparison or calibration-aa"
        )
    policy = copy.deepcopy(decision_policy)
    validate_windows_tun_policy(policy)
    contracts = windows_tun_scenario_contracts()
    trials: list[dict[str, object]] = []
    sequence = 0
    for scenario in contracts:
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
            members = ("parent", "candidate") if pair % 2 else ("candidate", "parent")
            for order, member in enumerate(members, start=1):
                sequence += 1
                trials.append(
                    {
                        "sequence": sequence,
                        "scenario": scenario,
                        "pair": pair,
                        "member": member,
                        "order": order,
                    }
                )
    calibrated = windows_tun_policy_is_calibrated(policy)
    return {
        "schema_version": WINDOWS_TUN_PLAN_SCHEMA_VERSION,
        "kind": "windows_tun_performance_plan",
        "selection": WINDOWS_TUN_SELECTION,
        "run_kind": run_kind,
        "pairs": WINDOWS_TUN_PAIR_COUNT,
        "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
        "recipe_sha256": windows_tun_recipe_sha256(),
        "scenarios": contracts,
        "trials": trials,
        "decision_policy": policy,
        "calibration_complete": calibrated,
        # A plan can enable a calibrated decision, but evidence is the only
        # thing that can make the resulting comparison adoption-eligible.
        "adoption_eligible": False,
    }


def load_windows_tun_plan(
    path: pathlib.Path, *, decision_policy: dict[str, object]
) -> dict[str, object]:
    try:
        plan = _strict_json(
            path.read_text(encoding="utf-8"), source="Windows TUN performance plan"
        )
        if type(plan) is not dict:
            raise CandidateControlError("Windows TUN plan must be a JSON object")
        _exact_fields(plan, WINDOWS_TUN_PLAN_FIELDS, "Windows TUN performance plan")
        expected = create_windows_tun_plan(
            run_kind=plan["run_kind"], decision_policy=decision_policy
        )
    except (OSError, KeyError, TypeError) as error:
        raise CandidateControlError("Windows TUN performance plan is invalid") from error
    if plan != expected:
        raise CandidateControlError(
            "Windows TUN performance plan does not match the canonical recipe or policy"
        )
    return plan


def _windows_tun_required_digest(
    row: dict[str, object], field: str, *, length: int
) -> str:
    value = row.get(field)
    pattern = r"[0-9a-f]{%d}" % length
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise CandidateControlError(
            f"Windows TUN evidence {field} must be lowercase {length}-hex"
        )
    return value


def _validate_windows_tun_environment(environment: object) -> dict[str, object]:
    if type(environment) is not dict:
        raise CandidateControlError("Windows TUN evidence environment must be an object")
    _exact_fields(environment, WINDOWS_TUN_ENVIRONMENT_FIELDS, "Windows TUN environment")
    for field, expected in WINDOWS_TUN_GUEST.items():
        if environment[field] != expected:
            raise CandidateControlError(
                f"Windows TUN evidence environment {field} is unsupported"
            )
    for field in ("guest_build", "cpu_model", "power_plan_guid"):
        if type(environment[field]) is not str or not environment[field].strip():
            raise CandidateControlError(
                f"Windows TUN evidence environment {field} is invalid"
            )
    for field in ("cpu_count", "memory_bytes"):
        if type(environment[field]) is not int or environment[field] <= 0:
            raise CandidateControlError(
                f"Windows TUN evidence environment {field} is invalid"
            )
    return environment


def _windows_tun_utc(value: object, field: str) -> datetime:
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z",
        value,
    ) is None:
        raise CandidateControlError(
            f"Windows TUN evidence {field} must be canonical UTC"
        )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CandidateControlError(
            f"Windows TUN evidence {field} is not a real timestamp"
        ) from error
    if parsed.tzinfo != timezone.utc:
        raise CandidateControlError(f"Windows TUN evidence {field} is not UTC")
    return parsed


def _validate_windows_tun_network_model_reference(
    value: object, *, scenario: str, sequence: int, member: str, pair: int
) -> None:
    model_scenarios = {"udp-route-once", "network-lifecycle"}
    if scenario not in model_scenarios:
        if value is not None:
            raise CandidateControlError(
                "non-model Windows TUN trial cannot reference network-model evidence"
            )
        return
    if type(value) is not dict:
        raise CandidateControlError(
            f"{scenario} trial must reference network-model evidence"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_NETWORK_MODEL_EVIDENCE_FIELDS,
        "Windows TUN network-model evidence reference",
    )
    if value["schema_version"] != 1:
        raise CandidateControlError("Windows TUN network-model reference is unsupported")
    if value["controller_sha256"] != WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256:
        raise CandidateControlError("Windows TUN network-model controller identity mismatch")
    collector_digest = value["collector_sha256"]
    if type(collector_digest) is not str or SHA256.fullmatch(collector_digest) is None:
        raise CandidateControlError("Windows TUN network-model collector SHA-256 is invalid")
    if value["plan_sha256"] != WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256:
        raise CandidateControlError("Windows TUN network-model plan identity mismatch")
    expected_file = f"{sequence:03d}-{scenario}-{member}-pair-{pair}.network-model.json"
    if value["observation_file"] != expected_file:
        raise CandidateControlError("Windows TUN network-model observation name mismatch")
    digest = value["observation_sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise CandidateControlError("Windows TUN network-model observation SHA-256 is invalid")


def _windows_tun_diagnostic_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise CandidateControlError(
            f"Windows TUN fragment diagnostics {field} must be a non-negative u64"
        )
    return value


def _validate_windows_tun_diagnostics(
    value: object,
    *,
    scenario: str,
    contract: dict[str, object],
    checked_units: int,
) -> None:
    if scenario != "fragment-reassembly-throughput":
        if value is not None:
            raise CandidateControlError(
                "non-fragment Windows TUN trial diagnostics must be null"
            )
        return
    if type(value) is not dict:
        raise CandidateControlError(
            "fragment Windows TUN trial diagnostics must be an object"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_FIELDS,
        "Windows TUN fragment diagnostics",
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_SCHEMA_VERSION
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics schema_version is unsupported"
        )
    if value["kind"] != "fragment_ack_accounting":
        raise CandidateControlError("Windows TUN fragment diagnostics kind is invalid")

    recipe = contract["recipe"]
    for field in WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS:
        expected = recipe[field]
        if type(value[field]) is not type(expected) or value[field] != expected:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} does not match the recipe"
            )

    accounting = value["accounting"]
    if type(accounting) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics accounting must be an object"
        )
    _exact_fields(
        accounting,
        WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS,
        "Windows TUN fragment diagnostics accounting",
    )
    counts = {
        field: _windows_tun_diagnostic_u64(
            accounting[field], f"accounting.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS
    }
    for field in (
        "warmup_unique_datagrams",
        "active_unique_datagrams",
        "total_unique_datagrams",
    ):
        if counts[field] == 0:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} must be positive"
            )
        if counts[field] % recipe["batch_datagrams"] != 0:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} is not batch-aligned"
            )
    if counts["active_unique_datagrams"] != checked_units:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics active unique count does not match correctness"
        )
    for phase in ("warmup", "active"):
        if counts[f"{phase}_request_attempts"] < counts[f"{phase}_unique_datagrams"]:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {phase} attempts are below unique datagrams"
            )
    if counts["total_unique_datagrams"] != (
        counts["warmup_unique_datagrams"] + counts["active_unique_datagrams"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics total unique count is inconsistent"
        )
    if counts["total_request_attempts"] != (
        counts["warmup_request_attempts"] + counts["active_request_attempts"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics total attempt count is inconsistent"
        )
    if counts["retransmissions"] != (
        counts["total_request_attempts"] - counts["total_unique_datagrams"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retransmission count is inconsistent"
        )
    if counts["ack_window_expirations"] != counts["retransmissions"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics ACK-window expiration count is inconsistent"
        )
    if counts["duplicate_or_stale_acks"] > counts["retransmissions"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics duplicate/stale ACK count is inconsistent"
        )
    maximum_retransmissions = (
        counts["total_unique_datagrams"]
        * recipe["max_retransmissions_per_sequence"]
    )
    if counts["retransmissions"] > maximum_retransmissions:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics exceeded the per-sequence retry bound"
        )
    retry_budget = max(
        recipe["minimum_retry_budget"],
        (
            counts["total_unique_datagrams"]
            + recipe["retry_budget_unique_datagrams"]
            - 1
        )
        // recipe["retry_budget_unique_datagrams"],
    )
    if counts["retry_budget"] != retry_budget:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retry budget is inconsistent"
        )
    if counts["retransmissions"] > counts["retry_budget"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retransmissions exceeded the retry budget"
        )

    packet_counters = value["packet_counter_deltas"]
    if type(packet_counters) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment packet counter deltas must be an object"
        )
    _exact_fields(
        packet_counters,
        WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS,
        "Windows TUN fragment packet counter deltas",
    )
    packet_counts = {
        field: _windows_tun_diagnostic_u64(
            packet_counters[field], f"packet_counter_deltas.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS
    }
    if packet_counts["background_packets"] != (
        packet_counts["background_family_disabled"]
        + packet_counts["background_invalid_destination"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment background packet accounting is inconsistent"
        )
    expected_fragment_packets = (
        counts["total_request_attempts"] * recipe["fragments_per_datagram"]
    )
    if packet_counts["accepted_packets"] != expected_fragment_packets:
        raise CandidateControlError(
            "Windows TUN fragment accepted-packet accounting is inconsistent"
        )
    if packet_counts["ingress_packets"] != (
        expected_fragment_packets + packet_counts["background_packets"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment ingress/background accounting is inconsistent"
        )

    adapter = value["adapter_counter_deltas"]
    if type(adapter) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment adapter counter deltas must be an object"
        )
    _exact_fields(
        adapter,
        WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS,
        "Windows TUN fragment adapter counter deltas",
    )
    adapter_counts = {
        field: _windows_tun_diagnostic_u64(
            adapter[field], f"adapter_counter_deltas.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS
    }
    for field in (
        "ReceivedDiscardedPackets",
        "ReceivedPacketErrors",
        "OutboundDiscardedPackets",
        "OutboundPacketErrors",
    ):
        if adapter_counts[field] != 0:
            raise CandidateControlError(
                f"Windows TUN fragment adapter counter {field} recorded packet loss"
            )
    if adapter_counts["SentUnicastPackets"] != packet_counts["ingress_packets"]:
        raise CandidateControlError(
            "Windows TUN fragment adapter sent-packet accounting is inconsistent"
        )
    if adapter_counts["ReceivedUnicastPackets"] < counts["total_unique_datagrams"]:
        raise CandidateControlError(
            "Windows TUN fragment adapter received-packet accounting is inconsistent"
        )


def validate_windows_tun_trial(
    row: object,
    *,
    plan: dict[str, object],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[str, int, str]:
    if type(row) is not dict:
        raise CandidateControlError("Windows TUN trial must be a JSON object")
    _exact_fields(row, WINDOWS_TUN_TRIAL_FIELDS, "Windows TUN trial")
    if (
        type(row["schema_version"]) is not int
        or row["schema_version"] != WINDOWS_TUN_TRIAL_SCHEMA_VERSION
        or row["kind"] != "windows_tun_performance_trial"
    ):
        raise CandidateControlError("Windows TUN trial schema is unsupported")
    for field in ("selection", "run_kind", "recipe_sha256"):
        if row[field] != plan[field]:
            raise CandidateControlError(f"Windows TUN trial {field} does not match plan")
    if row["parent_sha"] != parent_sha or row["candidate_sha"] != candidate_sha:
        raise CandidateControlError("Windows TUN trial comparison identity mismatch")
    scenario = row["scenario"]
    if type(scenario) is not str or scenario not in WINDOWS_TUN_SCENARIOS:
        raise CandidateControlError("Windows TUN trial scenario is not planned")
    pair = row["pair"]
    member = row["member"]
    order = row["order"]
    if (
        type(pair) is not int
        or not 1 <= pair <= WINDOWS_TUN_PAIR_COUNT
        or member not in {"parent", "candidate"}
        or type(order) is not int
        or order not in {1, 2}
    ):
        raise CandidateControlError("Windows TUN trial pair/member/order is invalid")
    expected_order = 1 if (member == "parent") == (pair % 2 == 1) else 2
    if order != expected_order:
        raise CandidateControlError(
            "Windows TUN trial does not follow alternating parent/candidate order"
        )
    expected_sequence = (
        list(WINDOWS_TUN_SCENARIOS).index(scenario) * WINDOWS_TUN_PAIR_COUNT * 2
        + (pair - 1) * 2
        + order
    )
    if type(row["sequence"]) is not int or row["sequence"] != expected_sequence:
        raise CandidateControlError("Windows TUN trial sequence does not match the plan")
    _validate_windows_tun_network_model_reference(
        row["network_model_evidence"],
        scenario=scenario,
        sequence=expected_sequence,
        member=member,
        pair=pair,
    )
    started = _windows_tun_utc(row["started_utc"], "started_utc")
    finished = _windows_tun_utc(row["finished_utc"], "finished_utc")
    if finished <= started:
        raise CandidateControlError("Windows TUN trial finish must follow its start")
    _windows_tun_required_digest(row, "parent_sha", length=40)
    _windows_tun_required_digest(row, "candidate_sha", length=40)
    expected_sha = parent_sha if member == "parent" else candidate_sha
    if _windows_tun_required_digest(row, "sha", length=40) != expected_sha:
        raise CandidateControlError("Windows TUN trial member SHA mismatch")
    _windows_tun_required_digest(row, "tree", length=40)
    for field in (
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "recipe_sha256",
    ):
        _windows_tun_required_digest(row, field, length=64)
    _validate_windows_tun_environment(row["environment"])
    contract = WINDOWS_TUN_SCENARIOS[scenario]
    measurements = row["measurements"]
    if type(measurements) is not dict or set(measurements) != set(contract["metrics"]):
        raise CandidateControlError(
            f"Windows TUN trial {scenario} measurements are incomplete"
        )
    for metric, metric_contract in contract["metrics"].items():
        measurement = measurements[metric]
        if type(measurement) is not dict:
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} must be an object"
            )
        _exact_fields(
            measurement,
            WINDOWS_TUN_MEASUREMENT_FIELDS,
            f"Windows TUN measurement {scenario}/{metric}",
        )
        if measurement["unit"] != metric_contract["unit"]:
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} unit mismatch"
            )
        if (
            type(measurement["value"]) is not int
            or measurement["value"] <= 0
            or measurement["value"] > U64_MAX
        ):
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} must be a positive u64"
            )
    correctness = row["correctness"]
    if type(correctness) is not dict:
        raise CandidateControlError("Windows TUN correctness must be an object")
    _exact_fields(correctness, WINDOWS_TUN_CORRECTNESS_FIELDS, "Windows TUN correctness")
    if correctness["status"] != "PASS":
        raise CandidateControlError("Windows TUN trial correctness did not pass")
    if correctness["checked_unit"] != contract["checked_unit"]:
        raise CandidateControlError("Windows TUN correctness unit mismatch")
    if (
        type(correctness["checked_units"]) is not int
        or correctness["checked_units"] < contract["minimum_checked_units"]
        or correctness["checked_units"] > U64_MAX
    ):
        raise CandidateControlError("Windows TUN correctness coverage is insufficient")
    checks = correctness["checks"]
    expected_checks = set(contract["correctness_checks"])
    if type(checks) is not dict or set(checks) != expected_checks:
        raise CandidateControlError("Windows TUN correctness checks are incomplete")
    if any(value is not True for value in checks.values()):
        raise CandidateControlError("Windows TUN correctness check failed")
    _validate_windows_tun_diagnostics(
        row["diagnostics"],
        scenario=scenario,
        contract=contract,
        checked_units=correctness["checked_units"],
    )
    if row["status"] != "PASS":
        raise CandidateControlError("Windows TUN trial status did not pass")
    return scenario, pair, member


def _network_model_trial_values(summary: dict[str, object]) -> dict[str, int]:
    reset = summary["latency_nanoseconds"]["reset_network"]
    rebuild = summary["latency_nanoseconds"]["full_rebuild"]
    return {
        "reset_p50": reset["p50"],
        "reset_p95": reset["p95"],
        "reset_p99": reset["p99"],
        "full_rebuild_p50": rebuild["p50"],
        "full_rebuild_p95": rebuild["p95"],
        "full_rebuild_p99": rebuild["p99"],
        "interface_switch_recovery": summary[
            "interface_switch_recovery_nanoseconds"
        ],
        "interface_resolver_cache_hit": summary["interface_resolver"][
            "cache_hits_per_million_resolutions"
        ],
    }


def _route_once_trial_values(summary: dict[str, object]) -> dict[str, int]:
    return {
        "multi_target_packet_rate": summary["packets_per_second"],
        "association_creation_rate": summary["associations_per_second"],
        "router_invocations_avoided": summary["router_invocations_avoided"],
    }


def _validate_windows_tun_network_model_sidecars(
    *, evidence_root: pathlib.Path, rows: dict[tuple[str, int, str], dict[str, object]]
) -> list[dict[str, object]]:
    model_root = evidence_root / "network-model"
    if not model_root.is_dir() or model_root.is_symlink():
        raise CandidateControlError("Windows TUN network-model evidence directory is missing")
    model_scenarios = ("udp-route-once", "network-lifecycle")
    expected_files = {
        rows[(scenario, pair, member)]["network_model_evidence"]["observation_file"]
        for scenario in model_scenarios
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1)
        for member in ("parent", "candidate")
    }
    try:
        actual_paths = list(model_root.iterdir())
    except OSError as error:
        raise CandidateControlError(
            "unable to enumerate Windows TUN network-model evidence"
        ) from error
    if (
        any(not path.is_file() or path.is_symlink() for path in actual_paths)
        or {path.name for path in actual_paths} != expected_files
    ):
        raise CandidateControlError(
            "Windows TUN network-model evidence set is incomplete or contains extras"
        )
    evidence_files: list[dict[str, object]] = []
    for scenario in model_scenarios:
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
            for member in ("parent", "candidate"):
                row = rows[(scenario, pair, member)]
                reference = row["network_model_evidence"]
                path = model_root / reference["observation_file"]
                try:
                    raw = path.read_bytes()
                except OSError as error:
                    raise CandidateControlError(
                        "unable to read Windows TUN network-model observation"
                    ) from error
                if hashlib.sha256(raw).hexdigest() != reference["observation_sha256"]:
                    raise CandidateControlError(
                        "Windows TUN network-model observation identity mismatch"
                    )
                evidence_files.append(
                    {
                        "sequence": row["sequence"],
                        "file": f"network-model/{path.name}",
                        "sha256": reference["observation_sha256"],
                    }
                )
                try:
                    observation = WINDOWS_TUN_NETWORK_MODEL.load_observation(path)
                    summary = WINDOWS_TUN_NETWORK_MODEL.summarize_observation(observation)
                except WINDOWS_TUN_NETWORK_MODEL.NetworkModelError as error:
                    raise CandidateControlError(
                        f"invalid Windows TUN network-model observation: {error}"
                    ) from error
                identity = summary["identity"]
                expected_identity = {
                    "run_kind": row["run_kind"],
                    "member": row["member"],
                    "pair": row["pair"],
                    "trial_sequence": row["sequence"],
                    "vm_name": row["environment"]["vm_name"],
                    "vm_id": row["environment"]["vm_id"],
                    "checkpoint_name": row["environment"]["checkpoint_name"],
                    "checkpoint_id": row["environment"]["checkpoint_id"],
                    "sha": row["sha"],
                    "tree": row["tree"],
                    "client_sha256": row["client_sha256"],
                    "server_sha256": row["server_sha256"],
                    "harness_sha256": row["harness_sha256"],
                    "collector_sha256": reference["collector_sha256"],
                    "recipe_sha256": row["recipe_sha256"],
                    "model_controller_sha256": reference["controller_sha256"],
                    "model_plan_sha256": reference["plan_sha256"],
                }
                if any(identity[field] != value for field, value in expected_identity.items()):
                    raise CandidateControlError(
                        "Windows TUN network-model observation is not bound to its trial"
                    )
                measured = {
                    metric: entry["value"] for metric, entry in row["measurements"].items()
                }
                if scenario == "udp-route-once":
                    if measured != _route_once_trial_values(summary):
                        raise CandidateControlError(
                            "Windows TUN route-once measurements were not recomputed from raw evidence"
                        )
                    expected_checks = {
                        "every_reply_accounted": True,
                        "payload_exact": True,
                        "direct_and_proxy_sources": summary["direct_and_proxy_verified"],
                        "association_creation_counter_exact": True,
                        "router_invocation_counter_exact": summary["route_once_verified"],
                        "post_reset_reroute_verified": summary["post_reset_reroute_verified"],
                        "network_model_evidence_bound": True,
                        "tun_path_observed": True,
                        "clean_drain": True,
                    }
                    if row["correctness"]["checked_units"] != summary["datagrams_sent"]:
                        raise CandidateControlError(
                            "Windows TUN route-once checked units were not derived from raw evidence"
                        )
                else:
                    if measured != _network_model_trial_values(summary):
                        raise CandidateControlError(
                            "Windows TUN lifecycle measurements were not recomputed from raw evidence"
                        )
                    reset_growth = summary["resources"]["reset_network"]["growth"]
                    expected_checks = {
                        "same_process_all_cycles": True,
                        "generation_advanced_once_per_cycle": True,
                        "managed_identity_preserved_across_resets": summary[
                            "managed_identity_preserved_across_resets"
                        ],
                        "damage_only_full_rebuild": summary["damage_only_full_rebuild"],
                        "reset_and_full_rebuild_metrics_are_exact": summary[
                            "reset_and_full_rebuild_metrics_are_exact"
                        ],
                        "resource_growth_zero_after_1000_resets": all(
                            value <= 0 for value in reset_growth.values()
                        ),
                        "tcp_and_udp_recovered_after_interface_switch": summary[
                            "tcp_and_udp_recovered_each_cycle"
                        ],
                        "interface_resolver_cache_hit_observed": summary[
                            "interface_resolver"
                        ]["cache_hits"]
                        > 0,
                        "network_model_evidence_bound": True,
                        "tun_path_observed": True,
                        "clean_drain": True,
                    }
                if row["correctness"]["checks"] != expected_checks:
                    raise CandidateControlError(
                        f"Windows TUN {scenario} correctness was not derived from raw evidence"
                    )
    return evidence_files


def _read_windows_tun_rows(
    *,
    evidence_root: pathlib.Path,
    plan: dict[str, object],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[
    dict[tuple[str, int, str], dict[str, object]],
    list[dict[str, object]],
    dict[str, tuple[object, ...]],
    dict[str, object],
]:
    try:
        paths = sorted(evidence_root.glob("*.json"))
    except OSError as error:
        raise CandidateControlError("unable to enumerate Windows TUN evidence") from error
    expected_count = len(WINDOWS_TUN_SCENARIOS) * WINDOWS_TUN_PAIR_COUNT * 2
    if len(paths) != expected_count:
        raise CandidateControlError(
            f"Windows TUN evidence requires exactly {expected_count} trial files"
        )
    rows: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, object]] = []
    member_identity: dict[str, tuple[object, ...]] = {}
    environment_identity: dict[str, object] | None = None
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise CandidateControlError("unable to read Windows TUN evidence") from error
        if len(raw) > WINDOWS_TUN_TRIAL_MAX_BYTES:
            raise CandidateControlError("Windows TUN trial exceeds the size bound")
        try:
            row = _strict_json(raw.decode("utf-8"), source=f"Windows TUN trial {path.name}")
        except UnicodeError as error:
            raise CandidateControlError("Windows TUN evidence must be UTF-8") from error
        scenario, pair, member = validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
        )
        key = (scenario, pair, member)
        if key in rows:
            raise CandidateControlError(
                f"duplicate Windows TUN evidence for {scenario}/{pair}/{member}"
            )
        rows[key] = row
        identity = tuple(
            row[field]
            for field in ("sha", "tree", "client_sha256", "server_sha256")
        )
        if member in member_identity and member_identity[member] != identity:
            raise CandidateControlError(
                f"Windows TUN {member} build identity changed between trials"
            )
        member_identity[member] = identity
        if environment_identity is None:
            environment_identity = row["environment"]
        elif environment_identity != row["environment"]:
            raise CandidateControlError(
                "Windows TUN guest environment changed between trials"
            )
        evidence_files.append(
            {
                "sequence": row["sequence"],
                "file": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    expected_keys = {
        (scenario, pair, member)
        for scenario in WINDOWS_TUN_SCENARIOS
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1)
        for member in ("parent", "candidate")
    }
    if set(rows) != expected_keys:
        raise CandidateControlError("Windows TUN evidence set is incomplete")
    if environment_identity is None:
        raise CandidateControlError("Windows TUN evidence environment is missing")
    ordered_rows = sorted(rows.values(), key=lambda row: row["sequence"])
    if [row["sequence"] for row in ordered_rows] != list(
        range(1, expected_count + 1)
    ):
        raise CandidateControlError("Windows TUN evidence sequence is incomplete")
    for previous, current in zip(ordered_rows, ordered_rows[1:], strict=False):
        if _windows_tun_utc(
            current["started_utc"], "started_utc"
        ) < _windows_tun_utc(previous["finished_utc"], "finished_utc"):
            raise CandidateControlError(
                "Windows TUN trials overlap or were not executed in planned order"
            )
    if plan["run_kind"] == "calibration-aa":
        if parent_sha != candidate_sha:
            raise CandidateControlError("Windows TUN A/A requires identical commit SHAs")
        if member_identity["parent"] != member_identity["candidate"]:
            raise CandidateControlError("Windows TUN A/A requires identical binary identities")
    elif parent_sha == candidate_sha:
        raise CandidateControlError("Windows TUN comparison requires distinct commits")
    harness_hashes = {row["harness_sha256"] for row in rows.values()}
    if len(harness_hashes) != 1:
        raise CandidateControlError("Windows TUN harness identity changed between trials")
    evidence_files.extend(
        _validate_windows_tun_network_model_sidecars(
            evidence_root=evidence_root, rows=rows
        )
    )
    evidence_files.sort(key=lambda entry: (entry["sequence"], entry["file"]))
    return rows, evidence_files, member_identity, environment_identity


def _windows_tun_policy_environment(
    environment: dict[str, object], *, recipe_sha256: str
) -> dict[str, object]:
    return {
        **environment,
        "recipe_sha256": recipe_sha256,
    }


def _windows_tun_metric_decision(
    *,
    entry: dict[str, object],
    observed_environment: dict[str, object],
    improvements: Sequence[Decimal],
) -> dict[str, object]:
    median = _median(improvements)
    wins = sum(value > 0 for value in improvements)
    losses = sum(value < 0 for value in improvements)
    common = {
        "noise_band_percent": entry["noise_band_percent"],
        "regression_threshold_percent": entry["regression_threshold_percent"],
        "adoption_threshold_percent": entry["adoption_threshold_percent"],
        "minimum_pairs": entry["minimum_pairs"],
        "minimum_wins": entry["minimum_wins"],
        "minimum_losses": entry["minimum_losses"],
        "calibration_source": entry["calibration_source"],
        "calibration_artifact_sha256": entry["calibration_artifact_sha256"],
    }
    if entry["calibration_environment"] is None:
        return {
            **common,
            "decision_enabled": False,
            "threshold_decision": "NO_CALIBRATION",
            "status": "CALIBRATION_REQUIRED",
        }
    if entry["calibration_environment"] != observed_environment:
        return {
            **common,
            "decision_enabled": False,
            "threshold_decision": "CALIBRATION_ENVIRONMENT_MISMATCH",
            "status": "CALIBRATION_REQUIRED",
        }
    regression = _policy_percent(
        entry["regression_threshold_percent"], "regression_threshold_percent"
    )
    adoption = _policy_percent(
        entry["adoption_threshold_percent"], "adoption_threshold_percent"
    )
    if median <= regression:
        if losses >= entry["minimum_losses"]:
            return {
                **common,
                "decision_enabled": True,
                "threshold_decision": "CONFIRMED_REGRESSION",
                "status": "REGRESSION",
            }
        return {
            **common,
            "decision_enabled": True,
            "threshold_decision": "REGRESSION_WITHOUT_CONFIRMING_LOSSES",
            "status": "INCONCLUSIVE",
        }
    if median >= adoption and wins >= entry["minimum_wins"]:
        return {
            **common,
            "decision_enabled": True,
            "threshold_decision": "CONFIRMED_IMPROVEMENT",
            "status": "CANDIDATE_WIN",
        }
    return {
        **common,
        "decision_enabled": True,
        "threshold_decision": "NO_REGRESSION",
        "status": "NO_REGRESSION",
    }


def summarize_windows_tun_evidence(
    *,
    plan: dict[str, object],
    evidence_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    _windows_tun_required_digest({"sha": parent_sha}, "sha", length=40)
    _windows_tun_required_digest({"sha": candidate_sha}, "sha", length=40)
    rows, evidence_files, member_identity, environment = _read_windows_tun_rows(
        evidence_root=evidence_root,
        plan=plan,
        parent_sha=parent_sha,
        candidate_sha=candidate_sha,
    )
    policy_environment = _windows_tun_policy_environment(
        environment, recipe_sha256=plan["recipe_sha256"]
    )
    scenario_summaries: list[dict[str, object]] = []
    flat_metric_summaries: list[dict[str, object]] = []
    for scenario, contract in WINDOWS_TUN_SCENARIOS.items():
        metric_summaries: list[dict[str, object]] = []
        for metric, metric_contract in contract["metrics"].items():
            pair_summaries: list[dict[str, object]] = []
            improvements: list[Decimal] = []
            for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
                parent = rows[(scenario, pair, "parent")]
                candidate = rows[(scenario, pair, "candidate")]
                parent_value = parent["measurements"][metric]["value"]
                candidate_value = candidate["measurements"][metric]["value"]
                improvement = _improvement(
                    parent_value, candidate_value, metric_contract["direction"]
                )
                improvements.append(improvement)
                pair_summaries.append(
                    {
                        "pair": pair,
                        "parent_order": parent["order"],
                        "candidate_order": candidate["order"],
                        "parent_value": parent_value,
                        "candidate_value": candidate_value,
                        "improvement_percent": _display_decimal(improvement),
                    }
                )
            wins = sum(value > 0 for value in improvements)
            losses = sum(value < 0 for value in improvements)
            ties = len(improvements) - wins - losses
            policy_entry = plan["decision_policy"]["scenarios"][scenario][
                "metrics"
            ][metric]
            spread, warnings = _stability_warnings(
                improvements, noise_band=policy_entry["noise_band_percent"]
            )
            if plan["run_kind"] == "calibration-aa":
                decision = {
                    "noise_band_percent": None,
                    "regression_threshold_percent": None,
                    "adoption_threshold_percent": None,
                    "minimum_pairs": None,
                    "minimum_wins": None,
                    "minimum_losses": None,
                    "calibration_source": None,
                    "calibration_artifact_sha256": None,
                    "decision_enabled": False,
                    "threshold_decision": "A_A_OBSERVATION_ONLY",
                    "status": "MEASURED",
                }
            else:
                decision = _windows_tun_metric_decision(
                    entry=policy_entry,
                    observed_environment=policy_environment,
                    improvements=improvements,
                )
            metric_summary = {
                "scenario": scenario,
                "metric": metric,
                "unit": metric_contract["unit"],
                "direction": metric_contract["direction"],
                "pairs": pair_summaries,
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "median_improvement_percent": _display_decimal(
                    _median(improvements)
                ),
                "minimum_improvement_percent": _display_decimal(min(improvements)),
                "maximum_improvement_percent": _display_decimal(max(improvements)),
                "spread_percent": _display_decimal(spread),
                "warnings": warnings,
                **decision,
            }
            metric_summaries.append(metric_summary)
            flat_metric_summaries.append(metric_summary)
        scenario_statuses = {metric["status"] for metric in metric_summaries}
        if "REGRESSION" in scenario_statuses:
            scenario_status = "REGRESSION"
        elif "CALIBRATION_REQUIRED" in scenario_statuses:
            scenario_status = "CALIBRATION_REQUIRED"
        elif "INCONCLUSIVE" in scenario_statuses:
            scenario_status = "INCONCLUSIVE"
        elif plan["run_kind"] == "calibration-aa":
            scenario_status = "MEASURED"
        else:
            scenario_status = "NO_REGRESSION"
        scenario_summaries.append(
            {
                "scenario": scenario,
                "recipe": windows_tun_scenario_contracts()[scenario]["recipe"],
                "checked_unit": contract["checked_unit"],
                "minimum_checked_units": contract["minimum_checked_units"],
                "status": scenario_status,
                "metrics": metric_summaries,
            }
        )
    if plan["run_kind"] == "calibration-aa":
        status = "CALIBRATION_EVIDENCE"
        decision_reason = (
            "A/A evidence is measurement-only and must be reviewed into a separate policy"
        )
        adoption_eligible = False
    elif any(metric["status"] == "REGRESSION" for metric in flat_metric_summaries):
        status = "REGRESSION"
        decision_reason = "at least one calibrated Windows TUN metric regressed"
        adoption_eligible = False
    elif any(
        metric["status"] == "CALIBRATION_REQUIRED"
        for metric in flat_metric_summaries
    ):
        status = "CALIBRATION_REQUIRED"
        decision_reason = (
            "reviewed thresholds, artifact identity, or exact guest calibration are unavailable"
        )
        adoption_eligible = False
    elif any(metric["status"] == "INCONCLUSIVE" for metric in flat_metric_summaries):
        status = "INCONCLUSIVE"
        decision_reason = "a threshold crossing lacks the required confirming pair count"
        adoption_eligible = False
    else:
        status = "NO_REGRESSION"
        decision_reason = "all calibrated metrics remain above their regression thresholds"
        adoption_eligible = True
    identity_fields = ("sha", "tree", "client_sha256", "server_sha256")
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    return {
        "schema_version": WINDOWS_TUN_SUMMARY_SCHEMA_VERSION,
        "kind": "windows_tun_performance_summary",
        "selection": WINDOWS_TUN_SELECTION,
        "run_kind": plan["run_kind"],
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "pairs": WINDOWS_TUN_PAIR_COUNT,
        "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
        "recipe_sha256": plan["recipe_sha256"],
        "network_model": {
            "schema_version": WINDOWS_TUN_NETWORK_MODEL.SCHEMA_VERSION,
            "controller_sha256": WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256,
            "plan_sha256": WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256,
            "raw_observations": WINDOWS_TUN_PAIR_COUNT * 2 * 2,
        },
        "decision_policy": plan["decision_policy"],
        "calibration_complete": plan["calibration_complete"],
        "environment": environment,
        "build_identities": build_identities,
        "correctness_complete": True,
        "adoption_eligible": adoption_eligible,
        "performance_improvement_claim": adoption_eligible
        and all(metric["status"] == "CANDIDATE_WIN" for metric in flat_metric_summaries),
        "status": status,
        "decision_reason": decision_reason,
        "mandatory_scenarios": list(WINDOWS_TUN_SCENARIOS),
        "scenarios": scenario_summaries,
        "evidence_files": evidence_files,
    }


def windows_tun_calibration_artifact(
    summary: dict[str, object],
) -> dict[str, object]:
    if (
        summary.get("kind") != "windows_tun_performance_summary"
        or summary.get("run_kind") != "calibration-aa"
        or summary.get("status") != "CALIBRATION_EVIDENCE"
        or summary.get("adoption_eligible") is not False
    ):
        raise CandidateControlError(
            "Windows TUN calibration artifact requires valid A/A evidence"
        )
    observations: dict[str, object] = {}
    for scenario in summary["scenarios"]:
        metric_observations: dict[str, object] = {}
        for metric in scenario["metrics"]:
            absolute = [
                abs(Decimal(str(pair["improvement_percent"])))
                for pair in metric["pairs"]
            ]
            metric_observations[metric["metric"]] = {
                "unit": metric["unit"],
                "direction": metric["direction"],
                "paired_improvement_percent": [
                    pair["improvement_percent"] for pair in metric["pairs"]
                ],
                "median_improvement_percent": metric[
                    "median_improvement_percent"
                ],
                "median_absolute_improvement_percent": _display_decimal(
                    _median(absolute)
                ),
                "maximum_absolute_improvement_percent": _display_decimal(max(absolute)),
                "spread_percent": metric["spread_percent"],
            }
        observations[scenario["scenario"]] = {"metrics": metric_observations}
    artifact = {
        "schema_version": WINDOWS_TUN_CALIBRATION_SCHEMA_VERSION,
        "kind": "windows_tun_performance_aa_calibration",
        "selection": WINDOWS_TUN_SELECTION,
        "source_summary_schema_version": summary["schema_version"],
        "recipe_sha256": summary["recipe_sha256"],
        "network_model": summary["network_model"],
        "pairs": summary["pairs"],
        "pair_schedule": summary["pair_schedule"],
        "aa_sha": summary["parent_sha"],
        "build_identity": summary["build_identities"]["parent"],
        "environment": _windows_tun_policy_environment(
            summary["environment"], recipe_sha256=summary["recipe_sha256"]
        ),
        "evidence_files": summary["evidence_files"],
        "observations": observations,
        "adoption_eligible": False,
        "thresholds_reviewed": False,
        "policy_action": (
            "review repeated A/A artifacts, choose thresholds outside measured noise, "
            "then bind the reviewed artifact SHA-256 in the policy"
        ),
    }
    return {
        **artifact,
        "content_sha256": hashlib.sha256(_canonical_json_bytes(artifact)).hexdigest(),
    }


def windows_tun_summary_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Windows TUN paired performance",
        "",
        f"- Status: **{summary['status']}**",
        f"- Run kind: `{summary['run_kind']}`",
        f"- Recipe SHA-256: `{summary['recipe_sha256']}`",
        f"- Network-model plan SHA-256: `{summary['network_model']['plan_sha256']}`",
        f"- Adoption eligible: `{str(summary['adoption_eligible']).lower()}`",
        f"- Decision: {summary['decision_reason']}",
        "- Correctness and units are mandatory for every trial; GSO is disabled by recipe.",
        "",
    ]
    if summary["status"] == "INVALID_EVIDENCE":
        lines.append(f"- Error: {summary['error']}")
        lines.append("")
        return "\n".join(lines)
    lines.extend(
        [
            "| Scenario | Metric | Unit | Median % | Wins | Losses | Decision |",
            "|---|---|---|---:|---:|---:|---|",
        ]
    )
    for scenario in summary["scenarios"]:
        for metric in scenario["metrics"]:
            lines.append(
                f"| {scenario['scenario']} | {metric['metric']} | {metric['unit']} | "
                f"{metric['median_improvement_percent']:.6f} | {metric['wins']} | "
                f"{metric['losses']} | {metric['threshold_decision']} |"
            )
    lines.append("")
    return "\n".join(lines)


def _write_windows_tun_outputs(
    summary: dict[str, object], *, output: pathlib.Path, markdown: pathlib.Path
) -> None:
    _atomic_text(
        output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(markdown, windows_tun_summary_markdown(summary))


def run_windows_tun_summary_command(parsed: argparse.Namespace) -> int:
    plan: dict[str, object] | None = None
    try:
        policy = load_windows_tun_policy(parsed.policy)
        plan = load_windows_tun_plan(parsed.plan, decision_policy=policy)
        if plan["run_kind"] == "calibration-aa" and parsed.calibration_output is None:
            raise CandidateControlError(
                "Windows TUN A/A requires --calibration-output"
            )
        if plan["run_kind"] == "comparison" and parsed.calibration_output is not None:
            raise CandidateControlError(
                "Windows TUN comparison cannot write a calibration artifact"
            )
        summary = summarize_windows_tun_evidence(
            plan=plan,
            evidence_root=parsed.evidence_root,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
        )
        if parsed.calibration_output is not None:
            calibration = windows_tun_calibration_artifact(summary)
            _atomic_text(
                parsed.calibration_output,
                json.dumps(calibration, sort_keys=True, indent=2, allow_nan=False)
                + "\n",
            )
    except CandidateControlError as error:
        summary = {
            "schema_version": WINDOWS_TUN_SUMMARY_SCHEMA_VERSION,
            "kind": "windows_tun_performance_summary",
            "selection": WINDOWS_TUN_SELECTION,
            "run_kind": None if plan is None else plan["run_kind"],
            "parent_sha": parsed.parent_sha,
            "candidate_sha": parsed.candidate_sha,
            "recipe_sha256": None if plan is None else plan["recipe_sha256"],
            "network_model": {
                "schema_version": WINDOWS_TUN_NETWORK_MODEL.SCHEMA_VERSION,
                "controller_sha256": WINDOWS_TUN_NETWORK_MODEL_CONTROLLER_SHA256,
                "plan_sha256": WINDOWS_TUN_NETWORK_MODEL_PLAN_SHA256,
                "raw_observations": 0,
            },
            "adoption_eligible": False,
            "correctness_complete": False,
            "status": "INVALID_EVIDENCE",
            "decision_reason": "invalid or incomplete Windows TUN evidence",
            "error": str(error),
        }
        _write_windows_tun_outputs(
            summary, output=parsed.output, markdown=parsed.markdown
        )
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
    _write_windows_tun_outputs(summary, output=parsed.output, markdown=parsed.markdown)
    if summary["status"] in {"CALIBRATION_EVIDENCE", "NO_REGRESSION"}:
        return 0
    if summary["status"] == "REGRESSION":
        print(
            "performance-candidate: calibrated Windows TUN regression",
            file=sys.stderr,
        )
        return 3
    print(
        "performance-candidate: Windows TUN adoption is not eligible without "
        "applicable reviewed calibration",
        file=sys.stderr,
    )
    return 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-inputs", help="validate bounded workflow measurement inputs"
    )
    validate.add_argument("--warmup-seconds", required=True)
    validate.add_argument("--active-seconds", required=True)
    validate.add_argument("--pairs", required=True)
    relation = commands.add_parser(
        "validate-git", help="validate strict parent-to-candidate ancestry"
    )
    relation.add_argument("--repository", required=True, type=pathlib.Path)
    relation.add_argument("--parent-sha", required=True)
    relation.add_argument("--candidate-sha", required=True)
    plan = commands.add_parser("plan", help="write a canonical scenario plan")
    plan.add_argument("--mode", required=True)
    plan.add_argument("--selection", required=True)
    plan.add_argument("--warmup-seconds", required=True)
    plan.add_argument("--active-seconds", required=True)
    plan.add_argument("--pairs", required=True)
    plan.add_argument("--policy", required=True, type=pathlib.Path)
    plan.add_argument("--scale-policy", type=pathlib.Path)
    plan.add_argument("--scale-lineage", type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    scenarios = commands.add_parser(
        "scenarios", help="emit planned scenario names, one per line"
    )
    scenarios.add_argument("--plan", required=True, type=pathlib.Path)
    scenarios.add_argument("--policy", required=True, type=pathlib.Path)
    scenarios.add_argument("--scale-policy", type=pathlib.Path)
    summary = commands.add_parser(
        "summarize", help="validate paired evidence and write machine/human summaries"
    )
    summary.add_argument("--plan", required=True, type=pathlib.Path)
    summary.add_argument("--parent-root", required=True, type=pathlib.Path)
    summary.add_argument("--candidate-root", required=True, type=pathlib.Path)
    summary.add_argument("--parent-sha", required=True)
    summary.add_argument("--candidate-sha", required=True)
    summary.add_argument("--policy", required=True, type=pathlib.Path)
    summary.add_argument("--scale-policy", type=pathlib.Path)
    summary.add_argument("--repository", type=pathlib.Path)
    summary.add_argument("--output", required=True, type=pathlib.Path)
    summary.add_argument("--markdown", required=True, type=pathlib.Path)
    lineage = commands.add_parser(
        "scale-lineage", help="verify and bind H -> P16 -> C32 scale lineage"
    )
    lineage.add_argument("--repository", required=True, type=pathlib.Path)
    lineage.add_argument("--head-sha", required=True)
    lineage.add_argument("--parent-sha", required=True)
    lineage.add_argument("--candidate-sha", required=True)
    lineage.add_argument("--runner", required=True, type=pathlib.Path)
    lineage.add_argument("--parent-client", required=True, type=pathlib.Path)
    lineage.add_argument("--parent-server", required=True, type=pathlib.Path)
    lineage.add_argument("--candidate-client", required=True, type=pathlib.Path)
    lineage.add_argument("--candidate-server", required=True, type=pathlib.Path)
    lineage.add_argument("--output", required=True, type=pathlib.Path)
    source_lineage = commands.add_parser(
        "scale-source-lineage",
        help="verify exact H -> P16 -> C32 source lineage before compilation",
    )
    source_lineage.add_argument("--repository", required=True, type=pathlib.Path)
    source_lineage.add_argument("--head-sha", required=True)
    source_lineage.add_argument("--parent-sha", required=True)
    source_lineage.add_argument("--candidate-sha", required=True)
    windows_tun_plan = commands.add_parser(
        "windows-tun-plan",
        help="write the fixed nine-scenario Windows TUN paired plan",
    )
    windows_tun_plan.add_argument(
        "--run-kind", required=True, choices=sorted(WINDOWS_TUN_RUN_KINDS)
    )
    windows_tun_plan.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_plan.add_argument("--output", required=True, type=pathlib.Path)
    windows_tun_trials = commands.add_parser(
        "windows-tun-trials",
        help="emit scenario/member/pair/order rows from a canonical Windows TUN plan",
    )
    windows_tun_trials.add_argument("--plan", required=True, type=pathlib.Path)
    windows_tun_trials.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_validate_trial = commands.add_parser(
        "windows-tun-validate-trial",
        help="validate one raw approved-guest Windows TUN trial",
    )
    windows_tun_validate_trial.add_argument(
        "--plan", required=True, type=pathlib.Path
    )
    windows_tun_validate_trial.add_argument(
        "--trial", required=True, type=pathlib.Path
    )
    windows_tun_validate_trial.add_argument("--parent-sha", required=True)
    windows_tun_validate_trial.add_argument("--candidate-sha", required=True)
    windows_tun_validate_trial.add_argument(
        "--policy", required=True, type=pathlib.Path
    )
    windows_tun_summary = commands.add_parser(
        "windows-tun-summarize",
        help="validate and summarize paired Windows TUN evidence",
    )
    windows_tun_summary.add_argument("--plan", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument(
        "--evidence-root", required=True, type=pathlib.Path
    )
    windows_tun_summary.add_argument("--parent-sha", required=True)
    windows_tun_summary.add_argument("--candidate-sha", required=True)
    windows_tun_summary.add_argument("--policy", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument("--output", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument("--markdown", required=True, type=pathlib.Path)
    windows_tun_summary.add_argument(
        "--calibration-output", type=pathlib.Path
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    if parsed.command == "summarize":
        return run_summary_command(parsed)
    if parsed.command == "windows-tun-summarize":
        return run_windows_tun_summary_command(parsed)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        if parsed.command == "plan":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            scale_lineage = (
                None
                if parsed.scale_lineage is None
                else load_scale_lineage(parsed.scale_lineage)
            )
            plan = create_plan(
                mode=parsed.mode,
                selection=parsed.selection,
                warmup_seconds=parsed.warmup_seconds,
                active_seconds=parsed.active_seconds,
                pairs=parsed.pairs,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
                scale_lineage=scale_lineage,
            )
            write_plan(parsed.output, plan)
            return 0
        if parsed.command == "scenarios":
            decision_policy = load_decision_policy(parsed.policy)
            scale_policy = (
                None
                if parsed.scale_policy is None
                else load_scale_safety_policy(parsed.scale_policy)
            )
            plan = load_plan(
                parsed.plan,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
            )
            for scenario in plan["scenarios"]:
                print(scenario["scenario"])
            return 0
        if parsed.command == "validate-git":
            validate_git_relation(
                parsed.repository, parsed.parent_sha, parsed.candidate_sha
            )
            return 0
        if parsed.command == "scale-lineage":
            lineage = build_scale_lineage(
                repository=parsed.repository,
                head_sha=parsed.head_sha,
                parent_sha=parsed.parent_sha,
                candidate_sha=parsed.candidate_sha,
                runner=parsed.runner,
                parent_client=parsed.parent_client,
                parent_server=parsed.parent_server,
                candidate_client=parsed.candidate_client,
                candidate_server=parsed.candidate_server,
            )
            _atomic_text(
                parsed.output,
                json.dumps(lineage, sort_keys=True, indent=2, allow_nan=False) + "\n",
            )
            return 0
        if parsed.command == "scale-source-lineage":
            validate_scale_source_lineage(
                parsed.repository,
                parsed.head_sha,
                parsed.parent_sha,
                parsed.candidate_sha,
            )
            return 0
        if parsed.command == "windows-tun-plan":
            policy = load_windows_tun_policy(parsed.policy)
            plan = create_windows_tun_plan(
                run_kind=parsed.run_kind, decision_policy=policy
            )
            _atomic_text(
                parsed.output,
                json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
            )
            return 0
        if parsed.command == "windows-tun-trials":
            policy = load_windows_tun_policy(parsed.policy)
            plan = load_windows_tun_plan(parsed.plan, decision_policy=policy)
            for trial in plan["trials"]:
                print(
                    "\t".join(
                        str(trial[field])
                        for field in (
                            "sequence",
                            "scenario",
                            "member",
                            "pair",
                            "order",
                        )
                    )
                )
            return 0
        if parsed.command == "windows-tun-validate-trial":
            policy = load_windows_tun_policy(parsed.policy)
            plan = load_windows_tun_plan(parsed.plan, decision_policy=policy)
            try:
                raw = parsed.trial.read_bytes()
            except OSError as error:
                raise CandidateControlError(
                    "unable to read Windows TUN trial"
                ) from error
            if len(raw) > WINDOWS_TUN_TRIAL_MAX_BYTES:
                raise CandidateControlError("Windows TUN trial exceeds the size bound")
            try:
                row = _strict_json(
                    raw.decode("utf-8"), source="Windows TUN trial"
                )
            except UnicodeError as error:
                raise CandidateControlError(
                    "Windows TUN trial must be UTF-8"
                ) from error
            scenario, pair, member = validate_windows_tun_trial(
                row,
                plan=plan,
                parent_sha=parsed.parent_sha,
                candidate_sha=parsed.candidate_sha,
            )
            print(f"{scenario}\t{member}\t{pair}\t{row['order']}")
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
