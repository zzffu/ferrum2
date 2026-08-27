"""Canonical Windows TUN recipe and source identity owner."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from functools import lru_cache

from tools.performance_candidate.json_contract import CandidateControlError, SHA256, _canonical_json_bytes, _exact_fields, _strict_json
from tools.performance_candidate.windows_tun import network_model, network_model_identity, network_model_lifecycle, network_model_route

WINDOWS_TUN_SELECTION = "windows-tun-m17"


WINDOWS_TUN_RUN_KINDS = frozenset({"comparison", "calibration-aa"})


WINDOWS_TUN_PAIR_COUNT = network_model_identity.PAIR_COUNT


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_STRATEGY = (
    "explicit_tun_ipv4_contiguous"
)


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4 = "198.18.0.2"


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PREFIX_LENGTH = 30


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST = 20_000


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST = 28_191


WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_COUNT = (
    WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
    - WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
    + 1
)


WINDOWS_TUN_RING_PRESSURE_MINIMUM_RESPONSE_ATTEMPTS = 32_768


WINDOWS_TUN_PAIR_SCHEDULE = "abba-six-pairs"


WINDOWS_TUN_GUEST = {
    "runner_os": "Windows",
    "runner_arch": "X64",
    "runner_label": "ferrum2-hyperv-guest",
    "vm_name": "Windows 10 MSIX packaging environment",
    "vm_id": "82e20295-1d30-48e7-a751-e21d35d872d4",
    "checkpoint_name": "Ferrum2-WindowsTun-InternalSupport-v1",
    "rust_toolchain": "1.97.1",
    "cargo_profile": "profiling",
    "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
}


WINDOWS_TUN_TOPOLOGY_ENVIRONMENT_FIELDS = frozenset(
    {
        "checkpoint_id",
        "topology_manifest_sha256",
        "topology_plan_sha256",
        "support_switch_id",
    }
)


WINDOWS_TUN_ENVIRONMENT_FIELDS = frozenset(
    {
        *WINDOWS_TUN_GUEST,
        *WINDOWS_TUN_TOPOLOGY_ENVIRONMENT_FIELDS,
        "guest_build",
        "cpu_model",
        "cpu_count",
        "memory_bytes",
        "power_plan_guid",
    }
)


def _validate_windows_tun_topology_environment(
    environment: dict[str, object], *, label: str
) -> None:
    guid = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    for field in ("checkpoint_id", "support_switch_id"):
        value = environment[field]
        if (
            type(value) is not str
            or guid.fullmatch(value) is None
            or value == "00000000-0000-0000-0000-000000000000"
        ):
            raise CandidateControlError(f"{label} {field} is invalid")
    for field in ("topology_manifest_sha256", "topology_plan_sha256"):
        value = environment[field]
        if type(value) is not str or SHA256.fullmatch(value) is None:
            raise CandidateControlError(f"{label} {field} is invalid")


def validate_environment(environment: object) -> dict[str, object]:
    if type(environment) is not dict:
        raise CandidateControlError("Windows TUN evidence environment must be an object")
    _exact_fields(environment, WINDOWS_TUN_ENVIRONMENT_FIELDS, "Windows TUN environment")
    for field, expected in WINDOWS_TUN_GUEST.items():
        if environment[field] != expected:
            raise CandidateControlError(
                f"Windows TUN evidence environment {field} is unsupported"
            )
    _validate_windows_tun_topology_environment(
        environment, label="Windows TUN evidence environment"
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


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[3]


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def network_model_bundle_path() -> pathlib.Path:
    return pathlib.Path(__file__).with_name("network_model_bundle.json")


def source_paths() -> dict[str, pathlib.Path]:
    root = repository_root()
    return {
        "runner": root
        / "tools"
        / "windows-tun"
        / "run_windows_tun_performance_hyperv.ps1",
        "performance_bundle": root
        / "tools"
        / "powershell"
        / "Ferrum2.Performance"
        / "bundle.json",
        "topology_plan": root / "tools" / "windows_tun_hyperv_support_topology_plan.json",
        "topology_runtime": root
        / "tools"
        / "windows-tun"
        / "windows_tun_hyperv_support_topology_runtime.ps1",
        "host_network_path": root
        / "tools"
        / "windows-tun"
        / "windows_tun_host_network_path.ps1",
        "guest_network_path": root
        / "tools"
        / "windows-tun"
        / "get_windows_tun_guest_network_path.ps1",
        "collector": root
        / "tools"
        / "windows-tun"
        / "collect_windows_tun_performance_trial.ps1",
        "diagnostic_collector": root
        / "tools"
        / "windows-tun"
        / "collect_windows_tun_udp_boundary_diagnostic.ps1",
        "harness": root
        / "tools"
        / "ferrum2-m4-qualification"
        / "src"
        / "m4_support"
        / "windows_tun"
        / "bundle.json",
    }


@lru_cache(maxsize=1)
def network_model_bundle_sha256() -> str:
    manifest_path = network_model_bundle_path()
    raw = manifest_path.read_bytes()
    manifest = _strict_json(raw.decode("utf-8"), source="network-model bundle")
    if type(manifest) is not dict:
        raise CandidateControlError("network-model bundle must be an object")
    _exact_fields(
        manifest,
        {"entrypoint", "files", "kind", "schema_version"},
        "network-model bundle",
    )
    if (
        manifest["schema_version"] != 1
        or manifest["kind"] != "ferrum2.performance-network-model-bundle.v1"
        or manifest["entrypoint"] != "network_model.py"
        or type(manifest["files"]) is not list
    ):
        raise CandidateControlError("network-model bundle identity is invalid")
    expected_files = {
        "network_model.py",
        "network_model_identity.py",
        "network_model_lifecycle.py",
        "network_model_route.py",
    }
    observed_files = set()
    for entry in manifest["files"]:
        if type(entry) is not dict:
            raise CandidateControlError("network-model bundle file must be an object")
        _exact_fields(entry, {"bytes", "path", "sha256"}, "network-model bundle file")
        relative = entry["path"]
        if type(relative) is not str or pathlib.Path(relative).name != relative:
            raise CandidateControlError("network-model bundle file path is unsafe")
        source = manifest_path.parent / relative
        if relative in observed_files or not source.is_file() or source.is_symlink():
            raise CandidateControlError("network-model bundle file set is invalid")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] <= 0
            or source.stat().st_size != entry["bytes"]
            or type(entry["sha256"]) is not str
            or SHA256.fullmatch(entry["sha256"]) is None
            or _sha256(source) != entry["sha256"]
        ):
            raise CandidateControlError(
                f"network-model bundle file identity changed: {relative}"
            )
        observed_files.add(relative)
    if observed_files != expected_files:
        raise CandidateControlError("network-model bundle file set is incomplete")
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def m4_windows_tun_bundle_sha256() -> str:
    manifest_path = source_paths()["harness"]
    raw = manifest_path.read_bytes()
    manifest = _strict_json(raw.decode("utf-8"), source="M4 Windows TUN bundle")
    if type(manifest) is not dict:
        raise CandidateControlError("M4 Windows TUN bundle must be an object")
    _exact_fields(
        manifest,
        {"entrypoint", "files", "kind", "schema_version"},
        "M4 Windows TUN bundle",
    )
    expected_files = {
        "contract.rs",
        "diagnostic.rs",
        "mod.rs",
        "scenarios.rs",
        "self_check.rs",
        "self_check/cli_contract.rs",
        "self_check/diagnostic.rs",
        "self_check/workload.rs",
        "support.rs",
        "workload.rs",
        "workload_diagnostic.rs",
    }
    if (
        manifest["schema_version"] != 1
        or manifest["kind"] != "ferrum2.m4-windows-tun-source-bundle.v1"
        or manifest["entrypoint"] != "mod.rs"
        or type(manifest["files"]) is not list
    ):
        raise CandidateControlError("M4 Windows TUN bundle identity is invalid")
    observed_files = set()
    for entry in manifest["files"]:
        if type(entry) is not dict:
            raise CandidateControlError("M4 Windows TUN bundle file must be an object")
        _exact_fields(entry, {"bytes", "path", "sha256"}, "M4 Windows TUN bundle file")
        relative = entry["path"]
        relative_path = pathlib.PurePosixPath(relative) if type(relative) is str else None
        if (
            relative_path is None
            or relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or any(part in ("", ".", "..") for part in relative_path.parts)
        ):
            raise CandidateControlError("M4 Windows TUN bundle file path is unsafe")
        source = manifest_path.parent.joinpath(*relative_path.parts)
        if relative in observed_files or not source.is_file() or source.is_symlink():
            raise CandidateControlError("M4 Windows TUN bundle file set is invalid")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] <= 0
            or source.stat().st_size != entry["bytes"]
            or type(entry["sha256"]) is not str
            or SHA256.fullmatch(entry["sha256"]) is None
            or _sha256(source) != entry["sha256"]
        ):
            raise CandidateControlError(
                f"M4 Windows TUN bundle file identity changed: {relative}"
            )
        observed_files.add(relative)
    if observed_files != expected_files:
        raise CandidateControlError("M4 Windows TUN bundle file set is incomplete")
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def performance_source_bundle_sha256() -> str:
    root = repository_root()
    manifest_path = source_paths()["performance_bundle"]
    raw = manifest_path.read_bytes()
    manifest = _strict_json(raw.decode("utf-8"), source="performance source bundle")
    if type(manifest) is not dict:
        raise CandidateControlError("performance source bundle must be an object")
    _exact_fields(
        manifest,
        {"entrypoint", "files", "kind", "schema_version"},
        "performance source bundle",
    )
    if (
        manifest["schema_version"] != 1
        or manifest["kind"] != "ferrum2.windows-tun-performance-source-bundle.v1"
        or manifest["entrypoint"]
        != "tools/windows-tun/run_windows_tun_performance_hyperv.ps1"
        or type(manifest["files"]) is not list
    ):
        raise CandidateControlError("performance source bundle identity is invalid")
    observed = set()
    for entry in manifest["files"]:
        if type(entry) is not dict:
            raise CandidateControlError("performance source bundle file must be an object")
        _exact_fields(entry, {"bytes", "path", "sha256"}, "performance source bundle file")
        relative = entry["path"]
        if (
            type(relative) is not str
            or pathlib.PurePosixPath(relative).is_absolute()
            or ".." in pathlib.PurePosixPath(relative).parts
            or relative in observed
        ):
            raise CandidateControlError("performance source bundle path is unsafe")
        source = root / pathlib.PurePosixPath(relative)
        if not source.is_file() or source.is_symlink():
            raise CandidateControlError("performance source bundle file set is invalid")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] <= 0
            or source.stat().st_size != entry["bytes"]
            or type(entry["sha256"]) is not str
            or SHA256.fullmatch(entry["sha256"]) is None
            or _sha256(source) != entry["sha256"]
        ):
            raise CandidateControlError(
                f"performance source bundle file identity changed: {relative}"
            )
        observed.add(relative)
    expected = {
        "tools/windows-tun/run_windows_tun_performance_hyperv.ps1",
        "tools/windows-tun/collect_windows_tun_performance_trial.ps1",
        "tools/windows-tun/collect_windows_tun_udp_boundary_diagnostic.ps1",
        "tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1",
        "tools/powershell/Ferrum2.Qualification.Common/Ferrum2.Qualification.Common.psd1",
        "tools/powershell/Ferrum2.Qualification.Common/Ferrum2.Qualification.Common.psm1",
        "tools/powershell/Ferrum2.Qualification.Evidence/Ferrum2.Qualification.Evidence.psd1",
        "tools/powershell/Ferrum2.Qualification.Evidence/Ferrum2.Qualification.Evidence.psm1",
        "tools/powershell/Ferrum2.Qualification.HostHyperV/Ferrum2.Qualification.HostHyperV.psd1",
        "tools/powershell/Ferrum2.Qualification.HostHyperV/Ferrum2.Qualification.HostHyperV.psm1",
        *{
            f"tools/powershell/Ferrum2.Qualification.HostHyperV/private/{name}"
            for name in (
                "Artifacts.ps1", "Evidence.ps1", "Facade.ps1", "Manifest.ps1",
                "Paths.ps1", "Process.ps1", "VmTransaction.ps1",
            )
        },
        *{
            f"tools/powershell/Ferrum2.Performance/{name}"
            for name in (
                "CollectorCore.ps1", "CollectorLifecycle.ps1", "CollectorUdpSource.ps1",
                "Ferrum2.Performance.psd1", "Ferrum2.Performance.psm1",
                "GuestSupport.ps1", "GuestTransaction.ps1", "HostContract.ps1",
                "HostUdpEvidence.ps1", "HostUdpResult.ps1", "HostVmTransaction.ps1",
                "PerformanceProcessOwner.cs", "RuntimeStaging.ps1",
                "TrialScenario.fragment-reassembly-throughput.ps1",
                "TrialScenario.idle-cpu-wakeup.ps1", "TrialScenario.network-lifecycle.ps1",
                "TrialScenario.tcp-256-flow-fairness.ps1", "TrialScenario.tcp-single-flow.ps1",
                "TrialScenario.udp-8192-association-lookup-expiry.ps1",
                "TrialScenario.udp-packets-per-second.ps1", "TrialScenario.udp-route-once.ps1",
                "TrialScenario.wintun-ring-full-drop-rate.ps1", "UdpDiagnosticCore.ps1",
                "UdpDiagnosticEvidence.ps1", "UdpDiagnosticSource.ps1",
            )
        },
    }
    if observed != expected:
        raise CandidateControlError("performance source bundle file set is incomplete")
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def source_identities() -> dict[str, str]:
    paths = source_paths()
    return {
        "runner_source_sha256": performance_source_bundle_sha256(),
        "performance_source_bundle_sha256": performance_source_bundle_sha256(),
        "topology_plan_source_sha256": _sha256(paths["topology_plan"]),
        "topology_runtime_source_sha256": _sha256(paths["topology_runtime"]),
        "host_network_path_source_sha256": _sha256(paths["host_network_path"]),
        "guest_network_path_source_sha256": _sha256(paths["guest_network_path"]),
        "collector_source_sha256": _sha256(paths["collector"]),
        "diagnostic_collector_source_sha256": _sha256(paths["diagnostic_collector"]),
        "harness_source_sha256": m4_windows_tun_bundle_sha256(),
        "network_model_controller_sha256": network_model_bundle_sha256(),
    }


@lru_cache(maxsize=1)
def network_model_plan() -> dict[str, object]:
    return network_model.create_local_hyperv_plan()


@lru_cache(maxsize=1)
def network_model_plan_sha256() -> str:
    encoded = (json.dumps(network_model_plan(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@lru_cache(maxsize=1)
def runtime_recipe() -> dict[str, object]:
    sources = source_identities()
    return {
    "runner_source_sha256": sources["runner_source_sha256"],
    "performance_source_bundle_sha256": sources["performance_source_bundle_sha256"],
    "topology_plan_source_sha256": sources["topology_plan_source_sha256"],
    "topology_runtime_source_sha256": sources["topology_runtime_source_sha256"],
    "host_network_path_source_sha256": sources["host_network_path_source_sha256"],
    "guest_network_path_source_sha256": sources["guest_network_path_source_sha256"],
    "collector_source_sha256": sources["collector_source_sha256"],
    "harness_source_sha256": sources["harness_source_sha256"],
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
    "tun_ring_capacity_bytes": 8_388_608,
    "tun_max_tcp_flows": 4_096,
    "tun_tcp_buffer_bytes": 32_768,
    "tun_max_udp_mappings": 8_192,
    "tun_udp_datagram_queue_packets": 8,
    "tun_udp_response_queue_packets_per_association": 8,
    "tun_udp_filtering": "endpoint_independent",
    "udp_max_sessions": 16_384,
    "udp_max_buffered_bytes": 268_435_456,
    "udp_idle_timeout_milliseconds": 60_000,
    "client_runtime_idle_timeout_milliseconds": 60_000,
    "support_tcp_idle_timeout_milliseconds": 120_000,
    "shadowsocks_method": "2022-blake3-aes-128-gcm",
    "gso": False,
}


@lru_cache(maxsize=1)
def scenario_catalog() -> dict[str, object]:
    sources = source_identities()
    return {
    "tcp-single-flow": {
        "recipe": {
            **runtime_recipe(),
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
            **runtime_recipe(),
            "topology": "tun-shadowsocks-external-echo",
            "warmup_seconds": 10,
            "active_seconds": 30,
            "flows": 256,
            "payload_bytes": 16_384,
            "connection_readiness": "sequential_exact_round_trip",
            "readiness_payload_bytes": 1_024,
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
            "all_256_flows_ready",
            "all_256_flows_nonzero",
            "payload_exact",
            "no_gso",
            "tun_path_observed",
            "clean_drain",
        ),
    },
    "udp-packets-per-second": {
        "recipe": {
            **runtime_recipe(),
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "active_seconds": 30,
            "associations": 1,
            "batch_datagrams": 8,
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
            **runtime_recipe(),
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "associations": 8_192,
            "bootstrap_batch_associations": 1,
            "batch_associations": 8,
            "lookup_rounds": 64,
            "expiry_rounds": 1,
            "payload_bytes": 32,
            "canonical_source_port_strategy": (
                WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_STRATEGY
            ),
            "canonical_source_ipv4": WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
            "canonical_source_port_first": (
                WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
            ),
            "canonical_source_port_last": (
                WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
            ),
            "diagnostic_source_ipv4": WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
            "diagnostic_source_port_first": (
                WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
            ),
            "diagnostic_source_port_last": (
                WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
            ),
            "diagnostic_collector_source_sha256": (
                sources["diagnostic_collector_source_sha256"]
            ),
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
            **runtime_recipe(),
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
            **runtime_recipe(),
            "topology": "tun-idle-no-traffic",
            "settle_seconds": 10,
            "active_seconds": 60,
            "sample_interval_milliseconds": 1_000,
            "expected_traffic_packets": 0,
            "allowed_idle_background_rejection_reasons": (
                "family_disabled",
                "invalid_destination",
            ),
            "minimum_reported_integer_rate": 1,
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
            "known_background_ingress_exactly_accounted",
            "no_busy_poll_fallback",
            "clean_drain",
        ),
    },
    "wintun-ring-full-drop-rate": {
        "recipe": {
            **runtime_recipe(),
            "topology": "tun-direct-external-echo",
            "warmup_seconds": 5,
            "burst_attempts": 1_000_000,
            "minimum_response_attempts": (
                WINDOWS_TUN_RING_PRESSURE_MINIMUM_RESPONSE_ATTEMPTS
            ),
            "packets_per_event": 1,
            "payload_bytes": 1_200,
            "post_burst_settle_seconds": 5,
            "drop_rate_denominator": "tun_response_attempts",
            "pending_response_peak_maximum": 1,
            "ring_full_branch_proof": "separate_m17_correctness_gate",
        },
        "metrics": {
            "drop_rate": {
                "unit": "dropped_packets_per_million_responses",
                "direction": "lower_is_better",
                "allow_zero": True,
                "zero_baseline_comparison": (
                    "zero_zero_tie_zero_to_positive_signed_100_percent"
                ),
            },
            "pending_response_peak": {
                "unit": "pending_udp_responses",
                "direction": "lower_is_better",
                "allow_zero": True,
                "zero_baseline_comparison": (
                    "zero_zero_tie_zero_to_positive_signed_100_percent"
                ),
            },
        },
        "checked_unit": "tun_response_attempts",
        "minimum_checked_units": (
            WINDOWS_TUN_RING_PRESSURE_MINIMUM_RESPONSE_ATTEMPTS
        ),
        "correctness_checks": (
            "minimum_response_attempts_met",
            "response_attempt_denominator_derived",
            "drop_rate_recomputed_from_raw_counts",
            "drop_rate_denominator_bound",
            "ring_full_counter_sampled",
            "pending_response_peak_bounded",
            "pending_response_baseline_and_drain",
            "no_network_reset_or_full_rebuild",
            "tun_path_observed",
        ),
    },
    "udp-route-once": {
        "recipe": {
            **runtime_recipe(),
            "topology": "tun-mixed-direct-shadowsocks-external-echo",
            "network_model_schema_version": network_model_identity.SCHEMA_VERSION,
            "network_model_controller_sha256": sources["network_model_controller_sha256"],
            "network_model_plan_sha256": network_model_plan_sha256(),
            "generations": network_model_route.ROUTE_GENERATIONS,
            "source_slots": network_model_route.ROUTE_SOURCE_SLOTS,
            "target_slots": network_model_route.ROUTE_TARGET_SLOTS,
            "datagrams_per_target": network_model_route.ROUTE_DATAGRAMS_PER_TARGET,
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
            network_model_route.ROUTE_GENERATIONS
            * network_model_route.ROUTE_SOURCE_SLOTS
            * network_model_route.ROUTE_TARGET_SLOTS
            * network_model_route.ROUTE_DATAGRAMS_PER_TARGET
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
            **runtime_recipe(),
            "topology": "tun-mixed-direct-shadowsocks-external-echo",
            "network_model_schema_version": network_model_identity.SCHEMA_VERSION,
            "network_model_controller_sha256": sources["network_model_controller_sha256"],
            "network_model_plan_sha256": network_model_plan_sha256(),
            "resource_warmup_reset_cycles": (
                network_model_lifecycle.RESOURCE_WARMUP_RESET_CYCLES
            ),
            "resource_warmup_route_metric_states": (
                network_model_lifecycle.RESOURCE_WARMUP_ROUTE_METRIC_STATES
            ),
            "resource_quiescence_seconds": (
                network_model_lifecycle.RESOURCE_QUIESCENCE_SECONDS
            ),
            "reset_network_cycles": network_model_lifecycle.RESET_CYCLES,
            "total_reset_network_cycles": network_model_lifecycle.TOTAL_RESET_CYCLES,
            "full_rebuild_cycles": network_model_lifecycle.FULL_REBUILD_CYCLES,
            "full_rebuild_damage_reason": network_model_lifecycle.FULL_REBUILD_DAMAGE_REASON,
            "interface_switch_kind": "approved_underlay_disable_enable",
            "interface_switch_sequence": network_model_lifecycle.INTERFACE_SWITCH_SEQUENCE,
            "interface_switch_trial_reset_ordinal": (
                network_model_lifecycle.INTERFACE_SWITCH_TRIAL_RESET_ORDINAL
            ),
            "interface_resolver_probes": network_model_lifecycle.INTERFACE_RESOLVER_PROBES,
            "terminal_resource_convergence_excluded_from_elapsed": True,
            "retained_resource_growth_enforced_operations": ("reset_network",),
            "diagnostic_resource_growth_operations": ("full_rebuild",),
            "recovery_timeout_seconds": (
                network_model_lifecycle.INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS
            ),
            "interface_switch_probe_retry_milliseconds": (
                network_model_lifecycle.INTERFACE_SWITCH_PROBE_RETRY_MILLISECONDS
            ),
            "interface_switch_retryable_failure": (
                "outbound_explicit_resolution_failure"
            ),
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
        "minimum_checked_units": network_model_lifecycle.RESET_CYCLES,
        "correctness_checks": (
            "same_process_all_cycles",
            "resource_warmup_exact",
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


def scenario_contracts() -> dict[str, object]:
    return json.loads(_canonical_json_bytes(scenario_catalog()).decode("ascii"))


def recipe_sha256(controller_bundle_sha256: str) -> str:
    if (
        type(controller_bundle_sha256) is not str
        or SHA256.fullmatch(controller_bundle_sha256) is None
    ):
        raise CandidateControlError("runtime controller bundle identity is invalid")
    contract = {
        "controller_bundle_sha256": controller_bundle_sha256,
        "scenarios": scenario_contracts(),
    }
    return hashlib.sha256(_canonical_json_bytes(contract)).hexdigest()
