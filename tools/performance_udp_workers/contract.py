"""Fixed schemas and semantic source identity for GATE-05 evidence."""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any


class UdpWorkerControlError(ValueError):
    """Raised when the closed qualification contract is violated."""


TRIAL_SCHEMA_VERSION = 1
PLAN_SCHEMA_VERSION = 1
SUMMARY_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1
STRUCTURAL_SCHEMA_VERSION = 7
STRUCTURAL_AGGREGATION = "checked_sum_of_client_and_server_checked_deltas"
TRIAL_KIND = "ferrum2_udp_worker_trial"
RUNNER_IMAGE = "ubuntu-24.04"
BUILD_PROFILE = "profiling-structural-metrics"
WARMUP_SECONDS = 3
ACTIVE_SECONDS = 15
PAIRS = 6
AA_ROUNDS = 2
SESSION_TOPOLOGIES = ("same-session", "multi-session")
SESSION_COUNTS = {"same-session": 1, "multi-session": 32}
COMPARISON_WORKERS = (2, 4, 8)
AUTHORITY = {
    "scope": "github-hosted-amd-provisional",
    "performance_authoritative": False,
    "bare_metal_gate": False,
    "adoption_claim": False,
}

STRUCTURAL_COUNTERS = (
    "tcp_decrypt_prepare_copy_bytes",
    "tcp_frame_encode_copy_bytes",
    "tcp_plain_to_encrypt_copy_bytes",
    "tcp_decrypt_to_plain_copy_bytes",
    "udp_payload_to_wire_copy_bytes",
    "socks_udp_copy_bytes",
    "dns_udp_copy_bytes",
    "tcp_zeroized_bytes",
    "udp_request_wire_resize_bytes",
    "udp_request_wire_zero_bytes",
    "tcp_read_self_wakeups",
    "tcp_poll_budget_exhaustions",
    "relay_activity_wakeups",
    "udp_aes_body_cipher_constructions",
    "replay_cleared_words",
    "replay_cleared_bits",
    "socks_udp_allocations",
    "dns_udp_allocations",
    "udp_owned_fast_path_hits",
    "tcp_fused_fast_path_connections",
    "tcp_fused_fallback_direct_connections",
    "tcp_fused_fallback_multi_hop_connections",
    "tcp_fused_fallback_tun_connections",
    "tcp_fused_fallback_dns_connections",
    "tcp_fused_fallback_rule_set_connections",
    "tcp_fused_fallback_server_non_direct_connections",
    "tcp_fused_fallback_unsupported_flow_connections",
    "tcp_fused_owned_upload_frames",
    "tcp_fused_borrowed_download_frames",
    "tcp_fused_partial_writes",
    "tcp_fused_frames",
    "tcp_fused_encrypt_buffer_capacity_bytes",
    "tcp_fused_decrypt_buffer_capacity_bytes",
    "tcp_fused_relay_buffer_capacity_removed_bytes",
    "admission_lock_wait_nanoseconds",
    "admission_lock_hold_nanoseconds",
    "admission_lock_samples",
    "udp_server_lock_wait_nanoseconds",
    "udp_server_lock_hold_nanoseconds",
    "udp_server_lock_samples",
    "udp_mappings_lock_wait_nanoseconds",
    "udp_mappings_lock_hold_nanoseconds",
    "udp_mappings_lock_samples",
    "session_shard_lock_wait_nanoseconds",
    "session_shard_lock_hold_nanoseconds",
    "session_shard_lock_samples",
    "response_codec_lock_wait_nanoseconds",
    "response_codec_lock_hold_nanoseconds",
    "response_codec_lock_samples",
)

PRODUCER_SOURCES = (
    "crates/ferrum2-structural/src/lib.rs",
    "tools/ferrum2-m4-qualification/Cargo.toml",
    "tools/ferrum2-m4-qualification/src/m4_support/mod.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/dns_resource.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/evidence_support.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/host_identity.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/process_support.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/profile_contract.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/profile_output.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/profile_structural.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/profile_udp.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/proxy_config.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/resource.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/self_check.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/structural_contract.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/throughput.rs",
    "tools/ferrum2-m4-qualification/src/m4_support/udp_worker.rs",
    "tools/ferrum2-m4-qualification/src/main.rs",
)
CONTROLLER_SOURCES = (
    ".github/workflows/performance-udp-workers.yml",
    "tools/ci/performance_udp_worker_workflow.py",
    "tools/performance_udp_workers/__init__.py",
    "tools/performance_udp_workers/__main__.py",
    "tools/performance_udp_workers/cli.py",
    "tools/performance_udp_workers/contract.py",
    "tools/performance_udp_workers/evidence.py",
    "tools/performance_udp_workers/pairing.py",
    "tools/performance_udp_workers/runner.py",
)


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise UdpWorkerControlError("value is outside canonical JSON") from error


def sha256_file(path: pathlib.Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise UdpWorkerControlError("evidence source is not a regular file")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise UdpWorkerControlError("evidence source is unavailable") from error


def source_bundle_sha256(root: pathlib.Path, paths: tuple[str, ...]) -> str:
    if len(paths) != len(set(paths)):
        raise UdpWorkerControlError("source bundle paths are duplicated")
    entries: list[dict[str, object]] = []
    for relative in paths:
        path = root / relative
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise UdpWorkerControlError(
                f"source bundle is missing {relative}"
            ) from error
        if path.is_symlink() or not path.is_file():
            raise UdpWorkerControlError(f"source bundle path is invalid: {relative}")
        entries.append(
            {
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


def semantic_recipe() -> dict[str, object]:
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "scenario": "udp-small-high",
        "topology": "shadowsocks",
        "server_receive_workers": [1, 2, 4, 8],
        "session_topologies": [
            {"name": name, "logical_sessions": SESSION_COUNTS[name]}
            for name in SESSION_TOPOLOGIES
        ],
        "warmup_seconds": WARMUP_SECONDS,
        "active_seconds": ACTIVE_SECONDS,
        "pairs": PAIRS,
        "pair_schedule": "abba-six-pairs",
        "aa_rounds": AA_ROUNDS,
        "metrics": [
            "datagrams_per_second",
            "p99_nanoseconds",
            "p99_sample_count",
            "combined_cpu_core_millis",
            "voluntary_context_switches",
            "involuntary_context_switches",
            "admission_lock_wait_hold",
            "udp_server_lock_wait_hold",
            "udp_mappings_lock_wait_hold",
        ],
    }


def evidence_contract(root: pathlib.Path) -> dict[str, str | int]:
    producer = source_bundle_sha256(root, PRODUCER_SOURCES)
    controller = source_bundle_sha256(root, CONTROLLER_SOURCES)
    recipe = hashlib.sha256(canonical_bytes(semantic_recipe())).hexdigest()
    bundle: dict[str, str | int] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "trial_schema_version": TRIAL_SCHEMA_VERSION,
        "structural_schema_version": STRUCTURAL_SCHEMA_VERSION,
        "runner_image": RUNNER_IMAGE,
        "producer_source_sha256": producer,
        "controller_source_sha256": controller,
        "semantic_recipe_sha256": recipe,
    }
    return {
        **bundle,
        "evidence_bundle_sha256": hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
    }


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise UdpWorkerControlError(f"{label} does not match its closed schema")
    return value


def require_uint(value: object, label: str, *, positive: bool = False) -> int:
    if (
        type(value) is not int
        or value < (1 if positive else 0)
        or value > (1 << 64) - 1
    ):
        raise UdpWorkerControlError(f"{label} is not an unsigned integer")
    return value
