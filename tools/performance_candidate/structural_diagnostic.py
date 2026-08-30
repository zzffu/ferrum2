"""Closed consumer for non-authoritative structural diagnostic evidence."""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess

from tools.performance_candidate.json_contract import (
    U64_MAX,
    CandidateControlError,
    _exact_fields,
    _required_string,
    _required_u64,
    read_bounded_closed_json,
)


STRUCTURAL_SCHEMA_VERSION = 7
STRUCTURAL_KIND = "m18_structural_trial"
STRUCTURAL_SCENARIO = "tcp-stream-64k"
PENDING_SURFACE_SCHEMA_VERSION = 8
PENDING_SURFACE_SCENARIO = "tcp-bulk"
STRUCTURAL_AGGREGATION = "checked_sum_of_client_and_server_checked_deltas"
STRUCTURAL_MAX_BYTES = 256 * 1024
STRUCTURAL_BINARY_MAX_BYTES = 512 * 1024 * 1024
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")

COUNTER_UNITS: dict[str, str] = {
    "tcp_decrypt_prepare_copy_bytes": "bytes",
    "tcp_frame_encode_copy_bytes": "bytes",
    "tcp_plain_to_encrypt_copy_bytes": "bytes",
    "tcp_decrypt_to_plain_copy_bytes": "bytes",
    "udp_payload_to_wire_copy_bytes": "bytes",
    "socks_udp_copy_bytes": "bytes",
    "dns_udp_copy_bytes": "bytes",
    "tcp_zeroized_bytes": "bytes",
    "udp_request_wire_resize_bytes": "bytes",
    "udp_request_wire_zero_bytes": "bytes",
    "tcp_read_self_wakeups": "events",
    "tcp_poll_budget_exhaustions": "events",
    "relay_activity_wakeups": "events",
    "udp_aes_body_cipher_constructions": "events",
    "replay_cleared_words": "events",
    "replay_cleared_bits": "events",
    "socks_udp_allocations": "events",
    "dns_udp_allocations": "events",
    "udp_owned_fast_path_hits": "events",
    "tcp_fused_fast_path_connections": "events",
    "tcp_fused_fallback_direct_connections": "events",
    "tcp_fused_fallback_multi_hop_connections": "events",
    "tcp_fused_fallback_tun_connections": "events",
    "tcp_fused_fallback_dns_connections": "events",
    "tcp_fused_fallback_rule_set_connections": "events",
    "tcp_fused_fallback_server_non_direct_connections": "events",
    "tcp_fused_fallback_unsupported_flow_connections": "events",
    "tcp_fused_owned_upload_frames": "events",
    "tcp_fused_borrowed_download_frames": "events",
    "tcp_fused_partial_writes": "events",
    "tcp_fused_frames": "events",
    "tcp_fused_encrypt_buffer_capacity_bytes": "bytes",
    "tcp_fused_decrypt_buffer_capacity_bytes": "bytes",
    "tcp_fused_relay_buffer_capacity_removed_bytes": "bytes",
    "admission_lock_wait_nanoseconds": "nanoseconds",
    "admission_lock_hold_nanoseconds": "nanoseconds",
    "admission_lock_samples": "events",
    "udp_server_lock_wait_nanoseconds": "nanoseconds",
    "udp_server_lock_hold_nanoseconds": "nanoseconds",
    "udp_server_lock_samples": "events",
    "udp_mappings_lock_wait_nanoseconds": "nanoseconds",
    "udp_mappings_lock_hold_nanoseconds": "nanoseconds",
    "udp_mappings_lock_samples": "events",
    "session_shard_lock_wait_nanoseconds": "nanoseconds",
    "session_shard_lock_hold_nanoseconds": "nanoseconds",
    "session_shard_lock_samples": "events",
    "response_codec_lock_wait_nanoseconds": "nanoseconds",
    "response_codec_lock_hold_nanoseconds": "nanoseconds",
    "response_codec_lock_samples": "events",
}
PENDING_SURFACE_COUNTER_UNITS: dict[str, str] = {
    **COUNTER_UNITS,
    "tcp_fused_upload_drain_pending_frames": "events",
    "tcp_fused_upload_drain_pending_polls": "events",
    "tcp_fused_download_sink_pending_frames": "events",
    "tcp_fused_download_sink_pending_polls": "events",
}
SCHEMA_CONTRACTS: dict[int, tuple[str, dict[str, str]]] = {
    STRUCTURAL_SCHEMA_VERSION: (STRUCTURAL_SCENARIO, COUNTER_UNITS),
    PENDING_SURFACE_SCHEMA_VERSION: (
        PENDING_SURFACE_SCENARIO,
        PENDING_SURFACE_COUNTER_UNITS,
    ),
}

TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "candidate_sha",
        "tree_sha",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
        "scenario",
        "warmup_seconds",
        "active_seconds",
        "build_profile",
        "performance_authoritative",
        "performance_adoption_allowed",
        "counter_schema",
        "snapshots",
        "overflow",
        "deltas",
        "workload",
        "cleanup",
        "correctness",
        "status",
    }
)


def validate_structural_diagnostic(
    evidence: pathlib.Path,
    *,
    repository: pathlib.Path,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    candidate_sha: str,
) -> dict[str, object]:
    """Validate and independently recompute one schema-v7 diagnostic."""

    return _validate_structural_diagnostic(
        evidence,
        repository=repository,
        runner=runner,
        client=client,
        server=server,
        candidate_sha=candidate_sha,
        expected_schema_version=STRUCTURAL_SCHEMA_VERSION,
    )


def validate_tcp_pending_surface_diagnostic(
    evidence: pathlib.Path,
    *,
    repository: pathlib.Path,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    candidate_sha: str,
) -> dict[str, object]:
    """Validate and independently recompute one schema-v8 pending diagnostic."""

    return _validate_structural_diagnostic(
        evidence,
        repository=repository,
        runner=runner,
        client=client,
        server=server,
        candidate_sha=candidate_sha,
        expected_schema_version=PENDING_SURFACE_SCHEMA_VERSION,
    )


def _validate_structural_diagnostic(
    evidence: pathlib.Path,
    *,
    repository: pathlib.Path,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    candidate_sha: str,
    expected_schema_version: int,
) -> dict[str, object]:
    """Validate one structural diagnostic against its command-bound schema."""

    bounded = read_bounded_closed_json(
        evidence,
        maximum_bytes=STRUCTURAL_MAX_BYTES,
        source="structural diagnostic evidence",
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError("structural diagnostic evidence must be an object")
    _exact_fields(row, TOP_LEVEL_FIELDS, "structural diagnostic evidence")
    schema_version = _required_u64(row, "schema_version", positive=True)
    if schema_version != expected_schema_version:
        raise CandidateControlError(
            "structural diagnostic schema version does not match the validator command"
        )
    scenario, counter_units = SCHEMA_CONTRACTS[schema_version]
    _required_string(row, "kind", expected=STRUCTURAL_KIND)
    _required_string(row, "scenario", expected=scenario)
    _required_string(row, "build_profile", expected="profiling-structural-metrics")
    _required_string(row, "correctness", expected="PASS")
    _required_string(row, "status", expected="PASS")
    if row["performance_authoritative"] is not False:
        raise CandidateControlError("structural diagnostic cannot be performance authoritative")
    if row["performance_adoption_allowed"] is not False:
        raise CandidateControlError("structural diagnostic cannot allow performance adoption")
    warmup_seconds = _required_u64(row, "warmup_seconds", positive=True)
    active_seconds = _required_u64(row, "active_seconds", positive=True)
    if not 1 <= warmup_seconds <= 10 or not 1 <= active_seconds <= 60:
        raise CandidateControlError("structural diagnostic timing is outside its finite bound")

    _validate_identity(
        row,
        repository=repository,
        runner=runner,
        client=client,
        server=server,
        candidate_sha=candidate_sha,
    )
    _validate_counter_schema(row["counter_schema"], counter_units)
    snapshots = _validate_snapshots(row["snapshots"], counter_units)
    _validate_overflow(row["overflow"])
    computed = _compute_deltas(snapshots, counter_units)
    _validate_recorded_deltas(row["deltas"], computed, counter_units)
    _validate_fused_path(computed["merged"])
    if schema_version == PENDING_SURFACE_SCHEMA_VERSION:
        _validate_pending_surface(computed)
    _validate_workload(row["workload"])
    _validate_cleanup(row["cleanup"])
    return row


def _validate_identity(
    row: dict[str, object],
    *,
    repository: pathlib.Path,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    candidate_sha: str,
) -> None:
    if COMMIT_SHA.fullmatch(candidate_sha) is None:
        raise CandidateControlError("candidate_sha must be a lowercase full commit SHA")
    repository = _resolve(repository, "structural repository")
    if not repository.is_dir():
        raise CandidateControlError("structural repository must be a directory")
    head = _git(repository, "rev-parse", "HEAD")
    if head != candidate_sha or row["candidate_sha"] != candidate_sha:
        raise CandidateControlError("structural candidate identity does not match checkout HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    if row["tree_sha"] != tree:
        raise CandidateControlError("structural tree identity does not match checkout HEAD")
    if _git(repository, "status", "--porcelain=v1"):
        raise CandidateControlError("structural checkout is dirty during validation")

    expected_dir = _resolve(
        repository / "target/structural-diagnostic/profiling",
        "structural target directory",
    )
    for path, expected_name, field in (
        (runner, "m4-qualification", "runner_sha256"),
        (client, "ferrum2-client", "client_sha256"),
        (server, "ferrum2-server", "server_sha256"),
    ):
        if path.is_symlink():
            raise CandidateControlError("structural diagnostic binary cannot be a symlink")
        path = _resolve(path, "structural diagnostic binary")
        if not path.is_file() or path.parent != expected_dir or path.name != expected_name:
            raise CandidateControlError(
                "structural binaries must come from the independent diagnostic target"
            )
        if row[field] != _sha256(path):
            raise CandidateControlError(f"{field} does not match the diagnostic binary")


def _git(repository: pathlib.Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CandidateControlError("unable to recompute structural git identity") from error
    if completed.returncode != 0:
        raise CandidateControlError("unable to recompute structural git identity")
    return completed.stdout.strip()


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        size = path.stat().st_size
        if size <= 0 or size > STRUCTURAL_BINARY_MAX_BYTES:
            raise CandidateControlError(
                "structural diagnostic binary is outside its size bound"
            )
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except CandidateControlError:
        raise
    except OSError as error:
        raise CandidateControlError("unable to hash structural diagnostic binary") from error
    return digest.hexdigest()


def _resolve(path: pathlib.Path, name: str) -> pathlib.Path:
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise CandidateControlError(f"{name} is unavailable") from error


def _validate_counter_schema(value: object, counter_units: dict[str, str]) -> None:
    if type(value) is not dict:
        raise CandidateControlError("structural counter_schema must be an object")
    _exact_fields(value, frozenset(counter_units), "structural counter_schema")
    if len(value) != len(counter_units):
        raise CandidateControlError(
            f"structural counter_schema must contain {len(counter_units)} families"
        )
    for counter, unit in counter_units.items():
        entry = value[counter]
        if type(entry) is not dict:
            raise CandidateControlError(f"structural schema entry is invalid: {counter}")
        _exact_fields(
            entry,
            frozenset({"unit", "aggregation", "range"}),
            f"structural schema entry {counter}",
        )
        if entry["unit"] != unit or entry["aggregation"] != STRUCTURAL_AGGREGATION:
            raise CandidateControlError(f"structural schema semantics mismatch: {counter}")
        value_range = entry["range"]
        if type(value_range) is not dict:
            raise CandidateControlError(f"structural range is invalid: {counter}")
        _exact_fields(
            value_range,
            frozenset({"minimum", "maximum"}),
            f"structural range {counter}",
        )
        if value_range != {"minimum": 0, "maximum": U64_MAX}:
            raise CandidateControlError(f"structural range is not the u64 range: {counter}")


def _validate_snapshots(
    value: object, counter_units: dict[str, str]
) -> dict[str, dict[str, dict[str, int]]]:
    if type(value) is not dict:
        raise CandidateControlError("structural snapshots must be an object")
    _exact_fields(value, frozenset({"client", "server"}), "structural snapshots")
    snapshots: dict[str, dict[str, dict[str, int]]] = {}
    for endpoint in ("client", "server"):
        endpoint_value = value[endpoint]
        if type(endpoint_value) is not dict:
            raise CandidateControlError(f"structural {endpoint} snapshots must be an object")
        _exact_fields(
            endpoint_value,
            frozenset({"before", "after"}),
            f"structural {endpoint} snapshots",
        )
        snapshots[endpoint] = {
            phase: _counter_values(
                endpoint_value[phase], f"{endpoint} {phase}", counter_units
            )
            for phase in ("before", "after")
        }
    return snapshots


def _counter_values(
    value: object, name: str, counter_units: dict[str, str]
) -> dict[str, int]:
    if type(value) is not dict:
        raise CandidateControlError(f"structural {name} counters must be an object")
    _exact_fields(value, frozenset(counter_units), f"structural {name} counters")
    parsed: dict[str, int] = {}
    for counter, item in value.items():
        if type(item) is not int or not 0 <= item <= U64_MAX:
            raise CandidateControlError(
                f"structural {name} counter must be a u64: {counter}"
            )
        parsed[counter] = item
    return parsed


def _validate_overflow(value: object) -> None:
    expected = frozenset(
        {"client_before", "client_after", "server_before", "server_after", "any"}
    )
    if type(value) is not dict:
        raise CandidateControlError("structural overflow must be an object")
    _exact_fields(value, expected, "structural overflow")
    raw = [value[field] for field in expected if field != "any"]
    if any(type(item) is not bool for item in raw) or type(value["any"]) is not bool:
        raise CandidateControlError("structural overflow flags must be booleans")
    recomputed = any(raw)
    if value["any"] != recomputed:
        raise CandidateControlError("structural overflow aggregate was not recomputed")
    if recomputed:
        raise CandidateControlError("structural counter overflow invalidates the diagnostic")


def _compute_deltas(
    snapshots: dict[str, dict[str, dict[str, int]]],
    counter_units: dict[str, str],
) -> dict[str, dict[str, int]]:
    computed: dict[str, dict[str, int]] = {"client": {}, "server": {}, "merged": {}}
    for endpoint in ("client", "server"):
        before = snapshots[endpoint]["before"]
        after = snapshots[endpoint]["after"]
        for counter in counter_units:
            if after[counter] < before[counter]:
                raise CandidateControlError(
                    f"structural counter decreased at {endpoint}: {counter}"
                )
            computed[endpoint][counter] = after[counter] - before[counter]
    for counter in counter_units:
        merged = computed["client"][counter] + computed["server"][counter]
        if merged > U64_MAX:
            raise CandidateControlError(f"merged structural delta overflowed: {counter}")
        computed["merged"][counter] = merged
    return computed


def _validate_recorded_deltas(
    value: object,
    computed: dict[str, dict[str, int]],
    counter_units: dict[str, str],
) -> None:
    if type(value) is not dict:
        raise CandidateControlError("structural deltas must be an object")
    _exact_fields(value, frozenset(computed), "structural deltas")
    for aggregation in ("client", "server", "merged"):
        recorded = _counter_values(
            value[aggregation], f"{aggregation} deltas", counter_units
        )
        if recorded != computed[aggregation]:
            raise CandidateControlError(
                f"structural {aggregation} deltas do not match snapshots"
            )


def _validate_fused_path(merged: dict[str, int]) -> None:
    for counter in (
        "tcp_plain_to_encrypt_copy_bytes",
        "tcp_decrypt_to_plain_copy_bytes",
    ):
        if merged[counter] != 0:
            raise CandidateControlError(f"structural zero-copy assertion failed: {counter}")
    for counter in (
        "tcp_fused_fast_path_connections",
        "tcp_fused_owned_upload_frames",
        "tcp_fused_borrowed_download_frames",
        "tcp_fused_frames",
        "tcp_fused_encrypt_buffer_capacity_bytes",
        "tcp_fused_decrypt_buffer_capacity_bytes",
        "tcp_fused_relay_buffer_capacity_removed_bytes",
    ):
        if merged[counter] == 0:
            raise CandidateControlError(f"structural fused-path evidence is absent: {counter}")
    for counter in (
        "tcp_fused_fallback_direct_connections",
        "tcp_fused_fallback_multi_hop_connections",
        "tcp_fused_fallback_tun_connections",
        "tcp_fused_fallback_dns_connections",
        "tcp_fused_fallback_rule_set_connections",
        "tcp_fused_fallback_server_non_direct_connections",
        "tcp_fused_fallback_unsupported_flow_connections",
    ):
        if merged[counter] != 0:
            raise CandidateControlError(f"structural fused-path fallback was observed: {counter}")


def _validate_pending_surface(computed: dict[str, dict[str, int]]) -> None:
    for aggregation in ("client", "server", "merged"):
        counters = computed[aggregation]
        upload_frames = counters["tcp_fused_upload_drain_pending_frames"]
        upload_polls = counters["tcp_fused_upload_drain_pending_polls"]
        download_frames = counters["tcp_fused_download_sink_pending_frames"]
        download_polls = counters["tcp_fused_download_sink_pending_polls"]
        if upload_frames > upload_polls:
            raise CandidateControlError(
                f"structural {aggregation} upload pending frames exceed pending polls"
            )
        if download_frames > download_polls:
            raise CandidateControlError(
                f"structural {aggregation} download pending frames exceed pending polls"
            )
        if upload_frames > counters["tcp_fused_owned_upload_frames"]:
            raise CandidateControlError(
                f"structural {aggregation} upload pending frames exceed owned upload frames"
            )
        if download_frames > counters["tcp_fused_borrowed_download_frames"]:
            raise CandidateControlError(
                f"structural {aggregation} download pending frames exceed borrowed download frames"
            )


def _validate_workload(value: object) -> None:
    if type(value) is not dict:
        raise CandidateControlError("structural workload must be an object")
    _exact_fields(value, frozenset({"checked_bytes", "workers"}), "structural workload")
    _required_u64(value, "checked_bytes", positive=True)
    if _required_u64(value, "workers", positive=True) != 8:
        raise CandidateControlError("structural workload must use the fixed eight workers")


def _validate_cleanup(value: object) -> None:
    if type(value) is not dict:
        raise CandidateControlError("structural cleanup must be an object")
    _exact_fields(
        value,
        frozenset({"active_processes", "active_workers", "rebind_status", "status"}),
        "structural cleanup",
    )
    if _required_u64(value, "active_processes") != 0:
        raise CandidateControlError("structural cleanup retained active processes")
    if _required_u64(value, "active_workers") != 0:
        raise CandidateControlError("structural cleanup retained active workers")
    _required_string(value, "rebind_status", expected="PASS")
    _required_string(value, "status", expected="PASS")
