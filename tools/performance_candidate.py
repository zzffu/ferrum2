#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from decimal import Decimal
from fractions import Fraction

WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
MODES = frozenset({"diagnostic", "qualification"})
PLAN_SCHEMA_VERSION = 6
PROFILE_TRIAL_SCHEMA_VERSION = 4
SUMMARY_SCHEMA_VERSION = 7
REGULAR_TRIAL_MAX_BYTES = 16 * 1024
SCALE_TRIAL_MAX_BYTES = 512 * 1024
SCALE_SCENARIO = "tcp-scale-10k"
UDP_IDLE_SCENARIO = "udp-idle-4096"
# This reachable pre-event baseline already allocates receive storage only after
# readiness, but still scans every live mapping every 50 ms. Binding it isolates
# the T3 liveness change from the earlier receive-buffer change.
UDP_IDLE_QUALIFICATION_PARENT_SHA = "2d6cf6428c7da0bd49dd54722463a5dab45756fe"
UDP_IDLE_QUALIFICATION_BASELINE = (
    "pre-event-50ms-full-live-mapping-reconcile-after-readiness-buffering"
)
SCALE_POLICY_SCHEMA_VERSION = 1
UDP_IDLE_POLICY_SCHEMA_VERSION = 1
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
UDP_IDLE_RECIPE = {
    "sessions": 4_096,
    "setup_workers": 256,
    "payload_bytes": 128,
    "setup_deadline_seconds": 20,
    "setup_schedule_lead_milliseconds": 500,
    "setup_send_spacing_microseconds": 2_000,
    "warmup_seconds": 3,
    "active_seconds": 30,
    "active_elapsed_maximum_slack_milliseconds": 250,
    "idle_timeout_milliseconds": 60_000,
    "drain_timeout_seconds": 120,
    "server_max_buffered_bytes": 256 * 1024 * 1024,
    "measurement_process": "ferrum2-server",
    "traffic_path": "loopback-direct-sip022-server",
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
        "udp_idle",
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
UDP_IDLE_POLICY_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "required_pairs",
        "required_sessions",
        "candidate_maximum_percent_of_parent",
        "minimum_wins_beyond_noise",
        "noise_ticks",
        "minimum_saved_ticks",
        "minimum_parent_signal_ticks",
        "clock_ticks_per_second",
        "qualification_parent_sha",
        "calibration_source",
        "calibration_environment",
    }
)
UDP_IDLE_POLICY_RUNTIME_FIELDS = frozenset(
    {*UDP_IDLE_POLICY_DOCUMENT_FIELDS, "policy_sha256"}
)
UDP_IDLE_FIELDS = frozenset(
    {"schema_version", "recipe", "correctness", "cpu", "resource"}
)
UDP_IDLE_CORRECTNESS_FIELDS = frozenset(
    {
        "requests_sent",
        "target_echoed",
        "responses_validated",
        "generator_workers_joined",
        "retained_sessions",
        "server_active_before",
        "server_active_after",
        "server_active_drained",
        "server_buffered_before",
        "server_buffered_after",
        "server_buffered_drained",
        "accepted_client_to_target",
        "completed_target_to_client",
        "drain",
        "rebind",
        "cleanup",
    }
)
UDP_IDLE_CPU_FIELDS = frozenset(
    {
        "process_start_time_ticks",
        "start_ticks",
        "end_ticks",
        "delta_ticks",
        "clock_ticks_per_second",
        "elapsed_nanoseconds",
    }
)
UDP_IDLE_RESOURCE_FIELDS = frozenset(
    {"setup_elapsed_nanoseconds", "pre_load", "established", "after_idle_window", "drained"}
)
UDP_IDLE_SAMPLE_FIELDS = frozenset(
    {
        "active_sessions",
        "buffered_bytes",
        "fds",
        "tasks",
        "rss_kib",
        "smaps_rss_kib",
        "anonymous_kib",
        "anon_huge_pages_kib",
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


def _udp_idle_scenario_entry() -> dict[str, object]:
    return {
        "scenario": UDP_IDLE_SCENARIO,
        "role": "idle_cpu_qualification",
        "mandatory": True,
        "metric": "server_cpu_ticks",
        "direction": "lower_is_better",
        "topology": "shadowsocks-server",
        "application_payload_bytes": UDP_IDLE_RECIPE["payload_bytes"],
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
    udp_idle_cpu_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the authoritative scenario plan for one manual workflow run."""

    if mode not in MODES:
        raise CandidateControlError("mode must be diagnostic or qualification")
    if mode == "diagnostic" and selection not in SCENARIO_CATALOG:
        raise CandidateControlError("diagnostic selection must be one profile workload")
    if mode == "qualification" and selection not in (
        set(SCENARIO_CATALOG)
        | set(QUALIFICATION_GROUPS)
        | {SCALE_SCENARIO, UDP_IDLE_SCENARIO}
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
    is_udp_idle = selection == UDP_IDLE_SCENARIO
    if is_scale:
        if mode != "qualification":
            raise CandidateControlError("tcp-scale-10k is qualification-only")
        if udp_idle_cpu_policy is not None:
            raise CandidateControlError("UDP idle CPU policy is invalid for tcp-scale-10k")
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
    elif is_udp_idle:
        if mode != "qualification":
            raise CandidateControlError("udp-idle-4096 is qualification-only")
        if (warmup, active, pair_count) != (3, 30, 5):
            raise CandidateControlError("udp-idle-4096 requires the exact 3/30/5 recipe")
        if udp_idle_cpu_policy is None:
            raise CandidateControlError("udp-idle-4096 requires its dedicated CPU policy")
        if scale_safety_policy is not None or scale_lineage is not None:
            raise CandidateControlError("scale inputs are invalid for udp-idle-4096")
        validate_udp_idle_cpu_policy(udp_idle_cpu_policy)
        scenario_group = UDP_IDLE_SCENARIO
        scenarios = [_udp_idle_scenario_entry()]
    elif scale_safety_policy is not None or scale_lineage is not None:
        raise CandidateControlError("scale policy and lineage are only valid for tcp-scale-10k")
    elif udp_idle_cpu_policy is not None:
        raise CandidateControlError("UDP idle CPU policy is only valid for udp-idle-4096")
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
            selection
            if selection in SCENARIO_CATALOG or is_scale or is_udp_idle
            else None
        ),
        "scenario_group": scenario_group,
        "warmup_seconds": warmup,
        "active_seconds": active,
        "pairs": pair_count,
        "measurement_environment": dict(MEASUREMENT_ENVIRONMENT),
        "decision_policy": policy,
        "scale_safety_policy": copy.deepcopy(scale_safety_policy),
        "scale_lineage": copy.deepcopy(scale_lineage),
        "udp_idle_cpu_policy": copy.deepcopy(udp_idle_cpu_policy),
        "adoption_eligible": not is_scale
        and not is_udp_idle
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


def validate_udp_idle_cpu_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("UDP idle CPU policy must be a JSON object")
    _exact_fields(policy, UDP_IDLE_POLICY_RUNTIME_FIELDS, "UDP idle CPU policy")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != UDP_IDLE_POLICY_SCHEMA_VERSION
    ):
        raise CandidateControlError("UDP idle CPU policy schema_version is unsupported")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("UDP idle CPU policy_id must be non-empty")
    digest = policy["policy_sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise CandidateControlError("UDP idle CPU policy must have a SHA-256 identity")
    exact = {
        "required_pairs": 5,
        "required_sessions": UDP_IDLE_RECIPE["sessions"],
        "candidate_maximum_percent_of_parent": 50,
        "minimum_wins_beyond_noise": 4,
    }
    for field, expected in exact.items():
        if type(policy[field]) is not int or policy[field] != expected:
            raise CandidateControlError(f"UDP idle CPU policy {field} must be {expected}")
    calibration_fields = (
        "noise_ticks",
        "minimum_saved_ticks",
        "minimum_parent_signal_ticks",
        "clock_ticks_per_second",
        "qualification_parent_sha",
        "calibration_source",
        "calibration_environment",
    )
    values = [policy[field] for field in calibration_fields]
    if all(value is None for value in values):
        return
    if any(value is None for value in values):
        raise CandidateControlError(
            "UDP idle CPU policy calibration must be complete or entirely null"
        )
    for field in ("noise_ticks", "minimum_saved_ticks", "minimum_parent_signal_ticks"):
        value = policy[field]
        if type(value) is not int or not 0 <= value <= U64_MAX:
            raise CandidateControlError(f"UDP idle CPU policy {field} must be u64")
    clock_ticks_per_second = policy["clock_ticks_per_second"]
    if (
        type(clock_ticks_per_second) is not int
        or not 0 < clock_ticks_per_second <= U64_MAX
    ):
        raise CandidateControlError(
            "UDP idle CPU policy clock_ticks_per_second must be positive u64"
        )
    noise = policy["noise_ticks"]
    if policy["minimum_saved_ticks"] < noise + 1:
        raise CandidateControlError("UDP idle CPU minimum_saved_ticks is inside noise")
    required_signal = max(2, 2 * (noise + 1))
    if policy["minimum_parent_signal_ticks"] < required_signal:
        raise CandidateControlError("UDP idle CPU parent signal floor is too weak")
    source = policy["calibration_source"]
    if type(source) is not str or re.fullmatch(r"(?:artifact|commit):\S+", source) is None:
        raise CandidateControlError("UDP idle CPU calibration_source is invalid")
    if policy["qualification_parent_sha"] != UDP_IDLE_QUALIFICATION_PARENT_SHA:
        raise CandidateControlError(
            "UDP idle CPU qualification_parent_sha must bind the pre-event 50 ms reconcile baseline"
        )
    environment = policy["calibration_environment"]
    if type(environment) is not dict:
        raise CandidateControlError("UDP idle CPU calibration_environment is required")
    _exact_fields(
        environment,
        CALIBRATION_ENVIRONMENT_FIELDS,
        "UDP idle CPU calibration_environment",
    )
    expected_environment = {
        **MEASUREMENT_ENVIRONMENT,
        "warmup_seconds": UDP_IDLE_RECIPE["warmup_seconds"],
        "active_seconds": UDP_IDLE_RECIPE["active_seconds"],
    }
    if environment != expected_environment:
        raise CandidateControlError("UDP idle CPU calibration_environment is unsupported")


def load_udp_idle_cpu_policy(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        document = _strict_json(raw.decode("utf-8"), source="UDP idle CPU policy")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read UDP idle CPU policy") from error
    if type(document) is not dict:
        raise CandidateControlError("UDP idle CPU policy must be a JSON object")
    _exact_fields(document, UDP_IDLE_POLICY_DOCUMENT_FIELDS, "UDP idle CPU policy")
    policy = {**document, "policy_sha256": hashlib.sha256(raw).hexdigest()}
    validate_udp_idle_cpu_policy(policy)
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
    udp_idle_cpu_policy: dict[str, object] | None = None,
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
        selected_udp_idle_policy = (
            plan.get("udp_idle_cpu_policy")
            if udp_idle_cpu_policy is None
            else udp_idle_cpu_policy
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
            udp_idle_cpu_policy=selected_udp_idle_policy,
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


def _validate_udp_idle_sample(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError(f"{field} must be an object")
    _exact_fields(value, UDP_IDLE_SAMPLE_FIELDS, field)
    for key in UDP_IDLE_SAMPLE_FIELDS:
        _scale_u64(value[key], f"{field}.{key}")
    return value


def _validate_udp_idle_evidence(row: dict[str, object]) -> dict[str, object]:
    evidence = row["udp_idle"]
    if type(evidence) is not dict:
        raise CandidateControlError("udp-idle-4096 evidence requires an udp_idle object")
    _exact_fields(evidence, UDP_IDLE_FIELDS, "UDP idle evidence")
    if _scale_u64(evidence["schema_version"], "udp_idle.schema_version") != 1:
        raise CandidateControlError("UDP idle evidence schema_version is unsupported")

    recipe = evidence["recipe"]
    if type(recipe) is not dict:
        raise CandidateControlError("UDP idle recipe must be an object")
    _exact_fields(recipe, frozenset(UDP_IDLE_RECIPE), "UDP idle recipe")
    for field, expected in UDP_IDLE_RECIPE.items():
        value = recipe[field]
        if type(expected) is int:
            value = _scale_u64(value, f"udp_idle.recipe.{field}")
        if value != expected:
            raise CandidateControlError(f"UDP idle recipe {field} does not match")

    correctness = evidence["correctness"]
    if type(correctness) is not dict:
        raise CandidateControlError("UDP idle correctness must be an object")
    _exact_fields(correctness, UDP_IDLE_CORRECTNESS_FIELDS, "UDP idle correctness")
    for field in UDP_IDLE_CORRECTNESS_FIELDS - {"drain", "rebind", "cleanup"}:
        _scale_u64(correctness[field], f"udp_idle.correctness.{field}")
    for field in ("drain", "rebind", "cleanup"):
        if correctness[field] != "PASS":
            raise CandidateControlError(f"UDP idle correctness {field} must pass")
    sessions = UDP_IDLE_RECIPE["sessions"]
    exact_counts = {
        "requests_sent": sessions,
        "target_echoed": sessions,
        "responses_validated": sessions,
        "generator_workers_joined": UDP_IDLE_RECIPE["setup_workers"],
        "retained_sessions": sessions,
        "server_active_before": 0,
        "server_active_after": sessions,
        "server_active_drained": 0,
        "accepted_client_to_target": sessions,
        "completed_target_to_client": sessions,
    }
    for field, expected in exact_counts.items():
        if correctness[field] != expected:
            raise CandidateControlError(f"UDP idle correctness {field} is inconsistent")
    baseline_buffered = correctness["server_buffered_before"]
    if (
        not 0 < baseline_buffered <= UDP_IDLE_RECIPE["server_max_buffered_bytes"]
        or correctness["server_buffered_after"] != baseline_buffered
        or correctness["server_buffered_drained"] != baseline_buffered
    ):
        raise CandidateControlError(
            "UDP idle buffered-byte lifecycle did not preserve the root baseline"
        )

    cpu = evidence["cpu"]
    if type(cpu) is not dict:
        raise CandidateControlError("UDP idle CPU evidence must be an object")
    _exact_fields(cpu, UDP_IDLE_CPU_FIELDS, "UDP idle CPU evidence")
    for field in UDP_IDLE_CPU_FIELDS:
        _scale_u64(cpu[field], f"udp_idle.cpu.{field}")
    if cpu["process_start_time_ticks"] == 0 or cpu["clock_ticks_per_second"] == 0:
        raise CandidateControlError("UDP idle CPU identity is incomplete")
    if cpu["end_ticks"] < cpu["start_ticks"]:
        raise CandidateControlError("UDP idle CPU ticks moved backwards")
    delta = cpu["end_ticks"] - cpu["start_ticks"]
    if cpu["delta_ticks"] != delta:
        raise CandidateControlError("UDP idle CPU delta is inconsistent")
    minimum_elapsed = UDP_IDLE_RECIPE["active_seconds"] * 1_000_000_000
    maximum_elapsed = minimum_elapsed + (
        UDP_IDLE_RECIPE["active_elapsed_maximum_slack_milliseconds"] * 1_000_000
    )
    if not minimum_elapsed <= cpu["elapsed_nanoseconds"] <= maximum_elapsed:
        raise CandidateControlError("UDP idle CPU elapsed window is outside its strict bound")

    resource = evidence["resource"]
    if type(resource) is not dict:
        raise CandidateControlError("UDP idle resource evidence must be an object")
    _exact_fields(resource, UDP_IDLE_RESOURCE_FIELDS, "UDP idle resource evidence")
    setup_elapsed = _scale_u64(
        resource["setup_elapsed_nanoseconds"],
        "udp_idle.resource.setup_elapsed_nanoseconds",
    )
    if not 0 < setup_elapsed <= UDP_IDLE_RECIPE["setup_deadline_seconds"] * 1_000_000_000:
        raise CandidateControlError("UDP idle setup elapsed time is outside its bound")
    samples = {
        field: _validate_udp_idle_sample(resource[field], f"udp_idle.resource.{field}")
        for field in ("pre_load", "established", "after_idle_window", "drained")
    }
    expected_active = {
        "pre_load": 0,
        "established": sessions,
        "after_idle_window": sessions,
        "drained": 0,
    }
    for field, expected in expected_active.items():
        if samples[field]["active_sessions"] != expected:
            raise CandidateControlError(f"UDP idle resource {field} active count is inconsistent")
    for field in ("pre_load", "established", "after_idle_window", "drained"):
        if samples[field]["buffered_bytes"] != baseline_buffered:
            raise CandidateControlError(
                f"UDP idle resource {field} buffered bytes changed from the root baseline"
            )
    expected_established_fds = samples["pre_load"]["fds"] + sessions
    if (
        expected_established_fds > U64_MAX
        or samples["established"]["fds"] != expected_established_fds
    ):
        raise CandidateControlError(
            "UDP idle established descriptor count does not prove every target socket"
        )
    for field in ("fds", "tasks"):
        if samples["after_idle_window"][field] != samples["established"][field]:
            raise CandidateControlError(
                f"UDP idle {field} changed during the CPU window"
            )
        if samples["drained"][field] != samples["pre_load"][field]:
            raise CandidateControlError(f"UDP idle drained {field} did not return to baseline")
    if row["value"] != delta or row["checked_units"] != sessions:
        raise CandidateControlError("UDP idle top-level CPU/session evidence is inconsistent")
    if row["io_completions"] != sessions * 2:
        raise CandidateControlError("UDP idle top-level I/O accounting is inconsistent")
    return {"delta_ticks": delta, "samples": samples}


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
    is_scale = scenario == SCALE_SCENARIO
    is_udp_idle = scenario == UDP_IDLE_SCENARIO
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
    for field in ("runner_sha256", "server_sha256"):
        _require_pattern(_required_string(row, field), SHA256, field=field)
    if is_udp_idle:
        if row["client_sha256"] is not None:
            raise CandidateControlError(
                "udp-idle-4096 evidence must mark the unused client binary null"
            )
    else:
        _require_pattern(
            _required_string(row, "client_sha256"), SHA256, field="client_sha256"
        )
    for field in ("rustc", "kernel", "cpu_model"):
        _required_string(row, field)
    _required_u64(row, "cpu_count", positive=True)
    _required_u64(row, "memory_kib", positive=True)
    metric = _required_string(row, "metric", expected=planned[scenario]["metric"])
    value = _required_u64(row, "value")
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
        if row["udp_idle"] is not None:
            raise CandidateControlError("tcp-scale-10k evidence must have null udp_idle")
    elif is_udp_idle:
        if row["scale"] is not None:
            raise CandidateControlError("udp-idle-4096 evidence must have null scale")
        _validate_udp_idle_evidence(row)
    elif row["scale"] is not None:
        raise CandidateControlError("ordinary profile evidence must have null scale")
    elif row["udp_idle"] is not None:
        raise CandidateControlError("ordinary profile evidence must have null udp_idle")
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
        "udp_idle_cpu_policy": None,
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
        "udp_idle_cpu": None,
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }


def _odd_integer_median(values: Sequence[int], field: str) -> int:
    if not values or len(values) % 2 == 0:
        raise CandidateControlError(f"{field} requires a nonempty odd vector")
    return sorted(values)[len(values) // 2]


def _summarize_udp_idle_evidence(
    *,
    plan: dict[str, object],
    rows: dict[tuple[str, int, str], dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
    member_identity: dict[str, tuple[object, ...]],
    identity_fields: tuple[str, ...],
    evidence_files: list[dict[str, str]],
) -> dict[str, object]:
    policy = plan["udp_idle_cpu_policy"]
    validate_udp_idle_cpu_policy(policy)
    if (
        policy["qualification_parent_sha"] is not None
        and parent_sha != policy["qualification_parent_sha"]
    ):
        raise CandidateControlError(
            "UDP idle CPU summary does not use the bound pre-event 50 ms reconcile baseline"
        )
    parent_ticks: list[int] = []
    candidate_ticks: list[int] = []
    saved_ticks: list[int] = []
    clock_tick_rates: set[int] = set()
    pairs: list[dict[str, object]] = []
    for pair in range(1, plan["pairs"] + 1):
        parent = rows[(UDP_IDLE_SCENARIO, pair, "parent")]
        candidate = rows[(UDP_IDLE_SCENARIO, pair, "candidate")]
        if {parent["order"], candidate["order"]} != {1, 2}:
            raise CandidateControlError(f"UDP idle pair={pair} must contain orders 1 and 2")
        expected_parent_order = 1 if pair % 2 else 2
        if parent["order"] != expected_parent_order:
            raise CandidateControlError(f"UDP idle pair={pair} does not alternate order")
        parent_delta = _validate_udp_idle_evidence(parent)["delta_ticks"]
        candidate_delta = _validate_udp_idle_evidence(candidate)["delta_ticks"]
        clock_tick_rates.update(
            (
                parent["udp_idle"]["cpu"]["clock_ticks_per_second"],
                candidate["udp_idle"]["cpu"]["clock_ticks_per_second"],
            )
        )
        saved = parent_delta - candidate_delta
        parent_ticks.append(parent_delta)
        candidate_ticks.append(candidate_delta)
        saved_ticks.append(saved)
        pairs.append(
            {
                "pair": pair,
                "parent_order": parent["order"],
                "candidate_order": candidate["order"],
                "parent_cpu_ticks": parent_delta,
                "candidate_cpu_ticks": candidate_delta,
                "saved_ticks": saved,
            }
        )
    if len(clock_tick_rates) != 1:
        raise CandidateControlError("UDP idle clock-tick rate changed between trials")
    clock_tick_rate = next(iter(clock_tick_rates))
    parent_median = _odd_integer_median(parent_ticks, "UDP idle parent median")
    candidate_median = _odd_integer_median(candidate_ticks, "UDP idle candidate median")
    median_saved = _odd_integer_median(saved_ticks, "UDP idle saved median")
    calibrated = policy["noise_ticks"] is not None
    if calibrated and clock_tick_rate != policy["clock_ticks_per_second"]:
        raise CandidateControlError(
            "UDP idle clock-tick rate does not match the A/A calibrated policy"
        )
    tree_index = identity_fields.index("tree")
    runner_index = identity_fields.index("runner_sha256")
    if (
        member_identity["parent"][runner_index]
        != member_identity["candidate"][runner_index]
    ):
        raise CandidateControlError(
            "UDP idle parent and candidate evidence must use one identical harness"
        )
    trees_equal = (
        member_identity["parent"][tree_index]
        == member_identity["candidate"][tree_index]
    )
    if not calibrated and not trees_equal:
        raise CandidateControlError(
            "UDP idle A/A calibration requires identical parent and candidate source trees"
        )
    if calibrated and trees_equal:
        raise CandidateControlError(
            "UDP idle calibrated A/B requires different parent and candidate source trees"
        )
    observed_noise = None if calibrated else max(abs(value) for value in saved_ticks)
    if observed_noise is not None and observed_noise > (U64_MAX - 2) // 2:
        raise CandidateControlError("UDP idle A/A noise calibration arithmetic overflows u64")
    failures: list[str] = []
    wins_beyond_noise: int | None = None
    if calibrated:
        noise = policy["noise_ticks"]
        wins_beyond_noise = sum(saved > noise for saved in saved_ticks)
        if parent_median < policy["minimum_parent_signal_ticks"]:
            failures.append("PARENT_SIGNAL_FLOOR")
        if (
            candidate_median * 100
            > parent_median * policy["candidate_maximum_percent_of_parent"]
        ):
            failures.append("MEDIAN_REDUCTION")
        if median_saved < policy["minimum_saved_ticks"]:
            failures.append("MEDIAN_SAVED_TICKS")
        if wins_beyond_noise < policy["minimum_wins_beyond_noise"]:
            failures.append("WINS_BEYOND_NOISE")
        for pair, (parent_tick, candidate_tick) in enumerate(
            zip(parent_ticks, candidate_ticks, strict=True), start=1
        ):
            if candidate_tick > parent_tick + noise:
                failures.append(f"PAIR_{pair}_REGRESSION_BEYOND_NOISE")
        status = "UDP_IDLE_CPU_QUALIFICATION_PASS" if not failures else "UDP_IDLE_CPU_QUALIFICATION_FAIL"
        decision_reason = (
            "all dedicated UDP idle CPU qualification gates passed"
            if not failures
            else "one or more dedicated UDP idle CPU qualification gates failed"
        )
        threshold_availability = "idle_cpu"
    else:
        status = "UDP_IDLE_CPU_UNCALIBRATED"
        decision_reason = "A/A evidence measured noise; policy thresholds remain uncalibrated"
        threshold_availability = "uncalibrated"
    failures = sorted(set(failures))
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    ratio = (
        None
        if parent_median == 0
        else _display_decimal(
            Decimal(candidate_median) * Decimal(100) / Decimal(parent_median)
        )
    )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selection": plan["selection"],
        "selected_scenario": UDP_IDLE_SCENARIO,
        "scenario_group": UDP_IDLE_SCENARIO,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": build_identities,
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "scale_safety_policy": None,
        "scale_lineage": None,
        "udp_idle_cpu_policy": policy,
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": calibrated,
        "candidate_win_enabled": False,
        "decision_reason": decision_reason,
        "threshold_availability": threshold_availability,
        "adoption_claim": False,
        "status": status,
        "workflow_failure_reason": None if not failures else "; ".join(failures),
        "mandatory_scenarios": [UDP_IDLE_SCENARIO],
        "missing_scenarios": [],
        "primary_results": [],
        "guard_results": [],
        "scenarios": [{"scenario": UDP_IDLE_SCENARIO, "status": status}],
        "scale_safety": None,
        "udp_idle_cpu": {
            "schema_version": 1,
            "status": (
                "UNCALIBRATED"
                if not calibrated
                else ("PASS" if not failures else "FAIL")
            ),
            "failures": failures,
            "parent_median_ticks": parent_median,
            "candidate_median_ticks": candidate_median,
            "candidate_median_percent_of_parent": ratio,
            "median_saved_ticks": median_saved,
            "wins_beyond_noise": wins_beyond_noise,
            "observed_noise_ticks": observed_noise,
            "recommended_noise_ticks": (
                policy["noise_ticks"] if calibrated else observed_noise
            ),
            "recommended_minimum_saved_ticks": (
                policy["minimum_saved_ticks"] if calibrated else observed_noise + 1
            ),
            "recommended_minimum_parent_signal_ticks": (
                policy["minimum_parent_signal_ticks"]
                if calibrated
                else max(2, 2 * (observed_noise + 1))
            ),
            "clock_ticks_per_second": clock_tick_rate,
            "recommended_clock_ticks_per_second": (
                policy["clock_ticks_per_second"] if calibrated else clock_tick_rate
            ),
            "qualification_parent_sha": UDP_IDLE_QUALIFICATION_PARENT_SHA,
            "qualification_baseline": UDP_IDLE_QUALIFICATION_BASELINE,
            "pairs": pairs,
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
    is_udp_idle = plan["selection"] == UDP_IDLE_SCENARIO
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
    if is_udp_idle:
        return _summarize_udp_idle_evidence(
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
        "udp_idle_cpu_policy": None,
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
        "udp_idle_cpu": None,
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
        "udp_idle_cpu_policy": copy.deepcopy(
            plan.get("udp_idle_cpu_policy") if plan is not None else None
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
        "udp_idle_cpu": None,
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
    if summary["selection"] == UDP_IDLE_SCENARIO:
        idle = summary["udp_idle_cpu"]
        lines.extend(
            [
                f"- Mode: `{summary['mode']}`",
                f"- UDP idle CPU qualification: **{idle['status']}**",
                f"- Dedicated policy: `{summary['udp_idle_cpu_policy']['policy_id']}` "
                f"(`{summary['udp_idle_cpu_policy']['policy_sha256']}`)",
                f"- Decision: {summary['decision_reason']}",
                f"- Parent/candidate median ticks: `{idle['parent_median_ticks']} / "
                f"{idle['candidate_median_ticks']}`",
                f"- Candidate median % of parent: `"
                f"{idle['candidate_median_percent_of_parent'] if idle['candidate_median_percent_of_parent'] is not None else '-'}`",
                f"- Observed/recommended noise ticks: `"
                f"{idle['observed_noise_ticks'] if idle['observed_noise_ticks'] is not None else '-'} / "
                f"{idle['recommended_noise_ticks']}`",
                f"- Recommended saved/signal floors: `"
                f"{idle['recommended_minimum_saved_ticks']} / "
                f"{idle['recommended_minimum_parent_signal_ticks']}`",
                f"- Observed/recommended CLK_TCK: `{idle['clock_ticks_per_second']} / "
                f"{idle['recommended_clock_ticks_per_second']}`",
                f"- Bound A/B parent: `{idle['qualification_parent_sha']}`",
                f"- Bound A/B scope: `{idle['qualification_baseline']}`",
                f"- Failures: `{', '.join(idle['failures']) or '-'}`",
                "- This qualification is not an adoption claim.",
                "",
                "| Pair | Parent order/ticks | Candidate order/ticks | Saved ticks |",
                "|---:|---|---|---:|",
            ]
        )
        for pair in idle["pairs"]:
            lines.append(
                f"| {pair['pair']} | {pair['parent_order']} / {pair['parent_cpu_ticks']} | "
                f"{pair['candidate_order']} / {pair['candidate_cpu_ticks']} | "
                f"{pair['saved_ticks']} |"
            )
        lines.append("")
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
        idle_policy_path = getattr(parsed, "idle_cpu_policy", None)
        idle_policy = (
            None
            if idle_policy_path is None
            else load_udp_idle_cpu_policy(idle_policy_path)
        )
        plan = load_plan(
            parsed.plan,
            decision_policy=decision_policy,
            scale_safety_policy=scale_policy,
            udp_idle_cpu_policy=idle_policy,
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
        "UDP_IDLE_CPU_UNCALIBRATED",
        "UDP_IDLE_CPU_QUALIFICATION_PASS",
    }:
        return 0
    if summary["status"] in {
        "REGRESSION",
        "SCALE_SAFETY_FAIL",
        "UDP_IDLE_CPU_QUALIFICATION_FAIL",
    }:
        message = (
            "dedicated tcp-scale safety gate failed"
            if summary["status"] == "SCALE_SAFETY_FAIL"
            else (
                "dedicated UDP idle CPU qualification failed"
                if summary["status"] == "UDP_IDLE_CPU_QUALIFICATION_FAIL"
                else "calibrated mandatory scenario regressed"
            )
        )
        print(f"performance-candidate: {message}", file=sys.stderr)
        return 3
    print("performance-candidate: unknown summary status", file=sys.stderr)
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
    plan.add_argument("--idle-cpu-policy", type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    scenarios = commands.add_parser(
        "scenarios", help="emit planned scenario names, one per line"
    )
    scenarios.add_argument("--plan", required=True, type=pathlib.Path)
    scenarios.add_argument("--policy", required=True, type=pathlib.Path)
    scenarios.add_argument("--scale-policy", type=pathlib.Path)
    scenarios.add_argument("--idle-cpu-policy", type=pathlib.Path)
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
    summary.add_argument("--idle-cpu-policy", type=pathlib.Path)
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
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    if parsed.command == "summarize":
        return run_summary_command(parsed)
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
            idle_policy = (
                None
                if parsed.idle_cpu_policy is None
                else load_udp_idle_cpu_policy(parsed.idle_cpu_policy)
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
                udp_idle_cpu_policy=idle_policy,
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
            idle_policy = (
                None
                if parsed.idle_cpu_policy is None
                else load_udp_idle_cpu_policy(parsed.idle_cpu_policy)
            )
            plan = load_plan(
                parsed.plan,
                decision_policy=decision_policy,
                scale_safety_policy=scale_policy,
                udp_idle_cpu_policy=idle_policy,
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
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
