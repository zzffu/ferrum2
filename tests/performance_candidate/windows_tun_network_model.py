#!/usr/bin/env python3
"""Deterministic Windows TUN network-model performance controller.

The controller is intentionally independent of a live network.  A local Hyper-V
runner can consume the plan and return bounded JSON observations; this module
then recomputes the route-once and lifecycle measurements from those raw
observations.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import sys
from typing import NoReturn

SCHEMA_VERSION = 6
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ELAPSED_NANOSECONDS = 120 * 1_000_000_000
MAX_ROUTE_ELAPSED_NANOSECONDS = 240 * 1_000_000_000

ROUTE_ONCE_WORKLOAD = "udp-route-once"
LIFECYCLE_WORKLOAD = "network-lifecycle"

ROUTE_GENERATIONS = 2
ROUTE_SOURCE_SLOTS = 64
ROUTE_TARGET_SLOTS = 4
ROUTE_DATAGRAMS_PER_TARGET = 32

ORDINARY_RESET_REASONS = ("route_change", "interface_change")
FULL_REBUILD_REASONS = (
    "adapter_damage",
    "session_damage",
    "address_damage",
    "route_damage",
    "dns_damage",
    "strict_route_damage",
    "ownership_ledger_damage",
)
RESET_CYCLES = 1_000
INTERFACE_SWITCH_SEQUENCE = 500
INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS = 30
INTERFACE_SWITCH_PROBE_RETRY_MILLISECONDS = 250
MAX_INTERFACE_SWITCH_PROBE_ATTEMPTS = (
    INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS * 1_000
    // INTERFACE_SWITCH_PROBE_RETRY_MILLISECONDS
)
FULL_REBUILD_CYCLES = 10
FULL_REBUILD_DAMAGE_REASON = "route_damage"
INTERFACE_RESOLVER_PROBES = 32
RESOURCE_WARMUP_RESET_CYCLES = 12
RESOURCE_WARMUP_ROUTE_METRIC_STATES = 3
RESOURCE_QUIESCENCE_SECONDS = 30
TOTAL_RESET_CYCLES = RESOURCE_WARMUP_RESET_CYCLES + RESET_CYCLES
INTERFACE_SWITCH_TRIAL_RESET_ORDINAL = (
    RESOURCE_WARMUP_RESET_CYCLES + INTERFACE_SWITCH_SEQUENCE
)

RESOURCE_FIELDS = (
    "process_handles",
    "process_threads",
    "udp_associations_active",
    "managed_adapters_active",
)
RESOURCE_LIMITS = {
    "process_handles": 1_000_000,
    "process_threads": 100_000,
    "udp_associations_active": 65_536,
    "managed_adapters_active": 16,
}
LIFECYCLE_METRIC_FIELDS = (
    "network_generation",
    "session_generation",
    "network_reset_total",
    "network_reset_started",
    "network_reset_succeeded",
    "network_reset_failed",
    "full_rebuild_total",
    "full_rebuild_started",
    "full_rebuild_succeeded",
    "full_rebuild_failed",
)
MAX_LIFECYCLE_METRIC = 10_000_000
IDENTITY = re.compile(r"^[0-9a-f]{64}$")
COMMIT_IDENTITY = re.compile(r"^[0-9a-f]{40}$")
RUN_KINDS = frozenset({"comparison", "calibration-aa"})
MEMBERS = frozenset({"parent", "candidate"})
OBSERVATION_IDENTITY_FIELDS = {
    "run_kind",
    "member",
    "pair",
    "trial_sequence",
    "client_pid",
    "server_pid",
    "vm_name",
    "vm_id",
    "checkpoint_name",
    "checkpoint_id",
    "sha",
    "tree",
    "client_sha256",
    "server_sha256",
    "harness_sha256",
    "collector_sha256",
    "recipe_sha256",
    "model_controller_sha256",
    "model_plan_sha256",
}


class NetworkModelError(ValueError):
    """A deterministic workload observation violates the closed contract."""


def create_local_hyperv_plan() -> dict[str, object]:
    """Return the closed, measurement-free local Hyper-V workload plan."""

    return {
        "schema_version": SCHEMA_VERSION,
        "execution": "local_hyperv_guest",
        "host_network_mutation": "forbidden",
        "workloads": {
            ROUTE_ONCE_WORKLOAD: {
                "generations": ROUTE_GENERATIONS,
                "source_slots": ROUTE_SOURCE_SLOTS,
                "target_slots": ROUTE_TARGET_SLOTS,
                "datagrams_per_target": ROUTE_DATAGRAMS_PER_TARGET,
                "required_outbounds": ["direct", "proxy"],
            },
            LIFECYCLE_WORKLOAD: {
                "resource_warmup_reset_cycles": RESOURCE_WARMUP_RESET_CYCLES,
                "resource_warmup_route_metric_states": (
                    RESOURCE_WARMUP_ROUTE_METRIC_STATES
                ),
                "resource_quiescence_seconds": RESOURCE_QUIESCENCE_SECONDS,
                "reset_network_cycles": RESET_CYCLES,
                "total_reset_network_cycles": TOTAL_RESET_CYCLES,
                "full_rebuild_cycles": FULL_REBUILD_CYCLES,
                "ordinary_reset_reasons": list(ORDINARY_RESET_REASONS),
                "full_rebuild_reasons": list(FULL_REBUILD_REASONS),
                "full_rebuild_damage_reason": FULL_REBUILD_DAMAGE_REASON,
                "interface_switch_kind": "approved_underlay_disable_enable",
                "interface_switch_sequence": INTERFACE_SWITCH_SEQUENCE,
                "interface_switch_recovery_timeout_seconds": (
                    INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS
                ),
                "interface_switch_probe_retry_milliseconds": (
                    INTERFACE_SWITCH_PROBE_RETRY_MILLISECONDS
                ),
                "interface_switch_trial_reset_ordinal": (
                    INTERFACE_SWITCH_TRIAL_RESET_ORDINAL
                ),
                "interface_resolver_probes": INTERFACE_RESOLVER_PROBES,
                "terminal_resource_convergence_excluded_from_elapsed": True,
                "latency_percentiles": [50, 95, 99],
                "maximum_retained_resource_growth": {
                    field: 0 for field in RESOURCE_FIELDS
                },
                "retained_resource_growth_enforced_operations": ["reset_network"],
                "diagnostic_resource_growth_operations": ["full_rebuild"],
            },
        },
        "observation_identity_fields": sorted(OBSERVATION_IDENTITY_FIELDS),
    }


def _fail(message: str) -> NoReturn:
    raise NetworkModelError(message)


def _exact_fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} fields mismatch: missing={missing}, extra={extra}")
    return value


def _integer(
    value: object,
    *,
    label: str,
    minimum: int = 0,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _identity(value: object, *, label: str) -> str:
    if type(value) is not str or IDENTITY.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 identity")
    return value


def _resource_snapshot(value: object, *, label: str) -> dict[str, int]:
    snapshot = _exact_fields(value, set(RESOURCE_FIELDS), label)
    return {
        field: _integer(
            snapshot[field],
            label=f"{label}.{field}",
            maximum=RESOURCE_LIMITS[field],
        )
        for field in RESOURCE_FIELDS
    }


def _lifecycle_metric_snapshot(value: object, *, label: str) -> dict[str, int]:
    row = _exact_fields(value, set(LIFECYCLE_METRIC_FIELDS), label)
    snapshot = {
        field: _integer(
            row[field],
            label=f"{label}.{field}",
            minimum=1 if field.endswith("_generation") else 0,
            maximum=MAX_LIFECYCLE_METRIC,
        )
        for field in LIFECYCLE_METRIC_FIELDS
    }
    if snapshot["network_generation"] != snapshot["session_generation"]:
        _fail(f"{label} network and session generations must match")
    for family in ("network_reset", "full_rebuild"):
        known = sum(
            snapshot[f"{family}_{result}"]
            for result in ("started", "succeeded", "failed")
        )
        if snapshot[f"{family}_total"] < known:
            _fail(f"{label}.{family}_total is smaller than its expected reason series")
    return snapshot


def _validate_lifecycle_metric_transition(
    before: dict[str, int],
    after: dict[str, int],
    *,
    operation: str,
    label: str,
) -> None:
    if after["network_generation"] != before["network_generation"] + 1:
        _fail(f"{label} must advance the network generation exactly once")
    if after["session_generation"] != before["session_generation"] + 1:
        _fail(f"{label} must advance the session generation exactly once")

    active_family = "network_reset" if operation == "reset_network" else "full_rebuild"
    inactive_family = "full_rebuild" if operation == "reset_network" else "network_reset"
    expected_deltas: dict[str, int] = {}
    for family in (active_family, inactive_family):
        expected_deltas[f"{family}_started"] = 1 if family == active_family else 0
        expected_deltas[f"{family}_succeeded"] = 1 if family == active_family else 0
        expected_deltas[f"{family}_failed"] = 0
        expected_deltas[f"{family}_total"] = 2 if family == active_family else 0
    for field, expected_delta in expected_deltas.items():
        actual_delta = after[field] - before[field]
        if actual_delta != expected_delta:
            _fail(
                f"{label}.{field} delta must be {expected_delta}, got {actual_delta}"
            )


def _observation_identity(value: object) -> dict[str, object]:
    identity = _exact_fields(value, OBSERVATION_IDENTITY_FIELDS, "observation identity")
    if identity["run_kind"] not in RUN_KINDS or identity["member"] not in MEMBERS:
        _fail("observation identity run_kind/member is invalid")
    _integer(identity["pair"], label="observation identity.pair", minimum=1, maximum=5)
    _integer(
        identity["trial_sequence"],
        label="observation identity.trial_sequence",
        minimum=1,
        maximum=90,
    )
    for field in ("client_pid", "server_pid"):
        _integer(
            identity[field],
            label=f"observation identity.{field}",
            minimum=1,
            maximum=2_147_483_647,
        )
    for field in ("vm_name", "vm_id", "checkpoint_name", "checkpoint_id"):
        if type(identity[field]) is not str or not identity[field].strip():
            _fail(f"observation identity.{field} must be non-empty")
    for field in ("sha", "tree"):
        if type(identity[field]) is not str or COMMIT_IDENTITY.fullmatch(identity[field]) is None:
            _fail(f"observation identity.{field} must be lowercase 40-hex")
    for field in (
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "collector_sha256",
        "recipe_sha256",
        "model_controller_sha256",
        "model_plan_sha256",
    ):
        _identity(identity[field], label=f"observation identity.{field}")
    return identity


def summarize_route_once_observation(observation: object) -> dict[str, object]:
    """Validate and summarize the fixed multi-target UDP workload."""

    row = _exact_fields(
        observation,
        {
            "schema_version",
            "workload",
            "identity",
            "elapsed_nanoseconds",
            "association_creation_elapsed_nanoseconds",
            "association_creations_observed",
            "router_invocations_observed",
            "generations",
        },
        "route-once observation",
    )
    if row["schema_version"] != SCHEMA_VERSION or row["workload"] != ROUTE_ONCE_WORKLOAD:
        _fail("route-once observation schema is unsupported")
    elapsed = _integer(
        row["elapsed_nanoseconds"],
        label="route-once elapsed_nanoseconds",
        minimum=1,
        maximum=MAX_ROUTE_ELAPSED_NANOSECONDS,
    )
    association_elapsed = _integer(
        row["association_creation_elapsed_nanoseconds"],
        label="route-once association_creation_elapsed_nanoseconds",
        minimum=1,
        maximum=elapsed,
    )
    identity = _observation_identity(row["identity"])
    expected_count = ROUTE_GENERATIONS * ROUTE_SOURCE_SLOTS
    association_creations = _integer(
        row["association_creations_observed"],
        label="route-once association_creations_observed",
        maximum=expected_count,
    )
    router_invocations = _integer(
        row["router_invocations_observed"],
        label="route-once router_invocations_observed",
        maximum=expected_count * ROUTE_TARGET_SLOTS,
    )
    if association_creations != expected_count:
        _fail("route-once workload did not create exactly one association per source and generation")
    if router_invocations != expected_count:
        _fail("route-once workload did not invoke the router exactly once per association")
    generations = row["generations"]
    if type(generations) is not list or len(generations) != ROUTE_GENERATIONS:
        _fail(f"route-once workload requires exactly {ROUTE_GENERATIONS} generations")

    datagrams_sent = 0
    direct_datagrams = 0
    proxy_datagrams = 0
    expected_targets = list(range(ROUTE_TARGET_SLOTS))
    expected_datagrams = ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET
    expected_path_datagrams = ROUTE_SOURCE_SLOTS // 2 * expected_datagrams
    prior_network_generation: int | None = None
    for generation_index, generation_value in enumerate(generations, start=1):
        generation_label = f"route-once generation[{generation_index - 1}]"
        generation = _exact_fields(
            generation_value,
            {
                "ordinal",
                "network_generation",
                "session_generation",
                "direct_datagrams_observed",
                "direct_replies_observed",
                "proxy_datagrams_observed",
                "proxy_replies_observed",
                "associations",
            },
            generation_label,
        )
        if generation["ordinal"] != generation_index:
            _fail(f"{generation_label}.ordinal is not contiguous")
        network_generation = _integer(
            generation["network_generation"],
            label=f"{generation_label}.network_generation",
            minimum=1,
            maximum=MAX_LIFECYCLE_METRIC,
        )
        session_generation = _integer(
            generation["session_generation"],
            label=f"{generation_label}.session_generation",
            minimum=1,
            maximum=MAX_LIFECYCLE_METRIC,
        )
        if network_generation != session_generation:
            _fail(f"{generation_label} network and session generations must match")
        if prior_network_generation is not None and network_generation != prior_network_generation + 1:
            _fail("route-once reset must advance the generation exactly once")
        prior_network_generation = network_generation
        for path in ("direct", "proxy"):
            observed_datagrams = _integer(
                generation[f"{path}_datagrams_observed"],
                label=f"{generation_label}.{path}_datagrams_observed",
                maximum=expected_path_datagrams,
            )
            observed_replies = _integer(
                generation[f"{path}_replies_observed"],
                label=f"{generation_label}.{path}_replies_observed",
                maximum=expected_path_datagrams,
            )
            if observed_datagrams != expected_path_datagrams or observed_replies != expected_path_datagrams:
                _fail(f"{generation_label} did not observe the exact {path} traffic split")
            if path == "direct":
                direct_datagrams += observed_datagrams
            else:
                proxy_datagrams += observed_datagrams
        associations = generation["associations"]
        if type(associations) is not list or len(associations) != ROUTE_SOURCE_SLOTS:
            _fail(f"{generation_label} requires exactly {ROUTE_SOURCE_SLOTS} associations")
        observed_sources: set[int] = set()
        for association_index, association_value in enumerate(associations):
            label = f"{generation_label}.association[{association_index}]"
            association = _exact_fields(
                association_value,
                {
                    "source_slot",
                    "target_slots",
                    "first_target_slot",
                    "datagrams_sent",
                    "replies_received",
                },
                label,
            )
            source_slot = _integer(
                association["source_slot"],
                label=f"{label}.source_slot",
                maximum=ROUTE_SOURCE_SLOTS - 1,
            )
            if source_slot in observed_sources:
                _fail(f"{generation_label} source slot {source_slot} is duplicated")
            observed_sources.add(source_slot)
            if association["target_slots"] != expected_targets:
                _fail(f"{label}.target_slots does not cover the deterministic target set")
            expected_first_target = 0 if source_slot % 2 == 0 else 1
            if association["first_target_slot"] != expected_first_target:
                _fail(f"{label}.first_target_slot does not select the closed outbound split")
            if association["datagrams_sent"] != expected_datagrams:
                _fail(f"{label}.datagrams_sent does not match the workload recipe")
            if association["replies_received"] != expected_datagrams:
                _fail(f"{label}.replies_received does not account for every datagram")
            datagrams_sent += expected_datagrams
        if observed_sources != set(range(ROUTE_SOURCE_SLOTS)):
            _fail(f"{generation_label} does not cover every source slot")

    per_target_baseline = expected_count * ROUTE_TARGET_SLOTS
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": ROUTE_ONCE_WORKLOAD,
        "identity": dict(identity),
        "associations_created": association_creations,
        "datagrams_sent": datagrams_sent,
        "direct_datagrams_observed": direct_datagrams,
        "proxy_datagrams_observed": proxy_datagrams,
        "packets_per_second": datagrams_sent * 1_000_000_000 // elapsed,
        "associations_per_second": association_creations * 1_000_000_000
        // association_elapsed,
        "router_invocations": router_invocations,
        "per_target_routing_baseline": per_target_baseline,
        "router_invocations_avoided": per_target_baseline - router_invocations,
        "direct_and_proxy_verified": True,
        "route_once_verified": True,
        "post_reset_reroute_verified": True,
    }


def _nearest_rank(values: list[int], percentile: int) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered) / 100) - 1]


def _latency_summary(values: list[int]) -> dict[str, int]:
    return {
        "count": len(values),
        "minimum": min(values),
        "p50": _nearest_rank(values, 50),
        "p95": _nearest_rank(values, 95),
        "p99": _nearest_rank(values, 99),
        "maximum": max(values),
    }


def _resource_accounting(
    baseline: dict[str, int],
    samples: list[dict[str, int]],
    *,
    label: str,
    retained_growth_enforced: bool,
) -> dict[str, object]:
    final = samples[-1]
    growth = {field: final[field] - baseline[field] for field in RESOURCE_FIELDS}
    peak = {
        field: max([baseline[field], *(sample[field] for sample in samples)])
        for field in RESOURCE_FIELDS
    }
    peak_growth = {field: peak[field] - baseline[field] for field in RESOURCE_FIELDS}
    positive = {field: value for field, value in growth.items() if value > 0}
    if retained_growth_enforced and positive:
        _fail(f"{label} retained resource growth is not zero: {positive}")
    return {
        "baseline": dict(baseline),
        "final": dict(final),
        "growth": growth,
        "peak": peak,
        "peak_growth": peak_growth,
        "retained_growth_enforced": retained_growth_enforced,
    }


def _validate_resource_warmup(
    value: object, *, baseline: dict[str, int]
) -> tuple[dict[str, object], dict[str, int], str]:
    warmup = _exact_fields(
        value,
        {
            "reset_network_cycles",
            "route_metric_baseline",
            "quiescence_seconds",
            "cold_start_resources",
            "cycles",
            "baseline_resource_samples",
        },
        "resource_warmup",
    )
    cycle_count = _integer(
        warmup["reset_network_cycles"],
        label="resource_warmup.reset_network_cycles",
        minimum=RESOURCE_WARMUP_RESET_CYCLES,
        maximum=RESOURCE_WARMUP_RESET_CYCLES,
    )
    route_metric_baseline = _integer(
        warmup["route_metric_baseline"],
        label="resource_warmup.route_metric_baseline",
        maximum=65_535,
    )
    quiescence_seconds = _integer(
        warmup["quiescence_seconds"],
        label="resource_warmup.quiescence_seconds",
        minimum=RESOURCE_QUIESCENCE_SECONDS,
        maximum=RESOURCE_QUIESCENCE_SECONDS,
    )
    cold_start = _resource_snapshot(
        warmup["cold_start_resources"],
        label="resource_warmup.cold_start_resources",
    )
    if cold_start["process_handles"] == 0 or cold_start["process_threads"] == 0:
        _fail("resource warmup cold-start process resources must be nonzero")
    if cold_start["udp_associations_active"] != 0:
        _fail("resource warmup cold-start state must not contain a UDP association")
    if cold_start["managed_adapters_active"] != 1:
        _fail("resource warmup cold-start state must contain exactly one managed adapter")

    if route_metric_baseline <= 65_533:
        route_metric_states = (
            route_metric_baseline + 1,
            route_metric_baseline + 2,
            route_metric_baseline,
        )
    elif route_metric_baseline >= 2:
        route_metric_states = (
            route_metric_baseline - 1,
            route_metric_baseline - 2,
            route_metric_baseline,
        )
    else:  # pragma: no cover - the uint16 range makes this unreachable
        _fail("resource warmup route metric has no bounded three-state mutation")

    cycles = warmup["cycles"]
    if type(cycles) is not list or len(cycles) != cycle_count:
        _fail(f"resource warmup requires exactly {cycle_count} cycles")
    previous_metrics: dict[str, int] | None = None
    previous_identity: str | None = None
    previous_route_metric = route_metric_baseline
    resource_samples: list[dict[str, int]] = []
    for index, cycle_value in enumerate(cycles):
        label = f"resource_warmup.cycle[{index}]"
        cycle = _exact_fields(
            cycle_value,
            {
                "sequence",
                "operation",
                "reason",
                "route_metric_before",
                "route_metric_after",
                "lifecycle_metrics_before",
                "lifecycle_metrics_after",
                "managed_identity_before",
                "managed_identity_after",
                "tcp_flows_before",
                "udp_associations_before",
                "tcp_flows_closed",
                "udp_associations_closed",
                "tcp_probe_succeeded",
                "udp_probe_succeeded",
                "resources_after",
            },
            label,
        )
        sequence = _integer(
            cycle["sequence"],
            label=f"{label}.sequence",
            minimum=1,
            maximum=cycle_count,
        )
        if sequence != index + 1:
            _fail(f"{label}.sequence is not contiguous")
        if cycle["operation"] != "reset_network" or cycle["reason"] != "route_change":
            _fail(f"{label} must be a route-change ResetNetwork")

        route_before = _integer(
            cycle["route_metric_before"],
            label=f"{label}.route_metric_before",
            maximum=65_535,
        )
        route_after = _integer(
            cycle["route_metric_after"],
            label=f"{label}.route_metric_after",
            maximum=65_535,
        )
        expected_route_after = route_metric_states[index % len(route_metric_states)]
        if route_before != previous_route_metric or route_after != expected_route_after:
            _fail(f"{label} does not follow the bounded three-state route schedule")
        previous_route_metric = route_after

        metrics_before = _lifecycle_metric_snapshot(
            cycle["lifecycle_metrics_before"],
            label=f"{label}.lifecycle_metrics_before",
        )
        metrics_after = _lifecycle_metric_snapshot(
            cycle["lifecycle_metrics_after"],
            label=f"{label}.lifecycle_metrics_after",
        )
        if previous_metrics is not None and metrics_before != previous_metrics:
            _fail(f"{label} lifecycle metrics do not continue the prior warmup cycle")
        _validate_lifecycle_metric_transition(
            metrics_before,
            metrics_after,
            operation="reset_network",
            label=label,
        )
        previous_metrics = metrics_after

        identity_before = _identity(
            cycle["managed_identity_before"],
            label=f"{label}.managed_identity_before",
        )
        identity_after = _identity(
            cycle["managed_identity_after"],
            label=f"{label}.managed_identity_after",
        )
        if previous_identity is not None and identity_before != previous_identity:
            _fail(f"{label} managed identity does not continue the prior warmup cycle")
        if identity_before != identity_after:
            _fail(f"{label} changed managed identity during warmup ResetNetwork")
        previous_identity = identity_after

        tcp_before = _integer(
            cycle["tcp_flows_before"],
            label=f"{label}.tcp_flows_before",
            maximum=65_536,
        )
        udp_before = _integer(
            cycle["udp_associations_before"],
            label=f"{label}.udp_associations_before",
            minimum=1,
            maximum=65_536,
        )
        if cycle["tcp_flows_closed"] != tcp_before:
            _fail(f"{label} did not close every TCP flow")
        if cycle["udp_associations_closed"] != udp_before:
            _fail(f"{label} did not close every UDP association")
        if (
            cycle["tcp_probe_succeeded"] is not True
            or cycle["udp_probe_succeeded"] is not True
        ):
            _fail(f"{label} did not recover both TCP and UDP probes")

        resources = _resource_snapshot(
            cycle["resources_after"], label=f"{label}.resources_after"
        )
        if resources["process_handles"] == 0 or resources["process_threads"] == 0:
            _fail(f"{label} process resources must be nonzero")
        if resources["udp_associations_active"] != 0:
            _fail(f"{label} retained a UDP association after warmup ResetNetwork")
        if resources["managed_adapters_active"] != 1:
            _fail(f"{label} changed the managed adapter count")
        resource_samples.append(resources)

    if previous_route_metric != route_metric_baseline:
        _fail("resource warmup route schedule did not restore its baseline")
    baseline_samples_value = warmup["baseline_resource_samples"]
    if type(baseline_samples_value) is not list or len(baseline_samples_value) != 3:
        _fail("resource warmup requires exactly three stable baseline resource samples")
    baseline_samples = [
        _resource_snapshot(sample, label=f"resource_warmup.baseline_resource_samples[{index}]")
        for index, sample in enumerate(baseline_samples_value)
    ]
    if any(sample != baseline for sample in baseline_samples):
        _fail("resource warmup baseline resource samples are not stable and exact")
    resource_samples.extend(baseline_samples)
    initialization_growth = {
        field: baseline[field] - cold_start[field] for field in RESOURCE_FIELDS
    }
    peak = {
        field: max([cold_start[field], *(sample[field] for sample in resource_samples)])
        for field in RESOURCE_FIELDS
    }
    return (
        {
            "reset_network_cycles": cycle_count,
            "measured_reset_network_cycles": RESET_CYCLES,
            "total_reset_network_cycles": TOTAL_RESET_CYCLES,
            "interface_switch_trial_reset_ordinal": (
                INTERFACE_SWITCH_TRIAL_RESET_ORDINAL
            ),
            "route_metric_baseline": route_metric_baseline,
            "route_metric_restored": True,
            "quiescence_seconds": quiescence_seconds,
            "terminal_resource_convergence_excluded_from_elapsed": True,
            "cold_start_resources": cold_start,
            "baseline_resources": dict(baseline),
            "initialization_growth": initialization_growth,
            "peak": peak,
        },
        previous_metrics,
        previous_identity,
    )


def summarize_lifecycle_observation(observation: object) -> dict[str, object]:
    """Validate reset/rebuild semantics and recompute latency/resource summaries."""

    row = _exact_fields(
        observation,
        {
            "schema_version",
            "workload",
            "identity",
            "resource_warmup",
            "baseline_resources",
            "cycles",
            "interface_resolver",
        },
        "lifecycle observation",
    )
    if row["schema_version"] != SCHEMA_VERSION or row["workload"] != LIFECYCLE_WORKLOAD:
        _fail("lifecycle observation schema is unsupported")
    identity = _observation_identity(row["identity"])
    baseline = _resource_snapshot(row["baseline_resources"], label="baseline_resources")
    if baseline["process_handles"] == 0 or baseline["process_threads"] == 0:
        _fail("lifecycle baseline process resources must be nonzero")
    if baseline["udp_associations_active"] != 0:
        _fail("lifecycle baseline must not contain a UDP association")
    if baseline["managed_adapters_active"] != 1:
        _fail("lifecycle baseline must contain exactly one managed adapter")
    warmup_summary, previous_lifecycle_metrics, previous_identity = (
        _validate_resource_warmup(row["resource_warmup"], baseline=baseline)
    )
    cycles = row["cycles"]
    expected_count = RESET_CYCLES + FULL_REBUILD_CYCLES
    if type(cycles) is not list or len(cycles) != expected_count:
        _fail(f"lifecycle workload requires exactly {expected_count} cycles")

    reset_latencies: list[int] = []
    rebuild_latencies: list[int] = []
    reset_resources: list[dict[str, int]] = []
    rebuild_resources: list[dict[str, int]] = []
    for index, cycle_value in enumerate(cycles):
        label = f"lifecycle cycle[{index}]"
        cycle = _exact_fields(
            cycle_value,
            {
                "sequence",
                "operation",
                "reason",
                "elapsed_nanoseconds",
                "lifecycle_metrics_before",
                "lifecycle_metrics_after",
                "managed_identity_before",
                "managed_identity_after",
                "tcp_flows_before",
                "udp_associations_before",
                "tcp_flows_closed",
                "udp_associations_closed",
                "tcp_probe_succeeded",
                "udp_probe_succeeded",
                "resources_after",
            },
            label,
        )
        sequence = _integer(
            cycle["sequence"],
            label=f"{label}.sequence",
            minimum=1,
            maximum=expected_count,
        )
        if sequence != index + 1:
            _fail(f"{label}.sequence is not contiguous")
        lifecycle_before = _lifecycle_metric_snapshot(
            cycle["lifecycle_metrics_before"],
            label=f"{label}.lifecycle_metrics_before",
        )
        lifecycle_after = _lifecycle_metric_snapshot(
            cycle["lifecycle_metrics_after"],
            label=f"{label}.lifecycle_metrics_after",
        )
        if (
            previous_lifecycle_metrics is not None
            and lifecycle_before != previous_lifecycle_metrics
        ):
            _fail(f"{label} lifecycle metrics do not continue the prior cycle")
        previous_lifecycle_metrics = lifecycle_after
        identity_before = _identity(
            cycle["managed_identity_before"], label=f"{label}.managed_identity_before"
        )
        identity_after = _identity(
            cycle["managed_identity_after"], label=f"{label}.managed_identity_after"
        )
        if previous_identity is not None and identity_before != previous_identity:
            _fail(f"{label} managed identity does not continue the prior cycle")
        previous_identity = identity_after
        elapsed = _integer(
            cycle["elapsed_nanoseconds"],
            label=f"{label}.elapsed_nanoseconds",
            minimum=1,
            maximum=MAX_ELAPSED_NANOSECONDS,
        )
        tcp_before = _integer(
            cycle["tcp_flows_before"],
            label=f"{label}.tcp_flows_before",
            maximum=65_536,
        )
        udp_before = _integer(
            cycle["udp_associations_before"],
            label=f"{label}.udp_associations_before",
            minimum=1,
            maximum=65_536,
        )
        if cycle["tcp_flows_closed"] != tcp_before:
            _fail(f"{label} did not close every TCP flow")
        if cycle["udp_associations_closed"] != udp_before:
            _fail(f"{label} did not close every UDP association")
        if (
            cycle["tcp_probe_succeeded"] is not True
            or cycle["udp_probe_succeeded"] is not True
        ):
            _fail(f"{label} did not recover both TCP and UDP probes")
        resources = _resource_snapshot(cycle["resources_after"], label=f"{label}.resources_after")
        if resources["udp_associations_active"] != 0:
            _fail(f"{label} retained a UDP association after lifecycle transition")
        if resources["managed_adapters_active"] != baseline["managed_adapters_active"]:
            _fail(f"{label} changed the managed adapter count")

        if sequence <= RESET_CYCLES:
            expected_reason = (
                "interface_change"
                if sequence == INTERFACE_SWITCH_SEQUENCE
                else "route_change"
            )
            if cycle["operation"] != "reset_network" or cycle["reason"] != expected_reason:
                _fail(f"{label} does not match the ordinary ResetNetwork schedule")
            _validate_lifecycle_metric_transition(
                lifecycle_before,
                lifecycle_after,
                operation="reset_network",
                label=label,
            )
            if identity_before != identity_after:
                _fail(f"{label} changed managed identity during ResetNetwork")
            reset_latencies.append(elapsed)
            reset_resources.append(resources)
        else:
            expected_reason = FULL_REBUILD_DAMAGE_REASON
            if cycle["operation"] != "full_rebuild" or cycle["reason"] != expected_reason:
                _fail(f"{label} does not match the managed-damage rebuild schedule")
            _validate_lifecycle_metric_transition(
                lifecycle_before,
                lifecycle_after,
                operation="full_rebuild",
                label=label,
            )
            rebuild_latencies.append(elapsed)
            rebuild_resources.append(resources)

    switch_cycle = cycles[INTERFACE_SWITCH_SEQUENCE - 1]
    if (
        switch_cycle["elapsed_nanoseconds"]
        > INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS * 1_000_000_000
    ):
        _fail("interface switch did not recover within its bounded timeout")
    resolver = _exact_fields(
        row["interface_resolver"],
        {
            "probes",
            "resolutions",
            "cache_hits",
            "interface_switch_probe_attempts",
            "interface_switch_resolution_failures",
        },
        "interface_resolver",
    )
    probes = _integer(
        resolver["probes"],
        label="interface_resolver.probes",
        minimum=INTERFACE_RESOLVER_PROBES,
        maximum=INTERFACE_RESOLVER_PROBES,
    )
    resolutions = _integer(
        resolver["resolutions"],
        label="interface_resolver.resolutions",
        minimum=probes,
        maximum=probes * 8,
    )
    cache_hits = _integer(
        resolver["cache_hits"],
        label="interface_resolver.cache_hits",
        minimum=1,
        maximum=resolutions,
    )
    interface_switch_probe_attempts = _integer(
        resolver["interface_switch_probe_attempts"],
        label="interface_resolver.interface_switch_probe_attempts",
        minimum=1,
        maximum=MAX_INTERFACE_SWITCH_PROBE_ATTEMPTS,
    )
    interface_switch_resolution_failures = _integer(
        resolver["interface_switch_resolution_failures"],
        label="interface_resolver.interface_switch_resolution_failures",
        maximum=MAX_INTERFACE_SWITCH_PROBE_ATTEMPTS - 1,
    )
    if interface_switch_resolution_failures != interface_switch_probe_attempts - 1:
        _fail("interface switch probe attempt accounting is inconsistent")

    reset_accounting = _resource_accounting(
        baseline,
        reset_resources,
        label="ResetNetwork",
        retained_growth_enforced=True,
    )
    rebuild_accounting = _resource_accounting(
        reset_resources[-1],
        rebuild_resources,
        label="full rebuild",
        retained_growth_enforced=False,
    )
    reset_latency = _latency_summary(reset_latencies)
    rebuild_latency = _latency_summary(rebuild_latencies)
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": LIFECYCLE_WORKLOAD,
        "identity": identity,
        "resource_warmup": warmup_summary,
        "cycles": {
            "reset_network": RESET_CYCLES,
            "full_rebuild": FULL_REBUILD_CYCLES,
        },
        "latency_nanoseconds": {
            "reset_network": reset_latency,
            "full_rebuild": rebuild_latency,
            "full_rebuild_p95_over_reset_p95_basis_points": (
                rebuild_latency["p95"] * 10_000 // reset_latency["p95"]
            ),
        },
        "resources": {
            "reset_network": reset_accounting,
            "full_rebuild": rebuild_accounting,
        },
        "managed_identity_preserved_across_resets": True,
        "connections_closed": True,
        "damage_only_full_rebuild": True,
        "reset_and_full_rebuild_metrics_are_exact": True,
        "tcp_and_udp_recovered_each_cycle": True,
        "interface_switch_recovery_nanoseconds": switch_cycle["elapsed_nanoseconds"],
        "interface_switch_kind": "approved_underlay_disable_enable",
        "interface_resolver": {
            "probes": probes,
            "resolutions": resolutions,
            "cache_hits": cache_hits,
            "cache_hits_per_million_resolutions": cache_hits * 1_000_000 // resolutions,
            "interface_switch_probe_attempts": interface_switch_probe_attempts,
            "interface_switch_resolution_failures": interface_switch_resolution_failures,
        },
    }


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_observation(path: pathlib.Path) -> object:
    """Read a bounded UTF-8 JSON observation and reject duplicate object keys."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise NetworkModelError(f"unable to read observation {path}") from error
    if len(raw) > MAX_ARTIFACT_BYTES:
        _fail(f"observation exceeds {MAX_ARTIFACT_BYTES} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkModelError("observation is not canonical UTF-8 JSON") from error


def summarize_observation(observation: object) -> dict[str, object]:
    if type(observation) is not dict:
        _fail("observation must be an object")
    workload = observation.get("workload")
    if workload == ROUTE_ONCE_WORKLOAD:
        return summarize_route_once_observation(observation)
    if workload == LIFECYCLE_WORKLOAD:
        return summarize_lifecycle_observation(observation)
    _fail("observation workload is unsupported")


def _write_json(path: pathlib.Path, value: object) -> None:
    try:
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        path.write_bytes(encoded)
    except OSError as error:
        raise NetworkModelError(f"unable to write output {path}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--output", type=pathlib.Path, required=True)
    summarize_parser = subparsers.add_parser("summarize")
    summarize_parser.add_argument("--input", type=pathlib.Path, required=True)
    summarize_parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "plan":
            result = create_local_hyperv_plan()
        else:
            result = summarize_observation(load_observation(arguments.input))
        _write_json(arguments.output, result)
    except NetworkModelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
