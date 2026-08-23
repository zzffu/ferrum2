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

SCHEMA_VERSION = 2
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ELAPSED_NANOSECONDS = 120 * 1_000_000_000

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
FULL_REBUILD_CYCLES = 10
FULL_REBUILD_DAMAGE_REASON = "route_damage"
INTERFACE_RESOLVER_PROBES = 32

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
                "reset_network_cycles": RESET_CYCLES,
                "full_rebuild_cycles": FULL_REBUILD_CYCLES,
                "ordinary_reset_reasons": list(ORDINARY_RESET_REASONS),
                "full_rebuild_reasons": list(FULL_REBUILD_REASONS),
                "full_rebuild_damage_reason": FULL_REBUILD_DAMAGE_REASON,
                "interface_switch_kind": "approved_underlay_disable_enable",
                "interface_switch_sequence": INTERFACE_SWITCH_SEQUENCE,
                "interface_resolver_probes": INTERFACE_RESOLVER_PROBES,
                "latency_percentiles": [50, 95, 99],
                "maximum_retained_resource_growth": {
                    field: 0 for field in RESOURCE_FIELDS
                },
            },
        },
        "lifecycle_observation_identity_fields": sorted(OBSERVATION_IDENTITY_FIELDS),
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
        maximum=80,
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
        {"schema_version", "workload", "elapsed_nanoseconds", "associations"},
        "route-once observation",
    )
    if row["schema_version"] != SCHEMA_VERSION or row["workload"] != ROUTE_ONCE_WORKLOAD:
        _fail("route-once observation schema is unsupported")
    elapsed = _integer(
        row["elapsed_nanoseconds"],
        label="route-once elapsed_nanoseconds",
        minimum=1,
        maximum=MAX_ELAPSED_NANOSECONDS,
    )
    associations = row["associations"]
    expected_count = ROUTE_GENERATIONS * ROUTE_SOURCE_SLOTS
    if type(associations) is not list or len(associations) != expected_count:
        _fail(f"route-once workload requires exactly {expected_count} associations")

    expected_keys = {
        (generation, source_slot)
        for generation in range(1, ROUTE_GENERATIONS + 1)
        for source_slot in range(ROUTE_SOURCE_SLOTS)
    }
    observed_keys: set[tuple[int, int]] = set()
    datagrams_sent = 0
    router_invocations = 0
    egress_instances = 0
    expected_targets = list(range(ROUTE_TARGET_SLOTS))
    expected_datagrams = ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET
    for index, association_value in enumerate(associations):
        label = f"route-once association[{index}]"
        association = _exact_fields(
            association_value,
            {
                "generation",
                "source_slot",
                "target_slots",
                "datagrams_sent",
                "router_invocations",
                "association_commits",
                "egress_instances",
                "frozen_outbound",
            },
            label,
        )
        generation = _integer(
            association["generation"],
            label=f"{label}.generation",
            minimum=1,
            maximum=ROUTE_GENERATIONS,
        )
        source_slot = _integer(
            association["source_slot"],
            label=f"{label}.source_slot",
            maximum=ROUTE_SOURCE_SLOTS - 1,
        )
        key = (generation, source_slot)
        if key in observed_keys:
            _fail(f"route-once association key {key} is duplicated")
        observed_keys.add(key)
        if association["target_slots"] != expected_targets:
            _fail(f"{label}.target_slots does not cover the deterministic target set")
        if association["datagrams_sent"] != expected_datagrams:
            _fail(f"{label}.datagrams_sent does not match the workload recipe")
        if association["router_invocations"] != 1:
            _fail(f"{label} must invoke the router exactly once")
        if association["association_commits"] != 1:
            _fail(f"{label} must commit exactly one association")
        if association["egress_instances"] != 1:
            _fail(f"{label} must create exactly one multi-target egress")
        expected_outbound = "direct" if source_slot % 2 == 0 else "proxy"
        if association["frozen_outbound"] != expected_outbound:
            _fail(f"{label}.frozen_outbound does not match the first-route decision")
        datagrams_sent += expected_datagrams
        router_invocations += 1
        egress_instances += 1

    if observed_keys != expected_keys:
        _fail("route-once association keys do not cover both generations and all sources")
    per_target_baseline = expected_count * ROUTE_TARGET_SLOTS
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": ROUTE_ONCE_WORKLOAD,
        "associations_created": expected_count,
        "datagrams_sent": datagrams_sent,
        "packets_per_second": datagrams_sent * 1_000_000_000 // elapsed,
        "associations_per_second": expected_count * 1_000_000_000 // elapsed,
        "router_invocations": router_invocations,
        "per_target_routing_baseline": per_target_baseline,
        "router_invocations_avoided": per_target_baseline - router_invocations,
        "egress_instances": egress_instances,
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
    baseline: dict[str, int], samples: list[dict[str, int]], *, label: str
) -> dict[str, object]:
    final = samples[-1]
    growth = {field: final[field] - baseline[field] for field in RESOURCE_FIELDS}
    peak = {
        field: max([baseline[field], *(sample[field] for sample in samples)])
        for field in RESOURCE_FIELDS
    }
    peak_growth = {field: peak[field] - baseline[field] for field in RESOURCE_FIELDS}
    positive = {field: value for field, value in growth.items() if value > 0}
    if positive:
        _fail(f"{label} retained resource growth is not zero: {positive}")
    return {
        "baseline": dict(baseline),
        "final": dict(final),
        "growth": growth,
        "peak": peak,
        "peak_growth": peak_growth,
    }


def summarize_lifecycle_observation(observation: object) -> dict[str, object]:
    """Validate reset/rebuild semantics and recompute latency/resource summaries."""

    row = _exact_fields(
        observation,
        {
            "schema_version",
            "workload",
            "identity",
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
    cycles = row["cycles"]
    expected_count = RESET_CYCLES + FULL_REBUILD_CYCLES
    if type(cycles) is not list or len(cycles) != expected_count:
        _fail(f"lifecycle workload requires exactly {expected_count} cycles")

    reset_latencies: list[int] = []
    rebuild_latencies: list[int] = []
    reset_resources: list[dict[str, int]] = []
    rebuild_resources: list[dict[str, int]] = []
    previous_identity: str | None = None
    previous_lifecycle_metrics: dict[str, int] | None = None
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
    resolver = _exact_fields(
        row["interface_resolver"],
        {"probes", "resolutions", "cache_hits"},
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

    reset_accounting = _resource_accounting(
        baseline, reset_resources, label="ResetNetwork"
    )
    rebuild_accounting = _resource_accounting(
        reset_resources[-1], rebuild_resources, label="full rebuild"
    )
    reset_latency = _latency_summary(reset_latencies)
    rebuild_latency = _latency_summary(rebuild_latencies)
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": LIFECYCLE_WORKLOAD,
        "identity": identity,
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
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
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
