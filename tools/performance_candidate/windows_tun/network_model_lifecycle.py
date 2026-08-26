"""network model lifecycle owner."""

from __future__ import annotations

import math


from tools.performance_candidate.windows_tun.network_model_identity import MAX_LIFECYCLE_METRIC, SCHEMA_VERSION, _exact_fields, _fail, _identity, _integer, _observation_identity

MAX_ELAPSED_NANOSECONDS = 120 * 1_000_000_000


LIFECYCLE_WORKLOAD = "network-lifecycle"


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
