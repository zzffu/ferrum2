"""network model owner."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from tools.performance_candidate.windows_tun.network_model_identity import NetworkModelError, OBSERVATION_IDENTITY_FIELDS, SCHEMA_VERSION, _fail
from tools.performance_candidate.windows_tun.network_model_lifecycle import FULL_REBUILD_CYCLES, FULL_REBUILD_DAMAGE_REASON, FULL_REBUILD_REASONS, INTERFACE_RESOLVER_PROBES, INTERFACE_SWITCH_PROBE_RETRY_MILLISECONDS, INTERFACE_SWITCH_RECOVERY_TIMEOUT_SECONDS, INTERFACE_SWITCH_SEQUENCE, INTERFACE_SWITCH_TRIAL_RESET_ORDINAL, LIFECYCLE_WORKLOAD, ORDINARY_RESET_REASONS, RESET_CYCLES, RESOURCE_FIELDS, RESOURCE_QUIESCENCE_SECONDS, RESOURCE_WARMUP_RESET_CYCLES, RESOURCE_WARMUP_ROUTE_METRIC_STATES, TOTAL_RESET_CYCLES, summarize_lifecycle_observation
from tools.performance_candidate.windows_tun.network_model_route import ROUTE_DATAGRAMS_PER_TARGET, ROUTE_GENERATIONS, ROUTE_ONCE_WORKLOAD, ROUTE_SOURCE_SLOTS, ROUTE_TARGET_SLOTS, summarize_route_once_observation

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024


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
