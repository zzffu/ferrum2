"""Validation for one raw Windows-host TUN performance trial."""

from __future__ import annotations

import math
import re

from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields
from tools.performance_candidate.windows_tun.recipe import (
    WINDOWS_TUN_TOPOLOGIES,
    WINDOWS_TUN_WORKLOAD_CHECKS,
    WINDOWS_TUN_WORKLOAD_MEASUREMENTS,
)

WINDOWS_TUN_TRIAL_MAX_BYTES = 512 * 1024
_TRIAL_FIELDS = frozenset(
    {
        "run_id",
        "performance_source_bundle_sha256",
        "schema_version",
        "kind",
        "sequence",
        "pair",
        "order",
        "topology",
        "scenario",
        "member",
        "commit_sha",
        "metric",
        "unit",
        "direction",
        "value",
        "warmup_seconds",
        "active_seconds",
        "cpu_sample_seconds",
        "io_completions",
        "p99_nanoseconds",
        "client_cpu_percent",
        "server_present",
        "server_cpu_percent",
        "client_peak_working_set_bytes",
        "server_peak_working_set_bytes",
        "client_failure_counter_delta",
        "server_failure_counter_delta",
        "checked_units",
        "loopback_interface_index",
        "loopback_interface_alias",
        "route_proofs",
        "workload_measurements",
        "workload_checks",
        "status",
    }
)
_ROUTE_FIELDS = frozenset(
    {
        "purpose",
        "remote_address",
        "local_address",
        "interface_index",
        "interface_alias",
        "destination_prefix",
        "next_hop",
    }
)


def _finite_positive(value: object, field: str, *, allow_zero: bool = False) -> float:
    if type(value) not in {int, float}:
        raise CandidateControlError(f"{field} must be a finite number")
    number = float(value)
    if not math.isfinite(number) or number < 0 or (number == 0 and not allow_zero):
        raise CandidateControlError(f"{field} is outside its finite positive contract")
    return number


def _positive_int(value: object, field: str) -> int:
    if type(value) is not int or not 0 < value <= 2**64 - 1:
        raise CandidateControlError(f"{field} must be a positive uint64 integer")
    return value


def _run_network_identity(run_id: str) -> tuple[str, str]:
    value = int(run_id[:4], 16)
    third = (value >> 8) & 0xFF
    block = (value & 0xFF) % 63 * 4
    return f"198.18.{third}.{block + 2}", f"198.19.{third}.{block + 1}"


def _validate_route_proofs(
    value: object,
    *,
    run_id: str,
    sequence: int,
    topology: str,
    loopback_interface_index: int,
    loopback_interface_alias: str,
) -> None:
    if topology not in WINDOWS_TUN_TOPOLOGIES:
        raise CandidateControlError("Windows TUN trial topology is invalid")
    direct = topology == "ClientDirect"
    expected_purposes = [
        "benchmark-application-to-test-tun",
        (
            "client-direct-to-support-without-test-tun"
            if direct
            else "server-to-support-without-test-tun"
        ),
    ]
    if not direct:
        expected_purposes.append("product-underlay-control")
    expected_purposes.append("sing-box-proxy-excluded")
    if type(value) is not list or len(value) != len(expected_purposes):
        raise CandidateControlError("Windows TUN trial route proof count changed")
    if [row.get("purpose") for row in value if type(row) is dict] != expected_purposes:
        raise CandidateControlError("Windows TUN trial route proof purpose closure changed")
    tun_address, support_address = _run_network_identity(run_id)
    expected_alias = f"Ferrum2Perf-{run_id}-{sequence:03d}"
    expected_endpoints = [
        (support_address, tun_address, f"{support_address}/32"),
        (support_address, support_address, f"{support_address}/32"),
    ]
    if not direct:
        expected_endpoints.append(("127.0.0.1", "127.0.0.1", "127.0.0.1/32"))
    expected_endpoints.append(("127.0.0.1", "127.0.0.1", "127.0.0.1/32"))
    for index, (row, endpoints) in enumerate(zip(value, expected_endpoints, strict=True)):
        if type(row) is not dict:
            raise CandidateControlError("Windows TUN route proof must be an object")
        _exact_fields(row, _ROUTE_FIELDS, "Windows TUN route proof")
        if type(row["interface_index"]) is not int or row["interface_index"] <= 0:
            raise CandidateControlError("Windows TUN route proof interface index is invalid")
        remote_address, local_address, destination_prefix = endpoints
        if (
            row["remote_address"] != remote_address
            or row["local_address"] != local_address
            or row["destination_prefix"] != destination_prefix
            or row["next_hop"] != "0.0.0.0"
        ):
            raise CandidateControlError("Windows TUN route proof is not bound to its RunId")
        if index == 0:
            if row["interface_alias"] != expected_alias:
                raise CandidateControlError(
                    "benchmark traffic did not prove the run-owned TUN path"
                )
        elif (
            row["interface_index"] != loopback_interface_index
            or row["interface_alias"] != loopback_interface_alias
        ):
            raise CandidateControlError("egress/control traffic did not prove loopback exclusion")


def _validate_workload_measurements(trial: dict[str, object]) -> None:
    scenario = str(trial["scenario"])
    expected = WINDOWS_TUN_WORKLOAD_MEASUREMENTS.get(scenario)
    measurements = trial["workload_measurements"]
    if expected is None or type(measurements) is not dict or frozenset(measurements) != expected:
        raise CandidateControlError("Windows TUN workload measurement closure is invalid")
    for name, value in measurements.items():
        if name == "tail_checked_units":
            if type(value) is not int or not 0 <= value <= 2**64 - 1:
                raise CandidateControlError("tail_checked_units must be a uint64 integer")
        else:
            _positive_int(value, f"workload_measurements.{name}")
    primary = measurements[str(trial["metric"])]
    if not math.isclose(float(trial["value"]), float(primary), rel_tol=0.0, abs_tol=0.0):
        raise CandidateControlError("Windows TUN primary metric does not match workload evidence")
    if trial["io_completions"] != measurements["io_completions"]:
        raise CandidateControlError("Windows TUN I/O completion count does not match workload evidence")
    if "p99_nanoseconds" in measurements:
        if not (
            measurements["p50_nanoseconds"]
            <= measurements["p95_nanoseconds"]
            <= measurements["p99_nanoseconds"]
        ):
            raise CandidateControlError("Windows TUN latency percentiles are unordered")
        if measurements["latency_samples"] != min(trial["checked_units"], 2_000_000):
            raise CandidateControlError("Windows TUN latency sample count does not match checked work")
    expected_p99 = measurements.get("p99_nanoseconds")
    if trial["p99_nanoseconds"] != expected_p99:
        raise CandidateControlError("Windows TUN p99 latency does not match workload evidence")
    _validate_workload_accounting(trial)


def _validate_workload_accounting(trial: dict[str, object]) -> None:
    scenario = str(trial["scenario"])
    measurements = trial["workload_measurements"]
    checked = trial["checked_units"]
    minimum, alignment = {
        "tcp-single-flow": (64 * 1024 * 1024, 65536),
        "tcp-request-1k-p99": (1024, 1),
        "tcp-256-flow-fairness": (256 * 16384, 16384),
        "udp-packets-per-second": (4096, 1),
        "fragment-reassembly-throughput": (4096, 4),
    }[scenario]
    if checked < minimum or checked % alignment:
        raise CandidateControlError("Windows TUN checked work violates workload coverage or alignment")
    if scenario == "fragment-reassembly-throughput":
        if measurements["io_completions"] < checked * 2 or measurements["io_completions"] % 2:
            raise CandidateControlError("fragment I/O completions omit checked work")
    elif measurements["io_completions"] != checked // alignment * 2:
        raise CandidateControlError("Windows TUN I/O completions contradict checked work")
    if scenario == "tcp-single-flow":
        if measurements["cpu_payload_bytes"] < checked or measurements["cpu_payload_bytes"] % alignment:
            raise CandidateControlError("TCP total payload does not cover checked work")
    elapsed = measurements["active_elapsed_nanoseconds"]
    nominal = _positive_int(trial["active_seconds"], "active_seconds") * 1_000_000_000
    tail = measurements["tail_checked_units"]
    tail_limit = {
        "tcp-single-flow": 65536,
        "tcp-request-1k-p99": 1,
        "tcp-256-flow-fairness": 256 * 16384,
        "udp-packets-per-second": 1,
        "fragment-reassembly-throughput": 4,
    }[scenario]
    if (
        elapsed < nominal
        or tail > min(checked, tail_limit)
        or tail % alignment
        or (tail == 0) != (elapsed == nominal)
        or float(trial["cpu_sample_seconds"]) * 1_000_000_000 < elapsed
    ):
        raise CandidateControlError("Windows TUN active window or tail accounting is inconsistent")
    rate_contract = {
        "tcp-single-flow": ("throughput", 1),
        "udp-packets-per-second": ("packet_rate", 1),
        "tcp-256-flow-fairness": ("aggregate_throughput", 1),
        "fragment-reassembly-throughput": ("reassembly_rate", 1440),
    }.get(scenario)
    if rate_contract is not None:
        field, payload = rate_contract
        units = checked * payload
        if units > 2**64 - 1 or measurements[field] != max(1, units * 1_000_000_000 // elapsed):
            raise CandidateControlError("Windows TUN rate contradicts checked work and actual elapsed time")
    if scenario == "tcp-256-flow-fairness" and not 1_000_000_000 // 256 <= measurements["fairness"] <= 1_000_000_000:
        raise CandidateControlError("Windows TUN fairness is outside its Jain index range")


def validate_windows_tun_trial(
    value: object,
    *,
    planned_trial: dict[str, object],
    run_id: str,
    performance_source_bundle_sha256: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError("Windows TUN host trial must be a JSON object")
    trial = value
    _exact_fields(trial, _TRIAL_FIELDS, "Windows TUN host trial")
    if (
        type(trial["schema_version"]) is not int
        or trial["schema_version"] != 4
        or trial["kind"] != "ferrum2.windows-tun.host-performance-trial"
        or type(trial["run_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{12}", trial["run_id"]) is None
        or trial["run_id"] != run_id
        or trial["performance_source_bundle_sha256"]
        != performance_source_bundle_sha256
        or trial["status"] != "PASS"
    ):
        raise CandidateControlError("Windows TUN host trial identity is invalid")
    for field in (
        "sequence",
        "pair",
        "order",
        "topology",
        "scenario",
        "member",
        "commit_sha",
        "metric",
        "unit",
        "direction",
        "warmup_seconds",
        "active_seconds",
    ):
        if trial[field] != planned_trial[field]:
            raise CandidateControlError(f"Windows TUN trial {field} does not match its plan")
    _finite_positive(trial["value"], "value")
    cpu_sample_seconds = _finite_positive(
        trial["cpu_sample_seconds"], "cpu_sample_seconds"
    )
    if not (
        float(trial["active_seconds"])
        <= cpu_sample_seconds
        <= float(trial["active_seconds"]) + 60.0
    ):
        raise CandidateControlError("Windows TUN trial CPU sample window is invalid")
    _positive_int(trial["io_completions"], "io_completions")
    _positive_int(trial["checked_units"], "checked_units")
    _positive_int(trial["client_peak_working_set_bytes"], "client_peak_working_set_bytes")
    _finite_positive(trial["client_cpu_percent"], "client_cpu_percent", allow_zero=True)
    if trial["client_failure_counter_delta"] != 0:
        raise CandidateControlError("Windows TUN trial recorded a client failure counter")
    server_present = trial["topology"] == "EndToEnd"
    if trial["server_present"] is not server_present:
        raise CandidateControlError("Windows TUN server presence does not match topology")
    if server_present:
        _finite_positive(trial["server_cpu_percent"], "server_cpu_percent", allow_zero=True)
        _positive_int(
            trial["server_peak_working_set_bytes"], "server_peak_working_set_bytes"
        )
        if trial["server_failure_counter_delta"] != 0:
            raise CandidateControlError("Windows TUN trial recorded a server failure counter")
    elif any(
        trial[field] is not None
        for field in (
            "server_cpu_percent",
            "server_peak_working_set_bytes",
            "server_failure_counter_delta",
        )
    ):
        raise CandidateControlError("client-direct trial retained server measurements")
    _validate_workload_measurements(trial)
    loopback_index = trial["loopback_interface_index"]
    loopback_alias = trial["loopback_interface_alias"]
    if (
        type(loopback_index) is not int
        or loopback_index <= 0
        or type(loopback_alias) is not str
        or not loopback_alias
    ):
        raise CandidateControlError("Windows TUN loopback identity is invalid")
    checks = trial["workload_checks"]
    expected_checks = WINDOWS_TUN_WORKLOAD_CHECKS.get(str(trial["scenario"]))
    if (
        expected_checks is None
        or type(checks) is not dict
        or frozenset(checks) != expected_checks
        or any(value is not True for value in checks.values())
    ):
        raise CandidateControlError("Windows TUN workload check closure is invalid")
    _validate_route_proofs(
        trial["route_proofs"],
        run_id=run_id,
        sequence=trial["sequence"],
        topology=trial["topology"],
        loopback_interface_index=loopback_index,
        loopback_interface_alias=loopback_alias,
    )
    return trial
