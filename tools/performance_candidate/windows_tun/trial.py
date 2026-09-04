"""Validation for one raw Windows-host TUN performance trial."""

from __future__ import annotations

import math
import re

from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_WORKLOAD_CHECKS

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
        "scenario",
        "member",
        "commit_sha",
        "metric",
        "unit",
        "value",
        "warmup_seconds",
        "active_seconds",
        "cpu_sample_seconds",
        "client_cpu_percent",
        "server_cpu_percent",
        "client_failure_counter_delta",
        "server_failure_counter_delta",
        "checked_units",
        "loopback_interface_index",
        "loopback_interface_alias",
        "route_proofs",
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
    loopback_interface_index: int,
    loopback_interface_alias: str,
) -> None:
    if type(value) is not list or len(value) != 4:
        raise CandidateControlError("Windows TUN trial must contain four route proofs")
    expected_purposes = [
        "benchmark-application-to-test-tun",
        "server-to-support-without-test-tun",
        "product-underlay-control",
        "sing-box-proxy-excluded",
    ]
    if [row.get("purpose") for row in value if type(row) is dict] != expected_purposes:
        raise CandidateControlError("Windows TUN route proof purpose closure changed")
    tun_address, support_address = _run_network_identity(run_id)
    expected_alias = f"Ferrum2Perf-{run_id}-{sequence:03d}"
    expected_endpoints = [
        (support_address, tun_address, f"{support_address}/32"),
        (support_address, support_address, f"{support_address}/32"),
        ("127.0.0.1", "127.0.0.1", "127.0.0.1/32"),
        ("127.0.0.1", "127.0.0.1", "127.0.0.1/32"),
    ]
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
            raise CandidateControlError("underlay/support traffic did not prove loopback exclusion")


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
        trial["schema_version"] != 1
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
        "scenario",
        "member",
        "commit_sha",
        "metric",
        "unit",
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
    _finite_positive(trial["client_cpu_percent"], "client_cpu_percent", allow_zero=True)
    _finite_positive(trial["server_cpu_percent"], "server_cpu_percent", allow_zero=True)
    _finite_positive(trial["checked_units"], "checked_units")
    if trial["client_failure_counter_delta"] != 0 or trial["server_failure_counter_delta"] != 0:
        raise CandidateControlError("Windows TUN trial recorded a product failure counter")
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
        loopback_interface_index=loopback_index,
        loopback_interface_alias=loopback_alias,
    )
    return trial
