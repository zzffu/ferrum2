"""Validation for one raw Windows-host TUN performance trial."""

from __future__ import annotations

import ipaddress
import math
import re

from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields

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


def _validate_route_proofs(
    value: object,
    *,
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
    for index, row in enumerate(value):
        if type(row) is not dict:
            raise CandidateControlError("Windows TUN route proof must be an object")
        _exact_fields(row, _ROUTE_FIELDS, "Windows TUN route proof")
        if type(row["interface_index"]) is not int or row["interface_index"] <= 0:
            raise CandidateControlError("Windows TUN route proof interface index is invalid")
        try:
            remote = ipaddress.ip_address(row["remote_address"])
            local = ipaddress.ip_address(row["local_address"])
            prefix = ipaddress.ip_network(row["destination_prefix"], strict=False)
        except (TypeError, ValueError) as error:
            raise CandidateControlError("Windows TUN route proof address is invalid") from error
        if (
            remote.version != 4
            or local.version != 4
            or prefix.prefixlen != 32
            or remote not in prefix
        ):
            raise CandidateControlError("Windows TUN route proof must use its narrow IPv4 route")
        if index == 0:
            if (
                not str(row["interface_alias"]).startswith("Ferrum2Perf-")
                or row["next_hop"] != "0.0.0.0"
                or not remote in ipaddress.ip_network("198.18.0.0/15")
                or not local in ipaddress.ip_network("198.18.0.0/15")
            ):
                raise CandidateControlError("benchmark traffic did not prove the owned TUN path")
        elif (
            row["interface_index"] != loopback_interface_index
            or row["interface_alias"] != loopback_interface_alias
            or row["next_hop"] != "0.0.0.0"
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
    if type(checks) is not dict or not checks or any(value is not True for value in checks.values()):
        raise CandidateControlError("Windows TUN workload checks did not all pass")
    _validate_route_proofs(
        trial["route_proofs"],
        loopback_interface_index=loopback_index,
        loopback_interface_alias=loopback_alias,
    )
    return trial
