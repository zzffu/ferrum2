"""udp values owner."""

from __future__ import annotations

import os
from tools.performance_candidate.json_contract import CandidateControlError, U64_MAX, _exact_fields, _strict_json

import ipaddress
import pathlib
import re
from datetime import datetime, timezone

from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES, WINDOWS_TUN_UDP_FAILURE_TUPLE_FIELDS, WINDOWS_TUN_UDP_SUPPORT_ENDPOINT_FIELDS

def _windows_tun_required_digest(
    row: dict[str, object], field: str, *, length: int
) -> str:
    value = row.get(field)
    pattern = r"[0-9a-f]{%d}" % length
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise CandidateControlError(
            f"Windows TUN evidence {field} must be lowercase {length}-hex"
        )
    return value


def _windows_tun_utc(value: object, field: str) -> datetime:
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z",
        value,
    ) is None:
        raise CandidateControlError(
            f"Windows TUN evidence {field} must be canonical UTC"
        )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CandidateControlError(
            f"Windows TUN evidence {field} is not a real timestamp"
        ) from error
    if parsed.tzinfo != timezone.utc:
        raise CandidateControlError(f"Windows TUN evidence {field} is not UTC")
    return parsed


def _windows_tun_udp_u64(
    value: object, field: str, *, positive: bool = False
) -> int:
    if (
        type(value) is not int
        or value < (1 if positive else 0)
        or value > U64_MAX
    ):
        requirement = "positive" if positive else "non-negative"
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} must be a {requirement} u64"
        )
    return value


def _windows_tun_source_preflight_count(
    value: object, field: str, *, positive: bool = False
) -> int:
    if (
        type(value) is not int
        or value < (1 if positive else 0)
        or value > U64_MAX
    ):
        requirement = "positive" if positive else "non-negative"
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} must be a {requirement} u64"
        )
    return value


def _windows_tun_udp_decimal_u64(
    value: object, field: str, *, positive: bool = False
) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None:
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} must be a canonical decimal u64"
        )
    parsed = int(value, 10)
    _windows_tun_udp_u64(parsed, field, positive=positive)
    return parsed


def _windows_tun_udp_ipv4(value: object, field: str) -> str:
    if type(value) is not str:
        raise CandidateControlError(f"Windows TUN UDP diagnostic {field} must be IPv4")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} must be IPv4"
        ) from error
    if parsed.version != 4 or str(parsed) != value:
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} must be canonical IPv4"
        )
    return value


def _windows_tun_udp_port(value: object, field: str) -> int:
    if type(value) is not int or not 1 <= value <= 65_535:
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} must be a valid port"
        )
    return value


def _windows_tun_udp_endpoint(
    value: dict[str, object], ip_field: str, port_field: str, field: str
) -> tuple[str, int] | None:
    ip_value = value[ip_field]
    port_value = value[port_field]
    if ip_value is None and port_value is None:
        return None
    if ip_value is None or port_value is None:
        raise CandidateControlError(
            f"Windows TUN UDP diagnostic {field} endpoint is incomplete"
        )
    return (
        _windows_tun_udp_ipv4(ip_value, f"{field}.{ip_field}"),
        _windows_tun_udp_port(port_value, f"{field}.{port_field}"),
    )


def _validate_windows_tun_udp_support_endpoints(
    value: object,
) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != 5:
        raise CandidateControlError(
            "Windows TUN UDP support listen_endpoints must contain five endpoints"
        )
    identities = set()
    for endpoint in value:
        if type(endpoint) is not dict:
            raise CandidateControlError(
                "Windows TUN UDP support listen endpoint must be an object"
            )
        _exact_fields(
            endpoint,
            WINDOWS_TUN_UDP_SUPPORT_ENDPOINT_FIELDS,
            "Windows TUN UDP support listen endpoint",
        )
        if endpoint["protocol"] not in ("tcp", "udp"):
            raise CandidateControlError(
                "Windows TUN UDP support listen endpoint protocol is invalid"
            )
        identity = (
            endpoint["protocol"],
            _windows_tun_udp_ipv4(endpoint["ip"], "support listen endpoint ip"),
            _windows_tun_udp_port(endpoint["port"], "support listen endpoint port"),
        )
        if identity in identities:
            raise CandidateControlError(
                "Windows TUN UDP support listen endpoint is duplicated"
            )
        identities.add(identity)
    return value


def _validate_windows_tun_udp_failure_tuple_shape(
    value: object, *, field: str
) -> None:
    if value is None:
        return
    if type(value) is not dict:
        raise CandidateControlError(f"Windows TUN UDP {field} must be an object")
    _exact_fields(value, WINDOWS_TUN_UDP_FAILURE_TUPLE_FIELDS, f"Windows TUN UDP {field}")
    _windows_tun_udp_ipv4(value["source_ip"], f"{field}.source_ip")
    _windows_tun_udp_port(value["source_port"], f"{field}.source_port")
    _windows_tun_udp_ipv4(value["target_ip"], f"{field}.target_ip")
    _windows_tun_udp_port(value["target_port"], f"{field}.target_port")


def _windows_tun_udp_artifact_path(
    evidence_root: pathlib.Path, relative: object, field: str
) -> tuple[pathlib.Path, str, int]:
    if type(relative) is not str or not relative or ":" in relative:
        raise CandidateControlError(f"Windows TUN UDP {field} path is invalid")
    relative_path = pathlib.Path(relative)
    if (
        relative_path.is_absolute()
        or relative_path.drive
        or relative_path.as_posix() != relative
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise CandidateControlError(
            f"Windows TUN UDP {field} path must be normalized and relative"
        )
    path = evidence_root / relative_path
    try:
        root_resolved = evidence_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
        stat = resolved.stat()
        if path.is_symlink() or not resolved.is_file():
            raise OSError("not a regular non-symlink file")
    except (OSError, ValueError) as error:
        raise CandidateControlError(
            f"Windows TUN UDP {field} path is missing, unsafe, or outside evidence root"
        ) from error
    return resolved, os.path.normcase(str(resolved)), stat.st_size


def _read_windows_tun_udp_document(path: pathlib.Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise CandidateControlError("Windows TUN UDP diagnostic is missing or not a regular file")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateControlError("unable to read Windows TUN UDP diagnostic") from error
    if len(raw) > WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES:
        raise CandidateControlError("Windows TUN UDP diagnostic exceeds the size bound")
    try:
        row = _strict_json(raw.decode("utf-8"), source="Windows TUN UDP diagnostic")
    except UnicodeError as error:
        raise CandidateControlError("Windows TUN UDP diagnostic must be UTF-8") from error
    if type(row) is not dict:
        raise CandidateControlError("Windows TUN UDP diagnostic must be an object")
    return row
