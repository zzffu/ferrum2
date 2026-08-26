"""udp source owner."""

from __future__ import annotations

from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PREFIX_LENGTH

import re

from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_SOURCE_ADAPTER_FIELDS, WINDOWS_TUN_UDP_SOURCE_CONFLICT_ENDPOINT_FIELDS, WINDOWS_TUN_UDP_SOURCE_CONFLICT_FIELDS, WINDOWS_TUN_UDP_SOURCE_CONTRACT_FIELDS, WINDOWS_TUN_UDP_SOURCE_EXCLUDED_RANGE_FIELDS, WINDOWS_TUN_UDP_SOURCE_IP_OWNER_FIELDS, WINDOWS_TUN_UDP_SOURCE_MATCH_SET_FIELDS, WINDOWS_TUN_UDP_SOURCE_NETSH_SNAPSHOT_FIELDS, WINDOWS_TUN_UDP_SOURCE_PORT_RANGE_FIELDS, WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_FIELDS, WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_SCHEMA
from tools.performance_candidate.windows_tun.udp_values import _windows_tun_source_preflight_count, _windows_tun_udp_ipv4, _windows_tun_udp_port, _windows_tun_utc

def _validate_windows_tun_udp_source_netsh_snapshot(
    value: object, *, field: str, command: str
) -> list[str]:
    if type(value) is not dict:
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} must be an object"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_UDP_SOURCE_NETSH_SNAPSHOT_FIELDS,
        f"Windows TUN UDP source preflight {field}",
    )
    if value["command"] != command:
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} command is invalid"
        )
    if type(value["exit_code"]) is not int or value["exit_code"] != 0:
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} exit code is invalid"
        )
    lines = value["lines"]
    if type(lines) is not list or any(
        type(line) is not str or "\r" in line or "\n" in line for line in lines
    ):
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} lines are invalid"
        )
    if (
        type(value["total_lines"]) is not int
        or value["total_lines"] != len(lines)
        or len(lines) > 128
        or len("\n".join(lines).encode("utf-8")) > 16 * 1024
        or value["truncated"] is not False
    ):
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} accounting is invalid"
        )
    return lines


def _validate_windows_tun_udp_source_port_range(
    value: object, *, field: str
) -> tuple[int, int, int]:
    if type(value) is not dict:
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} must be an object"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_UDP_SOURCE_PORT_RANGE_FIELDS,
        f"Windows TUN UDP source preflight {field}",
    )
    first = _windows_tun_udp_port(value["first_port"], f"{field}.first_port")
    last = _windows_tun_udp_port(value["last_port"], f"{field}.last_port")
    count = _windows_tun_source_preflight_count(
        value["port_count"], f"{field}.port_count", positive=True
    )
    if last < first or last - first + 1 != count:
        raise CandidateControlError(
            f"Windows TUN UDP source preflight {field} is inconsistent"
        )
    return first, last, count


def _validate_windows_tun_udp_source_excluded_ranges(
    value: object,
) -> list[tuple[int, int]]:
    if type(value) is not list:
        raise CandidateControlError(
            "Windows TUN UDP source preflight excluded_port_ranges must be an array"
        )
    ranges = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise CandidateControlError(
                "Windows TUN UDP source preflight excluded port range must be an object"
            )
        _exact_fields(
            item,
            WINDOWS_TUN_UDP_SOURCE_EXCLUDED_RANGE_FIELDS,
            "Windows TUN UDP source preflight excluded port range",
        )
        first = _windows_tun_udp_port(
            item["first_port"], f"excluded_port_ranges[{index}].first_port"
        )
        last = _windows_tun_udp_port(
            item["last_port"], f"excluded_port_ranges[{index}].last_port"
        )
        if last < first:
            raise CandidateControlError(
                "Windows TUN UDP source preflight excluded port range is invalid"
            )
        ranges.append((first, last))
    return ranges


def _validate_windows_tun_udp_association_source_preflight(
    value: object, *, recipe: dict[str, object]
) -> None:
    if type(value) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP association source preflight must be an object"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_FIELDS,
        "Windows TUN UDP association source preflight",
    )
    if value["schema"] != WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_SCHEMA:
        raise CandidateControlError(
            "Windows TUN UDP association source preflight schema is unsupported"
        )
    _windows_tun_utc(
        value["captured_utc"], "udp association source preflight captured_utc"
    )

    source = value["source_contract"]
    if type(source) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight source_contract must be an object"
        )
    _exact_fields(
        source,
        WINDOWS_TUN_UDP_SOURCE_CONTRACT_FIELDS,
        "Windows TUN UDP source preflight source contract",
    )
    adapter_name = source["adapter_name"]
    if type(adapter_name) is not str or not adapter_name.strip():
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter_name is invalid"
        )
    source_ip = _windows_tun_udp_ipv4(
        source["source_ip"], "source preflight source_ip"
    )
    source_first = _windows_tun_udp_port(
        source["source_port_first"], "source preflight source_port_first"
    )
    source_last = _windows_tun_udp_port(
        source["source_port_last"], "source preflight source_port_last"
    )
    source_count = _windows_tun_source_preflight_count(
        source["source_port_count"], "source_contract.source_port_count", positive=True
    )
    if (
        type(source["source_prefix_length"]) is not int
        or source["source_prefix_length"]
        != WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PREFIX_LENGTH
        or source_ip != recipe["canonical_source_ipv4"]
        or source_first != recipe["canonical_source_port_first"]
        or source_last != recipe["canonical_source_port_last"]
        or source_count != recipe["associations"]
        or source_last - source_first + 1 != source_count
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight source contract does not match the recipe"
        )

    adapter = value["adapter"]
    if type(adapter) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter must be an object"
        )
    _exact_fields(
        adapter,
        WINDOWS_TUN_UDP_SOURCE_MATCH_SET_FIELDS,
        "Windows TUN UDP source preflight adapter",
    )
    adapter_matches = adapter["matches"]
    adapter_match_count = _windows_tun_source_preflight_count(
        adapter["match_count"], "adapter.match_count"
    )
    adapter_retained_count = _windows_tun_source_preflight_count(
        adapter["retained_count"], "adapter.retained_count"
    )
    if type(adapter_matches) is not list:
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter matches must be an array"
        )
    if (
        adapter_match_count != 1
        or adapter_retained_count != 1
        or len(adapter_matches) != 1
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter identity is not unique"
        )
    adapter_match = adapter_matches[0]
    if type(adapter_match) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter match must be an object"
        )
    _exact_fields(
        adapter_match,
        WINDOWS_TUN_UDP_SOURCE_ADAPTER_FIELDS,
        "Windows TUN UDP source preflight adapter match",
    )
    for field in ("name", "interface_description", "status", "mac_address"):
        if type(adapter_match[field]) is not str:
            raise CandidateControlError(
                f"Windows TUN UDP source preflight adapter {field} is invalid"
            )
    adapter_index = _windows_tun_source_preflight_count(
        adapter_match["interface_index"], "adapter.interface_index", positive=True
    )
    if adapter_match["name"] != adapter_name or adapter_match["status"] != "Up":
        raise CandidateControlError(
            "Windows TUN UDP source preflight adapter does not match the source contract"
        )

    ip_owner = value["ip_owner"]
    if type(ip_owner) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight ip_owner must be an object"
        )
    _exact_fields(
        ip_owner,
        WINDOWS_TUN_UDP_SOURCE_MATCH_SET_FIELDS,
        "Windows TUN UDP source preflight ip_owner",
    )
    ip_matches = ip_owner["matches"]
    ip_match_count = _windows_tun_source_preflight_count(
        ip_owner["match_count"], "ip_owner.match_count"
    )
    ip_retained_count = _windows_tun_source_preflight_count(
        ip_owner["retained_count"], "ip_owner.retained_count"
    )
    if type(ip_matches) is not list:
        raise CandidateControlError(
            "Windows TUN UDP source preflight ip_owner matches must be an array"
        )
    if ip_match_count != 1 or ip_retained_count != 1 or len(ip_matches) != 1:
        raise CandidateControlError(
            "Windows TUN UDP source preflight IP owner identity is not unique"
        )
    ip_match = ip_matches[0]
    if type(ip_match) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight IP owner match must be an object"
        )
    _exact_fields(
        ip_match,
        WINDOWS_TUN_UDP_SOURCE_IP_OWNER_FIELDS,
        "Windows TUN UDP source preflight IP owner match",
    )
    owner_ip = _windows_tun_udp_ipv4(
        ip_match["ip_address"], "source preflight ip_owner.ip_address"
    )
    owner_index = _windows_tun_source_preflight_count(
        ip_match["interface_index"], "ip_owner.interface_index", positive=True
    )
    for field in (
        "interface_alias",
        "address_state",
        "prefix_origin",
        "suffix_origin",
    ):
        if type(ip_match[field]) is not str or not ip_match[field].strip():
            raise CandidateControlError(
                f"Windows TUN UDP source preflight IP owner {field} is invalid"
            )
    if (
        owner_ip != source_ip
        or type(ip_match["prefix_length"]) is not int
        or ip_match["prefix_length"] != source["source_prefix_length"]
        or owner_index != adapter_index
        or ip_match["interface_alias"] != adapter_name
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight IP owner does not match the adapter"
        )

    conflicts = value["udp_endpoint_conflicts"]
    if type(conflicts) is not dict:
        raise CandidateControlError(
            "Windows TUN UDP source preflight endpoint conflicts must be an object"
        )
    _exact_fields(
        conflicts,
        WINDOWS_TUN_UDP_SOURCE_CONFLICT_FIELDS,
        "Windows TUN UDP source preflight endpoint conflicts",
    )
    endpoints = conflicts["endpoints"]
    conflict_count = _windows_tun_source_preflight_count(
        conflicts["count"], "udp_endpoint_conflicts.count"
    )
    conflict_retained_count = _windows_tun_source_preflight_count(
        conflicts["retained_count"], "udp_endpoint_conflicts.retained_count"
    )
    if type(endpoints) is not list:
        raise CandidateControlError(
            "Windows TUN UDP source preflight conflict endpoints must be an array"
        )
    for endpoint in endpoints:
        if type(endpoint) is not dict:
            raise CandidateControlError(
                "Windows TUN UDP source preflight conflict endpoint must be an object"
            )
        _exact_fields(
            endpoint,
            WINDOWS_TUN_UDP_SOURCE_CONFLICT_ENDPOINT_FIELDS,
            "Windows TUN UDP source preflight conflict endpoint",
        )
        if type(endpoint["local_address"]) is not str:
            raise CandidateControlError(
                "Windows TUN UDP source preflight conflict address is invalid"
            )
        _windows_tun_udp_port(
            endpoint["local_port"], "source preflight conflict local_port"
        )
        _windows_tun_source_preflight_count(
            endpoint["owning_process"], "source preflight conflict owning_process"
        )
    if (
        conflict_count != 0
        or conflict_retained_count != 0
        or conflicts["truncated"] is not False
        or endpoints != []
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight source port range is occupied"
        )

    dynamic_lines = _validate_windows_tun_udp_source_netsh_snapshot(
        value["dynamic_port_udp"],
        field="dynamic_port_udp",
        command="netsh.exe interface ipv4 show dynamicport udp",
    )
    dynamic_first, dynamic_last, dynamic_count = (
        _validate_windows_tun_udp_source_port_range(
            value["dynamic_port_range"], field="dynamic_port_range"
        )
    )
    dynamic_values = [
        int(match.group(1), 10)
        for line in dynamic_lines
        if (match := re.search(r":\s*([0-9]{1,5})\s*$", line)) is not None
    ]
    if dynamic_values != [dynamic_first, dynamic_count]:
        raise CandidateControlError(
            "Windows TUN UDP source preflight dynamic port snapshot is inconsistent"
        )
    dynamic_intersects = (
        source_first <= dynamic_last and dynamic_first <= source_last
    )
    if value["dynamic_port_intersects_source"] is not False or dynamic_intersects:
        raise CandidateControlError(
            "Windows TUN UDP source preflight intersects the dynamic port range"
        )

    excluded_lines = _validate_windows_tun_udp_source_netsh_snapshot(
        value["excluded_port_ranges_udp"],
        field="excluded_port_ranges_udp",
        command=(
            "netsh.exe interface ipv4 show excludedportrange protocol=udp"
        ),
    )
    excluded_ranges = _validate_windows_tun_udp_source_excluded_ranges(
        value["excluded_port_ranges"]
    )
    parsed_excluded_ranges = []
    for line in excluded_lines:
        match = re.fullmatch(
            r"\s*([0-9]{1,5})\s+([0-9]{1,5})(?:\s+\*)?\s*", line
        )
        if match is not None:
            parsed_excluded_ranges.append(
                (int(match.group(1), 10), int(match.group(2), 10))
            )
    if parsed_excluded_ranges != excluded_ranges:
        raise CandidateControlError(
            "Windows TUN UDP source preflight excluded port snapshot is inconsistent"
        )
    if any(
        source_first <= last and first <= source_last
        for first, last in excluded_ranges
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight intersects an excluded port range"
        )
    if (
        type(value["excluded_port_intersections"]) is not list
        or value["excluded_port_intersections"] != []
    ):
        raise CandidateControlError(
            "Windows TUN UDP source preflight excluded intersections are invalid"
        )

    if (
        value["valid"] is not True
        or type(value["violations"]) is not list
        or value["violations"] != []
        or type(value["errors"]) is not list
        or value["errors"] != []
    ):
        raise CandidateControlError(
            "Windows TUN UDP association source preflight did not pass"
        )
