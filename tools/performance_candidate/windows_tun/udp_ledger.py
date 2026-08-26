"""udp ledger owner."""

from __future__ import annotations

from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields, _strict_json
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4, WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST, WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST

import pathlib
import re

from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_LEDGER_COUNTER_FIELDS, WINDOWS_TUN_UDP_SUPPORT_EVENT_FIELDS, WINDOWS_TUN_UDP_WORKLOAD_EVENT_FIELDS, WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
from tools.performance_candidate.windows_tun.udp_values import _windows_tun_udp_decimal_u64, _windows_tun_udp_endpoint, _windows_tun_udp_ipv4, _windows_tun_udp_port, _windows_tun_udp_u64

def _windows_tun_udp_ledger_event(
    row: object,
    *,
    schema: str,
    run_nonce: str,
    trial_sequence: int,
    header: dict[str, object],
    previous: dict[str, object] | None,
    position: int,
) -> dict[str, object]:
    if type(row) is not dict:
        raise CandidateControlError("Windows TUN UDP ledger event must be an object")
    expected_fields = (
        WINDOWS_TUN_UDP_WORKLOAD_EVENT_FIELDS
        if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
        else WINDOWS_TUN_UDP_SUPPORT_EVENT_FIELDS
    )
    _exact_fields(row, expected_fields, "Windows TUN UDP ledger event")
    if row["schema"] != schema or row["record_type"] != "event":
        raise CandidateControlError("Windows TUN UDP ledger event schema is invalid")
    event_index = _windows_tun_udp_u64(row["event_index"], "event_index")
    timestamp = _windows_tun_udp_u64(row["timestamp_qpc"], "timestamp_qpc")
    if row["timestamp_qpc_frequency"] != 1_000_000_000:
        raise CandidateControlError("Windows TUN UDP ledger clock frequency is invalid")
    counters = row["ledger_counters"]
    if type(counters) is not dict:
        raise CandidateControlError("Windows TUN UDP ledger counters must be an object")
    _exact_fields(
        counters,
        WINDOWS_TUN_UDP_LEDGER_COUNTER_FIELDS,
        "Windows TUN UDP ledger counters",
    )
    for field in counters:
        _windows_tun_udp_u64(counters[field], f"ledger_counters.{field}")
    if (
        counters["events_written"] != position
        or counters["attempted_events"]
        != counters["events_written"]
        + counters["dropped_events"]
        + counters["write_failures"]
        or event_index + 1 != counters["attempted_events"]
    ):
        raise CandidateControlError("Windows TUN UDP ledger event count is inconsistent")
    if previous is not None:
        previous_counters = previous["ledger_counters"]
        if (
            event_index <= previous["event_index"]
            or timestamp < previous["timestamp_qpc"]
            or counters["attempted_events"] <= previous_counters["attempted_events"]
            or counters["dropped_events"] < previous_counters["dropped_events"]
            or counters["write_failures"] < previous_counters["write_failures"]
        ):
            raise CandidateControlError(
                "Windows TUN UDP ledger event counters are not monotonic"
            )
    if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA:
        if row["run_nonce"] != run_nonce or row["trial_sequence"] != trial_sequence:
            raise CandidateControlError("Windows TUN UDP workload ledger identity mismatch")
        if (
            type(row["trial_sequence"]) is not int
            or not 1 <= row["trial_sequence"] <= 65_535
            or row["phase"] != "bootstrap"
        ):
            raise CandidateControlError("Windows TUN UDP workload event identity is invalid")
        for field in ("association_index", "round"):
            if _windows_tun_udp_u64(row[field], field) > 0xFFFF_FFFF:
                raise CandidateControlError(f"Windows TUN UDP {field} exceeds u32")
        _windows_tun_udp_decimal_u64(row["packet_nonce"], "packet_nonce")
        workload_endpoint = _windows_tun_udp_endpoint(
            row, "workload_local_ip", "workload_local_port", "workload_local"
        )
        target_endpoint = _windows_tun_udp_endpoint(row, "target_ip", "target_port", "target")
        if workload_endpoint is None or target_endpoint is None:
            raise CandidateControlError("Windows TUN UDP workload endpoint identity is missing")
        expected_source_endpoint = (
            header["source_ip"],
            header["source_port_first"] + row["association_index"],
        )
        if (
            expected_source_endpoint[1] > header["source_port_last"]
            or workload_endpoint != expected_source_endpoint
        ):
            raise CandidateControlError(
                "Windows TUN UDP workload source endpoint is invalid"
            )
        reply_endpoint = _windows_tun_udp_endpoint(
            row, "reply_source_ip", "reply_source_port", "reply_source"
        )
        send_result = row["send_result"]
        reply_result = row["reply_result"]
        if (
            send_result not in ("success", "partial", "error")
            or reply_result
            not in (
                "success",
                "timeout",
                "error",
                "payload_mismatch",
                "not_attempted",
                "not_observed",
            )
            or type(row["payload_match"]) is not bool
        ):
            raise CandidateControlError("Windows TUN UDP workload outcome is invalid")
        error_kind = row["error_kind"]
        if error_kind is not None and (
            type(error_kind) is not str
            or re.fullmatch(r"[a-z0-9_]{1,64}", error_kind) is None
        ):
            raise CandidateControlError("Windows TUN UDP workload error_kind is invalid")
        send_bytes = row["send_bytes"]
        if send_result == "success":
            if send_bytes != 32 or reply_result == "not_attempted":
                raise CandidateControlError("Windows TUN UDP successful send is inconsistent")
        elif send_result == "partial":
            if type(send_bytes) is not int or not 0 <= send_bytes < 32:
                raise CandidateControlError("Windows TUN UDP partial send is inconsistent")
        elif send_bytes is not None:
            raise CandidateControlError("Windows TUN UDP failed send has bytes")
        if reply_result == "success":
            valid_reply = (
                reply_endpoint == target_endpoint
                and row["payload_match"]
                and error_kind is None
            )
        elif reply_result == "payload_mismatch":
            valid_reply = (
                reply_endpoint == target_endpoint
                and not row["payload_match"]
                and error_kind == "payload_mismatch"
            )
        elif reply_result == "not_observed":
            valid_reply = (
                send_result == "success"
                and reply_endpoint is None
                and not row["payload_match"]
                and error_kind == "prior_batch_failure"
            )
        elif reply_result == "not_attempted":
            valid_reply = (
                send_result != "success"
                and reply_endpoint is None
                and not row["payload_match"]
                and error_kind is not None
            )
        else:
            valid_reply = (
                send_result == "success"
                and reply_endpoint is None
                and not row["payload_match"]
                and error_kind is not None
            )
        if not valid_reply:
            raise CandidateControlError("Windows TUN UDP workload reply is inconsistent")
    else:
        listen = (
            _windows_tun_udp_ipv4(row["listen_ip"], "support.listen_ip"),
            _windows_tun_udp_port(row["listen_port"], "support.listen_port"),
        )
        if listen[0] != header["listen_ip"] or listen[1] not in header["udp_ports"]:
            raise CandidateControlError("Windows TUN UDP support listen endpoint mismatch")
        _windows_tun_udp_ipv4(row["remote_ip"], "support.remote_ip")
        _windows_tun_udp_port(row["remote_port"], "support.remote_port")
        if _windows_tun_udp_u64(row["recv_bytes"], "recv_bytes") > 65_507:
            raise CandidateControlError("Windows TUN UDP support recv_bytes is invalid")
        identity_fields = (
            "payload_run_nonce",
            "payload_run_nonce_match",
            "trial_sequence",
            "phase",
            "association_index",
            "round",
            "packet_nonce",
        )
        identity_nulls = [row[field] is None for field in identity_fields]
        if any(identity_nulls) and not all(identity_nulls):
            raise CandidateControlError("Windows TUN UDP support payload identity is partial")
        payload_nonce = row["payload_run_nonce"]
        if payload_nonce is not None:
            _windows_tun_udp_decimal_u64(payload_nonce, "payload_run_nonce")
            if (
                type(row["payload_run_nonce_match"]) is not bool
                or row["payload_run_nonce_match"] != (payload_nonce == run_nonce)
                or type(row["trial_sequence"]) is not int
                or not 1 <= row["trial_sequence"] <= 65_535
                or row["phase"] != "bootstrap"
            ):
                raise CandidateControlError("Windows TUN UDP support payload identity is invalid")
            for field in ("association_index", "round"):
                if _windows_tun_udp_u64(row[field], field) > 0xFFFF_FFFF:
                    raise CandidateControlError(f"Windows TUN UDP {field} exceeds u32")
            _windows_tun_udp_decimal_u64(row["packet_nonce"], "packet_nonce")
            if payload_nonce == run_nonce and row["trial_sequence"] != trial_sequence:
                raise CandidateControlError("Windows TUN UDP support payload identity mismatch")
        error_kind = row["error_kind"]
        if error_kind is not None and (
            type(error_kind) is not str
            or re.fullmatch(r"[a-z0-9_]{1,64}", error_kind) is None
        ):
            raise CandidateControlError("Windows TUN UDP support error_kind is invalid")
        if row["stage"] == "rx":
            valid_stage = (
                row["send_attempted"] is None
                and row["send_result"] == "pending"
                and row["send_bytes"] is None
                and error_kind is None
            )
        elif row["stage"] == "tx" and type(row["send_attempted"]) is bool:
            if row["send_attempted"]:
                if row["send_result"] in ("success", "partial"):
                    valid_stage = (
                        type(row["send_bytes"]) is int
                        and 0 <= row["send_bytes"] <= 65_507
                        and (error_kind is None) == (row["send_result"] == "success")
                    )
                else:
                    valid_stage = (
                        row["send_result"] == "error"
                        and row["send_bytes"] is None
                        and error_kind is not None
                    )
            else:
                valid_stage = (
                    row["send_result"] == "not_attempted"
                    and row["send_bytes"] is None
                    and error_kind is not None
                )
        else:
            valid_stage = False
        if not valid_stage:
            raise CandidateControlError("Windows TUN UDP support stage outcome is invalid")
    return row


def _read_windows_tun_udp_ledger(
    path: pathlib.Path,
    *,
    schema: str,
    run_nonce: str,
    trial_sequence: int,
    max_line_bytes: int,
) -> dict[str, object]:
    common_header_fields = set(
        "schema record_type scope closure run_nonce max_events timestamp_clock".split()
    )
    header_fields = frozenset(
        common_header_fields
        | (
            {
                "trial_sequence",
                "source_ip",
                "source_port_first",
                "source_port_last",
            }
            if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
            else {"pid", "listen_ip", "tcp_port", "udp_ports"}
        )
    )
    footer_fields = frozenset(
        "schema record_type run_nonce attempted_events events_written dropped_events "
        "write_failures closed".split()
    )
    truncation_fields = frozenset(
        "schema record_type run_nonce attempted_events events_written "
        "dropped_events_at_least write_failures".split()
    )
    rows: list[object] = []
    try:
        with path.open("rb") as source:
            while True:
                raw = source.readline(max_line_bytes + 2)
                if not raw:
                    break
                if (
                    not raw.endswith(b"\n")
                    or raw.endswith(b"\r\n")
                    or len(raw) - 1 > max_line_bytes
                ):
                    raise CandidateControlError(
                        "Windows TUN UDP ledger line exceeds the bound or is unterminated"
                    )
                try:
                    rows.append(
                        _strict_json(
                            raw[:-1].decode("utf-8"), source="Windows TUN UDP ledger line"
                        )
                    )
                except UnicodeError as error:
                    raise CandidateControlError(
                        "Windows TUN UDP ledger must be UTF-8"
                    ) from error
    except OSError as error:
        raise CandidateControlError("unable to read Windows TUN UDP ledger") from error
    if not rows or type(rows[0]) is not dict:
        raise CandidateControlError("Windows TUN UDP ledger header is missing")
    header = rows[0]
    _exact_fields(header, header_fields, "Windows TUN UDP ledger header")
    if (
        header["schema"] != schema
        or header["record_type"] != "header"
        or header["scope"] != "bootstrap"
        or header["closure"]
        != (
            "workload_process_exit"
            if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
            else "host_four_port_barrier_after_vm_off"
        )
        or header["run_nonce"] != run_nonce
        or header["timestamp_clock"] != "std_instant_normalized_nanoseconds"
    ):
        raise CandidateControlError("Windows TUN UDP ledger header identity is invalid")
    _windows_tun_udp_decimal_u64(header["run_nonce"], "ledger header run_nonce", positive=True)
    if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA:
        source_ip = _windows_tun_udp_ipv4(
            header["source_ip"], "workload header source_ip"
        )
        source_port_first = _windows_tun_udp_port(
            header["source_port_first"], "workload header source_port_first"
        )
        source_port_last = _windows_tun_udp_port(
            header["source_port_last"], "workload header source_port_last"
        )
        if (
            type(header["trial_sequence"]) is not int
            or not 1 <= header["trial_sequence"] <= 65_535
            or header["trial_sequence"] != trial_sequence
        ):
            raise CandidateControlError("Windows TUN UDP workload ledger header trial mismatch")
        if (
            source_ip != WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4
            or source_port_first != WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
            or source_port_last != WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
            or source_port_last - source_port_first + 1 != 8_192
        ):
            raise CandidateControlError(
                "Windows TUN UDP workload ledger source range is invalid"
            )
    else:
        _windows_tun_udp_u64(header["pid"], "support header pid", positive=True)
        _windows_tun_udp_ipv4(header["listen_ip"], "support header listen_ip")
        _windows_tun_udp_port(header["tcp_port"], "support header tcp_port")
        if (
            type(header["udp_ports"]) is not list
            or len(header["udp_ports"]) != 4
            or any(
                type(port) is not int or not 1 <= port <= 65_535
                for port in header["udp_ports"]
            )
            or len(set(header["udp_ports"])) != 4
            or header["udp_ports"]
            != list(range(header["udp_ports"][0], header["udp_ports"][0] + 4))
        ):
            raise CandidateControlError("Windows TUN UDP support ledger endpoint is invalid")
    max_events = _windows_tun_udp_u64(header["max_events"], "max_events", positive=True)
    footer = None
    if len(rows) > 1 and type(rows[-1]) is dict and rows[-1].get("record_type") == "footer":
        footer = rows.pop()
        _exact_fields(footer, footer_fields, "Windows TUN UDP ledger footer")
        if (
            footer["schema"] != schema
            or footer["run_nonce"] != run_nonce
            or footer["closed"] is not True
        ):
            raise CandidateControlError("Windows TUN UDP ledger footer identity is invalid")
    truncation = None
    if len(rows) > 1 and type(rows[-1]) is dict and rows[-1].get("record_type") == "truncation":
        truncation = rows.pop()
        _exact_fields(truncation, truncation_fields, "Windows TUN UDP ledger truncation")
        if truncation["schema"] != schema or truncation["run_nonce"] != run_nonce:
            raise CandidateControlError("Windows TUN UDP ledger truncation identity is invalid")
    previous = None
    events = rows[1:]
    for position, event in enumerate(events, start=1):
        previous = _windows_tun_udp_ledger_event(
            event,
            schema=schema,
            run_nonce=run_nonce,
            trial_sequence=trial_sequence,
            header=header,
            previous=previous,
            position=position,
        )
        if previous["event_index"] >= max_events:
            raise CandidateControlError("Windows TUN UDP ledger exceeded max_events")
    workload_nonces = (
        [int(event["packet_nonce"], 10) for event in events]
        if schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
        else []
    )
    if any(current <= previous for previous, current in zip(workload_nonces, workload_nonces[1:])):
        raise CandidateControlError(
            "Windows TUN UDP workload packet nonces are not increasing"
        )
    last_counters = events[-1]["ledger_counters"] if events else {
        "attempted_events": 0,
        "events_written": 0,
        "dropped_events": 0,
        "write_failures": 0,
    }
    result = {
        "records": len(events),
        "max_events": max_events,
        "dropped_events": last_counters["dropped_events"],
        "write_failures": last_counters["write_failures"],
        "complete": False,
        "header": header,
        "events": events,
        "footer": footer,
        "truncation": truncation,
    }
    if truncation is not None:
        for field in ("attempted_events", "events_written", "dropped_events_at_least", "write_failures"):
            _windows_tun_udp_u64(truncation[field], field)
        if (
            truncation["events_written"] != len(events)
            or truncation["dropped_events_at_least"] < 1
            or truncation["attempted_events"]
            != truncation["events_written"]
            + truncation["dropped_events_at_least"]
            + truncation["write_failures"]
            or truncation["attempted_events"] != max_events + 1
            or truncation["attempted_events"] < last_counters["attempted_events"]
            or truncation["dropped_events_at_least"]
            < last_counters["dropped_events"]
            or truncation["write_failures"] < last_counters["write_failures"]
        ):
            raise CandidateControlError("Windows TUN UDP ledger truncation counters are inconsistent")
        result["dropped_events"] = truncation["dropped_events_at_least"]
        result["write_failures"] = truncation["write_failures"]
    if footer is not None:
        for field in (
            "attempted_events",
            "events_written",
            "dropped_events",
            "write_failures",
        ):
            _windows_tun_udp_u64(footer[field], field)
        if (
            footer["events_written"] != len(events)
            or footer["attempted_events"]
            != footer["events_written"]
            + footer["dropped_events"]
            + footer["write_failures"]
            or footer["attempted_events"] < last_counters["attempted_events"]
            or footer["dropped_events"] < last_counters["dropped_events"]
            or footer["write_failures"] < last_counters["write_failures"]
        ):
            raise CandidateControlError("Windows TUN UDP ledger footer counters are inconsistent")
        result.update(
            {
                "dropped_events": footer["dropped_events"],
                "write_failures": footer["write_failures"],
                "complete": footer["dropped_events"] == 0
                and footer["write_failures"] == 0
                and truncation is None,
            }
        )
        if truncation is not None and (
            footer["attempted_events"] < truncation["attempted_events"]
            or footer["dropped_events"] < truncation["dropped_events_at_least"]
            or footer["write_failures"] < truncation["write_failures"]
        ):
            raise CandidateControlError(
                "Windows TUN UDP ledger truncation exceeds footer accounting"
            )
        if footer["dropped_events"] == footer["write_failures"] == 0 and any(
            event["event_index"] != index
            or event["ledger_counters"]["attempted_events"] != index + 1
            for index, event in enumerate(events)
        ):
            raise CandidateControlError(
                "Windows TUN UDP complete ledger event sequence is not contiguous"
            )
        if (
            schema == WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
            and footer["dropped_events"] == footer["write_failures"] == 0
            and workload_nonces != list(range(len(events)))
        ):
            raise CandidateControlError(
                "Windows TUN UDP complete workload nonce sequence is not contiguous"
            )
    return result


def _windows_tun_udp_first_failed_flow(
    events: list[dict[str, object]],
) -> dict[str, object] | None:
    first_not_observed = None
    for event in events:
        if (
            event["send_result"] != "success"
            or event["reply_result"] not in ("success", "not_observed")
            or (
                event["reply_result"] == "success"
                and event["payload_match"] is not True
            )
        ):
            return event
        if event["reply_result"] == "not_observed" and first_not_observed is None:
            first_not_observed = event
    return first_not_observed


def _validate_windows_tun_udp_workload_source_coverage(
    events: list[dict[str, object]], *, expected_associations: int, passing: bool
) -> None:
    if len(events) > expected_associations or any(
        event["association_index"] != association_index
        for association_index, event in enumerate(events)
    ):
        raise CandidateControlError(
            "Windows TUN UDP workload source coverage is not a consecutive prefix"
        )
    if passing and len(events) != expected_associations:
        raise CandidateControlError(
            "passing Windows TUN UDP diagnostic lacks complete source coverage"
        )


def _windows_tun_udp_support_boundary(
    events: list[dict[str, object]],
    *,
    run_nonce: str,
    flow: dict[str, object] | None,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    if flow is None:
        return None, None
    matched = [
        event
        for event in events
        if event["payload_run_nonce"] == run_nonce
        and event["trial_sequence"] == flow["trial_sequence"]
        and event["phase"] == flow["phase"]
        and event["association_index"] == flow["association_index"]
        and event["round"] == flow["round"]
        and event["packet_nonce"] == flow["packet_nonce"]
    ]
    rx_events = [event for event in matched if event["stage"] == "rx"]
    tx_events = [event for event in matched if event["stage"] == "tx"]
    if len(rx_events) > 1 or len(tx_events) > 1:
        raise CandidateControlError(
            "Windows TUN UDP support ledger duplicates a packet boundary"
        )
    rx = rx_events[0] if rx_events else None
    tx = tx_events[0] if tx_events else None
    if tx is not None and (
        rx is None
        or rx["event_index"] >= tx["event_index"]
        or rx["listen_ip"] != tx["listen_ip"]
        or rx["listen_port"] != tx["listen_port"]
        or rx["remote_ip"] != tx["remote_ip"]
        or rx["remote_port"] != tx["remote_port"]
    ):
        raise CandidateControlError(
            "Windows TUN UDP support TX is not ordered after its matching RX"
        )
    if rx is not None and rx["recv_bytes"] != 32:
        raise CandidateControlError("Windows TUN UDP tagged support RX length is invalid")
    if tx is not None and (
        tx["recv_bytes"] != 32
        or tx["send_attempted"] is not True
        or tx["send_result"] not in ("success", "partial", "error")
        or (tx["send_result"] == "success" and tx["send_bytes"] != 32)
        or (
            tx["send_result"] == "partial"
            and (type(tx["send_bytes"]) is not int or not 0 <= tx["send_bytes"] < 32)
        )
    ):
        raise CandidateControlError("Windows TUN UDP tagged support TX outcome is invalid")
    return rx, tx


def _windows_tun_udp_failure_tuple(
    source: dict[str, object] | None,
    *,
    source_ip: str,
    source_port: str,
    target_ip: str,
    target_port: str,
) -> dict[str, object] | None:
    if source is None:
        return None
    if (
        source[source_ip] is None
        or source[source_port] is None
        or source[target_ip] is None
        or source[target_port] is None
    ):
        return None
    return {
        "source_ip": source[source_ip],
        "source_port": source[source_port],
        "target_ip": source[target_ip],
        "target_port": source[target_port],
    }
