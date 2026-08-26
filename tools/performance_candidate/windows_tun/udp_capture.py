"""udp capture owner."""

from __future__ import annotations

from tools.performance_candidate.identity import _file_sha256
from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields, _strict_json

import pathlib

from tools.performance_candidate.windows_tun.udp_ledger import _windows_tun_udp_failure_tuple, _windows_tun_udp_first_failed_flow, _windows_tun_udp_support_boundary
from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_CAPTURE_FILES, WINDOWS_TUN_UDP_CAPTURE_FILE_FIELDS, WINDOWS_TUN_UDP_CAPTURE_FILTER_FIELDS, WINDOWS_TUN_UDP_CAPTURE_MANIFEST_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_CLEANUP_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES, WINDOWS_TUN_UDP_FAILURE_SUMMARY_FIELDS, WINDOWS_TUN_UDP_FAILURE_SUMMARY_SCHEMA, WINDOWS_TUN_UDP_OBSERVATION_SOURCES, WINDOWS_TUN_UDP_OBSERVATION_SOURCE_FIELDS, WINDOWS_TUN_UDP_OBSERVATION_STAGES
from tools.performance_candidate.windows_tun.udp_values import _validate_windows_tun_udp_failure_tuple_shape, _windows_tun_required_digest, _windows_tun_udp_artifact_path, _windows_tun_udp_port, _windows_tun_udp_u64, _windows_tun_utc

def _validate_windows_tun_udp_cleanup(
    value: object, *, name: str
) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError(f"{name} must be an object")
    _exact_fields(value, WINDOWS_TUN_UDP_DIAGNOSTIC_CLEANUP_FIELDS, name)
    if (
        value["status"] not in ("PASS", "FAIL")
        or type(value["checkpoint_restored"]) is not bool
        or value["final_vm_state"] not in ("Off", "Running", "Paused", "Saved", "Unknown")
        or value["capture_stop_status"] not in ("PASS", "FAIL", "NOT_STARTED")
    ):
        raise CandidateControlError(f"{name} status is invalid")
    _windows_tun_udp_u64(value["guest_owned_processes"], f"{name}.guest_owned_processes")
    if (
        not value["checkpoint_restored"]
        or value["final_vm_state"] != "Off"
        or value["guest_owned_processes"] != 0
        or (value["status"] == "PASS" and value["capture_stop_status"] != "PASS")
    ):
        raise CandidateControlError(f"{name} is inconsistent")
    return value


def _validate_windows_tun_udp_failure_summary(
    value: object,
    *,
    row: dict[str, object],
    artifacts: dict[str, dict[str, object]],
    ledgers: dict[str, dict[str, object]],
) -> None:
    if type(value) is not dict:
        raise CandidateControlError("Windows TUN UDP failure summary must be an object")
    _exact_fields(value, WINDOWS_TUN_UDP_FAILURE_SUMMARY_FIELDS, "Windows TUN UDP failure summary")
    if value["qualification"] is not False:
        raise CandidateControlError(
            "Windows TUN UDP failure summary qualification must be false"
        )
    _windows_tun_udp_u64(value["support_pid"], "failure.support_pid", positive=True)
    trial_sequence = _windows_tun_udp_u64(
        value["trial_sequence"], "failure.trial_sequence", positive=True
    )
    if trial_sequence > 65_535:
        raise CandidateControlError("Windows TUN UDP failure trial_sequence exceeds u16")
    for field in ("pair", "order"):
        _windows_tun_udp_u64(value[field], f"failure.{field}", positive=True)
    for field in ("association_index", "round"):
        if value[field] is not None and _windows_tun_udp_u64(
            value[field], f"failure.{field}"
        ) > 0xFFFF_FFFF:
            raise CandidateControlError(f"Windows TUN UDP failure {field} exceeds u32")
    _validate_windows_tun_udp_cleanup(
        value["cleanup"], name="Windows TUN UDP failure cleanup"
    )
    for field in ("workload_tuple", "physical_tuple"):
        _validate_windows_tun_udp_failure_tuple_shape(value[field], field=field)
    identity = row["identity"]
    trial = row["trial"]
    support = row["support"]
    expected = {field: item for field, item in identity.items() if field != "plan_sha256"}
    expected.update(
        schema=WINDOWS_TUN_UDP_FAILURE_SUMMARY_SCHEMA,
        qualification=False,
        run_nonce=row["run_nonce"],
        vm_id=row["environment"]["vm_id"],
        checkpoint_id=row["environment"]["checkpoint_id"],
        support_pid=support["pid"],
        support_owner=support["owner"],
        support_sha256=support["binary_sha256"],
        trial_sequence=trial["sequence"],
        cleanup=row["cleanup"],
    )
    expected.update({field: trial[field] for field in "scenario member pair order".split()})
    if any(value[field] != item for field, item in expected.items()):
        raise CandidateControlError("Windows TUN UDP failure summary identity mismatch")
    flow = _windows_tun_udp_first_failed_flow(ledgers["workload_ledger"]["events"])
    support_rx, support_tx = _windows_tun_udp_support_boundary(
        ledgers["support_ledger"]["events"], run_nonce=row["run_nonce"], flow=flow
    )
    if any(
        event is not None and event["remote_ip"] != row["topology"]["guest_ipv4"]
        for event in (support_rx, support_tx)
    ):
        raise CandidateControlError(
            "Windows TUN UDP support packet source is not guest-bound"
        )
    if flow is None:
        flow_identity = {
            "phase": "bootstrap",
            "association_index": None,
            "round": None,
            "packet_nonce": None,
        }
        failure_kind = "other"
    else:
        flow_identity = {
            field: flow[field]
            for field in ("phase", "association_index", "round", "packet_nonce")
        }
        if flow["send_result"] in ("error", "partial"):
            failure_kind = "send_error"
        elif flow["reply_result"] == "timeout":
            failure_kind = "timeout"
        elif flow["reply_result"] == "error":
            failure_kind = "receive_error"
        elif flow["reply_result"] == "payload_mismatch":
            failure_kind = "payload_mismatch"
        else:
            failure_kind = "other"
    workload_tuple = _windows_tun_udp_failure_tuple(
        flow,
        source_ip="workload_local_ip",
        source_port="workload_local_port",
        target_ip="target_ip",
        target_port="target_port",
    )
    physical_tuple = _windows_tun_udp_failure_tuple(
        support_rx,
        source_ip="remote_ip",
        source_port="remote_port",
        target_ip="listen_ip",
        target_port="listen_port",
    )
    derived_failure = {
        **flow_identity,
        "failure_kind": failure_kind,
        "workload_tuple": workload_tuple,
        "physical_tuple": physical_tuple,
    }
    if any(value[field] != item for field, item in derived_failure.items()):
        raise CandidateControlError(
            "Windows TUN UDP failure classification is not ledger-bound"
        )
    if value["response_sink_outcome"] is not None:
        raise CandidateControlError(
            "Windows TUN UDP response sink cannot be claimed without boundary evidence"
        )
    observations = value["observations"]
    if type(observations) is not dict:
        raise CandidateControlError("Windows TUN UDP observations must be an object")
    _exact_fields(
        observations,
        frozenset(WINDOWS_TUN_UDP_OBSERVATION_STAGES),
        "Windows TUN UDP observations",
    )
    if any(state not in ("SEEN", "NOT_SEEN", "UNKNOWN") for state in observations.values()):
        raise CandidateControlError("Windows TUN UDP observation state is invalid")
    sources = value["observation_sources"]
    if type(sources) is not dict:
        raise CandidateControlError("Windows TUN UDP observation sources must be an object")
    _exact_fields(sources, WINDOWS_TUN_UDP_OBSERVATION_SOURCES, "Windows TUN UDP observation sources")
    for name, source in sources.items():
        if type(source) is not dict:
            raise CandidateControlError(f"Windows TUN UDP observation source {name} must be an object")
        _exact_fields(
            source,
            WINDOWS_TUN_UDP_OBSERVATION_SOURCE_FIELDS,
            f"Windows TUN UDP observation source {name}",
        )
        if source["state"] not in ("COMPLETE", "TRUNCATED", "MISSING", "ERROR", "NOT_ENABLED"):
            raise CandidateControlError("Windows TUN UDP observation source state is invalid")
        for field in ("records", "dropped_events", "write_failures"):
            _windows_tun_udp_u64(source[field], f"{name}.{field}")
        if type(source["covers_packet_nonce"]) is not bool:
            raise CandidateControlError("Windows TUN UDP source nonce coverage is invalid")
    for name in ("workload_ledger", "support_ledger"):
        source = sources[name]
        artifact = artifacts[name]
        ledger = ledgers[name]
        expected_state = "COMPLETE" if ledger["complete"] else "TRUNCATED"
        expected_coverage = ledger["complete"] and flow is not None
        if (
            source["state"] != expected_state
            or source["records"] != artifact["records"]
            or source["dropped_events"] != artifact["dropped_events"]
            or source["write_failures"] != artifact["write_failures"]
            or source["covers_packet_nonce"] is not expected_coverage
        ):
            raise CandidateControlError(f"Windows TUN UDP {name} source accounting mismatch")
    host_source = sources["host_capture"]
    expected_host_state = (
        "COMPLETE" if artifacts["host_capture"]["state"] == "COMPLETE" else "ERROR"
    )
    if host_source != {
        "state": expected_host_state,
        "records": 0,
        "dropped_events": 0,
        "write_failures": 0,
        "covers_packet_nonce": False,
    }:
        raise CandidateControlError("Windows TUN UDP host capture completeness mismatch")
    disabled_source = {
        "state": "NOT_ENABLED",
        "records": 0,
        "dropped_events": 0,
        "write_failures": 0,
        "covers_packet_nonce": False,
    }
    if any(sources[name] != disabled_source for name in ("guest_capture", "ferrum_boundary")):
        raise CandidateControlError("Windows TUN UDP observation source is not artifact-bound")
    workload_complete = ledgers["workload_ledger"]["complete"]
    support_complete = ledgers["support_ledger"]["complete"]
    if flow is None:
        expected_workload_send = expected_workload_reply = "UNKNOWN"
    else:
        expected_workload_send = (
            "SEEN"
            if flow["send_result"] == "success"
            else "NOT_SEEN" if workload_complete else "UNKNOWN"
        )
        expected_workload_reply = (
            "SEEN"
            if flow["reply_result"] == "success"
            else "UNKNOWN"
            if flow["reply_result"] == "not_observed"
            else "NOT_SEEN"
            if workload_complete
            else "UNKNOWN"
        )
    if (
        observations["workload_send"] != expected_workload_send
        or observations["workload_reply"] != expected_workload_reply
    ):
        raise CandidateControlError(
            "Windows TUN UDP workload observations are not ledger-derived"
        )
    for stage, event in (("support_rx", support_rx), ("support_tx", support_tx)):
        if event is not None:
            expected_observation = "SEEN"
        elif support_complete and flow is not None:
            expected_observation = "NOT_SEEN"
        else:
            expected_observation = "UNKNOWN"
        if observations[stage] != expected_observation:
            raise CandidateControlError(
                f"Windows TUN UDP {stage} observation is not ledger-derived"
            )
    uninstrumented = set(WINDOWS_TUN_UDP_OBSERVATION_STAGES) - {
        "workload_send",
        "workload_reply",
        "support_rx",
        "support_tx",
    }
    if any(observations[stage] != "UNKNOWN" for stage in uninstrumented):
        raise CandidateControlError(
            "Windows TUN UDP uninstrumented stage claims evidence"
        )
    last_confirmed = (
        "support_tx"
        if support_tx is not None
        else "support_rx"
        if support_rx is not None
        else "workload_send"
        if flow is not None and flow["send_result"] == "success"
        else None
    )
    first_missing = (
        "workload_send"
        if observations["workload_send"] == "NOT_SEEN"
        else "support_tx"
        if observations["support_rx"] == "SEEN"
        and observations["support_tx"] == "NOT_SEEN"
        else None
    )
    if (
        value["last_confirmed_stage"] != last_confirmed
        or value["first_missing_stage"] != first_missing
    ):
        raise CandidateControlError("Windows TUN UDP failure stages are not ledger-derived")
    support_tx_success = support_tx is not None and support_tx["send_result"] == "success"
    if support_tx_success:
        failure_fingerprint = "udp/bootstrap/reply-missing-after-support-tx"
    elif support_tx is not None:
        failure_fingerprint = "udp/bootstrap/support-tx-not-success"
    elif support_rx is not None:
        failure_fingerprint = (
            "udp/bootstrap/reply-missing-at-support-tx"
            if support_complete
            else "udp/bootstrap/support-tx-boundary-unknown"
        )
    else:
        failure_fingerprint = (
            "udp/bootstrap/request-missing-before-support-rx"
            if support_complete
            else "udp/bootstrap/support-boundary-unknown"
        )
    if value["failure_fingerprint"] != failure_fingerprint:
        raise CandidateControlError(
            "Windows TUN UDP failure fingerprint is not ledger-derived"
        )


def _validate_windows_tun_udp_capture_manifest(
    *,
    evidence_root: pathlib.Path,
    manifest_path: pathlib.Path,
    manifest_relative: str,
    artifact: dict[str, object],
    artifacts: dict[str, dict[str, object]],
    top_files: dict[str, tuple[int, str]],
    top_file_roles: dict[str, str],
    max_artifact_bytes: int,
    support_ipv4: str,
    support_udp_ports: list[int],
) -> int:
    if artifact["bytes"] > WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES:
        raise CandidateControlError("Windows TUN UDP capture manifest exceeds its bound")
    try:
        manifest = _strict_json(
            manifest_path.read_text(encoding="utf-8"),
            source="Windows TUN UDP capture manifest",
        )
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read Windows TUN UDP capture manifest") from error
    if type(manifest) is not dict:
        raise CandidateControlError("Windows TUN UDP capture manifest must be an object")
    _exact_fields(
        manifest,
        WINDOWS_TUN_UDP_CAPTURE_MANIFEST_FIELDS,
        "Windows TUN UDP capture manifest",
    )
    if (
        manifest["schema"] != "ferrum2.windows-tun.host-capture-manifest.v1"
        or manifest["state"] != artifact["state"]
        or manifest["expected_files"] != list(WINDOWS_TUN_UDP_CAPTURE_FILES)
        or manifest["stop_status"] not in ("PASS", "FAIL", "NOT_STARTED")
    ):
        raise CandidateControlError("Windows TUN UDP capture manifest identity is invalid")
    if manifest["started_utc"] is not None:
        _windows_tun_utc(manifest["started_utc"], "capture.started_utc")
    if (
        type(manifest["filters"]) is not list
        or len(manifest["filters"]) not in (0, 4)
        or type(manifest["failures"]) is not list
        or len(manifest["failures"]) > 32
        or any(type(item) is not str or not item or len(item) > 2_048 for item in manifest["failures"])
        or type(manifest["files"]) is not list
        or len(manifest["files"]) > len(WINDOWS_TUN_UDP_CAPTURE_FILES)
    ):
        raise CandidateControlError("Windows TUN UDP capture manifest bounds are invalid")
    observed_filter_ports = []
    for item in manifest["filters"]:
        if type(item) is not dict:
            raise CandidateControlError("Windows TUN UDP capture filter must be an object")
        _exact_fields(
            item,
            WINDOWS_TUN_UDP_CAPTURE_FILTER_FIELDS,
            "Windows TUN UDP capture filter",
        )
        port = _windows_tun_udp_port(item["port"], "capture filter port")
        if (
            item["name"] != f"Ferrum2UdpDiagnostic-{port}"
            or item["support_ipv4"] != support_ipv4
            or item["protocol"] != "UDP"
            or type(item["command_exit_code"]) is not int
            or item["command_exit_code"] != 0
        ):
            raise CandidateControlError("Windows TUN UDP capture filter identity is invalid")
        observed_filter_ports.append(port)
    if observed_filter_ports not in ([], support_udp_ports):
        raise CandidateControlError("Windows TUN UDP capture filter port set is invalid")
    seen_names = set()
    seen_identities = set()
    nested_identities: dict[str, str] = {}
    nested_bytes = 0
    manifest_parent = pathlib.Path(manifest_relative).parent
    for item in manifest["files"]:
        if type(item) is not dict:
            raise CandidateControlError("Windows TUN UDP capture file must be an object")
        _exact_fields(item, WINDOWS_TUN_UDP_CAPTURE_FILE_FIELDS, "Windows TUN UDP capture file")
        name = item["file"]
        if type(name) is not str or name not in WINDOWS_TUN_UDP_CAPTURE_FILES or name in seen_names:
            raise CandidateControlError("Windows TUN UDP capture file identity is invalid")
        nested_relative = (manifest_parent / name).as_posix()
        path, path_identity, size = _windows_tun_udp_artifact_path(
            evidence_root, nested_relative, f"capture file {name}"
        )
        declared_size = _windows_tun_udp_u64(item["bytes"], f"capture file {name} bytes", positive=True)
        _windows_tun_required_digest(item, "sha256", length=64)
        if (
            size != declared_size
            or size > max_artifact_bytes
            or _file_sha256(path, f"Windows TUN UDP capture file {name}") != item["sha256"]
            or path_identity in seen_identities
        ):
            raise CandidateControlError("Windows TUN UDP capture file binding is invalid")
        if path_identity in top_files:
            if (
                name != "PktMon.etl"
                or top_file_roles[path_identity] != "host_capture_native"
                or top_files[path_identity] != (size, item["sha256"])
            ):
                raise CandidateControlError("Windows TUN UDP capture file alias is inconsistent")
        else:
            top_files[path_identity] = (size, item["sha256"])
            nested_bytes += size
        seen_names.add(name)
        seen_identities.add(path_identity)
        nested_identities[name] = path_identity
    if artifact["state"] == "COMPLETE":
        if (
            seen_names != set(WINDOWS_TUN_UDP_CAPTURE_FILES)
            or manifest["failures"] != []
            or manifest["stop_status"] != "PASS"
            or manifest["started_utc"] is None
            or observed_filter_ports != support_udp_ports
        ):
            raise CandidateControlError("Windows TUN UDP complete capture manifest is incomplete")
    elif manifest["failures"] == [] and manifest["stop_status"] == "PASS":
        raise CandidateControlError("Windows TUN UDP partial capture lacks a failure reason")
    native = artifacts.get("host_capture_native")
    if "PktMon.etl" in seen_names:
        if native is None:
            raise CandidateControlError("Windows TUN UDP native capture artifact is missing")
        _native_path, native_identity, _native_size = _windows_tun_udp_artifact_path(
            evidence_root, native["file"], "native capture artifact"
        )
        etl = next(item for item in manifest["files"] if item["file"] == "PktMon.etl")
        if (
            native_identity != nested_identities["PktMon.etl"]
            or native["bytes"] != etl["bytes"]
            or native["sha256"] != etl["sha256"]
            or native["state"] != artifact["state"]
        ):
            raise CandidateControlError("Windows TUN UDP native capture binding mismatch")
    return nested_bytes
