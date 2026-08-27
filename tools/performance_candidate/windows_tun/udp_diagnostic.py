"""udp diagnostic owner."""

from __future__ import annotations

from tools.performance_candidate.identity import _file_sha256
from tools.performance_candidate.json_contract import CandidateControlError, _exact_fields, _strict_json
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4, WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST, WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST, WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_STRATEGY, source_identities, validate_environment

import pathlib

from tools.performance_candidate.windows_tun.udp_capture import _validate_windows_tun_udp_capture_manifest, _validate_windows_tun_udp_cleanup, _validate_windows_tun_udp_failure_summary
from tools.performance_candidate.windows_tun.udp_ledger import _read_windows_tun_udp_ledger, _validate_windows_tun_udp_workload_source_coverage, _windows_tun_udp_first_failed_flow
from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_ROLES, WINDOWS_TUN_UDP_DIAGNOSTIC_BOUND_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_IDENTITY_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_LIMITS, WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES, WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA, WINDOWS_TUN_UDP_DIAGNOSTIC_SUPPORT_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_TOPOLOGY_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_FIELDS, WINDOWS_TUN_UDP_FAILURE_REFERENCE_FIELDS, WINDOWS_TUN_UDP_SUPPORT_LEDGER_SCHEMA, WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
from tools.performance_candidate.windows_tun.udp_values import _read_windows_tun_udp_document, _validate_windows_tun_udp_support_endpoints, _windows_tun_required_digest, _windows_tun_udp_artifact_path, _windows_tun_udp_decimal_u64, _windows_tun_udp_ipv4, _windows_tun_udp_u64, _windows_tun_utc

WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_SEQUENCE = 37


def validate_windows_tun_udp_diagnostic(
    *,
    plan: dict[str, object],
    plan_sha256: str,
    evidence_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    """Validate one bounded, explicitly non-qualification UDP diagnostic run."""

    if plan["run_kind"] != "calibration-aa" or parent_sha != candidate_sha:
        raise CandidateControlError(
            "Windows TUN UDP diagnostic requires a calibration-aa A/A plan"
        )
    row = _read_windows_tun_udp_document(evidence_root / "udp-diagnostic.json")
    _exact_fields(row, WINDOWS_TUN_UDP_DIAGNOSTIC_FIELDS, "Windows TUN UDP diagnostic")
    if (
        row["schema"] != WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA
        or row["qualification"] is not False
        or row["profile"] != "UdpFlowBoundary"
        or row["evidence_status"] not in ("COMPLETE", "PARTIAL")
        or row["trial_status"] not in ("PASS", "FAIL")
    ):
        raise CandidateControlError("Windows TUN UDP diagnostic schema or status is invalid")
    _windows_tun_udp_decimal_u64(row["run_nonce"], "run_nonce", positive=True)
    started = _windows_tun_utc(row["started_utc"], "started_utc")
    finished = _windows_tun_utc(row["finished_utc"], "finished_utc")
    if finished <= started:
        raise CandidateControlError("Windows TUN UDP diagnostic finish must follow its start")
    identity = row["identity"]
    if type(identity) is not dict:
        raise CandidateControlError("Windows TUN UDP diagnostic identity must be an object")
    _exact_fields(identity, WINDOWS_TUN_UDP_DIAGNOSTIC_IDENTITY_FIELDS, "Windows TUN UDP identity")
    for field in ("parent_sha", "candidate_sha", "sha", "tree"):
        _windows_tun_required_digest(identity, field, length=40)
    for field in (
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "runner_sha256",
        "recipe_sha256",
        "plan_sha256",
    ):
        _windows_tun_required_digest(identity, field, length=64)
    if (
        identity["parent_sha"] != parent_sha
        or identity["candidate_sha"] != candidate_sha
        or identity["plan_sha256"] != plan_sha256
        or identity["recipe_sha256"] != plan["recipe_sha256"]
        or identity["runner_sha256"] != source_identities()["runner_source_sha256"]
    ):
        raise CandidateControlError("Windows TUN UDP diagnostic build or plan identity mismatch")
    trial = row["trial"]
    if type(trial) is not dict:
        raise CandidateControlError("Windows TUN UDP diagnostic trial must be an object")
    _exact_fields(trial, WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_FIELDS, "Windows TUN UDP trial")
    for field in ("sequence", "pair", "order"):
        _windows_tun_udp_u64(trial[field], f"trial.{field}", positive=True)
    planned = [candidate for candidate in plan["trials"] if candidate["sequence"] == trial["sequence"]]
    planned_identity_fields = {"sequence", "scenario", "member", "pair", "order"}
    if (
        len(planned) != 1
        or trial["selection"] != plan["selection"]
        or trial["run_kind"] != plan["run_kind"]
        or any(trial[field] != planned[0][field] for field in planned_identity_fields)
    ):
        raise CandidateControlError("Windows TUN UDP diagnostic trial is not plan-bound")
    if (
        trial["sequence"] != WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_SEQUENCE
        or trial["scenario"] != "udp-8192-association-lookup-expiry"
    ):
        raise CandidateControlError(
            "Windows TUN UDP diagnostic must be the reviewed sequence "
            f"{WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_SEQUENCE} scenario"
        )
    expected_sha = parent_sha if trial["member"] == "parent" else candidate_sha
    if identity["sha"] != expected_sha:
        raise CandidateControlError("Windows TUN UDP diagnostic member SHA mismatch")
    validate_environment(row["environment"])
    support = row["support"]
    if type(support) is not dict:
        raise CandidateControlError("Windows TUN UDP diagnostic support must be an object")
    _exact_fields(support, WINDOWS_TUN_UDP_DIAGNOSTIC_SUPPORT_FIELDS, "Windows TUN UDP support")
    _windows_tun_udp_u64(support["pid"], "support.pid", positive=True)
    if (
        type(support["owner"]) is not str
        or not support["owner"]
        or support["owner"].strip() != support["owner"]
        or len(support["owner"]) > 256
    ):
        raise CandidateControlError("Windows TUN UDP diagnostic support owner is invalid")
    _windows_tun_required_digest(support, "binary_sha256", length=64)
    _validate_windows_tun_udp_support_endpoints(support["listen_endpoints"])
    if support["binary_sha256"] != identity["harness_sha256"]:
        raise CandidateControlError("Windows TUN UDP diagnostic support identity mismatch")
    topology = row["topology"]
    if type(topology) is not dict:
        raise CandidateControlError("Windows TUN UDP topology must be an object")
    _exact_fields(topology, WINDOWS_TUN_UDP_DIAGNOSTIC_TOPOLOGY_FIELDS, "Windows TUN UDP topology")
    if topology["host_tun_bypassed"] is not True or topology["host_network_mutations"] != []:
        raise CandidateControlError("Windows TUN UDP diagnostic changed or traversed host TUN state")
    support_ipv4 = _windows_tun_udp_ipv4(topology["support_ipv4"], "topology.support_ipv4")
    _windows_tun_udp_ipv4(topology["guest_ipv4"], "topology.guest_ipv4")
    _windows_tun_required_digest(topology, "host_network_path_sha256", length=64)
    bounds = row["bounds"]
    if type(bounds) is not dict:
        raise CandidateControlError("Windows TUN UDP diagnostic bounds must be an object")
    _exact_fields(bounds, WINDOWS_TUN_UDP_DIAGNOSTIC_BOUND_FIELDS, "Windows TUN UDP bounds")
    for field, ceiling in WINDOWS_TUN_UDP_DIAGNOSTIC_LIMITS.items():
        observed = _windows_tun_udp_u64(bounds[field], f"bounds.{field}", positive=True)
        if observed > ceiling:
            raise CandidateControlError(f"Windows TUN UDP diagnostic {field} exceeds the controller bound")
    if bounds["max_artifact_bytes"] > bounds["max_total_bytes"]:
        raise CandidateControlError("Windows TUN UDP artifact bounds are inconsistent")
    artifacts_value = row["artifacts"]
    if type(artifacts_value) is not list or not artifacts_value or len(artifacts_value) > bounds["max_artifacts"]:
        raise CandidateControlError("Windows TUN UDP artifact count is invalid")
    artifacts: dict[str, dict[str, object]] = {}
    files = set()
    file_identities = set()
    artifact_paths: dict[str, pathlib.Path] = {}
    top_files: dict[str, tuple[int, str]] = {}
    top_file_roles: dict[str, str] = {}
    total_bytes = 0
    for artifact in artifacts_value:
        if type(artifact) is not dict:
            raise CandidateControlError("Windows TUN UDP artifact must be an object")
        _exact_fields(artifact, WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_FIELDS, "Windows TUN UDP artifact")
        role = artifact["role"]
        if (
            type(role) is not str
            or role not in WINDOWS_TUN_UDP_DIAGNOSTIC_ARTIFACT_ROLES
            or role in artifacts
        ):
            raise CandidateControlError("Windows TUN UDP artifact role is invalid or duplicated")
        if artifact["state"] not in ("COMPLETE", "PARTIAL"):
            raise CandidateControlError("Windows TUN UDP artifact state is invalid")
        relative = artifact["file"]
        if type(relative) is not str or not relative or relative in files:
            raise CandidateControlError("Windows TUN UDP artifact path is invalid or duplicated")
        path, path_identity, observed_size = _windows_tun_udp_artifact_path(
            evidence_root, relative, f"artifact {role}"
        )
        if path_identity in file_identities:
            raise CandidateControlError("Windows TUN UDP artifact aliases another role")
        size = _windows_tun_udp_u64(
            artifact["bytes"], f"artifact {role} bytes", positive=True
        )
        if size > bounds["max_artifact_bytes"] or observed_size != size:
            raise CandidateControlError("Windows TUN UDP artifact size binding is invalid")
        _windows_tun_required_digest(artifact, "sha256", length=64)
        if _file_sha256(path, "Windows TUN UDP artifact") != artifact["sha256"]:
            raise CandidateControlError("Windows TUN UDP artifact SHA-256 binding is invalid")
        for field in ("dropped_events", "write_failures"):
            _windows_tun_udp_u64(artifact[field], f"artifact {role} {field}")
        if role in {"workload_ledger", "support_ledger"}:
            _windows_tun_udp_u64(artifact["records"], f"artifact {role} records")
            _windows_tun_udp_u64(artifact["max_events"], f"artifact {role} max_events", positive=True)
        elif (
            artifact["records"] is not None
            or artifact["max_events"] is not None
            or artifact["dropped_events"] != 0
            or artifact["write_failures"] != 0
        ):
            raise CandidateControlError("Windows TUN UDP non-ledger artifact has ledger counters")
        total_bytes += size
        artifacts[role] = artifact
        artifact_paths[role] = path
        files.add(relative)
        file_identities.add(path_identity)
        top_files[path_identity] = (size, artifact["sha256"])
        top_file_roles[path_identity] = role
    if total_bytes > bounds["max_total_bytes"]:
        raise CandidateControlError("Windows TUN UDP artifacts exceed the total size bound")
    required = {
        "workload_ledger",
        "support_ledger",
        "host_capture",
        "endpoint_snapshot_before",
        "endpoint_snapshot_after",
        "dynamic_port_snapshot_before",
        "dynamic_port_snapshot_after",
        "host_network_path",
    }
    if row["trial_status"] == "FAIL":
        required.add("failure_summary")
    if not required.issubset(artifacts):
        raise CandidateControlError("Windows TUN UDP required artifact set is incomplete")
    network_path_artifact = artifacts["host_network_path"]
    if (
        topology["host_network_path_file"] != network_path_artifact["file"]
        or topology["host_network_path_sha256"] != network_path_artifact["sha256"]
    ):
        raise CandidateControlError("Windows TUN UDP host network path binding mismatch")
    ledgers = {}
    for role, schema in (
        ("workload_ledger", WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA),
        ("support_ledger", WINDOWS_TUN_UDP_SUPPORT_LEDGER_SCHEMA),
    ):
        artifact = artifacts[role]
        ledger = _read_windows_tun_udp_ledger(
            evidence_root / artifact["file"],
            schema=schema,
            run_nonce=row["run_nonce"],
            trial_sequence=trial["sequence"],
            max_line_bytes=bounds["max_ndjson_line_bytes"],
        )
        if (
            ledger["records"] != artifact["records"]
            or ledger["max_events"] != artifact["max_events"]
            or ledger["max_events"] > bounds["max_ledger_events"]
            or artifact["dropped_events"] != ledger["dropped_events"]
            or artifact["write_failures"] != ledger["write_failures"]
            or artifact["state"] != ("COMPLETE" if ledger["complete"] else "PARTIAL")
        ):
            raise CandidateControlError(f"Windows TUN UDP {role} manifest accounting mismatch")
        ledgers[role] = ledger
    support_header = ledgers["support_ledger"]["header"]
    header_support_endpoints = [
        {"protocol": "tcp", "ip": support_header["listen_ip"], "port": support_header["tcp_port"]},
        *[
            {"protocol": "udp", "ip": support_header["listen_ip"], "port": port}
            for port in support_header["udp_ports"]
        ],
    ]
    if (
        support_header["pid"] != support["pid"]
        or support_header["listen_ip"] != support_ipv4
        or header_support_endpoints != support["listen_endpoints"]
    ):
        raise CandidateControlError("Windows TUN UDP support ledger header binding mismatch")
    if any(
        event["target_ip"] != support_ipv4
        or event["target_port"] not in support_header["udp_ports"]
        for event in ledgers["workload_ledger"]["events"]
    ):
        raise CandidateControlError("Windows TUN UDP workload target is not support-bound")
    association_recipe = plan["scenarios"][
        "udp-8192-association-lookup-expiry"
    ]["recipe"]
    workload_header = ledgers["workload_ledger"]["header"]
    canonical_source = (
        association_recipe.get("canonical_source_ipv4"),
        association_recipe.get("canonical_source_port_first"),
        association_recipe.get("canonical_source_port_last"),
    )
    diagnostic_source = (
        association_recipe.get("diagnostic_source_ipv4"),
        association_recipe.get("diagnostic_source_port_first"),
        association_recipe.get("diagnostic_source_port_last"),
    )
    workload_source = (
        workload_header["source_ip"],
        workload_header["source_port_first"],
        workload_header["source_port_last"],
    )
    if (
        association_recipe.get("canonical_source_port_strategy")
        != WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_STRATEGY
        or canonical_source
        != (
            WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
            WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST,
            WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST,
        )
        or diagnostic_source != canonical_source
        or workload_source != canonical_source
        or association_recipe.get("diagnostic_collector_source_sha256")
        != source_identities()["diagnostic_collector_source_sha256"]
        or canonical_source[2] - canonical_source[1] + 1
        != association_recipe.get("associations")
    ):
        raise CandidateControlError(
            "Windows TUN UDP workload source header is not plan-bound"
        )
    _validate_windows_tun_udp_workload_source_coverage(
        ledgers["workload_ledger"]["events"],
        expected_associations=association_recipe["associations"],
        passing=row["trial_status"] == "PASS",
    )
    if row["trial_status"] == "PASS" and (
        _windows_tun_udp_first_failed_flow(
            ledgers["workload_ledger"]["events"]
        )
        is not None
    ):
        raise CandidateControlError(
            "passing Windows TUN UDP diagnostic contains a failed workload flow"
        )
    total_bytes += _validate_windows_tun_udp_capture_manifest(
        evidence_root=evidence_root,
        manifest_path=artifact_paths["host_capture"],
        manifest_relative=artifacts["host_capture"]["file"],
        artifact=artifacts["host_capture"],
        artifacts=artifacts,
        top_files=top_files,
        top_file_roles=top_file_roles,
        max_artifact_bytes=bounds["max_artifact_bytes"],
        support_ipv4=support_ipv4,
        support_udp_ports=support_header["udp_ports"],
    )
    if total_bytes > bounds["max_total_bytes"]:
        raise CandidateControlError(
            "Windows TUN UDP artifacts and nested capture files exceed the total size bound"
        )
    expected_evidence_status = (
        "PARTIAL"
        if any(artifact["state"] == "PARTIAL" for artifact in artifacts.values())
        else "COMPLETE"
    )
    if row["evidence_status"] != expected_evidence_status:
        raise CandidateControlError("Windows TUN UDP evidence completeness is inconsistent")
    cleanup = _validate_windows_tun_udp_cleanup(
        row["cleanup"], name="Windows TUN UDP cleanup"
    )
    if cleanup["status"] == "FAIL" and (
        row["evidence_status"] != "PARTIAL"
        or artifacts["host_capture"]["state"] != "PARTIAL"
        or (
            "host_capture_native" in artifacts
            and artifacts["host_capture_native"]["state"] != "PARTIAL"
        )
    ):
        raise CandidateControlError(
            "Windows TUN UDP failed cleanup must degrade capture evidence"
        )
    if row["trial_status"] == "FAIL":
        failure_artifact = artifacts["failure_summary"]
        reference = row["failure_summary"]
        if type(reference) is not dict:
            raise CandidateControlError(
                "Windows TUN UDP failure summary reference must be an object"
            )
        _exact_fields(
            reference,
            WINDOWS_TUN_UDP_FAILURE_REFERENCE_FIELDS,
            "Windows TUN UDP failure summary reference",
        )
        if (
            failure_artifact["state"] != "COMPLETE"
            or reference["file"] != failure_artifact["file"]
            or reference["sha256"] != failure_artifact["sha256"]
        ):
            raise CandidateControlError(
                "Windows TUN UDP failure summary reference binding mismatch"
            )
        if failure_artifact["bytes"] > WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES:
            raise CandidateControlError("Windows TUN UDP failure summary exceeds the size bound")
        try:
            failure_raw = artifact_paths["failure_summary"].read_bytes()
            failure = _strict_json(failure_raw.decode("utf-8"), source="Windows TUN UDP failure summary")
        except (OSError, UnicodeError) as error:
            raise CandidateControlError("unable to read Windows TUN UDP failure summary") from error
        _validate_windows_tun_udp_failure_summary(
            failure, row=row, artifacts=artifacts, ledgers=ledgers
        )
    elif row["failure_summary"] is not None or "failure_summary" in artifacts:
        raise CandidateControlError("passing Windows TUN UDP diagnostic cannot have a failure summary")
    return row
