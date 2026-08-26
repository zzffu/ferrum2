"""windows tun trial owner."""

from __future__ import annotations

import hashlib
import pathlib

from tools.performance_candidate.windows_tun import network_model, network_model_identity, network_model_lifecycle
from tools.performance_candidate.windows_tun.recipe import network_model_plan_sha256, scenario_catalog, source_identities
from tools.performance_candidate.json_contract import CandidateControlError, SHA256, U64_MAX, _exact_fields, _strict_json
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_PAIR_COUNT, validate_environment
from tools.performance_candidate.windows_tun.udp_schema import WINDOWS_TUN_UDP_ASSOCIATION_DIAGNOSTIC_FIELDS, WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA
from tools.performance_candidate.windows_tun.udp_source import _validate_windows_tun_udp_association_source_preflight
from tools.performance_candidate.windows_tun.udp_values import _read_windows_tun_udp_document, _windows_tun_required_digest, _windows_tun_utc

WINDOWS_TUN_TRIAL_SCHEMA_VERSION = 5


WINDOWS_TUN_TRIAL_MAX_BYTES = 64 * 1024


WINDOWS_TUN_TRIAL_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "selection",
        "run_kind",
        "scenario",
        "member",
        "pair",
        "order",
        "sequence",
        "started_utc",
        "finished_utc",
        "parent_sha",
        "candidate_sha",
        "sha",
        "tree",
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "recipe_sha256",
        "controller_bundle_sha256",
        "environment",
        "measurements",
        "correctness",
        "diagnostics",
        "network_model_evidence",
        "status",
    }
)


WINDOWS_TUN_MEASUREMENT_FIELDS = frozenset({"unit", "value"})


WINDOWS_TUN_CORRECTNESS_FIELDS = frozenset(
    {"status", "checked_unit", "checked_units", "checks"}
)


WINDOWS_TUN_RING_PRESSURE_DIAGNOSTIC_SCHEMA_VERSION = 1


WINDOWS_TUN_RING_PRESSURE_DIAGNOSTIC_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "workload_attempted_datagrams",
        "tun_packets_egress",
        "wintun_ring_full_dropped",
        "tun_response_attempts",
        "pending_response_before",
        "pending_response_peak",
        "pending_response_after",
    }
)


WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_SCHEMA_VERSION = 2


WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS = frozenset(
    {
        "batch_datagrams",
        "ack_window_milliseconds",
        "max_missing_per_batch",
        "max_retransmissions_per_sequence",
        "retry_budget_unique_datagrams",
        "minimum_retry_budget",
        "retry_scope",
    }
)


WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        *WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS,
        "accounting",
        "packet_counter_deltas",
        "adapter_counter_deltas",
    }
)


WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS = frozenset(
    {
        "warmup_unique_datagrams",
        "warmup_request_attempts",
        "active_unique_datagrams",
        "active_request_attempts",
        "total_unique_datagrams",
        "total_request_attempts",
        "retransmissions",
        "ack_window_expirations",
        "duplicate_or_stale_acks",
        "retry_budget",
    }
)


WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS = frozenset(
    {
        "accepted_packets",
        "ingress_packets",
        "background_family_disabled",
        "background_invalid_destination",
        "background_packets",
    }
)


WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS = frozenset(
    {
        "ReceivedUnicastPackets",
        "ReceivedDiscardedPackets",
        "ReceivedPacketErrors",
        "SentUnicastPackets",
        "OutboundDiscardedPackets",
        "OutboundPacketErrors",
    }
)


network_model_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "controller_sha256",
        "collector_sha256",
        "plan_sha256",
        "observation_file",
        "observation_sha256",
    }
)


def _validate_windows_tun_network_model_reference(
    value: object, *, scenario: str, sequence: int, member: str, pair: int
) -> None:
    model_scenarios = {"udp-route-once", "network-lifecycle"}
    if scenario not in model_scenarios:
        if value is not None:
            raise CandidateControlError(
                "non-model Windows TUN trial cannot reference network-model evidence"
            )
        return
    if type(value) is not dict:
        raise CandidateControlError(
            f"{scenario} trial must reference network-model evidence"
        )
    _exact_fields(
        value,
        network_model_EVIDENCE_FIELDS,
        "Windows TUN network-model evidence reference",
    )
    if value["schema_version"] != 1:
        raise CandidateControlError("Windows TUN network-model reference is unsupported")
    if value["controller_sha256"] != source_identities()["network_model_controller_sha256"]:
        raise CandidateControlError("Windows TUN network-model controller identity mismatch")
    if value["collector_sha256"] != source_identities()["collector_source_sha256"]:
        raise CandidateControlError("Windows TUN network-model collector identity mismatch")
    if value["plan_sha256"] != network_model_plan_sha256():
        raise CandidateControlError("Windows TUN network-model plan identity mismatch")
    expected_file = f"{sequence:03d}-{scenario}-{member}-pair-{pair}.network-model.json"
    if value["observation_file"] != expected_file:
        raise CandidateControlError("Windows TUN network-model observation name mismatch")
    digest = value["observation_sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise CandidateControlError("Windows TUN network-model observation SHA-256 is invalid")


def _windows_tun_diagnostic_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise CandidateControlError(
            f"Windows TUN fragment diagnostics {field} must be a non-negative u64"
        )
    return value


def _validate_windows_tun_diagnostics(
    value: object,
    *,
    scenario: str,
    contract: dict[str, object],
    checked_units: int,
    measurements: dict[str, object],
) -> None:
    if scenario == "udp-8192-association-lookup-expiry":
        if type(value) is not dict:
            raise CandidateControlError(
                "UDP association Windows TUN trial diagnostics must be an object"
            )
        _exact_fields(
            value,
            WINDOWS_TUN_UDP_ASSOCIATION_DIAGNOSTIC_FIELDS,
            "Windows TUN UDP association diagnostics",
        )
        _validate_windows_tun_udp_association_source_preflight(
            value["udp_association_source_preflight"],
            recipe=contract["recipe"],
        )
        return
    if scenario == "wintun-ring-full-drop-rate":
        if type(value) is not dict:
            raise CandidateControlError(
                "Wintun egress pressure diagnostics must be an object"
            )
        _exact_fields(
            value,
            WINDOWS_TUN_RING_PRESSURE_DIAGNOSTIC_FIELDS,
            "Wintun egress pressure diagnostics",
        )
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"]
            != WINDOWS_TUN_RING_PRESSURE_DIAGNOSTIC_SCHEMA_VERSION
        ):
            raise CandidateControlError(
                "Wintun egress pressure diagnostics schema_version is unsupported"
            )
        if value["kind"] != "wintun_egress_pressure_accounting":
            raise CandidateControlError(
                "Wintun egress pressure diagnostics kind is invalid"
            )
        count_fields = WINDOWS_TUN_RING_PRESSURE_DIAGNOSTIC_FIELDS - {
            "schema_version",
            "kind",
        }
        counts = {
            field: _windows_tun_diagnostic_u64(value[field], field)
            for field in count_fields
        }
        recipe = contract["recipe"]
        if counts["workload_attempted_datagrams"] != recipe["burst_attempts"]:
            raise CandidateControlError(
                "Wintun egress pressure workload attempts do not match the recipe"
            )
        if counts["tun_response_attempts"] != (
            counts["tun_packets_egress"] + counts["wintun_ring_full_dropped"]
        ):
            raise CandidateControlError(
                "Wintun egress pressure response accounting is inconsistent"
            )
        if counts["tun_response_attempts"] != checked_units:
            raise CandidateControlError(
                "Wintun egress pressure response attempts do not match correctness"
            )
        if (
            counts["tun_response_attempts"] < recipe["minimum_response_attempts"]
            or counts["tun_response_attempts"]
            > counts["workload_attempted_datagrams"]
        ):
            raise CandidateControlError(
                "Wintun egress pressure response denominator is out of bounds"
            )
        if (
            counts["pending_response_before"] != 0
            or counts["pending_response_after"] != 0
        ):
            raise CandidateControlError(
                "Wintun egress pressure pending responses did not start and end drained"
            )
        if (
            counts["pending_response_peak"]
            > recipe["pending_response_peak_maximum"]
        ):
            raise CandidateControlError(
                "Wintun egress pressure pending response peak exceeded its bound"
            )
        expected_drop_rate = (
            counts["wintun_ring_full_dropped"] * 1_000_000
            + counts["tun_response_attempts"]
            - 1
        ) // counts["tun_response_attempts"]
        if measurements["drop_rate"]["value"] != expected_drop_rate:
            raise CandidateControlError(
                "Wintun egress pressure drop rate was not recomputed from raw counts"
            )
        if (
            measurements["pending_response_peak"]["value"]
            != counts["pending_response_peak"]
        ):
            raise CandidateControlError(
                "Wintun egress pressure pending peak was not recomputed from raw counts"
            )
        return
    if scenario != "fragment-reassembly-throughput":
        if value is not None:
            raise CandidateControlError(
                "non-fragment Windows TUN trial diagnostics must be null"
            )
        return
    if type(value) is not dict:
        raise CandidateControlError(
            "fragment Windows TUN trial diagnostics must be an object"
        )
    _exact_fields(
        value,
        WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_FIELDS,
        "Windows TUN fragment diagnostics",
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_SCHEMA_VERSION
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics schema_version is unsupported"
        )
    if value["kind"] != "fragment_ack_accounting":
        raise CandidateControlError("Windows TUN fragment diagnostics kind is invalid")

    recipe = contract["recipe"]
    for field in WINDOWS_TUN_FRAGMENT_DIAGNOSTIC_PARAMETER_FIELDS:
        expected = recipe[field]
        if type(value[field]) is not type(expected) or value[field] != expected:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} does not match the recipe"
            )

    accounting = value["accounting"]
    if type(accounting) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics accounting must be an object"
        )
    _exact_fields(
        accounting,
        WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS,
        "Windows TUN fragment diagnostics accounting",
    )
    counts = {
        field: _windows_tun_diagnostic_u64(
            accounting[field], f"accounting.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_ACCOUNTING_FIELDS
    }
    for field in (
        "warmup_unique_datagrams",
        "active_unique_datagrams",
        "total_unique_datagrams",
    ):
        if counts[field] == 0:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} must be positive"
            )
        if counts[field] % recipe["batch_datagrams"] != 0:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {field} is not batch-aligned"
            )
    if counts["active_unique_datagrams"] != checked_units:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics active unique count does not match correctness"
        )
    for phase in ("warmup", "active"):
        if counts[f"{phase}_request_attempts"] < counts[f"{phase}_unique_datagrams"]:
            raise CandidateControlError(
                f"Windows TUN fragment diagnostics {phase} attempts are below unique datagrams"
            )
    if counts["total_unique_datagrams"] != (
        counts["warmup_unique_datagrams"] + counts["active_unique_datagrams"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics total unique count is inconsistent"
        )
    if counts["total_request_attempts"] != (
        counts["warmup_request_attempts"] + counts["active_request_attempts"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics total attempt count is inconsistent"
        )
    if counts["retransmissions"] != (
        counts["total_request_attempts"] - counts["total_unique_datagrams"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retransmission count is inconsistent"
        )
    if counts["ack_window_expirations"] != counts["retransmissions"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics ACK-window expiration count is inconsistent"
        )
    if counts["duplicate_or_stale_acks"] > counts["retransmissions"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics duplicate/stale ACK count is inconsistent"
        )
    maximum_retransmissions = (
        counts["total_unique_datagrams"]
        * recipe["max_retransmissions_per_sequence"]
    )
    if counts["retransmissions"] > maximum_retransmissions:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics exceeded the per-sequence retry bound"
        )
    retry_budget = max(
        recipe["minimum_retry_budget"],
        (
            counts["total_unique_datagrams"]
            + recipe["retry_budget_unique_datagrams"]
            - 1
        )
        // recipe["retry_budget_unique_datagrams"],
    )
    if counts["retry_budget"] != retry_budget:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retry budget is inconsistent"
        )
    if counts["retransmissions"] > counts["retry_budget"]:
        raise CandidateControlError(
            "Windows TUN fragment diagnostics retransmissions exceeded the retry budget"
        )

    packet_counters = value["packet_counter_deltas"]
    if type(packet_counters) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment packet counter deltas must be an object"
        )
    _exact_fields(
        packet_counters,
        WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS,
        "Windows TUN fragment packet counter deltas",
    )
    packet_counts = {
        field: _windows_tun_diagnostic_u64(
            packet_counters[field], f"packet_counter_deltas.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_PACKET_COUNTER_FIELDS
    }
    if packet_counts["background_packets"] != (
        packet_counts["background_family_disabled"]
        + packet_counts["background_invalid_destination"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment background packet accounting is inconsistent"
        )
    expected_fragment_packets = (
        counts["total_request_attempts"] * recipe["fragments_per_datagram"]
    )
    if packet_counts["accepted_packets"] != expected_fragment_packets:
        raise CandidateControlError(
            "Windows TUN fragment accepted-packet accounting is inconsistent"
        )
    if packet_counts["ingress_packets"] != (
        expected_fragment_packets + packet_counts["background_packets"]
    ):
        raise CandidateControlError(
            "Windows TUN fragment ingress/background accounting is inconsistent"
        )

    adapter = value["adapter_counter_deltas"]
    if type(adapter) is not dict:
        raise CandidateControlError(
            "Windows TUN fragment adapter counter deltas must be an object"
        )
    _exact_fields(
        adapter,
        WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS,
        "Windows TUN fragment adapter counter deltas",
    )
    adapter_counts = {
        field: _windows_tun_diagnostic_u64(
            adapter[field], f"adapter_counter_deltas.{field}"
        )
        for field in WINDOWS_TUN_FRAGMENT_ADAPTER_COUNTER_FIELDS
    }
    for field in (
        "ReceivedDiscardedPackets",
        "ReceivedPacketErrors",
        "OutboundDiscardedPackets",
        "OutboundPacketErrors",
    ):
        if adapter_counts[field] != 0:
            raise CandidateControlError(
                f"Windows TUN fragment adapter counter {field} recorded packet loss"
            )
    if adapter_counts["SentUnicastPackets"] != packet_counts["ingress_packets"]:
        raise CandidateControlError(
            "Windows TUN fragment adapter sent-packet accounting is inconsistent"
        )
    if adapter_counts["ReceivedUnicastPackets"] < counts["total_unique_datagrams"]:
        raise CandidateControlError(
            "Windows TUN fragment adapter received-packet accounting is inconsistent"
        )


def validate_windows_tun_trial(
    row: object,
    *,
    plan: dict[str, object],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[str, int, str]:
    if type(row) is not dict:
        raise CandidateControlError("Windows TUN trial must be a JSON object")
    if row.get("schema") == WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA:
        raise CandidateControlError(
            "instrumented UDP diagnostic evidence cannot be validated as a formal Windows TUN trial"
        )
    _exact_fields(row, WINDOWS_TUN_TRIAL_FIELDS, "Windows TUN trial")
    if (
        type(row["schema_version"]) is not int
        or row["schema_version"] != WINDOWS_TUN_TRIAL_SCHEMA_VERSION
        or row["kind"] != "windows_tun_performance_trial"
    ):
        raise CandidateControlError("Windows TUN trial schema is unsupported")
    for field in (
        "selection",
        "run_kind",
        "recipe_sha256",
        "controller_bundle_sha256",
    ):
        if row[field] != plan[field]:
            raise CandidateControlError(f"Windows TUN trial {field} does not match plan")
    if row["parent_sha"] != parent_sha or row["candidate_sha"] != candidate_sha:
        raise CandidateControlError("Windows TUN trial comparison identity mismatch")
    scenario = row["scenario"]
    if type(scenario) is not str or scenario not in scenario_catalog():
        raise CandidateControlError("Windows TUN trial scenario is not planned")
    pair = row["pair"]
    member = row["member"]
    order = row["order"]
    if (
        type(pair) is not int
        or not 1 <= pair <= WINDOWS_TUN_PAIR_COUNT
        or member not in {"parent", "candidate"}
        or type(order) is not int
        or order not in {1, 2}
    ):
        raise CandidateControlError("Windows TUN trial pair/member/order is invalid")
    expected_order = 1 if (member == "parent") == (pair % 2 == 1) else 2
    if order != expected_order:
        raise CandidateControlError(
            "Windows TUN trial does not follow alternating parent/candidate order"
        )
    sequence = row["sequence"]
    if type(sequence) is not int:
        raise CandidateControlError("Windows TUN trial sequence is invalid")
    planned_trials = [
        trial
        for trial in plan["trials"]
        if type(trial["sequence"]) is int and trial["sequence"] == sequence
    ]
    if len(planned_trials) != 1:
        raise CandidateControlError(
            "Windows TUN trial sequence does not uniquely match the plan"
        )
    planned_trial = planned_trials[0]
    if (
        type(planned_trial["scenario"]) is not str
        or type(planned_trial["member"]) is not str
        or type(planned_trial["pair"]) is not int
        or type(planned_trial["order"]) is not int
    ):
        raise CandidateControlError("Windows TUN planned trial identity is invalid")
    identity_fields = ("sequence", "scenario", "member", "pair", "order")
    if any(row[field] != planned_trial[field] for field in identity_fields):
        raise CandidateControlError(
            "Windows TUN trial identity does not match its planned sequence"
        )
    _validate_windows_tun_network_model_reference(
        row["network_model_evidence"],
        scenario=scenario,
        sequence=sequence,
        member=member,
        pair=pair,
    )
    started = _windows_tun_utc(row["started_utc"], "started_utc")
    finished = _windows_tun_utc(row["finished_utc"], "finished_utc")
    if finished <= started:
        raise CandidateControlError("Windows TUN trial finish must follow its start")
    _windows_tun_required_digest(row, "parent_sha", length=40)
    _windows_tun_required_digest(row, "candidate_sha", length=40)
    expected_sha = parent_sha if member == "parent" else candidate_sha
    if _windows_tun_required_digest(row, "sha", length=40) != expected_sha:
        raise CandidateControlError("Windows TUN trial member SHA mismatch")
    _windows_tun_required_digest(row, "tree", length=40)
    for field in (
        "client_sha256",
        "server_sha256",
        "harness_sha256",
        "recipe_sha256",
        "controller_bundle_sha256",
    ):
        _windows_tun_required_digest(row, field, length=64)
    validate_environment(row["environment"])
    contract = scenario_catalog()[scenario]
    measurements = row["measurements"]
    if type(measurements) is not dict or set(measurements) != set(contract["metrics"]):
        raise CandidateControlError(
            f"Windows TUN trial {scenario} measurements are incomplete"
        )
    for metric, metric_contract in contract["metrics"].items():
        measurement = measurements[metric]
        if type(measurement) is not dict:
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} must be an object"
            )
        _exact_fields(
            measurement,
            WINDOWS_TUN_MEASUREMENT_FIELDS,
            f"Windows TUN measurement {scenario}/{metric}",
        )
        if measurement["unit"] != metric_contract["unit"]:
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} unit mismatch"
            )
        allow_zero = metric_contract.get("allow_zero", False)
        if (
            type(measurement["value"]) is not int
            or measurement["value"] < (0 if allow_zero else 1)
            or measurement["value"] > U64_MAX
        ):
            value_contract = "non-negative" if allow_zero else "positive"
            raise CandidateControlError(
                f"Windows TUN measurement {scenario}/{metric} must be a {value_contract} u64"
            )
    correctness = row["correctness"]
    if type(correctness) is not dict:
        raise CandidateControlError("Windows TUN correctness must be an object")
    _exact_fields(correctness, WINDOWS_TUN_CORRECTNESS_FIELDS, "Windows TUN correctness")
    if correctness["status"] != "PASS":
        raise CandidateControlError("Windows TUN trial correctness did not pass")
    if correctness["checked_unit"] != contract["checked_unit"]:
        raise CandidateControlError("Windows TUN correctness unit mismatch")
    if (
        type(correctness["checked_units"]) is not int
        or correctness["checked_units"] < contract["minimum_checked_units"]
        or correctness["checked_units"] > U64_MAX
    ):
        raise CandidateControlError("Windows TUN correctness coverage is insufficient")
    if (
        scenario == "network-lifecycle"
        and correctness["checked_units"] != network_model_lifecycle.RESET_CYCLES
    ):
        raise CandidateControlError(
            "Windows TUN lifecycle correctness coverage must be exactly 1000 measured resets"
        )
    checks = correctness["checks"]
    expected_checks = set(contract["correctness_checks"])
    if type(checks) is not dict or set(checks) != expected_checks:
        raise CandidateControlError("Windows TUN correctness checks are incomplete")
    if any(value is not True for value in checks.values()):
        raise CandidateControlError("Windows TUN correctness check failed")
    _validate_windows_tun_diagnostics(
        row["diagnostics"],
        scenario=scenario,
        contract=contract,
        checked_units=correctness["checked_units"],
        measurements=measurements,
    )
    if row["status"] != "PASS":
        raise CandidateControlError("Windows TUN trial status did not pass")
    return scenario, pair, member


def _network_model_trial_values(summary: dict[str, object]) -> dict[str, int]:
    reset = summary["latency_nanoseconds"]["reset_network"]
    rebuild = summary["latency_nanoseconds"]["full_rebuild"]
    return {
        "reset_p50": reset["p50"],
        "reset_p95": reset["p95"],
        "reset_p99": reset["p99"],
        "full_rebuild_p50": rebuild["p50"],
        "full_rebuild_p95": rebuild["p95"],
        "full_rebuild_p99": rebuild["p99"],
        "interface_switch_recovery": summary[
            "interface_switch_recovery_nanoseconds"
        ],
        "interface_resolver_cache_hit": summary["interface_resolver"][
            "cache_hits_per_million_resolutions"
        ],
    }


def _route_once_trial_values(summary: dict[str, object]) -> dict[str, int]:
    return {
        "multi_target_packet_rate": summary["packets_per_second"],
        "association_creation_rate": summary["associations_per_second"],
        "router_invocations_avoided": summary["router_invocations_avoided"],
    }


def _validate_windows_tun_network_model_sidecars(
    *, evidence_root: pathlib.Path, rows: dict[tuple[str, int, str], dict[str, object]]
) -> list[dict[str, object]]:
    model_root = evidence_root / "network-model"
    if not model_root.is_dir() or model_root.is_symlink():
        raise CandidateControlError("Windows TUN network-model evidence directory is missing")
    model_scenarios = ("udp-route-once", "network-lifecycle")
    expected_files = {
        rows[(scenario, pair, member)]["network_model_evidence"]["observation_file"]
        for scenario in model_scenarios
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1)
        for member in ("parent", "candidate")
    }
    try:
        actual_paths = list(model_root.iterdir())
    except OSError as error:
        raise CandidateControlError(
            "unable to enumerate Windows TUN network-model evidence"
        ) from error
    if (
        any(not path.is_file() or path.is_symlink() for path in actual_paths)
        or {path.name for path in actual_paths} != expected_files
    ):
        raise CandidateControlError(
            "Windows TUN network-model evidence set is incomplete or contains extras"
        )
    evidence_files: list[dict[str, object]] = []
    for scenario in model_scenarios:
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
            for member in ("parent", "candidate"):
                row = rows[(scenario, pair, member)]
                reference = row["network_model_evidence"]
                path = model_root / reference["observation_file"]
                try:
                    raw = path.read_bytes()
                except OSError as error:
                    raise CandidateControlError(
                        "unable to read Windows TUN network-model observation"
                    ) from error
                if hashlib.sha256(raw).hexdigest() != reference["observation_sha256"]:
                    raise CandidateControlError(
                        "Windows TUN network-model observation identity mismatch"
                    )
                evidence_files.append(
                    {
                        "sequence": row["sequence"],
                        "file": f"network-model/{path.name}",
                        "sha256": reference["observation_sha256"],
                    }
                )
                try:
                    observation = network_model.load_observation(path)
                    summary = network_model.summarize_observation(observation)
                except network_model_identity.NetworkModelError as error:
                    raise CandidateControlError(
                        f"invalid Windows TUN network-model observation: {error}"
                    ) from error
                identity = summary["identity"]
                expected_identity = {
                    "run_kind": row["run_kind"],
                    "member": row["member"],
                    "pair": row["pair"],
                    "trial_sequence": row["sequence"],
                    "vm_name": row["environment"]["vm_name"],
                    "vm_id": row["environment"]["vm_id"],
                    "checkpoint_name": row["environment"]["checkpoint_name"],
                    "checkpoint_id": row["environment"]["checkpoint_id"],
                    "sha": row["sha"],
                    "tree": row["tree"],
                    "client_sha256": row["client_sha256"],
                    "server_sha256": row["server_sha256"],
                    "harness_sha256": row["harness_sha256"],
                    "collector_sha256": reference["collector_sha256"],
                    "recipe_sha256": row["recipe_sha256"],
                    "model_controller_sha256": reference["controller_sha256"],
                    "model_plan_sha256": reference["plan_sha256"],
                }
                if any(identity[field] != value for field, value in expected_identity.items()):
                    raise CandidateControlError(
                        "Windows TUN network-model observation is not bound to its trial"
                    )
                measured = {
                    metric: entry["value"] for metric, entry in row["measurements"].items()
                }
                if scenario == "udp-route-once":
                    if measured != _route_once_trial_values(summary):
                        raise CandidateControlError(
                            "Windows TUN route-once measurements were not recomputed from raw evidence"
                        )
                    expected_checks = {
                        "every_reply_accounted": True,
                        "payload_exact": True,
                        "direct_and_proxy_sources": summary["direct_and_proxy_verified"],
                        "association_creation_counter_exact": True,
                        "router_invocation_counter_exact": summary["route_once_verified"],
                        "post_reset_reroute_verified": summary["post_reset_reroute_verified"],
                        "network_model_evidence_bound": True,
                        "tun_path_observed": True,
                        "clean_drain": True,
                    }
                    if row["correctness"]["checked_units"] != summary["datagrams_sent"]:
                        raise CandidateControlError(
                            "Windows TUN route-once checked units were not derived from raw evidence"
                        )
                else:
                    if measured != _network_model_trial_values(summary):
                        raise CandidateControlError(
                            "Windows TUN lifecycle measurements were not recomputed from raw evidence"
                        )
                    reset_growth = summary["resources"]["reset_network"]["growth"]
                    expected_checks = {
                        "same_process_all_cycles": True,
                        "resource_warmup_exact": summary["resource_warmup"][
                            "reset_network_cycles"
                        ]
                        == network_model_lifecycle.RESOURCE_WARMUP_RESET_CYCLES,
                        "generation_advanced_once_per_cycle": True,
                        "managed_identity_preserved_across_resets": summary[
                            "managed_identity_preserved_across_resets"
                        ],
                        "damage_only_full_rebuild": summary["damage_only_full_rebuild"],
                        "reset_and_full_rebuild_metrics_are_exact": summary[
                            "reset_and_full_rebuild_metrics_are_exact"
                        ],
                        "resource_growth_zero_after_1000_resets": all(
                            value <= 0 for value in reset_growth.values()
                        ),
                        "tcp_and_udp_recovered_after_interface_switch": summary[
                            "tcp_and_udp_recovered_each_cycle"
                        ],
                        "interface_resolver_cache_hit_observed": summary[
                            "interface_resolver"
                        ]["cache_hits"]
                        > 0,
                        "network_model_evidence_bound": True,
                        "tun_path_observed": True,
                        "clean_drain": True,
                    }
                if row["correctness"]["checks"] != expected_checks:
                    raise CandidateControlError(
                        f"Windows TUN {scenario} correctness was not derived from raw evidence"
                    )
    return evidence_files


def _read_windows_tun_rows(
    *,
    evidence_root: pathlib.Path,
    plan: dict[str, object],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[
    dict[tuple[str, int, str], dict[str, object]],
    list[dict[str, object]],
    dict[str, tuple[object, ...]],
    dict[str, object],
]:
    diagnostic_path = evidence_root / "udp-diagnostic.json"
    if diagnostic_path.exists():
        diagnostic = _read_windows_tun_udp_document(diagnostic_path)
        if diagnostic.get("schema") == WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA:
            raise CandidateControlError(
                "instrumented UDP diagnostic evidence cannot enter the formal Windows TUN reducer"
            )
    try:
        paths = sorted(evidence_root.glob("*.json"))
    except OSError as error:
        raise CandidateControlError("unable to enumerate Windows TUN evidence") from error
    planned_trials = plan["trials"]
    expected_count = len(planned_trials)
    planned_sequences = [trial["sequence"] for trial in planned_trials]
    planned_keys = [
        (trial["scenario"], trial["pair"], trial["member"])
        for trial in planned_trials
    ]
    if (
        any(type(sequence) is not int for sequence in planned_sequences)
        or planned_sequences != list(range(1, expected_count + 1))
        or len(set(planned_keys)) != expected_count
    ):
        raise CandidateControlError("Windows TUN plan trial schedule is invalid")
    if len(paths) != expected_count:
        raise CandidateControlError(
            f"Windows TUN evidence requires exactly {expected_count} trial files"
        )
    rows: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, object]] = []
    member_identity: dict[str, tuple[object, ...]] = {}
    environment_identity: dict[str, object] | None = None
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise CandidateControlError("unable to read Windows TUN evidence") from error
        if len(raw) > WINDOWS_TUN_TRIAL_MAX_BYTES:
            raise CandidateControlError("Windows TUN trial exceeds the size bound")
        try:
            row = _strict_json(raw.decode("utf-8"), source=f"Windows TUN trial {path.name}")
        except UnicodeError as error:
            raise CandidateControlError("Windows TUN evidence must be UTF-8") from error
        scenario, pair, member = validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
        )
        key = (scenario, pair, member)
        if key in rows:
            raise CandidateControlError(
                f"duplicate Windows TUN evidence for {scenario}/{pair}/{member}"
            )
        rows[key] = row
        identity = tuple(
            row[field]
            for field in ("sha", "tree", "client_sha256", "server_sha256")
        )
        if member in member_identity and member_identity[member] != identity:
            raise CandidateControlError(
                f"Windows TUN {member} build identity changed between trials"
            )
        member_identity[member] = identity
        if environment_identity is None:
            environment_identity = row["environment"]
        elif environment_identity != row["environment"]:
            raise CandidateControlError(
                "Windows TUN guest environment changed between trials"
            )
        evidence_files.append(
            {
                "sequence": row["sequence"],
                "file": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    expected_keys = set(planned_keys)
    if set(rows) != expected_keys:
        raise CandidateControlError("Windows TUN evidence set is incomplete")
    if environment_identity is None:
        raise CandidateControlError("Windows TUN evidence environment is missing")
    ordered_rows = [rows[key] for key in planned_keys]
    if [row["sequence"] for row in ordered_rows] != planned_sequences:
        raise CandidateControlError("Windows TUN evidence sequence is incomplete")
    for previous, current in zip(ordered_rows, ordered_rows[1:], strict=False):
        if _windows_tun_utc(
            current["started_utc"], "started_utc"
        ) < _windows_tun_utc(previous["finished_utc"], "finished_utc"):
            raise CandidateControlError(
                "Windows TUN trials overlap or were not executed in planned order"
            )
    if plan["run_kind"] == "calibration-aa":
        if parent_sha != candidate_sha:
            raise CandidateControlError("Windows TUN A/A requires identical commit SHAs")
        if member_identity["parent"] != member_identity["candidate"]:
            raise CandidateControlError("Windows TUN A/A requires identical binary identities")
    elif parent_sha == candidate_sha:
        raise CandidateControlError("Windows TUN comparison requires distinct commits")
    harness_hashes = {row["harness_sha256"] for row in rows.values()}
    if len(harness_hashes) != 1:
        raise CandidateControlError("Windows TUN harness identity changed between trials")
    evidence_files.extend(
        _validate_windows_tun_network_model_sidecars(
            evidence_root=evidence_root, rows=rows
        )
    )
    evidence_files.sort(key=lambda entry: (entry["sequence"], entry["file"]))
    return rows, evidence_files, member_identity, environment_identity
