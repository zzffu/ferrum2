"""linux plan owner."""

from __future__ import annotations

import copy
import json
import pathlib

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux.catalog import (
    ACTIVE_SECONDS,
    DNS_CACHE_SIZE_SCENARIOS,
    MODES,
    PAIR_COUNTS,
    PAIR_SCHEDULE,
    QUALIFICATION_GROUPS,
    QUALIFICATION_ONLY_SELECTIONS,
    RUN_KINDS,
    SCENARIO_CATALOG,
    SCENARIO_EVIDENCE,
    SCENARIO_WORKLOAD_SCALE,
    SOCKS_DIRECT_REQUEST_SCENARIOS,
    STRUCTURAL_MATRIX_SCENARIOS,
    TCP_REQUEST_SCENARIOS,
    UDP_DIRECT_PAYLOAD_BOUNDS,
    UDP_RESPONSE_CONCURRENCY_SCENARIOS,
    UDP_SS_PAYLOAD_MATRIX,
    WARMUP_SECONDS,
)
from tools.performance_candidate.linux.evidence_contract import (
    scenario_evidence_contract,
)
from tools.performance_candidate.linux.policy import (
    MEASUREMENT_ENVIRONMENT,
    UNCALIBRATED_POLICY,
    validate_decision_policy,
)
from tools.performance_candidate.linux.scale import (
    SCALE_SCENARIO,
    _scale_scenario_entry,
    validate_scale_lineage_shape,
    validate_scale_safety_policy,
)
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_SELECTION

PLAN_SCHEMA_VERSION = 11
PLAN_MAX_BYTES = 1024 * 1024


def _allowed_integer(value: str, *, name: str, allowed: frozenset[int]) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CandidateControlError(f"{name} must be an integer") from error
    if str(parsed) != value or parsed not in allowed:
        choices = ", ".join(str(choice) for choice in sorted(allowed))
        raise CandidateControlError(f"{name} must be one of: {choices}")
    return parsed


def validate_measurement_inputs(
    warmup_seconds: str, active_seconds: str, pairs: str
) -> tuple[int, int, int]:
    """Validate each bounded measurement input independently."""

    return (
        _allowed_integer(warmup_seconds, name="warmup_seconds", allowed=WARMUP_SECONDS),
        _allowed_integer(active_seconds, name="active_seconds", allowed=ACTIVE_SECONDS),
        _allowed_integer(pairs, name="pairs", allowed=PAIR_COUNTS),
    )


def _scenario_entry(scenario: str, role: str) -> dict[str, object]:
    metric, direction, _family = SCENARIO_CATALOG[scenario]
    topology, payload_bytes, socks_bytes, upstream_bytes = SCENARIO_EVIDENCE[scenario]
    return {
        "scenario": scenario,
        "role": role,
        "mandatory": True,
        "metric": metric,
        "direction": direction,
        "topology": topology,
        "application_payload_bytes": payload_bytes,
        "workload_scale": SCENARIO_WORKLOAD_SCALE.get(scenario),
        "socks_datagram_bytes": socks_bytes,
        "upstream_wire_bytes": upstream_bytes,
    }


def _qualification_scenarios(
    selected: str,
) -> tuple[str, list[dict[str, object]]]:
    if selected == "tcp-frame-capacity":
        return (
            selected,
            [
                _scenario_entry("tcp-stream-64k", "primary"),
                _scenario_entry("tcp-bulk", "primary"),
                *(
                    _scenario_entry(scenario, "guard")
                    for scenario in TCP_REQUEST_SCENARIOS
                ),
            ],
        )
    if selected == "udp-payload-matrix":
        return (
            selected,
            [
                _scenario_entry(scenario, "primary" if index == 0 else "guard")
                for index, scenario in enumerate(UDP_SS_PAYLOAD_MATRIX)
            ],
        )
    if selected == "udp-direct-payload-bounds":
        return (
            selected,
            [
                _scenario_entry(scenario, "primary" if index == 0 else "guard")
                for index, scenario in enumerate(UDP_DIRECT_PAYLOAD_BOUNDS)
            ],
        )
    if selected == "structural-baseline-matrix":
        return (
            selected,
            [
                _scenario_entry(scenario, "primary" if index == 0 else "guard")
                for index, scenario in enumerate(STRUCTURAL_MATRIX_SCENARIOS)
            ],
        )
    family = SCENARIO_CATALOG[selected][2]
    if family == "tcp-throughput":
        guard = "tcp-bulk" if selected == "tcp-stream-64k" else "tcp-stream-64k"
        return (
            "tcp-throughput",
            [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")],
        )
    if family == "tcp-request":
        scenarios = [_scenario_entry(selected, "primary")]
        scenarios.extend(
            _scenario_entry(scenario, "guard")
            for scenario in TCP_REQUEST_SCENARIOS
            if scenario != selected
        )
        scenarios.append(_scenario_entry("tcp-bulk", "guard"))
        return "tcp-request", scenarios
    if family == "udp-established":
        guard = "udp-mtu-1200" if selected == "udp-small-high" else "udp-small-high"
        return "udp", [
            _scenario_entry(selected, "primary"),
            _scenario_entry(guard, "guard"),
        ]
    if family == "udp-ss-payload":
        return "udp-ss-payload", [
            _scenario_entry(selected, "primary"),
            _scenario_entry("udp-small-high", "guard"),
        ]
    if family == "udp-direct":
        guard = next(
            scenario for scenario in UDP_DIRECT_PAYLOAD_BOUNDS if scenario != selected
        )
        return "udp-direct", [
            _scenario_entry(selected, "primary"),
            _scenario_entry(guard, "guard"),
        ]
    if family == "udp-response-concurrency":
        return "udp-response-concurrency", [
            _scenario_entry(scenario, "primary" if scenario == selected else "guard")
            for scenario in UDP_RESPONSE_CONCURRENCY_SCENARIOS
        ]
    if family == "socks-direct-request":
        return "socks-direct-request", [
            _scenario_entry(scenario, "primary" if scenario == selected else "guard")
            for scenario in SOCKS_DIRECT_REQUEST_SCENARIOS
        ]
    if family == "dns-cache":
        return "dns-cache", [
            _scenario_entry(scenario, "primary" if scenario == selected else "guard")
            for scenario in DNS_CACHE_SIZE_SCENARIOS
        ]
    if family in {"udp-replay", "dns-udp"}:
        return family, [_scenario_entry(selected, "primary")]
    raise AssertionError(f"unhandled scenario family: {family}")


def create_plan(
    *,
    mode: str,
    selection: str,
    warmup_seconds: str,
    active_seconds: str,
    pairs: str,
    run_kind: str = "comparison",
    decision_policy: dict[str, object] | None = None,
    scale_safety_policy: dict[str, object] | None = None,
    scale_lineage: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the authoritative scenario plan for one manual workflow run."""

    if mode not in MODES:
        raise CandidateControlError("mode must be diagnostic or qualification")
    if run_kind not in RUN_KINDS:
        raise CandidateControlError("run_kind must be comparison or calibration-aa")
    if run_kind == "calibration-aa" and mode != "qualification":
        raise CandidateControlError("calibration-aa requires qualification mode")
    if selection in QUALIFICATION_ONLY_SELECTIONS:
        raise CandidateControlError(
            "Windows TUN lifecycle selection is qualification-only; use "
            "windows-tun-m17 for paired performance evidence"
        )
    if selection == WINDOWS_TUN_SELECTION:
        raise CandidateControlError(
            "windows-tun-m17 uses the dedicated windows-tun-plan command"
        )
    if mode == "diagnostic" and selection not in SCENARIO_CATALOG:
        raise CandidateControlError("diagnostic selection must be one profile workload")
    if mode == "qualification" and selection not in (
        set(SCENARIO_CATALOG) | set(QUALIFICATION_GROUPS) | {SCALE_SCENARIO}
    ):
        raise CandidateControlError("qualification selection is not supported")
    warmup, active, pair_count = validate_measurement_inputs(
        warmup_seconds, active_seconds, pairs
    )
    policy = copy.deepcopy(
        UNCALIBRATED_POLICY if decision_policy is None else decision_policy
    )
    validate_decision_policy(policy)
    is_scale = selection == SCALE_SCENARIO
    if is_scale:
        if run_kind != "comparison":
            raise CandidateControlError("tcp-scale-10k does not support calibration-aa")
        if mode != "qualification":
            raise CandidateControlError("tcp-scale-10k is qualification-only")
        if (warmup, active, pair_count) != (10, 30, 6):
            raise CandidateControlError(
                "tcp-scale-10k requires the exact 10/30/6 recipe"
            )
        if scale_safety_policy is None or scale_lineage is None:
            raise CandidateControlError(
                "tcp-scale-10k requires a reviewed scale policy and bound lineage"
            )
        validate_scale_safety_policy(scale_safety_policy)
        validate_scale_lineage_shape(scale_lineage)
        scenario_group = SCALE_SCENARIO
        scenarios = [_scale_scenario_entry()]
    elif scale_safety_policy is not None or scale_lineage is not None:
        raise CandidateControlError(
            "scale policy and lineage are only valid for tcp-scale-10k"
        )
    elif mode == "diagnostic":
        scenario_group = "diagnostic"
        scenarios = [_scenario_entry(selection, "diagnostic")]
    else:
        scenario_group, scenarios = _qualification_scenarios(selection)
    for scenario in scenarios:
        scenario["evidence_contract"] = scenario_evidence_contract(
            scenario,
            warmup_seconds=warmup,
            active_seconds=active,
            pair_schedule=PAIR_SCHEDULE,
        )
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "run_kind": run_kind,
        "mode": mode,
        "selection": selection,
        "selected_scenario": (
            selection if selection in SCENARIO_CATALOG or is_scale else None
        ),
        "scenario_group": scenario_group,
        "warmup_seconds": warmup,
        "active_seconds": active,
        "pairs": pair_count,
        "measurement_environment": dict(MEASUREMENT_ENVIRONMENT),
        "authority": copy.deepcopy(policy["authority"]),
        "decision_policy": policy,
        "scale_safety_policy": copy.deepcopy(scale_safety_policy),
        "scale_lineage": copy.deepcopy(scale_lineage),
        "adoption_eligible": False,
        "scenarios": scenarios,
    }


def write_plan(path: pathlib.Path, plan: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_plan(
    path: pathlib.Path,
    decision_policy: dict[str, object] | None = None,
    scale_safety_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        plan = read_bounded_closed_json(
            path, maximum_bytes=PLAN_MAX_BYTES, source="performance plan"
        ).value
        if type(plan) is not dict:
            raise CandidateControlError("performance plan must be a JSON object")
        policy = plan["decision_policy"] if decision_policy is None else decision_policy
        validate_decision_policy(policy)
        selected_scale_policy = (
            plan.get("scale_safety_policy")
            if scale_safety_policy is None
            else scale_safety_policy
        )
        expected = create_plan(
            mode=plan["mode"],
            selection=plan["selection"],
            warmup_seconds=str(plan["warmup_seconds"]),
            active_seconds=str(plan["active_seconds"]),
            pairs=str(plan["pairs"]),
            run_kind=plan["run_kind"],
            decision_policy=policy,
            scale_safety_policy=selected_scale_policy,
            scale_lineage=plan.get("scale_lineage"),
        )
    except (KeyError, TypeError) as error:
        raise CandidateControlError("performance plan is invalid") from error
    if plan != expected:
        raise CandidateControlError(
            "performance plan does not match the canonical scenario set"
        )
    return plan
