"""windows tun plan owner."""

from __future__ import annotations

import copy
import pathlib

from tools.performance_candidate.windows_tun.recipe import recipe_sha256, scenario_catalog, scenario_contracts
from tools.performance_candidate.json_contract import CandidateControlError, _canonical_json_bytes, _exact_fields, read_bounded_closed_json
from tools.performance_candidate.windows_tun.policy import validate_windows_tun_policy, windows_tun_policy_is_calibrated
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_PAIR_COUNT, WINDOWS_TUN_PAIR_SCHEDULE, WINDOWS_TUN_RUN_KINDS, WINDOWS_TUN_SELECTION

WINDOWS_TUN_PLAN_SCHEMA_VERSION = 5
WINDOWS_TUN_PLAN_MAX_BYTES = 4 * 1024 * 1024

WINDOWS_TUN_DIAGNOSTIC_PROFILES = {
    "UdpFlowBoundary": {
        "scenario": "udp-8192-association-lookup-expiry",
        "member": "parent",
        "pair": 1,
        "order": 1,
    }
}


WINDOWS_TUN_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "selection",
        "run_kind",
        "pairs",
        "pair_schedule",
        "recipe_sha256",
        "controller_bundle_sha256",
        "scenarios",
        "trials",
        "diagnostic_profiles",
        "decision_policy",
        "calibration_complete",
        "adoption_eligible",
    }
)


def create_windows_tun_plan(
    *,
    run_kind: str,
    decision_policy: dict[str, object],
    controller_bundle_sha256: str,
) -> dict[str, object]:
    if run_kind not in WINDOWS_TUN_RUN_KINDS:
        raise CandidateControlError(
            "Windows TUN run_kind must be comparison or calibration-aa"
        )
    policy = copy.deepcopy(decision_policy)
    validate_windows_tun_policy(
        policy, controller_bundle_sha256=controller_bundle_sha256
    )
    contracts = scenario_contracts()
    trials: list[dict[str, object]] = []
    sequence = 0
    # The canonical JSON form sorts object keys for hashing, but trial execution
    # follows the reviewed declaration order. Never derive an ordered schedule
    # from canonical object keys.
    for scenario in scenario_catalog():
        for pair in range(1, WINDOWS_TUN_PAIR_COUNT + 1):
            members = ("parent", "candidate") if pair % 2 else ("candidate", "parent")
            for order, member in enumerate(members, start=1):
                sequence += 1
                trials.append(
                    {
                        "sequence": sequence,
                        "scenario": scenario,
                        "pair": pair,
                        "member": member,
                        "order": order,
                    }
                )
    calibrated = windows_tun_policy_is_calibrated(
        policy, controller_bundle_sha256=controller_bundle_sha256
    )
    return {
        "schema_version": WINDOWS_TUN_PLAN_SCHEMA_VERSION,
        "kind": "windows_tun_performance_plan",
        "selection": WINDOWS_TUN_SELECTION,
        "run_kind": run_kind,
        "pairs": WINDOWS_TUN_PAIR_COUNT,
        "pair_schedule": WINDOWS_TUN_PAIR_SCHEDULE,
        "recipe_sha256": recipe_sha256(controller_bundle_sha256),
        "controller_bundle_sha256": controller_bundle_sha256,
        "scenarios": contracts,
        "trials": trials,
        "diagnostic_profiles": copy.deepcopy(WINDOWS_TUN_DIAGNOSTIC_PROFILES),
        "decision_policy": policy,
        "calibration_complete": calibrated,
        # A plan can enable a calibrated decision, but evidence is the only
        # thing that can make the resulting comparison adoption-eligible.
        "adoption_eligible": False,
    }


def load_windows_tun_plan(
    path: pathlib.Path,
    *,
    decision_policy: dict[str, object],
    controller_bundle_sha256: str,
) -> dict[str, object]:
    try:
        plan = read_bounded_closed_json(
            path,
            maximum_bytes=WINDOWS_TUN_PLAN_MAX_BYTES,
            source="Windows TUN performance plan",
        ).value
        if type(plan) is not dict:
            raise CandidateControlError("Windows TUN plan must be a JSON object")
        _exact_fields(plan, WINDOWS_TUN_PLAN_FIELDS, "Windows TUN performance plan")
        expected = create_windows_tun_plan(
            run_kind=plan["run_kind"],
            decision_policy=decision_policy,
            controller_bundle_sha256=controller_bundle_sha256,
        )
    except (KeyError, TypeError) as error:
        raise CandidateControlError("Windows TUN performance plan is invalid") from error
    if _canonical_json_bytes(plan) != _canonical_json_bytes(expected):
        raise CandidateControlError(
            "Windows TUN performance plan does not match the canonical recipe or policy"
        )
    return plan


def resolve_windows_tun_diagnostic_profile(
    plan: dict[str, object], profile: str
) -> dict[str, object]:
    """Resolve a stable diagnostic profile to its canonical scheduled trial."""

    try:
        profiles = plan["diagnostic_profiles"]
        if type(profiles) is not dict or profile not in profiles:
            raise CandidateControlError("Windows TUN diagnostic profile is unsupported")
        selector = profiles[profile]
        if type(selector) is not dict:
            raise CandidateControlError("Windows TUN diagnostic profile must be an object")
        selector_fields = {"scenario", "member", "pair", "order"}
        _exact_fields(
            selector,
            selector_fields,
            f"Windows TUN diagnostic profile {profile}",
        )
        trials = plan["trials"]
        if type(trials) is not list:
            raise CandidateControlError("Windows TUN plan trials must be an array")
        matching = [
            trial
            for trial in trials
            if type(trial) is dict
            and all(trial.get(field) == selector[field] for field in selector_fields)
        ]
    except (KeyError, TypeError) as error:
        raise CandidateControlError("Windows TUN diagnostic profile is invalid") from error
    if len(matching) != 1:
        raise CandidateControlError(
            "Windows TUN diagnostic profile does not resolve to one canonical trial"
        )
    return matching[0]
