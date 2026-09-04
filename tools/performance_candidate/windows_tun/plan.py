"""Validation for the nonmutating Windows-host TUN execution plan."""

from __future__ import annotations

import pathlib
import re

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_PROFILES

WINDOWS_TUN_PLAN_MAX_BYTES = 512 * 1024
_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "execution",
        "mode",
        "baseline_sha",
        "candidate_sha",
        "performance_source_bundle_sha256",
        "pair_count",
        "warmup_seconds",
        "active_seconds",
        "lifecycle_cycles",
        "scenario_count",
        "trial_count",
        "scenarios",
        "trials",
        "safety",
        "qualification",
    }
)
_TRIAL_FIELDS = frozenset(
    {
        "sequence",
        "pair",
        "order",
        "scenario",
        "metric",
        "unit",
        "member",
        "commit_sha",
        "warmup_seconds",
        "active_seconds",
        "initial_product_state",
    }
)
_LIFECYCLE_TRIAL_FIELDS = frozenset(
    {"sequence", "scenario", "member", "commit_sha", "lifecycle_cycles", "action"}
)


def _sha(value: object, field: str) -> str:
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise CandidateControlError(f"{field} must be a lowercase SHA-256 identity")
    return value

def _commit_sha(value: object, field: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise CandidateControlError(f"{field} must be a lowercase commit SHA")
    return value


def _exact_safety(plan: dict[str, object]) -> None:
    safety = plan["safety"]
    if type(safety) is not dict:
        raise CandidateControlError("Windows TUN plan safety must be an object")
    _exact_fields(
        safety,
        frozenset(
            {
                "requires_elevation",
                "requires_explicit_acknowledgement",
                "automatic_elevation",
                "address_family",
                "route_scope",
                "mutations",
                "forbidden_mutations",
                "cleanup",
                "recovery",
            }
        ),
        "Windows TUN plan safety",
    )
    if (
        safety["requires_elevation"] is not True
        or safety["requires_explicit_acknowledgement"] is not True
        or safety["automatic_elevation"] is not False
        or safety["address_family"] != "RFC2544 198.18.0.0/15"
        or safety["route_scope"] != "run-owned /32 only"
    ):
        raise CandidateControlError("Windows TUN plan weakened the host authorization contract")
    if safety["mutations"] != [
        "one run-owned Wintun adapter",
        "run-owned RFC2544 loopback support address",
        "run-owned narrow routes",
    ]:
        raise CandidateControlError("Windows TUN plan mutation closure changed")
    if safety["forbidden_mutations"] != [
        "default route",
        "system DNS",
        "physical adapters",
        "WLAN",
        "firewall",
        "WFP",
        "sing-box",
    ]:
        raise CandidateControlError("Windows TUN plan forbidden mutation closure changed")


def validate_windows_tun_plan(
    value: object, *, baseline_sha: str, candidate_sha: str, mode: str
) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError("Windows TUN host plan must be a JSON object")
    plan = value
    _exact_fields(plan, _PLAN_FIELDS, "Windows TUN host plan")
    if (
        plan["schema_version"] != 1
        or plan["kind"] != "ferrum2.windows-tun.host-performance-plan"
        or plan["execution"] != "explicit-authorized-windows-host"
        or plan["mode"] != mode
    ):
        raise CandidateControlError("Windows TUN host plan identity is invalid")
    if mode not in WINDOWS_TUN_PROFILES:
        raise CandidateControlError("Windows TUN host plan mode is invalid")
    _sha(
        plan["performance_source_bundle_sha256"],
        "performance_source_bundle_sha256",
    )
    if _commit_sha(plan["baseline_sha"], "baseline_sha") != baseline_sha:
        raise CandidateControlError("Windows TUN plan baseline SHA changed")
    if _commit_sha(plan["candidate_sha"], "candidate_sha") != candidate_sha:
        raise CandidateControlError("Windows TUN plan candidate SHA changed")
    profile = WINDOWS_TUN_PROFILES[mode]
    for field in ("pair_count", "warmup_seconds", "active_seconds", "lifecycle_cycles"):
        if plan[field] != profile[field]:
            raise CandidateControlError(f"Windows TUN plan {field} changed")
    expected_scenarios = [
        {"name": name, "metric": metric, "unit": unit}
        for name, metric, unit in profile["scenarios"]
    ]
    if plan["scenarios"] != expected_scenarios or plan["scenario_count"] != len(expected_scenarios):
        raise CandidateControlError("Windows TUN plan scenario closure changed")
    trials = plan["trials"]
    if type(trials) is not list:
        raise CandidateControlError("Windows TUN plan trials must be an array")
    expected_trial_count = 1 if mode == "Lifecycle" else len(expected_scenarios) * profile["pair_count"] * 2
    if plan["trial_count"] != expected_trial_count or len(trials) != expected_trial_count:
        raise CandidateControlError("Windows TUN plan trial count is invalid")
    if mode == "Lifecycle":
        trial = trials[0]
        if type(trial) is not dict:
            raise CandidateControlError("Windows TUN lifecycle trial must be an object")
        _exact_fields(trial, _LIFECYCLE_TRIAL_FIELDS, "Windows TUN lifecycle trial")
        if trial != {
            "sequence": 1,
            "scenario": "product-lifecycle",
            "member": "candidate",
            "commit_sha": candidate_sha,
            "lifecycle_cycles": 20,
            "action": "product-start-probe-stop",
        }:
            raise CandidateControlError("Windows TUN lifecycle trial contract changed")
    else:
        sequence = 0
        for scenario in expected_scenarios:
            for pair in range(1, profile["pair_count"] + 1):
                order = "baseline-candidate" if pair % 2 else "candidate-baseline"
                members = ("baseline", "candidate") if pair % 2 else ("candidate", "baseline")
                for member in members:
                    sequence += 1
                    trial = trials[sequence - 1]
                    if type(trial) is not dict:
                        raise CandidateControlError("Windows TUN plan trial must be an object")
                    _exact_fields(trial, _TRIAL_FIELDS, "Windows TUN plan trial")
                    expected_sha = baseline_sha if member == "baseline" else candidate_sha
                    expected = {
                        "sequence": sequence,
                        "pair": pair,
                        "order": order,
                        "scenario": scenario["name"],
                        "metric": scenario["metric"],
                        "unit": scenario["unit"],
                        "member": member,
                        "commit_sha": expected_sha,
                        "warmup_seconds": profile["warmup_seconds"],
                        "active_seconds": profile["active_seconds"],
                        "initial_product_state": "fresh-processes-and-adapter",
                    }
                    if trial != expected:
                        raise CandidateControlError(f"Windows TUN trial {sequence} changed")
    _exact_safety(plan)
    qualification = plan["qualification"]
    if type(qualification) is not dict:
        raise CandidateControlError("Windows TUN qualification plan must be an object")
    _exact_fields(
        qualification,
        frozenset(
            {"product_lifecycle_cycles", "long_durability_soak", "vm_start", "checkpoint_restore", "guest_staging"}
        ),
        "Windows TUN qualification plan",
    )
    if qualification != {
        "product_lifecycle_cycles": profile["lifecycle_cycles"],
        "long_durability_soak": "excluded",
        "vm_start": False,
        "checkpoint_restore": False,
        "guest_staging": False,
    }:
        raise CandidateControlError("Windows TUN qualification isolation changed")
    return plan


def load_windows_tun_plan(
    path: pathlib.Path, *, baseline_sha: str, candidate_sha: str, mode: str
) -> dict[str, object]:
    document = read_bounded_closed_json(
        path, maximum_bytes=WINDOWS_TUN_PLAN_MAX_BYTES, source="Windows TUN host plan"
    )
    return validate_windows_tun_plan(
        document.value,
        baseline_sha=baseline_sha,
        candidate_sha=candidate_sha,
        mode=mode,
    )
