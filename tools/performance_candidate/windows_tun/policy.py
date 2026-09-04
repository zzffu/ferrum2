"""Closed decision policy for Windows-host TUN performance evidence."""

from __future__ import annotations

import pathlib

from tools.performance_candidate.json_contract import (
    CandidateControlError,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.windows_tun.recipe import (
    WINDOWS_TUN_PROFILES,
    WINDOWS_TUN_SELECTION,
    WINDOWS_TUN_THRESHOLD_PERCENT,
)

WINDOWS_TUN_POLICY_MAX_BYTES = 64 * 1024
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "selection",
        "threshold_percent",
        "maximum_non_target_regression_percent",
        "require_majority_pairs",
        "profiles",
        "soak",
    }
)
_PROFILE_FIELDS = frozenset(
    {"pair_count", "warmup_seconds", "active_seconds", "lifecycle_cycles", "scenarios"}
)


def _integer(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CandidateControlError(f"{field} is outside its bounded integer contract")
    return value


def validate_windows_tun_policy(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError("Windows TUN policy must be a JSON object")
    policy = value
    _exact_fields(policy, _POLICY_FIELDS, "Windows TUN policy")
    if policy["schema_version"] != 1:
        raise CandidateControlError("Windows TUN policy schema_version is invalid")
    if policy["kind"] != "ferrum2.windows-tun.host-performance-policy":
        raise CandidateControlError("Windows TUN policy kind is invalid")
    if policy["selection"] != WINDOWS_TUN_SELECTION:
        raise CandidateControlError("Windows TUN policy selection is invalid")
    if policy["threshold_percent"] != WINDOWS_TUN_THRESHOLD_PERCENT:
        raise CandidateControlError("Windows TUN policy threshold is invalid")
    if policy["maximum_non_target_regression_percent"] != 2.0:
        raise CandidateControlError("Windows TUN non-target regression bound is invalid")
    if policy["require_majority_pairs"] is not True:
        raise CandidateControlError("Windows TUN policy must require a pair majority")
    profiles = policy["profiles"]
    if type(profiles) is not dict or set(profiles) != set(WINDOWS_TUN_PROFILES):
        raise CandidateControlError("Windows TUN policy profile set is invalid")
    for mode, expected in WINDOWS_TUN_PROFILES.items():
        profile = profiles[mode]
        if type(profile) is not dict:
            raise CandidateControlError(f"Windows TUN {mode} profile must be an object")
        _exact_fields(profile, _PROFILE_FIELDS, f"Windows TUN {mode} profile")
        for field, maximum in (
            ("pair_count", 16),
            ("warmup_seconds", 60),
            ("active_seconds", 300),
            ("lifecycle_cycles", 100),
        ):
            actual = _integer(profile[field], f"{mode}.{field}", minimum=0, maximum=maximum)
            if actual != expected[field]:
                raise CandidateControlError(f"Windows TUN {mode}.{field} changed")
        scenarios = profile["scenarios"]
        expected_scenarios = [row[0] for row in expected["scenarios"]]
        if type(scenarios) is not list or scenarios != expected_scenarios:
            raise CandidateControlError(f"Windows TUN {mode} scenario set changed")
    soak = policy["soak"]
    if type(soak) is not dict:
        raise CandidateControlError("Windows TUN soak policy must be an object")
    _exact_fields(
        soak,
        frozenset({"enabled_by_default", "cycles", "candidate_decision_input"}),
        "Windows TUN soak policy",
    )
    if (
        soak["enabled_by_default"] is not False
        or soak["candidate_decision_input"] is not False
        or _integer(soak["cycles"], "soak.cycles", minimum=1000, maximum=1000) != 1000
    ):
        raise CandidateControlError("Windows TUN soak must remain isolated and opt-in")
    return policy


def load_windows_tun_policy(path: pathlib.Path) -> dict[str, object]:
    document = read_bounded_closed_json(
        path,
        maximum_bytes=WINDOWS_TUN_POLICY_MAX_BYTES,
        source="Windows TUN host performance policy",
    )
    return validate_windows_tun_policy(document.value)
