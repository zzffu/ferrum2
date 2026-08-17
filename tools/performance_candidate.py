#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from decimal import Decimal

WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
MODES = frozenset({"diagnostic", "qualification"})
SCENARIO_CATALOG = {
    "tcp-bulk": ("bytes_per_second", "higher_is_better", "tcp-throughput"),
    "tcp-stream-64k": (
        "bytes_per_second",
        "higher_is_better",
        "tcp-throughput",
    ),
    "tcp-request-1k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-4k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-16k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "udp-small-high": (
        "datagrams_per_second",
        "higher_is_better",
        "udp",
    ),
    "udp-mtu-1200": ("datagrams_per_second", "higher_is_better", "udp"),
}
TCP_REQUEST_SCENARIOS = (
    "tcp-request-1k",
    "tcp-request-4k",
    "tcp-request-16k",
)
PROFILE_FIELDS = frozenset(
    {
        "kind",
        "parent_sha",
        "candidate_sha",
        "member",
        "pair",
        "order",
        "build_profile",
        "scenario",
        "warmup_seconds",
        "active_seconds",
        "sha",
        "tree",
        "runner_sha256",
        "client_sha256",
        "server_sha256",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "metric",
        "value",
        "checked_units",
        "p99_nanoseconds",
        "io_completions",
        "correctness",
        "status",
    }
)
SHA256 = re.compile(r"[0-9a-f]{64}")
U64_MAX = (1 << 64) - 1
MEASUREMENT_ENVIRONMENT = {
    "runner_image": "ubuntu-24.04",
    "runner_os": "Linux",
    "runner_arch": "X64",
    "rust_toolchain": "1.97.1",
    "cargo_profile": "profiling",
    "evidence_build_profile": "current",
    "pair_schedule": "alternating-parent-candidate",
}
POLICY_DOCUMENT_FIELDS = frozenset({"schema_version", "policy_id", "scenarios"})
POLICY_RUNTIME_FIELDS = frozenset(
    {"schema_version", "policy_id", "policy_sha256", "scenarios"}
)
THRESHOLD_FIELDS = frozenset(
    {
        "metric",
        "direction",
        "noise_band_percent",
        "regression_threshold_percent",
        "adoption_threshold_percent",
        "minimum_pairs",
        "minimum_wins",
        "minimum_losses",
        "calibration_source",
        "calibration_environment",
    }
)
CALIBRATION_ENVIRONMENT_FIELDS = frozenset(
    {
        *MEASUREMENT_ENVIRONMENT,
        "warmup_seconds",
        "active_seconds",
    }
)
UNCALIBRATED_POLICY = {
    "schema_version": 1,
    "policy_id": "in-memory-uncalibrated-policy",
    "policy_sha256": None,
    "scenarios": {
        scenario: {
            "metric": metric,
            "direction": direction,
            "noise_band_percent": None,
            "regression_threshold_percent": None,
            "adoption_threshold_percent": None,
            "minimum_pairs": None,
            "minimum_wins": None,
            "minimum_losses": None,
            "calibration_source": None,
            "calibration_environment": None,
        }
        for scenario, (metric, direction, _family) in SCENARIO_CATALOG.items()
    },
}


class CandidateControlError(ValueError):
    """An invalid performance-candidate request or evidence set."""


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


def _git(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _require_commit(repository: pathlib.Path, sha: str, *, name: str) -> str:
    if COMMIT_SHA.fullmatch(sha) is None:
        raise CandidateControlError(f"{name} must be a full 40-character commit SHA")
    canonical = sha.lower()
    probe = _git(repository, "cat-file", "-t", canonical)
    if probe.returncode != 0 or probe.stdout.strip() != "commit":
        raise CandidateControlError(
            f"{name} is not an available commit; fetch complete history before comparing"
        )
    return canonical


def validate_git_relation(
    repository: pathlib.Path, parent_sha: str, candidate_sha: str
) -> tuple[str, str]:
    """Require two available commits with parent strictly ancestral to candidate."""

    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("repository must be an existing directory")
    parent = _require_commit(repository, parent_sha, name="parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="candidate_sha")
    if parent == candidate:
        raise CandidateControlError(
            "parent_sha and candidate_sha must be different commits"
        )
    relation = _git(repository, "merge-base", "--is-ancestor", parent, candidate)
    if relation.returncode == 1:
        raise CandidateControlError("parent_sha is not an ancestor of candidate_sha")
    if relation.returncode != 0:
        raise CandidateControlError(
            "unable to confirm parent/candidate ancestry from the available history"
        )
    return parent, candidate


def _scenario_entry(scenario: str, role: str) -> dict[str, object]:
    metric, direction, _family = SCENARIO_CATALOG[scenario]
    return {
        "scenario": scenario,
        "role": role,
        "mandatory": True,
        "metric": metric,
        "direction": direction,
    }


def _qualification_scenarios(selected: str) -> list[dict[str, object]]:
    family = SCENARIO_CATALOG[selected][2]
    if family == "tcp-throughput":
        guard = "tcp-bulk" if selected == "tcp-stream-64k" else "tcp-stream-64k"
        return [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")]
    if family == "tcp-request":
        scenarios = [_scenario_entry(selected, "primary")]
        scenarios.extend(
            _scenario_entry(scenario, "guard")
            for scenario in TCP_REQUEST_SCENARIOS
            if scenario != selected
        )
        scenarios.append(_scenario_entry("tcp-bulk", "guard"))
        return scenarios
    if family == "udp":
        guard = "udp-mtu-1200" if selected == "udp-small-high" else "udp-small-high"
        return [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")]
    raise AssertionError(f"unhandled scenario family: {family}")


def create_plan(
    *,
    mode: str,
    scenario: str,
    warmup_seconds: str,
    active_seconds: str,
    pairs: str,
    decision_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the authoritative scenario plan for one manual workflow run."""

    if mode not in MODES:
        raise CandidateControlError("mode must be diagnostic or qualification")
    if scenario not in SCENARIO_CATALOG:
        raise CandidateControlError("scenario is not a supported profile workload")
    warmup, active, pair_count = validate_measurement_inputs(
        warmup_seconds, active_seconds, pairs
    )
    policy = copy.deepcopy(
        UNCALIBRATED_POLICY if decision_policy is None else decision_policy
    )
    validate_decision_policy(policy)
    scenarios = (
        [_scenario_entry(scenario, "diagnostic")]
        if mode == "diagnostic"
        else _qualification_scenarios(scenario)
    )
    return {
        "schema_version": 2,
        "mode": mode,
        "selected_scenario": scenario,
        "warmup_seconds": warmup,
        "active_seconds": active,
        "pairs": pair_count,
        "measurement_environment": dict(MEASUREMENT_ENVIRONMENT),
        "decision_policy": policy,
        "adoption_eligible": mode == "qualification"
        and _plan_has_complete_applicable_policy(
            scenarios=scenarios,
            policy=policy,
            warmup_seconds=warmup,
            active_seconds=active,
            pairs=pair_count,
        ),
        "scenarios": scenarios,
    }


def write_plan(path: pathlib.Path, plan: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _reject_json_constant(value: str) -> object:
    raise CandidateControlError(f"non-finite JSON number is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateControlError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _strict_json(text: str, *, source: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except CandidateControlError:
        raise
    except json.JSONDecodeError as error:
        raise CandidateControlError(f"{source} is not valid JSON") from error


def _exact_fields(
    value: dict[str, object], expected: frozenset[str], name: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise CandidateControlError(
            f"{name} schema mismatch: missing={missing}, unexpected={unexpected}"
        )


def _policy_percent(value: object, field: str) -> Decimal:
    if type(value) not in {int, float}:
        raise CandidateControlError(f"{field} must be a finite JSON number")
    parsed = Decimal(str(value))
    if not parsed.is_finite():
        raise CandidateControlError(f"{field} must be finite")
    return parsed


def _calibration_environment_matches(
    environment: dict[str, object], *, warmup_seconds: int, active_seconds: int
) -> bool:
    expected = {
        **MEASUREMENT_ENVIRONMENT,
        "warmup_seconds": warmup_seconds,
        "active_seconds": active_seconds,
    }
    return environment == expected


def validate_decision_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(policy, POLICY_RUNTIME_FIELDS, "decision policy")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise CandidateControlError("decision policy schema_version must be 1")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("decision policy_id must be a non-empty string")
    digest = policy["policy_sha256"]
    if digest is not None and (
        type(digest) is not str or SHA256.fullmatch(digest) is None
    ):
        raise CandidateControlError("decision policy_sha256 must be a SHA-256 digest")
    scenarios = policy["scenarios"]
    if type(scenarios) is not dict or set(scenarios) != set(SCENARIO_CATALOG):
        raise CandidateControlError(
            "decision policy scenarios must exactly match the scenario catalog"
        )
    for scenario, entry in scenarios.items():
        if type(entry) is not dict:
            raise CandidateControlError(f"policy scenario {scenario} must be an object")
        _exact_fields(entry, THRESHOLD_FIELDS, f"policy scenario {scenario}")
        metric, direction, _family = SCENARIO_CATALOG[scenario]
        if entry["metric"] != metric or entry["direction"] != direction:
            raise CandidateControlError(
                f"policy scenario {scenario} metric or direction does not match the catalog"
            )
        calibrated_fields = (
            "noise_band_percent",
            "regression_threshold_percent",
            "adoption_threshold_percent",
            "minimum_pairs",
            "minimum_wins",
            "minimum_losses",
            "calibration_source",
            "calibration_environment",
        )
        values = [entry[field] for field in calibrated_fields]
        if all(value is None for value in values):
            continue
        if any(value is None for value in values):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration must be complete or entirely null"
            )
        noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
        regression = _policy_percent(
            entry["regression_threshold_percent"],
            "regression_threshold_percent",
        )
        adoption = _policy_percent(
            entry["adoption_threshold_percent"], "adoption_threshold_percent"
        )
        if noise < 0 or regression >= -noise or adoption <= noise:
            raise CandidateControlError(
                f"policy scenario {scenario} thresholds must lie outside the noise band"
            )
        minimum_pairs = entry["minimum_pairs"]
        minimum_wins = entry["minimum_wins"]
        minimum_losses = entry["minimum_losses"]
        if (
            type(minimum_pairs) is not int
            or minimum_pairs not in PAIR_COUNTS
            or type(minimum_wins) is not int
            or not 1 <= minimum_wins <= minimum_pairs
            or type(minimum_losses) is not int
            or not 1 <= minimum_losses <= minimum_pairs
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} minimum pair/win/loss counts are invalid"
            )
        if (
            type(entry["calibration_source"]) is not str
            or not entry["calibration_source"].strip()
            or re.fullmatch(r"(?:artifact|commit):\S+", entry["calibration_source"])
            is None
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration_source is required"
            )
        environment = entry["calibration_environment"]
        if type(environment) is not dict:
            raise CandidateControlError(
                f"policy scenario {scenario} calibration_environment is required"
            )
        _exact_fields(
            environment,
            CALIBRATION_ENVIRONMENT_FIELDS,
            f"policy scenario {scenario} calibration_environment",
        )
        for field, expected in MEASUREMENT_ENVIRONMENT.items():
            if environment[field] != expected:
                raise CandidateControlError(
                    f"policy scenario {scenario} calibration_environment {field} is unsupported"
                )
        if (
            type(environment["warmup_seconds"]) is not int
            or environment["warmup_seconds"] not in WARMUP_SECONDS
            or type(environment["active_seconds"]) is not int
            or environment["active_seconds"] not in ACTIVE_SECONDS
        ):
            raise CandidateControlError(
                f"policy scenario {scenario} calibration recipe is unsupported"
            )


def load_decision_policy(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        document = _strict_json(raw.decode("utf-8"), source="decision policy")
    except (OSError, UnicodeError) as error:
        raise CandidateControlError("unable to read decision policy") from error
    if type(document) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(document, POLICY_DOCUMENT_FIELDS, "decision policy document")
    policy = {
        **document,
        "policy_sha256": hashlib.sha256(raw).hexdigest(),
    }
    validate_decision_policy(policy)
    return policy


def _scenario_policy_is_applicable(
    *,
    entry: dict[str, object],
    warmup_seconds: int,
    active_seconds: int,
    pairs: int,
) -> bool:
    environment = entry["calibration_environment"]
    return (
        environment is not None
        and pairs >= entry["minimum_pairs"]
        and _calibration_environment_matches(
            environment,
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
        )
    )


def _plan_has_complete_applicable_policy(
    *,
    scenarios: list[dict[str, object]],
    policy: dict[str, object],
    warmup_seconds: int,
    active_seconds: int,
    pairs: int,
) -> bool:
    return all(
        _scenario_policy_is_applicable(
            entry=policy["scenarios"][scenario["scenario"]],
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
            pairs=pairs,
        )
        for scenario in scenarios
    )


def load_plan(
    path: pathlib.Path, decision_policy: dict[str, object] | None = None
) -> dict[str, object]:
    try:
        plan = _strict_json(path.read_text(encoding="utf-8"), source="performance plan")
        if type(plan) is not dict:
            raise CandidateControlError("performance plan must be a JSON object")
        policy = plan["decision_policy"] if decision_policy is None else decision_policy
        validate_decision_policy(policy)
        expected = create_plan(
            mode=plan["mode"],
            scenario=plan["selected_scenario"],
            warmup_seconds=str(plan["warmup_seconds"]),
            active_seconds=str(plan["active_seconds"]),
            pairs=str(plan["pairs"]),
            decision_policy=policy,
        )
    except (OSError, KeyError, TypeError) as error:
        raise CandidateControlError("performance plan is invalid") from error
    if plan != expected:
        raise CandidateControlError(
            "performance plan does not match the canonical scenario set"
        )
    return plan


def _required_string(
    row: dict[str, object], field: str, *, expected: str | None = None
) -> str:
    value = row.get(field)
    if type(value) is not str or not value:
        raise CandidateControlError(f"{field} must be a non-empty string")
    if expected is not None and value != expected:
        raise CandidateControlError(f"{field} does not match the expected value")
    return value


def _required_u64(row: dict[str, object], field: str, *, positive: bool = False) -> int:
    value = row.get(field)
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise CandidateControlError(f"{field} must be an unsigned 64-bit integer")
    if positive and value == 0:
        raise CandidateControlError(f"{field} must be positive")
    return value


def _require_pattern(value: str, pattern: re.Pattern[str], *, field: str) -> None:
    if pattern.fullmatch(value) is None:
        raise CandidateControlError(f"{field} has an invalid identity")


def _read_trial(path: pathlib.Path) -> dict[str, object]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CandidateControlError(
            f"unable to read evidence file {path.name}"
        ) from error
    if len(lines) != 1 or not lines[0]:
        raise CandidateControlError(
            f"evidence file {path.name} must contain exactly one JSON row"
        )
    row = _strict_json(lines[0], source=f"evidence file {path.name}")
    if type(row) is not dict:
        raise CandidateControlError(f"evidence file {path.name} must contain an object")
    if set(row) != PROFILE_FIELDS:
        missing = sorted(PROFILE_FIELDS - set(row))
        unexpected = sorted(set(row) - PROFILE_FIELDS)
        raise CandidateControlError(
            f"evidence schema mismatch in {path.name}: missing={missing}, unexpected={unexpected}"
        )
    return row


def _validate_trial(
    row: dict[str, object],
    *,
    source_member: str,
    plan: dict[str, object],
    planned: dict[str, dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
) -> tuple[str, int, str]:
    _required_string(row, "kind", expected="m18_profile_trial")
    _required_string(row, "parent_sha", expected=parent_sha)
    _required_string(row, "candidate_sha", expected=candidate_sha)
    member = _required_string(row, "member")
    if member not in {"parent", "candidate"} or member != source_member:
        raise CandidateControlError(
            "evidence member does not match its source directory"
        )
    scenario = _required_string(row, "scenario")
    if scenario not in planned:
        raise CandidateControlError(f"unexpected scenario in evidence: {scenario}")
    pair = _required_u64(row, "pair", positive=True)
    if pair > plan["pairs"]:
        raise CandidateControlError("evidence pair is outside the planned range")
    order = _required_u64(row, "order", positive=True)
    if order not in {1, 2}:
        raise CandidateControlError("evidence order must be 1 or 2")
    _required_string(row, "build_profile", expected="current")
    if _required_u64(row, "warmup_seconds", positive=True) != plan["warmup_seconds"]:
        raise CandidateControlError("evidence warmup_seconds does not match the plan")
    if _required_u64(row, "active_seconds", positive=True) != plan["active_seconds"]:
        raise CandidateControlError("evidence active_seconds does not match the plan")
    expected_sha = parent_sha if member == "parent" else candidate_sha
    sha = _required_string(row, "sha", expected=expected_sha)
    tree = _required_string(row, "tree")
    _require_pattern(sha, COMMIT_SHA, field="sha")
    _require_pattern(tree, COMMIT_SHA, field="tree")
    for field in ("runner_sha256", "client_sha256", "server_sha256"):
        _require_pattern(_required_string(row, field), SHA256, field=field)
    for field in ("rustc", "kernel", "cpu_model"):
        _required_string(row, field)
    _required_u64(row, "cpu_count", positive=True)
    _required_u64(row, "memory_kib", positive=True)
    metric = _required_string(row, "metric", expected=planned[scenario]["metric"])
    value = _required_u64(row, "value")
    _required_u64(row, "checked_units", positive=True)
    _required_u64(row, "io_completions", positive=True)
    p99 = row.get("p99_nanoseconds")
    if metric == "p99_nanoseconds":
        if type(p99) is not int or p99 != value or value == 0:
            raise CandidateControlError(
                "request evidence requires positive matching value and p99_nanoseconds"
            )
    elif p99 is not None:
        raise CandidateControlError(
            "throughput evidence must have null p99_nanoseconds"
        )
    _required_string(row, "correctness", expected="PASS")
    _required_string(row, "status", expected="PASS")
    return scenario, pair, member


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    if not ordered:
        raise CandidateControlError("median requires at least one value")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def _improvement(parent: int, candidate: int, direction: str) -> Decimal:
    if parent <= 0:
        raise CandidateControlError("parent metric baseline must be positive")
    difference = (
        candidate - parent if direction == "higher_is_better" else parent - candidate
    )
    return Decimal(difference) * Decimal(100) / Decimal(parent)


def _display_decimal(value: Decimal) -> float:
    return round(float(value), 9)


def _observed_direction(*, wins: int, losses: int) -> str:
    if wins and losses:
        return "mixed"
    if wins:
        return "positive"
    if losses:
        return "negative"
    return "neutral"


def _scenario_threshold_decision(
    *,
    plan: dict[str, object],
    scenario_plan: dict[str, object],
    wins: int,
    losses: int,
    median_improvement: Decimal,
) -> dict[str, object]:
    entry = plan["decision_policy"]["scenarios"][scenario_plan["scenario"]]
    common = {
        "noise_band_percent": entry["noise_band_percent"],
        "regression_threshold_percent": entry["regression_threshold_percent"],
        "adoption_threshold_percent": entry["adoption_threshold_percent"],
        "minimum_pairs": entry["minimum_pairs"],
        "minimum_wins": entry["minimum_wins"],
        "minimum_losses": entry["minimum_losses"],
        "threshold_source": entry["calibration_source"],
        "calibration_environment": entry["calibration_environment"],
    }
    if plan["mode"] == "diagnostic":
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "diagnostic mode reports measurements only",
            "threshold_decision": "DIAGNOSTIC_ONLY",
            "guard_passed": None,
            "status": "MEASURED",
        }
    if entry["calibration_environment"] is None:
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "no calibrated threshold for this scenario",
            "threshold_decision": "NO_CALIBRATION",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    if not _scenario_policy_is_applicable(
        entry=entry,
        warmup_seconds=plan["warmup_seconds"],
        active_seconds=plan["active_seconds"],
        pairs=plan["pairs"],
    ):
        return {
            **common,
            "decision_enabled": False,
            "decision_reason": "calibration recipe or minimum pair count does not match",
            "threshold_decision": "CALIBRATION_NOT_APPLICABLE",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
    regression = _policy_percent(
        entry["regression_threshold_percent"], "regression_threshold_percent"
    )
    adoption = _policy_percent(
        entry["adoption_threshold_percent"], "adoption_threshold_percent"
    )
    if median_improvement <= regression:
        if losses >= entry["minimum_losses"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "median and loss count confirm calibrated regression",
                "threshold_decision": "CONFIRMED_REGRESSION",
                "guard_passed": False,
                "status": "REGRESSION",
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "regression threshold crossed without enough confirming losses",
            "threshold_decision": "INSUFFICIENT_LOSSES",
            "guard_passed": False,
            "status": "INCONCLUSIVE",
        }
    if scenario_plan["role"] == "guard":
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "guard remains above its calibrated regression threshold",
            "threshold_decision": "GUARD_CLEAR",
            "guard_passed": True,
            "status": "INCONCLUSIVE",
        }
    if median_improvement >= adoption:
        if wins >= entry["minimum_wins"]:
            return {
                **common,
                "decision_enabled": True,
                "decision_reason": "adoption threshold and minimum wins are satisfied",
                "threshold_decision": "CANDIDATE_IMPROVEMENT",
                "guard_passed": None,
                "status": "CANDIDATE_WIN",
            }
        return {
            **common,
            "decision_enabled": True,
            "decision_reason": "adoption threshold crossed without enough wins",
            "threshold_decision": "INSUFFICIENT_WINS",
            "guard_passed": None,
            "status": "INCONCLUSIVE",
        }
    if -noise <= median_improvement <= noise:
        reason = "median remains inside the calibrated noise band"
        threshold_decision = "WITHIN_NOISE"
    else:
        reason = "median does not cross a calibrated decision threshold"
        threshold_decision = "BETWEEN_THRESHOLDS"
    return {
        **common,
        "decision_enabled": True,
        "decision_reason": reason,
        "threshold_decision": threshold_decision,
        "guard_passed": None,
        "status": "INCONCLUSIVE",
    }


def summarize_evidence(
    *,
    plan: dict[str, object],
    parent_root: pathlib.Path,
    candidate_root: pathlib.Path,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    """Validate paired raw evidence and calculate per-pair directional deltas."""

    if (
        COMMIT_SHA.fullmatch(parent_sha) is None
        or COMMIT_SHA.fullmatch(candidate_sha) is None
    ):
        raise CandidateControlError("summary identities must be full commit SHAs")
    parent_sha = parent_sha.lower()
    candidate_sha = candidate_sha.lower()
    if parent_sha == candidate_sha:
        raise CandidateControlError("summary parent and candidate must be different")
    planned = {entry["scenario"]: entry for entry in plan["scenarios"]}
    rows: dict[tuple[str, int, str], dict[str, object]] = {}
    evidence_files: list[dict[str, str]] = []
    member_identity: dict[str, tuple[object, ...]] = {}
    environment_identity: tuple[object, ...] | None = None
    for member, root in (("parent", parent_root), ("candidate", candidate_root)):
        if not root.is_dir():
            raise CandidateControlError(f"{member} evidence directory is missing")
        files = sorted(root.glob("*.jsonl"))
        if not files:
            raise CandidateControlError(
                f"{member} evidence directory has no JSONL files"
            )
        for path in files:
            row = _read_trial(path)
            scenario, pair, row_member = _validate_trial(
                row,
                source_member=member,
                plan=plan,
                planned=planned,
                parent_sha=parent_sha,
                candidate_sha=candidate_sha,
            )
            key = (scenario, pair, row_member)
            if key in rows:
                raise CandidateControlError(
                    f"duplicate evidence row for scenario={scenario}, pair={pair}, member={row_member}"
                )
            rows[key] = row
            identity = tuple(
                row[field]
                for field in (
                    "sha",
                    "tree",
                    "runner_sha256",
                    "client_sha256",
                    "server_sha256",
                )
            )
            if member in member_identity and member_identity[member] != identity:
                raise CandidateControlError(
                    f"{member} build identity changed between trials"
                )
            member_identity[member] = identity
            environment = tuple(
                row[field]
                for field in (
                    "rustc",
                    "kernel",
                    "cpu_model",
                    "cpu_count",
                    "memory_kib",
                    "build_profile",
                )
            )
            if environment_identity is not None and environment_identity != environment:
                raise CandidateControlError("runner environment changed between trials")
            environment_identity = environment
            evidence_files.append(
                {
                    "member": member,
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    expected = {
        (scenario, pair, member)
        for scenario in planned
        for pair in range(1, plan["pairs"] + 1)
        for member in ("parent", "candidate")
    }
    if set(rows) != expected:
        missing = sorted(expected - set(rows))
        unexpected = sorted(set(rows) - expected)
        raise CandidateControlError(
            f"evidence set is incomplete: missing={missing}, unexpected={unexpected}"
        )

    scenario_summaries = []
    for scenario, scenario_plan in planned.items():
        direction = scenario_plan["direction"]
        pair_summaries = []
        improvements = []
        for pair in range(1, plan["pairs"] + 1):
            parent = rows[(scenario, pair, "parent")]
            candidate = rows[(scenario, pair, "candidate")]
            if {parent["order"], candidate["order"]} != {1, 2}:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} must contain orders 1 and 2"
                )
            expected_parent_order = 1 if pair % 2 else 2
            if parent["order"] != expected_parent_order:
                raise CandidateControlError(
                    f"scenario={scenario}, pair={pair} does not alternate execution order"
                )
            parent_value = parent["value"]
            candidate_value = candidate["value"]
            improvement = _improvement(parent_value, candidate_value, direction)
            improvements.append(improvement)
            pair_summaries.append(
                {
                    "pair": pair,
                    "parent_order": parent["order"],
                    "candidate_order": candidate["order"],
                    "parent_value": parent_value,
                    "candidate_value": candidate_value,
                    "improvement_percent": _display_decimal(improvement),
                }
            )
        wins = sum(value > 0 for value in improvements)
        losses = sum(value < 0 for value in improvements)
        ties = len(improvements) - wins - losses
        median_improvement = _median(improvements)
        threshold_decision = _scenario_threshold_decision(
            plan=plan,
            scenario_plan=scenario_plan,
            wins=wins,
            losses=losses,
            median_improvement=median_improvement,
        )
        scenario_summaries.append(
            {
                "scenario": scenario,
                "role": scenario_plan["role"],
                "mandatory": scenario_plan["mandatory"],
                "metric": scenario_plan["metric"],
                "direction": direction,
                "pairs": pair_summaries,
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "median_improvement_percent": _display_decimal(median_improvement),
                "minimum_improvement_percent": _display_decimal(min(improvements)),
                "maximum_improvement_percent": _display_decimal(max(improvements)),
                "observed_direction": _observed_direction(wins=wins, losses=losses),
                "warnings": [],
                **threshold_decision,
            }
        )
    enabled_count = sum(result["decision_enabled"] for result in scenario_summaries)
    if enabled_count == 0:
        threshold_availability = "none"
    elif enabled_count == len(scenario_summaries):
        threshold_availability = "complete"
    else:
        threshold_availability = "partial"
    if plan["mode"] == "diagnostic":
        status = "MEASURED"
        decision_reason = "diagnostic mode reports measurements only"
    elif any(result["status"] == "REGRESSION" for result in scenario_summaries):
        status = "REGRESSION"
        decision_reason = "at least one calibrated mandatory scenario regressed"
    else:
        primary_summaries = [
            result for result in scenario_summaries if result["role"] == "primary"
        ]
        guard_summaries = [
            result for result in scenario_summaries if result["role"] == "guard"
        ]
        if (
            threshold_availability == "complete"
            and all(result["status"] == "CANDIDATE_WIN" for result in primary_summaries)
            and all(result["guard_passed"] is True for result in guard_summaries)
        ):
            status = "CANDIDATE_WIN"
            decision_reason = (
                "all calibrated primaries and guards satisfy the adoption policy"
            )
        else:
            status = "INCONCLUSIVE"
            decision_reason = (
                "calibrated thresholds are unavailable or adoption conditions are unmet"
            )
    primary_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "primary"
    ]
    guard_results = [
        {"scenario": result["scenario"], "status": result["status"]}
        for result in scenario_summaries
        if result["role"] == "guard"
    ]
    return {
        "schema_version": 2,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selected_scenario": plan["selected_scenario"],
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "decision_enabled": enabled_count > 0,
        "candidate_win_enabled": threshold_availability == "complete",
        "decision_reason": decision_reason,
        "threshold_availability": threshold_availability,
        "adoption_claim": status == "CANDIDATE_WIN",
        "status": status,
        "workflow_failure_reason": (
            decision_reason if status == "REGRESSION" else None
        ),
        "mandatory_scenarios": list(planned),
        "missing_scenarios": [],
        "primary_results": primary_results,
        "guard_results": guard_results,
        "scenarios": scenario_summaries,
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }


def invalid_summary(
    *,
    parent_sha: str,
    candidate_sha: str,
    error: CandidateControlError,
    plan: dict[str, object] | None = None,
    decision_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    mandatory = (
        [entry["scenario"] for entry in plan["scenarios"]] if plan is not None else []
    )
    return {
        "schema_version": 2,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"] if plan is not None else None,
        "selected_scenario": plan["selected_scenario"] if plan is not None else None,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "decision_policy": copy.deepcopy(
            plan["decision_policy"]
            if plan is not None
            else (UNCALIBRATED_POLICY if decision_policy is None else decision_policy)
        ),
        "decision_enabled": False,
        "candidate_win_enabled": False,
        "decision_reason": "invalid evidence",
        "threshold_availability": "none",
        "adoption_claim": False,
        "status": "INVALID_EVIDENCE",
        "workflow_failure_reason": str(error),
        "mandatory_scenarios": mandatory,
        "missing_scenarios": mandatory,
        "primary_results": [],
        "guard_results": [],
        "error": str(error),
        "scenarios": [],
        "evidence_files": [],
    }


def summary_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Performance candidate result",
        "",
        f"- Status: **{summary['status']}**",
        f"- Parent: `{summary['parent_sha']}`",
        f"- Candidate: `{summary['candidate_sha']}`",
        f"- Adoption claim: **{str(summary['adoption_claim']).lower()}**",
        "",
    ]
    if summary["status"] == "INVALID_EVIDENCE":
        lines.extend([f"Evidence error: `{summary['error']}`", ""])
        return "\n".join(lines)
    lines.extend(
        [
            f"- Mode: `{summary['mode']}`",
            f"- Policy: `{summary['decision_policy']['policy_id']}` "
            f"(`{summary['decision_policy']['policy_sha256'] or 'in-memory'}`)",
            f"- Threshold availability: `{summary['threshold_availability']}`",
            f"- Decision: {summary['decision_reason']}",
            "",
            "| Scenario | Role | Metric | Direction | Observed | Wins | Losses | Ties | Median % | Min % | Max % | Threshold decision | Status |",
            "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|---|",
        ]
    )
    for scenario in summary["scenarios"]:
        lines.append(
            f"| {scenario['scenario']} | {scenario['role']} | {scenario['metric']} | "
            f"{scenario['direction']} | {scenario['observed_direction']} | "
            f"{scenario['wins']} | {scenario['losses']} | "
            f"{scenario['ties']} | {scenario['median_improvement_percent']:.6f} | "
            f"{scenario['minimum_improvement_percent']:.6f} | "
            f"{scenario['maximum_improvement_percent']:.6f} | "
            f"{scenario['threshold_decision']} | {scenario['status']} |"
        )
    lines.extend(
        [
            "",
            "| Scenario | Pair | Parent order/value | Candidate order/value | Improvement % |",
            "|---|---:|---|---|---:|",
        ]
    )
    for scenario in summary["scenarios"]:
        for pair in scenario["pairs"]:
            lines.append(
                f"| {scenario['scenario']} | {pair['pair']} | "
                f"{pair['parent_order']} / {pair['parent_value']} | "
                f"{pair['candidate_order']} / {pair['candidate_value']} | "
                f"{pair['improvement_percent']:.6f} |"
            )
    lines.append("")
    return "\n".join(lines)


def _atomic_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            pathlib.Path(temporary_name).unlink(missing_ok=True)


def write_summary_outputs(
    summary: dict[str, object], *, output: pathlib.Path, markdown: pathlib.Path
) -> None:
    _atomic_text(
        output,
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(markdown, summary_markdown(summary))


def run_summary_command(parsed: argparse.Namespace) -> int:
    plan = None
    decision_policy = None
    try:
        decision_policy = load_decision_policy(parsed.policy)
        plan = load_plan(parsed.plan, decision_policy=decision_policy)
        summary = summarize_evidence(
            plan=plan,
            parent_root=parsed.parent_root,
            candidate_root=parsed.candidate_root,
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
        )
    except CandidateControlError as error:
        summary = invalid_summary(
            parent_sha=parsed.parent_sha,
            candidate_sha=parsed.candidate_sha,
            error=error,
            plan=plan,
            decision_policy=decision_policy,
        )
        write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2
    write_summary_outputs(summary, output=parsed.output, markdown=parsed.markdown)
    if summary["status"] in {"MEASURED", "INCONCLUSIVE", "CANDIDATE_WIN"}:
        return 0
    if summary["status"] == "REGRESSION":
        print(
            "performance-candidate: calibrated mandatory scenario regressed",
            file=sys.stderr,
        )
        return 3
    print("performance-candidate: unknown summary status", file=sys.stderr)
    return 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-inputs", help="validate bounded workflow measurement inputs"
    )
    validate.add_argument("--warmup-seconds", required=True)
    validate.add_argument("--active-seconds", required=True)
    validate.add_argument("--pairs", required=True)
    relation = commands.add_parser(
        "validate-git", help="validate strict parent-to-candidate ancestry"
    )
    relation.add_argument("--repository", required=True, type=pathlib.Path)
    relation.add_argument("--parent-sha", required=True)
    relation.add_argument("--candidate-sha", required=True)
    plan = commands.add_parser("plan", help="write a canonical scenario plan")
    plan.add_argument("--mode", required=True)
    plan.add_argument("--scenario", required=True)
    plan.add_argument("--warmup-seconds", required=True)
    plan.add_argument("--active-seconds", required=True)
    plan.add_argument("--pairs", required=True)
    plan.add_argument("--policy", required=True, type=pathlib.Path)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    scenarios = commands.add_parser(
        "scenarios", help="emit planned scenario names, one per line"
    )
    scenarios.add_argument("--plan", required=True, type=pathlib.Path)
    scenarios.add_argument("--policy", required=True, type=pathlib.Path)
    summary = commands.add_parser(
        "summarize", help="validate paired evidence and write machine/human summaries"
    )
    summary.add_argument("--plan", required=True, type=pathlib.Path)
    summary.add_argument("--parent-root", required=True, type=pathlib.Path)
    summary.add_argument("--candidate-root", required=True, type=pathlib.Path)
    summary.add_argument("--parent-sha", required=True)
    summary.add_argument("--candidate-sha", required=True)
    summary.add_argument("--policy", required=True, type=pathlib.Path)
    summary.add_argument("--output", required=True, type=pathlib.Path)
    summary.add_argument("--markdown", required=True, type=pathlib.Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    if parsed.command == "summarize":
        return run_summary_command(parsed)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        if parsed.command == "plan":
            decision_policy = load_decision_policy(parsed.policy)
            plan = create_plan(
                mode=parsed.mode,
                scenario=parsed.scenario,
                warmup_seconds=parsed.warmup_seconds,
                active_seconds=parsed.active_seconds,
                pairs=parsed.pairs,
                decision_policy=decision_policy,
            )
            write_plan(parsed.output, plan)
            return 0
        if parsed.command == "scenarios":
            decision_policy = load_decision_policy(parsed.policy)
            plan = load_plan(parsed.plan, decision_policy=decision_policy)
            for scenario in plan["scenarios"]:
                print(scenario["scenario"])
            return 0
        if parsed.command == "validate-git":
            validate_git_relation(
                parsed.repository, parsed.parent_sha, parsed.candidate_sha
            )
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
