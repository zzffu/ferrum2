"""Linux reviewed threshold policy and calibration applicability owner."""

from __future__ import annotations

import pathlib
import re

from tools.performance_candidate.json_contract import CandidateControlError, SHA256, _exact_fields, _policy_percent, read_bounded_closed_json
from tools.performance_candidate.linux.catalog import ACTIVE_SECONDS, PAIR_COUNTS, PAIR_SCHEDULE, SCENARIO_CATALOG, WARMUP_SECONDS

DECISION_POLICY_MAX_BYTES = 256 * 1024

MEASUREMENT_ENVIRONMENT = {
    "runner_image": "ubuntu-24.04",
    "runner_os": "Linux",
    "runner_arch": "X64",
    "rust_toolchain": "1.97.1",
    "cargo_profile": "profiling",
    "evidence_build_profile": "current",
    "pair_schedule": PAIR_SCHEDULE,
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
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
        "rustc",
        "kernel",
        "cpu_model",
        "cpu_count",
        "memory_kib",
        "build_profile",
    }
)


UNCALIBRATED_POLICY = {
    "schema_version": 2,
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


def _calibration_environment_matches(
    environment: dict[str, object],
    *,
    warmup_seconds: int,
    active_seconds: int,
    evidence_contract: dict[str, object],
    observed_environment: dict[str, object] | None = None,
) -> bool:
    expected = {
        **MEASUREMENT_ENVIRONMENT,
        "warmup_seconds": warmup_seconds,
        "active_seconds": active_seconds,
        **{
            field: evidence_contract[field]
            for field in (
                "producer_source_sha256",
                "controller_source_sha256",
                "semantic_recipe_sha256",
                "evidence_bundle_sha256",
            )
        },
    }
    if observed_environment is None:
        return all(environment.get(field) == value for field, value in expected.items())
    return environment == {**expected, **observed_environment}


def validate_decision_policy(policy: dict[str, object]) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(policy, POLICY_RUNTIME_FIELDS, "decision policy")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 2:
        raise CandidateControlError("decision policy schema_version must be 2")
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
        for field in (
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
        ):
            if type(environment[field]) is not str or SHA256.fullmatch(environment[field]) is None:
                raise CandidateControlError(
                    f"policy scenario {scenario} calibration_environment {field} is invalid"
                )
        for field in ("rustc", "kernel", "cpu_model", "build_profile"):
            if type(environment[field]) is not str or not environment[field]:
                raise CandidateControlError(
                    f"policy scenario {scenario} calibration_environment {field} is invalid"
                )
        for field in ("cpu_count", "memory_kib"):
            if type(environment[field]) is not int or environment[field] <= 0:
                raise CandidateControlError(
                    f"policy scenario {scenario} calibration_environment {field} is invalid"
                )


def load_decision_policy(path: pathlib.Path) -> dict[str, object]:
    loaded = read_bounded_closed_json(
        path, maximum_bytes=DECISION_POLICY_MAX_BYTES, source="decision policy"
    )
    document = loaded.value
    if type(document) is not dict:
        raise CandidateControlError("decision policy must be a JSON object")
    _exact_fields(document, POLICY_DOCUMENT_FIELDS, "decision policy document")
    policy = {
        **document,
        "policy_sha256": loaded.sha256,
    }
    validate_decision_policy(policy)
    return policy


def _scenario_policy_is_applicable(
    *,
    entry: dict[str, object],
    scenario_plan: dict[str, object],
    warmup_seconds: int,
    active_seconds: int,
    pairs: int,
    observed_environment: dict[str, object] | None = None,
) -> bool:
    environment = entry["calibration_environment"]
    return (
        environment is not None
        and pairs >= entry["minimum_pairs"]
        and _calibration_environment_matches(
            environment,
            warmup_seconds=warmup_seconds,
            active_seconds=active_seconds,
            evidence_contract=scenario_plan["evidence_contract"],
            observed_environment=observed_environment,
        )
    )
