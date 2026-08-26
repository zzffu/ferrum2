"""windows tun policy owner."""

from __future__ import annotations

import pathlib
import re
from decimal import Decimal

from tools.performance_candidate.windows_tun.recipe import recipe_sha256, scenario_catalog
from tools.performance_candidate.json_contract import CandidateControlError, SHA256, _exact_fields, _policy_percent, read_bounded_closed_json
from tools.performance_candidate.windows_tun.recipe import WINDOWS_TUN_GUEST, WINDOWS_TUN_PAIR_COUNT, WINDOWS_TUN_SELECTION, WINDOWS_TUN_TOPOLOGY_ENVIRONMENT_FIELDS, _validate_windows_tun_topology_environment

WINDOWS_TUN_POLICY_SCHEMA_VERSION = 4
WINDOWS_TUN_POLICY_MAX_BYTES = 1024 * 1024


WINDOWS_TUN_POLICY_DOCUMENT_FIELDS = frozenset(
    {"schema_version", "policy_id", "selection", "scenarios"}
)


WINDOWS_TUN_POLICY_RUNTIME_FIELDS = frozenset(
    {*WINDOWS_TUN_POLICY_DOCUMENT_FIELDS, "policy_sha256"}
)


WINDOWS_TUN_POLICY_SCENARIO_FIELDS = frozenset({"metrics"})


WINDOWS_TUN_POLICY_METRIC_FIELDS = frozenset(
    {
        "unit",
        "direction",
        "noise_band_percent",
        "regression_threshold_percent",
        "adoption_threshold_percent",
        "minimum_pairs",
        "minimum_wins",
        "minimum_losses",
        "calibration_source",
        "calibration_artifact_sha256",
        "calibration_environment",
    }
)


WINDOWS_TUN_CALIBRATION_ENVIRONMENT_FIELDS = frozenset(
    {
        *WINDOWS_TUN_GUEST,
        *WINDOWS_TUN_TOPOLOGY_ENVIRONMENT_FIELDS,
        "recipe_sha256",
        "controller_bundle_sha256",
        "guest_build",
        "cpu_model",
        "cpu_count",
        "memory_bytes",
        "power_plan_guid",
    }
)


def _windows_tun_calibration_fields(entry: dict[str, object]) -> tuple[object, ...]:
    return tuple(
        entry[field]
        for field in (
            "noise_band_percent",
            "regression_threshold_percent",
            "adoption_threshold_percent",
            "minimum_pairs",
            "minimum_wins",
            "minimum_losses",
            "calibration_source",
            "calibration_artifact_sha256",
            "calibration_environment",
        )
    )


def validate_windows_tun_policy(
    policy: dict[str, object], *, controller_bundle_sha256: str
) -> None:
    if type(policy) is not dict:
        raise CandidateControlError("Windows TUN policy must be a JSON object")
    _exact_fields(policy, WINDOWS_TUN_POLICY_RUNTIME_FIELDS, "Windows TUN policy")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != WINDOWS_TUN_POLICY_SCHEMA_VERSION
    ):
        raise CandidateControlError("Windows TUN policy schema_version is unsupported")
    if type(policy["policy_id"]) is not str or not policy["policy_id"].strip():
        raise CandidateControlError("Windows TUN policy_id must be non-empty")
    if policy["selection"] != WINDOWS_TUN_SELECTION:
        raise CandidateControlError("Windows TUN policy selection is invalid")
    digest = policy["policy_sha256"]
    if digest is not None and (
        type(digest) is not str or SHA256.fullmatch(digest) is None
    ):
        raise CandidateControlError("Windows TUN policy SHA-256 is invalid")
    scenarios = policy["scenarios"]
    if type(scenarios) is not dict or set(scenarios) != set(scenario_catalog()):
        raise CandidateControlError(
            "Windows TUN policy scenarios must exactly match the nine-scenario catalog"
        )
    calibration_states: list[bool] = []
    calibration_identities: list[tuple[object, object, object]] = []
    if (
        type(controller_bundle_sha256) is not str
        or SHA256.fullmatch(controller_bundle_sha256) is None
    ):
        raise CandidateControlError("Windows TUN controller bundle SHA-256 is invalid")
    expected_recipe_sha256 = recipe_sha256(controller_bundle_sha256)
    for scenario, contract in scenario_catalog().items():
        scenario_policy = scenarios[scenario]
        if type(scenario_policy) is not dict:
            raise CandidateControlError(
                f"Windows TUN policy scenario {scenario} must be an object"
            )
        _exact_fields(
            scenario_policy,
            WINDOWS_TUN_POLICY_SCENARIO_FIELDS,
            f"Windows TUN policy scenario {scenario}",
        )
        metrics = scenario_policy["metrics"]
        expected_metrics = contract["metrics"]
        if type(metrics) is not dict or set(metrics) != set(expected_metrics):
            raise CandidateControlError(
                f"Windows TUN policy scenario {scenario} metrics are incomplete"
            )
        for metric, metric_contract in expected_metrics.items():
            entry = metrics[metric]
            if type(entry) is not dict:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} must be an object"
                )
            _exact_fields(
                entry,
                WINDOWS_TUN_POLICY_METRIC_FIELDS,
                f"Windows TUN policy metric {scenario}/{metric}",
            )
            if (
                entry["unit"] != metric_contract["unit"]
                or entry["direction"] != metric_contract["direction"]
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} unit or direction mismatch"
                )
            calibrated = _windows_tun_calibration_fields(entry)
            if all(value is None for value in calibrated):
                calibration_states.append(False)
                continue
            if any(value is None for value in calibrated):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} calibration "
                    "must be complete or entirely null"
                )
            calibration_states.append(True)
            noise = _policy_percent(entry["noise_band_percent"], "noise_band_percent")
            regression = _policy_percent(
                entry["regression_threshold_percent"],
                "regression_threshold_percent",
            )
            adoption = _policy_percent(
                entry["adoption_threshold_percent"],
                "adoption_threshold_percent",
            )
            if noise < 0 or regression >= -noise or adoption <= noise:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} thresholds "
                    "must lie outside the noise band"
                )
            if metric_contract.get("allow_zero", False) and (
                regression < Decimal(-100) or adoption > Decimal(100)
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} zero-capable "
                    "thresholds must include the signed 100 percent sentinel"
                )
            if (
                type(entry["minimum_pairs"]) is not int
                or entry["minimum_pairs"] != WINDOWS_TUN_PAIR_COUNT
                or type(entry["minimum_wins"]) is not int
                or not 1 <= entry["minimum_wins"] <= WINDOWS_TUN_PAIR_COUNT
                or type(entry["minimum_losses"]) is not int
                or not 1 <= entry["minimum_losses"] <= WINDOWS_TUN_PAIR_COUNT
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} pair counts are invalid"
                )
            source = entry["calibration_source"]
            artifact_digest = entry["calibration_artifact_sha256"]
            if (
                type(source) is not str
                or re.fullmatch(r"artifact:\S+@sha256:[0-9a-f]{64}", source) is None
                or type(artifact_digest) is not str
                or SHA256.fullmatch(artifact_digest) is None
                or not source.endswith(f"@sha256:{artifact_digest}")
            ):
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} must bind one "
                    "SHA-256 identified calibration artifact"
                )
            environment = entry["calibration_environment"]
            if type(environment) is not dict:
                raise CandidateControlError(
                    f"Windows TUN policy metric {scenario}/{metric} calibration "
                    "environment is invalid"
                )
            _exact_fields(
                environment,
                WINDOWS_TUN_CALIBRATION_ENVIRONMENT_FIELDS,
                f"Windows TUN policy metric {scenario}/{metric} environment",
            )
            for field, expected in WINDOWS_TUN_GUEST.items():
                if environment[field] != expected:
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is unsupported"
                    )
            _validate_windows_tun_topology_environment(
                environment, label="Windows TUN calibration environment"
            )
            if environment["recipe_sha256"] != expected_recipe_sha256:
                raise CandidateControlError(
                    "Windows TUN calibration recipe does not match this controller"
                )
            if environment["controller_bundle_sha256"] != controller_bundle_sha256:
                raise CandidateControlError(
                    "Windows TUN calibration controller bundle does not match this run"
                )
            for field in ("guest_build", "cpu_model", "power_plan_guid"):
                if type(environment[field]) is not str or not environment[field].strip():
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is invalid"
                    )
            for field in ("cpu_count", "memory_bytes"):
                if type(environment[field]) is not int or environment[field] <= 0:
                    raise CandidateControlError(
                        f"Windows TUN calibration environment {field} is invalid"
                    )
            calibration_identities.append((source, artifact_digest, environment))
    if any(calibration_states) and not all(calibration_states):
        raise CandidateControlError(
            "Windows TUN policy cannot mix calibrated and uncalibrated metrics"
        )
    if calibration_identities and any(
        identity != calibration_identities[0] for identity in calibration_identities[1:]
    ):
        raise CandidateControlError(
            "Windows TUN policy metrics must share one calibration artifact and environment"
        )


def load_windows_tun_policy(
    path: pathlib.Path, *, controller_bundle_sha256: str
) -> dict[str, object]:
    loaded = read_bounded_closed_json(
        path,
        maximum_bytes=WINDOWS_TUN_POLICY_MAX_BYTES,
        source="Windows TUN policy",
    )
    document = loaded.value
    if type(document) is not dict:
        raise CandidateControlError("Windows TUN policy must be a JSON object")
    _exact_fields(
        document,
        WINDOWS_TUN_POLICY_DOCUMENT_FIELDS,
        "Windows TUN policy document",
    )
    policy = {
        **document,
        "policy_sha256": loaded.sha256,
    }
    validate_windows_tun_policy(
        policy, controller_bundle_sha256=controller_bundle_sha256
    )
    return policy


def windows_tun_policy_is_calibrated(
    policy: dict[str, object], *, controller_bundle_sha256: str
) -> bool:
    validate_windows_tun_policy(
        policy, controller_bundle_sha256=controller_bundle_sha256
    )
    first_scenario = next(iter(scenario_catalog()))
    first_metric = next(iter(scenario_catalog()[first_scenario]["metrics"]))
    entry = policy["scenarios"][first_scenario]["metrics"][first_metric]
    return entry["calibration_environment"] is not None
