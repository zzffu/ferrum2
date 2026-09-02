"""Run-scoped Linux A/A calibration owner."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
from decimal import ROUND_CEILING, Decimal

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.linux.decision import summarize_evidence
from tools.performance_candidate.linux.policy import (
    MEASUREMENT_ENVIRONMENT,
    validate_decision_policy,
)
from tools.performance_candidate.linux.scale import SCALE_SCENARIO
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.pairing import _display_decimal, _improvement, _median

CALIBRATION_SCHEMA_VERSION = 1
CALIBRATION_MINIMUM_PERCENT = Decimal("0.1")
CALIBRATION_DECISION_MULTIPLIER = Decimal("1.25")
CALIBRATION_MINIMUM_PAIRS = 6
CALIBRATION_MINIMUM_WINS = 5
CALIBRATION_MINIMUM_LOSSES = 4
CALIBRATION_SOURCE = re.compile(r"artifact:\S+")


def _ceil_tenth(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.1"), rounding=ROUND_CEILING)


def _calibration_values(scenario: dict[str, object]) -> dict[str, object]:
    direction = str(scenario["direction"])
    deltas = [
        _improvement(
            int(pair["parent_value"]),
            int(pair["candidate_value"]),
            direction,
        )
        for pair in scenario["pairs"]
    ]
    if len(deltas) != CALIBRATION_MINIMUM_PAIRS:
        raise CandidateControlError("A/A calibration requires exactly six pairs")
    median = _median(deltas)
    deviations = [abs(value - median) for value in deltas]
    mad = _median(deviations)
    maximum_absolute = max(abs(value) for value in deltas)
    robust_bound = abs(median) + Decimal(3) * mad
    noise = _ceil_tenth(
        max(CALIBRATION_MINIMUM_PERCENT, maximum_absolute, robust_bound)
    )
    decision = _ceil_tenth(noise * CALIBRATION_DECISION_MULTIPLIER)
    return {
        "scenario": scenario["scenario"],
        "direction": direction,
        "pair_improvement_percent": [_display_decimal(value) for value in deltas],
        "median_improvement_percent": _display_decimal(median),
        "median_absolute_deviation_percent": _display_decimal(mad),
        "maximum_absolute_pair_percent": _display_decimal(maximum_absolute),
        "robust_bound_percent": _display_decimal(robust_bound),
        "noise_band_percent": float(noise),
        "adoption_threshold_percent": float(decision),
        "regression_threshold_percent": float(-decision),
        "minimum_pairs": CALIBRATION_MINIMUM_PAIRS,
        "minimum_wins": CALIBRATION_MINIMUM_WINS,
        "minimum_losses": CALIBRATION_MINIMUM_LOSSES,
    }


def derive_run_calibration(
    *,
    plan: dict[str, object],
    left_root: pathlib.Path,
    right_root: pathlib.Path,
    baseline_sha: str,
    source: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate same-binary evidence and derive one host-local decision policy."""

    if plan["mode"] != "qualification" or plan["selection"] == SCALE_SCENARIO:
        raise CandidateControlError(
            "run-scoped calibration requires an ordinary qualification plan"
        )
    if CALIBRATION_SOURCE.fullmatch(source) is None or "@sha256:" in source:
        raise CandidateControlError(
            "calibration source must be an artifact reference without a digest"
        )
    calibration_fields = (
        "noise_band_percent",
        "regression_threshold_percent",
        "adoption_threshold_percent",
        "minimum_pairs",
        "minimum_wins",
        "minimum_losses",
        "calibration_source",
        "calibration_environment",
    )
    for policy_entry in plan["decision_policy"]["scenarios"].values():
        if any(policy_entry[field] is not None for field in calibration_fields):
            raise CandidateControlError(
                "A/A calibration base policy must be entirely uncalibrated"
            )

    summary = summarize_evidence(
        plan=plan,
        parent_root=left_root,
        candidate_root=right_root,
        parent_sha=baseline_sha,
        candidate_sha=baseline_sha,
        allow_same_commit=True,
    )
    identities = summary["build_identities"]
    if identities["parent"] != identities["candidate"]:
        raise CandidateControlError(
            "A/A calibration members must have identical build identities"
        )
    scenario_calibrations = [
        _calibration_values(scenario) for scenario in summary["scenarios"]
    ]
    report = {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "kind": "performance_candidate_run_calibration",
        "selection": plan["selection"],
        "scenario_group": plan["scenario_group"],
        "baseline_sha": baseline_sha.lower(),
        "pairs": plan["pairs"],
        "warmup_seconds": plan["warmup_seconds"],
        "active_seconds": plan["active_seconds"],
        "environment_identity": copy.deepcopy(summary["environment_identity"]),
        "build_identity": copy.deepcopy(identities["parent"]),
        "threshold_algorithm": {
            "id": "max-absolute-or-median-plus-3mad-v1",
            "minimum_percent": float(CALIBRATION_MINIMUM_PERCENT),
            "decision_multiplier": float(CALIBRATION_DECISION_MULTIPLIER),
            "rounding_percent": 0.1,
            "minimum_pairs": CALIBRATION_MINIMUM_PAIRS,
            "minimum_wins": CALIBRATION_MINIMUM_WINS,
            "minimum_losses": CALIBRATION_MINIMUM_LOSSES,
        },
        "scenarios": scenario_calibrations,
        "evidence_files": copy.deepcopy(summary["evidence_files"]),
    }
    report_text = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    report_sha256 = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    calibration_source = f"{source}@sha256:{report_sha256}"

    policy = {
        "schema_version": plan["decision_policy"]["schema_version"],
        "policy_id": f"run-scoped-aa-{report_sha256[:12]}",
        "scenarios": copy.deepcopy(plan["decision_policy"]["scenarios"]),
    }
    plan_scenarios = {
        entry["scenario"]: entry for entry in plan["scenarios"]
    }
    observed_environment = summary["environment_identity"]
    for calibrated in scenario_calibrations:
        scenario = str(calibrated["scenario"])
        contract = plan_scenarios[scenario]["evidence_contract"]
        environment = {
            **MEASUREMENT_ENVIRONMENT,
            "warmup_seconds": plan["warmup_seconds"],
            "active_seconds": plan["active_seconds"],
            **{
                field: contract[field]
                for field in (
                    "producer_source_sha256",
                    "controller_source_sha256",
                    "semantic_recipe_sha256",
                    "evidence_bundle_sha256",
                )
            },
            "rustc": observed_environment["rustc"],
            "kernel": observed_environment["kernel"],
            "cpu_model": observed_environment["cpu_model"],
            "cpu_count": observed_environment["cpu_count"],
            "memory_kib": observed_environment["memory_kib"],
            "build_profile": observed_environment["build_profile"],
        }
        policy["scenarios"][scenario].update(
            {
                "noise_band_percent": calibrated["noise_band_percent"],
                "regression_threshold_percent": calibrated[
                    "regression_threshold_percent"
                ],
                "adoption_threshold_percent": calibrated[
                    "adoption_threshold_percent"
                ],
                "minimum_pairs": calibrated["minimum_pairs"],
                "minimum_wins": calibrated["minimum_wins"],
                "minimum_losses": calibrated["minimum_losses"],
                "calibration_source": calibration_source,
                "calibration_environment": environment,
            }
        )
    runtime_policy = {**policy, "policy_sha256": None}
    validate_decision_policy(runtime_policy)
    return report, policy


def write_run_calibration(
    *,
    report: dict[str, object],
    policy: dict[str, object],
    report_output: pathlib.Path,
    policy_output: pathlib.Path,
) -> None:
    _atomic_text(
        report_output,
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    _atomic_text(
        policy_output,
        json.dumps(policy, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
