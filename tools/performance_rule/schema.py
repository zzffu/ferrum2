"""Current Rule performance schemas, bounds, identities, and exit statuses."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


RUNNER_SCHEMA = "ferrum2.rule-qualification.v2"
CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v6"
CALIBRATION_SCHEMA = "ferrum2.rule-qualification-calibration.v2"
THRESHOLD_POLICY_VERSION = "section-5.7-match-set-median-gates.v5"
PAIR_COUNT = 6
LOCAL_TARGET_PERCENT = 5.0
NOISY_GATE_CEILING_PERCENT = 10.0
P99_TARGET_PERCENT = 15.0
P99_CLASSIFICATION = "observed_cross_process"
P99_GATE_OWNER = "final_candidate_in_process_paired_parity"
RUNNER_PRIORITY_NORMAL = "normal"
RUNNER_PRIORITY_HIGH = "high"
MATCH_SET_SUITE = "match_set"
ROUTE_PROGRAM_SUITE = "route_program"
DNS_POLICY_SUITE = "dns_policy"

CALIBRATION_REQUIRED = "CALIBRATION_REQUIRED"
CANDIDATE_WIN = "CANDIDATE_WIN"
WITHIN_CALIBRATED_BAND = "WITHIN_CALIBRATED_BAND"
REGRESSION = "REGRESSION"
INCONCLUSIVE = "INCONCLUSIVE"
INVALID = "INVALID"

SUITE_POLICY = {
    MATCH_SET_SUITE: {
        "scope_authority": "plan.section_5_7",
        "median_classification": "hard_gate",
    },
    ROUTE_PROGRAM_SUITE: {
        "scope_authority": "plan.section_17_2",
        "median_classification": "observed_cross_process",
    },
    DNS_POLICY_SUITE: {
        "scope_authority": "plan.section_17_3",
        "median_classification": "observed_cross_process",
    },
}


class ControlError(RuntimeError):
    """Closed controller input or evidence failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_pairs(pairs: int) -> None:
    if type(pairs) is not int or pairs != PAIR_COUNT:
        raise ControlError(f"--pairs must be exactly {PAIR_COUNT}")


def runner_creation_flags(priority: str) -> int:
    if priority == RUNNER_PRIORITY_NORMAL:
        return 0
    if priority != RUNNER_PRIORITY_HIGH:
        raise ControlError("runner process priority is invalid")
    if sys.platform != "win32":
        raise ControlError("--runner-priority high is supported only on Windows")
    high_priority = getattr(subprocess, "HIGH_PRIORITY_CLASS", None)
    if type(high_priority) is not int or high_priority <= 0:
        raise ControlError("Windows high-priority process creation is unavailable")
    return high_priority
