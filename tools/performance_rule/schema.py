"""Current Rule performance schemas, bounds, identities, and exit statuses."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

RUNNER_SCHEMA = "ferrum2.rule-qualification.v3"
CONTROL_SCHEMA = "ferrum2.rule-qualification-control.v7"
CALIBRATION_SCHEMA = "ferrum2.rule-qualification-calibration.v3"
THRESHOLD_POLICY_VERSION = "section-5.7-and-rule-04-conditional-median-gates.v6"
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
SNAPSHOT_REGISTRY_SUITE = "snapshot_registry"
ATOMIC_SNAPSHOT_FEATURE = "candidate-atomic-snapshot"
SNAPSHOT_READER_THREADS = 4
SNAPSHOT_LIFECYCLE_PUBLISH_COUNT = SNAPSHOT_READER_THREADS
SNAPSHOT_RELEASE_DEADLINE_NS = 5_000_000_000
SMOKE_MATCH_SIZES = (64, 65, 100)
SMOKE_ROUTE_SIZES = (1, 32, 64)
SMOKE_DNS_RULE_SIZES = (1,)
QUALIFICATION_MATCH_SIZES = (8, 32, 64, 65, 100, 128, 1_000, 10_000)
QUALIFICATION_ROUTE_SIZES = (1, 8, 32, 64, 128, 1_000, 10_000)
QUALIFICATION_DNS_RULE_SIZES = (1, 64, 65, 100, 1_000, 10_000)
WORKFLOW_SAMPLES = 101
WORKFLOW_BASE_ITERATIONS = 1

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
    SNAPSHOT_REGISTRY_SUITE: {
        "scope_authority": "plan.rule_04",
        "median_classification": "candidate_conditional",
        "candidate_feature": ATOMIC_SNAPSHOT_FEATURE,
    },
}


class ControlError(RuntimeError):
    """Closed controller input or evidence failure."""


def expected_profile_sizes(
    profile: str, includes_100k: bool
) -> tuple[list[int], list[int], list[int]]:
    if type(includes_100k) is not bool:
        raise ControlError("runner 100k configuration is invalid")
    if profile == "smoke":
        match_sizes = list(SMOKE_MATCH_SIZES)
        route_sizes = list(SMOKE_ROUTE_SIZES)
        dns_rule_sizes = list(SMOKE_DNS_RULE_SIZES)
    elif profile == "qualification":
        match_sizes = list(QUALIFICATION_MATCH_SIZES)
        route_sizes = list(QUALIFICATION_ROUTE_SIZES)
        dns_rule_sizes = list(QUALIFICATION_DNS_RULE_SIZES)
    else:
        raise ControlError("runner profile is invalid")
    if includes_100k:
        match_sizes.append(100_000)
    return match_sizes, route_sizes, dns_rule_sizes


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
