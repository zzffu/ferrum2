"""Reviewed-input candidate generation for repeated Linux A/A summaries."""

from __future__ import annotations

import hashlib
import math
import pathlib
import statistics

from tools.performance_candidate.identity import COMMIT_SHA
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    SHA256,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux.evidence_contract import (
    EVIDENCE_CONTRACT_SCHEMA_VERSION,
    PROFILE_TRIAL_SCHEMA_VERSION,
    RUNNER_IMAGE,
)
from tools.performance_candidate.linux.environment import (
    MEMORY_CAPACITY_QUANTUM_KIB,
    calibration_environments_match,
    memory_capacity_class,
)
from tools.performance_candidate.linux.policy import validate_hosted_authority

CALIBRATION_CANDIDATE_SCHEMA_VERSION = 3
SUMMARY_MAX_BYTES = 4 * 1024 * 1024
BUILD_IDENTITY_FIELDS = frozenset(
    {"sha", "tree", "runner_sha256", "client_sha256", "server_sha256"}
)
EVIDENCE_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "trial_schema_version",
        "unit",
        "runner_image",
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
        "cleanup_contract",
    }
)
EVIDENCE_DIGEST_FIELDS = (
    "producer_source_sha256",
    "controller_source_sha256",
    "semantic_recipe_sha256",
    "evidence_bundle_sha256",
)
EXPECTED_CLEANUP_CONTRACT = {
    "active_processes": 0,
    "active_workers": 0,
    "ready_file_removed": True,
    "status": "PASS",
}


def _number(value: object, *, field: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise CandidateControlError(f"{field} must be one finite JSON number")
    return float(value)


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _valid_build_identity(identity: object, *, expected_sha: str) -> bool:
    return (
        type(identity) is dict
        and set(identity) == BUILD_IDENTITY_FIELDS
        and identity["sha"] == expected_sha
        and type(identity["sha"]) is str
        and COMMIT_SHA.fullmatch(identity["sha"]) is not None
        and type(identity["tree"]) is str
        and COMMIT_SHA.fullmatch(identity["tree"]) is not None
        and all(
            type(identity[field]) is str
            and SHA256.fullmatch(identity[field]) is not None
            for field in ("runner_sha256", "client_sha256", "server_sha256")
        )
    )


def _valid_evidence_contract(contract: object) -> bool:
    if type(contract) is not dict or set(contract) != EVIDENCE_CONTRACT_FIELDS:
        return False
    cleanup = contract["cleanup_contract"]
    return (
        contract["schema_version"] == EVIDENCE_CONTRACT_SCHEMA_VERSION
        and type(contract["schema_version"]) is int
        and contract["trial_schema_version"] == PROFILE_TRIAL_SCHEMA_VERSION
        and type(contract["trial_schema_version"]) is int
        and type(contract["unit"]) is str
        and bool(contract["unit"])
        and contract["runner_image"] == RUNNER_IMAGE
        and all(
            type(contract[field]) is str
            and SHA256.fullmatch(contract[field]) is not None
            for field in EVIDENCE_DIGEST_FIELDS
        )
        and type(cleanup) is dict
        and cleanup == EXPECTED_CLEANUP_CONTRACT
        and type(cleanup["active_processes"]) is int
        and type(cleanup["active_workers"]) is int
        and cleanup["ready_file_removed"] is True
    )


def create_calibration_candidate(
    summaries: list[pathlib.Path],
) -> dict[str, object]:
    """Aggregate at least two complete six-pair A/A summaries without adopting thresholds."""

    if not 2 <= len(summaries) <= 16:
        raise CandidateControlError(
            "Linux calibration requires 2 through 16 A/A summaries"
        )
    loaded: list[tuple[pathlib.Path, bytes, dict[str, object]]] = []
    source_digests: set[str] = set()
    for path in summaries:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise CandidateControlError("unable to read Linux A/A summary") from error
        if len(raw) > SUMMARY_MAX_BYTES:
            raise CandidateControlError("Linux A/A summary exceeds the size bound")
        value = read_bounded_closed_json(
            path,
            maximum_bytes=SUMMARY_MAX_BYTES,
            source="Linux A/A summary",
        ).value
        if type(value) is not dict:
            raise CandidateControlError("Linux A/A summary must be a JSON object")
        digest = hashlib.sha256(raw).hexdigest()
        if digest in source_digests:
            raise CandidateControlError(
                "Linux calibration requires distinct A/A summary rounds"
            )
        source_digests.add(digest)
        loaded.append((path, raw, value))

    first = loaded[0][2]
    try:
        expected_identity = (
            first["parent_sha"],
            first["candidate_sha"],
            first["pairs"],
            first["selection"],
        )
        expected_environment = first["environment_identity"]
        if type(expected_environment) is not dict:
            raise CandidateControlError("Linux A/A summary environment is invalid")
        expected_build_identities = first["build_identities"]
        if (
            type(expected_build_identities) is not dict
            or set(expected_build_identities) != {"parent", "candidate"}
            or any(
                not _valid_build_identity(identity, expected_sha=first["parent_sha"])
                for identity in expected_build_identities.values()
            )
            or expected_build_identities["parent"]
            != expected_build_identities["candidate"]
        ):
            raise CandidateControlError(
                "Linux A/A summary build identities are invalid"
            )
        expected_decision_policy = first["decision_policy"]
        if type(expected_decision_policy) is not dict or not expected_decision_policy:
            raise CandidateControlError("Linux A/A summary decision policy is invalid")
        expected_authority = first["authority"]
        validate_hosted_authority(expected_authority, label="Linux A/A summary")
        if first["parent_sha"] != first["candidate_sha"]:
            raise CandidateControlError("Linux A/A summary commits must be identical")
        if first["pairs"] != 6:
            raise CandidateControlError("Linux A/A calibration requires six pairs")
        expected_scenarios = [entry["scenario"] for entry in first["scenarios"]]
        expected_evidence_contracts = [
            (entry["scenario"], entry["evidence_contract"])
            for entry in first["scenarios"]
        ]
        if any(
            not _valid_evidence_contract(contract)
            for _scenario, contract in expected_evidence_contracts
        ):
            raise CandidateControlError(
                "Linux A/A summary evidence contracts are invalid"
            )
    except (KeyError, TypeError) as error:
        raise CandidateControlError("Linux A/A summary shape is invalid") from error

    aggregate = {scenario: [] for scenario in expected_scenarios}
    sources = []
    environments = []
    for path, raw, summary in loaded:
        try:
            if summary["kind"] != "performance_candidate_summary":
                raise CandidateControlError("Linux A/A summary kind is invalid")
            if summary["run_kind"] != "calibration-aa":
                raise CandidateControlError(
                    "Linux calibration accepts only calibration-aa summaries"
                )
            if (
                summary["status"] != "CALIBRATION_REQUIRED"
                or summary["adoption_claim"] is not False
                or summary["production_feature_enabled_by_default"] is not False
                or summary["workflow_failure_reason"] is not None
            ):
                raise CandidateControlError(
                    "Linux A/A summary must be complete review-only evidence"
                )
            identity = (
                summary["parent_sha"],
                summary["candidate_sha"],
                summary["pairs"],
                summary["selection"],
            )
            environment = summary["environment_identity"]
            if (
                identity != expected_identity
                or type(environment) is not dict
                or not calibration_environments_match(expected_environment, environment)
            ):
                raise CandidateControlError(
                    "Linux A/A summaries must share commit, environment, recipe, and selection"
                )
            build_identities = summary["build_identities"]
            if (
                type(build_identities) is not dict
                or set(build_identities) != {"parent", "candidate"}
                or any(
                    not _valid_build_identity(
                        build_identity, expected_sha=summary["parent_sha"]
                    )
                    for build_identity in build_identities.values()
                )
                or build_identities["parent"] != build_identities["candidate"]
                or build_identities != expected_build_identities
            ):
                raise CandidateControlError(
                    "Linux A/A summaries must share full build identities"
                )
            decision_policy = summary["decision_policy"]
            if (
                type(decision_policy) is not dict
                or decision_policy != expected_decision_policy
            ):
                raise CandidateControlError(
                    "Linux A/A summaries must share the full decision policy"
                )
            validate_hosted_authority(summary["authority"], label="Linux A/A summary")
            if summary["authority"] != expected_authority:
                raise CandidateControlError(
                    "Linux A/A summaries must share hosted authority"
                )
            scenarios = summary["scenarios"]
            if [entry["scenario"] for entry in scenarios] != expected_scenarios:
                raise CandidateControlError("Linux A/A scenario order or set changed")
            evidence_contracts = [
                (entry["scenario"], entry["evidence_contract"]) for entry in scenarios
            ]
            if (
                any(
                    not _valid_evidence_contract(contract)
                    for _scenario, contract in evidence_contracts
                )
                or evidence_contracts != expected_evidence_contracts
            ):
                raise CandidateControlError(
                    "Linux A/A summaries must share scenario evidence contracts"
                )
            for scenario in scenarios:
                pairs = scenario["pairs"]
                if len(pairs) != 6:
                    raise CandidateControlError(
                        "Linux A/A scenario is missing a six-pair round"
                    )
                aggregate[scenario["scenario"]].extend(
                    _number(
                        pair["improvement_percent"],
                        field="A/A pair improvement_percent",
                    )
                    for pair in pairs
                )
        except (KeyError, TypeError) as error:
            raise CandidateControlError("Linux A/A summary shape is invalid") from error
        environments.append(environment)
        sources.append(
            {
                "file": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    scenario_candidates = {}
    for scenario, samples in aggregate.items():
        median = statistics.median(samples)
        deviations = [abs(value - median) for value in samples]
        scenario_candidates[scenario] = {
            "samples": len(samples),
            "rounds": len(loaded),
            "median_directional_bias_percent": median,
            "median_absolute_deviation_percent": statistics.median(deviations),
            "p95_absolute_delta_percent": _nearest_rank(
                [abs(value) for value in samples], 0.95
            ),
            "minimum_delta_percent": min(samples),
            "maximum_delta_percent": max(samples),
            "review_required": True,
        }

    memory_observations = sorted(
        environment["memory_kib"] for environment in environments
    )
    memory_capacity = memory_capacity_class(memory_observations[0])
    if memory_capacity is None:
        raise CandidateControlError("Linux A/A summary environment is invalid")
    representative_environment = dict(expected_environment)
    representative_environment["memory_kib"] = memory_capacity

    return {
        "schema_version": CALIBRATION_CANDIDATE_SCHEMA_VERSION,
        "kind": "linux_performance_calibration_candidate",
        "authority": dict(expected_authority),
        "source_commit": first["parent_sha"],
        "environment_identity": representative_environment,
        "memory_capacity_quantum_kib": MEMORY_CAPACITY_QUANTUM_KIB,
        "memory_observations_kib": memory_observations,
        "selection": first["selection"],
        "pairs_per_round": 6,
        "rounds": len(loaded),
        "sources": sources,
        "scenarios": scenario_candidates,
        "thresholds_adopted": False,
        "production_feature_enabled_by_default": False,
    }
