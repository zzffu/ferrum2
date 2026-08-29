"""Closed policy and source identity for the Phase 7 headroom campaign."""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.linux import evidence_contract as linux_evidence

POLICY_SCHEMA_VERSION = "ferrum2-performance-udp-headroom-policy-v1"
PLAN_SCHEMA_VERSION = "ferrum2-performance-udp-headroom-plan-v1"
BUILD_SCHEMA_VERSION = "ferrum2-performance-udp-headroom-build-v1"
QUALIFICATION_SCHEMA_VERSION = "ferrum2-performance-udp-headroom-qualification-v1"
RUNNER_IMAGE = "ubuntu-24.04"
ARTIFACT_NAMES = ("ferrum2-client", "ferrum2-server", "m4-qualification")
VARIANT_NAMES = (
    "default",
    "candidate",
    "diagnostic-default",
    "diagnostic-candidate",
)
TIMED_VARIANTS = ("default", "candidate")
SCENARIO_NAMES = (
    "udp-small-high",
    "udp-mtu-1200",
    "udp-payload-8192",
    "udp-max-wire-65507",
    "udp-response-concurrency-32",
)
AUTHORITY = {
    "adoption_claim": False,
    "default_enabled": False,
    "gate03_stable_host_satisfied": False,
    "gate07_durable_evidence_satisfied": False,
    "performance_authoritative": False,
    "scope": "github-hosted-amd-provisional",
}
EXPECTED_SCENARIOS = [
    {
        "active_seconds": 15,
        "application_payload_bytes": 128,
        "metric": "datagrams_per_second",
        "name": "udp-small-high",
        "socks_datagram_bytes": 138,
        "upstream_wire_bytes": 186,
        "warmup_seconds": 1,
        "workload_scale": None,
    },
    {
        "active_seconds": 15,
        "application_payload_bytes": 1_200,
        "metric": "datagrams_per_second",
        "name": "udp-mtu-1200",
        "socks_datagram_bytes": 1_210,
        "upstream_wire_bytes": 1_258,
        "warmup_seconds": 1,
        "workload_scale": None,
    },
    {
        "active_seconds": 15,
        "application_payload_bytes": 8_192,
        "metric": "datagrams_per_second",
        "name": "udp-payload-8192",
        "socks_datagram_bytes": 8_202,
        "upstream_wire_bytes": 8_250,
        "warmup_seconds": 1,
        "workload_scale": None,
    },
    {
        "active_seconds": 15,
        "application_payload_bytes": 65_449,
        "metric": "datagrams_per_second",
        "name": "udp-max-wire-65507",
        "socks_datagram_bytes": 65_459,
        "upstream_wire_bytes": 65_507,
        "warmup_seconds": 1,
        "workload_scale": None,
    },
    {
        "active_seconds": 15,
        "application_payload_bytes": 128,
        "metric": "datagrams_per_second",
        "name": "udp-response-concurrency-32",
        "socks_datagram_bytes": 138,
        "upstream_wire_bytes": 186,
        "warmup_seconds": 1,
        "workload_scale": 32,
    },
]
EXPECTED_DIAGNOSTIC = {
    "candidate_assertions": {
        "client": {
            "udp_owned_fast_path_hits": "positive",
            "udp_payload_to_wire_copy_bytes": 0,
        },
        "server": {
            "udp_owned_fast_path_hits": "positive",
            "udp_payload_to_wire_copy_bytes": 0,
        },
    },
    "counter_count": 49,
    "default_assertions": {
        "client": {"udp_payload_to_wire_copy_bytes": "positive"},
        "server": {"udp_payload_to_wire_copy_bytes": "positive"},
    },
    "scenario": "udp-small-high",
    "session_topology": "multi-session",
}
SCHEDULE = {"a_a_rounds": 2, "pair_count": 6, "pair_schedule": "abba-six-pairs"}


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise CandidateControlError(
            "UDP headroom value is outside canonical JSON"
        ) from error


def source_bundle_sha256(root: pathlib.Path, paths: tuple[str, ...]) -> str:
    if len(paths) != len(set(paths)) or tuple(sorted(paths)) != paths:
        raise CandidateControlError("UDP headroom source bundle paths are not closed")
    entries: list[dict[str, object]] = []
    for relative in paths:
        path = root / relative
        try:
            metadata = path.lstat()
            raw = path.read_bytes()
        except OSError as error:
            raise CandidateControlError(
                f"UDP headroom source bundle is missing {relative}"
            ) from error
        if path.is_symlink() or not path.is_file() or metadata.st_size != len(raw):
            raise CandidateControlError(
                "UDP headroom source bundle contains an invalid file"
            )
        entries.append(
            {
                "bytes": len(raw),
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


CONTROLLER_SOURCE_PATHS = tuple(
    sorted(
        (
            ".github/workflows/performance-udp-headroom.yml",
            "tools/performance_udp_headroom/__init__.py",
            "tools/performance_udp_headroom/__main__.py",
            "tools/performance_udp_headroom/build.py",
            "tools/performance_udp_headroom/cli.py",
            "tools/performance_udp_headroom/contract.py",
            "tools/performance_udp_headroom/evidence.py",
            "tools/performance_udp_headroom/policy.json",
        )
    )
)


def controller_source_sha256() -> str:
    return source_bundle_sha256(repository_root(), CONTROLLER_SOURCE_PATHS)


def load_policy(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="UDP headroom policy",
    )
    policy = bounded.value
    if type(policy) is not dict:
        raise CandidateControlError("UDP headroom policy must be an object")
    _exact_fields(
        policy,
        frozenset(
            {
                "authority",
                "candidate_feature",
                "diagnostic",
                "policy_id",
                "scenarios",
                "schedule",
                "schema_version",
            }
        ),
        "UDP headroom policy",
    )
    expected = {
        "authority": AUTHORITY,
        "candidate_feature": "candidate-udp-owned-headroom",
        "diagnostic": EXPECTED_DIAGNOSTIC,
        "policy_id": "shadowsocks-udp-owned-headroom-phase7-v1",
        "scenarios": EXPECTED_SCENARIOS,
        "schedule": SCHEDULE,
        "schema_version": POLICY_SCHEMA_VERSION,
    }
    if policy != expected:
        raise CandidateControlError("UDP headroom policy contract changed")
    return policy, bounded.sha256


def timed_evidence_contract(scenario: dict[str, Any]) -> dict[str, object]:
    recipe = {
        "active_seconds": scenario["active_seconds"],
        "application_payload_bytes": scenario["application_payload_bytes"],
        "direction": "higher_is_better",
        "metric": scenario["metric"],
        "name": scenario["name"],
        "pair_schedule": SCHEDULE["pair_schedule"],
        "socks_datagram_bytes": scenario["socks_datagram_bytes"],
        "topology": "shadowsocks",
        "unit": "datagrams_per_second",
        "upstream_wire_bytes": scenario["upstream_wire_bytes"],
        "warmup_seconds": scenario["warmup_seconds"],
        "workload_scale": scenario["workload_scale"],
    }
    material = {
        "controller_source_sha256": controller_source_sha256(),
        "producer_source_sha256": linux_evidence.producer_source_sha256(),
        "runner_image": RUNNER_IMAGE,
        "schema_version": linux_evidence.EVIDENCE_CONTRACT_SCHEMA_VERSION,
        "semantic_recipe_sha256": hashlib.sha256(canonical_bytes(recipe)).hexdigest(),
        "trial_schema_version": linux_evidence.PROFILE_TRIAL_SCHEMA_VERSION,
    }
    return {
        **material,
        "cleanup_contract": {
            "active_processes": 0,
            "active_workers": 0,
            "ready_file_removed": True,
            "status": "PASS",
        },
        "evidence_bundle_sha256": hashlib.sha256(canonical_bytes(material)).hexdigest(),
        "unit": "datagrams_per_second",
    }


def planned_scenarios(policy: dict[str, Any]) -> list[dict[str, object]]:
    return [
        {
            **scenario,
            "direction": "higher_is_better",
            "evidence_contract": timed_evidence_contract(scenario),
            "topology": "shadowsocks",
        }
        for scenario in policy["scenarios"]
    ]


def diagnostic_evidence_contract() -> dict[str, str | int]:
    from tools.performance_udp_workers.contract import evidence_contract

    return evidence_contract(repository_root())
