"""Semantic identity for Linux trial producers, controllers, and recipes."""

from __future__ import annotations

import hashlib
import json
import pathlib
from functools import lru_cache

from tools.performance_candidate.json_contract import CandidateControlError


EVIDENCE_CONTRACT_SCHEMA_VERSION = 3
PROFILE_TRIAL_SCHEMA_VERSION = 6
RUNNER_IMAGE = "ubuntu-24.04"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


# BEGIN M18 STRUCTURAL DIAGNOSTIC (excluded from timed v6 source identity)
_DIAGNOSTIC_BEGIN = b"BEGIN M18 " + b"STRUCTURAL DIAGNOSTIC"
_DIAGNOSTIC_END = b"END M18 " + b"STRUCTURAL DIAGNOSTIC"
_DIAGNOSTIC_BOUNDARIES = {
    "tools/ferrum2-m4-qualification/Cargo.toml": 2,
    "tools/ferrum2-m4-qualification/src/m4_support/mod.rs": 2,
    "tools/ferrum2-m4-qualification/src/m4_support/self_check.rs": 1,
    "tools/performance_candidate/cli.py": 3,
    "tools/performance_candidate/linux/evidence_contract.py": 4,
}
_TIMED_V6_EXCLUDED_CONTROLLER_FILES = frozenset(
    {
        "build_experiment.py",
        "build_qualification.py",
        "conditional_decision.py",
        "evidence_matrix.py",
        "structural_diagnostic.py",
    }
)


def _timed_v6_source_bytes(relative: str, raw: bytes) -> bytes:
    """Project independent diagnostic additions out of the timed-v6 identity."""

    expected = _DIAGNOSTIC_BOUNDARIES.get(relative, 0)
    if raw.count(_DIAGNOSTIC_BEGIN) != expected or raw.count(_DIAGNOSTIC_END) != expected:
        raise CandidateControlError(
            f"diagnostic source boundary count is invalid: {relative}"
        )
    while True:
        marker = raw.find(_DIAGNOSTIC_BEGIN)
        if marker < 0:
            break
        line_start = raw.rfind(b"\n", 0, marker) + 1
        end = raw.find(_DIAGNOSTIC_END, marker + len(_DIAGNOSTIC_BEGIN))
        if end < 0:
            raise CandidateControlError(
                f"unterminated diagnostic source boundary: {relative}"
            )
        line_end = raw.find(b"\n", end + len(_DIAGNOSTIC_END))
        if line_end < 0:
            line_end = len(raw) - 1
        raw = raw[:line_start] + raw[line_end + 1 :]
    if _DIAGNOSTIC_END in raw:
        raise CandidateControlError(f"orphan diagnostic source boundary: {relative}")
    return raw


# END M18 STRUCTURAL DIAGNOSTIC
def _source_bundle(root: pathlib.Path, paths: tuple[pathlib.Path, ...]) -> str:
    entries: list[dict[str, object]] = []
    for path in paths:
        try:
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            raw = path.read_bytes()
            # BEGIN M18 STRUCTURAL DIAGNOSTIC (excluded from timed v6 source identity)
            raw = _timed_v6_source_bytes(relative, raw)
            # END M18 STRUCTURAL DIAGNOSTIC
        except (OSError, ValueError) as error:
            raise CandidateControlError("unable to identify performance source bundle") from error
        if path.is_symlink() or not metadata.st_mode:
            raise CandidateControlError("performance source bundle contains an invalid file")
        entries.append(
            {
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return hashlib.sha256(_canonical_bytes(entries)).hexdigest()


def _repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[3]


@lru_cache(maxsize=1)
def controller_source_sha256() -> str:
    root = _repository_root()
    package = root / "tools" / "performance_candidate"
    paths = tuple(sorted(package.rglob("*.py")))
    # BEGIN M18 STRUCTURAL DIAGNOSTIC (excluded from timed v6 source identity)
    paths = tuple(
        path for path in paths if path.name not in _TIMED_V6_EXCLUDED_CONTROLLER_FILES
    )
    # END M18 STRUCTURAL DIAGNOSTIC
    if not paths:
        raise CandidateControlError("performance controller source bundle is empty")
    return _source_bundle(root, paths)


@lru_cache(maxsize=1)
def producer_source_sha256() -> str:
    root = _repository_root()
    package = root / "tools" / "ferrum2-m4-qualification"
    paths = (package / "Cargo.toml", *sorted((package / "src").rglob("*.rs")))
    # BEGIN M18 STRUCTURAL DIAGNOSTIC (excluded from timed v6 source identity)
    paths = tuple(path for path in paths if not path.name.startswith("structural_"))
    # END M18 STRUCTURAL DIAGNOSTIC
    return _source_bundle(root, tuple(paths))


def metric_unit(metric: str) -> str:
    try:
        return {
            "bytes_per_second": "bytes_per_second",
            "datagrams_per_second": "datagrams_per_second",
            "operations_per_second": "operations_per_second",
            "queries_per_second": "queries_per_second",
            "p99_nanoseconds": "nanoseconds",
        }[metric]
    except KeyError as error:
        raise CandidateControlError(f"unsupported performance metric unit: {metric}") from error


def scenario_evidence_contract(
    scenario: dict[str, object], *, warmup_seconds: int, active_seconds: int, pair_schedule: str
) -> dict[str, object]:
    recipe = {
        "scenario": scenario["scenario"],
        "metric": scenario["metric"],
        "unit": metric_unit(str(scenario["metric"])),
        "direction": scenario["direction"],
        "topology": scenario["topology"],
        "application_payload_bytes": scenario["application_payload_bytes"],
        "workload_scale": scenario["workload_scale"],
        "socks_datagram_bytes": scenario["socks_datagram_bytes"],
        "upstream_wire_bytes": scenario["upstream_wire_bytes"],
        "warmup_seconds": warmup_seconds,
        "active_seconds": active_seconds,
        "pair_schedule": pair_schedule,
    }
    semantic_recipe_sha256 = hashlib.sha256(_canonical_bytes(recipe)).hexdigest()
    producer = producer_source_sha256()
    controller = controller_source_sha256()
    bundle = {
        "schema_version": EVIDENCE_CONTRACT_SCHEMA_VERSION,
        "trial_schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
        "runner_image": RUNNER_IMAGE,
        "producer_source_sha256": producer,
        "controller_source_sha256": controller,
        "semantic_recipe_sha256": semantic_recipe_sha256,
    }
    return {
        **bundle,
        "evidence_bundle_sha256": hashlib.sha256(_canonical_bytes(bundle)).hexdigest(),
        "unit": recipe["unit"],
        "cleanup_contract": {
            "active_processes": 0,
            "active_workers": 0,
            "ready_file_removed": True,
            "status": "PASS",
        },
    }


def catalog_evidence_contract(
    scenario: str, *, warmup_seconds: int, active_seconds: int, pair_schedule: str
) -> dict[str, object]:
    from tools.performance_candidate.linux.catalog import (
        SCENARIO_CATALOG,
        SCENARIO_EVIDENCE,
        SCENARIO_WORKLOAD_SCALE,
    )

    try:
        metric, direction, _family = SCENARIO_CATALOG[scenario]
        topology, payload, socks_bytes, upstream_bytes = SCENARIO_EVIDENCE[scenario]
    except KeyError as error:
        raise CandidateControlError(f"unknown performance scenario: {scenario}") from error
    return scenario_evidence_contract(
        {
            "scenario": scenario,
            "metric": metric,
            "direction": direction,
            "topology": topology,
            "application_payload_bytes": payload,
            "workload_scale": SCENARIO_WORKLOAD_SCALE.get(scenario),
            "socks_datagram_bytes": socks_bytes,
            "upstream_wire_bytes": upstream_bytes,
        },
        warmup_seconds=warmup_seconds,
        active_seconds=active_seconds,
        pair_schedule=pair_schedule,
    )


def scale_evidence_contract() -> dict[str, object]:
    from tools.performance_candidate.linux.scale import SCALE_RECIPE, SCALE_SCENARIO

    return scenario_evidence_contract(
        {
            "scenario": SCALE_SCENARIO,
            "metric": "bytes_per_second",
            "direction": "higher_is_better",
            "topology": "shadowsocks",
            "application_payload_bytes": SCALE_RECIPE["payload_bytes"],
            "workload_scale": None,
            "socks_datagram_bytes": None,
            "upstream_wire_bytes": None,
        },
        warmup_seconds=10,
        active_seconds=30,
        pair_schedule="abba-six-pairs",
    )
