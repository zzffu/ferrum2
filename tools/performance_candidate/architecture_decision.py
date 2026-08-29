"""Closed non-adoption and prerequisite decisions for deferred performance ideas."""

from __future__ import annotations

import argparse
import json
import pathlib

from tools.performance_candidate import build_experiment
from tools.performance_candidate.json_contract import (
    CandidateControlError,
    _exact_fields,
    read_bounded_closed_json,
)
from tools.performance_candidate.output import _atomic_text

SCHEMA_VERSION = "ferrum2-performance-architecture-decisions-v1"
COMMANDS = frozenset({"architecture-decisions"})

DECISIONS = [
    {
        "decision": "SUPERSEDED_BY_FAIRNESS_INVARIANT",
        "evidence": {
            "authoritative": False,
            "observation": "continuous RX polling approximately 12 MiB/s; one-read scheduling boundary approximately 160 MiB/s",
            "provenance": "exact source bisection ending at 6a669a65238c310ae2b860c610e153a0b400658d",
            "raw_evidence_durable": False,
        },
        "forbidden_change": "restore continuous successful TCP RX polling within one outer poll",
        "invariant": "each outer poll performs at most one successful read transition and preserves the existing self-wake fairness boundary",
        "item_id": "TCP-06",
        "prerequisite": None,
        "rationale": "The measured continuous-poll variant is a severe throughput regression and no longer represents the intended optimization.",
    },
    {
        "decision": "DEFERRED",
        "evidence": None,
        "forbidden_change": None,
        "invariant": "single-hop fused relay remains the production specialization",
        "item_id": "SS-PHASE6-MULTI-HOP-OWNERSHIP",
        "prerequisite": {
            "kind": "multi-hop-copy-profile",
            "required_observation": "multi-hop ownership copies are a material top-profile bottleneck",
        },
        "rationale": "Multi-hop ownership changes require a workload-specific copy trigger and cannot be inferred from single-hop results.",
    },
    {
        "decision": "DEFERRED",
        "evidence": None,
        "forbidden_change": None,
        "invariant": "portable async plain TCP path remains unchanged",
        "item_id": "LINUX-PLAIN-SPLICE",
        "prerequisite": {
            "kind": "linux-plain-copy-profile",
            "required_observation": "plain TCP user-space copy cost is material after correctness and fairness gates",
        },
        "rationale": "splice is Linux-specific and needs a plain-path copy profile plus shutdown semantics evidence.",
    },
    {
        "decision": "DEFERRED",
        "evidence": None,
        "forbidden_change": None,
        "invariant": "platform socket defaults remain unchanged",
        "item_id": "LINUX-SOCKET-BUFFER-TUNING",
        "prerequisite": {
            "kind": "socket-buffer-pressure-profile",
            "required_observation": "socket queue pressure or drops dominate the target workload",
        },
        "rationale": "Global buffer tuning without queue-pressure evidence can increase memory and tail latency.",
    },
    {
        "decision": "DEFERRED",
        "evidence": None,
        "forbidden_change": None,
        "invariant": "current UDP wire and correctness contracts remain unchanged",
        "item_id": "LINUX-GRO-GSO",
        "prerequisite": {
            "kind": "udp-offload-profile",
            "required_observation": "packet-rate and syscall evidence shows safe GRO/GSO would address a material bottleneck",
        },
        "rationale": "Offload adoption requires kernel/NIC capability, segmentation correctness, and fallback evidence.",
    },
    {
        "decision": "NOT_ADOPTED",
        "evidence": None,
        "forbidden_change": "enable busy-poll by default or in general release artifacts",
        "invariant": "ordinary non-TUN operation remains scheduler-driven without busy spinning",
        "item_id": "LINUX-BUSY-POLL",
        "prerequisite": None,
        "rationale": "Power, CPU isolation, and fairness costs are incompatible with the general deployment contract.",
    },
    {
        "decision": "EXTERNAL_LAB_REQUIRED",
        "evidence": None,
        "forbidden_change": None,
        "invariant": "hosted correctness diagnostics do not claim ETW lock-wait or hold-time qualification",
        "item_id": "WIN-01-LOCK-ETW",
        "prerequisite": {
            "kind": "windows-external-lab-etw",
            "required_observation": "approved Windows lab records lock wait, hold duration, and ETW correlation on the physical non-TUN generation path",
        },
        "rationale": "Hosted runners cannot provide the privileged, stable Windows ETW lab boundary required by this evidence.",
    },
]


def create_architecture_decisions(
    *, source_sha: str, source_tree: str
) -> dict[str, object]:
    if (
        build_experiment.COMMIT_SHA.fullmatch(source_sha) is None
        or build_experiment.GIT_OBJECT.fullmatch(source_tree) is None
    ):
        raise CandidateControlError("architecture decision source identity is invalid")
    record = {
        "adoption_claim": False,
        "bare_metal_gate_satisfied": False,
        "decisions": DECISIONS,
        "durable_evidence_gate_satisfied": False,
        "generated_at_utc": build_experiment._utc_now(),
        "performance_authoritative": False,
        "schema_version": SCHEMA_VERSION,
        "scope": "repository-architecture-closure",
        "source_identity": {
            "comparison_axis": "architecture-decision",
            "source_sha": source_sha,
            "source_tree": source_tree,
        },
    }
    record["record_id"] = build_experiment._json_sha256(record)
    return record


def load_architecture_decisions(path: pathlib.Path) -> tuple[dict[str, object], str]:
    bounded = read_bounded_closed_json(
        path,
        maximum_bytes=build_experiment.MAX_JSON_BYTES,
        source="performance architecture decisions",
    )
    row = bounded.value
    if type(row) is not dict:
        raise CandidateControlError(
            "performance architecture decisions must be an object"
        )
    _exact_fields(
        row,
        frozenset(
            {
                "adoption_claim",
                "bare_metal_gate_satisfied",
                "decisions",
                "durable_evidence_gate_satisfied",
                "generated_at_utc",
                "performance_authoritative",
                "record_id",
                "schema_version",
                "scope",
                "source_identity",
            }
        ),
        "performance architecture decisions",
    )
    if (
        row["schema_version"] != SCHEMA_VERSION
        or row["decisions"] != DECISIONS
        or row["adoption_claim"] is not False
        or row["performance_authoritative"] is not False
        or row["bare_metal_gate_satisfied"] is not False
        or row["durable_evidence_gate_satisfied"] is not False
        or row["scope"] != "repository-architecture-closure"
    ):
        raise CandidateControlError("performance architecture decision values changed")
    source = row["source_identity"]
    if type(source) is not dict:
        raise CandidateControlError(
            "performance architecture decision source is invalid"
        )
    _exact_fields(
        source,
        frozenset({"comparison_axis", "source_sha", "source_tree"}),
        "performance architecture decision source",
    )
    if (
        source["comparison_axis"] != "architecture-decision"
        or build_experiment.COMMIT_SHA.fullmatch(source["source_sha"]) is None
        or build_experiment.GIT_OBJECT.fullmatch(source["source_tree"]) is None
    ):
        raise CandidateControlError("performance architecture decision source changed")
    material = dict(row)
    record_id = material.pop("record_id")
    if record_id != build_experiment._json_sha256(material):
        raise CandidateControlError(
            "performance architecture decision record_id changed"
        )
    return row, bounded.sha256


def add_cli_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    command = commands.add_parser(
        "architecture-decisions",
        help="write the closed deferred/rejected performance architecture decisions",
    )
    command.add_argument("--source-sha", required=True)
    command.add_argument("--source-tree", required=True)
    command.add_argument("--output", required=True, type=pathlib.Path)


def run_cli_command(parsed: argparse.Namespace) -> int:
    record = create_architecture_decisions(
        source_sha=parsed.source_sha, source_tree=parsed.source_tree
    )
    _atomic_text(
        parsed.output,
        json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return 0
