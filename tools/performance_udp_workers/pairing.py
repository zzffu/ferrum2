"""Deterministic two-round A/A and six-pair ABBA trial planning."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from tools.performance_udp_workers.contract import (
    AA_ROUNDS,
    AUTHORITY,
    COMPARISON_WORKERS,
    PAIRS,
    PLAN_SCHEMA_VERSION,
    SESSION_COUNTS,
    SESSION_TOPOLOGIES,
    UdpWorkerControlError,
    semantic_recipe,
)


@dataclass(frozen=True)
class Trial:
    sequence: int
    phase: str
    round: int
    pair: int
    order: int
    member: str
    comparison_receive_workers: int
    server_receive_workers: int
    session_topology: str
    logical_sessions: int
    output: str
    ready_file: str

    def as_json(self) -> dict[str, object]:
        return asdict(self)


def pair_members(pair: int) -> tuple[str, str]:
    if type(pair) is not int or not 1 <= pair <= PAIRS:
        raise UdpWorkerControlError("pair is outside the fixed six-pair schedule")
    return ("baseline", "variant") if pair % 2 == 1 else ("variant", "baseline")


def _trial(
    *,
    sequence: int,
    topology: str,
    phase: str,
    round_number: int,
    pair: int,
    order: int,
    member: str,
    comparison_workers: int,
) -> Trial:
    server_workers = 1 if member == "baseline" else comparison_workers
    stem = (
        f"{topology}-{phase}-round-{round_number}-workers-{comparison_workers}"
        f"-pair-{pair}-order-{order}-{member}"
    )
    return Trial(
        sequence=sequence,
        phase=phase,
        round=round_number,
        pair=pair,
        order=order,
        member=member,
        comparison_receive_workers=comparison_workers,
        server_receive_workers=server_workers,
        session_topology=topology,
        logical_sessions=SESSION_COUNTS[topology],
        output=f"profiles/udp-workers/raw/{topology}/{stem}.json",
        ready_file=f"profiles/udp-workers/ready/{stem}.ready",
    )


def build_trials() -> list[Trial]:
    trials: list[Trial] = []
    for topology in SESSION_TOPOLOGIES:
        for round_number in range(1, AA_ROUNDS + 1):
            for pair in range(1, PAIRS + 1):
                for order, member in enumerate(pair_members(pair), start=1):
                    trials.append(
                        _trial(
                            sequence=len(trials) + 1,
                            topology=topology,
                            phase="calibration-aa",
                            round_number=round_number,
                            pair=pair,
                            order=order,
                            member=member,
                            comparison_workers=1,
                        )
                    )
        for comparison_workers in COMPARISON_WORKERS:
            for pair in range(1, PAIRS + 1):
                for order, member in enumerate(pair_members(pair), start=1):
                    trials.append(
                        _trial(
                            sequence=len(trials) + 1,
                            topology=topology,
                            phase="comparison",
                            round_number=1,
                            pair=pair,
                            order=order,
                            member=member,
                            comparison_workers=comparison_workers,
                        )
                    )
    validate_trials(trials)
    return trials


def validate_trials(trials: list[Trial]) -> None:
    expected_count = (
        len(SESSION_TOPOLOGIES) * (AA_ROUNDS + len(COMPARISON_WORKERS)) * PAIRS * 2
    )
    if len(trials) != expected_count:
        raise UdpWorkerControlError("UDP worker trial plan is incomplete")
    if [trial.sequence for trial in trials] != list(range(1, expected_count + 1)):
        raise UdpWorkerControlError("UDP worker trial sequence is not closed")
    if len({trial.output for trial in trials}) != expected_count:
        raise UdpWorkerControlError("UDP worker trial output paths are duplicated")
    for trial in trials:
        if trial.member not in pair_members(trial.pair):
            raise UdpWorkerControlError("UDP worker member is outside ABBA")
        if pair_members(trial.pair)[trial.order - 1] != trial.member:
            raise UdpWorkerControlError("UDP worker order does not match ABBA")
        if trial.logical_sessions != SESSION_COUNTS.get(trial.session_topology):
            raise UdpWorkerControlError("UDP worker session topology is inconsistent")
        if trial.phase == "calibration-aa":
            valid = (
                trial.round in range(1, AA_ROUNDS + 1)
                and trial.comparison_receive_workers == 1
                and trial.server_receive_workers == 1
            )
        else:
            valid = (
                trial.phase == "comparison"
                and trial.round == 1
                and trial.comparison_receive_workers in COMPARISON_WORKERS
                and trial.server_receive_workers
                == (
                    1
                    if trial.member == "baseline"
                    else trial.comparison_receive_workers
                )
            )
        if not valid:
            raise UdpWorkerControlError("UDP worker axis label is inconsistent")


def build_plan(candidate_sha: str, contract: dict[str, str | int]) -> dict[str, object]:
    if len(candidate_sha) != 40 or any(
        character not in "0123456789abcdef" for character in candidate_sha
    ):
        raise UdpWorkerControlError("candidate SHA is outside the closed plan identity")
    if set(contract) != {
        "schema_version",
        "trial_schema_version",
        "structural_schema_version",
        "runner_image",
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
    }:
        raise UdpWorkerControlError(
            "evidence contract is outside the closed plan schema"
        )
    trials = build_trials()
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "kind": "ferrum2_udp_worker_plan",
        "candidate_sha": candidate_sha,
        "recipe": semantic_recipe(),
        "evidence_contract": contract,
        "trials": [trial.as_json() for trial in trials],
        "authority": dict(AUTHORITY),
    }
