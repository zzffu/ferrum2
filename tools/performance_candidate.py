#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Sequence


WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
MODES = frozenset({"diagnostic", "qualification"})
SCENARIO_CATALOG = {
    "tcp-bulk": ("bytes_per_second", "higher_is_better", "tcp-throughput"),
    "tcp-stream-64k": (
        "bytes_per_second",
        "higher_is_better",
        "tcp-throughput",
    ),
    "tcp-request-1k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-4k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-16k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "udp-small-high": (
        "datagrams_per_second",
        "higher_is_better",
        "udp",
    ),
    "udp-mtu-1200": ("datagrams_per_second", "higher_is_better", "udp"),
}
TCP_REQUEST_SCENARIOS = (
    "tcp-request-1k",
    "tcp-request-4k",
    "tcp-request-16k",
)


class CandidateControlError(ValueError):
    """An invalid performance-candidate request or evidence set."""


def _allowed_integer(value: str, *, name: str, allowed: frozenset[int]) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CandidateControlError(f"{name} must be an integer") from error
    if str(parsed) != value or parsed not in allowed:
        choices = ", ".join(str(choice) for choice in sorted(allowed))
        raise CandidateControlError(f"{name} must be one of: {choices}")
    return parsed


def validate_measurement_inputs(
    warmup_seconds: str, active_seconds: str, pairs: str
) -> tuple[int, int, int]:
    """Validate each bounded measurement input independently."""

    return (
        _allowed_integer(
            warmup_seconds, name="warmup_seconds", allowed=WARMUP_SECONDS
        ),
        _allowed_integer(
            active_seconds, name="active_seconds", allowed=ACTIVE_SECONDS
        ),
        _allowed_integer(pairs, name="pairs", allowed=PAIR_COUNTS),
    )


def _git(repository: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _require_commit(repository: pathlib.Path, sha: str, *, name: str) -> str:
    if COMMIT_SHA.fullmatch(sha) is None:
        raise CandidateControlError(f"{name} must be a full 40-character commit SHA")
    canonical = sha.lower()
    probe = _git(repository, "cat-file", "-e", f"{canonical}^{{commit}}")
    if probe.returncode != 0:
        raise CandidateControlError(
            f"{name} is not an available commit; fetch complete history before comparing"
        )
    return canonical


def validate_git_relation(
    repository: pathlib.Path, parent_sha: str, candidate_sha: str
) -> tuple[str, str]:
    """Require two available commits with parent strictly ancestral to candidate."""

    repository = repository.resolve()
    if not repository.is_dir():
        raise CandidateControlError("repository must be an existing directory")
    parent = _require_commit(repository, parent_sha, name="parent_sha")
    candidate = _require_commit(repository, candidate_sha, name="candidate_sha")
    if parent == candidate:
        raise CandidateControlError("parent_sha and candidate_sha must be different commits")
    relation = _git(repository, "merge-base", "--is-ancestor", parent, candidate)
    if relation.returncode == 1:
        raise CandidateControlError("parent_sha is not an ancestor of candidate_sha")
    if relation.returncode != 0:
        raise CandidateControlError(
            "unable to confirm parent/candidate ancestry from the available history"
        )
    return parent, candidate


def _scenario_entry(scenario: str, role: str) -> dict[str, object]:
    metric, direction, _family = SCENARIO_CATALOG[scenario]
    return {
        "scenario": scenario,
        "role": role,
        "mandatory": True,
        "metric": metric,
        "direction": direction,
    }


def _qualification_scenarios(selected: str) -> list[dict[str, object]]:
    family = SCENARIO_CATALOG[selected][2]
    if family == "tcp-throughput":
        guard = "tcp-bulk" if selected == "tcp-stream-64k" else "tcp-stream-64k"
        return [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")]
    if family == "tcp-request":
        scenarios = [_scenario_entry(selected, "primary")]
        scenarios.extend(
            _scenario_entry(scenario, "guard")
            for scenario in TCP_REQUEST_SCENARIOS
            if scenario != selected
        )
        scenarios.append(_scenario_entry("tcp-bulk", "guard"))
        return scenarios
    if family == "udp":
        guard = "udp-mtu-1200" if selected == "udp-small-high" else "udp-small-high"
        return [_scenario_entry(selected, "primary"), _scenario_entry(guard, "guard")]
    raise AssertionError(f"unhandled scenario family: {family}")


def create_plan(
    *,
    mode: str,
    scenario: str,
    warmup_seconds: str,
    active_seconds: str,
    pairs: str,
) -> dict[str, object]:
    """Build the authoritative scenario plan for one manual workflow run."""

    if mode not in MODES:
        raise CandidateControlError("mode must be diagnostic or qualification")
    if scenario not in SCENARIO_CATALOG:
        raise CandidateControlError("scenario is not a supported profile workload")
    warmup, active, pair_count = validate_measurement_inputs(
        warmup_seconds, active_seconds, pairs
    )
    scenarios = (
        [_scenario_entry(scenario, "diagnostic")]
        if mode == "diagnostic"
        else _qualification_scenarios(scenario)
    )
    return {
        "schema_version": 1,
        "mode": mode,
        "selected_scenario": scenario,
        "warmup_seconds": warmup,
        "active_seconds": active,
        "pairs": pair_count,
        "decision_policy": None,
        "adoption_eligible": False,
        "scenarios": scenarios,
    }


def write_plan(path: pathlib.Path, plan: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_plan(path: pathlib.Path) -> dict[str, object]:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
        expected = create_plan(
            mode=plan["mode"],
            scenario=plan["selected_scenario"],
            warmup_seconds=str(plan["warmup_seconds"]),
            active_seconds=str(plan["active_seconds"]),
            pairs=str(plan["pairs"]),
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise CandidateControlError("performance plan is invalid") from error
    if plan != expected:
        raise CandidateControlError("performance plan does not match the canonical scenario set")
    return plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-inputs", help="validate bounded workflow measurement inputs"
    )
    validate.add_argument("--warmup-seconds", required=True)
    validate.add_argument("--active-seconds", required=True)
    validate.add_argument("--pairs", required=True)
    relation = commands.add_parser(
        "validate-git", help="validate strict parent-to-candidate ancestry"
    )
    relation.add_argument("--repository", required=True, type=pathlib.Path)
    relation.add_argument("--parent-sha", required=True)
    relation.add_argument("--candidate-sha", required=True)
    plan = commands.add_parser("plan", help="write a canonical scenario plan")
    plan.add_argument("--mode", required=True)
    plan.add_argument("--scenario", required=True)
    plan.add_argument("--warmup-seconds", required=True)
    plan.add_argument("--active-seconds", required=True)
    plan.add_argument("--pairs", required=True)
    plan.add_argument("--output", required=True, type=pathlib.Path)
    scenarios = commands.add_parser(
        "scenarios", help="emit planned scenario names, one per line"
    )
    scenarios.add_argument("--plan", required=True, type=pathlib.Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        if parsed.command == "plan":
            plan = create_plan(
                mode=parsed.mode,
                scenario=parsed.scenario,
                warmup_seconds=parsed.warmup_seconds,
                active_seconds=parsed.active_seconds,
                pairs=parsed.pairs,
            )
            write_plan(parsed.output, plan)
            return 0
        if parsed.command == "scenarios":
            plan = load_plan(parsed.plan)
            for scenario in plan["scenarios"]:
                print(scenario["scenario"])
            return 0
        if parsed.command == "validate-git":
            validate_git_relation(
                parsed.repository, parsed.parent_sha, parsed.candidate_sha
            )
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
