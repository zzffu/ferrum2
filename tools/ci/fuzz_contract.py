#!/usr/bin/env python3
"""Plan the hosted TUN fuzz workflow from the reviewed workspace policy."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
import re
from typing import Sequence
import tomllib

from tools.ci.git_changes import ChangeRequest, discover_changed_paths


ONE_HOUR_SECONDS = 3_600
TARGET_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")


@dataclass(frozen=True)
class ImpactExclusion:
    pattern: str
    kind: str


@dataclass(frozen=True)
class FuzzContract:
    owner_paths: tuple[str, ...]
    documentation_exclusions: tuple[ImpactExclusion, ...]
    targets: tuple[str, ...]
    seconds_per_target: int

    @property
    def targets_json(self) -> str:
        return json.dumps(self.targets, separators=(",", ":"))


@dataclass(frozen=True)
class ImpactDecision:
    affected: bool
    changed_path_count: int
    reason: str


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field} must contain non-empty strings")
    items = tuple(value)
    if len(items) != len(set(items)):
        raise ValueError(f"{field} must not contain duplicates")
    return items


def _documentation_exclusions(value: object) -> tuple[ImpactExclusion, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("fuzz_impact.documentation_exclusions must be an array")
    exclusions: list[ImpactExclusion] = []
    for index, item in enumerate(value):
        field = f"fuzz_impact.documentation_exclusions[{index}]"
        if not isinstance(item, dict) or set(item) != {"pattern", "kind"}:
            raise ValueError(f"{field} must contain exactly pattern and kind")
        pattern = item["pattern"]
        kind = item["kind"]
        if not isinstance(pattern, str) or not pattern or "\\" in pattern or ".." in pattern:
            raise ValueError(f"{field}.pattern must be a normalized repository glob")
        if kind != "markdown" or not pattern.endswith(".md"):
            raise ValueError(f"{field} may only exclude typed Markdown paths")
        exclusions.append(ImpactExclusion(pattern, kind))
    if len({item.pattern for item in exclusions}) != len(exclusions):
        raise ValueError("fuzz_impact.documentation_exclusions must not contain duplicates")
    return tuple(exclusions)


def load_contract(policy_path: Path) -> FuzzContract:
    with policy_path.open("rb") as source:
        policy = tomllib.load(source)

    impact = policy.get("fuzz_impact")
    campaign = policy.get("fuzz_campaign")
    if not isinstance(impact, dict) or not isinstance(campaign, dict):
        raise ValueError("policy must define fuzz_impact and fuzz_campaign tables")

    owner_paths = _string_list(impact.get("owner_paths"), "fuzz_impact.owner_paths")
    documentation_exclusions = _documentation_exclusions(
        impact.get("documentation_exclusions")
    )
    targets = _string_list(campaign.get("targets"), "fuzz_campaign.targets")
    if any(TARGET_NAME.fullmatch(target) is None for target in targets):
        raise ValueError("fuzz_campaign.targets contains an unsafe target name")

    seconds_per_target = campaign.get("seconds_per_target")
    total_seconds = campaign.get("total_seconds")
    if (
        isinstance(seconds_per_target, bool)
        or not isinstance(seconds_per_target, int)
        or seconds_per_target <= 0
    ):
        raise ValueError("fuzz_campaign.seconds_per_target must be a positive integer")
    if isinstance(total_seconds, bool) or not isinstance(total_seconds, int):
        raise ValueError("fuzz_campaign.total_seconds must be an integer")
    if seconds_per_target * len(targets) != total_seconds:
        raise ValueError("fuzz campaign per-target budgets do not add up to total_seconds")
    if total_seconds != ONE_HOUR_SECONDS:
        raise ValueError("fuzz campaign total_seconds must be exactly 3600")

    return FuzzContract(owner_paths, documentation_exclusions, targets, seconds_per_target)


def classify_impact(
    contract: FuzzContract,
    *,
    event_name: str,
    base_sha: str,
    head_sha: str,
    repository: Path,
) -> ImpactDecision:
    changes = discover_changed_paths(
        repository,
        ChangeRequest(event_name=event_name, base_sha=base_sha, head_sha=head_sha),
    )
    if not changes.complete:
        return ImpactDecision(True, 0, f"{changes.reason}; fuzz impact fails closed")
    match_count = 0
    for path in changes.paths:
        owned = any(fnmatch.fnmatchcase(path, pattern) for pattern in contract.owner_paths)
        documented = any(
            exclusion.kind == "markdown"
            and fnmatch.fnmatchcase(path, exclusion.pattern)
            for exclusion in contract.documentation_exclusions
        )
        if owned and not documented:
            match_count += 1
    if match_count:
        reason = f"{match_count} changed path(s) matched the reviewed owner ledger"
    else:
        reason = "reviewed owner paths did not change"
    return ImpactDecision(bool(match_count), len(changes.paths), reason)


def write_github_outputs(path: Path, contract: FuzzContract, decision: ImpactDecision) -> None:
    affected = "true" if decision.affected else "false"
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"affected={affected}\n")
        output.write(f"targets_json={contract.targets_json}\n")
        output.write(f"seconds_per_target={contract.seconds_per_target}\n")


def write_github_summary(path: Path, decision: ImpactDecision) -> None:
    affected = "true" if decision.affected else "false"
    with path.open("a", encoding="utf-8", newline="\n") as summary:
        summary.write(f"Fuzz impact: **{affected}** — {decision.reason}\n\n")
        summary.write(f"Changed paths considered: {decision.changed_path_count}\n")


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--github-summary", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    contract = load_contract(args.policy)
    decision = classify_impact(
        contract,
        event_name=args.event_name,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        repository=args.repository,
    )
    write_github_outputs(args.github_output, contract, decision)
    write_github_summary(args.github_summary, decision)
    affected = "true" if decision.affected else "false"
    print(f"fuzz impact={affected}: {decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
