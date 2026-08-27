"""Classify whether the ordinary hosted gates must run for a Git change."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tools.ci.git_changes import ChangeRequest, discover_changed_paths


@dataclass(frozen=True)
class GateDecision:
    run_expensive: bool
    changed_path_count: int
    reason: str


def classify(
    *,
    event_name: str,
    base_sha: str,
    head_sha: str,
    repository: Path,
) -> GateDecision:
    changes = discover_changed_paths(
        repository,
        ChangeRequest(event_name=event_name, base_sha=base_sha, head_sha=head_sha),
    )
    if not changes.complete:
        return GateDecision(True, 0, f"{changes.reason}; ordinary gates fail closed")
    if not changes.paths:
        return GateDecision(True, 0, "empty diff runs ordinary gates")
    if all(path.endswith(".md") for path in changes.paths):
        return GateDecision(False, len(changes.paths), "every changed path is Markdown")
    return GateDecision(True, len(changes.paths), "a non-Markdown path changed")


def write_github_output(path: Path, decision: GateDecision) -> None:
    value = "true" if decision.run_expensive else "false"
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"run_expensive={value}\n")


def write_github_summary(path: Path, decision: GateDecision) -> None:
    value = "true" if decision.run_expensive else "false"
    with path.open("a", encoding="utf-8", newline="\n") as summary:
        summary.write(f"Ordinary gates: **{value}** — {decision.reason}\n\n")
        summary.write(f"Changed paths considered: {decision.changed_path_count}\n")


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--github-summary", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    decision = classify(
        event_name=args.event_name,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        repository=args.repository,
    )
    write_github_output(args.github_output, decision)
    write_github_summary(args.github_summary, decision)
    value = "true" if decision.run_expensive else "false"
    print(f"ordinary gates={value}: {decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
