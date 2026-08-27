#!/usr/bin/env python3
"""Validate the terminal required job from typed GitHub job results."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class GateMode(Enum):
    ORDINARY = "ordinary"
    FUZZ = "fuzz"


class JobResult(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class GatePolicy:
    classifier: str
    conditional: tuple[str, ...]

    @property
    def dependencies(self) -> frozenset[str]:
        return frozenset((self.classifier, *self.conditional))


POLICIES = {
    GateMode.ORDINARY: GatePolicy("changes", ("quality", "platform", "interop")),
    GateMode.FUZZ: GatePolicy(
        "impact", ("deterministic-build", "libfuzzer-build", "fuzz-campaign")
    ),
}


def parse_decision(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"decision must be true or false, got {value!r}")


def parse_results(values: Sequence[str]) -> dict[str, JobResult]:
    results: dict[str, JobResult] = {}
    for value in values:
        name, separator, result = value.partition("=")
        if not separator or not name or not result:
            raise ValueError(f"dependency result must use NAME=RESULT, got {value!r}")
        if name in results:
            raise ValueError(f"dependency result is duplicated: {name}")
        try:
            results[name] = JobResult(result)
        except ValueError as error:
            raise ValueError(f"dependency {name} has unknown result {result!r}") from error
    return results


def validate_gate(
    mode: GateMode, decision: bool, results: dict[str, JobResult]
) -> None:
    policy = POLICIES[mode]
    actual = frozenset(results)
    if actual != policy.dependencies:
        missing = sorted(policy.dependencies - actual)
        extra = sorted(actual - policy.dependencies)
        raise ValueError(f"dependency set drifted: missing={missing}, extra={extra}")
    if results[policy.classifier] is not JobResult.SUCCESS:
        raise ValueError(f"classifier {policy.classifier} did not succeed")

    expected = JobResult.SUCCESS if decision else JobResult.SKIPPED
    mismatches = [
        f"{name}={results[name].value}"
        for name in policy.conditional
        if results[name] is not expected
    ]
    if mismatches:
        raise ValueError(
            f"conditional gates must be {expected.value}: {', '.join(mismatches)}"
        )


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=[mode.value for mode in GateMode], required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--dependency", action="append", default=[], required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        mode = GateMode(args.mode)
        decision = parse_decision(args.decision)
        results = parse_results(args.dependency)
        validate_gate(mode, decision, results)
    except ValueError as error:
        print(f"required gate: FAIL: {error}")
        return 1
    print(
        f"required gate: PASS: mode={mode.value} decision={'true' if decision else 'false'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
