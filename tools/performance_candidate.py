#!/usr/bin/env python3
"""Control-plane helpers for manual parent/candidate performance runs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


WARMUP_SECONDS = frozenset({1, 3, 5, 10})
ACTIVE_SECONDS = frozenset({15, 30, 60})
PAIR_COUNTS = frozenset({3, 5})


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-inputs", help="validate bounded workflow measurement inputs"
    )
    validate.add_argument("--warmup-seconds", required=True)
    validate.add_argument("--active-seconds", required=True)
    validate.add_argument("--pairs", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "validate-inputs":
            validate_measurement_inputs(
                parsed.warmup_seconds, parsed.active_seconds, parsed.pairs
            )
            return 0
        raise AssertionError(f"unhandled command: {parsed.command}")
    except CandidateControlError as error:
        print(f"performance-candidate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
