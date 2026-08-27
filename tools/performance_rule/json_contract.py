"""Closed, bounded JSON contracts shared by Rule evidence readers."""

from __future__ import annotations

import json
import math
from typing import Any

from tools.performance_rule.schema import ControlError


def closed_json_bytes(raw: bytes, *, label: str, maximum_bytes: int) -> Any:
    if len(raw) > maximum_bytes:
        raise ControlError(f"{label} exceeds the {maximum_bytes}-byte bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ControlError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ControlError(f"{label} contains non-finite JSON number {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ControlError(f"{label} contains a non-finite JSON number")
        return parsed

    def bounded_integer(value: str) -> int:
        if len(value.removeprefix("-")) > 20:
            raise ControlError(
                f"{label} contains a JSON integer outside the bounded envelope"
            )
        return int(value, 10)

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
            parse_float=finite_float,
            parse_int=bounded_integer,
        )
    except ControlError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError, OverflowError) as error:
        raise ControlError(f"{label} is not one valid UTF-8 JSON document") from error


def exact_fields(value: Any, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ControlError(f"{label} fields do not match the current schema")
    return value
