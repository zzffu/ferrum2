"""json contract owner."""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal


SHA256 = re.compile(r"[0-9a-f]{64}")


U64_MAX = (1 << 64) - 1


class CandidateControlError(ValueError):
    """An invalid performance-candidate request or evidence set."""

    def __init__(
        self, message: str, *, missing_scenarios: Sequence[str] | None = None
    ) -> None:
        super().__init__(message)
        self.missing_scenarios = sorted(set(missing_scenarios or ()))


@dataclass(frozen=True)
class BoundedClosedJson:
    value: object
    sha256: str


def _reject_json_constant(value: str) -> object:
    raise CandidateControlError(f"non-finite JSON number is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateControlError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _bounded_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 20:
        raise CandidateControlError("JSON integer exceeds the bounded integer envelope")
    return int(value, 10)


def _bounded_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CandidateControlError("JSON float exceeds the finite number envelope")
    return parsed


def _strict_json(text: str, *, source: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_bounded_json_float,
            parse_int=_bounded_json_integer,
        )
    except CandidateControlError:
        raise
    except (ValueError, RecursionError, OverflowError) as error:
        raise CandidateControlError(f"{source} is not valid JSON") from error


def read_bounded_closed_json(
    path: pathlib.Path, *, maximum_bytes: int, source: str
) -> BoundedClosedJson:
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise CandidateControlError(f"{source} has an invalid byte bound")
    try:
        if path.stat().st_size > maximum_bytes:
            raise CandidateControlError(
                f"{source} exceeds the {maximum_bytes}-byte bound"
            )
        with path.open("rb") as handle:
            raw = handle.read(maximum_bytes + 1)
    except CandidateControlError:
        raise
    except OSError as error:
        raise CandidateControlError(f"unable to read {source}") from error
    if len(raw) > maximum_bytes:
        raise CandidateControlError(f"{source} exceeds the {maximum_bytes}-byte bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CandidateControlError(f"{source} must be strict UTF-8") from error
    return BoundedClosedJson(
        value=_strict_json(text, source=source),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _exact_fields(
    value: dict[str, object], expected: frozenset[str], name: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise CandidateControlError(
            f"{name} schema mismatch: missing={missing}, unexpected={unexpected}"
        )


def _policy_percent(value: object, field: str) -> Decimal:
    if type(value) not in {int, float}:
        raise CandidateControlError(f"{field} must be a finite JSON number")
    parsed = Decimal(str(value))
    if not parsed.is_finite():
        raise CandidateControlError(f"{field} must be finite")
    return parsed


def _scale_decimal(value: object, field: str) -> Decimal:
    parsed = _policy_percent(value, field)
    return parsed


def _required_string(
    row: dict[str, object], field: str, *, expected: str | None = None
) -> str:
    value = row.get(field)
    if type(value) is not str or not value:
        raise CandidateControlError(f"{field} must be a non-empty string")
    if expected is not None and value != expected:
        raise CandidateControlError(f"{field} does not match the expected value")
    return value


def _required_u64(row: dict[str, object], field: str, *, positive: bool = False) -> int:
    value = row.get(field)
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise CandidateControlError(f"{field} must be an unsigned 64-bit integer")
    if positive and value == 0:
        raise CandidateControlError(f"{field} must be positive")
    return value


def _optional_u64(row: dict[str, object], field: str) -> int | None:
    value = row.get(field)
    if value is None:
        return None
    return _required_u64(row, field, positive=True)


def _require_pattern(value: str, pattern: re.Pattern[str], *, field: str) -> None:
    if pattern.fullmatch(value) is None:
        raise CandidateControlError(f"{field} has an invalid identity")


def _required_i64(value: object, field: str) -> int:
    if type(value) is not int or not -(1 << 63) <= value <= (1 << 63) - 1:
        raise CandidateControlError(f"{field} must be a signed 64-bit integer")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
