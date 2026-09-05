"""Bounded container validation; it does not certify CPU samples or lost events."""

from __future__ import annotations

import gzip
import io
import json
import math
from pathlib import Path


class EvidenceError(ValueError):
    pass


def bounded_bytes(path: Path, maximum: int) -> bytes:
    try:
        if path.stat().st_size > maximum:
            raise EvidenceError("artifact_byte_limit")
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
    except OSError as error:
        raise EvidenceError("artifact_unreadable") from error
    if len(raw) > maximum:
        raise EvidenceError("artifact_byte_limit")
    return raw


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("duplicate_json_key")
        value[key] = item
    return value


def _constant(_value):
    raise EvidenceError("nonfinite_json_value")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise EvidenceError("nonfinite_json_value")
    return number


def validate_samply_container(
    path: Path, *, compressed_cap: int = 32 * 1024 * 1024,
    decompressed_cap: int = 128 * 1024 * 1024,
) -> dict[str, object]:
    # Header/size checks precede decompression; read remains capped if the file grows.
    raw = bounded_bytes(path, compressed_cap)
    if not raw.startswith(b"\x1f\x8b"):
        raise EvidenceError("invalid_gzip")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            content = stream.read(decompressed_cap + 1)
        if len(content) > decompressed_cap:
            raise EvidenceError("decompressed_byte_limit")
        value = json.loads(
            content.decode("utf-8"), object_pairs_hook=_object,
            parse_constant=_constant, parse_float=_float,
        )
    except EvidenceError:
        raise
    except (OSError, EOFError, ValueError, RecursionError, OverflowError) as error:
        raise EvidenceError("invalid_profile_container") from error
    if type(value) is not dict:
        raise EvidenceError("profile_container_not_object")
    return {
        "container": "gzip_json_object", "sample_schema": "unverified",
        "compressed_bytes": len(raw), "decompressed_bytes": len(content),
    }


def validate_perf_container(path: Path) -> dict[str, object]:
    raw = bounded_bytes(path, 1024 * 1024)
    if not raw.strip():
        raise EvidenceError("empty_perf_output")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise EvidenceError("invalid_perf_encoding") from error
    if "<not supported>" in text or "<not counted>" in text:
        raise EvidenceError("unavailable_perf_counter")
    # No reviewed perf version/column fixture is present yet. Do not guess a
    # complete event/coverage schema from an arbitrary nonempty numeric line.
    return {"container": "utf8_text", "counter_schema": "unverified", "bytes": len(raw)}
