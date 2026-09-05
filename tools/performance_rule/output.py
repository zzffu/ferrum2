"""One encoded-byte budget for collection, evidence readers and atomic output."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from tools.performance_rule.schema import ControlError

EVIDENCE_MAX_BYTES = 64 * 1024 * 1024


class EvidenceLimit(ControlError):
    """The next evidence document does not fit the retained run budget."""


def _chunks(value: Any):
    yield from json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False).iterencode(value)
    yield "\n"


def encoded_size(value: Any) -> int:
    total = 0
    for chunk in _chunks(value):
        total += len(chunk.encode("utf-8"))
        if total > EVIDENCE_MAX_BYTES:
            raise EvidenceLimit("controller evidence exceeds the encoded byte bound")
    return total


def emit_result(result: dict[str, Any], output: Path | None) -> None:
    # Measure the exact shared encoder before allocating the complete document.
    # Collection calls this same check for each prospective retained report.
    encoded_size(result)
    encoded = "".join(_chunks(result))
    if len(encoded.encode("utf-8")) > EVIDENCE_MAX_BYTES:
        raise EvidenceLimit("controller evidence exceeds the encoded byte bound")
    if output is not None:
        if output.suffix != ".json":
            raise ControlError("--output must have a .json extension")
        output.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
        primary: BaseException | None = None
        cleanup_errors: list[BaseException] = []
        try:
            temporary = os.fdopen(handle, "w", encoding="utf-8", newline="\n")
            handle = None  # The stream now owns the descriptor.
            try:
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            except BaseException as error:
                primary = error
            finally:
                try:
                    temporary.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if primary is None and not cleanup_errors:
                os.replace(temporary_name, output)
        except BaseException as error:
            primary = error
        finally:
            if handle is not None:
                try:
                    os.close(handle)
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            except BaseException as error:
                cleanup_errors.append(error)
        if primary is not None:
            if cleanup_errors:
                raise primary from BaseExceptionGroup("output cleanup failed", cleanup_errors)
            raise primary
        if cleanup_errors:
            if len(cleanup_errors) == 1:
                raise cleanup_errors[0]
            raise BaseExceptionGroup("output cleanup failed", cleanup_errors)
    sys.stdout.write(encoded)
