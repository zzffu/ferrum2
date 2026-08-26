"""Verify an explicitly supplied directory of external Rule performance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from tests.performance_rule.archive_verifier import (
    ARCHIVED_CONTROLLER_CONTRACTS,
    validate_archived_controller,
)


MANIFEST = Path(__file__).with_name("fixtures") / "external-evidence-manifest-v1.json"


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def verify(evidence_directory: Path) -> dict[str, object]:
    manifest = json.loads(
        MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=_closed_object
    )
    if (
        type(manifest) is not dict
        or set(manifest)
        != {"artifacts", "kind", "schema_version", "storage", "total_bytes"}
        or manifest["schema_version"] != 1
    ):
        raise ValueError("external evidence manifest is unsupported")

    selected_root = evidence_directory.absolute()
    if not selected_root.exists():
        raise ValueError("evidence directory does not exist")
    if _is_reparse_point(selected_root):
        raise ValueError("evidence directory cannot be a reparse point")
    root = selected_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("evidence directory must be a real directory")

    expected_names = {entry["file"] for entry in manifest["artifacts"]}
    unexpected_release_files = {
        path.name for path in root.glob("release-*.json") if path.name not in expected_names
    }
    if unexpected_release_files:
        raise ValueError(
            f"unexpected external evidence versions: {sorted(unexpected_release_files)}"
        )

    verified = []
    for entry in manifest["artifacts"]:
        if type(entry) is not dict or set(entry) != {
            "bytes",
            "file",
            "role",
            "sha256",
        }:
            raise ValueError("external evidence manifest entry is invalid")
        name = entry["file"]
        if type(name) is not str or Path(name).name != name:
            raise ValueError("external evidence file name is unsafe")
        path = root / name
        if not path.exists() or _is_reparse_point(path) or not path.is_file():
            raise ValueError(f"external evidence is missing: {name}")
        if path.stat().st_size != entry["bytes"]:
            raise ValueError(f"external evidence byte length changed: {name}")
        if _sha256(path) != entry["sha256"]:
            raise ValueError(f"external evidence SHA-256 changed: {name}")
        if entry["role"] in ARCHIVED_CONTROLLER_CONTRACTS:
            validate_archived_controller(path, entry["role"])
        verified.append(
            {"file": name, "role": entry["role"], "sha256": entry["sha256"]}
        )

    return {
        "kind": "ferrum2_rule_external_evidence_verification",
        "schema_version": 1,
        "status": "PASS",
        "artifact_count": len(verified),
        "total_bytes": manifest["total_bytes"],
        "artifacts": verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    result = verify(parser.parse_args().evidence_directory)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
