"""Pure manifest contracts for pinned Linux interoperability providers."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, NoReturn, Protocol


REVIEW_BOUNDARY = "execute only as an independent test process; do not redistribute"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class Artifact:
    asset: str
    url: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ProviderPin:
    provider_id: str
    version: str
    source_commit: str
    expected_version: str
    license_review: str
    linux: Artifact
    license: Artifact | None = None


@dataclass(frozen=True)
class SupplementalArtifactContract:
    asset_template: str
    url_field: str
    size_field: str
    sha256_field: str
    require_source_commit_in_url: bool


@dataclass(frozen=True)
class ArchiveStrategy:
    exact_member_templates: tuple[str, ...] | None = None
    rooted_tree_template: str | None = None
    strip_root: bool = False


class ProviderContract(Protocol):
    provider_id: str
    license_marker: str
    supplemental_artifact: SupplementalArtifactContract | None


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def table(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        fail(f"{context} must be a TOML table")
    return value


def text(values: Mapping[str, object], key: str, context: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{context}.{key} must be a non-empty string")
    return value


def positive_integer(values: Mapping[str, object], key: str, context: str) -> int:
    value = values.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{context}.{key} must be a positive integer")
    return value


def parse_artifact(values: Mapping[str, object], prefix: str, context: str) -> Artifact:
    artifact = Artifact(
        asset=text(values, f"{prefix}asset", context),
        url=text(values, f"{prefix}url", context),
        size=positive_integer(values, f"{prefix}size", context),
        sha256=text(values, f"{prefix}sha256", context),
    )
    if Path(artifact.asset).name != artifact.asset:
        fail(f"{context}.{prefix}asset must be a basename")
    if not artifact.url.startswith("https://") or not artifact.url.endswith(
        "/" + artifact.asset
    ):
        fail(f"{context}.{prefix}url must be HTTPS and end with the asset name")
    if not HEX_256.fullmatch(artifact.sha256):
        fail(f"{context}.{prefix}sha256 must be lowercase SHA-256")
    return artifact


def parse_supplemental_artifact(
    values: Mapping[str, object],
    provider_id: str,
    version: str,
    source_commit: str,
    contract: SupplementalArtifactContract,
) -> Artifact:
    artifact = Artifact(
        asset=contract.asset_template.format(version=version),
        url=text(values, contract.url_field, provider_id),
        size=positive_integer(values, contract.size_field, provider_id),
        sha256=text(values, contract.sha256_field, provider_id),
    )
    if not artifact.url.startswith("https://"):
        fail(f"{provider_id}.{contract.url_field} must use HTTPS")
    if not HEX_256.fullmatch(artifact.sha256):
        fail(f"{provider_id}.{contract.sha256_field} must be lowercase SHA-256")
    if contract.require_source_commit_in_url and source_commit not in artifact.url:
        fail(f"{provider_id}.{contract.url_field} must be pinned to source_commit")
    return artifact


def parse_document(contents: bytes) -> Mapping[str, object]:
    document = tomllib.loads(contents.decode("utf-8"))
    if document.get("schema_version") != 1:
        fail("versions.toml schema_version must be 1")
    return document


def parse_provider(
    document: Mapping[str, object], spec: ProviderContract
) -> ProviderPin:
    values = table(document.get(spec.provider_id), spec.provider_id)
    version = text(values, "version", spec.provider_id)
    source_commit = text(values, "source_commit", spec.provider_id)
    expected_version = text(values, "expected_version", spec.provider_id)
    license_review = text(values, "license_review", spec.provider_id)
    if not SOURCE_COMMIT.fullmatch(source_commit):
        fail(f"{spec.provider_id}.source_commit must be a lowercase Git commit")
    if version not in expected_version:
        fail(f"{spec.provider_id}.expected_version must identify its version")
    if spec.license_marker not in license_review or REVIEW_BOUNDARY not in license_review:
        fail(f"{spec.provider_id}.license_review does not preserve the reviewed boundary")
    linux = parse_artifact(values, "linux_", spec.provider_id)
    if version not in linux.asset:
        fail(f"{spec.provider_id}.linux_asset must identify its version")
    supplemental_artifact = (
        parse_supplemental_artifact(
            values,
            spec.provider_id,
            version,
            source_commit,
            spec.supplemental_artifact,
        )
        if spec.supplemental_artifact is not None
        else None
    )
    return ProviderPin(
        spec.provider_id,
        version,
        source_commit,
        expected_version,
        license_review,
        linux,
        supplemental_artifact,
    )
