#!/usr/bin/env python3
"""Provision the pinned Linux interoperability reference binaries."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, NoReturn


REVIEW_BOUNDARY = "execute only as an independent test process; do not redistribute"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
COREDNS_GO_VERSION = re.compile(r"go[1-9][0-9]*\.[0-9]+\.[0-9]+\Z")
COREDNS_SHORT_REVISION_LENGTH = 7


class Provider(str, Enum):
    SING_BOX = "sing_box"
    SHADOWSOCKS_RUST = "shadowsocks_rust"
    COREDNS = "coredns"
    BIND = "bind"


@dataclass(frozen=True)
class Artifact:
    asset: str
    url: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ProviderPin:
    provider: Provider
    version: str
    source_commit: str
    expected_version: str
    license_review: str
    linux: Artifact
    license: Artifact | None = None


@dataclass(frozen=True)
class ProviderDefinition:
    timeout_seconds: int
    license_marker: str


DEFINITIONS = {
    Provider.SING_BOX: ProviderDefinition(5 * 60, "NOASSERTION"),
    Provider.SHADOWSOCKS_RUST: ProviderDefinition(5 * 60, "MIT"),
    Provider.COREDNS: ProviderDefinition(5 * 60, "Apache-2.0"),
    Provider.BIND: ProviderDefinition(15 * 60, "MPL-2.0"),
}

GITHUB_STATUS_NAMES = {
    Provider.SING_BOX: "M2_SING_BOX_SETUP_STATUS",
    Provider.SHADOWSOCKS_RUST: "M2_SHADOWSOCKS_RUST_SETUP_STATUS",
    Provider.COREDNS: "M12_COREDNS_SETUP_STATUS",
    Provider.BIND: "M12_BIND_SETUP_STATUS",
}


@dataclass
class Deadline:
    expires_at: float

    @classmethod
    def after(cls, seconds: int) -> "Deadline":
        return cls(time.monotonic() + seconds)

    def remaining(self, operation: str) -> float:
        seconds = self.expires_at - time.monotonic()
        if seconds <= 0:
            raise TimeoutError(f"provider timeout during {operation}")
        return seconds


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
    if not artifact.url.startswith("https://") or not artifact.url.endswith("/" + artifact.asset):
        fail(f"{context}.{prefix}url must be HTTPS and end with the asset name")
    if not HEX_256.fullmatch(artifact.sha256):
        fail(f"{context}.{prefix}sha256 must be lowercase SHA-256")
    return artifact


def parse_coredns_license(values: Mapping[str, object], version: str) -> Artifact:
    context = "coredns"
    artifact = Artifact(
        asset=f"coredns-{version}-LICENSE",
        url=text(values, "license_url", context),
        size=positive_integer(values, "license_size", context),
        sha256=text(values, "license_sha256", context),
    )
    if not artifact.url.startswith("https://"):
        fail("coredns.license_url must use HTTPS")
    if not HEX_256.fullmatch(artifact.sha256):
        fail("coredns.license_sha256 must be lowercase SHA-256")
    return artifact


def parse_document(contents: bytes) -> Mapping[str, object]:
    document = tomllib.loads(contents.decode("utf-8"))
    if document.get("schema_version") != 1:
        fail("versions.toml schema_version must be 1")
    return document


def parse_provider(document: Mapping[str, object], provider: Provider) -> ProviderPin:
    values = table(document.get(provider.value), provider.value)
    version = text(values, "version", provider.value)
    source_commit = text(values, "source_commit", provider.value)
    expected_version = text(values, "expected_version", provider.value)
    license_review = text(values, "license_review", provider.value)
    definition = DEFINITIONS[provider]
    if not SOURCE_COMMIT.fullmatch(source_commit):
        fail(f"{provider.value}.source_commit must be a lowercase Git commit")
    if version not in expected_version:
        fail(f"{provider.value}.expected_version must identify its version")
    if definition.license_marker not in license_review or REVIEW_BOUNDARY not in license_review:
        fail(f"{provider.value}.license_review does not preserve the reviewed boundary")
    linux = parse_artifact(values, "linux_", provider.value)
    if version not in linux.asset:
        fail(f"{provider.value}.linux_asset must identify its version")
    license_artifact = None
    if provider is Provider.COREDNS:
        license_artifact = parse_coredns_license(values, version)
        if source_commit not in license_artifact.url:
            fail("coredns.license_url must be pinned to source_commit")
    return ProviderPin(
        provider,
        version,
        source_commit,
        expected_version,
        license_review,
        linux,
        license_artifact,
    )


def parse_manifest(contents: bytes) -> tuple[ProviderPin, ...]:
    document = parse_document(contents)
    return tuple(parse_provider(document, provider) for provider in Provider)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(path: Path, artifact: Artifact) -> None:
    if not path.is_file() or path.stat().st_size != artifact.size:
        raise RuntimeError(f"artifact size mismatch: {path}")
    if sha256(path) != artifact.sha256:
        raise RuntimeError(f"artifact SHA-256 mismatch: {path}")


def download_atomic(artifact: Artifact, destination: Path, deadline: Deadline) -> None:
    if destination.exists():
        try:
            verify_artifact(destination, artifact)
            return
        except RuntimeError:
            destination.unlink()
    partial = destination.with_name(destination.name + ".partial")
    last_error: Exception | None = None
    for attempt in range(1, 4):
        partial.unlink(missing_ok=True)
        try:
            request = urllib.request.Request(artifact.url, headers={"User-Agent": "ferrum2-ci/1"})
            with urllib.request.urlopen(
                request, timeout=min(30.0, deadline.remaining("download"))
            ) as response, partial.open("xb") as output:
                copied = 0
                while chunk := response.read(1024 * 1024):
                    deadline.remaining("download")
                    copied += len(chunk)
                    if copied > artifact.size:
                        raise RuntimeError("download exceeded pinned size")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            verify_artifact(partial, artifact)
            partial.replace(destination)
            return
        except Exception as error:  # urllib exposes several unrelated transport errors.
            last_error = error
            partial.unlink(missing_ok=True)
            print(f"download attempt {attempt}/3 failed for {artifact.asset}: {error}", file=sys.stderr)
    raise RuntimeError(f"download failed for {artifact.asset}") from last_error


def archive_names(path: Path) -> tuple[str, ...]:
    with tarfile.open(path, "r:*") as archive:
        return tuple(member.name for member in archive.getmembers())


def expected_archive_names(pin: ProviderPin) -> tuple[str, ...] | None:
    if pin.provider is Provider.SING_BOX:
        root = f"sing-box-{pin.version}-linux-amd64-glibc"
        return (root, f"{root}/LICENSE", f"{root}/sing-box")
    if pin.provider is Provider.SHADOWSOCKS_RUST:
        return ("sslocal", "ssserver", "ssurl", "ssmanager", "ssservice")
    if pin.provider is Provider.COREDNS:
        return ("coredns",)
    return None


def verify_archive_members(pin: ProviderPin, path: Path) -> None:
    names = archive_names(path)
    expected = expected_archive_names(pin)
    if expected is not None and names != expected:
        raise RuntimeError(f"{pin.provider.value} archive members changed: {names!r}")
    if pin.provider is Provider.BIND:
        root = f"bind-{pin.version}"
        if not names or names[0].rstrip("/") != root:
            raise RuntimeError("BIND archive root changed")
        if any(name.rstrip("/") != root and not name.startswith(root + "/") for name in names):
            raise RuntimeError("BIND archive contains a member outside its pinned root")


def extract_atomic(archive_path: Path, destination: Path, strip_prefix: str | None = None) -> None:
    partial = destination.with_name(destination.name + ".partial")
    if destination.exists() or partial.exists():
        raise RuntimeError(f"provider extraction path already exists: {destination}")
    partial.mkdir()
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            archive.extractall(partial, filter="data")
        if strip_prefix is None:
            partial.replace(destination)
        else:
            extracted_root = partial / strip_prefix
            if not extracted_root.is_dir():
                raise RuntimeError(f"archive root is missing: {strip_prefix}")
            extracted_root.replace(destination)
            partial.rmdir()
    except tarfile.TarError as error:
        shutil.rmtree(partial, ignore_errors=True)
        raise RuntimeError(f"unsafe archive member: {error}") from error
    except Exception:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def print_captured(output: str | bytes | None) -> None:
    if output is None:
        return
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    print(output, end="")


def run(command: list[str], deadline: Deadline, *, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=deadline.remaining(command[0]),
        )
    except subprocess.TimeoutExpired as error:
        print_captured(error.stdout)
        print_captured(error.stderr)
        raise RuntimeError(f"command timed out: {command[0]}") from None
    print_captured(result.stdout)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with status {result.returncode}: {command[0]}")
    return result.stdout


def require_executable(path: Path) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"required provider binary is not executable: {path}")


def require_reviewed_license(path: Path) -> None:
    if not path.is_file() or not 1 <= path.stat().st_size <= 256 * 1024:
        raise RuntimeError(f"reviewed license bounds changed: {path}")


def provider_root(pin: ProviderPin, work_root: Path) -> Path:
    name = {
        Provider.SING_BOX: f"sing-box-{pin.version}",
        Provider.SHADOWSOCKS_RUST: f"shadowsocks-rust-{pin.version}",
        Provider.COREDNS: f"coredns-{pin.version}",
        Provider.BIND: f"bind-{pin.version}",
    }[pin.provider]
    return work_root / name


def verify_sing_box(pin: ProviderPin, root: Path, deadline: Deadline) -> None:
    packaged_root = root / f"sing-box-{pin.version}-linux-amd64-glibc"
    binary = packaged_root / "sing-box"
    require_executable(binary)
    require_reviewed_license(packaged_root / "LICENSE")
    output = run([str(binary), "version"], deadline)
    if pin.expected_version not in output or f"Revision: {pin.source_commit}" not in output:
        raise RuntimeError("sing-box version or revision mismatch")


def verify_shadowsocks_rust(pin: ProviderPin, root: Path, deadline: Deadline) -> None:
    for name in ("sslocal", "ssserver"):
        binary = root / name
        require_executable(binary)
        if run([str(binary), "--version"], deadline).strip() != pin.expected_version:
            raise RuntimeError(f"{name} version mismatch")


def verify_coredns_version(pin: ProviderPin, output: str) -> None:
    lines = output.splitlines()
    platform = lines[1].split(", ") if len(lines) == 2 else []
    if (
        len(lines) != 2
        or lines[0] != pin.expected_version
        or len(platform) != 3
        or platform[0] != "linux/amd64"
        or COREDNS_GO_VERSION.fullmatch(platform[1]) is None
        or platform[2] != pin.source_commit[:COREDNS_SHORT_REVISION_LENGTH]
    ):
        raise RuntimeError("CoreDNS version mismatch")


def verify_coredns(pin: ProviderPin, root: Path, work_root: Path, deadline: Deadline) -> None:
    binary = root / "coredns"
    require_executable(binary)
    if pin.license is None:
        raise AssertionError("CoreDNS license pin is required")
    cached_license = work_root / pin.license.asset
    download_atomic(pin.license, cached_license, deadline)
    shutil.copyfile(cached_license, root / "LICENSE")
    verify_artifact(root / "LICENSE", pin.license)
    verify_coredns_version(pin, run([str(binary), "-version"], deadline))


def build_and_verify_bind(pin: ProviderPin, root: Path, deadline: Deadline) -> None:
    require_reviewed_license(root / "LICENSE")
    run(["sudo", "apt-get", "update"], deadline)
    run(
        [
            "sudo",
            "apt-get",
            "install",
            "--no-install-recommends",
            "-y",
            "libcap-dev",
            "libssl-dev",
            "liburcu-dev",
            "libuv1-dev",
            "pkg-config",
        ],
        deadline,
    )
    run(
        [
            "./configure",
            "--disable-doh",
            "--without-json-c",
            "--without-libidn2",
            "--without-libxml2",
        ],
        deadline,
        cwd=root,
    )
    run(["make", "-j2"], deadline, cwd=root)
    binary = root / "bin/dig/dig"
    require_executable(binary)
    if pin.expected_version not in run([str(binary), "-v"], deadline):
        raise RuntimeError("BIND dig version mismatch")


def provision(pin: ProviderPin, work_root: Path) -> None:
    deadline = Deadline.after(DEFINITIONS[pin.provider].timeout_seconds)
    artifact_path = work_root / pin.linux.asset
    root = provider_root(pin, work_root)
    download_atomic(pin.linux, artifact_path, deadline)
    verify_archive_members(pin, artifact_path)
    strip_prefix = f"bind-{pin.version}" if pin.provider is Provider.BIND else None
    extract_atomic(artifact_path, root, strip_prefix)
    if pin.provider is Provider.SING_BOX:
        verify_sing_box(pin, root, deadline)
    elif pin.provider is Provider.SHADOWSOCKS_RUST:
        verify_shadowsocks_rust(pin, root, deadline)
    elif pin.provider is Provider.COREDNS:
        verify_coredns(pin, root, work_root, deadline)
    else:
        build_and_verify_bind(pin, root, deadline)


def provision_document(
    document: Mapping[str, object], work_root: Path
) -> dict[Provider, int]:
    statuses: dict[Provider, int] = {}
    for provider in Provider:
        try:
            pin = parse_provider(document, provider)
            provision(pin, work_root)
            statuses[provider] = 0
        except Exception as error:
            statuses[provider] = 1
            print(f"{provider.value} provider setup failed: {error}", file=sys.stderr)
    return statuses


def write_github_environment(path: Path, statuses: Mapping[Provider, int]) -> None:
    if set(statuses) != set(Provider):
        raise ValueError("provider statuses must cover every provider exactly once")
    rendered: list[str] = []
    for provider in Provider:
        status = statuses[provider]
        if not isinstance(status, int) or isinstance(status, bool) or status < 0:
            raise ValueError(f"{provider.value} provider status must be a non-negative integer")
        rendered.append(f"{GITHUB_STATUS_NAMES[provider]}={status}\n")
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.writelines(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    document = parse_document(args.manifest.read_bytes())
    args.work_root.mkdir(parents=True, exist_ok=True)
    statuses = provision_document(document, args.work_root)
    write_github_environment(args.github_env, statuses)
    rendered = " ".join(f"{provider.value}={statuses[provider]}" for provider in Provider)
    print(f"provider_setup {rendered}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
