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
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .interop_manifest import (
    ArchiveStrategy,
    Artifact,
    ProviderPin,
    SupplementalArtifactContract,
    parse_document,
    parse_provider,
)

COREDNS_GO_VERSION = re.compile(r"go[1-9][0-9]*\.[0-9]+\.[0-9]+\Z")
COREDNS_SHORT_REVISION_LENGTH = 7

def parse_manifest(contents: bytes) -> tuple[ProviderPin, ...]:
    document = parse_document(contents)
    return tuple(parse_provider(document, spec) for spec in PROVIDER_SPECS)


# Download, archive, filesystem, and process effects.

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
            print(
                f"download attempt {attempt}/3 failed for {artifact.asset}: {error}",
                file=sys.stderr,
            )
    raise RuntimeError(f"download failed for {artifact.asset}") from last_error


def archive_names(path: Path) -> tuple[str, ...]:
    with tarfile.open(path, "r:*") as archive:
        return tuple(member.name for member in archive.getmembers())


def render_version_template(template: str, pin: ProviderPin) -> str:
    return template.format(version=pin.version)


def expected_archive_names(
    spec: "ProviderSpec", pin: ProviderPin
) -> tuple[str, ...] | None:
    templates = spec.archive.exact_member_templates
    if templates is None:
        return None
    return tuple(render_version_template(template, pin) for template in templates)


def archive_tree_root(spec: "ProviderSpec", pin: ProviderPin) -> str | None:
    template = spec.archive.rooted_tree_template
    return render_version_template(template, pin) if template is not None else None


def verify_archive_members(spec: "ProviderSpec", pin: ProviderPin, path: Path) -> None:
    names = archive_names(path)
    expected = expected_archive_names(spec, pin)
    if expected is not None and names != expected:
        raise RuntimeError(f"{pin.provider_id} archive members changed: {names!r}")
    root = archive_tree_root(spec, pin)
    if root is not None:
        if not names or names[0].rstrip("/") != root:
            raise RuntimeError(f"{pin.provider_id} archive root changed")
        if any(
            name.rstrip("/") != root and not name.startswith(root + "/")
            for name in names
        ):
            raise RuntimeError(
                f"{pin.provider_id} archive contains a member outside its pinned root"
            )


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


def provider_root(spec: "ProviderSpec", pin: ProviderPin, work_root: Path) -> Path:
    return work_root / render_version_template(spec.root_template, pin)


def verify_sing_box(
    pin: ProviderPin, root: Path, _work_root: Path, deadline: Deadline
) -> None:
    packaged_root = root / f"sing-box-{pin.version}-linux-amd64-glibc"
    binary = packaged_root / "sing-box"
    require_executable(binary)
    require_reviewed_license(packaged_root / "LICENSE")
    output = run([str(binary), "version"], deadline)
    if pin.expected_version not in output or f"Revision: {pin.source_commit}" not in output:
        raise RuntimeError("sing-box version or revision mismatch")


def verify_shadowsocks_rust(
    pin: ProviderPin, root: Path, _work_root: Path, deadline: Deadline
) -> None:
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


def verify_bind(
    pin: ProviderPin, root: Path, _work_root: Path, deadline: Deadline
) -> None:
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


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    timeout_seconds: int
    github_status_name: str
    license_marker: str
    root_template: str
    archive: ArchiveStrategy
    verifier: Callable[[ProviderPin, Path, Path, Deadline], None]
    supplemental_artifact: SupplementalArtifactContract | None = None


PROVIDER_SPECS = (
    ProviderSpec(
        provider_id="sing_box",
        timeout_seconds=5 * 60,
        github_status_name="M2_SING_BOX_SETUP_STATUS",
        license_marker="NOASSERTION",
        root_template="sing-box-{version}",
        archive=ArchiveStrategy(
            exact_member_templates=(
                "sing-box-{version}-linux-amd64-glibc",
                "sing-box-{version}-linux-amd64-glibc/LICENSE",
                "sing-box-{version}-linux-amd64-glibc/sing-box",
            )
        ),
        verifier=verify_sing_box,
    ),
    ProviderSpec(
        provider_id="shadowsocks_rust",
        timeout_seconds=5 * 60,
        github_status_name="M2_SHADOWSOCKS_RUST_SETUP_STATUS",
        license_marker="MIT",
        root_template="shadowsocks-rust-{version}",
        archive=ArchiveStrategy(
            exact_member_templates=(
                "sslocal",
                "ssserver",
                "ssurl",
                "ssmanager",
                "ssservice",
            )
        ),
        verifier=verify_shadowsocks_rust,
    ),
    ProviderSpec(
        provider_id="coredns",
        timeout_seconds=5 * 60,
        github_status_name="M12_COREDNS_SETUP_STATUS",
        license_marker="Apache-2.0",
        root_template="coredns-{version}",
        archive=ArchiveStrategy(exact_member_templates=("coredns",)),
        verifier=verify_coredns,
        supplemental_artifact=SupplementalArtifactContract(
            asset_template="coredns-{version}-LICENSE",
            url_field="license_url",
            size_field="license_size",
            sha256_field="license_sha256",
            require_source_commit_in_url=True,
        ),
    ),
    ProviderSpec(
        provider_id="bind",
        timeout_seconds=15 * 60,
        github_status_name="M12_BIND_SETUP_STATUS",
        license_marker="MPL-2.0",
        root_template="bind-{version}",
        archive=ArchiveStrategy(
            rooted_tree_template="bind-{version}",
            strip_root=True,
        ),
        verifier=verify_bind,
    ),
)


def validate_provider_specs(specs: tuple[ProviderSpec, ...]) -> None:
    provider_ids = [spec.provider_id for spec in specs]
    github_status_names = [spec.github_status_name for spec in specs]
    if len(set(provider_ids)) != len(provider_ids):
        raise AssertionError("provider IDs must be unique")
    if len(set(github_status_names)) != len(github_status_names):
        raise AssertionError("provider GitHub status names must be unique")
    for spec in specs:
        archive = spec.archive
        if (archive.exact_member_templates is None) == (
            archive.rooted_tree_template is None
        ):
            raise AssertionError(
                f"{spec.provider_id} must select exactly one archive member strategy"
            )
        if archive.strip_root and archive.rooted_tree_template is None:
            raise AssertionError(
                f"{spec.provider_id} cannot strip an archive without a rooted tree"
            )


validate_provider_specs(PROVIDER_SPECS)


# Ordered orchestration. Every provider dispatches through its registered strategy.

def provision(spec: ProviderSpec, pin: ProviderPin, work_root: Path) -> None:
    if pin.provider_id != spec.provider_id:
        raise ValueError("provider pin and strategy do not match")
    deadline = Deadline.after(spec.timeout_seconds)
    artifact_path = work_root / pin.linux.asset
    root = provider_root(spec, pin, work_root)
    download_atomic(pin.linux, artifact_path, deadline)
    verify_archive_members(spec, pin, artifact_path)
    strip_prefix = archive_tree_root(spec, pin) if spec.archive.strip_root else None
    extract_atomic(artifact_path, root, strip_prefix)
    spec.verifier(pin, root, work_root, deadline)


def provision_document(
    document: Mapping[str, object], work_root: Path
) -> dict[str, int]:
    statuses: dict[str, int] = {}
    for spec in PROVIDER_SPECS:
        try:
            pin = parse_provider(document, spec)
            provision(spec, pin, work_root)
            statuses[spec.provider_id] = 0
        except Exception as error:
            statuses[spec.provider_id] = 1
            print(f"{spec.provider_id} provider setup failed: {error}", file=sys.stderr)
    return statuses


def write_github_environment(path: Path, statuses: Mapping[str, int]) -> None:
    expected_provider_ids = {spec.provider_id for spec in PROVIDER_SPECS}
    if set(statuses) != expected_provider_ids:
        raise ValueError("provider statuses must cover every provider exactly once")
    rendered: list[str] = []
    for spec in PROVIDER_SPECS:
        status = statuses[spec.provider_id]
        if not isinstance(status, int) or isinstance(status, bool) or status < 0:
            raise ValueError(
                f"{spec.provider_id} provider status must be a non-negative integer"
            )
        rendered.append(f"{spec.github_status_name}={status}\n")
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
    rendered = " ".join(
        f"{spec.provider_id}={statuses[spec.provider_id]}" for spec in PROVIDER_SPECS
    )
    print(f"provider_setup {rendered}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
