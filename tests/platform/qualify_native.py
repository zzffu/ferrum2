#!/usr/bin/env python3
"""Run the portable native contract locally or emit hosted qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from native_contract import (
    BinarySpec,
    QualificationError,
    assert_native_contract,
    binary_specs,
    bounded_run,
    require,
)


@dataclass(frozen=True)
class NativeProfile:
    target: str
    runner_os: str


@dataclass(frozen=True)
class HostedContext:
    profile: str
    target: str
    sha: str
    run_id: str
    run_attempt: str
    runner: str
    image: str
    toolchain: str


NATIVE_PROFILES = {
    "windows-msvc": NativeProfile("x86_64-pc-windows-msvc", "Windows"),
    "linux-gnu": NativeProfile("x86_64-unknown-linux-gnu", "Linux"),
    "linux-musl": NativeProfile("x86_64-unknown-linux-musl", "Linux"),
}


def selected_profile(name: str, target: str) -> NativeProfile:
    require(name in NATIVE_PROFILES, "unknown-platform-profile")
    selected = NATIVE_PROFILES[name]
    require(target == selected.target, "profile-target-mismatch")
    return selected


def require_native_host(profile_spec: NativeProfile) -> None:
    require(platform.machine().lower() in {"amd64", "x86_64"}, "non-native-architecture")
    if profile_spec.runner_os == "Windows":
        require(sys.platform == "win32", "non-native-operating-system")
    else:
        require(sys.platform.startswith("linux"), "non-native-operating-system")


def environment_field(value: str | None) -> str:
    require(value is not None and value != "", "missing-runner-evidence")
    return re.sub(r"[^A-Za-z0-9_.:/-]", "_", value)


def hosted_context(
    arguments: argparse.Namespace, profile_spec: NativeProfile
) -> HostedContext:
    require(os.environ.get("GITHUB_ACTIONS") == "true", "not-github-actions")
    require(os.environ.get("RUNNER_OS") == profile_spec.runner_os, "wrong-runner-os")
    require(os.environ.get("RUNNER_ARCH") == "X64", "wrong-runner-architecture")

    sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-fA-F]{40}", sha) is not None, "invalid-github-sha")
    require(run_id.isdecimal() and int(run_id) > 0, "invalid-run-id")
    require(run_attempt.isdecimal() and int(run_attempt) > 0, "invalid-run-attempt")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    ).stdout.decode("ascii").strip()
    require(head == sha, "checkout-sha-mismatch")
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    ).stdout
    require(status == b"", "checkout-not-clean")

    runner = environment_field(os.environ.get("RUNNER_NAME"))
    image_os = environment_field(os.environ.get("ImageOS"))
    image_version = environment_field(os.environ.get("ImageVersion"))
    toolchain_output = bounded_run(["rustc", "+1.97.1", "-Vv"], timeout=10)
    require(toolchain_output.returncode == 0, "missing-rust-toolchain")
    release = re.search(rb"(?m)^release: ([^\r\n]+)$", toolchain_output.stdout)
    require(release is not None and release.group(1) == b"1.97.1", "wrong-rust-toolchain")
    return HostedContext(
        profile=arguments.profile,
        target=arguments.target,
        sha=sha.lower(),
        run_id=run_id,
        run_attempt=run_attempt,
        runner=runner,
        image=f"{image_os}/{image_version}",
        toolchain=release.group(1).decode("ascii"),
    )


def artifact_line(context: HostedContext, spec: BinarySpec) -> str:
    digest = hashlib.sha256(spec.path.read_bytes()).hexdigest()
    size = spec.path.stat().st_size
    require(size > 0 and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "artifact-identity")
    return (
        "m3_release_artifact status=PASS "
        f"profile={context.profile} target={context.target} binary={spec.name} "
        f"size={size} sha256={digest} toolchain={context.toolchain} "
        f"runner={context.runner} image={context.image} sha={context.sha} "
        f"run_id={context.run_id} run_attempt={context.run_attempt}"
    )


def lifecycle_line(context: HostedContext, spec: BinarySpec) -> str:
    return (
        "m3_native_lifecycle_completion status=PASS "
        f"profile={context.profile} target={context.target} binary={spec.name} "
        "help=PASS version=PASS valid_config=PASS invalid_config=PASS "
        "tagged_config=PASS routed_config=PASS route_tcp=PASS route_udp=PASS "
        "startup_rollback=PASS tagged_second_bind_rollback=PASS "
        "tagged_rebind=PASS graceful_signal=PASS forced_signal=PASS "
        "bounded_exit=PASS rebind=PASS cleanup=PASS "
        f"sha={context.sha} run_id={context.run_id} run_attempt={context.run_attempt}"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument(
        "--local-contract",
        action="store_true",
        help="run native behavior checks locally without emitting hosted CI evidence",
    )
    return parser.parse_args()


def require_local_contract_environment() -> None:
    require(os.environ.get("GITHUB_ACTIONS") != "true", "local-contract-in-github-actions")


def run_local(arguments: argparse.Namespace, specs: tuple[BinarySpec, BinarySpec]) -> int:
    require_local_contract_environment()
    assert_native_contract(specs)
    print(
        "m3_local_native_contract status=PASS "
        f"profile={arguments.profile} target={arguments.target}",
        flush=True,
    )
    return 0


def run_hosted(
    specs: tuple[BinarySpec, BinarySpec], context: HostedContext
) -> int:
    assert_native_contract(specs)
    lines = [
        line
        for spec in specs
        for line in (artifact_line(context, spec), lifecycle_line(context, spec))
    ]
    require(len(lines) == 4 and len(set(lines)) == 4, "duplicate-platform-evidence")
    for line in lines:
        print(line, flush=True)
    return 0


def main() -> int:
    try:
        arguments = parse_arguments()
        profile_spec = selected_profile(arguments.profile, arguments.target)
        require_native_host(profile_spec)
        root = Path.cwd().resolve()
        specs = binary_specs(
            root=root,
            target=arguments.target,
            client=Path(arguments.client),
            server=Path(arguments.server),
        )
        if arguments.local_contract:
            return run_local(arguments, specs)
        return run_hosted(specs, hosted_context(arguments, profile_spec))
    except (OSError, QualificationError, subprocess.SubprocessError) as error:
        root = error.args[0] if isinstance(error, QualificationError) else type(error).__name__
        print(f"m3_platform_failure status=FAIL canonical_root={root}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
