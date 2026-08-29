"""CLI and external adapters for the manual AMD Rule performance workflow."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import fields
from typing import TypeVar

from tools.ci import performance_rule_evidence as evidence
from tools.performance_rule.schema import ControlError

MAX_API_BYTES = 1024 * 1024
ReadText = Callable[[pathlib.Path, int], str]
ApiFetch = Callable[[str, str], Mapping[str, object]]
Inputs = TypeVar("Inputs")


def default_read_text(path: pathlib.Path, maximum: int) -> str:
    if path.is_symlink():
        evidence.fail(f"{path.as_posix()} must not be a symbolic link")
    try:
        with path.open("rb") as source:
            encoded = source.read(maximum + 1)
    except FileNotFoundError:
        evidence.fail(f"{path.as_posix()} is missing")
    if not encoded or len(encoded) > maximum:
        evidence.fail(f"{path.as_posix()} exceeds its bounded size")
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise evidence.WorkflowContractError(
            f"{path.as_posix()} is not UTF-8"
        ) from error


def capture_host_identity(
    output: pathlib.Path,
    *,
    environ: Mapping[str, str] = os.environ,
    read_text: ReadText = default_read_text,
    command_probe: evidence.CommandProbe = evidence.default_command_probe,
    cpu_count: Callable[[], int | None] = os.cpu_count,
) -> dict[str, object]:
    cpuinfo = read_text(pathlib.Path("/proc/cpuinfo"), 4 * 1024 * 1024)
    meminfo = read_text(pathlib.Path("/proc/meminfo"), 1024 * 1024)
    vendors = sorted(
        set(re.findall(r"^vendor_id\s*:\s*(.+?)\s*$", cpuinfo, re.MULTILINE))
    )
    models = sorted(
        set(re.findall(r"^model name\s*:\s*(.+?)\s*$", cpuinfo, re.MULTILINE))
    )
    memory_match = re.search(r"^MemTotal:\s*([0-9]+)\s+kB$", meminfo, re.MULTILINE)
    value: dict[str, object] = {
        "schema": evidence.HOST_SCHEMA,
        "cpu_vendor": vendors[0] if len(vendors) == 1 else "UNKNOWN",
        "cpu_model": models[0] if len(models) == 1 else "UNKNOWN",
        "logical_cpus": cpu_count() or 0,
        "memory_kib": int(memory_match.group(1)) if memory_match else 0,
        "kernel": command_probe(("uname", "-srvmo"), pathlib.Path.cwd()),
        "runner_os": environ.get("RUNNER_OS", ""),
        "runner_arch": environ.get("RUNNER_ARCH", ""),
        "runner_environment": environ.get("RUNNER_ENVIRONMENT", ""),
        "image_os": environ.get("ImageOS", ""),
        "image_version": environ.get("ImageVersion", ""),
    }
    evidence.write_json_atomic(output, value)
    evidence.validate_host_document(value)
    return value


def append_github_env(path: pathlib.Path, values: Mapping[str, str]) -> None:
    lines = []
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value or "\r" in value:
            evidence.fail("GitHub environment entry is unsafe")
        lines.append(f"{key}={value}\n")
    with path.open("a", encoding="utf-8", newline="\n") as environment:
        environment.writelines(lines)
        environment.flush()
        os.fsync(environment.fileno())


def prepare_comparison(
    root: pathlib.Path,
    github_env: pathlib.Path,
    *,
    run_id: int,
    current_run_id: int,
    reviewed_by: str,
    reviewed_utc: str,
    feature: str,
) -> None:
    evidence.positive_integer(run_id, "calibration run ID")
    evidence.positive_integer(current_run_id, "current run ID")
    if run_id == current_run_id:
        evidence.fail("comparison cannot consume its own workflow run")
    evidence.validate_review(reviewed_by, reviewed_utc)
    enabled = evidence.FEATURES.get(feature)
    if enabled is None:
        evidence.fail("candidate feature is not supported")
    downloaded = root / "downloaded-calibration"
    comparison = root / "comparison"
    downloaded.mkdir(parents=True, exist_ok=False)
    comparison.joinpath("parent").mkdir(parents=True, exist_ok=False)
    comparison.joinpath("candidate").mkdir(exist_ok=False)
    append_github_env(
        github_env,
        {
            "DOWNLOADED_CALIBRATION": str(downloaded),
            "COMPARISON_EVIDENCE": str(comparison),
            "COMPARISON_HOST_IDENTITY": str(comparison / "host-identity.json"),
            "CANDIDATE_TARGET": str(root / "candidate-target"),
            "CALIBRATED_PARENT": str(
                comparison / "parent" / "ferrum2-rule-qualification"
            ),
            "CANDIDATE_BINARY": str(
                comparison / "candidate" / "ferrum2-rule-qualification"
            ),
            "REVIEWED_CALIBRATION": str(comparison / "reviewed-aa-v3.json"),
            "AB_REPORT": str(comparison / "release-ab-v7.json"),
            "QUALIFICATION_REPORT": str(comparison / "candidate-qualification.json"),
            "CANDIDATE_FEATURES": ",".join(enabled),
            "EXPECTED_FEATURES_JSON": json.dumps(list(enabled), separators=(",", ":")),
        },
    )


def default_api_fetch(url: str, token: str) -> Mapping[str, object]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        contents = response.read(MAX_API_BYTES + 1)
    return evidence.decode_strict_json(
        contents, MAX_API_BYTES, "calibration workflow API response"
    )


def resolve_calibration_run(
    *,
    run_id: int,
    current_run_id: int,
    repository: str,
    expected_sha: str,
    api_url: str,
    token: str,
    github_env: pathlib.Path,
    api_fetch: ApiFetch = default_api_fetch,
) -> tuple[int, str]:
    evidence.positive_integer(run_id, "calibration run ID")
    evidence.positive_integer(current_run_id, "current run ID")
    if run_id == current_run_id:
        evidence.fail("comparison cannot consume its own workflow run")
    evidence.validate_repository(repository)
    evidence.validate_git_sha(expected_sha, "expected SHA")
    if not api_url.startswith("https://") or not token:
        evidence.fail("GitHub API identity is unavailable")
    source_run = api_fetch(f"{api_url}/repos/{repository}/actions/runs/{run_id}", token)
    attempt = source_run.get("run_attempt")
    if (
        source_run.get("id") != run_id
        or source_run.get("event") != "workflow_dispatch"
        or source_run.get("status") != "completed"
        or source_run.get("conclusion") != "success"
        or source_run.get("head_sha") != expected_sha
        or source_run.get("path") not in evidence.APPROVED_RUN_WORKFLOW_PATHS
        or type(attempt) is not int
        or attempt <= 0
        or not isinstance(source_run.get("repository"), dict)
        or source_run["repository"].get("full_name") != repository
    ):
        evidence.fail("calibration workflow run identity is not approved")
    artifact_name = f"performance-rule-calibration-{run_id}-{attempt}"
    append_github_env(
        github_env,
        {
            "CALIBRATION_RUN_ATTEMPT": str(attempt),
            "CALIBRATION_ARTIFACT_NAME": artifact_name,
        },
    )
    return attempt, artifact_name


def _positive_argument(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("must be a positive integer")
    return int(value)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    host = commands.add_parser("capture-host")
    host.add_argument("--output", required=True, type=pathlib.Path)

    calibration = commands.add_parser("calibration-manifest")
    for name in (
        "evidence",
        "parent",
        "aa-report",
        "host-identity",
        "workspace",
        "output",
    ):
        calibration.add_argument(f"--{name}", required=True, type=pathlib.Path)
    calibration.add_argument("--expected-sha", required=True)
    calibration.add_argument("--repository", required=True)
    calibration.add_argument("--run-id", required=True, type=_positive_argument)
    calibration.add_argument("--run-attempt", required=True, type=_positive_argument)

    prepare = commands.add_parser("prepare-comparison")
    prepare.add_argument("--root", required=True, type=pathlib.Path)
    prepare.add_argument("--github-env", required=True, type=pathlib.Path)
    prepare.add_argument("--run-id", required=True, type=_positive_argument)
    prepare.add_argument("--current-run-id", required=True, type=_positive_argument)
    prepare.add_argument("--reviewed-by", required=True)
    prepare.add_argument("--reviewed-utc", required=True)
    prepare.add_argument("--feature", required=True, choices=tuple(evidence.FEATURES))

    resolve = commands.add_parser("resolve-calibration")
    resolve.add_argument("--run-id", required=True, type=_positive_argument)
    resolve.add_argument("--current-run-id", required=True, type=_positive_argument)
    resolve.add_argument("--repository", required=True)
    resolve.add_argument("--expected-sha", required=True)
    resolve.add_argument("--api-url", required=True)
    resolve.add_argument("--github-env", required=True, type=pathlib.Path)

    verify = commands.add_parser("verify-calibration")
    for name in ("artifact", "comparison-host", "workspace"):
        verify.add_argument(f"--{name}", required=True, type=pathlib.Path)
    verify.add_argument("--expected-sha", required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--run-id", required=True, type=_positive_argument)
    verify.add_argument("--run-attempt", required=True, type=_positive_argument)

    comparison = commands.add_parser("validate-comparison")
    for name in (
        "evidence",
        "workspace",
        "parent",
        "candidate",
        "calibration",
        "ab-report",
        "qualification-report",
        "output",
    ):
        comparison.add_argument(f"--{name}", required=True, type=pathlib.Path)
    comparison.add_argument("--reviewed-by", required=True)
    comparison.add_argument("--reviewed-utc", required=True)
    comparison.add_argument(
        "--feature", required=True, choices=tuple(evidence.FEATURES)
    )
    comparison.add_argument("--repository", required=True)
    comparison.add_argument("--expected-sha", required=True)
    comparison.add_argument(
        "--comparison-run-id", required=True, type=_positive_argument
    )
    comparison.add_argument(
        "--comparison-run-attempt", required=True, type=_positive_argument
    )
    comparison.add_argument(
        "--calibration-run-id", required=True, type=_positive_argument
    )
    return parser.parse_args(arguments)


def _inputs_from_arguments(
    input_type: type[Inputs], args: argparse.Namespace
) -> Inputs:
    return input_type(
        **{field.name: getattr(args, field.name) for field in fields(input_type)}
    )


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        args = parse_arguments(arguments)
        if args.command == "capture-host":
            capture_host_identity(args.output)
        elif args.command == "calibration-manifest":
            evidence.build_calibration_manifest(
                _inputs_from_arguments(evidence.CalibrationManifestInputs, args)
            )
        elif args.command == "prepare-comparison":
            prepare_comparison(
                args.root,
                args.github_env,
                run_id=args.run_id,
                current_run_id=args.current_run_id,
                reviewed_by=args.reviewed_by,
                reviewed_utc=args.reviewed_utc,
                feature=args.feature,
            )
        elif args.command == "resolve-calibration":
            resolve_calibration_run(
                run_id=args.run_id,
                current_run_id=args.current_run_id,
                repository=args.repository,
                expected_sha=args.expected_sha,
                api_url=args.api_url,
                token=os.environ.get("GH_TOKEN", ""),
                github_env=args.github_env,
            )
        elif args.command == "verify-calibration":
            evidence.verify_calibration_artifact(
                _inputs_from_arguments(evidence.CalibrationVerificationInputs, args)
            )
        elif args.command == "validate-comparison":
            evidence.validate_comparison(
                _inputs_from_arguments(evidence.ComparisonValidationInputs, args)
            )
        else:
            evidence.fail("unknown workflow command")
    except (
        evidence.WorkflowContractError,
        ControlError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"performance rule workflow control failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
