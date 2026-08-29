"""Offline-testable workflow identity and artifact closure for GATE-05."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
from typing import Any

from tools.performance_udp_workers.contract import (
    AUTHORITY,
    MANIFEST_SCHEMA_VERSION,
    RUNNER_IMAGE,
    UdpWorkerControlError,
    canonical_bytes,
    evidence_contract,
    require_exact_keys,
)
from tools.performance_udp_workers.evidence import (
    load_and_validate_trials,
    load_json,
    summarize,
)
from tools.performance_udp_workers.pairing import build_plan, build_trials


def _write_new(path: pathlib.Path, value: object) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
    except OSError as error:
        raise UdpWorkerControlError("refused to overwrite workflow evidence") from error


def _first_line(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise UdpWorkerControlError(
            f"host identity probe failed: {command[0]}"
        ) from error
    lines = completed.stdout.splitlines()
    if not lines or not lines[0] or len(lines[0]) > 1024:
        raise UdpWorkerControlError(f"host identity probe is malformed: {command[0]}")
    return lines[0]


def capture_host() -> dict[str, object]:
    try:
        cpuinfo = pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8")
        meminfo = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError as error:
        raise UdpWorkerControlError("Linux host identity is unavailable") from error
    vendors = {
        line.split(":", 1)[1].strip()
        for line in cpuinfo.splitlines()
        if line.startswith("vendor_id") and ":" in line
    }
    models = {
        line.split(":", 1)[1].strip()
        for line in cpuinfo.splitlines()
        if line.startswith("model name") and ":" in line
    }
    memory = [
        line.split()[1] for line in meminfo.splitlines() if line.startswith("MemTotal:")
    ]
    cpu_count = os.cpu_count()
    if (
        vendors != {"AuthenticAMD"}
        or len(models) != 1
        or not next(iter(models))
        or len(memory) != 1
        or not memory[0].isdigit()
        or type(cpu_count) is not int
        or cpu_count <= 0
    ):
        raise UdpWorkerControlError(
            "workflow requires one exact AuthenticAMD host identity"
        )
    return {
        "schema_version": 1,
        "kind": "ferrum2_udp_worker_host",
        "runner_image": RUNNER_IMAGE,
        "runner_os": os.environ.get("RUNNER_OS", "Linux"),
        "runner_arch": os.environ.get("RUNNER_ARCH", "X64"),
        "cpu_vendor": "AuthenticAMD",
        "cpu_model": next(iter(models)),
        "cpu_count": cpu_count,
        "memory_kib": int(memory[0]),
        "kernel": _first_line(["uname", "-srvmo"]),
        "rustc": _first_line(["rustc", "+1.97.1", "--version"]),
    }


def validate_checkout(root: pathlib.Path, candidate_sha: str) -> str:
    if len(candidate_sha) != 40 or any(
        character not in "0123456789abcdef" for character in candidate_sha
    ):
        raise UdpWorkerControlError("workflow candidate SHA is malformed")

    def git(*arguments: str) -> str:
        return _first_line(["git", "-C", str(root), *arguments])

    if git("rev-parse", "HEAD") != candidate_sha:
        raise UdpWorkerControlError(
            "workflow checkout HEAD does not match candidate SHA"
        )
    tree = git("rev-parse", "HEAD^{tree}")
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise UdpWorkerControlError(
            "workflow checkout status is unavailable"
        ) from error
    if status:
        raise UdpWorkerControlError("workflow checkout is dirty")
    return tree


def build_manifest(
    *,
    root: pathlib.Path,
    binary_dir: pathlib.Path,
    candidate_sha: str,
    repository: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, object]:
    tree = validate_checkout(root, candidate_sha)
    repository_parts = repository.split("/")
    if (
        len(repository_parts) != 2
        or any(
            not part
            or any(
                character
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
                for character in part
            )
            for part in repository_parts
        )
        or not run_id.isdigit()
        or int(run_id) <= 0
        or not run_attempt.isdigit()
        or int(run_attempt) <= 0
    ):
        raise UdpWorkerControlError("workflow run identity is malformed")
    contract = evidence_contract(root)
    trials = build_trials()
    records = load_and_validate_trials(
        root,
        trials,
        candidate_sha=candidate_sha,
        contract=contract,
        runner=binary_dir / "m4-qualification",
        client=binary_dir / "ferrum2-client",
        server=binary_dir / "ferrum2-server",
    )
    if records and records[0]["identity"]["tree"] != tree:
        raise UdpWorkerControlError(
            "UDP worker raw tree does not match the exact checkout"
        )
    host = load_json(root / "profiles/udp-workers/host.json", "UDP worker host")
    require_exact_keys(
        host,
        {
            "schema_version",
            "kind",
            "runner_image",
            "runner_os",
            "runner_arch",
            "cpu_vendor",
            "cpu_model",
            "cpu_count",
            "memory_kib",
            "kernel",
            "rustc",
        },
        "UDP worker host",
    )
    if (
        host["schema_version"] != 1
        or host["kind"] != "ferrum2_udp_worker_host"
        or host["runner_image"] != RUNNER_IMAGE
        or host["runner_os"] != "Linux"
        or host["runner_arch"] != "X64"
        or host["cpu_vendor"] != "AuthenticAMD"
    ):
        raise UdpWorkerControlError(
            "UDP worker host identity is outside the closed runner"
        )
    if records:
        trial_environment = records[0]["identity"]["environment"]
        for key in (
            "runner_image",
            "cpu_vendor",
            "cpu_model",
            "cpu_count",
            "memory_kib",
            "kernel",
            "rustc",
        ):
            if host[key] != trial_environment[key]:
                raise UdpWorkerControlError(
                    "UDP worker host and trial identities differ"
                )
    expected_plan = build_plan(candidate_sha, contract)
    observed_plan = load_json(
        root / "profiles/udp-workers/plan.json", "UDP worker plan"
    )
    if observed_plan != expected_plan:
        raise UdpWorkerControlError("UDP worker plan does not recompute")
    expected_summary = summarize(records, candidate_sha)
    observed_summary = load_json(
        root / "profiles/udp-workers/summary.json", "UDP worker summary"
    )
    if observed_summary != expected_summary:
        raise UdpWorkerControlError("UDP worker summary does not recompute")
    relative_files = [
        "profiles/udp-workers/host.json",
        "profiles/udp-workers/plan.json",
        *[trial.output for trial in trials],
        "profiles/udp-workers/summary.json",
    ]
    entries: list[dict[str, object]] = []
    for relative in relative_files:
        path = root / relative
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise UdpWorkerControlError(
                "UDP worker artifact set is incomplete"
            ) from error
        if path.is_symlink() or not path.is_file():
            raise UdpWorkerControlError("UDP worker artifact contains an invalid file")
        entries.append(
            {
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    evidence_root = root / "profiles/udp-workers"
    observed_files = {
        path.relative_to(root).as_posix()
        for path in evidence_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if observed_files != set(relative_files):
        raise UdpWorkerControlError(
            "UDP worker artifact directory contains an extra file"
        )
    artifact_set_sha256 = hashlib.sha256(canonical_bytes(entries)).hexdigest()
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "ferrum2_udp_worker_manifest",
        "repository": repository,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
        "candidate_sha": candidate_sha,
        "tree": tree,
        "trial_count": len(trials),
        "evidence_contract": contract,
        "files": entries,
        "artifact_set_sha256": artifact_set_sha256,
        "manifest_self": {
            "path": "profiles/udp-workers/manifest.json",
            "hash_scope": "excluded_self_reference",
        },
        "decision": "DEFERRED",
        "default_receive_workers": 1,
        "default_changed": False,
        "authority": dict(AUTHORITY),
        "retention": {
            "github_artifact_days": 90,
            "durable_provenance": False,
        },
        "status": "PASS",
    }


def validate_manifest(manifest: object) -> None:
    manifest = require_exact_keys(
        manifest,
        {
            "schema_version",
            "kind",
            "repository",
            "run_id",
            "run_attempt",
            "candidate_sha",
            "tree",
            "trial_count",
            "evidence_contract",
            "files",
            "artifact_set_sha256",
            "manifest_self",
            "decision",
            "default_receive_workers",
            "default_changed",
            "authority",
            "retention",
            "status",
        },
        "UDP worker manifest",
    )
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["kind"] != "ferrum2_udp_worker_manifest"
        or manifest["decision"] != "DEFERRED"
        or manifest["default_receive_workers"] != 1
        or manifest["default_changed"] is not False
        or manifest["authority"] != AUTHORITY
        or manifest["retention"]
        != {"github_artifact_days": 90, "durable_provenance": False}
        or manifest["manifest_self"]
        != {
            "path": "profiles/udp-workers/manifest.json",
            "hash_scope": "excluded_self_reference",
        }
        or manifest["status"] != "PASS"
    ):
        raise UdpWorkerControlError(
            "UDP worker manifest broadened its provisional authority"
        )
    if (
        not isinstance(manifest["repository"], str)
        or len(manifest["repository"].split("/")) != 2
        or any(not part for part in manifest["repository"].split("/"))
        or type(manifest["run_id"]) is not int
        or manifest["run_id"] <= 0
        or type(manifest["run_attempt"]) is not int
        or manifest["run_attempt"] <= 0
        or manifest["trial_count"] != 120
    ):
        raise UdpWorkerControlError("UDP worker manifest run identity is malformed")
    for field in ("candidate_sha", "tree"):
        value = manifest[field]
        if (
            not isinstance(value, str)
            or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise UdpWorkerControlError(
                "UDP worker manifest source identity is malformed"
            )
    contract = require_exact_keys(
        manifest["evidence_contract"],
        {
            "schema_version",
            "trial_schema_version",
            "structural_schema_version",
            "runner_image",
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
            "evidence_bundle_sha256",
        },
        "UDP worker manifest evidence contract",
    )
    if (
        contract["schema_version"] != 1
        or contract["trial_schema_version"] != 1
        or contract["structural_schema_version"] != 7
        or contract["runner_image"] != RUNNER_IMAGE
    ):
        raise UdpWorkerControlError("UDP worker manifest evidence contract changed")
    for field in (
        "producer_source_sha256",
        "controller_source_sha256",
        "semantic_recipe_sha256",
        "evidence_bundle_sha256",
    ):
        value = contract[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise UdpWorkerControlError(
                "UDP worker manifest evidence digest is malformed"
            )
    bundle = {
        key: contract[key]
        for key in (
            "schema_version",
            "trial_schema_version",
            "structural_schema_version",
            "runner_image",
            "producer_source_sha256",
            "controller_source_sha256",
            "semantic_recipe_sha256",
        )
    }
    if (
        contract["evidence_bundle_sha256"]
        != hashlib.sha256(canonical_bytes(bundle)).hexdigest()
    ):
        raise UdpWorkerControlError(
            "UDP worker evidence bundle digest does not recompute"
        )
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != manifest["trial_count"] + 3:
        raise UdpWorkerControlError("UDP worker manifest file set is incomplete")
    paths: list[str] = []
    for entry in files:
        entry = require_exact_keys(
            entry, {"path", "bytes", "sha256"}, "UDP worker manifest file"
        )
        if (
            not isinstance(entry["path"], str)
            or not entry["path"].startswith("profiles/udp-workers/")
            or type(entry["bytes"]) is not int
            or entry["bytes"] <= 0
            or not isinstance(entry["sha256"], str)
            or len(entry["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in entry["sha256"])
        ):
            raise UdpWorkerControlError(
                "UDP worker manifest file identity is malformed"
            )
        paths.append(entry["path"])
    if len(paths) != len(set(paths)):
        raise UdpWorkerControlError("UDP worker manifest file paths are duplicated")
    expected_paths = [
        "profiles/udp-workers/host.json",
        "profiles/udp-workers/plan.json",
        *[trial.output for trial in build_trials()],
        "profiles/udp-workers/summary.json",
    ]
    if paths != expected_paths:
        raise UdpWorkerControlError("UDP worker manifest file order or closure changed")
    observed_digest = hashlib.sha256(canonical_bytes(files)).hexdigest()
    if manifest["artifact_set_sha256"] != observed_digest:
        raise UdpWorkerControlError("UDP worker manifest digest does not recompute")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.ci.performance_udp_worker_workflow"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    host = commands.add_parser("capture-host")
    host.add_argument("--output", type=pathlib.Path, required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--workspace", type=pathlib.Path, required=True)
    manifest.add_argument("--binary-dir", type=pathlib.Path, required=True)
    manifest.add_argument("--candidate-sha", required=True)
    manifest.add_argument("--repository", required=True)
    manifest.add_argument("--run-id", required=True)
    manifest.add_argument("--run-attempt", required=True)
    manifest.add_argument("--output", type=pathlib.Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "capture-host":
            value = capture_host()
        else:
            value = build_manifest(
                root=arguments.workspace.resolve(strict=True),
                binary_dir=arguments.binary_dir.resolve(strict=True),
                candidate_sha=arguments.candidate_sha,
                repository=arguments.repository,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
            )
        _write_new(arguments.output, value)
        if arguments.command == "manifest":
            persisted = load_json(arguments.output, "UDP worker persisted manifest")
            if persisted != value:
                raise UdpWorkerControlError("UDP worker manifest readback changed")
            validate_manifest(persisted)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except UdpWorkerControlError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
