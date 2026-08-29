"""Execute the pre-registered UDP worker schedule in one exact checkout."""

from __future__ import annotations

import pathlib
import subprocess
from collections.abc import Callable
from typing import Any

from tools.performance_udp_workers.contract import (
    RUNNER_IMAGE,
    UdpWorkerControlError,
    canonical_bytes,
    evidence_contract,
)
from tools.performance_udp_workers.evidence import load_and_validate_trials, summarize
from tools.performance_udp_workers.pairing import Trial, build_plan, build_trials

Executor = Callable[..., subprocess.CompletedProcess[str]]


def _write_new_json(path: pathlib.Path, value: object) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(canonical_bytes(value))
            stream.write(b"\n")
    except OSError as error:
        raise UdpWorkerControlError(
            f"refused to overwrite qualification output: {path.name}"
        ) from error


def _validate_sha(value: str) -> None:
    if len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise UdpWorkerControlError("candidate SHA must be lowercase and exact")


def trial_command(
    trial: Trial,
    *,
    root: pathlib.Path,
    binary_dir: pathlib.Path,
    candidate_sha: str,
    contract: dict[str, str | int],
) -> list[str]:
    return [
        str(binary_dir / "m4-qualification"),
        "udp-worker-workload",
        "--server-receive-workers",
        str(trial.server_receive_workers),
        "--comparison-receive-workers",
        str(trial.comparison_receive_workers),
        "--session-topology",
        trial.session_topology,
        "--phase",
        trial.phase,
        "--member",
        trial.member,
        "--round",
        str(trial.round),
        "--pair",
        str(trial.pair),
        "--order",
        str(trial.order),
        "--output",
        trial.output,
        "--ready-file",
        trial.ready_file,
        "--repository-root",
        str(root),
        "--binary-dir",
        str(binary_dir),
        "--candidate-sha",
        candidate_sha,
        "--runner-image",
        RUNNER_IMAGE,
        "--producer-source-sha256",
        str(contract["producer_source_sha256"]),
        "--controller-source-sha256",
        str(contract["controller_source_sha256"]),
        "--semantic-recipe-sha256",
        str(contract["semantic_recipe_sha256"]),
        "--evidence-bundle-sha256",
        str(contract["evidence_bundle_sha256"]),
    ]


def run_schedule(
    *,
    root: pathlib.Path,
    binary_dir: pathlib.Path,
    candidate_sha: str,
    execute: Executor = subprocess.run,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_sha(candidate_sha)
    try:
        root = root.resolve(strict=True)
        binary_dir = binary_dir.resolve(strict=True)
    except OSError as error:
        raise UdpWorkerControlError(
            "qualification root or binary directory is unavailable"
        ) from error
    expected_binary_dir = (root / "target/profiling").resolve(strict=True)
    if binary_dir != expected_binary_dir:
        raise UdpWorkerControlError("UDP worker binaries must use target/profiling")
    runner = binary_dir / "m4-qualification"
    client = binary_dir / "ferrum2-client"
    server = binary_dir / "ferrum2-server"
    if any(
        path.is_symlink() or not path.is_file() for path in (runner, client, server)
    ):
        raise UdpWorkerControlError("exact UDP worker binaries are missing")
    contract = evidence_contract(root)
    trials = build_trials()
    plan = build_plan(candidate_sha, contract)
    plan_path = root / "profiles/udp-workers/plan.json"
    _write_new_json(plan_path, plan)
    for trial in trials:
        command = trial_command(
            trial,
            root=root,
            binary_dir=binary_dir,
            candidate_sha=candidate_sha,
            contract=contract,
        )
        try:
            completed = execute(
                command,
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise UdpWorkerControlError(
                f"UDP worker trial {trial.sequence} could not execute"
            ) from error
        if completed.returncode != 0:
            raise UdpWorkerControlError(
                f"UDP worker trial {trial.sequence} failed with exit code {completed.returncode}"
            )
        if "udp_worker_workload status=PASS" not in completed.stdout:
            raise UdpWorkerControlError(
                f"UDP worker trial {trial.sequence} omitted its bounded completion"
            )
    records = load_and_validate_trials(
        root,
        trials,
        candidate_sha=candidate_sha,
        contract=contract,
        runner=runner,
        client=client,
        server=server,
    )
    summary = summarize(records, candidate_sha)
    _write_new_json(root / "profiles/udp-workers/summary.json", summary)
    return plan, summary
