"""Command-line interface for the GATE-05 qualification controller."""

from __future__ import annotations

import argparse
import json
import pathlib

from tools.performance_udp_workers.contract import (
    UdpWorkerControlError,
    canonical_bytes,
    evidence_contract,
)
from tools.performance_udp_workers.evidence import load_and_validate_trials, summarize
from tools.performance_udp_workers.pairing import build_plan, build_trials
from tools.performance_udp_workers.runner import run_schedule


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.performance_udp_workers")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=pathlib.Path, required=True)
        command.add_argument("--candidate-sha", required=True)
        if name in {"run", "validate"}:
            command.add_argument("--binary-dir", type=pathlib.Path, required=True)
        if name == "plan":
            command.add_argument("--output", type=pathlib.Path, required=True)
        if name == "validate":
            command.add_argument("--summary", type=pathlib.Path, required=True)
    return parser


def _write_new(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
    except OSError as error:
        raise UdpWorkerControlError("refused to overwrite controller output") from error


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        root = arguments.repository.resolve(strict=True)
        if arguments.command == "plan":
            value = build_plan(arguments.candidate_sha, evidence_contract(root))
            _write_new(arguments.output, value)
        elif arguments.command == "run":
            _, value = run_schedule(
                root=root,
                binary_dir=arguments.binary_dir,
                candidate_sha=arguments.candidate_sha,
            )
        else:
            binary_dir = arguments.binary_dir.resolve(strict=True)
            records = load_and_validate_trials(
                root,
                build_trials(),
                candidate_sha=arguments.candidate_sha,
                contract=evidence_contract(root),
                runner=binary_dir / "m4-qualification",
                client=binary_dir / "ferrum2-client",
                server=binary_dir / "ferrum2-server",
            )
            value = summarize(records, arguments.candidate_sha)
            _write_new(arguments.summary, value)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except UdpWorkerControlError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
