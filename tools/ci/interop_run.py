#!/usr/bin/env python3
"""Run every hosted interop qualification group with one closed result model."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Sequence


NOT_RUN = 125


@dataclass(frozen=True)
class QualificationGroup:
    name: str
    cargo_arguments: tuple[str, ...]
    qualification_arguments: tuple[str, ...]


@dataclass(frozen=True)
class QualificationResult:
    group: QualificationGroup
    build_status: int
    qualification_status: int

    @property
    def status(self) -> int:
        return self.build_status or self.qualification_status


GROUPS = (
    QualificationGroup(
        name="transport",
        cargo_arguments=(),
        qualification_arguments=(),
    ),
    QualificationGroup(
        name="dns",
        cargo_arguments=("--features", "ferrum2-dns/__interop-test-root"),
        qualification_arguments=("--dns-only",),
    ),
)


def execute(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        return subprocess.CompletedProcess(arguments, 126, f"{type(error).__name__}: {error}\n")


def emit_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)


def run_group(group: QualificationGroup, target_root: Path | None) -> QualificationResult:
    if target_root is None or not target_root.is_dir():
        print(f"interop {group.name} build root was not prepared", flush=True)
        return QualificationResult(group, NOT_RUN, NOT_RUN)

    build = execute(
        (
            "cargo",
            "build",
            "--target-dir",
            str(target_root),
            "-p",
            "ferrum2-client",
            "-p",
            "ferrum2-server",
            "-p",
            "ferrum2-m0-harness",
            "--bins",
            "--locked",
            *group.cargo_arguments,
        )
    )
    emit_output(build)
    qualification_status = NOT_RUN
    if build.returncode == 0:
        qualification = execute(
            (
                str(target_root / "debug" / "m0-qualification"),
                *group.qualification_arguments,
            )
        )
        emit_output(qualification)
        qualification_status = qualification.returncode
    result = QualificationResult(group, build.returncode, qualification_status)
    label = "PASS" if result.status == 0 else "FAIL"
    print(
        f"m3_interop_{group.name} status={label} "
        f"build={result.build_status} qualification={result.qualification_status}",
        flush=True,
    )
    return result


def run_all(target_root: Path | None) -> tuple[QualificationResult, ...]:
    return tuple(run_group(group, target_root) for group in GROUPS)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", default="")
    args = parser.parse_args(arguments)
    target_root = Path(args.target_root) if args.target_root else None
    results = run_all(target_root)
    return int(any(result.status != 0 for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
