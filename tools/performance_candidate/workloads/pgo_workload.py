"""Reviewed PGO workload driver; never imported by ordinary controller tests."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile

from tools.ci.performance_build_workflow import materialize_profile_artifacts
from tools.performance_candidate.linux.evidence_contract import (
    catalog_evidence_contract,
)

SCENARIOS = {
    "tcp-request": "tcp-request-1k",
    "tcp-bulk": "tcp-bulk",
    "udp-small": "udp-small-high",
    "udp-mtu": "udp-mtu-1200",
    "dns": "dns-udp-concurrency",
}


def _git(repository: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    value = result.stdout.strip().splitlines()
    if len(value) != 1 or not value[0]:
        raise RuntimeError("Git identity probe did not return one value")
    return value[0]


def _run_m4(
    *,
    category: str,
    runner: pathlib.Path,
    client: pathlib.Path,
    server: pathlib.Path,
    repository: pathlib.Path,
) -> None:
    scenario = SCENARIOS[category]
    binary_directories = {path.resolve().parent for path in (runner, client, server)}
    if len(binary_directories) != 1:
        raise RuntimeError("PGO M4 artifacts must share one build directory")
    binary_directory = binary_directories.pop()
    if (
        runner.resolve() != binary_directory / "m4-qualification"
        or client.resolve() != binary_directory / "ferrum2-client"
        or server.resolve() != binary_directory / "ferrum2-server"
    ):
        raise RuntimeError("PGO M4 artifact roles are invalid")
    profile_binary_directory = materialize_profile_artifacts(
        source_dir=binary_directory,
        repository=repository,
    )
    source_sha = _git(repository, "rev-parse", "HEAD")
    contract = catalog_evidence_contract(
        scenario,
        warmup_seconds=1,
        active_seconds=15,
        pair_schedule="abba-six-pairs",
    )
    profiles = repository / "profiles"
    if profiles.is_symlink():
        raise RuntimeError("PGO profile root must not be a symlink")
    profiles.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ferrum2-pgo-workload-", dir=profiles
    ) as temporary:
        root = pathlib.Path(temporary)
        relative_root = root.relative_to(repository)
        command = [
            str(profile_binary_directory / "m4-qualification"),
            "profile-workload",
            "--scenario",
            scenario,
            "--warmup-seconds",
            "1",
            "--active-seconds",
            "15",
            "--repository-root",
            str(repository),
            "--binary-dir",
            str(profile_binary_directory),
            "--ready-file",
            str(relative_root / "ready"),
            "--output",
            str(relative_root / "trial.jsonl"),
            "--parent-sha",
            source_sha,
            "--candidate-sha",
            source_sha,
            "--member",
            "parent",
            "--pair",
            "1",
            "--order",
            "1",
            "--build-profile",
            "current",
            "--unit",
            contract["unit"],
            "--runner-image",
            contract["runner_image"],
            "--producer-source-sha256",
            contract["producer_source_sha256"],
            "--controller-source-sha256",
            contract["controller_source_sha256"],
            "--semantic-recipe-sha256",
            contract["semantic_recipe_sha256"],
            "--evidence-bundle-sha256",
            contract["evidence_bundle_sha256"],
        ]
        subprocess.run(command, cwd=repository, check=True, timeout=240)
        if not (root / "trial.jsonl").is_file() or (root / "ready").exists():
            raise RuntimeError(
                "PGO M4 workload did not complete its evidence lifecycle"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", required=True, choices=(*SCENARIOS, "rule"))
    parser.add_argument("--runner", required=True, type=pathlib.Path)
    parser.add_argument("--client", required=True, type=pathlib.Path)
    parser.add_argument("--server", required=True, type=pathlib.Path)
    parser.add_argument("--rule", required=True, type=pathlib.Path)
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parsed = parser.parse_args()
    repository = parsed.repository.resolve()
    if parsed.category == "rule":
        subprocess.run(
            [
                str(parsed.rule.resolve()),
                "--profile",
                "smoke",
                "--samples",
                "11",
                "--workspace-root",
                str(repository),
            ],
            cwd=repository,
            check=True,
            timeout=300,
        )
    else:
        _run_m4(
            category=parsed.category,
            runner=parsed.runner.resolve(),
            client=parsed.client.resolve(),
            server=parsed.server.resolve(),
            repository=repository,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
