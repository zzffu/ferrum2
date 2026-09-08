"""Build and measure real crate-owned TUN mock workloads, without host networking."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time

from tools.performance_candidate.json_contract import CandidateControlError, _strict_json
from tools.performance_candidate.output import _atomic_text
from tools.performance_candidate.tun_mock_process import ProcessTree
from tools.performance_candidate.tun_mock_contract import (
    BUILD_COMMAND, MODES, RECIPE_PATHS, artifact, decision, digest, fail, file_hash,
    load, schedule, sha, trial, validate,
)


def register_commands(commands) -> None:
    for command in ("tun-mock-calibrate", "tun-mock-run", "tun-mock-validate"):
        parser = commands.add_parser(command, help="TUN-only mock-I/O paired evidence")
        parser.add_argument("--baseline-sha", required=True)
        parser.add_argument("--candidate-sha", required=command != "tun-mock-calibrate")
        parser.add_argument("--mode", choices=tuple(MODES), required=True)
        parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
        if command != "tun-mock-validate":
            parser.add_argument("--repository", type=pathlib.Path, default=pathlib.Path("."))
        if command != "tun-mock-calibrate":
            parser.add_argument("--calibration-root", type=pathlib.Path)
            parser.add_argument("--calibration-sha256")


def controller_identity() -> str:
    package = pathlib.Path(__file__).resolve().parent
    paths = [package / name for name in ("cli.py", "tun_mock.py", "tun_mock_contract.py", "tun_mock_process.py", "identity.py", "json_contract.py", "pairing.py", "output.py", "__main__.py", "__init__.py")]
    return digest({path.name: file_hash(path) for path in paths})


def write_json(path: pathlib.Path, value: object) -> None:
    _atomic_text(path, json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def execute(command: list[str], *, cwd: pathlib.Path, stdout: pathlib.Path,
            stderr: pathlib.Path, timeout: int, env: dict | None = None,
            maximum_bytes: int = 32 * 1024 * 1024) -> None:
    """Bound wall time and log size; terminate the entire owned process tree."""
    stdout.parent.mkdir(parents=True, exist_ok=True)
    # Create suspended on Windows so no descendant can escape job assignment.
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x4} if os.name == "nt" else {"start_new_session": True}
    try:
        with stdout.open("wb") as out, stderr.open("wb") as err:
            child = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, **kwargs)
            tree = None
            try:
                tree = ProcessTree(child)
                deadline = time.monotonic() + timeout
                while child.poll() is None:
                    if time.monotonic() >= deadline:
                        fail(f"process timeout: {command[0]}; logs retained")
                    if stdout.stat().st_size + stderr.stat().st_size > maximum_bytes:
                        fail(f"process output exceeded bound: {command[0]}; logs retained")
                    time.sleep(0.05)
                if child.returncode != 0:
                    fail(f"process exited {child.returncode}: {command[0]}; logs retained")
                if stdout.stat().st_size + stderr.stat().st_size > maximum_bytes:
                    fail(f"process output exceeded bound: {command[0]}; logs retained")
            finally:
                if tree is not None:
                    tree.close()
                elif child.poll() is None:
                    child.kill()
                child.wait(timeout=15)
    except (OSError, subprocess.SubprocessError) as error:
        raise CandidateControlError(f"unable to execute {command[0]}; logs retained: {error}") from error


def inspect_command(command: list[str], repository: pathlib.Path) -> str:
    with tempfile.TemporaryDirectory(prefix="tun-mock-inspect-") as temporary:
        root = pathlib.Path(temporary)
        execute(command, cwd=repository, stdout=root / "stdout", stderr=root / "stderr", timeout=30, maximum_bytes=1024 * 1024)
        return (root / "stdout").read_text(encoding="utf-8").strip()


def environment(repository: pathlib.Path) -> dict:
    return {"os": platform.system(), "release": platform.release(), "version": platform.version(),
            "architecture": platform.machine(), "cpu": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unknown"),
            "cpu_count": os.cpu_count() or 1, "rustc": inspect_command(["rustc", "-vV"], repository),
            "cargo": inspect_command(["cargo", "-V"], repository),
            "environment_sha256": digest(dict(sorted(os.environ.items())))}


def run(parsed) -> dict:
    repository = parsed.repository.resolve()
    root = parsed.evidence_root.resolve()
    baseline = sha(parsed.baseline_sha, 40)
    candidate = baseline if parsed.command == "tun-mock-calibrate" else sha(parsed.candidate_sha, 40)
    aa = parsed.command == "tun-mock-calibrate"
    if not aa and baseline == candidate:
        fail("same-commit measurements must use tun-mock-calibrate")
    calibration_root = getattr(parsed, "calibration_root", None)
    calibration_hash = getattr(parsed, "calibration_sha256", None)
    if not aa and (calibration_root is None or calibration_hash is None):
        fail("A/B requires --calibration-root and reviewed --calibration-sha256")
    if root.exists():
        fail("evidence root must not already exist; invalid trials are never overwritten")
    controller = controller_identity()
    observed_environment = environment(repository)
    calibration = None
    if not aa:
        if file_hash(calibration_root / "manifest.json") != sha(calibration_hash):
            fail("reviewed calibration digest mismatch")
        calibration = load(calibration_root / "manifest.json")
        if type(calibration) is not dict:
            fail("invalid calibration manifest")
        validate(calibration_root, baseline_sha=calibration.get("baseline_sha"), candidate_sha=calibration.get("baseline_sha"), mode=parsed.mode, controller_sha256=controller)
        if observed_environment != calibration["environment"]:
            fail("calibration environment differs from current host/toolchain/environment")
    root.mkdir(parents=True)
    manifest = {"schema_version": 1, "kind": "ferrum2.tun-mock.aa" if aa else "ferrum2.tun-mock.ab",
                "baseline_sha": baseline, "candidate_sha": candidate, "mode": parsed.mode,
                "controller_sha256": controller, "recipe_sha256": None, "environment": observed_environment,
                "builds": {}, "trials": [], "calibration_sha256": calibration_hash,
                "result": None, "artifacts": {}}
    worktrees = []
    failure = None
    try:
        for side, source in (("baseline", baseline), ("candidate", candidate)):
            if inspect_command(["git", "cat-file", "-t", source], repository) != "commit":
                fail("source SHA must identify an available commit")
            # A fresh, detached worktree and separate target directory for each side,
            # including A/A: no shared product object cache or reused executable.
            temporary = pathlib.Path(tempfile.mkdtemp(prefix=f"tun-mock-{side}-"))
            tree = temporary / "source"
            worktrees.append((temporary, tree))
            inspect_command(["git", "worktree", "add", "--detach", str(tree), source], repository)
            if inspect_command(["git", "rev-parse", "HEAD"], tree) != source:
                fail("worktree source identity mismatch")
            recipe_files = {path: file_hash(tree / path) for path in RECIPE_PATHS}
            recipe = digest(recipe_files)
            if manifest["recipe_sha256"] is None:
                manifest["recipe_sha256"] = recipe
            if recipe != manifest["recipe_sha256"] or (calibration is not None and recipe != calibration["recipe_sha256"]):
                fail("harness recipe differs between builds or reviewed calibration")
            build_dir = root / "builds" / side
            stdout = build_dir / "stdout.log"
            stderr = build_dir / "stderr.log"
            target = temporary / "target"
            env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0")
            execute(BUILD_COMMAND, cwd=tree, stdout=stdout, stderr=stderr, timeout=1800, env=env)
            name = "tun-benchmark" + (".exe" if os.name == "nt" else "")
            binary = build_dir / name
            shutil.copy2(target / "profiling" / "examples" / name, binary)
            manifest["builds"][side] = {"source_sha": source, "recipe_files": recipe_files,
                "binary": binary.relative_to(root).as_posix(), "binary_sha256": file_hash(binary),
                "command": BUILD_COMMAND, "stdout": stdout.relative_to(root).as_posix(), "stderr": stderr.relative_to(root).as_posix()}
        for index, (scenario, pair, side) in enumerate(schedule(parsed.mode)):
            build = manifest["builds"][side]
            binary = artifact(root, build["binary"])
            if file_hash(binary) != build["binary_sha256"]:
                fail("retained executable changed before trial")
            stdout = root / "trials" / f"{index:03d}.json"
            stderr = root / "trials" / f"{index:03d}.stderr"
            execute([str(binary), "--scenario", scenario, "--mode", parsed.mode], cwd=root,
                    stdout=stdout, stderr=stderr, timeout=120, maximum_bytes=65536)
            value = trial(_strict_json(stdout.read_text(encoding="utf-8"), source=str(stdout)), scenario, parsed.mode)
            manifest["trials"].append({"scenario": scenario, "pair": pair, "side": side,
                "binary_sha256": build["binary_sha256"], "stdout": stdout.relative_to(root).as_posix(),
                "stderr": stderr.relative_to(root).as_posix(), "trial": value})
        bounds = None if calibration is None else calibration["result"]["noise_bounds_percent"]
        manifest["result"] = decision(manifest["trials"], bounds)
    except (CandidateControlError, OSError, UnicodeError) as error:
        failure = str(error)
    finally:
        cleanup_errors = []
        for temporary, tree in reversed(worktrees):
            try:
                if tree.exists():
                    inspect_command(["git", "worktree", "remove", "--force", str(tree)], repository)
                shutil.rmtree(temporary)
            except (CandidateControlError, OSError) as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            failure = (failure or "") + "; worktree cleanup failed: " + "; ".join(cleanup_errors)
    manifest["artifacts"] = {p.relative_to(root).as_posix(): file_hash(p) for p in root.rglob("*") if p.is_file()}
    write_json(root / "manifest.json", manifest)
    if failure is not None:
        write_json(root / "failure.json", {"error": failure})
        fail(f"{failure}; incomplete evidence retained at {root}")
    result = validate(root, baseline_sha=baseline, candidate_sha=candidate, mode=parsed.mode,
                      controller_sha256=controller, calibration_root=calibration_root, calibration_sha256=calibration_hash)
    return {**result, "manifest_sha256": file_hash(root / "manifest.json"), "evidence_root": str(root)}


def run_command(parsed) -> dict:
    try:
        if parsed.command != "tun-mock-validate":
            return run(parsed)
        result = validate(parsed.evidence_root, baseline_sha=parsed.baseline_sha,
                          candidate_sha=parsed.candidate_sha, mode=parsed.mode, controller_sha256=controller_identity(),
                          calibration_root=parsed.calibration_root, calibration_sha256=parsed.calibration_sha256)
        return {**result, "manifest_sha256": file_hash(parsed.evidence_root / "manifest.json")}
    except (OSError, UnicodeError) as error:
        raise CandidateControlError(f"TUN mock evidence I/O failure: {error}") from error
