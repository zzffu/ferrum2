"""Private orchestration for the existing Linux attach-only shell entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import asdict
from contextlib import ExitStack
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.cpu_profile.evidence import (
    EvidenceError, bounded_bytes, validate_perf_container, validate_samply_container,
)
from tools.cpu_profile.process import CleanupStatus, CommandStatus, ProcessOwner, private_file


EVENTS = (
    "task-clock", "cycles:u", "instructions:u", "branches:u", "branch-misses:u",
    "cache-references:u", "cache-misses:u", "context-switches", "page-faults",
)
UNVERIFIED_REASONS = [
    "build_provenance_unbound", "workload_identity_unbound", "active_window_unbound",
    "workload_final_result_missing", "perf_counter_schema_unverified",
    "samply_sample_loss_symbol_schema_unverified",
]


def _positive(value: str, maximum: int) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > maximum:
        raise argparse.ArgumentTypeError(f"expected an integer in 1..{maximum}")
    return int(value)


def arguments(argv):
    parser = argparse.ArgumentParser(prog="tools/profile-cpu.sh")
    parser.add_argument("--scenario", required=True, choices=("tcp-bulk", "udp-small-high"))
    parser.add_argument("--role", required=True, choices=("client", "server"))
    parser.add_argument("--pid", required=True, type=lambda value: _positive(value, 2**31 - 1))
    parser.add_argument("--duration", required=True, type=lambda value: _positive(value, 300))
    parser.add_argument("--frequency", required=True, type=lambda value: _positive(value, 1000))
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def create_output(repository: Path, requested: Path) -> Path:
    repository = repository.resolve(strict=True)
    output = repository / requested
    try:
        relative = output.relative_to(repository)
    except ValueError as error:
        raise EvidenceError("output_outside_profiles") from error
    if (len(relative.parts) < 2 or relative.parts[0] != "profiles"
            or ".." in relative.parts):
        raise EvidenceError("output_outside_profiles")
    # Validate through held directories before any mkdir/chmod. Descriptor-relative
    # traversal cannot follow an existing or substituted parent symlink elsewhere.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as owned:
        root_fd = os.open(repository, flags)
        owned.callback(os.close, root_fd)
        try:
            profiles_fd = os.open("profiles", flags, dir_fd=root_fd)
        except FileNotFoundError:
            profiles_fd = None
        except OSError as error:
            raise EvidenceError("unsafe_profiles_directory") from error
        if profiles_fd is None:
            if len(relative.parts) != 2:
                raise EvidenceError("output_parent_missing")
            parent_fd = None
        else:
            owned.callback(os.close, profiles_fd)
            parent_fd = profiles_fd
            for part in relative.parts[1:-1]:
                try:
                    parent_fd = os.open(part, flags, dir_fd=parent_fd)
                except OSError as error:
                    raise EvidenceError("unsafe_output_parent") from error
                owned.callback(os.close, parent_fd)
            try:
                os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise EvidenceError("output_already_exists")
        if profiles_fd is None:
            os.mkdir("profiles", mode=0o700, dir_fd=root_fd)
            profiles_fd = os.open("profiles", flags, dir_fd=root_fd)
            owned.callback(os.close, profiles_fd)
            parent_fd = profiles_fd
        os.mkdir(relative.name, mode=0o700, dir_fd=parent_fd)
        os.fchmod(profiles_fd, 0o700)
        mode = os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False).st_mode
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
            raise EvidenceError("output_not_private")
    return output


def observe_target(pid: int, role: str) -> dict[str, object]:
    process = Path(f"/proc/{pid}")
    try:
        executable = process / "exe"
        if executable.resolve(strict=True).name != f"ferrum2-{role}":
            raise EvidenceError("unexpected_target_executable")
        raw_stat = bounded_bytes(process / "stat", 4096).decode("utf-8")
        fields = raw_stat.rsplit(") ", 1)[1].split()
        start = int(fields[19])
        if fields[0] in {"Z", "X"}:
            raise EvidenceError("target_not_live")
        proc_info = process.stat()
        digest = hashlib.sha256()
        with executable.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > 256 * 1024 * 1024:
                raise EvidenceError("executable_byte_limit")
            count = 0
            while chunk := stream.read(65_536):
                count += len(chunk)
                if count > 256 * 1024 * 1024:
                    raise EvidenceError("executable_byte_limit")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise EvidenceError("executable_changed_during_read")
        return {
            "pid": pid, "start_ticks": start, "proc_device": proc_info.st_dev,
            "proc_inode": proc_info.st_ino, "exe_device": before.st_dev,
            "exe_inode": before.st_ino, "exe_sha256": digest.hexdigest(),
        }
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise EvidenceError("target_identity_unavailable") from error


def _text(path: Path) -> str:
    text = bounded_bytes(path, 65_536).decode("utf-8").strip()
    if not text or "\n" in text or "\r" in text:
        raise EvidenceError("invalid_tool_identity")
    return text


def _controller_sources():
    root = Path(__file__).resolve().parents[2]
    paths = [root / "tools" / "profile-cpu.sh"]
    paths.extend(Path(__file__).parent / name for name in ("__init__.py", "record.py", "process.py", "evidence.py"))
    paths.append(root / "tools" / "owned_process.py")
    sources = []
    for path in sorted(paths):
        raw = bounded_bytes(path, 256 * 1024)
        sources.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
    return sources


def _cpu_model():
    try:
        with open("/proc/cpuinfo", "rb") as stream:
            prefix = stream.read(65_536).decode("utf-8")
        match = re.search(r"^model name\s*:\s*(.+)$", prefix, re.MULTILINE)
        return None if match is None else match[1].strip()
    except (OSError, UnicodeError):
        return None


def capture(args, repository: Path, output: Path, owner: ProcessOwner) -> dict[str, object]:
    metadata = {
        "schema_version": 1, "kind": "cpu_profile_diagnostic", "result": "FAILED",
        "evidence_validity": "unverified", "unverified_reasons": list(UNVERIFIED_REASONS),
        "analysis_qualified": False, "adoption_claim": False,
        "scenario": args.scenario, "role": args.role, "pid": args.pid,
        "duration_seconds_per_collector": args.duration, "frequency_hz": args.frequency,
        "clock": "monotonic", "stage_times": "helper_invocation_not_sample_window",
        "python": sys.version.split()[0],
        "stages": [], "error": None,
    }
    deadline = time.monotonic() + 2 * args.duration + 60
    preflight_deadline = min(deadline, time.monotonic() + 30)

    def command(name, argv, *, seconds=5, preflight=True, interrupt_after=None):
        result = owner.run(
            argv, deadline=min(preflight_deadline if preflight else deadline, time.monotonic() + seconds),
            stdout=output / f"{name}.stdout.txt", stderr=output / f"{name}.stderr.txt",
            interrupt_after=interrupt_after,
        )
        metadata["stages"].append({
            "stage": name, **asdict(result), "status": result.status.value,
            "cleanup": result.cleanup.value,
        })
        if result.status is not CommandStatus.COMPLETED:
            raise EvidenceError(result.status.value)
        if result.cleanup is CleanupStatus.UNCONFIRMED:
            raise EvidenceError("cleanup_unconfirmed")
        return output / f"{name}.stdout.txt"

    try:
        metadata["controller_sources"] = _controller_sources()
        metadata["cpu_model"] = _cpu_model()
        if metadata["cpu_model"] is None:
            metadata["unverified_reasons"].append("host_cpu_identity_missing")
        metadata["target_observation"] = observe_target(args.pid, args.role)
        # These describe the wrapper checkout, not the sampled binary's provenance.
        metadata["controller_sha"] = _text(command("git-head", ["git", "-C", str(repository), "rev-parse", "HEAD"]))
        metadata["controller_tree"] = _text(command("git-tree", ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"]))
        dirty = command("git-status", ["git", "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=normal"])
        metadata["controller_worktree_clean"] = not bounded_bytes(dirty, 65_536).strip()
        for name, argv in (
            ("rustc", ["rustc", "--version"]), ("cargo", ["cargo", "--version"]),
            ("kernel", ["uname", "-srmo"]), ("perf-version", ["perf", "--version"]),
            ("samply-version", ["samply", "--version"]),
        ):
            metadata[name] = _text(command(name, argv))
        if metadata["samply-version"] != "samply 0.13.1":
            raise EvidenceError("unsupported_samply_version")
        help_path = command("samply-help", ["samply", "record", "--help"])
        help_text = bounded_bytes(help_path, 65_536).decode("utf-8")
        if any(option not in help_text for option in ("--pid", "--duration", "--rate", "--save-only", "--output")):
            raise EvidenceError("unsupported_samply_options")
        notes = command("readelf", ["readelf", "-n", f"/proc/{args.pid}/exe"])
        build_ids = re.findall(r"Build\s+ID:\s+([0-9a-fA-F]+)", bounded_bytes(notes, 65_536).decode("utf-8"))
        if len(build_ids) != 1:
            raise EvidenceError("invalid_elf_build_id")
        metadata["elf_build_id_observed"] = build_ids[0]
        event_list = ",".join(EVENTS)
        for event in EVENTS:
            listing = command(f"perf-list-{event.replace(':', '-')}", ["perf", "list", event.split(":")[0]])
            if event.split(":")[0] not in bounded_bytes(listing, 65_536).decode("utf-8"):
                raise EvidenceError("perf_event_unavailable")
        command("perf-preflight", ["perf", "stat", "-e", event_list, "-p", str(args.pid), "--", "sleep", "0"])
        for stage in ("perf-stat", "samply"):
            if observe_target(args.pid, args.role) != metadata["target_observation"]:
                raise EvidenceError("target_identity_changed")
            if stage == "perf-stat":
                artifact = output / "perf-stat.txt"
                command(stage, ["perf", "stat", "-x", ";", "-o", str(artifact), "-e", event_list,
                                "-p", str(args.pid), "--", "sleep", str(args.duration)],
                        preflight=False, seconds=args.duration + 5)
                metadata["perf_container"] = validate_perf_container(artifact)
            else:
                artifact = output / "samply.json.gz"
                command(stage, ["samply", "record", "--pid", str(args.pid), "--duration", str(args.duration),
                                "--rate", str(args.frequency), "--save-only", "--output", str(artifact)],
                        preflight=False, seconds=args.duration + 10, interrupt_after=args.duration)
                metadata["samply_container"] = validate_samply_container(artifact)
            if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
                raise EvidenceError("artifact_not_private")
            if observe_target(args.pid, args.role) != metadata["target_observation"]:
                raise EvidenceError("target_identity_changed")
        if owner.cancelled:
            raise EvidenceError("interrupted")
        if time.monotonic() >= deadline:
            raise EvidenceError("run_deadline_exceeded")
        metadata["result"] = "COLLECTED"
    except (EvidenceError, OSError, UnicodeError) as error:
        metadata["evidence_validity"] = "invalid"
        metadata["error"] = str(error) if isinstance(error, EvidenceError) else "evidence_io_failed"
    finally:
        with private_file(output / "metadata.json") as stream:
            stream.write((json.dumps(metadata, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())
        with private_file(output / "stage-status.txt") as stream:
            for entry in metadata["stages"]:
                stream.write(f"stage={entry['stage']} status={entry['status']} cleanup={entry['cleanup']}\n".encode())
            stream.write(f"result={metadata['result']} evidence_validity={metadata['evidence_validity']}\n".encode())
    return metadata


def main(argv=None) -> int:
    args = arguments(argv)
    if sys.platform != "linux":
        print("profile-cpu: Linux is required", file=sys.stderr)
        return 1
    os.umask(0o077)
    repository = Path(__file__).resolve().parents[2]
    try:
        output = create_output(repository, args.output)
        with ProcessOwner() as owner:
            metadata = capture(args, repository, output, owner)
    except (EvidenceError, OSError):
        print("profile-cpu: unable to create or retain private evidence", file=sys.stderr)
        return 1
    if metadata["result"] != "COLLECTED":
        print(f"profile-cpu: {metadata['error']}", file=sys.stderr)
        return 1
    print("profile-cpu: COLLECTED; evidence unverified, not analysis or adoption evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
