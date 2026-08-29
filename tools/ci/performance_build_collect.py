"""Parse bounded raw profiler output into conditional prerequisite measurements."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import sys

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.conditional_decision import UDP_SYSCALL_TOPOLOGIES

MAX_RAW_BYTES = 64 * 1024 * 1024
UDP_RECV_SYSCALLS = frozenset({"recvfrom", "recvmsg", "recvmmsg"})
UDP_SEND_SYSCALLS = frozenset({"sendto", "sendmsg", "sendmmsg"})
SYSCALL = re.compile(r"\b(recvfrom|recvmsg|recvmmsg|sendto|sendmsg|sendmmsg)\(")
PERCENT = re.compile(r"(?P<percent>[0-9]+(?:\.[0-9]+)?)%")
ALLOCATOR_SYMBOL = re.compile(
    r"(?:^|[^A-Za-z])(malloc|calloc|realloc|free|alloc|jemalloc|mimalloc)(?:[^A-Za-z]|$)",
    re.IGNORECASE,
)
SAMPLE_COUNT = re.compile(
    r"^#\s*Samples:\s*(?P<count>[0-9]+(?:\.[0-9]+)?)(?P<suffix>[KMG]?)\s+of event\b",
    re.IGNORECASE,
)


def _positive_finite(value: object, field: str) -> float:
    if type(value) not in {int, float}:
        raise CandidateControlError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise CandidateControlError(f"{field} must be finite and positive")
    return result


def _text(path: pathlib.Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateControlError("unable to read profiler output") from error
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise CandidateControlError("profiler output is empty or exceeds its bound")
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise CandidateControlError("profiler output must be UTF-8") from error


def strace_udp_measurement(
    path: pathlib.Path,
    *,
    datagrams: int,
    topology_id: str,
    trigger_threshold: float,
) -> dict[str, object]:
    if (
        type(datagrams) is not int
        or datagrams <= 0
        or topology_id not in UDP_SYSCALL_TOPOLOGIES
    ):
        raise CandidateControlError("strace measurement inputs are invalid")
    threshold = _positive_finite(trigger_threshold, "strace trigger threshold")
    counts = {name: 0 for name in UDP_RECV_SYSCALLS | UDP_SEND_SYSCALLS}
    for line in _text(path).splitlines():
        match = SYSCALL.search(line)
        if match is not None:
            counts[match.group(1)] += 1
    recv = sum(counts[name] for name in UDP_RECV_SYSCALLS)
    send = sum(counts[name] for name in UDP_SEND_SYSCALLS)
    if recv + send == 0:
        raise CandidateControlError("strace output contains no UDP syscalls")
    topology = UDP_SYSCALL_TOPOLOGIES[topology_id]
    expected_recv = datagrams * topology["recv_legs_per_datagram"]
    expected_send = datagrams * topology["send_legs_per_datagram"]
    excess_recv = max(0, recv - expected_recv)
    excess_send = max(0, send - expected_send)
    normalized_excess = (excess_recv + excess_send) / datagrams
    return {
        "datagrams": datagrams,
        "excess_recv_syscalls": excess_recv,
        "excess_send_syscalls": excess_send,
        "expected_recv_syscalls": expected_recv,
        "expected_send_syscalls": expected_send,
        "normalized_excess_syscalls_per_datagram": normalized_excess,
        "recv_syscalls": recv,
        "send_syscalls": send,
        "topology": {"id": topology_id, **topology},
        "trigger_present": normalized_excess >= threshold,
        "trigger_threshold_excess_per_datagram": threshold,
    }


def _perf_csv_value(text: str, event: str) -> float:
    matches: list[float] = []
    for line in text.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if event not in fields:
            continue
        raw = fields[0].replace(" ", "")
        if raw in {"<notcounted>", "<notsupported>"}:
            continue
        try:
            matches.append(float(raw))
        except ValueError as error:
            raise CandidateControlError(
                f"perf stat {event} value is invalid"
            ) from error
    if len(matches) != 1 or not math.isfinite(matches[0]) or matches[0] < 0:
        raise CandidateControlError(f"perf stat must contain one {event} value")
    return matches[0]


def udp_kernel_cpu_measurement(
    path: pathlib.Path, *, trigger_threshold_percent: float
) -> dict[str, object]:
    threshold = _positive_finite(
        trigger_threshold_percent, "UDP kernel CPU trigger threshold"
    )
    if threshold > 100.0:
        raise CandidateControlError("UDP kernel CPU trigger threshold exceeds 100%")
    text = _text(path)
    total_cycles = _perf_csv_value(text, "cycles")
    kernel_cycles = _perf_csv_value(text, "cycles:k")
    if total_cycles <= 0 or kernel_cycles > total_cycles:
        raise CandidateControlError("perf stat UDP cycle counts are inconsistent")
    share = kernel_cycles * 100.0 / total_cycles
    return {
        "kernel_cpu_share_percent": share,
        "kernel_cycles": kernel_cycles,
        "total_cycles": total_cycles,
        "trigger_present": share >= threshold,
        "trigger_threshold_percent": threshold,
    }


def context_switch_measurement(
    path: pathlib.Path, *, duration_seconds: float, trigger_threshold: float
) -> dict[str, object]:
    duration = _positive_finite(duration_seconds, "context-switch duration")
    threshold = _positive_finite(trigger_threshold, "context-switch trigger threshold")
    switches = _perf_csv_value(_text(path), "context-switches")
    rate = switches / duration
    return {
        "context_switches_per_second": rate,
        "trigger_present": rate >= threshold,
        "trigger_threshold_per_second": threshold,
    }


def perf_c2c_measurement(
    path: pathlib.Path, *, trigger_minimum: int
) -> dict[str, object]:
    if type(trigger_minimum) is not int or trigger_minimum <= 0:
        raise CandidateControlError("perf-c2c trigger minimum is invalid")
    total = 0
    matched = False
    for line in _text(path).splitlines():
        if (
            "HITM" not in line.upper()
            or "LOAD" in line.upper()
            and "HITM" not in line.upper()
        ):
            continue
        values = re.findall(r"\b[0-9][0-9,]*\b", line)
        if values:
            total += int(values[0].replace(",", ""))
            matched = True
    if not matched:
        raise CandidateControlError("perf-c2c output contains no HITM observation")
    return {
        "cache_line_bounces": total,
        "trigger_minimum": trigger_minimum,
        "trigger_present": total >= trigger_minimum,
    }


def allocator_hotspot_measurement(
    path: pathlib.Path, *, trigger_threshold: float
) -> dict[str, object]:
    threshold = _positive_finite(trigger_threshold, "allocator trigger threshold")
    text = _text(path)
    sample_counts = []
    suffix_scale = {"": 1, "K": 1_000, "M": 1_000_000, "G": 1_000_000_000}
    for line in text.splitlines():
        match = SAMPLE_COUNT.match(line)
        if match is not None:
            observed = (
                float(match.group("count"))
                * suffix_scale[match.group("suffix").upper()]
            )
            if not math.isfinite(observed) or observed < 1:
                raise CandidateControlError("allocator sample count is invalid")
            sample_counts.append(round(observed))
    if len(sample_counts) != 1:
        raise CandidateControlError("allocator report must contain one sample count")
    percent = 0.0
    matched = False
    for line in text.splitlines():
        if ALLOCATOR_SYMBOL.search(line) is None:
            continue
        match = PERCENT.search(line)
        if match is not None:
            percent += float(match.group("percent"))
            matched = True
    if not matched or percent > 100.000_001:
        raise CandidateControlError("allocator report contains no bounded hotspot")
    return {
        "hotspot_percent": percent,
        "sample_count": sample_counts[0],
        "trigger_present": percent >= threshold,
        "trigger_threshold_percent": threshold,
    }


def allocator_cpu_lock_measurement(
    perf_path: pathlib.Path,
    lock_path: pathlib.Path,
    *,
    trigger_threshold: float,
) -> dict[str, object]:
    hotspot = allocator_hotspot_measurement(
        perf_path, trigger_threshold=trigger_threshold
    )
    lock_wait = _perf_csv_value(_text(lock_path), "lock-contention-nanoseconds")
    return {
        "allocator_cpu_percent": hotspot["hotspot_percent"],
        "lock_wait_nanoseconds": lock_wait,
        "trigger_present": hotspot["hotspot_percent"] >= trigger_threshold,
        "trigger_threshold_percent": trigger_threshold,
    }


def _write(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    udp = commands.add_parser("udp-syscall")
    udp.add_argument("--raw", required=True, type=pathlib.Path)
    udp.add_argument("--datagrams", required=True, type=int)
    udp.add_argument(
        "--topology", required=True, choices=sorted(UDP_SYSCALL_TOPOLOGIES)
    )
    udp.add_argument("--trigger-threshold", required=True, type=float)
    udp_cpu = commands.add_parser("udp-kernel-cpu")
    udp_cpu.add_argument("--raw", required=True, type=pathlib.Path)
    udp_cpu.add_argument("--trigger-threshold-percent", required=True, type=float)
    context = commands.add_parser("context-switch")
    context.add_argument("--raw", required=True, type=pathlib.Path)
    context.add_argument("--duration-seconds", required=True, type=float)
    context.add_argument("--trigger-threshold", required=True, type=float)
    c2c = commands.add_parser("perf-c2c")
    c2c.add_argument("--raw", required=True, type=pathlib.Path)
    c2c.add_argument("--trigger-minimum", required=True, type=int)
    allocation = commands.add_parser("allocation-hotspots")
    allocation.add_argument("--raw", required=True, type=pathlib.Path)
    allocation.add_argument("--trigger-threshold", required=True, type=float)
    allocator = commands.add_parser("allocator-cpu-lock")
    allocator.add_argument("--perf-raw", required=True, type=pathlib.Path)
    allocator.add_argument("--lock-raw", required=True, type=pathlib.Path)
    allocator.add_argument("--trigger-threshold", required=True, type=float)
    assertion = commands.add_parser("assertion")
    assertion.add_argument("--reason", required=True)
    assertion.add_argument("--satisfied", required=True, choices=("true", "false"))
    for command in (udp, udp_cpu, context, c2c, allocation, allocator):
        command.add_argument("--output", required=True, type=pathlib.Path)
    assertion.add_argument("--output", required=True, type=pathlib.Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    try:
        parsed = _parser().parse_args(arguments)
        if parsed.command == "udp-syscall":
            value = strace_udp_measurement(
                parsed.raw,
                datagrams=parsed.datagrams,
                topology_id=parsed.topology,
                trigger_threshold=parsed.trigger_threshold,
            )
        elif parsed.command == "udp-kernel-cpu":
            value = udp_kernel_cpu_measurement(
                parsed.raw,
                trigger_threshold_percent=parsed.trigger_threshold_percent,
            )
        elif parsed.command == "context-switch":
            value = context_switch_measurement(
                parsed.raw,
                duration_seconds=parsed.duration_seconds,
                trigger_threshold=parsed.trigger_threshold,
            )
        elif parsed.command == "perf-c2c":
            value = perf_c2c_measurement(
                parsed.raw, trigger_minimum=parsed.trigger_minimum
            )
        elif parsed.command == "allocation-hotspots":
            value = allocator_hotspot_measurement(
                parsed.raw,
                trigger_threshold=parsed.trigger_threshold,
            )
        elif parsed.command == "allocator-cpu-lock":
            value = allocator_cpu_lock_measurement(
                parsed.perf_raw,
                parsed.lock_raw,
                trigger_threshold=parsed.trigger_threshold,
            )
        elif parsed.command == "assertion":
            if not parsed.reason or len(parsed.reason) > 512:
                raise CandidateControlError("assertion reason is invalid")
            value = {
                "reason": parsed.reason,
                "satisfied": parsed.satisfied == "true",
            }
        else:
            raise AssertionError(f"unhandled collector command: {parsed.command}")
        _write(parsed.output, value)
        return 0
    except CandidateControlError as error:
        print(f"performance-build-collect: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
