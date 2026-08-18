#!/usr/bin/env python3
"""Direct native qualification for ferrum2 release binaries.

This driver is intentionally limited to committed synthetic configuration and
the two release artifacts built by the current GitHub Actions platform row. It
does not synthesize a report: every PASS field follows a bounded observation of
the supplied native binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


PROCESS_TIMEOUT_SECONDS = 20
READINESS_TIMEOUT_SECONDS = 10
OUTPUT_LIMIT = 64 * 1024
POLL_SECONDS = 0.05
SYNTHETIC_PSK = "AAECAwQFBgcICQoLDA0ODw=="
INVALID_STDERR = (
    b"error[config.semantic] shadowsocks.psk: configuration value is invalid\n"
)
STARTUP_BIND_STDERR = (
    b"error[startup.bind] process: unable to prepare required endpoint\n"
)
STARTUP_BIND_REPORT_FIELDS = frozenset(
    {
        "actual_grace_deadline_elapsed_ns",
        "actual_grace_deadline_source",
        "cleanup_failure",
        "event",
        "forced_root_count",
        "owner_baseline",
        "owner_delta",
        "owner_stopped",
        "process_states",
        "process_transitions",
        "role",
        "root",
        "root_error_category",
        "root_exit_category",
        "root_exit_events",
        "shutdown_grace_ns",
        "termination_cause",
    }
)
OWNER_COUNTER_FIELDS = frozenset(
    {
        "process_supervisors",
        "prepared_process_roots",
        "active_process_roots",
        "process_root_reaps",
        "process_root_rollbacks",
        "process_forced_roots",
        "active_tun_tcp_flows",
        "active_tun_handler_tasks",
        "active_supervisor_children",
        "connection_tasks",
        "owned_buffers",
        "owned_permits",
        "listeners",
        "forced_shutdowns",
        "udp_sessions",
        "udp_sockets",
        "udp_tasks",
        "udp_queued_datagrams",
        "udp_buffered_bytes",
        "udp_scratch_buffers",
        "udp_forced_shutdowns",
        "sniff_buffered_bytes",
    }
)
ACTIVE_OWNER_COUNTER_FIELDS = frozenset(
    {
        "process_supervisors",
        "prepared_process_roots",
        "active_process_roots",
        "active_tun_tcp_flows",
        "active_tun_handler_tasks",
        "active_supervisor_children",
        "connection_tasks",
        "owned_buffers",
        "owned_permits",
        "listeners",
        "udp_sessions",
        "udp_sockets",
        "udp_tasks",
        "udp_queued_datagrams",
        "udp_buffered_bytes",
        "udp_scratch_buffers",
        "sniff_buffered_bytes",
    }
)


class QualificationError(RuntimeError):
    """A canonical fail-closed qualification error."""


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


@dataclass(frozen=True)
class BinarySpec:
    name: str
    path: Path
    valid_config: Path
    invalid_config: Path
    role: str


@dataclass
class Capture:
    threads: tuple[threading.Thread, threading.Thread]
    slots: dict[str, tuple[bytes, bool]]


def require(condition: bool, root: str) -> None:
    if not condition:
        raise QualificationError(root)


def startup_bind_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        require(name not in value, "startup-bind-report-duplicate-field")
        value[name] = item
    return value


def reject_startup_bind_json_number(value: str) -> float:
    raise ValueError(f"unsupported JSON number: {value}")


def json_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def assert_owner_counters(value: object, signed: bool) -> dict[str, int]:
    require(isinstance(value, dict), "startup-bind-report-owner-type")
    require(set(value) == OWNER_COUNTER_FIELDS, "startup-bind-report-owner-fields")
    require(
        all(json_integer(counter) and (signed or counter >= 0) for counter in value.values()),
        "startup-bind-report-owner-value",
    )
    return value


def assert_client_startup_bind_report(
    report_line: bytes,
    expected_root: tuple[str, int],
    expected_shutdown_grace_ns: int,
) -> None:
    try:
        report = json.loads(
            report_line,
            object_pairs_hook=startup_bind_json_object,
            parse_float=reject_startup_bind_json_number,
            parse_constant=reject_startup_bind_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise QualificationError("startup-bind-report-json") from error
    require(isinstance(report, dict), "startup-bind-report-type")
    require(set(report) == STARTUP_BIND_REPORT_FIELDS, "startup-bind-report-fields")
    require(report["event"] == "process_shutdown_report", "startup-bind-report-event")
    require(report["role"] == "client", "startup-bind-report-role")

    states = ["Validated", "Preparing", "Rollback", "Stopped"]
    require(report["process_states"] == states, "startup-bind-report-states")
    transitions = report["process_transitions"]
    require(
        isinstance(transitions, list) and len(transitions) == len(states),
        "startup-bind-report-transitions",
    )
    elapsed: list[int] = []
    for state, transition in zip(states, transitions, strict=True):
        require(
            isinstance(transition, dict)
            and set(transition) == {"state", "elapsed_ns"}
            and transition["state"] == state
            and json_integer(transition["elapsed_ns"])
            and transition["elapsed_ns"] >= 0,
            "startup-bind-report-transition",
        )
        elapsed.append(transition["elapsed_ns"])
    require(elapsed == sorted(elapsed), "startup-bind-report-transition-order")

    require(report["root_exit_events"] == [], "startup-bind-report-root-events")
    require(
        report["shutdown_grace_ns"] == expected_shutdown_grace_ns,
        "startup-bind-report-grace",
    )
    require(
        report["actual_grace_deadline_elapsed_ns"] is None
        and report["actual_grace_deadline_source"] is None,
        "startup-bind-report-deadline",
    )
    require(
        report["termination_cause"] == "PreparationFailed",
        "startup-bind-report-cause",
    )
    root = report["root"]
    require(
        isinstance(root, dict)
        and set(root) == {"name", "id"}
        and root["name"] == expected_root[0]
        and json_integer(root["id"])
        and root["id"] == expected_root[1],
        "startup-bind-report-root",
    )
    require(report["root_exit_category"] is None, "startup-bind-report-root-exit")
    require(
        report["root_error_category"] == "startup.bind",
        "startup-bind-report-root-error",
    )
    require(
        json_integer(report["forced_root_count"])
        and report["forced_root_count"] == 0,
        "startup-bind-report-forced-root",
    )
    require(report["cleanup_failure"] is None, "startup-bind-report-cleanup")

    baseline = assert_owner_counters(report["owner_baseline"], signed=False)
    stopped = assert_owner_counters(report["owner_stopped"], signed=False)
    delta = assert_owner_counters(report["owner_delta"], signed=True)
    require(all(counter == 0 for counter in baseline.values()), "startup-bind-report-baseline")
    require(
        all(stopped[name] == 0 for name in ACTIVE_OWNER_COUNTER_FIELDS),
        "startup-bind-report-owner-leak",
    )
    require(
        all(delta[name] == stopped[name] - baseline[name] for name in OWNER_COUNTER_FIELDS),
        "startup-bind-report-owner-delta",
    )


def assert_startup_bind_stderr(
    spec: BinarySpec,
    stderr: bytes,
    expected_client_root: tuple[str, int],
    expected_shutdown_grace_ns: int,
) -> None:
    if spec.role == "server":
        require(stderr == STARTUP_BIND_STDERR, "startup-bind-stderr")
        return
    lines = stderr.splitlines(keepends=True)
    require(
        len(lines) == 2
        and lines[0].endswith(b"\n")
        and lines[1] == STARTUP_BIND_STDERR,
        "client-startup-bind-stderr",
    )
    assert_client_startup_bind_report(
        lines[0][:-1], expected_client_root, expected_shutdown_grace_ns
    )


def environment_field(value: str | None) -> str:
    require(value is not None and value != "", "missing-runner-evidence")
    return re.sub(r"[^A-Za-z0-9_.:/-]", "_", value)


def hosted_context(arguments: argparse.Namespace) -> HostedContext:
    profiles = {
        "windows-msvc": ("x86_64-pc-windows-msvc", "Windows"),
        "linux-gnu": ("x86_64-unknown-linux-gnu", "Linux"),
        "linux-musl": ("x86_64-unknown-linux-musl", "Linux"),
    }
    require(arguments.profile in profiles, "unknown-platform-profile")
    target, runner_os = profiles[arguments.profile]
    require(arguments.target == target, "profile-target-mismatch")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "not-github-actions")
    require(os.environ.get("RUNNER_OS") == runner_os, "wrong-runner-os")
    require(os.environ.get("RUNNER_ARCH") == "X64", "wrong-runner-architecture")
    machine = platform.machine().lower()
    require(machine in {"amd64", "x86_64"}, "non-native-architecture")
    if runner_os == "Windows":
        require(sys.platform == "win32", "non-native-operating-system")
    else:
        require(sys.platform.startswith("linux"), "non-native-operating-system")

    sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-fA-F]{40}", sha) is not None, "invalid-github-sha")
    require(run_id.isdecimal() and int(run_id) > 0, "invalid-run-id")
    require(
        run_attempt.isdecimal() and int(run_attempt) > 0,
        "invalid-run-attempt",
    )
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


def expected_artifact(root: Path, target: str, name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    return (root / "target" / target / "release" / f"{name}{suffix}").resolve()


def binary_specs(arguments: argparse.Namespace, root: Path) -> tuple[BinarySpec, BinarySpec]:
    client = Path(arguments.client).resolve()
    server = Path(arguments.server).resolve()
    require(
        client == expected_artifact(root, arguments.target, "ferrum2-client"),
        "unexpected-client-artifact-path",
    )
    require(
        server == expected_artifact(root, arguments.target, "ferrum2-server"),
        "unexpected-server-artifact-path",
    )
    for artifact in (client, server):
        require(artifact.is_file() and not artifact.is_symlink(), "missing-release-artifact")
    config = root / "tests" / "platform" / "config"
    return (
        BinarySpec(
            "ferrum2-client",
            client,
            config / "client-valid.toml",
            config / "client-invalid-key-length.toml",
            "client",
        ),
        BinarySpec(
            "ferrum2-server",
            server,
            config / "server-valid.toml",
            config / "server-invalid-key-length.toml",
            "server",
        ),
    )


def capture_pipe(stream: BinaryIO, name: str, slots: dict[str, tuple[bytes, bool]]) -> None:
    output = bytearray()
    exceeded = False
    try:
        while chunk := stream.read(4096):
            remaining = OUTPUT_LIMIT - len(output)
            output.extend(chunk[: max(remaining, 0)])
            exceeded |= len(chunk) > remaining
    finally:
        stream.close()
        slots[name] = (bytes(output), exceeded)


def start_capture(process: subprocess.Popen[bytes]) -> Capture:
    require(process.stdout is not None and process.stderr is not None, "capture-not-piped")
    slots: dict[str, tuple[bytes, bool]] = {}
    stdout = threading.Thread(
        target=capture_pipe,
        args=(process.stdout, "stdout", slots),
        name="m3-platform-stdout",
    )
    stderr = threading.Thread(
        target=capture_pipe,
        args=(process.stderr, "stderr", slots),
        name="m3-platform-stderr",
    )
    stdout.start()
    stderr.start()
    return Capture((stdout, stderr), slots)


def finish_capture(capture: Capture) -> tuple[bytes, bytes]:
    for thread in capture.threads:
        thread.join(timeout=5)
    require(not any(thread.is_alive() for thread in capture.threads), "capture-join-timeout")
    require(set(capture.slots) == {"stdout", "stderr"}, "capture-incomplete")
    stdout, stdout_exceeded = capture.slots["stdout"]
    stderr, stderr_exceeded = capture.slots["stderr"]
    require(not stdout_exceeded and not stderr_exceeded, "process-output-limit")
    return stdout, stderr


def bounded_run(
    arguments: list[str], timeout: int = PROCESS_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    capture = start_capture(process)
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait(timeout=5)
        finish_capture(capture)
        raise QualificationError("process-timeout") from error
    stdout, stderr = finish_capture(capture)
    require(
        SYNTHETIC_PSK.encode() not in stdout and SYNTHETIC_PSK.encode() not in stderr,
        "secret-in-process-output",
    )
    return subprocess.CompletedProcess(arguments, status, stdout, stderr)


def write_offline_config(
    source: Path,
    destination: Path,
    spec: BinarySpec,
    ports: tuple[int, ...],
) -> None:
    fixed_ports = (1080, 8388, 9090) if spec.role == "client" else (8388, 9090)
    require(len(ports) == len(fixed_ports), "offline-config-port-count")
    text = source.read_text(encoding="utf-8")
    for fixed, allocated in zip(fixed_ports, ports, strict=True):
        endpoint = f"127.0.0.1:{fixed}"
        require(endpoint in text, "offline-config-endpoint")
        text = text.replace(endpoint, f"127.0.0.1:{allocated}")
    destination.write_text(text, encoding="utf-8", newline="\n")


def assert_cli_contract(spec: BinarySpec, directory: Path) -> None:
    help_result = bounded_run([str(spec.path), "--help"])
    require(help_result.returncode == 0, "help-exit")
    require(b"Usage:" in help_result.stdout and help_result.stderr == b"", "help-output")

    version_result = bounded_run([str(spec.path), "--version"])
    require(version_result.returncode == 0, "version-exit")
    require(
        version_result.stdout.startswith(f"{spec.name} ".encode())
        and version_result.stdout.endswith(b"\n")
        and version_result.stderr == b"",
        "version-output",
    )

    traps = tcp_listeners(3 if spec.role == "client" else 2)
    for trap in traps:
        trap.setblocking(False)
    ports = tuple(int(trap.getsockname()[1]) for trap in traps)
    valid_config = directory / f"{spec.name}-offline-valid.toml"
    invalid_config = directory / f"{spec.name}-offline-invalid.toml"
    write_offline_config(spec.valid_config, valid_config, spec, ports)
    write_offline_config(spec.invalid_config, invalid_config, spec, ports)
    try:
        valid = bounded_run(
            [str(spec.path), "--config", str(valid_config), "--check-config"]
        )
        require(
            valid.returncode == 0
            and valid.stdout == b"configuration valid\n"
            and valid.stderr == b"",
            "valid-offline-config",
        )
        assert_no_connections(traps)

        invalid = bounded_run(
            [str(spec.path), "--config", str(invalid_config), "--check-config"]
        )
        require(
            invalid.returncode == 2
            and invalid.stdout == b""
            and invalid.stderr == INVALID_STDERR,
            "invalid-offline-config",
        )
        assert_no_connections(traps)
    finally:
        for trap in traps:
            trap.close()


def write_tagged_config(
    path: Path,
    spec: BinarySpec,
    listens: tuple[int, int],
    servers: tuple[int, int] | None,
    routed: bool = False,
    schema_version: int = 1,
) -> None:
    require((spec.role == "client") == (servers is not None), "tagged-config-role")
    inbounds = "\n\n".join(
        f'''[[inbounds]]
tag = "in-{index}"
listen = "127.0.0.1:{listen}"
''' + ("" if routed else f'outbound = "out-{index}"')
        for index, listen in enumerate(listens)
    )
    outbounds = "\n\n".join(
        f'''[[outbounds]]
tag = "out-{index}"'''
        + (f'\nserver = "127.0.0.1:{servers[index]}"' if servers else "")
        for index in range(2)
    )
    path.write_text(
        f'''schema_version = {schema_version}

{inbounds}

{outbounds}

''' + ('''[route]
final = "out-0"
[[route.rules]]
inbound = "in-0"
network = "tcp"
outbound = "out-0"
[[route.rules]]
network = "udp"
outbound = "out-1"

''' if routed else "") + f'''[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "{SYNTHETIC_PSK}"
''',
        encoding="utf-8",
        newline="\n",
    )


def assert_tagged_offline_config(spec: BinarySpec, directory: Path) -> None:
    traps = tcp_listeners(4 if spec.role == "client" else 2)
    for trap in traps:
        trap.setblocking(False)
    listens = tuple(int(trap.getsockname()[1]) for trap in traps[:2])
    servers = (
        tuple(int(trap.getsockname()[1]) for trap in traps[2:])
        if spec.role == "client"
        else None
    )
    try:
        config = directory / f"{spec.name}-tagged-offline.toml"
        for routed in (False, True):
            write_tagged_config(config, spec, listens, servers, routed)
            result = bounded_run(
                [str(spec.path), "--config", str(config), "--check-config"]
            )
            require(
                result.returncode == 0
                and result.stdout == b"configuration valid\n"
                and result.stderr == b"",
                "routed-offline-config" if routed else "tagged-offline-config",
            )
            assert_no_connections(traps)
    finally:
        for trap in traps:
            trap.close()

def assert_no_connections(traps: list[socket.socket]) -> None:
    for trap in traps:
        try:
            connection, _ = trap.accept()
        except BlockingIOError:
            continue
        connection.close()
        raise QualificationError("offline-config-side-effect")


def tcp_listener(port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen()
    return listener


def tcp_listeners(count: int) -> list[socket.socket]:
    listeners = []
    try:
        for _ in range(count):
            listeners.append(tcp_listener(0))
        return listeners
    except BaseException:
        for listener in listeners:
            listener.close()
        raise


def reserve_ports(count: int) -> tuple[int, ...]:
    reservations = tcp_listeners(count)
    try:
        return tuple(int(reservation.getsockname()[1]) for reservation in reservations)
    finally:
        for reservation in reservations:
            reservation.close()


def write_runtime_config(path: Path, spec: BinarySpec, listen: int, metrics: int, grace: int) -> None:
    role = (
        f'[client]\nlisten = "127.0.0.1:{listen}"\nserver = "127.0.0.1:1"'
        if spec.role == "client"
        else f'[server]\nlisten = "127.0.0.1:{listen}"'
    )
    path.write_text(
        f"""schema_version = 1

{role}

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "{SYNTHETIC_PSK}"

[metrics]
listen = "127.0.0.1:{metrics}"

[runtime]
shutdown_grace_ms = {grace}
""",
        encoding="utf-8",
        newline="\n",
    )


def assert_startup_rollback(spec: BinarySpec, directory: Path) -> None:
    listen, metrics = reserve_ports(2)
    occupied_listen = tcp_listener(listen)
    config = directory / f"{spec.name}-occupied-listen.toml"
    write_runtime_config(config, spec, listen, metrics, 1000)
    probes: list[socket.socket] = []
    try:
        result = bounded_run([str(spec.path), "--config", str(config)])
        require(
            result.returncode == 1
            and result.stdout == b"",
            "occupied-listen-startup-rollback",
        )
        assert_startup_bind_stderr(spec, result.stderr, ("socks", 0), 1_000_000_000)
        probes.append(tcp_listener(metrics))
        if spec.role == "server":
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", listen))
            probes.append(udp)
    finally:
        for probe in probes:
            probe.close()
        occupied_listen.close()
    assert_rebindable(spec, listen, metrics)

    listen, metrics = reserve_ports(2)
    occupied_metrics = tcp_listener(metrics)
    config = directory / f"{spec.name}-occupied-metrics.toml"
    write_runtime_config(config, spec, listen, metrics, 1000)
    try:
        result = bounded_run([str(spec.path), "--config", str(config)])
        require(
            result.returncode == 1
            and result.stdout == b"",
            "occupied-startup-rollback",
        )
        assert_startup_bind_stderr(spec, result.stderr, ("metrics", 1), 1_000_000_000)
        assert_rebindable(spec, listen, None)
    finally:
        occupied_metrics.close()
    assert_rebindable(spec, listen, metrics)


def assert_tagged_startup_rollback(spec: BinarySpec, directory: Path) -> None:
    last_collision: OSError | None = None
    for _ in range(3):
        try:
            assert_tagged_startup_rollback_once(spec, directory)
            return
        except OSError as error:
            last_collision = error
    raise QualificationError("tagged-port-setup-collision") from last_collision


def assert_tagged_startup_rollback_once(spec: BinarySpec, directory: Path) -> None:
    listeners = tcp_listeners(2)
    listens = tuple(int(listener.getsockname()[1]) for listener in listeners)
    try:
        server_traps = tcp_listeners(2) if spec.role == "client" else []
    except BaseException:
        for listener in listeners:
            listener.close()
        raise
    for trap in server_traps:
        trap.setblocking(False)
    servers = (
        tuple(int(trap.getsockname()[1]) for trap in server_traps)
        if server_traps
        else None
    )
    config = directory / f"{spec.name}-tagged-second-listener.toml"
    try:
        write_tagged_config(config, spec, listens, servers)
        listeners[0].close()
        result = bounded_run([str(spec.path), "--config", str(config)])
        require(
            result.returncode == 1
            and result.stdout == b"",
            "tagged-second-listener-rollback",
        )
        assert_startup_bind_stderr(spec, result.stderr, ("socks", 0), 30_000_000_000)
        assert_no_connections(server_traps)
        assert_tagged_rebindable(spec, (listens[0],))
    finally:
        for listener in listeners:
            listener.close()
        for trap in server_traps:
            trap.close()
    assert_tagged_rebindable(spec, listens)


def spawn_live(spec: BinarySpec, config: Path) -> tuple[subprocess.Popen[bytes], Capture]:
    options: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if sys.platform == "win32":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    process = subprocess.Popen([str(spec.path), "--config", str(config)], **options)
    return process, start_capture(process)


def wait_ready(process: subprocess.Popen[bytes], port: int) -> socket.socket:
    deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        require(process.poll() is None, "process-exited-before-readiness")
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=POLL_SECONDS)
        except OSError:
            time.sleep(POLL_SECONDS)
    raise QualificationError("readiness-timeout")


def bounded_accept(listener: socket.socket, size: int, timeout: float = READINESS_TIMEOUT_SECONDS) -> tuple[socket.socket, bytes]:
    peer = None
    try:
        listener.settimeout(timeout)
        peer, _ = listener.accept(); peer.settimeout(timeout)
        payload = b""
        while len(payload) < size:
            chunk = peer.recv(size - len(payload)); require(chunk != b"", "routed-smoke-closed"); payload += chunk
        return peer, payload
    except (TimeoutError, OSError) as error:
        if peer is not None: peer.close()
        raise QualificationError("routed-smoke-timeout") from error


def finish_live(live: list[tuple[subprocess.Popen[bytes], Capture]], first_error: BaseException | None = None) -> BaseException | None:
    process, capture = live.pop()
    try:
        kill_and_reap(process)
    except BaseException as error:
        if first_error is None: first_error = error
    try:
        require(SYNTHETIC_PSK.encode() not in b"".join(finish_capture(capture)), "secret-in-process-output")
    except BaseException as error:
        if first_error is None: first_error = error
    return first_error


def assert_routed_smoke(specs: tuple[BinarySpec, BinarySpec], directory: Path) -> None:
    client, server = specs
    ports = reserve_ports(6); servers, tcp_clients, udp_clients = ports[:2], ports[2:4], ports[4:]
    configs = tuple(directory / f"route-{name}.toml" for name in ("server", "tcp", "udp"))
    tcp = tcp_listener(0); tcp_dead = tcp_listener(0)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0)); udp.settimeout(READINESS_TIMEOUT_SECONDS)
    udp_dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp_dead.bind(("127.0.0.1", 0))
    write_tagged_config(configs[0], server, servers, None, True)
    write_tagged_config(configs[1], client, tcp_clients, (servers[0], int(tcp_dead.getsockname()[1])), True)
    write_tagged_config(configs[2], client, udp_clients, (int(udp_dead.getsockname()[1]), servers[1]), True, 2)
    configs[2].write_text(configs[2].read_text() + "\n[udp]\n", encoding="utf-8")
    live: list[tuple[subprocess.Popen[bytes], Capture]] = []; sockets = [tcp, tcp_dead, udp, udp_dead]; streams = []; first_error = None
    try:
        for spec, config, listens in ((server, configs[0], servers), (client, configs[1], tcp_clients)):
            process, capture = spawn_live(spec, config); live.append((process, capture))
            for listen in listens: wait_ready(process, listen).close()
        target = (127, 0, 0, 1, *int(tcp.getsockname()[1]).to_bytes(2, "big"))
        socks = socket.create_connection(("127.0.0.1", tcp_clients[1]), timeout=5); sockets.append(socks)
        stream = socks.makefile("rwb"); streams.append(stream); stream.write(bytes((5, 1, 0))); stream.flush()
        require(stream.read(2) == bytes((5, 0)), "route-tcp-method")
        stream.write(bytes((5, 1, 0, 1, *target))); stream.flush()
        require(stream.read(10)[:2] == bytes((5, 0)), "route-tcp-connect")
        stream.write(b"route-tcp"); stream.flush(); peer, payload = bounded_accept(tcp, 9); sockets.append(peer)
        require(payload == b"route-tcp", "route-tcp-forward")
        peer.sendall(b"route-tcp"); require(stream.read(9) == b"route-tcp", "route-tcp-reverse")
        first_error = finish_live(live, first_error)
        if first_error is not None: raise first_error
        process, capture = spawn_live(client, configs[2]); live.append((process, capture))
        for listen in udp_clients: wait_ready(process, listen).close()
        control = socket.create_connection(("127.0.0.1", udp_clients[0]), timeout=5); sockets.append(control)
        stream = control.makefile("rwb"); streams.append(stream); stream.write(bytes((5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0))); stream.flush()
        require(stream.read(2) == bytes((5, 0)), "route-udp-method"); reply = stream.read(10)
        app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); app.settimeout(5); sockets.append(app)
        target = (127, 0, 0, 1, *int(udp.getsockname()[1]).to_bytes(2, "big")); packet = bytes((0, 0, 0, 1, *target)) + b"route-udp"
        app.sendto(packet, ("127.0.0.1", int.from_bytes(reply[8:10], "big")))
        payload, peer = udp.recvfrom(64); udp.sendto(payload, peer)
        require(app.recv(64) == packet, "route-udp-round-trip")
    except BaseException as error:
        if first_error is None: first_error = error
    finally:
        while live: first_error = finish_live(live, first_error)
        for owned in [*streams, *sockets]:
            try: owned.close()
            except BaseException as error:
                if first_error is None: first_error = error
    if first_error is not None: raise first_error
    assert_tagged_rebindable(client, tcp_clients + udp_clients); assert_tagged_rebindable(server, servers)


def send_genuine_signal(process: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(process.pid, signal.SIGINT)


def kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        process.wait(timeout=2)
        return
    if sys.platform == "win32":
        process.kill()
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def signal_cycle(spec: BinarySpec, config: Path, listen: int, hold_connection: bool) -> None:
    connection: socket.socket | None = None
    process, capture = spawn_live(spec, config)
    status: int | None = None
    try:
        connection = wait_ready(process, listen)
        if not hold_connection:
            connection.close()
            connection = None
            time.sleep(0.1)
        send_genuine_signal(process)
        try:
            status = process.wait(timeout=PROCESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise QualificationError("signal-exit-timeout") from error
        if connection is not None:
            connection.settimeout(2)
            try:
                closed = connection.recv(1) == b""
            except (ConnectionResetError, ConnectionAbortedError):
                closed = True
            require(closed, "forced-connection-not-closed")
    finally:
        if connection is not None:
            connection.close()
        kill_and_reap(process)
        output, diagnostics = finish_capture(capture)
    require(status == 0, "signal-exit")
    require(SYNTHETIC_PSK.encode() not in output + diagnostics, "secret-in-process-output")


def assert_rebindable(spec: BinarySpec, listen: int, metrics: int | None) -> None:
    probes: list[socket.socket] = []
    try:
        probes.append(tcp_listener(listen))
        if spec.role == "server":
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", listen))
            probes.append(udp)
        if metrics is not None:
            probes.append(tcp_listener(metrics))
    except OSError as error:
        raise QualificationError("immediate-rebind-failed") from error
    finally:
        for probe in probes:
            probe.close()


def assert_tagged_rebindable(spec: BinarySpec, listens: tuple[int, ...]) -> None:
    for listen in listens:
        tcp = tcp_listener(listen)
        tcp.close()
        if spec.role == "server":
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                udp.bind(("127.0.0.1", listen))
            finally:
                udp.close()


def assert_signal_lifecycle(spec: BinarySpec, directory: Path, forced: bool) -> None:
    listen, metrics = reserve_ports(2)
    config = directory / f"{spec.name}-{'forced' if forced else 'graceful'}.toml"
    write_runtime_config(config, spec, listen, metrics, 0 if forced else 3000)
    signal_cycle(spec, config, listen, hold_connection=forced)
    assert_rebindable(spec, listen, metrics)
    signal_cycle(spec, config, listen, hold_connection=False)
    assert_rebindable(spec, listen, metrics)


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
    return parser.parse_args()


def main() -> int:
    try:
        arguments = parse_arguments()
        root = Path.cwd().resolve()
        context = hosted_context(arguments)
        specs = binary_specs(arguments, root)
        lines: list[str] = []
        with tempfile.TemporaryDirectory(prefix="ferrum2-m3-platform-") as temporary:
            directory = Path(temporary)
            for spec in specs:
                assert_cli_contract(spec, directory)
                assert_tagged_offline_config(spec, directory)
                assert_startup_rollback(spec, directory)
                assert_tagged_startup_rollback(spec, directory)
                assert_signal_lifecycle(spec, directory, forced=False)
                assert_signal_lifecycle(spec, directory, forced=True)
                lines.extend((artifact_line(context, spec), lifecycle_line(context, spec)))
            assert_routed_smoke(specs, directory)
        require(len(lines) == 4 and len(set(lines)) == 4, "duplicate-platform-evidence")
        for line in lines:
            print(line, flush=True)
        return 0
    except (OSError, QualificationError, subprocess.SubprocessError) as error:
        root = error.args[0] if isinstance(error, QualificationError) else type(error).__name__
        print(f"m3_platform_failure status=FAIL canonical_root={root}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
