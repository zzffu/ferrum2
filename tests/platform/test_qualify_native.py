from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import qualify_native


def binary_spec(role: str) -> qualify_native.BinarySpec:
    diagnostics = {
        "client": qualify_native.CLIENT_INVALID_STDERR,
        "server": qualify_native.SERVER_INVALID_STDERR,
    }
    return qualify_native.BinarySpec(
        f"ferrum2-{role}",
        Path(f"ferrum2-{role}"),
        Path("valid.toml"),
        Path("invalid.toml"),
        diagnostics[role],
        role,
    )


def startup_bind_stderr(root: tuple[str, int]) -> bytes:
    counters = {name: 0 for name in qualify_native.OWNER_COUNTER_FIELDS}
    report = {
        "actual_grace_deadline_elapsed_ns": None,
        "actual_grace_deadline_source": None,
        "cleanup_failure": None,
        "event": "process_shutdown_report",
        "forced_root_count": 0,
        "owner_baseline": counters,
        "owner_delta": counters,
        "owner_stopped": counters,
        "process_states": ["Validated", "Preparing", "Rollback", "Stopped"],
        "process_transitions": [
            {"state": state, "elapsed_ns": 0}
            for state in ["Validated", "Preparing", "Rollback", "Stopped"]
        ],
        "role": "client",
        "root": {"name": root[0], "id": root[1]},
        "root_error_category": "startup.bind",
        "root_exit_category": None,
        "root_exit_events": [],
        "shutdown_grace_ns": 1_000_000_000,
        "termination_cause": "PreparationFailed",
    }
    document = json.dumps(report, separators=(",", ":")).encode()
    return document + b"\n" + qualify_native.STARTUP_BIND_STDERR


class InvalidConfigContractTests(unittest.TestCase):
    def assert_accepts(self, spec: qualify_native.BinarySpec, stderr: bytes) -> None:
        result = subprocess.CompletedProcess([], 2, b"", stderr)
        qualify_native.assert_invalid_config_result(spec, result)

    def assert_rejects(self, spec: qualify_native.BinarySpec, stderr: bytes) -> None:
        result = subprocess.CompletedProcess([], 2, b"", stderr)
        with self.assertRaisesRegex(
            qualify_native.QualificationError, "invalid-offline-config"
        ):
            qualify_native.assert_invalid_config_result(spec, result)

    def test_client_requires_tagged_outbound_field(self) -> None:
        spec = binary_spec("client")
        self.assert_accepts(spec, qualify_native.CLIENT_INVALID_STDERR)
        self.assert_rejects(spec, qualify_native.SERVER_INVALID_STDERR)

    def test_server_requires_server_credentials_field(self) -> None:
        spec = binary_spec("server")
        self.assert_accepts(spec, qualify_native.SERVER_INVALID_STDERR)
        self.assert_rejects(spec, qualify_native.CLIENT_INVALID_STDERR)


class LocalContractModeTests(unittest.TestCase):
    def test_local_mode_cannot_replace_github_evidence(self) -> None:
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            with self.assertRaisesRegex(
                qualify_native.QualificationError,
                "local-contract-in-github-actions",
            ):
                qualify_native.require_local_contract_environment()


class NativeClientRootContractTests(unittest.TestCase):
    def test_windows_no_tun_network_owner_precedes_listener_roots(self) -> None:
        with patch.object(qualify_native.sys, "platform", "win32"):
            self.assertEqual(qualify_native.native_client_root("network"), ("network", 0))
            self.assertEqual(qualify_native.native_client_root("socks"), ("socks", 1))
            self.assertEqual(qualify_native.native_client_root("metrics"), ("metrics", 2))

    def test_windows_startup_report_requires_the_network_owner_offset(self) -> None:
        spec = binary_spec("client")
        with patch.object(qualify_native.sys, "platform", "win32"):
            qualify_native.assert_startup_bind_stderr(
                spec, startup_bind_stderr(("socks", 1)), "socks", 1_000_000_000
            )
            with self.assertRaisesRegex(
                qualify_native.QualificationError, "startup-bind-report-root"
            ):
                qualify_native.assert_startup_bind_stderr(
                    spec, startup_bind_stderr(("socks", 0)), "socks", 1_000_000_000
                )

    def test_portable_listener_roots_keep_their_native_order(self) -> None:
        with patch.object(qualify_native.sys, "platform", "linux"):
            self.assertEqual(qualify_native.native_client_root("socks"), ("socks", 0))
            self.assertEqual(qualify_native.native_client_root("metrics"), ("metrics", 1))

    def test_unknown_native_root_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            qualify_native.QualificationError, "startup-bind-root-name"
        ):
            qualify_native.native_client_root("unknown")


if __name__ == "__main__":
    unittest.main()
