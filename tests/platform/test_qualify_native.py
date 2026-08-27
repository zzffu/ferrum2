from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import native_contract as contract
import qualify_native


def binary_spec(role: str) -> contract.BinarySpec:
    diagnostics = {
        "client": contract.CLIENT_INVALID_STDERR,
        "server": contract.SERVER_INVALID_STDERR,
    }
    return contract.BinarySpec(
        f"ferrum2-{role}",
        Path(f"ferrum2-{role}"),
        Path("valid.toml"),
        Path("invalid.toml"),
        diagnostics[role],
        role,
    )


def startup_bind_stderr(root: tuple[str, int]) -> bytes:
    counters = {name: 0 for name in contract.OWNER_COUNTER_FIELDS}
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
    return document + b"\n" + contract.STARTUP_BIND_STDERR


class InvalidConfigContractTests(unittest.TestCase):
    def assert_accepts(self, spec: contract.BinarySpec, stderr: bytes) -> None:
        result = subprocess.CompletedProcess([], 2, b"", stderr)
        contract.assert_invalid_config_result(spec, result)

    def assert_rejects(self, spec: contract.BinarySpec, stderr: bytes) -> None:
        result = subprocess.CompletedProcess([], 2, b"", stderr)
        with self.assertRaisesRegex(
            contract.QualificationError, "invalid-offline-config"
        ):
            contract.assert_invalid_config_result(spec, result)

    def test_client_requires_tagged_outbound_field(self) -> None:
        spec = binary_spec("client")
        self.assert_accepts(spec, contract.CLIENT_INVALID_STDERR)
        self.assert_rejects(spec, contract.SERVER_INVALID_STDERR)

    def test_server_requires_server_credentials_field(self) -> None:
        spec = binary_spec("server")
        self.assert_accepts(spec, contract.SERVER_INVALID_STDERR)
        self.assert_rejects(spec, contract.CLIENT_INVALID_STDERR)


class LocalContractModeTests(unittest.TestCase):
    def test_local_mode_cannot_replace_github_evidence(self) -> None:
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            with self.assertRaisesRegex(
                contract.QualificationError,
                "local-contract-in-github-actions",
            ):
                qualify_native.require_local_contract_environment()


class NativeClientRootContractTests(unittest.TestCase):
    def test_startup_report_uses_semantic_root_name_not_registration_order(self) -> None:
        spec = binary_spec("client")
        contract.assert_startup_bind_stderr(
            spec, startup_bind_stderr(("socks", 73)), "socks", 1_000_000_000
        )

    def test_startup_report_rejects_wrong_root_name(self) -> None:
        spec = binary_spec("client")
        with self.assertRaisesRegex(contract.QualificationError, "startup-bind-report-root"):
            contract.assert_startup_bind_stderr(
                spec, startup_bind_stderr(("metrics", 0)), "socks", 1_000_000_000
            )

    def test_startup_report_rejects_negative_root_id(self) -> None:
        spec = binary_spec("client")
        with self.assertRaisesRegex(contract.QualificationError, "startup-bind-report-root"):
            contract.assert_startup_bind_stderr(
                spec, startup_bind_stderr(("socks", -1)), "socks", 1_000_000_000
            )


if __name__ == "__main__":
    unittest.main()
