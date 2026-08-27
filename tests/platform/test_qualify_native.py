from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
