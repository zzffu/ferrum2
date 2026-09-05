from __future__ import annotations

import json
import os
import subprocess
import shutil
import tempfile
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


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class HostFailureEvidenceTests(unittest.TestCase):
    def test_probe_failure_retains_product_metrics_and_logs_before_cleanup(self) -> None:
        owners = Path(__file__).resolve().parents[2] / "tools/powershell"
        with tempfile.TemporaryDirectory(prefix="ferrum2-qualification-failure-") as temporary:
            root = Path(temporary)
            for role in ("client", "server"):
                for stream in ("stdout", "stderr"):
                    (root / f"{role}.{stream}").write_text(f"{role} {stream}\n", encoding="utf-8")
            script = root / "probe.ps1"
            script.write_text(r"""
param([string]$Owners, [string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $Owners 'Ferrum2.Performance/HostExecution.ps1')
. (Join-Path $Owners 'Ferrum2.Performance/HostProduct.ps1')
. (Join-Path $Owners 'Ferrum2.Qualification.Host/HostQualification.ps1')
function Add-Ferrum2OwnedAddress { }
function Start-Ferrum2Support { return @{ tcp_port = 41002; udp_port = 41003 } }
function Fixture-Process($Role) {
    return @{ stdout = (Join-Path $FixtureRoot "$Role.stdout"); stderr = (Join-Path $FixtureRoot "$Role.stderr") }
}
function Start-Ferrum2ProductTrial {
    return @{ client = (Fixture-Process client); server = (Fixture-Process server); client_metrics_port = 41000; server_metrics_port = 41001 }
}
$script:stops = 0
function Stop-Ferrum2ProductTrial { $script:stops += 1 }
function Assert-Ferrum2QualificationWfpAbsent { }
function Get-Ferrum2QualificationWfpWitness { return @{} }
$script:metricsCalls = 0
function Get-Ferrum2Metrics($Port) {
    $script:metricsCalls += 1
    return "metrics $Port call $script:metricsCalls`n"
}
function Get-Ferrum2MetricValue { return 1 }
function Get-Ferrum2QualificationMetricLabelValue($Metrics, $Name, $Label, $Value, [switch]$AllowAbsent) {
    if ($Value -eq 'failure') { return 0 }
    return 1
}
function Invoke-Ferrum2OwnedCommand { throw 'injected TCP probe failure' }
$failure = $null
try {
    Invoke-Ferrum2HostQualificationChecks -Context @{ evidence_directory = $FixtureRoot } `
        -Candidate @{ harness = (Join-Path $FixtureRoot 'harness.exe') } `
        -Network @{ support_address = '198.19.0.1'; support_prefix_length = 32 } -Loopback @{} | Out-Null
} catch { $failure = $_.Exception.Message }
@{ failure = $failure; stops = $script:stops } | ConvertTo-Json -Compress
""", encoding="utf-8")
            completed = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), "-Owners", str(owners), "-FixtureRoot", str(root)],
                check=True, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(json.loads(completed.stdout), {"failure": "injected TCP probe failure", "stops": 2})
            self.assertEqual(
                {path.name: path.read_text(encoding="utf-8") for path in root.glob("*.txt")},
                {
                    "qualification-client-metrics-before.txt": "metrics 41000 call 1\n",
                    "qualification-server-metrics-before.txt": "metrics 41001 call 2\n",
                    "qualification-client-metrics-failure.txt": "metrics 41000 call 3\n",
                    "qualification-server-metrics-failure.txt": "metrics 41001 call 4\n",
                },
            )
            self.assertEqual(
                {path.name: path.read_text(encoding="utf-8") for path in (root / "process-logs").glob("*.log")},
                {f"trial-2-{role}.{stream}.log": f"{role} {stream}\n"
                 for role in ("client", "server") for stream in ("stdout", "stderr")},
            )


if __name__ == "__main__":
    unittest.main()
