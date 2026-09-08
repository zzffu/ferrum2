"""Injected product-start failures; no process launch or host networking."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ROOT / "tools/powershell/Ferrum2.Qualification.Host"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class ProductStartupFailureTests(unittest.TestCase):
    def test_startup_failure_preserves_every_started_product_log(self) -> None:
        for failed_role, expected_roles in (("client", ["client"]), ("server", ["client", "server"])):
            with self.subTest(failed_role=failed_role):
                self.check_failure(failed_role, expected_roles)

    def test_export_failure_does_not_replace_the_startup_error(self) -> None:
        self.check_failure("server", [], export_failure=True)

    def check_failure(self, failed_role: str, expected_roles: list[str], *, export_failure: bool = False) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-startup-evidence-") as directory:
            root = Path(directory)
            for role in ("client", "server"):
                for stream in ("stdout", "stderr"):
                    (root / f"qualification-1-{role}.{stream}.log").write_text(f"synthetic {role} {stream}\n", encoding="utf-8")
            script = root / "probe.ps1"
            script.write_text(
                r"""
param([string]$Owners, [string]$FixtureRoot, [string]$FailedRole, [string]$ExportFailure)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
. (Join-Path $Owners 'HostExecution.ps1')
. (Join-Path $Owners 'HostProduct.ps1')
function Set-Ferrum2OwnedAdapterPlan { }
function New-Ferrum2ProductPorts {
    return @{ dynamic_ranges = @(@{ protocol = 'tcp'; start_port = 49152; end_port = 65535 }); client_metrics = @{ port = 41001; sockets = @() };
        server = @{ port = 41003; sockets = @() }; server_metrics = @{ port = 41002; sockets = @() } }
}
function Add-Ferrum2OwnedPort { }
function Add-Ferrum2OwnedFirewallRule { }
function Complete-Ferrum2FirewallInterface { }
function Write-Ferrum2HostConfigs { return @{ client = 'client.toml'; server = 'server.toml' } }
function Invoke-Ferrum2ConfigCheck { }
function Start-Ferrum2OwnedNativeProcess {
    param($Context, $Application, $Arguments, $WorkingDirectory, $LogPrefix, $Purpose)
    return @{
        stdout = Join-Path $FixtureRoot "$LogPrefix.stdout.log"
        stderr = Join-Path $FixtureRoot "$LogPrefix.stderr.log"
    }
}
function Wait-Ferrum2Metric {
    param($Process, $Port, $Name, $Minimum)
    if (($FailedRole -eq 'client' -and $Name -eq 'ferrum2_tun_session_active') -or
        ($FailedRole -eq 'server' -and $Name -eq 'ferrum2_network_generation')) {
        throw 'injected product readiness failure'
    }
}
function Complete-Ferrum2OwnedAdapterIdentity { return @{ ifIndex = 7 } }
function Get-NetRoute { return @{ NextHop = '0.0.0.0'; RouteMetric = 1 } }
function Get-NetIPInterface { return @{ NlMtu = 1420 } }
function Write-Ferrum2HostLedger { }
function Get-Ferrum2HostRouteProofs { throw 'unexpected route proof after readiness failure' }
if ($ExportFailure -eq 'true') {
    function Export-Ferrum2OwnedCommandFailureLogs { throw 'injected export failure' }
}
$context = @{
    evidence_directory = $FixtureRoot
    ledger = @{ resources = @{ routes = @() } }
}
$failure = $null
try {
    Start-Ferrum2HostProduct -Context $context `
        -Member @{ client = (Join-Path $FixtureRoot 'client.exe'); server = (Join-Path $FixtureRoot 'server.exe') } `
        -Network @{ adapter_name_prefix = 'fixture'; tun_address = '198.18.0.2'; support_address = '198.18.0.1' } `
        -Loopback @{ interface_alias = 'fixture-loopback' } -Sequence 1 | Out-Null
} catch { $failure = $_.Exception.Message }
@{ failure = $failure } | ConvertTo-Json -Compress
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), "-Owners", str(OWNERS),
                 "-FixtureRoot", str(root), "-FailedRole", failed_role,
                 "-ExportFailure", str(export_failure).lower()],
                check=True, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(json.loads(completed.stdout), {"failure": "injected product readiness failure"})
            exports = root / "process-logs"
            actual = {p.read_text(encoding="utf-8") for p in exports.glob("*.log")}
            expected = {
                f"synthetic {role} {stream}\n"
                for role in expected_roles for stream in ("stdout", "stderr")
            }
            self.assertEqual(actual, expected)
