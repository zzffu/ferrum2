"""Trial failure evidence survives cleanup; all product/network operations are injected."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OWNERS = Path(__file__).resolve().parents[2] / "tools/powershell/Ferrum2.Performance"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class TrialFailureTests(unittest.TestCase):
    def test_both_workload_phases_retain_before_after_metrics_and_all_logs(self) -> None:
        for phase in ("warmup-readiness", "active-completion"):
            with self.subTest(phase=phase):
                self.check_failure(phase, export_failure=False)

    def test_log_export_failure_preserves_the_workload_error_and_metrics(self) -> None:
        self.check_failure("active-completion", export_failure=True)

    def check_failure(self, phase: str, *, export_failure: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-trial-failure-") as temporary:
            root = Path(temporary)
            for role in ("client", "server", "workload"):
                for stream in ("stdout", "stderr"):
                    (root / f"{role}.{stream}").write_text(f"{role} {stream}\n", encoding="utf-8")
            script = root / "probe.ps1"
            script.write_text(
                r"""
param([string]$Owners, [string]$FixtureRoot, [string]$Phase, [string]$ExportFailure)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
. (Join-Path $Owners 'HostExecution.ps1')
. (Join-Path $Owners 'HostProduct.ps1')
function Fixture-Process($Role, $Id) {
    return @{ pid = $Id; stdout = (Join-Path $FixtureRoot "$Role.stdout"); stderr = (Join-Path $FixtureRoot "$Role.stderr") }
}
function Start-Ferrum2ProductTrial {
    return @{ client = (Fixture-Process client 1); server = (Fixture-Process server 2); client_metrics_port = 41000; server_metrics_port = 41001 }
}
$script:metricsCalls = 0
function Get-Ferrum2Metrics($Port) {
    $script:metricsCalls += 1
    return "metrics $Port call $script:metricsCalls`n"
}
function Start-Ferrum2OwnedNativeProcess { return Fixture-Process workload 3 }
function Wait-Ferrum2Text($Path, $Pattern, $TimeoutSeconds) {
    if ($Path.EndsWith('active-ready') -and $Phase -eq 'active-completion') {
        [IO.File]::WriteAllText($Path, "ready`n")
        return
    }
    throw 'injected workload failure'
}
function Get-Ferrum2ProcessCpuMilliseconds { return 1 }
function Stop-Ferrum2OwnedProcess { }
$script:stopped = $false
function Stop-Ferrum2ProductTrial { $script:stopped = $true }
function Set-Ferrum2HostPerformanceState { }
if ($ExportFailure -eq 'true') {
    function Export-Ferrum2OwnedCommandFailureLogs { throw 'injected export failure' }
}
$failure = $null
try {
    Invoke-Ferrum2HostTrial -Context @{ evidence_directory = $FixtureRoot } `
        -Trial @{ sequence = 1; scenario = 'tcp-single-flow'; topology = 'EndToEnd'; warmup_seconds = 2; active_seconds = 10 } `
        -Member @{} -Harness (Join-Path $FixtureRoot 'harness.exe') `
        -Network @{ support_address = '198.18.0.1' } -Loopback @{} `
        -Support @{ tcp_port = 41002; udp_port = 41003 } | Out-Null
} catch { $failure = $_.Exception.Message }
@{ failure = $failure; stopped = $script:stopped } | ConvertTo-Json -Compress
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), "-Owners", str(OWNERS),
                 "-FixtureRoot", str(root), "-Phase", phase,
                 "-ExportFailure", str(export_failure).lower()],
                check=True, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                json.loads(completed.stdout),
                {"failure": "injected workload failure", "stopped": True},
            )
            actual = {
                path.name: path.read_text(encoding="utf-8")
                for path in (root / "trials/001").glob("*.txt")
            }
            self.assertEqual(actual, {
                "client-metrics-before.txt": "metrics 41000 call 1\n",
                "server-metrics-before.txt": "metrics 41001 call 2\n",
                "client-metrics-failure.txt": "metrics 41000 call 3\n",
                "server-metrics-failure.txt": "metrics 41001 call 4\n",
                "failure-phase.txt": f"{phase}\n",
            })
            logs = {
                path.name: path.read_text(encoding="utf-8")
                for path in (root / "process-logs").glob("*.log")
            }
            self.assertEqual(logs, {} if export_failure else {
                f"trial-1-{role}.{stream}.log": f"{role} {stream}\n"
                for role in ("client", "server", "workload")
                for stream in ("stdout", "stderr")
            })
