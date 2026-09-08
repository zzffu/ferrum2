"""Finite loopback ownership and injected startup tests; no adapter or route mutation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ROOT / "tools/powershell/Ferrum2.Qualification.Host"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class ListenerReservationTests(unittest.TestCase):
    def run_script(self, body: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-port-contract-") as temporary:
            root = Path(temporary)
            script = root / "test.ps1"
            script.write_text(r'''
param([string]$Owners, [string]$Root)
$ErrorActionPreference = 'Stop'
. (Join-Path $Owners 'HostExecution.ps1')
$ranges = @(
    @{ protocol = 'tcp'; start_port = 49152; end_port = 65535 },
    @{ protocol = 'udp'; start_port = 49152; end_port = 65535 }
)
function Assert-BindState {
    param([uint16]$Port, [string]$Protocol, [bool]$Available)
    $socket = if ($Protocol -eq 'tcp') {
        [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    } else {
        [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    }
    $bound = $false
    try {
        $socket.ExclusiveAddressUse = $true
        try { $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $Port)); $bound = $true }
        catch [Net.Sockets.SocketException] { }
    } finally { $socket.Dispose() }
    if ($bound -ne $Available) { throw "unexpected $Protocol reservation availability" }
}
''' + body, encoding="utf-8")
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), str(OWNERS), str(root)],
                capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_range_readback_is_closed_and_locale_independent(self) -> None:
        self.run_script(r'''
foreach ($text in @("Start Port : 49152`nNumber of Ports : 16384", "起始端口 : 49152`n端口数量 : 16384")) {
    $range = ConvertFrom-Ferrum2DynamicPortRange -Text $text -Protocol tcp
    if ($range.protocol -cne 'tcp' -or $range.start_port -ne 49152 -or $range.end_port -ne 65535) {
        throw 'wrong dynamic range'
    }
}
foreach ($text in @('unknown', "Start : 0`nCount : 10", "Start : 65535`nCount : 2",
    "Start : 1024`nCount : 0", "Start : 1024`nCount : 10`nExtra : 2", "Start : 999999999999`nCount : 1")) {
    $rejected = $false
    try { ConvertFrom-Ferrum2DynamicPortRange -Text $text -Protocol udp | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'invalid dynamic range accepted' }
}
''')

    def test_reserved_tcp_and_udp_reject_competitors_until_handoff(self) -> None:
        self.run_script(r'''
$reservation = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp
try {
    if ($reservation.port -ge 49152 -or $reservation.port -lt 1024) { throw 'selected dynamic port' }
    Assert-BindState -Port $reservation.port -Protocol tcp -Available $false
    Assert-BindState -Port $reservation.port -Protocol udp -Available $false
} finally { Close-Ferrum2PortReservation -Reservation $reservation }
Close-Ferrum2PortReservation -Reservation $reservation
Assert-BindState -Port $reservation.port -Protocol tcp -Available $true
Assert-BindState -Port $reservation.port -Protocol udp -Available $true
''')

    def test_partial_dual_bind_releases_tcp_before_another_candidate(self) -> None:
        self.run_script(r'''
$first = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp
$second = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp
$blocked = $first.port
$next = $second.port
Close-Ferrum2PortReservation -Reservation $first
Close-Ferrum2PortReservation -Reservation $second
$udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $blocked))
$script:candidates = [Collections.Generic.Queue[int]]::new()
$script:candidates.Enqueue($blocked); $script:candidates.Enqueue($next)
function Get-Random { param($Minimum, $Maximum) return $script:candidates.Dequeue() }
$result = $null
try {
    $result = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp
    if ($result.port -ne $next) { throw 'did not move past occupied UDP port' }
    Assert-BindState -Port $blocked -Protocol tcp -Available $true
    Assert-BindState -Port $next -Protocol tcp -Available $false
} finally {
    Close-Ferrum2PortReservation -Reservation $result
    $udp.Dispose()
}
''')

    def test_cohort_allocation_failure_releases_earlier_reservation(self) -> None:
        self.run_script(r'''
$script:first = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp
$script:calls = 0
function Get-Ferrum2DynamicPortRanges { return $ranges }
function New-Ferrum2PortReservation {
    $script:calls += 1
    if ($script:calls -eq 2) { throw 'injected second reservation failure' }
    return $script:first
}
$failure = $null
try { New-Ferrum2ProductPorts -Context @{} -Sequence 1 | Out-Null }
catch { $failure = $_.Exception.Message }
if ($failure -cne 'injected second reservation failure') { throw 'wrong allocation failure' }
Assert-BindState -Port $script:first.port -Protocol tcp -Available $true
''')

    def test_product_handoff_holds_server_ports_through_client_startup(self) -> None:
        self.run_script(r'''
. (Join-Path $Owners 'HostProduct.ps1')
function Get-Ferrum2DynamicPortRanges { return $ranges }
function Set-Ferrum2OwnedAdapterPlan { }
function Add-Ferrum2OwnedPort { }
function Add-Ferrum2OwnedFirewallRule { }
function Complete-Ferrum2FirewallInterface { }
function Write-Ferrum2HostConfigs {
    param($Context, $Network, $Loopback, $AdapterName, $ServerPort,
        $ClientMetricsPort, $ServerMetricsPort, $Sequence)
    $script:chosen = @{ client = $ClientMetricsPort; server = $ServerPort; metrics = $ServerMetricsPort }
    return @{ client = 'client.toml'; server = 'server.toml' }
}
function Invoke-Ferrum2ConfigCheck { }
function Start-Ferrum2OwnedNativeProcess {
    param($Context, $Application, $Arguments, $WorkingDirectory, $LogPrefix, $Purpose)
    if ($Application -eq "$Root/server.exe") {
        Assert-BindState -Port $script:chosen.server -Protocol tcp -Available $true
        Assert-BindState -Port $script:chosen.server -Protocol udp -Available $true
        Assert-BindState -Port $script:chosen.metrics -Protocol tcp -Available $true
        throw 'injected server startup failure'
    }
    Assert-BindState -Port $script:chosen.client -Protocol tcp -Available $true
    return @{ pid = 1 }
}
function Wait-Ferrum2Metric {
    Assert-BindState -Port $script:chosen.server -Protocol tcp -Available $false
    Assert-BindState -Port $script:chosen.server -Protocol udp -Available $false
    Assert-BindState -Port $script:chosen.metrics -Protocol tcp -Available $false
}
function Complete-Ferrum2OwnedAdapterIdentity { return @{ ifIndex = 7 } }
function Get-NetRoute { return @{ NextHop = '0.0.0.0'; RouteMetric = 1 } }
function Get-NetIPInterface { return @{ NlMtu = 1420 } }
function Write-Ferrum2HostLedger { }
function Export-Ferrum2ProductFailureLogs { }
$context = @{ ledger = @{ resources = @{ routes = @() } } }
$failure = $null
try {
    Start-Ferrum2HostProduct -Context $context -Sequence 1 -Loopback @{ interface_alias = 'fixture-loopback' } `
        -Member @{ client = "$Root/client.exe"; server = "$Root/server.exe" } `
        -Network @{ adapter_name_prefix = 'fixture'; tun_address = '198.18.0.2'; support_address = '198.18.0.1' } | Out-Null
} catch { $failure = $_.Exception.Message }
if ($failure -cne 'injected server startup failure') { throw "wrong startup failure: $failure" }
foreach ($port in $script:chosen.Values) { Assert-BindState -Port $port -Protocol tcp -Available $true }
Assert-BindState -Port $script:chosen.server -Protocol udp -Available $true
''')

    @unittest.skipUnless(os.name == "nt", "native netsh readback requires Windows")
    def test_joined_native_readback_drives_reservation_and_records_ranges(self) -> None:
        self.run_script(r'''
Add-Type -Path (Join-Path $Owners 'HostProcessOwner.cs')
$script:owned = [Collections.Generic.HashSet[int]]::new()
function Add-Ferrum2OwnedProcess { param($Context, $ProcessId, $Executable, $Purpose)
    [void]$script:owned.Add($ProcessId)
}
function Remove-Ferrum2OwnedProcessRecord { param($Context, $ProcessId)
    [void]$script:owned.Remove($ProcessId)
}
function Write-AtomicJsonFile { param($Path, $Document)
    $Document | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding utf8
}
$context = @{ run_root = $Root; evidence_directory = $Root }
$actual = @(Get-Ferrum2DynamicPortRanges -Context $context -Sequence 1)
if ($actual.Count -ne 2 -or $script:owned.Count -ne 0) { throw 'native range readers did not join' }
$record = Get-Content (Join-Path $Root 'port-ranges/1.json') -Raw | ConvertFrom-Json
if ($record.sequence -ne 1 -or $record.ipv4_dynamic_ranges.Count -ne 2) { throw 'missing range evidence' }
$reservation = New-Ferrum2PortReservation -DynamicRanges $actual -Protocols tcp,udp
try {
    foreach ($range in $actual) {
        if ($reservation.port -ge $range.start_port -and $reservation.port -le $range.end_port) {
            throw 'listener overlaps actual dynamic allocation range'
        }
    }
    Assert-BindState -Port $reservation.port -Protocol tcp -Available $false
} finally { Close-Ferrum2PortReservation -Reservation $reservation }
''')

    def test_early_process_exit_does_not_wait_for_metrics_timeout(self) -> None:
        self.run_script(r'''
Add-Type -TypeDefinition 'public static class Ferrum2HostProcessGroup {
    public static bool Wait(uint pid, uint ms) { return true; }
    public static int ExitCode(uint pid) { return 1; }
}'
$script:metricsPolled = $false
function Get-Ferrum2Metrics { $script:metricsPolled = $true; throw 'metrics must not be polled after process exit' }
$failure = $null
try { Wait-Ferrum2Metric -Process @{ pid = 42 } -Port 1234 -Name ferrum2_network_generation -Minimum 1 }
catch { $failure = $_.Exception.Message }
if ($null -eq $failure -or $script:metricsPolled) { throw 'exited process was accepted or metrics were polled' }
''')
