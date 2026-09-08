"""Finite loopback ownership and injected startup tests; no adapter or route mutation."""
import contextlib
import http.server
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ROOT / "tools/powershell/Ferrum2.Qualification.Host"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class ListenerReservationTests(unittest.TestCase):
    def run_script(self, body: str) -> None:
        for family in ("IPv4", "IPv6"):
            with self.subTest(address_family=family):
                self.run_family_script(body, family)

    def run_family_script(self, body: str, family: str, *, environment: dict[str, str] | None = None) -> dict:
        with tempfile.TemporaryDirectory(prefix="ferrum2-port-contract-") as temporary:
            root = Path(temporary)
            script = root / "test.ps1"
            script.write_text(r'''
param([string]$Owners, [string]$Root, [string]$AddressFamily)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
. (Join-Path $Owners 'AddressFamily.ps1')
. (Join-Path $Owners 'HostOwnership.ps1')
. (Join-Path $Owners 'HostExecution.ps1')
$profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
$network = New-Ferrum2HostNetworkIdentity -RunId '0123456789ab' -AddressFamily $AddressFamily
$context = @{ address_family = $AddressFamily; run_id = '0123456789ab'; run_root = $Root; evidence_directory = $Root;
    ledger = @{ resources = @{ routes = @() } } }
$ranges = @(
    @{ protocol = 'tcp'; start_port = 49152; end_port = 65535 },
    @{ protocol = 'udp'; start_port = 49152; end_port = 65535 }
)
function Assert-BindState {
    param([uint16]$Port, [string]$Protocol, [bool]$Available)
    $socket = if ($Protocol -eq 'tcp') {
        [Net.Sockets.Socket]::new($profile.socket_family,
            [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    } else {
        [Net.Sockets.Socket]::new($profile.socket_family,
            [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    }
    $bound = $false
    try {
        $socket.ExclusiveAddressUse = $true
        if ($AddressFamily -ceq 'IPv6') { $socket.DualMode = $false }
        try { $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($profile.loopback_address), $Port)); $bound = $true }
        catch [Net.Sockets.SocketException] { }
    } finally { $socket.Dispose() }
    if ($bound -ne $Available) { throw "unexpected $Protocol reservation availability" }
}
''' + body, encoding="utf-8")
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), str(OWNERS), str(root), family],
                capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return {
                path.name: tomllib.loads(path.read_text(encoding="utf-8"))
                for path in root.glob("configs/*/*.toml")
            }

    def test_ipv6_metrics_ignores_inherited_http_proxy(self) -> None:
        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.server.requests += 1
                body = self.server.metrics.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class IPv6Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6

        with contextlib.ExitStack() as stack:
            endpoint = stack.enter_context(IPv6Server(("::1", 0), MetricsHandler))
            proxy = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", 0), MetricsHandler))
            endpoint.metrics = "ferrum2_tun_session_active 1\n"
            proxy.metrics = "ferrum2_tun_session_active 999\n"
            threads = []
            for server in (endpoint, proxy):
                server.requests = 0
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
                thread.start()
                threads.append(thread)
            try:
                proxy_names = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
                environment = {key: value for key, value in os.environ.items() if key.upper() not in proxy_names}
                proxy_url = f"http://127.0.0.1:{proxy.server_port}"
                environment.update(HTTP_PROXY=proxy_url, HTTPS_PROXY=proxy_url, ALL_PROXY=proxy_url, NO_PROXY="")
                self.run_family_script(
                    f'$metrics = Get-Ferrum2Metrics -Port {endpoint.server_port} -AddressFamily IPv6\n'
                    'if ($metrics -cne "ferrum2_tun_session_active 1`n") { throw "metrics came from inherited proxy" }\n',
                    "IPv6",
                    environment=environment,
                )
                self.assertEqual({"endpoint": endpoint.requests, "proxy": proxy.requests}, {"endpoint": 1, "proxy": 0})
            finally:
                for server in (endpoint, proxy):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)

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
$reservation = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp -AddressFamily $AddressFamily
try {
    if ($reservation.port -ge 49152 -or $reservation.port -lt 1024) { throw 'selected dynamic port' }
    if ($AddressFamily -ceq 'IPv6') {
        foreach ($socket in $reservation.sockets) {
            if ($socket.DualMode) { throw 'IPv6 reservation accepted IPv4-mapped traffic' }
        }
    }
    Assert-BindState -Port $reservation.port -Protocol tcp -Available $false
    Assert-BindState -Port $reservation.port -Protocol udp -Available $false
} finally { Close-Ferrum2PortReservation -Reservation $reservation }
Close-Ferrum2PortReservation -Reservation $reservation
Assert-BindState -Port $reservation.port -Protocol tcp -Available $true
Assert-BindState -Port $reservation.port -Protocol udp -Available $true
''')

    def test_partial_dual_bind_releases_tcp_before_another_candidate(self) -> None:
        self.run_script(r'''
$first = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp -AddressFamily $AddressFamily
$second = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp -AddressFamily $AddressFamily
$blocked = $first.port
$next = $second.port
Close-Ferrum2PortReservation -Reservation $first
Close-Ferrum2PortReservation -Reservation $second
$udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($profile.loopback_address), $blocked))
$script:candidates = [Collections.Generic.Queue[int]]::new()
$script:candidates.Enqueue($blocked); $script:candidates.Enqueue($next)
function Get-Random { param($Minimum, $Maximum) return $script:candidates.Dequeue() }
$result = $null
try {
    $result = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp -AddressFamily $AddressFamily
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
$script:first = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp -AddressFamily $AddressFamily
$script:calls = 0
function Get-Ferrum2DynamicPortRanges { return $ranges }
function New-Ferrum2PortReservation {
    $script:calls += 1
    if ($script:calls -eq 2) { throw 'injected second reservation failure' }
    return $script:first
}
$failure = $null
try { New-Ferrum2ProductPorts -Context $context -Sequence 1 | Out-Null }
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
function Complete-Ferrum2OwnedAdapterIdentity { return @{ ifIndex = 7; InterfaceGuid = '01234567-89ab-cdef-0123-456789abcdef' } }
function Get-NetRoute { return @{ NextHop = $profile.unspecified_address; RouteMetric = 1 } }
function Get-NetIPInterface { return @{ NlMtu = 1420 } }
function Write-Ferrum2HostLedger { }
function Export-Ferrum2ProductFailureLogs { }
$failure = $null
try {
    Start-Ferrum2HostProduct -Context $context -Sequence 1 -Loopback @{ interface_alias = 'fixture-loopback' } `
        -Member @{ client = "$Root/client.exe"; server = "$Root/server.exe" } `
        -Network $network | Out-Null
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
$actual = @(Get-Ferrum2DynamicPortRanges -Context $context -Sequence 1)
if ($actual.Count -ne 2 -or $script:owned.Count -ne 0) { throw 'native range readers did not join' }
$record = Get-Content (Join-Path $Root 'port-ranges/1.json') -Raw | ConvertFrom-Json
if ($record.sequence -ne 1 -or $record.address_family -cne $AddressFamily -or
    $record.dynamic_ranges.Count -ne 2) { throw 'missing range evidence' }
$reservation = New-Ferrum2PortReservation -DynamicRanges $actual -Protocols tcp,udp -AddressFamily $AddressFamily
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
try { Wait-Ferrum2Metric -Process @{ pid = 42 } -Port 1234 -Name ferrum2_network_generation -Minimum 1 -AddressFamily $AddressFamily }
catch { $failure = $_.Exception.Message }
if ($null -eq $failure -or $script:metricsPolled) { throw 'exited process was accepted or metrics were polled' }
''')

    def test_configs_use_only_selected_family_and_bracket_ipv6_endpoints(self) -> None:
        for family, loopback, tun_field, bind_field, host_prefix, tun_prefix in (
            ("IPv4", "127.0.0.1", "ipv4_address", "inet4_bind_address", 32, 30),
            ("IPv6", "::1", "ipv6_address", "inet6_bind_address", 128, 126),
        ):
            with self.subTest(address_family=family):
                configs = self.run_family_script(r'''
$reset = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($network.reset_address), 443)
Write-Ferrum2HostConfigs -Context $context -Network $network `
    -Loopback @{ interface_alias = 'fixture-loopback' } -AdapterName 'fixture' `
    -ServerPort 41001 -ClientMetricsPort 41002 -ServerMetricsPort 41003 `
    -Sequence 1 -ResetProbeEndpoint $reset | Out-Null
''', family)
                client, server = configs["client.toml"], configs["server.toml"]
                endpoint_host = f"[{loopback}]" if family == "IPv6" else loopback
                self.assertEqual(client["outbounds"][0]["server"], f"{endpoint_host}:41001")
                self.assertEqual(server["inbounds"][0]["listen"], f"{endpoint_host}:41001")
                self.assertEqual(client["metrics"]["listen"], f"{endpoint_host}:41002")
                self.assertEqual(server["metrics"]["listen"], f"{endpoint_host}:41003")
                self.assertEqual(client["outbounds"][0][bind_field], loopback)
                self.assertTrue(client["tun"][tun_field].endswith(f"/{tun_prefix}"))
                support = server["outbounds"][0][bind_field]
                self.assertEqual(client["tun"]["route_address"], [f"{support}/{host_prefix}"])
                reset_endpoint = client["outbounds"][1]["server"]
                if family == "IPv6":
                    self.assertTrue(reset_endpoint.startswith("[fd00:"))
                    self.assertTrue(reset_endpoint.endswith("]:443"))
                    self.assertNotIn("ipv4_address", client["tun"])
                    for outbound in client["outbounds"] + server["outbounds"]:
                        self.assertNotIn("inet4_bind_address", outbound)
                    self.assertNotIn("127.0.0.1", str(configs))
                else:
                    self.assertNotIn("ipv6_address", client["tun"])
                    self.assertNotIn("inet6_bind_address", client["outbounds"][0])
                    self.assertNotIn("[", reset_endpoint)

    def test_tcp_udp_dynamic_exclusions_are_applied_before_binding(self) -> None:
        self.run_script(r'''
$candidate = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp -AddressFamily $AddressFamily
$port = $candidate.port
Close-Ferrum2PortReservation -Reservation $candidate
$script:candidates = [Collections.Generic.Queue[int]]::new()
$script:candidates.Enqueue(50000)
$script:candidates.Enqueue(60000)
$script:candidates.Enqueue($port)
$separateRanges = @(
    @{ protocol = 'tcp'; start_port = 49152; end_port = 55000 },
    @{ protocol = 'udp'; start_port = 55001; end_port = 65535 }
)
function Get-Random { param($Minimum, $Maximum) return $script:candidates.Dequeue() }
$reservation = New-Ferrum2PortReservation -DynamicRanges $separateRanges -Protocols tcp,udp -AddressFamily $AddressFamily
try {
    if ($reservation.port -ne $port) { throw 'selected TCP or UDP dynamic allocation port' }
    Assert-BindState -Port $port -Protocol tcp -Available $false
    Assert-BindState -Port $port -Protocol udp -Available $false
} finally { Close-Ferrum2PortReservation -Reservation $reservation }
''')
