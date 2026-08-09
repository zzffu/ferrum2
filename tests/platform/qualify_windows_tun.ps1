param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("lifecycle", "tcp")]
    [string]$Mode,
    [string]$WintunZip
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
}

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$zipInput = if ($WintunZip) { $WintunZip } elseif ($env:FERRUM2_WINTUN_ZIP) { $env:FERRUM2_WINTUN_ZIP } else { throw "Wintun ZIP path is required via -WintunZip or FERRUM2_WINTUN_ZIP" }
$zip = (Resolve-Path -LiteralPath $zipInput).Path
$expectedZipHash = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
$expectedDllHash = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
$expectedExports = @(
    "WintunAllocateSendPacket", "WintunCloseAdapter", "WintunCreateAdapter",
    "WintunDeleteDriver", "WintunEndSession", "WintunGetAdapterLUID", "WintunGetReadWaitEvent",
    "WintunGetRunningDriverVersion", "WintunReceivePacket",
    "WintunOpenAdapter", "WintunReleaseReceivePacket", "WintunSendPacket", "WintunSetLogger",
    "WintunStartSession"
) | Sort-Object

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("ferrum2-m15-tun-" + [Guid]::NewGuid().ToString("N"))
$binary = Join-Path $workspace "target\debug\ferrum2-client.exe"
$siblingDll = Join-Path (Split-Path -Parent $binary) "wintun.dll"
$adapterName = "Ferrum2-M15-$PID"
$config = Join-Path $work "client.toml"
$failureConfig = Join-Path $work "client-failure.toml"
$ownedRoutes = [System.Collections.Generic.List[object]]::new()
$activeProcess = $null
$ownedInterfaceIndex = $null
$heldMetrics = $null
$udp4 = $null
$foundation = 0
$tcpRows = 0
$serverProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$ownedAddresses = [System.Collections.Generic.List[object]]::new()
$ownedTargetRoutes = [System.Collections.Generic.List[object]]::new()
$tcpResources = [System.Collections.Generic.List[System.IDisposable]]::new()
$usedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$createdSiblingDll = $false
$completed = $false

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Find-Dumpbin {
    $command = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $candidate = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" | Select-Object -First 1
        if ($candidate) { return $candidate }
    }
    throw "dumpbin.exe is required for the exact export check"
}

function Wait-AdapterReady([string]$Name, [int]$TimeoutSeconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
        }
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $v4 = @($addresses | Where-Object { $_.IPAddress -eq "198.18.0.2" -and $_.PrefixLength -eq 30 -and $_.AddressState -eq "Preferred" })
            $v6 = @($addresses | Where-Object { $_.IPAddress -eq "fd00::2" -and $_.PrefixLength -eq 126 -and $_.AddressState -eq "Preferred" })
            if ($v4.Count -eq 1 -and $v6.Count -eq 1) { return $adapter }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "adapter readiness timeout"
}

function Wait-AdapterAbsent([string]$Name, [int]$TimeoutSeconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (-not (Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "adapter cleanup timeout"
}

function Wait-AdapterAppeared([string]$Name, [int]$TimeoutSeconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $adapter = Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction SilentlyContinue
        if ($adapter) { return $adapter }
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "candidate failed before adapter creation was observed" }
        }
        Start-Sleep -Milliseconds 25
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "adapter creation was not observed"
}

function Get-InterfaceAddressSnapshot([int]$InterfaceIndex) {
    return @(
        Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue |
            Sort-Object AddressFamily, IPAddress, PrefixLength |
            ForEach-Object { "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.AddressState)" }
    )
}

function Get-InterfaceRouteSnapshot([int]$InterfaceIndex) {
    return @(
        Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Sort-Object AddressFamily, DestinationPrefix, NextHop |
            ForEach-Object { "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)" }
    )
}

function Assert-SnapshotEqual([object[]]$Expected, [object[]]$Actual, [string]$Label) {
    $difference = @(Compare-Object -ReferenceObject @($Expected) -DifferenceObject @($Actual))
    Assert-True ($difference.Count -eq 0) "$Label snapshot changed"
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Get-UniqueTcpPort {
    do { $port = Get-FreeTcpPort } while (-not $script:usedTcpPorts.Add($port))
    return $port
}

function Get-Metrics([int]$Port, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try { return (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/metrics" -TimeoutSec 1).Content }
        catch {
            if ($script:activeProcess) {
                $script:activeProcess.Refresh()
                if ($script:activeProcess.HasExited) { throw "candidate failed before metrics became ready" }
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "metrics readiness timeout"
}

function Get-CounterValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))_total ([0-9]+)$")
    Assert-True $match.Success "missing no-label counter: $Name"
    return [uint64]$match.Groups[1].Value
}

function Assert-InterfaceGone([string]$Name, [Nullable[int]]$InterfaceIndex) {
    Assert-True (-not (Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction SilentlyContinue)) "adapter leaked"
    Assert-True (@(Get-NetIPAddress -InterfaceAlias $Name -ErrorAction SilentlyContinue).Count -eq 0) "address rows leaked"
    Assert-True (@(Get-NetRoute -InterfaceAlias $Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route rows leaked"
    if ($null -ne $InterfaceIndex) {
        Assert-True (@(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "address owner leaked"
        Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route owner leaked"
    }
}

function Wait-ProcessExit([System.Diagnostics.Process]$Process, [int]$TimeoutSeconds) {
    return [Ferrum2ProcessGroup]::Wait([uint32]$Process.Id, [uint32]($TimeoutSeconds * 1000))
}

function Start-Candidate([string]$Executable, [string]$Configuration) {
    $arguments = "--config `"$Configuration`""
    $id = [Ferrum2ProcessGroup]::Start($Executable, $arguments, (Split-Path -Parent $Executable))
    return Get-Process -Id $id
}

function Stop-Candidate([System.Diagnostics.Process]$Process) {
    if ($Process.HasExited) { throw "candidate stopped before controller shutdown" }
    Assert-True ([Ferrum2ProcessGroup]::Break([uint32]$Process.Id)) "CTRL_BREAK delivery failed"
    Assert-True (Wait-ProcessExit $Process 20) "candidate did not exit"
    $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
    Assert-True ($exitCode -eq 0) "candidate shutdown failed: exit=$exitCode"
    [Ferrum2ProcessGroup]::Close([uint32]$Process.Id)
}

function Wait-TcpListener([int]$Port, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { return }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "TCP listener readiness timeout"
}

function Start-Server([string]$Executable, [string]$Configuration) {
    $arguments = "--config `"$Configuration`""
    $id = [Ferrum2ProcessGroup]::Start($Executable, $arguments, (Split-Path -Parent $Executable))
    $process = Get-Process -Id $id
    $script:serverProcesses.Add($process)
    return $process
}

function Add-TunRoute([int]$InterfaceIndex, [string]$Address) {
    $isV6 = $Address.Contains(":")
    $prefix = if ($isV6) { "$Address/128" } else { "$Address/32" }
    $nextHop = if ($isV6) { "::" } else { "0.0.0.0" }
    $route = New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $InterfaceIndex -NextHop $nextHop -RouteMetric 1 -PolicyStore ActiveStore
    $script:ownedRoutes.Add($route)
    return $route
}

function Remove-OwnedRoute([object]$Route) {
    Remove-NetRoute -InputObject $Route -Confirm:$false -ErrorAction Stop
    [void]$script:ownedRoutes.Remove($Route)
}

function Add-TargetAddress([string]$Address) {
    Assert-True (@(Get-NetIPAddress -IPAddress $Address -ErrorAction SilentlyContinue).Count -eq 0) "target address baseline not absent"
    $prefix = if ($Address.Contains(":")) { 128 } else { 32 }
    $prefixText = "$Address/$prefix"
    Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "target route baseline not absent"
    $row = New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $true
    $script:ownedAddresses.Add($row)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $current = Get-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -ErrorAction SilentlyContinue
        if ($current -and $current.AddressState -eq "Preferred") { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-True ($current -and $current.AddressState -eq "Preferred") "controller target address readiness timeout"
    $localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if (-not $localRoute) {
        $nextHop = if ($Address.Contains(":")) { "::" } else { "0.0.0.0" }
        $localRoute = New-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -NextHop $nextHop -RouteMetric 1 -PolicyStore ActiveStore
    } else {
        $localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PolicyStore ActiveStore -PassThru
    }
    $script:ownedTargetRoutes.Add($localRoute)
    return $row
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class Ferrum2ProcessGroup {
    private static readonly object Sync = new object();
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private static readonly Dictionary<uint, ProcessEntry> Processes = new Dictionary<uint, ProcessEntry>();
    private sealed class ProcessEntry {
        public IntPtr Handle;
        public bool SeparateConsole;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars; public int yChars;
        public int fill; public int flags; public short show; public short reserved2; public IntPtr reservedBytes;
        public IntPtr stdin; public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr process; public IntPtr thread; public uint processId; public uint threadId; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeConsole();

    private static bool HasConsole() {
        return GetConsoleProcessList(new uint[1], 1) != 0;
    }

    public static int Start(string application, string arguments, string directory) {
        var separateConsole = !HasConsole();
        var startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(startup);
        if (separateConsole) startup.flags = STARTF_USESHOWWINDOW;
        PROCESS_INFORMATION process;
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        var flags = CREATE_NEW_PROCESS_GROUP | (separateConsole ? CREATE_NEW_CONSOLE : 0);
        if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, directory, ref startup, out process))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
        CloseHandle(process.thread);
        lock (Sync) Processes.Add(process.processId, new ProcessEntry { Handle = process.process, SeparateConsole = separateConsole });
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return WaitForSingleObject(process.Handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) throw new InvalidOperationException();
        uint exitCode; if (!GetExitCodeProcess(process.Handle, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)exitCode);
    }
    public static bool Terminate(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return TerminateProcess(process.Handle, 1);
    }
    public static void Close(uint processId) {
        ProcessEntry process;
        lock (Sync) { if (!Processes.TryGetValue(processId, out process)) return; Processes.Remove(processId); }
        CloseHandle(process.Handle);
    }
    public static bool Break(uint processGroup) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processGroup, out process)) return false;
        var attached = false;
        try {
            if (process.SeparateConsole) {
                FreeConsole();
                if (!AttachConsole(processGroup)) return false;
                attached = true;
            }
            if (!SetConsoleCtrlHandler(IntPtr.Zero, true)) return false;
            try { return GenerateConsoleCtrlEvent(1, processGroup); }
            finally { Thread.Sleep(250); SetConsoleCtrlHandler(IntPtr.Zero, false); }
        }
        finally {
            if (attached) FreeConsole();
        }
    }
}

public sealed class Ferrum2TcpGate : IDisposable {
    private readonly TcpListener listener;
    private readonly int upstreamPort;
    private readonly ConcurrentDictionary<int, ManualResetEventSlim> releases = new ConcurrentDictionary<int, ManualResetEventSlim>();
    private readonly ConcurrentBag<TcpClient> clients = new ConcurrentBag<TcpClient>();
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private int accepted;

    public Ferrum2TcpGate(int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        var ignored = Task.Run(AcceptLoop);
    }

    public int Accepted { get { return Volatile.Read(ref accepted); } }

    public bool WaitAccepted(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Accepted >= expected) return true;
            Thread.Sleep(10);
        }
        return Accepted >= expected;
    }

    public void Release(int index) {
        ManualResetEventSlim release;
        if (!releases.TryGetValue(index, out release)) throw new InvalidOperationException("gate session missing");
        release.Set();
    }

    private async Task AcceptLoop() {
        try {
            while (!stopped.IsCancellationRequested) {
                var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                clients.Add(client);
                var index = Interlocked.Increment(ref accepted);
                var release = new ManualResetEventSlim(false);
                releases[index] = release;
                var ignored = Task.Run(() => RunSession(client, release));
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    private void RunSession(TcpClient client, ManualResetEventSlim release) {
        try {
            release.Wait(stopped.Token);
            using (client)
            using (var upstream = new TcpClient(AddressFamily.InterNetwork)) {
                upstream.Connect(IPAddress.Loopback, upstreamPort);
                var first = Pump(client, upstream);
                var second = Pump(upstream, client);
                Task.WaitAll(first, second);
            }
        } catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (SocketException) { }
    }

    private static async Task Pump(TcpClient source, TcpClient destination) {
        try {
            await source.GetStream().CopyToAsync(destination.GetStream()).ConfigureAwait(false);
            try { destination.Client.Shutdown(SocketShutdown.Send); } catch (SocketException) { }
        } catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    public void Dispose() {
        stopped.Cancel();
        listener.Stop();
        foreach (var release in releases.Values) release.Set();
        TcpClient client;
        while (clients.TryTake(out client)) client.Dispose();
        stopped.Dispose();
        foreach (var release in releases.Values) release.Dispose();
    }
}

public sealed class Ferrum2TcpProbe : IDisposable {
    private readonly TcpListener listener;
    private readonly string mode;
    private readonly ManualResetEventSlim accepted = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim completed = new ManualResetEventSlim(false);
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private TcpClient client;
    private byte[] received = new byte[0];

    public Ferrum2TcpProbe(string address, int port, string mode) {
        this.mode = mode;
        listener = new TcpListener(IPAddress.Parse(address), port);
        listener.Start();
        var ignored = Task.Run(Run);
    }

    public bool WaitAccepted(int milliseconds) { return accepted.Wait(milliseconds); }
    public bool WaitCompleted(int milliseconds) { return completed.Wait(milliseconds); }
    public byte[] Received { get { return received; } }

    private async Task Run() {
        try {
            client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            accepted.Set();
            if (mode == "stall") {
                stopped.Token.WaitHandle.WaitOne();
                return;
            }
            var stream = client.GetStream();
            using (var bytes = new MemoryStream()) {
                var buffer = new byte[4096];
                do {
                    var count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (count == 0) break;
                    bytes.Write(buffer, 0, count);
                    if (mode == "capture") break;
                } while (!stopped.IsCancellationRequested);
                received = bytes.ToArray();
            }
            if (mode == "echo") {
                await stream.WriteAsync(received, 0, received.Length).ConfigureAwait(false);
                try { client.Client.Shutdown(SocketShutdown.Send); } catch (SocketException) { }
            }
        } catch (ObjectDisposedException) { }
        catch (IOException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        finally { completed.Set(); }
    }

    public void Dispose() {
        stopped.Cancel();
        listener.Stop();
        if (client != null) client.Dispose();
        accepted.Dispose();
        completed.Dispose();
        stopped.Dispose();
    }
}

public sealed class Ferrum2DnsResponder : IDisposable {
    private readonly UdpClient socket;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private int requests;

    public Ferrum2DnsResponder(int port) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        var ignored = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                var query = request.Buffer;
                if (query.Length < 17) continue;
                using (var response = new MemoryStream()) {
                    response.WriteByte(query[0]); response.WriteByte(query[1]);
                    response.WriteByte(0x81); response.WriteByte(0x80);
                    response.WriteByte(0); response.WriteByte(1);
                    response.WriteByte(0); response.WriteByte(1);
                    response.Write(new byte[4], 0, 4);
                    response.Write(query, 12, query.Length - 12);
                    byte[] answer = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 55 };
                    response.Write(answer, 0, answer.Length);
                    var bytes = response.ToArray();
                    await socket.SendAsync(bytes, bytes.Length, request.RemoteEndPoint).ConfigureAwait(false);
                }
                Interlocked.Increment(ref requests);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    public void Dispose() {
        stopped.Cancel();
        socket.Dispose();
        stopped.Dispose();
    }
}
'@

function Open-TunTcp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $route = Add-TunRoute $InterfaceIndex $Address
    $family = if ($Address.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $client = [Net.Sockets.TcpClient]::new($family)
    $client.NoDelay = $true
    $client.SendBufferSize = 4096
    $connected = $client.ConnectAsync($Address, $Port)
    Assert-True ($connected.Wait(5000)) "TUN TCP local handshake timeout"
    if ($connected.IsFaulted) { throw "TUN TCP local handshake failed" }
    return [pscustomobject]@{ Client = $client; Route = $route }
}

function Read-StreamToEnd([Net.Sockets.NetworkStream]$Stream) {
    $Stream.ReadTimeout = 5000
    $output = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(4096)
        do {
            $count = $Stream.Read($buffer, 0, $buffer.Length)
            if ($count -gt 0) { $output.Write($buffer, 0, $count) }
        } while ($count -gt 0)
        return $output.ToArray()
    } finally { $output.Dispose() }
}

function Read-ExactBytes([Net.Sockets.NetworkStream]$Stream, [int]$Length) {
    $Stream.ReadTimeout = 5000
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        Assert-True ($count -gt 0) "stream ended before exact frame"
        $offset += $count
    }
    return $bytes
}

function Invoke-EchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate]$Gate,
    [byte[]]$Payload
) {
    $expectedGate = $Gate.Accepted + 1
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    Assert-True ($Gate.WaitAccepted($expectedGate, 5000)) "selected egress gate was not opened"
    Remove-OwnedRoute $session.Route
    [void](Add-TargetAddress $Address)
    $probe = [Ferrum2TcpProbe]::new($Address, $Port, "echo")
    $script:tcpResources.Add($probe)
    $Gate.Release($expectedGate)
    Assert-True ($probe.WaitAccepted(5000)) "selected target was not opened"
    try {
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        $echo = Read-StreamToEnd $stream
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "echo or half-close mismatch"
        Assert-True ($probe.WaitCompleted(5000)) "target half-close did not complete"
    } finally { $session.Client.Dispose() }
}

function Assert-ResetWithoutEgress(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate[]]$Gates
) {
    $counts = @($Gates | ForEach-Object Accepted)
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        $stream = $session.Client.GetStream()
        $stream.ReadTimeout = 5000
        $closed = $false
        try {
            $stream.WriteByte(1)
            $closed = $stream.ReadByte() -eq -1
        } catch [IO.IOException] { $closed = $true }
        Assert-True $closed "terminal flow did not close/reset"
        for ($index = 0; $index -lt $Gates.Count; $index++) {
            Assert-True ($Gates[$index].Accepted -eq $counts[$index]) "terminal flow opened an egress gate"
        }
    } finally {
        $session.Client.Dispose()
        Remove-OwnedRoute $session.Route
    }
}

function New-DnsQuery([uint16]$Id) {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]([byte]($Id -shr 8), [byte]$Id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in @("query", "tun", "test")) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$encoded.Length)
        $bytes.AddRange($encoded)
    }
    $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
    return $bytes.ToArray()
}

try {
    Assert-True ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -eq $expectedZipHash) "ZIP hash mismatch"
    New-Item -ItemType Directory -Path $work | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $work
    $sourceDll = Join-Path $work "wintun\bin\amd64\wintun.dll"
    Assert-True (Test-Path -LiteralPath (Join-Path $work "wintun\LICENSE.txt")) "license member missing"
    Assert-True ((Get-Item -LiteralPath $sourceDll).Length -eq 427552) "DLL size mismatch"
    Assert-True ((Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash -eq $expectedDllHash) "DLL hash mismatch"
    $pe = [IO.File]::ReadAllBytes($sourceDll)
    $peOffset = [BitConverter]::ToInt32($pe, 0x3c)
    Assert-True ([BitConverter]::ToUInt16($pe, $peOffset + 4) -eq 0x8664) "DLL is not AMD64 PE"
    Assert-True ((Get-AuthenticodeSignature -LiteralPath $sourceDll).Status -eq "Valid") "Authenticode trust invalid"
    $exportsText = & (Find-Dumpbin) /nologo /exports $sourceDll | Out-String
    $exports = @([regex]::Matches($exportsText, '\bWintun[A-Za-z0-9]+\b') | ForEach-Object Value | Sort-Object -Unique)
    Assert-True (($exports -join "|") -eq ($expectedExports -join "|")) "DLL export set mismatch"
    $foundation++

    Push-Location $workspace
    try {
        if ($Mode -eq "tcp") { & cargo +1.97.1 build -p ferrum2-client -p ferrum2-server --locked }
        else { & cargo +1.97.1 build -p ferrum2-client --locked }
        if ($LASTEXITCODE -ne 0) { throw "candidate build failed" }
    }
    finally { Pop-Location }
    if ($Mode -eq "lifecycle") {
    $metricsPort = Get-FreeTcpPort
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
outbound = "proxy"
ready_timeout_ms = 15000
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[runtime]
shutdown_grace_ms = 1000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
    Assert-InterfaceGone $adapterName $null
    $offlineOutput = @(& $binary --config $config --check-config 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) "offline config validation failed"
    Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "offline config marker mismatch"
    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "offline validation touched the DLL seam"
    Assert-InterfaceGone $adapterName $null
    $foundation++

    Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
    $createdSiblingDll = $true
    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $readyAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($readyAddresses -contains "IPv4|198.18.0.2|30|Preferred") "IPv4 address snapshot missing"
    Assert-True ($readyAddresses -contains "IPv6|fd00::2|126|Preferred") "IPv6 address snapshot missing"
    $systemRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedAddressDerivedRoutes = @(
        "IPv4|198.18.0.0/30|0.0.0.0",
        "IPv4|198.18.0.2/32|0.0.0.0",
        "IPv6|fd00::/126|::",
        "IPv6|fd00::2/128|::"
    )
    $addressDerivedRoutes = @($systemRoutes | Where-Object {
        ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or
        ($_ -like "IPv6|fd00::*")
    })
    Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "exact ready address-derived routes"
    $dynamicLinkLocalRoutes = @($systemRoutes | Where-Object { $_ -match '^IPv6\|fe80::.+/128\|::$' })
    Assert-True ($dynamicLinkLocalRoutes.Count -eq 1) "unexpected link-local host route count"
    $expectedAutomaticRoutes = @(
        "IPv4|198.18.0.3/32|0.0.0.0",
        "IPv4|224.0.0.0/4|0.0.0.0",
        "IPv4|255.255.255.255/32|0.0.0.0",
        "IPv6|fe80::/64|::",
        $dynamicLinkLocalRoutes[0],
        "IPv6|ff00::/8|::"
    )
    $automaticRoutes = @($systemRoutes | Where-Object { $expectedAddressDerivedRoutes -notcontains $_ })
    Assert-SnapshotEqual $expectedAutomaticRoutes $automaticRoutes "exact ready automatic routes"
    $ownedRoutes.Add((New-NetRoute -DestinationPrefix "192.0.2.200/32" -InterfaceIndex $adapter.ifIndex -NextHop "0.0.0.0" -PolicyStore ActiveStore))
    $ownedRoutes.Add((New-NetRoute -DestinationPrefix "2001:db8::200/128" -InterfaceIndex $adapter.ifIndex -NextHop "::" -PolicyStore ActiveStore))
    $withControllerRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedControllerRoutes = @(
        "IPv4|192.0.2.200/32|0.0.0.0",
        "IPv6|2001:db8::200/128|::"
    )
    foreach ($expectedRoute in $expectedControllerRoutes) {
        Assert-True ($withControllerRoutes -contains $expectedRoute) "controller route missing: $expectedRoute"
    }
    Assert-True ($withControllerRoutes.Count -eq $systemRoutes.Count + 2) "unexpected route mutation"
    $udp4 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $udp4.Connect("192.0.2.200", 53)
    $settleDeadline = [DateTime]::UtcNow.AddSeconds(5)
    $stableSamples = 0
    $acceptedBefore = -1
    $droppedBefore = -1
    do {
        $beforeMetrics = Get-Metrics $metricsPort
        $acceptedSample = Get-CounterValue $beforeMetrics "ferrum2_tun_packets_accepted"
        $droppedSample = Get-CounterValue $beforeMetrics "ferrum2_tun_packets_foundation_dropped"
        if ($acceptedSample -eq $acceptedBefore -and $droppedSample -eq $droppedBefore) {
            $stableSamples++
        } else {
            $stableSamples = 0
            $acceptedBefore = $acceptedSample
            $droppedBefore = $droppedSample
        }
        if ($stableSamples -ge 5) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $settleDeadline)
    Assert-True ($stableSamples -ge 5) "TUN packet counters did not reach a bounded quiet baseline"
    try {
        [void]$udp4.Send([byte[]](1,2,3,4), 4)
    } finally { $udp4.Dispose(); $udp4 = $null }
    $packetDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $afterMetrics = Get-Metrics $metricsPort
        $acceptedAfter = Get-CounterValue $afterMetrics "ferrum2_tun_packets_accepted"
        $droppedAfter = Get-CounterValue $afterMetrics "ferrum2_tun_packets_foundation_dropped"
        $acceptedDelta = $acceptedAfter - $acceptedBefore
        $droppedDelta = $droppedAfter - $droppedBefore
        if ($acceptedDelta -gt 0 -and $acceptedDelta -eq $droppedDelta) { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $packetDeadline)
    Assert-True ($acceptedDelta -gt 0) "valid packet did not traverse receive/validation/enqueue"
    Assert-True ($droppedDelta -gt 0) "valid packet did not traverse poll/foundation drop"
    Assert-True ($acceptedDelta -eq $droppedDelta) "accepted packet did not have one foundation-drop outcome"
    $udp6 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    try { [void]$udp6.Send([byte[]](5,6,7,8), 4, "2001:db8::200", 53) }
    finally { $udp6.Dispose() }
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $attempt = $tcp.BeginConnect("192.0.2.200", 443, $null, $null)
        [void]$attempt.AsyncWaitHandle.WaitOne(250)
    } finally { $tcp.Dispose() }
    Start-Sleep -Milliseconds 250
    $activeProcess.Refresh()
    Assert-True (-not $activeProcess.HasExited) "valid packets terminated the required root"
    $foundation++

    foreach ($route in $ownedRoutes) { Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop }
    $ownedRoutes.Clear()
    $afterOwnedRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    Assert-SnapshotEqual $systemRoutes $afterOwnedRoutes "controller route removal"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex

    $heldMetrics = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $heldMetrics.Start()
    $heldPort = ([Net.IPEndPoint]$heldMetrics.LocalEndpoint).Port
    (Get-Content -LiteralPath $config -Raw).Replace("127.0.0.1:$metricsPort", "127.0.0.1:$heldPort") |
        Set-Content -LiteralPath $failureConfig -Encoding utf8NoBOM
    $activeProcess = Start-Candidate $binary $failureConfig
    $failedAdapter = Wait-AdapterAppeared $adapterName
    $ownedInterfaceIndex = [int]$failedAdapter.ifIndex
    Assert-True (Wait-ProcessExit $activeProcess 20) "later-root failure candidate did not exit"
    $failureExit = [Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id)
    Assert-True ($failureExit -ne 0) "later-root failure candidate unexpectedly succeeded"
    [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    $heldMetrics.Stop()
    $heldMetrics = $null

    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $reboundAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($reboundAddresses -contains "IPv4|198.18.0.2|30|Preferred") "rebound IPv4 address missing"
    Assert-True ($reboundAddresses -contains "IPv6|fd00::2|126|Preferred") "rebound IPv6 address missing"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    $foundation++

    Assert-True ($foundation -eq 4) "foundation row count mismatch"
    } else {
        $serverBinary = Join-Path $workspace "target\debug\ferrum2-server.exe"
        $serverPortA = Get-UniqueTcpPort
        $serverPortB = Get-UniqueTcpPort
        $gatePortA = Get-UniqueTcpPort
        $gatePortB = Get-UniqueTcpPort
        $deadPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        $metricsPort = Get-UniqueTcpPort
        $ports = 1..8 | ForEach-Object { Get-UniqueTcpPort }
        $targets = @(
            "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
            "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208"
        )
        $serverAConfig = Join-Path $work "server-a.toml"
        $serverBConfig = Join-Path $work "server-b.toml"
        foreach ($serverCase in @(@($serverAConfig, $serverPortA), @($serverBConfig, $serverPortB))) {
            @"
schema_version = 1
[server]
listen = "127.0.0.1:$($serverCase[1])"
[runtime]
shutdown_grace_ms = 1000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $serverCase[0] -Encoding utf8NoBOM
        }
        [void](Start-Server $serverBinary $serverAConfig)
        [void](Start-Server $serverBinary $serverBConfig)
        Wait-TcpListener $serverPortA
        Wait-TcpListener $serverPortB

        $gateA = [Ferrum2TcpGate]::new($gatePortA, $serverPortA)
        $gateB = [Ferrum2TcpGate]::new($gatePortB, $serverPortA)
        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($gateA)
        $tcpResources.Add($gateB)
        $tcpResources.Add($dnsResponder)

        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
max_tcp_flows = 8
tcp_buffer_bytes = 4096
[[outbounds]]
tag = "one"
server = "127.0.0.1:$gatePortA"
[[outbounds]]
tag = "inner"
server = "127.0.0.1:$serverPortB"
[[outbounds]]
tag = "sniff"
server = "127.0.0.1:$gatePortB"
[[outbounds]]
tag = "dead"
server = "127.0.0.1:$deadPort"
[[outbounds]]
tag = "fallback"
server = "127.0.0.1:$gatePortB"
[[chains]]
tag = "two-hop"
hops = ["one", "inner"]
[[selectors]]
tag = "manual"
outbounds = ["dead", "fallback"]
default = "dead"
[route]
final = "one"
[route.sniff]
timeout_ms = 1000
max_bytes = 8192
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "one"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "two-hop"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
action = "sniff"
sniffers = "tls"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
protocol = "tls"
domain = "tls.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "http"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "http"
domain = "http.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
protocol = "dns"
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "manual"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "one"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:$dnsPort"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 10000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "TCP config validation failed: $($offlineOutput -join '|')"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "TCP config marker mismatch"
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        $readyRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $expectedAddressDerivedRoutes = @(
            "IPv4|198.18.0.0/30|0.0.0.0", "IPv4|198.18.0.2/32|0.0.0.0",
            "IPv6|fd00::/126|::", "IPv6|fd00::2/128|::"
        )
        $addressDerivedRoutes = @($readyRoutes | Where-Object {
            ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or ($_ -like "IPv6|fd00::*")
        })
        Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "TCP ready address-derived routes"

        Invoke-EchoRow $targets[0] $ports[0] $ownedInterfaceIndex $gateA ([Text.Encoding]::ASCII.GetBytes("tcp-01-half-close"))
        $tcpRows++
        Invoke-EchoRow $targets[1] $ports[1] $ownedInterfaceIndex $gateA ([Text.Encoding]::ASCII.GetBytes("tcp-02-two-hop"))
        $tcpRows++

        $tlsGate = $gateB.Accepted + 1
        $tls = Open-TunTcp $targets[2] $ports[2] $ownedInterfaceIndex
        $ssl = [Net.Security.SslStream]::new($tls.Client.GetStream(), $false, { $true })
        $sslTask = $ssl.AuthenticateAsClientAsync("tls.tun.test")
        Assert-True ($gateB.WaitAccepted($tlsGate, 5000)) "TLS sniff did not select its exact egress"
        Remove-OwnedRoute $tls.Route
        [void](Add-TargetAddress $targets[2])
        $tlsProbe = [Ferrum2TcpProbe]::new($targets[2], $ports[2], "capture")
        $tcpResources.Add($tlsProbe)
        $gateB.Release($tlsGate)
        Assert-True ($tlsProbe.WaitCompleted(5000)) "TLS replay target did not receive prefix"
        $tlsBytes = $tlsProbe.Received
        Assert-True ($tlsBytes.Length -gt 5 -and $tlsBytes[0] -eq 22) "TLS replay record missing"
        Assert-True ([Text.Encoding]::ASCII.GetString($tlsBytes).Contains("tls.tun.test")) "TLS SNI was not replayed"
        $ssl.Dispose(); $tls.Client.Dispose()
        $tcpRows++

        $httpGate = $gateB.Accepted + 1
        $http = Open-TunTcp $targets[3] $ports[3] $ownedInterfaceIndex
        $httpBytes = [Text.Encoding]::ASCII.GetBytes("GET /tun HTTP/1.1`r`nHost: http.tun.test`r`nConnection: close`r`n`r`n")
        $httpStream = $http.Client.GetStream()
        $httpStream.Write($httpBytes, 0, $httpBytes.Length)
        $http.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        Assert-True ($gateB.WaitAccepted($httpGate, 5000)) "HTTP sniff did not select its exact egress"
        Remove-OwnedRoute $http.Route
        [void](Add-TargetAddress $targets[3])
        $httpProbe = [Ferrum2TcpProbe]::new($targets[3], $ports[3], "echo")
        $tcpResources.Add($httpProbe)
        $gateB.Release($httpGate)
        Assert-True ($httpProbe.WaitAccepted(5000)) "HTTP replay target was not opened"
        $httpEcho = Read-StreamToEnd $httpStream
        Assert-True (($httpEcho -join ",") -eq ($httpBytes -join ",")) "HTTP prefix was not replayed exactly once"
        $http.Client.Dispose()
        $tcpRows++

        $gateCounts = @($gateA.Accepted, $gateB.Accepted)
        $dnsFlow = Open-TunTcp $targets[4] $ports[4] $ownedInterfaceIndex
        try {
            $dnsStream = $dnsFlow.Client.GetStream()
            foreach ($id in [uint16[]](0x1201, 0x1202)) {
                $query = New-DnsQuery $id
                $frame = [byte[]]::new($query.Length + 2)
                $frame[0] = [byte]($query.Length -shr 8); $frame[1] = [byte]$query.Length
                [Array]::Copy($query, 0, $frame, 2, $query.Length)
                $dnsStream.Write($frame, 0, $frame.Length)
                $length = Read-ExactBytes $dnsStream 2
                $responseLength = ([int]$length[0] -shl 8) -bor $length[1]
                $response = Read-ExactBytes $dnsStream $responseLength
                Assert-True ($response[0] -eq [byte]($id -shr 8) -and $response[1] -eq [byte]$id) "DNS response ID mismatch"
            }
            Assert-True ($dnsResponder.Requests -eq 2) "DNS hijack did not answer both framed queries"
            Assert-True ($gateA.Accepted -eq $gateCounts[0] -and $gateB.Accepted -eq $gateCounts[1]) "DNS hijack opened Shadowsocks"
        } finally {
            $dnsFlow.Client.Dispose()
            Remove-OwnedRoute $dnsFlow.Route
        }
        $tcpRows++

        Assert-ResetWithoutEgress $targets[5] $ports[5] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++
        Assert-ResetWithoutEgress $targets[6] $ports[6] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++

        $pressureGate = $gateA.Accepted + 1
        $pressure = Open-TunTcp $targets[7] $ports[7] $ownedInterfaceIndex
        Assert-True ($gateA.WaitAccepted($pressureGate, 5000)) "backpressure route did not open"
        Remove-OwnedRoute $pressure.Route
        [void](Add-TargetAddress $targets[7])
        $stall = [Ferrum2TcpProbe]::new($targets[7], $ports[7], "stall")
        $tcpResources.Add($stall)
        $gateA.Release($pressureGate)
        Assert-True ($stall.WaitAccepted(5000)) "backpressure target was not opened"
        $pressureBytes = [byte[]]::new(8 * 1024 * 1024)
        $pressureWrite = $pressure.Client.GetStream().WriteAsync($pressureBytes, 0, $pressureBytes.Length)
        Assert-True (-not $pressureWrite.Wait(500)) "backpressure write unexpectedly drained"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        $pressure.Client.Dispose()
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        $tcpRows++
        Assert-True ($tcpRows -eq 8) "TCP row count mismatch"
    }
    $completed = $true
}
finally {
    if ($udp4) { $udp4.Dispose() }
    if ($heldMetrics) { $heldMetrics.Stop() }
    foreach ($route in $ownedRoutes) {
        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($activeProcess -and -not [Ferrum2ProcessGroup]::Wait([uint32]$activeProcess.Id, 0)) {
        [void][Ferrum2ProcessGroup]::Break([uint32]$activeProcess.Id)
        if (-not (Wait-ProcessExit $activeProcess 5)) {
            Stop-Process -InputObject $activeProcess -Force -ErrorAction SilentlyContinue
            Assert-True (Wait-ProcessExit $activeProcess 5) "owned candidate fallback termination failed"
        }
    }
    if ($activeProcess) { [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id) }
    foreach ($resource in $tcpResources) { $resource.Dispose() }
    foreach ($server in $serverProcesses) {
        if (-not [Ferrum2ProcessGroup]::Wait([uint32]$server.Id, 0)) {
            [void][Ferrum2ProcessGroup]::Break([uint32]$server.Id)
            if (-not (Wait-ProcessExit $server 5)) {
                Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$server.Id)) "owned server fallback termination failed"
                Assert-True (Wait-ProcessExit $server 5) "owned server did not terminate"
            }
        }
        [Ferrum2ProcessGroup]::Close([uint32]$server.Id)
    }
    if (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue) {
        Wait-AdapterAbsent $adapterName 20
    }
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    foreach ($route in $ownedTargetRoutes) {
        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($address in $ownedAddresses) {
        Remove-NetIPAddress -InputObject $address -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($address in $ownedAddresses) {
        Assert-True (@(Get-NetIPAddress -IPAddress $address.IPAddress -ErrorAction SilentlyContinue).Count -eq 0) "controller-owned target address leaked"
    }
    foreach ($route in $ownedTargetRoutes) {
        Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $route.DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "controller-owned target route leaked"
    }
    foreach ($expectedRoute in @("192.0.2.200/32", "2001:db8::200/128")) {
        $leaked = @(Get-NetRoute -DestinationPrefix $expectedRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $null -ne $ownedInterfaceIndex -and $_.InterfaceIndex -eq $ownedInterfaceIndex })
        Assert-True ($leaked.Count -eq 0) "controller-owned route leaked: $expectedRoute"
    }
    if ($createdSiblingDll -and (Test-Path -LiteralPath $siblingDll)) { Remove-Item -LiteralPath $siblingDll -Force }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    if ($createdSiblingDll) { Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "owned sibling DLL leaked" }
    Assert-True (-not (Test-Path -LiteralPath $work)) "controller work directory leaked"
}

if ($completed) {
    $sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $runAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    if ($Mode -eq "lifecycle") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=foundation foundation=4/4 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } else {
        Write-Output "m15_windows_tun_e2e status=PASS profile=tcp tcp=8/8 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    }
}
