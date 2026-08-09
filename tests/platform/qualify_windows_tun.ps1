param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("lifecycle")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
}

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$zip = if ($env:FERRUM2_WINTUN_ZIP) {
    (Resolve-Path -LiteralPath $env:FERRUM2_WINTUN_ZIP).Path
} else {
    (Resolve-Path -LiteralPath "C:\Users\ZZZ\Downloads\wintun-0.14.1.zip").Path
}
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
$foundation = 0

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

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Ferrum2ProcessGroup {
    private static readonly object Sync = new object();
    private static readonly Dictionary<uint, IntPtr> Processes = new Dictionary<uint, IntPtr>();
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
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();

    public static int Start(string application, string arguments, string directory) {
        if (GetConsoleWindow() == IntPtr.Zero && !AllocConsole()) throw new Win32Exception(Marshal.GetLastWin32Error());
        var startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(startup);
        PROCESS_INFORMATION process;
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false, 0x00000200, IntPtr.Zero, directory, ref startup, out process))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        CloseHandle(process.thread);
        lock (Sync) Processes.Add(process.processId, process.process);
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        IntPtr handle; lock (Sync) if (!Processes.TryGetValue(processId, out handle)) return false;
        return WaitForSingleObject(handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        IntPtr handle; lock (Sync) if (!Processes.TryGetValue(processId, out handle)) throw new InvalidOperationException();
        uint exitCode; if (!GetExitCodeProcess(handle, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)exitCode);
    }
    public static bool Terminate(uint processId) {
        IntPtr handle; lock (Sync) if (!Processes.TryGetValue(processId, out handle)) return false;
        return TerminateProcess(handle, 1);
    }
    public static void Close(uint processId) {
        IntPtr handle;
        lock (Sync) { if (!Processes.TryGetValue(processId, out handle)) return; Processes.Remove(processId); }
        CloseHandle(handle);
    }
    public static bool Break(uint processGroup) {
        if (!SetConsoleCtrlHandler(IntPtr.Zero, true)) return false;
        try { return GenerateConsoleCtrlEvent(1, processGroup); }
        finally { Thread.Sleep(250); SetConsoleCtrlHandler(IntPtr.Zero, false); }
    }
}
'@

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
    try { & cargo +1.97.1 build -p ferrum2-client --locked; if ($LASTEXITCODE -ne 0) { throw "candidate build failed" } }
    finally { Pop-Location }
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
    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $readyAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($readyAddresses -contains "IPv4|198.18.0.2|30|Preferred") "IPv4 address snapshot missing"
    Assert-True ($readyAddresses -contains "IPv6|fd00::2|126|Preferred") "IPv6 address snapshot missing"
    $systemRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    foreach ($expectedRoute in @(
        "IPv4|198.18.0.0/30|0.0.0.0",
        "IPv4|198.18.0.2/32|0.0.0.0",
        "IPv6|fd00::/126|::",
        "IPv6|fd00::2/128|::"
    )) {
        Assert-True ($systemRoutes -contains $expectedRoute) "expected OS-managed route missing: $expectedRoute"
    }
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
    $udp6 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    try {
        [void]$udp4.Send([byte[]](1,2,3,4), 4, "192.0.2.200", 53)
        [void]$udp6.Send([byte[]](5,6,7,8), 4, "2001:db8::200", 53)
        $tcp = [Net.Sockets.TcpClient]::new()
        try { $attempt = $tcp.BeginConnect("192.0.2.200", 443, $null, $null); [void]$attempt.AsyncWaitHandle.WaitOne(250) }
        finally { $tcp.Dispose() }
    } finally { $udp4.Dispose(); $udp6.Dispose() }
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
    $metricsPort = ([Net.IPEndPoint]$heldMetrics.LocalEndpoint).Port
    "$(Get-Content -LiteralPath $config -Raw)`n[metrics]`nlisten = `"127.0.0.1:$metricsPort`"`n" |
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
    $sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $runAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    Write-Output "m15_windows_tun_e2e status=PASS profile=foundation foundation=4/4 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
}
finally {
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
    if (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue) {
        Wait-AdapterAbsent $adapterName 20
    }
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    foreach ($expectedRoute in @("192.0.2.200/32", "2001:db8::200/128")) {
        $leaked = @(Get-NetRoute -DestinationPrefix $expectedRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $null -ne $ownedInterfaceIndex -and $_.InterfaceIndex -eq $ownedInterfaceIndex })
        Assert-True ($leaked.Count -eq 0) "controller-owned route leaked: $expectedRoute"
    }
    if (Test-Path -LiteralPath $siblingDll) { Remove-Item -LiteralPath $siblingDll -Force }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
