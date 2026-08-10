param(
    [Parameter(Mandatory = $true)]
    # Legacy M15 mode contract: [ValidateSet("lifecycle", "tcp", "udp", "cycles", "full", "performance", "cleanup")]
    [ValidateSet("lifecycle", "tcp", "udp", "cycles", "full", "performance", "network-feasibility", "cleanup")]
    [string]$Mode,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
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

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runIdentity = if ($RunToken) { $RunToken } elseif ($Mode -eq "cleanup") { throw "cleanup requires RunToken" } else { "local-$PID" }
if ($runIdentity -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw "RunToken is invalid" }
$work = if ($Mode -eq "network-feasibility") {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-network-$runIdentity"
} else {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m15-tun-$runIdentity"
}
$binary = Join-Path $workspace "target\debug\ferrum2-client.exe"
$serverBinary = Join-Path $workspace "target\debug\ferrum2-server.exe"
$siblingDll = Join-Path (Split-Path -Parent $binary) "wintun.dll"
$adapterName = if ($Mode -eq "network-feasibility") { "Ferrum2-M16-$runIdentity" } else { "Ferrum2-M15-$runIdentity" }
$config = Join-Path $work "client.toml"
$failureConfig = Join-Path $work "client-failure.toml"
$addressJournal = Join-Path $work "owned-target-addresses.txt"
$dllJournal = Join-Path $work "owned-wintun-dll.txt"

function Get-ExactRunProcesses([string]$WorkPath) {
    $executables = @($binary, $serverBinary)
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and
        $executables -contains $_.ExecutablePath -and
        $_.CommandLine -and
        $_.CommandLine.IndexOf($WorkPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}

if ($Mode -eq "cleanup") {
    foreach ($process in @(Get-ExactRunProcesses $work)) {
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $processes = @(Get-ExactRunProcesses $work)
        $adapter = Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue
        if ($processes.Count -eq 0 -and -not $adapter) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $allowedAddresses = @(
        "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
        "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208", "192.0.2.250"
    )
    $journaledAddresses = if (Test-Path -LiteralPath $addressJournal) { @(Get-Content -LiteralPath $addressJournal) } else { @() }
    foreach ($address in $journaledAddresses) {
        if ($allowedAddresses -notcontains $address) { throw "target address journal is invalid" }
        $prefix = if ($address.Contains(":")) { "$address/128" } else { "$address/32" }
        Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $dllJournal) {
        if (Test-Path -LiteralPath $siblingDll) {
            if ((Get-FileHash -LiteralPath $siblingDll -Algorithm SHA256).Hash -ne $expectedDllHash) { throw "owned sibling DLL hash mismatch" }
            Remove-Item -LiteralPath $siblingDll -Force
        }
    }
    if (@(Get-ExactRunProcesses $work).Count -ne 0) { throw "controller process residue" }
    if (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue) { throw "controller adapter residue" }
    foreach ($address in $journaledAddresses) {
        $prefix = if ($address.Contains(":")) { "$address/128" } else { "$address/32" }
        if (Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address -ErrorAction SilentlyContinue) { throw "controller address residue" }
        if (Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue) { throw "controller route residue" }
    }
    if ((Test-Path -LiteralPath $dllJournal) -and (Test-Path -LiteralPath $siblingDll)) { throw "controller DLL residue" }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    if (Test-Path -LiteralPath $work) { throw "controller temp residue" }
    return
}

$zipInput = if ($WintunZip) { $WintunZip } elseif ($env:FERRUM2_WINTUN_ZIP) { $env:FERRUM2_WINTUN_ZIP } else { throw "Wintun ZIP path is required via -WintunZip or FERRUM2_WINTUN_ZIP" }
$zip = (Resolve-Path -LiteralPath $zipInput).Path
$ownedRoutes = [System.Collections.Generic.List[object]]::new()
$activeProcess = $null
$ownedInterfaceIndex = $null
$heldMetrics = $null
$udp4 = $null
$foundation = 0
$tcpRows = 0
$udpRows = 0
$serverProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$ownedAddresses = [System.Collections.Generic.List[object]]::new()
$ownedTargetRoutes = [System.Collections.Generic.List[object]]::new()
$tcpResources = [System.Collections.Generic.List[System.IDisposable]]::new()
$udpGateA = $null
$udpGateB = $null
$usedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$createdSiblingDll = $false
$completed = $false
$primaryError = $null
$outerCleanupError = $null
$tcp01Diagnostic = $null
$cycleRows = 0
$performanceWitnesses = 0
$performanceAdapterRxBytes = [uint64]0
$performanceAdapterTxBytes = [uint64]0
$performanceAdapterRxPackets = [uint64]0
$performanceAdapterTxPackets = [uint64]0
$performanceAdapterRxErrors = [uint64]0
$performanceAdapterTxErrors = [uint64]0
$performanceAdapterRxDiscards = [uint64]0
$performanceAdapterTxDiscards = [uint64]0
$performanceTunAcceptedDelta = [uint64]0
$performanceCpuMilliseconds = [uint64]0
$performanceRssBytes = [uint64]0
$performanceHandlesPeak = [uint64]0
$performanceThreadsPeak = [uint64]0
$performanceUdpSessionsPeak = [uint64]0
$performanceUdpBufferedBytesPeak = [uint64]0
$performanceControllerInflightPeak = [uint64]0
$performanceCpuBaseline = [double]0
$performanceTunAcceptedBaseline = [uint64]0
$performanceTrafficBaseline = $null
$performanceFieldsCollected = $false
$performanceAdapterChurn = 0
$performanceGraceDrain = $false
$performanceForceDrain = $false
$capabilityIdentity = $null
$capabilityIdentityHash = $null
$capabilityEvidence = $null
$capabilityRoutes = [System.Collections.Generic.List[System.IDisposable]]::new()
$capabilityDnsSnapshot = $null
$capabilityDnsApplied = $false
$capabilityMetricSnapshot = $null
$capabilityMetricApplied = $false
$capabilityInterfaceMetric = $null
$capabilityRouteRows = 0
$capabilityTcpRows = 0
$capabilityUdpRows = 0
$capabilityDnsRows = 0
$capabilityWindowRows = 0
$capabilityHardKillRows = 0
$pktmonStarted = $false
$pktmonStartAttempted = $false
$pktmonTcpFilterOwned = $false
$pktmonUdpFilterOwned = $false
$pktmonComponentId = $null
$capabilityFilteredPackets = [ordered]@{
    fixed_tcp_unpinned = $null
    fixed_tcp_pinned = $null
    dynamic_tcp_unpinned = $null
    dynamic_tcp_pinned = $null
    fixed_udp_unpinned = $null
    fixed_udp_pinned = $null
    dynamic_udp_unpinned = $null
    dynamic_udp_pinned = $null
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-NetworkFeasibilityIdentity([string]$Path) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path)) "network feasibility requires IdentityLedger"
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $bytes = [IO.File]::ReadAllBytes($resolved)
    Assert-True ($bytes.Length -gt 1 -and $bytes[$bytes.Length - 1] -eq 10) "identity ledger must end in one LF"
    Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf)) "identity ledger must not have a BOM"
    Assert-True (@($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0) "identity ledger must be one LF-terminated line"
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString($bytes)
    $json = $text.Substring(0, $text.Length - 1)
    $ledger = $json | ConvertFrom-Json -Depth 4
    $keys = @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id", "guest_product",
        "guest_edition", "guest_architecture", "guest_version", "guest_build", "candidate_sha",
        "probe_sha256", "support_listener"
    )
    Assert-True ((@($ledger.PSObject.Properties.Name) -join "|") -ceq ($keys -join "|")) "identity ledger keys are invalid"
    $listenerKeys = @("ipv4", "tcp_port", "udp_port", "pid", "owner")
    Assert-True ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -ceq ($listenerKeys -join "|")) "support listener keys are invalid"
    Assert-True (($ledger | ConvertTo-Json -Compress -Depth 4) -ceq $json) "identity ledger is not canonical JSON"
    Assert-True ($ledger.schema -is [long] -and $ledger.schema -eq 1) "identity ledger schema is invalid"
    Assert-True ($ledger.vm_name -ceq "Windows 10 MSIX packaging environment") "identity ledger VM name is invalid"
    Assert-True ($ledger.checkpoint_name -ceq "M15-T04-before-2b0c25b-20260810") "identity ledger checkpoint name is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger VM ID is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger checkpoint ID is invalid"
    Assert-True ([string]$ledger.candidate_sha -cmatch '^[0-9a-f]{40}$') "identity ledger candidate SHA is invalid"
    Assert-True ([string]$ledger.probe_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger probe hash is invalid"
    $probePath = Join-Path $PSScriptRoot "qualify_windows_tun.ps1"
    $probeHash = (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($ledger.probe_sha256 -ceq $probeHash) "identity ledger probe hash mismatch"

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $version = [Environment]::OSVersion.Version.ToString()
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
    Assert-True ($ledger.guest_product -ceq [string]$currentVersion.ProductName) "identity ledger guest product mismatch"
    Assert-True ($ledger.guest_edition -ceq [string]$currentVersion.EditionID) "identity ledger guest edition mismatch"
    Assert-True ($ledger.guest_architecture -ceq "AMD64" -and [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "X64") "identity ledger guest architecture mismatch"
    Assert-True ($ledger.guest_version -ceq $version) "identity ledger guest version mismatch"
    Assert-True ($ledger.guest_build -ceq $build -and [string]$os.BuildNumber -ceq [string]$currentVersion.CurrentBuildNumber) "identity ledger guest build mismatch"

    $address = $null
    Assert-True ([Net.IPAddress]::TryParse([string]$ledger.support_listener.ipv4, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) "support listener address is not IPv4"
    $octets = $address.GetAddressBytes()
    Assert-True (-not [Net.IPAddress]::IsLoopback($address) -and $octets[0] -ne 0 -and $octets[0] -lt 224 -and -not ($octets[0] -eq 169 -and $octets[1] -eq 254)) "support listener address is not eligible"
    Assert-True (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $address.IPAddressToString -ErrorAction SilentlyContinue).Count -eq 0) "support listener address is guest-local"
    foreach ($name in @("tcp_port", "udp_port")) {
        Assert-True ($ledger.support_listener.$name -is [long] -and $ledger.support_listener.$name -ge 1 -and $ledger.support_listener.$name -le 65535) "support listener port is invalid"
    }
    Assert-True ($ledger.support_listener.pid -is [long] -and $ledger.support_listener.pid -ge 1 -and $ledger.support_listener.pid -le [uint32]::MaxValue) "support listener PID is invalid"
    Assert-True ([string]$ledger.support_listener.owner -cmatch '^[^\r\n]{1,256}$') "support listener owner is invalid"

    return [pscustomobject]@{
        Ledger = $ledger
        Path = $resolved
        IdentitySha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        GuestBuild = $build
        SupportAddress = $address.IPAddressToString
        TcpPort = [int]$ledger.support_listener.tcp_port
        UdpPort = [int]$ledger.support_listener.udp_port
    }
}

if ($Mode -eq "network-feasibility") {
    $capabilityIdentity = Get-NetworkFeasibilityIdentity $IdentityLedger
    $capabilityIdentityHash = $capabilityIdentity.IdentitySha256
    $capabilityEvidence = "$($capabilityIdentity.Path).evidence-$runIdentity.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $capabilityEvidence)) "network feasibility evidence baseline not absent"
}

function Get-Tcp01Boundary([hashtable]$State) {
    $yesNo = @("yes", "no")
    $gateFaults = @("none", "io", "disposed", "socket", "cancelled", "invalid_operation", "not_supported", "aggregate", "other")
    $probeFaults = @("none", "io", "disposed", "socket", "cancelled", "other")
    $stages = @("pending", "source_stream", "destination_stream", "read", "write", "shutdown")
    foreach ($name in @("GateAccepted", "GateForwardEof", "GateReverseEof", "GateComplete", "ProbeAccepted", "ProbeReadEof", "ProbeShutdown", "ProbeComplete")) {
        if (-not $State.ContainsKey($name) -or $yesNo -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("GateForwardFault", "GateReverseFault")) {
        if (-not $State.ContainsKey($name) -or $gateFaults -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    if (-not $State.ContainsKey("ProbeFault") -or $probeFaults -notcontains $State.ProbeFault) { return "UNRESOLVED" }
    foreach ($name in @("GateForwardStage", "GateReverseStage")) {
        if (-not $State.ContainsKey($name) -or $stages -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("GateForwardBytes", "GateReverseBytes")) {
        if (-not $State.ContainsKey($name) -or @("zero", "nonzero") -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("ProbeRequest", "ProbeEcho")) {
        if (-not $State.ContainsKey($name) -or @("none", "exact", "other") -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    if (-not $State.ContainsKey("AppResult") -or @("reset", "io", "success", "other") -notcontains $State.AppResult) { return "UNRESOLVED" }
    if ($State.GateAccepted -eq "no" -or $State.GateForwardBytes -eq "zero" -or $State.ProbeAccepted -eq "no") { return "BEFORE_TARGET" }
    if ($State.ProbeRequest -ne "exact" -or $State.ProbeReadEof -ne "yes" -or $State.ProbeEcho -ne "exact" -or
        $State.ProbeShutdown -ne "yes" -or $State.ProbeFault -ne "none" -or $State.ProbeComplete -ne "yes") { return "TARGET_ECHO_INCOMPLETE" }
    if ($State.GateReverseBytes -eq "zero" -or $State.GateReverseEof -ne "yes" -or
        $State.GateReverseFault -ne "none" -or $State.GateComplete -ne "yes") { return "GATE_REVERSE_INCOMPLETE" }
    if ($State.GateForwardEof -ne "yes" -or $State.GateForwardFault -ne "none") { return "UNRESOLVED" }
    if ($State.AppResult -ne "success") { return "CLIENT_AFTER_GATE_REVERSE" }
    return "COMPLETE"
}

$tcp01CompleteState = @{
    GateAccepted = "yes"; GateForwardBytes = "nonzero"; GateForwardEof = "yes"; GateForwardFault = "none"; GateForwardStage = "shutdown"
    GateReverseBytes = "nonzero"; GateReverseEof = "yes"; GateReverseFault = "none"; GateReverseStage = "shutdown"; GateComplete = "yes"
    ProbeAccepted = "yes"; ProbeRequest = "exact"; ProbeReadEof = "yes"; ProbeEcho = "exact"
    ProbeShutdown = "yes"; ProbeFault = "none"; ProbeComplete = "yes"; AppResult = "success"
}
foreach ($row in @(
    @{ Change = @{ GateAccepted = "no" }; Expected = "BEFORE_TARGET" },
    @{ Change = @{ ProbeEcho = "other" }; Expected = "TARGET_ECHO_INCOMPLETE" },
    @{ Change = @{ ProbeComplete = "no" }; Expected = "TARGET_ECHO_INCOMPLETE" },
    @{ Change = @{ GateReverseBytes = "zero" }; Expected = "GATE_REVERSE_INCOMPLETE" },
    @{ Change = @{ GateComplete = "no" }; Expected = "GATE_REVERSE_INCOMPLETE" },
    @{ Change = @{ AppResult = "reset" }; Expected = "CLIENT_AFTER_GATE_REVERSE" },
    @{ Change = @{}; Expected = "COMPLETE" },
    @{ Change = @{ GateForwardFault = "invalid" }; Expected = "UNRESOLVED" },
    @{ Change = @{ GateReverseStage = "invalid" }; Expected = "UNRESOLVED" }
)) {
    $state = $tcp01CompleteState.Clone()
    foreach ($name in $row.Change.Keys) { $state[$name] = $row.Change[$name] }
    Assert-True ((Get-Tcp01Boundary $state) -eq $row.Expected) "TCP-01 boundary table mismatch"
}

function Get-PeExportNames([byte[]]$Bytes) {
    Assert-True ($Bytes.Length -ge 64) "PE image is truncated"
    $stream = [IO.MemoryStream]::new($Bytes, $false)
    $reader = [Reflection.PortableExecutable.PEReader]::new($stream)
    try {
        $peHeader = $reader.PEHeaders.PEHeader
        Assert-True ($null -ne $peHeader) "PE optional header is missing"
        $directory = $peHeader.ExportTableDirectory
        Assert-True ($directory.RelativeVirtualAddress -gt 0 -and $directory.Size -ge 40) "PE export directory is missing"
        $directoryBlock = $reader.GetSectionData($directory.RelativeVirtualAddress)
        Assert-True ($directoryBlock.Length -ge 40) "PE export directory is truncated"
        [byte[]]$directoryBytes = $directoryBlock.GetContent(0, 40)
        [uint32]$functionCount = [BitConverter]::ToUInt32($directoryBytes, 20)
        [uint32]$nameCount = [BitConverter]::ToUInt32($directoryBytes, 24)
        Assert-True ($functionCount -eq $nameCount -and $nameCount -ge 1 -and $nameCount -le 256) "PE export count is invalid"
        [uint32]$nameTableRva = [BitConverter]::ToUInt32($directoryBytes, 32)
        Assert-True ($nameTableRva -gt 0 -and $nameTableRva -le [int]::MaxValue) "PE export name table RVA is invalid"
        $nameTableLength = [int]$nameCount * 4
        $nameTableBlock = $reader.GetSectionData([int]$nameTableRva)
        Assert-True ($nameTableBlock.Length -ge $nameTableLength) "PE export name table is truncated"
        [byte[]]$nameTableBytes = $nameTableBlock.GetContent(0, $nameTableLength)
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $names = [Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt [int]$nameCount; $index++) {
            [uint32]$nameRva = [BitConverter]::ToUInt32($nameTableBytes, $index * 4)
            Assert-True ($nameRva -gt 0 -and $nameRva -le [int]::MaxValue) "PE export name RVA is invalid"
            $nameBlock = $reader.GetSectionData([int]$nameRva)
            $boundedLength = [Math]::Min(257, $nameBlock.Length)
            Assert-True ($boundedLength -ge 2) "PE export name is truncated"
            [byte[]]$nameBytes = $nameBlock.GetContent(0, $boundedLength)
            $terminator = [Array]::IndexOf($nameBytes, [byte]0)
            Assert-True ($terminator -ge 1 -and $terminator -le 256) "PE export name is not bounded"
            $names.Add($utf8.GetString($nameBytes, 0, $terminator))
        }
        $sorted = @($names | Sort-Object -Unique)
        Assert-True ($sorted.Count -eq [int]$nameCount) "PE export names are not unique"
        return $sorted
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
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

function Get-ClientGaugeValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))\{role=`"client`"\} ([0-9]+)$")
    Assert-True $match.Success "missing client gauge: $Name"
    return [uint64]$match.Groups[1].Value
}

function Get-AdapterTraffic([string]$Name) {
    $statistics = Get-NetAdapterStatistics -Name $Name -ErrorAction Stop
    return @{
        ReceivedBytes = [uint64]$statistics.ReceivedBytes
        SentBytes = [uint64]$statistics.SentBytes
        ReceivedUnicastPackets = [uint64]$statistics.ReceivedUnicastPackets
        SentUnicastPackets = [uint64]$statistics.SentUnicastPackets
        ReceivedPacketErrors = [uint64]$statistics.ReceivedPacketErrors
        OutboundPacketErrors = [uint64]$statistics.OutboundPacketErrors
        ReceivedDiscardedPackets = [uint64]$statistics.ReceivedDiscardedPackets
        OutboundDiscardedPackets = [uint64]$statistics.OutboundDiscardedPackets
    }
}

function Update-PerformancePeaks([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    $Process.Refresh()
    $script:performanceRssBytes = [Math]::Max($script:performanceRssBytes, [uint64]$Process.WorkingSet64)
    $script:performanceHandlesPeak = [Math]::Max($script:performanceHandlesPeak, [uint64]$Process.HandleCount)
    $script:performanceThreadsPeak = [Math]::Max($script:performanceThreadsPeak, [uint64]$Process.Threads.Count)
    $metrics = Get-Metrics $MetricsPort
    $script:performanceUdpSessionsPeak = [Math]::Max(
        $script:performanceUdpSessionsPeak,
        (Get-ClientGaugeValue $metrics "ferrum2_udp_sessions_active")
    )
    $script:performanceUdpBufferedBytesPeak = [Math]::Max(
        $script:performanceUdpBufferedBytesPeak,
        (Get-ClientGaugeValue $metrics "ferrum2_udp_buffered_bytes")
    )
}

function Start-PerformanceSample([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    $Process.Refresh()
    $script:performanceCpuBaseline = $Process.TotalProcessorTime.TotalMilliseconds
    $metrics = Get-Metrics $MetricsPort
    $script:performanceTunAcceptedBaseline = Get-CounterValue $metrics "ferrum2_tun_packets_accepted"
    $script:performanceTrafficBaseline = Get-AdapterTraffic $script:adapterName
    $script:performanceFieldsCollected = $true
    Update-PerformancePeaks $Process $MetricsPort
}

function Complete-PerformanceSample([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    Update-PerformancePeaks $Process $MetricsPort
    $Process.Refresh()
    $cpu = $Process.TotalProcessorTime.TotalMilliseconds
    Assert-True ($cpu -ge $script:performanceCpuBaseline) "candidate CPU counter moved backwards"
    $script:performanceCpuMilliseconds += [uint64][Math]::Ceiling($cpu - $script:performanceCpuBaseline)
    $metrics = Get-Metrics $MetricsPort
    $accepted = Get-CounterValue $metrics "ferrum2_tun_packets_accepted"
    Assert-True ($accepted -ge $script:performanceTunAcceptedBaseline) "TUN accepted counter moved backwards"
    $script:performanceTunAcceptedDelta += $accepted - $script:performanceTunAcceptedBaseline
    $after = Get-AdapterTraffic $script:adapterName
    foreach ($property in $script:performanceTrafficBaseline.Keys) {
        Assert-True ($after[$property] -ge $script:performanceTrafficBaseline[$property]) "adapter counter moved backwards: $property"
    }
    $script:performanceAdapterRxBytes += $after.ReceivedBytes - $script:performanceTrafficBaseline.ReceivedBytes
    $script:performanceAdapterTxBytes += $after.SentBytes - $script:performanceTrafficBaseline.SentBytes
    $script:performanceAdapterRxPackets += $after.ReceivedUnicastPackets - $script:performanceTrafficBaseline.ReceivedUnicastPackets
    $script:performanceAdapterTxPackets += $after.SentUnicastPackets - $script:performanceTrafficBaseline.SentUnicastPackets
    $script:performanceAdapterRxErrors += $after.ReceivedPacketErrors - $script:performanceTrafficBaseline.ReceivedPacketErrors
    $script:performanceAdapterTxErrors += $after.OutboundPacketErrors - $script:performanceTrafficBaseline.OutboundPacketErrors
    $script:performanceAdapterRxDiscards += $after.ReceivedDiscardedPackets - $script:performanceTrafficBaseline.ReceivedDiscardedPackets
    $script:performanceAdapterTxDiscards += $after.OutboundDiscardedPackets - $script:performanceTrafficBaseline.OutboundDiscardedPackets
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

function Add-TunRoute([int]$InterfaceIndex, [string]$DestinationPrefix, [int]$RouteMetric = 1) {
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "controller route baseline not absent"
    $nextHop = if ($DestinationPrefix.Contains(":")) { "::" } else { "0.0.0.0" }
    $route = New-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -NextHop $nextHop -RouteMetric $RouteMetric -PolicyStore ActiveStore
    $script:ownedRoutes.Add($route)
    return $route
}

function Add-TargetAddress([string]$Address, [bool]$SkipAsSource = $true) {
    Assert-True (@(Get-NetIPAddress -IPAddress $Address -ErrorAction SilentlyContinue).Count -eq 0) "target address baseline not absent"
    $prefix = if ($Address.Contains(":")) { 128 } else { 32 }
    $prefixText = "$Address/$prefix"
    Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "target route baseline not absent"
    Add-Content -LiteralPath $script:addressJournal -Value $Address -Encoding utf8
    $row = New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore ActiveStore
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
        $localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru
    }
    $script:ownedTargetRoutes.Add($localRoute)
    return $row
}

Add-Type -TypeDefinition @'
using System;
using System.Collections;
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

public sealed class Ferrum2TcpGateObservation {
    private long clientToServerBytes;
    private long serverToClientBytes;
    private int clientToServerEof;
    private int serverToClientEof;
    private int sessionComplete;
    private string clientToServerStage = "pending";
    private string serverToClientStage = "pending";
    private string clientToServerFault;
    private string serverToClientFault;

    public string ClientToServerBytes { get { return Interlocked.Read(ref clientToServerBytes) == 0 ? "zero" : "nonzero"; } }
    public string ServerToClientBytes { get { return Interlocked.Read(ref serverToClientBytes) == 0 ? "zero" : "nonzero"; } }
    public string ClientToServerStage { get { return Volatile.Read(ref clientToServerStage); } }
    public string ServerToClientStage { get { return Volatile.Read(ref serverToClientStage); } }
    public string ClientToServerEof { get { return Volatile.Read(ref clientToServerEof) == 0 ? "no" : "yes"; } }
    public string ServerToClientEof { get { return Volatile.Read(ref serverToClientEof) == 0 ? "no" : "yes"; } }
    public string ClientToServerFault { get { return Volatile.Read(ref clientToServerFault) ?? "none"; } }
    public string ServerToClientFault { get { return Volatile.Read(ref serverToClientFault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }

    internal void AddBytes(bool forward, int count) {
        if (forward) Interlocked.Add(ref clientToServerBytes, count);
        else Interlocked.Add(ref serverToClientBytes, count);
    }
    internal void MarkEof(bool forward) {
        if (forward) Volatile.Write(ref clientToServerEof, 1);
        else Volatile.Write(ref serverToClientEof, 1);
    }
    internal void SetStage(bool forward, string stage) {
        if (forward) Volatile.Write(ref clientToServerStage, stage);
        else Volatile.Write(ref serverToClientStage, stage);
    }
    internal void Fail(bool forward, string fault) {
        if (forward) Interlocked.CompareExchange(ref clientToServerFault, fault, null);
        else Interlocked.CompareExchange(ref serverToClientFault, fault, null);
    }
    internal void FailBoth(string fault) { Fail(true, fault); Fail(false, fault); }
    internal void Complete() { Volatile.Write(ref sessionComplete, 1); }
}

public sealed class Ferrum2TcpGate : IDisposable {
    private readonly TcpListener listener;
    private readonly int upstreamPort;
    private readonly ConcurrentDictionary<int, ManualResetEventSlim> releases = new ConcurrentDictionary<int, ManualResetEventSlim>();
    private readonly ConcurrentDictionary<int, Ferrum2TcpGateObservation> observations = new ConcurrentDictionary<int, Ferrum2TcpGateObservation>();
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

    public bool WaitCompleted(int index, int milliseconds) {
        Ferrum2TcpGateObservation observation;
        if (!observations.TryGetValue(index, out observation)) return false;
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (observation.SessionComplete == "yes") return true;
            Thread.Sleep(10);
        }
        return observation.SessionComplete == "yes";
    }

    public Ferrum2TcpGateObservation Observation(int index) {
        Ferrum2TcpGateObservation observation;
        return observations.TryGetValue(index, out observation) ? observation : null;
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
                var index = Accepted + 1;
                var release = new ManualResetEventSlim(false);
                var observation = new Ferrum2TcpGateObservation();
                releases[index] = release;
                observations[index] = observation;
                Volatile.Write(ref accepted, index);
                var ignored = Task.Run(() => RunSession(client, release, observation));
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    private void RunSession(TcpClient client, ManualResetEventSlim release, Ferrum2TcpGateObservation observation) {
        try {
            release.Wait(stopped.Token);
            using (client)
            using (var upstream = new TcpClient(AddressFamily.InterNetwork)) {
                upstream.Connect(IPAddress.Loopback, upstreamPort);
                observation.SetStage(true, "source_stream");
                observation.SetStage(false, "destination_stream");
                var clientStream = client.GetStream();
                observation.SetStage(true, "destination_stream");
                observation.SetStage(false, "source_stream");
                var upstreamStream = upstream.GetStream();
                var first = Pump(clientStream, upstreamStream, upstream.Client, observation, true);
                var second = Pump(upstreamStream, clientStream, client.Client, observation, false);
                Task.WaitAll(first, second);
            }
        } catch (OperationCanceledException) { observation.FailBoth("cancelled"); }
        catch (IOException) { observation.FailBoth("io"); }
        catch (ObjectDisposedException) { observation.FailBoth("disposed"); }
        catch (SocketException) { observation.FailBoth("socket"); }
        catch (InvalidOperationException) { observation.FailBoth("invalid_operation"); }
        catch (NotSupportedException) { observation.FailBoth("not_supported"); }
        catch (AggregateException) { observation.FailBoth("aggregate"); }
        catch (Exception) { observation.FailBoth("other"); }
        finally { observation.Complete(); }
    }

    private static async Task Pump(NetworkStream input, NetworkStream output, Socket destination, Ferrum2TcpGateObservation observation, bool forward) {
        try {
            var buffer = new byte[4096];
            while (true) {
                observation.SetStage(forward, "read");
                var count = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) { observation.MarkEof(forward); break; }
                observation.SetStage(forward, "write");
                await output.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                observation.AddBytes(forward, count);
            }
            observation.SetStage(forward, "shutdown");
            try { destination.Shutdown(SocketShutdown.Send); }
            catch (SocketException) { observation.Fail(forward, "socket"); }
        } catch (OperationCanceledException) { observation.Fail(forward, "cancelled"); }
        catch (IOException) { observation.Fail(forward, "io"); }
        catch (ObjectDisposedException) { observation.Fail(forward, "disposed"); }
        catch (SocketException) { observation.Fail(forward, "socket"); }
        catch (InvalidOperationException) { observation.Fail(forward, "invalid_operation"); }
        catch (NotSupportedException) { observation.Fail(forward, "not_supported"); }
        catch (Exception) { observation.Fail(forward, "other"); }
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
    private long echoBytes;
    private int readEof;
    private int sendShutdown;
    private int sessionComplete;
    private string fault;

    public Ferrum2TcpProbe(string address, int port, string mode) {
        this.mode = mode;
        listener = new TcpListener(IPAddress.Parse(address), port);
        listener.Start();
        var ignored = Task.Run(Run);
    }

    public bool WaitAccepted(int milliseconds) { return accepted.Wait(milliseconds); }
    public bool WaitCompleted(int milliseconds) { return completed.Wait(milliseconds); }
    public byte[] Received { get { return received; } }
    public long EchoByteCount { get { return Interlocked.Read(ref echoBytes); } }
    public string ReadEof { get { return Volatile.Read(ref readEof) == 0 ? "no" : "yes"; } }
    public string SendShutdown { get { return Volatile.Read(ref sendShutdown) == 0 ? "no" : "yes"; } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }

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
                    if (count == 0) { Volatile.Write(ref readEof, 1); break; }
                    bytes.Write(buffer, 0, count);
                    if (mode == "capture") break;
                } while (!stopped.IsCancellationRequested);
                received = bytes.ToArray();
            }
            if (mode == "echo") {
                await stream.WriteAsync(received, 0, received.Length).ConfigureAwait(false);
                Interlocked.Add(ref echoBytes, received.Length);
                try {
                    client.Client.Shutdown(SocketShutdown.Send);
                    Volatile.Write(ref sendShutdown, 1);
                } catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
            }
        } catch (OperationCanceledException) { Interlocked.CompareExchange(ref fault, "cancelled", null); }
        catch (IOException) { Interlocked.CompareExchange(ref fault, "io", null); }
        catch (ObjectDisposedException) { Interlocked.CompareExchange(ref fault, "disposed", null); }
        catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
        catch (Exception) { Interlocked.CompareExchange(ref fault, "other", null); }
        finally {
            Volatile.Write(ref sessionComplete, 1);
            completed.Set();
        }
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

public sealed class Ferrum2UdpGate : IDisposable {
    private readonly object sync = new object();
    private readonly UdpClient socket;
    private readonly int upstreamPort;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private byte[] firstResponse;
    private IPEndPoint latestClient;
    private int requests;
    private int responses;
    private string fault;

    public Ferrum2UdpGate(string listenAddress, int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(listenAddress), listenPort));
        var ignored = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    public bool ReplayFirstToLatest() {
        byte[] response;
        IPEndPoint client;
        lock (sync) {
            response = firstResponse;
            client = latestClient;
        }
        if (response == null || client == null) return false;
        socket.Send(response, response.Length, client);
        return true;
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                lock (sync) { latestClient = request.RemoteEndPoint; }
                Interlocked.Increment(ref requests);
                using (var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
                    upstream.Connect(IPAddress.Loopback, upstreamPort);
                    await upstream.SendAsync(request.Buffer, request.Buffer.Length).ConfigureAwait(false);
                    var response = await upstream.ReceiveAsync().ConfigureAwait(false);
                    lock (sync) {
                        if (firstResponse == null) firstResponse = (byte[])response.Buffer.Clone();
                    }
                    await socket.SendAsync(response.Buffer, response.Buffer.Length, request.RemoteEndPoint).ConfigureAwait(false);
                    Interlocked.Increment(ref responses);
                }
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) { Interlocked.CompareExchange(ref fault, "other", null); }
    }

    public void Dispose() {
        stopped.Cancel();
        socket.Dispose();
        stopped.Dispose();
    }
}

public sealed class Ferrum2UdpProbe : IDisposable {
    private readonly UdpClient socket;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private byte[] received = new byte[0];
    private int requests;
    private int responses;
    private string fault;

    public Ferrum2UdpProbe(string address, int port) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        var ignored = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public byte[] Received { get { return Volatile.Read(ref received); } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                Volatile.Write(ref received, (byte[])request.Buffer.Clone());
                Interlocked.Increment(ref requests);
                await socket.SendAsync(request.Buffer, request.Buffer.Length, request.RemoteEndPoint).ConfigureAwait(false);
                Interlocked.Increment(ref responses);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) { Interlocked.CompareExchange(ref fault, "other", null); }
    }

    public void Dispose() {
        stopped.Cancel();
        socket.Dispose();
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

[StructLayout(LayoutKind.Explicit, Size = 28)]
internal struct Ferrum2SockaddrInet {
    [FieldOffset(0)] internal ushort Family;
    [FieldOffset(2)] internal ushort Port;
    [FieldOffset(4)] internal uint Address;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpAddressPrefix {
    internal Ferrum2SockaddrInet Prefix;
    internal byte PrefixLength;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpForwardRow2 {
    internal ulong InterfaceLuid;
    internal uint InterfaceIndex;
    internal Ferrum2IpAddressPrefix DestinationPrefix;
    internal Ferrum2SockaddrInet NextHop;
    internal byte SitePrefixLength;
    internal uint ValidLifetime;
    internal uint PreferredLifetime;
    internal uint Metric;
    internal int Protocol;
    [MarshalAs(UnmanagedType.U1)] internal bool Loopback;
    [MarshalAs(UnmanagedType.U1)] internal bool AutoconfigureAddress;
    [MarshalAs(UnmanagedType.U1)] internal bool Publish;
    [MarshalAs(UnmanagedType.U1)] internal bool Immortal;
    internal uint Age;
    internal int Origin;
}

public sealed class Ferrum2UnderlayProbe {
    public uint InterfaceIndex { get; internal set; }
    public string SourceAddress { get; internal set; }
    public string NextHop { get; internal set; }
    public byte PrefixLength { get; internal set; }
    public uint RouteMetric { get; internal set; }
}

public sealed class Ferrum2CaptureRoute : IDisposable {
    private const uint ERROR_NOT_FOUND = 1168;
    private Ferrum2IpForwardRow2 intended;
    private bool disposed;

    internal Ferrum2CaptureRoute(Ferrum2IpForwardRow2 row) { intended = row; }

    public void Verify() {
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route readback mismatch");
    }

    public void Dispose() {
        if (disposed) return;
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result == ERROR_NOT_FOUND) { disposed = true; return; }
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route ownership changed");
        result = Ferrum2NetworkFeasibility.DeleteRoute(ref current);
        if (result != 0 && result != ERROR_NOT_FOUND)
            throw new Win32Exception(checked((int)result), "DeleteIpForwardEntry2");
        result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != ERROR_NOT_FOUND) throw new InvalidOperationException("capture route delete readback mismatch");
        disposed = true;
    }
}

public static class Ferrum2NetworkFeasibility {
    private const ushort AF_INET = 2;
    private const uint ERROR_NOT_FOUND = 1168;
    private const int IPPROTO_IP = 0;
    private const int IP_UNICAST_IF = 31;

    [DllImport("iphlpapi.dll")]
    private static extern void InitializeIpForwardEntry(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint CreateIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint DeleteIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestInterfaceEx(ref Ferrum2SockaddrInet destination, out uint interfaceIndex);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestRoute2(IntPtr interfaceLuid, uint interfaceIndex, IntPtr sourceAddress,
        ref Ferrum2SockaddrInet destination, uint addressSortOptions,
        out Ferrum2IpForwardRow2 bestRoute, out Ferrum2SockaddrInet bestSourceAddress);
    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int setsockopt(IntPtr socket, int level, int option, ref uint value, int valueLength);
    [DllImport("ws2_32.dll")]
    private static extern int WSAGetLastError();

    public static int RouteRowSize { get { return Marshal.SizeOf(typeof(Ferrum2IpForwardRow2)); } }

    private static Ferrum2SockaddrInet Address(string text) {
        var address = IPAddress.Parse(text);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("IPv4 is required", "text");
        return new Ferrum2SockaddrInet {
            Family = AF_INET,
            Address = BitConverter.ToUInt32(address.GetAddressBytes(), 0)
        };
    }

    private static string Address(Ferrum2SockaddrInet value) {
        if (value.Family != AF_INET) throw new InvalidOperationException("IPv4 readback is required");
        return new IPAddress(BitConverter.GetBytes(value.Address)).ToString();
    }

    private static Ferrum2IpForwardRow2 Key(Ferrum2IpForwardRow2 intended) {
        var key = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref key);
        key.InterfaceIndex = intended.InterfaceIndex;
        key.DestinationPrefix = intended.DestinationPrefix;
        key.NextHop = intended.NextHop;
        return key;
    }

    internal static uint ReadRoute(Ferrum2IpForwardRow2 intended, out Ferrum2IpForwardRow2 current) {
        current = Key(intended);
        return GetIpForwardEntry2(ref current);
    }

    internal static uint DeleteRoute(ref Ferrum2IpForwardRow2 row) { return DeleteIpForwardEntry2(ref row); }

    internal static bool MatchesOwned(Ferrum2IpForwardRow2 expected, Ferrum2IpForwardRow2 actual) {
        return actual.InterfaceIndex == expected.InterfaceIndex &&
            actual.DestinationPrefix.Prefix.Family == AF_INET &&
            actual.DestinationPrefix.Prefix.Address == expected.DestinationPrefix.Prefix.Address &&
            actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength &&
            actual.NextHop.Family == AF_INET && actual.NextHop.Address == 0 &&
            actual.SitePrefixLength == expected.SitePrefixLength &&
            actual.ValidLifetime == expected.ValidLifetime &&
            actual.PreferredLifetime == expected.PreferredLifetime &&
            actual.Metric == expected.Metric && actual.Protocol == expected.Protocol &&
            actual.Loopback == expected.Loopback &&
            actual.AutoconfigureAddress == expected.AutoconfigureAddress &&
            actual.Publish == expected.Publish && actual.Immortal == expected.Immortal &&
            actual.Origin == expected.Origin;
    }

    public static Ferrum2CaptureRoute CreateCaptureRoute(uint interfaceIndex, string prefix, uint metric) {
        if (RouteRowSize != 104) throw new InvalidOperationException("MIB_IPFORWARD_ROW2 ABI size mismatch");
        var parts = prefix.Split('/');
        if (parts.Length != 2 || parts[1] != "1" || (parts[0] != "0.0.0.0" && parts[0] != "128.0.0.0"))
            throw new ArgumentException("an exact IPv4 /1 capture prefix is required", "prefix");
        var row = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref row);
        row.InterfaceLuid = 0;
        row.InterfaceIndex = interfaceIndex;
        row.DestinationPrefix = new Ferrum2IpAddressPrefix { Prefix = Address(parts[0]), PrefixLength = 1 };
        row.NextHop = Address("0.0.0.0");
        row.SitePrefixLength = 0;
        row.ValidLifetime = UInt32.MaxValue;
        row.PreferredLifetime = UInt32.MaxValue;
        row.Metric = metric;
        row.Protocol = 3;
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;
        row.Age = 0;
        row.Origin = 0;
        Ferrum2IpForwardRow2 ignored;
        var result = ReadRoute(row, out ignored);
        if (result != ERROR_NOT_FOUND) {
            if (result == 0) throw new InvalidOperationException("capture route baseline not absent");
            throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        }
        result = CreateIpForwardEntry2(ref row);
        if (result != 0) throw new Win32Exception(checked((int)result), "CreateIpForwardEntry2");
        var lease = new Ferrum2CaptureRoute(row);
        try { lease.Verify(); return lease; }
        catch { lease.Dispose(); throw; }
    }

    public static Ferrum2UnderlayProbe GetFixedRoute(string destinationText) {
        var destination = Address(destinationText);
        uint interfaceIndex;
        var result = GetBestInterfaceEx(ref destination, out interfaceIndex);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestInterfaceEx");
        return GetConstrainedRoute(destinationText, interfaceIndex);
    }

    public static Ferrum2UnderlayProbe GetConstrainedRoute(string destinationText, uint interfaceIndex) {
        var destination = Address(destinationText);
        Ferrum2IpForwardRow2 route;
        Ferrum2SockaddrInet source;
        var result = GetBestRoute2(IntPtr.Zero, interfaceIndex, IntPtr.Zero, ref destination, 0, out route, out source);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestRoute2");
        if (route.InterfaceIndex != interfaceIndex || source.Family != AF_INET || source.Address == 0)
            throw new InvalidOperationException("constrained best route identity mismatch");
        return new Ferrum2UnderlayProbe {
            InterfaceIndex = interfaceIndex,
            SourceAddress = Address(source),
            NextHop = Address(route.NextHop),
            PrefixLength = route.DestinationPrefix.PrefixLength,
            RouteMetric = route.Metric
        };
    }

    private static void Pin(Socket socket, uint interfaceIndex) {
        var networkOrder = unchecked((uint)IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex)));
        if (setsockopt(socket.Handle, IPPROTO_IP, IP_UNICAST_IF, ref networkOrder, sizeof(uint)) != 0)
            throw new Win32Exception(WSAGetLastError(), "IP_UNICAST_IF");
    }

    private static void SendAll(Socket socket, byte[] payload) {
        var offset = 0;
        while (offset < payload.Length) offset += socket.Send(payload, offset, payload.Length - offset, SocketFlags.None);
    }

    private static byte[] ReceiveExact(Socket socket, int length) {
        var received = new byte[length];
        var offset = 0;
        while (offset < length) {
            var count = socket.Receive(received, offset, length - offset, SocketFlags.None);
            if (count == 0) throw new EndOfStreamException("support listener closed before echo");
            offset += count;
        }
        return received;
    }

    private static void VerifySource(Socket socket, string expectedSource) {
        var local = socket.LocalEndPoint as IPEndPoint;
        if (local == null || local.Address.ToString() != expectedSource)
            throw new InvalidOperationException("pinned socket source mismatch");
    }

    public static void TcpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            VerifySource(socket, expectedSource);
            SendAll(socket, payload);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support TCP echo mismatch");
        }
    }

    public static void UdpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            SendAll(socket, payload);
            VerifySource(socket, expectedSource);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support UDP echo mismatch");
        }
    }
}
'@

function Write-CapabilityEvidence([string]$Phase, [hashtable]$Data) {
    $row = [ordered]@{
        schema = 1
        phase = $Phase
        timestamp_utc = [DateTime]::UtcNow.ToString("O")
        data = $Data
    }
    Add-Content -LiteralPath $script:capabilityEvidence -Value ($row | ConvertTo-Json -Compress -Depth 8) -Encoding utf8NoBOM
}

function Get-Ipv4DefaultUnderlay {
    $rows = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                $route = $_
                $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -ErrorAction Stop
                $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -IncludeHidden -ErrorAction Stop
                if ($route.InterfaceIndex -ne 1 -and $route.InterfaceIndex -ne $script:ownedInterfaceIndex -and
                    $interface.ConnectionState -eq "Connected" -and $adapter.Status -eq "Up" -and
                    $adapter.InterfaceDescription -notmatch "Wintun") {
                    [pscustomobject]@{
                        Route = $route
                        Interface = $interface
                        EffectiveMetric = [uint64]$route.RouteMetric + [uint64]$interface.InterfaceMetric
                    }
                }
            }
    )
    Assert-True ($rows.Count -gt 0) "eligible IPv4 default underlay is missing"
    $minimum = ($rows | Measure-Object EffectiveMetric -Minimum).Minimum
    $best = @($rows | Where-Object { $_.EffectiveMetric -eq $minimum })
    $indices = @($best | ForEach-Object { [uint32]$_.Route.InterfaceIndex } | Sort-Object -Unique)
    Assert-True ($indices.Count -eq 1 -and $best.Count -eq 1) "eligible IPv4 default underlay is ambiguous"
    $sources = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $indices[0] -AddressState Preferred -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne "0.0.0.0" -and $_.IPAddress -notlike "169.254.*" })
    Assert-True ($sources.Count -ge 1) "eligible IPv4 default source is missing"
    return [pscustomobject]@{ InterfaceIndex = $indices[0]; Row = $best[0]; Sources = $sources }
}

function Get-PhysicalDnsSnapshot([int]$TunInterfaceIndex) {
    return @(
        Get-DnsClientServerAddress -ErrorAction Stop |
            Where-Object { $_.InterfaceIndex -ne $TunInterfaceIndex } |
            Sort-Object InterfaceIndex, AddressFamily |
            ForEach-Object { "$($_.InterfaceIndex)|$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" }
    )
}

function Get-TunIpv4Dns([int]$InterfaceIndex) {
    $row = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
    return @($row.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Set-CapabilityDns([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityDnsApplied) "capability DNS is already applied"
    $script:capabilityDnsSnapshot = @(Get-TunIpv4Dns $InterfaceIndex)
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses "198.18.0.1" -Validate -ErrorAction Stop
    $script:capabilityDnsApplied = $true
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS readback"
}

function Restore-CapabilityDns([int]$InterfaceIndex) {
    if (-not $script:capabilityDnsApplied) { return }
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS ownership"
    if ($script:capabilityDnsSnapshot.Count -eq 0) {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $script:capabilityDnsSnapshot -Validate -ErrorAction Stop
    }
    Assert-SnapshotEqual @($script:capabilityDnsSnapshot) @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS restore"
    $script:capabilityDnsApplied = $false
    $script:capabilityDnsSnapshot = $null
}

function Set-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityMetricApplied) "capability interface metric is already applied"
    $row = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricSnapshot = [pscustomobject]@{
        AutomaticMetric = [string]$row.AutomaticMetric
        InterfaceMetric = [uint32]$row.InterfaceMetric
    }
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricApplied = $true
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric readback mismatch"
}

function Restore-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    if (-not $script:capabilityMetricApplied) { return }
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric ownership changed"
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
        -AutomaticMetric $script:capabilityMetricSnapshot.AutomaticMetric `
        -InterfaceMetric $script:capabilityMetricSnapshot.InterfaceMetric -PolicyStore ActiveStore -ErrorAction Stop
    $restored = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ([string]$restored.AutomaticMetric -eq $script:capabilityMetricSnapshot.AutomaticMetric -and
        [uint32]$restored.InterfaceMetric -eq $script:capabilityMetricSnapshot.InterfaceMetric) "capability interface metric restore mismatch"
    $script:capabilityMetricApplied = $false
    $script:capabilityMetricSnapshot = $null
}

function Remove-CapabilityRoutes {
    for ($index = $script:capabilityRoutes.Count - 1; $index -ge 0; $index--) {
        $script:capabilityRoutes[$index].Dispose()
        $script:capabilityRoutes.RemoveAt($index)
    }
}

function Get-TunAccepted([int]$MetricsPort) {
    return Get-CounterValue (Get-Metrics $MetricsPort) "ferrum2_tun_packets_accepted"
}

function Wait-TunAcceptedAfter([int]$MetricsPort, [uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $after = Get-TunAccepted $MetricsPort
        if ($after -gt $Before) { return $after }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "unpinned packet did not enter Wintun"
}

function Invoke-PktMon([string[]]$Arguments, [int]$TimeoutMilliseconds = 5000) {
    $path = "C:\Windows\System32\PktMon.exe"
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $version = [Version](($item.VersionInfo.FileVersion -split " ")[0])
    Assert-True ($version -eq [Version]"10.0.19041.906") "PktMon version mismatch"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-True $process.Start() "PktMon did not start"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "PktMon command timed out"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-True ($process.ExitCode -eq 0) "PktMon command failed"
        return [pscustomobject]@{ Stdout = $stdout; Stderr = $stderr }
    } finally {
        $process.Dispose()
    }
}

function Get-PktMonOutputLines([string]$Text) {
    return @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
}

function Assert-PktMonAbsent {
    $status = Get-PktMonOutputLines (Invoke-PktMon @("status")).Stdout
    Assert-True (@($status | Where-Object { $_ -ceq "Packet Monitor is not running." }).Count -eq 1) "PktMon baseline is running"
    $filters = Get-PktMonOutputLines (Invoke-PktMon @("filter", "list")).Stdout
    Assert-True ($filters.Count -eq 2 -and $filters[0] -ceq "Packet Filters:" -and $filters[1] -ceq "None") "PktMon filter baseline is not empty"
}

function Get-PktMonDirectProperties([object]$Record) {
    $propertyField = $Record.PSObject.Properties["Properties"]
    Assert-True ($null -ne $propertyField -and $propertyField.Value -is [Array]) "PktMon component properties are invalid"
    $result = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($property in @($propertyField.Value)) {
        Assert-True ((@($property.PSObject.Properties.Name) -join "|") -ceq "Name|Value") "PktMon component property shape is invalid"
        $name = [string]$property.Name
        Assert-True (-not [string]::IsNullOrWhiteSpace($name)) "PktMon component property name is invalid"
        if ($name -ceq "ifIndex" -or $name -ceq "ifGuid") {
            Assert-True (-not $result.ContainsKey($name)) "PktMon identity property is duplicated"
            $result.Add($name, $property.Value)
        }
    }
    return $result
}

function Get-PktMonComponentId([object]$Adapter) {
    $text = (Invoke-PktMon @("list", "--json")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon component JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon component JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon component groups are empty"
    $interfaceGuid = [guid]::Empty
    Assert-True ([guid]::TryParse([string]$Adapter.InterfaceGuid, [ref]$interfaceGuid)) "owned adapter GUID is invalid"
    $expectedDriver = $null
    if ($null -ne $Adapter.PSObject.Properties["DriverFileName"] -and
        -not [string]::IsNullOrWhiteSpace([string]$Adapter.DriverFileName)) {
        $expectedDriver = [IO.Path]::GetFileName([string]$Adapter.DriverFileName)
    }
    $recordsById = @{}
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon component group shape is invalid"
        foreach ($record in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $record.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$record.Id, [ref]$id) -and $id -gt 0) "PktMon component Id is invalid"
            [void](Get-PktMonDirectProperties $record)
            if (-not $recordsById.ContainsKey($id)) { $recordsById[$id] = [Collections.Generic.List[object]]::new() }
            $recordsById[$id].Add($record)
        }
    }
    $matches = [Collections.Generic.List[int]]::new()
    foreach ($entry in $recordsById.GetEnumerator()) {
        $hasIdentityRecord = $false
        $hasDriver = $null -eq $expectedDriver
        foreach ($record in $entry.Value) {
            $properties = Get-PktMonDirectProperties $record
            $recordIndexMatches = $false
            $recordGuidMatches = $false
            if ($properties.ContainsKey("ifIndex")) {
                [int]$ifIndex = 0
                Assert-True ([int]::TryParse([string]$properties["ifIndex"], [ref]$ifIndex)) "PktMon ifIndex is invalid"
                $recordIndexMatches = $ifIndex -eq [int]$Adapter.ifIndex
            }
            if ($properties.ContainsKey("ifGuid")) {
                $ifGuid = [guid]::Empty
                Assert-True ([guid]::TryParse([string]$properties["ifGuid"], [ref]$ifGuid)) "PktMon ifGuid is invalid"
                $recordGuidMatches = $ifGuid -eq $interfaceGuid
            }
            if ($recordIndexMatches -and $recordGuidMatches) { $hasIdentityRecord = $true }
            if ($null -ne $expectedDriver -and $null -ne $record.PSObject.Properties["DriverName"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.DriverName) -and
                [IO.Path]::GetFileName([string]$record.DriverName) -ieq $expectedDriver) {
                $hasDriver = $true
            }
        }
        if ($hasIdentityRecord -and $hasDriver) { $matches.Add([int]$entry.Key) }
    }
    Assert-True ($matches.Count -eq 1) "owned Wintun PktMon component is ambiguous"
    return $matches[0]
}

function ConvertTo-PktMonUInt64([object]$Value) {
    [uint64]$parsed = 0
    Assert-True ([uint64]::TryParse([string]$Value, [ref]$parsed)) "PktMon counter value is invalid"
    return $parsed
}

function Add-PktMonChecked([uint64]$Total, [uint64]$Value) {
    Assert-True ($Value -le [uint64]::MaxValue - $Total) "PktMon counter overflowed"
    return [uint64]($Total + $Value)
}

function Get-PktMonFlowPackets {
    $text = (Invoke-PktMon @("counters", "--type", "flow", "--json", "--zero")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon counter JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon counter JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon counter groups are empty"
    $records = [Collections.Generic.List[object]]::new()
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon counter group shape is invalid"
        foreach ($component in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $component.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$component.Id, [ref]$id) -and $id -gt 0) "PktMon counter component Id is invalid"
            if ($id -eq $script:pktmonComponentId) { $records.Add($component) }
        }
    }
    Assert-True ($records.Count -gt 0) "owned PktMon component counters are missing"
    [uint64]$total = 0
    $flowEdges = 0
    foreach ($component in $records) {
        Assert-True ($null -ne $component.PSObject.Properties["Counters"] -and $component.Counters -is [Array]) "PktMon counter component shape is invalid"
        foreach ($counter in @($component.Counters)) {
            Assert-True ($null -ne $counter.PSObject.Properties["Type"] -and $counter.Type -ceq "Flows") "PktMon counter edge type is invalid"
            foreach ($direction in @("Inbound", "Outbound")) {
                $edge = $counter.PSObject.Properties[$direction]
                Assert-True ($null -ne $edge -and $null -ne $edge.Value.PSObject.Properties["Packets"] -and
                    $null -ne $edge.Value.PSObject.Properties["Bytes"]) "PktMon flow edge shape is invalid"
                $packets = ConvertTo-PktMonUInt64 $edge.Value.Packets
                [void](ConvertTo-PktMonUInt64 $edge.Value.Bytes)
                $total = Add-PktMonChecked $total $packets
            }
            $flowEdges++
        }
    }
    Assert-True ($flowEdges -gt 0) "owned PktMon flow counters are missing"
    return $total
}

function Get-PktMonFlowPacketDelta([uint64]$Before) {
    $after = Get-PktMonFlowPackets
    Assert-True ($after -ge $Before) "PktMon flow counter regressed"
    return [uint64]($after - $Before)
}

function Wait-PktMonFlowPacketsAfter([uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    $quiet = [Diagnostics.Stopwatch]::StartNew()
    [uint64]$last = $Before
    $observed = $false
    do {
        $after = Get-PktMonFlowPackets
        Assert-True ($after -ge $last) "PktMon flow counter regressed"
        if ($after -gt $Before) {
            if (-not $observed -or $after -ne $last) {
                $observed = $true
                $quiet.Restart()
            } elseif ($quiet.ElapsedMilliseconds -ge 500) {
                return [uint64]($after - $Before)
            }
        }
        $last = $after
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "filtered unpinned flow did not enter Wintun"
}

function Stop-CapabilityPktMon {
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    if ($script:pktmonStarted -or $script:pktmonStartAttempted) {
        try {
            [void](Invoke-PktMon @("stop"))
            $script:pktmonStarted = $false
            $script:pktmonStartAttempted = $false
        } catch { $cleanupFailures.Add("stop") }
    }
    if ($script:pktmonTcpFilterOwned -or $script:pktmonUdpFilterOwned) {
        try {
            [void](Invoke-PktMon @("filter", "remove"))
            $script:pktmonTcpFilterOwned = $false
            $script:pktmonUdpFilterOwned = $false
        } catch { $cleanupFailures.Add("filters") }
        try { [void](Invoke-PktMon @("reset")) }
        catch { $cleanupFailures.Add("reset") }
    }
    try { Assert-PktMonAbsent }
    catch { $cleanupFailures.Add("absence") }
    Assert-True ($cleanupFailures.Count -eq 0) "PktMon cleanup failed"
}

function Invoke-UnpinnedTcpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connected = $client.ConnectAsync($Address, $Port)
        if ($connected.Wait(1500) -and -not $connected.IsFaulted) {
            $stream = $client.GetStream()
            $stream.Write($Payload, 0, $Payload.Length)
            $read = [byte[]]::new($Payload.Length)
            $response = $stream.ReadAsync($read, 0, $read.Length)
            if ($response.Wait(750) -and -not $response.IsFaulted -and $response.Result -gt 0 -and
                (($read[0..($response.Result - 1)] -join ",") -eq ($Payload[0..($response.Result - 1)] -join ","))) {
                throw "unpinned TCP reached the support listener"
            }
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-UnpinnedUdpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Connect($Address, $Port)
        [void]$client.Send($Payload, $Payload.Length)
        $response = $client.ReceiveAsync()
        if ($response.Wait(750) -and -not $response.IsFaulted -and
            (($response.Result.Buffer -join ",") -eq ($Payload -join ","))) {
            throw "unpinned UDP reached the support listener"
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-SystemDnsWitness([string]$Name, [bool]$TcpOnly, [Ferrum2DnsResponder]$Responder) {
    $before = $Responder.Requests
    Clear-DnsClientCache -ErrorAction Stop
    $parameters = @{ Name = $Name; Type = "A"; DnsOnly = $true; NoHostsFile = $true; ErrorAction = "Stop" }
    if ($TcpOnly) { $parameters.TcpOnly = $true }
    $answer = @(Resolve-DnsName @parameters | Where-Object { $_.Type -eq "A" -and $_.IPAddress -eq "192.0.2.55" })
    Assert-True ($answer.Count -ge 1) "Windows resolver did not return the capability answer"
    Assert-True ($Responder.Requests -eq $before + 1) "Windows resolver did not use the local DNS answer path exactly once"
}

function Open-TunTcp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.TcpClient]::new($family)
    $client.NoDelay = $true
    $client.SendBufferSize = 4096
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $connected = $client.ConnectAsync($Address, $Port)
    Assert-True ($connected.Wait(5000)) "TUN TCP local handshake timeout"
    if ($connected.IsFaulted) { throw "TUN TCP local handshake failed" }
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN TCP source bind mismatch"
    return [pscustomobject]@{ Client = $client }
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
    [byte[]]$Payload,
    [hashtable]$Observation = $null
) {
    $expectedGate = $Gate.Accepted + 1
    if ($null -ne $Observation) {
        $Observation.Gate = $Gate
        $Observation.GateIndex = $expectedGate
        $Observation.GateAccepted = "no"
        $Observation.Probe = $null
        $Observation.ProbeAccepted = "no"
        $Observation.AppResult = "other"
    }
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        Assert-True ($Gate.WaitAccepted($expectedGate, 5000)) "selected egress gate was not opened"
        if ($null -ne $Observation) { $Observation.GateAccepted = "yes" }
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        $probe = [Ferrum2TcpProbe]::new($Address, $Port, "echo")
        $script:tcpResources.Add($probe)
        if ($null -ne $Observation) { $Observation.Probe = $probe }
        $Gate.Release($expectedGate)
        $probeAccepted = $probe.WaitAccepted(5000)
        if ($null -ne $Observation -and $probeAccepted) { $Observation.ProbeAccepted = "yes" }
        Assert-True $probeAccepted "selected target was not opened"
        $echo = Read-StreamToEnd $stream
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "echo or half-close mismatch"
        Assert-True ($probe.WaitCompleted(5000)) "target half-close did not complete"
        Assert-True ($probe.SessionComplete -eq "yes" -and $probe.Fault -eq "none" -and
            $probe.ReadEof -eq "yes" -and $probe.SendShutdown -eq "yes") "target half-close completed with a fault"
        if ($null -ne $Observation) { $Observation.AppResult = "success" }
    } catch {
        if ($null -ne $Observation) {
            $errorCursor = $_.Exception
            $sawIo = $false
            $appResult = "other"
            for ($depth = 0; $depth -lt 4 -and $errorCursor; $depth++) {
                if ($errorCursor -is [Net.Sockets.SocketException] -and
                    $errorCursor.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset) { $appResult = "reset"; break }
                if ($errorCursor -is [IO.IOException]) { $sawIo = $true }
                $errorCursor = $errorCursor.InnerException
            }
            if ($appResult -eq "other" -and $sawIo) { $appResult = "io" }
            $Observation.AppResult = $appResult
        }
        throw
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
    }
}

function New-DnsQuery([uint16]$Id) {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]([byte]($Id -shr 8), [byte]($Id -band 0xff), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in @("query", "tun", "test")) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$encoded.Length)
        $bytes.AddRange($encoded)
    }
    $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
    return $bytes.ToArray()
}

function Open-TunUdp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.UdpClient]::new($family)
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $client.Connect($Address, $Port)
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN UDP source bind mismatch"
    return $client
}

function Receive-TunUdp([Net.Sockets.UdpClient]$Client, [int]$TimeoutMilliseconds = 5000) {
    $receive = $Client.ReceiveAsync()
    Assert-True ($receive.Wait($TimeoutMilliseconds)) "TUN UDP response timeout"
    if ($receive.IsFaulted) { throw "TUN UDP response failed" }
    return $receive.Result.Buffer
}

function Invoke-UdpEchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2UdpGate]$Gate,
    [byte[]]$Payload
) {
    $expectedGate = $Gate.Requests + 1
    $probe = [Ferrum2UdpProbe]::new($Address, $Port)
    $script:tcpResources.Add($probe)
    $client = Open-TunUdp $Address $Port $InterfaceIndex
    try {
        [void]$client.Send($Payload, $Payload.Length)
        Assert-True ($Gate.WaitRequests($expectedGate, 5000)) "selected UDP egress gate was not opened"
        $response = Receive-TunUdp $client
        Assert-True (($response -join ",") -eq ($Payload -join ",")) "UDP echo mismatch"
        Assert-True ($probe.WaitRequests(1, 5000)) "UDP target did not receive datagram"
        Assert-True (($probe.Received -join ",") -eq ($Payload -join ",")) "UDP target payload mismatch"
        Assert-True ($Gate.Fault -eq "none" -and $probe.Fault -eq "none") "UDP witness faulted"
    } finally { $client.Dispose() }
}

function Invoke-AdapterCycles([string]$Executable, [string]$Configuration) {
    for ($cycle = 0; $cycle -lt 100; $cycle++) {
        Assert-True (-not $script:activeProcess) "cycle candidate state was not empty"
        $candidateBaseline = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
        Assert-True ($candidateBaseline.Count -eq 0) "cycle candidate baseline not absent"
        Assert-InterfaceGone $script:adapterName $null
        $script:activeProcess = Start-Candidate $Executable $Configuration
        $adapter = Wait-AdapterReady $script:adapterName
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        $cycleRoute = Add-TunRoute $script:ownedInterfaceIndex "192.0.2.200/32"
        $cycleRouteReadback = @(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($cycleRouteReadback.Count -eq 1) "cycle route readback mismatch"
        Remove-NetRoute -InputObject $cycleRoute -Confirm:$false -ErrorAction Stop
        Assert-True $script:ownedRoutes.Remove($cycleRoute) "cycle route ownership mismatch"
        Assert-True (@(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "cycle route leaked"
        $cycleProcess = $script:activeProcess
        Stop-Candidate $cycleProcess
        $cycleProcess.Refresh()
        Assert-True $cycleProcess.HasExited "cycle candidate process leaked"
        $script:activeProcess = $null
        $candidateAfterStop = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
        Assert-True ($candidateAfterStop.Count -eq 0) "cycle candidate remained after stop"
        Wait-AdapterAbsent $script:adapterName
        Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
        $script:cycleRows++
    }
    Assert-True ($script:cycleRows -eq 100) "adapter cycle count mismatch"
}

try {
    Assert-True (-not (Test-Path -LiteralPath $work)) "run work baseline not absent"
    Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) "run process baseline not absent"
    Assert-True (-not (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)) "run adapter baseline not absent"
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
    $exports = @(Get-PeExportNames $pe)
    Assert-True (($exports -join "|") -eq ($expectedExports -join "|")) "DLL export set mismatch"
    $foundation++

    if ($Mode -eq "network-feasibility") {
        Assert-True (Test-Path -LiteralPath $binary) "staged candidate binary is missing"
    } else {
        Push-Location $workspace
        try {
            if ($Mode -in @("tcp", "udp", "full", "performance")) { & cargo +1.97.1 build -p ferrum2-client -p ferrum2-server --locked }
            else { & cargo +1.97.1 build -p ferrum2-client --locked }
            if ($LASTEXITCODE -ne 0) { throw "candidate build failed" }
        }
        finally { Pop-Location }
    }
    if ($Mode -eq "network-feasibility") {
        Assert-PktMonAbsent
        Assert-True ([Ferrum2NetworkFeasibility]::RouteRowSize -eq 104) "route ABI size mismatch"
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $fixedUnderlay = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
        $defaultUnderlay = Get-Ipv4DefaultUnderlay
        Assert-True ($fixedUnderlay.InterfaceIndex -eq $defaultUnderlay.InterfaceIndex -and $fixedUnderlay.PrefixLength -eq 0) "fixed endpoint did not use the eligible IPv4 physical default"
        Assert-True (@($defaultUnderlay.Sources | Where-Object { $_.IPAddress -eq $fixedUnderlay.SourceAddress }).Count -eq 1) "fixed endpoint best source mismatch"
        $dynamicUnderlay = [Ferrum2NetworkFeasibility]::GetConstrainedRoute($supportAddress, $defaultUnderlay.InterfaceIndex)
        Assert-True ($dynamicUnderlay.InterfaceIndex -eq $defaultUnderlay.InterfaceIndex -and $dynamicUnderlay.PrefixLength -eq 0) "dynamic default constrained route mismatch"
        Assert-True (@($defaultUnderlay.Sources | Where-Object { $_.IPAddress -eq $dynamicUnderlay.SourceAddress }).Count -eq 1) "dynamic default source mismatch"

        $preflightTcp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-tcp-live")
        $preflightUdp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-udp-live")
        [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightTcp)
        [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightUdp)

        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        Write-CapabilityEvidence "before" ([ordered]@{
            candidate_sha = $capabilityIdentity.Ledger.candidate_sha
            probe_sha256 = $capabilityIdentity.Ledger.probe_sha256
            identity_sha256 = $capabilityIdentityHash
            guest_build = $capabilityIdentity.GuestBuild
            physical_default = @($defaultUnderlay.Row.Route | Select-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric)
            fixed_underlay = $fixedUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            dynamic_underlay = $dynamicUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            physical_dns = $physicalDnsBaseline
            ferrum2_processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            ferrum2_adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
        })

        $metricsPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "dead"
server = "127.0.0.1:9"
[route]
final = "dead"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$supportAddress"
port = $supportTcpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$supportAddress"
port = $supportUdpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[udp]
enabled = false
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
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
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($dnsResponder)
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "network feasibility config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "network feasibility config marker mismatch"
        Set-Content -LiteralPath $dllJournal -Value $expectedDllHash -Encoding ascii
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        $addressBaseline = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
        $routeBaseline = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $ipv6AddressBaseline = @($addressBaseline | Where-Object { $_ -like "IPv6|*" })
        Assert-True ($addressBaseline -contains "IPv4|198.18.0.2|30|Preferred" -and $addressBaseline -contains "IPv6|fd00::2|126|Preferred") "network feasibility address baseline mismatch"

        $partial = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, "0.0.0.0/1", 1)
        $capabilityRoutes.Add($partial)
        $partial.Verify()
        $partial.Dispose()
        Assert-True $capabilityRoutes.Remove($partial) "partial route journal mismatch"
        Assert-SnapshotEqual $routeBaseline @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex) "partial route rollback"

        $captureTraffic = Get-AdapterTraffic $adapterName
        $captureWindow = [Diagnostics.Stopwatch]::StartNew()
        $firstPrefix = if ([byte][Net.IPAddress]::Parse($supportAddress).GetAddressBytes()[0] -lt 128) { "0.0.0.0/1" } else { "128.0.0.0/1" }
        $secondPrefix = if ($firstPrefix -eq "0.0.0.0/1") { "128.0.0.0/1" } else { "0.0.0.0/1" }
        $firstRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $firstPrefix, 1)
        $capabilityRoutes.Add($firstRoute)
        [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort ([Text.Encoding]::ASCII.GetBytes("m16-capture-window")))
        $secondRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $secondPrefix, 1)
        $capabilityRoutes.Add($secondRoute)
        $captureWindow.Stop()
        Assert-True ($captureWindow.ElapsedMilliseconds -le 3000) "capture-before-admission window exceeded"
        $captureTrafficAfter = Get-AdapterTraffic $adapterName
        Assert-True ($captureTrafficAfter.ReceivedPacketErrors -eq $captureTraffic.ReceivedPacketErrors -and
            $captureTrafficAfter.OutboundPacketErrors -eq $captureTraffic.OutboundPacketErrors -and
            $captureTrafficAfter.ReceivedDiscardedPackets -eq $captureTraffic.ReceivedDiscardedPackets -and
            $captureTrafficAfter.OutboundDiscardedPackets -eq $captureTraffic.OutboundDiscardedPackets) "capture-before-admission overflowed the Wintun ring"
        $capabilityWindowRows = 1
        foreach ($route in $capabilityRoutes) { $route.Verify() }
        $capabilityRouteRows = 2

        Assert-PktMonAbsent
        $pktmonComponentId = Get-PktMonComponentId $adapter
        $pktmonTcpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Tcp", "-i", $supportAddress, "-t", "TCP", "-p", [string]$supportTcpPort))
        $pktmonUdpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Udp", "-i", $supportAddress, "-t", "UDP", "-p", [string]$supportUdpPort))
        $pktmonStartAttempted = $true
        [void](Invoke-PktMon @("start", "--capture", "--counters-only", "--comp", [string]$pktmonComponentId, "--type", "flow"))
        $pktmonStarted = $true
        $pktmonStartAttempted = $false
        [void](Get-PktMonFlowPackets)

        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-tcp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedTcpCapture $supportAddress $supportTcpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_tcp_unpinned"] = $filteredPackets
            $capabilityTcpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned TCP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_tcp_pinned"] = $filteredPackets
            $capabilityTcpRows++
        }
        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-udp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_udp_unpinned"] = $filteredPackets
            $capabilityUdpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned UDP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_udp_pinned"] = $filteredPackets
            $capabilityUdpRows++
        }
        Assert-True ($capabilityTcpRows -eq 4 -and $capabilityUdpRows -eq 4) "socket pin row count mismatch"

        Set-CapabilityDns $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS after Wintun apply"
        try {
            Invoke-SystemDnsWitness "m16-$runIdentity-udp.tun.test" $false $dnsResponder
            Invoke-SystemDnsWitness "m16-$runIdentity-tcp.tun.test" $true $dnsResponder
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "unchanged"
        } catch {
            Set-CapabilityInterfaceMetric $ownedInterfaceIndex
            $capabilityDnsRows = 0
            Invoke-SystemDnsWitness "m16-$runIdentity-lease-udp.tun.test" $false $dnsResponder
            Invoke-SystemDnsWitness "m16-$runIdentity-lease-tcp.tun.test" $true $dnsResponder
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "leased"
        }
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS active sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address active sentinel"

        Write-CapabilityEvidence "active" ([ordered]@{
            interface_metric = $capabilityInterfaceMetric
            capture_window_ms = $captureWindow.ElapsedMilliseconds
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
            tun_accepted = Get-TunAccepted $metricsPort
            route_rows = $capabilityRouteRows
            tcp_rows = $capabilityTcpRows
            udp_rows = $capabilityUdpRows
            dns_rows = $capabilityDnsRows
            pktmon_filtered_flow_packets = $capabilityFilteredPackets
        })

        Stop-CapabilityPktMon
        $routesBeforeCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $limitedBroadcastRoute = "IPv4|255.255.255.255/32|0.0.0.0"
        Assert-True (@($routeBaseline | Where-Object { $_ -ceq $limitedBroadcastRoute }).Count -eq 1) "limited broadcast route baseline mismatch"
        $routeCleanupBaseline = @($routeBaseline | Where-Object { $_ -cne $limitedBroadcastRoute })
        Assert-True ($routeCleanupBaseline.Count -eq $routeBaseline.Count - 1) "limited broadcast cleanup baseline mismatch"
        $captureRouteRows = @(
            "IPv4|0.0.0.0/1|0.0.0.0",
            "IPv4|128.0.0.0/1|0.0.0.0"
        )
        foreach ($captureRouteRow in $captureRouteRows) {
            Assert-True (@($routesBeforeCaptureCleanup | Where-Object { $_ -ceq $captureRouteRow }).Count -eq 1) "owned capture route snapshot mismatch"
        }
        Remove-CapabilityRoutes
        $routeCleanupDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $routesAfterCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            if (@(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup)).Count -eq 0) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $routeCleanupDeadline)
        $routeCleanupDifference = @(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup))
        $routeCleanupLabel = "capture route exact rollback"
        if ($routeCleanupDifference.Count -gt 0) {
            $routeCleanupDiagnostic = @($routeCleanupDifference | Select-Object InputObject,SideIndicator)
            $routeCleanupLabel += " difference=$(ConvertTo-Json -InputObject $routeCleanupDiagnostic -Compress)"
        }
        Assert-SnapshotEqual $routeCleanupBaseline $routesAfterCaptureCleanup $routeCleanupLabel
        Restore-CapabilityDns $ownedInterfaceIndex
        Restore-CapabilityInterfaceMetric $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS normal cleanup sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address normal cleanup sentinel"
        $ownerMetrics = Get-Metrics $metricsPort
        Assert-True ((Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_sessions_active") -eq 0 -and
            (Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_buffered_bytes") -eq 0) "normal cleanup process-private owners remained"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "normal cleanup process residue"
        Write-CapabilityEvidence "normal-cleanup" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
        })

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        if ($capabilityInterfaceMetric -eq "leased") { Set-CapabilityInterfaceMetric $ownedInterfaceIndex }
        Set-CapabilityDns $ownedInterfaceIndex
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $route = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $prefix, 1)
            $capabilityRoutes.Add($route)
        }
        Write-CapabilityEvidence "hard-kill-active" ([ordered]@{
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
        })
        $killedProcess = $activeProcess
        Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$killedProcess.Id)) "TerminateProcess failed"
        Assert-True (Wait-ProcessExit $killedProcess 20) "hard-kill candidate did not exit"
        Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$killedProcess.Id) -ne 0) "hard-kill candidate unexpectedly exited cleanly"
        [Ferrum2ProcessGroup]::Close([uint32]$killedProcess.Id)
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "hard-kill process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill DNS residue"
        Remove-CapabilityRoutes
        $capabilityDnsApplied = $false
        $capabilityDnsSnapshot = $null
        $capabilityMetricApplied = $false
        $capabilityMetricSnapshot = $null
        $capabilityHardKillRows = 1
        Write-CapabilityEvidence "after" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
        })
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS final sentinel"
    }
    if ($Mode -in @("lifecycle", "full")) {
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

    Set-Content -LiteralPath $dllJournal -Value $expectedDllHash -Encoding ascii
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
    [void](Add-TunRoute $adapter.ifIndex "192.0.2.200/32")
    [void](Add-TunRoute $adapter.ifIndex "2001:db8::200/128")
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
    $beforeMetrics = Get-Metrics $metricsPort
    $acceptedBefore = Get-CounterValue $beforeMetrics "ferrum2_tun_packets_accepted"
    try {
        [void]$udp4.Send([byte[]](1,2,3,4), 4)
    } finally { $udp4.Dispose(); $udp4 = $null }
    $packetDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $afterMetrics = Get-Metrics $metricsPort
        $acceptedAfter = Get-CounterValue $afterMetrics "ferrum2_tun_packets_accepted"
        $acceptedDelta = $acceptedAfter - $acceptedBefore
        if ($acceptedDelta -gt 0) { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $packetDeadline)
    Assert-True ($acceptedDelta -gt 0) "valid packet did not traverse receive/validation/enqueue"
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
    }
    if ($Mode -eq "cycles") {
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
        Assert-True ($LASTEXITCODE -eq 0) "cycle config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "cycle config marker mismatch"
        Set-Content -LiteralPath $dllJournal -Value $expectedDllHash -Encoding ascii
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        Invoke-AdapterCycles $binary $config
    }
    if ($Mode -in @("tcp", "udp", "full", "performance")) {
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
        $ports[4] = 53
        $targets = @(
            "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
            "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208"
        )
        $udpGateAddress = "192.0.2.250"
        $serverAConfig = Join-Path $work "server-a.toml"
        $serverBConfig = Join-Path $work "server-b.toml"
        foreach ($serverCase in @(@($serverAConfig, $serverPortA), @($serverBConfig, $serverPortB))) {
            @"
schema_version = 1
[server]
listen = "127.0.0.1:$($serverCase[1])"
[runtime]
shutdown_grace_ms = 1000
[udp]
enabled = true
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
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
        if ($Mode -in @("udp", "full", "performance")) {
            [void](Add-TargetAddress $udpGateAddress $false)
            $udpGateA = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortA, $serverPortA)
            $udpGateB = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortB, $serverPortB)
            $tcpResources.Add($udpGateA)
            $tcpResources.Add($udpGateB)
        }

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
ring_capacity = 8388608
max_udp_mappings = 4
max_udp_buffered_bytes = 4194304
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
[[outbounds]]
tag = "udp-one"
server = "${udpGateAddress}:$gatePortA"
[[outbounds]]
tag = "udp-inner"
server = "${udpGateAddress}:$gatePortB"
[[chains]]
tag = "two-hop"
hops = ["one", "inner"]
[[chains]]
tag = "udp-two-hop"
hops = ["udp-one", "udp-inner"]
[[selectors]]
tag = "manual"
outbounds = ["dead", "fallback"]
default = "dead"
[[selectors]]
tag = "udp-manual"
outbounds = ["udp-one", "udp-inner"]
default = "udp-one"
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
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[2])"
port = $($ports[2])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "dns"
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[4])"
port = $($ports[4])
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "udp-one"
[udp]
enabled = false
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
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
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        if ($Mode -eq "full") {
            Assert-True ((Get-FileHash -LiteralPath $siblingDll -Algorithm SHA256).Hash -eq $expectedDllHash) "full profile sibling DLL drifted"
        } else {
            Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        }
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "TCP config validation failed: $($offlineOutput -join '|')"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "TCP config marker mismatch"
        if ($Mode -ne "full") {
            Set-Content -LiteralPath $dllJournal -Value $expectedDllHash -Encoding ascii
            Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
            $createdSiblingDll = $true
        }
        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($Mode -eq "performance") { Start-PerformanceSample $activeProcess $metricsPort }
        else { [void](Get-Metrics $metricsPort) }
        $readyRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $expectedAddressDerivedRoutes = @(
            "IPv4|198.18.0.0/30|0.0.0.0", "IPv4|198.18.0.2/32|0.0.0.0",
            "IPv6|fd00::/126|::", "IPv6|fd00::2/128|::"
        )
        $addressDerivedRoutes = @($readyRoutes | Where-Object {
            ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or ($_ -like "IPv6|fd00::*")
        })
        Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "TCP ready address-derived routes"
        $strongHostInterfaces = @(Get-NetIPInterface -InterfaceIndex @($ownedInterfaceIndex, 1) -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($strongHostInterfaces.Count -eq 4) "strong-host interface rows missing"
        $weakHostInterfaces = @($strongHostInterfaces | Where-Object { $_.WeakHostSend -ne "Disabled" -or $_.WeakHostReceive -ne "Disabled" })
        Assert-True ($weakHostInterfaces.Count -eq 0) "weak-host forwarding is unsupported"
        foreach ($target in $targets) {
            $prefixLength = if ($target.Contains(":")) { 128 } else { 32 }
            [void](Add-TunRoute $ownedInterfaceIndex "$target/$prefixLength" 500)
        }
        foreach ($targetIndex in @(0, 1, 2, 3, 7)) {
            [void](Add-TargetAddress $targets[$targetIndex])
        }

        $tcp01Target = $targets[0]
        $tcp01Port = $ports[0]
        $tcp01Payload = [Text.Encoding]::ASCII.GetBytes("tcp-01-half-close")
        $tcp01Observation = @{ Diagnostic = "pending" }
        $tcp01Error = $null
        if ($Mode -eq "performance") {
            $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
        }
        try {
            Invoke-EchoRow $tcp01Target $tcp01Port $ownedInterfaceIndex $gateA $tcp01Payload $tcp01Observation
        } catch { $tcp01Error = $_ }

        $gateSettled = $false
        if ($tcp01Observation.Gate) {
            $gateSettled = $tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)
        }
        $probeSettled = $false
        if ($tcp01Observation.Probe) {
            $probeSettled = $tcp01Observation.Probe.WaitCompleted(1500)
        }
        $gateObservation = if ($tcp01Observation.Gate) {
            $tcp01Observation.Gate.Observation([int]$tcp01Observation.GateIndex)
        } else { $null }
        $probe = $tcp01Observation.Probe
        $probeRequest = if (-not $probe -or $probe.Received.Length -eq 0) { "none" }
            elseif (($probe.Received -join ",") -eq ($tcp01Payload -join ",")) { "exact" }
            else { "other" }
        $probeEcho = if (-not $probe -or $probe.EchoByteCount -eq 0) { "none" }
            elseif ($probeRequest -eq "exact" -and $probe.EchoByteCount -eq $tcp01Payload.Length) { "exact" }
            else { "other" }
        $tcp01State = @{
            GateAccepted = $tcp01Observation.GateAccepted
            GateForwardBytes = if ($gateObservation) { $gateObservation.ClientToServerBytes } else { "zero" }
            GateForwardStage = if ($gateObservation) { $gateObservation.ClientToServerStage } else { "pending" }
            GateForwardEof = if ($gateObservation) { $gateObservation.ClientToServerEof } else { "no" }
            GateForwardFault = if ($gateObservation) { $gateObservation.ClientToServerFault } else { "other" }
            GateReverseBytes = if ($gateObservation) { $gateObservation.ServerToClientBytes } else { "zero" }
            GateReverseStage = if ($gateObservation) { $gateObservation.ServerToClientStage } else { "pending" }
            GateReverseEof = if ($gateObservation) { $gateObservation.ServerToClientEof } else { "no" }
            GateReverseFault = if ($gateObservation) { $gateObservation.ServerToClientFault } else { "other" }
            GateComplete = if ($gateSettled -and $gateObservation -and $gateObservation.SessionComplete -eq "yes") { "yes" } else { "no" }
            ProbeAccepted = $tcp01Observation.ProbeAccepted
            ProbeRequest = $probeRequest
            ProbeReadEof = if ($probe) { $probe.ReadEof } else { "no" }
            ProbeEcho = $probeEcho
            ProbeShutdown = if ($probe) { $probe.SendShutdown } else { "no" }
            ProbeFault = if ($probe) { $probe.Fault } else { "other" }
            ProbeComplete = if ($probeSettled -and $probe -and $probe.SessionComplete -eq "yes") { "yes" } else { "no" }
            AppResult = $tcp01Observation.AppResult
        }
        $tcp01Boundary = Get-Tcp01Boundary $tcp01State
        if ($tcp01Error -or $tcp01Boundary -ne "COMPLETE") {
            $tcp01Diagnostic = "status=OBSERVED boundary=$tcp01Boundary app=$($tcp01State.AppResult) gate_accepted=$($tcp01State.GateAccepted) gate_c2s_bytes=$($tcp01State.GateForwardBytes) gate_c2s_stage=$($tcp01State.GateForwardStage) gate_c2s_eof=$($tcp01State.GateForwardEof) gate_c2s_fault=$($tcp01State.GateForwardFault) gate_s2c_bytes=$($tcp01State.GateReverseBytes) gate_s2c_stage=$($tcp01State.GateReverseStage) gate_s2c_eof=$($tcp01State.GateReverseEof) gate_s2c_fault=$($tcp01State.GateReverseFault) gate_complete=$($tcp01State.GateComplete) probe_accepted=$($tcp01State.ProbeAccepted) probe_request=$($tcp01State.ProbeRequest) probe_read_eof=$($tcp01State.ProbeReadEof) probe_echo=$($tcp01State.ProbeEcho) probe_shutdown=$($tcp01State.ProbeShutdown) probe_fault=$($tcp01State.ProbeFault) probe_complete=$($tcp01State.ProbeComplete)"
        }
        if ($tcp01Error) { throw $tcp01Error }
        Assert-True ($tcp01Boundary -eq "COMPLETE") "TCP-01 observation incomplete"
        $tcpRows++
        if ($Mode -eq "performance") {
            $performanceWitnesses++
            Update-PerformancePeaks $activeProcess $metricsPort
        }
        Invoke-EchoRow $targets[1] $ports[1] $ownedInterfaceIndex $gateA ([Text.Encoding]::ASCII.GetBytes("tcp-02-two-hop"))
        $tcpRows++

        $tlsGate = $gateB.Accepted + 1
        $tls = Open-TunTcp $targets[2] $ports[2] $ownedInterfaceIndex
        $ssl = [Net.Security.SslStream]::new($tls.Client.GetStream(), $false, { $true })
        $sslTask = $ssl.AuthenticateAsClientAsync("tls.tun.test")
        Assert-True ($gateB.WaitAccepted($tlsGate, 5000)) "TLS sniff did not select its exact egress"
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
                Assert-True ($response[0] -eq [byte]($id -shr 8) -and $response[1] -eq [byte]($id -band 0xff)) "DNS response ID mismatch"
            }
            Assert-True ($dnsResponder.Requests -eq 2) "DNS hijack did not answer both framed queries"
            Assert-True ($gateA.Accepted -eq $gateCounts[0] -and $gateB.Accepted -eq $gateCounts[1]) "DNS hijack opened Shadowsocks"
        } finally {
            $dnsFlow.Client.Dispose()
        }
        $tcpRows++

        Assert-ResetWithoutEgress $targets[5] $ports[5] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++
        Assert-ResetWithoutEgress $targets[6] $ports[6] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++

        $pressureGate = $gateA.Accepted + 1
        $pressure = Open-TunTcp $targets[7] $ports[7] $ownedInterfaceIndex
        Assert-True ($gateA.WaitAccepted($pressureGate, 5000)) "backpressure route did not open"
        $pressureChunk = [byte[]]::new(1024 * 1024)
        $pressureWrite = $null
        for ($attempt = 0; $attempt -lt 128; $attempt++) {
            $pressureWrite = $pressure.Client.GetStream().WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            if (-not $pressureWrite.Wait(100)) { break }
        }
        Assert-True ($pressureWrite -and -not $pressureWrite.IsCompleted) "backpressure write unexpectedly drained"
        $stall = [Ferrum2TcpProbe]::new($targets[7], $ports[7], "stall")
        $tcpResources.Add($stall)
        $gateA.Release($pressureGate)
        Assert-True ($stall.WaitAccepted(5000)) "backpressure target was not opened"
        if ($Mode -eq "performance") { Complete-PerformanceSample $activeProcess $metricsPort }
        $forcedShutdown = [Diagnostics.Stopwatch]::StartNew()
        Assert-True ([Ferrum2ProcessGroup]::Break([uint32]$activeProcess.Id)) "TCP-08 CTRL_BREAK delivery failed"
        Assert-True (-not [Ferrum2ProcessGroup]::Wait([uint32]$activeProcess.Id, 300)) "TCP-08 exited during grace"
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressured flow was not owned through grace"
        Assert-True (Wait-ProcessExit $activeProcess 10) "TCP-08 forced cancellation did not exit"
        $forcedShutdown.Stop()
        Assert-True ($forcedShutdown.ElapsedMilliseconds -ge 900) "TCP-08 force preceded the grace deadline"
        $forcedExit = [Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id)
        Assert-True ($forcedExit -eq 0) "TCP-08 forced shutdown was not clean: exit=$forcedExit"
        if ($Mode -eq "performance") { $performanceForceDrain = $true }
        [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
        $activeProcess = $null
        $pressure.Client.Dispose()
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($Mode -eq "performance") {
            $performanceAdapterChurn++
            Start-PerformanceSample $activeProcess $metricsPort
        }
        if ($Mode -eq "tcp") {
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        } else {
            foreach ($target in $targets) {
                $prefixLength = if ($target.Contains(":")) { 128 } else { 32 }
                [void](Add-TunRoute $ownedInterfaceIndex "$target/$prefixLength" 500)
            }
        }
        $tcpRows++
        Assert-True ($tcpRows -eq 8) "TCP row count mismatch"

        if ($Mode -in @("udp", "full", "performance")) {
            foreach ($targetIndex in @(4, 5, 6)) {
                [void](Add-TargetAddress $targets[$targetIndex])
            }

            # UDP-01 IPv4 one-hop route and authenticated response binding.
            if ($Mode -eq "performance") {
                $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
            }
            Invoke-UdpEchoRow $targets[0] $ports[0] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-01-one-hop"))
            $udpRows++
            if ($Mode -eq "performance") {
                $performanceWitnesses++
                Update-PerformancePeaks $activeProcess $metricsPort
            }

            # UDP-02 IPv6 fixed two-hop chain.
            $beforeGateA = $udpGateA.Requests
            $beforeGateB = $udpGateB.Requests
            Invoke-UdpEchoRow $targets[1] $ports[1] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-02-two-hop"))
            Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-02 did not traverse both exact hops"
            $udpRows++

            # UDP-03 IPv4 selector snapshot unchanged for a live mapping.
            $selectorProbe = [Ferrum2UdpProbe]::new($targets[2], $ports[2])
            $tcpResources.Add($selectorProbe)
            $selectorClient = Open-TunUdp $targets[2] $ports[2] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                foreach ($payload in @(
                    [Text.Encoding]::ASCII.GetBytes("udp-03-first"),
                    [Text.Encoding]::ASCII.GetBytes("udp-03-snapshot")
                )) {
                    [void]$selectorClient.Send($payload, $payload.Length)
                    $response = Receive-TunUdp $selectorClient
                    Assert-True (($response -join ",") -eq ($payload -join ",")) "UDP-03 mapping changed its response binding"
                }
                Assert-True ($selectorProbe.WaitRequests(2, 5000)) "UDP-03 target did not receive both datagrams"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-03 selector mapping was not fixed"
            } finally { $selectorClient.Dispose() }
            $udpRows++

            # UDP-04 IPv6 expiry and reselection.
            $expiryProbe = [Ferrum2UdpProbe]::new($targets[3], $ports[3])
            $tcpResources.Add($expiryProbe)
            $expiryClient = Open-TunUdp $targets[3] $ports[3] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $plain = [Text.Encoding]::ASCII.GetBytes("udp-04-before-dns")
                [void]$expiryClient.Send($plain, $plain.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($plain -join ",")) "UDP-04 initial response mismatch"
                $query = New-DnsQuery 0x1401
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 live snapshot response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-04 live mapping re-entered policy"
                Start-Sleep -Milliseconds 60500
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 expired response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 3 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-04 did not reselect after expiry"
            } finally { $expiryClient.Dispose() }
            $udpRows++

            # UDP-05 IPv4 DNS hijack with zero Shadowsocks owner.
            $beforeGateA = $udpGateA.Requests
            $beforeGateB = $udpGateB.Requests
            $beforeDns = $dnsResponder.Requests
            $dnsClient = Open-TunUdp $targets[4] $ports[4] $ownedInterfaceIndex
            try {
                $query = New-DnsQuery 0x1501
                [void]$dnsClient.Send($query, $query.Length)
                $response = Receive-TunUdp $dnsClient
                Assert-True ($response[0] -eq 0x15 -and $response[1] -eq 0x01) "UDP-05 DNS response ID mismatch"
                Assert-True ($dnsResponder.Requests -eq $beforeDns + 1) "UDP-05 DNS proxy did not answer"
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-05 DNS hijack opened Shadowsocks"
            } finally { $dnsClient.Dispose() }
            $udpRows++

            # UDP-06 IPv6 reject tombstone and no policy re-entry.
            $beforeGateA = $udpGateA.Requests
            $beforeGateB = $udpGateB.Requests
            $rejectClient = Open-TunUdp $targets[5] $ports[5] $ownedInterfaceIndex
            try {
                $rejected = [Text.Encoding]::ASCII.GetBytes("udp-06-reject")
                [void]$rejectClient.Send($rejected, $rejected.Length)
                [void]$rejectClient.Send($rejected, $rejected.Length)
                $rejectedResponse = $rejectClient.ReceiveAsync()
                Assert-True (-not $rejectedResponse.Wait(500)) "UDP-06 reject returned a datagram"
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-06 reject opened an egress"
            } finally { $rejectClient.Dispose() }
            $udpRows++

            # UDP-07 IPv4 over-limit no-commit then selector re-read.
            $overLimitClient = Open-TunUdp $targets[6] $ports[6] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $overLimit = [byte[]]::new(2000)
                [void]$overLimitClient.Send($overLimit, $overLimit.Length)
                Start-Sleep -Milliseconds 500
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 over-limit candidate committed"
                $overLimitProbe = [Ferrum2UdpProbe]::new($targets[6], $ports[6])
                $tcpResources.Add($overLimitProbe)
                $valid = [Text.Encoding]::ASCII.GetBytes("udp-07-valid")
                [void]$overLimitClient.Send($valid, $valid.Length)
                Assert-True (((Receive-TunUdp $overLimitClient) -join ",") -eq ($valid -join ",")) "UDP-07 recovery response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 valid candidate did not re-read selector"
            } finally { $overLimitClient.Dispose() }
            $udpRows++

            # UDP-08 IPv6 mapping saturation, generation reuse and wrong-response drop.
            Start-Sleep -Milliseconds 60500
            $saturationProbe = [Ferrum2UdpProbe]::new($targets[7], $ports[7])
            $tcpResources.Add($saturationProbe)
            $saturatedClients = [System.Collections.Generic.List[Net.Sockets.UdpClient]]::new()
            $overflowClient = $null
            try {
                $beforeGateA = $udpGateA.Requests
                foreach ($index in 0..3) {
                    $mappingClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                    $saturatedClients.Add($mappingClient)
                    $payload = [Text.Encoding]::ASCII.GetBytes("udp-08-slot-$index")
                    [void]$mappingClient.Send($payload, $payload.Length)
                    Assert-True (((Receive-TunUdp $mappingClient) -join ",") -eq ($payload -join ",")) "UDP-08 live mapping response mismatch"
                }
                Assert-True ($saturatedClients.Count -eq 4) "UDP-08 mapping saturation setup mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 did not commit the fixed mapping capacity"
                $overflowClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                $overflow = [Text.Encoding]::ASCII.GetBytes("udp-08-overflow")
                [void]$overflowClient.Send($overflow, $overflow.Length)
                $overflowResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $overflowResponse.Wait(500) -and $udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 evicted a live mapping"
                Start-Sleep -Milliseconds 60500
                [void]$overflowClient.Send($overflow, $overflow.Length)
                Assert-True ($overflowResponse.Wait(5000)) "UDP-08 expired response timeout"
                if ($overflowResponse.IsFaulted) { throw "UDP-08 expired response failed" }
                Assert-True (($overflowResponse.Result.Buffer -join ",") -eq ($overflow -join ",")) "UDP-08 expired slot was not reusable"
                Assert-True ($udpGateA.ReplayFirstToLatest()) "UDP-08 stale response replay was unavailable"
                $staleResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $staleResponse.Wait(500)) "UDP-08 stale response crossed the new generation"
            } finally {
                if ($overflowClient) { $overflowClient.Dispose() }
                foreach ($client in $saturatedClients) { $client.Dispose() }
            }
            $udpRows++
            Assert-True ($udpRows -eq 8) "UDP row count mismatch"

            if ($Mode -eq "performance") { Complete-PerformanceSample $activeProcess $metricsPort }
            Stop-Candidate $activeProcess
            if ($Mode -eq "performance") { $performanceGraceDrain = $true }
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            $activeProcess = Start-Candidate $binary $config
            $adapter = Wait-AdapterReady $adapterName
            $ownedInterfaceIndex = [int]$adapter.ifIndex
            if ($Mode -eq "performance") { $performanceAdapterChurn++ }
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            if ($Mode -eq "performance") {
                Assert-True $performanceFieldsCollected "performance fields were not collected"
                Assert-True ($performanceWitnesses -eq 2) "performance witness count mismatch"
                Assert-True ($performanceAdapterRxBytes -gt 0 -and $performanceAdapterTxBytes -gt 0) "adapter byte witnesses missing"
                Assert-True ($performanceAdapterRxPackets -gt 0 -and $performanceAdapterTxPackets -gt 0) "adapter packet witnesses missing"
                Assert-True ($performanceTunAcceptedDelta -gt 0) "TUN accepted witness missing"
                Assert-True ($performanceRssBytes -gt 0 -and $performanceHandlesPeak -gt 0 -and $performanceThreadsPeak -gt 0) "process resource sample missing"
                Assert-True ($performanceControllerInflightPeak -gt 0) "controller inflight sample missing"
                Assert-True ($performanceAdapterChurn -ge 2) "adapter churn witness missing"
                Assert-True ($performanceGraceDrain -and $performanceForceDrain) "grace/force drain witness missing"
            }
        }
    }
    if ($Mode -eq "full") {
        Assert-True ($foundation -eq 4 -and $tcpRows -eq 8 -and $udpRows -eq 8) "full profile prerequisite count mismatch"
        Invoke-AdapterCycles $binary $config
    }
    $completed = $true
}
catch { $primaryError = $_ }
finally {
    try {
    if ($udp4) { $udp4.Dispose() }
    if ($heldMetrics) { $heldMetrics.Stop() }
    foreach ($route in $ownedRoutes) {
        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($Mode -eq "network-feasibility") {
        try { Stop-CapabilityPktMon }
        catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
        try { Remove-CapabilityRoutes }
        catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
        $capabilityAdapter = Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue
        if ($capabilityAdapter) {
            try { Restore-CapabilityDns ([int]$capabilityAdapter.ifIndex) }
            catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
            try { Restore-CapabilityInterfaceMetric ([int]$capabilityAdapter.ifIndex) }
            catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
        } else {
            $capabilityDnsApplied = $false
            $capabilityDnsSnapshot = $null
            $capabilityMetricApplied = $false
            $capabilityMetricSnapshot = $null
        }
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
    foreach ($route in $ownedRoutes) {
        $leaked = @(Get-NetRoute -DestinationPrefix $route.DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex })
        Assert-True ($leaked.Count -eq 0) "controller-owned route leaked: $($route.DestinationPrefix)"
    }
    if ($createdSiblingDll -and (Test-Path -LiteralPath $siblingDll)) { Remove-Item -LiteralPath $siblingDll -Force }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    if ($createdSiblingDll) { Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "owned sibling DLL leaked" }
    Assert-True (-not (Test-Path -LiteralPath $work)) "controller work directory leaked"
    } catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
}

if ($tcp01Diagnostic) {
    $tcp01Cleanup = if ($outerCleanupError) { "FAIL" } else { "PASS" }
    $tcp01Sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $tcp01RunId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $tcp01RunAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    [Console]::Error.WriteLine("m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt")
}
if ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }
if ($primaryError) { throw $primaryError }

if ($completed) {
    $sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $runAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    if ($Mode -eq "lifecycle") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=foundation foundation=4/4 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "tcp") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=tcp tcp=8/8 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "cycles") {
        Write-Output "m15_windows_tun_cycles status=PASS cycles=100/100 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "performance") {
        Write-Output "m15_windows_tun_performance_resource adapter_rx_bytes=$performanceAdapterRxBytes adapter_tx_bytes=$performanceAdapterTxBytes adapter_rx_packets=$performanceAdapterRxPackets adapter_tx_packets=$performanceAdapterTxPackets adapter_rx_errors=$performanceAdapterRxErrors adapter_tx_errors=$performanceAdapterTxErrors adapter_rx_discards=$performanceAdapterRxDiscards adapter_tx_discards=$performanceAdapterTxDiscards tun_accepted_delta=$performanceTunAcceptedDelta cpu_ms_delta=$performanceCpuMilliseconds rss_bytes=$performanceRssBytes handles_peak=$performanceHandlesPeak threads_peak=$performanceThreadsPeak udp_sessions_peak=$performanceUdpSessionsPeak udp_buffered_bytes_peak=$performanceUdpBufferedBytesPeak controller_inflight_peak=$performanceControllerInflightPeak queues=bounded bounds_ring_bytes=8388608 bounds_tcp_flows=8 bounds_tcp_buffer_bytes=4096 bounds_udp_mappings=4 bounds_udp_buffered_bytes=4194304 adapter_churn=$performanceAdapterChurn grace_drain=PASS force_drain=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
        Write-Output "m15_windows_tun_performance status=PASS witnesses=2/2 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "network-feasibility") {
        Assert-True ($capabilityRouteRows -eq 2 -and $capabilityTcpRows -eq 4 -and $capabilityUdpRows -eq 4 -and
            $capabilityDnsRows -eq 2 -and $capabilityWindowRows -eq 1 -and $capabilityHardKillRows -eq 1 -and
            $capabilityInterfaceMetric -in @("unchanged", "leased")) "network feasibility marker prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath $capabilityEvidence) "network feasibility evidence is missing"
        Write-Output "m16_windows_network_feasibility status=PASS routes=2/2 tcp_pin=4/4 udp_pin=4/4 dns=2/2 capture_window=1/1 hard_kill=1/1 interface_metric=$capabilityInterfaceMetric cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
    } elseif ($Mode -eq "full") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=full functional=16/16 cycles=100/100 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } else {
        Write-Output "m15_windows_tun_e2e status=PASS profile=transport functional=16/16 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    }
}
