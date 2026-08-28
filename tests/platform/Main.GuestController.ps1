# Main M17 guest controller implementation. Hard-kill has a separate controller and bundle.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full")]
    [string]$Profile,
    [ValidateRange(0, 10)] [int]$ValidationCycleLimit = 0,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger,
    [string]$TopologyManifest,
    [string]$GuestNetworkPath,
    [string]$ClientBinary,
    [string]$ServerBinary,
    [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [string]$RuntimeLibraryDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$controllerEntryPointPath = Join-Path $PSScriptRoot 'qualify_windows_tun.ps1'

$qualificationModuleRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "modules")) {
    Join-Path $PSScriptRoot "modules"
} else {
    Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path `
        "tools\powershell"
}
$controllerBundleManifestPath = Join-Path $PSScriptRoot "controller-bundle.json"
if (-not (Test-Path -LiteralPath $controllerBundleManifestPath -PathType Leaf)) {
    throw "controller bundle manifest is required"
}
$controllerBundleManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = `
    'modules/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
$bootstrapEntry = @($controllerBundleManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $PSScriptRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw 'main controller bundle bootstrap changed'
}
. $bootstrapPath
$verifiedControllerBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot
if ([string]$verifiedControllerBundle.entrypoint -cne 'qualify_windows_tun.ps1') {
    throw 'main controller bundle entrypoint changed'
}
Import-Module (Join-Path $qualificationModuleRoot `
    "Ferrum2.Qualification.GuestController\Ferrum2.Qualification.GuestController.psd1") `
    -Scope Local -Force -ErrorAction Stop

$controllerStartedUtc = [DateTime]::UtcNow.ToString("o")
$expectedHyperVVmName = $null
$expectedHyperVVmId = $null
$expectedHyperVCheckpointName = $null
$expectedHyperVCheckpointId = $null

$profileContract = Resolve-Ferrum2QualificationProfile -Profile $Profile `
    -ValidationCycleLimit $ValidationCycleLimit
$NetworkResetCycles = if ($Profile -ceq 'network-reset') {
    [int]$profileContract.cycle_limit
} else { 0 }
$RestartCycles = if ($Profile -ceq 'restart-stress') {
    [int]$profileContract.cycle_limit
} else { 0 }
$releaseMilestones = @(
    $profileContract.release_milestones | ForEach-Object { [int]$_ }
)

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
}
# Every profile can mutate adapter, route, or DNS state. Keep accidental host execution
# fail-closed; the host orchestrator must copy and invoke this script in
# an isolated Hyper-V guest.
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if ($computerSystem.Manufacturer -cne "Microsoft Corporation" -or
    $computerSystem.Model -cne "Virtual Machine") {
    throw "Windows TUN qualification must run inside an isolated Hyper-V guest"
}

function Assert-CurrentGuestIdentityMarker([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Windows TUN qualification requires an identity ledger"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.Length -lt 2 -or $item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Windows TUN identity ledger file boundary is invalid"
    }
    $ledger = Get-Content -LiteralPath $resolved -Raw -Encoding utf8 | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    $vmId = [Guid]::Empty
    $checkpointId = [Guid]::Empty
    if ($ledger.schema -ne 4 -or
        [string]$ledger.vm_name -cnotmatch '^[^\r\n]{1,128}$' -or
        -not [Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$vmId) -or
        $vmId -eq [Guid]::Empty -or
        [string]$ledger.checkpoint_name -cnotmatch '^[^\r\n]{1,128}$' -or
        -not [Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$checkpointId) -or
        $checkpointId -eq [Guid]::Empty -or
        [string]$ledger.controller_bundle_sha256 -cne
            [string]$script:controllerBundleManifest.controller_bundle_sha256) {
        throw "Windows TUN identity ledger does not name one bounded Hyper-V guest checkpoint"
    }
    $script:expectedHyperVVmName = [string]$ledger.vm_name
    $script:expectedHyperVVmId = $vmId.ToString("D")
    $script:expectedHyperVCheckpointName = [string]$ledger.checkpoint_name
    $script:expectedHyperVCheckpointId = $checkpointId.ToString("D")
    return $resolved
}

$identityMarker = Assert-CurrentGuestIdentityMarker $IdentityLedger

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
$clientBinaryInput = $ClientBinary
$serverBinaryInput = $ServerBinary
$resolvedProductRoot = if ($ProductRoot) {
    (Resolve-Path -LiteralPath $ProductRoot).Path
} else { $workspace }
$clientBinaryExplicit = -not [string]::IsNullOrWhiteSpace($clientBinaryInput)
$serverBinaryExplicit = -not [string]::IsNullOrWhiteSpace($serverBinaryInput)
$runtimeLibraryDirectoryExplicit = -not [string]::IsNullOrWhiteSpace($RuntimeLibraryDirectory)
$resolvedRuntimeLibraryDirectory = $null
$runtimeVcruntimePath = $null
$runtimeVcruntimeBytes = $null
$runtimeVcruntimeSha256 = $null
$runIdentity = if ($RunToken) { $RunToken } else { "local-$PID" }
if ($runIdentity -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw "RunToken is invalid" }
$work = Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m17-tun-$runIdentity"
$binary = if ($clientBinaryExplicit) {
    (Resolve-Path -LiteralPath $clientBinaryInput).Path
} else { [IO.Path]::GetFullPath((Join-Path $resolvedProductRoot "target\debug\ferrum2-client.exe")) }
$serverBinary = if ($serverBinaryExplicit) {
    (Resolve-Path -LiteralPath $serverBinaryInput).Path
} else { [IO.Path]::GetFullPath((Join-Path $resolvedProductRoot "target\debug\ferrum2-server.exe")) }
$siblingDll = Join-Path (Split-Path -Parent $binary) "wintun.dll"
$runtimeIdleTimeoutMilliseconds = 2000
$adapterName = "F2-M17-$runIdentity"
$addressJournal = Join-Path $work "owned-target-addresses.txt"
$dllJournal = Join-Path $work "owned-wintun-dll.txt"
$m17NetworkMutationJournal = Join-Path $work "m17-network-mutations"
$m17NetworkResetProbeAddress = "203.0.113.254"
$m17NetworkResetProbePrefix = "$m17NetworkResetProbeAddress/32"
$m17UdpFirewallRuleName = "Ferrum2-M17-UDP-$runIdentity"
$controllerProgram = [IO.Path]::GetFullPath((Get-Process -Id $PID -ErrorAction Stop).Path)
$runIdentityJournalRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) "Ferrum2\ControllerRunIdentities"
$runIdentityJournalPath = Join-Path $runIdentityJournalRoot "$runIdentity.json"


. (Join-Path $PSScriptRoot 'Guest.Identity.ps1')

. (Join-Path $PSScriptRoot 'Guest.Cleanup.ps1')

if ($runtimeLibraryDirectoryExplicit) {
    $runtimeDirectoryItem = Get-Item -LiteralPath $RuntimeLibraryDirectory -Force -ErrorAction Stop
    Assert-True $runtimeDirectoryItem.PSIsContainer "RuntimeLibraryDirectory must be a directory"
    Assert-True (($runtimeDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "RuntimeLibraryDirectory must not be a reparse point"
    $resolvedRuntimeLibraryDirectory = [IO.Path]::GetFullPath($runtimeDirectoryItem.FullName)
    $runtimeVcruntimePath = Join-Path $resolvedRuntimeLibraryDirectory "vcruntime140.dll"
    Assert-True (Test-Path -LiteralPath $runtimeVcruntimePath -PathType Leaf) "RuntimeLibraryDirectory is missing vcruntime140.dll"
    Assert-NotReparsePoint $runtimeVcruntimePath "runtime vcruntime140.dll"
    $runtimeVcruntimeItem = Get-Item -LiteralPath $runtimeVcruntimePath -Force -ErrorAction Stop
    $runtimeVcruntimeBytes = $runtimeVcruntimeItem.Length
    $runtimeVcruntimeSha256 = (Get-FileHash -LiteralPath $runtimeVcruntimePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $env:Path = if ([string]::IsNullOrEmpty($env:Path)) {
        $resolvedRuntimeLibraryDirectory
    } else {
        "$resolvedRuntimeLibraryDirectory;$env:Path"
    }
}

$zipInput = if ($WintunZip) { $WintunZip } elseif ($env:FERRUM2_WINTUN_ZIP) { $env:FERRUM2_WINTUN_ZIP } else { throw "Wintun ZIP path is required via -WintunZip or FERRUM2_WINTUN_ZIP" }
$zip = (Resolve-Path -LiteralPath $zipInput).Path
$ownedRoutes = [System.Collections.Generic.List[object]]::new()
$activeProcess = $null
$ownedInterfaceIndex = $null
$serverProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$ownedAddresses = [System.Collections.Generic.List[object]]::new()
$ownedTargetRoutes = [System.Collections.Generic.List[object]]::new()
$tcpResources = [System.Collections.Generic.List[System.IDisposable]]::new()
$usedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$createdSiblingDll = $false
$runJournalIdentity = $null
$completed = $false
$primaryError = $null
$outerCleanupError = $null
$cleanupSucceeded = $false
$capabilityIdentity = $null
$capabilityIdentityHash = $null
$m17ArtifactRoot = $null
$m17ArtifactInitialized = $false
$m17GuestNetworkPathDocument = $null
$m17Contract = $null
$m17FixtureRows = @()
$m17WitnessRows = [ordered]@{}
$m17ProcessRows = [System.Collections.Generic.List[object]]::new()
$m17LiveRows = [System.Collections.Generic.List[object]]::new()
$m17CounterBefore = $null
$m17CounterAfter = $null
$m17StartedUtc = $null
$m17FinishedUtc = $null
$m17ProcessOrdinal = 0
$m17ServerProcess = $null
$m17ServerPort = $null
$m17MetricsPort = $null


. (Join-Path $PSScriptRoot 'Guest.HardKillSupport.ps1')

. (Join-Path $PSScriptRoot 'Guest.Topology.ps1')

$capabilityIdentity = Get-NetworkFeasibilityIdentity `
    $IdentityLedger $true
$capabilityIdentityHash = $capabilityIdentity.IdentitySha256
$m17GuestNetworkPathDocument = Read-M17GuestNetworkPath `
    $GuestNetworkPath $capabilityIdentity.Ledger


. (Join-Path $PSScriptRoot 'Guest.Runtime.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeProcess.cs.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeTransport.cs.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeNetwork.cs.ps1')

. (Join-Path $PSScriptRoot 'Guest.TransportProbes.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Contract.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Runtime.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Reset.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Protocol.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Udp.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Scheduler.ps1')

try {
    Assert-True (-not (Test-Path -LiteralPath $work)) "run work baseline not absent"
    Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) "run process baseline not absent"
    Assert-True (-not (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)) "run adapter baseline not absent"
    Assert-True (-not (Get-NetFirewallRule -Name $m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 UDP firewall rule baseline not absent"
    Assert-True ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -eq $expectedZipHash) "ZIP hash mismatch"
    Write-RunIdentityJournal
    $runJournalIdentity = Read-RunIdentityJournal $runIdentityJournalPath @(Get-ControllerWorkPaths)
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
    Assert-True (Test-Path -LiteralPath $binary) "candidate client binary is missing after selection/build"
    Assert-True (Test-Path -LiteralPath $serverBinary) "candidate server binary is missing after selection/build"
    [void](Invoke-M17ContractPreflight)
    Invoke-M17Qualification $sourceDll
    $completed = $true
}
catch { $primaryError = $_ }
finally {
    try {
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
    Restore-M17NetworkMutationJournal $work $m17NetworkMutationJournal
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
    if ($createdSiblingDll) { Remove-OwnedSiblingDll $runJournalIdentity }
    if (Test-Path -LiteralPath $work) {
        Assert-NotReparsePoint $work "controller work directory"
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    if ($createdSiblingDll) { Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "owned sibling DLL leaked" }
    Assert-True (-not (Test-Path -LiteralPath $work)) "controller work directory leaked"
    Assert-M17ExternalIdentityInputsUnchanged
    $cleanupSucceeded = $true
    } catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
}
if ($m17ArtifactInitialized) {
    $m17Succeeded = $completed -and -not $primaryError -and -not $outerCleanupError -and $cleanupSucceeded
    try { Complete-M17Artifact $m17Succeeded $primaryError $outerCleanupError }
    catch {
        if (-not $primaryError) { $primaryError = $_ }
        elseif (-not $outerCleanupError) { $outerCleanupError = $_ }
    }
}
if ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }
if ($primaryError) { throw $primaryError }

if ($completed) {
    $artifact = Join-Path $m17ArtifactRoot "m17-result.json"
    Assert-True (Test-Path -LiteralPath $artifact) "M17 result artifact is missing"
    $witnessCount = @($m17WitnessRows.Keys).Count
    $expectedWitnessCount = @($m17Contract.witnesses).Count
    Assert-True ($witnessCount -eq $expectedWitnessCount) "M17 final witness count changed"
    Write-Output "m17_windows_tun status=PASS profile=$Profile witnesses=$witnessCount/$expectedWitnessCount cleanup=PASS run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) artifact=$artifact"
}
