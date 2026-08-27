[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$WintunZip,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$IdentityLedger,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$TopologyManifest,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$GuestNetworkPath,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ClientBinary,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ServerBinary,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$RuntimeLibraryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Profile = 'hard-kill'
$controllerEntryPointPath = Join-Path $PSScriptRoot `
    'qualify_windows_tun_hard_kill.ps1'
$controllerBundleManifestPath = Join-Path $PSScriptRoot 'controller-bundle.json'
if (-not (Test-Path -LiteralPath $controllerBundleManifestPath -PathType Leaf)) {
    throw 'hard-kill controller bundle manifest is required'
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
    throw 'hard-kill controller bundle bootstrap changed'
}
. $bootstrapPath
$verifiedControllerBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot
if ([string]$verifiedControllerBundle.entrypoint -cne
    'qualify_windows_tun_hard_kill.ps1') {
    throw 'hard-kill controller bundle entrypoint changed'
}

foreach ($owner in @(
    'Guest.Identity.ps1'
    'Guest.Cleanup.ps1'
    'Guest.Topology.ps1'
    'Guest.Runtime.ps1'
    'Guest.NativeProcess.cs.ps1'
    'Guest.NativeTransport.cs.ps1'
    'Guest.NativeNetwork.cs.ps1'
    'Guest.TransportProbes.ps1'
    'Guest.HardKillSupport.ps1'
    'Hard.Qualification.ps1'
)) {
    . (Join-Path $PSScriptRoot $owner)
}

if (-not $IsWindows -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'hard-kill controller requires Windows AMD64'
}
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if ($computerSystem.Manufacturer -cne 'Microsoft Corporation' -or
    $computerSystem.Model -cne 'Virtual Machine') {
    throw 'hard-kill controller requires the isolated Hyper-V guest'
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw 'hard-kill controller requires an elevated administrator'
}

$expectedZipHash = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$expectedDllHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$expectedExports = @(
    'WintunAllocateSendPacket', 'WintunCloseAdapter', 'WintunEndSession',
    'WintunFreeAdapter', 'WintunGetAdapterLUID', 'WintunGetReadWaitEvent',
    'WintunGetRunningDriverVersion', 'WintunOpenAdapter', 'WintunReceivePacket',
    'WintunReleaseReceivePacket', 'WintunSendPacket', 'WintunSetLogger',
    'WintunStartSession'
) | Sort-Object
$runIdentity = $RunToken
$work = Join-Path ([IO.Path]::GetTempPath()) "ferrum2-m16-product-$runIdentity"
$managedAutoAdapterName = "F2-M16P-A-$runIdentity"
$managedManualAdapterName = "F2-M16P-M-$runIdentity"
$managedLifecycleConfig = Join-Path $work 'client-managed-lifecycle.toml'
$managedRouteOnlyConfig = Join-Path $work 'client-managed-route-only.toml'
$addressJournal = Join-Path $work 'owned-target-addresses.txt'
$dllJournal = Join-Path $work 'owned-wintun-dll.txt'
$m17NetworkMutationJournal = Join-Path $work 'm17-network-mutations'
$m17UdpFirewallRuleName = "Ferrum2-M17-UDP-$runIdentity"
$runIdentityJournalRoot = Join-Path `
    ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) `
    'Ferrum2\ControllerRunIdentities'
$runIdentityJournalPath = Join-Path $runIdentityJournalRoot "$runIdentity.json"
$controllerProgram = [IO.Path]::GetFullPath((Get-Process -Id $PID -ErrorAction Stop).Path)
$identityMarker = $IdentityLedger
$ProductRoot = if ($null -eq $ProductRoot) { '' } else { $ProductRoot }
$resolvedProductRoot = if ([string]::IsNullOrWhiteSpace($ProductRoot)) {
    $PSScriptRoot
} else {
    [IO.Path]::GetFullPath($ProductRoot)
}
$clientBinaryExplicit = -not [string]::IsNullOrWhiteSpace($ClientBinary)
$serverBinaryExplicit = -not [string]::IsNullOrWhiteSpace($ServerBinary)
$binary = if ($clientBinaryExplicit) {
    [IO.Path]::GetFullPath($ClientBinary)
} else {
    Join-Path $resolvedProductRoot 'target\debug\ferrum2-client.exe'
}
$serverBinary = if ($serverBinaryExplicit) {
    [IO.Path]::GetFullPath($ServerBinary)
} else {
    Join-Path $resolvedProductRoot 'target\debug\ferrum2-server.exe'
}
$siblingDll = Join-Path (Split-Path -Parent $binary) 'wintun.dll'
$createdSiblingDll = $false
$ownedInterfaceIndex = $null
$m17GuestNetworkPathDocument = $null
$capabilityEvidence = $null
$tcpResources = [Collections.Generic.List[IDisposable]]::new()

function Invoke-Ferrum2HardKillRecovery {
    $issues = [Collections.Generic.List[string]]::new()
    if ((Test-Path Variable:script:hardContext) -and
        $null -ne $script:hardContext.active_process) {
        $ownedProcess = $script:hardContext.active_process
        try {
            if (-not $ownedProcess.HasExited) {
                [void][Ferrum2ProcessGroup]::Terminate([uint32]$ownedProcess.Id)
                [void](Wait-ProcessExit $ownedProcess 10)
            }
            [Ferrum2ProcessGroup]::Close([uint32]$ownedProcess.Id)
            $script:hardContext.active_process = $null
        } catch { $issues.Add("owned process: $($_.Exception.Message)") }
    }
    $processes = @(Get-ExactRunProcesses -WorkPath $script:work)
    foreach ($process in $processes) {
        try {
            $row = Get-Process -Id ([int]$process.ProcessId) -ErrorAction SilentlyContinue
            if ($null -ne $row) {
                [void][Ferrum2ProcessGroup]::Terminate([uint32]$row.Id)
                [void](Wait-ProcessExit $row 10)
                [Ferrum2ProcessGroup]::Close([uint32]$row.Id)
            }
        } catch { $issues.Add("process: $($_.Exception.Message)") }
    }
    foreach ($name in @($script:managedAutoAdapterName, $script:managedManualAdapterName)) {
        try {
            if (Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue) {
                Wait-AdapterAbsent $name 20
            }
        } catch { $issues.Add("adapter $name`: $($_.Exception.Message)") }
    }
    foreach ($resource in @($script:tcpResources)) {
        try { $resource.Dispose() }
        catch { $issues.Add("resource: $($_.Exception.Message)") }
    }
    $script:tcpResources.Clear()
    if (Test-Path -LiteralPath $script:runIdentityJournalPath -PathType Leaf) {
        try {
            $identity = Read-RunIdentityJournal $script:runIdentityJournalPath @($script:work)
            if (Test-Path -LiteralPath $identity.DllMarkerPath -PathType Leaf) {
                Remove-OwnedSiblingDll $identity
            }
        } catch { $issues.Add("sibling DLL: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $script:work) {
        try {
            Assert-NotReparsePoint $script:work 'hard-kill work directory'
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction Stop
        } catch { $issues.Add("work directory: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $script:runIdentityJournalPath -PathType Leaf) {
        try {
            Remove-Item -LiteralPath $script:runIdentityJournalPath -Force -ErrorAction Stop
        } catch { $issues.Add("identity journal: $($_.Exception.Message)") }
    }
    if ($issues.Count -ne 0) {
        throw "hard-kill recovery failed: $($issues -join '; ')"
    }
}

if ($Cleanup) {
    Invoke-Ferrum2HardKillRecovery
    Write-Output "m16_windows_hard_kill_cleanup status=PASS run_token=$runIdentity"
    return
}

$resolvedRuntimeLibraryDirectory = (Resolve-Path -LiteralPath `
    $RuntimeLibraryDirectory -ErrorAction Stop).Path
$runtimeDirectoryItem = Get-Item -LiteralPath $resolvedRuntimeLibraryDirectory `
    -Force -ErrorAction Stop
if (-not $runtimeDirectoryItem.PSIsContainer -or
    ($runtimeDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'hard-kill runtime library directory is invalid'
}
$runtimeVcruntimePath = Join-Path $resolvedRuntimeLibraryDirectory 'vcruntime140.dll'
if (-not (Test-Path -LiteralPath $runtimeVcruntimePath -PathType Leaf)) {
    throw 'hard-kill runtime is missing vcruntime140.dll'
}
$runtimeVcruntimeItem = Get-Item -LiteralPath $runtimeVcruntimePath -Force
$runtimeVcruntimeBytes = [long]$runtimeVcruntimeItem.Length
$runtimeVcruntimeSha256 = (Get-FileHash -LiteralPath $runtimeVcruntimePath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$env:Path = "$resolvedRuntimeLibraryDirectory;$env:Path"
$zip = (Resolve-Path -LiteralPath $WintunZip -ErrorAction Stop).Path
$runJournalIdentity = $null
$hardContext = [ordered]@{
    capability_identity = $null
    binary = $binary
    work = $work
    managed_auto_adapter_name = $managedAutoAdapterName
    managed_lifecycle_config = $managedLifecycleConfig
    managed_route_only_config = $managedRouteOnlyConfig
    sibling_dll = $siblingDll
    source_dll = $null
    run_journal_identity = $null
    tcp_resources = $tcpResources
    run_identity = $runIdentity
    active_process = $null
    owned_interface_index = $null
    dns_responder = $null
    sibling_dll_owned = $false
}
$primaryFailure = $null
$qualificationResult = $null
try {
    Assert-True (-not (Test-Path -LiteralPath $work)) `
        'hard-kill work baseline is not absent'
    Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) `
        'hard-kill process baseline is not absent'
    Assert-True (-not (Get-NetAdapter -Name $managedAutoAdapterName `
        -IncludeHidden -ErrorAction SilentlyContinue)) `
        'hard-kill adapter baseline is not absent'
    Assert-True ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ceq
        $expectedZipHash) 'Wintun ZIP hash mismatch'
    Write-RunIdentityJournal
    $runJournalIdentity = Read-RunIdentityJournal $runIdentityJournalPath @($work)
    New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $work -ErrorAction Stop
    $sourceDll = Join-Path $work 'wintun\bin\amd64\wintun.dll'
    Assert-True (Test-Path -LiteralPath (Join-Path $work 'wintun\LICENSE.txt')) `
        'Wintun license member is missing'
    Assert-True ((Get-Item -LiteralPath $sourceDll).Length -eq 427552) `
        'Wintun DLL size mismatch'
    Assert-True ((Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash -ceq
        $expectedDllHash) 'Wintun DLL hash mismatch'
    $pe = [IO.File]::ReadAllBytes($sourceDll)
    $peOffset = [BitConverter]::ToInt32($pe, 0x3c)
    Assert-True ([BitConverter]::ToUInt16($pe, $peOffset + 4) -eq 0x8664) `
        'Wintun DLL is not AMD64 PE'
    Assert-True ((Get-AuthenticodeSignature -LiteralPath $sourceDll).Status -eq 'Valid') `
        'Wintun Authenticode trust is invalid'
    Assert-True ((@(Get-PeExportNames $pe) -join '|') -ceq
        ($expectedExports -join '|')) 'Wintun export set mismatch'
    Assert-True (Test-Path -LiteralPath $binary -PathType Leaf) `
        'hard-kill client binary is missing'
    Assert-True (Test-Path -LiteralPath $serverBinary -PathType Leaf) `
        'hard-kill server binary is missing'
    $capabilityIdentity = Get-NetworkFeasibilityIdentity $IdentityLedger $false
    $capabilityEvidence = "$($capabilityIdentity.Path).evidence-$runIdentity.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $capabilityEvidence)) `
        'hard-kill evidence baseline is not absent'
    $m17GuestNetworkPathDocument = Read-M17GuestNetworkPath `
        $GuestNetworkPath $capabilityIdentity.Ledger
    $hardContext.capability_identity = $capabilityIdentity
    $hardContext.source_dll = $sourceDll
    $hardContext.run_journal_identity = $runJournalIdentity
    $qualificationResult = Invoke-Ferrum2HardKillQualification -Context $hardContext
    Assert-True ($qualificationResult.cases -eq 3 -and
        $qualificationResult.cleanup -ceq 'pass') `
        'hard-kill transaction result is invalid'
} catch {
    $primaryFailure = $_
} finally {
    try { Invoke-Ferrum2HardKillRecovery }
    catch {
        if ($null -eq $primaryFailure) { $primaryFailure = $_ }
        else {
            $primaryFailure = [InvalidOperationException]::new(
                "$($primaryFailure.Exception.Message); $($_.Exception.Message)"
            )
        }
    }
}
if ($null -ne $primaryFailure) { throw $primaryFailure }
Assert-True (Test-Path -LiteralPath $capabilityEvidence -PathType Leaf) `
    'hard-kill evidence is missing'
Write-Output (
    'm16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS ' +
    'adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT ' +
    'strict_route_wfp=ABSENT cleanup=PASS ' +
    "guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity " +
    "candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) " +
    "probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) " +
    "identity_sha256=$($capabilityIdentity.IdentitySha256)"
)
