Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:expectedPowerShellVersion = '7.4.19'
$script:expectedPowerShellZipSha256 = `
    'cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9'

$labManifest = Join-Path $PSScriptRoot `
    '..\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1'
Import-Module $labManifest -Scope Local -ErrorAction Stop

foreach ($owner in @(
    'Paths.ps1'
    'VmTransaction.ps1'
    'Process.ps1'
    'Manifest.ps1'
    'Artifacts.ps1'
    'Evidence.ps1'
)) {
    . (Join-Path $PSScriptRoot "private/$owner")
}

$moduleRepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..') `
    -ErrorAction Stop).Path
$loadedTopologyRuntimePath = Join-Path $moduleRepositoryRoot `
    'tools/windows-tun/lab/windows_tun_hyperv_support_topology_runtime.ps1'
$loadedHostNetworkPathHelperPath = Join-Path $moduleRepositoryRoot `
    'tools/windows-tun/lab/windows_tun_host_network_path.ps1'
$script:loadedTopologyRuntimeSha256 = Get-Ferrum2LowerSha256 $loadedTopologyRuntimePath
$script:loadedHostNetworkPathHelperSha256 = Get-Ferrum2LowerSha256 `
    $loadedHostNetworkPathHelperPath
. $loadedTopologyRuntimePath -LibraryOnly
. $loadedHostNetworkPathHelperPath
if ((Get-Ferrum2LowerSha256 $loadedTopologyRuntimePath) -cne
        $script:loadedTopologyRuntimeSha256 -or
    (Get-Ferrum2LowerSha256 $loadedHostNetworkPathHelperPath) -cne
        $script:loadedHostNetworkPathHelperSha256) {
    throw 'support topology runtime source changed while loading'
}

$script:HostContextInitialized = $false

function Invoke-Ferrum2QualificationHostController {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)]
        [ValidateSet('MainCampaign', 'MainProbe', 'MainProbeWorker', 'MainWorker', 'HardKill')]
        [string]$Controller,
        [Parameter(Mandatory)] [Collections.IDictionary]$Context
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $contracts = [ordered]@{
        MainCampaign = [ordered]@{
            source = 'tests/platform/Main.CampaignController.ps1'
            bundle = 'tests/platform/main-source-bundle.json'
            modules = @('Evidence', 'GuestController')
        }
        MainProbe = [ordered]@{
            source = 'tests/platform/Main.ProbeController.ps1'
            bundle = 'tests/platform/main-source-bundle.json'
            modules = @('Evidence')
        }
        MainProbeWorker = [ordered]@{
            source = 'tests/platform/Main.ProbeWorkerController.ps1'
            bundle = 'tests/platform/main-source-bundle.json'
            modules = @('Evidence')
        }
        MainWorker = [ordered]@{
            source = 'tests/platform/Main.HostController.ps1'
            bundle = 'tests/platform/main-source-bundle.json'
            modules = @('Evidence', 'GuestController')
        }
        HardKill = [ordered]@{
            source = 'tests/platform/Hard.HostController.ps1'
            bundle = 'tests/platform/hard-source-bundle.json'
            modules = @('Evidence')
        }
    }
    $contract = $contracts[$Controller]
    $bundlePath = Resolve-Ferrum2OrdinaryFile `
        -Path (Join-Path $root $contract.bundle) `
        -Label "$Controller source bundle" -MaximumBytes 1MB -RequiredRoot $root
    $bundle = Get-Content -LiteralPath $bundlePath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    [void](Assert-Ferrum2ControllerBundleManifest -Manifest $bundle -BundleRoot $root)
    $sourceEntry = @($bundle.files | Where-Object {
        [string]$_.path -ceq [string]$contract.source
    })
    if ($sourceEntry.Count -ne 1) {
        throw "$Controller fixed controller source is absent from its bundle"
    }
    $resolved = Resolve-Ferrum2OrdinaryFile `
        -Path (Join-Path $root $contract.source) `
        -Label "$Controller fixed controller" -MaximumBytes 4MB -RequiredRoot $root
    if ((Get-Ferrum2LowerSha256 $resolved) -cne [string]$sourceEntry[0].sha256) {
        throw "$Controller fixed controller source identity changed"
    }
    $moduleRoot = Join-Path $root 'tools/powershell'
    foreach ($name in @($contract.modules)) {
        $moduleName = "Ferrum2.Qualification.$name"
        Import-Module (Join-Path $moduleRoot "$moduleName/$moduleName.psd1") `
            -Scope Local -ErrorAction Stop
    }
    . $resolved -Context $Context
}

function Initialize-Ferrum2HostHyperVModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [ValidateRange(576, 65535)] [int]$MinimumSupportIpv4PacketBytes = 1468
    )
    if ($script:HostContextInitialized) {
        throw 'HostHyperV context was initialized more than once'
    }
    $script:repositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $script:minimumSupportIpv4PacketBytes = $MinimumSupportIpv4PacketBytes
    $script:topologyManifestDocument = $null
    $script:approvedVmName = ''
    $script:approvedVmId = [Guid]::Empty
    $script:approvedCheckpointName = ''
    $script:approvedCheckpointId = [Guid]::Empty
    $script:approvedVmIdentity = $null
    $script:topologyRuntimeLoaded = $false
    $script:topologyRuntimePath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/lab/windows_tun_hyperv_support_topology_runtime.ps1'
    $script:hostNetworkPathHelperPath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/lab/windows_tun_host_network_path.ps1'
    $script:guestNetworkPathProbePath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/lab/get_windows_tun_guest_network_path.ps1'
    $script:topologyProvisioningLibraryPath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/lab/windows_tun_hyperv_support_topology_provisioning.ps1'
    foreach ($source in @(
        [ordered]@{ Path = $script:topologyRuntimePath; Label = 'support topology runtime' }
        [ordered]@{ Path = $script:hostNetworkPathHelperPath; Label = 'host network-path helper' }
        [ordered]@{ Path = $script:guestNetworkPathProbePath; Label = 'guest network-path probe' }
        [ordered]@{ Path = $script:topologyProvisioningLibraryPath; Label = 'topology provisioning library' }
    )) {
        $null = Resolve-BoundedFile -Path $source.Path -Label $source.Label `
            -MaximumBytes 4194304
    }
    $runtimeHash = Get-Ferrum2LowerSha256 $script:topologyRuntimePath
    $hostHelperHash = Get-Ferrum2LowerSha256 $script:hostNetworkPathHelperPath
    $guestProbeHash = Get-Ferrum2LowerSha256 $script:guestNetworkPathProbePath
    if ($runtimeHash -cne $script:loadedTopologyRuntimeSha256 -or
        $hostHelperHash -cne $script:loadedHostNetworkPathHelperSha256 -or
        (Get-Ferrum2LowerSha256 $script:guestNetworkPathProbePath) -cne $guestProbeHash) {
        throw 'support topology runtime source changed while loading'
    }
    $script:topologyRuntimeSha256 = $runtimeHash
    $script:hostNetworkPathHelperSha256 = $hostHelperHash
    $script:guestNetworkPathProbeSha256 = $guestProbeHash
    $script:topologyRuntimeLoaded = $true
    $script:HostContextInitialized = $true
    [pscustomobject][ordered]@{
        topology_runtime_sha256 = $runtimeHash
        host_network_path_helper_sha256 = $hostHelperHash
        guest_network_path_probe_sha256 = $guestProbeHash
        guest_network_path_probe = $script:guestNetworkPathProbePath
    }
}

function New-Ferrum2HyperVMutationCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Read', 'Start', 'Stop', 'Restore')]
        [string]$Action,
        [Parameter(Mandatory)] [Guid]$VmId,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName,
        [Guid]$CheckpointId = [Guid]::Empty,
        [AllowNull()] [string]$ExpectedCheckpointName = $null,
        [Guid]$ExpectedCheckpointParentId = [Guid]::Empty,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 120
    )
    if ($VmId -eq [Guid]::Empty -or
        ($Action -ceq 'Restore' -and
            ($CheckpointId -eq [Guid]::Empty -or
                $ExpectedCheckpointParentId -eq [Guid]::Empty -or
                [string]::IsNullOrWhiteSpace($ExpectedCheckpointName) -or
                $ExpectedCheckpointName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')) -or
        ($Action -cne 'Restore' -and
            ($CheckpointId -ne [Guid]::Empty -or
                $ExpectedCheckpointParentId -ne [Guid]::Empty -or
                -not [string]::IsNullOrWhiteSpace($ExpectedCheckpointName)))) {
        throw 'bounded Hyper-V mutation identity is invalid'
    }
    $scriptText = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$mutationGateName = [string]`$env:FERRUM2_HYPERV_MUTATION_GATE
if (`$mutationGateName -cnotmatch '^Local\\Ferrum2-HyperV-Mutation-[0-9a-f]{32}$') {
    throw 'bounded Hyper-V mutation gate identity is invalid'
}
`$mutationGate = [Threading.EventWaitHandle]::OpenExisting(`$mutationGateName)
[Environment]::SetEnvironmentVariable('FERRUM2_HYPERV_MUTATION_GATE', `$null, 'Process')
try {
    if (-not `$mutationGate.WaitOne(30000)) {
        throw 'bounded Hyper-V mutation start gate timed out'
    }
} finally {
    `$mutationGate.Dispose()
}
Import-Module Hyper-V -ErrorAction Stop
`$vmId = [Guid]'$($VmId.ToString("D"))'
`$expectedVmName = '$ExpectedVmName'
`$rows = @(Get-VM -Id `$vmId -ErrorAction Stop)
if (`$rows.Count -ne 1 -or [Guid]`$rows[0].Id -ne `$vmId) {
    throw 'bounded Hyper-V VM identity is unavailable or ambiguous'
}
`$vm = `$rows[0]
switch ('$Action') {
    'Read' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V read VM name identity changed'
        }
    }
    'Start' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V start VM name identity changed'
        }
        if ([string]`$vm.State -cne 'Off') { throw 'bounded Hyper-V start requires Off' }
        `$vm | Start-VM -ErrorAction Stop | Out-Null
    }
    'Stop' {
        if ([string]`$vm.State -cne 'Off') {
            `$vm | Stop-VM -TurnOff -Force -Confirm:`$false -ErrorAction Stop | Out-Null
        }
    }
    'Restore' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V restore VM name identity changed'
        }
        if ([string]`$vm.State -cne 'Off') { throw 'bounded Hyper-V restore requires Off' }
        `$checkpointId = [Guid]'$($CheckpointId.ToString("D"))'
        `$checkpointParentId = [Guid]'$($ExpectedCheckpointParentId.ToString("D"))'
        `$expectedCheckpointName = '$ExpectedCheckpointName'
        `$checkpoint = @(
            Get-VMSnapshot -VM `$vm -ErrorAction Stop |
                Where-Object { [Guid]`$_.Id -eq `$checkpointId }
        )
        if (`$checkpoint.Count -ne 1 -or
            [string]`$checkpoint[0].Name -cne `$expectedCheckpointName -or
            [Guid][string]`$checkpoint[0].ParentCheckpointId -ne `$checkpointParentId) {
            throw 'bounded Hyper-V checkpoint identity is unavailable or ambiguous'
        }
        `$checkpoint[0] | Restore-VMSnapshot -Confirm:`$false -ErrorAction Stop | Out-Null
    }
    default { throw 'bounded Hyper-V action is invalid' }
}
`$expectedState = switch ('$Action') {
    'Start' { 'Running' }
    'Stop' { 'Off' }
    'Restore' { 'Off' }
    default { `$null }
}
`$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    `$stateRows = @(Get-VM -Id `$vmId -ErrorAction Stop)
    if (`$stateRows.Count -ne 1 -or [Guid]`$stateRows[0].Id -ne `$vmId) {
        throw 'bounded Hyper-V final VM identity is unavailable or ambiguous'
    }
    `$state = [string]`$stateRows[0].State
    if (`$null -eq `$expectedState -or `$state -ceq `$expectedState) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt `$deadline)
if (`$null -ne `$expectedState -and `$state -cne `$expectedState) {
    throw "bounded Hyper-V action did not reach expected state `$expectedState"
}
if ([string]`$stateRows[0].Name -cne `$expectedVmName) {
    throw 'bounded Hyper-V final VM name identity changed'
}
[Console]::Out.WriteLine("FERRUM2_BOUNDED_HYPERV_ACTION_PASS action=$Action state=`$state")
"@
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))
}

function Assert-Ferrum2HostFinalState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$FinalVmState,
        [Parameter(Mandatory)] [bool]$CheckpointRestored,
        [Parameter(Mandatory)] [bool]$CleanupPassed
    )
    if ($FinalVmState -cne 'Off') {
        throw 'approved VM final state is not Off'
    }
    if (-not $CheckpointRestored) {
        throw 'approved checkpoint restore was not proven'
    }
    if (-not $CleanupPassed) {
        throw 'qualification cleanup did not pass'
    }
}

Export-ModuleMember -Function @(
    'Invoke-Ferrum2QualificationHostController'
    'Initialize-Ferrum2HostHyperVModule'
)
