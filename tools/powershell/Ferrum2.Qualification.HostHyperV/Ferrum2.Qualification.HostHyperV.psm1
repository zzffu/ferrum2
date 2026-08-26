Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonManifest = Join-Path $PSScriptRoot `
    '..\Ferrum2.Qualification.Common\Ferrum2.Qualification.Common.psd1'
Import-Module $commonManifest -Scope Local -Force -ErrorAction Stop

foreach ($owner in @(
    'Facade.ps1'
    'Paths.ps1'
    'VmTransaction.ps1'
    'Process.ps1'
    'Manifest.ps1'
    'Artifacts.ps1'
    'Evidence.ps1'
)) {
    . (Join-Path $PSScriptRoot "private/$owner")
}

$script:HostContextInitialized = $false

function Invoke-Ferrum2HostControllerExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$ExtensionPath,
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory)] [Collections.IDictionary]$Context,
        [ValidateSet('Evidence', 'GuestController')]
        [string[]]$RequiredModules = @('Evidence')
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $resolved = Resolve-Ferrum2OrdinaryFile -Path $ExtensionPath `
        -Label 'HostHyperV controller extension' -MaximumBytes 4MB -RequiredRoot $root
    if ((Get-Ferrum2LowerSha256 $resolved) -cne $ExpectedSha256) {
        throw 'HostHyperV controller extension identity changed'
    }
    $moduleRoot = Join-Path $root 'tools/powershell'
    foreach ($name in @($RequiredModules | Sort-Object -Unique)) {
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
    $script:topologyRuntimeLoaded = $false
    $script:topologyRuntimePath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/windows_tun_hyperv_support_topology_runtime.ps1'
    $script:hostNetworkPathHelperPath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/windows_tun_host_network_path.ps1'
    $script:guestNetworkPathProbePath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/get_windows_tun_guest_network_path.ps1'
    $script:topologyProvisioningLibraryPath = Join-Path $script:repositoryRoot `
        'tools/windows-tun/windows_tun_hyperv_support_topology_provisioning.ps1'
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
    . $script:topologyRuntimePath -LibraryOnly
    . $script:hostNetworkPathHelperPath
    if ((Get-Ferrum2LowerSha256 $script:topologyRuntimePath) -cne $runtimeHash -or
        (Get-Ferrum2LowerSha256 $script:hostNetworkPathHelperPath) -cne $hostHelperHash -or
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
    'Invoke-Ferrum2HostControllerExtension'
    'Initialize-Ferrum2HostHyperVModule'
    'Resolve-Ferrum2HostInput'
    'New-Ferrum2HostVmIdentity'
    'Get-Ferrum2HostVmContext'
    'Invoke-Ferrum2HostVmLifecycle'
    'Connect-Ferrum2HostGuest'
)
