#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Creates the explicitly authorized isolated Hyper-V support topology for Windows TUN lab workflows.

.DESCRIPTION
This is a one-time, fail-closed transaction. It validates the closed provisioning source bundle,
requires -Apply, a fixed authorization token, and an absent manifest path outside the repository.
It restores the pinned source checkpoint, creates
one Internal vSwitch and one static-MAC VM NIC, configures only the two new support interfaces,
creates and verifies a new Standard checkpoint, writes generated identities to the manifest, and
leaves the VM Off. On failure it audits ownership before restoring the source checkpoint and
removes only resources whose preassigned ID or random transaction marker proves they belong to
this invocation; ambiguous concurrent state is left intact for explicit recovery.

The script does not configure NAT, ICS, firewall policy, the Default Switch, a physical adapter,
or host tun0. Use -WhatIf to execute the complete read-only preflight without loading a credential
or changing state.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidUsingPlainTextForPassword",
    "",
    Justification = "CredentialPath names a DPAPI-protected PSCredential file; no password is accepted."
)]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [Parameter(Mandatory = $true)]
    [switch]$Apply,

    [Parameter(Mandatory = $true)]
    [ValidateSet("CREATE-FERRUM2-INTERNAL-SUPPORT-V1")]
    [string]$AuthorizationToken,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$TopologyPlanPath,

    [string]$CredentialPath,

    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:sourceManifestPath = Join-Path $PSScriptRoot 'provisioning-source-bundle.json'
$script:repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..') `
    -ErrorAction Stop).Path
$script:toolsRoot = Join-Path $script:repositoryRoot 'tools'
$script:expectedProvisioningFiles = @(
    [pscustomobject][ordered]@{ role = 'bootstrap'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1' }
    [pscustomobject][ordered]@{ role = 'driver'; path = 'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1' }
    [pscustomobject][ordered]@{ role = 'readonly'; path = 'tools/windows-tun/lab/windows_tun_hyperv_support_topology_readonly.ps1' }
    [pscustomobject][ordered]@{ role = 'primary'; path = 'tools/windows-tun/lab/windows_tun_hyperv_support_topology_provisioning.ps1' }
    [pscustomobject][ordered]@{ role = 'host'; path = 'tools/windows-tun/lab/windows_tun_hyperv_support_topology_provisioning_host.ps1' }
    [pscustomobject][ordered]@{ role = 'guest'; path = 'tools/windows-tun/lab/windows_tun_hyperv_support_topology_provisioning_guest.ps1' }
    [pscustomobject][ordered]@{ role = 'rollback'; path = 'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology_rollback.ps1' }
    [pscustomobject][ordered]@{ role = 'transaction'; path = 'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology_transaction.ps1' }
    [pscustomobject][ordered]@{ role = 'lab_manifest'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psd1' }
    [pscustomobject][ordered]@{ role = 'lab_module'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psm1' }
    [pscustomobject][ordered]@{ role = 'lab_json'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/private/JsonSource.ps1' }
    [pscustomobject][ordered]@{ role = 'lab_bundle'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/private/BundleFileSystem.ps1' }
    [pscustomobject][ordered]@{ role = 'lab_vm'; path = 'tools/powershell/Ferrum2.WindowsTun.Lab/private/VmSession.ps1' }
)

$bootstrapRelative = 'tools/powershell/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
[byte[]]$rawManifestBytes = [IO.File]::ReadAllBytes($script:sourceManifestPath)
$rawManifest = [Text.UTF8Encoding]::new($false, $true).GetString(
    $rawManifestBytes
) | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapEntry = @($rawManifest.files | Where-Object {
    [string]$_.role -ceq 'bootstrap' -and
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $script:repositoryRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
[byte[]]$bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)
$bootstrapSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($bootstrapBytes)
).ToLowerInvariant()
if ($bootstrapEntry.Count -ne 1 -or $bootstrapBytes.Length -ne
        [long]$bootstrapEntry[0].bytes -or
    $bootstrapSha256 -cne [string]$bootstrapEntry[0].sha256) {
    throw 'provisioning source bootstrap changed'
}
. ([scriptblock]::Create(
    [Text.UTF8Encoding]::new($false, $true).GetString($bootstrapBytes)
))

function Read-ProvisioningSourceIdentity {
    Read-Ferrum2BootstrapSourceClosure `
        -ManifestPath $script:sourceManifestPath `
        -BundleRoot $script:repositoryRoot -RequiredRoot $script:toolsRoot `
        -ExpectedSchema 'ferrum2.windows-tun-provisioning-source-bundle.v1' `
        -ExpectedEntrypoint (
            'tools/windows-tun/lab/' +
            'provision_windows_tun_hyperv_support_topology.ps1'
        ) -Format Role -ExpectedMembers $script:expectedProvisioningFiles
}

function Assert-ProvisioningSourceIdentity {
    $current = Read-ProvisioningSourceIdentity
    if ($current.ManifestSha256 -cne $script:provisioningSourceIdentity.ManifestSha256 -or
        $current.SourceBundleSha256 -cne
            $script:provisioningSourceIdentity.SourceBundleSha256) {
        throw 'provisioning source identity changed during the topology transaction'
    }
}

$script:provisioningSourceIdentity = Read-ProvisioningSourceIdentity
[void](Assert-Ferrum2BootstrapControllerSelfMember `
    -Closure $script:provisioningSourceIdentity `
    -RelativePath 'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1' `
    -InvocationPath $PSCommandPath)
$labModuleContext = [pscustomobject][ordered]@{
    OwnerTexts = @(
        [string]$script:provisioningSourceIdentity.Sources['lab_json'].Text
        [string]$script:provisioningSourceIdentity.Sources['lab_bundle'].Text
        [string]$script:provisioningSourceIdentity.Sources['lab_vm'].Text
    )
    Exports = [string[]]@(
        (& ([scriptblock]::Create(
            [string]$script:provisioningSourceIdentity.Sources['lab_manifest'].Text
        ))).FunctionsToExport
    )
}
$verifiedLabModule = New-Module -Name (
    'Ferrum2.WindowsTun.Lab.Verified.' + [Guid]::NewGuid().ToString('N')
) -ArgumentList $labModuleContext -ScriptBlock {
    param([Parameter(Mandatory)] [object]$Context)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    foreach ($ownerText in $Context.OwnerTexts) {
        . ([scriptblock]::Create([string]$ownerText))
    }
    Export-ModuleMember -Function $Context.Exports
}
Import-Module $verifiedLabModule -Global -Force -ErrorAction Stop

. ([scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['readonly'].Text
)) -LibraryOnly
. ([scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['host'].Text
)) -LibraryOnly
. ([scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['primary'].Text
)) -LibraryOnly
. ([scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['rollback'].Text
)) -LibraryOnly
. ([scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['transaction'].Text
)) -LibraryOnly
$script:guestProvisioningScript = [scriptblock]::Create(
    [string]$script:provisioningSourceIdentity.Sources['guest'].Text
)
Assert-ProvisioningSourceIdentity

if (-not $Apply -or $AuthorizationToken -cne 'CREATE-FERRUM2-INTERNAL-SUPPORT-V1') {
    throw 'the explicit topology authorization contract is invalid'
}

$planDocument = Read-TopologyPlan -Path $TopologyPlanPath
$plan = $planDocument.Value
$initialContext = Get-Ferrum2PinnedVmContext `
    -Identity (New-Ferrum2PinnedVmIdentity -Plan $plan)
$initialPreflight = Get-ReadOnlyPreflight -Context $initialContext -Plan $plan
$resolvedManifestPath = Resolve-Ferrum2HostOutputFile `
    -RepositoryRoot $script:repositoryRoot -Path $ManifestPath `
    -Label 'topology identity manifest' -Extension '.json'
$state = New-ProvisioningTransactionState -PlanDocument $planDocument `
    -InitialPreflight $initialPreflight -ManifestPath $resolvedManifestPath `
    -CredentialPath $CredentialPath -ReadinessTimeoutSeconds $ReadinessTimeoutSeconds `
    -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
    -SourceIdentity $script:provisioningSourceIdentity
$script:provisioningVmIdentity = $state.VmIdentity

$target = "VM $($plan.vm.id) isolated support topology"
if (-not $PSCmdlet.ShouldProcess($target, 'create, configure, checkpoint, and verify')) {
    [pscustomobject][ordered]@{
        schema = 1
        status = 'not_applied'
        topology_plan_sha256 = $planDocument.Sha256
        preflight = $initialPreflight
        manifest_path = $resolvedManifestPath
        terminal_vm_state = 'Off'
    } | ConvertTo-Json -Depth 8
    return
}

try {
    Enter-ProvisioningTransaction -State $state
    Initialize-ProvisioningInfrastructure -State $state
    Initialize-ProvisioningGuest -State $state
    New-ProvisioningCheckpoint -State $state
    Test-ProvisioningCheckpointRestore -State $state
    New-ProvisioningTerminalEvidence -State $state
    Commit-ProvisioningManifest -State $state
} catch {
    $state.Failure = $_
} finally {
    Complete-ProvisioningTransaction -State $state
}

if ($null -ne $state.Failure) { throw $state.Failure }
