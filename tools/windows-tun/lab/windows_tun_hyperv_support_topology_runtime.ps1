#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines read-only runtime checks for the provisioned Windows TUN Hyper-V support topology.

.DESCRIPTION
This dot-source-only library validates the external provisioning manifest and its closed source
bundle, binds generated switch, adapter, and checkpoint identities to the configured topology plan,
and validates the live
Hyper-V and host-network state. It never starts or stops a VM and never changes an adapter, address,
route, DNS setting, firewall rule, switch, checkpoint, or TUN session.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:ferrum2TopologyReadonlyPath = Join-Path $PSScriptRoot `
    'windows_tun_hyperv_support_topology_readonly.ps1'
$script:ferrum2ProvisioningSourceManifestPath = Join-Path $PSScriptRoot `
    'provisioning-source-bundle.json'
$script:ferrum2RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..') `
    -ErrorAction Stop).Path
$script:ferrum2ToolsRoot = Join-Path $script:ferrum2RepositoryRoot 'tools'
$script:ferrum2ExpectedProvisioningFiles = @(
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
$labManifestPath = Join-Path $script:ferrum2RepositoryRoot `
    'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psd1'
Import-Module $labManifestPath -Force -ErrorAction Stop
. $script:ferrum2TopologyReadonlyPath -LibraryOnly

if (-not $LibraryOnly) {
    throw "support topology runtime helpers are dot-source-only"
}

function Read-Ferrum2SupportTopologyPlanDocument {
    param([Parameter(Mandatory)] [string]$Path)

    Read-TopologyPlan -Path $Path
}

function Get-Ferrum2ProvisioningSourceIdentity {
    param(
        [Parameter(Mandatory)] [string]$ExpectedManifestSha256,
        [Parameter(Mandatory)] [string]$ExpectedBundleSha256
    )
    $identity = Read-Ferrum2ClosedSourceManifest `
        -Path $script:ferrum2ProvisioningSourceManifestPath `
        -RepositoryRoot $script:ferrum2RepositoryRoot `
        -RequiredRoot $script:ferrum2ToolsRoot `
        -Schema 'ferrum2.windows-tun-provisioning-source-bundle.v1' `
        -EntryPoint 'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1' `
        -ExpectedFiles $script:ferrum2ExpectedProvisioningFiles
    if ($identity.ManifestSha256 -cne $ExpectedManifestSha256 -or
        $identity.SourceBundleSha256 -cne $ExpectedBundleSha256) {
        throw 'provisioning source identity changed'
    }
    $identity
}

function Assert-Ferrum2SupportTopologyManifestProperties {
    param([Parameter(Mandatory)] [object]$Manifest)

    foreach ($contract in @(
        @($Manifest, @(
            'schema', 'created_utc', 'topology_plan_sha256',
            'provisioning_source_manifest_sha256', 'provisioning_source_bundle_sha256', 'vm',
            'source_checkpoint', 'lab_checkpoint', 'management_adapter', 'support',
            'protected_host_tun', 'constraints'
        ), 'support topology manifest'),
        @($Manifest.vm, @('name', 'id', 'terminal_state', 'automatic_checkpoints_enabled'),
            'manifest VM'),
        @($Manifest.source_checkpoint, @('name', 'id', 'type'), 'manifest source checkpoint'),
        @($Manifest.lab_checkpoint, @(
            'name', 'id', 'type', 'parent_id', 'support_vm_adapter_snapshot_id', 'restore_verified'
        ), 'manifest lab checkpoint'),
        @($Manifest.management_adapter, @(
            'name', 'id', 'switch_name', 'switch_id', 'mac_address',
            'dynamic_mac_address', 'guest_interface_alias', 'guest_interface_guid'
        ), 'manifest management adapter'),
        @($Manifest.support, @('switch', 'vm_adapter', 'guest'), 'manifest support topology'),
        @($Manifest.support.switch, @(
            'switch_name', 'switch_id', 'switch_type', 'management_os_adapter_id',
            'management_os_device_id', 'host_interface_alias', 'host_interface_guid',
            'host_interface_index', 'host_mac_address', 'host_ipv4', 'prefix_length', 'network',
            'gateway', 'dns_servers', 'mtu_bytes', 'nat_enabled', 'ics_enabled',
            'selected_source_ipv4', 'selected_route_prefix', 'selected_route_next_hop'
        ), 'manifest support switch'),
        @($Manifest.support.vm_adapter, @(
            'name', 'id', 'switch_id', 'mac_address', 'dynamic_mac_address',
            'virtual_system_identifiers'
        ), 'manifest support VM adapter'),
        @($Manifest.support.guest, @(
            'schema', 'management_interface_alias', 'management_interface_guid',
            'management_interface_index', 'management_mac_address', 'support_interface_alias',
            'support_interface_guid', 'support_interface_index', 'support_mac_address', 'guest_ipv4',
            'prefix_length', 'network', 'gateway', 'dns_servers', 'mtu_bytes',
            'selected_source_ipv4', 'selected_route_prefix', 'selected_route_next_hop'
        ), 'manifest guest support topology'),
        @($Manifest.protected_host_tun, @(
            'present', 'name', 'interface_guid', 'interface_index', 'status'
        ), 'manifest protected host TUN'),
        @($Manifest.constraints, @(
            'nat', 'ics', 'gateway', 'dns', 'firewall_mutation',
            'default_switch_mutation', 'host_tun_mutation'
        ), 'manifest constraints')
    )) {
        Assert-Ferrum2ClosedProperties -Value $contract[0] `
            -Expected ([string[]]$contract[1]) -Label ([string]$contract[2])
    }
}

function Assert-Ferrum2SupportTopologyManifestProvenance {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$PlanDocument
    )

    foreach ($hashName in @(
        'topology_plan_sha256', 'provisioning_source_manifest_sha256',
        'provisioning_source_bundle_sha256'
    )) {
        if ($Manifest.$hashName -isnot [string] -or
            [string]$Manifest.$hashName -cnotmatch '^[0-9a-f]{64}$') {
            throw "manifest $hashName is invalid"
        }
    }
    if ($Manifest.schema -isnot [long] -or [long]$Manifest.schema -ne 1 -or
        $Manifest.created_utc -isnot [DateTime] -or
        [DateTime]$Manifest.created_utc -gt [DateTime]::UtcNow.AddMinutes(5) -or
        [string]$Manifest.topology_plan_sha256 -cne [string]$PlanDocument.Sha256) {
        throw 'support topology manifest provenance is invalid'
    }
    $null = Get-Ferrum2ProvisioningSourceIdentity `
        -ExpectedManifestSha256 ([string]$Manifest.provisioning_source_manifest_sha256) `
        -ExpectedBundleSha256 ([string]$Manifest.provisioning_source_bundle_sha256)
}

function Assert-Ferrum2ManifestVmCheckpointContract {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan
    )

    $vmId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.vm.id -Label 'manifest VM'
    $sourceId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.source_checkpoint.id `
        -Label 'manifest source checkpoint'
    $checkpointId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.lab_checkpoint.id `
        -Label 'manifest lab checkpoint'
    $parentId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.lab_checkpoint.parent_id `
        -Label 'manifest lab checkpoint parent'
    $supportSnapshotOwner = $Manifest.lab_checkpoint.support_vm_adapter_snapshot_id.Split('\')[0]
    if ($vmId -cne (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.vm.id -Label 'planned VM') -or
        [string]$Manifest.vm.name -cne [string]$Plan.vm.name -or
        [string]$Manifest.vm.terminal_state -cne 'Off' -or
        $Manifest.vm.automatic_checkpoints_enabled -isnot [bool] -or
        $Manifest.vm.automatic_checkpoints_enabled -ne $false -or
        $sourceId -cne (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.source_checkpoint.id `
            -Label 'planned source checkpoint') -or
        [string]$Manifest.source_checkpoint.name -cne [string]$Plan.source_checkpoint.name -or
        [string]$Manifest.source_checkpoint.type -cne [string]$Plan.source_checkpoint.type -or
        $checkpointId -ceq $sourceId -or $parentId -cne $sourceId -or
        [string]$Manifest.lab_checkpoint.name -cne [string]$Plan.lab_checkpoint.name -or
        [string]$Manifest.lab_checkpoint.type -cne [string]$Plan.lab_checkpoint.type -or
        $Manifest.lab_checkpoint.restore_verified -isnot [bool] -or
        $Manifest.lab_checkpoint.restore_verified -ne $true -or
        $supportSnapshotOwner -cne ('Microsoft:' + $checkpointId.ToUpperInvariant())) {
        throw 'manifest VM or checkpoint contract is invalid'
    }
    $null = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$Manifest.lab_checkpoint.support_vm_adapter_snapshot_id) `
        -ExpectedOwnerId $checkpointId -Label 'manifest lab support snapshot'
}

function Get-Ferrum2ManifestAdapterMacs {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan
    )

    $managementMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Manifest.management_adapter.mac_address) `
        -Label 'manifest management adapter'
    $supportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Manifest.support.vm_adapter.mac_address) `
        -Label 'manifest support VM adapter'
    if ([string]$Manifest.management_adapter.name -cne [string]$Plan.management_adapter.name -or
        [string]$Manifest.management_adapter.id -cne [string]$Plan.management_adapter.id -or
        [string]$Manifest.management_adapter.switch_name -cne
            [string]$Plan.management_adapter.switch_name -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.management_adapter.switch_id `
            -Label 'manifest management switch') -cne
            (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.management_adapter.switch_id `
                -Label 'planned management switch') -or
        $managementMac -cne (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$Plan.management_adapter.mac_address) -Label 'planned management') -or
        $Manifest.management_adapter.dynamic_mac_address -isnot [bool] -or
        $Manifest.management_adapter.dynamic_mac_address -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$Manifest.management_adapter.guest_interface_alias)) {
        throw 'manifest management adapter contract is invalid'
    }
    $null = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.management_adapter.guest_interface_guid `
        -Label 'manifest guest management interface'
    [pscustomobject][ordered]@{ Management = $managementMac; Support = $supportMac }
}

function Assert-Ferrum2ManifestSupportSwitchContract {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan
    )

    $switch = $Manifest.support.switch
    $switchId = ConvertTo-Ferrum2CanonicalGuid -Value $switch.switch_id `
        -Label 'manifest support switch'
    $adapterSwitchId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.support.vm_adapter.switch_id -Label 'manifest support adapter switch'
    if ([string]$switch.switch_name -cne [string]$Plan.support.switch_name -or
        [string]$switch.switch_type -cne 'Internal' -or $switchId -cne $adapterSwitchId -or
        [string]$switch.host_ipv4 -cne [string]$Plan.support.host_ipv4 -or
        [int]$switch.prefix_length -ne [int]$Plan.support.prefix_length -or
        [string]$switch.network -cne [string]$Plan.support.network -or
        $null -ne $switch.gateway -or @($switch.dns_servers).Count -ne 0 -or
        [int]$switch.host_interface_index -le 0 -or [int]$switch.mtu_bytes -lt 1468 -or
        $switch.nat_enabled -isnot [bool] -or $switch.nat_enabled -ne $false -or
        $switch.ics_enabled -isnot [bool] -or $switch.ics_enabled -ne $false -or
        [string]$switch.selected_source_ipv4 -cne [string]$Plan.support.host_ipv4 -or
        [string]$switch.selected_route_prefix -cne [string]$Plan.support.network -or
        [string]$switch.selected_route_next_hop -cne '0.0.0.0') {
        throw 'manifest support switch contract is invalid'
    }
    $hostGuid = ConvertTo-Ferrum2CanonicalGuid -Value $switch.host_interface_guid `
        -Label 'manifest host support interface'
    if ((ConvertTo-Ferrum2CanonicalGuid -Value $switch.management_os_device_id `
            -Label 'manifest support management OS device') -cne $hostGuid -or
        [string]::IsNullOrWhiteSpace([string]$switch.management_os_adapter_id)) {
        throw 'manifest host support adapter identity is invalid'
    }
    $null = ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$switch.host_mac_address) `
        -Label 'manifest host support interface'
}

function Assert-Ferrum2ManifestSupportVmAdapterContract {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [string]$SupportMac
    )

    $vmAdapter = $Manifest.support.vm_adapter
    $identifiers = @($vmAdapter.virtual_system_identifiers | ForEach-Object {
        ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label 'manifest support adapter identifier'
    })
    if ([string]$vmAdapter.name -cne [string]$Plan.support.vm_adapter_name -or
        $SupportMac -cne (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$Plan.support.vm_mac_address) -Label 'planned support adapter') -or
        $vmAdapter.dynamic_mac_address -isnot [bool] -or
        $vmAdapter.dynamic_mac_address -ne $false -or $identifiers.Count -ne 2 -or
        @($identifiers | Sort-Object -Unique).Count -ne 2) {
        throw 'manifest support VM adapter contract is invalid'
    }
    $vmId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.vm.id -Label 'manifest VM'
    $null = Get-Ferrum2VmAdapterInstanceGuid -AdapterId ([string]$vmAdapter.id) `
        -ExpectedOwnerId $vmId -Label 'manifest support VM adapter'
}

function Assert-Ferrum2ManifestGuestSupportContract {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [object]$AdapterMacs
    )

    $guest = $Manifest.support.guest
    if ($guest.schema -isnot [long] -or [long]$guest.schema -ne 1 -or
        [string]$guest.management_interface_alias -cne
            [string]$Manifest.management_adapter.guest_interface_alias -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $guest.management_interface_guid `
            -Label 'manifest guest management interface') -cne
            (ConvertTo-Ferrum2CanonicalGuid `
                -Value $Manifest.management_adapter.guest_interface_guid `
                -Label 'manifest management adapter guest interface') -or
        [int]$guest.management_interface_index -le 0 -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$guest.management_mac_address) `
            -Label 'manifest guest management interface') -cne $AdapterMacs.Management -or
        [string]$guest.support_interface_alias -cne [string]$Plan.support.guest_interface_alias -or
        [int]$guest.support_interface_index -le 0 -or
        [int]$guest.support_interface_index -eq [int]$guest.management_interface_index -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$guest.support_mac_address) `
            -Label 'manifest guest support interface') -cne $AdapterMacs.Support -or
        [string]$guest.guest_ipv4 -cne [string]$Plan.support.guest_ipv4 -or
        [int]$guest.prefix_length -ne [int]$Plan.support.prefix_length -or
        [string]$guest.network -cne [string]$Plan.support.network -or
        $null -ne $guest.gateway -or @($guest.dns_servers).Count -ne 0 -or
        [int]$guest.mtu_bytes -lt 1468 -or
        [string]$guest.selected_source_ipv4 -cne [string]$Plan.support.guest_ipv4 -or
        [string]$guest.selected_route_prefix -cne [string]$Plan.support.network -or
        [string]$guest.selected_route_next_hop -cne '0.0.0.0') {
        throw 'manifest guest support interface contract is invalid'
    }
    $null = ConvertTo-Ferrum2CanonicalGuid -Value $guest.support_interface_guid `
        -Label 'manifest guest support interface'
}

function Assert-Ferrum2ManifestIsolationContract {
    param([Parameter(Mandatory)] [object]$Manifest)

    if ($Manifest.protected_host_tun.present -isnot [bool] -or
        $Manifest.protected_host_tun.present -ne $true -or
        [string]$Manifest.protected_host_tun.name -cne 'tun0' -or
        [int]$Manifest.protected_host_tun.interface_index -le 0 -or
        [string]$Manifest.protected_host_tun.status -cne 'Up') {
        throw 'manifest protected host TUN contract is invalid'
    }
    $null = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.protected_host_tun.interface_guid -Label 'manifest protected host TUN'
    $constraints = $Manifest.constraints
    if ([string]$constraints.nat -cne 'absent' -or
        [string]$constraints.ics -cne 'absent' -or
        [string]$constraints.gateway -cne 'absent' -or
        [string]$constraints.dns -cne 'absent_on_support_interfaces' -or
        [string]$constraints.firewall_mutation -cne 'none' -or
        [string]$constraints.default_switch_mutation -cne 'none' -or
        [string]$constraints.host_tun_mutation -cne 'none') {
        throw 'manifest isolation constraints are invalid'
    }
}

function Assert-Ferrum2SupportTopologyManifestShape {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][object]$PlanDocument
    )

    $plan = $PlanDocument.Value
    Assert-Ferrum2SupportTopologyManifestProperties -Manifest $Manifest

    Assert-Ferrum2SupportTopologyManifestProvenance `
        -Manifest $Manifest -PlanDocument $PlanDocument
    Assert-Ferrum2ManifestVmCheckpointContract -Manifest $Manifest -Plan $plan

    $adapterMacs = Get-Ferrum2ManifestAdapterMacs -Manifest $Manifest -Plan $plan

    Assert-Ferrum2ManifestSupportSwitchContract -Manifest $Manifest -Plan $plan

    Assert-Ferrum2ManifestSupportVmAdapterContract -Manifest $Manifest -Plan $plan `
        -SupportMac $adapterMacs.Support

    Assert-Ferrum2ManifestGuestSupportContract -Manifest $Manifest -Plan $plan `
        -AdapterMacs $adapterMacs

    Assert-Ferrum2ManifestIsolationContract -Manifest $Manifest
}

function Read-Ferrum2SupportTopologyManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TopologyPlanPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $resolved = Resolve-Ferrum2HostInput -RepositoryRoot $RepositoryRoot -Path $Path `
        -Label 'support topology manifest' -Kind ExternalFile -MaximumBytes 131072
    $document = Read-Ferrum2JsonDocument -Path $resolved -MaximumBytes 131072 -SingleLine
    if ($document.Sha256 -cne $ExpectedSha256) {
        throw 'support topology manifest hash mismatch'
    }
    $planDocument = Read-Ferrum2SupportTopologyPlanDocument -Path $TopologyPlanPath
    Assert-Ferrum2SupportTopologyManifestShape -Manifest $document.Value `
        -PlanDocument $planDocument
    [pscustomobject][ordered]@{
        Path = [string]$document.Path
        Sha256 = [string]$document.Sha256
        Length = [long]$document.Length
        Value = $document.Value
        PlanDocument = $planDocument
    }
}

function Assert-Ferrum2SupportTopologyManifestUnchanged {
    param([Parameter(Mandatory = $true)][object]$Document)

    $item = Get-Item -LiteralPath ([string]$Document.Path) -Force -ErrorAction Stop
    if ($item.PSIsContainer -or [long]$item.Length -ne [long]$Document.Length -or
        (Get-Ferrum2LowerSha256 -Path ([string]$Document.Path)) -cne
            [string]$Document.Sha256) {
        throw "support topology manifest changed during the run"
    }
}

function Assert-Ferrum2SupportTopologySourceUnchanged {
    param([Parameter(Mandatory = $true)][object]$Document)

    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $Document
    $manifest = $Document.Value
    if ((Get-Ferrum2LowerSha256 -Path ([string]$Document.PlanDocument.Path)) -cne
            [string]$manifest.topology_plan_sha256) {
        throw "support topology source changed during the run"
    }
    $null = Get-Ferrum2ProvisioningSourceIdentity `
        -ExpectedManifestSha256 ([string]$manifest.provisioning_source_manifest_sha256) `
        -ExpectedBundleSha256 ([string]$manifest.provisioning_source_bundle_sha256)
}

function Assert-Ferrum2ObjectFieldsEqual {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][string]$Label
    )

    foreach ($field in $Fields) {
        if ([string]$Expected.$field -cne [string]$Actual.$field) {
            throw "$Label changed: field=$field"
        }
    }
}

function Get-Ferrum2ApprovedPinnedTopologyInventory {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan
    )

    $checkpointId = [Guid][string]$Manifest.lab_checkpoint.id
    $sourceCheckpointId = [Guid][string]$Manifest.source_checkpoint.id
    $supportSwitchId = [Guid][string]$Manifest.support.switch.switch_id
    $pinnedContext = Get-Ferrum2PinnedVmContext `
        -Identity (New-Ferrum2PinnedVmIdentity -Plan $Plan)
    $checkpoints = @(Get-VMSnapshot -VM $pinnedContext.Vm -ErrorAction Stop)
    $labCheckpoint = @($checkpoints | Where-Object { $_.Id -eq $checkpointId })
    $namedLabCheckpoint = @(
        Get-VMSnapshot -VM $pinnedContext.Vm `
            -Name ([string]$Manifest.lab_checkpoint.name) -ErrorAction Stop
    )
    if ($checkpoints.Count -ne 2 -or $labCheckpoint.Count -ne 1 -or
        $namedLabCheckpoint.Count -ne 1 -or
        $namedLabCheckpoint[0].Id -ne $checkpointId -or
        [string]$labCheckpoint[0].Name -cne [string]$Manifest.lab_checkpoint.name -or
        [string]$labCheckpoint[0].SnapshotType -cne [string]$Manifest.lab_checkpoint.type -or
        [Guid][string]$labCheckpoint[0].ParentCheckpointId -ne $sourceCheckpointId) {
        throw 'approved topology checkpoint inventory is invalid'
    }
    $switches = @(Get-VMSwitch -Id $supportSwitchId -ErrorAction Stop)
    $namedSwitches = @(Get-VMSwitch -Name ([string]$Manifest.support.switch.switch_name) `
        -ErrorAction Stop)
    if ($switches.Count -ne 1 -or $namedSwitches.Count -ne 1 -or
        $namedSwitches[0].Id -ne $supportSwitchId -or
        [string]$switches[0].Name -cne [string]$Manifest.support.switch.switch_name -or
        [string]$switches[0].SwitchType -cne 'Internal' -or
        $switches[0].AllowManagementOS -ne $true) {
        throw 'approved support switch identity is invalid'
    }
    [pscustomobject][ordered]@{
        Vm = $pinnedContext.Vm
        SourceCheckpoint = $pinnedContext.SourceCheckpoint
        Checkpoint = $labCheckpoint[0]
        SupportSwitch = $switches[0]
        SupportSwitchId = $supportSwitchId
    }
}

function Get-Ferrum2ApprovedLiveTopologyState {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [object]$Inventory,
        [Parameter(Mandatory)] [int]$ReadinessTimeoutSeconds
    )

    $state = [pscustomobject][ordered]@{
        Host = Get-ValidatedSupportHostState -Plan $Plan `
            -SwitchId $Inventory.SupportSwitchId -TimeoutSeconds $ReadinessTimeoutSeconds
        VmAdapter = Get-ValidatedSupportVmAdapter -Plan $Plan `
            -SupportSwitchId $Inventory.SupportSwitchId `
            -SupportAdapterId ([string]$Manifest.support.vm_adapter.id) `
            -VirtualSystemIdentifiers ([Guid[]]@(
                $Manifest.support.vm_adapter.virtual_system_identifiers | ForEach-Object {
                    [Guid][string]$_
                }
            ))
        Tun = Get-HostTunIdentity
    }
    Assert-Ferrum2ObjectFieldsEqual -Expected $Manifest.support.switch `
        -Actual $state.Host -Fields @(
            'switch_name', 'switch_id', 'switch_type', 'management_os_adapter_id',
            'management_os_device_id', 'host_interface_alias', 'host_interface_guid',
            'host_interface_index', 'host_mac_address', 'host_ipv4', 'prefix_length', 'network',
            'mtu_bytes', 'nat_enabled', 'ics_enabled', 'selected_source_ipv4',
            'selected_route_prefix', 'selected_route_next_hop'
        ) -Label 'approved support host topology'
    if ($null -ne $state.Host.gateway -or @($state.Host.dns_servers).Count -ne 0) {
        throw 'approved support host gateway or DNS state is invalid'
    }
    $liveSupportAdapter = [pscustomobject][ordered]@{
        name = [string]$state.VmAdapter.Name
        id = [string]$state.VmAdapter.Id
        switch_id = ConvertTo-Ferrum2CanonicalGuid -Value $state.VmAdapter.SwitchId `
            -Label 'live support adapter switch'
        mac_address = ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$state.VmAdapter.MacAddress) -Label 'live support VM adapter'
        dynamic_mac_address = [bool]$state.VmAdapter.DynamicMacAddressEnabled
    }
    Assert-Ferrum2ObjectFieldsEqual -Expected $Manifest.support.vm_adapter `
        -Actual $liveSupportAdapter `
        -Fields @('name', 'id', 'switch_id', 'mac_address', 'dynamic_mac_address') `
        -Label 'approved support VM adapter'
    $expectedIdentifiers = @($Manifest.support.vm_adapter.virtual_system_identifiers |
        ForEach-Object {
            ConvertTo-Ferrum2CanonicalGuid -Value $_ `
                -Label 'manifest support adapter identifier'
        } | Sort-Object)
    $actualIdentifiers = @($state.VmAdapter.VirtualSystemIdentifiers | ForEach-Object {
        ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label 'live support adapter identifier'
    } | Sort-Object)
    if (($actualIdentifiers -join '|') -cne ($expectedIdentifiers -join '|')) {
        throw 'approved support VM adapter identifiers changed'
    }
    $liveAdapters = @(Get-VMNetworkAdapter -VM $Inventory.Vm -ErrorAction Stop)
    $management = @($liveAdapters | Where-Object {
        [string]$_.Id -ceq [string]$Manifest.management_adapter.id
    })
    if ($liveAdapters.Count -ne 2 -or $management.Count -ne 1 -or
        $management[0].Connected -ne $true -or
        [string]$management[0].Name -cne [string]$Manifest.management_adapter.name -or
        [string]$management[0].SwitchName -cne [string]$Manifest.management_adapter.switch_name -or
        $management[0].SwitchId.ToString('D') -cne [string]$Manifest.management_adapter.switch_id -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$management[0].MacAddress) `
            -Label 'live management adapter') -cne
            [string]$Manifest.management_adapter.mac_address -or
        $management[0].DynamicMacAddressEnabled -ne $true) {
        throw 'approved live VM adapter inventory is invalid'
    }
    $state | Add-Member -NotePropertyName ManagementVmAdapter `
        -NotePropertyValue $management[0]
    $state | Add-Member -NotePropertyName ExpectedSupportIdentifiers `
        -NotePropertyValue $expectedIdentifiers
    $state
}

function Get-Ferrum2ApprovedSupportSnapshotReference {
    param([Parameter(Mandatory)] [Guid]$SupportSwitchId)

    $references = @(
        foreach ($snapshotVm in @(Get-VM -ErrorAction Stop)) {
            foreach ($snapshot in @(Get-VMSnapshot -VM $snapshotVm -ErrorAction Stop)) {
                foreach ($adapter in @(Get-VMNetworkAdapter -VMSnapshot $snapshot `
                        -ErrorAction Stop | Where-Object { $_.SwitchId -eq $SupportSwitchId })) {
                    [pscustomobject][ordered]@{ Snapshot = $snapshot; Adapter = $adapter }
                }
            }
        }
    )
    if ($references.Count -ne 1) {
        throw 'approved support switch snapshot attachment inventory is not unique'
    }
    $references[0]
}

function Assert-Ferrum2ApprovedSupportSnapshotAdapter {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [object]$Inventory,
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$SnapshotReference,
        [Parameter(Mandatory)] [object]$CheckpointSupport
    )

    $snapshotSupport = $SnapshotReference.Adapter
    $snapshotIdentifiers = @($snapshotSupport.VirtualSystemIdentifiers | ForEach-Object {
        ConvertTo-Ferrum2CanonicalGuid -Value $_ `
            -Label 'lab snapshot support adapter identifier'
    } | Sort-Object)
    $liveInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$State.VmAdapter.Id) `
        -ExpectedOwnerId ([string]$Manifest.vm.id) -Label 'live support VM adapter'
    $snapshotInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$snapshotSupport.Id) `
        -ExpectedOwnerId ([string]$Manifest.lab_checkpoint.id) `
        -Label 'lab snapshot support VM adapter'
    $labCheckpointGuid = [Guid][string]$Manifest.lab_checkpoint.id
    if ($SnapshotReference.Snapshot.Id -ne $labCheckpointGuid -or
        [string]$snapshotSupport.Id -cne
            [string]$Manifest.lab_checkpoint.support_vm_adapter_snapshot_id -or
        $snapshotSupport.VMId -ne [Guid][string]$Manifest.vm.id -or
        $snapshotSupport.VMSnapshotId -ne $labCheckpointGuid -or
        $snapshotSupport.VMCheckpointId -ne $labCheckpointGuid -or
        [string]$CheckpointSupport.Name -cne [string]$Plan.support.vm_adapter_name -or
        $CheckpointSupport.SwitchId -ne $Inventory.SupportSwitchId -or
        [string]$CheckpointSupport.SwitchName -cne [string]$Plan.support.switch_name -or
        $CheckpointSupport.DynamicMacAddressEnabled -ne $false -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$CheckpointSupport.MacAddress) `
            -Label 'lab checkpoint support adapter') -cne
            [string]$Manifest.support.vm_adapter.mac_address -or
        ($snapshotIdentifiers -join '|') -cne
            ($State.ExpectedSupportIdentifiers -join '|') -or
        $snapshotInstanceId -cne $liveInstanceId) {
        throw 'approved checkpoint support VM adapter inventory is invalid'
    }
}

function Assert-Ferrum2ApprovedManagementSnapshotAdapters {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$LabManagement,
        [Parameter(Mandatory)] [object]$SourceManagement
    )

    $liveInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$State.ManagementVmAdapter.Id) `
        -ExpectedOwnerId ([string]$Manifest.vm.id) -Label 'live management VM adapter'
    $labInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$LabManagement.Id) `
        -ExpectedOwnerId ([string]$Manifest.lab_checkpoint.id) `
        -Label 'lab snapshot management VM adapter'
    $sourceInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$SourceManagement.Id) `
        -ExpectedOwnerId ([string]$Manifest.source_checkpoint.id) `
        -Label 'source snapshot management VM adapter'
    $vmGuid = [Guid][string]$Manifest.vm.id
    $labGuid = [Guid][string]$Manifest.lab_checkpoint.id
    $sourceGuid = [Guid][string]$Manifest.source_checkpoint.id
    if ($LabManagement.VMId -ne $vmGuid -or
        $LabManagement.VMSnapshotId -ne $labGuid -or
        $LabManagement.VMCheckpointId -ne $labGuid -or
        [string]$LabManagement.Name -cne [string]$Manifest.management_adapter.name -or
        [string]$LabManagement.SwitchName -cne [string]$Manifest.management_adapter.switch_name -or
        $LabManagement.DynamicMacAddressEnabled -ne $true -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$LabManagement.MacAddress) `
            -Label 'lab checkpoint management adapter') -cne
            [string]$Manifest.management_adapter.mac_address -or
        $labInstanceId -cne $liveInstanceId -or
        $SourceManagement.VMId -ne $vmGuid -or
        $SourceManagement.VMSnapshotId -ne $sourceGuid -or
        $SourceManagement.VMCheckpointId -ne $sourceGuid -or
        [string]$SourceManagement.Name -cne [string]$Manifest.management_adapter.name -or
        $SourceManagement.SwitchId -ne [Guid][string]$Manifest.management_adapter.switch_id -or
        [string]$SourceManagement.SwitchName -cne
            [string]$Manifest.management_adapter.switch_name -or
        $SourceManagement.DynamicMacAddressEnabled -ne $true -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$SourceManagement.MacAddress) `
            -Label 'source checkpoint management adapter') -cne
            [string]$Manifest.management_adapter.mac_address -or
        $sourceInstanceId -cne $liveInstanceId) {
        throw 'approved checkpoint management VM adapter inventory is invalid'
    }
}

function Assert-Ferrum2ApprovedCheckpointAdapterInventory {
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [object]$Inventory,
        [Parameter(Mandatory)] [object]$State
    )

    $labAdapters = @(Get-VMNetworkAdapter -VMSnapshot $Inventory.Checkpoint `
        -ErrorAction Stop)
    $labSupport = @($labAdapters | Where-Object {
        [string]$_.Id -ceq [string]$Manifest.lab_checkpoint.support_vm_adapter_snapshot_id
    })
    $labManagement = @($labAdapters | Where-Object {
        $_.SwitchId -eq [Guid][string]$Manifest.management_adapter.switch_id
    })
    $sourceManagement = @(
        Get-VMNetworkAdapter -VMSnapshot $Inventory.SourceCheckpoint -ErrorAction Stop
    )
    if ($labAdapters.Count -ne 2 -or $labSupport.Count -ne 1 -or
        $labManagement.Count -ne 1 -or $sourceManagement.Count -ne 1) {
        throw 'approved checkpoint VM adapter counts are invalid'
    }
    $snapshotReference = Get-Ferrum2ApprovedSupportSnapshotReference `
        -SupportSwitchId $Inventory.SupportSwitchId
    Assert-Ferrum2ApprovedSupportSnapshotAdapter -Manifest $Manifest -Plan $Plan `
        -Inventory $Inventory -State $State -SnapshotReference $snapshotReference `
        -CheckpointSupport $labSupport[0]
    Assert-Ferrum2ApprovedManagementSnapshotAdapters -Manifest $Manifest -State $State `
        -LabManagement $labManagement[0] -SourceManagement $sourceManagement[0]
}

function Get-Ferrum2ApprovedHyperVTopologyContext {
    param(
        [Parameter(Mandatory = $true)][object]$Document,
        [ValidateRange(1, 60)][int]$ReadinessTimeoutSeconds = 10
    )

    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    $manifest = $Document.Value
    $plan = $Document.PlanDocument.Value
    $inventory = Get-Ferrum2ApprovedPinnedTopologyInventory `
        -Manifest $manifest -Plan $plan

    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    $runtimeState = Get-Ferrum2ApprovedLiveTopologyState -Manifest $manifest `
        -Plan $plan -Inventory $inventory `
        -ReadinessTimeoutSeconds $ReadinessTimeoutSeconds

    Assert-Ferrum2ApprovedCheckpointAdapterInventory -Manifest $manifest -Plan $plan `
        -Inventory $inventory -State $runtimeState

    Assert-Ferrum2ObjectFieldsEqual -Expected $manifest.protected_host_tun `
        -Actual $runtimeState.Tun -Fields @(
            "present", "name", "interface_guid", "interface_index", "status"
        ) -Label "protected host TUN"
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    return [pscustomobject][ordered]@{
        Vm = $inventory.Vm
        SourceCheckpoint = $inventory.SourceCheckpoint
        Checkpoint = $inventory.Checkpoint
        SupportSwitch = $inventory.SupportSwitch
        SupportHost = $runtimeState.Host
        SupportVmAdapter = $runtimeState.VmAdapter
        ManagementVmAdapter = $runtimeState.ManagementVmAdapter
        ProtectedHostTun = $runtimeState.Tun
    }
}
