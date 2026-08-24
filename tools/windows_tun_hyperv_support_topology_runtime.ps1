#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines read-only runtime checks for the provisioned Windows TUN Hyper-V support topology.

.DESCRIPTION
This dot-source-only library validates the external provisioning manifest, binds its generated
switch, adapter, and checkpoint identities to the repository topology plan, and validates the live
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

$ferrum2TopologyInspectorPath = Join-Path $PSScriptRoot `
    "inspect_windows_tun_hyperv_support_topology.ps1"
$ferrum2TopologyProvisioningLibraryPath = Join-Path $PSScriptRoot `
    "windows_tun_hyperv_support_topology_provisioning.ps1"
$ferrum2TopologyProvisioningDriverPath = Join-Path $PSScriptRoot `
    "provision_windows_tun_hyperv_support_topology.ps1"

if (-not $LibraryOnly) {
    throw "support topology runtime helpers are dot-source-only"
}

function Get-Ferrum2ExactFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Test-Ferrum2PathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-Ferrum2NoReparsePointInExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use a rooted filesystem path"
    }
    $current = $root
    foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object {
        $_.Length -gt 0
    })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function ConvertTo-Ferrum2CanonicalGuid {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$Value, [ref]$parsed) -or $parsed -eq [Guid]::Empty) {
        throw "$Label GUID is invalid"
    }
    return $parsed.ToString("D")
}

function ConvertTo-Ferrum2CanonicalMacAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $canonical = ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($canonical -cnotmatch '^[0-9A-F]{12}$' -or $canonical -ceq "000000000000") {
        throw "$Label MAC address is invalid"
    }
    return $canonical
}

function Assert-Ferrum2ExactPropertySet {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ((@($Value.PSObject.Properties.Name) -join "|") -cne ($Expected -join "|")) {
        throw "$Label property set or order is invalid"
    }
}

function Assert-Ferrum2NoDuplicateJsonProperty {
    param([Parameter(Mandatory = $true)][string]$Json)

    function Test-Ferrum2JsonElement {
        param(
            [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
            [Parameter(Mandatory = $true)][string]$Path
        )

        if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name)) {
                    throw "support topology manifest has a duplicate JSON property at $Path"
                }
                Test-Ferrum2JsonElement -Element $property.Value `
                    -Path "$Path.$($property.Name)"
            }
        } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
            $index = 0
            foreach ($item in $Element.EnumerateArray()) {
                Test-Ferrum2JsonElement -Element $item -Path "$Path[$index]"
                $index += 1
            }
        }
    }

    $document = [Text.Json.JsonDocument]::Parse($Json)
    try {
        Test-Ferrum2JsonElement -Element $document.RootElement -Path '$'
    } finally {
        $document.Dispose()
    }
}

function Read-Ferrum2SupportTopologyPlanDocument {
    foreach ($path in @(
        $script:ferrum2TopologyInspectorPath,
        $script:ferrum2TopologyProvisioningLibraryPath,
        $script:ferrum2TopologyProvisioningDriverPath
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "support topology source is missing: $path"
        }
    }
    $module = New-Module -Name (
        "Ferrum2SupportTopologyPlan_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $script:ferrum2TopologyInspectorPath -ScriptBlock {
        param([string]$InspectorPath)
        . $InspectorPath -LibraryOnly
        Export-ModuleMember -Function "Read-TopologyPlan"
    }
    try {
        return & $module { Read-TopologyPlan }
    } finally {
        Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
    }
}

function Get-Ferrum2VmAdapterInstanceGuid {
    param(
        [Parameter(Mandatory = $true)][string]$AdapterId,
        [Parameter(Mandatory = $true)][string]$ExpectedOwnerId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parts = $AdapterId.Split('\')
    $owner = ConvertTo-Ferrum2CanonicalGuid -Value $ExpectedOwnerId -Label "$Label owner"
    if ($parts.Count -ne 2 -or
        [string]$parts[0] -cne ("Microsoft:" + $owner.ToUpperInvariant())) {
        throw "$Label adapter ID owner is invalid"
    }
    return ConvertTo-Ferrum2CanonicalGuid -Value $parts[1] -Label "$Label instance"
}

function Assert-Ferrum2SupportTopologyManifestShape {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][object]$PlanDocument
    )

    $plan = $PlanDocument.Value
    Assert-Ferrum2ExactPropertySet -Value $Manifest -Expected @(
        "schema", "created_utc", "topology_plan_sha256", "inspector_sha256",
        "provisioning_library_sha256", "provisioning_script_sha256", "vm",
        "source_checkpoint", "qualification_checkpoint", "management_adapter", "support",
        "protected_host_tun", "constraints"
    ) -Label "support topology manifest"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.vm -Expected @(
        "name", "id", "terminal_state", "automatic_checkpoints_enabled"
    ) -Label "manifest VM"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.source_checkpoint -Expected @(
        "name", "id", "type"
    ) -Label "manifest source checkpoint"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.qualification_checkpoint -Expected @(
        "name", "id", "type", "parent_id", "support_vm_adapter_snapshot_id",
        "restore_verified"
    ) -Label "manifest qualification checkpoint"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.management_adapter -Expected @(
        "name", "id", "switch_name", "switch_id", "mac_address",
        "dynamic_mac_address", "guest_interface_alias", "guest_interface_guid"
    ) -Label "manifest management adapter"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.support -Expected @(
        "switch", "vm_adapter", "guest"
    ) -Label "manifest support topology"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.support.switch -Expected @(
        "switch_name", "switch_id", "switch_type", "management_os_adapter_id",
        "management_os_device_id", "host_interface_alias", "host_interface_guid",
        "host_interface_index", "host_mac_address", "host_ipv4", "prefix_length", "network",
        "gateway", "dns_servers", "mtu_bytes", "nat_enabled", "ics_enabled",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) -Label "manifest support switch"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.support.vm_adapter -Expected @(
        "name", "id", "switch_id", "mac_address", "dynamic_mac_address",
        "virtual_system_identifiers"
    ) -Label "manifest support VM adapter"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.support.guest -Expected @(
        "schema", "management_interface_alias", "management_interface_guid",
        "management_interface_index", "management_mac_address", "support_interface_alias",
        "support_interface_guid", "support_interface_index", "support_mac_address", "guest_ipv4",
        "prefix_length", "network", "gateway", "dns_servers", "mtu_bytes",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) -Label "manifest guest support topology"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.protected_host_tun -Expected @(
        "present", "name", "interface_guid", "interface_index", "status"
    ) -Label "manifest protected host TUN"
    Assert-Ferrum2ExactPropertySet -Value $Manifest.constraints -Expected @(
        "nat", "ics", "gateway", "dns", "firewall_mutation", "default_switch_mutation",
        "host_tun_mutation"
    ) -Label "manifest constraints"

    foreach ($hashName in @(
        "topology_plan_sha256", "inspector_sha256", "provisioning_library_sha256",
        "provisioning_script_sha256"
    )) {
        if ($Manifest.$hashName -isnot [string] -or
            [string]$Manifest.$hashName -cnotmatch '^[0-9a-f]{64}$') {
            throw "manifest $hashName is invalid"
        }
    }
    if ($Manifest.schema -isnot [long] -or [long]$Manifest.schema -ne 1 -or
        $Manifest.created_utc -isnot [DateTime] -or
        [DateTime]$Manifest.created_utc -gt [DateTime]::UtcNow.AddMinutes(5) -or
        [string]$Manifest.topology_plan_sha256 -cne [string]$PlanDocument.Sha256 -or
        [string]$Manifest.inspector_sha256 -cne
            (Get-Ferrum2ExactFileSha256 -Path $script:ferrum2TopologyInspectorPath) -or
        [string]$Manifest.provisioning_library_sha256 -cne
            (Get-Ferrum2ExactFileSha256 -Path $script:ferrum2TopologyProvisioningLibraryPath) -or
        [string]$Manifest.provisioning_script_sha256 -cne
            (Get-Ferrum2ExactFileSha256 -Path $script:ferrum2TopologyProvisioningDriverPath)) {
        throw "support topology manifest provenance is invalid"
    }

    $vmId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.vm.id -Label "manifest VM"
    $sourceId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.source_checkpoint.id `
        -Label "manifest source checkpoint"
    $checkpointId = ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.qualification_checkpoint.id `
        -Label "manifest qualification checkpoint"
    $parentId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.qualification_checkpoint.parent_id `
        -Label "manifest qualification checkpoint parent"
    $supportSwitchId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.support.switch.switch_id -Label "manifest support switch"
    $supportAdapterSwitchId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.support.vm_adapter.switch_id -Label "manifest support adapter switch"
    $supportSnapshotOwner = $Manifest.qualification_checkpoint.support_vm_adapter_snapshot_id.
        Split('\')[0]
    if ($vmId -cne (ConvertTo-Ferrum2CanonicalGuid -Value $plan.vm.id -Label "planned VM") -or
        [string]$Manifest.vm.name -cne [string]$plan.vm.name -or
        [string]$Manifest.vm.terminal_state -cne "Off" -or
        $Manifest.vm.automatic_checkpoints_enabled -isnot [bool] -or
        $Manifest.vm.automatic_checkpoints_enabled -ne $false -or
        $sourceId -cne (ConvertTo-Ferrum2CanonicalGuid -Value $plan.source_checkpoint.id `
            -Label "planned source checkpoint") -or
        [string]$Manifest.source_checkpoint.name -cne [string]$plan.source_checkpoint.name -or
        [string]$Manifest.source_checkpoint.type -cne [string]$plan.source_checkpoint.type -or
        $checkpointId -ceq $sourceId -or $parentId -cne $sourceId -or
        [string]$Manifest.qualification_checkpoint.name -cne
            [string]$plan.qualification_checkpoint.name -or
        [string]$Manifest.qualification_checkpoint.type -cne
            [string]$plan.qualification_checkpoint.type -or
        $Manifest.qualification_checkpoint.restore_verified -isnot [bool] -or
        $Manifest.qualification_checkpoint.restore_verified -ne $true -or
        $supportSnapshotOwner -cne ("Microsoft:" + $checkpointId.ToUpperInvariant())) {
        throw "manifest VM or checkpoint contract is invalid"
    }
    $null = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$Manifest.qualification_checkpoint.support_vm_adapter_snapshot_id) `
        -ExpectedOwnerId $checkpointId -Label "manifest qualification support snapshot"

    $managementMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Manifest.management_adapter.mac_address) `
        -Label "manifest management adapter"
    $supportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Manifest.support.vm_adapter.mac_address) `
        -Label "manifest support VM adapter"
    if ([string]$Manifest.management_adapter.name -cne [string]$plan.management_adapter.name -or
        [string]$Manifest.management_adapter.id -cne [string]$plan.management_adapter.id -or
        [string]$Manifest.management_adapter.switch_name -cne
            [string]$plan.management_adapter.switch_name -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $Manifest.management_adapter.switch_id `
            -Label "manifest management switch") -cne
            (ConvertTo-Ferrum2CanonicalGuid -Value $plan.management_adapter.switch_id `
                -Label "planned management switch") -or
        $managementMac -cne (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$plan.management_adapter.mac_address) -Label "planned management") -or
        $Manifest.management_adapter.dynamic_mac_address -isnot [bool] -or
        $Manifest.management_adapter.dynamic_mac_address -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$Manifest.management_adapter.guest_interface_alias)) {
        throw "manifest management adapter contract is invalid"
    }
    $null = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.management_adapter.guest_interface_guid `
        -Label "manifest guest management interface"

    $switch = $Manifest.support.switch
    if ([string]$switch.switch_name -cne [string]$plan.support.switch_name -or
        [string]$switch.switch_type -cne "Internal" -or
        $supportSwitchId -cne $supportAdapterSwitchId -or
        [string]$switch.host_ipv4 -cne [string]$plan.support.host_ipv4 -or
        [int]$switch.prefix_length -ne [int]$plan.support.prefix_length -or
        [string]$switch.network -cne [string]$plan.support.network -or
        $null -ne $switch.gateway -or @($switch.dns_servers).Count -ne 0 -or
        [int]$switch.host_interface_index -le 0 -or [int]$switch.mtu_bytes -lt 1468 -or
        $switch.nat_enabled -isnot [bool] -or $switch.nat_enabled -ne $false -or
        $switch.ics_enabled -isnot [bool] -or $switch.ics_enabled -ne $false -or
        [string]$switch.selected_source_ipv4 -cne [string]$plan.support.host_ipv4 -or
        [string]$switch.selected_route_prefix -cne [string]$plan.support.network -or
        [string]$switch.selected_route_next_hop -cne "0.0.0.0") {
        throw "manifest support switch contract is invalid"
    }
    $hostInterfaceGuid = ConvertTo-Ferrum2CanonicalGuid `
        -Value $switch.host_interface_guid -Label "manifest host support interface"
    if ((ConvertTo-Ferrum2CanonicalGuid -Value $switch.management_os_device_id `
            -Label "manifest support management OS device") -cne $hostInterfaceGuid -or
        [string]::IsNullOrWhiteSpace([string]$switch.management_os_adapter_id)) {
        throw "manifest host support adapter identity is invalid"
    }
    $null = ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$switch.host_mac_address) `
        -Label "manifest host support interface"

    $vmAdapter = $Manifest.support.vm_adapter
    $identifiers = @($vmAdapter.virtual_system_identifiers | ForEach-Object {
        ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label "manifest support adapter identifier"
    })
    if ([string]$vmAdapter.name -cne [string]$plan.support.vm_adapter_name -or
        $supportMac -cne (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$plan.support.vm_mac_address) -Label "planned support adapter") -or
        $vmAdapter.dynamic_mac_address -isnot [bool] -or
        $vmAdapter.dynamic_mac_address -ne $false -or $identifiers.Count -ne 2 -or
        @($identifiers | Sort-Object -Unique).Count -ne 2) {
        throw "manifest support VM adapter contract is invalid"
    }
    $null = Get-Ferrum2VmAdapterInstanceGuid -AdapterId ([string]$vmAdapter.id) `
        -ExpectedOwnerId $vmId -Label "manifest support VM adapter"

    $guest = $Manifest.support.guest
    if ($guest.schema -isnot [long] -or [long]$guest.schema -ne 1 -or
        [string]$guest.management_interface_alias -cne
            [string]$Manifest.management_adapter.guest_interface_alias -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $guest.management_interface_guid `
            -Label "manifest guest management interface") -cne
            (ConvertTo-Ferrum2CanonicalGuid `
                -Value $Manifest.management_adapter.guest_interface_guid `
                -Label "manifest management adapter guest interface") -or
        [int]$guest.management_interface_index -le 0 -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$guest.management_mac_address) `
            -Label "manifest guest management interface") -cne $managementMac -or
        [string]$guest.support_interface_alias -cne [string]$plan.support.guest_interface_alias -or
        [int]$guest.support_interface_index -le 0 -or
        [int]$guest.support_interface_index -eq [int]$guest.management_interface_index -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$guest.support_mac_address) `
            -Label "manifest guest support interface") -cne $supportMac -or
        [string]$guest.guest_ipv4 -cne [string]$plan.support.guest_ipv4 -or
        [int]$guest.prefix_length -ne [int]$plan.support.prefix_length -or
        [string]$guest.network -cne [string]$plan.support.network -or
        $null -ne $guest.gateway -or @($guest.dns_servers).Count -ne 0 -or
        [int]$guest.mtu_bytes -lt 1468 -or
        [string]$guest.selected_source_ipv4 -cne [string]$plan.support.guest_ipv4 -or
        [string]$guest.selected_route_prefix -cne [string]$plan.support.network -or
        [string]$guest.selected_route_next_hop -cne "0.0.0.0") {
        throw "manifest guest support interface contract is invalid"
    }
    $null = ConvertTo-Ferrum2CanonicalGuid -Value $guest.support_interface_guid `
        -Label "manifest guest support interface"

    if ($Manifest.protected_host_tun.present -isnot [bool] -or
        $Manifest.protected_host_tun.present -ne $true -or
        [string]$Manifest.protected_host_tun.name -cne "tun0" -or
        [int]$Manifest.protected_host_tun.interface_index -le 0 -or
        [string]$Manifest.protected_host_tun.status -cne "Up") {
        throw "manifest protected host TUN contract is invalid"
    }
    $null = ConvertTo-Ferrum2CanonicalGuid `
        -Value $Manifest.protected_host_tun.interface_guid -Label "manifest protected host TUN"

    $constraints = $Manifest.constraints
    if ([string]$constraints.nat -cne "absent" -or
        [string]$constraints.ics -cne "absent" -or
        [string]$constraints.gateway -cne "absent" -or
        [string]$constraints.dns -cne "absent_on_support_interfaces" -or
        [string]$constraints.firewall_mutation -cne "none" -or
        [string]$constraints.default_switch_mutation -cne "none" -or
        [string]$constraints.host_tun_mutation -cne "none") {
        throw "manifest isolation constraints are invalid"
    }
}

function Read-Ferrum2SupportTopologyManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "support topology manifest path must be absolute"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-Ferrum2NoReparsePointInExistingPath -Path $resolved `
        -Label "support topology manifest"
    if (Test-Ferrum2PathWithinRoot -Path $resolved -Root $RepositoryRoot) {
        throw "support topology manifest must remain outside the repository"
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -lt 2 -or $item.Length -gt 131072) {
        throw "support topology manifest file boundary is invalid"
    }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    $actualSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($actualSha256 -cne $ExpectedSha256) {
        throw "support topology manifest hash mismatch"
    }
    if ($bytes[-1] -ne 10 -or @($bytes | Where-Object { $_ -eq 10 }).Count -ne 1 -or
        @($bytes | Where-Object { $_ -eq 13 }).Count -ne 0 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and
            $bytes[2] -eq 0xbf)) {
        throw "support topology manifest must be one BOM-free LF-terminated UTF-8 document"
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-Ferrum2NoDuplicateJsonProperty -Json $json
    $manifest = $json | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    $planDocument = Read-Ferrum2SupportTopologyPlanDocument
    Assert-Ferrum2SupportTopologyManifestShape -Manifest $manifest `
        -PlanDocument $planDocument
    return [pscustomobject][ordered]@{
        Path = $resolved
        Sha256 = $actualSha256
        Length = [long]$bytes.Length
        Value = $manifest
        PlanDocument = $planDocument
    }
}

function Assert-Ferrum2SupportTopologyManifestUnchanged {
    param([Parameter(Mandatory = $true)][object]$Document)

    $item = Get-Item -LiteralPath ([string]$Document.Path) -Force -ErrorAction Stop
    if ($item.PSIsContainer -or [long]$item.Length -ne [long]$Document.Length -or
        (Get-Ferrum2ExactFileSha256 -Path ([string]$Document.Path)) -cne
            [string]$Document.Sha256) {
        throw "support topology manifest changed during the run"
    }
}

function Assert-Ferrum2SupportTopologySourceUnchanged {
    param([Parameter(Mandatory = $true)][object]$Document)

    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $Document
    $manifest = $Document.Value
    if ((Get-Ferrum2ExactFileSha256 -Path ([string]$Document.PlanDocument.Path)) -cne
            [string]$manifest.topology_plan_sha256 -or
        (Get-Ferrum2ExactFileSha256 -Path $script:ferrum2TopologyInspectorPath) -cne
            [string]$manifest.inspector_sha256 -or
        (Get-Ferrum2ExactFileSha256 `
            -Path $script:ferrum2TopologyProvisioningLibraryPath) -cne
            [string]$manifest.provisioning_library_sha256 -or
        (Get-Ferrum2ExactFileSha256 `
            -Path $script:ferrum2TopologyProvisioningDriverPath) -cne
            [string]$manifest.provisioning_script_sha256) {
        throw "support topology source changed during the run"
    }
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

function Get-Ferrum2ApprovedHyperVTopologyContext {
    param(
        [Parameter(Mandatory = $true)][object]$Document,
        [ValidateRange(1, 60)][int]$ReadinessTimeoutSeconds = 10
    )

    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    $manifest = $Document.Value
    $plan = $Document.PlanDocument.Value
    $vmId = [Guid][string]$manifest.vm.id
    $checkpointId = [Guid][string]$manifest.qualification_checkpoint.id
    $sourceCheckpointId = [Guid][string]$manifest.source_checkpoint.id
    $supportSwitchId = [Guid][string]$manifest.support.switch.switch_id

    $vm = Get-VM -Id $vmId -ErrorAction Stop
    $namedVm = @(Get-VM -Name ([string]$manifest.vm.name) -ErrorAction Stop)
    if ([string]$vm.Name -cne [string]$manifest.vm.name -or
        $namedVm.Count -ne 1 -or $namedVm[0].Id -ne $vmId -or
        $vm.AutomaticCheckpointsEnabled -ne $false) {
        throw "approved topology VM identity is invalid"
    }
    $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $source = @($checkpoints | Where-Object { $_.Id -eq $sourceCheckpointId })
    $qualification = @($checkpoints | Where-Object { $_.Id -eq $checkpointId })
    $namedQualification = @(
        Get-VMSnapshot -VM $vm -Name ([string]$manifest.qualification_checkpoint.name) `
            -ErrorAction Stop
    )
    if ($checkpoints.Count -ne 2 -or $source.Count -ne 1 -or
        [string]$source[0].Name -cne [string]$manifest.source_checkpoint.name -or
        [string]$source[0].SnapshotType -cne [string]$manifest.source_checkpoint.type -or
        $qualification.Count -ne 1 -or $namedQualification.Count -ne 1 -or
        $namedQualification[0].Id -ne $checkpointId -or
        [string]$qualification[0].Name -cne [string]$manifest.qualification_checkpoint.name -or
        [string]$qualification[0].SnapshotType -cne
            [string]$manifest.qualification_checkpoint.type -or
        [Guid][string]$qualification[0].ParentCheckpointId -ne $sourceCheckpointId) {
        throw "approved topology checkpoint inventory is invalid"
    }

    $switches = @(Get-VMSwitch -Id $supportSwitchId -ErrorAction Stop)
    $namedSwitches = @(Get-VMSwitch -Name ([string]$manifest.support.switch.switch_name) `
        -ErrorAction Stop)
    if ($switches.Count -ne 1 -or $namedSwitches.Count -ne 1 -or
        $namedSwitches[0].Id -ne $supportSwitchId -or
        [string]$switches[0].Name -cne [string]$manifest.support.switch.switch_name -or
        [string]$switches[0].SwitchType -cne "Internal" -or
        $switches[0].AllowManagementOS -ne $true) {
        throw "approved support switch identity is invalid"
    }

    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    $runtimeModule = New-Module -Name (
        "Ferrum2SupportTopologyRuntime_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList @(
        $script:ferrum2TopologyProvisioningLibraryPath,
        [string]$manifest.provisioning_library_sha256
    ) -ScriptBlock {
        param([string]$LibraryPath, [string]$ExpectedLibrarySha256)
        if ((Get-FileHash -LiteralPath $LibraryPath -Algorithm SHA256).Hash.
                ToLowerInvariant() -cne $ExpectedLibrarySha256) {
            throw "support topology provisioning library changed before loading"
        }
        . $LibraryPath -LibraryOnly
        if ((Get-FileHash -LiteralPath $LibraryPath -Algorithm SHA256).Hash.
                ToLowerInvariant() -cne $ExpectedLibrarySha256) {
            throw "support topology provisioning library changed while loading"
        }
        Export-ModuleMember -Function @(
            "Get-ValidatedSupportHostState",
            "Get-ValidatedSupportVmAdapter",
            "Get-HostTunIdentity"
        )
    }
    try {
        $runtimeState = & $runtimeModule {
            param(
                [object]$Plan,
                [Guid]$SwitchId,
                [string]$AdapterId,
                [Guid[]]$VirtualSystemIdentifiers,
                [int]$TimeoutSeconds
            )
            [pscustomobject][ordered]@{
                Host = Get-ValidatedSupportHostState -Plan $Plan -SwitchId $SwitchId `
                    -TimeoutSeconds $TimeoutSeconds
                VmAdapter = Get-ValidatedSupportVmAdapter -Plan $Plan `
                    -SupportSwitchId $SwitchId -SupportAdapterId $AdapterId `
                    -VirtualSystemIdentifiers $VirtualSystemIdentifiers
                Tun = Get-HostTunIdentity
            }
        } $plan $supportSwitchId ([string]$manifest.support.vm_adapter.id) `
            ([Guid[]]@($manifest.support.vm_adapter.virtual_system_identifiers | ForEach-Object {
                [Guid][string]$_
            })) $ReadinessTimeoutSeconds
    } finally {
        Remove-Module -ModuleInfo $runtimeModule -Force -ErrorAction SilentlyContinue
    }

    Assert-Ferrum2ObjectFieldsEqual -Expected $manifest.support.switch `
        -Actual $runtimeState.Host -Fields @(
            "switch_name", "switch_id", "switch_type", "management_os_adapter_id",
            "management_os_device_id", "host_interface_alias", "host_interface_guid",
            "host_interface_index", "host_mac_address", "host_ipv4", "prefix_length", "network",
            "mtu_bytes", "nat_enabled", "ics_enabled", "selected_source_ipv4",
            "selected_route_prefix", "selected_route_next_hop"
        ) -Label "approved support host topology"
    if ($null -ne $runtimeState.Host.gateway -or
        @($runtimeState.Host.dns_servers).Count -ne 0) {
        throw "approved support host gateway or DNS state is invalid"
    }
    $liveSupportAdapter = [pscustomobject][ordered]@{
        name = [string]$runtimeState.VmAdapter.Name
        id = [string]$runtimeState.VmAdapter.Id
        switch_id = (ConvertTo-Ferrum2CanonicalGuid `
            -Value $runtimeState.VmAdapter.SwitchId -Label "live support adapter switch")
        mac_address = (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$runtimeState.VmAdapter.MacAddress) `
            -Label "live support VM adapter")
        dynamic_mac_address = [bool]$runtimeState.VmAdapter.DynamicMacAddressEnabled
    }
    Assert-Ferrum2ObjectFieldsEqual -Expected $manifest.support.vm_adapter `
        -Actual $liveSupportAdapter -Fields @(
            "name", "id", "switch_id", "mac_address", "dynamic_mac_address"
        ) -Label "approved support VM adapter"
    $actualIdentifiers = @($runtimeState.VmAdapter.VirtualSystemIdentifiers | ForEach-Object {
        (ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label "live support adapter identifier")
    } | Sort-Object)
    $expectedIdentifiers = @($manifest.support.vm_adapter.virtual_system_identifiers |
        ForEach-Object {
            ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label "manifest support adapter identifier"
        } | Sort-Object)
    if (($actualIdentifiers -join "|") -cne ($expectedIdentifiers -join "|")) {
        throw "approved support VM adapter identifiers changed"
    }

    $liveAdapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    $management = @($liveAdapters | Where-Object {
        [string]$_.Id -ceq [string]$manifest.management_adapter.id
    })
    if ($liveAdapters.Count -ne 2 -or $management.Count -ne 1 -or
        $management[0].Connected -ne $true -or
        [string]$management[0].Name -cne [string]$manifest.management_adapter.name -or
        [string]$management[0].SwitchName -cne [string]$manifest.management_adapter.switch_name -or
        $management[0].SwitchId.ToString("D") -cne [string]$manifest.management_adapter.switch_id -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$management[0].MacAddress) `
            -Label "live management adapter") -cne
            [string]$manifest.management_adapter.mac_address -or
        $management[0].DynamicMacAddressEnabled -ne $true) {
        throw "approved live VM adapter inventory is invalid"
    }

    $qualificationAdapters = @(Get-VMNetworkAdapter -VMSnapshot $qualification[0] `
        -ErrorAction Stop)
    $qualificationSupport = @($qualificationAdapters | Where-Object {
        [string]$_.Id -ceq
            [string]$manifest.qualification_checkpoint.support_vm_adapter_snapshot_id
    })
    $qualificationManagement = @($qualificationAdapters | Where-Object {
        $_.SwitchId -eq [Guid][string]$manifest.management_adapter.switch_id
    })
    $sourceAdapters = @(Get-VMNetworkAdapter -VMSnapshot $source[0] -ErrorAction Stop)
    $supportSnapshotReferences = @(
        foreach ($snapshotVm in @(Get-VM -ErrorAction Stop)) {
            foreach ($snapshot in @(Get-VMSnapshot -VM $snapshotVm -ErrorAction Stop)) {
                foreach ($snapshotAdapter in @(Get-VMNetworkAdapter `
                        -VMSnapshot $snapshot -ErrorAction Stop | Where-Object {
                            $_.SwitchId -eq $supportSwitchId
                        })) {
                    [pscustomobject][ordered]@{
                        Snapshot = $snapshot
                        Adapter = $snapshotAdapter
                    }
                }
            }
        }
    )
    if ($supportSnapshotReferences.Count -ne 1) {
        throw "approved support switch snapshot attachment inventory is not unique"
    }
    $snapshotSupport = $supportSnapshotReferences[0].Adapter
    $snapshotSupportIdentifiers = @(
        $snapshotSupport.VirtualSystemIdentifiers | ForEach-Object {
            ConvertTo-Ferrum2CanonicalGuid -Value $_ `
                -Label "qualification snapshot support adapter identifier"
        } | Sort-Object
    )
    $liveSupportInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$runtimeState.VmAdapter.Id) `
        -ExpectedOwnerId ([string]$manifest.vm.id) -Label "live support VM adapter"
    $snapshotSupportInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$snapshotSupport.Id) `
        -ExpectedOwnerId ([string]$manifest.qualification_checkpoint.id) `
        -Label "qualification snapshot support VM adapter"
    $liveManagementInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$management[0].Id) `
        -ExpectedOwnerId ([string]$manifest.vm.id) -Label "live management VM adapter"
    $sourceManagementInstanceId = if ($sourceAdapters.Count -eq 1) {
        Get-Ferrum2VmAdapterInstanceGuid -AdapterId ([string]$sourceAdapters[0].Id) `
            -ExpectedOwnerId ([string]$manifest.source_checkpoint.id) `
            -Label "source snapshot management VM adapter"
    } else {
        ""
    }
    $qualificationManagementInstanceId = if ($qualificationManagement.Count -eq 1) {
        Get-Ferrum2VmAdapterInstanceGuid `
            -AdapterId ([string]$qualificationManagement[0].Id) `
            -ExpectedOwnerId ([string]$manifest.qualification_checkpoint.id) `
            -Label "qualification snapshot management VM adapter"
    } else {
        ""
    }
    $approvedVmGuid = [Guid][string]$manifest.vm.id
    $sourceCheckpointGuid = [Guid][string]$manifest.source_checkpoint.id
    $qualificationCheckpointGuid = [Guid][string]$manifest.qualification_checkpoint.id
    if ($qualificationAdapters.Count -ne 2 -or $qualificationSupport.Count -ne 1 -or
        $qualificationManagement.Count -ne 1 -or
        $supportSnapshotReferences[0].Snapshot.Id -ne $qualificationCheckpointGuid -or
        [string]$snapshotSupport.Id -cne
            [string]$manifest.qualification_checkpoint.support_vm_adapter_snapshot_id -or
        $snapshotSupport.VMId -ne $approvedVmGuid -or
        $snapshotSupport.VMSnapshotId -ne $qualificationCheckpointGuid -or
        $snapshotSupport.VMCheckpointId -ne $qualificationCheckpointGuid -or
        [string]$qualificationSupport[0].Name -cne [string]$plan.support.vm_adapter_name -or
        $qualificationSupport[0].SwitchId -ne $supportSwitchId -or
        [string]$qualificationSupport[0].SwitchName -cne [string]$plan.support.switch_name -or
        $qualificationSupport[0].DynamicMacAddressEnabled -ne $false -or
        (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$qualificationSupport[0].MacAddress) `
            -Label "qualification support adapter") -cne
            [string]$manifest.support.vm_adapter.mac_address -or
        ($snapshotSupportIdentifiers -join "|") -cne ($expectedIdentifiers -join "|") -or
        $snapshotSupportInstanceId -cne $liveSupportInstanceId -or
        $qualificationManagement[0].VMId -ne $approvedVmGuid -or
        $qualificationManagement[0].VMSnapshotId -ne $qualificationCheckpointGuid -or
        $qualificationManagement[0].VMCheckpointId -ne $qualificationCheckpointGuid -or
        [string]$qualificationManagement[0].Name -cne
            [string]$manifest.management_adapter.name -or
        [string]$qualificationManagement[0].SwitchName -cne
            [string]$manifest.management_adapter.switch_name -or
        $qualificationManagement[0].DynamicMacAddressEnabled -ne $true -or
        (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$qualificationManagement[0].MacAddress) `
            -Label "qualification management adapter") -cne
            [string]$manifest.management_adapter.mac_address -or
        $qualificationManagementInstanceId -cne $liveManagementInstanceId -or
        $sourceAdapters.Count -ne 1 -or
        $sourceAdapters[0].VMId -ne $approvedVmGuid -or
        $sourceAdapters[0].VMSnapshotId -ne $sourceCheckpointGuid -or
        $sourceAdapters[0].VMCheckpointId -ne $sourceCheckpointGuid -or
        [string]$sourceAdapters[0].Name -cne [string]$manifest.management_adapter.name -or
        $sourceAdapters[0].SwitchId -ne [Guid][string]$manifest.management_adapter.switch_id -or
        [string]$sourceAdapters[0].SwitchName -cne
            [string]$manifest.management_adapter.switch_name -or
        $sourceAdapters[0].DynamicMacAddressEnabled -ne $true -or
        (ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$sourceAdapters[0].MacAddress) `
            -Label "source checkpoint management adapter") -cne
            [string]$manifest.management_adapter.mac_address -or
        $sourceManagementInstanceId -cne $liveManagementInstanceId) {
        throw "approved checkpoint VM adapter inventory is invalid"
    }

    Assert-Ferrum2ObjectFieldsEqual -Expected $manifest.protected_host_tun `
        -Actual $runtimeState.Tun -Fields @(
            "present", "name", "interface_guid", "interface_index", "status"
        ) -Label "protected host TUN"
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $Document
    return [pscustomobject][ordered]@{
        Vm = $vm
        SourceCheckpoint = $source[0]
        Checkpoint = $qualification[0]
        SupportSwitch = $switches[0]
        SupportHost = $runtimeState.Host
        SupportVmAdapter = $runtimeState.VmAdapter
        ManagementVmAdapter = $management[0]
        ProtectedHostTun = $runtimeState.Tun
    }
}
