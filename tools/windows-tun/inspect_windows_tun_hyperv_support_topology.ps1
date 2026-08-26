#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Performs the read-only preflight for the pinned Windows TUN Hyper-V support topology.

.DESCRIPTION
This script validates the exact VM, source checkpoint, retained Default Switch management NIC,
dedicated /30, static MAC, new switch name, and new checkpoint name. It emits the closed topology
plan as JSON. It never starts the VM, loads a guest credential, or changes any network or Hyper-V
state. The mutating provisioning transaction is intentionally a separate review and invocation.
#>

[CmdletBinding(DefaultParameterSetName = "Inspect")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$toolsRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") `
    -ErrorAction Stop).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $toolsRoot "..") `
    -ErrorAction Stop).Path
$planPath = Join-Path $toolsRoot "windows_tun_hyperv_support_topology_plan.json"

function Test-PathWithinRoot {
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
    if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $fullPath.StartsWith(
        $fullRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function ConvertTo-CanonicalMacAddress {
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

function ConvertTo-CanonicalGuid {
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

function Get-VmAdapterInstanceGuid {
    param(
        [Parameter(Mandatory = $true)][string]$AdapterId,
        [Parameter(Mandatory = $true)][string]$ExpectedOwnerId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parts = $AdapterId.Split('\')
    $expectedPrefix = "Microsoft:" +
        (ConvertTo-CanonicalGuid -Value $ExpectedOwnerId -Label "$Label owner").ToUpperInvariant()
    if ($parts.Count -ne 2 -or [string]$parts[0] -cne $expectedPrefix) {
        throw "$Label adapter ID owner is invalid"
    }
    return ConvertTo-CanonicalGuid -Value $parts[1] -Label "$Label instance"
}

function Assert-PropertyOrder {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ((@($Value.PSObject.Properties.Name) -join "|") -cne ($Expected -join "|")) {
        throw "$Label property set or order is invalid"
    }
}

function Assert-NoDuplicateJsonProperty {
    param([Parameter(Mandatory = $true)][string]$Json)

    function Assert-JsonElementPropertyNamesUnique {
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
                    throw "topology plan has a duplicate JSON property at $Path"
                }
                Assert-JsonElementPropertyNamesUnique `
                    -Element $property.Value -Path "$Path.$($property.Name)"
            }
        } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
            $index = 0
            foreach ($item in $Element.EnumerateArray()) {
                Assert-JsonElementPropertyNamesUnique -Element $item -Path "$Path[$index]"
                $index += 1
            }
        }
    }

    $document = [Text.Json.JsonDocument]::Parse($Json)
    try {
        Assert-JsonElementPropertyNamesUnique -Element $document.RootElement -Path '$'
    } finally {
        $document.Dispose()
    }
}

function Read-TopologyPlan {
    $resolved = (Resolve-Path -LiteralPath $script:planPath -ErrorAction Stop).Path
    if (-not (Test-PathWithinRoot -Path $resolved -Root $script:repositoryRoot)) {
        throw "topology plan escaped the repository"
    }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    if ($bytes.Length -lt 2 -or $bytes[-1] -ne 10 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and
            $bytes[2] -eq 0xbf) -or @($bytes | Where-Object { $_ -eq 13 }).Count -ne 0) {
        throw "topology plan must be BOM-free LF-terminated UTF-8"
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-NoDuplicateJsonProperty -Json $json
    $plan = $json | ConvertFrom-Json -Depth 8 -ErrorAction Stop

    Assert-PropertyOrder -Value $plan -Expected @(
        "schema", "vm", "source_checkpoint", "management_adapter", "support",
        "qualification_checkpoint"
    ) -Label "topology plan"
    Assert-PropertyOrder -Value $plan.vm `
        -Expected @("name", "id", "automatic_checkpoints_enabled") -Label "VM plan"
    Assert-PropertyOrder -Value $plan.source_checkpoint `
        -Expected @("name", "id", "type") -Label "source checkpoint plan"
    Assert-PropertyOrder -Value $plan.management_adapter -Expected @(
        "name", "id", "switch_name", "switch_id", "mac_address", "dynamic_mac_address"
    ) -Label "management adapter plan"
    Assert-PropertyOrder -Value $plan.support -Expected @(
        "switch_name", "switch_type", "vm_adapter_name", "vm_mac_address",
        "guest_interface_alias", "network", "host_ipv4", "guest_ipv4", "prefix_length",
        "gateway", "dns_servers"
    ) -Label "support topology plan"
    Assert-PropertyOrder -Value $plan.qualification_checkpoint `
        -Expected @("name", "type") -Label "qualification checkpoint plan"

    if ($plan.schema -isnot [long] -or
        $plan.management_adapter.dynamic_mac_address -isnot [bool] -or
        $plan.vm.automatic_checkpoints_enabled -isnot [bool] -or
        $plan.support.prefix_length -isnot [long] -or
        $plan.support.dns_servers -isnot [object[]] -or
        $plan.vm.name -isnot [string] -or $plan.vm.id -isnot [string] -or
        $plan.source_checkpoint.name -isnot [string] -or
        $plan.source_checkpoint.id -isnot [string] -or
        $plan.source_checkpoint.type -isnot [string] -or
        $plan.management_adapter.name -isnot [string] -or
        $plan.management_adapter.id -isnot [string] -or
        $plan.management_adapter.switch_name -isnot [string] -or
        $plan.management_adapter.switch_id -isnot [string] -or
        $plan.management_adapter.mac_address -isnot [string] -or
        $plan.support.switch_name -isnot [string] -or
        $plan.support.switch_type -isnot [string] -or
        $plan.support.vm_adapter_name -isnot [string] -or
        $plan.support.vm_mac_address -isnot [string] -or
        $plan.support.guest_interface_alias -isnot [string] -or
        $plan.support.network -isnot [string] -or
        $plan.support.host_ipv4 -isnot [string] -or
        $plan.support.guest_ipv4 -isnot [string] -or
        $plan.qualification_checkpoint.name -isnot [string] -or
        $plan.qualification_checkpoint.type -isnot [string]) {
        throw "topology plan JSON types are invalid"
    }
    if ($plan.schema -ne 1 -or $plan.vm.automatic_checkpoints_enabled -ne $false -or
        [string]$plan.vm.name -cne "Windows 10 MSIX packaging environment" -or
        (ConvertTo-CanonicalGuid -Value $plan.vm.id -Label "VM") -cne
            "82e20295-1d30-48e7-a751-e21d35d872d4" -or
        (ConvertTo-CanonicalGuid -Value $plan.source_checkpoint.id `
            -Label "source checkpoint") -cne "1e570209-faf7-4248-8167-aa0687cdb8cf" -or
        [string]$plan.source_checkpoint.type -cne "Standard" -or
        [string]$plan.management_adapter.switch_name -cne "Default Switch" -or
        (ConvertTo-CanonicalGuid -Value $plan.management_adapter.switch_id `
            -Label "management switch") -cne "c08cb7b8-9b3c-408e-8e30-5e16a3aeb444" -or
        $plan.management_adapter.dynamic_mac_address -ne $true -or
        [string]$plan.support.switch_type -cne "Internal" -or
        [string]$plan.support.network -cne "192.168.250.0/30" -or
        [string]$plan.support.host_ipv4 -cne "192.168.250.1" -or
        [string]$plan.support.guest_ipv4 -cne "192.168.250.2" -or
        [int]$plan.support.prefix_length -ne 30 -or
        $null -ne $plan.support.gateway -or @($plan.support.dns_servers).Count -ne 0 -or
        [string]$plan.qualification_checkpoint.type -cne "Standard") {
        throw "topology plan violates the approved isolated /30 contract"
    }

    $network = [Net.IPNetwork]::Parse([string]$plan.support.network)
    $hostAddress = [Net.IPAddress]::Parse([string]$plan.support.host_ipv4)
    $guestAddress = [Net.IPAddress]::Parse([string]$plan.support.guest_ipv4)
    if ($network.BaseAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $network.PrefixLength -ne 30 -or -not $network.Contains($hostAddress) -or
        -not $network.Contains($guestAddress) -or
        [string]$hostAddress -ceq [string]$network.BaseAddress -or
        [string]$guestAddress -ceq [string]$network.BaseAddress -or
        [string]$hostAddress -ceq [string]$guestAddress) {
        throw "support endpoints are not the two usable IPv4 addresses in the planned /30"
    }

    $managementMac = ConvertTo-CanonicalMacAddress `
        -Value ([string]$plan.management_adapter.mac_address) -Label "management adapter"
    $supportMac = ConvertTo-CanonicalMacAddress `
        -Value ([string]$plan.support.vm_mac_address) -Label "support adapter"
    if ($managementMac -ceq $supportMac -or $supportMac -cnotmatch '^00155D') {
        throw "support static MAC is not isolated from the management adapter"
    }
    $null = Get-VmAdapterInstanceGuid -AdapterId ([string]$plan.management_adapter.id) `
        -ExpectedOwnerId ([string]$plan.vm.id) -Label "planned management"

    return [pscustomobject][ordered]@{
        Value = $plan
        Path = $resolved
        Sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
    }
}

function Get-ApprovedVmContext {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $vmId = [Guid][string]$Plan.vm.id
    $vm = Get-VM -Id $vmId -ErrorAction Stop
    if ([string]$vm.Name -cne [string]$Plan.vm.name) {
        throw "approved VM identity mismatch"
    }
    $byName = @(Get-VM -Name ([string]$Plan.vm.name) -ErrorAction Stop)
    if ($byName.Count -ne 1 -or $byName[0].Id -ne $vmId) {
        throw "approved VM name does not resolve to the approved ID"
    }

    $checkpointId = [Guid][string]$Plan.source_checkpoint.id
    $checkpoint = @(Get-VMSnapshot -Id $checkpointId -ErrorAction Stop)
    if ($checkpoint.Count -ne 1 -or $checkpoint[0].VMId -ne $vmId -or
        [string]$checkpoint[0].Name -cne [string]$Plan.source_checkpoint.name -or
        [string]$checkpoint[0].SnapshotType -cne [string]$Plan.source_checkpoint.type -or
        $checkpoint[0].IsAutomaticCheckpoint -ne $false) {
        throw "source checkpoint identity mismatch"
    }
    $checkpointByName = @(
        Get-VMSnapshot -VM $vm -Name ([string]$Plan.source_checkpoint.name) -ErrorAction Stop
    )
    if ($checkpointByName.Count -ne 1 -or $checkpointByName[0].Id -ne $checkpointId) {
        throw "source checkpoint name does not resolve to the approved ID"
    }
    if ([string]$vm.CheckpointType -cne "Standard" -or
        [bool]$vm.AutomaticCheckpointsEnabled -ne
            [bool]$Plan.vm.automatic_checkpoints_enabled) {
        throw "approved VM checkpoint policy must remain Standard without automatic checkpoints"
    }
    return [pscustomobject][ordered]@{ Vm = $vm; SourceCheckpoint = $checkpoint[0] }
}

function Get-ManagementAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Vm,
        [Parameter(Mandatory = $true)][object]$Plan
    )

    $adapters = @(Get-VMNetworkAdapter -VM $Vm -ErrorAction Stop)
    $management = @($adapters | Where-Object {
        [string]$_.Id -ieq [string]$Plan.management_adapter.id
    })
    if ($management.Count -ne 1) {
        throw "approved management VM adapter identity is not unique"
    }
    $adapter = $management[0]
    if ([string]$adapter.Name -cne [string]$Plan.management_adapter.name -or
        [string]$adapter.SwitchName -cne [string]$Plan.management_adapter.switch_name -or
        (ConvertTo-CanonicalGuid -Value $adapter.SwitchId -Label "management switch") -cne
            (ConvertTo-CanonicalGuid -Value $Plan.management_adapter.switch_id `
                -Label "planned management switch") -or
        (ConvertTo-CanonicalMacAddress -Value ([string]$adapter.MacAddress) `
            -Label "management adapter") -cne
            (ConvertTo-CanonicalMacAddress -Value ([string]$Plan.management_adapter.mac_address) `
                -Label "planned management adapter") -or
        [bool]$adapter.DynamicMacAddressEnabled -ne
            [bool]$Plan.management_adapter.dynamic_mac_address -or
        $adapter.Connected -ne $true) {
        throw "approved management VM adapter contract changed"
    }
    return $adapter
}

function Get-SourceCheckpointManagementAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan
    )

    $snapshotAdapters = @(
        Get-VMNetworkAdapter -VMSnapshot $Context.SourceCheckpoint -ErrorAction Stop
    )
    if ($snapshotAdapters.Count -ne 1) {
        throw "source checkpoint must contain only the approved management adapter"
    }
    $snapshotAdapter = $snapshotAdapters[0]
    $plannedInstanceGuid = Get-VmAdapterInstanceGuid `
        -AdapterId ([string]$Plan.management_adapter.id) `
        -ExpectedOwnerId ([string]$Plan.vm.id) -Label "planned management"
    $snapshotInstanceGuid = Get-VmAdapterInstanceGuid `
        -AdapterId ([string]$snapshotAdapter.Id) `
        -ExpectedOwnerId ([string]$Context.SourceCheckpoint.Id) `
        -Label "source checkpoint management"
    if ($snapshotInstanceGuid -cne $plannedInstanceGuid -or
        [string]$snapshotAdapter.Name -cne [string]$Plan.management_adapter.name -or
        [string]$snapshotAdapter.SwitchName -cne [string]$Plan.management_adapter.switch_name -or
        (ConvertTo-CanonicalGuid -Value $snapshotAdapter.SwitchId `
            -Label "source checkpoint management switch") -cne
            (ConvertTo-CanonicalGuid -Value $Plan.management_adapter.switch_id `
                -Label "planned management switch") -or
        (ConvertTo-CanonicalMacAddress -Value ([string]$snapshotAdapter.MacAddress) `
            -Label "source checkpoint management adapter") -cne
            (ConvertTo-CanonicalMacAddress -Value ([string]$Plan.management_adapter.mac_address) `
                -Label "planned management adapter") -or
        [bool]$snapshotAdapter.DynamicMacAddressEnabled -ne
            [bool]$Plan.management_adapter.dynamic_mac_address -or
        $snapshotAdapter.Connected -ne $true) {
        throw "source checkpoint management adapter contract changed"
    }
    return [pscustomobject][ordered]@{
        Adapter = $snapshotAdapter
        InstanceGuid = $snapshotInstanceGuid
    }
}

function Assert-DefaultSwitch {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $switchId = [Guid][string]$Plan.management_adapter.switch_id
    $switch = @(Get-VMSwitch -Id $switchId -ErrorAction Stop)
    if ($switch.Count -ne 1 -or
        [string]$switch[0].Name -cne [string]$Plan.management_adapter.switch_name -or
        [string]$switch[0].SwitchType -cne "Internal" -or
        $switch[0].AllowManagementOS -ne $true) {
        throw "approved Default Switch identity changed"
    }
}

function Test-Ipv4PrefixOverlap {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftNetwork = [Net.IPNetwork]::Parse($Left)
    $rightNetwork = [Net.IPNetwork]::Parse($Right)
    if ($leftNetwork.BaseAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        $rightNetwork.BaseAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "prefix overlap check only accepts IPv4"
    }
    return $leftNetwork.Contains($rightNetwork.BaseAddress) -or
        $rightNetwork.Contains($leftNetwork.BaseAddress)
}

function Get-PersistentIpv4AddressRow {
    try {
        return @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore PersistentStore `
            -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
            return @()
        }
        throw
    }
}

function Get-PersistentIpv4RouteRow {
    try {
        return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore `
            -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetRoute") {
            return @()
        }
        throw
    }
}

function Get-HostTunIdentity {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        [string]$_.Name -ieq "tun0"
    })
    if ($adapters.Count -eq 0) {
        return [pscustomobject][ordered]@{ present = $false }
    }
    if ($adapters.Count -ne 1) {
        throw "host tun0 identity is not unique"
    }
    return [pscustomobject][ordered]@{
        present = $true
        name = [string]$adapters[0].Name
        interface_guid = (ConvertTo-CanonicalGuid `
            -Value $adapters[0].InterfaceGuid -Label "host tun0")
        interface_index = [int]$adapters[0].ifIndex
        status = [string]$adapters[0].Status
    }
}

function Get-ReadOnlyPreflight {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan
    )

    if ([string]$Context.Vm.State -cne "Off") {
        throw "approved VM must be Off during the read-only topology preflight"
    }
    $checkpointInventory = @(Get-VMSnapshot -VM $Context.Vm -ErrorAction Stop)
    if ($checkpointInventory.Count -ne 1 -or
        $checkpointInventory[0].Id -ne $Context.SourceCheckpoint.Id -or
        $checkpointInventory[0].IsAutomaticCheckpoint -ne $false) {
        throw "source VM checkpoint inventory is not the unique approved Standard checkpoint"
    }
    Assert-DefaultSwitch -Plan $Plan
    $management = Get-ManagementAdapter -Vm $Context.Vm -Plan $Plan
    $snapshotManagement = Get-SourceCheckpointManagementAdapter `
        -Context $Context -Plan $Plan
    $vmAdapters = @(Get-VMNetworkAdapter -VM $Context.Vm -ErrorAction Stop)
    if ($vmAdapters.Count -ne 1 -or [string]$vmAdapters[0].Id -ine [string]$management.Id) {
        throw "source VM must contain only the approved Default Switch management adapter"
    }

    if (@(Get-VMSwitch -ErrorAction Stop | Where-Object {
            [string]$_.Name -ieq [string]$Plan.support.switch_name
        }).Count -ne 0) {
        throw "planned support vSwitch name already exists"
    }
    if (@(Get-VMSnapshot -VM $Context.Vm -ErrorAction Stop | Where-Object {
            [string]$_.Name -ieq [string]$Plan.qualification_checkpoint.name
        }).Count -ne 0) {
        throw "planned qualification checkpoint name already exists"
    }

    $supportMac = ConvertTo-CanonicalMacAddress `
        -Value ([string]$Plan.support.vm_mac_address) -Label "planned support adapter"
    $macCollisions = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.MacAddress) -and
        (($_.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -ceq $supportMac)
    })
    if ($macCollisions.Count -ne 0) {
        throw "planned support static MAC already exists"
    }
    $hostMacCollisions = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.MacAddress) -and
        (($_.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -ceq $supportMac)
    })
    if ($hostMacCollisions.Count -ne 0) {
        throw "planned support static MAC collides with a host adapter"
    }
    $vmHost = Get-VMHost -ErrorAction Stop
    $dynamicMinimum = [Convert]::ToUInt64(
        (ConvertTo-CanonicalMacAddress -Value ([string]$vmHost.MacAddressMinimum) `
            -Label "Hyper-V dynamic MAC minimum"),
        16
    )
    $dynamicMaximum = [Convert]::ToUInt64(
        (ConvertTo-CanonicalMacAddress -Value ([string]$vmHost.MacAddressMaximum) `
            -Label "Hyper-V dynamic MAC maximum"),
        16
    )
    $supportMacInteger = [Convert]::ToUInt64($supportMac, 16)
    if ($supportMacInteger -ge $dynamicMinimum -and $supportMacInteger -le $dynamicMaximum) {
        throw "planned static support MAC falls inside the host dynamic MAC pool"
    }

    $network = [string]$Plan.support.network
    $addressRows = @(
        Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Get-PersistentIpv4AddressRow
    )
    $addressCollisions = @($addressRows | Where-Object {
        Test-Ipv4PrefixOverlap -Left "$($_.IPAddress)/32" -Right $network
    })
    if ($addressCollisions.Count -ne 0) {
        throw "planned support /30 overlaps an existing host IPv4 address"
    }
    $routeRows = @(
        Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Get-PersistentIpv4RouteRow
    )
    $routeCollisions = @($routeRows | Where-Object {
        [string]$_.DestinationPrefix -cne "0.0.0.0/0" -and
        (Test-Ipv4PrefixOverlap -Left ([string]$_.DestinationPrefix) -Right $network)
    })
    if ($routeCollisions.Count -ne 0) {
        throw "planned support /30 overlaps an existing non-default host route"
    }
    $natCollisions = @(Get-NetNat -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.InternalIPInterfaceAddressPrefix) -and
        (Test-Ipv4PrefixOverlap `
            -Left ([string]$_.InternalIPInterfaceAddressPrefix) -Right $network)
    })
    if ($natCollisions.Count -ne 0) {
        throw "planned support /30 overlaps an existing NAT"
    }
    $hostTun = Get-HostTunIdentity
    if ($hostTun.present -ne $true -or [string]$hostTun.name -cne "tun0" -or
        [string]$hostTun.status -cne "Up") {
        throw "protected host tun0 must be uniquely present and Up"
    }

    return [pscustomobject][ordered]@{
        vm_state = [string]$Context.Vm.State
        automatic_checkpoints_enabled = [bool]$Context.Vm.AutomaticCheckpointsEnabled
        source_checkpoint_id = $Context.SourceCheckpoint.Id.ToString("D")
        source_checkpoint_management_instance_id = $snapshotManagement.InstanceGuid
        management_adapter_id = [string]$management.Id
        management_mac_address = ConvertTo-CanonicalMacAddress `
            -Value ([string]$management.MacAddress) -Label "management adapter"
        management_switch_id = (ConvertTo-CanonicalGuid `
            -Value $management.SwitchId -Label "management switch")
        support_switch_absent = $true
        support_mac_unused = $true
        support_mac_outside_dynamic_pool = $true
        support_network_unused = $true
        qualification_checkpoint_absent = $true
        host_tun = $hostTun
    }
}

if ($LibraryOnly) {
    return
}

$planDocument = Read-TopologyPlan
$context = Get-ApprovedVmContext -Plan $planDocument.Value
$preflight = Get-ReadOnlyPreflight -Context $context -Plan $planDocument.Value

[pscustomobject][ordered]@{
    schema = 1
    mode = "read_only_preflight"
    status = "ready_for_explicit_authorization"
    topology_plan_path = $planDocument.Path
    topology_plan_sha256 = $planDocument.Sha256
    inspector_sha256 = (Get-FileHash -LiteralPath $PSCommandPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    preflight = $preflight
    proposed_mutations = @(
        "restore exact source checkpoint while VM is Off",
        "create one Internal vSwitch named $($planDocument.Value.support.switch_name)",
        "assign $($planDocument.Value.support.host_ipv4)/$($planDocument.Value.support.prefix_length) to its host vNIC",
        "add one static-MAC support NIC to the approved VM",
        "assign $($planDocument.Value.support.guest_ipv4)/$($planDocument.Value.support.prefix_length) to the guest support NIC",
        "create and verify Standard checkpoint $($planDocument.Value.qualification_checkpoint.name)",
        "write a new external identity manifest"
    )
    forbidden_mutations = @(
        "host tun0",
        "Default Switch",
        "physical host adapters",
        "default routes",
        "NAT",
        "ICS",
        "firewall",
        "DNS outside the two new support interfaces"
    )
    terminal_vm_state = "Off"
} | ConvertTo-Json -Depth 8
