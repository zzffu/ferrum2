#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines pure plan parsing and live readback for Windows TUN Hyper-V support topology.

.DESCRIPTION
This dot-source-only owner contains no mutation commands. Provisioning and runtime validation share
its exact plan parser, pinned VM inventory, host TUN, switch, route, DNS, and adapter readback.
#>

[CmdletBinding(DefaultParameterSetName = "Inspect")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly,
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [string]$LabRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$resolvedLabRoot = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path
$windowsTunRoot = (Resolve-Path -LiteralPath (Join-Path $resolvedLabRoot "..") `
    -ErrorAction Stop).Path
$toolsRoot = (Resolve-Path -LiteralPath (Join-Path $windowsTunRoot "..") `
    -ErrorAction Stop).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $toolsRoot "..") `
    -ErrorAction Stop).Path
$planPath = Join-Path $toolsRoot 'windows_tun_hyperv_support_topology_plan.json'

function Assert-TopologyPlanPropertiesAndTypes {
    param([Parameter(Mandatory)] [object]$Plan)

    foreach ($contract in @(
        @($Plan, @('schema', 'vm', 'source_checkpoint', 'management_adapter', 'support',
            'lab_checkpoint'), 'topology plan'),
        @($Plan.vm, @('name', 'id', 'automatic_checkpoints_enabled'), 'VM plan'),
        @($Plan.source_checkpoint, @('name', 'id', 'type'), 'source checkpoint plan'),
        @($Plan.management_adapter, @(
            'name', 'id', 'switch_name', 'switch_id', 'mac_address', 'dynamic_mac_address'
        ), 'management adapter plan'),
        @($Plan.support, @(
            'switch_name', 'switch_type', 'vm_adapter_name', 'vm_mac_address',
            'guest_interface_alias', 'network', 'host_ipv4', 'guest_ipv4', 'prefix_length',
            'gateway', 'dns_servers'
        ), 'support topology plan'),
        @($Plan.lab_checkpoint, @('name', 'type'), 'lab checkpoint plan')
    )) {
        Assert-Ferrum2ClosedProperties -Value $contract[0] `
            -Expected ([string[]]$contract[1]) -Label ([string]$contract[2])
    }
    if ($Plan.schema -isnot [long] -or
        $Plan.management_adapter.dynamic_mac_address -isnot [bool] -or
        $Plan.vm.automatic_checkpoints_enabled -isnot [bool] -or
        $Plan.support.prefix_length -isnot [long] -or
        $Plan.support.dns_servers -isnot [object[]] -or
        $Plan.vm.name -isnot [string] -or $Plan.vm.id -isnot [string] -or
        $Plan.source_checkpoint.name -isnot [string] -or
        $Plan.source_checkpoint.id -isnot [string] -or
        $Plan.source_checkpoint.type -isnot [string] -or
        $Plan.management_adapter.name -isnot [string] -or
        $Plan.management_adapter.id -isnot [string] -or
        $Plan.management_adapter.switch_name -isnot [string] -or
        $Plan.management_adapter.switch_id -isnot [string] -or
        $Plan.management_adapter.mac_address -isnot [string] -or
        $Plan.support.switch_name -isnot [string] -or
        $Plan.support.switch_type -isnot [string] -or
        $Plan.support.vm_adapter_name -isnot [string] -or
        $Plan.support.vm_mac_address -isnot [string] -or
        $Plan.support.guest_interface_alias -isnot [string] -or
        $Plan.support.network -isnot [string] -or
        $Plan.support.host_ipv4 -isnot [string] -or
        $Plan.support.guest_ipv4 -isnot [string] -or
        $Plan.lab_checkpoint.name -isnot [string] -or
        $Plan.lab_checkpoint.type -isnot [string]) {
        throw 'topology plan JSON types are invalid'
    }
}

function Assert-TopologyPlanIsolationContract {
    param([Parameter(Mandatory)] [object]$Plan)

    if ($Plan.schema -ne 1 -or $Plan.vm.automatic_checkpoints_enabled -ne $false -or
        [string]$Plan.vm.name -cne 'Windows 10 MSIX packaging environment' -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.vm.id -Label 'VM') -cne
            '82e20295-1d30-48e7-a751-e21d35d872d4' -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.source_checkpoint.id `
            -Label 'source checkpoint') -cne '1e570209-faf7-4248-8167-aa0687cdb8cf' -or
        [string]$Plan.source_checkpoint.type -cne 'Standard' -or
        [string]$Plan.management_adapter.switch_name -cne 'Default Switch' -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.management_adapter.switch_id `
            -Label 'management switch') -cne 'c08cb7b8-9b3c-408e-8e30-5e16a3aeb444' -or
        $Plan.management_adapter.dynamic_mac_address -ne $true -or
        [string]$Plan.support.switch_type -cne 'Internal' -or
        [string]$Plan.support.network -cne '192.168.250.0/30' -or
        [string]$Plan.support.host_ipv4 -cne '192.168.250.1' -or
        [string]$Plan.support.guest_ipv4 -cne '192.168.250.2' -or
        [int]$Plan.support.prefix_length -ne 30 -or
        $null -ne $Plan.support.gateway -or @($Plan.support.dns_servers).Count -ne 0 -or
        [string]$Plan.lab_checkpoint.type -cne 'Standard') {
        throw 'topology plan violates the approved isolated /30 contract'
    }
    $network = [Net.IPNetwork]::Parse([string]$Plan.support.network)
    $hostAddress = [Net.IPAddress]::Parse([string]$Plan.support.host_ipv4)
    $guestAddress = [Net.IPAddress]::Parse([string]$Plan.support.guest_ipv4)
    if ($network.BaseAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $network.PrefixLength -ne 30 -or -not $network.Contains($hostAddress) -or
        -not $network.Contains($guestAddress) -or
        [string]$hostAddress -ceq [string]$network.BaseAddress -or
        [string]$guestAddress -ceq [string]$network.BaseAddress -or
        [string]$hostAddress -ceq [string]$guestAddress) {
        throw 'support endpoints are not the two usable IPv4 addresses in the planned /30'
    }
    $managementMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Plan.management_adapter.mac_address) -Label 'management adapter'
    $supportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Plan.support.vm_mac_address) -Label 'support adapter'
    if ($managementMac -ceq $supportMac -or $supportMac -cnotmatch '^00155D') {
        throw 'support static MAC is not isolated from the management adapter'
    }
    $null = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$Plan.management_adapter.id) `
        -ExpectedOwnerId ([string]$Plan.vm.id) -Label 'planned management'
}

function Read-TopologyPlan {
    $document = Read-Ferrum2JsonDocument -Path $script:planPath -MaximumBytes 131072
    if (-not (Test-Ferrum2PathWithinRoot -Path $document.Path `
            -Root $script:repositoryRoot)) {
        throw 'topology plan escaped the repository'
    }
    $plan = $document.Value

    Assert-TopologyPlanPropertiesAndTypes -Plan $plan
    Assert-TopologyPlanIsolationContract -Plan $plan

    return [pscustomobject][ordered]@{
        Value = $plan
        Path = [string]$document.Path
        Sha256 = [string]$document.Sha256
    }
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
        (ConvertTo-Ferrum2CanonicalGuid -Value $adapter.SwitchId -Label "management switch") -cne
            (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.management_adapter.switch_id `
                -Label "planned management switch") -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$adapter.MacAddress) `
            -Label "management adapter") -cne
            (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$Plan.management_adapter.mac_address) `
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
    $plannedInstanceGuid = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$Plan.management_adapter.id) `
        -ExpectedOwnerId ([string]$Plan.vm.id) -Label "planned management"
    $snapshotInstanceGuid = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$snapshotAdapter.Id) `
        -ExpectedOwnerId ([string]$Context.SourceCheckpoint.Id) `
        -Label "source checkpoint management"
    if ($snapshotInstanceGuid -cne $plannedInstanceGuid -or
        [string]$snapshotAdapter.Name -cne [string]$Plan.management_adapter.name -or
        [string]$snapshotAdapter.SwitchName -cne [string]$Plan.management_adapter.switch_name -or
        (ConvertTo-Ferrum2CanonicalGuid -Value $snapshotAdapter.SwitchId `
            -Label "source checkpoint management switch") -cne
            (ConvertTo-Ferrum2CanonicalGuid -Value $Plan.management_adapter.switch_id `
                -Label "planned management switch") -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$snapshotAdapter.MacAddress) `
            -Label "source checkpoint management adapter") -cne
            (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$Plan.management_adapter.mac_address) `
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
        interface_guid = (ConvertTo-Ferrum2CanonicalGuid `
            -Value $adapters[0].InterfaceGuid -Label "host tun0")
        interface_index = [int]$adapters[0].ifIndex
        status = [string]$adapters[0].Status
    }
}

function Get-ReadOnlySourceVmInventory {
    param(
        [Parameter(Mandatory)] [object]$Context,
        [Parameter(Mandatory)] [object]$Plan
    )

    if ([string]$Context.Vm.State -cne 'Off') {
        throw 'approved VM must be Off during the read-only topology preflight'
    }
    $checkpoints = @(Get-VMSnapshot -VM $Context.Vm -ErrorAction Stop)
    if ($checkpoints.Count -ne 1 -or
        $checkpoints[0].Id -ne $Context.SourceCheckpoint.Id -or
        $checkpoints[0].IsAutomaticCheckpoint -ne $false) {
        throw 'source VM checkpoint inventory is not the unique approved Standard checkpoint'
    }
    Assert-DefaultSwitch -Plan $Plan
    $management = Get-ManagementAdapter -Vm $Context.Vm -Plan $Plan
    $snapshotManagement = Get-SourceCheckpointManagementAdapter `
        -Context $Context -Plan $Plan
    $vmAdapters = @(Get-VMNetworkAdapter -VM $Context.Vm -ErrorAction Stop)
    if ($vmAdapters.Count -ne 1 -or [string]$vmAdapters[0].Id -ine [string]$management.Id) {
        throw 'source VM must contain only the approved Default Switch management adapter'
    }
    if (@(Get-VMSwitch -ErrorAction Stop | Where-Object {
            [string]$_.Name -ieq [string]$Plan.support.switch_name
        }).Count -ne 0) {
        throw 'planned support vSwitch name already exists'
    }
    if (@(Get-VMSnapshot -VM $Context.Vm -ErrorAction Stop | Where-Object {
            [string]$_.Name -ieq [string]$Plan.lab_checkpoint.name
        }).Count -ne 0) {
        throw 'planned lab checkpoint name already exists'
    }
    [pscustomobject][ordered]@{
        Management = $management
        SnapshotManagement = $snapshotManagement
    }
}

function Assert-ReadOnlySupportMacAvailable {
    param([Parameter(Mandatory)] [object]$Plan)

    $supportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Plan.support.vm_mac_address) -Label 'planned support adapter'
    $vmCollisions = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.MacAddress) -and
        (($_.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -ceq $supportMac)
    })
    if ($vmCollisions.Count -ne 0) { throw 'planned support static MAC already exists' }
    $hostCollisions = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.MacAddress) -and
        (($_.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -ceq $supportMac)
    })
    if ($hostCollisions.Count -ne 0) {
        throw 'planned support static MAC collides with a host adapter'
    }
    $vmHost = Get-VMHost -ErrorAction Stop
    $dynamicMinimum = [Convert]::ToUInt64(
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$vmHost.MacAddressMinimum) `
            -Label 'Hyper-V dynamic MAC minimum'), 16
    )
    $dynamicMaximum = [Convert]::ToUInt64(
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$vmHost.MacAddressMaximum) `
            -Label 'Hyper-V dynamic MAC maximum'), 16
    )
    $supportMacInteger = [Convert]::ToUInt64($supportMac, 16)
    if ($supportMacInteger -ge $dynamicMinimum -and $supportMacInteger -le $dynamicMaximum) {
        throw 'planned static support MAC falls inside the host dynamic MAC pool'
    }
}

function Assert-ReadOnlySupportNetworkAvailable {
    param([Parameter(Mandatory)] [object]$Plan)

    $network = [string]$Plan.support.network
    $addressRows = @(
        Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Get-PersistentIpv4AddressRow
    )
    if (@($addressRows | Where-Object {
            Test-Ipv4PrefixOverlap -Left "$($_.IPAddress)/32" -Right $network
        }).Count -ne 0) {
        throw 'planned support /30 overlaps an existing host IPv4 address'
    }
    $routeRows = @(
        Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Get-PersistentIpv4RouteRow
    )
    if (@($routeRows | Where-Object {
            [string]$_.DestinationPrefix -cne '0.0.0.0/0' -and
            (Test-Ipv4PrefixOverlap -Left ([string]$_.DestinationPrefix) -Right $network)
        }).Count -ne 0) {
        throw 'planned support /30 overlaps an existing non-default host route'
    }
    if (@(Get-NetNat -ErrorAction Stop | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.InternalIPInterfaceAddressPrefix) -and
            (Test-Ipv4PrefixOverlap `
                -Left ([string]$_.InternalIPInterfaceAddressPrefix) -Right $network)
        }).Count -ne 0) {
        throw 'planned support /30 overlaps an existing NAT'
    }
}

function Get-ReadOnlyPreflight {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan
    )

    $inventory = Get-ReadOnlySourceVmInventory -Context $Context -Plan $Plan
    Assert-ReadOnlySupportMacAvailable -Plan $Plan
    Assert-ReadOnlySupportNetworkAvailable -Plan $Plan
    $hostTun = Get-HostTunIdentity
    if ($hostTun.present -ne $true -or [string]$hostTun.name -cne "tun0" -or
        [string]$hostTun.status -cne "Up") {
        throw "protected host tun0 must be uniquely present and Up"
    }

    return [pscustomobject][ordered]@{
        vm_state = [string]$Context.Vm.State
        automatic_checkpoints_enabled = [bool]$Context.Vm.AutomaticCheckpointsEnabled
        source_checkpoint_id = $Context.SourceCheckpoint.Id.ToString("D")
        source_checkpoint_management_instance_id = $inventory.SnapshotManagement.InstanceGuid
        management_adapter_id = [string]$inventory.Management.Id
        management_mac_address = ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$inventory.Management.MacAddress) -Label "management adapter"
        management_switch_id = (ConvertTo-Ferrum2CanonicalGuid `
            -Value $inventory.Management.SwitchId -Label "management switch")
        support_switch_absent = $true
        support_mac_unused = $true
        support_mac_outside_dynamic_pool = $true
        support_network_unused = $true
        lab_checkpoint_absent = $true
        host_tun = $hostTun
    }
}

function Get-SupportSwitchContext {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $switches = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
            $_.Id -eq $SwitchId
        })
        if ($switches.Count -eq 1 -and
            [string]$switches[0].Name -ceq [string]$Plan.support.switch_name -and
            [string]$switches[0].SwitchType -ceq "Internal" -and
            $switches[0].AllowManagementOS -eq $true) {
            $byName = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
                [string]$_.Name -ieq [string]$Plan.support.switch_name
            })
            $managementAdapters = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop |
                Where-Object { $_.SwitchId -eq $SwitchId })
            if ($byName.Count -eq 1 -and $byName[0].Id -eq $SwitchId -and
                $managementAdapters.Count -eq 1) {
                $deviceGuid = [Guid]::Empty
                if ([Guid]::TryParse([string]$managementAdapters[0].DeviceId, [ref]$deviceGuid)) {
                    $hostAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                        Where-Object { ([Guid][string]$_.InterfaceGuid) -eq $deviceGuid })
                    if ($hostAdapters.Count -eq 1 -and
                        $hostAdapters[0].Virtual -eq $true -and
                        $hostAdapters[0].HardwareInterface -eq $false) {
                        return [pscustomobject][ordered]@{
                            Switch = $switches[0]
                            ManagementAdapter = $managementAdapters[0]
                            HostAdapter = $hostAdapters[0]
                        }
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "new support switch did not expose one exact host vNIC"
}

function Assert-IcsDisabledForHostAdapter {
    param([Parameter(Mandatory = $true)][Guid]$InterfaceGuid)

    $sharingManager = New-Object -ComObject HNetCfg.HNetShare
    $sharingConnections = [Collections.Generic.List[object]]::new()
    foreach ($connection in @($sharingManager.EnumEveryConnection)) {
        $properties = $sharingManager.NetConnectionProps($connection)
        if ([Guid][string]$properties.Guid -eq $InterfaceGuid) {
            $sharingConnections.Add($connection)
        }
    }
    if ($sharingConnections.Count -ne 1) {
        throw "support host vNIC is not unique in the ICS inventory"
    }
    $configuration = $sharingManager.INetSharingConfigurationForINetConnection(
        $sharingConnections[0]
    )
    if ($configuration.SharingEnabled) {
        throw "ICS is unexpectedly enabled on the support host vNIC"
    }
}

function Assert-NoSupportNat {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $collisions = @(Get-NetNat -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.InternalIPInterfaceAddressPrefix) -and
        (Test-Ipv4PrefixOverlap -Left ([string]$_.InternalIPInterfaceAddressPrefix) `
            -Right ([string]$Plan.support.network))
    })
    if ($collisions.Count -ne 0) {
        throw "support /30 is unexpectedly covered by NAT"
    }
}

function Get-ActiveIpv4AddressRow {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    try {
        return @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -PolicyStore ActiveStore -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
            return @()
        }
        throw
    }
}

function Get-SupportPersistentIpv4AddressRow {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    try {
        return @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -PolicyStore PersistentStore -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
            return @()
        }
        throw
    }
}

function Get-Ipv4RouteRow {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ActiveStore", "PersistentStore")]
        [string]$PolicyStore,
        [string]$DestinationPrefix
    )

    $parameters = @{
        InterfaceIndex = $InterfaceIndex
        AddressFamily = "IPv4"
        PolicyStore = $PolicyStore
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPrefix)) {
        $parameters.DestinationPrefix = $DestinationPrefix
    }
    try {
        return @(Get-NetRoute @parameters)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like "CmdletizationQuery_NotFound*,Get-NetRoute") {
            return @()
        }
        throw
    }
}

function Get-ValidatedSupportHostState {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $context = Get-SupportSwitchContext -Plan $Plan -SwitchId $SwitchId `
        -TimeoutSeconds $TimeoutSeconds
    $interfaceIndex = [int]$context.HostAdapter.ifIndex
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $addresses = @(Get-ActiveIpv4AddressRow -InterfaceIndex $interfaceIndex)
        $expectedAddresses = @($addresses | Where-Object {
            [string]$_.IPAddress -ceq [string]$Plan.support.host_ipv4 -and
            [int]$_.PrefixLength -eq [int]$Plan.support.prefix_length -and
            [string]$_.AddressState -ceq "Preferred"
        })
        if ($addresses.Count -eq 1 -and $expectedAddresses.Count -eq 1) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($addresses.Count -ne 1 -or $expectedAddresses.Count -ne 1) {
        throw "support host vNIC does not have the exact preferred /30 address"
    }
    $persistentAddresses = @(Get-SupportPersistentIpv4AddressRow `
        -InterfaceIndex $interfaceIndex)
    $expectedPersistentAddresses = @($persistentAddresses | Where-Object {
        [string]$_.IPAddress -ceq [string]$Plan.support.host_ipv4 -and
        [int]$_.PrefixLength -eq [int]$Plan.support.prefix_length
    })
    if ($persistentAddresses.Count -ne 1 -or $expectedPersistentAddresses.Count -ne 1) {
        throw "support host /30 address is not uniquely persistent"
    }

    $ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $persistentIpInterfaces = @(Get-NetIPInterface -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction Stop)
    $directRoutes = @(Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex `
        -PolicyStore ActiveStore -DestinationPrefix ([string]$Plan.support.network) |
        Where-Object {
        [string]$_.NextHop -ceq "0.0.0.0"
    })
    $allRoutes = @(
        Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore
        Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex -PolicyStore PersistentStore
    )
    $defaultRoutes = @($allRoutes | Where-Object {
        [string]$_.DestinationPrefix -ceq "0.0.0.0/0"
    })
    $gatewayRoutes = @($allRoutes | Where-Object {
        [string]$_.NextHop -cne "0.0.0.0"
    })
    $ipv4DnsServers = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object
    )
    $ipv6DnsServers = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -ErrorAction Stop |
            ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object
    )
    $windowsIntrinsicIpv6Dns = @(
        "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
    )
    $dnsStateValid = $ipv4DnsServers.Count -eq 0 -and
        ($ipv6DnsServers.Count -eq 0 -or
            ($ipv6DnsServers -join "|") -ieq ($windowsIntrinsicIpv6Dns -join "|"))
    $selection = @(Find-NetRoute -RemoteIPAddress ([string]$Plan.support.guest_ipv4) `
        -ErrorAction Stop)
    $sourceRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["IPAddress"]
    })
    $routeRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["DestinationPrefix"]
    })
    $activeInterfaceValid = $ipInterfaces.Count -eq 1 -and
        [string]$ipInterfaces[0].Dhcp -ceq "Disabled" -and
        [string]$ipInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled" -and
        [int]$ipInterfaces[0].NlMtu -ge 1468
    $persistentInterfaceValid = $persistentIpInterfaces.Count -eq 1 -and
        [string]$persistentIpInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled"
    $sourceSelectionValid = $sourceRows.Count -eq 1 -and
        [string]$sourceRows[0].IPAddress -ceq [string]$Plan.support.host_ipv4 -and
        [int]$sourceRows[0].InterfaceIndex -eq $interfaceIndex
    $routeSelectionValid = $routeRows.Count -eq 1 -and
        [string]$routeRows[0].DestinationPrefix -ceq [string]$Plan.support.network -and
        [string]$routeRows[0].NextHop -ceq "0.0.0.0" -and
        [int]$routeRows[0].InterfaceIndex -eq $interfaceIndex
    $violations = @(
        if (-not $activeInterfaceValid) { "active_interface" }
        if (-not $persistentInterfaceValid) { "persistent_interface" }
        if ($directRoutes.Count -ne 1) { "direct_route_count=$($directRoutes.Count)" }
        if ($defaultRoutes.Count -ne 0) { "default_route_count=$($defaultRoutes.Count)" }
        if ($gatewayRoutes.Count -ne 0) { "gateway_route_count=$($gatewayRoutes.Count)" }
        if (-not $dnsStateValid) {
            "dns_state=ipv4:$($ipv4DnsServers.Count),ipv6:$($ipv6DnsServers.Count)"
        }
        if (-not $sourceSelectionValid) { "source_selection" }
        if (-not $routeSelectionValid) { "route_selection" }
    )
    if ($violations.Count -ne 0) {
        throw "support host route, DNS, DHCP, MTU, or source-selection contract is invalid: " +
            ($violations -join ",")
    }
    Assert-NoSupportNat -Plan $Plan
    Assert-IcsDisabledForHostAdapter -InterfaceGuid ([Guid]$context.HostAdapter.InterfaceGuid)

    return [pscustomobject][ordered]@{
        switch_name = [string]$context.Switch.Name
        switch_id = $context.Switch.Id.ToString("D")
        switch_type = [string]$context.Switch.SwitchType
        management_os_adapter_id = [string]$context.ManagementAdapter.Id
        management_os_device_id = (ConvertTo-Ferrum2CanonicalGuid `
            -Value $context.ManagementAdapter.DeviceId -Label "support management OS adapter")
        host_interface_alias = [string]$context.HostAdapter.Name
        host_interface_guid = (ConvertTo-Ferrum2CanonicalGuid `
            -Value $context.HostAdapter.InterfaceGuid -Label "support host interface")
        host_interface_index = $interfaceIndex
        host_mac_address = ConvertTo-Ferrum2CanonicalMacAddress `
            -Value ([string]$context.HostAdapter.MacAddress) -Label "support host interface"
        host_ipv4 = [string]$expectedAddresses[0].IPAddress
        prefix_length = [int]$expectedAddresses[0].PrefixLength
        network = [string]$Plan.support.network
        gateway = $null
        dns_servers = @()
        mtu_bytes = [int]$ipInterfaces[0].NlMtu
        nat_enabled = $false
        ics_enabled = $false
        selected_source_ipv4 = [string]$sourceRows[0].IPAddress
        selected_route_prefix = [string]$routeRows[0].DestinationPrefix
        selected_route_next_hop = [string]$routeRows[0].NextHop
    }
}

function Get-ValidatedSupportVmAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SupportSwitchId,
        [Parameter(Mandatory = $true)][string]$SupportAdapterId,
        [Parameter(Mandatory = $true)][Guid[]]$VirtualSystemIdentifiers
    )

    $vm = (Get-Ferrum2PinnedVmContext `
        -Identity (New-Ferrum2PinnedVmIdentity -Plan $Plan)).Vm
    $management = Get-ManagementAdapter -Vm $vm -Plan $Plan
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    $support = @($adapters | Where-Object { [string]$_.Id -ieq $SupportAdapterId })
    $expectedVirtualSystemIdentifiers = @($VirtualSystemIdentifiers | ForEach-Object {
        $_.ToString("D")
    } | Sort-Object)
    $actualVirtualSystemIdentifiers = if ($support.Count -eq 1) {
        @($support[0].VirtualSystemIdentifiers | ForEach-Object {
            (ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label "support VM adapter identifier")
        } | Sort-Object)
    } else {
        @()
    }
    $switchVmAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
        $_.SwitchId -eq $SupportSwitchId -and $_.IsManagementOs -ne $true
    })
    if ($adapters.Count -ne 2 -or $support.Count -ne 1 -or
        $expectedVirtualSystemIdentifiers.Count -ne 2 -or
        ($expectedVirtualSystemIdentifiers | Select-Object -Unique).Count -ne 2 -or
        ($actualVirtualSystemIdentifiers -join "|") -cne
            ($expectedVirtualSystemIdentifiers -join "|") -or
        $switchVmAttachments.Count -ne 1 -or
        [string]$switchVmAttachments[0].Id -ine $SupportAdapterId -or
        [string]$support[0].Name -cne [string]$Plan.support.vm_adapter_name -or
        $support[0].SwitchId -ne $SupportSwitchId -or
        [string]$support[0].SwitchName -cne [string]$Plan.support.switch_name -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$support[0].MacAddress) `
            -Label "support VM adapter") -cne
            (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$Plan.support.vm_mac_address) `
                -Label "planned support VM adapter") -or
        $support[0].DynamicMacAddressEnabled -ne $false -or
        $support[0].Connected -ne $true -or [string]$management.Id -ieq $SupportAdapterId) {
        throw "support VM adapter contract is invalid"
    }
    return $support[0]
}
