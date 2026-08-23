#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines fail-closed, read-only host checks for the Windows TUN performance path.

.DESCRIPTION
This file is dot-sourced by run_windows_tun_performance_hyperv.ps1 after that runner defines
Resolve-ExternalFile and Get-ApprovedVmContext. The checks never modify a host adapter, address,
route, DNS setting, firewall rule, WFP object, or TUN session.
#>

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

function Get-SelectedIpv4Route {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $selection = @(Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop)
    $sourceRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["IPAddress"]
    })
    $routeRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["DestinationPrefix"]
    })
    if ($sourceRows.Count -ne 1 -or $routeRows.Count -ne 1) {
        throw "$Label route selection is not unique"
    }
    return [pscustomobject]@{ Source = $sourceRows[0]; Route = $routeRows[0] }
}

function Get-HostSupportContext {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ProcessOwner,
        [Parameter(Mandatory = $true)][int]$MinimumIpv4PacketBytes
    )
    $addressRows = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Address `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($addressRows.Count -ne 1 -or
        [string]$addressRows[0].IPAddress -cne $Address -or
        [string]$addressRows[0].AddressState -cne "Preferred") {
        throw "support address is not one unique preferred host IPv4 address"
    }
    $interfaceIndex = [int]$addressRows[0].InterfaceIndex
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        [int]$_.ifIndex -eq $interfaceIndex
    })
    $physicalAdapters = @(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop |
        Where-Object { [int]$_.ifIndex -eq $interfaceIndex })
    if ($adapters.Count -ne 1 -or $physicalAdapters.Count -ne 1 -or
        [string]$adapters[0].Status -cne "Up" -or
        $adapters[0].HardwareInterface -ne $true -or
        $adapters[0].Virtual -ne $false -or
        [string]$addressRows[0].InterfaceAlias -cne [string]$adapters[0].Name) {
        throw "support address must belong to one active physical host adapter"
    }
    $ipInterfaces = @(Get-NetIPInterface -AddressFamily IPv4 `
        -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop)
    if ($ipInterfaces.Count -ne 1 -or
        [string]$ipInterfaces[0].ConnectionState -cne "Connected" -or
        [int]$ipInterfaces[0].NlMtu -lt $MinimumIpv4PacketBytes) {
        throw "support physical IPv4 MTU cannot carry the support probe without fragmentation"
    }
    $localRoute = Get-SelectedIpv4Route -RemoteAddress $Address -Label "host support"
    if ([string]$localRoute.Source.IPAddress -cne $Address -or
        [string]$localRoute.Source.AddressState -cne "Preferred" -or
        [int]$localRoute.Source.InterfaceIndex -ne $interfaceIndex -or
        [string]$localRoute.Route.DestinationPrefix -cne "$Address/32" -or
        [string]$localRoute.Route.NextHop -cne "0.0.0.0" -or
        [string]$localRoute.Route.State -cne "Alive" -or
        [string]$localRoute.Route.Protocol -cne "Local" -or
        [int]$localRoute.Route.InterfaceIndex -ne $interfaceIndex) {
        throw "support address is not selected as a physical host-local route"
    }

    $processRows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter ("ProcessId = {0}" -f $ProcessId) -ErrorAction Stop)
    if ($processRows.Count -ne 1) {
        throw "support process identity is not unique"
    }
    $owner = Invoke-CimMethod -InputObject $processRows[0] -MethodName GetOwner `
        -ErrorAction Stop
    $ownerIdentity = "$($owner.Domain)/$($owner.User)"
    if ([uint32]$owner.ReturnValue -ne 0 -or $ownerIdentity -cne $ProcessOwner) {
        throw "support process owner identity mismatch"
    }
    $executable = Resolve-ExternalFile -Path ([string]$processRows[0].ExecutablePath) `
        -Label "support executable" -MaximumBytes 536870912

    $tcpRows = @(Get-NetTCPConnection -State Listen -OwningProcess $ProcessId `
        -ErrorAction SilentlyContinue)
    if ($tcpRows.Count -ne 1 -or
        [string]$tcpRows[0].LocalAddress -cne $Address -or
        [int]$tcpRows[0].LocalPort -ne $TcpPort) {
        throw "support TCP listener binding is not exact"
    }
    $udpRows = @(Get-NetUDPEndpoint -OwningProcess $ProcessId -ErrorAction SilentlyContinue)
    if ($udpRows.Count -ne 4) {
        throw "support UDP listener count is not exactly four"
    }
    foreach ($port in $UdpPort..($UdpPort + 3)) {
        $portRows = @($udpRows | Where-Object {
            [string]$_.LocalAddress -ceq $Address -and [int]$_.LocalPort -eq $port
        })
        if ($portRows.Count -ne 1) {
            throw "support UDP listener binding is not exact: port=$port"
        }
    }

    return [pscustomobject][ordered]@{
        ipv4 = $Address
        interface_index = $interfaceIndex
        interface_alias = [string]$adapters[0].Name
        interface_mtu_bytes = [int]$ipInterfaces[0].NlMtu
        tcp_port = $TcpPort
        udp_port = $UdpPort
        pid = $ProcessId
        owner = $ownerIdentity
        executable = $executable
        executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        creation_utc = $processRows[0].CreationDate.ToUniversalTime().ToString("o")
    }
}

function Assert-HostSupportContextUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )
    foreach ($field in @(
        "ipv4", "interface_index", "interface_alias", "interface_mtu_bytes", "tcp_port",
        "udp_port", "pid", "owner", "executable", "executable_sha256", "creation_utc"
    )) {
        if ([string]$Expected.$field -cne [string]$Actual.$field) {
            throw "support listener context changed: field=$field"
        }
    }
}

function Get-ApprovedVmNetworkContext {
    param([Parameter(Mandatory = $true)][int]$MinimumIpv4PacketBytes)

    $context = Get-ApprovedVmContext
    $vmAdapters = @(Get-VMNetworkAdapter -VM $context.Vm -ErrorAction Stop)
    if ($vmAdapters.Count -ne 1 -or $vmAdapters[0].Connected -ne $true -or
        [string]$vmAdapters[0].SwitchName -cne $script:approvedVmSwitchName) {
        throw "approved VM is not connected to its unique approved switch"
    }
    $switches = @(Get-VMSwitch -Id $vmAdapters[0].SwitchId -ErrorAction Stop)
    if ($switches.Count -ne 1 -or
        [string]$switches[0].Name -cne $script:approvedVmSwitchName -or
        [string]$switches[0].SwitchType -cne "Internal" -or
        $switches[0].AllowManagementOS -ne $true) {
        throw "approved VM switch identity is invalid"
    }
    $managementAdapters = @(Get-VMNetworkAdapter -ManagementOS `
        -SwitchName $script:approvedVmSwitchName -ErrorAction Stop)
    if ($managementAdapters.Count -ne 1) {
        throw "approved switch management adapter identity is not unique"
    }
    $managementGuid = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$managementAdapters[0].DeviceId, [ref]$managementGuid)) {
        throw "approved switch management adapter GUID is invalid"
    }
    $hostAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        ([Guid][string]$_.InterfaceGuid) -eq $managementGuid
    })
    if ($hostAdapters.Count -ne 1 -or
        [string]$hostAdapters[0].Status -cne "Up" -or
        $hostAdapters[0].HardwareInterface -ne $false -or
        $hostAdapters[0].Virtual -ne $true) {
        throw "approved switch host adapter is not uniquely active"
    }
    $hostIpInterfaces = @(Get-NetIPInterface -AddressFamily IPv4 `
        -InterfaceIndex ([int]$hostAdapters[0].ifIndex) -PolicyStore ActiveStore `
        -ErrorAction Stop)
    if ($hostIpInterfaces.Count -ne 1 -or
        [string]$hostIpInterfaces[0].ConnectionState -cne "Connected" -or
        [int]$hostIpInterfaces[0].NlMtu -lt $MinimumIpv4PacketBytes) {
        throw "approved switch IPv4 MTU cannot carry the support probe without fragmentation"
    }
    return [pscustomobject][ordered]@{
        vm_mac_address = ConvertTo-CanonicalMacAddress `
            -Value ([string]$vmAdapters[0].MacAddress) -Label "approved VM"
        switch_id = ([Guid][string]$switches[0].Id).ToString("D")
        switch_name = [string]$switches[0].Name
        host_interface_index = [int]$hostAdapters[0].ifIndex
        host_interface_alias = [string]$hostAdapters[0].Name
        host_interface_guid = ([Guid][string]$hostAdapters[0].InterfaceGuid).ToString("D")
        host_interface_mtu_bytes = [int]$hostIpInterfaces[0].NlMtu
    }
}

function Assert-ApprovedVmNetworkContextUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )
    foreach ($field in @(
        "vm_mac_address", "switch_id", "switch_name", "host_interface_index",
        "host_interface_alias", "host_interface_guid", "host_interface_mtu_bytes"
    )) {
        if ([string]$Expected.$field -cne [string]$Actual.$field) {
            throw "approved VM network context changed: field=$field"
        }
    }
}

function Get-HostGuestReturnPath {
    param(
        [Parameter(Mandatory = $true)][object]$GuestPath,
        [Parameter(Mandatory = $true)][object]$VmNetworkContext,
        [Parameter(Mandatory = $true)][string]$ExpectedSupportIpv4
    )
    $expectedFields = @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_mtu_bytes",
        "guest_mac_address",
        "guest_route_prefix", "guest_route_next_hop", "guest_dns_ipv4"
    )
    if ((@($GuestPath.PSObject.Properties.Name) -join "|") -cne
        ($expectedFields -join "|") -or
        [int]$GuestPath.schema -ne 1 -or
        [string]$GuestPath.support_ipv4 -cne $ExpectedSupportIpv4 -or
        [string]$GuestPath.guest_route_prefix -cne "0.0.0.0/0") {
        throw "guest support path evidence shape or identity is invalid"
    }
    $guestAddress = [string]$GuestPath.guest_ipv4
    $parsedGuest = $null
    if (-not [Net.IPAddress]::TryParse($guestAddress, [ref]$parsedGuest) -or
        $parsedGuest.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($parsedGuest) -or
        [int]$GuestPath.guest_interface_index -le 0 -or
        [int]$GuestPath.guest_prefix_length -lt 1 -or
        [int]$GuestPath.guest_prefix_length -gt 32 -or
        [string]::IsNullOrWhiteSpace([string]$GuestPath.guest_interface_alias)) {
        throw "guest support path source identity is invalid"
    }
    if (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $guestAddress `
            -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "guest underlay address is unexpectedly host-local"
    }
    $guestMac = ConvertTo-CanonicalMacAddress -Value ([string]$GuestPath.guest_mac_address) `
        -Label "guest underlay"
    if ($guestMac -cne [string]$VmNetworkContext.vm_mac_address) {
        throw "guest underlay MAC does not match the approved VM adapter"
    }
    if (@($GuestPath.guest_dns_ipv4) -ccontains $ExpectedSupportIpv4 -or
        [string]$GuestPath.guest_route_next_hop -ceq $ExpectedSupportIpv4) {
        throw "support address collides with guest gateway or DNS state"
    }

    $returnRoute = Get-SelectedIpv4Route -RemoteAddress $guestAddress `
        -Label "host return"
    $source = $returnRoute.Source
    $route = $returnRoute.Route
    if ([string]$source.AddressFamily -cne "IPv4" -or
        [string]$source.AddressState -cne "Preferred" -or
        [string]$route.AddressFamily -cne "IPv4" -or
        [string]$route.State -cne "Alive" -or
        [string]$route.Protocol -cne "Local" -or
        [string]$route.DestinationPrefix -ceq "0.0.0.0/0" -or
        [string]$route.NextHop -cne "0.0.0.0" -or
        [int]$source.InterfaceIndex -ne [int]$VmNetworkContext.host_interface_index -or
        [int]$route.InterfaceIndex -ne [int]$VmNetworkContext.host_interface_index) {
        throw "host return path is not the approved switch's direct local route"
    }
    $allowedNeighborStates = @("Reachable", "Stale", "Delay", "Probe", "Permanent")
    $neighbor = $null
    $neighborDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 `
            -InterfaceIndex ([int]$VmNetworkContext.host_interface_index) `
            -IPAddress $guestAddress -ErrorAction SilentlyContinue)
        if ($neighbors.Count -eq 1 -and
            $allowedNeighborStates -ccontains [string]$neighbors[0].State) {
            $neighborMac = ([string]$neighbors[0].LinkLayerAddress `
                -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($neighborMac -cmatch '^[0-9A-F]{12}$' -and
                $neighborMac -cne "000000000000" -and $neighborMac -ceq $guestMac) {
                $neighbor = $neighbors[0]
                break
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $neighborDeadline)
    if ($null -eq $neighbor) {
        throw "host return-path neighbor does not match the approved VM"
    }
    return [pscustomobject][ordered]@{
        guest_ipv4 = $guestAddress
        source_ipv4 = [string]$source.IPAddress
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        protocol = [string]$route.Protocol
        interface_index = [int]$route.InterfaceIndex
        interface_alias = [string]$route.InterfaceAlias
        interface_mtu_bytes = [int]$VmNetworkContext.host_interface_mtu_bytes
        neighbor_state = [string]$neighbor.State
        neighbor_mac_address = $guestMac
    }
}
