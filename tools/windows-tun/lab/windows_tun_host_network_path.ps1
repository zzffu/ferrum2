#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines fail-closed, read-only host checks shared by Windows TUN host controllers.

.DESCRIPTION
The caller imports Ferrum2.WindowsTun.Lab before dot-sourcing this file. The checks never modify a
host adapter, address, route, DNS setting, firewall rule, WFP object, or TUN session.
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
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][object]$TopologyDocument,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ProcessOwner,
        [Parameter(Mandatory = $true)][int]$MinimumIpv4PacketBytes
    )
    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $TopologyDocument
    $approved = $TopologyDocument.Value.support.switch
    if ($Address -cne [string]$approved.host_ipv4) {
        throw "support listener address does not match the topology manifest"
    }
    $addressRows = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Address `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($addressRows.Count -ne 1 -or
        [string]$addressRows[0].IPAddress -cne $Address -or
        [string]$addressRows[0].AddressState -cne "Preferred" -or
        [int]$addressRows[0].PrefixLength -ne [int]$approved.prefix_length) {
        throw "support address is not one unique preferred host IPv4 address"
    }
    $interfaceIndex = [int]$addressRows[0].InterfaceIndex
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        [int]$_.ifIndex -eq $interfaceIndex
    })
    if ($adapters.Count -ne 1 -or
        [string]$adapters[0].Status -cne "Up" -or
        $adapters[0].HardwareInterface -ne $false -or
        $adapters[0].Virtual -ne $true -or
        [string]$addressRows[0].InterfaceAlias -cne [string]$adapters[0].Name -or
        [string]$adapters[0].Name -cne [string]$approved.host_interface_alias -or
        ([Guid][string]$adapters[0].InterfaceGuid).ToString("D") -cne
            [string]$approved.host_interface_guid -or
        $interfaceIndex -ne [int]$approved.host_interface_index -or
        (ConvertTo-CanonicalMacAddress -Value ([string]$adapters[0].MacAddress) `
            -Label "support host") -cne [string]$approved.host_mac_address) {
        throw "support address must belong to the exact active manifest host adapter"
    }
    $ipInterfaces = @(Get-NetIPInterface -AddressFamily IPv4 `
        -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop)
    if ($ipInterfaces.Count -ne 1 -or
        [string]$ipInterfaces[0].ConnectionState -cne "Connected" -or
        [int]$ipInterfaces[0].NlMtu -lt $MinimumIpv4PacketBytes -or
        [int]$ipInterfaces[0].NlMtu -ne [int]$approved.mtu_bytes) {
        throw "support Internal-switch IPv4 MTU cannot carry the support probe"
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
        throw "support address is not selected as the manifest host-local route"
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
    $executable = Resolve-Ferrum2HostInput `
        -RepositoryRoot $RepositoryRoot `
        -Path ([string]$processRows[0].ExecutablePath) `
        -Label "support executable" `
        -Kind ExternalFile `
        -MaximumBytes 536870912

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
        interface_guid = ([Guid][string]$adapters[0].InterfaceGuid).ToString("D")
        interface_mac_address = ConvertTo-CanonicalMacAddress `
            -Value ([string]$adapters[0].MacAddress) -Label "support host"
        interface_mtu_bytes = [int]$ipInterfaces[0].NlMtu
        tcp_port = $TcpPort
        udp_port = $UdpPort
        pid = $ProcessId
        owner = $ownerIdentity
        executable = $executable
        executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        creation_utc = $processRows[0].CreationDate.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture
        )
        topology_manifest_sha256 = [string]$TopologyDocument.Sha256
    }
}

function Assert-HostSupportContextUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )
    foreach ($field in @(
        "ipv4", "interface_index", "interface_alias", "interface_guid",
        "interface_mac_address", "interface_mtu_bytes", "tcp_port", "udp_port", "pid",
        "owner", "executable", "executable_sha256", "creation_utc",
        "topology_manifest_sha256"
    )) {
        if ([string]$Expected.$field -cne [string]$Actual.$field) {
            throw "support listener context changed: field=$field"
        }
    }
}

function Get-ApprovedVmNetworkContext {
    param(
        [Parameter(Mandatory = $true)][object]$TopologyDocument,
        [Parameter(Mandatory = $true)][int]$MinimumIpv4PacketBytes
    )

    $context = Get-Ferrum2ApprovedHyperVTopologyContext `
        -Document $TopologyDocument -ReadinessTimeoutSeconds 10
    $manifest = $TopologyDocument.Value
    if ([int]$context.SupportHost.mtu_bytes -lt $MinimumIpv4PacketBytes) {
        throw "approved support switch MTU cannot carry the support probe"
    }
    return [pscustomobject][ordered]@{
        vm_mac_address = ConvertTo-CanonicalMacAddress `
            -Value ([string]$context.SupportVmAdapter.MacAddress) -Label "approved support VM"
        vm_adapter_id = [string]$context.SupportVmAdapter.Id
        switch_id = ([Guid][string]$context.SupportSwitch.Id).ToString("D")
        switch_name = [string]$context.SupportSwitch.Name
        network = [string]$manifest.support.guest.network
        guest_ipv4 = [string]$manifest.support.guest.guest_ipv4
        guest_prefix_length = [int]$manifest.support.guest.prefix_length
        guest_interface_alias = [string]$manifest.support.guest.support_interface_alias
        guest_interface_guid = [string]$manifest.support.guest.support_interface_guid
        guest_interface_index = [int]$manifest.support.guest.support_interface_index
        guest_interface_mtu_bytes = [int]$manifest.support.guest.mtu_bytes
        host_ipv4 = [string]$context.SupportHost.host_ipv4
        host_interface_index = [int]$context.SupportHost.host_interface_index
        host_interface_alias = [string]$context.SupportHost.host_interface_alias
        host_interface_guid = [string]$context.SupportHost.host_interface_guid
        host_interface_mtu_bytes = [int]$context.SupportHost.mtu_bytes
        topology_manifest_sha256 = [string]$TopologyDocument.Sha256
    }
}

function Assert-ApprovedVmNetworkContextUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )
    foreach ($field in @(
        "vm_mac_address", "vm_adapter_id", "switch_id", "switch_name", "network",
        "guest_ipv4", "guest_prefix_length", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_index", "guest_interface_mtu_bytes", "host_ipv4",
        "host_interface_index", "host_interface_alias",
        "host_interface_guid", "host_interface_mtu_bytes", "topology_manifest_sha256"
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
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes",
        "guest_mac_address",
        "guest_route_prefix", "guest_route_next_hop", "guest_dns_servers"
    )
    if ((@($GuestPath.PSObject.Properties.Name) -join "|") -cne
        ($expectedFields -join "|") -or
        [int]$GuestPath.schema -ne 2 -or
        [string]$GuestPath.support_ipv4 -cne $ExpectedSupportIpv4 -or
        [string]$GuestPath.guest_route_prefix -cne [string]$VmNetworkContext.network -or
        [string]$GuestPath.guest_route_next_hop -cne "0.0.0.0" -or
        [string]$GuestPath.guest_ipv4 -cne [string]$VmNetworkContext.guest_ipv4 -or
        [int]$GuestPath.guest_prefix_length -ne
            [int]$VmNetworkContext.guest_prefix_length -or
        [string]$GuestPath.guest_interface_alias -cne
            [string]$VmNetworkContext.guest_interface_alias -or
        ([Guid][string]$GuestPath.guest_interface_guid).ToString("D") -cne
            ([Guid][string]$VmNetworkContext.guest_interface_guid).ToString("D") -or
        [int]$GuestPath.guest_interface_index -ne
            [int]$VmNetworkContext.guest_interface_index -or
        [int]$GuestPath.guest_interface_mtu_bytes -ne
            [int]$VmNetworkContext.guest_interface_mtu_bytes -or
        @($GuestPath.guest_dns_servers).Count -ne 0) {
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
    $returnRoute = Get-SelectedIpv4Route -RemoteAddress $guestAddress `
        -Label "host return"
    $source = $returnRoute.Source
    $route = $returnRoute.Route
    if ([string]$source.AddressFamily -cne "IPv4" -or
        [string]$source.AddressState -cne "Preferred" -or
        [string]$route.AddressFamily -cne "IPv4" -or
        [string]$route.State -cne "Alive" -or
        [string]$route.Protocol -cne "Local" -or
        [string]$source.IPAddress -cne [string]$VmNetworkContext.host_ipv4 -or
        [string]$route.DestinationPrefix -cne [string]$VmNetworkContext.network -or
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
