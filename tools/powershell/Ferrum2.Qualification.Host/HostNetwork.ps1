Set-StrictMode -Version Latest

function New-Ferrum2HostNetworkIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    if ($RunId -cnotmatch '^[0-9a-f]{12}$') { throw 'network RunId is invalid' }
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    $AddressFamily = $profile.address_family
    if ($AddressFamily -ceq 'IPv6') {
        $prefix = 'fd00:' + $RunId.Substring(0, 4) + ':' +
            $RunId.Substring(4, 4) + ':' + $RunId.Substring(8, 4)
        $tun = ([Net.IPAddress]::Parse("${prefix}::2")).ToString()
        $peer = ([Net.IPAddress]::Parse("${prefix}::1")).ToString()
        $support = ([Net.IPAddress]::Parse("${prefix}:1::1")).ToString()
        $reset = ([Net.IPAddress]::Parse("${prefix}:1::2")).ToString()
    } else {
        $value = [Convert]::ToUInt32($RunId.Substring(0, 4), 16)
        $third = [int](($value -shr 8) -band 0xff)
        $block = [int](($value -band 0xff) % 63) * 4
        $tun = "198.18.$third.$($block + 2)"
        $peer = "198.18.$third.$($block + 1)"
        $support = "198.19.$third.$($block + 1)"
        $reset = "198.19.$third.$($block + 2)"
    }
    return [pscustomobject][ordered]@{
        address_family = $AddressFamily
        tun_address = $tun
        tun_prefix_length = $profile.tun_prefix_length
        peer_address = $peer
        support_address = $support
        support_prefix_length = $profile.host_prefix_length
        reset_address = $reset
        host_prefix_length = $profile.host_prefix_length
        adapter_name_prefix = "Ferrum2Host-$RunId"
    }
}

function Get-Ferrum2LoopbackIdentity {
    param([ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4')
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    $AddressFamily = $profile.address_family
    $address = @(Get-NetIPAddress -AddressFamily $AddressFamily `
        -IPAddress $profile.loopback_address -ErrorAction Stop)
    if ($address.Count -ne 1) { throw "host loopback $AddressFamily identity is not unique" }
    $interface = @(Get-NetIPInterface -AddressFamily $AddressFamily `
        -InterfaceIndex $address[0].InterfaceIndex -ErrorAction Stop)
    if ($interface.Count -ne 1 -or [string]$interface[0].InterfaceAlias -cnotlike 'Loopback*') {
        throw 'host loopback interface identity is not unique'
    }
    return [pscustomobject][ordered]@{
        address_family = $AddressFamily
        interface_index = [uint32]$interface[0].InterfaceIndex
        interface_alias = [string]$interface[0].InterfaceAlias
        interface_guid = $null
        local_address = $profile.loopback_address
    }
}

function Get-Ferrum2NetworkInventory {
    param([ValidateSet('IPv4', 'IPv6')][string]$AddressFamily)
    $addresses = @(Get-NetIPAddress -AddressFamily $AddressFamily -PolicyStore ActiveStore -ErrorAction Stop)
    $routes = @(Get-NetRoute -AddressFamily $AddressFamily -PolicyStore ActiveStore -ErrorAction Stop)
    if ($addresses.Count -gt 16384 -or $routes.Count -gt 65536) {
        throw 'network inventory exceeds its identity bound'
    }
    return [pscustomobject]@{ addresses = $addresses; routes = $routes }
}

function Assert-Ferrum2HostNetworkIdentityAvailable {
    param(
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $Network.address_family
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $profile.address_family
    $owned = @($Network.tun_address, $Network.peer_address, $Network.support_address, $Network.reset_address)
    foreach ($address in $owned) {
        Assert-Ferrum2CanonicalAddress -Address $address -AddressFamily $profile.address_family
        if (@($inventory.addresses | Where-Object IPAddress -CEQ $address).Count -ne 0) {
            throw "dedicated benchmark address already exists: $address"
        }
        $addressBytes = ([Net.IPAddress]::Parse($address)).GetAddressBytes()
        foreach ($route in $inventory.routes) {
            $parts = ([string]$route.DestinationPrefix).Split('/')
            if ($parts.Count -ne 2) { throw 'route prefix readback is invalid' }
            $bits = [int]$parts[1]
            # Defaults are not conflicts and are never changed by this runner.
            if ($bits -eq 0) { continue }
            $prefixBytes = ([Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
            if ($bits -lt 0 -or $bits -gt $addressBytes.Length * 8 -or
                $prefixBytes.Length -ne $addressBytes.Length) { throw 'route family readback is invalid' }
            $matches = $true
            for ($i = 0; $i -lt $addressBytes.Length -and $bits -gt 0; $i++) {
                $take = [Math]::Min(8, $bits)
                $mask = (255 -shl (8 - $take)) -band 255
                if (($addressBytes[$i] -band $mask) -ne ($prefixBytes[$i] -band $mask)) { $matches = $false; break }
                $bits -= $take
            }
            if ($matches) { throw "route conflicts with dedicated benchmark identity: $($route.DestinationPrefix)" }
        }
    }
    if ($Loopback.interface_index -eq 0 -or $Loopback.local_address -cne $profile.loopback_address -or
        $Loopback.address_family -cne $profile.address_family) { throw 'loopback identity is invalid' }
}

function Assert-Ferrum2OwnedNetworkRow {
    param([object]$Row, [string]$RunId, [string]$AddressFamily,
        [ValidateSet('address', 'route')][string]$Type)
    $network = New-Ferrum2HostNetworkIdentity -RunId $RunId -AddressFamily $AddressFamily
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    foreach ($entry in @(@('address_family', $AddressFamily), @('run_id', $RunId))) {
        $property = $Row.PSObject.Properties[$entry[0]]
        if ($null -ne $property -and [string]$property.Value -cne $entry[1]) {
            throw 'owned network family or run identity mismatch'
        }
    }
    if ([uint32]$Row.interface_index -eq 0 -or [string]$Row.state -notin @('planned', 'created')) {
        throw 'owned network interface or state is invalid'
    }
    if ($Type -ceq 'address') {
        Assert-Ferrum2CanonicalAddress -Address $Row.address -AddressFamily $AddressFamily
        if (-not (
            ([string]$Row.address -ceq $network.support_address -and
                [int]$Row.prefix_length -eq $profile.host_prefix_length) -or
            ([string]$Row.address -ceq $network.tun_address -and
                [int]$Row.prefix_length -eq $profile.tun_prefix_length))) {
            throw 'owned address is outside exact run scope'
        }
        if ([string]$Row.address -ceq $network.tun_address -and (
            $null -eq $Row.PSObject.Properties['interface_guid'] -or
            [string]::IsNullOrEmpty([string]$Row.interface_guid))) {
            throw 'TUN address requires durable adapter ownership'
        }
    } else {
        $parts = ([string]$Row.destination_prefix).Split('/')
        if ($parts.Count -ne 2) { throw 'owned route prefix is invalid' }
        Assert-Ferrum2CanonicalAddress -Address $parts[0] -AddressFamily $AddressFamily
        Assert-Ferrum2CanonicalAddress -Address $Row.next_hop -AddressFamily $AddressFamily
        if ([string]$Row.policy_store -cne 'ActiveStore') { throw 'owned route store is invalid' }
        if ([string]$Row.kind -cnotin @('runner', 'product', 'adapter-connected',
            'qualification-reset-baseline', 'qualification-reset-change')) { throw 'owned route kind is invalid' }
        $allowed = @("$($network.support_address)/$($profile.host_prefix_length)",
            "$($network.reset_address)/$($profile.host_prefix_length)")
        if ([string]$Row.kind -ceq 'adapter-connected') {
            $bytes = ([Net.IPAddress]::Parse($network.tun_address)).GetAddressBytes()
            $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -band 252
            $allowed = @("$([Net.IPAddress]::new($bytes).ToString())/$($profile.tun_prefix_length)")
            if ($null -eq $Row.PSObject.Properties['interface_guid'] -or
                [string]::IsNullOrEmpty([string]$Row.interface_guid)) {
                throw 'connected route requires durable adapter ownership'
            }
        }
        if ([string]$Row.destination_prefix -cnotin $allowed) { throw 'owned route is outside exact run scope' }
        if ([string]$Row.next_hop -cne $profile.unspecified_address -and -not (
            $AddressFamily -ceq 'IPv4' -and [string]$Row.kind -ceq 'qualification-reset-baseline' -and
            [string]$Row.destination_prefix -ceq "$($network.reset_address)/32" -and
            -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($Row.next_hop)))) {
            throw 'owned route next hop is not authorized'
        }
    }
}

function Get-Ferrum2OwnedInterfaceBinding {
    param([uint32]$InterfaceIndex, [string]$AddressFamily)
    $loopback = Get-Ferrum2LoopbackIdentity -AddressFamily $AddressFamily
    if ($InterfaceIndex -eq $loopback.interface_index) { return $null }
    $inventory = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    if ($inventory.Count -gt 4096) { throw 'adapter inventory exceeds its identity bound' }
    $adapters = @($inventory | Where-Object { [uint32]$_.ifIndex -eq $InterfaceIndex })
    if ($adapters.Count -ne 1 -or [Guid]$adapters[0].InterfaceGuid -eq [Guid]::Empty) {
        throw 'owned network adapter GUID is unavailable'
    }
    return ([Guid]$adapters[0].InterfaceGuid).ToString('D').ToLowerInvariant()
}

function Assert-Ferrum2OwnedInterfaceBinding {
    param([object]$Row)
    $actual = Get-Ferrum2OwnedInterfaceBinding -InterfaceIndex $Row.interface_index -AddressFamily $Row.address_family
    if ([string]$actual -cne [string]$Row.interface_guid) { throw 'owned network interface was replaced' }
}

function Add-Ferrum2OwnedAddress {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$PrefixLength
    )
    $family = Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger
    $currentLoopback = Get-Ferrum2LoopbackIdentity -AddressFamily $family
    if ($Loopback.interface_index -ne $currentLoopback.interface_index -or
        $Loopback.local_address -cne $currentLoopback.local_address -or
        $null -ne $Loopback.interface_guid) { throw 'owned address requires the existing selected-family loopback' }
    $row = [pscustomobject][ordered]@{
        address_family = $family
        run_id = $Context.run_id
        address = $Address
        prefix_length = $PrefixLength
        interface_index = $Loopback.interface_index
        interface_guid = $Loopback.interface_guid
        state = "planned"
    }
    Assert-Ferrum2OwnedNetworkRow -Row $row -RunId $Context.run_id -AddressFamily $family -Type address
    $network = New-Ferrum2HostNetworkIdentity -RunId $Context.run_id -AddressFamily $family
    if ($Address -cne $network.support_address) { throw 'runner may add only the exact support address' }
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $family
    if (@($inventory.addresses | Where-Object IPAddress -CEQ $Address).Count -ne 0) {
        throw 'owned address baseline is not absent'
    }
    $Context.ledger.resources.addresses = @($Context.ledger.resources.addresses) + @($row)
    Write-Ferrum2HostLedger -Context $Context
    New-NetIPAddress -AddressFamily $family -InterfaceIndex $Loopback.interface_index `
        -IPAddress $Address -PrefixLength $PrefixLength -SkipAsSource $true `
        -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $row.state = "created"
    Write-Ferrum2HostLedger -Context $Context
    return $row
}

function Add-Ferrum2OwnedRoute {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][uint32]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$DestinationPrefix,
        [Parameter(Mandatory = $true)][uint16]$RouteMetric,
        [string]$Kind = "runner",
        [string]$NextHop
    )
    $family = Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger
    if ([string]::IsNullOrEmpty($NextHop)) {
        $NextHop = (Get-Ferrum2AddressFamilyProfile -AddressFamily $family).unspecified_address
    }
    $row = [pscustomobject][ordered]@{
        address_family = $family
        run_id = $Context.run_id
        interface_guid = Get-Ferrum2OwnedInterfaceBinding -InterfaceIndex $InterfaceIndex -AddressFamily $family
        destination_prefix = $DestinationPrefix
        interface_index = $InterfaceIndex
        next_hop = $NextHop
        route_metric = $RouteMetric
        policy_store = "ActiveStore"
        kind = $Kind
        state = "planned"
    }
    if ($Kind -cnotin @('runner', 'qualification-reset-baseline', 'qualification-reset-change')) {
        throw 'runner route kind is invalid'
    }
    Assert-Ferrum2OwnedNetworkRow -Row $row -RunId $Context.run_id -AddressFamily $family -Type route
    $network = New-Ferrum2HostNetworkIdentity -RunId $Context.run_id -AddressFamily $family
    $loopback = Get-Ferrum2LoopbackIdentity -AddressFamily $family
    if ($Kind -cnotin @('qualification-reset-baseline', 'qualification-reset-change') -or
        $family -ceq 'IPv6') {
        if ($InterfaceIndex -ne $loopback.interface_index -and (
            $null -eq $Context.ledger.resources.adapter -or
            [string]$Context.ledger.resources.adapter.state -cne 'created' -or
            [uint32]$Context.ledger.resources.adapter.interface_index -ne $InterfaceIndex -or
            [string]$Context.ledger.resources.adapter.interface_guid -cne [string]$row.interface_guid)) {
            throw 'runner route interface is not run-owned or loopback'
        }
    }
    if ($Kind -ceq 'qualification-reset-change') {
        $baselines = @($Context.ledger.expected_resources.routes | Where-Object {
            [string]$_.kind -ceq 'qualification-reset-baseline' -and
            [string]$_.state -ceq 'created' -and
            [string]$_.destination_prefix -ceq $DestinationPrefix -and
            [uint32]$_.interface_index -eq $InterfaceIndex -and
            [string]$_.interface_guid -ceq [string]$row.interface_guid -and
            [uint16]$_.route_metric -eq 4094
        })
        if ($baselines.Count -ne 1 -or $RouteMetric -ne 4093) {
            throw 'reset change requires its exact retired baseline interface and metric'
        }
    }
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $family
    if (@($inventory.routes | Where-Object {
        [string]$_.DestinationPrefix -ceq $DestinationPrefix -and
        [uint32]$_.InterfaceIndex -eq $InterfaceIndex
    }).Count -ne 0) { throw 'owned route baseline is not absent' }
    $Context.ledger.resources.routes = @($Context.ledger.resources.routes) + @($row)
    Write-Ferrum2HostLedger -Context $Context
    New-NetRoute -AddressFamily $family -InterfaceIndex $InterfaceIndex `
        -DestinationPrefix $DestinationPrefix -NextHop $NextHop `
        -RouteMetric $RouteMetric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $row.state = "created"
    Write-Ferrum2HostLedger -Context $Context
    return $row
}

function Remove-Ferrum2OwnedRoute {
    param([Parameter(Mandatory = $true)][object]$Row)
    Assert-Ferrum2OwnedNetworkRow -Row $Row -RunId $Row.run_id -AddressFamily $Row.address_family -Type route
    $routeState = [string]$Row.state
    if ($routeState -notin @("planned", "created")) {
        throw "owned route ledger state is invalid"
    }
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $Row.address_family
    $routes = @($inventory.routes | Where-Object {
        [string]$_.DestinationPrefix -ceq [string]$Row.destination_prefix -and
        [uint32]$_.InterfaceIndex -eq [uint32]$Row.interface_index
    })
    if ($routes.Count -gt 1) { throw "owned route identity is not unique" }
    if ($routes.Count -eq 1) {
        if ($routeState -cne "created") {
            throw "planned route presence is ambiguous; refusing removal"
        }
        if ([uint16]$routes[0].RouteMetric -ne [uint16]$Row.route_metric) {
            throw "owned route metric identity mismatch"
        }
        Assert-Ferrum2OwnedInterfaceBinding -Row $Row
        if ([string]$routes[0].NextHop -cne [string]$Row.next_hop) {
            throw "owned route next-hop identity mismatch"
        }
        Remove-NetRoute -InputObject $routes[0] -Confirm:$false -ErrorAction Stop
    }
}

function Set-Ferrum2OwnedAdapterPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$AdapterName
    )
    $network = New-Ferrum2HostNetworkIdentity -RunId $Context.run_id `
        -AddressFamily (Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger)
    if ($AdapterName -cnotmatch ('^' + [regex]::Escape($network.adapter_name_prefix) + '-00[1-3]$')) {
        throw 'adapter name is outside exact run scope'
    }
    $inventory = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    if ($inventory.Count -gt 4096) { throw 'adapter inventory exceeds its identity bound' }
    if (@($inventory | Where-Object Name -CEQ $AdapterName).Count -ne 0) {
        throw "owned adapter name baseline is not absent: $AdapterName"
    }
    $Context.ledger.resources.adapter = [pscustomobject][ordered]@{
        name = $AdapterName
        interface_guid = $null
        interface_index = $null
        interface_description = $null
        expected_interface_description = "Ferrum2 Tunnel"
        state = "planned"
    }
    Write-Ferrum2HostLedger -Context $Context
}

function Complete-Ferrum2OwnedAdapterIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$AdapterName
    )
    $adapter = @(Get-NetAdapter -IncludeHidden -Name $AdapterName -ErrorAction Stop)
    if ($adapter.Count -ne 1) {
        throw "owned Wintun adapter identity is not unique"
    }
    if ([string]$adapter[0].InterfaceDescription -cne "Ferrum2 Tunnel") {
        throw "owned adapter does not identify the Wintun driver"
    }
    $Context.ledger.resources.adapter.interface_guid =
        ([Guid]$adapter[0].InterfaceGuid).ToString("D").ToLowerInvariant()
    $Context.ledger.resources.adapter.interface_index = [uint32]$adapter[0].ifIndex
    $Context.ledger.resources.adapter.interface_description = [string]$adapter[0].InterfaceDescription
    $Context.ledger.resources.adapter.state = "created"
    Write-Ferrum2HostLedger -Context $Context
    $family = Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger
    $network = New-Ferrum2HostNetworkIdentity -RunId $Context.run_id -AddressFamily $family
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $family
    $bytes = ([Net.IPAddress]::Parse($network.tun_address)).GetAddressBytes()
    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -band 252
    $connectedPrefix = "$([Net.IPAddress]::new($bytes).ToString())/$($profile.tun_prefix_length)"
    # These are adapter-owned, not independent deletion permissions. Retain their exact
    # identities for readback even after successful product shutdown retires the adapter.
    $addressRow = [pscustomobject]@{
        run_id = $Context.run_id; address_family = $family
        address = $network.tun_address; prefix_length = $profile.tun_prefix_length
        interface_index = [uint32]$adapter[0].ifIndex
        interface_guid = $Context.ledger.resources.adapter.interface_guid; state = 'created'
    }
    $routeRow = [pscustomobject]@{
        run_id = $Context.run_id; address_family = $family
        destination_prefix = $connectedPrefix; next_hop = $profile.unspecified_address
        interface_index = [uint32]$adapter[0].ifIndex
        interface_guid = $Context.ledger.resources.adapter.interface_guid
        policy_store = 'ActiveStore'; kind = 'adapter-connected'; state = 'created'
    }
    Assert-Ferrum2OwnedNetworkRow -Row $addressRow -RunId $Context.run_id -AddressFamily $family -Type address
    Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $Context.run_id -AddressFamily $family -Type route
    $Context.ledger.expected_resources.addresses = @($Context.ledger.expected_resources.addresses) + @($addressRow)
    $Context.ledger.expected_resources.routes = @($Context.ledger.expected_resources.routes) + @($routeRow)
    Write-Ferrum2HostLedger -Context $Context
    return $adapter[0]
}

function Add-Ferrum2OwnedPort {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][uint16]$Port,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $family = Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $family
    $network = New-Ferrum2HostNetworkIdentity -RunId $Context.run_id -AddressFamily $family
    Assert-Ferrum2CanonicalAddress -Address $Address -AddressFamily $family
    if ($Protocol -cnotin @('tcp', 'udp') -or $Port -eq 0 -or
        $Address -cnotin @($profile.loopback_address, $network.support_address)) {
        throw 'owned endpoint is outside exact run scope'
    }
    $Context.ledger.resources.ports = @($Context.ledger.resources.ports) + @(
        [pscustomobject][ordered]@{
            address_family = $family
            run_id = $Context.run_id
            protocol = $Protocol
            address = $Address
            port = $Port
            purpose = $Purpose
        }
    )
    Write-Ferrum2HostLedger -Context $Context
}

function Remove-Ferrum2OwnedAddress {
    param([Parameter(Mandatory = $true)][object]$Row)
    Assert-Ferrum2OwnedNetworkRow -Row $Row -RunId $Row.run_id -AddressFamily $Row.address_family -Type address
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $Row.address_family
    $addresses = @($inventory.addresses | Where-Object {
        [string]$_.IPAddress -ceq [string]$Row.address -and
        [uint32]$_.InterfaceIndex -eq [uint32]$Row.interface_index
    })
    if ($addresses.Count -gt 1) { throw 'owned address identity is not unique' }
    if ($addresses.Count -eq 1) {
        if ([string]$Row.state -cne 'created') { throw 'planned address presence is ambiguous; refusing removal' }
        if ([int]$addresses[0].PrefixLength -ne [int]$Row.prefix_length) {
            throw 'owned address prefix identity mismatch'
        }
        Assert-Ferrum2OwnedInterfaceBinding -Row $Row
        Remove-NetIPAddress -InputObject $addresses[0] -Confirm:$false -ErrorAction Stop
    }
}

