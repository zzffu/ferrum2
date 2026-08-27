#requires -Version 7.4
#requires -RunAsAdministrator

param(
    [Parameter(Mandatory)] [string]$ManagementMac,
    [Parameter(Mandatory)] [string]$SupportMac,
    [Parameter(Mandatory)] [string]$SupportAlias,
    [Parameter(Mandatory)] [string]$GuestIpv4,
    [Parameter(Mandatory)] [int]$PrefixLength,
    [Parameter(Mandatory)] [string]$Network,
    [Parameter(Mandatory)] [string]$HostIpv4,
    [Parameter(Mandatory)]
    [ValidateSet('initial_configure', 'post_checkpoint_restore')]
    [string]$ValidationPhase,
    [Parameter(Mandatory)] [bool]$ShouldConfigure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:guestContract = [pscustomobject][ordered]@{
    ManagementMac = $ManagementMac
    SupportMac = $SupportMac
    SupportAlias = $SupportAlias
    GuestIpv4 = $GuestIpv4
    PrefixLength = $PrefixLength
    Network = $Network
    HostIpv4 = $HostIpv4
    ValidationPhase = $ValidationPhase
}


function ConvertTo-GuestCanonicalMac {
    param([Parameter(Mandatory)] [string]$Value)
    ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

function Get-GuestIpv4AddressRow {
    param(
        [Parameter(Mandatory)] [int]$InterfaceIndex,
        [Parameter(Mandatory)]
        [ValidateSet('ActiveStore', 'PersistentStore')]
        [string]$PolicyStore
    )
    try {
        @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -PolicyStore $PolicyStore -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq
                [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                'CmdletizationQuery_NotFound*,Get-NetIPAddress') {
            return @()
        }
        throw
    }
}

function Get-GuestIpv4RouteRow {
    param(
        [Parameter(Mandatory)] [int]$InterfaceIndex,
        [Parameter(Mandatory)]
        [ValidateSet('ActiveStore', 'PersistentStore')]
        [string]$PolicyStore,
        [string]$DestinationPrefix
    )
    $parameters = @{
        InterfaceIndex = $InterfaceIndex
        AddressFamily = 'IPv4'
        PolicyStore = $PolicyStore
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPrefix)) {
        $parameters.DestinationPrefix = $DestinationPrefix
    }
    try {
        @(Get-NetRoute @parameters)
    } catch {
        if ($_.CategoryInfo.Category -eq
                [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                'CmdletizationQuery_NotFound*,Get-NetRoute') {
            return @()
        }
        throw
    }
}

function Get-GuestSupportAdapterContext {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $management = @($adapters | Where-Object {
        (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $script:guestContract.ManagementMac
    })
    $support = @($adapters | Where-Object {
        (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $script:guestContract.SupportMac
    })
    if ($management.Count -ne 1 -or $support.Count -ne 1 -or
        [int]$management[0].ifIndex -eq [int]$support[0].ifIndex) {
        throw 'guest Hyper-V NIC identities are not unique'
    }
    [pscustomobject][ordered]@{
        Adapters = $adapters
        Management = $management[0]
        Support = $support[0]
    }
}

function Invoke-GuestSupportNetworkConfiguration {
    $context = Get-GuestSupportAdapterContext
    $aliasCollisions = @($context.Adapters | Where-Object {
        [string]$_.Name -ieq $script:guestContract.SupportAlias -and
        [int]$_.ifIndex -ne [int]$context.Support.ifIndex
    })
    if ($aliasCollisions.Count -ne 0) {
        throw 'guest support interface alias already belongs to another adapter'
    }
    if ([string]$context.Support.Name -cne $script:guestContract.SupportAlias) {
        $context.Support | Rename-NetAdapter -NewName $script:guestContract.SupportAlias -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }
    $context = Get-GuestSupportAdapterContext
    if ([string]$context.Support.Name -cne $script:guestContract.SupportAlias) {
        throw 'guest support interface rename lost the pinned MAC identity'
    }
    $supportIndex = [int]$context.Support.ifIndex
    Set-NetIPInterface -InterfaceIndex $supportIndex -AddressFamily IPv4 `
        -PolicyStore ActiveStore -Dhcp Disabled -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    Set-NetIPInterface -InterfaceIndex $supportIndex -AddressFamily IPv4 `
        -PolicyStore PersistentStore -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        foreach ($route in @(Get-GuestIpv4RouteRow -InterfaceIndex $supportIndex `
                -PolicyStore $store -DestinationPrefix '0.0.0.0/0')) {
            $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }
        foreach ($address in @(Get-GuestIpv4AddressRow -InterfaceIndex $supportIndex `
                -PolicyStore $store)) {
            $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        }
    }
    Set-DnsClientServerAddress -InterfaceIndex $supportIndex -ResetServerAddresses `
        -ErrorAction Stop | Out-Null
    $netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
    if (-not (Test-Path -LiteralPath $netshPath -PathType Leaf)) {
        throw 'netsh.exe is unavailable for guest support DNS cleanup'
    }
    foreach ($addressFamily in @('ipv4', 'ipv6')) {
        $output = @(& $netshPath interface $addressFamily set dnsservers `
            "name=$supportIndex" 'source=static' 'address=none' `
            'register=none' 'validate=no' 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "guest support $addressFamily DNS cleanup failed with exit " +
                "$LASTEXITCODE`: $($output -join ' ')"
        }
    }
    Set-DnsClient -InterfaceIndex $supportIndex `
        -RegisterThisConnectionsAddress:$false -UseSuffixWhenRegistering:$false `
        -ErrorAction Stop | Out-Null
    New-NetIPAddress -InterfaceIndex $supportIndex -IPAddress $script:guestContract.GuestIpv4 `
        -PrefixLength ([byte]$script:guestContract.PrefixLength) -AddressFamily IPv4 -Type Unicast `
        -ErrorAction Stop | Out-Null
}

function Get-GuestSupportNetworkState {
    $context = Get-GuestSupportAdapterContext
    if ([string]$context.Support.Name -cne $script:guestContract.SupportAlias -or
        [string]$context.Support.Status -cne 'Up' -or
        [string]$context.Management.Status -cne 'Up') {
        throw 'guest NIC identities or link state changed during support configuration'
    }
    $supportIndex = [int]$context.Support.ifIndex
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $addresses = @(Get-GuestIpv4AddressRow -InterfaceIndex $supportIndex `
            -PolicyStore ActiveStore)
        $expectedAddresses = @($addresses | Where-Object {
            [string]$_.IPAddress -ceq $script:guestContract.GuestIpv4 -and
            [int]$_.PrefixLength -eq $script:guestContract.PrefixLength -and
            [string]$_.AddressState -ceq 'Preferred'
        })
        if ($addresses.Count -eq 1 -and $expectedAddresses.Count -eq 1) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($addresses.Count -ne 1 -or $expectedAddresses.Count -ne 1) {
        throw 'guest support interface does not have the exact preferred /30 address'
    }
    $persistentAddresses = @(Get-GuestIpv4AddressRow -InterfaceIndex $supportIndex `
        -PolicyStore PersistentStore)
    $expectedPersistent = @($persistentAddresses | Where-Object {
        [string]$_.IPAddress -ceq $script:guestContract.GuestIpv4 -and [int]$_.PrefixLength -eq $script:guestContract.PrefixLength
    })
    if ($persistentAddresses.Count -ne 1 -or $expectedPersistent.Count -ne 1) {
        throw 'guest support /30 address is not uniquely persistent'
    }
    Get-GuestSupportNetworkEvidence -Context $context -SupportIndex $supportIndex `
        -ExpectedAddress $expectedAddresses[0]
}

function Get-GuestSupportNetworkEvidence {
    param(
        [Parameter(Mandatory)] [object]$Context,
        [Parameter(Mandatory)] [int]$SupportIndex,
        [Parameter(Mandatory)] [object]$ExpectedAddress
    )
    $interfaces = @(Get-NetIPInterface -InterfaceIndex $SupportIndex `
        -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    $persistentInterfaces = @(Get-NetIPInterface -InterfaceIndex $SupportIndex `
        -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction Stop)
    $directRoutes = @(Get-GuestIpv4RouteRow -InterfaceIndex $SupportIndex `
        -PolicyStore ActiveStore -DestinationPrefix $script:guestContract.Network | Where-Object {
        [string]$_.NextHop -ceq '0.0.0.0'
    })
    $allRoutes = @(
        Get-GuestIpv4RouteRow -InterfaceIndex $SupportIndex -PolicyStore ActiveStore
        Get-GuestIpv4RouteRow -InterfaceIndex $SupportIndex -PolicyStore PersistentStore
    )
    $defaultRoutes = @($allRoutes | Where-Object {
        [string]$_.DestinationPrefix -ceq '0.0.0.0/0'
    })
    $gatewayRoutes = @($allRoutes | Where-Object { [string]$_.NextHop -cne '0.0.0.0' })
    $ipv4Dns = @(Get-DnsClientServerAddress -InterfaceIndex $SupportIndex `
        -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { @($_.ServerAddresses) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object)
    $ipv6Dns = @(Get-DnsClientServerAddress -InterfaceIndex $SupportIndex `
        -AddressFamily IPv6 -ErrorAction Stop | ForEach-Object { @($_.ServerAddresses) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object)
    $intrinsicIpv6Dns = @('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
    $selection = @(Find-NetRoute -RemoteIPAddress $script:guestContract.HostIpv4 -ErrorAction Stop)
    $sourceRows = @($selection | Where-Object { $null -ne $_.PSObject.Properties['IPAddress'] })
    $routeRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties['DestinationPrefix']
    })
    $violations = @(
        if ($interfaces.Count -ne 1 -or [string]$interfaces[0].Dhcp -cne 'Disabled' -or
            [string]$interfaces[0].IgnoreDefaultRoutes -cne 'Enabled' -or
            [int]$interfaces[0].NlMtu -lt 1468) { 'active_interface' }
        if ($persistentInterfaces.Count -ne 1 -or
            [string]$persistentInterfaces[0].IgnoreDefaultRoutes -cne 'Enabled') {
            'persistent_interface'
        }
        if ($directRoutes.Count -ne 1) { "direct_route_count=$($directRoutes.Count)" }
        if ($defaultRoutes.Count -ne 0) { "default_route_count=$($defaultRoutes.Count)" }
        if ($gatewayRoutes.Count -ne 0) { "gateway_route_count=$($gatewayRoutes.Count)" }
        if ($ipv4Dns.Count -ne 0 -or
            ($ipv6Dns.Count -ne 0 -and ($ipv6Dns -join '|') -ine ($intrinsicIpv6Dns -join '|'))) {
            "dns_state=ipv4:$($ipv4Dns.Count),ipv6:$($ipv6Dns.Count)"
        }
        if ($sourceRows.Count -ne 1 -or [string]$sourceRows[0].IPAddress -cne $script:guestContract.GuestIpv4 -or
            [int]$sourceRows[0].InterfaceIndex -ne $SupportIndex) { 'source_selection' }
        if ($routeRows.Count -ne 1 -or
            [string]$routeRows[0].DestinationPrefix -cne $script:guestContract.Network -or
            [string]$routeRows[0].NextHop -cne '0.0.0.0' -or
            [int]$routeRows[0].InterfaceIndex -ne $SupportIndex) { 'route_selection' }
    )
    if ($violations.Count -ne 0) {
        throw "guest support route, DNS, DHCP, MTU, or source-selection contract is invalid " +
            "($script:guestContract.ValidationPhase): $($violations -join ',')"
    }
    [pscustomobject][ordered]@{
        schema = 1
        management_interface_alias = [string]$Context.Management.Name
        management_interface_guid = ([Guid][string]$Context.Management.InterfaceGuid).ToString('D')
        management_interface_index = [int]$Context.Management.ifIndex
        management_mac_address = $script:guestContract.ManagementMac
        support_interface_alias = [string]$Context.Support.Name
        support_interface_guid = ([Guid][string]$Context.Support.InterfaceGuid).ToString('D')
        support_interface_index = $SupportIndex
        support_mac_address = $script:guestContract.SupportMac
        guest_ipv4 = [string]$ExpectedAddress.IPAddress
        prefix_length = [int]$ExpectedAddress.PrefixLength
        network = $script:guestContract.Network
        gateway = $null
        dns_servers = @()
        mtu_bytes = [int]$interfaces[0].NlMtu
        selected_source_ipv4 = [string]$sourceRows[0].IPAddress
        selected_route_prefix = [string]$routeRows[0].DestinationPrefix
        selected_route_next_hop = [string]$routeRows[0].NextHop
    }
}

if ($ShouldConfigure) { Invoke-GuestSupportNetworkConfiguration }
Get-GuestSupportNetworkState
