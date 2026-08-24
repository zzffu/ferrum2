#requires -Version 5.1

<#
.SYNOPSIS
Returns the read-only guest underlay path used to reach a Windows TUN support listener.

.DESCRIPTION
This probe is intentionally run before the managed performance adapter exists. It validates the
manifest-bound isolated /30, rejects a support address that is guest-local, a gateway, or a DNS
server, and binds the selected direct route to the exact support adapter. It opens no listener and
changes no adapter, address, route, or DNS setting.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SupportIpv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$SupportPort,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedGuestIpv4,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\r\n]{1,128}$')]
    [string]$ExpectedInterfaceAlias,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedNetwork,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 32)]
    [int]$ExpectedPrefixLength,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-F]{12}$')]
    [string]$ExpectedMacAddress,

    [Parameter(Mandatory = $true)]
    [Guid]$ExpectedInterfaceGuid,

    [Parameter(Mandatory = $true)]
    [ValidateRange(576, 65535)]
    [int]$ExpectedMtuBytes,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\r\n]{1,128}$')]
    [string]$ManagedAdapterName,

    [Parameter(Mandatory = $true)]
    [ValidateRange(576, 65535)]
    [int]$MinimumUnderlayIpv4PacketBytes,

    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function ConvertTo-CanonicalIpv4 {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Label is not an IPv4 literal"
    }
    return $parsed.ToString()
}

function Test-Ipv4CidrMembership {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][Net.IPAddress]$NetworkAddress,
        [Parameter(Mandatory = $true)][ValidateRange(1, 32)][int]$PrefixLength,
        [switch]$RequireCanonicalNetwork
    )

    $addressBytes = $Address.GetAddressBytes()
    $networkBytes = $NetworkAddress.GetAddressBytes()
    foreach ($index in 0..3) {
        $remainingBits = $PrefixLength - ($index * 8)
        $mask = if ($remainingBits -ge 8) {
            255
        } elseif ($remainingBits -le 0) {
            0
        } else {
            (255 -shl (8 - $remainingBits)) -band 255
        }
        if ((([int]$addressBytes[$index]) -band $mask) -ne
            (([int]$networkBytes[$index]) -band $mask)) {
            return $false
        }
        if ($RequireCanonicalNetwork -and
            (([int]$networkBytes[$index] -band (255 -bxor $mask)) -ne 0)) {
            return $false
        }
    }
    return $true
}

$supportAddress = ConvertTo-CanonicalIpv4 -Value $SupportIpv4 -Label "support address"
$supportIp = [Net.IPAddress]::Parse($supportAddress)
$expectedGuestAddress = ConvertTo-CanonicalIpv4 -Value $ExpectedGuestIpv4 `
    -Label "expected guest support address"
$expectedNetworkParts = @($ExpectedNetwork.Split('/'))
$expectedNetworkPrefix = 0
if ($expectedNetworkParts.Count -ne 2 -or
    -not [int]::TryParse($expectedNetworkParts[1], [ref]$expectedNetworkPrefix) -or
    $expectedNetworkPrefix -ne $ExpectedPrefixLength) {
    throw "expected support network is not a canonical IPv4 CIDR"
}
$expectedNetworkAddress = ConvertTo-CanonicalIpv4 -Value $expectedNetworkParts[0] `
    -Label "expected support network"
$expectedNetworkIp = [Net.IPAddress]::Parse($expectedNetworkAddress)
if ($ExpectedNetwork -cne "$expectedNetworkAddress/$expectedNetworkPrefix" -or
    -not (Test-Ipv4CidrMembership -Address $expectedNetworkIp `
        -NetworkAddress $expectedNetworkIp -PrefixLength $expectedNetworkPrefix `
        -RequireCanonicalNetwork) -or
    -not (Test-Ipv4CidrMembership -Address $supportIp `
        -NetworkAddress $expectedNetworkIp -PrefixLength $expectedNetworkPrefix) -or
    -not (Test-Ipv4CidrMembership -Address ([Net.IPAddress]::Parse($expectedGuestAddress)) `
        -NetworkAddress $expectedNetworkIp -PrefixLength $expectedNetworkPrefix) -or
    $supportAddress -ceq $expectedGuestAddress) {
    throw "expected support endpoints do not form the approved IPv4 network"
}
if ($supportIp.Equals([Net.IPAddress]::Any) -or
    [Net.IPAddress]::IsLoopback($supportIp) -or
    $supportIp.GetAddressBytes()[0] -eq 0 -or
    $supportIp.GetAddressBytes()[0] -ge 224 -or
    ($supportIp.GetAddressBytes()[0] -eq 169 -and
        $supportIp.GetAddressBytes()[1] -eq 254)) {
    throw "support address is not an eligible unicast IPv4 address"
}
if (Get-NetAdapter -Name $ManagedAdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
    throw "managed performance adapter must be absent during underlay selection"
}
if (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $supportAddress `
        -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "support address is guest-local"
}
$expectedGuestRows = @(Get-NetIPAddress -AddressFamily IPv4 `
    -IPAddress $expectedGuestAddress -PolicyStore ActiveStore -ErrorAction Stop)
if ($expectedGuestRows.Count -ne 1 -or
    [string]$expectedGuestRows[0].InterfaceAlias -cne $ExpectedInterfaceAlias -or
    [int]$expectedGuestRows[0].PrefixLength -ne $ExpectedPrefixLength -or
    [string]$expectedGuestRows[0].AddressState -cne "Preferred") {
    throw "expected guest support address is not uniquely active"
}

$defaultGateways = @(
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
        -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object {
            [string]$_.State -ceq "Alive" -and
            -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
            [string]$_.NextHop -cne "0.0.0.0"
        } |
        ForEach-Object {
            ConvertTo-CanonicalIpv4 -Value ([string]$_.NextHop) -Label "default gateway"
        } |
        Sort-Object -Unique
)
if ($defaultGateways -ccontains $supportAddress) {
    throw "support address collides with a guest default gateway"
}

$allDnsServers = @(
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        ForEach-Object {
            foreach ($server in @($_.ServerAddresses)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$server)) {
                    ConvertTo-CanonicalIpv4 -Value ([string]$server) -Label "DNS server"
                }
            }
        } |
        Sort-Object -Unique
)
if ($allDnsServers -ccontains $supportAddress) {
    throw "support address collides with a guest DNS server"
}
$supportIpv4DnsServers = @(
    Get-DnsClientServerAddress `
        -InterfaceIndex ([int]$expectedGuestRows[0].InterfaceIndex) `
        -AddressFamily IPv4 -ErrorAction Stop |
        ForEach-Object { @($_.ServerAddresses) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ } |
        Sort-Object
)
$supportIpv6DnsServers = @(
    Get-DnsClientServerAddress `
        -InterfaceIndex ([int]$expectedGuestRows[0].InterfaceIndex) `
        -AddressFamily IPv6 -ErrorAction Stop |
        ForEach-Object { @($_.ServerAddresses) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ } |
        Sort-Object
)
$windowsIntrinsicIpv6Dns = @(
    "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
)
$supportDnsStateValid = $supportIpv4DnsServers.Count -eq 0 -and
    ($supportIpv6DnsServers.Count -eq 0 -or
        ($supportIpv6DnsServers -join "|") -ieq ($windowsIntrinsicIpv6Dns -join "|"))
if (-not $supportDnsStateValid) {
    throw "guest support interface must not have DNS servers"
}
$supportDnsServers = @()

$selection = @(Find-NetRoute -RemoteIPAddress $supportAddress -ErrorAction Stop)
$sourceRows = @($selection | Where-Object {
    $null -ne $_.CimClass -and $_.CimClass.CimClassName -ceq "MSFT_NetIPAddress"
})
$routeRows = @($selection | Where-Object {
    $null -ne $_.CimClass -and $_.CimClass.CimClassName -ceq "MSFT_NetRoute"
})
if ($sourceRows.Count -ne 1 -or $routeRows.Count -ne 1) {
    throw "support route selection is not unique"
}
$source = $sourceRows[0]
$route = $routeRows[0]
if ([string]$source.AddressFamily -cne "IPv4" -or
    [string]$source.AddressState -cne "Preferred" -or
    [string]$route.AddressFamily -cne "IPv4" -or
    [string]$route.State -cne "Alive" -or
    [int]$source.InterfaceIndex -ne [int]$route.InterfaceIndex) {
    throw "support route and selected source are not an active IPv4 pair"
}
$guestAddress = ConvertTo-CanonicalIpv4 -Value ([string]$source.IPAddress) `
    -Label "guest underlay address"
$nextHop = ConvertTo-CanonicalIpv4 -Value ([string]$route.NextHop) `
    -Label "support route next hop"
if ([string]$route.DestinationPrefix -cne $ExpectedNetwork -or
    $nextHop -cne "0.0.0.0" -or
    $guestAddress -cne $expectedGuestAddress -or
    [int]$source.PrefixLength -ne $ExpectedPrefixLength -or
    [int]$source.InterfaceIndex -ne [int]$expectedGuestRows[0].InterfaceIndex) {
    throw "support route is not the manifest-bound direct guest path"
}

$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
    [int]$_.ifIndex -eq [int]$source.InterfaceIndex
})
if ($adapters.Count -ne 1 -or
    [string]$adapters[0].Status -cne "Up" -or
    [string]$adapters[0].Name -cne $ExpectedInterfaceAlias -or
    ([Guid][string]$adapters[0].InterfaceGuid).ToString("D") -cne
        $ExpectedInterfaceGuid.ToString("D") -or
    [string]$adapters[0].Name -ceq $ManagedAdapterName) {
    throw "guest underlay adapter is not uniquely active"
}
$ipInterfaces = @(Get-NetIPInterface -AddressFamily IPv4 `
    -InterfaceIndex ([int]$source.InterfaceIndex) -PolicyStore ActiveStore -ErrorAction Stop)
if ($ipInterfaces.Count -ne 1 -or
    [string]$ipInterfaces[0].ConnectionState -cne "Connected" -or
    [int]$ipInterfaces[0].NlMtu -ne $ExpectedMtuBytes -or
    [int]$ipInterfaces[0].NlMtu -lt $MinimumUnderlayIpv4PacketBytes) {
    throw "guest underlay IPv4 MTU cannot carry the support probe without fragmentation"
}
$macAddress = ([string]$adapters[0].MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
if ($macAddress -cnotmatch '^[0-9A-F]{12}$') {
    throw "guest underlay adapter MAC address is invalid"
}
if ($macAddress -cne $ExpectedMacAddress) {
    throw "guest support adapter MAC does not match the topology manifest"
}

$socket = New-Object Net.Sockets.Socket(
    [Net.Sockets.AddressFamily]::InterNetwork,
    [Net.Sockets.SocketType]::Dgram,
    [Net.Sockets.ProtocolType]::Udp
)
try {
    $socket.Connect((New-Object Net.IPEndPoint($supportIp, $SupportPort)))
    $socketSource = ([Net.IPEndPoint]$socket.LocalEndPoint).Address.ToString()
} finally {
    $socket.Dispose()
}
if ($socketSource -cne $guestAddress) {
    throw "socket source selection disagrees with Find-NetRoute"
}

$result = [pscustomobject][ordered]@{
    schema = 2
    support_ipv4 = $supportAddress
    guest_ipv4 = $guestAddress
    guest_prefix_length = [int]$source.PrefixLength
    guest_interface_index = [int]$source.InterfaceIndex
    guest_interface_alias = [string]$adapters[0].Name
    guest_interface_guid = ([Guid][string]$adapters[0].InterfaceGuid).ToString("D")
    guest_interface_mtu_bytes = [int]$ipInterfaces[0].NlMtu
    guest_mac_address = $macAddress
    guest_route_prefix = [string]$route.DestinationPrefix
    guest_route_next_hop = $nextHop
    guest_dns_servers = @($supportDnsServers)
}
if ($AsJson) {
    $result | ConvertTo-Json -Compress -Depth 4
} else {
    $result
}
