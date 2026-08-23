#requires -Version 5.1

<#
.SYNOPSIS
Returns the read-only guest underlay path used to reach a Windows TUN support listener.

.DESCRIPTION
This probe is intentionally run before the managed performance adapter exists. It rejects a
support address that is guest-local, a default gateway, or a DNS server, and it binds the selected
route to one active guest adapter. It opens no listener and changes no adapter, address, route, or
DNS setting.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SupportIpv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$SupportPort,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\r\n]{1,128}$')]
    [string]$ManagedAdapterName
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

$supportAddress = ConvertTo-CanonicalIpv4 -Value $SupportIpv4 -Label "support address"
$supportIp = [Net.IPAddress]::Parse($supportAddress)
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

$dnsServers = @(
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
if ($dnsServers -ccontains $supportAddress) {
    throw "support address collides with a guest DNS server"
}

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
if ($defaultGateways.Count -ne 1 -or
    [string]$route.DestinationPrefix -cne "0.0.0.0/0" -or
    $nextHop -ceq "0.0.0.0" -or
    $nextHop -cne $defaultGateways[0]) {
    throw "support route is not the unique guest default underlay path"
}

$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
    [int]$_.ifIndex -eq [int]$source.InterfaceIndex
})
if ($adapters.Count -ne 1 -or
    [string]$adapters[0].Status -cne "Up" -or
    [string]$adapters[0].Name -ceq $ManagedAdapterName) {
    throw "guest underlay adapter is not uniquely active"
}
$macAddress = ([string]$adapters[0].MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
if ($macAddress -cnotmatch '^[0-9A-F]{12}$') {
    throw "guest underlay adapter MAC address is invalid"
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

[pscustomobject][ordered]@{
    schema = 1
    support_ipv4 = $supportAddress
    guest_ipv4 = $guestAddress
    guest_prefix_length = [int]$source.PrefixLength
    guest_interface_index = [int]$source.InterfaceIndex
    guest_interface_alias = [string]$adapters[0].Name
    guest_mac_address = $macAddress
    guest_route_prefix = [string]$route.DestinationPrefix
    guest_route_next_hop = $nextHop
    guest_dns_ipv4 = @($dnsServers)
}
