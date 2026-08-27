#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines host and VM transaction helpers for Windows TUN lab topology provisioning.

.DESCRIPTION
This dot-source-only owner contains only support host-interface mutation. Readback and identity
validation come from the read-only topology owner; generic VM mechanics come from the Lab module. The manifest-bound provisioning library verifies this
file's exact hash before and after loading it. Loading this file does not mutate state.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseShouldProcessForStateChangingFunctions",
    "",
    Justification = "Private helpers are invoked only after the public driver's ShouldProcess gate."
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $LibraryOnly) {
    throw "host provisioning helpers are dot-source-only"
}

function Set-SupportHostAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$SwitchContext
    )

    $interfaceIndex = [int]$SwitchContext.HostAdapter.ifIndex
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore ActiveStore -Dhcp Disabled -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore PersistentStore -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    foreach ($store in @("ActiveStore", "PersistentStore")) {
        foreach ($route in @(Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex `
                -PolicyStore $store -DestinationPrefix "0.0.0.0/0")) {
            $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }
    }
    foreach ($address in @(Get-ActiveIpv4AddressRow -InterfaceIndex $interfaceIndex)) {
        $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    }
    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses `
        -ErrorAction Stop | Out-Null
    Set-DnsClient -InterfaceIndex $interfaceIndex -RegisterThisConnectionsAddress:$false `
        -UseSuffixWhenRegistering:$false -ErrorAction Stop | Out-Null
    New-NetIPAddress -InterfaceIndex $interfaceIndex `
        -IPAddress ([string]$Plan.support.host_ipv4) `
        -PrefixLength ([byte][int]$Plan.support.prefix_length) `
        -AddressFamily IPv4 -Type Unicast -ErrorAction Stop | Out-Null
}
