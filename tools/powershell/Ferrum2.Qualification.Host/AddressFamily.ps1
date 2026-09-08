Set-StrictMode -Version Latest

function Get-Ferrum2AddressFamilyProfile {
    param([ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4')
    $AddressFamily = $(if ($AddressFamily -ieq 'IPv6') { 'IPv6' } else { 'IPv4' })
    $v6 = $AddressFamily -ceq 'IPv6'
    return [pscustomobject][ordered]@{
        address_family = $AddressFamily
        socket_family = $(if ($v6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork })
        loopback_address = $(if ($v6) { '::1' } else { '127.0.0.1' })
        unspecified_address = $(if ($v6) { '::' } else { '0.0.0.0' })
        host_prefix_length = $(if ($v6) { 128 } else { 32 })
        tun_prefix_length = $(if ($v6) { 126 } else { 30 })
        tun_config_field = $(if ($v6) { 'ipv6_address' } else { 'ipv4_address' })
        bind_config_field = $(if ($v6) { 'inet6_bind_address' } else { 'inet4_bind_address' })
        netsh_family = $AddressFamily.ToLowerInvariant()
        wfp_layer = $(if ($v6) { 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6' } else { 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4' })
        wfp_address_type = $(if ($v6) { 'FWP_BYTE_ARRAY16_TYPE' } else { 'FWP_UINT32' })
        loopback_firewall_rules = -not $v6
        firewall_rule_count = $(if ($v6) { 6 } else { 18 })
    }
}

function Assert-Ferrum2CanonicalAddress {
    param([string]$Address, [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily)
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne $profile.socket_family -or
        $parsed.ToString() -cne $Address -or $Address.Contains('%')) {
        throw 'network address is not canonical or belongs to another family'
    }
}

# A missing family is accepted only for historical IPv4 ledgers, never inferred from
# an untrusted caller override. Explicit identities still have to agree with the ledger.
function Get-Ferrum2LedgerAddressFamily {
    param([object]$Ledger)
    $property = $Ledger.PSObject.Properties['address_family']
    $family = 'IPv4'
    if ($null -ne $property) { $family = [string]$property.Value }
    [void](Get-Ferrum2AddressFamilyProfile -AddressFamily $family)
    return $family
}
