Set-StrictMode -Version Latest

function Read-Ferrum2QualificationWorkloadJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 1MB -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'qualification workload evidence file identity is invalid'
    }
    return Get-Content -LiteralPath $Path -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 20 -ErrorAction Stop
}

function Assert-Ferrum2QualificationInteger {
    param([AllowNull()][object]$Value, [long]$Minimum, [long]$Maximum)
    if (($Value -isnot [long] -and $Value -isnot [int] -and $Value -isnot [uint64]) -or
        $Value -lt $Minimum -or $Value -gt $Maximum) {
        throw 'qualification workload integer witness is invalid'
    }
}

function Assert-Ferrum2QualificationResetReady {
    param(
        [Parameter(Mandatory = $true)][object]$Witness,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    if ($Witness.address_family -cne $AddressFamily) {
        throw 'qualification reset-ready address family differs'
    }
    if ($Witness.schema_version -cne 1 -or
        $Witness.kind -cne 'ferrum2.windows-tun-reset-ready' -or
        $Witness.generation -cne 1 -or $Witness.tcp_pending -isnot [bool] -or
        $Witness.tcp_pending -ne $true -or $Witness.udp_pending -isnot [bool] -or
        $Witness.udp_pending -ne $true) {
        throw 'qualification reset requires active old-generation TCP and UDP work'
    }
    Assert-Ferrum2QualificationInteger $Witness.tcp_paused_bytes_sent 1 8388607
    Assert-Ferrum2QualificationInteger $Witness.tcp_unwritable_milliseconds 100 100
    Assert-Ferrum2QualificationInteger $Witness.udp_pending_datagrams 1 1
    $endpoint = $null
    if (-not [Net.IPEndPoint]::TryParse([string]$Witness.udp_local_endpoint, [ref]$endpoint) -or
        $endpoint.AddressFamily -ne $profile.socket_family -or
        $endpoint.Address.IsIPv4MappedToIPv6 -or
        $endpoint.Address.Equals([Net.IPAddress]::Any) -or
        $endpoint.Address.Equals([Net.IPAddress]::IPv6Any) -or $endpoint.Port -eq 0) {
        throw 'qualification reset UDP socket identity is invalid'
    }
}

function Assert-Ferrum2QualificationWorkloadWitness {
    param(
        [Parameter(Mandatory = $true)][object]$Witness,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    if ($Witness.address_family -cne $AddressFamily) {
        throw 'qualification workload address family differs'
    }
    if ($Witness.schema_version -cne 1 -or
        $Witness.kind -cne 'ferrum2.windows-tun-qualification' -or
        $Witness.status -cne 'PASS' -or @($Witness.generations).Count -ne 2) {
        throw 'qualification workload requires two checked generations'
    }
    $endpoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt 2; $index++) {
        $generation = $Witness.generations[$index]
        $expected = $index + 1
        if ($generation.generation -cne $expected -or
            $generation.payload_identity -cne "generation-$expected" -or
            $generation.all_flows_established_barrier -isnot [bool] -or
            $generation.all_flows_established_barrier -ne $true -or
            $generation.concurrent_flows -cne 4 -or @($generation.flows).Count -ne 4) {
            throw 'qualification workload generation or concurrent-flow identity is invalid'
        }
        for ($flowIndex = 0; $flowIndex -lt 4; $flowIndex++) {
            $flow = $generation.flows[$flowIndex]
            if ($flow.flow -cne $flowIndex -or $flow.generation -cne $expected -or
                (@($flow.same_connection_phases) -join '|') -cne
                    'request_before|paused_reader|full_duplex|request_after|half_close') {
                throw 'qualification workload same-connection phase witness is invalid'
            }
            $endpoint = $null
            if (-not [Net.IPEndPoint]::TryParse([string]$flow.local_endpoint, [ref]$endpoint) -or
                $endpoint.AddressFamily -ne $profile.socket_family -or
                $endpoint.Address.IsIPv4MappedToIPv6 -or
                $endpoint.Address.Equals([Net.IPAddress]::Any) -or
                $endpoint.Address.Equals([Net.IPAddress]::IPv6Any) -or
                $endpoint.Port -eq 0 -or -not $endpoints.Add($endpoint.ToString())) {
                throw 'qualification workload requires distinct real selected-family connections'
            }
            Assert-Ferrum2QualificationInteger $flow.bulk_bytes 8388608 8388608
            Assert-Ferrum2QualificationInteger $flow.paused_bytes_sent 1 8388607
            Assert-Ferrum2QualificationInteger $flow.paused_unwritable_milliseconds 100 100
            Assert-Ferrum2QualificationInteger $flow.resumed_bytes_sent 1 8388607
            if ($flow.paused_bytes_sent + $flow.resumed_bytes_sent -ne $flow.bulk_bytes) {
                throw 'qualification workload lacks checked progress after backpressure'
            }
            Assert-Ferrum2QualificationInteger $flow.checked_tcp_bytes 8391680 8391680
            Assert-Ferrum2QualificationInteger $flow.udp_replies_during_tcp 4 4
            Assert-Ferrum2QualificationInteger $flow.fragment_replies_during_tcp 4 4
            Assert-Ferrum2QualificationInteger $flow.fragment_request_bytes 4096 4096
            foreach ($field in @('payload_exact', 'half_close_reply_checked', 'remote_eof')) {
                if ($flow.$field -isnot [bool] -or $flow.$field -ne $true) {
                    throw "qualification workload lacks $field witness"
                }
            }
        }
    }
    $reset = $Witness.reset
    if ($null -eq $reset -or $reset.ready_generation -cne 1 -or
        $reset.release_generation -cne 2 -or $reset.old_tcp_retired -isnot [bool] -or
        $reset.old_tcp_retired -ne $true -or $reset.old_tcp_retirement -cnotin @('eof', 'reset') -or
        $reset.same_tuple_udp_fresh_reply_checked -isnot [bool] -or
        $reset.same_tuple_udp_fresh_reply_checked -ne $true -or
        $reset.udp_fresh_payload_identity -cne 'generation-2') {
        throw 'qualification reset requires retired TCP and fresh generation transfers'
    }
    Assert-Ferrum2QualificationInteger $reset.old_tcp_pending_bytes 1 8388607
    Assert-Ferrum2QualificationInteger $reset.old_tcp_drained_bytes 0 $reset.old_tcp_pending_bytes
    Assert-Ferrum2QualificationInteger $reset.old_udp_pending_datagrams 1 1
    Assert-Ferrum2QualificationInteger $reset.old_udp_buffered_replies 0 1
    $endpoint = $null
    if (-not [Net.IPEndPoint]::TryParse([string]$reset.udp_local_endpoint, [ref]$endpoint) -or
        $endpoint.AddressFamily -ne $profile.socket_family -or
        $endpoint.Address.IsIPv4MappedToIPv6 -or
        $endpoint.Address.Equals([Net.IPAddress]::Any) -or
        $endpoint.Address.Equals([Net.IPAddress]::IPv6Any) -or $endpoint.Port -eq 0) {
        throw 'qualification reset UDP socket identity is invalid'
    }
}
