function New-M17PaddedDnsQuery([uint16]$Id, [int]$PaddingBytes = 2048) {
    Assert-True ($PaddingBytes -ge 1200 -and $PaddingBytes -le 4096) "M17 DNS padding is outside the bounded witness range"
    $query = [Collections.Generic.List[byte]]::new()
    $baseQuery = [byte[]](New-DnsQuery $Id)
    $query.AddRange($baseQuery)
    $query[11] = 1
    $query.Add(0)
    $query.AddRange([byte[]](0, 41, 16, 0, 0, 0, 0, 0))
    $optionLength = $PaddingBytes + 4
    $query.Add([byte]($optionLength -shr 8))
    $query.Add([byte]($optionLength -band 0xff))
    $query.AddRange([byte[]](0, 12, [byte]($PaddingBytes -shr 8), [byte]($PaddingBytes -band 0xff)))
    $query.AddRange([byte[]]::new($PaddingBytes))
    return $query.ToArray()
}

function Invoke-M17DnsBytes([string]$Source, [string]$Destination, [byte[]]$Query) {
    $family = if ($Destination.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $client = [Net.Sockets.UdpClient]::new($family)
    try {
        $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
        [void]$client.Send($Query, $Query.Length, $Destination, 53)
        $task = $client.ReceiveAsync()
        Assert-True ($task.Wait(10000) -and -not $task.IsFaulted) "M17 padded DNS response timeout"
        $response = $task.Result.Buffer
    } finally { $client.Dispose() }
    Assert-True ($response.Length -ge 12 -and $response[0] -eq $Query[0] -and $response[1] -eq $Query[1] -and
        ($response[2] -band 0x80) -ne 0) "M17 padded DNS response is invalid"
}

function Get-M17PayloadSha256([byte[]]$Payload) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($Payload))).Replace("-", "").ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Assert-M17DnsQueryEnvelope([byte[]]$Payload, [uint16]$Id) {
    Assert-True ($Payload.Length -eq 32 -and
        $Payload[0] -eq [byte]($Id -shr 8) -and $Payload[1] -eq [byte]($Id -band 0xff) -and
        $Payload[2] -eq 1 -and $Payload[3] -eq 0 -and
        $Payload[4] -eq 0 -and $Payload[5] -eq 1 -and
        $Payload[6] -eq 0 -and $Payload[7] -eq 0 -and
        $Payload[8] -eq 0 -and $Payload[9] -eq 0 -and
        $Payload[10] -eq 0 -and $Payload[11] -eq 0 -and
        $Payload[27] -eq 0 -and $Payload[28] -eq 0 -and $Payload[29] -eq 1 -and
        $Payload[30] -eq 0 -and $Payload[31] -eq 1) "M17 DNS query wire envelope is invalid"
}

function New-M17QuicV1InitialEnvelope {
    # A deterministic 1,200-byte QUIC v1 Initial envelope. The protected body is opaque, but the
    # long header, connection IDs, zero token, two-byte packet length, packet number length, and
    # RFC minimum datagram size are independently parsed below before the live round trip.
    $packet = [byte[]]::new(1200)
    $packet[0] = 0xc3
    $packet[4] = 1
    $packet[5] = 8
    [Array]::Copy([byte[]](0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08), 0, $packet, 6, 8)
    $packet[14] = 8
    [Array]::Copy([byte[]](0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5), 0, $packet, 15, 8)
    $packet[23] = 0
    $packet[24] = 0x44
    $packet[25] = 0x96
    [Array]::Copy([byte[]](0, 0, 0, 2), 0, $packet, 26, 4)
    foreach ($index in 30..1199) { $packet[$index] = [byte](($index * 29 + 17) % 251) }
    return $packet
}

function Assert-M17QuicV1InitialEnvelope([byte[]]$Payload) {
    $declaredLength = (($Payload[24] -band 0x3f) -shl 8) -bor $Payload[25]
    Assert-True ($Payload.Length -eq 1200 -and
        ($Payload[0] -band 0xc0) -eq 0xc0 -and ($Payload[0] -band 0x30) -eq 0 -and
        (($Payload[0] -band 3) + 1) -eq 4 -and
        $Payload[1] -eq 0 -and $Payload[2] -eq 0 -and $Payload[3] -eq 0 -and $Payload[4] -eq 1 -and
        $Payload[5] -eq 8 -and $Payload[14] -eq 8 -and $Payload[23] -eq 0 -and
        ($Payload[24] -shr 6) -eq 1 -and $declaredLength -eq 1174 -and
        26 + $declaredLength -eq $Payload.Length) "M17 QUIC v1 Initial envelope is not structurally parseable"
}

function Get-M17StunFingerprintCrc([byte[]]$Payload, [int]$Length) {
    Assert-True ($Length -ge 20 -and $Length -le $Payload.Length) "M17 STUN fingerprint input length is invalid"
    [uint32]$crc = [uint32]::MaxValue
    foreach ($index in 0..($Length - 1)) {
        $crc = [uint32]($crc -bxor [uint32]$Payload[$index])
        foreach ($bit in 0..7) {
            if (($crc -band 1) -ne 0) {
                $crc = [uint32](($crc -shr 1) -bxor [uint32]3988292384)
            } else {
                $crc = [uint32]($crc -shr 1)
            }
        }
    }
    return [uint32](($crc -bxor [uint32]::MaxValue) -bxor [uint32]1398035790)
}

function Get-M17IceMessageIntegrity([byte[]]$Payload, [int]$MessageIntegrityOffset) {
    Assert-True ($MessageIntegrityOffset -ge 20 -and $MessageIntegrityOffset + 24 -le $Payload.Length) "M17 ICE MESSAGE-INTEGRITY offset is invalid"
    $input = [byte[]]::new($MessageIntegrityOffset)
    [Array]::Copy($Payload, 0, $input, 0, $input.Length)
    $lengthThroughIntegrity = $MessageIntegrityOffset + 24 - 20
    $input[2] = [byte]($lengthThroughIntegrity -shr 8)
    $input[3] = [byte]($lengthThroughIntegrity -band 0xff)
    $key = [Text.Encoding]::ASCII.GetBytes("m17-ice-password-0123456789abcdef")
    $algorithm = [Security.Cryptography.HMACSHA1]::new($key)
    try { return $algorithm.ComputeHash($input) }
    finally { $algorithm.Dispose() }
}

function New-M17StunBindingRequest([byte]$TransactionSeed, [bool]$IceCandidate) {
    $message = [Collections.Generic.List[byte]]::new()
    $message.AddRange([byte[]](0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42))
    foreach ($index in 0..11) { $message.Add([byte](($TransactionSeed + $index) -band 0xff)) }
    if ($IceCandidate) {
        $username = [Text.Encoding]::ASCII.GetBytes("remote17:local17")
        $message.AddRange([byte[]](0, 6, 0, $username.Length))
        $message.AddRange($username)
        while (($message.Count % 4) -ne 0) { $message.Add(0) }
        $message.AddRange([byte[]](0, 0x24, 0, 4, 0x6e, 0, 1, 0xff))
        $message.AddRange([byte[]](0x80, 0x2a, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88))
        $messageIntegrityOffset = $message.Count
        $message.AddRange([byte[]](0, 8, 0, 20))
        $message.AddRange([byte[]]::new(20))
        $lengthThroughIntegrity = $message.Count - 20
        $message[2] = [byte]($lengthThroughIntegrity -shr 8)
        $message[3] = [byte]($lengthThroughIntegrity -band 0xff)
        [byte[]]$integrity = Get-M17IceMessageIntegrity $message.ToArray() $messageIntegrityOffset
        foreach ($index in 0..($integrity.Length - 1)) {
            $message[$messageIntegrityOffset + 4 + $index] = $integrity[$index]
        }
        $fingerprintOffset = $message.Count
        $message.AddRange([byte[]](0x80, 0x28, 0, 4, 0, 0, 0, 0))
        $bodyLength = $message.Count - 20
        $message[2] = [byte]($bodyLength -shr 8)
        $message[3] = [byte]($bodyLength -band 0xff)
        [uint32]$fingerprint = Get-M17StunFingerprintCrc $message.ToArray() $fingerprintOffset
        $message[$fingerprintOffset + 4] = [byte](($fingerprint -shr 24) -band 0xff)
        $message[$fingerprintOffset + 5] = [byte](($fingerprint -shr 16) -band 0xff)
        $message[$fingerprintOffset + 6] = [byte](($fingerprint -shr 8) -band 0xff)
        $message[$fingerprintOffset + 7] = [byte]($fingerprint -band 0xff)
    }
    $bodyLength = $message.Count - 20
    $message[2] = [byte]($bodyLength -shr 8)
    $message[3] = [byte]($bodyLength -band 0xff)
    return $message.ToArray()
}

function Assert-M17StunBindingRequest([byte[]]$Payload, [bool]$IceCandidate) {
    Assert-True ($Payload.Length -ge 20 -and $Payload[0] -eq 0 -and $Payload[1] -eq 1 -and
        $Payload[4] -eq 0x21 -and $Payload[5] -eq 0x12 -and
        $Payload[6] -eq 0xa4 -and $Payload[7] -eq 0x42) "M17 STUN Binding request header is invalid"
    $declaredLength = ([int]$Payload[2] -shl 8) -bor [int]$Payload[3]
    Assert-True (($declaredLength % 4) -eq 0 -and 20 + $declaredLength -eq $Payload.Length) "M17 STUN message length is invalid"
    $attributes = [Collections.Generic.HashSet[int]]::new()
    $attributeOffsets = @{}
    $offset = 20
    while ($offset -lt $Payload.Length) {
        Assert-True ($offset + 4 -le $Payload.Length) "M17 STUN attribute header is truncated"
        $attribute = ([int]$Payload[$offset] -shl 8) -bor [int]$Payload[$offset + 1]
        $length = ([int]$Payload[$offset + 2] -shl 8) -bor [int]$Payload[$offset + 3]
        $paddedLength = ($length + 3) -band (-bnot 3)
        Assert-True ($offset + 4 + $paddedLength -le $Payload.Length) "M17 STUN attribute value is truncated"
        [void]$attributes.Add($attribute)
        $attributeOffsets[$attribute] = $offset
        $offset += 4 + $paddedLength
    }
    if ($IceCandidate) {
        Assert-True ($attributes.Contains(0x0006) -and $attributes.Contains(0x0024) -and
            $attributes.Contains(0x802a) -and $attributes.Contains(0x0008) -and
            $attributes.Contains(0x8028)) "M17 WebRTC ICE connectivity-check attributes are incomplete"
        $messageIntegrityOffset = [int]$attributeOffsets[0x0008]
        [byte[]]$expectedIntegrity = Get-M17IceMessageIntegrity $Payload $messageIntegrityOffset
        [byte[]]$actualIntegrity = $Payload[($messageIntegrityOffset + 4)..($messageIntegrityOffset + 23)]
        Assert-True (($actualIntegrity -join ",") -ceq ($expectedIntegrity -join ",")) "M17 ICE MESSAGE-INTEGRITY is invalid"
        $fingerprintOffset = [int]$attributeOffsets[0x8028]
        Assert-True ($fingerprintOffset + 8 -eq $Payload.Length) "M17 ICE FINGERPRINT is not the final attribute"
        [uint32]$expectedFingerprint = Get-M17StunFingerprintCrc $Payload $fingerprintOffset
        [uint32]$actualFingerprint = ([uint32]$Payload[$fingerprintOffset + 4] -shl 24) -bor
            ([uint32]$Payload[$fingerprintOffset + 5] -shl 16) -bor
            ([uint32]$Payload[$fingerprintOffset + 6] -shl 8) -bor
            [uint32]$Payload[$fingerprintOffset + 7]
        Assert-True ($actualFingerprint -eq $expectedFingerprint) "M17 ICE FINGERPRINT is invalid"
    } else {
        Assert-True ($attributes.Count -eq 0) "M17 bare STUN Binding request unexpectedly has attributes"
    }
}

function New-M17GamePeerDatagram([byte]$Peer, [uint32]$Sequence) {
    $packet = [byte[]]::new(24)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("F2GM"), 0, $packet, 0, 4)
    $packet[4] = 1
    $packet[5] = 1
    $packet[6] = $Peer
    $packet[8] = 0x17
    $packet[9] = 0x06
    $packet[10] = 0x20
    $packet[11] = 0x26
    $packet[12] = [byte]($Sequence -shr 24)
    $packet[13] = [byte]($Sequence -shr 16)
    $packet[14] = [byte]($Sequence -shr 8)
    $packet[15] = [byte]($Sequence -band 0xff)
    $packet[17] = 6
    foreach ($index in 18..23) { $packet[$index] = [byte](($Peer * 31 + $index) -band 0xff) }
    return $packet
}

function Assert-M17GamePeerDatagram([byte[]]$Payload, [byte]$Peer, [uint32]$Sequence) {
    $decodedSequence = ([uint32]$Payload[12] -shl 24) -bor ([uint32]$Payload[13] -shl 16) -bor
        ([uint32]$Payload[14] -shl 8) -bor [uint32]$Payload[15]
    Assert-True ($Payload.Length -eq 24 -and
        [Text.Encoding]::ASCII.GetString($Payload, 0, 4) -ceq "F2GM" -and
        $Payload[4] -eq 1 -and $Payload[5] -eq 1 -and $Payload[6] -eq $Peer -and
        $Payload[16] -eq 0 -and $Payload[17] -eq 6 -and
        $decodedSequence -eq $Sequence) "M17 game-style binary datagram is invalid"
}

function Wait-M17MetricIncrease(
    [int]$MetricsPort,
    [string]$Name,
    [double]$Before,
    [int]$TimeoutSeconds = 5
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $metrics = Get-Metrics $MetricsPort 2
        if ((Get-M17MetricValue $metrics $Name $true) -gt $Before) { return $metrics }
        Start-Sleep -Milliseconds 20
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 metric did not increase: $Name"
}

function New-M17TunUdpClient([string]$Source, [int]$InterfaceIndex) {
    $address = [Net.IPAddress]::Parse($Source)
    $client = [Net.Sockets.UdpClient]::new($address.AddressFamily)
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($address, 0))
    return $client
}

function Invoke-M17UdpEcho(
    [Net.Sockets.UdpClient]$Client,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [int]$TimeoutMilliseconds = 10000
) {
    [void]$Client.Send($Payload, $Payload.Length, $Address, $Port)
    $task = $Client.ReceiveAsync()
    Assert-True ($task.Wait($TimeoutMilliseconds) -and -not $task.IsFaulted) "M17 TUN UDP echo timeout"
    Assert-True (($task.Result.Buffer -join ",") -ceq ($Payload -join ",") -and
        $task.Result.RemoteEndPoint.Address.ToString() -ceq ([Net.IPAddress]::Parse($Address)).ToString() -and
        $task.Result.RemoteEndPoint.Port -eq $Port) "M17 TUN UDP response source or payload mismatch"
}

function Wait-M17ProbeRemoteEndpoint([Ferrum2UdpProbe]$Probe, [int]$TimeoutMilliseconds = 5000) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $endpoint = $Probe.RemoteEndpoint
        if ($null -ne $endpoint) { return $endpoint }
        Start-Sleep -Milliseconds 10
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 target probe did not publish its remote endpoint"
}

function Receive-M17UdpIfReady(
    [Net.Sockets.UdpClient]$Client,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [int]$TimeoutMilliseconds = 250
) {
    if (-not $Client.Client.Poll($TimeoutMilliseconds * 1000, [Net.Sockets.SelectMode]::SelectRead)) {
        return $false
    }
    $task = $Client.ReceiveAsync()
    Assert-True ($task.Wait(1000) -and -not $task.IsFaulted) "M17 readable UDP response could not be received"
    Assert-True (($task.Result.Buffer -join ",") -ceq ($Payload -join ",") -and
        $task.Result.RemoteEndPoint.Address.ToString() -ceq ([Net.IPAddress]::Parse($Address)).ToString() -and
        $task.Result.RemoteEndPoint.Port -eq $Port) "M17 unsolicited UDP response source or payload mismatch"
    return $true
}

function Assert-M17UdpQuiet([Net.Sockets.UdpClient]$Client, [int]$TimeoutMilliseconds = 1000) {
    $ready = $Client.Client.Poll($TimeoutMilliseconds * 1000, [Net.Sockets.SelectMode]::SelectRead)
    Assert-True (-not $ready) "M17 rejected UDP peer reached the TUN client"
}

function Add-M17LoopbackTarget(
    [string]$Address,
    [int]$Port,
    [byte[]]$ResponsePayload = $null
) {
    [void](Add-TargetAddress $Address $false)
    $probe = if ($null -eq $ResponsePayload) {
        [Ferrum2UdpProbe]::new($Address, $Port)
    } else {
        [Ferrum2UdpProbe]::new($Address, $Port, $ResponsePayload)
    }
    $script:tcpResources.Add($probe)
    return $probe
}

function Get-M17TargetRoutePreference([int]$InterfaceIndex, [string]$Address) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { "IPv6" } else { "IPv4" }
    $prefix = if ($isV6) { "$Address/128" } else { "$Address/32" }
    $tunRoutes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $localRoutes = @(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    Assert-True ($tunRoutes.Count -eq 1 -and $localRoutes.Count -eq 1) "M17 target route ownership is ambiguous: $prefix"
    $tunInterface = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily $family `
        -PolicyStore ActiveStore -ErrorAction Stop
    $localInterface = Get-NetIPInterface -InterfaceIndex 1 -AddressFamily $family `
        -PolicyStore ActiveStore -ErrorAction Stop
    [uint64]$tunEffective = [uint64]$tunRoutes[0].RouteMetric + [uint64]$tunInterface.InterfaceMetric
    [uint64]$localEffective = [uint64]$localRoutes[0].RouteMetric + [uint64]$localInterface.InterfaceMetric
    Assert-True ($localEffective -lt $tunEffective) "M17 unpinned server target route does not prefer loopback: $prefix"
    return [ordered]@{
        destination_prefix = $prefix
        tun_interface_index = $InterfaceIndex
        tun_route_metric = [uint32]$tunRoutes[0].RouteMetric
        tun_interface_metric = [uint32]$tunInterface.InterfaceMetric
        tun_effective_metric = $tunEffective
        local_route_metric = [uint32]$localRoutes[0].RouteMetric
        local_interface_metric = [uint32]$localInterface.InterfaceMetric
        local_effective_metric = $localEffective
    }
}

function Invoke-M17Fragments {
    $v4Target = "192.0.2.241"
    $v6Target = "2001:db8::241"
    $v4Ack = [Text.Encoding]::ASCII.GetBytes("m17-fragment-v4-ack")
    $v6Ack = [Text.Encoding]::ASCII.GetBytes("m17-fragment-v6-ack")
    $v4Port = Get-UniqueTcpPort
    $v6Port = Get-UniqueTcpPort
    $v4Probe = Add-M17LoopbackTarget $v4Target $v4Port $v4Ack
    $v6Probe = Add-M17LoopbackTarget $v6Target $v6Port $v6Ack
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-fragments.toml"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
mtu = 1280
max_udp_mappings = 16
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "proxy" $script:m17MetricsPort
    Assert-M17Config $path "fragments"
    $script:activeProcess = Start-M17Candidate $path "fragments"
    $adapter = Wait-M17AdapterReady -Name $script:adapterName -Ipv4 $true -Ipv6 $true -ExpectedMtu 1280
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    [void](Add-TunRoute $script:ownedInterfaceIndex "$v4Target/32" 500)
    [void](Add-TunRoute $script:ownedInterfaceIndex "$v6Target/128" 500)
    Add-M17LiveRow "fragment-target-route-preference" ([ordered]@{
        routes = @(
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $v4Target
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $v6Target
        )
    })
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $initial.Metrics
    $completedBefore = Get-M17MetricValue $initial.Metrics "ferrum2_tun_reassembly_completed"
    $v4Payload = [byte[]]::new(8192)
    $v6Payload = [byte[]]::new(8192)
    for ($index = 0; $index -lt $v4Payload.Length; $index++) {
        $v4Payload[$index] = [byte]($index % 251)
        $v6Payload[$index] = [byte](250 - ($index % 251))
    }
    $v4Client = Open-TunUdp $v4Target $v4Port $script:ownedInterfaceIndex
    $v6Client = Open-TunUdp $v6Target $v6Port $script:ownedInterfaceIndex
    try {
        [void]$v4Client.Send($v4Payload, $v4Payload.Length)
        $v4Echo = Receive-TunUdp $v4Client 10000
        Assert-True (($v4Echo -join ",") -ceq ($v4Ack -join ",")) "M17 fragmented IPv4 UDP acknowledgement changed"
        [void]$v6Client.Send($v6Payload, $v6Payload.Length)
        $v6Echo = Receive-TunUdp $v6Client 10000
        Assert-True (($v6Echo -join ",") -ceq ($v6Ack -join ",")) "M17 fragmented IPv6 UDP acknowledgement changed"
    } finally { $v4Client.Dispose(); $v6Client.Dispose() }
    Assert-True ($v4Probe.WaitRequests(1, 5000) -and $v6Probe.WaitRequests(1, 5000)) "M17 fragmented target did not observe both datagrams"
    Assert-True (($v4Probe.Received -join ",") -ceq ($v4Payload -join ",") -and
        ($v6Probe.Received -join ",") -ceq ($v6Payload -join ",")) "M17 fragmented target request payload changed"
    $fragmentMetrics = Get-Metrics $script:m17MetricsPort
    Assert-True ((Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_completed") -ge $completedBefore + 2 -and
        (Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_entries_active") -eq 0) "M17 live fragment completion metrics changed"
    Add-M17LiveRow "live-fragmented-udp" ([ordered]@{
        ipv4_payload_bytes = $v4Payload.Length
        ipv6_payload_bytes = $v6Payload.Length
        ipv4_response_bytes = $v4Ack.Length
        ipv6_response_bytes = $v6Ack.Length
        completed_delta = (Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_completed") - $completedBefore
        active_entries = Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_entries_active"
    })
    Add-M17Witness "large_ipv4_and_ipv6_udp_reassembles" "live-product" `
        "8 KiB IPv4 and IPv6 UDP datagrams crossed the 1,280-byte TUN MTU, reassembled, and round-tripped without active reassembly residue"
    Stop-M17Candidate $script:activeProcess "fragments"

    $resolverAddress = "127.0.0.1"
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $dnsMetricsPort = Get-UniqueTcpPort
    $dnsPath = Join-Path $script:work "m17-fragmented-dns.toml"
    Write-M17ClientConfig $dnsPath @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
mtu = 1280
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $dnsMetricsPort @"
[dns]
timeout_ms = 2000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$(Get-UniqueTcpPort)"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${resolverAddress}:$resolverPort"
detour = "direct"
[dns.route]
final = "resolver"
"@
    Assert-M17Config $dnsPath "fragmented-dns"
    $script:activeProcess = Start-M17Candidate $dnsPath "fragmented-dns"
    $adapter = Wait-M17AdapterReady -Name $script:adapterName -Ipv4 $true -Ipv6 $true `
        -Ipv4Dns @("198.18.0.1") -Ipv6Dns @("fd00::1") -ExpectedMtu 1280
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $dnsState = Wait-M17Session $dnsMetricsPort 1 1
    $dnsCompletedBefore = Get-M17MetricValue $dnsState.Metrics "ferrum2_tun_reassembly_completed"
    Invoke-M17DnsBytes "198.18.0.2" "198.18.0.1" (New-M17PaddedDnsQuery 0x1701)
    $dnsMetrics = Get-Metrics $dnsMetricsPort
    Assert-True ((Get-M17MetricValue $dnsMetrics "ferrum2_tun_reassembly_completed") -gt $dnsCompletedBefore) "M17 fragmented synthetic DNS did not complete reassembly"
    Add-M17Witness "fragmented_synthetic_dns" "live-product" "padded UDP DNS query reassembled before synthetic DNS handling"
    Add-M17LiveRow "fragmented-synthetic-dns" ([ordered]@{
        query_bytes = (New-M17PaddedDnsQuery 0x1701).Length
        resolver_requests = $dnsResponder.Requests
    })
    $script:m17CounterAfter = Get-M17CounterSnapshot $dnsMetrics
    Stop-M17Candidate $script:activeProcess "fragmented-dns"
}
