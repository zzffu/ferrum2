function Invoke-M17DualStackDns {
    $resolverAddress = "127.0.0.1"
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $cases = @(
        [ordered]@{ Name = "ipv4-only"; V4 = $true; V6 = $false; V4Dns = @("198.18.0.1"); V6Dns = @(); Fields = @"
ipv4_address = "198.18.0.2/30"
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ },
        [ordered]@{ Name = "ipv6-only"; V4 = $false; V6 = $true; V4Dns = @(); V6Dns = @("fd00::1"); Fields = @"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["2001:db8:17::/48"]
auto_dns = true
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ },
        [ordered]@{ Name = "dual"; V4 = $true; V6 = $true; V4Dns = @("198.18.0.1"); V6Dns = @("fd00::1"); Fields = @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32", "2001:db8:17::/48"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ }
    )
    $caseOrdinal = 0
    foreach ($case in $cases) {
        $caseOrdinal++
        $metricsPort = Get-UniqueTcpPort
        $path = Join-Path $script:work "m17-dns-$($case.Name).toml"
        Write-M17ClientConfig $path $case.Fields "direct" $metricsPort @"
[dns]
timeout_ms = 1000
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
        Assert-M17Config $path "dns-$($case.Name)"
        $script:activeProcess = Start-M17Candidate $path "dns-$($case.Name)"
        $adapter = Wait-M17AdapterReady $script:adapterName $case.V4 $case.V6 $case.V4Dns $case.V6Dns
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        $state = Wait-M17Session $metricsPort 1 1
        if ($caseOrdinal -eq 1) { $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics }
        if ($case.V4) {
            Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false ([uint16](0x1710 + $caseOrdinal))
            Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $true ([uint16](0x1720 + $caseOrdinal))
            if (-not $script:m17WitnessRows.Contains("ipv4_udp_dns")) { Add-M17Witness "ipv4_udp_dns" "live-product" "IPv4 synthetic DNS UDP response validated" }
            if (-not $script:m17WitnessRows.Contains("ipv4_tcp_dns")) { Add-M17Witness "ipv4_tcp_dns" "live-product" "IPv4 synthetic DNS TCP response validated" }
        }
        if ($case.V6) {
            Invoke-M17DnsQuery "fd00::2" "fd00::1" $false ([uint16](0x1730 + $caseOrdinal))
            Invoke-M17DnsQuery "fd00::2" "fd00::1" $true ([uint16](0x1740 + $caseOrdinal))
            if (-not $script:m17WitnessRows.Contains("ipv6_udp_dns")) { Add-M17Witness "ipv6_udp_dns" "live-product" "IPv6 synthetic DNS UDP response validated" }
            if (-not $script:m17WitnessRows.Contains("ipv6_tcp_dns")) { Add-M17Witness "ipv6_tcp_dns" "live-product" "IPv6 synthetic DNS TCP response validated" }
        }
        $activeMetrics = Get-Metrics $metricsPort
        Add-M17LiveRow "dns-$($case.Name)" ([ordered]@{
            ipv4 = $case.V4
            ipv6 = $case.V6
            ipv4_dns = $case.V4Dns
            ipv6_dns = $case.V6Dns
            ingress = Get-M17MetricValue $activeMetrics "ferrum2_tun_packets_ingress"
            egress = Get-M17MetricValue $activeMetrics "ferrum2_tun_packets_egress"
        })
        if ($case.Name -ceq "dual") { $script:m17CounterAfter = Get-M17CounterSnapshot $activeMetrics }
        $oldIndex = $script:ownedInterfaceIndex
        Stop-M17Candidate $script:activeProcess "dns-$($case.Name)"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $oldIndex -ErrorAction SilentlyContinue).Count -eq 0) "M17 DNS rows remained after adapter cleanup"
    }
    Add-M17Witness "dual_dns_readback_and_restore" "live-product" "IPv4-only, IPv6-only and dual exact DNS readback followed by absent-row cleanup"
}

function Invoke-M17UdpPolicy {
    Enable-M17UdpFirewallAdmission
    Add-M17LiveRow "udp-firewall-scope" ([ordered]@{
        policy_store = "ActiveStore"
        direction = "inbound"
        protocol = "udp"
        local_address = "198.18.0.2"
        remote_address = "any"
        local_only_mapping = $true
        program = $script:controllerProgram
        purpose = "prevent Windows stateful endpoint filtering from masking product ADF/EIF while remaining controller-process scoped"
    })
    try {
    $directTarget = [ordered]@{
        Address = [string]$script:capabilityIdentity.SupportAddress
        Port = [int]$script:capabilityIdentity.UdpPort
    }
    Assert-True ([Net.IPAddress]::Parse($directTarget.Address).AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) "M17 UDP direct witness requires the approved IPv4 support listener"
    $targets = @(
        [ordered]@{ Address = "192.0.2.241"; Port = Get-UniqueTcpPort },
        [ordered]@{ Address = "192.0.2.242"; Port = Get-UniqueTcpPort },
        [ordered]@{ Address = "2001:db8::241"; Port = Get-UniqueTcpPort }
    )
    $probes = @(
        Add-M17LoopbackTarget $targets[0].Address $targets[0].Port
        Add-M17LoopbackTarget $targets[1].Address $targets[1].Port
        Add-M17LoopbackTarget $targets[2].Address $targets[2].Port
    )
    $alternatePort = Get-UniqueTcpPort
    $sameAddressAlternate = [Ferrum2UdpProbe]::new($targets[0].Address, $alternatePort)
    $script:tcpResources.Add($sameAddressAlternate)
    foreach ($filtering in @("address_dependent", "endpoint_independent")) {
        $filterLabel = if ($filtering -ceq "address_dependent") { "adf" } else { "eif" }
        $metricsPort = Get-UniqueTcpPort
        $path = Join-Path $script:work "m17-udp-$filterLabel.toml"
        Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "$filtering"
ready_timeout_ms = 15000
"@ "proxy" $metricsPort @"
[[outbounds]]
tag = "direct"
type = "direct"
bind_interface = "$($script:capabilityIdentity.Ledger.topology.guest_interface_alias)"
inet4_bind_address = "$($script:capabilityIdentity.Ledger.topology.guest_ipv4)"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($directTarget.Address)"
port = $($directTarget.Port)
action = "route"
outbound = "direct"
"@
        Assert-M17Config $path "udp-$filterLabel"
        $script:activeProcess = Start-M17Candidate $path "udp-$filterLabel"
        $adapter = Wait-M17AdapterReady $script:adapterName $true $true
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        foreach ($target in $targets) {
            $prefix = if ($target.Address.Contains(":")) { "$($target.Address)/128" } else { "$($target.Address)/32" }
            [void](Add-TunRoute $script:ownedInterfaceIndex $prefix 500)
        }
        [void](Add-TunRoute $script:ownedInterfaceIndex "$($directTarget.Address)/32" 500)
        $targetRoutePreference = @($targets | ForEach-Object {
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $_.Address
        })
        $directCaptureRoute = @(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex `
            -DestinationPrefix "$($directTarget.Address)/32" -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($directCaptureRoute.Count -eq 1) "M17 direct UDP capture route readback is not exact"
        Add-M17LiveRow "udp-$filterLabel-target-route-preference" ([ordered]@{
            client_socket_interface = $script:ownedInterfaceIndex
            routes = $targetRoutePreference
            direct_target = $directTarget
            direct_capture_route_count = $directCaptureRoute.Count
        })
        $state = Wait-M17Session $metricsPort 1 1
        Start-Sleep -Milliseconds 1000
        $preTrafficMetrics = Get-Metrics $metricsPort
        Assert-True ((Get-M17MetricValue $state.Metrics "ferrum2_tun_udp_associations_active") -eq 0 -and
            (Get-M17MetricValue $state.Metrics "ferrum2_tun_udp_candidates_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_associations_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_candidates_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_association_created" $true) -eq 0) "M17 background traffic allocated a UDP association before the test"
        Add-M17LiveRow "udp-$filterLabel-pre-traffic-isolation" ([ordered]@{
            samples = 2
            interval_milliseconds = 1000
            associations_active = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_associations_active"
            candidates_active = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_candidates_active"
            associations_created = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_association_created" $true
        })
        if ($filtering -ceq "address_dependent") { $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics }
        $v4 = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
        $v6 = New-M17TunUdpClient "fd00::2" $script:ownedInterfaceIndex
        try {
            Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v4-a"))
            $relayEndpoint = Wait-M17ProbeRemoteEndpoint $probes[0]
            if ($filtering -ceq "address_dependent") {
                $sameIpBefore = Get-Metrics $metricsPort
                $sameIpEgressBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_packets_egress" $true
                $sameIpFilteredBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_udp_response_filtered" $true
                $sameIpQueueBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_udp_response_queue_full" $true
                $sameIpPayload = [Text.Encoding]::ASCII.GetBytes("m17-adf-same-ip-other-port")
                $sameAddressAlternate.SendTo($sameIpPayload, $relayEndpoint)
                $sameIpMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_packets_egress" $sameIpEgressBefore
                Assert-True ((Get-M17MetricValue $sameIpMetrics "ferrum2_tun_packets_egress") - $sameIpEgressBefore -eq 1 -and
                    (Get-M17MetricValue $sameIpMetrics "ferrum2_tun_udp_response_filtered" $true) -eq $sameIpFilteredBefore -and
                    (Get-M17MetricValue $sameIpMetrics "ferrum2_tun_udp_response_queue_full" $true) -eq $sameIpQueueBefore) "M17 ADF same-IP alternate-port response did not cross the Wintun send boundary exactly once"
                $sameIpPlatformDelivery = Receive-M17UdpIfReady $v4 $targets[0].Address $alternatePort $sameIpPayload
                Add-M17LiveRow "udp-adf-same-ip-alternate-port" ([ordered]@{
                    response_source = "$($targets[0].Address):$alternatePort"
                    wintun_egress_delta = 1
                    response_filtered_delta = 0
                    response_queue_full_delta = 0
                    windows_socket_delivery = $sameIpPlatformDelivery
                    windows_boundary = "delivery is optional because the emulated target address is also owned by guest loopback"
                })
                Add-M17Witness "adf_allows_authorized_ip_any_port" "live-product" "authorized same-IP alternate-port response crossed the live ADF filter and Wintun send boundary; the exact candidate test verifies the emitted source tuple"

                $unauthorizedBefore = Get-Metrics $metricsPort
                $unauthorizedFilteredBefore = Get-M17MetricValue $unauthorizedBefore "ferrum2_tun_udp_response_filtered" $true
                $unauthorizedPayload = [Text.Encoding]::ASCII.GetBytes("m17-adf-unauthorized-ip")
                $probes[1].SendTo($unauthorizedPayload, $relayEndpoint)
                $unauthorizedMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_udp_response_filtered" $unauthorizedFilteredBefore
                Assert-True ((Get-M17MetricValue $unauthorizedMetrics "ferrum2_tun_udp_response_filtered") - $unauthorizedFilteredBefore -eq 1) "M17 ADF unauthorized response was not filtered exactly once"
                Assert-M17UdpQuiet $v4
                Add-M17Witness "adf_rejects_unauthorized_ip" "live-product" "unseen IPv4 peer response was not delivered"
            } else {
                $eifBefore = Get-Metrics $metricsPort
                $eifEgressBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_packets_egress" $true
                $eifFilteredBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_udp_response_filtered" $true
                $eifQueueBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_udp_response_queue_full" $true
                $eifPayload = [Text.Encoding]::ASCII.GetBytes("m17-eif-unseen-ip")
                $probes[1].SendTo($eifPayload, $relayEndpoint)
                $eifMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_packets_egress" $eifEgressBefore
                Assert-True ((Get-M17MetricValue $eifMetrics "ferrum2_tun_packets_egress") - $eifEgressBefore -eq 1 -and
                    (Get-M17MetricValue $eifMetrics "ferrum2_tun_udp_response_filtered" $true) -eq $eifFilteredBefore -and
                    (Get-M17MetricValue $eifMetrics "ferrum2_tun_udp_response_queue_full" $true) -eq $eifQueueBefore) "M17 EIF unseen-peer response did not cross the Wintun send boundary exactly once"
                $eifPlatformDelivery = Receive-M17UdpIfReady $v4 $targets[1].Address $targets[1].Port $eifPayload
                Add-M17LiveRow "udp-eif-unseen-peer" ([ordered]@{
                    response_source = "$($targets[1].Address):$($targets[1].Port)"
                    wintun_egress_delta = 1
                    response_filtered_delta = 0
                    response_queue_full_delta = 0
                    windows_socket_delivery = $eifPlatformDelivery
                    windows_boundary = "delivery is optional because the emulated target address is also owned by guest loopback"
                })
                Add-M17Witness "eif_allows_valid_same_family_peer" "live-product" "unseen same-family response crossed the live EIF filter and Wintun send boundary; the exact candidate test verifies the emitted source tuple"
            }
            if ($filtering -ceq "address_dependent") {
                [uint16]$dnsId = 0x17d1
                [byte[]]$dnsPayload = New-DnsQuery $dnsId
                Assert-M17DnsQueryEnvelope $dnsPayload $dnsId
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $dnsPayload
                Assert-M17DnsQueryEnvelope $probes[0].Received $dnsId

                [byte[]]$quicPayload = New-M17QuicV1InitialEnvelope
                Assert-M17QuicV1InitialEnvelope $quicPayload
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $quicPayload
                Assert-M17QuicV1InitialEnvelope $probes[1].Received

                [byte[]]$stunA = New-M17StunBindingRequest 0x11 $false
                [byte[]]$stunB = New-M17StunBindingRequest 0x31 $false
                Assert-M17StunBindingRequest $stunA $false
                Assert-M17StunBindingRequest $stunB $false
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $stunA
                Assert-M17StunBindingRequest $probes[0].Received $false
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $stunB
                Assert-M17StunBindingRequest $probes[1].Received $false

                [byte[]]$icePayload = New-M17StunBindingRequest 0x51 $true
                Assert-M17StunBindingRequest $icePayload $true
                Invoke-M17UdpEcho $v6 $targets[2].Address $targets[2].Port $icePayload
                Assert-M17StunBindingRequest $probes[2].Received $true

                [byte[]]$gameA = New-M17GamePeerDatagram 1 1001
                [byte[]]$gameB = New-M17GamePeerDatagram 2 1002
                Assert-M17GamePeerDatagram $gameA 1 1001
                Assert-M17GamePeerDatagram $gameB 2 1002
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $gameA
                Assert-M17GamePeerDatagram $probes[0].Received 1 1001
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $gameB
                Assert-M17GamePeerDatagram $probes[1].Received 2 1002

                [byte[]]$laterRulePayload = New-M17StunBindingRequest 0x71 $false
                Assert-M17StunBindingRequest $laterRulePayload $false
                Invoke-M17UdpEcho $v4 $directTarget.Address $directTarget.Port $laterRulePayload

                Add-M17LiveRow "udp-protocol-interoperability" ([ordered]@{
                    dns = [ordered]@{ bytes = $dnsPayload.Length; sha256 = Get-M17PayloadSha256 $dnsPayload; target = "proxy-ipv4-a" }
                    quic_v1_initial = [ordered]@{ bytes = $quicPayload.Length; sha256 = Get-M17PayloadSha256 $quicPayload; target = "proxy-ipv4-b" }
                    stun_servers = @(
                        [ordered]@{ family = "ipv4"; target = "proxy-ipv4-a"; sha256 = Get-M17PayloadSha256 $stunA },
                        [ordered]@{ family = "ipv4"; target = "proxy-ipv4-b"; sha256 = Get-M17PayloadSha256 $stunB }
                    )
                    webrtc_ice = [ordered]@{ family = "ipv6"; bytes = $icePayload.Length; sha256 = Get-M17PayloadSha256 $icePayload }
                    game_peers = @(
                        [ordered]@{ peer = 1; target = "proxy-ipv4-a"; sequence = 1001; sha256 = Get-M17PayloadSha256 $gameA },
                        [ordered]@{ peer = 2; target = "proxy-ipv4-b"; sequence = 1002; sha256 = Get-M17PayloadSha256 $gameB }
                    )
                    later_rule_target = [ordered]@{
                        family = "ipv4"
                        bytes = $laterRulePayload.Length
                        sha256 = Get-M17PayloadSha256 $laterRulePayload
                        independent_rule_outbound = "direct"
                    }
                })
                Add-M17Witness "dns_udp_payload_round_trips" "live-product" "a parsed DNS A query crossed the TUN and Shadowsocks target unchanged"
                Add-M17Witness "quic_v1_initial_envelope_round_trips" "live-product" "a parsed 1,200-byte QUIC v1 Initial envelope crossed the TUN unchanged"
                Add-M17Witness "stun_binding_requests_reach_multiple_servers" "live-product" "distinct valid STUN Binding requests reached two IPv4 server endpoints from one local socket"
                Add-M17Witness "webrtc_ice_candidate_check_round_trips" "live-product" "an IPv6 ICE Binding request with USERNAME, PRIORITY, ICE-CONTROLLING, valid short-term MESSAGE-INTEGRITY, and FINGERPRINT round-tripped unchanged"
                Add-M17Witness "game_style_binary_datagrams_reach_multiple_peers" "live-product" "sequenced binary datagrams reached two peer endpoints from one local socket"
            } else {
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v4-b"))
                Invoke-M17UdpEcho $v6 $targets[2].Address $targets[2].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v6"))
            }

            $capacityBeforeMetrics = Get-Metrics $metricsPort
            $capacityBefore = Get-M17MetricValue $capacityBeforeMetrics "ferrum2_tun_udp_association_rejected_limit" $true
            $capacityRequestsBefore = $probes[0].Requests
            $capacityClient = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
            try {
                $capacityPayload = [Text.Encoding]::ASCII.GetBytes("m17-$filterLabel-capacity-drop-new")
                [void]$capacityClient.Send($capacityPayload, $capacityPayload.Length, $targets[0].Address, $targets[0].Port)
                Assert-M17UdpQuiet $capacityClient
                $capacityMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_udp_association_rejected_limit" $capacityBefore
                Assert-True ($probes[0].Requests -eq $capacityRequestsBefore -and
                    (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_associations_active") -eq 2 -and
                    (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_candidates_active") -eq 0) "M17 association capacity did not drop only the new source"
                $livePayload = [Text.Encoding]::ASCII.GetBytes("m17-$filterLabel-capacity-live-source")
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $livePayload
                Assert-True ($probes[0].WaitRequests($capacityRequestsBefore + 1, 5000)) "M17 live association was evicted under capacity pressure"
            } finally { $capacityClient.Dispose() }
            Add-M17LiveRow "udp-$filterLabel-capacity-drop-new" ([ordered]@{
                configured_associations = 2
                active_associations = Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_associations_active"
                provisional_candidates = Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_candidates_active"
                rejected_limit_delta = (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_association_rejected_limit") - $capacityBefore
                rejected_target_request_delta = $probes[0].Requests - $capacityRequestsBefore - 1
                existing_association_recovery = "echo-pass"
            })
            if ($filtering -ceq "address_dependent") {
                Add-M17Witness "association_capacity_drops_new_without_evicting_live" "live-product" "the third local source was rejected at capacity two while both live associations and an existing echo remained intact"
            }
        } catch {
            $trafficFailure = $_
            $failureMetrics = try { Get-Metrics $metricsPort 2 } catch { $null }
            $script:m17ServerProcess.Refresh()
            $script:m17LiveRows.Add([ordered]@{
                name = "udp-$filterLabel-failure-diagnostic"
                status = "failure"
                evidence = [ordered]@{
                    message = [string]$trafficFailure.Exception.Message
                    client_ipv4_local = [string]$v4.Client.LocalEndPoint
                    client_ipv4_available_bytes = $(try { [int]$v4.Client.Available } catch { -1 })
                    client_ipv4_readable = $(try { [bool]$v4.Client.Poll(0, [Net.Sockets.SelectMode]::SelectRead) } catch { $false })
                    client_ipv6_local = [string]$v6.Client.LocalEndPoint
                    server_alive = -not $script:m17ServerProcess.HasExited
                    server_udp_owner = @(
                        Get-NetUDPEndpoint -LocalPort $script:m17ServerPort -ErrorAction SilentlyContinue |
                            ForEach-Object { [uint32]$_.OwningProcess }
                    )
                    target_requests = @($probes | ForEach-Object { $_.Requests })
                    target_responses = @($probes | ForEach-Object { $_.Responses })
                    target_faults = @($probes | ForEach-Object { $_.Fault })
                    target_remote_endpoints = @($probes | ForEach-Object { [string]$_.RemoteEndpoint })
                    route_preference = $targetRoutePreference
                    packets_ingress = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_packets_ingress" $true } else { $null }
                    packets_egress = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_packets_egress" $true } else { $null }
                    associations_active = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_associations_active" $true } else { $null }
                    candidates_active = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_candidates_active" $true } else { $null }
                    associations_created = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_association_created" $true } else { $null }
                    association_limit_rejections = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_association_rejected_limit" $true } else { $null }
                    response_filtered = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_response_filtered" $true } else { $null }
                    response_queue_full = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_response_queue_full" $true } else { $null }
                    target_to_client_datagrams = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_udp_datagrams" $true } else { $null }
                }
            })
            throw $trafficFailure
        } finally { $v4.Dispose(); $v6.Dispose() }
        $metrics = Get-Metrics $metricsPort
        Assert-True ((Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active") -eq 2 -and
            (Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active") -eq 0) "M17 EIM association/candidate gauges changed"
        Add-M17LiveRow "udp-$filtering" ([ordered]@{
            ipv4_targets = 3
            first_ordinary_route_outbound = "proxy"
            later_ipv4_target_with_independent_direct_rule = 1
            ipv6_targets = 1
            associations_active = Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active"
            candidates_active = Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active"
            target_requests = @($probes | ForEach-Object { $_.Requests })
            same_address_alternate_port = $alternatePort
            unseen_peer = if ($filtering -ceq "address_dependent") { "dropped" } else { "accepted" }
        })
        if ($filtering -ceq "address_dependent") {
            Add-M17Witness "one_eim_association_for_multiple_targets" "live-product" "one IPv4 local socket reached three targets while associations_active remained one per family"
            Add-M17Witness "ipv4_and_ipv6_sources_form_distinct_associations" "live-product" "IPv4 and IPv6 local sources each completed through one source-keyed association"
        } else {
            $script:m17CounterAfter = Get-M17CounterSnapshot $metrics
        }
        Stop-M17Candidate $script:activeProcess "udp-$filterLabel"
    }
    } finally {
        Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
        Assert-True (-not (Get-NetFirewallRule -Name $script:m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 UDP firewall scope was not removed"
        Add-M17LiveRow "udp-firewall-cleanup" ([ordered]@{
            rule_name = $script:m17UdpFirewallRuleName
            active_store_rules = 0
        })
        Add-M17Witness "udp_firewall_scope_is_journaled_and_removed" "live-platform" "the address-scoped ActiveStore allow rule was durably journaled, removed, and read back absent"
    }
}
