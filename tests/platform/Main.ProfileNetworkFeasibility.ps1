    if ($Mode -eq "network-feasibility") {
        Assert-PktMonAbsent
        Assert-True ([Ferrum2NetworkFeasibility]::RouteRowSize -eq 104) "route ABI size mismatch"
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $fixedUnderlay = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
        Assert-SupportUnderlayProbe $fixedUnderlay "network-feasibility fixed support endpoint"
        $dynamicUnderlay = [Ferrum2NetworkFeasibility]::GetConstrainedRoute(
            $supportAddress,
            [uint32]$capabilityIdentity.Ledger.topology.guest_interface_index)
        Assert-SupportUnderlayProbe $dynamicUnderlay "network-feasibility constrained support endpoint"

        $preflightTcp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-tcp-live")
        $preflightUdp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-udp-live")
        [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightTcp)
        [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightUdp)

        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        Write-CapabilityEvidence "before" ([ordered]@{
            candidate_sha = $capabilityIdentity.Ledger.candidate_sha
            probe_sha256 = $capabilityIdentity.Ledger.probe_sha256
            identity_sha256 = $capabilityIdentityHash
            guest_build = $capabilityIdentity.GuestBuild
            guest_network_path = $m17GuestNetworkPathDocument.Value
            fixed_underlay = $fixedUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            dynamic_underlay = $dynamicUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            physical_dns = $physicalDnsBaseline
            ferrum2_processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            ferrum2_adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
        })

        $metricsPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "dead"
type = "shadowsocks"
server = "127.0.0.1:9"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[route]
final = "dead"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$supportAddress"
port = $supportTcpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$supportAddress"
port = $supportUdpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[udp]
enabled = false
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:$dnsPort"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$metricsPort"
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($dnsResponder)
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "network feasibility config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "network feasibility config marker mismatch"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        $addressBaseline = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
        $routeBaseline = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $ipv6AddressBaseline = @($addressBaseline | Where-Object { $_ -like "IPv6|*" })
        Assert-True ($addressBaseline -contains "IPv4|198.18.0.2|30|Preferred" -and $addressBaseline -contains "IPv6|fd00::2|126|Preferred") "network feasibility address baseline mismatch"

        $partial = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, "0.0.0.0/1", 1)
        $capabilityRoutes.Add($partial)
        $partial.Verify()
        $partial.Dispose()
        Assert-True $capabilityRoutes.Remove($partial) "partial route journal mismatch"
        Assert-SnapshotEqual $routeBaseline @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex) "partial route rollback"

        $captureTraffic = Get-AdapterTraffic $adapterName
        $captureWindow = [Diagnostics.Stopwatch]::StartNew()
        $firstPrefix = if ([byte][Net.IPAddress]::Parse($supportAddress).GetAddressBytes()[0] -lt 128) { "0.0.0.0/1" } else { "128.0.0.0/1" }
        $secondPrefix = if ($firstPrefix -eq "0.0.0.0/1") { "128.0.0.0/1" } else { "0.0.0.0/1" }
        $firstRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $firstPrefix, 1)
        $capabilityRoutes.Add($firstRoute)
        [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort ([Text.Encoding]::ASCII.GetBytes("m16-capture-window")))
        $secondRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $secondPrefix, 1)
        $capabilityRoutes.Add($secondRoute)
        $captureWindow.Stop()
        Assert-True ($captureWindow.ElapsedMilliseconds -le 3000) "capture-before-admission window exceeded"
        $captureTrafficAfter = Get-AdapterTraffic $adapterName
        Assert-True ($captureTrafficAfter.ReceivedPacketErrors -eq $captureTraffic.ReceivedPacketErrors -and
            $captureTrafficAfter.OutboundPacketErrors -eq $captureTraffic.OutboundPacketErrors -and
            $captureTrafficAfter.ReceivedDiscardedPackets -eq $captureTraffic.ReceivedDiscardedPackets -and
            $captureTrafficAfter.OutboundDiscardedPackets -eq $captureTraffic.OutboundDiscardedPackets) "capture-before-admission overflowed the Wintun ring"
        $capabilityWindowRows = 1
        foreach ($route in $capabilityRoutes) { $route.Verify() }
        $capabilityRouteRows = 2

        Assert-PktMonAbsent
        $pktmonComponentId = Get-PktMonComponentId $adapter
        $pktmonTcpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Tcp", "-i", $supportAddress, "-t", "TCP", "-p", [string]$supportTcpPort))
        $pktmonUdpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Udp", "-i", $supportAddress, "-t", "UDP", "-p", [string]$supportUdpPort))
        $pktmonStartAttempted = $true
        [void](Invoke-PktMon @("start", "--capture", "--counters-only", "--comp", [string]$pktmonComponentId, "--type", "flow"))
        $pktmonStarted = $true
        $pktmonStartAttempted = $false
        [void](Get-PktMonFlowPackets)

        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-tcp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedTcpCapture $supportAddress $supportTcpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_tcp_unpinned"] = $filteredPackets
            $capabilityTcpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned TCP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_tcp_pinned"] = $filteredPackets
            $capabilityTcpRows++
        }
        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-udp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_udp_unpinned"] = $filteredPackets
            $capabilityUdpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned UDP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_udp_pinned"] = $filteredPackets
            $capabilityUdpRows++
        }
        Assert-True ($capabilityTcpRows -eq 4 -and $capabilityUdpRows -eq 4) "socket pin row count mismatch"

        Set-CapabilityDns $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS after Wintun apply"
        try {
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-udp.tun.test" $false)
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-tcp.tun.test" $true)
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "unchanged"
        } catch {
            Set-CapabilityInterfaceMetric $ownedInterfaceIndex
            $capabilityDnsRows = 0
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-lease-udp.tun.test" $false)
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-lease-tcp.tun.test" $true)
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "leased"
        }
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS active sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address active sentinel"

        Write-CapabilityEvidence "active" ([ordered]@{
            interface_metric = $capabilityInterfaceMetric
            capture_window_ms = $captureWindow.ElapsedMilliseconds
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
            tun_accepted = Get-TunAccepted $metricsPort
            route_rows = $capabilityRouteRows
            tcp_rows = $capabilityTcpRows
            udp_rows = $capabilityUdpRows
            dns_rows = $capabilityDnsRows
            pktmon_filtered_flow_packets = $capabilityFilteredPackets
        })

        Stop-CapabilityPktMon
        $routesBeforeCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $limitedBroadcastRoute = "IPv4|255.255.255.255/32|0.0.0.0"
        Assert-True (@($routeBaseline | Where-Object { $_ -ceq $limitedBroadcastRoute }).Count -eq 1) "limited broadcast route baseline mismatch"
        $routeCleanupBaseline = @($routeBaseline | Where-Object { $_ -cne $limitedBroadcastRoute })
        Assert-True ($routeCleanupBaseline.Count -eq $routeBaseline.Count - 1) "limited broadcast cleanup baseline mismatch"
        $captureRouteRows = @(
            "IPv4|0.0.0.0/1|0.0.0.0",
            "IPv4|128.0.0.0/1|0.0.0.0"
        )
        foreach ($captureRouteRow in $captureRouteRows) {
            Assert-True (@($routesBeforeCaptureCleanup | Where-Object { $_ -ceq $captureRouteRow }).Count -eq 1) "owned capture route snapshot mismatch"
        }
        Remove-CapabilityRoutes
        $routeCleanupDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $routesAfterCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            if (@(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup)).Count -eq 0) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $routeCleanupDeadline)
        $routeCleanupDifference = @(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup))
        $routeCleanupLabel = "capture route exact rollback"
        if ($routeCleanupDifference.Count -gt 0) {
            $routeCleanupDiagnostic = @($routeCleanupDifference | Select-Object InputObject,SideIndicator)
            $routeCleanupLabel += " difference=$(ConvertTo-Json -InputObject $routeCleanupDiagnostic -Compress)"
        }
        Assert-SnapshotEqual $routeCleanupBaseline $routesAfterCaptureCleanup $routeCleanupLabel
        Restore-CapabilityDns $ownedInterfaceIndex
        Restore-CapabilityInterfaceMetric $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS normal cleanup sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address normal cleanup sentinel"
        $ownerMetrics = Get-Metrics $metricsPort
        Assert-True ((Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_sessions_active") -eq 0 -and
            (Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_buffered_bytes") -eq 0) "normal cleanup process-private owners remained"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "normal cleanup process residue"
        Write-CapabilityEvidence "normal-cleanup" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
        })

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        if ($capabilityInterfaceMetric -eq "leased") { Set-CapabilityInterfaceMetric $ownedInterfaceIndex }
        Set-CapabilityDns $ownedInterfaceIndex
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $route = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $prefix, 1)
            $capabilityRoutes.Add($route)
        }
        Write-CapabilityEvidence "hard-kill-active" ([ordered]@{
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
        })
        $killedProcess = $activeProcess
        Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$killedProcess.Id)) "TerminateProcess failed"
        Assert-True (Wait-ProcessExit $killedProcess 20) "hard-kill candidate did not exit"
        Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$killedProcess.Id) -ne 0) "hard-kill candidate unexpectedly exited cleanly"
        [Ferrum2ProcessGroup]::Close([uint32]$killedProcess.Id)
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "hard-kill process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill DNS residue"
        Remove-CapabilityRoutes
        $capabilityDnsApplied = $false
        $capabilityDnsSnapshot = $null
        $capabilityMetricApplied = $false
        $capabilityMetricSnapshot = $null
        $capabilityHardKillRows = 1
        Write-CapabilityEvidence "after" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
        })
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS final sentinel"
    }
