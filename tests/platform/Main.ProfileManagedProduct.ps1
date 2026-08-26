    if ($Mode -eq "managed-product") {
        Assert-PktMonAbsent
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        $systemRouteBaseline = @(Get-Ipv4SystemRouteSnapshot)
        $supportUnderlay = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
        Assert-SupportUnderlayProbe $supportUnderlay "managed product support endpoint"
        Write-CapabilityEvidence "before" ([ordered]@{
            candidate_sha = $capabilityIdentity.Ledger.candidate_sha
            probe_sha256 = $capabilityIdentity.Ledger.probe_sha256
            identity_sha256 = $capabilityIdentityHash
            guest_build = $capabilityIdentity.GuestBuild
            support_underlay = $supportUnderlay | Select-Object InterfaceIndex, SourceAddress, DestinationPrefix, NextHop, PrefixLength, RouteMetric
            physical_dns_rows = $physicalDnsBaseline.Count
            ferrum2_processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            ferrum2_adapters = 0
        })

        $proxySocksPort = Get-UniqueTcpPort
        $directSocksPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        $autoMetricsPort = Get-UniqueTcpPort
        $manualMetricsPort = Get-UniqueTcpPort
        @"
schema_version = 2
[[inbounds]]
tag = "proxy-socks"
listen = "127.0.0.1:$proxySocksPort"
[[inbounds]]
tag = "direct-socks"
listen = "127.0.0.1:$directSocksPort"
[tun]
tag = "tun-in"
adapter_name = "$managedAutoAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "proxy-tcp"
type = "shadowsocks"
server = "${supportAddress}:$supportTcpPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "proxy-udp"
type = "shadowsocks"
server = "${supportAddress}:$supportUdpPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "direct"
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
inbound = "proxy-socks"
network = "tcp"
action = "route"
outbound = "proxy-tcp"
[[route.rules]]
inbound = "proxy-socks"
network = "udp"
action = "route"
outbound = "proxy-udp"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-product"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "dns-udp"
transport = "udp"
address = "${supportAddress}:$supportUdpPort"
[[dns.servers]]
tag = "dns-tcp"
transport = "tcp"
address = "${supportAddress}:$supportTcpPort"
detour = "direct"
[dns.route]
final = "dns-udp"
[[dns.route.rules]]
inbound = "dns-product"
network = "tcp"
action = "route"
server = "dns-tcp"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$autoMetricsPort"
"@ | Set-Content -LiteralPath $managedAutoConfig -Encoding utf8NoBOM

        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$managedManualAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = false
outbound = "direct"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "direct"
type = "direct"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$manualMetricsPort"
"@ | Set-Content -LiteralPath $managedManualConfig -Encoding utf8NoBOM

        foreach ($managedConfig in @($managedAutoConfig, $managedManualConfig)) {
            $offlineOutput = @(& $binary --config $managedConfig --check-config 2>&1)
            Assert-True ($LASTEXITCODE -eq 0) "managed product config validation failed"
            Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed product config marker mismatch"
        }
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $managedAutoAdapterName $null
        Assert-InterfaceGone $managedManualAdapterName $null
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true

        $activeProcess = Start-Candidate $binary $managedAutoConfig
        $adapter = Wait-AdapterReady $managedAutoAdapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $autoMetricsPort)
        $autoAddressSnapshot = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
        Assert-True ($autoAddressSnapshot -contains "IPv4|198.18.0.2|30|Preferred" -and
            $autoAddressSnapshot -contains "IPv6|fd00::2|126|Preferred") "managed product address baseline mismatch"
        $autoMetricBaseline = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        $productRoutes = @(
            Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
        )
        Assert-True ($productRoutes.Count -eq 2) "managed product capture route count mismatch"
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $row = @($productRoutes | Where-Object { $_.DestinationPrefix -ceq $prefix })
            Assert-True ($row.Count -eq 1 -and $row[0].NextHop -ceq "0.0.0.0" -and
                [uint32]$row[0].RouteMetric -eq 1) "managed product capture route readback mismatch"
        }
        $productRouteSnapshot = @($productRoutes | Sort-Object DestinationPrefix |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)" })
        $managedRouteRows = 2

        $pktmonComponentId = Get-PktMonComponentId $adapter
        $pktmonTcpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16ProductTcp", "-i", $supportAddress, "-t", "TCP", "-p", [string]$supportTcpPort))
        $pktmonUdpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16ProductUdp", "-i", $supportAddress, "-t", "UDP", "-p", [string]$supportUdpPort))
        $pktmonStartAttempted = $true
        [void](Invoke-PktMon @("start", "--capture", "--counters-only", "--comp", [string]$pktmonComponentId, "--type", "flow"))
        $pktmonStarted = $true
        $pktmonStartAttempted = $false
        [void](Get-PktMonFlowPackets)

        $filteredBefore = Get-PktMonFlowPackets
        Invoke-UnpinnedTcpCapture $supportAddress $supportTcpPort $autoMetricsPort ([Text.Encoding]::ASCII.GetBytes("m16-product-unpinned-tcp"))
        $managedFilteredPackets.unpinned_tcp = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
        $managedUnpinnedRows++
        $filteredBefore = Get-PktMonFlowPackets
        Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $autoMetricsPort ([Text.Encoding]::ASCII.GetBytes("m16-product-unpinned-udp"))
        $managedFilteredPackets.unpinned_udp = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
        $managedUnpinnedRows++

        $managedFilteredPackets.proxy_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksTcp $proxySocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-proxy-tcp")) $false
        } "managed proxy TCP entered Wintun"
        $managedFixedTcpRows++
        $managedFilteredPackets.proxy_udp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksUdp $proxySocksPort $supportAddress $supportUdpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-proxy-udp")) $false
        } "managed proxy UDP entered Wintun"
        $managedFixedUdpRows++
        $managedFilteredPackets.direct_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksTcp $directSocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-direct-tcp")) $true
        } "managed direct TCP entered Wintun"
        $managedDynamicTcpRows++
        $managedFilteredPackets.direct_udp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksUdp $directSocksPort $supportAddress $supportUdpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-direct-udp")) $true
        } "managed direct UDP entered Wintun"
        $managedDynamicUdpRows++
        $managedFilteredPackets.dns_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductDns $dnsInboundPort $true (New-DnsQuery 0x1601)
        } "managed DNS TCP entered Wintun"
        $managedFixedTcpRows++
        $managedFilteredPackets.dns_udp = Invoke-ProductPinnedRow {
            Invoke-ProductDns $dnsInboundPort $false (New-DnsQuery 0x1602)
        } "managed DNS UDP entered Wintun"
        $managedFixedUdpRows++
        $activeProcess.Refresh()
        Assert-True (-not $activeProcess.HasExited) "managed auto-route candidate exited during product rows"

        $activeMetric = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Assert-True ([string]$activeMetric.AutomaticMetric -eq [string]$autoMetricBaseline.AutomaticMetric -and
            [uint32]$activeMetric.InterfaceMetric -eq [uint32]$autoMetricBaseline.InterfaceMetric) "managed product interface metric changed"
        $activeProductRoutes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
            Sort-Object DestinationPrefix |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)" })
        Assert-SnapshotEqual $productRouteSnapshot $activeProductRoutes "managed product capture ownership"
        $managedInterfaceMetric = "unchanged"
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "managed product physical DNS sentinel"
        Write-CapabilityEvidence "auto-active" ([ordered]@{
            route_rows = $managedRouteRows
            interface_metric = $managedInterfaceMetric
            fixed_tcp_rows = $managedFixedTcpRows
            fixed_udp_rows = $managedFixedUdpRows
            dynamic_tcp_rows = $managedDynamicTcpRows
            dynamic_udp_rows = $managedDynamicUdpRows
            unpinned_rows = $managedUnpinnedRows
            pktmon_filtered_flow_packets = $managedFilteredPackets
        })

        Stop-CapabilityPktMon
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $managedAutoAdapterName
        Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "managed auto-route process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed auto-route DNS residue"
        Wait-Ipv4SystemRouteSnapshot $systemRouteBaseline
        Write-CapabilityEvidence "auto-cleanup" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
        })

        $adapterName = $managedManualAdapterName
        $activeProcess = Start-Candidate $binary $managedManualConfig
        $adapter = Wait-AdapterReady $managedManualAdapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        $manualInterfaceIndex = $ownedInterfaceIndex
        [void](Get-Metrics $manualMetricsPort)
        $manualRouteBaseline = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        Assert-True (@($manualRouteBaseline | Where-Object { $_ -in @("IPv4|0.0.0.0/1|0.0.0.0", "IPv4|128.0.0.0/1|0.0.0.0") }).Count -eq 0) "manual product capture baseline changed"
        $manualMetricBaseline = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        [void](Add-TunRoute $manualInterfaceIndex "0.0.0.0/1" 1)
        [void](Add-TunRoute $manualInterfaceIndex "128.0.0.0/1" 1)
        $manualCaptureRoutes = @(
            Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
        )
        Assert-True ($manualCaptureRoutes.Count -eq 2) "manual capture route readback mismatch"
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $row = @($manualCaptureRoutes | Where-Object { $_.DestinationPrefix -ceq $prefix })
            Assert-True ($row.Count -eq 1 -and $row[0].NextHop -ceq "0.0.0.0" -and
                [uint32]$row[0].RouteMetric -eq 1) "manual capture route readback mismatch"
        }
        Invoke-TunProductTcp $supportAddress $supportTcpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-product-manual-tcp"))
        $managedManualTcpRows++
        Invoke-TunProductUdp $supportAddress $supportUdpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-product-manual-udp"))
        $managedManualUdpRows++
        $manualMetric = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Assert-True ([string]$manualMetric.AutomaticMetric -eq [string]$manualMetricBaseline.AutomaticMetric -and
            [uint32]$manualMetric.InterfaceMetric -eq [uint32]$manualMetricBaseline.InterfaceMetric) "manual product interface metric changed"
        Write-CapabilityEvidence "manual-active" ([ordered]@{
            controller_capture_rows = $manualCaptureRoutes.Count
            manual_tcp_rows = $managedManualTcpRows
            manual_udp_rows = $managedManualUdpRows
            interface_metric = "unchanged"
        })
        foreach ($route in @($ownedRoutes)) { Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop }
        $ownedRoutes.Clear()
        Assert-True (@(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }).Count -eq 0) "manual capture route residue"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $managedManualAdapterName
        Assert-InterfaceGone $managedManualAdapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "managed manual process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed manual DNS residue"
        Wait-Ipv4SystemRouteSnapshot $systemRouteBaseline
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot 0) "managed product final physical DNS sentinel"
        Assert-PktMonAbsent

        Remove-OwnedSiblingDll $runJournalIdentity
        Assert-NotReparsePoint $work "controller work directory"
        Remove-Item -LiteralPath $work -Recurse -Force
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed product sibling DLL residue"
        Assert-True (-not (Test-Path -LiteralPath $work)) "managed product work residue"
        Assert-True (-not (Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue) -and
            -not (Get-NetAdapter -Name $managedManualAdapterName -IncludeHidden -ErrorAction SilentlyContinue)) "managed product adapter residue"
        Write-CapabilityEvidence "after" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = 0
            work = 0
            sibling_dll = 0
            pktmon = "absent"
            physical_dns_rows = @(Get-PhysicalDnsSnapshot 0).Count
        })
    }
