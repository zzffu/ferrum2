    if ($Mode -in @("full", "hard-kill")) {
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $directSocksPort = Get-UniqueTcpPort
        $proxySocksPort = Get-UniqueTcpPort
        $managedMetricsPort = Get-UniqueTcpPort
        $managedDnsPort = Get-UniqueTcpPort
        $managedDnsInboundPort = Get-UniqueTcpPort
        $physicalDefault = Get-Ipv4DefaultUnderlay
        $managedDnsAddress = [string]$physicalDefault.Sources[0].IPAddress
        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        $systemRouteBaseline = @(Get-Ipv4SystemRouteSnapshot)
        $physicalInterfaceBaseline = Get-NetAdapter -InterfaceIndex $physicalDefault.InterfaceIndex -IncludeHidden -ErrorAction Stop
        Assert-True ([uint64]$physicalInterfaceBaseline.NetLuid -ne 0 -and
            [uint32]$physicalInterfaceBaseline.InterfaceAdminStatus -eq 1 -and
            [uint32]$physicalInterfaceBaseline.InterfaceOperationalStatus -eq 1 -and
            [uint32]$physicalInterfaceBaseline.MediaConnectState -eq 1 -and
            [bool]$physicalInterfaceBaseline.HardwareInterface) "eligible physical interface baseline mismatch"
        $supportFixedRoute = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
        Assert-SupportUnderlayProbe $supportFixedRoute "managed lifecycle support endpoint"
        $supportFixedRouteBaseline = "$supportAddress|$($supportFixedRoute.InterfaceLuid)|$($supportFixedRoute.InterfaceIndex)|$($supportFixedRoute.DestinationPrefix)|$($supportFixedRoute.PrefixLength)|$($supportFixedRoute.NextHop)|$($supportFixedRoute.RouteMetric)|$($supportFixedRoute.SourceAddress)"
        $physicalFixedRouteDestinations = @(@($managedDnsAddress) | Sort-Object -Unique)
        $physicalFixedRouteBaseline = @(
            $physicalFixedRouteDestinations | ForEach-Object {
                $route = [Ferrum2NetworkFeasibility]::GetFixedRoute($_)
                Assert-True ($route.InterfaceLuid -eq $physicalInterfaceBaseline.NetLuid -and
                    $route.InterfaceIndex -eq $physicalDefault.InterfaceIndex -and
                    @($physicalDefault.Sources | Where-Object { $_.IPAddress -ceq $route.SourceAddress }).Count -eq 1) "fixed physical underlay baseline mismatch"
                "$_|$($route.InterfaceLuid)|$($route.InterfaceIndex)|$($route.DestinationPrefix)|$($route.PrefixLength)|$($route.NextHop)|$($route.RouteMetric)|$($route.SourceAddress)"
            }
        )
        $physicalUnderlayBaseline = [pscustomobject]@{
            InterfaceIndex = [uint32]$physicalDefault.InterfaceIndex
            SourceAddress = $managedDnsAddress
            Gateway = [string]$physicalDefault.Row.Route.NextHop
            RouteMetric = [uint32]$physicalDefault.Row.Route.RouteMetric
            InterfaceMetric = [uint32]$physicalDefault.Row.Interface.InterfaceMetric
            AutomaticMetric = $physicalDefault.Row.Interface.AutomaticMetric
            SkipAsSource = [bool]$physicalDefault.Sources[0].SkipAsSource
        }

        @"
schema_version = 2
[[inbounds]]
tag = "direct-socks"
listen = "127.0.0.1:$directSocksPort"
[[inbounds]]
tag = "proxy-socks"
listen = "127.0.0.1:$proxySocksPort"
[tun]
tag = "tun-in"
adapter_name = "$managedAutoAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "${supportAddress}:$supportTcpPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[route]
final = "direct"
[[route.rules]]
inbound = "proxy-socks"
network = "tcp"
action = "route"
outbound = "proxy"
[[route.rules]]
inbound = "proxy-socks"
network = "udp"
action = "route"
outbound = "proxy"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$managedDnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${managedDnsAddress}:$managedDnsPort"
detour = "direct"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$managedMetricsPort"
"@ | Set-Content -LiteralPath $managedLifecycleConfig -Encoding utf8NoBOM

        @"
schema_version = 2
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
tag = "direct"
type = "direct"
[route]
final = "direct"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
action = "reject"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$managedMetricsPort"
"@ | Set-Content -LiteralPath $managedRouteOnlyConfig -Encoding utf8NoBOM

        $managedLifecycleTemplate = Get-Content -LiteralPath $managedLifecycleConfig -Raw
        $managedRouteOnlyTemplate = Get-Content -LiteralPath $managedRouteOnlyConfig -Raw

        foreach ($managedConfig in @($managedLifecycleConfig, $managedRouteOnlyConfig)) {
            $offlineOutput = @(& $binary --config $managedConfig --check-config 2>&1)
            Assert-True ($LASTEXITCODE -eq 0) "managed lifecycle config validation failed"
            Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed lifecycle config marker mismatch"
        }
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed lifecycle sibling DLL baseline not absent"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        $dnsResponder = [Ferrum2DnsResponder]::new($managedDnsAddress, $managedDnsPort)
        $tcpResources.Add($dnsResponder)

        if ($Mode -eq "full") {
            $activeProcess = Start-Candidate $binary $managedLifecycleConfig
            $adapter = Wait-AdapterReady $managedAutoAdapterName 20 $true $true
            $ownedInterfaceIndex = [int]$adapter.ifIndex
            [void](Get-Metrics $managedMetricsPort)
            Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "managed full DNS steering"
            $capture = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") })
            Assert-True ($capture.Count -eq 2) "managed full capture route count mismatch"
            Invoke-TunProductTcp $supportAddress $supportTcpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-full-direct-tcp"))
            $managedDirectTcpRows = 1
            Invoke-TunProductUdp $supportAddress $supportUdpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-full-direct-udp"))
            $managedDirectUdpRows = 1
            Invoke-SystemDnsWitness "m16-$runIdentity-udp.tun.test" $false
            $managedSystemDnsRows++
            Invoke-SystemDnsWitness "m16-$runIdentity-tcp.tun.test" $true
            $managedSystemDnsRows++
            Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "managed full physical DNS sentinel"
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $managedAutoAdapterName
            Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
            Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed full graceful DNS residue"

            Invoke-AdapterCycles $binary $managedRouteOnlyConfig $managedAutoAdapterName $managedMetricsPort $true $directSocksPort

            foreach ($change in @("route", "interface", "address")) {
                $physicalDefault = Get-Ipv4DefaultUnderlay
                $physicalRoute = $physicalDefault.Row.Route
                $physicalAdapter = Get-NetAdapter -InterfaceIndex $physicalDefault.InterfaceIndex -IncludeHidden -ErrorAction Stop
                $sourceAddress = [string]$physicalDefault.Sources[0].IPAddress
                $sourceRow = Get-NetIPAddress -InterfaceIndex $physicalDefault.InterfaceIndex -AddressFamily IPv4 -IPAddress $sourceAddress -ErrorAction Stop
                $routeMetric = [uint32]$physicalRoute.RouteMetric
                $skipAsSource = [bool]$sourceRow.SkipAsSource
                $changeConfiguration = Join-Path $work "client-managed-network-change-$change.toml"
                $changeDirectSocksPort = Get-UniqueTcpPort
                $changeProxySocksPort = Get-UniqueTcpPort
                $changeDnsInboundPort = Get-UniqueTcpPort
                $changeMetricsPort = Get-UniqueTcpPort
                $changeConfigText = $managedLifecycleTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$changeDirectSocksPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$proxySocksPort", "127.0.0.1:$changeProxySocksPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$managedDnsInboundPort", "127.0.0.1:$changeDnsInboundPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$changeMetricsPort")
                try {
                    Assert-True (-not (Test-Path -LiteralPath $changeConfiguration)) "managed network-change generated config baseline not absent"
                    Assert-True (-not $changeConfigText.Contains("127.0.0.1:$directSocksPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$proxySocksPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$managedDnsInboundPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$managedMetricsPort")) "managed network-change listener generation mismatch"
                    Set-Content -LiteralPath $changeConfiguration -Value $changeConfigText -Encoding utf8NoBOM -NoNewline
                    $offlineOutput = @(& $binary --config $changeConfiguration --check-config 2>&1)
                    Assert-True ($LASTEXITCODE -eq 0) "managed network-change generated config validation failed"
                    Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed network-change generated config marker mismatch"

                    $activeProcess = Start-Candidate $binary $changeConfiguration
                    $adapter = Wait-AdapterReady $managedAutoAdapterName 20 $true $true
                    $ownedInterfaceIndex = [int]$adapter.ifIndex
                    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "network-change DNS active"
                    try {
                        if ($change -eq "route") {
                            Set-NetRoute -InputObject $physicalRoute -RouteMetric ($routeMetric + 1) -ErrorAction Stop
                        } elseif ($change -eq "interface") {
                            Disable-NetAdapter -InputObject $physicalAdapter -Confirm:$false -ErrorAction Stop
                        } else {
                            Set-NetIPAddress -InputObject $sourceRow -SkipAsSource (-not $skipAsSource) -ErrorAction Stop
                        }

                        $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(20)
                        do {
                            $captureRemaining = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }).Count
                            $dnsRemaining = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
                            if ($captureRemaining -eq 0 -and $dnsRemaining -eq 0) { break }
                            Start-Sleep -Milliseconds 50
                        } while ([DateTime]::UtcNow -lt $cleanupDeadline)
                        Assert-True ($captureRemaining -eq 0 -and $dnsRemaining -eq 0) "$change change did not remove capture and DNS"

                        $admissionRejected = $activeProcess.HasExited
                        if (-not $admissionRejected) {
                            try {
                                $probe = Open-ProductSocks $changeDirectSocksPort
                                try {
                                    $request = New-SocksRequest 1 $supportAddress $supportTcpPort
                                    $probe.Stream.Write($request, 0, $request.Length)
                                    $reply = Read-SocksReply $probe.Stream
                                    $admissionRejected = $reply.Reply -ne 0
                                } finally { $probe.Client.Dispose() }
                            } catch { $admissionRejected = $true }
                        }
                        Assert-True $admissionRejected "$change change admitted a new socket"
                        Assert-True (Wait-ProcessExit $activeProcess 20) "$change change did not terminate the candidate"
                        Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id) -ne 0) "$change change candidate exited cleanly"
                        [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
                        $activeProcess = $null
                        Wait-AdapterAbsent $managedAutoAdapterName
                        Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
                        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "$change change process residue"
                        $managedNetworkChangeRows++
                        if ($change -eq "route") { $managedRouteChangeRows++ }
                        elseif ($change -eq "interface") { $managedInterfaceChangeRows++ }
                        else { $managedAddressChangeRows++ }
                        Write-CapabilityEvidence "network-change-$change" ([ordered]@{
                            callback = "observed"
                            admission = "rejected"
                            capture = "absent"
                            dns = "absent"
                            supervised_termination = "complete"
                            residue = "absent"
                        })
                    } finally {
                        if ($change -eq "route") {
                            $changedRoute = Get-NetRoute -InterfaceIndex $physicalDefault.InterfaceIndex `
                                -DestinationPrefix $physicalRoute.DestinationPrefix -PolicyStore ActiveStore -ErrorAction Stop |
                                Where-Object { $_.NextHop -ceq $physicalRoute.NextHop }
                            Assert-True (@($changedRoute).Count -eq 1) "physical route restore identity mismatch"
                            Set-NetRoute -InputObject $changedRoute -RouteMetric $routeMetric -ErrorAction Stop
                        } elseif ($change -eq "interface") {
                            Enable-NetAdapter -Name $physicalAdapter.Name -Confirm:$false -ErrorAction Stop
                        } else {
                            Set-NetIPAddress -InterfaceIndex $physicalDefault.InterfaceIndex -IPAddress $sourceAddress `
                                -SkipAsSource $skipAsSource -ErrorAction Stop
                        }

                        $stableDeadline = [DateTime]::UtcNow.AddSeconds(20)
                        $stableSamples = 0
                        do {
                            $baselineMatches = $false
                            try {
                                $currentSystemRoutes = @(Get-Ipv4SystemRouteSnapshot)
                                $currentPhysicalDns = @(Get-PhysicalDnsSnapshot 0)
                                $currentUnderlay = Get-Ipv4DefaultUnderlay
                                $currentPhysicalAdapter = Get-NetAdapter -InterfaceIndex $currentUnderlay.InterfaceIndex -IncludeHidden -ErrorAction Stop
                                $currentFixedRoutes = @(
                                    $physicalFixedRouteDestinations | ForEach-Object {
                                        $route = [Ferrum2NetworkFeasibility]::GetFixedRoute($_)
                                        "$_|$($route.InterfaceLuid)|$($route.InterfaceIndex)|$($route.DestinationPrefix)|$($route.PrefixLength)|$($route.NextHop)|$($route.RouteMetric)|$($route.SourceAddress)"
                                    }
                                )
                                $currentSupportRoute = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
                                Assert-SupportUnderlayProbe $currentSupportRoute "managed lifecycle restored support endpoint"
                                $currentSupportRouteRow = "$supportAddress|$($currentSupportRoute.InterfaceLuid)|$($currentSupportRoute.InterfaceIndex)|$($currentSupportRoute.DestinationPrefix)|$($currentSupportRoute.PrefixLength)|$($currentSupportRoute.NextHop)|$($currentSupportRoute.RouteMetric)|$($currentSupportRoute.SourceAddress)"
                                $currentPreferredSource = @($currentUnderlay.Sources | Where-Object {
                                    $_.IPAddress -ceq $physicalUnderlayBaseline.SourceAddress
                                })
                                $currentSourceRows = @(Get-NetIPAddress -InterfaceIndex $currentUnderlay.InterfaceIndex `
                                    -AddressFamily IPv4 -IPAddress $physicalUnderlayBaseline.SourceAddress -ErrorAction Stop)
                                $currentSourceRow = if ($currentSourceRows.Count -eq 1) { $currentSourceRows[0] } else { $null }
                                $baselineMatches =
                                    @(Compare-Object -ReferenceObject @($systemRouteBaseline) -DifferenceObject $currentSystemRoutes).Count -eq 0 -and
                                    @(Compare-Object -ReferenceObject @($physicalDnsBaseline) -DifferenceObject $currentPhysicalDns).Count -eq 0 -and
                                    @(Compare-Object -ReferenceObject @($physicalFixedRouteBaseline) -DifferenceObject $currentFixedRoutes).Count -eq 0 -and
                                    $currentSupportRouteRow -ceq $supportFixedRouteBaseline -and
                                    $currentUnderlay.InterfaceIndex -eq $physicalUnderlayBaseline.InterfaceIndex -and
                                    $currentPhysicalAdapter.NetLuid -eq $physicalInterfaceBaseline.NetLuid -and
                                    [uint32]$currentPhysicalAdapter.InterfaceAdminStatus -eq [uint32]$physicalInterfaceBaseline.InterfaceAdminStatus -and
                                    [uint32]$currentPhysicalAdapter.InterfaceOperationalStatus -eq [uint32]$physicalInterfaceBaseline.InterfaceOperationalStatus -and
                                    [uint32]$currentPhysicalAdapter.MediaConnectState -eq [uint32]$physicalInterfaceBaseline.MediaConnectState -and
                                    $currentPhysicalAdapter.HardwareInterface -eq $physicalInterfaceBaseline.HardwareInterface -and
                                    $currentPreferredSource.Count -eq 1 -and
                                    $null -ne $currentSourceRow -and
                                    $currentUnderlay.Row.Route.NextHop -ceq $physicalUnderlayBaseline.Gateway -and
                                    $currentUnderlay.Row.Route.RouteMetric -eq $physicalUnderlayBaseline.RouteMetric -and
                                    $currentUnderlay.Row.Interface.InterfaceMetric -eq $physicalUnderlayBaseline.InterfaceMetric -and
                                    $currentUnderlay.Row.Interface.AutomaticMetric -eq $physicalUnderlayBaseline.AutomaticMetric -and
                                    $currentSourceRow.SkipAsSource -eq $physicalUnderlayBaseline.SkipAsSource
                            } catch { $baselineMatches = $false }
                            if ($baselineMatches) { $stableSamples++ }
                            else { $stableSamples = 0 }
                            if ($stableSamples -ge 11) { break }
                            Start-Sleep -Milliseconds 500
                        } while ([DateTime]::UtcNow -lt $stableDeadline)
                        Assert-True ($stableSamples -ge 11) "physical baseline did not stabilize after controller restore"

                        if ($change -eq "interface") {
                            Assert-True $tcpResources.Remove($dnsResponder) "DNS responder ownership mismatch"
                            $dnsResponder.Dispose()
                            $dnsResponder = [Ferrum2DnsResponder]::new($managedDnsAddress, $managedDnsPort)
                            $tcpResources.Add($dnsResponder)
                        }
                    }
                } finally {
                    if (Test-Path -LiteralPath $changeConfiguration) { Remove-Item -LiteralPath $changeConfiguration -Force }
                    Assert-True (-not (Test-Path -LiteralPath $changeConfiguration)) "managed network-change generated config leaked"
                }
            }
            Assert-True ($managedNetworkChangeRows -eq 3 -and $managedRouteChangeRows -eq 1 -and
                $managedInterfaceChangeRows -eq 1 -and $managedAddressChangeRows -eq 1) "managed network-change row count mismatch"
        }

        foreach ($hardKill in @(
            @{ Name = "auto-route"; Dns = $false; Traffic = $false },
            @{ Name = "auto-dns"; Dns = $true; Traffic = $false },
            @{ Name = "mixed"; Dns = $true; Traffic = $true }
        )) {
            $heldHardKillTcp = $null
            $heldHardKillUdp = $null
            $hardKillWfpIdentity = $null
            $hardKillConfiguration = Join-Path $work "client-managed-hard-kill-$($hardKill.Name).toml"
            $hardKillDirectSocksPort = Get-UniqueTcpPort
            $hardKillMetricsPort = Get-UniqueTcpPort
            if ($hardKill.Dns) {
                $hardKillProxySocksPort = Get-UniqueTcpPort
                $hardKillDnsInboundPort = Get-UniqueTcpPort
                $hardKillConfigText = $managedLifecycleTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$hardKillDirectSocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$proxySocksPort", "127.0.0.1:$hardKillProxySocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedDnsInboundPort", "127.0.0.1:$hardKillDnsInboundPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$hardKillMetricsPort")
                Assert-True (
                    @($hardKillConfigText -split '\r?\n' | Where-Object {
                        $_ -ceq "auto_dns = true"
                    }).Count -eq 1 -and
                    @($hardKillConfigText -split '\r?\n' | Where-Object {
                        $_.StartsWith("strict_route =", [StringComparison]::Ordinal)
                    }).Count -eq 0
                ) "managed hard-kill DNS template is ambiguous"
                $hardKillConfigText = $hardKillConfigText.Replace(
                    "auto_dns = true",
                    "strict_route = true`nauto_dns = true"
                )
            } else {
                $hardKillConfigText = $managedRouteOnlyTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$hardKillDirectSocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$hardKillMetricsPort")
            }
            $hardKillCapturePrefix = "$supportAddress/32"
            $autoRouteRows = @($hardKillConfigText -split '\r?\n' | Where-Object { $_ -ceq "auto_route = true" })
            Assert-True ($autoRouteRows.Count -eq 1 -and
                @($hardKillConfigText -split '\r?\n' | Where-Object {
                    $_.StartsWith("route_address =", [StringComparison]::Ordinal)
                }).Count -eq 0) "managed hard-kill capture template is ambiguous"
            $hardKillRouteLine = "route_address = [`"$hardKillCapturePrefix`"]"
            $hardKillConfigText = $hardKillConfigText.Replace(
                "auto_route = true",
                "auto_route = true`n$hardKillRouteLine"
            )
            Assert-True (@($hardKillConfigText -split '\r?\n' | Where-Object {
                $_ -ceq $hardKillRouteLine
            }).Count -eq 1) "managed hard-kill target capture generation mismatch"
            try {
                Assert-True (-not (Test-Path -LiteralPath $hardKillConfiguration)) "managed hard-kill generated config baseline not absent"
                Assert-True (-not $hardKillConfigText.Contains("127.0.0.1:$directSocksPort") -and
                    -not $hardKillConfigText.Contains("127.0.0.1:$managedMetricsPort")) "managed hard-kill listener generation mismatch"
                if ($hardKill.Dns) {
                    Assert-True (-not $hardKillConfigText.Contains("127.0.0.1:$proxySocksPort") -and
                        -not $hardKillConfigText.Contains("127.0.0.1:$managedDnsInboundPort")) "managed hard-kill DNS listener generation mismatch"
                    Assert-True (
                        @($hardKillConfigText -split '\r?\n' | Where-Object {
                            $_ -ceq "strict_route = true"
                        }).Count -eq 1
                    ) "managed hard-kill strict-route generation mismatch"
                }
                Set-Content -LiteralPath $hardKillConfiguration -Value $hardKillConfigText -Encoding utf8NoBOM -NoNewline
                $offlineOutput = @(& $binary --config $hardKillConfiguration --check-config 2>&1)
                Assert-True ($LASTEXITCODE -eq 0) "managed hard-kill generated config validation failed"
                Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed hard-kill generated config marker mismatch"

                $activeProcess = Start-Candidate $binary $hardKillConfiguration
                $adapter = Wait-AdapterReady -Name $managedAutoAdapterName -TimeoutSeconds 20 `
                    -Managed $true -ManagedDns ([bool]$hardKill.Dns) `
                    -ManagedCapturePrefixes @($hardKillCapturePrefix)
                $ownedInterfaceIndex = [int]$adapter.ifIndex
                $hardKillCaptureRoutes = @(
                    Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 `
                        -PolicyStore ActiveStore -ErrorAction Stop |
                        Where-Object { $_.DestinationPrefix -ceq $hardKillCapturePrefix }
                )
                Assert-True ($hardKillCaptureRoutes.Count -eq 1 -and
                    $hardKillCaptureRoutes[0].NextHop -ceq "0.0.0.0" -and
                    [uint32]$hardKillCaptureRoutes[0].RouteMetric -eq 1 -and
                    @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 `
                        -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
                            $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1")
                        }).Count -eq 0) "managed hard-kill target capture readback mismatch"
                if ($hardKill.Dns) {
                    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "hard-kill DNS active"
                    $strictRouteMetrics = Get-Metrics $hardKillMetricsPort
                    Assert-True (
                        (Get-M17MetricValue $strictRouteMetrics `
                            "ferrum2_tun_strict_route_requested") -eq 1 -and
                        (Get-M17MetricValue $strictRouteMetrics `
                            "ferrum2_tun_strict_route_effective") -eq 1 -and
                        (Get-M17LabeledMetricValue $strictRouteMetrics `
                            "ferrum2_tun_strict_route_filter_install" "result" "success") -eq 1 -and
                        (Get-M17LabeledMetricValue $strictRouteMetrics `
                            "ferrum2_tun_strict_route_filter_install" "result" "failure" $true) -eq 0
                    ) "hard-kill strict-route DNS guard is not effective"
                }
                if ($hardKill.Traffic) {
                    $heldHardKillTcp = (Open-TunTcp $supportAddress $supportTcpPort $ownedInterfaceIndex).Client
                    $tcpResources.Add($heldHardKillTcp)
                    $tcpPayload = [Text.Encoding]::ASCII.GetBytes("m16-hard-kill-tcp")
                    $heldHardKillTcp.GetStream().Write($tcpPayload, 0, $tcpPayload.Length)
                    $tcpEcho = Read-ExactBytes $heldHardKillTcp.GetStream() $tcpPayload.Length
                    Assert-True (($tcpEcho -join ",") -eq ($tcpPayload -join ",")) "hard-kill direct TCP echo mismatch"
                    $heldHardKillUdp = Open-TunUdp $supportAddress $supportUdpPort $ownedInterfaceIndex
                    $tcpResources.Add($heldHardKillUdp)
                    $udpPayload = [Text.Encoding]::ASCII.GetBytes("m16-hard-kill-udp")
                    [void]$heldHardKillUdp.Send($udpPayload, $udpPayload.Length)
                    $udpEcho = Receive-TunUdp $heldHardKillUdp
                    Assert-True (($udpEcho -join ",") -eq ($udpPayload -join ",")) "hard-kill direct UDP echo mismatch"
                    Invoke-ProductSocksTcp $hardKillProxySocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-hard-kill-proxy")) $false

                    # Keep this unpinned so it remains a system auto-DNS witness. The effective
                    # strict-route WFP guard permits the candidate/TUN path and blocks ordinary
                    # TCP/UDP DNS fan-out through a physical or management interface.
                    $dnsRequestsBefore = [int]$dnsResponder.Requests
                    [void](Invoke-SystemDnsWitness "m16-$runIdentity-hard-kill.tun.test" $false)
                    $dnsRequestDeadline = [DateTime]::UtcNow.AddSeconds(2)
                    while ($dnsResponder.Requests -lt $dnsRequestsBefore + 1 -and
                        [DateTime]::UtcNow -lt $dnsRequestDeadline) {
                        Start-Sleep -Milliseconds 25
                    }
                    Assert-True (
                        $dnsResponder.Requests -eq $dnsRequestsBefore + 1
                    ) "hard-kill system DNS did not reach the guest-local responder exactly once"
                    Start-Sleep -Milliseconds 500
                    Assert-True (
                        $dnsResponder.Requests -eq $dnsRequestsBefore + 1
                    ) "hard-kill system DNS retried after the guest-local response"
                }
                if ($hardKill.Dns) {
                    $hardKillManagedPlane = Get-M17ManagedPlaneIdentity `
                        $managedAutoAdapterName
                    Assert-True (
                        $hardKillManagedPlane.InterfaceIndex -eq $ownedInterfaceIndex
                    ) "hard-kill strict-route managed plane identity changed"
                    $hardKillWfpIdentity = Get-M17StrictRouteWfpIdentity `
                        "hard-kill-$($hardKill.Name)-active" `
                        $hardKillManagedPlane.InterfaceLuid `
                        ([uint32]$activeProcess.Id) `
                        $work
                }
                Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$activeProcess.Id)) "hard-kill TerminateProcess failed"
                Assert-True (Wait-ProcessExit $activeProcess 20) "hard-kill candidate did not exit"
                Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id) -ne 0) "hard-kill candidate exited cleanly"
                [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
                $activeProcess = $null
                if ($heldHardKillTcp) {
                    Assert-True $tcpResources.Remove($heldHardKillTcp) "hard-kill TCP witness ownership mismatch"
                    $heldHardKillTcp.Dispose()
                }
                if ($heldHardKillUdp) {
                    Assert-True $tcpResources.Remove($heldHardKillUdp) "hard-kill UDP witness ownership mismatch"
                    $heldHardKillUdp.Dispose()
                }
                Wait-AdapterAbsent $managedAutoAdapterName 20 11
                Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
                Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "hard-kill process residue"
                Assert-True (@(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill address residue"
                Assert-True (@(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill route residue"
                Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill DNS residue"
                if ($hardKill.Dns) {
                    Assert-M17StrictRouteWfpIdentityAbsent `
                        "hard-kill-$($hardKill.Name)-absent" `
                        $hardKillWfpIdentity `
                        $work
                }
                $managedHardKillRows++
                Write-CapabilityEvidence "hard-kill-$($hardKill.Name)" ([ordered]@{
                    process = "absent"
                    adapter = "absent"
                    addresses = "absent"
                    routes = "absent"
                    dns = "absent"
                    strict_route_wfp = if ($hardKill.Dns) {
                        [ordered]@{
                            applicable = $true
                            before_kill = [ordered]@{
                                session_key = [string]$hardKillWfpIdentity.SessionKey
                                sublayer_key = [string]$hardKillWfpIdentity.SublayerKey
                                owner_pid = [long]$hardKillWfpIdentity.ProcessId
                                interface_luid = [string]$hardKillWfpIdentity.InterfaceLuid
                                app_id_sha256 = [string]$hardKillWfpIdentity.AppIdSha256
                                filters = @($hardKillWfpIdentity.Filters |
                                    ForEach-Object {
                                        [ordered]@{
                                            key = [string]$_.Key
                                            id = [string]$_.Id
                                        }
                                    })
                                identity_sha256 = [string]$hardKillWfpIdentity.Sha256
                            }
                            after_kill = [ordered]@{
                                session = "absent"
                                sublayer = "absent"
                                filters = "absent"
                            }
                        }
                    } else {
                        [ordered]@{ applicable = $false }
                    }
                }) 2
            } finally {
                if (Test-Path -LiteralPath $hardKillConfiguration) { Remove-Item -LiteralPath $hardKillConfiguration -Force }
                Assert-True (-not (Test-Path -LiteralPath $hardKillConfiguration)) "managed hard-kill generated config leaked"
            }
        }
        Assert-True ($managedHardKillRows -eq 3) "hard-kill row count mismatch"
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot 0) "managed lifecycle final physical DNS sentinel"
        Assert-True $tcpResources.Remove($dnsResponder) "managed lifecycle DNS responder ownership mismatch"
        $dnsResponder.Dispose()
        $dnsResponder = $null
        Remove-OwnedSiblingDll $runJournalIdentity
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed lifecycle sibling DLL residue"
    }
