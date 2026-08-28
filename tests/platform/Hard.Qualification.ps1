function Invoke-Ferrum2HardKillQualification {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [Collections.IDictionary]$Context)
    $expectedKeys = @(
        'capability_identity', 'binary', 'work', 'managed_auto_adapter_name',
        'managed_lifecycle_config', 'managed_route_only_config', 'sibling_dll',
        'source_dll', 'run_journal_identity', 'tcp_resources', 'run_identity',
        'active_process', 'owned_interface_index', 'dns_responder',
        'sibling_dll_owned'
    )
    if ((@($Context.Keys) -join '|') -cne ($expectedKeys -join '|')) {
        throw 'hard-kill qualification context is not closed'
    }
    $capabilityIdentity = $Context.capability_identity
    $binary = [string]$Context.binary
    $work = [string]$Context.work
    $managedAutoAdapterName = [string]$Context.managed_auto_adapter_name
    $managedLifecycleConfig = [string]$Context.managed_lifecycle_config
    $managedRouteOnlyConfig = [string]$Context.managed_route_only_config
    $siblingDll = [string]$Context.sibling_dll
    $sourceDll = [string]$Context.source_dll
    $runJournalIdentity = $Context.run_journal_identity
    $tcpResources = $Context.tcp_resources
    $runIdentity = [string]$Context.run_identity
    $managedHardKillRows = 0
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
        $Context.sibling_dll_owned = $true
        $dnsResponder = [Ferrum2DnsResponder]::new($managedDnsAddress, $managedDnsPort)
        $tcpResources.Add($dnsResponder)
        $Context.dns_responder = $dnsResponder

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
                $Context.active_process = $activeProcess
                $script:activeProcess = $activeProcess
                $adapter = Wait-AdapterReady -Name $managedAutoAdapterName -TimeoutSeconds 20 `
                    -Managed $true -ManagedDns ([bool]$hardKill.Dns) `
                    -ManagedCapturePrefixes @($hardKillCapturePrefix)
                $ownedInterfaceIndex = [int]$adapter.ifIndex
                $Context.owned_interface_index = $ownedInterfaceIndex
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
                        $dnsResponder.Requests -ge $dnsRequestsBefore + 1 -and
                        $dnsResponder.Requests -le $dnsRequestsBefore + 4
                    ) "hard-kill system DNS did not reach the guest-local responder within bounds"
                    $dnsRequestsObserved = [int]$dnsResponder.Requests
                    $dnsQuietSince = [DateTime]::UtcNow
                    $dnsQuietDeadline = $dnsQuietSince.AddSeconds(2)
                    while ([DateTime]::UtcNow -lt $dnsQuietDeadline -and
                        [DateTime]::UtcNow -lt $dnsQuietSince.AddMilliseconds(500)) {
                        Start-Sleep -Milliseconds 25
                        $dnsRequestsCurrent = [int]$dnsResponder.Requests
                        Assert-True (
                            $dnsRequestsCurrent -le $dnsRequestsBefore + 4
                        ) "hard-kill system DNS retries exceeded the bounded witness"
                        if ($dnsRequestsCurrent -ne $dnsRequestsObserved) {
                            $dnsRequestsObserved = $dnsRequestsCurrent
                            $dnsQuietSince = [DateTime]::UtcNow
                        }
                    }
                    Assert-True (
                        [DateTime]::UtcNow -ge $dnsQuietSince.AddMilliseconds(500)
                    ) "hard-kill system DNS did not become quiet after bounded retries"
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
                $Context.active_process = $null
                $script:activeProcess = $null
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
        $Context.dns_responder = $null
        Remove-OwnedSiblingDll $runJournalIdentity
        $Context.sibling_dll_owned = $false
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed lifecycle sibling DLL residue"
    [pscustomobject][ordered]@{
        cases = [long]$managedHardKillRows
        evidence_path = [string]$script:capabilityEvidence
        cleanup = 'pass'
    }
}
