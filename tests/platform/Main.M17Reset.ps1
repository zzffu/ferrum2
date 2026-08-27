function Invoke-M17NetworkReset {
    $udpAssociationLimit = 32
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-network-reset.toml"
    $resolverAddress = "127.0.0.1"
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $supportAddress = $script:capabilityIdentity.SupportAddress
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$supportAddress/32"]
strict_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = $udpAssociationLimit
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $script:m17MetricsPort @"
[[outbounds]]
tag = "network-probe"
type = "shadowsocks"
server = "$($script:m17NetworkResetProbeAddress):8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "dns-direct"
type = "direct"
[[selectors]]
tag = "network-egress"
outbounds = ["direct", "network-probe"]
default = "direct"
[route]
final = "network-egress"
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
detour = "dns-direct"
[dns.route]
final = "resolver"
"@ $true
    Assert-M17Config $path "network-reset"
    $script:activeProcess = Start-M17Candidate $path "network-reset"
    $candidatePid = [uint32]$script:activeProcess.Id
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $managedBaseline = Get-M17ManagedPlaneIdentity $script:adapterName
    $wfpBaseline = Get-M17StrictRouteWfpIdentity "network-reset-0000" $managedBaseline.InterfaceLuid $candidatePid
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-network-reset-before"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-network-reset-before"))
    Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false 0x1710
    $initialDrain = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    $baseline = Get-M17NetworkResetMetricState $initialDrain.Metrics
    Assert-True ($baseline.StrictRequested -eq 1 -and $baseline.StrictEffective -eq 1 -and
        $baseline.StrictInstallSucceeded -ge 1 -and $baseline.StrictInstallFailed -eq 0 -and
        $baseline.SessionGeneration -eq $initial.Generation -and
        $baseline.ResetStarted -eq $baseline.ResetSucceeded -and $baseline.ResetFailed -eq 0 -and
        $baseline.RetryStarted -eq 0 -and $baseline.RetrySucceeded -eq 0 -and $baseline.RetryFailed -eq 0 -and
        $baseline.FullRebuild -eq 0) "M17 network-reset strict-route or lifecycle metric baseline is invalid"
    $script:m17CounterBefore = Get-M17CounterSnapshot $initialDrain.Metrics
    Add-M17LiveRow "network-reset-baseline" ([ordered]@{
        process_id = $candidatePid
        interface_guid = $managedBaseline.InterfaceGuid
        interface_luid = $managedBaseline.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
        interface_index = $managedBaseline.InterfaceIndex
        managed_plane_sha256 = $managedBaseline.Sha256
        managed_plane = $managedBaseline.Document
        strict_route_wfp_sha256 = $wfpBaseline.Sha256
        strict_route_filters = $wfpBaseline.FilterCount
        strict_route_filter_ids = @($wfpBaseline.FilterIds)
        strict_route_session_key = $wfpBaseline.SessionKey
        strict_route_sublayer_key = $wfpBaseline.SublayerKey
        session_generation = $baseline.SessionGeneration
        network_generation = $baseline.NetworkGeneration
    })

    $evidencePath = Join-Path $script:m17ArtifactRoot "network-reset-cycles.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $evidencePath)) "M17 network-reset cycle evidence baseline is not absent"
    $stream = [IO.FileStream]::new($evidencePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true
    $evidenceBytes = 0
    $wfpSamples = 1
    $sampleStride = [Math]::Max(1, [int][Math]::Ceiling($script:NetworkResetCycles / 10.0))
    $mutation = $null
    $final = $null
    try {
        foreach ($cycle in 1..$script:NetworkResetCycles) {
            if ($cycle -eq 1) {
                $mutation = Start-M17NetworkResetRouteMutation
                $mutationKind = "create"
            } else {
                $metric = if (($cycle % 2) -eq 0) { [uint32]4095 } else { [uint32]4094 }
                Set-M17NetworkResetRouteMetric $mutation $metric
                $mutationKind = "metric_toggle"
            }
            $expectedGeneration = $initial.Generation + $cycle
            $final = Wait-M17NetworkResetCycle $script:m17MetricsPort $baseline $cycle $expectedGeneration
            $script:activeProcess.Refresh()
            Assert-True (-not $script:activeProcess.HasExited -and [uint32]$script:activeProcess.Id -eq $candidatePid) "M17 ordinary network reset replaced the client process"
            $managed = Get-M17ManagedPlaneIdentity $script:adapterName
            Assert-True ($managed.Canonical -ceq $managedBaseline.Canonical) "M17 ordinary network reset changed managed adapter/address/route/DNS state"
            $sampleWfp = $cycle -eq 1 -or $cycle -eq $script:NetworkResetCycles -or ($cycle % $sampleStride) -eq 0
            if ($sampleWfp) {
                $wfp = Get-M17StrictRouteWfpIdentity ("network-reset-{0:D4}" -f $cycle) $managed.InterfaceLuid $candidatePid
                Assert-True ($wfp.Canonical -ceq $wfpBaseline.Canonical) "M17 ordinary network reset replaced the strict-route WFP session or filters"
                $wfpSamples++
            }
            $payload = [Text.Encoding]::ASCII.GetBytes(("m17-network-reset-{0:D4}" -f $cycle))
            Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex $payload
            Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex $payload
            if ($sampleWfp) { Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false ([uint16](0x1800 + ($cycle % 2048))) }
            $drained = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
            $state = Get-M17NetworkResetMetricState $drained.Metrics
            Assert-True ($state.ResetStarted -eq $final.State.ResetStarted -and
                $state.ResetSucceeded -eq $final.State.ResetSucceeded -and
                $state.ResetFailed -eq $baseline.ResetFailed -and
                $state.RetryStarted -eq $baseline.RetryStarted -and
                $state.RetrySucceeded -eq $baseline.RetrySucceeded -and
                $state.RetryFailed -eq $baseline.RetryFailed -and
                $state.SessionGeneration -eq $expectedGeneration -and
                $state.NetworkGeneration -eq $expectedGeneration -and
                $state.FullRebuild -eq $baseline.FullRebuild -and
                $state.StrictRequested -eq 1 -and $state.StrictEffective -eq 1 -and
                $state.StrictInstallSucceeded -eq $baseline.StrictInstallSucceeded -and
                $state.StrictInstallFailed -eq $baseline.StrictInstallFailed) "M17 post-reset health changed lifecycle state"
            $row = [ordered]@{
                cycle = $cycle
                mutation = $mutationKind
                route_metric = [uint32]$mutation.RouteMetric
                process_id = $candidatePid
                interface_guid = $managed.InterfaceGuid
                interface_luid = $managed.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
                interface_index = $managed.InterfaceIndex
                managed_plane_sha256 = $managed.Sha256
                strict_route_wfp_sha256 = $wfpBaseline.Sha256
                wfp_sampled = $sampleWfp
                session_generation = $state.SessionGeneration
                network_generation = $state.NetworkGeneration
                reset_started = $state.ResetStarted
                reset_succeeded = $state.ResetSucceeded
                reset_failed = $state.ResetFailed
                full_rebuild = $state.FullRebuild
                strict_route_effective = $state.StrictEffective
            }
            $line = $row | ConvertTo-Json -Compress -Depth 4
            $lineBytes = [Text.UTF8Encoding]::new($false).GetByteCount($line) + 1
            $evidenceBytes += $lineBytes
            Assert-True ($evidenceBytes -le 1048576) "M17 network-reset cycle evidence exceeded its 1 MiB boundary"
            $writer.WriteLine($line)
            if ($cycle -in $script:releaseMilestones) {
                Add-M17LiveRow ("network-reset-milestone-{0:D4}" -f $cycle) ([ordered]@{
                    cycle = $cycle
                    status = "pass"
                    process_id = $candidatePid
                    session_generation = $state.SessionGeneration
                    network_generation = $state.NetworkGeneration
                    reset_succeeded = $state.ResetSucceeded
                    managed_plane_sha256 = $managed.Sha256
                    strict_route_wfp_sha256 = $wfpBaseline.Sha256
                })
            }
        }
    } finally { $writer.Dispose() }

    $finalMetrics = Get-Metrics $script:m17MetricsPort 2
    $finalState = Get-M17NetworkResetMetricState $finalMetrics
    Assert-True ($finalState.ResetStarted -eq $baseline.ResetStarted + $script:NetworkResetCycles -and
        $finalState.ResetSucceeded -eq $baseline.ResetSucceeded + $script:NetworkResetCycles -and
        $finalState.ResetFailed -eq $baseline.ResetFailed -and
        $finalState.RetryStarted -eq $baseline.RetryStarted -and
        $finalState.RetrySucceeded -eq $baseline.RetrySucceeded -and
        $finalState.RetryFailed -eq $baseline.RetryFailed -and
        $finalState.SessionGeneration -eq $initial.Generation + $script:NetworkResetCycles -and
        $finalState.NetworkGeneration -eq $finalState.SessionGeneration -and
        $finalState.NetworkGeneration -gt $baseline.NetworkGeneration -and
        $finalState.FullRebuild -eq $baseline.FullRebuild -and
        $finalState.StrictRequested -eq 1 -and $finalState.StrictEffective -eq 1 -and
        $finalState.StrictInstallSucceeded -eq $baseline.StrictInstallSucceeded -and
        $finalState.StrictInstallFailed -eq $baseline.StrictInstallFailed) "M17 network-reset final lifecycle contract changed"
    $evidenceItem = Get-Item -LiteralPath $evidencePath -Force -ErrorAction Stop
    $evidence = [IO.File]::ReadAllBytes($evidencePath)
    Assert-True ($evidenceItem.Length -eq $evidenceBytes -and $evidenceItem.Length -le 1048576 -and
        @($evidence | Where-Object { $_ -eq 10 }).Count -eq $script:NetworkResetCycles -and
        @($evidence | Where-Object { $_ -eq 13 }).Count -eq 0) "M17 network-reset cycle evidence is not closed"
    $evidenceText = [Text.UTF8Encoding]::new($false, $true).GetString($evidence)
    $evidenceLines = $evidenceText.Split([char[]]@([char]10), [StringSplitOptions]::None)
    Assert-True ($evidenceLines.Count -eq $script:NetworkResetCycles + 1 -and
        $evidenceLines[-1].Length -eq 0) "M17 network-reset cycle evidence row count is invalid"
    $cycleProperties = @(
        "cycle", "mutation", "route_metric", "process_id", "interface_guid", "interface_luid",
        "interface_index", "managed_plane_sha256", "strict_route_wfp_sha256", "wfp_sampled",
        "session_generation", "network_generation", "reset_started", "reset_succeeded",
        "reset_failed", "full_rebuild", "strict_route_effective"
    )
    foreach ($offset in 0..($script:NetworkResetCycles - 1)) {
        $cycle = $offset + 1
        $row = $evidenceLines[$offset] | ConvertFrom-Json -Depth 4 -ErrorAction Stop
        Assert-ClosedJsonProperties $row $cycleProperties "M17 network-reset cycle evidence row"
        $expectedMetric = if ($cycle -eq 1 -or ($cycle % 2) -ne 0) { 4094 } else { 4095 }
        $expectedMutation = if ($cycle -eq 1) { "create" } else { "metric_toggle" }
        $expectedWfpSample = $cycle -eq 1 -or $cycle -eq $script:NetworkResetCycles -or
            ($cycle % $sampleStride) -eq 0
        Assert-True ($row.cycle -is [long] -and [long]$row.cycle -eq $cycle -and
            $row.mutation -is [string] -and $row.mutation -ceq $expectedMutation -and
            $row.route_metric -is [long] -and [long]$row.route_metric -eq $expectedMetric -and
            $row.process_id -is [long] -and [uint32]$row.process_id -eq $candidatePid -and
            $row.interface_guid -is [string] -and $row.interface_guid -ceq $managedBaseline.InterfaceGuid -and
            $row.interface_luid -is [string] -and $row.interface_luid -ceq $managedBaseline.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture) -and
            $row.interface_index -is [long] -and [uint32]$row.interface_index -eq $managedBaseline.InterfaceIndex -and
            $row.managed_plane_sha256 -is [string] -and $row.managed_plane_sha256 -ceq $managedBaseline.Sha256 -and
            $row.strict_route_wfp_sha256 -is [string] -and $row.strict_route_wfp_sha256 -ceq $wfpBaseline.Sha256 -and
            $row.wfp_sampled -is [bool] -and $row.wfp_sampled -eq $expectedWfpSample -and
            $row.session_generation -is [double] -and $row.network_generation -is [double] -and
            $row.reset_started -is [double] -and $row.reset_succeeded -is [double] -and
            $row.reset_failed -is [double] -and
            $row.full_rebuild -is [double] -and $row.strict_route_effective -is [double] -and
            [double]$row.session_generation -eq $initial.Generation + $cycle -and
            [double]$row.network_generation -eq $initial.Generation + $cycle -and
            [double]$row.reset_started -eq $baseline.ResetStarted + $cycle -and
            [double]$row.reset_succeeded -eq $baseline.ResetSucceeded + $cycle -and
            [double]$row.reset_failed -eq $baseline.ResetFailed -and
            [double]$row.full_rebuild -eq $baseline.FullRebuild -and
            [double]$row.strict_route_effective -eq 1) "M17 network-reset cycle evidence row values are invalid: cycle=$cycle"
    }
    $routeIntent = Read-M17NetworkResetRouteMutationIntent ([string]$mutation.IntentPath)
    $foreignRoute = @(Get-NetRoute -InterfaceIndex ([int]$routeIntent.interface_index) `
        -DestinationPrefix ([string]$routeIntent.destination_prefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$routeIntent.next_hop -and [uint32]$_.RouteMetric -in @($routeIntent.route_metrics) })
    Assert-True ($foreignRoute.Count -eq 1) "M17 journaled notification route did not survive ordinary resets"
    $script:m17CounterAfter = Get-M17CounterSnapshot $finalMetrics
    Add-M17Witness "ordinary_route_notifications_reset_network_runtime" "live-product" "$script:NetworkResetCycles journaled underlay route mutations completed lightweight ResetNetwork"
    Add-M17Witness "same_process_and_managed_adapter_identity" "live-product" "every reset retained one PID and the exact adapter GUID, LUID, and interface index"
    Add-M17Witness "managed_addresses_routes_and_dns_are_unchanged" "live-product" "every reset reproduced the exact managed-plane address, route, DNS, MTU, and adapter snapshot hash"
    Add-M17Witness "strict_route_is_effective_and_filter_identity_is_unchanged" "live-product" "every notification passed exact strict-route health revalidation, and $wfpSamples bounded WFP snapshots retained the same process-owned dynamic session and eight dual-stack DNS guard filter IDs"
    Add-M17Witness "network_generation_and_reset_metrics_advance" "live-product" "network and TUN generations plus successful ResetNetwork counters advanced exactly once per mutation"
    Add-M17Witness "retry_reset_failure_and_full_rebuild_metrics_are_unchanged" "live-product" "retry, reset-failure, and full-rebuild counters remained at baseline"
    Add-M17LiveRow "network-reset-summary" ([ordered]@{
        cycles = $script:NetworkResetCycles
        process_id = $candidatePid
        initial_session_generation = $initial.Generation
        final_session_generation = $finalState.SessionGeneration
        final_network_generation = $finalState.NetworkGeneration
        reset_started_delta = $finalState.ResetStarted - $baseline.ResetStarted
        reset_succeeded_delta = $finalState.ResetSucceeded - $baseline.ResetSucceeded
        reset_failed_delta = $finalState.ResetFailed - $baseline.ResetFailed
        full_rebuild_delta = $finalState.FullRebuild - $baseline.FullRebuild
        strict_route_filter_install_delta = $finalState.StrictInstallSucceeded - $baseline.StrictInstallSucceeded
        managed_plane_sha256 = $managedBaseline.Sha256
        strict_route_wfp_sha256 = $wfpBaseline.Sha256
        strict_route_filter_ids = @($wfpBaseline.FilterIds)
        strict_route_health_revalidations = $script:NetworkResetCycles
        strict_route_wfp_samples = $wfpSamples
        cycle_evidence = [IO.Path]::GetFileName($evidencePath)
        cycle_evidence_bytes = $evidenceItem.Length
        cycle_evidence_sha256 = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
    Stop-M17Candidate $script:activeProcess "network-reset"
    Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
    Assert-True (@(Get-NetRoute -DestinationPrefix $script:m17NetworkResetProbePrefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 network-reset notification route cleanup was not exact"
    Add-M17LiveRow "network-reset-mutation-cleanup" ([ordered]@{
        destination_prefix = $script:m17NetworkResetProbePrefix
        active_store_routes = 0
        mutation_journal = "absent"
    })
}

function Invoke-M17RestartStress {
    $udpAssociationLimit = 32
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-restart-stress.toml"
    $resolverAddress = "127.0.0.1"
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $supportAddress = $script:capabilityIdentity.SupportAddress
    Assert-True ($supportAddress -cne "198.51.100.254") "M17 restart notification prefix collides with the support listener"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$supportAddress/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = $udpAssociationLimit
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $script:m17MetricsPort @"
[[outbounds]]
tag = "dns-direct"
type = "direct"
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
detour = "dns-direct"
[dns.route]
final = "resolver"
"@ $true
    Assert-M17Config $path "restart-stress"
    $script:activeProcess = Start-M17Candidate $path "restart-stress"
    $candidatePid = [uint32]$script:activeProcess.Id
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $initial.Metrics
    $associationLimitBefore = Get-M17MetricValue $initial.Metrics "ferrum2_tun_udp_association_rejected_limit" $true
    Assert-True ($associationLimitBefore -eq 0) "M17 restart baseline already exhausted the UDP association limit"
    $preHealthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    Assert-True ((Get-M17MetricValue $preHealthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 initial pre-health association limit changed"
    Add-M17LiveRow "restart-initial-pre-health" ([ordered]@{
        generation = $preHealthBaseline.Generation
        udp_associations = $preHealthBaseline.UdpAssociations
        udp_candidates = $preHealthBaseline.UdpCandidates
        handler_tasks = $preHealthBaseline.HandlerTasks
    })
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-before"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-before"))
    $healthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    Assert-True ($healthBaseline.UdpCandidates -eq 0 -and
        $healthBaseline.UdpAssociations -le $udpAssociationLimit -and
        $healthBaseline.HandlerTasks -eq $healthBaseline.UdpAssociations -and
        (Get-M17MetricValue $healthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 initial handler/association baseline is not bounded"
    $maxSettledUdpAssociations = [Math]::Max($preHealthBaseline.UdpAssociations, $healthBaseline.UdpAssociations)
    $maxSettledHandlerTasks = [Math]::Max($preHealthBaseline.HandlerTasks, $healthBaseline.HandlerTasks)

    $generation = $initial.Generation
    $lifecycleBefore = Get-M17ManagedRouteRebuildMetricState $initial.Metrics
    foreach ($cycle in 1..$script:RestartCycles) {
        Remove-M17ManagedRouteForRestart $script:ownedInterfaceIndex "$supportAddress/32"
        $expectedGeneration = $generation + 1
        [void](Wait-M17Session $script:m17MetricsPort $expectedGeneration 1 45)
        Start-Sleep -Milliseconds 500
        $stableState = Wait-M17Session $script:m17MetricsPort $expectedGeneration 1 10
        Assert-True ($stableState.Generation -eq $expectedGeneration -and
            $stableState.Active -eq 1) "M17 restart produced more than one stable generation"
        $script:activeProcess.Refresh()
        Assert-True (-not $script:activeProcess.HasExited -and [uint32]$script:activeProcess.Id -eq $candidatePid) "M17 restart replaced the client process"
        $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-M17ExactManagedRoute $script:ownedInterfaceIndex "$supportAddress/32")
        $preHealthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
        Assert-True ((Get-M17MetricValue $preHealthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 per-cycle pre-health association limit changed"
        $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $preHealthBaseline.UdpAssociations)
        $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $preHealthBaseline.HandlerTasks)
        Add-M17LiveRow ("restart-cycle-{0:D4}-pre-health" -f $cycle) ([ordered]@{
            cycle = $cycle
            generation = $preHealthBaseline.Generation
            process_id = $candidatePid
            interface_index = $script:ownedInterfaceIndex
            tcp_flows = $preHealthBaseline.TcpFlows
            udp_associations = $preHealthBaseline.UdpAssociations
            udp_candidates = $preHealthBaseline.UdpCandidates
            reassembly_entries = $preHealthBaseline.ReassemblyEntries
            handler_tasks = $preHealthBaseline.HandlerTasks
        })
        $payload = [Text.Encoding]::ASCII.GetBytes(("m17-restart-{0:D4}" -f $cycle))
        Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex $payload
        Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex $payload
        $cycleBaseline = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
        Assert-True ($cycleBaseline.UdpCandidates -eq 0 -and
            $cycleBaseline.UdpAssociations -le $udpAssociationLimit -and
            $cycleBaseline.HandlerTasks -eq $cycleBaseline.UdpAssociations -and
            (Get-M17MetricValue $cycleBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 per-cycle handler/association baseline changed"
        $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $cycleBaseline.UdpAssociations)
        $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $cycleBaseline.HandlerTasks)
        Add-M17LiveRow ("restart-cycle-{0:D4}-post-health" -f $cycle) ([ordered]@{
            cycle = $cycle
            generation = $cycleBaseline.Generation
            process_id = $candidatePid
            interface_index = $script:ownedInterfaceIndex
            tcp_flows = $cycleBaseline.TcpFlows
            udp_associations = $cycleBaseline.UdpAssociations
            udp_candidates = $cycleBaseline.UdpCandidates
            reassembly_entries = $cycleBaseline.ReassemblyEntries
            handler_tasks = $cycleBaseline.HandlerTasks
            tcp_health = "pass"
            udp_health = "pass"
        })
        if ($cycle -in $script:releaseMilestones) {
            Add-M17LiveRow ("restart-stress-milestone-{0:D4}" -f $cycle) ([ordered]@{
                cycle = $cycle
                status = "pass"
                process_id = $candidatePid
                generation = $cycleBaseline.Generation
                interface_index = $script:ownedInterfaceIndex
                tcp_health = "pass"
                udp_health = "pass"
            })
        }
        $generation = $expectedGeneration
    }
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-after"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-after"))
    $finalBaseline = Wait-M17FlowDrain $script:m17MetricsPort $generation $udpAssociationLimit
    $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $finalBaseline.UdpAssociations)
    $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $finalBaseline.HandlerTasks)
    $finalMetrics = $finalBaseline.Metrics
    $lifecycleAfter = Get-M17ManagedRouteRebuildMetricState $finalMetrics
    Assert-True ($generation -eq $initial.Generation + $script:RestartCycles -and
        $lifecycleAfter.SessionGeneration -eq $generation -and
        $lifecycleAfter.NetworkGeneration -eq $generation -and
        $lifecycleAfter.RouteDamageStarted -eq $lifecycleBefore.RouteDamageStarted + $script:RestartCycles -and
        $lifecycleAfter.RouteDamageSucceeded -eq $lifecycleBefore.RouteDamageSucceeded + $script:RestartCycles -and
        $lifecycleAfter.RouteDamageFailed -eq $lifecycleBefore.RouteDamageFailed -and
        $lifecycleAfter.FullRebuildTotal -eq $lifecycleBefore.FullRebuildTotal + (2 * $script:RestartCycles) -and
        $lifecycleAfter.NetworkResetTotal -eq $lifecycleBefore.NetworkResetTotal -and
        (Get-M17MetricValue $finalMetrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 restart stress counters changed"
    $script:m17CounterAfter = Get-M17CounterSnapshot $finalMetrics
    Add-M17Witness "same_process_for_every_restart" "live-product" "$script:RestartCycles observed notifications retained one PID"
    Add-M17Witness "generation_advances_once_per_restart" "live-product" "each notification reached exactly the next stable generation"
    Add-M17Witness "adapter_route_dns_and_handler_baselines_restore" "live-product" "dual-stack adapter, capture route, DNS, TCP and UDP recovered after every restart with zero candidates, exact handler/association parity and no capacity rejection"
    Add-M17LiveRow "restart-stress" ([ordered]@{
        cycles = $script:RestartCycles
        process_id = $candidatePid
        initial_generation = $initial.Generation
        final_generation = $generation
        route_damage_rebuild_started = $lifecycleAfter.RouteDamageStarted
        route_damage_rebuild_succeeded = $lifecycleAfter.RouteDamageSucceeded
        route_damage_rebuild_failed = $lifecycleAfter.RouteDamageFailed
        network_reset_delta = $lifecycleAfter.NetworkResetTotal - $lifecycleBefore.NetworkResetTotal
        udp_association_limit = $udpAssociationLimit
        max_settled_udp_associations = $maxSettledUdpAssociations
        max_settled_handler_tasks = $maxSettledHandlerTasks
        udp_association_limit_rejections = Get-M17MetricValue $finalMetrics "ferrum2_tun_udp_association_rejected_limit" $true
    })
    Stop-M17Candidate $script:activeProcess "restart-stress"
}
