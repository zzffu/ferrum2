function Wait-Metric(
    [string]$Name,
    [scriptblock]$Predicate,
    [int]$TimeoutSeconds
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $metrics = Get-Metrics $script:MetricsPort 2
        $value = Get-Metric $metrics $Name
        if (& $Predicate $value) {
            return [pscustomobject]@{ Metrics = $metrics; Value = $value }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "metric wait timed out: $Name"
}

function Wait-CleanDrain([bool]$Udp) {
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $metrics = Get-Metrics $script:MetricsPort 2
        $tcp = Get-Metric $metrics "ferrum2_tun_tcp_flows_active"
        $fragments = Get-Metric $metrics "ferrum2_tun_reassembly_entries_active"
        $udpAssociations = Get-Metric $metrics "ferrum2_tun_udp_associations_active"
        $udpCandidates = Get-Metric $metrics "ferrum2_tun_udp_candidates_active"
        $pendingUdpResponses = Get-Metric $metrics "ferrum2_tun_pending_udp_responses"
        if (
            $tcp -eq 0 -and
            $fragments -eq 0 -and
            ((-not $Udp) -or (
                $udpAssociations -eq 0 -and
                $udpCandidates -eq 0 -and
                $pendingUdpResponses -eq 0
            ))
        ) {
            return $metrics
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "product flow/association/reassembly state did not drain"
}

function Get-ManagedAdapter {
    $rows = @(Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop)
    Assert-Condition ($rows.Count -eq 1) "managed performance adapter identity is not exact"
    return $rows[0]
}

function Get-ManagedAdapterCounter {
    $rows = @(Get-NetAdapterStatistics -Name $AdapterName -ErrorAction Stop)
    Assert-Condition ($rows.Count -eq 1) "managed performance adapter statistics are not exact"
    $statistics = $rows[0]
    return [ordered]@{
        ReceivedUnicastPackets = [uint64]$statistics.ReceivedUnicastPackets
        ReceivedDiscardedPackets = [uint64]$statistics.ReceivedDiscardedPackets
        ReceivedPacketErrors = [uint64]$statistics.ReceivedPacketErrors
        SentUnicastPackets = [uint64]$statistics.SentUnicastPackets
        OutboundDiscardedPackets = [uint64]$statistics.OutboundDiscardedPackets
        OutboundPacketErrors = [uint64]$statistics.OutboundPacketErrors
    }
}

function Get-FragmentCounterSignature(
    [string]$Metrics,
    [object]$AdapterCounters,
    [string]$AdapterIdentity
) {
    $packetReject = Get-PacketRejectCounter -Metrics $Metrics
    $dropCounters = Get-ProductDropCounter -Metrics $Metrics
    $signature = [ordered]@{
        ingress = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_packets_ingress" -AllowAbsent $true)
        accepted = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_packets_accepted" -AllowAbsent $true)
        session_active = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_session_active")
        session_generation = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_session_generation")
        tcp_flows_active = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_tcp_flows_active")
        reassembly_entries_active = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_reassembly_entries_active")
        udp_associations_active = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_udp_associations_active")
        udp_candidates_active = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_udp_candidates_active")
        pending_udp_responses = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_pending_udp_responses")
        reassembly_completed = [uint64](Get-Metric -Metrics $Metrics `
            -Name "ferrum2_tun_reassembly_completed" -AllowAbsent $true)
        packet_rejected_total = [uint64]$packetReject.total
        packet_rejected_family_disabled = [uint64]$packetReject.family_disabled
        packet_rejected_invalid_destination = [uint64]$packetReject.invalid_destination
        packet_rejected_unexpected = [uint64]$packetReject.unexpected
        adapter_identity = $AdapterIdentity
    }
    foreach ($name in $dropCounters.Keys) {
        $signature[$name] = [uint64]$dropCounters[$name]
    }
    foreach ($name in $AdapterCounters.Keys) {
        $signature["adapter_$name"] = [uint64]$AdapterCounters[$name]
    }
    return ($signature | ConvertTo-Json -Compress -Depth 3)
}

function Get-CoherentFragmentCounterSnapshot([int]$TimeoutSeconds = 5) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSignature = $null
    [uint64]$lastIngress = 0
    [uint64]$lastSent = 0
    do {
        # Sandwich the Wintun counters between two product scrapes, then require
        # two identical sandwiches separated by a quiet window. Wintun publishes
        # the ring tail just before its send statistic, so a single equality is
        # not a sufficient stable boundary.
        $metricsBefore = Get-Metrics $script:MetricsPort 2
        $clientProcess.Refresh()
        Assert-Condition (-not $clientProcess.HasExited) `
            "client exited before a coherent fragment counter snapshot"
        $managedAdapter = Get-ManagedAdapter
        $parsedAdapterGuid = [guid]::Empty
        Assert-Condition (
            [guid]::TryParse([string]$managedAdapter.InterfaceGuid, [ref]$parsedAdapterGuid) -and
            $parsedAdapterGuid -ne [guid]::Empty -and
            [uint32]$managedAdapter.ifIndex -gt 0
        ) "managed performance adapter identity is invalid"
        $adapterIdentity = (
            $parsedAdapterGuid.ToString("D").ToLowerInvariant() + "|" +
                [string]$managedAdapter.ifIndex
        )
        $adapterCounters = Get-ManagedAdapterCounter
        $metricsAfter = Get-Metrics $script:MetricsPort 2
        [uint64]$lastIngress = Get-Metric -Metrics $metricsAfter `
            -Name "ferrum2_tun_packets_ingress" -AllowAbsent $true
        [uint64]$lastSent = $adapterCounters.SentUnicastPackets
        $fragmentStateDrained = (
            (Get-Metric -Metrics $metricsAfter -Name "ferrum2_tun_tcp_flows_active") -eq 0 -and
            (Get-Metric -Metrics $metricsAfter `
                -Name "ferrum2_tun_reassembly_entries_active") -eq 0 -and
            (Get-Metric -Metrics $metricsAfter `
                -Name "ferrum2_tun_udp_associations_active") -eq 0 -and
            (Get-Metric -Metrics $metricsAfter `
                -Name "ferrum2_tun_udp_candidates_active") -eq 0 -and
            (Get-Metric -Metrics $metricsAfter `
                -Name "ferrum2_tun_pending_udp_responses") -eq 0
        )
        foreach ($name in @(
            "ReceivedDiscardedPackets", "ReceivedPacketErrors",
            "OutboundDiscardedPackets", "OutboundPacketErrors"
        )) {
            Assert-Condition ([uint64]$adapterCounters[$name] -eq 0) `
                "managed performance adapter recorded packet loss before a coherent snapshot: $name"
        }
        $beforeSignature = Get-FragmentCounterSignature `
            -Metrics $metricsBefore -AdapterCounters $adapterCounters `
            -AdapterIdentity $adapterIdentity
        $afterSignature = Get-FragmentCounterSignature `
            -Metrics $metricsAfter -AdapterCounters $adapterCounters `
            -AdapterIdentity $adapterIdentity
        if (
            $beforeSignature -ceq $afterSignature -and
            $lastIngress -eq $lastSent -and
            $fragmentStateDrained
        ) {
            if ($null -ne $stableSignature -and $stableSignature -ceq $afterSignature) {
                return [pscustomobject]@{
                    Metrics = $metricsAfter
                    AdapterCounters = $adapterCounters
                    AdapterIdentity = $adapterIdentity
                }
            }
            $stableSignature = $afterSignature
        } else {
            $stableSignature = $null
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw (
        "fragment counters did not reach a coherent snapshot: " +
            "ingress=$lastIngress sent=$lastSent"
    )
}

function Get-AdapterCounterDelta([object]$Before, [object]$After) {
    $deltas = [ordered]@{}
    foreach ($name in @(
        "ReceivedUnicastPackets", "ReceivedDiscardedPackets", "ReceivedPacketErrors",
        "SentUnicastPackets", "OutboundDiscardedPackets", "OutboundPacketErrors"
    )) {
        [uint64]$beforeValue = $Before[$name]
        [uint64]$afterValue = $After[$name]
        Assert-Condition ($afterValue -ge $beforeValue) `
            "managed performance adapter counter decreased: $name"
        $deltas[$name] = [uint64]($afterValue - $beforeValue)
    }
    return $deltas
}

function Get-PacketRejectCounter([string]$Metrics) {
    # Windows emits unrelated IPv6 and non-test-destination background traffic
    # into the managed adapter. Subtract only those two closed reasons; any
    # current or future rejection reason remains in the fail-closed anomaly sum.
    [uint64]$packetRejected = Get-Metric `
        -Metrics $Metrics -Name "ferrum2_tun_packets_rejected" -AllowAbsent $true
    [uint64]$familyDisabled = Get-LabeledMetric `
        -Metrics $Metrics -Name "ferrum2_tun_packets_rejected" `
        -Labels @{ reason = "family_disabled" } -AllowAbsent $true
    [uint64]$invalidDestination = Get-LabeledMetric `
        -Metrics $Metrics -Name "ferrum2_tun_packets_rejected" `
        -Labels @{ reason = "invalid_destination" } -AllowAbsent $true
    [decimal]$backgroundRejected = [decimal]$familyDisabled + $invalidDestination
    Assert-Condition ([decimal]$packetRejected -ge $backgroundRejected) `
        "packet rejection reason accounting is inconsistent"
    return [ordered]@{
        total = $packetRejected
        family_disabled = $familyDisabled
        invalid_destination = $invalidDestination
        unexpected = [uint64]([decimal]$packetRejected - $backgroundRejected)
    }
}

function Get-ProductDropCounter([string]$Metrics) {
    $counters = [ordered]@{}
    foreach ($name in @(
        "ferrum2_tun_internal_egress_backpressured",
        "ferrum2_tun_packets_foundation_dropped",
        "ferrum2_tun_reassembly_dropped_limit",
        "ferrum2_tun_reassembly_dropped_malformed",
        "ferrum2_tun_reassembly_dropped_overlap",
        "ferrum2_tun_reassembly_dropped_timeout",
        "ferrum2_tun_tcp_bridge_blocked",
        "ferrum2_tun_tcp_flows_rejected_limit",
        "ferrum2_tun_tcp_flows_reset_restart",
        "ferrum2_tun_udp_association_rejected_limit",
        "ferrum2_tun_udp_datagram_queue_full",
        "ferrum2_tun_udp_response_filtered",
        "ferrum2_tun_udp_response_dropped",
        "ferrum2_tun_udp_response_queue_full",
        "ferrum2_tun_udp_stale_generation",
        "ferrum2_tun_underlay_bind_stale",
        "ferrum2_tun_wintun_ring_full_dropped"
    )) {
        $counters[$name] = [uint64](Get-Metric `
            -Metrics $Metrics -Name $name -AllowAbsent $true
        )
    }
    $packetReject = Get-PacketRejectCounter -Metrics $Metrics
    $counters["ferrum2_tun_packets_rejected_unexpected"] = `
        [uint64]$packetReject.unexpected
    return $counters
}

function Assert-ProductDropCounterUnchanged([object]$Before, [object]$After) {
    foreach ($name in $Before.Keys) {
        Assert-Condition ([uint64]$After[$name] -eq [uint64]$Before[$name]) `
            "workload changed product drop counter: $name"
    }
}

function Get-ManagedIdentity {
    $adapter = Get-ManagedAdapter
    $addresses = @(
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.PrefixOrigin)|$($_.SuffixOrigin)|$($_.SkipAsSource)"
            } | Sort-Object
    )
    $routes = @(
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)|$($_.Protocol)"
            } | Sort-Object
    )
    $dns = @(
        Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$(@($_.ServerAddresses | Sort-Object) -join ',')"
            } | Sort-Object
    )
    $identity = [ordered]@{
        interface_guid = ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
        net_luid = [uint64]$adapter.NetLuid
        interface_index = [uint32]$adapter.ifIndex
        interface_description = [string]$adapter.InterfaceDescription
        addresses = $addresses
        routes = $routes
        dns = $dns
    }
    $bytes = $script:Utf8NoBom.GetBytes(($identity | ConvertTo-Json -Compress -Depth 5))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-LifecycleProcessSnapshot {
    $clientProcess.Refresh()
    Assert-Condition (-not $clientProcess.HasExited) "client exited during lifecycle sampling"
    return [ordered]@{
        process_handles = [uint64]$clientProcess.HandleCount
        process_threads = [uint64]$clientProcess.Threads.Count
    }
}

function Get-LifecycleResources(
    [string]$Metrics,
    [object]$ProcessResources = $null
) {
    if ($null -eq $ProcessResources) {
        $ProcessResources = Get-LifecycleProcessSnapshot
    }
    $managedAdapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop).Count
    return [ordered]@{
        process_handles = [uint64]$ProcessResources.process_handles
        process_threads = [uint64]$ProcessResources.process_threads
        udp_associations_active = [uint64](
            Get-Metric $Metrics "ferrum2_tun_udp_associations_active"
        )
        managed_adapters_active = [uint64]$managedAdapters
    }
}

function Get-ObserverIsolatedLifecycleSnapshot(
    [object]$ExpectedLifecycleMetrics,
    [string]$AdvanceMessage
) {
    # A metrics scrape creates a short-lived connection inside the client. Sample the
    # process after the prior scrape has quiesced and before creating the next one.
    Start-Sleep -Milliseconds 100
    $processResources = Get-LifecycleProcessSnapshot
    $freshMetrics = Get-Metrics $MetricsPort 5
    $freshLifecycleMetrics = Get-NetworkLifecycleMetrics $freshMetrics
    Assert-NetworkLifecycleMetricsEqual `
        $ExpectedLifecycleMetrics $freshLifecycleMetrics $AdvanceMessage
    return Get-LifecycleResources $freshMetrics $processResources
}

function Wait-LifecycleResourcesAtBaseline(
    [object]$Baseline,
    [object]$ExpectedLifecycleMetrics,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $initial = $null
    $stableSamples = 0
    do {
        $current = Get-ObserverIsolatedLifecycleSnapshot `
            $ExpectedLifecycleMetrics `
            "network lifecycle metrics advanced during terminal resource convergence"
        if ($null -eq $initial) { $initial = $current }
        if (
            $current.process_handles -le $Baseline.process_handles -and
            $current.process_threads -le $Baseline.process_threads -and
            $current.udp_associations_active -eq $Baseline.udp_associations_active -and
            $current.managed_adapters_active -eq $Baseline.managed_adapters_active
        ) {
            $stableSamples++
            if ($stableSamples -eq 3) { return $current }
        } else {
            $stableSamples = 0
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    $growth = [ordered]@{
        process_handles = (
            [int64]$current.process_handles - [int64]$Baseline.process_handles
        )
        process_threads = (
            [int64]$current.process_threads - [int64]$Baseline.process_threads
        )
        udp_associations_active = (
            [int64]$current.udp_associations_active -
                [int64]$Baseline.udp_associations_active
        )
        managed_adapters_active = (
            [int64]$current.managed_adapters_active -
                [int64]$Baseline.managed_adapters_active
        )
    }
    $baselineJson = $Baseline | ConvertTo-Json -Compress
    $initialJson = $initial | ConvertTo-Json -Compress
    $currentJson = $current | ConvertTo-Json -Compress
    $growthJson = $growth | ConvertTo-Json -Compress
    throw "lifecycle resources did not return to baseline: baseline=$baselineJson initial=$initialJson final=$currentJson growth=$growthJson"
}

function Wait-LifecycleResourcesStable(
    [object]$ExpectedLifecycleMetrics,
    [int]$TimeoutSeconds = 5
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $samples = [Collections.Generic.List[object]]::new()
    $previous = $null
    do {
        $current = Get-ObserverIsolatedLifecycleSnapshot `
            $ExpectedLifecycleMetrics `
            "network lifecycle metrics advanced during resource convergence"
        $quiescent = (
            $current.process_handles -gt 0 -and
            $current.process_threads -gt 0 -and
            $current.udp_associations_active -eq 0 -and
            $current.managed_adapters_active -eq 1
        )
        $sameAsPrevious = (
            $null -ne $previous -and
            $current.process_handles -eq $previous.process_handles -and
            $current.process_threads -eq $previous.process_threads -and
            $current.udp_associations_active -eq $previous.udp_associations_active -and
            $current.managed_adapters_active -eq $previous.managed_adapters_active
        )
        if (-not $quiescent -or -not $sameAsPrevious) {
            $samples.Clear()
        }
        if ($quiescent) {
            $samples.Add($current)
            if ($samples.Count -eq 3) {
                return [ordered]@{
                    baseline = $current
                    samples = $samples.ToArray()
                }
            }
        }
        $previous = $current
    } while ([DateTime]::UtcNow -lt $deadline)
    $currentJson = $current | ConvertTo-Json -Compress
    $samplesJson = $samples.ToArray() | ConvertTo-Json -Compress -Depth 3
    throw "lifecycle resources did not produce three stable quiescent samples: final=$currentJson samples=$samplesJson"
}

function Get-UnderlayIpv4RouteRows(
    [ValidateSet("ActiveStore", "PersistentStore")][string]$PolicyStore,
    [string]$DestinationPrefix
) {
    $parameters = @{
        AddressFamily = "IPv4"
        InterfaceIndex = $ExpectedUnderlayInterfaceIndex
        PolicyStore = $PolicyStore
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPrefix)) {
        $parameters.DestinationPrefix = $DestinationPrefix
    }
    try {
        return @(Get-NetRoute @parameters)
    } catch {
        if ($_.CategoryInfo.Category -eq
                [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetRoute") {
            return @()
        }
        throw
    }
}

function Get-FixedUnderlayRoute {
    [Net.IPAddress]$fixedEndpoint = $null
    Assert-Condition (
        [Net.IPAddress]::TryParse($ExpectedFixedEndpointIpv4, [ref]$fixedEndpoint) -and
        $fixedEndpoint.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $fixedEndpoint.ToString() -ceq $ExpectedFixedEndpointIpv4
    ) "fixed underlay endpoint must be one canonical IPv4 address"

    $expectedGuid = ([Guid]$ExpectedUnderlayInterfaceGuid).
        ToString("D").ToLowerInvariant()
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        [uint32]$_.ifIndex -eq [uint32]$ExpectedUnderlayInterfaceIndex
    })
    Assert-Condition (
        $adapters.Count -eq 1 -and
        [string]$adapters[0].Name -ceq $ExpectedUnderlayInterfaceAlias -and
        ([Guid]$adapters[0].InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
            $expectedGuid -and
        [string]$adapters[0].Status -ceq "Up"
    ) "fixed underlay adapter identity is not uniquely active"

    $addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ExpectedFixedEndpointIpv4 `
            -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object {
                [uint32]$_.InterfaceIndex -eq [uint32]$ExpectedUnderlayInterfaceIndex
            }
    )
    Assert-Condition (
        $addresses.Count -eq 1 -and
        [string]$addresses[0].IPAddress -ceq $ExpectedFixedEndpointIpv4 -and
        [string]$addresses[0].AddressState -ceq "Preferred" -and
        [string]$addresses[0].InterfaceAlias -ceq $ExpectedUnderlayInterfaceAlias
    ) "fixed underlay endpoint is not one preferred address on the approved adapter"

    $selection = @(Find-NetRoute -RemoteIPAddress $ExpectedFixedEndpointIpv4 `
        -ErrorAction Stop)
    $sourceRows = @($selection | Where-Object {
        $null -ne $_.CimClass -and $_.CimClass.CimClassName -ceq "MSFT_NetIPAddress"
    })
    $routeRows = @($selection | Where-Object {
        $null -ne $_.CimClass -and $_.CimClass.CimClassName -ceq "MSFT_NetRoute"
    })
    $expectedPrefix = "$ExpectedFixedEndpointIpv4/32"
    Assert-Condition (
        $sourceRows.Count -eq 1 -and $routeRows.Count -eq 1 -and
        [string]$sourceRows[0].IPAddress -ceq $ExpectedFixedEndpointIpv4 -and
        [string]$sourceRows[0].AddressState -ceq "Preferred" -and
        [uint32]$sourceRows[0].InterfaceIndex -eq
            [uint32]$ExpectedUnderlayInterfaceIndex -and
        [string]$routeRows[0].DestinationPrefix -ceq $expectedPrefix -and
        [string]$routeRows[0].NextHop -ceq "0.0.0.0" -and
        [string]$routeRows[0].Protocol -ceq "Local" -and
        [string]$routeRows[0].State -ceq "Alive" -and
        [uint32]$routeRows[0].InterfaceIndex -eq
            [uint32]$ExpectedUnderlayInterfaceIndex
    ) "fixed endpoint selection is not the approved underlay-local route"

    $activeRows = @(Get-UnderlayIpv4RouteRows "ActiveStore" $expectedPrefix |
        Where-Object {
            [string]$_.NextHop -ceq "0.0.0.0" -and
            [string]$_.Protocol -ceq "Local"
        })
    $persistentRows = @(Get-UnderlayIpv4RouteRows "PersistentStore" `
        $expectedPrefix | Where-Object { [string]$_.NextHop -ceq "0.0.0.0" })
    Assert-Condition (
        $activeRows.Count -eq 1 -and $persistentRows.Count -eq 0 -and
        [string]$activeRows[0].State -ceq "Alive" -and
        [uint32]$activeRows[0].RouteMetric -le [uint32][uint16]::MaxValue -and
        [uint32]$activeRows[0].RouteMetric -eq [uint32]$routeRows[0].RouteMetric
    ) "fixed underlay route is not one exact ActiveStore-only row"
    return [pscustomobject]@{
        Route = $activeRows[0]
        Adapter = $adapters[0]
    }
}

function New-FixedUnderlayRouteIdentity([object]$Context) {
    return [pscustomobject][ordered]@{
        schema = "ferrum2.windows-tun.fixed-underlay-route-journal.v1"
        fixed_endpoint_ipv4 = $ExpectedFixedEndpointIpv4
        interface_index = [uint32]$Context.Route.InterfaceIndex
        interface_guid = ([Guid]$Context.Adapter.InterfaceGuid).
            ToString("D").ToLowerInvariant()
        interface_name = [string]$Context.Adapter.Name
        policy_store = "ActiveStore"
        destination_prefix = [string]$Context.Route.DestinationPrefix
        next_hop = [string]$Context.Route.NextHop
        protocol = [string]$Context.Route.Protocol
        route_metric = [uint16]$Context.Route.RouteMetric
    }
}

function Assert-FixedUnderlayRouteIdentity([object]$Identity) {
    Assert-ExactProperties $Identity @(
        "schema", "fixed_endpoint_ipv4", "interface_index", "interface_guid",
        "interface_name", "policy_store", "destination_prefix", "next_hop",
        "protocol", "route_metric"
    ) "fixed underlay route identity"
    Assert-Condition (
        [string]$Identity.schema -ceq
            "ferrum2.windows-tun.fixed-underlay-route-journal.v1" -and
        [string]$Identity.fixed_endpoint_ipv4 -ceq $ExpectedFixedEndpointIpv4 -and
        [uint32]$Identity.interface_index -eq
            [uint32]$ExpectedUnderlayInterfaceIndex -and
        [string]$Identity.interface_guid -ceq $ExpectedUnderlayInterfaceGuid -and
        [string]$Identity.interface_name -ceq $ExpectedUnderlayInterfaceAlias -and
        [string]$Identity.policy_store -ceq "ActiveStore" -and
        [string]$Identity.destination_prefix -ceq "$ExpectedFixedEndpointIpv4/32" -and
        [string]$Identity.next_hop -ceq "0.0.0.0" -and
        [string]$Identity.protocol -ceq "Local"
    ) "fixed underlay route identity escaped its approved boundary"
}

function Get-ExactFixedUnderlayRoute([object]$Identity) {
    Assert-FixedUnderlayRouteIdentity $Identity
    $current = Get-FixedUnderlayRoute
    Assert-Condition (
        [uint32]$current.Route.InterfaceIndex -eq [uint32]$Identity.interface_index -and
        ([Guid]$current.Adapter.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
            [string]$Identity.interface_guid -and
        [string]$current.Adapter.Name -ceq [string]$Identity.interface_name -and
        [string]$current.Route.DestinationPrefix -ceq
            [string]$Identity.destination_prefix -and
        [string]$current.Route.NextHop -ceq [string]$Identity.next_hop -and
        [string]$current.Route.Protocol -ceq [string]$Identity.protocol
    ) "fixed underlay route readback changed identity"
    return $current
}

function Wait-ExactFixedUnderlayRoute(
    [object]$Identity,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastFailure = "route was unavailable"
    do {
        try {
            return Get-ExactFixedUnderlayRoute $Identity
        } catch {
            $lastFailure = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "fixed underlay route did not recover: $lastFailure"
}

function Wait-LifecycleTransition(
    [ValidateSet("reset_network", "full_rebuild")][string]$Operation,
    [object]$Before,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 25
        $metrics = Get-Metrics $script:MetricsPort 2
        $current = Get-NetworkLifecycleMetrics $metrics
        $active = Get-Metric $metrics "ferrum2_tun_session_active"
        if ($Operation -ceq "reset_network") {
            $activeFamily = "network_reset"
            $inactiveFamily = "full_rebuild"
        } else {
            $activeFamily = "full_rebuild"
            $inactiveFamily = "network_reset"
        }
        $ready = (
            [uint64]$current.network_generation -eq [uint64]$Before.network_generation + 1 -and
            [uint64]$current.session_generation -eq [uint64]$Before.session_generation + 1 -and
            [uint64]$current["${activeFamily}_started"] -eq
                [uint64]$Before["${activeFamily}_started"] + 1 -and
            [uint64]$current["${activeFamily}_succeeded"] -eq
                [uint64]$Before["${activeFamily}_succeeded"] + 1 -and
            [uint64]$current["${activeFamily}_total"] -eq
                [uint64]$Before["${activeFamily}_total"] + 2 -and
            $active -eq 1
        )
        foreach ($name in @(
            "network_generation", "session_generation",
            "${activeFamily}_started", "${activeFamily}_succeeded"
        )) {
            Assert-Condition (
                [uint64]$current[$name] -ge [uint64]$Before[$name] -and
                [uint64]$current[$name] -le [uint64]$Before[$name] + 1
            ) "network lifecycle transition advanced $name more than once"
        }
        Assert-Condition (
            [uint64]$current["${activeFamily}_failed"] -eq
                [uint64]$Before["${activeFamily}_failed"] -and
            [uint64]$current["${activeFamily}_total"] -ge
                [uint64]$Before["${activeFamily}_total"] -and
            [uint64]$current["${activeFamily}_total"] -le
                [uint64]$Before["${activeFamily}_total"] + 2 -and
            [uint64]$current["${inactiveFamily}_total"] -eq
                [uint64]$Before["${inactiveFamily}_total"]
        ) "network lifecycle transition escaped its closed metric family"
        if ($ready) {
            Assert-NetworkLifecycleTransition $Operation $Before $current
            return [pscustomobject]@{
                Metrics = $metrics
                LifecycleMetrics = $current
            }
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Operation recovery exceeded $TimeoutSeconds seconds"
}
