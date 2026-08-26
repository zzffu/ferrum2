Start-Sleep -Seconds 5
$underlay = Get-FixedUnderlayRoute
$underlayRouteIdentity = New-FixedUnderlayRouteIdentity $underlay
$underlayJournal = Join-Path $script:WorkRoot "underlay-route-journal.json"
[IO.File]::WriteAllText(
    $underlayJournal,
    (($underlayRouteIdentity | ConvertTo-Json -Compress) + "`n"),
    $script:Utf8NoBom
)
[uint16[]]$routeMetrics = if (
    [uint16]$underlayRouteIdentity.route_metric -le
        ([uint16]::MaxValue - 2)
) {
    @(
        [uint16]([uint16]$underlayRouteIdentity.route_metric + 1),
        [uint16]([uint16]$underlayRouteIdentity.route_metric + 2),
        [uint16]$underlayRouteIdentity.route_metric
    )
} elseif ([uint16]$underlayRouteIdentity.route_metric -ge 2) {
    @(
        [uint16]([uint16]$underlayRouteIdentity.route_metric - 1),
        [uint16]([uint16]$underlayRouteIdentity.route_metric - 2),
        [uint16]$underlayRouteIdentity.route_metric
    )
} else {
    throw "fixed underlay route metric has no bounded three-state mutation"
}
$initial = Get-Metrics $MetricsPort 5
$lifecycleMetrics = Get-NetworkLifecycleMetrics $initial
Assert-Condition (
    [uint64]$lifecycleMetrics.network_generation -ge 1 -and
    [uint64]$lifecycleMetrics.network_generation -eq
        [uint64]$lifecycleMetrics.session_generation
) "published network/session generations are unavailable or inconsistent"
$managedIdentity = Get-ManagedIdentity
$coldStartResources = Get-LifecycleResources $initial
Assert-Condition (
    $coldStartResources.udp_associations_active -eq 0 -and
    $coldStartResources.managed_adapters_active -eq 1
) "network lifecycle cold-start resources are not quiescent"
$resourceWarmupCycles = [Collections.Generic.List[object]]::new()
$warmupRouteMutationIndex = 0
$baselineResources = $null
$baselineResourceSamples = $null
Invoke-Probe
foreach ($warmupCycle in 1..12) {
    $before = Get-Metrics $MetricsPort 5
    [uint64]$tcpBefore = Get-Metric $before "ferrum2_tun_tcp_flows_active"
    [uint64]$udpBefore = Get-Metric $before "ferrum2_tun_udp_associations_active"
    Assert-Condition ($udpBefore -ge 1) `
        "resource warmup cycle lacks a live UDP association"
    $identityBefore = $managedIdentity
    $lifecycleBefore = Get-NetworkLifecycleMetrics $before
    Assert-NetworkLifecycleMetricsEqual $lifecycleMetrics $lifecycleBefore `
        "network lifecycle metrics advanced between resource warmup cycles"
    $currentRoute = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
    [uint16]$routeMetricBefore = $currentRoute.Route.RouteMetric
    $nextMetric = $routeMetrics[$warmupRouteMutationIndex % $routeMetrics.Count]
    $warmupRouteMutationIndex++
    Set-NetRoute -InputObject $currentRoute.Route -RouteMetric $nextMetric `
        -ErrorAction Stop
    $routeReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
    Assert-Condition (
        [uint16]$routeReadback.Route.RouteMetric -eq [uint16]$nextMetric
    ) "resource warmup route metric was not read back exactly"
    $transition = Wait-LifecycleTransition "reset_network" $lifecycleBefore 30
    $identityAfter = Get-ManagedIdentity
    $resourcesAfter = Get-LifecycleResources $transition.Metrics
    Assert-Condition (
        (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
        (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
    ) "resource warmup ResetNetwork retained a connection"
    if ($warmupCycle -eq 12) {
        Start-Sleep -Seconds 30
        $stableResources = Wait-LifecycleResourcesStable `
            $transition.LifecycleMetrics 5
        $baselineResources = $stableResources.baseline
        $baselineResourceSamples = $stableResources.samples
    }
    Invoke-Probe
    $afterProbe = Get-Metrics $MetricsPort 5
    $lifecycleAfter = Get-NetworkLifecycleMetrics $afterProbe
    Assert-NetworkLifecycleMetricsEqual `
        $transition.LifecycleMetrics $lifecycleAfter `
        "resource warmup probe traffic triggered an extra lifecycle transition"
    $resourceWarmupCycles.Add([ordered]@{
        sequence = [uint64]$warmupCycle
        operation = "reset_network"
        reason = "route_change"
        route_metric_before = [uint64]$routeMetricBefore
        route_metric_after = [uint64]$nextMetric
        lifecycle_metrics_before = $lifecycleBefore
        lifecycle_metrics_after = $lifecycleAfter
        managed_identity_before = $identityBefore
        managed_identity_after = $identityAfter
        tcp_flows_before = $tcpBefore
        udp_associations_before = $udpBefore
        tcp_flows_closed = $tcpBefore
        udp_associations_closed = $udpBefore
        tcp_probe_succeeded = $true
        udp_probe_succeeded = $true
        resources_after = $resourcesAfter
    })
    $managedIdentity = $identityAfter
    $lifecycleMetrics = $lifecycleAfter
}
Assert-Condition (
    $warmupRouteMutationIndex -eq 12 -and
    $routeMetrics[($warmupRouteMutationIndex - 1) % $routeMetrics.Count] -eq
        [uint16]$underlayRouteIdentity.route_metric
) "resource warmup route schedule did not end at its baseline"
$warmupUnderlayReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
Assert-Condition (
    [uint16]$warmupUnderlayReadback.Route.RouteMetric -eq
        [uint16]$underlayRouteIdentity.route_metric
) "resource warmup route metric baseline was not restored in-band"
Assert-Condition (
    $null -ne $baselineResources -and
    $null -ne $baselineResourceSamples -and
    @($baselineResourceSamples).Count -eq 3
) "resource warmup did not establish a stable quiescent baseline"
$resourceWarmup = [ordered]@{
    reset_network_cycles = [uint64]12
    route_metric_baseline = [uint64]$underlayRouteIdentity.route_metric
    quiescence_seconds = [uint64]30
    cold_start_resources = $coldStartResources
    cycles = $resourceWarmupCycles.ToArray()
    baseline_resource_samples = $baselineResourceSamples
}
$cycles = [Collections.Generic.List[object]]::new()
$resetLatencies = [Collections.Generic.List[uint64]]::new()
$rebuildLatencies = [Collections.Generic.List[uint64]]::new()
$routeMutationIndex = 0
$interfaceSwitchRecovery = $null

foreach ($cycle in 1..1000) {
    $before = Get-Metrics $MetricsPort 5
    [uint64]$tcpBefore = Get-Metric $before "ferrum2_tun_tcp_flows_active"
    [uint64]$udpBefore = Get-Metric $before "ferrum2_tun_udp_associations_active"
    Assert-Condition ($udpBefore -ge 1) "reset cycle lacks a live UDP association"
    $identityBefore = $managedIdentity
    $lifecycleBefore = Get-NetworkLifecycleMetrics $before
    Assert-NetworkLifecycleMetricsEqual $lifecycleMetrics $lifecycleBefore `
        "network lifecycle metrics advanced between reset cycles"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $reason = "route_change"
    if ($cycle -eq 500) {
        $reason = "interface_change"
        $interfaceJournal = Join-Path $script:WorkRoot `
            "underlay-interface-journal.json"
        [IO.File]::WriteAllText(
            $interfaceJournal,
            (($underlayRouteIdentity | ConvertTo-Json -Compress) + "`n"),
            $script:Utf8NoBom
        )
        Disable-NetAdapter -Name $underlayRouteIdentity.interface_name `
            -Confirm:$false -ErrorAction Stop
        Start-Sleep -Milliseconds 100
        Enable-NetAdapter -Name $underlayRouteIdentity.interface_name `
            -Confirm:$false -ErrorAction Stop
        [void](Wait-ExactFixedUnderlayRoute $underlayRouteIdentity 30)
        Start-Sleep -Seconds 5
    } else {
        $currentRoute = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
        $nextMetric = $routeMetrics[$routeMutationIndex % $routeMetrics.Count]
        $routeMutationIndex++
        Set-NetRoute -InputObject $currentRoute.Route -RouteMetric $nextMetric `
            -ErrorAction Stop
        $routeReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
        Assert-Condition (
            [uint16]$routeReadback.Route.RouteMetric -eq [uint16]$nextMetric
        ) "fixed underlay metric mutation was not read back exactly"
    }
    $transition = Wait-LifecycleTransition "reset_network" $lifecycleBefore 30
    $identityAfter = Get-ManagedIdentity
    if ($cycle -eq 1000) {
        $timer.Stop()
        $resourceCheckpoints = [ordered]@{}
        foreach ($index in @(0, 1, 9, 99, 498, 499, 500, 998)) {
            $resourceCheckpoints[[string]($index + 1)] =
                $cycles[$index].resources_after
        }
        try {
            $resourcesAfter = Wait-LifecycleResourcesAtBaseline `
                $baselineResources $transition.LifecycleMetrics 30
        } catch {
            $checkpointJson = $resourceCheckpoints |
                ConvertTo-Json -Compress -Depth 3
            throw "$($_.Exception.Message) checkpoints=$checkpointJson"
        }
        $timer.Start()
    } else {
        $resourcesAfter = Get-LifecycleResources $transition.Metrics
    }
    Assert-Condition (
        (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
        (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
    ) "ResetNetwork retained a connection"
    if ($cycle -eq 500) {
        $interfaceSwitchRecovery = Invoke-InterfaceSwitchRecoveryProbe `
            -ExpectedLifecycleMetrics $transition.LifecycleMetrics `
            -RecoveryTimer $timer -TimeoutSeconds 30
    } else {
        Invoke-Probe
    }
    $timer.Stop()
    $afterProbe = Get-Metrics $MetricsPort 5
    $lifecycleAfter = Get-NetworkLifecycleMetrics $afterProbe
    Assert-NetworkLifecycleMetricsEqual `
        $transition.LifecycleMetrics $lifecycleAfter `
        "probe traffic triggered an extra lifecycle transition after ResetNetwork"
    $elapsed = Get-ElapsedNanoseconds $timer
    $resetLatencies.Add($elapsed)
    $cycles.Add([ordered]@{
        sequence = [uint64]$cycle
        operation = "reset_network"
        reason = $reason
        elapsed_nanoseconds = $elapsed
        lifecycle_metrics_before = $lifecycleBefore
        lifecycle_metrics_after = $lifecycleAfter
        managed_identity_before = $identityBefore
        managed_identity_after = $identityAfter
        tcp_flows_before = $tcpBefore
        udp_associations_before = $udpBefore
        tcp_flows_closed = $tcpBefore
        udp_associations_closed = $udpBefore
        tcp_probe_succeeded = $true
        udp_probe_succeeded = $true
        resources_after = $resourcesAfter
    })
    $managedIdentity = $identityAfter
    $lifecycleMetrics = $lifecycleAfter
    if ($cycle -eq 500) {
        $currentUnderlay = Get-ExactFixedUnderlayRoute `
            $underlayRouteIdentity
        Assert-Condition (
            [string]$currentUnderlay.Adapter.Status -ceq "Up"
        ) "fixed underlay interface switch did not restore its route"
        Remove-Item -LiteralPath $interfaceJournal -Force
    }
}
Assert-Condition (
    $routeMutationIndex -eq 999 -and
    $routeMetrics[($routeMutationIndex - 1) % $routeMetrics.Count] -eq
        [uint16]$underlayRouteIdentity.route_metric
) "fixed underlay route metric schedule did not end at its baseline"
$underlayReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
Assert-Condition (
    [uint16]$underlayReadback.Route.RouteMetric -eq
        [uint16]$underlayRouteIdentity.route_metric
) "fixed underlay route metric baseline was not restored in-band"
Remove-Item -LiteralPath $underlayJournal -Force
foreach ($rebuild in 1..10) {
    $before = Get-Metrics $MetricsPort 5
    [uint64]$tcpBefore = Get-Metric $before "ferrum2_tun_tcp_flows_active"
    [uint64]$udpBefore = Get-Metric $before "ferrum2_tun_udp_associations_active"
    Assert-Condition ($udpBefore -ge 1) "full rebuild cycle lacks a live UDP association"
    $identityBefore = $managedIdentity
    $lifecycleBefore = Get-NetworkLifecycleMetrics $before
    Assert-NetworkLifecycleMetricsEqual $lifecycleMetrics $lifecycleBefore `
        "network lifecycle metrics advanced between full-rebuild cycles"
    $managed = Get-ManagedAdapter
    $prefix = "$script:TargetAddress/32"
    $managedRoutes = @(
        Get-NetRoute -InterfaceIndex $managed.ifIndex -DestinationPrefix $prefix `
            -PolicyStore ActiveStore -ErrorAction Stop
    )
    Assert-Condition ($managedRoutes.Count -eq 1) `
        "full rebuild damage target is not one exact managed route"
    $managedRouteIdentity = [ordered]@{
        interface_guid = ([Guid]$managed.InterfaceGuid).ToString("D").ToLowerInvariant()
        destination_prefix = [string]$managedRoutes[0].DestinationPrefix
        next_hop = [string]$managedRoutes[0].NextHop
        route_metric = [uint32]$managedRoutes[0].RouteMetric
    }
    $managedJournal = Join-Path $script:WorkRoot "managed-route-journal.json"
    [IO.File]::WriteAllText(
        $managedJournal,
        (($managedRouteIdentity | ConvertTo-Json -Compress) + "`n"),
        $script:Utf8NoBom
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $managedRoutes[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
    $transition = Wait-LifecycleTransition "full_rebuild" $lifecycleBefore 30
    $identityAfter = Get-ManagedIdentity
    if ($rebuild -eq 10) {
        $timer.Stop()
        Start-Sleep -Seconds 30
        $stableResources = Wait-LifecycleResourcesStable `
            $transition.LifecycleMetrics 5
        $resourcesAfter = $stableResources.baseline
        $timer.Start()
    } else {
        $resourcesAfter = Get-LifecycleResources $transition.Metrics
    }
    Assert-Condition (
        (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
        (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
    ) "managed full rebuild retained a connection"
    $restoredAdapter = Get-ManagedAdapter
    $restoredRoutes = @(
        Get-NetRoute -InterfaceIndex $restoredAdapter.ifIndex `
            -DestinationPrefix $managedRouteIdentity.destination_prefix `
            -PolicyStore ActiveStore -ErrorAction Stop
    )
    Assert-Condition (
        $restoredRoutes.Count -eq 1 -and
        [string]$restoredRoutes[0].NextHop -ceq $managedRouteIdentity.next_hop -and
        [uint32]$restoredRoutes[0].RouteMetric -eq $managedRouteIdentity.route_metric
    ) "managed route was not rebuilt exactly"
    Remove-Item -LiteralPath $managedJournal -Force
    Invoke-Probe
    $timer.Stop()
    $afterProbe = Get-Metrics $MetricsPort 5
    $lifecycleAfter = Get-NetworkLifecycleMetrics $afterProbe
    Assert-NetworkLifecycleMetricsEqual `
        $transition.LifecycleMetrics $lifecycleAfter `
        "probe traffic triggered an extra lifecycle transition after full rebuild"
    $elapsed = Get-ElapsedNanoseconds $timer
    $rebuildLatencies.Add($elapsed)
    $cycles.Add([ordered]@{
        sequence = [uint64](1000 + $rebuild)
        operation = "full_rebuild"
        reason = "route_damage"
        elapsed_nanoseconds = $elapsed
        lifecycle_metrics_before = $lifecycleBefore
        lifecycle_metrics_after = $lifecycleAfter
        managed_identity_before = $identityBefore
        managed_identity_after = $identityAfter
        tcp_flows_before = $tcpBefore
        udp_associations_before = $udpBefore
        tcp_flows_closed = $tcpBefore
        udp_associations_closed = $udpBefore
        tcp_probe_succeeded = $true
        udp_probe_succeeded = $true
        resources_after = $resourcesAfter
    })
    $managedIdentity = $identityAfter
    $lifecycleMetrics = $lifecycleAfter
}

$resolverBefore = Get-Metrics $MetricsPort 5
[double]$resolutionsBefore = Get-Metric $resolverBefore `
    "ferrum2_outbound_interface_resolution" $true
[double]$cacheHitsBefore = Get-Metric $resolverBefore `
    "ferrum2_outbound_interface_resolution_cache_hit" $true
foreach ($probe in 1..32) { Invoke-Probe }
$resolverAfter = Get-Metrics $MetricsPort 5
[uint64]$resolutions = (Get-Metric $resolverAfter `
    "ferrum2_outbound_interface_resolution" $true) - $resolutionsBefore
[uint64]$cacheHits = (Get-Metric $resolverAfter `
    "ferrum2_outbound_interface_resolution_cache_hit" $true) - $cacheHitsBefore
Assert-Condition ($resolutions -ge 32 -and $resolutions -le 256 -and $cacheHits -gt 0 `
    -and $cacheHits -le $resolutions) "interface resolver cache-hit evidence is invalid"
Assert-Condition ($null -ne $interfaceSwitchRecovery) `
    "interface-switch recovery evidence is missing"
[void](Wait-CleanDrain $true)
$finalMetrics = Get-Metrics $MetricsPort 5
Assert-Condition (
    (Get-Metric $finalMetrics "ferrum2_tun_udp_associations_active") -eq 0 -and
    -not $clientProcess.HasExited -and -not $serverProcess.HasExited
) "network lifecycle did not reach a clean final drain"

$rawIdentity = [ordered]@{
    run_kind = $RunKind
    member = $Member
    pair = [uint64]$Pair
    trial_sequence = [uint64]$Sequence
    client_pid = [uint64]$ClientPid
    server_pid = [uint64]$ServerPid
    vm_name = $ExpectedVmName
    vm_id = $ExpectedVmId
    checkpoint_name = $ExpectedCheckpointName
    checkpoint_id = $ExpectedCheckpointId
    sha = $memberSha
    tree = $Tree
    client_sha256 = $clientHash
    server_sha256 = $serverHash
    harness_sha256 = $harnessHash
    collector_sha256 = $collectorHash
    recipe_sha256 = $RecipeSha256
    model_controller_sha256 = $modelControllerHash
    model_plan_sha256 = $modelPlanHash
}
$rawObservation = [ordered]@{
    schema_version = 6
    workload = "network-lifecycle"
    identity = $rawIdentity
    resource_warmup = $resourceWarmup
    baseline_resources = $baselineResources
    cycles = $cycles.ToArray()
    interface_resolver = [ordered]@{
        probes = [uint64]32
        resolutions = $resolutions
        cache_hits = $cacheHits
        interface_switch_probe_attempts = `
            [uint64]$interfaceSwitchRecovery.probe_attempts
        interface_switch_resolution_failures = `
            [uint64]$interfaceSwitchRecovery.resolution_failures
    }
}
$modelPending = "$modelOutputPath.pending"
Assert-Condition (-not (Test-Path -LiteralPath $modelPending)) `
    "network-model pending output baseline is not absent"
[IO.File]::WriteAllText(
    $modelPending,
    (($rawObservation | ConvertTo-Json -Depth 12) + "`n"),
    $script:Utf8NoBom
)
Assert-Condition ((Get-Item -LiteralPath $modelPending).Length -le 2097152) `
    "network-model observation exceeds 2 MiB"
Move-Item -LiteralPath $modelPending -Destination $modelOutputPath -ErrorAction Stop
$modelEvidenceReference = [ordered]@{
    schema_version = 1
    controller_sha256 = $modelControllerHash
    collector_sha256 = $collectorHash
    plan_sha256 = $modelPlanHash
    observation_file = [IO.Path]::GetFileName($modelOutputPath)
    observation_sha256 = Get-LowerSha256 $modelOutputPath
}
$checkedUnits = 1000
$measurements.reset_p50 = [ordered]@{
    unit = "p50_reset_network_nanoseconds"
    value = Get-NearestRank $resetLatencies.ToArray() 50
}
$measurements.reset_p95 = [ordered]@{
    unit = "p95_reset_network_nanoseconds"
    value = Get-NearestRank $resetLatencies.ToArray() 95
}
$measurements.reset_p99 = [ordered]@{
    unit = "p99_reset_network_nanoseconds"
    value = Get-NearestRank $resetLatencies.ToArray() 99
}
$measurements.full_rebuild_p50 = [ordered]@{
    unit = "p50_full_rebuild_nanoseconds"
    value = Get-NearestRank $rebuildLatencies.ToArray() 50
}
$measurements.full_rebuild_p95 = [ordered]@{
    unit = "p95_full_rebuild_nanoseconds"
    value = Get-NearestRank $rebuildLatencies.ToArray() 95
}
$measurements.full_rebuild_p99 = [ordered]@{
    unit = "p99_full_rebuild_nanoseconds"
    value = Get-NearestRank $rebuildLatencies.ToArray() 99
}
$measurements.interface_switch_recovery = [ordered]@{
    unit = "interface_switch_recovery_nanoseconds"
    value = [uint64]$resetLatencies[499]
}
$measurements.interface_resolver_cache_hit = [ordered]@{
    unit = "cache_hits_per_million_resolutions"
    value = [uint64][Math]::Floor(
        ([decimal]$cacheHits * [decimal]1000000) / [decimal]$resolutions
    )
}
$resetFinal = $cycles[999].resources_after
$checks.same_process_all_cycles = $true
$checks.resource_warmup_exact = $true
$checks.generation_advanced_once_per_cycle = $true
$checks.managed_identity_preserved_across_resets = $true
$checks.damage_only_full_rebuild = $true
$checks.reset_and_full_rebuild_metrics_are_exact = $true
$checks.resource_growth_zero_after_1000_resets = (
    $resetFinal.process_handles -le $baselineResources.process_handles -and
    $resetFinal.process_threads -le $baselineResources.process_threads -and
    $resetFinal.udp_associations_active -eq $baselineResources.udp_associations_active -and
    $resetFinal.managed_adapters_active -eq $baselineResources.managed_adapters_active
)
$checks.tcp_and_udp_recovered_after_interface_switch = $true
$checks.interface_resolver_cache_hit_observed = $true
$checks.network_model_evidence_bound = $true
