Start-Sleep -Seconds 5
$underlay = Get-FixedUnderlayRoute
$underlayRouteIdentity = New-FixedUnderlayRouteIdentity $underlay
$underlayJournal = Join-Path $script:WorkRoot "underlay-route-journal.json"
[IO.File]::WriteAllText(
    $underlayJournal,
    (($underlayRouteIdentity | ConvertTo-Json -Compress) + "`n"),
    $script:Utf8NoBom
)
[uint16]$mutatedRouteMetric = if (
    [uint16]$underlayRouteIdentity.route_metric -lt [uint16]::MaxValue
) {
    [uint16]([uint16]$underlayRouteIdentity.route_metric + 1)
} else {
    [uint16]([uint16]$underlayRouteIdentity.route_metric - 1)
}
$rawGenerations = [Collections.Generic.List[object]]::new()
[uint64]$totalElapsedNanoseconds = 0
[uint64]$totalAssociationCreationNanoseconds = 0
[uint64]$totalAssociationCreations = 0
[uint64]$totalRouterInvocations = 0
[uint64]$totalDatagrams = 0
foreach ($generationOrdinal in 1..2) {
    $before = Get-Metrics $MetricsPort 5
    $lifecycleBefore = Get-NetworkLifecycleMetrics $before
    [uint64]$createdBefore = Get-Metric $before `
        "ferrum2_tun_udp_association_created" $true
    [uint64]$routeBefore = Get-Metric $before `
        "ferrum2_tun_udp_association_route" $true
    [uint64]$successfulRouteBefore = Get-LabeledMetric $before `
        "ferrum2_tun_udp_association_route" @{ result = "success" } $true
    $serverBefore = Get-Metrics $ServerMetricsPort 5
    [uint64]$proxyDatagramsBefore = Get-LabeledMetric $serverBefore `
        "ferrum2_udp_datagrams" @{
            role = "server"; direction = "client_to_target"; outcome = "accepted"
        } $true
    [uint64]$proxyRepliesBefore = Get-LabeledMetric $serverBefore `
        "ferrum2_udp_datagrams" @{
            role = "server"; direction = "target_to_client"; outcome = "completed"
        } $true
    $observation = Invoke-Workload $Scenario 120
    Assert-ExactProperties $observation @(
        "measurements", "checked_units", "associations", "checks"
    ) "route-once guest workload"
    Assert-ExactProperties $observation.measurements @(
        "elapsed_nanoseconds", "association_creation_elapsed_nanoseconds",
        "packet_rate"
    ) "route-once guest measurements"
    Assert-ExactProperties $observation.checks @(
        "every_reply_accounted", "payload_exact", "multi_target_sources", "no_gso"
    ) "route-once guest checks"
    Assert-Condition (
        $observation.checks.every_reply_accounted -eq $true -and
        $observation.checks.payload_exact -eq $true -and
        $observation.checks.multi_target_sources -eq $true -and
        $observation.checks.no_gso -eq $true -and
        [uint64]$observation.checked_units -eq 8192 -and
        [uint64]$observation.measurements.elapsed_nanoseconds -gt 0 -and
        [uint64]$observation.measurements.association_creation_elapsed_nanoseconds `
            -gt 0 -and
        [uint64]$observation.measurements.association_creation_elapsed_nanoseconds `
            -le [uint64]$observation.measurements.elapsed_nanoseconds -and
        @($observation.associations).Count -eq 64
    ) "route-once guest workload contract changed"
    $after = Get-Metrics $MetricsPort 5
    $lifecycleAfter = Get-NetworkLifecycleMetrics $after
    Assert-NetworkLifecycleMetricsEqual $lifecycleBefore $lifecycleAfter `
        "route-once workload triggered an unplanned lifecycle transition"
    [uint64]$createdDelta = (Get-Metric $after `
        "ferrum2_tun_udp_association_created") - $createdBefore
    [uint64]$routeDelta = (Get-Metric $after `
        "ferrum2_tun_udp_association_route") - $routeBefore
    [uint64]$successfulRouteDelta = (Get-LabeledMetric $after `
        "ferrum2_tun_udp_association_route" @{ result = "success" }) - `
        $successfulRouteBefore
    $serverAfter = Get-Metrics $ServerMetricsPort 5
    [uint64]$proxyDatagramsDelta = (Get-LabeledMetric $serverAfter `
        "ferrum2_udp_datagrams" @{
            role = "server"; direction = "client_to_target"; outcome = "accepted"
        }) - $proxyDatagramsBefore
    [uint64]$proxyRepliesDelta = (Get-LabeledMetric $serverAfter `
        "ferrum2_udp_datagrams" @{
            role = "server"; direction = "target_to_client"; outcome = "completed"
        }) - $proxyRepliesBefore
    [uint64]$expectedPathDatagrams = 32 * 4 * 32
    Assert-Condition (
        $createdDelta -eq 64 -and
        $routeDelta -eq 64 -and
        $successfulRouteDelta -eq 64 -and
        $proxyDatagramsDelta -eq $expectedPathDatagrams -and
        $proxyRepliesDelta -eq $expectedPathDatagrams -and
        (Get-Metric $after "ferrum2_tun_udp_associations_active") -eq 64
    ) "route-once product association/router/proxy counters are not exact"
    $rawAssociations = [Collections.Generic.List[object]]::new()
    $seenSources = [Collections.Generic.HashSet[uint64]]::new()
    foreach ($association in @($observation.associations)) {
        Assert-ExactProperties $association @(
            "source_slot", "target_slots", "first_target_slot",
            "datagrams_sent", "replies_received"
        ) "route-once guest association"
        [uint64]$sourceSlot = $association.source_slot
        [uint64]$expectedFirstTargetSlot = if (($sourceSlot % 2) -eq 0) {
            0
        } else {
            1
        }
        Assert-Condition (
            $sourceSlot -lt 64 -and $seenSources.Add($sourceSlot) -and
            (@($association.target_slots) -join "|") -ceq "0|1|2|3" -and
            [uint64]$association.first_target_slot -eq $expectedFirstTargetSlot -and
            [uint64]$association.datagrams_sent -eq 128 -and
            [uint64]$association.replies_received -eq 128
        ) "route-once guest association coverage is invalid"
        $rawAssociations.Add([ordered]@{
            source_slot = $sourceSlot
            target_slots = @(0, 1, 2, 3)
            first_target_slot = [uint64]$association.first_target_slot
            datagrams_sent = [uint64]$association.datagrams_sent
            replies_received = [uint64]$association.replies_received
        })
    }
    Assert-Condition ($seenSources.Count -eq 64) `
        "route-once guest workload did not cover every source slot"
    $rawGenerations.Add([ordered]@{
        ordinal = [uint64]$generationOrdinal
        network_generation = [uint64]$lifecycleBefore.network_generation
        session_generation = [uint64]$lifecycleBefore.session_generation
        direct_datagrams_observed = `
            [uint64]$observation.checked_units - $proxyDatagramsDelta
        direct_replies_observed = `
            [uint64]$observation.checked_units - $proxyRepliesDelta
        proxy_datagrams_observed = $proxyDatagramsDelta
        proxy_replies_observed = $proxyRepliesDelta
        associations = $rawAssociations.ToArray()
    })
    $totalElapsedNanoseconds += [uint64]$observation.measurements.elapsed_nanoseconds
    $totalAssociationCreationNanoseconds += `
        [uint64]$observation.measurements.association_creation_elapsed_nanoseconds
    $totalAssociationCreations += $createdDelta
    $totalRouterInvocations += $successfulRouteDelta
    $totalDatagrams += [uint64]$observation.checked_units

    $currentRoute = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
    [uint16]$nextMetric = if ($generationOrdinal -eq 1) {
        $mutatedRouteMetric
    } else {
        [uint16]$underlayRouteIdentity.route_metric
    }
    Set-NetRoute -InputObject $currentRoute.Route -RouteMetric $nextMetric `
        -ErrorAction Stop
    $routeReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
    Assert-Condition (
        [uint16]$routeReadback.Route.RouteMetric -eq $nextMetric
    ) "route-once fixed underlay metric mutation was not read back exactly"
    $transition = Wait-LifecycleTransition "reset_network" $lifecycleAfter 30
    Assert-Condition (
        (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
    ) "route-once ResetNetwork retained an old association"
}
$underlayReadback = Get-ExactFixedUnderlayRoute $underlayRouteIdentity
Assert-Condition (
    [uint16]$underlayReadback.Route.RouteMetric -eq
        [uint16]$underlayRouteIdentity.route_metric
) "route-once fixed underlay route metric baseline was not restored"
Remove-Item -LiteralPath $underlayJournal -Force
[void](Wait-CleanDrain $true)

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
    workload = "udp-route-once"
    identity = $rawIdentity
    elapsed_nanoseconds = $totalElapsedNanoseconds
    association_creation_elapsed_nanoseconds = `
        $totalAssociationCreationNanoseconds
    association_creations_observed = $totalAssociationCreations
    router_invocations_observed = $totalRouterInvocations
    generations = $rawGenerations.ToArray()
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
$checkedUnits = $totalDatagrams
$measurements.multi_target_packet_rate = [ordered]@{
    unit = "multi_target_datagrams_per_second"
    value = [uint64][Math]::Floor(
        ([decimal]$totalDatagrams * [decimal]1000000000) /
        [decimal]$totalElapsedNanoseconds
    )
}
$measurements.association_creation_rate = [ordered]@{
    unit = "associations_per_second"
    value = [uint64][Math]::Floor(
        ([decimal]$totalAssociationCreations * [decimal]1000000000) /
        [decimal]$totalAssociationCreationNanoseconds
    )
}
$measurements.router_invocations_avoided = [ordered]@{
    unit = "avoided_router_invocations"
    value = [uint64](2 * 64 * 4 - $totalRouterInvocations)
}
$checks.every_reply_accounted = $true
$checks.payload_exact = $true
$checks.direct_and_proxy_sources = $true
$checks.association_creation_counter_exact = $true
$checks.router_invocation_counter_exact = $true
$checks.post_reset_reroute_verified = $true
$checks.network_model_evidence_bound = $true
$checks.clean_drain = $true
