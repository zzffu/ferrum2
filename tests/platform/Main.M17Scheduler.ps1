function Invoke-M17SchedulerRingFull {
    Enable-M17UdpFirewallAdmission
    Add-M17LiveRow "scheduler-firewall-scope" ([ordered]@{
        policy_store = "ActiveStore"
        direction = "inbound"
        protocol = "udp"
        local_address = "198.18.0.2"
        remote_address = "any"
        local_only_mapping = $true
        program = $script:controllerProgram
        purpose = "prevent Windows stateful endpoint filtering from masking scheduler accounting while remaining controller-process scoped"
    })
    try {
    $target = "192.0.2.241"
    $port = Get-UniqueTcpPort
    $probe = Add-M17LoopbackTarget $target $port
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-scheduler-ring-full.toml"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ring_capacity = 131072
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "proxy" $script:m17MetricsPort
    Assert-M17Config $path "scheduler-ring-full"
    $script:activeProcess = Start-M17Candidate $path "scheduler-ring-full"
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    [void](Add-TunRoute $script:ownedInterfaceIndex "$target/32" 500)
    Add-M17LiveRow "scheduler-target-route-preference" ([ordered]@{
        route = Get-M17TargetRoutePreference $script:ownedInterfaceIndex $target
    })
    $state = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics
    $client = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
    try {
        $client.Client.ReceiveBufferSize = 4MB
        $warmupMetricsBefore = Get-Metrics $script:m17MetricsPort
        $warmupIngressBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_ingress"
        $warmupAcceptedBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_accepted"
        $warmupRejectedBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_rejected" $true
        $warmupEgressBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_egress"
        $warmupResetBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_network_reset" $true
        $warmupFullRebuildBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_network_full_rebuild" $true
        $warmupRingBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        Invoke-M17UdpEcho $client $target $port ([Text.Encoding]::ASCII.GetBytes("m17-warmup"))
        $warmupStableSamples = 0
        $warmupDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $ordinaryMetricsBefore = Get-Metrics $script:m17MetricsPort
            $warmupIngressAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_ingress"
            $warmupAcceptedAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_accepted"
            $warmupRejectedAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_rejected" $true
            $warmupEgressAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_egress"
            $warmupIngressDelta = $warmupIngressAfter - $warmupIngressBefore
            $warmupAcceptedDelta = $warmupAcceptedAfter - $warmupAcceptedBefore
            $warmupRejectedDelta = $warmupRejectedAfter - $warmupRejectedBefore
            $warmupEgressDelta = $warmupEgressAfter - $warmupEgressBefore
            Assert-True ($warmupIngressDelta -ge $warmupAcceptedDelta -and
                $warmupAcceptedDelta -le 1 -and $warmupEgressDelta -le 1) "M17 scheduler accepted/egress counter overshoot: phase=warmup expected=1 raw_ingress_delta=$warmupIngressDelta accepted_before=$warmupAcceptedBefore accepted_after=$warmupAcceptedAfter accepted_delta=$warmupAcceptedDelta rejected_delta=$warmupRejectedDelta egress_before=$warmupEgressBefore egress_after=$warmupEgressAfter egress_delta=$warmupEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses)"
            if ($warmupAcceptedDelta -eq 1 -and $warmupEgressDelta -eq 1 -and
                $probe.Requests -eq 1 -and $probe.Responses -eq 1) {
                $warmupStableSamples++
                if ($warmupStableSamples -ge 2) { break }
            } else {
                $warmupStableSamples = 0
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $warmupDeadline)
        Assert-True ($warmupStableSamples -ge 2) "M17 scheduler counters did not stabilize: phase=warmup expected=1 raw_ingress_delta=$warmupIngressDelta accepted_before=$warmupAcceptedBefore accepted_after=$warmupAcceptedAfter accepted_delta=$warmupAcceptedDelta rejected_delta=$warmupRejectedDelta egress_before=$warmupEgressBefore egress_after=$warmupEgressAfter egress_delta=$warmupEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses) generation=$(Get-M17MetricValue $ordinaryMetricsBefore 'ferrum2_tun_session_generation') active=$(Get-M17MetricValue $ordinaryMetricsBefore 'ferrum2_tun_session_active')"
        Assert-True ((Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_reset" $true) -eq $warmupResetBefore -and
            (Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_full_rebuild" $true) -eq $warmupFullRebuildBefore -and
            (Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_wintun_ring_full_dropped") -eq $warmupRingBefore) "M17 scheduler warmup reset/rebuilt the network runtime or filled the Wintun ring"
        Add-M17LiveRow "scheduler-warmup-counter-stability" ([ordered]@{
            stable_samples = $warmupStableSamples
            raw_ingress_delta = $warmupIngressDelta
            accepted_delta = $warmupAcceptedDelta
            rejected_delta = $warmupRejectedDelta
            non_accepted_ingress_delta = $warmupIngressDelta - $warmupAcceptedDelta
            egress_delta = $warmupEgressDelta
            target_requests = $probe.Requests
            target_responses = $probe.Responses
        })
        $ingressBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_ingress"
        $acceptedBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_accepted"
        $rejectedBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_rejected" $true
        $egressBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_egress"
        $networkResetBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_reset" $true
        $fullRebuildBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_full_rebuild" $true
        $ringBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        $burstSourceCount = 8
        $burstClients = [Collections.Generic.List[Net.Sockets.UdpClient]]::new()
        try {
            foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                $burstClients.Add((New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex))
            }
            foreach ($burst in @(8, 16, 64)) {
                $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($round in 0..(($burst / $burstSourceCount) - 1)) {
                    foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                        $index = $round * $burstSourceCount + $sourceIndex
                        $text = "m17-$burst-$index"
                        [void]$expected.Add($text)
                        $payload = [Text.Encoding]::ASCII.GetBytes($text)
                        [void]$burstClients[$sourceIndex].Send($payload, $payload.Length, $target, $port)
                    }
                    foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                        $task = $burstClients[$sourceIndex].ReceiveAsync()
                        Assert-True ($task.Wait(10000) -and -not $task.IsFaulted) "M17 scheduler capacity-aware sequence response timeout: $burst/$round/$sourceIndex"
                        [void]$actual.Add([Text.Encoding]::ASCII.GetString($task.Result.Buffer))
                    }
                }
                Assert-True ($actual.SetEquals($expected)) "M17 scheduler capacity-aware sequence lost or duplicated a packet: $burst"
            }
        } finally {
            foreach ($burstClient in $burstClients) { $burstClient.Dispose() }
        }

        Assert-True ($probe.Requests -eq 89 -and $probe.Responses -eq 89) "M17 scheduler warmup and ordinary target accounting was not exact"
        $ordinaryStableSamples = 0
        $ordinaryDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $ordinaryMetrics = Get-Metrics $script:m17MetricsPort
            $ordinaryIngressAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_ingress"
            $ordinaryAcceptedAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_accepted"
            $ordinaryRejectedAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_rejected" $true
            $ordinaryEgressAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_egress"
            $ordinaryIngressDelta = $ordinaryIngressAfter - $ingressBefore
            $ordinaryAcceptedDelta = $ordinaryAcceptedAfter - $acceptedBefore
            $ordinaryRejectedDelta = $ordinaryRejectedAfter - $rejectedBefore
            $ordinaryEgressDelta = $ordinaryEgressAfter - $egressBefore
            Assert-True ($ordinaryIngressDelta -ge $ordinaryAcceptedDelta -and
                $ordinaryAcceptedDelta -le 88 -and $ordinaryEgressDelta -le 88) "M17 scheduler accepted/egress counter overshoot: phase=burst expected=88 raw_ingress_delta=$ordinaryIngressDelta accepted_before=$acceptedBefore accepted_after=$ordinaryAcceptedAfter accepted_delta=$ordinaryAcceptedDelta rejected_delta=$ordinaryRejectedDelta egress_before=$egressBefore egress_after=$ordinaryEgressAfter egress_delta=$ordinaryEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses)"
            if ($ordinaryAcceptedDelta -eq 88 -and $ordinaryEgressDelta -eq 88) {
                $ordinaryStableSamples++
                if ($ordinaryStableSamples -ge 2) { break }
            } else {
                $ordinaryStableSamples = 0
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $ordinaryDeadline)
        Assert-True ($ordinaryStableSamples -ge 2) "M17 scheduler counters did not stabilize: phase=burst expected=88 raw_ingress_delta=$ordinaryIngressDelta accepted_before=$acceptedBefore accepted_after=$ordinaryAcceptedAfter accepted_delta=$ordinaryAcceptedDelta rejected_delta=$ordinaryRejectedDelta egress_before=$egressBefore egress_after=$ordinaryEgressAfter egress_delta=$ordinaryEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses) network_reset_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_network_reset' $true) - $networkResetBefore) full_rebuild_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_network_full_rebuild' $true) - $fullRebuildBefore) ring_full_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_wintun_ring_full_dropped') - $ringBefore) generation=$(Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_session_generation') active=$(Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_session_active')"
        Add-M17LiveRow "scheduler-burst-counter-stability" ([ordered]@{
            stable_samples = $ordinaryStableSamples
            raw_ingress_delta = $ordinaryIngressDelta
            accepted_delta = $ordinaryAcceptedDelta
            rejected_delta = $ordinaryRejectedDelta
            non_accepted_ingress_delta = $ordinaryIngressDelta - $ordinaryAcceptedDelta
            egress_delta = $ordinaryEgressDelta
            target_requests = $probe.Requests
            target_responses = $probe.Responses
        })
        Assert-True ((Get-M17MetricValue $ordinaryMetrics "ferrum2_network_reset" $true) -eq $networkResetBefore -and
            (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_full_rebuild" $true) -eq $fullRebuildBefore -and
            (Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_wintun_ring_full_dropped") -eq $ringBefore) "M17 ordinary bursts reset/rebuilt the network runtime or filled the Wintun ring"

        $pressurePackets = 256
        $pressurePayloadBytes = 1200
        $pressureTargetBefore = $probe.Requests
        Assert-True ($pressureTargetBefore -eq 89 -and $probe.Responses -eq 89) "M17 scheduler target accounting changed after counter stabilization"
        $pressureMetricsBefore = $ordinaryMetrics
        $pressureEgressBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_tun_packets_egress"
        $pressureRingBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        $pressureResetBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_network_reset" $true
        $pressureFullRebuildBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_network_full_rebuild" $true
        $pressureBatchPackets = 1
        foreach ($batch in 0..(($pressurePackets / $pressureBatchPackets) - 1)) {
            $batchStart = $batch * $pressureBatchPackets
            foreach ($ordinal in $batchStart..($batchStart + $pressureBatchPackets - 1)) {
                $payload = [byte[]]::new($pressurePayloadBytes)
                [BitConverter]::GetBytes([uint32]$ordinal).CopyTo($payload, 0)
                [void]$client.Send($payload, $payload.Length, $target, $port)
            }
            $expectedTargetCount = $pressureTargetBefore + $batchStart + $pressureBatchPackets
            Assert-True ($probe.WaitRequests($expectedTargetCount, 5000)) "M17 pressure target request batch was incomplete"
            Assert-True ($probe.Requests -eq $expectedTargetCount) "M17 pressure target request batch was not exact"
            $responseDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while ($probe.Responses -lt $expectedTargetCount -and [DateTime]::UtcNow -lt $responseDeadline) {
                Start-Sleep -Milliseconds 5
            }
            Assert-True ($probe.Responses -eq $expectedTargetCount) "M17 pressure target response batch was not exact"
        }

        $pressureDeadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            $pressureMetrics = Get-Metrics $script:m17MetricsPort
            $pressureEgressDelta = (Get-M17MetricValue $pressureMetrics "ferrum2_tun_packets_egress") - $pressureEgressBefore
            $pressureRingDelta = (Get-M17MetricValue $pressureMetrics "ferrum2_tun_wintun_ring_full_dropped") - $pressureRingBefore
            if ($pressureEgressDelta + $pressureRingDelta -ge $pressurePackets) { break }
            Start-Sleep -Milliseconds 25
        } while ([DateTime]::UtcNow -lt $pressureDeadline)
        Assert-True ($pressureEgressDelta -ge 0 -and $pressureRingDelta -ge 0 -and
            $pressureEgressDelta + $pressureRingDelta -eq $pressurePackets) "M17 pressure output accounting is not closed"
        Assert-True ((Get-M17MetricValue $pressureMetrics "ferrum2_network_reset" $true) -eq $pressureResetBefore -and
            (Get-M17MetricValue $pressureMetrics "ferrum2_network_full_rebuild" $true) -eq $pressureFullRebuildBefore) "M17 ring pressure reset or rebuilt the network runtime"

        $pressureActual = [Collections.Generic.HashSet[uint32]]::new()
        if ($pressureEgressDelta -gt 0) {
            foreach ($ignored in 1..([int]$pressureEgressDelta)) {
                $task = $client.ReceiveAsync()
                Assert-True ($task.Wait(15000) -and -not $task.IsFaulted) "M17 accounted pressure response did not reach the TUN socket"
                $response = $task.Result
                Assert-True ($response.Buffer.Length -eq $pressurePayloadBytes -and
                    $response.RemoteEndPoint.Address.ToString() -ceq $target -and
                    $response.RemoteEndPoint.Port -eq $port) "M17 pressure response shape or source changed"
                $ordinal = [BitConverter]::ToUInt32($response.Buffer, 0)
                Assert-True ($ordinal -lt $pressurePackets -and $pressureActual.Add($ordinal)) "M17 pressure response was invalid or duplicated"
            }
        }
        Assert-True ($pressureActual.Count -eq [int]$pressureEgressDelta) "M17 pressure delivery count changed"
        $pressureReceiveBufferBytes = $client.Client.ReceiveBufferSize
    } finally { $client.Dispose() }
    Assert-True ($probe.WaitRequests(345, 10000)) "M17 scheduler target did not observe every burst and pressure packet"
    Assert-True ($probe.Requests -eq 345 -and $probe.Responses -eq 345) "M17 scheduler target accounting was not exact"
    Start-Sleep -Milliseconds 100
    $metrics = Get-Metrics $script:m17MetricsPort
    $finalPressureEgressDelta = (Get-M17MetricValue $metrics "ferrum2_tun_packets_egress") - $pressureEgressBefore
    $finalPressureRingDelta = (Get-M17MetricValue $metrics "ferrum2_tun_wintun_ring_full_dropped") - $pressureRingBefore
    Assert-True ($finalPressureEgressDelta -eq $pressureEgressDelta -and
        $finalPressureRingDelta -eq $pressureRingDelta -and
        $finalPressureEgressDelta + $finalPressureRingDelta -eq $pressurePackets) "M17 pressure output accounting did not remain stable after drain"
    Assert-True ((Get-M17MetricValue $metrics "ferrum2_network_reset" $true) -eq $pressureResetBefore -and
        (Get-M17MetricValue $metrics "ferrum2_network_full_rebuild" $true) -eq $pressureFullRebuildBefore) "M17 pressure caused a delayed network reset or full rebuild"
    Add-M17LiveRow "scheduler-egress-pressure" ([ordered]@{
        packets = $pressurePackets
        batch_packets = $pressureBatchPackets
        payload_bytes = $pressurePayloadBytes
        delivered = [int]$finalPressureEgressDelta
        ring_full_dropped = [int]$finalPressureRingDelta
        receive_buffer_bytes = $pressureReceiveBufferBytes
        network_reset_delta = 0
        full_rebuild_delta = 0
    })
    Add-M17Witness "live_egress_pressure_has_closed_accounting" "live-product" "256 1200-byte responses were exactly partitioned into delivered and explicit ring-full outcomes without a network reset or full rebuild"
    Add-M17LiveRow "scheduler-bursts" ([ordered]@{
        sequence_packets = @(8, 16, 64)
        batch_packets = $burstSourceCount
        sources = $burstSourceCount
        packets = 88
        ingress_delta = $ordinaryAcceptedDelta
        raw_ingress_delta = $ordinaryIngressDelta
        rejected_delta = $ordinaryRejectedDelta
        non_accepted_ingress_delta = $ordinaryIngressDelta - $ordinaryAcceptedDelta
        egress_delta = $ordinaryEgressAfter - $egressBefore
        target_requests = $pressureTargetBefore
        network_reset_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_reset" $true) - $networkResetBefore
        full_rebuild_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_full_rebuild" $true) - $fullRebuildBefore
        live_ring_full_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_wintun_ring_full_dropped") - $ringBefore
    })
    Add-M17Witness "rx_bursts_8_16_64_have_no_structural_drop" "live-product" `
        "8, 16, and 64 packet capacity-aware sequences round-tripped exactly with stable ingress and egress accounting"
    $script:m17CounterAfter = Get-M17CounterSnapshot $metrics
    Stop-M17Candidate $script:activeProcess "scheduler-ring-full"
    } finally {
        Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
        Assert-True (-not (Get-NetFirewallRule -Name $script:m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 scheduler firewall scope was not removed"
        Add-M17LiveRow "scheduler-firewall-cleanup" ([ordered]@{
            rule_name = $script:m17UdpFirewallRuleName
            active_store_rules = 0
        })
    }
}

function Invoke-M17Qualification([string]$SourceDll) {
    Assert-True (-not (Test-Path -LiteralPath $script:siblingDll)) "M17 sibling DLL baseline not absent"
    Write-OwnedSiblingDllIntent
    Copy-Item -LiteralPath $SourceDll -Destination $script:siblingDll
    $script:createdSiblingDll = $true
    Assert-True ((Get-FileHash -LiteralPath $script:siblingDll -Algorithm SHA256).Hash -eq $script:expectedDllHash) "M17 sibling DLL identity changed"
    Start-M17Server
    switch ($script:Profile) {
        "network-reset" { Invoke-M17NetworkReset }
        "restart-stress" { Invoke-M17RestartStress }
        "fragments" { Invoke-M17Fragments }
        "dual-stack-dns" { Invoke-M17DualStackDns }
        "udp-policy" { Invoke-M17UdpPolicy }
        "scheduler-ring-full" { Invoke-M17SchedulerRingFull }
        default { throw "M17 live dispatch received an invalid profile" }
    }
    $actualWitnesses = @($script:m17WitnessRows.Keys | Sort-Object)
    $expectedWitnesses = @($script:m17Contract.witnesses | Sort-Object)
    Assert-True (($actualWitnesses -join "`n") -ceq ($expectedWitnesses -join "`n")) "M17 witness set is incomplete"
}

function Complete-M17Artifact([bool]$Succeeded, [object]$PrimaryFailure, [object]$CleanupFailure) {
    if (-not $script:m17ArtifactInitialized) { return }
    Assert-M17ExternalIdentityInputsUnchanged
    $script:m17FinishedUtc = [DateTime]::UtcNow.ToString("o")
    $failure = if ($PrimaryFailure) { $PrimaryFailure } else { $CleanupFailure }
    $failureRecord = if ($failure) {
        $message = [string]$failure.Exception.Message
        if ($message.Length -gt 2048) { $message = $message.Substring(0, 2048) }
        [ordered]@{ type = $failure.Exception.GetType().FullName; message = $message }
    } else { $null }
    $cleanupProcesses = @(Get-ExactRunProcesses -WorkPath $script:work).Count
    $cleanupAdapters = @(Get-NetAdapter -Name $script:adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
    $cleanupSibling = if (Test-Path -LiteralPath $script:siblingDll) { 1 } else { 0 }
    $cleanupWork = if (Test-Path -LiteralPath $script:work) { 1 } else { 0 }
    $cleanupPassed = -not $CleanupFailure -and $cleanupProcesses -eq 0 -and $cleanupAdapters -eq 0 -and
        $cleanupSibling -eq 0 -and $cleanupWork -eq 0
    $cleanup = [ordered]@{
        status = if ($cleanupPassed) { "pass" } else { "fail" }
        processes = $cleanupProcesses
        adapters = $cleanupAdapters
        sibling_dll = $cleanupSibling
        work_directory = $cleanupWork
        cleanup_failure_type = if ($CleanupFailure) { $CleanupFailure.Exception.GetType().FullName } else { $null }
    }
    if ($Succeeded) {
        Assert-True $cleanupPassed "M17 cleanup evidence is not absent"
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.m17-result.v4"
        status = if ($Succeeded) { "pass" } else { "fail" }
        profile = $script:Profile
        run_token = $script:runIdentity
        cycle_limit = if ($script:Profile -in @("network-reset", "restart-stress")) { 1000 } else { $null }
        release_milestones = @($script:releaseMilestones)
        approved_vm_name = $script:expectedHyperVVmName
        approved_vm_id = $script:expectedHyperVVmId
        approved_checkpoint_name = $script:expectedHyperVCheckpointName
        approved_checkpoint_id = $script:expectedHyperVCheckpointId
        guest_build = [string]$script:capabilityIdentity.Ledger.guest_build
        identity_sha256 = $script:capabilityIdentityHash
        candidate_sha = [string]$script:capabilityIdentity.Ledger.candidate_sha
        client_sha256 = [string]$script:capabilityIdentity.Ledger.client_sha256
        server_sha256 = [string]$script:capabilityIdentity.Ledger.server_sha256
        controller_sha256 = (Get-FileHash -LiteralPath $script:controllerEntryPointPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        controller_bundle_sha256 = [string]$script:controllerBundleManifest.controller_bundle_sha256
        wintun_zip_sha256 = $script:expectedZipHash.ToLowerInvariant()
        wintun_dll_sha256 = $script:expectedDllHash.ToLowerInvariant()
        topology = $script:capabilityIdentity.Ledger.topology
        guest_network_path = $script:m17GuestNetworkPathDocument.Value
        started_utc = $script:m17StartedUtc
        finished_utc = $script:m17FinishedUtc
        fixtures = $script:m17FixtureRows
        processes = @($script:m17ProcessRows)
        live_checks = @($script:m17LiveRows)
        witnesses = @($script:m17WitnessRows.Values)
        counters_before = $script:m17CounterBefore
        counters_after = $script:m17CounterAfter
        cleanup = $cleanup
        failure = $failureRecord
    }
    $artifact = Join-Path $script:m17ArtifactRoot "m17-result.json"
    [IO.File]::WriteAllText($artifact, (($document | ConvertTo-Json -Depth 12) + "`n"), [Text.UTF8Encoding]::new($false))
    Assert-True ((Get-Item -LiteralPath $artifact).Length -le 1048576) "M17 result artifact exceeded the 1 MiB cap"
}
