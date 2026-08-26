function Write-M17ClientConfig(
    [string]$Path,
    [string]$TunFields,
    [ValidateSet("direct", "proxy")][string]$Outbound,
    [int]$MetricsPort,
    [string]$Additional = "",
    [bool]$BindDirectToSupport = $false
) {
    $tunOutbound = if ([regex]::IsMatch($Additional, '(?m)^\[route\]\r?$')) {
        ""
    } else {
        "outbound = `"$Outbound`""
    }
    $outboundText = if ($Outbound -eq "direct") {
        $supportBinding = if ($BindDirectToSupport) {
@"
bind_interface = "$($script:capabilityIdentity.Ledger.topology.guest_interface_alias)"
inet4_bind_address = "$($script:capabilityIdentity.Ledger.topology.guest_ipv4)"
"@
        } else { "" }
@"
[[outbounds]]
tag = "direct"
type = "direct"
$supportBinding
"@
    } else {
@"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "127.0.0.1:$script:m17ServerPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@
    }
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$script:adapterName"
$TunFields
$tunOutbound
$outboundText
[udp]
enabled = true
max_sessions = 64
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
$Additional
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$MetricsPort"
"@ | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-M17Config([string]$Path, [string]$Label) {
    $result = Invoke-M17BoundedCommand "config-$Label" $script:binary @("--config", $Path, "--check-config") (Split-Path -Parent $script:binary) 30
    Assert-True ($result.ExitCode -eq 0 -and $result.Stdout.TrimEnd([char[]]"`r`n") -ceq "configuration valid") "M17 live config validation failed: $Label"
    Assert-True ([string]::IsNullOrEmpty($result.Stderr)) "M17 live config emitted stderr: $Label"
}

function Stop-M17Candidate([System.Diagnostics.Process]$Process, [string]$Label) {
    Stop-Candidate $Process
    $script:activeProcess = $null
    Wait-AdapterAbsent $script:adapterName
    Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
    Add-M17LiveRow "client-$Label-graceful-stop" ([ordered]@{ exit_code = 0; adapter = "absent" })
}

function Start-M17NetworkResetRouteMutation {
    Assert-True ($script:Mode -ceq "network-reset") "M17 network-reset route mutation is mode restricted"
    $supportPath = $script:m17GuestNetworkPathDocument.Value
    $supportAdapter = @(Get-NetAdapter -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -IncludeHidden -ErrorAction Stop)
    Assert-True ($supportAdapter.Count -eq 1 -and
        [string]$supportAdapter[0].Name -ceq [string]$supportPath.guest_interface_alias -and
        ([Guid][string]$supportAdapter[0].InterfaceGuid).ToString("D") -ceq
            [string]$supportPath.guest_interface_guid -and
        [string]$supportAdapter[0].Status -ceq "Up") "M17 support route mutation adapter identity changed"
    $prefix = $script:m17NetworkResetProbePrefix
    Assert-True (@(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 network-reset notification route baseline is not absent"
    $intentPath = Get-M17NetworkResetRouteIntentPath
    Write-M17DurableMutationIntent $intentPath ([ordered]@{
        schema = "ferrum2.windows-tun.m17-network-reset-route-intent.v2"
        run_token = $script:runIdentity
        source_mode = "network-reset"
        work_path = [IO.Path]::GetFullPath($script:work)
        interface_index = [uint32]$supportPath.guest_interface_index
        destination_prefix = $prefix
        next_hop = "0.0.0.0"
        route_metrics = @([uint32]4094, [uint32]4095)
    })
    [void](New-NetRoute -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -DestinationPrefix $prefix -NextHop "0.0.0.0" -RouteMetric 4094 `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $readback = @(Get-NetRoute -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
            $_.NextHop -ceq "0.0.0.0" -and [uint32]$_.RouteMetric -eq 4094
        })
    Assert-True ($readback.Count -eq 1) "M17 network-reset notification route create readback failed"
    return [pscustomobject]@{
        IntentPath = $intentPath
        InterfaceIndex = [uint32]$supportPath.guest_interface_index
        DestinationPrefix = $prefix
        NextHop = "0.0.0.0"
        RouteMetric = [uint32]4094
    }
}

function Set-M17NetworkResetRouteMetric([object]$Mutation, [uint32]$Metric) {
    Assert-True ($script:Mode -ceq "network-reset" -and $Metric -in @(4094, 4095)) "M17 network-reset route metric is outside the closed mutation set"
    $intent = Read-M17NetworkResetRouteMutationIntent ([string]$Mutation.IntentPath)
    Assert-True ([uint32]$intent.interface_index -eq [uint32]$Mutation.InterfaceIndex -and
        [string]$intent.destination_prefix -ceq [string]$Mutation.DestinationPrefix -and
        [string]$intent.next_hop -ceq [string]$Mutation.NextHop -and
        @($intent.route_metrics) -contains [long]$Metric) "M17 network-reset route no longer matches its durable intent"
    $routes = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop })
    Assert-True ($routes.Count -eq 1 -and [uint32]$routes[0].RouteMetric -in @($intent.route_metrics) -and
        [uint32]$routes[0].RouteMetric -ne $Metric) "M17 network-reset route mutation ownership changed"
    Set-NetRoute -InputObject $routes[0] -RouteMetric $Metric -ErrorAction Stop | Out-Null
    $readback = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop -and [uint32]$_.RouteMetric -eq $Metric })
    Assert-True ($readback.Count -eq 1) "M17 network-reset route metric readback failed"
    $Mutation.RouteMetric = $Metric
}

function Get-M17ExactManagedRoute([int]$InterfaceIndex, [string]$Prefix) {
    $routes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    Assert-True ($routes.Count -eq 1) "M17 managed restart route readback is not exact: $Prefix"
    return $routes[0]
}

function Remove-M17ManagedRouteForRestart([int]$InterfaceIndex, [string]$Prefix) {
    $route = Get-M17ExactManagedRoute $InterfaceIndex $Prefix
    Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 managed restart route mutation failed: $Prefix"
}

function Invoke-M17DnsQuery([string]$Source, [string]$Destination, [bool]$Tcp, [uint16]$Id) {
    $query = New-DnsQuery $Id
    $family = if ($Destination.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    if ($Tcp) {
        $client = [Net.Sockets.TcpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            $connected = $client.ConnectAsync($Destination, 53)
            Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "M17 synthetic DNS TCP connect failed"
            $stream = $client.GetStream()
            $frame = [byte[]]::new($query.Length + 2)
            $frame[0] = [byte]($query.Length -shr 8)
            $frame[1] = [byte]($query.Length -band 0xff)
            [Array]::Copy($query, 0, $frame, 2, $query.Length)
            $stream.Write($frame, 0, $frame.Length)
            $lengthBytes = Read-ExactBytes $stream 2
            $length = ([int]$lengthBytes[0] -shl 8) -bor [int]$lengthBytes[1]
            $response = Read-ExactBytes $stream $length
        } finally { $client.Dispose() }
    } else {
        $client = [Net.Sockets.UdpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            [void]$client.Send($query, $query.Length, $Destination, 53)
            $task = $client.ReceiveAsync()
            Assert-True ($task.Wait(5000) -and -not $task.IsFaulted) "M17 synthetic DNS UDP response timeout"
            $response = $task.Result.Buffer
        } finally { $client.Dispose() }
    }
    Assert-True ($response.Length -ge 12 -and $response[0] -eq $query[0] -and $response[1] -eq $query[1] -and
        ($response[2] -band 0x80) -ne 0) "M17 synthetic DNS response is invalid"
}

function Invoke-M17CandidateTests {
    Assert-True $script:candidateTestDirectoryExplicit "M17 candidate tests require host-built artifacts"
    $testHashes = [ordered]@{}
    foreach ($name in @("client", "tun", "wintun")) {
        $file = switch ($name) {
            "client" { "ferrum2-client-tests.exe" }
            "tun" { "ferrum2-tun-tests.exe" }
            "wintun" { "ferrum2-platform-windows-tests.exe" }
        }
        $testHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $script:resolvedCandidateTestDirectory $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Add-M17LiveRow "candidate-test-source" ([ordered]@{
        git_head = [string]$script:capabilityIdentity.Ledger.candidate_sha
        provenance = "host-built-rust-1.97.1-prebuilt-tests"
        test_binaries = $testHashes
    })

    $specs = switch ($script:Mode) {
        "network-reset" { @(
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::underlay::dual_stack_target_binding_selects_actual_target_and_rejects_tun"; Witnesses = @("fixed_and_direct_dual_stack_underlay_binding") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::underlay::target_binding_excludes_tun_and_orders_prefix_then_effective_metric"; Witnesses = @("multihoming_prefix_and_metric_selection") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::notification::network_change_notifications_cover_each_callback_and_runtime_owned_events"; Witnesses = @("route_interface_and_address_notifications") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::managed_routes::managed_route_cleanup_preserves_replacements_and_audits_every_delete"; Witnesses = @("foreign_route_state_survives_cleanup") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::managed_routes::managed_address_readback_and_cleanup_are_exact_and_foreign_safe"; Witnesses = @("foreign_address_state_survives_cleanup") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::session::dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit"; Witnesses = @("dad_failure_rolls_back_in_reverse") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::strict_route::managed_state_health_reports_owned_route_dns_and_strict_route_damage"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::strict_route::strict_route_health_reads_every_exact_filter_id_and_rejects_damage"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::underlay::network_change_revalidates_underlay_and_owned_routes_before_shutdown"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::catalog::windows_catalog_is_family_aware_and_marks_the_exact_managed_tun"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::catalog::resolved_socket_binding_applies_interface_then_family_source"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::lifecycle::only_managed_damage_escalates_a_network_change_to_full_rebuild"; Witnesses = @("owned_state_damage_is_the_only_full_rebuild_trigger") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::lifecycle::reset_retries_transient_readback_errors_without_tearing_down_managed_state"; Witnesses = @("reset_retries_without_managed_teardown") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::lifecycle::network_lifecycle_bridge_reports_retry_before_completion"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::stack_udp::session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state"; Witnesses = @() },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::client_network_hook_retries_failure_and_accepts_each_generation_once"; Witnesses = @("network_reset_hooks_accept_each_generation_once") }
        ) }
        "restart-stress" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::stack_udp::session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state"; Witnesses = @("admission_quiesces_during_rebuild", "stale_flows_and_fragments_are_cleared") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c17_stale_generation_handles_cannot_commit_close_or_inject"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "supervisor::tests::notification_burst_keeps_only_latest_generation_and_extends_debounce"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::lifecycle::owner_cancel_eof_panic_and_cleanup_conflict_are_reaped_before_join"; Witnesses = @() }
        ) }
        "fragments" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::reassembles_ipv4_and_ipv6_strictly_out_of_order_then_reparses"; Witnesses = @("ipv4_udp_out_of_order") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::reassembles_three_fragment_tcp_and_preserves_initial_syn_semantics"; Witnesses = @("ipv4_tcp_out_of_order") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::ipv6_extensions_before_and_after_fragment_reassemble_canonically"; Witnesses = @("ipv6_extension_and_fragment") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::strips_atomic_ipv6_fragment_before_reparse"; Witnesses = @("ipv6_atomic_fragment") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::overlap_or_duplicate_drops_the_entire_entry"; Witnesses = @("overlap_drops_entry") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::timeout_and_generation_change_prevent_cross_epoch_completion"; Witnesses = @("timeout_drops_entry", "network_reset_rejects_stale_generation") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::fragmented_dns_reaches_post_reassembly_udp_dispatch_metadata"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::stack_udp::fragmented_udp_reaches_admission_only_after_out_of_order_reassembly"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::disabled_family_fragments_are_rejected_before_allocating_reassembly_state"; Witnesses = @("disabled_family_rejects_fragment") }
        ) }
        "dual-stack-dns" { @(
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::synthetic_dns_matches_each_configured_family_exactly"; Witnesses = @("exact_port_53_match", "ordinary_port_53_not_intercepted") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::dns::managed_dns_snapshots_reads_back_and_conditionally_restores"; Witnesses = @() }
        ) }
        "udp-policy" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::tcp_flow::configured_ipv4_directed_broadcast_never_reaches_tcp_or_udp_admission"; Witnesses = @("directed_broadcast_never_allocates_association") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c19_eim_adf_eif_and_actual_response_source_are_enforced"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::adf_peer_reservations_are_bounded_and_authorize_only_on_commit"; Witnesses = @("rejected_target_never_authorizes_peer") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c8_lifecycle_control_is_reliable_when_data_queues_are_congested"; Witnesses = @("udp_queue_pressure_is_bounded_and_control_remains_live") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c10_hash_index_free_list_counts_and_generation_deadlines_are_exact"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c17_stale_generation_handles_cannot_commit_close_or_inject"; Witnesses = @("reset_clears_udp_stale_generation_state") },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::synthetic_dns_precedes_one_frozen_ordinary_udp_route"; Witnesses = @("first_ordinary_datagram_freezes_route_and_outbound") },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::tun_udp_authorizes_only_successful_send_or_dns_answer_and_adf_ignores_port"; Witnesses = @() },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::tun_udp_route_snapshot_is_bounded_and_immutable_after_selection"; Witnesses = @("one_eim_association_reuses_first_outbound_for_all_targets") }
        ) }
        "scheduler-ring-full" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::device_packet::capacity_aware_rotation_drains_eight_sixteen_and_sixty_four_packets"; Witnesses = @("rx_bursts_8_16_64_have_no_structural_drop") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "scheduler::tests::rotation_is_stable_across_arbitrary_work_budget_boundaries"; Witnesses = @("work_stages_rotate_fairly") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c2_response_backpressure_preserves_current_event_and_does_not_consume_next"; Witnesses = @("udp_response_backpressure_is_lossless") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::device_packet::ring_full_drops_exactly_one_complete_output_and_fatal_retains_it"; Witnesses = @("ring_full_drops_one_complete_packet", "ring_full_is_not_retried", "ring_full_does_not_reset_or_rebuild_network") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::lifecycle::wintun_error_kinds_have_exact_owner_dispositions"; Witnesses = @("wintun_error_kinds_have_exact_owner_dispositions") },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "tests::operation_error_kinds_are_closed_and_redacted"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::session::receive_null_distinguishes_empty_recoverable_eof_and_corruption"; Witnesses = @() },
            @{ Package = "ferrum2-platform-windows"; Target = "lib"; Test = "windows::ffi::tests::session::send_allocation_failure_distinguishes_ring_full_from_fatal_errors"; Witnesses = @() }
        ) }
    }
    $ordinal = 0
    foreach ($spec in $specs) {
        $ordinal++
        $testFile = switch ($spec.Package) {
            "ferrum2-client" { "ferrum2-client-tests.exe" }
            "ferrum2-tun" { "ferrum2-tun-tests.exe" }
            "ferrum2-platform-windows" { "ferrum2-platform-windows-tests.exe" }
            default { throw "M17 prebuilt test package is not closed" }
        }
        $testRunner = Join-Path $script:resolvedCandidateTestDirectory $testFile
        $arguments = @($spec.Test, "--exact", "--nocapture")
        $runnerKind = "prebuilt-rust-1.97.1"
        $result = Invoke-M17BoundedCommand ("test-{0:D2}-{1}" -f $ordinal, $spec.Package) $testRunner $arguments $script:resolvedProductRoot 300
        $testOutput = $result.Stdout + $result.Stderr
        $ranExactlyOne = $testOutput -match '(?m)^running 1 test\r?$' -and
            $testOutput -match '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+\r?$'
        Assert-True ($result.ExitCode -eq 0 -and $ranExactlyOne) "M17 exact candidate test failed or did not execute exactly once: $($spec.Test)"
        $script:m17TestRows.Add([ordered]@{
            package = $spec.Package
            test = $spec.Test
            status = "pass"
            runner = $runnerKind
            duration_ms = $result.DurationMilliseconds
            stdout_sha256 = (Get-FileHash -LiteralPath $result.StdoutPath -Algorithm SHA256).Hash.ToLowerInvariant()
            stderr_sha256 = (Get-FileHash -LiteralPath $result.StderrPath -Algorithm SHA256).Hash.ToLowerInvariant()
        })
        foreach ($witness in $spec.Witnesses) {
            Add-M17Witness $witness "deterministic-candidate-test" "$($spec.Package):$($spec.Test)"
        }
    }
}

function Get-M17MetricLabelSetValue(
    [string]$Metrics,
    [string]$Name,
    [System.Collections.IDictionary]$Labels,
    [bool]$AllowAbsent = $false
) {
    $lookaheads = @($Labels.GetEnumerator() | ForEach-Object {
        "(?=[^}`r`n]*$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|}))"
    }) -join ""
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{$lookaheads[^}`r`n]*\} ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return 0.0 }
    Assert-True ($matches.Count -eq 1) "missing or ambiguous M17 metric label set: $Name"
    return [double]::Parse($matches[0].Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-M17NetworkResetMetricState([string]$Metrics) {
    $reset = {
        param([string]$Reason, [string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_reset" ([ordered]@{
            reason = $Reason
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        ResetStarted = & $reset "network_change" "started"
        ResetSucceeded = & $reset "network_change" "succeeded"
        ResetFailed = & $reset "network_change" "failed"
        RetryStarted = & $reset "retry" "started"
        RetrySucceeded = & $reset "retry" "succeeded"
        RetryFailed = & $reset "retry" "failed"
        FullRebuild = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
        SessionActive = Get-M17MetricValue $Metrics "ferrum2_tun_session_active"
        StrictRequested = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_requested"
        StrictEffective = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_effective"
        StrictInstallSucceeded = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "success" $true
        StrictInstallFailed = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "failure" $true
    }
}

function Get-M17ManagedRouteRebuildMetricState([string]$Metrics) {
    $rebuild = {
        param([string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_full_rebuild" ([ordered]@{
            reason = "route_damage"
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        RouteDamageStarted = & $rebuild "started"
        RouteDamageSucceeded = & $rebuild "succeeded"
        RouteDamageFailed = & $rebuild "failed"
        FullRebuildTotal = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkResetTotal = Get-M17MetricValue $Metrics "ferrum2_network_reset" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
    }
}

function Wait-M17NetworkResetCycle(
    [int]$MetricsPort,
    [object]$Baseline,
    [int]$Cycle,
    [double]$ExpectedSessionGeneration,
    [int]$TimeoutSeconds = 60
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $state = $null
    do {
        $metrics = Get-Metrics $MetricsPort 2
        $state = Get-M17NetworkResetMetricState $metrics
        if ($state.ResetStarted -eq $Baseline.ResetStarted + $Cycle -and
            $state.ResetSucceeded -eq $Baseline.ResetSucceeded + $Cycle -and
            $state.ResetFailed -eq $Baseline.ResetFailed -and
            $state.RetryStarted -eq $Baseline.RetryStarted -and
            $state.RetrySucceeded -eq $Baseline.RetrySucceeded -and
            $state.RetryFailed -eq $Baseline.RetryFailed -and
            $state.FullRebuild -eq $Baseline.FullRebuild -and
            $state.NetworkGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionActive -eq 1 -and
            $state.StrictRequested -eq 1 -and $state.StrictEffective -eq 1 -and
            $state.StrictInstallSucceeded -eq $Baseline.StrictInstallSucceeded -and
            $state.StrictInstallFailed -eq $Baseline.StrictInstallFailed) {
            # Hold beyond the runtime's 350 ms notification debounce before accepting one cycle.
            Start-Sleep -Milliseconds 500
            $stableMetrics = Get-Metrics $MetricsPort 2
            $stable = Get-M17NetworkResetMetricState $stableMetrics
            Assert-True ($stable.ResetStarted -eq $state.ResetStarted -and
                $stable.ResetSucceeded -eq $state.ResetSucceeded -and
                $stable.ResetFailed -eq $state.ResetFailed -and
                $stable.RetryStarted -eq $state.RetryStarted -and
                $stable.RetrySucceeded -eq $state.RetrySucceeded -and
                $stable.RetryFailed -eq $state.RetryFailed -and
                $stable.NetworkGeneration -eq $state.NetworkGeneration -and
                $stable.SessionGeneration -eq $state.SessionGeneration -and
                $stable.FullRebuild -eq $state.FullRebuild -and
                $stable.StrictRequested -eq $state.StrictRequested -and
                $stable.StrictEffective -eq $state.StrictEffective -and
                $stable.StrictInstallSucceeded -eq $state.StrictInstallSucceeded -and
                $stable.StrictInstallFailed -eq $state.StrictInstallFailed) "M17 network-reset cycle did not stabilize"
            return [pscustomobject]@{ Metrics = $stableMetrics; State = $stable }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 network-reset cycle timeout: cycle=$Cycle expected_generation=$ExpectedSessionGeneration state=$($state | ConvertTo-Json -Compress)"
}
