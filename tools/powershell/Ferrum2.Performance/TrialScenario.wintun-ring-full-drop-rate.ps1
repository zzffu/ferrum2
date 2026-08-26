[uint64]$minimumResponseAttempts = 32768
Start-Sleep -Seconds 5
$before = Get-Metrics $MetricsPort 5
$ringBefore = Get-Metric $before "ferrum2_tun_wintun_ring_full_dropped" $true
$egressBefore = Get-Metric $before "ferrum2_tun_packets_egress" $true
$pendingBefore = Get-Metric $before "ferrum2_tun_pending_udp_responses"
Assert-Condition ($pendingBefore -eq 0) `
    "ring-full pending UDP response baseline is not zero"
$lifecycleBefore = Get-NetworkLifecycleMetrics $before
$sampledWorkload = Invoke-Workload $Scenario 600 `
    "ferrum2_tun_pending_udp_responses"
$observation = $sampledWorkload.Observation
[uint64]$pendingResponsePeak = $sampledWorkload.PeakMetric
Start-Sleep -Seconds 5
$after = Get-Metrics $MetricsPort 5
[uint64]$attempts = $observation.measurements.attempted_datagrams
[uint64]$drops = (Get-Metric $after "ferrum2_tun_wintun_ring_full_dropped" $true) - $ringBefore
[uint64]$egress = (Get-Metric $after "ferrum2_tun_packets_egress" $true) - $egressBefore
[uint64]$pendingAfter = Get-Metric $after "ferrum2_tun_pending_udp_responses"
[uint64]$responseAttempts = $drops + $egress
Assert-Condition ($attempts -eq 1000000) `
    "Wintun egress pressure workload attempt count is invalid"
Assert-Condition ($pendingResponsePeak -le 1) `
    "Wintun egress pressure exceeded the bounded pending UDP response depth"
Assert-Condition ($pendingAfter -eq 0) `
    "Wintun egress pressure pending UDP response did not drain"
Assert-Condition (
    $responseAttempts -ge $minimumResponseAttempts -and
    $responseAttempts -le $attempts
) (
    "Wintun egress pressure response accounting is outside the bounded request " +
    "denominator: response_attempts=$responseAttempts " +
    "minimum=$minimumResponseAttempts workload_attempts=$attempts"
)
$lifecycleAfter = Get-NetworkLifecycleMetrics $after
Assert-NetworkLifecycleMetricsEqual $lifecycleBefore $lifecycleAfter `
    "Wintun egress pressure triggered a network lifecycle transition"
$checkedUnits = $responseAttempts
$measurements.drop_rate = [ordered]@{
    unit = "dropped_packets_per_million_responses"
    value = [uint64][Math]::Ceiling(([decimal]$drops * 1000000) / [decimal]$responseAttempts)
}
$measurements.pending_response_peak = [ordered]@{
    unit = "pending_udp_responses"
    value = $pendingResponsePeak
}
$diagnostics = [ordered]@{
    schema_version = 1
    kind = "wintun_egress_pressure_accounting"
    workload_attempted_datagrams = $attempts
    tun_packets_egress = $egress
    wintun_ring_full_dropped = $drops
    tun_response_attempts = $responseAttempts
    pending_response_before = [uint64]$pendingBefore
    pending_response_peak = $pendingResponsePeak
    pending_response_after = $pendingAfter
}
$checks.minimum_response_attempts_met = $true
$checks.response_attempt_denominator_derived = $true
$checks.drop_rate_recomputed_from_raw_counts = $true
$checks.drop_rate_denominator_bound = $true
$checks.ring_full_counter_sampled = $true
$checks.pending_response_peak_bounded = $true
$checks.pending_response_baseline_and_drain = $true
$checks.no_network_reset_or_full_rebuild = $true
