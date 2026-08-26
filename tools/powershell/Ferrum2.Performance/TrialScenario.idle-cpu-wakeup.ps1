Start-Sleep -Seconds 10
$cpuBefore = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
$switchBefore = Get-ContextSwitches $ClientPid
$trafficBefore = Get-Metrics $MetricsPort 5
[uint64]$ingressBefore = Get-Metric `
    -Metrics $trafficBefore -Name "ferrum2_tun_packets_ingress" `
    -AllowAbsent $true
[uint64]$acceptedBefore = Get-Metric `
    -Metrics $trafficBefore -Name "ferrum2_tun_packets_accepted" `
    -AllowAbsent $true
[uint64]$egressBefore = Get-Metric `
    -Metrics $trafficBefore -Name "ferrum2_tun_packets_egress" `
    -AllowAbsent $true
$packetRejectBefore = Get-PacketRejectCounter -Metrics $trafficBefore
$dropCountersBefore = Get-ProductDropCounter -Metrics $trafficBefore
$checkedUnits = 0
foreach ($sample in 1..60) {
    Start-Sleep -Seconds 1
    $sampleMetrics = Get-Metrics $MetricsPort 2
    Assert-Condition ((Get-Metric $sampleMetrics "ferrum2_tun_session_active") -eq 1) "TUN session was not active throughout idle sample"
    $checkedUnits++
}
$trafficAfter = Get-Metrics $MetricsPort 5
$cpuAfter = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
$switchAfter = Get-ContextSwitches $ClientPid
[uint64]$ingressAfter = Get-Metric `
    -Metrics $trafficAfter -Name "ferrum2_tun_packets_ingress" `
    -AllowAbsent $true
[uint64]$acceptedAfter = Get-Metric `
    -Metrics $trafficAfter -Name "ferrum2_tun_packets_accepted" `
    -AllowAbsent $true
[uint64]$egressAfter = Get-Metric `
    -Metrics $trafficAfter -Name "ferrum2_tun_packets_egress" `
    -AllowAbsent $true
$packetRejectAfter = Get-PacketRejectCounter -Metrics $trafficAfter
$dropCountersAfter = Get-ProductDropCounter -Metrics $trafficAfter
foreach ($name in @(
    "total", "family_disabled", "invalid_destination", "unexpected"
)) {
    Assert-Condition (
        [uint64]$packetRejectAfter[$name] -ge `
            [uint64]$packetRejectBefore[$name]
    ) "idle packet rejection counter regressed: $name"
}
Assert-Condition ($ingressAfter -ge $ingressBefore) `
    "idle ingress counter regressed"
Assert-Condition ($acceptedAfter -ge $acceptedBefore) `
    "idle accepted counter regressed"
Assert-Condition ($egressAfter -ge $egressBefore) `
    "idle egress counter regressed"
[decimal]$ingressDelta = [decimal]$ingressAfter - $ingressBefore
[decimal]$acceptedDelta = [decimal]$acceptedAfter - $acceptedBefore
[decimal]$egressDelta = [decimal]$egressAfter - $egressBefore
[decimal]$familyDisabledDelta = (
    [decimal]$packetRejectAfter["family_disabled"] -
        [decimal]$packetRejectBefore["family_disabled"]
)
[decimal]$invalidDestinationDelta = (
    [decimal]$packetRejectAfter["invalid_destination"] -
        [decimal]$packetRejectBefore["invalid_destination"]
)
[decimal]$unexpectedRejectDelta = (
    [decimal]$packetRejectAfter["unexpected"] -
        [decimal]$packetRejectBefore["unexpected"]
)
[decimal]$knownBackgroundDelta = `
    $familyDisabledDelta + $invalidDestinationDelta
Assert-Condition (
    $acceptedDelta -eq 0 -and
    $egressDelta -eq 0 -and
    $unexpectedRejectDelta -eq 0 -and
    $ingressDelta -eq $knownBackgroundDelta
) (
    "idle window contained unaccounted TUN traffic: " +
        "ingress_delta=$ingressDelta accepted_delta=$acceptedDelta " +
        "egress_delta=$egressDelta " +
        "known_background_rejected_delta=$knownBackgroundDelta " +
        "unexpected_rejected_delta=$unexpectedRejectDelta"
)
Assert-ProductDropCounterUnchanged `
    -Before $dropCountersBefore -After $dropCountersAfter
Assert-Condition ($cpuAfter -ge $cpuBefore) `
    "idle CPU counter regressed: before=$cpuBefore after=$cpuAfter"
Assert-Condition ($switchAfter -ge $switchBefore) `
    "idle context-switch counter regressed: before=$switchBefore after=$switchAfter"
[uint64]$cpuRate = [uint64][Math]::Ceiling(
    ($cpuAfter - $cpuBefore) / 60.0
)
[uint64]$switchRate = [uint64][Math]::Ceiling(
    ($switchAfter - $switchBefore) / 60.0
)
# The reducer uses paired percentages and therefore requires a positive baseline.
# Censor a sub-resolution zero observation at the recipe-bound integer rate floor.
if ($cpuRate -eq 0) { $cpuRate = 1 }
if ($switchRate -eq 0) { $switchRate = 1 }
$measurements.cpu_idle_cost = [ordered]@{
    unit = "cpu_nanoseconds_per_second"; value = $cpuRate
}
$measurements.wakeups = [ordered]@{
    unit = "process_context_switches_per_second"; value = $switchRate
}
$checks.session_active_throughout = $true
$checks.zero_test_traffic = $true
$checks.known_background_ingress_exactly_accounted = $true
$checks.no_busy_poll_fallback = $true
[void](Wait-CleanDrain $true)
$checks.clean_drain = $true
