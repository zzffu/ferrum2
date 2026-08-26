$counterSnapshotBefore = Get-CoherentFragmentCounterSnapshot
$before = $counterSnapshotBefore.Metrics
$adapterCountersBefore = $counterSnapshotBefore.AdapterCounters
$adapterIdentityBefore = [string]$counterSnapshotBefore.AdapterIdentity
$dropCountersBefore = Get-ProductDropCounter -Metrics $before
$packetRejectBefore = Get-PacketRejectCounter -Metrics $before
[uint64]$fragmentIngressBefore = Get-Metric -Metrics $before `
    -Name "ferrum2_tun_packets_ingress" -AllowAbsent $true
[uint64]$fragmentAcceptedBefore = Get-Metric -Metrics $before `
    -Name "ferrum2_tun_packets_accepted" -AllowAbsent $true
[uint64]$completedBefore = Get-Metric -Metrics $before `
    -Name "ferrum2_tun_reassembly_completed" -AllowAbsent $true
[uint64]$fragmentGenerationBefore = Get-Metric -Metrics $before `
    -Name "ferrum2_tun_session_generation"
Assert-Condition (
    $fragmentGenerationBefore -ge 1 -and
    (Get-Metric -Metrics $before -Name "ferrum2_tun_session_active") -eq 1
) "TUN session is not active before fragment workload"
$observation = Invoke-Workload $Scenario 120
Assert-ExactProperties -Value $observation -Expected @(
    "measurements", "checked_units", "accounting", "checks"
) -Name "fragment workload observation"
Assert-ExactProperties -Value $observation.measurements `
    -Expected @("reassembly_rate") -Name "fragment workload measurements"
Assert-ExactProperties -Value $observation.checks -Expected @(
    "payload_exact", "no_gso", "all_sequences_acknowledged",
    "bounded_retransmissions"
) -Name "fragment workload checks"
Assert-ExactProperties -Value $observation.accounting -Expected @(
    "warmup_unique_datagrams", "warmup_request_attempts",
    "active_unique_datagrams", "active_request_attempts",
    "total_unique_datagrams", "total_request_attempts", "retransmissions",
    "ack_window_expirations", "duplicate_or_stale_acks", "retry_budget"
) -Name "fragment workload accounting"

$checkedUnits = Get-StrictUInt64Property -Value $observation `
    -PropertyName "checked_units" -Name "fragment workload observation"
$accounting = [ordered]@{}
foreach ($name in @(
    "warmup_unique_datagrams", "warmup_request_attempts",
    "active_unique_datagrams", "active_request_attempts",
    "total_unique_datagrams", "total_request_attempts", "retransmissions",
    "ack_window_expirations", "duplicate_or_stale_acks", "retry_budget"
)) {
    $accounting[$name] = Get-StrictUInt64Property `
        -Value $observation.accounting -PropertyName $name `
        -Name "fragment workload accounting"
}
Assert-Condition (
    [uint64]$accounting.warmup_unique_datagrams -gt 0 -and
    [uint64]$accounting.active_unique_datagrams -gt 0 -and
    [uint64]$accounting.warmup_unique_datagrams % 8 -eq 0 -and
    [uint64]$accounting.active_unique_datagrams % 8 -eq 0 -and
    [uint64]$accounting.total_unique_datagrams % 8 -eq 0
) "fragment unique datagram accounting is not batch-aligned"
Assert-Condition (
    [uint64]$accounting.active_unique_datagrams -eq $checkedUnits
) "fragment active unique datagrams do not match checked units"
Assert-Condition (
    [uint64]$accounting.warmup_request_attempts -ge
        [uint64]$accounting.warmup_unique_datagrams -and
    [uint64]$accounting.active_request_attempts -ge
        [uint64]$accounting.active_unique_datagrams
) "fragment phase request attempts are below unique datagrams"
Assert-Condition (
    [decimal]$accounting.total_unique_datagrams -eq
        [decimal]$accounting.warmup_unique_datagrams +
            [decimal]$accounting.active_unique_datagrams
) "fragment total unique datagram accounting is inconsistent"
Assert-Condition (
    [decimal]$accounting.total_request_attempts -eq
        [decimal]$accounting.warmup_request_attempts +
            [decimal]$accounting.active_request_attempts
) "fragment total request attempt accounting is inconsistent"
Assert-Condition (
    [uint64]$accounting.total_request_attempts -ge
        [uint64]$accounting.total_unique_datagrams -and
    [decimal]$accounting.total_request_attempts -
        [decimal]$accounting.total_unique_datagrams -eq
        [decimal]$accounting.retransmissions
) "fragment retransmission accounting is inconsistent"
Assert-Condition (
    [uint64]$accounting.ack_window_expirations -eq
        [uint64]$accounting.retransmissions -and
    [uint64]$accounting.duplicate_or_stale_acks -le
        [uint64]$accounting.retransmissions
) "fragment ACK-window accounting is inconsistent"
[uint64]$expectedRetryBudget = [uint64][Math]::Ceiling(
    [decimal]$accounting.total_unique_datagrams / [decimal]1000000
)
if ($expectedRetryBudget -lt 1) { $expectedRetryBudget = 1 }
Assert-Condition (
    [uint64]$accounting.retry_budget -eq $expectedRetryBudget -and
    [uint64]$accounting.retransmissions -le [uint64]$accounting.retry_budget
) "fragment retransmission budget accounting is inconsistent"

[void](Wait-CleanDrain $true)
$checks.clean_drain = $true
$counterSnapshotAfter = Get-CoherentFragmentCounterSnapshot
$after = $counterSnapshotAfter.Metrics
$adapterCountersAfter = $counterSnapshotAfter.AdapterCounters
Assert-Condition (
    [string]$counterSnapshotAfter.AdapterIdentity -ceq $adapterIdentityBefore
) "managed performance adapter identity changed during fragment workload"
$dropCountersAfter = Get-ProductDropCounter -Metrics $after
$packetRejectAfter = Get-PacketRejectCounter -Metrics $after
Assert-ProductDropCounterUnchanged `
    -Before $dropCountersBefore -After $dropCountersAfter
[uint64]$fragmentIngressAfter = Get-Metric -Metrics $after `
    -Name "ferrum2_tun_packets_ingress" -AllowAbsent $true
[uint64]$fragmentAcceptedAfter = Get-Metric -Metrics $after `
    -Name "ferrum2_tun_packets_accepted" -AllowAbsent $true
[uint64]$completedAfter = Get-Metric -Metrics $after `
    -Name "ferrum2_tun_reassembly_completed" -AllowAbsent $true
[uint64]$fragmentGenerationAfter = Get-Metric -Metrics $after `
    -Name "ferrum2_tun_session_generation"
Assert-Condition (
    $fragmentGenerationAfter -eq $fragmentGenerationBefore -and
    (Get-Metric -Metrics $after -Name "ferrum2_tun_session_active") -eq 1
) "TUN session changed during fragment workload"
Assert-Condition (
    $fragmentIngressAfter -ge $fragmentIngressBefore -and
    $fragmentAcceptedAfter -ge $fragmentAcceptedBefore -and
    $completedAfter -ge $completedBefore
) "fragment product counters decreased"
Assert-Condition (
    [uint64]$packetRejectAfter.family_disabled -ge
        [uint64]$packetRejectBefore.family_disabled -and
    [uint64]$packetRejectAfter.invalid_destination -ge
        [uint64]$packetRejectBefore.invalid_destination
) "fragment background rejection counters decreased"
[uint64]$fragmentIngressDelta = $fragmentIngressAfter - $fragmentIngressBefore
[uint64]$fragmentAcceptedDelta = `
    $fragmentAcceptedAfter - $fragmentAcceptedBefore
[uint64]$completedDelta = $completedAfter - $completedBefore
[uint64]$familyDisabledDelta = `
    [uint64]$packetRejectAfter.family_disabled - `
    [uint64]$packetRejectBefore.family_disabled
[uint64]$invalidDestinationDelta = `
    [uint64]$packetRejectAfter.invalid_destination - `
    [uint64]$packetRejectBefore.invalid_destination
[decimal]$backgroundPacketCount = `
    [decimal]$familyDisabledDelta + $invalidDestinationDelta
Assert-Condition ($backgroundPacketCount -le [decimal][uint64]::MaxValue) `
    "fragment background packet count overflowed"
Assert-Condition (
    [decimal]$accounting.total_request_attempts -le
        [decimal][uint64]::MaxValue / [decimal]2
) "fragment request attempt count exceeds the packet denominator"
[uint64]$expectedFragmentPackets = [uint64]$accounting.total_request_attempts * 2
Assert-Condition (
    [decimal]$expectedFragmentPackets + $backgroundPacketCount -le
        [decimal][uint64]::MaxValue
) "fragment ingress packet accounting overflowed"
[uint64]$expectedIngressPackets = [uint64](
    [decimal]$expectedFragmentPackets + $backgroundPacketCount
)
Assert-Condition ($fragmentAcceptedDelta -eq $expectedFragmentPackets) `
    "fragment workload accepted-packet accounting is inconsistent"
Assert-Condition ($fragmentIngressDelta -eq $expectedIngressPackets) `
    "fragment workload ingress/background accounting is inconsistent"
Assert-Condition (
    $completedDelta -eq [uint64]$accounting.total_request_attempts
) "fragment request attempts did not all reach product reassembly"
$packetCounterDeltas = [ordered]@{
    accepted_packets = $fragmentAcceptedDelta
    ingress_packets = $fragmentIngressDelta
    background_family_disabled = $familyDisabledDelta
    background_invalid_destination = $invalidDestinationDelta
    background_packets = [uint64]$backgroundPacketCount
}

$adapterCounterDeltas = Get-AdapterCounterDelta `
    -Before $adapterCountersBefore -After $adapterCountersAfter
foreach ($name in @(
    "ReceivedDiscardedPackets", "ReceivedPacketErrors",
    "OutboundDiscardedPackets", "OutboundPacketErrors"
)) {
    Assert-Condition ([uint64]$adapterCounterDeltas[$name] -eq 0) `
        "fragment workload recorded adapter packet loss: $name"
}
Assert-Condition (
    [uint64]$adapterCounterDeltas.SentUnicastPackets -eq
        $expectedIngressPackets
) (
    "fragment workload adapter sent-packet accounting is inconsistent: " +
        "expected=$expectedIngressPackets actual=" +
        [uint64]$adapterCounterDeltas.SentUnicastPackets
)
Assert-Condition (
    [uint64]$adapterCounterDeltas.ReceivedUnicastPackets -ge
        [uint64]$accounting.total_unique_datagrams
) "fragment workload adapter received-packet accounting is inconsistent"
$diagnostics = [ordered]@{
    schema_version = 2
    kind = "fragment_ack_accounting"
    batch_datagrams = 8
    ack_window_milliseconds = 500
    max_missing_per_batch = 1
    max_retransmissions_per_sequence = 1
    retry_budget_unique_datagrams = 1000000
    minimum_retry_budget = 1
    retry_scope = "missing-sequence-only"
    accounting = $accounting
    packet_counter_deltas = $packetCounterDeltas
    adapter_counter_deltas = $adapterCounterDeltas
}
$measurements.reassembly_rate = [ordered]@{
    unit = "reassembled_payload_bytes_per_second"; value = [uint64]$observation.measurements.reassembly_rate
}
$checks.fragment_packets_observed = $true
$checks.no_reassembly_drop = $true
$checks.payload_exact = $observation.checks.payload_exact -eq $true
$checks.no_gso = $observation.checks.no_gso -eq $true
$checks.all_sequences_acknowledged = `
    $observation.checks.all_sequences_acknowledged -eq $true
$checks.bounded_retransmissions = `
    $observation.checks.bounded_retransmissions -eq $true
$checks.no_adapter_packet_loss = $true
