param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "tcp-single-flow",
        "tcp-256-flow-fairness",
        "udp-packets-per-second",
        "udp-8192-association-lookup-expiry",
        "fragment-reassembly-throughput",
        "idle-cpu-wakeup",
        "wintun-ring-full-drop-rate",
        "udp-route-once",
        "network-lifecycle"
    )]
    [string]$Scenario,

    [Parameter(Mandatory = $true)]
    [ValidateSet("comparison", "calibration-aa")]
    [string]$RunKind,

    [Parameter(Mandatory = $true)]
    [ValidateSet("parent", "candidate")]
    [string]$Member,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 5)]
    [int]$Pair,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2)]
    [int]$Order,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 90)]
    [int]$Sequence,

    [Parameter(Mandatory = $true)][string]$ParentSha,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$Tree,
    [Parameter(Mandatory = $true)][string]$RecipeSha256,
    [Parameter(Mandatory = $true)][string]$ClientBinary,
    [Parameter(Mandatory = $true)][string]$ServerBinary,
    [Parameter(Mandatory = $true)][string]$HarnessBinary,
    [Parameter(Mandatory = $true)][string]$IdentityLedger,
    [Parameter(Mandatory = $true)][string]$NetworkModelPlan,
    [Parameter(Mandatory = $true)][string]$NetworkModelController,
    [Parameter(Mandatory = $true)][string]$AdapterName,
    [string]$NetworkModelOutput,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ClientPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ServerPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$MetricsPort,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ServerMetricsPort,
    [Parameter(Mandatory = $true)][string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($MetricsPort -eq $ServerMetricsPort) {
    throw "client and server metrics ports must be distinct"
}

$ExpectedVmName = "Windows 10 MSIX packaging environment"
$ExpectedVmId = "82e20295-1d30-48e7-a751-e21d35d872d4"
$ExpectedCheckpointName = "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9"
$ExpectedCheckpointId = "1e570209-faf7-4248-8167-aa0687cdb8cf"
$ExpectedRunnerLabel = "ferrum2-hyperv-guest"
$Utf8NoBom = [Text.UTF8Encoding]::new($false)

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ExactProperties(
    [object]$Value,
    [string[]]$Expected,
    [string]$Name
) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Condition (($actual -join "|") -ceq ($wanted -join "|")) "$Name schema mismatch"
}

function Resolve-Leaf([string]$Path, [string]$Name) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-Condition (Test-Path -LiteralPath $resolved -PathType Leaf) "$Name is not a file"
    $item = Get-Item -LiteralPath $resolved -Force
    Assert-Condition (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) "$Name cannot be a reparse point"
    return $resolved
}

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Metrics([int]$Port, [int]$TimeoutSeconds = 5) {
    return (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/metrics" `
        -TimeoutSec $TimeoutSeconds -ErrorAction Stop).Content
}

function Get-Metric([string]$Metrics, [string]$Name, [bool]$AllowAbsent = $false) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?(?:\{[^}`r`n]*\})? ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return [double]0 }
    Assert-Condition ($matches.Count -gt 0) "missing product metric: $Name"
    [double]$total = 0
    foreach ($match in $matches) {
        $total += [double]::Parse(
            $match.Groups[1].Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    return $total
}

function Get-LabeledMetric(
    [string]$Metrics,
    [string]$Name,
    [hashtable]$Labels,
    [bool]$AllowAbsent = $false
) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{(?<labels>[^}`r`n]*)\} (?<value>[0-9]+(?:\.[0-9]+)?)$"
    $selected = @([regex]::Matches($Metrics, $pattern) | Where-Object {
        $encoded = $_.Groups["labels"].Value
        @($Labels.GetEnumerator() | Where-Object {
            $encoded -cnotmatch "(?:^|,)$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|$)"
        }).Count -eq 0
    })
    if ($selected.Count -eq 0 -and $AllowAbsent) { return [double]0 }
    Assert-Condition ($selected.Count -eq 1) "missing or ambiguous labeled product metric: $Name"
    return [double]::Parse(
        $selected[0].Groups["value"].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-StrictUInt64Property(
    [object]$Value,
    [string]$PropertyName,
    [string]$Name
) {
    Assert-Condition ($null -ne $Value) "$Name is null"
    $property = $Value.PSObject.Properties[$PropertyName]
    Assert-Condition ($null -ne $property) "$Name is missing $PropertyName"
    $raw = $property.Value
    $isInteger = (
        $raw -is [byte] -or $raw -is [uint16] -or $raw -is [uint32] -or
        $raw -is [uint64] -or $raw -is [sbyte] -or $raw -is [int16] -or
        $raw -is [int32] -or $raw -is [int64]
    )
    Assert-Condition $isInteger "$Name $PropertyName must be an integer"
    Assert-Condition ([decimal]$raw -ge 0) "$Name $PropertyName must be non-negative"
    return [uint64]$raw
}

function Get-NetworkLifecycleMetrics([string]$Metrics) {
    return [ordered]@{
        network_generation = [uint64](
            Get-Metric $Metrics "ferrum2_network_generation"
        )
        session_generation = [uint64](
            Get-Metric $Metrics "ferrum2_tun_session_generation"
        )
        network_reset_total = [uint64](
            Get-Metric $Metrics "ferrum2_network_reset" $true
        )
        network_reset_started = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_reset" @{
                reason = "network_change"; result = "started"
            } $true
        )
        network_reset_succeeded = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_reset" @{
                reason = "network_change"; result = "succeeded"
            } $true
        )
        network_reset_failed = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_reset" @{
                reason = "network_change"; result = "failed"
            } $true
        )
        full_rebuild_total = [uint64](
            Get-Metric $Metrics "ferrum2_network_full_rebuild" $true
        )
        full_rebuild_started = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_full_rebuild" @{
                reason = "route_damage"; result = "started"
            } $true
        )
        full_rebuild_succeeded = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_full_rebuild" @{
                reason = "route_damage"; result = "succeeded"
            } $true
        )
        full_rebuild_failed = [uint64](
            Get-LabeledMetric $Metrics "ferrum2_network_full_rebuild" @{
                reason = "route_damage"; result = "failed"
            } $true
        )
    }
}

function Assert-NetworkLifecycleMetricsEqual(
    [object]$Expected,
    [object]$Actual,
    [string]$Message
) {
    foreach ($name in @(
        "network_generation", "session_generation",
        "network_reset_total", "network_reset_started", "network_reset_succeeded",
        "network_reset_failed", "full_rebuild_total", "full_rebuild_started",
        "full_rebuild_succeeded", "full_rebuild_failed"
    )) {
        Assert-Condition ([uint64]$Actual[$name] -eq [uint64]$Expected[$name]) `
            "$Message ($name)"
    }
}

function Assert-NetworkLifecycleTransition(
    [ValidateSet("reset_network", "full_rebuild")][string]$Operation,
    [object]$Before,
    [object]$After
) {
    Assert-Condition (
        [uint64]$Before.network_generation -eq [uint64]$Before.session_generation -and
        [uint64]$After.network_generation -eq [uint64]$After.session_generation -and
        [uint64]$After.network_generation -eq [uint64]$Before.network_generation + 1
    ) "$Operation did not advance both generations exactly once"
    $activeFamily = if ($Operation -ceq "reset_network") {
        "network_reset"
    } else {
        "full_rebuild"
    }
    $inactiveFamily = if ($Operation -ceq "reset_network") {
        "full_rebuild"
    } else {
        "network_reset"
    }
    foreach ($family in @($activeFamily, $inactiveFamily)) {
        foreach ($result in @("started", "succeeded", "failed", "total")) {
            [uint64]$expectedDelta = if ($family -ceq $activeFamily) {
                if ($result -ceq "started" -or $result -ceq "succeeded") {
                    1
                } elseif ($result -ceq "total") {
                    2
                } else {
                    0
                }
            } else {
                0
            }
            $name = "${family}_${result}"
            [uint64]$actualDelta = [uint64]$After[$name] - [uint64]$Before[$name]
            Assert-Condition ($actualDelta -eq $expectedDelta) `
                "$Operation metric delta mismatch: $name"
        }
    }
}

function Get-ElapsedNanoseconds([Diagnostics.Stopwatch]$Timer) {
    return [uint64][Math]::Ceiling(
        ([decimal]$Timer.ElapsedTicks * [decimal]1000000000) /
        [decimal][Diagnostics.Stopwatch]::Frequency
    )
}

function Get-NearestRank([uint64[]]$Values, [ValidateSet(50, 95, 99)][int]$Percentile) {
    Assert-Condition ($Values.Count -gt 0) "latency sample set is empty"
    $ordered = @($Values | Sort-Object)
    $rank = [int][Math]::Ceiling(([decimal]$Percentile * $ordered.Count) / 100)
    return [uint64]$ordered[$rank - 1]
}

function Get-ProcessCpuNanoseconds([Diagnostics.Process[]]$Processes) {
    [decimal]$ticks = 0
    foreach ($process in $Processes) {
        $process.Refresh()
        Assert-Condition (-not $process.HasExited) "measured product process exited"
        $ticks += [decimal]$process.TotalProcessorTime.Ticks
    }
    return [uint64]($ticks * 100)
}

function Get-ContextSwitches([int]$ProcessId) {
    $rows = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process `
        -Filter "IDProcess=$ProcessId" -ErrorAction Stop)
    Assert-Condition ($rows.Count -eq 1) "client context-switch counter is unavailable"
    return [uint64]$rows[0].ContextSwitchesPersec
}

function Invoke-BoundedHarness(
    [string[]]$Arguments,
    [int]$TimeoutSeconds,
    [string]$PeakMetricName = ""
) {
    $stdoutPath = Join-Path $script:WorkRoot "harness-$([guid]::NewGuid().ToString('N')).stdout"
    $stderrPath = "$stdoutPath.stderr"
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $script:HarnessPath
    $info.WorkingDirectory = Split-Path -Parent $script:HarnessPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    Assert-Condition $process.Start() "traffic harness failed to start"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    [uint64]$peakMetric = 0
    $sampledMetric = $false
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (-not [string]::IsNullOrWhiteSpace($PeakMetricName)) {
            $sample = [uint64](Get-Metric (Get-Metrics $script:MetricsPort 2) $PeakMetricName)
            if (-not $sampledMetric -or $sample -gt $peakMetric) { $peakMetric = $sample }
            $sampledMetric = $true
        }
        if ($process.WaitForExit(10)) { break }
    } while ([DateTime]::UtcNow -lt $deadline)
    $timedOut = -not $process.HasExited
    if ($timedOut) {
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
        Assert-Condition ($process.WaitForExit(10000)) "timed-out traffic harness could not be reaped"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText($stdoutPath, $stdout, $script:Utf8NoBom)
    [IO.File]::WriteAllText($stderrPath, $stderr, $script:Utf8NoBom)
    $exitCode = $process.ExitCode
    $process.Dispose()
    $failureDetail = "exit_code=$exitCode stderr=$($stderr.Trim()) stdout=$($stdout.Trim())".
        Replace("`r", " ").Replace("`n", " ")
    if ($failureDetail.Length -gt 4096) {
        $failureDetail = $failureDetail.Substring(0, 4096)
    }
    Assert-Condition (-not $timedOut) "traffic harness timed out: $failureDetail"
    Assert-Condition ($exitCode -eq 0) "traffic harness failed: $failureDetail"
    Assert-Condition (
        $script:Utf8NoBom.GetByteCount($stdout) -le 65536 -and
        $script:Utf8NoBom.GetByteCount($stderr) -le 65536
    ) "traffic harness output exceeded 64 KiB"
    if (-not [string]::IsNullOrWhiteSpace($PeakMetricName)) {
        Assert-Condition $sampledMetric "traffic harness metric sampler collected no observations"
        return $peakMetric
    }
}

function Invoke-Workload(
    [string]$SelectedScenario,
    [int]$TimeoutSeconds,
    [string]$PeakMetricName = ""
) {
    $path = Join-Path $script:WorkRoot ("workload-{0}.json" -f [guid]::NewGuid().ToString("N"))
    Assert-Condition (-not (Test-Path -LiteralPath $path)) "workload output baseline is not absent"
    $arguments = @(
            "windows-tun-workload",
            "--scenario", $SelectedScenario,
            "--target-ip", $script:TargetAddress,
            "--tcp-port", [string]$script:TargetTcpPort,
            "--udp-port", [string]$script:TargetUdpPort,
            "--output", $path
        )
    $peakMetric = if ([string]::IsNullOrWhiteSpace($PeakMetricName)) {
        [void](Invoke-BoundedHarness $arguments $TimeoutSeconds)
        $null
    } else {
        [uint64](Invoke-BoundedHarness $arguments $TimeoutSeconds $PeakMetricName)
    }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8
    Assert-ExactProperties $raw @("schema_version", "kind", "scenario", "observation", "status") "workload"
    Assert-Condition (
        $raw.schema_version -eq 1 -and
        $raw.kind -ceq "windows_tun_guest_workload" -and
        $raw.scenario -ceq $SelectedScenario -and
        $raw.status -ceq "PASS"
    ) "workload identity/status mismatch"
    if ([string]::IsNullOrWhiteSpace($PeakMetricName)) { return $raw.observation }
    return [pscustomobject]@{
        Observation = $raw.observation
        PeakMetric = $peakMetric
    }
}

function Invoke-Probe {
    [void](Invoke-BoundedHarness @(
        "windows-tun-probe",
        "--target-ip", $script:TargetAddress,
        "--tcp-port", [string]$script:TargetTcpPort,
        "--udp-port", [string]$script:TargetUdpPort
    ) 30)
}

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
            "fragment workload changed product drop counter: $name"
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

function Get-LifecycleResources([string]$Metrics) {
    $clientProcess.Refresh()
    Assert-Condition (-not $clientProcess.HasExited) "client exited during lifecycle sampling"
    $managedAdapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop).Count
    return [ordered]@{
        process_handles = [uint64]$clientProcess.HandleCount
        process_threads = [uint64]$clientProcess.Threads.Count
        udp_associations_active = [uint64](
            Get-Metric $Metrics "ferrum2_tun_udp_associations_active"
        )
        managed_adapters_active = [uint64]$managedAdapters
    }
}

function Get-PhysicalDefaultRoute {
    $managed = Get-ManagedAdapter
    $rows = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
            -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [uint32]$_.InterfaceIndex -ne [uint32]$managed.ifIndex } |
            ForEach-Object {
                $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -IncludeHidden `
                    -ErrorAction Stop
                $interface = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex `
                    -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
                [pscustomobject]@{
                    Route = $_
                    Adapter = $adapter
                    EffectiveMetric = [uint64]$_.RouteMetric + [uint64]$interface.InterfaceMetric
                }
            } | Sort-Object EffectiveMetric, @{ Expression = { $_.Route.InterfaceIndex } }
    )
    Assert-Condition (
        $rows.Count -gt 0 -and
        [bool]$rows[0].Adapter.HardwareInterface -and
        [string]$rows[0].Adapter.Status -ceq "Up" -and
        ($rows.Count -eq 1 -or $rows[0].EffectiveMetric -lt $rows[1].EffectiveMetric)
    ) "one preferred physical IPv4 default route is required"
    return $rows[0]
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

foreach ($digest in @($ParentSha, $CandidateSha, $Tree)) {
    Assert-Condition ($digest -cmatch '^[0-9a-f]{40}$') "commit/tree identity must be lowercase 40-hex"
}
Assert-Condition ($RecipeSha256 -cmatch '^[0-9a-f]{64}$') "recipe identity must be lowercase SHA-256"
$expectedOrder = if (($Member -ceq "parent") -eq (($Pair % 2) -eq 1)) { 1 } else { 2 }
Assert-Condition ($Order -eq $expectedOrder) "trial order does not follow the alternating schedule"
if ($RunKind -ceq "calibration-aa") {
    Assert-Condition ($ParentSha -ceq $CandidateSha) "A/A trial requires identical commit SHAs"
} else {
    Assert-Condition ($ParentSha -cne $CandidateSha) "comparison trial requires distinct commit SHAs"
}
$memberSha = if ($Member -ceq "parent") { $ParentSha } else { $CandidateSha }

$script:ClientPath = Resolve-Leaf $ClientBinary "client binary"
$script:ServerPath = Resolve-Leaf $ServerBinary "server binary"
$script:HarnessPath = Resolve-Leaf $HarnessBinary "traffic harness"
$ledgerPath = Resolve-Leaf $IdentityLedger "identity ledger"
$modelPlanPath = Resolve-Leaf $NetworkModelPlan "network-model plan"
$modelControllerPath = Resolve-Leaf $NetworkModelController "network-model controller"
$modelPlanHash = Get-LowerSha256 $modelPlanPath
$modelControllerHash = Get-LowerSha256 $modelControllerPath
$modelPlan = Get-Content -LiteralPath $modelPlanPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 12
Assert-ExactProperties $modelPlan @(
    "schema_version", "execution", "host_network_mutation", "workloads",
    "observation_identity_fields"
) "network-model plan"
Assert-Condition (
    $modelPlan.schema_version -eq 3 -and
    $modelPlan.execution -ceq "local_hyperv_guest" -and
    $modelPlan.host_network_mutation -ceq "forbidden"
) "network-model plan execution boundary changed"
Assert-ExactProperties $modelPlan.workloads @("network-lifecycle", "udp-route-once") `
    "network-model workloads"
$lifecyclePlan = $modelPlan.workloads."network-lifecycle"
$routeOncePlan = $modelPlan.workloads."udp-route-once"
Assert-Condition (
    [int]$lifecyclePlan.reset_network_cycles -eq 1000 -and
    [int]$lifecyclePlan.full_rebuild_cycles -eq 10 -and
    [string]$lifecyclePlan.full_rebuild_damage_reason -ceq "route_damage" -and
    [string]$lifecyclePlan.interface_switch_kind -ceq "approved_underlay_disable_enable" -and
    [int]$lifecyclePlan.interface_switch_sequence -eq 500 -and
    [int]$lifecyclePlan.interface_resolver_probes -eq 32
) "network-model lifecycle recipe changed"
Assert-Condition (
    [int]$routeOncePlan.generations -eq 2 -and
    [int]$routeOncePlan.source_slots -eq 64 -and
    [int]$routeOncePlan.target_slots -eq 4 -and
    [int]$routeOncePlan.datagrams_per_target -eq 32 -and
    (@($routeOncePlan.required_outbounds) -join "|") -ceq "direct|proxy"
) "network-model route-once recipe changed"
$outputPath = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputPath
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) "trial output baseline is not absent"
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) "trial output parent does not exist"
$outputParentItem = Get-Item -LiteralPath $outputParent -Force
Assert-Condition (-not ($outputParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "trial output parent cannot be a reparse point"
$modelOutputPath = $null
if ($Scenario -in @("udp-route-once", "network-lifecycle")) {
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "$Scenario requires raw network-model output"
    $modelOutputPath = [IO.Path]::GetFullPath($NetworkModelOutput)
    $modelOutputParent = Split-Path -Parent $modelOutputPath
    Assert-Condition (
        -not (Test-Path -LiteralPath $modelOutputPath) -and
        (Test-Path -LiteralPath $modelOutputParent -PathType Container) -and
        -not ((Get-Item -LiteralPath $modelOutputParent -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -and
        [IO.Path]::GetFileName($modelOutputPath) -ceq (
            "{0:D3}-{1}-{2}-pair-{3}.network-model.json" -f `
                $Sequence, $Scenario, $Member, $Pair
        )
    ) "network-model output boundary or identity is invalid"
} else {
    Assert-Condition ([string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "non-model trial cannot write network-model evidence"
}

$ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 6
$requiredLedger = @(
    "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
    "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
    "candidate_sha", "probe_sha256", "client_sha256", "server_sha256", "support_listener"
)
$ledgerNames = @($ledger.PSObject.Properties.Name)
Assert-Condition (@($requiredLedger | Where-Object { $ledgerNames -cnotcontains $_ }).Count -eq 0) "identity ledger is incomplete"
$clientHash = Get-LowerSha256 $script:ClientPath
$serverHash = Get-LowerSha256 $script:ServerPath
$harnessHash = Get-LowerSha256 $script:HarnessPath
$collectorHash = Get-LowerSha256 $PSCommandPath
Assert-Condition (
    $ledger.schema -eq 1 -and
    $ledger.vm_name -ceq $ExpectedVmName -and
    $ledger.vm_id -ceq $ExpectedVmId -and
    $ledger.checkpoint_name -ceq $ExpectedCheckpointName -and
    $ledger.checkpoint_id -ceq $ExpectedCheckpointId -and
    $ledger.guest_architecture -ceq "AMD64" -and
    $ledger.candidate_sha -ceq $memberSha -and
    $ledger.probe_sha256 -ceq $collectorHash -and
    $ledger.client_sha256 -ceq $clientHash -and
    $ledger.server_sha256 -ceq $serverHash
) "identity ledger does not bind this member and approved guest"
Assert-ExactProperties $ledger.support_listener @("ipv4", "tcp_port", "udp_port", "pid", "owner") "support listener"
Assert-Condition (
    $ledger.support_listener.pid -is [long] -and
    $ledger.support_listener.pid -gt 0 -and
    $ledger.support_listener.pid -le [int]::MaxValue -and
    $ledger.support_listener.owner -is [string] -and
    -not [string]::IsNullOrWhiteSpace($ledger.support_listener.owner)
) "support listener identity is invalid"
$parsedTarget = $null
Assert-Condition (
    [Net.IPAddress]::TryParse([string]$ledger.support_listener.ipv4, [ref]$parsedTarget) -and
    $parsedTarget.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
    -not [Net.IPAddress]::IsLoopback($parsedTarget)
) "support listener target must be a non-loopback IPv4 literal"
$script:TargetAddress = [string]$ledger.support_listener.ipv4
$script:TargetTcpPort = [int]$ledger.support_listener.tcp_port
$script:TargetUdpPort = [int]$ledger.support_listener.udp_port
Assert-Condition (
    $script:TargetTcpPort -ge 1 -and $script:TargetTcpPort -le 65535 -and
    $script:TargetUdpPort -ge 1 -and $script:TargetUdpPort -le 65532
) "support listener ports are invalid"

$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
Assert-Condition (
    $computer.Manufacturer -ceq "Microsoft Corporation" -and
    $computer.Model -ceq "Virtual Machine"
) "collector is restricted to the approved Hyper-V guest"
$rustcVersion = @(& rustc.exe --version 2>&1)
Assert-Condition (
    $LASTEXITCODE -eq 0 -and ($rustcVersion -join "`n") -cmatch '^rustc 1\.97\.1 \('
) "the pinned Rust 1.97.1 toolchain is unavailable or changed"
$cpuRows = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
Assert-Condition ($cpuRows.Count -gt 0) "CPU identity is unavailable"
$power = (& powercfg.exe /getactivescheme 2>&1 | Out-String)
$powerMatch = [regex]::Match($power, '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
Assert-Condition $powerMatch.Success "active power plan identity is unavailable"

$clientRow = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ClientPid")
$serverRow = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ServerPid")
Assert-Condition ($clientRow.Count -eq 1 -and $serverRow.Count -eq 1) "product process identity is unavailable"
Assert-Condition (
    [IO.Path]::GetFullPath($clientRow[0].ExecutablePath).Equals($script:ClientPath, [StringComparison]::OrdinalIgnoreCase) -and
    [IO.Path]::GetFullPath($serverRow[0].ExecutablePath).Equals($script:ServerPath, [StringComparison]::OrdinalIgnoreCase)
) "live process executable does not match the measured binary"
$clientProcess = Get-Process -Id $ClientPid -ErrorAction Stop
$serverProcess = Get-Process -Id $ServerPid -ErrorAction Stop
$script:MetricsPort = $MetricsPort
$script:WorkRoot = [IO.Path]::GetFullPath(
    (Join-Path $outputParent (".tun-trial-{0}" -f [guid]::NewGuid().ToString("N")))
)
$workPrefix = [IO.Path]::GetFullPath($outputParent).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
Assert-Condition (
    $script:WorkRoot.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase)
) "trial work directory escaped the output parent"
New-Item -ItemType Directory -Path $script:WorkRoot | Out-Null
$measurements = [ordered]@{}
$checks = [ordered]@{}
$diagnostics = $null
$modelEvidenceReference = $null
$modelPending = $null
[uint64]$checkedUnits = 0
$startedUtc = [DateTime]::UtcNow.ToString("o")

try {
    $initialMetrics = Get-Metrics $MetricsPort 10
    Assert-Condition (
        (Get-Metric $initialMetrics "ferrum2_tun_session_active") -eq 1 -and
        (Get-Metric $initialMetrics "ferrum2_tun_session_generation") -ge 1
    ) "live TUN session is not active"
    Invoke-Probe
    [void](Wait-CleanDrain $true)
    $trialTrafficBefore = Get-Metrics $MetricsPort 5
    $trialIngressBefore = Get-Metric $trialTrafficBefore "ferrum2_tun_packets_ingress" $true
    $trialEgressBefore = Get-Metric $trialTrafficBefore "ferrum2_tun_packets_egress" $true
    switch ($Scenario) {
        "tcp-single-flow" {
            $cpuBefore = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
            $observation = Invoke-Workload $Scenario 120
            $cpuAfter = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
            $checkedUnits = [uint64]$observation.checked_units
            Assert-Condition ($checkedUnits -ge 67108864) "TCP checked-byte floor was not met"
            [uint64]$cpuPayloadBytes = $observation.measurements.cpu_payload_bytes
            Assert-Condition ($cpuPayloadBytes -ge $checkedUnits) "TCP CPU byte denominator is incomplete"
            [uint64]$cpuDelta = $cpuAfter - $cpuBefore
            Assert-Condition ($cpuDelta -gt 0) "TCP CPU delta is zero"
            $cpuCost = [uint64][Math]::Ceiling(
                ([decimal]$cpuDelta * [decimal]1073741824) / [decimal]$cpuPayloadBytes
            )
            $measurements.throughput = [ordered]@{
                unit = "bytes_per_second"; value = [uint64]$observation.measurements.throughput
            }
            $measurements.cpu_cost = [ordered]@{
                unit = "cpu_nanoseconds_per_gibibyte"; value = $cpuCost
            }
            $checks.single_flow_only = $observation.checks.single_flow_only -eq $true
            $checks.payload_exact = $observation.checks.payload_exact -eq $true
            $checks.no_gso = $observation.checks.no_gso -eq $true
            [void](Wait-CleanDrain $false)
            $checks.clean_drain = $true
        }
        "tcp-256-flow-fairness" {
            $observation = Invoke-Workload $Scenario 90
            $checkedUnits = [uint64]$observation.checked_units
            $measurements.fairness = [ordered]@{
                unit = "jain_index_parts_per_billion"; value = [uint64]$observation.measurements.fairness
            }
            $checks.all_256_flows_nonzero = $observation.checks.all_256_flows_nonzero -eq $true
            $checks.payload_exact = $observation.checks.payload_exact -eq $true
            $checks.no_gso = $observation.checks.no_gso -eq $true
            [void](Wait-CleanDrain $false)
            $checks.clean_drain = $true
        }
        "udp-packets-per-second" {
            $observation = Invoke-Workload $Scenario 60
            $checkedUnits = [uint64]$observation.checked_units
            $measurements.packet_rate = [ordered]@{
                unit = "datagrams_per_second"; value = [uint64]$observation.measurements.packet_rate
            }
            $checks.every_reply_accounted = $observation.checks.every_reply_accounted -eq $true
            $checks.payload_exact = $observation.checks.payload_exact -eq $true
            $checks.no_gso = $observation.checks.no_gso -eq $true
            [void](Wait-CleanDrain $true)
            $checks.clean_drain = $true
        }
        "udp-8192-association-lookup-expiry" {
            $observation = Invoke-Workload $Scenario 1800
            $checkedUnits = [uint64]$observation.checked_units
            $peakMetrics = Get-Metrics $MetricsPort 5
            $activeAssociations = Get-Metric $peakMetrics "ferrum2_tun_udp_associations_active"
            Assert-Condition ($activeAssociations -eq 8192) "product did not retain exactly 8192 associations"
            $expiry = [Diagnostics.Stopwatch]::StartNew()
            [void](Wait-Metric "ferrum2_tun_udp_associations_active" { param($value) $value -eq 0 } 180)
            $expiry.Stop()
            $expiryNanoseconds = [uint64][Math]::Ceiling(
                ([decimal]$expiry.ElapsedTicks * [decimal]1000000000) /
                [decimal][Diagnostics.Stopwatch]::Frequency
            )
            Assert-Condition ($expiryNanoseconds -gt 0) "association expiry duration is zero"
            $measurements.lookup_rate = [ordered]@{
                unit = "lookups_per_second"; value = [uint64]$observation.measurements.lookup_rate
            }
            $measurements.expiry_cost = [ordered]@{
                unit = "nanoseconds_per_8192_expirations"; value = $expiryNanoseconds
            }
            $checks.exactly_8192_associations = $observation.checks.exactly_8192_associations -eq $true
            $checks.all_lookups_hit = $observation.checks.all_lookups_hit -eq $true
            $checks.all_associations_expired = $true
            [void](Wait-CleanDrain $true)
            $checks.clean_drain = $true
        }
        "fragment-reassembly-throughput" {
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
        }
        "idle-cpu-wakeup" {
            Start-Sleep -Seconds 10
            $cpuBefore = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
            $switchBefore = Get-ContextSwitches $ClientPid
            $trafficBefore = Get-Metrics $MetricsPort 5
            $ingressBefore = Get-Metric $trafficBefore "ferrum2_tun_packets_ingress" $true
            $egressBefore = Get-Metric $trafficBefore "ferrum2_tun_packets_egress" $true
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
            Assert-Condition (
                (Get-Metric $trafficAfter "ferrum2_tun_packets_ingress" $true) -eq $ingressBefore -and
                (Get-Metric $trafficAfter "ferrum2_tun_packets_egress" $true) -eq $egressBefore
            ) "idle window contained TUN test traffic"
            Assert-Condition ($cpuAfter -gt $cpuBefore -and $switchAfter -gt $switchBefore) "idle resource counters did not advance"
            $measurements.cpu_idle_cost = [ordered]@{
                unit = "cpu_nanoseconds_per_second"; value = [uint64][Math]::Ceiling(($cpuAfter - $cpuBefore) / 60.0)
            }
            $measurements.wakeups = [ordered]@{
                unit = "process_context_switches_per_second"; value = [uint64][Math]::Ceiling(($switchAfter - $switchBefore) / 60.0)
            }
            $checks.session_active_throughout = $true
            $checks.zero_test_traffic = $true
            $checks.no_busy_poll_fallback = $true
            [void](Wait-CleanDrain $true)
            $checks.clean_drain = $true
        }
        "wintun-ring-full-drop-rate" {
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
            Assert-Condition ($drops -gt 0) "real workload did not trigger Wintun ring-full"
            Assert-Condition ($pendingResponsePeak -eq 1) `
                "ring-full workload did not observe the bounded pending UDP response depth"
            Assert-Condition ($pendingAfter -eq 0) `
                "ring-full pending UDP response did not drain"
            Assert-Condition ($responseAttempts -gt 0 -and $responseAttempts -le $attempts) "ring-full response accounting exceeds the request denominator"
            $lifecycleAfter = Get-NetworkLifecycleMetrics $after
            Assert-NetworkLifecycleMetricsEqual $lifecycleBefore $lifecycleAfter `
                "ring-full triggered a network lifecycle transition"
            $checkedUnits = $drops
            $measurements.drop_rate = [ordered]@{
                unit = "dropped_packets_per_million_responses"
                value = [uint64][Math]::Ceiling(([decimal]$drops * 1000000) / [decimal]$responseAttempts)
            }
            $measurements.pending_response_peak = [ordered]@{
                unit = "pending_udp_responses"
                value = $pendingResponsePeak
            }
            $checks.ring_full_counter_increased = $true
            $checks.drop_rate_denominator_bound = $true
            $checks.no_ring_full_retry = $true
            $checks.pending_response_peak_observed = $true
            $checks.pending_response_baseline_and_drain = $true
            $checks.no_network_reset_or_full_rebuild = $true
        }
        "udp-route-once" {
            Start-Sleep -Seconds 5
            $physical = Get-PhysicalDefaultRoute
            $physicalRoute = $physical.Route
            $physicalRouteIdentity = [ordered]@{
                interface_index = [uint32]$physicalRoute.InterfaceIndex
                interface_guid = ([Guid]$physical.Adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
                interface_name = [string]$physical.Adapter.Name
                destination_prefix = [string]$physicalRoute.DestinationPrefix
                next_hop = [string]$physicalRoute.NextHop
                route_metric = [uint32]$physicalRoute.RouteMetric
            }
            $physicalJournal = Join-Path $script:WorkRoot "physical-route-journal.json"
            [IO.File]::WriteAllText(
                $physicalJournal,
                (($physicalRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                $script:Utf8NoBom
            )
            [uint64]$mutatedRouteMetric = if ($physicalRouteIdentity.route_metric -lt 4294967295) {
                [uint64]$physicalRouteIdentity.route_metric + 1
            } else {
                [uint64]$physicalRouteIdentity.route_metric - 1
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
                    Assert-Condition (
                        $sourceSlot -lt 64 -and $seenSources.Add($sourceSlot) -and
                        (@($association.target_slots) -join "|") -ceq "0|1|2|3" -and
                        [uint64]$association.first_target_slot -eq (
                            if (($sourceSlot % 2) -eq 0) { 0 } else { 1 }
                        ) -and
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

                $currentRoutes = @(
                    Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                        -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                        -PolicyStore ActiveStore -ErrorAction Stop |
                        Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
                )
                Assert-Condition ($currentRoutes.Count -eq 1) `
                    "route-once physical route mutation target is not exact"
                [uint64]$nextMetric = if ($generationOrdinal -eq 1) {
                    $mutatedRouteMetric
                } else {
                    [uint64]$physicalRouteIdentity.route_metric
                }
                Set-NetRoute -InputObject $currentRoutes[0] -RouteMetric $nextMetric -ErrorAction Stop
                $transition = Wait-LifecycleTransition "reset_network" $lifecycleAfter 30
                Assert-Condition (
                    (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
                ) "route-once ResetNetwork retained an old association"
            }
            $physicalReadback = @(
                Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                    -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                    -PolicyStore ActiveStore -ErrorAction Stop |
                    Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
            )
            Assert-Condition (
                $physicalReadback.Count -eq 1 -and
                [uint32]$physicalReadback[0].RouteMetric -eq [uint32]$physicalRouteIdentity.route_metric
            ) "route-once physical route metric baseline was not restored"
            Remove-Item -LiteralPath $physicalJournal -Force
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
                schema_version = 3
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
        }
        "network-lifecycle" {
            Start-Sleep -Seconds 5
            $physical = Get-PhysicalDefaultRoute
            $physicalRoute = $physical.Route
            $physicalRouteIdentity = [ordered]@{
                interface_index = [uint32]$physicalRoute.InterfaceIndex
                interface_guid = ([Guid]$physical.Adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
                interface_name = [string]$physical.Adapter.Name
                destination_prefix = [string]$physicalRoute.DestinationPrefix
                next_hop = [string]$physicalRoute.NextHop
                route_metric = [uint32]$physicalRoute.RouteMetric
            }
            $physicalJournal = Join-Path $script:WorkRoot "physical-route-journal.json"
            [IO.File]::WriteAllText(
                $physicalJournal,
                (($physicalRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                $script:Utf8NoBom
            )
            [uint64[]]$routeMetrics = if ($physicalRouteIdentity.route_metric -le 4294967293) {
                @(
                    [uint64]$physicalRouteIdentity.route_metric + 1,
                    [uint64]$physicalRouteIdentity.route_metric + 2,
                    [uint64]$physicalRouteIdentity.route_metric
                )
            } elseif ($physicalRouteIdentity.route_metric -ge 2) {
                @(
                    [uint64]$physicalRouteIdentity.route_metric - 1,
                    [uint64]$physicalRouteIdentity.route_metric - 2,
                    [uint64]$physicalRouteIdentity.route_metric
                )
            } else {
                throw "physical route metric has no bounded three-state mutation"
            }
            $initial = Get-Metrics $MetricsPort 5
            $lifecycleMetrics = Get-NetworkLifecycleMetrics $initial
            Assert-Condition (
                [uint64]$lifecycleMetrics.network_generation -ge 1 -and
                [uint64]$lifecycleMetrics.network_generation -eq
                    [uint64]$lifecycleMetrics.session_generation
            ) "published network/session generations are unavailable or inconsistent"
            $managedIdentity = Get-ManagedIdentity
            $baselineResources = Get-LifecycleResources $initial
            Assert-Condition (
                $baselineResources.udp_associations_active -eq 0 -and
                $baselineResources.managed_adapters_active -eq 1
            ) "network lifecycle resource baseline is not quiescent"
            $cycles = [Collections.Generic.List[object]]::new()
            $resetLatencies = [Collections.Generic.List[uint64]]::new()
            $rebuildLatencies = [Collections.Generic.List[uint64]]::new()
            $routeMutationIndex = 0
            Invoke-Probe

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
                    $interfaceJournal = Join-Path $script:WorkRoot "physical-interface-journal.json"
                    [IO.File]::WriteAllText(
                        $interfaceJournal,
                        (($physicalRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                        $script:Utf8NoBom
                    )
                    Disable-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Milliseconds 100
                    Enable-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -Confirm:$false -ErrorAction Stop
                } else {
                    $currentRoutes = @(
                        Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                            -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                            -PolicyStore ActiveStore -ErrorAction Stop |
                            Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
                    )
                    Assert-Condition ($currentRoutes.Count -eq 1) `
                        "physical route mutation target is not exact"
                    $nextMetric = $routeMetrics[$routeMutationIndex % $routeMetrics.Count]
                    $routeMutationIndex++
                    Set-NetRoute -InputObject $currentRoutes[0] -RouteMetric $nextMetric `
                        -ErrorAction Stop
                }
                $transition = Wait-LifecycleTransition "reset_network" $lifecycleBefore 30
                $identityAfter = Get-ManagedIdentity
                $resourcesAfter = Get-LifecycleResources $transition.Metrics
                Assert-Condition (
                    (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
                    (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
                ) "ResetNetwork retained a connection"
                Invoke-Probe
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
                    $currentAdapter = Get-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -IncludeHidden -ErrorAction Stop
                    Assert-Condition (
                        [string]$currentAdapter.Status -ceq "Up" -and
                        ([Guid]$currentAdapter.InterfaceGuid).ToString("D").ToLowerInvariant() `
                            -ceq $physicalRouteIdentity.interface_guid
                    ) "physical interface switch did not restore its identity"
                    Remove-Item -LiteralPath $interfaceJournal -Force
                }
            }
            Assert-Condition (
                $routeMutationIndex -eq 999 -and
                $routeMetrics[($routeMutationIndex - 1) % $routeMetrics.Count] -eq
                    $physicalRouteIdentity.route_metric
            ) "physical route metric schedule did not end at its baseline"
            $physicalReadback = @(
                Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                    -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                    -PolicyStore ActiveStore -ErrorAction Stop |
                    Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
            )
            Assert-Condition (
                $physicalReadback.Count -eq 1 -and
                [uint32]$physicalReadback[0].RouteMetric -eq
                    [uint32]$physicalRouteIdentity.route_metric
            ) "physical route metric baseline was not restored in-band"

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
                $resourcesAfter = Get-LifecycleResources $transition.Metrics
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
                schema_version = 3
                workload = "network-lifecycle"
                identity = $rawIdentity
                baseline_resources = $baselineResources
                cycles = $cycles.ToArray()
                interface_resolver = [ordered]@{
                    probes = [uint64]32
                    resolutions = $resolutions
                    cache_hits = $cacheHits
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
            $checks.generation_advanced_once_per_cycle = $true
            $checks.managed_identity_preserved_across_resets = $true
            $checks.damage_only_full_rebuild = $true
            $checks.reset_and_full_rebuild_metrics_are_exact = $true
            $checks.resource_growth_zero_after_1000_resets = (
                $resetFinal.process_handles -le $baselineResources.process_handles -and
                $resetFinal.process_threads -le $baselineResources.process_threads -and
                $resetFinal.udp_associations_active -le $baselineResources.udp_associations_active -and
                $resetFinal.managed_adapters_active -le $baselineResources.managed_adapters_active
            )
            $checks.tcp_and_udp_recovered_after_interface_switch = $true
            $checks.interface_resolver_cache_hit_observed = $true
            $checks.network_model_evidence_bound = $true
            $checks.clean_drain = $true
        }
    }

    if ($Scenario -cne "idle-cpu-wakeup") {
        $trialTrafficAfter = Get-Metrics $MetricsPort 5
        Assert-Condition (
            (Get-Metric $trialTrafficAfter "ferrum2_tun_packets_ingress" $true) -gt $trialIngressBefore -and
            (Get-Metric $trialTrafficAfter "ferrum2_tun_packets_egress" $true) -gt $trialEgressBefore
        ) "workload did not traverse both directions of the live TUN session"
        $checks.tun_path_observed = $true
    }

    Assert-Condition ($checkedUnits -gt 0) "trial checked-unit count is zero"
    Assert-Condition (@($checks.Values | Where-Object { $_ -ne $true }).Count -eq 0) "one or more trial correctness checks failed"
    $environment = [ordered]@{
        runner_os = "Windows"
        runner_arch = "X64"
        runner_label = $ExpectedRunnerLabel
        vm_name = $ExpectedVmName
        vm_id = $ExpectedVmId
        checkpoint_name = $ExpectedCheckpointName
        checkpoint_id = $ExpectedCheckpointId
        rust_toolchain = "1.97.1"
        cargo_profile = "profiling"
        pair_schedule = "alternating-parent-candidate"
        guest_build = [string]$ledger.guest_build
        cpu_model = (@($cpuRows | ForEach-Object { $_.Name.Trim() }) -join " | ")
        cpu_count = [int]$computer.NumberOfLogicalProcessors
        memory_bytes = [uint64]$computer.TotalPhysicalMemory
        power_plan_guid = $powerMatch.Value.ToLowerInvariant()
    }
    $finishedUtc = [DateTime]::UtcNow.ToString("o")
    $document = [ordered]@{
        schema_version = 3
        kind = "windows_tun_performance_trial"
        selection = "windows-tun-m17"
        run_kind = $RunKind
        scenario = $Scenario
        member = $Member
        pair = $Pair
        order = $Order
        sequence = $Sequence
        started_utc = $startedUtc
        finished_utc = $finishedUtc
        parent_sha = $ParentSha
        candidate_sha = $CandidateSha
        sha = $memberSha
        tree = $Tree
        client_sha256 = $clientHash
        server_sha256 = $serverHash
        harness_sha256 = $harnessHash
        recipe_sha256 = $RecipeSha256
        environment = $environment
        measurements = $measurements
        correctness = [ordered]@{
            status = "PASS"
            checked_unit = switch ($Scenario) {
                "tcp-single-flow" { "payload_bytes" }
                "tcp-256-flow-fairness" { "completed_flows" }
                "udp-packets-per-second" { "echoed_datagrams" }
                "udp-8192-association-lookup-expiry" { "association_lookups" }
                "fragment-reassembly-throughput" { "reassembled_datagrams" }
                "idle-cpu-wakeup" { "idle_samples" }
                "wintun-ring-full-drop-rate" { "ring_full_events" }
                "udp-route-once" { "echoed_multi_target_datagrams" }
                "network-lifecycle" { "successful_reset_network_cycles" }
            }
            checked_units = $checkedUnits
            checks = $checks
        }
        diagnostics = $diagnostics
        network_model_evidence = $modelEvidenceReference
        status = "PASS"
    }
    $temporary = "$outputPath.pending"
    Assert-Condition (-not (Test-Path -LiteralPath $temporary)) "trial pending output baseline is not absent"
    [IO.File]::WriteAllText(
        $temporary,
        (($document | ConvertTo-Json -Depth 10) + "`n"),
        $script:Utf8NoBom
    )
    Move-Item -LiteralPath $temporary -Destination $outputPath -ErrorAction Stop
    Write-Output "windows_tun_trial status=PASS scenario=$Scenario member=$Member pair=$Pair order=$Order sequence=$Sequence output=$outputPath"
} finally {
    if (Test-Path -LiteralPath $script:WorkRoot -PathType Container) {
        $resolvedWorkRoot = (Resolve-Path -LiteralPath $script:WorkRoot).Path
        Assert-Condition (
            $resolvedWorkRoot.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            -not $resolvedWorkRoot.Equals([IO.Path]::GetFullPath($outputParent), [StringComparison]::OrdinalIgnoreCase)
        ) "refusing to remove an out-of-scope trial work directory"
        $interfaceJournalPath = Join-Path $script:WorkRoot "physical-interface-journal.json"
        if (Test-Path -LiteralPath $interfaceJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $interfaceJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $adapter = Get-NetAdapter -Name $identity.interface_name -IncludeHidden `
                -ErrorAction Stop
            Assert-Condition (
                ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
                    [string]$identity.interface_guid
            ) "refusing to enable a changed physical interface identity"
            if ([string]$adapter.Status -cne "Up") {
                Enable-NetAdapter -Name $identity.interface_name -Confirm:$false -ErrorAction Stop
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $adapter = Get-NetAdapter -Name $identity.interface_name -IncludeHidden `
                    -ErrorAction Stop
                if ([string]$adapter.Status -ceq "Up") { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ([string]$adapter.Status -ceq "Up") `
                "physical interface did not return Up during journal recovery"
        }
        $physicalJournalPath = Join-Path $script:WorkRoot "physical-route-journal.json"
        if (Test-Path -LiteralPath $physicalJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $physicalJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $present = @(
                    Get-NetRoute -InterfaceIndex $identity.interface_index `
                        -DestinationPrefix $identity.destination_prefix -PolicyStore ActiveStore `
                        -ErrorAction SilentlyContinue |
                        Where-Object { $_.NextHop -ceq [string]$identity.next_hop }
                )
                if ($present.Count -eq 1) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ($present.Count -eq 1) `
                "physical route restore target is not exact"
            if ([uint32]$present[0].RouteMetric -ne [uint32]$identity.route_metric) {
                Set-NetRoute -InputObject $present[0] -RouteMetric $identity.route_metric `
                    -ErrorAction Stop
            }
        }
        $managedJournalPath = Join-Path $script:WorkRoot "managed-route-journal.json"
        if (Test-Path -LiteralPath $managedJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $managedJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $managedRows = @(
                    Get-NetAdapter -Name $AdapterName -IncludeHidden `
                        -ErrorAction SilentlyContinue
                )
                if ($managedRows.Count -eq 1) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ($managedRows.Count -eq 1) `
                "managed adapter did not return during journal recovery"
            $managed = $managedRows[0]
            $present = @(
                Get-NetRoute -InterfaceIndex $managed.ifIndex `
                    -DestinationPrefix $identity.destination_prefix -PolicyStore ActiveStore `
                    -ErrorAction SilentlyContinue
            )
            Assert-Condition ($present.Count -le 1) `
                "managed route recovery target is ambiguous"
            if ($present.Count -eq 0) {
                New-NetRoute -InterfaceIndex $managed.ifIndex `
                    -DestinationPrefix $identity.destination_prefix `
                    -NextHop $identity.next_hop -RouteMetric $identity.route_metric `
                    -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            }
        }
        Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction Stop
    }
    if ($null -ne $modelPending -and (Test-Path -LiteralPath $modelPending -PathType Leaf)) {
        Remove-Item -LiteralPath $modelPending -Force -ErrorAction Stop
    }
    if ($null -ne $modelOutputPath -and
        (Test-Path -LiteralPath $modelOutputPath -PathType Leaf) -and
        -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        Remove-Item -LiteralPath $modelOutputPath -Force -ErrorAction Stop
    }
}
