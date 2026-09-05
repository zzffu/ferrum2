Set-StrictMode -Version Latest

function Get-Ferrum2FailureCounterTotal {
    param([string]$Metrics)
    # These dimensions are the observability emitter's closed public result families.
    $policies = @{
        ferrum2_network_reset_total = @{
            labels = @{ reason = @('network_change', 'retry'); result = @('started', 'succeeded', 'failed') }
            failures = @('failed')
        }
        ferrum2_network_full_rebuild_total = @{
            labels = @{
                reason = @('adapter_damage', 'session_damage', 'address_damage', 'route_damage',
                    'dns_damage', 'strict_route_damage', 'ownership_ledger_damage')
                result = @('started', 'succeeded', 'failed')
            }
            failures = @('failed')
        }
        ferrum2_ruleset_load_total = @{
            labels = @{ result = @('success', 'failure', 'unchanged') }; failures = @('failure')
        }
        ferrum2_ruleset_refresh_total = @{
            labels = @{ result = @('success', 'failure', 'unchanged') }; failures = @('failure')
        }
        ferrum2_dns_resolve_total = @{
            labels = @{
                resolver = @('system', 'configured')
                purpose = @('application', 'fixed_endpoint', 'ruleset_download')
                result = @('success', 'failure')
            }
            failures = @('failure')
        }
        ferrum2_tun_strict_route_filter_install_total = @{
            labels = @{ result = @('success', 'failure') }; failures = @('failure')
        }
        ferrum2_outbound_interface_resolution_total = @{
            labels = @{
                source = @('outbound_explicit', 'auto_detected', 'route_default', 'system_best_route')
                result = @('success', 'failure')
            }
            failures = @('failure')
        }
        ferrum2_tun_udp_association_route_total = @{
            labels = @{ result = @('success', 'rejected', 'failure', 'stale_generation') }
            failures = @('rejected', 'failure', 'stale_generation')
        }
    }
    [double]$sum = 0
    foreach ($line in ($Metrics -split "`n")) {
        if ($line.StartsWith('#') -or [string]::IsNullOrWhiteSpace($line)) { continue }
        # Preserve the declared exclusions for out-of-workload Windows probing packets.
        if ($line -cmatch '^ferrum2_tun_packets_rejected_total\{reason="(?:family_disabled|invalid_destination)"\}\s+') {
            continue
        }
        if ($line -cnotmatch '^([A-Za-z_:][A-Za-z0-9_:]*)') { continue }
        $name = $Matches[1]
        $hasResultPolicy = $name -cin @($policies.Keys)
        if ($line -cnotmatch '^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9]+(?:\.[0-9]+)?)\s*$') {
            if ($hasResultPolicy) { throw 'closed failure metric sample is malformed' }
            continue
        }
        $labelText = $Matches[2]
        $value = [double]::Parse($Matches[3], [Globalization.CultureInfo]::InvariantCulture)
        if (-not [double]::IsFinite($value)) { throw 'failure metric value is not finite' }
        $counted = $name -cmatch '(drop|error|reject|failure|failed)'
        if ($hasResultPolicy) {
            $policy = $policies[$name]
            $labels = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
            foreach ($label in ($labelText -split ',')) {
                if ($label -cnotmatch '^([a-z_][a-z0-9_]*)="([a-z_][a-z0-9_]*)"$') {
                    throw 'closed failure metric labels are malformed'
                }
                $key = $Matches[1]; $encoded = $Matches[2]
                if ($key -cnotin @($policy.labels.Keys) -or
                    $encoded -cnotin $policy.labels[$key] -or -not $labels.TryAdd($key, $encoded)) {
                    throw 'closed failure metric label identity is invalid'
                }
            }
            if ($labels.Count -ne $policy.labels.Count) { throw 'closed failure metric labels are incomplete' }
            $counted = $counted -or $labels['result'] -cin $policy.failures
        }
        # One inclusion decision per sample, even if both classifiers select it.
        if ($counted) { $sum += $value }
    }
    return $sum
}

function Get-Ferrum2MeasurementInteger {
    param([object]$Value, [string]$Name, [switch]$AllowZero)
    if ($Value -isnot [int] -and $Value -isnot [long] -and
        $Value -isnot [uint64] -and $Value -isnot [bigint]) {
        throw "$Name must be an integer"
    }
    [bigint]$number = $Value
    if ($number -lt 0 -or $number -gt [uint64]::MaxValue -or
        (-not $AllowZero -and $number -eq 0)) {
        throw "$Name is outside its uint64 contract"
    }
    return $number
}

function Assert-Ferrum2TrialMeasurements {
    param(
        [Parameter(Mandatory = $true)][object]$Measurements,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][object]$CheckedUnits,
        [Parameter(Mandatory = $true)][object]$ActiveSeconds,
        [Parameter(Mandatory = $true)][double]$CpuSampleSeconds
    )
    $windowFields = @("active_elapsed_nanoseconds", "tail_checked_units")
    $latencyFields = @("p50_nanoseconds", "p95_nanoseconds", "p99_nanoseconds", "latency_samples")
    $minimum = 0; $alignment = 1; $tailLimit = 0; $rateField = $null; $payload = 1
    switch -CaseSensitive ($Scenario) {
        "tcp-single-flow" {
            $fields = $windowFields + @("throughput", "cpu_payload_bytes", "io_completions")
            $minimum = 67108864; $alignment = 65536; $tailLimit = 65536; $rateField = "throughput"
        }
        "tcp-request-1k-p99" {
            $fields = $latencyFields + $windowFields + @("io_completions")
            $minimum = 1024; $tailLimit = 1
        }
        "tcp-256-flow-fairness" {
            $fields = $windowFields + @("fairness", "aggregate_throughput", "io_completions")
            $minimum = 4194304; $alignment = 16384; $tailLimit = 4194304
            $rateField = "aggregate_throughput"
        }
        "udp-packets-per-second" {
            $fields = $latencyFields + $windowFields + @("packet_rate", "io_completions")
            $minimum = 4096; $tailLimit = 1; $rateField = "packet_rate"
        }
        "fragment-reassembly-throughput" {
            $fields = $windowFields + @("reassembly_rate", "io_completions")
            $minimum = 4096; $alignment = 4; $tailLimit = 4
            $rateField = "reassembly_rate"; $payload = 1440
        }
        default { throw "workload scenario is invalid" }
    }
    if ((@($Measurements.PSObject.Properties.Name | Sort-Object) -join "|") -cne
        (@($fields | Sort-Object) -join "|")) {
        throw "workload measurement closure is invalid"
    }
    $values = @{}
    foreach ($field in $fields) {
        $values[$field] = Get-Ferrum2MeasurementInteger -Value $Measurements.$field `
            -Name $field -AllowZero:($field -ceq "tail_checked_units")
    }
    $checked = Get-Ferrum2MeasurementInteger -Value $CheckedUnits -Name "checked_units"
    if ($checked -lt $minimum -or ($checked % $alignment) -ne 0) {
        throw "workload checked work violates coverage or alignment"
    }
    if ($Scenario -ceq "fragment-reassembly-throughput") {
        if ($values.io_completions -lt $checked * 2 -or ($values.io_completions % 2) -ne 0) {
            throw "fragment I/O completions omit checked work"
        }
    } elseif ($values.io_completions -ne [bigint]::Divide($checked, $alignment) * 2) {
        throw "workload I/O completions contradict checked work"
    }
    if ($Scenario -ceq "tcp-single-flow") {
        if ($values.cpu_payload_bytes -lt $checked -or ($values.cpu_payload_bytes % $alignment) -ne 0) {
            throw "TCP total payload does not cover checked work"
        }
    }
    $nominal = (Get-Ferrum2MeasurementInteger -Value $ActiveSeconds -Name "active_seconds") * 1000000000
    $elapsed = $values.active_elapsed_nanoseconds
    $tail = $values.tail_checked_units
    if ($elapsed -lt $nominal -or $tail -gt $checked -or $tail -gt $tailLimit -or
        ($tail % $alignment) -ne 0 -or (($tail -eq 0) -ne ($elapsed -eq $nominal)) -or
        -not [double]::IsFinite($CpuSampleSeconds) -or
        ($CpuSampleSeconds * 1000000000.0) -lt [double]$elapsed) {
        throw "workload active window or tail accounting is inconsistent"
    }
    if ($null -ne $rateField) {
        [bigint]$units = $checked * $payload
        if ($units -gt [uint64]::MaxValue) { throw "workload payload count overflow" }
        $expectedRate = [bigint]::Divide(($units * 1000000000), $elapsed)
        if ($expectedRate -lt 1) { $expectedRate = [bigint]1 }
        if ($values[$rateField] -ne $expectedRate) {
            throw "workload rate contradicts checked work and actual elapsed time"
        }
    }
    if ($Scenario -ceq "tcp-256-flow-fairness" -and
        ($values.fairness -lt 3906250 -or $values.fairness -gt 1000000000)) {
        throw "workload fairness is outside its Jain index range"
    }
    if ($Scenario -in @("tcp-request-1k-p99", "udp-packets-per-second")) {
        $expectedSamples = if ($checked -lt 2000000) { $checked } else { [bigint]2000000 }
        if ($values.p50_nanoseconds -gt $values.p95_nanoseconds -or
            $values.p95_nanoseconds -gt $values.p99_nanoseconds -or
            $values.latency_samples -ne $expectedSamples) {
            throw "workload latency percentiles or sample count are invalid"
        }
    }
}

function Invoke-Ferrum2HostTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Trial,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][string]$Harness,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][object]$Support
    )
    $trialRoot = Join-Path $Context.evidence_directory ("trials\{0:D3}" -f $Trial.sequence)
    New-Item -ItemType Directory -Path $trialRoot -ErrorAction Stop | Out-Null
    $runtime = $null
    $workloadProcess = $null
    $succeeded = $false
    $failurePhase = "product-startup"
    try {
        $runtime = Start-Ferrum2ProductTrial -Context $Context -Member $Member -Network $Network `
            -Loopback $Loopback -Sequence $Trial.sequence -Topology $Trial.topology
        $serverPresent = $null -ne $runtime.server
        $metricsBefore = Get-Ferrum2Metrics -Port $runtime.client_metrics_port
        $serverMetricsBefore = if ($serverPresent) {
            Get-Ferrum2Metrics -Port $runtime.server_metrics_port
        } else { $null }
        Write-NewUtf8File -Path (Join-Path $trialRoot "client-metrics-before.txt") `
            -Text $metricsBefore
        if ($serverPresent) {
            Write-NewUtf8File -Path (Join-Path $trialRoot "server-metrics-before.txt") `
                -Text $serverMetricsBefore
        }
        $failurePhase = "workload-startup"
        $output = Join-Path $trialRoot "workload.json"
        $activeReadyMarker = [IO.Path]::ChangeExtension($output, "active-ready")
        $activeCompleteMarker = [IO.Path]::ChangeExtension($output, "active-complete")
        $arguments = "windows-tun-workload --scenario $($Trial.scenario) " +
            "--target-ip $($Network.support_address) --tcp-port $($Support.tcp_port) " +
            "--udp-port $($Support.udp_port) --warmup-seconds $($Trial.warmup_seconds) " +
            "--active-seconds $($Trial.active_seconds) --output `"$output`""
        $workloadLogPrefix = "trial-$($Trial.sequence)-workload"
        $workloadProcess = Start-Ferrum2OwnedNativeProcess -Context $Context `
            -Application $Harness -Arguments $arguments `
            -WorkingDirectory (Split-Path -Parent $Harness) -LogPrefix $workloadLogPrefix `
            -Purpose $workloadLogPrefix
        try {
            $failurePhase = "warmup-readiness"
            Wait-Ferrum2Text -Path $activeReadyMarker -Pattern '^ready\r?\n?$' `
                -TimeoutSeconds ([int]$Trial.warmup_seconds + 30)
            $clientCpuBefore = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
            $serverCpuBefore = if ($serverPresent) {
                Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
            } else { $null }
            $cpuSampleStopwatch = [Diagnostics.Stopwatch]::StartNew()
            Remove-Item -LiteralPath $activeReadyMarker -Force -ErrorAction Stop
            $failurePhase = "active-completion"
            Wait-Ferrum2Text -Path $activeCompleteMarker -Pattern '^complete\r?\n?$' `
                -TimeoutSeconds ([int]$Trial.active_seconds + 60)
            $clientCpuAfter = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
            $serverCpuAfter = if ($serverPresent) {
                Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
            } else { $null }
            $clientPeakWorkingSet =
                Get-Ferrum2ProcessPeakWorkingSetBytes -ProcessId $runtime.client.pid
            $serverPeakWorkingSet = if ($serverPresent) {
                Get-Ferrum2ProcessPeakWorkingSetBytes -ProcessId $runtime.server.pid
            } else { $null }
            $cpuSampleStopwatch.Stop()
            Remove-Item -LiteralPath $activeCompleteMarker -Force -ErrorAction Stop
        } catch {
            $markerFailure = $_
            Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $workloadProcess.pid
            try {
                [void](Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
                    -Process $workloadProcess -LogPrefix $workloadLogPrefix)
            } catch { Write-Warning "workload diagnostic export failed" }
            throw $markerFailure
        }
        $failurePhase = "workload-result"
        [void](Complete-Ferrum2OwnedCommand -Context $Context -Process $workloadProcess `
            -LogPrefix $workloadLogPrefix -TimeoutSeconds 60)
        $metricsAfter = Get-Ferrum2Metrics -Port $runtime.client_metrics_port
        $serverMetricsAfter = if ($serverPresent) {
            Get-Ferrum2Metrics -Port $runtime.server_metrics_port
        } else { $null }
        Write-NewUtf8File -Path (Join-Path $trialRoot "client-metrics-after.txt") `
            -Text $metricsAfter
        if ($serverPresent) {
            Write-NewUtf8File -Path (Join-Path $trialRoot "server-metrics-after.txt") `
                -Text $serverMetricsAfter
        }
        $workloadItem = Get-Item -LiteralPath $output -Force -ErrorAction Stop
        if ($workloadItem.Length -le 0 -or $workloadItem.Length -gt 1MB) {
            throw "workload observation size is invalid"
        }
        $workload = Get-Content -LiteralPath $output -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 20
        if (($workload.schema_version -isnot [int] -and $workload.schema_version -isnot [long]) -or
            $workload.schema_version -ne 5 -or $workload.kind -cne "windows_tun_workload" -or
            $workload.status -cne "PASS" -or [string]$workload.scenario -cne [string]$Trial.scenario -or
            $workload.window.warmup_seconds -ne $Trial.warmup_seconds -or
            $workload.window.active_seconds -ne $Trial.active_seconds) {
            throw "workload observation identity is invalid"
        }
        $measurements = $workload.observation.measurements
        $metricValue = [double]$measurements.([string]$Trial.metric)
        if (-not [double]::IsFinite($metricValue) -or $metricValue -le 0) {
            throw "workload primary metric is invalid"
        }
        [uint64]$ioCompletions = $measurements.io_completions
        if ($ioCompletions -eq 0) { throw "workload I/O completion count is invalid" }
        $p99Property = $measurements.PSObject.Properties["p99_nanoseconds"]
        $p99Nanoseconds = if ($null -ne $p99Property) {
            [uint64]$p99Property.Value
        } else { $null }
        if ($null -ne $p99Nanoseconds -and $p99Nanoseconds -eq 0) {
            throw "workload p99 latency is invalid"
        }
        if ($null -ne $p99Nanoseconds) {
            [uint64]$p50 = $measurements.p50_nanoseconds
            [uint64]$p95 = $measurements.p95_nanoseconds
            [uint64]$samples = $measurements.latency_samples
            if ($p50 -eq 0 -or $p50 -gt $p95 -or $p95 -gt $p99Nanoseconds -or
                $samples -ne [Math]::Min([uint64]$workload.observation.checked_units, 2000000UL)) {
                throw "workload latency percentiles or sample count are invalid"
            }
        }
        $workloadChecks = @($workload.observation.checks.PSObject.Properties)
        if ($workloadChecks.Count -eq 0 -or
            @($workloadChecks | Where-Object { $_.Value -ne $true }).Count -ne 0) {
            throw "workload correctness checks did not all pass"
        }
        Assert-Ferrum2TrialMeasurements -Measurements $measurements -Scenario $Trial.scenario `
            -CheckedUnits $workload.observation.checked_units -ActiveSeconds $Trial.active_seconds `
            -CpuSampleSeconds $cpuSampleStopwatch.Elapsed.TotalSeconds
        [uint64]$checkedUnits = $workload.observation.checked_units
        [double]$cpuSampleSeconds = $cpuSampleStopwatch.Elapsed.TotalSeconds
        if (-not [double]::IsFinite($cpuSampleSeconds) -or $cpuSampleSeconds -le 0) {
            throw "trial CPU sample window is invalid"
        }
        [double]$clientCpuPercent =
            (($clientCpuAfter - $clientCpuBefore) / ($cpuSampleSeconds * 1000.0)) * 100.0
        $serverCpuPercent = if ($serverPresent) {
            (($serverCpuAfter - $serverCpuBefore) / ($cpuSampleSeconds * 1000.0)) * 100.0
        } else { $null }
        [double]$clientFailureDelta =
            (Get-Ferrum2FailureCounterTotal $metricsAfter) -
                (Get-Ferrum2FailureCounterTotal $metricsBefore)
        $serverFailureDelta = if ($serverPresent) {
            (Get-Ferrum2FailureCounterTotal $serverMetricsAfter) -
                (Get-Ferrum2FailureCounterTotal $serverMetricsBefore)
        } else { $null }
        if (-not [double]::IsFinite($clientCpuPercent) -or $clientCpuPercent -lt 0 -or
            ($serverPresent -and
                (-not [double]::IsFinite([double]$serverCpuPercent) -or
                    [double]$serverCpuPercent -lt 0)) -or
            $clientFailureDelta -ne 0 -or
            ($serverPresent -and [double]$serverFailureDelta -ne 0)) {
            throw "trial CPU or failure-counter evidence is invalid"
        }
        $observation = [pscustomobject][ordered]@{
            schema_version = 4
            kind = "ferrum2.windows-tun.host-performance-trial"
            run_id = $Context.run_id
            performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
            sequence = $Trial.sequence
            pair = $Trial.pair
            order = $Trial.order
            topology = $Trial.topology
            scenario = $Trial.scenario
            member = $Trial.member
            commit_sha = $Trial.commit_sha
            metric = $Trial.metric
            unit = $Trial.unit
            direction = $Trial.direction
            value = $metricValue
            warmup_seconds = $Trial.warmup_seconds
            active_seconds = $Trial.active_seconds
            cpu_sample_seconds = $cpuSampleSeconds
            io_completions = $ioCompletions
            p99_nanoseconds = $p99Nanoseconds
            client_cpu_percent = $clientCpuPercent
            server_present = $serverPresent
            server_cpu_percent = $serverCpuPercent
            client_peak_working_set_bytes = $clientPeakWorkingSet
            server_peak_working_set_bytes = $serverPeakWorkingSet
            client_failure_counter_delta = $clientFailureDelta
            server_failure_counter_delta = $serverFailureDelta
            checked_units = $checkedUnits
            loopback_interface_index = [uint32]$Loopback.interface_index
            loopback_interface_alias = [string]$Loopback.interface_alias
            route_proofs = $runtime.route_proofs
            workload_measurements = $measurements
            workload_checks = $workload.observation.checks
            status = "PASS"
        }
        Write-AtomicJsonFile -Path (Join-Path $trialRoot "trial.json") -Document $observation
        $succeeded = $true
        return $observation
    } catch {
        $failure = $_
        if ($null -ne $workloadProcess) {
            try {
                [void](Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
                    -Process $workloadProcess -LogPrefix $workloadLogPrefix)
            } catch { Write-Warning "workload diagnostic export failed" }
        }
        try {
            Write-NewUtf8File -Path (Join-Path $trialRoot "failure-phase.txt") -Text "$failurePhase`n"
        } catch { Write-Warning "trial phase diagnostic export failed" }
        if ($null -ne $runtime) {
            Export-Ferrum2ProductFailureLogs -Context $Context -Client $runtime.client `
                -Server $runtime.server -Sequence ([int]$Trial.sequence)
            $endpoints = [Collections.Generic.List[object]]::new()
            [void]$endpoints.Add([pscustomobject]@{
                name = "client"; port = $runtime.client_metrics_port
            })
            if ($null -ne $runtime.server) {
                [void]$endpoints.Add([pscustomobject]@{
                    name = "server"; port = $runtime.server_metrics_port
                })
            }
            foreach ($endpoint in $endpoints) {
                try {
                    $metrics = Get-Ferrum2Metrics -Port $endpoint.port
                    Write-NewUtf8File `
                        -Path (Join-Path $trialRoot "$($endpoint.name)-metrics-failure.txt") `
                        -Text $metrics
                } catch {
                    Write-NewUtf8File `
                        -Path (Join-Path $trialRoot "$($endpoint.name)-metrics-capture-error.txt") `
                        -Text ($_.Exception.Message + "`n")
                }
            }
        }
        throw $failure
    } finally {
        if ($null -ne $runtime) {
            Stop-Ferrum2ProductTrial -Context $Context -Runtime $runtime
        }
        if (-not $succeeded) {
            Set-Ferrum2HostPerformanceState -Context $Context -State "trial_failed"
        }
    }
}
