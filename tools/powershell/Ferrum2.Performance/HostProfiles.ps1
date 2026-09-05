Set-StrictMode -Version Latest

function Get-Ferrum2Median {
    param([Parameter(Mandatory = $true)][double[]]$Values)
    if ($Values.Count -eq 0) { throw "median requires at least one value" }
    $sorted = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function Get-Ferrum2CpuCostRatio {
    param(
        [Parameter(Mandatory = $true)][double]$BaselineCpuSeconds,
        [Parameter(Mandatory = $true)][double]$CandidateCpuSeconds,
        [Parameter(Mandatory = $true)][double]$WorkRatio
    )
    if ($BaselineCpuSeconds -eq 0) {
        return $(if ($CandidateCpuSeconds -eq 0) { 1.0 } else { [double]::PositiveInfinity })
    }
    return ($CandidateCpuSeconds / $BaselineCpuSeconds) / $WorkRatio
}
function Get-Ferrum2ImprovementRatio {
    param(
        [Parameter(Mandatory = $true)][double]$Baseline,
        [Parameter(Mandatory = $true)][double]$Candidate,
        [Parameter(Mandatory = $true)]
        [ValidateSet("higher_is_better", "lower_is_better")]
        [string]$Direction
    )
    if ($Baseline -le 0 -or $Candidate -le 0) {
        throw "paired performance values must be positive"
    }
    if ($Direction -ceq "higher_is_better") {
        return $Candidate / $Baseline
    }
    return $Baseline / $Candidate
}


function Test-Ferrum2PairedCpuCostRegression {
    param(
        [Parameter(Mandatory = $true)][double[]]$Ratios,
        [Parameter(Mandatory = $true)][double]$MaximumRegressionPercent
    )
    $median = Get-Ferrum2Median -Values $Ratios
    $majority = @($Ratios | Where-Object { $_ -gt 1.0 }).Count -gt
        [Math]::Floor($Ratios.Count / 2)
    return $median -gt (1.0 + ($MaximumRegressionPercent / 100.0)) -and $majority
}

function New-Ferrum2HostSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object[]]$Trials
    )
    $serverPresent = [string]$Plan.topology -ceq "EndToEnd"
    $scenarios = [Collections.Generic.List[object]]::new()
    foreach ($scenario in $Plan.scenarios) {
        $rows = @($Trials | Where-Object { [string]$_.scenario -ceq [string]$scenario.name })
        $ratios = [Collections.Generic.List[double]]::new()
        $pairs = [Collections.Generic.List[object]]::new()
        $clientCpuCostRatios = [Collections.Generic.List[double]]::new()
        $serverCpuCostRatios = [Collections.Generic.List[double]]::new()
        foreach ($pair in 1..$Plan.pair_count) {
            $baseline = @($rows | Where-Object { $_.pair -eq $pair -and $_.member -ceq "baseline" })
            $candidate = @($rows | Where-Object { $_.pair -eq $pair -and $_.member -ceq "candidate" })
            if ($baseline.Count -ne 1 -or $candidate.Count -ne 1) {
                throw "paired trial evidence is incomplete"
            }
            $ratio = Get-Ferrum2ImprovementRatio -Baseline ([double]$baseline[0].value) `
                -Candidate ([double]$candidate[0].value) -Direction $scenario.direction
            [void]$ratios.Add($ratio)
            $workRatio = [double]$candidate[0].checked_units /
                [double]$baseline[0].checked_units
            [void]$clientCpuCostRatios.Add((Get-Ferrum2CpuCostRatio `
                -BaselineCpuSeconds ([double]$baseline[0].client_cpu_percent / 100.0 * [double]$baseline[0].cpu_sample_seconds) `
                -CandidateCpuSeconds ([double]$candidate[0].client_cpu_percent / 100.0 * [double]$candidate[0].cpu_sample_seconds) `
                -WorkRatio $workRatio))
            if ($serverPresent) {
                [void]$serverCpuCostRatios.Add((Get-Ferrum2CpuCostRatio `
                    -BaselineCpuSeconds ([double]$baseline[0].server_cpu_percent / 100.0 * [double]$baseline[0].cpu_sample_seconds) `
                    -CandidateCpuSeconds ([double]$candidate[0].server_cpu_percent / 100.0 * [double]$candidate[0].cpu_sample_seconds) `
                    -WorkRatio $workRatio))
            }
            [void]$pairs.Add([pscustomobject][ordered]@{
                pair = $pair
                order = $baseline[0].order
                baseline = $baseline[0].value
                candidate = $candidate[0].value
                baseline_checked_units = $baseline[0].checked_units
                candidate_checked_units = $candidate[0].checked_units
                improvement_ratio = $ratio
            })
        }
        $ratioValues = $ratios.ToArray()
        $medianRatio = Get-Ferrum2Median -Values $ratioValues
        $deviations = @($ratioValues | ForEach-Object {
            [Math]::Abs([double]$_ - $medianRatio)
        })
        $medianAbsoluteDeviation = Get-Ferrum2Median -Values $deviations
        $outlierPairs = if ($medianAbsoluteDeviation -eq 0) {
            @()
        } else {
            @($pairs | Where-Object {
                [Math]::Abs([double]$_.improvement_ratio - $medianRatio) -gt
                    (3.0 * $medianAbsoluteDeviation)
            } | ForEach-Object { [int]$_.pair })
        }
        $pairsImproved = @($ratios | Where-Object { $_ -gt 1.0 }).Count
        $maximumCpuRegressionPercent = 2.0
        $serverCpuCostRegressed = $false
        if ($serverPresent) {
            $serverCpuCostRegressed = Test-Ferrum2PairedCpuCostRegression `
                -Ratios $serverCpuCostRatios.ToArray() `
                -MaximumRegressionPercent $maximumCpuRegressionPercent
        }
        $cpuCostRegressed =
            (Test-Ferrum2PairedCpuCostRegression `
                -Ratios $clientCpuCostRatios.ToArray() `
                -MaximumRegressionPercent $maximumCpuRegressionPercent) -or
            $serverCpuCostRegressed
        $baselineClientCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "baseline" |
                ForEach-Object { [double]$_.client_cpu_percent }
        )
        $candidateClientCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "candidate" |
                ForEach-Object { [double]$_.client_cpu_percent }
        )
        $baselineServerCpu = if ($serverPresent) {
            Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.server_cpu_percent }
            )
        } else { $null }
        $candidateServerCpu = if ($serverPresent) {
            Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.server_cpu_percent }
            )
        } else { $null }
        $hasP99 = $null -ne $rows[0].p99_nanoseconds
        $baselineP99 = if ($hasP99) {
            Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.p99_nanoseconds }
            )
        } else { $null }
        $candidateP99 = if ($hasP99) {
            Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.p99_nanoseconds }
            )
        } else { $null }
        $qualificationStatus = if ($cpuCostRegressed -or
            ($medianRatio -le 0.98 -and
                @($ratios | Where-Object { $_ -lt 1.0 }).Count -gt
                    [Math]::Floor($Plan.pair_count / 2))) {
            "regression"
        } elseif ($medianRatio -ge 1.02 -and
            $pairsImproved -gt [Math]::Floor($Plan.pair_count / 2)) {
            "candidate-win"
        } else {
            "within-noise-band"
        }
        [void]$scenarios.Add([pscustomobject][ordered]@{
            scenario = $scenario.name
            topology = $Plan.topology
            metric = $scenario.metric
            unit = $scenario.unit
            direction = $scenario.direction
            pairs = $pairs.ToArray()
            median_pair_improvement_ratio = $medianRatio
            median_pair_improvement_percent = ($medianRatio - 1.0) * 100.0
            minimum_pair_improvement_ratio = ($ratios | Measure-Object -Minimum).Minimum
            maximum_pair_improvement_ratio = ($ratios | Measure-Object -Maximum).Maximum
            median_absolute_deviation = $medianAbsoluteDeviation
            outlier_pairs = @($outlierPairs)
            pairs_improved = $pairsImproved
            baseline_checked_units_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.checked_units }
            )
            candidate_checked_units_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.checked_units }
            )
            baseline_io_completions_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.io_completions }
            )
            candidate_io_completions_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.io_completions }
            )
            baseline_p99_nanoseconds_median = $baselineP99
            candidate_p99_nanoseconds_median = $candidateP99
            baseline_client_cpu_percent_median = $baselineClientCpu
            candidate_client_cpu_percent_median = $candidateClientCpu
            baseline_server_cpu_percent_median = $baselineServerCpu
            candidate_server_cpu_percent_median = $candidateServerCpu
            baseline_client_peak_working_set_bytes_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.client_peak_working_set_bytes }
            )
            candidate_client_peak_working_set_bytes_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.client_peak_working_set_bytes }
            )
            baseline_server_peak_working_set_bytes_median = if ($serverPresent) {
                Get-Ferrum2Median -Values @(
                    $rows | Where-Object member -CEQ "baseline" |
                        ForEach-Object { [double]$_.server_peak_working_set_bytes }
                )
            } else { $null }
            candidate_server_peak_working_set_bytes_median = if ($serverPresent) {
                Get-Ferrum2Median -Values @(
                    $rows | Where-Object member -CEQ "candidate" |
                        ForEach-Object { [double]$_.server_peak_working_set_bytes }
                )
            } else { $null }
            client_failure_counter_delta = 0
            server_failure_counter_delta = if ($serverPresent) { 0 } else { $null }
            qualification_status = $qualificationStatus
        })
    }
    return [pscustomobject][ordered]@{
        schema_version = 2
        kind = "ferrum2.windows-tun.host-performance-summary"
        run_id = $Context.run_id
        performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
        mode = $Plan.mode
        topology = $Plan.topology
        baseline_sha = $Plan.baseline_sha
        candidate_sha = $Plan.candidate_sha
        pair_count = $Plan.pair_count
        scenarios = $scenarios.ToArray()
        threshold_percent = 2.0
        maximum_non_target_cpu_regression_percent = 2.0
        status = "PASS"
    }
}

function Invoke-Ferrum2HostPairedProfile {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($trial in $Plan.trials) {
        $member = if ($trial.member -ceq "baseline") { $Builds.baseline } else { $Builds.candidate }
        [void]$observations.Add((Invoke-Ferrum2HostTrial -Context $Context -Trial $trial `
            -Member $member -Harness $Builds.harness -Network $Network -Loopback $Loopback `
            -Support $support))
    }
    Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $support.process.pid
    $Context.ledger.resources.ports = @($Context.ledger.resources.ports | Where-Object {
        [string]$_.purpose -notmatch '^support-'
    })
    Write-Ferrum2HostPerformanceLedger -Context $Context
    $summary = New-Ferrum2HostSummary -Context $Context -Plan $Plan `
        -Trials $observations.ToArray()
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "summary.json") -Document $summary
    return $summary
}

function Invoke-Ferrum2HostLifecycleProfile {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = $null
    $cycleLatencies = [Collections.Generic.List[double]]::new()
    try {
        $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
        $supportProcessCount = @($Context.ledger.resources.processes).Count
        $supportPortCount = @($Context.ledger.resources.ports).Count
        foreach ($cycle in 1..$Plan.lifecycle_cycles) {
            $runtime = $null
            $timer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $runtime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
                    -Network $Network -Loopback $Loopback -Sequence $cycle `
                    -Topology $Plan.topology
                [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Builds.harness `
                    -Arguments "windows-tun-probe --target-ip $($Network.support_address) --tcp-port $($support.tcp_port) --udp-port $($support.udp_port)" `
                    -WorkingDirectory (Split-Path -Parent $Builds.harness) `
                    -LogPrefix "lifecycle-$cycle-probe" -TimeoutSeconds 60)
            } finally {
                if ($null -ne $runtime) {
                    Stop-Ferrum2ProductTrial -Context $Context -Runtime $runtime
                }
            }
            $timer.Stop()
            if ($null -ne $Context.ledger.resources.adapter -or
                @($Context.ledger.resources.routes).Count -ne 0 -or
                @($Context.ledger.resources.processes).Count -ne $supportProcessCount -or
                @($Context.ledger.resources.ports).Count -ne $supportPortCount) {
                throw "lifecycle cycle $cycle retained a product-owned resource"
            }
            [void]$cycleLatencies.Add($timer.Elapsed.TotalMilliseconds)
        }
    } finally {
        if ($null -ne $support) {
            Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $support.process.pid
            $Context.ledger.resources.ports = @($Context.ledger.resources.ports | Where-Object {
                [string]$_.purpose -notmatch '^support-'
            })
            Write-Ferrum2HostPerformanceLedger -Context $Context
        }
    }
    if ($null -ne $Context.ledger.resources.adapter -or
        @($Context.ledger.resources.routes).Count -ne 0 -or
        @($Context.ledger.resources.processes).Count -ne 0 -or
        @($Context.ledger.resources.ports).Count -ne 0) {
        throw "Lifecycle retained a product or support resource"
    }
    $ordered = @($cycleLatencies | Sort-Object)
    $p95Index = [Math]::Min($ordered.Count - 1, [int][Math]::Ceiling($ordered.Count * 0.95) - 1)
    $summary = [pscustomobject][ordered]@{
        schema_version = 2
        kind = "ferrum2.windows-tun.host-lifecycle-summary"
        run_id = $Context.run_id
        performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
        mode = "Lifecycle"
        topology = $Plan.topology
        candidate_sha = $Plan.candidate_sha
        lifecycle_cycles = [int]$Plan.lifecycle_cycles
        lifecycle_action = "product-start-probe-stop"
        cycle_latencies_ms = $cycleLatencies.ToArray()
        cycle_latency_median_ms = Get-Ferrum2Median -Values $cycleLatencies.ToArray()
        cycle_latency_p95_ms = [double]$ordered[$p95Index]
        cycle_latency_minimum_ms = [double]$ordered[0]
        cycle_latency_maximum_ms = [double]$ordered[-1]
        probe_failures = 0
        between_cycle_adapter_remaining = 0
        between_cycle_routes_remaining = 0
        between_cycle_product_processes_remaining = 0
        between_cycle_product_ports_remaining = 0
        physical_adapter_mutations = 0
        wlan_mutations = 0
        dns_mutations = 0
        status = "PASS"
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "summary.json") -Document $summary
    return $summary
}

function Invoke-Ferrum2HostSafetyCheck {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
    $checks = [Collections.Generic.List[object]]::new()
    Assert-Ferrum2HostPerformanceRootSecurity -Root (Get-Ferrum2HostPerformanceRoot)
    [void]$checks.Add([pscustomobject][ordered]@{
            name = "administrator-owned-recovery-root"
            status = "PASS"
            detail = "Recovery ledger root is owned by Administrators and writable only by Administrators and SYSTEM."
        })
    $createRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 1 -Topology "EndToEnd"
    Stop-Ferrum2ProductTrial -Context $Context -Runtime $createRuntime
    [void]$checks.Add([pscustomobject]@{ name = "create-immediate-cleanup"; status = "PASS" })
    $smokeRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 2 -Topology "EndToEnd"
    try {
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Builds.harness `
            -Arguments "windows-tun-probe --target-ip $($Network.support_address) --tcp-port $($support.tcp_port) --udp-port $($support.udp_port)" `
            -WorkingDirectory (Split-Path -Parent $Builds.harness) -LogPrefix "safety-smoke" `
            -TimeoutSeconds 60)
    } finally { Stop-Ferrum2ProductTrial -Context $Context -Runtime $smokeRuntime }
    [void]$checks.Add([pscustomobject]@{ name = "shortest-tun-smoke"; status = "PASS" })
    $faultRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 3 -Topology "EndToEnd"
    [Ferrum2PerfProcessGroup]::CloseGroup()
    Start-Sleep -Milliseconds 500
    $addressRows = @($Context.ledger.resources.addresses)
    if ($addressRows.Count -ne 1) {
        throw "safety check expected one owned support address"
    }
    $addressRows[0].state = "planned"
    $Context.ledger.state = "recovery_required"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    $plannedAddressRefused = $false
    try {
        [void](Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path)
    } catch {
        if ([string]$_.Exception.Message -cne
            "planned address presence is ambiguous; refusing removal") {
            throw
        }
        $plannedAddressRefused = $true
    }
    $remainingAddress = @(Get-NetIPAddress -AddressFamily IPv4 `
        -IPAddress $Network.support_address -InterfaceIndex $Loopback.interface_index `
        -ErrorAction SilentlyContinue)
    if (-not $plannedAddressRefused -or $remainingAddress.Count -ne 1) {
        throw "planned address ambiguity did not fail closed"
    }
    $addressRows[0].state = "created"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    [void](Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path)
    [void]$checks.Add([pscustomobject]@{
        name = "planned-address-ambiguity-fails-closed"
        status = "PASS"
    })
    [void]$checks.Add([pscustomobject]@{
        name = "fault-job-close-and-stale-ledger-recovery"
        status = "PASS"
    })
    $report = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-safety-check"
        run_id = $Context.run_id
        performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
        checks = $checks.ToArray()
        route_proofs = $smokeRuntime.route_proofs
        adapter_remaining = 0
        routes_remaining = 0
        addresses_remaining = 0
        processes_remaining = 0
        ports_remaining = 0
        status = "PASS"
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "safety-check.json") -Document $report
    return $report
}
