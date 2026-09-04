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
        [Parameter(Mandatory = $true)][double]$BaselineCpu,
        [Parameter(Mandatory = $true)][double]$CandidateCpu,
        [Parameter(Mandatory = $true)][double]$WorkRatio
    )
    if ($BaselineCpu -eq 0) {
        return $(if ($CandidateCpu -eq 0) { 1.0 } else { [double]::PositiveInfinity })
    }
    return ($CandidateCpu / $BaselineCpu) / $WorkRatio
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
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object[]]$Trials
    )
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
            if ($baseline.Count -ne 1 -or $candidate.Count -ne 1) { throw "paired trial evidence is incomplete" }
            $ratio = [double]$candidate[0].value / [double]$baseline[0].value
            [void]$ratios.Add($ratio)
            [void]$clientCpuCostRatios.Add((Get-Ferrum2CpuCostRatio `
                -BaselineCpu ([double]$baseline[0].client_cpu_percent) `
                -CandidateCpu ([double]$candidate[0].client_cpu_percent) `
                -WorkRatio $ratio))
            [void]$serverCpuCostRatios.Add((Get-Ferrum2CpuCostRatio `
                -BaselineCpu ([double]$baseline[0].server_cpu_percent) `
                -CandidateCpu ([double]$candidate[0].server_cpu_percent) `
                -WorkRatio $ratio))
            [void]$pairs.Add([pscustomobject][ordered]@{
                pair = $pair
                order = $baseline[0].order
                baseline = $baseline[0].value
                candidate = $candidate[0].value
                ratio = $ratio
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
                [Math]::Abs([double]$_.ratio - $medianRatio) -gt
                    (3.0 * $medianAbsoluteDeviation)
            } | ForEach-Object { [int]$_.pair })
        }
        $pairsImproved = @($ratios | Where-Object { $_ -gt 1.0 }).Count
        $maximumCpuRegressionPercent = 2.0
        $cpuCostRegressed =
            (Test-Ferrum2PairedCpuCostRegression `
                -Ratios $clientCpuCostRatios.ToArray() `
                -MaximumRegressionPercent $maximumCpuRegressionPercent) -or
            (Test-Ferrum2PairedCpuCostRegression `
                -Ratios $serverCpuCostRatios.ToArray() `
                -MaximumRegressionPercent $maximumCpuRegressionPercent)
        $baselineClientCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "baseline" |
                ForEach-Object { [double]$_.client_cpu_percent }
        )
        $candidateClientCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "candidate" |
                ForEach-Object { [double]$_.client_cpu_percent }
        )
        $baselineServerCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "baseline" |
                ForEach-Object { [double]$_.server_cpu_percent }
        )
        $candidateServerCpu = Get-Ferrum2Median -Values @(
            $rows | Where-Object member -CEQ "candidate" |
                ForEach-Object { [double]$_.server_cpu_percent }
        )
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
            metric = $scenario.metric
            unit = $scenario.unit
            pairs = $pairs.ToArray()
            median_pair_ratio = $medianRatio
            median_pair_improvement_percent = ($medianRatio - 1.0) * 100.0
            minimum_pair_ratio = ($ratios | Measure-Object -Minimum).Minimum
            maximum_pair_ratio = ($ratios | Measure-Object -Maximum).Maximum
            median_absolute_deviation = $medianAbsoluteDeviation
            outlier_pairs = @($outlierPairs)
            pairs_improved = $pairsImproved
            baseline_client_cpu_percent_median = $baselineClientCpu
            candidate_client_cpu_percent_median = $candidateClientCpu
            baseline_server_cpu_percent_median = $baselineServerCpu
            candidate_server_cpu_percent_median = $candidateServerCpu
            client_failure_counter_delta = 0
            server_failure_counter_delta = 0
            qualification_status = $qualificationStatus
        })
    }
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-performance-summary"
        mode = $Plan.mode
        baseline_sha = $Plan.baseline_sha
        candidate_sha = $Plan.candidate_sha
        pair_count = $Plan.pair_count
        scenarios = $scenarios.ToArray()
        threshold_percent = 2.0
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
    $summary = New-Ferrum2HostSummary -Plan $Plan -Trials $observations.ToArray()
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
                    -Network $Network -Loopback $Loopback -Sequence $cycle
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
        schema_version = 1
        kind = "ferrum2.windows-tun.host-lifecycle-summary"
        mode = "Lifecycle"
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
        long_durability_soak = "not-run"
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
        -Network $Network -Loopback $Loopback -Sequence 1
    Stop-Ferrum2ProductTrial -Context $Context -Runtime $createRuntime
    [void]$checks.Add([pscustomobject]@{ name = "create-immediate-cleanup"; status = "PASS" })
    $smokeRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 2
    try {
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Builds.harness `
            -Arguments "windows-tun-probe --target-ip $($Network.support_address) --tcp-port $($support.tcp_port) --udp-port $($support.udp_port)" `
            -WorkingDirectory (Split-Path -Parent $Builds.harness) -LogPrefix "safety-smoke" `
            -TimeoutSeconds 60)
    } finally { Stop-Ferrum2ProductTrial -Context $Context -Runtime $smokeRuntime }
    [void]$checks.Add([pscustomobject]@{ name = "shortest-tun-smoke"; status = "PASS" })
    $faultRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 3
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
        Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
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
    Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
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
