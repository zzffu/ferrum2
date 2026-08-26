function Test-PortRangeIntersection(
    [int]$FirstA,
    [int]$LastA,
    [int]$FirstB,
    [int]$LastB
) {
    return $FirstA -le $LastB -and $FirstB -le $LastA
}

function ConvertFrom-NetshUdpDynamicPortRange([object]$Snapshot) {
    $values = [Collections.Generic.List[int]]::new()
    foreach ($line in @($Snapshot.lines)) {
        $match = [regex]::Match([string]$line, ':\s*([0-9]{1,5})\s*$')
        if ($match.Success) {
            $values.Add([int]::Parse(
                $match.Groups[1].Value,
                [Globalization.CultureInfo]::InvariantCulture
            ))
        }
    }
    Assert-Condition ($values.Count -eq 2) `
        "UDP dynamic-port output did not contain exactly one start/count pair"
    $first = $values[0]
    $count = $values[1]
    Assert-Condition ($first -ge 1 -and $first -le 65535 -and $count -ge 1) `
        "UDP dynamic-port range is invalid"
    [long]$last = [long]$first + [long]$count - 1L
    Assert-Condition ($last -le 65535) "UDP dynamic-port range exceeds port 65535"
    return [ordered]@{
        first_port = $first
        last_port = [int]$last
        port_count = $count
    }
}

function ConvertFrom-NetshUdpExcludedPortRangeOutput([object]$Snapshot) {
    $ranges = [Collections.Generic.List[object]]::new()
    foreach ($line in @($Snapshot.lines)) {
        $match = [regex]::Match(
            [string]$line,
            '^\s*([0-9]{1,5})\s+([0-9]{1,5})(?:\s+\*)?\s*$'
        )
        if (-not $match.Success) { continue }
        $first = [int]::Parse(
            $match.Groups[1].Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
        $last = [int]::Parse(
            $match.Groups[2].Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
        Assert-Condition ($first -ge 1 -and $first -le $last -and $last -le 65535) `
            "UDP excluded-port range is invalid"
        $ranges.Add([ordered]@{
            first_port = $first
            last_port = $last
        })
    }
    return $ranges.ToArray()
}

function Get-UdpAssociationSourcePreflight([string]$TunAdapterName) {
    $violations = [Collections.Generic.List[string]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $adapterRows = @()
    try {
        $adapterRows = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq $TunAdapterName
        })
        if ($adapterRows.Count -ne 1) {
            $violations.Add("adapter_identity")
        } elseif ([string]$adapterRows[0].Status -cne "Up") {
            $violations.Add("adapter_not_up")
        }
    } catch {
        $violations.Add("adapter_query")
        $errors.Add("adapter query: $($_.Exception.Message)")
    }
    $adapterEvidence = @($adapterRows | Select-Object -First 16 | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            interface_description = [string]$_.InterfaceDescription
            interface_index = [int]$_.ifIndex
            status = [string]$_.Status
            mac_address = [string]$_.MacAddress
        }
    })
    $adapterInterfaceIndex = if ($adapterRows.Count -eq 1) {
        [int]$adapterRows[0].ifIndex
    } else {
        $null
    }

    $ipRows = @()
    try {
        $ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            [string]$_.IPAddress -ceq $script:UdpAssociationSourceIpv4
        })
        if ($ipRows.Count -ne 1) {
            $violations.Add("source_ip_identity")
        } else {
            if ([int]$ipRows[0].PrefixLength -ne 30) {
                $violations.Add("source_ip_prefix")
            }
            if ($null -eq $adapterInterfaceIndex -or
                [int]$ipRows[0].InterfaceIndex -ne $adapterInterfaceIndex) {
                $violations.Add("source_ip_owner")
            }
        }
    } catch {
        $violations.Add("source_ip_query")
        $errors.Add("source IP query: $($_.Exception.Message)")
    }
    $ipEvidence = @($ipRows | Select-Object -First 16 | ForEach-Object {
        [ordered]@{
            ip_address = [string]$_.IPAddress
            prefix_length = [int]$_.PrefixLength
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_state = [string]$_.AddressState
            prefix_origin = [string]$_.PrefixOrigin
            suffix_origin = [string]$_.SuffixOrigin
        }
    })

    $conflictRows = @()
    try {
        $conflictRows = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
            [int]$_.LocalPort -ge $script:UdpAssociationSourcePortFirst -and
            [int]$_.LocalPort -le $script:UdpAssociationSourcePortLast
        } | Sort-Object LocalPort, LocalAddress, OwningProcess)
        if ($conflictRows.Count -ne 0) {
            $violations.Add("source_port_conflict")
        }
    } catch {
        $violations.Add("udp_endpoint_query")
        $errors.Add("UDP endpoint query: $($_.Exception.Message)")
    }
    $conflictEvidence = @($conflictRows | Select-Object -First 256 | ForEach-Object {
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            owning_process = [int]$_.OwningProcess
        }
    })

    $dynamicSnapshot = $null
    $dynamicRange = $null
    $dynamicIntersects = $null
    try {
        $dynamicSnapshot = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "dynamicport", "udp"
        )
        $dynamicRange = ConvertFrom-NetshUdpDynamicPortRange -Snapshot $dynamicSnapshot
        $dynamicIntersects = Test-PortRangeIntersection `
            -FirstA $script:UdpAssociationSourcePortFirst `
            -LastA $script:UdpAssociationSourcePortLast `
            -FirstB ([int]$dynamicRange.first_port) `
            -LastB ([int]$dynamicRange.last_port)
        if ($dynamicIntersects) {
            $violations.Add("dynamic_port_intersection")
        }
    } catch {
        $violations.Add("dynamic_port_query_or_parse")
        $errors.Add("UDP dynamic-port query: $($_.Exception.Message)")
    }

    $excludedSnapshot = $null
    $excludedRanges = @()
    $excludedIntersections = [Collections.Generic.List[object]]::new()
    try {
        $excludedSnapshot = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "excludedportrange", "protocol=udp"
        )
        $excludedRanges = @(ConvertFrom-NetshUdpExcludedPortRangeOutput `
            -Snapshot $excludedSnapshot)
        foreach ($range in $excludedRanges) {
            if (Test-PortRangeIntersection `
                    -FirstA $script:UdpAssociationSourcePortFirst `
                    -LastA $script:UdpAssociationSourcePortLast `
                    -FirstB ([int]$range.first_port) `
                    -LastB ([int]$range.last_port)) {
                $excludedIntersections.Add($range)
            }
        }
        if ($excludedIntersections.Count -ne 0) {
            $violations.Add("excluded_port_intersection")
        }
    } catch {
        $violations.Add("excluded_port_query_or_parse")
        $errors.Add("UDP excluded-port query: $($_.Exception.Message)")
    }

    return [ordered]@{
        schema = "ferrum2.windows-tun.udp-fixed-source-preflight.v1"
        captured_utc = [DateTime]::UtcNow.ToString("o")
        source_contract = [ordered]@{
            adapter_name = $TunAdapterName
            source_ip = $script:UdpAssociationSourceIpv4
            source_prefix_length = 30
            source_port_first = $script:UdpAssociationSourcePortFirst
            source_port_last = $script:UdpAssociationSourcePortLast
            source_port_count = $ExpectedUdpAssociationSourcePortCount
        }
        adapter = [ordered]@{
            match_count = $adapterRows.Count
            retained_count = $adapterEvidence.Count
            matches = $adapterEvidence
        }
        ip_owner = [ordered]@{
            match_count = $ipRows.Count
            retained_count = $ipEvidence.Count
            matches = $ipEvidence
        }
        udp_endpoint_conflicts = [ordered]@{
            count = $conflictRows.Count
            retained_count = $conflictEvidence.Count
            truncated = $conflictRows.Count -gt $conflictEvidence.Count
            endpoints = $conflictEvidence
        }
        dynamic_port_udp = $dynamicSnapshot
        dynamic_port_range = $dynamicRange
        dynamic_port_intersects_source = $dynamicIntersects
        excluded_port_ranges_udp = $excludedSnapshot
        excluded_port_ranges = $excludedRanges
        excluded_port_intersections = $excludedIntersections.ToArray()
        valid = $violations.Count -eq 0
        violations = $violations.ToArray()
        errors = $errors.ToArray()
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
    if ($SelectedScenario -ceq "udp-8192-association-lookup-expiry") {
        $arguments += @(
            "--source-ip", $script:UdpAssociationSourceIpv4,
            "--source-port-first", [string]$script:UdpAssociationSourcePortFirst,
            "--source-port-last", [string]$script:UdpAssociationSourcePortLast
        )
    }
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

function Invoke-Probe([int]$TimeoutSeconds = 30) {
    [void](Invoke-BoundedHarness @(
        "windows-tun-probe",
        "--target-ip", $script:TargetAddress,
        "--tcp-port", [string]$script:TargetTcpPort,
        "--udp-port", [string]$script:TargetUdpPort
    ) $TimeoutSeconds)
}

function Invoke-InterfaceSwitchRecoveryProbe(
    [object]$ExpectedLifecycleMetrics,
    [Diagnostics.Stopwatch]$RecoveryTimer,
    [int]$TimeoutSeconds = 30
) {
    # Only the approved Disable/Enable checkpoint gets this bounded retry. Each rejected attempt
    # must remain visible in the client's outbound-explicit failure metric.
    $metrics = Get-Metrics $script:MetricsPort 5
    [uint64]$resolutionFailures = Get-LabeledMetric -Metrics $metrics `
        -Name "ferrum2_outbound_interface_resolution" -Labels @{
            source = "outbound_explicit"; result = "failure"
        } -AllowAbsent $true
    [uint64]$initialResolutionFailures = $resolutionFailures
    [uint64]$attempts = 0
    $lastFailure = ""
    while ($RecoveryTimer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        [double]$remainingSeconds = $TimeoutSeconds - $RecoveryTimer.Elapsed.TotalSeconds
        if ($remainingSeconds -lt 1) { break }
        $attempts++
        try {
            Invoke-Probe ([int][Math]::Floor($remainingSeconds))
        } catch {
            $lastFailure = [string]$_.Exception.Message
            $metrics = Get-Metrics $script:MetricsPort 1
            $actualLifecycleMetrics = Get-NetworkLifecycleMetrics $metrics
            Assert-NetworkLifecycleMetricsEqual -Expected $ExpectedLifecycleMetrics `
                -Actual $actualLifecycleMetrics -Message `
                "interface-switch recovery probe triggered an extra lifecycle transition"
            [uint64]$nextResolutionFailures = Get-LabeledMetric -Metrics $metrics `
                -Name "ferrum2_outbound_interface_resolution" -Labels @{
                    source = "outbound_explicit"; result = "failure"
                } -AllowAbsent $true
            Assert-Condition ($nextResolutionFailures -eq $resolutionFailures + 1) `
                "interface-switch recovery probe failed for an unexpected reason"
            $resolutionFailures = $nextResolutionFailures
            $clientProcess.Refresh()
            $serverProcess.Refresh()
            Assert-Condition (-not $clientProcess.HasExited -and -not $serverProcess.HasExited) `
                "interface-switch recovery probe lost a measured process"
            if ($RecoveryTimer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
            Start-Sleep -Milliseconds 250
            continue
        }
        $RecoveryTimer.Stop()
        Assert-Condition ($RecoveryTimer.Elapsed.TotalSeconds -le $TimeoutSeconds) `
            "interface-switch recovery exceeded its timeout"
        return [ordered]@{
            probe_attempts = $attempts
            resolution_failures = [uint64]($resolutionFailures - $initialResolutionFailures)
        }
    }
    throw "interface-switch recovery probe timed out after $attempts attempts: $lastFailure"
}
