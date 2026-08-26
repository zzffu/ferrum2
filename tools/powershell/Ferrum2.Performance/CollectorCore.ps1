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
    $rows = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Thread `
        -Filter "IDProcess=$ProcessId" -ErrorAction Stop)
    Assert-Condition ($rows.Count -gt 0) "client context-switch counters are unavailable"
    [uint64]$total = 0
    foreach ($row in $rows) {
        $properties = @($row.CimInstanceProperties | Where-Object {
            $_.Name -ceq "ContextSwitchesPersec"
        })
        Assert-Condition ($properties.Count -eq 1 -and $null -ne $properties[0].Value) `
            "client thread context-switch counter is unavailable"
        [uint64]$value = [uint64]$properties[0].Value
        Assert-Condition ($total -le [uint64]::MaxValue - $value) `
            "client context-switch counters overflowed"
        $total += $value
    }
    return $total
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

function Invoke-NetshBounded([string[]]$Arguments) {
    foreach ($argument in $Arguments) {
        Assert-Condition ($argument -cnotmatch '["\r\n]') `
            "netsh snapshot contains an unsupported native argument"
    }
    $temporaryToken = [Guid]::NewGuid().ToString("N")
    $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) `
        "ferrum2-netsh-$temporaryToken.stdout"
    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) `
        "ferrum2-netsh-$temporaryToken.stderr"
    Assert-Condition (-not (Test-Path -LiteralPath $stdoutPath)) `
        "netsh stdout baseline is not absent"
    Assert-Condition (-not (Test-Path -LiteralPath $stderrPath)) `
        "netsh stderr baseline is not absent"
    $process = $null
    try {
        $process = Start-Process -FilePath "netsh.exe" -ArgumentList $Arguments `
            -WindowStyle Hidden -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath -PassThru -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $timedOut = $false
        $outputBoundaryExceeded = $false
        do {
            $stdoutBytes = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stdoutPath -Force).Length
            } else { [long]0 }
            $stderrBytes = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stderrPath -Force).Length
            } else { [long]0 }
            if ($stdoutBytes + $stderrBytes -gt 16384) {
                $outputBoundaryExceeded = $true
                break
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $process.HasExited) {
            $timedOut = -not $outputBoundaryExceeded
            try { $process.Kill($true) }
            catch {
                try { $process.Kill() }
                catch { throw "netsh snapshot termination request failed: $($_.Exception.Message)" }
            }
        }
        Assert-Condition ($process.WaitForExit(10000)) `
            "netsh snapshot process could not be reaped"
        Assert-Condition (-not $outputBoundaryExceeded) `
            "netsh snapshot exceeded 16 KiB"
        Assert-Condition (-not $timedOut) "netsh snapshot timed out"
        Assert-Condition ($process.ExitCode -eq 0) `
            "netsh snapshot failed: $($Arguments -join ' ')"
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            foreach ($line in [IO.File]::ReadLines($path)) {
                Assert-Condition ($lines.Count -lt 128) `
                    "netsh snapshot exceeded 128 lines"
                $lines.Add(([string]$line -replace "[\r\n]+", " ").TrimEnd())
            }
        }
        $lineArray = $lines.ToArray()
        Assert-Condition (
            $script:Utf8NoBom.GetByteCount($lineArray -join "`n") -le 16384
        ) "netsh snapshot exceeded 16 KiB"
        return [ordered]@{
            command = "netsh.exe $($Arguments -join ' ')"
            exit_code = $process.ExitCode
            total_lines = $lineArray.Count
            truncated = $false
            lines = $lineArray
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [IO.File]::Delete($path)
            }
        }
    }
}
