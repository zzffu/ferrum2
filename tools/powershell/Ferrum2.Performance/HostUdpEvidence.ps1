function Write-Utf8FileNew {
    param([string]$Path, [string]$Text)
    $bytes = $script:utf8NoBom.GetBytes($Text)
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Invoke-BoundedNativeText {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$MaximumLines = 4096,
        [int]$MaximumBytes = 4194304,
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 60,
        [switch]$AllowFailure
    )
    foreach ($argument in $Arguments) {
        if ($argument -cmatch '["\r\n]') {
            throw "$Label contains an unsupported native argument"
        }
    }
    $temporaryName = "ferrum2-native-capture-$([Guid]::NewGuid().ToString('N'))"
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) $temporaryName
    $stdoutPath = Join-Path $temporaryDirectory "stdout.txt"
    $stderrPath = Join-Path $temporaryDirectory "stderr.txt"
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $process = $null
    try {
        $quotedArguments = @($Arguments | ForEach-Object {
            if ($_ -cmatch '\s') { '"{0}"' -f $_ } else { $_ }
        })
        $process = Start-Process -FilePath $Executable -ArgumentList $quotedArguments `
            -WindowStyle Hidden -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath -PassThru -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $boundaryExceeded = $false
        do {
            $stdoutBytes = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stdoutPath -Force).Length
            } else { [long]0 }
            $stderrBytes = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stderrPath -Force).Length
            } else { [long]0 }
            if ($stdoutBytes + $stderrBytes -gt $MaximumBytes) {
                $boundaryExceeded = $true
                try { $process.Kill($true) } catch { $process.Kill() }
                break
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $process.HasExited) {
            try { $process.Kill($true) } catch { $process.Kill() }
        }
        if (-not $process.WaitForExit(10000)) {
            throw "$Label process could not be reaped"
        }
        if ($boundaryExceeded) { throw "$Label output exceeded its byte boundary" }
        if ([DateTime]::UtcNow -ge $deadline) { throw "$Label exceeded its timeout" }
        $lines = [Collections.Generic.List[string]]::new()
        $totalLines = 0
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            foreach ($line in [IO.File]::ReadLines($path)) {
                $totalLines++
                if ($totalLines -le $MaximumLines) {
                    $lines.Add(([string]$line -replace '[\r\n]+', ' ').TrimEnd())
                }
            }
        }
        if ($totalLines -gt $MaximumLines) {
            throw "$Label output exceeded its line boundary"
        }
        $textValue = $lines.ToArray() -join "`n"
        if ($script:utf8NoBom.GetByteCount($textValue) -gt $MaximumBytes) {
            throw "$Label output exceeded its decoded byte boundary"
        }
        $exitCode = $process.ExitCode
        if (-not $AllowFailure -and $exitCode -ne 0) {
            $detail = if ($textValue.Length -gt 2048) {
                $textValue.Substring(0, 2048)
            } else {
                $textValue
            }
            throw "$Label failed with exit code ${exitCode}: $detail"
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Lines = $lines.ToArray()
            TotalLines = $totalLines
            Truncated = $false
            Text = $textValue
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [IO.File]::Delete($path)
            }
        }
        if ((Test-Path -LiteralPath $temporaryDirectory -PathType Container) -and
            [IO.Path]::GetFileName($temporaryDirectory) -ceq $temporaryName -and
            [IO.Path]::GetDirectoryName($temporaryDirectory).TrimEnd('\', '/') -ceq
                [IO.Path]::GetTempPath().TrimEnd('\', '/')) {
            [IO.Directory]::Delete($temporaryDirectory, $false)
        }
    }
}

function Complete-UdpSupportDiagnosticLedger {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$TargetIpv4,
        [ValidateRange(1, 65532)]
        [Parameter(Mandatory = $true)][int]$FirstUdpPort,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [ValidateRange(1, 65535)]
        [Parameter(Mandatory = $true)][int]$TrialSequence
    )
    $result = Invoke-BoundedNativeText `
        -Executable $Executable `
        -Arguments @(
            "windows-tun-udp-diagnostic-finalize",
            "--target-ip", $TargetIpv4,
            "--udp-port", [string]$FirstUdpPort,
            "--diagnostic-run-nonce", $RunNonce,
            "--diagnostic-trial-sequence", [string]$TrialSequence
        ) `
        -Label "Windows TUN UDP diagnostic support ledger finalize" `
        -MaximumLines 1 -MaximumBytes 4096 -TimeoutSeconds 60
    $expected = "windows_tun_udp_diagnostic_finalize status=PASS " +
        "target=$TargetIpv4 udp_ports=$FirstUdpPort..$($FirstUdpPort + 3) " +
        "trial_sequence=$TrialSequence"
    if ($result.ExitCode -ne 0 -or $result.Lines.Count -ne 1 -or
        [string]$result.Lines[0] -cne $expected) {
        throw "Windows TUN UDP diagnostic support ledger finalize result is invalid"
    }
}

function Write-HostUdpEndpointSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][int]$SupportProcessId
    )
    $dynamic = Invoke-BoundedNativeText -Executable "netsh.exe" -Arguments @(
        "interface", "ipv4", "show", "dynamicport", "udp"
    ) -Label "host UDP dynamic-port snapshot" -MaximumLines 512 -MaximumBytes 131072
    $excluded = Invoke-BoundedNativeText -Executable "netsh.exe" -Arguments @(
        "interface", "ipv4", "show", "excludedportrange", "protocol=udp"
    ) -Label "host UDP excluded-port snapshot" -MaximumLines 512 -MaximumBytes 131072
    $endpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $supportEndpoints = @($endpoints | Where-Object {
        [int]$_.OwningProcess -eq $SupportProcessId
    } | Sort-Object LocalAddress, LocalPort | ForEach-Object {
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            owning_process = [int]$_.OwningProcess
        }
    })
    $topOwners = @($endpoints | Group-Object OwningProcess | Sort-Object Count -Descending |
        Select-Object -First 64 | ForEach-Object {
            $ownerPid = [int]$_.Name
            $processName = $null
            try {
                $processName = [string](Get-Process -Id $ownerPid -ErrorAction Stop).ProcessName
            } catch {
                $processName = $null
            }
            [ordered]@{
                owning_process = $ownerPid
                process_name = $processName
                endpoint_count = $_.Count
                support_process = $ownerPid -eq $SupportProcessId
            }
        })
    $snapshot = [ordered]@{
        schema = "ferrum2.windows-tun.host-udp-endpoint-snapshot.v1"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        dynamic_port_udp = [ordered]@{
            exit_code = $dynamic.ExitCode
            total_lines = $dynamic.TotalLines
            truncated = $dynamic.Truncated
            lines = $dynamic.Lines
        }
        excluded_port_ranges_udp = [ordered]@{
            exit_code = $excluded.ExitCode
            total_lines = $excluded.TotalLines
            truncated = $excluded.Truncated
            lines = $excluded.Lines
        }
        endpoint_count = $endpoints.Count
        support_endpoints = $supportEndpoints
        top_endpoint_owners = $topOwners
    }
    $textValue = ($snapshot | ConvertTo-Json -Depth 8) + "`n"
    if ($script:utf8NoBom.GetByteCount($textValue) -gt 1048576) {
        throw "host UDP endpoint snapshot exceeded 1 MiB"
    }
    Write-Utf8FileNew -Path $Path -Text $textValue
}

function Write-HostUdpEndpointErrorSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][int]$SupportProcessId,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($existing.PSIsContainer -or
            $existing.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "host UDP endpoint error snapshot target is unsafe"
        }
        [IO.File]::Delete($existing.FullName)
    }
    $boundedFailure = ($Failure -replace '[\r\n]+', ' ').Trim()
    if ($boundedFailure.Length -gt 2048) {
        $boundedFailure = $boundedFailure.Substring(0, 2048)
    }
    $snapshot = [ordered]@{
        schema = "ferrum2.windows-tun.host-udp-endpoint-snapshot.v1"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        support_pid = $SupportProcessId
        state = "PARTIAL"
        error = $boundedFailure
    }
    Write-Utf8FileNew -Path $Path `
        -Text (($snapshot | ConvertTo-Json -Depth 4) + "`n")
}

function Assert-PktmonCaptureLifecycleState {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Running", "Stopped")]
        [string]$ExpectedState
    )
    $status = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @("status") `
        -Label "Pktmon lifecycle status" -MaximumLines 64 -MaximumBytes 16384 `
        -AllowFailure
    $session = Invoke-BoundedNativeText -Executable "logman.exe" `
        -Arguments @("query", "-ets", "PktMon") `
        -Label "Pktmon lifecycle ETW session query" `
        -MaximumLines 64 -MaximumBytes 16384 -AllowFailure
    $statusSaysStopped = $status.ExitCode -eq 0 -and
        $status.Text -cmatch '(?i)(not\s+running|没有运行)'
    $sessionSaysRunning = $session.ExitCode -eq 0
    if ($ExpectedState -ceq "Running") {
        if ($status.ExitCode -ne 0 -or $statusSaysStopped -or
            -not $sessionSaysRunning) {
            throw "Pktmon running state was not proven by status and ETW session readback"
        }
    } elseif (-not $statusSaysStopped -or $sessionSaysRunning) {
        throw "Pktmon stopped state was not proven by status and ETW session readback"
    }
}

function Stop-PktmonCaptureAndAssertStopped {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$OutputPath
    )
    $stop = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("stop") -Label $Label -MaximumLines 256 `
        -MaximumBytes 65536 -AllowFailure
    if (-not [string]::IsNullOrWhiteSpace($OutputPath) -and
        -not (Test-Path -LiteralPath $OutputPath)) {
        Write-Utf8FileNew -Path $OutputPath -Text ($stop.Text + "`n")
    }
    try {
        Assert-PktmonCaptureLifecycleState -ExpectedState "Stopped"
    } catch {
        throw "$Label did not prove Pktmon stopped (stop exit=$($stop.ExitCode)): $($_.Exception.Message)"
    }
}

function Assert-PktmonUnused {
    Assert-PktmonCaptureLifecycleState -ExpectedState "Stopped"
    $filters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "list") -Label "Pktmon filter list" `
        -MaximumLines 256 -MaximumBytes 65536
    if ($filters.Text -cnotmatch `
        '(?im)^\s*(none|无|No packet filters are specified\.|未指定数据包筛选器。)\s*$') {
        throw "Pktmon filter baseline is not empty"
    }
    return $filters.Text
}

function Get-PktmonFilterListText {
    $filters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "list") -Label "Pktmon owned filter readback" `
        -MaximumLines 512 -MaximumBytes 131072
    return $filters.Text
}

function Remove-OwnedPktmonFiltersSafely {
    param([Parameter(Mandatory = $true)][string]$ExpectedFilterListText)
    $actualFilterListText = Get-PktmonFilterListText
    if ($actualFilterListText -cne $ExpectedFilterListText) {
        throw "Pktmon filter set changed after Ferrum2 acquired ownership; filters were preserved"
    }
    [void](Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "remove") -Label "Pktmon filter cleanup" `
        -MaximumLines 128 -MaximumBytes 32768)
    $remaining = Get-PktmonFilterListText
    if ($remaining -cnotmatch `
        '(?im)^\s*(none|无|No packet filters are specified\.|未指定数据包筛选器。)\s*$') {
        throw "Pktmon owned filter cleanup did not restore the empty baseline"
    }
}

function Start-HostUdpDiagnosticCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$SupportAddress,
        [Parameter(Mandatory = $true)][int]$FirstUdpPort
    )
    $mutex = [Threading.Mutex]::new(
        $false,
        "Global\Ferrum2WindowsTunUdpDiagnosticPktmon"
    )
    $mutexHeld = $false
    $filtersAdded = $false
    $captureStarted = $false
    $captureStartAttempted = $false
    $ownedFilterListText = $null
    try {
        try { $mutexHeld = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
        if (-not $mutexHeld) {
            throw "another Ferrum2 UDP diagnostic owns the global Pktmon mutex"
        }
        $ownedFilterListText = Assert-PktmonUnused
        $filterRows = [Collections.Generic.List[object]]::new()
        foreach ($port in $FirstUdpPort..($FirstUdpPort + 3)) {
            $filterName = "Ferrum2UdpDiagnostic-$port"
            $filterResult = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                "filter", "add", $filterName,
                "--ip", $SupportAddress,
                "--transport", "UDP",
                "--port", [string]$port
            ) -Label "Pktmon UDP filter $port" -MaximumLines 64 -MaximumBytes 16384
            $filterRows.Add([ordered]@{
                name = $filterName
                support_ipv4 = $SupportAddress
                protocol = "UDP"
                port = $port
                command_exit_code = $filterResult.ExitCode
            })
            $filtersAdded = $true
            $ownedFilterListText = Get-PktmonFilterListText
        }
        $etlPath = Join-Path $Directory "PktMon.etl"
        $captureStartAttempted = $true
        $startResult = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
            "start", "--capture", "--comp", "all", "--type", "all",
            "--pkt-size", "128", "--file-name", $etlPath,
            "--file-size", "16", "--log-mode", "circular"
        ) -Label "Pktmon capture start" -MaximumLines 128 -MaximumBytes 32768
        Assert-PktmonCaptureLifecycleState -ExpectedState "Running"
        $captureStarted = $true
        return [pscustomobject]@{
            Mutex = $mutex
            MutexHeld = $mutexHeld
            FiltersAdded = $filtersAdded
            CaptureStarted = $captureStarted
            Directory = $Directory
            EtlPath = $etlPath
            Filters = $filterRows.ToArray()
            OwnedFilterListText = $ownedFilterListText
            StartOutput = $startResult.Lines
            StartedUtc = [DateTime]::UtcNow.ToString("o")
        }
    } catch {
        $startFailure = $_
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        $captureStopped = -not $captureStartAttempted
        if ($captureStartAttempted) {
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon failed-start stop"
                $captureStopped = $true
            } catch {
                $cleanupFailures.Add("capture stop: $($_.Exception.Message)")
            }
        }
        if ($filtersAdded -and $captureStopped) {
            try {
                Remove-OwnedPktmonFiltersSafely `
                    -ExpectedFilterListText $ownedFilterListText
            } catch {
                $cleanupFailures.Add("filter cleanup: $($_.Exception.Message)")
            }
        } elseif ($filtersAdded) {
            $cleanupFailures.Add(
                "filter cleanup skipped because stopped capture state was not proven; filters were preserved"
            )
        } elseif ($mutexHeld -and -not [string]::IsNullOrWhiteSpace(
            $ownedFilterListText
        )) {
            try {
                if ((Get-PktmonFilterListText) -cne $ownedFilterListText) {
                    $cleanupFailures.Add(
                        "filter mutation could not be attributed safely; filters were preserved"
                    )
                }
            } catch {
                $cleanupFailures.Add("filter readback: $($_.Exception.Message)")
            }
        }
        if ($mutexHeld) {
            try { $mutex.ReleaseMutex() }
            catch { $cleanupFailures.Add("mutex release: $($_.Exception.Message)") }
        }
        $mutex.Dispose()
        if ($cleanupFailures.Count -ne 0) {
            throw "$($startFailure.Exception.Message); Pktmon failed-start cleanup: $($cleanupFailures -join '; ')"
        }
        throw $startFailure
    }
}

function Complete-HostUdpDiagnosticCapture {
    param([Parameter(Mandatory = $true)][object]$State)
    $failures = [Collections.Generic.List[string]]::new()
    $captureStopStatus = "NOT_STARTED"
    try {
        if ($State.CaptureStarted) {
            try {
                $counters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
                    -Arguments @("counters", "--json") -Label "Pktmon counters" `
                    -MaximumLines 65536 -MaximumBytes 8388608
                Write-Utf8FileNew -Path (Join-Path $State.Directory "pktmon-counters.json") `
                    -Text ($counters.Text + "`n")
            } catch {
                $failures.Add("counters: $($_.Exception.Message)")
            }
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon capture stop" `
                    -OutputPath (Join-Path $State.Directory "pktmon-stop.txt")
                $captureStopStatus = "PASS"
                $State.CaptureStarted = $false
            } catch {
                $captureStopStatus = "FAIL"
                $failures.Add("stop: $($_.Exception.Message)")
            }
        }
        if (-not $State.CaptureStarted -and
            (Test-Path -LiteralPath $State.EtlPath -PathType Leaf)) {
            try {
                $etl = Get-Item -LiteralPath $State.EtlPath -Force
                if ($etl.Length -le 0 -or $etl.Length -gt 33554432) {
                    throw "Pktmon ETL size is outside its boundary"
                }
                [void](Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                    "etl2txt", $State.EtlPath,
                    "--out", (Join-Path $State.Directory "PktMon.txt"),
                    "--hex"
                ) -Label "Pktmon ETL text conversion" -MaximumLines 256 `
                    -MaximumBytes 65536)
                [void](Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                    "etl2pcap", $State.EtlPath,
                    "--out", (Join-Path $State.Directory "PktMon.pcapng")
                ) -Label "Pktmon ETL pcap conversion" -MaximumLines 256 `
                    -MaximumBytes 65536)
                foreach ($captureFile in @(
                    (Join-Path $State.Directory "PktMon.txt"),
                    (Join-Path $State.Directory "PktMon.pcapng")
                )) {
                    $item = Get-Item -LiteralPath $captureFile -Force -ErrorAction Stop
                    if ($item.Length -le 0 -or $item.Length -gt 134217728) {
                        throw "converted Pktmon artifact size is outside its boundary"
                    }
                }
            } catch {
                $failures.Add("conversion: $($_.Exception.Message)")
            }
        }
    } finally {
        if ($State.CaptureStarted) {
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon final capture stop" `
                    -OutputPath (Join-Path $State.Directory "pktmon-stop.txt")
                $captureStopStatus = "PASS"
                $State.CaptureStarted = $false
            } catch {
                $captureStopStatus = "FAIL"
                $failures.Add("final stop: $($_.Exception.Message)")
            }
        }
        if ($State.FiltersAdded -and -not $State.CaptureStarted) {
            try {
                Remove-OwnedPktmonFiltersSafely `
                    -ExpectedFilterListText $State.OwnedFilterListText
                $State.FiltersAdded = $false
            } catch {
                $failures.Add("filter cleanup: $($_.Exception.Message)")
            }
        } elseif ($State.FiltersAdded) {
            $failures.Add(
                "filter cleanup skipped because stopped capture state was not proven; filters were preserved"
            )
        }
        if ($State.MutexHeld) {
            try { $State.Mutex.ReleaseMutex() }
            catch { $failures.Add("mutex release: $($_.Exception.Message)") }
            $State.MutexHeld = $false
        }
        $State.Mutex.Dispose()
    }
    return [pscustomobject]@{
        CaptureStopStatus = $captureStopStatus
        Status = if ($failures.Count -eq 0) { "PASS" } else { "FAIL" }
        Failures = $failures.ToArray()
    }
}

function New-SharedUdpDiagnosticLedgerReader {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
        4096,
        [IO.FileOptions]::SequentialScan
    )
    try {
        return [IO.StreamReader]::new(
            $stream,
            [Text.UTF8Encoding]::new($false, $true),
            $true,
            4096,
            $false
        )
    } catch {
        $stream.Dispose()
        throw
    }
}

function Get-SharedUdpDiagnosticLedgerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
        4096,
        [IO.FileOptions]::SequentialScan
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($stream)).
            Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Copy-SharedUdpDiagnosticLedgerFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $sourceStream = $null
    $destinationStream = $null
    try {
        $sourceStream = [IO.FileStream]::new(
            $Source,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
            81920,
            [IO.FileOptions]::SequentialScan
        )
        $destinationStream = [IO.FileStream]::new(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read,
            81920,
            [IO.FileOptions]::None
        )
        $sourceStream.CopyTo($destinationStream, 81920)
        $destinationStream.Flush()
    } finally {
        if ($null -ne $destinationStream) { $destinationStream.Dispose() }
        if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    }
}

function Get-UdpDiagnosticLedgerSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)][int]$ExpectedMaxEvents,
        [long]$MaximumBytes = 268451840
    )
    $resolved = Resolve-Ferrum2HostInput `
        -RepositoryRoot $repositoryRoot -Kind ExternalFile `
        -Path $Path -Label "UDP diagnostic ledger" `
        -MaximumBytes $MaximumBytes
    $recordCount = 0
    $eventCount = 0
    $matchingRunNonceEvents = 0
    $headerRecord = $null
    $lastRecord = $null
    $truncationRecord = $null
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $resolved
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $recordCount++
            if ($recordCount -gt ($ExpectedMaxEvents + 3)) {
                throw "UDP diagnostic ledger exceeds its record boundary"
            }
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "UDP diagnostic ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.schema -cne $ExpectedSchema) {
                throw "UDP diagnostic ledger schema mismatch"
            }
            if ($recordCount -eq 1) {
                if ([string]$record.record_type -cne "header" -or
                    [string]$record.run_nonce -cne $ExpectedRunNonce -or
                    [int]$record.max_events -ne $ExpectedMaxEvents) {
                    throw "UDP diagnostic ledger header identity mismatch"
                }
                $headerRecord = $record
            } elseif ([string]$record.record_type -ceq "event") {
                $eventCount++
                if ($record.PSObject.Properties.Name -ccontains
                        "payload_run_nonce_match" -and
                    $record.payload_run_nonce_match -eq $true -and
                    [string]$record.payload_run_nonce -ceq $ExpectedRunNonce) {
                    $matchingRunNonceEvents++
                }
            } elseif ([string]$record.record_type -ceq "truncation") {
                $truncationRecord = $record
            }
            $lastRecord = $record
        }
    } finally {
        $reader.Dispose()
    }
    if ($recordCount -lt 1) { throw "UDP diagnostic ledger is empty" }
    $closed = [string]$lastRecord.record_type -ceq "footer" -and
        [string]$lastRecord.run_nonce -ceq $ExpectedRunNonce -and
        $lastRecord.closed -eq $true
    $droppedEvents = if ($closed) {
        [long]$lastRecord.dropped_events
    } elseif ($null -ne $truncationRecord) {
        [long]$truncationRecord.dropped_events_at_least
    } elseif ([string]$lastRecord.record_type -ceq "event" -and
        $null -ne $lastRecord.ledger_counters) {
        [long]$lastRecord.ledger_counters.dropped_events
    } else {
        [long]0
    }
    $writeFailures = if ($closed) {
        [long]$lastRecord.write_failures
    } elseif ($null -ne $truncationRecord) {
        [long]$truncationRecord.write_failures
    } elseif ([string]$lastRecord.record_type -ceq "event" -and
        $null -ne $lastRecord.ledger_counters) {
        [long]$lastRecord.ledger_counters.write_failures
    } else {
        [long]0
    }
    return [pscustomobject]@{
        Path = $resolved
        Bytes = [long](Get-Item -LiteralPath $resolved -Force).Length
        Sha256 = Get-SharedUdpDiagnosticLedgerSha256 -Path $resolved
        Records = $recordCount
        Events = $eventCount
        MatchingRunNonceEvents = $matchingRunNonceEvents
        Header = $headerRecord
        Closed = $closed
        DroppedEvents = $droppedEvents
        WriteFailures = $writeFailures
    }
}

function Get-StableUdpDiagnosticLedgerFileState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $before = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($before.PSIsContainer -or
        $before.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $before.Length -le 0 -or $before.Length -gt 268451840) {
        throw "$Label is outside its stable-copy boundary"
    }
    $beforeLength = [long]$before.Length
    $beforeWriteTicks = [long]$before.LastWriteTimeUtc.Ticks
    $sha256 = Get-SharedUdpDiagnosticLedgerSha256 -Path $before.FullName
    $afterHash = Get-Item -LiteralPath $before.FullName -Force -ErrorAction Stop
    if ([long]$afterHash.Length -ne $beforeLength -or
        [long]$afterHash.LastWriteTimeUtc.Ticks -ne $beforeWriteTicks) {
        throw "$Label changed while its hash was calculated"
    }
    return [pscustomobject]@{
        Path = $before.FullName
        Bytes = $beforeLength
        LastWriteTimeUtcTicks = $beforeWriteTicks
        Sha256 = $sha256
    }
}

function Copy-StableUdpDiagnosticLedger {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination) {
        throw "support diagnostic ledger copy baseline is not absent"
    }
    $sourceBefore = Get-StableUdpDiagnosticLedgerFileState `
        -Path $Source -Label "support diagnostic ledger before copy"
    Copy-SharedUdpDiagnosticLedgerFile -Source $sourceBefore.Path `
        -Destination $Destination
    $sourceAfter = Get-StableUdpDiagnosticLedgerFileState `
        -Path $sourceBefore.Path -Label "support diagnostic ledger after copy"
    $destinationState = Get-StableUdpDiagnosticLedgerFileState `
        -Path $Destination -Label "support diagnostic ledger copy"
    if ($sourceBefore.Bytes -ne $sourceAfter.Bytes -or
        $sourceBefore.LastWriteTimeUtcTicks -ne
            $sourceAfter.LastWriteTimeUtcTicks -or
        $sourceBefore.Sha256 -cne $sourceAfter.Sha256 -or
        $destinationState.Bytes -ne $sourceAfter.Bytes -or
        $destinationState.Sha256 -cne $sourceAfter.Sha256) {
        throw "support diagnostic ledger changed during its single stable-copy attempt"
    }
    return $destinationState
}

function New-UdpDiagnosticArtifactRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$LedgerSummary,
        [int]$MaxEvents = 0,
        [ValidateSet("COMPLETE", "PARTIAL")]
        [string]$StateOverride
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required UDP diagnostic artifact is missing: role=$Role"
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $item.Length -le 0 -or $item.Length -gt 134217728) {
        throw "UDP diagnostic artifact boundary is invalid: role=$Role"
    }
    return [ordered]@{
        role = $Role
        state = if (-not [string]::IsNullOrWhiteSpace($StateOverride)) {
            $StateOverride
        } elseif ($null -ne $LedgerSummary -and (
            -not $LedgerSummary.Closed -or
            $LedgerSummary.DroppedEvents -ne 0 -or
            $LedgerSummary.WriteFailures -ne 0
        )) { "PARTIAL" } else { "COMPLETE" }
        file = [IO.Path]::GetRelativePath($script:hostDiagnosticRoot, $item.FullName).
            Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).
            Hash.ToLowerInvariant()
        bytes = [long]$item.Length
        records = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.Events
        } else {
            $null
        }
        max_events = if ($MaxEvents -gt 0) { $MaxEvents } else { $null }
        dropped_events = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.DroppedEvents
        } else {
            [long]0
        }
        write_failures = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.WriteFailures
        } else {
            [long]0
        }
    }
}

function Get-UdpDiagnosticArtifactTotalByteCount {
    param(
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[object]]$Artifacts
    )
    [long]$total = 0
    foreach ($artifact in $Artifacts) {
        if (-not ($artifact -is [Collections.IDictionary]) -or
            -not $artifact.Contains("bytes")) {
            throw "UDP diagnostic artifact record is missing its byte count"
        }
        [long]$artifactBytes = $artifact["bytes"]
        if ($artifactBytes -le 0 -or
            $total -gt ([long]::MaxValue - $artifactBytes)) {
            throw "UDP diagnostic artifact byte count is invalid"
        }
        $total += $artifactBytes
    }
    return $total
}

function Get-FirstFailedUdpDiagnosticFlow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$MaximumEvents
    )
    $eventCount = 0
    $firstNotObserved = $null
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $Path
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "workload flow ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.record_type -cne "event") { continue }
            $eventCount++
            if ($eventCount -gt $MaximumEvents) {
                throw "workload flow ledger exceeds its event boundary"
            }
            $sendResult = [string]$record.send_result
            $replyResult = [string]$record.reply_result
            if ($sendResult -cne "success" -or
                $replyResult -notin @("success", "not_observed") -or
                ($replyResult -ceq "success" -and $record.payload_match -ne $true)) {
                return $record
            }
            if ($replyResult -ceq "not_observed" -and $null -eq $firstNotObserved) {
                $firstNotObserved = $record
            }
        }
    } finally {
        $reader.Dispose()
    }
    return $firstNotObserved
}

function Get-SupportUdpBoundaryForFlow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][object]$Flow,
        [Parameter(Mandatory = $true)][int]$MaximumEvents
    )
    $rx = $null
    $tx = $null
    $eventCount = 0
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $Path
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "support ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.record_type -cne "event") { continue }
            $eventCount++
            if ($eventCount -gt $MaximumEvents) {
                throw "support ledger exceeds its event boundary"
            }
            if ([string]$record.payload_run_nonce -cne $RunNonce -or
                [string]$record.packet_nonce -cne [string]$Flow.packet_nonce -or
                [int]$record.trial_sequence -ne [int]$Flow.trial_sequence -or
                [string]$record.phase -cne [string]$Flow.phase -or
                [int]$record.association_index -ne [int]$Flow.association_index -or
                [int]$record.round -ne [int]$Flow.round) {
                continue
            }
            if ([string]$record.stage -ceq "rx" -and $null -eq $rx) { $rx = $record }
            if ([string]$record.stage -ceq "tx" -and $null -eq $tx) { $tx = $record }
        }
    } finally {
        $reader.Dispose()
    }
    return [pscustomobject]@{ Rx = $rx; Tx = $tx }
}
