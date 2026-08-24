#requires -Version 7.4

<#
.SYNOPSIS
Runs the bounded, diagnostic-only Windows TUN UDP association workload.

.DESCRIPTION
This helper is staged into the approved Hyper-V guest by
run_windows_tun_performance_hyperv.ps1. It does not start or stop Ferrum2 product
processes and it never emits canonical performance evidence. A nonzero workload
exit is an observed diagnostic result: the helper retains the partial flow
ledger, endpoint snapshots, metrics, and bounded process output before returning
control to the guest controller.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("UdpFlowBoundary")]
    [string]$Profile,

    [Parameter(Mandatory = $true)]
    [ValidateSet("calibration-aa")]
    [string]$RunKind,

    [Parameter(Mandatory = $true)]
    [ValidateSet("parent")]
    [string]$Member,

    [Parameter(Mandatory = $true)]
    [ValidateRange(31, 31)]
    [int]$TrialSequence,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ParentSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Tree,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$RecipeSha256,

    [Parameter(Mandatory = $true)]
    [string]$HarnessBinary,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Ferrum2Perf")]
    [string]$TunAdapterName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $parsed = $null
        [Net.IPAddress]::TryParse($_, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
    })]
    [string]$TargetIpv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$TargetTcpPort,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65532)]
    [int]$TargetUdpPort,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ClientPid,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ServerPid,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$ClientMetricsPort,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$DiagnosticRunNonce,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65536)]
    [int]$DiagnosticMaxEvents,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$startedUtc = [DateTime]::UtcNow.ToString("o")
$diagnosticSourceIpv4 = "198.18.0.2"
$diagnosticSourcePortFirst = 20000
$diagnosticSourcePortLast = 28191
$diagnosticSourcePortCount = 8192
$workloadLedgerSchema = "ferrum2.windows-tun.udp-workload-flow-ledger.v3"

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Resolve-NormalizedLeaf {
    param([string]$Path, [string]$Label, [long]$MaximumBytes)
    Assert-Condition ([IO.Path]::IsPathFullyQualified($Path)) "$Label path must be absolute"
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    Assert-Condition (-not $item.PSIsContainer) "$Label is not a file"
    Assert-Condition (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) `
        "$Label cannot be a reparse point"
    Assert-Condition ($item.Length -gt 0 -and $item.Length -le $MaximumBytes) `
        "$Label size is outside its boundary"
    return $resolved
}

function Write-NewUtf8File {
    param([string]$Path, [string]$Text, [long]$MaximumBytes)
    Assert-Condition (-not (Test-Path -LiteralPath $Path)) "output baseline is not absent: $Path"
    Assert-Condition ($script:utf8NoBom.GetByteCount($Text) -le $MaximumBytes) `
        "output exceeds its byte boundary: $Path"
    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function Invoke-BoundedNativeProcess {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$StdoutPath,
        [string]$StderrPath,
        [long]$MaximumOutputBytes,
        [int]$TimeoutSeconds,
        [string]$Label
    )
    foreach ($argument in $Arguments) {
        Assert-Condition ($argument -cnotmatch '["\r\n]') `
            "$Label contains an unsupported native argument"
    }
    Assert-Condition (-not (Test-Path -LiteralPath $StdoutPath)) `
        "$Label stdout baseline is not absent"
    Assert-Condition (-not (Test-Path -LiteralPath $StderrPath)) `
        "$Label stderr baseline is not absent"
    $quotedArguments = @($Arguments | ForEach-Object {
        if ($_ -cmatch '\s') { '"{0}"' -f $_ } else { $_ }
    })
    $startParameters = @{
        FilePath = $Executable
        ArgumentList = $quotedArguments
        WindowStyle = "Hidden"
        RedirectStandardOutput = $StdoutPath
        RedirectStandardError = $StderrPath
        PassThru = $true
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $startParameters.WorkingDirectory = $WorkingDirectory
    }
    $process = Start-Process @startParameters
    $processId = $process.Id
    $timedOut = $false
    $outputBoundaryExceeded = $false
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $stdoutBytes = if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $StdoutPath -Force).Length
            } else { [long]0 }
            $stderrBytes = if (Test-Path -LiteralPath $StderrPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $StderrPath -Force).Length
            } else { [long]0 }
            if ($stdoutBytes + $stderrBytes -gt $MaximumOutputBytes) {
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
                catch { throw "$Label termination request failed: $($_.Exception.Message)" }
            }
        }
        Assert-Condition ($process.WaitForExit(10000)) "$Label process could not be reaped"
        return [pscustomobject]@{
            Pid = $processId
            ExitCode = $process.ExitCode
            TimedOut = $timedOut
            OutputBoundaryExceeded = $outputBoundaryExceeded
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-NetshBounded {
    param([string[]]$Arguments)
    $temporaryToken = [Guid]::NewGuid().ToString("N")
    $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) `
        "ferrum2-netsh-$temporaryToken.stdout"
    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) `
        "ferrum2-netsh-$temporaryToken.stderr"
    try {
        $result = Invoke-BoundedNativeProcess -Executable "netsh.exe" `
            -Arguments $Arguments -WorkingDirectory "" `
            -StdoutPath $stdoutPath -StderrPath $stderrPath `
            -MaximumOutputBytes 131072 -TimeoutSeconds 30 -Label "netsh snapshot"
        Assert-Condition (-not $result.TimedOut) "netsh snapshot timed out"
        Assert-Condition (-not $result.OutputBoundaryExceeded) `
            "netsh snapshot exceeded 128 KiB"
        Assert-Condition ($result.ExitCode -eq 0) `
            "netsh snapshot failed: $($Arguments -join ' ')"
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            foreach ($line in [IO.File]::ReadLines($path)) {
                Assert-Condition ($lines.Count -lt 512) `
                    "netsh snapshot exceeded 512 lines"
                $lines.Add(([string]$line -replace "[\r\n]+", " ").TrimEnd())
            }
        }
    } finally {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) { [IO.File]::Delete($path) }
        }
    }
    $lineArray = $lines.ToArray()
    $exitCode = $result.ExitCode
    $text = $lineArray -join "`n"
    Assert-Condition ($exitCode -eq 0) "netsh snapshot failed: $($Arguments -join ' ')"
    Assert-Condition ($script:utf8NoBom.GetByteCount($text) -le 131072) `
        "netsh snapshot exceeded 128 KiB"
    return [ordered]@{
        command = "netsh.exe $($Arguments -join ' ')"
        exit_code = $exitCode
        total_lines = $lineArray.Count
        truncated = $false
        lines = $lineArray
    }
}

function Test-PortRangeIntersection {
    param(
        [int]$FirstA,
        [int]$LastA,
        [int]$FirstB,
        [int]$LastB
    )
    return $FirstA -le $LastB -and $FirstB -le $LastA
}

function ConvertFrom-NetshUdpDynamicPortRange {
    param([object]$Snapshot)
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

function ConvertFrom-NetshUdpExcludedPortRangeOutput {
    param([object]$Snapshot)
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

function Get-DiagnosticSourcePreflight {
    param([string]$AdapterName)
    $violations = [Collections.Generic.List[string]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $adapterRows = @()
    try {
        $adapterRows = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq $AdapterName
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
            [string]$_.IPAddress -ceq $script:diagnosticSourceIpv4
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
            [int]$_.LocalPort -ge $script:diagnosticSourcePortFirst -and
            [int]$_.LocalPort -le $script:diagnosticSourcePortLast
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
            -FirstA $script:diagnosticSourcePortFirst `
            -LastA $script:diagnosticSourcePortLast `
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
                    -FirstA $script:diagnosticSourcePortFirst `
                    -LastA $script:diagnosticSourcePortLast `
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
            adapter_name = $AdapterName
            source_ip = $script:diagnosticSourceIpv4
            source_prefix_length = 30
            source_port_first = $script:diagnosticSourcePortFirst
            source_port_last = $script:diagnosticSourcePortLast
            source_port_count = $script:diagnosticSourcePortCount
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

function Write-UdpEndpointSnapshot {
    param(
        [string]$Path,
        [string]$Stage,
        [int]$ClientProcessId,
        [int]$ServerProcessId,
        [object]$SourcePreflight
    )
    $allEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Sort-Object `
        OwningProcess, LocalAddress, LocalPort)
    $productEndpoints = @($allEndpoints | Where-Object {
        [int]$_.OwningProcess -in @($ClientProcessId, $ServerProcessId)
    })
    $otherEndpoints = @($allEndpoints | Where-Object {
        [int]$_.OwningProcess -notin @($ClientProcessId, $ServerProcessId)
    } | Select-Object -First ([Math]::Max(0, 8192 - $productEndpoints.Count)))
    $selectedEndpoints = @($productEndpoints) + @($otherEndpoints)
    $selected = @($selectedEndpoints | ForEach-Object {
        $role = if ([int]$_.OwningProcess -eq $ClientProcessId) {
            "ferrum2-client"
        } elseif ([int]$_.OwningProcess -eq $ServerProcessId) {
            "ferrum2-server"
        } else {
            "other"
        }
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            owning_process = [int]$_.OwningProcess
            role = $role
        }
    })
    $topOwners = @($allEndpoints | Group-Object OwningProcess | Sort-Object Count -Descending |
        Select-Object -First 64 | ForEach-Object {
            $processId = [int]$_.Name
            $processName = $null
            try { $processName = [string](Get-Process -Id $processId -ErrorAction Stop).ProcessName }
            catch { $processName = $null }
            [ordered]@{
                owning_process = $processId
                process_name = $processName
                endpoint_count = $_.Count
            }
        })
    if ($PSBoundParameters.ContainsKey("SourcePreflight")) {
        $dynamicPortUdp = $SourcePreflight.dynamic_port_udp
        $excludedPortRangesUdp = $SourcePreflight.excluded_port_ranges_udp
    } else {
        $dynamicPortUdp = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "dynamicport", "udp"
        )
        $excludedPortRangesUdp = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "excludedportrange", "protocol=udp"
        )
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.udp-endpoint-snapshot.v2"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        scope = "ferrum2-product-endpoints-with-bounded-system-context"
        workload_tuple_source = "udp-workload-flow-ledger.ndjson"
        diagnostic_source_preflight = $SourcePreflight
        dynamic_port_udp = $dynamicPortUdp
        excluded_port_ranges_udp = $excludedPortRangesUdp
        endpoint_count = $allEndpoints.Count
        retained_endpoint_count = $selected.Count
        endpoints_truncated = $allEndpoints.Count -gt $selected.Count
        endpoints = $selected
        top_endpoint_owners = $topOwners
    }
    Write-NewUtf8File -Path $Path `
        -Text (($document | ConvertTo-Json -Depth 8) + "`n") -MaximumBytes 4194304
}

function Write-UdpEndpointErrorSnapshot {
    param(
        [string]$Path,
        [string]$Stage,
        [int]$ClientProcessId,
        [int]$ServerProcessId,
        [string]$Failure,
        [object]$SourcePreflight
    )
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        Assert-Condition (-not $existing.PSIsContainer -and
            -not ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) `
            "endpoint error snapshot target is unsafe"
        [IO.File]::Delete($existing.FullName)
    }
    $boundedFailure = ($Failure -replace '[\r\n]+', ' ').Trim()
    if ($boundedFailure.Length -gt 2048) {
        $boundedFailure = $boundedFailure.Substring(0, 2048)
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.udp-endpoint-snapshot.v2"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        scope = "ferrum2-product-endpoints-with-bounded-system-context"
        workload_tuple_source = "udp-workload-flow-ledger.ndjson"
        diagnostic_source_preflight = $SourcePreflight
        client_pid = $ClientProcessId
        server_pid = $ServerProcessId
        state = "PARTIAL"
        error = $boundedFailure
    }
    Write-NewUtf8File -Path $Path `
        -Text (($document | ConvertTo-Json -Depth 4) + "`n") -MaximumBytes 65536
}

function Write-MetricsErrorSnapshot {
    param([string]$Path, [string]$Stage, [string]$Failure)
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        Assert-Condition (-not $existing.PSIsContainer -and
            -not ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) `
            "metrics error snapshot target is unsafe"
        [IO.File]::Delete($existing.FullName)
    }
    $boundedFailure = ($Failure -replace '[\r\n]+', ' ').Trim()
    if ($boundedFailure.Length -gt 2048) {
        $boundedFailure = $boundedFailure.Substring(0, 2048)
    }
    $text = "ferrum2_udp_metrics_snapshot state=PARTIAL stage=$Stage error=$boundedFailure`n"
    Write-NewUtf8File -Path $Path -Text $text -MaximumBytes 4096
}

function Get-BoundedMetricsText {
    param([int]$Port, [int]$MaximumBytes = 1048576)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $cancellation = [Threading.CancellationTokenSource]::new(
        [TimeSpan]::FromSeconds(5)
    )
    $response = $null
    $stream = $null
    $buffered = [IO.MemoryStream]::new()
    try {
        $response = $client.GetAsync(
            "http://127.0.0.1:$Port/metrics",
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancellation.Token
        ).GetAwaiter().GetResult()
        Assert-Condition ($response.StatusCode -eq [Net.HttpStatusCode]::OK) `
            "client metrics endpoint did not return HTTP 200"
        $contentLength = $response.Content.Headers.ContentLength
        Assert-Condition ($null -eq $contentLength -or
            [long]$contentLength -le $MaximumBytes) `
            "client metrics snapshot exceeds its declared byte boundary"
        $stream = $response.Content.ReadAsStreamAsync($cancellation.Token).
            GetAwaiter().GetResult()
        $buffer = [byte[]]::new(8192)
        while ($true) {
            $remaining = ([long]$MaximumBytes + 1L) - $buffered.Length
            if ($remaining -le 0) {
                throw "client metrics snapshot exceeds its byte boundary"
            }
            $readLength = [int][Math]::Min([long]$buffer.Length, $remaining)
            $read = $stream.ReadAsync(
                $buffer, 0, $readLength, $cancellation.Token
            ).GetAwaiter().GetResult()
            if ($read -eq 0) { break }
            $buffered.Write($buffer, 0, $read)
        }
        Assert-Condition ($buffered.Length -gt 0 -and
            $buffered.Length -le $MaximumBytes) `
            "client metrics snapshot is empty or too large"
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        return $strictUtf8.GetString($buffered.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $buffered.Dispose()
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-FileEvidence {
    param([string]$Path, [long]$MaximumBytes)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    Assert-Condition (-not $item.PSIsContainer -and
        -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        $item.Length -ge 0 -and $item.Length -le $MaximumBytes) `
        "diagnostic artifact size is outside its boundary"
    return [ordered]@{
        file = [IO.Path]::GetFileName($resolved)
        bytes = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

Assert-Condition ($ParentSha -ceq $CandidateSha) `
    "UdpFlowBoundary requires identical parent and candidate SHAs"
Assert-Condition ($diagnosticSourcePortLast - $diagnosticSourcePortFirst + 1 -eq
        $diagnosticSourcePortCount) "diagnostic source port contract is inconsistent"
Assert-Condition ($DiagnosticMaxEvents -ge $diagnosticSourcePortCount) `
    "diagnostic max-events cannot retain the fixed source-port coverage"
$nonceValue = [uint64]0
Assert-Condition ([uint64]::TryParse(
        $DiagnosticRunNonce,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$nonceValue
    ) -and $nonceValue -ne 0 -and $nonceValue.ToString(
        [Globalization.CultureInfo]::InvariantCulture
    ) -ceq $DiagnosticRunNonce) "diagnostic run nonce is not canonical"

$harness = Resolve-NormalizedLeaf -Path $HarnessBinary -Label "traffic harness" `
    -MaximumBytes 536870912
$harnessSha256 = (Get-FileHash -LiteralPath $harness -Algorithm SHA256).
    Hash.ToLowerInvariant()
$collectorSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
Assert-Condition ([IO.Path]::IsPathFullyQualified($OutputDirectory)) `
    "diagnostic output directory must be absolute"
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
Assert-Condition ((Test-Path -LiteralPath $outputRoot -PathType Container)) `
    "diagnostic output directory does not exist"
Assert-Condition (-not ((Get-Item -LiteralPath $outputRoot -Force).Attributes -band `
        [IO.FileAttributes]::ReparsePoint)) "diagnostic output directory cannot be a reparse point"
$outputPath = [IO.Path]::GetFullPath($Output)
$outputPrefix = $outputRoot + [IO.Path]::DirectorySeparatorChar
Assert-Condition ($outputPath.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) `
    "diagnostic output must remain inside its output directory"
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) `
    "diagnostic raw output baseline is not absent"

$preSnapshot = Join-Path $outputRoot "guest-endpoints-pre.json"
$postSnapshot = Join-Path $outputRoot "guest-endpoints-post.json"
$metricsPrePath = Join-Path $outputRoot "client-metrics-pre.txt"
$metricsPostPath = Join-Path $outputRoot "client-metrics-post.txt"
$ledgerPath = Join-Path $outputRoot "udp-workload-flow-ledger.ndjson"
$observationPath = Join-Path $outputRoot "workload-observation.json"
$stdoutPath = Join-Path $outputRoot "workload.stdout.log"
$stderrPath = Join-Path $outputRoot "workload.stderr.log"
$workloadPid = 0
$workloadExitCode = $null
$workloadTimedOut = $false
$infrastructureError = $null
$snapshotErrors = [Collections.Generic.List[string]]::new()
$sourcePreflight = $null

try {
    $sourcePreflight = Get-DiagnosticSourcePreflight -AdapterName $TunAdapterName
    try {
        Write-UdpEndpointSnapshot -Path $preSnapshot -Stage "pre_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
            -SourcePreflight $sourcePreflight
    }
    catch {
        $snapshotErrors.Add("pre endpoint snapshot: $($_.Exception.Message)")
        Write-UdpEndpointErrorSnapshot -Path $preSnapshot -Stage "pre_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
            -Failure $_.Exception.Message -SourcePreflight $sourcePreflight
    }
    Assert-Condition ($sourcePreflight.valid -eq $true) `
        "fixed diagnostic source preflight failed: $($sourcePreflight.violations -join ',')"
    try {
        $metrics = Get-BoundedMetricsText -Port $ClientMetricsPort
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($metrics)) `
            "client pre-workload metrics snapshot is empty"
        Write-NewUtf8File -Path $metricsPrePath -Text $metrics -MaximumBytes 1048576
    } catch {
        $snapshotErrors.Add("client pre-workload metrics snapshot: $($_.Exception.Message)")
        Write-MetricsErrorSnapshot -Path $metricsPrePath -Stage "pre_workload" `
            -Failure $_.Exception.Message
    }

    $workloadArguments = @(
        "windows-tun-workload",
        "--scenario", "udp-8192-association-lookup-expiry",
        "--target-ip", $TargetIpv4,
        "--tcp-port", [string]$TargetTcpPort,
        "--udp-port", [string]$TargetUdpPort,
        "--output", $observationPath,
        "--diagnostic-ledger", $ledgerPath,
        "--diagnostic-run-nonce", $DiagnosticRunNonce,
        "--diagnostic-max-events", [string]$DiagnosticMaxEvents,
        "--diagnostic-trial-sequence", [string]$TrialSequence,
        "--source-ip", $diagnosticSourceIpv4,
        "--source-port-first", [string]$diagnosticSourcePortFirst,
        "--source-port-last", [string]$diagnosticSourcePortLast
    )
    $workloadResult = Invoke-BoundedNativeProcess -Executable $harness `
        -Arguments $workloadArguments -WorkingDirectory (Split-Path -Parent $harness) `
        -StdoutPath $stdoutPath -StderrPath $stderrPath `
        -MaximumOutputBytes 131072 -TimeoutSeconds 1800 `
        -Label "diagnostic workload"
    $workloadPid = $workloadResult.Pid
    $workloadExitCode = $workloadResult.ExitCode
    $workloadTimedOut = $workloadResult.TimedOut
    if ($workloadResult.OutputBoundaryExceeded) {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                (Get-Item -LiteralPath $path -Force).Length -gt 65536) {
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write)
                try { $stream.SetLength(65536) } finally { $stream.Dispose() }
            }
        }
        throw "diagnostic workload output exceeded 128 KiB"
    }
} catch {
    $infrastructureError = $_.Exception.Message
} finally {
    try {
        Write-UdpEndpointSnapshot -Path $postSnapshot -Stage "post_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid
    }
    catch {
        $snapshotErrors.Add("post endpoint snapshot: $($_.Exception.Message)")
        try {
            Write-UdpEndpointErrorSnapshot -Path $postSnapshot -Stage "post_workload" `
                -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
                -Failure $_.Exception.Message
        } catch {
            $snapshotErrors.Add("post endpoint error document: $($_.Exception.Message)")
        }
    }
    try {
        $metrics = Get-BoundedMetricsText -Port $ClientMetricsPort
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($metrics)) `
            "client post-workload metrics snapshot is empty"
        Write-NewUtf8File -Path $metricsPostPath -Text $metrics -MaximumBytes 1048576
    } catch {
        $snapshotErrors.Add("client metrics snapshot: $($_.Exception.Message)")
        try {
            Write-MetricsErrorSnapshot -Path $metricsPostPath -Stage "post_workload" `
                -Failure $_.Exception.Message
        } catch {
            $snapshotErrors.Add("post metrics error document: $($_.Exception.Message)")
        }
    }
}

$ledgerHeaderValid = $false
$ledgerLines = 0
$ledgerError = $null
$ledgerClosed = $false
$ledgerTruncated = $false
$ledgerDroppedEvents = $null
$ledgerWriteFailures = $null
$ledgerBootstrapEventCount = 0
$ledgerSourcePrefixValid = $false
$ledgerSourceComplete = $false
try {
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
        throw "workload flow ledger was not created"
    }
    $ledgerItem = Get-Item -LiteralPath $ledgerPath -Force
    $maximumLedgerBytes = 16384L + ([long]$DiagnosticMaxEvents * 4097L)
    Assert-Condition ($ledgerItem.Length -gt 0 -and $ledgerItem.Length -le $maximumLedgerBytes) `
        "workload flow ledger exceeds its byte boundary"
    $headerLine = [IO.File]::ReadLines($ledgerPath) | Select-Object -First 1
    $header = $headerLine | ConvertFrom-Json -ErrorAction Stop
    $expectedHeaderFields = @(
        "closure", "max_events", "record_type", "run_nonce", "schema", "scope",
        "source_ip", "source_port_first", "source_port_last", "timestamp_clock",
        "trial_sequence"
    )
    $actualHeaderFields = @($header.PSObject.Properties.Name | Sort-Object)
    $ledgerHeaderValid = ($actualHeaderFields -join "`n") -ceq
        ($expectedHeaderFields -join "`n") -and
        [string]$header.schema -ceq `
        $workloadLedgerSchema -and
        [string]$header.record_type -ceq "header" -and
        [string]$header.scope -ceq "bootstrap" -and
        [string]$header.closure -ceq "workload_process_exit" -and
        [string]$header.run_nonce -ceq $DiagnosticRunNonce -and
        [string]$header.timestamp_clock -ceq
            "std_instant_normalized_nanoseconds" -and
        [int]$header.max_events -eq $DiagnosticMaxEvents -and
        [int]$header.trial_sequence -eq $TrialSequence -and
        [string]$header.source_ip -ceq $diagnosticSourceIpv4 -and
        [int]$header.source_port_first -eq $diagnosticSourcePortFirst -and
        [int]$header.source_port_last -eq $diagnosticSourcePortLast -and
        [int]$header.source_port_last - [int]$header.source_port_first + 1 -eq
            $diagnosticSourcePortCount
    Assert-Condition $ledgerHeaderValid "workload flow ledger header identity mismatch"
    $footer = $null
    $seenFooter = $false
    $seenTruncation = $false
    foreach ($line in [IO.File]::ReadLines($ledgerPath)) {
        $ledgerLines++
        Assert-Condition ($ledgerLines -le ($DiagnosticMaxEvents + 3)) `
            "workload flow ledger exceeds its line boundary"
        Assert-Condition ($script:utf8NoBom.GetByteCount($line) -le 4096) `
            "workload flow ledger line exceeds 4096 bytes"
        $record = $line | ConvertFrom-Json -ErrorAction Stop
        Assert-Condition ([string]$record.schema -ceq $workloadLedgerSchema) `
            "workload flow ledger record schema mismatch"
        if ($ledgerLines -eq 1) {
            Assert-Condition ([string]$record.record_type -ceq "header") `
                "workload flow ledger first record is not its header"
            continue
        }
        Assert-Condition (-not $seenFooter) `
            "workload flow ledger contains a record after its footer"
        if ([string]$record.record_type -ceq "truncation") {
            Assert-Condition (-not $seenTruncation) `
                "workload flow ledger contains duplicate truncation records"
            $seenTruncation = $true
            $ledgerTruncated = $true
            $ledgerDroppedEvents = [long]$record.dropped_events_at_least
            $ledgerWriteFailures = [long]$record.write_failures
        } elseif ([string]$record.record_type -ceq "event") {
            Assert-Condition (-not $seenTruncation) `
                "workload flow ledger contains an event after truncation"
            $requiredEventFields = @(
                "schema", "record_type", "event_index", "run_nonce",
                "trial_sequence", "phase", "association_index", "round",
                "workload_local_ip", "workload_local_port"
            )
            $actualEventFields = @($record.PSObject.Properties.Name)
            Assert-Condition (@($requiredEventFields | Where-Object {
                $actualEventFields -cnotcontains $_
            }).Count -eq 0) "workload flow ledger event source identity is incomplete"
            $expectedAssociationIndex = $ledgerBootstrapEventCount
            Assert-Condition ([string]$record.schema -ceq $workloadLedgerSchema -and
                [string]$record.run_nonce -ceq $DiagnosticRunNonce -and
                [int]$record.trial_sequence -eq $TrialSequence -and
                [string]$record.phase -ceq "bootstrap" -and
                [long]$record.event_index -eq $expectedAssociationIndex -and
                [long]$record.association_index -eq $expectedAssociationIndex -and
                [long]$record.round -eq 0 -and
                [string]$record.workload_local_ip -ceq $diagnosticSourceIpv4 -and
                [int]$record.workload_local_port -eq
                    ($diagnosticSourcePortFirst + $expectedAssociationIndex)) `
                "workload flow ledger fixed source-port prefix is invalid"
            $ledgerBootstrapEventCount++
            Assert-Condition ($ledgerBootstrapEventCount -le $diagnosticSourcePortCount) `
                "workload flow ledger exceeds fixed source-port coverage"
        } elseif ([string]$record.record_type -ceq "footer") {
            $seenFooter = $true
            $footer = $record
        } elseif ([string]$record.record_type -ceq "header") {
            throw "workload flow ledger contains a duplicate header"
        } else {
            throw "workload flow ledger contains an unknown record type"
        }
    }
    Assert-Condition ($ledgerLines -le ($DiagnosticMaxEvents + 3)) `
        "workload flow ledger exceeds its line boundary"
    $ledgerSourcePrefixValid = $true
    $ledgerSourceComplete = $ledgerBootstrapEventCount -eq $diagnosticSourcePortCount
    if ($null -ne $footer) {
        $expectedFooterFields = @(
            "attempted_events", "closed", "dropped_events", "events_written",
            "record_type", "run_nonce", "schema", "write_failures"
        )
        $actualFooterFields = @($footer.PSObject.Properties.Name | Sort-Object)
        $ledgerClosed = ($actualFooterFields -join "`n") -ceq
            ($expectedFooterFields -join "`n") -and
            [string]$footer.schema -ceq
            $workloadLedgerSchema -and
            [string]$footer.record_type -ceq "footer" -and
            [string]$footer.run_nonce -ceq $DiagnosticRunNonce -and
            $footer.closed -eq $true -and
            [long]$footer.events_written -eq $ledgerBootstrapEventCount -and
            [long]$footer.attempted_events -eq
                ([long]$footer.events_written + [long]$footer.dropped_events +
                    [long]$footer.write_failures)
        $ledgerDroppedEvents = [long]$footer.dropped_events
        $ledgerWriteFailures = [long]$footer.write_failures
    }
} catch {
    $ledgerError = $_.Exception.Message
}

$observationValid = $false
if (Test-Path -LiteralPath $observationPath -PathType Leaf) {
    try {
        $observation = Get-Content -LiteralPath $observationPath -Raw -Encoding utf8 |
            ConvertFrom-Json -Depth 8 -ErrorAction Stop
        $observationValid = $observation.schema_version -eq 1 -and
            [string]$observation.kind -ceq "windows_tun_guest_workload" -and
            [string]$observation.scenario -ceq `
                "udp-8192-association-lookup-expiry" -and
            [string]$observation.status -ceq "PASS"
    } catch {
        $snapshotErrors.Add("workload observation: $($_.Exception.Message)")
    }
}

$requiredArtifactPaths = @(
    $ledgerPath, $stdoutPath, $stderrPath,
    $preSnapshot, $postSnapshot, $metricsPrePath, $metricsPostPath
)
$requiredArtifactsPresent = @($requiredArtifactPaths | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf)
}).Count -eq 0
$workloadReportedPass = -not $workloadTimedOut -and $workloadExitCode -eq 0 -and
    $observationValid
$ledgerSourceCoverageValid = $ledgerSourcePrefixValid -and (
    -not $workloadReportedPass -or $ledgerSourceComplete
)
if ($workloadReportedPass -and -not $ledgerSourceComplete -and
    $null -eq $ledgerError) {
    $ledgerError = "passing workload did not cover all 8192 fixed source ports"
}
$evidenceStatus = if (
    $null -eq $infrastructureError -and
    $null -eq $ledgerError -and
    $ledgerHeaderValid -and $ledgerClosed -and -not $ledgerTruncated -and
    $ledgerSourceCoverageValid -and
    $ledgerDroppedEvents -eq 0 -and $ledgerWriteFailures -eq 0 -and
    $snapshotErrors.Count -eq 0 -and $requiredArtifactsPresent -and
    -not $workloadTimedOut
) {
    "COMPLETE"
} else {
    "PARTIAL"
}
$trialStatus = if ($workloadReportedPass -and $ledgerSourceCoverageValid) {
    "PASS"
} else {
    "FAIL"
}
$rawDocument = [ordered]@{
    schema = "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v1"
    qualification = $false
    profile = $Profile
    evidence_status = $evidenceStatus
    trial_status = $trialStatus
    started_utc = $startedUtc
    finished_utc = [DateTime]::UtcNow.ToString("o")
    identity = [ordered]@{
        run_kind = $RunKind
        member = $Member
        trial_sequence = $TrialSequence
        parent_sha = $ParentSha
        candidate_sha = $CandidateSha
        tree = $Tree
        recipe_sha256 = $RecipeSha256
        harness_sha256 = $harnessSha256
        collector_sha256 = $collectorSha256
        diagnostic_run_nonce = $DiagnosticRunNonce
        diagnostic_max_events = $DiagnosticMaxEvents
    }
    workload = [ordered]@{
        pid = $workloadPid
        exit_code = $workloadExitCode
        global_timeout = $workloadTimedOut
        observation_valid = $observationValid
        source_ip = $diagnosticSourceIpv4
        source_port_first = $diagnosticSourcePortFirst
        source_port_last = $diagnosticSourcePortLast
        source_preflight = $sourcePreflight
        infrastructure_error = $infrastructureError
        flow_ledger_header_valid = $ledgerHeaderValid
        flow_ledger_lines = $ledgerLines
        flow_ledger_closed = $ledgerClosed
        flow_ledger_truncated = $ledgerTruncated
        flow_ledger_dropped_events = $ledgerDroppedEvents
        flow_ledger_write_failures = $ledgerWriteFailures
        flow_ledger_bootstrap_event_count = $ledgerBootstrapEventCount
        flow_ledger_source_prefix_valid = $ledgerSourcePrefixValid
        flow_ledger_source_complete = $ledgerSourceComplete
        flow_ledger_error = $ledgerError
    }
    artifacts = [ordered]@{
        workload_flow_ledger = Get-FileEvidence $ledgerPath 268451840
        workload_observation = Get-FileEvidence $observationPath 1048576
        workload_stdout = Get-FileEvidence $stdoutPath 131072
        workload_stderr = Get-FileEvidence $stderrPath 131072
        endpoints_pre = Get-FileEvidence $preSnapshot 4194304
        endpoints_post = Get-FileEvidence $postSnapshot 4194304
        client_metrics_pre = Get-FileEvidence $metricsPrePath 1048576
        client_metrics_post = Get-FileEvidence $metricsPostPath 1048576
    }
    snapshot_errors = $snapshotErrors.ToArray()
}
Write-NewUtf8File -Path $outputPath `
    -Text (($rawDocument | ConvertTo-Json -Depth 10) + "`n") -MaximumBytes 1048576
Write-Output "windows_tun_udp_boundary evidence=$evidenceStatus trial=$trialStatus output=$outputPath"
exit 0
