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
