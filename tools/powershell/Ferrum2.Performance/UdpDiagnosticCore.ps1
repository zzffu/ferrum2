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
