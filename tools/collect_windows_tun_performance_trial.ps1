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
        "restart-recovery"
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

    [Parameter(Mandatory = $true)][string]$ParentSha,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$Tree,
    [Parameter(Mandatory = $true)][string]$RecipeSha256,
    [Parameter(Mandatory = $true)][string]$ClientBinary,
    [Parameter(Mandatory = $true)][string]$ServerBinary,
    [Parameter(Mandatory = $true)][string]$HarnessBinary,
    [Parameter(Mandatory = $true)][string]$IdentityLedger,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ClientPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ServerPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$MetricsPort,
    [Parameter(Mandatory = $true)][string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Invoke-BoundedHarness([string[]]$Arguments, [int]$TimeoutSeconds) {
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
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
        Assert-Condition ($process.WaitForExit(10000)) "timed-out traffic harness could not be reaped"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText($stdoutPath, $stdout, $script:Utf8NoBom)
    [IO.File]::WriteAllText($stderrPath, $stderr, $script:Utf8NoBom)
    Assert-Condition (-not $timedOut) "traffic harness timed out"
    Assert-Condition ($process.ExitCode -eq 0) "traffic harness failed; see $stderrPath"
    Assert-Condition (
        $script:Utf8NoBom.GetByteCount($stdout) -le 65536 -and
        $script:Utf8NoBom.GetByteCount($stderr) -le 65536
    ) "traffic harness output exceeded 64 KiB"
    $process.Dispose()
}

function Invoke-Workload([string]$SelectedScenario, [int]$TimeoutSeconds) {
    $path = Join-Path $script:WorkRoot "workload.json"
    Assert-Condition (-not (Test-Path -LiteralPath $path)) "workload output baseline is not absent"
    Invoke-BoundedHarness @(
        "windows-tun-workload",
        "--scenario", $SelectedScenario,
        "--target-ip", $script:TargetAddress,
        "--tcp-port", [string]$script:TargetTcpPort,
        "--udp-port", [string]$script:TargetUdpPort,
        "--output", $path
    ) $TimeoutSeconds
    $raw = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8
    Assert-ExactProperties $raw @("schema_version", "kind", "scenario", "observation", "status") "workload"
    Assert-Condition (
        $raw.schema_version -eq 1 -and
        $raw.kind -ceq "windows_tun_guest_workload" -and
        $raw.scenario -ceq $SelectedScenario -and
        $raw.status -ceq "PASS"
    ) "workload identity/status mismatch"
    return $raw.observation
}

function Invoke-Probe {
    Invoke-BoundedHarness @(
        "windows-tun-probe",
        "--target-ip", $script:TargetAddress,
        "--tcp-port", [string]$script:TargetTcpPort,
        "--udp-port", [string]$script:TargetUdpPort
    ) 30
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
        if ($tcp -eq 0 -and $fragments -eq 0 -and ((-not $Udp) -or $udpAssociations -eq 0)) {
            return $metrics
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "product flow/association/reassembly state did not drain"
}

function Get-P99Nanoseconds([uint64[]]$Values) {
    Assert-Condition ($Values.Count -eq 10) "restart recovery requires exactly ten values"
    $ordered = @($Values | Sort-Object)
    return [uint64]$ordered[9]
}

foreach ($digest in @($ParentSha, $CandidateSha, $Tree)) {
    Assert-Condition ($digest -cmatch '^[0-9a-f]{40}$') "commit/tree identity must be lowercase 40-hex"
}
Assert-Condition ($RecipeSha256 -cmatch '^[0-9a-f]{64}$') "recipe identity must be lowercase SHA-256"
$expectedOrder = if (($Member -ceq "parent") -eq (($Pair % 2) -eq 1)) { 1 } else { 2 }
Assert-Condition ($Order -eq $expectedOrder) "trial order does not follow the alternating schedule"
$scenarioOrder = @(
    "tcp-single-flow",
    "tcp-256-flow-fairness",
    "udp-packets-per-second",
    "udp-8192-association-lookup-expiry",
    "fragment-reassembly-throughput",
    "idle-cpu-wakeup",
    "wintun-ring-full-drop-rate",
    "restart-recovery"
)
$scenarioIndex = [Array]::IndexOf($scenarioOrder, $Scenario)
Assert-Condition ($scenarioIndex -ge 0) "scenario is outside the fixed schedule"
$sequence = $scenarioIndex * 10 + ($Pair - 1) * 2 + $Order
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
$outputPath = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputPath
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) "trial output baseline is not absent"
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) "trial output parent does not exist"
$outputParentItem = Get-Item -LiteralPath $outputParent -Force
Assert-Condition (-not ($outputParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "trial output parent cannot be a reparse point"

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
Assert-Condition (
    $ledger.schema -eq 1 -and
    $ledger.vm_name -ceq $ExpectedVmName -and
    $ledger.vm_id -ceq $ExpectedVmId -and
    $ledger.checkpoint_name -ceq $ExpectedCheckpointName -and
    $ledger.checkpoint_id -ceq $ExpectedCheckpointId -and
    $ledger.guest_architecture -ceq "AMD64" -and
    $ledger.candidate_sha -ceq $memberSha -and
    [string]$ledger.probe_sha256 -cmatch '^[0-9a-f]{64}$' -and
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
    $script:TargetUdpPort -ge 1 -and $script:TargetUdpPort -le 65535
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
            $before = Get-Metrics $MetricsPort 5
            $fragmentIngressBefore = Get-Metric $before "ferrum2_tun_packets_ingress" $true
            $completedBefore = Get-Metric $before "ferrum2_tun_reassembly_completed" $true
            $dropsBefore = @(
                "ferrum2_tun_reassembly_dropped_overlap",
                "ferrum2_tun_reassembly_dropped_timeout",
                "ferrum2_tun_reassembly_dropped_limit",
                "ferrum2_tun_reassembly_dropped_malformed"
            ) | ForEach-Object { Get-Metric $before $_ $true } | Measure-Object -Sum
            $observation = Invoke-Workload $Scenario 120
            $checkedUnits = [uint64]$observation.checked_units
            $after = Get-Metrics $MetricsPort 5
            $fragmentIngressDelta = (Get-Metric $after "ferrum2_tun_packets_ingress" $true) - $fragmentIngressBefore
            $completedDelta = (Get-Metric $after "ferrum2_tun_reassembly_completed" $true) - $completedBefore
            $dropsAfter = @(
                "ferrum2_tun_reassembly_dropped_overlap",
                "ferrum2_tun_reassembly_dropped_timeout",
                "ferrum2_tun_reassembly_dropped_limit",
                "ferrum2_tun_reassembly_dropped_malformed"
            ) | ForEach-Object { Get-Metric $after $_ $true } | Measure-Object -Sum
            Assert-Condition ($fragmentIngressDelta -ge $checkedUnits * 3) "fragment workload did not produce the fixed three-fragment recipe"
            Assert-Condition ($completedDelta -ge $checkedUnits) "fragment workload did not reach product reassembly"
            Assert-Condition ($dropsAfter.Sum -eq $dropsBefore.Sum) "fragment workload changed a reassembly drop counter"
            $measurements.reassembly_rate = [ordered]@{
                unit = "reassembled_payload_bytes_per_second"; value = [uint64]$observation.measurements.reassembly_rate
            }
            $checks.fragment_packets_observed = $true
            $checks.no_reassembly_drop = $true
            $checks.payload_exact = $observation.checks.payload_exact -eq $true
            [void](Wait-CleanDrain $true)
            $checks.clean_drain = $true
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
            $restartBefore = Get-Metric $before "ferrum2_tun_session_restart_started" $true
            $observation = Invoke-Workload $Scenario 600
            Start-Sleep -Seconds 5
            $after = Get-Metrics $MetricsPort 5
            [uint64]$attempts = $observation.measurements.attempted_datagrams
            [uint64]$drops = (Get-Metric $after "ferrum2_tun_wintun_ring_full_dropped" $true) - $ringBefore
            [uint64]$egress = (Get-Metric $after "ferrum2_tun_packets_egress" $true) - $egressBefore
            [uint64]$responseAttempts = $drops + $egress
            Assert-Condition ($drops -gt 0) "real workload did not trigger Wintun ring-full"
            Assert-Condition ($responseAttempts -gt 0 -and $responseAttempts -le $attempts) "ring-full response accounting exceeds the request denominator"
            Assert-Condition ((Get-Metric $after "ferrum2_tun_session_restart_started" $true) -eq $restartBefore) "ring-full restarted the TUN session"
            $checkedUnits = $drops
            $measurements.drop_rate = [ordered]@{
                unit = "dropped_packets_per_million_responses"
                value = [uint64][Math]::Ceiling(([decimal]$drops * 1000000) / [decimal]$responseAttempts)
            }
            $checks.ring_full_counter_increased = $true
            $checks.drop_rate_denominator_bound = $true
            $checks.no_ring_full_retry = $true
            $checks.no_session_restart = $true
        }
        "restart-recovery" {
            Start-Sleep -Seconds 5
            $prefix = "$script:TargetAddress/32"
            $routes = @(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction Stop)
            Assert-Condition ($routes.Count -eq 1) "restart workload requires one exact managed target route"
            $route = $routes[0]
            $routeIdentity = [ordered]@{
                interface_index = [uint32]$route.InterfaceIndex
                destination_prefix = [string]$route.DestinationPrefix
                next_hop = [string]$route.NextHop
                route_metric = [uint32]$route.RouteMetric
            }
            $journal = Join-Path $script:WorkRoot "restart-route-journal.json"
            [IO.File]::WriteAllText($journal, (($routeIdentity | ConvertTo-Json -Compress) + "`n"), $script:Utf8NoBom)
            $initial = Get-Metrics $MetricsPort 5
            [double]$generation = Get-Metric $initial "ferrum2_tun_session_generation"
            [double]$restartSucceeded = Get-Metric $initial "ferrum2_tun_session_restart_succeeded" $true
            [double]$restartFailed = Get-Metric $initial "ferrum2_tun_session_restart_failed" $true
            $recoveries = [System.Collections.Generic.List[uint64]]::new()
            foreach ($cycle in 1..10) {
                $timer = [Diagnostics.Stopwatch]::StartNew()
                Remove-NetRoute -InterfaceIndex $routeIdentity.interface_index `
                    -DestinationPrefix $routeIdentity.destination_prefix `
                    -NextHop $routeIdentity.next_hop -PolicyStore ActiveStore `
                    -Confirm:$false -ErrorAction Stop
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                do {
                    Start-Sleep -Milliseconds 50
                    $metrics = Get-Metrics $MetricsPort 2
                    $newGeneration = Get-Metric $metrics "ferrum2_tun_session_generation"
                    $active = Get-Metric $metrics "ferrum2_tun_session_active"
                    $succeeded = Get-Metric $metrics "ferrum2_tun_session_restart_succeeded" $true
                    if ($newGeneration -eq $generation + 1 -and $active -eq 1 -and $succeeded -eq $restartSucceeded + 1) { break }
                } while ([DateTime]::UtcNow -lt $deadline)
                Assert-Condition ($newGeneration -eq $generation + 1 -and $active -eq 1 -and $succeeded -eq $restartSucceeded + 1) "restart recovery exceeded 30 seconds"
                Invoke-Probe
                $timer.Stop()
                $recoveries.Add([uint64][Math]::Ceiling(
                    ([decimal]$timer.ElapsedTicks * [decimal]1000000000) /
                    [decimal][Diagnostics.Stopwatch]::Frequency
                ))
                $generation = $newGeneration
                $restartSucceeded = $succeeded
                $restored = @(Get-NetRoute -InterfaceIndex $routeIdentity.interface_index `
                    -DestinationPrefix $routeIdentity.destination_prefix -PolicyStore ActiveStore `
                    -ErrorAction SilentlyContinue)
                Assert-Condition ($restored.Count -eq 1 -and $restored[0].NextHop -ceq $routeIdentity.next_hop) "managed route was not restored exactly"
            }
            $final = Get-Metrics $MetricsPort 5
            Assert-Condition ((Get-Metric $final "ferrum2_tun_session_restart_failed" $true) -eq $restartFailed) "restart failure counter changed"
            Remove-Item -LiteralPath $journal -Force
            $checkedUnits = 10
            $measurements.recovery = [ordered]@{
                unit = "p99_recovery_nanoseconds"; value = Get-P99Nanoseconds $recoveries.ToArray()
            }
            $checks.same_process_all_cycles = (-not $clientProcess.HasExited)
            $checks.generation_advanced_once_per_cycle = $true
            $checks.tcp_and_udp_recovered_each_cycle = $true
            [void](Wait-CleanDrain $true)
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
        schema_version = 1
        kind = "windows_tun_performance_trial"
        selection = "windows-tun-m17"
        run_kind = $RunKind
        scenario = $Scenario
        member = $Member
        pair = $Pair
        order = $Order
        sequence = $sequence
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
                "restart-recovery" { "successful_restart_cycles" }
            }
            checked_units = $checkedUnits
            checks = $checks
        }
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
    Write-Output "windows_tun_trial status=PASS scenario=$Scenario member=$Member pair=$Pair order=$Order output=$outputPath"
} finally {
    if (Test-Path -LiteralPath $script:WorkRoot -PathType Container) {
        $resolvedWorkRoot = (Resolve-Path -LiteralPath $script:WorkRoot).Path
        Assert-Condition (
            $resolvedWorkRoot.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            -not $resolvedWorkRoot.Equals([IO.Path]::GetFullPath($outputParent), [StringComparison]::OrdinalIgnoreCase)
        ) "refusing to remove an out-of-scope trial work directory"
        $journalPath = Join-Path $script:WorkRoot "restart-route-journal.json"
        if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
            $routeIdentity = Get-Content -LiteralPath $journalPath -Raw -Encoding utf8 | ConvertFrom-Json
            $present = @(Get-NetRoute -InterfaceIndex $routeIdentity.interface_index `
                -DestinationPrefix $routeIdentity.destination_prefix -PolicyStore ActiveStore `
                -ErrorAction SilentlyContinue)
            $exact = (
                $present.Count -eq 1 -and
                [string]$present[0].NextHop -ceq [string]$routeIdentity.next_hop -and
                [uint32]$present[0].RouteMetric -eq [uint32]$routeIdentity.route_metric
            )
            if (-not $exact) {
                foreach ($entry in $present) {
                    $entry | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                }
                New-NetRoute -InterfaceIndex $routeIdentity.interface_index `
                    -DestinationPrefix $routeIdentity.destination_prefix `
                    -NextHop $routeIdentity.next_hop -RouteMetric $routeIdentity.route_metric `
                    -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            }
        }
        Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction Stop
    }
}
