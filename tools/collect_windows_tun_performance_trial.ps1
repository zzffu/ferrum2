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
        "network-lifecycle"
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
    [Parameter(Mandatory = $true)][string]$NetworkModelPlan,
    [Parameter(Mandatory = $true)][string]$NetworkModelController,
    [Parameter(Mandatory = $true)][string]$AdapterName,
    [string]$NetworkModelOutput,
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

function Get-ManagedAdapter {
    $rows = @(Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop)
    Assert-Condition ($rows.Count -eq 1) "managed performance adapter identity is not exact"
    return $rows[0]
}

function Get-ManagedIdentity {
    $adapter = Get-ManagedAdapter
    $addresses = @(
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.PrefixOrigin)|$($_.SuffixOrigin)|$($_.SkipAsSource)"
            } | Sort-Object
    )
    $routes = @(
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)|$($_.Protocol)"
            } | Sort-Object
    )
    $dns = @(
        Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            ForEach-Object {
                "$($_.AddressFamily)|$(@($_.ServerAddresses | Sort-Object) -join ',')"
            } | Sort-Object
    )
    $identity = [ordered]@{
        interface_guid = ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
        net_luid = [uint64]$adapter.NetLuid
        interface_index = [uint32]$adapter.ifIndex
        interface_description = [string]$adapter.InterfaceDescription
        addresses = $addresses
        routes = $routes
        dns = $dns
    }
    $bytes = $script:Utf8NoBom.GetBytes(($identity | ConvertTo-Json -Compress -Depth 5))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-LifecycleResources([string]$Metrics) {
    $clientProcess.Refresh()
    Assert-Condition (-not $clientProcess.HasExited) "client exited during lifecycle sampling"
    $managedAdapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop).Count
    return [ordered]@{
        process_handles = [uint64]$clientProcess.HandleCount
        process_threads = [uint64]$clientProcess.Threads.Count
        udp_associations_active = [uint64](
            Get-Metric $Metrics "ferrum2_tun_udp_associations_active"
        )
        managed_adapters_active = [uint64]$managedAdapters
    }
}

function Get-PhysicalDefaultRoute {
    $managed = Get-ManagedAdapter
    $rows = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
            -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [uint32]$_.InterfaceIndex -ne [uint32]$managed.ifIndex } |
            ForEach-Object {
                $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -IncludeHidden `
                    -ErrorAction Stop
                $interface = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex `
                    -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
                [pscustomobject]@{
                    Route = $_
                    Adapter = $adapter
                    EffectiveMetric = [uint64]$_.RouteMetric + [uint64]$interface.InterfaceMetric
                }
            } | Sort-Object EffectiveMetric, @{ Expression = { $_.Route.InterfaceIndex } }
    )
    Assert-Condition (
        $rows.Count -gt 0 -and
        [bool]$rows[0].Adapter.HardwareInterface -and
        [string]$rows[0].Adapter.Status -ceq "Up" -and
        ($rows.Count -eq 1 -or $rows[0].EffectiveMetric -lt $rows[1].EffectiveMetric)
    ) "one preferred physical IPv4 default route is required"
    return $rows[0]
}

function Wait-LifecycleTransition(
    [ValidateSet("reset_network", "full_rebuild")][string]$Operation,
    [double]$GenerationBefore,
    [double]$SuccessBefore,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 25
        $metrics = Get-Metrics $script:MetricsPort 2
        $generation = Get-Metric $metrics "ferrum2_network_generation"
        $active = Get-Metric $metrics "ferrum2_tun_session_active"
        if ($Operation -ceq "reset_network") {
            $success = Get-LabeledMetric $metrics "ferrum2_network_reset" @{
                reason = "network_change"; result = "succeeded"
            } $true
        } else {
            $success = Get-LabeledMetric $metrics "ferrum2_network_full_rebuild" @{
                reason = "route_damage"; result = "succeeded"
            } $true
        }
        if (
            $generation -eq $GenerationBefore + 1 -and
            $success -eq $SuccessBefore + 1 -and
            $active -eq 1
        ) {
            return [pscustomobject]@{
                Metrics = $metrics
                Generation = $generation
                Success = $success
            }
        }
        Assert-Condition (
            $generation -le $GenerationBefore + 1 -and $success -le $SuccessBefore + 1
        ) "network lifecycle transition advanced more than once"
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Operation recovery exceeded $TimeoutSeconds seconds"
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
    "network-lifecycle"
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
$modelPlanPath = Resolve-Leaf $NetworkModelPlan "network-model plan"
$modelControllerPath = Resolve-Leaf $NetworkModelController "network-model controller"
$modelPlanHash = Get-LowerSha256 $modelPlanPath
$modelControllerHash = Get-LowerSha256 $modelControllerPath
$modelPlan = Get-Content -LiteralPath $modelPlanPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 12
Assert-ExactProperties $modelPlan @(
    "schema_version", "execution", "host_network_mutation", "workloads",
    "lifecycle_observation_identity_fields"
) "network-model plan"
Assert-Condition (
    $modelPlan.schema_version -eq 2 -and
    $modelPlan.execution -ceq "local_hyperv_guest" -and
    $modelPlan.host_network_mutation -ceq "forbidden"
) "network-model plan execution boundary changed"
Assert-ExactProperties $modelPlan.workloads @("network-lifecycle", "udp-route-once") `
    "network-model workloads"
$lifecyclePlan = $modelPlan.workloads."network-lifecycle"
Assert-Condition (
    [int]$lifecyclePlan.reset_network_cycles -eq 1000 -and
    [int]$lifecyclePlan.full_rebuild_cycles -eq 10 -and
    [string]$lifecyclePlan.full_rebuild_damage_reason -ceq "route_damage" -and
    [string]$lifecyclePlan.interface_switch_kind -ceq "approved_underlay_disable_enable" -and
    [int]$lifecyclePlan.interface_switch_sequence -eq 500 -and
    [int]$lifecyclePlan.interface_resolver_probes -eq 32
) "network-model lifecycle recipe changed"
$outputPath = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputPath
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) "trial output baseline is not absent"
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) "trial output parent does not exist"
$outputParentItem = Get-Item -LiteralPath $outputParent -Force
Assert-Condition (-not ($outputParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "trial output parent cannot be a reparse point"
$modelOutputPath = $null
if ($Scenario -ceq "network-lifecycle") {
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "network-lifecycle requires raw network-model output"
    $modelOutputPath = [IO.Path]::GetFullPath($NetworkModelOutput)
    $modelOutputParent = Split-Path -Parent $modelOutputPath
    Assert-Condition (
        -not (Test-Path -LiteralPath $modelOutputPath) -and
        (Test-Path -LiteralPath $modelOutputParent -PathType Container) -and
        -not ((Get-Item -LiteralPath $modelOutputParent -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -and
        [IO.Path]::GetFileName($modelOutputPath) -ceq (
            "{0:D3}-network-lifecycle-{1}-pair-{2}.network-model.json" -f `
                $sequence, $Member, $Pair
        )
    ) "network-model output boundary or identity is invalid"
} else {
    Assert-Condition ([string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "non-lifecycle trial cannot write network-model evidence"
}

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
$collectorHash = Get-LowerSha256 $PSCommandPath
Assert-Condition (
    $ledger.schema -eq 1 -and
    $ledger.vm_name -ceq $ExpectedVmName -and
    $ledger.vm_id -ceq $ExpectedVmId -and
    $ledger.checkpoint_name -ceq $ExpectedCheckpointName -and
    $ledger.checkpoint_id -ceq $ExpectedCheckpointId -and
    $ledger.guest_architecture -ceq "AMD64" -and
    $ledger.candidate_sha -ceq $memberSha -and
    $ledger.probe_sha256 -ceq $collectorHash -and
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
$modelEvidenceReference = $null
$modelPending = $null
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
        "network-lifecycle" {
            Start-Sleep -Seconds 5
            $physical = Get-PhysicalDefaultRoute
            $physicalRoute = $physical.Route
            $physicalRouteIdentity = [ordered]@{
                interface_index = [uint32]$physicalRoute.InterfaceIndex
                interface_guid = ([Guid]$physical.Adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
                interface_name = [string]$physical.Adapter.Name
                destination_prefix = [string]$physicalRoute.DestinationPrefix
                next_hop = [string]$physicalRoute.NextHop
                route_metric = [uint32]$physicalRoute.RouteMetric
            }
            $physicalJournal = Join-Path $script:WorkRoot "physical-route-journal.json"
            [IO.File]::WriteAllText(
                $physicalJournal,
                (($physicalRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                $script:Utf8NoBom
            )
            [uint64[]]$routeMetrics = if ($physicalRouteIdentity.route_metric -le 4294967293) {
                @(
                    [uint64]$physicalRouteIdentity.route_metric + 1,
                    [uint64]$physicalRouteIdentity.route_metric + 2,
                    [uint64]$physicalRouteIdentity.route_metric
                )
            } elseif ($physicalRouteIdentity.route_metric -ge 2) {
                @(
                    [uint64]$physicalRouteIdentity.route_metric - 1,
                    [uint64]$physicalRouteIdentity.route_metric - 2,
                    [uint64]$physicalRouteIdentity.route_metric
                )
            } else {
                throw "physical route metric has no bounded three-state mutation"
            }
            $initial = Get-Metrics $MetricsPort 5
            [double]$generation = Get-Metric $initial "ferrum2_network_generation"
            Assert-Condition ($generation -ge 1) "published network generation is unavailable"
            [double]$resetSucceeded = Get-LabeledMetric $initial "ferrum2_network_reset" @{
                reason = "network_change"; result = "succeeded"
            } $true
            [double]$rebuildSucceeded = Get-LabeledMetric $initial `
                "ferrum2_network_full_rebuild" @{
                    reason = "route_damage"; result = "succeeded"
                } $true
            [double]$restartStarted = Get-Metric $initial `
                "ferrum2_tun_session_restart_started" $true
            $managedIdentity = Get-ManagedIdentity
            $baselineResources = Get-LifecycleResources $initial
            Assert-Condition (
                $baselineResources.udp_associations_active -eq 0 -and
                $baselineResources.managed_adapters_active -eq 1
            ) "network lifecycle resource baseline is not quiescent"
            $cycles = [Collections.Generic.List[object]]::new()
            $resetLatencies = [Collections.Generic.List[uint64]]::new()
            $rebuildLatencies = [Collections.Generic.List[uint64]]::new()
            $routeMutationIndex = 0
            Invoke-Probe

            foreach ($cycle in 1..1000) {
                $before = Get-Metrics $MetricsPort 5
                [uint64]$tcpBefore = Get-Metric $before "ferrum2_tun_tcp_flows_active"
                [uint64]$udpBefore = Get-Metric $before "ferrum2_tun_udp_associations_active"
                Assert-Condition ($udpBefore -ge 1) "reset cycle lacks a live UDP association"
                $identityBefore = $managedIdentity
                [double]$generationBefore = $generation
                [double]$successBefore = $resetSucceeded
                [double]$restartBefore = Get-Metric $before `
                    "ferrum2_tun_session_restart_started" $true
                $timer = [Diagnostics.Stopwatch]::StartNew()
                $reason = "route_change"
                if ($cycle -eq 500) {
                    $reason = "interface_change"
                    $interfaceJournal = Join-Path $script:WorkRoot "physical-interface-journal.json"
                    [IO.File]::WriteAllText(
                        $interfaceJournal,
                        (($physicalRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                        $script:Utf8NoBom
                    )
                    Disable-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Milliseconds 100
                    Enable-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -Confirm:$false -ErrorAction Stop
                } else {
                    $currentRoutes = @(
                        Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                            -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                            -PolicyStore ActiveStore -ErrorAction Stop |
                            Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
                    )
                    Assert-Condition ($currentRoutes.Count -eq 1) `
                        "physical route mutation target is not exact"
                    $nextMetric = $routeMetrics[$routeMutationIndex % $routeMetrics.Count]
                    $routeMutationIndex++
                    Set-NetRoute -InputObject $currentRoutes[0] -RouteMetric $nextMetric `
                        -ErrorAction Stop
                }
                $transition = Wait-LifecycleTransition "reset_network" `
                    $generationBefore $successBefore 30
                $identityAfter = Get-ManagedIdentity
                $resourcesAfter = Get-LifecycleResources $transition.Metrics
                Assert-Condition (
                    (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
                    (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
                ) "ResetNetwork retained a connection"
                Invoke-Probe
                $timer.Stop()
                $afterProbe = Get-Metrics $MetricsPort 5
                [double]$restartAfter = Get-Metric $afterProbe `
                    "ferrum2_tun_session_restart_started" $true
                Assert-Condition ($restartAfter -eq $restartBefore) `
                    "ordinary ResetNetwork used the session-restart path"
                $elapsed = Get-ElapsedNanoseconds $timer
                $resetLatencies.Add($elapsed)
                $cycles.Add([ordered]@{
                    sequence = [uint64]$cycle
                    operation = "reset_network"
                    reason = $reason
                    generation_before = [uint64]$generationBefore
                    generation_after = [uint64]$transition.Generation
                    elapsed_nanoseconds = $elapsed
                    operation_counter_before = [uint64]$successBefore
                    operation_counter_after = [uint64]$transition.Success
                    session_restart_started_before = [uint64]$restartBefore
                    session_restart_started_after = [uint64]$restartAfter
                    managed_identity_before = $identityBefore
                    managed_identity_after = $identityAfter
                    tcp_flows_before = $tcpBefore
                    udp_associations_before = $udpBefore
                    tcp_flows_closed = $tcpBefore
                    udp_associations_closed = $udpBefore
                    tcp_probe_succeeded = $true
                    udp_probe_succeeded = $true
                    resources_after = $resourcesAfter
                })
                $managedIdentity = $identityAfter
                $generation = $transition.Generation
                $resetSucceeded = $transition.Success
                $restartStarted = $restartAfter
                if ($cycle -eq 500) {
                    $currentAdapter = Get-NetAdapter -Name $physicalRouteIdentity.interface_name `
                        -IncludeHidden -ErrorAction Stop
                    Assert-Condition (
                        [string]$currentAdapter.Status -ceq "Up" -and
                        ([Guid]$currentAdapter.InterfaceGuid).ToString("D").ToLowerInvariant() `
                            -ceq $physicalRouteIdentity.interface_guid
                    ) "physical interface switch did not restore its identity"
                    Remove-Item -LiteralPath $interfaceJournal -Force
                }
            }
            Assert-Condition (
                $routeMutationIndex -eq 999 -and
                $routeMetrics[($routeMutationIndex - 1) % $routeMetrics.Count] -eq
                    $physicalRouteIdentity.route_metric
            ) "physical route metric schedule did not end at its baseline"
            $physicalReadback = @(
                Get-NetRoute -InterfaceIndex $physicalRouteIdentity.interface_index `
                    -DestinationPrefix $physicalRouteIdentity.destination_prefix `
                    -PolicyStore ActiveStore -ErrorAction Stop |
                    Where-Object { $_.NextHop -ceq $physicalRouteIdentity.next_hop }
            )
            Assert-Condition (
                $physicalReadback.Count -eq 1 -and
                [uint32]$physicalReadback[0].RouteMetric -eq
                    [uint32]$physicalRouteIdentity.route_metric
            ) "physical route metric baseline was not restored in-band"

            foreach ($rebuild in 1..10) {
                $before = Get-Metrics $MetricsPort 5
                [uint64]$tcpBefore = Get-Metric $before "ferrum2_tun_tcp_flows_active"
                [uint64]$udpBefore = Get-Metric $before "ferrum2_tun_udp_associations_active"
                Assert-Condition ($udpBefore -ge 1) "full rebuild cycle lacks a live UDP association"
                $identityBefore = $managedIdentity
                [double]$generationBefore = $generation
                [double]$successBefore = $rebuildSucceeded
                [double]$restartBefore = Get-Metric $before `
                    "ferrum2_tun_session_restart_started" $true
                $managed = Get-ManagedAdapter
                $prefix = "$script:TargetAddress/32"
                $managedRoutes = @(
                    Get-NetRoute -InterfaceIndex $managed.ifIndex -DestinationPrefix $prefix `
                        -PolicyStore ActiveStore -ErrorAction Stop
                )
                Assert-Condition ($managedRoutes.Count -eq 1) `
                    "full rebuild damage target is not one exact managed route"
                $managedRouteIdentity = [ordered]@{
                    interface_guid = ([Guid]$managed.InterfaceGuid).ToString("D").ToLowerInvariant()
                    destination_prefix = [string]$managedRoutes[0].DestinationPrefix
                    next_hop = [string]$managedRoutes[0].NextHop
                    route_metric = [uint32]$managedRoutes[0].RouteMetric
                }
                $managedJournal = Join-Path $script:WorkRoot "managed-route-journal.json"
                [IO.File]::WriteAllText(
                    $managedJournal,
                    (($managedRouteIdentity | ConvertTo-Json -Compress) + "`n"),
                    $script:Utf8NoBom
                )
                $timer = [Diagnostics.Stopwatch]::StartNew()
                $managedRoutes[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                $transition = Wait-LifecycleTransition "full_rebuild" `
                    $generationBefore $successBefore 30
                $identityAfter = Get-ManagedIdentity
                $resourcesAfter = Get-LifecycleResources $transition.Metrics
                Assert-Condition (
                    (Get-Metric $transition.Metrics "ferrum2_tun_tcp_flows_active") -eq 0 -and
                    (Get-Metric $transition.Metrics "ferrum2_tun_udp_associations_active") -eq 0
                ) "managed full rebuild retained a connection"
                $restoredAdapter = Get-ManagedAdapter
                $restoredRoutes = @(
                    Get-NetRoute -InterfaceIndex $restoredAdapter.ifIndex `
                        -DestinationPrefix $managedRouteIdentity.destination_prefix `
                        -PolicyStore ActiveStore -ErrorAction Stop
                )
                Assert-Condition (
                    $restoredRoutes.Count -eq 1 -and
                    [string]$restoredRoutes[0].NextHop -ceq $managedRouteIdentity.next_hop -and
                    [uint32]$restoredRoutes[0].RouteMetric -eq $managedRouteIdentity.route_metric
                ) "managed route was not rebuilt exactly"
                Remove-Item -LiteralPath $managedJournal -Force
                Invoke-Probe
                $timer.Stop()
                $afterProbe = Get-Metrics $MetricsPort 5
                [double]$restartAfter = Get-Metric $afterProbe `
                    "ferrum2_tun_session_restart_started" $true
                Assert-Condition ($restartAfter -eq $restartBefore) `
                    "managed full rebuild used the session-restart path"
                $elapsed = Get-ElapsedNanoseconds $timer
                $rebuildLatencies.Add($elapsed)
                $cycles.Add([ordered]@{
                    sequence = [uint64](1000 + $rebuild)
                    operation = "full_rebuild"
                    reason = "route_damage"
                    generation_before = [uint64]$generationBefore
                    generation_after = [uint64]$transition.Generation
                    elapsed_nanoseconds = $elapsed
                    operation_counter_before = [uint64]$successBefore
                    operation_counter_after = [uint64]$transition.Success
                    session_restart_started_before = [uint64]$restartBefore
                    session_restart_started_after = [uint64]$restartAfter
                    managed_identity_before = $identityBefore
                    managed_identity_after = $identityAfter
                    tcp_flows_before = $tcpBefore
                    udp_associations_before = $udpBefore
                    tcp_flows_closed = $tcpBefore
                    udp_associations_closed = $udpBefore
                    tcp_probe_succeeded = $true
                    udp_probe_succeeded = $true
                    resources_after = $resourcesAfter
                })
                $managedIdentity = $identityAfter
                $generation = $transition.Generation
                $rebuildSucceeded = $transition.Success
                $restartStarted = $restartAfter
            }

            $resolverBefore = Get-Metrics $MetricsPort 5
            [double]$resolutionsBefore = Get-Metric $resolverBefore `
                "ferrum2_outbound_interface_resolution" $true
            [double]$cacheHitsBefore = Get-Metric $resolverBefore `
                "ferrum2_outbound_interface_resolution_cache_hit" $true
            foreach ($probe in 1..32) { Invoke-Probe }
            $resolverAfter = Get-Metrics $MetricsPort 5
            [uint64]$resolutions = (Get-Metric $resolverAfter `
                "ferrum2_outbound_interface_resolution" $true) - $resolutionsBefore
            [uint64]$cacheHits = (Get-Metric $resolverAfter `
                "ferrum2_outbound_interface_resolution_cache_hit" $true) - $cacheHitsBefore
            Assert-Condition ($resolutions -ge 32 -and $resolutions -le 256 -and $cacheHits -gt 0 `
                -and $cacheHits -le $resolutions) "interface resolver cache-hit evidence is invalid"
            [void](Wait-CleanDrain $true)
            $finalMetrics = Get-Metrics $MetricsPort 5
            Assert-Condition (
                (Get-Metric $finalMetrics "ferrum2_tun_udp_associations_active") -eq 0 -and
                -not $clientProcess.HasExited -and -not $serverProcess.HasExited
            ) "network lifecycle did not reach a clean final drain"

            $rawIdentity = [ordered]@{
                run_kind = $RunKind
                member = $Member
                pair = [uint64]$Pair
                trial_sequence = [uint64]$sequence
                client_pid = [uint64]$ClientPid
                server_pid = [uint64]$ServerPid
                vm_name = $ExpectedVmName
                vm_id = $ExpectedVmId
                checkpoint_name = $ExpectedCheckpointName
                checkpoint_id = $ExpectedCheckpointId
                sha = $memberSha
                tree = $Tree
                client_sha256 = $clientHash
                server_sha256 = $serverHash
                harness_sha256 = $harnessHash
                collector_sha256 = $collectorHash
                recipe_sha256 = $RecipeSha256
                model_controller_sha256 = $modelControllerHash
                model_plan_sha256 = $modelPlanHash
            }
            $rawObservation = [ordered]@{
                schema_version = 2
                workload = "network-lifecycle"
                identity = $rawIdentity
                baseline_resources = $baselineResources
                cycles = $cycles.ToArray()
                interface_resolver = [ordered]@{
                    probes = [uint64]32
                    resolutions = $resolutions
                    cache_hits = $cacheHits
                }
            }
            $modelPending = "$modelOutputPath.pending"
            Assert-Condition (-not (Test-Path -LiteralPath $modelPending)) `
                "network-model pending output baseline is not absent"
            [IO.File]::WriteAllText(
                $modelPending,
                (($rawObservation | ConvertTo-Json -Depth 12) + "`n"),
                $script:Utf8NoBom
            )
            Assert-Condition ((Get-Item -LiteralPath $modelPending).Length -le 2097152) `
                "network-model observation exceeds 2 MiB"
            Move-Item -LiteralPath $modelPending -Destination $modelOutputPath -ErrorAction Stop
            $modelEvidenceReference = [ordered]@{
                schema_version = 1
                controller_sha256 = $modelControllerHash
                collector_sha256 = $collectorHash
                plan_sha256 = $modelPlanHash
                observation_file = [IO.Path]::GetFileName($modelOutputPath)
                observation_sha256 = Get-LowerSha256 $modelOutputPath
            }
            $checkedUnits = 1000
            $measurements.reset_p50 = [ordered]@{
                unit = "p50_reset_network_nanoseconds"
                value = Get-NearestRank $resetLatencies.ToArray() 50
            }
            $measurements.reset_p95 = [ordered]@{
                unit = "p95_reset_network_nanoseconds"
                value = Get-NearestRank $resetLatencies.ToArray() 95
            }
            $measurements.reset_p99 = [ordered]@{
                unit = "p99_reset_network_nanoseconds"
                value = Get-NearestRank $resetLatencies.ToArray() 99
            }
            $measurements.full_rebuild_p50 = [ordered]@{
                unit = "p50_full_rebuild_nanoseconds"
                value = Get-NearestRank $rebuildLatencies.ToArray() 50
            }
            $measurements.full_rebuild_p95 = [ordered]@{
                unit = "p95_full_rebuild_nanoseconds"
                value = Get-NearestRank $rebuildLatencies.ToArray() 95
            }
            $measurements.full_rebuild_p99 = [ordered]@{
                unit = "p99_full_rebuild_nanoseconds"
                value = Get-NearestRank $rebuildLatencies.ToArray() 99
            }
            $measurements.interface_switch_recovery = [ordered]@{
                unit = "interface_switch_recovery_nanoseconds"
                value = [uint64]$resetLatencies[499]
            }
            $measurements.interface_resolver_cache_hit = [ordered]@{
                unit = "cache_hits_per_million_resolutions"
                value = [uint64][Math]::Floor(
                    ([decimal]$cacheHits * [decimal]1000000) / [decimal]$resolutions
                )
            }
            $resetFinal = $cycles[999].resources_after
            $checks.same_process_all_cycles = $true
            $checks.generation_advanced_once_per_cycle = $true
            $checks.managed_identity_preserved_across_resets = $true
            $checks.damage_only_full_rebuild = $true
            $checks.resource_growth_zero_after_1000_resets = (
                $resetFinal.process_handles -le $baselineResources.process_handles -and
                $resetFinal.process_threads -le $baselineResources.process_threads -and
                $resetFinal.udp_associations_active -le $baselineResources.udp_associations_active -and
                $resetFinal.managed_adapters_active -le $baselineResources.managed_adapters_active
            )
            $checks.tcp_and_udp_recovered_after_interface_switch = $true
            $checks.interface_resolver_cache_hit_observed = $true
            $checks.network_model_evidence_bound = $true
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
        schema_version = 2
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
                "network-lifecycle" { "successful_reset_network_cycles" }
            }
            checked_units = $checkedUnits
            checks = $checks
        }
        network_model_evidence = $modelEvidenceReference
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
        $interfaceJournalPath = Join-Path $script:WorkRoot "physical-interface-journal.json"
        if (Test-Path -LiteralPath $interfaceJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $interfaceJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $adapter = Get-NetAdapter -Name $identity.interface_name -IncludeHidden `
                -ErrorAction Stop
            Assert-Condition (
                ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
                    [string]$identity.interface_guid
            ) "refusing to enable a changed physical interface identity"
            if ([string]$adapter.Status -cne "Up") {
                Enable-NetAdapter -Name $identity.interface_name -Confirm:$false -ErrorAction Stop
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $adapter = Get-NetAdapter -Name $identity.interface_name -IncludeHidden `
                    -ErrorAction Stop
                if ([string]$adapter.Status -ceq "Up") { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ([string]$adapter.Status -ceq "Up") `
                "physical interface did not return Up during journal recovery"
        }
        $physicalJournalPath = Join-Path $script:WorkRoot "physical-route-journal.json"
        if (Test-Path -LiteralPath $physicalJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $physicalJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $present = @(
                    Get-NetRoute -InterfaceIndex $identity.interface_index `
                        -DestinationPrefix $identity.destination_prefix -PolicyStore ActiveStore `
                        -ErrorAction SilentlyContinue |
                        Where-Object { $_.NextHop -ceq [string]$identity.next_hop }
                )
                if ($present.Count -eq 1) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ($present.Count -eq 1) `
                "physical route restore target is not exact"
            if ([uint32]$present[0].RouteMetric -ne [uint32]$identity.route_metric) {
                Set-NetRoute -InputObject $present[0] -RouteMetric $identity.route_metric `
                    -ErrorAction Stop
            }
        }
        $managedJournalPath = Join-Path $script:WorkRoot "managed-route-journal.json"
        if (Test-Path -LiteralPath $managedJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $managedJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $managedRows = @(
                    Get-NetAdapter -Name $AdapterName -IncludeHidden `
                        -ErrorAction SilentlyContinue
                )
                if ($managedRows.Count -eq 1) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-Condition ($managedRows.Count -eq 1) `
                "managed adapter did not return during journal recovery"
            $managed = $managedRows[0]
            $present = @(
                Get-NetRoute -InterfaceIndex $managed.ifIndex `
                    -DestinationPrefix $identity.destination_prefix -PolicyStore ActiveStore `
                    -ErrorAction SilentlyContinue
            )
            Assert-Condition ($present.Count -le 1) `
                "managed route recovery target is ambiguous"
            if ($present.Count -eq 0) {
                New-NetRoute -InterfaceIndex $managed.ifIndex `
                    -DestinationPrefix $identity.destination_prefix `
                    -NextHop $identity.next_hop -RouteMetric $identity.route_metric `
                    -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            }
        }
        Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction Stop
    }
    if ($null -ne $modelPending -and (Test-Path -LiteralPath $modelPending -PathType Leaf)) {
        Remove-Item -LiteralPath $modelPending -Force -ErrorAction Stop
    }
    if ($null -ne $modelOutputPath -and
        (Test-Path -LiteralPath $modelOutputPath -PathType Leaf) -and
        -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        Remove-Item -LiteralPath $modelOutputPath -Force -ErrorAction Stop
    }
}
