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
        "udp-route-once",
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
    [ValidateRange(1, 6)]
    [int]$Pair,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2)]
    [int]$Order,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 108)]
    [int]$Sequence,

    [Parameter(Mandatory = $true)][string]$ParentSha,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$Tree,
    [Parameter(Mandatory = $true)][string]$RecipeSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ControllerBundleSha256,
    [Parameter(Mandatory = $true)][string]$ClientBinary,
    [Parameter(Mandatory = $true)][string]$ServerBinary,
    [Parameter(Mandatory = $true)][string]$HarnessBinary,
    [Parameter(Mandatory = $true)][string]$IdentityLedger,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ExpectedCheckpointId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedTopologyManifestSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedTopologyPlanSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ExpectedSupportSwitchId,
    [Parameter(Mandatory = $true)][string]$NetworkModelPlan,
    [Parameter(Mandatory = $true)][string]$NetworkModelController,
    [Parameter(Mandatory = $true)][string]$AdapterName,
    [string]$NetworkModelOutput,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ClientPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ServerPid,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$MetricsPort,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ServerMetricsPort,
    [Parameter(Mandatory = $true)][string]$ExpectedFixedEndpointIpv4,
    [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)]
    [int]$ExpectedUnderlayInterfaceIndex,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string]$ExpectedUnderlayInterfaceAlias,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ExpectedUnderlayInterfaceGuid,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$UdpAssociationSourceIpv4,
    [int]$UdpAssociationSourcePortFirst,
    [int]$UdpAssociationSourcePortLast
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$controllerBundleManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    "controller-bundle.json"
$bootstrapRelative = "modules/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1"
$bootstrapManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapEntry = @($bootstrapManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $PSScriptRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw "performance collector bundle bootstrap changed"
}
. $bootstrapPath
$controllerBundleManifest = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot

if ($MetricsPort -eq $ServerMetricsPort) {
    throw "client and server metrics ports must be distinct"
}

$ExpectedVmName = "Windows 10 MSIX packaging environment"
$ExpectedVmId = "82e20295-1d30-48e7-a751-e21d35d872d4"
$ExpectedCheckpointName = "Ferrum2-WindowsTun-InternalSupport-v1"
$ExpectedSupportSwitchName = "Ferrum2 TUN Support"
$ExpectedRunnerLabel = "ferrum2-hyperv-guest"
$ExpectedUdpAssociationSourceIpv4 = "198.18.0.2"
$ExpectedUdpAssociationSourcePortFirst = 20000
$ExpectedUdpAssociationSourcePortLast = 28191
$ExpectedUdpAssociationSourcePortCount = 8192
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$performanceCollectorRoot = Join-Path $PSScriptRoot "powershell\Ferrum2.Performance"
$collectorCorePath = Join-Path $performanceCollectorRoot "CollectorCore.ps1"
$collectorUdpSourcePath = Join-Path $performanceCollectorRoot "CollectorUdpSource.ps1"
$collectorLifecyclePath = Join-Path $performanceCollectorRoot "CollectorLifecycle.ps1"
foreach ($collectorModule in @($collectorCorePath, $collectorUdpSourcePath, $collectorLifecyclePath)) {
    if (-not (Test-Path -LiteralPath $collectorModule -PathType Leaf)) {
        throw "performance collector module is missing: $collectorModule"
    }
}
. $collectorCorePath
. $collectorUdpSourcePath
. $collectorLifecyclePath
foreach ($digest in @($ParentSha, $CandidateSha, $Tree)) {
    Assert-Condition ($digest -cmatch '^[0-9a-f]{40}$') "commit/tree identity must be lowercase 40-hex"
}
Assert-Condition ($RecipeSha256 -cmatch '^[0-9a-f]{64}$') "recipe identity must be lowercase SHA-256"
$udpAssociationSourceParameterCount = 0
foreach ($parameterName in @(
    "UdpAssociationSourceIpv4",
    "UdpAssociationSourcePortFirst",
    "UdpAssociationSourcePortLast"
)) {
    if ($PSBoundParameters.ContainsKey($parameterName)) {
        $udpAssociationSourceParameterCount++
    }
}
Assert-Condition (
    $ExpectedUdpAssociationSourcePortLast -
        $ExpectedUdpAssociationSourcePortFirst + 1 -eq
        $ExpectedUdpAssociationSourcePortCount
) "canonical UDP association source-port contract is inconsistent"
if ($Scenario -ceq "udp-8192-association-lookup-expiry") {
    Assert-Condition ($udpAssociationSourceParameterCount -eq 3) `
        "UDP association source parameters must be supplied together"
    Assert-Condition (
        $UdpAssociationSourceIpv4 -ceq $ExpectedUdpAssociationSourceIpv4 -and
        $UdpAssociationSourcePortFirst -eq $ExpectedUdpAssociationSourcePortFirst -and
        $UdpAssociationSourcePortLast -eq $ExpectedUdpAssociationSourcePortLast
    ) "UDP association source parameters do not match the canonical plan"
} else {
    Assert-Condition ($udpAssociationSourceParameterCount -eq 0) `
        "non-association workload cannot receive UDP association source parameters"
}
$script:UdpAssociationSourceIpv4 = $UdpAssociationSourceIpv4
$script:UdpAssociationSourcePortFirst = $UdpAssociationSourcePortFirst
$script:UdpAssociationSourcePortLast = $UdpAssociationSourcePortLast
$expectedOrder = if (($Member -ceq "parent") -eq (($Pair % 2) -eq 1)) { 1 } else { 2 }
Assert-Condition ($Order -eq $expectedOrder) "trial order does not follow the alternating schedule"
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
    "observation_identity_fields"
) "network-model plan"
Assert-Condition (
    $modelPlan.schema_version -eq 6 -and
    $modelPlan.execution -ceq "local_hyperv_guest" -and
    $modelPlan.host_network_mutation -ceq "forbidden"
) "network-model plan execution boundary changed"
Assert-ExactProperties $modelPlan.workloads @("network-lifecycle", "udp-route-once") `
    "network-model workloads"
$lifecyclePlan = $modelPlan.workloads."network-lifecycle"
$routeOncePlan = $modelPlan.workloads."udp-route-once"
Assert-ExactProperties $lifecyclePlan @(
    "resource_warmup_reset_cycles", "resource_warmup_route_metric_states",
    "resource_quiescence_seconds", "reset_network_cycles",
    "total_reset_network_cycles", "full_rebuild_cycles", "ordinary_reset_reasons",
    "full_rebuild_reasons", "full_rebuild_damage_reason", "interface_switch_kind",
    "interface_switch_sequence", "interface_switch_recovery_timeout_seconds",
    "interface_switch_probe_retry_milliseconds", "interface_switch_trial_reset_ordinal",
    "interface_resolver_probes", "terminal_resource_convergence_excluded_from_elapsed",
    "latency_percentiles", "maximum_retained_resource_growth",
    "retained_resource_growth_enforced_operations",
    "diagnostic_resource_growth_operations"
) "network-model lifecycle workload"
Assert-Condition (
    [int]$lifecyclePlan.resource_warmup_reset_cycles -eq 12 -and
    [int]$lifecyclePlan.resource_warmup_route_metric_states -eq 3 -and
    [int]$lifecyclePlan.resource_quiescence_seconds -eq 30 -and
    [int]$lifecyclePlan.reset_network_cycles -eq 1000 -and
    [int]$lifecyclePlan.total_reset_network_cycles -eq 1012 -and
    [int]$lifecyclePlan.full_rebuild_cycles -eq 10 -and
    [string]$lifecyclePlan.full_rebuild_damage_reason -ceq "route_damage" -and
    [string]$lifecyclePlan.interface_switch_kind -ceq "approved_underlay_disable_enable" -and
    [int]$lifecyclePlan.interface_switch_sequence -eq 500 -and
    [int]$lifecyclePlan.interface_switch_recovery_timeout_seconds -eq 30 -and
    [int]$lifecyclePlan.interface_switch_probe_retry_milliseconds -eq 250 -and
    [int]$lifecyclePlan.interface_switch_trial_reset_ordinal -eq 512 -and
    [int]$lifecyclePlan.interface_resolver_probes -eq 32 -and
    $lifecyclePlan.terminal_resource_convergence_excluded_from_elapsed -eq $true -and
    (@($lifecyclePlan.retained_resource_growth_enforced_operations) -join "|") -ceq
        "reset_network" -and
    (@($lifecyclePlan.diagnostic_resource_growth_operations) -join "|") -ceq
        "full_rebuild"
) "network-model lifecycle recipe changed"
Assert-Condition (
    [int]$routeOncePlan.generations -eq 2 -and
    [int]$routeOncePlan.source_slots -eq 64 -and
    [int]$routeOncePlan.target_slots -eq 4 -and
    [int]$routeOncePlan.datagrams_per_target -eq 32 -and
    (@($routeOncePlan.required_outbounds) -join "|") -ceq "direct|proxy"
) "network-model route-once recipe changed"
$outputPath = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputPath
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) "trial output baseline is not absent"
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) "trial output parent does not exist"
$outputParentItem = Get-Item -LiteralPath $outputParent -Force
Assert-Condition (-not ($outputParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "trial output parent cannot be a reparse point"
$modelOutputPath = $null
if ($Scenario -in @("udp-route-once", "network-lifecycle")) {
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "$Scenario requires raw network-model output"
    $modelOutputPath = [IO.Path]::GetFullPath($NetworkModelOutput)
    $modelOutputParent = Split-Path -Parent $modelOutputPath
    Assert-Condition (
        -not (Test-Path -LiteralPath $modelOutputPath) -and
        (Test-Path -LiteralPath $modelOutputParent -PathType Container) -and
        -not ((Get-Item -LiteralPath $modelOutputParent -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -and
        [IO.Path]::GetFileName($modelOutputPath) -ceq (
            "{0:D3}-{1}-{2}-pair-{3}.network-model.json" -f `
                $Sequence, $Scenario, $Member, $Pair
        )
    ) "network-model output boundary or identity is invalid"
} else {
    Assert-Condition ([string]::IsNullOrWhiteSpace($NetworkModelOutput)) `
        "non-model trial cannot write network-model evidence"
}

$ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 6
$requiredLedger = @(
    "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
    "topology_manifest_sha256", "topology_plan_sha256", "support_switch_name",
    "support_switch_id",
    "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
    "candidate_sha", "probe_sha256", "controller_bundle_sha256",
    "client_sha256", "server_sha256", "support_listener"
)
Assert-ExactProperties $ledger $requiredLedger "identity ledger"
$clientHash = Get-LowerSha256 $script:ClientPath
$serverHash = Get-LowerSha256 $script:ServerPath
$harnessHash = Get-LowerSha256 $script:HarnessPath
$collectorHash = Get-LowerSha256 $PSCommandPath
Assert-Condition (
    $ledger.schema -eq 3 -and
    $ledger.vm_name -ceq $ExpectedVmName -and
    $ledger.vm_id -ceq $ExpectedVmId -and
    $ledger.checkpoint_name -ceq $ExpectedCheckpointName -and
    $ledger.checkpoint_id -ceq $ExpectedCheckpointId -and
    $ledger.topology_manifest_sha256 -ceq $ExpectedTopologyManifestSha256 -and
    $ledger.topology_plan_sha256 -ceq $ExpectedTopologyPlanSha256 -and
    $ledger.support_switch_name -ceq $ExpectedSupportSwitchName -and
    $ledger.support_switch_id -ceq $ExpectedSupportSwitchId -and
    $ledger.guest_architecture -ceq "AMD64" -and
    $ledger.candidate_sha -ceq $memberSha -and
    $ledger.probe_sha256 -ceq $collectorHash -and
    $ledger.controller_bundle_sha256 -ceq
        [string]$controllerBundleManifest.controller_bundle_sha256 -and
    $ledger.controller_bundle_sha256 -ceq $ControllerBundleSha256 -and
    $ledger.client_sha256 -ceq $clientHash -and
    $ledger.server_sha256 -ceq $serverHash
) "identity ledger does not bind this member and approved guest"
Assert-Condition (
    $ledger.controller_bundle_sha256 -is [string] -and
    $ledger.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $ledger.topology_manifest_sha256 -is [string] -and
    $ledger.topology_manifest_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $ledger.topology_plan_sha256 -is [string] -and
    $ledger.topology_plan_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $ledger.support_switch_name -is [string] -and
    -not [string]::IsNullOrWhiteSpace([string]$ledger.support_switch_name) -and
    $ledger.support_switch_id -is [string] -and
    $ledger.support_switch_id -cmatch `
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and
    $ledger.support_switch_id -cne "00000000-0000-0000-0000-000000000000"
) "identity ledger topology binding is invalid"
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
    $script:TargetUdpPort -ge 1 -and $script:TargetUdpPort -le 65532
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
$diagnostics = $null
$modelEvidenceReference = $null
$modelPending = $null
[uint64]$checkedUnits = 0
$startedUtc = [DateTime]::UtcNow.ToString("o")
$trialFailure = $null
$managedJournalRecoveryFailure = $null

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
    $scenarioScript = Join-Path $performanceCollectorRoot `
        ("TrialScenario.{0}.ps1" -f $Scenario)
    if (-not (Test-Path -LiteralPath $scenarioScript -PathType Leaf)) {
        throw "performance trial scenario owner is missing: $Scenario"
    }
    . $scenarioScript

    if ($Scenario -cne "idle-cpu-wakeup") {
        $trialTrafficAfter = Get-Metrics $MetricsPort 5
        Assert-Condition (
            (Get-Metric $trialTrafficAfter "ferrum2_tun_packets_ingress" $true) -gt $trialIngressBefore -and
            (Get-Metric $trialTrafficAfter "ferrum2_tun_packets_egress" $true) -gt $trialEgressBefore
        ) "workload did not traverse both directions of the live TUN session"
        $checks.tun_path_observed = $true
    }

    Assert-Condition ($checkedUnits -gt 0) "trial checked-unit count is zero"
    $failedChecks = @($checks.GetEnumerator() | Where-Object { $_.Value -ne $true } |
        ForEach-Object { [string]$_.Key })
    Assert-Condition ($failedChecks.Count -eq 0) `
        "one or more trial correctness checks failed: $($failedChecks -join ',')"
    $environment = [ordered]@{
        runner_os = "Windows"
        runner_arch = "X64"
        runner_label = $ExpectedRunnerLabel
        vm_name = $ExpectedVmName
        vm_id = $ExpectedVmId
        checkpoint_name = $ExpectedCheckpointName
        checkpoint_id = $ExpectedCheckpointId
        topology_manifest_sha256 = [string]$ledger.topology_manifest_sha256
        topology_plan_sha256 = [string]$ledger.topology_plan_sha256
        support_switch_id = [string]$ledger.support_switch_id
        rust_toolchain = "1.97.1"
        cargo_profile = "profiling"
        pair_schedule = "abba-six-pairs"
        guest_build = [string]$ledger.guest_build
        cpu_model = (@($cpuRows | ForEach-Object { $_.Name.Trim() }) -join " | ")
        cpu_count = [int]$computer.NumberOfLogicalProcessors
        memory_bytes = [uint64]$computer.TotalPhysicalMemory
        power_plan_guid = $powerMatch.Value.ToLowerInvariant()
    }
    $finishedUtc = [DateTime]::UtcNow.ToString("o")
    $document = [ordered]@{
        schema_version = 5
        kind = "windows_tun_performance_trial"
        selection = "windows-tun-m17"
        run_kind = $RunKind
        scenario = $Scenario
        member = $Member
        pair = $Pair
        order = $Order
        sequence = $Sequence
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
        controller_bundle_sha256 = $ControllerBundleSha256
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
                "wintun-ring-full-drop-rate" { "tun_response_attempts" }
                "udp-route-once" { "echoed_multi_target_datagrams" }
                "network-lifecycle" { "successful_reset_network_cycles" }
            }
            checked_units = $checkedUnits
            checks = $checks
        }
        diagnostics = $diagnostics
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
    Write-Output "windows_tun_trial status=PASS scenario=$Scenario member=$Member pair=$Pair order=$Order sequence=$Sequence output=$outputPath"
} catch {
    $trialFailure = $_
} finally {
    if (Test-Path -LiteralPath $script:WorkRoot -PathType Container) {
        $resolvedWorkRoot = (Resolve-Path -LiteralPath $script:WorkRoot).Path
        Assert-Condition (
            $resolvedWorkRoot.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            -not $resolvedWorkRoot.Equals([IO.Path]::GetFullPath($outputParent), [StringComparison]::OrdinalIgnoreCase)
        ) "refusing to remove an out-of-scope trial work directory"
        $interfaceJournalPath = Join-Path $script:WorkRoot `
            "underlay-interface-journal.json"
        if (Test-Path -LiteralPath $interfaceJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $interfaceJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            Assert-FixedUnderlayRouteIdentity $identity
            $adapterRows = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                [string]$_.Name -ceq [string]$identity.interface_name -and
                ([Guid]$_.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
                    [string]$identity.interface_guid
            })
            Assert-Condition ($adapterRows.Count -eq 1) `
                "refusing to enable a changed fixed underlay interface identity"
            $adapter = $adapterRows[0]
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
            Assert-Condition (
                [string]$adapter.Status -ceq "Up" -and
                ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
                    [string]$identity.interface_guid
            ) "fixed underlay interface did not return Up during journal recovery"
            Assert-Condition (
                [uint32]$adapter.ifIndex -eq [uint32]$identity.interface_index
            ) "fixed underlay interface index drifted after journal recovery"
            [void](Wait-ExactFixedUnderlayRoute $identity 30)
        }
        $underlayJournalPath = Join-Path $script:WorkRoot "underlay-route-journal.json"
        if (Test-Path -LiteralPath $underlayJournalPath -PathType Leaf) {
            $identity = Get-Content -LiteralPath $underlayJournalPath -Raw -Encoding utf8 |
                ConvertFrom-Json
            $present = Wait-ExactFixedUnderlayRoute $identity 30
            if ([uint16]$present.Route.RouteMetric -ne [uint16]$identity.route_metric) {
                Set-NetRoute -InputObject $present.Route `
                    -RouteMetric ([uint16]$identity.route_metric) `
                    -ErrorAction Stop
            }
            $restored = Get-ExactFixedUnderlayRoute $identity
            Assert-Condition (
                [uint16]$restored.Route.RouteMetric -eq [uint16]$identity.route_metric
            ) "fixed underlay route metric was not restored exactly"
        }
        $managedJournalPath = Join-Path $script:WorkRoot "managed-route-journal.json"
        if (Test-Path -LiteralPath $managedJournalPath -PathType Leaf) {
            try {
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
                Assert-Condition (
                    ([Guid]$managed.InterfaceGuid).ToString("D").ToLowerInvariant() -ceq
                        [string]$identity.interface_guid
                ) "managed adapter identity changed during journal recovery"
                Assert-Condition (
                    [uint32]$identity.route_metric -le [uint32][uint16]::MaxValue
                ) "managed route journal metric escaped the NetTCPIP boundary"
                $present = @(
                    Get-NetRoute -InterfaceIndex $managed.ifIndex `
                        -DestinationPrefix $identity.destination_prefix `
                        -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                )
                Assert-Condition ($present.Count -le 1) `
                    "managed route recovery target is ambiguous"
                if ($present.Count -eq 0) {
                    New-NetRoute -InterfaceIndex $managed.ifIndex `
                        -DestinationPrefix $identity.destination_prefix `
                        -NextHop $identity.next_hop `
                        -RouteMetric ([uint16]$identity.route_metric) `
                        -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
                } else {
                    Assert-Condition (
                        [string]$present[0].NextHop -ceq [string]$identity.next_hop
                    ) "managed route next hop changed during journal recovery"
                    if ([uint32]$present[0].RouteMetric -ne
                        [uint32]$identity.route_metric) {
                        Set-NetRoute -InputObject $present[0] `
                            -RouteMetric ([uint16]$identity.route_metric) `
                            -ErrorAction Stop
                    }
                }
                $restored = @(
                    Get-NetRoute -InterfaceIndex $managed.ifIndex `
                        -DestinationPrefix $identity.destination_prefix `
                        -PolicyStore ActiveStore -ErrorAction Stop
                )
                Assert-Condition (
                    $restored.Count -eq 1 -and
                    [string]$restored[0].NextHop -ceq [string]$identity.next_hop -and
                    [uint32]$restored[0].RouteMetric -eq [uint32]$identity.route_metric
                ) "managed route was not restored exactly from its journal"
            } catch {
                $managedJournalRecoveryFailure = $_
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

if ($null -ne $trialFailure) {
    if ($null -ne $managedJournalRecoveryFailure) {
        Write-Warning (
            "managed route journal recovery also failed: " +
            $managedJournalRecoveryFailure.Exception.Message
        ) -WarningAction Continue
    }
    throw $trialFailure
}
if ($null -ne $managedJournalRecoveryFailure) {
    throw $managedJournalRecoveryFailure
}
