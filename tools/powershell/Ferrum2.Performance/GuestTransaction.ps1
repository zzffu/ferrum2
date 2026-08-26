#requires -Version 7.4
param(
    [string]$Root,
    [string]$VmName,
    [string]$VmId,
    [string]$CheckpointName,
    [string]$CheckpointId,
    [string]$TopologyManifestSha256Value,
    [string]$TopologyPlanSha256Value,
    [string]$SupportSwitchName,
    [string]$SupportSwitchId,
    [string]$WintunZipSha256,
    [string]$WintunDllSha256,
    [string]$PowerShellVersion,
    [string]$PowerShellExecutableSha256,
    [long]$PowerShellFileCount,
    [long]$PowerShellExpandedBytes,
    [string]$RunKindValue,
    [string]$ParentCommit,
    [string]$CandidateCommit,
    [string]$ParentTree,
    [string]$CandidateTree,
    [string]$RecipeSha256,
    [string]$NetworkModelControllerSha256,
    [string]$NetworkModelPlanSha256,
    [string]$ControllerBundleSha256,
    [string]$GuestNetworkPathProbeSha256,
    [string]$ExpectedGuestNetworkPathJson,
    [string]$SupportAddress,
    [int]$SupportTcp,
    [int]$SupportUdp,
    [string]$ExpectedGuestAddress,
    [string]$ExpectedGuestInterfaceAlias,
    [string]$ExpectedSupportNetwork,
    [int]$ExpectedSupportPrefixLength,
    [string]$ExpectedSupportMacAddress,
    [string]$ExpectedSupportInterfaceGuid,
    [int]$ExpectedSupportMtuBytes,
    [int]$SupportProcessId,
    [string]$SupportProcessOwner,
    [int]$MinimumSupportIpv4PacketBytes,
    [string]$CanonicalSourceIpv4,
    [int]$CanonicalSourcePortFirst,
    [int]$CanonicalSourcePortLast,
    [int]$DiagnosticTrialSequenceValue,
    [string]$DiagnosticProfileValue,
    [string]$DiagnosticRunNonce,
    [int]$DiagnosticMaxEvents,
    [string]$UdpBoundaryCollectorSha256,
    [string]$DiagnosticSourceIpv4,
    [int]$DiagnosticSourcePortFirst,
    [int]$DiagnosticSourcePortLast
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object Text.UTF8Encoding($false)
$InputRoot = Join-Path $Root "input"
$EvidenceRoot = Join-Path $Root "raw-evidence"
$DiagnosticEvidenceRoot = Join-Path $Root "udp-diagnostic"
$NetworkModelEvidenceRoot = Join-Path $EvidenceRoot "network-model"
$InstrumentedDiagnostic = -not [string]::IsNullOrWhiteSpace(
    $DiagnosticProfileValue
)
$ProcessLogRoot = if ($InstrumentedDiagnostic) {
    Join-Path $DiagnosticEvidenceRoot "process-logs"
} else {
    Join-Path $EvidenceRoot "process-logs"
}
$AdapterName = "Ferrum2Perf"
if ($GuestNetworkPathProbeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($ExpectedGuestNetworkPathJson) -or
    $ExpectedGuestNetworkPathJson.Length -gt 8192 -or
    $ExpectedGuestNetworkPathJson -cmatch '[\r\n]') {
    throw "expected guest network-path identity is invalid"
}
$ExpectedGuestNetworkPath = $ExpectedGuestNetworkPathJson | ConvertFrom-Json
if (-not $Root.StartsWith("C:\Windows\Temp\ferrum2-tun-performance-", [StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath $InputRoot -PathType Container) -or
    (Test-Path -LiteralPath $EvidenceRoot) -or
    ($InstrumentedDiagnostic -and
        (Test-Path -LiteralPath $DiagnosticEvidenceRoot))) {
    throw "guest performance boundary is invalid"
}
if ($CanonicalSourceIpv4 -cne "198.18.0.2" -or
    $CanonicalSourcePortFirst -ne 20000 -or
    $CanonicalSourcePortLast -ne 28191 -or
    ($CanonicalSourcePortLast - $CanonicalSourcePortFirst + 1) -ne 8192) {
    throw "guest canonical UDP association source identity is invalid"
}
$controllerBundleRoot = Join-Path $InputRoot "controller"
$controllerBundleManifestPath = Join-Path $InputRoot "controller-bundle.json"
$controllerEvidenceModule = Join-Path $controllerBundleRoot `
    "modules\Ferrum2.Qualification.Evidence\Ferrum2.Qualification.Evidence.psd1"
$bootstrapRelative = "modules/Ferrum2.Qualification.Common/BundleBootstrap.ps1"
$bootstrapManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapEntry = @($bootstrapManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $controllerBundleRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw "guest performance bundle bootstrap changed"
}
. $bootstrapPath
$controllerBundleManifest = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $controllerBundleRoot
Import-Module $controllerEvidenceModule -Scope Local -Force -ErrorAction Stop
if ([string]$controllerBundleManifest.controller_bundle_sha256 -cne
        $ControllerBundleSha256) {
    throw "guest performance controller bundle identity changed"
}
if ($InstrumentedDiagnostic) {
    if ($DiagnosticProfileValue -cne "UdpFlowBoundary" -or
        $DiagnosticTrialSequenceValue -ne 31 -or
        $RunKindValue -cne "calibration-aa" -or
        $ParentCommit -cne $CandidateCommit -or
        $DiagnosticRunNonce -cnotmatch '^[1-9][0-9]{0,19}$' -or
        $DiagnosticMaxEvents -lt 1 -or $DiagnosticMaxEvents -gt 65536 -or
        $UdpBoundaryCollectorSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $DiagnosticSourceIpv4 -cne "198.18.0.2" -or
        $DiagnosticSourcePortFirst -ne 20000 -or
        $DiagnosticSourcePortLast -ne 28191 -or
        ($DiagnosticSourcePortLast - $DiagnosticSourcePortFirst + 1) -ne
            8192) {
        throw "guest UdpFlowBoundary diagnostic identity is invalid"
    }
} elseif (-not [string]::IsNullOrWhiteSpace($DiagnosticRunNonce) -or
    $DiagnosticMaxEvents -ne 0 -or
    -not [string]::IsNullOrWhiteSpace($DiagnosticSourceIpv4) -or
    $DiagnosticSourcePortFirst -ne 0 -or
    $DiagnosticSourcePortLast -ne 0) {
    throw "guest support diagnostic arguments require UdpFlowBoundary"
}
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$version = Get-ItemProperty `
    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
    -ErrorAction Stop
if ($computer.Manufacturer -cne "Microsoft Corporation" -or
    $computer.Model -cne "Virtual Machine" -or
    [string]$env:PROCESSOR_ARCHITECTURE -cne "AMD64" -or
    [string]$os.BuildNumber -cne [string]$version.CurrentBuildNumber) {
    throw "guest identity changed after staging"
}
$allInput = @(Get-Item -LiteralPath $InputRoot -Force) + @(
    Get-ChildItem -LiteralPath $InputRoot -Force -Recurse
)
if (@($allInput | Where-Object {
    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
}).Count -ne 0) {
    throw "guest staging cannot contain a reparse point"
}
if ($InstrumentedDiagnostic) {
    New-Item -ItemType Directory -Path $DiagnosticEvidenceRoot | Out-Null
} else {
    New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
    New-Item -ItemType Directory -Path $NetworkModelEvidenceRoot | Out-Null
}
New-Item -ItemType Directory -Path $ProcessLogRoot | Out-Null

$RustRoot = Join-Path $InputRoot "runtime\rust"
$PowerShell = Join-Path $InputRoot "runtime\pwsh\pwsh.exe"
$env:PATH = "$RustRoot;$env:PATH"
$rustVersion = @(& (Join-Path $RustRoot "rustc.exe") --version 2>&1)
if ($LASTEXITCODE -ne 0 -or ($rustVersion -join "`n") -cnotmatch '^rustc 1\.97\.1 \(') {
    throw "staged Rust 1.97.1 runtime verification failed"
}
$pwshItems = @(Get-Item -LiteralPath (Split-Path -Parent $PowerShell) -Force) + @(
    Get-ChildItem -LiteralPath (Split-Path -Parent $PowerShell) -Force -Recurse
)
$pwshFiles = @($pwshItems | Where-Object { -not $_.PSIsContainer })
$pwshBytes = [long]($pwshFiles | Measure-Object Length -Sum).Sum
if (@($pwshItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0 -or
    $pwshFiles.Count -ne $PowerShellFileCount -or
    $pwshBytes -ne $PowerShellExpandedBytes) {
    throw "staged PowerShell runtime boundary changed"
}
$pwshVersion = @(& $PowerShell -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
    [string]$pwshVersion[0] -cne $PowerShellVersion -or
    (Get-FileHash -LiteralPath $PowerShell -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $PowerShellExecutableSha256) {
    throw "staged PowerShell runtime identity verification failed"
}
$networkModelController = Join-Path $InputRoot "windows_tun_network_model.bundle.json"
$networkModelPlan = Join-Path $InputRoot "network-model-plan.json"
if (
    (Get-FileHash -LiteralPath $networkModelController -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne $NetworkModelControllerSha256 -or
    (Get-FileHash -LiteralPath $networkModelPlan -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne $NetworkModelPlanSha256
) {
    throw "staged network-model controller or plan identity changed"
}

$wintunZip = Join-Path $InputRoot "wintun-0.14.1.zip"
if ((Get-FileHash -LiteralPath $wintunZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $WintunZipSha256) {
    throw "guest Wintun ZIP hash mismatch"
}
$wintunRoot = Join-Path $Root "wintun"
Expand-Archive -LiteralPath $wintunZip -DestinationPath $wintunRoot -ErrorAction Stop
$wintunDll = Join-Path $wintunRoot "wintun\bin\amd64\wintun.dll"
if ((Get-FileHash -LiteralPath $wintunDll -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $WintunDllSha256 -or
    (Get-AuthenticodeSignature -LiteralPath $wintunDll).Status -ne "Valid") {
    throw "guest Wintun DLL trust boundary failed"
}
foreach ($member in @("parent", "candidate")) {
    $memberRoot = Join-Path $InputRoot "artifacts\$member"
    Copy-Item -LiteralPath $wintunDll -Destination (Join-Path $memberRoot "wintun.dll") `
        -ErrorAction Stop
    foreach ($runtimeDll in @(Get-ChildItem -LiteralPath (Join-Path $InputRoot "runtime\vc-runtime") -File)) {
        Copy-Item -LiteralPath $runtimeDll.FullName -Destination $memberRoot -ErrorAction Stop
    }
}
foreach ($runtimeDll in @(Get-ChildItem -LiteralPath (Join-Path $InputRoot "runtime\vc-runtime") -File)) {
    $harnessRuntimeDll = Join-Path (Join-Path $InputRoot "artifacts") $runtimeDll.Name
    if (-not (Test-Path -LiteralPath $harnessRuntimeDll -PathType Leaf) -or
        (Get-FileHash -LiteralPath $harnessRuntimeDll -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $runtimeDll.FullName -Algorithm SHA256).Hash) {
        throw "guest preflight Visual C++ runtime identity changed"
    }
}

$processOwnerSource = Join-Path $controllerBundleRoot "PerformanceProcessOwner.cs"
Add-Type -Path $processOwnerSource
. (Join-Path $controllerBundleRoot "GuestSupport.ps1")

$collector = Join-Path $controllerBundleRoot "collect_windows_tun_performance_trial.ps1"
$performanceSourceBundle = Join-Path $controllerBundleRoot "performance-source-bundle.json"
$udpBoundaryCollector = Join-Path $controllerBundleRoot `
    "collect_windows_tun_udp_boundary_diagnostic.ps1"
$harness = Join-Path $InputRoot "artifacts\m4-qualification.exe"
$collectorHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToLowerInvariant()
$performanceSourceBundleHash = (Get-FileHash -LiteralPath $performanceSourceBundle `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($InstrumentedDiagnostic -and (
    -not (Test-Path -LiteralPath $udpBoundaryCollector -PathType Leaf) -or
    (Get-FileHash -LiteralPath $udpBoundaryCollector -Algorithm SHA256).
        Hash.ToLowerInvariant() -cne $UdpBoundaryCollectorSha256
)) {
    throw "guest UDP boundary collector identity changed during staging"
}
$plan = Get-Content -LiteralPath (Join-Path $InputRoot "plan.json") -Raw -Encoding utf8 |
    ConvertFrom-Json
if ($plan.schema_version -ne 4 -or
    @($plan.trials).Count -ne 108 -or
    $plan.recipe_sha256 -cne $RecipeSha256 -or
    [string]$plan.controller_bundle_sha256 -cne $ControllerBundleSha256 -or
    $null -eq $plan.scenarios."udp-8192-association-lookup-expiry" -or
    $plan.scenarios."network-lifecycle".recipe.collector_source_sha256 `
        -cne $collectorHash -or
    $plan.scenarios."network-lifecycle".recipe.performance_source_bundle_sha256 `
        -cne $performanceSourceBundleHash -or
    $plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256 `
        -cne $NetworkModelControllerSha256 -or
    $plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256 `
        -cne $NetworkModelPlanSha256) {
    throw "guest trial plan changed during staging"
}
$udpBoundaryRecipe = $plan.scenarios.
    "udp-8192-association-lookup-expiry".recipe
if ([string]$udpBoundaryRecipe.canonical_source_port_strategy -cne
        "explicit_tun_ipv4_contiguous" -or
    [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
        $CanonicalSourceIpv4 -or
    [int]$udpBoundaryRecipe.canonical_source_port_first -ne
        $CanonicalSourcePortFirst -or
    [int]$udpBoundaryRecipe.canonical_source_port_last -ne
        $CanonicalSourcePortLast -or
    [int]$udpBoundaryRecipe.associations -ne 8192 -or
    ($CanonicalSourcePortLast - $CanonicalSourcePortFirst + 1) -ne
        [int]$udpBoundaryRecipe.associations) {
    throw "guest canonical UDP source-port plan changed during staging"
}
if ($InstrumentedDiagnostic -and (
    [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
        $DiagnosticSourceIpv4 -or
    [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
        $DiagnosticSourcePortFirst -or
    [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
        $DiagnosticSourcePortLast -or
    [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
        [string]$udpBoundaryRecipe.canonical_source_ipv4 -or
    [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
        [int]$udpBoundaryRecipe.canonical_source_port_first -or
    [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
        [int]$udpBoundaryRecipe.canonical_source_port_last -or
    [string]$udpBoundaryRecipe.diagnostic_collector_source_sha256 -cne
        $UdpBoundaryCollectorSha256)) {
    throw "guest UDP diagnostic source-port plan changed during staging"
}
if ($DiagnosticTrialSequenceValue -lt 0 -or
    $DiagnosticTrialSequenceValue -gt 108 -or
    ($DiagnosticTrialSequenceValue -gt 0 -and $RunKindValue -cne "calibration-aa")) {
    throw "guest diagnostic trial selection is invalid"
}
$executionTrials = @(if ($DiagnosticTrialSequenceValue -gt 0) {
    $plan.trials | Where-Object {
        [int]$_.sequence -eq $DiagnosticTrialSequenceValue
    } | Sort-Object sequence
} else {
    $plan.trials | Sort-Object sequence
})
if (($DiagnosticTrialSequenceValue -gt 0 -and $executionTrials.Count -ne 1) -or
    ($DiagnosticTrialSequenceValue -eq 0 -and $executionTrials.Count -ne 108)) {
    throw "guest canonical trial execution selection is invalid"
}
if ($InstrumentedDiagnostic -and (
    [string]$executionTrials[0].scenario -cne
        "udp-8192-association-lookup-expiry" -or
    [string]$executionTrials[0].member -cne "parent"
)) {
    throw "guest UdpFlowBoundary trial identity mismatch"
}
$expectedTrialCount = if ($InstrumentedDiagnostic) { 0 } else {
    $executionTrials.Count
}
$expectedNetworkModelObservationCount = if ($InstrumentedDiagnostic) { 0 } else {
    @($executionTrials | Where-Object {
        [string]$_.scenario -in @("udp-route-once", "network-lifecycle")
    }).Count
}
$expectedProcessLogCount = if ($InstrumentedDiagnostic) { 4 } else {
    4 * $expectedTrialCount
}
$instrumentedTrialStatus = $null
$instrumentedEvidenceStatus = $null
$guestNetworkPath = Get-GuestNetworkPath
$guestUnderlayAddress = [string]$guestNetworkPath.guest_ipv4
$supportProbeResult = Invoke-NativeCapture $harness @(
    "windows-tun-probe", "--target-ip", $SupportAddress,
    "--tcp-port", [string]$SupportTcp, "--udp-port", [string]$SupportUdp
)
$supportProbe = @($supportProbeResult.Output)
if ($supportProbeResult.ExitCode -ne 0 -or $supportProbe.Count -ne 1 -or
    [string]$supportProbe[0] -cne "windows_tun_probe status=PASS protocols=tcp,udp") {
    throw "guest support listener preflight failed"
}

foreach ($trial in $executionTrials) {
    if (Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
        throw "managed performance adapter baseline is not absent"
    }
    [void](Get-GuestNetworkPath)
    $member = [string]$trial.member
    $memberRoot = Join-Path $InputRoot "artifacts\$member"
    $client = Join-Path $memberRoot "ferrum2-client.exe"
    $server = Join-Path $memberRoot "ferrum2-server.exe"
    $memberCommit = if ($member -ceq "parent") { $ParentCommit } else { $CandidateCommit }
    $memberTree = if ($member -ceq "parent") { $ParentTree } else { $CandidateTree }
    $trialRoot = Join-Path $Root ("trial-{0:D3}" -f [int]$trial.sequence)
    New-Item -ItemType Directory -Path $trialRoot | Out-Null
    $metricsPort = Get-FreeTcpPort
    $serverPort = 0
    foreach ($attempt in 1..100) {
        $candidatePort = Get-FreeDualPort -LocalAddress $guestUnderlayAddress
        if ($candidatePort -ne $metricsPort) {
            $serverPort = $candidatePort
            break
        }
    }
    if ($serverPort -eq 0) { throw "unable to reserve a distinct server port" }
    $serverMetricsPort = 0
    foreach ($attempt in 1..100) {
        $candidatePort = Get-FreeTcpPort
        if ($candidatePort -ne $metricsPort -and $candidatePort -ne $serverPort) {
            $serverMetricsPort = $candidatePort
            break
        }
    }
    if ($serverMetricsPort -eq 0) {
        throw "unable to reserve a distinct server metrics port"
    }
    $clientConfig = Join-Path $trialRoot "client.toml"
    $serverConfig = Join-Path $trialRoot "server.toml"
    $ledger = Join-Path $trialRoot "identity-ledger.json"
    $logPrefix = "{0:D3}-{1}-{2}" -f @(
        [int]$trial.sequence,
        [string]$trial.scenario,
        $member
    )
    $clientStdout = Join-Path $ProcessLogRoot "$logPrefix-client.stdout.log"
    $clientStderr = Join-Path $ProcessLogRoot "$logPrefix-client.stderr.log"
    $serverStdout = Join-Path $ProcessLogRoot "$logPrefix-server.stdout.log"
    $serverStderr = Join-Path $ProcessLogRoot "$logPrefix-server.stderr.log"
    foreach ($logPath in @($clientStdout, $clientStderr, $serverStdout, $serverStderr)) {
        if (Test-Path -LiteralPath $logPath) {
            throw "performance process log baseline is not absent"
        }
    }
    $clientText = Get-Content -LiteralPath (Join-Path $InputRoot "client.toml.template") -Raw
    $clientText = $clientText.Replace("{{ADAPTER_NAME}}", $AdapterName).
        Replace("{{SUPPORT_IPV4}}", $SupportAddress).
        Replace("{{SUPPORT_UDP_PORT}}", [string]$SupportUdp).
        Replace("{{SUPPORT_INTERFACE_ALIAS}}", $ExpectedGuestInterfaceAlias).
        Replace("{{GUEST_SUPPORT_IPV4}}", $ExpectedGuestAddress).
        Replace("{{SERVER_ADDRESS}}", $guestUnderlayAddress).
        Replace("{{SERVER_PORT}}", [string]$serverPort).
        Replace("{{METRICS_PORT}}", [string]$metricsPort)
    $serverText = (Get-Content -LiteralPath (Join-Path $InputRoot "server.toml.template") -Raw).
        Replace("{{SUPPORT_INTERFACE_ALIAS}}", $ExpectedGuestInterfaceAlias).
        Replace("{{GUEST_SUPPORT_IPV4}}", $ExpectedGuestAddress).
        Replace("{{SERVER_ADDRESS}}", $guestUnderlayAddress).
        Replace("{{SERVER_PORT}}", [string]$serverPort).
        Replace("{{SERVER_METRICS_PORT}}", [string]$serverMetricsPort)
    if ($clientText.Contains("{{") -or $serverText.Contains("{{")) {
        throw "configuration template substitution is incomplete"
    }
    [IO.File]::WriteAllText($clientConfig, $clientText, $Utf8NoBom)
    [IO.File]::WriteAllText($serverConfig, $serverText, $Utf8NoBom)
    $clientHash = (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash.ToLowerInvariant()
    $serverHash = (Get-FileHash -LiteralPath $server -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-CanonicalLedger $ledger $memberCommit $clientHash $serverHash `
        $collectorHash $ControllerBundleSha256

    $clientCheckResult = Invoke-NativeCapture $client @(
        "--config", $clientConfig, "--check-config"
    )
    $clientCheck = @($clientCheckResult.Output)
    if ($clientCheckResult.ExitCode -ne 0 -or $clientCheck.Count -ne 1 -or
        [string]$clientCheck[0] -cne "configuration valid") {
        throw "client performance configuration is invalid"
    }
    $serverCheckResult = Invoke-NativeCapture $server @(
        "--config", $serverConfig, "--check-config"
    )
    $serverCheck = @($serverCheckResult.Output)
    if ($serverCheckResult.ExitCode -ne 0 -or $serverCheck.Count -ne 1 -or
        [string]$serverCheck[0] -cne "configuration valid") {
        throw "server performance configuration is invalid"
    }

    $serverPid = 0
    $clientPid = 0
    $trialFailure = $null
    try {
        $serverPid = [Ferrum2PerfProcessGroup]::Start(
            $server, "--config `"$serverConfig`"", $memberRoot,
            $serverStdout, $serverStderr
        )
        Wait-ProcessListener -ProcessId $serverPid `
            -LocalAddress $guestUnderlayAddress -Port $serverPort -RequireUdp $true
        Wait-ProcessListener -ProcessId $serverPid `
            -LocalAddress "127.0.0.1" -Port $serverMetricsPort -RequireUdp $false
        $serverNetworkBaseline = Wait-ServerNetworkStable `
            -ProcessId $serverPid -MetricsPort $serverMetricsPort `
            -Baseline $null -RequireAdvance $false
        $clientPid = [Ferrum2PerfProcessGroup]::Start(
            $client, "--config `"$clientConfig`"", $memberRoot,
            $clientStdout, $clientStderr
        )
        Wait-TunReady $clientPid $metricsPort
        [void](Wait-ServerNetworkStable `
            -ProcessId $serverPid -MetricsPort $serverMetricsPort `
            -Baseline $serverNetworkBaseline -RequireAdvance $true)
        Wait-ProcessListener -ProcessId $serverPid `
            -LocalAddress $guestUnderlayAddress -Port $serverPort -RequireUdp $true
        Wait-ProcessListener -ProcessId $serverPid `
            -LocalAddress "127.0.0.1" -Port $serverMetricsPort -RequireUdp $false
        Wait-TunReady $clientPid $metricsPort
        if ($InstrumentedDiagnostic) {
            $diagnosticRawOutput = Join-Path $DiagnosticEvidenceRoot `
                "guest-raw.json"
            $boundaryArguments = @(
                "-NoProfile", "-File", $udpBoundaryCollector,
                "-Profile", $DiagnosticProfileValue,
                "-RunKind", $RunKindValue,
                "-Member", $member,
                "-TrialSequence", [string]$trial.sequence,
                "-ParentSha", $ParentCommit,
                "-CandidateSha", $CandidateCommit,
                "-Tree", $memberTree,
                "-RecipeSha256", $RecipeSha256,
                "-ControllerBundleSha256", $ControllerBundleSha256,
                "-HarnessBinary", $harness,
                "-TargetIpv4", $SupportAddress,
                "-TargetTcpPort", [string]$SupportTcp,
                "-TargetUdpPort", [string]$SupportUdp,
                "-TunAdapterName", $AdapterName,
                "-ClientPid", [string]$clientPid,
                "-ServerPid", [string]$serverPid,
                "-ClientMetricsPort", [string]$metricsPort,
                "-DiagnosticRunNonce", $DiagnosticRunNonce,
                "-DiagnosticMaxEvents", [string]$DiagnosticMaxEvents,
                "-OutputDirectory", $DiagnosticEvidenceRoot,
                "-Output", $diagnosticRawOutput
            )
            $boundaryResult = Invoke-NativeCapture $PowerShell $boundaryArguments
            $boundaryLines = @($boundaryResult.Output | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    [string]$_.Exception.Message
                } else {
                    [string]$_
                }
            })
            if ($boundaryResult.ExitCode -ne 0 -or
                $boundaryLines.Count -ne 1 -or
                [string]$boundaryLines[0] -cnotmatch
                    '^windows_tun_udp_boundary evidence=(COMPLETE|PARTIAL) trial=(PASS|FAIL) output=' -or
                -not (Test-Path -LiteralPath $diagnosticRawOutput -PathType Leaf) -or
                (Get-Item -LiteralPath $diagnosticRawOutput).Length -gt 1048576) {
                throw "Windows TUN UDP boundary helper did not retain a valid raw result"
            }
            $diagnosticRaw = Get-Content -LiteralPath $diagnosticRawOutput `
                -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            if ([string]$diagnosticRaw.schema -cne
                    "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v2" -or
                $diagnosticRaw.qualification -ne $false -or
                [string]$diagnosticRaw.profile -cne $DiagnosticProfileValue -or
                [string]$diagnosticRaw.identity.run_kind -cne $RunKindValue -or
                [string]$diagnosticRaw.identity.member -cne $member -or
                [int]$diagnosticRaw.identity.trial_sequence -ne
                    [int]$trial.sequence -or
                [string]$diagnosticRaw.identity.parent_sha -cne $ParentCommit -or
                [string]$diagnosticRaw.identity.candidate_sha -cne
                    $CandidateCommit -or
                [string]$diagnosticRaw.identity.controller_bundle_sha256 -cne
                    $ControllerBundleSha256 -or
                [string]$diagnosticRaw.identity.collector_sha256 -cne
                    $UdpBoundaryCollectorSha256 -or
                [string]$diagnosticRaw.identity.diagnostic_run_nonce -cne
                    $DiagnosticRunNonce -or
                [int]$diagnosticRaw.identity.diagnostic_max_events -ne
                    $DiagnosticMaxEvents -or
                [string]$diagnosticRaw.workload.source_ip -cne
                    $DiagnosticSourceIpv4 -or
                [int]$diagnosticRaw.workload.source_port_first -ne
                    $DiagnosticSourcePortFirst -or
                [int]$diagnosticRaw.workload.source_port_last -ne
                    $DiagnosticSourcePortLast -or
                [string]$diagnosticRaw.evidence_status -cnotin
                    @("COMPLETE", "PARTIAL") -or
                [string]$diagnosticRaw.trial_status -cnotin @("PASS", "FAIL")) {
                throw "Windows TUN UDP boundary raw result identity mismatch"
            }
            $instrumentedTrialStatus = [string]$diagnosticRaw.trial_status
            $instrumentedEvidenceStatus = [string]$diagnosticRaw.evidence_status
        } else {
        $outputName = "{0:D3}-{1}-{2}-pair-{3}.json" -f @(
            [int]$trial.sequence, [string]$trial.scenario, $member, [int]$trial.pair
        )
        $output = Join-Path $EvidenceRoot $outputName
        $collectorArguments = @(
            "-NoProfile", "-File", $collector,
            "-Scenario", [string]$trial.scenario,
            "-RunKind", $RunKindValue,
            "-Member", $member,
            "-Pair", [string]$trial.pair,
            "-Order", [string]$trial.order,
            "-Sequence", [string]$trial.sequence,
            "-ParentSha", $ParentCommit,
            "-CandidateSha", $CandidateCommit,
            "-Tree", $memberTree,
            "-RecipeSha256", $RecipeSha256,
            "-ControllerBundleSha256", $ControllerBundleSha256,
            "-ClientBinary", $client,
            "-ServerBinary", $server,
            "-HarnessBinary", $harness,
            "-IdentityLedger", $ledger,
            "-ExpectedCheckpointId", $CheckpointId,
            "-ExpectedTopologyManifestSha256", $TopologyManifestSha256Value,
            "-ExpectedTopologyPlanSha256", $TopologyPlanSha256Value,
            "-ExpectedSupportSwitchId", $SupportSwitchId,
            "-NetworkModelPlan", $networkModelPlan,
            "-NetworkModelController", $networkModelController,
            "-AdapterName", $AdapterName,
            "-ClientPid", [string]$clientPid,
            "-ServerPid", [string]$serverPid,
            "-MetricsPort", [string]$metricsPort,
            "-ServerMetricsPort", [string]$serverMetricsPort,
            "-ExpectedFixedEndpointIpv4", $ExpectedGuestAddress,
            "-ExpectedUnderlayInterfaceIndex",
                [string]$ExpectedGuestNetworkPath.guest_interface_index,
            "-ExpectedUnderlayInterfaceAlias", $ExpectedGuestInterfaceAlias,
            "-ExpectedUnderlayInterfaceGuid", $ExpectedSupportInterfaceGuid,
            "-Output", $output
        )
        if ([string]$trial.scenario -ceq
                "udp-8192-association-lookup-expiry") {
            $collectorArguments += @(
                "-UdpAssociationSourceIpv4", $CanonicalSourceIpv4,
                "-UdpAssociationSourcePortFirst", [string]$CanonicalSourcePortFirst,
                "-UdpAssociationSourcePortLast", [string]$CanonicalSourcePortLast
            )
        }
        if ([string]$trial.scenario -in @("udp-route-once", "network-lifecycle")) {
            $networkModelOutput = Join-Path $NetworkModelEvidenceRoot (
                "{0:D3}-{1}-{2}-pair-{3}.network-model.json" -f `
                    [int]$trial.sequence, [string]$trial.scenario,
                    $member, [int]$trial.pair
            )
            $collectorArguments += @("-NetworkModelOutput", $networkModelOutput)
        }
        $collectorResult = Invoke-NativeCapture $PowerShell $collectorArguments
        $collectorOutput = @($collectorResult.Output)
        $collectorExit = $collectorResult.ExitCode
        $collectorLines = @($collectorOutput | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                [string]$_.Exception.Message
            } else {
                [string]$_
            }
        })
        $expectedCollectorOutput = "windows_tun_trial status=PASS " +
            "scenario=$($trial.scenario) member=$member pair=$($trial.pair) " +
            "order=$($trial.order) sequence=$($trial.sequence) output=$output"
        if ($collectorExit -ne 0 -or $collectorLines.Count -ne 1 -or
            [string]$collectorLines[0] -cne $expectedCollectorOutput -or
            -not (Test-Path -LiteralPath $output -PathType Leaf) -or
            (Get-Item -LiteralPath $output).Length -gt 1048576) {
            $snapshotFailures = New-Object Collections.Generic.List[string]
            foreach ($snapshot in @(
                [pscustomobject]@{ Name = "client"; Port = $metricsPort },
                [pscustomobject]@{ Name = "server"; Port = $serverMetricsPort }
            )) {
                try {
                    $metricsText = [string](Invoke-WebRequest -UseBasicParsing `
                        -Uri "http://127.0.0.1:$($snapshot.Port)/metrics" `
                        -TimeoutSec 5 -ErrorAction Stop).Content
                    if ($Utf8NoBom.GetByteCount($metricsText) -gt 1048576) {
                        throw "$($snapshot.Name) failure metrics exceeded 1 MiB"
                    }
                    [IO.File]::WriteAllText(
                        (Join-Path $ProcessLogRoot `
                            "$logPrefix-$($snapshot.Name).failure.metrics.txt"),
                        $metricsText,
                        $Utf8NoBom
                    )
                } catch {
                    [void]$snapshotFailures.Add(
                        "$($snapshot.Name) metrics snapshot failed: $($_.Exception.Message)"
                    )
                }
            }
            $failureText = (@($collectorLines) + @($snapshotFailures)) -join "`n"
            if ($failureText.Length -gt 16384) {
                $failureText = $failureText.Substring(0, 16384)
            }
            $failurePath = Join-Path $ProcessLogRoot `
                "$logPrefix-collector.failure.txt"
            [IO.File]::WriteAllText($failurePath, $failureText, $Utf8NoBom)
            $failureDetail = if ($failureText.Length -gt 2048) {
                $failureText.Substring(0, 2048)
            } else {
                $failureText
            }
            throw "Windows TUN collector trial failed: sequence=$($trial.sequence) detail=$failureDetail"
        }
        $trialEvidence = Get-Content -LiteralPath $output -Raw -Encoding utf8 |
            ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-JsonInteger -Value $trialEvidence.schema_version) -or
            $trialEvidence.schema_version -ne 5 -or
            $trialEvidence.kind -isnot [string] -or
            $trialEvidence.kind -cne "windows_tun_performance_trial" -or
            $trialEvidence.selection -isnot [string] -or
            $trialEvidence.selection -cne [string]$plan.selection -or
            $trialEvidence.run_kind -isnot [string] -or
            $trialEvidence.run_kind -cne $RunKindValue -or
            $trialEvidence.controller_bundle_sha256 -isnot [string] -or
            $trialEvidence.controller_bundle_sha256 -cne $ControllerBundleSha256 -or
            -not (Test-JsonInteger -Value $trialEvidence.sequence) -or
            $trialEvidence.sequence -ne $trial.sequence -or
            $trialEvidence.scenario -isnot [string] -or
            $trialEvidence.scenario -cne [string]$trial.scenario -or
            $trialEvidence.member -isnot [string] -or
            $trialEvidence.member -cne $member -or
            -not (Test-JsonInteger -Value $trialEvidence.pair) -or
            $trialEvidence.pair -ne $trial.pair -or
            -not (Test-JsonInteger -Value $trialEvidence.order) -or
            $trialEvidence.order -ne $trial.order) {
            throw "Windows TUN collector output identity does not match the planned trial"
        }
        }
    } catch {
        $trialFailure = $_
    } finally {
        $stopFailures = New-Object Collections.Generic.List[string]
        if ($clientPid -gt 0) {
            try { Stop-OwnedProcess $clientPid "client" }
            catch { [void]$stopFailures.Add($_.Exception.Message) }
        }
        try { Wait-AdapterAbsent }
        catch { [void]$stopFailures.Add($_.Exception.Message) }
        if ($serverPid -gt 0) {
            try { Stop-OwnedProcess $serverPid "server" }
            catch { [void]$stopFailures.Add($_.Exception.Message) }
        }
        if ($stopFailures.Count -ne 0) {
            $cleanupFailure = $stopFailures -join "; "
            $failureMessage = if ($null -eq $trialFailure) {
                $cleanupFailure
            } else {
                "$($trialFailure.Exception.Message); cleanup: $cleanupFailure"
            }
            $trialFailure = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new($failureMessage),
                "Ferrum2PerformanceCleanup",
                [Management.Automation.ErrorCategory]::OperationStopped,
                $trialRoot
            )
        }
    }
    if ($null -ne $trialFailure) { throw $trialFailure }
}
$files = @(if ($InstrumentedDiagnostic) { @() } else {
    Get-ChildItem -LiteralPath $EvidenceRoot -File -Filter "*.json"
})
$networkModelFiles = @(if ($InstrumentedDiagnostic) { @() } else {
    Get-ChildItem -LiteralPath $NetworkModelEvidenceRoot -File `
        -Filter "*.network-model.json"
})
$processLogFiles = @(Get-ChildItem -LiteralPath $ProcessLogRoot -File -Filter "*.log")
if ($files.Count -ne $expectedTrialCount -or
    $networkModelFiles.Count -ne $expectedNetworkModelObservationCount -or
    $processLogFiles.Count -ne $expectedProcessLogCount) {
    throw "guest evidence set is incomplete"
}
if ($InstrumentedDiagnostic) {
    $diagnosticFiles = @(Get-ChildItem -LiteralPath $DiagnosticEvidenceRoot `
        -File -Recurse -ErrorAction Stop)
    $diagnosticLengths = @($diagnosticFiles | ForEach-Object { [long]$_.Length })
    if ($instrumentedTrialStatus -cnotin @("PASS", "FAIL") -or
        $instrumentedEvidenceStatus -cnotin @("COMPLETE", "PARTIAL") -or
        $diagnosticFiles.Count -lt 8 -or $diagnosticFiles.Count -gt 32 -or
        [long]($diagnosticLengths | Measure-Object -Sum).Sum -gt 335544320 -or
        [long]($diagnosticLengths | Measure-Object -Maximum).Maximum -gt 268451840) {
        throw "guest UDP diagnostic evidence set exceeds its closed boundary"
    }
}
$guestControllerResult = [ordered]@{
    status = "PASS"
    trials = $files.Count
    network_model_observations = $networkModelFiles.Count
    process_logs = $processLogFiles.Count
    evidence_path = if ($InstrumentedDiagnostic) {
        $DiagnosticEvidenceRoot
    } else {
        $EvidenceRoot
    }
    powershell_version = [string]$pwshVersion[0]
    powershell_executable_sha256 = $PowerShellExecutableSha256
}
if ($InstrumentedDiagnostic) {
    $cpuRows = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    if ($cpuRows.Count -le 0) { throw "guest CPU identity is unavailable" }
    $powerText = (& powercfg.exe /getactivescheme 2>&1 | Out-String)
    $powerMatch = [regex]::Match(
        $powerText,
        '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    )
    if (-not $powerMatch.Success) {
        throw "guest active power plan identity is unavailable"
    }
    $guestControllerResult["diagnostic_profile"] = $DiagnosticProfileValue
    $guestControllerResult["diagnostic_evidence_status"] = `
        $instrumentedEvidenceStatus
    $guestControllerResult["diagnostic_trial_status"] = $instrumentedTrialStatus
    $guestControllerResult["guest_build"] = `
        "$($version.CurrentBuildNumber).$($version.UBR)"
    $guestControllerResult["cpu_model"] = `
        (@($cpuRows | ForEach-Object { $_.Name.Trim() }) -join " | ")
    $guestControllerResult["cpu_count"] = `
        [int]$computer.NumberOfLogicalProcessors
    $guestControllerResult["memory_bytes"] = `
        [uint64]$computer.TotalPhysicalMemory
    $guestControllerResult["power_plan_guid"] = `
        $powerMatch.Value.ToLowerInvariant()
}
