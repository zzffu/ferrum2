#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Collects and reduces Windows TUN performance evidence in the approved local Hyper-V guest.

.DESCRIPTION
The host builds exact commits, stages portable dependencies through PowerShell Direct, exports raw
evidence, and runs the repository performance reducer. Every adapter, route, TUN, traffic, and
product-process operation runs inside the pinned guest. The host never changes a network adapter,
address, route, DNS setting, firewall rule, WFP object, or TUN session.

The default credential is the current-user DPAPI-protected PSCredential at
%LOCALAPPDATA%\Ferrum2\hyperv-ferrum2-test.credential.xml. The password is never accepted as a
parameter and the credential must remain outside this repository.

The portable guest controller defaults to the SHA-256-pinned PowerShell 7.4.19 win-x64 archive at
%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip. The archive must remain outside the repository.

Run mode requires the SHA-256-pinned external manifest created by the reviewed support-topology
provisioner and an already provisioned candidate qualification support listener. The listener
provides TCP echo, ordinary UDP echo, bounded fragment acknowledgements, and four contiguous UDP
ports, and must bind the manifest's dedicated host /30 address. Before any TUN session starts, the
runner proves that both directions use the isolated Internal switch and the exact manifest-bound
host and guest interfaces. The path and generated identities are retained as evidence.

PlanOnly validates repository lineage and emits the closed 108-trial plan without building, starting
the VM, loading a credential, staging files, or executing traffic.

DiagnosticTrialSequence runs exactly one canonical A/A trial while retaining the complete plan and
the ordinary evidence-export and VM-restore boundaries. Diagnostic evidence is explicitly not a
qualification result and cannot be used for comparison or calibration adoption.

DiagnosticProfile UdpFlowBoundary is restricted to calibration-aa sequence 31. It writes an
independent bounded guest/host flow diagnostic under udp-diagnostic and preserves the canonical
performance and diagnostic evidence paths unchanged.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseUsingScopeModifierInNewRunspaces",
    "",
    Justification = "All remoting values are bound through explicit ArgumentList and param blocks."
)]
[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [switch]$PlanOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateSet("calibration-aa", "comparison")]
    [string]$RunKind,

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ParentSha,

    [Parameter(ParameterSetName = "Plan")]
    [Parameter(ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(ParameterSetName = "Run")]
    [string]$CredentialPath,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(1, 108)]
    [int]$DiagnosticTrialSequence,

    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("UdpFlowBoundary")]
    [string]$DiagnosticProfile,

    [Parameter(ParameterSetName = "Run")]
    [string]$SupportDiagnosticLedger,

    [Parameter(ParameterSetName = "Run")]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$SupportDiagnosticRunNonce,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(1, 65536)]
    [int]$SupportDiagnosticMaxEvents,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$diagnosticMode = $PSBoundParameters.ContainsKey("DiagnosticTrialSequence")
$instrumentedDiagnosticMode = $PSBoundParameters.ContainsKey("DiagnosticProfile")
if ($diagnosticMode -and $RunKind -cne "calibration-aa") {
    throw "DiagnosticTrialSequence is restricted to calibration-aa runs"
}
$supportDiagnosticParameterNames = @(
    "SupportDiagnosticLedger",
    "SupportDiagnosticRunNonce",
    "SupportDiagnosticMaxEvents"
)
$supportDiagnosticParametersSupplied = @($supportDiagnosticParameterNames | Where-Object {
    $PSBoundParameters.ContainsKey($_)
})
if ($instrumentedDiagnosticMode) {
    if (-not $diagnosticMode -or $DiagnosticTrialSequence -ne 31 -or
        $RunKind -cne "calibration-aa") {
        throw "UdpFlowBoundary requires calibration-aa and DiagnosticTrialSequence 31"
    }
    if ($supportDiagnosticParametersSupplied.Count -ne
        $supportDiagnosticParameterNames.Count) {
        throw "UdpFlowBoundary requires the complete support diagnostic ledger parameter group"
    }
    $parsedDiagnosticRunNonce = [uint64]0
    if (-not [uint64]::TryParse(
            $SupportDiagnosticRunNonce,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedDiagnosticRunNonce
        ) -or $parsedDiagnosticRunNonce -eq 0 -or
        $parsedDiagnosticRunNonce.ToString(
            [Globalization.CultureInfo]::InvariantCulture
        ) -cne $SupportDiagnosticRunNonce) {
        throw "support diagnostic run nonce must be a canonical nonzero u64"
    }
} elseif ($supportDiagnosticParametersSupplied.Count -ne 0) {
    throw "support diagnostic ledger parameters require DiagnosticProfile UdpFlowBoundary"
}

$approvedVmName = ""
$approvedVmId = [Guid]::Empty
$approvedCheckpointName = ""
$approvedCheckpointId = [Guid]::Empty
$approvedVmSwitchName = ""
$supportGuestIpv4 = ""
$supportGuestInterfaceAlias = ""
$supportNetwork = ""
$supportPrefixLength = 0
$supportVmMacAddress = ""
$topologyManifestDocument = $null
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$minimumSupportIpv4PacketBytes = 1468
$udpAssociationSourceIpv4 = "198.18.0.2"
$udpAssociationSourcePortFirst = 20000
$udpAssociationSourcePortLast = 28191
$udpAssociationCount = 8192
$toolsRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") -ErrorAction Stop).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $toolsRoot "..") -ErrorAction Stop).Path
$approvedRustTarget = "x86_64-pc-windows-msvc"
$reproducibleRustSourceRoot = "C:\ferrum2-reproducible-source"
$policyPath = Join-Path $toolsRoot "windows_tun_performance_policy.json"
$controlModule = "tools.performance_candidate"
$controlEntryPath = Join-Path $toolsRoot "performance_candidate\__main__.py"
$collectorPath = Join-Path $PSScriptRoot "collect_windows_tun_performance_trial.ps1"
$udpBoundaryCollectorPath = Join-Path $PSScriptRoot `
    "collect_windows_tun_udp_boundary_diagnostic.ps1"
$guestNetworkPathProbePath = Join-Path $PSScriptRoot `
    "get_windows_tun_guest_network_path.ps1"
$hostNetworkPathHelperPath = Join-Path $PSScriptRoot `
    "windows_tun_host_network_path.ps1"
$topologyRuntimePath = Join-Path $PSScriptRoot `
    "windows_tun_hyperv_support_topology_runtime.ps1"
$networkModelControllerPath = Join-Path $repositoryRoot `
    "tools\performance_candidate\windows_tun\network_model.py"
$networkModelBundleManifestPath = Join-Path $repositoryRoot `
    "tools\performance_candidate\windows_tun\network_model_bundle.json"
$performanceSourceBundlePath = Join-Path $toolsRoot `
    "powershell\Ferrum2.Performance\bundle.json"
$performanceSourceBundle = Get-Content -LiteralPath $performanceSourceBundlePath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bundleBootstrapRelative = `
    "tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1"
$bundleBootstrapEntry = @($performanceSourceBundle.files | Where-Object {
    [string]$_.path -ceq $bundleBootstrapRelative
})
$bundleBootstrapPath = Join-Path $repositoryRoot `
    $bundleBootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bundleBootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bundleBootstrapPath -Algorithm SHA256 `
        -ErrorAction Stop).Hash.ToLowerInvariant() -cne
        [string]$bundleBootstrapEntry[0].sha256) {
    throw "performance source bundle bootstrap changed"
}
. $bundleBootstrapPath
$performanceSourcePaths = @(
    'tools/windows-tun/collect_windows_tun_performance_trial.ps1'
    'tools/windows-tun/collect_windows_tun_udp_boundary_diagnostic.ps1'
    'tools/powershell/Ferrum2.Performance/CollectorCore.ps1'
    'tools/powershell/Ferrum2.Performance/CollectorLifecycle.ps1'
    'tools/powershell/Ferrum2.Performance/CollectorUdpSource.ps1'
    'tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psd1'
    'tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psm1'
    'tools/powershell/Ferrum2.Performance/GuestSupport.ps1'
    'tools/powershell/Ferrum2.Performance/GuestTransaction.ps1'
    'tools/powershell/Ferrum2.Performance/HostContract.ps1'
    'tools/powershell/Ferrum2.Performance/HostUdpEvidence.ps1'
    'tools/powershell/Ferrum2.Performance/HostUdpResult.ps1'
    'tools/powershell/Ferrum2.Performance/HostVmTransaction.ps1'
    'tools/powershell/Ferrum2.Performance/PerformanceProcessOwner.cs'
    'tools/powershell/Ferrum2.Performance/RuntimeStaging.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.fragment-reassembly-throughput.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.idle-cpu-wakeup.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.network-lifecycle.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.tcp-256-flow-fairness.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.tcp-single-flow.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.udp-8192-association-lookup-expiry.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.udp-packets-per-second.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.udp-route-once.ps1'
    'tools/powershell/Ferrum2.Performance/TrialScenario.wintun-ring-full-drop-rate.ps1'
    'tools/powershell/Ferrum2.Performance/UdpDiagnosticCore.ps1'
    'tools/powershell/Ferrum2.Performance/UdpDiagnosticEvidence.ps1'
    'tools/powershell/Ferrum2.Performance/UdpDiagnosticSource.ps1'
    'tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
    'tools/powershell/Ferrum2.Qualification.Common/Ferrum2.Qualification.Common.psd1'
    'tools/powershell/Ferrum2.Qualification.Common/Ferrum2.Qualification.Common.psm1'
    'tools/powershell/Ferrum2.Qualification.Evidence/Ferrum2.Qualification.Evidence.psd1'
    'tools/powershell/Ferrum2.Qualification.Evidence/Ferrum2.Qualification.Evidence.psm1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/Ferrum2.Qualification.HostHyperV.psd1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/Ferrum2.Qualification.HostHyperV.psm1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Artifacts.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Evidence.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Facade.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Manifest.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Paths.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/Process.ps1'
    'tools/powershell/Ferrum2.Qualification.HostHyperV/private/VmTransaction.ps1'
    'tools/windows-tun/run_windows_tun_performance_hyperv.ps1'
)
$runnerSourceSha256 = Assert-Ferrum2BootstrapSourceManifest `
    -ManifestPath $performanceSourceBundlePath `
    -RepositoryRoot $repositoryRoot `
    -ExpectedKind "ferrum2.windows-tun-performance-source-bundle.v1" `
    -ExpectedEntrypoint "tools/windows-tun/run_windows_tun_performance_hyperv.ps1" `
    -ExpectedPaths $performanceSourcePaths
$qualificationEvidenceModulePath = Join-Path $repositoryRoot `
    "tools\powershell\Ferrum2.Qualification.Evidence\Ferrum2.Qualification.Evidence.psd1"
Import-Module $qualificationEvidenceModulePath -Scope Local -Force -ErrorAction Stop
$hostHyperVModulePath = Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Qualification.HostHyperV\Ferrum2.Qualification.HostHyperV.psd1'
Import-Module $hostHyperVModulePath -Scope Local -Force -ErrorAction Stop
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$topologyRuntimeSha256 = ""
$guestNetworkPathProbeSourceSha256 = ""
$udpBoundaryCollectorSourceSha256 = ""
$performanceModuleRoot = Join-Path $toolsRoot "powershell\Ferrum2.Performance"
$performanceModuleManifestPath = Join-Path $performanceModuleRoot `
    "Ferrum2.Performance.psd1"
Import-Module $performanceModuleManifestPath -Scope Local -Force -ErrorAction Stop
$hostContractPath = Join-Path $performanceModuleRoot "HostContract.ps1"
$hostUdpEvidencePath = Join-Path $performanceModuleRoot "HostUdpEvidence.ps1"
$runtimeStagingPath = Join-Path $performanceModuleRoot "RuntimeStaging.ps1"
$hostVmTransactionPath = Join-Path $performanceModuleRoot "HostVmTransaction.ps1"
$hostUdpResultPath = Join-Path $performanceModuleRoot "HostUdpResult.ps1"
$guestTransactionPath = Join-Path $performanceModuleRoot "GuestTransaction.ps1"
$guestSupportPath = Join-Path $performanceModuleRoot "GuestSupport.ps1"
$processOwnerSourcePath = Join-Path $performanceModuleRoot "PerformanceProcessOwner.cs"
foreach ($performanceSource in @($hostContractPath, $hostUdpEvidencePath, $runtimeStagingPath, $hostVmTransactionPath, $hostUdpResultPath, $guestTransactionPath, $guestSupportPath, $processOwnerSourcePath)) {
    if (-not (Test-Path -LiteralPath $performanceSource -PathType Leaf)) {
        throw "performance module source is missing: $performanceSource"
    }
}
. $hostContractPath
. $hostUdpEvidencePath
. $runtimeStagingPath
$git = @(Get-Command git -CommandType Application -ErrorAction Stop)[0].Source
$python = @(Get-Command python -CommandType Application -ErrorAction Stop)[0].Source
foreach ($required in @(
    $policyPath, $controlEntryPath, $collectorPath, $guestNetworkPathProbePath,
    $hostNetworkPathHelperPath, $topologyRuntimePath, $networkModelControllerPath,
    $networkModelBundleManifestPath
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required performance controller file is missing: $required"
    }
}
$performanceControllerFileMap = @(
    [pscustomobject][ordered]@{
        source_path = $collectorPath
        relative_path = "collect_windows_tun_performance_trial.ps1"
    }
    [pscustomobject][ordered]@{
        source_path = $udpBoundaryCollectorPath
        relative_path = "collect_windows_tun_udp_boundary_diagnostic.ps1"
    }
    [pscustomobject][ordered]@{
        source_path = $performanceSourceBundlePath
        relative_path = "performance-source-bundle.json"
    }
) + @(Get-Ferrum2PerformanceGuestFileMap -ModuleRoot $performanceModuleRoot) + `
    @(Get-Ferrum2GuestControllerModuleFileMap -RepositoryRoot $repositoryRoot)
$performanceControllerBundleManifest = New-Ferrum2ControllerBundleManifest `
    -FileMap $performanceControllerFileMap `
    -EntryPoint "collect_windows_tun_performance_trial.ps1"
if (-not (Test-Path -LiteralPath $udpBoundaryCollectorPath -PathType Leaf)) {
    throw "required UDP boundary collector file is missing: $udpBoundaryCollectorPath"
}
$udpBoundaryCollectorSourceSha256 = (Get-FileHash `
    -LiteralPath $udpBoundaryCollectorPath -Algorithm SHA256).Hash.ToLowerInvariant()
$collectorSourceSha256 = (Get-FileHash -LiteralPath $collectorPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
. $topologyRuntimePath -LibraryOnly
$topologyRuntimeSha256 = (Get-FileHash -LiteralPath $topologyRuntimePath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$guestNetworkPathProbeSourceSha256 = (Get-FileHash `
    -LiteralPath $guestNetworkPathProbePath -Algorithm SHA256).Hash.ToLowerInvariant()
$topologyPlanDocument = Read-Ferrum2SupportTopologyPlanDocument
$approvedVmName = [string]$topologyPlanDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyPlanDocument.Value.vm.id
$approvedCheckpointName = [string]$topologyPlanDocument.Value.
    qualification_checkpoint.name
$approvedVmSwitchName = [string]$topologyPlanDocument.Value.support.switch_name
$SupportIpv4 = [string]$topologyPlanDocument.Value.support.host_ipv4
$supportGuestIpv4 = [string]$topologyPlanDocument.Value.support.guest_ipv4
$supportGuestInterfaceAlias = [string]$topologyPlanDocument.Value.support.guest_interface_alias
$supportNetwork = [string]$topologyPlanDocument.Value.support.network
$supportPrefixLength = [int]$topologyPlanDocument.Value.support.prefix_length
$supportVmMacAddress = ConvertTo-Ferrum2CanonicalMacAddress `
    -Value ([string]$topologyPlanDocument.Value.support.vm_mac_address) `
    -Label "planned support VM adapter"
$supportGuestInterfaceGuid = [Guid]::Empty
$supportGuestMtuBytes = 0
if (-not $PlanOnly) {
    $topologyManifestDocument = Read-Ferrum2SupportTopologyManifest `
        -Path $TopologyManifestPath -ExpectedSha256 $TopologyManifestSha256 `
        -RepositoryRoot $repositoryRoot
    $approvedCheckpointId = [Guid][string]$topologyManifestDocument.Value.
        qualification_checkpoint.id
    $supportGuestInterfaceGuid = [Guid][string]$topologyManifestDocument.Value.support.guest.
        support_interface_guid
    $supportGuestMtuBytes = [int]$topologyManifestDocument.Value.support.guest.mtu_bytes
    $hostHyperVIdentity = New-Ferrum2HostVmIdentity `
        -TopologyDocument $topologyManifestDocument
}
. $hostNetworkPathHelperPath
$hostNetworkPathHelperSha256 = (Get-FileHash -LiteralPath $hostNetworkPathHelperPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$head = [string](& $git -C $repositoryRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[0-9a-f]{40}$') {
    throw "repository HEAD identity is invalid"
}
if ([string]::IsNullOrWhiteSpace($CandidateSha)) { $CandidateSha = $head }
[void](Resolve-Commit -Git $git -Sha $CandidateSha -Label "candidate")
[void](Resolve-Commit -Git $git -Sha $ParentSha -Label "parent")
$parentTree = Get-TreeSha -Git $git -Sha $ParentSha
$candidateTree = Get-TreeSha -Git $git -Sha $CandidateSha
if ($RunKind -ceq "calibration-aa" -and $ParentSha -cne $CandidateSha) {
    throw "calibration-aa requires identical parent and candidate SHAs"
}
if ($instrumentedDiagnosticMode -and $ParentSha -cne $CandidateSha) {
    throw "UdpFlowBoundary requires identical parent and candidate SHAs"
}
if ($RunKind -ceq "comparison") {
    if ($ParentSha -ceq $CandidateSha) { throw "comparison requires distinct commits" }
    Invoke-NativeChecked -Executable $python -Label "parent/candidate ancestry validation" -Arguments @(
        "-B", "-m", $controlModule, "validate-git", "--repository", $repositoryRoot,
        "--parent-sha", $ParentSha, "--candidate-sha", $CandidateSha
    )
}

if ($PlanOnly) {
    $planRoot = Join-Path ([IO.Path]::GetTempPath()) ("ferrum2-tun-plan-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($planRoot) | Out-Null
    try {
        $planPath = Join-Path $planRoot "plan.json"
        $plan = New-CanonicalPlan -Python $python -RunKindValue $RunKind -Output $planPath
        $networkModelPlanPath = Join-Path $planRoot "network-model-plan.json"
        [void](New-NetworkModelPlan -Python $python -Output $networkModelPlanPath `
            -ExpectedSha256 ([string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256))
        [pscustomobject]@{
            schema = "ferrum2.windows-tun.hyperv-performance-plan.v4"
            run_kind = $RunKind
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            parent_tree = $parentTree
            candidate_tree = $candidateTree
            trials = @($plan.trials).Count
            recipe_sha256 = [string]$plan.recipe_sha256
            controller_bundle_sha256 = [string]$performanceControllerBundleManifest.
                controller_bundle_sha256
            network_model_controller_sha256 = [string]$plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256
            network_model_plan_sha256 = [string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $null
            topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
            topology_manifest_required_at_run = $true
            host_actions = @(
                "validate manifest-bound isolated support binding", "archive exact commits",
                "build profiling binaries", "stage files",
                "validate direct Internal-switch return path", "reduce evidence"
            )
            guest_actions = @(
                "reject gateway and DNS support collisions", "probe support",
                "validate manifest-bound /30 underlay", "run 108 collector trials",
                "collect 10 raw route-once and 10 raw lifecycle sidecars",
                "clean each TUN session"
            )
            host_network_mutations = 0
        } | ConvertTo-Json -Depth 6
    } finally {
        if ((Test-Path -LiteralPath $planRoot -PathType Container) -and
            $planRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
            [IO.Directory]::Delete($planRoot, $true)
        }
    }
    exit 0
}

if ($CandidateSha -cne $head) { throw "run mode requires candidate SHA to equal repository HEAD" }
& $git -C $repositoryRoot diff --quiet --exit-code
if ($LASTEXITCODE -ne 0) { throw "run mode requires no unstaged tracked changes" }
& $git -C $repositoryRoot diff --cached --quiet --exit-code
if ($LASTEXITCODE -ne 0) { throw "run mode requires no staged changes" }
$supportHostBaseline = Get-HostSupportContext `
    -TopologyDocument $topologyManifestDocument `
    -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner `
    -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
$vmNetworkBaseline = Get-ApprovedVmNetworkContext `
    -TopologyDocument $topologyManifestDocument `
    -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes

if ([string]::IsNullOrWhiteSpace($PowerShellZip)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default portable PowerShell ZIP"
    }
    $PowerShellZip = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\PowerShell-$expectedPowerShellVersion-win-x64.zip"
}
$resolvedPowerShellZip = Resolve-Ferrum2HostInput `
    -RepositoryRoot $repositoryRoot -Kind ExternalFile `
    -Path $PowerShellZip `
    -Label "portable PowerShell ZIP" `
    -MaximumBytes 536870912
if ((Get-FileHash -LiteralPath $resolvedPowerShellZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $expectedPowerShellZipSha256) {
    throw "portable PowerShell ZIP hash mismatch"
}
$resolvedWintunZip = Resolve-Ferrum2HostInput `
    -RepositoryRoot $repositoryRoot -Kind ExternalFile `
    -Path $WintunZip -Label "Wintun ZIP"
if ((Get-FileHash -LiteralPath $resolvedWintunZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $expectedWintunZipSha256) {
    throw "Wintun ZIP hash mismatch"
}
$resolvedSupportDiagnosticLedger = $null
$supportDiagnosticBaseline = $null
if ($instrumentedDiagnosticMode) {
    $resolvedSupportDiagnosticLedger = Resolve-Ferrum2HostInput `
        -RepositoryRoot $repositoryRoot -Kind ExternalFile `
        -Path $SupportDiagnosticLedger -Label "support diagnostic ledger" `
        -MaximumBytes 268451840
    $supportDiagnosticBaseline = Get-UdpDiagnosticLedgerSummary `
        -Path $resolvedSupportDiagnosticLedger `
        -ExpectedSchema "ferrum2.windows-tun.udp-support-ledger.v2" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    $expectedSupportHeaderFields = @(
        "closure", "listen_ip", "max_events", "pid", "record_type",
        "run_nonce", "schema", "scope", "tcp_port", "timestamp_clock",
        "udp_ports"
    )
    $actualSupportHeaderFields = @(
        $supportDiagnosticBaseline.Header.PSObject.Properties.Name |
            Sort-Object
    )
    $supportHeaderPorts = @($supportDiagnosticBaseline.Header.udp_ports)
    $supportHeaderPortsMatch = $supportHeaderPorts.Count -eq 4
    if ($supportHeaderPortsMatch) {
        for ($portOffset = 0; $portOffset -lt 4; $portOffset++) {
            if ([int]$supportHeaderPorts[$portOffset] -ne
                ($SupportUdpPort + $portOffset)) {
                $supportHeaderPortsMatch = $false
                break
            }
        }
    }
    if (($actualSupportHeaderFields -join "`n") -cne
            ($expectedSupportHeaderFields -join "`n") -or
        [int]$supportDiagnosticBaseline.Header.pid -ne $SupportPid -or
        [string]$supportDiagnosticBaseline.Header.listen_ip -cne $SupportIpv4 -or
        [int]$supportDiagnosticBaseline.Header.tcp_port -ne $SupportTcpPort -or
        [string]$supportDiagnosticBaseline.Header.scope -cne "bootstrap" -or
        [string]$supportDiagnosticBaseline.Header.closure -cne
            "host_four_port_barrier_after_vm_off" -or
        -not $supportHeaderPortsMatch) {
        throw "support diagnostic ledger header does not match the pinned support process"
    }
    if ($supportDiagnosticBaseline.Closed -or
        $supportDiagnosticBaseline.DroppedEvents -ne 0 -or
        $supportDiagnosticBaseline.WriteFailures -ne 0 -or
        $supportDiagnosticBaseline.MatchingRunNonceEvents -ne 0) {
        throw "support diagnostic ledger baseline is stale, closed, or degraded"
    }
}
$hostEvidenceRoot = Resolve-Ferrum2HostInput `
    -RepositoryRoot $repositoryRoot -Kind ExternalDirectory `
    -Path $EvidenceDirectory -Label "evidence directory"
$credential = Resolve-Ferrum2HostInput `
    -RepositoryRoot $repositoryRoot -Kind GuestCredential `
    -Path $CredentialPath -Label "guest credential" -MaximumBytes 1048576
$cargo = @(Get-Command cargo -CommandType Application -ErrorAction Stop)[0].Source
$rustup = @(Get-Command rustup -CommandType Application -ErrorAction Stop)[0].Source
$tar = @(Get-Command tar -CommandType Application -ErrorAction Stop)[0].Source
if (-not [string]::IsNullOrEmpty($env:RUSTFLAGS) -or
    -not [string]::IsNullOrEmpty($env:CARGO_ENCODED_RUSTFLAGS)) {
    throw "run mode requires empty host Rust flag environment variables"
}
$hostRustc = [string](& $rustup which --toolchain 1.97.1 rustc 2>$null)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostRustc -PathType Leaf)) {
    throw "host Rust 1.97.1 compiler is unavailable"
}
$hostRustIdentity = @(& $hostRustc -vV 2>&1)
$hostRustIdentityText = $hostRustIdentity -join "`n"
if ($LASTEXITCODE -ne 0 -or
    $hostRustIdentityText -cnotmatch '^rustc 1\.97\.1 \(' -or
    $hostRustIdentityText -cnotmatch '(?m)^host: x86_64-pc-windows-msvc$') {
    throw "host Rust toolchain must be Rust 1.97.1 x86_64-pc-windows-msvc"
}
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-tun-performance-" + [Guid]::NewGuid().ToString("N")
)
$artifactRoot = Join-Path $temporaryRoot "input\artifacts"
$runtimeRoot = Join-Path $temporaryRoot "input\runtime"
$hostPlanPath = Join-Path $hostEvidenceRoot "plan.json"
$hostTopologyManifestPath = Join-Path $hostEvidenceRoot "topology-manifest.json"
$hostNetworkModelPlanPath = Join-Path $hostEvidenceRoot "network-model-plan.json"
$hostNetworkPathPath = Join-Path $hostEvidenceRoot "host-network-path.json"
$hostSchedulePath = Join-Path $hostEvidenceRoot "trial-schedule.tsv"
$hostSummaryPath = Join-Path $hostEvidenceRoot "summary.json"
$hostMarkdownPath = Join-Path $hostEvidenceRoot "summary.md"
$hostCalibrationPath = Join-Path $hostEvidenceRoot "aa-calibration.json"
$hostDiagnosticRoot = Join-Path $hostEvidenceRoot "udp-diagnostic"
$hostDiagnosticGuestRoot = Join-Path $hostDiagnosticRoot "guest"
$hostDiagnosticHostRoot = Join-Path $hostDiagnosticRoot "host"
$hostDiagnosticSupportRoot = Join-Path $hostDiagnosticRoot "support"
$hostDiagnosticPath = Join-Path $hostDiagnosticRoot "udp-diagnostic.json"
$hostDiagnosticFailurePath = Join-Path $hostDiagnosticRoot "failure-summary.json"
$guestToken = [Guid]::NewGuid().ToString("N")
$guestRoot = "C:\Windows\Temp\ferrum2-tun-performance-$guestToken"
$session = $null
$vmWindowStarted = $false
$guestEvidenceAvailable = $false
$runFailure = $null
$restoreFailure = $null
$hostCaptureState = $null
$hostCaptureResult = $null
$hostCaptureFailure = $null
$hostEndpointSnapshotFailures = [Collections.Generic.List[string]]::new()
$diagnosticSourcePlan = $null
. $hostVmTransactionPath
if ($null -ne $restoreFailure) {
    if ($null -ne $runFailure) {
        throw "performance run failed and final checkpoint restore failed: run=$($runFailure.Exception.Message); restore=$($restoreFailure.Exception.Message)"
    }
    throw $restoreFailure
}
if ($null -ne $runFailure) { throw $runFailure }
if (-not $guestEvidenceAvailable) { throw "guest evidence was not marked complete" }
$finalTopologyContext = Get-Ferrum2ApprovedHyperVTopologyContext `
    -Document $topologyManifestDocument -ReadinessTimeoutSeconds 10
if ([string]$finalTopologyContext.Vm.State -cne "Off") {
    throw "approved topology final VM state is not Off"
}
. $hostUdpResultPath
$rawEvidence = Join-Path $hostEvidenceRoot "raw-evidence"
$rawNetworkModelEvidence = Join-Path $rawEvidence "network-model"
$rawProcessLogs = Join-Path $rawEvidence "process-logs"
$rawTrialFiles = @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json" `
    -ErrorAction Stop)
$rawNetworkModelFiles = @(if (
    Test-Path -LiteralPath $rawNetworkModelEvidence -PathType Container
) {
    Get-ChildItem -LiteralPath $rawNetworkModelEvidence -File `
        -Filter "*.network-model.json" -ErrorAction Stop
})
$rawProcessLogFiles = @(Get-ChildItem -LiteralPath $rawProcessLogs -File -Filter "*.log" `
    -ErrorAction Stop)
if (-not (Test-Path -LiteralPath $hostNetworkPathPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $rawEvidence -PathType Container) -or
    $rawTrialFiles.Count -ne $expectedTrialCount -or
    ($expectedNetworkModelObservationCount -ne 0 -and
        -not (Test-Path -LiteralPath $rawNetworkModelEvidence -PathType Container)) -or
    $rawNetworkModelFiles.Count -ne $expectedNetworkModelObservationCount -or
    -not (Test-Path -LiteralPath $rawProcessLogs -PathType Container) -or
    $rawProcessLogFiles.Count -ne $expectedProcessLogCount) {
    throw "exported raw evidence is incomplete"
}
if ($diagnosticMode) {
    $diagnosticFileName = "{0:D3}-{1}-{2}-pair-{3}.json" -f @(
        [int]$diagnosticTrial.sequence,
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair
    )
    $diagnosticTrialPath = Join-Path $rawEvidence $diagnosticFileName
    $diagnosticTrialItem = Get-Item -LiteralPath $diagnosticTrialPath `
        -ErrorAction SilentlyContinue
    if ($rawTrialFiles.Count -ne 1 -or
        $null -eq $diagnosticTrialItem -or $diagnosticTrialItem.PSIsContainer -or
        -not $rawTrialFiles[0].FullName.Equals(
            $diagnosticTrialItem.FullName,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "diagnostic trial evidence identity is invalid"
    }
    Push-Location $repositoryRoot
    try {
        $validatorRows = @(& $python -B -m $controlModule `
            "windows-tun-validate-trial" `
            "--plan" $hostPlanPath `
            "--trial" $diagnosticTrialPath `
            "--parent-sha" $ParentSha `
            "--candidate-sha" $CandidateSha `
            "--controller-bundle-sha256" `
                $performanceControllerBundleManifest.controller_bundle_sha256 `
            "--policy" $policyPath 2>&1)
        $validatorExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $validatorLines = @($validatorRows | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            [string]$_.Exception.Message
        } else {
            [string]$_
        }
    })
    $expectedValidatorLine = "{0}`t{1}`t{2}`t{3}" -f @(
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair,
        [int]$diagnosticTrial.order
    )
    if ($validatorExit -ne 0 -or $validatorLines.Count -ne 1 -or
        [string]$validatorLines[0] -cne $expectedValidatorLine) {
        $validatorDetail = ($validatorLines -join " | ")
        if ($validatorDetail.Length -gt 2048) {
            $validatorDetail = $validatorDetail.Substring(0, 2048)
        }
        throw "diagnostic trial validation failed: exit=$validatorExit detail=$validatorDetail"
    }
    $diagnosticFinalVmState = [string](
        Get-Ferrum2HostVmContext -Identity $hostHyperVIdentity
    ).Vm.State
    if ($diagnosticFinalVmState -cne "Off") {
        throw "approved VM final diagnostic state is not Off"
    }
    [pscustomobject]@{
        schema = "ferrum2.windows-tun.hyperv-performance-diagnostic-result.v2"
        status = "PASS"
        qualification = $false
        run_kind = $RunKind
        diagnostic_trial_sequence = [int]$diagnosticTrial.sequence
        scenario = [string]$diagnosticTrial.scenario
        member = [string]$diagnosticTrial.member
        pair = [int]$diagnosticTrial.pair
        order = [int]$diagnosticTrial.order
        validator_status = "PASS"
        reducer_invoked = $false
        evidence_directory = $hostEvidenceRoot
        controller_bundle_sha256 = [string]$performanceControllerBundleManifest.
            controller_bundle_sha256
        raw_trials = $rawTrialFiles.Count
        raw_network_model_observations = $rawNetworkModelFiles.Count
        process_logs = $rawProcessLogFiles.Count
        host_network_path = $hostNetworkPathPath
        host_network_path_sha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        topology_manifest = $hostTopologyManifestPath
        topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
        topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
        support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        final_vm_state = $diagnosticFinalVmState
        checkpoint_restored = $true
        host_tun_bypassed = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Depth 4
    exit 0
}
$summaryArguments = @(
    "-B", "-m", $controlModule, "windows-tun-summarize",
    "--plan", $hostPlanPath,
    "--evidence-root", $rawEvidence,
    "--parent-sha", $ParentSha,
    "--candidate-sha", $CandidateSha,
    "--controller-bundle-sha256",
        $performanceControllerBundleManifest.controller_bundle_sha256,
    "--policy", $policyPath,
    "--output", $hostSummaryPath,
    "--markdown", $hostMarkdownPath
)
if ($RunKind -ceq "calibration-aa") {
    $summaryArguments += @("--calibration-output", $hostCalibrationPath)
}
Push-Location $repositoryRoot
try {
    & $python @summaryArguments
    $summaryExit = $LASTEXITCODE
} finally {
    Pop-Location
}
if (-not (Test-Path -LiteralPath $hostSummaryPath -PathType Leaf)) {
    throw "host reducer did not write a summary"
}
$summary = Get-Content -LiteralPath $hostSummaryPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30
if ($summary.schema_version -ne 4 -or
    [string]$summary.controller_bundle_sha256 -cne
        [string]$performanceControllerBundleManifest.controller_bundle_sha256) {
    throw "host reducer summary controller bundle identity is invalid"
}
[pscustomobject]@{
    schema = "ferrum2.windows-tun.hyperv-performance-result.v4"
    status = [string]$summary.status
    reducer_exit_code = $summaryExit
    evidence_directory = $hostEvidenceRoot
    controller_bundle_sha256 = [string]$performanceControllerBundleManifest.
        controller_bundle_sha256
    raw_trials = $rawTrialFiles.Count
    raw_network_model_observations = $rawNetworkModelFiles.Count
    process_logs = $rawProcessLogFiles.Count
    host_network_path = $hostNetworkPathPath
    host_network_path_sha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    topology_manifest = $hostTopologyManifestPath
    topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
    topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
    support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
    vm_name = $approvedVmName
    vm_id = $approvedVmId.ToString("D")
    checkpoint_name = $approvedCheckpointName
    checkpoint_id = $approvedCheckpointId.ToString("D")
    final_vm_state = [string](
        Get-Ferrum2HostVmContext -Identity $hostHyperVIdentity
    ).Vm.State
    checkpoint_restored = $true
    host_tun_bypassed = $true
    host_network_mutations = 0
} | ConvertTo-Json -Depth 4
exit $summaryExit
