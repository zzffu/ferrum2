param([Parameter(Mandatory)] [Collections.IDictionary]$Context)
$expectedFields = @(
    'entrypoint_path', 'repository_root', 'internal_worker', 'internal_worker_token',
    'probe_only', 'profile', 'run_token', 'identity_ledger', 'topology_manifest_path',
    'topology_manifest_sha256', 'support_tcp_port', 'support_udp_port', 'support_pid',
    'support_owner', 'wintun_zip', 'powershell_zip', 'evidence_directory',
    'credential_path', 'readiness_timeout_seconds', 'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'main host controller context'
$entryPointPath = [string]$Context.entrypoint_path
$repositoryRoot = [string]$Context.repository_root
$InternalWorker = [bool]$Context.internal_worker
$InternalWorkerToken = [string]$Context.internal_worker_token
$ProbeOnly = [bool]$Context.probe_only
$Profile = [string]$Context.profile
$RunToken = [string]$Context.run_token
$IdentityLedger = [string]$Context.identity_ledger
$TopologyManifestPath = [string]$Context.topology_manifest_path
$TopologyManifestSha256 = [string]$Context.topology_manifest_sha256
$SupportTcpPort = [int]$Context.support_tcp_port
$SupportUdpPort = [int]$Context.support_udp_port
$SupportPid = [int]$Context.support_pid
$SupportOwner = [string]$Context.support_owner
$WintunZip = [string]$Context.wintun_zip
$PowerShellZip = [string]$Context.powershell_zip
$EvidenceDirectory = [string]$Context.evidence_directory
$CredentialPath = [string]$Context.credential_path
$ReadinessTimeoutSeconds = [int]$Context.readiness_timeout_seconds
$ShutdownTimeoutSeconds = [int]$Context.shutdown_timeout_seconds
$expectedWintunZipSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$expectedWintunDllSha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
$expectedPowerShellVersion = '7.4.19'
$expectedPowerShellZipSha256 = 'cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9'
$hostRuntime = Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot
$topologyRuntimeSha256 = [string]$hostRuntime.topology_runtime_sha256
$hostNetworkPathHelperSha256 = [string]$hostRuntime.host_network_path_helper_sha256
$guestNetworkPathProbeSha256 = [string]$hostRuntime.guest_network_path_probe_sha256
$guestNetworkPathProbePath = [string]$hostRuntime.guest_network_path_probe
if ($LibraryOnly) { return }

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the Hyper-V host orchestrator requires 64-bit Windows AMD64"
}
if ($InternalWorker) {
    if ([string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
        throw "bounded Hyper-V worker token is required"
    }
    Assert-BoundedHyperVInternalWorker -Token $InternalWorkerToken
} elseif (-not [string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
    throw "bounded Hyper-V worker token is not valid outside the internal worker"
}
# Resolve both exact identities and the DPAPI credential before any VM lifecycle operation.
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -ManifestPath $TopologyManifestPath -ExpectedSha256 $TopologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportAddress = [string]$topologyDocument.Value.support.switch.host_ipv4
$supportHostBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner
$initialContext = Get-ApprovedVmContext
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

# Keep the user-facing process outside the VM-active execution path. The hidden worker may use
# synchronous PowerShell Direct, but the supervisor has already captured exact-GUID cleanup authority
# and can terminate the entire worker tree before performing bounded Stop -> Restore -> Stop cleanup.
if (-not $InternalWorker) {
    $supervisorInitialState = [string]$initialContext.Vm.State
    if ($ProbeOnly) {
        if ($supervisorInitialState -notin @("Off", "Running")) {
            throw "ProbeOnly requires the approved VM to be Off or Running"
        }
    } elseif ($supervisorInitialState -cne "Off") {
        throw "approved VM must be Off at the full qualification supervisor baseline"
    }
    $supervisorCleanupAuthority = if ($supervisorInitialState -ceq "Off") {
        New-ApprovedVmCleanupAuthority -Context $initialContext
    } else {
        $null
    }
    $workerTimeoutSeconds = if ($ProbeOnly) {
        1800
    } elseif ($Profile -clike "*-1000") {
        10800
    } else {
        7200
    }
    $supervisorFailureManifestPath = $null
    if (-not $ProbeOnly) {
        $supervisorEvidenceDirectory = $EvidenceDirectory
        if ([string]::IsNullOrWhiteSpace($supervisorEvidenceDirectory)) {
            if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
                throw "LOCALAPPDATA is required for the default evidence directory"
            }
            $supervisorEvidenceDirectory = Join-Path $env:LOCALAPPDATA `
                "Ferrum2\windows-tun-evidence\$RunToken"
        }
        $supervisorEvidenceDirectory = Resolve-ExternalDirectoryTarget `
            -Path $supervisorEvidenceDirectory `
            -Label "supervised evidence directory"
        $supervisorFailureManifestPath = Join-Path `
            $supervisorEvidenceDirectory "host-orchestration.json"
    }
    Invoke-BoundedHyperVWorkerSupervisor `
        -ScriptPath $entryPointPath `
        -BoundParameters $PSBoundParameters `
        -ForwardedParameterNames @(
            "ProbeOnly", "Profile", "RunToken", "IdentityLedger",
            "TopologyManifestPath", "TopologyManifestSha256",
            "SupportTcpPort", "SupportUdpPort", "SupportPid", "SupportOwner",
            "WintunZip", "PowerShellZip", "EvidenceDirectory", "CredentialPath",
            "ReadinessTimeoutSeconds", "ShutdownTimeoutSeconds"
        ) `
        -WorkerTimeoutSeconds $workerTimeoutSeconds `
        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
        -ExpectedVmId $approvedVmId `
        -ExpectedVmName $approvedVmName `
        -ExpectedFinalState $supervisorInitialState `
        -CleanupAuthority $supervisorCleanupAuthority `
        -CleanupMode $(if ($ProbeOnly) { "StopOnly" } else { "RestoreCheckpoint" }) `
        -WorkerContract $(if ($ProbeOnly) { "Probe" } else { "Qualification" }) `
        -FailureManifestPath $supervisorFailureManifestPath `
        -Label "Windows TUN HyperV worker"
    return
}

if ($ProbeOnly) {
    $initialState = [string]$initialContext.Vm.State
    if ($initialState -notin @("Off", "Running")) {
        throw "ProbeOnly requires the approved VM to be Off or Running"
    }

    $probeStartedVm = $false
    $probeCleanupAuthority = $null
    $connection = $null
    $probeGuestTopology = $null
    $probeFailure = $null
    $probeFinalizationFailures = [Collections.Generic.List[string]]::new()
    try {
        if ($initialState -ceq "Off") {
            $probeCleanupAuthority = New-ApprovedVmCleanupAuthority `
                -Context (Get-ApprovedVmContext)
            $probeStartedVm = $true
            Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
        }
        $connection = Connect-ApprovedGuest `
            -Credential $guestCredential `
            -TimeoutSeconds $ReadinessTimeoutSeconds
        $probeGuestTopology = Get-ApprovedGuestSupportTopologyRuntimeState `
            -Session $connection.Session -TopologyDocument $topologyDocument
    } catch {
        $probeFailure = $_
    } finally {
        if ($probeStartedVm) {
            $probeVmConfirmedOff = $false
            try {
                Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $probeVmConfirmedOff = $true
            } catch {
                $probeFinalizationFailures.Add(
                    "probe emergency VM stop failed: $($_.Exception.Message)"
                )
            }
            if (-not $probeVmConfirmedOff) {
                $probeFinalizationFailures.Add("probe did not prove the temporarily started VM Off")
            }
        }
        if ($null -ne $connection) {
            Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
        }
    }

    $probeFinalVmState = $null
    $probeFinalTopologyState = $null
    $probeFinalSupport = $null
    try {
        $probeFinalVmState = [string](Get-ApprovedVmContext).Vm.State
        if ($probeFinalVmState -cne $initialState) {
            $probeFinalizationFailures.Add(
                "probe changed the approved VM state: expected=$initialState actual=$probeFinalVmState"
            )
            if ($probeStartedVm -and $null -ne $probeCleanupAuthority) {
                Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $probeFinalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                ).State
                if ($probeFinalVmState -cne "Off") {
                    throw "probe emergency final VM state is $probeFinalVmState"
                }
            }
        }
    } catch {
        $probeFinalizationFailures.Add(
            "probe final VM state readback failed: $($_.Exception.Message)"
        )
        if ($probeStartedVm -and $null -ne $probeCleanupAuthority) {
            try {
                $probeFinalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                ).State
                if ($probeFinalVmState -cne "Off") {
                    Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                        -TimeoutSeconds $ShutdownTimeoutSeconds
                    $probeFinalVmState = [string](
                        Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                    ).State
                }
                if ($probeFinalVmState -cne "Off") {
                    throw "probe emergency final VM state is $probeFinalVmState"
                }
            } catch {
                $probeFinalizationFailures.Add(
                    "probe emergency final VM state recovery failed: " +
                        $_.Exception.Message
                )
            }
        }
    }
    try {
        $probeFinalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
            -TopologyDocument $topologyDocument
        Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
            -Expected $initialTopologyState -Actual $probeFinalTopologyState
    } catch {
        $probeFinalizationFailures.Add(
            "probe final topology readback failed: $($_.Exception.Message)"
        )
    }
    try {
        $probeFinalSupport = Get-ApprovedHostSupportRuntimeState `
            -TopologyDocument $topologyDocument `
            -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
            -ProcessId $SupportPid -ProcessOwner $SupportOwner
        Assert-ApprovedHostSupportRuntimeStateUnchanged `
            -Expected $supportHostBaseline -Actual $probeFinalSupport
    } catch {
        $probeFinalizationFailures.Add(
            "probe final support-listener readback failed: $($_.Exception.Message)"
        )
    }
    try {
        Assert-ApprovedTopologyHelperSourcesUnchanged
    } catch {
        $probeFinalizationFailures.Add(
            "probe final helper-source readback failed: $($_.Exception.Message)"
        )
    }

    if ($null -ne $probeFailure -or $probeFinalizationFailures.Count -ne 0) {
        $messages = [Collections.Generic.List[string]]::new()
        if ($null -ne $probeFailure) {
            $messages.Add("probe failed: $($probeFailure.Exception.Message)")
        }
        foreach ($message in $probeFinalizationFailures) {
            $messages.Add($message)
        }
        throw [InvalidOperationException]::new(($messages -join "; "))
    }

    [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-probe.v2"
        status = "pass"
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        initial_vm_state = $initialState.ToLowerInvariant()
        final_vm_state = $probeFinalVmState
        guest_product = [string]$connection.Probe.Product
        guest_edition = [string]$connection.Probe.Edition
        guest_version = [string]$connection.Probe.Version
        guest_build = [string]$connection.Probe.Build
        guest_architecture = [string]$connection.Probe.Architecture
        powershell_version = [string]$connection.Probe.PowerShellVersion
        topology_manifest_sha256 = [string]$topologyDocument.Sha256
        topology_plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
        support_switch_id = [string]$topologyDocument.Value.support.switch.switch_id
        support_host_ipv4 = $supportAddress
        support_guest = $probeGuestTopology
        protected_host_tun = $probeFinalTopologyState.Runtime.ProtectedHostTun
        support_listener = $probeFinalSupport
        checkpoint_restored = $false
        files_staged = $false
        controller_invoked = $false
        host_tun_unchanged = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Compress
    return
}

$profileContract = Resolve-Ferrum2QualificationProfile -Profile $Profile
$requestedMode = [string]$profileContract.mode
$requestedRestartCycles = if ([long]$profileContract.restart_cycles -gt 0) {
    [long]$profileContract.restart_cycles
} else { $null }
$requestedNetworkResetCycles = if ([long]$profileContract.network_reset_cycles -gt 0) {
    [long]$profileContract.network_reset_cycles
} else { $null }

$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\qualify_windows_tun.ps1") `
    -Label "qualification controller" `
    -MaximumBytes 4194304
$controllerBundleFileMap = @(
    Get-Ferrum2MainControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controllerBundleManifest = New-Ferrum2ControllerBundleManifest `
    -FileMap $controllerBundleFileMap `
    -EntryPoint "qualify_windows_tun.ps1"
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -ControllerBundleSha256 $controllerBundleManifest.controller_bundle_sha256 `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportHostBaseline
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
$wintunHash = (Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($wintunHash -cne $expectedWintunZipSha256) {
    throw "Wintun archive hash mismatch"
}
if ([string]::IsNullOrWhiteSpace($PowerShellZip)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default portable PowerShell ZIP"
    }
    $PowerShellZip = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\PowerShell-$expectedPowerShellVersion-win-x64.zip"
}

if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default evidence directory"
    }
    $EvidenceDirectory = Join-Path $env:LOCALAPPDATA "Ferrum2\windows-tun-evidence\$RunToken"
}
$hostEvidencePath = Resolve-ExternalDirectoryTarget `
    -Path $EvidenceDirectory `
    -Label "evidence directory"

$baselineContext = Get-ApprovedVmContext
if ([string]$baselineContext.Vm.State -cne "Off") {
    throw "approved VM must be Off at the full qualification baseline"
}
$baselineTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
    -TopologyDocument $topologyDocument
Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
    -Expected $initialTopologyState -Actual $baselineTopologyState
$baselineSupportState = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner
Assert-ApprovedHostSupportRuntimeStateUnchanged `
    -Expected $supportHostBaseline -Actual $baselineSupportState

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("ferrum2-hyperv-" + [Guid]::NewGuid().ToString("N"))
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$hostArtifactRoot = Join-Path $temporaryRoot "artifacts"
$hostRuntimeLibraryRoot = Join-Path $temporaryRoot "vc-runtime"
$hostPowerShellArchive = Join-Path $temporaryRoot "portable-pwsh.zip"
$stagedInputManifestPath = Join-Path $temporaryRoot "staged-input.json"
$controllerBundleManifestPath = Join-Path $temporaryRoot "controller-bundle.json"
$hostTopologyManifestPath = Join-Path $hostEvidencePath "topology-manifest.json"
$hostNetworkPathPath = Join-Path $hostEvidencePath "host-network-path.json"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$cleanupAuthority = $null
$checkpointRestored = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$guestResult = $null
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null
$guestNetworkPath = $null
$guestNetworkPathPost = $null
$guestNetworkPathSha256 = $null
$hostNetworkPathSha256 = $null
$postGuestTopology = $null
$finalTopologyState = $null
$finalSupportState = $null

try {

. (Join-Path $PSScriptRoot 'Main.HostStage.ps1')

. (Join-Path $PSScriptRoot 'Main.HostGuestTransaction.ps1')

. (Join-Path $PSScriptRoot 'Main.HostReadback.ps1')

} catch {
    $runFailure = $_
} finally {
    if ($null -ne $connection -and -not [string]::IsNullOrWhiteSpace($guestExportPath) -and
        (Test-Path -LiteralPath $hostEvidencePath -PathType Container)) {
        try {
            Copy-GuestEvidence `
                -Session $connection.Session `
                -GuestExportPath $guestExportPath `
                -HostEvidencePath $hostEvidencePath
        } catch {
            $finalizationFailures.Add("evidence export failed: $($_.Exception.Message)")
        }
    }
    if ($restoreRequired) {
        $vmConfirmedOff = $false
        try {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $vmConfirmedOff = $true
        } catch {
            $finalizationFailures.Add(
                "mandatory emergency VM stop failed: $($_.Exception.Message)"
            )
        }
        if ($vmConfirmedOff) {
            $checkpointRestored = $false
            try {
                Restore-ApprovedCheckpointEmergency `
                    -Authority $cleanupAuthority `
                    -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds
                $checkpointRestored = $true
            } catch {
                $finalizationFailures.Add(
                    "mandatory emergency checkpoint restore failed: " +
                        $_.Exception.Message
                )
            }
        } else {
            $finalizationFailures.Add(
                "mandatory final checkpoint restore could not start because Off was not proven"
            )
        }
        try {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $vmConfirmedOff = $true
        } catch {
            $finalizationFailures.Add(
                "mandatory post-restore emergency VM stop failed: $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $connection) {
        Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $temporaryRoot) {
        try {
            $resolvedTemporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot -ErrorAction Stop).Path
            if (-not (Test-Ferrum2PathWithinRoot -Path $resolvedTemporaryRoot -Root $temporaryBase) -or
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cnotmatch '^ferrum2-hyperv-[0-9a-f]{32}$') {
                throw "temporary staging cleanup boundary is invalid"
            }
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label "temporary staging cleanup"
            $temporaryItems = @(Get-Item -LiteralPath $resolvedTemporaryRoot -Force) + @(
                Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Force -Recurse
            )
            if (@($temporaryItems | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -ne 0) {
                throw "temporary staging cleanup cannot traverse a reparse point"
            }
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction Stop
        } catch {
            $finalizationFailures.Add("temporary staging cleanup failed: $($_.Exception.Message)")
        }
    }
}

$finalVmState = $null
try {
    $finalVmState = [string](Get-ApprovedVmContext).Vm.State
    if ($finalVmState -cne "Off") {
        $finalizationFailures.Add("approved VM final state is not Off")
        if ($restoreRequired -and $null -ne $cleanupAuthority) {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $finalVmState = [string](
                Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
            ).State
            if ($finalVmState -cne "Off") {
                throw "approved emergency final VM state is $finalVmState"
            }
        }
    }
} catch {
    $finalizationFailures.Add("approved VM final state readback failed: $($_.Exception.Message)")
    if ($restoreRequired -and $null -ne $cleanupAuthority) {
        try {
            $finalVmState = [string](
                Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
            ).State
            if ($finalVmState -cne "Off") {
                Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $finalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
                ).State
            }
            if ($finalVmState -cne "Off") {
                throw "approved emergency final VM state is $finalVmState"
            }
        } catch {
            $finalizationFailures.Add(
                "approved emergency final VM state recovery failed: " +
                    $_.Exception.Message
            )
        }
    }
}
try {
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $topologyDocument
    Assert-ApprovedTopologyHelperSourcesUnchanged
    $finalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $finalTopologyState
} catch {
    $finalizationFailures.Add("approved topology final readback failed: $($_.Exception.Message)")
}
try {
    $finalSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $finalSupportState
} catch {
    $finalizationFailures.Add("support listener final readback failed: $($_.Exception.Message)")
}
try {
    Assert-Ferrum2HostFinalState `
        -FinalVmState $finalVmState `
        -CheckpointRestored ($checkpointRestored -and $finalVmState -ceq "Off") `
        -CleanupPassed ($finalizationFailures.Count -eq 0)
} catch {
    $finalizationFailures.Add("host final-state seam failed: $($_.Exception.Message)")
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) { "pass" } else { "fail" }
try {
        $hostEvidenceItem = Get-Item -LiteralPath $hostEvidencePath `
            -Force -ErrorAction Stop
        if (-not $hostEvidenceItem.PSIsContainer -or
            ($hostEvidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "mandatory host evidence root is invalid"
        }
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-host-run.v5"
            status = $status
            profile = $Profile
            mode = $requestedMode
            restart_cycles = $requestedRestartCycles
            network_reset_cycles = $requestedNetworkResetCycles
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            controller_bundle_sha256 = [string]$controllerBundleManifest.controller_bundle_sha256
            staged_input_sha256 = $stagedInputSha256
            topology_manifest_sha256 = [string]$topologyDocument.Sha256
            topology_plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
            topology = $ledgerIdentity.Ledger.topology
            guest_network_path_sha256 = $guestNetworkPathSha256
            guest_network_path = $guestNetworkPath
            host_network_path_sha256 = $hostNetworkPathSha256
            support_listener = $ledgerIdentity.Ledger.support_listener
            protected_host_tun = if ($null -eq $finalTopologyState) {
                $null
            } else { $finalTopologyState.Runtime.ProtectedHostTun }
            topology_runtime_sha256 = $topologyRuntimeSha256
            host_network_path_helper_sha256 = $hostNetworkPathHelperSha256
            guest_network_path_probe_sha256 = $guestNetworkPathProbeSha256
            rust_version = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.RustVersion }
            fuzz_smoke_sha256 = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Sha256 }
            fuzz_smoke_bytes = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Bytes }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = if ($null -eq $guestResult) { $null } else { [string]$connection.Probe.Build }
            checkpoint_restored = $checkpointRestored -and $finalVmState -ceq "Off"
            support_listener_unchanged = $null -ne $finalSupportState
            host_tun_unchanged = $null -ne $finalTopologyState
            host_network_mutations = 0
            started_utc = $startedUtc
            finished_utc = [DateTime]::UtcNow.ToString("o")
            final_vm_state = $finalVmState
            evidence_files = @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath)
        }
        $hostManifestPath = Join-Path $hostEvidencePath "host-orchestration.json"
        $hostManifestPendingPath = Join-Path $hostEvidencePath `
            "host-orchestration.pending.json"
        $hostManifestFinalCreated = $false
        $hostManifestFinalValidated = $false
        try {
            if ((Test-Path -LiteralPath $hostManifestPath) -or
                (Test-Path -LiteralPath $hostManifestPendingPath)) {
                throw "host manifest publication paths must be absent before publication"
            }
            Write-Ferrum2JsonCreateNew -Path $hostManifestPendingPath -Value $manifest -Depth 8
            $expectedHostManifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                ($manifest | ConvertTo-Json -Depth 8) + "`n"
            )
            $actualHostManifestBytes = [IO.File]::ReadAllBytes($hostManifestPendingPath)
            if ([Convert]::ToBase64String($actualHostManifestBytes) -cne
                [Convert]::ToBase64String($expectedHostManifestBytes)) {
                throw "host manifest bytes differ from the expected closed document"
            }
            $hostManifestReadback = Get-Content -LiteralPath $hostManifestPendingPath `
                -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10 -ErrorAction Stop
        $hostManifestKeys = @(
            "schema", "status", "profile", "mode", "restart_cycles", "network_reset_cycles",
            "run_token", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
            "candidate_sha", "identity_sha256", "controller_bundle_sha256",
            "staged_input_sha256",
            "topology_manifest_sha256", "topology_plan_sha256", "topology",
            "guest_network_path_sha256", "guest_network_path", "host_network_path_sha256",
            "support_listener", "protected_host_tun", "topology_runtime_sha256",
            "host_network_path_helper_sha256", "guest_network_path_probe_sha256",
            "rust_version", "fuzz_smoke_sha256", "fuzz_smoke_bytes", "guest_execution",
            "guest_build", "checkpoint_restored", "support_listener_unchanged",
            "host_tun_unchanged", "host_network_mutations", "started_utc", "finished_utc",
            "final_vm_state", "evidence_files"
        )
        if ((@($hostManifestReadback.PSObject.Properties.Name) -join "|") -cne
                ($hostManifestKeys -join "|") -or
            $hostManifestReadback.schema -cne "ferrum2.windows-tun.hyperv-host-run.v5" -or
            $hostManifestReadback.identity_sha256 -cne $ledgerIdentity.Sha256 -or
            $hostManifestReadback.controller_bundle_sha256 -cne
                [string]$controllerBundleManifest.controller_bundle_sha256 -or
            $hostManifestReadback.topology_manifest_sha256 -cne
                [string]$topologyDocument.Sha256 -or
            $hostManifestReadback.topology_plan_sha256 -cne
                [string]$topologyDocument.PlanDocument.Sha256 -or
            ($hostManifestReadback.topology | ConvertTo-Json -Compress -Depth 5) -cne
                ($ledgerIdentity.Ledger.topology | ConvertTo-Json -Compress -Depth 5) -or
            ($hostManifestReadback.support_listener | ConvertTo-Json -Compress -Depth 5) -cne
                ($ledgerIdentity.Ledger.support_listener | ConvertTo-Json -Compress -Depth 5) -or
            $hostManifestReadback.topology_runtime_sha256 -cne $topologyRuntimeSha256 -or
            $hostManifestReadback.host_network_path_helper_sha256 -cne
                $hostNetworkPathHelperSha256 -or
            $hostManifestReadback.guest_network_path_probe_sha256 -cne
                $guestNetworkPathProbeSha256 -or
            [long]$hostManifestReadback.host_network_mutations -ne 0 -or
            ($status -ceq "pass" -and
                ($hostManifestReadback.guest_network_path_sha256 -cne
                    $guestNetworkPathSha256 -or
                $hostManifestReadback.host_network_path_sha256 -cne
                    $hostNetworkPathSha256 -or
                ($hostManifestReadback.guest_network_path |
                    ConvertTo-Json -Compress -Depth 5) -cne
                    ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5) -or
                ($hostManifestReadback.protected_host_tun |
                    ConvertTo-Json -Compress -Depth 5) -cne
                    ($finalTopologyState.Runtime.ProtectedHostTun |
                        ConvertTo-Json -Compress -Depth 5) -or
                [string]$hostManifestReadback.protected_host_tun.name -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_name -or
                [string]$hostManifestReadback.protected_host_tun.interface_guid -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_guid -or
                [long]$hostManifestReadback.protected_host_tun.interface_index -ne
                    [long]$ledgerIdentity.Ledger.topology.protected_host_tun_index -or
                [string]$hostManifestReadback.protected_host_tun.status -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_status -or
                $hostManifestReadback.checkpoint_restored -ne $true -or
                $hostManifestReadback.support_listener_unchanged -ne $true -or
                $hostManifestReadback.host_tun_unchanged -ne $true -or
                $hostManifestReadback.final_vm_state -cne "Off"))) {
            throw "host orchestration result closed binding is invalid"
        }
            $expectedEvidenceFilesJson = ConvertTo-Json `
                -InputObject @($manifest.evidence_files) -Compress -Depth 5
            $freshEvidenceFilesJson = ConvertTo-Json `
                -InputObject @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath) `
                -Compress -Depth 5
            if ($freshEvidenceFilesJson -cne $expectedEvidenceFilesJson) {
                throw "host evidence files changed before manifest publication"
            }
            [IO.File]::Move($hostManifestPendingPath, $hostManifestPath)
            $hostManifestFinalCreated = $true
            if (Test-Path -LiteralPath $hostManifestPendingPath) {
                throw "host manifest pending path survived atomic publication"
            }
            if ([Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($hostManifestPath)
                ) -cne [Convert]::ToBase64String($expectedHostManifestBytes)) {
                throw "host manifest changed during atomic publication"
            }
            $finalEvidenceFilesJson = ConvertTo-Json `
                -InputObject @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath) `
                -Compress -Depth 5
            if ($finalEvidenceFilesJson -cne $expectedEvidenceFilesJson) {
                throw "host evidence files changed during manifest publication"
            }
            $hostManifestFinalValidated = $true
        } finally {
            foreach ($ownedManifestPath in @(
                $hostManifestPendingPath,
                $(if ($hostManifestFinalCreated -and -not $hostManifestFinalValidated) {
                    $hostManifestPath
                })
            )) {
                if (-not [string]::IsNullOrWhiteSpace([string]$ownedManifestPath) -and
                    (Test-Path -LiteralPath $ownedManifestPath)) {
                    $ownedManifestItem = Get-Item -LiteralPath $ownedManifestPath `
                        -Force -ErrorAction Stop
                    if ($ownedManifestItem.PSIsContainer -or
                        ($ownedManifestItem.Attributes -band
                            [IO.FileAttributes]::ReparsePoint)) {
                        throw "owned host manifest cleanup boundary is invalid"
                    }
                    [IO.File]::Delete($ownedManifestItem.FullName)
                }
            }
        }
} catch {
    $finalizationFailures.Add("host evidence manifest failed: $($_.Exception.Message)")
    $status = "fail"
}

if ($null -ne $runFailure -or $finalizationFailures.Count -ne 0) {
    $messages = [Collections.Generic.List[string]]::new()
    if ($null -ne $runFailure) {
        $messages.Add("qualification failed: $($runFailure.Exception.Message)")
    }
    foreach ($message in $finalizationFailures) {
        $messages.Add($message)
    }
    throw [InvalidOperationException]::new(($messages -join "; "))
}

Write-Output "hyperv_windows_tun status=PASS profile=$Profile run_token=$RunToken candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
