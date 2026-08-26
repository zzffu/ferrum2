param([Parameter(Mandatory)] [Collections.IDictionary]$Context)
$expectedFields = @(
    'entrypoint_path', 'repository_root', 'internal_worker', 'internal_worker_token',
    'run_token', 'identity_ledger', 'topology_manifest_path', 'topology_manifest_sha256',
    'support_tcp_port', 'support_udp_port', 'support_pid', 'support_owner', 'wintun_zip',
    'powershell_zip', 'evidence_directory', 'credential_path',
    'readiness_timeout_seconds', 'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'hard host controller context'
$entryPointPath = [string]$Context.entrypoint_path
$repositoryRoot = [string]$Context.repository_root
$InternalWorker = [bool]$Context.internal_worker
$InternalWorkerToken = [string]$Context.internal_worker_token
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
$expectedPowerShellVersion = '7.4.19'
$expectedPowerShellZipSha256 = 'cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9'
$expectedArtifactFiles = @(
    'identity-ledger.json', 'controller.stdout.log', 'controller.stderr.log',
    'hard-kill-evidence.jsonl', 'hard-kill-result.json', 'cleanup.stdout.log',
    'cleanup.stderr.log', 'hard-kill-cleanup.json'
)
$topologyPropertyNames = @(
    'manifest_sha256', 'plan_sha256', 'support_switch_id', 'support_host_ipv4',
    'support_network', 'support_prefix_length', 'guest_interface_alias',
    'guest_interface_guid', 'guest_interface_index', 'guest_mac_address', 'guest_ipv4',
    'guest_mtu_bytes', 'protected_host_tun_name', 'protected_host_tun_guid',
    'protected_host_tun_index', 'protected_host_tun_status'
)
$supportListenerPropertyNames = @(
    'ipv4', 'tcp_port', 'udp_port', 'pid', 'owner', 'executable_sha256', 'creation_utc'
)
. (Join-Path $PSScriptRoot 'Hard.HostContract.ps1')
if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the hard-kill Hyper-V orchestrator requires 64-bit Windows AMD64"
}

$hostRuntime = Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot
$guestNetworkPathProbePath = [string]$hostRuntime.guest_network_path_probe
if ($InternalWorker) {
    if ([string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
        throw "bounded Hyper-V worker token is required"
    }
    Assert-BoundedHyperVInternalWorker -Token $InternalWorkerToken
} elseif (-not [string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
    throw "bounded Hyper-V worker token is not valid outside the internal worker"
}
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -ManifestPath $TopologyManifestPath `
    -ExpectedSha256 $TopologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$approvedVmName = [string]$topologyDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyDocument.Value.vm.id
$approvedCheckpointName = [string]$topologyDocument.Value.qualification_checkpoint.name
$approvedCheckpointId = [Guid][string]$topologyDocument.Value.qualification_checkpoint.id
$topologyBinding = New-TopologyBinding $topologyDocument
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address ([string]$topologyBinding.support_host_ipv4) `
    -TcpPort $SupportTcpPort `
    -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid `
    -ProcessOwner $SupportOwner
$supportListenerBinding = New-SupportListenerBinding $supportBaseline
$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot `
        "tests\platform\qualify_windows_tun_hard_kill.ps1") `
    -Label "hard-kill qualification controller" `
    -MaximumBytes 4194304
$controllerBundleFileMap = @(
    Get-Ferrum2HardKillControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controllerBundleManifest = New-Ferrum2ControllerBundleManifest `
    -FileMap $controllerBundleFileMap `
    -EntryPoint "qualify_windows_tun_hard_kill.ps1"
$guestWrapperPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\invoke_windows_tun_hard_kill_guest.ps1") `
    -Label "hard-kill guest wrapper" `
    -MaximumBytes 2097152
$guestNetworkPathProbePath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot `
        "tools\windows-tun\get_windows_tun_guest_network_path.ps1") `
    -Label "guest network-path probe" `
    -MaximumBytes 1048576
Assert-True (
    (Get-Ferrum2LowerSha256 $guestNetworkPathProbePath) -ceq
        [string]$topologyInitialization.GuestNetworkPathProbeSha256
) "guest network-path probe hash differs from the approved topology runtime"
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -ControllerBundleSha256 $controllerBundleManifest.controller_bundle_sha256 `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportBaseline
Assert-ExactObjectFields `
    -Expected $topologyBinding `
    -Actual $ledgerIdentity.Ledger.topology `
    -Fields $topologyPropertyNames `
    -Label "identity ledger topology"
Assert-ExactObjectFields `
    -Expected $supportListenerBinding `
    -Actual $ledgerIdentity.Ledger.support_listener `
    -Fields $supportListenerPropertyNames `
    -Label "identity ledger support listener"
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
Assert-True ((Get-Ferrum2LowerSha256 $wintunPath) -ceq $expectedWintunZipSha256) `
    "Wintun archive hash mismatch"
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
    $EvidenceDirectory = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\windows-tun-hard-kill-evidence\$RunToken"
}
$hostEvidencePath = Resolve-ExternalDirectoryTarget `
    -Path $EvidenceDirectory `
    -Label "hard-kill evidence directory"

# Resolve both exact VM/checkpoint identities and the DPAPI credential before any lifecycle action.
$baselineContext = Get-ApprovedVmContext
if ([string]$baselineContext.Vm.State -cne "Off") {
    throw "approved VM must be Off at the hard-kill qualification baseline"
}
$preflightTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
    -TopologyDocument $topologyDocument
Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
    -Expected $initialTopologyState `
    -Actual $preflightTopologyState
$preflightSupportState = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address ([string]$topologyBinding.support_host_ipv4) `
    -TcpPort $SupportTcpPort `
    -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid `
    -ProcessOwner $SupportOwner
Assert-ApprovedHostSupportRuntimeStateUnchanged `
    -Expected $supportBaseline `
    -Actual $preflightSupportState
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

# Supervise the complete VM-active phase from a separate process so a synchronous PowerShell Direct
# hang cannot prevent exact-GUID Stop -> Restore -> Stop cleanup.
if (-not $InternalWorker) {
    $supervisorCleanupAuthority = New-ApprovedVmCleanupAuthority -Context $baselineContext
    Invoke-BoundedHyperVWorkerSupervisor `
        -ScriptPath $entryPointPath `
        -BoundParameters $PSBoundParameters `
        -ForwardedParameterNames @(
            "RunToken", "IdentityLedger", "TopologyManifestPath",
            "TopologyManifestSha256", "SupportTcpPort", "SupportUdpPort",
            "SupportPid", "SupportOwner", "WintunZip", "PowerShellZip",
            "EvidenceDirectory", "CredentialPath", "ReadinessTimeoutSeconds",
            "ShutdownTimeoutSeconds"
        ) `
        -WorkerTimeoutSeconds 7200 `
        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
        -ExpectedVmId $approvedVmId `
        -ExpectedVmName $approvedVmName `
        -ExpectedFinalState "Off" `
        -CleanupAuthority $supervisorCleanupAuthority `
        -CleanupMode "RestoreCheckpoint" `
        -WorkerContract "HardKill" `
        -FailureManifestPath (Join-Path $hostEvidencePath "host-orchestration.json") `
        -Label "Windows TUN hard kill worker"
    return
}

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-hard-kill-hyperv-" + [Guid]::NewGuid().ToString("N")
)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$hostArtifactRoot = Join-Path $temporaryRoot "artifacts"
$hostRuntimeLibraryRoot = Join-Path $temporaryRoot "vc-runtime"
$hostPowerShellArchive = Join-Path $temporaryRoot "portable-pwsh.zip"
$stagedInputManifestPath = Join-Path $temporaryRoot "staged-input.json"
$controllerBundleManifestPath = Join-Path $temporaryRoot "controller-bundle.json"
$hostTopologyManifestPath = Join-Path $hostEvidencePath "topology-manifest.json"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$cleanupAuthority = $null
$checkpointRestored = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null
$wrapperEntry = $null
$guestResult = $null
$guestNetworkPathPreflight = $null
$guestNetworkPathPostflight = $null
$finalTopologyUnchanged = $false
$finalSupportUnchanged = $false

. (Join-Path $PSScriptRoot 'Hard.HostTransaction.ps1')

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
            Assert-True ($finalVmState -ceq "Off") `
                "approved emergency final VM state is not Off"
        }
    }
} catch {
    $finalizationFailures.Add("approved VM final-state readback failed: $($_.Exception.Message)")
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
            Assert-True ($finalVmState -ceq "Off") `
                "approved emergency final VM state is not Off"
        } catch {
            $finalizationFailures.Add(
                "approved emergency final-state recovery failed: " +
                    $_.Exception.Message
            )
        }
    }
}
try {
    $finalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState `
        -Actual $finalTopologyState
    $finalTopologyUnchanged = $true
} catch {
    $finalizationFailures.Add(
        "approved topology final readback failed: $($_.Exception.Message)"
    )
}
try {
    $finalSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $finalSupportState
    $finalSupportUnchanged = $true
} catch {
    $finalizationFailures.Add(
        "host support final readback failed: $($_.Exception.Message)"
    )
}
try {
    Assert-Ferrum2HostFinalState `
        -FinalVmState $finalVmState `
        -CheckpointRestored ([bool]$checkpointRestored) `
        -CleanupPassed ($finalizationFailures.Count -eq 0)
} catch {
    $finalizationFailures.Add("host final-state seam failed: $($_.Exception.Message)")
}
if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    try {
        $finalCandidate = Get-CandidateIdentity
        Assert-True ($finalCandidate.Sha -ceq $candidate.Sha) `
            "candidate commit changed during hard-kill qualification"
        Assert-HardKillExport `
            -Path (Join-Path $hostEvidencePath "guest\export") `
            -Ledger $ledgerIdentity.Ledger `
            -IdentitySha256 $ledgerIdentity.Sha256 `
            -CandidateSha $candidate.Sha
    } catch {
        $runFailure = $_
    }
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    "pass"
} else {
    "fail"
}
try {
        $hostEvidenceItem = Get-Item -LiteralPath $hostEvidencePath `
            -Force -ErrorAction Stop
        Assert-True (
            $hostEvidenceItem.PSIsContainer -and
            ($hostEvidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        ) "mandatory hard-kill evidence root is invalid"
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v3"
            status = $status
            mode = "hard-kill"
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            topology = $topologyBinding
            support_listener = $supportListenerBinding
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            controller_sha256 = [string]$ledgerIdentity.Ledger.probe_sha256
            controller_bundle_sha256 = [string]$ledgerIdentity.Ledger.controller_bundle_sha256
            guest_wrapper_sha256 = if ($null -eq $wrapperEntry) {
                $null
            } else {
                [string]$wrapperEntry.sha256
            }
            topology_runtime_sha256 = [string]$topologyInitialization.TopologyRuntimeSha256
            host_network_path_helper_sha256 =
                [string]$topologyInitialization.HostNetworkPathHelperSha256
            guest_network_path_probe_sha256 =
                [string]$topologyInitialization.GuestNetworkPathProbeSha256
            staged_input_sha256 = $stagedInputSha256
            rust_version = if ($null -eq $candidateArtifacts) {
                $null
            } else {
                $candidateArtifacts.RustVersion
            }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = [string]$ledgerIdentity.Ledger.guest_build
            checkpoint_restored = [bool]$checkpointRestored
            host_tun_unchanged = [bool]$finalTopologyUnchanged
            host_support_unchanged = [bool]$finalSupportUnchanged
            host_network_mutations = [long]0
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
            Assert-True (-not (Test-Path -LiteralPath $hostManifestPath) -and
                -not (Test-Path -LiteralPath $hostManifestPendingPath)) `
                "hard-kill host manifest publication paths must be absent"
            Write-Ferrum2JsonCreateNew -Path $hostManifestPendingPath -Value $manifest -Depth 8
            Assert-HardKillHostManifest `
                -Path $hostManifestPendingPath -Expected $manifest `
                -EvidenceRoot $hostEvidencePath
            $expectedPublishedManifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                ($manifest | ConvertTo-Json -Depth 8) + "`n"
            )
            [IO.File]::Move($hostManifestPendingPath, $hostManifestPath)
            $hostManifestFinalCreated = $true
            Assert-True (-not (Test-Path -LiteralPath $hostManifestPendingPath)) `
                "hard-kill host manifest pending path survived publication"
            Assert-True (
                [Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($hostManifestPath)
                ) -ceq [Convert]::ToBase64String($expectedPublishedManifestBytes)
            ) "hard-kill host manifest changed during atomic publication"
            Assert-HardKillHostManifest `
                -Path $hostManifestPath -Expected $manifest `
                -EvidenceRoot $hostEvidencePath
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
                    Assert-True (
                        -not $ownedManifestItem.PSIsContainer -and
                        ($ownedManifestItem.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -eq 0
                    ) "owned hard-kill manifest cleanup boundary is invalid"
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
        $messages.Add("hard-kill qualification failed: $($runFailure.Exception.Message)")
    }
    foreach ($message in $finalizationFailures) { $messages.Add($message) }
    throw [InvalidOperationException]::new(($messages -join "; "))
}

Write-Output (
    "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill run_token=$RunToken " +
    "candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
)
