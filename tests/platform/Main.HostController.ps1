param([Parameter(Mandatory)] [Collections.IDictionary]$Context)
$expectedFields = @(
    'repository_root', 'internal_worker_token', 'candidate_artifact_manifest',
    'profile', 'run_token', 'identity_ledger', 'topology_plan_path', 'topology_manifest_path',
    'topology_manifest_sha256', 'support_tcp_port', 'support_udp_port',
    'support_pid', 'support_owner', 'wintun_zip', 'powershell_zip',
    'evidence_directory', 'credential_path', 'readiness_timeout_seconds',
    'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'main host worker context'
$repositoryRoot = [string]$Context.repository_root
$internalWorkerToken = [string]$Context.internal_worker_token
$candidateArtifactManifest = [string]$Context.candidate_artifact_manifest
$qualificationProfile = [string]$Context.profile
$RunToken = [string]$Context.run_token
$IdentityLedger = [string]$Context.identity_ledger
$TopologyPlanPath = [string]$Context.topology_plan_path
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
Assert-BoundedHyperVInternalWorker -Token $internalWorkerToken
if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'the Hyper-V qualification worker requires 64-bit Windows AMD64'
}
$topologyRuntimeSha256 = [string]$hostRuntime.topology_runtime_sha256
$hostNetworkPathHelperSha256 = [string]$hostRuntime.host_network_path_helper_sha256
$guestNetworkPathProbeSha256 = [string]$hostRuntime.guest_network_path_probe_sha256
$guestNetworkPathProbePath = [string]$hostRuntime.guest_network_path_probe
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -TopologyPlanPath $TopologyPlanPath `
    -ManifestPath $TopologyManifestPath -ExpectedSha256 $TopologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$approvedVmName = [string]$topologyDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyDocument.Value.vm.id
$approvedCheckpointName = [string]$topologyDocument.Value.lab_checkpoint.name
$approvedCheckpointId = [Guid][string]$topologyDocument.Value.lab_checkpoint.id
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportAddress = [string]$topologyDocument.Value.support.switch.host_ipv4
$supportHostBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner
$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot 'tests/platform/qualify_windows_tun.ps1') `
    -Label 'qualification controller' -MaximumBytes 4194304
$controllerBundleFileMap = @(
    Get-Ferrum2MainControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controllerBundleManifest = New-Ferrum2ControllerBundleManifest `
    -FileMap $controllerBundleFileMap -EntryPoint 'qualify_windows_tun.ps1'
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -ControllerBundleSha256 $controllerBundleManifest.controller_bundle_sha256 `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportHostBaseline
$profileContract = Resolve-Ferrum2QualificationProfile -Profile $qualificationProfile
$requestedCycleLimit = if ([long]$profileContract.cycle_limit -gt 0) {
    [long]$profileContract.cycle_limit
} else { $null }
$requestedReleaseMilestones = @(
    $profileContract.release_milestones | ForEach-Object { [long]$_ }
)
$candidateArtifacts = Read-Ferrum2CandidateArtifactBundle `
    -ManifestPath $candidateArtifactManifest `
    -CandidateSha $candidate.Sha -Ledger $ledgerIdentity.Ledger
$initialContext = Get-ApprovedVmContext
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

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
$finalTopologyUnchanged = $false
$finalSupportUnchanged = $false

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
    $finalTopologyUnchanged = $true
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
    $finalSupportUnchanged = $true
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
            schema = "ferrum2.windows-tun.hyperv-host-run.v7"
            status = $status
            profile = $qualificationProfile
            cycle_limit = $requestedCycleLimit
            release_milestones = $requestedReleaseMilestones
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            candidate_artifact_manifest_sha256 = $candidateArtifacts.ManifestSha256
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
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = if ($null -eq $guestResult) { $null } else { [string]$connection.Probe.Build }
            checkpoint_restored = $checkpointRestored -and $finalVmState -ceq "Off"
            support_listener_unchanged = $finalSupportUnchanged
            host_tun_unchanged = $finalTopologyUnchanged
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
            "schema", "status", "profile", "cycle_limit", "release_milestones",
            "run_token", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
            "candidate_sha", "candidate_artifact_manifest_sha256", "identity_sha256",
            "controller_bundle_sha256",
            "staged_input_sha256",
            "topology_manifest_sha256", "topology_plan_sha256", "topology",
            "guest_network_path_sha256", "guest_network_path", "host_network_path_sha256",
            "support_listener", "protected_host_tun", "topology_runtime_sha256",
            "host_network_path_helper_sha256", "guest_network_path_probe_sha256",
            "rust_version", "guest_execution",
            "guest_build", "checkpoint_restored", "support_listener_unchanged",
            "host_tun_unchanged", "host_network_mutations", "started_utc", "finished_utc",
            "final_vm_state", "evidence_files"
        )
        if ((@($hostManifestReadback.PSObject.Properties.Name) -join "|") -cne
                ($hostManifestKeys -join "|") -or
            $hostManifestReadback.schema -cne "ferrum2.windows-tun.hyperv-host-run.v7" -or
            $hostManifestReadback.candidate_artifact_manifest_sha256 -cne
                $candidateArtifacts.ManifestSha256 -or
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

Write-Output "hyperv_windows_tun status=PASS profile=$qualificationProfile run_token=$RunToken candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
