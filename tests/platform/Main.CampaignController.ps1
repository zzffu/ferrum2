param([Parameter(Mandatory)] [Collections.IDictionary]$Context)

$expectedFields = @(
    'repository_root', 'suite', 'campaign_token', 'identity_ledger',
    'topology_manifest_path', 'topology_manifest_sha256', 'support_tcp_port',
    'support_udp_port', 'support_pid', 'support_owner', 'wintun_zip', 'powershell_zip',
    'evidence_directory', 'credential_path', 'readiness_timeout_seconds',
    'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'qualification campaign context'

$repositoryRoot = [string]$Context.repository_root
$suite = [string]$Context.suite
$campaignToken = [string]$Context.campaign_token
$identityLedger = [string]$Context.identity_ledger
$topologyManifestPath = [string]$Context.topology_manifest_path
$topologyManifestSha256 = [string]$Context.topology_manifest_sha256
$supportTcpPort = [int]$Context.support_tcp_port
$supportUdpPort = [int]$Context.support_udp_port
$supportPid = [int]$Context.support_pid
$supportOwner = [string]$Context.support_owner
$wintunZip = [string]$Context.wintun_zip
$powerShellZip = [string]$Context.powershell_zip
$evidenceDirectory = [string]$Context.evidence_directory
$credentialPath = [string]$Context.credential_path
$readinessTimeoutSeconds = [int]$Context.readiness_timeout_seconds
$shutdownTimeoutSeconds = [int]$Context.shutdown_timeout_seconds

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'the Windows TUN qualification campaign requires 64-bit Windows AMD64'
}

$tokenSuffixes = [ordered]@{
    fragments = 'fragments'
    'dual-stack-dns' = 'dns'
    'udp-policy' = 'udp'
    'scheduler-ring-full' = 'ring'
    'network-reset' = 'reset'
    'restart-stress' = 'restart'
}
$suiteProfiles = @(Get-Ferrum2QualificationSuiteProfiles -Suite $suite)
$closedProfiles = @(Get-Ferrum2QualificationProfiles)
if ((@($tokenSuffixes.Keys | Sort-Object) -join '|') -cne
        ((@($closedProfiles | Sort-Object)) -join '|')) {
    throw 'qualification campaign profile closure differs from GuestController'
}

[void](Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot)
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -ManifestPath $topologyManifestPath `
    -ExpectedSha256 $topologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$approvedVmName = [string]$topologyDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyDocument.Value.vm.id
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportAddress = [string]$topologyDocument.Value.support.switch.host_ipv4
$supportBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress `
    -TcpPort $supportTcpPort `
    -UdpPort $supportUdpPort `
    -ProcessId $supportPid `
    -ProcessOwner $supportOwner
$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot 'tests\platform\qualify_windows_tun.ps1') `
    -Label 'qualification controller' `
    -MaximumBytes 4194304
$controllerBundleFileMap = @(
    Get-Ferrum2MainControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controllerBundleManifest = New-Ferrum2ControllerBundleManifest `
    -FileMap $controllerBundleFileMap `
    -EntryPoint 'qualify_windows_tun.ps1'
$ledgerIdentity = Read-IdentityLedger `
    -Path $identityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -ControllerBundleSha256 $controllerBundleManifest.controller_bundle_sha256 `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportBaseline
$wintunPath = Resolve-BoundedFile `
    -Path $wintunZip `
    -Label 'Wintun archive' `
    -MaximumBytes 16777216
if ((Get-Ferrum2LowerSha256 $wintunPath) -cne
    '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51') {
    throw 'Wintun archive hash mismatch'
}
$evidenceRoot = Resolve-ExternalDirectoryTarget `
    -Path $evidenceDirectory `
    -Label 'qualification campaign evidence directory'
[IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null

$campaignStartedUtc = [DateTime]::UtcNow.ToString('o')
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$temporaryRoot = Join-Path $temporaryBase (
    'ferrum2-qualification-campaign-' + [Guid]::NewGuid().ToString('N')
)
$candidateArtifacts = $null
$profileRows = [Collections.Generic.List[object]]::new()
$campaignFailure = $null
$finalVmState = $null
$artifactCleanupFailure = $null

try {
    $candidateArtifacts = Build-Ferrum2CandidateArtifactBundle `
        -Destination (Join-Path $temporaryRoot 'candidate') `
        -CandidateSha $candidate.Sha `
        -Ledger $ledgerIdentity.Ledger

    if ([string](Get-ApprovedVmContext).Vm.State -cne 'Off') {
        throw 'approved VM must be Off at the qualification campaign baseline'
    }

    foreach ($qualificationProfile in $suiteProfiles) {
        $runToken = "$campaignToken-$($tokenSuffixes[$qualificationProfile])"
        $profileEvidencePath = Join-Path $evidenceRoot $qualificationProfile
        if (Test-Path -LiteralPath $profileEvidencePath) {
            throw "qualification profile evidence baseline is not absent: $qualificationProfile"
        }
        $profileBaseline = Get-ApprovedVmContext
        if ([string]$profileBaseline.Vm.State -cne 'Off') {
            throw "approved VM is not Off before profile: $qualificationProfile"
        }
        $cleanupAuthority = New-ApprovedVmCleanupAuthority -Context $profileBaseline
        $workerParameters = [ordered]@{
            Profile = $qualificationProfile
            RunToken = $runToken
            IdentityLedger = $ledgerIdentity.Path
            CandidateArtifactManifest = $candidateArtifacts.ManifestPath
            TopologyManifestPath = $topologyDocument.Path
            TopologyManifestSha256 = $topologyDocument.Sha256
            SupportTcpPort = $supportTcpPort
            SupportUdpPort = $supportUdpPort
            SupportPid = $supportPid
            SupportOwner = $supportOwner
            WintunZip = $wintunPath
            EvidenceDirectory = $profileEvidencePath
            ReadinessTimeoutSeconds = $readinessTimeoutSeconds
            ShutdownTimeoutSeconds = $shutdownTimeoutSeconds
        }
        if (-not [string]::IsNullOrWhiteSpace($powerShellZip)) {
            $workerParameters.PowerShellZip = $powerShellZip
        }
        if (-not [string]::IsNullOrWhiteSpace($credentialPath)) {
            $workerParameters.CredentialPath = $credentialPath
        }

        $workerTimeoutSeconds = if ($qualificationProfile -in @(
                'network-reset', 'restart-stress'
            )) {
            10800
        } else {
            7200
        }
        $null = Invoke-BoundedHyperVWorkerSupervisor `
            -ScriptPath (Join-Path $repositoryRoot `
                'tests/platform/invoke_windows_tun_hyperv_worker.ps1') `
            -BoundParameters $workerParameters `
            -ForwardedParameterNames @(
                'Profile', 'RunToken', 'IdentityLedger', 'CandidateArtifactManifest',
                'TopologyManifestPath', 'TopologyManifestSha256', 'SupportTcpPort',
                'SupportUdpPort', 'SupportPid', 'SupportOwner', 'WintunZip',
                'PowerShellZip', 'EvidenceDirectory', 'CredentialPath',
                'ReadinessTimeoutSeconds', 'ShutdownTimeoutSeconds'
            ) `
            -WorkerTimeoutSeconds $workerTimeoutSeconds `
            -ShutdownTimeoutSeconds $shutdownTimeoutSeconds `
            -ExpectedVmId $approvedVmId `
            -ExpectedVmName $approvedVmName `
            -ExpectedFinalState 'Off' `
            -CleanupAuthority $cleanupAuthority `
            -CleanupMode 'RestoreCheckpoint' `
            -WorkerContract 'Qualification' `
            -FailureManifestPath (Join-Path $profileEvidencePath 'host-orchestration.json') `
            -Label "Windows TUN $qualificationProfile worker"

        $hostManifestPath = Join-Path $profileEvidencePath 'host-orchestration.json'
        $hostManifest = Get-Content -LiteralPath $hostManifestPath -Raw -Encoding utf8 |
            ConvertFrom-Json -Depth 10 -ErrorAction Stop
        if ($hostManifest.schema -cne 'ferrum2.windows-tun.hyperv-host-run.v7' -or
            $hostManifest.status -cne 'pass' -or
            $hostManifest.profile -cne $qualificationProfile -or
            $hostManifest.run_token -cne $runToken -or
            $hostManifest.candidate_sha -cne $candidate.Sha -or
            $hostManifest.candidate_artifact_manifest_sha256 -cne
                $candidateArtifacts.ManifestSha256 -or
            $hostManifest.final_vm_state -cne 'Off' -or
            $hostManifest.checkpoint_restored -ne $true) {
            throw "qualification profile host manifest is invalid: $qualificationProfile"
        }
        $profileRows.Add([pscustomobject][ordered]@{
            profile = $qualificationProfile
            run_token = $runToken
            status = 'pass'
            host_manifest_path = "$qualificationProfile/host-orchestration.json"
            host_manifest_sha256 = Get-Ferrum2LowerSha256 $hostManifestPath
            candidate_artifact_manifest_sha256 = $candidateArtifacts.ManifestSha256
        })

        if ([string](Get-ApprovedVmContext).Vm.State -cne 'Off') {
            throw "qualification profile did not leave the approved VM Off: $qualificationProfile"
        }
        $postProfileTopology = Get-ApprovedHyperVTopologyRuntimeState `
            -TopologyDocument $topologyDocument
        Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
            -Expected $initialTopologyState `
            -Actual $postProfileTopology
        $postProfileSupport = Get-ApprovedHostSupportRuntimeState `
            -TopologyDocument $topologyDocument `
            -Address $supportAddress `
            -TcpPort $supportTcpPort `
            -UdpPort $supportUdpPort `
            -ProcessId $supportPid `
            -ProcessOwner $supportOwner
        Assert-ApprovedHostSupportRuntimeStateUnchanged `
            -Expected $supportBaseline `
            -Actual $postProfileSupport
    }
} catch {
    $campaignFailure = $_
} finally {
    try {
        $finalVmState = [string](Get-ApprovedVmContext).Vm.State
    } catch {
        $finalVmState = $null
        if ($null -eq $campaignFailure) { $campaignFailure = $_ }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        try {
            $resolvedTemporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot -ErrorAction Stop).Path
            if (-not $resolvedTemporaryRoot.StartsWith(
                    $temporaryBase + [IO.Path]::DirectorySeparatorChar,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cnotmatch
                    '^ferrum2-qualification-campaign-[0-9a-f]{32}$') {
                throw 'qualification campaign temporary cleanup boundary is invalid'
            }
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label 'qualification campaign temporary cleanup'
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction Stop
        } catch {
            $artifactCleanupFailure = $_
            if ($null -eq $campaignFailure) { $campaignFailure = $_ }
        }
    }
}

if ($null -eq $campaignFailure -and $finalVmState -cne 'Off') {
    $campaignFailure = [InvalidOperationException]::new(
        'qualification campaign did not leave the approved VM Off'
    )
}
if ($null -eq $campaignFailure -and $profileRows.Count -ne $suiteProfiles.Count) {
    $campaignFailure = [InvalidOperationException]::new(
        'qualification campaign did not complete its closed profile set'
    )
}
$campaignStatus = if ($null -eq $campaignFailure -and $finalVmState -ceq 'Off' -and
    $profileRows.Count -eq $suiteProfiles.Count) { 'pass' } else { 'fail' }
$campaignFailureMessage = if ($null -eq $campaignFailure) {
    $null
} elseif ($campaignFailure -is [Management.Automation.ErrorRecord]) {
    [string]$campaignFailure.Exception.Message
} elseif ($campaignFailure -is [Exception]) {
    [string]$campaignFailure.Message
} else {
    [string]$campaignFailure
}
$campaignManifest = [ordered]@{
    schema = 'ferrum2.windows-tun.qualification-campaign.v1'
    status = $campaignStatus
    suite = $suite
    campaign_token = $campaignToken
    candidate_sha = $candidate.Sha
    identity_sha256 = $ledgerIdentity.Sha256
    controller_bundle_sha256 = $controllerBundleManifest.controller_bundle_sha256
    candidate_artifact_manifest_sha256 = if ($null -eq $candidateArtifacts) {
        $null
    } else { $candidateArtifacts.ManifestSha256 }
    selected_profiles = @($suiteProfiles)
    profiles = @($profileRows)
    started_utc = $campaignStartedUtc
    finished_utc = [DateTime]::UtcNow.ToString('o')
    final_vm_state = $finalVmState
    artifact_bundle_removed = $null -eq $artifactCleanupFailure
    failure = $campaignFailureMessage
}
$campaignManifestPath = Join-Path $evidenceRoot 'qualification-campaign.json'
Write-Ferrum2JsonCreateNew `
    -Path $campaignManifestPath `
    -Value $campaignManifest `
    -Depth 8

if ($campaignStatus -cne 'pass') {
    throw [InvalidOperationException]::new(
        "Windows TUN qualification campaign failed; evidence=$campaignManifestPath; " +
            "failure=$($campaignManifest.failure)"
    )
}
Write-Output (
    "windows_tun_qualification_campaign status=PASS suite=$suite " +
        "campaign_token=$campaignToken candidate_sha=$($candidate.Sha) " +
        "profiles=$($profileRows.Count) evidence=$evidenceRoot final_vm_state=Off"
)
