    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    Write-Ferrum2ControllerBundleManifest `
        -Path $controllerBundleManifestPath `
        -Manifest $controllerBundleManifest
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $topologyDocument
    Copy-Item -LiteralPath $topologyDocument.Path `
        -Destination $hostTopologyManifestPath -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $hostTopologyManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne [string]$topologyDocument.Sha256 -or
        (Get-Item -LiteralPath $hostTopologyManifestPath -Force).Length -ne
            [long]$topologyDocument.Length) {
        throw "evidence topology manifest copy changed"
    }
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )
    $candidateArtifacts = Build-CandidateArtifacts `
        -Destination $hostArtifactRoot `
        -Ledger $ledgerIdentity.Ledger
    $portablePowerShell = New-PortablePowerShellArchive `
        -SourceZip $PowerShellZip `
        -Destination $hostPowerShellArchive
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun.ps1" `
        -MaximumBytes 4194304
    $controllerBundleManifestEntry = New-StagedFileEntry `
        -Path $controllerBundleManifestPath `
        -Name "controller-bundle.json" `
        -MaximumBytes 131072
    $identityEntry = New-StagedFileEntry `
        -Path $ledgerIdentity.Path `
        -Name "identity-ledger.json" `
        -MaximumBytes 65536
    $topologyManifestEntry = New-StagedFileEntry `
        -Path $topologyDocument.Path `
        -Name "topology-manifest.json" `
        -MaximumBytes 131072
    $guestNetworkPathProbeEntry = New-StagedFileEntry `
        -Path $guestNetworkPathProbePath `
        -Name "get_windows_tun_guest_network_path.ps1" `
        -MaximumBytes 4194304
    $wintunEntry = New-StagedFileEntry `
        -Path $wintunPath `
        -Name "wintun-0.14.1.zip" `
        -MaximumBytes 16777216
    $vcEntries = @($runtimeLibraries | ForEach-Object {
        New-StagedFileEntry -Path $_.Path -Name $_.Name -MaximumBytes 16777216
    })
    if ($controllerEntry.sha256 -cne [string]$ledgerIdentity.Ledger.probe_sha256 -or
        $controllerBundleManifest.controller_bundle_sha256 -cne
            [string]$ledgerIdentity.Ledger.controller_bundle_sha256 -or
        $identityEntry.sha256 -cne $ledgerIdentity.Sha256 -or
        $topologyManifestEntry.sha256 -cne [string]$topologyDocument.Sha256 -or
        $guestNetworkPathProbeEntry.sha256 -cne $guestNetworkPathProbeSha256 -or
        [string]$ledgerIdentity.Ledger.topology.manifest_sha256 -cne
            [string]$topologyDocument.Sha256 -or
        $wintunEntry.sha256 -cne $expectedWintunZipSha256) {
        throw "host staged input identity changed after preflight"
    }
    $postBuildCandidate = Get-CandidateIdentity
    if ($postBuildCandidate.Sha -cne $candidate.Sha) {
        throw "candidate commit changed during host artifact preparation"
    }
    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-staged-input.v4"
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        controller_bundle = $controllerBundleManifest
        topology_manifest_sha256 = [string]$topologyDocument.Sha256
        profile = $Profile
        mode = $requestedMode
        network_reset_cycles = $requestedNetworkResetCycles
        restart_cycles = $requestedRestartCycles
        files = [ordered]@{
            controller = $controllerEntry
            controller_bundle_manifest = $controllerBundleManifestEntry
            identity_ledger = $identityEntry
            topology_manifest = $topologyManifestEntry
            guest_network_path_probe = $guestNetworkPathProbeEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry -Path $candidateArtifacts.Client.Path -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry -Path $candidateArtifacts.Server.Path -Name "ferrum2-server.exe")
            client_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.client.Path -Name "ferrum2-client-tests.exe")
            tun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.tun.Path -Name "ferrum2-tun-tests.exe")
            wintun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.wintun.Path -Name "ferrum2-platform-windows-tests.exe")
            fuzz_smoke = $(New-StagedFileEntry -Path $candidateArtifacts.FuzzSmoke.Path -Name "ferrum2-tun-fuzz-smoke.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 536870912)
        }
        runtime = [ordered]@{
            rust_version = $candidateArtifacts.RustVersion
            powershell_version = $portablePowerShell.Version
            powershell_executable_sha256 = $portablePowerShell.ExecutableSha256
            powershell_file_count = $portablePowerShell.FileCount
            powershell_expanded_bytes = $portablePowerShell.ExpandedBytes
            vc_libraries = $vcEntries
        }
    }
    Write-Ferrum2JsonCreateNew -Path $stagedInputManifestPath -Value $stagedInput -Depth 8
    $stagedInputSha256 = (Get-FileHash -LiteralPath $stagedInputManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item `
        -LiteralPath $stagedInputManifestPath `
        -Destination (Join-Path $hostEvidencePath "staged-input.json") `
        -ErrorAction Stop

    $preMutationTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $preMutationTopologyState
    $preMutationSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $preMutationSupportState

    # Capture fresh, GUID-only cleanup authority immediately before the first VM mutation. It is
    # used only if later manifest/name/inventory drift prevents the stricter normal cleanup path.
    $cleanupAuthority = New-ApprovedVmCleanupAuthority `
        -Context (Get-ApprovedVmContext)
    # From this point onward every exit path must leave the exact approved checkpoint restored Off.
    $restoreRequired = $true
    Restore-ApprovedCheckpoint -TimeoutSeconds $ShutdownTimeoutSeconds
    Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
    $connection = Connect-ApprovedGuest `
        -Credential $guestCredential `
        -TimeoutSeconds $ReadinessTimeoutSeconds

    $guestPaths = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList $RunToken `
        -ErrorAction Stop `
        -ScriptBlock {
            param([string]$Token)
            if ($Token -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') {
                throw "guest staging token is invalid"
            }
            $base = Join-Path $env:ProgramData "Ferrum2\HostQualification"
            if (Test-Path -LiteralPath $base) {
                $baseItem = Get-Item -LiteralPath $base -Force
                if (-not $baseItem.PSIsContainer -or
                    ($baseItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw "guest staging base is unsafe"
                }
            } else {
                New-Item -ItemType Directory -Path $base -ErrorAction Stop | Out-Null
            }
            $root = Join-Path $base $Token
            if (Test-Path -LiteralPath $root) {
                throw "guest staging baseline is not absent"
            }
            $inputPath = Join-Path $root "input"
            $exportPath = Join-Path $root "export"
            New-Item -ItemType Directory -Path $inputPath -Force -ErrorAction Stop | Out-Null
            New-Item -ItemType Directory -Path $exportPath -Force -ErrorAction Stop | Out-Null
            foreach ($relative in @(
                    "controller",
                    "controller\modules\Ferrum2.Qualification.Common",
                    "controller\modules\Ferrum2.Qualification.GuestController",
                    "controller\modules\Ferrum2.Qualification.Evidence",
                    "artifacts",
                    "runtime\vc-runtime"
                )) {
                New-Item `
                    -ItemType Directory `
                    -Path (Join-Path $inputPath $relative) `
                    -Force `
                    -ErrorAction Stop | Out-Null
            }
            [pscustomobject]@{
                Root = $root
                Input = $inputPath
                Export = $exportPath
            }
        })
    if ($guestPaths.Count -ne 1) {
        throw "guest staging did not return one bounded path set"
    }
    $guestExportPath = [string]$guestPaths[0].Export
    $guestInputPath = [string]$guestPaths[0].Input
    $stagedFiles = @(
        [ordered]@{ Source = $controllerBundleManifestPath; Destination = $(Join-Path $guestInputPath "controller\controller-bundle.json") },
        [ordered]@{ Source = $ledgerIdentity.Path; Destination = $(Join-Path $guestInputPath "identity-ledger.json") },
        [ordered]@{ Source = $topologyDocument.Path; Destination = $(Join-Path $guestInputPath "topology-manifest.json") },
        [ordered]@{ Source = $guestNetworkPathProbePath; Destination = $(Join-Path $guestInputPath "controller\get_windows_tun_guest_network_path.ps1") },
        [ordered]@{ Source = $wintunPath; Destination = $(Join-Path $guestInputPath "wintun-0.14.1.zip") },
        [ordered]@{ Source = $stagedInputManifestPath; Destination = $(Join-Path $guestInputPath "staged-input.json") },
        [ordered]@{ Source = $portablePowerShell.Path; Destination = $(Join-Path $guestInputPath "portable-pwsh.zip") },
        [ordered]@{ Source = $candidateArtifacts.Client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client.exe") },
        [ordered]@{ Source = $candidateArtifacts.Server.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-server.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.tun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-tun-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.wintun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-platform-windows-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.FuzzSmoke.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-tun-fuzz-smoke.exe") }
    )
    foreach ($mapping in $controllerBundleFileMap) {
        $stagedFiles += [ordered]@{
            Source = [string]$mapping.source_path
            Destination = Join-Path $guestInputPath `
                ("controller\" + ([string]$mapping.relative_path).Replace('/', '\'))
        }
    }
    foreach ($library in $runtimeLibraries) {
        $stagedFiles += [ordered]@{
            Source = $library.Path
            Destination = $(Join-Path $guestInputPath ("runtime\vc-runtime\" + $library.Name))
        }
    }
    foreach ($file in $stagedFiles) {
        Copy-Item `
            -ToSession $connection.Session `
            -LiteralPath $file.Source `
            -Destination $file.Destination `
            -ErrorAction Stop
    }

    $guestNetworkPathEvidencePath = Join-Path $guestExportPath "guest-network-path.json"
    $guestManagedAdapterName = "F2-M17-$RunToken"
    $guestSupportTopologyBaseline = Get-ApprovedGuestSupportTopologyRuntimeState `
        -Session $connection.Session -TopologyDocument $topologyDocument
    $guestPathBootstrap = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName $guestManagedAdapterName `
        -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -OutputPath $guestNetworkPathEvidencePath `
        -TopologyDocument $topologyDocument
    $guestNetworkPath = $guestPathBootstrap.path
    $guestNetworkPathSha256 = [string]$guestPathBootstrap.evidence_sha256
    $pathTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $pathTopologyState
    $pathSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $pathSupportState
    $hostReturnPath = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPath `
        -VmNetworkContext $pathTopologyState.VmNetwork `
        -ExpectedSupportIpv4 $supportAddress
    $hostNetworkPathEvidence = [ordered]@{
        schema = 2
        kind = "windows_tun_host_network_path"
        topology = [ordered]@{
            manifest_sha256 = [string]$topologyDocument.Sha256
            plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
            support_switch_id = [string]$topologyDocument.Value.support.switch.switch_id
            qualification_checkpoint_id = $approvedCheckpointId.ToString("D")
        }
        support_listener = $pathSupportState
        approved_vm_network = $pathTopologyState.VmNetwork
        guest_forward_path = $guestNetworkPath
        host_return_path = $hostReturnPath
        guest_probe_sha256 = $guestNetworkPathProbeSha256
        host_helper_sha256 = $hostNetworkPathHelperSha256
        support_path_probe = [ordered]@{
            status = "PASS"
            tcp_echo = $true
            udp_echo = $true
            minimum_ipv4_packet_bytes = $minimumSupportIpv4PacketBytes
        }
        host_tun_bypassed = $true
        host_network_mutations = 0
    }
    Write-Ferrum2JsonCreateNew -Path $hostNetworkPathPath -Value $hostNetworkPathEvidence -Depth 8
    $hostNetworkPathSha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()

    # BEGIN GUEST_ONLY_EXECUTION
