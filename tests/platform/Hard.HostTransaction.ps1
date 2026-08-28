try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    Write-Ferrum2ControllerBundleManifest `
        -Path $controllerBundleManifestPath `
        -Manifest $controllerBundleManifest
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )
    Assert-True (
        (Get-Ferrum2LowerSha256 (Join-Path $hostEvidencePath "identity-ledger.json")) -ceq
            $ledgerIdentity.Sha256
    ) "host identity ledger evidence copy changed"
    Copy-Item `
        -LiteralPath $candidateArtifacts.ManifestPath `
        -Destination (Join-Path $hostEvidencePath "candidate-artifacts.json") `
        -ErrorAction Stop
    Assert-True (
        (Get-Ferrum2LowerSha256 `
            (Join-Path $hostEvidencePath "candidate-artifacts.json")) -ceq
                $candidateArtifacts.ManifestSha256
    ) "host candidate artifact manifest evidence copy changed"
    $topologyBytes = [IO.File]::ReadAllBytes([string]$topologyDocument.Path)
    Assert-True (
        [long]$topologyBytes.Length -eq [long]$topologyDocument.Length -and
        (Get-Ferrum2LowerSha256 ([string]$topologyDocument.Path)) -ceq
            [string]$topologyDocument.Sha256
    ) "support topology manifest changed before evidence staging"
    [IO.File]::WriteAllBytes($hostTopologyManifestPath, $topologyBytes)
    Assert-True ((Get-Ferrum2LowerSha256 $hostTopologyManifestPath) -ceq
        [string]$topologyDocument.Sha256) `
        "host topology manifest evidence copy changed"
    $portablePowerShell = New-PortablePowerShellArchive `
        -SourceZip $PowerShellZip `
        -Destination $hostPowerShellArchive
    Assert-True (
        $portablePowerShell.Sha256 -ceq $expectedPowerShellZipSha256 -and
        $portablePowerShell.Version -ceq $expectedPowerShellVersion
    ) "portable PowerShell identity changed after preflight"
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun_hard_kill.ps1" `
        -MaximumBytes 4194304
    $controllerBundleManifestEntry = New-StagedFileEntry `
        -Path $controllerBundleManifestPath `
        -Name "controller-bundle.json" `
        -MaximumBytes 131072
    $wrapperEntry = New-StagedFileEntry `
        -Path $guestWrapperPath `
        -Name "invoke_windows_tun_hard_kill_guest.ps1" `
        -MaximumBytes 2097152
    $identityEntry = New-StagedFileEntry `
        -Path $ledgerIdentity.Path `
        -Name "identity-ledger.json" `
        -MaximumBytes 65536
    $topologyManifestEntry = New-StagedFileEntry `
        -Path ([string]$topologyDocument.Path) `
        -Name "topology-manifest.json" `
        -MaximumBytes 131072
    $guestNetworkPathProbeEntry = New-StagedFileEntry `
        -Path $guestNetworkPathProbePath `
        -Name "get_windows_tun_guest_network_path.ps1" `
        -MaximumBytes 1048576
    $wintunEntry = New-StagedFileEntry `
        -Path $wintunPath `
        -Name "wintun-0.14.1.zip" `
        -MaximumBytes 16777216
    $vcEntries = @($runtimeLibraries | ForEach-Object {
        New-StagedFileEntry -Path $_.Path -Name $_.Name -MaximumBytes 16777216
    })
    Assert-True (
        $controllerEntry.sha256 -ceq [string]$ledgerIdentity.Ledger.probe_sha256 -and
        $controllerBundleManifest.controller_bundle_sha256 -ceq
            [string]$ledgerIdentity.Ledger.controller_bundle_sha256 -and
        $identityEntry.sha256 -ceq $ledgerIdentity.Sha256 -and
        $topologyManifestEntry.sha256 -ceq [string]$topologyDocument.Sha256 -and
        $guestNetworkPathProbeEntry.sha256 -ceq
            [string]$topologyInitialization.GuestNetworkPathProbeSha256 -and
        $wintunEntry.sha256 -ceq $expectedWintunZipSha256
    ) "host staged input identity changed after preflight"
    $postBuildCandidate = Get-CandidateIdentity
    Assert-True ($postBuildCandidate.Sha -ceq $candidate.Sha) `
        "candidate commit changed during artifact preparation"

    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-staged-input.v4"
        mode = "hard-kill"
        run_token = $RunToken
        candidate_sha = $candidate.Sha
        candidate_artifact_manifest_sha256 = $candidateArtifacts.ManifestSha256
        identity_sha256 = $ledgerIdentity.Sha256
        controller_bundle = $controllerBundleManifest
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        guest_product = [string]$ledgerIdentity.Ledger.guest_product
        guest_edition = [string]$ledgerIdentity.Ledger.guest_edition
        guest_architecture = [string]$ledgerIdentity.Ledger.guest_architecture
        guest_version = [string]$ledgerIdentity.Ledger.guest_version
        guest_build = [string]$ledgerIdentity.Ledger.guest_build
        topology = $topologyBinding
        files = [ordered]@{
            guest_wrapper = $wrapperEntry
            controller = $controllerEntry
            controller_bundle_manifest = $controllerBundleManifestEntry
            identity_ledger = $identityEntry
            topology_manifest = $topologyManifestEntry
            guest_network_path_probe = $guestNetworkPathProbeEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Client.Path `
                -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Server.Path `
                -Name "ferrum2-server.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 536870912)
            vc_libraries = $vcEntries
        }
        runtime = [ordered]@{
            rust_version = $candidateArtifacts.RustVersion
            powershell_version = $portablePowerShell.Version
            powershell_executable_sha256 = $portablePowerShell.ExecutableSha256
            powershell_file_count = $portablePowerShell.FileCount
            powershell_expanded_bytes = $portablePowerShell.ExpandedBytes
        }
    }
    Write-Ferrum2JsonCreateNew -Path $stagedInputManifestPath -Value $stagedInput -Depth 8
    $stagedInputSha256 = Get-Ferrum2LowerSha256 $stagedInputManifestPath
    Copy-Item `
        -LiteralPath $stagedInputManifestPath `
        -Destination (Join-Path $hostEvidencePath "staged-input.json") `
        -ErrorAction Stop
    Assert-True (
        (Get-Ferrum2LowerSha256 (Join-Path $hostEvidencePath "staged-input.json")) -ceq
            $stagedInputSha256
    ) "host staged-input evidence copy changed"

    # From this point every exit path must leave the exact checkpoint restored and the VM Off.
    $preMutationTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState `
        -Actual $preMutationTopologyState
    $preMutationSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $preMutationSupportState
    $cleanupAuthority = New-ApprovedVmCleanupAuthority `
        -Context (Get-ApprovedVmContext)
    $restoreRequired = $true
    Restore-ApprovedCheckpoint -TimeoutSeconds $ShutdownTimeoutSeconds
    Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
    $connection = Connect-ApprovedGuest `
        -Credential $guestCredential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    Assert-True (
        [string]$connection.Probe.Product -ceq [string]$ledgerIdentity.Ledger.guest_product -and
        [string]$connection.Probe.Edition -ceq [string]$ledgerIdentity.Ledger.guest_edition -and
        [string]$connection.Probe.Version -ceq [string]$ledgerIdentity.Ledger.guest_version -and
        [string]$connection.Probe.Build -ceq [string]$ledgerIdentity.Ledger.guest_build -and
        [string]$connection.Probe.Architecture -ceq "X64"
    ) "live guest identity differs from the identity ledger"

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
                throw "guest hard-kill staging baseline is not absent"
            }
            $inputPath = Join-Path $root "input"
            $exportPath = Join-Path $root "export"
            New-Item -ItemType Directory -Path $inputPath -Force -ErrorAction Stop | Out-Null
            New-Item -ItemType Directory -Path $exportPath -Force -ErrorAction Stop | Out-Null
            foreach ($relative in @(
                    "controller",
                    "controller\modules\Ferrum2.WindowsTun.Lab",
                    "controller\modules\Ferrum2.WindowsTun.Lab\private",
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
    Assert-True ($guestPaths.Count -eq 1) `
        "guest staging did not return one bounded path set"
    $guestRoot = [string]$guestPaths[0].Root
    $guestInputPath = [string]$guestPaths[0].Input
    $guestExportPath = [string]$guestPaths[0].Export
    $stagedFiles = @(
        [ordered]@{
            Source = $controllerBundleManifestPath
            Destination = Join-Path $guestInputPath "controller\controller-bundle.json"
        },
        [ordered]@{
            Source = $guestWrapperPath
            Destination = Join-Path $guestInputPath "invoke_windows_tun_hard_kill_guest.ps1"
        },
        [ordered]@{
            Source = $ledgerIdentity.Path
            Destination = Join-Path $guestInputPath "identity-ledger.json"
        },
        [ordered]@{
            Source = [string]$topologyDocument.Path
            Destination = Join-Path $guestInputPath "topology-manifest.json"
        },
        [ordered]@{
            Source = $guestNetworkPathProbePath
            Destination = Join-Path $guestInputPath `
                "controller\get_windows_tun_guest_network_path.ps1"
        },
        [ordered]@{
            Source = $wintunPath
            Destination = Join-Path $guestInputPath "wintun-0.14.1.zip"
        },
        [ordered]@{
            Source = $stagedInputManifestPath
            Destination = Join-Path $guestInputPath "staged-input.json"
        },
        [ordered]@{
            Source = $portablePowerShell.Path
            Destination = Join-Path $guestInputPath "portable-pwsh.zip"
        },
        [ordered]@{
            Source = $candidateArtifacts.Client.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-client.exe"
        },
        [ordered]@{
            Source = $candidateArtifacts.Server.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-server.exe"
        }
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
            Destination = Join-Path $guestInputPath ("runtime\vc-runtime\" + $library.Name)
        }
    }
    foreach ($file in $stagedFiles) {
        Copy-Item `
            -ToSession $connection.Session `
            -LiteralPath $file.Source `
            -Destination $file.Destination `
            -ErrorAction Stop
    }
    $guestNetworkPathPreflight = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName "F2-M16P-A-$RunToken" `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument

    # BEGIN GUEST_ONLY_EXECUTION
    $guestResults = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList @(
            $guestRoot,
            $stagedInputSha256,
            $RunToken,
            $expectedPowerShellZipSha256,
            $expectedPowerShellVersion
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$Root,
                [string]$ExpectedManifestSha256,
                [string]$ExpectedRunToken,
                [string]$ExpectedPowerShellZipSha256,
                [string]$ExpectedPowerShellVersion
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $ProgressPreference = "SilentlyContinue"
            function Get-Sha256([string]$Path) {
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).
                    Hash.ToLowerInvariant()
            }
            function Assert-ManifestFile(
                [string]$Path,
                [object]$Entry,
                [string]$ExpectedName,
                [long]$MaximumBytes
            ) {
                $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                if ($item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
                    $Entry.name -cne $ExpectedName -or
                    [long]$Entry.bytes -ne [long]$item.Length -or
                    [string]$Entry.sha256 -cne (Get-Sha256 $Path)) {
                    throw "bootstrap staged file is invalid: $ExpectedName"
                }
            }
            $inputPath = Join-Path $Root "input"
            $manifestPath = Join-Path $inputPath "staged-input.json"
            if ((Get-Sha256 $manifestPath) -cne $ExpectedManifestSha256) {
                throw "bootstrap manifest hash changed"
            }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
                ConvertFrom-Json -ErrorAction Stop
            if ($manifest.schema -cne "ferrum2.windows-tun.hard-kill-staged-input.v4" -or
                $manifest.mode -cne "hard-kill" -or
                $manifest.run_token -cne $ExpectedRunToken -or
                [string]$manifest.candidate_artifact_manifest_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$manifest.files.powershell_archive.sha256 -cne
                    $ExpectedPowerShellZipSha256 -or
                [string]$manifest.runtime.powershell_version -cne $ExpectedPowerShellVersion -or
                [IO.Path]::GetFileName([IO.Path]::GetFullPath($Root).TrimEnd('\', '/')) -cne
                    $ExpectedRunToken) {
                throw "bootstrap staged identity is invalid"
            }
            $wrapperPath = Join-Path $inputPath "invoke_windows_tun_hard_kill_guest.ps1"
            $archivePath = Join-Path $inputPath "portable-pwsh.zip"
            Assert-ManifestFile $wrapperPath $manifest.files.guest_wrapper `
                "invoke_windows_tun_hard_kill_guest.ps1" 2097152
            Assert-ManifestFile $archivePath $manifest.files.powershell_archive `
                "portable-pwsh.zip" 536870912
            $pwshRoot = Join-Path $Root "pwsh74"
            if (Test-Path -LiteralPath $pwshRoot) {
                throw "portable PowerShell expansion baseline is not absent"
            }
            Expand-Archive -LiteralPath $archivePath -DestinationPath $pwshRoot -Force
            $items = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
                Get-ChildItem -LiteralPath $pwshRoot -Force -Recurse
            )
            $files = @($items | Where-Object { -not $_.PSIsContainer })
            $bytes = [long]($files | Measure-Object Length -Sum).Sum
            if (@($items | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -ne 0 -or
                $files.Count -ne [long]$manifest.runtime.powershell_file_count -or
                $bytes -ne [long]$manifest.runtime.powershell_expanded_bytes) {
                throw "portable PowerShell expansion boundary changed"
            }
            $pwsh = Join-Path $pwshRoot "pwsh.exe"
            if ((Get-Sha256 $pwsh) -cne
                [string]$manifest.runtime.powershell_executable_sha256) {
                throw "portable PowerShell executable hash changed"
            }
            $output = @(& $pwsh -NoProfile -File $wrapperPath `
                -RunRoot $Root `
                -ExpectedManifestSha256 $ExpectedManifestSha256 2>&1)
            $exitCode = [int]$LASTEXITCODE
            $outputLines = @($output | ForEach-Object { [string]$_ })
            if ($exitCode -ne 0) {
                throw "guest hard-kill wrapper failed with exit code $exitCode; " +
                    (@($outputLines | Select-Object -Last 20) -join " | ")
            }
            $expectedMarker = "m16_product_hard_kill_wrapper status=PASS " +
                "run_token=$ExpectedRunToken files=8/8 cleanup=PASS"
            if ($outputLines.Count -ne 1 -or $outputLines[0] -cne $expectedMarker) {
                throw "guest hard-kill wrapper marker is invalid"
            }
            [pscustomobject][ordered]@{
                schema = "ferrum2.windows-tun.hard-kill-guest-bootstrap.v3"
                status = "pass"
                mode = "hard-kill"
                run_token = $ExpectedRunToken
                staged_input_sha256 = $ExpectedManifestSha256
                controller_bundle_sha256 = [string]$manifest.controller_bundle.controller_bundle_sha256
                topology = $manifest.topology
                files = [long]17
                cleanup = "pass"
            }
        })
    # END GUEST_ONLY_EXECUTION
    Assert-True ($guestResults.Count -eq 1) "guest hard-kill returned an invalid result count"
    $guestResult = $guestResults[0]
    Assert-Ferrum2ClosedProperties $guestResult @(
        "schema", "status", "mode", "run_token", "staged_input_sha256",
        "controller_bundle_sha256", "topology", "files",
        "cleanup"
    ) "hard-kill guest bootstrap"
    Assert-True (
        $guestResult.schema -ceq "ferrum2.windows-tun.hard-kill-guest-bootstrap.v3" -and
        $guestResult.status -ceq "pass" -and
        $guestResult.mode -ceq "hard-kill" -and
        $guestResult.run_token -ceq $RunToken -and
        $guestResult.staged_input_sha256 -ceq $stagedInputSha256 -and
        $guestResult.controller_bundle_sha256 -ceq
            [string]$controllerBundleManifest.controller_bundle_sha256 -and
        ($guestResult.files -is [int] -or $guestResult.files -is [long]) -and
        [long]$guestResult.files -eq 17 -and
        $guestResult.cleanup -ceq "pass"
    ) "hard-kill guest bootstrap result is invalid"
    Assert-ExactObjectFields `
        -Expected $topologyBinding `
        -Actual $guestResult.topology `
        -Fields $topologyPropertyNames `
        -Label "hard-kill guest bootstrap topology"

    $guestNetworkPathPostflight = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName "F2-M16P-A-$RunToken" `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument
    Assert-ApprovedGuestNetworkPathUnchanged `
        -Expected $guestNetworkPathPreflight.path `
        -Actual $guestNetworkPathPostflight.path
    $postGuestSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $postGuestSupportState
} catch {

    $runFailure = $_
} finally {
    if ($null -ne $connection -and
        -not [string]::IsNullOrWhiteSpace($guestExportPath) -and
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
            Assert-True (
                (Test-Ferrum2PathWithinRoot -Path $resolvedTemporaryRoot -Root $temporaryBase) -and
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cmatch
                    '^ferrum2-hard-kill-hyperv-[0-9a-f]{32}$'
            ) "temporary staging cleanup boundary is invalid"
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label "temporary hard-kill staging cleanup"
            $temporaryItems = @(Get-Item -LiteralPath $resolvedTemporaryRoot -Force) + @(
                Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Force -Recurse
            )
            Assert-True (@($temporaryItems | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -eq 0) "temporary staging contains a reparse point"
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction Stop
        } catch {
            $finalizationFailures.Add("temporary staging cleanup failed: $($_.Exception.Message)")
        }
    }
}
