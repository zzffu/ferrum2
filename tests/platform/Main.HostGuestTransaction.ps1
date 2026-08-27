    $guestResults = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList @(
            [string]$guestPaths[0].Root,
            $candidate.Sha,
            $qualificationProfile,
            $RunToken,
            $ledgerIdentity.Sha256,
            $expectedWintunZipSha256,
            $expectedWintunDllSha256,
            $expectedPowerShellZipSha256,
            $expectedPowerShellVersion,
            $stagedInputSha256,
            [string]$topologyDocument.Sha256,
            $guestNetworkPathProbeSha256,
            $guestNetworkPathSha256
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$RunRoot,
                [string]$CandidateSha,
                [string]$RequestedProfile,
                [string]$Token,
                [string]$ExpectedLedgerHash,
                [string]$ExpectedWintunHash,
                [string]$ExpectedWintunDllHash,
                [string]$ExpectedPowerShellZipHash,
                [string]$ExpectedPowerShellVersion,
                [string]$ExpectedInputManifestHash,
                [string]$ExpectedTopologyManifestHash,
                [string]$ExpectedGuestNetworkPathProbeHash,
                [string]$ExpectedGuestNetworkPathHash
            )

            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $ProgressPreference = "SilentlyContinue"

            $inputPath = Join-Path $RunRoot "input"
            $inputManifestPath = Join-Path $inputPath "staged-input.json"
            if ((Get-FileHash -LiteralPath $inputManifestPath -Algorithm SHA256 `
                    -ErrorAction Stop).Hash.ToLowerInvariant() -cne
                $ExpectedInputManifestHash) {
                throw "guest staged input manifest changed before source verification"
            }
            $preflightInput = Get-Content -LiteralPath $inputManifestPath `
                -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
            $controllerBundleManifestPath = Join-Path $inputPath `
                "controller\controller-bundle.json"
            if ((Get-FileHash -LiteralPath $controllerBundleManifestPath `
                    -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne
                [string]$preflightInput.files.controller_bundle_manifest.sha256) {
                throw "guest controller bundle manifest changed before source verification"
            }
            $preflightBundle = Get-Content -LiteralPath $controllerBundleManifestPath `
                -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
            $controllerRoot = Join-Path $inputPath 'controller'
            $bootstrapRelative = `
                'modules/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
            $bootstrapEntry = @($preflightBundle.files | Where-Object {
                [string]$_.path -ceq $bootstrapRelative
            })
            $bootstrapPath = Join-Path $controllerRoot `
                $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
            if ($bootstrapEntry.Count -ne 1 -or
                (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 `
                    -ErrorAction Stop).Hash.ToLowerInvariant() -cne
                    [string]$bootstrapEntry[0].sha256) {
                throw "guest controller bundle bootstrap changed"
            }
            . $bootstrapPath
            $verifiedBundle = Assert-Ferrum2BootstrapControllerBundle `
                -ManifestPath $controllerBundleManifestPath `
                -BundleRoot $controllerRoot
            if ([string]$verifiedBundle.entrypoint -cne 'qualify_windows_tun.ps1') {
                throw "guest controller bundle entrypoint changed"
            }
            . (Join-Path $inputPath "controller\Main.GuestBootstrapSupport.ps1")
            $exportPath = Join-Path $RunRoot "export"
            $runtimePath = Join-Path $RunRoot "runtime"
            $artifactPath = Join-Path $exportPath "artifacts"
            $setupStdout = Join-Path $exportPath "setup.stdout.log"
            $setupStderr = Join-Path $exportPath "setup.stderr.log"
            $controllerStdout = Join-Path $artifactPath "controller.stdout.log"
            $controllerStderr = Join-Path $artifactPath "controller.stderr.log"
            $cleanupStdout = Join-Path $artifactPath "cleanup.stdout.log"
            $cleanupStderr = Join-Path $artifactPath "cleanup.stderr.log"
            $controllerPath = Join-Path $inputPath "controller\qualify_windows_tun.ps1"
            $cleanupControllerPath = Join-Path $inputPath `
                "controller\qualify_windows_tun_cleanup.ps1"
            $ledgerPath = Join-Path $inputPath "identity-ledger.json"
            $topologyManifestPath = Join-Path $inputPath "topology-manifest.json"
            $guestNetworkPathProbe = Join-Path $inputPath `
                "controller\get_windows_tun_guest_network_path.ps1"
            $guestNetworkPathPath = Join-Path $exportPath "guest-network-path.json"
            $wintunPath = Join-Path $inputPath "wintun-0.14.1.zip"
            $powerShellArchive = Join-Path $inputPath "portable-pwsh.zip"
            $candidateArtifactDirectory = Join-Path $inputPath "artifacts"
            $runtimeLibraryDirectory = Join-Path $inputPath "runtime\vc-runtime"
            $clientBinary = Join-Path $candidateArtifactDirectory "ferrum2-client.exe"
            $serverBinary = Join-Path $candidateArtifactDirectory "ferrum2-server.exe"
            New-Item -ItemType Directory -Path $artifactPath -ErrorAction Stop | Out-Null

            $cycleLimit = $null
            $releaseMilestones = @()

            $phase = "input"
            $qualificationExit = $null
            $cleanupExit = $null
            $controllerStarted = $false
            $failurePhase = $null
            try {
                $inputItems = @(Get-Item -LiteralPath $inputPath -Force) + @(
                    Get-ChildItem -LiteralPath $inputPath -Force -Recurse
                )
                $inputFiles = @($inputItems | Where-Object { -not $_.PSIsContainer })
                $inputDirectories = @($inputItems | Where-Object { $_.PSIsContainer })
                $inputBytes = [long]($inputFiles | Measure-Object Length -Sum).Sum
                if (@($inputItems | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0 -or
                    $inputBytes -le 0 -or $inputBytes -gt 2147483648) {
                    throw "guest staged input boundary is invalid"
                }
                $manifestItem = Get-Item -LiteralPath $inputManifestPath -Force -ErrorAction Stop
                if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 65536 -or
                    (Get-FileHash -LiteralPath $inputManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        $ExpectedInputManifestHash) {
                    throw "guest staged input manifest identity is invalid"
                }
                $manifest = Get-Content -LiteralPath $inputManifestPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                Assert-ClosedProperties $manifest @(
                    "schema", "candidate_sha", "candidate_artifact_manifest_sha256",
                    "identity_sha256", "controller_bundle",
                    "topology_manifest_sha256",
                    "profile", "cycle_limit", "release_milestones", "files", "runtime"
                ) "staged input manifest"
                Assert-ClosedProperties $manifest.files @(
                    "controller", "controller_bundle_manifest", "identity_ledger",
                    "topology_manifest",
                    "guest_network_path_probe", "wintun_zip", "client", "server",
                    "powershell_archive"
                ) "staged input file manifest"
                Assert-ClosedProperties $manifest.runtime @(
                    "rust_version", "powershell_version", "powershell_executable_sha256",
                    "powershell_file_count", "powershell_expanded_bytes", "vc_libraries"
                ) "staged runtime manifest"
                if ($manifest.schema -cne "ferrum2.windows-tun.hyperv-staged-input.v6" -or
                    $manifest.candidate_sha -cne $CandidateSha -or
                    [string]$manifest.candidate_artifact_manifest_sha256 -cnotmatch
                        '^[0-9a-f]{64}$' -or
                    $manifest.identity_sha256 -cne $ExpectedLedgerHash -or
                    $manifest.topology_manifest_sha256 -cne $ExpectedTopologyManifestHash -or
                    [string]$manifest.runtime.rust_version -cnotmatch '^rustc 1\.97\.1 \(' -or
                    [string]$manifest.runtime.powershell_version -cne $ExpectedPowerShellVersion -or
                    [string]$manifest.runtime.powershell_executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-JsonInteger $manifest.runtime.powershell_file_count) -or
                    -not (Test-JsonInteger $manifest.runtime.powershell_expanded_bytes) -or
                    [long]$manifest.runtime.powershell_file_count -le 0 -or
                    [long]$manifest.runtime.powershell_file_count -gt 4096 -or
                    [long]$manifest.runtime.powershell_expanded_bytes -le 0 -or
                    [long]$manifest.runtime.powershell_expanded_bytes -gt 1073741824) {
                    throw "guest staged input manifest binding is invalid"
                }
                $fileChecks = @(
                    @($controllerPath, $manifest.files.controller, "qualify_windows_tun.ps1", 1, 4194304),
                    @($controllerBundleManifestPath, $manifest.files.controller_bundle_manifest, "controller-bundle.json", 2, 131072),
                    @($ledgerPath, $manifest.files.identity_ledger, "identity-ledger.json", 2, 65536),
                    @($topologyManifestPath, $manifest.files.topology_manifest, "topology-manifest.json", 2, 131072),
                    @($guestNetworkPathProbe, $manifest.files.guest_network_path_probe, "get_windows_tun_guest_network_path.ps1", 2, 4194304),
                    @($wintunPath, $manifest.files.wintun_zip, "wintun-0.14.1.zip", 1, 16777216),
                    @($clientBinary, $manifest.files.client, "ferrum2-client.exe", 4096, 536870912),
                    @($serverBinary, $manifest.files.server, "ferrum2-server.exe", 4096, 536870912),
                    @($powerShellArchive, $manifest.files.powershell_archive, "portable-pwsh.zip", 1, 536870912)
                )
                foreach ($check in $fileChecks) {
                    Assert-StagedFileIdentity $check[0] $check[1] $check[2] $check[3] $check[4]
                }
                $bundleManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
                    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
                if (($bundleManifest | ConvertTo-Json -Compress -Depth 8) -cne
                    ($manifest.controller_bundle | ConvertTo-Json -Compress -Depth 8)) {
                    throw "guest controller bundle manifests disagree"
                }
                $labModule = Join-Path $inputPath `
                    "controller\modules\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1"
                Import-Module $labModule -Scope Local -Force -ErrorAction Stop
                [void](Assert-Ferrum2ControllerBundleManifest `
                    -Manifest $bundleManifest `
                    -BundleRoot (Join-Path $inputPath "controller"))
                $guestControllerModule = Join-Path $inputPath `
                    "controller\modules\Ferrum2.Qualification.GuestController\Ferrum2.Qualification.GuestController.psd1"
                Import-Module $guestControllerModule -Scope Local -Force -ErrorAction Stop
                $profileContract = Resolve-Ferrum2QualificationProfile -Profile $RequestedProfile
                $cycleLimit = if ([long]$profileContract.cycle_limit -gt 0) {
                    [long]$profileContract.cycle_limit
                } else { $null }
                $releaseMilestones = @($profileContract.release_milestones | ForEach-Object { [long]$_ })
                if ($manifest.profile -cne $RequestedProfile -or
                    ($null -eq $cycleLimit -and $null -ne $manifest.cycle_limit) -or
                    ($null -ne $cycleLimit -and
                        (-not (Test-JsonInteger $manifest.cycle_limit) -or
                            [long]$manifest.cycle_limit -ne [long]$cycleLimit)) -or
                    (@($manifest.release_milestones | ForEach-Object { [long]$_ }) -join '|') -cne
                        ($releaseMilestones -join '|')) {
                    throw "guest qualification profile mapping is invalid"
                }
                if ([string]$manifest.files.identity_ledger.sha256 -cne $ExpectedLedgerHash -or
                    [string]$manifest.files.topology_manifest.sha256 -cne
                        $ExpectedTopologyManifestHash -or
                    [string]$manifest.files.guest_network_path_probe.sha256 -cne
                        $ExpectedGuestNetworkPathProbeHash -or
                    [string]$manifest.files.wintun_zip.sha256 -cne $ExpectedWintunHash -or
                    [string]$manifest.files.powershell_archive.sha256 -cne
                        $ExpectedPowerShellZipHash) {
                    throw "guest staged archive or identity hash mismatch"
                }
                $ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                if ($ledger.schema -ne 4 -or
                    $ledger.candidate_sha -cne $CandidateSha -or
                    $ledger.topology.manifest_sha256 -cne $ExpectedTopologyManifestHash -or
                    $ledger.probe_sha256 -cne [string]$manifest.files.controller.sha256 -or
                    $ledger.controller_bundle_sha256 -cne
                        [string]$bundleManifest.controller_bundle_sha256 -or
                    $ledger.client_sha256 -cne [string]$manifest.files.client.sha256 -or
                    $ledger.server_sha256 -cne [string]$manifest.files.server.sha256) {
                    throw "guest candidate ledger binding failed"
                }
                $guestNetworkPathItem = Get-Item -LiteralPath $guestNetworkPathPath `
                    -Force -ErrorAction Stop
                if ($guestNetworkPathItem.PSIsContainer -or
                    ($guestNetworkPathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $guestNetworkPathItem.Length -lt 2 -or
                    $guestNetworkPathItem.Length -gt 65536 -or
                    (Get-FileHash -LiteralPath $guestNetworkPathPath -Algorithm SHA256).
                        Hash.ToLowerInvariant() -cne $ExpectedGuestNetworkPathHash) {
                    throw "guest network-path evidence identity is invalid"
                }
                $guestNetworkPath = Get-Content -LiteralPath $guestNetworkPathPath `
                    -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
                Assert-ClosedProperties $guestNetworkPath @(
                    "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
                    "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
                    "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
                    "guest_route_next_hop", "guest_dns_servers"
                ) "guest network path"
                if ($guestNetworkPath.schema -ne 2 -or
                    [string]$guestNetworkPath.support_ipv4 -cne
                        [string]$ledger.topology.support_host_ipv4 -or
                    [string]$guestNetworkPath.guest_ipv4 -cne
                        [string]$ledger.topology.guest_ipv4 -or
                    [int]$guestNetworkPath.guest_prefix_length -ne
                        [int]$ledger.topology.support_prefix_length -or
                    [int]$guestNetworkPath.guest_interface_index -ne
                        [int]$ledger.topology.guest_interface_index -or
                    [string]$guestNetworkPath.guest_interface_alias -cne
                        [string]$ledger.topology.guest_interface_alias -or
                    [string]$guestNetworkPath.guest_interface_guid -cne
                        [string]$ledger.topology.guest_interface_guid -or
                    [int]$guestNetworkPath.guest_interface_mtu_bytes -ne
                        [int]$ledger.topology.guest_mtu_bytes -or
                    [string]$guestNetworkPath.guest_mac_address -cne
                        [string]$ledger.topology.guest_mac_address -or
                    [string]$guestNetworkPath.guest_route_prefix -cne
                        [string]$ledger.topology.support_network -or
                    [string]$guestNetworkPath.guest_route_next_hop -cne "0.0.0.0" -or
                    @($guestNetworkPath.guest_dns_servers).Count -ne 0) {
                    throw "guest network-path evidence does not match the identity ledger"
                }

                $vcEntries = @($manifest.runtime.vc_libraries)
                $allowedVcNames = @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
                if ($vcEntries.Count -lt 1 -or $vcEntries.Count -gt 3 -or
                    $vcEntries[0].name -cne "vcruntime140.dll" -or
                    (@($vcEntries | ForEach-Object { $_.name } | Select-Object -Unique)).Count -ne
                        $vcEntries.Count -or
                    @($vcEntries | Where-Object { $allowedVcNames -cnotcontains $_.name }).Count -ne 0) {
                    throw "guest Visual C++ runtime manifest is invalid"
                }
                foreach ($entry in $vcEntries) {
                    $vcPath = Join-Path $runtimeLibraryDirectory ([string]$entry.name)
                    Assert-StagedFileIdentity $vcPath $entry ([string]$entry.name) 1 16777216
                }
                $expectedInputFiles = @($bundleManifest.files | ForEach-Object {
                    Join-Path (Join-Path $inputPath "controller") `
                        ([string]$_.path).Replace('/', '\')
                }) + @(
                    $controllerBundleManifestPath,
                    $ledgerPath,
                    $topologyManifestPath,
                    $guestNetworkPathProbe,
                    $wintunPath,
                    $inputManifestPath,
                    $powerShellArchive,
                    $clientBinary,
                    $serverBinary
                ) + @($vcEntries | ForEach-Object {
                    Join-Path $runtimeLibraryDirectory ([string]$_.name)
                })
                $expectedInputDirectories = @(
                    $inputPath,
                    (Join-Path $inputPath "controller"),
                    (Join-Path $inputPath "controller\modules"),
                    (Join-Path $inputPath "controller\modules\Ferrum2.WindowsTun.Lab"),
                    (Join-Path $inputPath "controller\modules\Ferrum2.Qualification.GuestController"),
                    $candidateArtifactDirectory,
                    (Join-Path $inputPath "runtime"),
                    $runtimeLibraryDirectory
                )
                if ($inputFiles.Count -ne $expectedInputFiles.Count -or
                    @($inputFiles | Where-Object {
                        $actualPath = $_.FullName
                        @($expectedInputFiles | Where-Object {
                            $actualPath.Equals($_, [StringComparison]::OrdinalIgnoreCase)
                        }).Count -ne 1
                    }).Count -ne 0 -or
                    $inputDirectories.Count -ne $expectedInputDirectories.Count -or
                    @($inputDirectories | Where-Object {
                        $actualPath = $_.FullName.TrimEnd('\', '/')
                        @($expectedInputDirectories | Where-Object {
                            $actualPath.Equals(
                                ([IO.Path]::GetFullPath($_).TrimEnd('\', '/')),
                                [StringComparison]::OrdinalIgnoreCase
                            )
                        }).Count -ne 1
                    }).Count -ne 0) {
                    throw "guest staged input path set is not closed"
                }
                $env:Path = "$runtimeLibraryDirectory;$env:Path"

                $phase = "runtime"
                if (Test-Path -LiteralPath $runtimePath) {
                    throw "guest portable runtime baseline is not absent"
                }
                Expand-Archive `
                    -LiteralPath $powerShellArchive `
                    -DestinationPath (Join-Path $runtimePath "pwsh") `
                    -ErrorAction Stop
                $expandedItems = @(
                    Get-ChildItem -LiteralPath (Join-Path $runtimePath "pwsh") -Force -Recurse
                )
                $expandedFiles = @($expandedItems | Where-Object { -not $_.PSIsContainer })
                $expandedBytes = [long]($expandedFiles | Measure-Object Length -Sum).Sum
                if (@($expandedItems | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0 -or
                    $expandedFiles.Count -ne [long]$manifest.runtime.powershell_file_count -or
                    $expandedBytes -ne [long]$manifest.runtime.powershell_expanded_bytes) {
                    throw "expanded PowerShell runtime boundary is invalid"
                }
                $pwsh = Join-Path $runtimePath "pwsh\pwsh.exe"
                $pwshItem = Get-Item -LiteralPath $pwsh -Force -ErrorAction Stop
                if ($pwshItem.PSIsContainer -or
                    ($pwshItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$manifest.runtime.powershell_executable_sha256) {
                    throw "staged PowerShell executable identity is invalid"
                }
                $pwshVersion = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>> $setupStderr)
                if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
                    [string]$pwshVersion[0] -cne [string]$manifest.runtime.powershell_version -or
                    [string]$pwshVersion[0] -cne $ExpectedPowerShellVersion) {
                    throw "staged PowerShell runtime verification failed"
                }
                [IO.File]::WriteAllText(
                    $setupStdout,
                    "host_built_artifacts=verified`npowershell_version=$($pwshVersion[0])`n",
                    [Text.UTF8Encoding]::new($false)
                )

                $phase = "qualification"
                $controllerArguments = @(
                        "-NoProfile", "-File", $controllerPath,
                        "-Profile", $RequestedProfile,
                        "-RunToken", $Token,
                        "-IdentityLedger", $ledgerPath,
                        "-TopologyManifest", $topologyManifestPath,
                        "-GuestNetworkPath", $guestNetworkPathPath,
                        "-ClientBinary", $clientBinary,
                        "-ServerBinary", $serverBinary,
                        "-WintunZip", $wintunPath,
                        "-RuntimeLibraryDirectory", $runtimeLibraryDirectory,
                        "-ProductRoot", $RunRoot,
                        "-ArtifactDirectory", $artifactPath
                )
                $controllerStarted = $true
                $qualificationExit = Invoke-LoggedCommand `
                    -Executable $pwsh `
                    -Arguments $controllerArguments `
                    -StdoutPath $controllerStdout `
                    -StderrPath $controllerStderr
            } catch {
                $failurePhase = $phase
            } finally {
                if ($controllerStarted) {
                    $phase = "cleanup"
                    try {
                        $cleanupExit = Invoke-LoggedCommand `
                            -Executable $pwsh `
                            -Arguments @(
                                "-NoProfile", "-File", $cleanupControllerPath,
                                "-Profile", $RequestedProfile,
                                "-RunToken", $Token,
                                "-ClientBinary", $clientBinary,
                                "-ServerBinary", $serverBinary,
                                "-ProductRoot", $RunRoot,
                                "-ArtifactDirectory", $artifactPath
                            ) `
                            -StdoutPath $cleanupStdout `
                            -StderrPath $cleanupStderr
                    } catch {
                        $cleanupExit = -1
                        if ($null -eq $failurePhase) {
                            $failurePhase = "cleanup"
                        }
                    }
                }
            }

            $status = "fail"
            if ($null -eq $failurePhase -and $qualificationExit -eq 0 -and $cleanupExit -eq 0) {
                $requiredArtifacts = @(
                    "identity-ledger.json", "m17-contract.json", "m17-result.json", "external-cleanup.json"
                )
                $missing = @($requiredArtifacts | Where-Object {
                    -not (Test-Path -LiteralPath (Join-Path $artifactPath $_) -PathType Leaf)
                })
                if ($missing.Count -eq 0) {
                    $contract = Get-Content -LiteralPath (Join-Path $artifactPath "m17-contract.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    $result = Get-Content -LiteralPath (Join-Path $artifactPath "m17-result.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    $cleanup = Get-Content -LiteralPath (Join-Path $artifactPath "external-cleanup.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    Assert-ClosedProperties $contract @(
                        "schema", "status", "profile", "cycle_limit", "release_milestones",
                        "approved_vm_name", "approved_vm_id", "approved_checkpoint_name",
                        "approved_checkpoint_id", "guest_build", "identity_sha256", "candidate_sha",
                        "client_sha256", "server_sha256", "controller_sha256",
                        "controller_bundle_sha256", "wintun_zip_sha256",
                        "wintun_dll_sha256", "topology", "guest_network_path",
                        "fixtures", "witnesses", "counters"
                    ) "M17 contract"
                    Assert-ClosedProperties $result @(
                        "schema", "status", "profile", "run_token", "cycle_limit", "release_milestones",
                        "approved_vm_name", "approved_vm_id", "approved_checkpoint_name",
                        "approved_checkpoint_id", "guest_build", "identity_sha256", "candidate_sha",
                        "client_sha256", "server_sha256", "controller_sha256",
                        "controller_bundle_sha256", "wintun_zip_sha256",
                        "wintun_dll_sha256", "topology", "guest_network_path",
                        "started_utc", "finished_utc", "fixtures",
                        "processes", "live_checks", "witnesses", "counters_before",
                        "counters_after", "cleanup", "failure"
                    ) "M17 result"
                    $expectedCycleLimit = if ($RequestedProfile -in @("network-reset", "restart-stress")) {
                        [long]$cycleLimit
                    } else { $null }
                    $cycleContractMatches = if ($null -eq $expectedCycleLimit) {
                        $null -eq $contract.cycle_limit -and $null -eq $result.cycle_limit -and
                            @($contract.release_milestones).Count -eq 0 -and
                            @($result.release_milestones).Count -eq 0
                    } else {
                        (Test-JsonInteger $contract.cycle_limit) -and
                        (Test-JsonInteger $result.cycle_limit) -and
                        [long]$contract.cycle_limit -eq $expectedCycleLimit -and
                        [long]$result.cycle_limit -eq $expectedCycleLimit -and
                        (@($contract.release_milestones | ForEach-Object { [long]$_ }) -join '|') -ceq
                            ($releaseMilestones -join '|') -and
                        (@($result.release_milestones | ForEach-Object { [long]$_ }) -join '|') -ceq
                            ($releaseMilestones -join '|')
                    }
                    Assert-ClosedProperties $result.cleanup @(
                        "status", "processes", "adapters", "sibling_dll", "work_directory",
                        "cleanup_failure_type"
                    ) "M17 internal cleanup"
                    Assert-ClosedProperties $cleanup @(
                        "schema", "status", "run_token", "source_profile", "identity_sha256",
                        "processes", "adapters", "target_addresses", "target_routes",
                        "sibling_dll", "work_directories", "mutation_journals",
                        "identity_journal", "finished_utc"
                    ) "M17 external cleanup"
                    $internalCleanupZero = @(
                        "processes", "adapters", "sibling_dll", "work_directory"
                    ) | Where-Object {
                        -not (Test-JsonInteger $result.cleanup.$_) -or
                        [long]$result.cleanup.$_ -ne 0
                    }
                    $externalCleanupZero = @(
                        "processes", "adapters", "target_addresses", "target_routes",
                        "sibling_dll", "work_directories", "mutation_journals", "identity_journal"
                    ) | Where-Object {
                        -not (Test-JsonInteger $cleanup.$_) -or
                        [long]$cleanup.$_ -ne 0
                    }
                    $contractWitnesses = @($contract.witnesses | Sort-Object)
                    $resultWitnesses = @($result.witnesses)
                    $resultWitnessNames = @($resultWitnesses | ForEach-Object {
                        if ($_.status -cne "pass") { throw "M17 result contains a failed witness" }
                        [string]$_.name
                    } | Sort-Object)
                    $expectedWitnessCount = switch ($RequestedProfile) {
                        "network-reset" { 6 }
                        "restart-stress" { 3 }
                        "fragments" { 2 }
                        "dual-stack-dns" { 5 }
                        "udp-policy" { 12 }
                        "scheduler-ring-full" { 2 }
                        default { throw "M17 result profile has no closed witness count" }
                    }
                    $networkResetWitnessesMatch = $true
                    if ($RequestedProfile -ceq "network-reset") {
                        $expectedNetworkResetWitnesses = @(
                            "ordinary_route_notifications_reset_network_runtime",
                            "same_process_and_managed_adapter_identity",
                            "managed_addresses_routes_and_dns_are_unchanged",
                            "strict_route_is_effective_and_filter_identity_is_unchanged",
                            "network_generation_and_reset_metrics_advance",
                            "retry_reset_failure_and_full_rebuild_metrics_are_unchanged"
                        ) | Sort-Object
                        $networkResetWitnessesMatch = ($contractWitnesses -join "|") -ceq
                            ($expectedNetworkResetWitnesses -join "|")
                    }
                    $witnessesMatch = $contractWitnesses.Count -eq $expectedWitnessCount -and
                        $resultWitnesses.Count -eq $expectedWitnessCount -and
                        $networkResetWitnessesMatch -and
                        ($contractWitnesses -join "|") -ceq ($resultWitnessNames -join "|")
                    $milestonePrefix = if ($RequestedProfile -ceq "network-reset") {
                        "network-reset"
                    } elseif ($RequestedProfile -ceq "restart-stress") {
                        "restart-stress"
                    } else { $null }
                    $expectedMilestoneNames = if ($null -eq $milestonePrefix) { @() } else {
                        @($releaseMilestones | ForEach-Object {
                            "{0}-milestone-{1:D4}" -f $milestonePrefix, [long]$_
                        })
                    }
                    $milestoneRows = @($result.live_checks | Where-Object {
                        [string]$_.name -like '*-milestone-*'
                    })
                    $milestonesMatch = $milestoneRows.Count -eq $expectedMilestoneNames.Count -and
                        (@($milestoneRows | ForEach-Object { [string]$_.name } | Sort-Object) -join '|') -ceq
                            (@($expectedMilestoneNames | Sort-Object) -join '|') -and
                        @($milestoneRows | Where-Object {
                            $_.status -cne 'pass' -or $_.evidence.status -cne 'pass' -or
                            [long]$_.evidence.cycle -notin $releaseMilestones
                        }).Count -eq 0
                    if ($RequestedProfile -ceq "network-reset") {
                        Assert-NetworkResetEvidence `
                            -Result $result `
                            -ArtifactPath $artifactPath `
                            -ExpectedCycles ([int]$expectedCycleLimit)
                    }
                    $terminalLines = @(Get-Content -LiteralPath $controllerStdout -ErrorAction Stop |
                        Where-Object { $_ -cmatch '^m17_windows_tun status=PASS ' })
                    $expectedTerminal = "m17_windows_tun status=PASS profile=$RequestedProfile " +
                        "witnesses=$($resultWitnesses.Count)/$($contractWitnesses.Count) " +
                        "cleanup=PASS run_token=$Token " +
                        "candidate_sha=$CandidateSha artifact=$(Join-Path $artifactPath 'm17-result.json')"
                    $identityMatches = $contract.approved_vm_name -ceq $ledger.vm_name -and
                        $contract.approved_vm_id -ceq $ledger.vm_id -and
                        $contract.approved_checkpoint_name -ceq $ledger.checkpoint_name -and
                        $contract.approved_checkpoint_id -ceq $ledger.checkpoint_id -and
                        $result.approved_vm_name -ceq $ledger.vm_name -and
                        $result.approved_vm_id -ceq $ledger.vm_id -and
                        $result.approved_checkpoint_name -ceq $ledger.checkpoint_name -and
                        $result.approved_checkpoint_id -ceq $ledger.checkpoint_id
                    $binaryHashesMatch = $contract.candidate_sha -ceq $CandidateSha -and
                        $result.candidate_sha -ceq $CandidateSha -and
                        $contract.client_sha256 -ceq [string]$manifest.files.client.sha256 -and
                        $result.client_sha256 -ceq [string]$manifest.files.client.sha256 -and
                        $contract.server_sha256 -ceq [string]$manifest.files.server.sha256 -and
                        $result.server_sha256 -ceq [string]$manifest.files.server.sha256 -and
                        $contract.controller_sha256 -ceq [string]$manifest.files.controller.sha256 -and
                        $result.controller_sha256 -ceq [string]$manifest.files.controller.sha256 -and
                        $contract.controller_bundle_sha256 -ceq
                            [string]$bundleManifest.controller_bundle_sha256 -and
                        $result.controller_bundle_sha256 -ceq
                            [string]$bundleManifest.controller_bundle_sha256 -and
                        $contract.wintun_zip_sha256 -ceq $ExpectedWintunHash -and
                        $result.wintun_zip_sha256 -ceq $ExpectedWintunHash -and
                        $contract.wintun_dll_sha256 -ceq $ExpectedWintunDllHash -and
                        $result.wintun_dll_sha256 -ceq $ExpectedWintunDllHash
                    $m17TopologyMatches =
                        ($contract.topology | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($ledger.topology | ConvertTo-Json -Compress -Depth 5) -and
                        ($result.topology | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($ledger.topology | ConvertTo-Json -Compress -Depth 5)
                    $m17GuestPathMatches =
                        ($contract.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5) -and
                        ($result.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5)
                    if ($contract.schema -ceq "ferrum2.windows-tun.m17-contract.v4" -and
                        $contract.status -ceq "preflight_pass" -and
                        $contract.profile -ceq $RequestedProfile -and
                        $contract.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $contract.guest_build -ceq $ledger.guest_build -and
                        $result.schema -ceq "ferrum2.windows-tun.m17-result.v4" -and
                        $result.status -ceq "pass" -and
                        $result.profile -ceq $RequestedProfile -and
                        $result.run_token -ceq $Token -and
                        $result.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $result.guest_build -ceq $ledger.guest_build -and
                        $null -eq $result.failure -and $cycleContractMatches -and
                        $identityMatches -and $binaryHashesMatch -and
                        $m17TopologyMatches -and $m17GuestPathMatches -and
                        $witnessesMatch -and $milestonesMatch -and
                        $result.cleanup.status -ceq "pass" -and
                        $null -eq $result.cleanup.cleanup_failure_type -and
                        @($internalCleanupZero).Count -eq 0 -and
                        $cleanup.schema -ceq "ferrum2.windows-tun.m17-external-cleanup.v1" -and
                        $cleanup.status -ceq "pass" -and $cleanup.run_token -ceq $Token -and
                        $cleanup.source_profile -ceq $RequestedProfile -and
                        $cleanup.identity_sha256 -ceq $ExpectedLedgerHash -and
                        @($externalCleanupZero).Count -eq 0 -and
                        $terminalLines.Count -eq 1 -and $terminalLines[0] -ceq $expectedTerminal) {
                        $status = "pass"
                    } else {
                        $failurePhase = "evidence-readback"
                    }
                } else {
                    $failurePhase = "evidence-readback"
                }
            }
            if ($status -cne "pass" -and $null -eq $failurePhase) {
                $failurePhase = if ($qualificationExit -ne 0) {
                    "qualification"
                } else {
                    "cleanup"
                }
            }

            $guestResult = [ordered]@{
                schema = "ferrum2.windows-tun.hyperv-guest-run.v6"
                status = $status
                profile = $RequestedProfile
                cycle_limit = $cycleLimit
                release_milestones = $releaseMilestones
                run_token = $Token
                candidate_sha = $CandidateSha
                identity_sha256 = $ExpectedLedgerHash
                controller_bundle_sha256 = [string]$bundleManifest.controller_bundle_sha256
                staged_input_sha256 = $ExpectedInputManifestHash
                topology_manifest_sha256 = $ExpectedTopologyManifestHash
                guest_network_path_sha256 = $ExpectedGuestNetworkPathHash
                topology = $ledger.topology
                guest_network_path = $guestNetworkPath
                qualification_exit = if ($null -eq $qualificationExit) { $null } else { [long]$qualificationExit }
                cleanup_exit = if ($null -eq $cleanupExit) { $null } else { [long]$cleanupExit }
                failure_phase = $failurePhase
                finished_utc = [DateTime]::UtcNow.ToString("o")
            }
            Write-GuestJsonNew -Path (Join-Path $exportPath "guest-run.json") -Value $guestResult
            [pscustomobject]$guestResult
        })
    # END GUEST_ONLY_EXECUTION
