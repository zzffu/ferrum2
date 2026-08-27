try {
    [IO.Directory]::CreateDirectory($hostEvidenceRoot) | Out-Null
    Copy-Item -LiteralPath $topologyManifestDocument.Path `
        -Destination $hostTopologyManifestPath -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $hostTopologyManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $topologyManifestDocument.Sha256 -or
        (Get-Item -LiteralPath $hostTopologyManifestPath -Force).Length -ne
            $topologyManifestDocument.Length) {
        throw "evidence topology manifest copy changed"
    }
    [IO.Directory]::CreateDirectory($artifactRoot) | Out-Null
    [IO.Directory]::CreateDirectory($runtimeRoot) | Out-Null
    if ($instrumentedDiagnosticMode) {
        [IO.Directory]::CreateDirectory($hostDiagnosticRoot) | Out-Null
        [IO.Directory]::CreateDirectory($hostDiagnosticHostRoot) | Out-Null
        [IO.Directory]::CreateDirectory($hostDiagnosticSupportRoot) | Out-Null
    }
    $plan = New-CanonicalPlan -Python $python -RunKindValue $RunKind -Output $hostPlanPath
    $udpBoundaryRecipe = $plan.scenarios.
        "udp-8192-association-lookup-expiry".recipe
    $canonicalSourcePlan = [pscustomobject]@{
        Ipv4 = [string]$udpBoundaryRecipe.canonical_source_ipv4
        PortFirst = [int]$udpBoundaryRecipe.canonical_source_port_first
        PortLast = [int]$udpBoundaryRecipe.canonical_source_port_last
    }
    $diagnosticSourcePlan = [pscustomobject]@{
        Ipv4 = [string]$udpBoundaryRecipe.diagnostic_source_ipv4
        PortFirst = [int]$udpBoundaryRecipe.diagnostic_source_port_first
        PortLast = [int]$udpBoundaryRecipe.diagnostic_source_port_last
        CollectorSha256 = [string]$udpBoundaryRecipe.
            diagnostic_collector_source_sha256
    }
    $runtimeIdleTimeoutMilliseconds = [int]$plan.scenarios."tcp-single-flow".recipe.
        client_runtime_idle_timeout_milliseconds
    $tunRingCapacityBytes = [long]$plan.scenarios."tcp-single-flow".recipe.
        tun_ring_capacity_bytes
    [void](New-NetworkModelPlan -Python $python -Output $hostNetworkModelPlanPath `
        -ExpectedSha256 ([string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256))
    $diagnosticTrial = if ($instrumentedDiagnosticMode) {
        Resolve-CanonicalDiagnosticProfileTrial `
            -Plan $plan -Profile $DiagnosticProfile
    } else {
        $null
    }
    $executionTrials = @(if ($instrumentedDiagnosticMode) {
        $diagnosticTrial
    } else {
        $plan.trials | Sort-Object sequence
    })
    if (($instrumentedDiagnosticMode -and $executionTrials.Count -ne 1) -or
        (-not $instrumentedDiagnosticMode -and $executionTrials.Count -ne 108)) {
        throw "canonical Windows TUN execution selection is invalid"
    }
    $expectedTrialCount = if ($instrumentedDiagnosticMode) {
        0
    } else {
        $executionTrials.Count
    }
    $expectedNetworkModelObservationCount = if ($instrumentedDiagnosticMode) {
        0
    } else {
        @($executionTrials | Where-Object {
            [string]$_.scenario -in @("udp-route-once", "network-lifecycle")
        }).Count
    }
    $expectedProcessLogCount = 4 * $expectedTrialCount
    $expectedDiagnosticProcessLogCount = if ($instrumentedDiagnosticMode) { 4 } else { 0 }
    $diagnosticSequenceValue = if ($instrumentedDiagnosticMode) {
        [int]$diagnosticTrial.sequence
    } else { 0 }
    $scheduleLines = @($plan.trials | ForEach-Object {
        "$($_.sequence)`t$($_.scenario)`t$($_.member)`t$($_.pair)`t$($_.order)"
    })
    Write-Utf8FileNew -Path $hostSchedulePath -Text (($scheduleLines -join "`n") + "`n")

    $candidateBuild = Build-MemberArtifacts -Cargo $cargo -Git $git -Tar $tar `
        -Sha $CandidateSha -Member "candidate" -TemporaryRoot $temporaryRoot `
        -ArtifactRoot $artifactRoot -IncludeHarness
    if ($ParentSha -ceq $CandidateSha) {
        $parentDirectory = Join-Path $artifactRoot "parent"
        [IO.Directory]::CreateDirectory($parentDirectory) | Out-Null
        Copy-Item -LiteralPath $candidateBuild.Client `
            -Destination (Join-Path $parentDirectory "ferrum2-client.exe") -ErrorAction Stop
        Copy-Item -LiteralPath $candidateBuild.Server `
            -Destination (Join-Path $parentDirectory "ferrum2-server.exe") -ErrorAction Stop
        $parentBuild = [pscustomobject]@{
            Client = Join-Path $parentDirectory "ferrum2-client.exe"
            Server = Join-Path $parentDirectory "ferrum2-server.exe"
            ClientSha256 = $candidateBuild.ClientSha256
            ServerSha256 = $candidateBuild.ServerSha256
        }
    } else {
        $parentBuild = Build-MemberArtifacts -Cargo $cargo -Git $git -Tar $tar `
            -Sha $ParentSha -Member "parent" -TemporaryRoot $temporaryRoot `
            -ArtifactRoot $artifactRoot
    }

    $performanceControllerBundleRoot = Join-Path $temporaryRoot "input\controller"
    Copy-Ferrum2ControllerBundle -FileMap $performanceControllerFileMap `
        -Manifest $performanceControllerBundleManifest `
        -DestinationRoot $performanceControllerBundleRoot
    Write-Ferrum2ControllerBundleManifest `
        -Path (Join-Path $temporaryRoot "input\controller-bundle.json") `
        -Manifest $performanceControllerBundleManifest
    $udpBoundaryCollectorSha256 = ""
    if ($instrumentedDiagnosticMode) {
        Copy-Item -LiteralPath $udpBoundaryCollectorPath `
            -Destination (Join-Path $temporaryRoot "input") -ErrorAction Stop
        $udpBoundaryCollectorSha256 = (Get-FileHash `
            -LiteralPath $udpBoundaryCollectorPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($udpBoundaryCollectorSha256 -cne
                $udpBoundaryCollectorSourceSha256 -or
            $udpBoundaryCollectorSha256 -cne
                [string]$diagnosticSourcePlan.CollectorSha256) {
            throw "UDP boundary collector source changed after plan generation"
        }
    }
    $guestNetworkPathProbeDestination = Join-Path $temporaryRoot `
        "input\get_windows_tun_guest_network_path.ps1"
    Copy-Item -LiteralPath $guestNetworkPathProbePath `
        -Destination $guestNetworkPathProbeDestination -ErrorAction Stop
    $guestNetworkPathProbeSha256 = (Get-FileHash -LiteralPath $guestNetworkPathProbePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($guestNetworkPathProbeSha256 -cne $guestNetworkPathProbeSourceSha256) {
        throw "guest network-path probe source changed after plan generation"
    }
    if ((Get-FileHash -LiteralPath $guestNetworkPathProbeDestination `
            -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $guestNetworkPathProbeSourceSha256) {
        throw "staged guest network-path probe identity mismatch"
    }
    Copy-Item -LiteralPath $networkModelBundleManifestPath `
        -Destination (Join-Path $temporaryRoot "input\windows_tun_network_model.bundle.json") `
        -ErrorAction Stop
    Copy-Item -LiteralPath $resolvedWintunZip `
        -Destination (Join-Path $temporaryRoot "input\wintun-0.14.1.zip") -ErrorAction Stop
    Copy-Item -LiteralPath $hostPlanPath -Destination (Join-Path $temporaryRoot "input\plan.json") `
        -ErrorAction Stop
    Copy-Item -LiteralPath $hostNetworkModelPlanPath `
        -Destination (Join-Path $temporaryRoot "input\network-model-plan.json") `
        -ErrorAction Stop
    $portableRuntime = Stage-PortableRuntime `
        -Rustup $rustup `
        -PowerShellZip $resolvedPowerShellZip `
        -Destination $runtimeRoot

    $clientTemplate = @'
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "{{ADAPTER_NAME}}"
ipv4_address = "198.18.0.2/30"
mtu = 1420
auto_route = true
route_address = ["{{SUPPORT_IPV4}}/32"]
ring_capacity = {{TUN_RING_CAPACITY_BYTES}}
ready_timeout_ms = 30000
max_tcp_flows = 4096
tcp_buffer_bytes = 32768
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
[[outbounds]]
tag = "direct"
type = "direct"
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[route]
auto_detect_interface = false
default_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "{{SUPPORT_IPV4}}"
port = {{SUPPORT_UDP_PORT}}
action = "route"
outbound = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
idle_timeout_ms = {{RUNTIME_IDLE_TIMEOUT_MS}}
[metrics]
listen = "127.0.0.1:{{METRICS_PORT}}"
'@
    $clientTemplate = $clientTemplate.Replace(
        "{{RUNTIME_IDLE_TIMEOUT_MS}}",
        [string]$runtimeIdleTimeoutMilliseconds
    )
    $clientTemplate = $clientTemplate.Replace(
        "{{TUN_RING_CAPACITY_BYTES}}",
        [string]$tunRingCapacityBytes
    )
    $serverTemplate = @'
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
[[outbounds]]
tag = "direct"
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[route]
auto_detect_interface = false
default_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
final = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
[metrics]
listen = "127.0.0.1:{{SERVER_METRICS_PORT}}"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
'@
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\client.toml.template") `
        -Text ($clientTemplate.TrimStart([char[]]"`r`n") + "`n")
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\server.toml.template") `
        -Text ($serverTemplate.TrimStart([char[]]"`r`n") + "`n")

    $supportHostReadback = Get-HostSupportContext `
        -RepositoryRoot $repositoryRoot `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostReadback
    if ($instrumentedDiagnosticMode -and
        [string]$supportHostReadback.executable_sha256 -cne
            $candidateBuild.HarnessSha256) {
        throw "support diagnostic binary does not match the candidate harness"
    }
    $vmNetworkReadback = Get-ApprovedVmNetworkContext `
        -TopologyDocument $topologyManifestDocument `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $vmNetworkBaseline -Actual $vmNetworkReadback
    $context = Get-Ferrum2HostVmContext -Identity $hostHyperVIdentity
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off at the performance-window baseline"
    }
    # From this point every exit path must restore the approved checkpoint, including a
    # Start-VM call that reports failure after partially transitioning the VM.
    $vmWindowStarted = $true
    [void](Invoke-Ferrum2HostVmLifecycle -Identity $hostHyperVIdentity `
        -Action Restore -TimeoutSeconds $ShutdownTimeoutSeconds)
    $runningContext = Invoke-Ferrum2HostVmLifecycle `
        -Identity $hostHyperVIdentity -Action Start `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    if ([string]$runningContext.Vm.State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
    $connection = Connect-Ferrum2HostGuest `
        -Identity $hostHyperVIdentity -Credential $credential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    $session = $connection.Session

    Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
        param([string]$Root)
        if (Test-Path -LiteralPath $Root) { throw "guest staging baseline is not absent" }
        New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null
    }
    Copy-Item -ToSession $session -LiteralPath (Join-Path $temporaryRoot "input") `
        -Destination $guestRoot -Recurse -ErrorAction Stop

    $guestNetworkPathJsonRows = @(Invoke-Command -Session $session -ErrorAction Stop `
        -ArgumentList @(
            $guestRoot, $SupportIpv4, $SupportTcpPort, $SupportUdpPort,
            $supportGuestIpv4, $supportGuestInterfaceAlias, $supportNetwork,
            $supportPrefixLength, $supportVmMacAddress,
            $supportGuestInterfaceGuid.ToString("D"), $supportGuestMtuBytes,
            $guestNetworkPathProbeSha256, $candidateBuild.HarnessSha256,
            $portableRuntime.PowerShellExecutableSha256,
            $minimumSupportIpv4PacketBytes
        ) -ScriptBlock {
            param(
                [string]$Root,
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
                [string]$ExpectedNetworkPathProbeSha256,
                [string]$ExpectedHarnessSha256,
                [string]$ExpectedPowerShellSha256,
                [int]$MinimumSupportIpv4PacketBytes
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $inputRoot = Join-Path $Root "input"
            $networkPathProbe = Join-Path $inputRoot `
                "get_windows_tun_guest_network_path.ps1"
            $harness = Join-Path $inputRoot "artifacts\m4-qualification.exe"
            $powerShell = Join-Path $inputRoot "runtime\pwsh\pwsh.exe"
            if ((Get-FileHash -LiteralPath $networkPathProbe -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedNetworkPathProbeSha256 -or
                (Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedHarnessSha256 -or
                (Get-FileHash -LiteralPath $powerShell -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedPowerShellSha256) {
                throw "guest network-path preflight executable identity mismatch"
            }
            $vcRuntimeRoot = Join-Path $inputRoot "runtime\vc-runtime"
            $vcRuntimeItems = @(Get-ChildItem -LiteralPath $vcRuntimeRoot -Force -ErrorAction Stop)
            $vcRuntimeDlls = @($vcRuntimeItems | Where-Object { -not $_.PSIsContainer })
            $allowedVcRuntimeNames = @(
                "VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"
            )
            if ($vcRuntimeDlls.Count -le 0 -or $vcRuntimeDlls.Count -gt 3 -or
                $vcRuntimeItems.Count -ne $vcRuntimeDlls.Count -or
                @($vcRuntimeDlls | Where-Object {
                    $_.Name -cnotin $allowedVcRuntimeNames -or
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $_.Length -le 0 -or $_.Length -gt 16777216
                }).Count -ne 0) {
                throw "guest preflight Visual C++ runtime boundary is invalid"
            }
            $harnessRoot = Split-Path -Parent $harness
            foreach ($runtimeDll in $vcRuntimeDlls) {
                $runtimeDestination = Join-Path $harnessRoot $runtimeDll.Name
                if (Test-Path -LiteralPath $runtimeDestination) {
                    throw "guest preflight Visual C++ runtime baseline is not absent"
                }
                Copy-Item -LiteralPath $runtimeDll.FullName -Destination $runtimeDestination `
                    -ErrorAction Stop
                if ((Get-FileHash -LiteralPath $runtimeDestination -Algorithm SHA256).Hash `
                        -cne (Get-FileHash -LiteralPath $runtimeDll.FullName -Algorithm SHA256).Hash) {
                    throw "guest preflight Visual C++ runtime copy changed"
                }
            }
            $pathOutput = @(& $powerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $networkPathProbe -SupportIpv4 $SupportAddress `
                -SupportPort $SupportUdp -ManagedAdapterName "Ferrum2Perf" `
                -ExpectedGuestIpv4 $ExpectedGuestAddress `
                -ExpectedInterfaceAlias $ExpectedGuestInterfaceAlias `
                -ExpectedNetwork $ExpectedSupportNetwork `
                -ExpectedPrefixLength $ExpectedSupportPrefixLength `
                -ExpectedMacAddress $ExpectedSupportMacAddress `
                -ExpectedInterfaceGuid $ExpectedSupportInterfaceGuid `
                -ExpectedMtuBytes $ExpectedSupportMtuBytes `
                -MinimumUnderlayIpv4PacketBytes $MinimumSupportIpv4PacketBytes `
                -AsJson 2>&1)
            if ($LASTEXITCODE -ne 0 -or $pathOutput.Count -ne 1) {
                throw "guest network-path preflight returned an invalid result count"
            }
            $path = [string]$pathOutput[0] | ConvertFrom-Json
            $probeOutput = @(& $harness windows-tun-probe `
                --target-ip $SupportAddress --tcp-port $SupportTcp --udp-port $SupportUdp 2>&1)
            $probeExitCode = $LASTEXITCODE
            if ($probeExitCode -ne 0 -or $probeOutput.Count -ne 1 -or
                [string]$probeOutput[0] -cne
                    "windows_tun_probe status=PASS protocols=tcp,udp") {
                $probeDiagnostic = @($probeOutput | Select-Object -First 4 | ForEach-Object {
                    ([string]$_ -replace '[\r\n]+', ' ').Trim()
                }) -join " | "
                if ($probeDiagnostic.Length -gt 2048) {
                    $probeDiagnostic = $probeDiagnostic.Substring(0, 2048)
                }
                if ([string]::IsNullOrWhiteSpace($probeDiagnostic)) {
                    $probeDiagnostic = "<no output>"
                }
                throw "guest support listener direct preflight failed: exit=$probeExitCode output=$probeDiagnostic"
            }
            return ($path | ConvertTo-Json -Compress -Depth 5)
        })
    if ($guestNetworkPathJsonRows.Count -ne 1) {
        throw "guest network-path preflight result is not unique"
    }
    $guestNetworkPathJson = [string]$guestNetworkPathJsonRows[0]
    $guestNetworkPath = $guestNetworkPathJson | ConvertFrom-Json -Depth 5
    $supportHostAfterProbe = Get-HostSupportContext `
        -RepositoryRoot $repositoryRoot `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostAfterProbe
    $vmNetworkAfterProbe = Get-ApprovedVmNetworkContext `
        -TopologyDocument $topologyManifestDocument `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $vmNetworkBaseline -Actual $vmNetworkAfterProbe
    $hostReturnPath = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPath -VmNetworkContext $vmNetworkAfterProbe `
        -ExpectedSupportIpv4 $SupportIpv4
    $networkPathEvidence = [ordered]@{
        schema = 2
        kind = "windows_tun_host_network_path"
        topology = [ordered]@{
            manifest_sha256 = [string]$topologyManifestDocument.Sha256
            plan_sha256 = [string]$topologyPlanDocument.Sha256
            support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
            lab_checkpoint_id = $approvedCheckpointId.ToString("D")
        }
        support_listener = $supportHostAfterProbe
        approved_vm_network = $vmNetworkAfterProbe
        guest_forward_path = $guestNetworkPath
        host_return_path = $hostReturnPath
        guest_probe_sha256 = $guestNetworkPathProbeSha256
        host_helper_sha256 = $hostNetworkPathHelperSha256
        support_path_probe = [ordered]@{
            status = "PASS"
            harness_sha256 = $candidateBuild.HarnessSha256
            minimum_ipv4_packet_bytes = $minimumSupportIpv4PacketBytes
            fragment_payload_bytes = 1440
            fragment_ack_bytes = 24
        }
        host_tun_bypassed = $true
        host_network_mutations = 0
    }
    Write-Utf8FileNew -Path $hostNetworkPathPath `
        -Text (($networkPathEvidence | ConvertTo-Json -Depth 6) + "`n")

    if ($instrumentedDiagnosticMode) {
        $hostEndpointPrePath = Join-Path $hostDiagnosticHostRoot `
            "host-endpoints-pre.json"
        try {
            Write-HostUdpEndpointSnapshot -Path $hostEndpointPrePath `
                -Stage "pre_workload" -SupportProcessId $SupportPid
        } catch {
            $hostEndpointSnapshotFailures.Add("pre: $($_.Exception.Message)")
            Write-HostUdpEndpointErrorSnapshot -Path $hostEndpointPrePath `
                -Stage "pre_workload" -SupportProcessId $SupportPid `
                -Failure $_.Exception.Message
        }
        $hostCaptureState = Start-HostUdpDiagnosticCapture `
            -Directory $hostDiagnosticHostRoot `
            -SupportAddress $SupportIpv4 `
            -FirstUdpPort $SupportUdpPort
    }

    # BEGIN GUEST_ONLY_NETWORK_EXECUTION
    $guestResult = Invoke-Command -Session $session -ErrorAction Stop `
        -FilePath $guestTransactionPath -ArgumentList @(
        $guestRoot,
        $approvedVmName,
        $approvedVmId.ToString("D"),
        $approvedCheckpointName,
        $approvedCheckpointId.ToString("D"),
        [string]$topologyManifestDocument.Sha256,
        [string]$topologyPlanDocument.Sha256,
        $approvedVmSwitchName,
        [string]$topologyManifestDocument.Value.support.switch.switch_id,
        $expectedWintunZipSha256,
        $expectedWintunDllSha256,
        $portableRuntime.PowerShellVersion,
        $portableRuntime.PowerShellExecutableSha256,
        $portableRuntime.PowerShellFileCount,
        $portableRuntime.PowerShellExpandedBytes,
        $RunKind,
        $ParentSha,
        $CandidateSha,
        $parentTree,
        $candidateTree,
        [string]$plan.recipe_sha256,
        [string]$plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256,
        [string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256,
        [string]$performanceControllerBundleManifest.controller_bundle_sha256,
        $guestNetworkPathProbeSha256,
        $guestNetworkPathJson,
        $SupportIpv4,
        $SupportTcpPort,
        $SupportUdpPort,
        $supportGuestIpv4,
        $supportGuestInterfaceAlias,
        $supportNetwork,
        $supportPrefixLength,
        $supportVmMacAddress,
        $supportGuestInterfaceGuid.ToString("D"),
        $supportGuestMtuBytes,
        $SupportPid,
        $SupportOwner,
        $minimumSupportIpv4PacketBytes,
        [string]$canonicalSourcePlan.Ipv4,
        [int]$canonicalSourcePlan.PortFirst,
        [int]$canonicalSourcePlan.PortLast,
        $diagnosticSequenceValue,
        $(if ($instrumentedDiagnosticMode) { $DiagnosticProfile } else { "" }),
        $(if ($instrumentedDiagnosticMode) { $SupportDiagnosticRunNonce } else { "" }),
        $(if ($instrumentedDiagnosticMode) { $SupportDiagnosticMaxEvents } else { 0 }),
        $udpBoundaryCollectorSha256,
        $(if ($instrumentedDiagnosticMode) {
            [string]$diagnosticSourcePlan.Ipv4
        } else { "" }),
        $(if ($instrumentedDiagnosticMode) {
            [int]$diagnosticSourcePlan.PortFirst
        } else { 0 }),
        $(if ($instrumentedDiagnosticMode) {
            [int]$diagnosticSourcePlan.PortLast
        } else { 0 })
    )
    # END GUEST_ONLY_NETWORK_EXECUTION
    if (@($guestResult).Count -ne 1 -or $guestResult.status -cne "PASS" -or
        [int]$guestResult.trials -ne $expectedTrialCount -or
        [int]$guestResult.network_model_observations -ne
            $expectedNetworkModelObservationCount -or
        [int]$guestResult.process_logs -ne $(if ($instrumentedDiagnosticMode) {
            $expectedDiagnosticProcessLogCount
        } else {
            $expectedProcessLogCount
        }) -or
        [string]$guestResult.powershell_version -cne $portableRuntime.PowerShellVersion -or
        [string]$guestResult.powershell_executable_sha256 -cne
            $portableRuntime.PowerShellExecutableSha256) {
        throw "guest performance controller did not return a complete result"
    }
    if ($instrumentedDiagnosticMode -and (
        [string]$guestResult.diagnostic_profile -cne $DiagnosticProfile -or
        [string]$guestResult.diagnostic_evidence_status -cnotin @("COMPLETE", "PARTIAL") -or
        [string]$guestResult.diagnostic_trial_status -cnotin @("PASS", "FAIL")
    )) {
        throw "guest UDP diagnostic controller result is invalid"
    }
    $guestEvidenceAvailable = $true
} catch {
    $runFailure = $_
} finally {
    if ($instrumentedDiagnosticMode) {
        $hostEndpointPostPath = Join-Path $hostDiagnosticHostRoot `
            "host-endpoints-post.json"
        try {
            Write-HostUdpEndpointSnapshot `
                -Path $hostEndpointPostPath `
                -Stage "post_workload" -SupportProcessId $SupportPid
        } catch {
            $hostEndpointSnapshotFailures.Add("post: $($_.Exception.Message)")
            try {
                Write-HostUdpEndpointErrorSnapshot -Path $hostEndpointPostPath `
                    -Stage "post_workload" -SupportProcessId $SupportPid `
                    -Failure $_.Exception.Message
            } catch {
                $hostEndpointSnapshotFailures.Add(
                    "post error document: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $hostCaptureState) {
            try {
                $hostCaptureResult = Complete-HostUdpDiagnosticCapture `
                    -State $hostCaptureState
                if ($hostCaptureResult.Status -cne "PASS") {
                    throw "Pktmon completion failed: $($hostCaptureResult.Failures -join '; ')"
                }
            } catch {
                $hostCaptureFailure = $_
            }
        }
    }
    if ($null -ne $session) {
        $evidenceExportFailure = $null
        try {
            $guestEvidencePath = Join-Path $guestRoot $(if ($instrumentedDiagnosticMode) {
                "udp-diagnostic"
            } else {
                "raw-evidence"
            })
            $guestEvidenceDestination = if ($instrumentedDiagnosticMode) {
                $hostDiagnosticGuestRoot
            } else {
                $hostEvidenceRoot
            }
            $guestProductRoot = Join-Path $guestRoot "input\artifacts"
            $boundary = @(Invoke-Command -Session $session `
                -ArgumentList $guestEvidencePath, $guestProductRoot `
                -ErrorAction Stop -ScriptBlock {
                    param([string]$Path, [string]$ProductRoot)
                    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
                        return [pscustomobject]@{
                            Exists = $false
                            Safe = $false
                            Reason = "missing"
                            OwnedProcesses = 0
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $productPrefix = [IO.Path]::GetFullPath($ProductRoot).
                        TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                    function Get-OwnedProductProcessCount {
                        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
                                ([string]$_.ExecutablePath).StartsWith(
                                    $productPrefix,
                                    [StringComparison]::OrdinalIgnoreCase
                                ) -and
                                [IO.Path]::GetFileName([string]$_.ExecutablePath) -in @(
                                    "ferrum2-client.exe",
                                    "ferrum2-server.exe"
                                )
                            }).Count
                    }
                    $ownedProcessesBefore = Get-OwnedProductProcessCount
                    if ($ownedProcessesBefore -ne 0) {
                        return [pscustomobject]@{
                            Exists = $true
                            Safe = $false
                            Reason = "owned_process_before"
                            OwnedProcesses = $ownedProcessesBefore
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $items = @(Get-Item -LiteralPath $Path -Force -ErrorAction Stop) + @(
                        Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop
                    )
                    $hasReparsePoint = @($items | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0
                    if ($hasReparsePoint) {
                        return [pscustomobject]@{
                            Exists = $true
                            Safe = $false
                            Reason = "reparse_point"
                            OwnedProcesses = 0
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $artifactPaths = @([IO.Directory]::EnumerateFiles(
                        $Path,
                        "*",
                        [IO.SearchOption]::AllDirectories
                    ))
                    $fileLengths = @($artifactPaths | ForEach-Object {
                        [IO.FileInfo]::new([string]$_).Length
                    })
                    $ownedProcessesAfter = Get-OwnedProductProcessCount
                    [pscustomobject]@{
                        Exists = $true
                        Safe = $ownedProcessesAfter -eq 0
                        Reason = if ($ownedProcessesAfter -eq 0) {
                            "safe"
                        } else {
                            "owned_process_after"
                        }
                        OwnedProcesses = $ownedProcessesAfter
                        Files = @(Get-ChildItem -LiteralPath $Path -File -Filter "*.json" `
                            -ErrorAction Stop).Count
                        ModelFiles = @(if (
                            Test-Path -LiteralPath (Join-Path $Path "network-model") `
                                -PathType Container
                        ) {
                            Get-ChildItem -LiteralPath (Join-Path $Path "network-model") `
                                -File -Filter "*.network-model.json" -ErrorAction Stop
                        }).Count
                        TotalFiles = $artifactPaths.Count
                        TotalBytes = [long]($fileLengths | Measure-Object -Sum).Sum
                        LargestFileBytes = [long]($fileLengths | Measure-Object -Maximum).Maximum
                    }
                })
            if ($boundary.Count -ne 1) {
                throw "guest evidence export boundary result is not unique"
            }
            if ($boundary[0].Exists -ne $true) {
                if ($null -eq $runFailure) {
                    throw "guest evidence is absent without a prior run failure"
                }
            } elseif ($boundary[0].Safe -eq $true -and
                [int]$boundary[0].OwnedProcesses -eq 0 -and
                [int]$boundary[0].Files -le $(if ($instrumentedDiagnosticMode) { 8 } else { 108 }) -and
                [int]$boundary[0].ModelFiles -le $(if ($instrumentedDiagnosticMode) { 0 } else { 20 }) -and
                [int]$boundary[0].TotalFiles -le $(if ($instrumentedDiagnosticMode) { 32 } else { 512 }) -and
                [long]$boundary[0].TotalBytes -le $(if ($instrumentedDiagnosticMode) { 335544320 } else { 536870912 }) -and
                [long]$boundary[0].LargestFileBytes -le $(if ($instrumentedDiagnosticMode) { 268451840 } else { 8388608 })) {
                # WinPS 5.1's Copy-Item remoting helper reads Length from the source
                # DirectoryInfo. The guest controller leaves this persistent runspace in
                # strict mode, which turns that helper implementation detail into an error.
                Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    Set-StrictMode -Off
                }
                Copy-Item -FromSession $session -LiteralPath $guestEvidencePath `
                    -Destination $guestEvidenceDestination -Recurse -ErrorAction Stop
            } else {
                throw (
                    "guest evidence export boundary rejected: reason={0} owned={1} " +
                    "json={2} model={3} total_files={4} total_bytes={5} largest={6}"
                ) -f @(
                    [string]$boundary[0].Reason,
                    [int]$boundary[0].OwnedProcesses,
                    [int]$boundary[0].Files,
                    [int]$boundary[0].ModelFiles,
                    [int]$boundary[0].TotalFiles,
                    [long]$boundary[0].TotalBytes,
                    [long]$boundary[0].LargestFileBytes
                )
            }
        } catch {
            $evidenceExportFailure = $_
        }
        if ($null -ne $evidenceExportFailure) {
            if ($null -eq $runFailure) {
                $runFailure = $evidenceExportFailure
            } else {
                $runFailure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($runFailure.Exception.Message); evidence export: " +
                        "$($evidenceExportFailure.Exception.Message) " +
                        "at $($evidenceExportFailure.ScriptStackTrace)"
                    ),
                    "Ferrum2PerformanceEvidenceExport",
                    [Management.Automation.ErrorCategory]::OperationStopped,
                    $hostEvidenceRoot
                )
            }
        }
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        $session = $null
    }
    if ($vmWindowStarted) {
        try {
            [void](Invoke-Ferrum2HostVmLifecycle `
                -Identity $hostHyperVIdentity -Action RestoreFinal `
                -TimeoutSeconds $ShutdownTimeoutSeconds)
        } catch {
            $restoreFailure = $_
        }
    }
    if ((Test-Path -LiteralPath $temporaryRoot -PathType Container) -and
        $temporaryRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($temporaryRoot) -cmatch '^ferrum2-tun-performance-[0-9a-f]{32}$') {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
}
