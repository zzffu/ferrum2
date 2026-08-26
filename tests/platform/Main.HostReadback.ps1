    if ($guestResults.Count -ne 1) {
        throw "guest execution did not return one result"
    }
    $guestResult = $guestResults[0]
    $expectedGuestMode = $requestedMode
    $expectedRestartCycles = if ($null -eq $requestedRestartCycles) {
        $null
    } else { [long]$requestedRestartCycles }
    $expectedNetworkResetCycles = if ($null -eq $requestedNetworkResetCycles) {
        $null
    } else { [long]$requestedNetworkResetCycles }
    $guestResultKeys = @(
        "schema", "status", "profile", "mode", "restart_cycles", "network_reset_cycles",
        "run_token", "candidate_sha", "identity_sha256", "controller_bundle_sha256",
        "staged_input_sha256",
        "topology_manifest_sha256", "guest_network_path_sha256", "topology",
        "guest_network_path",
        "qualification_exit", "cleanup_exit", "fuzz_smoke", "failure_phase", "finished_utc"
    )
    if ((@($guestResult.PSObject.Properties.Name) -join "|") -cne ($guestResultKeys -join "|")) {
        throw "guest qualification result property set is invalid"
    }
    $fuzzSmokeMatches = if ($expectedGuestMode -ceq "fuzz-smoke") {
        $fuzzResultKeys = @(
            "schema", "status", "run_token", "candidate_sha", "identity_sha256", "staged_input_sha256",
            "binary_sha256", "binary_bytes", "packet_seed_count", "udp_reset_seed_count",
            "config_legacy_seed_count", "strict_route_seed_count",
            "terminal", "stdout_sha256", "stderr_sha256", "finished_utc"
        )
        $null -ne $guestResult.fuzz_smoke -and
            (@($guestResult.fuzz_smoke.PSObject.Properties.Name) -join "|") -ceq ($fuzzResultKeys -join "|") -and
            $guestResult.fuzz_smoke.schema -ceq "ferrum2.windows-tun.fuzz-smoke-result.v2" -and
            $guestResult.fuzz_smoke.status -ceq "pass" -and
            $guestResult.fuzz_smoke.run_token -ceq $RunToken -and
            $guestResult.fuzz_smoke.candidate_sha -ceq $candidate.Sha -and
            $guestResult.fuzz_smoke.identity_sha256 -ceq $ledgerIdentity.Sha256 -and
            $guestResult.fuzz_smoke.staged_input_sha256 -ceq $stagedInputSha256 -and
            $guestResult.fuzz_smoke.binary_sha256 -ceq $candidateArtifacts.FuzzSmoke.Sha256 -and
            [long]$guestResult.fuzz_smoke.binary_bytes -eq [long]$candidateArtifacts.FuzzSmoke.Bytes -and
            [long]$guestResult.fuzz_smoke.packet_seed_count -eq 4 -and
            [long]$guestResult.fuzz_smoke.udp_reset_seed_count -eq 3 -and
            [long]$guestResult.fuzz_smoke.config_legacy_seed_count -eq 8 -and
            [long]$guestResult.fuzz_smoke.strict_route_seed_count -eq 8 -and
            $guestResult.fuzz_smoke.terminal -ceq "TUN state smoke corpora: 4 packet, 3 UDP reset, 8 config legacy, and 8 strict-route seeds passed" -and
            [string]$guestResult.fuzz_smoke.stdout_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$guestResult.fuzz_smoke.stderr_sha256 -cmatch '^[0-9a-f]{64}$'
    } else {
        $null -eq $guestResult.fuzz_smoke
    }
    $cleanupExitMatches = if ($expectedGuestMode -ceq "fuzz-smoke") {
        $null -eq $guestResult.cleanup_exit
    } else {
        $null -ne $guestResult.cleanup_exit -and [long]$guestResult.cleanup_exit -eq 0
    }
    $guestTopologyMatches = ($guestResult.topology | ConvertTo-Json -Compress -Depth 5) -ceq
        ($ledgerIdentity.Ledger.topology | ConvertTo-Json -Compress -Depth 5)
    $guestPathMatches = ($guestResult.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
        ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5)
    if ($guestResult.schema -cne "ferrum2.windows-tun.hyperv-guest-run.v5" -or
        $guestResult.profile -cne $Profile -or
        $guestResult.mode -cne $expectedGuestMode -or
        $guestResult.run_token -cne $RunToken -or
        $guestResult.candidate_sha -cne $candidate.Sha -or
        $guestResult.identity_sha256 -cne $ledgerIdentity.Sha256 -or
        $guestResult.controller_bundle_sha256 -cne
            [string]$controllerBundleManifest.controller_bundle_sha256 -or
        $guestResult.staged_input_sha256 -cne $stagedInputSha256 -or
        $guestResult.topology_manifest_sha256 -cne [string]$topologyDocument.Sha256 -or
        $guestResult.guest_network_path_sha256 -cne $guestNetworkPathSha256 -or
        -not $guestTopologyMatches -or -not $guestPathMatches -or
        $null -eq $guestResult.qualification_exit -or [long]$guestResult.qualification_exit -ne 0 -or
        -not $cleanupExitMatches -or -not $fuzzSmokeMatches -or
        $null -ne $guestResult.failure_phase -or
        ($null -eq $expectedRestartCycles -and $null -ne $guestResult.restart_cycles) -or
        ($null -ne $expectedRestartCycles -and
            [long]$guestResult.restart_cycles -ne $expectedRestartCycles) -or
        ($null -eq $expectedNetworkResetCycles -and $null -ne $guestResult.network_reset_cycles) -or
        ($null -ne $expectedNetworkResetCycles -and
            [long]$guestResult.network_reset_cycles -ne $expectedNetworkResetCycles)) {
        throw "guest qualification result binding is invalid"
    }
    if ($guestResult.status -cne "pass") {
        throw "guest qualification failed in phase $($guestResult.failure_phase)"
    }
    $postGuestTopology = Get-ApprovedGuestSupportTopologyRuntimeState `
        -Session $connection.Session -TopologyDocument $topologyDocument
    if (($postGuestTopology | ConvertTo-Json -Compress -Depth 6) -cne
        ($guestSupportTopologyBaseline | ConvertTo-Json -Compress -Depth 6)) {
        throw "approved guest support topology changed during qualification"
    }
    $postPathProbe = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName $guestManagedAdapterName `
        -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument
    $guestNetworkPathPost = $postPathProbe.path
    Assert-ApprovedGuestNetworkPathUnchanged `
        -Expected $guestNetworkPath -Actual $guestNetworkPathPost
    $postTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $postTopologyState
    $postSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $postSupportState
    $null = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPathPost `
        -VmNetworkContext $postTopologyState.VmNetwork `
        -ExpectedSupportIpv4 $supportAddress
