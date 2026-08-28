    if ($guestResults.Count -ne 1) {
        throw "guest execution did not return one result"
    }
    $guestResultJson = [string]$guestResults[0]
    if ($guestResultJson.Length -lt 2 -or $guestResultJson.Length -gt 65536 -or
        $guestResultJson.Contains("`r") -or $guestResultJson.Contains("`n")) {
        throw "guest qualification result framing is invalid"
    }
    $guestResult = $guestResultJson | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $expectedCycleLimit = if ($null -eq $requestedCycleLimit) {
        $null
    } else { [long]$requestedCycleLimit }
    $guestResultKeys = @(
        "schema", "status", "profile", "cycle_limit", "release_milestones",
        "run_token", "candidate_sha", "identity_sha256", "controller_bundle_sha256",
        "staged_input_sha256",
        "topology_manifest_sha256", "guest_network_path_sha256", "topology",
        "guest_network_path",
        "qualification_exit", "cleanup_exit", "failure_phase", "finished_utc"
    )
    if ((@($guestResult.PSObject.Properties.Name) -join "|") -cne ($guestResultKeys -join "|")) {
        throw "guest qualification result property set is invalid"
    }
    $cleanupExitMatches = $null -ne $guestResult.cleanup_exit -and
        [long]$guestResult.cleanup_exit -eq 0
    $guestTopologyMatches = ($guestResult.topology | ConvertTo-Json -Compress -Depth 5) -ceq
        ($ledgerIdentity.Ledger.topology | ConvertTo-Json -Compress -Depth 5)
    $guestPathMatches = ($guestResult.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
        ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5)
    if ($guestResult.schema -cne "ferrum2.windows-tun.hyperv-guest-run.v6" -or
        $guestResult.profile -cne $qualificationProfile -or
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
        -not $cleanupExitMatches -or
        $null -ne $guestResult.failure_phase -or
        ($null -eq $expectedCycleLimit -and $null -ne $guestResult.cycle_limit) -or
        ($null -ne $expectedCycleLimit -and
            [long]$guestResult.cycle_limit -ne $expectedCycleLimit) -or
        (@($guestResult.release_milestones | ForEach-Object { [long]$_ }) -join '|') -cne
            ($requestedReleaseMilestones -join '|')) {
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
