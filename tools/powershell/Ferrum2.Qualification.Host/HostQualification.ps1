Set-StrictMode -Version Latest

$script:QualificationMaximumElapsedSeconds = 900
$script:QualificationWorkerTimeoutSeconds = 840
$script:QualificationBuildTimeoutSeconds = 600

function Get-Ferrum2HostQualificationPlan {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$QualificationSourceBundleSha256,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $family = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    $AddressFamily = $family.address_family
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-plan'
        address_family = $AddressFamily
        execution = 'explicit-authorized-windows-host'
        candidate_sha = $CandidateSha
        qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
        maximum_elapsed_seconds = $script:QualificationMaximumElapsedSeconds
        worker_timeout_seconds = $script:QualificationWorkerTimeoutSeconds
        build_timeout_seconds = $script:QualificationBuildTimeoutSeconds
        checks = @(
            'single-candidate-build',
            'wintun-create-and-delete',
            'system-tcp-and-udp-through-owned-tun',
            'narrow-route-isolation',
            'exact-tcp-ingress-wfp-live-readback',
            'network-reset-retains-strict-route-and-replaces-tcp-ingress-epoch',
            'forced-process-tree-recovery',
            'zero-residue-cleanup'
        )
        data_path_workload = [pscustomobject][ordered]@{
            concurrent_tcp_flows_per_generation = 4
            generations = 2
            checked_bulk_bytes_per_flow = 8388608
            phases = @('request_before', 'paused_reader', 'full_duplex', 'request_after', 'half_close')
            udp_and_fragment_replies_during_tcp_per_flow = 4
            fragment_request_bytes = 4096
            tun_mtu_bytes = 1420
            reset_contract = 'old TCP retires by EOF/reset; same UDP tuple checks new tagged reply separately from buffered old replies; reconnect TCP with new payload identity'
            workload_timeout_seconds = 60
            performance_adoption_thresholds = $false
        }
        safety = [pscustomobject][ordered]@{
            requires_elevation = $true
            requires_explicit_acknowledgement = $true
            automatic_elevation = $false
            live_address_family = if ($AddressFamily -ceq 'IPv4') { 'IPv4 only (RFC2544 198.18.0.0/15)' } else { 'IPv6 only (run-owned ULA)' }
            route_scope = if ($AddressFamily -ceq 'IPv4') { 'run-owned /32 only' } else { 'run-owned /128 routes; /126 connected route on owned TUN only' }
            tun_connected_prefix_length = $family.tun_prefix_length
            tcp_ingress_scope = 'exact app, TCP, TUN LUID, local address/port, and remote peer'
            wfp_lifetime = 'process-owned dynamic sessions only'
            tcp_ingress_installation = 'automatic after listener bind and before admission'
            firewall_rule_store = 'PersistentStore with exact ActiveStore readback'
            firewall_rule_lifetime = 'removed by finally/recovery; catastrophic interruption may retain rules until recovery'
            firewall_rule_scope = "current executable path/hash; exact $AddressFamily endpoints; fixed service ports or observed dynamic-port range; all profiles"
            firewall_interface_transition = 'client ingress only: prelaunch deferred interface, then same rule narrowed to owned TUN alias after identity/MTU readback and before traffic; all other rules exact interface throughout'
            mutations = @(
                'one run-owned Wintun adapter at a time',
                "run-owned $AddressFamily loopback support address",
                'run-owned narrow routes',
                'process-owned dynamic strict-route WFP session',
                'process-owned dynamic exact TCP ingress WFP session',
                'run-owned narrowly scoped Windows Firewall rules before executable launch'
            )
            forbidden_mutations = @(
                'default route', 'system DNS', 'physical adapters', 'WLAN',
                'unrelated Windows Firewall rules', 'global firewall profile/notification settings', 'unrelated WFP sessions',
                'sing-box', 'unrelated resources'
            )
            recovery = '%PROGRAMDATA%/Ferrum2HostPerformance-v2/<RunId>/recovery.json'
        }
    }
}

function Initialize-Ferrum2QualificationCandidate {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$CandidateSha
    )
    [void](Resolve-Ferrum2CommitSha -RepositoryRoot $Context.repository_root -Sha $CandidateSha)
    $assetRoot = Join-Path $Context.run_root 'assets'
    New-Item -ItemType Directory -Path $assetRoot -ErrorAction Stop | Out-Null
    $archive = Resolve-Ferrum2WintunArchive
    $dll = Join-Path $assetRoot 'wintun.dll'
    $dllHash = Expand-Ferrum2WintunDll -Archive $archive -Destination $dll

    $memberRoot = Join-Path $Context.run_root 'builds\candidate'
    $sourceRoot = Join-Path $memberRoot 'source'
    $targetRoot = Join-Path $memberRoot 'target'
    Export-Ferrum2CommitTree -RepositoryRoot $Context.repository_root `
        -Sha $CandidateSha -Destination $sourceRoot
    $m4SourceBundleSha256 = Get-Ferrum2M4SourceBundleIdentity -SourceRoot $sourceRoot
    $cargo = [string](Get-Command cargo -CommandType Application -ErrorAction Stop).Source
    $arguments = "build --release --locked --offline --target $script:WindowsRustTarget " +
        "--target-dir `"$targetRoot`" -p ferrum2-client -p ferrum2-server " +
        '-p ferrum2-m4-qualification'
    [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $cargo `
        -Arguments $arguments -WorkingDirectory $sourceRoot `
        -LogPrefix 'cargo-qualification' -TimeoutSeconds $script:QualificationBuildTimeoutSeconds)

    $binaryRoot = Join-Path $targetRoot "$($script:WindowsRustTarget)\release"
    $client = Join-Path $binaryRoot 'ferrum2-client.exe'
    $server = Join-Path $binaryRoot 'ferrum2-server.exe'
    $harness = Join-Path $binaryRoot 'm4-qualification.exe'
    foreach ($path in @($client, $server, $harness)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "host qualification build output is missing: $path"
        }
    }
    $dllTarget = Join-Path $binaryRoot 'wintun.dll'
    Copy-Item -LiteralPath $dll -Destination $dllTarget -ErrorAction Stop
    $candidate = [pscustomobject][ordered]@{
        commit_sha = $CandidateSha
        root = $memberRoot
        client = $client
        server = $server
        harness = $harness
        client_sha256 = (Get-FileHash $client -Algorithm SHA256).Hash.ToLowerInvariant()
        server_sha256 = (Get-FileHash $server -Algorithm SHA256).Hash.ToLowerInvariant()
        harness_sha256 = (Get-FileHash $harness -Algorithm SHA256).Hash.ToLowerInvariant()
        m4_source_bundle_sha256 = $m4SourceBundleSha256
        wintun_archive_sha256 = $script:ExpectedWintunZipSha256
        wintun_dll_sha256 = $dllHash
    }
    $manifest = [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-build'
        address_family = $Context.address_family
        run_id = $Context.run_id
        qualification_source_bundle_sha256 = $Context.qualification_source_bundle_sha256
        candidate = $candidate
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory 'build.json') `
        -Document $manifest
    return $candidate
}

function Get-Ferrum2QualificationMetricLabelValue {
    param(
        [Parameter(Mandatory = $true)][string]$Metrics,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Value,
        [switch]$AllowAbsent
    )
    $pattern = '(?m)^' + [regex]::Escape($Name) +
        '\{[^}\r\n]*' + [regex]::Escape($Label) + '="' +
        [regex]::Escape($Value) + '"[^}\r\n]*\}\s+([0-9]+(?:\.[0-9]+)?)$'
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0) {
        if ($AllowAbsent) { return [double]0 }
        throw "required labeled metric is absent: $Name/$Label=$Value"
    }
    [double]$sum = 0
    foreach ($match in $matches) {
        $sum += [double]::Parse(
            $match.Groups[1].Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    return $sum
}


function Initialize-Ferrum2QualificationResetRoute {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Network
    )
    $family = Get-Ferrum2AddressFamilyProfile -AddressFamily $Network.address_family
    $address = [string]$Network.reset_address
    $prefix = "$address/$($family.host_prefix_length)"
    $parsed = [Net.IPAddress]::Parse($address)
    if ($parsed.AddressFamily -ne $family.socket_family -or
        $parsed.IsIPv6Multicast -or [Net.IPAddress]::IsLoopback($parsed)) {
        throw 'qualification reset probe family or unicast identity is invalid'
    }
    $inventory = Get-Ferrum2NetworkInventory -AddressFamily $family.address_family
    if (@($inventory.routes | Where-Object DestinationPrefix -CEQ $prefix).Count -ne 0 -or
        @($inventory.addresses | Where-Object IPAddress -CEQ $address).Count -ne 0) {
        throw 'qualification reset probe route/address baseline must be absent'
    }
    $selected = $null
    if ($family.address_family -ceq 'IPv6') {
        # The unused fixed egress probe tracks this exact route fingerprint. Changing
        # its metric exercises semantic reset without a public IPv6 gateway or traffic.
        $loopback = Get-Ferrum2LoopbackIdentity -AddressFamily IPv6
        $selected = [pscustomobject]@{
            InterfaceIndex = $loopback.interface_index
            NextHop = $family.unspecified_address
        }
    } else {
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object { [string]$_.Status -ceq 'Up' } | Sort-Object ifIndex)
        if ($adapters.Count -gt 4096) {
            throw 'qualification physical interface inventory exceeds its bound'
        }
        foreach ($adapter in $adapters) {
            try {
                $rows = @(Find-NetRoute -RemoteIPAddress $address `
                    -InterfaceIndex ([uint32]$adapter.ifIndex) -ErrorAction Stop)
            } catch {
                continue
            }
            $routes = @($rows | Where-Object { $_.CimClass.CimClassName -ceq 'MSFT_NetRoute' })
            if ($routes.Count -eq 1 -and
                [uint32]$routes[0].InterfaceIndex -eq [uint32]$adapter.ifIndex -and
                [string]$routes[0].NextHop -cne $family.unspecified_address) {
                $selected = $routes[0]
                break
            }
        }
        if ($null -eq $selected) {
            throw 'qualification reset needs a readable active hardware IPv4 gateway route'
        }
    }
    # Only two successive exact host routes are owned. No existing route, physical
    # interface setting, DNS or WLAN state is changed; no probe socket is opened.
    $ownedRoute = Add-Ferrum2OwnedRoute -Context $Context `
        -InterfaceIndex ([uint32]$selected.InterfaceIndex) -DestinationPrefix $prefix `
        -NextHop ([string]$selected.NextHop) -RouteMetric 4094 `
        -Kind 'qualification-reset-baseline'
    $proof = Get-Ferrum2RouteProof -RemoteAddress $address `
        -ExpectedInterfaceIndex ([uint32]$selected.InterfaceIndex) `
        -Purpose 'qualification-reset-baseline'
    if ($proof.destination_prefix -cne $prefix -or
        $proof.next_hop -cne [string]$selected.NextHop -or $proof.route_metric -ne 4094) {
        throw 'qualification reset baseline did not select its exact owned route'
    }
    return [pscustomobject]@{
        address = $address
        prefix = $prefix
        endpoint = [Net.IPEndPoint]::new($parsed, 9)
        interface_index = [uint32]$selected.InterfaceIndex
        before = $proof
        owned_route = $ownedRoute
    }
}

function Invoke-Ferrum2HostQualificationChecks {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    $family = Get-Ferrum2AddressFamilyProfile -AddressFamily $Network.address_family
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Candidate.harness `
        -Network $Network -Loopback $Loopback
    $checks = [Collections.Generic.List[object]]::new()
    $checks.Add([pscustomobject][ordered]@{
        name = 'single-candidate-build'; status = 'PASS'
    })
    $routeProofs = $null
    $wfpBefore = $null
    $wfpAfter = $null
    $resetEpoch = $null
    $notificationWitness = $null
    $wfpAbsence = [Collections.Generic.List[object]]::new()
    [void]$wfpAbsence.Add(
        (Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'baseline')
    )

    $createRuntime = Start-Ferrum2HostProduct -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 1
    try {
        $createWfp = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
            -Runtime $createRuntime -Network $Network -ExecutablePath $Candidate.client `
            -Label 'create-live'
    } finally {
        Stop-Ferrum2HostProduct -Context $Context -Runtime $createRuntime
    }
    [void]$wfpAbsence.Add(
        (Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'create-cleanup')
    )
    $checks.Add([pscustomobject][ordered]@{
        name = 'wintun-create-and-delete'; status = 'PASS'
    })

    $resetRoute = Initialize-Ferrum2QualificationResetRoute -Context $Context -Network $Network
    $smokeRuntime = Start-Ferrum2HostProduct -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 2 `
        -ResetProbeEndpoint $resetRoute.endpoint
    try {
        $metricsBefore = Get-Ferrum2Metrics -Port $smokeRuntime.client_metrics_port -AddressFamily $family.address_family
        Write-NewUtf8File -Path (Join-Path $Context.evidence_directory `
            'qualification-client-metrics-before.txt') -Text $metricsBefore
        Write-NewUtf8File -Path (Join-Path $Context.evidence_directory `
            'qualification-server-metrics-before.txt') `
            -Text (Get-Ferrum2Metrics -Port $smokeRuntime.server_metrics_port -AddressFamily $family.address_family)
        $generationBefore = Get-Ferrum2MetricValue $metricsBefore `
            'ferrum2_tun_session_generation'
        if ((Get-Ferrum2MetricValue $metricsBefore 'ferrum2_tun_strict_route_requested') -ne 1 -or
            (Get-Ferrum2MetricValue $metricsBefore 'ferrum2_tun_strict_route_effective') -ne 1 -or
            $generationBefore -lt 1 -or
            (Get-Ferrum2QualificationMetricLabelValue $metricsBefore `
                'ferrum2_tun_strict_route_filter_install_total' 'result' 'success') -lt 1 -or
            (Get-Ferrum2QualificationMetricLabelValue $metricsBefore `
                'ferrum2_tun_strict_route_filter_install_total' 'result' 'failure' -AllowAbsent) -ne 0) {
            throw 'host qualification strict-route or session-generation metrics are invalid'
        }
        $wfpBefore = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
            -Runtime $smokeRuntime -Network $Network -ExecutablePath $Candidate.client `
            -Label 'before-network-reset'
        $workloadReady = Join-Path $Context.run_root 'qualification-reset-ready.json'
        $workloadRelease = Join-Path $Context.run_root 'qualification-reset-release.json'
        $workloadOutput = Join-Path $Context.evidence_directory 'qualification-workload.json'
        $udpRanges = @($smokeRuntime.dynamic_ranges | Where-Object { $_.protocol -ceq 'udp' })
        if ($udpRanges.Count -ne 1) { throw 'qualification UDP dynamic port identity is unavailable' }
        [void](Add-Ferrum2OwnedFirewallRule -Context $Context -Executable $Candidate.harness `
            -Protocol UDP -LocalAddress $Network.tun_address `
            -LocalPort "$($udpRanges[0].start_port)-$($udpRanges[0].end_port)" `
            -RemoteAddress $Network.support_address -RemotePort ([string]$support.udp_port) `
            -InterfaceAlias $smokeRuntime.adapter_name -Purpose 'workload-udp-replies')
        $workloadArguments = "windows-tun-qualification --address-family $($family.address_family) --target-ip $($Network.support_address) " +
            "--tcp-port $($support.tcp_port) --udp-port $($support.udp_port) " +
            "--reset-ready-file `"$workloadReady`" --reset-release-file `"$workloadRelease`" " +
            "--output `"$workloadOutput`""
        $workloadTimer = [Diagnostics.Stopwatch]::StartNew()
        $workload = Start-Ferrum2OwnedNativeProcess -Context $Context `
            -Application $Candidate.harness -Arguments $workloadArguments `
            -WorkingDirectory (Split-Path -Parent $Candidate.harness) `
            -LogPrefix 'qualification-workload' -Purpose 'qualification-workload'
        while (-not (Test-Path -LiteralPath $workloadReady -PathType Leaf)) {
            if ($workloadTimer.Elapsed.TotalSeconds -ge 20 -or
                [Ferrum2HostProcessGroup]::Wait([uint32]$workload.pid, 0)) {
                if (Test-Path -LiteralPath $workloadOutput -PathType Leaf) {
                    $failedWorkload = Read-Ferrum2QualificationWorkloadJson -Path $workloadOutput
                    if ($failedWorkload.status -ceq 'FAIL') {
                        throw "qualification workload failed: $($failedWorkload.error)"
                    }
                }
                throw 'qualification workload did not establish active reset work before deadline'
            }
            Start-Sleep -Milliseconds 50
        }
        $ready = Read-Ferrum2QualificationWorkloadJson -Path $workloadReady
        Assert-Ferrum2QualificationResetReady -Witness $ready -AddressFamily $family.address_family
        $routeProofs = @($smokeRuntime.route_proofs)
        $notificationAddress = $resetRoute.address
        $routeNotification = [Ferrum2QualificationRouteNotification]::new($family.address_family)
        try {
            Remove-Ferrum2OwnedRoute -Row $resetRoute.owned_route
            $Context.ledger.resources.routes = @($Context.ledger.resources.routes | Where-Object {
                -not ([string]$_.destination_prefix -ceq [string]$resetRoute.owned_route.destination_prefix -and
                    [uint32]$_.interface_index -eq [uint32]$resetRoute.owned_route.interface_index -and
                    [string]$_.next_hop -ceq [string]$resetRoute.owned_route.next_hop -and
                    [uint16]$_.route_metric -eq [uint16]$resetRoute.owned_route.route_metric)
            })
            Write-Ferrum2HostLedger -Context $Context
            [void](Add-Ferrum2OwnedRoute -Context $Context `
                -InterfaceIndex $resetRoute.interface_index `
                -DestinationPrefix $resetRoute.prefix -RouteMetric 4093 `
                -Kind 'qualification-reset-change' -NextHop $family.unspecified_address)
            if (-not $routeNotification.Wait(10000)) {
                throw 'host qualification did not observe the run-owned route notification'
            }
        } finally {
            $routeNotification.Dispose()
        }
        $metricsAfter = Wait-Ferrum2Metric -Process $smokeRuntime.client `
            -Port $smokeRuntime.client_metrics_port -Name 'ferrum2_tun_session_generation' `
            -Minimum ($generationBefore + 1) -TimeoutSeconds 30 -AddressFamily $family.address_family
        $resetRouteAfter = Get-Ferrum2RouteProof -RemoteAddress $notificationAddress `
            -ExpectedInterfaceIndex $resetRoute.interface_index `
            -Purpose 'qualification-reset-change'
        if ($resetRouteAfter.destination_prefix -cne $resetRoute.prefix -or
            $resetRouteAfter.next_hop -cne $family.unspecified_address -or
            $resetRouteAfter.route_metric -ne 4093) {
            throw 'qualification reset did not select its second exact owned route'
        }
        $generationAfter = Get-Ferrum2MetricValue $metricsAfter `
            'ferrum2_tun_session_generation'
        if ((Get-Ferrum2MetricValue $metricsAfter `
                'ferrum2_tun_strict_route_effective') -ne 1) {
            throw 'host qualification network reset did not preserve strict-route state'
        }
        $wfpAfter = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
            -Runtime $smokeRuntime -Network $Network -ExecutablePath $Candidate.client `
            -Label 'after-network-reset'
        if ($wfpAfter.strict_route.sublayer_weight -cne
                $wfpBefore.strict_route.sublayer_weight -or
            (@($wfpAfter.strict_route.filters.id) -join '|') -cne
                (@($wfpBefore.strict_route.filters.id) -join '|')) {
            throw 'host qualification network reset replaced strict-route WFP identity'
        }
        $resetEpoch = Compare-Ferrum2QualificationTcpIngressEpoch `
            -Before $wfpBefore.tcp_ingress -After $wfpAfter.tcp_ingress
        $notificationWitness = [pscustomobject][ordered]@{
            source = 'NotifyRouteChange2'
            observed = $true
            address_family = $family.address_family
            destination_prefix = $resetRoute.prefix
            route_before = $resetRoute.before
            route_after = $resetRouteAfter
            session_generation_before = [uint64]$generationBefore
            session_generation_after = [uint64]$generationAfter
            tun_mtu_bytes = $smokeRuntime.mtu_bytes
            active_work_ready = $ready
            workload_generation_before = 1
            workload_generation_after = 2
        }
        Write-AtomicJsonFile -Path $workloadRelease -Document ([pscustomobject]@{
            schema_version = 1
            kind = 'ferrum2.windows-tun-reset-release'
            address_family = $family.address_family
            generation = 2
        })
        $remainingSeconds = [int][Math]::Floor(60 - $workloadTimer.Elapsed.TotalSeconds)
        if ($remainingSeconds -le 0) { throw 'qualification workload exceeded its deadline' }
        [void](Complete-Ferrum2OwnedCommand -Context $Context -Process $workload `
            -LogPrefix 'qualification-workload' -TimeoutSeconds $remainingSeconds)
        $workloadWitness = Read-Ferrum2QualificationWorkloadJson -Path $workloadOutput
        Assert-Ferrum2QualificationWorkloadWitness -Witness $workloadWitness -AddressFamily $family.address_family
        $workloadTimer.Stop()
    } catch {
        $failure = $_
        Export-Ferrum2ProductFailureLogs -Context $Context -Client $smokeRuntime.client `
            -Server $smokeRuntime.server -Sequence 2
        foreach ($endpoint in @(
            @{ name = 'client'; port = $smokeRuntime.client_metrics_port },
            @{ name = 'server'; port = $smokeRuntime.server_metrics_port }
        )) {
            try {
                Write-NewUtf8File -Path (Join-Path $Context.evidence_directory `
                    "qualification-$($endpoint.name)-metrics-failure.txt") `
                    -Text (Get-Ferrum2Metrics -Port $endpoint.port -AddressFamily $family.address_family)
            } catch { Write-Warning 'qualification failure metrics unavailable' }
        }
        throw $failure
    } finally {
        Stop-Ferrum2HostProduct -Context $Context -Runtime $smokeRuntime
    }
    [void]$wfpAbsence.Add(
        (Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'smoke-cleanup')
    )
    foreach ($name in @(
        'system-tcp-and-udp-through-owned-tun',
        'narrow-route-isolation',
        'exact-tcp-ingress-wfp-live-readback',
        'network-reset-retains-strict-route-and-replaces-tcp-ingress-epoch'
    )) {
        $checks.Add([pscustomobject][ordered]@{ name = $name; status = 'PASS' })
    }

    $faultRuntime = Start-Ferrum2HostProduct -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 3
    $faultWfp = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
        -Runtime $faultRuntime -Network $Network -ExecutablePath $Candidate.client `
        -Label 'before-forced-close'
    [Ferrum2HostProcessGroup]::CloseGroup()
    Start-Sleep -Milliseconds 500
    $addressRows = @($Context.ledger.resources.addresses)
    if ($addressRows.Count -ne 1) {
        throw 'host qualification expected one owned support address'
    }
    $originalAddressState = [string]$addressRows[0].state
    $plannedAddressRefused = $false
    try {
        $addressRows[0].state = 'planned'
        $Context.ledger.state = 'recovery_required'
        Write-Ferrum2HostLedger -Context $Context
        [void](Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path)
    } catch {
        if ([string]$_.Exception.Message -cne
            'planned address presence is ambiguous; refusing removal') {
            throw
        }
        $plannedAddressRefused = $true
    } finally {
        $addressRows[0].state = $originalAddressState
        Write-Ferrum2HostLedger -Context $Context
    }
    if (-not $plannedAddressRefused) {
        throw 'host qualification recovery accepted ambiguous planned address ownership'
    }
    [void](Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path)
    [void]$wfpAbsence.Add(
        (Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'forced-close-cleanup')
    )
    $checks.Add([pscustomobject][ordered]@{
        name = 'forced-process-tree-recovery'; status = 'PASS'
    })

    if ($null -ne $Context.ledger.resources.adapter -or
        @($Context.ledger.resources.routes).Count -ne 0 -or
        @($Context.ledger.resources.addresses).Count -ne 0 -or
        @($Context.ledger.resources.processes).Count -ne 0 -or
        @($Context.ledger.resources.ports).Count -ne 0 -or
        @($Context.ledger.resources.firewall_rules).Count -ne 0) {
        throw 'host qualification retained a ledger-owned resource'
    }
    $checks.Add([pscustomobject][ordered]@{
        name = 'zero-residue-cleanup'; status = 'PASS'
    })
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-checks'
        address_family = $family.address_family
        run_id = $Context.run_id
        candidate_sha = $Candidate.commit_sha
        checks = $checks.ToArray()
        route_proofs = $routeProofs
        data_path = $workloadWitness
        firewall_rules = @($Context.ledger.expected_resources.firewall_rules)
        strict_route_wfp = [pscustomobject][ordered]@{
            notification = $notificationWitness
            before_network_reset = $wfpBefore.strict_route
            after_network_reset = $wfpAfter.strict_route
        }
        tcp_ingress_wfp = [pscustomobject][ordered]@{
            normal_start = $createWfp.tcp_ingress
            before_network_reset = $wfpBefore.tcp_ingress
            after_network_reset = $wfpAfter.tcp_ingress
            reset_epoch = $resetEpoch
            before_forced_close = $faultWfp.tcp_ingress
            absence = $wfpAbsence.ToArray()
        }
        status = 'PASS'
    }
}

function Invoke-Ferrum2HostQualification {
    [CmdletBinding(DefaultParameterSetName = 'Run')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
        [switch]$PlanOnly,
        [Parameter(Mandatory = $true, ParameterSetName = 'Recovery')]
        [switch]$RecoveryOnly,
        [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
        [string]$EvidenceDirectory,
        [Parameter(ParameterSetName = 'Plan')]
        [Parameter(ParameterSetName = 'Run')]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$AddressFamily = 'IPv4',
        [Parameter(ParameterSetName = 'Run')]
        [switch]$AcknowledgeHostNetworkMutation,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$QualificationSourceBundleSha256,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )
    $bundle = Read-Ferrum2HostQualificationSourceBundle `
        -RepositoryRoot $RepositoryRoot `
        -ManifestPath (Join-Path $RepositoryRoot `
            'tools\powershell\Ferrum2.Qualification.Host\bundle.json')
    if ($bundle.sha256 -cne $QualificationSourceBundleSha256) {
        throw 'host qualification source bundle identity changed'
    }
    if ($PlanOnly) {
        [void](Resolve-Ferrum2CommitSha -RepositoryRoot $RepositoryRoot -Sha $CandidateSha)
        return Get-Ferrum2HostQualificationPlan -CandidateSha $CandidateSha `
            -QualificationSourceBundleSha256 $QualificationSourceBundleSha256 -AddressFamily $AddressFamily
    }
    $mutex = $null
    if ($RecoveryOnly) {
        try {
            $mutex = Enter-Ferrum2HostMutex
            return Invoke-Ferrum2HostRecovery
        } finally {
            Exit-Ferrum2HostMutex -Mutex $mutex
        }
    }
    $AddressFamily = (Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily).address_family
    if (-not (Test-Ferrum2HostAdministrator)) {
        throw 'host qualification requires an already elevated PowerShell process'
    }
    if (-not $AcknowledgeHostNetworkMutation) {
        throw 'host qualification requires -AcknowledgeHostNetworkMutation'
    }

    $context = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $buildSeconds = 0.0
    $executionSeconds = 0.0
    $succeeded = $false
    $primaryFailure = $null
    $cleanupFailure = $null
    $checks = $null
    try {
        $mutex = Enter-Ferrum2HostMutex
        Assert-NoPendingFerrum2HostRecovery
        $context = New-Ferrum2HostContext -RepositoryRoot $RepositoryRoot `
            -EvidenceDirectory $EvidenceDirectory `
            -CandidateSha $CandidateSha `
            -QualificationSourceBundleSha256 $QualificationSourceBundleSha256 -AddressFamily $AddressFamily
        $plan = Get-Ferrum2HostQualificationPlan -CandidateSha $CandidateSha `
            -QualificationSourceBundleSha256 $QualificationSourceBundleSha256 -AddressFamily $AddressFamily
        Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory 'plan.json') `
            -Document $plan
        $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        if ((@($firewallProfiles | ForEach-Object { [string]$_.Name } | Sort-Object) -join '|') -cne
                'Domain|Private|Public' -or
            @($firewallProfiles | Where-Object {
                [string]$_.Enabled -cne 'True' -or
                [string]$_.AllowLocalFirewallRules -cne 'True' -or
                [string]$_.AllowInboundRules -cne 'True'
            }).Count -ne 0) {
            throw 'qualification requires enabled profiles accepting local inbound rules; no profile settings will be changed'
        }
        Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory 'firewall-profiles.json') `
            -Document @($firewallProfiles | Select-Object Name, Enabled, AllowLocalFirewallRules,
                AllowInboundRules, NotifyOnListen)
        $network = New-Ferrum2HostNetworkIdentity -RunId $context.run_id -AddressFamily $AddressFamily
        $loopback = Get-Ferrum2LoopbackIdentity -AddressFamily $AddressFamily
        Assert-Ferrum2HostNetworkIdentityAvailable -Network $network -Loopback $loopback
        Set-Ferrum2HostState -Context $context -State 'building'
        $buildTimer = [Diagnostics.Stopwatch]::StartNew()
        $candidate = Initialize-Ferrum2QualificationCandidate -Context $context `
            -CandidateSha $CandidateSha
        $buildTimer.Stop()
        $buildSeconds = $buildTimer.Elapsed.TotalSeconds
        Set-Ferrum2HostState -Context $context -State 'executing'
        $executionTimer = [Diagnostics.Stopwatch]::StartNew()
        $checks = Invoke-Ferrum2HostQualificationChecks -Context $context `
            -Candidate $candidate -Network $network -Loopback $loopback
        $executionTimer.Stop()
        $executionSeconds = $executionTimer.Elapsed.TotalSeconds
        $succeeded = $true
    } catch {
        $primaryFailure = $_
    } finally {
        if ($null -ne $context) {
            try {
                $cleanupTimer = [Diagnostics.Stopwatch]::StartNew()
                $cleanup = Complete-Ferrum2HostCleanup -Context $context `
                    -Succeeded $succeeded
                $inspectionRoot = Join-Path $context.evidence_directory `
                    'final-cleanup-inspection'
                if (Test-Path -LiteralPath $inspectionRoot) {
                    throw 'host qualification final inspection baseline must be absent'
                }
                New-Item -ItemType Directory -Path $inspectionRoot `
                    -ErrorAction Stop | Out-Null
                $inspectionContext = [pscustomobject]@{
                    address_family = $context.address_family
                    run_id = $context.run_id
                    run_root = $inspectionRoot
                    ledger_path = Join-Path $inspectionRoot 'recovery.json'
                    repository_root = $context.repository_root
                    evidence_directory = $context.evidence_directory
                    qualification_source_bundle_sha256 =
                        $context.qualification_source_bundle_sha256
                    ledger = $context.ledger
                }
                try {
                    $finalWfp = Assert-Ferrum2QualificationWfpAbsent `
                        -Context $inspectionContext -Label 'final-cleanup'
                } finally {
                    [Ferrum2HostProcessGroup]::CloseGroup()
                }
                $cleanupTimer.Stop()
                $qualificationCleanup = [pscustomobject][ordered]@{
                    schema_version = 1
                    kind = 'ferrum2.windows-tun.host-qualification-cleanup'
                    address_family = $AddressFamily
                    run_id = $context.run_id
                    qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
                    status = [string]$cleanup.status
                    adapter_remaining = [int]$cleanup.adapter_remaining
                    routes_remaining = [int]$cleanup.routes_remaining
                    addresses_remaining = [int]$cleanup.addresses_remaining
                    processes_remaining = [int]$cleanup.processes_remaining
                    ports_remaining = [int]$cleanup.ports_remaining
                    firewall_rule_remaining = [int]$cleanup.firewall_rule_remaining
                    strict_route_wfp_remaining = [int]$finalWfp.strict_route_objects
                    tcp_ingress_wfp_remaining = [int]$finalWfp.tcp_ingress_objects
                    elapsed_seconds = $cleanupTimer.Elapsed.TotalSeconds
                }
                Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory `
                    'qualification-cleanup.json') -Document $qualificationCleanup
            } catch {
                $cleanupFailure = $_
            }
        }
        $timer.Stop()
        if ($null -ne $context) {
            $runtime = [pscustomobject][ordered]@{
                schema_version = 1
                kind = 'ferrum2.windows-tun.host-qualification-runtime'
                address_family = $AddressFamily
                run_id = $context.run_id
                candidate_sha = $CandidateSha
                qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
                maximum_elapsed_seconds = $script:QualificationMaximumElapsedSeconds
                worker_timeout_seconds = $script:QualificationWorkerTimeoutSeconds
                build_seconds = $buildSeconds
                execution_seconds = $executionSeconds
                elapsed_seconds = $timer.Elapsed.TotalSeconds
            }
            Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory 'runtime.json') `
                -Document $runtime
        }
        Exit-Ferrum2HostMutex -Mutex $mutex
    }
    if ($null -ne $primaryFailure) { throw $primaryFailure }
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    if (-not $succeeded -or $null -eq $checks -or
        $timer.Elapsed.TotalSeconds -ge $script:QualificationWorkerTimeoutSeconds) {
        throw 'host qualification did not finish inside its worker deadline'
    }
    $workerResult = [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-worker'
        address_family = $AddressFamily
        status = 'PASS'
        qualification = $true
        run_id = $context.run_id
        candidate_sha = $CandidateSha
        qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
        elapsed_seconds = $timer.Elapsed.TotalSeconds
        checks = @($checks.checks)
        route_proofs = @($checks.route_proofs)
        strict_route_wfp = $checks.strict_route_wfp
        tcp_ingress_wfp = $checks.tcp_ingress_wfp
        data_path = $checks.data_path
        firewall_rules = @($checks.firewall_rules)
    }
    Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory `
        'qualification-worker.json') -Document $workerResult
    return $workerResult
}
