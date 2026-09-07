Set-StrictMode -Version Latest

$script:QualificationMaximumElapsedSeconds = 900
$script:QualificationWorkerTimeoutSeconds = 840
$script:QualificationBuildTimeoutSeconds = 600
$script:BaseWriteFerrum2TrialConfigs = ${function:Write-Ferrum2TrialConfigs}

function Write-Ferrum2TrialConfigs {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][string]$AdapterName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("EndToEnd")]
        [string]$Topology,
        [Parameter(Mandatory = $true)][uint16]$ServerPort,
        [Parameter(Mandatory = $true)][uint16]$ClientMetricsPort,
        [Parameter(Mandatory = $true)][uint16]$ServerMetricsPort,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [AllowNull()][Net.IPEndPoint]$ResetProbeEndpoint = $null
    )
    $configs = & $script:BaseWriteFerrum2TrialConfigs `
        -Context $Context -Network $Network -Loopback $Loopback `
        -AdapterName $AdapterName -Topology $Topology -ServerPort $ServerPort `
        -ClientMetricsPort $ClientMetricsPort -ServerMetricsPort $ServerMetricsPort `
        -Sequence $Sequence
    $text = [IO.File]::ReadAllText([string]$configs.client)
    $matches = [regex]::Matches($text, '(?m)^auto_route = true\r?$')
    if ($matches.Count -ne 1) {
        throw 'qualification client config has no unique automatic-route setting'
    }
    $text = [regex]::Replace(
        $text,
        '(?m)^auto_route = true\r?$',
        "auto_route = true`r`nstrict_route = true",
        1
    )
    if ($null -ne $ResetProbeEndpoint) {
        if ([regex]::Matches($text, '(?m)^final = "proxy"\r?$').Count -ne 1) {
            throw 'qualification reset config has no unique proxy route'
        }
        $text = [regex]::Replace(
            $text, '(?m)^final = "proxy"\r?$', 'final = "qualification-route"', 1
        )
        # The selector keeps both first hops in the underlay snapshot, but always uses the
        # existing proxy. The reset endpoint receives no qualification traffic.
        $text += @"

[[outbounds]]
tag = "qualification-reset-probe"
type = "shadowsocks"
server = "$ResetProbeEndpoint"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[selectors]]
tag = "qualification-route"
outbounds = ["proxy", "qualification-reset-probe"]
default = "proxy"
"@
    }
    [IO.File]::WriteAllText([string]$configs.client, $text, [Text.UTF8Encoding]::new($false))
    return $configs
}

function Get-Ferrum2HostQualificationPlan {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$QualificationSourceBundleSha256
    )
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-plan'
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
        safety = [pscustomobject][ordered]@{
            requires_elevation = $true
            requires_explicit_acknowledgement = $true
            automatic_elevation = $false
            live_address_family = 'IPv4 only (RFC2544 198.18.0.0/15)'
            route_scope = 'run-owned /32 only'
            tcp_ingress_scope = 'exact app, TCP, TUN LUID, local address/port, and remote peer'
            wfp_lifetime = 'process-owned dynamic sessions only'
            tcp_ingress_installation = 'automatic after listener bind and before admission'
            mutations = @(
                'one run-owned Wintun adapter at a time',
                'run-owned RFC2544 loopback support address',
                'run-owned narrow routes',
                'process-owned dynamic strict-route WFP session',
                'process-owned dynamic exact TCP ingress WFP session'
            )
            forbidden_mutations = @(
                'default route', 'system DNS', 'physical adapters', 'WLAN',
                'persistent Windows Firewall rules', 'unrelated WFP sessions',
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
        run_id = $Context.run_id
        qualification_source_bundle_sha256 = $Context.performance_source_bundle_sha256
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
    $octets = [Net.IPAddress]::Parse($Network.support_address).GetAddressBytes()
    if ($octets.Length -ne 4 -or $octets[0] -ne 198 -or
        $octets[1] -notin @(18, 19) -or $octets[3] -ge 254) {
        throw 'qualification reset probe is outside its run-owned RFC2544 range'
    }
    $address = "$($octets[0]).$($octets[1]).$($octets[2]).$($octets[3] + 1)"
    $prefix = "$address/32"
    if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix `
            -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $address `
            -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'qualification reset probe route/address baseline must be absent'
    }
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
        Where-Object { [string]$_.Status -ceq 'Up' } | Sort-Object ifIndex)
    if ($adapters.Count -gt 4096) {
        throw 'qualification physical interface inventory exceeds its bound'
    }
    $selected = $null
    foreach ($adapter in $adapters) {
        try {
            $rows = @(Find-NetRoute -RemoteIPAddress $address `
                -InterfaceIndex ([uint32]$adapter.ifIndex) -ErrorAction Stop)
        } catch {
            continue
        }
        $routes = @($rows | Where-Object {
            $_.CimClass.CimClassName -ceq 'MSFT_NetRoute'
        })
        if ($routes.Count -eq 1 -and
            [uint32]$routes[0].InterfaceIndex -eq [uint32]$adapter.ifIndex -and
            [string]$routes[0].NextHop -cne '0.0.0.0') {
            $selected = $routes[0]
            break
        }
    }
    if ($null -eq $selected) {
        throw 'qualification reset needs a readable active hardware IPv4 gateway route'
    }
    # These two exact /32 entries affect only the unused probe address. Adapter settings,
    # existing routes, DNS and WLAN state are never changed; no probe socket is opened.
    [void](Add-Ferrum2OwnedRoute -Context $Context `
        -InterfaceIndex ([uint32]$selected.InterfaceIndex) -DestinationPrefix $prefix `
        -NextHop ([string]$selected.NextHop) -RouteMetric 4094 `
        -Kind 'qualification-reset-baseline')
    $proof = Get-Ferrum2RouteProof -RemoteAddress $address `
        -ExpectedInterfaceIndex ([uint32]$selected.InterfaceIndex) `
        -Purpose 'qualification-reset-baseline'
    if ($proof.destination_prefix -cne $prefix -or
        $proof.next_hop -cne [string]$selected.NextHop) {
        throw 'qualification reset baseline did not select its exact owned route'
    }
    return [pscustomobject]@{
        address = $address
        prefix = $prefix
        endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($address), 9)
        interface_index = [uint32]$selected.InterfaceIndex
        before = $proof
    }
}

function Invoke-Ferrum2HostQualificationChecks {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Candidate.harness -Network $Network
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

    $createRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 1 -Topology "EndToEnd"
    try {
        $createWfp = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
            -Runtime $createRuntime -Network $Network -ExecutablePath $Candidate.client `
            -Label 'create-live'
    } finally {
        Stop-Ferrum2ProductTrial -Context $Context -Runtime $createRuntime
    }
    [void]$wfpAbsence.Add(
        (Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'create-cleanup')
    )
    $checks.Add([pscustomobject][ordered]@{
        name = 'wintun-create-and-delete'; status = 'PASS'
    })

    $resetRoute = Initialize-Ferrum2QualificationResetRoute -Context $Context -Network $Network
    $smokeRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 2 -Topology "EndToEnd" `
        -ResetProbeEndpoint $resetRoute.endpoint
    try {
        $metricsBefore = Get-Ferrum2Metrics -Port $smokeRuntime.client_metrics_port
        Write-NewUtf8File -Path (Join-Path $Context.evidence_directory `
            'qualification-client-metrics-before.txt') -Text $metricsBefore
        Write-NewUtf8File -Path (Join-Path $Context.evidence_directory `
            'qualification-server-metrics-before.txt') `
            -Text (Get-Ferrum2Metrics -Port $smokeRuntime.server_metrics_port)
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
        $probeArguments = "windows-tun-probe --target-ip $($Network.support_address) " +
            "--tcp-port $($support.tcp_port) --udp-port $($support.udp_port)"
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Candidate.harness `
            -Arguments $probeArguments `
            -WorkingDirectory (Split-Path -Parent $Candidate.harness) `
            -LogPrefix 'qualification-probe-before-network-reset' -TimeoutSeconds 60)
        $routeProofs = @($smokeRuntime.route_proofs)
        $notificationAddress = $resetRoute.address
        $routeNotification = [Ferrum2QualificationRouteNotification]::new()
        try {
            [void](Add-Ferrum2OwnedRoute -Context $Context `
                -InterfaceIndex $resetRoute.interface_index `
                -DestinationPrefix $resetRoute.prefix -RouteMetric 4093 `
                -Kind 'qualification-reset-change')
            if (-not $routeNotification.Wait(10000)) {
                throw 'host qualification did not observe the run-owned route notification'
            }
        } finally {
            $routeNotification.Dispose()
        }
        $metricsAfter = Wait-Ferrum2Metric -Process $smokeRuntime.client `
            -Port $smokeRuntime.client_metrics_port -Name 'ferrum2_tun_session_generation' `
            -Minimum ($generationBefore + 1) -TimeoutSeconds 30
        $resetRouteAfter = Get-Ferrum2RouteProof -RemoteAddress $notificationAddress `
            -ExpectedInterfaceIndex $resetRoute.interface_index `
            -Purpose 'qualification-reset-change'
        if ($resetRouteAfter.destination_prefix -cne $resetRoute.prefix -or
            $resetRouteAfter.next_hop -cne '0.0.0.0') {
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
            destination_prefix = "$notificationAddress/32"
            route_before = $resetRoute.before
            route_after = $resetRouteAfter
            session_generation_before = [uint64]$generationBefore
            session_generation_after = [uint64]$generationAfter
        }
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Candidate.harness `
            -Arguments $probeArguments `
            -WorkingDirectory (Split-Path -Parent $Candidate.harness) `
            -LogPrefix 'qualification-probe-after-network-reset' -TimeoutSeconds 60)
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
                    -Text (Get-Ferrum2Metrics -Port $endpoint.port)
            } catch { Write-Warning 'qualification failure metrics unavailable' }
        }
        throw $failure
    } finally {
        Stop-Ferrum2ProductTrial -Context $Context -Runtime $smokeRuntime
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

    $faultRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 3 -Topology "EndToEnd"
    $faultWfp = Get-Ferrum2QualificationLiveWfpWitness -Context $Context `
        -Runtime $faultRuntime -Network $Network -ExecutablePath $Candidate.client `
        -Label 'before-forced-close'
    [Ferrum2PerfProcessGroup]::CloseGroup()
    Start-Sleep -Milliseconds 500
    $addressRows = @($Context.ledger.resources.addresses)
    if ($addressRows.Count -ne 1) {
        throw 'host qualification expected one owned support address'
    }
    $addressRows[0].state = 'planned'
    $Context.ledger.state = 'recovery_required'
    Write-Ferrum2HostPerformanceLedger -Context $Context
    $plannedAddressRefused = $false
    try {
        [void](Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path)
    } catch {
        if ([string]$_.Exception.Message -cne
            'planned address presence is ambiguous; refusing removal') {
            throw
        }
        $plannedAddressRefused = $true
    }
    if (-not $plannedAddressRefused) {
        throw 'host qualification recovery accepted ambiguous planned address ownership'
    }
    $addressRows[0].state = 'created'
    Write-Ferrum2HostPerformanceLedger -Context $Context
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
        @($Context.ledger.resources.ports).Count -ne 0) {
        throw 'host qualification retained a ledger-owned resource'
    }
    $checks.Add([pscustomobject][ordered]@{
        name = 'zero-residue-cleanup'; status = 'PASS'
    })
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification-checks'
        run_id = $Context.run_id
        candidate_sha = $Candidate.commit_sha
        checks = $checks.ToArray()
        route_proofs = $routeProofs
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
            -QualificationSourceBundleSha256 $QualificationSourceBundleSha256
    }
    $mutex = $null
    if ($RecoveryOnly) {
        try {
            $mutex = Enter-Ferrum2HostPerformanceMutex
            return Invoke-Ferrum2HostPerformanceRecovery
        } finally {
            Exit-Ferrum2HostPerformanceMutex -Mutex $mutex
        }
    }
    if (-not (Test-Ferrum2HostPerformanceAdministrator)) {
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
        $mutex = Enter-Ferrum2HostPerformanceMutex
        Assert-NoPendingFerrum2HostPerformanceRecovery
        $context = New-Ferrum2HostPerformanceContext -RepositoryRoot $RepositoryRoot `
            -EvidenceDirectory $EvidenceDirectory -Mode 'Qualification' `
            -BaselineSha $CandidateSha -CandidateSha $CandidateSha `
            -PerformanceSourceBundleSha256 $QualificationSourceBundleSha256
        $plan = Get-Ferrum2HostQualificationPlan -CandidateSha $CandidateSha `
            -QualificationSourceBundleSha256 $QualificationSourceBundleSha256
        Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory 'plan.json') `
            -Document $plan
        $network = New-Ferrum2HostNetworkIdentity -RunId $context.run_id
        $loopback = Get-Ferrum2LoopbackIdentity
        Assert-Ferrum2HostNetworkIdentityAvailable -Network $network -Loopback $loopback
        Set-Ferrum2HostPerformanceState -Context $context -State 'building'
        $buildTimer = [Diagnostics.Stopwatch]::StartNew()
        $candidate = Initialize-Ferrum2QualificationCandidate -Context $context `
            -CandidateSha $CandidateSha
        $buildTimer.Stop()
        $buildSeconds = $buildTimer.Elapsed.TotalSeconds
        Set-Ferrum2HostPerformanceState -Context $context -State 'executing'
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
                $cleanup = Complete-Ferrum2HostPerformanceCleanup -Context $context `
                    -Succeeded $succeeded
                $inspectionRoot = Join-Path $context.evidence_directory `
                    'final-cleanup-inspection'
                if (Test-Path -LiteralPath $inspectionRoot) {
                    throw 'host qualification final inspection baseline must be absent'
                }
                New-Item -ItemType Directory -Path $inspectionRoot `
                    -ErrorAction Stop | Out-Null
                $inspectionContext = [pscustomobject]@{
                    run_id = $context.run_id
                    run_root = $inspectionRoot
                    ledger_path = Join-Path $inspectionRoot 'recovery.json'
                    repository_root = $context.repository_root
                    evidence_directory = $context.evidence_directory
                    performance_source_bundle_sha256 =
                        $context.performance_source_bundle_sha256
                    ledger = $context.ledger
                }
                try {
                    $finalWfp = Assert-Ferrum2QualificationWfpAbsent `
                        -Context $inspectionContext -Label 'final-cleanup'
                } finally {
                    [Ferrum2PerfProcessGroup]::CloseGroup()
                }
                $cleanupTimer.Stop()
                $qualificationCleanup = [pscustomobject][ordered]@{
                    schema_version = 1
                    kind = 'ferrum2.windows-tun.host-qualification-cleanup'
                    run_id = $context.run_id
                    qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
                    status = [string]$cleanup.status
                    adapter_remaining = [int]$cleanup.adapter_remaining
                    routes_remaining = [int]$cleanup.routes_remaining
                    addresses_remaining = [int]$cleanup.addresses_remaining
                    processes_remaining = [int]$cleanup.processes_remaining
                    ports_remaining = [int]$cleanup.ports_remaining
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
        Exit-Ferrum2HostPerformanceMutex -Mutex $mutex
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
    }
    Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory `
        'qualification-worker.json') -Document $workerResult
    return $workerResult
}
