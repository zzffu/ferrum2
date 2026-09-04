Set-StrictMode -Version Latest

$script:QualificationMaximumElapsedSeconds = 900
$script:QualificationWorkerTimeoutSeconds = 840
$script:QualificationBuildTimeoutSeconds = 600
$script:QualificationSessionKey = '{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}'
$script:QualificationSublayerKey = '{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}'
$script:QualificationFilterKeys = @(
    '{a158b31d-7a59-40bc-9339-38b5e8701001}',
    '{a158b31d-7a59-40bc-9339-38b5e8701002}',
    '{a158b31d-7a59-40bc-9339-38b5e8701003}',
    '{a158b31d-7a59-40bc-9339-38b5e8701004}',
    '{a158b31d-7a59-40bc-9339-38b5e8701006}'
)
$script:QualificationFilterNames = @(
    'Ferrum2 app permit IPv4',
    'Ferrum2 app permit IPv6',
    'Ferrum2 TUN permit IPv4',
    'Ferrum2 TUN permit IPv6',
    'Ferrum2 family block IPv6'
)
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
        [Parameter(Mandatory = $true)][int]$Sequence
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
            'tcp-and-udp-through-owned-tun',
            'narrow-route-isolation',
            'strict-route-wfp-live-readback',
            'network-notification-retains-wfp-identity',
            'forced-process-tree-recovery',
            'zero-residue-cleanup'
        )
        safety = [pscustomobject][ordered]@{
            requires_elevation = $true
            requires_explicit_acknowledgement = $true
            automatic_elevation = $false
            address_family = 'RFC2544 198.18.0.0/15'
            route_scope = 'run-owned /32 only'
            mutations = @(
                'one run-owned Wintun adapter at a time',
                'run-owned RFC2544 loopback support address',
                'run-owned narrow routes',
                'process-owned dynamic strict-route WFP session'
            )
            forbidden_mutations = @(
                'default route', 'system DNS', 'physical adapters', 'WLAN',
                'firewall rules', 'sing-box', 'unrelated resources'
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

function ConvertFrom-Ferrum2QualificationWfpStateXml {
    param([Parameter(Mandatory = $true)][string]$Text)

    $declaration = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    if (-not $Text.StartsWith($declaration, [StringComparison]::Ordinal)) {
        throw 'host qualification WFP snapshot declaration is invalid'
    }
    $document = [Xml.XmlDocument]::new()
    try {
        $document.LoadXml(
            "<ferrum2WfpState>$($Text.Substring($declaration.Length))</ferrum2WfpState>"
        )
    } catch {
        throw "host qualification WFP snapshot XML is invalid: $($_.Exception.Message)"
    }
    $rootNames = @($document.DocumentElement.ChildNodes | Where-Object {
        $_.NodeType -eq [Xml.XmlNodeType]::Element
    } | ForEach-Object { $_.LocalName })
    if (($rootNames -join '|') -cne 'wfpstate|firewallState') {
        throw 'host qualification WFP snapshot root set is invalid'
    }
    return $document
}

function Invoke-Ferrum2QualificationWfpState {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $path = Join-Path $Context.run_root "wfp-$Label.xml"
    if (Test-Path -LiteralPath $path) {
        throw 'host qualification WFP snapshot baseline must be absent'
    }
    $netsh = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
    try {
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $netsh `
            -Arguments "wfp show state file=`"$path`"" `
            -WorkingDirectory $Context.run_root -LogPrefix "wfp-$Label" -TimeoutSeconds 45)
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 64MB) {
            throw 'host qualification WFP snapshot size is invalid'
        }
        $text = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop
        return ConvertFrom-Ferrum2QualificationWfpStateXml -Text $text
    } finally {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-Ferrum2QualificationWfpWitness {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Runtime,
        [Parameter(Mandatory = $true)][string]$Label
    )
    [xml]$document = Invoke-Ferrum2QualificationWfpState -Context $Context -Label $Label
    $sublayerKey = $script:QualificationSublayerKey.ToLowerInvariant()
    $sessionKey = $script:QualificationSessionKey.ToLowerInvariant()
    $filters = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $null -ne $key -and $null -ne $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey
    })
    if ($filters.Count -ne $script:QualificationFilterKeys.Count) {
        throw 'host qualification strict-route WFP filter count is not exact'
    }
    $filterRows = [Collections.Generic.List[object]]::new()
    foreach ($expectedName in $script:QualificationFilterNames) {
        $matches = @($filters | Where-Object {
            $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
            $null -ne $name -and $name.InnerText -ceq $expectedName
        })
        if ($matches.Count -ne 1) {
            throw "host qualification WFP filter identity changed: $expectedName"
        }
        $key = $matches[0].SelectSingleNode("./*[local-name()='filterKey']")
        $id = $matches[0].SelectSingleNode("./*[local-name()='filterId']")
        if ($null -eq $key -or
            $key.InnerText.ToLowerInvariant() -cnotin $script:QualificationFilterKeys -or
            $null -eq $id -or [string]$id.InnerText -cnotmatch '^[1-9][0-9]*$') {
            throw "host qualification WFP filter readback is invalid: $expectedName"
        }
        $filterRows.Add([pscustomobject][ordered]@{
            name = $expectedName
            key = $key.InnerText.Trim('{}').ToLowerInvariant()
            id = [string]$id.InnerText
        })
    }
    $sublayers = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $null -eq $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey -and
            $null -ne $name -and $name.InnerText -ceq 'Ferrum2 strict route'
    })
    if ($sublayers.Count -ne 1) {
        throw 'host qualification strict-route WFP sublayer identity is not exact'
    }
    $weightNode = $sublayers[0].SelectSingleNode("./*[local-name()='weight']")
    if ($null -eq $weightNode -or [string]::IsNullOrWhiteSpace($weightNode.InnerText)) {
        throw 'host qualification strict-route WFP sublayer weight is unavailable'
    }
    $sessions = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='sessionKey']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $key.InnerText.ToLowerInvariant() -ceq $sessionKey -and
            $null -ne $name -and $name.InnerText -ceq 'Ferrum2 strict route dynamic session'
    })
    if ($sessions.Count -ne 1) {
        throw 'host qualification strict-route WFP session identity is not exact'
    }
    $processNode = $sessions[0].SelectSingleNode("./*[local-name()='processId']")
    if ($null -eq $processNode -or [uint32]$processNode.InnerText -ne [uint32]$Runtime.client.pid) {
        throw 'host qualification strict-route WFP owner process is not exact'
    }
    return [pscustomobject][ordered]@{
        session_key = $script:QualificationSessionKey.Trim('{}')
        sublayer_key = $script:QualificationSublayerKey.Trim('{}')
        sublayer_weight = [string]$weightNode.InnerText
        process_id = [uint32]$Runtime.client.pid
        filters = @($filterRows)
    }
}

function Assert-Ferrum2QualificationWfpAbsent {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label
    )
    [xml]$document = Invoke-Ferrum2QualificationWfpState -Context $Context -Label $Label
    $keys = @(
        $script:QualificationSessionKey,
        $script:QualificationSublayerKey
    ) + @($script:QualificationFilterKeys)
    $normalized = @($keys | ForEach-Object { $_.ToLowerInvariant() })
    $matches = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $item = $_
        @('sessionKey', 'subLayerKey', 'filterKey') | Where-Object {
            $node = $item.SelectSingleNode("./*[local-name()='$_']")
            $null -ne $node -and $node.InnerText.ToLowerInvariant() -cin $normalized
        }
    })
    if ($matches.Count -ne 0) {
        throw 'host qualification strict-route WFP objects remain after process exit'
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
    $notificationWitness = $null

    $createRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 1 -Topology "EndToEnd"
    Stop-Ferrum2ProductTrial -Context $Context -Runtime $createRuntime
    Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'create-cleanup'
    $checks.Add([pscustomobject][ordered]@{
        name = 'wintun-create-and-delete'; status = 'PASS'
    })

    $smokeRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 2 -Topology "EndToEnd"
    try {
        $metricsBefore = Get-Ferrum2Metrics -Port $smokeRuntime.client_metrics_port
        if ((Get-Ferrum2MetricValue $metricsBefore 'ferrum2_tun_strict_route_requested') -ne 1 -or
            (Get-Ferrum2MetricValue $metricsBefore 'ferrum2_tun_strict_route_effective') -ne 1 -or
            (Get-Ferrum2QualificationMetricLabelValue $metricsBefore `
                'ferrum2_tun_strict_route_filter_install_total' 'result' 'success') -lt 1 -or
            (Get-Ferrum2QualificationMetricLabelValue $metricsBefore `
                'ferrum2_tun_strict_route_filter_install_total' 'result' 'failure' -AllowAbsent) -ne 0) {
            throw 'host qualification strict-route metrics are invalid'
        }
        $wfpBefore = Get-Ferrum2QualificationWfpWitness -Context $Context `
            -Runtime $smokeRuntime -Label 'before-notification'
        $probeArguments = "windows-tun-probe --target-ip $($Network.support_address) " +
            "--tcp-port $($support.tcp_port) --udp-port $($support.udp_port)"
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Candidate.harness `
            -Arguments $probeArguments `
            -WorkingDirectory (Split-Path -Parent $Candidate.harness) `
            -LogPrefix 'qualification-probe-before-notification' -TimeoutSeconds 60)
        $routeProofs = @($smokeRuntime.route_proofs)
        $octets = $Network.support_address.Split('.')
        $notificationAddress = "$($octets[0]).$($octets[1]).$($octets[2]).$([int]$octets[3] + 1)"
        if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$notificationAddress/32" `
                -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'host qualification notification route baseline is not absent'
        }
        $routeNotification = [Ferrum2QualificationRouteNotification]::new()
        try {
            [void](Add-Ferrum2OwnedRoute -Context $Context `
                -InterfaceIndex $Loopback.interface_index `
                -DestinationPrefix "$notificationAddress/32" -RouteMetric 4094 `
                -Kind 'qualification-notification')
            if (-not $routeNotification.Wait(10000)) {
                throw 'host qualification did not observe the run-owned route notification'
            }
        } finally {
            $routeNotification.Dispose()
        }
        Start-Sleep -Seconds 1
        $metricsAfter = Get-Ferrum2Metrics -Port $smokeRuntime.client_metrics_port
        if ((Get-Ferrum2MetricValue $metricsAfter `
                'ferrum2_tun_strict_route_effective') -ne 1) {
            throw 'host qualification network notification did not preserve strict-route state'
        }
        $notificationWitness = [pscustomobject][ordered]@{
            source = 'NotifyRouteChange2'
            observed = $true
            destination_prefix = "$notificationAddress/32"
            debounce_wait_milliseconds = 1000
        }
        $wfpAfter = Get-Ferrum2QualificationWfpWitness -Context $Context `
            -Runtime $smokeRuntime -Label 'after-notification'
        if ($wfpAfter.sublayer_weight -cne $wfpBefore.sublayer_weight -or
            (@($wfpAfter.filters.id) -join '|') -cne (@($wfpBefore.filters.id) -join '|')) {
            throw 'host qualification network notification replaced strict-route WFP identity'
        }
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Candidate.harness `
            -Arguments $probeArguments `
            -WorkingDirectory (Split-Path -Parent $Candidate.harness) `
            -LogPrefix 'qualification-probe-after-notification' -TimeoutSeconds 60)
    } finally {
        Stop-Ferrum2ProductTrial -Context $Context -Runtime $smokeRuntime
    }
    Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'smoke-cleanup'
    foreach ($name in @(
        'tcp-and-udp-through-owned-tun',
        'narrow-route-isolation',
        'strict-route-wfp-live-readback',
        'network-notification-retains-wfp-identity'
    )) {
        $checks.Add([pscustomobject][ordered]@{ name = $name; status = 'PASS' })
    }

    $faultRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Candidate `
        -Network $Network -Loopback $Loopback -Sequence 3 -Topology "EndToEnd"
    [void](Get-Ferrum2QualificationWfpWitness -Context $Context `
        -Runtime $faultRuntime -Label 'before-forced-close')
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
        Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
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
    Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
    Assert-Ferrum2QualificationWfpAbsent -Context $Context -Label 'forced-close-cleanup'
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
            before_notification = $wfpBefore
            after_notification = $wfpAfter
            cleanup = 'absent'
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
    }
    Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory `
        'qualification-worker.json') -Document $workerResult
    return $workerResult
}
