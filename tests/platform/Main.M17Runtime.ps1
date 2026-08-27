function Write-M17ClientConfig(
    [string]$Path,
    [string]$TunFields,
    [ValidateSet("direct", "proxy")][string]$Outbound,
    [int]$MetricsPort,
    [string]$Additional = "",
    [bool]$BindDirectToSupport = $false
) {
    $tunOutbound = if ([regex]::IsMatch($Additional, '(?m)^\[route\]\r?$')) {
        ""
    } else {
        "outbound = `"$Outbound`""
    }
    $outboundText = if ($Outbound -eq "direct") {
        $supportBinding = if ($BindDirectToSupport) {
@"
bind_interface = "$($script:capabilityIdentity.Ledger.topology.guest_interface_alias)"
inet4_bind_address = "$($script:capabilityIdentity.Ledger.topology.guest_ipv4)"
"@
        } else { "" }
@"
[[outbounds]]
tag = "direct"
type = "direct"
$supportBinding
"@
    } else {
@"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "127.0.0.1:$script:m17ServerPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@
    }
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$script:adapterName"
$TunFields
$tunOutbound
$outboundText
[udp]
enabled = true
max_sessions = 64
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
$Additional
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$MetricsPort"
"@ | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-M17Config([string]$Path, [string]$Label) {
    $result = Invoke-M17BoundedCommand "config-$Label" $script:binary @("--config", $Path, "--check-config") (Split-Path -Parent $script:binary) 30
    Assert-True ($result.ExitCode -eq 0 -and $result.Stdout.TrimEnd([char[]]"`r`n") -ceq "configuration valid") "M17 live config validation failed: $Label"
    Assert-True ([string]::IsNullOrEmpty($result.Stderr)) "M17 live config emitted stderr: $Label"
}

function Stop-M17Candidate([System.Diagnostics.Process]$Process, [string]$Label) {
    Stop-Candidate $Process
    $script:activeProcess = $null
    Wait-AdapterAbsent $script:adapterName
    Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
    Add-M17LiveRow "client-$Label-graceful-stop" ([ordered]@{ exit_code = 0; adapter = "absent" })
}

function Start-M17NetworkResetRouteMutation {
    Assert-True ($script:Profile -ceq "network-reset") "M17 network-reset route mutation is profile restricted"
    $supportPath = $script:m17GuestNetworkPathDocument.Value
    $supportAdapter = @(Get-NetAdapter -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -IncludeHidden -ErrorAction Stop)
    Assert-True ($supportAdapter.Count -eq 1 -and
        [string]$supportAdapter[0].Name -ceq [string]$supportPath.guest_interface_alias -and
        ([Guid][string]$supportAdapter[0].InterfaceGuid).ToString("D") -ceq
            [string]$supportPath.guest_interface_guid -and
        [string]$supportAdapter[0].Status -ceq "Up") "M17 support route mutation adapter identity changed"
    $prefix = $script:m17NetworkResetProbePrefix
    Assert-True (@(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 network-reset notification route baseline is not absent"
    $intentPath = Get-M17NetworkResetRouteIntentPath
    Write-M17DurableMutationIntent $intentPath ([ordered]@{
        schema = "ferrum2.windows-tun.m17-network-reset-route-intent.v2"
        run_token = $script:runIdentity
        source_profile = "network-reset"
        work_path = [IO.Path]::GetFullPath($script:work)
        interface_index = [uint32]$supportPath.guest_interface_index
        destination_prefix = $prefix
        next_hop = "0.0.0.0"
        route_metrics = @([uint32]4094, [uint32]4095)
    })
    [void](New-NetRoute -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -DestinationPrefix $prefix -NextHop "0.0.0.0" -RouteMetric 4094 `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $readback = @(Get-NetRoute -InterfaceIndex ([int]$supportPath.guest_interface_index) `
        -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
            $_.NextHop -ceq "0.0.0.0" -and [uint32]$_.RouteMetric -eq 4094
        })
    Assert-True ($readback.Count -eq 1) "M17 network-reset notification route create readback failed"
    return [pscustomobject]@{
        IntentPath = $intentPath
        InterfaceIndex = [uint32]$supportPath.guest_interface_index
        DestinationPrefix = $prefix
        NextHop = "0.0.0.0"
        RouteMetric = [uint32]4094
    }
}

function Set-M17NetworkResetRouteMetric([object]$Mutation, [uint32]$Metric) {
    Assert-True ($script:Profile -ceq "network-reset" -and $Metric -in @(4094, 4095)) "M17 network-reset route metric is outside the closed mutation set"
    $intent = Read-M17NetworkResetRouteMutationIntent ([string]$Mutation.IntentPath)
    Assert-True ([uint32]$intent.interface_index -eq [uint32]$Mutation.InterfaceIndex -and
        [string]$intent.destination_prefix -ceq [string]$Mutation.DestinationPrefix -and
        [string]$intent.next_hop -ceq [string]$Mutation.NextHop -and
        @($intent.route_metrics) -contains [long]$Metric) "M17 network-reset route no longer matches its durable intent"
    $routes = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop })
    Assert-True ($routes.Count -eq 1 -and [uint32]$routes[0].RouteMetric -in @($intent.route_metrics) -and
        [uint32]$routes[0].RouteMetric -ne $Metric) "M17 network-reset route mutation ownership changed"
    Set-NetRoute -InputObject $routes[0] -RouteMetric $Metric -ErrorAction Stop | Out-Null
    $readback = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop -and [uint32]$_.RouteMetric -eq $Metric })
    Assert-True ($readback.Count -eq 1) "M17 network-reset route metric readback failed"
    $Mutation.RouteMetric = $Metric
}

function Get-M17ExactManagedRoute([int]$InterfaceIndex, [string]$Prefix) {
    $routes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    Assert-True ($routes.Count -eq 1) "M17 managed restart route readback is not exact: $Prefix"
    return $routes[0]
}

function Remove-M17ManagedRouteForRestart([int]$InterfaceIndex, [string]$Prefix) {
    $route = Get-M17ExactManagedRoute $InterfaceIndex $Prefix
    Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 managed restart route mutation failed: $Prefix"
}

function Invoke-M17DnsQuery([string]$Source, [string]$Destination, [bool]$Tcp, [uint16]$Id) {
    $query = New-DnsQuery $Id
    $family = if ($Destination.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    if ($Tcp) {
        $client = [Net.Sockets.TcpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            $connected = $client.ConnectAsync($Destination, 53)
            Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "M17 synthetic DNS TCP connect failed"
            $stream = $client.GetStream()
            $frame = [byte[]]::new($query.Length + 2)
            $frame[0] = [byte]($query.Length -shr 8)
            $frame[1] = [byte]($query.Length -band 0xff)
            [Array]::Copy($query, 0, $frame, 2, $query.Length)
            $stream.Write($frame, 0, $frame.Length)
            $lengthBytes = Read-ExactBytes $stream 2
            $length = ([int]$lengthBytes[0] -shl 8) -bor [int]$lengthBytes[1]
            $response = Read-ExactBytes $stream $length
        } finally { $client.Dispose() }
    } else {
        $client = [Net.Sockets.UdpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            [void]$client.Send($query, $query.Length, $Destination, 53)
            $task = $client.ReceiveAsync()
            Assert-True ($task.Wait(5000) -and -not $task.IsFaulted) "M17 synthetic DNS UDP response timeout"
            $response = $task.Result.Buffer
        } finally { $client.Dispose() }
    }
    Assert-True ($response.Length -ge 12 -and $response[0] -eq $query[0] -and $response[1] -eq $query[1] -and
        ($response[2] -band 0x80) -ne 0) "M17 synthetic DNS response is invalid"
}

function Get-M17MetricLabelSetValue(
    [string]$Metrics,
    [string]$Name,
    [System.Collections.IDictionary]$Labels,
    [bool]$AllowAbsent = $false
) {
    $lookaheads = @($Labels.GetEnumerator() | ForEach-Object {
        "(?=[^}`r`n]*$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|}))"
    }) -join ""
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{$lookaheads[^}`r`n]*\} ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return 0.0 }
    Assert-True ($matches.Count -eq 1) "missing or ambiguous M17 metric label set: $Name"
    return [double]::Parse($matches[0].Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-M17NetworkResetMetricState([string]$Metrics) {
    $reset = {
        param([string]$Reason, [string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_reset" ([ordered]@{
            reason = $Reason
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        ResetStarted = & $reset "network_change" "started"
        ResetSucceeded = & $reset "network_change" "succeeded"
        ResetFailed = & $reset "network_change" "failed"
        RetryStarted = & $reset "retry" "started"
        RetrySucceeded = & $reset "retry" "succeeded"
        RetryFailed = & $reset "retry" "failed"
        FullRebuild = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
        SessionActive = Get-M17MetricValue $Metrics "ferrum2_tun_session_active"
        StrictRequested = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_requested"
        StrictEffective = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_effective"
        StrictInstallSucceeded = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "success" $true
        StrictInstallFailed = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "failure" $true
    }
}

function Get-M17ManagedRouteRebuildMetricState([string]$Metrics) {
    $rebuild = {
        param([string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_full_rebuild" ([ordered]@{
            reason = "route_damage"
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        RouteDamageStarted = & $rebuild "started"
        RouteDamageSucceeded = & $rebuild "succeeded"
        RouteDamageFailed = & $rebuild "failed"
        FullRebuildTotal = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkResetTotal = Get-M17MetricValue $Metrics "ferrum2_network_reset" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
    }
}

function Wait-M17NetworkResetCycle(
    [int]$MetricsPort,
    [object]$Baseline,
    [int]$Cycle,
    [double]$ExpectedSessionGeneration,
    [int]$TimeoutSeconds = 60
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $state = $null
    do {
        $metrics = Get-Metrics $MetricsPort 2
        $state = Get-M17NetworkResetMetricState $metrics
        if ($state.ResetStarted -eq $Baseline.ResetStarted + $Cycle -and
            $state.ResetSucceeded -eq $Baseline.ResetSucceeded + $Cycle -and
            $state.ResetFailed -eq $Baseline.ResetFailed -and
            $state.RetryStarted -eq $Baseline.RetryStarted -and
            $state.RetrySucceeded -eq $Baseline.RetrySucceeded -and
            $state.RetryFailed -eq $Baseline.RetryFailed -and
            $state.FullRebuild -eq $Baseline.FullRebuild -and
            $state.NetworkGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionActive -eq 1 -and
            $state.StrictRequested -eq 1 -and $state.StrictEffective -eq 1 -and
            $state.StrictInstallSucceeded -eq $Baseline.StrictInstallSucceeded -and
            $state.StrictInstallFailed -eq $Baseline.StrictInstallFailed) {
            # Hold beyond the runtime's 350 ms notification debounce before accepting one cycle.
            Start-Sleep -Milliseconds 500
            $stableMetrics = Get-Metrics $MetricsPort 2
            $stable = Get-M17NetworkResetMetricState $stableMetrics
            Assert-True ($stable.ResetStarted -eq $state.ResetStarted -and
                $stable.ResetSucceeded -eq $state.ResetSucceeded -and
                $stable.ResetFailed -eq $state.ResetFailed -and
                $stable.RetryStarted -eq $state.RetryStarted -and
                $stable.RetrySucceeded -eq $state.RetrySucceeded -and
                $stable.RetryFailed -eq $state.RetryFailed -and
                $stable.NetworkGeneration -eq $state.NetworkGeneration -and
                $stable.SessionGeneration -eq $state.SessionGeneration -and
                $stable.FullRebuild -eq $state.FullRebuild -and
                $stable.StrictRequested -eq $state.StrictRequested -and
                $stable.StrictEffective -eq $state.StrictEffective -and
                $stable.StrictInstallSucceeded -eq $state.StrictInstallSucceeded -and
                $stable.StrictInstallFailed -eq $state.StrictInstallFailed) "M17 network-reset cycle did not stabilize"
            return [pscustomobject]@{ Metrics = $stableMetrics; State = $stable }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 network-reset cycle timeout: cycle=$Cycle expected_generation=$ExpectedSessionGeneration state=$($state | ConvertTo-Json -Compress)"
}
