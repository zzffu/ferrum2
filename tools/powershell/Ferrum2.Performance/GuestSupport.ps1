#requires -Version 7.4
function Invoke-NativeCapture([string]$Executable, [string[]]$Arguments) {
    $previousErrorActionPreference = $ErrorActionPreference
    $output = @()
    $exitCode = $null
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $Executable @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        ExitCode = if ($null -eq $exitCode) { -1 } else { [int]$exitCode }
        Output = @($output)
    }
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [int] -or $Value -is [long]
}

function Get-FreeTcpPort([string]$LocalAddress = "127.0.0.1") {
    $address = [Net.IPAddress]::Parse($LocalAddress)
    $listener = New-Object Net.Sockets.TcpListener($address, 0)
    try {
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}
function Get-FreeDualPort([string]$LocalAddress) {
    $address = [Net.IPAddress]::Parse($LocalAddress)
    foreach ($attempt in 1..100) {
        $port = Get-FreeTcpPort -LocalAddress $LocalAddress
        $udp = New-Object Net.Sockets.UdpClient
        try {
            $udp.Client.Bind((New-Object Net.IPEndPoint($address, $port)))
            return $port
        } catch {
            if ($attempt -eq 100) { throw }
        } finally {
            $udp.Dispose()
        }
    }
    throw "unable to reserve a dual TCP/UDP port"
}
function Get-GuestNetworkPath {
    $probe = Join-Path $InputRoot "get_windows_tun_guest_network_path.ps1"
    if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash.ToLowerInvariant() `
            -cne $GuestNetworkPathProbeSha256) {
        throw "guest network-path probe identity changed"
    }
    $probeResult = Invoke-NativeCapture $PowerShell @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $probe, "-SupportIpv4", $SupportAddress,
        "-SupportPort", [string]$SupportUdp,
        "-ExpectedGuestIpv4", $ExpectedGuestAddress,
        "-ExpectedInterfaceAlias", $ExpectedGuestInterfaceAlias,
        "-ExpectedNetwork", $ExpectedSupportNetwork,
        "-ExpectedPrefixLength", [string]$ExpectedSupportPrefixLength,
        "-ExpectedMacAddress", $ExpectedSupportMacAddress,
        "-ExpectedInterfaceGuid", $ExpectedSupportInterfaceGuid,
        "-ExpectedMtuBytes", [string]$ExpectedSupportMtuBytes,
        "-ManagedAdapterName", $AdapterName,
        "-MinimumUnderlayIpv4PacketBytes",
        [string]$MinimumSupportIpv4PacketBytes, "-AsJson"
    )
    if ($probeResult.ExitCode -ne 0 -or @($probeResult.Output).Count -ne 1) {
        throw "guest network-path probe result is not unique"
    }
    $actual = [string]$probeResult.Output[0] | ConvertFrom-Json
    $fields = @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes",
        "guest_mac_address",
        "guest_route_prefix", "guest_route_next_hop", "guest_dns_servers"
    )
    if ((@($actual.PSObject.Properties.Name) -join "|") -cne ($fields -join "|") -or
        (@($ExpectedGuestNetworkPath.PSObject.Properties.Name) -join "|") -cne
            ($fields -join "|") -or
        [int]$actual.schema -ne 2 -or [int]$ExpectedGuestNetworkPath.schema -ne 2) {
        throw "guest network-path evidence shape is invalid"
    }
    foreach ($field in @(
        "support_ipv4", "guest_ipv4", "guest_prefix_length", "guest_interface_index",
        "guest_interface_alias", "guest_interface_guid", "guest_interface_mtu_bytes",
        "guest_mac_address",
        "guest_route_prefix",
        "guest_route_next_hop"
    )) {
        if ([string]$actual.$field -cne [string]$ExpectedGuestNetworkPath.$field) {
            throw "guest network path changed: field=$field"
        }
    }
    if ((@($actual.guest_dns_servers) -join "|") -cne
        (@($ExpectedGuestNetworkPath.guest_dns_servers) -join "|")) {
        throw "guest network path changed: field=guest_dns_servers"
    }
    return $actual
}
function Wait-ProcessListener(
    [int]$ProcessId,
    [string]$LocalAddress,
    [int]$Port,
    [bool]$RequireUdp
) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $tcp = @()
    $udp = @()
    do {
        if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
            throw "server exited before listener readiness"
        }
        $tcp = @(Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue | Where-Object {
                [int]$_.OwningProcess -eq $ProcessId
            })
        if ($RequireUdp) {
            $udp = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue |
                Where-Object {
                    [int]$_.OwningProcess -eq $ProcessId
                })
        }
        $tcpExact = $tcp.Count -eq 1 -and
            [string]$tcp[0].LocalAddress -ceq $LocalAddress
        $udpExact = -not $RequireUdp -or (
            $udp.Count -eq 1 -and
            [string]$udp[0].LocalAddress -ceq $LocalAddress
        )
        if ($tcpExact -and $udpExact) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "server listener readiness timed out: address=$LocalAddress port=$Port tcp=$($tcp.Count) udp=$($udp.Count) require_udp=$RequireUdp"
}
function Get-PrometheusIntegerMetric(
    [string]$Metrics,
    [string]$Name
) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)? (?<value>[0-9]+)$"
    $selected = @([regex]::Matches($Metrics, $pattern))
    if ($selected.Count -ne 1) {
        throw "missing or ambiguous integer server metric: $Name"
    }
    return [uint64]::Parse(
        $selected[0].Groups["value"].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
}
function Get-PrometheusLabeledIntegerMetric(
    [string]$Metrics,
    [string]$Name,
    [hashtable]$Labels,
    [bool]$AllowAbsent = $false
) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{(?<labels>[^}`r`n]*)\} (?<value>[0-9]+)$"
    $selected = @([regex]::Matches($Metrics, $pattern) | Where-Object {
        $encoded = $_.Groups["labels"].Value
        @($encoded.Split(',')).Count -eq $Labels.Count -and
            @($Labels.GetEnumerator() | Where-Object {
                $encoded -cnotmatch "(?:^|,)$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|$)"
            }).Count -eq 0
    })
    if ($selected.Count -eq 0 -and $AllowAbsent) { return [uint64]0 }
    if ($selected.Count -ne 1) {
        throw "missing or ambiguous labeled integer server metric: $Name"
    }
    return [uint64]::Parse(
        $selected[0].Groups["value"].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
}
function Get-ServerNetworkState([int]$ProcessId, [int]$MetricsPort) {
    if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
        throw "server exited while waiting for network stability"
    }
    $metrics = (Invoke-WebRequest -UseBasicParsing `
        -Uri "http://127.0.0.1:$MetricsPort/metrics" -TimeoutSec 2).Content
    if ($metrics -cnotmatch '(?m)^# TYPE ferrum2_network_generation gauge$') {
        throw "server network generation metric metadata is missing"
    }
    $resetFamilyPresent = $metrics -cmatch `
        '(?m)^(?:# (?:HELP|TYPE) )?ferrum2_network_reset(?:_total)?(?:[ {])'
    if ($resetFamilyPresent -and
        $metrics -cnotmatch '(?m)^# TYPE ferrum2_network_reset counter$') {
        throw "server network reset metric metadata is invalid"
    }
    $reset = @{}
    foreach ($reason in @("network_change", "retry")) {
        foreach ($result in @("started", "succeeded", "failed")) {
            $reset["$reason.$result"] = Get-PrometheusLabeledIntegerMetric `
                -Metrics $metrics -Name "ferrum2_network_reset" -Labels @{
                    reason = $reason
                    result = $result
                } -AllowAbsent $true
        }
    }
    return [pscustomobject]@{
        Generation = Get-PrometheusIntegerMetric `
            -Metrics $metrics -Name "ferrum2_network_generation"
        NetworkChangeStarted = $reset["network_change.started"]
        NetworkChangeSucceeded = $reset["network_change.succeeded"]
        NetworkChangeFailed = $reset["network_change.failed"]
        RetryStarted = $reset["retry.started"]
        RetrySucceeded = $reset["retry.succeeded"]
        RetryFailed = $reset["retry.failed"]
    }
}
function Wait-ServerNetworkStable(
    [int]$ProcessId,
    [int]$MetricsPort,
    [object]$Baseline,
    [bool]$RequireAdvance
) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $stableSince = $null
    $lastSignature = $null
    $observedSignature = $null
    $state = $null
    do {
        $state = Get-ServerNetworkState `
            -ProcessId $ProcessId -MetricsPort $MetricsPort
        $values = @(
            $state.Generation,
            $state.NetworkChangeStarted,
            $state.NetworkChangeSucceeded,
            $state.NetworkChangeFailed,
            $state.RetryStarted,
            $state.RetrySucceeded,
            $state.RetryFailed
        )
        $observedSignature = $values -join "|"
        $totalStarted = $state.NetworkChangeStarted + $state.RetryStarted
        $totalFinished = $state.NetworkChangeSucceeded +
            $state.NetworkChangeFailed + $state.RetrySucceeded + $state.RetryFailed
        $eligible = $totalStarted -eq $totalFinished
        if ($eligible -and $RequireAdvance) {
            $monotonic = $state.Generation -ge $Baseline.Generation -and
                $state.NetworkChangeStarted -ge $Baseline.NetworkChangeStarted -and
                $state.NetworkChangeSucceeded -ge $Baseline.NetworkChangeSucceeded -and
                $state.NetworkChangeFailed -ge $Baseline.NetworkChangeFailed -and
                $state.RetryStarted -ge $Baseline.RetryStarted -and
                $state.RetrySucceeded -ge $Baseline.RetrySucceeded -and
                $state.RetryFailed -ge $Baseline.RetryFailed
            if ($monotonic) {
                $generationDelta = $state.Generation - $Baseline.Generation
                $networkChangeStartedDelta = $state.NetworkChangeStarted -
                    $Baseline.NetworkChangeStarted
                $startedDelta = $networkChangeStartedDelta +
                    ($state.RetryStarted - $Baseline.RetryStarted)
                $succeededDelta = ($state.NetworkChangeSucceeded -
                    $Baseline.NetworkChangeSucceeded) +
                    ($state.RetrySucceeded - $Baseline.RetrySucceeded)
                $failedDelta = ($state.NetworkChangeFailed -
                    $Baseline.NetworkChangeFailed) +
                    ($state.RetryFailed - $Baseline.RetryFailed)
                $eligible = $networkChangeStartedDelta -ge 1 -and
                    $generationDelta -gt 0 -and
                    $startedDelta -eq $succeededDelta + $failedDelta -and
                    $generationDelta -eq $succeededDelta
            } else {
                $eligible = $false
            }
        }
        if ($eligible) {
            if ($observedSignature -cne $lastSignature) {
                $lastSignature = $observedSignature
                $stableSince = [DateTime]::UtcNow
            } elseif (([DateTime]::UtcNow - $stableSince).TotalMilliseconds -ge 1500) {
                return $state
            }
        } else {
            $stableSince = $null
            $lastSignature = $null
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $baselineSignature = if ($null -eq $Baseline) { "none" } else {
        @(
            $Baseline.Generation,
            $Baseline.NetworkChangeStarted,
            $Baseline.NetworkChangeSucceeded,
            $Baseline.NetworkChangeFailed,
            $Baseline.RetryStarted,
            $Baseline.RetrySucceeded,
            $Baseline.RetryFailed
        ) -join "|"
    }
    throw "server network stability timed out: baseline=$baselineSignature last=$observedSignature require_advance=$RequireAdvance"
}
function Wait-TunReady([int]$ProcessId, [int]$Port) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
            throw "client exited before TUN readiness"
        }
        try {
            $metrics = (Invoke-WebRequest -UseBasicParsing `
                -Uri "http://127.0.0.1:$Port/metrics" -TimeoutSec 2).Content
            if ($metrics -match '(?m)^ferrum2_tun_session_active(?:\{[^}]*\})? 1(?:\.0+)?$') {
                return
            }
        } catch { }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "client TUN readiness timed out"
}
function Stop-OwnedProcess([int]$ProcessId, [string]$Label) {
    $confirmedExit = [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)
    try {
        $forced = $false
        if (-not $confirmedExit) {
            $breakSent = [Ferrum2PerfProcessGroup]::Break([uint32]$ProcessId)
            $confirmedExit = if ($breakSent) {
                [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 60000)
            } else {
                [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)
            }
        }
        if (-not $confirmedExit) {
            $terminateRequested = [Ferrum2PerfProcessGroup]::Terminate(
                [uint32]$ProcessId
            )
            $confirmedExit = [Ferrum2PerfProcessGroup]::Wait(
                [uint32]$ProcessId,
                10000
            )
            if (-not $confirmedExit) {
                throw "$Label fallback termination was not confirmed"
            }
            $forced = $terminateRequested
        }
        if ($forced) {
            throw "$Label did not stop gracefully"
        }
        $exit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$ProcessId)
        if ($exit -ne 0) { throw "$Label stopped with exit code $exit" }
    } finally {
        if ($confirmedExit) {
            [Ferrum2PerfProcessGroup]::Close([uint32]$ProcessId)
        }
    }
}
function Wait-AdapterAbsent {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        if (-not (Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "managed performance adapter did not disappear"
}
function Write-CanonicalLedger(
    [string]$Path,
    [string]$MemberCommit,
    [string]$ClientHash,
    [string]$ServerHash,
    [string]$CollectorHash,
    [string]$ControllerBundleHash
) {
    $ledger = [ordered]@{
        schema = 3
        vm_name = $VmName
        vm_id = $VmId
        checkpoint_name = $CheckpointName
        checkpoint_id = $CheckpointId
        topology_manifest_sha256 = $TopologyManifestSha256Value
        topology_plan_sha256 = $TopologyPlanSha256Value
        support_switch_name = $SupportSwitchName
        support_switch_id = $SupportSwitchId
        guest_product = [string]$version.ProductName
        guest_edition = [string]$version.EditionID
        guest_architecture = "AMD64"
        guest_version = [Environment]::OSVersion.Version.ToString()
        guest_build = "$($version.CurrentBuildNumber).$($version.UBR)"
        candidate_sha = $MemberCommit
        probe_sha256 = $CollectorHash
        controller_bundle_sha256 = $ControllerBundleHash
        client_sha256 = $ClientHash
        server_sha256 = $ServerHash
        support_listener = [ordered]@{
            ipv4 = $SupportAddress
            tcp_port = $SupportTcp
            udp_port = $SupportUdp
            pid = $SupportProcessId
            owner = $SupportProcessOwner
        }
    }
    [IO.File]::WriteAllText(
        $Path,
        (($ledger | ConvertTo-Json -Compress -Depth 4) + "`n"),
        $Utf8NoBom
    )
}
