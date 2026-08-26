function Convert-Tcp08CtrlBreakResult([Ferrum2CtrlBreakResult]$Result) {
    return [ordered]@{
        process_known = $Result.ProcessKnown
        separate_console = $Result.SeparateConsole
        had_console = $Result.HadConsole
        attach_attempted = $Result.AttachAttempted
        free_console_before_attach = [ordered]@{
            result = $Result.FreeConsoleBeforeAttachResult
            win32_error = $Result.FreeConsoleBeforeAttachWin32Error
        }
        attach_console = [ordered]@{
            result = $Result.AttachConsoleResult
            win32_error = $Result.AttachConsoleWin32Error
        }
        set_console_ctrl_handler = [ordered]@{
            result = $Result.SetConsoleCtrlHandlerResult
            win32_error = $Result.SetConsoleCtrlHandlerWin32Error
        }
        generate_console_ctrl_event = [ordered]@{
            result = $Result.GenerateConsoleCtrlEventResult
            win32_error = $Result.GenerateConsoleCtrlEventWin32Error
        }
        reset_console_ctrl_handler = [ordered]@{
            result = $Result.ResetConsoleCtrlHandlerResult
            win32_error = $Result.ResetConsoleCtrlHandlerWin32Error
        }
        free_console_after = [ordered]@{
            result = $Result.FreeConsoleAfterResult
            win32_error = $Result.FreeConsoleAfterWin32Error
        }
        send_started_timestamp = $Result.SendStartedTimestamp
        send_returned_timestamp = $Result.SendReturnedTimestamp
        send_duration_ms = [Math]::Round($Result.SendDurationMilliseconds, 3)
        internal_wait_started_timestamp = $Result.InternalWaitStartedTimestamp
        internal_wait_returned_timestamp = $Result.InternalWaitReturnedTimestamp
        internal_wait_ms = [Math]::Round($Result.InternalWaitMilliseconds, 3)
        total_duration_ms = [Math]::Round($Result.TotalDurationMilliseconds, 3)
        succeeded = $Result.Succeeded
    }
}

function Test-Tcp08ClientSocketOpen([Net.Sockets.TcpClient]$Client) {
    if (-not $Client) { return $false }
    try {
        $socket = $Client.Client
        return $socket -and $socket.Connected -and -not ($socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead) -and $socket.Available -eq 0)
    } catch [ObjectDisposedException] { return $false }
    catch [Net.Sockets.SocketException] { return $false }
}

function Get-Tcp08Endpoint([Net.Sockets.TcpClient]$Client, [bool]$Local) {
    if (-not $Client) { return $null }
    try {
        $endpoint = if ($Local) { $Client.Client.LocalEndPoint } else { $Client.Client.RemoteEndPoint }
        if ($endpoint) { return $endpoint.ToString() }
        return $null
    } catch [ObjectDisposedException] { return $null }
    catch [Net.Sockets.SocketException] { return $null }
}

function Get-Tcp08MetricEvidence([int]$MetricsPort) {
    $samples = @()
    try {
        $metrics = Get-Metrics $MetricsPort
        $samples = @($metrics -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object {
            $_ -match '^ferrum2_(tun_(packets_accepted|tcp_flows_active|handler_tasks_active)|tcp_connections_active|tcp_forced_shutdown|process_|runtime|root|owner|shutdown)'
        })
        return [ordered]@{
            available = $true
            required = [bool]$script:RequireTcp08ProductMetrics
            unavailable_after_quiesce_expected = $false
            owner_counts = [ordered]@{
                active_tun_tcp_flows = Get-ClientGaugeValue $metrics "ferrum2_tun_tcp_flows_active"
                active_tun_handler_tasks = Get-ClientGaugeValue $metrics "ferrum2_tun_handler_tasks_active"
                active_process_roots = Get-ClientGaugeValue $metrics "ferrum2_process_roots_active"
                forced_roots = Get-ClientCounterValue $metrics "ferrum2_process_roots_forced"
            }
            samples = $samples
        }
    } catch {
        return [ordered]@{
            available = $false
            required = [bool]$script:RequireTcp08ProductMetrics
            unavailable_after_quiesce_expected = $false
            failure_type = $_.Exception.GetType().FullName
            owner_counts = $null
            samples = $samples
        }
    }
}

function Assert-Tcp08ProductOwnerMetrics([object]$Evidence, [string]$Phase) {
    Assert-True $Evidence.available "TCP-08 product owner metrics were unavailable $Phase"
    Assert-True ($Evidence.owner_counts.active_tun_tcp_flows -ge 1) "TCP-08 had no active product-owned TUN TCP flow $Phase"
    Assert-True ($Evidence.owner_counts.active_tun_handler_tasks -ge 1) "TCP-08 had no active product-owned TUN handler task $Phase"
    Assert-True ($Evidence.owner_counts.active_process_roots -ge 1) "TCP-08 had no active product-owned process root $Phase"
    Assert-True ($Evidence.owner_counts.forced_roots -eq 0) "TCP-08 process root was already forced $Phase"
}

function Get-Tcp08ConnectionEvidence(
    [string]$Target,
    [int]$TargetPort,
    [int]$GatePort,
    [int]$ServerPort,
    [System.Diagnostics.Process]$CandidateProcess
) {
    $candidatePid = if ($CandidateProcess) { [uint32]$CandidateProcess.Id } else { [uint32]0 }
    $serverPids = @($script:serverProcesses | ForEach-Object { [uint32]$_.Id })
    $relevantPorts = @($TargetPort, $GatePort, $ServerPort) | Sort-Object -Unique
    $rows = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $relevantPorts -contains [int]$_.LocalPort -or
        $relevantPorts -contains [int]$_.RemotePort -or
        $_.LocalAddress -eq $Target -or $_.RemoteAddress -eq $Target -or
        [uint32]$_.OwningProcess -eq $candidatePid -or
        $serverPids -contains [uint32]$_.OwningProcess
    } | Sort-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort | ForEach-Object {
        $owner = [uint32]$_.OwningProcess
        $role = if ($owner -eq [uint32]$PID) { "controller" }
            elseif ($owner -eq $candidatePid) { "client" }
            elseif ($serverPids -contains $owner) { "server" }
            else { "other" }
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            remote_address = [string]$_.RemoteAddress
            remote_port = [int]$_.RemotePort
            state = [string]$_.State
            owning_process = $owner
            owner_role = $role
        }
    })
    $targetListener = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.local_port -eq $TargetPort -and $_.state -eq "Listen"
    }).Count
    $targetAccepted = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.local_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    $pressureLogical = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.remote_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    $clientUnderlay = @($rows | Where-Object {
        $_.owning_process -eq $candidatePid -and $_.remote_port -eq $GatePort -and $_.state -eq "Established"
    }).Count
    $serverRelay = @($rows | Where-Object {
        $serverPids -contains $_.owning_process -and $_.remote_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    return [ordered]@{
        rows = $rows
        assertions = [ordered]@{
            target_listener = $targetListener
            target_accepted = $targetAccepted
            pressure_logical = $pressureLogical
            client_underlay = $clientUnderlay
            server_relay = $serverRelay
        }
    }
}

function Get-Tcp08LiveEvidence(
    [string]$Phase,
    [string]$Target,
    [int]$TargetPort,
    [int]$GatePort,
    [int]$ServerPort,
    [int]$MetricsPort,
    [System.Diagnostics.Process]$CandidateProcess,
    [object]$Pressure,
    [Threading.Tasks.Task]$PressureWrite,
    [Ferrum2TcpProbe]$TargetProbe,
    [Ferrum2TcpGate]$Gate,
    [int]$GateIndex
) {
    $captured = Get-Tcp08MonotonicSample
    $CandidateProcess.Refresh()
    $gateObservation = $Gate.Observation($GateIndex)
    $connections = Get-Tcp08ConnectionEvidence $Target $TargetPort $GatePort $ServerPort $CandidateProcess
    $pressureAvailable = try { $Pressure.Client.Client.Available } catch { $null }
    return [ordered]@{
        phase = $Phase
        monotonic_ticks = $captured.monotonic_ticks
        elapsed_ms = $captured.elapsed_ms
        candidate = [ordered]@{
            process_id = [uint32]$CandidateProcess.Id
            has_exited = $CandidateProcess.HasExited
        }
        pressure_client = [ordered]@{
            socket_open = Test-Tcp08ClientSocketOpen $Pressure.Client
            connected_property = $Pressure.Client.Connected
            local_endpoint = Get-Tcp08Endpoint $Pressure.Client $true
            remote_endpoint = Get-Tcp08Endpoint $Pressure.Client $false
            available_bytes = $pressureAvailable
        }
        pressure_write = [ordered]@{
            task_id = if ($PressureWrite) { $PressureWrite.Id } else { $null }
            status = if ($PressureWrite) { $PressureWrite.Status.ToString() } else { "missing" }
            is_completed = if ($PressureWrite) { $PressureWrite.IsCompleted } else { $null }
            is_faulted = if ($PressureWrite) { $PressureWrite.IsFaulted } else { $null }
            is_canceled = if ($PressureWrite) { $PressureWrite.IsCanceled } else { $null }
        }
        target = [ordered]@{
            listener_active = $TargetProbe.ListenerActive
            accepted_socket_connected = $TargetProbe.AcceptedSocketConnected
            accepted_socket_open = $TargetProbe.AcceptedSocketOpen
            accepted_socket_available_bytes = $TargetProbe.AcceptedSocketAvailable
            accepted_socket_local_endpoint = $TargetProbe.AcceptedSocketLocalEndpoint
            accepted_socket_remote_endpoint = $TargetProbe.AcceptedSocketRemoteEndpoint
            read_attempts = $TargetProbe.ReadAttempts
            stall_wait_active = $TargetProbe.StallWaitActive
            worker_status = $TargetProbe.WorkerStatus
            session_complete = $TargetProbe.SessionComplete
            fault = $TargetProbe.Fault
        }
        gate = if ($gateObservation) {
            [ordered]@{
                session_index = $GateIndex
                client_to_server_bytes = $gateObservation.ClientToServerBytes
                client_to_server_stage = $gateObservation.ClientToServerStage
                client_to_server_eof = $gateObservation.ClientToServerEof
                client_to_server_fault = $gateObservation.ClientToServerFault
                server_to_client_bytes = $gateObservation.ServerToClientBytes
                server_to_client_stage = $gateObservation.ServerToClientStage
                server_to_client_eof = $gateObservation.ServerToClientEof
                server_to_client_fault = $gateObservation.ServerToClientFault
                session_complete = $gateObservation.SessionComplete
            }
        } else { $null }
        metrics = if ($Phase -in @("during_grace", "after_process_exit")) {
            [ordered]@{
                available = $false
                required = [bool]$script:RequireTcp08ProductMetrics
                unavailable_after_quiesce_expected = $true
                failure_type = "not_queried_after_process_quiesce"
                owner_counts = $null
                samples = @()
            }
        } else { Get-Tcp08MetricEvidence $MetricsPort }
        connections = $connections
    }
}

function Wait-Ipv4SystemRouteSnapshot([string[]]$Expected) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $actual = @(Get-Ipv4SystemRouteSnapshot)
        if (@(Compare-Object -ReferenceObject @($Expected) -DifferenceObject $actual).Count -eq 0) { return }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-SnapshotEqual $Expected $actual "system IPv4 route cleanup"
}

function Set-CapabilityDns([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityDnsApplied) "capability DNS is already applied"
    $script:capabilityDnsSnapshot = @(Get-TunIpv4Dns $InterfaceIndex)
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses "198.18.0.1" -Validate -ErrorAction Stop
    $script:capabilityDnsApplied = $true
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS readback"
}

function Restore-CapabilityDns([int]$InterfaceIndex) {
    if (-not $script:capabilityDnsApplied) { return }
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS ownership"
    if ($script:capabilityDnsSnapshot.Count -eq 0) {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $script:capabilityDnsSnapshot -Validate -ErrorAction Stop
    }
    Assert-SnapshotEqual @($script:capabilityDnsSnapshot) @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS restore"
    $script:capabilityDnsApplied = $false
    $script:capabilityDnsSnapshot = $null
}

function Set-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityMetricApplied) "capability interface metric is already applied"
    $row = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricSnapshot = [pscustomobject]@{
        AutomaticMetric = [string]$row.AutomaticMetric
        InterfaceMetric = [uint32]$row.InterfaceMetric
    }
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricApplied = $true
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric readback mismatch"
}

function Restore-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    if (-not $script:capabilityMetricApplied) { return }
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric ownership changed"
    if ($script:capabilityMetricSnapshot.AutomaticMetric -ceq "Enabled") {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -AutomaticMetric Enabled -PolicyStore ActiveStore -ErrorAction Stop
    } else {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -AutomaticMetric Disabled -InterfaceMetric $script:capabilityMetricSnapshot.InterfaceMetric `
            -PolicyStore ActiveStore -ErrorAction Stop
    }
    $restored = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $metricMatches = ($script:capabilityMetricSnapshot.AutomaticMetric -ceq "Enabled") -or
        ([uint32]$restored.InterfaceMetric -eq $script:capabilityMetricSnapshot.InterfaceMetric)
    Assert-True ([string]$restored.AutomaticMetric -ceq $script:capabilityMetricSnapshot.AutomaticMetric -and
        $metricMatches) "capability interface metric restore mismatch"
    $script:capabilityMetricApplied = $false
    $script:capabilityMetricSnapshot = $null
}

function Remove-CapabilityRoutes {
    for ($index = $script:capabilityRoutes.Count - 1; $index -ge 0; $index--) {
        $script:capabilityRoutes[$index].Dispose()
        $script:capabilityRoutes.RemoveAt($index)
    }
}

function Get-PktMonDirectProperties([object]$Record) {
    $propertyField = $Record.PSObject.Properties["Properties"]
    Assert-True ($null -ne $propertyField -and $propertyField.Value -is [Array]) "PktMon component properties are invalid"
    $result = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($property in @($propertyField.Value)) {
        Assert-True ((@($property.PSObject.Properties.Name) -join "|") -ceq "Name|Value") "PktMon component property shape is invalid"
        $name = [string]$property.Name
        Assert-True (-not [string]::IsNullOrWhiteSpace($name)) "PktMon component property name is invalid"
        if ($name -ceq "ifIndex" -or $name -ceq "ifGuid") {
            Assert-True (-not $result.ContainsKey($name)) "PktMon identity property is duplicated"
            $result.Add($name, $property.Value)
        }
    }
    return $result
}

function Get-PktMonComponentId([object]$Adapter) {
    $text = (Invoke-PktMon @("list", "--json")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon component JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon component JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon component groups are empty"
    $interfaceGuid = [guid]::Empty
    Assert-True ([guid]::TryParse([string]$Adapter.InterfaceGuid, [ref]$interfaceGuid)) "owned adapter GUID is invalid"
    $expectedDriver = $null
    if ($null -ne $Adapter.PSObject.Properties["DriverFileName"] -and
        -not [string]::IsNullOrWhiteSpace([string]$Adapter.DriverFileName)) {
        $expectedDriver = [IO.Path]::GetFileName([string]$Adapter.DriverFileName)
    }
    $recordsById = @{}
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon component group shape is invalid"
        foreach ($record in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $record.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$record.Id, [ref]$id) -and $id -gt 0) "PktMon component Id is invalid"
            [void](Get-PktMonDirectProperties $record)
            if (-not $recordsById.ContainsKey($id)) { $recordsById[$id] = [Collections.Generic.List[object]]::new() }
            $recordsById[$id].Add($record)
        }
    }
    $matches = [Collections.Generic.List[int]]::new()
    foreach ($entry in $recordsById.GetEnumerator()) {
        $hasIdentityRecord = $false
        $hasDriver = $null -eq $expectedDriver
        foreach ($record in $entry.Value) {
            $properties = Get-PktMonDirectProperties $record
            $recordIndexMatches = $false
            $recordGuidMatches = $false
            if ($properties.ContainsKey("ifIndex")) {
                [int]$ifIndex = 0
                Assert-True ([int]::TryParse([string]$properties["ifIndex"], [ref]$ifIndex)) "PktMon ifIndex is invalid"
                $recordIndexMatches = $ifIndex -eq [int]$Adapter.ifIndex
            }
            if ($properties.ContainsKey("ifGuid")) {
                $ifGuid = [guid]::Empty
                Assert-True ([guid]::TryParse([string]$properties["ifGuid"], [ref]$ifGuid)) "PktMon ifGuid is invalid"
                $recordGuidMatches = $ifGuid -eq $interfaceGuid
            }
            if ($recordIndexMatches -and $recordGuidMatches) { $hasIdentityRecord = $true }
            if ($null -ne $expectedDriver -and $null -ne $record.PSObject.Properties["DriverName"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.DriverName) -and
                [IO.Path]::GetFileName([string]$record.DriverName) -ieq $expectedDriver) {
                $hasDriver = $true
            }
        }
        if ($hasIdentityRecord -and $hasDriver) { $matches.Add([int]$entry.Key) }
    }
    Assert-True ($matches.Count -eq 1) "owned Wintun PktMon component is ambiguous"
    return $matches[0]
}

function Wait-PktMonFlowPacketsAfter([uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    $quiet = [Diagnostics.Stopwatch]::StartNew()
    [uint64]$last = $Before
    $observed = $false
    do {
        $after = Get-PktMonFlowPackets
        Assert-True ($after -ge $last) "PktMon flow counter regressed"
        if ($after -gt $Before) {
            if (-not $observed -or $after -ne $last) {
                $observed = $true
                $quiet.Restart()
            } elseif ($quiet.ElapsedMilliseconds -ge 500) {
                return [uint64]($after - $Before)
            }
        }
        $last = $after
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "filtered unpinned flow did not enter Wintun"
}
