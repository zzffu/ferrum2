function Invoke-Tcp08(
    [string]$Target,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate]$Gate,
    [int]$GatePort,
    [int]$ServerPort,
    [int]$MetricsPort,
    [bool]$CollectPerformance
) {
    $pressure = $null
    $pressureWrite = $null
    $stall = $null
    $pressureClientOwned = $false
    try {
        $pressureGate = $Gate.Accepted + 1
        $pressure = Open-TunTcp $Target $Port $InterfaceIndex
        $script:tcpResources.Add([IDisposable]$pressure.Client)
        $pressureClientOwned = $true
        Assert-True ($Gate.WaitAccepted($pressureGate, 5000)) "backpressure route did not open"
        $stall = [Ferrum2TcpProbe]::new($Target, $Port, "stall")
        $script:tcpResources.Add($stall)
        Add-Tcp08Event "pressure_listener_started" ([ordered]@{
            target = $Target
            port = $Port
            listener_active = $stall.ListenerActive
        })
        $Gate.Release($pressureGate)
        Assert-True ($stall.WaitAccepted(5000)) "backpressure target was not opened"
        Add-Tcp08Event "pressure_target_accepted" ([ordered]@{
            local_endpoint = $stall.AcceptedSocketLocalEndpoint
            remote_endpoint = $stall.AcceptedSocketRemoteEndpoint
        })
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and
            $stall.StallWaitActive -and $stall.ReadAttempts -eq 0) "backpressure target was not stably non-reading before pressure write"

        $pressureChunk = [byte[]]::new(1024 * 1024)
        $pressureStream = $pressure.Client.GetStream()
        Add-Tcp08Event "pressure_write_started" ([ordered]@{
            pressure_gate_index = $pressureGate
            chunk_bytes = $pressureChunk.Length
            attempt_limit = 128
            target_accepted_before_write = $true
        })
        $pendingAttempt = $null
        for ($attempt = 0; $attempt -lt 128; $attempt++) {
            $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            if (-not $pressureWrite.Wait(100)) {
                $pendingAttempt = $attempt + 1
                break
            }
        }
        Assert-True ($pressureWrite -and -not $pressureWrite.IsCompleted) "backpressure write unexpectedly drained"
        Add-Tcp08Event "pressure_write_became_pending" ([ordered]@{
            attempt = $pendingAttempt
            task_id = $pressureWrite.Id
            task_status = $pressureWrite.Status.ToString()
            observation_wait_ms = 100
        })
        if ($CollectPerformance) { Complete-PerformanceSample $script:activeProcess $MetricsPort }

        $beforeSignal = $null
        while (-not $beforeSignal) {
            while ($pressureWrite.Wait($script:tcp08PressureStableWaitMilliseconds)) {
                Assert-True ($pendingAttempt -lt 128) "TCP-08 pressure write never became stably pending"
                $pendingAttempt++
                $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            }
            Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressure write did not remain pending for the stable observation window"
            Add-Tcp08Event "pressure_write_stably_pending" ([ordered]@{
                phase = "before_live_evidence"
                attempt = $pendingAttempt
                task_id = $pressureWrite.Id
                task_status = $pressureWrite.Status.ToString()
                observation_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            })
            $evidenceCandidate = Get-Tcp08LiveEvidence "before_ctrl_break" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
            if (-not $evidenceCandidate.pressure_write.is_completed) {
                $beforeSignal = $evidenceCandidate
            } else {
                Add-Tcp08Event "pressure_write_completed_during_live_evidence" ([ordered]@{
                    attempt = $pendingAttempt
                    task_id = $pressureWrite.Id
                    task_status = $pressureWrite.Status.ToString()
                })
            }
        }
        $script:tcp08Samples.Add($beforeSignal)
        if ($RequireTcp08ProductMetrics -or $beforeSignal.metrics.available) {
            Assert-Tcp08ProductOwnerMetrics $beforeSignal.metrics "before CTRL_BREAK"
        }
        Assert-True $beforeSignal.pressure_client.socket_open "TCP-08 pressure client socket was not open before CTRL_BREAK"
        Assert-True (-not $beforeSignal.pressure_write.is_completed) "TCP-08 pressure write was not pending before CTRL_BREAK"
        Assert-True ($beforeSignal.target.listener_active -and $beforeSignal.target.accepted_socket_open -and
            $beforeSignal.target.stall_wait_active -and $beforeSignal.target.read_attempts -eq 0) "TCP-08 target was not an open non-reading peer before CTRL_BREAK"
        foreach ($name in @("target_listener", "target_accepted", "pressure_logical", "client_underlay", "server_relay")) {
            Assert-True ($beforeSignal.connections.assertions[$name] -gt 0) "TCP-08 socket ownership witness missing before CTRL_BREAK: $name"
        }

        if ($script:tcp08Enabled) {
            $shutdownReportPath = Join-Path $script:tcp08ArtifactPath "client.stderr.log"
            $reportSnapshotBeforeSignal = Get-Tcp08SharedLogSnapshot $shutdownReportPath "before_ctrl_break"
            Add-Tcp08Event "shutdown_report_candidate_window_opened" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                capture_phase = $reportSnapshotBeforeSignal.capture_phase
                byte_length = $reportSnapshotBeforeSignal.byte_length
                complete_byte_length = $reportSnapshotBeforeSignal.complete_byte_length
                trailing_partial_byte_count = $reportSnapshotBeforeSignal.trailing_partial_byte_count
                complete_line_count = $reportSnapshotBeforeSignal.complete_line_count
                lower_exclusive_candidate_ordinal = $reportSnapshotBeforeSignal.candidate_count
            })
        }

        while ($pressureWrite.Wait($script:tcp08PressureStableWaitMilliseconds)) {
            Assert-True ($pendingAttempt -lt 128) "TCP-08 pressure write never became stably pending"
            $pendingAttempt++
            $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
        }
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressure write did not remain pending for the stable observation window"
        Assert-True (Test-Tcp08ClientSocketOpen $pressure.Client) "TCP-08 pressure client socket closed before CTRL_BREAK"
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and $stall.StallWaitActive -and
            $stall.ReadAttempts -eq 0) "TCP-08 target stopped being an open non-reading peer before CTRL_BREAK"
        Add-Tcp08Event "pressure_write_stably_pending" ([ordered]@{
            phase = "before_ctrl_break"
            attempt = $pendingAttempt
            task_id = $pressureWrite.Id
            task_status = $pressureWrite.Status.ToString()
            observation_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            local_endpoint = Get-Tcp08Endpoint $pressure.Client $true
            remote_endpoint = Get-Tcp08Endpoint $pressure.Client $false
        })
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 stable pressure write completed before CTRL_BREAK dispatch"

        $forcedShutdown = [Diagnostics.Stopwatch]::StartNew()
        $breakResult = [Ferrum2ProcessGroup]::BreakDetailed([uint32]$script:activeProcess.Id)
        $script:tcp08CtrlBreak = Convert-Tcp08CtrlBreakResult $breakResult
        if ($breakResult.SendStartedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_send_started" $breakResult.SendStartedTimestamp ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                source = "Ferrum2ProcessGroup.BreakDetailed"
            })
        }
        if ($breakResult.SendReturnedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_send_returned" $breakResult.SendReturnedTimestamp ([ordered]@{
                generate_console_ctrl_event_result = $breakResult.GenerateConsoleCtrlEventResult
                win32_error = $breakResult.GenerateConsoleCtrlEventWin32Error
                send_duration_ms = [Math]::Round($breakResult.SendDurationMilliseconds, 3)
            })
        }
        if ($breakResult.InternalWaitStartedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_internal_wait_started" $breakResult.InternalWaitStartedTimestamp ([ordered]@{
                configured_wait_ms = 250
            })
        }
        if ($breakResult.InternalWaitReturnedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_internal_wait_returned" $breakResult.InternalWaitReturnedTimestamp ([ordered]@{
                measured_wait_ms = [Math]::Round($breakResult.InternalWaitMilliseconds, 3)
            })
        }
        Add-Tcp08Event "ctrl_break_call_returned" $script:tcp08CtrlBreak
        Assert-True $breakResult.Succeeded "TCP-08 CTRL_BREAK delivery failed"
        $exitedDuringGrace = [Ferrum2ProcessGroup]::Wait([uint32]$script:activeProcess.Id, 300)
        Add-Tcp08Event "grace_probe_completed" ([ordered]@{
            wait_ms = 300
            process_exited = $exitedDuringGrace
            pressure_write_pending = -not $pressureWrite.IsCompleted
            pressure_write_attempt = $pendingAttempt
            pressure_write_task_id = $pressureWrite.Id
            target_socket_open = $stall.AcceptedSocketOpen
        })
        if ($exitedDuringGrace) {
            Add-Tcp08Event "process_exited" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                observation = "controller_grace_probe"
                elapsed_since_ctrl_break_call_ms = [Math]::Round($forcedShutdown.Elapsed.TotalMilliseconds, 3)
            })
            $script:tcp08ExitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$script:activeProcess.Id)
            Add-Tcp08Event "process_exit_code" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                exit_code = $script:tcp08ExitCode
            })
        }
        Assert-True (-not $exitedDuringGrace) "TCP-08 exited during grace"
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressured flow was not owned through grace"
        Assert-True (Test-Tcp08ClientSocketOpen $pressure.Client) "TCP-08 pressure client socket closed during grace"
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and $stall.StallWaitActive -and
            $stall.ReadAttempts -eq 0) "TCP-08 target did not remain an open non-reading peer through grace"
        $duringGrace = Get-Tcp08LiveEvidence "during_grace" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
        $script:tcp08Samples.Add($duringGrace)
        if ($duringGrace.metrics.available) {
            Assert-Tcp08ProductOwnerMetrics $duringGrace.metrics "during grace"
        } else {
            Assert-True $duringGrace.metrics.unavailable_after_quiesce_expected "TCP-08 owner metric loss during grace was not classified"
            Add-Tcp08Event "product_owner_metrics_unavailable_after_quiesce" ([ordered]@{
                expected = $true
                required_before_ctrl_break = [bool]$RequireTcp08ProductMetrics
                failure_type = $duringGrace.metrics.failure_type
            })
        }

        Assert-True (Wait-ProcessExit $script:activeProcess 10) "TCP-08 forced cancellation did not exit"
        $forcedShutdown.Stop()
        Add-Tcp08Event "process_exited" ([ordered]@{
            process_id = [uint32]$script:activeProcess.Id
            observation = "controller_exit_wait"
            elapsed_since_ctrl_break_call_ms = [Math]::Round($forcedShutdown.Elapsed.TotalMilliseconds, 3)
        })
        $script:tcp08ExitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$script:activeProcess.Id)
        Add-Tcp08Event "process_exit_code" ([ordered]@{
            process_id = [uint32]$script:activeProcess.Id
            exit_code = $script:tcp08ExitCode
        })
        if ($script:tcp08Enabled) {
            $reportSnapshotAfterExit = Get-Tcp08SharedLogSnapshot $shutdownReportPath "after_process_exit"
            $script:tcp08ShutdownReportCandidateWindow = [ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                lower_exclusive_candidate_ordinal = $reportSnapshotBeforeSignal.candidate_count
                upper_inclusive_candidate_ordinal = $reportSnapshotAfterExit.candidate_count
                candidate_delta = $reportSnapshotAfterExit.candidate_count - $reportSnapshotBeforeSignal.candidate_count
                lower_capture = [ordered]@{
                    capture_phase = $reportSnapshotBeforeSignal.capture_phase
                    byte_length = $reportSnapshotBeforeSignal.byte_length
                    complete_byte_length = $reportSnapshotBeforeSignal.complete_byte_length
                    trailing_partial_byte_count = $reportSnapshotBeforeSignal.trailing_partial_byte_count
                    complete_line_count = $reportSnapshotBeforeSignal.complete_line_count
                }
                upper_capture = [ordered]@{
                    capture_phase = $reportSnapshotAfterExit.capture_phase
                    byte_length = $reportSnapshotAfterExit.byte_length
                    complete_byte_length = $reportSnapshotAfterExit.complete_byte_length
                    trailing_partial_byte_count = $reportSnapshotAfterExit.trailing_partial_byte_count
                    complete_line_count = $reportSnapshotAfterExit.complete_line_count
                }
            }
            Add-Tcp08Event "shutdown_report_candidate_window_frozen" $script:tcp08ShutdownReportCandidateWindow
        }
        Assert-True ($forcedShutdown.ElapsedMilliseconds -ge 900) "TCP-08 force preceded the grace deadline"
        if ($script:RequireTcp08ProductMetrics) {
            Assert-True ($script:tcp08ShutdownReportCandidateWindow.candidate_delta -eq 1) "TCP-08 strict shutdown-report candidate delta was not one"
        }
        Assert-True ($script:tcp08ExitCode -eq 0) "TCP-08 forced shutdown was not clean: exit=$($script:tcp08ExitCode)"
        $afterExit = Get-Tcp08LiveEvidence "after_process_exit" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
        $script:tcp08Samples.Add($afterExit)
        if ($CollectPerformance) { $script:performanceForceDrain = $true }
        [Ferrum2ProcessGroup]::Close([uint32]$script:activeProcess.Id)
        $script:activeProcess = $null
    } catch {
        $script:tcp08Result = "FAIL"
        Add-Tcp08Event "tcp08_failed" ([ordered]@{
            failure_type = $_.Exception.GetType().FullName
            failure = $_.Exception.Message
        })
        throw
    } finally {
        $pressureCleanupFailures = [Collections.Generic.List[Exception]]::new()
        if ($pressureClientOwned -and $pressure) {
            try { $pressure.Client.Dispose() }
            catch { $pressureCleanupFailures.Add($_.Exception) }
        }
        if ($pressureWrite) {
            try {
                $pressureWriteCleanup = Complete-Tcp08PressureWriteCleanup $pressureWrite
                Add-Tcp08Event "pressure_write_cleanup_completed" $pressureWriteCleanup
            } catch {
                $pressureCleanupFailures.Add($_.Exception)
            }
        }
        if ($pressureClientOwned -and $pressure) {
            try {
                Assert-True $script:tcpResources.Remove([IDisposable]$pressure.Client) "TCP-08 pressure client ownership mismatch"
                $pressureClientOwned = $false
            } catch {
                $pressureCleanupFailures.Add($_.Exception)
            }
        }
        if (-not $pressureClientOwned -and $pressure) { $pressure = $null }
        if ($pressureCleanupFailures.Count -eq 1) { throw $pressureCleanupFailures[0] }
        if ($pressureCleanupFailures.Count -gt 1) {
            throw [AggregateException]::new("TCP-08 pressure writer cleanup failed", $pressureCleanupFailures.ToArray())
        }
    }

    try {
        Wait-AdapterAbsent $script:adapterName
        Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
        Add-Tcp08Event "adapter_absent" ([ordered]@{ interface_index = $script:ownedInterfaceIndex })
        $script:tcp08Result = "PASS"
    } catch {
        $script:tcp08Result = "FAIL"
        Add-Tcp08Event "tcp08_failed" ([ordered]@{
            failure_type = $_.Exception.GetType().FullName
            failure = $_.Exception.Message
        })
        throw
    }
}
