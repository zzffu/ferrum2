function Get-Tcp08ProductTransition([object]$Report, [string]$State) {
    $matches = @($Report.process_transitions | Where-Object { $_.state -ceq $State })
    Assert-True ($matches.Count -le 1) "validated process report contains duplicate $State transitions"
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Get-Tcp08SharedLogSnapshot([string]$Path, [string]$CapturePhase) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            capture_phase = $CapturePhase
            byte_length = [int64]0
            complete_byte_length = [int64]0
            trailing_partial_byte_count = [int64]0
            complete_line_count = 0
            candidate_count = 0
            lines = @()
        }
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $byteLength = $stream.Length
        Assert-True ($byteLength -le [int]::MaxValue) "TCP-08 client stderr is too large to snapshot"
        $bytes = [byte[]]::new([int]$byteLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { break }
            $offset += $read
        }
    } finally { $stream.Dispose() }
    $lastLf = -1
    for ($index = $offset - 1; $index -ge 0; $index--) {
        if ($bytes[$index] -eq 10) { $lastLf = $index; break }
    }
    $completeByteLength = $lastLf + 1
    $candidateCount = 0
    if ($completeByteLength -gt 0) {
        $text = [Text.Encoding]::UTF8.GetString($bytes, 0, $completeByteLength)
        $rawLines = $text.Split([char]10)
        for ($index = 0; $index -lt $rawLines.Length - 1; $index++) {
            $line = $rawLines[$index].TrimEnd([char]13)
            $lines.Add($line)
            if ($line -match '"event"\s*:\s*"process_shutdown_report"') { $candidateCount++ }
        }
    }
    return [pscustomobject][ordered]@{
        capture_phase = $CapturePhase
        byte_length = [int64]$offset
        complete_byte_length = [int64]$completeByteLength
        trailing_partial_byte_count = [int64]($offset - $completeByteLength)
        complete_line_count = $lines.Count
        candidate_count = $candidateCount
        lines = $lines.ToArray()
    }
}

function Get-Tcp08ForcedReportAssessment(
    [object]$Report,
    [int]$RecordIndex,
    [int]$StderrLine,
    [int]$CandidateOrdinal
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    $activeTransition = Get-Tcp08ProductTransition $Report "Active"
    $forcedTransition = Get-Tcp08ProductTransition $Report "Forced"
    $quiescingTransition = Get-Tcp08ProductTransition $Report "Quiescing"
    $drainingTransition = Get-Tcp08ProductTransition $Report "Draining"
    $stoppedTransition = Get-Tcp08ProductTransition $Report "Stopped"
    $forcedIntent = $null -ne $forcedTransition -or $Report.forced_root_count -gt 0 -or
        @($Report.root_exit_events | Where-Object { $_.phase -in @("Forced", "WatchdogAbort") }).Count -gt 0
    if (-not $forcedIntent) {
        return [ordered]@{
            record_index = $RecordIndex
            stderr_line = $StderrLine
            candidate_ordinal = $CandidateOrdinal
            classification = "allowed_non_forced_report"
            selection_reason = "no_forced_state_count_or_root_event"
            failures = @()
            product_timeline_events = @()
        }
    }

    if ($null -eq $forcedTransition) { $failures.Add("missing_Forced_transition") }
    if ($null -eq $activeTransition) { $failures.Add("missing_Active_transition") }
    if ($null -eq $quiescingTransition) { $failures.Add("missing_Quiescing_transition") }
    if ($null -eq $drainingTransition) { $failures.Add("missing_Draining_transition") }
    if ($null -eq $stoppedTransition) { $failures.Add("missing_Stopped_transition") }
    $expectedForcedStates = @("Validated", "Preparing", "Prepared", "Active", "Quiescing", "Draining", "Forced", "Stopped")
    if ((@($Report.process_states) -join "|") -cne ($expectedForcedStates -join "|")) {
        $failures.Add("forced_process_state_sequence_not_canonical")
    }
    foreach ($state in @("Active", "Quiescing", "Draining", "Forced", "Stopped")) {
        if (@($Report.process_states | Where-Object { $_ -ceq $state }).Count -ne 1 -or
            @($Report.process_transitions | Where-Object { $_.state -ceq $state }).Count -ne 1) {
            $failures.Add("forced_process_state_count_not_one_$state")
        }
    }
    if ($null -ne $activeTransition -and $null -ne $quiescingTransition -and
        $null -ne $drainingTransition -and $null -ne $forcedTransition -and $null -ne $stoppedTransition) {
        $requiredOrder = @("Active", "Quiescing", "Draining", "Forced", "Stopped")
        $requiredIndexes = @($requiredOrder | ForEach-Object { [Array]::IndexOf([object[]]$Report.process_states, $_) })
        if ($requiredIndexes[0] -ge $requiredIndexes[1] -or
            $requiredIndexes[1] -ge $requiredIndexes[2] -or
            $requiredIndexes[2] -ge $requiredIndexes[3] -or
            $requiredIndexes[3] -ge $requiredIndexes[4]) {
            $failures.Add("forced_process_state_order_not_Active_Quiescing_Draining_Forced_Stopped")
        }
    }
    if ($Report.forced_root_count -le 0) { $failures.Add("forced_root_count_not_positive") }
    if ($Report.termination_cause -cne "ExternalShutdown") { $failures.Add("termination_cause_not_ExternalShutdown") }
    if ($null -ne $Report.root -or $null -ne $Report.root_exit_category -or $null -ne $Report.root_error_category) {
        $failures.Add("ExternalShutdown_report_has_primary_root_exit")
    }
    if ($null -ne $Report.cleanup_failure) { $failures.Add("cleanup_failure_present") }
    if ($null -eq $Report.actual_grace_deadline_elapsed_ns -or
        $Report.actual_grace_deadline_source -cne "runtime_process_supervisor") {
        $failures.Add("actual_runtime_grace_deadline_unavailable")
    }
    $tunEvents = @($Report.root_exit_events | Where-Object { $_.root.name -ceq "tun" })
    if ($tunEvents.Count -ne 1) {
        $failures.Add("stable_tun_root_event_count_not_one")
    } elseif ($tunEvents[0].phase -cne "Forced") {
        $failures.Add("stable_tun_root_not_cleanly_reaped_in_Forced_phase")
    } elseif ($tunEvents[0].exit_category -cne "Completed") {
        $failures.Add("stable_tun_root_exit_not_Completed")
    }
    $activeOwnerNames = @(
        "process_supervisors", "prepared_process_roots", "active_process_roots",
        "active_tun_tcp_flows", "active_tun_handler_tasks", "active_supervisor_children",
        "connection_tasks", "owned_buffers", "owned_permits", "listeners", "udp_sessions",
        "udp_sockets", "udp_tasks", "udp_queued_datagrams", "udp_buffered_bytes",
        "udp_scratch_buffers", "sniff_buffered_bytes", "network_reset_hooks",
        "network_runtime_owners", "network_reset_drivers"
    )
    foreach ($name in $activeOwnerNames) {
        if ($Report.owner_stopped.$name -ne $Report.owner_baseline.$name -or $Report.owner_delta.$name -ne 0) {
            $failures.Add("active_owner_not_returned_to_baseline_$name")
        }
    }
    foreach ($name in @("active_process_roots", "active_tun_tcp_flows", "active_tun_handler_tasks")) {
        if ($Report.owner_baseline.$name -ne 0 -or $Report.owner_stopped.$name -ne 0) {
            $failures.Add("required_active_owner_not_zero_$name")
        }
    }
    foreach ($name in @("process_root_reaps", "process_root_rollbacks", "process_forced_roots", "forced_shutdowns", "udp_forced_shutdowns")) {
        if ($Report.owner_delta.$name -lt 0) { $failures.Add("cumulative_owner_delta_negative_$name") }
    }
    if ($Report.owner_delta.process_forced_roots -le 0) { $failures.Add("process_forced_roots_delta_not_positive") }
    if ($Report.owner_delta.process_root_reaps -le 0) { $failures.Add("process_root_reaps_delta_not_positive") }
    if ($Report.owner_delta.process_forced_roots -ne $Report.forced_root_count) { $failures.Add("process_forced_roots_delta_count_mismatch") }
    if ($null -ne $Report.actual_grace_deadline_elapsed_ns) {
        if ($Report.actual_grace_deadline_elapsed_ns -gt $Report.report_elapsed_ns) {
            $failures.Add("grace_deadline_later_than_report")
        }
        if ($Report.actual_grace_deadline_elapsed_ns -lt $Report.shutdown_grace_ns) {
            $failures.Add("grace_deadline_precedes_configured_grace_origin")
        }
        if ($null -ne $drainingTransition -and
            ($Report.actual_grace_deadline_elapsed_ns - $Report.shutdown_grace_ns) -lt $drainingTransition.elapsed_ns) {
            $failures.Add("grace_deadline_creation_precedes_Draining_transition")
        }
        if ($null -ne $forcedTransition -and
            $forcedTransition.elapsed_ns -lt $Report.actual_grace_deadline_elapsed_ns) {
            $failures.Add("Forced_transition_precedes_grace_deadline")
        }
        if ($tunEvents.Count -eq 1 -and
            $tunEvents[0].elapsed_ns -lt $Report.actual_grace_deadline_elapsed_ns) {
            $failures.Add("stable_tun_root_event_precedes_grace_deadline")
        }
    }
    if ($null -ne $stoppedTransition) {
        if ($stoppedTransition.elapsed_ns -ne $Report.report_elapsed_ns) {
            $failures.Add("Stopped_transition_report_elapsed_mismatch")
        }
        if (@($Report.root_exit_events | Where-Object { $_.elapsed_ns -gt $stoppedTransition.elapsed_ns }).Count -gt 0) {
            $failures.Add("root_exit_event_later_than_Stopped_transition")
        }
    }

    $classification = if ($failures.Count -eq 0) { "tcp08_forced_candidate" } else { "incomplete_forced_report" }
    $selectionReason = if ($failures.Count -eq 0) {
        "closed_forced_state_positive_forced_count_actual_deadline_and_stable_tun_root_event"
    } else { "forced_intent_failed_closed_tcp08_criteria" }
    $productEvents = [System.Collections.Generic.List[object]]::new()
    if ($failures.Count -eq 0) {
        $productEvents.Add([ordered]@{
            name = "shutdown_signal_observed"
            source_ordinal = 1
            elapsed_ns = $quiescingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Quiescing_transition_upper_bound"
        })
        $productEvents.Add([ordered]@{
            name = "quiescing_started"
            source_ordinal = 2
            elapsed_ns = $quiescingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Quiescing_transition"
        })
        $productEvents.Add([ordered]@{
            name = "draining_started"
            source_ordinal = 3
            elapsed_ns = $drainingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Draining_transition"
        })
        $productEvents.Add([ordered]@{
            name = "grace_deadline_created"
            source_ordinal = 4
            elapsed_ns = [uint64]($Report.actual_grace_deadline_elapsed_ns - $Report.shutdown_grace_ns)
            clock_domain = "product_process_relative"
            timestamp_source = "actual_grace_deadline_elapsed_ns_minus_shutdown_grace_ns"
            deadline_elapsed_ns = $Report.actual_grace_deadline_elapsed_ns
        })
        $productEvents.Add([ordered]@{
            name = "forced_started"
            source_ordinal = 5
            elapsed_ns = $forcedTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Forced_transition"
        })
        $rootEventOrdinal = 6
        foreach ($rootEvent in $Report.root_exit_events) {
            $productEvents.Add([ordered]@{
                name = "root_exit_observed"
                source_ordinal = $rootEventOrdinal
                elapsed_ns = $rootEvent.elapsed_ns
                clock_domain = "product_process_relative"
                timestamp_source = "root_exit_events"
                root = $rootEvent.root
                phase = $rootEvent.phase
                exit_category = $rootEvent.exit_category
            })
            $rootEventOrdinal++
        }
    }
    return [ordered]@{
        record_index = $RecordIndex
        stderr_line = $StderrLine
        candidate_ordinal = $CandidateOrdinal
        classification = $classification
        selection_reason = $selectionReason
        failures = $failures
        product_timeline_events = @($productEvents | Sort-Object elapsed_ns, source_ordinal)
    }
}

function Get-Tcp08ProductShutdownEvidence {
    $path = Join-Path $script:tcp08ArtifactPath "client.stderr.log"
    $reports = [System.Collections.Generic.List[object]]::new()
    $assessments = [System.Collections.Generic.List[object]]::new()
    $invalidRecordDetails = [System.Collections.Generic.List[object]]::new()
    $invalidRecords = 0
    $candidateLines = 0
    $lineNumber = 0
    $readFailureType = $null
    $logSnapshot = $null
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $logSnapshot = Get-Tcp08SharedLogSnapshot $path "artifact_finalization"
            foreach ($line in @($logSnapshot.lines)) {
                $lineNumber++
                if ($line -notmatch '"event"\s*:\s*"process_shutdown_report"') { continue }
                $candidateLines++
                $candidateOrdinal = $candidateLines
                try {
                    $parsed = $line | ConvertFrom-Json -Depth 16 -ErrorAction Stop
                    $report = ConvertTo-Tcp08ProductShutdownReport $parsed
                    $recordIndex = $reports.Count
                    $reports.Add($report)
                    $assessments.Add((Get-Tcp08ForcedReportAssessment $report $recordIndex $lineNumber $candidateOrdinal))
                } catch {
                    $invalidRecords++
                    $invalidRecordDetails.Add([ordered]@{
                        stderr_line = $lineNumber
                        candidate_ordinal = $candidateOrdinal
                        rejection = "invalid_closed_process_shutdown_report"
                        error_type = $_.Exception.GetType().FullName
                    })
                }
            }
        } catch { $readFailureType = $_.Exception.GetType().FullName }
    }
    $availability = if ($reports.Count -gt 0) { "available" }
        elseif ($readFailureType) { "read_failed" }
        elseif ($invalidRecords -gt 0) { "invalid" }
        else { "unavailable" }
    $unavailableReason = if ($availability -eq "unavailable") { "no_closed_process_shutdown_report_record" } else { $null }
    $allForcedMatches = @($assessments | Where-Object { $_.classification -ceq "tcp08_forced_candidate" })
    $allIncompleteForced = @($assessments | Where-Object { $_.classification -ceq "incomplete_forced_report" })
    $allAllowedNonForced = @($assessments | Where-Object { $_.classification -ceq "allowed_non_forced_report" })
    $selectionWindow = $script:tcp08ShutdownReportCandidateWindow
    $windowBoundsValid = $false
    $windowAssessments = @()
    $windowInvalidRecordDetails = @()
    $windowCandidateLines = 0
    if ($null -ne $selectionWindow) {
        $lowerExclusive = [int]$selectionWindow.lower_exclusive_candidate_ordinal
        $upperInclusive = [int]$selectionWindow.upper_inclusive_candidate_ordinal
        $windowBoundsValid = $lowerExclusive -ge 0 -and $upperInclusive -ge $lowerExclusive -and
            $upperInclusive -le $candidateLines
        if ($windowBoundsValid) {
            $windowAssessments = @($assessments | Where-Object {
                $_.candidate_ordinal -gt $lowerExclusive -and $_.candidate_ordinal -le $upperInclusive
            })
            $windowInvalidRecordDetails = @($invalidRecordDetails | Where-Object {
                $_.candidate_ordinal -gt $lowerExclusive -and $_.candidate_ordinal -le $upperInclusive
            })
            $windowCandidateLines = $windowAssessments.Count + $windowInvalidRecordDetails.Count
        }
    }
    $forcedMatches = @($windowAssessments | Where-Object { $_.classification -ceq "tcp08_forced_candidate" })
    $incompleteForced = @($windowAssessments | Where-Object { $_.classification -ceq "incomplete_forced_report" })
    $allowedNonForced = @($windowAssessments | Where-Object { $_.classification -ceq "allowed_non_forced_report" })
    $windowAvailability = if ($null -eq $selectionWindow) { "unavailable" }
        elseif (-not $windowBoundsValid) { "invalid" }
        elseif ($windowAssessments.Count -gt 0) { "available" }
        elseif ($windowInvalidRecordDetails.Count -gt 0) { "invalid" }
        else { "unavailable" }
    $strictFailures = [System.Collections.Generic.List[string]]::new()
    if ($script:RequireTcp08ProductMetrics) {
        if ($readFailureType) { $strictFailures.Add("client_stderr_read_failed") }
        if ($logSnapshot -and $logSnapshot.trailing_partial_byte_count -ne 0) { $strictFailures.Add("client_stderr_trailing_partial_record") }
        if ($invalidRecords -ne 0) { $strictFailures.Add("invalid_process_shutdown_report_records") }
        if ($allIncompleteForced.Count -ne 0) { $strictFailures.Add("incomplete_forced_reports_present") }
        if ($null -eq $selectionWindow) {
            $strictFailures.Add("tcp08_candidate_window_missing")
        } elseif (-not $windowBoundsValid) {
            $strictFailures.Add("tcp08_candidate_window_outside_client_stderr")
        } else {
            if ([int]$selectionWindow.candidate_delta -ne 1) { $strictFailures.Add("tcp08_candidate_window_delta_not_one") }
            if ($windowCandidateLines -ne [int]$selectionWindow.candidate_delta) { $strictFailures.Add("tcp08_candidate_window_observation_mismatch") }
            if ($windowAssessments.Count -ne 1) { $strictFailures.Add("tcp08_candidate_window_valid_record_count_not_one") }
        }
        if ($forcedMatches.Count -eq 0) { $strictFailures.Add("tcp08_forced_report_missing") }
        if ($forcedMatches.Count -gt 1) { $strictFailures.Add("multiple_tcp08_forced_reports") }
        if ($script:Mode -ceq "tcp08" -and $candidateLines -ne 1) {
            $strictFailures.Add("focused_tcp08_candidate_line_count_not_one")
        }
    }
    $strictStatus = if (-not $script:RequireTcp08ProductMetrics) { "not_required" }
        elseif ($strictFailures.Count -eq 0) { "pass" }
        else { "fail" }
    $selectionReason = if ($null -eq $selectionWindow) { "tcp08_candidate_window_unavailable" }
        elseif (-not $windowBoundsValid) { "tcp08_candidate_window_outside_client_stderr" }
        elseif ($forcedMatches.Count -eq 1) { "unique_closed_tcp08_forced_report_in_frozen_candidate_window" }
        elseif ($forcedMatches.Count -eq 0) { "no_closed_tcp08_forced_report_in_frozen_candidate_window" }
        else { "multiple_closed_tcp08_forced_reports_in_frozen_candidate_window" }
    $selected = if ($forcedMatches.Count -eq 1) { $forcedMatches[0] } else { $null }
    return [ordered]@{
        source = "client.stderr.log"
        source_format = "closed allowlisted process_shutdown_report JSON line"
        availability = $availability
        unavailable_reason = $unavailableReason
        clock = [ordered]@{
            kind = "product process-relative monotonic duration"
            unit = "nanoseconds"
            global_stopwatch_alignment_available = $false
        }
        strict_validation = [ordered]@{
            required = [bool]$script:RequireTcp08ProductMetrics
            status = $strictStatus
            candidate_window = $selectionWindow
            candidate_window_availability = $windowAvailability
            candidate_line_count = $windowCandidateLines
            valid_record_count = $windowAssessments.Count
            invalid_record_count = $windowInvalidRecordDetails.Count
            tcp08_forced_candidate_count = $forcedMatches.Count
            incomplete_forced_report_count = $incompleteForced.Count
            allowed_non_forced_report_count = $allowedNonForced.Count
            non_forced_policy = "allowed_restart_or_other_closed_reports"
            selected_record_index = if ($selected) { $selected.record_index } else { $null }
            selected_stderr_line = if ($selected) { $selected.stderr_line } else { $null }
            selected_candidate_ordinal = if ($selected) { $selected.candidate_ordinal } else { $null }
            selection_reason = $selectionReason
            failures = $strictFailures
        }
        all_log_counts = [ordered]@{
            byte_length = if ($logSnapshot) { $logSnapshot.byte_length } else { $null }
            complete_byte_length = if ($logSnapshot) { $logSnapshot.complete_byte_length } else { $null }
            trailing_partial_byte_count = if ($logSnapshot) { $logSnapshot.trailing_partial_byte_count } else { $null }
            complete_line_count = if ($logSnapshot) { $logSnapshot.complete_line_count } else { 0 }
            candidate_line_count = $candidateLines
            valid_record_count = $reports.Count
            invalid_record_count = $invalidRecords
            tcp08_forced_candidate_count = $allForcedMatches.Count
            incomplete_forced_report_count = $allIncompleteForced.Count
            allowed_non_forced_report_count = $allAllowedNonForced.Count
        }
        selected_tcp08_forced_product_timeline = if ($selected) { $selected.product_timeline_events } else { @() }
        records = $reports
        record_assessments = $assessments
        invalid_candidate_records = $invalidRecords
        invalid_record_details = $invalidRecordDetails
        read_failure_type = $readFailureType
    }
}

function Write-Tcp08UnavailableArtifact([string]$Name) {
    Write-Tcp08Json $Name ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-artifact-unavailable.v1"
        artifact = $Name
        status = "not_collected_before_finalization"
    })
}

function Complete-Tcp08Artifacts([bool]$CleanupSucceeded, [object]$PrimaryFailure, [object]$CleanupFailure) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $completionErrors = [System.Collections.Generic.List[string]]::new()
    try { Write-Tcp08Json "process-after.json" (Get-Tcp08ProcessSnapshot) }
    catch {
        $completionErrors.Add("process-after.json")
        Write-Tcp08Json "process-after.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "process-after"
            error_type = $_.Exception.GetType().FullName
        })
    }
    try { Write-Tcp08Json "network-after.json" (Get-Tcp08ResidueNetworkSnapshot) }
    catch {
        $completionErrors.Add("network-after.json")
        Write-Tcp08Json "network-after.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "network-after"
            error_type = $_.Exception.GetType().FullName
        })
    }
    $productEvidence = Get-Tcp08ProductShutdownEvidence
    Write-Tcp08Json "process-report.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-process.v1"
        result = $script:tcp08Result
        process_exit_code = $script:tcp08ExitCode
        ctrl_break = $script:tcp08CtrlBreak
        samples = $script:tcp08Samples
        product = $productEvidence
    })
    Write-Tcp08Json "cleanup-report.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-cleanup.v1"
        cleanup_succeeded = $CleanupSucceeded
        primary_failure_type = if ($PrimaryFailure) { $PrimaryFailure.Exception.GetType().FullName } else { $null }
        primary_failure = if ($PrimaryFailure) { $PrimaryFailure.Exception.Message } else { $null }
        cleanup_failure_type = if ($CleanupFailure) { $CleanupFailure.Exception.GetType().FullName } else { $null }
        cleanup_failure = if ($CleanupFailure) { $CleanupFailure.Exception.Message } else { $null }
    })
    Write-Tcp08Json "timeline.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-timeline.v1"
        clock = [ordered]@{
            kind = "System.Diagnostics.Stopwatch"
            frequency = [Diagnostics.Stopwatch]::Frequency
            origin_timestamp = $script:tcp08ClockOriginTimestamp
            origin_wall_clock_utc = $script:tcp08ClockOriginUtc
        }
        events = $script:tcp08Events
        product = $productEvidence
    })
    foreach ($name in $script:tcp08RequiredJsonNames) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:tcp08ArtifactPath $name) -PathType Leaf)) {
            $completionErrors.Add($name)
            Write-Tcp08UnavailableArtifact $name
        }
    }
    $missingLogs = @($script:tcp08RequiredLogNames | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $script:tcp08ArtifactPath $_) -PathType Leaf)
    })
    $hashRows = @(Get-ChildItem -LiteralPath $script:tcp08ArtifactPath -File | Where-Object {
        $_.Name -ne "artifact-hashes.json"
    } | Sort-Object Name | ForEach-Object {
        $artifactFile = $_
        try {
            [ordered]@{
                name = $artifactFile.Name
                bytes = $artifactFile.Length
                sha256 = (Get-FileHash -LiteralPath $artifactFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                status = "captured"
            }
        } catch {
            $hashError = $_
            $deferToOuterFinalizer = $artifactFile.Name -in @("controller.stdout.log", "controller.stderr.log")
            if (-not $deferToOuterFinalizer) {
                $completionErrors.Add("hash:$($artifactFile.Name)")
            }
            [ordered]@{
                name = $artifactFile.Name
                bytes = $artifactFile.Length
                sha256 = $null
                status = if ($deferToOuterFinalizer) { "deferred_to_final_outer_recalculation" } else { "capture_failed" }
                error_type = $hashError.Exception.GetType().FullName
            }
        }
    })
    Write-Tcp08Json "artifact-hashes.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-artifact-hashes.v1"
        capture = "controller point-in-time before outer pwsh redirection handles close"
        final_outer_recalculation_required = $true
        files = $hashRows
    })
    Assert-True ($missingLogs.Count -eq 0) "required externally/child-produced logs are missing: $($missingLogs -join ',')"
    Assert-True ($completionErrors.Count -eq 0) "artifact capture failed: $($completionErrors -join ',')"
    if ($script:RequireTcp08ProductMetrics) {
        Assert-True ($productEvidence.strict_validation.status -ceq "pass") "strict TCP-08 product shutdown report validation failed: $($productEvidence.strict_validation.failures -join ',')"
    }
}
