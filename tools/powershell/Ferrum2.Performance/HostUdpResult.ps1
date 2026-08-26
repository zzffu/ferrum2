if ($instrumentedDiagnosticMode) {
    $finalVmState = [string](
        Get-Ferrum2HostVmContext -Identity $hostHyperVIdentity
    ).Vm.State
    if ($finalVmState -cne "Off") {
        throw "approved VM final UDP diagnostic state is not Off"
    }
    if (-not (Test-Path -LiteralPath $hostDiagnosticGuestRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $hostDiagnosticHostRoot -PathType Container)) {
        throw "exported UDP diagnostic evidence roots are incomplete"
    }
    $supportFinalContext = Get-HostSupportContext `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportFinalContext
    if ([string]$supportFinalContext.executable_sha256 -cne
        $candidateBuild.HarnessSha256) {
        throw "support diagnostic binary does not match the candidate harness"
    }
    Complete-UdpSupportDiagnosticLedger `
        -Executable ([string]$supportFinalContext.executable) `
        -TargetIpv4 $SupportIpv4 -FirstUdpPort $SupportUdpPort `
        -RunNonce $SupportDiagnosticRunNonce

    $supportLedgerCopy = Join-Path $hostDiagnosticSupportRoot `
        "udp-support-ledger.ndjson"
    [void](Copy-StableUdpDiagnosticLedger `
        -Source $resolvedSupportDiagnosticLedger `
        -Destination $supportLedgerCopy)
    $supportLedgerSummary = Get-UdpDiagnosticLedgerSummary `
        -Path $supportLedgerCopy `
        -ExpectedSchema "ferrum2.windows-tun.udp-support-ledger.v2" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    if ($supportLedgerSummary.Events -lt $supportDiagnosticBaseline.Events) {
        throw "support diagnostic ledger regressed below its validated baseline"
    }

    $diagnosticNetworkPath = Join-Path $hostDiagnosticHostRoot `
        "host-network-path.json"
    Copy-Item -LiteralPath $hostNetworkPathPath -Destination $diagnosticNetworkPath `
        -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $diagnosticNetworkPath -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $hostNetworkPathPath -Algorithm SHA256).Hash) {
        throw "UDP diagnostic host network-path copy changed"
    }

    $guestRawPath = Join-Path $hostDiagnosticGuestRoot "guest-raw.json"
    $workloadLedgerPath = Join-Path $hostDiagnosticGuestRoot `
        "udp-workload-flow-ledger.ndjson"
    $guestRaw = Get-Content -LiteralPath $guestRawPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 12 -ErrorAction Stop
    if ([string]$guestRaw.schema -cne
            "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v2" -or
        [string]$guestRaw.profile -cne $DiagnosticProfile -or
        [string]$guestRaw.identity.parent_sha -cne $ParentSha -or
        [string]$guestRaw.identity.candidate_sha -cne $CandidateSha -or
        [string]$guestRaw.identity.controller_bundle_sha256 -cne
            [string]$performanceControllerBundleManifest.controller_bundle_sha256 -or
        [string]$guestRaw.identity.harness_sha256 -cne
            $candidateBuild.HarnessSha256 -or
        [string]$guestRaw.identity.collector_sha256 -cne
            $udpBoundaryCollectorSha256 -or
        [string]$guestRaw.identity.diagnostic_run_nonce -cne
            $SupportDiagnosticRunNonce -or
        [int]$guestRaw.identity.diagnostic_max_events -ne
            $SupportDiagnosticMaxEvents -or
        [string]$guestRaw.workload.source_ip -cne
            [string]$diagnosticSourcePlan.Ipv4 -or
        [int]$guestRaw.workload.source_port_first -ne
            [int]$diagnosticSourcePlan.PortFirst -or
        [int]$guestRaw.workload.source_port_last -ne
            [int]$diagnosticSourcePlan.PortLast) {
        throw "exported guest UDP diagnostic raw identity mismatch"
    }
    $workloadLedgerSummary = Get-UdpDiagnosticLedgerSummary `
        -Path $workloadLedgerPath `
        -ExpectedSchema "ferrum2.windows-tun.udp-workload-flow-ledger.v3" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    $expectedWorkloadHeaderFields = @(
        "closure", "max_events", "record_type", "run_nonce", "schema", "scope",
        "source_ip", "source_port_first", "source_port_last", "timestamp_clock",
        "trial_sequence"
    )
    $actualWorkloadHeaderFields = @(
        $workloadLedgerSummary.Header.PSObject.Properties.Name | Sort-Object
    )
    if (($actualWorkloadHeaderFields -join "`n") -cne
            ($expectedWorkloadHeaderFields -join "`n") -or
        [string]$workloadLedgerSummary.Header.scope -cne "bootstrap" -or
        [string]$workloadLedgerSummary.Header.closure -cne
            "workload_process_exit" -or
        [int]$workloadLedgerSummary.Header.trial_sequence -ne
            $DiagnosticTrialSequence -or
        [string]$workloadLedgerSummary.Header.source_ip -cne
            [string]$diagnosticSourcePlan.Ipv4 -or
        [int]$workloadLedgerSummary.Header.source_port_first -ne
            [int]$diagnosticSourcePlan.PortFirst -or
        [int]$workloadLedgerSummary.Header.source_port_last -ne
            [int]$diagnosticSourcePlan.PortLast -or
        ([int]$workloadLedgerSummary.Header.source_port_last -
            [int]$workloadLedgerSummary.Header.source_port_first + 1) -ne
            $udpAssociationCount) {
        throw "exported workload ledger source-port contract mismatch"
    }
    $firstFailedFlow = Get-FirstFailedUdpDiagnosticFlow `
        -Path $workloadLedgerPath -MaximumEvents $SupportDiagnosticMaxEvents
    $supportBoundary = if ($null -ne $firstFailedFlow) {
        Get-SupportUdpBoundaryForFlow `
            -Path $supportLedgerCopy `
            -RunNonce $SupportDiagnosticRunNonce `
            -Flow $firstFailedFlow `
            -MaximumEvents $SupportDiagnosticMaxEvents
    } else {
        [pscustomobject]@{ Rx = $null; Tx = $null }
    }

    $cleanupStatus = if ($null -ne $hostCaptureFailure -or
        $hostEndpointSnapshotFailures.Count -ne 0 -or
        $null -eq $hostCaptureResult -or
        [string]$hostCaptureResult.Status -cne "PASS") {
        "FAIL"
    } else {
        "PASS"
    }
    $trialStatus = [string]$guestRaw.trial_status
    $cleanup = [ordered]@{
        status = $cleanupStatus
        checkpoint_restored = $true
        final_vm_state = $finalVmState
        capture_stop_status = if ($null -ne $hostCaptureResult) {
            [string]$hostCaptureResult.CaptureStopStatus
        } elseif ($null -ne $hostCaptureState) {
            "FAIL"
        } else {
            "NOT_STARTED"
        }
        guest_owned_processes = 0
    }

    $captureManifestPath = Join-Path $hostDiagnosticHostRoot `
        "host-capture-manifest.json"
    $captureManifestFiles = @(
        "PktMon.etl", "PktMon.txt", "PktMon.pcapng",
        "pktmon-counters.json", "pktmon-stop.txt"
    )
    $captureManifestRows = [Collections.Generic.List[object]]::new()
    $captureManifestFailures = [Collections.Generic.List[string]]::new()
    if ($null -ne $hostCaptureFailure) {
        $captureManifestFailures.Add(
            "capture: $($hostCaptureFailure.Exception.Message)"
        )
    }
    if ($null -eq $hostCaptureResult) {
        $captureManifestFailures.Add("capture completion result is unavailable")
    } else {
        foreach ($failure in @($hostCaptureResult.Failures)) {
            $captureManifestFailures.Add([string]$failure)
        }
    }
    foreach ($failure in @($hostEndpointSnapshotFailures)) {
        $captureManifestFailures.Add("endpoint snapshot: $failure")
    }
    $hostCaptureNativeAvailable = $false
    foreach ($captureFileName in $captureManifestFiles) {
        $capturePath = Join-Path $hostDiagnosticHostRoot $captureFileName
        if (-not (Test-Path -LiteralPath $capturePath -PathType Leaf)) {
            $captureManifestFailures.Add("missing: $captureFileName")
            continue
        }
        try {
            $captureItem = Get-Item -LiteralPath $capturePath -Force `
                -ErrorAction Stop
            $maximumCaptureBytes = if ($captureFileName -ceq "PktMon.etl") {
                33554432
            } else {
                134217728
            }
            if ($captureItem.PSIsContainer -or $captureItem.Length -le 0 -or
                $captureItem.Length -gt $maximumCaptureBytes -or
                $captureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "size or file identity is outside its boundary"
            }
            $captureManifestRows.Add([ordered]@{
                file = $captureFileName
                bytes = [long]$captureItem.Length
                sha256 = (Get-FileHash -LiteralPath $capturePath `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
            })
            if ($captureFileName -ceq "PktMon.etl") {
                $hostCaptureNativeAvailable = $true
            }
        } catch {
            $captureManifestFailures.Add(
                "invalid ${captureFileName}: $($_.Exception.Message)"
            )
        }
    }
    if ($captureManifestFailures.Count -ne 0) {
        $cleanupStatus = "FAIL"
        $cleanup["status"] = "FAIL"
    }
    $boundedCaptureFailures = @($captureManifestFailures | Select-Object -First 32 |
        ForEach-Object {
            $value = ([string]$_ -replace '[\r\n]+', ' ').Trim()
            if ($value.Length -gt 2048) { $value.Substring(0, 2048) } else { $value }
        })
    Write-Utf8FileNew -Path $captureManifestPath -Text (([ordered]@{
        schema = "ferrum2.windows-tun.host-capture-manifest.v1"
        state = if ($captureManifestFailures.Count -eq 0) { "COMPLETE" } else { "PARTIAL" }
        filters = if ($null -ne $hostCaptureState) {
            @($hostCaptureState.Filters)
        } else {
            @()
        }
        started_utc = if ($null -ne $hostCaptureState) {
            [string]$hostCaptureState.StartedUtc
        } else {
            $null
        }
        stop_status = if ($null -ne $hostCaptureResult) {
            [string]$hostCaptureResult.CaptureStopStatus
        } elseif ($null -ne $hostCaptureState) {
            "FAIL"
        } else {
            "NOT_STARTED"
        }
        expected_files = $captureManifestFiles
        files = $captureManifestRows.ToArray()
        failures = $boundedCaptureFailures
    } | ConvertTo-Json -Depth 6) + "`n")

    $guestProcessLogPath = Join-Path $hostDiagnosticGuestRoot `
        "guest-process-logs.txt"
    $guestProcessLogText = [Text.StringBuilder]::new()
    foreach ($processLog in @(Get-ChildItem `
        -LiteralPath (Join-Path $hostDiagnosticGuestRoot "process-logs") `
        -File -Filter "*.log" -ErrorAction Stop | Sort-Object Name)) {
        [void]$guestProcessLogText.AppendLine("===== $($processLog.Name) =====")
        [void]$guestProcessLogText.AppendLine(
            (Get-Content -LiteralPath $processLog.FullName -Raw -Encoding utf8)
        )
        if ($utf8NoBom.GetByteCount($guestProcessLogText.ToString()) -gt 8388608) {
            throw "combined guest process log exceeded 8 MiB"
        }
    }
    Write-Utf8FileNew -Path $guestProcessLogPath `
        -Text $guestProcessLogText.ToString()

    $failureSummary = $null
    $failureSummaryReference = $null
    if ($trialStatus -ceq "FAIL") {
        $supportRx = $null -ne $supportBoundary.Rx
        $supportTxObserved = $null -ne $supportBoundary.Tx
        $supportTxSuccess = $supportTxObserved -and
            [string]$supportBoundary.Tx.send_result -ceq "success"
        $lastConfirmedStage = if ($supportTxObserved) {
            "support_tx"
        } elseif ($supportRx) {
            "support_rx"
        } elseif ($null -ne $firstFailedFlow -and
            [string]$firstFailedFlow.send_result -ceq "success") {
            "workload_send"
        } else {
            $null
        }
        $firstMissingStage = $null
        $workloadCoversNonce = $null -ne $firstFailedFlow -and
            $workloadLedgerSummary.Closed -and
            $workloadLedgerSummary.DroppedEvents -eq 0 -and
            $workloadLedgerSummary.WriteFailures -eq 0
        $supportAbsenceProvable = $null -ne $firstFailedFlow -and
            $supportLedgerSummary.Closed -and
            $supportLedgerSummary.DroppedEvents -eq 0 -and
            $supportLedgerSummary.WriteFailures -eq 0
        $failureFingerprint = if ($supportTxSuccess) {
            "udp/bootstrap/reply-missing-after-support-tx"
        } elseif ($supportTxObserved) {
            "udp/bootstrap/support-tx-not-success"
        } elseif ($supportRx) {
            if ($supportAbsenceProvable) {
                "udp/bootstrap/reply-missing-at-support-tx"
            } else {
                "udp/bootstrap/support-tx-boundary-unknown"
            }
        } elseif ($supportAbsenceProvable) {
            "udp/bootstrap/request-missing-before-support-rx"
        } else {
            "udp/bootstrap/support-boundary-unknown"
        }
        $workloadTuple = if ($null -eq $firstFailedFlow) { $null } else {
            [ordered]@{
                source_ip = [string]$firstFailedFlow.workload_local_ip
                source_port = [int]$firstFailedFlow.workload_local_port
                target_ip = [string]$firstFailedFlow.target_ip
                target_port = [int]$firstFailedFlow.target_port
            }
        }
        $physicalTuple = if ($null -eq $supportBoundary.Rx) { $null } else {
            [ordered]@{
                source_ip = [string]$supportBoundary.Rx.remote_ip
                source_port = [int]$supportBoundary.Rx.remote_port
                target_ip = [string]$supportBoundary.Rx.listen_ip
                target_port = [int]$supportBoundary.Rx.listen_port
            }
        }
        $workloadLedgerComplete = $workloadLedgerSummary.Closed -and
            $workloadLedgerSummary.DroppedEvents -eq 0 -and
            $workloadLedgerSummary.WriteFailures -eq 0
        $supportLedgerComplete = $supportLedgerSummary.Closed -and
            $supportLedgerSummary.DroppedEvents -eq 0 -and
            $supportLedgerSummary.WriteFailures -eq 0
        $observations = [ordered]@{}
        foreach ($stage in @(
            "workload_send", "direct_send", "guest_request", "host_request",
            "support_rx", "support_tx", "host_reply", "guest_reply",
            "ferrum_receive", "response_classified", "response_sink",
            "wintun_injection", "workload_reply"
        )) {
            $observations[$stage] = "UNKNOWN"
        }
        if ($null -ne $firstFailedFlow) {
            $observations.workload_send = if (
                [string]$firstFailedFlow.send_result -ceq "success"
            ) { "SEEN" } elseif ($workloadLedgerComplete) { "NOT_SEEN" } else { "UNKNOWN" }
            $observations.workload_reply = if (
                [string]$firstFailedFlow.reply_result -ceq "success"
            ) {
                "SEEN"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "not_observed") {
                "UNKNOWN"
            } elseif ($workloadLedgerComplete) {
                "NOT_SEEN"
            } else {
                "UNKNOWN"
            }
        }
        if ($supportRx) {
            $observations.support_rx = "SEEN"
        } elseif ($supportLedgerComplete -and $null -ne $firstFailedFlow) {
            $observations.support_rx = "NOT_SEEN"
        }
        if ($supportTxObserved) {
            $observations.support_tx = "SEEN"
        } elseif ($supportLedgerComplete -and $null -ne $firstFailedFlow) {
            $observations.support_tx = "NOT_SEEN"
        }
        $firstMissingStage = if ($observations.workload_send -ceq "NOT_SEEN") {
            "workload_send"
        } elseif ($observations.support_rx -ceq "SEEN" -and
            $observations.support_tx -ceq "NOT_SEEN") {
            "support_tx"
        } else {
            $null
        }
        $source = {
            param([string]$State, [long]$Records, [long]$Dropped,
                [long]$WriteFailures, [bool]$CoversNonce)
            [ordered]@{
                state = $State
                records = $Records
                dropped_events = $Dropped
                write_failures = $WriteFailures
                covers_packet_nonce = $CoversNonce
            }
        }
        $failureSummary = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-udp-failure-summary.v1"
            qualification = $false
            run_nonce = $SupportDiagnosticRunNonce
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            sha = $ParentSha
            tree = $parentTree
            client_sha256 = $parentBuild.ClientSha256
            server_sha256 = $parentBuild.ServerSha256
            harness_sha256 = $candidateBuild.HarnessSha256
            runner_sha256 = $runnerSourceSha256
            recipe_sha256 = [string]$plan.recipe_sha256
            vm_id = $approvedVmId.ToString("D")
            checkpoint_id = $approvedCheckpointId.ToString("D")
            support_pid = $SupportPid
            support_owner = $SupportOwner
            support_sha256 = [string]$supportFinalContext.executable_sha256
            trial_sequence = [int]$diagnosticTrial.sequence
            scenario = [string]$diagnosticTrial.scenario
            member = [string]$diagnosticTrial.member
            pair = [int]$diagnosticTrial.pair
            order = [int]$diagnosticTrial.order
            failure_kind = if ($null -eq $firstFailedFlow) {
                "other"
            } elseif ([string]$firstFailedFlow.send_result -in @(
                "error", "partial"
            )) {
                "send_error"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "timeout") {
                "timeout"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "error") {
                "receive_error"
            } elseif ([string]$firstFailedFlow.reply_result -ceq
                "payload_mismatch") {
                "payload_mismatch"
            } else {
                "other"
            }
            phase = if ($null -ne $firstFailedFlow) {
                [string]$firstFailedFlow.phase
            } else {
                "bootstrap"
            }
            association_index = if ($null -ne $firstFailedFlow) {
                [int]$firstFailedFlow.association_index
            } else {
                $null
            }
            round = if ($null -ne $firstFailedFlow) {
                [int]$firstFailedFlow.round
            } else {
                $null
            }
            packet_nonce = if ($null -ne $firstFailedFlow) {
                [string]$firstFailedFlow.packet_nonce
            } else {
                $null
            }
            workload_tuple = $workloadTuple
            physical_tuple = $physicalTuple
            observation_sources = [ordered]@{
                workload_ledger = & $source `
                    $(if ($workloadLedgerComplete) { "COMPLETE" } else { "TRUNCATED" }) `
                    $workloadLedgerSummary.Events `
                    $workloadLedgerSummary.DroppedEvents `
                    $workloadLedgerSummary.WriteFailures $workloadCoversNonce
                support_ledger = & $source `
                    $(if ($supportLedgerComplete) { "COMPLETE" } else { "TRUNCATED" }) `
                    $supportLedgerSummary.Events `
                    $supportLedgerSummary.DroppedEvents `
                    $supportLedgerSummary.WriteFailures $supportAbsenceProvable
                host_capture = & $source `
                    $(if ($cleanupStatus -ceq "PASS") { "COMPLETE" } else { "ERROR" }) `
                    0 0 0 $false
                guest_capture = & $source "NOT_ENABLED" 0 0 0 $false
                ferrum_boundary = & $source "NOT_ENABLED" 0 0 0 $false
            }
            observations = $observations
            last_confirmed_stage = $lastConfirmedStage
            first_missing_stage = $firstMissingStage
            response_sink_outcome = $null
            failure_fingerprint = $failureFingerprint
            cleanup = $cleanup
        }
        Write-Utf8FileNew -Path $hostDiagnosticFailurePath `
            -Text (($failureSummary | ConvertTo-Json -Depth 10) + "`n")
        $failureSummaryReference = [ordered]@{
            file = [IO.Path]::GetRelativePath(
                $hostDiagnosticRoot,
                $hostDiagnosticFailurePath
            ).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $hostDiagnosticFailurePath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $artifacts = [Collections.Generic.List[object]]::new()
    $artifacts.Add((New-UdpDiagnosticArtifactRecord `
        -Role "workload_ledger" -Path $workloadLedgerPath `
        -LedgerSummary $workloadLedgerSummary -MaxEvents $SupportDiagnosticMaxEvents))
    $artifacts.Add((New-UdpDiagnosticArtifactRecord `
        -Role "support_ledger" -Path $supportLedgerCopy `
        -LedgerSummary $supportLedgerSummary -MaxEvents $SupportDiagnosticMaxEvents))
    foreach ($artifactSpec in @(
        @("host_capture", "host", "host-capture-manifest.json"),
        @("endpoint_snapshot_before", "guest", "guest-endpoints-pre.json"),
        @("endpoint_snapshot_after", "guest", "guest-endpoints-post.json"),
        @("dynamic_port_snapshot_before", "host", "host-endpoints-pre.json"),
        @("dynamic_port_snapshot_after", "host", "host-endpoints-post.json"),
        @("host_network_path", "host", "host-network-path.json"),
        @("runner_log", "guest", "guest-raw.json"),
        @("guest_process_log", "guest", "guest-process-logs.txt")
    )) {
        $artifactRoot = if ($artifactSpec[1] -ceq "host") {
            $hostDiagnosticHostRoot
        } else {
            $hostDiagnosticGuestRoot
        }
        $artifactState = if ($artifactSpec[0] -ceq "host_capture" -and
            $cleanupStatus -cne "PASS") {
            "PARTIAL"
        } elseif ($artifactSpec[0] -in @(
            "dynamic_port_snapshot_before", "dynamic_port_snapshot_after"
        ) -and $hostEndpointSnapshotFailures.Count -ne 0) {
            "PARTIAL"
        } elseif ($artifactSpec[0] -in @(
            "endpoint_snapshot_before", "endpoint_snapshot_after"
        ) -and @($guestRaw.snapshot_errors).Count -ne 0) {
            "PARTIAL"
        } elseif ($artifactSpec[0] -ceq "runner_log" -and
            [string]$guestRaw.evidence_status -cne "COMPLETE") {
            "PARTIAL"
        } else {
            "COMPLETE"
        }
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role $artifactSpec[0] `
            -Path (Join-Path $artifactRoot $artifactSpec[2]) `
            -StateOverride $artifactState))
    }
    if ($hostCaptureNativeAvailable) {
        $nativeCaptureState = if ($cleanupStatus -ceq "PASS") {
            "COMPLETE"
        } else {
            "PARTIAL"
        }
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role "host_capture_native" `
            -Path (Join-Path $hostDiagnosticHostRoot "PktMon.etl") `
            -StateOverride $nativeCaptureState))
    }
    if ($trialStatus -ceq "FAIL") {
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role "failure_summary" -Path $hostDiagnosticFailurePath))
    }
    if ($artifacts.Count -gt 16) {
        throw "UDP diagnostic artifact manifest exceeds its closed boundary"
    }
    $presentArtifactBytes = Get-UdpDiagnosticArtifactTotalByteCount -Artifacts $artifacts
    if ($presentArtifactBytes -gt 268435456) {
        throw "UDP diagnostic artifact manifest exceeds its total byte boundary"
    }
    $evidenceStatus = if (@($artifacts | Where-Object {
        $_.state -ceq "PARTIAL"
    }).Count -ne 0) { "PARTIAL" } else { "COMPLETE" }

    # PowerShell 7.6 materializes JSON ISO timestamps as DateTime; 7.4 retains strings.
    $guestRawStartedUtc = ConvertTo-CanonicalUtcText `
        -Value $guestRaw.started_utc -Label "guest raw started_utc"
    [void](ConvertTo-CanonicalUtcText `
        -Value $guestRaw.finished_utc -Label "guest raw finished_utc")
    $diagnosticDocument = [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-udp-diagnostic.v1"
        qualification = $false
        profile = $DiagnosticProfile
        evidence_status = $evidenceStatus
        trial_status = $trialStatus
        run_nonce = $SupportDiagnosticRunNonce
        started_utc = $guestRawStartedUtc
        finished_utc = [DateTime]::UtcNow.ToString("o")
        identity = [ordered]@{
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            sha = $ParentSha
            tree = $parentTree
            client_sha256 = $parentBuild.ClientSha256
            server_sha256 = $parentBuild.ServerSha256
            harness_sha256 = $candidateBuild.HarnessSha256
            runner_sha256 = $runnerSourceSha256
            recipe_sha256 = [string]$plan.recipe_sha256
            plan_sha256 = (Get-FileHash -LiteralPath $hostPlanPath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        trial = [ordered]@{
            selection = [string]$plan.selection
            run_kind = $RunKind
            sequence = [int]$diagnosticTrial.sequence
            scenario = [string]$diagnosticTrial.scenario
            member = [string]$diagnosticTrial.member
            pair = [int]$diagnosticTrial.pair
            order = [int]$diagnosticTrial.order
        }
        environment = [ordered]@{
            runner_os = "Windows"
            runner_arch = "X64"
            runner_label = "ferrum2-hyperv-guest"
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
            topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
            support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
            rust_toolchain = "1.97.1"
            cargo_profile = "profiling"
            pair_schedule = "abba-six-pairs"
            guest_build = [string]$guestResult.guest_build
            cpu_model = [string]$guestResult.cpu_model
            cpu_count = [int]$guestResult.cpu_count
            memory_bytes = [uint64]$guestResult.memory_bytes
            power_plan_guid = [string]$guestResult.power_plan_guid
        }
        support = [ordered]@{
            pid = $SupportPid
            owner = $SupportOwner
            binary_sha256 = [string]$supportFinalContext.executable_sha256
            listen_endpoints = @(
                [ordered]@{ protocol = "tcp"; ip = $SupportIpv4; port = $SupportTcpPort }
                $SupportUdpPort..($SupportUdpPort + 3) | ForEach-Object {
                    [ordered]@{ protocol = "udp"; ip = $SupportIpv4; port = [int]$_ }
                }
            )
        }
        topology = [ordered]@{
            support_ipv4 = $SupportIpv4
            guest_ipv4 = [string]$guestNetworkPath.guest_ipv4
            host_network_path_file = "host/host-network-path.json"
            host_network_path_sha256 = (Get-FileHash `
                -LiteralPath $diagnosticNetworkPath -Algorithm SHA256).Hash.ToLowerInvariant()
            host_tun_bypassed = $true
            host_network_mutations = @()
        }
        bounds = [ordered]@{
            max_artifacts = 16
            max_total_bytes = 268435456
            max_artifact_bytes = 134217728
            max_ndjson_line_bytes = 4096
            max_ledger_events = $SupportDiagnosticMaxEvents
        }
        artifacts = $artifacts.ToArray()
        failure_summary = $failureSummaryReference
        cleanup = $cleanup
    }
    Write-Utf8FileNew -Path $hostDiagnosticPath `
        -Text (($diagnosticDocument | ConvertTo-Json -Depth 10) + "`n")
    Push-Location $repositoryRoot
    try {
        $diagnosticValidatorRows = @(& $python -B -m $controlModule `
            "windows-tun-validate-udp-diagnostic" `
            "--plan" $hostPlanPath `
            "--evidence-root" $hostDiagnosticRoot `
            "--parent-sha" $ParentSha `
            "--candidate-sha" $CandidateSha `
            "--controller-bundle-sha256" `
                $performanceControllerBundleManifest.controller_bundle_sha256 `
            "--policy" $policyPath 2>&1)
        $diagnosticValidatorExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $diagnosticValidatorLines = @($diagnosticValidatorRows | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            [string]$_.Exception.Message
        } else {
            [string]$_
        }
    })
    $expectedDiagnosticValidatorLine = "{0}`t{1}`t{2}`t{3}`t{4}`tqualification=false" -f @(
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair,
        $trialStatus,
        $evidenceStatus
    )
    if ($diagnosticValidatorExit -ne 0 -or
        $diagnosticValidatorLines.Count -ne 1 -or
        [string]$diagnosticValidatorLines[0] -cne $expectedDiagnosticValidatorLine) {
        $validatorDetail = ($diagnosticValidatorLines -join " | ")
        if ($validatorDetail.Length -gt 2048) {
            $validatorDetail = $validatorDetail.Substring(0, 2048)
        }
        throw "UDP diagnostic validation failed: exit=$diagnosticValidatorExit detail=$validatorDetail"
    }
    [pscustomobject]@{
        schema = "ferrum2.windows-tun.hyperv-udp-diagnostic-result.v1"
        status = $trialStatus
        evidence_status = $evidenceStatus
        qualification = $false
        diagnostic = $hostDiagnosticPath
        failure_summary = if ($null -ne $failureSummary) {
            $hostDiagnosticFailurePath
        } else {
            $null
        }
        final_vm_state = $finalVmState
        checkpoint_restored = $true
        host_tun_bypassed = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Depth 4
    if ($trialStatus -ceq "PASS" -and $evidenceStatus -ceq "COMPLETE") {
        exit 0
    }
    exit 1
}
