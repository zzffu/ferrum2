            function Invoke-LoggedCommand {
                param(
                    [string]$Executable,
                    [string[]]$Arguments,
                    [string]$StdoutPath,
                    [string]$StderrPath
                )
                if (@($Arguments | Where-Object {
                        [string]::IsNullOrWhiteSpace($_) -or $_ -cmatch '[\s"]'
                    }).Count -ne 0) {
                    throw "logged command arguments must not require command-line quoting"
                }
                $process = Start-Process -FilePath $Executable `
                    -ArgumentList $Arguments `
                    -RedirectStandardOutput $StdoutPath `
                    -RedirectStandardError $StderrPath `
                    -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
                return [int]$process.ExitCode
            }

            function Write-GuestJsonNew {
                param([string]$Path, [object]$Value)
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
                    ($Value | ConvertTo-Json -Depth 6) + "`n"
                )
                $stream = [IO.FileStream]::new(
                    $Path,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None
                )
                try {
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush($true)
                } finally {
                    $stream.Dispose()
                }
            }

            function Assert-ClosedProperties {
                param([object]$Value, [string[]]$Expected, [string]$Label)
                if ((@($Value.PSObject.Properties.Name) -join "|") -cne ($Expected -join "|")) {
                    throw "$Label property set is invalid"
                }
            }

            function Test-JsonInteger {
                param([object]$Value)
                return $Value -is [int] -or $Value -is [long]
            }

            function Test-JsonNumber {
                param([object]$Value)
                return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or
                    $Value -is [long] -or $Value -is [single] -or $Value -is [double] -or
                    $Value -is [decimal]
            }

            function Test-Sha256 {
                param([object]$Value)
                return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
            }

            function Assert-NetworkResetEvidence {
                param(
                    [object]$Result,
                    [string]$ArtifactPath,
                    [int]$ExpectedCycles
                )
                if ($ExpectedCycles -notin @(10, 100, 1000)) {
                    throw "network-reset evidence cycle count is invalid"
                }
                $baselineRows = @($Result.live_checks | Where-Object {
                    $_.name -ceq "network-reset-baseline"
                })
                $summaryRows = @($Result.live_checks | Where-Object {
                    $_.name -ceq "network-reset-summary"
                })
                if ($baselineRows.Count -ne 1 -or $summaryRows.Count -ne 1) {
                    throw "network-reset WFP live evidence rows are not exact"
                }
                $baselineRow = $baselineRows[0]
                $summaryRow = $summaryRows[0]
                Assert-ClosedProperties $baselineRow @("name", "status", "evidence") "network-reset baseline row"
                Assert-ClosedProperties $summaryRow @("name", "status", "evidence") "network-reset summary row"
                if ($baselineRow.status -cne "pass" -or $summaryRow.status -cne "pass") {
                    throw "network-reset WFP live evidence did not pass"
                }

                $baseline = $baselineRow.evidence
                Assert-ClosedProperties $baseline @(
                    "process_id", "interface_guid", "interface_luid", "interface_index",
                    "managed_plane_sha256", "managed_plane", "strict_route_wfp_sha256",
                    "strict_route_filters", "strict_route_filter_ids", "strict_route_session_key",
                    "strict_route_sublayer_key", "session_generation", "network_generation"
                ) "network-reset baseline evidence"
                $filterIds = @($baseline.strict_route_filter_ids)
                if (-not (Test-JsonInteger $baseline.process_id) -or [long]$baseline.process_id -le 0 -or
                    $baseline.interface_guid -isnot [string] -or
                    [string]$baseline.interface_guid -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
                    $baseline.interface_luid -isnot [string] -or [string]$baseline.interface_luid -cnotmatch '^[1-9][0-9]*$' -or
                    -not (Test-JsonInteger $baseline.interface_index) -or [long]$baseline.interface_index -le 0 -or
                    -not (Test-Sha256 $baseline.managed_plane_sha256) -or
                    -not (Test-Sha256 $baseline.strict_route_wfp_sha256) -or
                    -not (Test-JsonInteger $baseline.strict_route_filters) -or
                    [long]$baseline.strict_route_filters -ne 8 -or $filterIds.Count -ne 8 -or
                    @($filterIds | Sort-Object -Unique).Count -ne 8 -or
                    @($filterIds | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[1-9][0-9]*$' }).Count -ne 0 -or
                    $baseline.strict_route_session_key -cne "8ea35b4e-6629-4e26-9776-95c5bf9c6b01" -or
                    $baseline.strict_route_sublayer_key -cne "ddbc2fa2-d52f-4a79-8a63-8446c308cf02" -or
                    -not (Test-JsonNumber $baseline.session_generation) -or
                    -not (Test-JsonNumber $baseline.network_generation)) {
                    throw "network-reset baseline WFP identity is invalid"
                }

                $summary = $summaryRow.evidence
                Assert-ClosedProperties $summary @(
                    "cycles", "process_id", "initial_session_generation", "final_session_generation",
                    "final_network_generation", "reset_started_delta", "reset_succeeded_delta",
                    "reset_failed_delta", "full_rebuild_delta",
                    "strict_route_filter_install_delta", "managed_plane_sha256",
                    "strict_route_wfp_sha256", "strict_route_filter_ids",
                    "strict_route_health_revalidations", "strict_route_wfp_samples",
                    "cycle_evidence", "cycle_evidence_bytes", "cycle_evidence_sha256"
                ) "network-reset summary evidence"
                $summaryFilterIds = @($summary.strict_route_filter_ids)
                $sampleStride = [Math]::Max(1, [int][Math]::Ceiling($ExpectedCycles / 10.0))
                $expectedWfpSamples = 1 + @(1..$ExpectedCycles | Where-Object {
                    $_ -eq 1 -or $_ -eq $ExpectedCycles -or ($_ % $sampleStride) -eq 0
                }).Count
                if (-not (Test-JsonInteger $summary.cycles) -or [long]$summary.cycles -ne $ExpectedCycles -or
                    -not (Test-JsonInteger $summary.process_id) -or
                    [long]$summary.process_id -ne [long]$baseline.process_id -or
                    -not (Test-JsonNumber $summary.initial_session_generation) -or
                    -not (Test-JsonNumber $summary.final_session_generation) -or
                    -not (Test-JsonNumber $summary.final_network_generation) -or
                    [double]$summary.final_session_generation -ne [double]$summary.initial_session_generation + $ExpectedCycles -or
                    [double]$summary.final_network_generation -ne [double]$summary.final_session_generation -or
                    -not (Test-JsonNumber $summary.reset_started_delta) -or
                    [double]$summary.reset_started_delta -ne $ExpectedCycles -or
                    -not (Test-JsonNumber $summary.reset_succeeded_delta) -or
                    [double]$summary.reset_succeeded_delta -ne $ExpectedCycles -or
                    -not (Test-JsonNumber $summary.reset_failed_delta) -or [double]$summary.reset_failed_delta -ne 0 -or
                    -not (Test-JsonNumber $summary.full_rebuild_delta) -or [double]$summary.full_rebuild_delta -ne 0 -or
                    -not (Test-JsonNumber $summary.strict_route_filter_install_delta) -or
                    [double]$summary.strict_route_filter_install_delta -ne 0 -or
                    $summary.managed_plane_sha256 -cne $baseline.managed_plane_sha256 -or
                    $summary.strict_route_wfp_sha256 -cne $baseline.strict_route_wfp_sha256 -or
                    ($summaryFilterIds -join "|") -cne ($filterIds -join "|") -or
                    -not (Test-JsonInteger $summary.strict_route_health_revalidations) -or
                    [long]$summary.strict_route_health_revalidations -ne $ExpectedCycles -or
                    -not (Test-JsonInteger $summary.strict_route_wfp_samples) -or
                    [long]$summary.strict_route_wfp_samples -ne $expectedWfpSamples -or
                    $summary.cycle_evidence -cne "network-reset-cycles.jsonl" -or
                    -not (Test-JsonInteger $summary.cycle_evidence_bytes) -or
                    [long]$summary.cycle_evidence_bytes -le 0 -or
                    [long]$summary.cycle_evidence_bytes -gt 1048576 -or
                    -not (Test-Sha256 $summary.cycle_evidence_sha256)) {
                    throw "network-reset summary WFP evidence is invalid"
                }

                $cyclePath = Join-Path $ArtifactPath "network-reset-cycles.jsonl"
                $cycleItem = Get-Item -LiteralPath $cyclePath -Force -ErrorAction Stop
                if ($cycleItem.PSIsContainer -or
                    ($cycleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $cycleItem.Length -ne [long]$summary.cycle_evidence_bytes -or
                    (Get-FileHash -LiteralPath $cyclePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$summary.cycle_evidence_sha256) {
                    throw "network-reset cycle evidence identity is invalid"
                }
                $cycleBytes = [IO.File]::ReadAllBytes($cyclePath)
                $lfCount = 0
                $crCount = 0
                foreach ($byte in $cycleBytes) {
                    if ($byte -eq 10) { $lfCount++ }
                    if ($byte -eq 13) { $crCount++ }
                }
                if ($cycleBytes.Length -eq 0 -or $cycleBytes[$cycleBytes.Length - 1] -ne 10 -or
                    $lfCount -ne $ExpectedCycles -or $crCount -ne 0) {
                    throw "network-reset cycle evidence framing is invalid"
                }
                $cycleText = [Text.UTF8Encoding]::new($false, $true).GetString($cycleBytes)
                $cycleLines = $cycleText.Split([char[]]@([char]10), [StringSplitOptions]::None)
                if ($cycleLines.Count -ne $ExpectedCycles + 1 -or $cycleLines[-1].Length -ne 0) {
                    throw "network-reset cycle evidence row count is invalid"
                }
                $cycleProperties = @(
                    "cycle", "mutation", "route_metric", "process_id", "interface_guid", "interface_luid",
                    "interface_index", "managed_plane_sha256", "strict_route_wfp_sha256", "wfp_sampled",
                    "session_generation", "network_generation", "reset_started", "reset_succeeded",
                    "reset_failed", "full_rebuild", "strict_route_effective"
                )
                $sampledRows = 0
                $resetStartedBaseline = $null
                $resetSucceededBaseline = $null
                $resetFailedBaseline = $null
                $fullRebuildBaseline = $null
                foreach ($offset in 0..($ExpectedCycles - 1)) {
                    $cycle = $offset + 1
                    $row = $cycleLines[$offset] | ConvertFrom-Json -ErrorAction Stop
                    Assert-ClosedProperties $row $cycleProperties "network-reset cycle evidence row"
                    $expectedMetric = if ($cycle -eq 1 -or ($cycle % 2) -ne 0) { 4094 } else { 4095 }
                    $expectedMutation = if ($cycle -eq 1) { "create" } else { "metric_toggle" }
                    $expectedSample = $cycle -eq 1 -or $cycle -eq $ExpectedCycles -or
                        ($cycle % $sampleStride) -eq 0
                    if ($row.wfp_sampled -eq $true) { $sampledRows++ }
                    if ($cycle -eq 1) {
                        $resetStartedBaseline = [double]$row.reset_started - 1
                        $resetSucceededBaseline = [double]$row.reset_succeeded - 1
                        $resetFailedBaseline = [double]$row.reset_failed
                        $fullRebuildBaseline = [double]$row.full_rebuild
                    }
                    if (-not (Test-JsonInteger $row.cycle) -or [long]$row.cycle -ne $cycle -or
                        $row.mutation -cne $expectedMutation -or
                        -not (Test-JsonInteger $row.route_metric) -or [long]$row.route_metric -ne $expectedMetric -or
                        -not (Test-JsonInteger $row.process_id) -or [long]$row.process_id -ne [long]$baseline.process_id -or
                        $row.interface_guid -cne $baseline.interface_guid -or
                        $row.interface_luid -cne $baseline.interface_luid -or
                        -not (Test-JsonInteger $row.interface_index) -or
                        [long]$row.interface_index -ne [long]$baseline.interface_index -or
                        $row.managed_plane_sha256 -cne $baseline.managed_plane_sha256 -or
                        $row.strict_route_wfp_sha256 -cne $baseline.strict_route_wfp_sha256 -or
                        $row.wfp_sampled -isnot [bool] -or $row.wfp_sampled -ne $expectedSample -or
                        -not (Test-JsonNumber $row.session_generation) -or
                        [double]$row.session_generation -ne [double]$summary.initial_session_generation + $cycle -or
                        -not (Test-JsonNumber $row.network_generation) -or
                        [double]$row.network_generation -ne [double]$row.session_generation -or
                        -not (Test-JsonNumber $row.reset_started) -or
                        [double]$row.reset_started -ne $resetStartedBaseline + $cycle -or
                        -not (Test-JsonNumber $row.reset_succeeded) -or
                        [double]$row.reset_succeeded -ne $resetSucceededBaseline + $cycle -or
                        -not (Test-JsonNumber $row.reset_failed) -or [double]$row.reset_failed -ne $resetFailedBaseline -or
                        -not (Test-JsonNumber $row.full_rebuild) -or [double]$row.full_rebuild -ne $fullRebuildBaseline -or
                        -not (Test-JsonNumber $row.strict_route_effective) -or
                        [double]$row.strict_route_effective -ne 1) {
                        throw "network-reset cycle evidence values are invalid: cycle=$cycle"
                    }
                }
                if ($sampledRows + 1 -ne [long]$summary.strict_route_wfp_samples) {
                    throw "network-reset WFP sample accounting is invalid"
                }
            }

            function Assert-StagedFileIdentity {
                param(
                    [string]$Path,
                    [object]$Entry,
                    [string]$ExpectedName,
                    [long]$MinimumBytes,
                    [long]$MaximumBytes
                )
                Assert-ClosedProperties $Entry @("name", "bytes", "sha256") "staged $ExpectedName identity"
                $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                if ($item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $Entry.name -cne $ExpectedName -or
                    -not (Test-JsonInteger $Entry.bytes) -or
                    [long]$Entry.bytes -ne [long]$item.Length -or
                    $item.Length -lt $MinimumBytes -or
                    $item.Length -gt $MaximumBytes -or
                    [string]$Entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$Entry.sha256) {
                    throw "staged $ExpectedName identity is invalid"
                }
            }
