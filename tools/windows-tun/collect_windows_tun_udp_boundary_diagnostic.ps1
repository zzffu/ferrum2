#requires -Version 7.4

<#
.SYNOPSIS
Runs the bounded, diagnostic-only Windows TUN UDP association workload.

.DESCRIPTION
This helper is staged into the approved Hyper-V guest by
run_windows_tun_performance_hyperv.ps1. It does not start or stop Ferrum2 product
processes and it never emits canonical performance evidence. A nonzero workload
exit is an observed diagnostic result: the helper retains the partial flow
ledger, endpoint snapshots, metrics, and bounded process output before returning
control to the guest controller.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("UdpFlowBoundary")]
    [string]$Profile,

    [Parameter(Mandatory = $true)]
    [ValidateSet("calibration-aa")]
    [string]$RunKind,

    [Parameter(Mandatory = $true)]
    [ValidateSet("parent")]
    [string]$Member,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$TrialSequence,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ParentSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Tree,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$RecipeSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ControllerBundleSha256,

    [Parameter(Mandatory = $true)]
    [string]$HarnessBinary,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Ferrum2Perf")]
    [string]$TunAdapterName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $parsed = $null
        [Net.IPAddress]::TryParse($_, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
    })]
    [string]$TargetIpv4,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$TargetTcpPort,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65532)]
    [int]$TargetUdpPort,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ClientPid,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ServerPid,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$ClientMetricsPort,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$DiagnosticRunNonce,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65536)]
    [int]$DiagnosticMaxEvents,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$startedUtc = [DateTime]::UtcNow.ToString("o")
$diagnosticSourceIpv4 = "198.18.0.2"
$diagnosticSourcePortFirst = 20000
$diagnosticSourcePortLast = 28191
$diagnosticSourcePortCount = 8192
$workloadLedgerSchema = "ferrum2.windows-tun.udp-workload-flow-ledger.v3"
$controllerBundleManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    "controller-bundle.json"
$bootstrapRelative = "modules/Ferrum2.Qualification.Common/BundleBootstrap.ps1"
$bootstrapManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapEntry = @($bootstrapManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $PSScriptRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw "performance diagnostic bundle bootstrap changed"
}
. $bootstrapPath
$verifiedControllerBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot
if ([string]$verifiedControllerBundle.controller_bundle_sha256 -cne
    $ControllerBundleSha256) {
    throw "performance diagnostic controller bundle identity changed"
}
$performanceDiagnosticRoot = Join-Path $PSScriptRoot "powershell\Ferrum2.Performance"
$diagnosticCorePath = Join-Path $performanceDiagnosticRoot "UdpDiagnosticCore.ps1"
$diagnosticSourcePath = Join-Path $performanceDiagnosticRoot "UdpDiagnosticSource.ps1"
$diagnosticEvidencePath = Join-Path $performanceDiagnosticRoot "UdpDiagnosticEvidence.ps1"
foreach ($diagnosticModule in @($diagnosticCorePath, $diagnosticSourcePath, $diagnosticEvidencePath)) {
    if (-not (Test-Path -LiteralPath $diagnosticModule -PathType Leaf)) {
        throw "performance UDP diagnostic module is missing: $diagnosticModule"
    }
}
. $diagnosticCorePath
. $diagnosticSourcePath
. $diagnosticEvidencePath
$nonceValue = [uint64]0
Assert-Condition ([uint64]::TryParse(
        $DiagnosticRunNonce,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$nonceValue
    ) -and $nonceValue -ne 0 -and $nonceValue.ToString(
        [Globalization.CultureInfo]::InvariantCulture
    ) -ceq $DiagnosticRunNonce) "diagnostic run nonce is not canonical"

$harness = Resolve-NormalizedLeaf -Path $HarnessBinary -Label "traffic harness" `
    -MaximumBytes 536870912
$harnessSha256 = (Get-FileHash -LiteralPath $harness -Algorithm SHA256).
    Hash.ToLowerInvariant()
$collectorSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
Assert-Condition ([IO.Path]::IsPathFullyQualified($OutputDirectory)) `
    "diagnostic output directory must be absolute"
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
Assert-Condition ((Test-Path -LiteralPath $outputRoot -PathType Container)) `
    "diagnostic output directory does not exist"
Assert-Condition (-not ((Get-Item -LiteralPath $outputRoot -Force).Attributes -band `
        [IO.FileAttributes]::ReparsePoint)) "diagnostic output directory cannot be a reparse point"
$outputPath = [IO.Path]::GetFullPath($Output)
$outputPrefix = $outputRoot + [IO.Path]::DirectorySeparatorChar
Assert-Condition ($outputPath.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) `
    "diagnostic output must remain inside its output directory"
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) `
    "diagnostic raw output baseline is not absent"

$preSnapshot = Join-Path $outputRoot "guest-endpoints-pre.json"
$postSnapshot = Join-Path $outputRoot "guest-endpoints-post.json"
$metricsPrePath = Join-Path $outputRoot "client-metrics-pre.txt"
$metricsPostPath = Join-Path $outputRoot "client-metrics-post.txt"
$ledgerPath = Join-Path $outputRoot "udp-workload-flow-ledger.ndjson"
$observationPath = Join-Path $outputRoot "workload-observation.json"
$stdoutPath = Join-Path $outputRoot "workload.stdout.log"
$stderrPath = Join-Path $outputRoot "workload.stderr.log"
$workloadPid = 0
$workloadExitCode = $null
$workloadTimedOut = $false
$infrastructureError = $null
$snapshotErrors = [Collections.Generic.List[string]]::new()
$sourcePreflight = $null

try {
    $sourcePreflight = Get-DiagnosticSourcePreflight -AdapterName $TunAdapterName
    try {
        Write-UdpEndpointSnapshot -Path $preSnapshot -Stage "pre_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
            -SourcePreflight $sourcePreflight
    }
    catch {
        $snapshotErrors.Add("pre endpoint snapshot: $($_.Exception.Message)")
        Write-UdpEndpointErrorSnapshot -Path $preSnapshot -Stage "pre_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
            -Failure $_.Exception.Message -SourcePreflight $sourcePreflight
    }
    Assert-Condition ($sourcePreflight.valid -eq $true) `
        "fixed diagnostic source preflight failed: $($sourcePreflight.violations -join ',')"
    try {
        $metrics = Get-BoundedMetricsText -Port $ClientMetricsPort
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($metrics)) `
            "client pre-workload metrics snapshot is empty"
        Write-NewUtf8File -Path $metricsPrePath -Text $metrics -MaximumBytes 1048576
    } catch {
        $snapshotErrors.Add("client pre-workload metrics snapshot: $($_.Exception.Message)")
        Write-MetricsErrorSnapshot -Path $metricsPrePath -Stage "pre_workload" `
            -Failure $_.Exception.Message
    }

    $workloadArguments = @(
        "windows-tun-workload",
        "--scenario", "udp-8192-association-lookup-expiry",
        "--target-ip", $TargetIpv4,
        "--tcp-port", [string]$TargetTcpPort,
        "--udp-port", [string]$TargetUdpPort,
        "--output", $observationPath,
        "--diagnostic-ledger", $ledgerPath,
        "--diagnostic-run-nonce", $DiagnosticRunNonce,
        "--diagnostic-max-events", [string]$DiagnosticMaxEvents,
        "--diagnostic-trial-sequence", [string]$TrialSequence,
        "--source-ip", $diagnosticSourceIpv4,
        "--source-port-first", [string]$diagnosticSourcePortFirst,
        "--source-port-last", [string]$diagnosticSourcePortLast
    )
    $workloadResult = Invoke-BoundedNativeProcess -Executable $harness `
        -Arguments $workloadArguments -WorkingDirectory (Split-Path -Parent $harness) `
        -StdoutPath $stdoutPath -StderrPath $stderrPath `
        -MaximumOutputBytes 131072 -TimeoutSeconds 1800 `
        -Label "diagnostic workload"
    $workloadPid = $workloadResult.Pid
    $workloadExitCode = $workloadResult.ExitCode
    $workloadTimedOut = $workloadResult.TimedOut
    if ($workloadResult.OutputBoundaryExceeded) {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                (Get-Item -LiteralPath $path -Force).Length -gt 65536) {
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write)
                try { $stream.SetLength(65536) } finally { $stream.Dispose() }
            }
        }
        throw "diagnostic workload output exceeded 128 KiB"
    }
} catch {
    $infrastructureError = $_.Exception.Message
} finally {
    try {
        Write-UdpEndpointSnapshot -Path $postSnapshot -Stage "post_workload" `
            -ClientProcessId $ClientPid -ServerProcessId $ServerPid
    }
    catch {
        $snapshotErrors.Add("post endpoint snapshot: $($_.Exception.Message)")
        try {
            Write-UdpEndpointErrorSnapshot -Path $postSnapshot -Stage "post_workload" `
                -ClientProcessId $ClientPid -ServerProcessId $ServerPid `
                -Failure $_.Exception.Message
        } catch {
            $snapshotErrors.Add("post endpoint error document: $($_.Exception.Message)")
        }
    }
    try {
        $metrics = Get-BoundedMetricsText -Port $ClientMetricsPort
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($metrics)) `
            "client post-workload metrics snapshot is empty"
        Write-NewUtf8File -Path $metricsPostPath -Text $metrics -MaximumBytes 1048576
    } catch {
        $snapshotErrors.Add("client metrics snapshot: $($_.Exception.Message)")
        try {
            Write-MetricsErrorSnapshot -Path $metricsPostPath -Stage "post_workload" `
                -Failure $_.Exception.Message
        } catch {
            $snapshotErrors.Add("post metrics error document: $($_.Exception.Message)")
        }
    }
}

$ledgerHeaderValid = $false
$ledgerLines = 0
$ledgerError = $null
$ledgerClosed = $false
$ledgerTruncated = $false
$ledgerDroppedEvents = $null
$ledgerWriteFailures = $null
$ledgerBootstrapEventCount = 0
$ledgerSourcePrefixValid = $false
$ledgerSourceComplete = $false
try {
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
        throw "workload flow ledger was not created"
    }
    $ledgerItem = Get-Item -LiteralPath $ledgerPath -Force
    $maximumLedgerBytes = 16384L + ([long]$DiagnosticMaxEvents * 4097L)
    Assert-Condition ($ledgerItem.Length -gt 0 -and $ledgerItem.Length -le $maximumLedgerBytes) `
        "workload flow ledger exceeds its byte boundary"
    $headerLine = [IO.File]::ReadLines($ledgerPath) | Select-Object -First 1
    $header = $headerLine | ConvertFrom-Json -ErrorAction Stop
    $expectedHeaderFields = @(
        "closure", "max_events", "record_type", "run_nonce", "schema", "scope",
        "source_ip", "source_port_first", "source_port_last", "timestamp_clock",
        "trial_sequence"
    )
    $actualHeaderFields = @($header.PSObject.Properties.Name | Sort-Object)
    $ledgerHeaderValid = ($actualHeaderFields -join "`n") -ceq
        ($expectedHeaderFields -join "`n") -and
        [string]$header.schema -ceq `
        $workloadLedgerSchema -and
        [string]$header.record_type -ceq "header" -and
        [string]$header.scope -ceq "bootstrap" -and
        [string]$header.closure -ceq "workload_process_exit" -and
        [string]$header.run_nonce -ceq $DiagnosticRunNonce -and
        [string]$header.timestamp_clock -ceq
            "std_instant_normalized_nanoseconds" -and
        [int]$header.max_events -eq $DiagnosticMaxEvents -and
        [int]$header.trial_sequence -eq $TrialSequence -and
        [string]$header.source_ip -ceq $diagnosticSourceIpv4 -and
        [int]$header.source_port_first -eq $diagnosticSourcePortFirst -and
        [int]$header.source_port_last -eq $diagnosticSourcePortLast -and
        [int]$header.source_port_last - [int]$header.source_port_first + 1 -eq
            $diagnosticSourcePortCount
    Assert-Condition $ledgerHeaderValid "workload flow ledger header identity mismatch"
    $footer = $null
    $seenFooter = $false
    $seenTruncation = $false
    foreach ($line in [IO.File]::ReadLines($ledgerPath)) {
        $ledgerLines++
        Assert-Condition ($ledgerLines -le ($DiagnosticMaxEvents + 3)) `
            "workload flow ledger exceeds its line boundary"
        Assert-Condition ($script:utf8NoBom.GetByteCount($line) -le 4096) `
            "workload flow ledger line exceeds 4096 bytes"
        $record = $line | ConvertFrom-Json -ErrorAction Stop
        Assert-Condition ([string]$record.schema -ceq $workloadLedgerSchema) `
            "workload flow ledger record schema mismatch"
        if ($ledgerLines -eq 1) {
            Assert-Condition ([string]$record.record_type -ceq "header") `
                "workload flow ledger first record is not its header"
            continue
        }
        Assert-Condition (-not $seenFooter) `
            "workload flow ledger contains a record after its footer"
        if ([string]$record.record_type -ceq "truncation") {
            Assert-Condition (-not $seenTruncation) `
                "workload flow ledger contains duplicate truncation records"
            $seenTruncation = $true
            $ledgerTruncated = $true
            $ledgerDroppedEvents = [long]$record.dropped_events_at_least
            $ledgerWriteFailures = [long]$record.write_failures
        } elseif ([string]$record.record_type -ceq "event") {
            Assert-Condition (-not $seenTruncation) `
                "workload flow ledger contains an event after truncation"
            $requiredEventFields = @(
                "schema", "record_type", "event_index", "run_nonce",
                "trial_sequence", "phase", "association_index", "round",
                "workload_local_ip", "workload_local_port"
            )
            $actualEventFields = @($record.PSObject.Properties.Name)
            Assert-Condition (@($requiredEventFields | Where-Object {
                $actualEventFields -cnotcontains $_
            }).Count -eq 0) "workload flow ledger event source identity is incomplete"
            $expectedAssociationIndex = $ledgerBootstrapEventCount
            Assert-Condition ([string]$record.schema -ceq $workloadLedgerSchema -and
                [string]$record.run_nonce -ceq $DiagnosticRunNonce -and
                [int]$record.trial_sequence -eq $TrialSequence -and
                [string]$record.phase -ceq "bootstrap" -and
                [long]$record.event_index -eq $expectedAssociationIndex -and
                [long]$record.association_index -eq $expectedAssociationIndex -and
                [long]$record.round -eq 0 -and
                [string]$record.workload_local_ip -ceq $diagnosticSourceIpv4 -and
                [int]$record.workload_local_port -eq
                    ($diagnosticSourcePortFirst + $expectedAssociationIndex)) `
                "workload flow ledger fixed source-port prefix is invalid"
            $ledgerBootstrapEventCount++
            Assert-Condition ($ledgerBootstrapEventCount -le $diagnosticSourcePortCount) `
                "workload flow ledger exceeds fixed source-port coverage"
        } elseif ([string]$record.record_type -ceq "footer") {
            $seenFooter = $true
            $footer = $record
        } elseif ([string]$record.record_type -ceq "header") {
            throw "workload flow ledger contains a duplicate header"
        } else {
            throw "workload flow ledger contains an unknown record type"
        }
    }
    Assert-Condition ($ledgerLines -le ($DiagnosticMaxEvents + 3)) `
        "workload flow ledger exceeds its line boundary"
    $ledgerSourcePrefixValid = $true
    $ledgerSourceComplete = $ledgerBootstrapEventCount -eq $diagnosticSourcePortCount
    if ($null -ne $footer) {
        $expectedFooterFields = @(
            "attempted_events", "closed", "dropped_events", "events_written",
            "record_type", "run_nonce", "schema", "write_failures"
        )
        $actualFooterFields = @($footer.PSObject.Properties.Name | Sort-Object)
        $ledgerClosed = ($actualFooterFields -join "`n") -ceq
            ($expectedFooterFields -join "`n") -and
            [string]$footer.schema -ceq
            $workloadLedgerSchema -and
            [string]$footer.record_type -ceq "footer" -and
            [string]$footer.run_nonce -ceq $DiagnosticRunNonce -and
            $footer.closed -eq $true -and
            [long]$footer.events_written -eq $ledgerBootstrapEventCount -and
            [long]$footer.attempted_events -eq
                ([long]$footer.events_written + [long]$footer.dropped_events +
                    [long]$footer.write_failures)
        $ledgerDroppedEvents = [long]$footer.dropped_events
        $ledgerWriteFailures = [long]$footer.write_failures
    }
} catch {
    $ledgerError = $_.Exception.Message
}

$observationValid = $false
if (Test-Path -LiteralPath $observationPath -PathType Leaf) {
    try {
        $observation = Get-Content -LiteralPath $observationPath -Raw -Encoding utf8 |
            ConvertFrom-Json -Depth 8 -ErrorAction Stop
        $observationValid = $observation.schema_version -eq 1 -and
            [string]$observation.kind -ceq "windows_tun_guest_workload" -and
            [string]$observation.scenario -ceq `
                "udp-8192-association-lookup-expiry" -and
            [string]$observation.status -ceq "PASS"
    } catch {
        $snapshotErrors.Add("workload observation: $($_.Exception.Message)")
    }
}

$requiredArtifactPaths = @(
    $ledgerPath, $stdoutPath, $stderrPath,
    $preSnapshot, $postSnapshot, $metricsPrePath, $metricsPostPath
)
$requiredArtifactsPresent = @($requiredArtifactPaths | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf)
}).Count -eq 0
$workloadReportedPass = -not $workloadTimedOut -and $workloadExitCode -eq 0 -and
    $observationValid
$ledgerSourceCoverageValid = $ledgerSourcePrefixValid -and (
    -not $workloadReportedPass -or $ledgerSourceComplete
)
if ($workloadReportedPass -and -not $ledgerSourceComplete -and
    $null -eq $ledgerError) {
    $ledgerError = "passing workload did not cover all 8192 fixed source ports"
}
$evidenceStatus = if (
    $null -eq $infrastructureError -and
    $null -eq $ledgerError -and
    $ledgerHeaderValid -and $ledgerClosed -and -not $ledgerTruncated -and
    $ledgerSourceCoverageValid -and
    $ledgerDroppedEvents -eq 0 -and $ledgerWriteFailures -eq 0 -and
    $snapshotErrors.Count -eq 0 -and $requiredArtifactsPresent -and
    -not $workloadTimedOut
) {
    "COMPLETE"
} else {
    "PARTIAL"
}
$trialStatus = if ($workloadReportedPass -and $ledgerSourceCoverageValid) {
    "PASS"
} else {
    "FAIL"
}
$rawDocument = [ordered]@{
    schema = "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v2"
    qualification = $false
    profile = $Profile
    evidence_status = $evidenceStatus
    trial_status = $trialStatus
    started_utc = $startedUtc
    finished_utc = [DateTime]::UtcNow.ToString("o")
    identity = [ordered]@{
        run_kind = $RunKind
        member = $Member
        trial_sequence = $TrialSequence
        parent_sha = $ParentSha
        candidate_sha = $CandidateSha
        tree = $Tree
        recipe_sha256 = $RecipeSha256
        controller_bundle_sha256 = $ControllerBundleSha256
        harness_sha256 = $harnessSha256
        collector_sha256 = $collectorSha256
        diagnostic_run_nonce = $DiagnosticRunNonce
        diagnostic_max_events = $DiagnosticMaxEvents
    }
    workload = [ordered]@{
        pid = $workloadPid
        exit_code = $workloadExitCode
        global_timeout = $workloadTimedOut
        observation_valid = $observationValid
        source_ip = $diagnosticSourceIpv4
        source_port_first = $diagnosticSourcePortFirst
        source_port_last = $diagnosticSourcePortLast
        source_preflight = $sourcePreflight
        infrastructure_error = $infrastructureError
        flow_ledger_header_valid = $ledgerHeaderValid
        flow_ledger_lines = $ledgerLines
        flow_ledger_closed = $ledgerClosed
        flow_ledger_truncated = $ledgerTruncated
        flow_ledger_dropped_events = $ledgerDroppedEvents
        flow_ledger_write_failures = $ledgerWriteFailures
        flow_ledger_bootstrap_event_count = $ledgerBootstrapEventCount
        flow_ledger_source_prefix_valid = $ledgerSourcePrefixValid
        flow_ledger_source_complete = $ledgerSourceComplete
        flow_ledger_error = $ledgerError
    }
    artifacts = [ordered]@{
        workload_flow_ledger = Get-FileEvidence $ledgerPath 268451840
        workload_observation = Get-FileEvidence $observationPath 1048576
        workload_stdout = Get-FileEvidence $stdoutPath 131072
        workload_stderr = Get-FileEvidence $stderrPath 131072
        endpoints_pre = Get-FileEvidence $preSnapshot 4194304
        endpoints_post = Get-FileEvidence $postSnapshot 4194304
        client_metrics_pre = Get-FileEvidence $metricsPrePath 1048576
        client_metrics_post = Get-FileEvidence $metricsPostPath 1048576
    }
    snapshot_errors = $snapshotErrors.ToArray()
}
Write-NewUtf8File -Path $outputPath `
    -Text (($rawDocument | ConvertTo-Json -Depth 10) + "`n") -MaximumBytes 1048576
Write-Output "windows_tun_udp_boundary evidence=$evidenceStatus trial=$trialStatus output=$outputPath"
exit 0
