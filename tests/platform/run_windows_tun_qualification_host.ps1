#requires -Version 7.4

<#
.SYNOPSIS
Runs the bounded, explicitly authorized Windows-host Wintun correctness qualification.

.DESCRIPTION
PlanOnly is unprivileged and nonmutating. RecoveryOnly removes only identities retained in the
transaction ledger. A real qualification requires an already elevated shell and the literal
-AcknowledgeHostNetworkMutation switch. The complete supervised run is capped at 900 seconds.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [switch]$PlanOnly,
    [Parameter(Mandatory = $true, ParameterSetName = "Recovery")]
    [switch]$RecoveryOnly,
    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$EvidenceDirectory,
    [Parameter(ParameterSetName = "Run")]
    [switch]$AcknowledgeHostNetworkMutation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$maximumElapsedSeconds = 900
$workerTimeoutSeconds = 840
$supervisorTimer = [Diagnostics.Stopwatch]::StartNew()
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') `
    -ErrorAction Stop).Path
$moduleRoot = Join-Path $repositoryRoot 'tools\powershell\Ferrum2.Qualification.Host'
. (Join-Path $moduleRoot 'SourceBundle.ps1')
$sourceBundle = Read-Ferrum2HostQualificationSourceBundle `
    -RepositoryRoot $repositoryRoot `
    -ManifestPath (Join-Path $moduleRoot 'bundle.json')
. (Join-Path $moduleRoot 'SupervisorEvidence.ps1')

if ($PlanOnly -or $RecoveryOnly) {
    Import-Module -Name (Join-Path $moduleRoot 'Ferrum2.Qualification.Host.psd1') `
        -Force -ErrorAction Stop
    $arguments = @{
        RepositoryRoot = $repositoryRoot
        QualificationSourceBundleSha256 = $sourceBundle.sha256
    }
    if ($PlanOnly) {
        $arguments.PlanOnly = [Management.Automation.SwitchParameter]$true
        $arguments.CandidateSha = $CandidateSha
    } else {
        $arguments.RecoveryOnly = [Management.Automation.SwitchParameter]$true
    }
    Invoke-Ferrum2HostQualification @arguments | ConvertTo-Json -Depth 20
    exit 0
}

if (-not $AcknowledgeHostNetworkMutation) {
    throw 'host qualification requires -AcknowledgeHostNetworkMutation'
}
if ($EvidenceDirectory -match '["\r\n]' -or
    [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    throw 'host qualification evidence path is invalid'
}
$resolvedEvidence = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\', '/')
if (Test-Path -LiteralPath $resolvedEvidence) {
    throw 'host qualification evidence directory baseline must be absent'
}

$supervisorRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ferrum2-host-qualification-supervisor-' + [Guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $supervisorRoot -ErrorAction Stop | Out-Null
$stdoutPath = Join-Path $supervisorRoot 'worker.stdout.log'
$stderrPath = Join-Path $supervisorRoot 'worker.stderr.log'
$processOwnerPath = Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Performance\PerformanceProcessOwner.cs'
Add-Type -Path $processOwnerPath -ErrorAction Stop
$pwsh = [string](Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
$worker = Join-Path $PSScriptRoot 'invoke_windows_tun_qualification_host_worker.ps1'
$workerArguments = @(
    '-NoProfile'
    '-File', ('"' + $worker + '"')
    '-CandidateSha', $CandidateSha
    '-EvidenceDirectory', ('"' + $resolvedEvidence + '"')
    '-QualificationSourceBundleSha256', $sourceBundle.sha256
    '-AcknowledgeHostNetworkMutation'
) -join ' '
$workerPid = $null
$timedOut = $false
$outcome = [ordered]@{
    phase = 'worker-start'; worker_exit_code = $null; recovery_exit_code = $null
    worker_timed_out = $false; recovery_timed_out = $false
    primary_error = $null; cleanup_error = $null
    cleanup_phase = 'pending'; cleanup_failures = @()
}
try {
    $workerPid = [Ferrum2PerfProcessGroup]::Start(
        $pwsh, $workerArguments, $repositoryRoot, $stdoutPath, $stderrPath
    )
    if (-not [Ferrum2PerfProcessGroup]::Wait(
            [uint32]$workerPid, [uint32]($workerTimeoutSeconds * 1000))) {
        $timedOut = $true
        $outcome.worker_timed_out = $true
        [Ferrum2PerfProcessGroup]::CloseGroup()
    } else {
        $exitCode = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$workerPid)
        $outcome.worker_exit_code = $exitCode
        [Ferrum2PerfProcessGroup]::Close([uint32]$workerPid)
        [Ferrum2PerfProcessGroup]::CloseGroup()
        if ($exitCode -ne 0) {
            throw "host qualification worker failed; evidence=$resolvedEvidence"
        }
    }
    if ($timedOut) {
        $outcome.phase = 'recovery'
        $recoveryStdout = Join-Path $supervisorRoot 'recovery.stdout.log'
        $recoveryStderr = Join-Path $supervisorRoot 'recovery.stderr.log'
        $recoveryArguments = @(
            '-NoProfile'
            '-File', ('"' + $PSCommandPath + '"')
            '-RecoveryOnly'
        ) -join ' '
        $recoveryPid = [Ferrum2PerfProcessGroup]::Start(
            $pwsh, $recoveryArguments, $repositoryRoot, $recoveryStdout, $recoveryStderr
        )
        if (-not [Ferrum2PerfProcessGroup]::Wait([uint32]$recoveryPid, 45000)) {
            $outcome.recovery_timed_out = $true
            [Ferrum2PerfProcessGroup]::CloseGroup()
            throw 'host qualification timed out and bounded recovery also timed out'
        }
        $recoveryExit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$recoveryPid)
        $outcome.recovery_exit_code = $recoveryExit
        [Ferrum2PerfProcessGroup]::Close([uint32]$recoveryPid)
        [Ferrum2PerfProcessGroup]::CloseGroup()
        if ($recoveryExit -ne 0) {
            throw "host qualification timed out and recovery failed; evidence=$resolvedEvidence; recovery log=recovery.stderr.log"
        }
        throw "host qualification exceeded the $workerTimeoutSeconds-second worker limit"
    }

    $outcome.phase = 'verdict'
    $workerResultPath = Join-Path $resolvedEvidence 'qualification-worker.json'
    $cleanupPath = Join-Path $resolvedEvidence 'qualification-cleanup.json'
    if (-not (Test-Path -LiteralPath $workerResultPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $cleanupPath -PathType Leaf)) {
        throw 'host qualification worker evidence is incomplete'
    }
    $workerResult = Get-Content -LiteralPath $workerResultPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 20 -ErrorAction Stop
    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 10 -ErrorAction Stop
    $expectedChecks = @(
        'single-candidate-build',
        'wintun-create-and-delete',
        'system-tcp-and-udp-through-owned-tun',
        'narrow-route-isolation',
        'exact-tcp-ingress-wfp-live-readback',
        'network-reset-retains-strict-route-and-replaces-tcp-ingress-epoch',
        'forced-process-tree-recovery',
        'zero-residue-cleanup'
    )
    $actualChecks = @($workerResult.checks)
    $actualCheckNames = @($actualChecks | ForEach-Object { [string]$_.name })
    $tcpIngress = $workerResult.tcp_ingress_wfp
    $ingressSnapshots = @(
        $tcpIngress.normal_start,
        $tcpIngress.before_network_reset,
        $tcpIngress.after_network_reset,
        $tcpIngress.before_forced_close
    )
    $expectedConditionShape = @(
        'FWPM_CONDITION_ALE_APP_ID:FWP_BYTE_BLOB_TYPE:FWP_MATCH_EQUAL',
        'FWPM_CONDITION_IP_LOCAL_ADDRESS:FWP_UINT32:FWP_MATCH_EQUAL',
        'FWPM_CONDITION_IP_LOCAL_INTERFACE:FWP_UINT64:FWP_MATCH_EQUAL',
        'FWPM_CONDITION_IP_LOCAL_PORT:FWP_UINT16:FWP_MATCH_EQUAL',
        'FWPM_CONDITION_IP_PROTOCOL:FWP_UINT8:FWP_MATCH_EQUAL',
        'FWPM_CONDITION_IP_REMOTE_ADDRESS:FWP_UINT32:FWP_MATCH_EQUAL'
    ) -join '|'
    $ingressEvidenceValid = (
        @($ingressSnapshots | Where-Object {
            (@($_.session_flags) -join '|') -cne 'FWPM_SESSION_FLAG_DYNAMIC' -or
            $_.session_key -cne '41b9d0c7-65ac-49a7-8d97-bf8ad5abbe01' -or
            $_.sublayer_key -cne '5e741969-f578-43bd-a1e2-a420c49a7f01' -or
            [string]$_.sublayer_weight -cnotmatch '^[1-9][0-9]{0,4}$' -or
            $_.process_id -ne $_.listener.process_id -or
            $_.filter.name -cne 'Ferrum2 TCP ingress IPv4' -or
            [string]$_.filter.key -cnotmatch '^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$' -or
            [string]$_.filter.id -cnotmatch '^[1-9][0-9]*$' -or
            $_.filter.layer -cne 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4' -or
            $_.filter.action -cne 'FWP_ACTION_PERMIT' -or
            $_.filter.flags -cnotcontains 'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT' -or
            @($_.filter.flags | Where-Object {
                $_ -cnotin @(
                    'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT',
                    'FWPM_FILTER_FLAG_INDEXED'
                )
            }).Count -ne 0 -or
            $_.filter.requested_weight.type -cne 'FWP_UINT8' -or
            $_.filter.requested_weight.value -cne '15' -or
            $_.filter.effective_weight.type -cne 'FWP_UINT64' -or
            [string]$_.filter.effective_weight.value -cnotmatch '^[1-9][0-9]*$' -or
            $null -ne $_.filter.provider_key -or
            $null -ne $_.filter.provider_context_key -or
            $_.filter.provider_data_size -ne 0 -or
            $null -ne $_.filter.reserved -or $_.filter.raw_context -ne 0 -or
            (@($_.filter.conditions | ForEach-Object {
                "$($_.field_key):$($_.type):$($_.match_type)"
            } | Sort-Object) -join '|') -cne $expectedConditionShape -or
            $_.listener.address_family -cne 'IPv4' -or
            $_.listener.local_address -in @('0.0.0.0', '::') -or
            $_.listener.local_port -eq 0 -or
            $_.listener.wildcard_listener_count -ne 0
        }).Count -eq 0 -and
        $tcpIngress.reset_epoch.old_filter_absent_after_reset -eq $true -and
        $tcpIngress.reset_epoch.old_filter_key -cne $tcpIngress.reset_epoch.new_filter_key -and
        $tcpIngress.reset_epoch.old_filter_id -cne $tcpIngress.reset_epoch.new_filter_id -and
        $tcpIngress.reset_epoch.old_local_port -ne $tcpIngress.reset_epoch.new_local_port -and
        @($tcpIngress.absence).Count -eq 4 -and
        @($tcpIngress.absence | Where-Object {
            $_.strict_route_objects -ne 0 -or $_.tcp_ingress_objects -ne 0
        }).Count -eq 0
    )
    $strictRoute = $workerResult.strict_route_wfp
    $resetEvidenceValid = (
        $strictRoute.notification.observed -eq $true -and
        $strictRoute.notification.session_generation_after -gt
            $strictRoute.notification.session_generation_before -and
        $strictRoute.before_network_reset.sublayer_weight -ceq
            $strictRoute.after_network_reset.sublayer_weight -and
        (@($strictRoute.before_network_reset.filters.id) -join '|') -ceq
            (@($strictRoute.after_network_reset.filters.id) -join '|')
    )
    if ($workerResult.status -cne 'PASS' -or $workerResult.qualification -ne $true -or
        $workerResult.candidate_sha -cne $CandidateSha -or
        $workerResult.qualification_source_bundle_sha256 -cne $sourceBundle.sha256 -or
        ($actualCheckNames -join '|') -cne ($expectedChecks -join '|') -or
        @($actualChecks | Where-Object { $_.status -cne 'PASS' }).Count -ne 0 -or
        $cleanup.status -cne 'PASS' -or $cleanup.adapter_remaining -ne 0 -or
        $cleanup.routes_remaining -ne 0 -or $cleanup.addresses_remaining -ne 0 -or
        $cleanup.processes_remaining -ne 0 -or $cleanup.ports_remaining -ne 0 -or
        $cleanup.strict_route_wfp_remaining -ne 0 -or
        $cleanup.tcp_ingress_wfp_remaining -ne 0 -or
        -not $ingressEvidenceValid -or -not $resetEvidenceValid -or
        $supervisorTimer.Elapsed.TotalSeconds -ge $maximumElapsedSeconds) {
        throw 'host qualification verdict or bounded cleanup is invalid'
    }
    $result = [pscustomobject][ordered]@{
        schema_version = 1
        kind = 'ferrum2.windows-tun.host-qualification'
        status = 'QUALIFIED'
        qualification = $true
        candidate_sha = $CandidateSha
        qualification_source_bundle_sha256 = $sourceBundle.sha256
        maximum_elapsed_seconds = $maximumElapsedSeconds
        supervisor_elapsed_seconds = $supervisorTimer.Elapsed.TotalSeconds
        checks = @($workerResult.checks)
        route_proofs = @($workerResult.route_proofs)
        strict_route_wfp = $workerResult.strict_route_wfp
        tcp_ingress_wfp = $workerResult.tcp_ingress_wfp
        cleanup = $cleanup
    }
    $outcome.phase = 'verdict-ready'
} catch {
    $outcome.primary_error = [string]$_.Exception.Message
    throw
} finally {
    $closeFailure = $null
    try { [Ferrum2PerfProcessGroup]::CloseGroup() } catch {
        $closeFailure = $_
        $outcome.cleanup_phase = 'close-process-group'
        $outcome.cleanup_error = [string]$_.Exception.Message
        $outcome.cleanup_failures = @($outcome.cleanup_failures) + @(
            [pscustomobject]@{ phase = $outcome.cleanup_phase; error = $outcome.cleanup_error })
    }
    try {
        Complete-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $supervisorRoot `
            -EvidenceDirectory $resolvedEvidence -Outcome $outcome
    } catch {
        if ($null -eq $closeFailure) { $closeFailure = $_ }
    }
    if ($null -ne $closeFailure) {
        if ($null -eq $outcome.primary_error) { throw $closeFailure }
        Write-Warning "supervisor cleanup failed in $($outcome.cleanup_phase); see supervisor-outcome.json"
    }
}
$supervisorTimer.Stop()
if ($supervisorTimer.Elapsed.TotalSeconds -ge $maximumElapsedSeconds) {
    throw 'host qualification exceeded its total deadline including supervisor cleanup'
}
$result.supervisor_elapsed_seconds = $supervisorTimer.Elapsed.TotalSeconds
$resultPath = Join-Path $resolvedEvidence 'qualification.json'
[IO.File]::WriteAllText($resultPath, (($result | ConvertTo-Json -Depth 20) + "`n"),
    [Text.UTF8Encoding]::new($false))
$result | ConvertTo-Json -Depth 20
