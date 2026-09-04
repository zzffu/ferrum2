Set-StrictMode -Version Latest

function Invoke-Ferrum2HostPerformance {
    [CmdletBinding(DefaultParameterSetName = "Run")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
        [switch]$PlanOnly,
        [Parameter(Mandatory = $true, ParameterSetName = "Recovery")]
        [switch]$RecoveryOnly,
        [Parameter(Mandatory = $true, ParameterSetName = "Safety")]
        [switch]$SafetyCheck,
        [Parameter(ParameterSetName = "Plan")]
        [Parameter(ParameterSetName = "Run")]
        [ValidateSet("Quick", "Confirm", "Lifecycle")]
        [string]$Mode = "Quick",
        [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
        [Parameter(Mandatory = $true, ParameterSetName = "Run")]
        [Parameter(Mandatory = $true, ParameterSetName = "Safety")]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$BaselineSha,
        [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
        [Parameter(Mandatory = $true, ParameterSetName = "Run")]
        [Parameter(Mandatory = $true, ParameterSetName = "Safety")]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true, ParameterSetName = "Run")]
        [Parameter(Mandatory = $true, ParameterSetName = "Safety")]
        [string]$EvidenceDirectory,
        [Parameter(ParameterSetName = "Run")]
        [Parameter(ParameterSetName = "Safety")]
        [switch]$AcknowledgeHostNetworkMutation,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$PerformanceSourceBundleSha256,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )
    if ($PlanOnly) {
        [void](Resolve-Ferrum2CommitSha -RepositoryRoot $RepositoryRoot -Sha $BaselineSha)
        [void](Resolve-Ferrum2CommitSha -RepositoryRoot $RepositoryRoot -Sha $CandidateSha)
        return New-Ferrum2HostPerformancePlan -Mode $Mode -BaselineSha $BaselineSha `
            -CandidateSha $CandidateSha `
            -PerformanceSourceBundleSha256 $PerformanceSourceBundleSha256
    }
    $mutex = $null
    $context = $null
    $succeeded = $false
    $totalTimer = $null
    $buildSeconds = 0.0
    $executionSeconds = 0.0
    $buildTimer = $null
    $executionTimer = $null
    try {
        $mutex = Enter-Ferrum2HostPerformanceMutex
        if ($RecoveryOnly) {
            return Invoke-Ferrum2HostPerformanceRecovery
        }
        Assert-Ferrum2HostPerformanceAuthorization `
            -Acknowledged ([bool]$AcknowledgeHostNetworkMutation)
        Assert-NoPendingFerrum2HostPerformanceRecovery
        $effectiveMode = if ($SafetyCheck) { "Quick" } else { $Mode }
        $plan = New-Ferrum2HostPerformancePlan -Mode $effectiveMode -BaselineSha $BaselineSha `
            -CandidateSha $CandidateSha `
            -PerformanceSourceBundleSha256 $PerformanceSourceBundleSha256
        $context = New-Ferrum2HostPerformanceContext -RepositoryRoot $RepositoryRoot `
            -EvidenceDirectory $EvidenceDirectory `
            -Mode $(if ($SafetyCheck) { "Safety" } else { $Mode }) `
            -BaselineSha $BaselineSha -CandidateSha $CandidateSha
        $totalTimer = [Diagnostics.Stopwatch]::StartNew()
        Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory "plan.json") -Document $plan
        $network = New-Ferrum2HostNetworkIdentity -RunId $context.run_id
        $loopback = Get-Ferrum2LoopbackIdentity
        Assert-Ferrum2HostNetworkIdentityAvailable -Network $network -Loopback $loopback
        Set-Ferrum2HostPerformanceState -Context $context -State "building"
        $buildTimer = [Diagnostics.Stopwatch]::StartNew()
        $builds = Initialize-Ferrum2HostBuilds -Context $context -BaselineSha $BaselineSha `
            -CandidateSha $CandidateSha
        $buildTimer.Stop()
        $buildSeconds = $buildTimer.Elapsed.TotalSeconds
        Set-Ferrum2HostPerformanceState -Context $context -State "executing"
        $executionTimer = [Diagnostics.Stopwatch]::StartNew()
        $result = if ($SafetyCheck) {
            Invoke-Ferrum2HostSafetyCheck -Context $context -Builds $builds -Network $network `
                -Loopback $loopback
        } elseif ($Mode -ceq "Lifecycle") {
            Invoke-Ferrum2HostLifecycleProfile -Context $context -Plan $plan -Builds $builds `
                -Network $network -Loopback $loopback
        } else {
            Invoke-Ferrum2HostPairedProfile -Context $context -Plan $plan -Builds $builds `
                -Network $network -Loopback $loopback
        }
        $executionTimer.Stop()
        $executionSeconds = $executionTimer.Elapsed.TotalSeconds
        $succeeded = $true
        return $result
    } finally {
        try {
            if ($null -ne $buildTimer -and $buildTimer.IsRunning) {
                $buildTimer.Stop()
                $buildSeconds = $buildTimer.Elapsed.TotalSeconds
            }
            if ($null -ne $context) {
                if ($null -ne $executionTimer -and $executionTimer.IsRunning) {
                    $executionTimer.Stop()
                    $executionSeconds = $executionTimer.Elapsed.TotalSeconds
                }
                $cleanupTimer = [Diagnostics.Stopwatch]::StartNew()
                $cleanup = Complete-Ferrum2HostPerformanceCleanup -Context $context `
                    -Succeeded $succeeded
                $cleanupTimer.Stop()
                if ($null -ne $totalTimer) { $totalTimer.Stop() }
                $runtime = [pscustomobject][ordered]@{
                    schema_version = 1
                    kind = "ferrum2.windows-tun.host-performance-runtime"
                    run_id = $context.run_id
                    mode = if ($SafetyCheck) { "Safety" } else { $Mode }
                    build_seconds = $buildSeconds
                    execution_seconds = $executionSeconds
                    cleanup_seconds = $cleanupTimer.Elapsed.TotalSeconds
                    elapsed_seconds = if ($null -eq $totalTimer) { 0.0 } else {
                        $totalTimer.Elapsed.TotalSeconds
                    }
                    cleanup_status = $cleanup.status
                }
                Write-AtomicJsonFile -Path (Join-Path $context.evidence_directory "runtime.json") `
                    -Document $runtime
            }
        } finally {
            Exit-Ferrum2HostPerformanceMutex -Mutex $mutex
        }
    }
}
