Set-StrictMode -Version Latest

$script:GuestRootFiles = @(
    'GuestTransaction.ps1'
    'GuestSupport.ps1'
    'PerformanceProcessOwner.cs'
)

$script:GuestNestedFiles = @(
    'CollectorCore.ps1'
    'CollectorUdpSource.ps1'
    'CollectorLifecycle.ps1'
    'TrialScenario.tcp-single-flow.ps1'
    'TrialScenario.tcp-256-flow-fairness.ps1'
    'TrialScenario.udp-packets-per-second.ps1'
    'TrialScenario.udp-8192-association-lookup-expiry.ps1'
    'TrialScenario.fragment-reassembly-throughput.ps1'
    'TrialScenario.idle-cpu-wakeup.ps1'
    'TrialScenario.wintun-ring-full-drop-rate.ps1'
    'TrialScenario.udp-route-once.ps1'
    'TrialScenario.network-lifecycle.ps1'
    'UdpDiagnosticCore.ps1'
    'UdpDiagnosticSource.ps1'
    'UdpDiagnosticEvidence.ps1'
)

function Get-Ferrum2PerformanceGuestFileMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleRoot
    )
    $resolvedRoot = (Resolve-Path -LiteralPath $ModuleRoot -ErrorAction Stop).Path
    $rows = @($script:GuestRootFiles | ForEach-Object {
        [pscustomobject][ordered]@{
            source_path = Join-Path $resolvedRoot $_
            relative_path = $_
        }
    }) + @($script:GuestNestedFiles | ForEach-Object {
        [pscustomobject][ordered]@{
            source_path = Join-Path $resolvedRoot $_
            relative_path = "powershell/Ferrum2.Performance/$_"
        }
    })
    foreach ($row in $rows) {
        if (-not (Test-Path -LiteralPath $row.source_path -PathType Leaf)) {
            throw "performance guest source is missing: $($row.source_path)"
        }
    }
    return $rows
}

Export-ModuleMember -Function Get-Ferrum2PerformanceGuestFileMap
