Set-StrictMode -Version Latest
$processOwnerPath = Join-Path $PSScriptRoot "PerformanceProcessOwner.cs"
if ($null -eq ("Ferrum2PerfProcessGroup" -as [type])) {
    Add-Type -Path $processOwnerPath -ErrorAction Stop
}
foreach ($owner in @(
    "HostPlan.ps1",
    "HostOwnership.ps1",
    "HostExecution.ps1",
    "HostPerformance.ps1"
)) {
    . (Join-Path $PSScriptRoot $owner)
}

Export-ModuleMember -Function Invoke-Ferrum2HostPerformance
