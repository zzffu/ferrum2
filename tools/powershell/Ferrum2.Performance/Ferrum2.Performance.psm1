Set-StrictMode -Version Latest
$processOwnerPath = Join-Path $PSScriptRoot "PerformanceProcessOwner.cs"
if ($null -ne ("Ferrum2PerfProcessGroup" -as [type])) {
    throw "Ferrum2 performance process owner is already loaded; use a fresh PowerShell process"
}
Add-Type -Path $processOwnerPath -ErrorAction Stop
foreach ($owner in @(
    "HostPlan.ps1",
    "HostOwnership.ps1",
    "HostExecution.ps1",
    "HostProfiles.ps1",
    "HostPerformance.ps1"
)) {
    . (Join-Path $PSScriptRoot $owner)
}

Export-ModuleMember -Function Invoke-Ferrum2HostPerformance
