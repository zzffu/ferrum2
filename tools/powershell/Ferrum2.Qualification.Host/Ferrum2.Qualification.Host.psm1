Set-StrictMode -Version Latest
$performanceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "Ferrum2.Performance"
$processOwnerPath = Join-Path $performanceRoot "PerformanceProcessOwner.cs"
$notificationOwnerPath = Join-Path $PSScriptRoot "QualificationRouteNotification.cs"
if ($null -ne ("Ferrum2PerfProcessGroup" -as [type])) {
    throw "Ferrum2 host process owner is already loaded; use a fresh PowerShell process"
}
if ($null -ne ("Ferrum2QualificationRouteNotification" -as [type])) {
    throw "Ferrum2 qualification notification owner is already loaded; use a fresh PowerShell process"
}
Add-Type -Path $processOwnerPath -ErrorAction Stop
Add-Type -Path $notificationOwnerPath -ErrorAction Stop
foreach ($owner in @(
    (Join-Path $performanceRoot "HostOwnership.ps1"),
    (Join-Path $performanceRoot "HostExecution.ps1"),
    (Join-Path $PSScriptRoot "SourceBundle.ps1"),
    (Join-Path $PSScriptRoot "HostQualification.ps1")
)) {
    . $owner
}

Export-ModuleMember -Function Invoke-Ferrum2HostQualification
