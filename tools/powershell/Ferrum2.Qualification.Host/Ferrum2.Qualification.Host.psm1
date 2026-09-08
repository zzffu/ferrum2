Set-StrictMode -Version Latest
$processOwnerPath = Join-Path $PSScriptRoot "HostProcessOwner.cs"
$notificationOwnerPath = Join-Path $PSScriptRoot "QualificationRouteNotification.cs"
if ($null -ne ("Ferrum2HostProcessGroup" -as [type])) {
    throw "Ferrum2 host process owner is already loaded; use a fresh PowerShell process"
}
if ($null -ne ("Ferrum2QualificationRouteNotification" -as [type])) {
    throw "Ferrum2 qualification notification owner is already loaded; use a fresh PowerShell process"
}
Add-Type -Path $processOwnerPath -ErrorAction Stop
Add-Type -Path $notificationOwnerPath -ErrorAction Stop
foreach ($owner in @(
    (Join-Path $PSScriptRoot "AddressFamily.ps1"),
    (Join-Path $PSScriptRoot "HostOwnership.ps1"),
    (Join-Path $PSScriptRoot "HostCleanup.ps1"),
    (Join-Path $PSScriptRoot "HostFirewall.ps1"),
    (Join-Path $PSScriptRoot "HostExecution.ps1"),
    (Join-Path $PSScriptRoot "HostProduct.ps1"),
    (Join-Path $PSScriptRoot "SourceBundle.ps1"),
    (Join-Path $PSScriptRoot "WfpEvidence.ps1"),
    (Join-Path $PSScriptRoot "WorkloadEvidence.ps1"),
    (Join-Path $PSScriptRoot "HostQualification.ps1")
)) {
    . $owner
}

Export-ModuleMember -Function Invoke-Ferrum2HostQualification
