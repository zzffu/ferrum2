Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($owner in @(
    'private/JsonSource.ps1'
    'private/BundleFileSystem.ps1'
    'private/VmSession.ps1'
)) {
    . (Join-Path $PSScriptRoot $owner)
}

Export-ModuleMember -Function @(
    'Assert-Ferrum2ClosedProperties'
    'Get-Ferrum2LowerSha256'
    'ConvertTo-Ferrum2CanonicalGuid'
    'ConvertTo-Ferrum2CanonicalMacAddress'
    'Get-Ferrum2VmAdapterInstanceGuid'
    'Read-Ferrum2JsonDocument'
    'Read-Ferrum2ClosedSourceManifest'
    'Resolve-Ferrum2OrdinaryFile'
    'Test-Ferrum2PathWithinRoot'
    'Write-Ferrum2JsonCreateNew'
    'New-Ferrum2ControllerBundleManifest'
    'Assert-Ferrum2ControllerBundleManifest'
    'Copy-Ferrum2ControllerBundle'
    'Write-Ferrum2ControllerBundleManifest'
    'Resolve-Ferrum2HostInput'
    'Resolve-Ferrum2HostOutputFile'
    'Assert-Ferrum2NoReparsePointInExistingPath'
    'New-Ferrum2PinnedVmIdentity'
    'Get-Ferrum2PinnedVmContext'
    'Invoke-Ferrum2PinnedVmLifecycle'
    'Connect-Ferrum2PinnedVmGuest'
    'Stop-Ferrum2PinnedVmGuest'
    'New-Ferrum2HostVmIdentity'
    'Get-Ferrum2HostVmContext'
    'Invoke-Ferrum2HostVmLifecycle'
    'Connect-Ferrum2HostGuest'
    'Get-Ferrum2WindowsTunLabBootstrapFileMap'
    'Get-Ferrum2WindowsTunLabRuntimeFileMap'
)
