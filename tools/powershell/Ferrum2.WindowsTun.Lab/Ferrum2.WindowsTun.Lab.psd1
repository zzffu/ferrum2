@{
    RootModule = 'Ferrum2.WindowsTun.Lab.psm1'
    ModuleVersion = '1.0.0'
    GUID = '294008b4-2ccd-4271-a5a8-7834b02c2f86'
    Author = 'Ferrum2'
    CompanyName = 'Ferrum2'
    Copyright = 'GPL-3.0-only'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
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
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
