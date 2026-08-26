@{
    RootModule = 'Ferrum2.Qualification.Common.psm1'
    ModuleVersion = '1.0.0'
    GUID = '89df3298-5561-4f8e-b19a-2cfbdba28548'
    Author = 'Ferrum2'
    CompanyName = 'Ferrum2'
    Copyright = 'GPL-3.0-only'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
        'Assert-Ferrum2ClosedProperties'
        'Get-Ferrum2LowerSha256'
        'Resolve-Ferrum2OrdinaryFile'
        'Test-Ferrum2PathWithinRoot'
        'Write-Ferrum2JsonCreateNew'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
