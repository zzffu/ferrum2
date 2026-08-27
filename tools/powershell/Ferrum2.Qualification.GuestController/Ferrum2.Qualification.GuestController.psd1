@{
    RootModule = 'Ferrum2.Qualification.GuestController.psm1'
    ModuleVersion = '1.0.0'
    GUID = '4df9e7d4-a6cc-4212-bd21-1fc964f88088'
    Author = 'Ferrum2'
    CompanyName = 'Ferrum2'
    Copyright = 'GPL-3.0-only'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
        'Get-Ferrum2QualificationProfiles'
        'Get-Ferrum2QualificationSuiteProfiles'
        'Resolve-Ferrum2QualificationProfile'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
