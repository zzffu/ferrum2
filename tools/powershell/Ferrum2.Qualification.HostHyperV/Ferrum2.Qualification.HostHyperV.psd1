@{
    RootModule = 'Ferrum2.Qualification.HostHyperV.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'bed23e51-6a11-4e21-a483-0ed3b9c3a06f'
    Author = 'Ferrum2'
    CompanyName = 'Ferrum2'
    Copyright = 'GPL-3.0-only'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
        'Invoke-Ferrum2QualificationHostController'
        'Initialize-Ferrum2HostHyperVModule'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
