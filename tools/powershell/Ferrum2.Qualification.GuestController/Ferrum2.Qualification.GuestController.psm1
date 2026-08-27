Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CoreProfiles = @(
    'fragments', 'dual-stack-dns', 'udp-policy', 'scheduler-ring-full'
)
$script:EnduranceProfiles = @('network-reset', 'restart-stress')
$script:Profiles = @($script:CoreProfiles) + @($script:EnduranceProfiles)

function Get-Ferrum2QualificationProfiles {
    [CmdletBinding()]
    param()
    @($script:Profiles)
}

function Get-Ferrum2QualificationSuiteProfiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Core', 'Endurance', 'Release')]
        [string]$Suite
    )
    switch ($Suite) {
        'Core' { @($script:CoreProfiles) }
        'Endurance' { @($script:EnduranceProfiles) }
        'Release' { @($script:Profiles) }
    }
}

function Resolve-Ferrum2QualificationProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Profile)
    if ($Profile -cnotin $script:Profiles) {
        throw 'qualification profile is outside the closed set'
    }
    $isEndurance = $Profile -cin $script:EnduranceProfiles
    [pscustomobject][ordered]@{
        profile = $Profile
        cycle_limit = if ($isEndurance) { [long]1000 } else { [long]0 }
        release_milestones = if ($isEndurance) { @([long]10, [long]100, [long]1000) } else { @() }
    }
}

Export-ModuleMember -Function @(
    'Get-Ferrum2QualificationProfiles'
    'Get-Ferrum2QualificationSuiteProfiles'
    'Resolve-Ferrum2QualificationProfile'
)
