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
    param(
        [Parameter(Mandatory)] [string]$Profile,
        [ValidateRange(0, 10)] [int]$ValidationCycleLimit = 0
    )
    if ($Profile -cnotin $script:Profiles) {
        throw 'qualification profile is outside the closed set'
    }
    $isEndurance = $Profile -cin $script:EnduranceProfiles
    $cycleLimit = if (-not $isEndurance) {
        [long]0
    } elseif ($ValidationCycleLimit -gt 0) {
        [long]$ValidationCycleLimit
    } else {
        [long]1000
    }
    $releaseMilestones = if (-not $isEndurance) {
        @()
    } elseif ($ValidationCycleLimit -eq 1) {
        @([long]1)
    } elseif ($ValidationCycleLimit -gt 1) {
        @([long]1, [long]$ValidationCycleLimit)
    } else {
        @([long]10, [long]100, [long]1000)
    }
    [pscustomobject][ordered]@{
        profile = $Profile
        cycle_limit = $cycleLimit
        release_milestones = $releaseMilestones
    }
}

Export-ModuleMember -Function @(
    'Get-Ferrum2QualificationProfiles'
    'Get-Ferrum2QualificationSuiteProfiles'
    'Resolve-Ferrum2QualificationProfile'
)
