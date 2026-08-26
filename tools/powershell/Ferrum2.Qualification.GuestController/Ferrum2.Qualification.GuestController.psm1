Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Profiles = [ordered]@{
    'network-reset-10' = @('network-reset', 0, 10)
    'network-reset-100' = @('network-reset', 0, 100)
    'network-reset-1000' = @('network-reset', 0, 1000)
    'restart-10' = @('restart-stress', 10, 0)
    'restart-100' = @('restart-stress', 100, 0)
    'restart-1000' = @('restart-stress', 1000, 0)
    'fragments' = @('fragments', 0, 0)
    'dual-stack-dns' = @('dual-stack-dns', 0, 0)
    'udp-policy' = @('udp-policy', 0, 0)
    'scheduler-ring-full' = @('scheduler-ring-full', 0, 0)
    'fuzz-smoke' = @('fuzz-smoke', 0, 0)
}
$script:GuestModes = @(
    'lifecycle', 'tcp', 'tcp08', 'udp', 'cycles', 'full', 'performance',
    'network-feasibility', 'managed-product', 'hard-kill', 'network-reset',
    'restart-stress', 'fragments', 'dual-stack-dns', 'udp-policy',
    'scheduler-ring-full', 'cleanup'
)
$script:M17Modes = @(
    'network-reset', 'restart-stress', 'fragments', 'dual-stack-dns',
    'udp-policy', 'scheduler-ring-full'
)
$script:TopologyBoundModes = @(
    'network-feasibility', 'managed-product', 'full', 'hard-kill'
) + $script:M17Modes

function Get-Ferrum2QualificationProfiles {
    [CmdletBinding()]
    param()
    @($script:Profiles.Keys)
}

function Resolve-Ferrum2QualificationProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Profile)
    if (-not $script:Profiles.Contains($Profile)) {
        throw 'qualification profile is outside the closed set'
    }
    $value = $script:Profiles[$Profile]
    [pscustomobject][ordered]@{
        profile = $Profile
        mode = [string]$value[0]
        restart_cycles = [long]$value[1]
        network_reset_cycles = [long]$value[2]
    }
}

function Assert-Ferrum2GuestQualificationMode {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Mode)
    if ($Mode -cnotin $script:GuestModes) {
        throw 'guest qualification mode is outside the closed set'
    }
}

function Get-Ferrum2GuestQualificationModeContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Mode)
    Assert-Ferrum2GuestQualificationMode -Mode $Mode
    [pscustomobject][ordered]@{
        mode = $Mode
        is_m17 = $Mode -cin $script:M17Modes
        topology_bound = $Mode -cin $script:TopologyBoundModes
        requires_candidate_tests = $Mode -cin $script:M17Modes
        accepts_network_reset_cycles = $Mode -ceq 'network-reset'
        accepts_restart_cycles = $Mode -ceq 'restart-stress'
    }
}

Export-ModuleMember -Function @(
    'Get-Ferrum2QualificationProfiles'
    'Resolve-Ferrum2QualificationProfile'
    'Assert-Ferrum2GuestQualificationMode'
    'Get-Ferrum2GuestQualificationModeContract'
)
