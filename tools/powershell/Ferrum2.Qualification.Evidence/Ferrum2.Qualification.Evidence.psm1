Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$labManifest = Join-Path $PSScriptRoot `
    '..\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1'
Import-Module $labManifest -Scope Local -ErrorAction Stop

function Get-Ferrum2GuestControllerModuleFileMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepositoryRoot)
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($mapping in @(Get-Ferrum2WindowsTunLabRuntimeFileMap -RepositoryRoot $root)) {
        $rows.Add($mapping)
    }
    foreach ($name in @('Ferrum2.Qualification.GuestController')) {
        foreach ($extension in @('psd1', 'psm1')) {
            $rows.Add([pscustomobject][ordered]@{
                source_path = Join-Path $root "tools/powershell/$name/$name.$extension"
                relative_path = "modules/$name/$name.$extension"
            })
        }
    }
    @($rows)
}

function Get-Ferrum2SharedGuestOwnerNames {
    @(
        'Guest.Cleanup.ps1'
        'Guest.HardKillSupport.ps1'
        'Guest.Identity.ps1'
        'Guest.Runtime.ps1'
        'Guest.Topology.ps1'
        'Guest.NativeNetwork.cs.ps1'
        'Guest.NativeProcess.cs.ps1'
        'Guest.NativeTransport.cs.ps1'
        'Guest.TransportProbes.ps1'
    )
}

function Get-Ferrum2MainGuestOwnerNames {
    @(
        'Main.GuestController.ps1'
        'Main.GuestCleanupController.ps1'
        'Main.GuestBootstrapSupport.ps1'
        @(Get-Ferrum2SharedGuestOwnerNames)
        'Main.M17Contract.ps1'
        'Main.M17Protocol.ps1'
        'Main.M17Reset.ps1'
        'Main.M17Runtime.ps1'
        'Main.M17Scheduler.ps1'
        'Main.M17Udp.ps1'
    )
}

function Get-Ferrum2ControllerBundleFileMap {
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)]
        [ValidateSet('main', 'hard-kill')]
        [string]$Controller
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $platformRoot = Join-Path $root 'tests/platform'
    $entryPoint = if ($Controller -ceq 'main') {
        'qualify_windows_tun.ps1'
    } else {
        'qualify_windows_tun_hard_kill.ps1'
    }
    $ownerNames = [Collections.Generic.List[string]]::new()
    $ownerNames.Add($entryPoint)
    if ($Controller -ceq 'main') {
        $ownerNames.Add('qualify_windows_tun_cleanup.ps1')
        foreach ($name in Get-Ferrum2MainGuestOwnerNames) { $ownerNames.Add($name) }
    } else {
        foreach ($name in Get-Ferrum2SharedGuestOwnerNames) { $ownerNames.Add($name) }
        foreach ($name in @(
            'Hard.GuestController.ps1'
            'Hard.Qualification.ps1'
            'Hard.GuestCleanup.ps1'
            'Hard.GuestContract.ps1'
            'Hard.GuestEvidence.ps1'
        )) { $ownerNames.Add($name) }
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($name in $ownerNames) {
        $rows.Add([pscustomobject][ordered]@{
            source_path = Join-Path $platformRoot $name
            relative_path = $name
        })
    }
    $moduleMap = if ($Controller -ceq 'main') {
        @(Get-Ferrum2GuestControllerModuleFileMap -RepositoryRoot $root)
    } else {
        @(Get-Ferrum2WindowsTunLabRuntimeFileMap -RepositoryRoot $root)
    }
    foreach ($mapping in $moduleMap) { $rows.Add($mapping) }
    @($rows)
}

function Get-Ferrum2MainControllerBundleFileMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepositoryRoot)
    @(Get-Ferrum2ControllerBundleFileMap `
        -RepositoryRoot $RepositoryRoot -Controller 'main')
}

function Get-Ferrum2HardKillControllerBundleFileMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepositoryRoot)
    @(Get-Ferrum2ControllerBundleFileMap `
        -RepositoryRoot $RepositoryRoot -Controller 'hard-kill')
}

Export-ModuleMember -Function @(
    'Get-Ferrum2MainControllerBundleFileMap'
    'Get-Ferrum2HardKillControllerBundleFileMap'
)
