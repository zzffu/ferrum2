Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonManifest = Join-Path $PSScriptRoot '..\Ferrum2.Qualification.Common\Ferrum2.Qualification.Common.psd1'
Import-Module $commonManifest -Scope Local -Force -ErrorAction Stop

$script:BundleSchema = 'ferrum2.qualification-controller-bundle.v1'

function ConvertTo-Ferrum2BundleRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'controller bundle path must be relative'
    }
    $normalized = $Path.Replace('\', '/')
    if ($normalized -cmatch '(^|/)\.\.(/|$)' -or $normalized -cmatch '(^|/)\.(/|$)' -or
        $normalized -cmatch '//' -or $normalized -cmatch '[:*?"<>|]' -or
        $normalized.StartsWith('/') -or $normalized.EndsWith('/')) {
        throw 'controller bundle path is not canonical'
    }
    $normalized
}

function Get-Ferrum2BundleRootSha256([string]$EntryPoint, [object[]]$Files) {
    $rows = [Collections.Generic.List[string]]::new()
    $rows.Add('schema=' + $script:BundleSchema)
    $rows.Add('entrypoint=' + $EntryPoint)
    foreach ($file in $Files) {
        $rows.Add('path=' + [string]$file.path)
        $rows.Add('bytes=' + [string][long]$file.bytes)
        $rows.Add('sha256=' + [string]$file.sha256)
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($rows -join "`n") + "`n")
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Sort-Ferrum2BundleFiles([object[]]$Files) {
    $byPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($file in $Files) { $byPath.Add([string]$file.path, $file) }
    [string[]]$paths = @($byPath.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    @($paths | ForEach-Object { $byPath[$_] })
}

function Get-Ferrum2GuestControllerModuleFileMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [switch]$ExcludeGuestController
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $names = @(
        'Ferrum2.Qualification.Common'
        'Ferrum2.Qualification.Evidence'
    )
    if (-not $ExcludeGuestController) {
        $names = @($names[0], 'Ferrum2.Qualification.GuestController', $names[1])
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($name in $names) {
        foreach ($extension in @('psd1', 'psm1')) {
            $relative = "modules/$name/$name.$extension"
            $rows.Add([pscustomobject][ordered]@{
                source_path = Join-Path $root "tools/powershell/$name/$name.$extension"
                relative_path = $relative
            })
        }
    }
    $rows.Add([pscustomobject][ordered]@{
        source_path = Join-Path $root `
            'tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
        relative_path = `
            'modules/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
    })
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
        'Main.GuestBootstrapSupport.ps1'
        @(Get-Ferrum2SharedGuestOwnerNames)
        'Main.M17Contract.ps1'
        'Main.M17Protocol.ps1'
        'Main.M17Reset.ps1'
        'Main.M17Runtime.ps1'
        'Main.M17Scheduler.ps1'
        'Main.M17Udp.ps1'
        'Main.ProfileClassic.ps1'
        'Main.ProfileFullHardKill.ps1'
        'Main.ProfileManagedProduct.ps1'
        'Main.ProfileNetworkFeasibility.ps1'
        'Main.Tcp08Capture.ps1'
        'Main.Tcp08Evidence.ps1'
        'Main.Tcp08Network.ps1'
        'Main.Tcp08Profile.ps1'
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
    $moduleMap = if ($Controller -ceq 'hard-kill') {
        @(Get-Ferrum2GuestControllerModuleFileMap `
            -RepositoryRoot $root -ExcludeGuestController)
    } else {
        @(Get-Ferrum2GuestControllerModuleFileMap -RepositoryRoot $root)
    }
    foreach ($mapping in $moduleMap) {
        $rows.Add($mapping)
    }
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

function New-Ferrum2ControllerBundleManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]$FileMap,
        [Parameter(Mandatory)] [string]$EntryPoint
    )
    $entry = ConvertTo-Ferrum2BundleRelativePath $EntryPoint
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($mapping in $FileMap) {
        Assert-Ferrum2ClosedProperties $mapping @('source_path', 'relative_path') 'bundle file mapping'
        $relative = ConvertTo-Ferrum2BundleRelativePath ([string]$mapping.relative_path)
        if (-not $seen.Add($relative)) { throw 'controller bundle path is duplicated' }
        $source = Resolve-Ferrum2OrdinaryFile -Path ([string]$mapping.source_path) `
            -Label "controller bundle file $relative" -MaximumBytes 16MB
        $item = Get-Item -LiteralPath $source -Force -ErrorAction Stop
        $files.Add([pscustomobject][ordered]@{
            path = $relative
            bytes = [long]$item.Length
            sha256 = Get-Ferrum2LowerSha256 $source
        })
    }
    $ordered = @(Sort-Ferrum2BundleFiles @($files))
    if ($entry -cnotin @($ordered.path)) { throw 'controller bundle entrypoint is absent' }
    [pscustomobject][ordered]@{
        schema = $script:BundleSchema
        entrypoint = $entry
        files = $ordered
        controller_bundle_sha256 = Get-Ferrum2BundleRootSha256 $entry $ordered
    }
}

function Assert-Ferrum2ControllerBundleManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [string]$BundleRoot
    )
    Assert-Ferrum2ClosedProperties $Manifest `
        @('schema', 'entrypoint', 'files', 'controller_bundle_sha256') 'controller bundle manifest'
    if ($Manifest.schema -cne $script:BundleSchema -or
        [string]$Manifest.controller_bundle_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'controller bundle manifest identity is invalid'
    }
    $root = (Resolve-Path -LiteralPath $BundleRoot -ErrorAction Stop).Path
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Manifest.files)) {
        Assert-Ferrum2ClosedProperties $file @('path', 'bytes', 'sha256') 'controller bundle file'
        $relative = ConvertTo-Ferrum2BundleRelativePath ([string]$file.path)
        if (-not $seen.Add($relative) -or $file.bytes -isnot [long] -or
            [long]$file.bytes -lt 1 -or [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'controller bundle file identity is invalid'
        }
        $path = Join-Path $root $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $resolved = Resolve-Ferrum2OrdinaryFile -Path $path -Label "controller bundle file $relative" `
            -MaximumBytes 16MB -RequiredRoot $root
        $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if ([long]$item.Length -ne [long]$file.bytes -or
            (Get-Ferrum2LowerSha256 $resolved) -cne [string]$file.sha256) {
            throw 'controller bundle file readback failed'
        }
        $files.Add([pscustomobject][ordered]@{
            path = $relative
            bytes = [long]$file.bytes
            sha256 = [string]$file.sha256
        })
    }
    $ordered = @(Sort-Ferrum2BundleFiles @($files))
    if ((@($files.path) -join '|') -cne (@($ordered.path) -join '|') -or
        [string]$Manifest.entrypoint -cnotin @($ordered.path) -or
        (Get-Ferrum2BundleRootSha256 ([string]$Manifest.entrypoint) $ordered) -cne
            [string]$Manifest.controller_bundle_sha256) {
        throw 'controller bundle canonical root readback failed'
    }
    $true
}

function Copy-Ferrum2ControllerBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]$FileMap,
        [Parameter(Mandatory)] [object]$Manifest,
        [Parameter(Mandatory)] [string]$DestinationRoot
    )
    $mappingPaths = [Collections.Generic.List[string]]::new()
    foreach ($mapping in $FileMap) {
        Assert-Ferrum2ClosedProperties $mapping @('source_path', 'relative_path') `
            'bundle file mapping'
        $mappingPaths.Add(
            (ConvertTo-Ferrum2BundleRelativePath ([string]$mapping.relative_path))
        )
    }
    [string[]]$orderedMappingPaths = @($mappingPaths)
    [Array]::Sort($orderedMappingPaths, [StringComparer]::Ordinal)
    $manifestPaths = @($Manifest.files | ForEach-Object { [string]$_.path })
    if (($orderedMappingPaths -join '|') -cne ($manifestPaths -join '|')) {
        throw 'controller bundle file map does not match its manifest'
    }
    if (Test-Path -LiteralPath $DestinationRoot) { throw 'controller bundle destination must be absent' }
    [void](New-Item -ItemType Directory -Path $DestinationRoot -ErrorAction Stop)
    foreach ($mapping in $FileMap) {
        $relative = ConvertTo-Ferrum2BundleRelativePath ([string]$mapping.relative_path)
        $destination = Join-Path $DestinationRoot $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [void](New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force -ErrorAction Stop)
        [IO.File]::Copy([string]$mapping.source_path, $destination, $false)
    }
    [void](Assert-Ferrum2ControllerBundleManifest -Manifest $Manifest -BundleRoot $DestinationRoot)
}

function Write-Ferrum2ControllerBundleManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [object]$Manifest
    )
    Write-Ferrum2JsonCreateNew -Path $Path -Value $Manifest -Depth 8
}

Export-ModuleMember -Function @(
    'New-Ferrum2ControllerBundleManifest'
    'Assert-Ferrum2ControllerBundleManifest'
    'Copy-Ferrum2ControllerBundle'
    'Write-Ferrum2ControllerBundleManifest'
    'Get-Ferrum2GuestControllerModuleFileMap'
    'Get-Ferrum2MainControllerBundleFileMap'
    'Get-Ferrum2HardKillControllerBundleFileMap'
)
