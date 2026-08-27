function Test-Ferrum2PathWithinRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
}

function Resolve-Ferrum2OrdinaryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [ValidateRange(1, [long]::MaxValue)] [long]$MaximumBytes = 1GB,
        [string]$RequiredRoot
    )
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    Assert-Ferrum2NoReparsePointInExistingPath -Path $Path -Label $Label
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if ($RequiredRoot) {
        Assert-Ferrum2NoReparsePointInExistingPath `
            -Path $RequiredRoot `
            -Label "$Label required root"
        if (-not (Test-Ferrum2PathWithinRoot -Path $resolved -Root $RequiredRoot)) {
            throw "$Label escaped its required root"
        }
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 1 -or $item.Length -gt $MaximumBytes) {
        throw "$Label file boundary is invalid"
    }
    $resolved
}

function Write-Ferrum2JsonCreateNew {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [object]$Value,
        [ValidateRange(2, 64)] [int]$Depth = 12
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'JSON parent directory is absent'
    }
    $json = ($Value | ConvertTo-Json -Depth $Depth) -replace "`r`n", "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writeFailure = $null
    $disposeFailure = $null
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } catch {
        $writeFailure = $_
    } finally {
        try { $stream.Dispose() } catch { $disposeFailure = $_ }
    }
    if ($null -ne $writeFailure) {
        if ($null -ne $disposeFailure) {
            throw (
                'JSON create-new write failed: ' +
                    "primary=$($writeFailure.Exception.Message); " +
                    "disposal=$($disposeFailure.Exception.Message)"
            )
        }
        throw $writeFailure
    }
    if ($null -ne $disposeFailure) {
        throw "JSON create-new disposal failed: $($disposeFailure.Exception.Message)"
    }
}

$script:BundleSchema = 'ferrum2.windows-tun-controller-bundle.v1'

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

function Get-Ferrum2WindowsTunLabBootstrapFileMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepositoryRoot)

    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $moduleName = 'Ferrum2.WindowsTun.Lab'
    @(
        [pscustomobject][ordered]@{
            source_path = Join-Path $root `
                "tools/powershell/$moduleName/BundleBootstrap.ps1"
            relative_path = "modules/$moduleName/BundleBootstrap.ps1"
        }
    )
}

function Get-Ferrum2WindowsTunLabRuntimeFileMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepositoryRoot)

    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $moduleName = 'Ferrum2.WindowsTun.Lab'
    @(
        foreach ($fileName in @(
            'Ferrum2.WindowsTun.Lab.psd1'
            'Ferrum2.WindowsTun.Lab.psm1'
            'BundleBootstrap.ps1'
            'private/JsonSource.ps1'
            'private/BundleFileSystem.ps1'
            'private/VmSession.ps1'
        )) {
            [pscustomobject][ordered]@{
                source_path = Join-Path $root "tools/powershell/$moduleName/$fileName"
                relative_path = "modules/$moduleName/$fileName"
            }
        }
    )
}

function Assert-Ferrum2NoReparsePointInExistingPath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use a rooted filesystem path"
    }
    $current = $root
    $relative = $fullPath.Substring($root.Length)
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) { break }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function Resolve-Ferrum2HostInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)]
        [ValidateSet('ExternalFile', 'ExternalDirectory', 'GuestCredential')]
        [string]$Kind,
        [long]$MaximumBytes = 1073741824
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $candidate = $Path
    if ($Kind -ceq 'GuestCredential' -and [string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw 'LOCALAPPDATA is unavailable for the default guest credential'
        }
        $candidate = Join-Path $env:LOCALAPPDATA `
            'Ferrum2\hyperv-ferrum2-test.credential.xml'
    }
    if (-not [IO.Path]::IsPathFullyQualified($candidate)) {
        throw "$Label path must be absolute"
    }
    if ($Kind -ceq 'ExternalDirectory') {
        $fullPath = [IO.Path]::GetFullPath($candidate).
            TrimEnd([IO.Path]::DirectorySeparatorChar)
        if (Test-Ferrum2PathWithinRoot -Path $fullPath -Root $root) {
            throw "$Label must be stored outside the repository"
        }
        if (Test-Path -LiteralPath $fullPath) { throw "$Label baseline must be absent" }
        $ancestor = [IO.Path]::GetDirectoryName($fullPath)
        while (-not [string]::IsNullOrWhiteSpace($ancestor) -and
            -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
            $next = [IO.Path]::GetDirectoryName($ancestor)
            if ($next -ceq $ancestor) { break }
            $ancestor = $next
        }
        if ([string]::IsNullOrWhiteSpace($ancestor) -or
            -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
            throw "$Label has no existing parent boundary"
        }
        Assert-Ferrum2NoReparsePointInExistingPath -Path $ancestor -Label $Label
        return $fullPath
    }
    Assert-Ferrum2NoReparsePointInExistingPath -Path $candidate -Label $Label
    $resolved = Resolve-Ferrum2OrdinaryFile -Path $candidate -Label $Label `
        -MaximumBytes $MaximumBytes
    if (Test-Ferrum2PathWithinRoot -Path $resolved -Root $root) {
        throw "$Label must be stored outside the repository"
    }
    if ($Kind -ceq 'GuestCredential') {
        $credential = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
        if ($credential -isnot [Management.Automation.PSCredential] -or
            [string]$credential.UserName -cne 'ferrum2-test') {
            throw 'guest credential file does not contain the approved local PSCredential'
        }
        return $credential
    }
    $resolved
}

function Resolve-Ferrum2HostOutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [string]$Extension
    )

    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $candidate = [IO.Path]::GetFullPath($Path)
    if (Test-Ferrum2PathWithinRoot -Path $candidate -Root $root) {
        throw "$Label must be stored outside the repository"
    }
    if (Test-Path -LiteralPath $candidate) {
        throw "$Label baseline must be absent"
    }
    if ([IO.Path]::GetExtension($candidate) -cne $Extension) {
        throw "$Label must use a $Extension extension"
    }
    $parent = [IO.Path]::GetDirectoryName($candidate)
    if ([string]::IsNullOrWhiteSpace($parent) -or
        -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "$Label parent directory must already exist"
    }
    Assert-Ferrum2NoReparsePointInExistingPath -Path $parent -Label $Label
    $candidate
}
