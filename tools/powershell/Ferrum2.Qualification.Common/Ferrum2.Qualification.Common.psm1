Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Ferrum2ClosedProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Value,
        [Parameter(Mandatory)] [string[]]$Expected,
        [Parameter(Mandatory)] [string]$Label
    )
    $actual = @($Value.PSObject.Properties.Name)
    if (($actual -join '|') -cne ($Expected -join '|')) {
        throw "$Label property set or order is invalid"
    }
}

function Get-Ferrum2LowerSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

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
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if ($RequiredRoot -and -not (Test-Ferrum2PathWithinRoot -Path $resolved -Root $RequiredRoot)) {
        throw "$Label escaped its required root"
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
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth $Depth) + "`n"
    )
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

Export-ModuleMember -Function @(
    'Assert-Ferrum2ClosedProperties'
    'Get-Ferrum2LowerSha256'
    'Resolve-Ferrum2OrdinaryFile'
    'Test-Ferrum2PathWithinRoot'
    'Write-Ferrum2JsonCreateNew'
)
