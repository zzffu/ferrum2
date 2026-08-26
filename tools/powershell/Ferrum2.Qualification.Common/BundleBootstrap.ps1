Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Ferrum2BootstrapSha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant()
}

function Resolve-Ferrum2BootstrapMember(
    [string]$Root,
    [string]$RelativePath,
    [string]$Label
) {
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [IO.Path]::IsPathFullyQualified($RelativePath) -or
        $RelativePath -cmatch '(^|/|\\)\.\.(/|\\|$)' -or
        $RelativePath -cmatch '(^|/|\\)\.(/|\\|$)' -or
        $RelativePath -cmatch '[:*?"<>|]' -or
        $RelativePath.StartsWith('/') -or $RelativePath.StartsWith('\')) {
        throw "$Label path is not canonical"
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path.TrimEnd('\', '/')
    $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedRoot `
        $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    $prefix = $resolvedRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its bundle root"
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label is not an ordinary file"
    }
    $candidate
}

function Assert-Ferrum2BootstrapControllerBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$BundleRoot,
        [string]$ExpectedManifestSha256
    )
    if (-not [string]::IsNullOrWhiteSpace($ExpectedManifestSha256) -and
        (Get-Ferrum2BootstrapSha256 $ManifestPath) -cne $ExpectedManifestSha256) {
        throw 'controller bundle manifest hash changed'
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    if ((@($manifest.PSObject.Properties.Name) -join '|') -cne
            'schema|entrypoint|files|controller_bundle_sha256' -or
        $manifest.schema -cne 'ferrum2.qualification-controller-bundle.v1' -or
        [string]$manifest.entrypoint -notmatch '^[^/\\].+' -or
        [string]$manifest.controller_bundle_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'controller bundle manifest identity is invalid'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rows = [Collections.Generic.List[string]]::new()
    $rows.Add('schema=ferrum2.qualification-controller-bundle.v1')
    $rows.Add('entrypoint=' + [string]$manifest.entrypoint)
    $previous = $null
    foreach ($file in @($manifest.files)) {
        if ((@($file.PSObject.Properties.Name) -join '|') -cne 'path|bytes|sha256' -or
            $file.bytes -isnot [long] -or [long]$file.bytes -lt 1 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $seen.Add([string]$file.path) -or
            ($null -ne $previous -and
                [StringComparer]::Ordinal.Compare($previous, [string]$file.path) -ge 0)) {
            throw 'controller bundle member identity or order is invalid'
        }
        $path = Resolve-Ferrum2BootstrapMember $BundleRoot ([string]$file.path) `
            'controller bundle member'
        if ((Get-Item -LiteralPath $path -Force).Length -ne [long]$file.bytes -or
            (Get-Ferrum2BootstrapSha256 $path) -cne [string]$file.sha256) {
            throw "controller bundle member changed: $($file.path)"
        }
        $rows.Add('path=' + [string]$file.path)
        $rows.Add('bytes=' + [string][long]$file.bytes)
        $rows.Add('sha256=' + [string]$file.sha256)
        $previous = [string]$file.path
    }
    if (-not $seen.Contains([string]$manifest.entrypoint)) {
        throw 'controller bundle entrypoint is absent'
    }
    $canonical = [Text.UTF8Encoding]::new($false).GetBytes(($rows -join "`n") + "`n")
    $rootHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($canonical)
    ).ToLowerInvariant()
    if ($rootHash -cne [string]$manifest.controller_bundle_sha256) {
        throw 'controller bundle canonical root changed'
    }
    $manifest
}

function Assert-Ferrum2BootstrapSourceManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$ExpectedKind,
        [Parameter(Mandatory)][string]$ExpectedEntrypoint,
        [Parameter(Mandatory)][string[]]$ExpectedPaths
    )
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    if ((@($manifest.PSObject.Properties.Name) -join '|') -cne
            'schema_version|kind|entrypoint|files' -or
        $manifest.schema_version -ne 1 -or $manifest.kind -cne $ExpectedKind -or
        $manifest.entrypoint -cne $ExpectedEntrypoint) {
        throw 'source manifest identity is invalid'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($file in @($manifest.files)) {
        if ((@($file.PSObject.Properties.Name) -join '|') -cne 'path|bytes|sha256' -or
            $file.bytes -isnot [long] -or [long]$file.bytes -lt 1 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $seen.Add([string]$file.path)) {
            throw 'source manifest member identity is invalid'
        }
        $path = Resolve-Ferrum2BootstrapMember $RepositoryRoot ([string]$file.path) `
            'source manifest member'
        if ((Get-Item -LiteralPath $path -Force).Length -ne [long]$file.bytes -or
            (Get-Ferrum2BootstrapSha256 $path) -cne [string]$file.sha256) {
            throw "source manifest member changed: $($file.path)"
        }
    }
    $expected = [Collections.Generic.HashSet[string]]::new(
        [string[]]$ExpectedPaths,
        [StringComparer]::Ordinal
    )
    if (-not $seen.SetEquals($expected)) {
        throw 'source manifest file set is incomplete'
    }
    Get-Ferrum2BootstrapSha256 $ManifestPath
}
