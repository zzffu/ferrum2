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

function Get-Ferrum2BytesSha256 {
    param([Parameter(Mandatory)] [byte[]]$Bytes)
    [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function ConvertTo-Ferrum2CanonicalGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Value,
        [Parameter(Mandatory)] [string]$Label
    )
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$Value, [ref]$parsed) -or
        $parsed -eq [Guid]::Empty) {
        throw "$Label GUID is invalid"
    }
    $parsed.ToString('D')
}

function ConvertTo-Ferrum2CanonicalMacAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Value,
        [Parameter(Mandatory)] [string]$Label
    )
    $canonical = ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($canonical -cnotmatch '^[0-9A-F]{12}$' -or $canonical -ceq '000000000000') {
        throw "$Label MAC address is invalid"
    }
    $canonical
}

function Get-Ferrum2VmAdapterInstanceGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$AdapterId,
        [Parameter(Mandatory)] [string]$ExpectedOwnerId,
        [Parameter(Mandatory)] [string]$Label
    )
    $parts = $AdapterId.Split('\')
    $owner = ConvertTo-Ferrum2CanonicalGuid -Value $ExpectedOwnerId -Label "$Label owner"
    if ($parts.Count -ne 2 -or
        [string]$parts[0] -cne ('Microsoft:' + $owner.ToUpperInvariant())) {
        throw "$Label adapter ID owner is invalid"
    }
    ConvertTo-Ferrum2CanonicalGuid -Value $parts[1] -Label "$Label instance"
}

function Assert-Ferrum2NoDuplicateJsonProperty {
    param([Parameter(Mandatory)] [string]$Json)

    function Assert-Ferrum2JsonElementPropertyNamesUnique {
        param(
            [Parameter(Mandatory)] [Text.Json.JsonElement]$Element,
            [Parameter(Mandatory)] [string]$Path
        )
        if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name)) {
                    throw "JSON document has a duplicate property at $Path"
                }
                Assert-Ferrum2JsonElementPropertyNamesUnique `
                    -Element $property.Value -Path "$Path.$($property.Name)"
            }
        } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
            $index = 0
            foreach ($item in $Element.EnumerateArray()) {
                Assert-Ferrum2JsonElementPropertyNamesUnique `
                    -Element $item -Path "$Path[$index]"
                $index += 1
            }
        }
    }

    $document = [Text.Json.JsonDocument]::Parse($Json)
    try {
        Assert-Ferrum2JsonElementPropertyNamesUnique `
            -Element $document.RootElement -Path '$'
    } finally {
        $document.Dispose()
    }
}

function Read-Ferrum2JsonDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [ValidateRange(2, 1048576)] [long]$MaximumBytes = 131072,
        [switch]$SingleLine
    )
    $resolved = Resolve-Ferrum2OrdinaryFile -Path $Path -Label 'JSON document' `
        -MaximumBytes $MaximumBytes
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    $lineFeeds = @($bytes | Where-Object { $_ -eq 10 }).Count
    if ($bytes[-1] -ne 10 -or $bytes -contains 13 -or
        ($SingleLine -and $lineFeeds -ne 1) -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and
            $bytes[1] -eq 187 -and $bytes[2] -eq 191)) {
        throw 'JSON document encoding is invalid'
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-Ferrum2NoDuplicateJsonProperty -Json $json
    [pscustomobject][ordered]@{
        Path = $resolved
        Sha256 = Get-Ferrum2BytesSha256 -Bytes $bytes
        Length = [long]$bytes.Length
        Value = $json | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    }
}

function Read-Ferrum2ClosedSourceManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$RequiredRoot,
        [Parameter(Mandatory)] [string]$Schema,
        [Parameter(Mandatory)] [string]$EntryPoint,
        [Parameter(Mandatory)] [object[]]$ExpectedFiles
    )
    $document = Read-Ferrum2JsonDocument -Path $Path -MaximumBytes 65536
    $manifest = $document.Value
    Assert-Ferrum2ClosedProperties -Value $manifest `
        -Expected @('schema', 'entrypoint', 'files', 'source_bundle_sha256') `
        -Label 'source manifest'
    if ([string]$manifest.schema -cne $Schema -or
        [string]$manifest.entrypoint -cne $EntryPoint -or
        @($manifest.files).Count -ne $ExpectedFiles.Count -or
        [string]$manifest.source_bundle_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'source manifest header is invalid'
    }
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $required = (Resolve-Path -LiteralPath $RequiredRoot -ErrorAction Stop).Path
    if (-not (Test-Ferrum2PathWithinRoot -Path $required -Root $root) -or
        -not (Test-Ferrum2PathWithinRoot -Path $document.Path -Root $required)) {
        throw 'source manifest escaped its required root'
    }
    Assert-Ferrum2NoReparsePointInExistingPath -Path $required `
        -Label 'source required root'
    $rootRows = [Collections.Generic.List[string]]::new()
    $rootRows.Add("schema=$Schema")
    $rootRows.Add("entrypoint=$EntryPoint")
    for ($index = 0; $index -lt $ExpectedFiles.Count; $index++) {
        $file = @($manifest.files)[$index]
        $expected = $ExpectedFiles[$index]
        Assert-Ferrum2ClosedProperties -Value $file `
            -Expected @('role', 'path', 'bytes', 'sha256') -Label 'source manifest file'
        if ([string]$file.role -cne [string]$expected.role -or
            [string]$file.path -cne [string]$expected.path) {
            throw "source contract is invalid: role=$([string]$expected.role)"
        }
        $relativePath = [string]$file.path
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathFullyQualified($relativePath) -or
            $relativePath -cmatch '\\' -or $relativePath -cmatch '(^|/)\.\.?(/|$)' -or
            $relativePath -cnotmatch '^[A-Za-z0-9._/-]+$') {
            throw "source path is not canonical: role=$([string]$expected.role)"
        }
        $resolved = [IO.Path]::GetFullPath((Join-Path $root $relativePath))
        if (-not (Test-Ferrum2PathWithinRoot -Path $resolved -Root $required)) {
            throw "source path escaped its required root: role=$([string]$expected.role)"
        }
        Assert-Ferrum2NoReparsePointInExistingPath -Path $resolved `
            -Label 'source manifest file'
        $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        [byte[]]$sourceBytes = [IO.File]::ReadAllBytes($resolved)
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            [long]$file.bytes -ne [long]$sourceBytes.Length -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            (Get-Ferrum2BytesSha256 -Bytes $sourceBytes) -cne [string]$file.sha256) {
            throw "source identity is invalid: role=$([string]$expected.role)"
        }
        $rootRows.Add(
            "role=$([string]$file.role);path=$([string]$file.path);" +
            "bytes=$([long]$file.bytes);sha256=$([string]$file.sha256)"
        )
    }
    [byte[]]$rootBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($rootRows -join "`n") + "`n"
    )
    $rootHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($rootBytes)
    ).ToLowerInvariant()
    if ($rootHash -cne [string]$manifest.source_bundle_sha256) {
        throw 'source manifest root hash is invalid'
    }
    [pscustomobject][ordered]@{
        Path = [string]$document.Path
        ManifestSha256 = [string]$document.Sha256
        SourceBundleSha256 = $rootHash
        Manifest = $manifest
    }
}
