Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Ferrum2BootstrapBytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).
            Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-Ferrum2BootstrapSha256([string]$Path) {
    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    Get-Ferrum2BootstrapBytesSha256 -Bytes $bytes
}

function Assert-Ferrum2BootstrapPropertySet(
    [object]$Value,
    [string[]]$Expected,
    [string]$Label
) {
    if ((@($Value.PSObject.Properties.Name) -join '|') -cne ($Expected -join '|')) {
        throw "$Label property set or order is invalid"
    }
}

function Assert-Ferrum2BootstrapJsonPropertiesUnique([string]$Json) {
    [byte[]]$jsonBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Json)
    if ($null -eq ('System.Xml.XmlDictionaryReaderQuotas' -as [type])) {
        Add-Type -AssemblyName System.Runtime.Serialization -ErrorAction Stop
    }
    $quotas = [System.Xml.XmlDictionaryReaderQuotas]::new()
    $quotas.MaxDepth = 64
    $quotas.MaxStringContentLength = 1048576
    $quotas.MaxArrayLength = 65536
    $quotas.MaxBytesPerRead = 4096
    $quotas.MaxNameTableCharCount = 1048576
    $reader = [System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
        $jsonBytes,
        $quotas
    )
    $objects = [Collections.Generic.Stack[object]]::new()
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                $elementPath = '$'
                if ($objects.Count -gt 0 -and
                    $reader.Depth -eq ([int]$objects.Peek().Depth + 1)) {
                    $parent = $objects.Peek()
                    $propertyName = [string]$reader.LocalName
                    $encodedName = [string]$reader.GetAttribute('item')
                    if ($propertyName -ceq 'item' -and
                        -not [string]::IsNullOrWhiteSpace($encodedName)) {
                        $propertyName = $encodedName
                    }
                    if (-not $parent.Names.Add($propertyName)) {
                        throw "source manifest has a duplicate property at $($parent.Path)"
                    }
                    $elementPath = "$($parent.Path).$propertyName"
                }
                if ([string]$reader.GetAttribute('type') -ceq 'object') {
                    $objects.Push([pscustomobject]@{
                        Depth = [int]$reader.Depth
                        Path = $elementPath
                        Names = [Collections.Generic.HashSet[string]]::new(
                            [StringComparer]::OrdinalIgnoreCase
                        )
                    })
                }
            } elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and
                $objects.Count -gt 0 -and
                [int]$objects.Peek().Depth -eq [int]$reader.Depth) {
                [void]$objects.Pop()
            }
        }
    } finally {
        $reader.Dispose()
    }
}

function Assert-Ferrum2BootstrapNoReparsePoint(
    [string]$Path,
    [string]$Label
) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use a rooted filesystem path"
    }
    $current = $root
    foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' |
            Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) { break }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function Test-Ferrum2BootstrapPathWithinRoot(
    [string]$Path,
    [string]$Root
) {
    $candidate = [IO.Path]::GetFullPath($Path)
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $candidate.StartsWith(
        $resolvedRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Resolve-Ferrum2BootstrapMember(
    [string]$Root,
    [string]$RequiredRoot,
    [string]$RelativePath,
    [string]$Label
) {
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath -cmatch '\\' -or
        $RelativePath -cmatch '(^|/)\.\.?(/|$)' -or
        $RelativePath -cnotmatch '^[A-Za-z0-9._/-]+$') {
        throw "$Label path is not canonical"
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path
    $resolvedRequiredRoot = (Resolve-Path -LiteralPath $RequiredRoot `
        -ErrorAction Stop).Path
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
            $resolvedRoot, $resolvedRequiredRoot
        ) -and -not (Test-Ferrum2BootstrapPathWithinRoot `
            -Path $resolvedRequiredRoot -Root $resolvedRoot)) {
        throw "$Label required root escaped its bundle root"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedRoot `
        $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not (Test-Ferrum2BootstrapPathWithinRoot `
        -Path $candidate -Root $resolvedRequiredRoot)) {
        throw "$Label escaped its required root"
    }
    Assert-Ferrum2BootstrapNoReparsePoint -Path $resolvedRequiredRoot `
        -Label "$Label required root"
    Assert-Ferrum2BootstrapNoReparsePoint -Path $candidate -Label $Label
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label is not an ordinary file"
    }
    $candidate
}

function Read-Ferrum2BootstrapManifestDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [byte[]]$CapturedBytes
    )

    Assert-Ferrum2BootstrapNoReparsePoint -Path $Path -Label 'source manifest'
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    [byte[]]$bytes = if ($PSBoundParameters.ContainsKey('CapturedBytes')) {
        $CapturedBytes
    } else {
        [IO.File]::ReadAllBytes($item.FullName)
    }
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $bytes.Length -lt 2 -or $bytes.Length -gt 1048576 -or
        $bytes[-1] -ne 10 -or $bytes -contains 13 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and
            $bytes[1] -eq 187 -and $bytes[2] -eq 191)) {
        throw 'source manifest boundary is invalid'
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-Ferrum2BootstrapJsonPropertiesUnique -Json $json
    [pscustomobject][ordered]@{
        Path = [string]$item.FullName
        Bytes = $bytes
        Sha256 = Get-Ferrum2BootstrapBytesSha256 -Bytes $bytes
        Value = $json | ConvertFrom-Json -ErrorAction Stop
    }
}

function Read-Ferrum2BootstrapSourceClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ManifestPath,
        [Parameter(Mandatory)] [string]$BundleRoot,
        [Parameter(Mandatory)] [string]$ExpectedSchema,
        [Parameter(Mandatory)] [string]$ExpectedEntrypoint,
        [ValidateSet('Controller', 'Role')] [string]$Format = 'Controller',
        [object[]]$ExpectedMembers,
        [string]$RequiredRoot,
        [string]$ExpectedManifestSha256
    )
    $document = Read-Ferrum2BootstrapManifestDocument -Path $ManifestPath
    if (-not [string]::IsNullOrWhiteSpace($ExpectedManifestSha256) -and
        $document.Sha256 -cne $ExpectedManifestSha256) {
        throw 'source manifest hash changed'
    }
    $root = (Resolve-Path -LiteralPath $BundleRoot -ErrorAction Stop).Path
    $required = if ([string]::IsNullOrWhiteSpace($RequiredRoot)) {
        $root
    } else {
        (Resolve-Path -LiteralPath $RequiredRoot -ErrorAction Stop).Path
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($root, $required) -and
        -not (Test-Ferrum2BootstrapPathWithinRoot -Path $required -Root $root)) {
        throw 'source required root escaped its bundle root'
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($required,
            (Split-Path -Parent $document.Path)) -and
        -not (Test-Ferrum2BootstrapPathWithinRoot `
            -Path $document.Path -Root $required)) {
        throw 'source manifest escaped its required root'
    }

    $manifest = $document.Value
    $hashProperty = if ($Format -ceq 'Controller') {
        Assert-Ferrum2BootstrapPropertySet -Value $manifest `
            -Expected @('schema', 'entrypoint', 'files', 'controller_bundle_sha256') `
            -Label 'controller source manifest'
        'controller_bundle_sha256'
    } else {
        Assert-Ferrum2BootstrapPropertySet -Value $manifest `
            -Expected @('schema', 'entrypoint', 'files', 'source_bundle_sha256') `
            -Label 'role source manifest'
        'source_bundle_sha256'
    }
    if ([string]$manifest.schema -cne $ExpectedSchema -or
        [string]$manifest.entrypoint -cne $ExpectedEntrypoint -or
        [string]$manifest.$hashProperty -cnotmatch '^[0-9a-f]{64}$') {
        throw 'source manifest identity is invalid'
    }

    $expectedByIndex = @()
    if ($Format -ceq 'Role') {
        if ($null -eq $ExpectedMembers -or $ExpectedMembers.Count -lt 1 -or
            @($manifest.files).Count -ne $ExpectedMembers.Count) {
            throw 'role source manifest member set is invalid'
        }
        $expectedRoles = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($expected in $ExpectedMembers) {
            Assert-Ferrum2BootstrapPropertySet -Value $expected `
                -Expected @('role', 'path') -Label 'expected source member'
            if ([string]$expected.role -cnotmatch '^[a-z][a-z0-9_]{0,63}$' -or
                -not $expectedRoles.Add([string]$expected.role)) {
                throw 'expected source roles are invalid'
            }
        }
        $expectedByIndex = @($ExpectedMembers)
    }

    $seenPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $seenRoles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $rootRows = [Collections.Generic.List[string]]::new()
    $members = [Collections.Generic.List[object]]::new()
    $sources = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    $rootRows.Add("schema=$ExpectedSchema")
    $rootRows.Add("entrypoint=$ExpectedEntrypoint")
    $previousPath = $null
    for ($index = 0; $index -lt @($manifest.files).Count; $index++) {
        $file = @($manifest.files)[$index]
        $role = $null
        if ($Format -ceq 'Controller') {
            Assert-Ferrum2BootstrapPropertySet -Value $file `
                -Expected @('path', 'bytes', 'sha256') -Label 'controller source member'
        } else {
            Assert-Ferrum2BootstrapPropertySet -Value $file `
                -Expected @('role', 'path', 'bytes', 'sha256') `
                -Label 'role source member'
            $expected = $expectedByIndex[$index]
            $role = [string]$file.role
            if ($role -cne [string]$expected.role -or
                [string]$file.path -cne [string]$expected.path -or
                -not $seenRoles.Add($role)) {
                throw "role source contract is invalid: role=$([string]$expected.role)"
            }
        }
        $relativePath = [string]$file.path
        if (($file.bytes -isnot [long] -and $file.bytes -isnot [int]) -or
            [long]$file.bytes -lt 1 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $seenPaths.Add($relativePath) -or
            ($Format -ceq 'Controller' -and $null -ne $previousPath -and
                [StringComparer]::Ordinal.Compare($previousPath, $relativePath) -ge 0)) {
            throw 'source member identity or order is invalid'
        }
        $path = Resolve-Ferrum2BootstrapMember -Root $root `
            -RequiredRoot $required -RelativePath $relativePath `
            -Label 'source member'
        [byte[]]$bytes = [IO.File]::ReadAllBytes($path)
        $sha256 = Get-Ferrum2BootstrapBytesSha256 -Bytes $bytes
        if ([long]$file.bytes -ne [long]$bytes.Length -or
            $sha256 -cne [string]$file.sha256) {
            throw "source member changed: $relativePath"
        }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $member = [pscustomobject][ordered]@{
            Role = $role
            RelativePath = $relativePath
            Path = $path
            Bytes = $bytes
            Text = $text
            Sha256 = $sha256
        }
        $members.Add($member)
        $sourceKey = if ($Format -ceq 'Role') { $role } else { $relativePath }
        $sources.Add($sourceKey, $member)
        if ($Format -ceq 'Controller') {
            $rootRows.Add("path=$relativePath")
            $rootRows.Add("bytes=$([long]$bytes.Length)")
            $rootRows.Add("sha256=$sha256")
        } else {
            $rootRows.Add(
                "role=$role;path=$relativePath;" +
                "bytes=$([long]$bytes.Length);sha256=$sha256"
            )
        }
        $previousPath = $relativePath
    }
    if (-not $seenPaths.Contains($ExpectedEntrypoint)) {
        throw 'source manifest entrypoint is absent'
    }
    $canonical = [Text.UTF8Encoding]::new($false).GetBytes(
        ($rootRows -join "`n") + "`n"
    )
    $rootHash = Get-Ferrum2BootstrapBytesSha256 -Bytes $canonical
    if ($rootHash -cne [string]$manifest.$hashProperty) {
        throw 'source manifest canonical root changed'
    }
    [pscustomobject][ordered]@{
        Manifest = $manifest
        ManifestPath = [string]$document.Path
        ManifestSha256 = [string]$document.Sha256
        SourceBundleSha256 = $rootHash
        Members = @($members)
        Sources = $sources
    }
}

function Assert-Ferrum2BootstrapControllerSelfMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Closure,
        [Parameter(Mandatory)] [string]$RelativePath,
        [Parameter(Mandatory)] [string]$InvocationPath
    )
    $member = @($Closure.Members | Where-Object {
        [string]$_.RelativePath -ceq $RelativePath
    })
    if ($member.Count -ne 1) {
        throw 'controller self member is absent or duplicated'
    }
    Assert-Ferrum2BootstrapNoReparsePoint -Path $InvocationPath `
        -Label 'controller invocation path'
    $invocationItem = Get-Item -LiteralPath $InvocationPath -Force -ErrorAction Stop
    [byte[]]$invocationBytes = [IO.File]::ReadAllBytes($invocationItem.FullName)
    if ($invocationItem.PSIsContainer -or
        ($invocationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetFullPath([string]$member[0].Path),
            [IO.Path]::GetFullPath([string]$invocationItem.FullName)
        ) -or
        $invocationBytes.Length -ne $member[0].Bytes.Length -or
        (Get-Ferrum2BootstrapBytesSha256 -Bytes $invocationBytes) -cne
            [string]$member[0].Sha256) {
        throw 'controller self member identity changed'
    }
    $member[0]
}

function Assert-Ferrum2BootstrapControllerBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ManifestPath,
        [Parameter(Mandatory)] [string]$BundleRoot,
        [string]$ExpectedManifestSha256
    )
    $document = Read-Ferrum2BootstrapManifestDocument -Path $ManifestPath
    $entrypoint = [string]$document.Value.entrypoint
    $closure = Read-Ferrum2BootstrapSourceClosure `
        -ManifestPath $ManifestPath -BundleRoot $BundleRoot `
        -ExpectedSchema 'ferrum2.windows-tun-controller-bundle.v1' `
        -ExpectedEntrypoint $entrypoint -Format Controller `
        -ExpectedManifestSha256 $ExpectedManifestSha256
    $closure.Manifest
}

function Read-Ferrum2BootstrapFlatSourceClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ManifestPath,
        [Parameter(Mandatory)] [byte[]]$ManifestBytes,
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$RequiredRoot,
        [Parameter(Mandatory)] [string]$ExpectedKind,
        [Parameter(Mandatory)] [string]$ExpectedEntrypoint,
        [Parameter(Mandatory)] [string[]]$ExpectedPaths
    )

    $document = Read-Ferrum2BootstrapManifestDocument `
        -Path $ManifestPath -CapturedBytes $ManifestBytes
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $required = (Resolve-Path -LiteralPath $RequiredRoot -ErrorAction Stop).Path
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($root, $required) -and
        -not (Test-Ferrum2BootstrapPathWithinRoot -Path $required -Root $root)) {
        throw 'flat source required root escaped its repository root'
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
            $required, (Split-Path -Parent $document.Path)
        ) -and -not (Test-Ferrum2BootstrapPathWithinRoot `
            -Path $document.Path -Root $required)) {
        throw 'flat source manifest escaped its required root'
    }

    $manifest = $document.Value
    Assert-Ferrum2BootstrapPropertySet -Value $manifest `
        -Expected @('schema_version', 'kind', 'entrypoint', 'files') `
        -Label 'flat source manifest'
    if (($manifest.schema_version -isnot [long] -and
            $manifest.schema_version -isnot [int]) -or
        $manifest.schema_version -ne 1 -or
        [string]$manifest.kind -cne $ExpectedKind -or
        [string]$manifest.entrypoint -cne $ExpectedEntrypoint) {
        throw 'flat source manifest identity is invalid'
    }

    $expected = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($path in $ExpectedPaths) {
        if (-not $expected.Add($path)) {
            throw 'expected flat source paths are duplicated'
        }
    }
    if (-not $expected.Contains($ExpectedEntrypoint) -or
        @($manifest.files).Count -ne $expected.Count) {
        throw 'flat source manifest file set is incomplete'
    }

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $members = [Collections.Generic.List[object]]::new()
    $sources = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($file in @($manifest.files)) {
        Assert-Ferrum2BootstrapPropertySet -Value $file `
            -Expected @('path', 'bytes', 'sha256') -Label 'flat source member'
        $relativePath = [string]$file.path
        if (($file.bytes -isnot [long] -and $file.bytes -isnot [int]) -or
            [long]$file.bytes -lt 1 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $seen.Add($relativePath) -or -not $expected.Contains($relativePath)) {
            throw 'flat source member identity is invalid'
        }
        $path = Resolve-Ferrum2BootstrapMember -Root $root `
            -RequiredRoot $required -RelativePath $relativePath `
            -Label 'flat source member'
        [byte[]]$bytes = [IO.File]::ReadAllBytes($path)
        $sha256 = Get-Ferrum2BootstrapBytesSha256 -Bytes $bytes
        if ($bytes.Length -ne [long]$file.bytes -or
            $sha256 -cne [string]$file.sha256) {
            throw "flat source member changed: $relativePath"
        }
        $member = [pscustomobject][ordered]@{
            Role = $null
            RelativePath = $relativePath
            Path = $path
            Bytes = $bytes
            Text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            Sha256 = $sha256
        }
        $members.Add($member)
        $sources.Add($relativePath, $member)
    }
    if (-not $seen.SetEquals($expected)) {
        throw 'flat source manifest file set is incomplete'
    }
    [pscustomobject][ordered]@{
        Manifest = $manifest
        ManifestPath = [string]$document.Path
        ManifestBytes = [byte[]]$document.Bytes
        ManifestSha256 = [string]$document.Sha256
        Members = @($members)
        Sources = $sources
    }
}

function Add-Ferrum2BootstrapSourceDependency {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Closure,
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$RequiredRoot,
        [Parameter(Mandatory)] [string]$RelativePath
    )

    $path = Resolve-Ferrum2BootstrapMember -Root $RepositoryRoot `
        -RequiredRoot $RequiredRoot -RelativePath $RelativePath `
        -Label 'captured source dependency'
    [byte[]]$bytes = [IO.File]::ReadAllBytes($path)
    $sha256 = Get-Ferrum2BootstrapBytesSha256 -Bytes $bytes
    if ($Closure.Sources.ContainsKey($RelativePath)) {
        $existing = $Closure.Sources[$RelativePath]
        if ([string]$existing.Sha256 -cne $sha256 -or
            $existing.Bytes.Length -ne $bytes.Length) {
            throw "captured source dependency changed: $RelativePath"
        }
        return $existing
    }
    $member = [pscustomobject][ordered]@{
        Role = $null
        RelativePath = $RelativePath
        Path = $path
        Bytes = $bytes
        Text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        Sha256 = $sha256
    }
    $Closure.Sources.Add($RelativePath, $member)
    $member
}

function Open-Ferrum2BootstrapLockedStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Closure,
        [Parameter(Mandatory)] [string]$ManifestRelativePath,
        [string]$NamePrefix = 'ferrum2-source'
    )

    if ([string]::IsNullOrWhiteSpace($ManifestRelativePath) -or
        [IO.Path]::IsPathRooted($ManifestRelativePath) -or
        $ManifestRelativePath -cmatch '\\' -or
        $ManifestRelativePath -cmatch '(^|/)\.\.?(/|$)' -or
        $ManifestRelativePath -cnotmatch '^[A-Za-z0-9._/-]+$' -or
        $Closure.Sources.ContainsKey($ManifestRelativePath) -or
        $NamePrefix -cnotmatch '^[a-z0-9][a-z0-9-]{0,47}$') {
        throw 'locked source stage identity is invalid'
    }
    $root = Join-Path ([IO.Path]::GetTempPath()) `
        ("$NamePrefix-" + [Guid]::NewGuid().ToString('N'))
    $locks = [Collections.Generic.List[IDisposable]]::new()
    try {
        [IO.Directory]::CreateDirectory($root) | Out-Null
        $files = [Collections.Generic.Dictionary[string, byte[]]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($entry in $Closure.Sources.GetEnumerator()) {
            $files.Add([string]$entry.Key, [byte[]]$entry.Value.Bytes)
        }
        $files.Add($ManifestRelativePath, [byte[]]$Closure.ManifestBytes)
        foreach ($entry in $files.GetEnumerator()) {
            $destination = Join-Path $root `
                $entry.Key.Replace('/', [IO.Path]::DirectorySeparatorChar)
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) |
                Out-Null
            $writer = [IO.File]::Open(
                $destination, [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write, [IO.FileShare]::None
            )
            try {
                $writer.Write([byte[]]$entry.Value)
                $writer.Flush($true)
            } finally {
                $writer.Dispose()
            }
            $locks.Add([IO.File]::Open(
                    $destination, [IO.FileMode]::Open,
                    [IO.FileAccess]::Read, [IO.FileShare]::Read
                ))
        }
        [pscustomobject][ordered]@{ Root = $root; Locks = $locks }
    } catch {
        foreach ($handle in $locks) { $handle.Dispose() }
        if (Test-Path -LiteralPath $root -PathType Container) {
            [IO.Directory]::Delete($root, $true)
        }
        throw
    }
}

function Close-Ferrum2BootstrapLockedStage {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Stage)

    foreach ($handle in $Stage.Locks) { $handle.Dispose() }
    if (Test-Path -LiteralPath $Stage.Root -PathType Container) {
        [IO.Directory]::Delete([string]$Stage.Root, $true)
    }
}

function Assert-Ferrum2BootstrapSourceManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ManifestPath,
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$ExpectedKind,
        [Parameter(Mandatory)] [string]$ExpectedEntrypoint,
        [Parameter(Mandatory)] [string[]]$ExpectedPaths
    )
    [byte[]]$manifestBytes = [IO.File]::ReadAllBytes($ManifestPath)
    $closure = Read-Ferrum2BootstrapFlatSourceClosure `
        -ManifestPath $ManifestPath -ManifestBytes $manifestBytes `
        -RepositoryRoot $RepositoryRoot -RequiredRoot $RepositoryRoot `
        -ExpectedKind $ExpectedKind -ExpectedEntrypoint $ExpectedEntrypoint `
        -ExpectedPaths $ExpectedPaths
    $closure.ManifestSha256
}
