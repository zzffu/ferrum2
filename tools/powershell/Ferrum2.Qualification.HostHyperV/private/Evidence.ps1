function New-PortablePowerShellArchive {
    param(
        [Parameter(Mandatory = $true)][string]$SourceZip,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not [IO.Path]::IsPathFullyQualified($Destination)) {
        throw "portable PowerShell archive destination must be absolute"
    }
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    $destinationParent = [IO.Path]::GetDirectoryName($destinationPath)
    if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
        throw "portable PowerShell archive destination parent is absent"
    }
    Assert-NoReparsePointInExistingPath `
        -Path $destinationParent `
        -Label "portable PowerShell archive destination"
    if (Test-Ferrum2PathWithinRoot -Path $destinationPath -Root $script:repositoryRoot) {
        throw "portable PowerShell archive destination must remain outside the repository"
    }
    $source = Resolve-BoundedFile `
        -Path $SourceZip `
        -Label "portable PowerShell ZIP" `
        -MaximumBytes 536870912 `
        -RequireOutsideRepository
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "portable PowerShell ZIP hash mismatch"
    }
    if (Test-Path -LiteralPath $destinationPath) {
        throw "portable PowerShell archive destination baseline is not absent"
    }
    Copy-Item -LiteralPath $source -Destination $destinationPath -ErrorAction Stop
    $archive = Resolve-BoundedFile `
        -Path $destinationPath `
        -Label "portable PowerShell archive" `
        -MaximumBytes 536870912 `
        -RequireOutsideRepository
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "copied portable PowerShell ZIP hash mismatch"
    }
    $inspectionRoot = Join-Path (Split-Path -Parent $archive) "portable-pwsh-inspection"
    if (Test-Path -LiteralPath $inspectionRoot) {
        throw "portable PowerShell inspection baseline is not absent"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $inspectionRoot -ErrorAction Stop
    $items = @(Get-Item -LiteralPath $inspectionRoot -Force) + @(
        Get-ChildItem -LiteralPath $inspectionRoot -Force -Recurse
    )
    if (@($items | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0) {
        throw "portable PowerShell runtime cannot contain a reparse point"
    }
    $files = @($items | Where-Object { -not $_.PSIsContainer })
    $bytes = [long]($files | Measure-Object Length -Sum).Sum
    if ($files.Count -eq 0 -or $files.Count -gt 4096 -or
        $bytes -le 0 -or $bytes -gt 1073741824) {
        throw "portable PowerShell runtime exceeds its staging boundary"
    }
    $pwsh = Join-Path $inspectionRoot "pwsh.exe"
    $version = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1)
    if ($LASTEXITCODE -ne 0 -or $version.Count -ne 1 -or
        [string]$version[0] -cne $script:expectedPowerShellVersion) {
        throw "portable PowerShell version is not the pinned compatible release"
    }
    return [pscustomobject]@{
        Path = $archive
        Name = [IO.Path]::GetFileName($archive)
        Bytes = [long](Get-Item -LiteralPath $archive -Force).Length
        Sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        ExecutableSha256 = (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant()
        Version = [string]$version[0]
        FileCount = [long]$files.Count
        ExpandedBytes = $bytes
    }
}

function Stage-VisualCppRuntime {
    param([Parameter(Mandatory = $true)][string]$Destination)

    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")) {
        $source = Join-Path $system $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            if ($name -ceq "vcruntime140.dll") {
                throw "host Visual C++ runtime is missing vcruntime140.dll"
            }
            continue
        }
        $resolved = Resolve-BoundedFile `
            -Path $source `
            -Label "Visual C++ runtime $name" `
            -MaximumBytes 16777216
        $destinationPath = Join-Path $Destination $name
        Copy-Item -LiteralPath $resolved -Destination $destinationPath -ErrorAction Stop
        $files.Add([pscustomobject]@{
            Path = $destinationPath
            Name = $name
            Bytes = [long](Get-Item -LiteralPath $destinationPath -Force).Length
            Sha256 = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    return @($files)
}

function New-StagedFileEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [long]$MaximumBytes = 536870912
    )

    $resolved = Resolve-BoundedFile `
        -Path $Path `
        -Label "staged input $Name" `
        -MaximumBytes $MaximumBytes
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    return [ordered]@{
        name = $Name
        bytes = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Copy-GuestEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$GuestExportPath,
        [Parameter(Mandatory = $true)]
        [string]$HostEvidencePath
    )

    $boundary = @(Invoke-Command -Session $Session -ArgumentList $GuestExportPath -ErrorAction Stop -ScriptBlock {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [pscustomobject]@{ Exists = $false; Safe = $false }
        }
        $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
        $files = @($items | Where-Object { -not $_.PSIsContainer })
        $directories = @($items | Where-Object { $_.PSIsContainer })
        $totalBytes = [long]($files | Measure-Object Length -Sum).Sum
        return [pscustomobject]@{
            Exists = $true
            Safe = @($items | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count -eq 0 -and
                $files.Count -le 512 -and
                $directories.Count -le 128 -and
                @($files | Where-Object { $_.Length -gt 67108864 }).Count -eq 0 -and
                $totalBytes -le 536870912
            Files = [long]$files.Count
            Directories = [long]$directories.Count
            Bytes = $totalBytes
        }
    })
    if ($boundary.Count -ne 1 -or $boundary[0].Exists -ne $true -or $boundary[0].Safe -ne $true) {
        throw "guest evidence boundary is missing or unsafe"
    }

    $guestDestination = Join-Path $HostEvidencePath "guest"
    [IO.Directory]::CreateDirectory($guestDestination) | Out-Null
    Copy-Item `
        -FromSession $Session `
        -LiteralPath $GuestExportPath `
        -Destination $guestDestination `
        -Recurse `
        -ErrorAction Stop
    Assert-NoReparsePointInExistingPath -Path $guestDestination -Label "exported evidence"
    $hostItems = @(Get-Item -LiteralPath $guestDestination -Force) + @(
        Get-ChildItem -LiteralPath $guestDestination -Force -Recurse
    )
    $hostFiles = @($hostItems | Where-Object { -not $_.PSIsContainer })
    $hostDirectories = @($hostItems | Where-Object { $_.PSIsContainer })
    $hostBytes = [long]($hostFiles | Measure-Object Length -Sum).Sum
    if ($hostFiles.Count -ne [long]$boundary[0].Files -or
        $hostDirectories.Count -gt ([long]$boundary[0].Directories + 1) -or
        $hostBytes -ne [long]$boundary[0].Bytes -or
        @($hostItems | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count -ne 0) {
        throw "exported evidence changed across the bounded copy"
    }
}

function Get-EvidenceHashes {
    param([string]$EvidenceRoot)

    $rows = [Collections.Generic.List[object]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $EvidenceRoot -File -Force -Recurse | Sort-Object FullName)) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "exported evidence cannot contain a reparse point"
        }
        $relative = [IO.Path]::GetRelativePath($EvidenceRoot, $file.FullName).Replace('\', '/')
        if ($relative -in @(
            "host-orchestration.json",
            "host-orchestration.pending.json"
        )) {
            continue
        }
        $rows.Add([ordered]@{
            path = $relative
            bytes = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    return @($rows)
}
