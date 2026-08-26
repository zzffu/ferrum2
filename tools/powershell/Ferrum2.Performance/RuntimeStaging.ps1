function Stage-PortableRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$Rustup,
        [Parameter(Mandatory = $true)][string]$PowerShellZip,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $rustc = [string](& $Rustup which --toolchain 1.97.1 rustc 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $rustc -PathType Leaf)) {
        throw "host Rust 1.97.1 compiler is unavailable"
    }
    $version = @(& $rustc --version 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($version -join "`n") -cnotmatch '^rustc 1\.97\.1 \(') {
        throw "host Rust toolchain does not match 1.97.1"
    }
    $rustDestination = Join-Path $Destination "rust"
    [IO.Directory]::CreateDirectory($rustDestination) | Out-Null
    $rustBin = Split-Path -Parent $rustc
    $rustFiles = @(
        Get-Item -LiteralPath $rustc -Force
        Get-ChildItem -LiteralPath $rustBin -File -Filter "rustc_driver-*.dll"
        Get-ChildItem -LiteralPath $rustBin -File -Filter "std-*.dll"
    )
    if ($rustFiles.Count -ne 3 -or ($rustFiles | Measure-Object Length -Sum).Sum -gt 536870912) {
        throw "minimal rustc runtime boundary is invalid"
    }
    foreach ($file in $rustFiles) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "minimal rustc runtime cannot contain a reparse point"
        }
        Copy-Item -LiteralPath $file.FullName -Destination $rustDestination -ErrorAction Stop
    }

    $powerShellArchive = Resolve-Ferrum2HostInput `
        -RepositoryRoot $repositoryRoot -Kind ExternalFile `
        -Path $PowerShellZip `
        -Label "portable PowerShell ZIP" `
        -MaximumBytes 536870912
    if ((Get-FileHash -LiteralPath $powerShellArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "portable PowerShell ZIP hash mismatch"
    }
    $stagedPowerShellArchive = Join-Path $Destination "portable-pwsh.zip"
    if (Test-Path -LiteralPath $stagedPowerShellArchive) {
        throw "portable PowerShell archive staging baseline is not absent"
    }
    Copy-Item -LiteralPath $powerShellArchive -Destination $stagedPowerShellArchive -ErrorAction Stop
    $stagedPowerShellHash = (Get-FileHash `
        -LiteralPath $stagedPowerShellArchive `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($stagedPowerShellHash -cne $script:expectedPowerShellZipSha256) {
        throw "copied portable PowerShell ZIP hash mismatch"
    }
    $pwshRoot = Join-Path $Destination "pwsh"
    if (Test-Path -LiteralPath $pwshRoot) {
        throw "portable PowerShell expansion baseline is not absent"
    }
    Expand-Archive -LiteralPath $stagedPowerShellArchive -DestinationPath $pwshRoot -ErrorAction Stop
    $pwshItems = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
        Get-ChildItem -LiteralPath $pwshRoot -Force -Recurse
    )
    if (@($pwshItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0) {
        throw "portable PowerShell runtime cannot contain a reparse point"
    }
    $pwshFiles = @($pwshItems | Where-Object { -not $_.PSIsContainer })
    $pwshBytes = [long]($pwshFiles | Measure-Object Length -Sum).Sum
    if ($pwshFiles.Count -le 0 -or $pwshFiles.Count -gt 4096 -or
        $pwshBytes -le 0 -or $pwshBytes -gt 1073741824) {
        throw "portable PowerShell runtime exceeds its staging boundary"
    }
    $pwsh = Join-Path $pwshRoot "pwsh.exe"
    $pwshVersion = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1)
    if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
        [string]$pwshVersion[0] -cne $script:expectedPowerShellVersion) {
        throw "portable PowerShell version is not the pinned compatible release"
    }
    $pwshExecutableSha256 = (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::Delete($stagedPowerShellArchive)

    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $vcDestination = Join-Path $Destination "vc-runtime"
    [IO.Directory]::CreateDirectory($vcDestination) | Out-Null
    $copied = 0
    foreach ($name in @("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll")) {
        $source = Join-Path $system $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination $vcDestination -ErrorAction Stop
            $copied++
        }
    }
    if ($copied -eq 0) { throw "host Visual C++ runtime dependencies are unavailable" }
    return [pscustomobject]@{
        PowerShellVersion = [string]$pwshVersion[0]
        PowerShellExecutableSha256 = $pwshExecutableSha256
        PowerShellFileCount = [long]$pwshFiles.Count
        PowerShellExpandedBytes = $pwshBytes
    }
}
