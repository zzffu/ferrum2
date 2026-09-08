Set-StrictMode -Version Latest

function Read-Ferrum2HostQualificationSourceBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )
    $expectedPaths = @(
        "tests/platform/invoke_windows_tun_qualification_host_worker.ps1"
        "tests/platform/run_windows_tun_qualification_host.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostExecution.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostProduct.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostOwnership.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostCleanup.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostFirewall.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/HostProcessOwner.cs"
        "tools/powershell/Ferrum2.Qualification.Host/Ferrum2.Qualification.Host.psd1"
        "tools/powershell/Ferrum2.Qualification.Host/Ferrum2.Qualification.Host.psm1"
        "tools/powershell/Ferrum2.Qualification.Host/HostQualification.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/QualificationRouteNotification.cs"
        "tools/powershell/Ferrum2.Qualification.Host/SourceBundle.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/SupervisorEvidence.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/WfpEvidence.ps1"
        "tools/powershell/Ferrum2.Qualification.Host/WorkloadEvidence.ps1"
    ) | Sort-Object
    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction Stop
    if ($manifestItem.PSIsContainer -or $manifestItem.Length -le 0 -or
        $manifestItem.Length -gt 1MB -or
        ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "host qualification source bundle manifest identity is invalid"
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -ErrorAction Stop
    $properties = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($properties -join "|") -cne "entrypoint|files|kind|schema_version" -or
        [int]$manifest.schema_version -ne 1 -or
        [string]$manifest.kind -cne
            "ferrum2.windows-tun-host-qualification-source-bundle.v1" -or
        [string]$manifest.entrypoint -cne
            "tests/platform/run_windows_tun_qualification_host.ps1") {
        throw "host qualification source bundle contract is invalid"
    }
    $manifestPaths = @($manifest.files | ForEach-Object { [string]$_.path } |
        Sort-Object)
    if (($manifestPaths -join "|") -cne ($expectedPaths -join "|") -or
        @($manifestPaths | Sort-Object -Unique).Count -ne $manifestPaths.Count) {
        throw "host qualification source bundle closure is invalid"
    }
    $rootPrefix = [IO.Path]::GetFullPath($RepositoryRoot).
        TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($row in $manifest.files) {
        $rowProperties = @($row.PSObject.Properties.Name | Sort-Object)
        $relativePath = [string]$row.path
        $path = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $relativePath))
        if (($rowProperties -join "|") -cne "bytes|path|sha256" -or
            [IO.Path]::IsPathFullyQualified($relativePath) -or
            $relativePath.Contains("..") -or
            -not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "host qualification source bundle member identity is invalid"
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            [long]$row.bytes -ne $item.Length -or
            [string]$row.sha256 -cne
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw "host qualification source bundle member identity mismatch: $relativePath"
        }
    }
    return [pscustomobject][ordered]@{
        manifest = $manifest
        sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant()
    }
}
