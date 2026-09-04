#requires -Version 7.4

<#
.SYNOPSIS
Runs explicitly authorized, transactional Windows-host Wintun performance profiles.

.DESCRIPTION
PlanOnly is nonmutating and unprivileged. Real execution requires an already elevated shell plus
-AcknowledgeHostNetworkMutation. The runner owns one RunId-scoped Wintun adapter at a time, exact
RFC 2544 support addresses and routes, product/support process trees, ports, temporary files,
evidence, and a durable recovery ledger. Cleanup removes only identities recorded by that ledger.
The runner never changes default routes, DNS, physical adapters, WLAN, firewall, WFP, or sing-box.

Quick runs two affected data-path scenarios with three interleaved pairs. Confirm runs three
scenarios with five interleaved pairs and longer windows. Lifecycle performs 20 complete
product-start, TUN-probe, and product-stop cycles. No mode runs a long durability soak.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [switch]$PlanOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Recovery")]
    [switch]$RecoveryOnly,

    [Parameter(ParameterSetName = "Plan")]
    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("Quick", "Confirm", "Lifecycle")]
    [string]$Mode = "Quick",

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$BaselineSha,

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(ParameterSetName = "Run")]
    [switch]$AcknowledgeHostNetworkMutation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Read-Ferrum2PerformanceSourceBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )
    $expectedPaths = @(
        "tools/windows-tun/performance/run_windows_tun_performance_host.ps1",
        "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psd1",
        "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psm1",
        "tools/powershell/Ferrum2.Performance/HostPlan.ps1",
        "tools/powershell/Ferrum2.Performance/HostOwnership.ps1",
        "tools/powershell/Ferrum2.Performance/HostExecution.ps1",
        "tools/powershell/Ferrum2.Performance/HostProfiles.ps1",
        "tools/powershell/Ferrum2.Performance/HostPerformance.ps1",
        "tools/powershell/Ferrum2.Performance/PerformanceProcessOwner.cs"
    ) | Sort-Object
    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction Stop
    if ($manifestItem.PSIsContainer -or $manifestItem.Length -le 0 -or
        $manifestItem.Length -gt 1MB -or
        ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "performance source bundle manifest identity is invalid"
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -ErrorAction Stop
    $properties = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($properties -join "|") -cne "entrypoint|files|kind|schema_version" -or
        [int]$manifest.schema_version -ne 1 -or
        [string]$manifest.kind -cne
            "ferrum2.windows-tun-performance-source-bundle.v2" -or
        [string]$manifest.entrypoint -cne
            "tools/windows-tun/performance/run_windows_tun_performance_host.ps1") {
        throw "performance source bundle contract is invalid"
    }
    $manifestPaths = @($manifest.files | ForEach-Object { [string]$_.path } |
        Sort-Object)
    if (($manifestPaths -join "|") -cne ($expectedPaths -join "|") -or
        @($manifestPaths | Sort-Object -Unique).Count -ne $manifestPaths.Count) {
        throw "performance source bundle closure is invalid"
    }
    $rootPrefix = [IO.Path]::GetFullPath($RepositoryRoot).
        TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($row in $manifest.files) {
        $rowProperties = @($row.PSObject.Properties.Name | Sort-Object)
        $relativePath = [string]$row.path
        $path = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $relativePath))
        if (($rowProperties -join "|") -cne "bytes|path|sha256" -or
            [IO.Path]::IsPathFullyQualified($relativePath) -or
            -not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "performance source bundle member identity is invalid"
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            [long]$row.bytes -ne $item.Length -or
            [string]$row.sha256 -cne
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).
                    Hash.ToLowerInvariant()) {
            throw "performance source bundle member identity mismatch: $relativePath"
        }
    }
    return [pscustomobject][ordered]@{
        manifest = $manifest
        sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant()
    }
}

$windowsTunRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") -ErrorAction Stop).Path
$toolsRoot = (Resolve-Path -LiteralPath (Join-Path $windowsTunRoot "..") -ErrorAction Stop).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $toolsRoot "..") -ErrorAction Stop).Path
$modulePath = Join-Path $toolsRoot "powershell\Ferrum2.Performance\Ferrum2.Performance.psm1"
$sourceBundle = Read-Ferrum2PerformanceSourceBundle -RepositoryRoot $repositoryRoot `
    -ManifestPath (Join-Path $toolsRoot "powershell\Ferrum2.Performance\bundle.json")
Import-Module -Name $modulePath -Force -ErrorAction Stop

$arguments = @{
    RepositoryRoot = $repositoryRoot
    PerformanceSourceBundleSha256 = $sourceBundle.sha256
}
foreach ($name in @(
    "PlanOnly", "RecoveryOnly", "Mode", "BaselineSha", "CandidateSha",
    "EvidenceDirectory", "AcknowledgeHostNetworkMutation"
)) {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}

$result = Invoke-Ferrum2HostPerformance @arguments
$result | ConvertTo-Json -Depth 20
