param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'network-reset', 'restart-stress', 'fragments', 'dual-stack-dns',
        'udp-policy', 'scheduler-ring-full'
    )]
    [string]$Profile,
    [Parameter(Mandatory)] [string]$RunToken,
    [Parameter(Mandatory)] [string]$ClientBinary,
    [Parameter(Mandatory)] [string]$ServerBinary,
    [Parameter(Mandatory)] [string]$ProductRoot,
    [Parameter(Mandatory)] [string]$ArtifactDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Main.GuestCleanupController.ps1') @PSBoundParameters
exit $LASTEXITCODE
