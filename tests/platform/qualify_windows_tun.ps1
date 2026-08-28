param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full")]
    [string]$Profile,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger,
    [string]$TopologyManifest,
    [string]$GuestNetworkPath,
    [string]$ClientBinary,
    [string]$ServerBinary,
    [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [string]$RuntimeLibraryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot 'Main.GuestController.ps1') @PSBoundParameters
exit 0
