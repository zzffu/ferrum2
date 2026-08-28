param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full")]
    [string]$Profile,
    [ValidateRange(0, 10)] [int]$ValidationCycleLimit = 0,
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
