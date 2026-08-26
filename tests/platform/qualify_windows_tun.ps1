param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance", "network-feasibility", "managed-product", "network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full", "cleanup")]
    [string]$Mode,
    [ValidateSet(10, 100, 1000)] [int]$NetworkResetCycles = 10,
    [ValidateSet(10, 100, 1000)] [int]$RestartCycles = 10,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger,
    [string]$TopologyManifest,
    [string]$GuestNetworkPath,
    [string]$ClientBinary,
    [string]$ServerBinary,
    [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [string]$CandidateTestDirectory,
    [string]$RuntimeLibraryDirectory,
    [switch]$RequireTcp08ProductMetrics
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot 'Main.GuestController.ps1') @PSBoundParameters
exit $LASTEXITCODE
