[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$WintunZip,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$IdentityLedger,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$TopologyManifest,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$GuestNetworkPath,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ClientBinary,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ServerBinary,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string]$RuntimeLibraryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot 'Hard.GuestController.ps1') @PSBoundParameters
exit 0
