#requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$QualificationSourceBundleSha256,
    [Parameter(Mandatory = $true)]
    [switch]$AcknowledgeHostNetworkMutation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') `
    -ErrorAction Stop).Path
$modulePath = Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Qualification.Host\Ferrum2.Qualification.Host.psd1'
Import-Module -Name $modulePath -Force -ErrorAction Stop
$result = Invoke-Ferrum2HostQualification `
    -RepositoryRoot $repositoryRoot `
    -QualificationSourceBundleSha256 $QualificationSourceBundleSha256 `
    -CandidateSha $CandidateSha `
    -EvidenceDirectory $EvidenceDirectory `
    -AcknowledgeHostNetworkMutation:$AcknowledgeHostNetworkMutation
$result | ConvertTo-Json -Depth 20
