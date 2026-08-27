#requires -Version 7.4
#requires -Modules Hyper-V

[CmdletBinding()]
param(
    [Parameter(Mandatory, DontShow)] [switch]$InternalWorker,
    [Parameter(Mandatory, DontShow)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalWorkerToken,
    [Parameter(Mandatory)]
    [ValidateSet(
        'network-reset', 'restart-stress', 'fragments', 'dual-stack-dns',
        'udp-policy', 'scheduler-ring-full'
    )]
    [string]$Profile,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,
    [Parameter(Mandatory)] [string]$IdentityLedger,
    [Parameter(Mandatory)] [string]$CandidateArtifactManifest,
    [Parameter(Mandatory)] [string]$TopologyManifestPath,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,
    [Parameter(Mandatory)] [ValidateRange(1, 65535)] [int]$SupportTcpPort,
    [Parameter(Mandatory)] [ValidateRange(1, 65532)] [int]$SupportUdpPort,
    [Parameter(Mandatory)] [ValidateRange(1, [int]::MaxValue)] [int]$SupportPid,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,
    [Parameter(Mandatory)] [string]$WintunZip,
    [string]$PowerShellZip,
    [Parameter(Mandatory)] [string]$EvidenceDirectory,
    [string]$CredentialPath,
    [ValidateRange(30, 900)] [int]$ReadinessTimeoutSeconds = 180,
    [ValidateRange(30, 900)] [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not $InternalWorker) { throw 'qualification worker requires supervisor capability' }

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') `
    -ErrorAction Stop).Path
$mainSourceBundlePath = Join-Path $PSScriptRoot 'main-source-bundle.json'
$mainSourceBundle = Get-Content -LiteralPath $mainSourceBundlePath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = 'tools/powershell/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
$bootstrapEntry = @($mainSourceBundle.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $repositoryRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
[byte[]]$bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)
$bootstrapSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($bootstrapBytes)
).ToLowerInvariant()
if ($bootstrapEntry.Count -ne 1 -or $bootstrapBytes.Length -ne
        [long]$bootstrapEntry[0].bytes -or
    $bootstrapSha256 -cne [string]$bootstrapEntry[0].sha256) {
    throw 'main source-bundle bootstrap changed'
}
. ([scriptblock]::Create(
    [Text.UTF8Encoding]::new($false, $true).GetString($bootstrapBytes)
))
$verifiedMainSourceBundle = Read-Ferrum2BootstrapSourceClosure `
    -ManifestPath $mainSourceBundlePath -BundleRoot $repositoryRoot `
    -ExpectedSchema 'ferrum2.windows-tun-controller-bundle.v1' `
    -ExpectedEntrypoint 'tests/platform/run_windows_tun_hyperv.ps1'
$runnerRelative = 'tests/platform/invoke_windows_tun_hyperv_worker.ps1'
[void](Assert-Ferrum2BootstrapControllerSelfMember `
    -Closure $verifiedMainSourceBundle -RelativePath $runnerRelative `
    -InvocationPath $PSCommandPath)
$moduleName = 'Ferrum2.Qualification.HostHyperV'
Import-Module (Join-Path $repositoryRoot `
    "tools/powershell/$moduleName/$moduleName.psd1") `
    -Scope Local -Force -ErrorAction Stop

$context = [ordered]@{
    repository_root = $repositoryRoot
    internal_worker_token = $InternalWorkerToken
    candidate_artifact_manifest = $CandidateArtifactManifest
    profile = $Profile
    run_token = $RunToken
    identity_ledger = $IdentityLedger
    topology_manifest_path = $TopologyManifestPath
    topology_manifest_sha256 = $TopologyManifestSha256
    support_tcp_port = $SupportTcpPort
    support_udp_port = $SupportUdpPort
    support_pid = $SupportPid
    support_owner = $SupportOwner
    wintun_zip = $WintunZip
    powershell_zip = $PowerShellZip
    evidence_directory = $EvidenceDirectory
    credential_path = $CredentialPath
    readiness_timeout_seconds = $ReadinessTimeoutSeconds
    shutdown_timeout_seconds = $ShutdownTimeoutSeconds
}
Invoke-Ferrum2QualificationHostController `
    -RepositoryRoot $repositoryRoot -Controller MainWorker -Context $context
