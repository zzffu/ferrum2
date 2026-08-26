#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs Windows TUN qualification and deterministic fuzz smoke only inside the approved Hyper-V guest.

.DESCRIPTION
The host side builds the exact clean candidate with Rust 1.97.1 and locked dependencies, including
the standalone Windows TUN fuzz smoke executable, then limits
itself to exact-identity VM lifecycle operations, PowerShell Direct, bounded file staging, and
evidence export. It stages precompiled client/server/test/smoke executables, a portable PowerShell runtime,
Visual C++ runtime libraries, Wintun, and the qualification controller. The guest never requires Git,
Cargo, rustup, or an installed PowerShell 7. The host never changes an adapter, address, route, DNS
setting, firewall rule, WFP object, or TUN session.

ProbeOnly verifies the exact VM and checkpoint identities, loads the external DPAPI-protected
credential, and opens a PowerShell Direct session for a read-only guest identity probe. If the VM is
Off, ProbeOnly starts it temporarily and returns it to Off. ProbeOnly never restores a checkpoint,
stages files, invokes the qualification controller, or changes guest network configuration.

The default credential path is
%LOCALAPPDATA%\Ferrum2\hyperv-ferrum2-test.credential.xml. Create it outside this repository with
Export-Clixml from a PSCredential owned by the current Windows user. Never pass a password to this
script or place one in the repository.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly,

    [Parameter(ParameterSetName = "Library", DontShow = $true)]
    [switch]$LoadPrivilegedLibraries,

    [Parameter(ParameterSetName = "Probe", DontShow = $true)]
    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [switch]$InternalWorker,

    [Parameter(ParameterSetName = "Probe", DontShow = $true)]
    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalWorkerToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [switch]$ProbeOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateSet(
        "network-reset-10",
        "network-reset-100",
        "network-reset-1000",
        "restart-10",
        "restart-100",
        "restart-1000",
        "fragments",
        "dual-stack-dns",
        "udp-policy",
        "scheduler-ring-full",
        "fuzz-smoke"
    )]
    [string]$Profile,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [string]$CredentialPath,

    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path
$qualificationModuleRoot = Join-Path $repositoryRoot "tools\powershell"
$mainSourceBundle = Get-Content -LiteralPath (Join-Path $PSScriptRoot `
    "main-source-bundle.json") -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = `
    'tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
$bootstrapEntry = @($mainSourceBundle.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $repositoryRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw 'main source-bundle bootstrap changed'
}
. $bootstrapPath
$verifiedMainSourceBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath (Join-Path $PSScriptRoot 'main-source-bundle.json') `
    -BundleRoot $repositoryRoot
if ([string]$verifiedMainSourceBundle.entrypoint -cne
    'tests/platform/run_windows_tun_hyperv.ps1') {
    throw 'main source-bundle entrypoint changed'
}
Import-Module (Join-Path $qualificationModuleRoot `
    'Ferrum2.Qualification.HostHyperV\Ferrum2.Qualification.HostHyperV.psd1') `
    -Scope Local -Force -ErrorAction Stop
if ($LibraryOnly) {
    if ($LoadPrivilegedLibraries) {
        [void](Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot)
    }
    return
}
$extensionRelative = 'tests/platform/Main.HostController.ps1'
$extensionEntry = @($verifiedMainSourceBundle.files | Where-Object {
    [string]$_.path -ceq $extensionRelative
})
if ($extensionEntry.Count -ne 1) { throw 'main host controller extension is absent' }
$context = [ordered]@{
    entrypoint_path = [string]$PSCommandPath
    repository_root = $repositoryRoot
    internal_worker = [bool]$InternalWorker
    internal_worker_token = [string]$InternalWorkerToken
    probe_only = [bool]$ProbeOnly
    profile = [string]$Profile
    run_token = [string]$RunToken
    identity_ledger = [string]$IdentityLedger
    topology_manifest_path = [string]$TopologyManifestPath
    topology_manifest_sha256 = [string]$TopologyManifestSha256
    support_tcp_port = [int]$SupportTcpPort
    support_udp_port = [int]$SupportUdpPort
    support_pid = [int]$SupportPid
    support_owner = [string]$SupportOwner
    wintun_zip = [string]$WintunZip
    powershell_zip = [string]$PowerShellZip
    evidence_directory = [string]$EvidenceDirectory
    credential_path = [string]$CredentialPath
    readiness_timeout_seconds = [int]$ReadinessTimeoutSeconds
    shutdown_timeout_seconds = [int]$ShutdownTimeoutSeconds
}
Invoke-Ferrum2HostControllerExtension `
    -RepositoryRoot $repositoryRoot `
    -ExtensionPath (Join-Path $repositoryRoot $extensionRelative) `
    -ExpectedSha256 ([string]$extensionEntry[0].sha256) `
    -Context $context -RequiredModules @('Evidence', 'GuestController')
