#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs the independently versioned M16 Windows TUN hard-kill gate in the approved Hyper-V guest.

.DESCRIPTION
The host builds and hash-binds a clean candidate, stages only precompiled artifacts and portable
runtime dependencies, invokes the dedicated guest hard-kill wrapper through PowerShell Direct,
exports bounded evidence, turns off the exact VM, restores the exact checkpoint, and leaves it Off.
It never changes host adapter, address, route, DNS, firewall, WFP, or TUN state.

The portable guest controller defaults to the SHA-256-pinned PowerShell 7.4.19 win-x64 archive at
%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip. The archive must remain outside the repository.

DescribeContract emits the closed static contract without resolving a credential, inspecting a VM,
building code, staging files, or invoking guest execution.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Describe")]
    [switch]$DescribeContract,

    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [switch]$InternalWorker,

    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalWorkerToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(ParameterSetName = "Run")]
    [string]$CredentialPath,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$expectedArtifactFiles = @(
    "identity-ledger.json",
    "controller.stdout.log",
    "controller.stderr.log",
    "hard-kill-evidence.jsonl",
    "hard-kill-result.json",
    "cleanup.stdout.log",
    "cleanup.stderr.log",
    "hard-kill-cleanup.json"
)
$topologyPropertyNames = @(
    "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
    "support_network", "support_prefix_length", "guest_interface_alias",
    "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
    "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
    "protected_host_tun_index", "protected_host_tun_status"
)
$supportListenerPropertyNames = @(
    "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256", "creation_utc"
)
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path
$qualificationModuleRoot = Join-Path $repositoryRoot "tools\powershell"
$hardSourceBundle = Get-Content -LiteralPath (Join-Path $PSScriptRoot `
    "hard-source-bundle.json") -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = `
    'tools/powershell/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
$bootstrapEntry = @($hardSourceBundle.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $repositoryRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw 'hard source-bundle bootstrap changed'
}
. $bootstrapPath
$verifiedHardSourceBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath (Join-Path $PSScriptRoot 'hard-source-bundle.json') `
    -BundleRoot $repositoryRoot
if ([string]$verifiedHardSourceBundle.entrypoint -cne
    'tests/platform/run_windows_tun_hard_kill_hyperv.ps1') {
    throw 'hard source-bundle entrypoint changed'
}
Import-Module (Join-Path $qualificationModuleRoot `
    'Ferrum2.Qualification.HostHyperV\Ferrum2.Qualification.HostHyperV.psd1') `
    -Scope Local -Force -ErrorAction Stop
if ($DescribeContract) {
    [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-static-contract.v3"
        mode = "hard-kill"
        controller_cases = @("auto-route", "auto-dns", "mixed")
        artifact_files = $expectedArtifactFiles
        staged_input_schema = "ferrum2.windows-tun.hard-kill-staged-input.v3"
        controller_bundle_schema = "ferrum2.qualification-controller-bundle.v1"
        controller_bundle_files = 20
        host_source_bundle_sha256 = [string]$hardSourceBundle.controller_bundle_sha256
        evidence_row_schema = 2
        result_schema = "ferrum2.windows-tun.hard-kill-result.v3"
        strict_route_cases = 2
        cleanup_schema = "ferrum2.windows-tun.hard-kill-cleanup.v2"
        guest_bootstrap_schema = "ferrum2.windows-tun.hard-kill-guest-bootstrap.v3"
        host_run_schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v3"
        topology_manifest_schema = 1
        topology_manifest_required_at_run = $true
        vm_name = $null
        vm_id = $null
        checkpoint_name = $null
        checkpoint_id = $null
        initial_vm_state = "Off"
        final_vm_state = "Off"
    } | ConvertTo-Json -Depth 5
    return
}
if ($LibraryOnly) { return }
$extensionRelative = 'tests/platform/Hard.HostController.ps1'
$extensionEntry = @($verifiedHardSourceBundle.files | Where-Object {
    [string]$_.path -ceq $extensionRelative
})
if ($extensionEntry.Count -ne 1) { throw 'hard host controller extension is absent' }
$context = [ordered]@{
    entrypoint_path = [string]$PSCommandPath
    repository_root = $repositoryRoot
    internal_worker = [bool]$InternalWorker
    internal_worker_token = [string]$InternalWorkerToken
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
    -Context $context -RequiredModules @('Evidence')
