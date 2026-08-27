#requires -Version 7.4

<#
.SYNOPSIS
Runs the M16 hard-kill controller and its ownership-scoped outer cleanup inside the approved guest.

.DESCRIPTION
This is a guest-only implementation detail of run_windows_tun_hard_kill_hyperv.ps1. It accepts only
a hash-bound staging root, never discovers a checkout or toolchain, and publishes the exact eight-file
hard-kill artifact set. Do not invoke it on a host.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$RunRoot,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedManifestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

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


$hardGuestSourceNames = @(
    "Hard.GuestCleanup.ps1", "Hard.GuestContract.ps1", "Hard.GuestEvidence.ps1"
)
$hardGuestSourceRoot = $PSScriptRoot
if (-not $LibraryOnly) {
    $preflightManifestPath = Join-Path $RunRoot "input\staged-input.json"
    if ((Get-FileHash -LiteralPath $preflightManifestPath -Algorithm SHA256 `
            -ErrorAction Stop).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256) {
        throw "hard-kill staged input changed before source verification"
    }
    $preflightManifest = Get-Content -LiteralPath $preflightManifestPath `
        -Raw -Encoding utf8 | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    $preflightBundlePath = Join-Path $RunRoot "input\controller\controller-bundle.json"
    if ((Get-FileHash -LiteralPath $preflightBundlePath -Algorithm SHA256 `
            -ErrorAction Stop).Hash.ToLowerInvariant() -cne
        [string]$preflightManifest.files.controller_bundle_manifest.sha256) {
        throw "hard-kill controller bundle manifest changed before source verification"
    }
    $preflightBundle = Get-Content -LiteralPath $preflightBundlePath `
        -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $hardGuestSourceRoot = Join-Path $RunRoot "input\controller"
    $bootstrapRelative = `
        'modules/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
    $bootstrapEntry = @($preflightBundle.files | Where-Object {
        [string]$_.path -ceq $bootstrapRelative
    })
    $bootstrapPath = Join-Path $hardGuestSourceRoot `
        $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
    if ($bootstrapEntry.Count -ne 1 -or
        (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 `
            -ErrorAction Stop).Hash.ToLowerInvariant() -cne
            [string]$bootstrapEntry[0].sha256) {
        throw "hard-kill bundle bootstrap changed before verification"
    }
    . $bootstrapPath
    $verifiedBundle = Assert-Ferrum2BootstrapControllerBundle `
        -ManifestPath $preflightBundlePath `
        -BundleRoot $hardGuestSourceRoot
    if ([string]$verifiedBundle.entrypoint -cne
        'qualify_windows_tun_hard_kill.ps1') {
        throw 'hard-kill controller bundle entrypoint changed'
    }
    $labManifestPath = Join-Path $hardGuestSourceRoot `
        'modules/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psd1'
    Import-Module $labManifestPath -Scope Local -Force -ErrorAction Stop
    foreach ($name in $hardGuestSourceNames) {
        $entry = @($preflightBundle.files | Where-Object {
            [string]$_.path -ceq $name
        })
        $path = Join-Path $hardGuestSourceRoot $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($entry.Count -ne 1 -or $item.PSIsContainer -or
            [long]$entry[0].bytes -ne [long]$item.Length -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).
                Hash.ToLowerInvariant() -cne [string]$entry[0].sha256) {
            throw "hard-kill source bundle member changed: $name"
        }
    }
}
foreach ($name in $hardGuestSourceNames) {
    . (Join-Path $hardGuestSourceRoot $name)
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the hard-kill guest wrapper requires 64-bit Windows AMD64"
}
if ($LibraryOnly) { return }

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
Assert-True ($principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) "the hard-kill guest wrapper requires an elevated administrator"
Assert-True (-not [string]::IsNullOrWhiteSpace($env:ProgramData) -and
    [IO.Path]::IsPathFullyQualified($RunRoot)) "guest run root is not fully qualified"
$runRootPath = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
$expectedBase = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData "Ferrum2\HostQualification")
).TrimEnd('\', '/')
Assert-True (
    [IO.Path]::GetDirectoryName($runRootPath).TrimEnd('\', '/').Equals(
        $expectedBase,
        [StringComparison]::OrdinalIgnoreCase
    )
) "guest run root is not an immediate child of the approved staging base"
$inputRoot = Join-Path $runRootPath "input"
$exportRoot = Join-Path $runRootPath "export"
$manifestPath = Join-Path $inputRoot "staged-input.json"
Assert-NoReparseDirectoryChain $runRootPath ([IO.Path]::GetFullPath($env:ProgramData)) `
    "guest staging directory"
Assert-OrdinaryDirectory $inputRoot "input root"
Assert-OrdinaryDirectory $exportRoot "export root"
Assert-OrdinaryLeaf $manifestPath "staged input manifest" 2 1048576
Assert-True ((Get-LowerSha256 $manifestPath) -ceq $ExpectedManifestSha256) `
    "staged input manifest hash changed"
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 12 -ErrorAction Stop
Assert-ClosedProperties $manifest @(
    "schema", "mode", "run_token", "candidate_sha",
    "candidate_artifact_manifest_sha256", "identity_sha256",
    "controller_bundle", "vm_name", "vm_id",
    "checkpoint_name", "checkpoint_id", "guest_product", "guest_edition", "guest_architecture",
    "guest_version", "guest_build", "topology", "files", "runtime"
) "staged input manifest"
Assert-ClosedProperties $manifest.files @(
    "guest_wrapper", "controller", "controller_bundle_manifest", "identity_ledger",
    "topology_manifest",
    "guest_network_path_probe", "wintun_zip", "client", "server", "powershell_archive",
    "vc_libraries"
) "staged input files"
Assert-ClosedProperties $manifest.runtime @(
    "rust_version", "powershell_version", "powershell_executable_sha256",
    "powershell_file_count", "powershell_expanded_bytes"
) "staged runtime"
Assert-True (
    $manifest.schema -ceq "ferrum2.windows-tun.hard-kill-staged-input.v4" -and
    $manifest.mode -ceq "hard-kill" -and
    [string]$manifest.run_token -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$' -and
    [IO.Path]::GetFileName($runRootPath) -ceq [string]$manifest.run_token -and
    [string]$manifest.candidate_sha -cmatch '^[0-9a-f]{40}$' -and
    [string]$manifest.candidate_artifact_manifest_sha256 -cmatch '^[0-9a-f]{64}$' -and
    [string]$manifest.identity_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $manifest.vm_name -is [string] -and
    -not [string]::IsNullOrWhiteSpace([string]$manifest.vm_name) -and
    $manifest.guest_architecture -ceq "AMD64" -and
    $manifest.runtime.rust_version -is [string] -and
    [string]$manifest.runtime.rust_version -cmatch '^rustc 1\.97\.1 \(' -and
    $manifest.runtime.powershell_version -is [string] -and
    [string]$manifest.runtime.powershell_version -ceq "7.4.19" -and
    $PSVersionTable.PSVersion.ToString() -ceq [string]$manifest.runtime.powershell_version -and
    [string]$manifest.runtime.powershell_executable_sha256 -cmatch '^[0-9a-f]{64}$' -and
    (Test-JsonInteger $manifest.runtime.powershell_file_count) -and
    [long]$manifest.runtime.powershell_file_count -ge 1 -and
    [long]$manifest.runtime.powershell_file_count -le 4096 -and
    (Test-JsonInteger $manifest.runtime.powershell_expanded_bytes) -and
    [long]$manifest.runtime.powershell_expanded_bytes -ge 1 -and
    [long]$manifest.runtime.powershell_expanded_bytes -le 1073741824
) "staged hard-kill identity is invalid"
Assert-CanonicalGuid $manifest.vm_id "staged VM"
Assert-CanonicalGuid $manifest.checkpoint_id "staged lab checkpoint"
Assert-TopologyContract $manifest.topology "staged topology"
$runToken = [string]$manifest.run_token
$controller = Join-Path $inputRoot `
    "controller\qualify_windows_tun_hard_kill.ps1"
$controllerBundleManifestPath = Join-Path $inputRoot "controller\controller-bundle.json"
$identityLedger = Join-Path $inputRoot "identity-ledger.json"
$topologyManifestPath = Join-Path $inputRoot "topology-manifest.json"
$guestNetworkPathProbe = Join-Path $inputRoot "controller\get_windows_tun_guest_network_path.ps1"
$guestNetworkPath = Join-Path $runRootPath "guest-network-path.json"
$wintunZip = Join-Path $inputRoot "wintun-0.14.1.zip"
$clientBinary = Join-Path $inputRoot "artifacts\ferrum2-client.exe"
$serverBinary = Join-Path $inputRoot "artifacts\ferrum2-server.exe"
$runtimeLibraries = Join-Path $inputRoot "runtime\vc-runtime"
$powerShellArchive = Join-Path $inputRoot "portable-pwsh.zip"
$pwsh = Join-Path $runRootPath "pwsh74\pwsh.exe"

Assert-StagedFile $PSCommandPath $manifest.files.guest_wrapper `
    "invoke_windows_tun_hard_kill_guest.ps1" 4096 2097152 "guest wrapper"
Assert-StagedFile $controller $manifest.files.controller `
    "qualify_windows_tun_hard_kill.ps1" `
    1 4194304 "controller"
Assert-StagedFile $controllerBundleManifestPath $manifest.files.controller_bundle_manifest `
    "controller-bundle.json" 2 131072 "controller bundle manifest"
$bundleManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
Assert-True (($bundleManifest | ConvertTo-Json -Compress -Depth 8) -ceq
    ($manifest.controller_bundle | ConvertTo-Json -Compress -Depth 8)) `
    "controller bundle manifests disagree"
$labModule = Join-Path $inputRoot `
    "controller\modules\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1"
Import-Module $labModule -Scope Local -Force -ErrorAction Stop
[void](Assert-Ferrum2ControllerBundleManifest `
    -Manifest $bundleManifest `
    -BundleRoot (Join-Path $inputRoot "controller"))
Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
    "topology-manifest.json" 2 131072 "support topology manifest"
Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
    "get_windows_tun_guest_network_path.ps1" 4096 1048576 "guest network-path probe"
Assert-StagedFile $wintunZip $manifest.files.wintun_zip "wintun-0.14.1.zip" `
    1 16777216 "Wintun archive"
Assert-StagedFile $clientBinary $manifest.files.client "ferrum2-client.exe" `
    4096 536870912 "client binary"
Assert-StagedFile $serverBinary $manifest.files.server "ferrum2-server.exe" `
    4096 536870912 "server binary"
Assert-StagedFile $powerShellArchive $manifest.files.powershell_archive "portable-pwsh.zip" `
    1 536870912 "portable PowerShell archive"
[void](Read-StagedTopologyManifest $topologyManifestPath $manifest)
$ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
Assert-True (
    (Get-LowerSha256 $controller) -ceq [string]$ledger.probe_sha256 -and
    [string]$bundleManifest.controller_bundle_sha256 -ceq
        [string]$ledger.controller_bundle_sha256 -and
    (Get-LowerSha256 $clientBinary) -ceq [string]$ledger.client_sha256 -and
    (Get-LowerSha256 $serverBinary) -ceq [string]$ledger.server_sha256
) "controller or product identity differs from the ledger"
$expectedAppIdSha256 = Get-WfpAppIdSha256 $clientBinary

Assert-OrdinaryDirectory $runtimeLibraries "runtime library directory"
$vcEntries = @($manifest.files.vc_libraries)
$allowedVcNames = @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
Assert-True (
    $vcEntries.Count -ge 1 -and
    $vcEntries.Count -le 3 -and
    $vcEntries[0].name -ceq "vcruntime140.dll" -and
    @($vcEntries.name | Sort-Object -Unique).Count -eq $vcEntries.Count -and
    @($vcEntries | Where-Object { $allowedVcNames -cnotcontains [string]$_.name }).Count -eq 0
) "Visual C++ runtime manifest is invalid"
foreach ($entry in $vcEntries) {
    Assert-StagedFile (Join-Path $runtimeLibraries ([string]$entry.name)) $entry `
        ([string]$entry.name) 1 16777216 "Visual C++ runtime"
}
$inputItems = @(Get-Item -LiteralPath $inputRoot -Force -ErrorAction Stop) + @(
    Get-ChildItem -LiteralPath $inputRoot -Force -Recurse -ErrorAction Stop
)
$inputFiles = @($inputItems | Where-Object { -not $_.PSIsContainer })
$inputDirectories = @($inputItems | Where-Object { $_.PSIsContainer })
$expectedInputFiles = @($bundleManifest.files | ForEach-Object {
    Join-Path (Join-Path $inputRoot "controller") ([string]$_.path).Replace('/', '\')
}) + @(
    $manifestPath, $PSCommandPath, $controllerBundleManifestPath, $identityLedger,
    $topologyManifestPath,
    $guestNetworkPathProbe, $wintunZip, $clientBinary, $serverBinary, $powerShellArchive
) + @($vcEntries | ForEach-Object {
    Join-Path $runtimeLibraries ([string]$_.name)
})
$expectedInputDirectories = @(
    $inputRoot,
    (Join-Path $inputRoot "controller"),
    (Join-Path $inputRoot "controller\modules"),
    (Join-Path $inputRoot "controller\modules\Ferrum2.WindowsTun.Lab"),
    (Join-Path $inputRoot "artifacts"),
    (Join-Path $inputRoot "runtime"),
    $runtimeLibraries
)
Assert-True (
    @($inputItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -eq 0 -and
    $inputFiles.Count -eq $expectedInputFiles.Count -and
    $inputDirectories.Count -eq $expectedInputDirectories.Count -and
    (($inputFiles.FullName | ForEach-Object {
        [IO.Path]::GetFullPath($_).ToLowerInvariant()
    } | Sort-Object) -join "|") -ceq
        (($expectedInputFiles | ForEach-Object {
            [IO.Path]::GetFullPath($_).ToLowerInvariant()
        } | Sort-Object) -join "|") -and
    (($inputDirectories.FullName | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd('\', '/').ToLowerInvariant()
    } | Sort-Object) -join "|") -ceq
        (($expectedInputDirectories | ForEach-Object {
            [IO.Path]::GetFullPath($_).TrimEnd('\', '/').ToLowerInvariant()
        } | Sort-Object) -join "|")
) "guest staged input is not the exact ordinary file and directory set"
Assert-OrdinaryLeaf $pwsh "portable PowerShell executable" 4096 536870912
Assert-True (
    (Get-LowerSha256 $pwsh) -ceq [string]$manifest.runtime.powershell_executable_sha256
) "portable PowerShell executable hash changed"

$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$currentVersion = Get-ItemProperty `
    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
    -ErrorAction Stop
Assert-True (
    $computer.Manufacturer -ceq "Microsoft Corporation" -and
    $computer.Model -ceq "Virtual Machine" -and
    [string]$currentVersion.ProductName -ceq $manifest.guest_product -and
    [string]$currentVersion.EditionID -ceq $manifest.guest_edition -and
    [Environment]::OSVersion.Version.ToString() -ceq $manifest.guest_version -and
    "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)" -ceq $manifest.guest_build
) "live guest identity differs from the staged contract"

Assert-True (@(Get-ChildItem -LiteralPath $exportRoot -Force).Count -eq 0) `
    "hard-kill export baseline is not empty"
$evidenceSource = "$identityLedger.evidence-$runToken.jsonl"
Assert-True (-not (Test-Path -LiteralPath $evidenceSource)) `
    "hard-kill controller evidence baseline is not absent"
Assert-ZeroResidue (Get-ResidueSnapshot)
$guestNetworkPathValue = Invoke-GuestNetworkPathProbe `
    -Path $guestNetworkPathProbe `
    -Topology $manifest.topology `
    -SupportPort ([int]$ledger.support_listener.udp_port) `
    -ManagedAdapterName "F2-M16P-A-$runToken" `
    -OutputPath $guestNetworkPath
$guestNetworkPathLength = [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length
$guestNetworkPathSha256 = Get-LowerSha256 $guestNetworkPath
$controllerStdout = Join-Path $exportRoot "controller.stdout.log"
$controllerStderr = Join-Path $exportRoot "controller.stderr.log"
$cleanupStdout = Join-Path $exportRoot "cleanup.stdout.log"
$cleanupStderr = Join-Path $exportRoot "cleanup.stderr.log"
$artifactLedger = Join-Path $exportRoot "identity-ledger.json"
$artifactEvidence = Join-Path $exportRoot "hard-kill-evidence.jsonl"
Copy-ExactLeafCreateNew $identityLedger $artifactLedger "identity ledger"
$qualificationFailure = $null
$cleanupFailure = $null
$qualificationOutcome = "failure"

try {
    try {
        $exitCode = Invoke-CapturedPwsh @(
            "-NoProfile", "-File", $controller,
            "-WintunZip", $wintunZip,
            "-RunToken", $runToken,
            "-IdentityLedger", $identityLedger,
            "-TopologyManifest", $topologyManifestPath,
            "-GuestNetworkPath", $guestNetworkPath,
            "-ClientBinary", $clientBinary,
            "-ServerBinary", $serverBinary,
            "-ProductRoot", $inputRoot,
            "-RuntimeLibraryDirectory", $runtimeLibraries
        ) $controllerStdout $controllerStderr $true 7200
        Assert-True ($exitCode -eq 0) "hard-kill controller failed with exit code $exitCode"
        $ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
        Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
            "topology-manifest.json" 2 131072 "support topology manifest"
        Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
            "get_windows_tun_guest_network_path.ps1" 4096 1048576 `
            "guest network-path probe"
        Assert-OrdinaryLeaf $guestNetworkPath "guest network-path output" 2 65536
        Assert-True (
            [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length -eq
                $guestNetworkPathLength -and
            (Get-LowerSha256 $guestNetworkPath) -ceq $guestNetworkPathSha256
        ) "guest network-path output changed during qualification"
        Assert-TerminalMarker $controllerStdout $ledger
        Assert-HardKillEvidence $evidenceSource $expectedAppIdSha256
        Copy-ExactLeafCreateNew $evidenceSource $artifactEvidence "hard-kill evidence"
        $result = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-result.v3"
            status = "pass"
            mode = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
            candidate_sha = [string]$manifest.candidate_sha
            client_sha256 = [string]$ledger.client_sha256
            server_sha256 = [string]$ledger.server_sha256
            controller_sha256 = [string]$ledger.probe_sha256
            controller_bundle_sha256 = [string]$ledger.controller_bundle_sha256
            support_listener = $ledger.support_listener
            topology = $ledger.topology
            guest_network_path = $guestNetworkPathValue
            guest_build = [string]$ledger.guest_build
            cases = [long]3
            process_absent = $true
            adapter_absent = $true
            addresses_absent = $true
            routes_absent = $true
            dns_absent = $true
            strict_route_cases = [long]2
            strict_route_wfp_identity_verified = $true
            strict_route_wfp_absent = $true
            inner_cleanup = "pass"
            evidence_sha256 = Get-LowerSha256 $artifactEvidence
            stdout_sha256 = Get-LowerSha256 $controllerStdout
            stderr_sha256 = Get-LowerSha256 $controllerStderr
            finished_utc = [DateTime]::UtcNow.ToString("o")
        }
        Write-JsonCreateNew (Join-Path $exportRoot "hard-kill-result.json") $result
        $qualificationOutcome = "success"
    } catch {
        $qualificationFailure = $_
    }
} finally {
    $cleanupIssues = [Collections.Generic.List[string]]::new()
    $cleanupInvocationPassed = $false
    $readbackPassed = $false
    $residue = $null
    try {
        $cleanupExit = Invoke-CapturedPwsh @(
            "-NoProfile", "-File", $controller,
            "-Cleanup",
            "-RunToken", $runToken
        ) $cleanupStdout $cleanupStderr $false 900
        if ($cleanupExit -ne 0) {
            throw "cleanup controller failed with exit code $cleanupExit"
        }
        $cleanupInvocationPassed = $true
    } catch {
        $cleanupIssues.Add("cleanup invocation: $($_.Exception.Message)")
    }
    try {
        [void](Read-CanonicalIdentityLedger $identityLedger $manifest)
        Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
            "topology-manifest.json" 2 131072 "support topology manifest"
        Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
            "get_windows_tun_guest_network_path.ps1" 4096 1048576 `
            "guest network-path probe"
        Assert-OrdinaryLeaf $guestNetworkPath "guest network-path output" 2 65536
        Assert-True (
            [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length -eq
                $guestNetworkPathLength -and
            (Get-LowerSha256 $guestNetworkPath) -ceq $guestNetworkPathSha256
        ) "guest network-path output changed during cleanup"
        Ensure-ExactDurableCopy $identityLedger $artifactLedger "identity ledger"
        if (Test-Path -LiteralPath $evidenceSource -PathType Leaf) {
            Assert-HardKillEvidence $evidenceSource $expectedAppIdSha256
            Ensure-ExactDurableCopy $evidenceSource $artifactEvidence "hard-kill evidence"
        } elseif ($qualificationOutcome -ceq "success") {
            throw "successful qualification lost its evidence source"
        }
        $readbackPassed = $true
    } catch {
        $cleanupIssues.Add("durable evidence readback: $($_.Exception.Message)")
    }
    try {
        $residue = Get-ResidueSnapshot
        Assert-ZeroResidue $residue
    } catch {
        $cleanupIssues.Add("zero-residue readback: $($_.Exception.Message)")
    }
    if ($cleanupInvocationPassed -and $readbackPassed -and
        $null -ne $residue -and $cleanupIssues.Count -eq 0) {
        $cleanup = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-cleanup.v2"
            status = "pass"
            source_profile = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
            topology = $manifest.topology
            qualification_outcome = $qualificationOutcome
            processes = [long]$residue.processes
            adapters = [long]$residue.adapters
            target_addresses = [long]$residue.target_addresses
            target_routes = [long]$residue.target_routes
            dns_rows = [long]$residue.dns_rows
            sibling_dll = [long]$residue.sibling_dll
            work_directories = [long]$residue.work_directories
            mutation_journals = [long]$residue.mutation_journals
            firewall_rules = [long]$residue.firewall_rules
            identity_journal = [long]$residue.identity_journal
            finished_utc = [DateTime]::UtcNow.ToString("o")
        }
        Write-JsonCreateNew (Join-Path $exportRoot "hard-kill-cleanup.json") $cleanup
    }
    if ($cleanupIssues.Count -ne 0) {
        $cleanupFailure = [InvalidOperationException]::new(($cleanupIssues -join "; "))
    }
}

if ($null -ne $qualificationFailure -or $null -ne $cleanupFailure) {
    $failures = [Collections.Generic.List[string]]::new()
    if ($null -ne $qualificationFailure) {
        $failures.Add("qualification: $($qualificationFailure.Exception.Message)")
    }
    if ($null -ne $cleanupFailure) {
        $failures.Add("cleanup: $($cleanupFailure.Message)")
    }
    throw ($failures -join "; ")
}

$ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
Assert-TerminalMarker $controllerStdout $ledger
Assert-HardKillEvidence $artifactEvidence $expectedAppIdSha256
Assert-PublishedHardKillJson $ledger
$items = @(Get-ChildItem -LiteralPath $exportRoot -Force -ErrorAction Stop)
Assert-True (
    $items.Count -eq 8 -and
    (($items.Name | Sort-Object) -join "|") -ceq
        (($expectedArtifactFiles | Sort-Object) -join "|") -and
    @($items | Where-Object {
        $_.PSIsContainer -or
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }).Count -eq 0
) "successful hard-kill artifact set is not the exact eight ordinary files"
[Console]::Out.WriteLine(
    "m16_product_hard_kill_wrapper status=PASS run_token=$runToken files=8/8 cleanup=PASS"
)
