# Main M15/M17 guest controller implementation. Hard-kill has a separate controller and bundle.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance", "network-feasibility", "managed-product", "network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full", "cleanup")]
    [string]$Mode,
    [ValidateSet(10, 100, 1000)]
    [int]$NetworkResetCycles = 10,
    [ValidateSet(10, 100, 1000)]
    [int]$RestartCycles = 10,
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

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$controllerEntryPointPath = Join-Path $PSScriptRoot 'qualify_windows_tun.ps1'

$qualificationModuleRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "modules")) {
    Join-Path $PSScriptRoot "modules"
} else {
    Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path `
        "tools\powershell"
}
$controllerBundleManifestPath = Join-Path $PSScriptRoot "controller-bundle.json"
if (-not (Test-Path -LiteralPath $controllerBundleManifestPath -PathType Leaf)) {
    throw "controller bundle manifest is required"
}
$controllerBundleManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = `
    'modules/Ferrum2.Qualification.Common/BundleBootstrap.ps1'
$bootstrapEntry = @($controllerBundleManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $PSScriptRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw 'main controller bundle bootstrap changed'
}
. $bootstrapPath
$verifiedControllerBundle = Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot
if ([string]$verifiedControllerBundle.entrypoint -cne 'qualify_windows_tun.ps1') {
    throw 'main controller bundle entrypoint changed'
}
Import-Module (Join-Path $qualificationModuleRoot `
    "Ferrum2.Qualification.Evidence\Ferrum2.Qualification.Evidence.psd1") `
    -Scope Local -Force -ErrorAction Stop
Import-Module (Join-Path $qualificationModuleRoot `
    "Ferrum2.Qualification.GuestController\Ferrum2.Qualification.GuestController.psd1") `
    -Scope Local -Force -ErrorAction Stop
Assert-Ferrum2GuestQualificationMode -Mode $Mode
$modeContract = Get-Ferrum2GuestQualificationModeContract -Mode $Mode

$tcp08ClockOriginUtc = [DateTime]::UtcNow.ToString("o")
$tcp08ClockOriginTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()
$controllerStartedUtc = $tcp08ClockOriginUtc
$expectedHyperVVmName = $null
$expectedHyperVVmId = $null
$expectedHyperVCheckpointName = $null
$expectedHyperVCheckpointId = $null

if ($modeContract.requires_candidate_tests -and
    [string]::IsNullOrWhiteSpace($CandidateTestDirectory)) {
    throw "M17 qualification requires host-built CandidateTestDirectory artifacts"
}

if (-not $modeContract.accepts_network_reset_cycles -and
    $PSBoundParameters.ContainsKey("NetworkResetCycles")) {
    throw "NetworkResetCycles is valid only with network-reset mode"
}
if (-not $modeContract.accepts_restart_cycles -and
    $PSBoundParameters.ContainsKey("RestartCycles")) {
    throw "RestartCycles is valid only with restart-stress mode"
}

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
}

# Every mode in this controller can mutate adapter, route, or DNS state, including cleanup. Keep
# accidental host execution fail-closed; the host orchestrator must copy and invoke this script in
# an isolated Hyper-V guest.
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if ($computerSystem.Manufacturer -cne "Microsoft Corporation" -or
    $computerSystem.Model -cne "Virtual Machine") {
    throw "Windows TUN qualification must run inside an isolated Hyper-V guest"
}

function Assert-CurrentGuestIdentityMarker([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Windows TUN qualification requires an identity ledger"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.Length -lt 2 -or $item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Windows TUN identity ledger file boundary is invalid"
    }
    $ledger = Get-Content -LiteralPath $resolved -Raw -Encoding utf8 | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    $vmId = [Guid]::Empty
    $checkpointId = [Guid]::Empty
    if ($ledger.schema -ne 3 -or
        [string]$ledger.vm_name -cnotmatch '^[^\r\n]{1,128}$' -or
        -not [Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$vmId) -or
        $vmId -eq [Guid]::Empty -or
        [string]$ledger.checkpoint_name -cnotmatch '^[^\r\n]{1,128}$' -or
        -not [Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$checkpointId) -or
        $checkpointId -eq [Guid]::Empty -or
        [string]$ledger.controller_bundle_sha256 -cne
            [string]$script:controllerBundleManifest.controller_bundle_sha256) {
        throw "Windows TUN identity ledger does not name one bounded Hyper-V guest checkpoint"
    }
    $script:expectedHyperVVmName = [string]$ledger.vm_name
    $script:expectedHyperVVmId = $vmId.ToString("D")
    $script:expectedHyperVCheckpointName = [string]$ledger.checkpoint_name
    $script:expectedHyperVCheckpointId = $checkpointId.ToString("D")
    return $resolved
}

$identityMarker = $null
if ($Mode -ne "cleanup") {
    $identityMarker = Assert-CurrentGuestIdentityMarker $IdentityLedger
}

$expectedZipHash = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
$expectedDllHash = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
$expectedExports = @(
    "WintunAllocateSendPacket", "WintunCloseAdapter", "WintunCreateAdapter",
    "WintunDeleteDriver", "WintunEndSession", "WintunGetAdapterLUID", "WintunGetReadWaitEvent",
    "WintunGetRunningDriverVersion", "WintunReceivePacket",
    "WintunOpenAdapter", "WintunReleaseReceivePacket", "WintunSendPacket", "WintunSetLogger",
    "WintunStartSession"
) | Sort-Object

$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$clientBinaryInput = $ClientBinary
$serverBinaryInput = $ServerBinary
$resolvedProductRoot = if ($ProductRoot) {
    if ($Mode -eq "cleanup") { [IO.Path]::GetFullPath($ProductRoot) } else { (Resolve-Path -LiteralPath $ProductRoot).Path }
} else { $workspace }
$clientBinaryExplicit = -not [string]::IsNullOrWhiteSpace($clientBinaryInput)
$serverBinaryExplicit = -not [string]::IsNullOrWhiteSpace($serverBinaryInput)
$runtimeLibraryDirectoryExplicit = -not [string]::IsNullOrWhiteSpace($RuntimeLibraryDirectory)
$candidateTestDirectoryExplicit = -not [string]::IsNullOrWhiteSpace($CandidateTestDirectory)
$resolvedCandidateTestDirectory = $null
$resolvedRuntimeLibraryDirectory = $null
$runtimeVcruntimePath = $null
$runtimeVcruntimeBytes = $null
$runtimeVcruntimeSha256 = $null
$runIdentity = if ($RunToken) { $RunToken } elseif ($Mode -eq "cleanup") { throw "cleanup requires RunToken" } else { "local-$PID" }
if ($runIdentity -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw "RunToken is invalid" }
$work = if ($modeContract.is_m17) {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m17-tun-$runIdentity"
} elseif ($Mode -eq "network-feasibility") {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-network-$runIdentity"
} elseif ($Mode -in @("managed-product", "full", "hard-kill")) {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-product-$runIdentity"
} else {
    Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m15-tun-$runIdentity"
}
$binary = if ($clientBinaryExplicit) {
    if ($Mode -eq "cleanup") { [IO.Path]::GetFullPath($clientBinaryInput) } else { (Resolve-Path -LiteralPath $clientBinaryInput).Path }
} else { [IO.Path]::GetFullPath((Join-Path $resolvedProductRoot "target\debug\ferrum2-client.exe")) }
$serverBinary = if ($serverBinaryExplicit) {
    if ($Mode -eq "cleanup") { [IO.Path]::GetFullPath($serverBinaryInput) } else { (Resolve-Path -LiteralPath $serverBinaryInput).Path }
} else { [IO.Path]::GetFullPath((Join-Path $resolvedProductRoot "target\debug\ferrum2-server.exe")) }
$siblingDll = Join-Path (Split-Path -Parent $binary) "wintun.dll"
$tcp08Enabled = $Mode -in @("tcp08", "performance")
$tcp08PressureStableWaitMilliseconds = 1000
$runtimeIdleTimeoutMilliseconds = if ($tcp08Enabled) { 60000 } else { 2000 }
if ($RequireTcp08ProductMetrics -and -not $tcp08Enabled) { throw "RequireTcp08ProductMetrics requires tcp08 or performance mode" }
$tcp08ArtifactPath = if ($tcp08Enabled) {
    if ($ArtifactDirectory) {
        [IO.Path]::GetFullPath($ArtifactDirectory)
    } else {
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-tcp08-artifacts\$runIdentity"
    }
} else { $null }
$tcp08Events = [System.Collections.Generic.List[object]]::new()
$tcp08Samples = [System.Collections.Generic.List[object]]::new()
$tcp08CtrlBreak = $null
$tcp08Result = "NOT_RUN"
$tcp08ExitCode = $null
$tcp08ShutdownReportCandidateWindow = $null
$tcp08ArtifactInitialized = $false
$tcp08CleanupSucceeded = $false
$tcp08RequiredLogNames = @(
    "client.stdout.log", "client.stderr.log", "server.stdout.log", "server.stderr.log",
    "controller.stdout.log", "controller.stderr.log"
)
$tcp08RequiredJsonNames = @(
    "metadata.json", "timeline.json", "process-report.json", "network-before.json",
    "network-after.json", "process-before.json", "process-after.json", "binary-hashes.json",
    "cleanup-report.json"
)
$managedAutoAdapterName = "F2-M16P-A-$runIdentity"
$managedManualAdapterName = "F2-M16P-M-$runIdentity"
$adapterName = if ($modeContract.is_m17) {
    "F2-M17-$runIdentity"
} elseif ($Mode -eq "network-feasibility") {
    "Ferrum2-M16-$runIdentity"
} elseif ($Mode -eq "managed-product") {
    $managedAutoAdapterName
} else {
    "Ferrum2-M15-$runIdentity"
}
$config = Join-Path $work "client.toml"
$managedAutoConfig = Join-Path $work "client-managed-auto.toml"
$managedManualConfig = Join-Path $work "client-managed-manual.toml"
$managedLifecycleConfig = Join-Path $work "client-managed-lifecycle.toml"
$managedRouteOnlyConfig = Join-Path $work "client-managed-route-only.toml"
$failureConfig = Join-Path $work "client-failure.toml"
$addressJournal = Join-Path $work "owned-target-addresses.txt"
$dllJournal = Join-Path $work "owned-wintun-dll.txt"
$m17NetworkMutationJournal = Join-Path $work "m17-network-mutations"
$m17NetworkResetProbeAddress = "203.0.113.254"
$m17NetworkResetProbePrefix = "$m17NetworkResetProbeAddress/32"
$m17UdpFirewallRuleName = "Ferrum2-M17-UDP-$runIdentity"
$controllerProgram = [IO.Path]::GetFullPath((Get-Process -Id $PID -ErrorAction Stop).Path)
$runIdentityJournalRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) "Ferrum2\ControllerRunIdentities"
$runIdentityJournalPath = Join-Path $runIdentityJournalRoot "$runIdentity.json"


. (Join-Path $PSScriptRoot 'Guest.Identity.ps1')

. (Join-Path $PSScriptRoot 'Guest.Cleanup.ps1')

if ($Mode -eq "cleanup") {
    $cleanupWorks = @(Get-ControllerWorkPaths)
    $cleanupAdapterNames = @(
        "Ferrum2-M15-$runIdentity", "Ferrum2-M16-$runIdentity",
        $managedAutoAdapterName, $managedManualAdapterName, "F2-M17-$runIdentity"
    )
    $pendingIdentityPath = "$runIdentityJournalPath.pending"
    $cleanupIdentity = $null
    if (Test-Path -LiteralPath $runIdentityJournalPath -PathType Leaf) {
        Initialize-RunIdentityJournalRoot
        Assert-True (-not (Test-Path -LiteralPath $pendingIdentityPath)) "completed and pending run identity journals coexist"
        $cleanupIdentity = Read-RunIdentityJournal $runIdentityJournalPath $cleanupWorks
    } elseif (Test-Path -LiteralPath $pendingIdentityPath) {
        Initialize-RunIdentityJournalRoot
        Assert-NotReparsePoint $pendingIdentityPath "pending run identity journal"
        Assert-True (@($cleanupWorks | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 0) "pending identity journal coexists with mutable run work"
        Remove-Item -LiteralPath $pendingIdentityPath -Force -ErrorAction Stop
    }
    $presentCleanupWorks = @($cleanupWorks | Where-Object { Test-Path -LiteralPath $_ })
    Assert-True ($null -ne $cleanupIdentity -or $presentCleanupWorks.Count -eq 0) "controller work exists without a durable run identity journal"
    if ($cleanupIdentity) {
        foreach ($cleanupWork in $presentCleanupWorks) {
            Assert-True ($cleanupWork.Equals($cleanupIdentity.WorkPath, [StringComparison]::OrdinalIgnoreCase)) "unowned token work path is present"
            Assert-NotReparsePoint $cleanupWork "controller work directory"
        }
    }
    $cleanupExecutables = if ($cleanupIdentity) {
        @($cleanupIdentity.ClientPath, $cleanupIdentity.ServerPath)
    } else { @($binary, $serverBinary) }
    foreach ($cleanupWork in $cleanupWorks) {
        foreach ($process in @(Get-ExactRunProcesses $cleanupWork $cleanupExecutables)) {
            Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $processes = @($cleanupWorks | ForEach-Object { Get-ExactRunProcesses $_ $cleanupExecutables })
        $adapters = @($cleanupAdapterNames | ForEach-Object {
            Get-NetAdapter -Name $_ -IncludeHidden -ErrorAction SilentlyContinue
        })
        if ($processes.Count -eq 0 -and $adapters.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $allowedAddresses = @(
        "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
        "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208", "192.0.2.250",
        "192.0.2.241", "192.0.2.242", "2001:db8::241"
    )
    $journaledAddresses = @($cleanupWorks | ForEach-Object {
        $cleanupAddressJournal = Join-Path $_ "owned-target-addresses.txt"
        if (Test-Path -LiteralPath $cleanupAddressJournal) { Get-Content -LiteralPath $cleanupAddressJournal }
    })
    foreach ($address in $journaledAddresses) {
        if ($allowedAddresses -notcontains $address) { throw "target address journal is invalid" }
        $prefix = if ($address.Contains(":")) { "$address/128" } else { "$address/32" }
        Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
    $dllIntents = @($cleanupWorks | ForEach-Object {
        $candidate = Join-Path $_ "owned-wintun-dll.txt"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { [IO.Path]::GetFullPath($candidate).TrimEnd('\', '/') }
    })
    Assert-True ($dllIntents.Count -le 1) "multiple DLL ownership intents exist for one run token"
    if ($dllIntents.Count -eq 1) {
        Assert-True ($null -ne $cleanupIdentity) "DLL ownership intent exists without a durable run identity journal"
        Assert-True ($cleanupIdentity.Document.dll_ownership -ceq "owned") "borrowed DLL identity has an ownership intent"
        Assert-True ($dllIntents[0].Equals($cleanupIdentity.DllMarkerPath, [StringComparison]::OrdinalIgnoreCase)) "DLL ownership intent path does not match run identity"
        Remove-OwnedSiblingDll $cleanupIdentity
    } elseif ($cleanupIdentity -and (Test-Path -LiteralPath $cleanupIdentity.SiblingDllPath)) {
        if ($cleanupIdentity.Document.dll_ownership -ceq "owned") {
            throw "owned sibling DLL exists without a matching ownership intent"
        }
        Assert-NotReparsePoint $cleanupIdentity.SiblingDllPath "borrowed sibling DLL"
        Assert-True ((Get-FileHash -LiteralPath $cleanupIdentity.SiblingDllPath -Algorithm SHA256).Hash -ceq $expectedDllHash) "borrowed sibling DLL hash changed"
    }
    if (@($cleanupWorks | ForEach-Object { Get-ExactRunProcesses $_ $cleanupExecutables }).Count -ne 0) { throw "controller process residue" }
    if (@($cleanupAdapterNames | ForEach-Object {
        Get-NetAdapter -Name $_ -IncludeHidden -ErrorAction SilentlyContinue
    }).Count -ne 0) { throw "controller adapter residue" }
    $mutationJournals = @($cleanupWorks | ForEach-Object {
        $candidate = Join-Path $_ "m17-network-mutations"
        if (Test-Path -LiteralPath $candidate) { [IO.Path]::GetFullPath($candidate).TrimEnd('\', '/') }
    })
    if ($cleanupIdentity -and
        (Get-Ferrum2GuestQualificationModeContract `
            -Mode ([string]$cleanupIdentity.Document.mode)).is_m17) {
        $expectedMutationJournal = Join-Path $cleanupIdentity.WorkPath "m17-network-mutations"
        Assert-True ($mutationJournals.Count -le 1 -and
            ($mutationJournals.Count -eq 0 -or $mutationJournals[0].Equals($expectedMutationJournal, [StringComparison]::OrdinalIgnoreCase))) "M17 recovery journal is outside the identity work path"
        Restore-M17NetworkMutationJournal $cleanupIdentity.WorkPath $expectedMutationJournal
    } else {
        Assert-True ($mutationJournals.Count -eq 0) "M17 recovery journal exists for a non-M17 identity"
    }
    Assert-True (-not (Get-NetFirewallRule -Name $m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "controller UDP firewall rule residue"
    foreach ($address in $journaledAddresses) {
        $prefix = if ($address.Contains(":")) { "$address/128" } else { "$address/32" }
        if (Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address -ErrorAction SilentlyContinue) { throw "controller address residue" }
        if (Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue) { throw "controller route residue" }
    }
    if ($cleanupIdentity) {
        if (Test-Path -LiteralPath $cleanupIdentity.WorkPath) {
            Assert-NotReparsePoint $cleanupIdentity.WorkPath "controller work directory"
            Remove-Item -LiteralPath $cleanupIdentity.WorkPath -Recurse -Force -ErrorAction Stop
        }
        Assert-True (-not (Test-Path -LiteralPath $cleanupIdentity.WorkPath)) "controller temp residue"
        foreach ($cleanupWork in $cleanupWorks) {
            if (-not $cleanupWork.Equals($cleanupIdentity.WorkPath, [StringComparison]::OrdinalIgnoreCase)) {
                Assert-True (-not (Test-Path -LiteralPath $cleanupWork)) "unowned token work path residue"
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($ArtifactDirectory)) {
        if ($cleanupIdentity) {
            Remove-Item -LiteralPath $runIdentityJournalPath -Force -ErrorAction Stop
            Assert-True (-not (Test-Path -LiteralPath $runIdentityJournalPath)) "run identity journal residue"
        }
        return
    }

    $externalArtifactRoot = [IO.Path]::GetFullPath($ArtifactDirectory).TrimEnd('\', '/')
    Assert-True (Test-Path -LiteralPath $externalArtifactRoot -PathType Container) "external cleanup artifact directory is missing"
    Assert-NotReparsePoint $externalArtifactRoot "external cleanup artifact directory"
    foreach ($cleanupWork in $cleanupWorks) {
        $workPrefix = "$($cleanupWork.TrimEnd('\', '/'))\"
        Assert-True (-not $externalArtifactRoot.Equals($cleanupWork, [StringComparison]::OrdinalIgnoreCase) -and
            -not $externalArtifactRoot.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase)) "external cleanup artifact directory is inside disposable work"
    }
    $artifactLedgerPath = Join-Path $externalArtifactRoot "identity-ledger.json"
    $artifactResultPath = Join-Path $externalArtifactRoot "m17-result.json"
    [void](Assert-CurrentGuestIdentityMarker $artifactLedgerPath)
    $artifactIdentityHash = (Get-FileHash -LiteralPath $artifactLedgerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True (Test-Path -LiteralPath $artifactResultPath -PathType Leaf) "external cleanup requires the M17 result artifact"
    Assert-NotReparsePoint $artifactResultPath "M17 result artifact"
    $artifactResultRaw = Get-Content -LiteralPath $artifactResultPath -Raw -Encoding utf8
    $artifactResultStrings = Get-RequiredJsonStrings $artifactResultRaw @(
        "schema", "status", "mode", "run_token", "approved_vm_name", "approved_vm_id",
        "approved_checkpoint_name", "approved_checkpoint_id", "identity_sha256",
        "controller_sha256", "controller_bundle_sha256",
        "started_utc", "finished_utc"
    ) "M17 result artifact"
    $artifactResult = $artifactResultRaw | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    Assert-ClosedJsonProperties $artifactResult @(
        "schema", "status", "mode", "run_token", "network_reset_cycles", "restart_cycles", "approved_vm_name",
        "approved_vm_id", "approved_checkpoint_name", "approved_checkpoint_id", "guest_build",
        "identity_sha256", "candidate_sha", "client_sha256", "server_sha256",
        "controller_sha256", "controller_bundle_sha256",
        "wintun_zip_sha256", "wintun_dll_sha256", "test_binaries", "topology",
        "guest_network_path", "started_utc", "finished_utc",
        "fixtures", "processes", "live_checks", "deterministic_tests", "witnesses", "counters_before",
        "counters_after", "cleanup", "failure"
    ) "M17 result artifact"
    Assert-True ($artifactResult.schema -is [string] -and
        $artifactResult.status -is [string] -and $artifactResult.mode -is [string] -and
        $artifactResult.run_token -is [string] -and $artifactResult.approved_vm_name -is [string] -and
        $artifactResult.approved_vm_id -is [string] -and $artifactResult.approved_checkpoint_name -is [string] -and
        $artifactResult.approved_checkpoint_id -is [string] -and $artifactResult.identity_sha256 -is [string] -and
        $artifactResult.controller_sha256 -is [string] -and
        $artifactResult.controller_bundle_sha256 -is [string] -and
        $artifactResult.schema -ceq "ferrum2.windows-tun.m17-result.v3" -and
        @("pass", "fail") -ccontains $artifactResult.status -and
        (Get-Ferrum2GuestQualificationModeContract `
            -Mode ([string]$artifactResult.mode)).is_m17 -and
        $artifactResult.run_token -ceq $script:runIdentity -and
        $artifactResult.approved_vm_name -ceq $script:expectedHyperVVmName -and
        $artifactResult.approved_vm_id -ceq $script:expectedHyperVVmId -and
        $artifactResult.approved_checkpoint_name -ceq $script:expectedHyperVCheckpointName -and
        $artifactResult.approved_checkpoint_id -ceq $script:expectedHyperVCheckpointId -and
        $artifactResult.identity_sha256 -ceq $artifactIdentityHash -and
        $artifactResult.controller_sha256 -ceq (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -and
        $artifactResult.controller_bundle_sha256 -ceq
            [string]$script:controllerBundleManifest.controller_bundle_sha256 -and
        (Test-UtcRoundTripTimestamp $artifactResultStrings.started_utc) -and
        (Test-UtcRoundTripTimestamp $artifactResultStrings.finished_utc)) "M17 result artifact identity is invalid"

    $externalPath = Join-Path $externalArtifactRoot "external-cleanup.json"
    $pendingExternalPath = "$externalPath.pending"
    Assert-True (-not ((Test-Path -LiteralPath $externalPath) -and
        (Test-Path -LiteralPath $pendingExternalPath))) "completed and pending external cleanup artifacts coexist"
    if ($cleanupIdentity) {
        Assert-True ($cleanupIdentity.Document.mode -ceq [string]$artifactResult.mode -and
            $cleanupIdentity.Document.identity_sha256 -ceq $artifactIdentityHash -and
            $cleanupIdentity.Document.controller_sha256 -ceq [string]$artifactResult.controller_sha256) "external cleanup journal and artifact identities differ"
    } else {
        Assert-True ((Test-Path -LiteralPath $externalPath -PathType Leaf) -or
            (Test-Path -LiteralPath $pendingExternalPath -PathType Leaf)) "external cleanup cannot mint evidence without a durable identity journal"
    }

    $evidenceAddresses = @("192.0.2.241", "192.0.2.242", "2001:db8::241")
    $processResidue = @($cleanupWorks | ForEach-Object { Get-ExactRunProcesses $_ $cleanupExecutables }).Count
    $adapterResidue = @($cleanupAdapterNames | ForEach-Object {
        Get-NetAdapter -Name $_ -IncludeHidden -ErrorAction SilentlyContinue
    }).Count
    $addressResidue = @($evidenceAddresses | Where-Object {
        Get-NetIPAddress -InterfaceIndex 1 -IPAddress $_ -ErrorAction SilentlyContinue
    }).Count
    $routeResidue = @($evidenceAddresses | Where-Object {
        $prefix = if ($_.Contains(":")) { "$_/128" } else { "$_/32" }
        Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    }).Count
    $workResidue = @($cleanupWorks | Where-Object { Test-Path -LiteralPath $_ }).Count
    $mutationResidue = @($cleanupWorks | Where-Object {
        Test-Path -LiteralPath (Join-Path $_ "m17-network-mutations")
    }).Count
    $firewallResidue = @(Get-NetFirewallRule -Name $m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
    $siblingResidue = if ($cleanupIdentity -and (Test-Path -LiteralPath $cleanupIdentity.SiblingDllPath)) { 1 } else { 0 }
    Assert-True ($processResidue -eq 0 -and $adapterResidue -eq 0 -and $addressResidue -eq 0 -and
        $routeResidue -eq 0 -and $workResidue -eq 0 -and $mutationResidue -eq 0 -and
        $firewallResidue -eq 0 -and $siblingResidue -eq 0) "external M17 cleanup readback found residue"

    $externalProperties = @(
        "schema", "status", "run_token", "source_mode", "identity_sha256", "processes", "adapters",
        "target_addresses", "target_routes", "sibling_dll", "work_directories", "mutation_journals",
        "identity_journal", "finished_utc"
    )
    if (Test-Path -LiteralPath $externalPath -PathType Leaf) {
        $publishedRaw = Get-Content -LiteralPath $externalPath -Raw -Encoding utf8
        $publishedStrings = Get-RequiredJsonStrings $publishedRaw @(
            "schema", "status", "run_token", "source_mode", "identity_sha256", "finished_utc"
        ) "external cleanup artifact"
        $published = $publishedRaw | ConvertFrom-Json -Depth 4 -ErrorAction Stop
        Assert-ClosedJsonProperties $published $externalProperties "external cleanup artifact"
        Assert-True ($published.schema -is [string] -and $published.status -is [string] -and
            $published.run_token -is [string] -and $published.source_mode -is [string] -and
            $published.identity_sha256 -is [string] -and
            $published.schema -ceq "ferrum2.windows-tun.m17-external-cleanup.v1" -and
            $published.status -ceq "pass" -and $published.run_token -ceq $script:runIdentity -and
            $published.source_mode -ceq [string]$artifactResult.mode -and
            $published.identity_sha256 -ceq $artifactIdentityHash -and
            (Test-UtcRoundTripTimestamp $publishedStrings.finished_utc) -and
            @($externalProperties[5..12] | Where-Object {
                $value = $published.$_
                -not ($value -is [long] -and $value -eq 0)
            }).Count -eq 0 -and
            -not (Test-Path -LiteralPath $runIdentityJournalPath)) "published external cleanup artifact is invalid"
        return
    }
    if (-not (Test-Path -LiteralPath $pendingExternalPath -PathType Leaf)) {
        Assert-True ($null -ne $cleanupIdentity) "external cleanup pending evidence lacks its durable identity journal"
        $externalDocument = [ordered]@{
            schema = "ferrum2.windows-tun.m17-external-cleanup.v1"
            status = "pass"
            run_token = $script:runIdentity
            source_mode = [string]$artifactResult.mode
            identity_sha256 = $artifactIdentityHash
            processes = 0
            adapters = 0
            target_addresses = 0
            target_routes = 0
            sibling_dll = 0
            work_directories = 0
            mutation_journals = 0
            identity_journal = 0
            finished_utc = [DateTime]::UtcNow.ToString("o")
        }
        $externalBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ($externalDocument | ConvertTo-Json -Depth 4) + "`n"
        )
        $externalStream = [IO.FileStream]::new(
            $pendingExternalPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try { $externalStream.Write($externalBytes, 0, $externalBytes.Length); $externalStream.Flush($true) }
        finally { $externalStream.Dispose() }
    }
    Assert-NotReparsePoint $pendingExternalPath "pending external cleanup artifact"
    $pendingExternalRaw = Get-Content -LiteralPath $pendingExternalPath -Raw -Encoding utf8
    $pendingExternalStrings = Get-RequiredJsonStrings $pendingExternalRaw @(
        "schema", "status", "run_token", "source_mode", "identity_sha256", "finished_utc"
    ) "pending external cleanup artifact"
    $pendingExternal = $pendingExternalRaw | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    Assert-ClosedJsonProperties $pendingExternal $externalProperties "pending external cleanup artifact"
    Assert-True ($pendingExternal.schema -is [string] -and $pendingExternal.status -is [string] -and
        $pendingExternal.run_token -is [string] -and $pendingExternal.source_mode -is [string] -and
        $pendingExternal.identity_sha256 -is [string] -and
        $pendingExternal.schema -ceq "ferrum2.windows-tun.m17-external-cleanup.v1" -and
        $pendingExternal.status -ceq "pass" -and $pendingExternal.run_token -ceq $script:runIdentity -and
        $pendingExternal.source_mode -ceq [string]$artifactResult.mode -and
        $pendingExternal.identity_sha256 -ceq $artifactIdentityHash -and
        (Test-UtcRoundTripTimestamp $pendingExternalStrings.finished_utc) -and
        @($externalProperties[5..12] | Where-Object {
            $value = $pendingExternal.$_
            -not ($value -is [long] -and $value -eq 0)
        }).Count -eq 0) "pending external cleanup artifact is invalid"
    if (Test-Path -LiteralPath $runIdentityJournalPath) {
        Remove-Item -LiteralPath $runIdentityJournalPath -Force -ErrorAction Stop
    }
    Assert-True (-not (Test-Path -LiteralPath $runIdentityJournalPath)) "run identity journal residue"
    Move-Item -LiteralPath $pendingExternalPath -Destination $externalPath -ErrorAction Stop
    Assert-True (Test-Path -LiteralPath $externalPath -PathType Leaf) "external cleanup artifact publish failed"
    return
}

if ($candidateTestDirectoryExplicit) {
    Assert-True $modeContract.is_m17 `
        "CandidateTestDirectory is valid only with an M17 mode"
    $candidateTestDirectoryItem = Get-Item -LiteralPath $CandidateTestDirectory -Force -ErrorAction Stop
    Assert-True $candidateTestDirectoryItem.PSIsContainer "CandidateTestDirectory must be a directory"
    Assert-True (($candidateTestDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "CandidateTestDirectory must not be a reparse point"
    $resolvedCandidateTestDirectory = [IO.Path]::GetFullPath($candidateTestDirectoryItem.FullName)
    foreach ($name in @("ferrum2-client-tests.exe", "ferrum2-tun-tests.exe", "ferrum2-platform-windows-tests.exe")) {
        $path = Join-Path $resolvedCandidateTestDirectory $name
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "CandidateTestDirectory is missing $name"
        Assert-NotReparsePoint $path "candidate test binary"
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-True ($item.Length -ge 4096 -and $item.Length -le 536870912) "candidate test binary size is invalid"
    }
}

if ($runtimeLibraryDirectoryExplicit) {
    $runtimeDirectoryItem = Get-Item -LiteralPath $RuntimeLibraryDirectory -Force -ErrorAction Stop
    Assert-True $runtimeDirectoryItem.PSIsContainer "RuntimeLibraryDirectory must be a directory"
    Assert-True (($runtimeDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "RuntimeLibraryDirectory must not be a reparse point"
    $resolvedRuntimeLibraryDirectory = [IO.Path]::GetFullPath($runtimeDirectoryItem.FullName)
    $runtimeVcruntimePath = Join-Path $resolvedRuntimeLibraryDirectory "vcruntime140.dll"
    Assert-True (Test-Path -LiteralPath $runtimeVcruntimePath -PathType Leaf) "RuntimeLibraryDirectory is missing vcruntime140.dll"
    Assert-NotReparsePoint $runtimeVcruntimePath "runtime vcruntime140.dll"
    $runtimeVcruntimeItem = Get-Item -LiteralPath $runtimeVcruntimePath -Force -ErrorAction Stop
    $runtimeVcruntimeBytes = $runtimeVcruntimeItem.Length
    $runtimeVcruntimeSha256 = (Get-FileHash -LiteralPath $runtimeVcruntimePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $env:Path = if ([string]::IsNullOrEmpty($env:Path)) {
        $resolvedRuntimeLibraryDirectory
    } else {
        "$resolvedRuntimeLibraryDirectory;$env:Path"
    }
}

$zipInput = if ($WintunZip) { $WintunZip } elseif ($env:FERRUM2_WINTUN_ZIP) { $env:FERRUM2_WINTUN_ZIP } else { throw "Wintun ZIP path is required via -WintunZip or FERRUM2_WINTUN_ZIP" }
$zip = (Resolve-Path -LiteralPath $zipInput).Path
$ownedRoutes = [System.Collections.Generic.List[object]]::new()
$activeProcess = $null
$ownedInterfaceIndex = $null
$heldMetrics = $null
$udp4 = $null
$foundation = 0
$tcpRows = 0
$udpRows = 0
$serverProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$ownedAddresses = [System.Collections.Generic.List[object]]::new()
$ownedTargetRoutes = [System.Collections.Generic.List[object]]::new()
$tcpResources = [System.Collections.Generic.List[System.IDisposable]]::new()
$udpGateA = $null
$udpGateB = $null
$usedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$createdSiblingDll = $false
$runJournalIdentity = $null
$completed = $false
$primaryError = $null
$outerCleanupError = $null
$tcp01Diagnostic = $null
$cycleRows = 0
$performanceWitnesses = 0
$performanceDirectRows = 0
$performanceDnsRows = 0
$performanceAdapterRxBytes = [uint64]0
$performanceAdapterTxBytes = [uint64]0
$performanceAdapterRxPackets = [uint64]0
$performanceAdapterTxPackets = [uint64]0
$performanceAdapterRxErrors = [uint64]0
$performanceAdapterTxErrors = [uint64]0
$performanceAdapterRxDiscards = [uint64]0
$performanceAdapterTxDiscards = [uint64]0
$performanceTunAcceptedDelta = [uint64]0
$performanceCpuMilliseconds = [uint64]0
$performanceRssBytes = [uint64]0
$performanceHandlesPeak = [uint64]0
$performanceThreadsPeak = [uint64]0
$performanceUdpSessionsPeak = [uint64]0
$performanceUdpBufferedBytesPeak = [uint64]0
$performanceControllerInflightPeak = [uint64]0
$performanceCpuBaseline = [double]0
$performanceTunAcceptedBaseline = [uint64]0
$performanceTrafficBaseline = $null
$performanceFieldsCollected = $false
$performanceAdapterChurn = 0
$performanceGraceDrain = $false
$performanceForceDrain = $false
$capabilityIdentity = $null
$capabilityIdentityHash = $null
$capabilityEvidence = $null
$capabilityRoutes = [System.Collections.Generic.List[System.IDisposable]]::new()
$capabilityDnsSnapshot = $null
$capabilityDnsApplied = $false
$capabilityMetricSnapshot = $null
$capabilityMetricApplied = $false
$capabilityInterfaceMetric = $null
$capabilityRouteRows = 0
$capabilityTcpRows = 0
$capabilityUdpRows = 0
$capabilityDnsRows = 0
$capabilityWindowRows = 0
$capabilityHardKillRows = 0
$managedFixedTcpRows = 0
$managedFixedUdpRows = 0
$managedDynamicTcpRows = 0
$managedDynamicUdpRows = 0
$managedManualTcpRows = 0
$managedManualUdpRows = 0
$managedUnpinnedRows = 0
$managedRouteRows = 0
$managedInterfaceMetric = $null
$managedDirectTcpRows = 0
$managedDirectUdpRows = 0
$managedSystemDnsRows = 0
$managedNetworkChangeRows = 0
$managedRouteChangeRows = 0
$managedInterfaceChangeRows = 0
$managedAddressChangeRows = 0
$managedHardKillRows = 0
$managedFilteredPackets = [ordered]@{
    unpinned_tcp = $null
    unpinned_udp = $null
    proxy_tcp = $null
    proxy_udp = $null
    direct_tcp = $null
    direct_udp = $null
    dns_tcp = $null
    dns_udp = $null
}
$pktmonStarted = $false
$pktmonStartAttempted = $false
$pktmonTcpFilterOwned = $false
$pktmonUdpFilterOwned = $false
$pktmonComponentId = $null
$capabilityFilteredPackets = [ordered]@{
    fixed_tcp_unpinned = $null
    fixed_tcp_pinned = $null
    dynamic_tcp_unpinned = $null
    dynamic_tcp_pinned = $null
    fixed_udp_unpinned = $null
    fixed_udp_pinned = $null
    dynamic_udp_unpinned = $null
    dynamic_udp_pinned = $null
}
$m17ArtifactRoot = $null
$m17ArtifactInitialized = $false
$m17GuestNetworkPathDocument = $null
$m17Contract = $null
$m17FixtureRows = @()
$m17WitnessRows = [ordered]@{}
$m17TestRows = [System.Collections.Generic.List[object]]::new()
$m17ProcessRows = [System.Collections.Generic.List[object]]::new()
$m17LiveRows = [System.Collections.Generic.List[object]]::new()
$m17CounterBefore = $null
$m17CounterAfter = $null
$m17StartedUtc = $null
$m17FinishedUtc = $null
$m17ProcessOrdinal = 0
$m17ServerProcess = $null
$m17ServerPort = $null
$m17MetricsPort = $null


. (Join-Path $PSScriptRoot 'Guest.HardKillSupport.ps1')

. (Join-Path $PSScriptRoot 'Main.Tcp08Capture.ps1')

. (Join-Path $PSScriptRoot 'Main.Tcp08Evidence.ps1')

. (Join-Path $PSScriptRoot 'Guest.Topology.ps1')

if ($modeContract.topology_bound) {
    $capabilityIdentity = Get-NetworkFeasibilityIdentity `
        $IdentityLedger ($Mode -eq "full" -or $modeContract.is_m17)
    $capabilityIdentityHash = $capabilityIdentity.IdentitySha256
    $capabilityEvidence = "$($capabilityIdentity.Path).evidence-$runIdentity.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $capabilityEvidence)) "network feasibility evidence baseline not absent"
    $m17GuestNetworkPathDocument = Read-M17GuestNetworkPath $GuestNetworkPath $capabilityIdentity.Ledger
}


. (Join-Path $PSScriptRoot 'Guest.Runtime.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeProcess.cs.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeTransport.cs.ps1')

. (Join-Path $PSScriptRoot 'Guest.NativeNetwork.cs.ps1')

. (Join-Path $PSScriptRoot 'Main.Tcp08Network.ps1')

. (Join-Path $PSScriptRoot 'Guest.TransportProbes.ps1')

. (Join-Path $PSScriptRoot 'Main.Tcp08Profile.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Contract.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Runtime.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Reset.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Protocol.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Udp.ps1')

. (Join-Path $PSScriptRoot 'Main.M17Scheduler.ps1')

try {
    Initialize-Tcp08Artifacts
    Assert-True (-not (Test-Path -LiteralPath $work)) "run work baseline not absent"
    Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) "run process baseline not absent"
    Assert-True (-not (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)) "run adapter baseline not absent"
    if ($modeContract.is_m17) {
        Assert-True (-not (Get-NetFirewallRule -Name $m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 UDP firewall rule baseline not absent"
    }
    if ($Mode -in @("managed-product", "full", "hard-kill")) {
        Assert-True (-not (Get-NetAdapter -Name $managedManualAdapterName -IncludeHidden -ErrorAction SilentlyContinue)) "manual product adapter baseline not absent"
        Assert-True (-not (Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue)) "managed lifecycle adapter baseline not absent"
    }
    Assert-True ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -eq $expectedZipHash) "ZIP hash mismatch"
    Write-RunIdentityJournal
    $runJournalIdentity = Read-RunIdentityJournal $runIdentityJournalPath @(Get-ControllerWorkPaths)
    New-Item -ItemType Directory -Path $work | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $work
    $sourceDll = Join-Path $work "wintun\bin\amd64\wintun.dll"
    Assert-True (Test-Path -LiteralPath (Join-Path $work "wintun\LICENSE.txt")) "license member missing"
    Assert-True ((Get-Item -LiteralPath $sourceDll).Length -eq 427552) "DLL size mismatch"
    Assert-True ((Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash -eq $expectedDllHash) "DLL hash mismatch"
    $pe = [IO.File]::ReadAllBytes($sourceDll)
    $peOffset = [BitConverter]::ToInt32($pe, 0x3c)
    Assert-True ([BitConverter]::ToUInt16($pe, $peOffset + 4) -eq 0x8664) "DLL is not AMD64 PE"
    Assert-True ((Get-AuthenticodeSignature -LiteralPath $sourceDll).Status -eq "Valid") "Authenticode trust invalid"
    $exports = @(Get-PeExportNames $pe)
    Assert-True (($exports -join "|") -eq ($expectedExports -join "|")) "DLL export set mismatch"
    $foundation++

    if (-not $modeContract.topology_bound) {
        $buildPackages = [System.Collections.Generic.List[string]]::new()
        if (-not $clientBinaryExplicit) {
            $buildPackages.Add("-p")
            $buildPackages.Add("ferrum2-client")
        }
        if ($Mode -in @("tcp", "tcp08", "udp", "performance") -and -not $serverBinaryExplicit) {
            $buildPackages.Add("-p")
            $buildPackages.Add("ferrum2-server")
        }
        if ($buildPackages.Count -gt 0) {
            Push-Location $resolvedProductRoot
            try {
                & cargo +1.97.1 build @buildPackages --locked
                if ($LASTEXITCODE -ne 0) { throw "candidate build failed" }
            }
            finally { Pop-Location }
        }
    }
    Assert-True (Test-Path -LiteralPath $binary) "candidate client binary is missing after selection/build"
    if ($Mode -in @("tcp", "tcp08", "udp", "performance") -or $modeContract.is_m17) {
        Assert-True (Test-Path -LiteralPath $serverBinary) "candidate server binary is missing after selection/build"
    }
    if ($tcp08Enabled) { Write-Tcp08BinaryEvidence $sourceDll }
    if ($modeContract.is_m17) {
        [void](Invoke-M17ContractPreflight)
        Invoke-M17Qualification $sourceDll
    }

. (Join-Path $PSScriptRoot 'Main.ProfileManagedProduct.ps1')

. (Join-Path $PSScriptRoot 'Main.ProfileFullHardKill.ps1')

. (Join-Path $PSScriptRoot 'Main.ProfileNetworkFeasibility.ps1')

. (Join-Path $PSScriptRoot 'Main.ProfileClassic.ps1')

    if ($Mode -eq "full") {
        Assert-True ($foundation -eq 4 -and $tcpRows -eq 8 -and $udpRows -eq 8) "full profile prerequisite count mismatch"
        if ($cycleRows -eq 0) { Invoke-AdapterCycles $binary $config }
    }
    $completed = $true
}
catch { $primaryError = $_ }
finally {
    Add-Tcp08Event "cleanup_started" ([ordered]@{ primary_failure = [bool]$primaryError })
    try {
    if ($udp4) { $udp4.Dispose() }
    if ($heldMetrics) { $heldMetrics.Stop() }
    foreach ($route in $ownedRoutes) {
        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($Mode -in @("network-feasibility", "managed-product")) {
        try { Stop-CapabilityPktMon }
        catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
    }
    if ($Mode -eq "network-feasibility") {
        try { Remove-CapabilityRoutes }
        catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
        $capabilityAdapter = Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue
        if ($capabilityAdapter) {
            try { Restore-CapabilityDns ([int]$capabilityAdapter.ifIndex) }
            catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
            try { Restore-CapabilityInterfaceMetric ([int]$capabilityAdapter.ifIndex) }
            catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
        } else {
            $capabilityDnsApplied = $false
            $capabilityDnsSnapshot = $null
            $capabilityMetricApplied = $false
            $capabilityMetricSnapshot = $null
        }
    }
    if ($activeProcess -and -not [Ferrum2ProcessGroup]::Wait([uint32]$activeProcess.Id, 0)) {
        [void][Ferrum2ProcessGroup]::Break([uint32]$activeProcess.Id)
        if (-not (Wait-ProcessExit $activeProcess 5)) {
            Stop-Process -InputObject $activeProcess -Force -ErrorAction SilentlyContinue
            Assert-True (Wait-ProcessExit $activeProcess 5) "owned candidate fallback termination failed"
        }
    }
    if ($activeProcess) { [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id) }
    foreach ($resource in $tcpResources) { $resource.Dispose() }
    foreach ($server in $serverProcesses) {
        if (-not [Ferrum2ProcessGroup]::Wait([uint32]$server.Id, 0)) {
            [void][Ferrum2ProcessGroup]::Break([uint32]$server.Id)
            if (-not (Wait-ProcessExit $server 5)) {
                Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$server.Id)) "owned server fallback termination failed"
                Assert-True (Wait-ProcessExit $server 5) "owned server did not terminate"
            }
        }
        [Ferrum2ProcessGroup]::Close([uint32]$server.Id)
    }
    if (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue) {
        Wait-AdapterAbsent $adapterName 20
    }
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    if ($Mode -in @("managed-product", "full", "hard-kill")) {
        if (Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
            Wait-AdapterAbsent $managedAutoAdapterName 20
        }
        if (Get-NetAdapter -Name $managedManualAdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
            Wait-AdapterAbsent $managedManualAdapterName 20
        }
        Assert-InterfaceGone $managedAutoAdapterName $null
        Assert-InterfaceGone $managedManualAdapterName $null
    }
    Restore-M17NetworkMutationJournal $work $m17NetworkMutationJournal
    foreach ($route in $ownedTargetRoutes) {
        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($address in $ownedAddresses) {
        Remove-NetIPAddress -InputObject $address -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($address in $ownedAddresses) {
        Assert-True (@(Get-NetIPAddress -IPAddress $address.IPAddress -ErrorAction SilentlyContinue).Count -eq 0) "controller-owned target address leaked"
    }
    foreach ($route in $ownedTargetRoutes) {
        Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $route.DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "controller-owned target route leaked"
    }
    foreach ($route in $ownedRoutes) {
        $leaked = @(Get-NetRoute -DestinationPrefix $route.DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex })
        Assert-True ($leaked.Count -eq 0) "controller-owned route leaked: $($route.DestinationPrefix)"
    }
    if ($createdSiblingDll) { Remove-OwnedSiblingDll $runJournalIdentity }
    if (Test-Path -LiteralPath $work) {
        Assert-NotReparsePoint $work "controller work directory"
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    if ($createdSiblingDll) { Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "owned sibling DLL leaked" }
    Assert-True (-not (Test-Path -LiteralPath $work)) "controller work directory leaked"
    if ($modeContract.topology_bound) {
        Assert-M17ExternalIdentityInputsUnchanged
    }
    $tcp08CleanupSucceeded = $true
    } catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
    Add-Tcp08Event "cleanup_completed" ([ordered]@{
        succeeded = $tcp08CleanupSucceeded
        cleanup_failure_type = if ($outerCleanupError) { $outerCleanupError.Exception.GetType().FullName } else { $null }
    })
    if ($tcp08ArtifactInitialized) {
        try { Complete-Tcp08Artifacts $tcp08CleanupSucceeded $primaryError $outerCleanupError }
        catch { if (-not $outerCleanupError) { $outerCleanupError = $_ } }
    }
}

if ($tcp01Diagnostic) {
    $tcp01Cleanup = if ($outerCleanupError) { "FAIL" } else { "PASS" }
    $tcp01Sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $tcp01RunId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $tcp01RunAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    [Console]::Error.WriteLine("m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt")
}
if ($modeContract.is_m17 -and $m17ArtifactInitialized) {
    $m17Succeeded = $completed -and -not $primaryError -and -not $outerCleanupError -and $tcp08CleanupSucceeded
    try { Complete-M17Artifact $m17Succeeded $primaryError $outerCleanupError }
    catch {
        if (-not $primaryError) { $primaryError = $_ }
        elseif (-not $outerCleanupError) { $outerCleanupError = $_ }
    }
}
if ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }
if ($primaryError) { throw $primaryError }

if ($completed) {
    $sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $runAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    if ($modeContract.is_m17) {
        $artifact = Join-Path $m17ArtifactRoot "m17-result.json"
        Assert-True (Test-Path -LiteralPath $artifact) "M17 result artifact is missing"
        $witnessCount = @($m17WitnessRows.Keys).Count
        $expectedWitnessCount = @($m17Contract.witnesses).Count
        $testCount = $m17TestRows.Count
        Assert-True ($witnessCount -eq $expectedWitnessCount) "M17 final witness count changed"
        Write-Output "m17_windows_tun status=PASS mode=$Mode witnesses=$witnessCount/$expectedWitnessCount exact_tests=$testCount cleanup=PASS run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) artifact=$artifact"
    } elseif ($Mode -eq "lifecycle") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=foundation foundation=4/4 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "tcp08") {
        Assert-True ($tcpRows -eq 1 -and $tcp08Result -eq "PASS" -and $tcp08CleanupSucceeded) "focused TCP-08 marker prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath (Join-Path $tcp08ArtifactPath "timeline.json")) "focused TCP-08 timeline artifact is missing"
        $tcp08ClientHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output "m15_windows_tun_tcp08 status=PASS tcp08=1/1 cleanup=PASS client_sha256=$tcp08ClientHash run_token=$runIdentity artifact_directory=$tcp08ArtifactPath"
    } elseif ($Mode -eq "tcp") {
        Write-Output "m15_windows_tun_e2e status=PASS profile=tcp tcp=8/8 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "cycles") {
        Write-Output "m15_windows_tun_cycles status=PASS cycles=100/100 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "performance") {
        Write-Output "m15_windows_tun_performance_resource adapter_rx_bytes=$performanceAdapterRxBytes adapter_tx_bytes=$performanceAdapterTxBytes adapter_rx_packets=$performanceAdapterRxPackets adapter_tx_packets=$performanceAdapterTxPackets adapter_rx_errors=$performanceAdapterRxErrors adapter_tx_errors=$performanceAdapterTxErrors adapter_rx_discards=$performanceAdapterRxDiscards adapter_tx_discards=$performanceAdapterTxDiscards tun_accepted_delta=$performanceTunAcceptedDelta cpu_ms_delta=$performanceCpuMilliseconds rss_bytes=$performanceRssBytes handles_peak=$performanceHandlesPeak threads_peak=$performanceThreadsPeak udp_sessions_peak=$performanceUdpSessionsPeak udp_buffered_bytes_peak=$performanceUdpBufferedBytesPeak controller_inflight_peak=$performanceControllerInflightPeak queues=bounded bounds_ring_bytes=8388608 bounds_tcp_flows=8 bounds_tcp_buffer_bytes=4096 bounds_udp_mappings=4 bounds_udp_buffered_bytes=4194304 adapter_churn=$performanceAdapterChurn grace_drain=PASS force_drain=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
        Write-Output "m15_windows_tun_performance status=PASS witnesses=2/2 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
        Write-Output "m16_windows_tun_performance status=PASS proxy=PASS direct=PASS dns=PASS cleanup=PASS candidate_sha=$sha run_id=$runId run_attempt=$runAttempt"
    } elseif ($Mode -eq "network-feasibility") {
        Assert-True ($capabilityRouteRows -eq 2 -and $capabilityTcpRows -eq 4 -and $capabilityUdpRows -eq 4 -and
            $capabilityDnsRows -eq 2 -and $capabilityWindowRows -eq 1 -and $capabilityHardKillRows -eq 1 -and
            $capabilityInterfaceMetric -in @("unchanged", "leased")) "network feasibility marker prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath $capabilityEvidence) "network feasibility evidence is missing"
        Write-Output "m16_windows_network_feasibility status=PASS routes=2/2 tcp_pin=4/4 udp_pin=4/4 dns=2/2 capture_window=1/1 hard_kill=1/1 interface_metric=$capabilityInterfaceMetric cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
    } elseif ($Mode -eq "managed-product") {
        Assert-True ($managedFixedTcpRows -eq 2 -and $managedFixedUdpRows -eq 2 -and
            $managedDynamicTcpRows -eq 1 -and $managedDynamicUdpRows -eq 1 -and
            $managedManualTcpRows -eq 1 -and $managedManualUdpRows -eq 1 -and
            $managedUnpinnedRows -eq 2 -and $managedRouteRows -eq 2 -and
            $managedInterfaceMetric -ceq "unchanged") "managed product marker prerequisites mismatch"
        Assert-True ($managedFilteredPackets.unpinned_tcp -gt 0 -and $managedFilteredPackets.unpinned_udp -gt 0 -and
            $managedFilteredPackets.proxy_tcp -eq 0 -and $managedFilteredPackets.proxy_udp -eq 0 -and
            $managedFilteredPackets.direct_tcp -eq 0 -and $managedFilteredPackets.direct_udp -eq 0 -and
            $managedFilteredPackets.dns_tcp -eq 0 -and $managedFilteredPackets.dns_udp -eq 0) "managed product PktMon prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath $capabilityEvidence) "managed product evidence is missing"
        Write-Output "m16_windows_managed_product status=PASS fixed_tcp=2/2 fixed_udp=2/2 dynamic_tcp=1/1 dynamic_udp=1/1 manual_tcp=1/1 manual_udp=1/1 unpinned=2/2 routes=2/2 interface_metric=unchanged cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
    } elseif ($Mode -eq "hard-kill") {
        Assert-True ($managedHardKillRows -eq 3) "hard-kill marker prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath $capabilityEvidence) "hard-kill evidence is missing"
        Write-Output "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT strict_route_wfp=ABSENT cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
    } elseif ($Mode -eq "full") {
        Assert-True ($foundation -eq 4 -and $tcpRows -eq 8 -and $udpRows -eq 8 -and $cycleRows -eq 100 -and
            $managedDirectTcpRows -eq 1 -and $managedDirectUdpRows -eq 1 -and $managedSystemDnsRows -eq 2 -and
            $managedNetworkChangeRows -eq 3 -and $managedRouteChangeRows -eq 1 -and
            $managedInterfaceChangeRows -eq 1 -and $managedAddressChangeRows -eq 1 -and
            $managedHardKillRows -eq 3) "managed full marker prerequisites mismatch"
        Assert-True (Test-Path -LiteralPath $capabilityEvidence) "managed full evidence is missing"
        Write-Output "m16_windows_tun_full status=PASS m15_transport=16/16 direct_tcp=1/1 direct_udp=1/1 dns=2/2 network_change=3/3 route_change=1/1 interface_change=1/1 address_change=1/1 cycles=100/100 hard_kill=3/3 cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
    } else {
        Write-Output "m15_windows_tun_e2e status=PASS profile=transport functional=16/16 cleanup=PASS sha=$sha run_id=$runId run_attempt=$runAttempt"
    }
}
