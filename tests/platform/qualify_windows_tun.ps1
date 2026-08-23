param(
    [Parameter(Mandatory = $true)]
    # Legacy M15 mode contract: [ValidateSet("lifecycle", "tcp", "udp", "cycles", "full", "performance", "cleanup")]
    [ValidateSet("lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance", "network-feasibility", "managed-product", "hard-kill", "network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full", "cleanup")]
    [string]$Mode,
    [ValidateSet(10, 100, 1000)]
    [int]$NetworkResetCycles = 10,
    [ValidateSet(10, 100, 1000)]
    [int]$RestartCycles = 10,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger,
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

$tcp08ClockOriginUtc = [DateTime]::UtcNow.ToString("o")
$tcp08ClockOriginTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()
$controllerStartedUtc = $tcp08ClockOriginUtc
$m17Modes = @(
    "network-reset", "restart-stress", "fragments", "dual-stack-dns", "udp-policy",
    "scheduler-ring-full"
)
$expectedHyperVVmName = "Windows 10 MSIX packaging environment"
$expectedHyperVVmId = "82e20295-1d30-48e7-a751-e21d35d872d4"
$expectedHyperVCheckpointName = "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9"
$expectedHyperVCheckpointId = "1e570209-faf7-4248-8167-aa0687cdb8cf"

if ($Mode -in $m17Modes -and [string]::IsNullOrWhiteSpace($CandidateTestDirectory)) {
    throw "M17 qualification requires host-built CandidateTestDirectory artifacts"
}

if ($Mode -ne "network-reset" -and $PSBoundParameters.ContainsKey("NetworkResetCycles")) {
    throw "NetworkResetCycles is valid only with network-reset mode"
}
if ($Mode -ne "restart-stress" -and $PSBoundParameters.ContainsKey("RestartCycles")) {
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

function Assert-M17GuestIdentityMarker([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "M17 Windows TUN qualification requires an identity ledger"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.Length -lt 2 -or $item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "M17 identity ledger file boundary is invalid"
    }
    $ledger = Get-Content -LiteralPath $resolved -Raw -Encoding utf8 | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    if ($ledger.schema -ne 1 -or
        $ledger.vm_name -cne $script:expectedHyperVVmName -or
        $ledger.vm_id -cne $script:expectedHyperVVmId -or
        $ledger.checkpoint_name -cne $script:expectedHyperVCheckpointName -or
        $ledger.checkpoint_id -cne $script:expectedHyperVCheckpointId) {
        throw "M17 identity ledger does not name the approved Hyper-V guest"
    }
    return $resolved
}

$m17IdentityMarker = $null
if ($Mode -in $m17Modes) {
    $m17IdentityMarker = Assert-M17GuestIdentityMarker $IdentityLedger
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
$work = if ($Mode -in $m17Modes) {
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
$adapterName = if ($Mode -in $m17Modes) {
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

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Test-UtcRoundTripTimestamp([object]$Value) {
    if ($Value -isnot [string]) { return $false }
    [DateTimeOffset]$parsed = [DateTimeOffset]::MinValue
    return [DateTimeOffset]::TryParseExact(
        $Value,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    ) -and $parsed.Offset -eq [TimeSpan]::Zero
}

function Get-RequiredJsonStrings([string]$Json, [string[]]$Names, [string]$Label) {
    $document = [Text.Json.JsonDocument]::Parse($Json)
    try {
        Assert-True ($document.RootElement.ValueKind -eq [Text.Json.JsonValueKind]::Object) "$Label root is not an object"
        $properties = @($document.RootElement.EnumerateObject())
        $result = [ordered]@{}
        foreach ($name in $Names) {
            $matches = @($properties | Where-Object { $_.Name -ceq $name })
            Assert-True ($matches.Count -eq 1 -and
                $matches[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::String) "$Label property is not one unique JSON string: $name"
            $result[$name] = $matches[0].Value.GetString()
        }
        return $result
    } finally {
        $document.Dispose()
    }
}

function Get-ControllerWorkPaths {
    $paths = @(
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m15-tun-$script:runIdentity"
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-network-$script:runIdentity"
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-product-$script:runIdentity"
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m17-tun-$script:runIdentity"
    )
    return @($paths | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') })
}

function Assert-ClosedJsonProperties([object]$Object, [string[]]$Expected, [string]$Label) {
    Assert-True ($null -ne $Object) "$Label is null"
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    Assert-True (($actual -join "`n") -ceq ($expectedSorted -join "`n")) "$Label property set is invalid"
}

function Get-CanonicalJournalPath([string]$Path, [string]$Label) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path) -and $Path -cmatch '^[A-Za-z]:\\') "$Label is not an absolute local path"
    $canonical = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    Assert-True ($canonical -cmatch '^[A-Za-z]:\\.+' -and
        $canonical.Equals($Path.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) "$Label is not canonical"
    return $canonical
}

function Assert-NotReparsePoint([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label must not be a reparse point"
}

function Initialize-RunIdentityJournalRoot {
    if (-not (Test-Path -LiteralPath $script:runIdentityJournalRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:runIdentityJournalRoot -Force -ErrorAction Stop | Out-Null
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        foreach ($sid in @(
            $currentSid,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        )) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                $allow
            ))
        }
        $security.SetOwner($currentSid)
        Set-Acl -LiteralPath $script:runIdentityJournalRoot -AclObject $security -ErrorAction Stop
    }
    Assert-NotReparsePoint $script:runIdentityJournalRoot "run identity journal root"
    $allowedSids = @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $acl = Get-Acl -LiteralPath $script:runIdentityJournalRoot -ErrorAction Stop
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $writeMask) -ne 0) {
            Assert-True ($allowedSids -contains $rule.IdentityReference.Value) "run identity journal root grants write access outside the closed principal set"
        }
    }
}

function Write-RunIdentityJournal {
    Initialize-RunIdentityJournalRoot
    $journalPath = $script:runIdentityJournalPath
    $pendingPath = "$journalPath.pending"
    Assert-True (-not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $pendingPath)) "run identity journal baseline is not absent"
    $clientPath = [IO.Path]::GetFullPath($script:binary).TrimEnd('\', '/')
    $serverPath = [IO.Path]::GetFullPath($script:serverBinary).TrimEnd('\', '/')
    $productRoot = [IO.Path]::GetFullPath($script:resolvedProductRoot).TrimEnd('\', '/')
    $workPath = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
    $siblingPath = [IO.Path]::GetFullPath($script:siblingDll).TrimEnd('\', '/')
    $controllerPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
    $serverRequired = $script:Mode -in @(
        "tcp", "tcp08", "udp", "full", "performance", "network-reset", "restart-stress",
        "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full"
    )
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.cleanup-identity.v1"
        run_token = $script:runIdentity
        mode = $script:Mode
        identity_sha256 = if ($script:Mode -in $script:m17Modes) {
            (Get-FileHash -LiteralPath $script:m17IdentityMarker -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
        work_path = $workPath
        product_root = $productRoot
        client_binary_path = $clientPath
        client_binary_sha256 = if ($script:clientBinaryExplicit) { (Get-FileHash -LiteralPath $clientPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        client_binary_explicit = [bool]$script:clientBinaryExplicit
        server_binary_path = $serverPath
        server_binary_sha256 = if ($script:serverBinaryExplicit) { (Get-FileHash -LiteralPath $serverPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        server_binary_explicit = [bool]$script:serverBinaryExplicit
        server_required = $serverRequired
        sibling_dll_path = $siblingPath
        dll_ownership = "owned"
        dll_marker_path = [IO.Path]::GetFullPath($script:dllJournal).TrimEnd('\', '/')
        expected_dll_sha256 = $script:expectedDllHash.ToLowerInvariant()
        controller_path = $controllerPath
        controller_sha256 = (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $json = $document | ConvertTo-Json -Depth 4 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $stream = [IO.FileStream]::new($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Move-Item -LiteralPath $pendingPath -Destination $journalPath -ErrorAction Stop
}

function Read-RunIdentityJournal([string]$Path, [string[]]$ExpectedWorks) {
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "run identity journal is missing"
    Assert-NotReparsePoint $Path "run identity journal"
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($item.Length -gt 0 -and $item.Length -le 65536) "run identity journal size is invalid"
    $document = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    Assert-ClosedJsonProperties $document @(
        "schema", "run_token", "mode", "identity_sha256", "work_path", "product_root",
        "client_binary_path", "client_binary_sha256", "client_binary_explicit",
        "server_binary_path", "server_binary_sha256", "server_binary_explicit", "server_required",
        "sibling_dll_path", "dll_ownership", "dll_marker_path", "expected_dll_sha256",
        "controller_path", "controller_sha256"
    ) "run identity journal"
    Assert-True ($document.schema -ceq "ferrum2.windows-tun.cleanup-identity.v1" -and
        $document.run_token -ceq $script:runIdentity) "run identity journal schema/token mismatch"
    Assert-True ($document.mode -in @(
        "lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance",
        "network-feasibility", "managed-product", "hard-kill", "network-reset",
        "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full"
    )) "run identity journal mode is invalid"
    if ($document.mode -in $script:m17Modes) {
        Assert-True ([string]$document.identity_sha256 -cmatch '^[0-9a-f]{64}$') "M17 run identity journal hash is invalid"
    } else {
        Assert-True ($null -eq $document.identity_sha256) "legacy run identity journal unexpectedly has an M17 identity hash"
    }
    $workPath = Get-CanonicalJournalPath ([string]$document.work_path) "journal work_path"
    Assert-True (@($ExpectedWorks | Where-Object { $_.Equals($workPath, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1) "run identity journal work path is outside the token scope"
    $productRoot = Get-CanonicalJournalPath ([string]$document.product_root) "journal product_root"
    $clientPath = Get-CanonicalJournalPath ([string]$document.client_binary_path) "journal client_binary_path"
    $serverPath = Get-CanonicalJournalPath ([string]$document.server_binary_path) "journal server_binary_path"
    $siblingPath = Get-CanonicalJournalPath ([string]$document.sibling_dll_path) "journal sibling_dll_path"
    $markerPath = Get-CanonicalJournalPath ([string]$document.dll_marker_path) "journal dll_marker_path"
    Assert-True ((Split-Path -Leaf $clientPath) -ceq "ferrum2-client.exe" -and
        (Split-Path -Leaf $serverPath) -ceq "ferrum2-server.exe") "run identity journal executable leaf is invalid"
    Assert-True ($siblingPath.Equals((Join-Path (Split-Path -Parent $clientPath) "wintun.dll"), [StringComparison]::OrdinalIgnoreCase)) "run identity journal sibling DLL derivation mismatch"
    Assert-True ($document.dll_ownership -in @("owned", "borrowed")) "run identity journal DLL ownership classification is invalid"
    Assert-True ($markerPath.Equals((Join-Path $workPath "owned-wintun-dll.txt"), [StringComparison]::OrdinalIgnoreCase)) "run identity journal DLL marker derivation mismatch"
    Assert-True ($document.expected_dll_sha256 -ceq $script:expectedDllHash.ToLowerInvariant()) "run identity journal DLL hash mismatch"
    foreach ($hashField in @("client_binary_sha256", "server_binary_sha256", "controller_sha256")) {
        $hash = $document.$hashField
        Assert-True ($null -eq $hash -or [string]$hash -cmatch '^[0-9a-f]{64}$') "run identity journal $hashField is invalid"
    }
    Assert-True ($document.client_binary_explicit -is [bool] -and
        $document.server_binary_explicit -is [bool] -and $document.server_required -is [bool]) "run identity journal boolean field is invalid"
    $expectedServerRequired = $document.mode -in @(
        "tcp", "tcp08", "udp", "full", "performance", "network-reset", "restart-stress",
        "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full"
    )
    Assert-True ($document.server_required -eq $expectedServerRequired) "run identity journal server requirement is inconsistent with mode"
    if (-not $document.client_binary_explicit) {
        Assert-True ($clientPath.Equals((Join-Path $productRoot "target\debug\ferrum2-client.exe"), [StringComparison]::OrdinalIgnoreCase)) "default client path escaped product root"
    } else {
        Assert-True ($null -ne $document.client_binary_sha256) "explicit client path lacks an identity hash"
    }
    if (-not $document.server_binary_explicit) {
        Assert-True ($serverPath.Equals((Join-Path $productRoot "target\debug\ferrum2-server.exe"), [StringComparison]::OrdinalIgnoreCase)) "default server path escaped product root"
    } else {
        Assert-True ($null -ne $document.server_binary_sha256) "explicit server path lacks an identity hash"
    }
    foreach ($pair in @(
        @($clientPath, $document.client_binary_sha256, "client"),
        @($serverPath, $document.server_binary_sha256, "server")
    )) {
        Assert-NotReparsePoint $pair[0] "journaled $($pair[2]) binary"
        if ((Test-Path -LiteralPath $pair[0] -PathType Leaf) -and $null -ne $pair[1]) {
            Assert-True ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$pair[1]) "journaled $($pair[2]) binary hash changed"
        }
    }
    $controllerPath = Get-CanonicalJournalPath ([string]$document.controller_path) "journal controller_path"
    Assert-NotReparsePoint $productRoot "journaled product root"
    Assert-NotReparsePoint $controllerPath "journaled controller"
    Assert-True ((Test-Path -LiteralPath $controllerPath -PathType Leaf) -and
        (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$document.controller_sha256) "journaled controller identity changed"
    if ($script:clientBinaryExplicit) { Assert-True ($clientPath.Equals($script:binary, [StringComparison]::OrdinalIgnoreCase)) "cleanup client path does not match journal" }
    if ($script:serverBinaryExplicit) { Assert-True ($serverPath.Equals($script:serverBinary, [StringComparison]::OrdinalIgnoreCase)) "cleanup server path does not match journal" }
    if (-not [string]::IsNullOrWhiteSpace($script:ProductRoot)) { Assert-True ($productRoot.Equals($script:resolvedProductRoot, [StringComparison]::OrdinalIgnoreCase)) "cleanup product root does not match journal" }
    return [pscustomobject]@{
        WorkPath = $workPath
        ProductRoot = $productRoot
        ClientPath = $clientPath
        ServerPath = $serverPath
        SiblingDllPath = $siblingPath
        DllMarkerPath = $markerPath
        Document = $document
    }
}

function Write-OwnedSiblingDllIntent {
    Assert-True (Test-Path -LiteralPath $script:runIdentityJournalPath -PathType Leaf) "run identity journal must precede DLL ownership intent"
    Assert-True ($script:runJournalIdentity -and $script:runJournalIdentity.Document.dll_ownership -ceq "owned") "borrowed DLL identity cannot create an ownership intent"
    Assert-True (-not (Test-Path -LiteralPath $script:dllJournal)) "DLL ownership intent baseline is not absent"
    Assert-True (-not (Test-Path -LiteralPath $script:siblingDll)) "DLL ownership intent cannot claim a pre-existing sibling DLL"
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.owned-sibling-dll.v1"
        run_token = $script:runIdentity
        work_path = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
        sibling_dll_path = [IO.Path]::GetFullPath($script:siblingDll).TrimEnd('\', '/')
        sha256 = $script:expectedDllHash.ToLowerInvariant()
    }
    $json = $document | ConvertTo-Json -Depth 3 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $stream = [IO.FileStream]::new($script:dllJournal, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-OwnedSiblingDllIntent([string]$Path, [object]$Identity) {
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "DLL ownership intent is missing"
    Assert-NotReparsePoint $Path "DLL ownership intent"
    $document = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 3 -ErrorAction Stop
    Assert-ClosedJsonProperties $document @("schema", "run_token", "work_path", "sibling_dll_path", "sha256") "DLL ownership intent"
    Assert-True ($document.schema -ceq "ferrum2.windows-tun.owned-sibling-dll.v1" -and
        $document.run_token -ceq $script:runIdentity -and
        $document.sha256 -ceq $script:expectedDllHash.ToLowerInvariant()) "DLL ownership intent schema/token/hash mismatch"
    $intentWork = Get-CanonicalJournalPath ([string]$document.work_path) "DLL intent work_path"
    $intentDll = Get-CanonicalJournalPath ([string]$document.sibling_dll_path) "DLL intent sibling_dll_path"
    Assert-True ($intentWork.Equals($Identity.WorkPath, [StringComparison]::OrdinalIgnoreCase) -and
        $intentDll.Equals($Identity.SiblingDllPath, [StringComparison]::OrdinalIgnoreCase) -and
        $Path.Equals($Identity.DllMarkerPath, [StringComparison]::OrdinalIgnoreCase)) "DLL ownership intent does not match run identity"
    return $document
}

function Remove-OwnedSiblingDll([object]$Identity) {
    [void](Read-OwnedSiblingDllIntent $Identity.DllMarkerPath $Identity)
    if (Test-Path -LiteralPath $Identity.SiblingDllPath) {
        Assert-NotReparsePoint $Identity.SiblingDllPath "owned sibling DLL"
        Assert-True ((Get-FileHash -LiteralPath $Identity.SiblingDllPath -Algorithm SHA256).Hash -ceq $script:expectedDllHash) "owned sibling DLL hash mismatch"
        Remove-Item -LiteralPath $Identity.SiblingDllPath -Force -ErrorAction Stop
    }
    Assert-True (-not (Test-Path -LiteralPath $Identity.SiblingDllPath)) "owned sibling DLL residue"
    Remove-Item -LiteralPath $Identity.DllMarkerPath -Force -ErrorAction Stop
    $script:createdSiblingDll = $false
}

function Get-ExactRunProcesses([string]$WorkPath, [string[]]$Executables = @($script:binary, $script:serverBinary)) {
    $canonicalWork = [IO.Path]::GetFullPath($WorkPath).TrimEnd('\', '/')
    $workPrefix = $canonicalWork + [IO.Path]::DirectorySeparatorChar
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and
        $executables -contains $_.ExecutablePath -and
        $_.CommandLine -and
        $_.CommandLine.IndexOf("--config", [StringComparison]::Ordinal) -ge 0 -and
        $_.CommandLine.IndexOf($workPrefix, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}

function Get-M17NetworkResetRouteIntentPath(
    [string]$JournalPath = $script:m17NetworkMutationJournal
) {
    return Join-Path $JournalPath "network-reset-route.json"
}

function Write-M17DurableMutationIntent([string]$Path, [System.Collections.IDictionary]$Document) {
    if (-not (Test-Path -LiteralPath $script:m17NetworkMutationJournal -PathType Container)) {
        New-Item -ItemType Directory -Path $script:m17NetworkMutationJournal -ErrorAction Stop | Out-Null
    }
    Assert-NotReparsePoint $script:m17NetworkMutationJournal "M17 network mutation journal directory"
    $parent = [IO.Path]::GetFullPath((Split-Path -Parent $Path)).TrimEnd('\', '/')
    $expectedParent = [IO.Path]::GetFullPath($script:m17NetworkMutationJournal).TrimEnd('\', '/')
    Assert-True ($parent.Equals($expectedParent, [StringComparison]::OrdinalIgnoreCase)) "M17 mutation intent escaped its journal directory"
    $pendingPath = "$Path.pending"
    Assert-True (-not (Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $pendingPath)) "M17 mutation intent baseline is not absent"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Document | ConvertTo-Json -Compress -Depth 4) + "`n")
    Assert-True ($bytes.Length -le 4096) "M17 mutation intent exceeded its fixed boundary"
    $stream = [IO.FileStream]::new($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Move-Item -LiteralPath $pendingPath -Destination $Path -ErrorAction Stop
}

function Read-M17MutationIntent(
    [string]$Path,
    [string]$Schema,
    [string[]]$Properties,
    [string]$ExpectedWorkPath = $script:work,
    [string[]]$ExpectedSourceMode = @("network-reset")
) {
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "M17 mutation intent is missing"
    Assert-NotReparsePoint $Path "M17 mutation intent"
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($item.Length -gt 1 -and $item.Length -le 4096) "M17 mutation intent size is invalid"
    $bytes = [IO.File]::ReadAllBytes($Path)
    Assert-True ($bytes[$bytes.Length - 1] -eq 10 -and
        -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf)) "M17 mutation intent encoding is invalid"
    $document = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json -Depth 4 -ErrorAction Stop
    Assert-ClosedJsonProperties $document $Properties "M17 mutation intent"
    Assert-True ($document.schema -ceq $Schema -and $document.run_token -ceq $script:runIdentity -and
        $ExpectedSourceMode -ccontains [string]$document.source_mode -and
        (Get-CanonicalJournalPath ([string]$document.work_path) "M17 mutation intent work_path").Equals(
            (Get-CanonicalJournalPath $ExpectedWorkPath "M17 expected mutation work_path"),
            [StringComparison]::OrdinalIgnoreCase
        )) "M17 mutation intent identity is invalid"
    return $document
}

function Read-M17UdpFirewallMutationIntent(
    [string]$Path,
    [string]$ExpectedWorkPath = $script:work,
    [string]$JournalPath = $script:m17NetworkMutationJournal
) {
    $document = Read-M17MutationIntent $Path "ferrum2.windows-tun.m17-udp-firewall-intent.v1" @(
        "schema", "run_token", "source_mode", "work_path", "rule_name",
        "local_address", "remote_address", "protocol", "direction", "action",
        "local_only_mapping", "program_path"
    ) $ExpectedWorkPath @("udp-policy", "scheduler-ring-full")
    $expectedPath = Join-Path $JournalPath "udp-firewall.json"
    $expectedRuleName = "Ferrum2-M17-UDP-$($script:runIdentity)"
    Assert-True ([IO.Path]::GetFullPath($Path).Equals([IO.Path]::GetFullPath($expectedPath), [StringComparison]::OrdinalIgnoreCase) -and
        $document.rule_name -ceq $expectedRuleName -and
        $document.local_address -ceq "198.18.0.2" -and
        $document.remote_address -ceq "Any" -and
        $document.protocol -ceq "UDP" -and $document.direction -ceq "Inbound" -and
        $document.action -ceq "Allow" -and
        $document.local_only_mapping -is [bool] -and
        $document.local_only_mapping -and
        $document.program_path -is [string] -and
        [IO.Path]::GetFullPath([string]$document.program_path).Equals(
            $script:controllerProgram,
            [StringComparison]::OrdinalIgnoreCase
        )) "M17 UDP firewall mutation intent values are invalid"
    return $document
}

function Read-M17NetworkResetRouteMutationIntent(
    [string]$Path,
    [string]$ExpectedWorkPath = $script:work,
    [string]$JournalPath = $script:m17NetworkMutationJournal
) {
    $document = Read-M17MutationIntent $Path "ferrum2.windows-tun.m17-network-reset-route-intent.v1" @(
        "schema", "run_token", "source_mode", "work_path", "interface_index",
        "destination_prefix", "next_hop", "route_metrics"
    ) $ExpectedWorkPath @("network-reset")
    $expectedPath = Get-M17NetworkResetRouteIntentPath $JournalPath
    Assert-True ([IO.Path]::GetFullPath($Path).Equals([IO.Path]::GetFullPath($expectedPath), [StringComparison]::OrdinalIgnoreCase) -and
        $document.interface_index -is [long] -and $document.interface_index -ge 1 -and
        $document.interface_index -le [uint32]::MaxValue -and
        $document.destination_prefix -ceq "203.0.113.254/32" -and
        @($document.route_metrics).Count -eq 2 -and
        @($document.route_metrics | Where-Object { $_ -isnot [long] -or $_ -notin @(4094, 4095) }).Count -eq 0 -and
        @($document.route_metrics | Sort-Object -Unique).Count -eq 2) "M17 network-reset route mutation intent values are invalid"
    $nextHop = $null
    Assert-True ([Net.IPAddress]::TryParse([string]$document.next_hop, [ref]$nextHop) -and
        $nextHop.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        -not $nextHop.Equals([Net.IPAddress]::Any)) "M17 network-reset route next hop is invalid"
    return $document
}

function Get-M17OwnedUdpFirewallRule([object]$Intent) {
    $rules = @(Get-NetFirewallRule -Name ([string]$Intent.rule_name) -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    Assert-True ($rules.Count -le 1) "M17 UDP firewall rule ownership is ambiguous"
    if ($rules.Count -eq 0) { return @() }
    $rule = $rules[0]
    $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $applicationFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $localAddresses = @($addressFilters | ForEach-Object { @($_.LocalAddress) })
    $remoteAddresses = @($addressFilters | ForEach-Object { @($_.RemoteAddress) })
    $protocols = @($portFilters | ForEach-Object { [string]$_.Protocol })
    Assert-True ($rule.Name -ceq [string]$Intent.rule_name -and
        $rule.DisplayName -ceq [string]$Intent.rule_name -and
        [string]$rule.Enabled -ceq "True" -and [string]$rule.Direction -ceq "Inbound" -and
        [string]$rule.Action -ceq "Allow" -and [string]$rule.Profile -ceq "Any" -and
        -not [bool]$rule.LooseSourceMapping -and [bool]$rule.LocalOnlyMapping -and
        $addressFilters.Count -eq 1 -and $portFilters.Count -eq 1 -and $applicationFilters.Count -eq 1 -and
        $localAddresses.Count -eq 1 -and $localAddresses[0] -ceq "198.18.0.2" -and
        $remoteAddresses.Count -eq 1 -and $remoteAddresses[0] -ceq "Any" -and
        $protocols.Count -eq 1 -and $protocols[0] -in @("UDP", "17") -and
        [IO.Path]::GetFullPath([string]$applicationFilters[0].Program).Equals(
            $script:controllerProgram,
            [StringComparison]::OrdinalIgnoreCase
        )) "M17 UDP firewall rule ownership changed"
    return @($rule)
}

function Enable-M17UdpFirewallAdmission {
    Assert-True (@("udp-policy", "scheduler-ring-full") -ccontains $script:Mode) "M17 UDP firewall exception is restricted to UDP live modes"
    Assert-True (-not (Get-NetFirewallRule -Name $script:m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 UDP firewall rule baseline is not absent"
    $intentPath = Join-Path $script:m17NetworkMutationJournal "udp-firewall.json"
    Write-M17DurableMutationIntent $intentPath ([ordered]@{
        schema = "ferrum2.windows-tun.m17-udp-firewall-intent.v1"
        run_token = $script:runIdentity
        source_mode = $script:Mode
        work_path = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
        rule_name = $script:m17UdpFirewallRuleName
        local_address = "198.18.0.2"
        remote_address = "Any"
        protocol = "UDP"
        direction = "Inbound"
        action = "Allow"
        local_only_mapping = $true
        program_path = $script:controllerProgram
    })
    New-NetFirewallRule `
        -Name $script:m17UdpFirewallRuleName `
        -DisplayName $script:m17UdpFirewallRuleName `
        -PolicyStore ActiveStore `
        -Enabled True `
        -Profile Any `
        -Direction Inbound `
        -Action Allow `
        -Protocol UDP `
        -LocalAddress "198.18.0.2" `
        -RemoteAddress Any `
        -Program $script:controllerProgram `
        -LocalOnlyMapping $true `
        -EdgeTraversalPolicy Block | Out-Null
    $intent = Read-M17UdpFirewallMutationIntent $intentPath
    Assert-True (@(Get-M17OwnedUdpFirewallRule $intent).Count -eq 1) "M17 UDP firewall rule readback failed"
}

function Complete-M17MutationIntent([string]$Path) {
    Assert-NotReparsePoint $Path "M17 completed mutation intent"
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (-not (Test-Path -LiteralPath $Path)) "M17 mutation intent was not removed"
}

function Restore-M17NetworkMutationJournal([string]$WorkPath, [string]$JournalPath) {
    $canonicalWork = Get-CanonicalJournalPath $WorkPath "M17 recovery work_path"
    $canonicalJournal = Get-CanonicalJournalPath $JournalPath "M17 recovery journal_path"
    $allowedWorks = @(Get-ControllerWorkPaths)
    Assert-True (@($allowedWorks | Where-Object { $_.Equals($canonicalWork, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1) "M17 recovery work escaped the run-token scope"
    Assert-True ($canonicalJournal.Equals((Join-Path $canonicalWork "m17-network-mutations"), [StringComparison]::OrdinalIgnoreCase)) "M17 recovery journal derivation is invalid"
    if (-not (Test-Path -LiteralPath $canonicalJournal)) { return }
    Assert-NotReparsePoint $canonicalWork "M17 recovery work directory"
    Assert-NotReparsePoint $canonicalJournal "M17 network mutation journal directory"
    $intentNames = @("network-reset-route.json", "udp-firewall.json")
    $allowedNames = @($intentNames + @($intentNames | ForEach-Object { "$_.pending" }))
    $entries = @(Get-ChildItem -LiteralPath $canonicalJournal -Force -ErrorAction Stop)
    Assert-True (@($entries | Where-Object { $_.PSIsContainer -or $allowedNames -notcontains $_.Name }).Count -eq 0) "M17 network mutation journal contains an unknown entry"
    foreach ($name in $intentNames) {
        $path = Join-Path $canonicalJournal $name
        $pendingPath = "$path.pending"
        if (Test-Path -LiteralPath $pendingPath) {
            Assert-True (-not (Test-Path -LiteralPath $path)) "completed and pending M17 mutation intents coexist"
            Assert-NotReparsePoint $pendingPath "pending M17 mutation intent"
            Remove-Item -LiteralPath $pendingPath -Force -ErrorAction Stop
        }
    }
    $firewallPath = Join-Path $canonicalJournal "udp-firewall.json"
    if (Test-Path -LiteralPath $firewallPath) {
        $intent = Read-M17UdpFirewallMutationIntent $firewallPath $canonicalWork $canonicalJournal
        $owned = @(Get-M17OwnedUdpFirewallRule $intent)
        if ($owned.Count -eq 1) { $owned[0] | Remove-NetFirewallRule -ErrorAction Stop }
        Assert-True (@(Get-NetFirewallRule -Name ([string]$intent.rule_name) -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 journaled UDP firewall rule remained"
        Complete-M17MutationIntent $firewallPath
    }
    $routePath = Get-M17NetworkResetRouteIntentPath $canonicalJournal
    if (Test-Path -LiteralPath $routePath) {
        $intent = Read-M17NetworkResetRouteMutationIntent $routePath $canonicalWork $canonicalJournal
        $owned = @(Get-NetRoute -InterfaceIndex ([int]$intent.interface_index) `
            -DestinationPrefix ([string]$intent.destination_prefix) -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ceq [string]$intent.next_hop -and [uint32]$_.RouteMetric -in @($intent.route_metrics) })
        Assert-True ($owned.Count -le 1) "M17 journaled network-reset route ownership is ambiguous"
        if ($owned.Count -eq 1) { Remove-NetRoute -InputObject $owned[0] -Confirm:$false -ErrorAction Stop }
        Assert-True (@(Get-NetRoute -InterfaceIndex ([int]$intent.interface_index) `
            -DestinationPrefix ([string]$intent.destination_prefix) -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ceq [string]$intent.next_hop }).Count -eq 0) "M17 journaled network-reset route remained"
        Complete-M17MutationIntent $routePath
    }
    Assert-True (@(Get-ChildItem -LiteralPath $canonicalJournal -Force -ErrorAction Stop).Count -eq 0) "M17 network mutation journal was not drained"
    Remove-Item -LiteralPath $canonicalJournal -Force -ErrorAction Stop
    Assert-True (-not (Test-Path -LiteralPath $canonicalJournal)) "M17 network mutation journal directory remained"
}

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
    if ($cleanupIdentity -and $cleanupIdentity.Document.mode -in $m17Modes) {
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
    [void](Assert-M17GuestIdentityMarker $artifactLedgerPath)
    $artifactIdentityHash = (Get-FileHash -LiteralPath $artifactLedgerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True (Test-Path -LiteralPath $artifactResultPath -PathType Leaf) "external cleanup requires the M17 result artifact"
    Assert-NotReparsePoint $artifactResultPath "M17 result artifact"
    $artifactResultRaw = Get-Content -LiteralPath $artifactResultPath -Raw -Encoding utf8
    $artifactResultStrings = Get-RequiredJsonStrings $artifactResultRaw @(
        "schema", "status", "mode", "run_token", "approved_vm_name", "approved_vm_id",
        "approved_checkpoint_name", "approved_checkpoint_id", "identity_sha256", "controller_sha256",
        "started_utc", "finished_utc"
    ) "M17 result artifact"
    $artifactResult = $artifactResultRaw | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    Assert-ClosedJsonProperties $artifactResult @(
        "schema", "status", "mode", "run_token", "network_reset_cycles", "restart_cycles", "approved_vm_name",
        "approved_vm_id", "approved_checkpoint_name", "approved_checkpoint_id", "guest_build",
        "identity_sha256", "candidate_sha", "client_sha256", "server_sha256", "controller_sha256",
        "wintun_zip_sha256", "wintun_dll_sha256", "test_binaries", "started_utc", "finished_utc",
        "fixtures", "processes", "live_checks", "deterministic_tests", "witnesses", "counters_before",
        "counters_after", "cleanup", "failure"
    ) "M17 result artifact"
    Assert-True ($artifactResult.schema -is [string] -and
        $artifactResult.status -is [string] -and $artifactResult.mode -is [string] -and
        $artifactResult.run_token -is [string] -and $artifactResult.approved_vm_name -is [string] -and
        $artifactResult.approved_vm_id -is [string] -and $artifactResult.approved_checkpoint_name -is [string] -and
        $artifactResult.approved_checkpoint_id -is [string] -and $artifactResult.identity_sha256 -is [string] -and
        $artifactResult.controller_sha256 -is [string] -and
        $artifactResult.schema -ceq "ferrum2.windows-tun.m17-result.v1" -and
        @("pass", "fail") -ccontains $artifactResult.status -and $m17Modes -ccontains $artifactResult.mode -and
        $artifactResult.run_token -ceq $script:runIdentity -and
        $artifactResult.approved_vm_name -ceq $script:expectedHyperVVmName -and
        $artifactResult.approved_vm_id -ceq $script:expectedHyperVVmId -and
        $artifactResult.approved_checkpoint_name -ceq $script:expectedHyperVCheckpointName -and
        $artifactResult.approved_checkpoint_id -ceq $script:expectedHyperVCheckpointId -and
        $artifactResult.identity_sha256 -ceq $artifactIdentityHash -and
        $artifactResult.controller_sha256 -ceq (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -and
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
    Assert-True ($Mode -in $m17Modes) "CandidateTestDirectory is valid only with an M17 mode"
    $candidateTestDirectoryItem = Get-Item -LiteralPath $CandidateTestDirectory -Force -ErrorAction Stop
    Assert-True $candidateTestDirectoryItem.PSIsContainer "CandidateTestDirectory must be a directory"
    Assert-True (($candidateTestDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "CandidateTestDirectory must not be a reparse point"
    $resolvedCandidateTestDirectory = [IO.Path]::GetFullPath($candidateTestDirectoryItem.FullName)
    foreach ($name in @("ferrum2-client-tests.exe", "ferrum2-tun-tests.exe", "ferrum2-wintun-tests.exe")) {
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
$m17ExpectedWarning = $null
$m17ExpectedWarningCount = $null

function Get-Tcp08ElapsedMilliseconds([long]$MonotonicTimestamp) {
    return [Math]::Round(
        (($MonotonicTimestamp - $script:tcp08ClockOriginTimestamp) * 1000.0) / [Diagnostics.Stopwatch]::Frequency,
        3
    )
}

function Get-Tcp08MonotonicSample {
    $timestamp = [Diagnostics.Stopwatch]::GetTimestamp()
    return [ordered]@{
        monotonic_ticks = $timestamp
        elapsed_ms = Get-Tcp08ElapsedMilliseconds $timestamp
    }
}

function Add-Tcp08EventAtTimestamp([string]$Name, [long]$MonotonicTimestamp, [object]$Details = $null) {
    if (-not $script:tcp08Enabled) { return }
    $script:tcp08Events.Add([ordered]@{
        ordinal = $script:tcp08Events.Count + 1
        name = $Name
        monotonic_ticks = $MonotonicTimestamp
        elapsed_ms = Get-Tcp08ElapsedMilliseconds $MonotonicTimestamp
        details = $Details
    })
}

function Add-Tcp08Event([string]$Name, [object]$Details = $null) {
    Add-Tcp08EventAtTimestamp $Name ([Diagnostics.Stopwatch]::GetTimestamp()) $Details
}

function Write-Tcp08Json([string]$Name, [object]$Value) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $path = Join-Path $script:tcp08ArtifactPath $Name
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
}

function Get-Tcp08ProcessSnapshot {
    $captured = Get-Tcp08MonotonicSample
    $controller = Get-Process -Id $PID -ErrorAction Stop
    $products = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and @($script:binary, $script:serverBinary) -contains $_.ExecutablePath
    } | ForEach-Object {
        [ordered]@{
            process_id = [uint32]$_.ProcessId
            parent_process_id = [uint32]$_.ParentProcessId
            name = [string]$_.Name
            executable_path = [string]$_.ExecutablePath
            creation_date = if ($_.CreationDate) { ([DateTime]$_.CreationDate).ToUniversalTime().ToString("o") } else { $null }
        }
    })
    return [ordered]@{
        captured_monotonic_ticks = $captured.monotonic_ticks
        captured_elapsed_ms = $captured.elapsed_ms
        controller = [ordered]@{
            process_id = [uint32]$PID
            name = $controller.ProcessName
            start_time_utc = $controller.StartTime.ToUniversalTime().ToString("o")
        }
        products = $products
    }
}

function Get-Tcp08ResidueNetworkSnapshot {
    $captured = Get-Tcp08MonotonicSample
    $testAddresses = @(
        "198.18.0.2", "fd00::2", "192.0.2.201", "2001:db8::202", "192.0.2.203",
        "2001:db8::204", "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208",
        "192.0.2.250", "192.0.2.241", "192.0.2.242", "2001:db8::241"
    )
    $adapterNames = @($script:adapterName, $script:managedAutoAdapterName, $script:managedManualAdapterName)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.Name
    } | ForEach-Object {
        [ordered]@{ name = $_.Name; interface_index = [int]$_.ifIndex; status = [string]$_.Status }
    })
    $addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.InterfaceAlias -or $testAddresses -contains $_.IPAddress
    } | ForEach-Object {
        [ordered]@{
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_family = [string]$_.AddressFamily
            ip_address = [string]$_.IPAddress
            prefix_length = [int]$_.PrefixLength
            address_state = [string]$_.AddressState
        }
    })
    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.InterfaceAlias -or
        $testAddresses -contains ([string]$_.DestinationPrefix).Split('/')[0]
    } | ForEach-Object {
        [ordered]@{
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            destination_prefix = [string]$_.DestinationPrefix
            next_hop = [string]$_.NextHop
            route_metric = [int]$_.RouteMetric
        }
    })
    return [ordered]@{
        captured_monotonic_ticks = $captured.monotonic_ticks
        captured_elapsed_ms = $captured.elapsed_ms
        adapters = $adapters
        addresses = $addresses
        routes = $routes
    }
}

function Initialize-Tcp08Artifacts {
    if (-not $script:tcp08Enabled) { return }
    $artifactFullPath = [IO.Path]::GetFullPath($script:tcp08ArtifactPath).TrimEnd('\', '/')
    $workFullPath = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
    $workPrefix = $workFullPath + [IO.Path]::DirectorySeparatorChar
    Assert-True (-not $artifactFullPath.Equals($workFullPath, [StringComparison]::OrdinalIgnoreCase) -and
        -not $artifactFullPath.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase)) "ArtifactDirectory must be outside the disposable run work directory"
    $script:tcp08ArtifactPath = $artifactFullPath
    if (Test-Path -LiteralPath $artifactFullPath) {
        $ownedArtifactNames = @($script:tcp08RequiredJsonNames) + @(
            "artifact-hashes.json", "client.stdout.log", "client.stderr.log",
            "server.stdout.log", "server.stderr.log"
        )
        $ownedBaseline = @(Get-ChildItem -LiteralPath $artifactFullPath -Force | Where-Object {
            $ownedArtifactNames -contains $_.Name
        })
        Assert-True ($ownedBaseline.Count -eq 0) "ArtifactDirectory already contains controller-owned evidence"
    } else {
        New-Item -ItemType Directory -Path $artifactFullPath | Out-Null
    }
    $script:tcp08ArtifactInitialized = $true
    Add-Tcp08Event "vm_test_started" ([ordered]@{
        controller_started_utc = $script:controllerStartedUtc
        clock_origin_timestamp = $script:tcp08ClockOriginTimestamp
    })
    foreach ($name in @("client.stdout.log", "client.stderr.log", "server.stdout.log", "server.stderr.log")) {
        New-Item -ItemType File -Path (Join-Path $artifactFullPath $name) -ErrorAction Stop | Out-Null
    }
    foreach ($name in @("controller.stdout.log", "controller.stderr.log")) {
        Assert-True (Test-Path -LiteralPath (Join-Path $artifactFullPath $name) -PathType Leaf) "outer pwsh redirection must create $name before controller startup"
    }
    try { Write-Tcp08Json "process-before.json" (Get-Tcp08ProcessSnapshot) }
    catch {
        Write-Tcp08Json "process-before.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "process-before"
            error_type = $_.Exception.GetType().FullName
        })
        throw
    }
    try { Write-Tcp08Json "network-before.json" (Get-Tcp08ResidueNetworkSnapshot) }
    catch {
        Write-Tcp08Json "network-before.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "network-before"
            error_type = $_.Exception.GetType().FullName
        })
        throw
    }
}

function Write-Tcp08BinaryEvidence([string]$WintunDll) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    Assert-True (Test-Path -LiteralPath $script:binary) "client binary is missing"
    Assert-True (Test-Path -LiteralPath $script:serverBinary) "server binary is missing"
    $controllerPath = $MyInvocation.ScriptName
    if ([string]::IsNullOrWhiteSpace($controllerPath)) { $controllerPath = Join-Path $script:PSScriptRoot "qualify_windows_tun.ps1" }
    Write-Tcp08Json "binary-hashes.json" ([ordered]@{
        client = [ordered]@{
            path = $script:binary
            sha256 = (Get-FileHash -LiteralPath $script:binary -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $script:binary).Length
            explicit = $script:clientBinaryExplicit
        }
        server = [ordered]@{
            path = $script:serverBinary
            sha256 = (Get-FileHash -LiteralPath $script:serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $script:serverBinary).Length
            explicit = $script:serverBinaryExplicit
        }
        controller = [ordered]@{
            path = $controllerPath
            sha256 = (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        runtime_library = [ordered]@{
            explicit = [bool]$script:runtimeLibraryDirectoryExplicit
            directory = $script:resolvedRuntimeLibraryDirectory
            vcruntime140_dll = [ordered]@{
                path = $script:runtimeVcruntimePath
                bytes = $script:runtimeVcruntimeBytes
                sha256 = $script:runtimeVcruntimeSha256
            }
        }
        wintun_zip = [ordered]@{ path = $script:zip; sha256 = $script:expectedZipHash.ToLowerInvariant() }
        wintun_dll = [ordered]@{ path = $WintunDll; sha256 = $script:expectedDllHash.ToLowerInvariant() }
    })
}

function Write-Tcp08Metadata([string]$Target, [int]$TargetPort, [int]$GatePort, [int]$ServerPort, [int]$MetricsPort) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    Write-Tcp08Json "metadata.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-metadata.v1"
        mode = $script:Mode
        run_token = $script:runIdentity
        controller_started_utc = $script:controllerStartedUtc
        product_root = $script:resolvedProductRoot
        client_binary_explicit = $script:clientBinaryExplicit
        server_binary_explicit = $script:serverBinaryExplicit
        runtime_library = [ordered]@{
            explicit = [bool]$script:runtimeLibraryDirectoryExplicit
            directory = $script:resolvedRuntimeLibraryDirectory
            vcruntime140_dll = [ordered]@{
                path = $script:runtimeVcruntimePath
                bytes = $script:runtimeVcruntimeBytes
                sha256 = $script:runtimeVcruntimeSha256
            }
        }
        artifact_directory = $script:tcp08ArtifactPath
        cleanup_identity = [ordered]@{
            journal_path = $script:runIdentityJournalPath
            journal_sha256 = (Get-FileHash -LiteralPath $script:runIdentityJournalPath -Algorithm SHA256).Hash.ToLowerInvariant()
            consumption = "external cleanup with the same run token"
        }
        windows = [ordered]@{
            product_name = [string]$currentVersion.ProductName
            edition = [string]$currentVersion.EditionID
            build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
        }
        powershell_version = $PSVersionTable.PSVersion.ToString()
        monotonic_clock = [ordered]@{
            kind = "System.Diagnostics.Stopwatch"
            frequency = [Diagnostics.Stopwatch]::Frequency
            origin_timestamp = $script:tcp08ClockOriginTimestamp
            origin_wall_clock_utc = $script:tcp08ClockOriginUtc
        }
        logs = [ordered]@{
            client_stdout = [ordered]@{ name = "client.stdout.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            client_stderr = [ordered]@{ name = "client.stderr.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            server_stdout = [ordered]@{ name = "server.stdout.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            server_stderr = [ordered]@{ name = "server.stderr.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            controller_stdout = [ordered]@{ name = "controller.stdout.log"; producer = "outer pwsh stream redirection"; mode = "append" }
            controller_stderr = [ordered]@{ name = "controller.stderr.log"; producer = "outer pwsh stream redirection"; mode = "append" }
        }
        artifact_manifest = [ordered]@{
            controller_capture_is_point_in_time = $true
            outer_redirection_may_still_be_open = $true
            final_outer_recalculation_required = $true
        }
        tcp08 = [ordered]@{
            target = $Target
            target_port = $TargetPort
            gate_port = $GatePort
            server_port = $ServerPort
            metrics_port = $MetricsPort
            require_product_owner_metrics = [bool]$script:RequireTcp08ProductMetrics
            pressure_chunk_bytes = 1048576
            pressure_attempt_limit = 128
            pressure_attempt_wait_ms = 100
            pressure_stable_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            runtime_idle_timeout_ms = $script:runtimeIdleTimeoutMilliseconds
            ctrl_break_internal_wait_ms = 250
            controller_grace_probe_ms = 300
            shutdown_grace_ms = 1000
            process_exit_wait_ms = 10000
        }
    })
}

function Get-Tcp08JsonProperty([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-Tcp08JsonNumber([object]$Value) {
    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [uint16] -or $Value -is [int16] -or
        $Value -is [uint32] -or $Value -is [int32] -or
        $Value -is [uint64] -or $Value -is [int64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]
}

function ConvertTo-Tcp08NonNegativeUInt64([object]$Value, [string]$Field) {
    Assert-True (Test-Tcp08JsonNumber $Value) "process shutdown report $Field is not numeric"
    try { $number = [decimal]$Value }
    catch { throw "process shutdown report $Field is outside the supported integer range" }
    Assert-True ($number -ge 0 -and $number -le [decimal]([uint64]::MaxValue) -and
        $number -eq [decimal]::Truncate($number)) "process shutdown report $Field is not a non-negative integer"
    return [uint64]$number
}

function ConvertTo-Tcp08SignedInt64([object]$Value, [string]$Field) {
    Assert-True (Test-Tcp08JsonNumber $Value) "process shutdown report $Field is not numeric"
    try { $number = [decimal]$Value }
    catch { throw "process shutdown report $Field is outside the supported integer range" }
    Assert-True ($number -ge [decimal]([int64]::MinValue) -and $number -le [decimal]([int64]::MaxValue) -and
        $number -eq [decimal]::Truncate($number)) "process shutdown report $Field is not an integer"
    return [int64]$number
}

function ConvertTo-Tcp08ProductRoot([object]$Root) {
    if ($null -eq $Root) { return $null }
    Assert-ClosedJsonProperties $Root @("name", "id") "process shutdown report root"
    $name = [string](Get-Tcp08JsonProperty $Root "name")
    Assert-True (@("socks", "dns", "metrics", "tun") -ccontains $name) "process shutdown report root name is invalid"
    $id = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Root "id") "root.id"
    Assert-True ($id -lt 4) "process shutdown report root ID is outside the closed client topology"
    return [ordered]@{
        name = $name
        id = $id
    }
}

function ConvertTo-Tcp08OwnerCounters([object]$Counters, [bool]$AllowNegative = $false) {
    if ($null -eq $Counters) { return $null }
    $names = @(
        "process_supervisors", "prepared_process_roots", "active_process_roots", "process_root_reaps",
        "process_root_rollbacks", "process_forced_roots", "active_tun_tcp_flows", "active_tun_handler_tasks",
        "active_supervisor_children", "connection_tasks", "owned_buffers", "owned_permits", "listeners",
        "forced_shutdowns", "udp_sessions", "udp_sockets", "udp_tasks", "udp_queued_datagrams",
        "udp_buffered_bytes", "udp_scratch_buffers", "udp_forced_shutdowns", "sniff_buffered_bytes"
    )
    Assert-ClosedJsonProperties $Counters $names "process shutdown report owner counters"
    $sanitized = [ordered]@{}
    foreach ($name in $names) {
        $value = Get-Tcp08JsonProperty $Counters $name
        $sanitized[$name] = if ($AllowNegative) {
            ConvertTo-Tcp08SignedInt64 $value "owner.$name"
        } else {
            ConvertTo-Tcp08NonNegativeUInt64 $value "owner.$name"
        }
    }
    return $sanitized
}

function ConvertTo-Tcp08CleanupFailure([object]$Failure, [int]$Depth = 0) {
    if ($null -eq $Failure) { return $null }
    Assert-True ($Depth -le 4) "process shutdown report cleanup nesting is invalid"
    $allowedProperties = @("kind", "root", "roots", "root_error_category", "prior", "owner_baseline", "owner_stopped", "owner_delta")
    $actualProperties = @($Failure.PSObject.Properties.Name)
    Assert-True (@($actualProperties | Where-Object { -not ($allowedProperties -ccontains $_) }).Count -eq 0 -and
        $actualProperties -ccontains "kind") "process shutdown report cleanup property set is invalid"
    $kind = [string](Get-Tcp08JsonProperty $Failure "kind")
    Assert-True ($kind -in @("RootFailed", "RootPanicked", "RootJoinFailed", "ForceReapTimedOut", "OwnerMismatch")) "process shutdown report cleanup kind is invalid"
    $sanitized = [ordered]@{ kind = $kind }
    $root = Get-Tcp08JsonProperty $Failure "root"
    if ($null -ne $root) { $sanitized.root = ConvertTo-Tcp08ProductRoot $root }
    $roots = Get-Tcp08JsonProperty $Failure "roots"
    if ($null -ne $roots) {
        $sanitizedRoots = @($roots | ForEach-Object { ConvertTo-Tcp08ProductRoot $_ })
        Assert-True (@($sanitizedRoots | Group-Object id | Where-Object Count -gt 1).Count -eq 0 -and
            @($sanitizedRoots | Group-Object name | Where-Object Count -gt 1).Count -eq 0) "process shutdown report cleanup roots contain duplicates"
        $sanitized.roots = $sanitizedRoots
    }
    $errorCategory = Get-Tcp08JsonProperty $Failure "root_error_category"
    if ($null -ne $errorCategory) {
        $errorCategory = [string]$errorCategory
        Assert-True ($errorCategory -match '^(startup|runtime|shutdown)\.[a-z]+$') "process shutdown report error category is invalid"
        $sanitized.root_error_category = $errorCategory
    }
    $prior = Get-Tcp08JsonProperty $Failure "prior"
    if ($null -ne $prior) { $sanitized.prior = ConvertTo-Tcp08CleanupFailure $prior ($Depth + 1) }
    foreach ($name in @("owner_baseline", "owner_stopped", "owner_delta")) {
        $value = Get-Tcp08JsonProperty $Failure $name
        if ($null -ne $value) { $sanitized[$name] = ConvertTo-Tcp08OwnerCounters $value ($name -ceq "owner_delta") }
    }
    return $sanitized
}

function ConvertTo-Tcp08ProductShutdownReport([object]$Report) {
    $requiredReportProperties = @(
        "event", "role", "process_states", "process_transitions", "shutdown_grace_ns",
        "actual_grace_deadline_elapsed_ns", "actual_grace_deadline_source", "termination_cause",
        "root", "root_exit_category", "root_error_category", "forced_root_count",
        "owner_baseline", "owner_stopped", "owner_delta", "cleanup_failure"
    )
    $allowedReportProperties = @($requiredReportProperties) + @("root_exit_events")
    $actualReportProperties = @($Report.PSObject.Properties.Name)
    Assert-True (@($actualReportProperties | Where-Object { -not ($allowedReportProperties -ccontains $_) }).Count -eq 0) "process shutdown report has unknown properties"
    Assert-True (@($requiredReportProperties | Where-Object { -not ($actualReportProperties -ccontains $_) }).Count -eq 0) "process shutdown report is missing required properties"
    Assert-True ((Get-Tcp08JsonProperty $Report "event") -ceq "process_shutdown_report") "process shutdown report event is invalid"
    Assert-True ((Get-Tcp08JsonProperty $Report "role") -ceq "client") "process shutdown report role is invalid"
    $allowedStates = @("Validated", "Preparing", "Prepared", "Active", "Rollback", "Fatal", "Quiescing", "Draining", "Forced", "Stopped")
    $states = @(Get-Tcp08JsonProperty $Report "process_states")
    Assert-True ($states.Count -gt 0 -and @($states | Where-Object { -not ($allowedStates -ccontains [string]$_) }).Count -eq 0) "process shutdown report states are invalid"
    $rawTransitions = @(Get-Tcp08JsonProperty $Report "process_transitions")
    Assert-True ($rawTransitions.Count -eq $states.Count) "process shutdown report state/transition count is inconsistent"
    $transitions = [System.Collections.Generic.List[object]]::new()
    $seenStates = @{}
    $previousTransitionElapsed = $null
    for ($index = 0; $index -lt $rawTransitions.Count; $index++) {
        Assert-ClosedJsonProperties $rawTransitions[$index] @("state", "elapsed_ns") "process shutdown report transition"
        $state = [string](Get-Tcp08JsonProperty $rawTransitions[$index] "state")
        Assert-True ($allowedStates -ccontains $state) "process shutdown report transition is invalid"
        Assert-True ($state -ceq [string]$states[$index]) "process shutdown report state/transition sequence is inconsistent"
        Assert-True (-not $seenStates.ContainsKey($state)) "process shutdown report contains a duplicate state transition"
        $seenStates[$state] = $true
        $elapsed = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $rawTransitions[$index] "elapsed_ns") "process_transitions[$index].elapsed_ns"
        if ($null -ne $previousTransitionElapsed) {
            Assert-True ($elapsed -ge $previousTransitionElapsed) "process shutdown report transitions are not monotonic"
        }
        $previousTransitionElapsed = $elapsed
        $transitions.Add([ordered]@{ state = $state; elapsed_ns = $elapsed })
    }
    Assert-True ([string]$states[$states.Count - 1] -ceq "Stopped") "process shutdown report is not closed by Stopped"
    $reportElapsed = [uint64]$previousTransitionElapsed

    $rootExitEvents = [System.Collections.Generic.List[object]]::new()
    $rootExitEventsAvailability = "unavailable"
    $rootExitEventsSchemaGeneration = "legacy"
    $rootExitEventsUnavailableReason = "legacy_process_shutdown_report_missing_root_exit_events"
    $rootExitEventsProperty = $Report.PSObject.Properties["root_exit_events"]
    if ($null -ne $rootExitEventsProperty) {
        $rootExitEventsAvailability = "available"
        $rootExitEventsSchemaGeneration = "current"
        $rootExitEventsUnavailableReason = $null
        $rawRootExitEvents = $rootExitEventsProperty.Value
        Assert-True ($rawRootExitEvents -is [System.Array]) "process shutdown report root_exit_events is not an array"
        Assert-True (@($rawRootExitEvents).Count -le 4) "process shutdown report has too many root exit events"
        $seenRootIds = @{}
        $seenRootNames = @{}
        $previousRootElapsed = $null
        $allowedRootPhases = @("Active", "Draining", "Forced", "WatchdogAbort")
        $allowedRootExitCategories = @("Completed", "Failed", "Panicked", "JoinFailed", "Aborted")
        foreach ($rawRootEvent in @($rawRootExitEvents)) {
            Assert-ClosedJsonProperties $rawRootEvent @("root", "phase", "exit_category", "elapsed_ns") "process shutdown report root exit event"
            $root = ConvertTo-Tcp08ProductRoot (Get-Tcp08JsonProperty $rawRootEvent "root")
            Assert-True ($null -ne $root) "process shutdown report root exit event has no root"
            $rootIdKey = ([uint64]$root.id).ToString([Globalization.CultureInfo]::InvariantCulture)
            $rootNameKey = [string]$root.name
            Assert-True (-not $seenRootIds.ContainsKey($rootIdKey)) "process shutdown report has a duplicate root exit ID"
            Assert-True (-not $seenRootNames.ContainsKey($rootNameKey)) "process shutdown report has a duplicate stable root exit name"
            $seenRootIds[$rootIdKey] = $true
            $seenRootNames[$rootNameKey] = $true
            $phase = [string](Get-Tcp08JsonProperty $rawRootEvent "phase")
            Assert-True ($allowedRootPhases -ccontains $phase) "process shutdown report root exit phase is invalid"
            $exitCategory = [string](Get-Tcp08JsonProperty $rawRootEvent "exit_category")
            Assert-True ($allowedRootExitCategories -ccontains $exitCategory) "process shutdown report root exit category is invalid"
            $elapsed = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $rawRootEvent "elapsed_ns") "root_exit_events.elapsed_ns"
            if ($null -ne $previousRootElapsed) {
                Assert-True ($elapsed -ge $previousRootElapsed) "process shutdown report root exit events are not monotonic"
            }
            Assert-True ($elapsed -le $reportElapsed) "process shutdown report root exit event is later than report completion"
            $previousRootElapsed = $elapsed
            $rootExitEvents.Add([ordered]@{
                root = $root
                phase = $phase
                exit_category = $exitCategory
                elapsed_ns = $elapsed
            })
        }
    }
    $terminationCause = [string](Get-Tcp08JsonProperty $Report "termination_cause")
    Assert-True (@("ExternalShutdown", "PreparationFailed", "PreparationPanicked", "ActivationFailed", "ActivationPanicked", "RootStopped") -ccontains $terminationCause) "process shutdown report cause is invalid"
    $rootExitCategory = Get-Tcp08JsonProperty $Report "root_exit_category"
    if ($null -ne $rootExitCategory) {
        $rootExitCategory = [string]$rootExitCategory
        Assert-True (@("Completed", "Failed", "Panicked", "JoinFailed") -ccontains $rootExitCategory) "process shutdown report root exit category is invalid"
    }
    $rootErrorCategory = Get-Tcp08JsonProperty $Report "root_error_category"
    if ($null -ne $rootErrorCategory) {
        $rootErrorCategory = [string]$rootErrorCategory
        Assert-True ($rootErrorCategory -match '^(startup|runtime|shutdown)\.[a-z]+$') "process shutdown report root error category is invalid"
    }
    $actualGraceDeadline = Get-Tcp08JsonProperty $Report "actual_grace_deadline_elapsed_ns"
    $actualGraceDeadlineSource = Get-Tcp08JsonProperty $Report "actual_grace_deadline_source"
    if ($null -ne $actualGraceDeadlineSource) {
        $actualGraceDeadlineSource = [string]$actualGraceDeadlineSource
        Assert-True ($actualGraceDeadlineSource -eq "runtime_process_supervisor") "process shutdown report grace deadline source is invalid"
    }
    Assert-True (($null -eq $actualGraceDeadline) -eq ($null -eq $actualGraceDeadlineSource)) "process shutdown report actual grace deadline pair is incomplete"
    if ($null -ne $actualGraceDeadline) {
        $actualGraceDeadline = ConvertTo-Tcp08NonNegativeUInt64 $actualGraceDeadline "actual_grace_deadline_elapsed_ns"
    }
    $graceDeadlineSemantics = if ($null -ne $actualGraceDeadline) { "actual_runtime_deadline" }
        else { "unavailable" }
    $ownerBaseline = Get-Tcp08JsonProperty $Report "owner_baseline"
    $ownerStopped = Get-Tcp08JsonProperty $Report "owner_stopped"
    $ownerDelta = Get-Tcp08JsonProperty $Report "owner_delta"
    Assert-True ($null -ne $ownerBaseline -and $null -ne $ownerStopped -and $null -ne $ownerDelta) "process shutdown report top-level owner triplet is incomplete"
    return [ordered]@{
        event = "process_shutdown_report"
        role = "client"
        process_states = @($states | ForEach-Object { [string]$_ })
        process_transitions = $transitions
        report_elapsed_ns = $reportElapsed
        report_elapsed_source = "final_Stopped_process_transition"
        root_exit_events = $rootExitEvents
        root_exit_events_availability = $rootExitEventsAvailability
        root_exit_events_schema_generation = $rootExitEventsSchemaGeneration
        root_exit_events_unavailable_reason = $rootExitEventsUnavailableReason
        shutdown_grace_ns = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Report "shutdown_grace_ns") "shutdown_grace_ns"
        actual_grace_deadline_elapsed_ns = $actualGraceDeadline
        actual_grace_deadline_source = $actualGraceDeadlineSource
        grace_deadline_semantics = $graceDeadlineSemantics
        termination_cause = $terminationCause
        root = ConvertTo-Tcp08ProductRoot (Get-Tcp08JsonProperty $Report "root")
        root_exit_category = $rootExitCategory
        root_error_category = $rootErrorCategory
        forced_root_count = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Report "forced_root_count") "forced_root_count"
        owner_baseline = ConvertTo-Tcp08OwnerCounters $ownerBaseline
        owner_stopped = ConvertTo-Tcp08OwnerCounters $ownerStopped
        owner_delta = ConvertTo-Tcp08OwnerCounters $ownerDelta $true
        cleanup_failure = ConvertTo-Tcp08CleanupFailure (Get-Tcp08JsonProperty $Report "cleanup_failure")
    }
}

function Get-Tcp08ProductTransition([object]$Report, [string]$State) {
    $matches = @($Report.process_transitions | Where-Object { $_.state -ceq $State })
    Assert-True ($matches.Count -le 1) "validated process report contains duplicate $State transitions"
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Get-Tcp08SharedLogSnapshot([string]$Path, [string]$CapturePhase) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            capture_phase = $CapturePhase
            byte_length = [int64]0
            complete_byte_length = [int64]0
            trailing_partial_byte_count = [int64]0
            complete_line_count = 0
            candidate_count = 0
            lines = @()
        }
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $byteLength = $stream.Length
        Assert-True ($byteLength -le [int]::MaxValue) "TCP-08 client stderr is too large to snapshot"
        $bytes = [byte[]]::new([int]$byteLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { break }
            $offset += $read
        }
    } finally { $stream.Dispose() }
    $lastLf = -1
    for ($index = $offset - 1; $index -ge 0; $index--) {
        if ($bytes[$index] -eq 10) { $lastLf = $index; break }
    }
    $completeByteLength = $lastLf + 1
    $candidateCount = 0
    if ($completeByteLength -gt 0) {
        $text = [Text.Encoding]::UTF8.GetString($bytes, 0, $completeByteLength)
        $rawLines = $text.Split([char]10)
        for ($index = 0; $index -lt $rawLines.Length - 1; $index++) {
            $line = $rawLines[$index].TrimEnd([char]13)
            $lines.Add($line)
            if ($line -match '"event"\s*:\s*"process_shutdown_report"') { $candidateCount++ }
        }
    }
    return [pscustomobject][ordered]@{
        capture_phase = $CapturePhase
        byte_length = [int64]$offset
        complete_byte_length = [int64]$completeByteLength
        trailing_partial_byte_count = [int64]($offset - $completeByteLength)
        complete_line_count = $lines.Count
        candidate_count = $candidateCount
        lines = $lines.ToArray()
    }
}

function Get-Tcp08ForcedReportAssessment(
    [object]$Report,
    [int]$RecordIndex,
    [int]$StderrLine,
    [int]$CandidateOrdinal
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    $activeTransition = Get-Tcp08ProductTransition $Report "Active"
    $forcedTransition = Get-Tcp08ProductTransition $Report "Forced"
    $quiescingTransition = Get-Tcp08ProductTransition $Report "Quiescing"
    $drainingTransition = Get-Tcp08ProductTransition $Report "Draining"
    $stoppedTransition = Get-Tcp08ProductTransition $Report "Stopped"
    $forcedIntent = $null -ne $forcedTransition -or $Report.forced_root_count -gt 0 -or
        @($Report.root_exit_events | Where-Object { $_.phase -in @("Forced", "WatchdogAbort") }).Count -gt 0
    if (-not $forcedIntent) {
        return [ordered]@{
            record_index = $RecordIndex
            stderr_line = $StderrLine
            candidate_ordinal = $CandidateOrdinal
            classification = "allowed_non_forced_report"
            selection_reason = "no_forced_state_count_or_root_event"
            failures = @()
            product_timeline_events = @()
        }
    }

    if ($null -eq $forcedTransition) { $failures.Add("missing_Forced_transition") }
    if ($null -eq $activeTransition) { $failures.Add("missing_Active_transition") }
    if ($null -eq $quiescingTransition) { $failures.Add("missing_Quiescing_transition") }
    if ($null -eq $drainingTransition) { $failures.Add("missing_Draining_transition") }
    if ($null -eq $stoppedTransition) { $failures.Add("missing_Stopped_transition") }
    $expectedForcedStates = @("Validated", "Preparing", "Prepared", "Active", "Quiescing", "Draining", "Forced", "Stopped")
    if ((@($Report.process_states) -join "|") -cne ($expectedForcedStates -join "|")) {
        $failures.Add("forced_process_state_sequence_not_canonical")
    }
    foreach ($state in @("Active", "Quiescing", "Draining", "Forced", "Stopped")) {
        if (@($Report.process_states | Where-Object { $_ -ceq $state }).Count -ne 1 -or
            @($Report.process_transitions | Where-Object { $_.state -ceq $state }).Count -ne 1) {
            $failures.Add("forced_process_state_count_not_one_$state")
        }
    }
    if ($null -ne $activeTransition -and $null -ne $quiescingTransition -and
        $null -ne $drainingTransition -and $null -ne $forcedTransition -and $null -ne $stoppedTransition) {
        $requiredOrder = @("Active", "Quiescing", "Draining", "Forced", "Stopped")
        $requiredIndexes = @($requiredOrder | ForEach-Object { [Array]::IndexOf([object[]]$Report.process_states, $_) })
        if ($requiredIndexes[0] -ge $requiredIndexes[1] -or
            $requiredIndexes[1] -ge $requiredIndexes[2] -or
            $requiredIndexes[2] -ge $requiredIndexes[3] -or
            $requiredIndexes[3] -ge $requiredIndexes[4]) {
            $failures.Add("forced_process_state_order_not_Active_Quiescing_Draining_Forced_Stopped")
        }
    }
    if ($Report.forced_root_count -le 0) { $failures.Add("forced_root_count_not_positive") }
    if ($Report.termination_cause -cne "ExternalShutdown") { $failures.Add("termination_cause_not_ExternalShutdown") }
    if ($null -ne $Report.root -or $null -ne $Report.root_exit_category -or $null -ne $Report.root_error_category) {
        $failures.Add("ExternalShutdown_report_has_primary_root_exit")
    }
    if ($null -ne $Report.cleanup_failure) { $failures.Add("cleanup_failure_present") }
    if ($Report.root_exit_events_availability -cne "available" -or
        $Report.root_exit_events_schema_generation -cne "current") {
        $failures.Add("current_root_exit_events_unavailable")
    }
    if ($null -eq $Report.actual_grace_deadline_elapsed_ns -or
        $Report.actual_grace_deadline_source -cne "runtime_process_supervisor") {
        $failures.Add("actual_runtime_grace_deadline_unavailable")
    }
    $tunEvents = @($Report.root_exit_events | Where-Object { $_.root.name -ceq "tun" })
    if ($tunEvents.Count -ne 1) {
        $failures.Add("stable_tun_root_event_count_not_one")
    } elseif ($tunEvents[0].phase -cne "Forced") {
        $failures.Add("stable_tun_root_not_cleanly_reaped_in_Forced_phase")
    } elseif ($tunEvents[0].exit_category -cne "Completed") {
        $failures.Add("stable_tun_root_exit_not_Completed")
    }
    $activeOwnerNames = @(
        "process_supervisors", "prepared_process_roots", "active_process_roots",
        "active_tun_tcp_flows", "active_tun_handler_tasks", "active_supervisor_children",
        "connection_tasks", "owned_buffers", "owned_permits", "listeners", "udp_sessions",
        "udp_sockets", "udp_tasks", "udp_queued_datagrams", "udp_buffered_bytes",
        "udp_scratch_buffers", "sniff_buffered_bytes"
    )
    foreach ($name in $activeOwnerNames) {
        if ($Report.owner_stopped.$name -ne $Report.owner_baseline.$name -or $Report.owner_delta.$name -ne 0) {
            $failures.Add("active_owner_not_returned_to_baseline_$name")
        }
    }
    foreach ($name in @("active_process_roots", "active_tun_tcp_flows", "active_tun_handler_tasks")) {
        if ($Report.owner_baseline.$name -ne 0 -or $Report.owner_stopped.$name -ne 0) {
            $failures.Add("required_active_owner_not_zero_$name")
        }
    }
    foreach ($name in @("process_root_reaps", "process_root_rollbacks", "process_forced_roots", "forced_shutdowns", "udp_forced_shutdowns")) {
        if ($Report.owner_delta.$name -lt 0) { $failures.Add("cumulative_owner_delta_negative_$name") }
    }
    if ($Report.owner_delta.process_forced_roots -le 0) { $failures.Add("process_forced_roots_delta_not_positive") }
    if ($Report.owner_delta.process_root_reaps -le 0) { $failures.Add("process_root_reaps_delta_not_positive") }
    if ($Report.owner_delta.process_forced_roots -ne $Report.forced_root_count) { $failures.Add("process_forced_roots_delta_count_mismatch") }
    if ($null -ne $Report.actual_grace_deadline_elapsed_ns) {
        if ($Report.actual_grace_deadline_elapsed_ns -gt $Report.report_elapsed_ns) {
            $failures.Add("grace_deadline_later_than_report")
        }
        if ($Report.actual_grace_deadline_elapsed_ns -lt $Report.shutdown_grace_ns) {
            $failures.Add("grace_deadline_precedes_configured_grace_origin")
        }
        if ($null -ne $drainingTransition -and
            ($Report.actual_grace_deadline_elapsed_ns - $Report.shutdown_grace_ns) -lt $drainingTransition.elapsed_ns) {
            $failures.Add("grace_deadline_creation_precedes_Draining_transition")
        }
        if ($null -ne $forcedTransition -and
            $forcedTransition.elapsed_ns -lt $Report.actual_grace_deadline_elapsed_ns) {
            $failures.Add("Forced_transition_precedes_grace_deadline")
        }
        if ($tunEvents.Count -eq 1 -and
            $tunEvents[0].elapsed_ns -lt $Report.actual_grace_deadline_elapsed_ns) {
            $failures.Add("stable_tun_root_event_precedes_grace_deadline")
        }
    }
    if ($null -ne $stoppedTransition) {
        if ($stoppedTransition.elapsed_ns -ne $Report.report_elapsed_ns) {
            $failures.Add("Stopped_transition_report_elapsed_mismatch")
        }
        if (@($Report.root_exit_events | Where-Object { $_.elapsed_ns -gt $stoppedTransition.elapsed_ns }).Count -gt 0) {
            $failures.Add("root_exit_event_later_than_Stopped_transition")
        }
    }

    $classification = if ($failures.Count -eq 0) { "tcp08_forced_candidate" } else { "incomplete_forced_report" }
    $selectionReason = if ($failures.Count -eq 0) {
        "closed_forced_state_positive_forced_count_actual_deadline_and_stable_tun_root_event"
    } else { "forced_intent_failed_closed_tcp08_criteria" }
    $productEvents = [System.Collections.Generic.List[object]]::new()
    if ($failures.Count -eq 0) {
        $productEvents.Add([ordered]@{
            name = "shutdown_signal_observed"
            source_ordinal = 1
            elapsed_ns = $quiescingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Quiescing_transition_upper_bound"
        })
        $productEvents.Add([ordered]@{
            name = "quiescing_started"
            source_ordinal = 2
            elapsed_ns = $quiescingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Quiescing_transition"
        })
        $productEvents.Add([ordered]@{
            name = "draining_started"
            source_ordinal = 3
            elapsed_ns = $drainingTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Draining_transition"
        })
        $productEvents.Add([ordered]@{
            name = "grace_deadline_created"
            source_ordinal = 4
            elapsed_ns = [uint64]($Report.actual_grace_deadline_elapsed_ns - $Report.shutdown_grace_ns)
            clock_domain = "product_process_relative"
            timestamp_source = "actual_grace_deadline_elapsed_ns_minus_shutdown_grace_ns"
            deadline_elapsed_ns = $Report.actual_grace_deadline_elapsed_ns
        })
        $productEvents.Add([ordered]@{
            name = "forced_started"
            source_ordinal = 5
            elapsed_ns = $forcedTransition.elapsed_ns
            clock_domain = "product_process_relative"
            timestamp_source = "Forced_transition"
        })
        $rootEventOrdinal = 6
        foreach ($rootEvent in $Report.root_exit_events) {
            $productEvents.Add([ordered]@{
                name = "root_exit_observed"
                source_ordinal = $rootEventOrdinal
                elapsed_ns = $rootEvent.elapsed_ns
                clock_domain = "product_process_relative"
                timestamp_source = "root_exit_events"
                root = $rootEvent.root
                phase = $rootEvent.phase
                exit_category = $rootEvent.exit_category
            })
            $rootEventOrdinal++
        }
    }
    return [ordered]@{
        record_index = $RecordIndex
        stderr_line = $StderrLine
        candidate_ordinal = $CandidateOrdinal
        classification = $classification
        selection_reason = $selectionReason
        failures = $failures
        product_timeline_events = @($productEvents | Sort-Object elapsed_ns, source_ordinal)
    }
}

function Get-Tcp08ProductShutdownEvidence {
    $path = Join-Path $script:tcp08ArtifactPath "client.stderr.log"
    $reports = [System.Collections.Generic.List[object]]::new()
    $assessments = [System.Collections.Generic.List[object]]::new()
    $invalidRecordDetails = [System.Collections.Generic.List[object]]::new()
    $invalidRecords = 0
    $candidateLines = 0
    $lineNumber = 0
    $readFailureType = $null
    $logSnapshot = $null
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $logSnapshot = Get-Tcp08SharedLogSnapshot $path "artifact_finalization"
            foreach ($line in @($logSnapshot.lines)) {
                $lineNumber++
                if ($line -notmatch '"event"\s*:\s*"process_shutdown_report"') { continue }
                $candidateLines++
                $candidateOrdinal = $candidateLines
                try {
                    $parsed = $line | ConvertFrom-Json -Depth 16 -ErrorAction Stop
                    $report = ConvertTo-Tcp08ProductShutdownReport $parsed
                    $recordIndex = $reports.Count
                    $reports.Add($report)
                    $assessments.Add((Get-Tcp08ForcedReportAssessment $report $recordIndex $lineNumber $candidateOrdinal))
                } catch {
                    $invalidRecords++
                    $invalidRecordDetails.Add([ordered]@{
                        stderr_line = $lineNumber
                        candidate_ordinal = $candidateOrdinal
                        rejection = "invalid_closed_process_shutdown_report"
                        error_type = $_.Exception.GetType().FullName
                    })
                }
            }
        } catch { $readFailureType = $_.Exception.GetType().FullName }
    }
    $availability = if ($reports.Count -gt 0) { "available" }
        elseif ($readFailureType) { "read_failed" }
        elseif ($invalidRecords -gt 0) { "invalid" }
        else { "unavailable" }
    $unavailableReason = if ($availability -eq "unavailable") { "no_closed_process_shutdown_report_record" } else { $null }
    $schemaGeneration = if ($reports.Count -gt 0) {
        $generations = @($reports | ForEach-Object { $_.root_exit_events_schema_generation } | Select-Object -Unique)
        if ($generations.Count -eq 1) { [string]$generations[0] } else { "mixed" }
    } elseif ($availability -eq "unavailable") { "legacy" }
    else { "unknown" }
    $allForcedMatches = @($assessments | Where-Object { $_.classification -ceq "tcp08_forced_candidate" })
    $allIncompleteForced = @($assessments | Where-Object { $_.classification -ceq "incomplete_forced_report" })
    $allAllowedNonForced = @($assessments | Where-Object { $_.classification -ceq "allowed_non_forced_report" })
    $selectionWindow = $script:tcp08ShutdownReportCandidateWindow
    $windowBoundsValid = $false
    $windowAssessments = @()
    $windowInvalidRecordDetails = @()
    $windowCandidateLines = 0
    if ($null -ne $selectionWindow) {
        $lowerExclusive = [int]$selectionWindow.lower_exclusive_candidate_ordinal
        $upperInclusive = [int]$selectionWindow.upper_inclusive_candidate_ordinal
        $windowBoundsValid = $lowerExclusive -ge 0 -and $upperInclusive -ge $lowerExclusive -and
            $upperInclusive -le $candidateLines
        if ($windowBoundsValid) {
            $windowAssessments = @($assessments | Where-Object {
                $_.candidate_ordinal -gt $lowerExclusive -and $_.candidate_ordinal -le $upperInclusive
            })
            $windowInvalidRecordDetails = @($invalidRecordDetails | Where-Object {
                $_.candidate_ordinal -gt $lowerExclusive -and $_.candidate_ordinal -le $upperInclusive
            })
            $windowCandidateLines = $windowAssessments.Count + $windowInvalidRecordDetails.Count
        }
    }
    $forcedMatches = @($windowAssessments | Where-Object { $_.classification -ceq "tcp08_forced_candidate" })
    $incompleteForced = @($windowAssessments | Where-Object { $_.classification -ceq "incomplete_forced_report" })
    $allowedNonForced = @($windowAssessments | Where-Object { $_.classification -ceq "allowed_non_forced_report" })
    $windowAvailability = if ($null -eq $selectionWindow) { "unavailable" }
        elseif (-not $windowBoundsValid) { "invalid" }
        elseif ($windowAssessments.Count -gt 0) { "available" }
        elseif ($windowInvalidRecordDetails.Count -gt 0) { "invalid" }
        else { "unavailable" }
    $windowSchemaGeneration = if ($windowAssessments.Count -gt 0) {
        $windowGenerations = @($windowAssessments | ForEach-Object {
            $reports[[int]$_.record_index].root_exit_events_schema_generation
        } | Select-Object -Unique)
        if ($windowGenerations.Count -eq 1) { [string]$windowGenerations[0] } else { "mixed" }
    } elseif ($windowBoundsValid -and $windowCandidateLines -eq 0) { "legacy" }
    else { "unknown" }
    $strictFailures = [System.Collections.Generic.List[string]]::new()
    if ($script:RequireTcp08ProductMetrics) {
        if ($readFailureType) { $strictFailures.Add("client_stderr_read_failed") }
        if ($logSnapshot -and $logSnapshot.trailing_partial_byte_count -ne 0) { $strictFailures.Add("client_stderr_trailing_partial_record") }
        if ($invalidRecords -ne 0) { $strictFailures.Add("invalid_process_shutdown_report_records") }
        if ($allIncompleteForced.Count -ne 0) { $strictFailures.Add("incomplete_forced_reports_present") }
        if ($null -eq $selectionWindow) {
            $strictFailures.Add("tcp08_candidate_window_missing")
        } elseif (-not $windowBoundsValid) {
            $strictFailures.Add("tcp08_candidate_window_outside_client_stderr")
        } else {
            if ([int]$selectionWindow.candidate_delta -ne 1) { $strictFailures.Add("tcp08_candidate_window_delta_not_one") }
            if ($windowCandidateLines -ne [int]$selectionWindow.candidate_delta) { $strictFailures.Add("tcp08_candidate_window_observation_mismatch") }
            if ($windowAssessments.Count -ne 1) { $strictFailures.Add("tcp08_candidate_window_valid_record_count_not_one") }
        }
        if ($forcedMatches.Count -eq 0) { $strictFailures.Add("tcp08_forced_report_missing") }
        if ($forcedMatches.Count -gt 1) { $strictFailures.Add("multiple_tcp08_forced_reports") }
        if ($script:Mode -ceq "tcp08" -and $candidateLines -ne 1) {
            $strictFailures.Add("focused_tcp08_candidate_line_count_not_one")
        }
    }
    $strictStatus = if (-not $script:RequireTcp08ProductMetrics) { "not_required" }
        elseif ($strictFailures.Count -eq 0) { "pass" }
        else { "fail" }
    $selectionReason = if ($null -eq $selectionWindow) { "tcp08_candidate_window_unavailable" }
        elseif (-not $windowBoundsValid) { "tcp08_candidate_window_outside_client_stderr" }
        elseif ($forcedMatches.Count -eq 1) { "unique_closed_tcp08_forced_report_in_frozen_candidate_window" }
        elseif ($forcedMatches.Count -eq 0) { "no_closed_tcp08_forced_report_in_frozen_candidate_window" }
        else { "multiple_closed_tcp08_forced_reports_in_frozen_candidate_window" }
    $selected = if ($forcedMatches.Count -eq 1) { $forcedMatches[0] } else { $null }
    return [ordered]@{
        source = "client.stderr.log"
        source_format = "closed allowlisted process_shutdown_report JSON line"
        availability = $availability
        schema_generation = $schemaGeneration
        unavailable_reason = $unavailableReason
        clock = [ordered]@{
            kind = "product process-relative monotonic duration"
            unit = "nanoseconds"
            global_stopwatch_alignment_available = $false
        }
        strict_validation = [ordered]@{
            required = [bool]$script:RequireTcp08ProductMetrics
            status = $strictStatus
            candidate_window = $selectionWindow
            candidate_window_availability = $windowAvailability
            candidate_window_schema_generation = $windowSchemaGeneration
            candidate_line_count = $windowCandidateLines
            valid_record_count = $windowAssessments.Count
            invalid_record_count = $windowInvalidRecordDetails.Count
            tcp08_forced_candidate_count = $forcedMatches.Count
            incomplete_forced_report_count = $incompleteForced.Count
            allowed_non_forced_report_count = $allowedNonForced.Count
            non_forced_policy = "allowed_restart_or_other_closed_reports"
            selected_record_index = if ($selected) { $selected.record_index } else { $null }
            selected_stderr_line = if ($selected) { $selected.stderr_line } else { $null }
            selected_candidate_ordinal = if ($selected) { $selected.candidate_ordinal } else { $null }
            selection_reason = $selectionReason
            failures = $strictFailures
        }
        all_log_counts = [ordered]@{
            byte_length = if ($logSnapshot) { $logSnapshot.byte_length } else { $null }
            complete_byte_length = if ($logSnapshot) { $logSnapshot.complete_byte_length } else { $null }
            trailing_partial_byte_count = if ($logSnapshot) { $logSnapshot.trailing_partial_byte_count } else { $null }
            complete_line_count = if ($logSnapshot) { $logSnapshot.complete_line_count } else { 0 }
            candidate_line_count = $candidateLines
            valid_record_count = $reports.Count
            invalid_record_count = $invalidRecords
            tcp08_forced_candidate_count = $allForcedMatches.Count
            incomplete_forced_report_count = $allIncompleteForced.Count
            allowed_non_forced_report_count = $allAllowedNonForced.Count
        }
        selected_tcp08_forced_product_timeline = if ($selected) { $selected.product_timeline_events } else { @() }
        records = $reports
        record_assessments = $assessments
        invalid_candidate_records = $invalidRecords
        invalid_record_details = $invalidRecordDetails
        read_failure_type = $readFailureType
    }
}

function Write-Tcp08UnavailableArtifact([string]$Name) {
    Write-Tcp08Json $Name ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-artifact-unavailable.v1"
        artifact = $Name
        status = "not_collected_before_finalization"
    })
}

function Complete-Tcp08Artifacts([bool]$CleanupSucceeded, [object]$PrimaryFailure, [object]$CleanupFailure) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $completionErrors = [System.Collections.Generic.List[string]]::new()
    try { Write-Tcp08Json "process-after.json" (Get-Tcp08ProcessSnapshot) }
    catch {
        $completionErrors.Add("process-after.json")
        Write-Tcp08Json "process-after.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "process-after"
            error_type = $_.Exception.GetType().FullName
        })
    }
    try { Write-Tcp08Json "network-after.json" (Get-Tcp08ResidueNetworkSnapshot) }
    catch {
        $completionErrors.Add("network-after.json")
        Write-Tcp08Json "network-after.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "network-after"
            error_type = $_.Exception.GetType().FullName
        })
    }
    $productEvidence = Get-Tcp08ProductShutdownEvidence
    Write-Tcp08Json "process-report.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-process.v1"
        result = $script:tcp08Result
        process_exit_code = $script:tcp08ExitCode
        ctrl_break = $script:tcp08CtrlBreak
        samples = $script:tcp08Samples
        product = $productEvidence
    })
    Write-Tcp08Json "cleanup-report.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-cleanup.v1"
        cleanup_succeeded = $CleanupSucceeded
        primary_failure_type = if ($PrimaryFailure) { $PrimaryFailure.Exception.GetType().FullName } else { $null }
        primary_failure = if ($PrimaryFailure) { $PrimaryFailure.Exception.Message } else { $null }
        cleanup_failure_type = if ($CleanupFailure) { $CleanupFailure.Exception.GetType().FullName } else { $null }
        cleanup_failure = if ($CleanupFailure) { $CleanupFailure.Exception.Message } else { $null }
    })
    Write-Tcp08Json "timeline.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-timeline.v1"
        clock = [ordered]@{
            kind = "System.Diagnostics.Stopwatch"
            frequency = [Diagnostics.Stopwatch]::Frequency
            origin_timestamp = $script:tcp08ClockOriginTimestamp
            origin_wall_clock_utc = $script:tcp08ClockOriginUtc
        }
        events = $script:tcp08Events
        product = $productEvidence
    })
    foreach ($name in $script:tcp08RequiredJsonNames) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:tcp08ArtifactPath $name) -PathType Leaf)) {
            $completionErrors.Add($name)
            Write-Tcp08UnavailableArtifact $name
        }
    }
    $missingLogs = @($script:tcp08RequiredLogNames | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $script:tcp08ArtifactPath $_) -PathType Leaf)
    })
    $hashRows = @(Get-ChildItem -LiteralPath $script:tcp08ArtifactPath -File | Where-Object {
        $_.Name -ne "artifact-hashes.json"
    } | Sort-Object Name | ForEach-Object {
        $artifactFile = $_
        try {
            [ordered]@{
                name = $artifactFile.Name
                bytes = $artifactFile.Length
                sha256 = (Get-FileHash -LiteralPath $artifactFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                status = "captured"
            }
        } catch {
            $hashError = $_
            $deferToOuterFinalizer = $artifactFile.Name -in @("controller.stdout.log", "controller.stderr.log")
            if (-not $deferToOuterFinalizer) {
                $completionErrors.Add("hash:$($artifactFile.Name)")
            }
            [ordered]@{
                name = $artifactFile.Name
                bytes = $artifactFile.Length
                sha256 = $null
                status = if ($deferToOuterFinalizer) { "deferred_to_final_outer_recalculation" } else { "capture_failed" }
                error_type = $hashError.Exception.GetType().FullName
            }
        }
    })
    Write-Tcp08Json "artifact-hashes.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-artifact-hashes.v1"
        capture = "controller point-in-time before outer pwsh redirection handles close"
        final_outer_recalculation_required = $true
        files = $hashRows
    })
    Assert-True ($missingLogs.Count -eq 0) "required externally/child-produced logs are missing: $($missingLogs -join ',')"
    Assert-True ($completionErrors.Count -eq 0) "artifact capture failed: $($completionErrors -join ',')"
    if ($script:RequireTcp08ProductMetrics) {
        Assert-True ($productEvidence.strict_validation.status -ceq "pass") "strict TCP-08 product shutdown report validation failed: $($productEvidence.strict_validation.failures -join ',')"
    }
}

function Get-NetworkFeasibilityIdentity([string]$Path, [bool]$RequireServer) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path)) "network feasibility requires IdentityLedger"
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $bytes = [IO.File]::ReadAllBytes($resolved)
    Assert-True ($bytes.Length -gt 1 -and $bytes[$bytes.Length - 1] -eq 10) "identity ledger must end in one LF"
    Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf)) "identity ledger must not have a BOM"
    Assert-True (@($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0) "identity ledger must be one LF-terminated line"
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString($bytes)
    $json = $text.Substring(0, $text.Length - 1)
    $ledger = $json | ConvertFrom-Json -Depth 4
    $keys = @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id", "guest_product",
        "guest_edition", "guest_architecture", "guest_version", "guest_build", "candidate_sha",
        "probe_sha256", "client_sha256", "server_sha256", "support_listener"
    )
    $hasTestBinaries = $ledger.PSObject.Properties.Name -ccontains "test_binaries"
    if ($hasTestBinaries) { $keys += "test_binaries" }
    Assert-True ((@($ledger.PSObject.Properties.Name) -join "|") -ceq ($keys -join "|")) "identity ledger keys are invalid"
    $listenerKeys = @("ipv4", "tcp_port", "udp_port", "pid", "owner")
    Assert-True ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -ceq ($listenerKeys -join "|")) "support listener keys are invalid"
    Assert-True (($ledger | ConvertTo-Json -Compress -Depth 4) -ceq $json) "identity ledger is not canonical JSON"
    Assert-True ($ledger.schema -is [long] -and $ledger.schema -eq 1) "identity ledger schema is invalid"
    Assert-True ($ledger.vm_name -ceq $script:expectedHyperVVmName) "identity ledger VM name is invalid"
    Assert-True ($ledger.vm_id -ceq $script:expectedHyperVVmId) "identity ledger VM ID is invalid"
    Assert-True ($ledger.checkpoint_name -ceq $script:expectedHyperVCheckpointName) "identity ledger checkpoint name is invalid"
    Assert-True ($ledger.checkpoint_id -ceq $script:expectedHyperVCheckpointId) "identity ledger checkpoint ID is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger VM ID is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger checkpoint ID is invalid"
    Assert-True ([string]$ledger.candidate_sha -cmatch '^[0-9a-f]{40}$') "identity ledger candidate SHA is invalid"
    Assert-True ([string]$ledger.probe_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger probe hash is invalid"
    Assert-True ([string]$ledger.client_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger client hash is invalid"
    Assert-True ([string]$ledger.server_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger server hash is invalid"
    if ($hasTestBinaries) {
        $testKeys = @("client", "tun", "wintun")
        Assert-True ((@($ledger.test_binaries.PSObject.Properties.Name) -join "|") -ceq ($testKeys -join "|")) "identity ledger test binary keys are invalid"
        foreach ($name in $testKeys) {
            Assert-True ([string]$ledger.test_binaries.$name -cmatch '^[0-9a-f]{64}$') "identity ledger test binary hash is invalid"
        }
    }
    if ($script:candidateTestDirectoryExplicit) {
        Assert-True $hasTestBinaries "prebuilt candidate tests require identity ledger hashes"
        $testFiles = [ordered]@{
            client = "ferrum2-client-tests.exe"
            tun = "ferrum2-tun-tests.exe"
            wintun = "ferrum2-wintun-tests.exe"
        }
        foreach ($name in $testFiles.Keys) {
            $path = Join-Path $script:resolvedCandidateTestDirectory $testFiles[$name]
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert-True ($ledger.test_binaries.$name -ceq $hash) "staged candidate test hash mismatch: $name"
        }
    }
    $probePath = (Resolve-Path -LiteralPath $PSCommandPath -ErrorAction Stop).Path
    $probeHash = (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($ledger.probe_sha256 -ceq $probeHash) "identity ledger probe hash mismatch"
    Assert-True (Test-Path -LiteralPath $binary) "staged candidate binary is missing"
    $clientHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($ledger.client_sha256 -ceq $clientHash) "staged client hash mismatch"
    if (Test-Path -LiteralPath $serverBinary) {
        $serverHash = (Get-FileHash -LiteralPath $serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-True ($ledger.server_sha256 -ceq $serverHash) "staged server hash mismatch"
    } else {
        Assert-True (-not $RequireServer) "staged server binary is missing"
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $version = [Environment]::OSVersion.Version.ToString()
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
    Assert-True ($ledger.guest_product -ceq [string]$currentVersion.ProductName) "identity ledger guest product mismatch"
    Assert-True ($ledger.guest_edition -ceq [string]$currentVersion.EditionID) "identity ledger guest edition mismatch"
    Assert-True ($ledger.guest_architecture -ceq "AMD64" -and [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "X64") "identity ledger guest architecture mismatch"
    Assert-True ($ledger.guest_version -ceq $version) "identity ledger guest version mismatch"
    Assert-True ($ledger.guest_build -ceq $build -and [string]$os.BuildNumber -ceq [string]$currentVersion.CurrentBuildNumber) "identity ledger guest build mismatch"

    $address = $null
    Assert-True ([Net.IPAddress]::TryParse([string]$ledger.support_listener.ipv4, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) "support listener address is not IPv4"
    $octets = $address.GetAddressBytes()
    Assert-True (-not [Net.IPAddress]::IsLoopback($address) -and $octets[0] -ne 0 -and $octets[0] -lt 224 -and -not ($octets[0] -eq 169 -and $octets[1] -eq 254)) "support listener address is not eligible"
    Assert-True (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $address.IPAddressToString -ErrorAction SilentlyContinue).Count -eq 0) "support listener address is guest-local"
    foreach ($name in @("tcp_port", "udp_port")) {
        Assert-True ($ledger.support_listener.$name -is [long] -and $ledger.support_listener.$name -ge 1 -and $ledger.support_listener.$name -le 65535) "support listener port is invalid"
    }
    Assert-True ($ledger.support_listener.pid -is [long] -and $ledger.support_listener.pid -ge 1 -and $ledger.support_listener.pid -le [uint32]::MaxValue) "support listener PID is invalid"
    Assert-True ([string]$ledger.support_listener.owner -cmatch '^[^\r\n]{1,256}$') "support listener owner is invalid"

    return [pscustomobject]@{
        Ledger = $ledger
        Path = $resolved
        IdentitySha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        GuestBuild = $build
        SupportAddress = $address.IPAddressToString
        TcpPort = [int]$ledger.support_listener.tcp_port
        UdpPort = [int]$ledger.support_listener.udp_port
    }
}

if ($Mode -in (@("network-feasibility", "managed-product", "full", "hard-kill") + $m17Modes)) {
    $capabilityIdentity = Get-NetworkFeasibilityIdentity $IdentityLedger ($Mode -eq "full" -or $Mode -in $m17Modes)
    $capabilityIdentityHash = $capabilityIdentity.IdentitySha256
    $capabilityEvidence = "$($capabilityIdentity.Path).evidence-$runIdentity.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $capabilityEvidence)) "network feasibility evidence baseline not absent"
}

function Get-Tcp01Boundary([hashtable]$State) {
    $yesNo = @("yes", "no")
    $gateFaults = @("none", "io", "disposed", "socket", "cancelled", "invalid_operation", "not_supported", "aggregate", "other")
    $probeFaults = @("none", "io", "disposed", "socket", "cancelled", "other")
    $stages = @("pending", "source_stream", "destination_stream", "read", "write", "shutdown")
    foreach ($name in @("GateAccepted", "GateForwardEof", "GateReverseEof", "GateComplete", "ProbeAccepted", "ProbeReadEof", "ProbeShutdown", "ProbeComplete")) {
        if (-not $State.ContainsKey($name) -or $yesNo -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("GateForwardFault", "GateReverseFault")) {
        if (-not $State.ContainsKey($name) -or $gateFaults -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    if (-not $State.ContainsKey("ProbeFault") -or $probeFaults -notcontains $State.ProbeFault) { return "UNRESOLVED" }
    foreach ($name in @("GateForwardStage", "GateReverseStage")) {
        if (-not $State.ContainsKey($name) -or $stages -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("GateForwardBytes", "GateReverseBytes")) {
        if (-not $State.ContainsKey($name) -or @("zero", "nonzero") -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    foreach ($name in @("ProbeRequest", "ProbeEcho")) {
        if (-not $State.ContainsKey($name) -or @("none", "exact", "other") -notcontains $State[$name]) { return "UNRESOLVED" }
    }
    if (-not $State.ContainsKey("AppResult") -or @("reset", "io", "success", "other") -notcontains $State.AppResult) { return "UNRESOLVED" }
    if ($State.GateAccepted -eq "no" -or $State.GateForwardBytes -eq "zero" -or $State.ProbeAccepted -eq "no") { return "BEFORE_TARGET" }
    if ($State.ProbeRequest -ne "exact" -or $State.ProbeReadEof -ne "yes" -or $State.ProbeEcho -ne "exact" -or
        $State.ProbeShutdown -ne "yes" -or $State.ProbeFault -ne "none" -or $State.ProbeComplete -ne "yes") { return "TARGET_ECHO_INCOMPLETE" }
    if ($State.GateReverseBytes -eq "zero" -or $State.GateReverseEof -ne "yes" -or
        $State.GateReverseFault -ne "none" -or $State.GateComplete -ne "yes") { return "GATE_REVERSE_INCOMPLETE" }
    if ($State.GateForwardEof -ne "yes" -or $State.GateForwardFault -ne "none") { return "UNRESOLVED" }
    if ($State.AppResult -ne "success") { return "CLIENT_AFTER_GATE_REVERSE" }
    return "COMPLETE"
}

$tcp01CompleteState = @{
    GateAccepted = "yes"; GateForwardBytes = "nonzero"; GateForwardEof = "yes"; GateForwardFault = "none"; GateForwardStage = "shutdown"
    GateReverseBytes = "nonzero"; GateReverseEof = "yes"; GateReverseFault = "none"; GateReverseStage = "shutdown"; GateComplete = "yes"
    ProbeAccepted = "yes"; ProbeRequest = "exact"; ProbeReadEof = "yes"; ProbeEcho = "exact"
    ProbeShutdown = "yes"; ProbeFault = "none"; ProbeComplete = "yes"; AppResult = "success"
}
foreach ($row in @(
    @{ Change = @{ GateAccepted = "no" }; Expected = "BEFORE_TARGET" },
    @{ Change = @{ ProbeEcho = "other" }; Expected = "TARGET_ECHO_INCOMPLETE" },
    @{ Change = @{ ProbeComplete = "no" }; Expected = "TARGET_ECHO_INCOMPLETE" },
    @{ Change = @{ GateReverseBytes = "zero" }; Expected = "GATE_REVERSE_INCOMPLETE" },
    @{ Change = @{ GateComplete = "no" }; Expected = "GATE_REVERSE_INCOMPLETE" },
    @{ Change = @{ AppResult = "reset" }; Expected = "CLIENT_AFTER_GATE_REVERSE" },
    @{ Change = @{}; Expected = "COMPLETE" },
    @{ Change = @{ GateForwardFault = "invalid" }; Expected = "UNRESOLVED" },
    @{ Change = @{ GateReverseStage = "invalid" }; Expected = "UNRESOLVED" }
)) {
    $state = $tcp01CompleteState.Clone()
    foreach ($name in $row.Change.Keys) { $state[$name] = $row.Change[$name] }
    Assert-True ((Get-Tcp01Boundary $state) -eq $row.Expected) "TCP-01 boundary table mismatch"
}

function Get-PeExportNames([byte[]]$Bytes) {
    Assert-True ($Bytes.Length -ge 64) "PE image is truncated"
    $stream = [IO.MemoryStream]::new($Bytes, $false)
    $reader = [Reflection.PortableExecutable.PEReader]::new($stream)
    try {
        $peHeader = $reader.PEHeaders.PEHeader
        Assert-True ($null -ne $peHeader) "PE optional header is missing"
        $directory = $peHeader.ExportTableDirectory
        Assert-True ($directory.RelativeVirtualAddress -gt 0 -and $directory.Size -ge 40) "PE export directory is missing"
        $directoryBlock = $reader.GetSectionData($directory.RelativeVirtualAddress)
        Assert-True ($directoryBlock.Length -ge 40) "PE export directory is truncated"
        [byte[]]$directoryBytes = $directoryBlock.GetContent(0, 40)
        [uint32]$functionCount = [BitConverter]::ToUInt32($directoryBytes, 20)
        [uint32]$nameCount = [BitConverter]::ToUInt32($directoryBytes, 24)
        Assert-True ($functionCount -eq $nameCount -and $nameCount -ge 1 -and $nameCount -le 256) "PE export count is invalid"
        [uint32]$nameTableRva = [BitConverter]::ToUInt32($directoryBytes, 32)
        Assert-True ($nameTableRva -gt 0 -and $nameTableRva -le [int]::MaxValue) "PE export name table RVA is invalid"
        $nameTableLength = [int]$nameCount * 4
        $nameTableBlock = $reader.GetSectionData([int]$nameTableRva)
        Assert-True ($nameTableBlock.Length -ge $nameTableLength) "PE export name table is truncated"
        [byte[]]$nameTableBytes = $nameTableBlock.GetContent(0, $nameTableLength)
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $names = [Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt [int]$nameCount; $index++) {
            [uint32]$nameRva = [BitConverter]::ToUInt32($nameTableBytes, $index * 4)
            Assert-True ($nameRva -gt 0 -and $nameRva -le [int]::MaxValue) "PE export name RVA is invalid"
            $nameBlock = $reader.GetSectionData([int]$nameRva)
            $boundedLength = [Math]::Min(257, $nameBlock.Length)
            Assert-True ($boundedLength -ge 2) "PE export name is truncated"
            [byte[]]$nameBytes = $nameBlock.GetContent(0, $boundedLength)
            $terminator = [Array]::IndexOf($nameBytes, [byte]0)
            Assert-True ($terminator -ge 1 -and $terminator -le 256) "PE export name is not bounded"
            $names.Add($utf8.GetString($nameBytes, 0, $terminator))
        }
        $sorted = @($names | Sort-Object -Unique)
        Assert-True ($sorted.Count -eq [int]$nameCount) "PE export names are not unique"
        return $sorted
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Wait-AdapterReady(
    [string]$Name,
    [int]$TimeoutSeconds = 20,
    [bool]$Managed = $false,
    [bool]$ManagedDns = $false,
    [string[]]$ManagedCapturePrefixes = @("0.0.0.0/1", "128.0.0.0/1")
) {
    $expectedCapturePrefixes = @($ManagedCapturePrefixes | Sort-Object -Unique)
    if ($Managed) {
        Assert-True ($expectedCapturePrefixes.Count -ge 1 -and
            $expectedCapturePrefixes.Count -eq $ManagedCapturePrefixes.Count -and
            @($expectedCapturePrefixes | Where-Object {
                [string]::IsNullOrWhiteSpace($_)
            }).Count -eq 0) "managed state readiness capture prefix contract is invalid"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
        }
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $v4 = @($addresses | Where-Object { $_.IPAddress -eq "198.18.0.2" -and $_.PrefixLength -eq 30 -and $_.AddressState -eq "Preferred" })
            $v6 = @($addresses | Where-Object { $_.IPAddress -eq "fd00::2" -and $_.PrefixLength -eq 126 -and $_.AddressState -eq "Preferred" })
            if ($v4.Count -eq 1 -and $v6.Count -eq 1) {
                if (-not $Managed) { return $adapter }
                $capturePrefixes = @(
                    Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                        Where-Object { $expectedCapturePrefixes -ccontains [string]$_.DestinationPrefix } |
                        Sort-Object DestinationPrefix |
                        ForEach-Object { $_.DestinationPrefix }
                )
                $dnsReady = -not $ManagedDns
                if ($ManagedDns) {
                    $dnsAddresses = @(Get-TunIpv4Dns $adapter.ifIndex)
                    $dnsReady = ($dnsAddresses -join "|") -ceq "198.18.0.1"
                }
                if (($capturePrefixes -join "|") -ceq ($expectedCapturePrefixes -join "|") -and $dnsReady) {
                    try {
                        $finalCapturePrefixes = @(
                            Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                                Where-Object { $expectedCapturePrefixes -ccontains [string]$_.DestinationPrefix } |
                                Sort-Object DestinationPrefix |
                                ForEach-Object { $_.DestinationPrefix }
                        )
                        Assert-SnapshotEqual $expectedCapturePrefixes $finalCapturePrefixes "managed state readiness capture"
                        if ($ManagedDns) {
                            $finalDnsAddresses = @(Get-TunIpv4Dns $adapter.ifIndex)
                            Assert-SnapshotEqual @("198.18.0.1") $finalDnsAddresses "managed state readiness DNS"
                        }
                    } catch { throw "managed state readiness readback failed" }
                    if ($script:activeProcess) {
                        $script:activeProcess.Refresh()
                        if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
                    }
                    return $adapter
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($script:activeProcess) {
        $script:activeProcess.Refresh()
        if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
    }
    if ($Managed) { throw "managed state readiness timeout" }
    throw "adapter readiness timeout"
}

function Wait-AdapterAbsent([string]$Name, [int]$TimeoutSeconds = 20, [int]$RequiredSamples = 4) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSamples = 0
    do {
        $absent = $false
        try {
            $absent = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                Where-Object { $_.Name -ceq $Name }).Count -eq 0 -and
                @(Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop |
                    Where-Object { $_.PNPDeviceID -like 'SWD\Wintun\*' }).Count -eq 0
        } catch { $absent = $false }
        if ($absent) { $stableSamples++ }
        else { $stableSamples = 0 }
        if ($stableSamples -ge $RequiredSamples) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "adapter cleanup timeout"
}

function Get-InterfaceAddressSnapshot([int]$InterfaceIndex) {
    return @(
        Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue |
            Sort-Object AddressFamily, IPAddress, PrefixLength |
            ForEach-Object { "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.AddressState)" }
    )
}

function Get-InterfaceRouteSnapshot([int]$InterfaceIndex) {
    return @(
        Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Sort-Object AddressFamily, DestinationPrefix, NextHop |
            ForEach-Object { "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)" }
    )
}

function Assert-SnapshotEqual([object[]]$Expected, [object[]]$Actual, [string]$Label) {
    $difference = @(Compare-Object -ReferenceObject @($Expected) -DifferenceObject @($Actual))
    Assert-True ($difference.Count -eq 0) "$Label snapshot changed"
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Server.ExclusiveAddressUse = $true
    $listener.Start()
    $udp = $null
    try {
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $udp.Client.ExclusiveAddressUse = $true
        $udp.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $port))
        return $port
    } finally {
        if ($udp) { $udp.Dispose() }
        $listener.Stop()
    }
}

function Get-UniqueTcpPort {
    do { $port = Get-FreeTcpPort } while (-not $script:usedTcpPorts.Add($port))
    return $port
}

function Get-Metrics([int]$Port, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try { return (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/metrics" -TimeoutSec 1).Content }
        catch {
            if ($script:activeProcess) {
                $script:activeProcess.Refresh()
                if ($script:activeProcess.HasExited) { throw "candidate failed before metrics became ready" }
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "metrics readiness timeout"
}

function Get-CounterValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))_total ([0-9]+)$")
    Assert-True $match.Success "missing no-label counter: $Name"
    return [uint64]$match.Groups[1].Value
}

function Get-ClientGaugeValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))\{role=`"client`"\} ([0-9]+)$")
    Assert-True $match.Success "missing client gauge: $Name"
    return [uint64]$match.Groups[1].Value
}

function Get-ClientCounterValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))_total\{role=`"client`"\} ([0-9]+)$")
    Assert-True $match.Success "missing client counter: $Name"
    return [uint64]$match.Groups[1].Value
}

function Get-AdapterTraffic([string]$Name) {
    $statistics = Get-NetAdapterStatistics -Name $Name -ErrorAction Stop
    return @{
        ReceivedBytes = [uint64]$statistics.ReceivedBytes
        SentBytes = [uint64]$statistics.SentBytes
        ReceivedUnicastPackets = [uint64]$statistics.ReceivedUnicastPackets
        SentUnicastPackets = [uint64]$statistics.SentUnicastPackets
        ReceivedPacketErrors = [uint64]$statistics.ReceivedPacketErrors
        OutboundPacketErrors = [uint64]$statistics.OutboundPacketErrors
        ReceivedDiscardedPackets = [uint64]$statistics.ReceivedDiscardedPackets
        OutboundDiscardedPackets = [uint64]$statistics.OutboundDiscardedPackets
    }
}

function Update-PerformancePeaks([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    $Process.Refresh()
    $script:performanceRssBytes = [Math]::Max($script:performanceRssBytes, [uint64]$Process.WorkingSet64)
    $script:performanceHandlesPeak = [Math]::Max($script:performanceHandlesPeak, [uint64]$Process.HandleCount)
    $script:performanceThreadsPeak = [Math]::Max($script:performanceThreadsPeak, [uint64]$Process.Threads.Count)
    $metrics = Get-Metrics $MetricsPort
    $script:performanceUdpSessionsPeak = [Math]::Max(
        $script:performanceUdpSessionsPeak,
        (Get-ClientGaugeValue $metrics "ferrum2_udp_sessions_active")
    )
    $script:performanceUdpBufferedBytesPeak = [Math]::Max(
        $script:performanceUdpBufferedBytesPeak,
        (Get-ClientGaugeValue $metrics "ferrum2_udp_buffered_bytes")
    )
}

function Start-PerformanceSample([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    $Process.Refresh()
    $script:performanceCpuBaseline = $Process.TotalProcessorTime.TotalMilliseconds
    $metrics = Get-Metrics $MetricsPort
    $script:performanceTunAcceptedBaseline = Get-CounterValue $metrics "ferrum2_tun_packets_accepted"
    $script:performanceTrafficBaseline = Get-AdapterTraffic $script:adapterName
    $script:performanceFieldsCollected = $true
    Update-PerformancePeaks $Process $MetricsPort
}

function Complete-PerformanceSample([System.Diagnostics.Process]$Process, [int]$MetricsPort) {
    Update-PerformancePeaks $Process $MetricsPort
    $Process.Refresh()
    $cpu = $Process.TotalProcessorTime.TotalMilliseconds
    Assert-True ($cpu -ge $script:performanceCpuBaseline) "candidate CPU counter moved backwards"
    $script:performanceCpuMilliseconds += [uint64][Math]::Ceiling($cpu - $script:performanceCpuBaseline)
    $metrics = Get-Metrics $MetricsPort
    $accepted = Get-CounterValue $metrics "ferrum2_tun_packets_accepted"
    Assert-True ($accepted -ge $script:performanceTunAcceptedBaseline) "TUN accepted counter moved backwards"
    $script:performanceTunAcceptedDelta += $accepted - $script:performanceTunAcceptedBaseline
    $after = Get-AdapterTraffic $script:adapterName
    foreach ($property in $script:performanceTrafficBaseline.Keys) {
        Assert-True ($after[$property] -ge $script:performanceTrafficBaseline[$property]) "adapter counter moved backwards: $property"
    }
    $script:performanceAdapterRxBytes += $after.ReceivedBytes - $script:performanceTrafficBaseline.ReceivedBytes
    $script:performanceAdapterTxBytes += $after.SentBytes - $script:performanceTrafficBaseline.SentBytes
    $script:performanceAdapterRxPackets += $after.ReceivedUnicastPackets - $script:performanceTrafficBaseline.ReceivedUnicastPackets
    $script:performanceAdapterTxPackets += $after.SentUnicastPackets - $script:performanceTrafficBaseline.SentUnicastPackets
    $script:performanceAdapterRxErrors += $after.ReceivedPacketErrors - $script:performanceTrafficBaseline.ReceivedPacketErrors
    $script:performanceAdapterTxErrors += $after.OutboundPacketErrors - $script:performanceTrafficBaseline.OutboundPacketErrors
    $script:performanceAdapterRxDiscards += $after.ReceivedDiscardedPackets - $script:performanceTrafficBaseline.ReceivedDiscardedPackets
    $script:performanceAdapterTxDiscards += $after.OutboundDiscardedPackets - $script:performanceTrafficBaseline.OutboundDiscardedPackets
}

function Assert-InterfaceGone([string]$Name, [Nullable[int]]$InterfaceIndex) {
    Assert-True (-not (Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction SilentlyContinue)) "adapter leaked"
    Assert-True (@(Get-NetIPAddress -InterfaceAlias $Name -ErrorAction SilentlyContinue).Count -eq 0) "address rows leaked"
    Assert-True (@(Get-NetRoute -InterfaceAlias $Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route rows leaked"
    if ($null -ne $InterfaceIndex) {
        Assert-True (@(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "address owner leaked"
        Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route owner leaked"
    }
}

function Wait-ProcessExit([System.Diagnostics.Process]$Process, [int]$TimeoutSeconds) {
    return [Ferrum2ProcessGroup]::Wait([uint32]$Process.Id, [uint32]($TimeoutSeconds * 1000))
}

function Start-Candidate([string]$Executable, [string]$Configuration) {
    $arguments = "--config `"$Configuration`""
    $stdoutPath = if ($script:tcp08Enabled) { Join-Path $script:tcp08ArtifactPath "client.stdout.log" } else { $null }
    $stderrPath = if ($script:tcp08Enabled) { Join-Path $script:tcp08ArtifactPath "client.stderr.log" } else { $null }
    $id = [Ferrum2ProcessGroup]::Start(
        $Executable,
        $arguments,
        (Split-Path -Parent $Executable),
        $stdoutPath,
        $stderrPath
    )
    return Get-Process -Id $id
}

function Stop-Candidate([System.Diagnostics.Process]$Process) {
    if ($Process.HasExited) { throw "candidate stopped before controller shutdown" }
    Assert-True ([Ferrum2ProcessGroup]::Break([uint32]$Process.Id)) "CTRL_BREAK delivery failed"
    Assert-True (Wait-ProcessExit $Process 20) "candidate did not exit"
    $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
    Assert-True ($exitCode -eq 0) "candidate shutdown failed: exit=$exitCode"
    [Ferrum2ProcessGroup]::Close([uint32]$Process.Id)
}

function Wait-TcpListener(
    [int]$Port,
    [System.Diagnostics.Process]$Process,
    [string]$Label,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $foreignListenerPids = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
            Add-Tcp08Event "server_listener_process_exited" ([ordered]@{
                label = $Label
                port = $Port
                process_id = [uint32]$Process.Id
                exit_code = $exitCode
            })
            throw "TCP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
        }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
        if (@($listeners | Where-Object { [uint32]$_.OwningProcess -eq [uint32]$Process.Id }).Count -gt 0) {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                Add-Tcp08Event "server_listener_ready" ([ordered]@{
                    label = $Label
                    port = $Port
                    process_id = [uint32]$Process.Id
                })
                return
            }
        }
        $foreignListenerPids = @($listeners |
            Where-Object { [uint32]$_.OwningProcess -ne [uint32]$Process.Id } |
            ForEach-Object { [uint32]$_.OwningProcess } |
            Sort-Object -Unique)
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    $Process.Refresh()
    if ($Process.HasExited) {
        $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
        Add-Tcp08Event "server_listener_process_exited" ([ordered]@{
            label = $Label
            port = $Port
            process_id = [uint32]$Process.Id
            exit_code = $exitCode
        })
        throw "TCP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
    }
    $foreignText = if ($foreignListenerPids.Count -eq 0) { "none" } else { $foreignListenerPids -join "," }
    Add-Tcp08Event "server_listener_readiness_timeout" ([ordered]@{
        label = $Label
        port = $Port
        process_id = [uint32]$Process.Id
        foreign_listener_process_ids = @($foreignListenerPids)
    })
    throw "TCP listener readiness timeout: label=$Label port=$Port expected_pid=$($Process.Id) foreign_listener_pids=$foreignText"
}

function Wait-UdpListener(
    [int]$Port,
    [System.Diagnostics.Process]$Process,
    [string]$Label,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSamples = 0
    $foreignListenerPids = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
            throw "UDP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
        }
        $listeners = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue)
        $owned = @($listeners | Where-Object {
            $_.LocalAddress -ceq "127.0.0.1" -and [uint32]$_.OwningProcess -eq [uint32]$Process.Id
        })
        if ($owned.Count -eq 1) {
            $stableSamples++
            if ($stableSamples -ge 2) {
                $Process.Refresh()
                if (-not $Process.HasExited) { return }
            }
        } else {
            $stableSamples = 0
        }
        $foreignListenerPids = @($listeners |
            Where-Object { [uint32]$_.OwningProcess -ne [uint32]$Process.Id } |
            ForEach-Object { [uint32]$_.OwningProcess } |
            Sort-Object -Unique)
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    $foreignText = if ($foreignListenerPids.Count -eq 0) { "none" } else { $foreignListenerPids -join "," }
    throw "UDP listener readiness timeout: label=$Label port=$Port expected_pid=$($Process.Id) foreign_listener_pids=$foreignText"
}

function Start-Server([string]$Executable, [string]$Configuration) {
    $arguments = "--config `"$Configuration`""
    $stdoutPath = if ($script:tcp08Enabled) { Join-Path $script:tcp08ArtifactPath "server.stdout.log" } else { $null }
    $stderrPath = if ($script:tcp08Enabled) { Join-Path $script:tcp08ArtifactPath "server.stderr.log" } else { $null }
    $id = [Ferrum2ProcessGroup]::Start(
        $Executable,
        $arguments,
        (Split-Path -Parent $Executable),
        $stdoutPath,
        $stderrPath
    )
    $process = Get-Process -Id $id
    $script:serverProcesses.Add($process)
    return $process
}

function Add-TunRoute([int]$InterfaceIndex, [string]$DestinationPrefix, [int]$RouteMetric = 1) {
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "controller route baseline not absent"
    $nextHop = if ($DestinationPrefix.Contains(":")) { "::" } else { "0.0.0.0" }
    $route = New-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -NextHop $nextHop -RouteMetric $RouteMetric -PolicyStore ActiveStore
    $script:ownedRoutes.Add($route)
    return $route
}

function Add-TargetAddress([string]$Address, [bool]$SkipAsSource = $true) {
    Assert-True (@(Get-NetIPAddress -IPAddress $Address -ErrorAction SilentlyContinue).Count -eq 0) "target address baseline not absent"
    $prefix = if ($Address.Contains(":")) { 128 } else { 32 }
    $prefixText = "$Address/$prefix"
    Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "target route baseline not absent"
    Add-Content -LiteralPath $script:addressJournal -Value $Address -Encoding utf8
    $row = New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore ActiveStore
    $script:ownedAddresses.Add($row)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $current = Get-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -ErrorAction SilentlyContinue
        if ($current -and $current.AddressState -eq "Preferred") { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-True ($current -and $current.AddressState -eq "Preferred") "controller target address readiness timeout"
    $localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if (-not $localRoute) {
        $nextHop = if ($Address.Contains(":")) { "::" } else { "0.0.0.0" }
        $localRoute = New-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -NextHop $nextHop -RouteMetric 1 -PolicyStore ActiveStore
    } else {
        $localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru
    }
    $script:ownedTargetRoutes.Add($localRoute)
    return $row
}

Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.ComponentModel;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class Ferrum2CtrlBreakResult {
    public bool ProcessKnown { get; internal set; }
    public bool SeparateConsole { get; internal set; }
    public bool HadConsole { get; internal set; }
    public bool FreeConsoleBeforeAttachResult { get; internal set; }
    public int FreeConsoleBeforeAttachWin32Error { get; internal set; }
    public bool AttachAttempted { get; internal set; }
    public bool AttachConsoleResult { get; internal set; }
    public int AttachConsoleWin32Error { get; internal set; }
    public bool SetConsoleCtrlHandlerResult { get; internal set; }
    public int SetConsoleCtrlHandlerWin32Error { get; internal set; }
    public bool GenerateConsoleCtrlEventResult { get; internal set; }
    public int GenerateConsoleCtrlEventWin32Error { get; internal set; }
    public bool ResetConsoleCtrlHandlerResult { get; internal set; }
    public int ResetConsoleCtrlHandlerWin32Error { get; internal set; }
    public bool FreeConsoleAfterResult { get; internal set; }
    public int FreeConsoleAfterWin32Error { get; internal set; }
    public long SendStartedTimestamp { get; internal set; }
    public long SendReturnedTimestamp { get; internal set; }
    public long InternalWaitStartedTimestamp { get; internal set; }
    public long InternalWaitReturnedTimestamp { get; internal set; }
    public double SendDurationMilliseconds { get; internal set; }
    public double InternalWaitMilliseconds { get; internal set; }
    public double TotalDurationMilliseconds { get; internal set; }
    public bool Succeeded { get; internal set; }
}

public static class Ferrum2ProcessGroup {
    private static readonly object Sync = new object();
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const uint FILE_APPEND_DATA = 0x00000004;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private static readonly Dictionary<uint, ProcessEntry> Processes = new Dictionary<uint, ProcessEntry>();
    private sealed class ProcessEntry {
        public IntPtr Handle;
        public bool SeparateConsole;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars; public int yChars;
        public int fill; public int flags; public short show; public short reserved2; public IntPtr reservedBytes;
        public IntPtr stdin; public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX {
        public STARTUPINFO startup;
        public IntPtr attributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int length;
        public IntPtr securityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr process; public IntPtr thread; public uint processId; public uint threadId; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessExtended(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount,
        uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeConsole();

    private static bool HasConsole() {
        return GetConsoleProcessList(new uint[1], 1) != 0;
    }

    private static IntPtr OpenInheritable(string path, uint access, uint disposition) {
        var security = new SECURITY_ATTRIBUTES {
            length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
            securityDescriptor = IntPtr.Zero,
            inheritHandle = true
        };
        var handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ref security, disposition, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW redirected stream");
        return handle;
    }

    public static int Start(string application, string arguments, string directory) {
        return Start(application, arguments, directory, null, null);
    }

    public static int Start(string application, string arguments, string directory, string stdoutPath, string stderrPath) {
        var separateConsole = !HasConsole();
        var startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(startup);
        if (separateConsole) startup.flags = STARTF_USESHOWWINDOW;
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        var flags = CREATE_NEW_PROCESS_GROUP | (separateConsole ? CREATE_NEW_CONSOLE : 0);
        var redirect = !String.IsNullOrWhiteSpace(stdoutPath) || !String.IsNullOrWhiteSpace(stderrPath);
        if (redirect && (String.IsNullOrWhiteSpace(stdoutPath) || String.IsNullOrWhiteSpace(stderrPath)))
            throw new ArgumentException("stdout and stderr redirection paths must be supplied together");
        PROCESS_INFORMATION process;
        if (!redirect) {
            if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, directory, ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
        } else {
            IntPtr stdoutHandle = IntPtr.Zero;
            IntPtr stderrHandle = IntPtr.Zero;
            IntPtr stdinHandle = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            try {
                stdoutHandle = OpenInheritable(stdoutPath, FILE_APPEND_DATA, OPEN_ALWAYS);
                stderrHandle = OpenInheritable(stderrPath, FILE_APPEND_DATA, OPEN_ALWAYS);
                stdinHandle = OpenInheritable("NUL", GENERIC_READ, OPEN_EXISTING);
                var startupEx = new STARTUPINFOEX();
                startupEx.startup.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startupEx.startup.flags = (separateConsole ? STARTF_USESHOWWINDOW : 0) | STARTF_USESTDHANDLES;
                startupEx.startup.stdin = stdinHandle;
                startupEx.startup.stdout = stdoutHandle;
                startupEx.startup.stderr = stderrHandle;
                IntPtr attributeBytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
                if (attributeBytes == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList size");
                attributeList = Marshal.AllocHGlobal(attributeBytes);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
                startupEx.attributeList = attributeList;
                handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleList, 0 * IntPtr.Size, stdinHandle);
                Marshal.WriteIntPtr(handleList, 1 * IntPtr.Size, stdoutHandle);
                Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stderrHandle);
                if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleList, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute handle list");
                if (!CreateProcessExtended(application, command, IntPtr.Zero, IntPtr.Zero, true,
                    flags | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, directory, ref startupEx, out process))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW redirected");
            } finally {
                if (attributeList != IntPtr.Zero) {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                if (stdinHandle != IntPtr.Zero && stdinHandle != INVALID_HANDLE_VALUE) CloseHandle(stdinHandle);
                if (stdoutHandle != IntPtr.Zero && stdoutHandle != INVALID_HANDLE_VALUE) CloseHandle(stdoutHandle);
                if (stderrHandle != IntPtr.Zero && stderrHandle != INVALID_HANDLE_VALUE) CloseHandle(stderrHandle);
            }
        }
        CloseHandle(process.thread);
        lock (Sync) Processes.Add(process.processId, new ProcessEntry { Handle = process.process, SeparateConsole = separateConsole });
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return WaitForSingleObject(process.Handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) throw new InvalidOperationException();
        uint exitCode; if (!GetExitCodeProcess(process.Handle, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)exitCode);
    }
    public static bool Terminate(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return TerminateProcess(process.Handle, 1);
    }
    public static void Close(uint processId) {
        ProcessEntry process;
        lock (Sync) { if (!Processes.TryGetValue(processId, out process)) return; Processes.Remove(processId); }
        CloseHandle(process.Handle);
    }
    public static Ferrum2CtrlBreakResult BreakDetailed(uint processGroup) {
        var total = Stopwatch.StartNew();
        var result = new Ferrum2CtrlBreakResult();
        ProcessEntry process;
        lock (Sync) {
            if (!Processes.TryGetValue(processGroup, out process)) {
                total.Stop();
                result.TotalDurationMilliseconds = total.Elapsed.TotalMilliseconds;
                return result;
            }
        }
        result.ProcessKnown = true;
        result.SeparateConsole = process.SeparateConsole;
        result.HadConsole = HasConsole();
        var attached = false;
        try {
            if (process.SeparateConsole) {
                result.FreeConsoleBeforeAttachResult = FreeConsole();
                result.FreeConsoleBeforeAttachWin32Error = result.FreeConsoleBeforeAttachResult ? 0 : Marshal.GetLastWin32Error();
                result.AttachAttempted = true;
                result.AttachConsoleResult = AttachConsole(processGroup);
                result.AttachConsoleWin32Error = result.AttachConsoleResult ? 0 : Marshal.GetLastWin32Error();
                if (!result.AttachConsoleResult) return result;
                attached = true;
            }
            result.SetConsoleCtrlHandlerResult = SetConsoleCtrlHandler(IntPtr.Zero, true);
            result.SetConsoleCtrlHandlerWin32Error = result.SetConsoleCtrlHandlerResult ? 0 : Marshal.GetLastWin32Error();
            if (!result.SetConsoleCtrlHandlerResult) return result;
            try {
                result.SendStartedTimestamp = Stopwatch.GetTimestamp();
                result.GenerateConsoleCtrlEventResult = GenerateConsoleCtrlEvent(1, processGroup);
                result.GenerateConsoleCtrlEventWin32Error = result.GenerateConsoleCtrlEventResult ? 0 : Marshal.GetLastWin32Error();
                result.SendReturnedTimestamp = Stopwatch.GetTimestamp();
                result.SendDurationMilliseconds = (result.SendReturnedTimestamp - result.SendStartedTimestamp) * 1000.0 / Stopwatch.Frequency;
                result.Succeeded = result.GenerateConsoleCtrlEventResult;
                return result;
            }
            finally {
                result.InternalWaitStartedTimestamp = Stopwatch.GetTimestamp();
                Thread.Sleep(250);
                result.InternalWaitReturnedTimestamp = Stopwatch.GetTimestamp();
                result.InternalWaitMilliseconds =
                    (result.InternalWaitReturnedTimestamp - result.InternalWaitStartedTimestamp) * 1000.0 / Stopwatch.Frequency;
                result.ResetConsoleCtrlHandlerResult = SetConsoleCtrlHandler(IntPtr.Zero, false);
                result.ResetConsoleCtrlHandlerWin32Error = result.ResetConsoleCtrlHandlerResult ? 0 : Marshal.GetLastWin32Error();
            }
        }
        finally {
            if (attached) {
                result.FreeConsoleAfterResult = FreeConsole();
                result.FreeConsoleAfterWin32Error = result.FreeConsoleAfterResult ? 0 : Marshal.GetLastWin32Error();
            }
            total.Stop();
            result.TotalDurationMilliseconds = total.Elapsed.TotalMilliseconds;
        }
    }
    public static bool Break(uint processGroup) { return BreakDetailed(processGroup).Succeeded; }
}

public sealed class Ferrum2TcpGateObservation {
    private long clientToServerBytes;
    private long serverToClientBytes;
    private int clientToServerEof;
    private int serverToClientEof;
    private int sessionComplete;
    private string clientToServerStage = "pending";
    private string serverToClientStage = "pending";
    private string clientToServerFault;
    private string serverToClientFault;

    public string ClientToServerBytes { get { return Interlocked.Read(ref clientToServerBytes) == 0 ? "zero" : "nonzero"; } }
    public string ServerToClientBytes { get { return Interlocked.Read(ref serverToClientBytes) == 0 ? "zero" : "nonzero"; } }
    public string ClientToServerStage { get { return Volatile.Read(ref clientToServerStage); } }
    public string ServerToClientStage { get { return Volatile.Read(ref serverToClientStage); } }
    public string ClientToServerEof { get { return Volatile.Read(ref clientToServerEof) == 0 ? "no" : "yes"; } }
    public string ServerToClientEof { get { return Volatile.Read(ref serverToClientEof) == 0 ? "no" : "yes"; } }
    public string ClientToServerFault { get { return Volatile.Read(ref clientToServerFault) ?? "none"; } }
    public string ServerToClientFault { get { return Volatile.Read(ref serverToClientFault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }

    internal void AddBytes(bool forward, int count) {
        if (forward) Interlocked.Add(ref clientToServerBytes, count);
        else Interlocked.Add(ref serverToClientBytes, count);
    }
    internal void MarkEof(bool forward) {
        if (forward) Volatile.Write(ref clientToServerEof, 1);
        else Volatile.Write(ref serverToClientEof, 1);
    }
    internal void SetStage(bool forward, string stage) {
        if (forward) Volatile.Write(ref clientToServerStage, stage);
        else Volatile.Write(ref serverToClientStage, stage);
    }
    internal void Fail(bool forward, string fault) {
        if (forward) Interlocked.CompareExchange(ref clientToServerFault, fault, null);
        else Interlocked.CompareExchange(ref serverToClientFault, fault, null);
    }
    internal void FailBoth(string fault) { Fail(true, fault); Fail(false, fault); }
    internal void Complete() { Volatile.Write(ref sessionComplete, 1); }
}

internal static class Ferrum2BackgroundTaskCleanup {
    internal const int TimeoutMilliseconds = 5000;

    internal static long CreateDeadline() {
        return Environment.TickCount64 + TimeoutMilliseconds;
    }

    internal static Exception Wait(Task task, long deadline, string name) {
        var remaining = deadline - Environment.TickCount64;
        var boundedMilliseconds = remaining <= 0
            ? 0
            : (int)Math.Min(remaining, (long)Int32.MaxValue);
        try {
            if (!task.Wait(boundedMilliseconds)) {
                return new TimeoutException(name + " did not stop within the bounded cleanup timeout");
            }
        } catch (AggregateException error) {
            return new InvalidOperationException(name + " faulted during bounded cleanup", error.Flatten());
        }
        return task.IsCompleted
            ? null
            : new TimeoutException(name + " did not report completion after bounded cleanup wait");
    }
}

public sealed class Ferrum2TcpGate : IDisposable {
    private readonly TcpListener listener;
    private readonly int upstreamPort;
    private readonly ConcurrentDictionary<int, ManualResetEventSlim> releases = new ConcurrentDictionary<int, ManualResetEventSlim>();
    private readonly ConcurrentDictionary<int, Ferrum2TcpGateObservation> observations = new ConcurrentDictionary<int, Ferrum2TcpGateObservation>();
    private readonly ConcurrentBag<TcpClient> clients = new ConcurrentBag<TcpClient>();
    private readonly ConcurrentBag<Task> sessionTasks = new ConcurrentBag<Task>();
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly object clientSync = new object();
    private readonly Task acceptTask;
    private int accepted;
    private int disposed;

    public Ferrum2TcpGate(int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        acceptTask = Task.Run(AcceptLoop);
    }

    public int Accepted { get { return Volatile.Read(ref accepted); } }

    public bool WaitAccepted(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Accepted >= expected) return true;
            Thread.Sleep(10);
        }
        return Accepted >= expected;
    }

    public bool WaitCompleted(int index, int milliseconds) {
        Ferrum2TcpGateObservation observation;
        if (!observations.TryGetValue(index, out observation)) return false;
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (observation.SessionComplete == "yes") return true;
            Thread.Sleep(10);
        }
        return observation.SessionComplete == "yes";
    }

    public Ferrum2TcpGateObservation Observation(int index) {
        Ferrum2TcpGateObservation observation;
        return observations.TryGetValue(index, out observation) ? observation : null;
    }

    public void Release(int index) {
        ManualResetEventSlim release;
        if (!releases.TryGetValue(index, out release)) throw new InvalidOperationException("gate session missing");
        release.Set();
    }

    private async Task AcceptLoop() {
        try {
            while (!stopped.IsCancellationRequested) {
                var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                if (!RegisterClient(client)) return;
                var index = Accepted + 1;
                var release = new ManualResetEventSlim(false);
                var observation = new Ferrum2TcpGateObservation();
                releases[index] = release;
                observations[index] = observation;
                Volatile.Write(ref accepted, index);
                var sessionTask = Task.Run(() => RunSession(client, release, observation));
                sessionTasks.Add(sessionTask);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    private void RunSession(TcpClient client, ManualResetEventSlim release, Ferrum2TcpGateObservation observation) {
        try {
            release.Wait(stopped.Token);
            using (client)
            using (var upstream = new TcpClient(AddressFamily.InterNetwork)) {
                if (!RegisterClient(upstream)) return;
                upstream.Connect(IPAddress.Loopback, upstreamPort);
                observation.SetStage(true, "source_stream");
                observation.SetStage(false, "destination_stream");
                var clientStream = client.GetStream();
                observation.SetStage(true, "destination_stream");
                observation.SetStage(false, "source_stream");
                var upstreamStream = upstream.GetStream();
                var first = Pump(clientStream, upstreamStream, upstream.Client, observation, true);
                var second = Pump(upstreamStream, clientStream, client.Client, observation, false);
                Task.WaitAll(first, second);
            }
        } catch (OperationCanceledException) { observation.FailBoth("cancelled"); }
        catch (IOException) { observation.FailBoth("io"); }
        catch (ObjectDisposedException) { observation.FailBoth("disposed"); }
        catch (SocketException) { observation.FailBoth("socket"); }
        catch (InvalidOperationException) { observation.FailBoth("invalid_operation"); }
        catch (NotSupportedException) { observation.FailBoth("not_supported"); }
        catch (AggregateException) { observation.FailBoth("aggregate"); }
        catch (Exception) { observation.FailBoth("other"); }
        finally { observation.Complete(); }
    }

    private static async Task Pump(NetworkStream input, NetworkStream output, Socket destination, Ferrum2TcpGateObservation observation, bool forward) {
        try {
            var buffer = new byte[4096];
            while (true) {
                observation.SetStage(forward, "read");
                var count = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) { observation.MarkEof(forward); break; }
                observation.SetStage(forward, "write");
                await output.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                observation.AddBytes(forward, count);
            }
            observation.SetStage(forward, "shutdown");
            try { destination.Shutdown(SocketShutdown.Send); }
            catch (SocketException) { observation.Fail(forward, "socket"); }
        } catch (OperationCanceledException) { observation.Fail(forward, "cancelled"); }
        catch (IOException) { observation.Fail(forward, "io"); }
        catch (ObjectDisposedException) { observation.Fail(forward, "disposed"); }
        catch (SocketException) { observation.Fail(forward, "socket"); }
        catch (InvalidOperationException) { observation.Fail(forward, "invalid_operation"); }
        catch (NotSupportedException) { observation.Fail(forward, "not_supported"); }
        catch (Exception) { observation.Fail(forward, "other"); }
    }

    private void ReleaseSessions() {
        foreach (var release in releases.Values) release.Set();
    }

    private bool RegisterClient(TcpClient client) {
        lock (clientSync) {
            if (Volatile.Read(ref disposed) != 0) {
                client.Dispose();
                return false;
            }
            clients.Add(client);
            return true;
        }
    }

    private void CloseClients() {
        lock (clientSync) {
            TcpClient client;
            while (clients.TryTake(out client)) client.Dispose();
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        listener.Stop();
        ReleaseSessions();
        CloseClients();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var failures = new List<Exception>();
        var acceptFailure = Ferrum2BackgroundTaskCleanup.Wait(acceptTask, deadline, "TCP gate accept task");
        if (acceptFailure != null) failures.Add(acceptFailure);
        if (!acceptTask.IsCompleted) throw failures[0];

        // AcceptLoop can win an accept race immediately before listener.Stop(). Once
        // it has joined, no later client or session can escape these final snapshots.
        ReleaseSessions();
        CloseClients();
        foreach (var sessionTask in sessionTasks.ToArray()) {
            var sessionFailure = Ferrum2BackgroundTaskCleanup.Wait(sessionTask, deadline, "TCP gate session task");
            if (sessionFailure != null) failures.Add(sessionFailure);
        }
        foreach (var sessionTask in sessionTasks) {
            if (!sessionTask.IsCompleted) {
                throw failures.Count == 1
                    ? failures[0]
                    : new AggregateException("TCP gate tasks did not complete during bounded cleanup", failures);
            }
        }

        foreach (var release in releases.Values) release.Dispose();
        stopped.Dispose();
        if (failures.Count == 1) throw failures[0];
        if (failures.Count > 1) throw new AggregateException("TCP gate tasks faulted during bounded cleanup", failures);
    }
}

public sealed class Ferrum2TcpProbe : IDisposable {
    private readonly TcpListener listener;
    private readonly string mode;
    private readonly Task worker;
    private readonly ManualResetEventSlim accepted = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim completed = new ManualResetEventSlim(false);
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly object clientSync = new object();
    private readonly object signalSync = new object();
    private TcpClient client;
    private byte[] received = new byte[0];
    private long echoBytes;
    private int readEof;
    private int sendShutdown;
    private int sessionComplete;
    private int readAttempts;
    private int disposed;
    private int signalsDisposed;
    private string fault;

    public Ferrum2TcpProbe(string address, int port, string mode) {
        this.mode = mode;
        listener = new TcpListener(IPAddress.Parse(address), port);
        listener.Start();
        worker = Task.Run(Run);
    }

    public bool WaitAccepted(int milliseconds) { return accepted.Wait(milliseconds); }
    public bool WaitCompleted(int milliseconds) { return completed.Wait(milliseconds); }
    public byte[] Received { get { return received; } }
    public long EchoByteCount { get { return Interlocked.Read(ref echoBytes); } }
    public string ReadEof { get { return Volatile.Read(ref readEof) == 0 ? "no" : "yes"; } }
    public string SendShutdown { get { return Volatile.Read(ref sendShutdown) == 0 ? "no" : "yes"; } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }
    public int ReadAttempts { get { return Volatile.Read(ref readAttempts); } }
    public string WorkerStatus { get { return worker.Status.ToString(); } }
    public bool ListenerActive {
        get {
            if (Volatile.Read(ref disposed) != 0) return false;
            try { return listener.Server != null && listener.Server.IsBound; }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public bool AcceptedSocketConnected {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return false;
            try { return current.Connected; }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public bool AcceptedSocketOpen {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return false;
            try {
                var socket = current.Client;
                return socket != null && socket.Connected && !(socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0);
            }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public int AcceptedSocketAvailable {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return 0;
            try { return current.Client.Available; }
            catch (ObjectDisposedException) { return 0; }
            catch (SocketException) { return 0; }
        }
    }
    public string AcceptedSocketLocalEndpoint {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return null;
            try { return current.Client.LocalEndPoint == null ? null : current.Client.LocalEndPoint.ToString(); }
            catch (ObjectDisposedException) { return null; }
            catch (SocketException) { return null; }
        }
    }
    public string AcceptedSocketRemoteEndpoint {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return null;
            try { return current.Client.RemoteEndPoint == null ? null : current.Client.RemoteEndPoint.ToString(); }
            catch (ObjectDisposedException) { return null; }
            catch (SocketException) { return null; }
        }
    }
    public bool StallWaitActive {
        get { return mode == "stall" && accepted.IsSet && !completed.IsSet && worker.Status != TaskStatus.RanToCompletion; }
    }

    private void Signal(ManualResetEventSlim signal) {
        lock (signalSync) {
            if (Volatile.Read(ref signalsDisposed) == 0) signal.Set();
        }
    }

    private async Task Run() {
        try {
            var acceptedClient = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            lock (clientSync) {
                if (Volatile.Read(ref disposed) != 0) {
                    acceptedClient.Dispose();
                    return;
                }
                Volatile.Write(ref client, acceptedClient);
            }
            Signal(accepted);
            if (mode == "stall") {
                stopped.Token.WaitHandle.WaitOne();
                return;
            }
            var stream = client.GetStream();
            using (var bytes = new MemoryStream()) {
                var buffer = new byte[4096];
                do {
                    Interlocked.Increment(ref readAttempts);
                    var count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (count == 0) { Volatile.Write(ref readEof, 1); break; }
                    bytes.Write(buffer, 0, count);
                    if (mode == "capture") break;
                } while (!stopped.IsCancellationRequested);
                received = bytes.ToArray();
            }
            if (mode == "echo") {
                await stream.WriteAsync(received, 0, received.Length).ConfigureAwait(false);
                Interlocked.Add(ref echoBytes, received.Length);
                try {
                    client.Client.Shutdown(SocketShutdown.Send);
                    Volatile.Write(ref sendShutdown, 1);
                } catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
            }
        } catch (OperationCanceledException) { Interlocked.CompareExchange(ref fault, "cancelled", null); }
        catch (IOException) { Interlocked.CompareExchange(ref fault, "io", null); }
        catch (ObjectDisposedException) { Interlocked.CompareExchange(ref fault, "disposed", null); }
        catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
        finally {
            Volatile.Write(ref sessionComplete, 1);
            Signal(completed);
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        listener.Stop();
        lock (clientSync) {
            var current = Volatile.Read(ref client);
            if (current != null) current.Dispose();
        }

        Exception workerFailure = null;
        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "TCP probe worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("TCP probe worker did not report completion after bounded cleanup wait");
        }

        lock (signalSync) {
            Volatile.Write(ref signalsDisposed, 1);
            accepted.Dispose();
            completed.Dispose();
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

public sealed class Ferrum2UdpGate : IDisposable {
    private readonly object sync = new object();
    private readonly object upstreamSync = new object();
    private readonly UdpClient socket;
    private readonly int upstreamPort;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private UdpClient activeUpstream;
    private byte[] firstResponse;
    private IPEndPoint latestClient;
    private int requests;
    private int responses;
    private int disposed;
    private string fault;

    public Ferrum2UdpGate(string listenAddress, int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(listenAddress), listenPort));
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    public bool ReplayFirstToLatest() {
        byte[] response;
        IPEndPoint client;
        lock (sync) {
            response = firstResponse;
            client = latestClient;
        }
        if (response == null || client == null) return false;
        socket.Send(response, response.Length, client);
        return true;
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                lock (sync) { latestClient = request.RemoteEndPoint; }
                Interlocked.Increment(ref requests);
                using (var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
                    if (!RegisterUpstream(upstream)) return;
                    try {
                        upstream.Connect(IPAddress.Loopback, upstreamPort);
                        await upstream.SendAsync(request.Buffer, request.Buffer.Length).ConfigureAwait(false);
                        var response = await upstream.ReceiveAsync().ConfigureAwait(false);
                        lock (sync) {
                            if (firstResponse == null) firstResponse = (byte[])response.Buffer.Clone();
                        }
                        await socket.SendAsync(response.Buffer, response.Buffer.Length, request.RemoteEndPoint).ConfigureAwait(false);
                        Interlocked.Increment(ref responses);
                    } finally {
                        UnregisterUpstream(upstream);
                    }
                }
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
    }

    private bool RegisterUpstream(UdpClient upstream) {
        lock (upstreamSync) {
            if (Volatile.Read(ref disposed) != 0) {
                upstream.Dispose();
                return false;
            }
            activeUpstream = upstream;
            return true;
        }
    }

    private void UnregisterUpstream(UdpClient upstream) {
        lock (upstreamSync) {
            if (Object.ReferenceEquals(activeUpstream, upstream)) activeUpstream = null;
        }
    }

    private void CloseActiveUpstream() {
        lock (upstreamSync) {
            if (activeUpstream != null) activeUpstream.Dispose();
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();
        CloseActiveUpstream();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "UDP gate worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("UDP gate worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

public sealed class Ferrum2UdpProbe : IDisposable {
    private readonly UdpClient socket;
    private readonly byte[] fixedResponse;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private byte[] received = new byte[0];
    private IPEndPoint remoteEndpoint;
    private int requests;
    private int responses;
    private int disposed;
    private string fault;

    public Ferrum2UdpProbe(string address, int port) : this(address, port, null) { }

    public Ferrum2UdpProbe(string address, int port, byte[] responsePayload) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        fixedResponse = responsePayload == null ? null : (byte[])responsePayload.Clone();
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public byte[] Received { get { return Volatile.Read(ref received); } }
    public IPEndPoint RemoteEndpoint {
        get {
            var endpoint = Volatile.Read(ref remoteEndpoint);
            return endpoint == null ? null : new IPEndPoint(endpoint.Address, endpoint.Port);
        }
    }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    public void SendTo(byte[] payload, IPEndPoint endpoint) {
        if (payload == null || endpoint == null) throw new ArgumentNullException();
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException("Ferrum2UdpProbe");
        socket.Send(payload, payload.Length, endpoint);
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                Volatile.Write(ref received, (byte[])request.Buffer.Clone());
                Volatile.Write(ref remoteEndpoint, request.RemoteEndPoint);
                Interlocked.Increment(ref requests);
                var response = fixedResponse ?? request.Buffer;
                await socket.SendAsync(response, response.Length, request.RemoteEndPoint).ConfigureAwait(false);
                Interlocked.Increment(ref responses);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "UDP probe worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("UDP probe worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

public sealed class Ferrum2DnsResponder : IDisposable {
    private readonly UdpClient socket;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private int requests;
    private int disposed;

    public Ferrum2DnsResponder(int port) : this("127.0.0.1", port) { }

    public Ferrum2DnsResponder(string address, int port) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                var query = request.Buffer;
                if (query.Length < 17) continue;
                var questionEnd = 12;
                var validQuestion = false;
                while (questionEnd < query.Length) {
                    var labelLength = query[questionEnd++];
                    if (labelLength == 0) {
                        validQuestion = questionEnd + 4 <= query.Length;
                        questionEnd += 4;
                        break;
                    }
                    if (labelLength > 63 || questionEnd + labelLength > query.Length) break;
                    questionEnd += labelLength;
                }
                if (!validQuestion) continue;
                using (var response = new MemoryStream()) {
                    response.WriteByte(query[0]); response.WriteByte(query[1]);
                    response.WriteByte(0x81); response.WriteByte(0x80);
                    response.WriteByte(0); response.WriteByte(1);
                    response.WriteByte(0); response.WriteByte(1);
                    response.Write(new byte[4], 0, 4);
                    response.Write(query, 12, questionEnd - 12);
                    byte[] answer = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 55 };
                    response.Write(answer, 0, answer.Length);
                    var bytes = response.ToArray();
                    await socket.SendAsync(bytes, bytes.Length, request.RemoteEndPoint).ConfigureAwait(false);
                }
                Interlocked.Increment(ref requests);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "DNS responder worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("DNS responder worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

[StructLayout(LayoutKind.Explicit, Size = 28)]
internal struct Ferrum2SockaddrInet {
    [FieldOffset(0)] internal ushort Family;
    [FieldOffset(2)] internal ushort Port;
    [FieldOffset(4)] internal uint Address;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpAddressPrefix {
    internal Ferrum2SockaddrInet Prefix;
    internal byte PrefixLength;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpForwardRow2 {
    internal ulong InterfaceLuid;
    internal uint InterfaceIndex;
    internal Ferrum2IpAddressPrefix DestinationPrefix;
    internal Ferrum2SockaddrInet NextHop;
    internal byte SitePrefixLength;
    internal uint ValidLifetime;
    internal uint PreferredLifetime;
    internal uint Metric;
    internal int Protocol;
    [MarshalAs(UnmanagedType.U1)] internal bool Loopback;
    [MarshalAs(UnmanagedType.U1)] internal bool AutoconfigureAddress;
    [MarshalAs(UnmanagedType.U1)] internal bool Publish;
    [MarshalAs(UnmanagedType.U1)] internal bool Immortal;
    internal uint Age;
    internal int Origin;
}

public sealed class Ferrum2UnderlayProbe {
    public ulong InterfaceLuid { get; internal set; }
    public uint InterfaceIndex { get; internal set; }
    public string DestinationPrefix { get; internal set; }
    public string SourceAddress { get; internal set; }
    public string NextHop { get; internal set; }
    public byte PrefixLength { get; internal set; }
    public uint RouteMetric { get; internal set; }
}

public sealed class Ferrum2CaptureRoute : IDisposable {
    private const uint ERROR_NOT_FOUND = 1168;
    private Ferrum2IpForwardRow2 intended;
    private bool disposed;

    internal Ferrum2CaptureRoute(Ferrum2IpForwardRow2 row) { intended = row; }

    public void Verify() {
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route readback mismatch");
    }

    public void Dispose() {
        if (disposed) return;
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result == ERROR_NOT_FOUND) { disposed = true; return; }
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route ownership changed");
        result = Ferrum2NetworkFeasibility.DeleteRoute(ref current);
        if (result != 0 && result != ERROR_NOT_FOUND)
            throw new Win32Exception(checked((int)result), "DeleteIpForwardEntry2");
        result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != ERROR_NOT_FOUND) throw new InvalidOperationException("capture route delete readback mismatch");
        disposed = true;
    }
}

public static class Ferrum2NetworkFeasibility {
    private const ushort AF_INET = 2;
    private const uint ERROR_NOT_FOUND = 1168;
    private const int IPPROTO_IP = 0;
    private const int IPPROTO_IPV6 = 41;
    private const int IP_UNICAST_IF = 31;
    private const int IPV6_UNICAST_IF = 31;

    [DllImport("iphlpapi.dll")]
    private static extern void InitializeIpForwardEntry(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint CreateIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint DeleteIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestInterfaceEx(ref Ferrum2SockaddrInet destination, out uint interfaceIndex);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestRoute2(IntPtr interfaceLuid, uint interfaceIndex, IntPtr sourceAddress,
        ref Ferrum2SockaddrInet destination, uint addressSortOptions,
        out Ferrum2IpForwardRow2 bestRoute, out Ferrum2SockaddrInet bestSourceAddress);
    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int setsockopt(IntPtr socket, int level, int option, ref uint value, int valueLength);
    [DllImport("ws2_32.dll")]
    private static extern int WSAGetLastError();

    public static int RouteRowSize { get { return Marshal.SizeOf(typeof(Ferrum2IpForwardRow2)); } }

    private static Ferrum2SockaddrInet Address(string text) {
        var address = IPAddress.Parse(text);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("IPv4 is required", "text");
        return new Ferrum2SockaddrInet {
            Family = AF_INET,
            Address = BitConverter.ToUInt32(address.GetAddressBytes(), 0)
        };
    }

    private static string Address(Ferrum2SockaddrInet value) {
        if (value.Family != AF_INET) throw new InvalidOperationException("IPv4 readback is required");
        return new IPAddress(BitConverter.GetBytes(value.Address)).ToString();
    }

    private static Ferrum2IpForwardRow2 Key(Ferrum2IpForwardRow2 intended) {
        var key = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref key);
        key.InterfaceIndex = intended.InterfaceIndex;
        key.DestinationPrefix = intended.DestinationPrefix;
        key.NextHop = intended.NextHop;
        return key;
    }

    internal static uint ReadRoute(Ferrum2IpForwardRow2 intended, out Ferrum2IpForwardRow2 current) {
        current = Key(intended);
        return GetIpForwardEntry2(ref current);
    }

    internal static uint DeleteRoute(ref Ferrum2IpForwardRow2 row) { return DeleteIpForwardEntry2(ref row); }

    internal static bool MatchesOwned(Ferrum2IpForwardRow2 expected, Ferrum2IpForwardRow2 actual) {
        return actual.InterfaceIndex == expected.InterfaceIndex &&
            actual.DestinationPrefix.Prefix.Family == AF_INET &&
            actual.DestinationPrefix.Prefix.Address == expected.DestinationPrefix.Prefix.Address &&
            actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength &&
            actual.NextHop.Family == AF_INET && actual.NextHop.Address == 0 &&
            actual.SitePrefixLength == expected.SitePrefixLength &&
            actual.ValidLifetime == expected.ValidLifetime &&
            actual.PreferredLifetime == expected.PreferredLifetime &&
            actual.Metric == expected.Metric && actual.Protocol == expected.Protocol &&
            actual.Loopback == expected.Loopback &&
            actual.AutoconfigureAddress == expected.AutoconfigureAddress &&
            actual.Publish == expected.Publish && actual.Immortal == expected.Immortal &&
            actual.Origin == expected.Origin;
    }

    public static Ferrum2CaptureRoute CreateCaptureRoute(uint interfaceIndex, string prefix, uint metric) {
        if (RouteRowSize != 104) throw new InvalidOperationException("MIB_IPFORWARD_ROW2 ABI size mismatch");
        var parts = prefix.Split('/');
        if (parts.Length != 2 || parts[1] != "1" || (parts[0] != "0.0.0.0" && parts[0] != "128.0.0.0"))
            throw new ArgumentException("an exact IPv4 /1 capture prefix is required", "prefix");
        var row = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref row);
        row.InterfaceLuid = 0;
        row.InterfaceIndex = interfaceIndex;
        row.DestinationPrefix = new Ferrum2IpAddressPrefix { Prefix = Address(parts[0]), PrefixLength = 1 };
        row.NextHop = Address("0.0.0.0");
        row.SitePrefixLength = 0;
        row.ValidLifetime = UInt32.MaxValue;
        row.PreferredLifetime = UInt32.MaxValue;
        row.Metric = metric;
        row.Protocol = 3;
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;
        row.Age = 0;
        row.Origin = 0;
        Ferrum2IpForwardRow2 ignored;
        var result = ReadRoute(row, out ignored);
        if (result != ERROR_NOT_FOUND) {
            if (result == 0) throw new InvalidOperationException("capture route baseline not absent");
            throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        }
        result = CreateIpForwardEntry2(ref row);
        if (result != 0) throw new Win32Exception(checked((int)result), "CreateIpForwardEntry2");
        var lease = new Ferrum2CaptureRoute(row);
        try { lease.Verify(); return lease; }
        catch { lease.Dispose(); throw; }
    }

    public static Ferrum2UnderlayProbe GetFixedRoute(string destinationText) {
        var destination = Address(destinationText);
        uint interfaceIndex;
        var result = GetBestInterfaceEx(ref destination, out interfaceIndex);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestInterfaceEx");
        return GetConstrainedRoute(destinationText, interfaceIndex);
    }

    public static Ferrum2UnderlayProbe GetConstrainedRoute(string destinationText, uint interfaceIndex) {
        var destination = Address(destinationText);
        Ferrum2IpForwardRow2 route;
        Ferrum2SockaddrInet source;
        var result = GetBestRoute2(IntPtr.Zero, interfaceIndex, IntPtr.Zero, ref destination, 0, out route, out source);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestRoute2");
        if (route.InterfaceIndex != interfaceIndex || source.Family != AF_INET || source.Address == 0)
            throw new InvalidOperationException("constrained best route identity mismatch");
        return new Ferrum2UnderlayProbe {
            InterfaceLuid = route.InterfaceLuid,
            InterfaceIndex = interfaceIndex,
            DestinationPrefix = Address(route.DestinationPrefix.Prefix),
            SourceAddress = Address(source),
            NextHop = Address(route.NextHop),
            PrefixLength = route.DestinationPrefix.PrefixLength,
            RouteMetric = route.Metric
        };
    }

    public static void Pin(Socket socket, uint interfaceIndex) {
        if (socket == null) throw new ArgumentNullException("socket");
        if (interfaceIndex == 0) throw new ArgumentOutOfRangeException("interfaceIndex");
        var value = interfaceIndex;
        var level = IPPROTO_IPV6;
        var option = IPV6_UNICAST_IF;
        var name = "IPV6_UNICAST_IF";
        if (socket.AddressFamily == AddressFamily.InterNetwork) {
            value = unchecked((uint)IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex)));
            level = IPPROTO_IP;
            option = IP_UNICAST_IF;
            name = "IP_UNICAST_IF";
        } else if (socket.AddressFamily != AddressFamily.InterNetworkV6) {
            throw new ArgumentException("an IPv4 or IPv6 socket is required", "socket");
        }
        if (setsockopt(socket.Handle, level, option, ref value, sizeof(uint)) != 0)
            throw new Win32Exception(WSAGetLastError(), name);
    }

    private static void SendAll(Socket socket, byte[] payload) {
        var offset = 0;
        while (offset < payload.Length) offset += socket.Send(payload, offset, payload.Length - offset, SocketFlags.None);
    }

    private static byte[] ReceiveExact(Socket socket, int length) {
        var received = new byte[length];
        var offset = 0;
        while (offset < length) {
            var count = socket.Receive(received, offset, length - offset, SocketFlags.None);
            if (count == 0) throw new EndOfStreamException("support listener closed before echo");
            offset += count;
        }
        return received;
    }

    private static void VerifySource(Socket socket, string expectedSource) {
        var local = socket.LocalEndPoint as IPEndPoint;
        if (local == null || local.Address.ToString() != expectedSource)
            throw new InvalidOperationException("pinned socket source mismatch");
    }

    public static void TcpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            VerifySource(socket, expectedSource);
            SendAll(socket, payload);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support TCP echo mismatch");
        }
    }

    public static void UdpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            SendAll(socket, payload);
            VerifySource(socket, expectedSource);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support UDP echo mismatch");
        }
    }
}
'@

function Convert-Tcp08CtrlBreakResult([Ferrum2CtrlBreakResult]$Result) {
    return [ordered]@{
        process_known = $Result.ProcessKnown
        separate_console = $Result.SeparateConsole
        had_console = $Result.HadConsole
        attach_attempted = $Result.AttachAttempted
        free_console_before_attach = [ordered]@{
            result = $Result.FreeConsoleBeforeAttachResult
            win32_error = $Result.FreeConsoleBeforeAttachWin32Error
        }
        attach_console = [ordered]@{
            result = $Result.AttachConsoleResult
            win32_error = $Result.AttachConsoleWin32Error
        }
        set_console_ctrl_handler = [ordered]@{
            result = $Result.SetConsoleCtrlHandlerResult
            win32_error = $Result.SetConsoleCtrlHandlerWin32Error
        }
        generate_console_ctrl_event = [ordered]@{
            result = $Result.GenerateConsoleCtrlEventResult
            win32_error = $Result.GenerateConsoleCtrlEventWin32Error
        }
        reset_console_ctrl_handler = [ordered]@{
            result = $Result.ResetConsoleCtrlHandlerResult
            win32_error = $Result.ResetConsoleCtrlHandlerWin32Error
        }
        free_console_after = [ordered]@{
            result = $Result.FreeConsoleAfterResult
            win32_error = $Result.FreeConsoleAfterWin32Error
        }
        send_started_timestamp = $Result.SendStartedTimestamp
        send_returned_timestamp = $Result.SendReturnedTimestamp
        send_duration_ms = [Math]::Round($Result.SendDurationMilliseconds, 3)
        internal_wait_started_timestamp = $Result.InternalWaitStartedTimestamp
        internal_wait_returned_timestamp = $Result.InternalWaitReturnedTimestamp
        internal_wait_ms = [Math]::Round($Result.InternalWaitMilliseconds, 3)
        total_duration_ms = [Math]::Round($Result.TotalDurationMilliseconds, 3)
        succeeded = $Result.Succeeded
    }
}

function Test-Tcp08ClientSocketOpen([Net.Sockets.TcpClient]$Client) {
    if (-not $Client) { return $false }
    try {
        $socket = $Client.Client
        return $socket -and $socket.Connected -and -not ($socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead) -and $socket.Available -eq 0)
    } catch [ObjectDisposedException] { return $false }
    catch [Net.Sockets.SocketException] { return $false }
}

function Get-Tcp08Endpoint([Net.Sockets.TcpClient]$Client, [bool]$Local) {
    if (-not $Client) { return $null }
    try {
        $endpoint = if ($Local) { $Client.Client.LocalEndPoint } else { $Client.Client.RemoteEndPoint }
        if ($endpoint) { return $endpoint.ToString() }
        return $null
    } catch [ObjectDisposedException] { return $null }
    catch [Net.Sockets.SocketException] { return $null }
}

function Get-Tcp08MetricEvidence([int]$MetricsPort) {
    $samples = @()
    try {
        $metrics = Get-Metrics $MetricsPort
        $samples = @($metrics -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object {
            $_ -match '^ferrum2_(tun_(packets_accepted|tcp_flows_active|handler_tasks_active)|tcp_connections_active|tcp_forced_shutdown|process_|runtime|root|owner|shutdown)'
        })
        return [ordered]@{
            available = $true
            required = [bool]$script:RequireTcp08ProductMetrics
            unavailable_after_quiesce_expected = $false
            owner_counts = [ordered]@{
                active_tun_tcp_flows = Get-ClientGaugeValue $metrics "ferrum2_tun_tcp_flows_active"
                active_tun_handler_tasks = Get-ClientGaugeValue $metrics "ferrum2_tun_handler_tasks_active"
                active_process_roots = Get-ClientGaugeValue $metrics "ferrum2_process_roots_active"
                forced_roots = Get-ClientCounterValue $metrics "ferrum2_process_roots_forced"
            }
            samples = $samples
        }
    } catch {
        return [ordered]@{
            available = $false
            required = [bool]$script:RequireTcp08ProductMetrics
            unavailable_after_quiesce_expected = $false
            failure_type = $_.Exception.GetType().FullName
            owner_counts = $null
            samples = $samples
        }
    }
}

function Assert-Tcp08ProductOwnerMetrics([object]$Evidence, [string]$Phase) {
    Assert-True $Evidence.available "TCP-08 product owner metrics were unavailable $Phase"
    Assert-True ($Evidence.owner_counts.active_tun_tcp_flows -ge 1) "TCP-08 had no active product-owned TUN TCP flow $Phase"
    Assert-True ($Evidence.owner_counts.active_tun_handler_tasks -ge 1) "TCP-08 had no active product-owned TUN handler task $Phase"
    Assert-True ($Evidence.owner_counts.active_process_roots -ge 1) "TCP-08 had no active product-owned process root $Phase"
    Assert-True ($Evidence.owner_counts.forced_roots -eq 0) "TCP-08 process root was already forced $Phase"
}

function Get-Tcp08ConnectionEvidence(
    [string]$Target,
    [int]$TargetPort,
    [int]$GatePort,
    [int]$ServerPort,
    [System.Diagnostics.Process]$CandidateProcess
) {
    $candidatePid = if ($CandidateProcess) { [uint32]$CandidateProcess.Id } else { [uint32]0 }
    $serverPids = @($script:serverProcesses | ForEach-Object { [uint32]$_.Id })
    $relevantPorts = @($TargetPort, $GatePort, $ServerPort) | Sort-Object -Unique
    $rows = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $relevantPorts -contains [int]$_.LocalPort -or
        $relevantPorts -contains [int]$_.RemotePort -or
        $_.LocalAddress -eq $Target -or $_.RemoteAddress -eq $Target -or
        [uint32]$_.OwningProcess -eq $candidatePid -or
        $serverPids -contains [uint32]$_.OwningProcess
    } | Sort-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort | ForEach-Object {
        $owner = [uint32]$_.OwningProcess
        $role = if ($owner -eq [uint32]$PID) { "controller" }
            elseif ($owner -eq $candidatePid) { "client" }
            elseif ($serverPids -contains $owner) { "server" }
            else { "other" }
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            remote_address = [string]$_.RemoteAddress
            remote_port = [int]$_.RemotePort
            state = [string]$_.State
            owning_process = $owner
            owner_role = $role
        }
    })
    $targetListener = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.local_port -eq $TargetPort -and $_.state -eq "Listen"
    }).Count
    $targetAccepted = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.local_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    $pressureLogical = @($rows | Where-Object {
        $_.owning_process -eq [uint32]$PID -and $_.remote_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    $clientUnderlay = @($rows | Where-Object {
        $_.owning_process -eq $candidatePid -and $_.remote_port -eq $GatePort -and $_.state -eq "Established"
    }).Count
    $serverRelay = @($rows | Where-Object {
        $serverPids -contains $_.owning_process -and $_.remote_port -eq $TargetPort -and $_.state -eq "Established"
    }).Count
    return [ordered]@{
        rows = $rows
        assertions = [ordered]@{
            target_listener = $targetListener
            target_accepted = $targetAccepted
            pressure_logical = $pressureLogical
            client_underlay = $clientUnderlay
            server_relay = $serverRelay
        }
    }
}

function Get-Tcp08LiveEvidence(
    [string]$Phase,
    [string]$Target,
    [int]$TargetPort,
    [int]$GatePort,
    [int]$ServerPort,
    [int]$MetricsPort,
    [System.Diagnostics.Process]$CandidateProcess,
    [object]$Pressure,
    [Threading.Tasks.Task]$PressureWrite,
    [Ferrum2TcpProbe]$TargetProbe,
    [Ferrum2TcpGate]$Gate,
    [int]$GateIndex
) {
    $captured = Get-Tcp08MonotonicSample
    $CandidateProcess.Refresh()
    $gateObservation = $Gate.Observation($GateIndex)
    $connections = Get-Tcp08ConnectionEvidence $Target $TargetPort $GatePort $ServerPort $CandidateProcess
    $pressureAvailable = try { $Pressure.Client.Client.Available } catch { $null }
    return [ordered]@{
        phase = $Phase
        monotonic_ticks = $captured.monotonic_ticks
        elapsed_ms = $captured.elapsed_ms
        candidate = [ordered]@{
            process_id = [uint32]$CandidateProcess.Id
            has_exited = $CandidateProcess.HasExited
        }
        pressure_client = [ordered]@{
            socket_open = Test-Tcp08ClientSocketOpen $Pressure.Client
            connected_property = $Pressure.Client.Connected
            local_endpoint = Get-Tcp08Endpoint $Pressure.Client $true
            remote_endpoint = Get-Tcp08Endpoint $Pressure.Client $false
            available_bytes = $pressureAvailable
        }
        pressure_write = [ordered]@{
            task_id = if ($PressureWrite) { $PressureWrite.Id } else { $null }
            status = if ($PressureWrite) { $PressureWrite.Status.ToString() } else { "missing" }
            is_completed = if ($PressureWrite) { $PressureWrite.IsCompleted } else { $null }
            is_faulted = if ($PressureWrite) { $PressureWrite.IsFaulted } else { $null }
            is_canceled = if ($PressureWrite) { $PressureWrite.IsCanceled } else { $null }
        }
        target = [ordered]@{
            listener_active = $TargetProbe.ListenerActive
            accepted_socket_connected = $TargetProbe.AcceptedSocketConnected
            accepted_socket_open = $TargetProbe.AcceptedSocketOpen
            accepted_socket_available_bytes = $TargetProbe.AcceptedSocketAvailable
            accepted_socket_local_endpoint = $TargetProbe.AcceptedSocketLocalEndpoint
            accepted_socket_remote_endpoint = $TargetProbe.AcceptedSocketRemoteEndpoint
            read_attempts = $TargetProbe.ReadAttempts
            stall_wait_active = $TargetProbe.StallWaitActive
            worker_status = $TargetProbe.WorkerStatus
            session_complete = $TargetProbe.SessionComplete
            fault = $TargetProbe.Fault
        }
        gate = if ($gateObservation) {
            [ordered]@{
                session_index = $GateIndex
                client_to_server_bytes = $gateObservation.ClientToServerBytes
                client_to_server_stage = $gateObservation.ClientToServerStage
                client_to_server_eof = $gateObservation.ClientToServerEof
                client_to_server_fault = $gateObservation.ClientToServerFault
                server_to_client_bytes = $gateObservation.ServerToClientBytes
                server_to_client_stage = $gateObservation.ServerToClientStage
                server_to_client_eof = $gateObservation.ServerToClientEof
                server_to_client_fault = $gateObservation.ServerToClientFault
                session_complete = $gateObservation.SessionComplete
            }
        } else { $null }
        metrics = if ($Phase -in @("during_grace", "after_process_exit")) {
            [ordered]@{
                available = $false
                required = [bool]$script:RequireTcp08ProductMetrics
                unavailable_after_quiesce_expected = $true
                failure_type = "not_queried_after_process_quiesce"
                owner_counts = $null
                samples = @()
            }
        } else { Get-Tcp08MetricEvidence $MetricsPort }
        connections = $connections
    }
}

function Write-CapabilityEvidence([string]$Phase, [hashtable]$Data) {
    $row = [ordered]@{
        schema = 1
        phase = $Phase
        timestamp_utc = [DateTime]::UtcNow.ToString("O")
        data = $Data
    }
    Add-Content -LiteralPath $script:capabilityEvidence -Value ($row | ConvertTo-Json -Compress -Depth 8) -Encoding utf8NoBOM
}

function Get-Ipv4DefaultUnderlay {
    $rows = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                $route = $_
                $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -ErrorAction Stop
                $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -IncludeHidden -ErrorAction Stop
                if ($route.InterfaceIndex -ne 1 -and $route.InterfaceIndex -ne $script:ownedInterfaceIndex -and
                    $interface.ConnectionState -eq "Connected" -and $adapter.Status -eq "Up" -and
                    $adapter.InterfaceDescription -notmatch "Wintun") {
                    [pscustomobject]@{
                        Route = $route
                        Interface = $interface
                        EffectiveMetric = [uint64]$route.RouteMetric + [uint64]$interface.InterfaceMetric
                    }
                }
            }
    )
    Assert-True ($rows.Count -gt 0) "eligible IPv4 default underlay is missing"
    $minimum = ($rows | Measure-Object EffectiveMetric -Minimum).Minimum
    $best = @($rows | Where-Object { $_.EffectiveMetric -eq $minimum })
    $indices = @($best | ForEach-Object { [uint32]$_.Route.InterfaceIndex } | Sort-Object -Unique)
    Assert-True ($indices.Count -eq 1 -and $best.Count -eq 1) "eligible IPv4 default underlay is ambiguous"
    $sources = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $indices[0] -AddressState Preferred -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne "0.0.0.0" -and $_.IPAddress -notlike "169.254.*" })
    Assert-True ($sources.Count -ge 1) "eligible IPv4 default source is missing"
    return [pscustomobject]@{ InterfaceIndex = $indices[0]; Row = $best[0]; Sources = $sources }
}

function Get-PhysicalDnsSnapshot([int]$TunInterfaceIndex) {
    return @(
        Get-DnsClientServerAddress -ErrorAction Stop |
            Where-Object { $_.InterfaceIndex -ne $TunInterfaceIndex } |
            Sort-Object InterfaceIndex, AddressFamily |
            ForEach-Object { "$($_.InterfaceIndex)|$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" }
    )
}

function Get-Ipv4SystemRouteSnapshot {
    return @(
        Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Protocol |
            ForEach-Object { "$($_.InterfaceIndex)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)|$($_.Protocol)" }
    )
}

function Wait-Ipv4SystemRouteSnapshot([string[]]$Expected) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $actual = @(Get-Ipv4SystemRouteSnapshot)
        if (@(Compare-Object -ReferenceObject @($Expected) -DifferenceObject $actual).Count -eq 0) { return }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-SnapshotEqual $Expected $actual "system IPv4 route cleanup"
}

function Get-TunIpv4Dns([int]$InterfaceIndex) {
    $rows = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    return @(
        $rows | ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Set-CapabilityDns([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityDnsApplied) "capability DNS is already applied"
    $script:capabilityDnsSnapshot = @(Get-TunIpv4Dns $InterfaceIndex)
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses "198.18.0.1" -Validate -ErrorAction Stop
    $script:capabilityDnsApplied = $true
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS readback"
}

function Restore-CapabilityDns([int]$InterfaceIndex) {
    if (-not $script:capabilityDnsApplied) { return }
    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS ownership"
    if ($script:capabilityDnsSnapshot.Count -eq 0) {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $script:capabilityDnsSnapshot -Validate -ErrorAction Stop
    }
    Assert-SnapshotEqual @($script:capabilityDnsSnapshot) @(Get-TunIpv4Dns $InterfaceIndex) "capability DNS restore"
    $script:capabilityDnsApplied = $false
    $script:capabilityDnsSnapshot = $null
}

function Set-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    Assert-True (-not $script:capabilityMetricApplied) "capability interface metric is already applied"
    $row = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricSnapshot = [pscustomobject]@{
        AutomaticMetric = [string]$row.AutomaticMetric
        InterfaceMetric = [uint32]$row.InterfaceMetric
    }
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 -PolicyStore ActiveStore -ErrorAction Stop
    $script:capabilityMetricApplied = $true
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric readback mismatch"
}

function Restore-CapabilityInterfaceMetric([int]$InterfaceIndex) {
    if (-not $script:capabilityMetricApplied) { return }
    $current = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ($current.AutomaticMetric -eq "Disabled" -and $current.InterfaceMetric -eq 1) "capability interface metric ownership changed"
    if ($script:capabilityMetricSnapshot.AutomaticMetric -ceq "Enabled") {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -AutomaticMetric Enabled -PolicyStore ActiveStore -ErrorAction Stop
    } else {
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -AutomaticMetric Disabled -InterfaceMetric $script:capabilityMetricSnapshot.InterfaceMetric `
            -PolicyStore ActiveStore -ErrorAction Stop
    }
    $restored = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    $metricMatches = ($script:capabilityMetricSnapshot.AutomaticMetric -ceq "Enabled") -or
        ([uint32]$restored.InterfaceMetric -eq $script:capabilityMetricSnapshot.InterfaceMetric)
    Assert-True ([string]$restored.AutomaticMetric -ceq $script:capabilityMetricSnapshot.AutomaticMetric -and
        $metricMatches) "capability interface metric restore mismatch"
    $script:capabilityMetricApplied = $false
    $script:capabilityMetricSnapshot = $null
}

function Remove-CapabilityRoutes {
    for ($index = $script:capabilityRoutes.Count - 1; $index -ge 0; $index--) {
        $script:capabilityRoutes[$index].Dispose()
        $script:capabilityRoutes.RemoveAt($index)
    }
}

function Get-TunAccepted([int]$MetricsPort) {
    return Get-CounterValue (Get-Metrics $MetricsPort) "ferrum2_tun_packets_accepted"
}

function Wait-TunAcceptedAfter([int]$MetricsPort, [uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $after = Get-TunAccepted $MetricsPort
        if ($after -gt $Before) { return $after }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "unpinned packet did not enter Wintun"
}

function Invoke-PktMon([string[]]$Arguments, [int]$TimeoutMilliseconds = 5000) {
    $path = "C:\Windows\System32\PktMon.exe"
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $version = [Version](($item.VersionInfo.FileVersion -split " ")[0])
    Assert-True ($version -eq [Version]"10.0.19041.906") "PktMon version mismatch"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-True $process.Start() "PktMon did not start"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "PktMon command timed out"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-True ($process.ExitCode -eq 0) "PktMon command failed"
        return [pscustomobject]@{ Stdout = $stdout; Stderr = $stderr }
    } finally {
        $process.Dispose()
    }
}

function Get-PktMonOutputLines([string]$Text) {
    return @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
}

function Assert-PktMonAbsent {
    $status = Get-PktMonOutputLines (Invoke-PktMon @("status")).Stdout
    Assert-True (@($status | Where-Object { $_ -ceq "Packet Monitor is not running." }).Count -eq 1) "PktMon baseline is running"
    $filters = Get-PktMonOutputLines (Invoke-PktMon @("filter", "list")).Stdout
    Assert-True ($filters.Count -eq 2 -and $filters[0] -ceq "Packet Filters:" -and $filters[1] -ceq "None") "PktMon filter baseline is not empty"
}

function Get-PktMonDirectProperties([object]$Record) {
    $propertyField = $Record.PSObject.Properties["Properties"]
    Assert-True ($null -ne $propertyField -and $propertyField.Value -is [Array]) "PktMon component properties are invalid"
    $result = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($property in @($propertyField.Value)) {
        Assert-True ((@($property.PSObject.Properties.Name) -join "|") -ceq "Name|Value") "PktMon component property shape is invalid"
        $name = [string]$property.Name
        Assert-True (-not [string]::IsNullOrWhiteSpace($name)) "PktMon component property name is invalid"
        if ($name -ceq "ifIndex" -or $name -ceq "ifGuid") {
            Assert-True (-not $result.ContainsKey($name)) "PktMon identity property is duplicated"
            $result.Add($name, $property.Value)
        }
    }
    return $result
}

function Get-PktMonComponentId([object]$Adapter) {
    $text = (Invoke-PktMon @("list", "--json")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon component JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon component JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon component groups are empty"
    $interfaceGuid = [guid]::Empty
    Assert-True ([guid]::TryParse([string]$Adapter.InterfaceGuid, [ref]$interfaceGuid)) "owned adapter GUID is invalid"
    $expectedDriver = $null
    if ($null -ne $Adapter.PSObject.Properties["DriverFileName"] -and
        -not [string]::IsNullOrWhiteSpace([string]$Adapter.DriverFileName)) {
        $expectedDriver = [IO.Path]::GetFileName([string]$Adapter.DriverFileName)
    }
    $recordsById = @{}
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon component group shape is invalid"
        foreach ($record in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $record.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$record.Id, [ref]$id) -and $id -gt 0) "PktMon component Id is invalid"
            [void](Get-PktMonDirectProperties $record)
            if (-not $recordsById.ContainsKey($id)) { $recordsById[$id] = [Collections.Generic.List[object]]::new() }
            $recordsById[$id].Add($record)
        }
    }
    $matches = [Collections.Generic.List[int]]::new()
    foreach ($entry in $recordsById.GetEnumerator()) {
        $hasIdentityRecord = $false
        $hasDriver = $null -eq $expectedDriver
        foreach ($record in $entry.Value) {
            $properties = Get-PktMonDirectProperties $record
            $recordIndexMatches = $false
            $recordGuidMatches = $false
            if ($properties.ContainsKey("ifIndex")) {
                [int]$ifIndex = 0
                Assert-True ([int]::TryParse([string]$properties["ifIndex"], [ref]$ifIndex)) "PktMon ifIndex is invalid"
                $recordIndexMatches = $ifIndex -eq [int]$Adapter.ifIndex
            }
            if ($properties.ContainsKey("ifGuid")) {
                $ifGuid = [guid]::Empty
                Assert-True ([guid]::TryParse([string]$properties["ifGuid"], [ref]$ifGuid)) "PktMon ifGuid is invalid"
                $recordGuidMatches = $ifGuid -eq $interfaceGuid
            }
            if ($recordIndexMatches -and $recordGuidMatches) { $hasIdentityRecord = $true }
            if ($null -ne $expectedDriver -and $null -ne $record.PSObject.Properties["DriverName"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.DriverName) -and
                [IO.Path]::GetFileName([string]$record.DriverName) -ieq $expectedDriver) {
                $hasDriver = $true
            }
        }
        if ($hasIdentityRecord -and $hasDriver) { $matches.Add([int]$entry.Key) }
    }
    Assert-True ($matches.Count -eq 1) "owned Wintun PktMon component is ambiguous"
    return $matches[0]
}

function ConvertTo-PktMonUInt64([object]$Value) {
    [uint64]$parsed = 0
    Assert-True ([uint64]::TryParse([string]$Value, [ref]$parsed)) "PktMon counter value is invalid"
    return $parsed
}

function Add-PktMonChecked([uint64]$Total, [uint64]$Value) {
    Assert-True ($Value -le [uint64]::MaxValue - $Total) "PktMon counter overflowed"
    return [uint64]($Total + $Value)
}

function Get-PktMonFlowPackets {
    $text = (Invoke-PktMon @("counters", "--type", "flow", "--json", "--zero")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon counter JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon counter JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon counter groups are empty"
    $records = [Collections.Generic.List[object]]::new()
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon counter group shape is invalid"
        foreach ($component in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $component.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$component.Id, [ref]$id) -and $id -gt 0) "PktMon counter component Id is invalid"
            if ($id -eq $script:pktmonComponentId) { $records.Add($component) }
        }
    }
    Assert-True ($records.Count -gt 0) "owned PktMon component counters are missing"
    [uint64]$total = 0
    $flowEdges = 0
    foreach ($component in $records) {
        Assert-True ($null -ne $component.PSObject.Properties["Counters"] -and $component.Counters -is [Array]) "PktMon counter component shape is invalid"
        foreach ($counter in @($component.Counters)) {
            Assert-True ($null -ne $counter.PSObject.Properties["Type"] -and $counter.Type -ceq "Flows") "PktMon counter edge type is invalid"
            foreach ($direction in @("Inbound", "Outbound")) {
                $edge = $counter.PSObject.Properties[$direction]
                Assert-True ($null -ne $edge -and $null -ne $edge.Value.PSObject.Properties["Packets"] -and
                    $null -ne $edge.Value.PSObject.Properties["Bytes"]) "PktMon flow edge shape is invalid"
                $packets = ConvertTo-PktMonUInt64 $edge.Value.Packets
                [void](ConvertTo-PktMonUInt64 $edge.Value.Bytes)
                $total = Add-PktMonChecked $total $packets
            }
            $flowEdges++
        }
    }
    Assert-True ($flowEdges -gt 0) "owned PktMon flow counters are missing"
    return $total
}

function Get-PktMonFlowPacketDelta([uint64]$Before) {
    $after = Get-PktMonFlowPackets
    Assert-True ($after -ge $Before) "PktMon flow counter regressed"
    return [uint64]($after - $Before)
}

function Wait-PktMonFlowPacketsAfter([uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    $quiet = [Diagnostics.Stopwatch]::StartNew()
    [uint64]$last = $Before
    $observed = $false
    do {
        $after = Get-PktMonFlowPackets
        Assert-True ($after -ge $last) "PktMon flow counter regressed"
        if ($after -gt $Before) {
            if (-not $observed -or $after -ne $last) {
                $observed = $true
                $quiet.Restart()
            } elseif ($quiet.ElapsedMilliseconds -ge 500) {
                return [uint64]($after - $Before)
            }
        }
        $last = $after
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "filtered unpinned flow did not enter Wintun"
}

function Invoke-ProductPinnedRow([scriptblock]$Action, [string]$Failure) {
    $before = Get-PktMonFlowPackets
    & $Action
    Start-Sleep -Milliseconds 500
    $delta = Get-PktMonFlowPacketDelta -Before $before
    Assert-True ($delta -eq 0) $Failure
    return $delta
}

function Stop-CapabilityPktMon {
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    if ($script:pktmonStarted -or $script:pktmonStartAttempted) {
        try {
            [void](Invoke-PktMon @("stop"))
            $script:pktmonStarted = $false
            $script:pktmonStartAttempted = $false
        } catch { $cleanupFailures.Add("stop") }
    }
    if ($script:pktmonTcpFilterOwned -or $script:pktmonUdpFilterOwned) {
        try {
            [void](Invoke-PktMon @("filter", "remove"))
            $script:pktmonTcpFilterOwned = $false
            $script:pktmonUdpFilterOwned = $false
        } catch { $cleanupFailures.Add("filters") }
        try { [void](Invoke-PktMon @("reset")) }
        catch { $cleanupFailures.Add("reset") }
    }
    try { Assert-PktMonAbsent }
    catch { $cleanupFailures.Add("absence") }
    Assert-True ($cleanupFailures.Count -eq 0) "PktMon cleanup failed"
}

function Invoke-UnpinnedTcpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connected = $client.ConnectAsync($Address, $Port)
        if ($connected.Wait(1500) -and -not $connected.IsFaulted) {
            $stream = $client.GetStream()
            $stream.Write($Payload, 0, $Payload.Length)
            $read = [byte[]]::new($Payload.Length)
            $response = $stream.ReadAsync($read, 0, $read.Length)
            if ($response.Wait(750) -and -not $response.IsFaulted -and $response.Result -gt 0 -and
                (($read[0..($response.Result - 1)] -join ",") -eq ($Payload[0..($response.Result - 1)] -join ","))) {
                throw "unpinned TCP reached the support listener"
            }
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-UnpinnedUdpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Connect($Address, $Port)
        [void]$client.Send($Payload, $Payload.Length)
        $response = $client.ReceiveAsync()
        if ($response.Wait(750) -and -not $response.IsFaulted -and
            (($response.Result.Buffer -join ",") -eq ($Payload -join ","))) {
            throw "unpinned UDP reached the support listener"
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-SystemDnsWitness([string]$Name, [bool]$TcpOnly) {
    Clear-DnsClientCache -ErrorAction Stop
    $parameters = @{ Name = $Name; Type = "A"; DnsOnly = $true; NoHostsFile = $true; ErrorAction = "Stop" }
    if ($TcpOnly) { $parameters.TcpOnly = $true }
    $answer = @(Resolve-DnsName @parameters | Where-Object { $_.Type -eq "A" -and $_.IPAddress -eq "192.0.2.55" })
    Assert-True ($answer.Count -eq 1) "Windows resolver did not return one unique capability answer"
}

function Open-TunTcp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.TcpClient]::new($family)
    $client.NoDelay = $true
    $client.SendBufferSize = 4096
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $connected = $client.ConnectAsync($Address, $Port)
    Assert-True ($connected.Wait(5000)) "TUN TCP local handshake timeout"
    if ($connected.IsFaulted) { throw "TUN TCP local handshake failed" }
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN TCP source bind mismatch"
    return [pscustomobject]@{ Client = $client }
}

function Read-StreamToEnd([Net.Sockets.NetworkStream]$Stream) {
    $Stream.ReadTimeout = 5000
    $output = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(4096)
        do {
            $count = $Stream.Read($buffer, 0, $buffer.Length)
            if ($count -gt 0) { $output.Write($buffer, 0, $count) }
        } while ($count -gt 0)
        return $output.ToArray()
    } finally { $output.Dispose() }
}

function Read-ExactBytes([Net.Sockets.NetworkStream]$Stream, [int]$Length) {
    $Stream.ReadTimeout = 5000
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        Assert-True ($count -gt 0) "stream ended before exact frame"
        $offset += $count
    }
    return $bytes
}

function Invoke-EchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate]$Gate,
    [byte[]]$Payload,
    [hashtable]$Observation = $null
) {
    $expectedGate = $Gate.Accepted + 1
    if ($null -ne $Observation) {
        $Observation.Gate = $Gate
        $Observation.GateIndex = $expectedGate
        $Observation.GateAccepted = "no"
        $Observation.Probe = $null
        $Observation.ProbeAccepted = "no"
        $Observation.AppResult = "other"
    }
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        Assert-True ($Gate.WaitAccepted($expectedGate, 5000)) "selected egress gate was not opened"
        if ($null -ne $Observation) { $Observation.GateAccepted = "yes" }
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        $probe = [Ferrum2TcpProbe]::new($Address, $Port, "echo")
        $script:tcpResources.Add($probe)
        if ($null -ne $Observation) { $Observation.Probe = $probe }
        $Gate.Release($expectedGate)
        $probeAccepted = $probe.WaitAccepted(5000)
        if ($null -ne $Observation -and $probeAccepted) { $Observation.ProbeAccepted = "yes" }
        Assert-True $probeAccepted "selected target was not opened"
        $echo = Read-StreamToEnd $stream
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "echo or half-close mismatch"
        Assert-True ($probe.WaitCompleted(5000)) "target half-close did not complete"
        Assert-True ($probe.SessionComplete -eq "yes" -and $probe.Fault -eq "none" -and
            $probe.ReadEof -eq "yes" -and $probe.SendShutdown -eq "yes") "target half-close completed with a fault"
        if ($null -ne $Observation) { $Observation.AppResult = "success" }
    } catch {
        if ($null -ne $Observation) {
            $errorCursor = $_.Exception
            $sawIo = $false
            $appResult = "other"
            for ($depth = 0; $depth -lt 4 -and $errorCursor; $depth++) {
                if ($errorCursor -is [Net.Sockets.SocketException] -and
                    $errorCursor.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset) { $appResult = "reset"; break }
                if ($errorCursor -is [IO.IOException]) { $sawIo = $true }
                $errorCursor = $errorCursor.InnerException
            }
            if ($appResult -eq "other" -and $sawIo) { $appResult = "io" }
            $Observation.AppResult = $appResult
        }
        throw
    } finally { $session.Client.Dispose() }
}

function Assert-ResetWithoutEgress(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate[]]$Gates
) {
    $counts = @($Gates | ForEach-Object Accepted)
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        $stream = $session.Client.GetStream()
        $stream.ReadTimeout = 5000
        $closed = $false
        try {
            $stream.WriteByte(1)
            $closed = $stream.ReadByte() -eq -1
        } catch [IO.IOException] { $closed = $true }
        Assert-True $closed "terminal flow did not close/reset"
        for ($index = 0; $index -lt $Gates.Count; $index++) {
            Assert-True ($Gates[$index].Accepted -eq $counts[$index]) "terminal flow opened an egress gate"
        }
    } finally {
        $session.Client.Dispose()
    }
}

function New-DnsQuery([uint16]$Id) {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]([byte]($Id -shr 8), [byte]($Id -band 0xff), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in @("query", "tun", "test")) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$encoded.Length)
        $bytes.AddRange($encoded)
    }
    $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
    return $bytes.ToArray()
}

function New-SocksRequest([byte]$Command, [string]$Address, [int]$Port) {
    $parsed = [Net.IPAddress]::Parse($Address)
    Assert-True ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) "SOCKS target family mismatch"
    $request = [Collections.Generic.List[byte]]::new()
    $request.AddRange([byte[]](5, $Command, 0, 1))
    $request.AddRange($parsed.GetAddressBytes())
    $request.Add([byte]($Port -shr 8))
    $request.Add([byte]($Port -band 0xff))
    return $request.ToArray()
}

function Open-ProductSocks([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connected = $client.ConnectAsync([Net.IPAddress]::Loopback, $Port)
        Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "SOCKS control connect failed"
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $greeting = [byte[]](5, 1, 0)
        $stream.Write($greeting, 0, $greeting.Length)
        $response = Read-ExactBytes $stream 2
        Assert-True ($response[0] -eq 5 -and $response[1] -eq 0) "SOCKS greeting failed"
        return [pscustomobject]@{ Client = $client; Stream = $stream }
    } catch {
        $client.Dispose()
        throw
    }
}

function Read-SocksReply([Net.Sockets.NetworkStream]$Stream) {
    $header = Read-ExactBytes $Stream 4
    Assert-True ($header[0] -eq 5 -and $header[2] -eq 0) "SOCKS reply header mismatch"
    $address = switch ($header[3]) {
        1 { [Net.IPAddress]::new((Read-ExactBytes $Stream 4)) }
        3 {
            $length = (Read-ExactBytes $Stream 1)[0]
            Assert-True ($length -gt 0) "SOCKS reply domain is empty"
            [Text.Encoding]::ASCII.GetString((Read-ExactBytes $Stream $length))
        }
        4 { [Net.IPAddress]::new((Read-ExactBytes $Stream 16)) }
        default { throw "SOCKS reply address family mismatch" }
    }
    $portBytes = Read-ExactBytes $Stream 2
    $port = ([int]$portBytes[0] -shl 8) -bor [int]$portBytes[1]
    return [pscustomobject]@{ Reply = [int]$header[1]; Address = $address; Port = $port; Type = [int]$header[3] }
}

function Invoke-ProductSocksTcp(
    [int]$SocksPort,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [bool]$ExpectEcho
) {
    $session = Open-ProductSocks $SocksPort
    try {
        $request = New-SocksRequest 1 $Address $Port
        $session.Stream.Write($request, 0, $request.Length)
        if ($ExpectEcho) {
            $reply = Read-SocksReply $session.Stream
            Assert-True ($reply.Reply -eq 0) "SOCKS direct TCP request failed"
            $session.Stream.Write($Payload, 0, $Payload.Length)
            $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
            $echo = Read-ExactBytes $session.Stream $Payload.Length
            Assert-True (($echo -join ",") -eq ($Payload -join ",")) "SOCKS direct TCP echo mismatch"
        } else {
            $session.Stream.ReadTimeout = 1500
            try {
                $reply = Read-SocksReply $session.Stream
                if ($reply.Reply -eq 0) { $session.Stream.Write($Payload, 0, $Payload.Length) }
            } catch { }
        }
    } finally { $session.Client.Dispose() }
}

function Invoke-ProductSocksUdp(
    [int]$SocksPort,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [bool]$ExpectEcho
) {
    $session = Open-ProductSocks $SocksPort
    $client = $null
    try {
        $request = New-SocksRequest 3 "0.0.0.0" 0
        $session.Stream.Write($request, 0, $request.Length)
        $reply = Read-SocksReply $session.Stream
        Assert-True ($reply.Reply -eq 0 -and $reply.Type -eq 1) "SOCKS UDP association failed"
        $relayAddress = [Net.IPAddress]$reply.Address
        if ($relayAddress.Equals([Net.IPAddress]::Any)) { $relayAddress = [Net.IPAddress]::Loopback }
        Assert-True ([Net.IPAddress]::IsLoopback($relayAddress)) "SOCKS UDP relay was not loopback"
        $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $client.Connect($relayAddress, $reply.Port)
        $datagram = [Collections.Generic.List[byte]]::new()
        $datagram.AddRange([byte[]](0, 0, 0, 1))
        $datagram.AddRange([Net.IPAddress]::Parse($Address).GetAddressBytes())
        $datagram.Add([byte]($Port -shr 8))
        $datagram.Add([byte]($Port -band 0xff))
        $datagram.AddRange($Payload)
        [void]$client.Send($datagram.ToArray(), $datagram.Count)
        $receive = $client.ReceiveAsync()
        if ($ExpectEcho) {
            Assert-True ($receive.Wait(5000) -and -not $receive.IsFaulted) "SOCKS direct UDP response failed"
            $response = $receive.Result.Buffer
            Assert-True ($response.Length -eq $Payload.Length + 10 -and
                $response[0] -eq 0 -and $response[1] -eq 0 -and $response[2] -eq 0 -and $response[3] -eq 1) "SOCKS direct UDP frame mismatch"
            Assert-True (($response[4..7] -join ",") -eq ([Net.IPAddress]::Parse($Address).GetAddressBytes() -join ",") -and
                ((([int]$response[8] -shl 8) -bor [int]$response[9]) -eq $Port) -and
                (($response[10..($response.Length - 1)] -join ",") -eq ($Payload -join ","))) "SOCKS direct UDP echo mismatch"
        } else {
            [void]$receive.Wait(750)
        }
    } finally {
        if ($client) { $client.Dispose() }
        $session.Client.Dispose()
    }
}

function Invoke-ProductDns([int]$ListenPort, [bool]$Tcp, [byte[]]$Query) {
    if ($Tcp) {
        $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $connected = $client.ConnectAsync([Net.IPAddress]::Loopback, $ListenPort)
            Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "local DNS TCP connect failed"
            $stream = $client.GetStream()
            $frame = [byte[]]::new($Query.Length + 2)
            $frame[0] = [byte]($Query.Length -shr 8)
            $frame[1] = [byte]($Query.Length -band 0xff)
            [Array]::Copy($Query, 0, $frame, 2, $Query.Length)
            $stream.Write($frame, 0, $frame.Length)
            Start-Sleep -Milliseconds 500
        } finally { $client.Dispose() }
    } else {
        $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $client.Connect([Net.IPAddress]::Loopback, $ListenPort)
            [void]$client.Send($Query, $Query.Length)
            Start-Sleep -Milliseconds 500
        } finally { $client.Dispose() }
    }
}

function Invoke-TunProductTcp([string]$Address, [int]$Port, [int]$InterfaceIndex, [byte[]]$Payload) {
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $echo = Read-ExactBytes $stream $Payload.Length
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "manual TUN TCP echo mismatch"
    } finally { $session.Client.Dispose() }
}

function Invoke-TunProductUdp([string]$Address, [int]$Port, [int]$InterfaceIndex, [byte[]]$Payload) {
    $client = Open-TunUdp $Address $Port $InterfaceIndex
    try {
        [void]$client.Send($Payload, $Payload.Length)
        $echo = Receive-TunUdp $client
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "manual TUN UDP echo mismatch"
    } finally { $client.Dispose() }
}

function Open-TunUdp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.UdpClient]::new($family)
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $client.Connect($Address, $Port)
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN UDP source bind mismatch"
    return $client
}

function Receive-TunUdp([Net.Sockets.UdpClient]$Client, [int]$TimeoutMilliseconds = 5000) {
    $receive = $Client.ReceiveAsync()
    Assert-True ($receive.Wait($TimeoutMilliseconds)) "TUN UDP response timeout"
    if ($receive.IsFaulted) { throw "TUN UDP response failed" }
    return $receive.Result.Buffer
}

function Invoke-UdpEchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2UdpGate]$Gate,
    [byte[]]$Payload
) {
    $expectedGate = $Gate.Requests + 1
    $probe = [Ferrum2UdpProbe]::new($Address, $Port)
    $script:tcpResources.Add($probe)
    $client = Open-TunUdp $Address $Port $InterfaceIndex
    try {
        [void]$client.Send($Payload, $Payload.Length)
        Assert-True ($Gate.WaitRequests($expectedGate, 5000)) "selected UDP egress gate was not opened"
        $response = Receive-TunUdp $client
        Assert-True (($response -join ",") -eq ($Payload -join ",")) "UDP echo mismatch"
        Assert-True ($probe.WaitRequests(1, 5000)) "UDP target did not receive datagram"
        Assert-True (($probe.Received -join ",") -eq ($Payload -join ",")) "UDP target payload mismatch"
        Assert-True ($Gate.Fault -eq "none" -and $probe.Fault -eq "none") "UDP witness faulted"
    } finally { $client.Dispose() }
}

function Invoke-AdapterCycles(
    [string]$Executable,
    [string]$Configuration,
    [string]$ExpectedAdapter = $script:adapterName,
    [Nullable[int]]$MetricsPort = $null,
    [bool]$Managed = $false,
    [Nullable[int]]$SocksPort = $null
) {
    if ($Managed) {
        Assert-True ($null -ne $MetricsPort) "managed cycles require metrics port"
        Assert-True ($null -ne $SocksPort) "managed cycles require SOCKS port"
        $configurationTemplate = Get-Content -LiteralPath $Configuration -Raw
    }
    for ($cycle = 0; $cycle -lt 100; $cycle++) {
        $cycleConfiguration = $Configuration
        $cycleMetricsPort = $MetricsPort
        try {
            if ($Managed) {
                $cycleConfiguration = Join-Path $script:work ("client-managed-route-only-cycle-{0:D3}.toml" -f ($cycle + 1))
                Assert-True (-not (Test-Path -LiteralPath $cycleConfiguration)) "managed cycle generated config baseline not absent"
                $cycleSocksPort = Get-UniqueTcpPort
                $cycleMetricsPort = Get-UniqueTcpPort
                $cycleConfigText = $configurationTemplate.Replace("127.0.0.1:$([int]$SocksPort)", "127.0.0.1:$cycleSocksPort").Replace("127.0.0.1:$([int]$MetricsPort)", "127.0.0.1:$cycleMetricsPort")
                Assert-True (-not $cycleConfigText.Contains("127.0.0.1:$([int]$SocksPort)") -and
                    -not $cycleConfigText.Contains("127.0.0.1:$([int]$MetricsPort)")) "managed cycle listener generation mismatch"
                Set-Content -LiteralPath $cycleConfiguration -Value $cycleConfigText -Encoding utf8NoBOM -NoNewline
                $offlineOutput = @(& $Executable --config $cycleConfiguration --check-config 2>&1)
                Assert-True ($LASTEXITCODE -eq 0) "managed cycle generated config validation failed"
                Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed cycle generated config marker mismatch"
            }
            Assert-True (-not $script:activeProcess) "cycle candidate state was not empty"
            $candidateBaseline = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
            Assert-True ($candidateBaseline.Count -eq 0) "cycle candidate baseline not absent"
            Assert-InterfaceGone $ExpectedAdapter $null
            $script:activeProcess = Start-Candidate $Executable $cycleConfiguration
            $adapter = Wait-AdapterReady $ExpectedAdapter 20 $Managed
            $script:ownedInterfaceIndex = [int]$adapter.ifIndex
            if ($Managed) {
                $owners = Get-Metrics ([int]$cycleMetricsPort)
                Assert-True ((Get-ClientGaugeValue $owners "ferrum2_udp_sessions_active") -eq 0 -and
                    (Get-ClientGaugeValue $owners "ferrum2_udp_buffered_bytes") -eq 0) "managed cycle process-private owner baseline changed"
            }
            $cycleRoute = Add-TunRoute $script:ownedInterfaceIndex "192.0.2.200/32"
            $cycleRouteReadback = @(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction Stop)
            Assert-True ($cycleRouteReadback.Count -eq 1) "cycle route readback mismatch"
            Remove-NetRoute -InputObject $cycleRoute -Confirm:$false -ErrorAction Stop
            Assert-True $script:ownedRoutes.Remove($cycleRoute) "cycle route ownership mismatch"
            Assert-True (@(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "cycle route leaked"
            $cycleProcess = $script:activeProcess
            Stop-Candidate $cycleProcess
            $cycleProcess.Refresh()
            Assert-True $cycleProcess.HasExited "cycle candidate process leaked"
            $script:activeProcess = $null
            $candidateAfterStop = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
            Assert-True ($candidateAfterStop.Count -eq 0) "cycle candidate remained after stop"
            Wait-AdapterAbsent $ExpectedAdapter 20 11
            Assert-InterfaceGone $ExpectedAdapter $script:ownedInterfaceIndex
            if ($Managed) {
                Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $script:ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed cycle DNS residue"
            }
            $script:cycleRows++
        } catch {
            if ($Managed) { [Console]::Error.WriteLine("managed cycle failure ordinal=$($cycle + 1)") }
            throw
        } finally {
            if ($Managed -and (Test-Path -LiteralPath $cycleConfiguration)) {
                Remove-Item -LiteralPath $cycleConfiguration -Force
            }
            if ($Managed) { Assert-True (-not (Test-Path -LiteralPath $cycleConfiguration)) "managed cycle generated config leaked" }
        }
    }
    Assert-True ($script:cycleRows -eq 100) "adapter cycle count mismatch"
}

function Complete-Tcp08PressureWriteCleanup([Threading.Tasks.Task]$Task) {
    $classification = "completed_after_socket_close"
    $exceptionTypes = @()
    try {
        Assert-True ($Task.Wait(5000)) "TCP-08 pressure writer did not stop within the bounded cleanup timeout"
    } catch [AggregateException] {
        $flattened = $_.Exception.Flatten()
        $exceptions = @($flattened.InnerExceptions)
        $exceptionTypes = @($exceptions | ForEach-Object { $_.GetType().FullName })
        $unexpected = @($exceptions | Where-Object {
            -not ($_ -is [OperationCanceledException]) -and
            -not ($_ -is [ObjectDisposedException]) -and
            -not ($_ -is [IO.IOException]) -and
            -not ($_ -is [Net.Sockets.SocketException])
        })
        if ($unexpected.Count -gt 0) {
            throw [InvalidOperationException]::new(
                "TCP-08 pressure writer faulted with an unexpected exception after socket close",
                $flattened
            )
        }
        $classification = if ($Task.IsCanceled) { "cancelled_after_socket_close" } else { "expected_fault_after_socket_close" }
    }
    Assert-True $Task.IsCompleted "TCP-08 pressure writer did not report a terminal state after bounded cleanup wait"
    return [ordered]@{
        classification = $classification
        task_status = $Task.Status.ToString()
        exception_types = $exceptionTypes
    }
}

function Invoke-Tcp08(
    [string]$Target,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate]$Gate,
    [int]$GatePort,
    [int]$ServerPort,
    [int]$MetricsPort,
    [bool]$CollectPerformance
) {
    $pressure = $null
    $pressureWrite = $null
    $stall = $null
    $pressureClientOwned = $false
    try {
        $pressureGate = $Gate.Accepted + 1
        $pressure = Open-TunTcp $Target $Port $InterfaceIndex
        $script:tcpResources.Add([IDisposable]$pressure.Client)
        $pressureClientOwned = $true
        Assert-True ($Gate.WaitAccepted($pressureGate, 5000)) "backpressure route did not open"
        $stall = [Ferrum2TcpProbe]::new($Target, $Port, "stall")
        $script:tcpResources.Add($stall)
        Add-Tcp08Event "pressure_listener_started" ([ordered]@{
            target = $Target
            port = $Port
            listener_active = $stall.ListenerActive
        })
        $Gate.Release($pressureGate)
        Assert-True ($stall.WaitAccepted(5000)) "backpressure target was not opened"
        Add-Tcp08Event "pressure_target_accepted" ([ordered]@{
            local_endpoint = $stall.AcceptedSocketLocalEndpoint
            remote_endpoint = $stall.AcceptedSocketRemoteEndpoint
        })
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and
            $stall.StallWaitActive -and $stall.ReadAttempts -eq 0) "backpressure target was not stably non-reading before pressure write"

        $pressureChunk = [byte[]]::new(1024 * 1024)
        $pressureStream = $pressure.Client.GetStream()
        Add-Tcp08Event "pressure_write_started" ([ordered]@{
            pressure_gate_index = $pressureGate
            chunk_bytes = $pressureChunk.Length
            attempt_limit = 128
            target_accepted_before_write = $true
        })
        $pendingAttempt = $null
        for ($attempt = 0; $attempt -lt 128; $attempt++) {
            $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            if (-not $pressureWrite.Wait(100)) {
                $pendingAttempt = $attempt + 1
                break
            }
        }
        Assert-True ($pressureWrite -and -not $pressureWrite.IsCompleted) "backpressure write unexpectedly drained"
        Add-Tcp08Event "pressure_write_became_pending" ([ordered]@{
            attempt = $pendingAttempt
            task_id = $pressureWrite.Id
            task_status = $pressureWrite.Status.ToString()
            observation_wait_ms = 100
        })
        if ($CollectPerformance) { Complete-PerformanceSample $script:activeProcess $MetricsPort }

        $beforeSignal = $null
        while (-not $beforeSignal) {
            while ($pressureWrite.Wait($script:tcp08PressureStableWaitMilliseconds)) {
                Assert-True ($pendingAttempt -lt 128) "TCP-08 pressure write never became stably pending"
                $pendingAttempt++
                $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            }
            Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressure write did not remain pending for the stable observation window"
            Add-Tcp08Event "pressure_write_stably_pending" ([ordered]@{
                phase = "before_live_evidence"
                attempt = $pendingAttempt
                task_id = $pressureWrite.Id
                task_status = $pressureWrite.Status.ToString()
                observation_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            })
            $evidenceCandidate = Get-Tcp08LiveEvidence "before_ctrl_break" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
            if (-not $evidenceCandidate.pressure_write.is_completed) {
                $beforeSignal = $evidenceCandidate
            } else {
                Add-Tcp08Event "pressure_write_completed_during_live_evidence" ([ordered]@{
                    attempt = $pendingAttempt
                    task_id = $pressureWrite.Id
                    task_status = $pressureWrite.Status.ToString()
                })
            }
        }
        $script:tcp08Samples.Add($beforeSignal)
        if ($RequireTcp08ProductMetrics -or $beforeSignal.metrics.available) {
            Assert-Tcp08ProductOwnerMetrics $beforeSignal.metrics "before CTRL_BREAK"
        }
        Assert-True $beforeSignal.pressure_client.socket_open "TCP-08 pressure client socket was not open before CTRL_BREAK"
        Assert-True (-not $beforeSignal.pressure_write.is_completed) "TCP-08 pressure write was not pending before CTRL_BREAK"
        Assert-True ($beforeSignal.target.listener_active -and $beforeSignal.target.accepted_socket_open -and
            $beforeSignal.target.stall_wait_active -and $beforeSignal.target.read_attempts -eq 0) "TCP-08 target was not an open non-reading peer before CTRL_BREAK"
        foreach ($name in @("target_listener", "target_accepted", "pressure_logical", "client_underlay", "server_relay")) {
            Assert-True ($beforeSignal.connections.assertions[$name] -gt 0) "TCP-08 socket ownership witness missing before CTRL_BREAK: $name"
        }

        if ($script:tcp08Enabled) {
            $shutdownReportPath = Join-Path $script:tcp08ArtifactPath "client.stderr.log"
            $reportSnapshotBeforeSignal = Get-Tcp08SharedLogSnapshot $shutdownReportPath "before_ctrl_break"
            Add-Tcp08Event "shutdown_report_candidate_window_opened" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                capture_phase = $reportSnapshotBeforeSignal.capture_phase
                byte_length = $reportSnapshotBeforeSignal.byte_length
                complete_byte_length = $reportSnapshotBeforeSignal.complete_byte_length
                trailing_partial_byte_count = $reportSnapshotBeforeSignal.trailing_partial_byte_count
                complete_line_count = $reportSnapshotBeforeSignal.complete_line_count
                lower_exclusive_candidate_ordinal = $reportSnapshotBeforeSignal.candidate_count
            })
        }

        while ($pressureWrite.Wait($script:tcp08PressureStableWaitMilliseconds)) {
            Assert-True ($pendingAttempt -lt 128) "TCP-08 pressure write never became stably pending"
            $pendingAttempt++
            $pressureWrite = $pressureStream.WriteAsync($pressureChunk, 0, $pressureChunk.Length)
        }
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressure write did not remain pending for the stable observation window"
        Assert-True (Test-Tcp08ClientSocketOpen $pressure.Client) "TCP-08 pressure client socket closed before CTRL_BREAK"
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and $stall.StallWaitActive -and
            $stall.ReadAttempts -eq 0) "TCP-08 target stopped being an open non-reading peer before CTRL_BREAK"
        Add-Tcp08Event "pressure_write_stably_pending" ([ordered]@{
            phase = "before_ctrl_break"
            attempt = $pendingAttempt
            task_id = $pressureWrite.Id
            task_status = $pressureWrite.Status.ToString()
            observation_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            local_endpoint = Get-Tcp08Endpoint $pressure.Client $true
            remote_endpoint = Get-Tcp08Endpoint $pressure.Client $false
        })
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 stable pressure write completed before CTRL_BREAK dispatch"

        $forcedShutdown = [Diagnostics.Stopwatch]::StartNew()
        $breakResult = [Ferrum2ProcessGroup]::BreakDetailed([uint32]$script:activeProcess.Id)
        $script:tcp08CtrlBreak = Convert-Tcp08CtrlBreakResult $breakResult
        if ($breakResult.SendStartedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_send_started" $breakResult.SendStartedTimestamp ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                source = "Ferrum2ProcessGroup.BreakDetailed"
            })
        }
        if ($breakResult.SendReturnedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_send_returned" $breakResult.SendReturnedTimestamp ([ordered]@{
                generate_console_ctrl_event_result = $breakResult.GenerateConsoleCtrlEventResult
                win32_error = $breakResult.GenerateConsoleCtrlEventWin32Error
                send_duration_ms = [Math]::Round($breakResult.SendDurationMilliseconds, 3)
            })
        }
        if ($breakResult.InternalWaitStartedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_internal_wait_started" $breakResult.InternalWaitStartedTimestamp ([ordered]@{
                configured_wait_ms = 250
            })
        }
        if ($breakResult.InternalWaitReturnedTimestamp -gt 0) {
            Add-Tcp08EventAtTimestamp "ctrl_break_internal_wait_returned" $breakResult.InternalWaitReturnedTimestamp ([ordered]@{
                measured_wait_ms = [Math]::Round($breakResult.InternalWaitMilliseconds, 3)
            })
        }
        Add-Tcp08Event "ctrl_break_call_returned" $script:tcp08CtrlBreak
        Assert-True $breakResult.Succeeded "TCP-08 CTRL_BREAK delivery failed"
        $exitedDuringGrace = [Ferrum2ProcessGroup]::Wait([uint32]$script:activeProcess.Id, 300)
        Add-Tcp08Event "grace_probe_completed" ([ordered]@{
            wait_ms = 300
            process_exited = $exitedDuringGrace
            pressure_write_pending = -not $pressureWrite.IsCompleted
            pressure_write_attempt = $pendingAttempt
            pressure_write_task_id = $pressureWrite.Id
            target_socket_open = $stall.AcceptedSocketOpen
        })
        if ($exitedDuringGrace) {
            Add-Tcp08Event "process_exited" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                observation = "controller_grace_probe"
                elapsed_since_ctrl_break_call_ms = [Math]::Round($forcedShutdown.Elapsed.TotalMilliseconds, 3)
            })
            $script:tcp08ExitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$script:activeProcess.Id)
            Add-Tcp08Event "process_exit_code" ([ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                exit_code = $script:tcp08ExitCode
            })
        }
        Assert-True (-not $exitedDuringGrace) "TCP-08 exited during grace"
        Assert-True (-not $pressureWrite.IsCompleted) "TCP-08 pressured flow was not owned through grace"
        Assert-True (Test-Tcp08ClientSocketOpen $pressure.Client) "TCP-08 pressure client socket closed during grace"
        Assert-True ($stall.ListenerActive -and $stall.AcceptedSocketOpen -and $stall.StallWaitActive -and
            $stall.ReadAttempts -eq 0) "TCP-08 target did not remain an open non-reading peer through grace"
        $duringGrace = Get-Tcp08LiveEvidence "during_grace" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
        $script:tcp08Samples.Add($duringGrace)
        if ($duringGrace.metrics.available) {
            Assert-Tcp08ProductOwnerMetrics $duringGrace.metrics "during grace"
        } else {
            Assert-True $duringGrace.metrics.unavailable_after_quiesce_expected "TCP-08 owner metric loss during grace was not classified"
            Add-Tcp08Event "product_owner_metrics_unavailable_after_quiesce" ([ordered]@{
                expected = $true
                required_before_ctrl_break = [bool]$RequireTcp08ProductMetrics
                failure_type = $duringGrace.metrics.failure_type
            })
        }

        Assert-True (Wait-ProcessExit $script:activeProcess 10) "TCP-08 forced cancellation did not exit"
        $forcedShutdown.Stop()
        Add-Tcp08Event "process_exited" ([ordered]@{
            process_id = [uint32]$script:activeProcess.Id
            observation = "controller_exit_wait"
            elapsed_since_ctrl_break_call_ms = [Math]::Round($forcedShutdown.Elapsed.TotalMilliseconds, 3)
        })
        $script:tcp08ExitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$script:activeProcess.Id)
        Add-Tcp08Event "process_exit_code" ([ordered]@{
            process_id = [uint32]$script:activeProcess.Id
            exit_code = $script:tcp08ExitCode
        })
        if ($script:tcp08Enabled) {
            $reportSnapshotAfterExit = Get-Tcp08SharedLogSnapshot $shutdownReportPath "after_process_exit"
            $script:tcp08ShutdownReportCandidateWindow = [ordered]@{
                process_id = [uint32]$script:activeProcess.Id
                lower_exclusive_candidate_ordinal = $reportSnapshotBeforeSignal.candidate_count
                upper_inclusive_candidate_ordinal = $reportSnapshotAfterExit.candidate_count
                candidate_delta = $reportSnapshotAfterExit.candidate_count - $reportSnapshotBeforeSignal.candidate_count
                lower_capture = [ordered]@{
                    capture_phase = $reportSnapshotBeforeSignal.capture_phase
                    byte_length = $reportSnapshotBeforeSignal.byte_length
                    complete_byte_length = $reportSnapshotBeforeSignal.complete_byte_length
                    trailing_partial_byte_count = $reportSnapshotBeforeSignal.trailing_partial_byte_count
                    complete_line_count = $reportSnapshotBeforeSignal.complete_line_count
                }
                upper_capture = [ordered]@{
                    capture_phase = $reportSnapshotAfterExit.capture_phase
                    byte_length = $reportSnapshotAfterExit.byte_length
                    complete_byte_length = $reportSnapshotAfterExit.complete_byte_length
                    trailing_partial_byte_count = $reportSnapshotAfterExit.trailing_partial_byte_count
                    complete_line_count = $reportSnapshotAfterExit.complete_line_count
                }
            }
            Add-Tcp08Event "shutdown_report_candidate_window_frozen" $script:tcp08ShutdownReportCandidateWindow
        }
        Assert-True ($forcedShutdown.ElapsedMilliseconds -ge 900) "TCP-08 force preceded the grace deadline"
        if ($script:RequireTcp08ProductMetrics) {
            Assert-True ($script:tcp08ShutdownReportCandidateWindow.candidate_delta -eq 1) "TCP-08 strict shutdown-report candidate delta was not one"
        }
        Assert-True ($script:tcp08ExitCode -eq 0) "TCP-08 forced shutdown was not clean: exit=$($script:tcp08ExitCode)"
        $afterExit = Get-Tcp08LiveEvidence "after_process_exit" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
        $script:tcp08Samples.Add($afterExit)
        if ($CollectPerformance) { $script:performanceForceDrain = $true }
        [Ferrum2ProcessGroup]::Close([uint32]$script:activeProcess.Id)
        $script:activeProcess = $null
    } catch {
        $script:tcp08Result = "FAIL"
        Add-Tcp08Event "tcp08_failed" ([ordered]@{
            failure_type = $_.Exception.GetType().FullName
            failure = $_.Exception.Message
        })
        throw
    } finally {
        $pressureCleanupFailures = [Collections.Generic.List[Exception]]::new()
        if ($pressureClientOwned -and $pressure) {
            try { $pressure.Client.Dispose() }
            catch { $pressureCleanupFailures.Add($_.Exception) }
        }
        if ($pressureWrite) {
            try {
                $pressureWriteCleanup = Complete-Tcp08PressureWriteCleanup $pressureWrite
                Add-Tcp08Event "pressure_write_cleanup_completed" $pressureWriteCleanup
            } catch {
                $pressureCleanupFailures.Add($_.Exception)
            }
        }
        if ($pressureClientOwned -and $pressure) {
            try {
                Assert-True $script:tcpResources.Remove([IDisposable]$pressure.Client) "TCP-08 pressure client ownership mismatch"
                $pressureClientOwned = $false
            } catch {
                $pressureCleanupFailures.Add($_.Exception)
            }
        }
        if (-not $pressureClientOwned -and $pressure) { $pressure = $null }
        if ($pressureCleanupFailures.Count -eq 1) { throw $pressureCleanupFailures[0] }
        if ($pressureCleanupFailures.Count -gt 1) {
            throw [AggregateException]::new("TCP-08 pressure writer cleanup failed", $pressureCleanupFailures.ToArray())
        }
    }

    try {
        Wait-AdapterAbsent $script:adapterName
        Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
        Add-Tcp08Event "adapter_absent" ([ordered]@{ interface_index = $script:ownedInterfaceIndex })
        $script:tcp08Result = "PASS"
    } catch {
        $script:tcp08Result = "FAIL"
        Add-Tcp08Event "tcp08_failed" ([ordered]@{
            failure_type = $_.Exception.GetType().FullName
            failure = $_.Exception.Message
        })
        throw
    }
}

function New-M17TunFixture(
    [string]$Name,
    [string]$TunFields,
    [bool]$WithDns,
    [string]$Additional = ""
) {
    $tunOutbound = if ([regex]::IsMatch($Additional, '(?m)^\[route\]\r?$')) {
        ""
    } else {
        'outbound = "proxy"'
    }
    $dns = if ($WithDns) {
@"
[dns]
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:15353"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "1.1.1.1:53"
[dns.route]
final = "resolver"
"@
    } else { "" }
    $source = @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$script:adapterName"
$TunFields
$tunOutbound
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
$dns
$Additional
"@
    return [pscustomobject]@{ Name = $Name; Source = $source }
}

function Get-M17ModeContract {
    switch ($script:Mode) {
        "network-reset" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "network-reset-dual-strict" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
strict_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = 32
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "ordinary_route_notifications_reset_network_runtime",
                    "same_process_and_managed_adapter_identity",
                    "managed_addresses_routes_and_dns_are_unchanged",
                    "strict_route_is_effective_and_filter_identity_is_unchanged",
                    "network_generation_and_reset_metrics_advance",
                    "retry_reset_failure_and_full_rebuild_metrics_are_unchanged",
                    "fixed_and_direct_dual_stack_underlay_binding",
                    "multihoming_prefix_and_metric_selection",
                    "route_interface_and_address_notifications",
                    "foreign_route_state_survives_cleanup",
                    "foreign_address_state_survives_cleanup",
                    "dad_failure_rolls_back_in_reverse",
                    "owned_state_damage_is_the_only_full_rebuild_trigger",
                    "reset_retries_without_managed_teardown",
                    "network_reset_hooks_accept_each_generation_once"
                )
                counters = @(
                    "ferrum2_network_reset_total",
                    "ferrum2_network_full_rebuild_total",
                    "ferrum2_network_generation",
                    "ferrum2_tun_session_generation",
                    "ferrum2_tun_strict_route_requested",
                    "ferrum2_tun_strict_route_effective",
                    "ferrum2_tun_strict_route_filter_install_total"
                )
                network_reset_cycles = $script:NetworkResetCycles
            }
        }
        "restart-stress" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "restart-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = 32
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "same_process_for_every_restart", "generation_advances_once_per_restart",
                    "admission_quiesces_during_rebuild", "stale_flows_and_fragments_are_cleared",
                    "adapter_route_dns_and_handler_baselines_restore"
                )
                counters = @(
                    "ferrum2_network_reset_total",
                    "ferrum2_network_full_rebuild_total",
                    "ferrum2_network_generation",
                    "ferrum2_tun_session_generation"
                )
                restart_cycles = $script:RestartCycles
            }
        }
        "fragments" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "fragments-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "ipv4_udp_out_of_order", "ipv4_tcp_out_of_order",
                    "ipv6_extension_and_fragment", "ipv6_atomic_fragment",
                    "fragmented_synthetic_dns", "overlap_drops_entry", "timeout_drops_entry",
                    "disabled_family_rejects_fragment", "network_reset_rejects_stale_generation"
                )
                counters = @(
                    "ferrum2_tun_reassembly_entries_active",
                    "ferrum2_tun_packets_rejected_total"
                )
            }
        }
        "dual-stack-dns" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "dns-ipv4-only" @"
ipv4_address = "198.18.0.2/30"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
udp_filtering = "address_dependent"
"@ $true
                    New-M17TunFixture "dns-ipv6-only" @"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                    New-M17TunFixture "dns-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "ipv4_udp_dns", "ipv4_tcp_dns", "ipv6_udp_dns", "ipv6_tcp_dns",
                    "exact_port_53_match", "ordinary_port_53_not_intercepted",
                    "dual_dns_readback_and_restore"
                )
                counters = @("ferrum2_tun_packets_ingress_total", "ferrum2_tun_packets_egress_total")
            }
        }
        "udp-policy" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "udp-adf" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "address_dependent"
"@ $false @"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.51.100.10"
port = 3478
action = "route"
outbound = "direct"
"@
                    New-M17TunFixture "udp-eif" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "endpoint_independent"
"@ $false @"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.51.100.10"
port = 3478
action = "route"
outbound = "direct"
"@
                )
                witnesses = @(
                    "one_eim_association_for_multiple_targets", "adf_allows_authorized_ip_any_port",
                    "adf_rejects_unauthorized_ip", "eif_allows_valid_same_family_peer",
                    "rejected_target_never_authorizes_peer", "first_ordinary_datagram_freezes_route_and_outbound",
                    "ipv4_and_ipv6_sources_form_distinct_associations", "directed_broadcast_never_allocates_association",
                    "udp_firewall_scope_is_journaled_and_removed",
                    "dns_udp_payload_round_trips", "quic_v1_initial_envelope_round_trips",
                    "stun_binding_requests_reach_multiple_servers",
                    "webrtc_ice_candidate_check_round_trips",
                    "game_style_binary_datagrams_reach_multiple_peers",
                    "one_eim_association_reuses_first_outbound_for_all_targets",
                    "association_capacity_drops_new_without_evicting_live",
                    "udp_queue_pressure_is_bounded_and_control_remains_live",
                    "reset_clears_udp_stale_generation_state"
                )
                counters = @(
                    "ferrum2_tun_udp_associations_active", "ferrum2_tun_udp_candidates_active",
                    "ferrum2_tun_udp_association_rejected_limit_total",
                    "ferrum2_tun_udp_datagram_queue_full_total",
                    "ferrum2_tun_udp_response_queue_full_total",
                    "ferrum2_tun_udp_stale_generation_total"
                )
            }
        }
        "scheduler-ring-full" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "scheduler-ring-full" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
udp_filtering = "address_dependent"
"@ $false
                )
                witnesses = @(
                    "rx_bursts_8_16_64_have_no_structural_drop", "work_stages_rotate_fairly",
                    "udp_response_backpressure_is_lossless", "ring_full_drops_one_complete_packet",
                    "ring_full_is_not_retried", "ring_full_does_not_reset_or_rebuild_network",
                    "wintun_error_kinds_have_exact_owner_dispositions",
                    "live_egress_pressure_has_closed_accounting"
                )
                counters = @(
                    "ferrum2_tun_internal_egress_backpressured_total",
                    "ferrum2_tun_wintun_ring_full_dropped_total",
                    "ferrum2_tun_packets_egress_total"
                )
            }
        }
        default { throw "M17 contract dispatch received an invalid mode" }
    }
}

function Invoke-M17ContractPreflight {
    $contract = Get-M17ModeContract
    $artifactRoot = if ([string]::IsNullOrWhiteSpace($script:ArtifactDirectory)) {
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m17-artifacts\$script:runIdentity"
    } else {
        [IO.Path]::GetFullPath($script:ArtifactDirectory)
    }
    $artifactRoot = [IO.Path]::GetFullPath($artifactRoot).TrimEnd('\', '/')
    $workRoot = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
    Assert-True (-not $artifactRoot.Equals($workRoot, [StringComparison]::OrdinalIgnoreCase) -and
        -not $artifactRoot.StartsWith("$workRoot\", [StringComparison]::OrdinalIgnoreCase)) "M17 artifacts must survive controller work cleanup"
    if (-not (Test-Path -LiteralPath $artifactRoot)) {
        New-Item -ItemType Directory -Path $artifactRoot | Out-Null
    }
    Assert-NotReparsePoint $artifactRoot "M17 artifact directory"
    foreach ($name in @(
        "identity-ledger.json", "m17-contract.json", "m17-result.json",
        "external-cleanup.json", "external-cleanup.json.pending", "network-reset-cycles.jsonl"
    )) {
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $artifactRoot $name))) "M17 artifact baseline is not absent: $name"
    }
    $script:m17ArtifactRoot = $artifactRoot
    $script:m17ArtifactInitialized = $true
    $script:m17Contract = $contract
    $script:m17StartedUtc = [DateTime]::UtcNow.ToString("o")
    $identityArtifact = Join-Path $artifactRoot "identity-ledger.json"
    [IO.File]::WriteAllBytes($identityArtifact, [IO.File]::ReadAllBytes($script:capabilityIdentity.Path))
    Assert-True ((Get-FileHash -LiteralPath $identityArtifact -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
        $script:capabilityIdentityHash) "M17 artifact identity ledger hash changed"
    $fixtureRoot = Join-Path $script:work "m17-fixtures"
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $fixtureRows = [System.Collections.Generic.List[object]]::new()
    foreach ($fixture in $contract.fixtures) {
        $path = Join-Path $fixtureRoot "$($fixture.Name).toml"
        [IO.File]::WriteAllText($path, $fixture.Source, [Text.UTF8Encoding]::new($false))
        $stderrPath = "$path.stderr"
        $stdout = @(& $script:binary --config $path --check-config 2> $stderrPath)
        $exitCode = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw -Encoding utf8
        } else { "" }
        Assert-True ($exitCode -eq 0) "M17 fixture $($fixture.Name) did not pass offline config validation"
        Assert-True (($stdout -join "`n") -ceq "configuration valid") "M17 fixture $($fixture.Name) stdout changed"
        Assert-True ([string]::IsNullOrEmpty($stderr)) "M17 fixture $($fixture.Name) emitted stderr during offline validation"
        $fixtureRows.Add([ordered]@{
            name = $fixture.Name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            offline_check = "pass"
        })
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.m17-contract.v1"
        status = "preflight_pass"
        mode = $script:Mode
        network_reset_cycles = if ($script:Mode -eq "network-reset") { $script:NetworkResetCycles } else { $null }
        restart_cycles = if ($script:Mode -eq "restart-stress") { $script:RestartCycles } else { $null }
        approved_vm_name = $script:expectedHyperVVmName
        approved_vm_id = $script:expectedHyperVVmId
        approved_checkpoint_name = $script:expectedHyperVCheckpointName
        approved_checkpoint_id = $script:expectedHyperVCheckpointId
        guest_build = [string]$script:capabilityIdentity.Ledger.guest_build
        identity_sha256 = $script:capabilityIdentityHash
        candidate_sha = [string]$script:capabilityIdentity.Ledger.candidate_sha
        client_sha256 = [string]$script:capabilityIdentity.Ledger.client_sha256
        server_sha256 = [string]$script:capabilityIdentity.Ledger.server_sha256
        controller_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        wintun_zip_sha256 = $script:expectedZipHash.ToLowerInvariant()
        wintun_dll_sha256 = $script:expectedDllHash.ToLowerInvariant()
        test_binaries = if ($script:capabilityIdentity.Ledger.PSObject.Properties.Name -ccontains "test_binaries") {
            $script:capabilityIdentity.Ledger.test_binaries
        } else { $null }
        fixtures = $fixtureRows
        witnesses = $contract.witnesses
        counters = $contract.counters
    }
    $artifact = Join-Path $artifactRoot "m17-contract.json"
    [IO.File]::WriteAllText(
        $artifact,
        (($document | ConvertTo-Json -Depth 8) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $script:m17FixtureRows = @($fixtureRows)
    return [pscustomobject]@{ Contract = $contract; ArtifactRoot = $artifactRoot; FixtureRoot = $fixtureRoot }
}

function Add-M17Witness([string]$Name, [string]$Provenance, [string]$Evidence) {
    Assert-True ($Name -in @($script:m17Contract.witnesses)) "M17 witness is outside the mode contract: $Name"
    Assert-True (-not $script:m17WitnessRows.Contains($Name)) "duplicate M17 witness: $Name"
    $script:m17WitnessRows[$Name] = [ordered]@{
        name = $Name
        status = "pass"
        provenance = $Provenance
        evidence = $Evidence
    }
}

function Add-M17LiveRow([string]$Name, [System.Collections.IDictionary]$Evidence) {
    $script:m17LiveRows.Add([ordered]@{
        name = $Name
        status = "pass"
        evidence = $Evidence
    })
}

function Invoke-M17BoundedCommand(
    [string]$Name,
    [string]$Executable,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$TimeoutSeconds = 300
) {
    Assert-True ($Name -cmatch '^[a-z0-9][a-z0-9-]{0,95}$') "M17 command name is invalid"
    $stdoutPath = Join-Path $script:m17ArtifactRoot "$Name.stdout.log"
    $stderrPath = Join-Path $script:m17ArtifactRoot "$Name.stderr.log"
    Assert-True (-not (Test-Path -LiteralPath $stdoutPath) -and -not (Test-Path -LiteralPath $stderrPath)) "M17 command log baseline is not absent"
    $start = [Diagnostics.Stopwatch]::StartNew()
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    Assert-True $process.Start() "M17 command did not start: $Name"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
        [void]$process.WaitForExit(10000)
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $start.Stop()
    $utf8 = [Text.UTF8Encoding]::new($false)
    Assert-True ($utf8.GetByteCount($stdout) -le 4194304 -and $utf8.GetByteCount($stderr) -le 4194304) "M17 command output exceeded the fixed 4 MiB cap: $Name"
    [IO.File]::WriteAllText($stdoutPath, $stdout, $utf8)
    [IO.File]::WriteAllText($stderrPath, $stderr, $utf8)
    Assert-True (-not $timedOut) "M17 command timed out: $Name"
    $exitCode = $process.ExitCode
    $process.Dispose()
    return [pscustomobject]@{
        Name = $Name
        ExitCode = $exitCode
        DurationMilliseconds = [Math]::Round($start.Elapsed.TotalMilliseconds, 3)
        Stdout = $stdout
        Stderr = $stderr
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

function Get-M17MetricValue([string]$Metrics, [string]$Name, [bool]$AllowAbsent = $false) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?(?:\{[^}`r`n]*\})? ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return 0.0 }
    Assert-True ($matches.Count -gt 0) "missing M17 metric: $Name"
    [double]$total = 0
    foreach ($match in $matches) { $total += [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) }
    return $total
}

function Get-M17LabeledMetricValue(
    [string]$Metrics,
    [string]$Name,
    [string]$Label,
    [string]$Value,
    [bool]$AllowAbsent = $false
) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{[^}`r`n]*$([regex]::Escape($Label))=`"$([regex]::Escape($Value))`"[^}`r`n]*\} ([0-9]+(?:\.[0-9]+)?)$"
    $match = [regex]::Match($Metrics, $pattern)
    if (-not $match.Success -and $AllowAbsent) { return 0.0 }
    Assert-True $match.Success "missing M17 labeled metric: $Name/$Label=$Value"
    return [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-M17CounterSnapshot([string]$Metrics) {
    $snapshot = [ordered]@{}
    foreach ($name in @($script:m17Contract.counters)) {
        $snapshot[$name] = Get-M17MetricValue $Metrics $name $true
    }
    foreach ($name in @("ferrum2_tun_session_active", "ferrum2_tun_session_generation")) {
        if (-not $snapshot.Contains($name)) { $snapshot[$name] = Get-M17MetricValue $Metrics $name }
    }
    return $snapshot
}

function Wait-M17Session(
    [int]$MetricsPort,
    [double]$MinimumGeneration,
    [double]$ExpectedActive,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $metrics = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $metrics = Get-Metrics $MetricsPort 2 }
        catch {
            if ($_.Exception.Message -cne "metrics readiness timeout") { throw }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 50
            continue
        }
        $generation = Get-M17MetricValue $metrics "ferrum2_tun_session_generation"
        $active = Get-M17MetricValue $metrics "ferrum2_tun_session_active"
        if ($generation -ge $MinimumGeneration -and $active -eq $ExpectedActive) {
            return [pscustomobject]@{ Metrics = $metrics; Generation = $generation; Active = $active }
        }
        Start-Sleep -Milliseconds 50
    }
    if ($null -eq $metrics) {
        throw "M17 metrics remained unavailable during the bounded session wait: minimum_generation=$MinimumGeneration expected_active=$ExpectedActive"
    }
    $networkReset = Get-M17MetricValue $metrics "ferrum2_network_reset" $true
    $fullRebuild = Get-M17MetricValue $metrics "ferrum2_network_full_rebuild" $true
    throw "M17 session state timeout: minimum_generation=$MinimumGeneration expected_active=$ExpectedActive generation=$generation active=$active network_reset_total=$networkReset full_rebuild_total=$fullRebuild"
}

function Wait-M17FlowDrain(
    [int]$MetricsPort,
    [double]$ExpectedGeneration,
    [int]$MaximumUdpAssociations,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $metrics = $null
    do {
        try { $metrics = Get-Metrics $MetricsPort 2 }
        catch {
            if ($_.Exception.Message -cne "metrics readiness timeout") { throw }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 50
            continue
        }
        $generation = Get-M17MetricValue $metrics "ferrum2_tun_session_generation"
        $active = Get-M17MetricValue $metrics "ferrum2_tun_session_active"
        $tcpFlows = Get-M17MetricValue $metrics "ferrum2_tun_tcp_flows_active"
        $udpAssociations = Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active"
        $udpCandidates = Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active"
        $reassemblyEntries = Get-M17MetricValue $metrics "ferrum2_tun_reassembly_entries_active"
        $handlerTasks = Get-ClientGaugeValue $metrics "ferrum2_tun_handler_tasks_active"
        if ($generation -eq $ExpectedGeneration -and $active -eq 1 -and
            $tcpFlows -eq 0 -and $udpCandidates -eq 0 -and
            $udpAssociations -le $MaximumUdpAssociations -and
            $reassemblyEntries -eq 0 -and $handlerTasks -eq $udpAssociations) {
            return [pscustomobject]@{
                Metrics = $metrics
                Generation = $generation
                TcpFlows = $tcpFlows
                UdpAssociations = $udpAssociations
                UdpCandidates = $udpCandidates
                ReassemblyEntries = $reassemblyEntries
                HandlerTasks = $handlerTasks
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $metrics) {
        throw "M17 metrics remained unavailable during the bounded flow/fragment wait: expected_generation=$ExpectedGeneration"
    }
    throw "M17 flow/fragment baseline did not drain: expected_generation=$ExpectedGeneration generation=$generation active=$active tcp_flows=$tcpFlows udp_associations=$udpAssociations udp_candidates=$udpCandidates udp_limit=$MaximumUdpAssociations reassembly_entries=$reassemblyEntries handler_tasks=$handlerTasks"
}

function Wait-M17AdapterReady(
    [string]$Name,
    [bool]$Ipv4,
    [bool]$Ipv6,
    [string[]]$Ipv4Dns = @(),
    [string[]]$Ipv6Dns = @(),
    [uint32]$ExpectedMtu = 1420,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "M17 candidate failed during prepare" }
        }
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $v4 = @($addresses | Where-Object { $_.IPAddress -ceq "198.18.0.2" -and $_.PrefixLength -eq 30 -and $_.AddressState -eq "Preferred" })
            $v6 = @($addresses | Where-Object { $_.IPAddress -ceq "fd00::2" -and $_.PrefixLength -eq 126 -and $_.AddressState -eq "Preferred" })
            $addressesReady = (($Ipv4 -and $v4.Count -eq 1) -or (-not $Ipv4 -and $v4.Count -eq 0)) -and
                (($Ipv6 -and $v6.Count -eq 1) -or (-not $Ipv6 -and $v6.Count -eq 0))
            if ($addressesReady) {
                $v4Interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                $v6Interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                $mtuReady = ((-not $Ipv4) -or ($v4Interface -and [uint32]$v4Interface.NlMtu -eq $ExpectedMtu)) -and
                    ((-not $Ipv6) -or ($v6Interface -and [uint32]$v6Interface.NlMtu -eq $ExpectedMtu))
                $actualV4Dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                $actualV6Dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                $expectedV4Dns = @($Ipv4Dns | Sort-Object -Unique)
                $expectedV6Dns = @($Ipv6Dns | Sort-Object -Unique)
                $windowsIntrinsicV6Dns = @(
                    "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
                )
                $v4DnsReady = ($actualV4Dns -join "|") -ceq ($expectedV4Dns -join "|")
                $v6DnsReady = ($actualV6Dns -join "|") -ceq ($expectedV6Dns -join "|") -or
                    ($expectedV6Dns.Count -eq 0 -and
                        ($actualV6Dns -join "|") -ceq ($windowsIntrinsicV6Dns -join "|"))
                if ($mtuReady -and $v4DnsReady -and $v6DnsReady) {
                    return $adapter
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 adapter readiness timeout"
}

function Start-M17Candidate([string]$Configuration, [string]$Label) {
    Assert-True ($Label -cmatch '^[a-z0-9][a-z0-9-]{0,63}$') "M17 process label is invalid"
    $script:m17ProcessOrdinal++
    $stdoutPath = Join-Path $script:m17ArtifactRoot ("{0:D3}-client-{1}.stdout.log" -f $script:m17ProcessOrdinal, $Label)
    $stderrPath = Join-Path $script:m17ArtifactRoot ("{0:D3}-client-{1}.stderr.log" -f $script:m17ProcessOrdinal, $Label)
    $arguments = "--config `"$Configuration`""
    $id = [Ferrum2ProcessGroup]::Start($script:binary, $arguments, (Split-Path -Parent $script:binary), $stdoutPath, $stderrPath)
    $process = Get-Process -Id $id
    $script:activeProcess = $process
    $script:m17ProcessRows.Add([ordered]@{
        role = "client"
        label = $Label
        process_id = [uint32]$id
        binary_sha256 = (Get-FileHash -LiteralPath $script:binary -Algorithm SHA256).Hash.ToLowerInvariant()
        stdout = [IO.Path]::GetFileName($stdoutPath)
        stderr = [IO.Path]::GetFileName($stderrPath)
    })
    return $process
}

function Start-M17Server {
    $serverConfig = Join-Path $script:work "m17-server.toml"
    $script:m17ServerPort = Get-UniqueTcpPort
    @"
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:$script:m17ServerPort"
outbound = "direct"
[[outbounds]]
tag = "direct"
[runtime]
shutdown_grace_ms = 1000
[udp]
enabled = true
max_sessions = 64
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $serverConfig -Encoding utf8NoBOM
    $stdoutPath = Join-Path $script:m17ArtifactRoot "server.stdout.log"
    $stderrPath = Join-Path $script:m17ArtifactRoot "server.stderr.log"
    $id = [Ferrum2ProcessGroup]::Start($script:serverBinary, "--config `"$serverConfig`"", (Split-Path -Parent $script:serverBinary), $stdoutPath, $stderrPath)
    $process = Get-Process -Id $id
    $script:serverProcesses.Add($process)
    $script:m17ServerProcess = $process
    $script:m17ProcessRows.Add([ordered]@{
        role = "server"
        label = "qualification"
        process_id = [uint32]$id
        binary_sha256 = (Get-FileHash -LiteralPath $script:serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        stdout = [IO.Path]::GetFileName($stdoutPath)
        stderr = [IO.Path]::GetFileName($stderrPath)
    })
    Wait-TcpListener $script:m17ServerPort $process "m17-server"
    Wait-UdpListener $script:m17ServerPort $process "m17-server"
    Add-M17LiveRow "server-binary-ready" ([ordered]@{
        process_id = [uint32]$id
        tcp_listener = "127.0.0.1:$script:m17ServerPort"
        udp_listener = "127.0.0.1:$script:m17ServerPort"
        stable_udp_samples = 2
    })
}

function Write-M17ClientConfig(
    [string]$Path,
    [string]$TunFields,
    [ValidateSet("direct", "proxy")][string]$Outbound,
    [int]$MetricsPort,
    [string]$Additional = ""
) {
    $tunOutbound = if ([regex]::IsMatch($Additional, '(?m)^\[route\]\r?$')) {
        ""
    } else {
        "outbound = `"$Outbound`""
    }
    $outboundText = if ($Outbound -eq "direct") {
@"
[[outbounds]]
tag = "direct"
type = "direct"
"@
    } else {
@"
[[outbounds]]
tag = "proxy"
server = "127.0.0.1:$script:m17ServerPort"
"@
    }
    $shadowsocks = if ($Outbound -eq "proxy") {
@"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@
    } else { "" }
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$script:adapterName"
$TunFields
$tunOutbound
$outboundText
[udp]
enabled = true
max_sessions = 64
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
$Additional
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$MetricsPort"
$shadowsocks
"@ | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-M17Config([string]$Path, [string]$Label, [bool]$ExpectDeprecatedWarning = $false) {
    $result = Invoke-M17BoundedCommand "config-$Label" $script:binary @("--config", $Path, "--check-config") (Split-Path -Parent $script:binary) 30
    Assert-True ($result.ExitCode -eq 0 -and $result.Stdout.TrimEnd([char[]]"`r`n") -ceq "configuration valid") "M17 live config validation failed: $Label"
    if ($ExpectDeprecatedWarning) {
        Assert-True ([regex]::Matches($result.Stderr, [regex]::Escape($script:m17ExpectedWarning)).Count -eq $script:m17ExpectedWarningCount -and
            $result.Stderr.TrimEnd([char[]]"`r`n") -ceq $script:m17ExpectedWarning) "M17 live config warning changed: $Label"
    } else {
        Assert-True ([string]::IsNullOrEmpty($result.Stderr)) "M17 live config emitted stderr: $Label"
    }
}

function Stop-M17Candidate([System.Diagnostics.Process]$Process, [string]$Label) {
    Stop-Candidate $Process
    $script:activeProcess = $null
    Wait-AdapterAbsent $script:adapterName
    Assert-InterfaceGone $script:adapterName $script:ownedInterfaceIndex
    Add-M17LiveRow "client-$Label-graceful-stop" ([ordered]@{ exit_code = 0; adapter = "absent" })
}

function Start-M17NetworkResetRouteMutation {
    Assert-True ($script:Mode -ceq "network-reset") "M17 network-reset route mutation is mode restricted"
    $underlay = Get-Ipv4DefaultUnderlay
    $prefix = $script:m17NetworkResetProbePrefix
    Assert-True (@(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 network-reset notification route baseline is not absent"
    $intentPath = Get-M17NetworkResetRouteIntentPath
    Write-M17DurableMutationIntent $intentPath ([ordered]@{
        schema = "ferrum2.windows-tun.m17-network-reset-route-intent.v1"
        run_token = $script:runIdentity
        source_mode = "network-reset"
        work_path = [IO.Path]::GetFullPath($script:work)
        interface_index = [uint32]$underlay.InterfaceIndex
        destination_prefix = $prefix
        next_hop = [string]$underlay.Row.Route.NextHop
        route_metrics = @([uint32]4094, [uint32]4095)
    })
    [void](New-NetRoute -InterfaceIndex $underlay.InterfaceIndex -DestinationPrefix $prefix `
        -NextHop $underlay.Row.Route.NextHop -RouteMetric 4094 -PolicyStore ActiveStore -ErrorAction Stop)
    $readback = @(Get-NetRoute -InterfaceIndex $underlay.InterfaceIndex -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
            $_.NextHop -ceq [string]$underlay.Row.Route.NextHop -and [uint32]$_.RouteMetric -eq 4094
        })
    Assert-True ($readback.Count -eq 1) "M17 network-reset notification route create readback failed"
    return [pscustomobject]@{
        IntentPath = $intentPath
        InterfaceIndex = [uint32]$underlay.InterfaceIndex
        DestinationPrefix = $prefix
        NextHop = [string]$underlay.Row.Route.NextHop
        RouteMetric = [uint32]4094
    }
}

function Set-M17NetworkResetRouteMetric([object]$Mutation, [uint32]$Metric) {
    Assert-True ($script:Mode -ceq "network-reset" -and $Metric -in @(4094, 4095)) "M17 network-reset route metric is outside the closed mutation set"
    $intent = Read-M17NetworkResetRouteMutationIntent ([string]$Mutation.IntentPath)
    Assert-True ([uint32]$intent.interface_index -eq [uint32]$Mutation.InterfaceIndex -and
        [string]$intent.destination_prefix -ceq [string]$Mutation.DestinationPrefix -and
        [string]$intent.next_hop -ceq [string]$Mutation.NextHop -and
        @($intent.route_metrics) -contains [long]$Metric) "M17 network-reset route no longer matches its durable intent"
    $routes = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop })
    Assert-True ($routes.Count -eq 1 -and [uint32]$routes[0].RouteMetric -in @($intent.route_metrics) -and
        [uint32]$routes[0].RouteMetric -ne $Metric) "M17 network-reset route mutation ownership changed"
    Set-NetRoute -InputObject $routes[0] -RouteMetric $Metric -ErrorAction Stop | Out-Null
    $readback = @(Get-NetRoute -InterfaceIndex ([int]$Mutation.InterfaceIndex) `
        -DestinationPrefix ([string]$Mutation.DestinationPrefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$Mutation.NextHop -and [uint32]$_.RouteMetric -eq $Metric })
    Assert-True ($readback.Count -eq 1) "M17 network-reset route metric readback failed"
    $Mutation.RouteMetric = $Metric
}

function Get-M17ExactManagedRoute([int]$InterfaceIndex, [string]$Prefix) {
    $routes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    Assert-True ($routes.Count -eq 1) "M17 managed restart route readback is not exact: $Prefix"
    return $routes[0]
}

function Remove-M17ManagedRouteForRestart([int]$InterfaceIndex, [string]$Prefix) {
    $route = Get-M17ExactManagedRoute $InterfaceIndex $Prefix
    Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $Prefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 managed restart route mutation failed: $Prefix"
}

function Invoke-M17DnsQuery([string]$Source, [string]$Destination, [bool]$Tcp, [uint16]$Id) {
    $query = New-DnsQuery $Id
    $family = if ($Destination.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    if ($Tcp) {
        $client = [Net.Sockets.TcpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            $connected = $client.ConnectAsync($Destination, 53)
            Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "M17 synthetic DNS TCP connect failed"
            $stream = $client.GetStream()
            $frame = [byte[]]::new($query.Length + 2)
            $frame[0] = [byte]($query.Length -shr 8)
            $frame[1] = [byte]($query.Length -band 0xff)
            [Array]::Copy($query, 0, $frame, 2, $query.Length)
            $stream.Write($frame, 0, $frame.Length)
            $lengthBytes = Read-ExactBytes $stream 2
            $length = ([int]$lengthBytes[0] -shl 8) -bor [int]$lengthBytes[1]
            $response = Read-ExactBytes $stream $length
        } finally { $client.Dispose() }
    } else {
        $client = [Net.Sockets.UdpClient]::new($family)
        try {
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
            [void]$client.Send($query, $query.Length, $Destination, 53)
            $task = $client.ReceiveAsync()
            Assert-True ($task.Wait(5000) -and -not $task.IsFaulted) "M17 synthetic DNS UDP response timeout"
            $response = $task.Result.Buffer
        } finally { $client.Dispose() }
    }
    Assert-True ($response.Length -ge 12 -and $response[0] -eq $query[0] -and $response[1] -eq $query[1] -and
        ($response[2] -band 0x80) -ne 0) "M17 synthetic DNS response is invalid"
}

function Invoke-M17CandidateTests {
    Assert-True $script:candidateTestDirectoryExplicit "M17 candidate tests require host-built artifacts"
    $testHashes = [ordered]@{}
    foreach ($name in @("client", "tun", "wintun")) {
        $file = switch ($name) {
            "client" { "ferrum2-client-tests.exe" }
            "tun" { "ferrum2-tun-tests.exe" }
            "wintun" { "ferrum2-wintun-tests.exe" }
        }
        $testHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $script:resolvedCandidateTestDirectory $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Add-M17LiveRow "candidate-test-source" ([ordered]@{
        git_head = [string]$script:capabilityIdentity.Ledger.candidate_sha
        provenance = "host-built-rust-1.97.1-prebuilt-tests"
        test_binaries = $testHashes
    })

    $specs = switch ($script:Mode) {
        "network-reset" { @(
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::dual_stack_target_binding_selects_actual_target_and_rejects_tun"; Witnesses = @("fixed_and_direct_dual_stack_underlay_binding") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::target_binding_excludes_tun_and_orders_prefix_then_effective_metric"; Witnesses = @("multihoming_prefix_and_metric_selection") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::network_change_notifications_cover_each_callback_and_runtime_owned_events"; Witnesses = @("route_interface_and_address_notifications") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::managed_route_cleanup_preserves_replacements_and_audits_every_delete"; Witnesses = @("foreign_route_state_survives_cleanup") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::managed_address_readback_and_cleanup_are_exact_and_foreign_safe"; Witnesses = @("foreign_address_state_survives_cleanup") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit"; Witnesses = @("dad_failure_rolls_back_in_reverse") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::managed_state_health_reports_owned_route_dns_and_strict_route_damage"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::strict_route_health_reads_every_exact_filter_id_and_rejects_damage"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::network_change_revalidates_underlay_and_owned_routes_before_shutdown"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::windows_catalog_is_family_aware_and_marks_the_exact_managed_tun"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::resolved_socket_binding_applies_interface_then_family_source"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::only_managed_damage_escalates_a_network_change_to_full_rebuild"; Witnesses = @("owned_state_damage_is_the_only_full_rebuild_trigger") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::reset_retries_transient_readback_errors_without_tearing_down_managed_state"; Witnesses = @("reset_retries_without_managed_teardown") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::network_lifecycle_bridge_reports_retry_before_completion"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state"; Witnesses = @() },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::client_network_hook_retries_failure_and_accepts_each_generation_once"; Witnesses = @("network_reset_hooks_accept_each_generation_once") }
        ) }
        "restart-stress" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state"; Witnesses = @("admission_quiesces_during_rebuild", "stale_flows_and_fragments_are_cleared") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c17_stale_generation_handles_cannot_commit_close_or_inject"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "supervisor::tests::notification_burst_keeps_only_latest_generation_and_extends_debounce"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::owner_cancel_eof_panic_and_cleanup_conflict_are_reaped_before_join"; Witnesses = @() }
        ) }
        "fragments" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::reassembles_ipv4_and_ipv6_strictly_out_of_order_then_reparses"; Witnesses = @("ipv4_udp_out_of_order") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::reassembles_three_fragment_tcp_and_preserves_initial_syn_semantics"; Witnesses = @("ipv4_tcp_out_of_order") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::ipv6_extensions_before_and_after_fragment_reassemble_canonically"; Witnesses = @("ipv6_extension_and_fragment") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::strips_atomic_ipv6_fragment_before_reparse"; Witnesses = @("ipv6_atomic_fragment") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::overlap_or_duplicate_drops_the_entire_entry"; Witnesses = @("overlap_drops_entry") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::timeout_and_generation_change_prevent_cross_epoch_completion"; Witnesses = @("timeout_drops_entry", "network_reset_rejects_stale_generation") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::fragmented_dns_reaches_post_reassembly_udp_dispatch_metadata"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::fragmented_udp_reaches_admission_only_after_out_of_order_reassembly"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "reassembly::tests::disabled_family_fragments_are_rejected_before_allocating_reassembly_state"; Witnesses = @("disabled_family_rejects_fragment") }
        ) }
        "dual-stack-dns" { @(
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::synthetic_dns_matches_each_configured_family_exactly"; Witnesses = @("exact_port_53_match", "ordinary_port_53_not_intercepted") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::managed_dns_snapshots_reads_back_and_conditionally_restores"; Witnesses = @() }
        ) }
        "udp-policy" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::configured_ipv4_directed_broadcast_never_reaches_tcp_or_udp_admission"; Witnesses = @("directed_broadcast_never_allocates_association") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c19_eim_adf_eif_and_actual_response_source_are_enforced"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::adf_peer_reservations_are_bounded_and_authorize_only_on_commit"; Witnesses = @("rejected_target_never_authorizes_peer") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c8_lifecycle_control_is_reliable_when_data_queues_are_congested"; Witnesses = @("udp_queue_pressure_is_bounded_and_control_remains_live") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c10_hash_index_free_list_counts_and_generation_deadlines_are_exact"; Witnesses = @() },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c17_stale_generation_handles_cannot_commit_close_or_inject"; Witnesses = @("reset_clears_udp_stale_generation_state") },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::synthetic_dns_precedes_one_frozen_ordinary_udp_route"; Witnesses = @("first_ordinary_datagram_freezes_route_and_outbound") },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::tun_udp_authorizes_only_successful_send_or_dns_answer_and_adf_ignores_port"; Witnesses = @() },
            @{ Package = "ferrum2-client"; Target = "bin"; Test = "run::tun::tests::tun_udp_route_snapshot_is_bounded_and_immutable_after_selection"; Witnesses = @("one_eim_association_reuses_first_outbound_for_all_targets") }
        ) }
        "scheduler-ring-full" { @(
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::capacity_aware_rotation_drains_eight_sixteen_and_sixty_four_packets"; Witnesses = @("rx_bursts_8_16_64_have_no_structural_drop") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "scheduler::tests::rotation_is_stable_across_arbitrary_work_budget_boundaries"; Witnesses = @("work_stages_rotate_fairly") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "udp::tests::c2_response_backpressure_preserves_current_event_and_does_not_consume_next"; Witnesses = @("udp_response_backpressure_is_lossless") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::ring_full_drops_exactly_one_complete_output_and_fatal_retains_it"; Witnesses = @("ring_full_drops_one_complete_packet", "ring_full_is_not_retried", "ring_full_does_not_reset_or_rebuild_network") },
            @{ Package = "ferrum2-tun"; Target = "lib"; Test = "tests::wintun_error_kinds_have_exact_owner_dispositions"; Witnesses = @("wintun_error_kinds_have_exact_owner_dispositions") },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "tests::operation_error_kinds_are_closed_and_redacted"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::receive_null_distinguishes_empty_recoverable_eof_and_corruption"; Witnesses = @() },
            @{ Package = "ferrum2-wintun"; Target = "lib"; Test = "windows::tests::send_allocation_failure_distinguishes_ring_full_from_fatal_errors"; Witnesses = @() }
        ) }
    }
    $ordinal = 0
    foreach ($spec in $specs) {
        $ordinal++
        $testFile = switch ($spec.Package) {
            "ferrum2-client" { "ferrum2-client-tests.exe" }
            "ferrum2-tun" { "ferrum2-tun-tests.exe" }
            "ferrum2-wintun" { "ferrum2-wintun-tests.exe" }
            default { throw "M17 prebuilt test package is not closed" }
        }
        $testRunner = Join-Path $script:resolvedCandidateTestDirectory $testFile
        $arguments = @($spec.Test, "--exact", "--nocapture")
        $runnerKind = "prebuilt-rust-1.97.1"
        $result = Invoke-M17BoundedCommand ("test-{0:D2}-{1}" -f $ordinal, $spec.Package) $testRunner $arguments $script:resolvedProductRoot 300
        $testOutput = $result.Stdout + $result.Stderr
        $ranExactlyOne = $testOutput -match '(?m)^running 1 test\r?$' -and
            $testOutput -match '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+\r?$'
        Assert-True ($result.ExitCode -eq 0 -and $ranExactlyOne) "M17 exact candidate test failed or did not execute exactly once: $($spec.Test)"
        $script:m17TestRows.Add([ordered]@{
            package = $spec.Package
            test = $spec.Test
            status = "pass"
            runner = $runnerKind
            duration_ms = $result.DurationMilliseconds
            stdout_sha256 = (Get-FileHash -LiteralPath $result.StdoutPath -Algorithm SHA256).Hash.ToLowerInvariant()
            stderr_sha256 = (Get-FileHash -LiteralPath $result.StderrPath -Algorithm SHA256).Hash.ToLowerInvariant()
        })
        foreach ($witness in $spec.Witnesses) {
            Add-M17Witness $witness "deterministic-candidate-test" "$($spec.Package):$($spec.Test)"
        }
    }
}

function Get-M17TextSha256([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Value))
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $algorithm.Dispose() }
}

function Get-M17ManagedPlaneIdentity([string]$Name) {
    $adapters = @(Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction Stop)
    Assert-True ($adapters.Count -eq 1) "M17 managed adapter identity is not exact"
    $adapter = $adapters[0]
    $interfaceIndex = [uint32]$adapter.ifIndex
    $interfaceLuid = [uint64]$adapter.NetLuid
    $interfaceGuid = ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
    Assert-True ($interfaceIndex -ne 0 -and $interfaceLuid -ne 0 -and
        [string]$adapter.Status -ceq "Up") "M17 managed adapter is not active"
    $addresses = @(
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily, IPAddress, PrefixLength |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.AddressState)|$($_.PrefixOrigin)|$($_.SuffixOrigin)|$([bool]$_.SkipAsSource)"
            }
    )
    $routes = @(
        Get-NetRoute -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily, DestinationPrefix, NextHop, RouteMetric, Protocol |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)|$([uint32]$_.RouteMetric)|$($_.Protocol)|$([bool]$_.Publish)"
            }
    )
    $dns = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ErrorAction Stop |
            Sort-Object AddressFamily |
            ForEach-Object { "$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" }
    )
    $interfaces = @(
        Get-NetIPInterface -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily |
            ForEach-Object {
                "$($_.AddressFamily)|$([uint32]$_.NlMtu)|$($_.ConnectionState)|$($_.Dhcp)|$($_.AutomaticMetric)|$([uint32]$_.InterfaceMetric)"
            }
    )
    $document = [ordered]@{
        adapter_name = [string]$adapter.Name
        interface_guid = $interfaceGuid
        interface_luid = $interfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
        interface_index = $interfaceIndex
        interface_description = [string]$adapter.InterfaceDescription
        addresses = $addresses
        routes = $routes
        dns = $dns
        interfaces = $interfaces
    }
    $canonical = $document | ConvertTo-Json -Compress -Depth 6
    return [pscustomobject]@{
        Document = $document
        Canonical = $canonical
        Sha256 = Get-M17TextSha256 $canonical
        InterfaceGuid = $interfaceGuid
        InterfaceLuid = $interfaceLuid
        InterfaceIndex = $interfaceIndex
    }
}

function Get-M17StrictRouteWfpIdentity(
    [string]$Label,
    [uint64]$InterfaceLuid,
    [uint32]$ProcessId
) {
    Assert-True ($Label -cmatch '^[a-z0-9][a-z0-9-]{0,63}$' -and
        $InterfaceLuid -ne 0 -and $ProcessId -ne 0) "M17 strict-route WFP snapshot identity is invalid"
    $path = Join-Path $script:work "m17-wfp-$Label.xml"
    Assert-True (-not (Test-Path -LiteralPath $path)) "M17 strict-route WFP snapshot baseline is not absent"
    $netsh = Join-Path ([Environment]::SystemDirectory) "netsh.exe"
    try {
        $result = Invoke-M17BoundedCommand "wfp-$Label" $netsh @("wfp", "show", "state", "file=$path") $script:work 60
        Assert-True ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $path -PathType Leaf)) "M17 strict-route WFP state capture failed"
        Assert-NotReparsePoint $path "M17 strict-route WFP snapshot"
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-True ($item.Length -gt 0 -and $item.Length -le 67108864) "M17 strict-route WFP snapshot exceeded its 64 MiB boundary"
        [xml]$document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $sublayer = "{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}"
        $expected = @(
            [pscustomobject]@{ Name = "Ferrum2 app permit IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701001}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT"; Condition = "app"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 app permit IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701002}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT"; Condition = "app"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 TUN permit IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701003}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT"; Condition = "tun"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 TUN permit IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701004}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT"; Condition = "tun"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 DNS TCP block IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701007}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 6 },
            [pscustomobject]@{ Name = "Ferrum2 DNS UDP block IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701008}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 17 },
            [pscustomobject]@{ Name = "Ferrum2 DNS TCP block IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701009}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 6 },
            [pscustomobject]@{ Name = "Ferrum2 DNS UDP block IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e870100a}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 17 }
        )
        $filters = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
            $subLayerNode = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
            $filterIdNode = $_.SelectSingleNode("./*[local-name()='filterId']")
            $null -ne $subLayerNode -and $null -ne $filterIdNode -and
                $subLayerNode.InnerText.ToLowerInvariant() -ceq $sublayer
        })
        Assert-True ($filters.Count -eq $expected.Count) "M17 strict-route WFP filter count is not exact"
        $rows = [System.Collections.Generic.List[string]]::new()
        foreach ($spec in $expected) {
            $matches = @($filters | Where-Object {
                $nameNode = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
                $null -ne $nameNode -and $nameNode.InnerText -ceq $spec.Name
            })
            Assert-True ($matches.Count -eq 1) "M17 strict-route WFP named filter is not exact: $($spec.Name)"
            $filter = $matches[0]
            $keyNode = $filter.SelectSingleNode("./*[local-name()='filterKey']")
            $layerNode = $filter.SelectSingleNode("./*[local-name()='layerKey']")
            $actionNode = $filter.SelectSingleNode("./*[local-name()='action']/*[local-name()='type']")
            $filterIdNode = $filter.SelectSingleNode("./*[local-name()='filterId']")
            [uint64]$filterId = 0
            Assert-True ($null -ne $keyNode -and $keyNode.InnerText.ToLowerInvariant() -ceq $spec.Key -and
                $null -ne $layerNode -and $layerNode.InnerText -ceq $spec.Layer -and
                $null -ne $actionNode -and $actionNode.InnerText -ceq $spec.Action -and
                $null -ne $filterIdNode -and [uint64]::TryParse($filterIdNode.InnerText, [ref]$filterId) -and
                $filterId -ne 0) "M17 strict-route WFP filter identity changed: $($spec.Name)"
            $fieldKeys = @($filter.SelectNodes(".//*[local-name()='fieldKey']") | ForEach-Object { $_.InnerText } | Sort-Object)
            if ($spec.Condition -ceq "app") {
                Assert-True (($fieldKeys -join "|") -ceq "FWPM_CONDITION_ALE_APP_ID") "M17 strict-route app permit condition changed"
            } elseif ($spec.Condition -ceq "tun") {
                $luidValues = @($filter.SelectNodes(".//*[local-name()='uint64']") | ForEach-Object { $_.InnerText })
                Assert-True (($fieldKeys -join "|") -ceq "FWPM_CONDITION_IP_LOCAL_INTERFACE" -and
                    $luidValues -contains $InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)) "M17 strict-route TUN LUID condition changed"
            } else {
                $protocolValues = @($filter.SelectNodes(".//*[local-name()='uint8']") | ForEach-Object { $_.InnerText })
                $portValues = @($filter.SelectNodes(".//*[local-name()='uint16']") | ForEach-Object { $_.InnerText })
                Assert-True (($fieldKeys -join "|") -ceq "FWPM_CONDITION_IP_PROTOCOL|FWPM_CONDITION_IP_REMOTE_PORT" -and
                    $protocolValues -contains ([string]$spec.Protocol) -and $portValues -contains "53") "M17 strict-route DNS condition changed"
            }
            $rows.Add("$($spec.Name)|$($spec.Key)|$filterId|$($spec.Layer)|$($spec.Action)|$sublayer")
        }
        $sessionKey = "{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}"
        $sessionName = "Ferrum2 strict route dynamic session"
        $sessions = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
            $keyNode = $_.SelectSingleNode("./*[local-name()='sessionKey']")
            $nameNode = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
            $null -ne $keyNode -and $keyNode.InnerText.ToLowerInvariant() -ceq $sessionKey -and
                $null -ne $nameNode -and $nameNode.InnerText -ceq $sessionName
        })
        Assert-True ($sessions.Count -eq 1) "M17 strict-route dynamic WFP session identity is not exact"
        $processNode = $sessions[0].SelectSingleNode("./*[local-name()='processId']")
        [uint32]$sessionProcessId = 0
        Assert-True ($null -ne $processNode -and
            [uint32]::TryParse($processNode.InnerText, [ref]$sessionProcessId) -and
            $sessionProcessId -eq $ProcessId) "M17 strict-route dynamic WFP session process identity changed"
        $sessionCanonical = "session|$sessionKey|$sessionName|$sessionProcessId"
        $canonical = (@($sessionCanonical) + @($rows | Sort-Object)) -join "`n"
        return [pscustomobject]@{
            Canonical = $canonical
            Sha256 = Get-M17TextSha256 $canonical
            FilterIds = @($rows | Sort-Object | ForEach-Object { ($_ -split '\|')[2] })
            FilterCount = $rows.Count
            ProcessId = $sessionProcessId
            SessionKey = "8ea35b4e-6629-4e26-9776-95c5bf9c6b01"
            SublayerKey = "ddbc2fa2-d52f-4a79-8a63-8446c308cf02"
        }
    } finally {
        if (Test-Path -LiteralPath $path) {
            Assert-NotReparsePoint $path "M17 strict-route WFP snapshot cleanup"
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}

function Get-M17MetricLabelSetValue(
    [string]$Metrics,
    [string]$Name,
    [System.Collections.IDictionary]$Labels,
    [bool]$AllowAbsent = $false
) {
    $lookaheads = @($Labels.GetEnumerator() | ForEach-Object {
        "(?=[^}`r`n]*$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|}))"
    }) -join ""
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{$lookaheads[^}`r`n]*\} ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return 0.0 }
    Assert-True ($matches.Count -eq 1) "missing or ambiguous M17 metric label set: $Name"
    return [double]::Parse($matches[0].Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-M17NetworkResetMetricState([string]$Metrics) {
    $reset = {
        param([string]$Reason, [string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_reset" ([ordered]@{
            reason = $Reason
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        ResetStarted = & $reset "network_change" "started"
        ResetSucceeded = & $reset "network_change" "succeeded"
        ResetFailed = & $reset "network_change" "failed"
        RetryStarted = & $reset "retry" "started"
        RetrySucceeded = & $reset "retry" "succeeded"
        RetryFailed = & $reset "retry" "failed"
        FullRebuild = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
        SessionActive = Get-M17MetricValue $Metrics "ferrum2_tun_session_active"
        StrictRequested = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_requested"
        StrictEffective = Get-M17MetricValue $Metrics "ferrum2_tun_strict_route_effective"
        StrictInstallSucceeded = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "success" $true
        StrictInstallFailed = Get-M17LabeledMetricValue $Metrics "ferrum2_tun_strict_route_filter_install" "result" "failure" $true
    }
}

function Get-M17ManagedRouteRebuildMetricState([string]$Metrics) {
    $rebuild = {
        param([string]$Result)
        Get-M17MetricLabelSetValue $Metrics "ferrum2_network_full_rebuild" ([ordered]@{
            reason = "route_damage"
            result = $Result
        }) $true
    }
    return [pscustomobject]@{
        RouteDamageStarted = & $rebuild "started"
        RouteDamageSucceeded = & $rebuild "succeeded"
        RouteDamageFailed = & $rebuild "failed"
        FullRebuildTotal = Get-M17MetricValue $Metrics "ferrum2_network_full_rebuild" $true
        NetworkResetTotal = Get-M17MetricValue $Metrics "ferrum2_network_reset" $true
        NetworkGeneration = Get-M17MetricValue $Metrics "ferrum2_network_generation"
        SessionGeneration = Get-M17MetricValue $Metrics "ferrum2_tun_session_generation"
    }
}

function Wait-M17NetworkResetCycle(
    [int]$MetricsPort,
    [object]$Baseline,
    [int]$Cycle,
    [double]$ExpectedSessionGeneration,
    [int]$TimeoutSeconds = 60
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $state = $null
    do {
        $metrics = Get-Metrics $MetricsPort 2
        $state = Get-M17NetworkResetMetricState $metrics
        if ($state.ResetStarted -eq $Baseline.ResetStarted + $Cycle -and
            $state.ResetSucceeded -eq $Baseline.ResetSucceeded + $Cycle -and
            $state.ResetFailed -eq $Baseline.ResetFailed -and
            $state.RetryStarted -eq $Baseline.RetryStarted -and
            $state.RetrySucceeded -eq $Baseline.RetrySucceeded -and
            $state.RetryFailed -eq $Baseline.RetryFailed -and
            $state.FullRebuild -eq $Baseline.FullRebuild -and
            $state.NetworkGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionGeneration -eq $ExpectedSessionGeneration -and
            $state.SessionActive -eq 1 -and
            $state.StrictRequested -eq 1 -and $state.StrictEffective -eq 1 -and
            $state.StrictInstallSucceeded -eq $Baseline.StrictInstallSucceeded -and
            $state.StrictInstallFailed -eq $Baseline.StrictInstallFailed) {
            # Hold beyond the runtime's 350 ms notification debounce before accepting one cycle.
            Start-Sleep -Milliseconds 500
            $stableMetrics = Get-Metrics $MetricsPort 2
            $stable = Get-M17NetworkResetMetricState $stableMetrics
            Assert-True ($stable.ResetStarted -eq $state.ResetStarted -and
                $stable.ResetSucceeded -eq $state.ResetSucceeded -and
                $stable.ResetFailed -eq $state.ResetFailed -and
                $stable.RetryStarted -eq $state.RetryStarted -and
                $stable.RetrySucceeded -eq $state.RetrySucceeded -and
                $stable.RetryFailed -eq $state.RetryFailed -and
                $stable.NetworkGeneration -eq $state.NetworkGeneration -and
                $stable.SessionGeneration -eq $state.SessionGeneration -and
                $stable.FullRebuild -eq $state.FullRebuild -and
                $stable.StrictRequested -eq $state.StrictRequested -and
                $stable.StrictEffective -eq $state.StrictEffective -and
                $stable.StrictInstallSucceeded -eq $state.StrictInstallSucceeded -and
                $stable.StrictInstallFailed -eq $state.StrictInstallFailed) "M17 network-reset cycle did not stabilize"
            return [pscustomobject]@{ Metrics = $stableMetrics; State = $stable }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 network-reset cycle timeout: cycle=$Cycle expected_generation=$ExpectedSessionGeneration state=$($state | ConvertTo-Json -Compress)"
}

function Invoke-M17NetworkReset {
    $udpAssociationLimit = 32
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-network-reset.toml"
    $physical = Get-Ipv4DefaultUnderlay
    $resolverAddress = [string]$physical.Sources[0].IPAddress
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $supportAddress = $script:capabilityIdentity.SupportAddress
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$supportAddress/32"]
strict_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = $udpAssociationLimit
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $script:m17MetricsPort @"
[[outbounds]]
tag = "network-probe"
server = "$($script:m17NetworkResetProbeAddress):8388"
[[selectors]]
tag = "network-egress"
outbounds = ["direct", "network-probe"]
default = "direct"
[route]
final = "network-egress"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$(Get-UniqueTcpPort)"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${resolverAddress}:$resolverPort"
detour = "direct"
[dns.route]
final = "resolver"
"@
    Assert-M17Config $path "network-reset"
    $script:activeProcess = Start-M17Candidate $path "network-reset"
    $candidatePid = [uint32]$script:activeProcess.Id
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $managedBaseline = Get-M17ManagedPlaneIdentity $script:adapterName
    $wfpBaseline = Get-M17StrictRouteWfpIdentity "network-reset-0000" $managedBaseline.InterfaceLuid $candidatePid
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-network-reset-before"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-network-reset-before"))
    Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false 0x1710
    $initialDrain = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    $baseline = Get-M17NetworkResetMetricState $initialDrain.Metrics
    Assert-True ($baseline.StrictRequested -eq 1 -and $baseline.StrictEffective -eq 1 -and
        $baseline.StrictInstallSucceeded -ge 1 -and $baseline.StrictInstallFailed -eq 0 -and
        $baseline.SessionGeneration -eq $initial.Generation -and
        $baseline.ResetStarted -eq $baseline.ResetSucceeded -and $baseline.ResetFailed -eq 0 -and
        $baseline.RetryStarted -eq 0 -and $baseline.RetrySucceeded -eq 0 -and $baseline.RetryFailed -eq 0 -and
        $baseline.FullRebuild -eq 0) "M17 network-reset strict-route or lifecycle metric baseline is invalid"
    $script:m17CounterBefore = Get-M17CounterSnapshot $initialDrain.Metrics
    Add-M17LiveRow "network-reset-baseline" ([ordered]@{
        process_id = $candidatePid
        interface_guid = $managedBaseline.InterfaceGuid
        interface_luid = $managedBaseline.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
        interface_index = $managedBaseline.InterfaceIndex
        managed_plane_sha256 = $managedBaseline.Sha256
        managed_plane = $managedBaseline.Document
        strict_route_wfp_sha256 = $wfpBaseline.Sha256
        strict_route_filters = $wfpBaseline.FilterCount
        strict_route_filter_ids = @($wfpBaseline.FilterIds)
        strict_route_session_key = $wfpBaseline.SessionKey
        strict_route_sublayer_key = $wfpBaseline.SublayerKey
        session_generation = $baseline.SessionGeneration
        network_generation = $baseline.NetworkGeneration
    })

    $evidencePath = Join-Path $script:m17ArtifactRoot "network-reset-cycles.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $evidencePath)) "M17 network-reset cycle evidence baseline is not absent"
    $stream = [IO.FileStream]::new($evidencePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true
    $evidenceBytes = 0
    $wfpSamples = 1
    $sampleStride = [Math]::Max(1, [int][Math]::Ceiling($script:NetworkResetCycles / 10.0))
    $mutation = $null
    $final = $null
    try {
        foreach ($cycle in 1..$script:NetworkResetCycles) {
            if ($cycle -eq 1) {
                $mutation = Start-M17NetworkResetRouteMutation
                $mutationKind = "create"
            } else {
                $metric = if (($cycle % 2) -eq 0) { [uint32]4095 } else { [uint32]4094 }
                Set-M17NetworkResetRouteMetric $mutation $metric
                $mutationKind = "metric_toggle"
            }
            $expectedGeneration = $initial.Generation + $cycle
            $final = Wait-M17NetworkResetCycle $script:m17MetricsPort $baseline $cycle $expectedGeneration
            $script:activeProcess.Refresh()
            Assert-True (-not $script:activeProcess.HasExited -and [uint32]$script:activeProcess.Id -eq $candidatePid) "M17 ordinary network reset replaced the client process"
            $managed = Get-M17ManagedPlaneIdentity $script:adapterName
            Assert-True ($managed.Canonical -ceq $managedBaseline.Canonical) "M17 ordinary network reset changed managed adapter/address/route/DNS state"
            $sampleWfp = $cycle -eq 1 -or $cycle -eq $script:NetworkResetCycles -or ($cycle % $sampleStride) -eq 0
            if ($sampleWfp) {
                $wfp = Get-M17StrictRouteWfpIdentity ("network-reset-{0:D4}" -f $cycle) $managed.InterfaceLuid $candidatePid
                Assert-True ($wfp.Canonical -ceq $wfpBaseline.Canonical) "M17 ordinary network reset replaced the strict-route WFP session or filters"
                $wfpSamples++
            }
            $payload = [Text.Encoding]::ASCII.GetBytes(("m17-network-reset-{0:D4}" -f $cycle))
            Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex $payload
            Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex $payload
            if ($sampleWfp) { Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false ([uint16](0x1800 + ($cycle % 2048))) }
            $drained = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
            $state = Get-M17NetworkResetMetricState $drained.Metrics
            Assert-True ($state.ResetStarted -eq $final.State.ResetStarted -and
                $state.ResetSucceeded -eq $final.State.ResetSucceeded -and
                $state.ResetFailed -eq $baseline.ResetFailed -and
                $state.RetryStarted -eq $baseline.RetryStarted -and
                $state.RetrySucceeded -eq $baseline.RetrySucceeded -and
                $state.RetryFailed -eq $baseline.RetryFailed -and
                $state.SessionGeneration -eq $expectedGeneration -and
                $state.NetworkGeneration -eq $expectedGeneration -and
                $state.FullRebuild -eq $baseline.FullRebuild -and
                $state.StrictRequested -eq 1 -and $state.StrictEffective -eq 1 -and
                $state.StrictInstallSucceeded -eq $baseline.StrictInstallSucceeded -and
                $state.StrictInstallFailed -eq $baseline.StrictInstallFailed) "M17 post-reset health changed lifecycle state"
            $row = [ordered]@{
                cycle = $cycle
                mutation = $mutationKind
                route_metric = [uint32]$mutation.RouteMetric
                process_id = $candidatePid
                interface_guid = $managed.InterfaceGuid
                interface_luid = $managed.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
                interface_index = $managed.InterfaceIndex
                managed_plane_sha256 = $managed.Sha256
                strict_route_wfp_sha256 = $wfpBaseline.Sha256
                wfp_sampled = $sampleWfp
                session_generation = $state.SessionGeneration
                network_generation = $state.NetworkGeneration
                reset_started = $state.ResetStarted
                reset_succeeded = $state.ResetSucceeded
                reset_failed = $state.ResetFailed
                full_rebuild = $state.FullRebuild
                strict_route_effective = $state.StrictEffective
            }
            $line = $row | ConvertTo-Json -Compress -Depth 4
            $lineBytes = [Text.UTF8Encoding]::new($false).GetByteCount($line) + 1
            $evidenceBytes += $lineBytes
            Assert-True ($evidenceBytes -le 1048576) "M17 network-reset cycle evidence exceeded its 1 MiB boundary"
            $writer.WriteLine($line)
        }
    } finally { $writer.Dispose() }

    $finalMetrics = Get-Metrics $script:m17MetricsPort 2
    $finalState = Get-M17NetworkResetMetricState $finalMetrics
    Assert-True ($finalState.ResetStarted -eq $baseline.ResetStarted + $script:NetworkResetCycles -and
        $finalState.ResetSucceeded -eq $baseline.ResetSucceeded + $script:NetworkResetCycles -and
        $finalState.ResetFailed -eq $baseline.ResetFailed -and
        $finalState.RetryStarted -eq $baseline.RetryStarted -and
        $finalState.RetrySucceeded -eq $baseline.RetrySucceeded -and
        $finalState.RetryFailed -eq $baseline.RetryFailed -and
        $finalState.SessionGeneration -eq $initial.Generation + $script:NetworkResetCycles -and
        $finalState.NetworkGeneration -eq $finalState.SessionGeneration -and
        $finalState.NetworkGeneration -gt $baseline.NetworkGeneration -and
        $finalState.FullRebuild -eq $baseline.FullRebuild -and
        $finalState.StrictRequested -eq 1 -and $finalState.StrictEffective -eq 1 -and
        $finalState.StrictInstallSucceeded -eq $baseline.StrictInstallSucceeded -and
        $finalState.StrictInstallFailed -eq $baseline.StrictInstallFailed) "M17 network-reset final lifecycle contract changed"
    $evidenceItem = Get-Item -LiteralPath $evidencePath -Force -ErrorAction Stop
    $evidence = [IO.File]::ReadAllBytes($evidencePath)
    Assert-True ($evidenceItem.Length -eq $evidenceBytes -and $evidenceItem.Length -le 1048576 -and
        @($evidence | Where-Object { $_ -eq 10 }).Count -eq $script:NetworkResetCycles -and
        @($evidence | Where-Object { $_ -eq 13 }).Count -eq 0) "M17 network-reset cycle evidence is not closed"
    $evidenceText = [Text.UTF8Encoding]::new($false, $true).GetString($evidence)
    $evidenceLines = $evidenceText.Split([char[]]@([char]10), [StringSplitOptions]::None)
    Assert-True ($evidenceLines.Count -eq $script:NetworkResetCycles + 1 -and
        $evidenceLines[-1].Length -eq 0) "M17 network-reset cycle evidence row count is invalid"
    $cycleProperties = @(
        "cycle", "mutation", "route_metric", "process_id", "interface_guid", "interface_luid",
        "interface_index", "managed_plane_sha256", "strict_route_wfp_sha256", "wfp_sampled",
        "session_generation", "network_generation", "reset_started", "reset_succeeded",
        "reset_failed", "full_rebuild", "strict_route_effective"
    )
    foreach ($offset in 0..($script:NetworkResetCycles - 1)) {
        $cycle = $offset + 1
        $row = $evidenceLines[$offset] | ConvertFrom-Json -Depth 4 -ErrorAction Stop
        Assert-ClosedJsonProperties $row $cycleProperties "M17 network-reset cycle evidence row"
        $expectedMetric = if ($cycle -eq 1 -or ($cycle % 2) -ne 0) { 4094 } else { 4095 }
        $expectedMutation = if ($cycle -eq 1) { "create" } else { "metric_toggle" }
        $expectedWfpSample = $cycle -eq 1 -or $cycle -eq $script:NetworkResetCycles -or
            ($cycle % $sampleStride) -eq 0
        Assert-True ($row.cycle -is [long] -and [long]$row.cycle -eq $cycle -and
            $row.mutation -is [string] -and $row.mutation -ceq $expectedMutation -and
            $row.route_metric -is [long] -and [long]$row.route_metric -eq $expectedMetric -and
            $row.process_id -is [long] -and [uint32]$row.process_id -eq $candidatePid -and
            $row.interface_guid -is [string] -and $row.interface_guid -ceq $managedBaseline.InterfaceGuid -and
            $row.interface_luid -is [string] -and $row.interface_luid -ceq $managedBaseline.InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture) -and
            $row.interface_index -is [long] -and [uint32]$row.interface_index -eq $managedBaseline.InterfaceIndex -and
            $row.managed_plane_sha256 -is [string] -and $row.managed_plane_sha256 -ceq $managedBaseline.Sha256 -and
            $row.strict_route_wfp_sha256 -is [string] -and $row.strict_route_wfp_sha256 -ceq $wfpBaseline.Sha256 -and
            $row.wfp_sampled -is [bool] -and $row.wfp_sampled -eq $expectedWfpSample -and
            $row.session_generation -is [double] -and $row.network_generation -is [double] -and
            $row.reset_started -is [double] -and $row.reset_succeeded -is [double] -and
            $row.reset_failed -is [double] -and
            $row.full_rebuild -is [double] -and $row.strict_route_effective -is [double] -and
            [double]$row.session_generation -eq $initial.Generation + $cycle -and
            [double]$row.network_generation -eq $initial.Generation + $cycle -and
            [double]$row.reset_started -eq $baseline.ResetStarted + $cycle -and
            [double]$row.reset_succeeded -eq $baseline.ResetSucceeded + $cycle -and
            [double]$row.reset_failed -eq $baseline.ResetFailed -and
            [double]$row.full_rebuild -eq $baseline.FullRebuild -and
            [double]$row.strict_route_effective -eq 1) "M17 network-reset cycle evidence row values are invalid: cycle=$cycle"
    }
    $routeIntent = Read-M17NetworkResetRouteMutationIntent ([string]$mutation.IntentPath)
    $foreignRoute = @(Get-NetRoute -InterfaceIndex ([int]$routeIntent.interface_index) `
        -DestinationPrefix ([string]$routeIntent.destination_prefix) -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.NextHop -ceq [string]$routeIntent.next_hop -and [uint32]$_.RouteMetric -in @($routeIntent.route_metrics) })
    Assert-True ($foreignRoute.Count -eq 1) "M17 journaled notification route did not survive ordinary resets"
    $script:m17CounterAfter = Get-M17CounterSnapshot $finalMetrics
    Add-M17Witness "ordinary_route_notifications_reset_network_runtime" "live-product" "$script:NetworkResetCycles journaled underlay route mutations completed lightweight ResetNetwork"
    Add-M17Witness "same_process_and_managed_adapter_identity" "live-product" "every reset retained one PID and the exact adapter GUID, LUID, and interface index"
    Add-M17Witness "managed_addresses_routes_and_dns_are_unchanged" "live-product" "every reset reproduced the exact managed-plane address, route, DNS, MTU, and adapter snapshot hash"
    Add-M17Witness "strict_route_is_effective_and_filter_identity_is_unchanged" "live-product" "every notification passed exact strict-route health revalidation, and $wfpSamples bounded WFP snapshots retained the same process-owned dynamic session and eight dual-stack DNS guard filter IDs"
    Add-M17Witness "network_generation_and_reset_metrics_advance" "live-product" "network and TUN generations plus successful ResetNetwork counters advanced exactly once per mutation"
    Add-M17Witness "retry_reset_failure_and_full_rebuild_metrics_are_unchanged" "live-product" "retry, reset-failure, and full-rebuild counters remained at baseline"
    Add-M17LiveRow "network-reset-summary" ([ordered]@{
        cycles = $script:NetworkResetCycles
        process_id = $candidatePid
        initial_session_generation = $initial.Generation
        final_session_generation = $finalState.SessionGeneration
        final_network_generation = $finalState.NetworkGeneration
        reset_started_delta = $finalState.ResetStarted - $baseline.ResetStarted
        reset_succeeded_delta = $finalState.ResetSucceeded - $baseline.ResetSucceeded
        reset_failed_delta = $finalState.ResetFailed - $baseline.ResetFailed
        full_rebuild_delta = $finalState.FullRebuild - $baseline.FullRebuild
        strict_route_filter_install_delta = $finalState.StrictInstallSucceeded - $baseline.StrictInstallSucceeded
        managed_plane_sha256 = $managedBaseline.Sha256
        strict_route_wfp_sha256 = $wfpBaseline.Sha256
        strict_route_filter_ids = @($wfpBaseline.FilterIds)
        strict_route_health_revalidations = $script:NetworkResetCycles
        strict_route_wfp_samples = $wfpSamples
        cycle_evidence = [IO.Path]::GetFileName($evidencePath)
        cycle_evidence_bytes = $evidenceItem.Length
        cycle_evidence_sha256 = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
    Stop-M17Candidate $script:activeProcess "network-reset"
    Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
    Assert-True (@(Get-NetRoute -DestinationPrefix $script:m17NetworkResetProbePrefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "M17 network-reset notification route cleanup was not exact"
    Add-M17LiveRow "network-reset-mutation-cleanup" ([ordered]@{
        destination_prefix = $script:m17NetworkResetProbePrefix
        active_store_routes = 0
        mutation_journal = "absent"
    })
}

function Invoke-M17RestartStress {
    $udpAssociationLimit = 32
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-restart-stress.toml"
    $physical = Get-Ipv4DefaultUnderlay
    $resolverAddress = [string]$physical.Sources[0].IPAddress
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $supportAddress = $script:capabilityIdentity.SupportAddress
    Assert-True ($supportAddress -cne "198.51.100.254") "M17 restart notification prefix collides with the support listener"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$supportAddress/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = $udpAssociationLimit
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $script:m17MetricsPort @"
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$(Get-UniqueTcpPort)"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${resolverAddress}:$resolverPort"
detour = "direct"
[dns.route]
final = "resolver"
"@
    Assert-M17Config $path "restart-stress"
    $script:activeProcess = Start-M17Candidate $path "restart-stress"
    $candidatePid = [uint32]$script:activeProcess.Id
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $initial.Metrics
    $associationLimitBefore = Get-M17MetricValue $initial.Metrics "ferrum2_tun_udp_association_rejected_limit" $true
    Assert-True ($associationLimitBefore -eq 0) "M17 restart baseline already exhausted the UDP association limit"
    $preHealthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    Assert-True ((Get-M17MetricValue $preHealthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 initial pre-health association limit changed"
    Add-M17LiveRow "restart-initial-pre-health" ([ordered]@{
        generation = $preHealthBaseline.Generation
        udp_associations = $preHealthBaseline.UdpAssociations
        udp_candidates = $preHealthBaseline.UdpCandidates
        handler_tasks = $preHealthBaseline.HandlerTasks
    })
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-before"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-before"))
    $healthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $initial.Generation $udpAssociationLimit
    Assert-True ($healthBaseline.UdpCandidates -eq 0 -and
        $healthBaseline.UdpAssociations -le $udpAssociationLimit -and
        $healthBaseline.HandlerTasks -eq $healthBaseline.UdpAssociations -and
        (Get-M17MetricValue $healthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 initial handler/association baseline is not bounded"
    $maxSettledUdpAssociations = [Math]::Max($preHealthBaseline.UdpAssociations, $healthBaseline.UdpAssociations)
    $maxSettledHandlerTasks = [Math]::Max($preHealthBaseline.HandlerTasks, $healthBaseline.HandlerTasks)

    $generation = $initial.Generation
    $lifecycleBefore = Get-M17ManagedRouteRebuildMetricState $initial.Metrics
    foreach ($cycle in 1..$script:RestartCycles) {
        Remove-M17ManagedRouteForRestart $script:ownedInterfaceIndex "$supportAddress/32"
        $expectedGeneration = $generation + 1
        $state = Wait-M17Session $script:m17MetricsPort $expectedGeneration 1 45
        Start-Sleep -Milliseconds 500
        $stableState = Wait-M17Session $script:m17MetricsPort $expectedGeneration 1 10
        Assert-True ($stableState.Generation -eq $expectedGeneration -and
            $stableState.Active -eq 1) "M17 restart produced more than one stable generation"
        $script:activeProcess.Refresh()
        Assert-True (-not $script:activeProcess.HasExited -and [uint32]$script:activeProcess.Id -eq $candidatePid) "M17 restart replaced the client process"
        $adapter = Wait-M17AdapterReady $script:adapterName $true $true @("198.18.0.1") @("fd00::1")
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-M17ExactManagedRoute $script:ownedInterfaceIndex "$supportAddress/32")
        $preHealthBaseline = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
        Assert-True ((Get-M17MetricValue $preHealthBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 per-cycle pre-health association limit changed"
        $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $preHealthBaseline.UdpAssociations)
        $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $preHealthBaseline.HandlerTasks)
        Add-M17LiveRow ("restart-cycle-{0:D4}-pre-health" -f $cycle) ([ordered]@{
            cycle = $cycle
            generation = $preHealthBaseline.Generation
            process_id = $candidatePid
            interface_index = $script:ownedInterfaceIndex
            tcp_flows = $preHealthBaseline.TcpFlows
            udp_associations = $preHealthBaseline.UdpAssociations
            udp_candidates = $preHealthBaseline.UdpCandidates
            reassembly_entries = $preHealthBaseline.ReassemblyEntries
            handler_tasks = $preHealthBaseline.HandlerTasks
        })
        $payload = [Text.Encoding]::ASCII.GetBytes(("m17-restart-{0:D4}" -f $cycle))
        Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex $payload
        Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex $payload
        $cycleBaseline = Wait-M17FlowDrain $script:m17MetricsPort $expectedGeneration $udpAssociationLimit
        Assert-True ($cycleBaseline.UdpCandidates -eq 0 -and
            $cycleBaseline.UdpAssociations -le $udpAssociationLimit -and
            $cycleBaseline.HandlerTasks -eq $cycleBaseline.UdpAssociations -and
            (Get-M17MetricValue $cycleBaseline.Metrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 per-cycle handler/association baseline changed"
        $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $cycleBaseline.UdpAssociations)
        $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $cycleBaseline.HandlerTasks)
        Add-M17LiveRow ("restart-cycle-{0:D4}-post-health" -f $cycle) ([ordered]@{
            cycle = $cycle
            generation = $cycleBaseline.Generation
            process_id = $candidatePid
            interface_index = $script:ownedInterfaceIndex
            tcp_flows = $cycleBaseline.TcpFlows
            udp_associations = $cycleBaseline.UdpAssociations
            udp_candidates = $cycleBaseline.UdpCandidates
            reassembly_entries = $cycleBaseline.ReassemblyEntries
            handler_tasks = $cycleBaseline.HandlerTasks
            tcp_health = "pass"
            udp_health = "pass"
        })
        $generation = $expectedGeneration
    }
    Invoke-TunProductTcp $supportAddress $script:capabilityIdentity.TcpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-after"))
    Invoke-TunProductUdp $supportAddress $script:capabilityIdentity.UdpPort $script:ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m17-restart-after"))
    $finalBaseline = Wait-M17FlowDrain $script:m17MetricsPort $generation $udpAssociationLimit
    $maxSettledUdpAssociations = [Math]::Max($maxSettledUdpAssociations, $finalBaseline.UdpAssociations)
    $maxSettledHandlerTasks = [Math]::Max($maxSettledHandlerTasks, $finalBaseline.HandlerTasks)
    $finalMetrics = $finalBaseline.Metrics
    $lifecycleAfter = Get-M17ManagedRouteRebuildMetricState $finalMetrics
    Assert-True ($generation -eq $initial.Generation + $script:RestartCycles -and
        $lifecycleAfter.SessionGeneration -eq $generation -and
        $lifecycleAfter.NetworkGeneration -eq $generation -and
        $lifecycleAfter.RouteDamageStarted -eq $lifecycleBefore.RouteDamageStarted + $script:RestartCycles -and
        $lifecycleAfter.RouteDamageSucceeded -eq $lifecycleBefore.RouteDamageSucceeded + $script:RestartCycles -and
        $lifecycleAfter.RouteDamageFailed -eq $lifecycleBefore.RouteDamageFailed -and
        $lifecycleAfter.FullRebuildTotal -eq $lifecycleBefore.FullRebuildTotal + (2 * $script:RestartCycles) -and
        $lifecycleAfter.NetworkResetTotal -eq $lifecycleBefore.NetworkResetTotal -and
        (Get-M17MetricValue $finalMetrics "ferrum2_tun_udp_association_rejected_limit" $true) -eq $associationLimitBefore) "M17 restart stress counters changed"
    $script:m17CounterAfter = Get-M17CounterSnapshot $finalMetrics
    Add-M17Witness "same_process_for_every_restart" "live-product" "$script:RestartCycles observed notifications retained one PID"
    Add-M17Witness "generation_advances_once_per_restart" "live-product" "each notification reached exactly the next stable generation"
    Add-M17Witness "adapter_route_dns_and_handler_baselines_restore" "live-product" "dual-stack adapter, capture route, DNS, TCP and UDP recovered after every restart with zero candidates, exact handler/association parity and no capacity rejection"
    Add-M17LiveRow "restart-stress" ([ordered]@{
        cycles = $script:RestartCycles
        process_id = $candidatePid
        initial_generation = $initial.Generation
        final_generation = $generation
        route_damage_rebuild_started = $lifecycleAfter.RouteDamageStarted
        route_damage_rebuild_succeeded = $lifecycleAfter.RouteDamageSucceeded
        route_damage_rebuild_failed = $lifecycleAfter.RouteDamageFailed
        network_reset_delta = $lifecycleAfter.NetworkResetTotal - $lifecycleBefore.NetworkResetTotal
        udp_association_limit = $udpAssociationLimit
        max_settled_udp_associations = $maxSettledUdpAssociations
        max_settled_handler_tasks = $maxSettledHandlerTasks
        udp_association_limit_rejections = Get-M17MetricValue $finalMetrics "ferrum2_tun_udp_association_rejected_limit" $true
    })
    Stop-M17Candidate $script:activeProcess "restart-stress"
}

function New-M17PaddedDnsQuery([uint16]$Id, [int]$PaddingBytes = 2048) {
    Assert-True ($PaddingBytes -ge 1200 -and $PaddingBytes -le 4096) "M17 DNS padding is outside the bounded witness range"
    $query = [Collections.Generic.List[byte]]::new()
    $baseQuery = [byte[]](New-DnsQuery $Id)
    $query.AddRange($baseQuery)
    $query[11] = 1
    $query.Add(0)
    $query.AddRange([byte[]](0, 41, 16, 0, 0, 0, 0, 0))
    $optionLength = $PaddingBytes + 4
    $query.Add([byte]($optionLength -shr 8))
    $query.Add([byte]($optionLength -band 0xff))
    $query.AddRange([byte[]](0, 12, [byte]($PaddingBytes -shr 8), [byte]($PaddingBytes -band 0xff)))
    $query.AddRange([byte[]]::new($PaddingBytes))
    return $query.ToArray()
}

function Invoke-M17DnsBytes([string]$Source, [string]$Destination, [byte[]]$Query) {
    $family = if ($Destination.Contains(":")) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $client = [Net.Sockets.UdpClient]::new($family)
    try {
        $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Source), 0))
        [void]$client.Send($Query, $Query.Length, $Destination, 53)
        $task = $client.ReceiveAsync()
        Assert-True ($task.Wait(10000) -and -not $task.IsFaulted) "M17 padded DNS response timeout"
        $response = $task.Result.Buffer
    } finally { $client.Dispose() }
    Assert-True ($response.Length -ge 12 -and $response[0] -eq $Query[0] -and $response[1] -eq $Query[1] -and
        ($response[2] -band 0x80) -ne 0) "M17 padded DNS response is invalid"
}

function Get-M17PayloadSha256([byte[]]$Payload) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($Payload))).Replace("-", "").ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Assert-M17DnsQueryEnvelope([byte[]]$Payload, [uint16]$Id) {
    Assert-True ($Payload.Length -eq 32 -and
        $Payload[0] -eq [byte]($Id -shr 8) -and $Payload[1] -eq [byte]($Id -band 0xff) -and
        $Payload[2] -eq 1 -and $Payload[3] -eq 0 -and
        $Payload[4] -eq 0 -and $Payload[5] -eq 1 -and
        $Payload[6] -eq 0 -and $Payload[7] -eq 0 -and
        $Payload[8] -eq 0 -and $Payload[9] -eq 0 -and
        $Payload[10] -eq 0 -and $Payload[11] -eq 0 -and
        $Payload[27] -eq 0 -and $Payload[28] -eq 0 -and $Payload[29] -eq 1 -and
        $Payload[30] -eq 0 -and $Payload[31] -eq 1) "M17 DNS query wire envelope is invalid"
}

function New-M17QuicV1InitialEnvelope {
    # A deterministic 1,200-byte QUIC v1 Initial envelope. The protected body is opaque, but the
    # long header, connection IDs, zero token, two-byte packet length, packet number length, and
    # RFC minimum datagram size are independently parsed below before the live round trip.
    $packet = [byte[]]::new(1200)
    $packet[0] = 0xc3
    $packet[4] = 1
    $packet[5] = 8
    [Array]::Copy([byte[]](0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08), 0, $packet, 6, 8)
    $packet[14] = 8
    [Array]::Copy([byte[]](0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5), 0, $packet, 15, 8)
    $packet[23] = 0
    $packet[24] = 0x44
    $packet[25] = 0x96
    [Array]::Copy([byte[]](0, 0, 0, 2), 0, $packet, 26, 4)
    foreach ($index in 30..1199) { $packet[$index] = [byte](($index * 29 + 17) % 251) }
    return $packet
}

function Assert-M17QuicV1InitialEnvelope([byte[]]$Payload) {
    $declaredLength = (($Payload[24] -band 0x3f) -shl 8) -bor $Payload[25]
    Assert-True ($Payload.Length -eq 1200 -and
        ($Payload[0] -band 0xc0) -eq 0xc0 -and ($Payload[0] -band 0x30) -eq 0 -and
        (($Payload[0] -band 3) + 1) -eq 4 -and
        $Payload[1] -eq 0 -and $Payload[2] -eq 0 -and $Payload[3] -eq 0 -and $Payload[4] -eq 1 -and
        $Payload[5] -eq 8 -and $Payload[14] -eq 8 -and $Payload[23] -eq 0 -and
        ($Payload[24] -shr 6) -eq 1 -and $declaredLength -eq 1174 -and
        26 + $declaredLength -eq $Payload.Length) "M17 QUIC v1 Initial envelope is not structurally parseable"
}

function Get-M17StunFingerprintCrc([byte[]]$Payload, [int]$Length) {
    Assert-True ($Length -ge 20 -and $Length -le $Payload.Length) "M17 STUN fingerprint input length is invalid"
    [uint32]$crc = [uint32]::MaxValue
    foreach ($index in 0..($Length - 1)) {
        $crc = [uint32]($crc -bxor [uint32]$Payload[$index])
        foreach ($bit in 0..7) {
            if (($crc -band 1) -ne 0) {
                $crc = [uint32](($crc -shr 1) -bxor [uint32]3988292384)
            } else {
                $crc = [uint32]($crc -shr 1)
            }
        }
    }
    return [uint32](($crc -bxor [uint32]::MaxValue) -bxor [uint32]1398035790)
}

function Get-M17IceMessageIntegrity([byte[]]$Payload, [int]$MessageIntegrityOffset) {
    Assert-True ($MessageIntegrityOffset -ge 20 -and $MessageIntegrityOffset + 24 -le $Payload.Length) "M17 ICE MESSAGE-INTEGRITY offset is invalid"
    $input = [byte[]]::new($MessageIntegrityOffset)
    [Array]::Copy($Payload, 0, $input, 0, $input.Length)
    $lengthThroughIntegrity = $MessageIntegrityOffset + 24 - 20
    $input[2] = [byte]($lengthThroughIntegrity -shr 8)
    $input[3] = [byte]($lengthThroughIntegrity -band 0xff)
    $key = [Text.Encoding]::ASCII.GetBytes("m17-ice-password-0123456789abcdef")
    $algorithm = [Security.Cryptography.HMACSHA1]::new($key)
    try { return $algorithm.ComputeHash($input) }
    finally { $algorithm.Dispose() }
}

function New-M17StunBindingRequest([byte]$TransactionSeed, [bool]$IceCandidate) {
    $message = [Collections.Generic.List[byte]]::new()
    $message.AddRange([byte[]](0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42))
    foreach ($index in 0..11) { $message.Add([byte](($TransactionSeed + $index) -band 0xff)) }
    if ($IceCandidate) {
        $username = [Text.Encoding]::ASCII.GetBytes("remote17:local17")
        $message.AddRange([byte[]](0, 6, 0, $username.Length))
        $message.AddRange($username)
        while (($message.Count % 4) -ne 0) { $message.Add(0) }
        $message.AddRange([byte[]](0, 0x24, 0, 4, 0x6e, 0, 1, 0xff))
        $message.AddRange([byte[]](0x80, 0x2a, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88))
        $messageIntegrityOffset = $message.Count
        $message.AddRange([byte[]](0, 8, 0, 20))
        $message.AddRange([byte[]]::new(20))
        $lengthThroughIntegrity = $message.Count - 20
        $message[2] = [byte]($lengthThroughIntegrity -shr 8)
        $message[3] = [byte]($lengthThroughIntegrity -band 0xff)
        [byte[]]$integrity = Get-M17IceMessageIntegrity $message.ToArray() $messageIntegrityOffset
        foreach ($index in 0..($integrity.Length - 1)) {
            $message[$messageIntegrityOffset + 4 + $index] = $integrity[$index]
        }
        $fingerprintOffset = $message.Count
        $message.AddRange([byte[]](0x80, 0x28, 0, 4, 0, 0, 0, 0))
        $bodyLength = $message.Count - 20
        $message[2] = [byte]($bodyLength -shr 8)
        $message[3] = [byte]($bodyLength -band 0xff)
        [uint32]$fingerprint = Get-M17StunFingerprintCrc $message.ToArray() $fingerprintOffset
        $message[$fingerprintOffset + 4] = [byte](($fingerprint -shr 24) -band 0xff)
        $message[$fingerprintOffset + 5] = [byte](($fingerprint -shr 16) -band 0xff)
        $message[$fingerprintOffset + 6] = [byte](($fingerprint -shr 8) -band 0xff)
        $message[$fingerprintOffset + 7] = [byte]($fingerprint -band 0xff)
    }
    $bodyLength = $message.Count - 20
    $message[2] = [byte]($bodyLength -shr 8)
    $message[3] = [byte]($bodyLength -band 0xff)
    return $message.ToArray()
}

function Assert-M17StunBindingRequest([byte[]]$Payload, [bool]$IceCandidate) {
    Assert-True ($Payload.Length -ge 20 -and $Payload[0] -eq 0 -and $Payload[1] -eq 1 -and
        $Payload[4] -eq 0x21 -and $Payload[5] -eq 0x12 -and
        $Payload[6] -eq 0xa4 -and $Payload[7] -eq 0x42) "M17 STUN Binding request header is invalid"
    $declaredLength = ([int]$Payload[2] -shl 8) -bor [int]$Payload[3]
    Assert-True (($declaredLength % 4) -eq 0 -and 20 + $declaredLength -eq $Payload.Length) "M17 STUN message length is invalid"
    $attributes = [Collections.Generic.HashSet[int]]::new()
    $attributeOffsets = @{}
    $offset = 20
    while ($offset -lt $Payload.Length) {
        Assert-True ($offset + 4 -le $Payload.Length) "M17 STUN attribute header is truncated"
        $attribute = ([int]$Payload[$offset] -shl 8) -bor [int]$Payload[$offset + 1]
        $length = ([int]$Payload[$offset + 2] -shl 8) -bor [int]$Payload[$offset + 3]
        $paddedLength = ($length + 3) -band (-bnot 3)
        Assert-True ($offset + 4 + $paddedLength -le $Payload.Length) "M17 STUN attribute value is truncated"
        [void]$attributes.Add($attribute)
        $attributeOffsets[$attribute] = $offset
        $offset += 4 + $paddedLength
    }
    if ($IceCandidate) {
        Assert-True ($attributes.Contains(0x0006) -and $attributes.Contains(0x0024) -and
            $attributes.Contains(0x802a) -and $attributes.Contains(0x0008) -and
            $attributes.Contains(0x8028)) "M17 WebRTC ICE connectivity-check attributes are incomplete"
        $messageIntegrityOffset = [int]$attributeOffsets[0x0008]
        [byte[]]$expectedIntegrity = Get-M17IceMessageIntegrity $Payload $messageIntegrityOffset
        [byte[]]$actualIntegrity = $Payload[($messageIntegrityOffset + 4)..($messageIntegrityOffset + 23)]
        Assert-True (($actualIntegrity -join ",") -ceq ($expectedIntegrity -join ",")) "M17 ICE MESSAGE-INTEGRITY is invalid"
        $fingerprintOffset = [int]$attributeOffsets[0x8028]
        Assert-True ($fingerprintOffset + 8 -eq $Payload.Length) "M17 ICE FINGERPRINT is not the final attribute"
        [uint32]$expectedFingerprint = Get-M17StunFingerprintCrc $Payload $fingerprintOffset
        [uint32]$actualFingerprint = ([uint32]$Payload[$fingerprintOffset + 4] -shl 24) -bor
            ([uint32]$Payload[$fingerprintOffset + 5] -shl 16) -bor
            ([uint32]$Payload[$fingerprintOffset + 6] -shl 8) -bor
            [uint32]$Payload[$fingerprintOffset + 7]
        Assert-True ($actualFingerprint -eq $expectedFingerprint) "M17 ICE FINGERPRINT is invalid"
    } else {
        Assert-True ($attributes.Count -eq 0) "M17 bare STUN Binding request unexpectedly has attributes"
    }
}

function New-M17GamePeerDatagram([byte]$Peer, [uint32]$Sequence) {
    $packet = [byte[]]::new(24)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("F2GM"), 0, $packet, 0, 4)
    $packet[4] = 1
    $packet[5] = 1
    $packet[6] = $Peer
    $packet[8] = 0x17
    $packet[9] = 0x06
    $packet[10] = 0x20
    $packet[11] = 0x26
    $packet[12] = [byte]($Sequence -shr 24)
    $packet[13] = [byte]($Sequence -shr 16)
    $packet[14] = [byte]($Sequence -shr 8)
    $packet[15] = [byte]($Sequence -band 0xff)
    $packet[17] = 6
    foreach ($index in 18..23) { $packet[$index] = [byte](($Peer * 31 + $index) -band 0xff) }
    return $packet
}

function Assert-M17GamePeerDatagram([byte[]]$Payload, [byte]$Peer, [uint32]$Sequence) {
    $decodedSequence = ([uint32]$Payload[12] -shl 24) -bor ([uint32]$Payload[13] -shl 16) -bor
        ([uint32]$Payload[14] -shl 8) -bor [uint32]$Payload[15]
    Assert-True ($Payload.Length -eq 24 -and
        [Text.Encoding]::ASCII.GetString($Payload, 0, 4) -ceq "F2GM" -and
        $Payload[4] -eq 1 -and $Payload[5] -eq 1 -and $Payload[6] -eq $Peer -and
        $Payload[16] -eq 0 -and $Payload[17] -eq 6 -and
        $decodedSequence -eq $Sequence) "M17 game-style binary datagram is invalid"
}

function Wait-M17MetricIncrease(
    [int]$MetricsPort,
    [string]$Name,
    [double]$Before,
    [int]$TimeoutSeconds = 5
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $metrics = Get-Metrics $MetricsPort 2
        if ((Get-M17MetricValue $metrics $Name $true) -gt $Before) { return $metrics }
        Start-Sleep -Milliseconds 20
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 metric did not increase: $Name"
}

function New-M17TunUdpClient([string]$Source, [int]$InterfaceIndex) {
    $address = [Net.IPAddress]::Parse($Source)
    $client = [Net.Sockets.UdpClient]::new($address.AddressFamily)
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($address, 0))
    return $client
}

function Invoke-M17UdpEcho(
    [Net.Sockets.UdpClient]$Client,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [int]$TimeoutMilliseconds = 10000
) {
    [void]$Client.Send($Payload, $Payload.Length, $Address, $Port)
    $task = $Client.ReceiveAsync()
    Assert-True ($task.Wait($TimeoutMilliseconds) -and -not $task.IsFaulted) "M17 TUN UDP echo timeout"
    Assert-True (($task.Result.Buffer -join ",") -ceq ($Payload -join ",") -and
        $task.Result.RemoteEndPoint.Address.ToString() -ceq ([Net.IPAddress]::Parse($Address)).ToString() -and
        $task.Result.RemoteEndPoint.Port -eq $Port) "M17 TUN UDP response source or payload mismatch"
}

function Wait-M17ProbeRemoteEndpoint([Ferrum2UdpProbe]$Probe, [int]$TimeoutMilliseconds = 5000) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $endpoint = $Probe.RemoteEndpoint
        if ($null -ne $endpoint) { return $endpoint }
        Start-Sleep -Milliseconds 10
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 target probe did not publish its remote endpoint"
}

function Receive-M17UdpIfReady(
    [Net.Sockets.UdpClient]$Client,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [int]$TimeoutMilliseconds = 250
) {
    if (-not $Client.Client.Poll($TimeoutMilliseconds * 1000, [Net.Sockets.SelectMode]::SelectRead)) {
        return $false
    }
    $task = $Client.ReceiveAsync()
    Assert-True ($task.Wait(1000) -and -not $task.IsFaulted) "M17 readable UDP response could not be received"
    Assert-True (($task.Result.Buffer -join ",") -ceq ($Payload -join ",") -and
        $task.Result.RemoteEndPoint.Address.ToString() -ceq ([Net.IPAddress]::Parse($Address)).ToString() -and
        $task.Result.RemoteEndPoint.Port -eq $Port) "M17 unsolicited UDP response source or payload mismatch"
    return $true
}

function Assert-M17UdpQuiet([Net.Sockets.UdpClient]$Client, [int]$TimeoutMilliseconds = 1000) {
    $ready = $Client.Client.Poll($TimeoutMilliseconds * 1000, [Net.Sockets.SelectMode]::SelectRead)
    Assert-True (-not $ready) "M17 rejected UDP peer reached the TUN client"
}

function Add-M17LoopbackTarget(
    [string]$Address,
    [int]$Port,
    [byte[]]$ResponsePayload = $null
) {
    [void](Add-TargetAddress $Address $false)
    $probe = if ($null -eq $ResponsePayload) {
        [Ferrum2UdpProbe]::new($Address, $Port)
    } else {
        [Ferrum2UdpProbe]::new($Address, $Port, $ResponsePayload)
    }
    $script:tcpResources.Add($probe)
    return $probe
}

function Get-M17TargetRoutePreference([int]$InterfaceIndex, [string]$Address) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { "IPv6" } else { "IPv4" }
    $prefix = if ($isV6) { "$Address/128" } else { "$Address/32" }
    $tunRoutes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $localRoutes = @(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction Stop)
    Assert-True ($tunRoutes.Count -eq 1 -and $localRoutes.Count -eq 1) "M17 target route ownership is ambiguous: $prefix"
    $tunInterface = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily $family `
        -PolicyStore ActiveStore -ErrorAction Stop
    $localInterface = Get-NetIPInterface -InterfaceIndex 1 -AddressFamily $family `
        -PolicyStore ActiveStore -ErrorAction Stop
    [uint64]$tunEffective = [uint64]$tunRoutes[0].RouteMetric + [uint64]$tunInterface.InterfaceMetric
    [uint64]$localEffective = [uint64]$localRoutes[0].RouteMetric + [uint64]$localInterface.InterfaceMetric
    Assert-True ($localEffective -lt $tunEffective) "M17 unpinned server target route does not prefer loopback: $prefix"
    return [ordered]@{
        destination_prefix = $prefix
        tun_interface_index = $InterfaceIndex
        tun_route_metric = [uint32]$tunRoutes[0].RouteMetric
        tun_interface_metric = [uint32]$tunInterface.InterfaceMetric
        tun_effective_metric = $tunEffective
        local_route_metric = [uint32]$localRoutes[0].RouteMetric
        local_interface_metric = [uint32]$localInterface.InterfaceMetric
        local_effective_metric = $localEffective
    }
}

function Invoke-M17Fragments {
    $v4Target = "192.0.2.241"
    $v6Target = "2001:db8::241"
    $v4Ack = [Text.Encoding]::ASCII.GetBytes("m17-fragment-v4-ack")
    $v6Ack = [Text.Encoding]::ASCII.GetBytes("m17-fragment-v6-ack")
    $v4Port = Get-UniqueTcpPort
    $v6Port = Get-UniqueTcpPort
    $v4Probe = Add-M17LoopbackTarget $v4Target $v4Port $v4Ack
    $v6Probe = Add-M17LoopbackTarget $v6Target $v6Port $v6Ack
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-fragments.toml"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
mtu = 1280
max_udp_mappings = 16
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "proxy" $script:m17MetricsPort
    Assert-M17Config $path "fragments"
    $script:activeProcess = Start-M17Candidate $path "fragments"
    $adapter = Wait-M17AdapterReady -Name $script:adapterName -Ipv4 $true -Ipv6 $true -ExpectedMtu 1280
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    [void](Add-TunRoute $script:ownedInterfaceIndex "$v4Target/32" 500)
    [void](Add-TunRoute $script:ownedInterfaceIndex "$v6Target/128" 500)
    Add-M17LiveRow "fragment-target-route-preference" ([ordered]@{
        routes = @(
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $v4Target
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $v6Target
        )
    })
    $initial = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $initial.Metrics
    $completedBefore = Get-M17MetricValue $initial.Metrics "ferrum2_tun_reassembly_completed"
    $v4Payload = [byte[]]::new(8192)
    $v6Payload = [byte[]]::new(8192)
    for ($index = 0; $index -lt $v4Payload.Length; $index++) {
        $v4Payload[$index] = [byte]($index % 251)
        $v6Payload[$index] = [byte](250 - ($index % 251))
    }
    $v4Client = Open-TunUdp $v4Target $v4Port $script:ownedInterfaceIndex
    $v6Client = Open-TunUdp $v6Target $v6Port $script:ownedInterfaceIndex
    try {
        [void]$v4Client.Send($v4Payload, $v4Payload.Length)
        $v4Echo = Receive-TunUdp $v4Client 10000
        Assert-True (($v4Echo -join ",") -ceq ($v4Ack -join ",")) "M17 fragmented IPv4 UDP acknowledgement changed"
        [void]$v6Client.Send($v6Payload, $v6Payload.Length)
        $v6Echo = Receive-TunUdp $v6Client 10000
        Assert-True (($v6Echo -join ",") -ceq ($v6Ack -join ",")) "M17 fragmented IPv6 UDP acknowledgement changed"
    } finally { $v4Client.Dispose(); $v6Client.Dispose() }
    Assert-True ($v4Probe.WaitRequests(1, 5000) -and $v6Probe.WaitRequests(1, 5000)) "M17 fragmented target did not observe both datagrams"
    Assert-True (($v4Probe.Received -join ",") -ceq ($v4Payload -join ",") -and
        ($v6Probe.Received -join ",") -ceq ($v6Payload -join ",")) "M17 fragmented target request payload changed"
    $fragmentMetrics = Get-Metrics $script:m17MetricsPort
    Assert-True ((Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_completed") -ge $completedBefore + 2 -and
        (Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_entries_active") -eq 0) "M17 live fragment completion metrics changed"
    Add-M17LiveRow "live-fragmented-udp" ([ordered]@{
        ipv4_payload_bytes = $v4Payload.Length
        ipv6_payload_bytes = $v6Payload.Length
        ipv4_response_bytes = $v4Ack.Length
        ipv6_response_bytes = $v6Ack.Length
        completed_delta = (Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_completed") - $completedBefore
        active_entries = Get-M17MetricValue $fragmentMetrics "ferrum2_tun_reassembly_entries_active"
    })
    Stop-M17Candidate $script:activeProcess "fragments"

    $physical = Get-Ipv4DefaultUnderlay
    $resolverAddress = [string]$physical.Sources[0].IPAddress
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $dnsMetricsPort = Get-UniqueTcpPort
    $dnsPath = Join-Path $script:work "m17-fragmented-dns.toml"
    Write-M17ClientConfig $dnsPath @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
mtu = 1280
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "direct" $dnsMetricsPort @"
[dns]
timeout_ms = 2000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$(Get-UniqueTcpPort)"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${resolverAddress}:$resolverPort"
detour = "direct"
[dns.route]
final = "resolver"
"@
    Assert-M17Config $dnsPath "fragmented-dns"
    $script:activeProcess = Start-M17Candidate $dnsPath "fragmented-dns"
    $adapter = Wait-M17AdapterReady -Name $script:adapterName -Ipv4 $true -Ipv6 $true `
        -Ipv4Dns @("198.18.0.1") -Ipv6Dns @("fd00::1") -ExpectedMtu 1280
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    $dnsState = Wait-M17Session $dnsMetricsPort 1 1
    $dnsCompletedBefore = Get-M17MetricValue $dnsState.Metrics "ferrum2_tun_reassembly_completed"
    Invoke-M17DnsBytes "198.18.0.2" "198.18.0.1" (New-M17PaddedDnsQuery 0x1701)
    $dnsMetrics = Get-Metrics $dnsMetricsPort
    Assert-True ((Get-M17MetricValue $dnsMetrics "ferrum2_tun_reassembly_completed") -gt $dnsCompletedBefore) "M17 fragmented synthetic DNS did not complete reassembly"
    Add-M17Witness "fragmented_synthetic_dns" "live-product" "padded UDP DNS query reassembled before synthetic DNS handling"
    Add-M17LiveRow "fragmented-synthetic-dns" ([ordered]@{
        query_bytes = (New-M17PaddedDnsQuery 0x1701).Length
        resolver_requests = $dnsResponder.Requests
    })
    $script:m17CounterAfter = Get-M17CounterSnapshot $dnsMetrics
    Stop-M17Candidate $script:activeProcess "fragmented-dns"
}

function Invoke-M17DualStackDns {
    $physical = Get-Ipv4DefaultUnderlay
    $resolverAddress = [string]$physical.Sources[0].IPAddress
    $resolverPort = Get-UniqueTcpPort
    $dnsResponder = [Ferrum2DnsResponder]::new($resolverAddress, $resolverPort)
    $script:tcpResources.Add($dnsResponder)
    $cases = @(
        [ordered]@{ Name = "ipv4-only"; V4 = $true; V6 = $false; V4Dns = @("198.18.0.1"); V6Dns = @(); Fields = @"
ipv4_address = "198.18.0.2/30"
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ },
        [ordered]@{ Name = "ipv6-only"; V4 = $false; V6 = $true; V4Dns = @(); V6Dns = @("fd00::1"); Fields = @"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["2001:db8:17::/48"]
auto_dns = true
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ },
        [ordered]@{ Name = "dual"; V4 = $true; V6 = $true; V4Dns = @("198.18.0.1"); V6Dns = @("fd00::1"); Fields = @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
route_address = ["$($script:capabilityIdentity.SupportAddress)/32", "2001:db8:17::/48"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ }
    )
    $caseOrdinal = 0
    foreach ($case in $cases) {
        $caseOrdinal++
        $metricsPort = Get-UniqueTcpPort
        $path = Join-Path $script:work "m17-dns-$($case.Name).toml"
        Write-M17ClientConfig $path $case.Fields "direct" $metricsPort @"
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$(Get-UniqueTcpPort)"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${resolverAddress}:$resolverPort"
detour = "direct"
[dns.route]
final = "resolver"
"@
        Assert-M17Config $path "dns-$($case.Name)"
        $script:activeProcess = Start-M17Candidate $path "dns-$($case.Name)"
        $adapter = Wait-M17AdapterReady $script:adapterName $case.V4 $case.V6 $case.V4Dns $case.V6Dns
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        $state = Wait-M17Session $metricsPort 1 1
        if ($caseOrdinal -eq 1) { $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics }
        if ($case.V4) {
            Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $false ([uint16](0x1710 + $caseOrdinal))
            Invoke-M17DnsQuery "198.18.0.2" "198.18.0.1" $true ([uint16](0x1720 + $caseOrdinal))
            if (-not $script:m17WitnessRows.Contains("ipv4_udp_dns")) { Add-M17Witness "ipv4_udp_dns" "live-product" "IPv4 synthetic DNS UDP response validated" }
            if (-not $script:m17WitnessRows.Contains("ipv4_tcp_dns")) { Add-M17Witness "ipv4_tcp_dns" "live-product" "IPv4 synthetic DNS TCP response validated" }
        }
        if ($case.V6) {
            Invoke-M17DnsQuery "fd00::2" "fd00::1" $false ([uint16](0x1730 + $caseOrdinal))
            Invoke-M17DnsQuery "fd00::2" "fd00::1" $true ([uint16](0x1740 + $caseOrdinal))
            if (-not $script:m17WitnessRows.Contains("ipv6_udp_dns")) { Add-M17Witness "ipv6_udp_dns" "live-product" "IPv6 synthetic DNS UDP response validated" }
            if (-not $script:m17WitnessRows.Contains("ipv6_tcp_dns")) { Add-M17Witness "ipv6_tcp_dns" "live-product" "IPv6 synthetic DNS TCP response validated" }
        }
        $activeMetrics = Get-Metrics $metricsPort
        Add-M17LiveRow "dns-$($case.Name)" ([ordered]@{
            ipv4 = $case.V4
            ipv6 = $case.V6
            ipv4_dns = $case.V4Dns
            ipv6_dns = $case.V6Dns
            ingress = Get-M17MetricValue $activeMetrics "ferrum2_tun_packets_ingress"
            egress = Get-M17MetricValue $activeMetrics "ferrum2_tun_packets_egress"
        })
        if ($case.Name -ceq "dual") { $script:m17CounterAfter = Get-M17CounterSnapshot $activeMetrics }
        $oldIndex = $script:ownedInterfaceIndex
        Stop-M17Candidate $script:activeProcess "dns-$($case.Name)"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $oldIndex -ErrorAction SilentlyContinue).Count -eq 0) "M17 DNS rows remained after adapter cleanup"
    }
    Add-M17Witness "dual_dns_readback_and_restore" "live-product" "IPv4-only, IPv6-only and dual exact DNS readback followed by absent-row cleanup"
}

function Invoke-M17UdpPolicy {
    Enable-M17UdpFirewallAdmission
    Add-M17LiveRow "udp-firewall-scope" ([ordered]@{
        policy_store = "ActiveStore"
        direction = "inbound"
        protocol = "udp"
        local_address = "198.18.0.2"
        remote_address = "any"
        local_only_mapping = $true
        program = $script:controllerProgram
        purpose = "prevent Windows stateful endpoint filtering from masking product ADF/EIF while remaining controller-process scoped"
    })
    try {
    $directTarget = [ordered]@{
        Address = [string]$script:capabilityIdentity.SupportAddress
        Port = [int]$script:capabilityIdentity.UdpPort
    }
    Assert-True ([Net.IPAddress]::Parse($directTarget.Address).AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) "M17 UDP direct witness requires the approved IPv4 support listener"
    $targets = @(
        [ordered]@{ Address = "192.0.2.241"; Port = Get-UniqueTcpPort },
        [ordered]@{ Address = "192.0.2.242"; Port = Get-UniqueTcpPort },
        [ordered]@{ Address = "2001:db8::241"; Port = Get-UniqueTcpPort }
    )
    $probes = @(
        Add-M17LoopbackTarget $targets[0].Address $targets[0].Port
        Add-M17LoopbackTarget $targets[1].Address $targets[1].Port
        Add-M17LoopbackTarget $targets[2].Address $targets[2].Port
    )
    $alternatePort = Get-UniqueTcpPort
    $sameAddressAlternate = [Ferrum2UdpProbe]::new($targets[0].Address, $alternatePort)
    $script:tcpResources.Add($sameAddressAlternate)
    foreach ($filtering in @("address_dependent", "endpoint_independent")) {
        $filterLabel = if ($filtering -ceq "address_dependent") { "adf" } else { "eif" }
        $metricsPort = Get-UniqueTcpPort
        $path = Join-Path $script:work "m17-udp-$filterLabel.toml"
        Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "$filtering"
ready_timeout_ms = 15000
"@ "proxy" $metricsPort @"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($directTarget.Address)"
port = $($directTarget.Port)
action = "route"
outbound = "direct"
"@
        Assert-M17Config $path "udp-$filterLabel"
        $script:activeProcess = Start-M17Candidate $path "udp-$filterLabel"
        $adapter = Wait-M17AdapterReady $script:adapterName $true $true
        $script:ownedInterfaceIndex = [int]$adapter.ifIndex
        foreach ($target in $targets) {
            $prefix = if ($target.Address.Contains(":")) { "$($target.Address)/128" } else { "$($target.Address)/32" }
            [void](Add-TunRoute $script:ownedInterfaceIndex $prefix 500)
        }
        [void](Add-TunRoute $script:ownedInterfaceIndex "$($directTarget.Address)/32" 500)
        $targetRoutePreference = @($targets | ForEach-Object {
            Get-M17TargetRoutePreference $script:ownedInterfaceIndex $_.Address
        })
        $directCaptureRoute = @(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex `
            -DestinationPrefix "$($directTarget.Address)/32" -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($directCaptureRoute.Count -eq 1) "M17 direct UDP capture route readback is not exact"
        Add-M17LiveRow "udp-$filterLabel-target-route-preference" ([ordered]@{
            client_socket_interface = $script:ownedInterfaceIndex
            routes = $targetRoutePreference
            direct_target = $directTarget
            direct_capture_route_count = $directCaptureRoute.Count
        })
        $state = Wait-M17Session $metricsPort 1 1
        Start-Sleep -Milliseconds 1000
        $preTrafficMetrics = Get-Metrics $metricsPort
        Assert-True ((Get-M17MetricValue $state.Metrics "ferrum2_tun_udp_associations_active") -eq 0 -and
            (Get-M17MetricValue $state.Metrics "ferrum2_tun_udp_candidates_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_associations_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_candidates_active") -eq 0 -and
            (Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_association_created" $true) -eq 0) "M17 background traffic allocated a UDP association before the test"
        Add-M17LiveRow "udp-$filterLabel-pre-traffic-isolation" ([ordered]@{
            samples = 2
            interval_milliseconds = 1000
            associations_active = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_associations_active"
            candidates_active = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_candidates_active"
            associations_created = Get-M17MetricValue $preTrafficMetrics "ferrum2_tun_udp_association_created" $true
        })
        if ($filtering -ceq "address_dependent") { $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics }
        $v4 = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
        $v6 = New-M17TunUdpClient "fd00::2" $script:ownedInterfaceIndex
        try {
            Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v4-a"))
            $relayEndpoint = Wait-M17ProbeRemoteEndpoint $probes[0]
            if ($filtering -ceq "address_dependent") {
                $sameIpBefore = Get-Metrics $metricsPort
                $sameIpEgressBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_packets_egress" $true
                $sameIpFilteredBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_udp_response_filtered" $true
                $sameIpQueueBefore = Get-M17MetricValue $sameIpBefore "ferrum2_tun_udp_response_queue_full" $true
                $sameIpPayload = [Text.Encoding]::ASCII.GetBytes("m17-adf-same-ip-other-port")
                $sameAddressAlternate.SendTo($sameIpPayload, $relayEndpoint)
                $sameIpMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_packets_egress" $sameIpEgressBefore
                Assert-True ((Get-M17MetricValue $sameIpMetrics "ferrum2_tun_packets_egress") - $sameIpEgressBefore -eq 1 -and
                    (Get-M17MetricValue $sameIpMetrics "ferrum2_tun_udp_response_filtered" $true) -eq $sameIpFilteredBefore -and
                    (Get-M17MetricValue $sameIpMetrics "ferrum2_tun_udp_response_queue_full" $true) -eq $sameIpQueueBefore) "M17 ADF same-IP alternate-port response did not cross the Wintun send boundary exactly once"
                $sameIpPlatformDelivery = Receive-M17UdpIfReady $v4 $targets[0].Address $alternatePort $sameIpPayload
                Add-M17LiveRow "udp-adf-same-ip-alternate-port" ([ordered]@{
                    response_source = "$($targets[0].Address):$alternatePort"
                    wintun_egress_delta = 1
                    response_filtered_delta = 0
                    response_queue_full_delta = 0
                    windows_socket_delivery = $sameIpPlatformDelivery
                    windows_boundary = "delivery is optional because the emulated target address is also owned by guest loopback"
                })
                Add-M17Witness "adf_allows_authorized_ip_any_port" "live-product" "authorized same-IP alternate-port response crossed the live ADF filter and Wintun send boundary; the exact candidate test verifies the emitted source tuple"

                $unauthorizedBefore = Get-Metrics $metricsPort
                $unauthorizedFilteredBefore = Get-M17MetricValue $unauthorizedBefore "ferrum2_tun_udp_response_filtered" $true
                $unauthorizedPayload = [Text.Encoding]::ASCII.GetBytes("m17-adf-unauthorized-ip")
                $probes[1].SendTo($unauthorizedPayload, $relayEndpoint)
                $unauthorizedMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_udp_response_filtered" $unauthorizedFilteredBefore
                Assert-True ((Get-M17MetricValue $unauthorizedMetrics "ferrum2_tun_udp_response_filtered") - $unauthorizedFilteredBefore -eq 1) "M17 ADF unauthorized response was not filtered exactly once"
                Assert-M17UdpQuiet $v4
                Add-M17Witness "adf_rejects_unauthorized_ip" "live-product" "unseen IPv4 peer response was not delivered"
            } else {
                $eifBefore = Get-Metrics $metricsPort
                $eifEgressBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_packets_egress" $true
                $eifFilteredBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_udp_response_filtered" $true
                $eifQueueBefore = Get-M17MetricValue $eifBefore "ferrum2_tun_udp_response_queue_full" $true
                $eifPayload = [Text.Encoding]::ASCII.GetBytes("m17-eif-unseen-ip")
                $probes[1].SendTo($eifPayload, $relayEndpoint)
                $eifMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_packets_egress" $eifEgressBefore
                Assert-True ((Get-M17MetricValue $eifMetrics "ferrum2_tun_packets_egress") - $eifEgressBefore -eq 1 -and
                    (Get-M17MetricValue $eifMetrics "ferrum2_tun_udp_response_filtered" $true) -eq $eifFilteredBefore -and
                    (Get-M17MetricValue $eifMetrics "ferrum2_tun_udp_response_queue_full" $true) -eq $eifQueueBefore) "M17 EIF unseen-peer response did not cross the Wintun send boundary exactly once"
                $eifPlatformDelivery = Receive-M17UdpIfReady $v4 $targets[1].Address $targets[1].Port $eifPayload
                Add-M17LiveRow "udp-eif-unseen-peer" ([ordered]@{
                    response_source = "$($targets[1].Address):$($targets[1].Port)"
                    wintun_egress_delta = 1
                    response_filtered_delta = 0
                    response_queue_full_delta = 0
                    windows_socket_delivery = $eifPlatformDelivery
                    windows_boundary = "delivery is optional because the emulated target address is also owned by guest loopback"
                })
                Add-M17Witness "eif_allows_valid_same_family_peer" "live-product" "unseen same-family response crossed the live EIF filter and Wintun send boundary; the exact candidate test verifies the emitted source tuple"
            }
            if ($filtering -ceq "address_dependent") {
                [uint16]$dnsId = 0x17d1
                [byte[]]$dnsPayload = New-DnsQuery $dnsId
                Assert-M17DnsQueryEnvelope $dnsPayload $dnsId
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $dnsPayload
                Assert-M17DnsQueryEnvelope $probes[0].Received $dnsId

                [byte[]]$quicPayload = New-M17QuicV1InitialEnvelope
                Assert-M17QuicV1InitialEnvelope $quicPayload
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $quicPayload
                Assert-M17QuicV1InitialEnvelope $probes[1].Received

                [byte[]]$stunA = New-M17StunBindingRequest 0x11 $false
                [byte[]]$stunB = New-M17StunBindingRequest 0x31 $false
                Assert-M17StunBindingRequest $stunA $false
                Assert-M17StunBindingRequest $stunB $false
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $stunA
                Assert-M17StunBindingRequest $probes[0].Received $false
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $stunB
                Assert-M17StunBindingRequest $probes[1].Received $false

                [byte[]]$icePayload = New-M17StunBindingRequest 0x51 $true
                Assert-M17StunBindingRequest $icePayload $true
                Invoke-M17UdpEcho $v6 $targets[2].Address $targets[2].Port $icePayload
                Assert-M17StunBindingRequest $probes[2].Received $true

                [byte[]]$gameA = New-M17GamePeerDatagram 1 1001
                [byte[]]$gameB = New-M17GamePeerDatagram 2 1002
                Assert-M17GamePeerDatagram $gameA 1 1001
                Assert-M17GamePeerDatagram $gameB 2 1002
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $gameA
                Assert-M17GamePeerDatagram $probes[0].Received 1 1001
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port $gameB
                Assert-M17GamePeerDatagram $probes[1].Received 2 1002

                [byte[]]$laterRulePayload = New-M17StunBindingRequest 0x71 $false
                Assert-M17StunBindingRequest $laterRulePayload $false
                Invoke-M17UdpEcho $v4 $directTarget.Address $directTarget.Port $laterRulePayload

                Add-M17LiveRow "udp-protocol-interoperability" ([ordered]@{
                    dns = [ordered]@{ bytes = $dnsPayload.Length; sha256 = Get-M17PayloadSha256 $dnsPayload; target = "proxy-ipv4-a" }
                    quic_v1_initial = [ordered]@{ bytes = $quicPayload.Length; sha256 = Get-M17PayloadSha256 $quicPayload; target = "proxy-ipv4-b" }
                    stun_servers = @(
                        [ordered]@{ family = "ipv4"; target = "proxy-ipv4-a"; sha256 = Get-M17PayloadSha256 $stunA },
                        [ordered]@{ family = "ipv4"; target = "proxy-ipv4-b"; sha256 = Get-M17PayloadSha256 $stunB }
                    )
                    webrtc_ice = [ordered]@{ family = "ipv6"; bytes = $icePayload.Length; sha256 = Get-M17PayloadSha256 $icePayload }
                    game_peers = @(
                        [ordered]@{ peer = 1; target = "proxy-ipv4-a"; sequence = 1001; sha256 = Get-M17PayloadSha256 $gameA },
                        [ordered]@{ peer = 2; target = "proxy-ipv4-b"; sequence = 1002; sha256 = Get-M17PayloadSha256 $gameB }
                    )
                    later_rule_target = [ordered]@{
                        family = "ipv4"
                        bytes = $laterRulePayload.Length
                        sha256 = Get-M17PayloadSha256 $laterRulePayload
                        independent_rule_outbound = "direct"
                    }
                })
                Add-M17Witness "dns_udp_payload_round_trips" "live-product" "a parsed DNS A query crossed the TUN and Shadowsocks target unchanged"
                Add-M17Witness "quic_v1_initial_envelope_round_trips" "live-product" "a parsed 1,200-byte QUIC v1 Initial envelope crossed the TUN unchanged"
                Add-M17Witness "stun_binding_requests_reach_multiple_servers" "live-product" "distinct valid STUN Binding requests reached two IPv4 server endpoints from one local socket"
                Add-M17Witness "webrtc_ice_candidate_check_round_trips" "live-product" "an IPv6 ICE Binding request with USERNAME, PRIORITY, ICE-CONTROLLING, valid short-term MESSAGE-INTEGRITY, and FINGERPRINT round-tripped unchanged"
                Add-M17Witness "game_style_binary_datagrams_reach_multiple_peers" "live-product" "sequenced binary datagrams reached two peer endpoints from one local socket"
            } else {
                Invoke-M17UdpEcho $v4 $targets[1].Address $targets[1].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v4-b"))
                Invoke-M17UdpEcho $v6 $targets[2].Address $targets[2].Port ([Text.Encoding]::ASCII.GetBytes("m17-$filtering-v6"))
            }

            $capacityBeforeMetrics = Get-Metrics $metricsPort
            $capacityBefore = Get-M17MetricValue $capacityBeforeMetrics "ferrum2_tun_udp_association_rejected_limit" $true
            $capacityRequestsBefore = $probes[0].Requests
            $capacityClient = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
            try {
                $capacityPayload = [Text.Encoding]::ASCII.GetBytes("m17-$filterLabel-capacity-drop-new")
                [void]$capacityClient.Send($capacityPayload, $capacityPayload.Length, $targets[0].Address, $targets[0].Port)
                Assert-M17UdpQuiet $capacityClient
                $capacityMetrics = Wait-M17MetricIncrease $metricsPort "ferrum2_tun_udp_association_rejected_limit" $capacityBefore
                Assert-True ($probes[0].Requests -eq $capacityRequestsBefore -and
                    (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_associations_active") -eq 2 -and
                    (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_candidates_active") -eq 0) "M17 association capacity did not drop only the new source"
                $livePayload = [Text.Encoding]::ASCII.GetBytes("m17-$filterLabel-capacity-live-source")
                Invoke-M17UdpEcho $v4 $targets[0].Address $targets[0].Port $livePayload
                Assert-True ($probes[0].WaitRequests($capacityRequestsBefore + 1, 5000)) "M17 live association was evicted under capacity pressure"
            } finally { $capacityClient.Dispose() }
            Add-M17LiveRow "udp-$filterLabel-capacity-drop-new" ([ordered]@{
                configured_associations = 2
                active_associations = Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_associations_active"
                provisional_candidates = Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_candidates_active"
                rejected_limit_delta = (Get-M17MetricValue $capacityMetrics "ferrum2_tun_udp_association_rejected_limit") - $capacityBefore
                rejected_target_request_delta = $probes[0].Requests - $capacityRequestsBefore - 1
                existing_association_recovery = "echo-pass"
            })
            if ($filtering -ceq "address_dependent") {
                Add-M17Witness "association_capacity_drops_new_without_evicting_live" "live-product" "the third local source was rejected at capacity two while both live associations and an existing echo remained intact"
            }
        } catch {
            $trafficFailure = $_
            $failureMetrics = try { Get-Metrics $metricsPort 2 } catch { $null }
            $script:m17ServerProcess.Refresh()
            $script:m17LiveRows.Add([ordered]@{
                name = "udp-$filterLabel-failure-diagnostic"
                status = "failure"
                evidence = [ordered]@{
                    message = [string]$trafficFailure.Exception.Message
                    client_ipv4_local = [string]$v4.Client.LocalEndPoint
                    client_ipv4_available_bytes = $(try { [int]$v4.Client.Available } catch { -1 })
                    client_ipv4_readable = $(try { [bool]$v4.Client.Poll(0, [Net.Sockets.SelectMode]::SelectRead) } catch { $false })
                    client_ipv6_local = [string]$v6.Client.LocalEndPoint
                    server_alive = -not $script:m17ServerProcess.HasExited
                    server_udp_owner = @(
                        Get-NetUDPEndpoint -LocalPort $script:m17ServerPort -ErrorAction SilentlyContinue |
                            ForEach-Object { [uint32]$_.OwningProcess }
                    )
                    target_requests = @($probes | ForEach-Object { $_.Requests })
                    target_responses = @($probes | ForEach-Object { $_.Responses })
                    target_faults = @($probes | ForEach-Object { $_.Fault })
                    target_remote_endpoints = @($probes | ForEach-Object { [string]$_.RemoteEndpoint })
                    route_preference = $targetRoutePreference
                    packets_ingress = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_packets_ingress" $true } else { $null }
                    packets_egress = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_packets_egress" $true } else { $null }
                    associations_active = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_associations_active" $true } else { $null }
                    candidates_active = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_candidates_active" $true } else { $null }
                    associations_created = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_association_created" $true } else { $null }
                    association_limit_rejections = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_association_rejected_limit" $true } else { $null }
                    response_filtered = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_response_filtered" $true } else { $null }
                    response_queue_full = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_tun_udp_response_queue_full" $true } else { $null }
                    target_to_client_datagrams = if ($failureMetrics) { Get-M17MetricValue $failureMetrics "ferrum2_udp_datagrams" $true } else { $null }
                }
            })
            throw $trafficFailure
        } finally { $v4.Dispose(); $v6.Dispose() }
        $metrics = Get-Metrics $metricsPort
        Assert-True ((Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active") -eq 2 -and
            (Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active") -eq 0) "M17 EIM association/candidate gauges changed"
        Add-M17LiveRow "udp-$filtering" ([ordered]@{
            ipv4_targets = 3
            first_ordinary_route_outbound = "proxy"
            later_ipv4_target_with_independent_direct_rule = 1
            ipv6_targets = 1
            associations_active = Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active"
            candidates_active = Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active"
            target_requests = @($probes | ForEach-Object { $_.Requests })
            same_address_alternate_port = $alternatePort
            unseen_peer = if ($filtering -ceq "address_dependent") { "dropped" } else { "accepted" }
        })
        if ($filtering -ceq "address_dependent") {
            Add-M17Witness "one_eim_association_for_multiple_targets" "live-product" "one IPv4 local socket reached three targets while associations_active remained one per family"
            Add-M17Witness "ipv4_and_ipv6_sources_form_distinct_associations" "live-product" "IPv4 and IPv6 local sources each completed through one source-keyed association"
        } else {
            $script:m17CounterAfter = Get-M17CounterSnapshot $metrics
        }
        Stop-M17Candidate $script:activeProcess "udp-$filterLabel"
    }
    } finally {
        Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
        Assert-True (-not (Get-NetFirewallRule -Name $script:m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 UDP firewall scope was not removed"
        Add-M17LiveRow "udp-firewall-cleanup" ([ordered]@{
            rule_name = $script:m17UdpFirewallRuleName
            active_store_rules = 0
        })
        Add-M17Witness "udp_firewall_scope_is_journaled_and_removed" "live-platform" "the address-scoped ActiveStore allow rule was durably journaled, removed, and read back absent"
    }
}

function Invoke-M17SchedulerRingFull {
    Enable-M17UdpFirewallAdmission
    Add-M17LiveRow "scheduler-firewall-scope" ([ordered]@{
        policy_store = "ActiveStore"
        direction = "inbound"
        protocol = "udp"
        local_address = "198.18.0.2"
        remote_address = "any"
        local_only_mapping = $true
        program = $script:controllerProgram
        purpose = "prevent Windows stateful endpoint filtering from masking scheduler accounting while remaining controller-process scoped"
    })
    try {
    $target = "192.0.2.241"
    $port = Get-UniqueTcpPort
    $probe = Add-M17LoopbackTarget $target $port
    $script:m17MetricsPort = Get-UniqueTcpPort
    $path = Join-Path $script:work "m17-scheduler-ring-full.toml"
    Write-M17ClientConfig $path @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ring_capacity = 131072
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
udp_filtering = "address_dependent"
ready_timeout_ms = 15000
"@ "proxy" $script:m17MetricsPort
    Assert-M17Config $path "scheduler-ring-full"
    $script:activeProcess = Start-M17Candidate $path "scheduler-ring-full"
    $adapter = Wait-M17AdapterReady $script:adapterName $true $true
    $script:ownedInterfaceIndex = [int]$adapter.ifIndex
    [void](Add-TunRoute $script:ownedInterfaceIndex "$target/32" 500)
    Add-M17LiveRow "scheduler-target-route-preference" ([ordered]@{
        route = Get-M17TargetRoutePreference $script:ownedInterfaceIndex $target
    })
    $state = Wait-M17Session $script:m17MetricsPort 1 1
    $script:m17CounterBefore = Get-M17CounterSnapshot $state.Metrics
    $client = New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex
    try {
        $client.Client.ReceiveBufferSize = 4MB
        $warmupMetricsBefore = Get-Metrics $script:m17MetricsPort
        $warmupIngressBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_ingress"
        $warmupAcceptedBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_accepted"
        $warmupRejectedBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_rejected" $true
        $warmupEgressBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_packets_egress"
        $warmupResetBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_network_reset" $true
        $warmupFullRebuildBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_network_full_rebuild" $true
        $warmupRingBefore = Get-M17MetricValue $warmupMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        Invoke-M17UdpEcho $client $target $port ([Text.Encoding]::ASCII.GetBytes("m17-warmup"))
        $warmupStableSamples = 0
        $warmupDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $ordinaryMetricsBefore = Get-Metrics $script:m17MetricsPort
            $warmupIngressAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_ingress"
            $warmupAcceptedAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_accepted"
            $warmupRejectedAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_rejected" $true
            $warmupEgressAfter = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_egress"
            $warmupIngressDelta = $warmupIngressAfter - $warmupIngressBefore
            $warmupAcceptedDelta = $warmupAcceptedAfter - $warmupAcceptedBefore
            $warmupRejectedDelta = $warmupRejectedAfter - $warmupRejectedBefore
            $warmupEgressDelta = $warmupEgressAfter - $warmupEgressBefore
            Assert-True ($warmupIngressDelta -ge $warmupAcceptedDelta -and
                $warmupAcceptedDelta -le 1 -and $warmupEgressDelta -le 1) "M17 scheduler accepted/egress counter overshoot: phase=warmup expected=1 raw_ingress_delta=$warmupIngressDelta accepted_before=$warmupAcceptedBefore accepted_after=$warmupAcceptedAfter accepted_delta=$warmupAcceptedDelta rejected_delta=$warmupRejectedDelta egress_before=$warmupEgressBefore egress_after=$warmupEgressAfter egress_delta=$warmupEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses)"
            if ($warmupAcceptedDelta -eq 1 -and $warmupEgressDelta -eq 1 -and
                $probe.Requests -eq 1 -and $probe.Responses -eq 1) {
                $warmupStableSamples++
                if ($warmupStableSamples -ge 2) { break }
            } else {
                $warmupStableSamples = 0
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $warmupDeadline)
        Assert-True ($warmupStableSamples -ge 2) "M17 scheduler counters did not stabilize: phase=warmup expected=1 raw_ingress_delta=$warmupIngressDelta accepted_before=$warmupAcceptedBefore accepted_after=$warmupAcceptedAfter accepted_delta=$warmupAcceptedDelta rejected_delta=$warmupRejectedDelta egress_before=$warmupEgressBefore egress_after=$warmupEgressAfter egress_delta=$warmupEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses) generation=$(Get-M17MetricValue $ordinaryMetricsBefore 'ferrum2_tun_session_generation') active=$(Get-M17MetricValue $ordinaryMetricsBefore 'ferrum2_tun_session_active')"
        Assert-True ((Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_reset" $true) -eq $warmupResetBefore -and
            (Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_full_rebuild" $true) -eq $warmupFullRebuildBefore -and
            (Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_wintun_ring_full_dropped") -eq $warmupRingBefore) "M17 scheduler warmup reset/rebuilt the network runtime or filled the Wintun ring"
        Add-M17LiveRow "scheduler-warmup-counter-stability" ([ordered]@{
            stable_samples = $warmupStableSamples
            raw_ingress_delta = $warmupIngressDelta
            accepted_delta = $warmupAcceptedDelta
            rejected_delta = $warmupRejectedDelta
            non_accepted_ingress_delta = $warmupIngressDelta - $warmupAcceptedDelta
            egress_delta = $warmupEgressDelta
            target_requests = $probe.Requests
            target_responses = $probe.Responses
        })
        $ingressBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_ingress"
        $acceptedBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_accepted"
        $rejectedBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_rejected" $true
        $egressBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_packets_egress"
        $networkResetBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_reset" $true
        $fullRebuildBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_network_full_rebuild" $true
        $ringBefore = Get-M17MetricValue $ordinaryMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        $burstSourceCount = 8
        $burstClients = [Collections.Generic.List[Net.Sockets.UdpClient]]::new()
        try {
            foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                $burstClients.Add((New-M17TunUdpClient "198.18.0.2" $script:ownedInterfaceIndex))
            }
            foreach ($burst in @(8, 16, 64)) {
                $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($round in 0..(($burst / $burstSourceCount) - 1)) {
                    foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                        $index = $round * $burstSourceCount + $sourceIndex
                        $text = "m17-$burst-$index"
                        [void]$expected.Add($text)
                        $payload = [Text.Encoding]::ASCII.GetBytes($text)
                        [void]$burstClients[$sourceIndex].Send($payload, $payload.Length, $target, $port)
                    }
                    foreach ($sourceIndex in 0..($burstSourceCount - 1)) {
                        $task = $burstClients[$sourceIndex].ReceiveAsync()
                        Assert-True ($task.Wait(10000) -and -not $task.IsFaulted) "M17 scheduler capacity-aware sequence response timeout: $burst/$round/$sourceIndex"
                        [void]$actual.Add([Text.Encoding]::ASCII.GetString($task.Result.Buffer))
                    }
                }
                Assert-True ($actual.SetEquals($expected)) "M17 scheduler capacity-aware sequence lost or duplicated a packet: $burst"
            }
        } finally {
            foreach ($burstClient in $burstClients) { $burstClient.Dispose() }
        }

        Assert-True ($probe.Requests -eq 89 -and $probe.Responses -eq 89) "M17 scheduler warmup and ordinary target accounting was not exact"
        $ordinaryStableSamples = 0
        $ordinaryDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $ordinaryMetrics = Get-Metrics $script:m17MetricsPort
            $ordinaryIngressAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_ingress"
            $ordinaryAcceptedAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_accepted"
            $ordinaryRejectedAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_rejected" $true
            $ordinaryEgressAfter = Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_packets_egress"
            $ordinaryIngressDelta = $ordinaryIngressAfter - $ingressBefore
            $ordinaryAcceptedDelta = $ordinaryAcceptedAfter - $acceptedBefore
            $ordinaryRejectedDelta = $ordinaryRejectedAfter - $rejectedBefore
            $ordinaryEgressDelta = $ordinaryEgressAfter - $egressBefore
            Assert-True ($ordinaryIngressDelta -ge $ordinaryAcceptedDelta -and
                $ordinaryAcceptedDelta -le 88 -and $ordinaryEgressDelta -le 88) "M17 scheduler accepted/egress counter overshoot: phase=burst expected=88 raw_ingress_delta=$ordinaryIngressDelta accepted_before=$acceptedBefore accepted_after=$ordinaryAcceptedAfter accepted_delta=$ordinaryAcceptedDelta rejected_delta=$ordinaryRejectedDelta egress_before=$egressBefore egress_after=$ordinaryEgressAfter egress_delta=$ordinaryEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses)"
            if ($ordinaryAcceptedDelta -eq 88 -and $ordinaryEgressDelta -eq 88) {
                $ordinaryStableSamples++
                if ($ordinaryStableSamples -ge 2) { break }
            } else {
                $ordinaryStableSamples = 0
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $ordinaryDeadline)
        Assert-True ($ordinaryStableSamples -ge 2) "M17 scheduler counters did not stabilize: phase=burst expected=88 raw_ingress_delta=$ordinaryIngressDelta accepted_before=$acceptedBefore accepted_after=$ordinaryAcceptedAfter accepted_delta=$ordinaryAcceptedDelta rejected_delta=$ordinaryRejectedDelta egress_before=$egressBefore egress_after=$ordinaryEgressAfter egress_delta=$ordinaryEgressDelta probe_requests=$($probe.Requests) probe_responses=$($probe.Responses) network_reset_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_network_reset' $true) - $networkResetBefore) full_rebuild_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_network_full_rebuild' $true) - $fullRebuildBefore) ring_full_delta=$((Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_wintun_ring_full_dropped') - $ringBefore) generation=$(Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_session_generation') active=$(Get-M17MetricValue $ordinaryMetrics 'ferrum2_tun_session_active')"
        Add-M17LiveRow "scheduler-burst-counter-stability" ([ordered]@{
            stable_samples = $ordinaryStableSamples
            raw_ingress_delta = $ordinaryIngressDelta
            accepted_delta = $ordinaryAcceptedDelta
            rejected_delta = $ordinaryRejectedDelta
            non_accepted_ingress_delta = $ordinaryIngressDelta - $ordinaryAcceptedDelta
            egress_delta = $ordinaryEgressDelta
            target_requests = $probe.Requests
            target_responses = $probe.Responses
        })
        Assert-True ((Get-M17MetricValue $ordinaryMetrics "ferrum2_network_reset" $true) -eq $networkResetBefore -and
            (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_full_rebuild" $true) -eq $fullRebuildBefore -and
            (Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_wintun_ring_full_dropped") -eq $ringBefore) "M17 ordinary bursts reset/rebuilt the network runtime or filled the Wintun ring"

        $pressurePackets = 256
        $pressurePayloadBytes = 1200
        $pressureTargetBefore = $probe.Requests
        Assert-True ($pressureTargetBefore -eq 89 -and $probe.Responses -eq 89) "M17 scheduler target accounting changed after counter stabilization"
        $pressureMetricsBefore = $ordinaryMetrics
        $pressureEgressBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_tun_packets_egress"
        $pressureRingBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_tun_wintun_ring_full_dropped"
        $pressureResetBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_network_reset" $true
        $pressureFullRebuildBefore = Get-M17MetricValue $pressureMetricsBefore "ferrum2_network_full_rebuild" $true
        $pressureBatchPackets = 1
        foreach ($batch in 0..(($pressurePackets / $pressureBatchPackets) - 1)) {
            $batchStart = $batch * $pressureBatchPackets
            foreach ($ordinal in $batchStart..($batchStart + $pressureBatchPackets - 1)) {
                $payload = [byte[]]::new($pressurePayloadBytes)
                [BitConverter]::GetBytes([uint32]$ordinal).CopyTo($payload, 0)
                [void]$client.Send($payload, $payload.Length, $target, $port)
            }
            $expectedTargetCount = $pressureTargetBefore + $batchStart + $pressureBatchPackets
            Assert-True ($probe.WaitRequests($expectedTargetCount, 5000)) "M17 pressure target request batch was incomplete"
            Assert-True ($probe.Requests -eq $expectedTargetCount) "M17 pressure target request batch was not exact"
            $responseDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while ($probe.Responses -lt $expectedTargetCount -and [DateTime]::UtcNow -lt $responseDeadline) {
                Start-Sleep -Milliseconds 5
            }
            Assert-True ($probe.Responses -eq $expectedTargetCount) "M17 pressure target response batch was not exact"
        }

        $pressureDeadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            $pressureMetrics = Get-Metrics $script:m17MetricsPort
            $pressureEgressDelta = (Get-M17MetricValue $pressureMetrics "ferrum2_tun_packets_egress") - $pressureEgressBefore
            $pressureRingDelta = (Get-M17MetricValue $pressureMetrics "ferrum2_tun_wintun_ring_full_dropped") - $pressureRingBefore
            if ($pressureEgressDelta + $pressureRingDelta -ge $pressurePackets) { break }
            Start-Sleep -Milliseconds 25
        } while ([DateTime]::UtcNow -lt $pressureDeadline)
        Assert-True ($pressureEgressDelta -ge 0 -and $pressureRingDelta -ge 0 -and
            $pressureEgressDelta + $pressureRingDelta -eq $pressurePackets) "M17 pressure output accounting is not closed"
        Assert-True ((Get-M17MetricValue $pressureMetrics "ferrum2_network_reset" $true) -eq $pressureResetBefore -and
            (Get-M17MetricValue $pressureMetrics "ferrum2_network_full_rebuild" $true) -eq $pressureFullRebuildBefore) "M17 ring pressure reset or rebuilt the network runtime"

        $pressureActual = [Collections.Generic.HashSet[uint32]]::new()
        if ($pressureEgressDelta -gt 0) {
            foreach ($ignored in 1..([int]$pressureEgressDelta)) {
                $task = $client.ReceiveAsync()
                Assert-True ($task.Wait(15000) -and -not $task.IsFaulted) "M17 accounted pressure response did not reach the TUN socket"
                $response = $task.Result
                Assert-True ($response.Buffer.Length -eq $pressurePayloadBytes -and
                    $response.RemoteEndPoint.Address.ToString() -ceq $target -and
                    $response.RemoteEndPoint.Port -eq $port) "M17 pressure response shape or source changed"
                $ordinal = [BitConverter]::ToUInt32($response.Buffer, 0)
                Assert-True ($ordinal -lt $pressurePackets -and $pressureActual.Add($ordinal)) "M17 pressure response was invalid or duplicated"
            }
        }
        Assert-True ($pressureActual.Count -eq [int]$pressureEgressDelta) "M17 pressure delivery count changed"
        $pressureReceiveBufferBytes = $client.Client.ReceiveBufferSize
    } finally { $client.Dispose() }
    Assert-True ($probe.WaitRequests(345, 10000)) "M17 scheduler target did not observe every burst and pressure packet"
    Assert-True ($probe.Requests -eq 345 -and $probe.Responses -eq 345) "M17 scheduler target accounting was not exact"
    Start-Sleep -Milliseconds 100
    $metrics = Get-Metrics $script:m17MetricsPort
    $finalPressureEgressDelta = (Get-M17MetricValue $metrics "ferrum2_tun_packets_egress") - $pressureEgressBefore
    $finalPressureRingDelta = (Get-M17MetricValue $metrics "ferrum2_tun_wintun_ring_full_dropped") - $pressureRingBefore
    Assert-True ($finalPressureEgressDelta -eq $pressureEgressDelta -and
        $finalPressureRingDelta -eq $pressureRingDelta -and
        $finalPressureEgressDelta + $finalPressureRingDelta -eq $pressurePackets) "M17 pressure output accounting did not remain stable after drain"
    Assert-True ((Get-M17MetricValue $metrics "ferrum2_network_reset" $true) -eq $pressureResetBefore -and
        (Get-M17MetricValue $metrics "ferrum2_network_full_rebuild" $true) -eq $pressureFullRebuildBefore) "M17 pressure caused a delayed network reset or full rebuild"
    Add-M17LiveRow "scheduler-egress-pressure" ([ordered]@{
        packets = $pressurePackets
        batch_packets = $pressureBatchPackets
        payload_bytes = $pressurePayloadBytes
        delivered = [int]$finalPressureEgressDelta
        ring_full_dropped = [int]$finalPressureRingDelta
        receive_buffer_bytes = $pressureReceiveBufferBytes
        network_reset_delta = 0
        full_rebuild_delta = 0
    })
    Add-M17Witness "live_egress_pressure_has_closed_accounting" "live-product" "256 1200-byte responses were exactly partitioned into delivered and explicit ring-full outcomes without a network reset or full rebuild"
    Add-M17LiveRow "scheduler-bursts" ([ordered]@{
        sequence_packets = @(8, 16, 64)
        batch_packets = $burstSourceCount
        sources = $burstSourceCount
        packets = 88
        ingress_delta = $ordinaryAcceptedDelta
        raw_ingress_delta = $ordinaryIngressDelta
        rejected_delta = $ordinaryRejectedDelta
        non_accepted_ingress_delta = $ordinaryIngressDelta - $ordinaryAcceptedDelta
        egress_delta = $ordinaryEgressAfter - $egressBefore
        target_requests = $pressureTargetBefore
        network_reset_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_reset" $true) - $networkResetBefore
        full_rebuild_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_network_full_rebuild" $true) - $fullRebuildBefore
        live_ring_full_delta = (Get-M17MetricValue $ordinaryMetrics "ferrum2_tun_wintun_ring_full_dropped") - $ringBefore
    })
    $script:m17CounterAfter = Get-M17CounterSnapshot $metrics
    Stop-M17Candidate $script:activeProcess "scheduler-ring-full"
    } finally {
        Restore-M17NetworkMutationJournal $script:work $script:m17NetworkMutationJournal
        Assert-True (-not (Get-NetFirewallRule -Name $script:m17UdpFirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) "M17 scheduler firewall scope was not removed"
        Add-M17LiveRow "scheduler-firewall-cleanup" ([ordered]@{
            rule_name = $script:m17UdpFirewallRuleName
            active_store_rules = 0
        })
    }
}

function Invoke-M17Qualification([string]$SourceDll) {
    Assert-True (-not (Test-Path -LiteralPath $script:siblingDll)) "M17 sibling DLL baseline not absent"
    Write-OwnedSiblingDllIntent
    Copy-Item -LiteralPath $SourceDll -Destination $script:siblingDll
    $script:createdSiblingDll = $true
    Assert-True ((Get-FileHash -LiteralPath $script:siblingDll -Algorithm SHA256).Hash -eq $script:expectedDllHash) "M17 sibling DLL identity changed"
    Start-M17Server
    switch ($script:Mode) {
        "network-reset" { Invoke-M17NetworkReset }
        "restart-stress" { Invoke-M17RestartStress }
        "fragments" { Invoke-M17Fragments }
        "dual-stack-dns" { Invoke-M17DualStackDns }
        "udp-policy" { Invoke-M17UdpPolicy }
        "scheduler-ring-full" { Invoke-M17SchedulerRingFull }
        default { throw "M17 live dispatch received an invalid mode" }
    }
    Invoke-M17CandidateTests
    $actualWitnesses = @($script:m17WitnessRows.Keys | Sort-Object)
    $expectedWitnesses = @($script:m17Contract.witnesses | Sort-Object)
    Assert-True (($actualWitnesses -join "`n") -ceq ($expectedWitnesses -join "`n")) "M17 witness set is incomplete"
}

function Complete-M17Artifact([bool]$Succeeded, [object]$PrimaryFailure, [object]$CleanupFailure) {
    if (-not $script:m17ArtifactInitialized) { return }
    $script:m17FinishedUtc = [DateTime]::UtcNow.ToString("o")
    $failure = if ($PrimaryFailure) { $PrimaryFailure } else { $CleanupFailure }
    $failureRecord = if ($failure) {
        $message = [string]$failure.Exception.Message
        if ($message.Length -gt 2048) { $message = $message.Substring(0, 2048) }
        [ordered]@{ type = $failure.Exception.GetType().FullName; message = $message }
    } else { $null }
    $cleanupProcesses = @(Get-ExactRunProcesses -WorkPath $script:work).Count
    $cleanupAdapters = @(Get-NetAdapter -Name $script:adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
    $cleanupSibling = if (Test-Path -LiteralPath $script:siblingDll) { 1 } else { 0 }
    $cleanupWork = if (Test-Path -LiteralPath $script:work) { 1 } else { 0 }
    $cleanupPassed = -not $CleanupFailure -and $cleanupProcesses -eq 0 -and $cleanupAdapters -eq 0 -and
        $cleanupSibling -eq 0 -and $cleanupWork -eq 0
    $cleanup = [ordered]@{
        status = if ($cleanupPassed) { "pass" } else { "fail" }
        processes = $cleanupProcesses
        adapters = $cleanupAdapters
        sibling_dll = $cleanupSibling
        work_directory = $cleanupWork
        cleanup_failure_type = if ($CleanupFailure) { $CleanupFailure.Exception.GetType().FullName } else { $null }
    }
    if ($Succeeded) {
        Assert-True $cleanupPassed "M17 cleanup evidence is not absent"
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.m17-result.v1"
        status = if ($Succeeded) { "pass" } else { "fail" }
        mode = $script:Mode
        run_token = $script:runIdentity
        network_reset_cycles = if ($script:Mode -eq "network-reset") { $script:NetworkResetCycles } else { $null }
        restart_cycles = if ($script:Mode -eq "restart-stress") { $script:RestartCycles } else { $null }
        approved_vm_name = $script:expectedHyperVVmName
        approved_vm_id = $script:expectedHyperVVmId
        approved_checkpoint_name = $script:expectedHyperVCheckpointName
        approved_checkpoint_id = $script:expectedHyperVCheckpointId
        guest_build = [string]$script:capabilityIdentity.Ledger.guest_build
        identity_sha256 = $script:capabilityIdentityHash
        candidate_sha = [string]$script:capabilityIdentity.Ledger.candidate_sha
        client_sha256 = [string]$script:capabilityIdentity.Ledger.client_sha256
        server_sha256 = [string]$script:capabilityIdentity.Ledger.server_sha256
        controller_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        wintun_zip_sha256 = $script:expectedZipHash.ToLowerInvariant()
        wintun_dll_sha256 = $script:expectedDllHash.ToLowerInvariant()
        test_binaries = if ($script:capabilityIdentity.Ledger.PSObject.Properties.Name -ccontains "test_binaries") {
            $script:capabilityIdentity.Ledger.test_binaries
        } else { $null }
        started_utc = $script:m17StartedUtc
        finished_utc = $script:m17FinishedUtc
        fixtures = $script:m17FixtureRows
        processes = @($script:m17ProcessRows)
        live_checks = @($script:m17LiveRows)
        deterministic_tests = @($script:m17TestRows)
        witnesses = @($script:m17WitnessRows.Values)
        counters_before = $script:m17CounterBefore
        counters_after = $script:m17CounterAfter
        cleanup = $cleanup
        failure = $failureRecord
    }
    $artifact = Join-Path $script:m17ArtifactRoot "m17-result.json"
    [IO.File]::WriteAllText($artifact, (($document | ConvertTo-Json -Depth 12) + "`n"), [Text.UTF8Encoding]::new($false))
    Assert-True ((Get-Item -LiteralPath $artifact).Length -le 1048576) "M17 result artifact exceeded the 1 MiB cap"
}

try {
    Initialize-Tcp08Artifacts
    Assert-True (-not (Test-Path -LiteralPath $work)) "run work baseline not absent"
    Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) "run process baseline not absent"
    Assert-True (-not (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)) "run adapter baseline not absent"
    if ($Mode -in $m17Modes) {
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

    if ($Mode -notin (@("network-feasibility", "managed-product", "full", "hard-kill") + $m17Modes)) {
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
    if ($Mode -in (@("tcp", "tcp08", "udp", "performance") + $m17Modes)) {
        Assert-True (Test-Path -LiteralPath $serverBinary) "candidate server binary is missing after selection/build"
    }
    if ($tcp08Enabled) { Write-Tcp08BinaryEvidence $sourceDll }
    if ($Mode -in $m17Modes) {
        [void](Invoke-M17ContractPreflight)
        Invoke-M17Qualification $sourceDll
    }
    if ($Mode -eq "managed-product") {
        Assert-PktMonAbsent
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        $systemRouteBaseline = @(Get-Ipv4SystemRouteSnapshot)
        $physicalDefault = Get-Ipv4DefaultUnderlay
        Write-CapabilityEvidence "before" ([ordered]@{
            candidate_sha = $capabilityIdentity.Ledger.candidate_sha
            probe_sha256 = $capabilityIdentity.Ledger.probe_sha256
            identity_sha256 = $capabilityIdentityHash
            guest_build = $capabilityIdentity.GuestBuild
            physical_defaults = 1
            physical_dns_rows = $physicalDnsBaseline.Count
            ferrum2_processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            ferrum2_adapters = 0
        })

        $proxySocksPort = Get-UniqueTcpPort
        $directSocksPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        $autoMetricsPort = Get-UniqueTcpPort
        $manualMetricsPort = Get-UniqueTcpPort
        @"
schema_version = 2
[[inbounds]]
tag = "proxy-socks"
listen = "127.0.0.1:$proxySocksPort"
[[inbounds]]
tag = "direct-socks"
listen = "127.0.0.1:$directSocksPort"
[tun]
tag = "tun-in"
adapter_name = "$managedAutoAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "proxy-tcp"
server = "${supportAddress}:$supportTcpPort"
[[outbounds]]
tag = "proxy-udp"
server = "${supportAddress}:$supportUdpPort"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "direct"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$supportAddress"
port = $supportTcpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$supportAddress"
port = $supportUdpPort
action = "reject"
[[route.rules]]
inbound = "proxy-socks"
network = "tcp"
action = "route"
outbound = "proxy-tcp"
[[route.rules]]
inbound = "proxy-socks"
network = "udp"
action = "route"
outbound = "proxy-udp"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-product"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "dns-udp"
transport = "udp"
address = "${supportAddress}:$supportUdpPort"
[[dns.servers]]
tag = "dns-tcp"
transport = "tcp"
address = "${supportAddress}:$supportTcpPort"
detour = "direct"
[dns.route]
final = "dns-udp"
[[dns.route.rules]]
inbound = "dns-product"
network = "tcp"
server = "dns-tcp"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$autoMetricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $managedAutoConfig -Encoding utf8NoBOM

        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$managedManualAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = false
outbound = "direct"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "direct"
type = "direct"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$manualMetricsPort"
"@ | Set-Content -LiteralPath $managedManualConfig -Encoding utf8NoBOM

        foreach ($managedConfig in @($managedAutoConfig, $managedManualConfig)) {
            $offlineOutput = @(& $binary --config $managedConfig --check-config 2>&1)
            Assert-True ($LASTEXITCODE -eq 0) "managed product config validation failed"
            Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed product config marker mismatch"
        }
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $managedAutoAdapterName $null
        Assert-InterfaceGone $managedManualAdapterName $null
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true

        $activeProcess = Start-Candidate $binary $managedAutoConfig
        $adapter = Wait-AdapterReady $managedAutoAdapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $autoMetricsPort)
        $autoAddressSnapshot = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
        Assert-True ($autoAddressSnapshot -contains "IPv4|198.18.0.2|30|Preferred" -and
            $autoAddressSnapshot -contains "IPv6|fd00::2|126|Preferred") "managed product address baseline mismatch"
        $autoMetricBaseline = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        $productRoutes = @(
            Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
        )
        Assert-True ($productRoutes.Count -eq 2) "managed product capture route count mismatch"
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $row = @($productRoutes | Where-Object { $_.DestinationPrefix -ceq $prefix })
            Assert-True ($row.Count -eq 1 -and $row[0].NextHop -ceq "0.0.0.0" -and
                [uint32]$row[0].RouteMetric -eq 1) "managed product capture route readback mismatch"
        }
        $productRouteSnapshot = @($productRoutes | Sort-Object DestinationPrefix |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)" })
        $managedRouteRows = 2

        $pktmonComponentId = Get-PktMonComponentId $adapter
        $pktmonTcpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16ProductTcp", "-i", $supportAddress, "-t", "TCP", "-p", [string]$supportTcpPort))
        $pktmonUdpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16ProductUdp", "-i", $supportAddress, "-t", "UDP", "-p", [string]$supportUdpPort))
        $pktmonStartAttempted = $true
        [void](Invoke-PktMon @("start", "--capture", "--counters-only", "--comp", [string]$pktmonComponentId, "--type", "flow"))
        $pktmonStarted = $true
        $pktmonStartAttempted = $false
        [void](Get-PktMonFlowPackets)

        $filteredBefore = Get-PktMonFlowPackets
        Invoke-UnpinnedTcpCapture $supportAddress $supportTcpPort $autoMetricsPort ([Text.Encoding]::ASCII.GetBytes("m16-product-unpinned-tcp"))
        $managedFilteredPackets.unpinned_tcp = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
        $managedUnpinnedRows++
        $filteredBefore = Get-PktMonFlowPackets
        Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $autoMetricsPort ([Text.Encoding]::ASCII.GetBytes("m16-product-unpinned-udp"))
        $managedFilteredPackets.unpinned_udp = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
        $managedUnpinnedRows++

        $managedFilteredPackets.proxy_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksTcp $proxySocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-proxy-tcp")) $false
        } "managed proxy TCP entered Wintun"
        $managedFixedTcpRows++
        $managedFilteredPackets.proxy_udp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksUdp $proxySocksPort $supportAddress $supportUdpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-proxy-udp")) $false
        } "managed proxy UDP entered Wintun"
        $managedFixedUdpRows++
        $managedFilteredPackets.direct_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksTcp $directSocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-direct-tcp")) $true
        } "managed direct TCP entered Wintun"
        $managedDynamicTcpRows++
        $managedFilteredPackets.direct_udp = Invoke-ProductPinnedRow {
            Invoke-ProductSocksUdp $directSocksPort $supportAddress $supportUdpPort ([Text.Encoding]::ASCII.GetBytes("m16-product-direct-udp")) $true
        } "managed direct UDP entered Wintun"
        $managedDynamicUdpRows++
        $managedFilteredPackets.dns_tcp = Invoke-ProductPinnedRow {
            Invoke-ProductDns $dnsInboundPort $true (New-DnsQuery 0x1601)
        } "managed DNS TCP entered Wintun"
        $managedFixedTcpRows++
        $managedFilteredPackets.dns_udp = Invoke-ProductPinnedRow {
            Invoke-ProductDns $dnsInboundPort $false (New-DnsQuery 0x1602)
        } "managed DNS UDP entered Wintun"
        $managedFixedUdpRows++
        $activeProcess.Refresh()
        Assert-True (-not $activeProcess.HasExited) "managed auto-route candidate exited during product rows"

        $activeMetric = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Assert-True ([string]$activeMetric.AutomaticMetric -eq [string]$autoMetricBaseline.AutomaticMetric -and
            [uint32]$activeMetric.InterfaceMetric -eq [uint32]$autoMetricBaseline.InterfaceMetric) "managed product interface metric changed"
        $activeProductRoutes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
            Sort-Object DestinationPrefix |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)" })
        Assert-SnapshotEqual $productRouteSnapshot $activeProductRoutes "managed product capture ownership"
        $managedInterfaceMetric = "unchanged"
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "managed product physical DNS sentinel"
        Write-CapabilityEvidence "auto-active" ([ordered]@{
            route_rows = $managedRouteRows
            interface_metric = $managedInterfaceMetric
            fixed_tcp_rows = $managedFixedTcpRows
            fixed_udp_rows = $managedFixedUdpRows
            dynamic_tcp_rows = $managedDynamicTcpRows
            dynamic_udp_rows = $managedDynamicUdpRows
            unpinned_rows = $managedUnpinnedRows
            pktmon_filtered_flow_packets = $managedFilteredPackets
        })

        Stop-CapabilityPktMon
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $managedAutoAdapterName
        Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "managed auto-route process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed auto-route DNS residue"
        Wait-Ipv4SystemRouteSnapshot $systemRouteBaseline
        Write-CapabilityEvidence "auto-cleanup" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
        })

        $adapterName = $managedManualAdapterName
        $activeProcess = Start-Candidate $binary $managedManualConfig
        $adapter = Wait-AdapterReady $managedManualAdapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        $manualInterfaceIndex = $ownedInterfaceIndex
        [void](Get-Metrics $manualMetricsPort)
        $manualRouteBaseline = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        Assert-True (@($manualRouteBaseline | Where-Object { $_ -in @("IPv4|0.0.0.0/1|0.0.0.0", "IPv4|128.0.0.0/1|0.0.0.0") }).Count -eq 0) "manual product capture baseline changed"
        $manualMetricBaseline = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        [void](Add-TunRoute $manualInterfaceIndex "0.0.0.0/1" 1)
        [void](Add-TunRoute $manualInterfaceIndex "128.0.0.0/1" 1)
        $manualCaptureRoutes = @(
            Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
        )
        Assert-True ($manualCaptureRoutes.Count -eq 2) "manual capture route readback mismatch"
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $row = @($manualCaptureRoutes | Where-Object { $_.DestinationPrefix -ceq $prefix })
            Assert-True ($row.Count -eq 1 -and $row[0].NextHop -ceq "0.0.0.0" -and
                [uint32]$row[0].RouteMetric -eq 1) "manual capture route readback mismatch"
        }
        Invoke-TunProductTcp $supportAddress $supportTcpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-product-manual-tcp"))
        $managedManualTcpRows++
        Invoke-TunProductUdp $supportAddress $supportUdpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-product-manual-udp"))
        $managedManualUdpRows++
        $manualMetric = Get-NetIPInterface -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
        Assert-True ([string]$manualMetric.AutomaticMetric -eq [string]$manualMetricBaseline.AutomaticMetric -and
            [uint32]$manualMetric.InterfaceMetric -eq [uint32]$manualMetricBaseline.InterfaceMetric) "manual product interface metric changed"
        Write-CapabilityEvidence "manual-active" ([ordered]@{
            controller_capture_rows = $manualCaptureRoutes.Count
            manual_tcp_rows = $managedManualTcpRows
            manual_udp_rows = $managedManualUdpRows
            interface_metric = "unchanged"
        })
        foreach ($route in @($ownedRoutes)) { Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop }
        $ownedRoutes.Clear()
        Assert-True (@(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }).Count -eq 0) "manual capture route residue"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $managedManualAdapterName
        Assert-InterfaceGone $managedManualAdapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "managed manual process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed manual DNS residue"
        Wait-Ipv4SystemRouteSnapshot $systemRouteBaseline
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot 0) "managed product final physical DNS sentinel"
        Assert-PktMonAbsent

        Remove-OwnedSiblingDll $runJournalIdentity
        Assert-NotReparsePoint $work "controller work directory"
        Remove-Item -LiteralPath $work -Recurse -Force
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed product sibling DLL residue"
        Assert-True (-not (Test-Path -LiteralPath $work)) "managed product work residue"
        Assert-True (-not (Get-NetAdapter -Name $managedAutoAdapterName -IncludeHidden -ErrorAction SilentlyContinue) -and
            -not (Get-NetAdapter -Name $managedManualAdapterName -IncludeHidden -ErrorAction SilentlyContinue)) "managed product adapter residue"
        Write-CapabilityEvidence "after" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = 0
            work = 0
            sibling_dll = 0
            pktmon = "absent"
            physical_dns_rows = @(Get-PhysicalDnsSnapshot 0).Count
        })
    }
    if ($Mode -in @("full", "hard-kill")) {
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $directSocksPort = Get-UniqueTcpPort
        $proxySocksPort = Get-UniqueTcpPort
        $managedMetricsPort = Get-UniqueTcpPort
        $managedDnsPort = Get-UniqueTcpPort
        $managedDnsInboundPort = Get-UniqueTcpPort
        $physicalDefault = Get-Ipv4DefaultUnderlay
        $managedDnsAddress = [string]$physicalDefault.Sources[0].IPAddress
        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        $systemRouteBaseline = @(Get-Ipv4SystemRouteSnapshot)
        $physicalInterfaceBaseline = Get-NetAdapter -InterfaceIndex $physicalDefault.InterfaceIndex -IncludeHidden -ErrorAction Stop
        Assert-True ([uint64]$physicalInterfaceBaseline.NetLuid -ne 0 -and
            [uint32]$physicalInterfaceBaseline.InterfaceAdminStatus -eq 1 -and
            [uint32]$physicalInterfaceBaseline.InterfaceOperationalStatus -eq 1 -and
            [uint32]$physicalInterfaceBaseline.MediaConnectState -eq 1 -and
            [bool]$physicalInterfaceBaseline.HardwareInterface) "eligible physical interface baseline mismatch"
        $physicalFixedRouteDestinations = @(@($supportAddress, $managedDnsAddress) | Sort-Object -Unique)
        $physicalFixedRouteBaseline = @(
            $physicalFixedRouteDestinations | ForEach-Object {
                $route = [Ferrum2NetworkFeasibility]::GetFixedRoute($_)
                Assert-True ($route.InterfaceLuid -eq $physicalInterfaceBaseline.NetLuid -and
                    $route.InterfaceIndex -eq $physicalDefault.InterfaceIndex -and
                    @($physicalDefault.Sources | Where-Object { $_.IPAddress -ceq $route.SourceAddress }).Count -eq 1) "fixed physical underlay baseline mismatch"
                "$_|$($route.InterfaceLuid)|$($route.InterfaceIndex)|$($route.DestinationPrefix)|$($route.PrefixLength)|$($route.NextHop)|$($route.RouteMetric)|$($route.SourceAddress)"
            }
        )
        $physicalUnderlayBaseline = [pscustomobject]@{
            InterfaceIndex = [uint32]$physicalDefault.InterfaceIndex
            SourceAddress = $managedDnsAddress
            Gateway = [string]$physicalDefault.Row.Route.NextHop
            RouteMetric = [uint32]$physicalDefault.Row.Route.RouteMetric
            InterfaceMetric = [uint32]$physicalDefault.Row.Interface.InterfaceMetric
            AutomaticMetric = $physicalDefault.Row.Interface.AutomaticMetric
            SkipAsSource = [bool]$physicalDefault.Sources[0].SkipAsSource
        }

        @"
schema_version = 2
[[inbounds]]
tag = "direct-socks"
listen = "127.0.0.1:$directSocksPort"
[[inbounds]]
tag = "proxy-socks"
listen = "127.0.0.1:$proxySocksPort"
[tun]
tag = "tun-in"
adapter_name = "$managedAutoAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
server = "${supportAddress}:$supportTcpPort"
[route]
final = "direct"
[[route.rules]]
inbound = "proxy-socks"
network = "tcp"
action = "route"
outbound = "proxy"
[[route.rules]]
inbound = "proxy-socks"
network = "udp"
action = "route"
outbound = "proxy"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
timeout_ms = 1000
max_inflight = 8
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:$managedDnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "${managedDnsAddress}:$managedDnsPort"
detour = "direct"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$managedMetricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $managedLifecycleConfig -Encoding utf8NoBOM

        @"
schema_version = 2
[[inbounds]]
tag = "direct-socks"
listen = "127.0.0.1:$directSocksPort"
[tun]
tag = "tun-in"
adapter_name = "$managedAutoAdapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "direct"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
action = "reject"
[udp]
enabled = true
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$managedMetricsPort"
"@ | Set-Content -LiteralPath $managedRouteOnlyConfig -Encoding utf8NoBOM

        $managedLifecycleTemplate = Get-Content -LiteralPath $managedLifecycleConfig -Raw
        $managedRouteOnlyTemplate = Get-Content -LiteralPath $managedRouteOnlyConfig -Raw

        foreach ($managedConfig in @($managedLifecycleConfig, $managedRouteOnlyConfig)) {
            $offlineOutput = @(& $binary --config $managedConfig --check-config 2>&1)
            Assert-True ($LASTEXITCODE -eq 0) "managed lifecycle config validation failed"
            Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed lifecycle config marker mismatch"
        }
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed lifecycle sibling DLL baseline not absent"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        $dnsResponder = [Ferrum2DnsResponder]::new($managedDnsAddress, $managedDnsPort)
        $tcpResources.Add($dnsResponder)

        if ($Mode -eq "full") {
            $activeProcess = Start-Candidate $binary $managedLifecycleConfig
            $adapter = Wait-AdapterReady $managedAutoAdapterName 20 $true $true
            $ownedInterfaceIndex = [int]$adapter.ifIndex
            [void](Get-Metrics $managedMetricsPort)
            Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "managed full DNS steering"
            $capture = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") })
            Assert-True ($capture.Count -eq 2) "managed full capture route count mismatch"
            Invoke-TunProductTcp $supportAddress $supportTcpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-full-direct-tcp"))
            $managedDirectTcpRows = 1
            Invoke-TunProductUdp $supportAddress $supportUdpPort $ownedInterfaceIndex ([Text.Encoding]::ASCII.GetBytes("m16-full-direct-udp"))
            $managedDirectUdpRows = 1
            Invoke-SystemDnsWitness "m16-$runIdentity-udp.tun.test" $false
            $managedSystemDnsRows++
            Invoke-SystemDnsWitness "m16-$runIdentity-tcp.tun.test" $true
            $managedSystemDnsRows++
            Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "managed full physical DNS sentinel"
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $managedAutoAdapterName
            Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
            Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed full graceful DNS residue"

            Invoke-AdapterCycles $binary $managedRouteOnlyConfig $managedAutoAdapterName $managedMetricsPort $true $directSocksPort

            foreach ($change in @("route", "interface", "address")) {
                $physicalDefault = Get-Ipv4DefaultUnderlay
                $physicalRoute = $physicalDefault.Row.Route
                $physicalAdapter = Get-NetAdapter -InterfaceIndex $physicalDefault.InterfaceIndex -IncludeHidden -ErrorAction Stop
                $sourceAddress = [string]$physicalDefault.Sources[0].IPAddress
                $sourceRow = Get-NetIPAddress -InterfaceIndex $physicalDefault.InterfaceIndex -AddressFamily IPv4 -IPAddress $sourceAddress -ErrorAction Stop
                $routeMetric = [uint32]$physicalRoute.RouteMetric
                $skipAsSource = [bool]$sourceRow.SkipAsSource
                $changeConfiguration = Join-Path $work "client-managed-network-change-$change.toml"
                $changeDirectSocksPort = Get-UniqueTcpPort
                $changeProxySocksPort = Get-UniqueTcpPort
                $changeDnsInboundPort = Get-UniqueTcpPort
                $changeMetricsPort = Get-UniqueTcpPort
                $changeConfigText = $managedLifecycleTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$changeDirectSocksPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$proxySocksPort", "127.0.0.1:$changeProxySocksPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$managedDnsInboundPort", "127.0.0.1:$changeDnsInboundPort")
                $changeConfigText = $changeConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$changeMetricsPort")
                try {
                    Assert-True (-not (Test-Path -LiteralPath $changeConfiguration)) "managed network-change generated config baseline not absent"
                    Assert-True (-not $changeConfigText.Contains("127.0.0.1:$directSocksPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$proxySocksPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$managedDnsInboundPort") -and
                        -not $changeConfigText.Contains("127.0.0.1:$managedMetricsPort")) "managed network-change listener generation mismatch"
                    Set-Content -LiteralPath $changeConfiguration -Value $changeConfigText -Encoding utf8NoBOM -NoNewline
                    $offlineOutput = @(& $binary --config $changeConfiguration --check-config 2>&1)
                    Assert-True ($LASTEXITCODE -eq 0) "managed network-change generated config validation failed"
                    Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed network-change generated config marker mismatch"

                    $activeProcess = Start-Candidate $binary $changeConfiguration
                    $adapter = Wait-AdapterReady $managedAutoAdapterName 20 $true $true
                    $ownedInterfaceIndex = [int]$adapter.ifIndex
                    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "network-change DNS active"
                    try {
                        if ($change -eq "route") {
                            Set-NetRoute -InputObject $physicalRoute -RouteMetric ($routeMetric + 1) -ErrorAction Stop
                        } elseif ($change -eq "interface") {
                            Disable-NetAdapter -InputObject $physicalAdapter -Confirm:$false -ErrorAction Stop
                        } else {
                            Set-NetIPAddress -InputObject $sourceRow -SkipAsSource (-not $skipAsSource) -ErrorAction Stop
                        }

                        $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(20)
                        do {
                            $captureRemaining = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }).Count
                            $dnsRemaining = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
                            if ($captureRemaining -eq 0 -and $dnsRemaining -eq 0) { break }
                            Start-Sleep -Milliseconds 50
                        } while ([DateTime]::UtcNow -lt $cleanupDeadline)
                        Assert-True ($captureRemaining -eq 0 -and $dnsRemaining -eq 0) "$change change did not remove capture and DNS"

                        $admissionRejected = $activeProcess.HasExited
                        if (-not $admissionRejected) {
                            try {
                                $probe = Open-ProductSocks $changeDirectSocksPort
                                try {
                                    $request = New-SocksRequest 1 $supportAddress $supportTcpPort
                                    $probe.Stream.Write($request, 0, $request.Length)
                                    $reply = Read-SocksReply $probe.Stream
                                    $admissionRejected = $reply.Reply -ne 0
                                } finally { $probe.Client.Dispose() }
                            } catch { $admissionRejected = $true }
                        }
                        Assert-True $admissionRejected "$change change admitted a new socket"
                        Assert-True (Wait-ProcessExit $activeProcess 20) "$change change did not terminate the candidate"
                        Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id) -ne 0) "$change change candidate exited cleanly"
                        [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
                        $activeProcess = $null
                        Wait-AdapterAbsent $managedAutoAdapterName
                        Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
                        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "$change change process residue"
                        $managedNetworkChangeRows++
                        if ($change -eq "route") { $managedRouteChangeRows++ }
                        elseif ($change -eq "interface") { $managedInterfaceChangeRows++ }
                        else { $managedAddressChangeRows++ }
                        Write-CapabilityEvidence "network-change-$change" ([ordered]@{
                            callback = "observed"
                            admission = "rejected"
                            capture = "absent"
                            dns = "absent"
                            supervised_termination = "complete"
                            residue = "absent"
                        })
                    } finally {
                        if ($change -eq "route") {
                            $changedRoute = Get-NetRoute -InterfaceIndex $physicalDefault.InterfaceIndex `
                                -DestinationPrefix $physicalRoute.DestinationPrefix -PolicyStore ActiveStore -ErrorAction Stop |
                                Where-Object { $_.NextHop -ceq $physicalRoute.NextHop }
                            Assert-True (@($changedRoute).Count -eq 1) "physical route restore identity mismatch"
                            Set-NetRoute -InputObject $changedRoute -RouteMetric $routeMetric -ErrorAction Stop
                        } elseif ($change -eq "interface") {
                            Enable-NetAdapter -Name $physicalAdapter.Name -Confirm:$false -ErrorAction Stop
                        } else {
                            Set-NetIPAddress -InterfaceIndex $physicalDefault.InterfaceIndex -IPAddress $sourceAddress `
                                -SkipAsSource $skipAsSource -ErrorAction Stop
                        }

                        $stableDeadline = [DateTime]::UtcNow.AddSeconds(20)
                        $stableSamples = 0
                        do {
                            $baselineMatches = $false
                            try {
                                $currentSystemRoutes = @(Get-Ipv4SystemRouteSnapshot)
                                $currentPhysicalDns = @(Get-PhysicalDnsSnapshot 0)
                                $currentUnderlay = Get-Ipv4DefaultUnderlay
                                $currentPhysicalAdapter = Get-NetAdapter -InterfaceIndex $currentUnderlay.InterfaceIndex -IncludeHidden -ErrorAction Stop
                                $currentFixedRoutes = @(
                                    $physicalFixedRouteDestinations | ForEach-Object {
                                        $route = [Ferrum2NetworkFeasibility]::GetFixedRoute($_)
                                        "$_|$($route.InterfaceLuid)|$($route.InterfaceIndex)|$($route.DestinationPrefix)|$($route.PrefixLength)|$($route.NextHop)|$($route.RouteMetric)|$($route.SourceAddress)"
                                    }
                                )
                                $currentPreferredSource = @($currentUnderlay.Sources | Where-Object {
                                    $_.IPAddress -ceq $physicalUnderlayBaseline.SourceAddress
                                })
                                $currentSourceRows = @(Get-NetIPAddress -InterfaceIndex $currentUnderlay.InterfaceIndex `
                                    -AddressFamily IPv4 -IPAddress $physicalUnderlayBaseline.SourceAddress -ErrorAction Stop)
                                $currentSourceRow = if ($currentSourceRows.Count -eq 1) { $currentSourceRows[0] } else { $null }
                                $baselineMatches =
                                    @(Compare-Object -ReferenceObject @($systemRouteBaseline) -DifferenceObject $currentSystemRoutes).Count -eq 0 -and
                                    @(Compare-Object -ReferenceObject @($physicalDnsBaseline) -DifferenceObject $currentPhysicalDns).Count -eq 0 -and
                                    @(Compare-Object -ReferenceObject @($physicalFixedRouteBaseline) -DifferenceObject $currentFixedRoutes).Count -eq 0 -and
                                    $currentUnderlay.InterfaceIndex -eq $physicalUnderlayBaseline.InterfaceIndex -and
                                    $currentPhysicalAdapter.NetLuid -eq $physicalInterfaceBaseline.NetLuid -and
                                    [uint32]$currentPhysicalAdapter.InterfaceAdminStatus -eq [uint32]$physicalInterfaceBaseline.InterfaceAdminStatus -and
                                    [uint32]$currentPhysicalAdapter.InterfaceOperationalStatus -eq [uint32]$physicalInterfaceBaseline.InterfaceOperationalStatus -and
                                    [uint32]$currentPhysicalAdapter.MediaConnectState -eq [uint32]$physicalInterfaceBaseline.MediaConnectState -and
                                    $currentPhysicalAdapter.HardwareInterface -eq $physicalInterfaceBaseline.HardwareInterface -and
                                    $currentPreferredSource.Count -eq 1 -and
                                    $null -ne $currentSourceRow -and
                                    $currentUnderlay.Row.Route.NextHop -ceq $physicalUnderlayBaseline.Gateway -and
                                    $currentUnderlay.Row.Route.RouteMetric -eq $physicalUnderlayBaseline.RouteMetric -and
                                    $currentUnderlay.Row.Interface.InterfaceMetric -eq $physicalUnderlayBaseline.InterfaceMetric -and
                                    $currentUnderlay.Row.Interface.AutomaticMetric -eq $physicalUnderlayBaseline.AutomaticMetric -and
                                    $currentSourceRow.SkipAsSource -eq $physicalUnderlayBaseline.SkipAsSource
                            } catch { $baselineMatches = $false }
                            if ($baselineMatches) { $stableSamples++ }
                            else { $stableSamples = 0 }
                            if ($stableSamples -ge 11) { break }
                            Start-Sleep -Milliseconds 500
                        } while ([DateTime]::UtcNow -lt $stableDeadline)
                        Assert-True ($stableSamples -ge 11) "physical baseline did not stabilize after controller restore"

                        if ($change -eq "interface") {
                            Assert-True $tcpResources.Remove($dnsResponder) "DNS responder ownership mismatch"
                            $dnsResponder.Dispose()
                            $dnsResponder = [Ferrum2DnsResponder]::new($managedDnsAddress, $managedDnsPort)
                            $tcpResources.Add($dnsResponder)
                        }
                    }
                } finally {
                    if (Test-Path -LiteralPath $changeConfiguration) { Remove-Item -LiteralPath $changeConfiguration -Force }
                    Assert-True (-not (Test-Path -LiteralPath $changeConfiguration)) "managed network-change generated config leaked"
                }
            }
            Assert-True ($managedNetworkChangeRows -eq 3 -and $managedRouteChangeRows -eq 1 -and
                $managedInterfaceChangeRows -eq 1 -and $managedAddressChangeRows -eq 1) "managed network-change row count mismatch"
        }

        foreach ($hardKill in @(
            @{ Name = "auto-route"; Dns = $false; Traffic = $false },
            @{ Name = "auto-dns"; Dns = $true; Traffic = $false },
            @{ Name = "mixed"; Dns = $true; Traffic = $true }
        )) {
            $heldHardKillTcp = $null
            $heldHardKillUdp = $null
            $hardKillConfiguration = Join-Path $work "client-managed-hard-kill-$($hardKill.Name).toml"
            $hardKillDirectSocksPort = Get-UniqueTcpPort
            $hardKillMetricsPort = Get-UniqueTcpPort
            if ($hardKill.Dns) {
                $hardKillProxySocksPort = Get-UniqueTcpPort
                $hardKillDnsInboundPort = Get-UniqueTcpPort
                $hardKillConfigText = $managedLifecycleTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$hardKillDirectSocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$proxySocksPort", "127.0.0.1:$hardKillProxySocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedDnsInboundPort", "127.0.0.1:$hardKillDnsInboundPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$hardKillMetricsPort")
            } else {
                $hardKillConfigText = $managedRouteOnlyTemplate.Replace("127.0.0.1:$directSocksPort", "127.0.0.1:$hardKillDirectSocksPort")
                $hardKillConfigText = $hardKillConfigText.Replace("127.0.0.1:$managedMetricsPort", "127.0.0.1:$hardKillMetricsPort")
            }
            $hardKillCapturePrefix = "$supportAddress/32"
            $autoRouteRows = @($hardKillConfigText -split '\r?\n' | Where-Object { $_ -ceq "auto_route = true" })
            Assert-True ($autoRouteRows.Count -eq 1 -and
                @($hardKillConfigText -split '\r?\n' | Where-Object {
                    $_.StartsWith("route_address =", [StringComparison]::Ordinal)
                }).Count -eq 0) "managed hard-kill capture template is ambiguous"
            $hardKillRouteLine = "route_address = [`"$hardKillCapturePrefix`"]"
            $hardKillConfigText = $hardKillConfigText.Replace(
                "auto_route = true",
                "auto_route = true`n$hardKillRouteLine"
            )
            Assert-True (@($hardKillConfigText -split '\r?\n' | Where-Object {
                $_ -ceq $hardKillRouteLine
            }).Count -eq 1) "managed hard-kill target capture generation mismatch"
            try {
                Assert-True (-not (Test-Path -LiteralPath $hardKillConfiguration)) "managed hard-kill generated config baseline not absent"
                Assert-True (-not $hardKillConfigText.Contains("127.0.0.1:$directSocksPort") -and
                    -not $hardKillConfigText.Contains("127.0.0.1:$managedMetricsPort")) "managed hard-kill listener generation mismatch"
                if ($hardKill.Dns) {
                    Assert-True (-not $hardKillConfigText.Contains("127.0.0.1:$proxySocksPort") -and
                        -not $hardKillConfigText.Contains("127.0.0.1:$managedDnsInboundPort")) "managed hard-kill DNS listener generation mismatch"
                }
                Set-Content -LiteralPath $hardKillConfiguration -Value $hardKillConfigText -Encoding utf8NoBOM -NoNewline
                $offlineOutput = @(& $binary --config $hardKillConfiguration --check-config 2>&1)
                Assert-True ($LASTEXITCODE -eq 0) "managed hard-kill generated config validation failed"
                Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed hard-kill generated config marker mismatch"

                $activeProcess = Start-Candidate $binary $hardKillConfiguration
                $adapter = Wait-AdapterReady -Name $managedAutoAdapterName -TimeoutSeconds 20 `
                    -Managed $true -ManagedDns ([bool]$hardKill.Dns) `
                    -ManagedCapturePrefixes @($hardKillCapturePrefix)
                $ownedInterfaceIndex = [int]$adapter.ifIndex
                $hardKillCaptureRoutes = @(
                    Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 `
                        -PolicyStore ActiveStore -ErrorAction Stop |
                        Where-Object { $_.DestinationPrefix -ceq $hardKillCapturePrefix }
                )
                Assert-True ($hardKillCaptureRoutes.Count -eq 1 -and
                    $hardKillCaptureRoutes[0].NextHop -ceq "0.0.0.0" -and
                    [uint32]$hardKillCaptureRoutes[0].RouteMetric -eq 1 -and
                    @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -AddressFamily IPv4 `
                        -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
                            $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1")
                        }).Count -eq 0) "managed hard-kill target capture readback mismatch"
                if ($hardKill.Dns) {
                    Assert-SnapshotEqual @("198.18.0.1") @(Get-TunIpv4Dns $ownedInterfaceIndex) "hard-kill DNS active"
                }
                if ($hardKill.Traffic) {
                    $heldHardKillTcp = (Open-TunTcp $supportAddress $supportTcpPort $ownedInterfaceIndex).Client
                    $tcpResources.Add($heldHardKillTcp)
                    $tcpPayload = [Text.Encoding]::ASCII.GetBytes("m16-hard-kill-tcp")
                    $heldHardKillTcp.GetStream().Write($tcpPayload, 0, $tcpPayload.Length)
                    $tcpEcho = Read-ExactBytes $heldHardKillTcp.GetStream() $tcpPayload.Length
                    Assert-True (($tcpEcho -join ",") -eq ($tcpPayload -join ",")) "hard-kill direct TCP echo mismatch"
                    $heldHardKillUdp = Open-TunUdp $supportAddress $supportUdpPort $ownedInterfaceIndex
                    $tcpResources.Add($heldHardKillUdp)
                    $udpPayload = [Text.Encoding]::ASCII.GetBytes("m16-hard-kill-udp")
                    [void]$heldHardKillUdp.Send($udpPayload, $udpPayload.Length)
                    $udpEcho = Receive-TunUdp $heldHardKillUdp
                    Assert-True (($udpEcho -join ",") -eq ($udpPayload -join ",")) "hard-kill direct UDP echo mismatch"
                    Invoke-ProductSocksTcp $hardKillProxySocksPort $supportAddress $supportTcpPort ([Text.Encoding]::ASCII.GetBytes("m16-hard-kill-proxy")) $false
                    [void](Invoke-SystemDnsWitness "m16-$runIdentity-hard-kill.tun.test" $false)
                }
                Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$activeProcess.Id)) "hard-kill TerminateProcess failed"
                Assert-True (Wait-ProcessExit $activeProcess 20) "hard-kill candidate did not exit"
                Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id) -ne 0) "hard-kill candidate exited cleanly"
                [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
                $activeProcess = $null
                if ($heldHardKillTcp) {
                    Assert-True $tcpResources.Remove($heldHardKillTcp) "hard-kill TCP witness ownership mismatch"
                    $heldHardKillTcp.Dispose()
                }
                if ($heldHardKillUdp) {
                    Assert-True $tcpResources.Remove($heldHardKillUdp) "hard-kill UDP witness ownership mismatch"
                    $heldHardKillUdp.Dispose()
                }
                Wait-AdapterAbsent $managedAutoAdapterName 20 11
                Assert-InterfaceGone $managedAutoAdapterName $ownedInterfaceIndex
                Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "hard-kill process residue"
                Assert-True (@(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill address residue"
                Assert-True (@(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill route residue"
                Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill DNS residue"
                $managedHardKillRows++
                Write-CapabilityEvidence "hard-kill-$($hardKill.Name)" ([ordered]@{
                    process = "absent"
                    adapter = "absent"
                    addresses = "absent"
                    routes = "absent"
                    dns = "absent"
                })
            } finally {
                if (Test-Path -LiteralPath $hardKillConfiguration) { Remove-Item -LiteralPath $hardKillConfiguration -Force }
                Assert-True (-not (Test-Path -LiteralPath $hardKillConfiguration)) "managed hard-kill generated config leaked"
            }
        }
        Assert-True ($managedHardKillRows -eq 3) "hard-kill row count mismatch"
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot 0) "managed lifecycle final physical DNS sentinel"
        Assert-True $tcpResources.Remove($dnsResponder) "managed lifecycle DNS responder ownership mismatch"
        $dnsResponder.Dispose()
        $dnsResponder = $null
        Remove-OwnedSiblingDll $runJournalIdentity
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "managed lifecycle sibling DLL residue"
    }
    if ($Mode -eq "network-feasibility") {
        Assert-PktMonAbsent
        Assert-True ([Ferrum2NetworkFeasibility]::RouteRowSize -eq 104) "route ABI size mismatch"
        $supportAddress = $capabilityIdentity.SupportAddress
        $supportTcpPort = $capabilityIdentity.TcpPort
        $supportUdpPort = $capabilityIdentity.UdpPort
        $fixedUnderlay = [Ferrum2NetworkFeasibility]::GetFixedRoute($supportAddress)
        $defaultUnderlay = Get-Ipv4DefaultUnderlay
        Assert-True ($fixedUnderlay.InterfaceIndex -eq $defaultUnderlay.InterfaceIndex -and $fixedUnderlay.PrefixLength -eq 0) "fixed endpoint did not use the eligible IPv4 physical default"
        Assert-True (@($defaultUnderlay.Sources | Where-Object { $_.IPAddress -eq $fixedUnderlay.SourceAddress }).Count -eq 1) "fixed endpoint best source mismatch"
        $dynamicUnderlay = [Ferrum2NetworkFeasibility]::GetConstrainedRoute($supportAddress, $defaultUnderlay.InterfaceIndex)
        Assert-True ($dynamicUnderlay.InterfaceIndex -eq $defaultUnderlay.InterfaceIndex -and $dynamicUnderlay.PrefixLength -eq 0) "dynamic default constrained route mismatch"
        Assert-True (@($defaultUnderlay.Sources | Where-Object { $_.IPAddress -eq $dynamicUnderlay.SourceAddress }).Count -eq 1) "dynamic default source mismatch"

        $preflightTcp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-tcp-live")
        $preflightUdp = [Text.Encoding]::ASCII.GetBytes("m16-$($capabilityIdentityHash.Substring(0, 16))-udp-live")
        [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightTcp)
        [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $fixedUnderlay.InterfaceIndex, $fixedUnderlay.SourceAddress, $preflightUdp)

        $physicalDnsBaseline = @(Get-PhysicalDnsSnapshot 0)
        Write-CapabilityEvidence "before" ([ordered]@{
            candidate_sha = $capabilityIdentity.Ledger.candidate_sha
            probe_sha256 = $capabilityIdentity.Ledger.probe_sha256
            identity_sha256 = $capabilityIdentityHash
            guest_build = $capabilityIdentity.GuestBuild
            physical_default = @($defaultUnderlay.Row.Route | Select-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric)
            fixed_underlay = $fixedUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            dynamic_underlay = $dynamicUnderlay | Select-Object InterfaceIndex, SourceAddress, NextHop, PrefixLength, RouteMetric
            physical_dns = $physicalDnsBaseline
            ferrum2_processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            ferrum2_adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
        })

        $metricsPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
ring_capacity = 8388608
[[outbounds]]
tag = "dead"
server = "127.0.0.1:9"
[route]
final = "dead"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$supportAddress"
port = $supportTcpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$supportAddress"
port = $supportUdpPort
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.18.0.1"
port = 53
action = "hijack-dns"
[udp]
enabled = false
max_sessions = 8
max_buffered_bytes = 1048576
idle_timeout_ms = 60000
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:$dnsPort"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($dnsResponder)
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "network feasibility config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "network feasibility config marker mismatch"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        $addressBaseline = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
        $routeBaseline = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $ipv6AddressBaseline = @($addressBaseline | Where-Object { $_ -like "IPv6|*" })
        Assert-True ($addressBaseline -contains "IPv4|198.18.0.2|30|Preferred" -and $addressBaseline -contains "IPv6|fd00::2|126|Preferred") "network feasibility address baseline mismatch"

        $partial = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, "0.0.0.0/1", 1)
        $capabilityRoutes.Add($partial)
        $partial.Verify()
        $partial.Dispose()
        Assert-True $capabilityRoutes.Remove($partial) "partial route journal mismatch"
        Assert-SnapshotEqual $routeBaseline @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex) "partial route rollback"

        $captureTraffic = Get-AdapterTraffic $adapterName
        $captureWindow = [Diagnostics.Stopwatch]::StartNew()
        $firstPrefix = if ([byte][Net.IPAddress]::Parse($supportAddress).GetAddressBytes()[0] -lt 128) { "0.0.0.0/1" } else { "128.0.0.0/1" }
        $secondPrefix = if ($firstPrefix -eq "0.0.0.0/1") { "128.0.0.0/1" } else { "0.0.0.0/1" }
        $firstRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $firstPrefix, 1)
        $capabilityRoutes.Add($firstRoute)
        [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort ([Text.Encoding]::ASCII.GetBytes("m16-capture-window")))
        $secondRoute = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $secondPrefix, 1)
        $capabilityRoutes.Add($secondRoute)
        $captureWindow.Stop()
        Assert-True ($captureWindow.ElapsedMilliseconds -le 3000) "capture-before-admission window exceeded"
        $captureTrafficAfter = Get-AdapterTraffic $adapterName
        Assert-True ($captureTrafficAfter.ReceivedPacketErrors -eq $captureTraffic.ReceivedPacketErrors -and
            $captureTrafficAfter.OutboundPacketErrors -eq $captureTraffic.OutboundPacketErrors -and
            $captureTrafficAfter.ReceivedDiscardedPackets -eq $captureTraffic.ReceivedDiscardedPackets -and
            $captureTrafficAfter.OutboundDiscardedPackets -eq $captureTraffic.OutboundDiscardedPackets) "capture-before-admission overflowed the Wintun ring"
        $capabilityWindowRows = 1
        foreach ($route in $capabilityRoutes) { $route.Verify() }
        $capabilityRouteRows = 2

        Assert-PktMonAbsent
        $pktmonComponentId = Get-PktMonComponentId $adapter
        $pktmonTcpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Tcp", "-i", $supportAddress, "-t", "TCP", "-p", [string]$supportTcpPort))
        $pktmonUdpFilterOwned = $true
        [void](Invoke-PktMon @("filter", "add", "M16Udp", "-i", $supportAddress, "-t", "UDP", "-p", [string]$supportUdpPort))
        $pktmonStartAttempted = $true
        [void](Invoke-PktMon @("start", "--capture", "--counters-only", "--comp", [string]$pktmonComponentId, "--type", "flow"))
        $pktmonStarted = $true
        $pktmonStartAttempted = $false
        [void](Get-PktMonFlowPackets)

        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-tcp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedTcpCapture $supportAddress $supportTcpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_tcp_unpinned"] = $filteredPackets
            $capabilityTcpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::TcpEcho($supportAddress, $supportTcpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned TCP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_tcp_pinned"] = $filteredPackets
            $capabilityTcpRows++
        }
        foreach ($row in @(
            @{ Name = "fixed"; Underlay = $fixedUnderlay },
            @{ Name = "dynamic"; Underlay = $dynamicUnderlay }
        )) {
            $payload = [Text.Encoding]::ASCII.GetBytes("m16-$($row.Name)-udp")
            $filteredBefore = Get-PktMonFlowPackets
            [void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort $payload)
            $filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore
            $capabilityFilteredPackets["$($row.Name)_udp_unpinned"] = $filteredPackets
            $capabilityUdpRows++
            $filteredBefore = Get-PktMonFlowPackets
            [Ferrum2NetworkFeasibility]::UdpEcho($supportAddress, $supportUdpPort, $row.Underlay.InterfaceIndex, $row.Underlay.SourceAddress, $payload)
            Start-Sleep -Milliseconds 500
            $filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore
            Assert-True ($filteredPackets -eq 0) "pinned UDP entered Wintun"
            $capabilityFilteredPackets["$($row.Name)_udp_pinned"] = $filteredPackets
            $capabilityUdpRows++
        }
        Assert-True ($capabilityTcpRows -eq 4 -and $capabilityUdpRows -eq 4) "socket pin row count mismatch"

        Set-CapabilityDns $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS after Wintun apply"
        try {
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-udp.tun.test" $false)
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-tcp.tun.test" $true)
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "unchanged"
        } catch {
            Set-CapabilityInterfaceMetric $ownedInterfaceIndex
            $capabilityDnsRows = 0
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-lease-udp.tun.test" $false)
            [void](Invoke-SystemDnsWitness "m16-$runIdentity-lease-tcp.tun.test" $true)
            $capabilityDnsRows = 2
            $capabilityInterfaceMetric = "leased"
        }
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS active sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address active sentinel"

        Write-CapabilityEvidence "active" ([ordered]@{
            interface_metric = $capabilityInterfaceMetric
            capture_window_ms = $captureWindow.ElapsedMilliseconds
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
            tun_accepted = Get-TunAccepted $metricsPort
            route_rows = $capabilityRouteRows
            tcp_rows = $capabilityTcpRows
            udp_rows = $capabilityUdpRows
            dns_rows = $capabilityDnsRows
            pktmon_filtered_flow_packets = $capabilityFilteredPackets
        })

        Stop-CapabilityPktMon
        $routesBeforeCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $limitedBroadcastRoute = "IPv4|255.255.255.255/32|0.0.0.0"
        Assert-True (@($routeBaseline | Where-Object { $_ -ceq $limitedBroadcastRoute }).Count -eq 1) "limited broadcast route baseline mismatch"
        $routeCleanupBaseline = @($routeBaseline | Where-Object { $_ -cne $limitedBroadcastRoute })
        Assert-True ($routeCleanupBaseline.Count -eq $routeBaseline.Count - 1) "limited broadcast cleanup baseline mismatch"
        $captureRouteRows = @(
            "IPv4|0.0.0.0/1|0.0.0.0",
            "IPv4|128.0.0.0/1|0.0.0.0"
        )
        foreach ($captureRouteRow in $captureRouteRows) {
            Assert-True (@($routesBeforeCaptureCleanup | Where-Object { $_ -ceq $captureRouteRow }).Count -eq 1) "owned capture route snapshot mismatch"
        }
        Remove-CapabilityRoutes
        $routeCleanupDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $routesAfterCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            if (@(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup)).Count -eq 0) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $routeCleanupDeadline)
        $routeCleanupDifference = @(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup))
        $routeCleanupLabel = "capture route exact rollback"
        if ($routeCleanupDifference.Count -gt 0) {
            $routeCleanupDiagnostic = @($routeCleanupDifference | Select-Object InputObject,SideIndicator)
            $routeCleanupLabel += " difference=$(ConvertTo-Json -InputObject $routeCleanupDiagnostic -Compress)"
        }
        Assert-SnapshotEqual $routeCleanupBaseline $routesAfterCaptureCleanup $routeCleanupLabel
        Restore-CapabilityDns $ownedInterfaceIndex
        Restore-CapabilityInterfaceMetric $ownedInterfaceIndex
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS normal cleanup sentinel"
        Assert-SnapshotEqual $ipv6AddressBaseline @((Get-InterfaceAddressSnapshot $ownedInterfaceIndex) | Where-Object { $_ -like "IPv6|*" }) "M15 IPv6 address normal cleanup sentinel"
        $ownerMetrics = Get-Metrics $metricsPort
        Assert-True ((Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_sessions_active") -eq 0 -and
            (Get-ClientGaugeValue $ownerMetrics "ferrum2_udp_buffered_bytes") -eq 0) "normal cleanup process-private owners remained"
        Stop-Candidate $activeProcess
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "normal cleanup process residue"
        Write-CapabilityEvidence "normal-cleanup" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
        })

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        [void](Get-Metrics $metricsPort)
        if ($capabilityInterfaceMetric -eq "leased") { Set-CapabilityInterfaceMetric $ownedInterfaceIndex }
        Set-CapabilityDns $ownedInterfaceIndex
        foreach ($prefix in @("0.0.0.0/1", "128.0.0.0/1")) {
            $route = [Ferrum2NetworkFeasibility]::CreateCaptureRoute([uint32]$ownedInterfaceIndex, $prefix, 1)
            $capabilityRoutes.Add($route)
        }
        Write-CapabilityEvidence "hard-kill-active" ([ordered]@{
            addresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
            routes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
            tun_ipv4_dns = @(Get-TunIpv4Dns $ownedInterfaceIndex)
        })
        $killedProcess = $activeProcess
        Assert-True ([Ferrum2ProcessGroup]::Terminate([uint32]$killedProcess.Id)) "TerminateProcess failed"
        Assert-True (Wait-ProcessExit $killedProcess 20) "hard-kill candidate did not exit"
        Assert-True ([Ferrum2ProcessGroup]::ExitCode([uint32]$killedProcess.Id) -ne 0) "hard-kill candidate unexpectedly exited cleanly"
        [Ferrum2ProcessGroup]::Close([uint32]$killedProcess.Id)
        $activeProcess = $null
        Wait-AdapterAbsent $adapterName
        Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        Assert-True (@(Get-ExactRunProcesses -WorkPath $work).Count -eq 0) "hard-kill process residue"
        Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "hard-kill DNS residue"
        Remove-CapabilityRoutes
        $capabilityDnsApplied = $false
        $capabilityDnsSnapshot = $null
        $capabilityMetricApplied = $false
        $capabilityMetricSnapshot = $null
        $capabilityHardKillRows = 1
        Write-CapabilityEvidence "after" ([ordered]@{
            processes = @(Get-ExactRunProcesses -WorkPath $work).Count
            adapters = @(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count
            addresses = @(Get-NetIPAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            routes = @(Get-NetRoute -InterfaceIndex $ownedInterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
            dns = @(Get-DnsClientServerAddress -InterfaceIndex $ownedInterfaceIndex -ErrorAction SilentlyContinue).Count
            physical_dns = @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex)
        })
        Assert-SnapshotEqual $physicalDnsBaseline @(Get-PhysicalDnsSnapshot $ownedInterfaceIndex) "physical DNS final sentinel"
    }
    if ($Mode -in @("lifecycle", "full")) {
    $metricsPort = Get-FreeTcpPort
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
outbound = "proxy"
ready_timeout_ms = 15000
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[runtime]
shutdown_grace_ms = 1000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
    Assert-InterfaceGone $adapterName $null
    $offlineOutput = @(& $binary --config $config --check-config 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) "offline config validation failed"
    Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "offline config marker mismatch"
    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "offline validation touched the DLL seam"
    Assert-InterfaceGone $adapterName $null
    $foundation++

    Write-OwnedSiblingDllIntent
    Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
    $createdSiblingDll = $true
    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $readyAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($readyAddresses -contains "IPv4|198.18.0.2|30|Preferred") "IPv4 address snapshot missing"
    Assert-True ($readyAddresses -contains "IPv6|fd00::2|126|Preferred") "IPv6 address snapshot missing"
    $systemRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedAddressDerivedRoutes = @(
        "IPv4|198.18.0.0/30|0.0.0.0",
        "IPv4|198.18.0.2/32|0.0.0.0",
        "IPv6|fd00::/126|::",
        "IPv6|fd00::2/128|::"
    )
    $addressDerivedRoutes = @($systemRoutes | Where-Object {
        ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or
        ($_ -like "IPv6|fd00::*")
    })
    Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "exact ready address-derived routes"
    $dynamicLinkLocalRoutes = @($systemRoutes | Where-Object { $_ -match '^IPv6\|fe80::.+/128\|::$' })
    Assert-True ($dynamicLinkLocalRoutes.Count -eq 1) "unexpected link-local host route count"
    $expectedAutomaticRoutes = @(
        "IPv4|198.18.0.3/32|0.0.0.0",
        "IPv4|224.0.0.0/4|0.0.0.0",
        "IPv4|255.255.255.255/32|0.0.0.0",
        "IPv6|fe80::/64|::",
        $dynamicLinkLocalRoutes[0],
        "IPv6|ff00::/8|::"
    )
    $automaticRoutes = @($systemRoutes | Where-Object { $expectedAddressDerivedRoutes -notcontains $_ })
    Assert-SnapshotEqual $expectedAutomaticRoutes $automaticRoutes "exact ready automatic routes"
    [void](Add-TunRoute $adapter.ifIndex "192.0.2.200/32")
    [void](Add-TunRoute $adapter.ifIndex "2001:db8::200/128")
    $withControllerRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedControllerRoutes = @(
        "IPv4|192.0.2.200/32|0.0.0.0",
        "IPv6|2001:db8::200/128|::"
    )
    foreach ($expectedRoute in $expectedControllerRoutes) {
        Assert-True ($withControllerRoutes -contains $expectedRoute) "controller route missing: $expectedRoute"
    }
    Assert-True ($withControllerRoutes.Count -eq $systemRoutes.Count + 2) "unexpected route mutation"
    $udp4 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $udp4.Connect("192.0.2.200", 53)
    $beforeMetrics = Get-Metrics $metricsPort
    $acceptedBefore = Get-CounterValue $beforeMetrics "ferrum2_tun_packets_accepted"
    try {
        [void]$udp4.Send([byte[]](1,2,3,4), 4)
    } finally { $udp4.Dispose(); $udp4 = $null }
    $packetDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $afterMetrics = Get-Metrics $metricsPort
        $acceptedAfter = Get-CounterValue $afterMetrics "ferrum2_tun_packets_accepted"
        $acceptedDelta = $acceptedAfter - $acceptedBefore
        if ($acceptedDelta -gt 0) { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $packetDeadline)
    Assert-True ($acceptedDelta -gt 0) "valid packet did not traverse receive/validation/enqueue"
    $udp6 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    try { [void]$udp6.Send([byte[]](5,6,7,8), 4, "2001:db8::200", 53) }
    finally { $udp6.Dispose() }
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $attempt = $tcp.BeginConnect("192.0.2.200", 443, $null, $null)
        [void]$attempt.AsyncWaitHandle.WaitOne(250)
    } finally { $tcp.Dispose() }
    Start-Sleep -Milliseconds 250
    $activeProcess.Refresh()
    Assert-True (-not $activeProcess.HasExited) "valid packets terminated the required root"
    $foundation++

    foreach ($route in $ownedRoutes) { Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop }
    $ownedRoutes.Clear()
    $afterOwnedRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    Assert-SnapshotEqual $systemRoutes $afterOwnedRoutes "controller route removal"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex

    $heldMetrics = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $heldMetrics.Start()
    $heldPort = ([Net.IPEndPoint]$heldMetrics.LocalEndpoint).Port
    (Get-Content -LiteralPath $config -Raw).Replace("127.0.0.1:$metricsPort", "127.0.0.1:$heldPort") |
        Set-Content -LiteralPath $failureConfig -Encoding utf8NoBOM
    $activeProcess = Start-Candidate $binary $failureConfig
    Assert-True (Wait-ProcessExit $activeProcess 20) "pre-TUN failure candidate did not exit"
    $failureExit = [Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id)
    Assert-True ($failureExit -ne 0) "pre-TUN failure candidate unexpectedly succeeded"
    [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
    $activeProcess = $null
    Assert-InterfaceGone $adapterName $null
    $heldMetrics.Stop()
    $heldMetrics = $null

    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $reboundAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($reboundAddresses -contains "IPv4|198.18.0.2|30|Preferred") "rebound IPv4 address missing"
    Assert-True ($reboundAddresses -contains "IPv6|fd00::2|126|Preferred") "rebound IPv6 address missing"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    $foundation++

    Assert-True ($foundation -eq 4) "foundation row count mismatch"
    }
    if ($Mode -eq "cycles") {
        $metricsPort = Get-FreeTcpPort
        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
outbound = "proxy"
ready_timeout_ms = 15000
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[runtime]
shutdown_grace_ms = 1000
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "cycle config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "cycle config marker mismatch"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        Invoke-AdapterCycles $binary $config
    }
    if ($Mode -in @("tcp", "tcp08", "udp", "full", "performance")) {
        $serverPortA = Get-UniqueTcpPort
        $serverPortB = Get-UniqueTcpPort
        $gatePortA = Get-UniqueTcpPort
        $gatePortB = Get-UniqueTcpPort
        $deadPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        $metricsPort = Get-UniqueTcpPort
        $performanceDirectInbound = ""
        $performanceDirectOutbound = ""
        $performanceDirectRule = ""
        if ($Mode -in @("tcp08", "performance")) {
            $performanceDirectSocksPort = Get-UniqueTcpPort
            $performanceDirectTargetPort = Get-UniqueTcpPort
            $performanceDirectInbound = "[[inbounds]]`ntag = `"performance-direct-socks`"`nlisten = `"127.0.0.1:$performanceDirectSocksPort`"`n"
            $performanceDirectOutbound = "[[outbounds]]`ntag = `"performance-direct`"`ntype = `"direct`"`n"
            $performanceDirectRule = "[[route.rules]]`ninbound = `"performance-direct-socks`"`nnetwork = `"tcp`"`naction = `"route`"`noutbound = `"performance-direct`"`n"
        }
        $ports = 1..8 | ForEach-Object { Get-UniqueTcpPort }
        $ports[4] = 53
        $targets = @(
            "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
            "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208"
        )
        $udpGateAddress = "192.0.2.250"
        if ($tcp08Enabled) {
            Write-Tcp08Metadata $targets[7] $ports[7] $gatePortA $serverPortA $metricsPort
        }
        $serverAConfig = Join-Path $work "server-a.toml"
        $serverBConfig = Join-Path $work "server-b.toml"
        foreach ($serverCase in @(@($serverAConfig, $serverPortA), @($serverBConfig, $serverPortB))) {
            @"
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:$($serverCase[1])"
outbound = "direct"
[[outbounds]]
tag = "direct"
[runtime]
shutdown_grace_ms = 1000
[udp]
enabled = true
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $serverCase[0] -Encoding utf8NoBOM
        }
        $serverProcessA = Start-Server $serverBinary $serverAConfig
        $serverProcessB = Start-Server $serverBinary $serverBConfig
        Wait-TcpListener $serverPortA $serverProcessA "server_a"
        Wait-TcpListener $serverPortB $serverProcessB "server_b"

        $gateA = [Ferrum2TcpGate]::new($gatePortA, $serverPortA)
        $gateB = [Ferrum2TcpGate]::new($gatePortB, $serverPortA)
        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($gateA)
        $tcpResources.Add($gateB)
        $tcpResources.Add($dnsResponder)
        if ($Mode -in @("udp", "full", "performance")) {
            [void](Add-TargetAddress $udpGateAddress $false)
            $udpGateA = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortA, $serverPortA)
            $udpGateB = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortB, $serverPortB)
            $tcpResources.Add($udpGateA)
            $tcpResources.Add($udpGateB)
        }

        @"
schema_version = 2
${performanceDirectInbound}[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
max_tcp_flows = 8
tcp_buffer_bytes = 4096
ring_capacity = 8388608
max_udp_mappings = 4
[[outbounds]]
tag = "one"
server = "127.0.0.1:$gatePortA"
[[outbounds]]
tag = "inner"
server = "127.0.0.1:$serverPortB"
[[outbounds]]
tag = "sniff"
server = "127.0.0.1:$gatePortB"
[[outbounds]]
tag = "dead"
server = "127.0.0.1:$deadPort"
[[outbounds]]
tag = "fallback"
server = "127.0.0.1:$gatePortB"
[[outbounds]]
tag = "udp-one"
server = "${udpGateAddress}:$gatePortA"
[[outbounds]]
tag = "udp-inner"
server = "${udpGateAddress}:$gatePortB"
${performanceDirectOutbound}[[chains]]
tag = "two-hop"
hops = ["one", "inner"]
[[chains]]
tag = "udp-two-hop"
hops = ["udp-one", "udp-inner"]
[[selectors]]
tag = "manual"
outbounds = ["dead", "fallback"]
default = "dead"
[[selectors]]
tag = "udp-manual"
outbounds = ["udp-one", "udp-inner"]
default = "udp-one"
[route]
final = "one"
[route.sniff]
timeout_ms = 1000
max_bytes = 8192
${performanceDirectRule}[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "one"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "two-hop"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
action = "sniff"
sniffers = "tls"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
protocol = "tls"
domain = "tls.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "http"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "http"
domain = "http.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
protocol = "dns"
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "manual"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[2])"
port = $($ports[2])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "dns"
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[4])"
port = $($ports[4])
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "udp-one"
[udp]
enabled = false
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:$dnsPort"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = $runtimeIdleTimeoutMilliseconds
[metrics]
listen = "127.0.0.1:$metricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        if ($Mode -eq "full") {
            Assert-True ((Get-FileHash -LiteralPath $siblingDll -Algorithm SHA256).Hash -eq $expectedDllHash) "full profile sibling DLL drifted"
        } else {
            Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        }
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "TCP config validation failed: $($offlineOutput -join '|')"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "TCP config marker mismatch"
        if ($Mode -ne "full") {
            Write-OwnedSiblingDllIntent
            Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
            $createdSiblingDll = $true
        }
        $activeProcess = Start-Candidate $binary $config
        if ($tcp08Enabled) {
            Add-Tcp08Event "process_started" ([ordered]@{
                process_id = [uint32]$activeProcess.Id
                executable = $binary
            })
        }
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($tcp08Enabled) {
            Add-Tcp08Event "adapter_ready" ([ordered]@{
                name = $adapterName
                interface_index = $ownedInterfaceIndex
            })
        }
        if ($Mode -eq "performance") { Start-PerformanceSample $activeProcess $metricsPort }
        else { [void](Get-Metrics $metricsPort) }
        $readyRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $expectedAddressDerivedRoutes = @(
            "IPv4|198.18.0.0/30|0.0.0.0", "IPv4|198.18.0.2/32|0.0.0.0",
            "IPv6|fd00::/126|::", "IPv6|fd00::2/128|::"
        )
        $addressDerivedRoutes = @($readyRoutes | Where-Object {
            ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or ($_ -like "IPv6|fd00::*")
        })
        Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "TCP ready address-derived routes"
        $strongHostInterfaces = @(Get-NetIPInterface -InterfaceIndex @($ownedInterfaceIndex, 1) -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($strongHostInterfaces.Count -eq 4) "strong-host interface rows missing"
        $weakHostInterfaces = @($strongHostInterfaces | Where-Object { $_.WeakHostSend -ne "Disabled" -or $_.WeakHostReceive -ne "Disabled" })
        Assert-True ($weakHostInterfaces.Count -eq 0) "weak-host forwarding is unsupported"
        $routeTargetIndexes = if ($Mode -eq "tcp08") { @(7) } else { @(0..7) }
        foreach ($targetIndex in $routeTargetIndexes) {
            $prefixLength = if ($targets[$targetIndex].Contains(":")) { 128 } else { 32 }
            [void](Add-TunRoute $ownedInterfaceIndex "$($targets[$targetIndex])/$prefixLength" 500)
        }
        $localTargetIndexes = if ($Mode -eq "tcp08") { @(7) } else { @(0, 1, 2, 3, 7) }
        foreach ($targetIndex in $localTargetIndexes) {
            [void](Add-TargetAddress $targets[$targetIndex])
        }

        if ($Mode -eq "tcp08") {
            Invoke-Tcp08 $targets[7] $ports[7] $ownedInterfaceIndex $gateA $gatePortA $serverPortA $metricsPort $false
            $tcpRows++
            Assert-True ($tcpRows -eq 1) "focused TCP-08 row count mismatch"
        } else {
        $tcp01Target = $targets[0]
        $tcp01Port = $ports[0]
        $tcp01Payload = [Text.Encoding]::ASCII.GetBytes("tcp-01-half-close")
        $tcp01Observation = @{ Diagnostic = "pending" }
        $tcp01Error = $null
        if ($Mode -eq "performance") {
            $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
        }
        try {
            Invoke-EchoRow $tcp01Target $tcp01Port $ownedInterfaceIndex $gateA $tcp01Payload $tcp01Observation
        } catch { $tcp01Error = $_ }

        $gateSettled = $false
        if ($tcp01Observation.Gate) {
            $gateSettled = $tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)
        }
        $probeSettled = $false
        if ($tcp01Observation.Probe) {
            $probeSettled = $tcp01Observation.Probe.WaitCompleted(1500)
        }
        $gateObservation = if ($tcp01Observation.Gate) {
            $tcp01Observation.Gate.Observation([int]$tcp01Observation.GateIndex)
        } else { $null }
        $probe = $tcp01Observation.Probe
        $probeRequest = if (-not $probe -or $probe.Received.Length -eq 0) { "none" }
            elseif (($probe.Received -join ",") -eq ($tcp01Payload -join ",")) { "exact" }
            else { "other" }
        $probeEcho = if (-not $probe -or $probe.EchoByteCount -eq 0) { "none" }
            elseif ($probeRequest -eq "exact" -and $probe.EchoByteCount -eq $tcp01Payload.Length) { "exact" }
            else { "other" }
        $tcp01State = @{
            GateAccepted = $tcp01Observation.GateAccepted
            GateForwardBytes = if ($gateObservation) { $gateObservation.ClientToServerBytes } else { "zero" }
            GateForwardStage = if ($gateObservation) { $gateObservation.ClientToServerStage } else { "pending" }
            GateForwardEof = if ($gateObservation) { $gateObservation.ClientToServerEof } else { "no" }
            GateForwardFault = if ($gateObservation) { $gateObservation.ClientToServerFault } else { "other" }
            GateReverseBytes = if ($gateObservation) { $gateObservation.ServerToClientBytes } else { "zero" }
            GateReverseStage = if ($gateObservation) { $gateObservation.ServerToClientStage } else { "pending" }
            GateReverseEof = if ($gateObservation) { $gateObservation.ServerToClientEof } else { "no" }
            GateReverseFault = if ($gateObservation) { $gateObservation.ServerToClientFault } else { "other" }
            GateComplete = if ($gateSettled -and $gateObservation -and $gateObservation.SessionComplete -eq "yes") { "yes" } else { "no" }
            ProbeAccepted = $tcp01Observation.ProbeAccepted
            ProbeRequest = $probeRequest
            ProbeReadEof = if ($probe) { $probe.ReadEof } else { "no" }
            ProbeEcho = $probeEcho
            ProbeShutdown = if ($probe) { $probe.SendShutdown } else { "no" }
            ProbeFault = if ($probe) { $probe.Fault } else { "other" }
            ProbeComplete = if ($probeSettled -and $probe -and $probe.SessionComplete -eq "yes") { "yes" } else { "no" }
            AppResult = $tcp01Observation.AppResult
        }
        $tcp01Boundary = Get-Tcp01Boundary $tcp01State
        if ($tcp01Error -or $tcp01Boundary -ne "COMPLETE") {
            $tcp01Diagnostic = "status=OBSERVED boundary=$tcp01Boundary app=$($tcp01State.AppResult) gate_accepted=$($tcp01State.GateAccepted) gate_c2s_bytes=$($tcp01State.GateForwardBytes) gate_c2s_stage=$($tcp01State.GateForwardStage) gate_c2s_eof=$($tcp01State.GateForwardEof) gate_c2s_fault=$($tcp01State.GateForwardFault) gate_s2c_bytes=$($tcp01State.GateReverseBytes) gate_s2c_stage=$($tcp01State.GateReverseStage) gate_s2c_eof=$($tcp01State.GateReverseEof) gate_s2c_fault=$($tcp01State.GateReverseFault) gate_complete=$($tcp01State.GateComplete) probe_accepted=$($tcp01State.ProbeAccepted) probe_request=$($tcp01State.ProbeRequest) probe_read_eof=$($tcp01State.ProbeReadEof) probe_echo=$($tcp01State.ProbeEcho) probe_shutdown=$($tcp01State.ProbeShutdown) probe_fault=$($tcp01State.ProbeFault) probe_complete=$($tcp01State.ProbeComplete)"
        }
        if ($tcp01Error) { throw $tcp01Error }
        Assert-True ($tcp01Boundary -eq "COMPLETE") "TCP-01 observation incomplete"
        $tcpRows++
        if ($Mode -eq "performance") {
            $performanceWitnesses++
            Update-PerformancePeaks $activeProcess $metricsPort
            $directProbe = [Ferrum2TcpProbe]::new("127.0.0.1", $performanceDirectTargetPort, "echo")
            $tcpResources.Add($directProbe)
            $directGateCounts = @($gateA.Accepted, $gateB.Accepted)
            Invoke-ProductSocksTcp $performanceDirectSocksPort "127.0.0.1" $performanceDirectTargetPort ([Text.Encoding]::ASCII.GetBytes("m16-performance-direct")) $true
            Assert-True ($directProbe.WaitCompleted(5000)) "performance direct target did not complete"
            Assert-True ($gateA.Accepted -eq $directGateCounts[0] -and $gateB.Accepted -eq $directGateCounts[1]) "performance direct row opened Shadowsocks"
            $performanceDirectRows++
            Update-PerformancePeaks $activeProcess $metricsPort
        }
        Invoke-EchoRow $targets[1] $ports[1] $ownedInterfaceIndex $gateA ([Text.Encoding]::ASCII.GetBytes("tcp-02-two-hop"))
        $tcpRows++

        $tlsGate = $gateB.Accepted + 1
        $tls = Open-TunTcp $targets[2] $ports[2] $ownedInterfaceIndex
        $ssl = [Net.Security.SslStream]::new($tls.Client.GetStream(), $false, { $true })
        $sslTask = $ssl.AuthenticateAsClientAsync("tls.tun.test")
        Assert-True ($gateB.WaitAccepted($tlsGate, 5000)) "TLS sniff did not select its exact egress"
        $tlsProbe = [Ferrum2TcpProbe]::new($targets[2], $ports[2], "capture")
        $tcpResources.Add($tlsProbe)
        $gateB.Release($tlsGate)
        Assert-True ($tlsProbe.WaitCompleted(5000)) "TLS replay target did not receive prefix"
        $tlsBytes = $tlsProbe.Received
        Assert-True ($tlsBytes.Length -gt 5 -and $tlsBytes[0] -eq 22) "TLS replay record missing"
        Assert-True ([Text.Encoding]::ASCII.GetString($tlsBytes).Contains("tls.tun.test")) "TLS SNI was not replayed"
        $ssl.Dispose(); $tls.Client.Dispose()
        $tcpRows++

        $httpGate = $gateB.Accepted + 1
        $http = Open-TunTcp $targets[3] $ports[3] $ownedInterfaceIndex
        $httpBytes = [Text.Encoding]::ASCII.GetBytes("GET /tun HTTP/1.1`r`nHost: http.tun.test`r`nConnection: close`r`n`r`n")
        $httpStream = $http.Client.GetStream()
        $httpStream.Write($httpBytes, 0, $httpBytes.Length)
        $http.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        Assert-True ($gateB.WaitAccepted($httpGate, 5000)) "HTTP sniff did not select its exact egress"
        $httpProbe = [Ferrum2TcpProbe]::new($targets[3], $ports[3], "echo")
        $tcpResources.Add($httpProbe)
        $gateB.Release($httpGate)
        Assert-True ($httpProbe.WaitAccepted(5000)) "HTTP replay target was not opened"
        $httpEcho = Read-StreamToEnd $httpStream
        Assert-True (($httpEcho -join ",") -eq ($httpBytes -join ",")) "HTTP prefix was not replayed exactly once"
        $http.Client.Dispose()
        $tcpRows++

        $gateCounts = @($gateA.Accepted, $gateB.Accepted)
        $dnsFlow = Open-TunTcp $targets[4] $ports[4] $ownedInterfaceIndex
        try {
            $dnsStream = $dnsFlow.Client.GetStream()
            foreach ($id in [uint16[]](0x1201, 0x1202)) {
                $query = New-DnsQuery $id
                $frame = [byte[]]::new($query.Length + 2)
                $frame[0] = [byte]($query.Length -shr 8); $frame[1] = [byte]$query.Length
                [Array]::Copy($query, 0, $frame, 2, $query.Length)
                $dnsStream.Write($frame, 0, $frame.Length)
                $length = Read-ExactBytes $dnsStream 2
                $responseLength = ([int]$length[0] -shl 8) -bor $length[1]
                $response = Read-ExactBytes $dnsStream $responseLength
                Assert-True ($response[0] -eq [byte]($id -shr 8) -and $response[1] -eq [byte]($id -band 0xff)) "DNS response ID mismatch"
            }
            Assert-True ($dnsResponder.Requests -eq 2) "DNS hijack did not answer both framed queries"
            Assert-True ($gateA.Accepted -eq $gateCounts[0] -and $gateB.Accepted -eq $gateCounts[1]) "DNS hijack opened Shadowsocks"
        } finally {
            $dnsFlow.Client.Dispose()
        }
        $tcpRows++
        if ($Mode -eq "performance") { $performanceDnsRows++ }

        Assert-ResetWithoutEgress $targets[5] $ports[5] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++
        Assert-ResetWithoutEgress $targets[6] $ports[6] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++

        Invoke-Tcp08 $targets[7] $ports[7] $ownedInterfaceIndex $gateA $gatePortA $serverPortA $metricsPort ($Mode -eq "performance")

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($Mode -eq "performance") {
            $performanceAdapterChurn++
            Start-PerformanceSample $activeProcess $metricsPort
        }
        if ($Mode -eq "tcp") {
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        } else {
            foreach ($target in $targets) {
                $prefixLength = if ($target.Contains(":")) { 128 } else { 32 }
                [void](Add-TunRoute $ownedInterfaceIndex "$target/$prefixLength" 500)
            }
        }
        $tcpRows++
        Assert-True ($tcpRows -eq 8) "TCP row count mismatch"
        }

        if ($Mode -in @("udp", "full", "performance")) {
            foreach ($targetIndex in @(4, 5, 6)) {
                [void](Add-TargetAddress $targets[$targetIndex])
            }

            # UDP-01 IPv4 one-hop route and authenticated response binding.
            if ($Mode -eq "performance") {
                $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
            }
            Invoke-UdpEchoRow $targets[0] $ports[0] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-01-one-hop"))
            $udpRows++
            if ($Mode -eq "performance") {
                $performanceWitnesses++
                Update-PerformancePeaks $activeProcess $metricsPort
            }

            if ($Mode -ne "performance") {
                # UDP-02 IPv6 fixed two-hop chain.
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                Invoke-UdpEchoRow $targets[1] $ports[1] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-02-two-hop"))
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-02 did not traverse both exact hops"
                $udpRows++

            # UDP-03 IPv4 selector snapshot unchanged for a live mapping.
            $selectorProbe = [Ferrum2UdpProbe]::new($targets[2], $ports[2])
            $tcpResources.Add($selectorProbe)
            $selectorClient = Open-TunUdp $targets[2] $ports[2] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                foreach ($payload in @(
                    [Text.Encoding]::ASCII.GetBytes("udp-03-first"),
                    [Text.Encoding]::ASCII.GetBytes("udp-03-snapshot")
                )) {
                    [void]$selectorClient.Send($payload, $payload.Length)
                    $response = Receive-TunUdp $selectorClient
                    Assert-True (($response -join ",") -eq ($payload -join ",")) "UDP-03 mapping changed its response binding"
                }
                Assert-True ($selectorProbe.WaitRequests(2, 5000)) "UDP-03 target did not receive both datagrams"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-03 selector mapping was not fixed"
            } finally { $selectorClient.Dispose() }
            $udpRows++

            # UDP-04 IPv6 expiry and reselection.
            $expiryProbe = [Ferrum2UdpProbe]::new($targets[3], $ports[3])
            $tcpResources.Add($expiryProbe)
            $expiryClient = Open-TunUdp $targets[3] $ports[3] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $plain = [Text.Encoding]::ASCII.GetBytes("udp-04-before-dns")
                [void]$expiryClient.Send($plain, $plain.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($plain -join ",")) "UDP-04 initial response mismatch"
                $query = New-DnsQuery 0x1401
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 live snapshot response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-04 live mapping re-entered policy"
                Start-Sleep -Milliseconds 60500
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 expired response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 3 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-04 did not reselect after expiry"
            } finally { $expiryClient.Dispose() }
            $udpRows++
            }

            # UDP-05 IPv4 DNS hijack with zero Shadowsocks owner.
            $beforeGateA = $udpGateA.Requests
            $beforeGateB = $udpGateB.Requests
            $beforeDns = $dnsResponder.Requests
            $dnsClient = Open-TunUdp $targets[4] $ports[4] $ownedInterfaceIndex
            try {
                $query = New-DnsQuery 0x1501
                [void]$dnsClient.Send($query, $query.Length)
                $response = Receive-TunUdp $dnsClient
                Assert-True ($response[0] -eq 0x15 -and $response[1] -eq 0x01) "UDP-05 DNS response ID mismatch"
                Assert-True ($dnsResponder.Requests -eq $beforeDns + 1) "UDP-05 DNS proxy did not answer"
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-05 DNS hijack opened Shadowsocks"
            } finally { $dnsClient.Dispose() }
            $udpRows++
            if ($Mode -eq "performance") { $performanceDnsRows++ }

            if ($Mode -ne "performance") {
                # UDP-06 IPv6 reject tombstone and no policy re-entry.
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $rejectClient = Open-TunUdp $targets[5] $ports[5] $ownedInterfaceIndex
                try {
                    $rejected = [Text.Encoding]::ASCII.GetBytes("udp-06-reject")
                    [void]$rejectClient.Send($rejected, $rejected.Length)
                    [void]$rejectClient.Send($rejected, $rejected.Length)
                    $rejectedResponse = $rejectClient.ReceiveAsync()
                    Assert-True (-not $rejectedResponse.Wait(500)) "UDP-06 reject returned a datagram"
                    Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-06 reject opened an egress"
                } finally { $rejectClient.Dispose() }
                $udpRows++

            # UDP-07 IPv4 over-limit no-commit then selector re-read.
            $overLimitClient = Open-TunUdp $targets[6] $ports[6] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $overLimit = [byte[]]::new(2000)
                [void]$overLimitClient.Send($overLimit, $overLimit.Length)
                Start-Sleep -Milliseconds 500
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 over-limit candidate committed"
                $overLimitProbe = [Ferrum2UdpProbe]::new($targets[6], $ports[6])
                $tcpResources.Add($overLimitProbe)
                $valid = [Text.Encoding]::ASCII.GetBytes("udp-07-valid")
                [void]$overLimitClient.Send($valid, $valid.Length)
                Assert-True (((Receive-TunUdp $overLimitClient) -join ",") -eq ($valid -join ",")) "UDP-07 recovery response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 valid candidate did not re-read selector"
            } finally { $overLimitClient.Dispose() }
            $udpRows++

            # UDP-08 IPv6 mapping saturation, generation reuse and wrong-response drop.
            Start-Sleep -Milliseconds 60500
            $saturationProbe = [Ferrum2UdpProbe]::new($targets[7], $ports[7])
            $tcpResources.Add($saturationProbe)
            $saturatedClients = [System.Collections.Generic.List[Net.Sockets.UdpClient]]::new()
            $overflowClient = $null
            try {
                $beforeGateA = $udpGateA.Requests
                foreach ($index in 0..3) {
                    $mappingClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                    $saturatedClients.Add($mappingClient)
                    $payload = [Text.Encoding]::ASCII.GetBytes("udp-08-slot-$index")
                    [void]$mappingClient.Send($payload, $payload.Length)
                    Assert-True (((Receive-TunUdp $mappingClient) -join ",") -eq ($payload -join ",")) "UDP-08 live mapping response mismatch"
                }
                Assert-True ($saturatedClients.Count -eq 4) "UDP-08 mapping saturation setup mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 did not commit the fixed mapping capacity"
                $overflowClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                $overflow = [Text.Encoding]::ASCII.GetBytes("udp-08-overflow")
                [void]$overflowClient.Send($overflow, $overflow.Length)
                $overflowResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $overflowResponse.Wait(500) -and $udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 evicted a live mapping"
                Start-Sleep -Milliseconds 60500
                [void]$overflowClient.Send($overflow, $overflow.Length)
                Assert-True ($overflowResponse.Wait(5000)) "UDP-08 expired response timeout"
                if ($overflowResponse.IsFaulted) { throw "UDP-08 expired response failed" }
                Assert-True (($overflowResponse.Result.Buffer -join ",") -eq ($overflow -join ",")) "UDP-08 expired slot was not reusable"
                Assert-True ($udpGateA.ReplayFirstToLatest()) "UDP-08 stale response replay was unavailable"
                $staleResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $staleResponse.Wait(500)) "UDP-08 stale response crossed the new generation"
            } finally {
                if ($overflowClient) { $overflowClient.Dispose() }
                foreach ($client in $saturatedClients) { $client.Dispose() }
            }
                $udpRows++
            }
            if ($Mode -eq "performance") {
                Assert-True ($udpRows -eq 2) "performance UDP witness row count mismatch"
            } else {
                Assert-True ($udpRows -eq 8) "UDP row count mismatch"
            }

            if ($Mode -eq "performance") { Complete-PerformanceSample $activeProcess $metricsPort }
            Stop-Candidate $activeProcess
            if ($Mode -eq "performance") { $performanceGraceDrain = $true }
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            $activeProcess = Start-Candidate $binary $config
            $adapter = Wait-AdapterReady $adapterName
            $ownedInterfaceIndex = [int]$adapter.ifIndex
            if ($Mode -eq "performance") { $performanceAdapterChurn++ }
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            if ($Mode -eq "performance") {
                Assert-True $performanceFieldsCollected "performance fields were not collected"
                Assert-True ($performanceWitnesses -eq 2) "performance witness count mismatch"
                Assert-True ($performanceDirectRows -eq 1) "performance direct row count mismatch"
                Assert-True ($performanceDnsRows -eq 2) "performance DNS row count mismatch"
                Assert-True ($performanceAdapterRxBytes -gt 0 -and $performanceAdapterTxBytes -gt 0) "adapter byte witnesses missing"
                Assert-True ($performanceAdapterRxPackets -gt 0 -and $performanceAdapterTxPackets -gt 0) "adapter packet witnesses missing"
                Assert-True ($performanceTunAcceptedDelta -gt 0) "TUN accepted witness missing"
                Assert-True ($performanceRssBytes -gt 0 -and $performanceHandlesPeak -gt 0 -and $performanceThreadsPeak -gt 0) "process resource sample missing"
                Assert-True ($performanceControllerInflightPeak -gt 0) "controller inflight sample missing"
                Assert-True ($performanceAdapterChurn -ge 2) "adapter churn witness missing"
                Assert-True ($performanceGraceDrain -and $performanceForceDrain) "grace/force drain witness missing"
            }
        }
    }
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
if ($Mode -in $m17Modes -and $m17ArtifactInitialized) {
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
    if ($Mode -in $m17Modes) {
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
        Write-Output "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT cleanup=PASS guest_build=$($capabilityIdentity.GuestBuild) run_token=$runIdentity candidate_sha=$($capabilityIdentity.Ledger.candidate_sha) probe_sha256=$($capabilityIdentity.Ledger.probe_sha256) identity_sha256=$capabilityIdentityHash"
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
