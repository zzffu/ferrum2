param(
    [Parameter(Mandatory = $true)]
    # Legacy M15 mode contract: [ValidateSet("lifecycle", "tcp", "udp", "cycles", "full", "performance", "cleanup")]
    [ValidateSet("lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance", "network-feasibility", "managed-product", "hard-kill", "cleanup")]
    [string]$Mode,
    [string]$WintunZip,
    [string]$RunToken,
    [string]$IdentityLedger,
    [string]$ClientBinary,
    [string]$ServerBinary,
    [string]$ProductRoot,
    [string]$ArtifactDirectory,
    [string]$RuntimeLibraryDirectory,
    [switch]$RequireTcp08ProductMetrics
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$tcp08ClockOriginUtc = [DateTime]::UtcNow.ToString("o")
$tcp08ClockOriginTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()
$controllerStartedUtc = $tcp08ClockOriginUtc

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64") {
    throw "Windows AMD64 is required"
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
$resolvedRuntimeLibraryDirectory = $null
$runtimeVcruntimePath = $null
$runtimeVcruntimeBytes = $null
$runtimeVcruntimeSha256 = $null
$runIdentity = if ($RunToken) { $RunToken } elseif ($Mode -eq "cleanup") { throw "cleanup requires RunToken" } else { "local-$PID" }
if ($runIdentity -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw "RunToken is invalid" }
$work = if ($Mode -eq "network-feasibility") {
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
$adapterName = if ($Mode -eq "network-feasibility") {
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
$runIdentityJournalRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) "Ferrum2\ControllerRunIdentities"
$runIdentityJournalPath = Join-Path $runIdentityJournalRoot "$runIdentity.json"

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-ControllerWorkPaths {
    $paths = @(
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m15-tun-$script:runIdentity"
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-network-$script:runIdentity"
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m16-product-$script:runIdentity"
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
    $serverRequired = $script:Mode -in @("tcp", "tcp08", "udp", "full", "performance")
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.cleanup-identity.v1"
        run_token = $script:runIdentity
        mode = $script:Mode
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
        "schema", "run_token", "mode", "work_path", "product_root",
        "client_binary_path", "client_binary_sha256", "client_binary_explicit",
        "server_binary_path", "server_binary_sha256", "server_binary_explicit", "server_required",
        "sibling_dll_path", "dll_ownership", "dll_marker_path", "expected_dll_sha256",
        "controller_path", "controller_sha256"
    ) "run identity journal"
    Assert-True ($document.schema -ceq "ferrum2.windows-tun.cleanup-identity.v1" -and
        $document.run_token -ceq $script:runIdentity) "run identity journal schema/token mismatch"
    Assert-True ($document.mode -in @("lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance", "network-feasibility", "managed-product", "hard-kill")) "run identity journal mode is invalid"
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
    $expectedServerRequired = $document.mode -in @("tcp", "tcp08", "udp", "full", "performance")
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

if ($Mode -eq "cleanup") {
    $cleanupWorks = @(Get-ControllerWorkPaths)
    $cleanupAdapterNames = @(
        "Ferrum2-M15-$runIdentity", "Ferrum2-M16-$runIdentity",
        $managedAutoAdapterName, $managedManualAdapterName
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
        "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208", "192.0.2.250"
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
        Remove-Item -LiteralPath $runIdentityJournalPath -Force -ErrorAction Stop
        Assert-True (-not (Test-Path -LiteralPath $runIdentityJournalPath)) "run identity journal residue"
    }
    return
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
        "192.0.2.250"
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
    Assert-True ((@($ledger.PSObject.Properties.Name) -join "|") -ceq ($keys -join "|")) "identity ledger keys are invalid"
    $listenerKeys = @("ipv4", "tcp_port", "udp_port", "pid", "owner")
    Assert-True ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -ceq ($listenerKeys -join "|")) "support listener keys are invalid"
    Assert-True (($ledger | ConvertTo-Json -Compress -Depth 4) -ceq $json) "identity ledger is not canonical JSON"
    Assert-True ($ledger.schema -is [long] -and $ledger.schema -eq 1) "identity ledger schema is invalid"
    Assert-True ($ledger.vm_name -ceq "Windows 10 MSIX packaging environment") "identity ledger VM name is invalid"
    Assert-True ($ledger.checkpoint_name -ceq "M15-T04-before-2b0c25b-20260810") "identity ledger checkpoint name is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger VM ID is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger checkpoint ID is invalid"
    Assert-True ([string]$ledger.candidate_sha -cmatch '^[0-9a-f]{40}$') "identity ledger candidate SHA is invalid"
    Assert-True ([string]$ledger.probe_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger probe hash is invalid"
    Assert-True ([string]$ledger.client_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger client hash is invalid"
    Assert-True ([string]$ledger.server_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger server hash is invalid"
    $probePath = Join-Path $PSScriptRoot "qualify_windows_tun.ps1"
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

if ($Mode -in @("network-feasibility", "managed-product", "full", "hard-kill")) {
    $capabilityIdentity = Get-NetworkFeasibilityIdentity $IdentityLedger ($Mode -eq "full")
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
    [bool]$ManagedDns = $false
) {
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
                        Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
                        Sort-Object DestinationPrefix |
                        ForEach-Object { $_.DestinationPrefix }
                )
                $dnsReady = -not $ManagedDns
                if ($ManagedDns) {
                    $dnsAddresses = @(Get-TunIpv4Dns $adapter.ifIndex)
                    $dnsReady = ($dnsAddresses -join "|") -ceq "198.18.0.1"
                }
                if (($capturePrefixes -join "|") -ceq "0.0.0.0/1|128.0.0.0/1" -and $dnsReady) {
                    try {
                        $finalCapturePrefixes = @(
                            Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                                Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
                                Sort-Object DestinationPrefix |
                                ForEach-Object { $_.DestinationPrefix }
                        )
                        Assert-SnapshotEqual @("0.0.0.0/1", "128.0.0.0/1") $finalCapturePrefixes "managed state readiness capture"
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
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
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
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private byte[] received = new byte[0];
    private int requests;
    private int responses;
    private int disposed;
    private string fault;

    public Ferrum2UdpProbe(string address, int port) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public byte[] Received { get { return Volatile.Read(ref received); } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                Volatile.Write(ref received, (byte[])request.Buffer.Clone());
                Interlocked.Increment(ref requests);
                await socket.SendAsync(request.Buffer, request.Buffer.Length, request.RemoteEndPoint).ConfigureAwait(false);
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
                using (var response = new MemoryStream()) {
                    response.WriteByte(query[0]); response.WriteByte(query[1]);
                    response.WriteByte(0x81); response.WriteByte(0x80);
                    response.WriteByte(0); response.WriteByte(1);
                    response.WriteByte(0); response.WriteByte(1);
                    response.Write(new byte[4], 0, 4);
                    response.Write(query, 12, query.Length - 12);
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
    private const int IP_UNICAST_IF = 31;

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

    private static void Pin(Socket socket, uint interfaceIndex) {
        var networkOrder = unchecked((uint)IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex)));
        if (setsockopt(socket.Handle, IPPROTO_IP, IP_UNICAST_IF, ref networkOrder, sizeof(uint)) != 0)
            throw new Win32Exception(WSAGetLastError(), "IP_UNICAST_IF");
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
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
        -AutomaticMetric $script:capabilityMetricSnapshot.AutomaticMetric `
        -InterfaceMetric $script:capabilityMetricSnapshot.InterfaceMetric -PolicyStore ActiveStore -ErrorAction Stop
    $restored = Get-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
    Assert-True ([string]$restored.AutomaticMetric -eq $script:capabilityMetricSnapshot.AutomaticMetric -and
        [uint32]$restored.InterfaceMetric -eq $script:capabilityMetricSnapshot.InterfaceMetric) "capability interface metric restore mismatch"
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
        Add-Tcp08Event "pressure_write_started" ([ordered]@{
            pressure_gate_index = $pressureGate
            chunk_bytes = $pressureChunk.Length
            attempt_limit = 128
            target_accepted_before_write = $true
        })
        $pendingAttempt = $null
        for ($attempt = 0; $attempt -lt 128; $attempt++) {
            $pressureWrite = $pressure.Client.GetStream().WriteAsync($pressureChunk, 0, $pressureChunk.Length)
            if (-not $pressureWrite.Wait(100)) {
                $pendingAttempt = $attempt + 1
                break
            }
        }
        Assert-True ($pressureWrite -and -not $pressureWrite.IsCompleted) "backpressure write unexpectedly drained"
        Add-Tcp08Event "pressure_write_became_pending" ([ordered]@{
            attempt = $pendingAttempt
            task_status = $pressureWrite.Status.ToString()
        })
        if ($CollectPerformance) { Complete-PerformanceSample $script:activeProcess $MetricsPort }

        $beforeSignal = Get-Tcp08LiveEvidence "before_ctrl_break" $Target $Port $GatePort $ServerPort $MetricsPort $script:activeProcess $pressure $pressureWrite $stall $Gate $pressureGate
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

try {
    Initialize-Tcp08Artifacts
    Assert-True (-not (Test-Path -LiteralPath $work)) "run work baseline not absent"
    Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) "run process baseline not absent"
    Assert-True (-not (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)) "run adapter baseline not absent"
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

    if ($Mode -notin @("network-feasibility", "managed-product", "full", "hard-kill")) {
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
    if ($Mode -in @("tcp", "tcp08", "udp", "performance")) {
        Assert-True (Test-Path -LiteralPath $serverBinary) "candidate server binary is missing after selection/build"
    }
    if ($tcp08Enabled) { Write-Tcp08BinaryEvidence $sourceDll }
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
                $adapter = Wait-AdapterReady $managedAutoAdapterName 20 $true $hardKill.Dns
                $ownedInterfaceIndex = [int]$adapter.ifIndex
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
schema_version = 1
[server]
listen = "127.0.0.1:$($serverCase[1])"
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
max_udp_buffered_bytes = 4194304
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
idle_timeout_ms = 2000
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
if ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }
if ($primaryError) { throw $primaryError }

if ($completed) {
    $sha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
    $runAttempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "local" }
    if ($Mode -eq "lifecycle") {
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
