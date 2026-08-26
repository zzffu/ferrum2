function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Test-UtcRoundTripTimestamp([object]$Value) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).Kind -eq [DateTimeKind]::Utc
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero
    }
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
        schema = "ferrum2.windows-tun.cleanup-identity.v2"
        run_token = $script:runIdentity
        mode = $script:Mode
        identity_sha256 = (Get-FileHash -LiteralPath $script:identityMarker -Algorithm SHA256).Hash.ToLowerInvariant()
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
    Assert-True ($document.schema -ceq "ferrum2.windows-tun.cleanup-identity.v2" -and
        $document.run_token -ceq $script:runIdentity) "run identity journal schema/token mismatch"
    Assert-True ($document.mode -in @(
        "lifecycle", "tcp", "tcp08", "udp", "cycles", "full", "performance",
        "network-feasibility", "managed-product", "hard-kill", "network-reset",
        "restart-stress", "fragments", "dual-stack-dns", "udp-policy", "scheduler-ring-full"
    )) "run identity journal mode is invalid"
    Assert-True ([string]$document.identity_sha256 -cmatch '^[0-9a-f]{64}$') "run identity journal hash is invalid"
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
    $document = Read-M17MutationIntent $Path "ferrum2.windows-tun.m17-network-reset-route-intent.v2" @(
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
        $nextHop.Equals([Net.IPAddress]::Any)) "M17 network-reset route next hop is invalid"
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
