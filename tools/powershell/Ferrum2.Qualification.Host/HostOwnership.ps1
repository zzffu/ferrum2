Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'HostNetwork.ps1')

function Test-Ferrum2HostAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Ferrum2PlainDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return $item.PSIsContainer -and
        -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# Retain the legacy recovery root, mutex name and v2 ledger identity together: qualification
# must discover and recover unfinished runs created before the performance runner was retired.
function Get-Ferrum2HostRoot {
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw "PROGRAMDATA is unavailable; the protected recovery root cannot be resolved."
    }
    return Join-Path $env:ProgramData "Ferrum2HostPerformance-v2"
}

function New-Ferrum2HostRootSecurity {
    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $users = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administrators)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(
            @{
                Identity = $administrators
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            @{
                Identity = $system
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            @{
                Identity = $users
                Rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            }
        )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Identity,
            $entry.Rights,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Assert-Ferrum2HostRootSecurity {
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not (Test-Ferrum2PlainDirectory -Path $Root)) {
        throw "Host qualification recovery root is not a plain directory: $Root"
    }
    $expectedAcl = New-Ferrum2HostRootSecurity
    $actualAcl = Get-Acl -LiteralPath $Root -ErrorAction Stop
    $actualOwner = $actualAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($actualOwner -cne "S-1-5-32-544" -or -not $actualAcl.AreAccessRulesProtected) {
        throw "Host qualification recovery root ACL is not the reviewed administrator-owned contract: $Root"
    }
    $expectedRules = @($expectedAcl.GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]
        ) | ForEach-Object {
            "$($_.IdentityReference.Value)|$([int64]$_.FileSystemRights)|" +
                "$([int]$_.InheritanceFlags)|$([int]$_.PropagationFlags)|" +
                "$([int]$_.AccessControlType)|$($_.IsInherited)"
        } | Sort-Object)
    $actualRules = @($actualAcl.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier]
        ) | ForEach-Object {
            "$($_.IdentityReference.Value)|$([int64]$_.FileSystemRights)|" +
                "$([int]$_.InheritanceFlags)|$([int]$_.PropagationFlags)|" +
                "$([int]$_.AccessControlType)|$($_.IsInherited)"
        } | Sort-Object)
    if ($actualRules.Count -ne $expectedRules.Count -or
        ($actualRules -join "`n") -cne ($expectedRules -join "`n")) {
        throw "Host qualification recovery root ACL is not the reviewed administrator-owned contract: $Root"
    }
}

function Initialize-Ferrum2HostRoot {
    if (-not (Test-Ferrum2HostAdministrator)) {
        throw "Creating or validating the host qualification recovery root requires elevation."
    }
    $root = Get-Ferrum2HostRoot
    if (Test-Path -LiteralPath $root) {
        Assert-Ferrum2HostRootSecurity -Root $root
        return $root
    }

    $temporary = Join-Path $env:ProgramData (
        ".Ferrum2HostPerformance-v2-$([Guid]::NewGuid().ToString('N')).tmp"
    )
    $temporaryCreated = $false
    try {
        New-Item -ItemType Directory -Path $temporary -ErrorAction Stop | Out-Null
        $temporaryCreated = $true
        Set-Acl -LiteralPath $temporary `
            -AclObject (New-Ferrum2HostRootSecurity) -ErrorAction Stop
        Assert-Ferrum2HostRootSecurity -Root $temporary
        [IO.Directory]::Move($temporary, $root)
        $temporaryCreated = $false
        Assert-Ferrum2HostRootSecurity -Root $root
        return $root
    } catch {
        if ($temporaryCreated -and (Test-Ferrum2PlainDirectory -Path $temporary)) {
            Remove-Item -LiteralPath $temporary -Force -Recurse -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Remove-Ferrum2HostRunRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )
    if ($RunId -cnotmatch '^[0-9a-f]{12}$') {
        throw "host qualification RunId is invalid"
    }
    $recoveryRoot = [IO.Path]::GetFullPath((Get-Ferrum2HostRoot))
    Assert-Ferrum2HostRootSecurity -Root $recoveryRoot
    $expectedRunRoot = [IO.Path]::GetFullPath((Join-Path $recoveryRoot $RunId))
    $actualRunRoot = [IO.Path]::GetFullPath($RunRoot)
    if (-not $actualRunRoot.Equals($expectedRunRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "host qualification run root identity is invalid"
    }
    if (-not (Test-Path -LiteralPath $actualRunRoot)) {
        return
    }
    $item = Get-Item -LiteralPath $actualRunRoot -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "host qualification run root is not a plain directory"
    }
    Remove-Item -LiteralPath $actualRunRoot -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $actualRunRoot) {
        throw "host qualification run root remains after cleanup"
    }
}

function Enter-Ferrum2HostMutex {
    $created = $false
    $mutex = [Threading.Mutex]::new($true, "Global\Ferrum2HostPerformance", [ref]$created)
    if (-not $created) {
        $mutex.Dispose()
        throw "another Ferrum2 host qualification run owns the global mutex"
    }
    return $mutex
}

function Exit-Ferrum2HostMutex {
    param([Threading.Mutex]$Mutex)
    if ($null -ne $Mutex) {
        try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
    }
}

function Write-AtomicJsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Document
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $utf8 = [Text.UTF8Encoding]::new($false)
    try {
        [IO.File]::WriteAllText(
            $temporary,
            (($Document | ConvertTo-Json -Depth 20) + "`n"),
            $utf8
        )
        Move-Item -LiteralPath $temporary -Destination $Path -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-Ferrum2HostLedger {
    param([Parameter(Mandatory = $true)][object]$Context)
    Update-Ferrum2ExpectedResources -Ledger $Context.ledger
    $Context.ledger.updated_utc = [DateTime]::UtcNow.ToString("O")
    Write-AtomicJsonFile -Path $Context.ledger_path -Document $Context.ledger
}

function New-Ferrum2HostContext {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$QualificationSourceBundleSha256,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $AddressFamily = (Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily).address_family
    $evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
    $evidenceCreated = $false
    $runRootCreated = $false
    $runRoot = $null
    $runId = $null
    try {
        # Capture before this context can launch a product or create an adapter.
        $adapterBaseline = @(Get-Ferrum2HostAdapterBaseline)
        if (Test-Path -LiteralPath $evidence) {
            throw "host qualification evidence directory baseline must be absent"
        }
        New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
        $evidenceCreated = $true

        $runId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
        $recoveryRoot = Initialize-Ferrum2HostRoot
        $runRoot = Join-Path $recoveryRoot $runId
        if (Test-Path -LiteralPath $runRoot) {
            throw "generated host qualification RunId already exists"
        }
        New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
        $runRootCreated = $true
        $ledger = [pscustomobject][ordered]@{
            schema_version = 2
            kind = "ferrum2.windows-tun.host-performance-recovery"
            run_id = $runId
            address_family = $AddressFamily
            state = "initializing"
            mode = "Qualification"
            baseline_sha = $CandidateSha
            candidate_sha = $CandidateSha
            performance_source_bundle_sha256 = $QualificationSourceBundleSha256
            repository_root = [IO.Path]::GetFullPath($RepositoryRoot)
            evidence_directory = $evidence
            created_utc = [DateTime]::UtcNow.ToString("O")
            updated_utc = [DateTime]::UtcNow.ToString("O")
            resources = [pscustomobject][ordered]@{
                processes = @()
                adapter = $null
                addresses = @()
                routes = @()
                ports = @()
                firewall_rules = @()
            }
            expected_resources = [pscustomobject][ordered]@{
                processes = @(); adapters = @(); addresses = @(); routes = @(); ports = @()
                firewall_rules = @()
                adapter_baseline_guids = $adapterBaseline
            }
            recovery = [pscustomobject][ordered]@{
                attempts = 0
                last_error = $null
            }
        }
        $context = [pscustomobject]@{
            run_id = $runId
            address_family = $AddressFamily
            run_root = $runRoot
            ledger_path = Join-Path $runRoot "recovery.json"
            repository_root = [IO.Path]::GetFullPath($RepositoryRoot)
            evidence_directory = $evidence
            qualification_source_bundle_sha256 = $QualificationSourceBundleSha256
            ledger = $ledger
        }
        Write-Ferrum2HostLedger -Context $context
        return $context
    } catch {
        $failure = $_
        if ($runRootCreated) {
            Remove-Ferrum2HostRunRoot -RunRoot $runRoot -RunId $runId
        }
        if ($evidenceCreated -and (Test-Ferrum2PlainDirectory -Path $evidence)) {
            $children = @(Get-ChildItem -LiteralPath $evidence -Force -ErrorAction Stop)
            if ($children.Count -eq 0) {
                Remove-Item -LiteralPath $evidence -Force -ErrorAction Stop
            }
        }
        throw $failure
    }
}

function Set-Ferrum2HostState {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$State
    )
    $Context.ledger.state = $State
    Write-Ferrum2HostLedger -Context $Context
}

function Get-Ferrum2HostLedgers {
    $root = Get-Ferrum2HostRoot
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    Assert-Ferrum2HostRootSecurity -Root $root
    $rows = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)
    if ($rows.Count -gt 128) {
        throw "host qualification recovery root exceeds 128 run directories"
    }
    $ledgers = [Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        if ($row.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "host qualification recovery directory must not be a reparse point"
        }
        $path = Join-Path $row.FullName "recovery.json"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt 1MB -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "host qualification recovery ledger is invalid: $path"
        }
        $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -Depth 20 -ErrorAction Stop
        if ($document.schema_version -ne 2 -or
            [string]$document.kind -cne "ferrum2.windows-tun.host-performance-recovery" -or
            [string]$document.run_id -cne $row.Name -or
            [string]$document.run_id -cnotmatch '^[0-9a-f]{12}$') {
            throw "host qualification recovery ledger identity is invalid: $path"
        }
        if ($null -eq $document.expected_resources.adapter_baseline_guids -or
            @($document.expected_resources.adapter_baseline_guids).Count -gt 4096) {
            throw "host qualification recovery adapter baseline is invalid: $path"
        }
        foreach ($encoded in $document.expected_resources.adapter_baseline_guids) {
            $identity = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$encoded, [ref]$identity) -or $identity -eq [Guid]::Empty) {
                throw "host qualification recovery adapter baseline identity is invalid: $path"
            }
        }
        [void]$ledgers.Add([pscustomobject]@{ path = $path; document = $document })
    }
    return $ledgers.ToArray()
}

function Assert-NoPendingFerrum2HostRecovery {
    $pending = @(Get-Ferrum2HostLedgers | Where-Object {
        [string]$_.document.state -notin @("cleaned", "recovered")
    })
    if ($pending.Count -ne 0) {
        throw "pending Ferrum2 host recovery ledger exists; run -RecoveryOnly"
    }
}

function Add-Ferrum2OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    $row = [pscustomobject][ordered]@{
        pid = $ProcessId
        purpose = $Purpose
        executable = [IO.Path]::GetFullPath($Executable)
        start_time_utc = $process.StartTime.ToUniversalTime().ToString("O")
    }
    $Context.ledger.resources.processes = @($Context.ledger.resources.processes) + @($row)
    Write-Ferrum2HostLedger -Context $Context
    return $row
}

function Remove-Ferrum2OwnedProcessRecord {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][int]$ProcessId
    )
    $Context.ledger.resources.processes = @($Context.ledger.resources.processes | Where-Object {
        [int]$_.pid -ne $ProcessId
    })
    Write-Ferrum2HostLedger -Context $Context
}

function Assert-Ferrum2ProcessIdentity {
    param([Parameter(Mandatory = $true)][object]$Row)
    $process = Get-Process -Id ([int]$Row.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    $path = [string]$process.Path
    if ([string]::IsNullOrWhiteSpace($path)) {
        $cim = Get-CimInstance -ClassName Win32_Process `
            -Filter "ProcessId = $([int]$Row.pid)" -ErrorAction SilentlyContinue
        if ($null -eq $cim -or [string]::IsNullOrWhiteSpace([string]$cim.ExecutablePath)) {
            throw "owned process executable identity is unavailable for PID $($Row.pid)"
        }
        $path = [string]$cim.ExecutablePath
    }
    $path = [IO.Path]::GetFullPath($path)
    $started = $process.StartTime.ToUniversalTime().ToString("O")
    if ($path -cne [IO.Path]::GetFullPath([string]$Row.executable) -or
        $started -cne [string]$Row.start_time_utc) {
        throw "process identity mismatch for owned PID $($Row.pid)"
    }
    return $process
}

function Stop-Ferrum2OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$TimeoutMilliseconds = 15000
    )
    $row = @($Context.ledger.resources.processes | Where-Object { [int]$_.pid -eq $ProcessId })
    if ($row.Count -ne 1) { throw "owned process record is not unique for PID $ProcessId" }
    $process = Assert-Ferrum2ProcessIdentity -Row $row[0]
    if ($null -ne $process) {
        $exitedGracefully = [Ferrum2HostProcessGroup]::Break([uint32]$ProcessId) -and
            [Ferrum2HostProcessGroup]::Wait(
                [uint32]$ProcessId, [uint32]$TimeoutMilliseconds)
        if (-not $exitedGracefully) {
            [void][Ferrum2HostProcessGroup]::Terminate([uint32]$ProcessId)
            if (-not [Ferrum2HostProcessGroup]::Wait(
                    [uint32]$ProcessId, [uint32]5000)) {
                throw "owned process did not terminate within the cleanup deadline"
            }
        }
    }
    [Ferrum2HostProcessGroup]::Close([uint32]$ProcessId)
    Remove-Ferrum2OwnedProcessRecord -Context $Context -ProcessId $ProcessId
}

function Restore-Ferrum2LegacyFirewallInterfaceIdentity {
    param([object]$Ledger, [string]$LedgerPath)
    $context = [pscustomobject]@{ ledger = $Ledger; ledger_path = $LedgerPath }
    foreach ($row in @($Ledger.resources.firewall_rules)) {
        $binding = $row.PSObject.Properties['interface_identity']
        if ($null -ne $binding -and $null -ne $binding.Value) { continue }
        $alias = [string]$row.interface_alias
        if ($alias -ceq 'Any') { continue }
        $adapters = @($Ledger.expected_resources.adapters | Where-Object {
            [string]$_.name -ceq $alias -and [string]$_.state -ceq 'created'
        })
        if ($adapters.Count -eq 0) { continue }
        $guids = @($adapters | ForEach-Object {
            ([Guid]$_.interface_guid).ToString('D').ToLowerInvariant()
        } | Sort-Object -Unique)
        if ($guids.Count -ne 1 -or $guids[0] -ceq [Guid]::Empty.ToString('D') -or
            $alias -cnotmatch ("^Ferrum2Host-" + [regex]::Escape([string]$Ledger.run_id) + "-00[1-3]$")) {
            throw 'legacy firewall adapter association is ambiguous'
        }
        $observed = @()
        $luid = $null
        foreach ($store in @('PersistentStore', 'ActiveStore')) {
            $rules = @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store | Where-Object {
                [string]$_.Name -ceq [string]$row.name
            })
            if ($rules.Count -gt 1) { throw 'legacy firewall rule identity is not unique' }
            if ($rules.Count -eq 0) { continue }
            $filters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rules[0] `
                -PolicyStore $store -ErrorAction Stop)
            if ($filters.Count -ne 1 -or @($filters[0].InterfaceAlias).Count -ne 1) {
                throw 'legacy firewall interface readback is ambiguous'
            }
            $representation = [string]$filters[0].InterfaceAlias
            $parsedGuid = [Guid]::Empty
            if ($representation -ceq $alias) {
                # This representation is already authorized by the original ledger.
            } elseif ([Guid]::TryParse($representation, [ref]$parsedGuid)) {
                if ($parsedGuid.ToString('D') -cne $guids[0]) { throw 'legacy firewall GUID differs from owned adapter' }
            } elseif ($representation -cmatch '^[1-9][0-9]*$') {
                [uint64]$parsedLuid = 0
                if (-not [uint64]::TryParse($representation, [ref]$parsedLuid) -or
                    ([Ferrum2QualificationRouteNotification]::InterfaceGuid($parsedLuid)).ToString('D') -cne $guids[0] -or
                    ($null -ne $luid -and $luid -cne $representation)) {
                    throw 'legacy firewall LUID cannot be bound to the owned adapter GUID'
                }
                $luid = $representation
            } else { throw 'legacy firewall interface representation is foreign' }
            $observed += [pscustomobject]@{ store = $store; rule = $rules[0] }
        }
        if ($observed.Count -eq 0) { continue }
        if ($observed.Count -ne 2) { throw 'legacy firewall policy stores disagree on rule presence' }
        $upgraded = $row.PSObject.Copy()
        $identity = [pscustomobject]@{
            alias = $alias; guid = $guids[0]; luid = $luid; recovered_from_legacy_ledger = $true
        }
        $upgraded | Add-Member -NotePropertyName interface_identity -NotePropertyValue $identity -Force
        foreach ($entry in $observed) {
            Assert-Ferrum2FirewallRuleMatches -Rule $entry.rule -Row $upgraded -PolicyStore $entry.store
        }
        Save-Ferrum2FirewallIdentity -Context $context -Row $upgraded
    }
}

function Initialize-Ferrum2RecoveryNetworkIdentity {
    param([object]$Ledger)
    $family = Get-Ferrum2LedgerAddressFamily -Ledger $Ledger
    foreach ($kind in @('addresses', 'routes')) {
        $type = $(if ($kind -ceq 'addresses') { 'address' } else { 'route' })
        foreach ($row in @($Ledger.resources.$kind) + @($Ledger.expected_resources.$kind)) {
            Assert-Ferrum2OwnedNetworkRow -Row $row -RunId $Ledger.run_id -AddressFamily $family -Type $type
            $row | Add-Member -NotePropertyName address_family -NotePropertyValue $family -Force
            $row | Add-Member -NotePropertyName run_id -NotePropertyValue $Ledger.run_id -Force
            if ($null -eq $row.PSObject.Properties['interface_guid']) {
                $ownedAdapters = @($Ledger.expected_resources.adapters | Where-Object {
                    [string]$_.state -ceq 'created' -and [uint32]$_.interface_index -eq [uint32]$row.interface_index
                })
                $identities = @($ownedAdapters | ForEach-Object { [string]$_.interface_guid } | Sort-Object -Unique)
                # A legacy physical-interface reset route has no durable GUID. Its absence
                # can be proven, but an occupied index alone never authorizes its deletion.
                $guid = $null
                if ($identities.Count -gt 1) { throw 'legacy network interface identity is ambiguous' }
                if ($identities.Count -eq 1) { $guid = $identities[0] }
                $row | Add-Member -NotePropertyName interface_guid -NotePropertyValue $guid
            }
        }
    }
}

function Remove-Ferrum2LedgerResources {
    param(
        [Parameter(Mandatory = $true)][object]$Ledger,
        [Parameter(Mandatory = $true)][string]$LedgerPath
    )
    Update-Ferrum2ExpectedResources -Ledger $Ledger
    Initialize-Ferrum2RecoveryNetworkIdentity -Ledger $Ledger
    Write-AtomicJsonFile -Path $LedgerPath -Document $Ledger
    Restore-Ferrum2LegacyFirewallInterfaceIdentity -Ledger $Ledger -LedgerPath $LedgerPath
    foreach ($row in @($Ledger.resources.processes)) {
        $process = Assert-Ferrum2ProcessIdentity -Row $row
        if ($null -ne $process) {
            Stop-Process -Id ([int]$row.pid) -Force -ErrorAction Stop
            [void]$process.WaitForExit(5000)
            if (-not $process.HasExited) { throw "owned process did not exit: $($row.pid)" }
        }
    }
    foreach ($row in @($Ledger.resources.firewall_rules)) {
        Remove-Ferrum2OwnedFirewallRule -Row $row
    }
    foreach ($row in @($Ledger.resources.routes)) {
        Remove-Ferrum2OwnedRoute -Row $row
    }
    # Exact address deletion shares the same ownership admission as ordinary cleanup.
    foreach ($row in @($Ledger.resources.addresses)) {
        Remove-Ferrum2OwnedAddress -Row $row
    }
    $adapterRow = $Ledger.resources.adapter
    if ($null -ne $adapterRow) {
        $adapterState = [string]$adapterRow.state
        if ($adapterState -notin @("planned", "created")) {
            throw "owned adapter ledger state is invalid"
        }
        $adapterInventory = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        if ($adapterInventory.Count -gt 4096) { throw 'adapter inventory exceeds its identity bound' }
        $adapters = @($adapterInventory | Where-Object { [string]$_.Name -ceq [string]$adapterRow.name })
        if ($adapters.Count -gt 1) { throw "owned adapter identity is not unique" }
        if ($adapters.Count -eq 1) {
            if ($adapterState -cne "created") {
                throw "planned adapter presence is ambiguous; refusing removal"
            }
            if ($null -eq $adapterRow.interface_guid) {
                throw "owned adapter GUID identity is unavailable"
            }
            $actualGuid = ([Guid]$adapters[0].InterfaceGuid).ToString("D").ToLowerInvariant()
            if ($null -ne $adapterRow.interface_guid -and
                $actualGuid -cne [string]$adapterRow.interface_guid) {
                throw "owned adapter GUID identity mismatch"
            }
            if ([string]$adapters[0].InterfaceDescription -cne
                [string]$adapterRow.expected_interface_description) {
                throw "owned adapter driver identity mismatch"
            }
            $pnpId = [string]$adapters[0].PnPDeviceID
            if ([string]::IsNullOrWhiteSpace($pnpId)) {
                throw "owned adapter PnP identity is unavailable"
            }
            & "$env:SystemRoot\System32\pnputil.exe" /remove-device $pnpId | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "exact owned adapter removal failed" }
        }
    }
    $readback = Get-Ferrum2HostCleanupReadback -Ledger $Ledger
    $Ledger.resources.processes = @()
    $Ledger.resources.routes = @()
    $Ledger.resources.addresses = @()
    $Ledger.resources.ports = @()
    $Ledger.resources.firewall_rules = @()
    $Ledger.resources.adapter = $null
    $Ledger.state = "recovered"
    $Ledger.recovery.attempts = [int]$Ledger.recovery.attempts + 1
    $Ledger.recovery.last_error = $null
    Write-AtomicJsonFile -Path $LedgerPath -Document $Ledger
    return $readback
}

function Invoke-Ferrum2HostRecovery {
    $ledgers = @(Get-Ferrum2HostLedgers | Where-Object {
        [string]$_.document.state -notin @("cleaned", "recovered")
    })
    if ($ledgers.Count -eq 0) {
        return [pscustomobject][ordered]@{ status = "PASS"; pending = 0; recovered = 0 }
    }
    if (-not (Test-Ferrum2HostAdministrator)) {
        throw "pending host network recovery requires an elevated PowerShell process"
    }
    $recovered = 0
    foreach ($entry in $ledgers) {
        try {
            [void](Remove-Ferrum2LedgerResources -Ledger $entry.document -LedgerPath $entry.path)
            Remove-Ferrum2HostRunRoot `
                -RunRoot (Split-Path -Parent $entry.path) `
                -RunId ([string]$entry.document.run_id)
            $recovered += 1
        } catch {
            $entry.document.recovery.attempts = [int]$entry.document.recovery.attempts + 1
            $entry.document.recovery.last_error = [string]$_.Exception.Message
            Write-AtomicJsonFile -Path $entry.path -Document $entry.document
            throw
        }
    }
    return [pscustomobject][ordered]@{
        status = "PASS"
        pending = $ledgers.Count
        recovered = $recovered
    }
}

function Complete-Ferrum2HostCleanup {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][bool]$Succeeded
    )
    try {
        [Ferrum2HostProcessGroup]::CloseGroup()
        Start-Sleep -Milliseconds 300
        $readback = Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
        $Context.ledger.state = "cleaned"
        $Context.ledger.recovery.last_error = $null
        Write-Ferrum2HostLedger -Context $Context
        Remove-Ferrum2HostRunRoot -RunRoot $Context.run_root `
            -RunId $Context.run_id
    } catch {
        $Context.ledger.state = "recovery_required"
        $Context.ledger.recovery.last_error = [string]$_.Exception.Message
        Write-Ferrum2HostLedger -Context $Context
        throw
    }
    $report = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-qualification-resource-cleanup"
        run_id = $Context.run_id
        address_family = Get-Ferrum2LedgerAddressFamily -Ledger $Context.ledger
        qualification_source_bundle_sha256 = $Context.qualification_source_bundle_sha256
        status = "PASS"
        qualification_succeeded = $Succeeded
        adapter_remaining = $readback.adapter_remaining
        routes_remaining = $readback.routes_remaining
        addresses_remaining = $readback.addresses_remaining
        processes_remaining = $readback.processes_remaining
        ports_remaining = $readback.ports_remaining
        firewall_rule_remaining = $readback.firewall_rule_remaining
        completed_utc = [DateTime]::UtcNow.ToString("O")
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "cleanup.json") `
        -Document $report
    return $report
}
