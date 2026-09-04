Set-StrictMode -Version Latest

function Test-Ferrum2HostPerformanceAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Ferrum2HostPerformanceAuthorization {
    param([Parameter(Mandatory = $true)][bool]$Acknowledged)
    if (-not (Test-Ferrum2HostPerformanceAdministrator)) {
        throw "host performance execution requires an already elevated PowerShell process"
    }
    if (-not $Acknowledged) {
        throw "host performance execution requires -AcknowledgeHostNetworkMutation"
    }
}

function Get-Ferrum2HostPerformanceRoot {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the host performance recovery root"
    }
    return Join-Path $env:LOCALAPPDATA "Ferrum2\host-performance"
}

function Remove-Ferrum2HostPerformanceRunRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )
    if ($RunId -cnotmatch '^[0-9a-f]{12}$') {
        throw "host performance RunId is invalid"
    }
    $recoveryRoot = [IO.Path]::GetFullPath((Get-Ferrum2HostPerformanceRoot))
    $expectedRunRoot = [IO.Path]::GetFullPath((Join-Path $recoveryRoot $RunId))
    $actualRunRoot = [IO.Path]::GetFullPath($RunRoot)
    if (-not $actualRunRoot.Equals($expectedRunRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "host performance run root identity is invalid"
    }
    if (-not (Test-Path -LiteralPath $actualRunRoot)) {
        return
    }
    $item = Get-Item -LiteralPath $actualRunRoot -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "host performance run root is not a plain directory"
    }
    Remove-Item -LiteralPath $actualRunRoot -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $actualRunRoot) {
        throw "host performance run root remains after cleanup"
    }
}

function Enter-Ferrum2HostPerformanceMutex {
    $created = $false
    $mutex = [Threading.Mutex]::new($true, "Global\Ferrum2HostPerformance", [ref]$created)
    if (-not $created) {
        $mutex.Dispose()
        throw "another Ferrum2 host-performance run owns the global mutex"
    }
    return $mutex
}

function Exit-Ferrum2HostPerformanceMutex {
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

function Write-Ferrum2HostPerformanceLedger {
    param([Parameter(Mandatory = $true)][object]$Context)
    $Context.ledger.updated_utc = [DateTime]::UtcNow.ToString("O")
    Write-AtomicJsonFile -Path $Context.ledger_path -Document $Context.ledger
}

function New-Ferrum2HostPerformanceContext {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$BaselineSha,
        [Parameter(Mandatory = $true)][string]$CandidateSha
    )
    $runId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $recoveryRoot = Get-Ferrum2HostPerformanceRoot
    $runRoot = Join-Path $recoveryRoot $runId
    if (Test-Path -LiteralPath $runRoot) {
        throw "generated host performance RunId already exists"
    }
    New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
    $evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
    if (Test-Path -LiteralPath $evidence) {
        throw "host performance evidence directory baseline must be absent"
    }
    New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
    $ledger = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-performance-recovery"
        run_id = $runId
        state = "initializing"
        mode = $Mode
        baseline_sha = $BaselineSha
        candidate_sha = $CandidateSha
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
        }
        recovery = [pscustomobject][ordered]@{
            attempts = 0
            last_error = $null
        }
    }
    $context = [pscustomobject]@{
        run_id = $runId
        run_root = $runRoot
        ledger_path = Join-Path $runRoot "recovery.json"
        repository_root = [IO.Path]::GetFullPath($RepositoryRoot)
        evidence_directory = $evidence
        ledger = $ledger
    }
    Write-Ferrum2HostPerformanceLedger -Context $context
    return $context
}

function Set-Ferrum2HostPerformanceState {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$State
    )
    $Context.ledger.state = $State
    Write-Ferrum2HostPerformanceLedger -Context $Context
}

function Get-Ferrum2HostPerformanceLedgers {
    $root = Get-Ferrum2HostPerformanceRoot
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "host performance recovery root must not be a reparse point"
    }
    $rows = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)
    if ($rows.Count -gt 128) {
        throw "host performance recovery root exceeds 128 run directories"
    }
    $ledgers = [Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        if ($row.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "host performance recovery directory must not be a reparse point"
        }
        $path = Join-Path $row.FullName "recovery.json"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt 1MB -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "host performance recovery ledger is invalid: $path"
        }
        $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -Depth 20 -ErrorAction Stop
        if ($document.schema_version -ne 1 -or
            [string]$document.kind -cne "ferrum2.windows-tun.host-performance-recovery" -or
            [string]$document.run_id -cne $row.Name -or
            [string]$document.run_id -cnotmatch '^[0-9a-f]{12}$') {
            throw "host performance recovery ledger identity is invalid: $path"
        }
        [void]$ledgers.Add([pscustomobject]@{ path = $path; document = $document })
    }
    return $ledgers.ToArray()
}

function Assert-NoPendingFerrum2HostPerformanceRecovery {
    $pending = @(Get-Ferrum2HostPerformanceLedgers | Where-Object {
        [string]$_.document.state -notin @("cleaned", "recovered")
    })
    if ($pending.Count -ne 0) {
        throw "pending Ferrum2 host-performance recovery ledger exists; run -RecoveryOnly"
    }
}

function New-Ferrum2HostNetworkIdentity {
    param([Parameter(Mandatory = $true)][string]$RunId)
    $value = [Convert]::ToUInt32($RunId.Substring(0, 4), 16)
    $third = [int](($value -shr 8) -band 0xff)
    $block = [int](($value -band 0xff) % 63) * 4
    return [pscustomobject][ordered]@{
        tun_address = "198.18.$third.$($block + 2)"
        tun_prefix_length = 30
        support_address = "198.19.$third.$($block + 1)"
        support_prefix_length = 32
        adapter_name_prefix = "Ferrum2Perf-$RunId"
    }
}

function Get-Ferrum2LoopbackIdentity {
    $address = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress "127.0.0.1" -ErrorAction Stop)
    if ($address.Count -ne 1) {
        throw "host loopback IPv4 identity is not unique"
    }
    $interface = @(Get-NetIPInterface -AddressFamily IPv4 `
        -InterfaceIndex $address[0].InterfaceIndex -ErrorAction Stop)
    if ($interface.Count -ne 1 -or [string]$interface[0].InterfaceAlias -cnotlike "Loopback*") {
        throw "host loopback interface identity is not unique"
    }
    return [pscustomobject][ordered]@{
        interface_index = [uint32]$interface[0].InterfaceIndex
        interface_alias = [string]$interface[0].InterfaceAlias
        interface_guid = $null
        local_address = "127.0.0.1"
    }
}

function Assert-Ferrum2HostNetworkIdentityAvailable {
    param(
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    foreach ($address in @($Network.tun_address, $Network.support_address)) {
        if (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $address -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "dedicated benchmark address already exists: $address"
        }
    }
    foreach ($prefix in @("$($Network.support_address)/32")) {
        if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "dedicated benchmark route already exists: $prefix"
        }
    }
    if ($Loopback.interface_index -eq 0 -or $Loopback.local_address -cne "127.0.0.1") {
        throw "loopback identity is invalid"
    }
    $wide = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        [string]$_.DestinationPrefix -in @("198.18.0.0/15", "198.18.0.0/16", "198.19.0.0/16")
    })
    if ($wide.Count -ne 0) {
        throw "a broad RFC2544 route conflicts with the dedicated benchmark range"
    }
}

function Add-Ferrum2OwnedAddress {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$PrefixLength
    )
    $row = [pscustomobject][ordered]@{
        address = $Address
        prefix_length = $PrefixLength
        interface_index = $Loopback.interface_index
        interface_guid = $Loopback.interface_guid
        state = "planned"
    }
    $Context.ledger.resources.addresses = @($Context.ledger.resources.addresses) + @($row)
    Write-Ferrum2HostPerformanceLedger -Context $Context
    New-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $Loopback.interface_index `
        -IPAddress $Address -PrefixLength $PrefixLength -SkipAsSource $true `
        -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $row.state = "created"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    return $row
}

function Add-Ferrum2OwnedRoute {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][uint32]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$DestinationPrefix,
        [Parameter(Mandatory = $true)][uint16]$RouteMetric,
        [string]$Kind = "runner"
    )
    $row = [pscustomobject][ordered]@{
        destination_prefix = $DestinationPrefix
        interface_index = $InterfaceIndex
        next_hop = "0.0.0.0"
        route_metric = $RouteMetric
        policy_store = "ActiveStore"
        kind = $Kind
        state = "planned"
    }
    $Context.ledger.resources.routes = @($Context.ledger.resources.routes) + @($row)
    Write-Ferrum2HostPerformanceLedger -Context $Context
    New-NetRoute -AddressFamily IPv4 -InterfaceIndex $InterfaceIndex `
        -DestinationPrefix $DestinationPrefix -NextHop "0.0.0.0" `
        -RouteMetric $RouteMetric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $row.state = "created"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    return $row
}

function Set-Ferrum2OwnedAdapterPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$AdapterName
    )
    if (@(Get-NetAdapter -IncludeHidden -Name $AdapterName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "owned adapter name baseline is not absent: $AdapterName"
    }
    $Context.ledger.resources.adapter = [pscustomobject][ordered]@{
        name = $AdapterName
        interface_guid = $null
        interface_index = $null
        interface_description = $null
        expected_interface_description = "Ferrum2 Tunnel"
        state = "planned"
    }
    Write-Ferrum2HostPerformanceLedger -Context $Context
}

function Complete-Ferrum2OwnedAdapterIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$AdapterName
    )
    $adapter = @(Get-NetAdapter -IncludeHidden -Name $AdapterName -ErrorAction Stop)
    if ($adapter.Count -ne 1) {
        throw "owned Wintun adapter identity is not unique"
    }
    if ([string]$adapter[0].InterfaceDescription -cne "Ferrum2 Tunnel") {
        throw "owned adapter does not identify the Wintun driver"
    }
    $Context.ledger.resources.adapter.interface_guid =
        ([Guid]$adapter[0].InterfaceGuid).ToString("D").ToLowerInvariant()
    $Context.ledger.resources.adapter.interface_index = [uint32]$adapter[0].ifIndex
    $Context.ledger.resources.adapter.interface_description = [string]$adapter[0].InterfaceDescription
    $Context.ledger.resources.adapter.state = "created"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    return $adapter[0]
}

function Add-Ferrum2OwnedPort {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][uint16]$Port,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $Context.ledger.resources.ports = @($Context.ledger.resources.ports) + @(
        [pscustomobject][ordered]@{
            protocol = $Protocol
            address = $Address
            port = $Port
            purpose = $Purpose
        }
    )
    Write-Ferrum2HostPerformanceLedger -Context $Context
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
    Write-Ferrum2HostPerformanceLedger -Context $Context
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
    Write-Ferrum2HostPerformanceLedger -Context $Context
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
        [void][Ferrum2PerfProcessGroup]::Terminate([uint32]$ProcessId)
        if (-not [Ferrum2PerfProcessGroup]::Wait(
                [uint32]$ProcessId, [uint32]$TimeoutMilliseconds)) {
            throw "owned process did not terminate within the cleanup deadline"
        }
    }
    [Ferrum2PerfProcessGroup]::Close([uint32]$ProcessId)
    Remove-Ferrum2OwnedProcessRecord -Context $Context -ProcessId $ProcessId
}

function Remove-Ferrum2LedgerResources {
    param(
        [Parameter(Mandatory = $true)][object]$Ledger,
        [Parameter(Mandatory = $true)][string]$LedgerPath
    )
    foreach ($row in @($Ledger.resources.processes)) {
        $process = Assert-Ferrum2ProcessIdentity -Row $row
        if ($null -ne $process) {
            Stop-Process -Id ([int]$row.pid) -Force -ErrorAction Stop
            $process.WaitForExit(5000)
            if (-not $process.HasExited) { throw "owned process did not exit: $($row.pid)" }
        }
    }
    foreach ($row in @($Ledger.resources.routes)) {
        $routeState = [string]$row.state
        if ($routeState -notin @("planned", "created")) {
            throw "owned route ledger state is invalid"
        }
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix ([string]$row.destination_prefix) `
            -InterfaceIndex ([uint32]$row.interface_index) -ErrorAction SilentlyContinue | Where-Object {
                [string]$_.NextHop -ceq [string]$row.next_hop
            })
        if ($routes.Count -gt 1) { throw "owned route identity is not unique" }
        if ($routes.Count -eq 1) {
            if ($routeState -cne "created") {
                throw "planned route presence is ambiguous; refusing removal"
            }
            if ([uint16]$routes[0].RouteMetric -ne [uint16]$row.route_metric) {
                throw "owned route metric identity mismatch"
            }
            Remove-NetRoute -InputObject $routes[0] -Confirm:$false -ErrorAction Stop
        }
    }
    foreach ($row in @($Ledger.resources.addresses)) {
        $addressState = [string]$row.state
        if ($addressState -notin @("planned", "created")) {
            throw "owned address ledger state is invalid"
        }
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress ([string]$row.address) `
            -InterfaceIndex ([uint32]$row.interface_index) -ErrorAction SilentlyContinue)
        if ($addresses.Count -gt 1) { throw "owned address identity is not unique" }
        if ($addresses.Count -eq 1) {
            if ($addressState -cne "created") {
                throw "planned address presence is ambiguous; refusing removal"
            }
            if ([int]$addresses[0].PrefixLength -ne [int]$row.prefix_length) {
                throw "owned address prefix identity mismatch"
            }
            Remove-NetIPAddress -InputObject $addresses[0] -Confirm:$false -ErrorAction Stop
        }
    }
    $adapterRow = $Ledger.resources.adapter
    if ($null -ne $adapterRow) {
        $adapterState = [string]$adapterRow.state
        if ($adapterState -notin @("planned", "created")) {
            throw "owned adapter ledger state is invalid"
        }
        $adapters = @(Get-NetAdapter -IncludeHidden -Name ([string]$adapterRow.name) `
            -ErrorAction SilentlyContinue)
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
    foreach ($row in @($Ledger.resources.ports)) {
        if ([string]$row.protocol -ceq "tcp") {
            $listeners = @(Get-NetTCPConnection -State Listen -LocalPort ([uint16]$row.port) `
                -ErrorAction SilentlyContinue)
            if ($listeners.Count -ne 0) { throw "owned TCP port remains in use: $($row.port)" }
        } else {
            $listeners = @(Get-NetUDPEndpoint -LocalPort ([uint16]$row.port) `
                -ErrorAction SilentlyContinue)
            if ($listeners.Count -ne 0) { throw "owned UDP port remains in use: $($row.port)" }
        }
    }
    if ($null -ne $adapterRow -and
        @(Get-NetAdapter -IncludeHidden -Name ([string]$adapterRow.name) `
            -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "owned adapter remains after cleanup"
    }
    $Ledger.resources.processes = @()
    $Ledger.resources.routes = @()
    $Ledger.resources.addresses = @()
    $Ledger.resources.ports = @()
    $Ledger.resources.adapter = $null
    $Ledger.state = "recovered"
    $Ledger.recovery.attempts = [int]$Ledger.recovery.attempts + 1
    $Ledger.recovery.last_error = $null
    Write-AtomicJsonFile -Path $LedgerPath -Document $Ledger
}

function Invoke-Ferrum2HostPerformanceRecovery {
    $ledgers = @(Get-Ferrum2HostPerformanceLedgers | Where-Object {
        [string]$_.document.state -notin @("cleaned", "recovered")
    })
    if ($ledgers.Count -eq 0) {
        return [pscustomobject][ordered]@{ status = "PASS"; pending = 0; recovered = 0 }
    }
    if (-not (Test-Ferrum2HostPerformanceAdministrator)) {
        throw "pending host network recovery requires an elevated PowerShell process"
    }
    $recovered = 0
    foreach ($entry in $ledgers) {
        try {
            Remove-Ferrum2LedgerResources -Ledger $entry.document -LedgerPath $entry.path
            Remove-Ferrum2HostPerformanceRunRoot `
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

function Complete-Ferrum2HostPerformanceCleanup {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][bool]$Succeeded
    )
    try {
        [Ferrum2PerfProcessGroup]::CloseGroup()
        Start-Sleep -Milliseconds 300
        Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
        $Context.ledger.state = "cleaned"
        $Context.ledger.recovery.last_error = $null
        Write-Ferrum2HostPerformanceLedger -Context $Context
        Remove-Ferrum2HostPerformanceRunRoot -RunRoot $Context.run_root `
            -RunId $Context.run_id
    } catch {
        $Context.ledger.state = "recovery_required"
        $Context.ledger.recovery.last_error = [string]$_.Exception.Message
        Write-Ferrum2HostPerformanceLedger -Context $Context
        throw
    }
    $report = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-performance-cleanup"
        run_id = $Context.run_id
        status = "PASS"
        benchmark_succeeded = $Succeeded
        adapter_remaining = 0
        routes_remaining = 0
        addresses_remaining = 0
        processes_remaining = 0
        ports_remaining = 0
        completed_utc = [DateTime]::UtcNow.ToString("O")
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "cleanup.json") `
        -Document $report
    return $report
}
