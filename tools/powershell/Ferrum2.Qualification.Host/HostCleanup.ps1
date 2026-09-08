Set-StrictMode -Version Latest

function Get-Ferrum2HostAdapterBaseline {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    if ($adapters.Count -gt 4096) { throw 'adapter baseline exceeds its identity bound' }
    $guids = [Collections.Generic.HashSet[Guid]]::new()
    foreach ($adapter in $adapters) {
        $identity = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$adapter.InterfaceGuid, [ref]$identity) -or
            $identity -eq [Guid]::Empty -or -not $guids.Add($identity)) {
            throw 'adapter baseline identity is unavailable or ambiguous'
        }
    }
    return @($guids | ForEach-Object { $_.ToString('D') } | Sort-Object)
}

# Expected identities survive retirement from the actionable recovery ledger. Copies also
# preserve the pre-mutation intent if creation or identity completion subsequently fails.
function Update-Ferrum2ExpectedResources {
    param([Parameter(Mandatory = $true)][object]$Ledger)
    # Old ledgers predate owned firewall rules; preserve their recoverability.
    foreach ($owner in @($Ledger.resources, $Ledger.expected_resources)) {
        if ($null -eq $owner.PSObject.Properties['firewall_rules']) {
            $owner | Add-Member -NotePropertyName firewall_rules -NotePropertyValue @()
        }
    }
    foreach ($kind in @('processes', 'adapters', 'addresses', 'routes', 'ports')) {
        $active = if ($kind -ceq 'adapters') {
            @($Ledger.resources.adapter | Where-Object { $null -ne $_ })
        } else { @($Ledger.resources.$kind) }
        $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($row in @($Ledger.expected_resources.$kind) + $active) {
            $encoded = ConvertTo-Json -InputObject $row -Depth 10 -Compress
            if ($identities.Add($encoded)) {
                [void]$rows.Add((ConvertFrom-Json -InputObject $encoded -Depth 10))
            }
        }
        $Ledger.expected_resources.$kind = $rows.ToArray()
    }
}

function Get-Ferrum2CleanupProcessBirthTicks {
    param([object]$Row)
    $birth = [DateTime]::MinValue
    $valid = $false
    if ($Row.start_time_utc -is [DateTime]) {
        # PowerShell 7.6 ConvertFrom-Json materializes ISO timestamps as DateTime.
        $birth = $Row.start_time_utc
        $valid = $true
    } elseif ($Row.start_time_utc -is [string]) {
        $valid = [DateTime]::TryParseExact($Row.start_time_utc,
            [string[]]@('O', "yyyy-MM-dd'T'HH:mm:ssK"),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$birth)
    }
    if (-not $valid -or $birth.Kind -ne [DateTimeKind]::Utc -or $birth -eq [DateTime]::MinValue) {
        throw ("cleanup process birth identity is unavailable or invalid: " +
            (ConvertTo-Json -InputObject $Row -Depth 5 -Compress))
    }
    return $birth.Ticks
}

# This provider performs only enumeration. Unlike filtered cmdlets with suppressed errors,
# an empty successful enumeration establishes absence; failed reads never establish zero.
function Get-Ferrum2HostCleanupSnapshot {
    param([Parameter(Mandatory = $true)][object]$Expected)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $routes = @(foreach ($family in @('IPv4', 'IPv6')) {
        Get-NetRoute -AddressFamily $family -PolicyStore ActiveStore -ErrorAction Stop
    })
    $addresses = @(foreach ($family in @('IPv4', 'IPv6')) {
        Get-NetIPAddress -AddressFamily $family -PolicyStore ActiveStore -ErrorAction Stop
    })
    if ($adapters.Count -gt 4096 -or $routes.Count -gt 65536 -or $addresses.Count -gt 16384) {
        throw 'cleanup network inventory exceeds its identity bound'
    }
    $allProcesses = @(Get-Process -ErrorAction Stop)
    if ($allProcesses.Count -gt 65536) { throw 'cleanup process inventory exceeds its identity bound' }
    $processes = @($allProcesses | Where-Object {
        [int]$_.Id -in @($Expected.processes | ForEach-Object { [int]$_.pid })
    } | ForEach-Object {
        $process = $_
        try {
            $start = $process.StartTime.ToUniversalTime().ToString('O')
        } catch {
            throw "cleanup process birth readback failed: pid=$($process.Id); executable=not-read-before-birth; error=$($_.Exception.Message)"
        }
        $identity = [pscustomobject]@{
            pid = [int]$process.Id; start_time_utc = $start; executable = $null
        }
        $birth = Get-Ferrum2CleanupProcessBirthTicks -Row $identity
        $sameLifetime = @($Expected.processes | Where-Object {
            [int]$_.pid -eq $identity.pid -and
            (Get-Ferrum2CleanupProcessBirthTicks -Row $_) -eq $birth
        })
        if ($sameLifetime.Count -ne 0) {
            try {
                $path = [string]$process.Path
                if ([string]::IsNullOrWhiteSpace($path)) { throw 'executable path is unavailable' }
                $identity.executable = [IO.Path]::GetFullPath($path)
            } catch {
                throw ("cleanup owned-lifetime executable readback failed: " +
                    (ConvertTo-Json -InputObject $identity -Compress) + "; error=$($_.Exception.Message)")
            }
        }
        $identity
    })
    $ports = @(
        Get-NetTCPConnection -ErrorAction Stop | Where-Object State -EQ Listen |
            ForEach-Object {
                [pscustomobject]@{ protocol = 'tcp'; address = [string]$_.LocalAddress; port = [int]$_.LocalPort }
            }
        Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ protocol = 'udp'; address = [string]$_.LocalAddress; port = [int]$_.LocalPort }
        }
    )
    if ($ports.Count -gt 131072) { throw 'cleanup endpoint inventory exceeds its identity bound' }
    return [pscustomobject]@{
        adapters = $adapters; routes = $routes; addresses = $addresses
        processes = $processes; ports = $ports
    }
}

# Pure readback reducer: every collection must come from a successful observation. This
# never authorizes removal of a replacement resource or of an occupied historical port.
function Measure-Ferrum2HostCleanupResidue {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Snapshot
    )
    foreach ($kind in @('adapters', 'routes', 'addresses', 'processes', 'ports')) {
        if ($null -eq $Snapshot.$kind -or $null -eq $Expected.$kind) {
            throw "cleanup $kind readback is unavailable"
        }
    }
    foreach ($kind in @('addresses', 'routes')) {
        foreach ($row in $Expected.$kind) {
            if ($null -ne $row.PSObject.Properties['run_id']) {
                $type = $(if ($kind -ceq 'addresses') { 'address' } else { 'route' })
                Assert-Ferrum2OwnedNetworkRow -Row $row -RunId $row.run_id -AddressFamily $row.address_family -Type $type
            }
        }
    }
    foreach ($port in $Expected.ports) {
        if ([string]$port.protocol -notin @('tcp', 'udp')) { throw 'owned port protocol is invalid' }
    }
    $adapterNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $adapterGuids = [Collections.Generic.HashSet[Guid]]::new()
    $baselineGuids = [Collections.Generic.HashSet[Guid]]::new()
    if ($null -eq $Expected.adapter_baseline_guids -or
        @($Expected.adapter_baseline_guids).Count -gt 4096) {
        throw 'cleanup adapter baseline is unavailable or exceeds its identity bound'
    }
    foreach ($encoded in $Expected.adapter_baseline_guids) {
        $identity = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$encoded, [ref]$identity) -or
            $identity -eq [Guid]::Empty -or -not $baselineGuids.Add($identity)) {
            throw 'cleanup adapter baseline identity is invalid'
        }
    }
    $unresolvedAdapterIntent = $false
    foreach ($row in $Expected.adapters) {
        if ([string]::IsNullOrWhiteSpace([string]$row.name) -or
            [string]$row.state -notin @('planned', 'created')) {
            throw 'cleanup expected adapter identity is invalid'
        }
        [void]$adapterNames.Add([string]$row.name)
        if ([string]$row.state -ceq 'planned') {
            # The journal retains the original plan as well as its completed identity.
            if (@($Expected.adapters | Where-Object {
                [string]$_.name -ieq [string]$row.name -and [string]$_.state -ceq 'created'
            }).Count -eq 0) { $unresolvedAdapterIntent = $true }
            continue
        }
        $expectedGuid = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$row.interface_guid, [ref]$expectedGuid) -or
            $expectedGuid -eq [Guid]::Empty) {
            throw 'cleanup expected adapter GUID is unavailable'
        }
        [void]$adapterGuids.Add($expectedGuid)
    }
    $adapterCount = 0
    if ($adapterNames.Count -ne 0) {
        foreach ($actual in $Snapshot.adapters) {
            $actualGuid = [Guid]::Empty
            if ([string]::IsNullOrWhiteSpace([string]$actual.Name) -or
                -not [Guid]::TryParse([string]$actual.InterfaceGuid, [ref]$actualGuid) -or
                $actualGuid -eq [Guid]::Empty) {
                throw 'cleanup observed adapter identity is unavailable'
            }
            if ($adapterGuids.Contains($actualGuid) -or $adapterNames.Contains([string]$actual.Name)) {
                $adapterCount += 1
            }
            if ($unresolvedAdapterIntent -and -not $baselineGuids.Contains($actualGuid)) {
                throw 'cleanup unresolved adapter intent has an unknown new GUID'
            }
        }
    }
    $routeCount = 0
    foreach ($actual in $Snapshot.routes) {
        if (@($Expected.routes | Where-Object {
            [string]$_.destination_prefix -ceq [string]$actual.DestinationPrefix -and
            [uint32]$_.interface_index -eq [uint32]$actual.InterfaceIndex
        }).Count -ne 0) { $routeCount += 1 }
    }
    $addressCount = 0
    foreach ($actual in $Snapshot.addresses) {
        if (@($Expected.addresses | Where-Object {
            [string]$_.address -ceq [string]$actual.IPAddress -and
            [uint32]$_.interface_index -eq [uint32]$actual.InterfaceIndex
        }).Count -ne 0) { $addressCount += 1 }
    }
    $processCount = 0
    foreach ($row in $Expected.processes) {
        [void](Get-Ferrum2CleanupProcessBirthTicks -Row $row)
    }
    foreach ($actual in $Snapshot.processes) {
        $matching = @($Expected.processes | Where-Object { [int]$_.pid -eq [int]$actual.pid })
        if ($matching.Count -ne 0) {
            $birth = Get-Ferrum2CleanupProcessBirthTicks -Row $actual
            $sameLifetime = @($matching | Where-Object {
                (Get-Ferrum2CleanupProcessBirthTicks -Row $_) -eq $birth
            })
            if ($sameLifetime.Count -eq 0) { continue }
            if ([string]::IsNullOrWhiteSpace([string]$actual.executable) -or
                @($sameLifetime | Where-Object {
                    [string]$_.executable -ceq [string]$actual.executable
                }).Count -eq 0) {
                throw ("cleanup process executable differs within the owned lifetime: " +
                    (ConvertTo-Json -InputObject ([pscustomobject]@{
                        actual = $actual; expected = $sameLifetime
                    }) -Depth 5 -Compress))
            }
            $processCount += 1
        }
    }
    $portCount = 0
    foreach ($actual in $Snapshot.ports) {
        if (@($Expected.ports | Where-Object {
            [string]$_.protocol -ceq [string]$actual.protocol -and
            [uint16]$_.port -eq [uint16]$actual.port -and
            ([string]$_.address -ceq [string]$actual.address -or
                [string]$actual.address -in @('0.0.0.0', '::'))
        }).Count -ne 0) { $portCount += 1 }
    }
    return [pscustomobject][ordered]@{
        adapter_remaining = $adapterCount
        routes_remaining = $routeCount
        addresses_remaining = $addressCount
        processes_remaining = $processCount
        ports_remaining = $portCount
    }
}

function Get-Ferrum2HostCleanupReadback {
    param([Parameter(Mandatory = $true)][object]$Ledger)
    $snapshot = Get-Ferrum2HostCleanupSnapshot -Expected $Ledger.expected_resources
    $residue = Measure-Ferrum2HostCleanupResidue -Expected $Ledger.expected_resources -Snapshot $snapshot
    $firewallCount = Get-Ferrum2FirewallRuleResidue -Expected @($Ledger.expected_resources.firewall_rules)
    $residue | Add-Member -NotePropertyName firewall_rule_remaining -NotePropertyValue $firewallCount
    if (@($residue.PSObject.Properties | Where-Object { [int]$_.Value -ne 0 }).Count -ne 0) {
        throw 'owned resource identities remain occupied after cleanup'
    }
    return $residue
}
