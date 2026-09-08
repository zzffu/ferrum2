# Firewall enforces Program by path, not by hash. The ledger hash is an ownership guard.
function Assert-Ferrum2FirewallExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.Length -gt 260 -or $Path -cnotmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2) -match '[:*?\[\]%"\x00-\x1f]' -or
        $Path -match '(^|\\)\.\.?($|\\)|[ .]($|\\)' -or
        [IO.Path]::GetFullPath($Path) -ine $Path -or [IO.Path]::GetExtension($Path) -ine '.exe') {
        throw 'Firewall executable must be a canonical, literal local executable path.'
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or [string]$item.FullName -ine $Path) { throw 'Firewall executable identity is not a plain file.' }
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Firewall executable path traverses a reparse point.'
        }
        if ($ancestor -is [IO.FileInfo]) { $ancestor = $ancestor.Directory } else { $ancestor = $ancestor.Parent }
    }
    return ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash).ToLowerInvariant()
}

function Assert-Ferrum2FirewallPort {
    param([string]$Port, [switch]$AllowAny)
    if ($AllowAny -and $Port -ceq 'Any') { return }
    if ($Port -cnotmatch '^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?$') { throw 'Firewall port scope is malformed.' }
    $bounds = $Port.Split('-')
    if ([int]$bounds[0] -gt 65535 -or ($bounds.Count -eq 2 -and
        ([int]$bounds[1] -gt 65535 -or [int]$bounds[1] -le [int]$bounds[0]))) {
        throw 'Firewall port scope is out of range.'
    }
}

function Get-Ferrum2FirewallInterfaceIdentity {
    param([Parameter(Mandatory = $true)][string]$Alias)
    if ([string]::IsNullOrWhiteSpace($Alias) -or $Alias.Length -gt 256 -or
        $Alias -ieq 'Any' -or $Alias -match '[*?\[\]`\x00-\x1f]') {
        throw 'Firewall interface alias is not literal.'
    }
    $luid = [Ferrum2QualificationRouteNotification]::InterfaceLuid([string]$Alias)
    $guid = [Ferrum2QualificationRouteNotification]::InterfaceGuid([uint64]$luid)
    if ($luid -eq 0 -or $guid -eq [Guid]::Empty) { throw 'Firewall interface identity is empty.' }
    return [pscustomobject][ordered]@{
        alias = $Alias
        guid = $guid.ToString('D').ToLowerInvariant()
        luid = $luid.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
}

function Assert-Ferrum2FirewallRow {
    param([Parameter(Mandatory = $true)][object]$Row)
    if ([string]$Row.name -cnotmatch '^Ferrum2-Qualification-[0-9a-f]{12}-[0-9a-f]{32}$' -or
        [string]$Row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Row.state -cnotin @('planned', 'created') -or
        [string]$Row.protocol -cnotin @('TCP', 'UDP') -or
        [string]$Row.profile -cne 'Domain,Private,Public') { throw 'Firewall ownership row is malformed.' }
    $family = $null
    foreach ($address in @([string]$Row.local_address, [string]$Row.remote_address)) {
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($address, [ref]$parsed) -or $parsed.ToString() -cne $address -or
            $parsed.IsIPv4MappedToIPv6 -or
            $parsed.Equals([Net.IPAddress]::Any) -or $parsed.Equals([Net.IPAddress]::IPv6Any) -or
            ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
                ($parsed.ScopeId -ne 0 -or $parsed.IsIPv6Multicast)) -or
            ($null -ne $family -and $parsed.AddressFamily -ne $family)) {
            throw 'Firewall addresses must be canonical, non-wildcard addresses of one family.'
        }
        $family = $parsed.AddressFamily
    }
    $addressFamily = if ($family -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { 'IPv6' } else { 'IPv4' }
    $declaredFamily = $Row.PSObject.Properties['address_family']
    if (($null -ne $declaredFamily -and $declaredFamily.Value -cne $addressFamily) -or
        ($addressFamily -ceq 'IPv6' -and $null -eq $declaredFamily)) {
        throw 'Firewall declared address family differs from its exact scope.'
    }
    Assert-Ferrum2FirewallPort -Port ([string]$Row.local_port)
    Assert-Ferrum2FirewallPort -Port ([string]$Row.remote_port) -AllowAny
    $phase = $Row.PSObject.Properties['interface_phase']
    $intended = $Row.PSObject.Properties['intended_interface_alias']
    if ($null -ne $phase -or $null -ne $intended) {
        if ($null -eq $phase -or $null -eq $intended -or
            [string]$phase.Value -cnotin @('prelaunch', 'narrowing', 'narrowed')) {
            throw 'Firewall interface transition is malformed.'
        }
        $runId = ([string]$Row.name).Split('-')[2]
        $network = New-Ferrum2HostNetworkIdentity -RunId $runId -AddressFamily $addressFamily
        $peer = $network.peer_address
        if ([string]$Row.purpose -cnotmatch '^client-ingress-([1-3])$') {
            throw 'Deferred firewall scope is not client ingress.'
        }
        $sequence = [int]$Matches[1]
        if ([string]$Row.protocol -cne 'TCP' -or [string]$Row.local_port -notmatch '^[0-9]+-[0-9]+$' -or
            [int](([string]$Row.local_port).Split('-')[0]) -lt 49152 -or
            [string]$Row.remote_port -cne 'Any' -or
            [string]$Row.local_address -cne $network.tun_address -or [string]$Row.remote_address -cne $peer -or
            [string]$intended.Value -cne "$($network.adapter_name_prefix)-$('{0:D3}' -f $sequence)") {
            throw 'Deferred firewall scope is not the exact run-owned client ingress scope.'
        }
        $expectedAlias = if ([string]$phase.Value -ceq 'narrowed') { [string]$intended.Value } else { 'Any' }
        if ([string]$Row.interface_alias -cne $expectedAlias -or
            ([string]$phase.Value -cne 'prelaunch' -and [string]$Row.state -cne 'created')) {
            throw 'Firewall interface phase and identity differ.'
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$Row.interface_alias) -or
        ([string]$Row.interface_alias).Length -gt 256 -or
        [string]$Row.interface_alias -match '[*?\[\]`\x00-\x1f]' -or
        ([string]$Row.interface_alias -ieq 'Any' -and $null -eq $phase) -or
        [string]::IsNullOrWhiteSpace([string]$Row.purpose) -or ([string]$Row.purpose).Length -gt 512) {
        throw 'Firewall interface or purpose scope is malformed.'
    }
    $identityMember = $Row.PSObject.Properties['interface_identity']
    if ($null -ne $identityMember -and $null -ne $identityMember.Value) {
        $identity = $identityMember.Value
        $expectedIdentityAlias = if ($null -ne $phase) { [string]$intended.Value } else { [string]$Row.interface_alias }
        $luid = [uint64]0
        $legacyMember = $identity.PSObject.Properties['recovered_from_legacy_ledger']
        $legacy = $null -ne $legacyMember -and $legacyMember.Value -is [bool] -and $legacyMember.Value
        if (($null -ne $phase -and [string]$phase.Value -ceq 'prelaunch') -or
            $null -eq $identity.PSObject.Properties['alias'] -or
            $null -eq $identity.PSObject.Properties['guid'] -or
            $null -eq $identity.PSObject.Properties['luid'] -or
            [string]$identity.alias -cne $expectedIdentityAlias -or
            [string]$identity.guid -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or
            [string]$identity.guid -ceq ([Guid]::Empty).ToString('D') -or
            ($null -ne $legacyMember -and $legacyMember.Value -isnot [bool]) -or
            ($null -eq $identity.luid -and -not $legacy) -or
            ($null -ne $identity.luid -and (
                [string]$identity.luid -cnotmatch '\A[1-9][0-9]{0,19}\z' -or
                -not [uint64]::TryParse([string]$identity.luid, [ref]$luid)))) {
            throw 'Firewall stable interface identity is malformed.'
        }
    }
}

function Get-Ferrum2FirewallRuleInventory {
    param([Parameter(Mandatory = $true)][ValidateSet('PersistentStore', 'ActiveStore')][string]$PolicyStore)
    # Enumerate successfully before deciding absence. A failed name query is not absence.
    $rows = [Collections.Generic.List[object]]::new()
    Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop | ForEach-Object {
        if ($rows.Count -ge 16384) { throw "Firewall $PolicyStore inventory exceeds the ownership bound." }
        $rows.Add($_)
    }
    return $rows.ToArray()
}

function Assert-Ferrum2FirewallValue {
    param([object]$Object, [string]$Property, [string[]]$Expected)
    $member = $Object.PSObject.Properties[$Property]
    if ($null -eq $member) { throw "Firewall readback lacks $Property." }
    $actual = @($member.Value | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $Expected.Count) { throw "Firewall readback differs at $Property." }
    for ($i = 0; $i -lt $actual.Count; $i++) {
        if ($actual[$i] -ine $Expected[$i]) { throw "Firewall readback differs at $Property." }
    }
}

function Assert-Ferrum2FirewallInterfaceFilter {
    param([object]$Filter, [object]$Row, [switch]$AllowInterfaceTransition)
    $member = $Filter.PSObject.Properties['InterfaceAlias']
    if ($null -eq $member -or @($member.Value).Count -ne 1) { throw 'Firewall interface readback is not unique.' }
    $actual = [string]@($member.Value)[0]
    $transition = $AllowInterfaceTransition -and $null -ne $Row.PSObject.Properties['interface_phase'] -and
        [string]$Row.interface_phase -ceq 'narrowing'
    if ($actual -ieq [string]$Row.interface_alias) { return }
    if ($transition -and $actual -ieq [string]$Row.intended_interface_alias) { return }
    # Prelaunch Any is not a binding. Stable representations are permitted only
    # for the final binding or the explicitly durable narrowing transition.
    if ([string]$Row.interface_alias -ieq 'Any' -and -not $transition) {
        throw 'Firewall interface scope differs.'
    }
    $identity = $Row.PSObject.Properties['interface_identity']
    if ($null -ne $identity -and $null -ne $identity.Value) {
        if ($null -ne $identity.Value.luid -and $actual -ceq [string]$identity.Value.luid) { return }
        if ($actual -match '\A([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})\z' -and
            ([Guid]$actual).ToString('D') -ceq [string]$identity.Value.guid) { return }
    }
    throw 'Firewall interface scope differs from its recorded identity.'
}

function Assert-Ferrum2FirewallConditions {
    param([object]$Rule, [object]$Row, [object]$Filters, [switch]$AllowInterfaceTransition)
    Assert-Ferrum2FirewallRow -Row $Row
    foreach ($pair in @(
        @('Name', [string]$Row.name), @('Enabled', 'True'), @('Direction', 'Inbound'),
        @('Action', 'Allow'), @('EdgeTraversalPolicy', 'Block'),
        @('LooseSourceMapping', 'False'), @('LocalOnlyMapping', 'False')
    )) { Assert-Ferrum2FirewallValue -Object $Rule -Property $pair[0] -Expected @($pair[1]) }
    # Profile is a flags enum; its formatted representation contains comma-separated names.
    $profiles = @(([string]$Rule.Profile).Split(',') | ForEach-Object { $_.Trim() } | Sort-Object)
    if (($profiles -join ',') -cne 'Domain,Private,Public') { throw 'Firewall profile scope differs.' }
    foreach ($property in @('Owner', 'PackageFamilyName', 'PolicyAppId', 'RemoteDynamicKeywordAddresses', 'Platform', 'Platforms', 'Group')) {
        $member = $Rule.PSObject.Properties[$property]
        if ($null -ne $member -and @($member.Value | Where-Object { -not [string]::IsNullOrEmpty([string]$_) }).Count -ne 0) {
            throw "Firewall unexpected expansion at $property."
        }
    }
    foreach ($kind in @('Application', 'Address', 'Port', 'Interface', 'InterfaceType', 'Service', 'Security')) {
        $filter = $Filters.$kind
        if ($null -eq $filter) { throw "Firewall readback lacks $kind filter." }
        $negated = $filter.PSObject.Properties['IsNegated']
        if ($null -ne $negated -and $null -ne $negated.Value -and [string]$negated.Value -notin @('', 'False')) {
            throw "Firewall $kind filter is negated."
        }
    }
    Assert-Ferrum2FirewallValue -Object $filters.Application -Property Program -Expected @([string]$Row.program)
    $package = $filters.Application.PSObject.Properties['Package']
    if ($null -eq $package -or [string]$package.Value -notin @('', 'Any')) { throw 'Firewall package scope differs.' }
    Assert-Ferrum2FirewallValue -Object $filters.Address -Property LocalAddress -Expected @([string]$Row.local_address)
    Assert-Ferrum2FirewallValue -Object $filters.Address -Property RemoteAddress -Expected @([string]$Row.remote_address)
    $protocol = [string]$filters.Port.Protocol
    $number = if ([string]$Row.protocol -ceq 'TCP') { '6' } else { '17' }
    if ($protocol -ine [string]$Row.protocol -and $protocol -cne $number) { throw 'Firewall protocol scope differs.' }
    foreach ($pair in @(@('LocalPort', [string]$Row.local_port), @('RemotePort', [string]$Row.remote_port), @('IcmpType', 'Any'), @('DynamicTarget', 'Any'))) {
        Assert-Ferrum2FirewallValue -Object $filters.Port -Property $pair[0] -Expected @($pair[1])
    }
    Assert-Ferrum2FirewallInterfaceFilter -Filter $filters.Interface -Row $Row -AllowInterfaceTransition:$AllowInterfaceTransition
    Assert-Ferrum2FirewallValue -Object $filters.InterfaceType -Property InterfaceType -Expected @('Any')
    Assert-Ferrum2FirewallValue -Object $filters.Service -Property Service -Expected @('Any')
    foreach ($pair in @(@('Authentication', 'NotRequired'), @('Encryption', 'NotRequired'), @('OverrideBlockRules', 'False'), @('LocalUser', 'Any'), @('RemoteUser', 'Any'), @('RemoteMachine', 'Any'))) {
        Assert-Ferrum2FirewallValue -Object $filters.Security -Property $pair[0] -Expected @($pair[1])
    }
}

function ConvertTo-Ferrum2FirewallObservation {
    param([object]$Object, [string[]]$Properties)
    $snapshot = [ordered]@{}
    foreach ($property in $Properties) {
        $member = $Object.PSObject.Properties[$property]
        if ($null -eq $member) { continue }
        $values = @($member.Value | ForEach-Object { [string]$_ })
        if ($values.Count -eq 1) { $snapshot[$property] = $values[0] } else { $snapshot[$property] = $values }
    }
    return [pscustomobject]$snapshot
}

function Assert-Ferrum2FirewallRuleMatches {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][object]$Row,
        [ValidateSet('PersistentStore', 'ActiveStore')][string]$PolicyStore = 'PersistentStore',
        [switch]$PassThru,
        [switch]$AllowInterfaceTransition
    )
    Assert-Ferrum2FirewallRow -Row $Row
    $hash = Assert-Ferrum2FirewallExecutable -Path ([string]$Row.program)
    if ($hash -cne [string]$Row.sha256) { throw 'Firewall executable hash no longer matches its ownership ledger.' }
    $properties = [ordered]@{
        Application = @('Program', 'Package')
        Address = @('LocalAddress', 'RemoteAddress')
        Port = @('Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTarget')
        Interface = @('InterfaceAlias')
        InterfaceType = @('InterfaceType')
        Service = @('Service')
        Security = @('Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine')
    }
    $filters = [ordered]@{}
    foreach ($kind in $properties.Keys) {
        $filter = @(& "Get-NetFirewall${kind}Filter" -AssociatedNetFirewallRule $Rule -PolicyStore $PolicyStore -ErrorAction Stop)
        if ($filter.Count -ne 1) { throw "Firewall $kind filter is not unique." }
        $filters[$kind] = ConvertTo-Ferrum2FirewallObservation -Object $filter[0] -Properties ($properties[$kind] + @('IsNegated'))
    }
    $observedRule = ConvertTo-Ferrum2FirewallObservation -Object $Rule -Properties @(
        'Name', 'Enabled', 'Direction', 'Action', 'Profile', 'EdgeTraversalPolicy',
        'LooseSourceMapping', 'LocalOnlyMapping', 'Owner', 'PackageFamilyName', 'PolicyAppId',
        'RemoteDynamicKeywordAddresses', 'Platform', 'Platforms', 'Group',
        'EnforcementStatus', 'PrimaryStatus', 'Status', 'StatusCode', 'PolicyStoreSource', 'PolicyStoreSourceType'
    )
    Assert-Ferrum2FirewallConditions -Rule $observedRule -Row $Row -Filters ([pscustomobject]$filters) -AllowInterfaceTransition:$AllowInterfaceTransition
    if ($PassThru) {
        return [pscustomobject][ordered]@{
            policy_store = $PolicyStore; program_sha256 = $hash
            rule = $observedRule; filters = [pscustomobject]$filters
        }
    }
}

function Save-Ferrum2FirewallIdentity {
    param([object]$Context, [object]$Row)
    Assert-Ferrum2FirewallRow -Row $Row
    foreach ($inventory in @($Context.ledger.resources, $Context.ledger.expected_resources)) {
        $indices = @()
        for ($i = 0; $i -lt @($inventory.firewall_rules).Count; $i++) {
            if ([string]$inventory.firewall_rules[$i].name -ceq [string]$Row.name) { $indices += $i }
        }
        if ($indices.Count -ne 1) { throw 'Firewall ledger identity is not unique.' }
        $inventory.firewall_rules[$indices[0]] = $Row.PSObject.Copy()
    }
    Write-Ferrum2HostLedger -Context $Context
}

function Complete-Ferrum2FirewallInterface {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Row
    )
    Assert-Ferrum2FirewallRow -Row $Row
    if ($null -eq $Row.PSObject.Properties['interface_phase'] -or
        [string]$Row.interface_phase -cne 'prelaunch' -or [string]$Row.state -cne 'created' -or
        ([string]$Row.name).Split('-')[2] -cne [string]$Context.run_id) {
        throw 'Firewall rule is not a created prelaunch rule for this run.'
    }
    foreach ($inventory in @($Context.ledger.resources, $Context.ledger.expected_resources)) {
        $owned = @($inventory.firewall_rules | Where-Object { [string]$_.name -ceq [string]$Row.name })
        if ($owned.Count -ne 1 -or
            ($owned[0] | ConvertTo-Json -Depth 10 -Compress) -cne ($Row | ConvertTo-Json -Depth 10 -Compress)) {
            throw 'Firewall transition identity differs from its durable inventories.'
        }
    }
    $persistent = $null
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store | Where-Object { [string]$_.Name -ieq [string]$Row.name })
        if ($rules.Count -ne 1) { throw 'Firewall prelaunch readback is not unique.' }
        Assert-Ferrum2FirewallRuleMatches -Rule $rules[0] -Row $Row -PolicyStore $store
        if ($store -ceq 'PersistentStore') { $persistent = $rules[0] }
    }
    # Record both exact allowed interface states before mutation. Recovery may see
    # either state in either store if policy propagation or this process stops.
    $identity = Get-Ferrum2FirewallInterfaceIdentity -Alias ([string]$Row.intended_interface_alias)
    $Row | Add-Member -NotePropertyName interface_identity -NotePropertyValue $identity -Force
    $Row.interface_phase = 'narrowing'
    Save-Ferrum2FirewallIdentity -Context $Context -Row $Row
    Set-NetFirewallRule -InputObject $persistent -InterfaceAlias $Row.intended_interface_alias -ErrorAction Stop | Out-Null
    $final = $Row.PSObject.Copy()
    $final.interface_alias = $Row.intended_interface_alias
    $final.interface_phase = 'narrowed'
    $observations = @()
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store | Where-Object { [string]$_.Name -ieq [string]$Row.name })
        if ($rules.Count -ne 1) { throw 'Firewall narrowed readback is not unique.' }
        $observations += Assert-Ferrum2FirewallRuleMatches -Rule $rules[0] -Row $final -PolicyStore $store -PassThru
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "firewall-rules/$($Row.name).json") -Document ([pscustomobject][ordered]@{
        schema_version = 1; kind = 'ferrum2.windows-tun.firewall-rule-readback'
        address_family = [string]$Context.address_family
        observed_utc = [DateTime]::UtcNow.ToString('O'); phase = 'narrowed'
        identity = $final; observations = $observations
    })
    $Row.interface_alias = $final.interface_alias
    $Row.interface_phase = 'narrowed'
    Save-Ferrum2FirewallIdentity -Context $Context -Row $Row
}

function Add-Ferrum2OwnedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [string]$RemotePort = 'Any',
        [Parameter(Mandatory = $true)][string]$InterfaceAlias,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [switch]$DeferInterface
    )
    if ([string]$Context.run_id -cnotmatch '^[0-9a-f]{12}$' -or
        @($Context.ledger.resources.firewall_rules).Count -ge 256 -or
        @($Context.ledger.expected_resources.firewall_rules).Count -ge 256) { throw 'Firewall run identity or ledger bound is invalid.' }
    $row = [pscustomobject][ordered]@{
        address_family = [string]$Context.address_family
        name = "Ferrum2-Qualification-$($Context.run_id)-$([Guid]::NewGuid().ToString('N'))"
        program = $Executable; sha256 = Assert-Ferrum2FirewallExecutable -Path $Executable
        protocol = $Protocol; local_address = $LocalAddress; local_port = $LocalPort
        remote_address = $RemoteAddress; remote_port = $RemotePort; interface_alias = $InterfaceAlias
        profile = 'Domain,Private,Public'; purpose = $Purpose; state = 'planned'
        interface_identity = $null
    }
    if ($DeferInterface) {
        $row | Add-Member -NotePropertyName intended_interface_alias -NotePropertyValue $InterfaceAlias
        $row | Add-Member -NotePropertyName interface_phase -NotePropertyValue 'prelaunch'
        $row.interface_alias = 'Any'
    }
    if (-not $DeferInterface) {
        $row.interface_identity = Get-Ferrum2FirewallInterfaceIdentity -Alias $InterfaceAlias
    }
    Assert-Ferrum2FirewallRow -Row $row
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $existing = @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store | Where-Object { [string]$_.Name -ieq $row.name })
        if ($existing.Count -ne 0) { throw 'Firewall owned name already exists.' }
    }
    $Context.ledger.resources.firewall_rules += $row
    $Context.ledger.expected_resources.firewall_rules += $row.PSObject.Copy()
    Write-Ferrum2HostLedger -Context $Context
    # Omit InterfaceAlias deliberately in prelaunch: the default filter is Any.
    # Fixed rules always supply their exact alias; no failed-create fallback exists.
    $arguments = @{
        PolicyStore = 'PersistentStore'; Name = $row.name; DisplayName = $row.name; Description = $Purpose
        Program = $row.program; Protocol = $row.protocol; LocalAddress = $row.local_address; LocalPort = $row.local_port
        RemoteAddress = $row.remote_address; RemotePort = $row.remote_port
        Profile = @('Domain', 'Private', 'Public'); Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'
        EdgeTraversalPolicy = 'Block'; LooseSourceMapping = $false; LocalOnlyMapping = $false
        Service = 'Any'; InterfaceType = 'Any'; Authentication = 'NotRequired'; Encryption = 'NotRequired'
        OverrideBlockRules = $false; LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'
        IcmpType = 'Any'; DynamicTarget = 'Any'; ErrorAction = 'Stop'
    }
    if (-not $DeferInterface) { $arguments.InterfaceAlias = $row.interface_alias }
    if ((Assert-Ferrum2FirewallExecutable -Path $row.program) -cne $row.sha256) {
        throw 'Firewall executable changed before rule creation.'
    }
    New-NetFirewallRule @arguments | Out-Null
    $observations = @()
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $created = @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store | Where-Object { [string]$_.Name -ieq $row.name })
        if ($created.Count -ne 1) { throw "Firewall $store readback is not unique." }
        $observations += Assert-Ferrum2FirewallRuleMatches -Rule $created[0] -Row $row -PolicyStore $store -PassThru
    }
    $suffix = if ($DeferInterface) { '.prelaunch' } else { '' }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "firewall-rules/$($row.name)$suffix.json") -Document ([pscustomobject][ordered]@{
        schema_version = 1
        address_family = [string]$Context.address_family
        kind = 'ferrum2.windows-tun.firewall-rule-readback'
        observed_utc = [DateTime]::UtcNow.ToString('O')
        phase = if ($DeferInterface) { 'prelaunch' } else { 'fixed' }
        identity = $row.PSObject.Copy()
        observations = $observations
    })
    $row.state = 'created'
    Save-Ferrum2FirewallIdentity -Context $Context -Row $row
    return $row
}

function Remove-Ferrum2OwnedFirewallRule {
    param([Parameter(Mandatory = $true)][object]$Row)
    Assert-Ferrum2FirewallRow -Row $Row
    $persistent = @(Get-Ferrum2FirewallRuleInventory -PolicyStore PersistentStore | Where-Object { [string]$_.Name -ieq [string]$Row.name })
    $active = @(Get-Ferrum2FirewallRuleInventory -PolicyStore ActiveStore | Where-Object { [string]$_.Name -ieq [string]$Row.name })
    if ($persistent.Count -eq 0 -and $active.Count -eq 0) { return }
    if ($persistent.Count -ne 1 -or $active.Count -ne 1) { throw 'Firewall ownership is ambiguous between policy stores.' }
    Assert-Ferrum2FirewallRuleMatches -Rule $persistent[0] -Row $Row -PolicyStore PersistentStore -AllowInterfaceTransition
    Assert-Ferrum2FirewallRuleMatches -Rule $active[0] -Row $Row -PolicyStore ActiveStore -AllowInterfaceTransition
    # Delete the validated local-store object, never an ambient or wildcard name match.
    Remove-NetFirewallRule -InputObject $persistent[0] -Confirm:$false -ErrorAction Stop
    if ((Get-Ferrum2FirewallRuleResidue -Expected @($Row)) -ne 0) { throw 'Owned firewall rule remains after removal.' }
}

function Get-Ferrum2FirewallRuleResidue {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Expected)
    if ($Expected.Count -gt 256) { throw 'Firewall expected inventory exceeds the ownership bound.' }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Expected) {
        if ([string]$row.name -cnotmatch '^Ferrum2-Qualification-[0-9a-f]{12}-[0-9a-f]{32}$') { throw 'Firewall historical name is malformed.' }
        [void]$names.Add([string]$row.name)
    }
    $residue = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        foreach ($rule in @(Get-Ferrum2FirewallRuleInventory -PolicyStore $store)) {
            if ($names.Contains([string]$rule.Name)) { [void]$residue.Add([string]$rule.Name) }
        }
    }
    return $residue.Count
}

function Assert-Ferrum2FirewallEvidence {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory
    )
    if ($Expected.Count -eq 0 -or $Expected.Count -gt 256) { throw 'Firewall evidence requires a bounded, nonempty expected inventory.' }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Expected) {
        Assert-Ferrum2FirewallRow -Row $row
        if (-not $names.Add([string]$row.name)) { throw 'Firewall evidence expected names are duplicated.' }
        $deferred = $null -ne $row.PSObject.Properties['interface_phase']
        if ($deferred -and ([string]$row.interface_phase -cne 'narrowed' -or
            [string]$row.interface_alias -cne [string]$row.intended_interface_alias)) {
            throw 'Deferred firewall evidence requires a narrowed final identity.'
        }
        $phases = if ($deferred) { @('prelaunch', 'narrowed') } else { @('fixed') }
        foreach ($phase in $phases) {
        $identity = $row.PSObject.Copy()
        $suffix = ''
        if ($phase -ceq 'prelaunch') {
            $identity.interface_phase = 'prelaunch'
            $identity.interface_alias = 'Any'
            if ($null -ne $identity.PSObject.Properties['interface_identity']) { $identity.interface_identity = $null }
            $suffix = '.prelaunch'
        }
        $path = Join-Path $EvidenceDirectory "firewall-rules/$($row.name)$suffix.json"
        $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -gt 131072 -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Firewall readback evidence is not a bounded plain file.'
        }
        $document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([int]$document.schema_version -ne 1 -or
            [string]$document.kind -cne 'ferrum2.windows-tun.firewall-rule-readback') { throw 'Firewall evidence schema differs.' }
        if ($document.address_family -cne $row.address_family) { throw 'Firewall evidence address family differs.' }
        Assert-Ferrum2FirewallRow -Row $document.identity
        $properties = @('address_family', 'name', 'program', 'sha256', 'protocol', 'local_address', 'local_port', 'remote_address', 'remote_port', 'interface_alias', 'profile', 'purpose')
        if ($deferred) {
            if ([string]$document.phase -cne $phase) { throw 'Firewall evidence phase differs.' }
            $properties += @('intended_interface_alias', 'interface_phase')
        } elseif ($null -ne $document.identity.PSObject.Properties['interface_phase']) {
            throw 'Fixed firewall evidence unexpectedly records a transition.'
        }
        foreach ($property in $properties) {
            if ([string]$document.identity.$property -cne [string]$identity.$property) { throw "Firewall evidence identity differs at $property." }
        }
        $expectedInterface = $identity.PSObject.Properties['interface_identity']
        $recordedInterface = $document.identity.PSObject.Properties['interface_identity']
        $expectedBinding = if ($null -ne $expectedInterface) { $expectedInterface.Value } else { $null }
        $recordedBinding = if ($null -ne $recordedInterface) { $recordedInterface.Value } else { $null }
        if (($null -eq $expectedBinding) -ne ($null -eq $recordedBinding)) {
            throw 'Firewall evidence stable interface identity differs.'
        }
        if ($null -ne $expectedBinding) {
            foreach ($property in @('alias', 'guid', 'luid')) {
                if ([string]$recordedBinding.$property -cne [string]$expectedBinding.$property) {
                    throw "Firewall evidence stable interface identity differs at $property."
                }
            }
            $expectedLegacy = $expectedBinding.PSObject.Properties['recovered_from_legacy_ledger']
            $recordedLegacy = $recordedBinding.PSObject.Properties['recovered_from_legacy_ledger']
            if (($null -ne $expectedLegacy -and $expectedLegacy.Value -eq $true) -ne
                ($null -ne $recordedLegacy -and $recordedLegacy.Value -eq $true)) {
                throw 'Firewall evidence legacy interface provenance differs.'
            }
        }
        if (@($document.observations).Count -ne 2) { throw 'Firewall evidence must contain both policy stores.' }
        $stores = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($observation in $document.observations) {
            if ([string]$observation.policy_store -cnotin @('PersistentStore', 'ActiveStore') -or
                -not $stores.Add([string]$observation.policy_store) -or
                [string]$observation.program_sha256 -cne [string]$row.sha256) { throw 'Firewall evidence store or observed binary identity differs.' }
            # Recheck captured conditions without touching the now-cleaned executable or host firewall.
            Assert-Ferrum2FirewallConditions -Rule $observation.rule -Row $identity -Filters $observation.filters
        }
        }
    }
}
