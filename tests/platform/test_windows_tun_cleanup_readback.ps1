[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ScratchDirectory,
    [Parameter(Mandatory = $true)][string]$SupervisorDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected $Message
}

# Load exact definitions, never a module or live provider. Mutation-path tests below
# inject every provider before invocation; there is no live-operation fallback.
foreach ($entry in @(
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/AddressFamily.ps1'; Names = @(
        'Get-Ferrum2AddressFamilyProfile', 'Assert-Ferrum2CanonicalAddress',
        'Get-Ferrum2LedgerAddressFamily') },
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/HostCleanup.ps1'; Names = @(
        'Update-Ferrum2ExpectedResources', 'Measure-Ferrum2HostCleanupResidue',
        'Get-Ferrum2HostCleanupReadback', 'Get-Ferrum2CleanupProcessBirthTicks') },
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/HostOwnership.ps1'; Names = @(
        'Write-Ferrum2HostLedger', 'Remove-Ferrum2OwnedProcessRecord',
        'Initialize-Ferrum2RecoveryNetworkIdentity') },
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/HostNetwork.ps1'; Names = @(
        'New-Ferrum2HostNetworkIdentity', 'Assert-Ferrum2OwnedNetworkRow',
        'Assert-Ferrum2OwnedInterfaceBinding', 'Add-Ferrum2OwnedRoute', 'Remove-Ferrum2OwnedRoute') }
)) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $entry.Path), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) 'source parse failed'
    foreach ($name in $entry.Names) {
        $definition = @($ast.FindAll({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $true))
        Assert-True ($definition.Count -eq 1) "pure definition missing: $name"
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }
}

# Pure admission and exact run derivation, with no host inventory or mutation fallback.
$runIds = @('000000000000', '000000000001', '000000010000', '000100000000', 'abcdef123456', 'ffffffffffff')
$ula = [Collections.Generic.HashSet[string]]::new()
foreach ($run in $runIds) {
    $identity = New-Ferrum2HostNetworkIdentity -RunId $run -AddressFamily IPv6
    foreach ($address in @($identity.tun_address, $identity.peer_address, $identity.support_address, $identity.reset_address)) {
        Assert-True ($ula.Add($address)) 'distinct IPv6 runs or roles collided'
        Assert-Ferrum2CanonicalAddress -Address $address -AddressFamily IPv6
    }
}
Assert-Rejected { New-Ferrum2HostNetworkIdentity -RunId '../unsafe' -AddressFamily IPv6 } 'unsafe RunId admitted'
Assert-Rejected { Assert-Ferrum2CanonicalAddress -Address 'fd00:0000::2' -AddressFamily IPv6 } 'noncanonical IPv6 admitted'
Assert-Rejected { Assert-Ferrum2CanonicalAddress -Address '::ffff:127.0.0.1' -AddressFamily IPv4 } 'mapped family admitted'
foreach ($family in @('IPv4', 'IPv6')) {
    $run = 'abcdef123456'
    $identity = New-Ferrum2HostNetworkIdentity -RunId $run -AddressFamily $family
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $family
    if ($family -ceq 'IPv4') {
        Assert-True ($identity.tun_address -ceq '198.18.171.66' -and
            $identity.support_address -ceq '198.19.171.65' -and
            $identity.reset_address -ceq '198.19.171.66') 'IPv4 derivation changed'
    } else {
        Assert-True ($identity.tun_address -ceq 'fd00:abcd:ef12:3456::2' -and
            $identity.support_address -ceq 'fd00:abcd:ef12:3456:1::1') 'IPv6 run bits changed'
    }
    $addressRow = [pscustomobject]@{
        run_id = $run; address_family = $family; address = $identity.support_address
        prefix_length = $profile.host_prefix_length; interface_index = 42; interface_guid = $null; state = 'created'
    }
    Assert-Ferrum2OwnedNetworkRow -Row $addressRow -RunId $run -AddressFamily $family -Type address
    $addressRow.prefix_length--
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $addressRow -RunId $run -AddressFamily $family -Type address } 'broad address admitted'
    $addressRow.prefix_length++
    $addressRow.address = $identity.reset_address
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $addressRow -RunId $run -AddressFamily $family -Type address } 'unowned reset address admitted'
    $addressRow.address = $identity.support_address
    $routeRow = [pscustomobject]@{
        run_id = $run; address_family = $family
        destination_prefix = "$($identity.reset_address)/$($profile.host_prefix_length)"
        next_hop = $profile.unspecified_address; interface_index = 42; interface_guid = $null
        route_metric = 4093; policy_store = 'ActiveStore'; kind = 'qualification-reset-change'; state = 'created'
    }
    Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route
    $routeRow.next_hop = $(if ($family -ceq 'IPv6') { '0.0.0.0' } else { '::' })
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route } 'opposite-family next hop admitted'
    $routeRow.next_hop = $profile.unspecified_address
    $routeRow.destination_prefix = "$($identity.reset_address)/$($profile.host_prefix_length - 1)"
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route } 'broad runner route admitted'
    $routeRow.destination_prefix = "$($identity.reset_address)/$($profile.host_prefix_length)"
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId 'abcdef123457' -AddressFamily $family -Type route } 'foreign run admitted'
    $routeRow.address_family = $(if ($family -ceq 'IPv6') { 'IPv4' } else { 'IPv6' })
    Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route } 'opposite-family ledger admitted'
    $routeRow.address_family = $family
    function Get-Ferrum2OwnedInterfaceBinding { param($InterfaceIndex, $AddressFamily)
        return '22222222-2222-2222-2222-222222222222'
    }
    $routeRow.interface_guid = '11111111-1111-1111-1111-111111111111'
    Assert-Rejected { Assert-Ferrum2OwnedInterfaceBinding -Row $routeRow } 'replacement adapter admitted'
    if ($family -ceq 'IPv6') {
        $routeRow.destination_prefix = 'fd00:abcd:ef12:3456::/126'
        Assert-Rejected { Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route } 'runner connected route admitted'
        $routeRow.kind = 'adapter-connected'
        Assert-Ferrum2OwnedNetworkRow -Row $routeRow -RunId $run -AddressFamily $family -Type route
        $familyExpected = [pscustomobject]@{
            adapters = @(); adapter_baseline_guids = @(); addresses = @($addressRow)
            routes = @($routeRow); processes = @(); ports = @()
        }
        $familySnapshot = [pscustomobject]@{
            adapters = @(); addresses = @([pscustomobject]@{ IPAddress = $addressRow.address; InterfaceIndex = 42 })
            routes = @([pscustomobject]@{ DestinationPrefix = $routeRow.destination_prefix; InterfaceIndex = 42; NextHop = '::1' })
            processes = @(); ports = @()
        }
        $familyResidue = Measure-Ferrum2HostCleanupResidue -Expected $familyExpected -Snapshot $familySnapshot
        Assert-True ($familyResidue.routes_remaining -eq 1 -and $familyResidue.addresses_remaining -eq 1) `
            'IPv6 connected-route or address residue was lost'
    }
}

foreach ($family in @('IPv4', 'IPv6')) {
    & {
        param($family)
        $run = 'abcdef123456'
        $network = New-Ferrum2HostNetworkIdentity -RunId $run -AddressFamily $family
        $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $family
        $index = $(if ($family -ceq 'IPv4') { 7 } else { 1 })
        $rows = [Collections.Generic.List[object]]::new()
        $resources = [pscustomobject]@{
            adapter = $null; addresses = @(); routes = @(); processes = @(); ports = @(); firewall_rules = @()
        }
        $expected = [pscustomobject]@{
            adapters = @(); addresses = @(); routes = @(); processes = @(); ports = @(); firewall_rules = @()
        }
        $context = [pscustomobject]@{
            run_id = $run
            ledger = [pscustomobject]@{ address_family = $family; resources = $resources; expected_resources = $expected }
        }
        function Get-Ferrum2LoopbackIdentity { param($AddressFamily) return @{ interface_index = 1 } }
        function Get-Ferrum2OwnedInterfaceBinding {
            param($InterfaceIndex, $AddressFamily)
            if ($InterfaceIndex -eq 1) { return $null }
            return '11111111-1111-1111-1111-111111111111'
        }
        function Get-Ferrum2NetworkInventory {
            param($AddressFamily)
            return @{ addresses = @(); routes = $rows.ToArray() }
        }
        function Write-Ferrum2HostLedger { param($Context) Update-Ferrum2ExpectedResources -Ledger $Context.ledger }
        function New-NetRoute {
            param($AddressFamily, $InterfaceIndex, $DestinationPrefix, $NextHop, $RouteMetric, $PolicyStore)
            $rows.Add([pscustomobject]@{
                DestinationPrefix = $DestinationPrefix; InterfaceIndex = $InterfaceIndex
                NextHop = $NextHop; RouteMetric = $RouteMetric
            })
        }
        function Remove-NetRoute { param($InputObject, $Confirm) [void]$rows.Remove($InputObject) }
        $prefix = "$($network.reset_address)/$($profile.host_prefix_length)"
        Assert-Rejected {
            Add-Ferrum2OwnedRoute -Context $context -InterfaceIndex $index `
                -DestinationPrefix $prefix -RouteMetric 4093 -Kind qualification-reset-change
        } 'reset change without an owned baseline was admitted'
        Assert-True ($rows.Count -eq 0) 'rejected reset mutated its provider'
        $nextHop = $(if ($family -ceq 'IPv4') { '192.0.2.1' } else { '::' })
        $before = Add-Ferrum2OwnedRoute -Context $context -InterfaceIndex $index `
            -DestinationPrefix $prefix -NextHop $nextHop -RouteMetric 4094 -Kind qualification-reset-baseline
        Remove-Ferrum2OwnedRoute -Row $before
        $resources.routes = @()
        Write-Ferrum2HostLedger -Context $context
        [void](Add-Ferrum2OwnedRoute -Context $context -InterfaceIndex $index `
            -DestinationPrefix $prefix -RouteMetric 4093 -Kind qualification-reset-change)
        Assert-True ($rows.Count -eq 1 -and $rows[0].DestinationPrefix -ceq $prefix -and
            $rows[0].InterfaceIndex -eq $index -and $rows[0].RouteMetric -eq 4093 -and
            $rows[0].NextHop -ceq $profile.unspecified_address) `
            'same-interface reset did not replace its exact owned route'
    } $family
}
$legacyAddress = [pscustomobject]@{
    address = '198.19.171.65'; prefix_length = 32; interface_index = 42
    interface_guid = $null; state = 'created'
}
$legacy = [pscustomobject]@{
    run_id = 'abcdef123456'
    resources = [pscustomobject]@{ addresses = @($legacyAddress); routes = @() }
    expected_resources = [pscustomobject]@{ addresses = @(); routes = @(); adapters = @() }
}
Initialize-Ferrum2RecoveryNetworkIdentity -Ledger $legacy
Assert-True ($legacyAddress.address_family -ceq 'IPv4' -and
    $legacyAddress.run_id -ceq $legacy.run_id) 'unambiguous historical IPv4 identity was not recovered'
$legacyAddress.address = 'fd00:abcd:ef12:3456:1::1'
Assert-Rejected { Initialize-Ferrum2RecoveryNetworkIdentity -Ledger $legacy } 'familyless IPv6 recovery inferred deletion authority'
function Write-AtomicJsonFile { param($Path, $Document)
    $script:persisted = $Document | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
}
function Get-Ferrum2FirewallRuleResidue { param($Expected) return 0 }
function Get-Ferrum2HostCleanupSnapshot { param($Expected)
    if ($script:readFailed) { throw 'injected read error' }
    return $script:snapshot
}
function New-EmptySnapshot {
    return [pscustomobject]@{ adapters = @(); routes = @(); addresses = @(); processes = @(); ports = @() }
}
$resources = [pscustomobject]@{
    adapter = [pscustomobject]@{
        name = 'owned-adapter'; interface_guid = '11111111-1111-1111-1111-111111111111'
        state = 'created'; interface_index = 42
    }
    routes = @([pscustomobject]@{ destination_prefix = '198.18.0.1/32'; interface_index = 42; next_hop = '0.0.0.0' })
    addresses = @([pscustomobject]@{ address = '198.18.0.2'; interface_index = 42 })
    processes = @([pscustomobject]@{ pid = 123; executable = 'owned.exe'; start_time_utc = '2026-09-08T01:00:00.0000000Z' })
    ports = @([pscustomobject]@{ protocol = 'tcp'; address = '127.0.0.1'; port = 12345 })
}
$context = [pscustomobject]@{
    ledger_path = 'injected-only'
    ledger = [pscustomobject]@{
        resources = $resources; expected_resources = (New-EmptySnapshot); updated_utc = ''
    }
}
$context.ledger.expected_resources | Add-Member -NotePropertyName adapter_baseline_guids `
    -NotePropertyValue @('33333333-3333-3333-3333-333333333333')
Write-Ferrum2HostLedger -Context $context
Remove-Ferrum2OwnedProcessRecord -Context $context -ProcessId 123
$context.ledger.resources = [pscustomobject]@{
    adapter = $null; routes = @(); addresses = @(); processes = @(); ports = @()
}
Write-Ferrum2HostLedger -Context $context
$expected = $script:persisted.expected_resources
foreach ($kind in @('adapters', 'routes', 'addresses', 'processes', 'ports')) {
    Assert-True (@($expected.$kind).Count -eq 1) "retiring active $kind lost expected identity"
}
$script:readFailed = $false
$script:snapshot = New-EmptySnapshot
$zero = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
foreach ($field in @('adapter_remaining', 'routes_remaining', 'addresses_remaining',
    'processes_remaining', 'ports_remaining', 'firewall_rule_remaining')) {
    Assert-True ($zero.$field -eq 0) "owned resource remained after cleanup: $field"
}
$observations = [ordered]@{
    adapters = [pscustomobject]@{ Name = 'owned-adapter'; InterfaceGuid = '22222222-2222-2222-2222-222222222222' }
    routes = [pscustomobject]@{ DestinationPrefix = '198.18.0.1/32'; InterfaceIndex = 42; NextHop = '0.0.0.0' }
    addresses = [pscustomobject]@{ IPAddress = '198.18.0.2'; InterfaceIndex = 42 }
    processes = [pscustomobject]@{ pid = 123; executable = 'owned.exe'; start_time_utc = '2026-09-08T01:00:00.0000000Z' }
    ports = [pscustomobject]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 12345 }
}
foreach ($kind in $observations.Keys) {
    $script:snapshot = New-EmptySnapshot
    $script:snapshot.$kind = @($observations[$kind])
    $counts = Measure-Ferrum2HostCleanupResidue -Expected $expected -Snapshot $script:snapshot
    Assert-True (($counts.PSObject.Properties.Value | Measure-Object -Sum).Sum -eq 1) "missing $kind residue"
    Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } "$kind residue passed"
    $script:snapshot.$kind = $null
    Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } "unknown $kind became zero"
}
$script:snapshot = New-EmptySnapshot
$script:snapshot.adapters = @([pscustomobject]@{
    Name = 'renamed-owned-adapter'; InterfaceGuid = '11111111-1111-1111-1111-111111111111'
})
$renamedCounts = Measure-Ferrum2HostCleanupResidue -Expected $expected -Snapshot $script:snapshot
Assert-True ($renamedCounts.adapter_remaining -eq 1) 'same GUID with changed name was lost'
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'renamed owned adapter passed'
$script:snapshot.adapters[0].InterfaceGuid = $null
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'missing observed GUID passed'
$script:snapshot = New-EmptySnapshot
$expected.adapters[0].interface_guid = $null
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'missing expected GUID passed'
$expected.adapters[0].state = 'planned'
$script:snapshot.adapters = @([pscustomobject]@{
    Name = 'baseline-adapter'; InterfaceGuid = '33333333-3333-3333-3333-333333333333'
})
$cancelledCounts = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True ($cancelledCounts.adapter_remaining -eq 0) 'creation-before-start cancellation was not recoverable'
$script:snapshot.adapters[0].Name = 'owned-adapter'
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'baseline GUID with intended name conflict passed'
$script:snapshot.adapters[0].Name = 'renamed-new-adapter'
$script:snapshot.adapters[0].InterfaceGuid = '44444444-4444-4444-4444-444444444444'
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'unresolved renamed new GUID passed'
$savedBaseline = $expected.adapter_baseline_guids
$expected.adapter_baseline_guids = $null
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'missing baseline passed'
$expected.adapter_baseline_guids = $savedBaseline
$script:snapshot = New-EmptySnapshot
$expected.adapters[0].state = 'created'
$expected.adapters[0].interface_guid = '11111111-1111-1111-1111-111111111111'
$expected.adapters = @($expected.adapters) + @([pscustomobject]@{
    name = 'owned-adapter'; interface_guid = $null; state = 'planned'; interface_index = $null
})
$completedPlanCounts = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True ($completedPlanCounts.adapter_remaining -eq 0) 'completed planned identity did not use recorded GUID'
$script:snapshot = New-EmptySnapshot
$script:snapshot.processes = @([pscustomobject]@{
    pid = 123; executable = $null; start_time_utc = '2026-09-08T02:00:00.0000000Z' })
$foreignCounts = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True ($foreignCounts.processes_remaining -eq 0) 'different valid birth was counted as owned'
foreach ($birth in @($null, '', 'invalid')) {
    $script:snapshot.processes[0].start_time_utc = $birth
    Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'unreadable process birth passed'
}
$script:snapshot.processes[0].start_time_utc = '2026-09-08T01:00:00.0000000Z'
$script:snapshot.processes[0].executable = 'replacement.exe'
$identityError = $null
try { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted | Out-Null }
catch { $identityError = $_.Exception.Message }
Assert-True ($null -ne $identityError -and $identityError.Contains('replacement.exe') -and
    $identityError.Contains('owned.exe') -and $identityError.Contains('123') -and
    $identityError.Contains('2026-09-08T01:00:00.0000000Z')) 'same-birth mismatch diagnostics were lost'
$script:readFailed = $true
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'read failure became zero'

# Exercise the production read provider with a closed, injected command surface. Each host
# cmdlet is defined here before the provider is loaded; none can resolve to a platform cmdlet.
function Get-NetAdapter { [CmdletBinding()]param([switch]$IncludeHidden)
    Assert-True ($ErrorActionPreference -eq 'Stop') 'adapter errors were suppressed'
}
function Get-NetRoute { [CmdletBinding()]param($AddressFamily, $PolicyStore)
    $script:routeFamilies.Add([string]$AddressFamily)
    Assert-True ($ErrorActionPreference -eq 'Stop') 'route errors were suppressed'
    if ($script:providerFailure) { throw 'injected route enumeration failure' }
}
function Get-NetIPAddress { [CmdletBinding()]param($AddressFamily, $PolicyStore)
    $script:addressFamilies.Add([string]$AddressFamily)
    Assert-True ($ErrorActionPreference -eq 'Stop') 'address errors were suppressed'
}
$script:providerProcesses = @()
function Get-Process { [CmdletBinding()]param()
    Assert-True ($ErrorActionPreference -eq 'Stop') 'process errors were suppressed'
    return $script:providerProcesses
}
function Get-NetTCPConnection { [CmdletBinding()]param()
    Assert-True ($ErrorActionPreference -eq 'Stop') 'TCP errors were suppressed'
}
function Get-NetUDPEndpoint { [CmdletBinding()]param()
    Assert-True ($ErrorActionPreference -eq 'Stop') 'UDP errors were suppressed'
}
$tokens = $null; $errors = $null
$providerAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $root 'tools/powershell/Ferrum2.Qualification.Host/HostCleanup.ps1'), [ref]$tokens, [ref]$errors)
$provider = @($providerAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-Ferrum2HostCleanupSnapshot'
}, $true))
Assert-True ($provider.Count -eq 1) 'read provider missing'
$allowedCommands = @('Get-NetAdapter', 'Get-NetRoute', 'Get-NetIPAddress', 'Get-Process',
    'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Where-Object', 'ForEach-Object',
    'Get-Ferrum2CleanupProcessBirthTicks', 'ConvertTo-Json')
foreach ($command in $provider[0].FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true)) {
    Assert-True ($command.GetCommandName() -cin $allowedCommands) 'provider has an uninjected command'
}
. ([scriptblock]::Create($provider[0].Extent.Text))
$script:routeFamilies = [Collections.Generic.List[string]]::new()
$script:addressFamilies = [Collections.Generic.List[string]]::new()
$script:providerFailure = $false
$observedZero = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True (($observedZero | ConvertTo-Json -Compress) -ceq ($zero | ConvertTo-Json -Compress)) 'empty enumeration changed readback'
Assert-True (($script:routeFamilies -join ',') -ceq 'IPv4,IPv6' -and
    ($script:addressFamilies -join ',') -ceq 'IPv4,IPv6') 'cleanup did not independently enumerate both families'
$foreignProcess = [pscustomobject]@{ Id = 123; StartTime = [DateTime]::Parse(
    '2026-09-08T02:00:00.0000000Z', [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind) }
$script:foreignPathRead = $false
$foreignProcess | Add-Member -MemberType ScriptProperty -Name Path -Value {
    $script:foreignPathRead = $true
    throw 'foreign protected path must not be read'
}
$script:providerProcesses = @($foreignProcess)
$foreignObserved = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True ($foreignObserved.processes_remaining -eq 0 -and -not $script:foreignPathRead) `
    'foreign PID reuse required protected executable readback'
$script:providerProcesses = @()
$script:providerFailure = $true
Assert-Rejected { Get-Ferrum2HostCleanupReadback -Ledger $script:persisted } 'enumeration failure passed readback'

# This owner performs file export only. Test both durable export and retained local failure
# evidence, without ever invoking the supervisor or recovery entrypoint.
. (Join-Path $root 'tools/powershell/Ferrum2.Qualification.Host/SupervisorEvidence.ps1')
$supervisor = Join-Path $ScratchDirectory 'supervisor'
[void](New-Item -ItemType Directory -Path $supervisor)
foreach ($name in @('worker.stdout.log', 'worker.stderr.log', 'recovery.stdout.log', 'recovery.stderr.log')) {
    [IO.File]::WriteAllText((Join-Path $supervisor $name), $name)
}
$outcome = [ordered]@{
    phase = 'recovery'; primary_error = 'worker timeout'; cleanup_error = 'recovery failed'
    cleanup_phase = 'pending'; cleanup_failures = @()
}
$evidence = Join-Path $ScratchDirectory 'evidence'
Assert-True (Export-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $supervisor `
    -EvidenceDirectory $evidence -Outcome $outcome) 'diagnostic export failed'
foreach ($name in @('supervisor.stdout.log', 'supervisor.stderr.log', 'recovery.stdout.log', 'recovery.stderr.log')) {
    $sourceName = $name.Replace('supervisor.', 'worker.')
    Assert-True ([IO.File]::ReadAllText((Join-Path $evidence $name)) -ceq $sourceName) "lost $name"
}
$metadata = Get-Content -Raw (Join-Path $evidence 'supervisor-outcome.json') | ConvertFrom-Json
Assert-True ($metadata.primary_error -ceq 'worker timeout' -and $metadata.cleanup_error -ceq 'recovery failed') 'failure metadata collapsed'
$blockedDestination = Join-Path $ScratchDirectory 'file-instead-of-directory'
[IO.File]::WriteAllText($blockedDestination, 'owned test fixture')
Assert-True (-not (Export-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $supervisor `
    -EvidenceDirectory $blockedDestination -Outcome $outcome)) 'unavailable export passed'
Assert-True (Test-Path -LiteralPath (Join-Path $supervisor 'recovery.stderr.log') -PathType Leaf) 'failed export erased recovery log'
$failedMetadata = Get-Content -Raw (Join-Path $supervisor 'supervisor-outcome.json') | ConvertFrom-Json
Assert-True ($failedMetadata.cleanup_phase -ceq 'export-diagnostics' -and
    $failedMetadata.cleanup_failures.Count -eq 1) 'export failure phase was not retained'

# Exercise the public file-finalization interface with only deletion injected. No
# supervisor runner or source-shaped finally extraction is needed for error propagation.
function Remove-Item { [CmdletBinding()]param($LiteralPath, [switch]$Recurse, [switch]$Force)
    if ($script:failDirectoryRemoval) { throw 'injected directory cleanup failure' }
    $script:directoryRemovalCompleted = $true
}
foreach ($failure in @('export', 'remove', 'none')) {
    $caseRoot = Join-Path $ScratchDirectory "finalize-$failure"
    [void](New-Item -ItemType Directory -Path $caseRoot)
    $destination = Join-Path $caseRoot 'evidence'
    if ($failure -ceq 'export') { [IO.File]::WriteAllText($destination, 'blocked destination') }
    [IO.File]::WriteAllText((Join-Path $SupervisorDirectory 'worker.stderr.log'), 'raw worker evidence')
    $outcome = [ordered]@{
        phase = 'recovery'; primary_error = 'worker failure'; cleanup_error = $null
        cleanup_phase = 'pending'; cleanup_failures = @()
    }
    $script:failDirectoryRemoval = $failure -ceq 'remove'
    $script:directoryRemovalCompleted = $false
    if ($failure -ceq 'none') {
        Complete-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $SupervisorDirectory `
            -EvidenceDirectory $destination -Outcome $outcome
        Assert-True ($script:directoryRemovalCompleted -and $outcome.cleanup_phase -ceq 'complete') `
            'successful finalization did not complete deletion'
        Assert-True ([IO.File]::ReadAllText((Join-Path $destination 'supervisor.stderr.log')) -ceq
            'raw worker evidence') 'finalization lost worker diagnostics'
    } else {
        Assert-Rejected {
            Complete-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $SupervisorDirectory `
                -EvidenceDirectory $destination -Outcome $outcome
        } "$failure finalization did not propagate failure"
        Assert-True (-not $script:directoryRemovalCompleted) "$failure finalized deletion"
        $retained = Get-Content -Raw (Join-Path $SupervisorDirectory 'supervisor-outcome.json') | ConvertFrom-Json
        $expectedPhase = if ($failure -ceq 'export') { 'export-diagnostics' } else { 'remove-supervisor-directory' }
        Assert-True ($retained.cleanup_phase -ceq $expectedPhase -and
            $retained.cleanup_failures.Count -eq 1 -and $retained.primary_error -ceq 'worker failure') `
            "$failure lost primary or cleanup diagnostics"
    }
}

# All path/type failures must occur before the injected deletion operation is invoked.
# Directory reads are injected only for the two type cases; no real reparse point is made.
function Get-Item { [CmdletBinding()]param($LiteralPath, [switch]$Force)
    return [pscustomobject]@{
        PSIsContainer = $script:isDirectory
        Attributes = $script:directoryAttributes
    }
}
foreach ($invalid in @('nested', 'name', 'evidence', 'file', 'reparse')) {
    $script:directoryRemovalCompleted = $false
    $script:failDirectoryRemoval = $false
    $script:isDirectory = $invalid -cne 'file'
    $script:directoryAttributes = if ($invalid -ceq 'reparse') {
        [IO.FileAttributes]::ReparsePoint
    } else { [IO.FileAttributes]::Directory }
    $badRoot = switch ($invalid) {
        'nested' { Join-Path $ScratchDirectory ('ferrum2-host-qualification-supervisor-' + ('a' * 32)) }
        'name' { $ScratchDirectory }
        'evidence' { $SupervisorDirectory }
        'file' { $SupervisorDirectory }
        'reparse' { $SupervisorDirectory }
    }
    $destination = if ($invalid -ceq 'evidence') { $badRoot } else { Join-Path $ScratchDirectory "invalid-$invalid" }
    # Export is a mandatory injected success here: this isolates deletion authorization and
    # cannot copy into or create any of the deliberately invalid paths.
    function Export-Ferrum2QualificationSupervisorEvidence { param($SupervisorRoot, $EvidenceDirectory, $Outcome)
        return $true
    }
    $outcome = [ordered]@{ cleanup_phase = 'pending'; cleanup_error = $null; cleanup_failures = @() }
    Assert-Rejected {
        Complete-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $badRoot `
            -EvidenceDirectory $destination -Outcome $outcome
    } "$invalid cleanup path passed"
    Assert-True (-not $script:directoryRemovalCompleted) "$invalid reached directory deletion"
}
Write-Output 'offline_cleanup_readback_and_supervisor_evidence=PASS'
