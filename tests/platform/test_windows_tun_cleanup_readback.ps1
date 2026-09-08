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

# Load an exact whitelist of pure definitions, never a module, provider, recovery routine,
# process owner, runner or removal command. There is no live-operation fallback in this test.
foreach ($entry in @(
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/HostCleanup.ps1'; Names = @(
        'Update-Ferrum2ExpectedResources', 'Measure-Ferrum2HostCleanupResidue',
        'Get-Ferrum2HostCleanupReadback', 'Get-Ferrum2CleanupProcessBirthTicks') },
    @{ Path = 'tools/powershell/Ferrum2.Qualification.Host/HostOwnership.ps1'; Names = @(
        'Write-Ferrum2HostLedger', 'Remove-Ferrum2OwnedProcessRecord') }
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
    Assert-True ($ErrorActionPreference -eq 'Stop') 'route errors were suppressed'
    if ($script:providerFailure) { throw 'injected route enumeration failure' }
}
function Get-NetIPAddress { [CmdletBinding()]param($AddressFamily, $PolicyStore)
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
$script:providerFailure = $false
$observedZero = Get-Ferrum2HostCleanupReadback -Ledger $script:persisted
Assert-True (($observedZero | ConvertTo-Json -Compress) -ceq ($zero | ConvertTo-Json -Compress)) 'empty enumeration changed readback'
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

# Execute only the production supervisor finally block and post-finally publish statements.
# The worker try body is deliberately not loaded. Its process-group type and directory
# removal are test-owned no-op/throw implementations, with no native or cmdlet fallback.
class Ferrum2HostProcessGroup {
    static [bool]$FailClose = $false
    static [void] CloseGroup() {
        if ([Ferrum2HostProcessGroup]::FailClose) { throw 'injected group close failure' }
    }
}
function Remove-Item { [CmdletBinding()]param($LiteralPath, [switch]$Recurse, [switch]$Force)
    if ($script:failDirectoryRemoval) { throw 'injected directory cleanup failure' }
    $script:directoryRemovalCompleted = $true
}
$runnerTokens = $null; $runnerErrors = $null
$runnerAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $root 'tests/platform/run_windows_tun_qualification_host.ps1'),
    [ref]$runnerTokens, [ref]$runnerErrors)
$transaction = @($runnerAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
})
Assert-True ($transaction.Count -eq 1) 'supervisor transaction changed'
$tail = @($runnerAst.EndBlock.Statements | Where-Object {
    $_.Extent.StartOffset -gt $transaction[0].Extent.EndOffset
} | ForEach-Object { $_.Extent.Text }) -join "`n"
$finalization = [scriptblock]::Create("try { } finally $($transaction[0].Finally.Extent.Text)`n$tail")
foreach ($failure in @('close', 'export', 'remove', 'deadline', 'none')) {
    $caseRoot = Join-Path $ScratchDirectory $failure
    [void](New-Item -ItemType Directory -Path $caseRoot)
    $supervisorRoot = $SupervisorDirectory
    [IO.File]::WriteAllText((Join-Path $supervisorRoot 'worker.stderr.log'), 'raw worker evidence')
    $resolvedEvidence = Join-Path $caseRoot 'evidence'
    if ($failure -ceq 'export') { [IO.File]::WriteAllText($resolvedEvidence, 'blocked destination') }
    $outcome = [ordered]@{
        phase = 'verdict-ready'; primary_error = $null; cleanup_error = $null
        cleanup_phase = 'pending'; cleanup_failures = @()
    }
    $result = [pscustomobject]@{ status = 'QUALIFIED'; supervisor_elapsed_seconds = 0 }
    $maximumElapsedSeconds = 900
    $supervisorTimer = [pscustomobject]@{
        Elapsed = [pscustomobject]@{ TotalSeconds = $(if ($failure -ceq 'deadline') { 900 } else { 12 }) }
    }
    $supervisorTimer | Add-Member -MemberType ScriptMethod -Name Stop -Value { }
    [Ferrum2HostProcessGroup]::FailClose = $failure -ceq 'close'
    $script:failDirectoryRemoval = $failure -ceq 'remove'
    $script:directoryRemovalCompleted = $false
    if ($failure -ceq 'none') {
        $published = & $finalization
        Assert-True ($script:directoryRemovalCompleted) 'verdict preceded directory cleanup'
        $verdict = Get-Content -Raw (Join-Path $resolvedEvidence 'qualification.json') | ConvertFrom-Json
        Assert-True ($verdict.status -ceq 'QUALIFIED' -and $verdict.supervisor_elapsed_seconds -eq 12 -and
            ($published -join '').Contains('QUALIFIED')) 'successful final verdict missing'
    } else {
        $script:publishedOnFailure = [Collections.Generic.List[object]]::new()
        Assert-Rejected {
            & $finalization | ForEach-Object { [void]$script:publishedOnFailure.Add($_) }
        } "$failure finalization passed"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $resolvedEvidence 'qualification.json'))) "$failure left a successful verdict"
        Assert-True ($script:publishedOnFailure.Count -eq 0) "$failure published success stdout"
        if ($failure -in @('export', 'remove')) {
            $retained = Get-Content -Raw (Join-Path $supervisorRoot 'supervisor-outcome.json') | ConvertFrom-Json
            $expectedPhase = if ($failure -ceq 'export') { 'export-diagnostics' } else { 'remove-supervisor-directory' }
            Assert-True ($retained.cleanup_phase -ceq $expectedPhase -and
                $retained.cleanup_failures.Count -eq 1) "$failure metadata was lost"
        }
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
