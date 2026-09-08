"""Offline firewall ownership boundaries; injected provider never touches Windows policy."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ROOT / "tools/powershell/Ferrum2.Qualification.Host"

HARNESS = r'''
param([string]$Owners, [string]$Root)
$ErrorActionPreference = 'Stop'
# Prevent module auto-loading from falling through to the real Windows provider.
$PSModuleAutoLoadingPreference = 'None'
Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
# Only native identity resolution is injected; production normalization and hashing run.
Add-Type -TypeDefinition @'
using System;
public static class Ferrum2QualificationRouteNotification {
    public static bool Disappeared = false;
    public static ulong InterfaceLuid(string alias) {
        if (Disappeared) throw new InvalidOperationException("adapter disappeared");
        if (alias != "Loopback Pseudo-Interface 1" && alias != "Ferrum2Host-012345abcdef-001")
            throw new ArgumentException("unknown adapter");
        return 14918723538255872UL;
    }
    public static Guid InterfaceGuid(ulong luid) {
        if (Disappeared) throw new InvalidOperationException("adapter disappeared");
        if (luid != 14918723538255872UL) throw new ArgumentException("unknown LUID");
        return new Guid("d3e4c652-a1e6-4346-a828-37d698e2bab3");
    }
}
'@
$script:InterfaceRepresentation = ''
. (Join-Path $Owners 'HostFirewall.ps1')
. (Join-Path $Owners 'HostOwnership.ps1')
$script:Executable = Join-Path $Root 'qualification.exe'
[IO.File]::WriteAllText($script:Executable, 'real fixture bytes, not an executable')
# Only the Windows path/reparse guard is substituted on other hosts. Hashing stays real.
if (-not $IsWindows) {
    function Assert-Ferrum2FirewallExecutable {
        param([string]$Path)
        if ($Path -cne $script:Executable -or -not [IO.File]::Exists($Path)) {
            throw 'executable does not identify the real temporary fixture'
        }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$script:Context = [pscustomobject]@{
    run_id = '012345abcdef'
    ledger_path = (Join-Path $Root 'ledger.json')
    evidence_directory = (Join-Path $Root 'evidence')
    ledger = [pscustomobject]@{
        resources = [pscustomobject]@{ firewall_rules = @() }
        expected_resources = [pscustomobject]@{ firewall_rules = @() }
    }
}
$script:Stores = @{ PersistentStore = @(); ActiveStore = @() }
$script:ReadFailure = ''
$script:LedgerFailure = $false
$script:CompletionWriteFailure = $false
$script:ActiveMismatch = $false
$script:NewCalls = 0
$script:SetCalls = 0
$script:SetFailure = ''
$script:Removed = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Rejected {
    param([scriptblock]$Operation)
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'unsafe operation unexpectedly succeeded'
}
function Assert-StableIdentity {
    param($Identity, [string]$Alias)
    Assert-True ($null -ne $Identity -and $Identity.alias -ceq $Alias -and
        $Identity.guid -ceq 'd3e4c652-a1e6-4346-a828-37d698e2bab3' -and
        $Identity.luid -ceq '14918723538255872') 'durable interface binding missing or incorrect'
}
function Copy-Rule {
    param($Rule)
    return ($Rule | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}
function New-ProviderRule {
    param([string]$Name, [string]$Program, [string]$Protocol = 'TCP',
        [string]$LocalAddress = '127.0.0.1', [string]$LocalPort = '49152-65535',
        [string]$RemoteAddress = '127.0.0.1', [string]$RemotePort = 'Any',
        [string]$InterfaceAlias = 'Loopback Pseudo-Interface 1')
    return [pscustomobject]@{
        Name = $Name; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'
        Profile = 'Domain, Private, Public'; EdgeTraversalPolicy = 'Block'
        LooseSourceMapping = $false; LocalOnlyMapping = $false
        Application = [pscustomobject]@{ Program = $Program; Package = 'Any' }
        Address = [pscustomobject]@{ LocalAddress = @($LocalAddress); RemoteAddress = @($RemoteAddress) }
        Port = [pscustomobject]@{ Protocol = $Protocol; LocalPort = @($LocalPort)
            RemotePort = @($RemotePort); IcmpType = 'Any'; DynamicTarget = 'Any' }
        Interface = [pscustomobject]@{ InterfaceAlias = @($InterfaceAlias) }
        InterfaceTypeFilter = [pscustomobject]@{ InterfaceType = 'Any' }
        ServiceFilter = [pscustomobject]@{ Service = 'Any' }
        Security = [pscustomobject]@{ Authentication = 'NotRequired'; Encryption = 'NotRequired'
            LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'; OverrideBlockRules = $false }
    }
}
function Write-AtomicJsonFile {
    param([string]$Path, $Document)
    # Evidence is real scratch output; this fixture does not exercise atomic publication.
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllText($Path, ($Document | ConvertTo-Json -Depth 30))
}
function Write-Ferrum2HostLedger {
    param($Context)
    if ($script:LedgerFailure) { throw 'injected durable ledger write failure' }
    [IO.File]::WriteAllText($Context.ledger_path, ($Context.ledger | ConvertTo-Json -Depth 20))
}
function Get-NetFirewallRule {
    [CmdletBinding()]
    param([string]$PolicyStore, [string]$Name)
    if ($PolicyStore -eq $script:ReadFailure) { throw 'injected inventory failure' }
    if (-not $script:Stores.ContainsKey($PolicyStore)) { throw 'unexpected policy store' }
    foreach ($rule in $script:Stores[$PolicyStore]) {
        if (-not $Name -or $rule.Name -eq $Name) { $rule }
    }
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.Application
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.Address
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.Port
}
function Get-NetFirewallInterfaceFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.Interface
}
function Get-NetFirewallInterfaceTypeFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.InterfaceTypeFilter
}
function Get-NetFirewallServiceFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.ServiceFilter
}
function Get-NetFirewallSecurityFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule, [string]$PolicyStore)
    $AssociatedNetFirewallRule.Security
}
function New-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [string]$Program, [string]$Protocol,
        [string]$LocalAddress, [string]$LocalPort, [string]$RemoteAddress,
        [string]$RemotePort, [string]$InterfaceAlias = 'Any', [string]$PolicyStore,
        [string]$DisplayName, [string]$Description, [string[]]$Profile,
        [string]$Direction, [string]$Action, [string]$Enabled,
        [string]$EdgeTraversalPolicy, [bool]$LooseSourceMapping, [bool]$LocalOnlyMapping,
        [string]$Service, [string]$InterfaceType, [string]$Authentication, [string]$Encryption,
        [bool]$OverrideBlockRules, [string]$LocalUser, [string]$RemoteUser,
        [string]$RemoteMachine, [string]$IcmpType, [string]$DynamicTarget)
    $script:NewCalls++
    Assert-True ([IO.File]::Exists($script:Context.ledger_path)) 'creation preceded durable ledger'
    $disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
    foreach ($rows in @(@{ value = $disk.resources.firewall_rules },
                         @{ value = $disk.expected_resources.firewall_rules })) {
        $planned = @($rows.value | Where-Object name -EQ $Name)
        Assert-True ($planned.Count -eq 1) 'intended identity not durable before creation'
        $row = $planned[0]
        Assert-True ($row.state -eq 'planned') 'creation has no recoverable planned state'
        Assert-True ($row.program -eq $Program -and
            $row.sha256 -eq (Get-FileHash -LiteralPath $Program -Algorithm SHA256).Hash -and
            $row.protocol -eq $Protocol -and $row.local_address -eq $LocalAddress -and
            $row.local_port -eq $LocalPort -and $row.remote_address -eq $RemoteAddress -and
            $row.remote_port -eq $RemotePort -and $row.interface_alias -eq $InterfaceAlias -and
            $row.profile -eq 'Domain,Private,Public' -and $row.purpose -eq $Description) `
            'persisted recovery identity differs from mutation'
        if ($InterfaceAlias -eq 'Any') {
            Assert-True ($null -eq $row.interface_identity) 'prelaunch bound an absent adapter'
        } else {
            Assert-StableIdentity -Identity $row.interface_identity -Alias $InterfaceAlias
        }
    }
    Assert-True ($PolicyStore -eq 'PersistentStore') 'rule is not durably owned'
    $rule = New-ProviderRule -Name $Name -Program $Program -Protocol $Protocol `
        -LocalAddress $LocalAddress -LocalPort $LocalPort -RemoteAddress $RemoteAddress `
        -RemotePort $RemotePort -InterfaceAlias $InterfaceAlias
    $rule.Profile = $Profile -join ', '
    $rule.Direction = $Direction
    $rule.Action = $Action
    $rule.Enabled = $Enabled
    $rule.EdgeTraversalPolicy = $EdgeTraversalPolicy
    $rule.LooseSourceMapping = $LooseSourceMapping
    $rule.LocalOnlyMapping = $LocalOnlyMapping
    $rule.ServiceFilter.Service = $Service
    $rule.InterfaceTypeFilter.InterfaceType = $InterfaceType
    $rule.Security.Authentication = $Authentication
    $rule.Security.Encryption = $Encryption
    $rule.Security.OverrideBlockRules = $OverrideBlockRules
    $rule.Security.LocalUser = $LocalUser
    $rule.Security.RemoteUser = $RemoteUser
    $rule.Security.RemoteMachine = $RemoteMachine
    $rule.Port.IcmpType = $IcmpType
    $rule.Port.DynamicTarget = $DynamicTarget
    $script:Stores.PersistentStore += $rule
    $active = Copy-Rule $rule
    if ($script:ActiveMismatch) { $active.Port.LocalPort = @('Any') }
    $script:Stores.ActiveStore += $active
    if ($script:CompletionWriteFailure) { $script:LedgerFailure = $true }
    $rule
}
function Set-NetFirewallRule {
    [CmdletBinding()]
    param($InputObject, [string]$InterfaceAlias)
    $script:SetCalls++
    $disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
    foreach ($rows in @(@{ value = $disk.resources.firewall_rules },
                         @{ value = $disk.expected_resources.firewall_rules })) {
        $matches = @($rows.value | Where-Object name -EQ $InputObject.Name)
        Assert-True ($matches.Count -eq 1) 'transition duplicated or lost owned identity'
        $row = $matches[0]
        Assert-True ($row.interface_phase -ceq 'narrowing' -and
            $row.interface_alias -ceq 'Any' -and
            $row.intended_interface_alias -ceq $InterfaceAlias) 'Set preceded durable transition intent'
        Assert-True ($row.program -ceq $InputObject.Application.Program -and
            $row.sha256 -eq (Get-FileHash -LiteralPath $row.program -Algorithm SHA256).Hash) `
            'transition changed executable identity'
        Assert-StableIdentity -Identity $row.interface_identity -Alias $InterfaceAlias
    }
    if ($script:SetFailure -eq 'before') { throw 'injected crash before Set' }
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        if ($script:SetFailure -eq "skip-$store") { continue }
        $matches = @($script:Stores[$store] | Where-Object Name -EQ $InputObject.Name)
        Assert-True ($matches.Count -eq 1) 'Set did not target existing same rule'
        $matches[0].Interface.InterfaceAlias = @($InterfaceAlias)
        if ($script:InterfaceRepresentation) {
            $matches[0].Interface.InterfaceAlias = @($script:InterfaceRepresentation)
        }
    }
    if ($script:SetFailure -eq 'after' -or $script:SetFailure -like 'skip-*') {
        throw 'injected crash after provider mutation'
    }
    if ($script:SetFailure -eq 'completion-write') { $script:LedgerFailure = $true }
}
function Remove-NetFirewallRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Name, [string]$PolicyStore, $InputObject)
    if ($null -ne $InputObject) { $Name = $InputObject.Name }
    Assert-True (-not [string]::IsNullOrWhiteSpace($Name)) 'unscoped removal attempted'
    $script:Removed += $Name
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $script:Stores[$store] = @($script:Stores[$store] | Where-Object Name -NE $Name)
    }
}
function Add-TestRule {
    Add-Ferrum2OwnedFirewallRule -Context $script:Context -Executable $script:Executable `
        -Protocol TCP -LocalAddress '127.0.0.1' -LocalPort '49152-65535' `
        -RemoteAddress '127.0.0.1' -RemotePort 'Any' `
        -InterfaceAlias 'Loopback Pseudo-Interface 1' -Purpose 'offline ownership test'
}
function Add-DeferredTestRule {
    param([hashtable]$Changes = @{})
    $options = @{
        Context = $script:Context; Executable = $script:Executable
        Protocol = 'TCP'; LocalAddress = '198.18.1.142'; LocalPort = '49152-65535'
        RemoteAddress = '198.18.1.141'; RemotePort = 'Any'
        InterfaceAlias = 'Ferrum2Host-012345abcdef-001'; Purpose = 'client-ingress-1'
        DeferInterface = $true
    }
    foreach ($key in $Changes.Keys) { $options[$key] = $Changes[$key] }
    Add-Ferrum2OwnedFirewallRule @options
}
$unrelated = New-ProviderRule -Name 'unrelated-existing-rule' -Program $script:Executable
$script:Stores.PersistentStore += $unrelated
$script:Stores.ActiveStore += Copy-Rule $unrelated
function Assert-UnrelatedSurvives {
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        Assert-True (@($script:Stores[$store] | Where-Object Name -EQ 'unrelated-existing-rule').Count -eq 1) `
            'unrelated rule was deleted'
    }
    Assert-True ($script:Removed -notcontains 'unrelated-existing-rule') 'unrelated deletion attempted'
}
'''


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class WindowsTunFirewallTests(unittest.TestCase):
    def run_script(self, body: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-firewall-contract-") as temporary:
            root = Path(temporary)
            # macOS temp roots may themselves be symlinks; production rejects reparse paths.
            root = root.resolve()
            script = root / "test.ps1"
            script.write_text(HARNESS + body, encoding="utf-8")
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), str(OWNERS), str(root)],
                capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_creation_persists_identity_and_owned_cleanup_is_idempotent(self) -> None:
        self.run_script(r'''
Add-TestRule | Out-Null
$row = $script:Context.ledger.resources.firewall_rules[0]
Assert-True ($script:NewCalls -eq 1 -and $row.state -eq 'created') 'creation did not finish'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -gt 0) 'live owned rule invisible'
Remove-Ferrum2OwnedFirewallRule -Row $row
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'absent cleanup was not idempotent'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -eq 0) 'owned rule survived cleanup'
Assert-UnrelatedSurvives
''')

    def test_ledger_write_failure_prevents_provider_mutation(self) -> None:
        self.run_script(r'''
$script:LedgerFailure = $true
Assert-Rejected { Add-TestRule }
Assert-True ($script:NewCalls -eq 0) 'rule creation survived failed durable write'
Assert-UnrelatedSurvives
''')

    def test_active_store_must_match_not_just_persistent_store(self) -> None:
        self.run_script(r'''
$script:ActiveMismatch = $true
Assert-Rejected { Add-TestRule }
Assert-True ($script:NewCalls -eq 1) 'did not exercise effective policy readback'
$expected = $script:Context.ledger.expected_resources.firewall_rules
Assert-True (@($expected).Count -eq 1) 'failed readback lost recoverable identity'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected $expected) -gt 0) 'mismatched effective rule hid residue'
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $expected[0] }
Assert-True ($script:Removed.Count -eq 0) 'effective policy mismatch allowed deletion'
Assert-UnrelatedSurvives
''')

    def test_planned_identity_recovers_creation_before_completion_write(self) -> None:
        self.run_script(r'''
$script:CompletionWriteFailure = $true
Assert-Rejected { Add-TestRule }
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$row = $disk.resources.firewall_rules[0]
Assert-True ($row.state -eq 'planned') 'failed completion lost durable planned identity'
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -eq 0) 'planned rule not recovered'
Assert-True ($script:Removed.Count -eq 1) 'planned rule cleanup did not remove exactly one rule'
Assert-UnrelatedSurvives
''')

    def test_identity_mismatches_refuse_deletion(self) -> None:
        mutations = {
            "program": "$rule.Application.Program = Join-Path $Root 'different.exe'",
            "hash": "[IO.File]::AppendAllText($script:Executable, 'changed binary')",
            "port": "$rule.Port.LocalPort = @('Any')",
            "interface": "$rule.Interface.InterfaceAlias = @('Any')",
            "foreign-guid": "$rule.Interface.InterfaceAlias = @('d3e4c652-a1e6-4346-a828-37d698e2bab4')",
            "foreign-luid": "$rule.Interface.InterfaceAlias = @('14918723538255873')",
            "noncanonical-luid": "$rule.Interface.InterfaceAlias = @('014918723538255872')",
            "profile": "$rule.Profile = 'Private'",
            "action": "$rule.Action = 'Block'",
        }
        for name, mutation in mutations.items():
            with self.subTest(identity=name):
                self.run_script(r'''
Add-TestRule | Out-Null
$row = $script:Context.ledger.resources.firewall_rules[0]
$rule = @($script:Stores.PersistentStore | Where-Object Name -EQ $row.name)[0]
''' + mutation + r'''
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $row }
Assert-True ($script:Removed.Count -eq 0) 'ownership mismatch reached deletion'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -gt 0) 'mismatch lost residual identity'
Assert-UnrelatedSurvives
''')

    def test_historical_inventory_detects_rules_after_live_ledger_is_cleared(self) -> None:
        for remaining_store in ("PersistentStore", "ActiveStore"):
            with self.subTest(store=remaining_store):
                self.run_script(r'''
Add-TestRule | Out-Null
$historical = @($script:Context.ledger.expected_resources.firewall_rules)
$script:Context.ledger.resources.firewall_rules = @()
''' + f"$otherStore = '{'ActiveStore' if remaining_store == 'PersistentStore' else 'PersistentStore'}'\n" + r'''
$script:Stores[$otherStore] = @($script:Stores[$otherStore] | Where-Object Name -EQ 'unrelated-existing-rule')
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected $historical) -gt 0) 'historical rule escaped independent inventory'
Assert-UnrelatedSurvives
''')

    def test_inventory_failure_never_means_absent_or_permits_creation(self) -> None:
        for store in ("PersistentStore", "ActiveStore"):
            with self.subTest(store=store):
                self.run_script(r'''
Add-TestRule | Out-Null
$row = $script:Context.ledger.resources.firewall_rules[0]
''' + f"$script:ReadFailure = '{store}'\n" + r'''
Assert-Rejected { Get-Ferrum2FirewallRuleResidue -Expected @($row) }
Assert-Rejected { Get-Ferrum2FirewallRuleResidue -Expected @() }
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $row }
Assert-Rejected { Add-TestRule }
Assert-True ($script:NewCalls -eq 1) 'baseline inventory failure allowed creation'
Assert-True ($script:Removed.Count -eq 0) 'failed inventory allowed deletion'
Assert-UnrelatedSurvives
''')

    def test_retained_readback_survives_cleanup_but_rejects_altered_observations(self) -> None:
        self.run_script(r'''
Add-TestRule | Out-Null
$expected = @($script:Context.ledger.expected_resources.firewall_rules)
$row = $expected[0]
Remove-Ferrum2OwnedFirewallRule -Row $row
[IO.File]::Delete($script:Executable)
$directory = $script:Context.evidence_directory
$path = Join-Path $directory "firewall-rules/$($row.name).json"
$original = [IO.File]::ReadAllText($path)
Assert-Ferrum2FirewallEvidence -Expected $expected -EvidenceDirectory $directory

$document = $original | ConvertFrom-Json
$document.observations[1].filters.Port.LocalPort = @('Any')
Write-AtomicJsonFile -Path $path -Document $document
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected $expected -EvidenceDirectory $directory }

$document = $original | ConvertFrom-Json
$document.observations[1].program_sha256 = '0' * 64
Write-AtomicJsonFile -Path $path -Document $document
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected $expected -EvidenceDirectory $directory }

$document = $original | ConvertFrom-Json
$document.observations = @($document.observations[0], $document.observations[0])
Write-AtomicJsonFile -Path $path -Document $document
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected $expected -EvidenceDirectory $directory }

[IO.File]::Delete($path)
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected $expected -EvidenceDirectory $directory }
Assert-UnrelatedSurvives
''')

    def test_deferred_scope_rejects_non_client_or_broadened_identity(self) -> None:
        mutations = (
            "Purpose = 'server-tcp-1'", "Purpose = 'client-ingress-4'",
            "Protocol = 'UDP'", "LocalPort = '50000'", "LocalPort = 'Any'",
            "LocalPort = '1024-65535'", "LocalAddress = '198.18.1.146'",
            "RemoteAddress = '198.18.1.140'", "RemoteAddress = 'Any'",
            "InterfaceAlias = 'Ferrum2Host-ffffffffffff-001'",
            "InterfaceAlias = 'Ferrum2Host-012345abcdef-002'",
            "InterfaceAlias = 'Any'",
        )
        for mutation in mutations:
            with self.subTest(scope=mutation):
                self.run_script(
                    "Assert-Rejected { Add-DeferredTestRule -Changes @{ " + mutation + " } }\n"
                    "Assert-True ($script:NewCalls -eq 0) 'unsafe prelaunch rule reached provider'\n"
                    "Assert-UnrelatedSurvives\n"
                )

    def test_prelaunch_any_is_recoverable_but_never_qualified(self) -> None:
        self.run_script(r'''
$row = Add-DeferredTestRule
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    Assert-True ($rule.Interface.InterfaceAlias[0] -ceq 'Any') 'prelaunch required absent adapter'
}
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $script:Context.evidence_directory }
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'prelaunch rule was not recoverable'
Assert-UnrelatedSurvives
''')

    def test_same_rule_narrows_and_retains_both_readback_phases(self) -> None:
        self.run_script(r'''
$row = Add-DeferredTestRule
$name = $row.name
$directory = $script:Context.evidence_directory
$initialPath = Join-Path $directory "firewall-rules/$name.prelaunch.json"
$initial = [IO.File]::ReadAllText($initialPath)
Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row
Assert-True ($script:NewCalls -eq 1 -and $script:SetCalls -eq 1 -and $row.name -ceq $name) `
    'narrowing replaced rather than updated the same rule'
foreach ($rows in @(@{ value = $script:Context.ledger.resources.firewall_rules },
                     @{ value = $script:Context.ledger.expected_resources.firewall_rules })) {
    Assert-True (@($rows.value).Count -eq 1) 'narrowing duplicated historical identity'
    Assert-True ($rows.value[0].interface_phase -ceq 'narrowed' -and
        $rows.value[0].interface_alias -ceq $row.intended_interface_alias) 'final identity not recorded'
}
Assert-True ([IO.File]::ReadAllText($initialPath) -ceq $initial) 'final readback overwrote initial evidence'
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $name)[0]
    Assert-True ($rule.Interface.InterfaceAlias[0] -ceq $row.intended_interface_alias) 'store not narrowed'
}
Remove-Ferrum2OwnedFirewallRule -Row $row
[IO.File]::Delete($script:Executable)
Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory
$finalPath = Join-Path $directory "firewall-rules/$name.json"
$original = [IO.File]::ReadAllText($finalPath)
$document = $original | ConvertFrom-Json
$document.observations[1].filters.Interface.InterfaceAlias = @('Any')
Write-AtomicJsonFile -Path $finalPath -Document $document
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory }
[IO.File]::WriteAllText($finalPath, $original)
$document = $initial | ConvertFrom-Json
$document.observations[0].filters.Port.LocalPort = @('Any')
Write-AtomicJsonFile -Path $initialPath -Document $document
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory }
[IO.File]::Delete($initialPath)
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory }
Assert-UnrelatedSurvives
''')

    def test_failed_transition_intent_write_prevents_set(self) -> None:
        self.run_script(r'''
$row = Add-DeferredTestRule
$script:LedgerFailure = $true
Assert-Rejected { Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row }
Assert-True ($script:SetCalls -eq 0) 'failed durable transition write reached Set'
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
Remove-Ferrum2OwnedFirewallRule -Row $disk.resources.firewall_rules[0]
Assert-True ($script:Removed.Count -eq 1) 'failed transition lost prelaunch recovery'
Assert-UnrelatedSurvives
''')

    def test_durable_transition_recovers_crashes_and_mixed_store_states(self) -> None:
        for failure in ("before", "after", "skip-ActiveStore", "skip-PersistentStore", "completion-write"):
            with self.subTest(crash=failure):
                self.run_script(r'''
$row = Add-DeferredTestRule
''' + f"$script:SetFailure = '{failure}'\n" + r'''
Assert-Rejected { Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row }
Assert-True ($script:SetCalls -eq 1) 'did not exercise transition crash'
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$recovery = $disk.resources.firewall_rules[0]
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($recovery) -EvidenceDirectory $script:Context.evidence_directory }
Remove-Ferrum2OwnedFirewallRule -Row $recovery
Assert-True ($script:Removed.Count -eq 1) 'durable transition not recovered'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($recovery)) -eq 0) 'transition residue remains'
Assert-UnrelatedSurvives
''')

    def test_transition_cleanup_refuses_foreign_identity(self) -> None:
        mutations = {
            "alias": "$rule.Interface.InterfaceAlias = @('foreign-adapter')",
            "guid": "$rule.Interface.InterfaceAlias = @('d3e4c652-a1e6-4346-a828-37d698e2bab4')",
            "numeric": "$rule.Interface.InterfaceAlias = @('14918723538255873')",
            "path": "$rule.Application.Program = Join-Path $Root 'foreign.exe'",
            "hash": "[IO.File]::AppendAllText($script:Executable, 'changed')",
        }
        for store in ("PersistentStore", "ActiveStore"):
            for identity, mutation in mutations.items():
                with self.subTest(store=store, identity=identity):
                    self.run_script(r'''
$row = Add-DeferredTestRule
$script:SetFailure = 'before'
Assert-Rejected { Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row }
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$row = $disk.resources.firewall_rules[0]
''' + f"$rule = @($script:Stores['{store}'] | Where-Object Name -EQ $row.name)[0]\n" + mutation + r'''
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $row }
Assert-True ($script:Removed.Count -eq 0) 'foreign transition identity reached deletion'
Assert-UnrelatedSurvives
''')

    def test_legacy_fixed_row_without_transition_fields_remains_recoverable(self) -> None:
        self.run_script(r'''
$row = Add-TestRule
$row.PSObject.Properties.Remove('intended_interface_alias')
$row.PSObject.Properties.Remove('interface_phase')
$row.PSObject.Properties.Remove('interface_identity')
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'legacy exact-interface row lost recovery'
Assert-UnrelatedSurvives
''')

    def test_only_recorded_transition_allows_either_interface(self) -> None:
        for phase in ("prelaunch", "narrowed"):
            with self.subTest(phase=phase):
                setup = (
                    "Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row\n"
                    "$unexpected = 'Any'\n"
                    if phase == "narrowed" else
                    "$unexpected = $row.intended_interface_alias\n"
                )
                self.run_script(r'''
$row = Add-DeferredTestRule
''' + setup + r'''
$rule = @($script:Stores.ActiveStore | Where-Object Name -EQ $row.name)[0]
$rule.Interface.InterfaceAlias = @($unexpected)
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $row }
Assert-True ($script:Removed.Count -eq 0) 'nontransition row allowed an unrecorded interface state'
Assert-UnrelatedSurvives
''')

    def test_saved_fixed_identity_recovers_after_adapter_disappears(self) -> None:
        for representation in (
            "d3e4c652-a1e6-4346-a828-37d698e2bab3",
            "{D3E4C652-A1E6-4346-A828-37D698E2BAB3}",
            "14918723538255872",
        ):
            with self.subTest(representation=representation):
                self.run_script(r'''
$script:CompletionWriteFailure = $true
Assert-Rejected { Add-TestRule }
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$row = $disk.resources.firewall_rules[0]
Assert-True ($row.state -eq 'planned') 'crash recovery did not use durable intent'
[Ferrum2QualificationRouteNotification]::Disappeared = $true
''' + f"$representation = '{representation}'\n" + r'''
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    $rule.Interface.InterfaceAlias = @($representation)
}
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'recorded stable identity did not recover planned rule'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -eq 0) 'recovered rule remains'
Assert-UnrelatedSurvives
''')

    def test_stable_narrowed_evidence_survives_adapter_and_executable_removal(self) -> None:
        for representation in (
            "{D3E4C652-A1E6-4346-A828-37D698E2BAB3}", "14918723538255872",
        ):
            with self.subTest(representation=representation):
                self.run_script(r'''
$row = Add-DeferredTestRule
''' + f"$script:InterfaceRepresentation = '{representation}'\n" + r'''
Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$row = $disk.expected_resources.firewall_rules[0]
[Ferrum2QualificationRouteNotification]::Disappeared = $true
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'stable narrowed rule was not recovered'
[IO.File]::Delete($script:Executable)
$directory = $script:Context.evidence_directory
Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory
$path = Join-Path $directory "firewall-rules/$($row.name).json"
$original = [IO.File]::ReadAllText($path)
foreach ($foreign in @('unknown-adapter', 'd3e4c652-a1e6-4346-a828-37d698e2bab4',
        '14918723538255873', '014918723538255872')) {
    $document = $original | ConvertFrom-Json
    $document.observations[1].filters.Interface.InterfaceAlias = @($foreign)
    Write-AtomicJsonFile -Path $path -Document $document
    Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $directory }
}
Assert-UnrelatedSurvives
''')

    def test_narrowing_crash_recovers_stable_representation_with_other_store_any(self) -> None:
        for store, representation in (
            ("ActiveStore", "d3e4c652-a1e6-4346-a828-37d698e2bab3"),
            ("PersistentStore", "14918723538255872"),
        ):
            with self.subTest(store=store):
                self.run_script(r'''
$row = Add-DeferredTestRule
''' + f"$script:SetFailure = 'skip-{store}'\n$script:InterfaceRepresentation = '{representation}'\n" + r'''
Assert-Rejected { Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row }
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
$row = $disk.resources.firewall_rules[0]
Assert-True ($row.interface_phase -ceq 'narrowing') 'crash lost durable transition state'
[Ferrum2QualificationRouteNotification]::Disappeared = $true
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'mixed Any and stable identity did not recover'
Assert-True ((Get-Ferrum2FirewallRuleResidue -Expected @($row)) -eq 0) 'mixed-store residue remains'
Assert-Rejected { Assert-Ferrum2FirewallEvidence -Expected @($row) -EvidenceDirectory $script:Context.evidence_directory }
Assert-UnrelatedSurvives
''')

    def test_missing_native_identity_prevents_fixed_creation_and_narrowing(self) -> None:
        self.run_script(r'''
[Ferrum2QualificationRouteNotification]::Disappeared = $true
Assert-Rejected { Add-TestRule }
Assert-True ($script:NewCalls -eq 0) 'unbound fixed rule reached creation'
$row = Add-DeferredTestRule
Assert-True ($script:NewCalls -eq 1) 'prelaunch unexpectedly required a live adapter'
Assert-Rejected { Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row }
Assert-True ($script:SetCalls -eq 0) 'unbound narrowing reached mutation'
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
Remove-Ferrum2OwnedFirewallRule -Row $disk.resources.firewall_rules[0]
Assert-True ($script:Removed.Count -eq 1) 'failed identity resolution lost prelaunch recovery'
Assert-UnrelatedSurvives
''')

    def test_legacy_guid_only_binding_never_authorizes_numeric_filter(self) -> None:
        self.run_script(r'''
$row = Add-TestRule
$row.interface_identity.luid = $null
$row.interface_identity | Add-Member -NotePropertyName recovered_from_legacy_ledger -NotePropertyValue $true
[Ferrum2QualificationRouteNotification]::Disappeared = $true
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    $rule.Interface.InterfaceAlias = @('14918723538255872')
}
Assert-Rejected { Remove-Ferrum2OwnedFirewallRule -Row $row }
Assert-True ($script:Removed.Count -eq 0) 'GUID-only legacy binding authorized unrecorded LUID'
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    $rule.Interface.InterfaceAlias = @('{D3E4C652-A1E6-4346-A828-37D698E2BAB3}')
}
Remove-Ferrum2OwnedFirewallRule -Row $row
Assert-True ($script:Removed.Count -eq 1) 'exact legacy GUID lost safe recovery'
Assert-UnrelatedSurvives
''')

    def test_legacy_upgrade_requires_recorded_adapter_and_exact_native_conversion(self) -> None:
        self.run_script(r'''
$row = Add-DeferredTestRule
Complete-Ferrum2FirewallInterface -Context $script:Context -Row $row
$row.interface_identity = $null
$script:Context.ledger | Add-Member -NotePropertyName run_id -NotePropertyValue $script:Context.run_id
$script:Context.ledger.expected_resources | Add-Member -NotePropertyName adapters -NotePropertyValue @(
    [pscustomobject]@{ name = $row.interface_alias; state = 'created'
        interface_guid = 'd3e4c652-a1e6-4346-a828-37d698e2bab3' })
Save-Ferrum2FirewallIdentity -Context $script:Context -Row $row
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    $rule.Interface.InterfaceAlias = @('14918723538255873')
}
Assert-Rejected {
    Restore-Ferrum2LegacyFirewallInterfaceIdentity -Ledger $script:Context.ledger `
        -LedgerPath $script:Context.ledger_path
}
Assert-True ($null -eq $script:Context.ledger.resources.firewall_rules[0].interface_identity) `
    'foreign numeric interface acquired a legacy binding'
foreach ($store in @('PersistentStore', 'ActiveStore')) {
    $rule = @($script:Stores[$store] | Where-Object Name -EQ $row.name)[0]
    $rule.Interface.InterfaceAlias = @('14918723538255872')
}
Restore-Ferrum2LegacyFirewallInterfaceIdentity -Ledger $script:Context.ledger `
    -LedgerPath $script:Context.ledger_path
$disk = [IO.File]::ReadAllText($script:Context.ledger_path) | ConvertFrom-Json
Assert-True ($disk.resources.firewall_rules[0].interface_identity.luid -ceq '14918723538255872' -and
    $disk.resources.firewall_rules[0].interface_identity.recovered_from_legacy_ledger -eq $true) `
    'verified legacy native identity was not durable'
Remove-Ferrum2OwnedFirewallRule -Row $disk.resources.firewall_rules[0]
Assert-UnrelatedSurvives
''')
