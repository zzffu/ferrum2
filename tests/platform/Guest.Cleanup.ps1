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
