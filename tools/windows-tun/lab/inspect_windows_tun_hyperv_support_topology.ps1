#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Performs the read-only preflight for the pinned Windows TUN Hyper-V support topology.
#>

[CmdletBinding(DefaultParameterSetName = 'Inspect')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Library', DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..') `
    -ErrorAction Stop).Path
$labManifestPath = Join-Path $repositoryRoot `
    'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psd1'
Import-Module $labManifestPath -Force -ErrorAction Stop
$readonlyOwnerPath = Join-Path $PSScriptRoot `
    'windows_tun_hyperv_support_topology_readonly.ps1'
. $readonlyOwnerPath -LibraryOnly -LabRoot $PSScriptRoot

if ($LibraryOnly) {
    return
}

$planDocument = Read-TopologyPlan
$context = Get-Ferrum2PinnedVmContext `
    -Identity (New-Ferrum2PinnedVmIdentity -Plan $planDocument.Value)
$preflight = Get-ReadOnlyPreflight -Context $context -Plan $planDocument.Value

[pscustomobject][ordered]@{
    schema = 1
    mode = "read_only_preflight"
    status = "ready_for_explicit_authorization"
    topology_plan_path = $planDocument.Path
    topology_plan_sha256 = $planDocument.Sha256
    inspector_sha256 = (Get-FileHash -LiteralPath $PSCommandPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    preflight = $preflight
    proposed_mutations = @(
        "restore exact source checkpoint while VM is Off",
        "create one Internal vSwitch named $($planDocument.Value.support.switch_name)",
        "assign $($planDocument.Value.support.host_ipv4)/$($planDocument.Value.support.prefix_length) to its host vNIC",
        "add one static-MAC support NIC to the approved VM",
        "assign $($planDocument.Value.support.guest_ipv4)/$($planDocument.Value.support.prefix_length) to the guest support NIC",
        "create and verify Standard checkpoint $($planDocument.Value.lab_checkpoint.name)",
        "write a new external identity manifest"
    )
    forbidden_mutations = @(
        "host tun0",
        "Default Switch",
        "physical host adapters",
        "default routes",
        "NAT",
        "ICS",
        "firewall",
        "DNS outside the two new support interfaces"
    )
    terminal_vm_state = "Off"
} | ConvertTo-Json -Depth 8
