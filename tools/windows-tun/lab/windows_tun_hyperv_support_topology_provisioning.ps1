#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines the manifest-bound library for Windows TUN Hyper-V support topology provisioning.

.DESCRIPTION
This dot-source-only library defines guest result and canonical evidence helpers. The driver loads
the verified read-only and host-mutation owners before loading this file.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseShouldProcessForStateChangingFunctions",
    "",
    Justification = "Private helpers are invoked only after the driver's single explicit ShouldProcess gate."
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseUsingScopeModifierInNewRunspaces",
    "",
    Justification = "Remoting values are bound through ArgumentList and the remote param block."
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $LibraryOnly) {
    throw "provisioning helpers are dot-source-only"
}

function Invoke-GuestSupportNetwork {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)]
        [ValidateSet('initial_configure', 'post_checkpoint_restore')]
        [string]$Phase,
        [switch]$Configure
    )

    if ($script:guestProvisioningScript -isnot [scriptblock]) {
        throw 'verified guest provisioning source is unavailable'
    }
    $result = @(Invoke-Command -Session $Session -ErrorAction Stop `
        -ScriptBlock $script:guestProvisioningScript -ArgumentList @(
        [string]$Plan.management_adapter.mac_address,
        [string]$Plan.support.vm_mac_address,
        [string]$Plan.support.guest_interface_alias,
        [string]$Plan.support.guest_ipv4,
        [int]$Plan.support.prefix_length,
        [string]$Plan.support.network,
        [string]$Plan.support.host_ipv4,
        $Phase,
        [bool]$Configure
    ))
    ConvertFrom-GuestSupportNetworkResult -Result $result -Plan $Plan
}

function ConvertFrom-GuestSupportNetworkResult {
    param(
        [Parameter(Mandatory = $true)][object[]]$Result,
        [Parameter(Mandatory = $true)][object]$Plan
    )

    if ($Result.Count -ne 1 -or [int]$Result[0].schema -ne 1) {
        throw 'guest support topology probe returned an invalid result'
    }
    $guestFields = @(
        'schema', 'management_interface_alias', 'management_interface_guid',
        'management_interface_index', 'management_mac_address', 'support_interface_alias',
        'support_interface_guid', 'support_interface_index', 'support_mac_address',
        'guest_ipv4', 'prefix_length', 'network', 'gateway', 'dns_servers', 'mtu_bytes',
        'selected_source_ipv4', 'selected_route_prefix', 'selected_route_next_hop'
    )
    $remotingFields = @('PSComputerName', 'RunspaceId', 'PSShowComputerName')
    $actualFields = @($Result[0].PSObject.Properties.Name)
    $cleanShape = ($actualFields -join '|') -ceq ($guestFields -join '|')
    $remotingShape = ($actualFields -join '|') -ceq
        (@($guestFields + $remotingFields) -join '|')
    if ((-not $cleanShape -and -not $remotingShape) -or
        $null -ne $Result[0].gateway -or @($Result[0].dns_servers).Count -ne 0) {
        throw 'guest support topology probe property set is invalid'
    }
    if ($remotingShape) {
        $runspaceId = [Guid]::Empty
        if ([string]$Result[0].PSComputerName -cne [string]$Plan.vm.name -or
            -not [Guid]::TryParse([string]$Result[0].RunspaceId, [ref]$runspaceId) -or
            $runspaceId -eq [Guid]::Empty -or
            $Result[0].PSShowComputerName -isnot [bool] -or
            $Result[0].PSShowComputerName -ne $true) {
            throw 'guest support topology probe remoting metadata is invalid'
        }
    }
    [pscustomobject][ordered]@{
        schema = [int]$Result[0].schema
        management_interface_alias = [string]$Result[0].management_interface_alias
        management_interface_guid = [string]$Result[0].management_interface_guid
        management_interface_index = [int]$Result[0].management_interface_index
        management_mac_address = [string]$Result[0].management_mac_address
        support_interface_alias = [string]$Result[0].support_interface_alias
        support_interface_guid = [string]$Result[0].support_interface_guid
        support_interface_index = [int]$Result[0].support_interface_index
        support_mac_address = [string]$Result[0].support_mac_address
        guest_ipv4 = [string]$Result[0].guest_ipv4
        prefix_length = [int]$Result[0].prefix_length
        network = [string]$Result[0].network
        gateway = $null
        dns_servers = @()
        mtu_bytes = [int]$Result[0].mtu_bytes
        selected_source_ipv4 = [string]$Result[0].selected_source_ipv4
        selected_route_prefix = [string]$Result[0].selected_route_prefix
        selected_route_next_hop = [string]$Result[0].selected_route_next_hop
    }
}

function Assert-GuestIdentityUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Before,
        [Parameter(Mandatory = $true)][object]$After
    )

    foreach ($field in @(
        "management_interface_alias", "management_interface_guid", "management_mac_address",
        "support_interface_alias", "support_interface_guid", "support_mac_address", "guest_ipv4",
        "prefix_length", "network", "mtu_bytes", "selected_source_ipv4",
        "selected_route_prefix", "selected_route_next_hop"
    )) {
        if ([string]$Before.$field -cne [string]$After.$field) {
            throw "guest support identity changed after checkpoint restore: field=$field"
        }
    }
}
function New-CanonicalJsonPayload {
    param([Parameter(Mandatory = $true)][object]$Value)

    $json = $Value | ConvertTo-Json -Compress -Depth 10
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    return [pscustomobject][ordered]@{
        PSTypeName = "Ferrum2.WindowsTun.CanonicalJsonPayload"
        Bytes = $bytes
        Sha256 = $hash
    }
}

function Write-NewCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Payload
    )

    if ($Payload.PSObject.TypeNames -notcontains
            "Ferrum2.WindowsTun.CanonicalJsonPayload" -or
        $Payload.PSObject.Properties.Name -notcontains "Bytes" -or
        $Payload.PSObject.Properties.Name -notcontains "Sha256" -or
        $Payload.Bytes -isnot [byte[]] -or
        ([byte[]]$Payload.Bytes).Length -eq 0 -or
        [string]$Payload.Sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw "canonical JSON payload is invalid"
    }
    [byte[]]$bytes = $Payload.Bytes
    $payloadHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($payloadHash -cne [string]$Payload.Sha256) {
        throw "canonical JSON payload hash does not match its bytes"
    }
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $moved = $false
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporaryPath, $Path)
        $moved = $true
    } finally {
        if (-not $moved) {
            try {
                if (Test-Path -LiteralPath $temporaryPath) {
                    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
                }
            } catch {
                $null = $_
            }
        }
    }
}
