#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines rollback helpers for Windows TUN lab topology provisioning.

.DESCRIPTION
This dot-source-only owner separates rollback ownership audit, source restoration, owned-resource
removal, and terminal verification. Loading it does not mutate state.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseShouldProcessForStateChangingFunctions',
    '',
    Justification = 'Rollback executes only inside the public driver authorized transaction.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $LibraryOnly) { throw 'topology rollback helpers are dot-source-only' }

function Get-TopologyRollbackOwnership {
    param([Parameter(Mandatory)] [object]$State)

    $vm = Get-VM -Id ([Guid][string]$State.Plan.vm.id) -ErrorAction Stop
    $null = Get-ManagementAdapter -Vm $vm -Plan $State.Plan
    $allAdapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    $ownedAdapterIds = @()
    if ($State.VmAdapterCreationAttempted -and
        $State.CreatedSwitchId -ne [Guid]::Empty) {
        $ownedAdapters = @(Get-NewSupportVmAdapterCandidate -Plan $State.Plan `
            -SwitchId $State.CreatedSwitchId `
            -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers)
        if ($ownedAdapters.Count -gt 1 -or
            ($ownedAdapters.Count -eq 1 -and
                -not [string]::IsNullOrWhiteSpace($State.CreatedVmAdapterId) -and
                [string]$ownedAdapters[0].Id -ine $State.CreatedVmAdapterId)) {
            throw 'support VM adapter ownership is ambiguous before rollback'
        }
        $ownedAdapterIds = @($ownedAdapters | ForEach-Object { [string]$_.Id })
    }
    $unexpectedAdapters = @($allAdapters | Where-Object {
        [string]$_.Id -ine [string]$State.Plan.management_adapter.id -and
        $ownedAdapterIds -inotcontains [string]$_.Id
    })
    if ($unexpectedAdapters.Count -ne 0) {
        throw 'approved VM gained an adapter not owned by this transaction'
    }

    $allCheckpoints = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $ownedCheckpointIds = @()
    if ($State.CheckpointCreationAttempted) {
        $ownedCheckpoints = @(if ($State.CreatedCheckpointId -ne [Guid]::Empty) {
            @($allCheckpoints | Where-Object {
                $_.Id -eq $State.CreatedCheckpointId -and
                $State.InitialCheckpointIds -cnotcontains $_.Id.ToString('D') -and
                ([string]$_.Name -ceq $State.CreatedCheckpointProvisioningName -or
                    [string]$_.Name -ceq [string]$State.Plan.lab_checkpoint.name) -and
                [string]$_.SnapshotType -ceq 'Standard' -and
                $_.IsAutomaticCheckpoint -eq $false
            })
        } else {
            @(Get-NewLabCheckpointCandidate -Plan $State.Plan `
                -InitialCheckpointIds $State.InitialCheckpointIds `
                -ProvisioningName $State.CreatedCheckpointProvisioningName)
        })
        if ($ownedCheckpoints.Count -gt 1) {
            throw 'lab checkpoint ownership is ambiguous before rollback'
        }
        $ownedCheckpointIds = @($ownedCheckpoints | ForEach-Object { $_.Id.ToString('D') })
    }
    $unexpectedCheckpoints = @($allCheckpoints | Where-Object {
        $State.InitialCheckpointIds -cnotcontains $_.Id.ToString('D') -and
        $ownedCheckpointIds -cnotcontains $_.Id.ToString('D')
    })
    if ($unexpectedCheckpoints.Count -ne 0) {
        throw 'approved VM gained a checkpoint not owned by this transaction'
    }
}

function Restore-TopologyRollbackSource {
    param([Parameter(Mandatory)] [object]$State)

    Invoke-Ferrum2PinnedVmLifecycle -Identity $script:provisioningVmIdentity `
        -Action Restore `
        -CheckpointId ([Guid][string]$State.Plan.source_checkpoint.id) `
        -CheckpointName ([string]$State.Plan.source_checkpoint.name) `
        -TimeoutSeconds $State.TimeoutSeconds | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds($State.TimeoutSeconds)
    do {
        $vm = Get-VM -Id ([Guid][string]$State.Plan.vm.id) -ErrorAction Stop
        $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
        $management = @($adapters | Where-Object {
            [string]$_.Id -ieq [string]$State.Plan.management_adapter.id
        })
        if ($adapters.Count -eq 1 -and $management.Count -eq 1) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'source checkpoint restore did not converge to its single-adapter inventory'
}

function Remove-TopologyRollbackCheckpoint {
    param([Parameter(Mandatory)] [object]$State)

    $vm = Get-VM -Id ([Guid][string]$State.Plan.vm.id) -ErrorAction Stop
    $rows = @(if ($State.CreatedCheckpointId -ne [Guid]::Empty) {
        Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
            $_.Id -eq $State.CreatedCheckpointId
        }
    } else {
        Get-NewLabCheckpointCandidate -Plan $State.Plan `
            -InitialCheckpointIds $State.InitialCheckpointIds `
            -ProvisioningName $State.CreatedCheckpointProvisioningName
    })
    if ($rows.Count -eq 0) { return }
    if ($rows.Count -ne 1 -or
        $State.InitialCheckpointIds -ccontains $rows[0].Id.ToString('D') -or
        $rows[0].VMId -ne [Guid][string]$State.Plan.vm.id -or
        ([string]$rows[0].Name -cne $State.CreatedCheckpointProvisioningName -and
            [string]$rows[0].Name -cne [string]$State.Plan.lab_checkpoint.name) -or
        [string]$rows[0].SnapshotType -cne 'Standard' -or
        $rows[0].IsAutomaticCheckpoint -ne $false) {
        throw 'created checkpoint no longer matches the recorded identity'
    }
    $checkpointId = $rows[0].Id
    $rows[0] | Remove-VMSnapshot -Confirm:$false -ErrorAction Stop | Out-Null
    if (@(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
            $_.Id -eq $checkpointId
        }).Count -ne 0) {
        throw 'created checkpoint remained after removal'
    }
}

function Remove-TopologyRollbackVmAdapter {
    param([Parameter(Mandatory)] [object]$State)

    $vm = Get-VM -Id ([Guid][string]$State.Plan.vm.id) -ErrorAction Stop
    $rows = if (-not [string]::IsNullOrWhiteSpace($State.CreatedVmAdapterId)) {
        @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
            [string]$_.Id -ieq $State.CreatedVmAdapterId
        })
    } elseif ($State.CreatedSwitchId -ne [Guid]::Empty) {
        @(Get-NewSupportVmAdapterCandidate -Plan $State.Plan `
            -SwitchId $State.CreatedSwitchId `
            -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers)
    } else {
        @()
    }
    if ($rows.Count -eq 0) { return }
    if ($rows.Count -ne 1) { throw 'created VM adapter identity is ambiguous' }
    $expectedIdentifiers = @($State.CreatedVmAdapterVirtualSystemIdentifiers |
        ForEach-Object { $_.ToString('D') })
    $actualIdentifiers = @($rows[0].VirtualSystemIdentifiers | ForEach-Object {
        ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label 'rollback support VM adapter identifier'
    })
    if ((ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$rows[0].MacAddress) `
            -Label 'rollback support VM adapter') -cne
            (ConvertTo-Ferrum2CanonicalMacAddress `
                -Value ([string]$State.Plan.support.vm_mac_address) `
                -Label 'planned support VM adapter') -or
        ($actualIdentifiers -join '|') -cne ($expectedIdentifiers -join '|') -or
        [string]$rows[0].Name -cne [string]$State.Plan.support.vm_adapter_name -or
        $rows[0].SwitchId -ne $State.CreatedSwitchId -or
        $rows[0].DynamicMacAddressEnabled -ne $false -or
        $rows[0].VMId -ne [Guid][string]$State.Plan.vm.id) {
        throw 'created VM adapter no longer matches the recorded identity'
    }
    $adapterId = [string]$rows[0].Id
    $rows[0] | Remove-VMNetworkAdapter -Confirm:$false -ErrorAction Stop | Out-Null
    if (@(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
            [string]$_.Id -ieq $adapterId
        }).Count -ne 0) {
        throw 'created VM adapter remained after removal'
    }
}

function Wait-TopologyRollbackSwitchDetach {
    param([Parameter(Mandatory)] [object]$State)

    $deadline = [DateTime]::UtcNow.AddSeconds($State.TimeoutSeconds)
    do {
        $vmAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
            $_.SwitchId -eq $State.CreatedSwitchId -and $_.IsManagementOs -ne $true
        })
        $snapshotAttachments = @(
            foreach ($vm in @(Get-VM -ErrorAction Stop)) {
                foreach ($snapshot in @(Get-VMSnapshot -VM $vm -ErrorAction Stop)) {
                    Get-VMNetworkAdapter -VMSnapshot $snapshot -ErrorAction Stop |
                        Where-Object { $_.SwitchId -eq $State.CreatedSwitchId }
                }
            }
        )
        if ($vmAttachments.Count -eq 0 -and $snapshotAttachments.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'created vSwitch still has VM or checkpoint attachments'
}

function Remove-TopologyRollbackSwitch {
    param([Parameter(Mandatory)] [object]$State)

    $rows = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
        $_.Id -eq $State.CreatedSwitchId
    })
    if ($rows.Count -eq 0) { return }
    if ($rows.Count -ne 1 -or
        [string]$rows[0].Name -cne [string]$State.Plan.support.switch_name -or
        [string]$rows[0].SwitchType -cne 'Internal' -or
        $rows[0].AllowManagementOS -ne $true) {
        throw 'created vSwitch ID no longer matches the recorded identity'
    }
    $context = Get-SupportSwitchContext -Plan $State.Plan `
        -SwitchId $State.CreatedSwitchId -TimeoutSeconds 5
    Wait-TopologyRollbackSwitchDetach -State $State
    $managementAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop |
        Where-Object {
            $_.SwitchId -eq $State.CreatedSwitchId -and $_.IsManagementOs -eq $true
        })
    if ($managementAttachments.Count -ne 1 -or
        [string]$managementAttachments[0].Id -ine [string]$context.ManagementAdapter.Id) {
        throw 'created vSwitch management OS attachment identity changed'
    }
    Assert-NoSupportNat -Plan $State.Plan
    Assert-IcsDisabledForHostAdapter -InterfaceGuid ([Guid]$context.HostAdapter.InterfaceGuid)
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        $addressRows = if ($store -ceq 'ActiveStore') {
            @(Get-ActiveIpv4AddressRow -InterfaceIndex ([int]$context.HostAdapter.ifIndex))
        } else {
            @(Get-PersistentIpv4AddressRow | Where-Object {
                    [int]$_.InterfaceIndex -eq [int]$context.HostAdapter.ifIndex
                })
        }
        $unexpected = @($addressRows | Where-Object {
            [string]$_.IPAddress -cne [string]$State.Plan.support.host_ipv4 -or
            [int]$_.PrefixLength -ne [int]$State.Plan.support.prefix_length
        })
        if ($unexpected.Count -ne 0 -or $addressRows.Count -gt 1) {
            throw "created vSwitch host IPv4 identity changed in $store"
        }
        foreach ($address in $addressRows) {
            $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        }
    }
    $rows[0] | Remove-VMSwitch -Force -Confirm:$false -ErrorAction Stop | Out-Null
    if (@(Get-VMSwitch -ErrorAction Stop | Where-Object {
            $_.Id -eq $State.CreatedSwitchId
        }).Count -ne 0) {
        throw 'created vSwitch remained after removal'
    }
}

function Assert-TopologyRollbackTerminalState {
    param([Parameter(Mandatory)] [object]$State)

    $context = Get-Ferrum2PinnedVmContext -Identity $script:provisioningVmIdentity
    $preflight = Get-ReadOnlyPreflight -Context $context -Plan $State.Plan
    if ([string]$preflight.host_tun.interface_guid -cne
            [string]$State.InitialTun.interface_guid -or
        [int]$preflight.host_tun.interface_index -ne
            [int]$State.InitialTun.interface_index -or
        [string]$preflight.host_tun.name -cne [string]$State.InitialTun.name -or
        [string]$preflight.host_tun.status -cne 'Up') {
        throw 'protected host tun0 identity changed during rollback'
    }
}

function Get-TopologyReprovisionState {
    param(
        [Parameter(Mandatory)] [object]$PlanDocument,
        [Parameter(Mandatory)] [string]$ManifestPath,
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedManifestSha256,
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $resolved = Resolve-Ferrum2HostInput -RepositoryRoot $RepositoryRoot `
        -Path $ManifestPath -Label 'existing topology identity manifest' `
        -Kind ExternalFile -MaximumBytes 131072
    $document = Read-Ferrum2JsonDocument -Path $resolved -MaximumBytes 131072 -SingleLine
    if ([string]$document.Sha256 -cne $ExpectedManifestSha256) {
        throw 'existing topology identity manifest hash mismatch'
    }

    $manifest = $document.Value
    $plan = $PlanDocument.Value
    foreach ($contract in @(
        @($manifest, @(
            'schema', 'created_utc', 'topology_plan_sha256',
            'provisioning_source_manifest_sha256', 'provisioning_source_bundle_sha256', 'vm',
            'source_checkpoint', 'lab_checkpoint', 'management_adapter', 'support',
            'protected_host_tun', 'constraints'
        ), 'existing topology manifest'),
        @($manifest.vm, @('name', 'id', 'terminal_state', 'automatic_checkpoints_enabled'),
            'existing topology VM'),
        @($manifest.source_checkpoint, @('name', 'id', 'type'),
            'existing source checkpoint'),
        @($manifest.lab_checkpoint, @(
            'name', 'id', 'type', 'parent_id', 'support_vm_adapter_snapshot_id',
            'restore_verified'
        ), 'existing lab checkpoint'),
        @($manifest.support, @('switch', 'vm_adapter', 'guest'),
            'existing support topology'),
        @($manifest.support.switch, @(
            'switch_name', 'switch_id', 'switch_type', 'management_os_adapter_id',
            'management_os_device_id', 'host_interface_alias', 'host_interface_guid',
            'host_interface_index', 'host_mac_address', 'host_ipv4', 'prefix_length', 'network',
            'gateway', 'dns_servers', 'mtu_bytes', 'nat_enabled', 'ics_enabled',
            'selected_source_ipv4', 'selected_route_prefix', 'selected_route_next_hop'
        ), 'existing support switch'),
        @($manifest.support.vm_adapter, @(
            'name', 'id', 'switch_id', 'mac_address', 'dynamic_mac_address',
            'virtual_system_identifiers'
        ), 'existing support VM adapter'),
        @($manifest.protected_host_tun, @(
            'present', 'name', 'interface_guid', 'interface_index', 'status'
        ), 'existing protected host TUN')
    )) {
        Assert-Ferrum2ClosedProperties -Value $contract[0] `
            -Expected ([string[]]$contract[1]) -Label ([string]$contract[2])
    }

    foreach ($hashName in @(
        'topology_plan_sha256', 'provisioning_source_manifest_sha256',
        'provisioning_source_bundle_sha256'
    )) {
        if ($manifest.$hashName -isnot [string] -or
            [string]$manifest.$hashName -cnotmatch '^[0-9a-f]{64}$') {
            throw "existing topology manifest $hashName is invalid"
        }
    }

    $vmId = ConvertTo-Ferrum2CanonicalGuid -Value $manifest.vm.id `
        -Label 'existing topology VM'
    $sourceCheckpointId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $manifest.source_checkpoint.id -Label 'existing source checkpoint'
    $labCheckpointId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $manifest.lab_checkpoint.id -Label 'existing lab checkpoint'
    $labParentId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $manifest.lab_checkpoint.parent_id -Label 'existing lab checkpoint parent'
    $switchId = ConvertTo-Ferrum2CanonicalGuid -Value $manifest.support.switch.switch_id `
        -Label 'existing support switch'
    $adapterSwitchId = ConvertTo-Ferrum2CanonicalGuid `
        -Value $manifest.support.vm_adapter.switch_id -Label 'existing support adapter switch'
    $plannedVmId = ConvertTo-Ferrum2CanonicalGuid -Value $plan.vm.id -Label 'planned VM'
    $plannedSourceId = ConvertTo-Ferrum2CanonicalGuid -Value $plan.source_checkpoint.id `
        -Label 'planned source checkpoint'
    $supportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$manifest.support.vm_adapter.mac_address) `
        -Label 'existing support VM adapter'
    $plannedSupportMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$plan.support.vm_mac_address) -Label 'planned support VM adapter'
    $virtualSystemIdentifiers = @($manifest.support.vm_adapter.virtual_system_identifiers |
        ForEach-Object {
            [Guid](ConvertTo-Ferrum2CanonicalGuid -Value $_ `
                -Label 'existing support VM adapter identifier')
        })

    if ($manifest.schema -isnot [long] -or [long]$manifest.schema -ne 1 -or
        [string]$manifest.topology_plan_sha256 -cne [string]$PlanDocument.Sha256 -or
        $vmId -cne $plannedVmId -or [string]$manifest.vm.name -cne [string]$plan.vm.name -or
        [string]$manifest.vm.terminal_state -cne 'Off' -or
        $manifest.vm.automatic_checkpoints_enabled -isnot [bool] -or
        $manifest.vm.automatic_checkpoints_enabled -ne $false -or
        $sourceCheckpointId -cne $plannedSourceId -or
        [string]$manifest.source_checkpoint.name -cne [string]$plan.source_checkpoint.name -or
        [string]$manifest.source_checkpoint.type -cne [string]$plan.source_checkpoint.type -or
        $labCheckpointId -ceq $sourceCheckpointId -or $labParentId -cne $sourceCheckpointId -or
        [string]$manifest.lab_checkpoint.name -cne [string]$plan.lab_checkpoint.name -or
        [string]$manifest.lab_checkpoint.type -cne [string]$plan.lab_checkpoint.type -or
        $manifest.lab_checkpoint.restore_verified -isnot [bool] -or
        $manifest.lab_checkpoint.restore_verified -ne $true -or
        [string]$manifest.support.switch.switch_name -cne [string]$plan.support.switch_name -or
        [string]$manifest.support.switch.switch_type -cne 'Internal' -or
        $switchId -cne $adapterSwitchId -or
        [string]$manifest.support.switch.host_ipv4 -cne [string]$plan.support.host_ipv4 -or
        [int]$manifest.support.switch.prefix_length -ne [int]$plan.support.prefix_length -or
        [string]$manifest.support.switch.network -cne [string]$plan.support.network -or
        $null -ne $manifest.support.switch.gateway -or
        @($manifest.support.switch.dns_servers).Count -ne 0 -or
        $manifest.support.switch.nat_enabled -isnot [bool] -or
        $manifest.support.switch.nat_enabled -ne $false -or
        $manifest.support.switch.ics_enabled -isnot [bool] -or
        $manifest.support.switch.ics_enabled -ne $false -or
        [string]$manifest.support.vm_adapter.name -cne
            [string]$plan.support.vm_adapter_name -or
        $supportMac -cne $plannedSupportMac -or
        $manifest.support.vm_adapter.dynamic_mac_address -isnot [bool] -or
        $manifest.support.vm_adapter.dynamic_mac_address -ne $false -or
        $virtualSystemIdentifiers.Count -ne 2 -or
        @($virtualSystemIdentifiers | Sort-Object -Unique).Count -ne 2 -or
        $manifest.protected_host_tun.present -isnot [bool] -or
        $manifest.protected_host_tun.present -ne $true -or
        [string]$manifest.protected_host_tun.name -cne 'tun0' -or
        [string]$manifest.protected_host_tun.status -cne 'Up') {
        throw 'existing topology manifest is not bound to the approved provisioned topology'
    }

    $null = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$manifest.support.vm_adapter.id) `
        -ExpectedOwnerId ([Guid]$vmId) -Label 'existing support VM adapter'
    $currentTun = Get-HostTunIdentity
    if ($currentTun.present -ne $true -or
        [string]$currentTun.name -cne [string]$manifest.protected_host_tun.name -or
        [string]$currentTun.interface_guid -cne
            [string]$manifest.protected_host_tun.interface_guid -or
        [string]$currentTun.status -cne [string]$manifest.protected_host_tun.status) {
        throw 'protected host tun0 identity changed before reprovisioning'
    }

    [pscustomobject][ordered]@{
        Plan = $plan
        CreatedSwitchId = [Guid]$switchId
        CreatedVmAdapterId = [string]$manifest.support.vm_adapter.id
        CreatedVmAdapterVirtualSystemIdentifiers = [Guid[]]$virtualSystemIdentifiers
        VmAdapterCreationAttempted = $true
        CreatedCheckpointId = [Guid]$labCheckpointId
        CreatedCheckpointProvisioningName = [string]$manifest.lab_checkpoint.name
        CheckpointCreationAttempted = $true
        InitialCheckpointIds = [string[]]@($sourceCheckpointId)
        InitialTun = $currentTun
        TimeoutSeconds = $TimeoutSeconds
        ExistingManifestPath = [string]$document.Path
        ExistingManifestSha256 = [string]$document.Sha256
    }
}

function Invoke-TopologyRollback {
    param(
        [Parameter(Mandatory)] [object]$Plan,
        [Parameter(Mandatory)] [Guid]$CreatedSwitchId,
        [AllowNull()] [string]$CreatedVmAdapterId,
        [Parameter(Mandatory)] [Guid[]]$CreatedVmAdapterVirtualSystemIdentifiers,
        [Parameter(Mandatory)] [bool]$VmAdapterCreationAttempted,
        [Parameter(Mandatory)] [Guid]$CreatedCheckpointId,
        [Parameter(Mandatory)] [string]$CreatedCheckpointProvisioningName,
        [Parameter(Mandatory)] [bool]$CheckpointCreationAttempted,
        [Parameter(Mandatory)] [string[]]$InitialCheckpointIds,
        [Parameter(Mandatory)] [object]$InitialTun,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $state = [pscustomobject][ordered]@{
        Plan = $Plan
        CreatedSwitchId = $CreatedSwitchId
        CreatedVmAdapterId = $CreatedVmAdapterId
        CreatedVmAdapterVirtualSystemIdentifiers = $CreatedVmAdapterVirtualSystemIdentifiers
        VmAdapterCreationAttempted = $VmAdapterCreationAttempted
        CreatedCheckpointId = $CreatedCheckpointId
        CreatedCheckpointProvisioningName = $CreatedCheckpointProvisioningName
        CheckpointCreationAttempted = $CheckpointCreationAttempted
        InitialCheckpointIds = $InitialCheckpointIds
        InitialTun = $InitialTun
        TimeoutSeconds = $TimeoutSeconds
    }
    $failures = [Collections.Generic.List[string]]::new()
    $vmOff = $false
    $ownershipApproved = $false
    $sourceRestored = $false
    try {
        Invoke-Ferrum2PinnedVmLifecycle -Identity $script:provisioningVmIdentity `
            -Action Stop `
            -TimeoutSeconds $TimeoutSeconds | Out-Null
        $vmOff = $true
    } catch { $failures.Add("VM Off: $($_.Exception.Message)") }
    if ($vmOff) {
        try {
            Get-TopologyRollbackOwnership -State $state
            $ownershipApproved = $true
        } catch { $failures.Add("rollback ownership audit: $($_.Exception.Message)") }
    }
    if ($ownershipApproved) {
        try {
            Restore-TopologyRollbackSource -State $state
            $sourceRestored = $true
        } catch { $failures.Add("source checkpoint restore: $($_.Exception.Message)") }
    }
    if ($CheckpointCreationAttempted -and $ownershipApproved) {
        try { Remove-TopologyRollbackCheckpoint -State $state }
        catch { $failures.Add("new checkpoint removal: $($_.Exception.Message)") }
    }
    if ($VmAdapterCreationAttempted -and -not $sourceRestored -and $ownershipApproved) {
        try { Remove-TopologyRollbackVmAdapter -State $state }
        catch { $failures.Add("support VM adapter removal: $($_.Exception.Message)") }
    }
    if ($CreatedSwitchId -ne [Guid]::Empty -and $ownershipApproved) {
        try { Remove-TopologyRollbackSwitch -State $state }
        catch { $failures.Add("support vSwitch removal: $($_.Exception.Message)") }
    }
    try { Assert-TopologyRollbackTerminalState -State $state }
    catch { $failures.Add("final source-state validation: $($_.Exception.Message)") }
    @($failures)
}
