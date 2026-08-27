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
        $ownedCheckpoints = if ($State.CreatedCheckpointId -ne [Guid]::Empty) {
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
        }
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
    $rows = if ($State.CreatedCheckpointId -ne [Guid]::Empty) {
        @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
            $_.Id -eq $State.CreatedCheckpointId
        })
    } else {
        @(Get-NewLabCheckpointCandidate -Plan $State.Plan `
            -InitialCheckpointIds $State.InitialCheckpointIds `
            -ProvisioningName $State.CreatedCheckpointProvisioningName)
    }
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
            @(Get-ProvisioningPersistentIpv4AddressRow `
                -InterfaceIndex ([int]$context.HostAdapter.ifIndex))
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
