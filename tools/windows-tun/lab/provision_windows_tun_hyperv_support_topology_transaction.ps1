#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines explicit phases for the Windows TUN lab provisioning transaction.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseShouldProcessForStateChangingFunctions',
    '',
    Justification = 'Every phase runs only after the public driver ShouldProcess gate.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, DontShow = $true)]
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $LibraryOnly) { throw 'provisioning transaction phases are dot-source-only' }

function Get-NewSupportVmAdapterCandidate {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][Guid[]]$VirtualSystemIdentifiers
    )

    $vm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
    $expectedMac = ConvertTo-Ferrum2CanonicalMacAddress `
        -Value ([string]$Plan.support.vm_mac_address) -Label "planned support VM adapter"
    $expectedIdentifiers = @($VirtualSystemIdentifiers | ForEach-Object { $_.ToString("D") })
    return @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
            $actualIdentifiers = @($_.VirtualSystemIdentifiers | ForEach-Object {
                    ConvertTo-Ferrum2CanonicalGuid -Value $_ -Label "candidate support VM adapter identifier"
                })
            [string]$_.Name -ceq [string]$Plan.support.vm_adapter_name -and
            $_.SwitchId -eq $SwitchId -and $_.DynamicMacAddressEnabled -eq $false -and
            ($actualIdentifiers -join "|") -ceq ($expectedIdentifiers -join "|") -and
            (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$_.MacAddress) `
                -Label "candidate support VM adapter") -ceq $expectedMac
        })
}

function Get-NewLabCheckpointCandidate {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string[]]$InitialCheckpointIds,
        [Parameter(Mandatory = $true)][string]$ProvisioningName
    )

    $vm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
    return @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
            $InitialCheckpointIds -cnotcontains $_.Id.ToString("D") -and
            [string]$_.Name -ceq $ProvisioningName -and
            [string]$_.SnapshotType -ceq "Standard" -and
            $_.IsAutomaticCheckpoint -eq $false
        })
}

function New-ProvisioningTransactionState {
    param(
        [Parameter(Mandatory)] [object]$PlanDocument,
        [Parameter(Mandatory)] [object]$InitialPreflight,
        [Parameter(Mandatory)] [string]$ManifestPath,
        [AllowEmptyString()] [string]$CredentialPath,
        [Parameter(Mandatory)] [int]$ReadinessTimeoutSeconds,
        [Parameter(Mandatory)] [int]$ShutdownTimeoutSeconds,
        [Parameter(Mandatory)] [object]$SourceIdentity
    )
    $plan = $PlanDocument.Value
    [pscustomobject][ordered]@{
        PlanDocument                             = $PlanDocument
        Plan                                     = $plan
        VmIdentity                               = New-Ferrum2PinnedVmIdentity -Plan $plan
        InitialPreflight                         = $InitialPreflight
        ManifestPath                             = $ManifestPath
        CredentialPath                           = $CredentialPath
        ReadinessTimeoutSeconds                  = $ReadinessTimeoutSeconds
        ShutdownTimeoutSeconds                   = $ShutdownTimeoutSeconds
        SourceIdentity                           = $SourceIdentity
        Mutex                                    = [Threading.Mutex]::new(
            $false,
            'Global\Ferrum2WindowsTunSupportTopologyV1'
        )
        MutexOwned                               = $false
        Credential                               = $null
        Session                                  = $null
        CreatedSwitchId                          = [Guid]::Empty
        CreatedVmAdapterId                       = $null
        CreatedVmAdapterVirtualSystemIdentifiers = @([Guid]::NewGuid(), [Guid]::NewGuid())
        CreatedCheckpointId                      = [Guid]::Empty
        CreatedCheckpointProvisioningName        =
        "$([string]$plan.lab_checkpoint.name).provisioning-$([Guid]::NewGuid().ToString('N'))"
        VmAdapterCreationAttempted               = $false
        CheckpointCreationAttempted              = $false
        InitialCheckpointIds                     = @()
        InitialTun                               = $null
        ConfiguredGuestState                     = $null
        VerifiedGuestState                       = $null
        RunningHostState                         = $null
        MutationStarted                          = $false
        ManifestCommitted                        = $false
        ManifestWriteAttempted                   = $false
        ManifestPayload                          = $null
        SuccessJson                              = $null
        Failure                                  = $null
    }
}

function Enter-ProvisioningTransaction {
    param([Parameter(Mandatory)] [object]$State)
    try {
        $State.MutexOwned = $State.Mutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        $State.MutexOwned = $true
        throw 'a prior support-topology transaction abandoned its mutex; retry after read-only audit'
    }
    if (-not $State.MutexOwned) {
        throw 'another Ferrum2 support-topology transaction is active'
    }
    $State.Credential = Resolve-Ferrum2HostInput -RepositoryRoot $script:repositoryRoot `
        -Path $State.CredentialPath -Label 'guest credential' -Kind GuestCredential `
        -MaximumBytes 1048576
    $freshPlanDocument = Read-TopologyPlan -Path $State.PlanDocument.Path
    if ($freshPlanDocument.Sha256 -cne $State.PlanDocument.Sha256) {
        throw 'topology plan changed after the initial preflight'
    }
    $freshContext = Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity
    $freshPreflight = Get-ReadOnlyPreflight -Context $freshContext -Plan $State.Plan
    Assert-ProvisioningSourceIdentity
    $State.InitialTun = $freshPreflight.host_tun
    $State.InitialCheckpointIds = @(
        Get-VMSnapshot -VM $freshContext.Vm -ErrorAction Stop |
            ForEach-Object { $_.Id.ToString('D') } |
            Sort-Object
    )
}

function Initialize-ProvisioningInfrastructure {
    param([Parameter(Mandatory)] [object]$State)
    $State.MutationStarted = $true
    Invoke-Ferrum2PinnedVmLifecycle -Identity $State.VmIdentity -Action Restore `
        -CheckpointId ([Guid][string]$State.Plan.source_checkpoint.id) `
        -CheckpointName ([string]$State.Plan.source_checkpoint.name) `
        -TimeoutSeconds $State.ShutdownTimeoutSeconds | Out-Null
    $restoredContext = Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity
    $null = Get-ReadOnlyPreflight -Context $restoredContext -Plan $State.Plan

    $State.CreatedSwitchId = [Guid]::NewGuid()
    $createdSwitchRows = @(New-VMSwitch -Name ([string]$State.Plan.support.switch_name) `
            -SwitchType Internal -Id $State.CreatedSwitchId.ToString("D") -Confirm:$false `
            -ErrorAction Stop)
    if ($createdSwitchRows.Count -ne 1 -or
        $createdSwitchRows[0].Id -ne $State.CreatedSwitchId -or
        [string]$createdSwitchRows[0].Name -cne [string]$State.Plan.support.switch_name -or
        [string]$createdSwitchRows[0].SwitchType -cne "Internal" -or
        $createdSwitchRows[0].AllowManagementOS -ne $true) {
        throw "new support switch did not return the preassigned exact identity"
    }
    $switchContext = Get-SupportSwitchContext -Plan $State.Plan -SwitchId $State.CreatedSwitchId `
        -TimeoutSeconds $State.ReadinessTimeoutSeconds
    Set-SupportHostAdapter -Plan $State.Plan -SwitchContext $switchContext

    $vm = (Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity).Vm
    $State.VmAdapterCreationAttempted = $true
    $adapterCreationFailure = $null
    $createdVmAdapterRows = @()
    try {
        $createdVmAdapterRows = @(Add-VMNetworkAdapter -VM $vm `
                -Name ([string]$State.Plan.support.vm_adapter_name) `
                -SwitchName ([string]$State.Plan.support.switch_name) `
                -StaticMacAddress ([string]$State.Plan.support.vm_mac_address) `
                -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers `
                -DeviceNaming On -Passthru -Confirm:$false -ErrorAction Stop)
    }
    catch {
        $adapterCreationFailure = $_
    }
    if ($createdVmAdapterRows.Count -eq 1 -and
        -not [string]::IsNullOrWhiteSpace([string]$createdVmAdapterRows[0].Id)) {
        $State.CreatedVmAdapterId = [string]$createdVmAdapterRows[0].Id
    }
    $adapterCandidates = @(Get-NewSupportVmAdapterCandidate -Plan $State.Plan `
            -SwitchId $State.CreatedSwitchId `
            -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers)
    if ($adapterCandidates.Count -eq 1) {
        $State.CreatedVmAdapterId = [string]$adapterCandidates[0].Id
    }
    if ($null -ne $adapterCreationFailure) {
        throw $adapterCreationFailure
    }
    if ($createdVmAdapterRows.Count -ne 1 -or $adapterCandidates.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($State.CreatedVmAdapterId) -or
        [string]$createdVmAdapterRows[0].Id -ine $State.CreatedVmAdapterId) {
        throw "new support VM adapter did not return one reconcilable exact identity"
    }
    $null = Get-ValidatedSupportVmAdapter -Plan $State.Plan `
        -SupportSwitchId $State.CreatedSwitchId -SupportAdapterId $State.CreatedVmAdapterId `
        -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers
}

function Initialize-ProvisioningGuest {
    param([Parameter(Mandatory)] [object]$State)
    Invoke-Ferrum2PinnedVmLifecycle -Identity $State.VmIdentity -Action Start `
        -TimeoutSeconds $State.ReadinessTimeoutSeconds | Out-Null
    $connection = Connect-Ferrum2PinnedVmGuest `
        -Identity $State.VmIdentity -Credential $State.Credential `
        -TimeoutSeconds $State.ReadinessTimeoutSeconds
    $State.Session = $connection.Session
    $State.ConfiguredGuestState = Invoke-GuestSupportNetwork `
        -Session $State.Session -Plan $State.Plan -Phase "initial_configure" -Configure
    Stop-Ferrum2PinnedVmGuest -Identity $State.VmIdentity `
        -Session $State.Session -TimeoutSeconds $State.ShutdownTimeoutSeconds | Out-Null
    $State.Session = $null
}

function Invoke-ProvisioningCheckpointCreation {
    param([Parameter(Mandatory)] [object]$State)

    $vm = (Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity).Vm
    $State.CheckpointCreationAttempted = $true
    $checkpointCreationFailure = $null
    $createdCheckpointRows = @()
    try {
        $createdCheckpointRows = @(Checkpoint-VM -VM $vm `
                -SnapshotName $State.CreatedCheckpointProvisioningName `
                -Passthru -Confirm:$false -ErrorAction Stop)
    }
    catch {
        $checkpointCreationFailure = $_
    }
    if ($createdCheckpointRows.Count -eq 1 -and
        [Guid]$createdCheckpointRows[0].Id -ne [Guid]::Empty) {
        $State.CreatedCheckpointId = [Guid]$createdCheckpointRows[0].Id
    }
    $checkpointDeadline = [DateTime]::UtcNow.AddSeconds($State.ReadinessTimeoutSeconds)
    do {
        $checkpointInventory = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
        $newCheckpointRows = @($checkpointInventory | Where-Object {
                $State.InitialCheckpointIds -cnotcontains $_.Id.ToString("D")
            })
        $initialCheckpointRows = @($checkpointInventory | Where-Object {
                $State.InitialCheckpointIds -ccontains $_.Id.ToString("D")
            })
        $checkpointCandidates = @($newCheckpointRows | Where-Object {
                [string]$_.Name -ceq $State.CreatedCheckpointProvisioningName -and
                [string]$_.SnapshotType -ceq "Standard" -and
                $_.IsAutomaticCheckpoint -eq $false -and
                $_.VMId -eq [Guid][string]$State.Plan.vm.id -and
                $null -ne $_.ParentCheckpointId -and
                $_.ParentCheckpointId -ne [Guid]::Empty -and
                [Guid]$_.ParentCheckpointId -eq [Guid][string]$State.Plan.source_checkpoint.id
            })
        if (($newCheckpointRows.Count -eq 1 -and
                $initialCheckpointRows.Count -eq $State.InitialCheckpointIds.Count -and
                $checkpointCandidates.Count -eq 1) -or
            $newCheckpointRows.Count -gt 1 -or $checkpointCandidates.Count -gt 1) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $checkpointDeadline)
    if ($checkpointCandidates.Count -eq 1) {
        $State.CreatedCheckpointId = [Guid]$checkpointCandidates[0].Id
    }
    if ($null -ne $checkpointCreationFailure) {
        throw $checkpointCreationFailure
    }
    $checkpointIdentityViolations = @(
        if ($createdCheckpointRows.Count -gt 1) {
            "passthru_count=$($createdCheckpointRows.Count)"
        }
        if ($newCheckpointRows.Count -ne 1) {
            "new_inventory_count=$($newCheckpointRows.Count)"
        }
        if ($initialCheckpointRows.Count -ne $State.InitialCheckpointIds.Count) {
            "initial_inventory_count=$($initialCheckpointRows.Count)"
        }
        if ($checkpointCandidates.Count -ne 1) {
            "candidate_count=$($checkpointCandidates.Count)"
        }
        if ($State.CreatedCheckpointId -eq [Guid]::Empty) {
            "empty_checkpoint_id"
        }
        if ($createdCheckpointRows.Count -eq 1 -and
            $createdCheckpointRows[0].Id -ne $State.CreatedCheckpointId) {
            "passthru_id_mismatch"
        }
    )
    if ($checkpointIdentityViolations.Count -ne 0 -or
        [string]$checkpointCandidates[0].Name -cne $State.CreatedCheckpointProvisioningName -or
        [string]$checkpointCandidates[0].SnapshotType -cne "Standard" -or
        $checkpointCandidates[0].IsAutomaticCheckpoint -ne $false) {
        throw "new lab checkpoint identity is invalid: " +
        ($checkpointIdentityViolations -join ",")
    }
}

function Rename-ProvisioningCheckpoint {
    param([Parameter(Mandatory)] [object]$State)

    $vm = (Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity).Vm
    $checkpointCandidates = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
            $_.Id -eq $State.CreatedCheckpointId -and
            [string]$_.Name -ceq $State.CreatedCheckpointProvisioningName
        })
    if ($checkpointCandidates.Count -ne 1) {
        throw 'created lab checkpoint is unavailable for rename'
    }
    $renamedCheckpointRows = @($checkpointCandidates[0] | Rename-VMSnapshot `
            -NewName ([string]$State.Plan.lab_checkpoint.name) -Passthru `
            -Confirm:$false -ErrorAction Stop)
    $renameDeadline = [DateTime]::UtcNow.AddSeconds($State.ReadinessTimeoutSeconds)
    do {
        $renamedCheckpoint = @(Get-VMSnapshot -VM $vm -ErrorAction Stop |
                Where-Object { $_.Id -eq $State.CreatedCheckpointId })
        if ($renamedCheckpoint.Count -eq 1 -and
            [string]$renamedCheckpoint[0].Name -ceq
            [string]$State.Plan.lab_checkpoint.name -and
            $renamedCheckpoint[0].VMId -eq [Guid][string]$State.Plan.vm.id -and
            [string]$renamedCheckpoint[0].SnapshotType -ceq "Standard" -and
            $renamedCheckpoint[0].IsAutomaticCheckpoint -eq $false -and
            $null -ne $renamedCheckpoint[0].ParentCheckpointId -and
            $renamedCheckpoint[0].ParentCheckpointId -ne [Guid]::Empty -and
            [Guid]$renamedCheckpoint[0].ParentCheckpointId -eq
            [Guid][string]$State.Plan.source_checkpoint.id) {
            break
        }
        if ($renamedCheckpoint.Count -gt 1) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $renameDeadline)
    $renameIdentityViolations = @(
        if ($renamedCheckpointRows.Count -gt 1) {
            "passthru_count=$($renamedCheckpointRows.Count)"
        }
        if ($renamedCheckpointRows.Count -eq 1 -and
            $renamedCheckpointRows[0].Id -ne $State.CreatedCheckpointId) {
            "passthru_id_mismatch"
        }
        if ($renamedCheckpoint.Count -ne 1) {
            "inventory_count=$($renamedCheckpoint.Count)"
        }
        if ($renamedCheckpoint.Count -eq 1) {
            if ($renamedCheckpoint[0].VMId -ne [Guid][string]$State.Plan.vm.id) {
                "vm_id"
            }
            if ([string]$renamedCheckpoint[0].Name -cne
                [string]$State.Plan.lab_checkpoint.name) {
                "name"
            }
            if ([string]$renamedCheckpoint[0].SnapshotType -cne "Standard") {
                "snapshot_type"
            }
            if ($renamedCheckpoint[0].IsAutomaticCheckpoint -ne $false) {
                "automatic_checkpoint"
            }
            if ($null -eq $renamedCheckpoint[0].ParentCheckpointId -or
                $renamedCheckpoint[0].ParentCheckpointId -eq [Guid]::Empty -or
                [Guid]$renamedCheckpoint[0].ParentCheckpointId -ne
                [Guid][string]$State.Plan.source_checkpoint.id) {
                "parent_checkpoint_id"
            }
        }
    )
    if ($renameIdentityViolations.Count -ne 0) {
        throw "lab checkpoint rename did not preserve the exact identity: " +
        ($renameIdentityViolations -join ",")
    }
}

function New-ProvisioningCheckpoint {
    param([Parameter(Mandatory)] [object]$State)

    Invoke-ProvisioningCheckpointCreation -State $State
    Rename-ProvisioningCheckpoint -State $State
}

function Test-ProvisioningCheckpointRestore {
    param([Parameter(Mandatory)] [object]$State)

    Invoke-Ferrum2PinnedVmLifecycle -Identity $State.VmIdentity -Action Restore `
        -CheckpointId $State.CreatedCheckpointId `
        -CheckpointName ([string]$State.Plan.lab_checkpoint.name) `
        -TimeoutSeconds $State.ShutdownTimeoutSeconds | Out-Null
    $null = Get-ValidatedSupportVmAdapter -Plan $State.Plan `
        -SupportSwitchId $State.CreatedSwitchId `
        -SupportAdapterId $State.CreatedVmAdapterId `
        -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers
    Invoke-Ferrum2PinnedVmLifecycle -Identity $State.VmIdentity -Action Start `
        -TimeoutSeconds $State.ReadinessTimeoutSeconds | Out-Null
    $connection = Connect-Ferrum2PinnedVmGuest -Identity $State.VmIdentity `
        -Credential $State.Credential -TimeoutSeconds $State.ReadinessTimeoutSeconds
    $State.Session = $connection.Session
    $State.VerifiedGuestState = Invoke-GuestSupportNetwork -Session $State.Session `
        -Plan $State.Plan -Phase 'post_checkpoint_restore'
    Assert-GuestIdentityUnchanged -Before $State.ConfiguredGuestState `
        -After $State.VerifiedGuestState
    $State.RunningHostState = Get-ValidatedSupportHostState -Plan $State.Plan `
        -SwitchId $State.CreatedSwitchId -TimeoutSeconds $State.ReadinessTimeoutSeconds
    Stop-Ferrum2PinnedVmGuest -Identity $State.VmIdentity -Session $State.Session `
        -TimeoutSeconds $State.ShutdownTimeoutSeconds | Out-Null
    $State.Session = $null
    Invoke-Ferrum2PinnedVmLifecycle -Identity $State.VmIdentity -Action Restore `
        -CheckpointId $State.CreatedCheckpointId `
        -CheckpointName ([string]$State.Plan.lab_checkpoint.name) `
        -TimeoutSeconds $State.ShutdownTimeoutSeconds | Out-Null
}

function Get-ProvisioningTerminalCheckpoint {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$Vm
    )

    $finalCheckpoints = @(Get-VMSnapshot -VM $Vm -ErrorAction Stop)
    $finalCheckpointIds = @($finalCheckpoints | ForEach-Object {
            $_.Id.ToString("D")
        } | Sort-Object)
    $expectedCheckpointIds = @(
        $State.InitialCheckpointIds
        $State.CreatedCheckpointId.ToString("D")
    ) | Sort-Object
    $finalLabCheckpointRows = @($finalCheckpoints | Where-Object {
            $_.Id -eq $State.CreatedCheckpointId
        })
    if (($finalCheckpointIds -join "|") -cne ($expectedCheckpointIds -join "|") -or
        $finalLabCheckpointRows.Count -ne 1 -or
        [string]$finalLabCheckpointRows[0].Name -cne [string]$State.Plan.lab_checkpoint.name -or
        [string]$finalLabCheckpointRows[0].SnapshotType -cne "Standard" -or
        $finalLabCheckpointRows[0].IsAutomaticCheckpoint -ne $false -or
        @($finalCheckpoints | Where-Object { $_.IsAutomaticCheckpoint -ne $false }).Count -ne 0) {
        throw "terminal checkpoint inventory is not the exact source-plus-lab set"
    }
    $checkpoint = $finalLabCheckpointRows[0]
    if ((ConvertTo-Ferrum2CanonicalGuid -Value $checkpoint.ParentCheckpointId `
                -Label "terminal lab checkpoint parent") -cne
        (ConvertTo-Ferrum2CanonicalGuid -Value $State.Plan.source_checkpoint.id `
            -Label "source checkpoint")) {
        throw "lab checkpoint is not a direct child of the pinned source checkpoint"
    }
    $checkpoint
}

function Get-ProvisioningTerminalSupportSnapshotAdapter {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$SupportVmAdapter
    )

    $supportSnapshotReferences = @(
        foreach ($snapshotVm in @(Get-VM -ErrorAction Stop)) {
            foreach ($snapshot in @(Get-VMSnapshot -VM $snapshotVm -ErrorAction Stop)) {
                foreach ($snapshotAdapter in @(Get-VMNetworkAdapter -VMSnapshot $snapshot `
                            -ErrorAction Stop | Where-Object {
                            $_.SwitchId -eq $State.CreatedSwitchId
                        })) {
                    [pscustomobject][ordered]@{
                        Snapshot = $snapshot
                        Adapter  = $snapshotAdapter
                    }
                }
            }
        }
    )
    if ($supportSnapshotReferences.Count -ne 1) {
        throw "support vSwitch snapshot attachment inventory is not unique"
    }
    $supportSnapshot = $supportSnapshotReferences[0].Snapshot
    $supportSnapshotAdapter = $supportSnapshotReferences[0].Adapter
    $expectedSupportIdentifiers = @(
        $State.CreatedVmAdapterVirtualSystemIdentifiers | ForEach-Object { $_.ToString("D") }
    )
    $snapshotSupportIdentifiers = @(
        $supportSnapshotAdapter.VirtualSystemIdentifiers | ForEach-Object {
            ConvertTo-Ferrum2CanonicalGuid -Value $_ `
                -Label "lab snapshot support adapter identifier"
        }
    )
    $liveSupportInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$SupportVmAdapter.Id) `
        -ExpectedOwnerId ([string]$State.Plan.vm.id) -Label "live support VM adapter"
    $snapshotSupportInstanceId = Get-Ferrum2VmAdapterInstanceGuid `
        -AdapterId ([string]$supportSnapshotAdapter.Id) `
        -ExpectedOwnerId $State.CreatedCheckpointId.ToString("D") `
        -Label "lab snapshot support VM adapter"
    if ($supportSnapshot.Id -ne $State.CreatedCheckpointId -or
        $supportSnapshotAdapter.VMId -ne [Guid][string]$State.Plan.vm.id -or
        $supportSnapshotAdapter.VMSnapshotId -ne $State.CreatedCheckpointId -or
        $supportSnapshotAdapter.VMCheckpointId -ne $State.CreatedCheckpointId -or
        [string]$supportSnapshotAdapter.Name -cne [string]$State.Plan.support.vm_adapter_name -or
        $supportSnapshotAdapter.SwitchId -ne $State.CreatedSwitchId -or
        [string]$supportSnapshotAdapter.SwitchName -cne [string]$State.Plan.support.switch_name -or
        $supportSnapshotAdapter.DynamicMacAddressEnabled -ne $false -or
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$supportSnapshotAdapter.MacAddress) `
            -Label "lab snapshot support VM adapter") -cne
        (ConvertTo-Ferrum2CanonicalMacAddress -Value ([string]$State.Plan.support.vm_mac_address) `
            -Label "planned support VM adapter") -or
        ($snapshotSupportIdentifiers -join "|") -cne ($expectedSupportIdentifiers -join "|") -or
        $snapshotSupportInstanceId -cne $liveSupportInstanceId) {
        throw "lab snapshot support VM adapter identity is invalid"
    }
    $supportSnapshotAdapter
}

function Get-ProvisioningTerminalTunIdentity {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$Vm,
        [Parameter(Mandatory)] [object]$HostState
    )

    $finalTun = Get-HostTunIdentity
    if ([string]$Vm.State -cne "Off" -or
        $Vm.AutomaticCheckpointsEnabled -ne $false -or
        $State.InitialTun.present -ne $true -or $finalTun.present -ne $true -or
        [string]$State.InitialTun.interface_guid -cne [string]$finalTun.interface_guid -or
        [int]$State.InitialTun.interface_index -ne [int]$finalTun.interface_index -or
        [string]$State.InitialTun.name -cne [string]$finalTun.name -or
        [string]$finalTun.status -cne "Up") {
        throw "terminal VM or protected host tun0 state is invalid"
    }
    foreach ($field in @(
            "switch_name", "switch_id", "switch_type", "management_os_adapter_id",
            "management_os_device_id", "host_interface_alias", "host_interface_guid",
            "host_interface_index", "host_mac_address", "host_ipv4", "prefix_length",
            "network", "mtu_bytes", "selected_source_ipv4", "selected_route_prefix",
            "selected_route_next_hop", "nat_enabled", "ics_enabled"
        )) {
        if ([string]$State.RunningHostState.$field -cne [string]$HostState.$field) {
            throw "support host identity changed before the terminal restore: field=$field"
        }
    }
    $finalTun
}

function New-ProvisioningManifestDocument {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [object]$Vm,
        [Parameter(Mandatory)] [object]$Checkpoint,
        [Parameter(Mandatory)] [object]$ManagementAdapter,
        [Parameter(Mandatory)] [object]$SupportVmAdapter,
        [Parameter(Mandatory)] [object]$SupportSnapshotAdapter,
        [Parameter(Mandatory)] [object]$HostState,
        [Parameter(Mandatory)] [object]$Tun
    )

    [pscustomobject][ordered]@{
        schema                              = 1
        created_utc                         = [DateTime]::UtcNow.ToString("o")
        topology_plan_sha256                = $State.PlanDocument.Sha256
        provisioning_source_manifest_sha256 =
        [string]$State.SourceIdentity.ManifestSha256
        provisioning_source_bundle_sha256   =
        [string]$State.SourceIdentity.SourceBundleSha256
        vm                                  = [pscustomobject][ordered]@{
            name                          = [string]$Vm.Name
            id                            = $Vm.Id.ToString("D")
            terminal_state                = [string]$Vm.State
            automatic_checkpoints_enabled = [bool]$Vm.AutomaticCheckpointsEnabled
        }
        source_checkpoint                   = [pscustomobject][ordered]@{
            name = [string]$State.Plan.source_checkpoint.name
            id   = (ConvertTo-Ferrum2CanonicalGuid -Value $State.Plan.source_checkpoint.id `
                    -Label "source checkpoint")
            type = [string]$State.Plan.source_checkpoint.type
        }
        lab_checkpoint                      = [pscustomobject][ordered]@{
            name                           = [string]$Checkpoint.Name
            id                             = $State.CreatedCheckpointId.ToString("D")
            type                           = [string]$Checkpoint.SnapshotType
            parent_id                      = (ConvertTo-Ferrum2CanonicalGuid `
                    -Value $Checkpoint.ParentCheckpointId `
                    -Label "lab checkpoint parent")
            support_vm_adapter_snapshot_id = [string]$SupportSnapshotAdapter.Id
            restore_verified               = $true
        }
        management_adapter                  = [pscustomobject][ordered]@{
            name                  = [string]$ManagementAdapter.Name
            id                    = [string]$ManagementAdapter.Id
            switch_name           = [string]$ManagementAdapter.SwitchName
            switch_id             = $ManagementAdapter.SwitchId.ToString("D")
            mac_address           = ConvertTo-Ferrum2CanonicalMacAddress `
                -Value ([string]$ManagementAdapter.MacAddress) -Label "management adapter"
            dynamic_mac_address   = [bool]$ManagementAdapter.DynamicMacAddressEnabled
            guest_interface_alias = [string]$State.VerifiedGuestState.management_interface_alias
            guest_interface_guid  = [string]$State.VerifiedGuestState.management_interface_guid
        }
        support                             = [pscustomobject][ordered]@{
            switch     = $HostState
            vm_adapter = [pscustomobject][ordered]@{
                name                       = [string]$SupportVmAdapter.Name
                id                         = [string]$SupportVmAdapter.Id
                switch_id                  = $SupportVmAdapter.SwitchId.ToString("D")
                mac_address                = ConvertTo-Ferrum2CanonicalMacAddress `
                    -Value ([string]$SupportVmAdapter.MacAddress) -Label "support VM adapter"
                dynamic_mac_address        = [bool]$SupportVmAdapter.DynamicMacAddressEnabled
                virtual_system_identifiers = @(
                    $SupportVmAdapter.VirtualSystemIdentifiers | ForEach-Object {
                        ConvertTo-Ferrum2CanonicalGuid -Value $_ `
                            -Label "support VM adapter identifier"
                    }
                )
            }
            guest      = $State.VerifiedGuestState
        }
        protected_host_tun                  = $Tun
        constraints                         = [pscustomobject][ordered]@{
            nat                     = "absent"
            ics                     = "absent"
            gateway                 = "absent"
            dns                     = "absent_on_support_interfaces"
            firewall_mutation       = "none"
            default_switch_mutation = "none"
            host_tun_mutation       = "none"
        }
    }
}

function New-ProvisioningTerminalEvidence {
    param([Parameter(Mandatory)] [object]$State)

    $supportVmAdapter = Get-ValidatedSupportVmAdapter -Plan $State.Plan `
        -SupportSwitchId $State.CreatedSwitchId -SupportAdapterId $State.CreatedVmAdapterId `
        -VirtualSystemIdentifiers $State.CreatedVmAdapterVirtualSystemIdentifiers
    $hostState = Get-ValidatedSupportHostState -Plan $State.Plan -SwitchId $State.CreatedSwitchId `
        -TimeoutSeconds $State.ReadinessTimeoutSeconds
    $finalVm = (Get-Ferrum2PinnedVmContext -Identity $State.VmIdentity).Vm
    $managementAdapter = Get-ManagementAdapter -Vm $finalVm -Plan $State.Plan
    $checkpoint = Get-ProvisioningTerminalCheckpoint -State $State -Vm $finalVm
    $supportSnapshotAdapter = Get-ProvisioningTerminalSupportSnapshotAdapter `
        -State $State -SupportVmAdapter $supportVmAdapter
    $finalTun = Get-ProvisioningTerminalTunIdentity -State $State -Vm $finalVm `
        -HostState $hostState
    $manifest = New-ProvisioningManifestDocument -State $State -Vm $finalVm `
        -Checkpoint $checkpoint -ManagementAdapter $managementAdapter `
        -SupportVmAdapter $supportVmAdapter `
        -SupportSnapshotAdapter $supportSnapshotAdapter -HostState $hostState `
        -Tun $finalTun
    $terminalPlanDocument = Read-TopologyPlan -Path $State.PlanDocument.Path
    if ($terminalPlanDocument.Sha256 -cne $State.PlanDocument.Sha256) {
        throw "topology plan changed during the topology transaction"
    }
    Assert-ProvisioningSourceIdentity
    $State.ManifestPayload = New-CanonicalJsonPayload -Value $manifest
    $State.SuccessJson = [pscustomobject][ordered]@{
        schema            = 1
        status            = "provisioned"
        manifest_path     = $State.ManifestPath
        manifest_sha256   = [string]$State.ManifestPayload.Sha256
        lab_checkpoint_id = $State.CreatedCheckpointId.ToString("D")
        support_switch_id = $State.CreatedSwitchId.ToString("D")
        vm_state          = [string]$finalVm.State
    } | ConvertTo-Json -Depth 4
}

function Commit-ProvisioningManifest {
    param([Parameter(Mandatory)] [object]$State)
    Assert-ProvisioningSourceIdentity
    $State.ManifestWriteAttempted = $true
    Write-NewCanonicalJson -Path $State.ManifestPath -Payload $State.ManifestPayload
    $State.ManifestCommitted = $true
    try {
        Write-Output $State.SuccessJson
    }
    catch {
        $null = $_
    }
}

function Complete-ProvisioningTransaction {
    param([Parameter(Mandatory)] [object]$State)
    if ($null -ne $State.Session) {
        Remove-PSSession -Session $State.Session -ErrorAction SilentlyContinue
        $State.Session = $null
    }
    $manifestReconciliationFailure = $null
    $manifestCommitAmbiguous = $false
    $manifestCommitRecovered = $false
    if (-not $State.ManifestCommitted -and $State.ManifestWriteAttempted -and
        $null -ne $State.ManifestPayload) {
        try {
            [byte[]]$committedBytes = [IO.File]::ReadAllBytes($State.ManifestPath)
            $committedHash = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($committedBytes)
            ).ToLowerInvariant()
            $bytesMatch = $committedBytes.Length -eq ([byte[]]$State.ManifestPayload.Bytes).Length -and
            [Convert]::ToBase64String($committedBytes) -ceq
            [Convert]::ToBase64String([byte[]]$State.ManifestPayload.Bytes)
            if ($bytesMatch -and $committedHash -ceq [string]$State.ManifestPayload.Sha256) {
                $State.ManifestCommitted = $true
                $manifestCommitRecovered = $true
                $State.Failure = $null
            }
            else {
                $manifestReconciliationFailure =
                "topology manifest appeared with bytes that do not match this transaction"
            }
        }
        catch [IO.FileNotFoundException] {
            $null = $_
        }
        catch [IO.DirectoryNotFoundException] {
            $null = $_
        }
        catch {
            $manifestCommitAmbiguous = $true
            $State.Failure = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    "topology manifest commit is unreadable or ambiguous; " +
                    "the verified topology was left intact for manual recovery: " +
                    $_.Exception.Message
                ),
                "Ferrum2SupportTopologyManifestCommitAmbiguous",
                [Management.Automation.ErrorCategory]::ReadError,
                $State.ManifestPath
            )
        }
    }
    if ($State.ManifestCommitted) {
        $State.Failure = $null
    }
    if ($manifestCommitRecovered -and
        -not [string]::IsNullOrWhiteSpace([string]$State.SuccessJson)) {
        try {
            Write-Output $State.SuccessJson
        }
        catch {
            $null = $_
        }
    }
    if ($State.MutationStarted -and -not $State.ManifestCommitted -and
        -not $manifestCommitAmbiguous) {
        $rollbackFailures = @($manifestReconciliationFailure | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })
        try {
            $rollbackFailures += @(Invoke-TopologyRollback -Plan $State.Plan `
                    -CreatedSwitchId $State.CreatedSwitchId `
                    -CreatedVmAdapterId $State.CreatedVmAdapterId `
                    -CreatedVmAdapterVirtualSystemIdentifiers `
                    $State.CreatedVmAdapterVirtualSystemIdentifiers `
                    -VmAdapterCreationAttempted $State.VmAdapterCreationAttempted `
                    -CreatedCheckpointId $State.CreatedCheckpointId `
                    -CreatedCheckpointProvisioningName $State.CreatedCheckpointProvisioningName `
                    -CheckpointCreationAttempted $State.CheckpointCreationAttempted `
                    -InitialCheckpointIds $State.InitialCheckpointIds `
                    -InitialTun $State.InitialTun `
                    -TimeoutSeconds $State.ShutdownTimeoutSeconds)
        }
        catch {
            $rollbackFailures += @("rollback dispatcher: $($_.Exception.Message)")
        }
        if ($rollbackFailures.Count -ne 0) {
            $failureMessage = if ($null -ne $State.Failure) {
                [string]$State.Failure.Exception.Message
            }
            else {
                "topology transaction stopped before commit"
            }
            $State.Failure = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    "$failureMessage; rollback failures: " +
                    ($rollbackFailures -join ' | ')
                ),
                "Ferrum2SupportTopologyRollbackFailed",
                [Management.Automation.ErrorCategory]::InvalidResult,
                $null
            )
        }
    }
    if ($State.MutexOwned) {
        try {
            $State.Mutex.ReleaseMutex()
        }
        catch {
            $null = $_
        }
    }
    try {
        $State.Mutex.Dispose()
    }
    catch {
        $null = $_
    }
}
