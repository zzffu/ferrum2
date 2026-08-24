#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Creates the explicitly authorized isolated Hyper-V support topology for Windows TUN qualification.

.DESCRIPTION
This is a one-time, fail-closed transaction. It requires -Apply, a fixed authorization token, and
an absent manifest path outside the repository. It restores the pinned source checkpoint, creates
one Internal vSwitch and one static-MAC VM NIC, configures only the two new support interfaces,
creates and verifies a new Standard checkpoint, writes generated identities to the manifest, and
leaves the VM Off. On failure it audits ownership before restoring the source checkpoint and
removes only resources whose preassigned ID or random transaction marker proves they belong to
this invocation; ambiguous concurrent state is left intact for explicit recovery.

The script does not configure NAT, ICS, firewall policy, the Default Switch, a physical adapter,
or host tun0. Use -WhatIf to execute the complete read-only preflight without loading a credential
or changing state.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidUsingPlainTextForPassword",
    "",
    Justification = "CredentialPath names a DPAPI-protected PSCredential file; no password is accepted."
)]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [Parameter(Mandatory = $true)]
    [switch]$Apply,

    [Parameter(Mandatory = $true)]
    [ValidateSet("CREATE-FERRUM2-INTERNAL-SUPPORT-V1")]
    [string]$AuthorizationToken,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$CredentialPath,

    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$driverFilePath = $PSCommandPath
$provisioningLibraryPath = Join-Path $PSScriptRoot `
    "windows_tun_hyperv_support_topology_provisioning.ps1"
$inspectorFilePath = Join-Path $PSScriptRoot `
    "inspect_windows_tun_hyperv_support_topology.ps1"

function Get-ExactFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Assert-ProvisioningSourceHash {
    param(
        [Parameter(Mandatory = $true)][string]$InspectorSha256,
        [Parameter(Mandatory = $true)][string]$LibrarySha256,
        [Parameter(Mandatory = $true)][string]$DriverSha256
    )

    if ((Get-ExactFileSha256 -Path $script:inspectorFilePath) -cne $InspectorSha256 -or
        (Get-ExactFileSha256 -Path $script:provisioningLibraryPath) -cne $LibrarySha256 -or
        (Get-ExactFileSha256 -Path $script:driverFilePath) -cne $DriverSha256) {
        throw "provisioning source changed during the topology transaction"
    }
}

$initialInspectorSha256 = Get-ExactFileSha256 -Path $inspectorFilePath
$initialLibrarySha256 = Get-ExactFileSha256 -Path $provisioningLibraryPath
$initialDriverSha256 = Get-ExactFileSha256 -Path $driverFilePath
. $provisioningLibraryPath -LibraryOnly
Assert-ProvisioningSourceHash -InspectorSha256 $initialInspectorSha256 `
    -LibrarySha256 $initialLibrarySha256 -DriverSha256 $initialDriverSha256

function Get-NewSupportVmAdapterCandidate {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][Guid[]]$VirtualSystemIdentifiers
    )

    $vm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
    $expectedMac = ConvertTo-CanonicalMacAddress `
        -Value ([string]$Plan.support.vm_mac_address) -Label "planned support VM adapter"
    $expectedIdentifiers = @($VirtualSystemIdentifiers | ForEach-Object { $_.ToString("D") })
    return @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
        $actualIdentifiers = @($_.VirtualSystemIdentifiers | ForEach-Object {
            ConvertTo-CanonicalGuid -Value $_ -Label "candidate support VM adapter identifier"
        })
        [string]$_.Name -ceq [string]$Plan.support.vm_adapter_name -and
        $_.SwitchId -eq $SwitchId -and $_.DynamicMacAddressEnabled -eq $false -and
        ($actualIdentifiers -join "|") -ceq ($expectedIdentifiers -join "|") -and
        (ConvertTo-CanonicalMacAddress -Value ([string]$_.MacAddress) `
            -Label "candidate support VM adapter") -ceq $expectedMac
    })
}

function Get-NewQualificationCheckpointCandidate {
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

function Invoke-TopologyRollback {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$CreatedSwitchId,
        [AllowNull()][string]$CreatedVmAdapterId,
        [Parameter(Mandatory = $true)][Guid[]]$CreatedVmAdapterVirtualSystemIdentifiers,
        [Parameter(Mandatory = $true)][bool]$VmAdapterCreationAttempted,
        [Parameter(Mandatory = $true)][Guid]$CreatedCheckpointId,
        [Parameter(Mandatory = $true)][string]$CreatedCheckpointProvisioningName,
        [Parameter(Mandatory = $true)][bool]$CheckpointCreationAttempted,
        [Parameter(Mandatory = $true)][string[]]$InitialCheckpointIds,
        [Parameter(Mandatory = $true)][object]$InitialTun,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $failures = [Collections.Generic.List[string]]::new()
    $vmIsOffForRollback = $false
    $vmInventoryOwnedForRollback = $false
    $sourceRestoreConverged = $false
    try {
        Stop-ExactVmHard -Plan $Plan -TimeoutSeconds $TimeoutSeconds
        $vmIsOffForRollback = $true
    } catch {
        $failures.Add("VM Off: $($_.Exception.Message)")
    }
    if ($vmIsOffForRollback) {
        try {
            $rollbackVm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
            $null = Get-ManagementAdapter -Vm $rollbackVm -Plan $Plan
            $allAdapters = @(Get-VMNetworkAdapter -VM $rollbackVm -ErrorAction Stop)
            $ownedAdapterIds = @()
            if ($VmAdapterCreationAttempted -and $CreatedSwitchId -ne [Guid]::Empty) {
                $ownedAdapterRows = @(Get-NewSupportVmAdapterCandidate -Plan $Plan `
                    -SwitchId $CreatedSwitchId `
                    -VirtualSystemIdentifiers $CreatedVmAdapterVirtualSystemIdentifiers)
                if ($ownedAdapterRows.Count -gt 1 -or
                    ($ownedAdapterRows.Count -eq 1 -and
                        -not [string]::IsNullOrWhiteSpace($CreatedVmAdapterId) -and
                        [string]$ownedAdapterRows[0].Id -ine $CreatedVmAdapterId)) {
                    throw "support VM adapter ownership is ambiguous before rollback"
                }
                $ownedAdapterIds = @($ownedAdapterRows | ForEach-Object { [string]$_.Id })
            }
            $unexpectedAdapters = @($allAdapters | Where-Object {
                [string]$_.Id -ine [string]$Plan.management_adapter.id -and
                $ownedAdapterIds -inotcontains [string]$_.Id
            })
            if ($unexpectedAdapters.Count -ne 0) {
                throw "approved VM gained an adapter not owned by this transaction"
            }

            $allCheckpoints = @(Get-VMSnapshot -VM $rollbackVm -ErrorAction Stop)
            $ownedCheckpointIds = @()
            if ($CheckpointCreationAttempted) {
                if ($CreatedCheckpointId -ne [Guid]::Empty) {
                    $ownedCheckpointRows = @($allCheckpoints | Where-Object {
                        $_.Id -eq $CreatedCheckpointId -and
                        $InitialCheckpointIds -cnotcontains $_.Id.ToString("D") -and
                        ([string]$_.Name -ceq $CreatedCheckpointProvisioningName -or
                            [string]$_.Name -ceq
                                [string]$Plan.qualification_checkpoint.name) -and
                        [string]$_.SnapshotType -ceq "Standard" -and
                        $_.IsAutomaticCheckpoint -eq $false
                    })
                } else {
                    $ownedCheckpointRows = @(Get-NewQualificationCheckpointCandidate `
                        -Plan $Plan -InitialCheckpointIds $InitialCheckpointIds `
                        -ProvisioningName $CreatedCheckpointProvisioningName)
                }
                if ($ownedCheckpointRows.Count -gt 1) {
                    throw "qualification checkpoint ownership is ambiguous before rollback"
                }
                $ownedCheckpointIds = @($ownedCheckpointRows | ForEach-Object {
                    $_.Id.ToString("D")
                })
            }
            $unexpectedCheckpoints = @($allCheckpoints | Where-Object {
                $InitialCheckpointIds -cnotcontains $_.Id.ToString("D") -and
                $ownedCheckpointIds -cnotcontains $_.Id.ToString("D")
            })
            if ($unexpectedCheckpoints.Count -ne 0) {
                throw "approved VM gained a checkpoint not owned by this transaction"
            }
            $vmInventoryOwnedForRollback = $true
        } catch {
            $failures.Add("rollback ownership audit: $($_.Exception.Message)")
        }
    }
    if ($vmIsOffForRollback -and $vmInventoryOwnedForRollback) {
        try {
            Restore-ExactCheckpoint -Plan $Plan `
                -CheckpointId ([Guid][string]$Plan.source_checkpoint.id) `
                -CheckpointName ([string]$Plan.source_checkpoint.name)
            $restoreDeadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $restoredVm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
                $restoredAdapters = @(Get-VMNetworkAdapter -VM $restoredVm -ErrorAction Stop)
                $restoredManagement = @($restoredAdapters | Where-Object {
                    [string]$_.Id -ieq [string]$Plan.management_adapter.id
                })
                if ($restoredAdapters.Count -eq 1 -and $restoredManagement.Count -eq 1) {
                    $sourceRestoreConverged = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $restoreDeadline)
            if (-not $sourceRestoreConverged) {
                throw "source checkpoint restore did not converge to its single-adapter inventory"
            }
        } catch {
            $failures.Add("source checkpoint restore: $($_.Exception.Message)")
        }
    }

    if ($CheckpointCreationAttempted -and $vmIsOffForRollback -and
        $vmInventoryOwnedForRollback) {
        try {
            $rollbackVm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
            $rows = @()
            if ($CreatedCheckpointId -ne [Guid]::Empty) {
                $rows = @(Get-VMSnapshot -VM $rollbackVm -ErrorAction Stop | Where-Object {
                    $_.Id -eq $CreatedCheckpointId
                })
            } else {
                $rows = @(Get-NewQualificationCheckpointCandidate -Plan $Plan `
                    -InitialCheckpointIds $InitialCheckpointIds `
                    -ProvisioningName $CreatedCheckpointProvisioningName)
            }
            if ($rows.Count -eq 1) {
                if ($InitialCheckpointIds -ccontains $rows[0].Id.ToString("D") -or
                    $rows[0].VMId -ne [Guid][string]$Plan.vm.id -or
                    ([string]$rows[0].Name -cne $CreatedCheckpointProvisioningName -and
                        [string]$rows[0].Name -cne
                            [string]$Plan.qualification_checkpoint.name) -or
                    [string]$rows[0].SnapshotType -cne "Standard" -or
                    $rows[0].IsAutomaticCheckpoint -ne $false) {
                    throw "created checkpoint no longer matches the recorded identity"
                }
                $rows[0] | Remove-VMSnapshot -Confirm:$false -ErrorAction Stop | Out-Null
                $remaining = @(Get-VMSnapshot -VM $rollbackVm -ErrorAction Stop | Where-Object {
                    $_.Id -eq $rows[0].Id
                })
                if ($remaining.Count -ne 0) {
                    throw "created checkpoint remained after removal"
                }
            } elseif ($rows.Count -ne 0) {
                throw "created checkpoint identity is ambiguous"
            }
        } catch {
            $failures.Add("new checkpoint removal: $($_.Exception.Message)")
        }
    }

    if ($VmAdapterCreationAttempted -and -not $sourceRestoreConverged -and
        $vmIsOffForRollback -and $vmInventoryOwnedForRollback) {
        try {
            $vm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
            $rows = @()
            if (-not [string]::IsNullOrWhiteSpace($CreatedVmAdapterId)) {
                $rows = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
                    [string]$_.Id -ieq $CreatedVmAdapterId
                })
            } elseif ($CreatedSwitchId -ne [Guid]::Empty) {
                $rows = @(Get-NewSupportVmAdapterCandidate -Plan $Plan `
                    -SwitchId $CreatedSwitchId `
                    -VirtualSystemIdentifiers $CreatedVmAdapterVirtualSystemIdentifiers)
            }
            if ($rows.Count -eq 1) {
                $expectedMac = ConvertTo-CanonicalMacAddress `
                    -Value ([string]$Plan.support.vm_mac_address) `
                    -Label "planned support VM adapter"
                $actualMac = ConvertTo-CanonicalMacAddress `
                    -Value ([string]$rows[0].MacAddress) `
                    -Label "rollback support VM adapter"
                $expectedIdentifiers = @(
                    $CreatedVmAdapterVirtualSystemIdentifiers | ForEach-Object {
                        $_.ToString("D")
                    }
                )
                $actualIdentifiers = @($rows[0].VirtualSystemIdentifiers | ForEach-Object {
                    ConvertTo-CanonicalGuid -Value $_ `
                        -Label "rollback support VM adapter identifier"
                })
                if ($actualMac -cne $expectedMac -or
                    ($actualIdentifiers -join "|") -cne ($expectedIdentifiers -join "|") -or
                    [string]$rows[0].Name -cne [string]$Plan.support.vm_adapter_name -or
                    $rows[0].SwitchId -ne $CreatedSwitchId -or
                    $rows[0].DynamicMacAddressEnabled -ne $false -or
                    $rows[0].VMId -ne [Guid][string]$Plan.vm.id) {
                    throw "created VM adapter no longer matches the recorded identity"
                }
                $rows[0] | Remove-VMNetworkAdapter -Confirm:$false -ErrorAction Stop | Out-Null
                $remaining = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
                    [string]$_.Id -ieq [string]$rows[0].Id
                })
                if ($remaining.Count -ne 0) {
                    throw "created VM adapter remained after removal"
                }
            } elseif ($rows.Count -ne 0) {
                throw "created VM adapter identity is ambiguous"
            }
        } catch {
            $failures.Add("support VM adapter removal: $($_.Exception.Message)")
        }
    }

    if ($CreatedSwitchId -ne [Guid]::Empty -and $vmIsOffForRollback -and
        $vmInventoryOwnedForRollback) {
        try {
            $rows = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
                $_.Id -eq $CreatedSwitchId
            })
            if ($rows.Count -eq 1) {
                if ([string]$rows[0].Name -cne [string]$Plan.support.switch_name -or
                    [string]$rows[0].SwitchType -cne "Internal" -or
                    $rows[0].AllowManagementOS -ne $true) {
                    throw "created vSwitch ID no longer matches the recorded identity"
                }
                $switchContext = Get-SupportSwitchContext -Plan $Plan `
                    -SwitchId $CreatedSwitchId -TimeoutSeconds 5
                $foreignVmAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop |
                    Where-Object {
                        $_.SwitchId -eq $CreatedSwitchId -and $_.IsManagementOs -ne $true
                    })
                if ($foreignVmAttachments.Count -ne 0) {
                    throw "created vSwitch still has VM attachments"
                }
                $snapshotAttachments = @(
                    foreach ($snapshotVm in @(Get-VM -ErrorAction Stop)) {
                        foreach ($snapshot in @(Get-VMSnapshot -VM $snapshotVm `
                                -ErrorAction Stop)) {
                            Get-VMNetworkAdapter -VMSnapshot $snapshot -ErrorAction Stop |
                                Where-Object { $_.SwitchId -eq $CreatedSwitchId }
                        }
                    }
                )
                if ($snapshotAttachments.Count -ne 0) {
                    throw "created vSwitch still has checkpoint VM adapter references"
                }
                $managementAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop |
                    Where-Object {
                        $_.SwitchId -eq $CreatedSwitchId -and $_.IsManagementOs -eq $true
                    })
                if ($managementAttachments.Count -ne 1 -or
                    [string]$managementAttachments[0].Id -ine
                        [string]$switchContext.ManagementAdapter.Id) {
                    throw "created vSwitch management OS attachment identity changed"
                }
                Assert-NoSupportNat -Plan $Plan
                Assert-IcsDisabledForHostAdapter `
                    -InterfaceGuid ([Guid]$switchContext.HostAdapter.InterfaceGuid)
                foreach ($store in @("ActiveStore", "PersistentStore")) {
                    $addressRows = if ($store -ceq "ActiveStore") {
                        @(Get-ActiveIpv4AddressRow `
                            -InterfaceIndex ([int]$switchContext.HostAdapter.ifIndex))
                    } else {
                        @(Get-ProvisioningPersistentIpv4AddressRow `
                            -InterfaceIndex ([int]$switchContext.HostAdapter.ifIndex))
                    }
                    $unexpectedAddresses = @($addressRows | Where-Object {
                        [string]$_.IPAddress -cne [string]$Plan.support.host_ipv4 -or
                        [int]$_.PrefixLength -ne [int]$Plan.support.prefix_length
                    })
                    if ($unexpectedAddresses.Count -ne 0 -or $addressRows.Count -gt 1) {
                        throw "created vSwitch host IPv4 identity changed in $store"
                    }
                    foreach ($address in $addressRows) {
                        $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                    }
                }
                $rows[0] | Remove-VMSwitch -Confirm:$false -ErrorAction Stop | Out-Null
                $remaining = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
                    $_.Id -eq $CreatedSwitchId
                })
                if ($remaining.Count -ne 0) {
                    throw "created vSwitch remained after removal"
                }
            } elseif ($rows.Count -ne 0) {
                throw "created vSwitch ID is not unique"
            }
        } catch {
            $failures.Add("support vSwitch removal: $($_.Exception.Message)")
        }
    }

    try {
        $finalContext = Get-ApprovedVmContext -Plan $Plan
        $finalPreflight = Get-ReadOnlyPreflight -Context $finalContext -Plan $Plan
        if ([string]$finalPreflight.host_tun.interface_guid -cne
                [string]$InitialTun.interface_guid -or
            [int]$finalPreflight.host_tun.interface_index -ne
                [int]$InitialTun.interface_index -or
            [string]$finalPreflight.host_tun.name -cne [string]$InitialTun.name -or
            [string]$finalPreflight.host_tun.status -cne "Up") {
            throw "protected host tun0 identity changed during rollback"
        }
    } catch {
        $failures.Add("final source-state validation: $($_.Exception.Message)")
    }
    return @($failures)
}

if (-not $Apply -or $AuthorizationToken -cne "CREATE-FERRUM2-INTERNAL-SUPPORT-V1") {
    throw "the explicit topology authorization contract is invalid"
}

$planDocument = Read-TopologyPlan
$plan = $planDocument.Value
$initialContext = Get-ApprovedVmContext -Plan $plan
$initialPreflight = Get-ReadOnlyPreflight -Context $initialContext -Plan $plan
$resolvedManifestPath = Resolve-NewExternalFile -Path $ManifestPath `
    -Label "topology identity manifest"
$target = "VM $($plan.vm.id) isolated support topology"
if (-not $PSCmdlet.ShouldProcess($target, "create, configure, checkpoint, and verify")) {
    [pscustomobject][ordered]@{
        schema = 1
        status = "not_applied"
        topology_plan_sha256 = $planDocument.Sha256
        preflight = $initialPreflight
        manifest_path = $resolvedManifestPath
        terminal_vm_state = "Off"
    } | ConvertTo-Json -Depth 8
    return
}

$mutex = [Threading.Mutex]::new($false, "Global\Ferrum2WindowsTunSupportTopologyV1")
$mutexOwned = $false
$session = $null
$createdSwitchId = [Guid]::Empty
$createdVmAdapterId = $null
$createdVmAdapterVirtualSystemIdentifiers = @([Guid]::NewGuid(), [Guid]::NewGuid())
$createdCheckpointId = [Guid]::Empty
$createdCheckpointProvisioningName =
    "$([string]$plan.qualification_checkpoint.name).provisioning-$([Guid]::NewGuid().ToString('N'))"
$vmAdapterCreationAttempted = $false
$checkpointCreationAttempted = $false
$initialCheckpointIds = @()
$mutationStarted = $false
$manifestCommitted = $false
$manifestWriteAttempted = $false
$manifestPayload = $null
$successJson = $null
$primaryFailure = $null

try {
    try {
        $mutexOwned = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $mutexOwned = $true
        throw "a prior support-topology transaction abandoned its mutex; retry after read-only audit"
    }
    if (-not $mutexOwned) {
        throw "another Ferrum2 support-topology transaction is active"
    }
    $credential = Import-ApprovedGuestCredential -Path $CredentialPath
    $freshPlanDocument = Read-TopologyPlan
    if ($freshPlanDocument.Sha256 -cne $planDocument.Sha256) {
        throw "topology plan changed after the initial preflight"
    }
    $freshContext = Get-ApprovedVmContext -Plan $plan
    $freshPreflight = Get-ReadOnlyPreflight -Context $freshContext -Plan $plan
    Assert-ProvisioningSourceHash -InspectorSha256 $initialInspectorSha256 `
        -LibrarySha256 $initialLibrarySha256 -DriverSha256 $initialDriverSha256
    $initialTun = $freshPreflight.host_tun
    $initialCheckpointIds = @(
        Get-VMSnapshot -VM $freshContext.Vm -ErrorAction Stop |
            ForEach-Object { $_.Id.ToString("D") } |
            Sort-Object
    )

    $mutationStarted = $true
    Restore-ExactCheckpoint -Plan $plan `
        -CheckpointId ([Guid][string]$plan.source_checkpoint.id) `
        -CheckpointName ([string]$plan.source_checkpoint.name)
    $restoredContext = Get-ApprovedVmContext -Plan $plan
    $null = Get-ReadOnlyPreflight -Context $restoredContext -Plan $plan

    $createdSwitchId = [Guid]::NewGuid()
    $createdSwitchRows = @(New-VMSwitch -Name ([string]$plan.support.switch_name) `
        -SwitchType Internal -Id $createdSwitchId.ToString("D") -Confirm:$false `
        -ErrorAction Stop)
    if ($createdSwitchRows.Count -ne 1 -or
        $createdSwitchRows[0].Id -ne $createdSwitchId -or
        [string]$createdSwitchRows[0].Name -cne [string]$plan.support.switch_name -or
        [string]$createdSwitchRows[0].SwitchType -cne "Internal" -or
        $createdSwitchRows[0].AllowManagementOS -ne $true) {
        throw "new support switch did not return the preassigned exact identity"
    }
    $switchContext = Get-SupportSwitchContext -Plan $plan -SwitchId $createdSwitchId `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    Set-SupportHostAdapter -Plan $plan -SwitchContext $switchContext

    $vm = (Get-ApprovedVmContext -Plan $plan).Vm
    $vmAdapterCreationAttempted = $true
    $adapterCreationFailure = $null
    $createdVmAdapterRows = @()
    try {
        $createdVmAdapterRows = @(Add-VMNetworkAdapter -VM $vm `
            -Name ([string]$plan.support.vm_adapter_name) `
            -SwitchName ([string]$plan.support.switch_name) `
            -StaticMacAddress ([string]$plan.support.vm_mac_address) `
            -VirtualSystemIdentifiers $createdVmAdapterVirtualSystemIdentifiers `
            -DeviceNaming On -Passthru -Confirm:$false -ErrorAction Stop)
    } catch {
        $adapterCreationFailure = $_
    }
    if ($createdVmAdapterRows.Count -eq 1 -and
        -not [string]::IsNullOrWhiteSpace([string]$createdVmAdapterRows[0].Id)) {
        $createdVmAdapterId = [string]$createdVmAdapterRows[0].Id
    }
    $adapterCandidates = @(Get-NewSupportVmAdapterCandidate -Plan $plan `
        -SwitchId $createdSwitchId `
        -VirtualSystemIdentifiers $createdVmAdapterVirtualSystemIdentifiers)
    if ($adapterCandidates.Count -eq 1) {
        $createdVmAdapterId = [string]$adapterCandidates[0].Id
    }
    if ($null -ne $adapterCreationFailure) {
        throw $adapterCreationFailure
    }
    if ($createdVmAdapterRows.Count -ne 1 -or $adapterCandidates.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($createdVmAdapterId) -or
        [string]$createdVmAdapterRows[0].Id -ine $createdVmAdapterId) {
        throw "new support VM adapter did not return one reconcilable exact identity"
    }
    $null = Get-ValidatedSupportVmAdapter -Plan $plan `
        -SupportSwitchId $createdSwitchId -SupportAdapterId $createdVmAdapterId `
        -VirtualSystemIdentifiers $createdVmAdapterVirtualSystemIdentifiers

    Start-ExactVm -Plan $plan
    $connection = Connect-ApprovedGuest -Plan $plan -Credential $credential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    $session = $connection.Session
    $configuredGuestState = Invoke-GuestSupportNetwork `
        -Session $session -Plan $plan -Configure
    Stop-GuestCleanly -Plan $plan -Session $session -TimeoutSeconds $ShutdownTimeoutSeconds
    $session = $null

    $vm = (Get-ApprovedVmContext -Plan $plan).Vm
    $checkpointCreationAttempted = $true
    $checkpointCreationFailure = $null
    $createdCheckpointRows = @()
    try {
        $createdCheckpointRows = @(Checkpoint-VM -VM $vm `
            -SnapshotName $createdCheckpointProvisioningName `
            -Passthru -Confirm:$false -ErrorAction Stop)
    } catch {
        $checkpointCreationFailure = $_
    }
    if ($createdCheckpointRows.Count -eq 1 -and
        [Guid]$createdCheckpointRows[0].Id -ne [Guid]::Empty) {
        $createdCheckpointId = [Guid]$createdCheckpointRows[0].Id
    }
    $checkpointCandidates = @(Get-NewQualificationCheckpointCandidate -Plan $plan `
        -InitialCheckpointIds $initialCheckpointIds `
        -ProvisioningName $createdCheckpointProvisioningName)
    if ($checkpointCandidates.Count -eq 1) {
        $createdCheckpointId = [Guid]$checkpointCandidates[0].Id
    }
    if ($null -ne $checkpointCreationFailure) {
        throw $checkpointCreationFailure
    }
    if ($createdCheckpointRows.Count -ne 1 -or $checkpointCandidates.Count -ne 1 -or
        $createdCheckpointId -eq [Guid]::Empty -or
        $createdCheckpointRows[0].Id -ne $createdCheckpointId -or
        [string]$checkpointCandidates[0].Name -cne $createdCheckpointProvisioningName -or
        [string]$checkpointCandidates[0].SnapshotType -cne "Standard" -or
        $checkpointCandidates[0].IsAutomaticCheckpoint -ne $false) {
        throw "new qualification checkpoint identity is invalid"
    }
    $renamedCheckpointRows = @($checkpointCandidates[0] | Rename-VMSnapshot `
        -NewName ([string]$plan.qualification_checkpoint.name) -Passthru `
        -Confirm:$false -ErrorAction Stop)
    $renamedCheckpoint = @(Get-VMSnapshot -Id $createdCheckpointId -ErrorAction Stop)
    if ($renamedCheckpointRows.Count -ne 1 -or
        $renamedCheckpointRows[0].Id -ne $createdCheckpointId -or
        $renamedCheckpoint.Count -ne 1 -or
        $renamedCheckpoint[0].VMId -ne [Guid][string]$plan.vm.id -or
        [string]$renamedCheckpoint[0].Name -cne
            [string]$plan.qualification_checkpoint.name -or
        [string]$renamedCheckpoint[0].SnapshotType -cne "Standard" -or
        $renamedCheckpoint[0].IsAutomaticCheckpoint -ne $false -or
        (ConvertTo-CanonicalGuid -Value $renamedCheckpoint[0].ParentCheckpointId `
            -Label "qualification checkpoint parent") -cne
            (ConvertTo-CanonicalGuid -Value $plan.source_checkpoint.id `
                -Label "source checkpoint")) {
        throw "qualification checkpoint rename did not preserve the exact identity"
    }

    Restore-ExactCheckpoint -Plan $plan -CheckpointId $createdCheckpointId `
        -CheckpointName ([string]$plan.qualification_checkpoint.name)
    $null = Get-ValidatedSupportVmAdapter -Plan $plan `
        -SupportSwitchId $createdSwitchId -SupportAdapterId $createdVmAdapterId `
        -VirtualSystemIdentifiers $createdVmAdapterVirtualSystemIdentifiers
    Start-ExactVm -Plan $plan
    $verificationConnection = Connect-ApprovedGuest -Plan $plan -Credential $credential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    $session = $verificationConnection.Session
    $verifiedGuestState = Invoke-GuestSupportNetwork -Session $session -Plan $plan
    Assert-GuestIdentityUnchanged -Before $configuredGuestState -After $verifiedGuestState
    $runningHostState = Get-ValidatedSupportHostState -Plan $plan -SwitchId $createdSwitchId `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    Stop-GuestCleanly -Plan $plan -Session $session -TimeoutSeconds $ShutdownTimeoutSeconds
    $session = $null
    Restore-ExactCheckpoint -Plan $plan -CheckpointId $createdCheckpointId `
        -CheckpointName ([string]$plan.qualification_checkpoint.name)

    $supportVmAdapter = Get-ValidatedSupportVmAdapter -Plan $plan `
        -SupportSwitchId $createdSwitchId -SupportAdapterId $createdVmAdapterId `
        -VirtualSystemIdentifiers $createdVmAdapterVirtualSystemIdentifiers
    $hostState = Get-ValidatedSupportHostState -Plan $plan -SwitchId $createdSwitchId `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    $finalVm = (Get-ApprovedVmContext -Plan $plan).Vm
    $managementAdapter = Get-ManagementAdapter -Vm $finalVm -Plan $plan
    $finalCheckpoints = @(Get-VMSnapshot -VM $finalVm -ErrorAction Stop)
    $finalCheckpointIds = @($finalCheckpoints | ForEach-Object {
        $_.Id.ToString("D")
    } | Sort-Object)
    $expectedCheckpointIds = @(
        $initialCheckpointIds
        $createdCheckpointId.ToString("D")
    ) | Sort-Object
    $finalQualificationRows = @($finalCheckpoints | Where-Object {
        $_.Id -eq $createdCheckpointId
    })
    if (($finalCheckpointIds -join "|") -cne ($expectedCheckpointIds -join "|") -or
        $finalQualificationRows.Count -ne 1 -or
        [string]$finalQualificationRows[0].Name -cne
            [string]$plan.qualification_checkpoint.name -or
        [string]$finalQualificationRows[0].SnapshotType -cne "Standard" -or
        $finalQualificationRows[0].IsAutomaticCheckpoint -ne $false -or
        @($finalCheckpoints | Where-Object { $_.IsAutomaticCheckpoint -ne $false }).Count -ne 0) {
        throw "terminal checkpoint inventory is not the exact source-plus-qualification set"
    }
    $finalQualificationCheckpoint = $finalQualificationRows[0]
    if ((ConvertTo-CanonicalGuid -Value $finalQualificationCheckpoint.ParentCheckpointId `
            -Label "terminal qualification checkpoint parent") -cne
            (ConvertTo-CanonicalGuid -Value $plan.source_checkpoint.id `
                -Label "source checkpoint")) {
        throw "qualification checkpoint is not a direct child of the pinned source checkpoint"
    }
    $supportSnapshotReferences = @(
        foreach ($snapshotVm in @(Get-VM -ErrorAction Stop)) {
            foreach ($snapshot in @(Get-VMSnapshot -VM $snapshotVm -ErrorAction Stop)) {
                foreach ($snapshotAdapter in @(Get-VMNetworkAdapter -VMSnapshot $snapshot `
                        -ErrorAction Stop | Where-Object {
                            $_.SwitchId -eq $createdSwitchId
                        })) {
                    [pscustomobject][ordered]@{
                        Snapshot = $snapshot
                        Adapter = $snapshotAdapter
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
        $createdVmAdapterVirtualSystemIdentifiers | ForEach-Object { $_.ToString("D") }
    )
    $snapshotSupportIdentifiers = @(
        $supportSnapshotAdapter.VirtualSystemIdentifiers | ForEach-Object {
            ConvertTo-CanonicalGuid -Value $_ `
                -Label "qualification snapshot support adapter identifier"
        }
    )
    $liveSupportInstanceId = Get-VmAdapterInstanceGuid `
        -AdapterId ([string]$supportVmAdapter.Id) `
        -ExpectedOwnerId ([string]$plan.vm.id) -Label "live support VM adapter"
    $snapshotSupportInstanceId = Get-VmAdapterInstanceGuid `
        -AdapterId ([string]$supportSnapshotAdapter.Id) `
        -ExpectedOwnerId $createdCheckpointId.ToString("D") `
        -Label "qualification snapshot support VM adapter"
    if ($supportSnapshot.Id -ne $createdCheckpointId -or
        $supportSnapshotAdapter.VMId -ne [Guid][string]$plan.vm.id -or
        $supportSnapshotAdapter.VMSnapshotId -ne $createdCheckpointId -or
        $supportSnapshotAdapter.VMCheckpointId -ne $createdCheckpointId -or
        [string]$supportSnapshotAdapter.Name -cne [string]$plan.support.vm_adapter_name -or
        $supportSnapshotAdapter.SwitchId -ne $createdSwitchId -or
        [string]$supportSnapshotAdapter.SwitchName -cne [string]$plan.support.switch_name -or
        $supportSnapshotAdapter.DynamicMacAddressEnabled -ne $false -or
        (ConvertTo-CanonicalMacAddress -Value ([string]$supportSnapshotAdapter.MacAddress) `
            -Label "qualification snapshot support VM adapter") -cne
            (ConvertTo-CanonicalMacAddress -Value ([string]$plan.support.vm_mac_address) `
                -Label "planned support VM adapter") -or
        ($snapshotSupportIdentifiers -join "|") -cne ($expectedSupportIdentifiers -join "|") -or
        $snapshotSupportInstanceId -cne $liveSupportInstanceId) {
        throw "qualification snapshot support VM adapter identity is invalid"
    }
    $finalTun = Get-HostTunIdentity
    if ([string]$finalVm.State -cne "Off" -or
        $finalVm.AutomaticCheckpointsEnabled -ne $false -or
        $initialTun.present -ne $true -or $finalTun.present -ne $true -or
        [string]$initialTun.interface_guid -cne [string]$finalTun.interface_guid -or
        [int]$initialTun.interface_index -ne [int]$finalTun.interface_index -or
        [string]$initialTun.name -cne [string]$finalTun.name -or
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
        if ([string]$runningHostState.$field -cne [string]$hostState.$field) {
            throw "support host identity changed before the terminal restore: field=$field"
        }
    }

    $manifest = [pscustomobject][ordered]@{
        schema = 1
        created_utc = [DateTime]::UtcNow.ToString("o")
        topology_plan_sha256 = $planDocument.Sha256
        inspector_sha256 = $initialInspectorSha256
        provisioning_library_sha256 = $initialLibrarySha256
        provisioning_script_sha256 = $initialDriverSha256
        vm = [pscustomobject][ordered]@{
            name = [string]$finalVm.Name
            id = $finalVm.Id.ToString("D")
            terminal_state = [string]$finalVm.State
            automatic_checkpoints_enabled = [bool]$finalVm.AutomaticCheckpointsEnabled
        }
        source_checkpoint = [pscustomobject][ordered]@{
            name = [string]$plan.source_checkpoint.name
            id = (ConvertTo-CanonicalGuid -Value $plan.source_checkpoint.id `
                -Label "source checkpoint")
            type = [string]$plan.source_checkpoint.type
        }
        qualification_checkpoint = [pscustomobject][ordered]@{
            name = [string]$finalQualificationCheckpoint.Name
            id = $createdCheckpointId.ToString("D")
            type = [string]$finalQualificationCheckpoint.SnapshotType
            parent_id = (ConvertTo-CanonicalGuid `
                -Value $finalQualificationCheckpoint.ParentCheckpointId `
                -Label "qualification checkpoint parent")
            support_vm_adapter_snapshot_id = [string]$supportSnapshotAdapter.Id
            restore_verified = $true
        }
        management_adapter = [pscustomobject][ordered]@{
            name = [string]$managementAdapter.Name
            id = [string]$managementAdapter.Id
            switch_name = [string]$managementAdapter.SwitchName
            switch_id = $managementAdapter.SwitchId.ToString("D")
            mac_address = ConvertTo-CanonicalMacAddress `
                -Value ([string]$managementAdapter.MacAddress) -Label "management adapter"
            dynamic_mac_address = [bool]$managementAdapter.DynamicMacAddressEnabled
            guest_interface_alias = [string]$verifiedGuestState.management_interface_alias
            guest_interface_guid = [string]$verifiedGuestState.management_interface_guid
        }
        support = [pscustomobject][ordered]@{
            switch = $hostState
            vm_adapter = [pscustomobject][ordered]@{
                name = [string]$supportVmAdapter.Name
                id = [string]$supportVmAdapter.Id
                switch_id = $supportVmAdapter.SwitchId.ToString("D")
                mac_address = ConvertTo-CanonicalMacAddress `
                    -Value ([string]$supportVmAdapter.MacAddress) -Label "support VM adapter"
                dynamic_mac_address = [bool]$supportVmAdapter.DynamicMacAddressEnabled
                virtual_system_identifiers = @(
                    $supportVmAdapter.VirtualSystemIdentifiers | ForEach-Object {
                        ConvertTo-CanonicalGuid -Value $_ `
                            -Label "support VM adapter identifier"
                    }
                )
            }
            guest = $verifiedGuestState
        }
        protected_host_tun = $finalTun
        constraints = [pscustomobject][ordered]@{
            nat = "absent"
            ics = "absent"
            gateway = "absent"
            dns = "absent_on_support_interfaces"
            firewall_mutation = "none"
            default_switch_mutation = "none"
            host_tun_mutation = "none"
        }
    }
    $terminalPlanDocument = Read-TopologyPlan
    if ($terminalPlanDocument.Sha256 -cne $planDocument.Sha256) {
        throw "topology plan changed during the topology transaction"
    }
    Assert-ProvisioningSourceHash -InspectorSha256 $initialInspectorSha256 `
        -LibrarySha256 $initialLibrarySha256 -DriverSha256 $initialDriverSha256
    $manifestPayload = New-CanonicalJsonPayload -Value $manifest
    $successJson = [pscustomobject][ordered]@{
        schema = 1
        status = "provisioned"
        manifest_path = $resolvedManifestPath
        manifest_sha256 = [string]$manifestPayload.Sha256
        qualification_checkpoint_id = $createdCheckpointId.ToString("D")
        support_switch_id = $createdSwitchId.ToString("D")
        vm_state = [string]$finalVm.State
    } | ConvertTo-Json -Depth 4
    Assert-ProvisioningSourceHash -InspectorSha256 $initialInspectorSha256 `
        -LibrarySha256 $initialLibrarySha256 -DriverSha256 $initialDriverSha256
    $manifestWriteAttempted = $true
    Write-NewCanonicalJson -Path $resolvedManifestPath -Payload $manifestPayload
    $manifestCommitted = $true
    try {
        Write-Output $successJson
    } catch {
        $null = $_
    }
} catch {
    $primaryFailure = $_
} finally {
    if ($null -ne $session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        $session = $null
    }
    $manifestReconciliationFailure = $null
    $manifestCommitAmbiguous = $false
    $manifestCommitRecovered = $false
    if (-not $manifestCommitted -and $manifestWriteAttempted -and
        $null -ne $manifestPayload) {
        try {
            [byte[]]$committedBytes = [IO.File]::ReadAllBytes($resolvedManifestPath)
            $committedHash = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($committedBytes)
            ).ToLowerInvariant()
            $bytesMatch = $committedBytes.Length -eq ([byte[]]$manifestPayload.Bytes).Length -and
                [Convert]::ToBase64String($committedBytes) -ceq
                    [Convert]::ToBase64String([byte[]]$manifestPayload.Bytes)
            if ($bytesMatch -and $committedHash -ceq [string]$manifestPayload.Sha256) {
                $manifestCommitted = $true
                $manifestCommitRecovered = $true
                $primaryFailure = $null
            } else {
                $manifestReconciliationFailure =
                    "topology manifest appeared with bytes that do not match this transaction"
            }
        } catch [IO.FileNotFoundException] {
            $null = $_
        } catch [IO.DirectoryNotFoundException] {
            $null = $_
        } catch {
            $manifestCommitAmbiguous = $true
            $primaryFailure = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    "topology manifest commit is unreadable or ambiguous; " +
                    "the verified topology was left intact for manual recovery: " +
                    $_.Exception.Message
                ),
                "Ferrum2SupportTopologyManifestCommitAmbiguous",
                [Management.Automation.ErrorCategory]::ReadError,
                $resolvedManifestPath
            )
        }
    }
    if ($manifestCommitted) {
        $primaryFailure = $null
    }
    if ($manifestCommitRecovered -and
        -not [string]::IsNullOrWhiteSpace([string]$successJson)) {
        try {
            Write-Output $successJson
        } catch {
            $null = $_
        }
    }
    if ($mutationStarted -and -not $manifestCommitted -and
        -not $manifestCommitAmbiguous) {
        $rollbackFailures = @($manifestReconciliationFailure | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
        try {
            $rollbackFailures += @(Invoke-TopologyRollback -Plan $plan `
                -CreatedSwitchId $createdSwitchId `
                -CreatedVmAdapterId $createdVmAdapterId `
                -CreatedVmAdapterVirtualSystemIdentifiers `
                    $createdVmAdapterVirtualSystemIdentifiers `
                -VmAdapterCreationAttempted $vmAdapterCreationAttempted `
                -CreatedCheckpointId $createdCheckpointId `
                -CreatedCheckpointProvisioningName $createdCheckpointProvisioningName `
                -CheckpointCreationAttempted $checkpointCreationAttempted `
                -InitialCheckpointIds $initialCheckpointIds `
                -InitialTun $initialTun `
                -TimeoutSeconds $ShutdownTimeoutSeconds)
        } catch {
            $rollbackFailures += @("rollback dispatcher: $($_.Exception.Message)")
        }
        if ($rollbackFailures.Count -ne 0) {
            $failureMessage = if ($null -ne $primaryFailure) {
                [string]$primaryFailure.Exception.Message
            } else {
                "topology transaction stopped before commit"
            }
            $primaryFailure = [Management.Automation.ErrorRecord]::new(
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
    if ($mutexOwned) {
        try {
            $mutex.ReleaseMutex()
        } catch {
            $null = $_
        }
    }
    try {
        $mutex.Dispose()
    } catch {
        $null = $_
    }
}

if ($null -ne $primaryFailure) {
    throw $primaryFailure
}
