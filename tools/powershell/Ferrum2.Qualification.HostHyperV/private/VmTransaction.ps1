function Initialize-ApprovedHyperVTopology {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256
    )

    if ($null -ne $script:topologyManifestDocument) {
        throw "support topology manifest was initialized more than once"
    }
    Import-ApprovedTopologyRuntime
    $document = Read-Ferrum2SupportTopologyManifest `
        -Path $ManifestPath -ExpectedSha256 $ExpectedSha256 `
        -RepositoryRoot $script:repositoryRoot
    $script:topologyManifestDocument = $document
    $script:approvedVmName = [string]$document.Value.vm.name
    $script:approvedVmId = [Guid][string]$document.Value.vm.id
    $script:approvedCheckpointName = [string]$document.Value.lab_checkpoint.name
    $script:approvedCheckpointId = [Guid][string]$document.Value.lab_checkpoint.id
    $script:approvedVmIdentity = New-Ferrum2HostVmIdentity -TopologyDocument $document
    $state = Get-ApprovedHyperVTopologyRuntimeState -TopologyDocument $document
    return [pscustomobject][ordered]@{
        Document = $document
        Runtime = $state.Runtime
        VmNetwork = $state.VmNetwork
        TopologyRuntimeSha256 = $script:topologyRuntimeSha256
        HostNetworkPathHelperSha256 = $script:hostNetworkPathHelperSha256
        GuestNetworkPathProbeSha256 = $script:guestNetworkPathProbeSha256
    }
}

function Import-ApprovedGuestCredential {
    param([string]$Path)

    Resolve-Ferrum2HostInput `
        -RepositoryRoot $script:repositoryRoot `
        -Path $Path `
        -Label "guest credential" `
        -Kind GuestCredential `
        -MaximumBytes 1048576
}

function Get-ApprovedVmContext {
    if ($null -eq $script:approvedVmIdentity) {
        throw "approved VM identity is not initialized"
    }
    Get-Ferrum2HostVmContext -Identity $script:approvedVmIdentity
}

function Invoke-BoundedHyperVMutation {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Read", "Start", "Stop", "Restore")]
        [string]$Action,
        [Parameter(Mandatory = $true)][Guid]$VmId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName,
        [Guid]$CheckpointId = [Guid]::Empty,
        [AllowNull()][string]$ExpectedCheckpointName = $null,
        [Guid]$ExpectedCheckpointParentId = [Guid]::Empty,
        [ValidateRange(1, 900)][int]$TimeoutSeconds = 120
    )

    if ($VmId -eq [Guid]::Empty -or
        ($Action -ceq "Restore" -and
            ($CheckpointId -eq [Guid]::Empty -or
                $ExpectedCheckpointParentId -eq [Guid]::Empty -or
                [string]::IsNullOrWhiteSpace($ExpectedCheckpointName) -or
                $ExpectedCheckpointName -cnotmatch
                    '^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')) -or
        ($Action -cne "Restore" -and
            ($CheckpointId -ne [Guid]::Empty -or
                $ExpectedCheckpointParentId -ne [Guid]::Empty -or
                -not [string]::IsNullOrWhiteSpace($ExpectedCheckpointName)))) {
        throw "bounded Hyper-V mutation identity is invalid"
    }
    $encodedCommand = New-Ferrum2HyperVMutationCommand `
        -Action $Action `
        -VmId $VmId `
        -ExpectedVmName $ExpectedVmName `
        -CheckpointId $CheckpointId `
        -ExpectedCheckpointName $ExpectedCheckpointName `
        -ExpectedCheckpointParentId $ExpectedCheckpointParentId `
        -TimeoutSeconds $TimeoutSeconds
    $gateName = "Local\Ferrum2-HyperV-Mutation-" + [Guid]::NewGuid().ToString("N")
    $gateCreated = $false
    $startGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $gateName,
        [ref]$gateCreated
    )
    if (-not $gateCreated) {
        $startGate.Dispose()
        throw "bounded Hyper-V mutation gate identity already exists"
    }
    $result = $null
    $primaryFailure = $null
    $finalizationIssues = [Collections.Generic.List[string]]::new()
    try {
        $result = Invoke-BoundedPwshFile -Arguments @(
            "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", $encodedCommand
        ) -TimeoutSeconds $TimeoutSeconds -Label "Bounded Hyper-V $Action mutation" `
            -Environment ([ordered]@{ FERRUM2_HYPERV_MUTATION_GATE = $gateName }) `
            -StartGate $startGate
    } catch {
        $primaryFailure = $_
    } finally {
        try {
            $startGate.Dispose()
        } catch {
            $finalizationIssues.Add(
                "bounded Hyper-V $Action mutation gate disposal failed: " +
                    $_.Exception.Message
            )
        }
    }
    if ($null -ne $primaryFailure) {
        if ($finalizationIssues.Count -ne 0) {
            throw (
                "bounded Hyper-V $Action mutation failed: " +
                    "primary=$($primaryFailure.Exception.Message); " +
                    "finalization=$($finalizationIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($finalizationIssues.Count -ne 0) {
        throw (
            "bounded Hyper-V $Action mutation finalization failed: " +
                ($finalizationIssues -join "; ")
        )
    }
    $stdout = [string]$result.Stdout
    $stderr = [string]$result.Stderr
    try {
        $lines = @($stdout -split '\r?\n' | Where-Object { $_.Length -gt 0 })
        $markerPattern = '^FERRUM2_BOUNDED_HYPERV_ACTION_PASS action=' +
            [regex]::Escape($Action) + ' state=(?<state>[A-Za-z]+)$'
        if ($result.ExitCode -ne 0 -or
            $lines.Count -ne 1 -or
            $lines[0] -cnotmatch $markerPattern -or
            -not [string]::IsNullOrWhiteSpace($stderr)) {
            $detail = (($stderr + "`n" + $stdout).Trim() -replace '[\r\n]+', ' | ')
            if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) }
            throw "bounded Hyper-V $Action mutation failed: $detail"
        }
        return [string]$Matches.state
    } catch {
        throw
    }
}

function Start-ApprovedVm {
    param([ValidateRange(1, 900)][int]$TimeoutSeconds = 120)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before start"
    }
    [void](Invoke-BoundedHyperVMutation -Action Start -VmId $script:approvedVmId `
        -ExpectedVmName $script:approvedVmName `
        -TimeoutSeconds $TimeoutSeconds)
    $started = Get-ApprovedVmContext
    if ([string]$started.Vm.State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
}

function Stop-ApprovedVm {
    param([int]$TimeoutSeconds)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        [void](Invoke-BoundedHyperVMutation -Action Stop -VmId $script:approvedVmId `
            -ExpectedVmName $script:approvedVmName `
            -TimeoutSeconds $TimeoutSeconds)
    }
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM did not become Off before the bounded timeout"
    }
}

function Restore-ApprovedCheckpoint {
    param([ValidateRange(1, 900)][int]$TimeoutSeconds = 120)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before checkpoint restore"
    }
    [void](Invoke-BoundedHyperVMutation -Action Restore -VmId $script:approvedVmId `
        -ExpectedVmName $script:approvedVmName `
        -CheckpointId $script:approvedCheckpointId `
        -ExpectedCheckpointName $script:approvedCheckpointName `
        -ExpectedCheckpointParentId ([Guid][string]$context.Checkpoint.ParentCheckpointId) `
        -TimeoutSeconds $TimeoutSeconds)
    $restored = Get-ApprovedVmContext
    if ([string]$restored.Vm.State -cne "Off") {
        throw "checkpoint restore did not leave the approved VM Off"
    }
}

function Assert-ApprovedVmCleanupAuthority {
    param([Parameter(Mandatory = $true)][object]$Authority)

    if ($null -eq $script:topologyManifestDocument -or
        $script:approvedVmId -eq [Guid]::Empty -or
        $script:approvedCheckpointId -eq [Guid]::Empty) {
        throw "approved VM cleanup authority cannot be used before topology initialization"
    }
    $approvedParentId = [Guid][string](
        $script:topologyManifestDocument.Value.source_checkpoint.id
    )
    $expected = @(
        "vm_id", "vm_name", "checkpoint_id", "checkpoint_name",
        "checkpoint_parent_id"
    )
    if ((@($Authority.PSObject.Properties.Name) -join "|") -cne
            ($expected -join "|") -or
        $Authority.vm_id -isnot [Guid] -or
        [Guid]$Authority.vm_id -eq [Guid]::Empty -or
        $Authority.checkpoint_id -isnot [Guid] -or
        [Guid]$Authority.checkpoint_id -eq [Guid]::Empty -or
        $Authority.checkpoint_parent_id -isnot [Guid] -or
        [Guid]$Authority.checkpoint_parent_id -eq [Guid]::Empty -or
        $Authority.vm_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Authority.vm_name) -or
        $Authority.checkpoint_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Authority.checkpoint_name) -or
        [Guid]$Authority.vm_id -ne $script:approvedVmId -or
        [string]$Authority.vm_name -cne $script:approvedVmName -or
        [Guid]$Authority.checkpoint_id -ne $script:approvedCheckpointId -or
        [string]$Authority.checkpoint_name -cne $script:approvedCheckpointName -or
        [Guid]$Authority.checkpoint_parent_id -ne $approvedParentId) {
        throw "approved VM cleanup authority is invalid"
    }
}

function New-ApprovedVmCleanupAuthority {
    param([Parameter(Mandatory = $true)][object]$Context)

    $document = Get-ApprovedTopologyDocument
    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $document
    $sourceCheckpointId = [Guid][string]$document.Value.source_checkpoint.id
    $vmId = [Guid]$Context.Vm.Id
    $checkpointId = [Guid]$Context.Checkpoint.Id
    $checkpointParentId = [Guid][string]$Context.Checkpoint.ParentCheckpointId
    if ($vmId -ne $script:approvedVmId -or
        [string]$Context.Vm.Name -cne $script:approvedVmName -or
        [string]$Context.Vm.State -cne "Off" -or
        $Context.Vm.AutomaticCheckpointsEnabled -ne $false -or
        $checkpointId -ne $script:approvedCheckpointId -or
        [string]$Context.Checkpoint.Name -cne $script:approvedCheckpointName -or
        $checkpointParentId -ne $sourceCheckpointId) {
        throw "approved VM cleanup authority baseline is invalid"
    }
    $authority = [pscustomobject][ordered]@{
        vm_id = $vmId
        vm_name = [string]$Context.Vm.Name
        checkpoint_id = $checkpointId
        checkpoint_name = [string]$Context.Checkpoint.Name
        checkpoint_parent_id = $checkpointParentId
    }
    Assert-ApprovedVmCleanupAuthority -Authority $authority
    return $authority
}

function Get-ApprovedVmEmergencyState {
    param([Parameter(Mandatory = $true)][object]$Authority)

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    $state = Invoke-BoundedHyperVMutation -Action Read `
        -VmId ([Guid]$Authority.vm_id) `
        -ExpectedVmName ([string]$Authority.vm_name) `
        -TimeoutSeconds 30
    return [pscustomobject][ordered]@{
        Id = [Guid]$Authority.vm_id
        State = [string]$state
    }
}

function Stop-ApprovedVmEmergency {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [ValidateRange(1, 900)][int]$TimeoutSeconds
    )

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    [void](Invoke-BoundedHyperVMutation -Action Stop `
        -VmId ([Guid]$Authority.vm_id) `
        -ExpectedVmName ([string]$Authority.vm_name) `
        -TimeoutSeconds $TimeoutSeconds)
}

function Restore-ApprovedCheckpointEmergency {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [ValidateRange(1, 900)][int]$ShutdownTimeoutSeconds
    )

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    try {
        [void](Invoke-BoundedHyperVMutation -Action Restore `
            -VmId ([Guid]$Authority.vm_id) `
            -ExpectedVmName ([string]$Authority.vm_name) `
            -CheckpointId ([Guid]$Authority.checkpoint_id) `
            -ExpectedCheckpointName ([string]$Authority.checkpoint_name) `
            -ExpectedCheckpointParentId ([Guid]$Authority.checkpoint_parent_id) `
            -TimeoutSeconds $ShutdownTimeoutSeconds)
    } catch {
        $restoreFailure = $_
        try {
            Stop-ApprovedVmEmergency -Authority $Authority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
        } catch {
            throw (
                "emergency checkpoint restore failed: $($restoreFailure.Exception.Message); " +
                "post-failure VM stop also failed: $($_.Exception.Message)"
            )
        }
        throw $restoreFailure
    }
}

function New-BoundedPwshFileArguments {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][string[]]$ForwardedParameterNames,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
        [string]$InternalWorkerToken
    )

    $resolvedScript = Resolve-BoundedFile `
        -Path $ScriptPath -Label "bounded PowerShell worker script" -MaximumBytes 4194304
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($argument in @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $resolvedScript)) {
        $arguments.Add($argument)
    }
    foreach ($name in $ForwardedParameterNames) {
        if (-not $BoundParameters.ContainsKey($name)) {
            continue
        }
        $value = $BoundParameters[$name]
        if ($value -is [Management.Automation.SwitchParameter]) {
            if ([Management.Automation.SwitchParameter]$value) {
                $arguments.Add("-$name")
            }
            continue
        }
        if ($null -eq $value) {
            continue
        }
        $arguments.Add("-$name")
        $arguments.Add([Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture))
    }
    $arguments.Add("-InternalWorker")
    $arguments.Add("-InternalWorkerToken")
    $arguments.Add($InternalWorkerToken)
    return @($arguments)
}
