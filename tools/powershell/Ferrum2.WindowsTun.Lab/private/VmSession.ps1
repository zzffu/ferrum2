function New-Ferrum2PinnedVmIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Plan)

    [pscustomobject][ordered]@{
        vm_name = [string]$Plan.vm.name
        vm_id = [Guid][string]$Plan.vm.id
        checkpoint_type = 'Standard'
        automatic_checkpoints_enabled = [bool]$Plan.vm.automatic_checkpoints_enabled
        source_checkpoint_name = [string]$Plan.source_checkpoint.name
        source_checkpoint_id = [Guid][string]$Plan.source_checkpoint.id
        source_checkpoint_type = [string]$Plan.source_checkpoint.type
    }
}

function Get-Ferrum2PinnedVmContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Identity)

    $vmRows = @(Get-VM -Id ([Guid]$Identity.vm_id) -ErrorAction Stop)
    $namedVm = @(Get-VM -Name ([string]$Identity.vm_name) -ErrorAction Stop)
    if ($vmRows.Count -ne 1 -or $namedVm.Count -ne 1 -or
        [Guid]$namedVm[0].Id -ne [Guid]$Identity.vm_id -or
        [string]$vmRows[0].Name -cne [string]$Identity.vm_name -or
        [string]$vmRows[0].CheckpointType -cne [string]$Identity.checkpoint_type -or
        [bool]$vmRows[0].AutomaticCheckpointsEnabled -ne
            [bool]$Identity.automatic_checkpoints_enabled) {
        throw 'pinned VM identity or checkpoint policy changed'
    }
    $sourceRows = @(Get-VMSnapshot -Id ([Guid]$Identity.source_checkpoint_id) `
        -ErrorAction Stop)
    $namedSource = @(Get-VMSnapshot -VM $vmRows[0] `
        -Name ([string]$Identity.source_checkpoint_name) -ErrorAction Stop)
    if ($sourceRows.Count -ne 1 -or $namedSource.Count -ne 1 -or
        [Guid]$namedSource[0].Id -ne [Guid]$Identity.source_checkpoint_id -or
        $sourceRows[0].VMId -ne [Guid]$Identity.vm_id -or
        [string]$sourceRows[0].Name -cne [string]$Identity.source_checkpoint_name -or
        [string]$sourceRows[0].SnapshotType -cne
            [string]$Identity.source_checkpoint_type -or
        $sourceRows[0].IsAutomaticCheckpoint -ne $false) {
        throw 'pinned source checkpoint identity changed'
    }
    [pscustomobject][ordered]@{ Vm = $vmRows[0]; SourceCheckpoint = $sourceRows[0] }
}

function Wait-Ferrum2PinnedVmState {
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [ValidateSet('Off', 'Running')] [string]$State,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $context = Get-Ferrum2PinnedVmContext -Identity $Identity
        if ([string]$context.Vm.State -ceq $State) { return $context }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "pinned VM did not reach $State before the bounded timeout"
}

function Invoke-Ferrum2PinnedVmLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)]
        [ValidateSet('Start', 'Stop', 'Restore')]
        [string]$Action,
        [Guid]$CheckpointId = [Guid]::Empty,
        [string]$CheckpointName = '',
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 120
    )
    $context = Get-Ferrum2PinnedVmContext -Identity $Identity
    switch ($Action) {
        'Start' {
            if ([string]$context.Vm.State -cne 'Off') {
                throw 'pinned VM start requires Off'
            }
            $context.Vm | Start-VM -ErrorAction Stop | Out-Null
            $expectedState = 'Running'
        }
        'Stop' {
            if ([string]$context.Vm.State -cne 'Off') {
                $context.Vm | Stop-VM -TurnOff -Force -Confirm:$false `
                    -ErrorAction Stop | Out-Null
            }
            $expectedState = 'Off'
        }
        'Restore' {
            if ([string]$context.Vm.State -cne 'Off') {
                throw 'checkpoint restore requires Off'
            }
            if ($CheckpointId -eq [Guid]::Empty -or
                [string]::IsNullOrWhiteSpace($CheckpointName)) {
                throw 'checkpoint restore requires a pinned checkpoint identity'
            }
            $rows = @(Get-VMSnapshot -Id $CheckpointId -ErrorAction Stop)
            if ($rows.Count -ne 1 -or $rows[0].VMId -ne [Guid]$Identity.vm_id -or
                [string]$rows[0].Name -cne $CheckpointName -or
                [string]$rows[0].SnapshotType -cne 'Standard' -or
                $rows[0].IsAutomaticCheckpoint -ne $false) {
                throw 'checkpoint identity mismatch before restore'
            }
            $rows[0] | Restore-VMSnapshot -Confirm:$false -ErrorAction Stop | Out-Null
            $expectedState = 'Off'
        }
    }
    Wait-Ferrum2PinnedVmState -Identity $Identity -State $expectedState `
        -TimeoutSeconds $TimeoutSeconds
}

function New-Ferrum2HostVmIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$TopologyDocument)
    $value = $TopologyDocument.Value
    $path = (Resolve-Path -LiteralPath ([string]$TopologyDocument.Path) `
        -ErrorAction Stop).Path
    $sha = Get-Ferrum2LowerSha256 $path
    if ($sha -cne [string]$TopologyDocument.Sha256) {
        throw 'Windows TUN Lab topology manifest identity changed'
    }
    [pscustomobject][ordered]@{
        topology_path = $path
        topology_sha256 = $sha
        vm_name = [string]$value.vm.name
        vm_id = [Guid][string]$value.vm.id
        checkpoint_name = [string]$value.lab_checkpoint.name
        checkpoint_id = [Guid][string]$value.lab_checkpoint.id
        source_checkpoint_id = [Guid][string]$value.source_checkpoint.id
    }
}

function Get-Ferrum2HostVmContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Identity)
    if ((Get-Ferrum2LowerSha256 ([string]$Identity.topology_path)) -cne
        [string]$Identity.topology_sha256) {
        throw 'Windows TUN Lab topology manifest changed during the transaction'
    }
    $vmRows = @(Get-VM -Id ([Guid]$Identity.vm_id) -ErrorAction Stop)
    if ($vmRows.Count -ne 1 -or [string]$vmRows[0].Name -cne
        [string]$Identity.vm_name -or $vmRows[0].AutomaticCheckpointsEnabled -ne $false) {
        throw 'approved VM identity mismatch'
    }
    $namedVm = @(Get-VM -Name ([string]$Identity.vm_name) -ErrorAction Stop)
    if ($namedVm.Count -ne 1 -or [Guid]$namedVm[0].Id -ne [Guid]$Identity.vm_id) {
        throw 'approved VM name does not resolve to the approved ID'
    }
    $snapshots = @(Get-VMSnapshot -VM $vmRows[0] -ErrorAction Stop)
    $checkpoint = @($snapshots | Where-Object {
        [Guid]$_.Id -eq [Guid]$Identity.checkpoint_id
    })
    $source = @($snapshots | Where-Object {
        [Guid]$_.Id -eq [Guid]$Identity.source_checkpoint_id
    })
    if ($snapshots.Count -ne 2 -or $checkpoint.Count -ne 1 -or $source.Count -ne 1 -or
        [string]$checkpoint[0].Name -cne [string]$Identity.checkpoint_name -or
        [Guid][string]$checkpoint[0].ParentCheckpointId -ne
            [Guid]$Identity.source_checkpoint_id) {
        throw 'approved checkpoint identity mismatch'
    }
    [pscustomobject][ordered]@{ Vm = $vmRows[0]; Checkpoint = $checkpoint[0] }
}

function Invoke-Ferrum2HostVmLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)]
        [ValidateSet('Start', 'Stop', 'Restore', 'RestoreFinal')]
        [string]$Action,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 120
    )
    if ($Action -ceq 'RestoreFinal') {
        $issues = [Collections.Generic.List[string]]::new()
        foreach ($attempt in 1..2) {
            try {
                Invoke-Ferrum2HostVmLifecycle -Identity $Identity `
                    -Action Stop -TimeoutSeconds $TimeoutSeconds
                Invoke-Ferrum2HostVmLifecycle -Identity $Identity `
                    -Action Restore -TimeoutSeconds $TimeoutSeconds
                return Get-Ferrum2HostVmContext -Identity $Identity
            } catch { $issues.Add("attempt ${attempt}: $($_.Exception.Message)") }
        }
        throw "approved VM final restore failed: $($issues -join ' | ')"
    }
    $context = Get-Ferrum2HostVmContext -Identity $Identity
    switch ($Action) {
        'Start' {
            if ([string]$context.Vm.State -cne 'Off') {
                throw 'approved VM start requires Off'
            }
            $context.Vm | Start-VM -ErrorAction Stop | Out-Null
            $expectedState = 'Running'
        }
        'Stop' {
            if ([string]$context.Vm.State -cne 'Off') {
                $context.Vm | Stop-VM -TurnOff -Force -Confirm:$false `
                    -ErrorAction Stop | Out-Null
            }
            $expectedState = 'Off'
        }
        'Restore' {
            if ([string]$context.Vm.State -cne 'Off') {
                throw 'approved VM restore requires Off'
            }
            $context.Checkpoint | Restore-VMSnapshot -Confirm:$false `
                -ErrorAction Stop | Out-Null
            $expectedState = 'Off'
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $readback = Get-Ferrum2HostVmContext -Identity $Identity
        if ([string]$readback.Vm.State -ceq $expectedState) { return $readback }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "approved VM did not reach $expectedState before the bounded timeout"
}

function Connect-Ferrum2VmGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory)] [ValidateSet('Manifest', 'Pinned')] [string]$IdentityKind,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 180
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $session = $null
        try {
            $context = if ($IdentityKind -ceq 'Pinned') {
                Get-Ferrum2PinnedVmContext -Identity $Identity
            } else {
                Get-Ferrum2HostVmContext -Identity $Identity
            }
            if ([string]$context.Vm.State -cne 'Running') {
                throw 'approved VM left Running before PowerShell Direct readiness'
            }
            $session = New-PSSession -VMId ([Guid]$Identity.vm_id) `
                -Credential $Credential -ErrorAction Stop
            $session.Runspace.ConnectionInfo.OperationTimeout = 43200000
            if ($session.Runspace.ConnectionInfo.OperationTimeout -ne 43200000) {
                throw 'PowerShell Direct operation timeout was not retained'
            }
            $probe = @(Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $version = Get-ItemProperty `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    -ErrorAction Stop
                $principal = [Security.Principal.WindowsPrincipal]::new(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                )
                [pscustomobject][ordered]@{
                    Manufacturer = [string]$computer.Manufacturer
                    Model = [string]$computer.Model
                    Product = [string]$version.ProductName
                    Edition = [string]$version.EditionID
                    Version = [Environment]::OSVersion.Version.ToString()
                    Build = "$($version.CurrentBuildNumber).$($version.UBR)"
                    OsBuild = [string]$os.BuildNumber
                    CurrentBuild = [string]$version.CurrentBuildNumber
                    Architecture = [string]$env:PROCESSOR_ARCHITECTURE
                    PowerShell = $PSVersionTable.PSVersion.ToString()
                    IsAdministrator = $principal.IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator
                    )
                }
            })
            if ($probe.Count -ne 1 -or $probe[0].Manufacturer -cne
                'Microsoft Corporation' -or $probe[0].Model -cne 'Virtual Machine' -or
                $probe[0].Architecture -cne 'AMD64' -or
                $probe[0].OsBuild -cne $probe[0].CurrentBuild -or
                $probe[0].IsAdministrator -ne $true) {
                throw 'PowerShell Direct reached an ineligible guest identity'
            }
            return [pscustomobject][ordered]@{ Session = $session; Probe = $probe[0] }
        } catch {
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Seconds 2
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'PowerShell Direct did not become ready before the bounded timeout'
}

function Connect-Ferrum2HostGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [Management.Automation.PSCredential]$Credential,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 180
    )
    Connect-Ferrum2VmGuest -Identity $Identity -Credential $Credential `
        -IdentityKind Manifest -TimeoutSeconds $TimeoutSeconds
}

function Connect-Ferrum2PinnedVmGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [Management.Automation.PSCredential]$Credential,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 180
    )
    Connect-Ferrum2VmGuest -Identity $Identity -Credential $Credential `
        -IdentityKind Pinned -TimeoutSeconds $TimeoutSeconds
}

function Stop-Ferrum2PinnedVmGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [object]$Session,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 120
    )
    try {
        Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
            & "$env:SystemRoot\System32\shutdown.exe" /s /t 0 /f
        } | Out-Null
    } catch {
        Write-Verbose 'PowerShell Direct disconnected during guest shutdown'
    }
    Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $context = Get-Ferrum2PinnedVmContext -Identity $Identity
        if ([string]$context.Vm.State -ceq 'Off') { return $context }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    Invoke-Ferrum2PinnedVmLifecycle -Identity $Identity -Action Stop `
        -TimeoutSeconds $TimeoutSeconds | Out-Null
    throw 'guest did not complete a clean shutdown before the bounded timeout'
}
