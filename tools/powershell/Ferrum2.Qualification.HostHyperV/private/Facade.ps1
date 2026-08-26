function Resolve-Ferrum2HostInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)]
        [ValidateSet('ExternalFile', 'ExternalDirectory', 'GuestCredential')]
        [string]$Kind,
        [long]$MaximumBytes = 1073741824
    )
    $root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    $candidate = $Path
    if ($Kind -ceq 'GuestCredential' -and [string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw 'LOCALAPPDATA is unavailable for the default guest credential'
        }
        $candidate = Join-Path $env:LOCALAPPDATA `
            'Ferrum2\hyperv-ferrum2-test.credential.xml'
    }
    if (-not [IO.Path]::IsPathFullyQualified($candidate)) {
        throw "$Label path must be absolute"
    }
    if ($Kind -ceq 'ExternalDirectory') {
        $fullPath = [IO.Path]::GetFullPath($candidate).
            TrimEnd([IO.Path]::DirectorySeparatorChar)
        if (Test-Ferrum2PathWithinRoot -Path $fullPath -Root $root) {
            throw "$Label must be stored outside the repository"
        }
        if (Test-Path -LiteralPath $fullPath) { throw "$Label baseline must be absent" }
        $ancestor = [IO.Path]::GetDirectoryName($fullPath)
        while (-not [string]::IsNullOrWhiteSpace($ancestor) -and
            -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
            $next = [IO.Path]::GetDirectoryName($ancestor)
            if ($next -ceq $ancestor) { break }
            $ancestor = $next
        }
        if ([string]::IsNullOrWhiteSpace($ancestor) -or
            -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
            throw "$Label has no existing parent boundary"
        }
        Assert-NoReparsePointInExistingPath -Path $ancestor -Label $Label
        return $fullPath
    }
    Assert-NoReparsePointInExistingPath -Path $candidate -Label $Label
    $resolved = Resolve-Ferrum2OrdinaryFile -Path $candidate -Label $Label `
        -MaximumBytes $MaximumBytes
    if (Test-Ferrum2PathWithinRoot -Path $resolved -Root $root) {
        throw "$Label must be stored outside the repository"
    }
    if ($Kind -ceq 'GuestCredential') {
        $credential = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
        if ($credential -isnot [Management.Automation.PSCredential] -or
            [string]$credential.UserName -cne 'ferrum2-test') {
            throw 'guest credential file does not contain the approved local PSCredential'
        }
        return $credential
    }
    $resolved
}

function New-Ferrum2HostVmIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$TopologyDocument)
    $value = $TopologyDocument.Value
    $path = (Resolve-Path -LiteralPath ([string]$TopologyDocument.Path) `
        -ErrorAction Stop).Path
    $sha = Get-Ferrum2LowerSha256 $path
    if ($sha -cne [string]$TopologyDocument.Sha256) {
        throw 'HostHyperV topology manifest identity changed'
    }
    [pscustomobject][ordered]@{
        topology_path = $path
        topology_sha256 = $sha
        vm_name = [string]$value.vm.name
        vm_id = [Guid][string]$value.vm.id
        checkpoint_name = [string]$value.qualification_checkpoint.name
        checkpoint_id = [Guid][string]$value.qualification_checkpoint.id
        source_checkpoint_id = [Guid][string]$value.source_checkpoint.id
    }
}

function Get-Ferrum2HostVmContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Identity)
    if ((Get-Ferrum2LowerSha256 ([string]$Identity.topology_path)) -cne
        [string]$Identity.topology_sha256) {
        throw 'HostHyperV topology manifest changed during the transaction'
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

function Connect-Ferrum2HostGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Identity,
        [Parameter(Mandatory)] [Management.Automation.PSCredential]$Credential,
        [ValidateRange(1, 900)] [int]$TimeoutSeconds = 180
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $session = $null
        try {
            if ([string](Get-Ferrum2HostVmContext -Identity $Identity).Vm.State -cne
                'Running') {
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
