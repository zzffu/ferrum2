#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Defines the mutation and rollback functions for the Windows TUN Hyper-V support topology.

.DESCRIPTION
This dot-source-only library imports the read-only topology inspector library and defines the
provisioning transaction helpers. It does not invoke any helper or change state when loaded.
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

$inspectorPath = Join-Path $PSScriptRoot "inspect_windows_tun_hyperv_support_topology.ps1"
. $inspectorPath -LibraryOnly

if (-not $LibraryOnly) {
    throw "provisioning helpers are dot-source-only"
}

function Assert-NoReparsePointInExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use a rooted filesystem path"
    }
    $current = $root
    foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object {
        $_.Length -gt 0
    })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function Resolve-ExternalFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 1048576
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-NoReparsePointInExistingPath -Path $resolved -Label $Label
    if (Test-PathWithinRoot -Path $resolved -Root $script:repositoryRoot) {
        throw "$Label must be stored outside the repository"
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label file boundary is invalid"
    }
    return $resolved
}

function Resolve-NewExternalFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (Test-PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) {
        throw "$Label must be stored outside the repository"
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw "$Label baseline must be absent"
    }
    if ([IO.Path]::GetExtension($fullPath) -cne ".json") {
        throw "$Label must use a .json extension"
    }
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parent) -or
        -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "$Label parent directory must already exist"
    }
    Assert-NoReparsePointInExistingPath -Path $parent -Label $Label
    return $fullPath
}

function Import-ApprovedGuestCredential {
    param([string]$Path)

    $candidate = $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw "LOCALAPPDATA is required for the default guest credential"
        }
        $candidate = Join-Path $env:LOCALAPPDATA `
            "Ferrum2\hyperv-ferrum2-test.credential.xml"
    }
    $resolved = Resolve-ExternalFile -Path $candidate -Label "guest credential"
    $credential = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    if ($credential -isnot [Management.Automation.PSCredential] -or
        [string]$credential.UserName -cne "ferrum2-test") {
        throw "guest credential file does not contain the approved local PSCredential"
    }
    return $credential
}

function Restore-ExactCheckpoint {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$CheckpointId,
        [Parameter(Mandatory = $true)][string]$CheckpointName
    )

    $context = Get-ApprovedVmContext -Plan $Plan
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before checkpoint restore"
    }
    $snapshot = @(Get-VMSnapshot -Id $CheckpointId -ErrorAction Stop)
    if ($snapshot.Count -ne 1 -or $snapshot[0].VMId -ne $context.Vm.Id -or
        [string]$snapshot[0].Name -cne $CheckpointName -or
        [string]$snapshot[0].SnapshotType -cne "Standard" -or
        $snapshot[0].IsAutomaticCheckpoint -ne $false) {
        throw "checkpoint identity mismatch before restore"
    }
    $snapshot[0] | Restore-VMSnapshot -Confirm:$false -ErrorAction Stop | Out-Null
    if ([string](Get-VM -Id $context.Vm.Id -ErrorAction Stop).State -cne "Off") {
        throw "checkpoint restore did not leave the approved VM Off"
    }
}

function Start-ExactVm {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $vm = (Get-ApprovedVmContext -Plan $Plan).Vm
    if ([string]$vm.State -cne "Off") {
        throw "approved VM must be Off before start"
    }
    $vm | Start-VM -ErrorAction Stop | Out-Null
    if ([string](Get-VM -Id $vm.Id -ErrorAction Stop).State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
}

function Stop-ExactVmHard {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $vmId = [Guid][string]$Plan.vm.id
    $vm = Get-VM -Id $vmId -ErrorAction Stop
    if ([string]$vm.State -cne "Off") {
        $vm | Stop-VM -TurnOff -Force -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ([string](Get-VM -Id $vmId -ErrorAction Stop).State -ceq "Off") {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "approved VM did not become Off before the bounded timeout"
}

function Stop-GuestCleanly {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    try {
        Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
            & "$env:SystemRoot\System32\shutdown.exe" /s /t 0 /f
        } | Out-Null
    } catch {
        # PowerShell Direct normally disconnects while shutdown.exe completes.
        Write-Verbose "PowerShell Direct disconnected during guest shutdown"
    }
    Remove-PSSession -Session $Session -ErrorAction SilentlyContinue

    $vmId = [Guid][string]$Plan.vm.id
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ([string](Get-VM -Id $vmId -ErrorAction Stop).State -ceq "Off") {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    Stop-ExactVmHard -Plan $Plan -TimeoutSeconds $TimeoutSeconds
    throw "guest did not complete a clean shutdown before the bounded timeout"
}

function Connect-ApprovedGuest {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $session = $null
        try {
            $vm = Get-VM -Id ([Guid][string]$Plan.vm.id) -ErrorAction Stop
            if ([string]$vm.State -cne "Running") {
                throw "approved VM left Running state before PowerShell Direct readiness"
            }
            $session = New-PSSession -VMId $vm.Id -Credential $Credential `
                -Name ("ferrum2-support-" + [Guid]::NewGuid().ToString("N")) `
                -ErrorAction Stop
            $probe = @(Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $version = Get-ItemProperty `
                    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    -ErrorAction Stop
                $principal = New-Object Security.Principal.WindowsPrincipal(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                )
                [pscustomobject][ordered]@{
                    manufacturer = [string]$computer.Manufacturer
                    model = [string]$computer.Model
                    product = [string]$version.ProductName
                    edition = [string]$version.EditionID
                    build = "$($version.CurrentBuildNumber).$($version.UBR)"
                    architecture = [string]$env:PROCESSOR_ARCHITECTURE
                    powershell = $PSVersionTable.PSVersion.ToString()
                    is_administrator = $principal.IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator
                    )
                }
            })
            if ($probe.Count -ne 1 -or
                [string]$probe[0].manufacturer -cne "Microsoft Corporation" -or
                [string]$probe[0].model -cne "Virtual Machine" -or
                [string]$probe[0].architecture -cne "AMD64" -or
                $probe[0].is_administrator -ne $true) {
                throw "PowerShell Direct reached an ineligible guest identity"
            }
            return [pscustomobject][ordered]@{ Session = $session; Identity = $probe[0] }
        } catch {
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                break
            }
            Start-Sleep -Seconds 2
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not become ready before the bounded timeout"
}

function Get-SupportSwitchContext {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $switches = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
            $_.Id -eq $SwitchId
        })
        if ($switches.Count -eq 1 -and
            [string]$switches[0].Name -ceq [string]$Plan.support.switch_name -and
            [string]$switches[0].SwitchType -ceq "Internal" -and
            $switches[0].AllowManagementOS -eq $true) {
            $byName = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
                [string]$_.Name -ieq [string]$Plan.support.switch_name
            })
            $managementAdapters = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop |
                Where-Object { $_.SwitchId -eq $SwitchId })
            if ($byName.Count -eq 1 -and $byName[0].Id -eq $SwitchId -and
                $managementAdapters.Count -eq 1) {
                $deviceGuid = [Guid]::Empty
                if ([Guid]::TryParse([string]$managementAdapters[0].DeviceId, [ref]$deviceGuid)) {
                    $hostAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                        Where-Object { ([Guid][string]$_.InterfaceGuid) -eq $deviceGuid })
                    if ($hostAdapters.Count -eq 1 -and
                        $hostAdapters[0].Virtual -eq $true -and
                        $hostAdapters[0].HardwareInterface -eq $false) {
                        return [pscustomobject][ordered]@{
                            Switch = $switches[0]
                            ManagementAdapter = $managementAdapters[0]
                            HostAdapter = $hostAdapters[0]
                        }
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "new support switch did not expose one exact host vNIC"
}

function Assert-IcsDisabledForHostAdapter {
    param([Parameter(Mandatory = $true)][Guid]$InterfaceGuid)

    $sharingManager = New-Object -ComObject HNetCfg.HNetShare
    $sharingConnections = [Collections.Generic.List[object]]::new()
    foreach ($connection in @($sharingManager.EnumEveryConnection)) {
        $properties = $sharingManager.NetConnectionProps($connection)
        if ([Guid][string]$properties.Guid -eq $InterfaceGuid) {
            $sharingConnections.Add($connection)
        }
    }
    if ($sharingConnections.Count -ne 1) {
        throw "support host vNIC is not unique in the ICS inventory"
    }
    $configuration = $sharingManager.INetSharingConfigurationForINetConnection(
        $sharingConnections[0]
    )
    if ($configuration.SharingEnabled) {
        throw "ICS is unexpectedly enabled on the support host vNIC"
    }
}

function Assert-NoSupportNat {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $collisions = @(Get-NetNat -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.InternalIPInterfaceAddressPrefix) -and
        (Test-Ipv4PrefixOverlap -Left ([string]$_.InternalIPInterfaceAddressPrefix) `
            -Right ([string]$Plan.support.network))
    })
    if ($collisions.Count -ne 0) {
        throw "support /30 is unexpectedly covered by NAT"
    }
}

function Get-ActiveIpv4AddressRow {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    try {
        return @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -PolicyStore ActiveStore -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
            return @()
        }
        throw
    }
}

function Get-ProvisioningPersistentIpv4AddressRow {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    try {
        return @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
            -PolicyStore PersistentStore -ErrorAction Stop)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like
                "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
            return @()
        }
        throw
    }
}

function Get-Ipv4RouteRow {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ActiveStore", "PersistentStore")]
        [string]$PolicyStore,
        [string]$DestinationPrefix
    )

    $parameters = @{
        InterfaceIndex = $InterfaceIndex
        AddressFamily = "IPv4"
        PolicyStore = $PolicyStore
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPrefix)) {
        $parameters.DestinationPrefix = $DestinationPrefix
    }
    try {
        return @(Get-NetRoute @parameters)
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            [string]$_.FullyQualifiedErrorId -like "CmdletizationQuery_NotFound*,Get-NetRoute") {
            return @()
        }
        throw
    }
}

function Set-SupportHostAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$SwitchContext
    )

    $interfaceIndex = [int]$SwitchContext.HostAdapter.ifIndex
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore ActiveStore -Dhcp Disabled -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore PersistentStore -IgnoreDefaultRoutes Enabled `
        -ErrorAction Stop | Out-Null
    foreach ($store in @("ActiveStore", "PersistentStore")) {
        foreach ($route in @(Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex `
                -PolicyStore $store -DestinationPrefix "0.0.0.0/0")) {
            $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }
    }
    foreach ($address in @(Get-ActiveIpv4AddressRow -InterfaceIndex $interfaceIndex)) {
        $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    }
    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses `
        -ErrorAction Stop | Out-Null
    Set-DnsClient -InterfaceIndex $interfaceIndex -RegisterThisConnectionsAddress:$false `
        -UseSuffixWhenRegistering:$false -ErrorAction Stop | Out-Null
    New-NetIPAddress -InterfaceIndex $interfaceIndex `
        -IPAddress ([string]$Plan.support.host_ipv4) `
        -PrefixLength ([byte][int]$Plan.support.prefix_length) `
        -AddressFamily IPv4 -Type Unicast -ErrorAction Stop | Out-Null
}

function Get-ValidatedSupportHostState {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SwitchId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $context = Get-SupportSwitchContext -Plan $Plan -SwitchId $SwitchId `
        -TimeoutSeconds $TimeoutSeconds
    $interfaceIndex = [int]$context.HostAdapter.ifIndex
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $addresses = @(Get-ActiveIpv4AddressRow -InterfaceIndex $interfaceIndex)
        $expectedAddresses = @($addresses | Where-Object {
            [string]$_.IPAddress -ceq [string]$Plan.support.host_ipv4 -and
            [int]$_.PrefixLength -eq [int]$Plan.support.prefix_length -and
            [string]$_.AddressState -ceq "Preferred"
        })
        if ($addresses.Count -eq 1 -and $expectedAddresses.Count -eq 1) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($addresses.Count -ne 1 -or $expectedAddresses.Count -ne 1) {
        throw "support host vNIC does not have the exact preferred /30 address"
    }
    $persistentAddresses = @(Get-ProvisioningPersistentIpv4AddressRow `
        -InterfaceIndex $interfaceIndex)
    $expectedPersistentAddresses = @($persistentAddresses | Where-Object {
        [string]$_.IPAddress -ceq [string]$Plan.support.host_ipv4 -and
        [int]$_.PrefixLength -eq [int]$Plan.support.prefix_length
    })
    if ($persistentAddresses.Count -ne 1 -or $expectedPersistentAddresses.Count -ne 1) {
        throw "support host /30 address is not uniquely persistent"
    }

    $ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $persistentIpInterfaces = @(Get-NetIPInterface -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction Stop)
    $directRoutes = @(Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex `
        -PolicyStore ActiveStore -DestinationPrefix ([string]$Plan.support.network) |
        Where-Object {
        [string]$_.NextHop -ceq "0.0.0.0"
    })
    $allRoutes = @(
        Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore
        Get-Ipv4RouteRow -InterfaceIndex $interfaceIndex -PolicyStore PersistentStore
    )
    $defaultRoutes = @($allRoutes | Where-Object {
        [string]$_.DestinationPrefix -ceq "0.0.0.0/0"
    })
    $gatewayRoutes = @($allRoutes | Where-Object {
        [string]$_.NextHop -cne "0.0.0.0"
    })
    $ipv4DnsServers = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object
    )
    $ipv6DnsServers = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -ErrorAction Stop |
            ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object
    )
    $windowsIntrinsicIpv6Dns = @(
        "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
    )
    $dnsStateValid = $ipv4DnsServers.Count -eq 0 -and
        ($ipv6DnsServers.Count -eq 0 -or
            ($ipv6DnsServers -join "|") -ieq ($windowsIntrinsicIpv6Dns -join "|"))
    $selection = @(Find-NetRoute -RemoteIPAddress ([string]$Plan.support.guest_ipv4) `
        -ErrorAction Stop)
    $sourceRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["IPAddress"]
    })
    $routeRows = @($selection | Where-Object {
        $null -ne $_.PSObject.Properties["DestinationPrefix"]
    })
    $activeInterfaceValid = $ipInterfaces.Count -eq 1 -and
        [string]$ipInterfaces[0].Dhcp -ceq "Disabled" -and
        [string]$ipInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled" -and
        [int]$ipInterfaces[0].NlMtu -ge 1468
    $persistentInterfaceValid = $persistentIpInterfaces.Count -eq 1 -and
        [string]$persistentIpInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled"
    $sourceSelectionValid = $sourceRows.Count -eq 1 -and
        [string]$sourceRows[0].IPAddress -ceq [string]$Plan.support.host_ipv4 -and
        [int]$sourceRows[0].InterfaceIndex -eq $interfaceIndex
    $routeSelectionValid = $routeRows.Count -eq 1 -and
        [string]$routeRows[0].DestinationPrefix -ceq [string]$Plan.support.network -and
        [string]$routeRows[0].NextHop -ceq "0.0.0.0" -and
        [int]$routeRows[0].InterfaceIndex -eq $interfaceIndex
    $violations = @(
        if (-not $activeInterfaceValid) { "active_interface" }
        if (-not $persistentInterfaceValid) { "persistent_interface" }
        if ($directRoutes.Count -ne 1) { "direct_route_count=$($directRoutes.Count)" }
        if ($defaultRoutes.Count -ne 0) { "default_route_count=$($defaultRoutes.Count)" }
        if ($gatewayRoutes.Count -ne 0) { "gateway_route_count=$($gatewayRoutes.Count)" }
        if (-not $dnsStateValid) {
            "dns_state=ipv4:$($ipv4DnsServers.Count),ipv6:$($ipv6DnsServers.Count)"
        }
        if (-not $sourceSelectionValid) { "source_selection" }
        if (-not $routeSelectionValid) { "route_selection" }
    )
    if ($violations.Count -ne 0) {
        throw "support host route, DNS, DHCP, MTU, or source-selection contract is invalid: " +
            ($violations -join ",")
    }
    Assert-NoSupportNat -Plan $Plan
    Assert-IcsDisabledForHostAdapter -InterfaceGuid ([Guid]$context.HostAdapter.InterfaceGuid)

    return [pscustomobject][ordered]@{
        switch_name = [string]$context.Switch.Name
        switch_id = $context.Switch.Id.ToString("D")
        switch_type = [string]$context.Switch.SwitchType
        management_os_adapter_id = [string]$context.ManagementAdapter.Id
        management_os_device_id = (ConvertTo-CanonicalGuid `
            -Value $context.ManagementAdapter.DeviceId -Label "support management OS adapter")
        host_interface_alias = [string]$context.HostAdapter.Name
        host_interface_guid = (ConvertTo-CanonicalGuid `
            -Value $context.HostAdapter.InterfaceGuid -Label "support host interface")
        host_interface_index = $interfaceIndex
        host_mac_address = ConvertTo-CanonicalMacAddress `
            -Value ([string]$context.HostAdapter.MacAddress) -Label "support host interface"
        host_ipv4 = [string]$expectedAddresses[0].IPAddress
        prefix_length = [int]$expectedAddresses[0].PrefixLength
        network = [string]$Plan.support.network
        gateway = $null
        dns_servers = @()
        mtu_bytes = [int]$ipInterfaces[0].NlMtu
        nat_enabled = $false
        ics_enabled = $false
        selected_source_ipv4 = [string]$sourceRows[0].IPAddress
        selected_route_prefix = [string]$routeRows[0].DestinationPrefix
        selected_route_next_hop = [string]$routeRows[0].NextHop
    }
}

function Get-ValidatedSupportVmAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][Guid]$SupportSwitchId,
        [Parameter(Mandatory = $true)][string]$SupportAdapterId,
        [Parameter(Mandatory = $true)][Guid[]]$VirtualSystemIdentifiers
    )

    $vm = (Get-ApprovedVmContext -Plan $Plan).Vm
    $management = Get-ManagementAdapter -Vm $vm -Plan $Plan
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    $support = @($adapters | Where-Object { [string]$_.Id -ieq $SupportAdapterId })
    $expectedVirtualSystemIdentifiers = @($VirtualSystemIdentifiers | ForEach-Object {
        $_.ToString("D")
    } | Sort-Object)
    $actualVirtualSystemIdentifiers = if ($support.Count -eq 1) {
        @($support[0].VirtualSystemIdentifiers | ForEach-Object {
            (ConvertTo-CanonicalGuid -Value $_ -Label "support VM adapter identifier")
        } | Sort-Object)
    } else {
        @()
    }
    $switchVmAttachments = @(Get-VMNetworkAdapter -All -ErrorAction Stop | Where-Object {
        $_.SwitchId -eq $SupportSwitchId -and $_.IsManagementOs -ne $true
    })
    if ($adapters.Count -ne 2 -or $support.Count -ne 1 -or
        $expectedVirtualSystemIdentifiers.Count -ne 2 -or
        ($expectedVirtualSystemIdentifiers | Select-Object -Unique).Count -ne 2 -or
        ($actualVirtualSystemIdentifiers -join "|") -cne
            ($expectedVirtualSystemIdentifiers -join "|") -or
        $switchVmAttachments.Count -ne 1 -or
        [string]$switchVmAttachments[0].Id -ine $SupportAdapterId -or
        [string]$support[0].Name -cne [string]$Plan.support.vm_adapter_name -or
        $support[0].SwitchId -ne $SupportSwitchId -or
        [string]$support[0].SwitchName -cne [string]$Plan.support.switch_name -or
        (ConvertTo-CanonicalMacAddress -Value ([string]$support[0].MacAddress) `
            -Label "support VM adapter") -cne
            (ConvertTo-CanonicalMacAddress -Value ([string]$Plan.support.vm_mac_address) `
                -Label "planned support VM adapter") -or
        $support[0].DynamicMacAddressEnabled -ne $false -or
        $support[0].Connected -ne $true -or [string]$management.Id -ieq $SupportAdapterId) {
        throw "support VM adapter contract is invalid"
    }
    return $support[0]
}

function Invoke-GuestSupportNetwork {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)]
        [ValidateSet("initial_configure", "post_checkpoint_restore")]
        [string]$Phase,
        [switch]$Configure
    )

    $result = @(Invoke-Command -Session $Session -ErrorAction Stop -ArgumentList @(
        [string]$Plan.management_adapter.mac_address,
        [string]$Plan.support.vm_mac_address,
        [string]$Plan.support.guest_interface_alias,
        [string]$Plan.support.guest_ipv4,
        [int]$Plan.support.prefix_length,
        [string]$Plan.support.network,
        [string]$Plan.support.host_ipv4,
        $Phase,
        [bool]$Configure
    ) -ScriptBlock {
        param(
            [string]$ManagementMac,
            [string]$SupportMac,
            [string]$SupportAlias,
            [string]$GuestIpv4,
            [int]$PrefixLength,
            [string]$Network,
            [string]$HostIpv4,
            [string]$ValidationPhase,
            [bool]$ShouldConfigure
        )

        function ConvertTo-GuestCanonicalMac {
            param([string]$Value)
            return ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        }

        function Get-GuestIpv4AddressRow {
            param(
                [int]$InterfaceIndex,
                [ValidateSet("ActiveStore", "PersistentStore")]
                [string]$PolicyStore
            )

            try {
                return @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
                    -PolicyStore $PolicyStore -ErrorAction Stop)
            } catch {
                if ($_.CategoryInfo.Category -eq
                        [Management.Automation.ErrorCategory]::ObjectNotFound -and
                    [string]$_.FullyQualifiedErrorId -like
                        "CmdletizationQuery_NotFound*,Get-NetIPAddress") {
                    return @()
                }
                throw
            }
        }

        function Get-GuestIpv4RouteRow {
            param(
                [int]$InterfaceIndex,
                [ValidateSet("ActiveStore", "PersistentStore")]
                [string]$PolicyStore,
                [string]$DestinationPrefix
            )

            $parameters = @{
                InterfaceIndex = $InterfaceIndex
                AddressFamily = "IPv4"
                PolicyStore = $PolicyStore
                ErrorAction = "Stop"
            }
            if (-not [string]::IsNullOrWhiteSpace($DestinationPrefix)) {
                $parameters.DestinationPrefix = $DestinationPrefix
            }
            try {
                return @(Get-NetRoute @parameters)
            } catch {
                if ($_.CategoryInfo.Category -eq
                        [Management.Automation.ErrorCategory]::ObjectNotFound -and
                    [string]$_.FullyQualifiedErrorId -like
                        "CmdletizationQuery_NotFound*,Get-NetRoute") {
                    return @()
                }
                throw
            }
        }

        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        $management = @($adapters | Where-Object {
            (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $ManagementMac
        })
        $support = @($adapters | Where-Object {
            (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $SupportMac
        })
        if ($management.Count -ne 1 -or $support.Count -ne 1 -or
            [int]$management[0].ifIndex -eq [int]$support[0].ifIndex) {
            throw "guest Hyper-V NIC identities are not unique"
        }

        if ($ShouldConfigure) {
            $aliasCollisions = @($adapters | Where-Object {
                [string]$_.Name -ieq $SupportAlias -and
                [int]$_.ifIndex -ne [int]$support[0].ifIndex
            })
            if ($aliasCollisions.Count -ne 0) {
                throw "guest support interface alias already belongs to another adapter"
            }
            if ([string]$support[0].Name -cne $SupportAlias) {
                $support[0] | Rename-NetAdapter -NewName $SupportAlias -Confirm:$false `
                    -ErrorAction Stop | Out-Null
            }
            $support = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $SupportMac
            })
            if ($support.Count -ne 1 -or [string]$support[0].Name -cne $SupportAlias) {
                throw "guest support interface rename lost the pinned MAC identity"
            }
            $supportIndex = [int]$support[0].ifIndex
            Set-NetIPInterface -InterfaceIndex $supportIndex -AddressFamily IPv4 `
                -PolicyStore ActiveStore -Dhcp Disabled -IgnoreDefaultRoutes Enabled `
                -ErrorAction Stop | Out-Null
            Set-NetIPInterface -InterfaceIndex $supportIndex -AddressFamily IPv4 `
                -PolicyStore PersistentStore -IgnoreDefaultRoutes Enabled `
                -ErrorAction Stop | Out-Null
            foreach ($store in @("ActiveStore", "PersistentStore")) {
                foreach ($route in @(Get-GuestIpv4RouteRow `
                        -InterfaceIndex $supportIndex -PolicyStore $store `
                        -DestinationPrefix "0.0.0.0/0")) {
                    $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                }
            }
            foreach ($store in @("ActiveStore", "PersistentStore")) {
                foreach ($address in @(Get-GuestIpv4AddressRow `
                        -InterfaceIndex $supportIndex -PolicyStore $store)) {
                    $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                }
            }
            Set-DnsClientServerAddress -InterfaceIndex $supportIndex -ResetServerAddresses `
                -ErrorAction Stop | Out-Null
            $netshPath = Join-Path $env:SystemRoot "System32\netsh.exe"
            if (-not (Test-Path -LiteralPath $netshPath -PathType Leaf)) {
                throw "netsh.exe is unavailable for guest support DNS cleanup"
            }
            foreach ($addressFamily in @("ipv4", "ipv6")) {
                $dnsClearOutput = @(& $netshPath interface $addressFamily set dnsservers `
                    "name=$supportIndex" "source=static" "address=none" `
                    "register=none" "validate=no" 2>&1)
                if ($LASTEXITCODE -ne 0) {
                    throw "guest support $addressFamily DNS cleanup failed with exit " +
                        "$LASTEXITCODE`: $($dnsClearOutput -join ' ')"
                }
            }
            Set-DnsClient -InterfaceIndex $supportIndex `
                -RegisterThisConnectionsAddress:$false -UseSuffixWhenRegistering:$false `
                -ErrorAction Stop | Out-Null
            New-NetIPAddress -InterfaceIndex $supportIndex -IPAddress $GuestIpv4 `
                -PrefixLength ([byte]$PrefixLength) -AddressFamily IPv4 -Type Unicast `
                -ErrorAction Stop | Out-Null
        }

        $support = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $SupportMac
        })
        $management = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            (ConvertTo-GuestCanonicalMac -Value ([string]$_.MacAddress)) -ceq $ManagementMac
        })
        if ($support.Count -ne 1 -or $management.Count -ne 1 -or
            [string]$support[0].Name -cne $SupportAlias -or
            [string]$support[0].Status -cne "Up" -or
            [string]$management[0].Status -cne "Up") {
            throw "guest NIC identities or link state changed during support configuration"
        }
        $supportIndex = [int]$support[0].ifIndex
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $addresses = @(Get-GuestIpv4AddressRow -InterfaceIndex $supportIndex `
                -PolicyStore ActiveStore)
            $expectedAddresses = @($addresses | Where-Object {
                [string]$_.IPAddress -ceq $GuestIpv4 -and [int]$_.PrefixLength -eq $PrefixLength -and
                [string]$_.AddressState -ceq "Preferred"
            })
            if ($addresses.Count -eq 1 -and $expectedAddresses.Count -eq 1) {
                break
            }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($addresses.Count -ne 1 -or $expectedAddresses.Count -ne 1) {
            throw "guest support interface does not have the exact preferred /30 address"
        }
        $persistentAddresses = @(Get-GuestIpv4AddressRow -InterfaceIndex $supportIndex `
            -PolicyStore PersistentStore)
        $expectedPersistentAddresses = @($persistentAddresses | Where-Object {
            [string]$_.IPAddress -ceq $GuestIpv4 -and [int]$_.PrefixLength -eq $PrefixLength
        })
        if ($persistentAddresses.Count -ne 1 -or $expectedPersistentAddresses.Count -ne 1) {
            throw "guest support /30 address is not uniquely persistent"
        }

        $ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $supportIndex `
            -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
        $persistentIpInterfaces = @(Get-NetIPInterface -InterfaceIndex $supportIndex `
            -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction Stop)
        $directRoutes = @(Get-GuestIpv4RouteRow -InterfaceIndex $supportIndex `
            -PolicyStore ActiveStore -DestinationPrefix $Network | Where-Object {
            [string]$_.NextHop -ceq "0.0.0.0"
        })
        $allRoutes = @(
            Get-GuestIpv4RouteRow -InterfaceIndex $supportIndex -PolicyStore ActiveStore
            Get-GuestIpv4RouteRow -InterfaceIndex $supportIndex -PolicyStore PersistentStore
        )
        $defaultRoutes = @($allRoutes | Where-Object {
            [string]$_.DestinationPrefix -ceq "0.0.0.0/0"
        })
        $gatewayRoutes = @($allRoutes | Where-Object {
            [string]$_.NextHop -cne "0.0.0.0"
        })
        $ipv4DnsServers = @(
            Get-DnsClientServerAddress -InterfaceIndex $supportIndex `
                -AddressFamily IPv4 -ErrorAction Stop |
                ForEach-Object { @($_.ServerAddresses) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ } |
                Sort-Object
        )
        $ipv6DnsServers = @(
            Get-DnsClientServerAddress -InterfaceIndex $supportIndex `
                -AddressFamily IPv6 -ErrorAction Stop |
                ForEach-Object { @($_.ServerAddresses) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ } |
                Sort-Object
        )
        $windowsIntrinsicIpv6Dns = @(
            "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
        )
        $dnsStateValid = $ipv4DnsServers.Count -eq 0 -and
            ($ipv6DnsServers.Count -eq 0 -or
                ($ipv6DnsServers -join "|") -ieq ($windowsIntrinsicIpv6Dns -join "|"))
        $selection = @(Find-NetRoute -RemoteIPAddress $HostIpv4 -ErrorAction Stop)
        $sourceRows = @($selection | Where-Object {
            $null -ne $_.PSObject.Properties["IPAddress"]
        })
        $routeRows = @($selection | Where-Object {
            $null -ne $_.PSObject.Properties["DestinationPrefix"]
        })
        $activeInterfaceValid = $ipInterfaces.Count -eq 1 -and
            [string]$ipInterfaces[0].Dhcp -ceq "Disabled" -and
            [string]$ipInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled" -and
            [int]$ipInterfaces[0].NlMtu -ge 1468
        $persistentInterfaceValid = $persistentIpInterfaces.Count -eq 1 -and
            [string]$persistentIpInterfaces[0].IgnoreDefaultRoutes -ceq "Enabled"
        $sourceSelectionValid = $sourceRows.Count -eq 1 -and
            [string]$sourceRows[0].IPAddress -ceq $GuestIpv4 -and
            [int]$sourceRows[0].InterfaceIndex -eq $supportIndex
        $routeSelectionValid = $routeRows.Count -eq 1 -and
            [string]$routeRows[0].DestinationPrefix -ceq $Network -and
            [string]$routeRows[0].NextHop -ceq "0.0.0.0" -and
            [int]$routeRows[0].InterfaceIndex -eq $supportIndex
        $violations = @(
            if (-not $activeInterfaceValid) { "active_interface" }
            if (-not $persistentInterfaceValid) { "persistent_interface" }
            if ($directRoutes.Count -ne 1) { "direct_route_count=$($directRoutes.Count)" }
            if ($defaultRoutes.Count -ne 0) { "default_route_count=$($defaultRoutes.Count)" }
            if ($gatewayRoutes.Count -ne 0) { "gateway_route_count=$($gatewayRoutes.Count)" }
            if (-not $dnsStateValid) {
                "dns_state=ipv4:$($ipv4DnsServers.Count),ipv6:$($ipv6DnsServers.Count)"
            }
            if (-not $sourceSelectionValid) { "source_selection" }
            if (-not $routeSelectionValid) { "route_selection" }
        )
        if ($violations.Count -ne 0) {
            throw "guest support route, DNS, DHCP, MTU, or source-selection contract is invalid " +
                "($ValidationPhase): $($violations -join ',')"
        }

        [pscustomobject][ordered]@{
            schema = 1
            management_interface_alias = [string]$management[0].Name
            management_interface_guid = ([Guid][string]$management[0].InterfaceGuid).ToString("D")
            management_interface_index = [int]$management[0].ifIndex
            management_mac_address = $ManagementMac
            support_interface_alias = [string]$support[0].Name
            support_interface_guid = ([Guid][string]$support[0].InterfaceGuid).ToString("D")
            support_interface_index = $supportIndex
            support_mac_address = $SupportMac
            guest_ipv4 = [string]$expectedAddresses[0].IPAddress
            prefix_length = [int]$expectedAddresses[0].PrefixLength
            network = $Network
            gateway = $null
            dns_servers = @()
            mtu_bytes = [int]$ipInterfaces[0].NlMtu
            selected_source_ipv4 = [string]$sourceRows[0].IPAddress
            selected_route_prefix = [string]$routeRows[0].DestinationPrefix
            selected_route_next_hop = [string]$routeRows[0].NextHop
        }
    })
    if ($result.Count -ne 1 -or [int]$result[0].schema -ne 1) {
        throw "guest support topology probe returned an invalid result"
    }
    return $result[0]
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
