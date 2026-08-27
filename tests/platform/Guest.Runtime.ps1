function Get-PeExportNames([byte[]]$Bytes) {
    Assert-True ($Bytes.Length -ge 64) "PE image is truncated"
    $stream = [IO.MemoryStream]::new($Bytes, $false)
    $reader = [Reflection.PortableExecutable.PEReader]::new($stream)
    try {
        $peHeader = $reader.PEHeaders.PEHeader
        Assert-True ($null -ne $peHeader) "PE optional header is missing"
        $directory = $peHeader.ExportTableDirectory
        Assert-True ($directory.RelativeVirtualAddress -gt 0 -and $directory.Size -ge 40) "PE export directory is missing"
        $directoryBlock = $reader.GetSectionData($directory.RelativeVirtualAddress)
        Assert-True ($directoryBlock.Length -ge 40) "PE export directory is truncated"
        [byte[]]$directoryBytes = $directoryBlock.GetContent(0, 40)
        [uint32]$functionCount = [BitConverter]::ToUInt32($directoryBytes, 20)
        [uint32]$nameCount = [BitConverter]::ToUInt32($directoryBytes, 24)
        Assert-True ($functionCount -eq $nameCount -and $nameCount -ge 1 -and $nameCount -le 256) "PE export count is invalid"
        [uint32]$nameTableRva = [BitConverter]::ToUInt32($directoryBytes, 32)
        Assert-True ($nameTableRva -gt 0 -and $nameTableRva -le [int]::MaxValue) "PE export name table RVA is invalid"
        $nameTableLength = [int]$nameCount * 4
        $nameTableBlock = $reader.GetSectionData([int]$nameTableRva)
        Assert-True ($nameTableBlock.Length -ge $nameTableLength) "PE export name table is truncated"
        [byte[]]$nameTableBytes = $nameTableBlock.GetContent(0, $nameTableLength)
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $names = [Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt [int]$nameCount; $index++) {
            [uint32]$nameRva = [BitConverter]::ToUInt32($nameTableBytes, $index * 4)
            Assert-True ($nameRva -gt 0 -and $nameRva -le [int]::MaxValue) "PE export name RVA is invalid"
            $nameBlock = $reader.GetSectionData([int]$nameRva)
            $boundedLength = [Math]::Min(257, $nameBlock.Length)
            Assert-True ($boundedLength -ge 2) "PE export name is truncated"
            [byte[]]$nameBytes = $nameBlock.GetContent(0, $boundedLength)
            $terminator = [Array]::IndexOf($nameBytes, [byte]0)
            Assert-True ($terminator -ge 1 -and $terminator -le 256) "PE export name is not bounded"
            $names.Add($utf8.GetString($nameBytes, 0, $terminator))
        }
        $sorted = @($names | Sort-Object -Unique)
        Assert-True ($sorted.Count -eq [int]$nameCount) "PE export names are not unique"
        return $sorted
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Wait-AdapterReady(
    [string]$Name,
    [int]$TimeoutSeconds = 20,
    [bool]$Managed = $false,
    [bool]$ManagedDns = $false,
    [string[]]$ManagedCapturePrefixes = @("0.0.0.0/1", "128.0.0.0/1")
) {
    $expectedCapturePrefixes = @($ManagedCapturePrefixes | Sort-Object -Unique)
    if ($Managed) {
        Assert-True ($expectedCapturePrefixes.Count -ge 1 -and
            $expectedCapturePrefixes.Count -eq $ManagedCapturePrefixes.Count -and
            @($expectedCapturePrefixes | Where-Object {
                [string]::IsNullOrWhiteSpace($_)
            }).Count -eq 0) "managed state readiness capture prefix contract is invalid"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
        }
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $v4 = @($addresses | Where-Object { $_.IPAddress -eq "198.18.0.2" -and $_.PrefixLength -eq 30 -and $_.AddressState -eq "Preferred" })
            $v6 = @($addresses | Where-Object { $_.IPAddress -eq "fd00::2" -and $_.PrefixLength -eq 126 -and $_.AddressState -eq "Preferred" })
            if ($v4.Count -eq 1 -and $v6.Count -eq 1) {
                if (-not $Managed) { return $adapter }
                $capturePrefixes = @(
                    Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                        Where-Object { $expectedCapturePrefixes -ccontains [string]$_.DestinationPrefix } |
                        Sort-Object DestinationPrefix |
                        ForEach-Object { $_.DestinationPrefix }
                )
                $dnsReady = -not $ManagedDns
                if ($ManagedDns) {
                    $dnsAddresses = @(Get-TunIpv4Dns $adapter.ifIndex)
                    $dnsReady = ($dnsAddresses -join "|") -ceq "198.18.0.1"
                }
                if (($capturePrefixes -join "|") -ceq ($expectedCapturePrefixes -join "|") -and $dnsReady) {
                    try {
                        $finalCapturePrefixes = @(
                            Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
                                Where-Object { $expectedCapturePrefixes -ccontains [string]$_.DestinationPrefix } |
                                Sort-Object DestinationPrefix |
                                ForEach-Object { $_.DestinationPrefix }
                        )
                        Assert-SnapshotEqual $expectedCapturePrefixes $finalCapturePrefixes "managed state readiness capture"
                        if ($ManagedDns) {
                            $finalDnsAddresses = @(Get-TunIpv4Dns $adapter.ifIndex)
                            Assert-SnapshotEqual @("198.18.0.1") $finalDnsAddresses "managed state readiness DNS"
                        }
                    } catch { throw "managed state readiness readback failed" }
                    if ($script:activeProcess) {
                        $script:activeProcess.Refresh()
                        if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
                    }
                    return $adapter
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($script:activeProcess) {
        $script:activeProcess.Refresh()
        if ($script:activeProcess.HasExited) { throw "candidate failed during prepare" }
    }
    if ($Managed) { throw "managed state readiness timeout" }
    throw "adapter readiness timeout"
}

function Wait-AdapterAbsent([string]$Name, [int]$TimeoutSeconds = 20, [int]$RequiredSamples = 4) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSamples = 0
    do {
        $absent = $false
        try {
            $absent = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                Where-Object { $_.Name -ceq $Name }).Count -eq 0 -and
                @(Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop |
                    Where-Object { $_.PNPDeviceID -like 'SWD\Wintun\*' }).Count -eq 0
        } catch { $absent = $false }
        if ($absent) { $stableSamples++ }
        else { $stableSamples = 0 }
        if ($stableSamples -ge $RequiredSamples) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "adapter cleanup timeout"
}

function Assert-SnapshotEqual([object[]]$Expected, [object[]]$Actual, [string]$Label) {
    $difference = @(Compare-Object -ReferenceObject @($Expected) -DifferenceObject @($Actual))
    Assert-True ($difference.Count -eq 0) "$Label snapshot changed"
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Server.ExclusiveAddressUse = $true
    $listener.Start()
    $udp = $null
    try {
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $udp.Client.ExclusiveAddressUse = $true
        $udp.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $port))
        return $port
    } finally {
        if ($udp) { $udp.Dispose() }
        $listener.Stop()
    }
}

function Get-UniqueTcpPort {
    do { $port = Get-FreeTcpPort } while (-not $script:usedTcpPorts.Add($port))
    return $port
}

function Get-Metrics([int]$Port, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try { return (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/metrics" -TimeoutSec 1).Content }
        catch {
            if ($script:activeProcess) {
                $script:activeProcess.Refresh()
                if ($script:activeProcess.HasExited) { throw "candidate failed before metrics became ready" }
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "metrics readiness timeout"
}

function Get-ClientGaugeValue([string]$Metrics, [string]$Name) {
    $match = [regex]::Match($Metrics, "(?m)^$([regex]::Escape($Name))\{role=`"client`"\} ([0-9]+)$")
    Assert-True $match.Success "missing client gauge: $Name"
    return [uint64]$match.Groups[1].Value
}

function Assert-InterfaceGone([string]$Name, [Nullable[int]]$InterfaceIndex) {
    Assert-True (-not (Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction SilentlyContinue)) "adapter leaked"
    Assert-True (@(Get-NetIPAddress -InterfaceAlias $Name -ErrorAction SilentlyContinue).Count -eq 0) "address rows leaked"
    Assert-True (@(Get-NetRoute -InterfaceAlias $Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route rows leaked"
    if ($null -ne $InterfaceIndex) {
        Assert-True (@(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "address owner leaked"
        Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "route owner leaked"
    }
}

function Wait-ProcessExit([System.Diagnostics.Process]$Process, [int]$TimeoutSeconds) {
    return [Ferrum2ProcessGroup]::Wait([uint32]$Process.Id, [uint32]($TimeoutSeconds * 1000))
}

function Start-Candidate([string]$Executable, [string]$Configuration) {
    $arguments = "--config `"$Configuration`""
    $id = [Ferrum2ProcessGroup]::Start(
        $Executable,
        $arguments,
        (Split-Path -Parent $Executable),
        $null,
        $null
    )
    return Get-Process -Id $id
}

function Stop-Candidate([System.Diagnostics.Process]$Process) {
    if ($Process.HasExited) { throw "candidate stopped before controller shutdown" }
    Assert-True ([Ferrum2ProcessGroup]::Break([uint32]$Process.Id)) "CTRL_BREAK delivery failed"
    Assert-True (Wait-ProcessExit $Process 20) "candidate did not exit"
    $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
    Assert-True ($exitCode -eq 0) "candidate shutdown failed: exit=$exitCode"
    [Ferrum2ProcessGroup]::Close([uint32]$Process.Id)
}

function Wait-TcpListener(
    [int]$Port,
    [System.Diagnostics.Process]$Process,
    [string]$Label,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $foreignListenerPids = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
            throw "TCP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
        }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
        if (@($listeners | Where-Object { [uint32]$_.OwningProcess -eq [uint32]$Process.Id }).Count -gt 0) {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                return
            }
        }
        $foreignListenerPids = @($listeners |
            Where-Object { [uint32]$_.OwningProcess -ne [uint32]$Process.Id } |
            ForEach-Object { [uint32]$_.OwningProcess } |
            Sort-Object -Unique)
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    $Process.Refresh()
    if ($Process.HasExited) {
        $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
        throw "TCP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
    }
    $foreignText = if ($foreignListenerPids.Count -eq 0) { "none" } else { $foreignListenerPids -join "," }
    throw "TCP listener readiness timeout: label=$Label port=$Port expected_pid=$($Process.Id) foreign_listener_pids=$foreignText"
}

function Wait-UdpListener(
    [int]$Port,
    [System.Diagnostics.Process]$Process,
    [string]$Label,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSamples = 0
    $foreignListenerPids = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            $exitCode = [Ferrum2ProcessGroup]::ExitCode([uint32]$Process.Id)
            throw "UDP listener process exited before readiness: label=$Label port=$Port pid=$($Process.Id) exit=$exitCode"
        }
        $listeners = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue)
        $owned = @($listeners | Where-Object {
            $_.LocalAddress -ceq "127.0.0.1" -and [uint32]$_.OwningProcess -eq [uint32]$Process.Id
        })
        if ($owned.Count -eq 1) {
            $stableSamples++
            if ($stableSamples -ge 2) {
                $Process.Refresh()
                if (-not $Process.HasExited) { return }
            }
        } else {
            $stableSamples = 0
        }
        $foreignListenerPids = @($listeners |
            Where-Object { [uint32]$_.OwningProcess -ne [uint32]$Process.Id } |
            ForEach-Object { [uint32]$_.OwningProcess } |
            Sort-Object -Unique)
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    $foreignText = if ($foreignListenerPids.Count -eq 0) { "none" } else { $foreignListenerPids -join "," }
    throw "UDP listener readiness timeout: label=$Label port=$Port expected_pid=$($Process.Id) foreign_listener_pids=$foreignText"
}

function Add-TunRoute([int]$InterfaceIndex, [string]$DestinationPrefix, [int]$RouteMetric = 1) {
    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "controller route baseline not absent"
    $nextHop = if ($DestinationPrefix.Contains(":")) { "::" } else { "0.0.0.0" }
    $route = New-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -NextHop $nextHop -RouteMetric $RouteMetric -PolicyStore ActiveStore
    $script:ownedRoutes.Add($route)
    return $route
}

function Add-TargetAddress([string]$Address, [bool]$SkipAsSource = $true) {
    Assert-True (@(Get-NetIPAddress -IPAddress $Address -ErrorAction SilentlyContinue).Count -eq 0) "target address baseline not absent"
    $prefix = if ($Address.Contains(":")) { 128 } else { 32 }
    $prefixText = "$Address/$prefix"
    Assert-True (@(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "target route baseline not absent"
    Add-Content -LiteralPath $script:addressJournal -Value $Address -Encoding utf8
    $row = New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore ActiveStore
    $script:ownedAddresses.Add($row)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $current = Get-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -ErrorAction SilentlyContinue
        if ($current -and $current.AddressState -eq "Preferred") { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-True ($current -and $current.AddressState -eq "Preferred") "controller target address readiness timeout"
    $localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if (-not $localRoute) {
        $nextHop = if ($Address.Contains(":")) { "::" } else { "0.0.0.0" }
        $localRoute = New-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -NextHop $nextHop -RouteMetric 1 -PolicyStore ActiveStore
    } else {
        $localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru
    }
    $script:ownedTargetRoutes.Add($localRoute)
    return $row
}
