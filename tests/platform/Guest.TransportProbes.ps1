function Invoke-ProductPinnedRow([scriptblock]$Action, [string]$Failure) {
    $before = Get-PktMonFlowPackets
    & $Action
    Start-Sleep -Milliseconds 500
    $delta = Get-PktMonFlowPacketDelta -Before $before
    Assert-True ($delta -eq 0) $Failure
    return $delta
}

function Stop-CapabilityPktMon {
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    if ($script:pktmonStarted -or $script:pktmonStartAttempted) {
        try {
            [void](Invoke-PktMon @("stop"))
            $script:pktmonStarted = $false
            $script:pktmonStartAttempted = $false
        } catch { $cleanupFailures.Add("stop") }
    }
    if ($script:pktmonTcpFilterOwned -or $script:pktmonUdpFilterOwned) {
        try {
            [void](Invoke-PktMon @("filter", "remove"))
            $script:pktmonTcpFilterOwned = $false
            $script:pktmonUdpFilterOwned = $false
        } catch { $cleanupFailures.Add("filters") }
        try { [void](Invoke-PktMon @("reset")) }
        catch { $cleanupFailures.Add("reset") }
    }
    try { Assert-PktMonAbsent }
    catch { $cleanupFailures.Add("absence") }
    Assert-True ($cleanupFailures.Count -eq 0) "PktMon cleanup failed"
}

function Invoke-UnpinnedTcpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connected = $client.ConnectAsync($Address, $Port)
        if ($connected.Wait(1500) -and -not $connected.IsFaulted) {
            $stream = $client.GetStream()
            $stream.Write($Payload, 0, $Payload.Length)
            $read = [byte[]]::new($Payload.Length)
            $response = $stream.ReadAsync($read, 0, $read.Length)
            if ($response.Wait(750) -and -not $response.IsFaulted -and $response.Result -gt 0 -and
                (($read[0..($response.Result - 1)] -join ",") -eq ($Payload[0..($response.Result - 1)] -join ","))) {
                throw "unpinned TCP reached the support listener"
            }
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-UnpinnedUdpCapture([string]$Address, [int]$Port, [int]$MetricsPort, [byte[]]$Payload) {
    $before = Get-TunAccepted $MetricsPort
    $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Connect($Address, $Port)
        [void]$client.Send($Payload, $Payload.Length)
        $response = $client.ReceiveAsync()
        if ($response.Wait(750) -and -not $response.IsFaulted -and
            (($response.Result.Buffer -join ",") -eq ($Payload -join ","))) {
            throw "unpinned UDP reached the support listener"
        }
    } catch [AggregateException] {
        if ($_.Exception.Flatten().InnerExceptions | Where-Object { $_ -isnot [Net.Sockets.SocketException] -and $_ -isnot [IO.IOException] }) { throw }
    } catch [Net.Sockets.SocketException] { } catch [IO.IOException] { }
    finally { $client.Dispose() }
    [void](Wait-TunAcceptedAfter $MetricsPort $before)
}

function Invoke-SystemDnsWitness([string]$Name, [bool]$TcpOnly) {
    Clear-DnsClientCache -ErrorAction Stop
    $parameters = @{ Name = $Name; Type = "A"; DnsOnly = $true; NoHostsFile = $true; ErrorAction = "Stop" }
    if ($TcpOnly) { $parameters.TcpOnly = $true }
    $answer = @(Resolve-DnsName @parameters | Where-Object { $_.Type -eq "A" -and $_.IPAddress -eq "192.0.2.55" })
    Assert-True ($answer.Count -eq 1) "Windows resolver did not return one unique capability answer"
}

function Open-TunTcp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.TcpClient]::new($family)
    $client.NoDelay = $true
    $client.SendBufferSize = 4096
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $connected = $client.ConnectAsync($Address, $Port)
    Assert-True ($connected.Wait(5000)) "TUN TCP local handshake timeout"
    if ($connected.IsFaulted) { throw "TUN TCP local handshake failed" }
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN TCP source bind mismatch"
    return [pscustomobject]@{ Client = $client }
}

function Read-StreamToEnd([Net.Sockets.NetworkStream]$Stream) {
    $Stream.ReadTimeout = 5000
    $output = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(4096)
        do {
            $count = $Stream.Read($buffer, 0, $buffer.Length)
            if ($count -gt 0) { $output.Write($buffer, 0, $count) }
        } while ($count -gt 0)
        return $output.ToArray()
    } finally { $output.Dispose() }
}

function Read-ExactBytes([Net.Sockets.NetworkStream]$Stream, [int]$Length) {
    $Stream.ReadTimeout = 5000
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        Assert-True ($count -gt 0) "stream ended before exact frame"
        $offset += $count
    }
    return $bytes
}

function Invoke-EchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate]$Gate,
    [byte[]]$Payload,
    [hashtable]$Observation = $null
) {
    $expectedGate = $Gate.Accepted + 1
    if ($null -ne $Observation) {
        $Observation.Gate = $Gate
        $Observation.GateIndex = $expectedGate
        $Observation.GateAccepted = "no"
        $Observation.Probe = $null
        $Observation.ProbeAccepted = "no"
        $Observation.AppResult = "other"
    }
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        Assert-True ($Gate.WaitAccepted($expectedGate, 5000)) "selected egress gate was not opened"
        if ($null -ne $Observation) { $Observation.GateAccepted = "yes" }
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        $probe = [Ferrum2TcpProbe]::new($Address, $Port, "echo")
        $script:tcpResources.Add($probe)
        if ($null -ne $Observation) { $Observation.Probe = $probe }
        $Gate.Release($expectedGate)
        $probeAccepted = $probe.WaitAccepted(5000)
        if ($null -ne $Observation -and $probeAccepted) { $Observation.ProbeAccepted = "yes" }
        Assert-True $probeAccepted "selected target was not opened"
        $echo = Read-StreamToEnd $stream
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "echo or half-close mismatch"
        Assert-True ($probe.WaitCompleted(5000)) "target half-close did not complete"
        Assert-True ($probe.SessionComplete -eq "yes" -and $probe.Fault -eq "none" -and
            $probe.ReadEof -eq "yes" -and $probe.SendShutdown -eq "yes") "target half-close completed with a fault"
        if ($null -ne $Observation) { $Observation.AppResult = "success" }
    } catch {
        if ($null -ne $Observation) {
            $errorCursor = $_.Exception
            $sawIo = $false
            $appResult = "other"
            for ($depth = 0; $depth -lt 4 -and $errorCursor; $depth++) {
                if ($errorCursor -is [Net.Sockets.SocketException] -and
                    $errorCursor.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset) { $appResult = "reset"; break }
                if ($errorCursor -is [IO.IOException]) { $sawIo = $true }
                $errorCursor = $errorCursor.InnerException
            }
            if ($appResult -eq "other" -and $sawIo) { $appResult = "io" }
            $Observation.AppResult = $appResult
        }
        throw
    } finally { $session.Client.Dispose() }
}

function Assert-ResetWithoutEgress(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2TcpGate[]]$Gates
) {
    $counts = @($Gates | ForEach-Object Accepted)
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        $stream = $session.Client.GetStream()
        $stream.ReadTimeout = 5000
        $closed = $false
        try {
            $stream.WriteByte(1)
            $closed = $stream.ReadByte() -eq -1
        } catch [IO.IOException] { $closed = $true }
        Assert-True $closed "terminal flow did not close/reset"
        for ($index = 0; $index -lt $Gates.Count; $index++) {
            Assert-True ($Gates[$index].Accepted -eq $counts[$index]) "terminal flow opened an egress gate"
        }
    } finally {
        $session.Client.Dispose()
    }
}

function New-DnsQuery([uint16]$Id) {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]([byte]($Id -shr 8), [byte]($Id -band 0xff), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in @("query", "tun", "test")) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$encoded.Length)
        $bytes.AddRange($encoded)
    }
    $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
    return $bytes.ToArray()
}

function New-SocksRequest([byte]$Command, [string]$Address, [int]$Port) {
    $parsed = [Net.IPAddress]::Parse($Address)
    Assert-True ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) "SOCKS target family mismatch"
    $request = [Collections.Generic.List[byte]]::new()
    $request.AddRange([byte[]](5, $Command, 0, 1))
    $request.AddRange($parsed.GetAddressBytes())
    $request.Add([byte]($Port -shr 8))
    $request.Add([byte]($Port -band 0xff))
    return $request.ToArray()
}

function Open-ProductSocks([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connected = $client.ConnectAsync([Net.IPAddress]::Loopback, $Port)
        Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "SOCKS control connect failed"
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $greeting = [byte[]](5, 1, 0)
        $stream.Write($greeting, 0, $greeting.Length)
        $response = Read-ExactBytes $stream 2
        Assert-True ($response[0] -eq 5 -and $response[1] -eq 0) "SOCKS greeting failed"
        return [pscustomobject]@{ Client = $client; Stream = $stream }
    } catch {
        $client.Dispose()
        throw
    }
}

function Read-SocksReply([Net.Sockets.NetworkStream]$Stream) {
    $header = Read-ExactBytes $Stream 4
    Assert-True ($header[0] -eq 5 -and $header[2] -eq 0) "SOCKS reply header mismatch"
    $address = switch ($header[3]) {
        1 { [Net.IPAddress]::new((Read-ExactBytes $Stream 4)) }
        3 {
            $length = (Read-ExactBytes $Stream 1)[0]
            Assert-True ($length -gt 0) "SOCKS reply domain is empty"
            [Text.Encoding]::ASCII.GetString((Read-ExactBytes $Stream $length))
        }
        4 { [Net.IPAddress]::new((Read-ExactBytes $Stream 16)) }
        default { throw "SOCKS reply address family mismatch" }
    }
    $portBytes = Read-ExactBytes $Stream 2
    $port = ([int]$portBytes[0] -shl 8) -bor [int]$portBytes[1]
    return [pscustomobject]@{ Reply = [int]$header[1]; Address = $address; Port = $port; Type = [int]$header[3] }
}

function Invoke-ProductSocksTcp(
    [int]$SocksPort,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [bool]$ExpectEcho
) {
    $session = Open-ProductSocks $SocksPort
    try {
        $request = New-SocksRequest 1 $Address $Port
        $session.Stream.Write($request, 0, $request.Length)
        if ($ExpectEcho) {
            $reply = Read-SocksReply $session.Stream
            Assert-True ($reply.Reply -eq 0) "SOCKS direct TCP request failed"
            $session.Stream.Write($Payload, 0, $Payload.Length)
            $session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
            $echo = Read-ExactBytes $session.Stream $Payload.Length
            Assert-True (($echo -join ",") -eq ($Payload -join ",")) "SOCKS direct TCP echo mismatch"
        } else {
            $session.Stream.ReadTimeout = 1500
            try {
                $reply = Read-SocksReply $session.Stream
                if ($reply.Reply -eq 0) { $session.Stream.Write($Payload, 0, $Payload.Length) }
            } catch { }
        }
    } finally { $session.Client.Dispose() }
}

function Invoke-ProductSocksUdp(
    [int]$SocksPort,
    [string]$Address,
    [int]$Port,
    [byte[]]$Payload,
    [bool]$ExpectEcho
) {
    $session = Open-ProductSocks $SocksPort
    $client = $null
    try {
        $request = New-SocksRequest 3 "0.0.0.0" 0
        $session.Stream.Write($request, 0, $request.Length)
        $reply = Read-SocksReply $session.Stream
        Assert-True ($reply.Reply -eq 0 -and $reply.Type -eq 1) "SOCKS UDP association failed"
        $relayAddress = [Net.IPAddress]$reply.Address
        if ($relayAddress.Equals([Net.IPAddress]::Any)) { $relayAddress = [Net.IPAddress]::Loopback }
        Assert-True ([Net.IPAddress]::IsLoopback($relayAddress)) "SOCKS UDP relay was not loopback"
        $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $client.Connect($relayAddress, $reply.Port)
        $datagram = [Collections.Generic.List[byte]]::new()
        $datagram.AddRange([byte[]](0, 0, 0, 1))
        $datagram.AddRange([Net.IPAddress]::Parse($Address).GetAddressBytes())
        $datagram.Add([byte]($Port -shr 8))
        $datagram.Add([byte]($Port -band 0xff))
        $datagram.AddRange($Payload)
        [void]$client.Send($datagram.ToArray(), $datagram.Count)
        $receive = $client.ReceiveAsync()
        if ($ExpectEcho) {
            Assert-True ($receive.Wait(5000) -and -not $receive.IsFaulted) "SOCKS direct UDP response failed"
            $response = $receive.Result.Buffer
            Assert-True ($response.Length -eq $Payload.Length + 10 -and
                $response[0] -eq 0 -and $response[1] -eq 0 -and $response[2] -eq 0 -and $response[3] -eq 1) "SOCKS direct UDP frame mismatch"
            Assert-True (($response[4..7] -join ",") -eq ([Net.IPAddress]::Parse($Address).GetAddressBytes() -join ",") -and
                ((([int]$response[8] -shl 8) -bor [int]$response[9]) -eq $Port) -and
                (($response[10..($response.Length - 1)] -join ",") -eq ($Payload -join ","))) "SOCKS direct UDP echo mismatch"
        } else {
            [void]$receive.Wait(750)
        }
    } finally {
        if ($client) { $client.Dispose() }
        $session.Client.Dispose()
    }
}

function Invoke-ProductDns([int]$ListenPort, [bool]$Tcp, [byte[]]$Query) {
    if ($Tcp) {
        $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $connected = $client.ConnectAsync([Net.IPAddress]::Loopback, $ListenPort)
            Assert-True ($connected.Wait(5000) -and -not $connected.IsFaulted) "local DNS TCP connect failed"
            $stream = $client.GetStream()
            $frame = [byte[]]::new($Query.Length + 2)
            $frame[0] = [byte]($Query.Length -shr 8)
            $frame[1] = [byte]($Query.Length -band 0xff)
            [Array]::Copy($Query, 0, $frame, 2, $Query.Length)
            $stream.Write($frame, 0, $frame.Length)
            Start-Sleep -Milliseconds 500
        } finally { $client.Dispose() }
    } else {
        $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $client.Connect([Net.IPAddress]::Loopback, $ListenPort)
            [void]$client.Send($Query, $Query.Length)
            Start-Sleep -Milliseconds 500
        } finally { $client.Dispose() }
    }
}

function Invoke-TunProductTcp([string]$Address, [int]$Port, [int]$InterfaceIndex, [byte[]]$Payload) {
    $session = Open-TunTcp $Address $Port $InterfaceIndex
    try {
        $stream = $session.Client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        $echo = Read-ExactBytes $stream $Payload.Length
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "manual TUN TCP echo mismatch"
    } finally { $session.Client.Dispose() }
}

function Invoke-TunProductUdp([string]$Address, [int]$Port, [int]$InterfaceIndex, [byte[]]$Payload) {
    $client = Open-TunUdp $Address $Port $InterfaceIndex
    try {
        [void]$client.Send($Payload, $Payload.Length)
        $echo = Receive-TunUdp $client
        Assert-True (($echo -join ",") -eq ($Payload -join ",")) "manual TUN UDP echo mismatch"
    } finally { $client.Dispose() }
}

function Open-TunUdp([string]$Address, [int]$Port, [int]$InterfaceIndex) {
    $isV6 = $Address.Contains(":")
    $family = if ($isV6) { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
    $sourceAddress = if ($isV6) { [Net.IPAddress]::Parse("fd00::2") } else { [Net.IPAddress]::Parse("198.18.0.2") }
    $client = [Net.Sockets.UdpClient]::new($family)
    [Ferrum2NetworkFeasibility]::Pin($client.Client, [uint32]$InterfaceIndex)
    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))
    $client.Connect($Address, $Port)
    $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
    Assert-True ($localEndpoint.Address.Equals($sourceAddress)) "TUN UDP source bind mismatch"
    return $client
}

function Receive-TunUdp([Net.Sockets.UdpClient]$Client, [int]$TimeoutMilliseconds = 5000) {
    $receive = $Client.ReceiveAsync()
    Assert-True ($receive.Wait($TimeoutMilliseconds)) "TUN UDP response timeout"
    if ($receive.IsFaulted) { throw "TUN UDP response failed" }
    return $receive.Result.Buffer
}

function Invoke-UdpEchoRow(
    [string]$Address,
    [int]$Port,
    [int]$InterfaceIndex,
    [Ferrum2UdpGate]$Gate,
    [byte[]]$Payload
) {
    $expectedGate = $Gate.Requests + 1
    $probe = [Ferrum2UdpProbe]::new($Address, $Port)
    $script:tcpResources.Add($probe)
    $client = Open-TunUdp $Address $Port $InterfaceIndex
    try {
        [void]$client.Send($Payload, $Payload.Length)
        Assert-True ($Gate.WaitRequests($expectedGate, 5000)) "selected UDP egress gate was not opened"
        $response = Receive-TunUdp $client
        Assert-True (($response -join ",") -eq ($Payload -join ",")) "UDP echo mismatch"
        Assert-True ($probe.WaitRequests(1, 5000)) "UDP target did not receive datagram"
        Assert-True (($probe.Received -join ",") -eq ($Payload -join ",")) "UDP target payload mismatch"
        Assert-True ($Gate.Fault -eq "none" -and $probe.Fault -eq "none") "UDP witness faulted"
    } finally { $client.Dispose() }
}

function Invoke-AdapterCycles(
    [string]$Executable,
    [string]$Configuration,
    [string]$ExpectedAdapter = $script:adapterName,
    [Nullable[int]]$MetricsPort = $null,
    [bool]$Managed = $false,
    [Nullable[int]]$SocksPort = $null
) {
    if ($Managed) {
        Assert-True ($null -ne $MetricsPort) "managed cycles require metrics port"
        Assert-True ($null -ne $SocksPort) "managed cycles require SOCKS port"
        $configurationTemplate = Get-Content -LiteralPath $Configuration -Raw
    }
    for ($cycle = 0; $cycle -lt 100; $cycle++) {
        $cycleConfiguration = $Configuration
        $cycleMetricsPort = $MetricsPort
        try {
            if ($Managed) {
                $cycleConfiguration = Join-Path $script:work ("client-managed-route-only-cycle-{0:D3}.toml" -f ($cycle + 1))
                Assert-True (-not (Test-Path -LiteralPath $cycleConfiguration)) "managed cycle generated config baseline not absent"
                $cycleSocksPort = Get-UniqueTcpPort
                $cycleMetricsPort = Get-UniqueTcpPort
                $cycleConfigText = $configurationTemplate.Replace("127.0.0.1:$([int]$SocksPort)", "127.0.0.1:$cycleSocksPort").Replace("127.0.0.1:$([int]$MetricsPort)", "127.0.0.1:$cycleMetricsPort")
                Assert-True (-not $cycleConfigText.Contains("127.0.0.1:$([int]$SocksPort)") -and
                    -not $cycleConfigText.Contains("127.0.0.1:$([int]$MetricsPort)")) "managed cycle listener generation mismatch"
                Set-Content -LiteralPath $cycleConfiguration -Value $cycleConfigText -Encoding utf8NoBOM -NoNewline
                $offlineOutput = @(& $Executable --config $cycleConfiguration --check-config 2>&1)
                Assert-True ($LASTEXITCODE -eq 0) "managed cycle generated config validation failed"
                Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "managed cycle generated config marker mismatch"
            }
            Assert-True (-not $script:activeProcess) "cycle candidate state was not empty"
            $candidateBaseline = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
            Assert-True ($candidateBaseline.Count -eq 0) "cycle candidate baseline not absent"
            Assert-InterfaceGone $ExpectedAdapter $null
            $script:activeProcess = Start-Candidate $Executable $cycleConfiguration
            $adapter = Wait-AdapterReady $ExpectedAdapter 20 $Managed
            $script:ownedInterfaceIndex = [int]$adapter.ifIndex
            if ($Managed) {
                $owners = Get-Metrics ([int]$cycleMetricsPort)
                Assert-True ((Get-ClientGaugeValue $owners "ferrum2_udp_sessions_active") -eq 0 -and
                    (Get-ClientGaugeValue $owners "ferrum2_udp_buffered_bytes") -eq 0) "managed cycle process-private owner baseline changed"
            }
            $cycleRoute = Add-TunRoute $script:ownedInterfaceIndex "192.0.2.200/32"
            $cycleRouteReadback = @(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction Stop)
            Assert-True ($cycleRouteReadback.Count -eq 1) "cycle route readback mismatch"
            Remove-NetRoute -InputObject $cycleRoute -Confirm:$false -ErrorAction Stop
            Assert-True $script:ownedRoutes.Remove($cycleRoute) "cycle route ownership mismatch"
            Assert-True (@(Get-NetRoute -InterfaceIndex $script:ownedInterfaceIndex -DestinationPrefix "192.0.2.200/32" -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) "cycle route leaked"
            $cycleProcess = $script:activeProcess
            Stop-Candidate $cycleProcess
            $cycleProcess.Refresh()
            Assert-True $cycleProcess.HasExited "cycle candidate process leaked"
            $script:activeProcess = $null
            $candidateAfterStop = @(Get-ExactRunProcesses $script:work | Where-Object { $_.ExecutablePath -eq $script:binary })
            Assert-True ($candidateAfterStop.Count -eq 0) "cycle candidate remained after stop"
            Wait-AdapterAbsent $ExpectedAdapter 20 11
            Assert-InterfaceGone $ExpectedAdapter $script:ownedInterfaceIndex
            if ($Managed) {
                Assert-True (@(Get-DnsClientServerAddress -InterfaceIndex $script:ownedInterfaceIndex -ErrorAction SilentlyContinue).Count -eq 0) "managed cycle DNS residue"
            }
            $script:cycleRows++
        } catch {
            if ($Managed) { [Console]::Error.WriteLine("managed cycle failure ordinal=$($cycle + 1)") }
            throw
        } finally {
            if ($Managed -and (Test-Path -LiteralPath $cycleConfiguration)) {
                Remove-Item -LiteralPath $cycleConfiguration -Force
            }
            if ($Managed) { Assert-True (-not (Test-Path -LiteralPath $cycleConfiguration)) "managed cycle generated config leaked" }
        }
    }
    Assert-True ($script:cycleRows -eq 100) "adapter cycle count mismatch"
}

function Complete-Tcp08PressureWriteCleanup([Threading.Tasks.Task]$Task) {
    $classification = "completed_after_socket_close"
    $exceptionTypes = @()
    try {
        Assert-True ($Task.Wait(5000)) "TCP-08 pressure writer did not stop within the bounded cleanup timeout"
    } catch [AggregateException] {
        $flattened = $_.Exception.Flatten()
        $exceptions = @($flattened.InnerExceptions)
        $exceptionTypes = @($exceptions | ForEach-Object { $_.GetType().FullName })
        $unexpected = @($exceptions | Where-Object {
            -not ($_ -is [OperationCanceledException]) -and
            -not ($_ -is [ObjectDisposedException]) -and
            -not ($_ -is [IO.IOException]) -and
            -not ($_ -is [Net.Sockets.SocketException])
        })
        if ($unexpected.Count -gt 0) {
            throw [InvalidOperationException]::new(
                "TCP-08 pressure writer faulted with an unexpected exception after socket close",
                $flattened
            )
        }
        $classification = if ($Task.IsCanceled) { "cancelled_after_socket_close" } else { "expected_fault_after_socket_close" }
    }
    Assert-True $Task.IsCompleted "TCP-08 pressure writer did not report a terminal state after bounded cleanup wait"
    return [ordered]@{
        classification = $classification
        task_status = $Task.Status.ToString()
        exception_types = $exceptionTypes
    }
}
