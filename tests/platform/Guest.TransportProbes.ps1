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
    foreach ($attempt in 1..3) {
        $client = Open-TunUdp $Address $Port $InterfaceIndex
        try {
            [void]$client.Send($Payload, $Payload.Length)
            $echo = Receive-TunUdp $client 2000
            Assert-True (($echo -join ",") -eq ($Payload -join ",")) `
                "manual TUN UDP echo mismatch"
            return
        } catch {
            if ($attempt -eq 3 -or
                $_.Exception.Message -cne "TUN UDP response timeout") {
                throw
            }
        } finally { $client.Dispose() }
        Start-Sleep -Milliseconds 50
    }
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
