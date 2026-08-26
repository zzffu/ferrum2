    if ($Mode -in @("lifecycle", "full")) {
    $metricsPort = Get-FreeTcpPort
    @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
outbound = "proxy"
ready_timeout_ms = 15000
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "192.0.2.10:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[runtime]
shutdown_grace_ms = 1000
[metrics]
listen = "127.0.0.1:$metricsPort"
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
    Assert-InterfaceGone $adapterName $null
    $offlineOutput = @(& $binary --config $config --check-config 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) "offline config validation failed"
    Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "offline config marker mismatch"
    Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "offline validation touched the DLL seam"
    Assert-InterfaceGone $adapterName $null
    $foundation++

    Write-OwnedSiblingDllIntent
    Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
    $createdSiblingDll = $true
    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $readyAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($readyAddresses -contains "IPv4|198.18.0.2|30|Preferred") "IPv4 address snapshot missing"
    Assert-True ($readyAddresses -contains "IPv6|fd00::2|126|Preferred") "IPv6 address snapshot missing"
    $systemRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedAddressDerivedRoutes = @(
        "IPv4|198.18.0.0/30|0.0.0.0",
        "IPv4|198.18.0.2/32|0.0.0.0",
        "IPv6|fd00::/126|::",
        "IPv6|fd00::2/128|::"
    )
    $addressDerivedRoutes = @($systemRoutes | Where-Object {
        ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or
        ($_ -like "IPv6|fd00::*")
    })
    Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "exact ready address-derived routes"
    $dynamicLinkLocalRoutes = @($systemRoutes | Where-Object { $_ -match '^IPv6\|fe80::.+/128\|::$' })
    Assert-True ($dynamicLinkLocalRoutes.Count -eq 1) "unexpected link-local host route count"
    $expectedAutomaticRoutes = @(
        "IPv4|198.18.0.3/32|0.0.0.0",
        "IPv4|224.0.0.0/4|0.0.0.0",
        "IPv4|255.255.255.255/32|0.0.0.0",
        "IPv6|fe80::/64|::",
        $dynamicLinkLocalRoutes[0],
        "IPv6|ff00::/8|::"
    )
    $automaticRoutes = @($systemRoutes | Where-Object { $expectedAddressDerivedRoutes -notcontains $_ })
    Assert-SnapshotEqual $expectedAutomaticRoutes $automaticRoutes "exact ready automatic routes"
    [void](Add-TunRoute $adapter.ifIndex "192.0.2.200/32")
    [void](Add-TunRoute $adapter.ifIndex "2001:db8::200/128")
    $withControllerRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    $expectedControllerRoutes = @(
        "IPv4|192.0.2.200/32|0.0.0.0",
        "IPv6|2001:db8::200/128|::"
    )
    foreach ($expectedRoute in $expectedControllerRoutes) {
        Assert-True ($withControllerRoutes -contains $expectedRoute) "controller route missing: $expectedRoute"
    }
    Assert-True ($withControllerRoutes.Count -eq $systemRoutes.Count + 2) "unexpected route mutation"
    $udp4 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $udp4.Connect("192.0.2.200", 53)
    $beforeMetrics = Get-Metrics $metricsPort
    $acceptedBefore = Get-CounterValue $beforeMetrics "ferrum2_tun_packets_accepted"
    try {
        [void]$udp4.Send([byte[]](1,2,3,4), 4)
    } finally { $udp4.Dispose(); $udp4 = $null }
    $packetDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $afterMetrics = Get-Metrics $metricsPort
        $acceptedAfter = Get-CounterValue $afterMetrics "ferrum2_tun_packets_accepted"
        $acceptedDelta = $acceptedAfter - $acceptedBefore
        if ($acceptedDelta -gt 0) { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $packetDeadline)
    Assert-True ($acceptedDelta -gt 0) "valid packet did not traverse receive/validation/enqueue"
    $udp6 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    try { [void]$udp6.Send([byte[]](5,6,7,8), 4, "2001:db8::200", 53) }
    finally { $udp6.Dispose() }
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $attempt = $tcp.BeginConnect("192.0.2.200", 443, $null, $null)
        [void]$attempt.AsyncWaitHandle.WaitOne(250)
    } finally { $tcp.Dispose() }
    Start-Sleep -Milliseconds 250
    $activeProcess.Refresh()
    Assert-True (-not $activeProcess.HasExited) "valid packets terminated the required root"
    $foundation++

    foreach ($route in $ownedRoutes) { Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop }
    $ownedRoutes.Clear()
    $afterOwnedRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
    Assert-SnapshotEqual $systemRoutes $afterOwnedRoutes "controller route removal"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex

    $heldMetrics = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $heldMetrics.Start()
    $heldPort = ([Net.IPEndPoint]$heldMetrics.LocalEndpoint).Port
    (Get-Content -LiteralPath $config -Raw).Replace("127.0.0.1:$metricsPort", "127.0.0.1:$heldPort") |
        Set-Content -LiteralPath $failureConfig -Encoding utf8NoBOM
    $activeProcess = Start-Candidate $binary $failureConfig
    Assert-True (Wait-ProcessExit $activeProcess 20) "pre-TUN failure candidate did not exit"
    $failureExit = [Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id)
    Assert-True ($failureExit -ne 0) "pre-TUN failure candidate unexpectedly succeeded"
    [Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)
    $activeProcess = $null
    Assert-InterfaceGone $adapterName $null
    $heldMetrics.Stop()
    $heldMetrics = $null

    $activeProcess = Start-Candidate $binary $config
    $adapter = Wait-AdapterReady $adapterName
    $ownedInterfaceIndex = [int]$adapter.ifIndex
    $reboundAddresses = @(Get-InterfaceAddressSnapshot $ownedInterfaceIndex)
    Assert-True ($reboundAddresses -contains "IPv4|198.18.0.2|30|Preferred") "rebound IPv4 address missing"
    Assert-True ($reboundAddresses -contains "IPv6|fd00::2|126|Preferred") "rebound IPv6 address missing"
    Stop-Candidate $activeProcess
    $activeProcess = $null
    Wait-AdapterAbsent $adapterName
    Assert-InterfaceGone $adapterName $ownedInterfaceIndex
    $foundation++

    Assert-True ($foundation -eq 4) "foundation row count mismatch"
    }
    if ($Mode -eq "cycles") {
        $metricsPort = Get-FreeTcpPort
        @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
outbound = "proxy"
ready_timeout_ms = 15000
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "192.0.2.10:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[runtime]
shutdown_grace_ms = 1000
[metrics]
listen = "127.0.0.1:$metricsPort"
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM
        Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "cycle config validation failed"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "cycle config marker mismatch"
        Write-OwnedSiblingDllIntent
        Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
        $createdSiblingDll = $true
        Invoke-AdapterCycles $binary $config
    }
    if ($Mode -in @("tcp", "tcp08", "udp", "full", "performance")) {
        $serverPortA = Get-UniqueTcpPort
        $serverPortB = Get-UniqueTcpPort
        $gatePortA = Get-UniqueTcpPort
        $gatePortB = Get-UniqueTcpPort
        $deadPort = Get-UniqueTcpPort
        $dnsPort = Get-UniqueTcpPort
        $dnsInboundPort = Get-UniqueTcpPort
        $metricsPort = Get-UniqueTcpPort
        $performanceDirectInbound = ""
        $performanceDirectOutbound = ""
        $performanceDirectRule = ""
        if ($Mode -in @("tcp08", "performance")) {
            $performanceDirectSocksPort = Get-UniqueTcpPort
            $performanceDirectTargetPort = Get-UniqueTcpPort
            $performanceDirectInbound = "[[inbounds]]`ntag = `"performance-direct-socks`"`nlisten = `"127.0.0.1:$performanceDirectSocksPort`"`n"
            $performanceDirectOutbound = "[[outbounds]]`ntag = `"performance-direct`"`ntype = `"direct`"`n"
            $performanceDirectRule = "[[route.rules]]`ninbound = `"performance-direct-socks`"`nnetwork = `"tcp`"`naction = `"route`"`noutbound = `"performance-direct`"`n"
        }
        $ports = 1..8 | ForEach-Object { Get-UniqueTcpPort }
        $ports[4] = 53
        $targets = @(
            "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
            "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208"
        )
        $udpGateAddress = "192.0.2.250"
        if ($tcp08Enabled) {
            Write-Tcp08Metadata $targets[7] $ports[7] $gatePortA $serverPortA $metricsPort
        }
        $serverAConfig = Join-Path $work "server-a.toml"
        $serverBConfig = Join-Path $work "server-b.toml"
        foreach ($serverCase in @(@($serverAConfig, $serverPortA), @($serverBConfig, $serverPortB))) {
            @"
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:$($serverCase[1])"
outbound = "direct"
[[outbounds]]
tag = "direct"
[runtime]
shutdown_grace_ms = 1000
[udp]
enabled = true
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $serverCase[0] -Encoding utf8NoBOM
        }
        $serverProcessA = Start-Server $serverBinary $serverAConfig
        $serverProcessB = Start-Server $serverBinary $serverBConfig
        Wait-TcpListener $serverPortA $serverProcessA "server_a"
        Wait-TcpListener $serverPortB $serverProcessB "server_b"

        $gateA = [Ferrum2TcpGate]::new($gatePortA, $serverPortA)
        $gateB = [Ferrum2TcpGate]::new($gatePortB, $serverPortA)
        $dnsResponder = [Ferrum2DnsResponder]::new($dnsPort)
        $tcpResources.Add($gateA)
        $tcpResources.Add($gateB)
        $tcpResources.Add($dnsResponder)
        if ($Mode -in @("udp", "full", "performance")) {
            [void](Add-TargetAddress $udpGateAddress $false)
            $udpGateA = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortA, $serverPortA)
            $udpGateB = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortB, $serverPortB)
            $tcpResources.Add($udpGateA)
            $tcpResources.Add($udpGateB)
        }

        @"
schema_version = 2
${performanceDirectInbound}[tun]
tag = "tun-in"
adapter_name = "$adapterName"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
ready_timeout_ms = 15000
max_tcp_flows = 8
tcp_buffer_bytes = 4096
ring_capacity = 8388608
max_udp_mappings = 4
[[outbounds]]
tag = "one"
type = "shadowsocks"
server = "127.0.0.1:$gatePortA"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "inner"
type = "shadowsocks"
server = "127.0.0.1:$serverPortB"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "sniff"
type = "shadowsocks"
server = "127.0.0.1:$gatePortB"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "dead"
type = "shadowsocks"
server = "127.0.0.1:$deadPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "fallback"
type = "shadowsocks"
server = "127.0.0.1:$gatePortB"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "udp-one"
type = "shadowsocks"
server = "${udpGateAddress}:$gatePortA"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "udp-inner"
type = "shadowsocks"
server = "${udpGateAddress}:$gatePortB"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
${performanceDirectOutbound}[[chains]]
tag = "two-hop"
hops = ["one", "inner"]
[[chains]]
tag = "udp-two-hop"
hops = ["udp-one", "udp-inner"]
[[selectors]]
tag = "manual"
outbounds = ["dead", "fallback"]
default = "dead"
[[selectors]]
tag = "udp-manual"
outbounds = ["udp-one", "udp-inner"]
default = "udp-one"
[route]
final = "one"
[route.sniff]
timeout_ms = 1000
max_bytes = 8192
${performanceDirectRule}[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "one"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "two-hop"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
action = "sniff"
sniffers = "tls"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[2])"
port = $($ports[2])
protocol = "tls"
domain = "tls.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "http"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "http"
domain = "http.tun.test"
action = "route"
outbound = "sniff"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[4])"
port = $($ports[4])
protocol = "dns"
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "manual"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[0])"
port = $($ports[0])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[1])"
port = $($ports[1])
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[2])"
port = $($ports[2])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "sniff"
sniffers = "dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
protocol = "dns"
action = "route"
outbound = "udp-two-hop"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[3])"
port = $($ports[3])
action = "route"
outbound = "udp-one"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[4])"
port = $($ports[4])
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[5])"
port = $($ports[5])
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[6])"
port = $($ports[6])
action = "route"
outbound = "udp-manual"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "$($targets[7])"
port = $($ports[7])
action = "route"
outbound = "udp-one"
[udp]
enabled = false
max_sessions = 32
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:$dnsInboundPort"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:$dnsPort"
[dns.route]
final = "resolver"
[runtime]
shutdown_grace_ms = 1000
idle_timeout_ms = $runtimeIdleTimeoutMilliseconds
[metrics]
listen = "127.0.0.1:$metricsPort"
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM

        if ($Mode -eq "full") {
            Assert-True ((Get-FileHash -LiteralPath $siblingDll -Algorithm SHA256).Hash -eq $expectedDllHash) "full profile sibling DLL drifted"
        } else {
            Assert-True (-not (Test-Path -LiteralPath $siblingDll)) "sibling DLL baseline not absent"
        }
        Assert-InterfaceGone $adapterName $null
        $offlineOutput = @(& $binary --config $config --check-config 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "TCP config validation failed: $($offlineOutput -join '|')"
        Assert-True (@($offlineOutput | Where-Object { $_ -eq "configuration valid" }).Count -eq 1) "TCP config marker mismatch"
        if ($Mode -ne "full") {
            Write-OwnedSiblingDllIntent
            Copy-Item -LiteralPath $sourceDll -Destination $siblingDll
            $createdSiblingDll = $true
        }
        $activeProcess = Start-Candidate $binary $config
        if ($tcp08Enabled) {
            Add-Tcp08Event "process_started" ([ordered]@{
                process_id = [uint32]$activeProcess.Id
                executable = $binary
            })
        }
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($tcp08Enabled) {
            Add-Tcp08Event "adapter_ready" ([ordered]@{
                name = $adapterName
                interface_index = $ownedInterfaceIndex
            })
        }
        if ($Mode -eq "performance") { Start-PerformanceSample $activeProcess $metricsPort }
        else { [void](Get-Metrics $metricsPort) }
        $readyRoutes = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)
        $expectedAddressDerivedRoutes = @(
            "IPv4|198.18.0.0/30|0.0.0.0", "IPv4|198.18.0.2/32|0.0.0.0",
            "IPv6|fd00::/126|::", "IPv6|fd00::2/128|::"
        )
        $addressDerivedRoutes = @($readyRoutes | Where-Object {
            ($_ -like "IPv4|198.18.0.*" -and $_ -ne "IPv4|198.18.0.3/32|0.0.0.0") -or ($_ -like "IPv6|fd00::*")
        })
        Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes "TCP ready address-derived routes"
        $strongHostInterfaces = @(Get-NetIPInterface -InterfaceIndex @($ownedInterfaceIndex, 1) -PolicyStore ActiveStore -ErrorAction Stop)
        Assert-True ($strongHostInterfaces.Count -eq 4) "strong-host interface rows missing"
        $weakHostInterfaces = @($strongHostInterfaces | Where-Object { $_.WeakHostSend -ne "Disabled" -or $_.WeakHostReceive -ne "Disabled" })
        Assert-True ($weakHostInterfaces.Count -eq 0) "weak-host forwarding is unsupported"
        $routeTargetIndexes = if ($Mode -eq "tcp08") { @(7) } else { @(0..7) }
        foreach ($targetIndex in $routeTargetIndexes) {
            $prefixLength = if ($targets[$targetIndex].Contains(":")) { 128 } else { 32 }
            [void](Add-TunRoute $ownedInterfaceIndex "$($targets[$targetIndex])/$prefixLength" 500)
        }
        $localTargetIndexes = if ($Mode -eq "tcp08") { @(7) } else { @(0, 1, 2, 3, 7) }
        foreach ($targetIndex in $localTargetIndexes) {
            [void](Add-TargetAddress $targets[$targetIndex])
        }

        if ($Mode -eq "tcp08") {
            Invoke-Tcp08 $targets[7] $ports[7] $ownedInterfaceIndex $gateA $gatePortA $serverPortA $metricsPort $false
            $tcpRows++
            Assert-True ($tcpRows -eq 1) "focused TCP-08 row count mismatch"
        } else {
        $tcp01Target = $targets[0]
        $tcp01Port = $ports[0]
        $tcp01Payload = [Text.Encoding]::ASCII.GetBytes("tcp-01-half-close")
        $tcp01Observation = @{ Diagnostic = "pending" }
        $tcp01Error = $null
        if ($Mode -eq "performance") {
            $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
        }
        try {
            Invoke-EchoRow $tcp01Target $tcp01Port $ownedInterfaceIndex $gateA $tcp01Payload $tcp01Observation
        } catch { $tcp01Error = $_ }

        $gateSettled = $false
        if ($tcp01Observation.Gate) {
            $gateSettled = $tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)
        }
        $probeSettled = $false
        if ($tcp01Observation.Probe) {
            $probeSettled = $tcp01Observation.Probe.WaitCompleted(1500)
        }
        $gateObservation = if ($tcp01Observation.Gate) {
            $tcp01Observation.Gate.Observation([int]$tcp01Observation.GateIndex)
        } else { $null }
        $probe = $tcp01Observation.Probe
        $probeRequest = if (-not $probe -or $probe.Received.Length -eq 0) { "none" }
            elseif (($probe.Received -join ",") -eq ($tcp01Payload -join ",")) { "exact" }
            else { "other" }
        $probeEcho = if (-not $probe -or $probe.EchoByteCount -eq 0) { "none" }
            elseif ($probeRequest -eq "exact" -and $probe.EchoByteCount -eq $tcp01Payload.Length) { "exact" }
            else { "other" }
        $tcp01State = @{
            GateAccepted = $tcp01Observation.GateAccepted
            GateForwardBytes = if ($gateObservation) { $gateObservation.ClientToServerBytes } else { "zero" }
            GateForwardStage = if ($gateObservation) { $gateObservation.ClientToServerStage } else { "pending" }
            GateForwardEof = if ($gateObservation) { $gateObservation.ClientToServerEof } else { "no" }
            GateForwardFault = if ($gateObservation) { $gateObservation.ClientToServerFault } else { "other" }
            GateReverseBytes = if ($gateObservation) { $gateObservation.ServerToClientBytes } else { "zero" }
            GateReverseStage = if ($gateObservation) { $gateObservation.ServerToClientStage } else { "pending" }
            GateReverseEof = if ($gateObservation) { $gateObservation.ServerToClientEof } else { "no" }
            GateReverseFault = if ($gateObservation) { $gateObservation.ServerToClientFault } else { "other" }
            GateComplete = if ($gateSettled -and $gateObservation -and $gateObservation.SessionComplete -eq "yes") { "yes" } else { "no" }
            ProbeAccepted = $tcp01Observation.ProbeAccepted
            ProbeRequest = $probeRequest
            ProbeReadEof = if ($probe) { $probe.ReadEof } else { "no" }
            ProbeEcho = $probeEcho
            ProbeShutdown = if ($probe) { $probe.SendShutdown } else { "no" }
            ProbeFault = if ($probe) { $probe.Fault } else { "other" }
            ProbeComplete = if ($probeSettled -and $probe -and $probe.SessionComplete -eq "yes") { "yes" } else { "no" }
            AppResult = $tcp01Observation.AppResult
        }
        $tcp01Boundary = Get-Tcp01Boundary $tcp01State
        if ($tcp01Error -or $tcp01Boundary -ne "COMPLETE") {
            $tcp01Diagnostic = "status=OBSERVED boundary=$tcp01Boundary app=$($tcp01State.AppResult) gate_accepted=$($tcp01State.GateAccepted) gate_c2s_bytes=$($tcp01State.GateForwardBytes) gate_c2s_stage=$($tcp01State.GateForwardStage) gate_c2s_eof=$($tcp01State.GateForwardEof) gate_c2s_fault=$($tcp01State.GateForwardFault) gate_s2c_bytes=$($tcp01State.GateReverseBytes) gate_s2c_stage=$($tcp01State.GateReverseStage) gate_s2c_eof=$($tcp01State.GateReverseEof) gate_s2c_fault=$($tcp01State.GateReverseFault) gate_complete=$($tcp01State.GateComplete) probe_accepted=$($tcp01State.ProbeAccepted) probe_request=$($tcp01State.ProbeRequest) probe_read_eof=$($tcp01State.ProbeReadEof) probe_echo=$($tcp01State.ProbeEcho) probe_shutdown=$($tcp01State.ProbeShutdown) probe_fault=$($tcp01State.ProbeFault) probe_complete=$($tcp01State.ProbeComplete)"
        }
        if ($tcp01Error) { throw $tcp01Error }
        Assert-True ($tcp01Boundary -eq "COMPLETE") "TCP-01 observation incomplete"
        $tcpRows++
        if ($Mode -eq "performance") {
            $performanceWitnesses++
            Update-PerformancePeaks $activeProcess $metricsPort
            $directProbe = [Ferrum2TcpProbe]::new("127.0.0.1", $performanceDirectTargetPort, "echo")
            $tcpResources.Add($directProbe)
            $directGateCounts = @($gateA.Accepted, $gateB.Accepted)
            Invoke-ProductSocksTcp $performanceDirectSocksPort "127.0.0.1" $performanceDirectTargetPort ([Text.Encoding]::ASCII.GetBytes("m16-performance-direct")) $true
            Assert-True ($directProbe.WaitCompleted(5000)) "performance direct target did not complete"
            Assert-True ($gateA.Accepted -eq $directGateCounts[0] -and $gateB.Accepted -eq $directGateCounts[1]) "performance direct row opened Shadowsocks"
            $performanceDirectRows++
            Update-PerformancePeaks $activeProcess $metricsPort
        }
        Invoke-EchoRow $targets[1] $ports[1] $ownedInterfaceIndex $gateA ([Text.Encoding]::ASCII.GetBytes("tcp-02-two-hop"))
        $tcpRows++

        $tlsGate = $gateB.Accepted + 1
        $tls = Open-TunTcp $targets[2] $ports[2] $ownedInterfaceIndex
        $ssl = [Net.Security.SslStream]::new($tls.Client.GetStream(), $false, { $true })
        $sslTask = $ssl.AuthenticateAsClientAsync("tls.tun.test")
        Assert-True ($gateB.WaitAccepted($tlsGate, 5000)) "TLS sniff did not select its exact egress"
        $tlsProbe = [Ferrum2TcpProbe]::new($targets[2], $ports[2], "capture")
        $tcpResources.Add($tlsProbe)
        $gateB.Release($tlsGate)
        Assert-True ($tlsProbe.WaitCompleted(5000)) "TLS replay target did not receive prefix"
        $tlsBytes = $tlsProbe.Received
        Assert-True ($tlsBytes.Length -gt 5 -and $tlsBytes[0] -eq 22) "TLS replay record missing"
        Assert-True ([Text.Encoding]::ASCII.GetString($tlsBytes).Contains("tls.tun.test")) "TLS SNI was not replayed"
        $ssl.Dispose(); $tls.Client.Dispose()
        $tcpRows++

        $httpGate = $gateB.Accepted + 1
        $http = Open-TunTcp $targets[3] $ports[3] $ownedInterfaceIndex
        $httpBytes = [Text.Encoding]::ASCII.GetBytes("GET /tun HTTP/1.1`r`nHost: http.tun.test`r`nConnection: close`r`n`r`n")
        $httpStream = $http.Client.GetStream()
        $httpStream.Write($httpBytes, 0, $httpBytes.Length)
        $http.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        Assert-True ($gateB.WaitAccepted($httpGate, 5000)) "HTTP sniff did not select its exact egress"
        $httpProbe = [Ferrum2TcpProbe]::new($targets[3], $ports[3], "echo")
        $tcpResources.Add($httpProbe)
        $gateB.Release($httpGate)
        Assert-True ($httpProbe.WaitAccepted(5000)) "HTTP replay target was not opened"
        $httpEcho = Read-StreamToEnd $httpStream
        Assert-True (($httpEcho -join ",") -eq ($httpBytes -join ",")) "HTTP prefix was not replayed exactly once"
        $http.Client.Dispose()
        $tcpRows++

        $gateCounts = @($gateA.Accepted, $gateB.Accepted)
        $dnsFlow = Open-TunTcp $targets[4] $ports[4] $ownedInterfaceIndex
        try {
            $dnsStream = $dnsFlow.Client.GetStream()
            foreach ($id in [uint16[]](0x1201, 0x1202)) {
                $query = New-DnsQuery $id
                $frame = [byte[]]::new($query.Length + 2)
                $frame[0] = [byte]($query.Length -shr 8); $frame[1] = [byte]$query.Length
                [Array]::Copy($query, 0, $frame, 2, $query.Length)
                $dnsStream.Write($frame, 0, $frame.Length)
                $length = Read-ExactBytes $dnsStream 2
                $responseLength = ([int]$length[0] -shl 8) -bor $length[1]
                $response = Read-ExactBytes $dnsStream $responseLength
                Assert-True ($response[0] -eq [byte]($id -shr 8) -and $response[1] -eq [byte]($id -band 0xff)) "DNS response ID mismatch"
            }
            Assert-True ($dnsResponder.Requests -eq 2) "DNS hijack did not answer both framed queries"
            Assert-True ($gateA.Accepted -eq $gateCounts[0] -and $gateB.Accepted -eq $gateCounts[1]) "DNS hijack opened Shadowsocks"
        } finally {
            $dnsFlow.Client.Dispose()
        }
        $tcpRows++
        if ($Mode -eq "performance") { $performanceDnsRows++ }

        Assert-ResetWithoutEgress $targets[5] $ports[5] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++
        Assert-ResetWithoutEgress $targets[6] $ports[6] $ownedInterfaceIndex @($gateA, $gateB)
        $tcpRows++

        Invoke-Tcp08 $targets[7] $ports[7] $ownedInterfaceIndex $gateA $gatePortA $serverPortA $metricsPort ($Mode -eq "performance")

        $activeProcess = Start-Candidate $binary $config
        $adapter = Wait-AdapterReady $adapterName
        $ownedInterfaceIndex = [int]$adapter.ifIndex
        if ($Mode -eq "performance") {
            $performanceAdapterChurn++
            Start-PerformanceSample $activeProcess $metricsPort
        }
        if ($Mode -eq "tcp") {
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
        } else {
            foreach ($target in $targets) {
                $prefixLength = if ($target.Contains(":")) { 128 } else { 32 }
                [void](Add-TunRoute $ownedInterfaceIndex "$target/$prefixLength" 500)
            }
        }
        $tcpRows++
        Assert-True ($tcpRows -eq 8) "TCP row count mismatch"
        }

        if ($Mode -in @("udp", "full", "performance")) {
            foreach ($targetIndex in @(4, 5, 6)) {
                [void](Add-TargetAddress $targets[$targetIndex])
            }

            # UDP-01 IPv4 one-hop route and authenticated response binding.
            if ($Mode -eq "performance") {
                $performanceControllerInflightPeak = [Math]::Max($performanceControllerInflightPeak, [uint64]1)
            }
            Invoke-UdpEchoRow $targets[0] $ports[0] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-01-one-hop"))
            $udpRows++
            if ($Mode -eq "performance") {
                $performanceWitnesses++
                Update-PerformancePeaks $activeProcess $metricsPort
            }

            if ($Mode -ne "performance") {
                # UDP-02 IPv6 fixed two-hop chain.
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                Invoke-UdpEchoRow $targets[1] $ports[1] $ownedInterfaceIndex $udpGateA ([Text.Encoding]::ASCII.GetBytes("udp-02-two-hop"))
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-02 did not traverse both exact hops"
                $udpRows++

            # UDP-03 IPv4 selector snapshot unchanged for a live mapping.
            $selectorProbe = [Ferrum2UdpProbe]::new($targets[2], $ports[2])
            $tcpResources.Add($selectorProbe)
            $selectorClient = Open-TunUdp $targets[2] $ports[2] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                foreach ($payload in @(
                    [Text.Encoding]::ASCII.GetBytes("udp-03-first"),
                    [Text.Encoding]::ASCII.GetBytes("udp-03-snapshot")
                )) {
                    [void]$selectorClient.Send($payload, $payload.Length)
                    $response = Receive-TunUdp $selectorClient
                    Assert-True (($response -join ",") -eq ($payload -join ",")) "UDP-03 mapping changed its response binding"
                }
                Assert-True ($selectorProbe.WaitRequests(2, 5000)) "UDP-03 target did not receive both datagrams"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-03 selector mapping was not fixed"
            } finally { $selectorClient.Dispose() }
            $udpRows++

            # UDP-04 IPv6 expiry and reselection.
            $expiryProbe = [Ferrum2UdpProbe]::new($targets[3], $ports[3])
            $tcpResources.Add($expiryProbe)
            $expiryClient = Open-TunUdp $targets[3] $ports[3] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $plain = [Text.Encoding]::ASCII.GetBytes("udp-04-before-dns")
                [void]$expiryClient.Send($plain, $plain.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($plain -join ",")) "UDP-04 initial response mismatch"
                $query = New-DnsQuery 0x1401
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 live snapshot response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 2 -and $udpGateB.Requests -eq $beforeGateB) "UDP-04 live mapping re-entered policy"
                Start-Sleep -Milliseconds 60500
                [void]$expiryClient.Send($query, $query.Length)
                Assert-True (((Receive-TunUdp $expiryClient) -join ",") -eq ($query -join ",")) "UDP-04 expired response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 3 -and $udpGateB.Requests -eq $beforeGateB + 1) "UDP-04 did not reselect after expiry"
            } finally { $expiryClient.Dispose() }
            $udpRows++
            }

            # UDP-05 IPv4 DNS hijack with zero Shadowsocks owner.
            $beforeGateA = $udpGateA.Requests
            $beforeGateB = $udpGateB.Requests
            $beforeDns = $dnsResponder.Requests
            $dnsClient = Open-TunUdp $targets[4] $ports[4] $ownedInterfaceIndex
            try {
                $query = New-DnsQuery 0x1501
                [void]$dnsClient.Send($query, $query.Length)
                $response = Receive-TunUdp $dnsClient
                Assert-True ($response[0] -eq 0x15 -and $response[1] -eq 0x01) "UDP-05 DNS response ID mismatch"
                Assert-True ($dnsResponder.Requests -eq $beforeDns + 1) "UDP-05 DNS proxy did not answer"
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-05 DNS hijack opened Shadowsocks"
            } finally { $dnsClient.Dispose() }
            $udpRows++
            if ($Mode -eq "performance") { $performanceDnsRows++ }

            if ($Mode -ne "performance") {
                # UDP-06 IPv6 reject tombstone and no policy re-entry.
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $rejectClient = Open-TunUdp $targets[5] $ports[5] $ownedInterfaceIndex
                try {
                    $rejected = [Text.Encoding]::ASCII.GetBytes("udp-06-reject")
                    [void]$rejectClient.Send($rejected, $rejected.Length)
                    [void]$rejectClient.Send($rejected, $rejected.Length)
                    $rejectedResponse = $rejectClient.ReceiveAsync()
                    Assert-True (-not $rejectedResponse.Wait(500)) "UDP-06 reject returned a datagram"
                    Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-06 reject opened an egress"
                } finally { $rejectClient.Dispose() }
                $udpRows++

            # UDP-07 IPv4 over-limit no-commit then selector re-read.
            $overLimitClient = Open-TunUdp $targets[6] $ports[6] $ownedInterfaceIndex
            try {
                $beforeGateA = $udpGateA.Requests
                $beforeGateB = $udpGateB.Requests
                $overLimit = [byte[]]::new(2000)
                [void]$overLimitClient.Send($overLimit, $overLimit.Length)
                Start-Sleep -Milliseconds 500
                Assert-True ($udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 over-limit candidate committed"
                $overLimitProbe = [Ferrum2UdpProbe]::new($targets[6], $ports[6])
                $tcpResources.Add($overLimitProbe)
                $valid = [Text.Encoding]::ASCII.GetBytes("udp-07-valid")
                [void]$overLimitClient.Send($valid, $valid.Length)
                Assert-True (((Receive-TunUdp $overLimitClient) -join ",") -eq ($valid -join ",")) "UDP-07 recovery response mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 1 -and $udpGateB.Requests -eq $beforeGateB) "UDP-07 valid candidate did not re-read selector"
            } finally { $overLimitClient.Dispose() }
            $udpRows++

            # UDP-08 IPv6 mapping saturation, generation reuse and wrong-response drop.
            Start-Sleep -Milliseconds 60500
            $saturationProbe = [Ferrum2UdpProbe]::new($targets[7], $ports[7])
            $tcpResources.Add($saturationProbe)
            $saturatedClients = [System.Collections.Generic.List[Net.Sockets.UdpClient]]::new()
            $overflowClient = $null
            try {
                $beforeGateA = $udpGateA.Requests
                foreach ($index in 0..3) {
                    $mappingClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                    $saturatedClients.Add($mappingClient)
                    $payload = [Text.Encoding]::ASCII.GetBytes("udp-08-slot-$index")
                    [void]$mappingClient.Send($payload, $payload.Length)
                    Assert-True (((Receive-TunUdp $mappingClient) -join ",") -eq ($payload -join ",")) "UDP-08 live mapping response mismatch"
                }
                Assert-True ($saturatedClients.Count -eq 4) "UDP-08 mapping saturation setup mismatch"
                Assert-True ($udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 did not commit the fixed mapping capacity"
                $overflowClient = Open-TunUdp $targets[7] $ports[7] $ownedInterfaceIndex
                $overflow = [Text.Encoding]::ASCII.GetBytes("udp-08-overflow")
                [void]$overflowClient.Send($overflow, $overflow.Length)
                $overflowResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $overflowResponse.Wait(500) -and $udpGateA.Requests -eq $beforeGateA + 4) "UDP-08 evicted a live mapping"
                Start-Sleep -Milliseconds 60500
                [void]$overflowClient.Send($overflow, $overflow.Length)
                Assert-True ($overflowResponse.Wait(5000)) "UDP-08 expired response timeout"
                if ($overflowResponse.IsFaulted) { throw "UDP-08 expired response failed" }
                Assert-True (($overflowResponse.Result.Buffer -join ",") -eq ($overflow -join ",")) "UDP-08 expired slot was not reusable"
                Assert-True ($udpGateA.ReplayFirstToLatest()) "UDP-08 stale response replay was unavailable"
                $staleResponse = $overflowClient.ReceiveAsync()
                Assert-True (-not $staleResponse.Wait(500)) "UDP-08 stale response crossed the new generation"
            } finally {
                if ($overflowClient) { $overflowClient.Dispose() }
                foreach ($client in $saturatedClients) { $client.Dispose() }
            }
                $udpRows++
            }
            if ($Mode -eq "performance") {
                Assert-True ($udpRows -eq 2) "performance UDP witness row count mismatch"
            } else {
                Assert-True ($udpRows -eq 8) "UDP row count mismatch"
            }

            if ($Mode -eq "performance") { Complete-PerformanceSample $activeProcess $metricsPort }
            Stop-Candidate $activeProcess
            if ($Mode -eq "performance") { $performanceGraceDrain = $true }
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            $activeProcess = Start-Candidate $binary $config
            $adapter = Wait-AdapterReady $adapterName
            $ownedInterfaceIndex = [int]$adapter.ifIndex
            if ($Mode -eq "performance") { $performanceAdapterChurn++ }
            Stop-Candidate $activeProcess
            $activeProcess = $null
            Wait-AdapterAbsent $adapterName
            Assert-InterfaceGone $adapterName $ownedInterfaceIndex
            if ($Mode -eq "performance") {
                Assert-True $performanceFieldsCollected "performance fields were not collected"
                Assert-True ($performanceWitnesses -eq 2) "performance witness count mismatch"
                Assert-True ($performanceDirectRows -eq 1) "performance direct row count mismatch"
                Assert-True ($performanceDnsRows -eq 2) "performance DNS row count mismatch"
                Assert-True ($performanceAdapterRxBytes -gt 0 -and $performanceAdapterTxBytes -gt 0) "adapter byte witnesses missing"
                Assert-True ($performanceAdapterRxPackets -gt 0 -and $performanceAdapterTxPackets -gt 0) "adapter packet witnesses missing"
                Assert-True ($performanceTunAcceptedDelta -gt 0) "TUN accepted witness missing"
                Assert-True ($performanceRssBytes -gt 0 -and $performanceHandlesPeak -gt 0 -and $performanceThreadsPeak -gt 0) "process resource sample missing"
                Assert-True ($performanceControllerInflightPeak -gt 0) "controller inflight sample missing"
                Assert-True ($performanceAdapterChurn -ge 2) "adapter churn witness missing"
                Assert-True ($performanceGraceDrain -and $performanceForceDrain) "grace/force drain witness missing"
            }
        }
    }
