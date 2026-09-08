Set-StrictMode -Version Latest

function Start-Ferrum2HostProduct {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [AllowNull()][Net.IPEndPoint]$ResetProbeEndpoint = $null
    )
    $adapterName = "$($Network.adapter_name_prefix)-$('{0:D3}' -f $Sequence)"
    Set-Ferrum2OwnedAdapterPlan -Context $Context -AdapterName $adapterName
    $ports = New-Ferrum2ProductPorts -Context $Context -Sequence $Sequence
    $server = $null
    $client = $null
    try {
        $clientMetrics = $ports.client_metrics.port
        [uint16]$serverPort = 0
        [uint16]$serverMetrics = 0
        $serverPort = $ports.server.port
        $serverMetrics = $ports.server_metrics.port
        if (@(@($serverPort, $clientMetrics, $serverMetrics) |
                Sort-Object -Unique).Count -ne 3) {
            throw "product ports are not distinct"
        }
        Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
            -Port $serverPort -Purpose "server-tcp"
        Add-Ferrum2OwnedPort -Context $Context -Protocol "udp" -Address "127.0.0.1" `
            -Port $serverPort -Purpose "server-udp"
        Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
            -Port $serverMetrics -Purpose "server-metrics"
        Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
            -Port $clientMetrics -Purpose "client-metrics"
        $tcpRanges = @($ports.dynamic_ranges | Where-Object { $_.protocol -ceq 'tcp' })
        if ($tcpRanges.Count -ne 1) { throw 'qualification TCP dynamic port identity is unavailable' }
        $tcpRange = "$($tcpRanges[0].start_port)-$($tcpRanges[0].end_port)"
        $octets = $Network.tun_address.Split('.')
        $peerAddress = "$($octets[0]).$($octets[1]).$($octets[2]).$([int]$octets[3] - 1)"
        $ingressFirewall = Add-Ferrum2OwnedFirewallRule -Context $Context -Executable $Member.client `
            -Protocol TCP -LocalAddress $Network.tun_address -LocalPort $tcpRange `
            -RemoteAddress $peerAddress -InterfaceAlias $adapterName `
            -Purpose "client-ingress-$Sequence" -DeferInterface
        foreach ($entry in @(
            @{ executable = $Member.client; port = $clientMetrics; protocol = 'TCP'; purpose = 'client-metrics' },
            @{ executable = $Member.server; port = $serverPort; protocol = 'TCP'; purpose = 'server-tcp' },
            @{ executable = $Member.server; port = $serverPort; protocol = 'UDP'; purpose = 'server-udp' },
            @{ executable = $Member.server; port = $serverMetrics; protocol = 'TCP'; purpose = 'server-metrics' }
        )) {
            [void](Add-Ferrum2OwnedFirewallRule -Context $Context -Executable $entry.executable `
                -Protocol $entry.protocol -LocalAddress '127.0.0.1' -LocalPort ([string]$entry.port) `
                -RemoteAddress '127.0.0.1' -InterfaceAlias $Loopback.interface_alias `
                -Purpose "$($entry.purpose)-$Sequence")
        }
        $configOptions = @{}
        if ($null -ne $ResetProbeEndpoint) {
            $configOptions.ResetProbeEndpoint = $ResetProbeEndpoint
        }
        $configs = Write-Ferrum2HostConfigs -Context $Context -Network $Network -Loopback $Loopback `
            -AdapterName $adapterName -ServerPort $serverPort `
            -ClientMetricsPort $clientMetrics -ServerMetricsPort $serverMetrics -Sequence $Sequence `
            @configOptions
        Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.client `
            -Config $configs.client -LogPrefix "qualification-$Sequence-client-config-check"
        Close-Ferrum2PortReservation -Reservation $ports.client_metrics
        $client = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.client `
            -Arguments "--config `"$($configs.client)`"" `
            -WorkingDirectory (Split-Path -Parent $Member.client) `
            -LogPrefix "qualification-$Sequence-client" -Purpose "qualification-$Sequence-client"
        [void](Wait-Ferrum2Metric -Process $client -Port $clientMetrics -Name "ferrum2_tun_session_active" -Minimum 1)
        $adapter = Complete-Ferrum2OwnedAdapterIdentity -Context $Context -AdapterName $adapterName
        $interfaces = @(Get-NetIPInterface -AddressFamily IPv4 `
            -InterfaceIndex ([uint32]$adapter.ifIndex) -ErrorAction Stop)
        if ($interfaces.Count -ne 1 -or [uint32]$interfaces[0].NlMtu -ne 1420) {
            throw 'qualification owned IPv4 TUN MTU must read back as 1420 bytes'
        }
        Complete-Ferrum2FirewallInterface -Context $Context -Row $ingressFirewall
        $route = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix "$($Network.support_address)/32" `
            -InterfaceIndex ([uint32]$adapter.ifIndex) -ErrorAction Stop)
        if ($route.Count -ne 1 -or [string]$route[0].NextHop -cne "0.0.0.0") {
            throw "product-owned qualification route identity is invalid"
        }
        $routeRow = [pscustomobject][ordered]@{
            destination_prefix = "$($Network.support_address)/32"
            interface_index = [uint32]$adapter.ifIndex
            next_hop = "0.0.0.0"
            route_metric = [uint16]$route[0].RouteMetric
            policy_store = "ActiveStore"
            kind = "product"
            state = "created"
        }
        $Context.ledger.resources.routes = @($Context.ledger.resources.routes) + @($routeRow)
        Write-Ferrum2HostLedger -Context $Context
        Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.server `
            -Config $configs.server -LogPrefix "qualification-$Sequence-server-config-check"
        Close-Ferrum2PortReservation -Reservation $ports.server
        Close-Ferrum2PortReservation -Reservation $ports.server_metrics
        $server = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.server `
            -Arguments "--config `"$($configs.server)`"" `
            -WorkingDirectory (Split-Path -Parent $Member.server) `
            -LogPrefix "qualification-$Sequence-server" -Purpose "qualification-$Sequence-server"
        [void](Wait-Ferrum2Metric -Process $server -Port $serverMetrics -Name "ferrum2_network_generation" -Minimum 1)
        $proofs = Get-Ferrum2HostRouteProofs -Network $Network -Loopback $Loopback `
            -TunInterfaceIndex ([uint32]$adapter.ifIndex)
        return [pscustomobject]@{
                adapter = $adapter
            adapter_name = $adapterName
            sequence = $Sequence
            mtu_bytes = [uint32]$interfaces[0].NlMtu
            server = $server
            client = $client
            server_port = $serverPort
            client_metrics_port = $clientMetrics
            server_metrics_port = $serverMetrics
            route_proofs = $proofs
            dynamic_ranges = $ports.dynamic_ranges
        }
    } catch {
        $failure = $_
        Export-Ferrum2ProductFailureLogs -Context $Context -Client $client `
            -Server $server -Sequence $Sequence
        throw $failure
    } finally {
        foreach ($reservation in @($ports.client_metrics, $ports.server, $ports.server_metrics)) {
            Close-Ferrum2PortReservation -Reservation $reservation
        }
    }
}

# Both startup and later workload failures must export logs before transaction cleanup.
function Export-Ferrum2ProductFailureLogs {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [AllowNull()][object]$Client,
        [AllowNull()][object]$Server,
        [Parameter(Mandatory = $true)][int]$Sequence
    )
    foreach ($entry in @(
        @{ name = "client"; process = $Client },
        @{ name = "server"; process = $Server }
    )) {
        if ($null -ne $entry.process) {
            try {
                [void](Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
                    -Process $entry.process -LogPrefix "qualification-$Sequence-$($entry.name)")
            } catch {
                Write-Warning "product diagnostic export failed"
            }
        }
    }
}

function Stop-Ferrum2HostProduct {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Runtime
    )
    # Retire ordinary per-product rules while their interface alias still resolves.
    # Expected identities and evidence survive; forced-kill recovery uses stable bindings.
    $retiringRules = @($Context.ledger.resources.firewall_rules | Where-Object {
        [string]$_.interface_alias -ceq [string]$Runtime.adapter_name -or
        [string]$_.purpose -cmatch ("^(client-ingress|client-metrics|server-tcp|server-udp|server-metrics)-" +
            [regex]::Escape([string]$Runtime.sequence) + '$')
    })
    foreach ($rule in $retiringRules) {
        Remove-Ferrum2OwnedFirewallRule -Row $rule
        $Context.ledger.resources.firewall_rules = @($Context.ledger.resources.firewall_rules |
            Where-Object { [string]$_.name -cne [string]$rule.name })
        Write-Ferrum2HostLedger -Context $Context
    }
    Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $Runtime.client.pid
    if ($null -ne $Runtime.server) {
        Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $Runtime.server.pid
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $remaining = @(Get-NetAdapter -IncludeHidden -Name $Runtime.adapter_name -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($remaining.Count -ne 0) { throw "owned Wintun adapter did not disappear after product shutdown" }
    $Context.ledger.resources.routes = @($Context.ledger.resources.routes | Where-Object {
        [uint32]$_.interface_index -ne [uint32]$Runtime.adapter.ifIndex
    })
    $Context.ledger.resources.ports = @($Context.ledger.resources.ports | Where-Object {
        [string]$_.purpose -notmatch '^(server-|client-metrics)'
    })
    $Context.ledger.resources.adapter = $null
    Write-Ferrum2HostLedger -Context $Context
}

