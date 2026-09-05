Set-StrictMode -Version Latest

function Start-Ferrum2ProductTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ClientDirect", "EndToEnd")]
        [string]$Topology
    )
    $adapterName = "$($Network.adapter_name_prefix)-$('{0:D3}' -f $Sequence)"
    Set-Ferrum2OwnedAdapterPlan -Context $Context -AdapterName $adapterName
    $clientMetrics = Get-Ferrum2FreeTcpPort
    [uint16]$serverPort = 0
    [uint16]$serverMetrics = 0
    if ($Topology -ceq "EndToEnd") {
        $serverPort = Get-Ferrum2FreeDualPort -Address "127.0.0.1"
        $serverMetrics = Get-Ferrum2FreeTcpPort
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
    }
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
        -Port $clientMetrics -Purpose "client-metrics"
    $configs = Write-Ferrum2TrialConfigs -Context $Context -Network $Network -Loopback $Loopback `
        -AdapterName $adapterName -Topology $Topology -ServerPort $serverPort `
        -ClientMetricsPort $clientMetrics -ServerMetricsPort $serverMetrics -Sequence $Sequence
    Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.client `
        -Config $configs.client -LogPrefix "trial-$Sequence-client-config-check"
    $server = $null
    $client = $null
    try {
        $client = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.client `
            -Arguments "--config `"$($configs.client)`"" `
            -WorkingDirectory (Split-Path -Parent $Member.client) `
            -LogPrefix "trial-$Sequence-client" -Purpose "trial-$Sequence-client"
        [void](Wait-Ferrum2Metric -Port $clientMetrics -Name "ferrum2_tun_session_active" -Minimum 1)
        $adapter = Complete-Ferrum2OwnedAdapterIdentity -Context $Context -AdapterName $adapterName
        $route = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix "$($Network.support_address)/32" `
            -InterfaceIndex ([uint32]$adapter.ifIndex) -ErrorAction Stop)
        if ($route.Count -ne 1 -or [string]$route[0].NextHop -cne "0.0.0.0") {
            throw "product-owned benchmark route identity is invalid"
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
        Write-Ferrum2HostPerformanceLedger -Context $Context
        if ($Topology -ceq "EndToEnd") {
            Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.server `
                -Config $configs.server -LogPrefix "trial-$Sequence-server-config-check"
            $server = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.server `
                -Arguments "--config `"$($configs.server)`"" `
                -WorkingDirectory (Split-Path -Parent $Member.server) `
                -LogPrefix "trial-$Sequence-server" -Purpose "trial-$Sequence-server"
            [void](Wait-Ferrum2Metric -Port $serverMetrics -Name "ferrum2_network_generation" -Minimum 1)
        }
        $proofs = Get-Ferrum2TrialRouteProofs -Network $Network -Loopback $Loopback `
            -TunInterfaceIndex ([uint32]$adapter.ifIndex) -Topology $Topology
        return [pscustomobject]@{
            topology = $Topology
            adapter = $adapter
            adapter_name = $adapterName
            server = $server
            client = $client
            server_port = $serverPort
            client_metrics_port = $clientMetrics
            server_metrics_port = $serverMetrics
            route_proofs = $proofs
        }
    } catch {
        $failure = $_
        Export-Ferrum2ProductFailureLogs -Context $Context -Client $client `
            -Server $server -Sequence $Sequence
        throw $failure
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
                    -Process $entry.process -LogPrefix "trial-$Sequence-$($entry.name)")
            } catch {
                Write-Warning "product diagnostic export failed"
            }
        }
    }
}

function Stop-Ferrum2ProductTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Runtime
    )
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
    Write-Ferrum2HostPerformanceLedger -Context $Context
}

