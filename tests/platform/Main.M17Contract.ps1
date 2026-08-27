function New-M17TunFixture(
    [string]$Name,
    [string]$TunFields,
    [bool]$WithDns,
    [string]$Additional = ""
) {
    $tunOutbound = if ([regex]::IsMatch($Additional, '(?m)^\[route\]\r?$')) {
        ""
    } else {
        'outbound = "proxy"'
    }
    $dns = if ($WithDns) {
@"
[dns]
[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:15353"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "1.1.1.1:53"
[dns.route]
final = "resolver"
"@
    } else { "" }
    $source = @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$script:adapterName"
$TunFields
$tunOutbound
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "192.0.2.10:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
$dns
$Additional
"@
    return [pscustomobject]@{ Name = $Name; Source = $source }
}

function Get-M17ProfileContract {
    switch ($script:Profile) {
        "network-reset" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "network-reset-dual-strict" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
strict_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = 32
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "ordinary_route_notifications_reset_network_runtime",
                    "same_process_and_managed_adapter_identity",
                    "managed_addresses_routes_and_dns_are_unchanged",
                    "strict_route_is_effective_and_filter_identity_is_unchanged",
                    "network_generation_and_reset_metrics_advance",
                    "retry_reset_failure_and_full_rebuild_metrics_are_unchanged"
                )
                counters = @(
                    "ferrum2_network_reset_total",
                    "ferrum2_network_full_rebuild_total",
                    "ferrum2_network_generation",
                    "ferrum2_tun_session_generation",
                    "ferrum2_tun_strict_route_requested",
                    "ferrum2_tun_strict_route_effective",
                    "ferrum2_tun_strict_route_filter_install_total"
                )
            }
        }
        "restart-stress" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "restart-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
max_udp_mappings = 32
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "same_process_for_every_restart", "generation_advances_once_per_restart",
                    "adapter_route_dns_and_handler_baselines_restore"
                )
                counters = @(
                    "ferrum2_network_reset_total",
                    "ferrum2_network_full_rebuild_total",
                    "ferrum2_network_generation",
                    "ferrum2_tun_session_generation"
                )
            }
        }
        "fragments" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "fragments-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "large_ipv4_and_ipv6_udp_reassembles", "fragmented_synthetic_dns"
                )
                counters = @(
                    "ferrum2_tun_reassembly_entries_active",
                    "ferrum2_tun_packets_rejected_total"
                )
            }
        }
        "dual-stack-dns" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "dns-ipv4-only" @"
ipv4_address = "198.18.0.2/30"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
udp_filtering = "address_dependent"
"@ $true
                    New-M17TunFixture "dns-ipv6-only" @"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                    New-M17TunFixture "dns-dual" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
auto_route = true
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00::1"
udp_filtering = "address_dependent"
"@ $true
                )
                witnesses = @(
                    "ipv4_udp_dns", "ipv4_tcp_dns", "ipv6_udp_dns", "ipv6_tcp_dns",
                    "dual_dns_readback_and_restore"
                )
                counters = @("ferrum2_tun_packets_ingress_total", "ferrum2_tun_packets_egress_total")
            }
        }
        "udp-policy" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "udp-adf" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "address_dependent"
"@ $false @"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.51.100.10"
port = 3478
action = "route"
outbound = "direct"
"@
                    New-M17TunFixture "udp-eif" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_udp_mappings = 2
udp_filtering = "endpoint_independent"
"@ $false @"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.51.100.10"
port = 3478
action = "route"
outbound = "direct"
"@
                )
                witnesses = @(
                    "one_eim_association_for_multiple_targets", "adf_allows_authorized_ip_any_port",
                    "adf_rejects_unauthorized_ip", "eif_allows_valid_same_family_peer",
                    "ipv4_and_ipv6_sources_form_distinct_associations",
                    "udp_firewall_scope_is_journaled_and_removed",
                    "dns_udp_payload_round_trips", "quic_v1_initial_envelope_round_trips",
                    "stun_binding_requests_reach_multiple_servers",
                    "webrtc_ice_candidate_check_round_trips",
                    "game_style_binary_datagrams_reach_multiple_peers",
                    "association_capacity_drops_new_without_evicting_live"
                )
                counters = @(
                    "ferrum2_tun_udp_associations_active", "ferrum2_tun_udp_candidates_active",
                    "ferrum2_tun_udp_association_rejected_limit_total",
                    "ferrum2_tun_udp_datagram_queue_full_total",
                    "ferrum2_tun_udp_response_queue_full_total",
                    "ferrum2_tun_udp_stale_generation_total"
                )
            }
        }
        "scheduler-ring-full" {
            return [ordered]@{
                fixtures = @(
                    New-M17TunFixture "scheduler-ring-full" @"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
udp_filtering = "address_dependent"
"@ $false
                )
                witnesses = @(
                    "rx_bursts_8_16_64_have_no_structural_drop",
                    "live_egress_pressure_has_closed_accounting"
                )
                counters = @(
                    "ferrum2_tun_internal_egress_backpressured_total",
                    "ferrum2_tun_wintun_ring_full_dropped_total",
                    "ferrum2_tun_packets_egress_total"
                )
            }
        }
        default { throw "M17 contract dispatch received an invalid profile" }
    }
}

function Invoke-M17ContractPreflight {
    Assert-M17ExternalIdentityInputsUnchanged
    $contract = Get-M17ProfileContract
    $artifactRoot = if ([string]::IsNullOrWhiteSpace($script:ArtifactDirectory)) {
        Join-Path ([System.IO.Path]::GetTempPath()) "ferrum2-m17-artifacts\$script:runIdentity"
    } else {
        [IO.Path]::GetFullPath($script:ArtifactDirectory)
    }
    $artifactRoot = [IO.Path]::GetFullPath($artifactRoot).TrimEnd('\', '/')
    $workRoot = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
    Assert-True (-not $artifactRoot.Equals($workRoot, [StringComparison]::OrdinalIgnoreCase) -and
        -not $artifactRoot.StartsWith("$workRoot\", [StringComparison]::OrdinalIgnoreCase)) "M17 artifacts must survive controller work cleanup"
    if (-not (Test-Path -LiteralPath $artifactRoot)) {
        New-Item -ItemType Directory -Path $artifactRoot | Out-Null
    }
    Assert-NotReparsePoint $artifactRoot "M17 artifact directory"
    foreach ($name in @(
        "identity-ledger.json", "m17-contract.json", "m17-result.json",
        "external-cleanup.json", "external-cleanup.json.pending", "network-reset-cycles.jsonl"
    )) {
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $artifactRoot $name))) "M17 artifact baseline is not absent: $name"
    }
    $script:m17ArtifactRoot = $artifactRoot
    $script:m17ArtifactInitialized = $true
    $script:m17Contract = $contract
    $script:m17StartedUtc = [DateTime]::UtcNow.ToString("o")
    $identityArtifact = Join-Path $artifactRoot "identity-ledger.json"
    [IO.File]::WriteAllBytes($identityArtifact, [IO.File]::ReadAllBytes($script:capabilityIdentity.Path))
    Assert-True ((Get-FileHash -LiteralPath $identityArtifact -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
        $script:capabilityIdentityHash) "M17 artifact identity ledger hash changed"
    $fixtureRoot = Join-Path $script:work "m17-fixtures"
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $fixtureRows = [System.Collections.Generic.List[object]]::new()
    foreach ($fixture in $contract.fixtures) {
        $path = Join-Path $fixtureRoot "$($fixture.Name).toml"
        [IO.File]::WriteAllText($path, $fixture.Source, [Text.UTF8Encoding]::new($false))
        $stderrPath = "$path.stderr"
        $stdout = @(& $script:binary --config $path --check-config 2> $stderrPath)
        $exitCode = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw -Encoding utf8
        } else { "" }
        Assert-True ($exitCode -eq 0) "M17 fixture $($fixture.Name) did not pass offline config validation"
        Assert-True (($stdout -join "`n") -ceq "configuration valid") "M17 fixture $($fixture.Name) stdout changed"
        Assert-True ([string]::IsNullOrEmpty($stderr)) "M17 fixture $($fixture.Name) emitted stderr during offline validation"
        $fixtureRows.Add([ordered]@{
            name = $fixture.Name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            offline_check = "pass"
        })
    }
    $document = [ordered]@{
        schema = "ferrum2.windows-tun.m17-contract.v4"
        status = "preflight_pass"
        profile = $script:Profile
        cycle_limit = if ($script:Profile -in @("network-reset", "restart-stress")) { 1000 } else { $null }
        release_milestones = if ($script:Profile -in @("network-reset", "restart-stress")) {
            $script:releaseMilestones
        } else { @() }
        approved_vm_name = $script:expectedHyperVVmName
        approved_vm_id = $script:expectedHyperVVmId
        approved_checkpoint_name = $script:expectedHyperVCheckpointName
        approved_checkpoint_id = $script:expectedHyperVCheckpointId
        guest_build = [string]$script:capabilityIdentity.Ledger.guest_build
        identity_sha256 = $script:capabilityIdentityHash
        candidate_sha = [string]$script:capabilityIdentity.Ledger.candidate_sha
        client_sha256 = [string]$script:capabilityIdentity.Ledger.client_sha256
        server_sha256 = [string]$script:capabilityIdentity.Ledger.server_sha256
        controller_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        controller_bundle_sha256 = [string]$script:controllerBundleManifest.controller_bundle_sha256
        wintun_zip_sha256 = $script:expectedZipHash.ToLowerInvariant()
        wintun_dll_sha256 = $script:expectedDllHash.ToLowerInvariant()
        topology = $script:capabilityIdentity.Ledger.topology
        guest_network_path = $script:m17GuestNetworkPathDocument.Value
        fixtures = $fixtureRows
        witnesses = $contract.witnesses
        counters = $contract.counters
    }
    $artifact = Join-Path $artifactRoot "m17-contract.json"
    [IO.File]::WriteAllText(
        $artifact,
        (($document | ConvertTo-Json -Depth 8) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $script:m17FixtureRows = @($fixtureRows)
    return [pscustomobject]@{ Contract = $contract; ArtifactRoot = $artifactRoot; FixtureRoot = $fixtureRoot }
}

function Add-M17Witness([string]$Name, [string]$Provenance, [string]$Evidence) {
    Assert-True ($Name -in @($script:m17Contract.witnesses)) "M17 witness is outside the profile contract: $Name"
    Assert-True (-not $script:m17WitnessRows.Contains($Name)) "duplicate M17 witness: $Name"
    $script:m17WitnessRows[$Name] = [ordered]@{
        name = $Name
        status = "pass"
        provenance = $Provenance
        evidence = $Evidence
    }
}

function Add-M17LiveRow([string]$Name, [System.Collections.IDictionary]$Evidence) {
    $script:m17LiveRows.Add([ordered]@{
        name = $Name
        status = "pass"
        evidence = $Evidence
    })
}

function Get-M17CounterSnapshot([string]$Metrics) {
    $snapshot = [ordered]@{}
    foreach ($name in @($script:m17Contract.counters)) {
        $snapshot[$name] = Get-M17MetricValue $Metrics $name $true
    }
    foreach ($name in @("ferrum2_tun_session_active", "ferrum2_tun_session_generation")) {
        if (-not $snapshot.Contains($name)) { $snapshot[$name] = Get-M17MetricValue $Metrics $name }
    }
    return $snapshot
}

function Wait-M17Session(
    [int]$MetricsPort,
    [double]$MinimumGeneration,
    [double]$ExpectedActive,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $metrics = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $metrics = Get-Metrics $MetricsPort 2 }
        catch {
            if ($_.Exception.Message -cne "metrics readiness timeout") { throw }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 50
            continue
        }
        $generation = Get-M17MetricValue $metrics "ferrum2_tun_session_generation"
        $active = Get-M17MetricValue $metrics "ferrum2_tun_session_active"
        if ($generation -ge $MinimumGeneration -and $active -eq $ExpectedActive) {
            return [pscustomobject]@{ Metrics = $metrics; Generation = $generation; Active = $active }
        }
        Start-Sleep -Milliseconds 50
    }
    if ($null -eq $metrics) {
        throw "M17 metrics remained unavailable during the bounded session wait: minimum_generation=$MinimumGeneration expected_active=$ExpectedActive"
    }
    $networkReset = Get-M17MetricValue $metrics "ferrum2_network_reset" $true
    $fullRebuild = Get-M17MetricValue $metrics "ferrum2_network_full_rebuild" $true
    throw "M17 session state timeout: minimum_generation=$MinimumGeneration expected_active=$ExpectedActive generation=$generation active=$active network_reset_total=$networkReset full_rebuild_total=$fullRebuild"
}

function Wait-M17FlowDrain(
    [int]$MetricsPort,
    [double]$ExpectedGeneration,
    [int]$MaximumUdpAssociations,
    [int]$TimeoutSeconds = 10
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $metrics = $null
    do {
        try { $metrics = Get-Metrics $MetricsPort 2 }
        catch {
            if ($_.Exception.Message -cne "metrics readiness timeout") { throw }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 50
            continue
        }
        $generation = Get-M17MetricValue $metrics "ferrum2_tun_session_generation"
        $active = Get-M17MetricValue $metrics "ferrum2_tun_session_active"
        $tcpFlows = Get-M17MetricValue $metrics "ferrum2_tun_tcp_flows_active"
        $udpAssociations = Get-M17MetricValue $metrics "ferrum2_tun_udp_associations_active"
        $udpCandidates = Get-M17MetricValue $metrics "ferrum2_tun_udp_candidates_active"
        $reassemblyEntries = Get-M17MetricValue $metrics "ferrum2_tun_reassembly_entries_active"
        $handlerTasks = Get-ClientGaugeValue $metrics "ferrum2_tun_handler_tasks_active"
        if ($generation -eq $ExpectedGeneration -and $active -eq 1 -and
            $tcpFlows -eq 0 -and $udpCandidates -eq 0 -and
            $udpAssociations -le $MaximumUdpAssociations -and
            $reassemblyEntries -eq 0 -and $handlerTasks -eq $udpAssociations) {
            return [pscustomobject]@{
                Metrics = $metrics
                Generation = $generation
                TcpFlows = $tcpFlows
                UdpAssociations = $udpAssociations
                UdpCandidates = $udpCandidates
                ReassemblyEntries = $reassemblyEntries
                HandlerTasks = $handlerTasks
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $metrics) {
        throw "M17 metrics remained unavailable during the bounded flow/fragment wait: expected_generation=$ExpectedGeneration"
    }
    throw "M17 flow/fragment baseline did not drain: expected_generation=$ExpectedGeneration generation=$generation active=$active tcp_flows=$tcpFlows udp_associations=$udpAssociations udp_candidates=$udpCandidates udp_limit=$MaximumUdpAssociations reassembly_entries=$reassemblyEntries handler_tasks=$handlerTasks"
}

function Wait-M17AdapterReady(
    [string]$Name,
    [bool]$Ipv4,
    [bool]$Ipv6,
    [string[]]$Ipv4Dns = @(),
    [string[]]$Ipv6Dns = @(),
    [uint32]$ExpectedMtu = 1420,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($script:activeProcess) {
            $script:activeProcess.Refresh()
            if ($script:activeProcess.HasExited) { throw "M17 candidate failed during prepare" }
        }
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $v4 = @($addresses | Where-Object { $_.IPAddress -ceq "198.18.0.2" -and $_.PrefixLength -eq 30 -and $_.AddressState -eq "Preferred" })
            $v6 = @($addresses | Where-Object { $_.IPAddress -ceq "fd00::2" -and $_.PrefixLength -eq 126 -and $_.AddressState -eq "Preferred" })
            $addressesReady = (($Ipv4 -and $v4.Count -eq 1) -or (-not $Ipv4 -and $v4.Count -eq 0)) -and
                (($Ipv6 -and $v6.Count -eq 1) -or (-not $Ipv6 -and $v6.Count -eq 0))
            if ($addressesReady) {
                $v4Interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                $v6Interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                $mtuReady = ((-not $Ipv4) -or ($v4Interface -and [uint32]$v4Interface.NlMtu -eq $ExpectedMtu)) -and
                    ((-not $Ipv6) -or ($v6Interface -and [uint32]$v6Interface.NlMtu -eq $ExpectedMtu))
                $actualV4Dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                $actualV6Dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                $expectedV4Dns = @($Ipv4Dns | Sort-Object -Unique)
                $expectedV6Dns = @($Ipv6Dns | Sort-Object -Unique)
                $windowsIntrinsicV6Dns = @(
                    "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"
                )
                $v4DnsReady = ($actualV4Dns -join "|") -ceq ($expectedV4Dns -join "|")
                $v6DnsReady = ($actualV6Dns -join "|") -ceq ($expectedV6Dns -join "|") -or
                    ($expectedV6Dns.Count -eq 0 -and
                        ($actualV6Dns -join "|") -ceq ($windowsIntrinsicV6Dns -join "|"))
                if ($mtuReady -and $v4DnsReady -and $v6DnsReady) {
                    return $adapter
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "M17 adapter readiness timeout"
}

function Start-M17Candidate([string]$Configuration, [string]$Label) {
    Assert-True ($Label -cmatch '^[a-z0-9][a-z0-9-]{0,63}$') "M17 process label is invalid"
    $script:m17ProcessOrdinal++
    $stdoutPath = Join-Path $script:m17ArtifactRoot ("{0:D3}-client-{1}.stdout.log" -f $script:m17ProcessOrdinal, $Label)
    $stderrPath = Join-Path $script:m17ArtifactRoot ("{0:D3}-client-{1}.stderr.log" -f $script:m17ProcessOrdinal, $Label)
    $arguments = "--config `"$Configuration`""
    $id = [Ferrum2ProcessGroup]::Start($script:binary, $arguments, (Split-Path -Parent $script:binary), $stdoutPath, $stderrPath)
    $process = Get-Process -Id $id
    $script:activeProcess = $process
    $script:m17ProcessRows.Add([ordered]@{
        role = "client"
        label = $Label
        process_id = [uint32]$id
        binary_sha256 = (Get-FileHash -LiteralPath $script:binary -Algorithm SHA256).Hash.ToLowerInvariant()
        stdout = [IO.Path]::GetFileName($stdoutPath)
        stderr = [IO.Path]::GetFileName($stderrPath)
    })
    return $process
}

function Start-M17Server {
    $serverConfig = Join-Path $script:work "m17-server.toml"
    $script:m17ServerPort = Get-UniqueTcpPort
    @"
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:$script:m17ServerPort"
outbound = "direct"
[[outbounds]]
tag = "direct"
[runtime]
shutdown_grace_ms = 1000
[udp]
enabled = true
max_sessions = 64
max_buffered_bytes = 4194304
idle_timeout_ms = 60000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@ | Set-Content -LiteralPath $serverConfig -Encoding utf8NoBOM
    $stdoutPath = Join-Path $script:m17ArtifactRoot "server.stdout.log"
    $stderrPath = Join-Path $script:m17ArtifactRoot "server.stderr.log"
    $id = [Ferrum2ProcessGroup]::Start($script:serverBinary, "--config `"$serverConfig`"", (Split-Path -Parent $script:serverBinary), $stdoutPath, $stderrPath)
    $process = Get-Process -Id $id
    $script:serverProcesses.Add($process)
    $script:m17ServerProcess = $process
    $script:m17ProcessRows.Add([ordered]@{
        role = "server"
        label = "qualification"
        process_id = [uint32]$id
        binary_sha256 = (Get-FileHash -LiteralPath $script:serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        stdout = [IO.Path]::GetFileName($stdoutPath)
        stderr = [IO.Path]::GetFileName($stderrPath)
    })
    Wait-TcpListener $script:m17ServerPort $process "m17-server"
    Wait-UdpListener $script:m17ServerPort $process "m17-server"
    Add-M17LiveRow "server-binary-ready" ([ordered]@{
        process_id = [uint32]$id
        tcp_listener = "127.0.0.1:$script:m17ServerPort"
        udp_listener = "127.0.0.1:$script:m17ServerPort"
        stable_udp_samples = 2
    })
}
