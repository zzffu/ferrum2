function Read-M17TopologyManifest([string]$Path, [object]$Ledger) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path)) "network qualification requires TopologyManifest"
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-NotReparsePoint $resolved "support topology manifest"
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    Assert-True (-not $item.PSIsContainer -and $item.Length -ge 2 -and $item.Length -le 131072) "support topology manifest file boundary is invalid"
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    Assert-True ($bytes[-1] -eq 10 -and @($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and
        @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0 -and
        -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and
            $bytes[2] -eq 0xbf)) "support topology manifest must be one BOM-free LF-terminated UTF-8 document"
    $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($actualHash -ceq [string]$Ledger.topology.manifest_sha256) "support topology manifest hash mismatch"
    $manifest = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json -Depth 12 -ErrorAction Stop
    Assert-ClosedJsonProperties -Object $manifest -Expected @(
        "schema", "created_utc", "topology_plan_sha256",
        "provisioning_source_manifest_sha256", "provisioning_source_bundle_sha256", "vm",
        "source_checkpoint", "lab_checkpoint", "management_adapter", "support",
        "protected_host_tun", "constraints"
    ) -Label "support topology manifest"
    Assert-ClosedJsonProperties -Object $manifest.vm -Expected @(
        "name", "id", "terminal_state", "automatic_checkpoints_enabled"
    ) -Label "support topology manifest VM"
    Assert-ClosedJsonProperties -Object $manifest.lab_checkpoint -Expected @(
        "name", "id", "type", "parent_id", "support_vm_adapter_snapshot_id",
        "restore_verified"
    ) -Label "support topology manifest lab checkpoint"
    Assert-ClosedJsonProperties -Object $manifest.support -Expected @(
        "switch", "vm_adapter", "guest"
    ) -Label "support topology manifest support"
    Assert-ClosedJsonProperties -Object $manifest.support.switch -Expected @(
        "switch_name", "switch_id", "switch_type", "management_os_adapter_id",
        "management_os_device_id", "host_interface_alias", "host_interface_guid",
        "host_interface_index", "host_mac_address", "host_ipv4", "prefix_length", "network",
        "gateway", "dns_servers", "mtu_bytes", "nat_enabled", "ics_enabled",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) -Label "support topology manifest switch"
    Assert-ClosedJsonProperties -Object $manifest.support.vm_adapter -Expected @(
        "name", "id", "switch_id", "mac_address", "dynamic_mac_address",
        "virtual_system_identifiers"
    ) -Label "support topology manifest VM adapter"
    Assert-ClosedJsonProperties -Object $manifest.support.guest -Expected @(
        "schema", "management_interface_alias", "management_interface_guid",
        "management_interface_index", "management_mac_address", "support_interface_alias",
        "support_interface_guid", "support_interface_index", "support_mac_address", "guest_ipv4",
        "prefix_length", "network", "gateway", "dns_servers", "mtu_bytes",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) -Label "support topology manifest guest"
    Assert-ClosedJsonProperties -Object $manifest.protected_host_tun -Expected @(
        "present", "name", "interface_guid", "interface_index", "status"
    ) -Label "support topology manifest protected host TUN"
    Assert-ClosedJsonProperties -Object $manifest.constraints -Expected @(
        "nat", "ics", "gateway", "dns", "firewall_mutation", "default_switch_mutation",
        "host_tun_mutation"
    ) -Label "support topology manifest constraints"
    $topology = $Ledger.topology
    Assert-True ($manifest.schema -is [long] -and [long]$manifest.schema -eq 1 -and
        [string]$manifest.topology_plan_sha256 -ceq [string]$topology.plan_sha256 -and
        [string]$manifest.provisioning_source_manifest_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$manifest.provisioning_source_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$manifest.vm.name -ceq [string]$Ledger.vm_name -and
        [string]$manifest.vm.id -ceq [string]$Ledger.vm_id -and
        [string]$manifest.vm.terminal_state -ceq "Off" -and
        $manifest.vm.automatic_checkpoints_enabled -is [bool] -and
        $manifest.vm.automatic_checkpoints_enabled -eq $false -and
        [string]$manifest.lab_checkpoint.name -ceq [string]$Ledger.checkpoint_name -and
        [string]$manifest.lab_checkpoint.id -ceq [string]$Ledger.checkpoint_id -and
        [string]$manifest.lab_checkpoint.type -ceq "Standard" -and
        $manifest.lab_checkpoint.restore_verified -is [bool] -and
        $manifest.lab_checkpoint.restore_verified -eq $true) "support topology manifest VM or checkpoint identity mismatch"
    $switch = $manifest.support.switch
    $guest = $manifest.support.guest
    Assert-True ([string]$switch.switch_id -ceq [string]$topology.support_switch_id -and
        [string]$switch.switch_type -ceq "Internal" -and
        [string]$switch.host_ipv4 -ceq [string]$topology.support_host_ipv4 -and
        [string]$switch.network -ceq [string]$topology.support_network -and
        [long]$switch.prefix_length -eq [long]$topology.support_prefix_length -and
        $null -eq $switch.gateway -and @($switch.dns_servers).Count -eq 0 -and
        $switch.nat_enabled -is [bool] -and $switch.nat_enabled -eq $false -and
        $switch.ics_enabled -is [bool] -and $switch.ics_enabled -eq $false -and
        [string]$switch.selected_source_ipv4 -ceq [string]$topology.support_host_ipv4 -and
        [string]$switch.selected_route_prefix -ceq [string]$topology.support_network -and
        [string]$switch.selected_route_next_hop -ceq "0.0.0.0") "support topology manifest host isolation mismatch"
    Assert-True ([string]$guest.support_interface_alias -ceq [string]$topology.guest_interface_alias -and
        [string]$guest.support_interface_guid -ceq [string]$topology.guest_interface_guid -and
        [long]$guest.support_interface_index -eq [long]$topology.guest_interface_index -and
        [string]$guest.support_mac_address -ceq [string]$topology.guest_mac_address -and
        [string]$guest.guest_ipv4 -ceq [string]$topology.guest_ipv4 -and
        [long]$guest.prefix_length -eq [long]$topology.support_prefix_length -and
        [string]$guest.network -ceq [string]$topology.support_network -and
        [long]$guest.mtu_bytes -eq [long]$topology.guest_mtu_bytes -and
        $null -eq $guest.gateway -and @($guest.dns_servers).Count -eq 0 -and
        [string]$guest.selected_source_ipv4 -ceq [string]$topology.guest_ipv4 -and
        [string]$guest.selected_route_prefix -ceq [string]$topology.support_network -and
        [string]$guest.selected_route_next_hop -ceq "0.0.0.0") "support topology manifest guest isolation mismatch"
    Assert-True ($manifest.protected_host_tun.present -is [bool] -and
        $manifest.protected_host_tun.present -eq $true -and
        [string]$manifest.protected_host_tun.name -ceq [string]$topology.protected_host_tun_name -and
        [string]$manifest.protected_host_tun.interface_guid -ceq [string]$topology.protected_host_tun_guid -and
        [long]$manifest.protected_host_tun.interface_index -eq [long]$topology.protected_host_tun_index -and
        [string]$manifest.protected_host_tun.status -ceq [string]$topology.protected_host_tun_status -and
        [string]$manifest.constraints.nat -ceq "absent" -and
        [string]$manifest.constraints.ics -ceq "absent" -and
        [string]$manifest.constraints.gateway -ceq "absent" -and
        [string]$manifest.constraints.dns -ceq "absent_on_support_interfaces" -and
        [string]$manifest.constraints.firewall_mutation -ceq "none" -and
        [string]$manifest.constraints.default_switch_mutation -ceq "none" -and
        [string]$manifest.constraints.host_tun_mutation -ceq "none") "support topology manifest isolation constraints mismatch"
    return [pscustomobject]@{ Path = $resolved; Sha256 = $actualHash; Value = $manifest }
}

function Read-M17GuestNetworkPath([string]$Path, [object]$Ledger) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path)) "M17 qualification requires GuestNetworkPath"
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-NotReparsePoint $resolved "guest support network path"
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    Assert-True (-not $item.PSIsContainer -and $item.Length -ge 2 -and $item.Length -le 65536) "guest support network path file boundary is invalid"
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    Assert-True ($bytes[-1] -eq 10 -and @($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and
        @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0 -and
        -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and
            $bytes[2] -eq 0xbf)) "guest support network path must be one BOM-free LF-terminated UTF-8 document"
    $value = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json -Depth 5 -ErrorAction Stop
    $fields = @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
        "guest_route_next_hop", "guest_dns_servers"
    )
    Assert-True ((@($value.PSObject.Properties.Name) -join "|") -ceq ($fields -join "|")) "guest support network path property order is invalid"
    $topology = $Ledger.topology
    Assert-True ($value.schema -is [long] -and [long]$value.schema -eq 2 -and
        [string]$value.support_ipv4 -ceq [string]$topology.support_host_ipv4 -and
        [string]$value.support_ipv4 -ceq [string]$Ledger.support_listener.ipv4 -and
        [string]$value.guest_ipv4 -ceq [string]$topology.guest_ipv4 -and
        [long]$value.guest_prefix_length -eq [long]$topology.support_prefix_length -and
        [long]$value.guest_interface_index -eq [long]$topology.guest_interface_index -and
        [string]$value.guest_interface_alias -ceq [string]$topology.guest_interface_alias -and
        [string]$value.guest_interface_guid -ceq [string]$topology.guest_interface_guid -and
        [long]$value.guest_interface_mtu_bytes -eq [long]$topology.guest_mtu_bytes -and
        [string]$value.guest_mac_address -ceq [string]$topology.guest_mac_address -and
        [string]$value.guest_route_prefix -ceq [string]$topology.support_network -and
        [string]$value.guest_route_next_hop -ceq "0.0.0.0" -and
        @($value.guest_dns_servers).Count -eq 0) "guest support network path does not match the identity ledger"
    return [pscustomobject]@{
        Path = $resolved
        Sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        Length = [long]$bytes.Length
        Value = $value
    }
}

function Assert-M17ExternalIdentityInputsUnchanged {
    Assert-True ($null -ne $script:capabilityIdentity.TopologyManifest -and
        $null -ne $script:m17GuestNetworkPathDocument) "M17 external identity inputs are unavailable"
    $manifestItem = Get-Item -LiteralPath $script:capabilityIdentity.TopologyManifest.Path `
        -Force -ErrorAction Stop
    $pathItem = Get-Item -LiteralPath $script:m17GuestNetworkPathDocument.Path `
        -Force -ErrorAction Stop
    Assert-True (-not $manifestItem.PSIsContainer -and
        (Get-FileHash -LiteralPath $manifestItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$script:capabilityIdentity.TopologyManifest.Sha256 -and
        -not $pathItem.PSIsContainer -and
        [long]$pathItem.Length -eq [long]$script:m17GuestNetworkPathDocument.Length -and
        (Get-FileHash -LiteralPath $pathItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$script:m17GuestNetworkPathDocument.Sha256) "M17 external identity input changed during the run"
}

function Get-NetworkFeasibilityIdentity([string]$Path, [bool]$RequireServer) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Path)) "network feasibility requires IdentityLedger"
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $bytes = [IO.File]::ReadAllBytes($resolved)
    Assert-True ($bytes.Length -gt 1 -and $bytes[$bytes.Length - 1] -eq 10) "identity ledger must end in one LF"
    Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf)) "identity ledger must not have a BOM"
    Assert-True (@($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0) "identity ledger must be one LF-terminated line"
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString($bytes)
    $json = $text.Substring(0, $text.Length - 1)
    $jsonDocument = [Text.Json.JsonDocument]::Parse($json)
    try {
        $supportCreationUtcText = $jsonDocument.RootElement.GetProperty(
            "support_listener"
        ).GetProperty("creation_utc").GetString()
    } finally {
        $jsonDocument.Dispose()
    }
    $ledger = $json | ConvertFrom-Json -Depth 6
    $supportCreationUtcRuntime = $ledger.support_listener.creation_utc
    $canonicalSupportCreationUtc = if ($supportCreationUtcRuntime -is [DateTime]) {
        ([DateTime]$supportCreationUtcRuntime).ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture)
    } else { $null }
    Assert-True ($supportCreationUtcRuntime -is [DateTime] -and
        ([DateTime]$supportCreationUtcRuntime).Kind -eq [DateTimeKind]::Utc -and
        $supportCreationUtcText -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$' -and
        $supportCreationUtcText -ceq $canonicalSupportCreationUtc -and
        [DateTime]$supportCreationUtcRuntime -le [DateTime]::UtcNow.AddMinutes(5)) "support listener creation time is invalid"
    $ledger.support_listener.creation_utc = $canonicalSupportCreationUtc
    $keys = @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id", "guest_product",
        "guest_edition", "guest_architecture", "guest_version", "guest_build", "candidate_sha",
        "probe_sha256", "controller_bundle_sha256", "client_sha256", "server_sha256",
        "support_listener", "topology"
    )
    Assert-True ((@($ledger.PSObject.Properties.Name) -join "|") -ceq ($keys -join "|")) "identity ledger keys are invalid"
    $listenerKeys = @(
        "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256", "creation_utc"
    )
    Assert-True ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -ceq ($listenerKeys -join "|")) "support listener keys are invalid"
    $topologyKeys = @(
        "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
        "support_network", "support_prefix_length", "guest_interface_alias",
        "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
        "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
        "protected_host_tun_index", "protected_host_tun_status"
    )
    Assert-True ((@($ledger.topology.PSObject.Properties.Name) -join "|") -ceq ($topologyKeys -join "|")) "identity ledger topology keys are invalid"
    Assert-True (($ledger | ConvertTo-Json -Compress -Depth 6) -ceq $json) "identity ledger is not canonical JSON"
    Assert-True ($ledger.schema -is [long] -and $ledger.schema -eq 4) "identity ledger schema is invalid"
    Assert-True ([string]$ledger.vm_name -cmatch '^[^\r\n]{1,128}$') "identity ledger VM name is invalid"
    Assert-True ([string]$ledger.checkpoint_name -cmatch '^[^\r\n]{1,128}$') "identity ledger checkpoint name is invalid"
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.vm_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger VM ID is invalid"
    $script:expectedHyperVVmName = [string]$ledger.vm_name
    $script:expectedHyperVVmId = $parsedGuid.ToString("D")
    $parsedGuid = [Guid]::Empty
    Assert-True ([Guid]::TryParseExact([string]$ledger.checkpoint_id, "D", [ref]$parsedGuid) -and $parsedGuid -ne [Guid]::Empty) "identity ledger checkpoint ID is invalid"
    $script:expectedHyperVCheckpointName = [string]$ledger.checkpoint_name
    $script:expectedHyperVCheckpointId = $parsedGuid.ToString("D")
    Assert-True ([string]$ledger.candidate_sha -cmatch '^[0-9a-f]{40}$') "identity ledger candidate SHA is invalid"
    Assert-True ([string]$ledger.probe_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger probe hash is invalid"
    Assert-True ([string]$ledger.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$') `
        "identity ledger controller bundle hash is invalid"
    Assert-True ([string]$ledger.client_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger client hash is invalid"
    Assert-True ([string]$ledger.server_sha256 -cmatch '^[0-9a-f]{64}$') "identity ledger server hash is invalid"
    $probePath = (Resolve-Path -LiteralPath `
        $script:controllerEntryPointPath -ErrorAction Stop).Path
    $probeHash = (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($ledger.probe_sha256 -ceq $probeHash) "identity ledger probe hash mismatch"
    Assert-True ($ledger.controller_bundle_sha256 -ceq
        [string]$script:controllerBundleManifest.controller_bundle_sha256) `
        "identity ledger controller bundle hash mismatch"
    Assert-True (Test-Path -LiteralPath $binary) "staged candidate binary is missing"
    $clientHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($ledger.client_sha256 -ceq $clientHash) "staged client hash mismatch"
    if (Test-Path -LiteralPath $serverBinary) {
        $serverHash = (Get-FileHash -LiteralPath $serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-True ($ledger.server_sha256 -ceq $serverHash) "staged server hash mismatch"
    } else {
        Assert-True (-not $RequireServer) "staged server binary is missing"
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $version = [Environment]::OSVersion.Version.ToString()
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
    Assert-True ($ledger.guest_product -ceq [string]$currentVersion.ProductName) "identity ledger guest product mismatch"
    Assert-True ($ledger.guest_edition -ceq [string]$currentVersion.EditionID) "identity ledger guest edition mismatch"
    Assert-True ($ledger.guest_architecture -ceq "AMD64" -and [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "X64") "identity ledger guest architecture mismatch"
    Assert-True ($ledger.guest_version -ceq $version) "identity ledger guest version mismatch"
    Assert-True ($ledger.guest_build -ceq $build -and [string]$os.BuildNumber -ceq [string]$currentVersion.CurrentBuildNumber) "identity ledger guest build mismatch"

    $address = $null
    Assert-True ([Net.IPAddress]::TryParse([string]$ledger.support_listener.ipv4, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) "support listener address is not IPv4"
    $octets = $address.GetAddressBytes()
    Assert-True (-not [Net.IPAddress]::IsLoopback($address) -and $octets[0] -ne 0 -and $octets[0] -lt 224 -and -not ($octets[0] -eq 169 -and $octets[1] -eq 254)) "support listener address is not eligible"
    Assert-True (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $address.IPAddressToString -ErrorAction SilentlyContinue).Count -eq 0) "support listener address is guest-local"
    Assert-True ($ledger.support_listener.tcp_port -is [long] -and
        [long]$ledger.support_listener.tcp_port -ge 1 -and
        [long]$ledger.support_listener.tcp_port -le 65535) "support listener TCP port is invalid"
    Assert-True ($ledger.support_listener.udp_port -is [long] -and
        [long]$ledger.support_listener.udp_port -ge 1 -and
        [long]$ledger.support_listener.udp_port -le 65532) "support listener UDP port is invalid"
    Assert-True ($ledger.support_listener.pid -is [long] -and
        [long]$ledger.support_listener.pid -ge 1 -and
        [long]$ledger.support_listener.pid -le [int]::MaxValue) "support listener PID is invalid"
    Assert-True ([string]$ledger.support_listener.owner -cmatch
        '^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$') "support listener owner is invalid"
    Assert-True ([string]$ledger.support_listener.executable_sha256 -cmatch '^[0-9a-f]{64}$') "support listener executable hash is invalid"

    $topology = $ledger.topology
    foreach ($name in @("manifest_sha256", "plan_sha256")) {
        Assert-True ([string]$topology.$name -cmatch '^[0-9a-f]{64}$') "identity ledger topology hash is invalid: $name"
    }
    foreach ($name in @("support_switch_id", "guest_interface_guid", "protected_host_tun_guid")) {
        $topologyGuid = [Guid]::Empty
        Assert-True ([Guid]::TryParseExact([string]$topology.$name, "D", [ref]$topologyGuid) -and
            $topologyGuid -ne [Guid]::Empty) "identity ledger topology GUID is invalid: $name"
    }
    $supportNetwork = [Net.IPNetwork]::Parse([string]$topology.support_network)
    $supportHostAddress = [Net.IPAddress]::Parse([string]$topology.support_host_ipv4)
    $supportGuestAddress = [Net.IPAddress]::Parse([string]$topology.guest_ipv4)
    Assert-True ($supportNetwork.BaseAddress.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetwork -and
        $supportNetwork.PrefixLength -eq 30 -and
        $supportNetwork.Contains($supportHostAddress) -and
        $supportNetwork.Contains($supportGuestAddress) -and
        [string]$supportHostAddress -cne [string]$supportGuestAddress -and
        $topology.support_prefix_length -is [long] -and
        [long]$topology.support_prefix_length -eq 30 -and
        -not [string]::IsNullOrWhiteSpace([string]$topology.guest_interface_alias) -and
        $topology.guest_interface_index -is [long] -and [long]$topology.guest_interface_index -gt 0 -and
        [string]$topology.guest_mac_address -cmatch '^[0-9A-F]{12}$' -and
        $topology.guest_mtu_bytes -is [long] -and
        [long]$topology.guest_mtu_bytes -ge 1468 -and
        [string]$topology.protected_host_tun_name -ceq "tun0" -and
        $topology.protected_host_tun_index -is [long] -and [long]$topology.protected_host_tun_index -gt 0 -and
        [string]$topology.protected_host_tun_status -ceq "Up" -and
        [string]$ledger.support_listener.ipv4 -ceq [string]$topology.support_host_ipv4) "identity ledger isolated support topology is invalid"
    $topologyManifestDocument = Read-M17TopologyManifest $TopologyManifest $ledger

    return [pscustomobject]@{
        Ledger = $ledger
        Path = $resolved
        IdentitySha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        GuestBuild = $build
        SupportAddress = $address.IPAddressToString
        TcpPort = [int]$ledger.support_listener.tcp_port
        UdpPort = [int]$ledger.support_listener.udp_port
        TopologyManifest = $topologyManifestDocument
    }
}
