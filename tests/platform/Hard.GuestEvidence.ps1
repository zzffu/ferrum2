function Read-StagedTopologyManifest([string]$Path, [object]$Manifest) {
    Assert-StagedFile $Path $Manifest.files.topology_manifest `
        "topology-manifest.json" 2 131072 "support topology manifest"
    $bytes = [IO.File]::ReadAllBytes($Path)
    Assert-True (
        $bytes[-1] -eq 10 -and
        @($bytes | Where-Object { $_ -eq 10 }).Count -eq 1 -and
        @($bytes | Where-Object { $_ -eq 13 }).Count -eq 0 -and
        -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
            $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    ) "support topology manifest framing is invalid"
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-NoDuplicateJsonProperties $text "support topology manifest"
    $topologyManifest = $text | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    Assert-ClosedProperties $topologyManifest @(
        "schema", "created_utc", "topology_plan_sha256", "inspector_sha256",
        "provisioning_library_sha256", "provisioning_script_sha256", "vm",
        "source_checkpoint", "qualification_checkpoint", "management_adapter", "support",
        "protected_host_tun", "constraints"
    ) "support topology manifest"
    Assert-ClosedProperties $topologyManifest.vm @(
        "name", "id", "terminal_state", "automatic_checkpoints_enabled"
    ) "support topology manifest VM"
    Assert-ClosedProperties $topologyManifest.source_checkpoint @(
        "name", "id", "type"
    ) "support topology manifest source checkpoint"
    Assert-ClosedProperties $topologyManifest.qualification_checkpoint @(
        "name", "id", "type", "parent_id", "support_vm_adapter_snapshot_id",
        "restore_verified"
    ) "support topology manifest qualification checkpoint"
    Assert-ClosedProperties $topologyManifest.management_adapter @(
        "name", "id", "switch_name", "switch_id", "mac_address",
        "dynamic_mac_address", "guest_interface_alias", "guest_interface_guid"
    ) "support topology manifest management adapter"
    Assert-ClosedProperties $topologyManifest.support @(
        "switch", "vm_adapter", "guest"
    ) "support topology manifest support"
    Assert-ClosedProperties $topologyManifest.support.switch @(
        "switch_name", "switch_id", "switch_type", "management_os_adapter_id",
        "management_os_device_id", "host_interface_alias", "host_interface_guid",
        "host_interface_index", "host_mac_address", "host_ipv4", "prefix_length", "network",
        "gateway", "dns_servers", "mtu_bytes", "nat_enabled", "ics_enabled",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) "support topology manifest switch"
    Assert-ClosedProperties $topologyManifest.support.vm_adapter @(
        "name", "id", "switch_id", "mac_address", "dynamic_mac_address",
        "virtual_system_identifiers"
    ) "support topology manifest VM adapter"
    Assert-ClosedProperties $topologyManifest.support.guest @(
        "schema", "management_interface_alias", "management_interface_guid",
        "management_interface_index", "management_mac_address", "support_interface_alias",
        "support_interface_guid", "support_interface_index", "support_mac_address", "guest_ipv4",
        "prefix_length", "network", "gateway", "dns_servers", "mtu_bytes",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    ) "support topology manifest guest"
    Assert-ClosedProperties $topologyManifest.protected_host_tun @(
        "present", "name", "interface_guid", "interface_index", "status"
    ) "support topology manifest protected host TUN"
    Assert-ClosedProperties $topologyManifest.constraints @(
        "nat", "ics", "gateway", "dns", "firewall_mutation", "default_switch_mutation",
        "host_tun_mutation"
    ) "support topology manifest constraints"

    $actualSha256 = Get-LowerSha256 $Path
    $derivedTopology = [pscustomobject][ordered]@{
        manifest_sha256 = $actualSha256
        plan_sha256 = [string]$topologyManifest.topology_plan_sha256
        support_switch_id = [string]$topologyManifest.support.switch.switch_id
        support_host_ipv4 = [string]$topologyManifest.support.switch.host_ipv4
        support_network = [string]$topologyManifest.support.guest.network
        support_prefix_length = [long]$topologyManifest.support.guest.prefix_length
        guest_interface_alias = [string]$topologyManifest.support.guest.support_interface_alias
        guest_interface_guid = [string]$topologyManifest.support.guest.support_interface_guid
        guest_interface_index = [long]$topologyManifest.support.guest.support_interface_index
        guest_mac_address = [string]$topologyManifest.support.guest.support_mac_address
        guest_ipv4 = [string]$topologyManifest.support.guest.guest_ipv4
        guest_mtu_bytes = [long]$topologyManifest.support.guest.mtu_bytes
        protected_host_tun_name = [string]$topologyManifest.protected_host_tun.name
        protected_host_tun_guid = [string]$topologyManifest.protected_host_tun.interface_guid
        protected_host_tun_index = [long]$topologyManifest.protected_host_tun.interface_index
        protected_host_tun_status = [string]$topologyManifest.protected_host_tun.status
    }
    Assert-TopologyEqual $Manifest.topology $derivedTopology `
        "staged input and support topology manifest"
    Assert-CanonicalGuid $topologyManifest.source_checkpoint.id `
        "support topology manifest source checkpoint"
    Assert-CanonicalGuid $topologyManifest.qualification_checkpoint.parent_id `
        "support topology manifest qualification checkpoint parent"
    Assert-CanonicalGuid $topologyManifest.management_adapter.switch_id `
        "support topology manifest management switch"
    Assert-CanonicalGuid $topologyManifest.management_adapter.guest_interface_guid `
        "support topology manifest management guest interface"
    Assert-CanonicalGuid $topologyManifest.support.vm_adapter.switch_id `
        "support topology manifest VM adapter switch"
    foreach ($identifier in @($topologyManifest.support.vm_adapter.virtual_system_identifiers)) {
        Assert-CanonicalGuid $identifier "support topology manifest VM adapter identifier"
    }
    Assert-True (
        $topologyManifest.schema -eq 1 -and
        $topologyManifest.vm.name -ceq $Manifest.vm_name -and
        $topologyManifest.vm.id -ceq $Manifest.vm_id -and
        $topologyManifest.vm.terminal_state -ceq "Off" -and
        $topologyManifest.vm.automatic_checkpoints_enabled -is [bool] -and
        -not $topologyManifest.vm.automatic_checkpoints_enabled -and
        $topologyManifest.qualification_checkpoint.name -ceq $Manifest.checkpoint_name -and
        $topologyManifest.qualification_checkpoint.id -ceq $Manifest.checkpoint_id -and
        $topologyManifest.qualification_checkpoint.type -ceq "Standard" -and
        $topologyManifest.qualification_checkpoint.parent_id -ceq
            $topologyManifest.source_checkpoint.id -and
        $topologyManifest.qualification_checkpoint.restore_verified -is [bool] -and
        $topologyManifest.qualification_checkpoint.restore_verified -and
        $topologyManifest.management_adapter.dynamic_mac_address -is [bool] -and
        $topologyManifest.management_adapter.dynamic_mac_address -and
        $topologyManifest.support.switch.switch_type -ceq "Internal" -and
        $null -eq $topologyManifest.support.switch.gateway -and
        @($topologyManifest.support.switch.dns_servers).Count -eq 0 -and
        $topologyManifest.support.switch.nat_enabled -is [bool] -and
        -not $topologyManifest.support.switch.nat_enabled -and
        $topologyManifest.support.switch.ics_enabled -is [bool] -and
        -not $topologyManifest.support.switch.ics_enabled -and
        $null -eq $topologyManifest.support.guest.gateway -and
        @($topologyManifest.support.guest.dns_servers).Count -eq 0 -and
        $topologyManifest.support.vm_adapter.dynamic_mac_address -is [bool] -and
        -not $topologyManifest.support.vm_adapter.dynamic_mac_address -and
        @($topologyManifest.support.vm_adapter.virtual_system_identifiers).Count -eq 2 -and
        $topologyManifest.protected_host_tun.present -is [bool] -and
        $topologyManifest.protected_host_tun.present -and
        $topologyManifest.constraints.nat -ceq "absent" -and
        $topologyManifest.constraints.ics -ceq "absent" -and
        $topologyManifest.constraints.gateway -ceq "absent" -and
        $topologyManifest.constraints.dns -ceq "absent_on_support_interfaces" -and
        $topologyManifest.constraints.firewall_mutation -ceq "none" -and
        $topologyManifest.constraints.default_switch_mutation -ceq "none" -and
        $topologyManifest.constraints.host_tun_mutation -ceq "none"
    ) "staged support topology manifest identity or isolation contract is invalid"
    return $topologyManifest
}

function Invoke-GuestNetworkPathProbe(
    [string]$Path,
    [object]$Topology,
    [int]$SupportPort,
    [string]$ManagedAdapterName,
    [string]$OutputPath
) {
    Assert-True (-not (Test-Path -LiteralPath $OutputPath)) `
        "guest network-path output baseline is not absent"
    $arguments = @(
        "-NoProfile", "-File", $Path,
        "-SupportIpv4", [string]$Topology.support_host_ipv4,
        "-SupportPort", [string]$SupportPort,
        "-ExpectedGuestIpv4", [string]$Topology.guest_ipv4,
        "-ExpectedInterfaceAlias", [string]$Topology.guest_interface_alias,
        "-ExpectedNetwork", [string]$Topology.support_network,
        "-ExpectedPrefixLength", [string]$Topology.support_prefix_length,
        "-ExpectedMacAddress", [string]$Topology.guest_mac_address,
        "-ExpectedInterfaceGuid", [string]$Topology.guest_interface_guid,
        "-ExpectedMtuBytes", [string]$Topology.guest_mtu_bytes,
        "-ManagedAdapterName", $ManagedAdapterName,
        "-MinimumUnderlayIpv4PacketBytes", "1468",
        "-AsJson"
    )
    $output = @(& $script:pwsh @arguments 2>&1)
    $exitCode = [int]$LASTEXITCODE
    $lines = @($output | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            [string]$_.Exception.Message
        } else {
            [string]$_
        }
    })
    Assert-True ($exitCode -eq 0 -and $lines.Count -eq 1) `
        "guest isolated network-path probe failed: exit=$exitCode output=$($lines -join ' | ')"
    $pathValue = $lines[0] | ConvertFrom-Json -Depth 5 -ErrorAction Stop
    Assert-ClosedProperties $pathValue @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
        "guest_route_next_hop", "guest_dns_servers"
    ) "guest isolated network path"
    Assert-True (
        (Test-JsonInteger $pathValue.schema) -and [long]$pathValue.schema -eq 2 -and
        $pathValue.support_ipv4 -ceq [string]$Topology.support_host_ipv4 -and
        $pathValue.guest_ipv4 -ceq [string]$Topology.guest_ipv4 -and
        (Test-JsonInteger $pathValue.guest_prefix_length) -and
        [int]$pathValue.guest_prefix_length -eq [int]$Topology.support_prefix_length -and
        (Test-JsonInteger $pathValue.guest_interface_index) -and
        [int]$pathValue.guest_interface_index -eq [int]$Topology.guest_interface_index -and
        $pathValue.guest_interface_alias -ceq [string]$Topology.guest_interface_alias -and
        $pathValue.guest_interface_guid -ceq [string]$Topology.guest_interface_guid -and
        (Test-JsonInteger $pathValue.guest_interface_mtu_bytes) -and
        [int]$pathValue.guest_interface_mtu_bytes -eq [int]$Topology.guest_mtu_bytes -and
        $pathValue.guest_mac_address -ceq [string]$Topology.guest_mac_address -and
        $pathValue.guest_route_prefix -ceq [string]$Topology.support_network -and
        $pathValue.guest_route_next_hop -ceq "0.0.0.0" -and
        @($pathValue.guest_dns_servers).Count -eq 0
    ) "guest isolated network path does not match the staged topology"
    Write-BytesCreateNew $OutputPath (
        [Text.UTF8Encoding]::new($false).GetBytes($lines[0] + "`n")
    )
    Assert-OrdinaryLeaf $OutputPath "guest network-path output" 2 65536
    Assert-True ((Get-Content -LiteralPath $OutputPath -Raw -Encoding utf8) -ceq
        ($lines[0] + "`n")) "guest network-path output changed during durable write"
    return $pathValue
}

function Read-CanonicalIdentityLedger([string]$Path, [object]$Manifest) {
    Assert-StagedFile $Path $Manifest.files.identity_ledger "identity-ledger.json" 2 65536 `
        "identity ledger"
    $bytes = [IO.File]::ReadAllBytes($Path)
    Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
            $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) "identity ledger must not contain a BOM"
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-True ($text.EndsWith("`n", [StringComparison]::Ordinal) -and
        -not $text.EndsWith("`n`n", [StringComparison]::Ordinal) -and
        -not $text.Contains("`r")) "identity ledger framing is not canonical"
    $jsonDocument = [Text.Json.JsonDocument]::Parse($text)
    try {
        $supportCreationUtcText = $jsonDocument.RootElement.GetProperty(
            "support_listener"
        ).GetProperty("creation_utc").GetString()
    } finally {
        $jsonDocument.Dispose()
    }
    $ledger = $text | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $ledger.support_listener.creation_utc = $supportCreationUtcText
    Assert-ClosedProperties $ledger @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
        "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
        "candidate_sha", "probe_sha256", "controller_bundle_sha256",
        "client_sha256", "server_sha256", "support_listener",
        "topology", "test_binaries"
    ) "identity ledger"
    Assert-SupportListenerContract $ledger.support_listener "identity support listener"
    Assert-TopologyContract $ledger.topology "identity topology"
    Assert-ClosedProperties $ledger.test_binaries @("client", "tun", "wintun") `
        "identity test binaries"
    $canonical = ($ledger | ConvertTo-Json -Compress -Depth 8) + "`n"
    Assert-True ([Convert]::ToHexString([Text.UTF8Encoding]::new($false).GetBytes($canonical)) -ceq
        [Convert]::ToHexString($bytes)) "identity ledger serialization is not canonical"
    Assert-True (
        $ledger.schema -eq 3 -and
        $ledger.vm_name -ceq $Manifest.vm_name -and
        $ledger.vm_id -ceq $Manifest.vm_id -and
        $ledger.checkpoint_name -ceq $Manifest.checkpoint_name -and
        $ledger.checkpoint_id -ceq $Manifest.checkpoint_id -and
        $ledger.guest_product -ceq $Manifest.guest_product -and
        $ledger.guest_edition -ceq $Manifest.guest_edition -and
        $ledger.guest_architecture -ceq $Manifest.guest_architecture -and
        $ledger.guest_version -ceq $Manifest.guest_version -and
        $ledger.guest_build -ceq $Manifest.guest_build -and
        $ledger.candidate_sha -ceq $Manifest.candidate_sha -and
        (Get-LowerSha256 $Path) -ceq $Manifest.identity_sha256
    ) "identity ledger does not close over the staged guest and candidate"
    Assert-TopologyEqual $Manifest.topology $ledger.topology `
        "identity ledger and staged input"
    Assert-True (
        [string]$ledger.support_listener.ipv4 -ceq
            [string]$ledger.topology.support_host_ipv4
    ) "identity support listener is not bound to the isolated topology"
    foreach ($name in @(
            "probe_sha256", "controller_bundle_sha256", "client_sha256", "server_sha256"
        )) {
        Assert-True ([string]$ledger.$name -cmatch '^[0-9a-f]{64}$') `
            "identity ledger hash is invalid: $name"
    }
    foreach ($name in @("client", "tun", "wintun")) {
        Assert-True ([string]$ledger.test_binaries.$name -cmatch '^[0-9a-f]{64}$') `
            "identity test hash is invalid: $name"
    }
    return $ledger
}

function Invoke-CapturedPwsh(
    [string[]]$Arguments,
    [string]$StdoutPath,
    [string]$StderrPath,
    [bool]$ProvideWintunZip,
    [int]$TimeoutSeconds
) {
    Assert-True (-not (Test-Path -LiteralPath $StdoutPath) -and
        -not (Test-Path -LiteralPath $StderrPath)) "captured log baseline is not absent"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:pwsh
    $start.WorkingDirectory = $script:inputRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($ProvideWintunZip) {
        $start.Environment["FERRUM2_WINTUN_ZIP"] = $script:wintunZip
    }
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        $terminationFailure = $null
        if ($timedOut) {
            try {
                $process.Kill($true)
                if (-not $process.WaitForExit(30000)) {
                    throw "process tree did not exit within 30 seconds after termination"
                }
            } catch {
                $terminationFailure = $_
            }
        }
        $captureFailure = $null
        try {
            $captureTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
            $captureAll = [Threading.Tasks.Task]::WhenAll($captureTasks)
            if (-not $captureAll.Wait(30000)) {
                throw "redirected output did not close within 30 seconds"
            }
        } catch {
            $captureFailure = $_
        }
        $stdout = if ($stdoutTask.IsCompletedSuccessfully) {
            $stdoutTask.GetAwaiter().GetResult()
        } else { "" }
        $stderr = if ($stderrTask.IsCompletedSuccessfully) {
            $stderrTask.GetAwaiter().GetResult()
        } else { "" }
        Assert-True (
            [Text.Encoding]::UTF8.GetByteCount($stdout) -le 67108864 -and
            [Text.Encoding]::UTF8.GetByteCount($stderr) -le 67108864
        ) "captured controller output exceeded its byte boundary"
        Write-BytesCreateNew $StdoutPath ([Text.UTF8Encoding]::new($false).GetBytes($stdout))
        Write-BytesCreateNew $StderrPath ([Text.UTF8Encoding]::new($false).GetBytes($stderr))
        if ($null -ne $terminationFailure) {
            throw "captured process termination failed: $($terminationFailure.Exception.Message)"
        }
        if ($null -ne $captureFailure) {
            throw "captured process output drain failed: $($captureFailure.Exception.Message)"
        }
        if ($timedOut) {
            throw "captured controller exceeded its bounded timeout"
        }
        return [int]$process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Get-ExpectedTerminalMarker([object]$Ledger) {
    return "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS " +
        "adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT " +
        "strict_route_wfp=ABSENT cleanup=PASS " +
        "guest_build=$($Ledger.guest_build) run_token=$($script:runToken) " +
        "candidate_sha=$($Ledger.candidate_sha) probe_sha256=$($Ledger.probe_sha256) " +
        "identity_sha256=$($script:manifest.identity_sha256)"
}

function Assert-TerminalMarker([string]$Path, [object]$Ledger) {
    Assert-OrdinaryLeaf $Path "controller stdout" 1 67108864
    $expected = Get-ExpectedTerminalMarker $Ledger
    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $terminals = @($lines | Where-Object {
        $_.StartsWith("m16_windows_hard_kill ", [StringComparison]::Ordinal)
    })
    $nonempty = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-True (
        $terminals.Count -eq 1 -and
        $terminals[0] -ceq $expected -and
        $nonempty.Count -gt 0 -and
        $nonempty[-1] -ceq $expected
    ) "hard-kill terminal marker is missing, duplicated, changed, or not terminal"
}

function Assert-HardKillWfpEvidence(
    [Text.Json.JsonElement]$Value,
    [bool]$Applicable,
    [string]$Label,
    [string]$ExpectedAppIdSha256
) {
    Assert-True ($Value.ValueKind -eq [Text.Json.JsonValueKind]::Object) `
        "$Label WFP evidence is not an object"
    $properties = @($Value.EnumerateObject())
    if (-not $Applicable) {
        Assert-True (
            ($properties.Name -join "|") -ceq "applicable" -and
            $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::False
        ) "$Label route-only WFP evidence is not the closed not-applicable object"
        return
    }
    Assert-True (
        ($properties.Name -join "|") -ceq "applicable|before_kill|after_kill" -and
        $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::True -and
        $properties[1].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object -and
        $properties[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object
    ) "$Label WFP lifecycle object is not closed"
    $before = @($properties[1].Value.EnumerateObject())
    [uint64]$interfaceLuid = 0
    Assert-True (
        ($before.Name -join "|") -ceq
            "session_key|sublayer_key|owner_pid|interface_luid|app_id_sha256|filters|identity_sha256" -and
        $before[0].Value.GetString() -ceq
            "8ea35b4e-6629-4e26-9776-95c5bf9c6b01" -and
        $before[1].Value.GetString() -ceq
            "ddbc2fa2-d52f-4a79-8a63-8446c308cf02" -and
        $before[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::Number -and
        $before[2].Value.GetInt64() -gt 0 -and
        $before[2].Value.GetInt64() -le [uint32]::MaxValue -and
        $ExpectedAppIdSha256 -cmatch '^[0-9a-f]{64}$' -and
        $before[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
        $before[3].Value.GetString() -cmatch '^[1-9][0-9]{0,19}$' -and
        [uint64]::TryParse(
            $before[3].Value.GetString(),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$interfaceLuid
        ) -and $interfaceLuid -ne 0 -and
        $before[4].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
        $before[4].Value.GetString() -ceq $ExpectedAppIdSha256 -and
        $before[5].Value.ValueKind -eq [Text.Json.JsonValueKind]::Array -and
        $before[6].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
        $before[6].Value.GetString() -cmatch '^[0-9a-f]{64}$'
    ) "$Label pre-kill WFP identity is invalid"
    $expectedFilters = @(
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701001"; Name = "Ferrum2 app permit IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701002"; Name = "Ferrum2 app permit IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701003"; Name = "Ferrum2 TUN permit IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701004"; Name = "Ferrum2 TUN permit IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701007"; Name = "Ferrum2 DNS TCP block IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701008"; Name = "Ferrum2 DNS UDP block IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701009"; Name = "Ferrum2 DNS TCP block IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e870100a"; Name = "Ferrum2 DNS UDP block IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK" }
    )
    $interfaceLuidText = $before[3].Value.GetString()
    $filters = @($before[5].Value.EnumerateArray())
    Assert-True ($filters.Count -eq 8) "$Label WFP filter count is not exact"
    $ids = [Collections.Generic.List[string]]::new()
    $rows = [Collections.Generic.List[string]]::new()
    for ($filterIndex = 0; $filterIndex -lt 8; $filterIndex++) {
        $filter = @($filters[$filterIndex].EnumerateObject())
        $id = if ($filter.Count -eq 2 -and
            $filter[1].Value.ValueKind -eq [Text.Json.JsonValueKind]::String) {
            $filter[1].Value.GetString()
        } else { "" }
        [uint64]$numericId = 0
        Assert-True (
            ($filter.Name -join "|") -ceq "key|id" -and
            $filter[0].Value.GetString() -ceq $expectedFilters[$filterIndex].Key -and
            $id -cmatch '^[1-9][0-9]{0,19}$' -and
            [uint64]::TryParse($id, [ref]$numericId) -and $numericId -ne 0
        ) "$Label WFP filter identity is invalid at index $filterIndex"
        $ids.Add($id)
        $spec = $expectedFilters[$filterIndex]
        $rows.Add(
            "$($spec.Name)|{$($spec.Key)}|$id|$($spec.Layer)|$($spec.Action)|" +
                "{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}"
        )
    }
    $uniqueIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $idsAreUnique = $true
    foreach ($filterId in $ids) {
        if (-not $uniqueIds.Add($filterId)) { $idsAreUnique = $false }
    }
    Assert-True ($idsAreUnique -and $uniqueIds.Count -eq 8) `
        "$Label WFP filter IDs are not unique"
    $ownerPid = $before[2].Value.GetInt64()
    $sessionCanonical = (
        "session|{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}|" +
            "Ferrum2 strict route dynamic session|$ownerPid"
    )
    $canonical = (@(
        $sessionCanonical,
        "interface_luid|$interfaceLuidText",
        "app_id_sha256|$ExpectedAppIdSha256"
    ) + @($rows)) -join "`n"
    $identitySha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.UTF8Encoding]::new($false).GetBytes($canonical)
        )
    ).ToLowerInvariant()
    Assert-True ($before[6].Value.GetString() -ceq $identitySha256) `
        "$Label WFP identity hash does not close over the exact filters"
    $after = @($properties[2].Value.EnumerateObject())
    Assert-True (
        ($after.Name -join "|") -ceq "session|sublayer|filters" -and
        @($after | Where-Object {
            $_.Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            $_.Value.GetString() -cne "absent"
        }).Count -eq 0
    ) "$Label post-kill WFP identity is not the exact all-absent set"
}

function Assert-HardKillEvidence([string]$Path, [string]$ExpectedAppIdSha256) {
    Assert-OrdinaryLeaf $Path "hard-kill evidence" 1 1048576
    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $expectedPhases = @("hard-kill-auto-route", "hard-kill-auto-dns", "hard-kill-mixed")
    Assert-True ($lines.Count -eq 3) "hard-kill evidence must contain exactly three rows"
    for ($index = 0; $index -lt 3; $index++) {
        $document = [Text.Json.JsonDocument]::Parse($lines[$index])
        try {
            $properties = @($document.RootElement.EnumerateObject())
            Assert-True (
                ($properties.Name -join "|") -ceq "schema|phase|timestamp_utc|data" -and
                $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::Number -and
                $properties[0].Value.GetInt64() -eq 2 -and
                $properties[1].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[1].Value.GetString() -ceq $expectedPhases[$index] -and
                $properties[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object
            ) "hard-kill evidence row schema, order, type, or phase changed"
            Assert-RoundTripUtcTimestamp $properties[2].Value.GetString() `
                "hard-kill evidence timestamp"
            $data = @($properties[3].Value.EnumerateObject())
            Assert-True (
                ($data.Name -join "|") -ceq
                    "process|adapter|addresses|routes|dns|strict_route_wfp"
            ) "hard-kill evidence residue data is not closed"
            Assert-True (
                @($data[0..4] | Where-Object {
                    $_.Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                    $_.Value.GetString() -cne "absent"
                }).Count -eq 0
            ) "hard-kill evidence residue is not the exact all-absent set"
            Assert-HardKillWfpEvidence $data[5].Value ($index -ne 0) `
                $expectedPhases[$index] $ExpectedAppIdSha256
        } finally {
            $document.Dispose()
        }
    }
}

function Assert-PublishedHardKillJson([object]$Ledger) {
    $resultPath = Join-Path $script:exportRoot "hard-kill-result.json"
    $cleanupPath = Join-Path $script:exportRoot "hard-kill-cleanup.json"
    Assert-OrdinaryLeaf $resultPath "hard-kill result" 1 1048576
    Assert-OrdinaryLeaf $cleanupPath "hard-kill cleanup" 1 1048576
    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-ClosedProperties $result @(
        "schema", "status", "mode", "run_token", "identity_sha256", "candidate_sha",
        "client_sha256", "server_sha256", "controller_sha256",
        "controller_bundle_sha256", "support_listener", "topology",
        "guest_network_path", "guest_build", "cases", "process_absent", "adapter_absent",
        "addresses_absent", "routes_absent", "dns_absent", "strict_route_cases",
        "strict_route_wfp_identity_verified", "strict_route_wfp_absent", "inner_cleanup", "evidence_sha256",
        "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v3" -and
        $result.status -ceq "pass" -and
        $result.mode -ceq "hard-kill" -and
        $result.run_token -ceq $script:runToken -and
        $result.identity_sha256 -ceq [string]$script:manifest.identity_sha256 -and
        $result.candidate_sha -ceq [string]$Ledger.candidate_sha -and
        $result.client_sha256 -ceq [string]$Ledger.client_sha256 -and
        $result.server_sha256 -ceq [string]$Ledger.server_sha256 -and
        $result.controller_sha256 -ceq [string]$Ledger.probe_sha256 -and
        $result.controller_bundle_sha256 -ceq [string]$Ledger.controller_bundle_sha256 -and
        $result.guest_build -ceq [string]$Ledger.guest_build -and
        ($result.cases -is [int] -or $result.cases -is [long]) -and
        [long]$result.cases -eq 3 -and
        $result.process_absent -is [bool] -and $result.process_absent -and
        $result.adapter_absent -is [bool] -and $result.adapter_absent -and
        $result.addresses_absent -is [bool] -and $result.addresses_absent -and
        $result.routes_absent -is [bool] -and $result.routes_absent -and
        $result.dns_absent -is [bool] -and $result.dns_absent -and
        ($result.strict_route_cases -is [int] -or
            $result.strict_route_cases -is [long]) -and
        [long]$result.strict_route_cases -eq 2 -and
        $result.strict_route_wfp_identity_verified -is [bool] -and
        $result.strict_route_wfp_identity_verified -and
        $result.strict_route_wfp_absent -is [bool] -and
        $result.strict_route_wfp_absent -and
        $result.inner_cleanup -ceq "pass" -and
        $result.evidence_sha256 -ceq (Get-LowerSha256 $script:artifactEvidence) -and
        $result.stdout_sha256 -ceq (Get-LowerSha256 $script:controllerStdout) -and
        $result.stderr_sha256 -ceq (Get-LowerSha256 $script:controllerStderr)
    ) "hard-kill result identity, JSON types, status, or hashes are invalid"
    Assert-SupportListenerContract $result.support_listener `
        "hard-kill result support listener"
    foreach ($name in $script:supportListenerPropertyNames) {
        $expectedValue = if ($name -ceq "creation_utc") {
            ConvertTo-CanonicalUtcTimestamp $Ledger.support_listener.$name `
                "identity support listener creation_utc"
        } else {
            [string]$Ledger.support_listener.$name
        }
        $actualValue = if ($name -ceq "creation_utc") {
            ConvertTo-CanonicalUtcTimestamp $result.support_listener.$name `
                "hard-kill result support listener creation_utc"
        } else {
            [string]$result.support_listener.$name
        }
        Assert-True (
            $actualValue -ceq $expectedValue
        ) "hard-kill result support listener changed: $name"
    }
    Assert-TopologyEqual $Ledger.topology $result.topology "hard-kill result"
    Assert-ClosedProperties $result.guest_network_path @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
        "guest_route_next_hop", "guest_dns_servers"
    ) "hard-kill result guest network path"
    Assert-True (
        [long]$result.guest_network_path.schema -eq 2 -and
        $result.guest_network_path.support_ipv4 -ceq [string]$Ledger.topology.support_host_ipv4 -and
        $result.guest_network_path.guest_ipv4 -ceq [string]$Ledger.topology.guest_ipv4 -and
        [int]$result.guest_network_path.guest_interface_index -eq
            [int]$Ledger.topology.guest_interface_index -and
        $result.guest_network_path.guest_interface_guid -ceq
            [string]$Ledger.topology.guest_interface_guid -and
        $result.guest_network_path.guest_route_prefix -ceq
            [string]$Ledger.topology.support_network -and
        $result.guest_network_path.guest_route_next_hop -ceq "0.0.0.0" -and
        @($result.guest_network_path.guest_dns_servers).Count -eq 0
    ) "hard-kill result guest network path changed"
    Assert-UtcTimestamp $result.finished_utc "hard-kill result finished_utc"

    $cleanupProperties = @(
        "schema", "status", "source_mode", "run_token", "identity_sha256", "topology",
        "qualification_outcome", "processes", "adapters", "target_addresses", "target_routes",
        "dns_rows", "sibling_dll", "work_directories", "mutation_journals", "firewall_rules",
        "identity_journal", "finished_utc"
    )
    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-ClosedProperties $cleanup $cleanupProperties "hard-kill cleanup"
    Assert-True (
        $cleanup.schema -ceq "ferrum2.windows-tun.hard-kill-cleanup.v2" -and
        $cleanup.status -ceq "pass" -and
        $cleanup.source_mode -ceq "hard-kill" -and
        $cleanup.run_token -ceq $script:runToken -and
        $cleanup.identity_sha256 -ceq [string]$script:manifest.identity_sha256 -and
        $cleanup.qualification_outcome -ceq "success"
    ) "hard-kill cleanup identity or outcome is invalid"
    Assert-TopologyEqual $Ledger.topology $cleanup.topology "hard-kill cleanup"
    foreach ($name in $cleanupProperties[7..16]) {
        Assert-True (
            ($cleanup.$name -is [int] -or $cleanup.$name -is [long]) -and
            [long]$cleanup.$name -eq 0
        ) "hard-kill cleanup residue is not integer zero: $name"
    }
    Assert-UtcTimestamp $cleanup.finished_utc "hard-kill cleanup finished_utc"
}
