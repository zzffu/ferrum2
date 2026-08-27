function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function ConvertTo-CanonicalUtcTimestamp([object]$Value, [string]$Label) {
    $format = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $utc = $null
    if ($Value -is [DateTime]) {
        Assert-True (([DateTime]$Value).Kind -eq [DateTimeKind]::Utc) `
            "$Label is not a UTC timestamp"
        $utc = ([DateTime]$Value).ToUniversalTime()
    } elseif ($Value -is [DateTimeOffset]) {
        Assert-True (([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero) `
            "$Label is not a UTC timestamp"
        $utc = ([DateTimeOffset]$Value).UtcDateTime
    } else {
        Assert-True (
            $Value -is [string] -and
            [string]$Value -cmatch
                '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$'
        ) "$Label is not a fixed-six-digit UTC timestamp"
        [DateTimeOffset]$timestamp = [DateTimeOffset]::MinValue
        $valid = [DateTimeOffset]::TryParseExact(
            [string]$Value,
            $format,
            $culture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$timestamp
        ) -and $timestamp.Offset -eq [TimeSpan]::Zero
        Assert-True $valid "$Label is not a fixed-six-digit UTC timestamp"
        $utc = $timestamp.UtcDateTime
    }
    return $utc.ToString($format, $culture)
}

function Assert-UtcTimestamp([object]$Value, [string]$Label) {
    [void](ConvertTo-CanonicalUtcTimestamp $Value $Label)
}

function Assert-RoundTripUtcTimestamp([object]$Value, [string]$Label) {
    $format = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'"
    $culture = [Globalization.CultureInfo]::InvariantCulture
    if ($Value -is [DateTime]) {
        Assert-True (([DateTime]$Value).Kind -eq [DateTimeKind]::Utc) `
            "$Label is not a UTC DateTime"
        return
    }
    if ($Value -is [DateTimeOffset]) {
        Assert-True (([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero) `
            "$Label is not a zero-offset DateTimeOffset"
        return
    }
    Assert-True (
        $Value -is [string] -and
        [string]$Value -cmatch
            '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'
    ) "$Label is not a round-trip UTC timestamp"
    [DateTimeOffset]$timestamp = [DateTimeOffset]::MinValue
    $valid = [DateTimeOffset]::TryParseExact(
        [string]$Value,
        $format,
        $culture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$timestamp
    ) -and $timestamp.Offset -eq [TimeSpan]::Zero
    Assert-True (
        $valid -and
        $timestamp.UtcDateTime.ToString($format, $culture) -ceq [string]$Value
    ) "$Label is not a canonical round-trip UTC timestamp"
}

function New-TopologyBinding([object]$Document) {
    $manifest = $Document.Value
    return [pscustomobject][ordered]@{
        manifest_sha256 = [string]$Document.Sha256
        plan_sha256 = [string]$Document.PlanDocument.Sha256
        support_switch_id = [string]$manifest.support.switch.switch_id
        support_host_ipv4 = [string]$manifest.support.switch.host_ipv4
        support_network = [string]$manifest.support.switch.network
        support_prefix_length = [long]$manifest.support.switch.prefix_length
        guest_interface_alias = [string]$manifest.support.guest.support_interface_alias
        guest_interface_guid = [string]$manifest.support.guest.support_interface_guid
        guest_interface_index = [long]$manifest.support.guest.support_interface_index
        guest_mac_address = [string]$manifest.support.guest.support_mac_address
        guest_ipv4 = [string]$manifest.support.guest.guest_ipv4
        guest_mtu_bytes = [long]$manifest.support.guest.mtu_bytes
        protected_host_tun_name = [string]$manifest.protected_host_tun.name
        protected_host_tun_guid = [string]$manifest.protected_host_tun.interface_guid
        protected_host_tun_index = [long]$manifest.protected_host_tun.interface_index
        protected_host_tun_status = [string]$manifest.protected_host_tun.status
    }
}

function New-SupportListenerBinding([object]$Context) {
    return [pscustomobject][ordered]@{
        ipv4 = [string]$Context.ipv4
        tcp_port = [long]$Context.tcp_port
        udp_port = [long]$Context.udp_port
        pid = [long]$Context.pid
        owner = [string]$Context.owner
        executable_sha256 = [string]$Context.executable_sha256
        creation_utc = [string]$Context.creation_utc
    }
}

function Assert-ExactObjectFields(
    [object]$Expected,
    [object]$Actual,
    [string[]]$Fields,
    [string]$Label
) {
    Assert-Ferrum2ClosedProperties $Expected $Fields "$Label expected"
    Assert-Ferrum2ClosedProperties $Actual $Fields "$Label actual"
    foreach ($name in $Fields) {
        $expectedValue = if ($name -ceq "creation_utc") {
            ConvertTo-CanonicalUtcTimestamp $Expected.$name "$Label expected creation_utc"
        } else {
            [string]$Expected.$name
        }
        $actualValue = if ($name -ceq "creation_utc") {
            ConvertTo-CanonicalUtcTimestamp $Actual.$name "$Label actual creation_utc"
        } else {
            [string]$Actual.$name
        }
        Assert-True ($expectedValue -ceq $actualValue) `
            "$Label changed: $name"
    }
}

function Assert-HardKillWfpEvidence(
    [Text.Json.JsonElement]$Value,
    [bool]$Applicable,
    [string]$Label,
    [AllowNull()][string]$ExpectedAppIdSha256 = $null
) {
    Assert-True ($Value.ValueKind -eq [Text.Json.JsonValueKind]::Object) `
        "$Label WFP evidence is not an object"
    $properties = @($Value.EnumerateObject())
    if (-not $Applicable) {
        Assert-True (
            ($properties.Name -join "|") -ceq "applicable" -and
            $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::False
        ) "$Label route-only WFP evidence is not the closed not-applicable object"
        return $null
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
        $before[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
        $before[3].Value.GetString() -cmatch '^[1-9][0-9]{0,19}$' -and
        [uint64]::TryParse(
            $before[3].Value.GetString(),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$interfaceLuid
        ) -and $interfaceLuid -ne 0 -and
        $before[4].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
        $before[4].Value.GetString() -cmatch '^[0-9a-f]{64}$' -and
        ([string]::IsNullOrEmpty($ExpectedAppIdSha256) -or
            $before[4].Value.GetString() -ceq $ExpectedAppIdSha256) -and
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
    $appIdSha256 = $before[4].Value.GetString()
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
        "app_id_sha256|$appIdSha256"
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
    return $appIdSha256
}

function Assert-HardKillEvidenceRows([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (-not $item.PSIsContainer -and $item.Length -ge 1 -and
        $item.Length -le 1048576 -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "exported hard-kill evidence boundary is invalid"
    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $expectedPhases = @("hard-kill-auto-route", "hard-kill-auto-dns", "hard-kill-mixed")
    Assert-True ($lines.Count -eq 3) "exported hard-kill evidence row count is invalid"
    $expectedAppIdSha256 = $null
    for ($index = 0; $index -lt 3; $index++) {
        $document = [Text.Json.JsonDocument]::Parse($lines[$index])
        try {
            $properties = @($document.RootElement.EnumerateObject())
            Assert-True (
                ($properties.Name -join "|") -ceq "schema|phase|timestamp_utc|data" -and
                $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::Number -and
                $properties[0].Value.GetInt64() -eq 2 -and
                $properties[1].Value.GetString() -ceq $expectedPhases[$index] -and
                $properties[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object
            ) "exported hard-kill evidence schema or phase is invalid"
            Assert-RoundTripUtcTimestamp $properties[2].Value.GetString() `
                "hard-kill evidence timestamp"
            $data = @($properties[3].Value.EnumerateObject())
            Assert-True (
                ($data.Name -join "|") -ceq
                    "process|adapter|addresses|routes|dns|strict_route_wfp"
            ) "exported hard-kill evidence is not closed"
            Assert-True (
                @($data[0..4] | Where-Object {
                    $_.Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                    $_.Value.GetString() -cne "absent"
                }).Count -eq 0
            ) "exported hard-kill residue is not the exact all-absent set"
            $validatedAppIdSha256 = Assert-HardKillWfpEvidence `
                $data[5].Value ($index -ne 0) $expectedPhases[$index] `
                $expectedAppIdSha256
            if ($index -eq 1) {
                $expectedAppIdSha256 = $validatedAppIdSha256
            }
        } finally {
            $document.Dispose()
        }
    }
    Assert-True ($expectedAppIdSha256 -cmatch '^[0-9a-f]{64}$') `
        "exported hard-kill WFP AppId identity is missing"
}

function Assert-HardKillExport(
    [string]$Path,
    [object]$Ledger,
    [string]$IdentitySha256,
    [string]$CandidateSha
) {
    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($directory.PSIsContainer -and
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "hard-kill export directory is invalid"
    $items = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
    Assert-True (
        $items.Count -eq 8 -and
        (($items.Name | Sort-Object) -join "|") -ceq
            (($script:expectedArtifactFiles | Sort-Object) -join "|") -and
        @($items | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $_.Length -gt 67108864
        }).Count -eq 0
    ) "exported hard-kill artifact set is not the exact eight bounded files"

    $identityPath = Join-Path $Path "identity-ledger.json"
    $stdoutPath = Join-Path $Path "controller.stdout.log"
    $stderrPath = Join-Path $Path "controller.stderr.log"
    $evidencePath = Join-Path $Path "hard-kill-evidence.jsonl"
    $resultPath = Join-Path $Path "hard-kill-result.json"
    $cleanupPath = Join-Path $Path "hard-kill-cleanup.json"
    Assert-True ((Get-Ferrum2LowerSha256 $identityPath) -ceq $IdentitySha256) `
        "exported identity ledger hash changed"
    Assert-HardKillEvidenceRows $evidencePath

    $expectedTerminal = "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS " +
        "adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT " +
        "strict_route_wfp=ABSENT cleanup=PASS " +
        "guest_build=$($Ledger.guest_build) run_token=$($script:RunToken) " +
        "candidate_sha=$CandidateSha probe_sha256=$($Ledger.probe_sha256) " +
        "identity_sha256=$IdentitySha256"
    $stdoutLines = @(Get-Content -LiteralPath $stdoutPath -Encoding utf8 -ErrorAction Stop)
    $terminalLines = @($stdoutLines | Where-Object {
        $_.StartsWith("m16_windows_hard_kill ", [StringComparison]::Ordinal)
    })
    $nonempty = @($stdoutLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-True ($nonempty.Count -gt 0 -and
        $terminalLines.Count -eq 1 -and
        $terminalLines[0] -ceq $expectedTerminal -and
        $nonempty[-1] -ceq $expectedTerminal) "exported terminal marker is invalid"

    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-Ferrum2ClosedProperties $result @(
        "schema", "status", "mode", "run_token", "identity_sha256", "candidate_sha",
        "client_sha256", "server_sha256", "controller_sha256",
        "controller_bundle_sha256", "support_listener", "topology",
        "guest_network_path", "guest_build", "cases", "process_absent", "adapter_absent",
        "addresses_absent", "routes_absent", "dns_absent", "strict_route_cases",
        "strict_route_wfp_identity_verified", "strict_route_wfp_absent", "inner_cleanup",
        "evidence_sha256", "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v3" -and
        $result.status -ceq "pass" -and
        $result.mode -ceq "hard-kill" -and
        $result.run_token -ceq $script:RunToken -and
        $result.identity_sha256 -ceq $IdentitySha256 -and
        $result.candidate_sha -ceq $CandidateSha -and
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
        $result.evidence_sha256 -ceq (Get-Ferrum2LowerSha256 $evidencePath) -and
        $result.stdout_sha256 -ceq (Get-Ferrum2LowerSha256 $stdoutPath) -and
        $result.stderr_sha256 -ceq (Get-Ferrum2LowerSha256 $stderrPath)
    ) "exported hard-kill result identity, types, status, or hashes are invalid"
    Assert-ExactObjectFields `
        -Expected $Ledger.support_listener `
        -Actual $result.support_listener `
        -Fields $script:supportListenerPropertyNames `
        -Label "hard-kill result support listener"
    Assert-ExactObjectFields `
        -Expected $Ledger.topology `
        -Actual $result.topology `
        -Fields $script:topologyPropertyNames `
        -Label "hard-kill result topology"
    Assert-Ferrum2ClosedProperties $result.guest_network_path @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
        "guest_route_next_hop", "guest_dns_servers"
    ) "hard-kill result guest network path"
    Assert-True (
        ($result.guest_network_path.schema -is [int] -or
            $result.guest_network_path.schema -is [long]) -and
        [long]$result.guest_network_path.schema -eq 2 -and
        $result.guest_network_path.support_ipv4 -ceq
            [string]$Ledger.topology.support_host_ipv4 -and
        $result.guest_network_path.guest_ipv4 -ceq [string]$Ledger.topology.guest_ipv4 -and
        ($result.guest_network_path.guest_prefix_length -is [int] -or
            $result.guest_network_path.guest_prefix_length -is [long]) -and
        [long]$result.guest_network_path.guest_prefix_length -eq
            [long]$Ledger.topology.support_prefix_length -and
        ($result.guest_network_path.guest_interface_index -is [int] -or
            $result.guest_network_path.guest_interface_index -is [long]) -and
        [long]$result.guest_network_path.guest_interface_index -eq
            [long]$Ledger.topology.guest_interface_index -and
        $result.guest_network_path.guest_interface_alias -ceq
            [string]$Ledger.topology.guest_interface_alias -and
        $result.guest_network_path.guest_interface_guid -ceq
            [string]$Ledger.topology.guest_interface_guid -and
        ($result.guest_network_path.guest_interface_mtu_bytes -is [int] -or
            $result.guest_network_path.guest_interface_mtu_bytes -is [long]) -and
        [long]$result.guest_network_path.guest_interface_mtu_bytes -eq
            [long]$Ledger.topology.guest_mtu_bytes -and
        $result.guest_network_path.guest_mac_address -ceq
            [string]$Ledger.topology.guest_mac_address -and
        $result.guest_network_path.guest_route_prefix -ceq
            [string]$Ledger.topology.support_network -and
        $result.guest_network_path.guest_route_next_hop -ceq "0.0.0.0" -and
        @($result.guest_network_path.guest_dns_servers).Count -eq 0
    ) "exported hard-kill guest network path is invalid"
    Assert-UtcTimestamp $result.finished_utc "hard-kill result finished_utc"

    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $cleanupProperties = @(
        "schema", "status", "source_profile", "run_token", "identity_sha256", "topology",
        "qualification_outcome", "processes", "adapters", "target_addresses",
        "target_routes", "dns_rows", "sibling_dll", "work_directories", "mutation_journals",
        "firewall_rules", "identity_journal", "finished_utc"
    )
    Assert-Ferrum2ClosedProperties $cleanup $cleanupProperties "hard-kill cleanup"
    Assert-True (
        $cleanup.schema -ceq "ferrum2.windows-tun.hard-kill-cleanup.v2" -and
        $cleanup.status -ceq "pass" -and
        $cleanup.source_profile -ceq "hard-kill" -and
        $cleanup.run_token -ceq $script:RunToken -and
        $cleanup.identity_sha256 -ceq $IdentitySha256 -and
        $cleanup.qualification_outcome -ceq "success"
    ) "exported hard-kill cleanup identity or outcome is invalid"
    Assert-ExactObjectFields `
        -Expected $Ledger.topology `
        -Actual $cleanup.topology `
        -Fields $script:topologyPropertyNames `
        -Label "hard-kill cleanup topology"
    foreach ($name in $cleanupProperties[7..16]) {
        Assert-True (
            ($cleanup.$name -is [int] -or $cleanup.$name -is [long]) -and
            [long]$cleanup.$name -eq 0
        ) "exported cleanup residue is not integer zero: $name"
    }
    Assert-UtcTimestamp $cleanup.finished_utc "hard-kill cleanup finished_utc"
}

function Assert-HardKillHostManifest(
    [string]$Path,
    [object]$Expected,
    [string]$EvidenceRoot
) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (
        -not $item.PSIsContainer -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -ge 2 -and $item.Length -le 2097152
    ) "hard-kill host manifest file boundary is invalid"
    $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Expected | ConvertTo-Json -Depth 8) + "`n"
    )
    $actualBytes = [IO.File]::ReadAllBytes($Path)
    Assert-True (
        [Convert]::ToBase64String($actualBytes) -ceq
            [Convert]::ToBase64String($expectedBytes)
    ) "hard-kill host manifest bytes differ from the expected closed document"
    $readback = [Text.UTF8Encoding]::new($false, $true).GetString($actualBytes) |
        ConvertFrom-Json -Depth 10 -ErrorAction Stop
    $fields = @(
        "schema", "status", "mode", "run_token", "vm_name", "vm_id",
        "checkpoint_name", "checkpoint_id", "topology", "support_listener",
        "candidate_sha", "candidate_artifact_manifest_sha256",
        "identity_sha256", "controller_sha256",
        "controller_bundle_sha256", "guest_wrapper_sha256",
        "topology_runtime_sha256", "host_network_path_helper_sha256",
        "guest_network_path_probe_sha256", "staged_input_sha256", "rust_version",
        "guest_execution", "guest_build", "checkpoint_restored", "host_tun_unchanged",
        "host_support_unchanged", "host_network_mutations", "started_utc", "finished_utc",
        "final_vm_state", "evidence_files"
    )
    Assert-Ferrum2ClosedProperties $readback $fields "hard-kill host manifest"

    foreach ($name in @(
        "schema", "status", "mode", "run_token", "vm_name", "vm_id",
        "checkpoint_name", "checkpoint_id", "candidate_sha",
        "candidate_artifact_manifest_sha256", "identity_sha256",
        "controller_sha256", "controller_bundle_sha256", "guest_wrapper_sha256",
        "topology_runtime_sha256",
        "host_network_path_helper_sha256", "guest_network_path_probe_sha256",
        "staged_input_sha256", "rust_version", "guest_execution", "guest_build",
        "final_vm_state"
    )) {
        $expectedNull = $null -eq $Expected.$name
        $actualNull = $null -eq $readback.$name
        Assert-True (
            $expectedNull -eq $actualNull -and
            ($expectedNull -or [string]$readback.$name -ceq [string]$Expected.$name)
        ) "hard-kill host manifest changed: $name"
    }
    Assert-True (
        $readback.schema -ceq "ferrum2.windows-tun.hard-kill-hyperv-host-run.v4" -and
        $readback.status -cin @("pass", "fail") -and
        $readback.mode -ceq "hard-kill" -and
        [string]$readback.candidate_sha -cmatch '^[0-9a-f]{40}$' -and
        [string]$readback.candidate_artifact_manifest_sha256 -cmatch
            '^[0-9a-f]{64}$' -and
        [string]$readback.identity_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.controller_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.topology_runtime_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.host_network_path_helper_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.guest_network_path_probe_sha256 -cmatch '^[0-9a-f]{64}$' -and
        $readback.guest_execution -ceq "host-built-precompiled-artifacts-only" -and
        $readback.checkpoint_restored -is [bool] -and
        $readback.host_tun_unchanged -is [bool] -and
        $readback.host_support_unchanged -is [bool] -and
        ($readback.host_network_mutations -is [int] -or
            $readback.host_network_mutations -is [long]) -and
        [long]$readback.host_network_mutations -eq 0
    ) "hard-kill host manifest identity or types are invalid"
    foreach ($name in @(
        "schema", "status", "mode", "run_token", "vm_name", "vm_id",
        "checkpoint_name", "checkpoint_id", "candidate_sha",
        "candidate_artifact_manifest_sha256", "identity_sha256",
        "controller_sha256", "topology_runtime_sha256", "host_network_path_helper_sha256",
        "guest_network_path_probe_sha256", "guest_execution", "guest_build"
    )) {
        Assert-True ($readback.$name -is [string]) `
            "hard-kill host manifest string type is invalid: $name"
    }
    foreach ($name in @(
        "guest_wrapper_sha256", "staged_input_sha256", "rust_version", "final_vm_state"
    )) {
        Assert-True ($null -eq $readback.$name -or $readback.$name -is [string]) `
            "hard-kill host manifest nullable string type is invalid: $name"
    }
    foreach ($name in @(
        "support_prefix_length", "guest_interface_index", "guest_mtu_bytes",
        "protected_host_tun_index"
    )) {
        Assert-True (
            $readback.topology.$name -is [int] -or
            $readback.topology.$name -is [long]
        ) "hard-kill host topology integer type is invalid: $name"
    }
    foreach ($name in @("tcp_port", "udp_port", "pid")) {
        Assert-True (
            $readback.support_listener.$name -is [int] -or
            $readback.support_listener.$name -is [long]
        ) "hard-kill host listener integer type is invalid: $name"
    }
    foreach ($name in @(
        "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
        "support_network", "guest_interface_alias", "guest_interface_guid",
        "guest_mac_address", "guest_ipv4", "protected_host_tun_name",
        "protected_host_tun_guid", "protected_host_tun_status"
    )) {
        Assert-True ($readback.topology.$name -is [string]) `
            "hard-kill host topology string type is invalid: $name"
    }
    foreach ($name in @("ipv4", "owner", "executable_sha256")) {
        Assert-True ($readback.support_listener.$name -is [string]) `
            "hard-kill host listener string type is invalid: $name"
    }
    Assert-True ($readback.evidence_files -is [object[]]) `
        "hard-kill host evidence_files must be a JSON array"
    Assert-ExactObjectFields -Expected $Expected.topology -Actual $readback.topology `
        -Fields $script:topologyPropertyNames -Label "hard-kill host manifest topology"
    Assert-ExactObjectFields `
        -Expected $Expected.support_listener -Actual $readback.support_listener `
        -Fields $script:supportListenerPropertyNames `
        -Label "hard-kill host manifest support listener"
    Assert-UtcTimestamp $readback.started_utc "hard-kill host manifest started_utc"
    Assert-UtcTimestamp $readback.finished_utc "hard-kill host manifest finished_utc"
    $expectedStartedUtc = [DateTime]::ParseExact(
        [string]$Expected.started_utc,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    $expectedFinishedUtc = [DateTime]::ParseExact(
        [string]$Expected.finished_utc,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    Assert-True (
        ([DateTime]$readback.started_utc).ToUniversalTime().Ticks -eq
            $expectedStartedUtc.ToUniversalTime().Ticks -and
        ([DateTime]$readback.finished_utc).ToUniversalTime().Ticks -eq
            $expectedFinishedUtc.ToUniversalTime().Ticks
    ) "hard-kill host manifest timestamps changed"

    $actualEvidence = @(Get-EvidenceHashes -EvidenceRoot $EvidenceRoot)
    $recordedEvidence = @($readback.evidence_files)
    foreach ($row in $recordedEvidence) {
        Assert-Ferrum2ClosedProperties $row @("path", "bytes", "sha256") `
            "hard-kill host evidence hash row"
        Assert-True (
            $row.path -is [string] -and
            -not [string]::IsNullOrWhiteSpace([string]$row.path) -and
            ($row.bytes -is [int] -or $row.bytes -is [long]) -and
            [long]$row.bytes -ge 0 -and
            [string]$row.sha256 -cmatch '^[0-9a-f]{64}$'
        ) "hard-kill host evidence hash row values are invalid"
    }
    Assert-True (
        ($recordedEvidence | ConvertTo-Json -Compress -Depth 5) -ceq
            ($actualEvidence | ConvertTo-Json -Compress -Depth 5)
    ) "hard-kill host evidence file hashes changed"

    $criticalEvidence = @(
        [ordered]@{
            path = "identity-ledger.json"
            sha256 = [string]$readback.identity_sha256
        },
        [ordered]@{
            path = "candidate-artifacts.json"
            sha256 = [string]$readback.candidate_artifact_manifest_sha256
        },
        [ordered]@{
            path = "staged-input.json"
            sha256 = [string]$readback.staged_input_sha256
        },
        [ordered]@{
            path = "topology-manifest.json"
            sha256 = [string]$readback.topology.manifest_sha256
        },
        [ordered]@{
            path = "guest/export/identity-ledger.json"
            sha256 = [string]$readback.identity_sha256
        }
    )
    foreach ($critical in $criticalEvidence) {
        $matches = @($recordedEvidence | Where-Object {
            [string]$_.path -ceq [string]$critical.path
        })
        if ($readback.status -ceq "pass") {
            Assert-True (
                $matches.Count -eq 1 -and
                [string]$matches[0].sha256 -ceq [string]$critical.sha256
            ) "hard-kill PASS evidence identity is invalid: $($critical.path)"
        } elseif ($matches.Count -ne 0) {
            Assert-True (
                $matches.Count -eq 1 -and
                -not [string]::IsNullOrWhiteSpace([string]$critical.sha256) -and
                [string]$matches[0].sha256 -ceq [string]$critical.sha256
            ) "hard-kill failure evidence identity is invalid: $($critical.path)"
        }
    }

    $stagedBindingPath = Join-Path $EvidenceRoot "staged-input.json"
    if (Test-Path -LiteralPath $stagedBindingPath -PathType Leaf) {
        $stagedBindingItem = Get-Item -LiteralPath $stagedBindingPath `
            -Force -ErrorAction Stop
        Assert-True (
            ($stagedBindingItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $stagedBindingItem.Length -ge 2 -and
            $stagedBindingItem.Length -le 2097152
        ) "hard-kill staged-input evidence boundary is invalid"
        $stagedBinding = Get-Content -LiteralPath $stagedBindingPath `
            -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10 -ErrorAction Stop
        Assert-True (
            $stagedBinding.schema -ceq
                "ferrum2.windows-tun.hard-kill-staged-input.v4" -and
            [string]$stagedBinding.candidate_artifact_manifest_sha256 -ceq
                [string]$readback.candidate_artifact_manifest_sha256
        ) "hard-kill staged-input candidate artifact binding is invalid"
    }

    if ($readback.status -ceq "pass") {
        Assert-True (
            [string]$readback.guest_wrapper_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$readback.staged_input_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$readback.rust_version -cmatch '^rustc 1\.97\.1 \(' -and
            $readback.checkpoint_restored -eq $true -and
            $readback.host_tun_unchanged -eq $true -and
            $readback.host_support_unchanged -eq $true -and
            $readback.final_vm_state -ceq "Off"
        ) "hard-kill host PASS invariants are invalid"
    }
}
