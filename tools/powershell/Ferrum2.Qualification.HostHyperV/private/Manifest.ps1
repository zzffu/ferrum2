function Get-BoundedWorkerManifestFields([string]$Schema) {
    switch ($Schema) {
        "ferrum2.windows-tun.hyperv-host-run.v5" {
            return @(
                "schema", "status", "profile", "mode", "restart_cycles",
                "network_reset_cycles", "run_token", "vm_name", "vm_id",
                "checkpoint_name", "checkpoint_id", "candidate_sha",
                "identity_sha256", "controller_bundle_sha256", "staged_input_sha256",
                "topology_manifest_sha256", "topology_plan_sha256", "topology",
                "guest_network_path_sha256", "guest_network_path",
                "host_network_path_sha256", "support_listener",
                "protected_host_tun", "topology_runtime_sha256",
                "host_network_path_helper_sha256",
                "guest_network_path_probe_sha256", "rust_version",
                "fuzz_smoke_sha256", "fuzz_smoke_bytes", "guest_execution",
                "guest_build", "checkpoint_restored",
                "support_listener_unchanged", "host_tun_unchanged",
                "host_network_mutations", "started_utc", "finished_utc",
                "final_vm_state", "evidence_files"
            )
        }
        "ferrum2.windows-tun.hard-kill-hyperv-host-run.v3" {
            return @(
                "schema", "status", "mode", "run_token", "vm_name", "vm_id",
                "checkpoint_name", "checkpoint_id", "topology", "support_listener",
                "candidate_sha", "identity_sha256", "controller_sha256",
                "controller_bundle_sha256",
                "guest_wrapper_sha256", "topology_runtime_sha256",
                "host_network_path_helper_sha256",
                "guest_network_path_probe_sha256", "staged_input_sha256",
                "rust_version", "guest_execution", "guest_build",
                "checkpoint_restored", "host_tun_unchanged",
                "host_support_unchanged", "host_network_mutations",
                "started_utc", "finished_utc", "final_vm_state",
                "evidence_files"
            )
        }
        default { throw "bounded worker manifest schema is invalid" }
    }
}

function Test-BoundedWorkerClosedProperties {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    return $null -ne $Value -and
        (@($Value.PSObject.Properties.Name) -join "|") -ceq ($Expected -join "|")
}

function Test-BoundedWorkerJsonInteger([AllowNull()][object]$Value) {
    return $Value -is [int] -or $Value -is [long]
}

function Test-BoundedWorkerCanonicalUtc([AllowNull()][object]$Value) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).Kind -eq [DateTimeKind]::Utc
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero
    }
    if ($Value -isnot [string]) { return $false }
    [DateTime]$parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact(
            [string]$Value,
            "o",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed
        )) {
        return $false
    }
    return $parsed.Kind -eq [DateTimeKind]::Utc -and
        $parsed.ToUniversalTime().ToString("o") -ceq [string]$Value
}

function Test-BoundedWorkerCanonicalListenerUtc([AllowNull()][object]$Value) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).Kind -eq [DateTimeKind]::Utc
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero
    }
    if ($Value -isnot [string]) { return $false }
    [DateTime]$parsed = [DateTime]::MinValue
    $format = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
    if (-not [DateTime]::TryParseExact(
            [string]$Value,
            $format,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed
        )) {
        return $false
    }
    return $parsed.Kind -eq [DateTimeKind]::Utc -and
        $parsed.ToString($format, [Globalization.CultureInfo]::InvariantCulture) -ceq
            [string]$Value
}

function Test-BoundedWorkerJsonHasUniqueProperties([object]$Element) {
    switch ([Text.Json.JsonValueKind]$Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add([string]$property.Name) -or
                    -not (Test-BoundedWorkerJsonHasUniqueProperties $property.Value)) {
                    return $false
                }
            }
        }
        ([Text.Json.JsonValueKind]::Array) {
            foreach ($item in $Element.EnumerateArray()) {
                if (-not (Test-BoundedWorkerJsonHasUniqueProperties $item)) {
                    return $false
                }
            }
        }
    }
    return $true
}

function Test-BoundedWorkerFailureEvidence([AllowNull()][object]$Rows) {
    if ($Rows -isnot [object[]]) { return $false }
    $paths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($row in @($Rows)) {
        if (-not (Test-BoundedWorkerClosedProperties -Value $row `
                -Expected @("path", "bytes", "sha256")) -or
            $row.path -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$row.path) -or
            [IO.Path]::IsPathFullyQualified([string]$row.path) -or
            [string]$row.path -match '(^|[\\/])\.\.([\\/]|$)' -or
            -not (Test-BoundedWorkerJsonInteger $row.bytes) -or
            [long]$row.bytes -lt 0 -or
            $row.sha256 -isnot [string] -or
            [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $paths.Add([string]$row.path)) {
            return $false
        }
    }
    return $true
}

function Test-BoundedWorkerFailureTopology([AllowNull()][object]$Value) {
    $fields = @(
        "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
        "support_network", "support_prefix_length", "guest_interface_alias",
        "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
        "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
        "protected_host_tun_index", "protected_host_tun_status"
    )
    if (-not (Test-BoundedWorkerClosedProperties -Value $Value -Expected $fields)) {
        return $false
    }
    foreach ($name in @("manifest_sha256", "plan_sha256")) {
        if ($Value.$name -isnot [string] -or
            [string]$Value.$name -cnotmatch '^[0-9a-f]{64}$') {
            return $false
        }
    }
    foreach ($name in @(
        "support_switch_id", "support_host_ipv4", "support_network",
        "guest_interface_alias", "guest_interface_guid", "guest_mac_address", "guest_ipv4",
        "protected_host_tun_name", "protected_host_tun_guid", "protected_host_tun_status"
    )) {
        if ($Value.$name -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Value.$name)) {
            return $false
        }
    }
    foreach ($name in @(
        "support_prefix_length", "guest_interface_index", "guest_mtu_bytes",
        "protected_host_tun_index"
    )) {
        if (-not (Test-BoundedWorkerJsonInteger $Value.$name) -or
            [long]$Value.$name -le 0) {
            return $false
        }
    }
    return $true
}

function Test-BoundedWorkerFailureListener([AllowNull()][object]$Value) {
    if (-not (Test-BoundedWorkerClosedProperties -Value $Value -Expected @(
            "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256",
            "creation_utc"
        )) -or
        $Value.ipv4 -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Value.ipv4) -or
        $Value.owner -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Value.owner) -or
        $Value.executable_sha256 -isnot [string] -or
        [string]$Value.executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-BoundedWorkerCanonicalListenerUtc $Value.creation_utc)) {
        return $false
    }
    foreach ($name in @("tcp_port", "udp_port", "pid")) {
        if (-not (Test-BoundedWorkerJsonInteger $Value.$name) -or
            [long]$Value.$name -le 0) {
            return $false
        }
    }
    return [long]$Value.tcp_port -le 65535 -and
        [long]$Value.udp_port -le 65535 -and
        [long]$Value.pid -le [int]::MaxValue
}

function Test-BoundedWorkerManifestMinimum {
    param(
        [Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][string]$RawJson,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][ValidateSet("pass", "fail")]
        [string]$ExpectedStatus,
        [Parameter(Mandatory = $true)][string]$ExpectedRunToken,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)][string]$ExpectedVmName,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )

    $expectedFields = @(Get-BoundedWorkerManifestFields -Schema $ExpectedSchema)
    if (-not (Test-BoundedWorkerClosedProperties -Value $Document `
            -Expected $expectedFields)) {
        return $false
    }
    $rawDocument = $null
    try {
        $rawDocument = [Text.Json.JsonDocument]::Parse(
            $RawJson,
            [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 12
            }
        )
        $root = $rawDocument.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
            -not (Test-BoundedWorkerJsonHasUniqueProperties $root)) {
            return $false
        }
        $startedElement = $root.GetProperty("started_utc")
        $finishedElement = $root.GetProperty("finished_utc")
        $listenerElement = $root.GetProperty("support_listener").
            GetProperty("creation_utc")
        if ($startedElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            $finishedElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            $listenerElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            -not (Test-BoundedWorkerCanonicalUtc $startedElement.GetString()) -or
            -not (Test-BoundedWorkerCanonicalUtc $finishedElement.GetString()) -or
            -not (Test-BoundedWorkerCanonicalListenerUtc $listenerElement.GetString())) {
            return $false
        }
    } catch {
        return $false
    } finally {
        if ($null -ne $rawDocument) { $rawDocument.Dispose() }
    }
    try { $documentVmId = [Guid][string]$Document.vm_id } catch { return $false }
    try { $checkpointId = [Guid][string]$Document.checkpoint_id } catch { return $false }
    if ([string]$Document.schema -cne $ExpectedSchema -or
        [string]$Document.status -cne $ExpectedStatus -or
        $Document.run_token -isnot [string] -or
        [string]$Document.run_token -cne $ExpectedRunToken -or
        $documentVmId -ne $ExpectedVmId -or
        $checkpointId -eq [Guid]::Empty -or
        $Document.vm_name -isnot [string] -or
        [string]$Document.vm_name -cne $ExpectedVmName -or
        $Document.checkpoint_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Document.checkpoint_name) -or
        $Document.candidate_sha -isnot [string] -or
        [string]$Document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        $Document.identity_sha256 -isnot [string] -or
        [string]$Document.identity_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Document.checkpoint_restored -isnot [bool] -or
        $Document.host_tun_unchanged -isnot [bool] -or
        -not (Test-BoundedWorkerJsonInteger $Document.host_network_mutations) -or
        [long]$Document.host_network_mutations -ne 0 -or
        -not (Test-BoundedWorkerCanonicalUtc $Document.started_utc) -or
        -not (Test-BoundedWorkerCanonicalUtc $Document.finished_utc) -or
        -not (Test-BoundedWorkerFailureEvidence $Document.evidence_files)) {
        return $false
    }
    try {
        $recordedEvidence = ConvertTo-Json `
            -InputObject @($Document.evidence_files) -Compress -Depth 5
        $actualEvidence = ConvertTo-Json `
            -InputObject @(Get-EvidenceHashes -EvidenceRoot $EvidenceRoot) `
            -Compress -Depth 5
    } catch {
        return $false
    }
    if ($recordedEvidence -cne $actualEvidence) { return $false }
    if ($null -ne $Document.final_vm_state -and
        ($Document.final_vm_state -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.final_vm_state))) {
        return $false
    }
    if (-not (Test-BoundedWorkerFailureTopology $Document.topology) -or
        -not (Test-BoundedWorkerFailureListener $Document.support_listener)) {
        return $false
    }

    $requiredShaFields = @(
        "topology_runtime_sha256", "host_network_path_helper_sha256",
        "guest_network_path_probe_sha256"
    )
    if ($ExpectedSchema -ceq "ferrum2.windows-tun.hyperv-host-run.v5") {
        $requiredShaFields += @(
            "controller_bundle_sha256", "topology_manifest_sha256", "topology_plan_sha256"
        )
        if ($Document.profile -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.profile) -or
            $Document.mode -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.mode) -or
            $Document.support_listener_unchanged -isnot [bool] -or
            $Document.guest_execution -cne "host-built-precompiled-artifacts-only") {
            return $false
        }
        foreach ($name in @(
            "staged_input_sha256", "guest_network_path_sha256",
            "host_network_path_sha256", "fuzz_smoke_sha256"
        )) {
            if ($null -ne $Document.$name -and
                ($Document.$name -isnot [string] -or
                    [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$')) {
                return $false
            }
        }
        foreach ($name in @("restart_cycles", "network_reset_cycles", "fuzz_smoke_bytes")) {
            if ($null -ne $Document.$name -and
                -not (Test-BoundedWorkerJsonInteger $Document.$name)) {
                return $false
            }
        }
        foreach ($name in @("rust_version", "guest_build")) {
            if ($null -ne $Document.$name -and $Document.$name -isnot [string]) {
                return $false
            }
        }
        if ($null -ne $Document.protected_host_tun -and
            -not (Test-BoundedWorkerClosedProperties `
                -Value $Document.protected_host_tun `
                -Expected @("present", "name", "interface_guid", "interface_index", "status"))) {
            return $false
        }
        if ($ExpectedStatus -ceq "pass" -and
            ($Document.staged_input_sha256 -isnot [string] -or
                [string]$Document.staged_input_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.guest_network_path_sha256 -isnot [string] -or
                [string]$Document.guest_network_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $null -eq $Document.guest_network_path -or
                $Document.host_network_path_sha256 -isnot [string] -or
                [string]$Document.host_network_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.fuzz_smoke_sha256 -isnot [string] -or
                [string]$Document.fuzz_smoke_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                -not (Test-BoundedWorkerJsonInteger $Document.fuzz_smoke_bytes) -or
                [long]$Document.fuzz_smoke_bytes -le 0 -or
                $Document.rust_version -isnot [string] -or
                [string]$Document.rust_version -cnotmatch '^rustc 1\.97\.1 \(' -or
                $Document.guest_build -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$Document.guest_build) -or
                $null -eq $Document.protected_host_tun)) {
            return $false
        }
    } else {
        $requiredShaFields += @("controller_sha256", "controller_bundle_sha256")
        if ($Document.mode -cne "hard-kill" -or
            $Document.guest_execution -cne "host-built-precompiled-artifacts-only" -or
            $Document.guest_build -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.guest_build) -or
            $Document.host_support_unchanged -isnot [bool]) {
            return $false
        }
        foreach ($name in @("guest_wrapper_sha256", "staged_input_sha256")) {
            if ($null -ne $Document.$name -and
                ($Document.$name -isnot [string] -or
                    [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$')) {
                return $false
            }
        }
        if ($null -ne $Document.rust_version -and
            $Document.rust_version -isnot [string]) {
            return $false
        }
        if ($ExpectedStatus -ceq "pass" -and
            ($Document.guest_wrapper_sha256 -isnot [string] -or
                [string]$Document.guest_wrapper_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.staged_input_sha256 -isnot [string] -or
                [string]$Document.staged_input_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.rust_version -isnot [string] -or
                [string]$Document.rust_version -cnotmatch '^rustc 1\.97\.1 \(')) {
            return $false
        }
    }
    foreach ($name in $requiredShaFields) {
        if ($Document.$name -isnot [string] -or
            [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$') {
            return $false
        }
    }
    if ($ExpectedStatus -ceq "pass") {
        $criticalEvidence = @(
            [ordered]@{ path = "identity-ledger.json"; sha256 = [string]$Document.identity_sha256 },
            [ordered]@{ path = "staged-input.json"; sha256 = [string]$Document.staged_input_sha256 },
            [ordered]@{ path = "topology-manifest.json"; sha256 = [string]$Document.topology.manifest_sha256 },
            [ordered]@{ path = "guest/export/identity-ledger.json"; sha256 = [string]$Document.identity_sha256 }
        )
        foreach ($critical in $criticalEvidence) {
            $matches = @($Document.evidence_files | Where-Object {
                [string]$_.path -ceq [string]$critical.path
            })
            if ($matches.Count -ne 1 -or
                [string]$matches[0].sha256 -cne [string]$critical.sha256) {
                return $false
            }
        }
    }
    return $true
}

function Assert-BoundedWorkerPassManifestAndTerminal {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$Terminal,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Qualification", "HardKill")]
        [string]$WorkerContract,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)][string]$ExpectedVmName
    )

    $fullPath = [IO.Path]::GetFullPath($ManifestPath)
    if (-not [IO.Path]::IsPathFullyQualified($ManifestPath) -or
        (Test-Ferrum2PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) -or
        [IO.Path]::GetFileName($fullPath) -cne "host-orchestration.json") {
        throw "bounded worker PASS manifest path is invalid"
    }
    Assert-NoReparsePointInExistingPath `
        -Path $fullPath -Label "bounded worker PASS manifest"
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 2 -or $item.Length -gt 4194304) {
        throw "bounded worker PASS manifest boundary is invalid"
    }
    $manifestText = Get-Content -LiteralPath $item.FullName -Raw -Encoding utf8
    $document = $manifestText | ConvertFrom-Json -Depth 10 -ErrorAction Stop
    $schema = if ($WorkerContract -ceq "Qualification") {
        "ferrum2.windows-tun.hyperv-host-run.v5"
    } else {
        "ferrum2.windows-tun.hard-kill-hyperv-host-run.v3"
    }
    $runToken = [string]$BoundParameters["RunToken"]
    $evidenceRoot = [IO.Path]::GetFullPath((Split-Path -Parent $fullPath))
    if (-not (Test-BoundedWorkerManifestMinimum `
            -Document $document -RawJson $manifestText `
            -ExpectedSchema $schema -ExpectedStatus "pass" `
            -ExpectedRunToken $runToken -ExpectedVmId $ExpectedVmId `
            -ExpectedVmName $ExpectedVmName -EvidenceRoot $evidenceRoot) -or
        [string]$document.final_vm_state -cne "Off" -or
        $document.checkpoint_restored -ne $true -or
        $document.host_tun_unchanged -ne $true) {
        throw "bounded worker PASS manifest contract is invalid"
    }
    $expectedTerminal = if ($WorkerContract -ceq "Qualification") {
        $profile = [string]$BoundParameters["Profile"]
        if ([string]$document.profile -cne $profile -or
            $document.support_listener_unchanged -ne $true) {
            throw "bounded qualification PASS manifest profile is invalid"
        }
        "hyperv_windows_tun status=PASS profile=$profile run_token=$runToken " +
            "candidate_sha=$($document.candidate_sha) evidence=$evidenceRoot " +
            "final_vm_state=Off"
    } else {
        if ([string]$document.mode -cne "hard-kill" -or
            $document.host_support_unchanged -ne $true) {
            throw "bounded hard-kill PASS manifest mode is invalid"
        }
        "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill " +
            "run_token=$runToken candidate_sha=$($document.candidate_sha) " +
            "evidence=$evidenceRoot final_vm_state=Off"
    }
    if ($Terminal -cne $expectedTerminal) {
        throw "bounded worker terminal does not match its PASS manifest"
    }
}

function Invoke-BoundedHyperVWorkerSupervisor {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][string[]]$ForwardedParameterNames,
        [Parameter(Mandatory = $true)][ValidateRange(30, 21600)]
        [int]$WorkerTimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(30, 900)]
        [int]$ShutdownTimeoutSeconds,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName,
        [Parameter(Mandatory = $true)][ValidateSet("Off", "Running")]
        [string]$ExpectedFinalState,
        [AllowNull()][object]$CleanupAuthority,
        [Parameter(Mandatory = $true)]
        [ValidateSet("StopOnly", "RestoreCheckpoint")]
        [string]$CleanupMode,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Probe", "Qualification", "HardKill")]
        [string]$WorkerContract,
        [AllowNull()][string]$FailureManifestPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9 -]{1,64}$')]
        [string]$Label
    )

    if ($ExpectedVmId -eq [Guid]::Empty -or
        ($ExpectedFinalState -ceq "Off" -and $null -eq $CleanupAuthority)) {
        throw "$Label supervisor identity or cleanup authority is invalid"
    }
    if ($null -ne $CleanupAuthority) {
        Assert-ApprovedVmCleanupAuthority -Authority $CleanupAuthority
        if ([Guid]$CleanupAuthority.vm_id -ne $ExpectedVmId -or
            [string]$CleanupAuthority.vm_name -cne $ExpectedVmName) {
            throw "$Label supervisor cleanup authority VM is invalid"
        }
    }

    $workerToken = [Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")
    $supervisorProcess = Get-Process -Id $PID -ErrorAction Stop
    $arguments = @(New-BoundedPwshFileArguments `
        -ScriptPath $ScriptPath `
        -BoundParameters $BoundParameters `
        -ForwardedParameterNames $ForwardedParameterNames `
        -InternalWorkerToken $workerToken)
    $workerEnvironment = [ordered]@{
        FERRUM2_HYPERV_WORKER_TOKEN = $workerToken
        FERRUM2_HYPERV_SUPERVISOR_PID = [string]$PID
        FERRUM2_HYPERV_SUPERVISOR_START_TICKS = [string](
            $supervisorProcess.StartTime.ToUniversalTime().Ticks
        )
    }
    $workerGateName = "Local\Ferrum2-HyperV-Worker-" +
        [Guid]::NewGuid().ToString("N")
    $workerGateCreated = $false
    $workerStartGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $workerGateName,
        [ref]$workerGateCreated
    )
    if (-not $workerGateCreated) {
        $workerStartGate.Dispose()
        throw "$Label worker start gate identity already exists"
    }
    $workerEnvironment.FERRUM2_HYPERV_WORKER_GATE = $workerGateName
    $workerAccepted = $false
    $primaryFailure = $null
    $recoveryIssues = [Collections.Generic.List[string]]::new()
    try {
        try {
            $result = Invoke-BoundedPwshFile `
                -Arguments $arguments `
                -TimeoutSeconds $WorkerTimeoutSeconds `
                -Label $Label `
                -Environment $workerEnvironment `
                -StartGate $workerStartGate
            $combinedOutput = (($result.Stderr + "`n" + $result.Stdout).Trim() `
                -replace '[\r\n]+', ' | ')
            if ($combinedOutput.Length -gt 2048) {
                $combinedOutput = $combinedOutput.Substring(0, 2048)
            }
            if ($result.ExitCode -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($result.Stderr) -or
                [string]::IsNullOrWhiteSpace($result.Stdout)) {
                throw "$Label failed with exit code $($result.ExitCode): $combinedOutput"
            }
            $workerLines = @($result.Stdout -split '\r?\n' |
                Where-Object { $_.Length -gt 0 })
            if ($workerLines.Count -ne 1) {
                throw "$Label returned an invalid terminal record count"
            }
            switch ($WorkerContract) {
                "Probe" {
                    $probe = $workerLines[0] |
                        ConvertFrom-Json -Depth 8 -ErrorAction Stop
                    if ($probe.schema -cne "ferrum2.windows-tun.hyperv-probe.v2" -or
                        $probe.status -cne "pass" -or
                        [Guid][string]$probe.vm_id -ne $ExpectedVmId -or
                        [string]$probe.initial_vm_state -cne
                            $ExpectedFinalState.ToLowerInvariant() -or
                        [string]$probe.final_vm_state -cne $ExpectedFinalState -or
                        $probe.checkpoint_restored -ne $false -or
                        [long]$probe.host_network_mutations -ne 0) {
                        throw "$Label probe terminal contract is invalid"
                    }
                }
                "Qualification" {
                    Assert-BoundedWorkerPassManifestAndTerminal `
                        -ManifestPath $FailureManifestPath `
                        -Terminal $workerLines[0] `
                        -WorkerContract $WorkerContract `
                        -BoundParameters $BoundParameters `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                }
                "HardKill" {
                    Assert-BoundedWorkerPassManifestAndTerminal `
                        -ManifestPath $FailureManifestPath `
                        -Terminal $workerLines[0] `
                        -WorkerContract $WorkerContract `
                        -BoundParameters $BoundParameters `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                }
            }
            $finalState = Invoke-BoundedHyperVMutation `
                -Action Read -VmId $ExpectedVmId `
                -ExpectedVmName $ExpectedVmName -TimeoutSeconds 30
            if ([string]$finalState -cne $ExpectedFinalState) {
                throw (
                    "$Label changed the exact VM final state: " +
                    "expected=$ExpectedFinalState actual=$finalState"
                )
            }
        } catch {
            $primaryFailure = $_
        }
    } finally {
        try {
            $workerStartGate.Dispose()
        } catch {
            $recoveryIssues.Add(
                "worker start gate disposal failed: $($_.Exception.Message)"
            )
        }
        if ($null -eq $primaryFailure -and $recoveryIssues.Count -eq 0) {
            try {
                [Console]::Out.Write($result.Stdout)
                $workerAccepted = $true
            } catch {
                $primaryFailure = $_
            }
        }
        if (-not $workerAccepted) {
            if ($null -ne $CleanupAuthority) {
                try {
                    Invoke-ApprovedVmWorkerEmergencyCleanup `
                        -Authority $CleanupAuthority `
                        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
                        -Mode $CleanupMode
                } catch {
                    $recoveryIssues.Add($_.Exception.Message)
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($FailureManifestPath)) {
                try {
                    $failureManifestSchema = switch ($WorkerContract) {
                        "Qualification" {
                            "ferrum2.windows-tun.hyperv-host-run.v5"
                        }
                        "HardKill" {
                            "ferrum2.windows-tun.hard-kill-hyperv-host-run.v3"
                        }
                        default { "" }
                    }
                    Remove-BoundedWorkerManifestIfPresent `
                        -Path $FailureManifestPath `
                        -ExpectedSchema $failureManifestSchema `
                        -ExpectedRunToken ([string]$BoundParameters["RunToken"]) `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                } catch {
                    $recoveryIssues.Add(
                        "invalid worker manifest removal failed: $($_.Exception.Message)"
                    )
                }
            }
        }
    }
    if ($null -ne $primaryFailure) {
        if ($recoveryIssues.Count -ne 0) {
            throw (
                "$Label supervisor failed: primary=$($primaryFailure.Exception.Message); " +
                    "recovery=$($recoveryIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($recoveryIssues.Count -ne 0) {
        throw "$Label supervisor recovery failed: $($recoveryIssues -join '; ')"
    }
}

function Assert-BoundedHyperVInternalWorker {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
        [string]$Token
    )

    $environmentToken = [string]$env:FERRUM2_HYPERV_WORKER_TOKEN
    $supervisorPidText = [string]$env:FERRUM2_HYPERV_SUPERVISOR_PID
    $supervisorStartTicksText = [string]$env:FERRUM2_HYPERV_SUPERVISOR_START_TICKS
    $workerGateName = [string]$env:FERRUM2_HYPERV_WORKER_GATE
    $supervisorPid = 0
    $supervisorStartTicks = [long]0
    if ($Token -cne $environmentToken -or
        $supervisorPidText -cnotmatch '^[1-9][0-9]{0,9}$' -or
        -not [int]::TryParse(
            $supervisorPidText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$supervisorPid
        ) -or
        $supervisorPid -eq $PID -or
        $workerGateName -cnotmatch
            '^Local\\Ferrum2-HyperV-Worker-[0-9a-f]{32}$' -or
        $supervisorStartTicksText -cnotmatch '^[1-9][0-9]{0,18}$' -or
        -not [long]::TryParse(
            $supervisorStartTicksText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$supervisorStartTicks
        )) {
        throw "bounded Hyper-V worker capability is invalid"
    }
    $supervisor = Get-Process -Id $supervisorPid -ErrorAction Stop
    $current = Get-Process -Id $PID -ErrorAction Stop
    if ([IO.Path]::GetFullPath([string]$supervisor.Path) -ine
            [IO.Path]::GetFullPath([string]$current.Path) -or
        $supervisor.StartTime.ToUniversalTime().Ticks -ne $supervisorStartTicks) {
        throw "bounded Hyper-V worker supervisor identity is invalid"
    }
    $workerStartGate = [Threading.EventWaitHandle]::OpenExisting($workerGateName)
    foreach ($name in @(
        "FERRUM2_HYPERV_WORKER_TOKEN",
        "FERRUM2_HYPERV_SUPERVISOR_PID",
        "FERRUM2_HYPERV_SUPERVISOR_START_TICKS",
        "FERRUM2_HYPERV_WORKER_GATE"
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    try {
        if (-not $workerStartGate.WaitOne(30000)) {
            throw "bounded Hyper-V worker start gate timed out"
        }
    } finally {
        $workerStartGate.Dispose()
    }
}
