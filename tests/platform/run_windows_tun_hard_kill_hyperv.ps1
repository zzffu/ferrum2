#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs the independently versioned M16 Windows TUN hard-kill gate in the approved Hyper-V guest.

.DESCRIPTION
The host builds and hash-binds a clean candidate, stages only precompiled artifacts and portable
runtime dependencies, invokes the dedicated guest hard-kill wrapper through PowerShell Direct,
exports bounded evidence, turns off the exact VM, restores the exact checkpoint, and leaves it Off.
It never changes host adapter, address, route, DNS, firewall, WFP, or TUN state.

The portable guest controller defaults to the SHA-256-pinned PowerShell 7.4.19 win-x64 archive at
%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip. The archive must remain outside the repository.

DescribeContract emits the closed static contract without resolving a credential, inspecting a VM,
building code, staging files, or invoking guest execution.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Describe")]
    [switch]$DescribeContract,

    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [switch]$InternalWorker,

    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalWorkerToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(ParameterSetName = "Run")]
    [string]$CredentialPath,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$approvedVmName = $null
$approvedVmId = $null
$approvedCheckpointName = $null
$approvedCheckpointId = $null
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$expectedArtifactFiles = @(
    "identity-ledger.json",
    "controller.stdout.log",
    "controller.stderr.log",
    "hard-kill-evidence.jsonl",
    "hard-kill-result.json",
    "cleanup.stdout.log",
    "cleanup.stderr.log",
    "hard-kill-cleanup.json"
)
$topologyPropertyNames = @(
    "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
    "support_network", "support_prefix_length", "guest_interface_alias",
    "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
    "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
    "protected_host_tun_index", "protected_host_tun_status"
)
$supportListenerPropertyNames = @(
    "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256", "creation_utc"
)
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path

if ($DescribeContract) {
    [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-static-contract.v2"
        mode = "hard-kill"
        controller_cases = @("auto-route", "auto-dns", "mixed")
        artifact_files = $expectedArtifactFiles
        staged_input_schema = "ferrum2.windows-tun.hard-kill-staged-input.v2"
        evidence_row_schema = 2
        result_schema = "ferrum2.windows-tun.hard-kill-result.v2"
        strict_route_cases = 2
        cleanup_schema = "ferrum2.windows-tun.hard-kill-cleanup.v2"
        guest_bootstrap_schema = "ferrum2.windows-tun.hard-kill-guest-bootstrap.v2"
        host_run_schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2"
        topology_manifest_schema = 1
        topology_manifest_required_at_run = $true
        vm_name = $null
        vm_id = $null
        checkpoint_name = $null
        checkpoint_id = $null
        initial_vm_state = "Off"
        final_vm_state = "Off"
    } | ConvertTo-Json -Depth 5
    return
}

function Import-ReviewedHyperVCommon {
    $commonPath = Join-Path $PSScriptRoot "run_windows_tun_hyperv.ps1"
    $module = New-Module -Name (
        "Ferrum2WindowsTunHyperVCommon_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $commonPath -ScriptBlock {
        param([string]$Path)
        . $Path -LibraryOnly
        Export-ModuleMember -Function @(
            "Test-PathWithinRoot",
            "Assert-NoReparsePointInExistingPath",
            "Resolve-BoundedFile",
            "Resolve-ExternalDirectoryTarget",
            "Import-ApprovedGuestCredential",
            "Get-ApprovedVmContext",
            "New-ApprovedVmCleanupAuthority",
            "Get-ApprovedVmEmergencyState",
            "Stop-ApprovedVmEmergency",
            "Restore-ApprovedCheckpointEmergency",
            "New-BoundedPwshFileArguments",
            "Invoke-BoundedPwshFile",
            "Invoke-ApprovedVmWorkerEmergencyCleanup",
            "Invoke-BoundedHyperVWorkerSupervisor",
            "Assert-BoundedHyperVInternalWorker",
            "Start-ApprovedVm",
            "Stop-ApprovedVm",
            "Restore-ApprovedCheckpoint",
            "Connect-ApprovedGuest",
            "Read-IdentityLedger",
            "Get-CandidateIdentity",
            "Build-CandidateArtifacts",
            "New-PortablePowerShellArchive",
            "Stage-VisualCppRuntime",
            "Write-JsonFileNew",
            "New-StagedFileEntry",
            "Copy-GuestEvidence",
            "Get-EvidenceHashes",
            "Initialize-ApprovedHyperVTopology",
            "Get-ApprovedHyperVTopologyRuntimeState",
            "Assert-ApprovedHyperVTopologyRuntimeStateUnchanged",
            "Get-ApprovedHostSupportRuntimeState",
            "Assert-ApprovedHostSupportRuntimeStateUnchanged",
            "Invoke-ApprovedGuestNetworkPathProbe",
            "Assert-ApprovedGuestNetworkPathUnchanged"
        )
    }
    Import-Module $module -Scope Local -Force
    return $module
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ClosedProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    Assert-True (
        (@($Value.PSObject.Properties.Name) -join "|") -ceq ($Expected -join "|")
    ) "$Label property set or order is invalid"
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

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
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
    Assert-ClosedProperties $Expected $Fields "$Label expected"
    Assert-ClosedProperties $Actual $Fields "$Label actual"
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
    Assert-True ((Get-LowerSha256 $identityPath) -ceq $IdentitySha256) `
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
    Assert-ClosedProperties $result @(
        "schema", "status", "mode", "run_token", "identity_sha256", "candidate_sha",
        "client_sha256", "server_sha256", "controller_sha256", "support_listener", "topology",
        "guest_network_path", "guest_build", "cases", "process_absent", "adapter_absent",
        "addresses_absent", "routes_absent", "dns_absent", "strict_route_cases",
        "strict_route_wfp_identity_verified", "strict_route_wfp_absent", "inner_cleanup",
        "evidence_sha256", "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v2" -and
        $result.status -ceq "pass" -and
        $result.mode -ceq "hard-kill" -and
        $result.run_token -ceq $script:RunToken -and
        $result.identity_sha256 -ceq $IdentitySha256 -and
        $result.candidate_sha -ceq $CandidateSha -and
        $result.client_sha256 -ceq [string]$Ledger.client_sha256 -and
        $result.server_sha256 -ceq [string]$Ledger.server_sha256 -and
        $result.controller_sha256 -ceq [string]$Ledger.probe_sha256 -and
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
        $result.evidence_sha256 -ceq (Get-LowerSha256 $evidencePath) -and
        $result.stdout_sha256 -ceq (Get-LowerSha256 $stdoutPath) -and
        $result.stderr_sha256 -ceq (Get-LowerSha256 $stderrPath)
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
    Assert-ClosedProperties $result.guest_network_path @(
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
        "schema", "status", "source_mode", "run_token", "identity_sha256", "topology",
        "qualification_outcome", "processes", "adapters", "target_addresses",
        "target_routes", "dns_rows", "sibling_dll", "work_directories", "mutation_journals",
        "firewall_rules", "identity_journal", "finished_utc"
    )
    Assert-ClosedProperties $cleanup $cleanupProperties "hard-kill cleanup"
    Assert-True (
        $cleanup.schema -ceq "ferrum2.windows-tun.hard-kill-cleanup.v2" -and
        $cleanup.status -ceq "pass" -and
        $cleanup.source_mode -ceq "hard-kill" -and
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
        "candidate_sha", "identity_sha256", "controller_sha256", "guest_wrapper_sha256",
        "topology_runtime_sha256", "host_network_path_helper_sha256",
        "guest_network_path_probe_sha256", "staged_input_sha256", "rust_version",
        "guest_execution", "guest_build", "checkpoint_restored", "host_tun_unchanged",
        "host_support_unchanged", "host_network_mutations", "started_utc", "finished_utc",
        "final_vm_state", "evidence_files"
    )
    Assert-ClosedProperties $readback $fields "hard-kill host manifest"

    foreach ($name in @(
        "schema", "status", "mode", "run_token", "vm_name", "vm_id",
        "checkpoint_name", "checkpoint_id", "candidate_sha", "identity_sha256",
        "controller_sha256", "guest_wrapper_sha256", "topology_runtime_sha256",
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
        $readback.schema -ceq "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2" -and
        $readback.status -cin @("pass", "fail") -and
        $readback.mode -ceq "hard-kill" -and
        [string]$readback.candidate_sha -cmatch '^[0-9a-f]{40}$' -and
        [string]$readback.identity_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$readback.controller_sha256 -cmatch '^[0-9a-f]{64}$' -and
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
        "checkpoint_name", "checkpoint_id", "candidate_sha", "identity_sha256",
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
        Assert-ClosedProperties $row @("path", "bytes", "sha256") `
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

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the hard-kill Hyper-V orchestrator requires 64-bit Windows AMD64"
}

$commonModule = Import-ReviewedHyperVCommon
if ($InternalWorker) {
    if ([string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
        throw "bounded Hyper-V worker token is required"
    }
    Assert-BoundedHyperVInternalWorker -Token $InternalWorkerToken
} elseif (-not [string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
    throw "bounded Hyper-V worker token is not valid outside the internal worker"
}
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -ManifestPath $TopologyManifestPath `
    -ExpectedSha256 $TopologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$approvedVmName = [string]$topologyDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyDocument.Value.vm.id
$approvedCheckpointName = [string]$topologyDocument.Value.qualification_checkpoint.name
$approvedCheckpointId = [Guid][string]$topologyDocument.Value.qualification_checkpoint.id
$topologyBinding = New-TopologyBinding $topologyDocument
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address ([string]$topologyBinding.support_host_ipv4) `
    -TcpPort $SupportTcpPort `
    -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid `
    -ProcessOwner $SupportOwner
$supportListenerBinding = New-SupportListenerBinding $supportBaseline
$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\qualify_windows_tun.ps1") `
    -Label "qualification controller" `
    -MaximumBytes 4194304
$guestWrapperPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\invoke_windows_tun_hard_kill_guest.ps1") `
    -Label "hard-kill guest wrapper" `
    -MaximumBytes 2097152
$guestNetworkPathProbePath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tools\get_windows_tun_guest_network_path.ps1") `
    -Label "guest network-path probe" `
    -MaximumBytes 1048576
Assert-True (
    (Get-LowerSha256 $guestNetworkPathProbePath) -ceq
        [string]$topologyInitialization.GuestNetworkPathProbeSha256
) "guest network-path probe hash differs from the approved topology runtime"
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportBaseline
Assert-ExactObjectFields `
    -Expected $topologyBinding `
    -Actual $ledgerIdentity.Ledger.topology `
    -Fields $topologyPropertyNames `
    -Label "identity ledger topology"
Assert-ExactObjectFields `
    -Expected $supportListenerBinding `
    -Actual $ledgerIdentity.Ledger.support_listener `
    -Fields $supportListenerPropertyNames `
    -Label "identity ledger support listener"
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
Assert-True ((Get-LowerSha256 $wintunPath) -ceq $expectedWintunZipSha256) `
    "Wintun archive hash mismatch"
if ([string]::IsNullOrWhiteSpace($PowerShellZip)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default portable PowerShell ZIP"
    }
    $PowerShellZip = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\PowerShell-$expectedPowerShellVersion-win-x64.zip"
}
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default evidence directory"
    }
    $EvidenceDirectory = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\windows-tun-hard-kill-evidence\$RunToken"
}
$hostEvidencePath = Resolve-ExternalDirectoryTarget `
    -Path $EvidenceDirectory `
    -Label "hard-kill evidence directory"

# Resolve both exact VM/checkpoint identities and the DPAPI credential before any lifecycle action.
$baselineContext = Get-ApprovedVmContext
if ([string]$baselineContext.Vm.State -cne "Off") {
    throw "approved VM must be Off at the hard-kill qualification baseline"
}
$preflightTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
    -TopologyDocument $topologyDocument
Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
    -Expected $initialTopologyState `
    -Actual $preflightTopologyState
$preflightSupportState = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address ([string]$topologyBinding.support_host_ipv4) `
    -TcpPort $SupportTcpPort `
    -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid `
    -ProcessOwner $SupportOwner
Assert-ApprovedHostSupportRuntimeStateUnchanged `
    -Expected $supportBaseline `
    -Actual $preflightSupportState
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

# Supervise the complete VM-active phase from a separate process so a synchronous PowerShell Direct
# hang cannot prevent exact-GUID Stop -> Restore -> Stop cleanup.
if (-not $InternalWorker) {
    $supervisorCleanupAuthority = New-ApprovedVmCleanupAuthority -Context $baselineContext
    Invoke-BoundedHyperVWorkerSupervisor `
        -ScriptPath $PSCommandPath `
        -BoundParameters $PSBoundParameters `
        -ForwardedParameterNames @(
            "RunToken", "IdentityLedger", "TopologyManifestPath",
            "TopologyManifestSha256", "SupportTcpPort", "SupportUdpPort",
            "SupportPid", "SupportOwner", "WintunZip", "PowerShellZip",
            "EvidenceDirectory", "CredentialPath", "ReadinessTimeoutSeconds",
            "ShutdownTimeoutSeconds"
        ) `
        -WorkerTimeoutSeconds 7200 `
        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
        -ExpectedVmId $approvedVmId `
        -ExpectedVmName $approvedVmName `
        -ExpectedFinalState "Off" `
        -CleanupAuthority $supervisorCleanupAuthority `
        -CleanupMode "RestoreCheckpoint" `
        -WorkerContract "HardKill" `
        -FailureManifestPath (Join-Path $hostEvidencePath "host-orchestration.json") `
        -Label "Windows TUN hard kill worker"
    return
}

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-hard-kill-hyperv-" + [Guid]::NewGuid().ToString("N")
)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$hostArtifactRoot = Join-Path $temporaryRoot "artifacts"
$hostRuntimeLibraryRoot = Join-Path $temporaryRoot "vc-runtime"
$hostPowerShellArchive = Join-Path $temporaryRoot "portable-pwsh.zip"
$stagedInputManifestPath = Join-Path $temporaryRoot "staged-input.json"
$hostTopologyManifestPath = Join-Path $hostEvidencePath "topology-manifest.json"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$cleanupAuthority = $null
$checkpointRestored = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null
$wrapperEntry = $null
$guestResult = $null
$guestNetworkPathPreflight = $null
$guestNetworkPathPostflight = $null
$finalTopologyUnchanged = $false
$finalSupportUnchanged = $false

try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )
    Assert-True (
        (Get-LowerSha256 (Join-Path $hostEvidencePath "identity-ledger.json")) -ceq
            $ledgerIdentity.Sha256
    ) "host identity ledger evidence copy changed"
    $topologyBytes = [IO.File]::ReadAllBytes([string]$topologyDocument.Path)
    Assert-True (
        [long]$topologyBytes.Length -eq [long]$topologyDocument.Length -and
        (Get-LowerSha256 ([string]$topologyDocument.Path)) -ceq
            [string]$topologyDocument.Sha256
    ) "support topology manifest changed before evidence staging"
    [IO.File]::WriteAllBytes($hostTopologyManifestPath, $topologyBytes)
    Assert-True ((Get-LowerSha256 $hostTopologyManifestPath) -ceq
        [string]$topologyDocument.Sha256) `
        "host topology manifest evidence copy changed"
    $candidateArtifacts = Build-CandidateArtifacts `
        -Destination $hostArtifactRoot `
        -Ledger $ledgerIdentity.Ledger
    $portablePowerShell = New-PortablePowerShellArchive `
        -SourceZip $PowerShellZip `
        -Destination $hostPowerShellArchive
    Assert-True (
        $portablePowerShell.Sha256 -ceq $expectedPowerShellZipSha256 -and
        $portablePowerShell.Version -ceq $expectedPowerShellVersion
    ) "portable PowerShell identity changed after preflight"
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun.ps1" `
        -MaximumBytes 4194304
    $wrapperEntry = New-StagedFileEntry `
        -Path $guestWrapperPath `
        -Name "invoke_windows_tun_hard_kill_guest.ps1" `
        -MaximumBytes 2097152
    $identityEntry = New-StagedFileEntry `
        -Path $ledgerIdentity.Path `
        -Name "identity-ledger.json" `
        -MaximumBytes 65536
    $topologyManifestEntry = New-StagedFileEntry `
        -Path ([string]$topologyDocument.Path) `
        -Name "topology-manifest.json" `
        -MaximumBytes 131072
    $guestNetworkPathProbeEntry = New-StagedFileEntry `
        -Path $guestNetworkPathProbePath `
        -Name "get_windows_tun_guest_network_path.ps1" `
        -MaximumBytes 1048576
    $wintunEntry = New-StagedFileEntry `
        -Path $wintunPath `
        -Name "wintun-0.14.1.zip" `
        -MaximumBytes 16777216
    $vcEntries = @($runtimeLibraries | ForEach-Object {
        New-StagedFileEntry -Path $_.Path -Name $_.Name -MaximumBytes 16777216
    })
    Assert-True (
        $controllerEntry.sha256 -ceq [string]$ledgerIdentity.Ledger.probe_sha256 -and
        $identityEntry.sha256 -ceq $ledgerIdentity.Sha256 -and
        $topologyManifestEntry.sha256 -ceq [string]$topologyDocument.Sha256 -and
        $guestNetworkPathProbeEntry.sha256 -ceq
            [string]$topologyInitialization.GuestNetworkPathProbeSha256 -and
        $wintunEntry.sha256 -ceq $expectedWintunZipSha256
    ) "host staged input identity changed after preflight"
    $postBuildCandidate = Get-CandidateIdentity
    Assert-True ($postBuildCandidate.Sha -ceq $candidate.Sha) `
        "candidate commit changed during artifact preparation"

    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-staged-input.v2"
        mode = "hard-kill"
        run_token = $RunToken
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        guest_product = [string]$ledgerIdentity.Ledger.guest_product
        guest_edition = [string]$ledgerIdentity.Ledger.guest_edition
        guest_architecture = [string]$ledgerIdentity.Ledger.guest_architecture
        guest_version = [string]$ledgerIdentity.Ledger.guest_version
        guest_build = [string]$ledgerIdentity.Ledger.guest_build
        topology = $topologyBinding
        files = [ordered]@{
            guest_wrapper = $wrapperEntry
            controller = $controllerEntry
            identity_ledger = $identityEntry
            topology_manifest = $topologyManifestEntry
            guest_network_path_probe = $guestNetworkPathProbeEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Client.Path `
                -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Server.Path `
                -Name "ferrum2-server.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 536870912)
            vc_libraries = $vcEntries
        }
        runtime = [ordered]@{
            rust_version = $candidateArtifacts.RustVersion
            powershell_version = $portablePowerShell.Version
            powershell_executable_sha256 = $portablePowerShell.ExecutableSha256
            powershell_file_count = $portablePowerShell.FileCount
            powershell_expanded_bytes = $portablePowerShell.ExpandedBytes
        }
    }
    Write-JsonFileNew -Path $stagedInputManifestPath -Value $stagedInput
    $stagedInputSha256 = Get-LowerSha256 $stagedInputManifestPath
    Copy-Item `
        -LiteralPath $stagedInputManifestPath `
        -Destination (Join-Path $hostEvidencePath "staged-input.json") `
        -ErrorAction Stop
    Assert-True (
        (Get-LowerSha256 (Join-Path $hostEvidencePath "staged-input.json")) -ceq
            $stagedInputSha256
    ) "host staged-input evidence copy changed"

    # From this point every exit path must leave the exact checkpoint restored and the VM Off.
    $preMutationTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState `
        -Actual $preMutationTopologyState
    $preMutationSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $preMutationSupportState
    $cleanupAuthority = New-ApprovedVmCleanupAuthority `
        -Context (Get-ApprovedVmContext)
    $restoreRequired = $true
    Restore-ApprovedCheckpoint -TimeoutSeconds $ShutdownTimeoutSeconds
    Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
    $connection = Connect-ApprovedGuest `
        -Credential $guestCredential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    Assert-True (
        [string]$connection.Probe.Product -ceq [string]$ledgerIdentity.Ledger.guest_product -and
        [string]$connection.Probe.Edition -ceq [string]$ledgerIdentity.Ledger.guest_edition -and
        [string]$connection.Probe.Version -ceq [string]$ledgerIdentity.Ledger.guest_version -and
        [string]$connection.Probe.Build -ceq [string]$ledgerIdentity.Ledger.guest_build -and
        [string]$connection.Probe.Architecture -ceq "X64"
    ) "live guest identity differs from the identity ledger"

    $guestPaths = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList $RunToken `
        -ErrorAction Stop `
        -ScriptBlock {
            param([string]$Token)
            if ($Token -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') {
                throw "guest staging token is invalid"
            }
            $base = Join-Path $env:ProgramData "Ferrum2\HostQualification"
            if (Test-Path -LiteralPath $base) {
                $baseItem = Get-Item -LiteralPath $base -Force
                if (-not $baseItem.PSIsContainer -or
                    ($baseItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw "guest staging base is unsafe"
                }
            } else {
                New-Item -ItemType Directory -Path $base -ErrorAction Stop | Out-Null
            }
            $root = Join-Path $base $Token
            if (Test-Path -LiteralPath $root) {
                throw "guest hard-kill staging baseline is not absent"
            }
            $inputPath = Join-Path $root "input"
            $exportPath = Join-Path $root "export"
            New-Item -ItemType Directory -Path $inputPath -Force -ErrorAction Stop | Out-Null
            New-Item -ItemType Directory -Path $exportPath -Force -ErrorAction Stop | Out-Null
            foreach ($relative in @("controller", "artifacts", "runtime\vc-runtime")) {
                New-Item `
                    -ItemType Directory `
                    -Path (Join-Path $inputPath $relative) `
                    -Force `
                    -ErrorAction Stop | Out-Null
            }
            [pscustomobject]@{
                Root = $root
                Input = $inputPath
                Export = $exportPath
            }
        })
    Assert-True ($guestPaths.Count -eq 1) `
        "guest staging did not return one bounded path set"
    $guestRoot = [string]$guestPaths[0].Root
    $guestInputPath = [string]$guestPaths[0].Input
    $guestExportPath = [string]$guestPaths[0].Export
    $stagedFiles = @(
        [ordered]@{
            Source = $controllerPath
            Destination = Join-Path $guestInputPath "controller\qualify_windows_tun.ps1"
        },
        [ordered]@{
            Source = $guestWrapperPath
            Destination = Join-Path $guestInputPath "invoke_windows_tun_hard_kill_guest.ps1"
        },
        [ordered]@{
            Source = $ledgerIdentity.Path
            Destination = Join-Path $guestInputPath "identity-ledger.json"
        },
        [ordered]@{
            Source = [string]$topologyDocument.Path
            Destination = Join-Path $guestInputPath "topology-manifest.json"
        },
        [ordered]@{
            Source = $guestNetworkPathProbePath
            Destination = Join-Path $guestInputPath `
                "controller\get_windows_tun_guest_network_path.ps1"
        },
        [ordered]@{
            Source = $wintunPath
            Destination = Join-Path $guestInputPath "wintun-0.14.1.zip"
        },
        [ordered]@{
            Source = $stagedInputManifestPath
            Destination = Join-Path $guestInputPath "staged-input.json"
        },
        [ordered]@{
            Source = $portablePowerShell.Path
            Destination = Join-Path $guestInputPath "portable-pwsh.zip"
        },
        [ordered]@{
            Source = $candidateArtifacts.Client.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-client.exe"
        },
        [ordered]@{
            Source = $candidateArtifacts.Server.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-server.exe"
        }
    )
    foreach ($library in $runtimeLibraries) {
        $stagedFiles += [ordered]@{
            Source = $library.Path
            Destination = Join-Path $guestInputPath ("runtime\vc-runtime\" + $library.Name)
        }
    }
    foreach ($file in $stagedFiles) {
        Copy-Item `
            -ToSession $connection.Session `
            -LiteralPath $file.Source `
            -Destination $file.Destination `
            -ErrorAction Stop
    }
    $guestNetworkPathPreflight = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName "F2-M16P-A-$RunToken" `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument

    # BEGIN GUEST_ONLY_EXECUTION
    $guestResults = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList @(
            $guestRoot,
            $stagedInputSha256,
            $RunToken,
            $expectedPowerShellZipSha256,
            $expectedPowerShellVersion
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$Root,
                [string]$ExpectedManifestSha256,
                [string]$ExpectedRunToken,
                [string]$ExpectedPowerShellZipSha256,
                [string]$ExpectedPowerShellVersion
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $ProgressPreference = "SilentlyContinue"
            function Get-Sha256([string]$Path) {
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).
                    Hash.ToLowerInvariant()
            }
            function Assert-ManifestFile(
                [string]$Path,
                [object]$Entry,
                [string]$ExpectedName,
                [long]$MaximumBytes
            ) {
                $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                if ($item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
                    $Entry.name -cne $ExpectedName -or
                    [long]$Entry.bytes -ne [long]$item.Length -or
                    [string]$Entry.sha256 -cne (Get-Sha256 $Path)) {
                    throw "bootstrap staged file is invalid: $ExpectedName"
                }
            }
            $inputPath = Join-Path $Root "input"
            $manifestPath = Join-Path $inputPath "staged-input.json"
            if ((Get-Sha256 $manifestPath) -cne $ExpectedManifestSha256) {
                throw "bootstrap manifest hash changed"
            }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
                ConvertFrom-Json -ErrorAction Stop
            if ($manifest.schema -cne "ferrum2.windows-tun.hard-kill-staged-input.v2" -or
                $manifest.mode -cne "hard-kill" -or
                $manifest.run_token -cne $ExpectedRunToken -or
                [string]$manifest.files.powershell_archive.sha256 -cne
                    $ExpectedPowerShellZipSha256 -or
                [string]$manifest.runtime.powershell_version -cne $ExpectedPowerShellVersion -or
                [IO.Path]::GetFileName([IO.Path]::GetFullPath($Root).TrimEnd('\', '/')) -cne
                    $ExpectedRunToken) {
                throw "bootstrap staged identity is invalid"
            }
            $wrapperPath = Join-Path $inputPath "invoke_windows_tun_hard_kill_guest.ps1"
            $archivePath = Join-Path $inputPath "portable-pwsh.zip"
            Assert-ManifestFile $wrapperPath $manifest.files.guest_wrapper `
                "invoke_windows_tun_hard_kill_guest.ps1" 2097152
            Assert-ManifestFile $archivePath $manifest.files.powershell_archive `
                "portable-pwsh.zip" 536870912
            $pwshRoot = Join-Path $Root "pwsh74"
            if (Test-Path -LiteralPath $pwshRoot) {
                throw "portable PowerShell expansion baseline is not absent"
            }
            Expand-Archive -LiteralPath $archivePath -DestinationPath $pwshRoot -Force
            $items = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
                Get-ChildItem -LiteralPath $pwshRoot -Force -Recurse
            )
            $files = @($items | Where-Object { -not $_.PSIsContainer })
            $bytes = [long]($files | Measure-Object Length -Sum).Sum
            if (@($items | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -ne 0 -or
                $files.Count -ne [long]$manifest.runtime.powershell_file_count -or
                $bytes -ne [long]$manifest.runtime.powershell_expanded_bytes) {
                throw "portable PowerShell expansion boundary changed"
            }
            $pwsh = Join-Path $pwshRoot "pwsh.exe"
            if ((Get-Sha256 $pwsh) -cne
                [string]$manifest.runtime.powershell_executable_sha256) {
                throw "portable PowerShell executable hash changed"
            }
            $output = @(& $pwsh -NoProfile -File $wrapperPath `
                -RunRoot $Root `
                -ExpectedManifestSha256 $ExpectedManifestSha256 2>&1)
            $exitCode = [int]$LASTEXITCODE
            $outputLines = @($output | ForEach-Object { [string]$_ })
            if ($exitCode -ne 0) {
                throw "guest hard-kill wrapper failed with exit code $exitCode; " +
                    (@($outputLines | Select-Object -Last 20) -join " | ")
            }
            $expectedMarker = "m16_product_hard_kill_wrapper status=PASS " +
                "run_token=$ExpectedRunToken files=8/8 cleanup=PASS"
            if ($outputLines.Count -ne 1 -or $outputLines[0] -cne $expectedMarker) {
                throw "guest hard-kill wrapper marker is invalid"
            }
            [pscustomobject][ordered]@{
                schema = "ferrum2.windows-tun.hard-kill-guest-bootstrap.v2"
                status = "pass"
                mode = "hard-kill"
                run_token = $ExpectedRunToken
                staged_input_sha256 = $ExpectedManifestSha256
                topology = $manifest.topology
                files = [long]10
                cleanup = "pass"
            }
        })
    # END GUEST_ONLY_EXECUTION
    Assert-True ($guestResults.Count -eq 1) "guest hard-kill returned an invalid result count"
    $guestResult = $guestResults[0]
    Assert-ClosedProperties $guestResult @(
        "schema", "status", "mode", "run_token", "staged_input_sha256", "topology", "files",
        "cleanup"
    ) "hard-kill guest bootstrap"
    Assert-True (
        $guestResult.schema -ceq "ferrum2.windows-tun.hard-kill-guest-bootstrap.v2" -and
        $guestResult.status -ceq "pass" -and
        $guestResult.mode -ceq "hard-kill" -and
        $guestResult.run_token -ceq $RunToken -and
        $guestResult.staged_input_sha256 -ceq $stagedInputSha256 -and
        ($guestResult.files -is [int] -or $guestResult.files -is [long]) -and
        [long]$guestResult.files -eq 10 -and
        $guestResult.cleanup -ceq "pass"
    ) "hard-kill guest bootstrap result is invalid"
    Assert-ExactObjectFields `
        -Expected $topologyBinding `
        -Actual $guestResult.topology `
        -Fields $topologyPropertyNames `
        -Label "hard-kill guest bootstrap topology"

    $guestNetworkPathPostflight = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName "F2-M16P-A-$RunToken" `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument
    Assert-ApprovedGuestNetworkPathUnchanged `
        -Expected $guestNetworkPathPreflight.path `
        -Actual $guestNetworkPathPostflight.path
    $postGuestSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $postGuestSupportState
} catch {
    $runFailure = $_
} finally {
    if ($null -ne $connection -and
        -not [string]::IsNullOrWhiteSpace($guestExportPath) -and
        (Test-Path -LiteralPath $hostEvidencePath -PathType Container)) {
        try {
            Copy-GuestEvidence `
                -Session $connection.Session `
                -GuestExportPath $guestExportPath `
                -HostEvidencePath $hostEvidencePath
        } catch {
            $finalizationFailures.Add("evidence export failed: $($_.Exception.Message)")
        }
    }
    if ($restoreRequired) {
        $vmConfirmedOff = $false
        try {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $vmConfirmedOff = $true
        } catch {
            $finalizationFailures.Add(
                "mandatory emergency VM stop failed: $($_.Exception.Message)"
            )
        }
        if ($vmConfirmedOff) {
            $checkpointRestored = $false
            try {
                Restore-ApprovedCheckpointEmergency `
                    -Authority $cleanupAuthority `
                    -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds
                $checkpointRestored = $true
            } catch {
                $finalizationFailures.Add(
                    "mandatory emergency checkpoint restore failed: " +
                        $_.Exception.Message
                )
            }
        } else {
            $finalizationFailures.Add(
                "mandatory final checkpoint restore could not start because Off was not proven"
            )
        }
        try {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $vmConfirmedOff = $true
        } catch {
            $finalizationFailures.Add(
                "mandatory post-restore emergency VM stop failed: $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $connection) {
        Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        try {
            $resolvedTemporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot -ErrorAction Stop).Path
            Assert-True (
                (Test-PathWithinRoot -Path $resolvedTemporaryRoot -Root $temporaryBase) -and
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cmatch
                    '^ferrum2-hard-kill-hyperv-[0-9a-f]{32}$'
            ) "temporary staging cleanup boundary is invalid"
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label "temporary hard-kill staging cleanup"
            $temporaryItems = @(Get-Item -LiteralPath $resolvedTemporaryRoot -Force) + @(
                Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Force -Recurse
            )
            Assert-True (@($temporaryItems | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -eq 0) "temporary staging contains a reparse point"
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction Stop
        } catch {
            $finalizationFailures.Add("temporary staging cleanup failed: $($_.Exception.Message)")
        }
    }
}

$finalVmState = $null
try {
    $finalVmState = [string](Get-ApprovedVmContext).Vm.State
    if ($finalVmState -cne "Off") {
        $finalizationFailures.Add("approved VM final state is not Off")
        if ($restoreRequired -and $null -ne $cleanupAuthority) {
            Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
            $finalVmState = [string](
                Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
            ).State
            Assert-True ($finalVmState -ceq "Off") `
                "approved emergency final VM state is not Off"
        }
    }
} catch {
    $finalizationFailures.Add("approved VM final-state readback failed: $($_.Exception.Message)")
    if ($restoreRequired -and $null -ne $cleanupAuthority) {
        try {
            $finalVmState = [string](
                Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
            ).State
            if ($finalVmState -cne "Off") {
                Stop-ApprovedVmEmergency -Authority $cleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $finalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $cleanupAuthority
                ).State
            }
            Assert-True ($finalVmState -ceq "Off") `
                "approved emergency final VM state is not Off"
        } catch {
            $finalizationFailures.Add(
                "approved emergency final-state recovery failed: " +
                    $_.Exception.Message
            )
        }
    }
}
try {
    $finalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState `
        -Actual $finalTopologyState
    $finalTopologyUnchanged = $true
} catch {
    $finalizationFailures.Add(
        "approved topology final readback failed: $($_.Exception.Message)"
    )
}
try {
    $finalSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address ([string]$topologyBinding.support_host_ipv4) `
        -TcpPort $SupportTcpPort `
        -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid `
        -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportBaseline `
        -Actual $finalSupportState
    $finalSupportUnchanged = $true
} catch {
    $finalizationFailures.Add(
        "host support final readback failed: $($_.Exception.Message)"
    )
}
if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    try {
        $finalCandidate = Get-CandidateIdentity
        Assert-True ($finalCandidate.Sha -ceq $candidate.Sha) `
            "candidate commit changed during hard-kill qualification"
        Assert-HardKillExport `
            -Path (Join-Path $hostEvidencePath "guest\export") `
            -Ledger $ledgerIdentity.Ledger `
            -IdentitySha256 $ledgerIdentity.Sha256 `
            -CandidateSha $candidate.Sha
    } catch {
        $runFailure = $_
    }
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    "pass"
} else {
    "fail"
}
try {
        $hostEvidenceItem = Get-Item -LiteralPath $hostEvidencePath `
            -Force -ErrorAction Stop
        Assert-True (
            $hostEvidenceItem.PSIsContainer -and
            ($hostEvidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        ) "mandatory hard-kill evidence root is invalid"
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2"
            status = $status
            mode = "hard-kill"
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            topology = $topologyBinding
            support_listener = $supportListenerBinding
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            controller_sha256 = [string]$ledgerIdentity.Ledger.probe_sha256
            guest_wrapper_sha256 = if ($null -eq $wrapperEntry) {
                $null
            } else {
                [string]$wrapperEntry.sha256
            }
            topology_runtime_sha256 = [string]$topologyInitialization.TopologyRuntimeSha256
            host_network_path_helper_sha256 =
                [string]$topologyInitialization.HostNetworkPathHelperSha256
            guest_network_path_probe_sha256 =
                [string]$topologyInitialization.GuestNetworkPathProbeSha256
            staged_input_sha256 = $stagedInputSha256
            rust_version = if ($null -eq $candidateArtifacts) {
                $null
            } else {
                $candidateArtifacts.RustVersion
            }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = [string]$ledgerIdentity.Ledger.guest_build
            checkpoint_restored = [bool]$checkpointRestored
            host_tun_unchanged = [bool]$finalTopologyUnchanged
            host_support_unchanged = [bool]$finalSupportUnchanged
            host_network_mutations = [long]0
            started_utc = $startedUtc
            finished_utc = [DateTime]::UtcNow.ToString("o")
            final_vm_state = $finalVmState
            evidence_files = @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath)
        }
        $hostManifestPath = Join-Path $hostEvidencePath "host-orchestration.json"
        $hostManifestPendingPath = Join-Path $hostEvidencePath `
            "host-orchestration.pending.json"
        $hostManifestFinalCreated = $false
        $hostManifestFinalValidated = $false
        try {
            Assert-True (-not (Test-Path -LiteralPath $hostManifestPath) -and
                -not (Test-Path -LiteralPath $hostManifestPendingPath)) `
                "hard-kill host manifest publication paths must be absent"
            Write-JsonFileNew -Path $hostManifestPendingPath -Value $manifest
            Assert-HardKillHostManifest `
                -Path $hostManifestPendingPath -Expected $manifest `
                -EvidenceRoot $hostEvidencePath
            $expectedPublishedManifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                ($manifest | ConvertTo-Json -Depth 8) + "`n"
            )
            [IO.File]::Move($hostManifestPendingPath, $hostManifestPath)
            $hostManifestFinalCreated = $true
            Assert-True (-not (Test-Path -LiteralPath $hostManifestPendingPath)) `
                "hard-kill host manifest pending path survived publication"
            Assert-True (
                [Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($hostManifestPath)
                ) -ceq [Convert]::ToBase64String($expectedPublishedManifestBytes)
            ) "hard-kill host manifest changed during atomic publication"
            Assert-HardKillHostManifest `
                -Path $hostManifestPath -Expected $manifest `
                -EvidenceRoot $hostEvidencePath
            $hostManifestFinalValidated = $true
        } finally {
            foreach ($ownedManifestPath in @(
                $hostManifestPendingPath,
                $(if ($hostManifestFinalCreated -and -not $hostManifestFinalValidated) {
                    $hostManifestPath
                })
            )) {
                if (-not [string]::IsNullOrWhiteSpace([string]$ownedManifestPath) -and
                    (Test-Path -LiteralPath $ownedManifestPath)) {
                    $ownedManifestItem = Get-Item -LiteralPath $ownedManifestPath `
                        -Force -ErrorAction Stop
                    Assert-True (
                        -not $ownedManifestItem.PSIsContainer -and
                        ($ownedManifestItem.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -eq 0
                    ) "owned hard-kill manifest cleanup boundary is invalid"
                    [IO.File]::Delete($ownedManifestItem.FullName)
                }
            }
        }
} catch {
    $finalizationFailures.Add("host evidence manifest failed: $($_.Exception.Message)")
    $status = "fail"
}

if ($null -ne $runFailure -or $finalizationFailures.Count -ne 0) {
    $messages = [Collections.Generic.List[string]]::new()
    if ($null -ne $runFailure) {
        $messages.Add("hard-kill qualification failed: $($runFailure.Exception.Message)")
    }
    foreach ($message in $finalizationFailures) { $messages.Add($message) }
    throw [InvalidOperationException]::new(($messages -join "; "))
}

Write-Output (
    "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill run_token=$RunToken " +
    "candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
)
