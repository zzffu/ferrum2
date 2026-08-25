#requires -Version 7.4

<#
.SYNOPSIS
Runs the M16 hard-kill controller and its ownership-scoped outer cleanup inside the approved guest.

.DESCRIPTION
This is a guest-only implementation detail of run_windows_tun_hard_kill_hyperv.ps1. It accepts only
a hash-bound staging root, never discovers a checkout or toolchain, and publishes the exact eight-file
hard-kill artifact set. Do not invoke it on a host.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedManifestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

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

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ClosedProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    Assert-True (
        (@($Value.PSObject.Properties.Name) -join "|") -ceq ($Expected -join "|")
    ) "$Label property set or order is invalid"
}

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class Ferrum2HardKillWfpIdentity {
    private const uint ERROR_SUCCESS = 0;
    private const int MAX_APP_ID_BYTES = 131072;

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB {
        public uint size;
        public IntPtr data;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);

    public static byte[] GetAppId(string executablePath) {
        if (String.IsNullOrWhiteSpace(executablePath) || !Path.IsPathRooted(executablePath))
            throw new ArgumentException("an absolute executable path is required", "executablePath");
        IntPtr allocation = IntPtr.Zero;
        var status = FwpmGetAppIdFromFileName0(executablePath, out allocation);
        try {
            if (status != ERROR_SUCCESS)
                throw new Win32Exception(unchecked((int)status), "FwpmGetAppIdFromFileName0");
            if (allocation == IntPtr.Zero)
                throw new InvalidOperationException("FwpmGetAppIdFromFileName0 returned no allocation");
            var blob = (FWP_BYTE_BLOB)Marshal.PtrToStructure(allocation, typeof(FWP_BYTE_BLOB));
            if (blob.size == 0 || blob.size > MAX_APP_ID_BYTES || blob.data == IntPtr.Zero)
                throw new InvalidOperationException("FwpmGetAppIdFromFileName0 returned an invalid blob");
            var bytes = new byte[checked((int)blob.size)];
            Marshal.Copy(blob.data, bytes, 0, bytes.Length);
            return bytes;
        } finally {
            if (allocation != IntPtr.Zero) FwpmFreeMemory0(ref allocation);
        }
    }
}
'@

function Get-WfpAppIdSha256([string]$ExecutablePath) {
    $resolved = (Resolve-Path -LiteralPath $ExecutablePath -ErrorAction Stop).Path
    Assert-OrdinaryLeaf $resolved "ferrum2 WFP AppId executable" 4096 536870912
    $bytes = [Ferrum2HardKillWfpIdentity]::GetAppId($resolved)
    Assert-True ($bytes.Length -gt 0 -and $bytes.Length -le 131072) `
        "ferrum2 WFP AppId byte boundary is invalid"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace(
            "-", ""
        ).ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Assert-OrdinaryLeaf(
    [string]$Path,
    [string]$Label,
    [long]$MinimumBytes,
    [long]$MaximumBytes
) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (-not $item.PSIsContainer) "$Label is not a file"
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "$Label must not be a reparse point"
    Assert-True ($item.Length -ge $MinimumBytes -and $item.Length -le $MaximumBytes) `
        "$Label byte boundary is invalid"
}

function Assert-OrdinaryDirectory([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True $item.PSIsContainer "$Label is not a directory"
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "$Label must not be a reparse point"
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

function Test-JsonInteger([object]$Value) {
    return $Value -is [int] -or $Value -is [long]
}

function Assert-CanonicalGuid([object]$Value, [string]$Label) {
    $parsed = [Guid]::Empty
    Assert-True (
        $Value -is [string] -and
        [Guid]::TryParseExact([string]$Value, "D", [ref]$parsed) -and
        $parsed -ne [Guid]::Empty -and
        $parsed.ToString("D") -ceq [string]$Value
    ) "$Label is not a canonical GUID"
}

function Assert-TopologyContract([object]$Topology, [string]$Label) {
    Assert-ClosedProperties $Topology $script:topologyPropertyNames $Label
    foreach ($name in @("manifest_sha256", "plan_sha256")) {
        Assert-True (
            $Topology.$name -is [string] -and
            [string]$Topology.$name -cmatch '^[0-9a-f]{64}$'
        ) "$Label hash is invalid: $name"
    }
    foreach ($name in @(
        "support_switch_id", "guest_interface_guid", "protected_host_tun_guid"
    )) {
        Assert-CanonicalGuid $Topology.$name "$Label $name"
    }
    foreach ($name in @(
        "support_host_ipv4", "guest_ipv4"
    )) {
        $parsed = $null
        Assert-True (
            $Topology.$name -is [string] -and
            [Net.IPAddress]::TryParse([string]$Topology.$name, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $parsed.ToString() -ceq [string]$Topology.$name
        ) "$Label IPv4 value is invalid: $name"
    }
    Assert-True (
        $Topology.support_network -is [string] -and
        [string]$Topology.support_network -cmatch '^[0-9]+(?:\.[0-9]+){3}/[0-9]{1,2}$' -and
        (Test-JsonInteger $Topology.support_prefix_length) -and
        [int]$Topology.support_prefix_length -ge 1 -and
        [int]$Topology.support_prefix_length -le 32 -and
        [string]$Topology.support_network -ceq
            "$($Topology.support_network.Split('/')[0])/$([int]$Topology.support_prefix_length)" -and
        $Topology.guest_interface_alias -is [string] -and
        -not [string]::IsNullOrWhiteSpace([string]$Topology.guest_interface_alias) -and
        (Test-JsonInteger $Topology.guest_interface_index) -and
        [int]$Topology.guest_interface_index -gt 0 -and
        $Topology.guest_mac_address -is [string] -and
        [string]$Topology.guest_mac_address -cmatch '^[0-9A-F]{12}$' -and
        (Test-JsonInteger $Topology.guest_mtu_bytes) -and
        [int]$Topology.guest_mtu_bytes -ge 1468 -and
        $Topology.protected_host_tun_name -is [string] -and
        -not [string]::IsNullOrWhiteSpace([string]$Topology.protected_host_tun_name) -and
        (Test-JsonInteger $Topology.protected_host_tun_index) -and
        [int]$Topology.protected_host_tun_index -gt 0 -and
        $Topology.protected_host_tun_status -is [string] -and
        [string]$Topology.protected_host_tun_status -ceq "Up"
    ) "$Label scalar identity is invalid"
}

function Assert-TopologyEqual([object]$Expected, [object]$Actual, [string]$Label) {
    Assert-TopologyContract $Expected "$Label expected topology"
    Assert-TopologyContract $Actual "$Label actual topology"
    foreach ($name in $script:topologyPropertyNames) {
        Assert-True ([string]$Expected.$name -ceq [string]$Actual.$name) `
            "$Label topology changed: $name"
    }
}

function Assert-SupportListenerContract([object]$Listener, [string]$Label) {
    Assert-ClosedProperties $Listener $script:supportListenerPropertyNames $Label
    $parsed = $null
    Assert-True (
        $Listener.ipv4 -is [string] -and
        [Net.IPAddress]::TryParse([string]$Listener.ipv4, [ref]$parsed) -and
        $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $parsed.ToString() -ceq [string]$Listener.ipv4 -and
        (Test-JsonInteger $Listener.tcp_port) -and
        [int]$Listener.tcp_port -ge 1 -and [int]$Listener.tcp_port -le 65535 -and
        (Test-JsonInteger $Listener.udp_port) -and
        [int]$Listener.udp_port -ge 1 -and [int]$Listener.udp_port -le 65532 -and
        (Test-JsonInteger $Listener.pid) -and
        [long]$Listener.pid -ge 1 -and [long]$Listener.pid -le [int]::MaxValue -and
        $Listener.owner -is [string] -and
        [string]$Listener.owner -cmatch '^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$' -and
        $Listener.executable_sha256 -is [string] -and
        [string]$Listener.executable_sha256 -cmatch '^[0-9a-f]{64}$'
    ) "$Label identity is invalid"
    Assert-UtcTimestamp $Listener.creation_utc "$Label creation_utc"
}

function Assert-NoReparseDirectoryChain([string]$Path, [string]$Root, [string]$Label) {
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    Assert-True (
        $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) "$Label escaped its approved root"
    $cursor = $fullPath
    while ($true) {
        Assert-OrdinaryDirectory $cursor $Label
        if ($cursor.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) { break }
        $next = [IO.Path]::GetDirectoryName($cursor)
        Assert-True (-not [string]::IsNullOrWhiteSpace($next) -and $next -cne $cursor) `
            "$Label directory chain is incomplete"
        $cursor = $next.TrimEnd('\', '/')
    }
}

function Write-BytesCreateNew([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Write-JsonCreateNew([string]$Path, [object]$Value) {
    $text = ($Value | ConvertTo-Json -Depth 8) + "`n"
    Write-BytesCreateNew $Path ([Text.UTF8Encoding]::new($false).GetBytes($text))
}

function Copy-ExactLeafCreateNew([string]$Source, [string]$Destination, [string]$Label) {
    Assert-OrdinaryLeaf $Source "$Label source" 1 67108864
    Assert-True (-not (Test-Path -LiteralPath $Destination)) `
        "$Label destination baseline is not absent"
    $input = [IO.FileStream]::new(
        $Source,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $output = $null
    try {
        $output = [IO.FileStream]::new(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $input.CopyTo($output)
        $output.Flush($true)
    } finally {
        if ($null -ne $output) { $output.Dispose() }
        $input.Dispose()
    }
    Assert-True (
        (Get-LowerSha256 $Source) -ceq (Get-LowerSha256 $Destination) -and
        (Get-Item -LiteralPath $Source -Force).Length -eq
            (Get-Item -LiteralPath $Destination -Force).Length
    ) "$Label changed during durable copy"
}

function Ensure-ExactDurableCopy([string]$Source, [string]$Destination, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Destination)) {
        Copy-ExactLeafCreateNew $Source $Destination $Label
        return
    }
    Assert-OrdinaryLeaf $Source "$Label source" 1 67108864
    Assert-OrdinaryLeaf $Destination "$Label destination" 1 67108864
    Assert-True (
        (Get-LowerSha256 $Source) -ceq (Get-LowerSha256 $Destination) -and
        (Get-Item -LiteralPath $Source -Force).Length -eq
            (Get-Item -LiteralPath $Destination -Force).Length
    ) "$Label durable copy differs from its source"
}

function Assert-StagedFile(
    [string]$Path,
    [object]$Entry,
    [string]$ExpectedName,
    [long]$MinimumBytes,
    [long]$MaximumBytes,
    [string]$Label
) {
    Assert-ClosedProperties $Entry @("name", "bytes", "sha256") "$Label manifest entry"
    Assert-True ($Entry.name -ceq $ExpectedName) "$Label manifest name is invalid"
    Assert-True ($Entry.bytes -is [long] -or $Entry.bytes -is [int]) `
        "$Label manifest byte count is not an integer"
    Assert-True ([string]$Entry.sha256 -cmatch '^[0-9a-f]{64}$') `
        "$Label manifest hash is invalid"
    Assert-OrdinaryLeaf $Path $Label $MinimumBytes $MaximumBytes
    Assert-True (
        [long](Get-Item -LiteralPath $Path -Force).Length -eq [long]$Entry.bytes -and
        (Get-LowerSha256 $Path) -ceq [string]$Entry.sha256
    ) "$Label does not match its staged manifest entry"
}

function Assert-NoDuplicateJsonProperties([string]$Json, [string]$Label) {
    function Assert-ElementProperties(
        [Text.Json.JsonElement]$Element,
        [string]$Path,
        [string]$DocumentLabel
    ) {
        if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($property in $Element.EnumerateObject()) {
                Assert-True $names.Add($property.Name) `
                    "$DocumentLabel contains a duplicate JSON property at $Path"
                Assert-ElementProperties $property.Value "$Path.$($property.Name)" $DocumentLabel
            }
        } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
            $index = 0
            foreach ($item in $Element.EnumerateArray()) {
                Assert-ElementProperties $item "$Path[$index]" $DocumentLabel
                $index += 1
            }
        }
    }

    $document = [Text.Json.JsonDocument]::Parse($Json)
    try {
        Assert-ElementProperties $document.RootElement '$' $Label
    } finally {
        $document.Dispose()
    }
}

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
        "candidate_sha", "probe_sha256", "client_sha256", "server_sha256", "support_listener",
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
        $ledger.schema -eq 2 -and
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
    foreach ($name in @("probe_sha256", "client_sha256", "server_sha256")) {
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
        "client_sha256", "server_sha256", "controller_sha256", "support_listener", "topology",
        "guest_network_path", "guest_build", "cases", "process_absent", "adapter_absent",
        "addresses_absent", "routes_absent", "dns_absent", "strict_route_cases",
        "strict_route_wfp_identity_verified", "strict_route_wfp_absent", "inner_cleanup", "evidence_sha256",
        "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v2" -and
        $result.status -ceq "pass" -and
        $result.mode -ceq "hard-kill" -and
        $result.run_token -ceq $script:runToken -and
        $result.identity_sha256 -ceq [string]$script:manifest.identity_sha256 -and
        $result.candidate_sha -ceq [string]$Ledger.candidate_sha -and
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

function Test-SamePath([string]$Left, [string]$Right) {
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    return [IO.Path]::GetFullPath($Left).TrimEnd('\', '/').Equals(
        [IO.Path]::GetFullPath($Right).TrimEnd('\', '/'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-ResidueSnapshot {
    $workPaths = @(
        "ferrum2-m15-tun-",
        "ferrum2-m16-network-",
        "ferrum2-m16-product-",
        "ferrum2-m17-tun-"
    ) | ForEach-Object {
        [IO.Path]::GetFullPath(
            (Join-Path ([IO.Path]::GetTempPath()) "$_$($script:runToken)")
        ).TrimEnd('\', '/')
    }
    $adapterNames = @(
        "Ferrum2-M15-$($script:runToken)",
        "Ferrum2-M16-$($script:runToken)",
        "F2-M16P-A-$($script:runToken)",
        "F2-M16P-M-$($script:runToken)",
        "F2-M17-$($script:runToken)"
    )
    $executables = @($script:clientBinary, $script:serverBinary)
    $processes = @(
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object {
            $row = $_
            @($executables | Where-Object {
                Test-SamePath ([string]$row.ExecutablePath) $_
            }).Count -eq 1 -and
                $row.CommandLine -and
                $row.CommandLine.IndexOf("--config", [StringComparison]::Ordinal) -ge 0 -and
                @($workPaths | Where-Object {
                    $row.CommandLine.IndexOf(
                        $_ + [IO.Path]::DirectorySeparatorChar,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                }).Count -ge 1
        }
    ).Count
    $adapters = @($adapterNames | ForEach-Object {
        $name = $_
        Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::Equals(
                    [string]$_.Name,
                    $name,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    }).Count
    $targets = @(
        "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
        "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208",
        "192.0.2.250", "192.0.2.241", "192.0.2.242", "2001:db8::241"
    )
    $addresses = @($targets | Where-Object {
        @(Get-NetIPAddress -InterfaceIndex 1 -IPAddress $_ -ErrorAction SilentlyContinue).Count -ne 0
    }).Count
    $routes = @($targets | Where-Object {
        $prefix = if ($_.Contains(":")) { "$_/128" } else { "$_/32" }
        @(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue).Count -ne 0
    }).Count
    $dnsRows = @($adapterNames | ForEach-Object {
        $name = $_
        Get-DnsClientServerAddress -InterfaceAlias $name -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::Equals(
                    [string]$_.InterfaceAlias,
                    $name,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    }).Count
    $journalRoot = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    ) "Ferrum2\ControllerRunIdentities"
    $journalPath = Join-Path $journalRoot "$($script:runToken).json"
    $siblingDll = Join-Path (Split-Path -Parent $script:clientBinary) "wintun.dll"

    return [pscustomobject][ordered]@{
        processes = [long]$processes
        adapters = [long]$adapters
        target_addresses = [long]$addresses
        target_routes = [long]$routes
        dns_rows = [long]$dnsRows
        sibling_dll = [long]$(if (Test-Path -LiteralPath $siblingDll) { 1 } else { 0 })
        work_directories = [long]@(
            $workPaths | Where-Object { Test-Path -LiteralPath $_ }
        ).Count
        mutation_journals = [long]@($workPaths | Where-Object {
            Test-Path -LiteralPath (Join-Path $_ "m17-network-mutations")
        }).Count
        firewall_rules = [long]@(
            Get-NetFirewallRule -Name "Ferrum2-M17-UDP-$($script:runToken)" `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        ).Count
        identity_journal = [long]@(
            @($journalPath, "$journalPath.pending") | Where-Object {
                Test-Path -LiteralPath $_
            }
        ).Count
    }
}

function Assert-ZeroResidue([object]$Residue) {
    foreach ($name in @(
        "processes", "adapters", "target_addresses", "target_routes", "dns_rows",
        "sibling_dll", "work_directories", "mutation_journals", "firewall_rules",
        "identity_journal"
    )) {
        Assert-True ([long]$Residue.$name -eq 0) `
            "token-scoped cleanup residue remained: $name=$($Residue.$name)"
    }
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the hard-kill guest wrapper requires 64-bit Windows AMD64"
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
Assert-True ($principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) "the hard-kill guest wrapper requires an elevated administrator"
Assert-True (-not [string]::IsNullOrWhiteSpace($env:ProgramData) -and
    [IO.Path]::IsPathFullyQualified($RunRoot)) "guest run root is not fully qualified"
$runRootPath = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
$expectedBase = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData "Ferrum2\HostQualification")
).TrimEnd('\', '/')
Assert-True (
    [IO.Path]::GetDirectoryName($runRootPath).TrimEnd('\', '/').Equals(
        $expectedBase,
        [StringComparison]::OrdinalIgnoreCase
    )
) "guest run root is not an immediate child of the approved staging base"
$inputRoot = Join-Path $runRootPath "input"
$exportRoot = Join-Path $runRootPath "export"
$manifestPath = Join-Path $inputRoot "staged-input.json"
Assert-NoReparseDirectoryChain $runRootPath ([IO.Path]::GetFullPath($env:ProgramData)) `
    "guest staging directory"
Assert-OrdinaryDirectory $inputRoot "input root"
Assert-OrdinaryDirectory $exportRoot "export root"
Assert-OrdinaryLeaf $manifestPath "staged input manifest" 2 1048576
Assert-True ((Get-LowerSha256 $manifestPath) -ceq $ExpectedManifestSha256) `
    "staged input manifest hash changed"
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 12 -ErrorAction Stop
Assert-ClosedProperties $manifest @(
    "schema", "mode", "run_token", "candidate_sha", "identity_sha256", "vm_name", "vm_id",
    "checkpoint_name", "checkpoint_id", "guest_product", "guest_edition", "guest_architecture",
    "guest_version", "guest_build", "topology", "files", "runtime"
) "staged input manifest"
Assert-ClosedProperties $manifest.files @(
    "guest_wrapper", "controller", "identity_ledger", "topology_manifest",
    "guest_network_path_probe", "wintun_zip", "client", "server", "powershell_archive",
    "vc_libraries"
) "staged input files"
Assert-ClosedProperties $manifest.runtime @(
    "rust_version", "powershell_version", "powershell_executable_sha256",
    "powershell_file_count", "powershell_expanded_bytes"
) "staged runtime"
Assert-True (
    $manifest.schema -ceq "ferrum2.windows-tun.hard-kill-staged-input.v2" -and
    $manifest.mode -ceq "hard-kill" -and
    [string]$manifest.run_token -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$' -and
    [IO.Path]::GetFileName($runRootPath) -ceq [string]$manifest.run_token -and
    [string]$manifest.candidate_sha -cmatch '^[0-9a-f]{40}$' -and
    [string]$manifest.identity_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $manifest.vm_name -is [string] -and
    -not [string]::IsNullOrWhiteSpace([string]$manifest.vm_name) -and
    $manifest.guest_architecture -ceq "AMD64" -and
    $manifest.runtime.rust_version -is [string] -and
    [string]$manifest.runtime.rust_version -cmatch '^rustc 1\.97\.1 \(' -and
    $manifest.runtime.powershell_version -is [string] -and
    [string]$manifest.runtime.powershell_version -ceq "7.4.19" -and
    $PSVersionTable.PSVersion.ToString() -ceq [string]$manifest.runtime.powershell_version -and
    [string]$manifest.runtime.powershell_executable_sha256 -cmatch '^[0-9a-f]{64}$' -and
    (Test-JsonInteger $manifest.runtime.powershell_file_count) -and
    [long]$manifest.runtime.powershell_file_count -ge 1 -and
    [long]$manifest.runtime.powershell_file_count -le 4096 -and
    (Test-JsonInteger $manifest.runtime.powershell_expanded_bytes) -and
    [long]$manifest.runtime.powershell_expanded_bytes -ge 1 -and
    [long]$manifest.runtime.powershell_expanded_bytes -le 1073741824
) "staged hard-kill identity is invalid"
Assert-CanonicalGuid $manifest.vm_id "staged VM"
Assert-CanonicalGuid $manifest.checkpoint_id "staged qualification checkpoint"
Assert-TopologyContract $manifest.topology "staged topology"
$runToken = [string]$manifest.run_token
$controller = Join-Path $inputRoot "controller\qualify_windows_tun.ps1"
$identityLedger = Join-Path $inputRoot "identity-ledger.json"
$topologyManifestPath = Join-Path $inputRoot "topology-manifest.json"
$guestNetworkPathProbe = Join-Path $inputRoot "controller\get_windows_tun_guest_network_path.ps1"
$guestNetworkPath = Join-Path $runRootPath "guest-network-path.json"
$wintunZip = Join-Path $inputRoot "wintun-0.14.1.zip"
$clientBinary = Join-Path $inputRoot "artifacts\ferrum2-client.exe"
$serverBinary = Join-Path $inputRoot "artifacts\ferrum2-server.exe"
$runtimeLibraries = Join-Path $inputRoot "runtime\vc-runtime"
$powerShellArchive = Join-Path $inputRoot "portable-pwsh.zip"
$pwsh = Join-Path $runRootPath "pwsh74\pwsh.exe"

Assert-StagedFile $PSCommandPath $manifest.files.guest_wrapper `
    "invoke_windows_tun_hard_kill_guest.ps1" 4096 2097152 "guest wrapper"
Assert-StagedFile $controller $manifest.files.controller "qualify_windows_tun.ps1" `
    4096 4194304 "controller"
Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
    "topology-manifest.json" 2 131072 "support topology manifest"
Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
    "get_windows_tun_guest_network_path.ps1" 4096 1048576 "guest network-path probe"
Assert-StagedFile $wintunZip $manifest.files.wintun_zip "wintun-0.14.1.zip" `
    1 16777216 "Wintun archive"
Assert-StagedFile $clientBinary $manifest.files.client "ferrum2-client.exe" `
    4096 536870912 "client binary"
Assert-StagedFile $serverBinary $manifest.files.server "ferrum2-server.exe" `
    4096 536870912 "server binary"
Assert-StagedFile $powerShellArchive $manifest.files.powershell_archive "portable-pwsh.zip" `
    1 536870912 "portable PowerShell archive"
[void](Read-StagedTopologyManifest $topologyManifestPath $manifest)
$ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
Assert-True (
    (Get-LowerSha256 $controller) -ceq [string]$ledger.probe_sha256 -and
    (Get-LowerSha256 $clientBinary) -ceq [string]$ledger.client_sha256 -and
    (Get-LowerSha256 $serverBinary) -ceq [string]$ledger.server_sha256
) "controller or product identity differs from the ledger"
$expectedAppIdSha256 = Get-WfpAppIdSha256 $clientBinary

Assert-OrdinaryDirectory $runtimeLibraries "runtime library directory"
$vcEntries = @($manifest.files.vc_libraries)
$allowedVcNames = @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
Assert-True (
    $vcEntries.Count -ge 1 -and
    $vcEntries.Count -le 3 -and
    $vcEntries[0].name -ceq "vcruntime140.dll" -and
    @($vcEntries.name | Sort-Object -Unique).Count -eq $vcEntries.Count -and
    @($vcEntries | Where-Object { $allowedVcNames -cnotcontains [string]$_.name }).Count -eq 0
) "Visual C++ runtime manifest is invalid"
foreach ($entry in $vcEntries) {
    Assert-StagedFile (Join-Path $runtimeLibraries ([string]$entry.name)) $entry `
        ([string]$entry.name) 1 16777216 "Visual C++ runtime"
}
$inputItems = @(Get-Item -LiteralPath $inputRoot -Force -ErrorAction Stop) + @(
    Get-ChildItem -LiteralPath $inputRoot -Force -Recurse -ErrorAction Stop
)
$inputFiles = @($inputItems | Where-Object { -not $_.PSIsContainer })
$inputDirectories = @($inputItems | Where-Object { $_.PSIsContainer })
$expectedInputFiles = @(
    $manifestPath, $PSCommandPath, $controller, $identityLedger, $topologyManifestPath,
    $guestNetworkPathProbe, $wintunZip, $clientBinary, $serverBinary, $powerShellArchive
) + @($vcEntries | ForEach-Object {
    Join-Path $runtimeLibraries ([string]$_.name)
})
$expectedInputDirectories = @(
    $inputRoot,
    (Join-Path $inputRoot "controller"),
    (Join-Path $inputRoot "artifacts"),
    (Join-Path $inputRoot "runtime"),
    $runtimeLibraries
)
Assert-True (
    @($inputItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -eq 0 -and
    $inputFiles.Count -eq $expectedInputFiles.Count -and
    $inputDirectories.Count -eq $expectedInputDirectories.Count -and
    (($inputFiles.FullName | ForEach-Object {
        [IO.Path]::GetFullPath($_).ToLowerInvariant()
    } | Sort-Object) -join "|") -ceq
        (($expectedInputFiles | ForEach-Object {
            [IO.Path]::GetFullPath($_).ToLowerInvariant()
        } | Sort-Object) -join "|") -and
    (($inputDirectories.FullName | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd('\', '/').ToLowerInvariant()
    } | Sort-Object) -join "|") -ceq
        (($expectedInputDirectories | ForEach-Object {
            [IO.Path]::GetFullPath($_).TrimEnd('\', '/').ToLowerInvariant()
        } | Sort-Object) -join "|")
) "guest staged input is not the exact ordinary file and directory set"
Assert-OrdinaryLeaf $pwsh "portable PowerShell executable" 4096 536870912
Assert-True (
    (Get-LowerSha256 $pwsh) -ceq [string]$manifest.runtime.powershell_executable_sha256
) "portable PowerShell executable hash changed"

$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$currentVersion = Get-ItemProperty `
    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
    -ErrorAction Stop
Assert-True (
    $computer.Manufacturer -ceq "Microsoft Corporation" -and
    $computer.Model -ceq "Virtual Machine" -and
    [string]$currentVersion.ProductName -ceq $manifest.guest_product -and
    [string]$currentVersion.EditionID -ceq $manifest.guest_edition -and
    [Environment]::OSVersion.Version.ToString() -ceq $manifest.guest_version -and
    "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)" -ceq $manifest.guest_build
) "live guest identity differs from the staged contract"

Assert-True (@(Get-ChildItem -LiteralPath $exportRoot -Force).Count -eq 0) `
    "hard-kill export baseline is not empty"
$evidenceSource = "$identityLedger.evidence-$runToken.jsonl"
Assert-True (-not (Test-Path -LiteralPath $evidenceSource)) `
    "hard-kill controller evidence baseline is not absent"
Assert-ZeroResidue (Get-ResidueSnapshot)
$guestNetworkPathValue = Invoke-GuestNetworkPathProbe `
    -Path $guestNetworkPathProbe `
    -Topology $manifest.topology `
    -SupportPort ([int]$ledger.support_listener.udp_port) `
    -ManagedAdapterName "F2-M16P-A-$runToken" `
    -OutputPath $guestNetworkPath
$guestNetworkPathLength = [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length
$guestNetworkPathSha256 = Get-LowerSha256 $guestNetworkPath
$controllerStdout = Join-Path $exportRoot "controller.stdout.log"
$controllerStderr = Join-Path $exportRoot "controller.stderr.log"
$cleanupStdout = Join-Path $exportRoot "cleanup.stdout.log"
$cleanupStderr = Join-Path $exportRoot "cleanup.stderr.log"
$artifactLedger = Join-Path $exportRoot "identity-ledger.json"
$artifactEvidence = Join-Path $exportRoot "hard-kill-evidence.jsonl"
Copy-ExactLeafCreateNew $identityLedger $artifactLedger "identity ledger"
$qualificationFailure = $null
$cleanupFailure = $null
$qualificationOutcome = "failure"

try {
    try {
        $exitCode = Invoke-CapturedPwsh @(
            "-NoProfile", "-File", $controller,
            "-Mode", "hard-kill",
            "-RunToken", $runToken,
            "-IdentityLedger", $identityLedger,
            "-TopologyManifest", $topologyManifestPath,
            "-GuestNetworkPath", $guestNetworkPath,
            "-ClientBinary", $clientBinary,
            "-ServerBinary", $serverBinary,
            "-ProductRoot", $inputRoot,
            "-RuntimeLibraryDirectory", $runtimeLibraries
        ) $controllerStdout $controllerStderr $true 7200
        Assert-True ($exitCode -eq 0) "hard-kill controller failed with exit code $exitCode"
        $ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
        Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
            "topology-manifest.json" 2 131072 "support topology manifest"
        Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
            "get_windows_tun_guest_network_path.ps1" 4096 1048576 `
            "guest network-path probe"
        Assert-OrdinaryLeaf $guestNetworkPath "guest network-path output" 2 65536
        Assert-True (
            [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length -eq
                $guestNetworkPathLength -and
            (Get-LowerSha256 $guestNetworkPath) -ceq $guestNetworkPathSha256
        ) "guest network-path output changed during qualification"
        Assert-TerminalMarker $controllerStdout $ledger
        Assert-HardKillEvidence $evidenceSource $expectedAppIdSha256
        Copy-ExactLeafCreateNew $evidenceSource $artifactEvidence "hard-kill evidence"
        $result = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-result.v2"
            status = "pass"
            mode = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
            candidate_sha = [string]$manifest.candidate_sha
            client_sha256 = [string]$ledger.client_sha256
            server_sha256 = [string]$ledger.server_sha256
            controller_sha256 = [string]$ledger.probe_sha256
            support_listener = $ledger.support_listener
            topology = $ledger.topology
            guest_network_path = $guestNetworkPathValue
            guest_build = [string]$ledger.guest_build
            cases = [long]3
            process_absent = $true
            adapter_absent = $true
            addresses_absent = $true
            routes_absent = $true
            dns_absent = $true
            strict_route_cases = [long]2
            strict_route_wfp_identity_verified = $true
            strict_route_wfp_absent = $true
            inner_cleanup = "pass"
            evidence_sha256 = Get-LowerSha256 $artifactEvidence
            stdout_sha256 = Get-LowerSha256 $controllerStdout
            stderr_sha256 = Get-LowerSha256 $controllerStderr
            finished_utc = [DateTime]::UtcNow.ToString("o")
        }
        Write-JsonCreateNew (Join-Path $exportRoot "hard-kill-result.json") $result
        $qualificationOutcome = "success"
    } catch {
        $qualificationFailure = $_
    }
} finally {
    $cleanupIssues = [Collections.Generic.List[string]]::new()
    $cleanupInvocationPassed = $false
    $readbackPassed = $false
    $residue = $null
    try {
        $cleanupExit = Invoke-CapturedPwsh @(
            "-NoProfile", "-File", $controller,
            "-Mode", "cleanup",
            "-RunToken", $runToken
        ) $cleanupStdout $cleanupStderr $false 900
        if ($cleanupExit -ne 0) {
            throw "cleanup controller failed with exit code $cleanupExit"
        }
        $cleanupInvocationPassed = $true
    } catch {
        $cleanupIssues.Add("cleanup invocation: $($_.Exception.Message)")
    }
    try {
        [void](Read-CanonicalIdentityLedger $identityLedger $manifest)
        Assert-StagedFile $topologyManifestPath $manifest.files.topology_manifest `
            "topology-manifest.json" 2 131072 "support topology manifest"
        Assert-StagedFile $guestNetworkPathProbe $manifest.files.guest_network_path_probe `
            "get_windows_tun_guest_network_path.ps1" 4096 1048576 `
            "guest network-path probe"
        Assert-OrdinaryLeaf $guestNetworkPath "guest network-path output" 2 65536
        Assert-True (
            [long](Get-Item -LiteralPath $guestNetworkPath -Force).Length -eq
                $guestNetworkPathLength -and
            (Get-LowerSha256 $guestNetworkPath) -ceq $guestNetworkPathSha256
        ) "guest network-path output changed during cleanup"
        Ensure-ExactDurableCopy $identityLedger $artifactLedger "identity ledger"
        if (Test-Path -LiteralPath $evidenceSource -PathType Leaf) {
            Assert-HardKillEvidence $evidenceSource $expectedAppIdSha256
            Ensure-ExactDurableCopy $evidenceSource $artifactEvidence "hard-kill evidence"
        } elseif ($qualificationOutcome -ceq "success") {
            throw "successful qualification lost its evidence source"
        }
        $readbackPassed = $true
    } catch {
        $cleanupIssues.Add("durable evidence readback: $($_.Exception.Message)")
    }
    try {
        $residue = Get-ResidueSnapshot
        Assert-ZeroResidue $residue
    } catch {
        $cleanupIssues.Add("zero-residue readback: $($_.Exception.Message)")
    }
    if ($cleanupInvocationPassed -and $readbackPassed -and
        $null -ne $residue -and $cleanupIssues.Count -eq 0) {
        $cleanup = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-cleanup.v2"
            status = "pass"
            source_mode = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
            topology = $manifest.topology
            qualification_outcome = $qualificationOutcome
            processes = [long]$residue.processes
            adapters = [long]$residue.adapters
            target_addresses = [long]$residue.target_addresses
            target_routes = [long]$residue.target_routes
            dns_rows = [long]$residue.dns_rows
            sibling_dll = [long]$residue.sibling_dll
            work_directories = [long]$residue.work_directories
            mutation_journals = [long]$residue.mutation_journals
            firewall_rules = [long]$residue.firewall_rules
            identity_journal = [long]$residue.identity_journal
            finished_utc = [DateTime]::UtcNow.ToString("o")
        }
        Write-JsonCreateNew (Join-Path $exportRoot "hard-kill-cleanup.json") $cleanup
    }
    if ($cleanupIssues.Count -ne 0) {
        $cleanupFailure = [InvalidOperationException]::new(($cleanupIssues -join "; "))
    }
}

if ($null -ne $qualificationFailure -or $null -ne $cleanupFailure) {
    $failures = [Collections.Generic.List[string]]::new()
    if ($null -ne $qualificationFailure) {
        $failures.Add("qualification: $($qualificationFailure.Exception.Message)")
    }
    if ($null -ne $cleanupFailure) {
        $failures.Add("cleanup: $($cleanupFailure.Message)")
    }
    throw ($failures -join "; ")
}

$ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
Assert-TerminalMarker $controllerStdout $ledger
Assert-HardKillEvidence $artifactEvidence $expectedAppIdSha256
Assert-PublishedHardKillJson $ledger
$items = @(Get-ChildItem -LiteralPath $exportRoot -Force -ErrorAction Stop)
Assert-True (
    $items.Count -eq 8 -and
    (($items.Name | Sort-Object) -join "|") -ceq
        (($expectedArtifactFiles | Sort-Object) -join "|") -and
    @($items | Where-Object {
        $_.PSIsContainer -or
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }).Count -eq 0
) "successful hard-kill artifact set is not the exact eight ordinary files"
[Console]::Out.WriteLine(
    "m16_product_hard_kill_wrapper status=PASS run_token=$runToken files=8/8 cleanup=PASS"
)
