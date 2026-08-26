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
