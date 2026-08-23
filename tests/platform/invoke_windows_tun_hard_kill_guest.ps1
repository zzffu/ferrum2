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

function Assert-UtcTimestamp([string]$Value, [string]$Label) {
    [DateTimeOffset]$timestamp = [DateTimeOffset]::MinValue
    $valid = [DateTimeOffset]::TryParseExact(
        $Value,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$timestamp
    ) -and $timestamp.Offset -eq [TimeSpan]::Zero
    Assert-True $valid "$Label is not a round-trip UTC timestamp"
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [int] -or $Value -is [long]
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
    $ledger = $text | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-ClosedProperties $ledger @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
        "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
        "candidate_sha", "probe_sha256", "client_sha256", "server_sha256", "support_listener",
        "test_binaries"
    ) "identity ledger"
    Assert-ClosedProperties $ledger.support_listener @(
        "ipv4", "tcp_port", "udp_port", "pid", "owner"
    ) "identity support listener"
    Assert-ClosedProperties $ledger.test_binaries @("client", "tun", "wintun") `
        "identity test binaries"
    $canonical = ($ledger | ConvertTo-Json -Compress -Depth 8) + "`n"
    Assert-True ([Convert]::ToHexString([Text.UTF8Encoding]::new($false).GetBytes($canonical)) -ceq
        [Convert]::ToHexString($bytes)) "identity ledger serialization is not canonical"
    Assert-True (
        $ledger.schema -eq 1 -and
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
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "captured controller exceeded its bounded timeout"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-True (
            [Text.Encoding]::UTF8.GetByteCount($stdout) -le 67108864 -and
            [Text.Encoding]::UTF8.GetByteCount($stderr) -le 67108864
        ) "captured controller output exceeded its byte boundary"
        Write-BytesCreateNew $StdoutPath ([Text.UTF8Encoding]::new($false).GetBytes($stdout))
        Write-BytesCreateNew $StderrPath ([Text.UTF8Encoding]::new($false).GetBytes($stderr))
        return [int]$process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Get-ExpectedTerminalMarker([object]$Ledger) {
    return "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS " +
        "adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT cleanup=PASS " +
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

function Assert-HardKillEvidence([string]$Path) {
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
                $properties[0].Value.GetInt64() -eq 1 -and
                $properties[1].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[1].Value.GetString() -ceq $expectedPhases[$index] -and
                $properties[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object
            ) "hard-kill evidence row schema, order, type, or phase changed"
            Assert-UtcTimestamp $properties[2].Value.GetString() "hard-kill evidence timestamp"
            $data = @($properties[3].Value.EnumerateObject())
            $expectedData = @("process", "adapter", "addresses", "routes", "dns")
            Assert-True (
                $data.Count -eq 5 -and
                (($data.Name | Sort-Object) -join "|") -ceq
                    (($expectedData | Sort-Object) -join "|") -and
                @($data | Where-Object {
                    $_.Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                    $_.Value.GetString() -cne "absent"
                }).Count -eq 0
            ) "hard-kill evidence residue data is not the closed all-absent set"
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
        "client_sha256", "server_sha256", "controller_sha256", "guest_build", "cases",
        "process_absent", "adapter_absent", "addresses_absent", "routes_absent", "dns_absent",
        "inner_cleanup", "evidence_sha256", "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v1" -and
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
        $result.inner_cleanup -ceq "pass" -and
        $result.evidence_sha256 -ceq (Get-LowerSha256 $script:artifactEvidence) -and
        $result.stdout_sha256 -ceq (Get-LowerSha256 $script:controllerStdout) -and
        $result.stderr_sha256 -ceq (Get-LowerSha256 $script:controllerStderr)
    ) "hard-kill result identity, JSON types, status, or hashes are invalid"
    Assert-UtcTimestamp $result.finished_utc "hard-kill result finished_utc"

    $cleanupProperties = @(
        "schema", "status", "source_mode", "run_token", "identity_sha256",
        "qualification_outcome", "processes", "adapters", "target_addresses", "target_routes",
        "dns_rows", "sibling_dll", "work_directories", "mutation_journals", "firewall_rules",
        "identity_journal", "finished_utc"
    )
    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-ClosedProperties $cleanup $cleanupProperties "hard-kill cleanup"
    Assert-True (
        $cleanup.schema -ceq "ferrum2.windows-tun.hard-kill-cleanup.v1" -and
        $cleanup.status -ceq "pass" -and
        $cleanup.source_mode -ceq "hard-kill" -and
        $cleanup.run_token -ceq $script:runToken -and
        $cleanup.identity_sha256 -ceq [string]$script:manifest.identity_sha256 -and
        $cleanup.qualification_outcome -ceq "success"
    ) "hard-kill cleanup identity or outcome is invalid"
    foreach ($name in $cleanupProperties[6..15]) {
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
    "guest_version", "guest_build", "files", "runtime"
) "staged input manifest"
Assert-ClosedProperties $manifest.files @(
    "guest_wrapper", "controller", "identity_ledger", "wintun_zip", "client", "server",
    "powershell_archive", "vc_libraries"
) "staged input files"
Assert-ClosedProperties $manifest.runtime @(
    "rust_version", "powershell_version", "powershell_executable_sha256",
    "powershell_file_count", "powershell_expanded_bytes"
) "staged runtime"
Assert-True (
    $manifest.schema -ceq "ferrum2.windows-tun.hard-kill-staged-input.v1" -and
    $manifest.mode -ceq "hard-kill" -and
    [string]$manifest.run_token -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$' -and
    [IO.Path]::GetFileName($runRootPath) -ceq [string]$manifest.run_token -and
    [string]$manifest.candidate_sha -cmatch '^[0-9a-f]{40}$' -and
    [string]$manifest.identity_sha256 -cmatch '^[0-9a-f]{64}$' -and
    $manifest.vm_name -ceq "Windows 10 MSIX packaging environment" -and
    $manifest.vm_id -ceq "82e20295-1d30-48e7-a751-e21d35d872d4" -and
    $manifest.checkpoint_name -ceq
        "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9" -and
    $manifest.checkpoint_id -ceq "1e570209-faf7-4248-8167-aa0687cdb8cf" -and
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
$runToken = [string]$manifest.run_token
$controller = Join-Path $inputRoot "controller\qualify_windows_tun.ps1"
$identityLedger = Join-Path $inputRoot "identity-ledger.json"
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
Assert-StagedFile $wintunZip $manifest.files.wintun_zip "wintun-0.14.1.zip" `
    1 16777216 "Wintun archive"
Assert-StagedFile $clientBinary $manifest.files.client "ferrum2-client.exe" `
    4096 536870912 "client binary"
Assert-StagedFile $serverBinary $manifest.files.server "ferrum2-server.exe" `
    4096 536870912 "server binary"
Assert-StagedFile $powerShellArchive $manifest.files.powershell_archive "portable-pwsh.zip" `
    1 536870912 "portable PowerShell archive"
$ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
Assert-True (
    (Get-LowerSha256 $controller) -ceq [string]$ledger.probe_sha256 -and
    (Get-LowerSha256 $clientBinary) -ceq [string]$ledger.client_sha256 -and
    (Get-LowerSha256 $serverBinary) -ceq [string]$ledger.server_sha256
) "controller or product identity differs from the ledger"

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
    $manifestPath, $PSCommandPath, $controller, $identityLedger, $wintunZip,
    $clientBinary, $serverBinary, $powerShellArchive
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
            "-ClientBinary", $clientBinary,
            "-ServerBinary", $serverBinary,
            "-ProductRoot", $inputRoot,
            "-RuntimeLibraryDirectory", $runtimeLibraries
        ) $controllerStdout $controllerStderr $true 7200
        Assert-True ($exitCode -eq 0) "hard-kill controller failed with exit code $exitCode"
        $ledger = Read-CanonicalIdentityLedger $identityLedger $manifest
        Assert-TerminalMarker $controllerStdout $ledger
        Assert-HardKillEvidence $evidenceSource
        Copy-ExactLeafCreateNew $evidenceSource $artifactEvidence "hard-kill evidence"
        $result = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-result.v1"
            status = "pass"
            mode = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
            candidate_sha = [string]$manifest.candidate_sha
            client_sha256 = [string]$ledger.client_sha256
            server_sha256 = [string]$ledger.server_sha256
            controller_sha256 = [string]$ledger.probe_sha256
            guest_build = [string]$ledger.guest_build
            cases = [long]3
            process_absent = $true
            adapter_absent = $true
            addresses_absent = $true
            routes_absent = $true
            dns_absent = $true
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
        Ensure-ExactDurableCopy $identityLedger $artifactLedger "identity ledger"
        if (Test-Path -LiteralPath $evidenceSource -PathType Leaf) {
            Assert-HardKillEvidence $evidenceSource
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
            schema = "ferrum2.windows-tun.hard-kill-cleanup.v1"
            status = "pass"
            source_mode = "hard-kill"
            run_token = $runToken
            identity_sha256 = [string]$manifest.identity_sha256
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
Assert-HardKillEvidence $artifactEvidence
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
