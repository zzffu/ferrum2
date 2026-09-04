Set-StrictMode -Version Latest

$script:ExpectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$script:ExpectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$script:WindowsRustTarget = "x86_64-pc-windows-msvc"

function Write-NewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (Test-Path -LiteralPath $Path) { throw "output baseline must be absent: $Path" }
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Resolve-Ferrum2WintunArchive {
    $paths = @(
        (Join-Path $env:LOCALAPPDATA "Ferrum2\assets\wintun-0.14.1.zip"),
        (Join-Path $env:LOCALAPPDATA "Ferrum2\wintun-0.14.1.zip"),
        (Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads\wintun-0.14.1.zip"),
        (Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads\wintun-0.14.1 (1).zip")
    )
    $matches = @($paths | Where-Object {
        (Test-Path -LiteralPath $_ -PathType Leaf) -and
        (Get-FileHash -LiteralPath $_ -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() `
            -ceq $script:ExpectedWintunZipSha256
    })
    if ($matches.Count -eq 0) {
        throw "the reviewed Wintun 0.14.1 archive is unavailable in the private runtime cache"
    }
    return (Resolve-Path -LiteralPath ($matches | Sort-Object | Select-Object -First 1) `
        -ErrorAction Stop).Path
}

function Expand-Ferrum2WintunDll {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $entries = @($zip.Entries | Where-Object {
            $_.FullName.Replace("\", "/") -cmatch '(^|/)bin/amd64/wintun\.dll$'
        })
        if ($entries.Count -ne 1 -or $entries[0].Length -le 0 -or $entries[0].Length -gt 4MB) {
            throw "reviewed Wintun archive DLL member identity is invalid"
        }
        if (Test-Path -LiteralPath $Destination) { throw "Wintun DLL output baseline must be absent" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $Destination, $false)
    } finally {
        $zip.Dispose()
    }
    $hash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($hash -cne $script:ExpectedWintunDllSha256) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        throw "reviewed Wintun DLL identity mismatch"
    }
    return $hash
}

function Resolve-Ferrum2CommitSha {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Sha
    )
    $resolved = (& git -C $RepositoryRoot rev-parse --verify "$Sha^{commit}" 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $resolved -cnotmatch '^[0-9a-f]{40}$' -or $resolved -cne $Sha) {
        throw "host performance commit identity is unavailable: $Sha"
    }
    return $resolved
}

function Export-Ferrum2CommitTree {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination) { throw "build source baseline must be absent" }
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    $archive = "$Destination.tar"
    & git -C $RepositoryRoot archive --format=tar --output=$archive $Sha
    if ($LASTEXITCODE -ne 0) { throw "git archive failed for $Sha" }
    try {
        & tar -xf $archive -C $Destination
        if ($LASTEXITCODE -ne 0) { throw "extract commit archive failed for $Sha" }
    } finally {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    }
}

function Get-Ferrum2M4SourceBundleIdentity {
    param([Parameter(Mandatory = $true)][string]$SourceRoot)
    $packageRoot = Join-Path $SourceRoot "tools\ferrum2-m4-qualification"
    $manifestPath = Join-Path $packageRoot "src\m4_support\windows_tun\bundle.json"
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
    if ($manifestItem.PSIsContainer -or $manifestItem.Length -le 0 -or
        $manifestItem.Length -gt 1MB -or
        ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "M4 Windows TUN source bundle manifest identity is invalid"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -ErrorAction Stop
    $manifestProperties = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($manifestProperties -join "|") -cne "entrypoint|files|kind|schema_version" -or
        [int]$manifest.schema_version -ne 1 -or
        [string]$manifest.kind -cne "ferrum2.m4-windows-tun-source-bundle.v2" -or
        [string]$manifest.entrypoint -cne "src/main.rs") {
        throw "M4 Windows TUN source bundle manifest contract is invalid"
    }
    $actualPaths = @(
        "Cargo.toml"
        Get-ChildItem -LiteralPath (Join-Path $packageRoot "src") -Filter "*.rs" -File -Recurse |
            ForEach-Object {
                [IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace("\", "/")
            }
    ) | Sort-Object
    $manifestPaths = @($manifest.files | ForEach-Object { [string]$_.path } | Sort-Object)
    if ($manifestPaths.Count -eq 0 -or
        ($manifestPaths -join "|") -cne ($actualPaths -join "|")) {
        throw "M4 Windows TUN source bundle closure is incomplete"
    }
    if (@($manifestPaths | Sort-Object -Unique).Count -ne $manifestPaths.Count) {
        throw "M4 Windows TUN source bundle paths are not unique"
    }
    foreach ($row in $manifest.files) {
        $rowProperties = @($row.PSObject.Properties.Name | Sort-Object)
        $relativePath = [string]$row.path
        if (($rowProperties -join "|") -cne "bytes|path|sha256" -or
            [IO.Path]::IsPathFullyQualified($relativePath) -or
            $relativePath.Contains("..") -or
            [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "M4 Windows TUN source bundle member identity is invalid"
        }
        $path = Join-Path $packageRoot $relativePath
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            [long]$row.bytes -ne $item.Length -or
            [string]$row.sha256 -cne
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw "M4 Windows TUN source bundle member identity mismatch: $relativePath"
        }
    }
    return (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Invoke-Ferrum2CargoBuild {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$TargetRoot,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$IncludeHarness
    )
    $cargo = [string](Get-Command cargo -CommandType Application -ErrorAction Stop).Source
    $packages = "-p ferrum2-client -p ferrum2-server"
    if ($IncludeHarness) { $packages += " -p ferrum2-m4-qualification" }
    $arguments = "build --release --locked --offline --target $script:WindowsRustTarget " +
        "--target-dir `"$TargetRoot`" $packages"
    [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $cargo `
        -Arguments $arguments -WorkingDirectory $SourceRoot -LogPrefix "cargo-$Label" `
        -TimeoutSeconds 1800)
}

function Build-Ferrum2HostMember {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][string]$WintunDll,
        [switch]$IncludeHarness
    )
    $memberRoot = Join-Path $Context.run_root "builds\$Label"
    $sourceRoot = Join-Path $memberRoot "source"
    $targetRoot = Join-Path $memberRoot "target"
    Export-Ferrum2CommitTree -RepositoryRoot $Context.repository_root -Sha $Sha -Destination $sourceRoot
    $sourceBundleSha256 = Get-Ferrum2M4SourceBundleIdentity -SourceRoot $sourceRoot
    Invoke-Ferrum2CargoBuild -Context $Context -SourceRoot $sourceRoot `
        -TargetRoot $targetRoot -Label $Label -IncludeHarness:$IncludeHarness
    $binaryRoot = Join-Path $targetRoot "$($script:WindowsRustTarget)\release"
    $client = Join-Path $binaryRoot "ferrum2-client.exe"
    $server = Join-Path $binaryRoot "ferrum2-server.exe"
    foreach ($path in @($client, $server)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "host performance build output is missing: $path"
        }
    }
    $harness = if ($IncludeHarness) {
        $path = Join-Path $binaryRoot "m4-qualification.exe"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "host performance shared harness is missing: $path"
        }
        $path
    } else { $null }
    $dllTarget = Join-Path $binaryRoot "wintun.dll"
    Copy-Item -LiteralPath $WintunDll -Destination $dllTarget -ErrorAction Stop
    return [pscustomobject][ordered]@{
        label = $Label
        commit_sha = $Sha
        root = $memberRoot
        client = $client
        server = $server
        harness = $harness
        client_sha256 = (Get-FileHash $client -Algorithm SHA256).Hash.ToLowerInvariant()
        server_sha256 = (Get-FileHash $server -Algorithm SHA256).Hash.ToLowerInvariant()
        harness_sha256 = if ($IncludeHarness) {
            (Get-FileHash $harness -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
        source_bundle_sha256 = $sourceBundleSha256
        wintun_dll_sha256 = (Get-FileHash $dllTarget -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Initialize-Ferrum2HostBuilds {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$BaselineSha,
        [Parameter(Mandatory = $true)][string]$CandidateSha
    )
    [void](Resolve-Ferrum2CommitSha -RepositoryRoot $Context.repository_root -Sha $BaselineSha)
    [void](Resolve-Ferrum2CommitSha -RepositoryRoot $Context.repository_root -Sha $CandidateSha)
    $assetRoot = Join-Path $Context.run_root "assets"
    New-Item -ItemType Directory -Path $assetRoot -ErrorAction Stop | Out-Null
    $archive = Resolve-Ferrum2WintunArchive
    $dll = Join-Path $assetRoot "wintun.dll"
    $dllHash = Expand-Ferrum2WintunDll -Archive $archive -Destination $dll
    $baseline = Build-Ferrum2HostMember -Context $Context -Label "baseline" -Sha $BaselineSha `
        -WintunDll $dll -IncludeHarness
    $candidate = Build-Ferrum2HostMember -Context $Context -Label "candidate" -Sha $CandidateSha `
        -WintunDll $dll
    if ([string]$baseline.source_bundle_sha256 -cne
        [string]$candidate.source_bundle_sha256) {
        throw "baseline and candidate M4 workload source bundles differ"
    }
    $candidate.harness = $baseline.harness
    $candidate.harness_sha256 = $baseline.harness_sha256
    if ([string]$baseline.harness_sha256 -cne [string]$candidate.harness_sha256) {
        throw "baseline and candidate M4 harness binaries differ"
    }
    $manifest = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-build-manifest"
        run_id = $Context.run_id
        performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
        baseline = $baseline
        candidate = $candidate
        shared_harness_sha256 = $baseline.harness_sha256
        shared_harness_commit_sha = $BaselineSha
        shared_source_bundle_sha256 = $baseline.source_bundle_sha256
        wintun_archive_sha256 = $script:ExpectedWintunZipSha256
        wintun_dll_sha256 = $dllHash
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "builds.json") -Document $manifest
    return [pscustomobject]@{ baseline = $baseline; candidate = $candidate; harness = $baseline.harness }
}

function Test-Ferrum2TcpPortAvailable {
    param([string]$Address, [uint16]$Port)
    $listener = $null
    try {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($Address), $Port)
        $listener.Start()
        return $true
    } catch { return $false } finally { if ($null -ne $listener) { $listener.Stop() } }
}

function Test-Ferrum2UdpPortAvailable {
    param([string]$Address, [uint16]$Port)
    $socket = $null
    try {
        $socket = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Address), $Port))
        return $true
    } catch { return $false } finally { if ($null -ne $socket) { $socket.Dispose() } }
}

function Get-Ferrum2FreeTcpPort {
    param([string]$Address = "127.0.0.1")
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($Address), 0)
    try {
        $listener.Start()
        return [uint16]([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally { $listener.Stop() }
}

function Get-Ferrum2FreeDualPort {
    param([Parameter(Mandatory = $true)][string]$Address)
    foreach ($attempt in 1..256) {
        $port = [uint16](Get-Random -Minimum 20000 -Maximum 60000)
        if ((Test-Ferrum2TcpPortAvailable -Address $Address -Port $port) -and
            (Test-Ferrum2UdpPortAvailable -Address $Address -Port $port)) { return $port }
    }
    throw "unable to allocate an available TCP/UDP port"
}

function Get-Ferrum2FreeSupportPorts {
    param([Parameter(Mandatory = $true)][string]$Address)
    foreach ($attempt in 1..256) {
        $base = [uint16](Get-Random -Minimum 20000 -Maximum 59996)
        if (-not (Test-Ferrum2TcpPortAvailable -Address $Address -Port $base)) { continue }
        $available = $true
        foreach ($offset in 0..3) {
            if (-not (Test-Ferrum2UdpPortAvailable -Address $Address -Port ([uint16]($base + $offset)))) {
                $available = $false
                break
            }
        }
        if ($available) { return $base }
    }
    throw "unable to allocate contiguous host support ports"
}

function Start-Ferrum2OwnedNativeProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Application,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogPrefix,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $logRoot = Join-Path $Context.run_root "process-logs"
    New-Item -ItemType Directory -Path $logRoot -Force -ErrorAction Stop | Out-Null
    $stdout = Join-Path $logRoot "$LogPrefix.stdout.log"
    $stderr = Join-Path $logRoot "$LogPrefix.stderr.log"
    $pid = [Ferrum2PerfProcessGroup]::Start($Application, $Arguments, $WorkingDirectory, $stdout, $stderr)
    try {
        [void](Add-Ferrum2OwnedProcess -Context $Context -ProcessId $pid `
            -Executable $Application -Purpose $Purpose)
    } catch {
        [void][Ferrum2PerfProcessGroup]::Terminate([uint32]$pid)
        [Ferrum2PerfProcessGroup]::Close([uint32]$pid)
        throw
    }
    return [pscustomobject]@{ pid = $pid; stdout = $stdout; stderr = $stderr }
}

function Wait-Ferrum2Text {
    param([string]$Path, [string]$Pattern, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if ($text -cmatch $Pattern) { return }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "process readiness output timed out"
}

function Get-Ferrum2Metrics {
    param([uint16]$Port)
    $text = [string](Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/metrics" `
        -TimeoutSec 2 -ErrorAction Stop).Content
    if ([Text.Encoding]::UTF8.GetByteCount($text) -le 0 -or
        [Text.Encoding]::UTF8.GetByteCount($text) -gt 1MB) {
        throw "metrics snapshot is empty or exceeds 1 MiB"
    }
    return $text
}

function Wait-Ferrum2Metric {
    param([uint16]$Port, [string]$Name, [double]$Minimum, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $metrics = Get-Ferrum2Metrics -Port $Port
            $value = Get-Ferrum2MetricValue -Metrics $metrics -Name $Name
            if ($value -ge $Minimum) { return $metrics }
        } catch { }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "metric readiness timed out: $Name"
}

function Get-Ferrum2MetricValue {
    param([string]$Metrics, [string]$Name, [switch]$AllowAbsent)
    $escaped = [regex]::Escape($Name)
    $matches = [regex]::Matches($Metrics, "(?m)^$escaped(?:\{[^\r\n]*\})?\s+([0-9]+(?:\.[0-9]+)?)$")
    if ($matches.Count -eq 0) {
        if ($AllowAbsent) { return [double]0 }
        throw "required metric is absent: $Name"
    }
    [double]$sum = 0
    foreach ($match in $matches) { $sum += [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) }
    return $sum
}


function Get-Ferrum2FailureCounterTotal {
    param([string]$Metrics)
    [double]$sum = 0
    foreach ($line in ($Metrics -split "`n")) {
        if ($line.StartsWith("#")) { continue }
        # Windows emits adapter-local IPv6 and address-probing packets outside the benchmark route.
        if ($line -match '^ferrum2_tun_packets_rejected_total\{reason="(?:family_disabled|invalid_destination)"\}\s+') {
            continue
        }
        if ($line -match '^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+([0-9]+(?:\.[0-9]+)?)\s*$') {
            $value = [double]::Parse($Matches[2], [Globalization.CultureInfo]::InvariantCulture)
            $name = $Matches[1]
            if ($name -cmatch '(drop|error|reject|failure|failed)') {
                $sum += $value
            }
        }
    }
    return $sum
}

function Write-Ferrum2TrialConfigs {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][string]$AdapterName,
        [Parameter(Mandatory = $true)][uint16]$ServerPort,
        [Parameter(Mandatory = $true)][uint16]$ClientMetricsPort,
        [Parameter(Mandatory = $true)][uint16]$ServerMetricsPort,
        [Parameter(Mandatory = $true)][int]$Sequence
    )
    foreach ($value in @($AdapterName, $Loopback.interface_alias)) {
        if ($value -match '["\r\n]') { throw "configuration identity contains an unsafe character" }
    }
    $root = Join-Path $Context.run_root "configs\$Sequence"
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $clientPath = Join-Path $root "client.toml"
    $serverPath = Join-Path $root "server.toml"
    $client = @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$AdapterName"
ipv4_address = "$($Network.tun_address)/$($Network.tun_prefix_length)"
mtu = 1420
auto_route = true
route_address = ["$($Network.support_address)/32"]
ring_capacity = 67108864
ready_timeout_ms = 30000
max_tcp_flows = 4096
tcp_buffer_bytes = 32768
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "127.0.0.1:$ServerPort"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
bind_interface = "$($Loopback.interface_alias)"
inet4_bind_address = "127.0.0.1"
[route]
auto_detect_interface = false
default_interface = "$($Loopback.interface_alias)"
final = "proxy"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
idle_timeout_ms = 1000
[metrics]
listen = "127.0.0.1:$ClientMetricsPort"
"@
    $server = @"
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:$ServerPort"
[[outbounds]]
tag = "direct"
bind_interface = "$($Loopback.interface_alias)"
inet4_bind_address = "$($Network.support_address)"
[route]
auto_detect_interface = false
default_interface = "$($Loopback.interface_alias)"
final = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
[metrics]
listen = "127.0.0.1:$ServerMetricsPort"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"@
    Write-NewUtf8File -Path $clientPath -Text ($client.TrimStart() + "`n")
    Write-NewUtf8File -Path $serverPath -Text ($server.TrimStart() + "`n")
    return [pscustomobject]@{ root = $root; client = $clientPath; server = $serverPath }
}

function Invoke-Ferrum2ConfigCheck {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$Config,
        [Parameter(Mandatory = $true)][string]$LogPrefix
    )
    [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Binary `
        -Arguments "--config `"$Config`" --check-config" `
        -WorkingDirectory (Split-Path -Parent $Binary) -LogPrefix $LogPrefix `
        -TimeoutSeconds 60)
}

function Get-Ferrum2RouteProof {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][uint32]$ExpectedInterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [AllowNull()][string]$LocalAddress = $null
    )
    $lookup = @{
        RemoteIPAddress = $RemoteAddress
        ErrorAction = "Stop"
    }
    if ($PSBoundParameters.ContainsKey("LocalAddress")) {
        $lookup.LocalIPAddress = $LocalAddress
        $lookup.InterfaceIndex = $ExpectedInterfaceIndex
    }
    $rows = @(Find-NetRoute @lookup)
    $source = @($rows | Where-Object { $_.CimClass.CimClassName -ceq "MSFT_NetIPAddress" })
    $route = @($rows | Where-Object { $_.CimClass.CimClassName -ceq "MSFT_NetRoute" })
    if ($source.Count -ne 1 -or $route.Count -ne 1 -or
        [uint32]$source[0].InterfaceIndex -ne $ExpectedInterfaceIndex -or
        [uint32]$route[0].InterfaceIndex -ne $ExpectedInterfaceIndex) {
        throw "actual route lookup did not select the $Purpose interface"
    }
    return [pscustomobject][ordered]@{
        purpose = $Purpose
        remote_address = $RemoteAddress
        local_address = [string]$source[0].IPAddress
        interface_index = [uint32]$route[0].InterfaceIndex
        interface_alias = [string]$route[0].InterfaceAlias
        destination_prefix = [string]$route[0].DestinationPrefix
        next_hop = [string]$route[0].NextHop
    }
}

function Get-Ferrum2TrialRouteProofs {
    param(
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][uint32]$TunInterfaceIndex
    )
    return @(
        Get-Ferrum2RouteProof -RemoteAddress $Network.support_address `
            -ExpectedInterfaceIndex $TunInterfaceIndex `
            -Purpose "benchmark-application-to-test-tun"
        Get-Ferrum2RouteProof -RemoteAddress $Network.support_address `
            -LocalAddress $Network.support_address `
            -ExpectedInterfaceIndex $Loopback.interface_index `
            -Purpose "server-to-support-without-test-tun"
        Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" -LocalAddress "127.0.0.1" `
            -ExpectedInterfaceIndex $Loopback.interface_index -Purpose "product-underlay-control"
        Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" -LocalAddress "127.0.0.1" `
            -ExpectedInterfaceIndex $Loopback.interface_index -Purpose "sing-box-proxy-excluded"
    )
}

function Start-Ferrum2Support {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Harness,
        [Parameter(Mandatory = $true)][object]$Network
    )
    $tcpPort = Get-Ferrum2FreeSupportPorts -Address $Network.support_address
    $udpPort = $tcpPort
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address $Network.support_address `
        -Port $tcpPort -Purpose "support-tcp"
    foreach ($offset in 0..3) {
        Add-Ferrum2OwnedPort -Context $Context -Protocol "udp" -Address $Network.support_address `
            -Port ([uint16]($udpPort + $offset)) -Purpose "support-udp-$offset"
    }
    $arguments = "windows-tun-support --listen-ip $($Network.support_address) --tcp-port $tcpPort --udp-port $udpPort"
    $process = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Harness `
        -Arguments $arguments -WorkingDirectory (Split-Path -Parent $Harness) `
        -LogPrefix "support" -Purpose "support"
    Wait-Ferrum2Text -Path $process.stdout -Pattern '^windows_tun_support status=READY ' -TimeoutSeconds 30
    return [pscustomobject]@{ process = $process; tcp_port = $tcpPort; udp_port = $udpPort }
}

function Start-Ferrum2ProductTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][int]$Sequence
    )
    $adapterName = "$($Network.adapter_name_prefix)-$('{0:D3}' -f $Sequence)"
    Set-Ferrum2OwnedAdapterPlan -Context $Context -AdapterName $adapterName
    $serverPort = Get-Ferrum2FreeDualPort -Address "127.0.0.1"
    $clientMetrics = Get-Ferrum2FreeTcpPort
    $serverMetrics = Get-Ferrum2FreeTcpPort
    if (@(@($serverPort, $clientMetrics, $serverMetrics) |
            Sort-Object -Unique).Count -ne 3) {
        throw "product ports are not distinct"
    }
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" -Port $serverPort -Purpose "server-tcp"
    Add-Ferrum2OwnedPort -Context $Context -Protocol "udp" -Address "127.0.0.1" -Port $serverPort -Purpose "server-udp"
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
        -Port $clientMetrics -Purpose "client-metrics"
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address "127.0.0.1" `
        -Port $serverMetrics -Purpose "server-metrics"
    $configs = Write-Ferrum2TrialConfigs -Context $Context -Network $Network -Loopback $Loopback `
        -AdapterName $adapterName -ServerPort $serverPort -ClientMetricsPort $clientMetrics `
        -ServerMetricsPort $serverMetrics -Sequence $Sequence
    Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.client `
        -Config $configs.client -LogPrefix "trial-$Sequence-client-config-check"
    Invoke-Ferrum2ConfigCheck -Context $Context -Binary $Member.server `
        -Config $configs.server -LogPrefix "trial-$Sequence-server-config-check"
    $server = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.server `
        -Arguments "--config `"$($configs.server)`"" -WorkingDirectory (Split-Path -Parent $Member.server) `
        -LogPrefix "trial-$Sequence-server" -Purpose "trial-$Sequence-server"
    [void](Wait-Ferrum2Metric -Port $serverMetrics -Name "ferrum2_network_generation" -Minimum 1)
    $client = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Member.client `
        -Arguments "--config `"$($configs.client)`"" -WorkingDirectory (Split-Path -Parent $Member.client) `
        -LogPrefix "trial-$Sequence-client" -Purpose "trial-$Sequence-client"
    [void](Wait-Ferrum2Metric -Port $clientMetrics -Name "ferrum2_tun_session_active" -Minimum 1)
    $adapter = Complete-Ferrum2OwnedAdapterIdentity -Context $Context -AdapterName $adapterName
    $route = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$($Network.support_address)/32" `
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
    $proofs = Get-Ferrum2TrialRouteProofs -Network $Network -Loopback $Loopback `
        -TunInterfaceIndex ([uint32]$adapter.ifIndex)
    return [pscustomobject]@{
        adapter = $adapter
        adapter_name = $adapterName
        server = $server
        client = $client
        server_port = $serverPort
        client_metrics_port = $clientMetrics
        server_metrics_port = $serverMetrics
        route_proofs = $proofs
    }
}

function Stop-Ferrum2ProductTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Runtime
    )
    Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $Runtime.client.pid
    Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $Runtime.server.pid
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

function Get-Ferrum2ProcessCpuMilliseconds {
    param([int]$ProcessId)
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    $process.Refresh()
    return $process.TotalProcessorTime.TotalMilliseconds
}

function Export-Ferrum2OwnedCommandFailureLogs {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][string]$LogPrefix
    )
    $failureRoot = Join-Path $Context.evidence_directory "process-logs"
    New-Item -ItemType Directory -Path $failureRoot -Force -ErrorAction Stop | Out-Null
    foreach ($stream in @("stdout", "stderr")) {
        $source = [string]$Process.$stream
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source `
                -Destination (Join-Path $failureRoot "$LogPrefix.$stream.log") `
                -Force -ErrorAction Stop
        }
    }
    return $failureRoot
}

function Complete-Ferrum2OwnedCommand {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][string]$LogPrefix,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    if (-not [Ferrum2PerfProcessGroup]::Wait(
            [uint32]$Process.pid, [uint32]($TimeoutSeconds * 1000))) {
        [void][Ferrum2PerfProcessGroup]::Terminate([uint32]$Process.pid)
        $failureLogs = Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
            -Process $Process -LogPrefix $LogPrefix
        throw "owned command timed out: $LogPrefix; logs: $failureLogs"
    }
    $exit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$Process.pid)
    [Ferrum2PerfProcessGroup]::Close([uint32]$Process.pid)
    Remove-Ferrum2OwnedProcessRecord -Context $Context -ProcessId $Process.pid
    if ($exit -ne 0) {
        $failureLogs = Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
            -Process $Process -LogPrefix $LogPrefix
        throw "owned command failed: $LogPrefix; logs: $failureLogs"
    }
    return $Process
}

function Invoke-Ferrum2OwnedCommand {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Application,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogPrefix,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $process = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Application `
        -Arguments $Arguments -WorkingDirectory $WorkingDirectory -LogPrefix $LogPrefix `
        -Purpose $LogPrefix
    return Complete-Ferrum2OwnedCommand -Context $Context -Process $process `
        -LogPrefix $LogPrefix -TimeoutSeconds $TimeoutSeconds
}

function Invoke-Ferrum2HostTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Trial,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][string]$Harness,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][object]$Support
    )
    $trialRoot = Join-Path $Context.evidence_directory ("trials\{0:D3}" -f $Trial.sequence)
    New-Item -ItemType Directory -Path $trialRoot -ErrorAction Stop | Out-Null
    $runtime = $null
    $succeeded = $false
    try {
        $runtime = Start-Ferrum2ProductTrial -Context $Context -Member $Member -Network $Network `
            -Loopback $Loopback -Sequence $Trial.sequence
        $metricsBefore = Get-Ferrum2Metrics -Port $runtime.client_metrics_port
        $serverMetricsBefore = Get-Ferrum2Metrics -Port $runtime.server_metrics_port
        $output = Join-Path $trialRoot "workload.json"
        $activeReadyMarker = [IO.Path]::ChangeExtension($output, "active-ready")
        $activeCompleteMarker = [IO.Path]::ChangeExtension($output, "active-complete")
        $arguments = "windows-tun-workload --scenario $($Trial.scenario) --target-ip $($Network.support_address) " +
            "--tcp-port $($Support.tcp_port) --udp-port $($Support.udp_port) " +
            "--warmup-seconds $($Trial.warmup_seconds) --active-seconds $($Trial.active_seconds) " +
            "--output `"$output`""
        $workloadLogPrefix = "trial-$($Trial.sequence)-workload"
        $workloadProcess = Start-Ferrum2OwnedNativeProcess -Context $Context `
            -Application $Harness -Arguments $arguments `
            -WorkingDirectory (Split-Path -Parent $Harness) -LogPrefix $workloadLogPrefix `
            -Purpose $workloadLogPrefix
        Wait-Ferrum2Text -Path $activeReadyMarker -Pattern '^ready\r?\n?$' `
            -TimeoutSeconds ([int]$Trial.warmup_seconds + 30)
        $clientCpuBefore = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
        $serverCpuBefore = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
        $cpuSampleStopwatch = [Diagnostics.Stopwatch]::StartNew()
        Remove-Item -LiteralPath $activeReadyMarker -Force -ErrorAction Stop
        Wait-Ferrum2Text -Path $activeCompleteMarker -Pattern '^complete\r?\n?$' `
            -TimeoutSeconds ([int]$Trial.active_seconds + 60)
        $clientCpuAfter = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
        $serverCpuAfter = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
        $cpuSampleStopwatch.Stop()
        Remove-Item -LiteralPath $activeCompleteMarker -Force -ErrorAction Stop
        [void](Complete-Ferrum2OwnedCommand -Context $Context -Process $workloadProcess `
            -LogPrefix $workloadLogPrefix -TimeoutSeconds 60)
        $metricsAfter = Get-Ferrum2Metrics -Port $runtime.client_metrics_port
        $serverMetricsAfter = Get-Ferrum2Metrics -Port $runtime.server_metrics_port
        Write-NewUtf8File -Path (Join-Path $trialRoot "client-metrics-before.txt") -Text $metricsBefore
        Write-NewUtf8File -Path (Join-Path $trialRoot "client-metrics-after.txt") -Text $metricsAfter
        Write-NewUtf8File -Path (Join-Path $trialRoot "server-metrics-before.txt") -Text $serverMetricsBefore
        Write-NewUtf8File -Path (Join-Path $trialRoot "server-metrics-after.txt") -Text $serverMetricsAfter
        $workloadItem = Get-Item -LiteralPath $output -Force -ErrorAction Stop
        if ($workloadItem.Length -le 0 -or $workloadItem.Length -gt 1MB) {
            throw "workload observation size is invalid"
        }
        $workload = Get-Content -LiteralPath $output -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 20
        if ($workload.status -cne "PASS" -or [string]$workload.scenario -cne [string]$Trial.scenario) {
            throw "workload observation identity is invalid"
        }
        $metricValue = [double]$workload.observation.measurements.([string]$Trial.metric)
        if (-not [double]::IsFinite($metricValue) -or $metricValue -le 0) {
            throw "workload primary metric is invalid"
        }
        $workloadChecks = @($workload.observation.checks.PSObject.Properties)
        if ($workloadChecks.Count -eq 0 -or
            @($workloadChecks | Where-Object { $_.Value -ne $true }).Count -ne 0) {
            throw "workload correctness checks did not all pass"
        }
        [double]$checkedUnits = $workload.observation.checked_units
        if (-not [double]::IsFinite($checkedUnits) -or $checkedUnits -le 0) {
            throw "workload checked-unit count is invalid"
        }
        [double]$cpuSampleSeconds = $cpuSampleStopwatch.Elapsed.TotalSeconds
        if (-not [double]::IsFinite($cpuSampleSeconds) -or $cpuSampleSeconds -le 0) {
            throw "trial CPU sample window is invalid"
        }
        [double]$clientCpuPercent =
            (($clientCpuAfter - $clientCpuBefore) / ($cpuSampleSeconds * 1000.0)) * 100.0
        [double]$serverCpuPercent =
            (($serverCpuAfter - $serverCpuBefore) / ($cpuSampleSeconds * 1000.0)) * 100.0
        [double]$clientFailureDelta =
            (Get-Ferrum2FailureCounterTotal $metricsAfter) -
                (Get-Ferrum2FailureCounterTotal $metricsBefore)
        [double]$serverFailureDelta =
            (Get-Ferrum2FailureCounterTotal $serverMetricsAfter) -
                (Get-Ferrum2FailureCounterTotal $serverMetricsBefore)
        if (-not [double]::IsFinite($clientCpuPercent) -or $clientCpuPercent -lt 0 -or
            -not [double]::IsFinite($serverCpuPercent) -or $serverCpuPercent -lt 0 -or
            $clientFailureDelta -ne 0 -or $serverFailureDelta -ne 0) {
            throw "trial CPU or failure-counter evidence is invalid"
        }
        $elapsedSeconds = [double]$Trial.active_seconds
        $observation = [pscustomobject][ordered]@{
            schema_version = 1
            kind = "ferrum2.windows-tun.host-performance-trial"
            run_id = $Context.run_id
            performance_source_bundle_sha256 = $Context.performance_source_bundle_sha256
            sequence = $Trial.sequence
            pair = $Trial.pair
            order = $Trial.order
            scenario = $Trial.scenario
            member = $Trial.member
            commit_sha = $Trial.commit_sha
            metric = $Trial.metric
            unit = $Trial.unit
            value = $metricValue
            warmup_seconds = $Trial.warmup_seconds
            active_seconds = $Trial.active_seconds
            cpu_sample_seconds = $cpuSampleSeconds
            client_cpu_percent = $clientCpuPercent
            server_cpu_percent = $serverCpuPercent
            client_failure_counter_delta = $clientFailureDelta
            server_failure_counter_delta = $serverFailureDelta
            checked_units = $checkedUnits
            loopback_interface_index = [uint32]$Loopback.interface_index
            loopback_interface_alias = [string]$Loopback.interface_alias
            route_proofs = $runtime.route_proofs
            workload_checks = $workload.observation.checks
            status = "PASS"
        }
        Write-AtomicJsonFile -Path (Join-Path $trialRoot "trial.json") -Document $observation
        $succeeded = $true
        return $observation
    } catch {
        $failure = $_
        if ($null -ne $runtime) {
            foreach ($endpoint in @(
                [pscustomobject]@{ name = "client"; port = $runtime.client_metrics_port },
                [pscustomobject]@{ name = "server"; port = $runtime.server_metrics_port }
            )) {
                try {
                    $metrics = Get-Ferrum2Metrics -Port $endpoint.port
                    Write-NewUtf8File -Path (Join-Path $trialRoot "$($endpoint.name)-metrics-failure.txt") `
                        -Text $metrics
                } catch {
                    Write-NewUtf8File -Path (Join-Path $trialRoot "$($endpoint.name)-metrics-capture-error.txt") `
                        -Text ($_.Exception.Message + "`n")
                }
            }
        }
        throw $failure
    } finally {
        if ($null -ne $runtime) { Stop-Ferrum2ProductTrial -Context $Context -Runtime $runtime }
        if (-not $succeeded) { Set-Ferrum2HostPerformanceState -Context $Context -State "trial_failed" }
    }
}
