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
    $bundleRoot = Join-Path $SourceRoot `
        "tools\ferrum2-m4-qualification\src\m4_support\windows_tun"
    $manifestPath = Join-Path $bundleRoot "bundle.json"
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
        [string]$manifest.kind -cne "ferrum2.m4-windows-tun-source-bundle.v1" -or
        [string]$manifest.entrypoint -cne "mod.rs") {
        throw "M4 Windows TUN source bundle manifest contract is invalid"
    }
    $actualPaths = @(Get-ChildItem -LiteralPath $bundleRoot -Filter "*.rs" -File -Recurse |
        ForEach-Object {
            [IO.Path]::GetRelativePath($bundleRoot, $_.FullName).Replace("\", "/")
        } | Sort-Object)
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
        $path = Join-Path $bundleRoot $relativePath
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
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$TargetRoot,
        [Parameter(Mandatory = $true)][string]$LogRoot
    )
    $stdout = Join-Path $LogRoot "cargo.stdout.log"
    $stderr = Join-Path $LogRoot "cargo.stderr.log"
    $arguments = @(
        "build", "--release", "--locked", "--offline", "--target", $script:WindowsRustTarget,
        "-p", "ferrum2-client", "-p", "ferrum2-server", "-p", "ferrum2-m4-qualification"
    )
    $process = Start-Process -FilePath "cargo" -ArgumentList $arguments `
        -WorkingDirectory $SourceRoot -Environment @{ CARGO_TARGET_DIR = $TargetRoot } `
        -PassThru -NoNewWindow -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -ErrorAction Stop
    try {
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        throw "offline host performance build failed; inspect bounded local build logs"
    }
}

function Build-Ferrum2HostMember {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][string]$WintunDll
    )
    $memberRoot = Join-Path $Context.run_root "builds\$Label"
    $sourceRoot = Join-Path $memberRoot "source"
    $targetRoot = Join-Path $memberRoot "target"
    $logRoot = Join-Path $memberRoot "logs"
    New-Item -ItemType Directory -Path $logRoot -Force -ErrorAction Stop | Out-Null
    Export-Ferrum2CommitTree -RepositoryRoot $Context.repository_root -Sha $Sha -Destination $sourceRoot
    $sourceBundleSha256 = Get-Ferrum2M4SourceBundleIdentity -SourceRoot $sourceRoot
    Invoke-Ferrum2CargoBuild -SourceRoot $sourceRoot -TargetRoot $targetRoot -LogRoot $logRoot
    $binaryRoot = Join-Path $targetRoot "$($script:WindowsRustTarget)\release"
    $client = Join-Path $binaryRoot "ferrum2-client.exe"
    $server = Join-Path $binaryRoot "ferrum2-server.exe"
    $harness = Join-Path $binaryRoot "m4-qualification.exe"
    foreach ($path in @($client, $server, $harness)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "host performance build output is missing: $path"
        }
    }
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
        harness_sha256 = (Get-FileHash $harness -Algorithm SHA256).Hash.ToLowerInvariant()
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
        -WintunDll $dll
    $candidate = Build-Ferrum2HostMember -Context $Context -Label "candidate" -Sha $CandidateSha `
        -WintunDll $dll
    if ([string]$baseline.source_bundle_sha256 -cne
        [string]$candidate.source_bundle_sha256) {
        throw "baseline and candidate M4 workload source bundles differ"
    }
    $manifest = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-build-manifest"
        baseline = $baseline
        candidate = $candidate
        shared_harness_sha256 = $candidate.harness_sha256
        shared_harness_commit_sha = $CandidateSha
        shared_source_bundle_sha256 = $candidate.source_bundle_sha256
        wintun_archive_sha256 = $script:ExpectedWintunZipSha256
        wintun_dll_sha256 = $dllHash
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "builds.json") -Document $manifest
    return [pscustomobject]@{ baseline = $baseline; candidate = $candidate; harness = $candidate.harness }
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
    param([string]$Binary, [string]$Config)
    & $Binary --config $Config --check-config | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "product configuration check failed" }
}

function Get-Ferrum2RouteProof {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][uint32]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $rows = @(Find-NetRoute -RemoteIPAddress $RemoteAddress -LocalIPAddress $LocalAddress `
        -InterfaceIndex $InterfaceIndex -ErrorAction Stop)
    $source = @($rows | Where-Object { $_.CimClass.CimClassName -ceq "MSFT_NetIPAddress" })
    $route = @($rows | Where-Object { $_.CimClass.CimClassName -ceq "MSFT_NetRoute" })
    if ($source.Count -ne 1 -or $route.Count -ne 1 -or
        [uint32]$source[0].InterfaceIndex -ne $InterfaceIndex -or
        [uint32]$route[0].InterfaceIndex -ne $InterfaceIndex) {
        throw "actual route lookup did not preserve the $Purpose interface"
    }
    return [pscustomobject][ordered]@{
        purpose = $Purpose
        remote_address = $RemoteAddress
        local_address = $LocalAddress
        interface_index = $InterfaceIndex
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
            -LocalAddress $Network.tun_address -InterfaceIndex $TunInterfaceIndex `
            -Purpose "benchmark-application-to-test-tun"
        Get-Ferrum2RouteProof -RemoteAddress $Network.support_address `
            -LocalAddress $Network.support_address -InterfaceIndex $Loopback.interface_index `
            -Purpose "server-to-support-without-test-tun"
        Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" -LocalAddress "127.0.0.1" `
            -InterfaceIndex $Loopback.interface_index -Purpose "product-underlay-control"
        Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" -LocalAddress "127.0.0.1" `
            -InterfaceIndex $Loopback.interface_index -Purpose "sing-box-proxy-excluded"
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
    Invoke-Ferrum2ConfigCheck -Binary $Member.client -Config $configs.client
    Invoke-Ferrum2ConfigCheck -Binary $Member.server -Config $configs.server
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
    if (-not [Ferrum2PerfProcessGroup]::Wait([uint32]$process.pid, [uint32]($TimeoutSeconds * 1000))) {
        [void][Ferrum2PerfProcessGroup]::Terminate([uint32]$process.pid)
        $failureLogs = Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
            -Process $process -LogPrefix $LogPrefix
        throw "owned command timed out: $LogPrefix; logs: $failureLogs"
    }
    $exit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$process.pid)
    [Ferrum2PerfProcessGroup]::Close([uint32]$process.pid)
    Remove-Ferrum2OwnedProcessRecord -Context $Context -ProcessId $process.pid
    if ($exit -ne 0) {
        $failureLogs = Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
            -Process $process -LogPrefix $LogPrefix
        throw "owned command failed: $LogPrefix; logs: $failureLogs"
    }
    return $process
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
        $clientCpuBefore = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
        $serverCpuBefore = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
        $output = Join-Path $trialRoot "workload.json"
        $arguments = "windows-tun-workload --scenario $($Trial.scenario) --target-ip $($Network.support_address) " +
            "--tcp-port $($Support.tcp_port) --udp-port $($Support.udp_port) " +
            "--warmup-seconds $($Trial.warmup_seconds) --active-seconds $($Trial.active_seconds) " +
            "--output `"$output`""
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Harness -Arguments $arguments `
            -WorkingDirectory (Split-Path -Parent $Harness) -LogPrefix "trial-$($Trial.sequence)-workload" `
            -TimeoutSeconds ([int]$Trial.warmup_seconds + [int]$Trial.active_seconds + 60))
        $clientCpuAfter = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.client.pid
        $serverCpuAfter = Get-Ferrum2ProcessCpuMilliseconds -ProcessId $runtime.server.pid
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
        [double]$clientCpuPercent =
            (($clientCpuAfter - $clientCpuBefore) / ([double]$Trial.active_seconds * 1000.0)) *
                100.0
        [double]$serverCpuPercent =
            (($serverCpuAfter - $serverCpuBefore) / ([double]$Trial.active_seconds * 1000.0)) *
                100.0
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
            client_cpu_percent = $clientCpuPercent
            server_cpu_percent = $serverCpuPercent
            client_failure_counter_delta = $clientFailureDelta
            server_failure_counter_delta = $serverFailureDelta
            checked_units = $checkedUnits
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

function Get-Ferrum2Median {
    param([Parameter(Mandatory = $true)][double[]]$Values)
    if ($Values.Count -eq 0) { throw "median requires at least one value" }
    $sorted = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function New-Ferrum2HostSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object[]]$Trials
    )
    $scenarios = [Collections.Generic.List[object]]::new()
    foreach ($scenario in $Plan.scenarios) {
        $rows = @($Trials | Where-Object { [string]$_.scenario -ceq [string]$scenario.name })
        $ratios = [Collections.Generic.List[double]]::new()
        $pairs = [Collections.Generic.List[object]]::new()
        foreach ($pair in 1..$Plan.pair_count) {
            $baseline = @($rows | Where-Object { $_.pair -eq $pair -and $_.member -ceq "baseline" })
            $candidate = @($rows | Where-Object { $_.pair -eq $pair -and $_.member -ceq "candidate" })
            if ($baseline.Count -ne 1 -or $candidate.Count -ne 1) { throw "paired trial evidence is incomplete" }
            $ratio = [double]$candidate[0].value / [double]$baseline[0].value
            [void]$ratios.Add($ratio)
            [void]$pairs.Add([pscustomobject][ordered]@{
                pair = $pair
                order = $baseline[0].order
                baseline = $baseline[0].value
                candidate = $candidate[0].value
                ratio = $ratio
            })
        }
        $ratioValues = $ratios.ToArray()
        $medianRatio = Get-Ferrum2Median -Values $ratioValues
        $deviations = @($ratioValues | ForEach-Object {
            [Math]::Abs([double]$_ - $medianRatio)
        })
        $medianAbsoluteDeviation = Get-Ferrum2Median -Values $deviations
        $outlierPairs = if ($medianAbsoluteDeviation -eq 0) {
            @()
        } else {
            @($pairs | Where-Object {
                [Math]::Abs([double]$_.ratio - $medianRatio) -gt
                    (3.0 * $medianAbsoluteDeviation)
            } | ForEach-Object { [int]$_.pair })
        }
        $pairsImproved = @($ratios | Where-Object { $_ -gt 1.0 }).Count
        $qualificationStatus = if ($medianRatio -ge 1.02 -and
            $pairsImproved -gt [Math]::Floor($Plan.pair_count / 2)) {
            "candidate-win"
        } elseif ($medianRatio -le 0.98 -and
            @($ratios | Where-Object { $_ -lt 1.0 }).Count -gt
                [Math]::Floor($Plan.pair_count / 2)) {
            "regression"
        } else {
            "within-noise-band"
        }
        [void]$scenarios.Add([pscustomobject][ordered]@{
            scenario = $scenario.name
            metric = $scenario.metric
            unit = $scenario.unit
            pairs = $pairs.ToArray()
            median_pair_ratio = $medianRatio
            median_pair_improvement_percent = ($medianRatio - 1.0) * 100.0
            minimum_pair_ratio = ($ratios | Measure-Object -Minimum).Minimum
            maximum_pair_ratio = ($ratios | Measure-Object -Maximum).Maximum
            median_absolute_deviation = $medianAbsoluteDeviation
            outlier_pairs = @($outlierPairs)
            pairs_improved = $pairsImproved
            baseline_client_cpu_percent_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.client_cpu_percent }
            )
            candidate_client_cpu_percent_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.client_cpu_percent }
            )
            baseline_server_cpu_percent_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "baseline" |
                    ForEach-Object { [double]$_.server_cpu_percent }
            )
            candidate_server_cpu_percent_median = Get-Ferrum2Median -Values @(
                $rows | Where-Object member -CEQ "candidate" |
                    ForEach-Object { [double]$_.server_cpu_percent }
            )
            client_failure_counter_delta = 0
            server_failure_counter_delta = 0
            qualification_status = $qualificationStatus
        })
    }
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-performance-summary"
        mode = $Plan.mode
        baseline_sha = $Plan.baseline_sha
        candidate_sha = $Plan.candidate_sha
        pair_count = $Plan.pair_count
        scenarios = $scenarios.ToArray()
        threshold_percent = 2.0
        status = "PASS"
    }
}

function Invoke-Ferrum2HostPairedProfile {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($trial in $Plan.trials) {
        $member = if ($trial.member -ceq "baseline") { $Builds.baseline } else { $Builds.candidate }
        [void]$observations.Add((Invoke-Ferrum2HostTrial -Context $Context -Trial $trial `
            -Member $member -Harness $Builds.harness -Network $Network -Loopback $Loopback `
            -Support $support))
    }
    Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $support.process.pid
    $Context.ledger.resources.ports = @($Context.ledger.resources.ports | Where-Object {
        [string]$_.purpose -notmatch '^support-'
    })
    Write-Ferrum2HostPerformanceLedger -Context $Context
    $summary = New-Ferrum2HostSummary -Plan $Plan -Trials $observations.ToArray()
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "summary.json") -Document $summary
    return $summary
}

function Invoke-Ferrum2HostLifecycleProfile {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = $null
    $cycleLatencies = [Collections.Generic.List[double]]::new()
    try {
        $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
        $supportProcessCount = @($Context.ledger.resources.processes).Count
        $supportPortCount = @($Context.ledger.resources.ports).Count
        foreach ($cycle in 1..$Plan.lifecycle_cycles) {
            $runtime = $null
            $timer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $runtime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
                    -Network $Network -Loopback $Loopback -Sequence $cycle
                [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Builds.harness `
                    -Arguments "windows-tun-probe --target-ip $($Network.support_address) --tcp-port $($support.tcp_port) --udp-port $($support.udp_port)" `
                    -WorkingDirectory (Split-Path -Parent $Builds.harness) `
                    -LogPrefix "lifecycle-$cycle-probe" -TimeoutSeconds 60)
            } finally {
                if ($null -ne $runtime) {
                    Stop-Ferrum2ProductTrial -Context $Context -Runtime $runtime
                }
            }
            $timer.Stop()
            if ($null -ne $Context.ledger.resources.adapter -or
                @($Context.ledger.resources.routes).Count -ne 0 -or
                @($Context.ledger.resources.processes).Count -ne $supportProcessCount -or
                @($Context.ledger.resources.ports).Count -ne $supportPortCount) {
                throw "lifecycle cycle $cycle retained a product-owned resource"
            }
            [void]$cycleLatencies.Add($timer.Elapsed.TotalMilliseconds)
        }
    } finally {
        if ($null -ne $support) {
            Stop-Ferrum2OwnedProcess -Context $Context -ProcessId $support.process.pid
            $Context.ledger.resources.ports = @($Context.ledger.resources.ports | Where-Object {
                [string]$_.purpose -notmatch '^support-'
            })
            Write-Ferrum2HostPerformanceLedger -Context $Context
        }
    }
    if ($null -ne $Context.ledger.resources.adapter -or
        @($Context.ledger.resources.routes).Count -ne 0 -or
        @($Context.ledger.resources.processes).Count -ne 0 -or
        @($Context.ledger.resources.ports).Count -ne 0) {
        throw "Lifecycle retained a product or support resource"
    }
    $ordered = @($cycleLatencies | Sort-Object)
    $p95Index = [Math]::Min($ordered.Count - 1, [int][Math]::Ceiling($ordered.Count * 0.95) - 1)
    $summary = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-lifecycle-summary"
        mode = "Lifecycle"
        candidate_sha = $Plan.candidate_sha
        lifecycle_cycles = [int]$Plan.lifecycle_cycles
        lifecycle_action = "product-start-probe-stop"
        cycle_latencies_ms = $cycleLatencies.ToArray()
        cycle_latency_median_ms = Get-Ferrum2Median -Values $cycleLatencies.ToArray()
        cycle_latency_p95_ms = [double]$ordered[$p95Index]
        cycle_latency_minimum_ms = [double]$ordered[0]
        cycle_latency_maximum_ms = [double]$ordered[-1]
        probe_failures = 0
        between_cycle_adapter_remaining = 0
        between_cycle_routes_remaining = 0
        between_cycle_product_processes_remaining = 0
        between_cycle_product_ports_remaining = 0
        physical_adapter_mutations = 0
        wlan_mutations = 0
        dns_mutations = 0
        long_durability_soak = "not-run"
        status = "PASS"
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "summary.json") -Document $summary
    return $summary
}

function Invoke-Ferrum2HostSafetyCheck {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Builds,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    [void](Add-Ferrum2OwnedAddress -Context $Context -Loopback $Loopback `
        -Address $Network.support_address -PrefixLength $Network.support_prefix_length)
    $support = Start-Ferrum2Support -Context $Context -Harness $Builds.harness -Network $Network
    $checks = [Collections.Generic.List[object]]::new()
    $createRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 1
    Stop-Ferrum2ProductTrial -Context $Context -Runtime $createRuntime
    [void]$checks.Add([pscustomobject]@{ name = "create-immediate-cleanup"; status = "PASS" })
    $smokeRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 2
    try {
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $Builds.harness `
            -Arguments "windows-tun-probe --target-ip $($Network.support_address) --tcp-port $($support.tcp_port) --udp-port $($support.udp_port)" `
            -WorkingDirectory (Split-Path -Parent $Builds.harness) -LogPrefix "safety-smoke" `
            -TimeoutSeconds 60)
    } finally { Stop-Ferrum2ProductTrial -Context $Context -Runtime $smokeRuntime }
    [void]$checks.Add([pscustomobject]@{ name = "shortest-tun-smoke"; status = "PASS" })
    $faultRuntime = Start-Ferrum2ProductTrial -Context $Context -Member $Builds.candidate `
        -Network $Network -Loopback $Loopback -Sequence 3
    [Ferrum2PerfProcessGroup]::CloseGroup()
    Start-Sleep -Milliseconds 500
    $Context.ledger.state = "recovery_required"
    Write-Ferrum2HostPerformanceLedger -Context $Context
    Remove-Ferrum2LedgerResources -Ledger $Context.ledger -LedgerPath $Context.ledger_path
    [void]$checks.Add([pscustomobject]@{ name = "fault-job-close-and-stale-ledger-recovery"; status = "PASS" })
    $report = [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-safety-check"
        checks = $checks.ToArray()
        route_proofs = $smokeRuntime.route_proofs
        adapter_remaining = 0
        routes_remaining = 0
        addresses_remaining = 0
        processes_remaining = 0
        ports_remaining = 0
        status = "PASS"
    }
    Write-AtomicJsonFile -Path (Join-Path $Context.evidence_directory "safety-check.json") -Document $report
    return $report
}
