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
        throw "host qualification commit identity is unavailable: $Sha"
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
        [string]$manifest.kind -cne "ferrum2.m4-windows-tun-source-bundle.v3" -or
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

function ConvertFrom-Ferrum2DynamicPortRange {
    param([string]$Text, [ValidateSet('tcp', 'udp')][string]$Protocol)
    $numbers = [regex]::Matches($Text, '(?m)^[^\r\n:：]+[:：]\s*([0-9]+)\s*\r?$')
    [int]$start = 0
    [int]$count = 0
    if ($numbers.Count -ne 2 -or
        -not [int]::TryParse($numbers[0].Groups[1].Value, [ref]$start) -or
        -not [int]::TryParse($numbers[1].Groups[1].Value, [ref]$count) -or
        $start -lt 1 -or $count -lt 1 -or [long]$start + $count -gt 65536) {
        throw 'dynamic port range readback is invalid'
    }
    return [pscustomobject]@{ protocol = $Protocol; start_port = $start; end_port = $start + $count - 1 }
}

function Get-Ferrum2DynamicPortRanges {
    param([object]$Context, [int]$Sequence)
    $netsh = Join-Path $env:SystemRoot 'System32/netsh.exe'
    $ranges = @(foreach ($protocol in @('tcp', 'udp')) {
        $process = Invoke-Ferrum2OwnedCommand -Context $Context -Application $netsh `
            -Arguments "int ipv4 show dynamicport $protocol" -WorkingDirectory $Context.run_root `
            -LogPrefix "ports-$Sequence-$protocol" -TimeoutSeconds 10
        # The command has joined and its private stdout is now immutable.
        $item = Get-Item -LiteralPath $process.stdout -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt 16KB) { throw 'dynamic port range output is invalid' }
        $text = Get-Content -LiteralPath $process.stdout -Raw -ErrorAction Stop
        ConvertFrom-Ferrum2DynamicPortRange -Text $text -Protocol $protocol
    })
    $root = Join-Path $Context.evidence_directory 'port-ranges'
    New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
    Write-AtomicJsonFile -Path (Join-Path $root "$Sequence.json") `
        -Document ([pscustomobject]@{ sequence = $Sequence; ipv4_dynamic_ranges = $ranges })
    return $ranges
}

function New-Ferrum2PortReservation {
    param(
        [Parameter(Mandatory = $true)][object[]]$DynamicRanges,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp')][string[]]$Protocols
    )
    foreach ($attempt in 1..256) {
        [uint16]$port = Get-Random -Minimum 1024 -Maximum 65536
        if (@($DynamicRanges | Where-Object {
            $_.protocol -in $Protocols -and $port -ge $_.start_port -and $port -le $_.end_port
        }).Count -ne 0) { continue }
        $sockets = [Collections.Generic.List[Net.Sockets.Socket]]::new()
        try {
            foreach ($protocol in $Protocols) {
                $socket = if ($protocol -ceq 'tcp') {
                    [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
                        [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
                } else {
                    [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
                        [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
                }
                $sockets.Add($socket)
                $socket.ExclusiveAddressUse = $true
                $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $port))
                # Unix .NET TCP Bind enables address reuse; listening makes the reservation exclusive.
                if ($protocol -ceq 'tcp') { $socket.Listen(1) }
            }
            return [pscustomobject]@{ port = $port; sockets = $sockets.ToArray() }
        } catch {
            foreach ($socket in $sockets) { $socket.Dispose() }
            if ($_.Exception.InnerException -isnot [Net.Sockets.SocketException] -and
                $_.Exception -isnot [Net.Sockets.SocketException]) { throw }
        }
    }
    throw 'unable to reserve product listener ports outside dynamic ranges'
}

function Close-Ferrum2PortReservation {
    param([AllowNull()][object]$Reservation)
    if ($null -eq $Reservation) { return }
    foreach ($socket in $Reservation.sockets) { $socket.Dispose() }
    $Reservation.sockets = @()
}

function New-Ferrum2ProductPorts {
    param([object]$Context, [int]$Sequence)
    $ranges = @(Get-Ferrum2DynamicPortRanges -Context $Context -Sequence $Sequence)
    $ports = [pscustomobject]@{ client_metrics = $null; server = $null; server_metrics = $null; dynamic_ranges = $ranges }
    try {
        $ports.client_metrics = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp
        $ports.server = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp,udp
        $ports.server_metrics = New-Ferrum2PortReservation -DynamicRanges $ranges -Protocols tcp
        return $ports
    } catch {
        foreach ($reservation in @($ports.client_metrics, $ports.server, $ports.server_metrics)) {
            Close-Ferrum2PortReservation -Reservation $reservation
        }
        throw
    }
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
    $ownedProcessId = [Ferrum2HostProcessGroup]::Start($Application, $Arguments, $WorkingDirectory, $stdout, $stderr)
    try {
        [void](Add-Ferrum2OwnedProcess -Context $Context -ProcessId $ownedProcessId `
            -Executable $Application -Purpose $Purpose)
    } catch {
        [void][Ferrum2HostProcessGroup]::Terminate([uint32]$ownedProcessId)
        [Ferrum2HostProcessGroup]::Close([uint32]$ownedProcessId)
        throw
    }
    return [pscustomobject]@{ pid = $ownedProcessId; stdout = $stdout; stderr = $stderr }
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
    param(
        [Parameter(Mandatory = $true)][object]$Process,
        [uint16]$Port, [string]$Name, [double]$Minimum, [int]$TimeoutSeconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ([Ferrum2HostProcessGroup]::Wait([uint32]$Process.pid, 0)) {
            $exit = [Ferrum2HostProcessGroup]::ExitCode([uint32]$Process.pid)
            throw "product exited before metric readiness: $Name; exit=$exit"
        }
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


function Write-Ferrum2HostConfigs {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][string]$AdapterName,
        [uint16]$ServerPort,
        [Parameter(Mandatory = $true)][uint16]$ClientMetricsPort,
        [uint16]$ServerMetricsPort,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [AllowNull()][Net.IPEndPoint]$ResetProbeEndpoint = $null
    )
    foreach ($value in @($AdapterName, $Loopback.interface_alias)) {
        if ($value -match '["\r\n]') { throw "configuration identity contains an unsafe character" }
    }
    $root = Join-Path $Context.run_root "configs\$Sequence"
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $clientPath = Join-Path $root "client.toml"
    $serverPath = Join-Path $root "server.toml"
    $clientOutbound = @"
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
"@
    if ($null -ne $ResetProbeEndpoint) {
        $clientOutbound = $clientOutbound.Replace('final = "proxy"', 'final = "qualification-route"')
        # Keep both first hops in the underlay snapshot; only the proxy carries traffic.
        $clientOutbound += @"

[[outbounds]]
tag = "qualification-reset-probe"
type = "shadowsocks"
server = "$ResetProbeEndpoint"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[selectors]]
tag = "qualification-route"
outbounds = ["proxy", "qualification-reset-probe"]
default = "proxy"
"@
    }
    $client = @"
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "$AdapterName"
ipv4_address = "$($Network.tun_address)/$($Network.tun_prefix_length)"
mtu = 1420
auto_route = true
strict_route = true
route_address = ["$($Network.support_address)/32"]
ring_capacity = 67108864
ready_timeout_ms = 30000
max_tcp_flows = 4096
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
$clientOutbound
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
idle_timeout_ms = 60000
[metrics]
listen = "127.0.0.1:$ClientMetricsPort"
"@
    Write-NewUtf8File -Path $clientPath -Text ($client.TrimStart() + "`n")
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
    Write-NewUtf8File -Path $serverPath -Text ($server.TrimStart() + "`n")
    return [pscustomobject]@{
        root = $root
        client = $clientPath
        server = $serverPath
    }
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

function Get-Ferrum2HostRouteProofs {
    param(
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback,
        [Parameter(Mandatory = $true)][uint32]$TunInterfaceIndex
    )
    $proofs = [Collections.Generic.List[object]]::new()
    [void]$proofs.Add((Get-Ferrum2RouteProof -RemoteAddress $Network.support_address `
        -ExpectedInterfaceIndex $TunInterfaceIndex `
        -Purpose "qualification-application-to-test-tun"))
    [void]$proofs.Add((Get-Ferrum2RouteProof -RemoteAddress $Network.support_address `
        -LocalAddress $Network.support_address `
        -ExpectedInterfaceIndex $Loopback.interface_index -Purpose "server-to-support-without-test-tun"))
    [void]$proofs.Add((Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" `
        -LocalAddress "127.0.0.1" -ExpectedInterfaceIndex $Loopback.interface_index `
        -Purpose "product-underlay-control"))
    [void]$proofs.Add((Get-Ferrum2RouteProof -RemoteAddress "127.0.0.1" `
        -LocalAddress "127.0.0.1" -ExpectedInterfaceIndex $Loopback.interface_index `
        -Purpose "sing-box-proxy-excluded"))
    return $proofs.ToArray()
}

function Start-Ferrum2Support {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Harness,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Loopback
    )
    $tcpPort = Get-Ferrum2FreeSupportPorts -Address $Network.support_address
    $udpPort = $tcpPort
    Add-Ferrum2OwnedPort -Context $Context -Protocol "tcp" -Address $Network.support_address `
        -Port $tcpPort -Purpose "support-tcp"
    Add-Ferrum2OwnedPort -Context $Context -Protocol "udp" -Address $Network.support_address `
        -Port $udpPort -Purpose "support-udp"
    foreach ($protocol in @('TCP', 'UDP')) {
        [void](Add-Ferrum2OwnedFirewallRule -Context $Context -Executable $Harness `
            -Protocol $protocol -LocalAddress $Network.support_address -LocalPort ([string]$tcpPort) `
            -RemoteAddress $Network.support_address -InterfaceAlias $Loopback.interface_alias `
            -Purpose "support-$($protocol.ToLowerInvariant())")
    }
    $arguments = "windows-tun-support --listen-ip $($Network.support_address) --tcp-port $tcpPort --udp-port $udpPort"
    $process = Start-Ferrum2OwnedNativeProcess -Context $Context -Application $Harness `
        -Arguments $arguments -WorkingDirectory (Split-Path -Parent $Harness) `
        -LogPrefix "support" -Purpose "support"
    Wait-Ferrum2Text -Path $process.stdout -Pattern '^windows_tun_support status=READY ' -TimeoutSeconds 30
    return [pscustomobject]@{ process = $process; tcp_port = $tcpPort; udp_port = $udpPort }
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
    if (-not [Ferrum2HostProcessGroup]::Wait(
            [uint32]$Process.pid, [uint32]($TimeoutSeconds * 1000))) {
        [void][Ferrum2HostProcessGroup]::Terminate([uint32]$Process.pid)
        $failureLogs = Export-Ferrum2OwnedCommandFailureLogs -Context $Context `
            -Process $Process -LogPrefix $LogPrefix
        throw "owned command timed out: $LogPrefix; logs: $failureLogs"
    }
    $exit = [Ferrum2HostProcessGroup]::ExitCode([uint32]$Process.pid)
    [Ferrum2HostProcessGroup]::Close([uint32]$Process.pid)
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
