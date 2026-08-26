function Get-Tcp08ElapsedMilliseconds([long]$MonotonicTimestamp) {
    return [Math]::Round(
        (($MonotonicTimestamp - $script:tcp08ClockOriginTimestamp) * 1000.0) / [Diagnostics.Stopwatch]::Frequency,
        3
    )
}

function Add-Tcp08EventAtTimestamp([string]$Name, [long]$MonotonicTimestamp, [object]$Details = $null) {
    if (-not $script:tcp08Enabled) { return }
    $script:tcp08Events.Add([ordered]@{
        ordinal = $script:tcp08Events.Count + 1
        name = $Name
        monotonic_ticks = $MonotonicTimestamp
        elapsed_ms = Get-Tcp08ElapsedMilliseconds $MonotonicTimestamp
        details = $Details
    })
}

function Add-Tcp08Event([string]$Name, [object]$Details = $null) {
    Add-Tcp08EventAtTimestamp $Name ([Diagnostics.Stopwatch]::GetTimestamp()) $Details
}

function Write-CapabilityEvidence(
    [string]$Phase,
    [Collections.IDictionary]$Data,
    [ValidateRange(1, 2)][int]$Schema = 1
) {
    $row = [ordered]@{
        schema = $Schema
        phase = $Phase
        timestamp_utc = [DateTime]::UtcNow.ToString("O")
        data = $Data
    }
    Add-Content -LiteralPath $script:capabilityEvidence -Value ($row | ConvertTo-Json -Compress -Depth 8) -Encoding utf8NoBOM
}

function Get-Ipv4DefaultUnderlay {
    $rows = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                $route = $_
                $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -ErrorAction Stop
                $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -IncludeHidden -ErrorAction Stop
                if ($route.InterfaceIndex -ne 1 -and $route.InterfaceIndex -ne $script:ownedInterfaceIndex -and
                    $interface.ConnectionState -eq "Connected" -and $adapter.Status -eq "Up" -and
                    $adapter.InterfaceDescription -notmatch "Wintun") {
                    [pscustomobject]@{
                        Route = $route
                        Interface = $interface
                        EffectiveMetric = [uint64]$route.RouteMetric + [uint64]$interface.InterfaceMetric
                    }
                }
            }
    )
    Assert-True ($rows.Count -gt 0) "eligible IPv4 default underlay is missing"
    $minimum = ($rows | Measure-Object EffectiveMetric -Minimum).Minimum
    $best = @($rows | Where-Object { $_.EffectiveMetric -eq $minimum })
    $indices = @($best | ForEach-Object { [uint32]$_.Route.InterfaceIndex } | Sort-Object -Unique)
    Assert-True ($indices.Count -eq 1 -and $best.Count -eq 1) "eligible IPv4 default underlay is ambiguous"
    $sources = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $indices[0] -AddressState Preferred -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne "0.0.0.0" -and $_.IPAddress -notlike "169.254.*" })
    Assert-True ($sources.Count -ge 1) "eligible IPv4 default source is missing"
    return [pscustomobject]@{ InterfaceIndex = $indices[0]; Row = $best[0]; Sources = $sources }
}

function Assert-SupportUnderlayProbe([object]$Probe, [string]$Label) {
    Assert-True ($null -ne $Probe -and $null -ne $script:m17GuestNetworkPathDocument) "$Label support underlay probe is unavailable"
    $path = $script:m17GuestNetworkPathDocument.Value
    $networkAddress = ([string]$path.guest_route_prefix).Split('/')[0]
    Assert-True ([uint64]$Probe.InterfaceLuid -ne 0 -and
        [uint32]$Probe.InterfaceIndex -eq [uint32]$path.guest_interface_index -and
        [string]$Probe.SourceAddress -ceq [string]$path.guest_ipv4 -and
        [string]$Probe.DestinationPrefix -ceq $networkAddress -and
        [byte]$Probe.PrefixLength -eq [byte]$path.guest_prefix_length -and
        [string]$Probe.NextHop -ceq "0.0.0.0") "$Label did not use the manifest-bound isolated support /30"
}

function Get-PhysicalDnsSnapshot([int]$TunInterfaceIndex) {
    return @(
        Get-DnsClientServerAddress -ErrorAction Stop |
            Where-Object { $_.InterfaceIndex -ne $TunInterfaceIndex } |
            Sort-Object InterfaceIndex, AddressFamily |
            ForEach-Object { "$($_.InterfaceIndex)|$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" }
    )
}

function Get-Ipv4SystemRouteSnapshot {
    return @(
        Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Protocol |
            ForEach-Object { "$($_.InterfaceIndex)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)|$($_.Protocol)" }
    )
}

function Get-TunIpv4Dns([int]$InterfaceIndex) {
    $rows = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    return @(
        $rows | ForEach-Object { @($_.ServerAddresses) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function ConvertTo-PktMonUInt64([object]$Value) {
    [uint64]$parsed = 0
    Assert-True ([uint64]::TryParse([string]$Value, [ref]$parsed)) "PktMon counter value is invalid"
    return $parsed
}

function Get-PktMonOutputLines([string]$Text) {
    return @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
}

function Add-PktMonChecked([uint64]$Total, [uint64]$Value) {
    Assert-True ($Value -le [uint64]::MaxValue - $Total) "PktMon counter overflowed"
    return [uint64]($Total + $Value)
}

function Invoke-PktMon([string[]]$Arguments, [int]$TimeoutMilliseconds = 5000) {
    $path = "C:\Windows\System32\PktMon.exe"
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $version = [Version](($item.VersionInfo.FileVersion -split " ")[0])
    Assert-True ($version -eq [Version]"10.0.19041.906") "PktMon version mismatch"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-True $process.Start() "PktMon did not start"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "PktMon command timed out"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-True ($process.ExitCode -eq 0) "PktMon command failed"
        return [pscustomobject]@{ Stdout = $stdout; Stderr = $stderr }
    } finally {
        $process.Dispose()
    }
}

function Get-PktMonFlowPackets {
    $text = (Invoke-PktMon @("counters", "--type", "flow", "--json", "--zero")).Stdout.Trim()
    Assert-True ($text.StartsWith("[") -and $text.EndsWith("]")) "PktMon counter JSON is invalid"
    try { $groups = @($text | ConvertFrom-Json -Depth 32 -ErrorAction Stop) }
    catch { throw "PktMon counter JSON is invalid" }
    Assert-True ($groups.Count -gt 0) "PktMon counter groups are empty"
    $records = [Collections.Generic.List[object]]::new()
    foreach ($group in $groups) {
        Assert-True ($null -ne $group.PSObject.Properties["Components"] -and $group.Components -is [Array]) "PktMon counter group shape is invalid"
        foreach ($component in @($group.Components)) {
            [int]$id = 0
            Assert-True ($null -ne $component.PSObject.Properties["Id"] -and
                [int]::TryParse([string]$component.Id, [ref]$id) -and $id -gt 0) "PktMon counter component Id is invalid"
            if ($id -eq $script:pktmonComponentId) { $records.Add($component) }
        }
    }
    Assert-True ($records.Count -gt 0) "owned PktMon component counters are missing"
    [uint64]$total = 0
    $flowEdges = 0
    foreach ($component in $records) {
        Assert-True ($null -ne $component.PSObject.Properties["Counters"] -and $component.Counters -is [Array]) "PktMon counter component shape is invalid"
        foreach ($counter in @($component.Counters)) {
            Assert-True ($null -ne $counter.PSObject.Properties["Type"] -and $counter.Type -ceq "Flows") "PktMon counter edge type is invalid"
            foreach ($direction in @("Inbound", "Outbound")) {
                $edge = $counter.PSObject.Properties[$direction]
                Assert-True ($null -ne $edge -and $null -ne $edge.Value.PSObject.Properties["Packets"] -and
                    $null -ne $edge.Value.PSObject.Properties["Bytes"]) "PktMon flow edge shape is invalid"
                $packets = ConvertTo-PktMonUInt64 $edge.Value.Packets
                [void](ConvertTo-PktMonUInt64 $edge.Value.Bytes)
                $total = Add-PktMonChecked $total $packets
            }
            $flowEdges++
        }
    }
    Assert-True ($flowEdges -gt 0) "owned PktMon flow counters are missing"
    return $total
}

function Get-PktMonFlowPacketDelta([uint64]$Before) {
    $after = Get-PktMonFlowPackets
    Assert-True ($after -ge $Before) "PktMon flow counter regressed"
    return [uint64]($after - $Before)
}

function Assert-PktMonAbsent {
    $status = Get-PktMonOutputLines (Invoke-PktMon @("status")).Stdout
    Assert-True (@($status | Where-Object { $_ -ceq "Packet Monitor is not running." }).Count -eq 1) "PktMon baseline is running"
    $filters = Get-PktMonOutputLines (Invoke-PktMon @("filter", "list")).Stdout
    Assert-True ($filters.Count -eq 2 -and $filters[0] -ceq "Packet Filters:" -and $filters[1] -ceq "None") "PktMon filter baseline is not empty"
}

function Get-TunAccepted([int]$MetricsPort) {
    return Get-CounterValue (Get-Metrics $MetricsPort) "ferrum2_tun_packets_accepted"
}

function Wait-TunAcceptedAfter([int]$MetricsPort, [uint64]$Before) {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $after = Get-TunAccepted $MetricsPort
        if ($after -gt $Before) { return $after }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "unpinned packet did not enter Wintun"
}

function Invoke-M17BoundedCommand(
    [string]$Name,
    [string]$Executable,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$TimeoutSeconds = 300,
    [AllowNull()][string]$LogDirectory = $null
) {
    Assert-True ($Name -cmatch '^[a-z0-9][a-z0-9-]{0,95}$') "M17 command name is invalid"
    $resolvedLogDirectory = if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        $script:m17ArtifactRoot
    } else {
        [IO.Path]::GetFullPath($LogDirectory)
    }
    Assert-True (-not [string]::IsNullOrWhiteSpace($resolvedLogDirectory) -and
        (Test-Path -LiteralPath $resolvedLogDirectory -PathType Container)) `
        "M17 command log directory is unavailable"
    Assert-NotReparsePoint $resolvedLogDirectory "M17 command log directory"
    $stdoutPath = Join-Path $resolvedLogDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $resolvedLogDirectory "$Name.stderr.log"
    Assert-True (-not (Test-Path -LiteralPath $stdoutPath) -and -not (Test-Path -LiteralPath $stderrPath)) "M17 command log baseline is not absent"
    $start = [Diagnostics.Stopwatch]::StartNew()
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    Assert-True $process.Start() "M17 command did not start: $Name"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
        [void]$process.WaitForExit(10000)
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $start.Stop()
    $utf8 = [Text.UTF8Encoding]::new($false)
    Assert-True ($utf8.GetByteCount($stdout) -le 4194304 -and $utf8.GetByteCount($stderr) -le 4194304) "M17 command output exceeded the fixed 4 MiB cap: $Name"
    [IO.File]::WriteAllText($stdoutPath, $stdout, $utf8)
    [IO.File]::WriteAllText($stderrPath, $stderr, $utf8)
    Assert-True (-not $timedOut) "M17 command timed out: $Name"
    $exitCode = $process.ExitCode
    $process.Dispose()
    return [pscustomobject]@{
        Name = $Name
        ExitCode = $exitCode
        DurationMilliseconds = [Math]::Round($start.Elapsed.TotalMilliseconds, 3)
        Stdout = $stdout
        Stderr = $stderr
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

function Get-M17MetricValue([string]$Metrics, [string]$Name, [bool]$AllowAbsent = $false) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?(?:\{[^}`r`n]*\})? ([0-9]+(?:\.[0-9]+)?)$"
    $matches = [regex]::Matches($Metrics, $pattern)
    if ($matches.Count -eq 0 -and $AllowAbsent) { return 0.0 }
    Assert-True ($matches.Count -gt 0) "missing M17 metric: $Name"
    [double]$total = 0
    foreach ($match in $matches) { $total += [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) }
    return $total
}

function Get-M17LabeledMetricValue(
    [string]$Metrics,
    [string]$Name,
    [string]$Label,
    [string]$Value,
    [bool]$AllowAbsent = $false
) {
    $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{[^}`r`n]*$([regex]::Escape($Label))=`"$([regex]::Escape($Value))`"[^}`r`n]*\} ([0-9]+(?:\.[0-9]+)?)$"
    $match = [regex]::Match($Metrics, $pattern)
    if (-not $match.Success -and $AllowAbsent) { return 0.0 }
    Assert-True $match.Success "missing M17 labeled metric: $Name/$Label=$Value"
    return [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-M17TextSha256([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Value))
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $algorithm.Dispose() }
}

function Get-M17BytesSha256([byte[]]$Value) {
    Assert-True ($null -ne $Value -and $Value.Length -gt 0) `
        "M17 byte identity is empty"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash($Value)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $algorithm.Dispose() }
}

function Get-M17ManagedPlaneIdentity([string]$Name) {
    $adapters = @(Get-NetAdapter -Name $Name -IncludeHidden -ErrorAction Stop)
    Assert-True ($adapters.Count -eq 1) "M17 managed adapter identity is not exact"
    $adapter = $adapters[0]
    $interfaceIndex = [uint32]$adapter.ifIndex
    $interfaceLuid = [uint64]$adapter.NetLuid
    $interfaceGuid = ([Guid]$adapter.InterfaceGuid).ToString("D").ToLowerInvariant()
    Assert-True ($interfaceIndex -ne 0 -and $interfaceLuid -ne 0 -and
        [string]$adapter.Status -ceq "Up") "M17 managed adapter is not active"
    $addresses = @(
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily, IPAddress, PrefixLength |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.IPAddress)|$($_.PrefixLength)|$($_.AddressState)|$($_.PrefixOrigin)|$($_.SuffixOrigin)|$([bool]$_.SkipAsSource)"
            }
    )
    $routes = @(
        Get-NetRoute -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily, DestinationPrefix, NextHop, RouteMetric, Protocol |
            ForEach-Object {
                "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)|$([uint32]$_.RouteMetric)|$($_.Protocol)|$([bool]$_.Publish)"
            }
    )
    $dns = @(
        Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ErrorAction Stop |
            Sort-Object AddressFamily |
            ForEach-Object { "$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" }
    )
    $interfaces = @(
        Get-NetIPInterface -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction Stop |
            Sort-Object AddressFamily |
            ForEach-Object {
                "$($_.AddressFamily)|$([uint32]$_.NlMtu)|$($_.ConnectionState)|$($_.Dhcp)|$($_.AutomaticMetric)|$([uint32]$_.InterfaceMetric)"
            }
    )
    $document = [ordered]@{
        adapter_name = [string]$adapter.Name
        interface_guid = $interfaceGuid
        interface_luid = $interfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
        interface_index = $interfaceIndex
        interface_description = [string]$adapter.InterfaceDescription
        addresses = $addresses
        routes = $routes
        dns = $dns
        interfaces = $interfaces
    }
    $canonical = $document | ConvertTo-Json -Compress -Depth 6
    return [pscustomobject]@{
        Document = $document
        Canonical = $canonical
        Sha256 = Get-M17TextSha256 $canonical
        InterfaceGuid = $interfaceGuid
        InterfaceLuid = $interfaceLuid
        InterfaceIndex = $interfaceIndex
    }
}

function Get-M17StrictRouteWfpDefinition {
    return [pscustomobject]@{
        SessionKey = "{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}"
        SessionName = "Ferrum2 strict route dynamic session"
        SublayerKey = "{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}"
        SublayerName = "Ferrum2 strict route"
        Filters = @(
            [pscustomobject]@{ Name = "Ferrum2 app permit IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701001}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT"; Condition = "app"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 app permit IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701002}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT"; Condition = "app"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 TUN permit IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701003}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT"; Condition = "tun"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 TUN permit IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701004}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT"; Condition = "tun"; Protocol = 0 },
            [pscustomobject]@{ Name = "Ferrum2 DNS TCP block IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701007}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 6 },
            [pscustomobject]@{ Name = "Ferrum2 DNS UDP block IPv4"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701008}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 17 },
            [pscustomobject]@{ Name = "Ferrum2 DNS TCP block IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e8701009}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 6 },
            [pscustomobject]@{ Name = "Ferrum2 DNS UDP block IPv6"; Key = "{a158b31d-7a59-40bc-9339-38b5e870100a}"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK"; Condition = "dns"; Protocol = 17 }
        )
    }
}

function Get-M17StrictRouteWfpIdentity(
    [string]$Label,
    [uint64]$InterfaceLuid,
    [uint32]$ProcessId,
    [AllowNull()][string]$LogDirectory = $null
) {
    Assert-True ($Label -cmatch '^[a-z0-9][a-z0-9-]{0,63}$' -and
        $InterfaceLuid -ne 0 -and $ProcessId -ne 0) "M17 strict-route WFP snapshot identity is invalid"
    $ownerProcesses = @(Get-Process -Id ([int]$ProcessId) -ErrorAction Stop)
    Assert-True ($ownerProcesses.Count -eq 1 -and
        -not [string]::IsNullOrWhiteSpace([string]$ownerProcesses[0].Path)) `
        "M17 strict-route WFP owner executable is not exact"
    $ownerExecutable = [IO.Path]::GetFullPath([string]$ownerProcesses[0].Path)
    Assert-True (
        $ownerExecutable.Equals(
            [IO.Path]::GetFullPath($script:binary),
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        (Test-Path -LiteralPath $ownerExecutable -PathType Leaf)
    ) "M17 strict-route WFP owner is not the current ferrum2 executable"
    Assert-NotReparsePoint $ownerExecutable "M17 strict-route WFP owner executable"
    $expectedAppId = [Ferrum2WfpIdentity]::GetAppId($ownerExecutable)
    Assert-True ($expectedAppId.Length -gt 0 -and $expectedAppId.Length -le 131072) `
        "M17 strict-route WFP owner AppId byte boundary is invalid"
    $expectedAppIdHex = ([BitConverter]::ToString($expectedAppId)).Replace("-", "").ToLowerInvariant()
    $appIdSha256 = Get-M17BytesSha256 $expectedAppId
    $path = Join-Path $script:work "m17-wfp-$Label.xml"
    Assert-True (-not (Test-Path -LiteralPath $path)) "M17 strict-route WFP snapshot baseline is not absent"
    $netsh = Join-Path ([Environment]::SystemDirectory) "netsh.exe"
    try {
        $result = Invoke-M17BoundedCommand "wfp-$Label" $netsh `
            @("wfp", "show", "state", "file=$path") $script:work 60 $LogDirectory
        Assert-True ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $path -PathType Leaf)) "M17 strict-route WFP state capture failed"
        Assert-NotReparsePoint $path "M17 strict-route WFP snapshot"
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-True ($item.Length -gt 0 -and $item.Length -le 67108864) "M17 strict-route WFP snapshot exceeded its 64 MiB boundary"
        [xml]$document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $definition = Get-M17StrictRouteWfpDefinition
        $sublayer = [string]$definition.SublayerKey
        $expected = @($definition.Filters)
        $filters = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
            $subLayerNode = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
            $filterIdNode = $_.SelectSingleNode("./*[local-name()='filterId']")
            $null -ne $subLayerNode -and $null -ne $filterIdNode -and
                $subLayerNode.InnerText.ToLowerInvariant() -ceq $sublayer
        })
        Assert-True ($filters.Count -eq $expected.Count) "M17 strict-route WFP filter count is not exact"
        $rows = [System.Collections.Generic.List[string]]::new()
        $filterEvidence = [System.Collections.Generic.List[object]]::new()
        foreach ($spec in $expected) {
            $matches = @($filters | Where-Object {
                $nameNode = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
                $null -ne $nameNode -and $nameNode.InnerText -ceq $spec.Name
            })
            Assert-True ($matches.Count -eq 1) "M17 strict-route WFP named filter is not exact: $($spec.Name)"
            $filter = $matches[0]
            $keyNode = $filter.SelectSingleNode("./*[local-name()='filterKey']")
            $layerNode = $filter.SelectSingleNode("./*[local-name()='layerKey']")
            $actionNode = $filter.SelectSingleNode("./*[local-name()='action']/*[local-name()='type']")
            $filterIdNode = $filter.SelectSingleNode("./*[local-name()='filterId']")
            [uint64]$filterId = 0
            Assert-True ($null -ne $keyNode -and $keyNode.InnerText.ToLowerInvariant() -ceq $spec.Key -and
                $null -ne $layerNode -and $layerNode.InnerText -ceq $spec.Layer -and
                $null -ne $actionNode -and $actionNode.InnerText -ceq $spec.Action -and
                $null -ne $filterIdNode -and [uint64]::TryParse($filterIdNode.InnerText, [ref]$filterId) -and
                $filterId -ne 0) "M17 strict-route WFP filter identity changed: $($spec.Name)"
            $conditions = @($filter.SelectNodes(
                "./*[local-name()='filterCondition']/*[local-name()='item']"
            ))
            $fieldKeys = @($conditions | ForEach-Object {
                $fieldKeyNode = $_.SelectSingleNode("./*[local-name()='fieldKey']")
                if ($null -ne $fieldKeyNode) { $fieldKeyNode.InnerText }
            })
            if ($spec.Condition -ceq "app") {
                $matchNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode("./*[local-name()='matchType']")
                } else { $null }
                $typeNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='type']"
                    )
                } else { $null }
                $appIdNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='byteBlob']/*[local-name()='data']"
                    )
                } else { $null }
                $appIdHex = if ($null -ne $appIdNode) {
                    $appIdNode.InnerText.Trim().ToLowerInvariant()
                } else { "" }
                Assert-True (
                    ($fieldKeys -join "|") -ceq "FWPM_CONDITION_ALE_APP_ID" -and
                    $null -ne $matchNode -and $matchNode.InnerText -ceq "FWP_MATCH_EQUAL" -and
                    $null -ne $typeNode -and $typeNode.InnerText -ceq "FWP_BYTE_BLOB_TYPE" -and
                    $appIdHex -cmatch '^(?:[0-9a-f]{2})+$' -and
                    $appIdHex -ceq $expectedAppIdHex
                ) "M17 strict-route app permit AppId condition changed"
            } elseif ($spec.Condition -ceq "tun") {
                $matchNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode("./*[local-name()='matchType']")
                } else { $null }
                $typeNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='type']"
                    )
                } else { $null }
                $luidNode = if ($conditions.Count -eq 1) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='uint64']"
                    )
                } else { $null }
                Assert-True (
                    ($fieldKeys -join "|") -ceq "FWPM_CONDITION_IP_LOCAL_INTERFACE" -and
                    $null -ne $matchNode -and $matchNode.InnerText -ceq "FWP_MATCH_EQUAL" -and
                    $null -ne $typeNode -and $typeNode.InnerText -ceq "FWP_UINT64" -and
                    $null -ne $luidNode -and $luidNode.InnerText -ceq
                        $InterfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)
                ) "M17 strict-route TUN LUID condition changed"
            } else {
                $protocolMatchNode = if ($conditions.Count -eq 2) {
                    $conditions[0].SelectSingleNode("./*[local-name()='matchType']")
                } else { $null }
                $protocolTypeNode = if ($conditions.Count -eq 2) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='type']"
                    )
                } else { $null }
                $protocolNode = if ($conditions.Count -eq 2) {
                    $conditions[0].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='uint8']"
                    )
                } else { $null }
                $portMatchNode = if ($conditions.Count -eq 2) {
                    $conditions[1].SelectSingleNode("./*[local-name()='matchType']")
                } else { $null }
                $portTypeNode = if ($conditions.Count -eq 2) {
                    $conditions[1].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='type']"
                    )
                } else { $null }
                $portNode = if ($conditions.Count -eq 2) {
                    $conditions[1].SelectSingleNode(
                        "./*[local-name()='conditionValue']/*[local-name()='uint16']"
                    )
                } else { $null }
                Assert-True (
                    ($fieldKeys -join "|") -ceq
                        "FWPM_CONDITION_IP_PROTOCOL|FWPM_CONDITION_IP_REMOTE_PORT" -and
                    $null -ne $protocolMatchNode -and
                    $protocolMatchNode.InnerText -ceq "FWP_MATCH_EQUAL" -and
                    $null -ne $protocolTypeNode -and
                    $protocolTypeNode.InnerText -ceq "FWP_UINT8" -and
                    $null -ne $protocolNode -and
                    $protocolNode.InnerText -ceq ([string]$spec.Protocol) -and
                    $null -ne $portMatchNode -and
                    $portMatchNode.InnerText -ceq "FWP_MATCH_EQUAL" -and
                    $null -ne $portTypeNode -and
                    $portTypeNode.InnerText -ceq "FWP_UINT16" -and
                    $null -ne $portNode -and $portNode.InnerText -ceq "53"
                ) "M17 strict-route DNS condition changed"
            }
            $rows.Add("$($spec.Name)|$($spec.Key)|$filterId|$($spec.Layer)|$($spec.Action)|$sublayer")
            $filterEvidence.Add([pscustomobject][ordered]@{
                Key = ([string]$spec.Key).Trim('{', '}')
                Id = $filterId.ToString([Globalization.CultureInfo]::InvariantCulture)
            })
        }
        $sublayers = @($document.SelectNodes("//*[local-name()='item']") |
            Where-Object {
                $keyNode = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
                $filterIdNode = $_.SelectSingleNode("./*[local-name()='filterId']")
                $nameNode = $_.SelectSingleNode(
                    "./*[local-name()='displayData']/*[local-name()='name']"
                )
                $null -ne $keyNode -and $null -eq $filterIdNode -and
                    $keyNode.InnerText.ToLowerInvariant() -ceq $sublayer -and
                    $null -ne $nameNode -and
                    $nameNode.InnerText -ceq [string]$definition.SublayerName
            })
        Assert-True ($sublayers.Count -eq 1) `
            "M17 strict-route dynamic WFP sublayer identity is not exact"
        $sessionKey = [string]$definition.SessionKey
        $sessionName = [string]$definition.SessionName
        $sessions = @($document.SelectNodes("//*[local-name()='item']") | Where-Object {
            $keyNode = $_.SelectSingleNode("./*[local-name()='sessionKey']")
            $nameNode = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
            $null -ne $keyNode -and $keyNode.InnerText.ToLowerInvariant() -ceq $sessionKey -and
                $null -ne $nameNode -and $nameNode.InnerText -ceq $sessionName
        })
        Assert-True ($sessions.Count -eq 1) "M17 strict-route dynamic WFP session identity is not exact"
        $processNode = $sessions[0].SelectSingleNode("./*[local-name()='processId']")
        [uint32]$sessionProcessId = 0
        Assert-True ($null -ne $processNode -and
            [uint32]::TryParse($processNode.InnerText, [ref]$sessionProcessId) -and
            $sessionProcessId -eq $ProcessId) "M17 strict-route dynamic WFP session process identity changed"
        $sessionCanonical = "session|$sessionKey|$sessionName|$sessionProcessId"
        $interfaceLuidText = $InterfaceLuid.ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
        $interfaceCanonical = "interface_luid|$interfaceLuidText"
        $appIdCanonical = "app_id_sha256|$appIdSha256"
        $canonical = (@(
            $sessionCanonical,
            $interfaceCanonical,
            $appIdCanonical
        ) + @($rows)) -join "`n"
        return [pscustomobject]@{
            Canonical = $canonical
            Sha256 = Get-M17TextSha256 $canonical
            InterfaceLuid = $interfaceLuidText
            AppIdSha256 = $appIdSha256
            FilterIds = @($rows | ForEach-Object { ($_ -split '\|')[2] })
            Filters = @($filterEvidence)
            FilterCount = $rows.Count
            ProcessId = $sessionProcessId
            SessionKey = "8ea35b4e-6629-4e26-9776-95c5bf9c6b01"
            SublayerKey = "ddbc2fa2-d52f-4a79-8a63-8446c308cf02"
        }
    } finally {
        if (Test-Path -LiteralPath $path) {
            Assert-NotReparsePoint $path "M17 strict-route WFP snapshot cleanup"
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}

function Assert-M17StrictRouteWfpIdentityAbsent(
    [string]$Label,
    [object]$Identity,
    [AllowNull()][string]$LogDirectory = $null
) {
    $identityFilterIds = if ($null -ne $Identity) {
        @($Identity.FilterIds | ForEach-Object { [string]$_ })
    } else { @() }
    $uniqueFilterIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $filterIdsAreUnique = $true
    foreach ($identityFilterId in $identityFilterIds) {
        if (-not $uniqueFilterIds.Add($identityFilterId)) {
            $filterIdsAreUnique = $false
        }
    }
    $identityInterfaceLuidText = if ($null -ne $Identity -and
        $null -ne $Identity.PSObject.Properties["InterfaceLuid"]) {
        [string]$Identity.InterfaceLuid
    } else { "" }
    [uint64]$identityInterfaceLuid = 0
    Assert-True ($Label -cmatch '^[a-z0-9][a-z0-9-]{0,63}$' -and
        $null -ne $Identity -and [long]$Identity.FilterCount -eq 8 -and
        [uint32]$Identity.ProcessId -ne 0 -and
        $identityInterfaceLuidText -cmatch '^[1-9][0-9]{0,19}$' -and
        [uint64]::TryParse(
            $identityInterfaceLuidText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$identityInterfaceLuid
        ) -and $identityInterfaceLuid -ne 0 -and
        $identityFilterIds.Count -eq 8 -and $filterIdsAreUnique) `
        "M17 strict-route WFP absence identity is invalid"
    $definition = Get-M17StrictRouteWfpDefinition
    Assert-True (
        [string]$Identity.SessionKey -ceq
            ([string]$definition.SessionKey).Trim('{', '}') -and
        [string]$Identity.SublayerKey -ceq
            ([string]$definition.SublayerKey).Trim('{', '}')
    ) "M17 strict-route WFP absence identity changed"
    $path = Join-Path $script:work "m17-wfp-$Label.xml"
    Assert-True (-not (Test-Path -LiteralPath $path)) `
        "M17 strict-route WFP absence snapshot baseline is not absent"
    $netsh = Join-Path ([Environment]::SystemDirectory) "netsh.exe"
    try {
        $result = Invoke-M17BoundedCommand "wfp-$Label" $netsh `
            @("wfp", "show", "state", "file=$path") $script:work 60 $LogDirectory
        Assert-True ($result.ExitCode -eq 0 -and
            (Test-Path -LiteralPath $path -PathType Leaf)) `
            "M17 strict-route WFP absence state capture failed"
        Assert-NotReparsePoint $path "M17 strict-route WFP absence snapshot"
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-True ($item.Length -gt 0 -and $item.Length -le 67108864) `
            "M17 strict-route WFP absence snapshot exceeded its 64 MiB boundary"
        [xml]$document = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $filterKeys = @($definition.Filters | ForEach-Object {
            ([string]$_.Key).ToLowerInvariant()
        })
        $filterNames = @($definition.Filters | ForEach-Object { [string]$_.Name })
        $filterIds = $identityFilterIds
        $sessionKey = ([string]$definition.SessionKey).ToLowerInvariant()
        $sessionName = [string]$definition.SessionName
        $sublayerKey = ([string]$definition.SublayerKey).ToLowerInvariant()
        $matchingItems = @($document.SelectNodes("//*[local-name()='item']") |
            Where-Object {
                $filterKeyNode = $_.SelectSingleNode("./*[local-name()='filterKey']")
                $filterIdNode = $_.SelectSingleNode("./*[local-name()='filterId']")
                $sessionKeyNode = $_.SelectSingleNode("./*[local-name()='sessionKey']")
                $sublayerKeyNode = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
                $nameNode = $_.SelectSingleNode(
                    "./*[local-name()='displayData']/*[local-name()='name']"
                )
                ($null -ne $filterKeyNode -and
                    $filterKeys -ccontains $filterKeyNode.InnerText.ToLowerInvariant()) -or
                ($null -ne $filterIdNode -and
                    $filterIds -ccontains $filterIdNode.InnerText) -or
                ($null -ne $sessionKeyNode -and
                    $sessionKeyNode.InnerText.ToLowerInvariant() -ceq $sessionKey) -or
                ($null -ne $sublayerKeyNode -and
                    $sublayerKeyNode.InnerText.ToLowerInvariant() -ceq $sublayerKey) -or
                ($null -ne $nameNode -and
                    ($nameNode.InnerText -ceq $sessionName -or
                        $nameNode.InnerText -ceq [string]$definition.SublayerName -or
                        $filterNames -ccontains $nameNode.InnerText))
            })
        Assert-True ($matchingItems.Count -eq 0) (
            "M17 strict-route dynamic WFP identity survived abrupt process exit: " +
                "matches=$($matchingItems.Count)"
        )
    } finally {
        if (Test-Path -LiteralPath $path) {
            Assert-NotReparsePoint $path "M17 strict-route WFP absence snapshot cleanup"
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}
