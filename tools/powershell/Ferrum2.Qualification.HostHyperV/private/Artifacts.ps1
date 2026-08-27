function Remove-BoundedWorkerManifestIfPresent {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
        [string]$ExpectedRunToken,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        (Test-Ferrum2PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) -or
        [IO.Path]::GetFileName($fullPath) -cne "host-orchestration.json" -or
        $ExpectedSchema -notin @(
            "ferrum2.windows-tun.hyperv-host-run.v7",
            "ferrum2.windows-tun.hard-kill-hyperv-host-run.v4"
        ) -or $ExpectedVmId -eq [Guid]::Empty) {
        throw "bounded worker failure manifest path is invalid"
    }
    $pendingPath = Join-Path (Split-Path -Parent $fullPath) `
        "host-orchestration.pending.json"
    $cleanupIssues = [Collections.Generic.List[string]]::new()
    foreach ($candidate in @($pendingPath, $fullPath)) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        try {
            Assert-NoReparsePointInExistingPath `
                -Path $candidate -Label "bounded worker failure manifest"
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $item.Length -gt 16777216) {
                throw "bounded worker failure manifest boundary is invalid"
            }
            if ($candidate -ceq $fullPath -and $item.Length -ge 2 -and
                $item.Length -le 4194304) {
                $retainDiagnostic = $false
                try {
                    $manifestText = Get-Content -LiteralPath $item.FullName `
                        -Raw -Encoding utf8
                    $document = $manifestText |
                        ConvertFrom-Json -Depth 10 -ErrorAction Stop
                    $retainDiagnostic = Test-BoundedWorkerManifestMinimum `
                        -Document $document -RawJson $manifestText `
                        -ExpectedSchema $ExpectedSchema -ExpectedStatus "fail" `
                        -ExpectedRunToken $ExpectedRunToken `
                        -ExpectedVmId $ExpectedVmId -ExpectedVmName $ExpectedVmName `
                        -EvidenceRoot (Split-Path -Parent $fullPath)
                } catch {
                    $retainDiagnostic = $false
                }
                if ($retainDiagnostic) {
                    continue
                }
            }
            if ($PSCmdlet.ShouldProcess(
                    $item.FullName,
                    "remove stale bounded worker manifest"
                )) {
                [IO.File]::Delete($item.FullName)
            }
        } catch {
            $cleanupIssues.Add(
                "$(Split-Path -Leaf $candidate): $($_.Exception.Message)"
            )
        }
    }
    if ($cleanupIssues.Count -ne 0) {
        throw (
            "bounded worker manifest cleanup failed: " +
                ($cleanupIssues -join "; ")
        )
    }
}

function Connect-ApprovedGuest {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.PSCredential]$Credential,
        [int]$TimeoutSeconds
    )

    if ($null -eq $script:approvedVmIdentity) {
        throw "approved VM identity is not initialized"
    }
    $connection = Connect-Ferrum2HostGuest `
        -Identity $script:approvedVmIdentity `
        -Credential $Credential `
        -TimeoutSeconds $TimeoutSeconds
    [pscustomobject][ordered]@{
        Session = $connection.Session
        Probe = [pscustomobject][ordered]@{
            Manufacturer = [string]$connection.Probe.Manufacturer
            Model = [string]$connection.Probe.Model
            Product = [string]$connection.Probe.Product
            Edition = [string]$connection.Probe.Edition
            Version = [string]$connection.Probe.Version
            Build = [string]$connection.Probe.Build
            OsBuildNumber = [string]$connection.Probe.OsBuild
            CurrentBuildNumber = [string]$connection.Probe.CurrentBuild
            Architecture = "X64"
            PowerShellVersion = [string]$connection.Probe.PowerShell
            IsAdministrator = [bool]$connection.Probe.IsAdministrator
        }
    }
}

function Read-IdentityLedger {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true)]
        [string]$ControllerPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ControllerBundleSha256,
        [object]$TopologyDocument,
        [object]$ExpectedSupportContext
    )

    $topologyDocument = Get-ApprovedTopologyDocument -TopologyDocument $TopologyDocument
    $resolved = Resolve-BoundedFile `
        -Path $Path `
        -Label "identity ledger" `
        -MaximumBytes 65536 `
        -RequireOutsideRepository
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    if ($bytes.Length -lt 2 -or $bytes[-1] -ne 10 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) -or
        @($bytes | Where-Object { $_ -eq 10 }).Count -ne 1 -or
        @($bytes | Where-Object { $_ -eq 13 }).Count -ne 0) {
        throw "identity ledger must be one BOM-free LF-terminated UTF-8 line"
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $bytes.Length - 1)
    $jsonDocument = [Text.Json.JsonDocument]::Parse($json)
    try {
        $supportCreationUtcText = $jsonDocument.RootElement.GetProperty(
            "support_listener"
        ).GetProperty("creation_utc").GetString()
    } finally {
        $jsonDocument.Dispose()
    }
    $ledger = $json | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $ledger.support_listener.creation_utc = $supportCreationUtcText
    $baseKeys = @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
        "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
        "candidate_sha", "probe_sha256", "controller_bundle_sha256",
        "client_sha256", "server_sha256", "support_listener",
        "topology"
    )
    $actualKeys = @($ledger.PSObject.Properties.Name)
    if (($actualKeys -join "|") -cne ($baseKeys -join "|") -or
        ($ledger | ConvertTo-Json -Compress -Depth 8) -cne $json) {
        throw "identity ledger is not canonical or has an invalid property set"
    }
    if ($ledger.schema -isnot [long] -or $ledger.schema -ne 4 -or
        $ledger.vm_name -cne [string]$topologyDocument.Value.vm.name -or
        $ledger.vm_id -cne [string]$topologyDocument.Value.vm.id -or
        $ledger.checkpoint_name -cne
            [string]$topologyDocument.Value.lab_checkpoint.name -or
        $ledger.checkpoint_id -cne
            [string]$topologyDocument.Value.lab_checkpoint.id -or
        $ledger.guest_architecture -cne "AMD64" -or
        $ledger.candidate_sha -cne $CandidateSha) {
        throw "identity ledger does not bind the approved guest and candidate"
    }
    foreach ($name in @(
            "probe_sha256", "controller_bundle_sha256", "client_sha256", "server_sha256"
        )) {
        if ([string]$ledger.$name -cnotmatch '^[0-9a-f]{64}$') {
            throw "identity ledger contains an invalid binary hash"
        }
    }
    $supportKeys = @(
        "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256", "creation_utc"
    )
    if ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -cne
        ($supportKeys -join "|")) {
        throw "identity ledger support listener shape is invalid"
    }
    $topologyKeys = @(
        "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
        "support_network", "support_prefix_length", "guest_interface_alias",
        "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
        "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
        "protected_host_tun_index", "protected_host_tun_status"
    )
    if ((@($ledger.topology.PSObject.Properties.Name) -join "|") -cne
        ($topologyKeys -join "|")) {
        throw "identity ledger topology binding shape is invalid"
    }
    $manifest = $topologyDocument.Value
    $topologyMatches =
        [string]$ledger.topology.manifest_sha256 -ceq [string]$topologyDocument.Sha256 -and
        [string]$ledger.topology.plan_sha256 -ceq [string]$topologyDocument.PlanDocument.Sha256 -and
        [string]$ledger.topology.support_switch_id -ceq
            [string]$manifest.support.switch.switch_id -and
        [string]$ledger.topology.support_host_ipv4 -ceq
            [string]$manifest.support.switch.host_ipv4 -and
        [string]$ledger.topology.support_network -ceq [string]$manifest.support.switch.network -and
        $ledger.topology.support_prefix_length -is [long] -and
        [long]$ledger.topology.support_prefix_length -eq
            [long]$manifest.support.switch.prefix_length -and
        [string]$ledger.topology.guest_interface_alias -ceq
            [string]$manifest.support.guest.support_interface_alias -and
        [string]$ledger.topology.guest_interface_guid -ceq
            [string]$manifest.support.guest.support_interface_guid -and
        $ledger.topology.guest_interface_index -is [long] -and
        [long]$ledger.topology.guest_interface_index -eq
            [long]$manifest.support.guest.support_interface_index -and
        [string]$ledger.topology.guest_mac_address -ceq
            [string]$manifest.support.guest.support_mac_address -and
        [string]$ledger.topology.guest_ipv4 -ceq [string]$manifest.support.guest.guest_ipv4 -and
        $ledger.topology.guest_mtu_bytes -is [long] -and
        [long]$ledger.topology.guest_mtu_bytes -eq [long]$manifest.support.guest.mtu_bytes -and
        [string]$ledger.topology.protected_host_tun_name -ceq
            [string]$manifest.protected_host_tun.name -and
        [string]$ledger.topology.protected_host_tun_guid -ceq
            [string]$manifest.protected_host_tun.interface_guid -and
        $ledger.topology.protected_host_tun_index -is [long] -and
        [long]$ledger.topology.protected_host_tun_index -eq
            [long]$manifest.protected_host_tun.interface_index -and
        [string]$ledger.topology.protected_host_tun_status -ceq
            [string]$manifest.protected_host_tun.status
    if (-not $topologyMatches -or
        [string]$ledger.support_listener.ipv4 -cne
            [string]$ledger.topology.support_host_ipv4 -or
        $null -ne $manifest.support.switch.gateway -or
        @($manifest.support.switch.dns_servers).Count -ne 0 -or
        $manifest.support.switch.nat_enabled -ne $false -or
        $manifest.support.switch.ics_enabled -ne $false -or
        $null -ne $manifest.support.guest.gateway -or
        @($manifest.support.guest.dns_servers).Count -ne 0) {
        throw "identity ledger topology binding does not match the isolated manifest"
    }
    if ($ledger.support_listener.tcp_port -isnot [long] -or
        [long]$ledger.support_listener.tcp_port -lt 1 -or
        [long]$ledger.support_listener.tcp_port -gt 65535 -or
        $ledger.support_listener.udp_port -isnot [long] -or
        [long]$ledger.support_listener.udp_port -lt 1 -or
        [long]$ledger.support_listener.udp_port -gt 65532 -or
        $ledger.support_listener.pid -isnot [long] -or
        [long]$ledger.support_listener.pid -lt 1 -or
        [long]$ledger.support_listener.pid -gt [int]::MaxValue -or
        [string]$ledger.support_listener.owner -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$' -or
        [string]$ledger.support_listener.executable_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "identity ledger support listener identity is invalid"
    }
    [DateTimeOffset]$supportCreationUtc = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $supportCreationUtcText,
            "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$supportCreationUtc
        ) -or $supportCreationUtc.Offset -ne [TimeSpan]::Zero) {
        throw "identity ledger support listener creation time is invalid"
    }
    $canonicalSupportCreationUtc = $supportCreationUtc.UtcDateTime.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture
    )
    if ($supportCreationUtcText -cne $canonicalSupportCreationUtc) {
        throw "identity ledger support listener creation time is not canonical UTC"
    }
    if ($null -eq $ExpectedSupportContext) {
        $ExpectedSupportContext = Get-ApprovedHostSupportRuntimeState `
            -TopologyDocument $topologyDocument `
            -Address ([string]$ledger.support_listener.ipv4) `
            -TcpPort ([int]$ledger.support_listener.tcp_port) `
            -UdpPort ([int]$ledger.support_listener.udp_port) `
            -ProcessId ([int]$ledger.support_listener.pid) `
            -ProcessOwner ([string]$ledger.support_listener.owner)
    }
    foreach ($field in @("ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256")) {
        if ([string]$ledger.support_listener.$field -cne [string]$ExpectedSupportContext.$field) {
            throw "identity ledger support listener changed: field=$field"
        }
    }
    if ($canonicalSupportCreationUtc -cne [string]$ExpectedSupportContext.creation_utc) {
        throw "identity ledger support listener changed: field=creation_utc"
    }
    $controllerHash = (Get-FileHash -LiteralPath $ControllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ledger.probe_sha256 -cne $controllerHash) {
        throw "identity ledger controller hash does not match the candidate"
    }
    if ($ledger.controller_bundle_sha256 -cne $ControllerBundleSha256) {
        throw "identity ledger controller bundle hash does not match the candidate"
    }
    return [pscustomobject]@{
        Path = $resolved
        Bytes = $bytes
        Ledger = $ledger
        Sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-CandidateIdentity {
    $gitCommand = (Get-Command git -CommandType Application -ErrorAction Stop).Source
    $status = @(& $gitCommand -C $script:repositoryRoot status --porcelain=v1 --untracked-files=all 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "unable to inspect candidate worktree"
    }
    if ($status.Count -ne 0) {
        throw "candidate worktree must be clean before privileged qualification"
    }
    $candidateSha = [string](& $gitCommand -C $script:repositoryRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or $candidateSha -cnotmatch '^[0-9a-f]{40}$') {
        throw "candidate commit identity is invalid"
    }
    return [pscustomobject]@{
        Sha = $candidateSha
    }
}

function Invoke-CapturedNativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [string]$WorkingDirectory = $script:repositoryRoot,
        [long]$MaximumOutputBytes = 67108864
    )

    $lines = [Collections.Generic.List[string]]::new()
    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $Executable @Arguments 2>&1 | ForEach-Object {
            [void]$lines.Add([string]$_)
        }
        $exitCode = [int]$LASTEXITCODE
    } finally {
        Pop-Location
    }
    $outputBytes = [Text.Encoding]::UTF8.GetByteCount(($lines -join "`n"))
    if ($outputBytes -gt $MaximumOutputBytes) {
        throw "$Label output exceeded its bounded capture"
    }
    if ($exitCode -ne 0) {
        $tail = @($lines | Select-Object -Last 20) -join "`n"
        throw "$Label failed with exit code $exitCode`n$tail"
    }
    return @($lines)
}

function Get-CargoCompilerArtifact {
    param([string[]]$Lines)

    $artifacts = [Collections.Generic.List[object]]::new()
    foreach ($line in $Lines) {
        if (-not $line.StartsWith("{", [StringComparison]::Ordinal)) {
            continue
        }
        try {
            $message = $line | ConvertFrom-Json -Depth 12 -ErrorAction Stop
        } catch {
            continue
        }
        if ($message.reason -ceq "compiler-artifact" -and
            -not [string]::IsNullOrWhiteSpace([string]$message.executable)) {
            $artifacts.Add($message)
        }
    }
    return @($artifacts)
}

function Select-CargoExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Messages,
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("bin", "lib")]
        [string]$TargetKind,
        [Parameter(Mandatory = $true)]
        [bool]$TestProfile,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $artifactMatches = @($Messages | Where-Object {
        $_.target.name -ceq $TargetName -and
        @($_.target.kind) -ccontains $TargetKind -and
        [bool]$_.profile.test -eq $TestProfile
    })
    if ($artifactMatches.Count -ne 1) {
        throw "$Label build did not yield exactly one executable"
    }
    return Resolve-BoundedFile `
        -Path ([string]$artifactMatches[0].executable) `
        -Label $Label `
        -MaximumBytes 536870912
}

function Copy-CandidateArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $resolved = Resolve-BoundedFile -Path $Source -Label $Label -MaximumBytes 536870912
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.Length -lt 4096) {
        throw "$Label executable boundary is invalid"
    }
    Copy-Item -LiteralPath $resolved -Destination $Destination -ErrorAction Stop
    $copied = Resolve-BoundedFile -Path $Destination -Label "staged $Label" -MaximumBytes 536870912
    $sourceHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    $destinationHash = (Get-FileHash -LiteralPath $copied -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -cne $destinationHash) {
        throw "$Label changed while staging"
    }
    return [pscustomobject]@{
        Path = $copied
        Name = [IO.Path]::GetFileName($copied)
        Bytes = [long](Get-Item -LiteralPath $copied -Force).Length
        Sha256 = $destinationHash
    }
}

function Read-Ferrum2CandidateArtifactBundle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true)]
        [object]$Ledger
    )

    if ($null -eq $Ledger -or
        [string]$Ledger.candidate_sha -cne $CandidateSha -or
        [string]$Ledger.client_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Ledger.server_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "candidate artifact ledger identity is invalid"
    }
    $resolvedManifest = Resolve-BoundedFile `
        -Path $ManifestPath `
        -Label "candidate artifact manifest" `
        -MaximumBytes 65536 `
        -RequireOutsideRepository
    if ([IO.Path]::GetFileName($resolvedManifest) -cne "candidate-artifacts.json") {
        throw "candidate artifact manifest filename is invalid"
    }

    [byte[]]$manifestBytes = [IO.File]::ReadAllBytes($resolvedManifest)
    if ($manifestBytes.Length -lt 2 -or
        $manifestBytes[-1] -ne 10 -or
        ($manifestBytes.Length -ge 3 -and
            $manifestBytes[0] -eq 0xef -and
            $manifestBytes[1] -eq 0xbb -and
            $manifestBytes[2] -eq 0xbf) -or
        @($manifestBytes | Where-Object { $_ -eq 10 }).Count -ne 1 -or
        @($manifestBytes | Where-Object { $_ -eq 13 }).Count -ne 0) {
        throw "candidate artifact manifest must be one BOM-free LF-terminated UTF-8 line"
    }

    $manifestJson = [Text.UTF8Encoding]::new($false, $true).GetString(
        $manifestBytes,
        0,
        $manifestBytes.Length - 1
    )
    $manifest = $manifestJson | ConvertFrom-Json -Depth 6 -ErrorAction Stop
    if ((@($manifest.PSObject.Properties.Name) -join "|") -cne
            "schema|candidate_sha|target|rust_version|files" -or
        $manifest.schema -cne "ferrum2.windows-tun.candidate-artifacts.v1" -or
        [string]$manifest.candidate_sha -cne $CandidateSha -or
        [string]$manifest.target -cne "x86_64-pc-windows-msvc" -or
        [string]$manifest.rust_version -cnotmatch
            '^rustc 1\.97\.1 \([0-9a-f]{9,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)$' -or
        ($manifest | ConvertTo-Json -Compress -Depth 6) -cne $manifestJson) {
        throw "candidate artifact manifest identity is invalid"
    }
    if ((@($manifest.files.PSObject.Properties.Name) -join "|") -cne
            "client|server") {
        throw "candidate artifact manifest file set is not closed"
    }

    $bundleRoot = Split-Path -Parent $resolvedManifest
    Assert-NoReparsePointInExistingPath `
        -Path $bundleRoot `
        -Label "candidate artifact bundle"
    $expectedNames = @(
        "candidate-artifacts.json",
        "ferrum2-client.exe",
        "ferrum2-server.exe"
    )
    $bundleItems = @(Get-ChildItem -LiteralPath $bundleRoot -Force -ErrorAction Stop)
    if ($bundleItems.Count -ne $expectedNames.Count -or
        @($bundleItems | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        }).Count -ne 0 -or
        ((@($bundleItems.Name | Sort-Object -CaseSensitive) -join "|") -cne
            ((@($expectedNames | Sort-Object -CaseSensitive)) -join "|"))) {
        throw "candidate artifact bundle file set is not closed"
    }

    $artifacts = [ordered]@{}
    $specifications = @(
        [ordered]@{
            Key = "client"
            Name = "ferrum2-client.exe"
            LedgerHash = [string]$Ledger.client_sha256
        },
        [ordered]@{
            Key = "server"
            Name = "ferrum2-server.exe"
            LedgerHash = [string]$Ledger.server_sha256
        }
    )
    foreach ($specification in $specifications) {
        $entry = $manifest.files.($specification.Key)
        if ((@($entry.PSObject.Properties.Name) -join "|") -cne
                "name|bytes|sha256" -or
            [string]$entry.name -cne $specification.Name -or
            ($entry.bytes -isnot [long] -and $entry.bytes -isnot [int]) -or
            [long]$entry.bytes -lt 4096 -or
            [long]$entry.bytes -gt 536870912 -or
            [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$entry.sha256 -cne $specification.LedgerHash) {
            throw "candidate $($specification.Key) manifest entry is invalid"
        }
        $path = Resolve-BoundedFile `
            -Path (Join-Path $bundleRoot $specification.Name) `
            -Label "candidate $($specification.Key) artifact" `
            -MaximumBytes 536870912 `
            -RequireOutsideRepository
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).
            Hash.ToLowerInvariant()
        if ([long]$item.Length -ne [long]$entry.bytes -or
            $sha256 -cne [string]$entry.sha256) {
            throw "candidate $($specification.Key) artifact identity changed"
        }
        $artifacts[$specification.Key] = [pscustomobject][ordered]@{
            Path = $path
            Name = $specification.Name
            Bytes = [long]$item.Length
            Sha256 = $sha256
        }
    }

    return [pscustomobject][ordered]@{
        ManifestPath = $resolvedManifest
        ManifestSha256 = (Get-FileHash -LiteralPath $resolvedManifest -Algorithm SHA256).
            Hash.ToLowerInvariant()
        CandidateSha = $CandidateSha
        Target = [string]$manifest.target
        RustVersion = [string]$manifest.rust_version
        Client = $artifacts.client
        Server = $artifacts.server
    }
}

function Build-Ferrum2CandidateArtifactBundle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true)]
        [object]$Ledger
    )

    if ($null -eq $Ledger -or
        [string]$Ledger.candidate_sha -cne $CandidateSha -or
        [string]$Ledger.client_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Ledger.server_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "candidate artifact ledger identity is invalid"
    }
    $preBuildCandidate = Get-CandidateIdentity
    if ($preBuildCandidate.Sha -cne $CandidateSha) {
        throw "candidate artifact build commit does not match the requested candidate"
    }
    $target = "x86_64-pc-windows-msvc"
    $rustup = (Get-Command rustup -CommandType Application -ErrorAction Stop).Source
    $versionDetails = Invoke-CapturedNativeCommand `
        -Executable $rustup `
        -Arguments @("run", "1.97.1", "rustc", "--version", "--verbose") `
        -Label "host Rust toolchain verification" `
        -MaximumOutputBytes 65536
    $versionLines = @($versionDetails | Where-Object {
        $_ -cmatch '^rustc 1\.97\.1 \([0-9a-f]{9,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)$'
    })
    $hostLines = @($versionDetails | Where-Object { $_ -ceq "host: $target" })
    $releaseLines = @($versionDetails | Where-Object { $_ -ceq "release: 1.97.1" })
    if ($versionLines.Count -ne 1 -or
        $hostLines.Count -ne 1 -or
        $releaseLines.Count -ne 1) {
        throw "host Rust toolchain does not match Rust 1.97.1 $target"
    }
    $rustVersion = [string]$versionLines[0]

    $bundleRoot = Resolve-ExternalDirectoryTarget `
        -Path $Destination `
        -Label "candidate artifact bundle"
    [IO.Directory]::CreateDirectory($bundleRoot) | Out-Null
    Assert-NoReparsePointInExistingPath `
        -Path $bundleRoot `
        -Label "candidate artifact bundle"

    $buildMessages = Get-CargoCompilerArtifact (Invoke-CapturedNativeCommand `
        -Executable $rustup `
        -Arguments @(
            "run", "1.97.1", "cargo", "build",
            "-p", "ferrum2-client", "-p", "ferrum2-server", "--bins",
            "--locked", "--target", $target,
            "--message-format=json-render-diagnostics",
            "--manifest-path", (Join-Path $script:repositoryRoot "Cargo.toml")
        ) `
        -Label "host candidate binary build")
    $clientSource = Select-CargoExecutable `
        -Messages $buildMessages `
        -TargetName "ferrum2-client" `
        -TargetKind "bin" `
        -TestProfile $false `
        -Label "candidate client"
    $serverSource = Select-CargoExecutable `
        -Messages $buildMessages `
        -TargetName "ferrum2-server" `
        -TargetKind "bin" `
        -TestProfile $false `
        -Label "candidate server"
    $client = Copy-CandidateArtifact `
        -Source $clientSource `
        -Destination (Join-Path $bundleRoot "ferrum2-client.exe") `
        -Label "candidate client"
    $server = Copy-CandidateArtifact `
        -Source $serverSource `
        -Destination (Join-Path $bundleRoot "ferrum2-server.exe") `
        -Label "candidate server"
    if ($client.Sha256 -cne [string]$Ledger.client_sha256 -or
        $server.Sha256 -cne [string]$Ledger.server_sha256) {
        throw "host-built candidate binary hashes do not match the identity ledger"
    }

    $manifest = [ordered]@{
        schema = "ferrum2.windows-tun.candidate-artifacts.v1"
        candidate_sha = $CandidateSha
        target = $target
        rust_version = $rustVersion
        files = [ordered]@{
            client = [ordered]@{
                name = $client.Name
                bytes = [long]$client.Bytes
                sha256 = $client.Sha256
            }
            server = [ordered]@{
                name = $server.Name
                bytes = [long]$server.Bytes
                sha256 = $server.Sha256
            }
        }
    }
    $manifestPath = Join-Path $bundleRoot "candidate-artifacts.json"
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($manifest | ConvertTo-Json -Compress -Depth 6) + "`n"
    )
    $manifestStream = [IO.FileStream]::new(
        $manifestPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $manifestStream.Write($manifestBytes, 0, $manifestBytes.Length)
        $manifestStream.Flush($true)
    } finally {
        $manifestStream.Dispose()
    }
    $postBuildCandidate = Get-CandidateIdentity
    if ($postBuildCandidate.Sha -cne $CandidateSha) {
        throw "candidate commit changed during artifact bundle construction"
    }

    return Read-Ferrum2CandidateArtifactBundle `
        -ManifestPath $manifestPath `
        -CandidateSha $CandidateSha `
        -Ledger $Ledger
}
