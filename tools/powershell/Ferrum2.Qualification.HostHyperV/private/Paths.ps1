function Assert-NoReparsePointInExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use a rooted filesystem path"
    }

    $current = $root
    $relative = $fullPath.Substring($root.Length)
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function Resolve-BoundedFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [long]$MaximumBytes = 1073741824,
        [switch]$RequireOutsideRepository
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-NoReparsePointInExistingPath -Path $resolved -Label $Label
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le $MaximumBytes) {
        if ($RequireOutsideRepository -and (Test-Ferrum2PathWithinRoot -Path $resolved -Root $script:repositoryRoot)) {
            throw "$Label must be stored outside the repository"
        }
        return $resolved
    }
    throw "$Label file boundary is invalid"
}

function Resolve-ExternalDirectoryTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (Test-Ferrum2PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) {
        throw "$Label must be stored outside the repository"
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw "$Label baseline must be absent"
    }

    $ancestor = [IO.Path]::GetDirectoryName($fullPath)
    while (-not [string]::IsNullOrWhiteSpace($ancestor) -and
        -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
        $next = [IO.Path]::GetDirectoryName($ancestor)
        if ($next -ceq $ancestor) {
            break
        }
        $ancestor = $next
    }
    if ([string]::IsNullOrWhiteSpace($ancestor) -or
        -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
        throw "$Label has no existing filesystem ancestor"
    }
    Assert-NoReparsePointInExistingPath -Path $ancestor -Label $Label
    return $fullPath
}

function Resolve-ExternalFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 1073741824
    )

    return Resolve-BoundedFile -Path $Path -Label $Label -MaximumBytes $MaximumBytes `
        -RequireOutsideRepository
}

function Import-ApprovedTopologyRuntime {
    if (-not $script:topologyRuntimeLoaded) {
        throw "approved topology helpers were not loaded in script scope"
    }
    Assert-ApprovedTopologyHelperSourcesUnchanged
}

function Assert-ApprovedTopologyHelperSourcesUnchanged {
    if (-not $script:topologyRuntimeLoaded -or
        [string]::IsNullOrWhiteSpace($script:topologyRuntimeSha256) -or
        [string]::IsNullOrWhiteSpace($script:hostNetworkPathHelperSha256) -or
        [string]::IsNullOrWhiteSpace($script:guestNetworkPathProbeSha256)) {
        throw "approved topology helpers have not been initialized"
    }
    if ((Get-FileHash -LiteralPath $script:topologyRuntimePath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $script:topologyRuntimeSha256 -or
        (Get-FileHash -LiteralPath $script:hostNetworkPathHelperPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $script:hostNetworkPathHelperSha256 -or
        (Get-FileHash -LiteralPath $script:guestNetworkPathProbePath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $script:guestNetworkPathProbeSha256) {
        throw "approved topology helper source changed during the run"
    }
}

function Get-ApprovedTopologyDocument {
    param([object]$TopologyDocument)

    $document = if ($null -ne $TopologyDocument) {
        $TopologyDocument
    } else {
        $script:topologyManifestDocument
    }
    if ($null -eq $document) {
        throw "support topology manifest has not been initialized"
    }
    return $document
}

function Get-ApprovedHyperVTopologyRuntimeState {
    param([object]$TopologyDocument)

    Import-ApprovedTopologyRuntime
    $document = Get-ApprovedTopologyDocument -TopologyDocument $TopologyDocument
    $runtime = Get-Ferrum2ApprovedHyperVTopologyContext `
        -Document $document -ReadinessTimeoutSeconds 10
    $vmNetwork = Get-ApprovedVmNetworkContext `
        -TopologyDocument $document `
        -MinimumIpv4PacketBytes $script:minimumSupportIpv4PacketBytes
    return [pscustomobject][ordered]@{
        Runtime = $runtime
        VmNetwork = $vmNetwork
    }
}

function Assert-ApprovedHyperVTopologyRuntimeStateUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )

    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $Expected.VmNetwork -Actual $Actual.VmNetwork
    Assert-Ferrum2ObjectFieldsEqual `
        -Expected $Expected.Runtime.ProtectedHostTun `
        -Actual $Actual.Runtime.ProtectedHostTun `
        -Fields @("present", "name", "interface_guid", "interface_index", "status") `
        -Label "protected host TUN runtime identity"
    foreach ($identity in @(
        [ordered]@{ Expected = $Expected.Runtime.Vm.Id; Actual = $Actual.Runtime.Vm.Id; Label = "VM" },
        [ordered]@{ Expected = $Expected.Runtime.Checkpoint.Id; Actual = $Actual.Runtime.Checkpoint.Id; Label = "qualification checkpoint" },
        [ordered]@{ Expected = $Expected.Runtime.SupportSwitch.Id; Actual = $Actual.Runtime.SupportSwitch.Id; Label = "support switch" },
        [ordered]@{ Expected = $Expected.Runtime.SupportVmAdapter.Id; Actual = $Actual.Runtime.SupportVmAdapter.Id; Label = "support VM adapter" }
    )) {
        if ([string]$identity.Expected -cne [string]$identity.Actual) {
            throw "approved topology $($identity.Label) identity changed"
        }
    }
}

function Get-ApprovedHostSupportRuntimeState {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ProcessOwner,
        [object]$TopologyDocument
    )

    Import-ApprovedTopologyRuntime
    $document = Get-ApprovedTopologyDocument -TopologyDocument $TopologyDocument
    return Get-HostSupportContext -TopologyDocument $document `
        -Address $Address -TcpPort $TcpPort -UdpPort $UdpPort `
        -ProcessId $ProcessId -ProcessOwner $ProcessOwner `
        -MinimumIpv4PacketBytes $script:minimumSupportIpv4PacketBytes
}

function Assert-ApprovedHostSupportRuntimeStateUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )

    Assert-HostSupportContextUnchanged -Expected $Expected -Actual $Actual
}

function Get-ApprovedGuestSupportTopologyRuntimeState {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [object]$TopologyDocument
    )

    Import-ApprovedTopologyRuntime
    $document = Get-ApprovedTopologyDocument -TopologyDocument $TopologyDocument
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $document
    $expectedLibraryHash = [string]$document.Value.provisioning_library_sha256
    if ((Get-FileHash -LiteralPath $script:topologyProvisioningLibraryPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $expectedLibraryHash) {
        throw "topology provisioning library changed before guest readback"
    }
    $module = New-Module -Name (
        "Ferrum2M17GuestTopology_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList @(
        $script:topologyProvisioningLibraryPath,
        $expectedLibraryHash
    ) -ScriptBlock {
        param([string]$LibraryPath, [string]$ExpectedSha256)
        if ((Get-FileHash -LiteralPath $LibraryPath -Algorithm SHA256).Hash.
                ToLowerInvariant() -cne $ExpectedSha256) {
            throw "topology provisioning library changed before loading"
        }
        . $LibraryPath -LibraryOnly
        if ((Get-FileHash -LiteralPath $LibraryPath -Algorithm SHA256).Hash.
                ToLowerInvariant() -cne $ExpectedSha256) {
            throw "topology provisioning library changed while loading"
        }
        Export-ModuleMember -Function "Invoke-GuestSupportNetwork"
    }
    try {
        $guest = & $module {
            param([object]$ApprovedSession, [object]$Plan)
            Invoke-GuestSupportNetwork -Session $ApprovedSession -Plan $Plan `
                -Phase "post_checkpoint_restore"
        } $Session $document.PlanDocument.Value
    } finally {
        Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
    }
    Assert-Ferrum2ObjectFieldsEqual -Expected $document.Value.support.guest -Actual $guest `
        -Fields @(
            "schema", "management_interface_alias", "management_interface_guid",
            "management_interface_index", "management_mac_address", "support_interface_alias",
            "support_interface_guid", "support_interface_index", "support_mac_address",
            "guest_ipv4", "prefix_length", "network", "mtu_bytes", "selected_source_ipv4",
            "selected_route_prefix", "selected_route_next_hop"
        ) -Label "approved guest support topology"
    if ($null -ne $guest.gateway -or @($guest.dns_servers).Count -ne 0) {
        throw "approved guest support topology acquired a gateway or DNS server"
    }
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $document
    return $guest
}

function Invoke-ApprovedGuestNetworkPathProbe {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][string]$GuestInputPath,
        [Parameter(Mandatory = $true)][string]$ManagedAdapterName,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string]$RunToken,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$IdentityLedgerSha256,
        [string]$OutputPath,
        [object]$TopologyDocument
    )

    Import-ApprovedTopologyRuntime
    $document = Get-ApprovedTopologyDocument -TopologyDocument $TopologyDocument
    $manifest = $document.Value
    $rows = @(Invoke-Command -Session $Session -ErrorAction Stop -ArgumentList @(
        $GuestInputPath,
        $ManagedAdapterName,
        $TcpPort,
        $UdpPort,
        $RunToken,
        $IdentityLedgerSha256,
        $OutputPath,
        [string]$document.Sha256,
        [string]$manifest.support.switch.host_ipv4,
        [string]$manifest.support.guest.guest_ipv4,
        [string]$manifest.support.guest.support_interface_alias,
        [string]$manifest.support.guest.network,
        [int]$manifest.support.guest.prefix_length,
        [string]$manifest.support.guest.support_mac_address,
        [string]$manifest.support.guest.support_interface_guid,
        [int]$manifest.support.guest.mtu_bytes,
        [string]$script:guestNetworkPathProbeSha256,
        [int]$script:minimumSupportIpv4PacketBytes
    ) -ScriptBlock {
        param(
            [string]$InputPath,
            [string]$ExpectedManagedAdapterName,
            [int]$ExpectedTcpPort,
            [int]$ExpectedUdpPort,
            [string]$ExpectedRunToken,
            [string]$ExpectedLedgerSha256,
            [string]$ResultPath,
            [string]$ExpectedManifestSha256,
            [string]$ExpectedSupportIpv4,
            [string]$ExpectedGuestIpv4,
            [string]$ExpectedGuestInterfaceAlias,
            [string]$ExpectedNetwork,
            [int]$ExpectedPrefixLength,
            [string]$ExpectedGuestMacAddress,
            [string]$ExpectedGuestInterfaceGuid,
            [int]$ExpectedGuestMtuBytes,
            [string]$ExpectedProbeSha256,
            [int]$MinimumPacketBytes
        )
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"
        function Test-EqualByteArray {
            param([byte[]]$Left, [byte[]]$Right)
            if ($Left.Length -ne $Right.Length) { return $false }
            for ($index = 0; $index -lt $Left.Length; $index++) {
                if ($Left[$index] -ne $Right[$index]) { return $false }
            }
            return $true
        }
        $probePath = Join-Path $InputPath "controller\get_windows_tun_guest_network_path.ps1"
        $manifestPath = Join-Path $InputPath "topology-manifest.json"
        $ledgerPath = Join-Path $InputPath "identity-ledger.json"
        foreach ($path in @($probePath, $manifestPath, $ledgerPath)) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $item.Length -lt 2 -or $item.Length -gt 4194304) {
                throw "guest topology preflight input boundary is invalid"
            }
        }
        if ((Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $ExpectedProbeSha256 -or
            (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $ExpectedManifestSha256 -or
            (Get-FileHash -LiteralPath $ledgerPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $ExpectedLedgerSha256) {
            throw "guest topology preflight source identity is invalid"
        }
        $ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 |
            ConvertFrom-Json -ErrorAction Stop
        if ($ledger.schema -ne 3 -or
            [string]$ledger.topology.manifest_sha256 -cne $ExpectedManifestSha256 -or
            [string]$ledger.topology.support_host_ipv4 -cne $ExpectedSupportIpv4 -or
            [string]$ledger.topology.guest_ipv4 -cne $ExpectedGuestIpv4 -or
            [string]$ledger.topology.guest_interface_alias -cne
                $ExpectedGuestInterfaceAlias -or
            [string]$ledger.topology.guest_interface_guid -cne
                $ExpectedGuestInterfaceGuid -or
            [string]$ledger.topology.guest_mac_address -cne $ExpectedGuestMacAddress -or
            [int]$ledger.topology.guest_mtu_bytes -ne $ExpectedGuestMtuBytes -or
            [string]$ledger.topology.support_network -cne $ExpectedNetwork -or
            [int]$ledger.topology.support_prefix_length -ne $ExpectedPrefixLength) {
            throw "guest topology preflight ledger binding is invalid"
        }
        $probeRows = @(& $probePath `
            -SupportIpv4 $ExpectedSupportIpv4 `
            -SupportPort $ExpectedUdpPort `
            -ExpectedGuestIpv4 $ExpectedGuestIpv4 `
            -ExpectedInterfaceAlias $ExpectedGuestInterfaceAlias `
            -ExpectedNetwork $ExpectedNetwork `
            -ExpectedPrefixLength $ExpectedPrefixLength `
            -ExpectedMacAddress $ExpectedGuestMacAddress `
            -ExpectedInterfaceGuid ([Guid]$ExpectedGuestInterfaceGuid) `
            -ExpectedMtuBytes $ExpectedGuestMtuBytes `
            -ManagedAdapterName $ExpectedManagedAdapterName `
            -MinimumUnderlayIpv4PacketBytes $MinimumPacketBytes `
            -AsJson 2>&1)
        if ($probeRows.Count -ne 1) {
            throw "guest network-path probe returned an invalid result count"
        }
        $path = [string]$probeRows[0] | ConvertFrom-Json -ErrorAction Stop

        [byte[]]$payload = [Text.UTF8Encoding]::new($false).GetBytes(
            "ferrum2-m17-path-$ExpectedRunToken"
        )
        $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $udp.Client.ReceiveTimeout = 5000
            $udp.Client.SendTimeout = 5000
            $udp.Connect($ExpectedSupportIpv4, $ExpectedUdpPort)
            if ($udp.Send($payload, $payload.Length) -ne $payload.Length) {
                throw "guest support UDP path probe send was partial"
            }
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            [byte[]]$udpReply = $udp.Receive([ref]$remote)
            if ($remote.Address.ToString() -cne $ExpectedSupportIpv4 -or
                $remote.Port -ne $ExpectedUdpPort -or
                -not (Test-EqualByteArray -Left $udpReply -Right $payload)) {
                throw "guest support UDP path probe reply is invalid"
            }
        } finally {
            $udp.Dispose()
        }

        $tcp = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $connectTask = $tcp.ConnectAsync($ExpectedSupportIpv4, $ExpectedTcpPort)
            if (-not $connectTask.Wait(5000) -or -not $tcp.Connected) {
                throw "guest support TCP path probe connect timed out"
            }
            $stream = $tcp.GetStream()
            $stream.ReadTimeout = 5000
            $stream.WriteTimeout = 5000
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
            [byte[]]$tcpReply = [byte[]]::new($payload.Length)
            $offset = 0
            while ($offset -lt $tcpReply.Length) {
                $read = $stream.Read($tcpReply, $offset, $tcpReply.Length - $offset)
                if ($read -le 0) {
                    throw "guest support TCP path probe reached EOF"
                }
                $offset += $read
            }
            if (-not (Test-EqualByteArray -Left $tcpReply -Right $payload)) {
                throw "guest support TCP path probe reply is invalid"
            }
        } finally {
            $tcp.Dispose()
        }

        $pathJson = $path | ConvertTo-Json -Compress -Depth 5
        $resultSha256 = $null
        if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
            if (Test-Path -LiteralPath $ResultPath) {
                throw "guest network-path evidence baseline is not absent"
            }
            [IO.File]::WriteAllText(
                $ResultPath,
                $pathJson + "`n",
                [Text.UTF8Encoding]::new($false)
            )
            $resultSha256 = (Get-FileHash -LiteralPath $ResultPath -Algorithm SHA256).
                Hash.ToLowerInvariant()
        }
        [pscustomobject][ordered]@{
            schema = 1
            path = $path
            evidence_sha256 = $resultSha256
            tcp_echo = $true
            udp_echo = $true
        } | ConvertTo-Json -Compress -Depth 6
    })
    if ($rows.Count -ne 1) {
        throw "guest support network-path bootstrap result is not unique"
    }
    $result = [string]$rows[0] | ConvertFrom-Json -Depth 8 -ErrorAction Stop
    if ((@($result.PSObject.Properties.Name) -join "|") -cne
            "schema|path|evidence_sha256|tcp_echo|udp_echo" -or
        [long]$result.schema -ne 1 -or $result.tcp_echo -ne $true -or
        $result.udp_echo -ne $true -or
        (-not [string]::IsNullOrWhiteSpace($OutputPath) -and
            [string]$result.evidence_sha256 -cnotmatch '^[0-9a-f]{64}$') -or
        ([string]::IsNullOrWhiteSpace($OutputPath) -and
            $null -ne $result.evidence_sha256)) {
        throw "guest support network-path bootstrap result is invalid"
    }
    return $result
}

function Assert-ApprovedGuestNetworkPathUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )

    foreach ($field in @(
        "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
        "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
        "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
        "guest_route_next_hop"
    )) {
        if ([string]$Expected.$field -cne [string]$Actual.$field) {
            throw "approved guest network path changed: field=$field"
        }
    }
    if (@($Expected.guest_dns_servers).Count -ne 0 -or
        @($Actual.guest_dns_servers).Count -ne 0) {
        throw "approved guest network path acquired DNS servers"
    }
}
