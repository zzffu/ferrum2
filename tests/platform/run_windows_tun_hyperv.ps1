#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs Windows TUN qualification and deterministic fuzz smoke only inside the approved Hyper-V guest.

.DESCRIPTION
The host side builds the exact clean candidate with Rust 1.97.1 and locked dependencies, including
the standalone Windows TUN fuzz smoke executable, then limits
itself to exact-identity VM lifecycle operations, PowerShell Direct, bounded file staging, and
evidence export. It stages precompiled client/server/test/smoke executables, a portable PowerShell runtime,
Visual C++ runtime libraries, Wintun, and the qualification controller. The guest never requires Git,
Cargo, rustup, or an installed PowerShell 7. The host never changes an adapter, address, route, DNS
setting, firewall rule, WFP object, or TUN session.

ProbeOnly verifies the exact VM and checkpoint identities, loads the external DPAPI-protected
credential, and opens a PowerShell Direct session for a read-only guest identity probe. If the VM is
Off, ProbeOnly starts it temporarily and returns it to Off. ProbeOnly never restores a checkpoint,
stages files, invokes the qualification controller, or changes guest network configuration.

The default credential path is
%LOCALAPPDATA%\Ferrum2\hyperv-ferrum2-test.credential.xml. Create it outside this repository with
Export-Clixml from a PSCredential owned by the current Windows user. Never pass a password to this
script or place one in the repository.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Library", DontShow = $true)]
    [switch]$LibraryOnly,

    [Parameter(ParameterSetName = "Probe", DontShow = $true)]
    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [switch]$InternalWorker,

    [Parameter(ParameterSetName = "Probe", DontShow = $true)]
    [Parameter(ParameterSetName = "Run", DontShow = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalWorkerToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [switch]$ProbeOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateSet(
        "network-reset-10",
        "network-reset-100",
        "network-reset-1000",
        "restart-10",
        "restart-100",
        "restart-1000",
        "fragments",
        "dual-stack-dns",
        "udp-policy",
        "scheduler-ring-full",
        "fuzz-smoke"
    )]
    [string]$Profile,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [string]$CredentialPath,

    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$approvedVmName = ""
$approvedVmId = [Guid]::Empty
$approvedCheckpointName = ""
$approvedCheckpointId = [Guid]::Empty
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path
$minimumSupportIpv4PacketBytes = 1468
$topologyManifestDocument = $null
$topologyRuntimeLoaded = $false
$topologyRuntimeSha256 = ""
$hostNetworkPathHelperSha256 = ""
$guestNetworkPathProbeSha256 = ""
$topologyRuntimePath = Join-Path $repositoryRoot `
    "tools\windows_tun_hyperv_support_topology_runtime.ps1"
$hostNetworkPathHelperPath = Join-Path $repositoryRoot `
    "tools\windows_tun_host_network_path.ps1"
$guestNetworkPathProbePath = Join-Path $repositoryRoot `
    "tools\get_windows_tun_guest_network_path.ps1"
$topologyProvisioningLibraryPath = Join-Path $repositoryRoot `
    "tools\windows_tun_hyperv_support_topology_provisioning.ps1"

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $fullPath.StartsWith(
        $fullRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )
}

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
        if ($RequireOutsideRepository -and (Test-PathWithinRoot -Path $resolved -Root $script:repositoryRoot)) {
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
    if (Test-PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) {
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

# These libraries must be dot-sourced from this script's persistent scope. Dot-sourcing them from
# Import-ApprovedTopologyRuntime would define their functions only in that function's local scope,
# so the commands would disappear as soon as the loader returned.
if (-not $script:topologyRuntimeLoaded) {
    foreach ($source in @(
        [ordered]@{ Path = $script:topologyRuntimePath; Label = "support topology runtime" },
        [ordered]@{ Path = $script:hostNetworkPathHelperPath; Label = "host network-path helper" },
        [ordered]@{ Path = $script:guestNetworkPathProbePath; Label = "guest network-path probe" },
        [ordered]@{ Path = $script:topologyProvisioningLibraryPath; Label = "topology provisioning library" }
    )) {
        $null = Resolve-BoundedFile -Path $source.Path -Label $source.Label `
            -MaximumBytes 4194304
    }
    $runtimeHash = (Get-FileHash -LiteralPath $script:topologyRuntimePath -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $hostHelperHash = (Get-FileHash -LiteralPath $script:hostNetworkPathHelperPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $guestProbeHash = (Get-FileHash -LiteralPath $script:guestNetworkPathProbePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    # The runtime library also has a LibraryOnly parameter. Dot-sourcing is intentionally required
    # to keep its functions in this persistent script scope, so preserve this runner's entry mode.
    $ferrum2RunnerLibraryOnly = $LibraryOnly
    . $script:topologyRuntimePath -LibraryOnly
    $LibraryOnly = $ferrum2RunnerLibraryOnly
    . $script:hostNetworkPathHelperPath
    if ((Get-FileHash -LiteralPath $script:topologyRuntimePath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $runtimeHash -or
        (Get-FileHash -LiteralPath $script:hostNetworkPathHelperPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $hostHelperHash -or
        (Get-FileHash -LiteralPath $script:guestNetworkPathProbePath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $guestProbeHash) {
        throw "support topology runtime source changed while loading"
    }
    $script:topologyRuntimeSha256 = $runtimeHash
    $script:hostNetworkPathHelperSha256 = $hostHelperHash
    $script:guestNetworkPathProbeSha256 = $guestProbeHash
    $script:topologyRuntimeLoaded = $true
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
        if ($ledger.schema -ne 2 -or
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

function Initialize-ApprovedHyperVTopology {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256
    )

    if ($null -ne $script:topologyManifestDocument) {
        throw "support topology manifest was initialized more than once"
    }
    Import-ApprovedTopologyRuntime
    $document = Read-Ferrum2SupportTopologyManifest `
        -Path $ManifestPath -ExpectedSha256 $ExpectedSha256 `
        -RepositoryRoot $script:repositoryRoot
    $script:topologyManifestDocument = $document
    $script:approvedVmName = [string]$document.Value.vm.name
    $script:approvedVmId = [Guid][string]$document.Value.vm.id
    $script:approvedCheckpointName = [string]$document.Value.qualification_checkpoint.name
    $script:approvedCheckpointId = [Guid][string]$document.Value.qualification_checkpoint.id
    $state = Get-ApprovedHyperVTopologyRuntimeState -TopologyDocument $document
    return [pscustomobject][ordered]@{
        Document = $document
        Runtime = $state.Runtime
        VmNetwork = $state.VmNetwork
        TopologyRuntimeSha256 = $script:topologyRuntimeSha256
        HostNetworkPathHelperSha256 = $script:hostNetworkPathHelperSha256
        GuestNetworkPathProbeSha256 = $script:guestNetworkPathProbeSha256
    }
}

function Import-ApprovedGuestCredential {
    param([string]$Path)

    $candidate = $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw "LOCALAPPDATA is required for the default guest credential path"
        }
        $candidate = Join-Path $env:LOCALAPPDATA "Ferrum2\hyperv-ferrum2-test.credential.xml"
    }
    $resolved = Resolve-BoundedFile `
        -Path $candidate `
        -Label "guest credential" `
        -MaximumBytes 1048576 `
        -RequireOutsideRepository
    $credential = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    if ($credential -isnot [Management.Automation.PSCredential] -or
        [string]$credential.UserName -cne "ferrum2-test") {
        throw "guest credential file does not contain the approved local PSCredential"
    }
    return $credential
}

function Get-ApprovedVmContext {
    $document = Get-ApprovedTopologyDocument
    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $document
    $vm = Get-VM -Id $script:approvedVmId -ErrorAction Stop
    if ($vm.Name -cne $script:approvedVmName -or
        $vm.AutomaticCheckpointsEnabled -ne $false) {
        throw "approved VM identity mismatch"
    }
    $namedVm = @(Get-VM -Name $script:approvedVmName -ErrorAction Stop)
    if ($namedVm.Count -ne 1 -or $namedVm[0].Id -ne $script:approvedVmId) {
        throw "approved VM name does not resolve to the approved ID"
    }

    $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $checkpoint = @($checkpoints | Where-Object {
        $_.Id -eq $script:approvedCheckpointId
    })
    $sourceCheckpointId = [Guid][string]$document.Value.source_checkpoint.id
    $sourceCheckpoint = @($checkpoints | Where-Object { $_.Id -eq $sourceCheckpointId })
    if ($checkpoints.Count -ne 2 -or $sourceCheckpoint.Count -ne 1 -or
        $checkpoint.Count -ne 1 -or $checkpoint[0].Name -cne $script:approvedCheckpointName -or
        [Guid][string]$checkpoint[0].ParentCheckpointId -ne $sourceCheckpointId) {
        throw "approved checkpoint identity mismatch"
    }
    $namedCheckpoint = @(Get-VMSnapshot -VM $vm -Name $script:approvedCheckpointName -ErrorAction Stop)
    if ($namedCheckpoint.Count -ne 1 -or $namedCheckpoint[0].Id -ne $script:approvedCheckpointId) {
        throw "approved checkpoint name does not resolve to the approved ID"
    }

    return [pscustomobject]@{
        Vm = $vm
        Checkpoint = $checkpoint[0]
    }
}

function Invoke-BoundedHyperVMutation {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Read", "Start", "Stop", "Restore")]
        [string]$Action,
        [Parameter(Mandatory = $true)][Guid]$VmId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName,
        [Guid]$CheckpointId = [Guid]::Empty,
        [AllowNull()][string]$ExpectedCheckpointName = $null,
        [Guid]$ExpectedCheckpointParentId = [Guid]::Empty,
        [ValidateRange(1, 900)][int]$TimeoutSeconds = 120
    )

    if ($VmId -eq [Guid]::Empty -or
        ($Action -ceq "Restore" -and
            ($CheckpointId -eq [Guid]::Empty -or
                $ExpectedCheckpointParentId -eq [Guid]::Empty -or
                [string]::IsNullOrWhiteSpace($ExpectedCheckpointName) -or
                $ExpectedCheckpointName -cnotmatch
                    '^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')) -or
        ($Action -cne "Restore" -and
            ($CheckpointId -ne [Guid]::Empty -or
                $ExpectedCheckpointParentId -ne [Guid]::Empty -or
                -not [string]::IsNullOrWhiteSpace($ExpectedCheckpointName)))) {
        throw "bounded Hyper-V mutation identity is invalid"
    }
    $childScript = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$mutationGateName = [string]`$env:FERRUM2_HYPERV_MUTATION_GATE
if (`$mutationGateName -cnotmatch
        '^Local\\Ferrum2-HyperV-Mutation-[0-9a-f]{32}$') {
    throw 'bounded Hyper-V mutation gate identity is invalid'
}
`$mutationGate = [Threading.EventWaitHandle]::OpenExisting(`$mutationGateName)
[Environment]::SetEnvironmentVariable(
    'FERRUM2_HYPERV_MUTATION_GATE',
    `$null,
    'Process'
)
try {
    if (-not `$mutationGate.WaitOne(30000)) {
        throw 'bounded Hyper-V mutation start gate timed out'
    }
} finally {
    `$mutationGate.Dispose()
}
Import-Module Hyper-V -ErrorAction Stop
`$vmId = [Guid]'$($VmId.ToString("D"))'
`$expectedVmName = '$ExpectedVmName'
`$rows = @(Get-VM -Id `$vmId -ErrorAction Stop)
if (`$rows.Count -ne 1 -or [Guid]`$rows[0].Id -ne `$vmId) {
    throw 'bounded Hyper-V VM identity is unavailable or ambiguous'
}
`$vm = `$rows[0]
switch ('$Action') {
    'Read' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V read VM name identity changed'
        }
    }
    'Start' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V start VM name identity changed'
        }
        if ([string]`$vm.State -cne 'Off') { throw 'bounded Hyper-V start requires Off' }
        `$vm | Start-VM -ErrorAction Stop | Out-Null
    }
    'Stop' {
        if ([string]`$vm.State -cne 'Off') {
            `$vm | Stop-VM -TurnOff -Force -Confirm:`$false -ErrorAction Stop | Out-Null
        }
    }
    'Restore' {
        if ([string]`$vm.Name -cne `$expectedVmName) {
            throw 'bounded Hyper-V restore VM name identity changed'
        }
        if ([string]`$vm.State -cne 'Off') { throw 'bounded Hyper-V restore requires Off' }
        `$checkpointId = [Guid]'$($CheckpointId.ToString("D"))'
        `$checkpointParentId = [Guid]'$($ExpectedCheckpointParentId.ToString("D"))'
        `$expectedCheckpointName = '$ExpectedCheckpointName'
        `$checkpoint = @(
            Get-VMSnapshot -VM `$vm -ErrorAction Stop |
                Where-Object { [Guid]`$_.Id -eq `$checkpointId }
        )
        if (`$checkpoint.Count -ne 1 -or
            [string]`$checkpoint[0].Name -cne `$expectedCheckpointName -or
            [Guid][string]`$checkpoint[0].ParentCheckpointId -ne `$checkpointParentId) {
            throw 'bounded Hyper-V checkpoint identity is unavailable or ambiguous'
        }
        `$checkpoint[0] | Restore-VMSnapshot -Confirm:`$false -ErrorAction Stop | Out-Null
    }
    default { throw 'bounded Hyper-V action is invalid' }
}
`$expectedState = switch ('$Action') {
    'Start' { 'Running' }
    'Stop' { 'Off' }
    'Restore' { 'Off' }
    default { `$null }
}
`$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    `$stateRows = @(Get-VM -Id `$vmId -ErrorAction Stop)
    if (`$stateRows.Count -ne 1 -or [Guid]`$stateRows[0].Id -ne `$vmId) {
        throw 'bounded Hyper-V final VM identity is unavailable or ambiguous'
    }
    `$state = [string]`$stateRows[0].State
    if (`$null -eq `$expectedState -or `$state -ceq `$expectedState) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt `$deadline)
if (`$null -ne `$expectedState -and `$state -cne `$expectedState) {
    throw "bounded Hyper-V action did not reach expected state `$expectedState"
}
if ([string]`$stateRows[0].Name -cne `$expectedVmName) {
    throw 'bounded Hyper-V final VM name identity changed'
}
[Console]::Out.WriteLine("FERRUM2_BOUNDED_HYPERV_ACTION_PASS action=$Action state=`$state")
"@
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($childScript)
    )
    $gateName = "Local\Ferrum2-HyperV-Mutation-" + [Guid]::NewGuid().ToString("N")
    $gateCreated = $false
    $startGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $gateName,
        [ref]$gateCreated
    )
    if (-not $gateCreated) {
        $startGate.Dispose()
        throw "bounded Hyper-V mutation gate identity already exists"
    }
    $result = $null
    $primaryFailure = $null
    $finalizationIssues = [Collections.Generic.List[string]]::new()
    try {
        $result = Invoke-BoundedPwshFile -Arguments @(
            "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", $encodedCommand
        ) -TimeoutSeconds $TimeoutSeconds -Label "Bounded Hyper-V $Action mutation" `
            -Environment ([ordered]@{ FERRUM2_HYPERV_MUTATION_GATE = $gateName }) `
            -StartGate $startGate
    } catch {
        $primaryFailure = $_
    } finally {
        try {
            $startGate.Dispose()
        } catch {
            $finalizationIssues.Add(
                "bounded Hyper-V $Action mutation gate disposal failed: " +
                    $_.Exception.Message
            )
        }
    }
    if ($null -ne $primaryFailure) {
        if ($finalizationIssues.Count -ne 0) {
            throw (
                "bounded Hyper-V $Action mutation failed: " +
                    "primary=$($primaryFailure.Exception.Message); " +
                    "finalization=$($finalizationIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($finalizationIssues.Count -ne 0) {
        throw (
            "bounded Hyper-V $Action mutation finalization failed: " +
                ($finalizationIssues -join "; ")
        )
    }
    $stdout = [string]$result.Stdout
    $stderr = [string]$result.Stderr
    try {
        $lines = @($stdout -split '\r?\n' | Where-Object { $_.Length -gt 0 })
        $markerPattern = '^FERRUM2_BOUNDED_HYPERV_ACTION_PASS action=' +
            [regex]::Escape($Action) + ' state=(?<state>[A-Za-z]+)$'
        if ($result.ExitCode -ne 0 -or
            $lines.Count -ne 1 -or
            $lines[0] -cnotmatch $markerPattern -or
            -not [string]::IsNullOrWhiteSpace($stderr)) {
            $detail = (($stderr + "`n" + $stdout).Trim() -replace '[\r\n]+', ' | ')
            if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) }
            throw "bounded Hyper-V $Action mutation failed: $detail"
        }
        return [string]$Matches.state
    } catch {
        throw
    }
}

function Start-ApprovedVm {
    param([ValidateRange(1, 900)][int]$TimeoutSeconds = 120)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before start"
    }
    [void](Invoke-BoundedHyperVMutation -Action Start -VmId $script:approvedVmId `
        -ExpectedVmName $script:approvedVmName `
        -TimeoutSeconds $TimeoutSeconds)
    $started = Get-ApprovedVmContext
    if ([string]$started.Vm.State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
}

function Stop-ApprovedVm {
    param([int]$TimeoutSeconds)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        [void](Invoke-BoundedHyperVMutation -Action Stop -VmId $script:approvedVmId `
            -ExpectedVmName $script:approvedVmName `
            -TimeoutSeconds $TimeoutSeconds)
    }
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM did not become Off before the bounded timeout"
    }
}

function Restore-ApprovedCheckpoint {
    param([ValidateRange(1, 900)][int]$TimeoutSeconds = 120)

    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before checkpoint restore"
    }
    [void](Invoke-BoundedHyperVMutation -Action Restore -VmId $script:approvedVmId `
        -ExpectedVmName $script:approvedVmName `
        -CheckpointId $script:approvedCheckpointId `
        -ExpectedCheckpointName $script:approvedCheckpointName `
        -ExpectedCheckpointParentId ([Guid][string]$context.Checkpoint.ParentCheckpointId) `
        -TimeoutSeconds $TimeoutSeconds)
    $restored = Get-ApprovedVmContext
    if ([string]$restored.Vm.State -cne "Off") {
        throw "checkpoint restore did not leave the approved VM Off"
    }
}

function Assert-ApprovedVmCleanupAuthority {
    param([Parameter(Mandatory = $true)][object]$Authority)

    if ($null -eq $script:topologyManifestDocument -or
        $script:approvedVmId -eq [Guid]::Empty -or
        $script:approvedCheckpointId -eq [Guid]::Empty) {
        throw "approved VM cleanup authority cannot be used before topology initialization"
    }
    $approvedParentId = [Guid][string](
        $script:topologyManifestDocument.Value.source_checkpoint.id
    )
    $expected = @(
        "vm_id", "vm_name", "checkpoint_id", "checkpoint_name",
        "checkpoint_parent_id"
    )
    if ((@($Authority.PSObject.Properties.Name) -join "|") -cne
            ($expected -join "|") -or
        $Authority.vm_id -isnot [Guid] -or
        [Guid]$Authority.vm_id -eq [Guid]::Empty -or
        $Authority.checkpoint_id -isnot [Guid] -or
        [Guid]$Authority.checkpoint_id -eq [Guid]::Empty -or
        $Authority.checkpoint_parent_id -isnot [Guid] -or
        [Guid]$Authority.checkpoint_parent_id -eq [Guid]::Empty -or
        $Authority.vm_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Authority.vm_name) -or
        $Authority.checkpoint_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Authority.checkpoint_name) -or
        [Guid]$Authority.vm_id -ne $script:approvedVmId -or
        [string]$Authority.vm_name -cne $script:approvedVmName -or
        [Guid]$Authority.checkpoint_id -ne $script:approvedCheckpointId -or
        [string]$Authority.checkpoint_name -cne $script:approvedCheckpointName -or
        [Guid]$Authority.checkpoint_parent_id -ne $approvedParentId) {
        throw "approved VM cleanup authority is invalid"
    }
}

function New-ApprovedVmCleanupAuthority {
    param([Parameter(Mandatory = $true)][object]$Context)

    $document = Get-ApprovedTopologyDocument
    Assert-Ferrum2SupportTopologyManifestUnchanged -Document $document
    $sourceCheckpointId = [Guid][string]$document.Value.source_checkpoint.id
    $vmId = [Guid]$Context.Vm.Id
    $checkpointId = [Guid]$Context.Checkpoint.Id
    $checkpointParentId = [Guid][string]$Context.Checkpoint.ParentCheckpointId
    if ($vmId -ne $script:approvedVmId -or
        [string]$Context.Vm.Name -cne $script:approvedVmName -or
        [string]$Context.Vm.State -cne "Off" -or
        $Context.Vm.AutomaticCheckpointsEnabled -ne $false -or
        $checkpointId -ne $script:approvedCheckpointId -or
        [string]$Context.Checkpoint.Name -cne $script:approvedCheckpointName -or
        $checkpointParentId -ne $sourceCheckpointId) {
        throw "approved VM cleanup authority baseline is invalid"
    }
    $authority = [pscustomobject][ordered]@{
        vm_id = $vmId
        vm_name = [string]$Context.Vm.Name
        checkpoint_id = $checkpointId
        checkpoint_name = [string]$Context.Checkpoint.Name
        checkpoint_parent_id = $checkpointParentId
    }
    Assert-ApprovedVmCleanupAuthority -Authority $authority
    return $authority
}

function Get-ApprovedVmEmergencyState {
    param([Parameter(Mandatory = $true)][object]$Authority)

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    $state = Invoke-BoundedHyperVMutation -Action Read `
        -VmId ([Guid]$Authority.vm_id) `
        -ExpectedVmName ([string]$Authority.vm_name) `
        -TimeoutSeconds 30
    return [pscustomobject][ordered]@{
        Id = [Guid]$Authority.vm_id
        State = [string]$state
    }
}

function Stop-ApprovedVmEmergency {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [ValidateRange(1, 900)][int]$TimeoutSeconds
    )

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    [void](Invoke-BoundedHyperVMutation -Action Stop `
        -VmId ([Guid]$Authority.vm_id) `
        -ExpectedVmName ([string]$Authority.vm_name) `
        -TimeoutSeconds $TimeoutSeconds)
}

function Restore-ApprovedCheckpointEmergency {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [ValidateRange(1, 900)][int]$ShutdownTimeoutSeconds
    )

    Assert-ApprovedVmCleanupAuthority -Authority $Authority
    try {
        [void](Invoke-BoundedHyperVMutation -Action Restore `
            -VmId ([Guid]$Authority.vm_id) `
            -ExpectedVmName ([string]$Authority.vm_name) `
            -CheckpointId ([Guid]$Authority.checkpoint_id) `
            -ExpectedCheckpointName ([string]$Authority.checkpoint_name) `
            -ExpectedCheckpointParentId ([Guid]$Authority.checkpoint_parent_id) `
            -TimeoutSeconds $ShutdownTimeoutSeconds)
    } catch {
        $restoreFailure = $_
        try {
            Stop-ApprovedVmEmergency -Authority $Authority `
                -TimeoutSeconds $ShutdownTimeoutSeconds
        } catch {
            throw (
                "emergency checkpoint restore failed: $($restoreFailure.Exception.Message); " +
                "post-failure VM stop also failed: $($_.Exception.Message)"
            )
        }
        throw $restoreFailure
    }
}

function New-BoundedPwshFileArguments {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][string[]]$ForwardedParameterNames,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
        [string]$InternalWorkerToken
    )

    $resolvedScript = Resolve-BoundedFile `
        -Path $ScriptPath -Label "bounded PowerShell worker script" -MaximumBytes 4194304
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($argument in @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $resolvedScript)) {
        $arguments.Add($argument)
    }
    foreach ($name in $ForwardedParameterNames) {
        if (-not $BoundParameters.ContainsKey($name)) {
            continue
        }
        $value = $BoundParameters[$name]
        if ($value -is [Management.Automation.SwitchParameter]) {
            if ([Management.Automation.SwitchParameter]$value) {
                $arguments.Add("-$name")
            }
            continue
        }
        if ($null -eq $value) {
            continue
        }
        $arguments.Add("-$name")
        $arguments.Add([Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture))
    }
    $arguments.Add("-InternalWorker")
    $arguments.Add("-InternalWorkerToken")
    $arguments.Add($InternalWorkerToken)
    return @($arguments)
}

function New-Ferrum2KillOnCloseJob {
    if ($null -eq ("Ferrum2.HyperV.KillOnCloseJob" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ferrum2.HyperV
{
    public sealed class KillOnCloseJob : IDisposable
    {
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private IntPtr handle;

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            uint informationClass,
            ref ExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(
            IntPtr process,
            IntPtr job,
            out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            uint informationClass,
            out BasicAccountingInformation information,
            uint informationLength,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public KillOnCloseJob()
        {
            handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
            }
            var information = new ExtendedLimitInformation();
            information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                handle = IntPtr.Zero;
                throw new Win32Exception(error, "SetInformationJobObject failed");
            }
        }

        public void Add(Process process)
        {
            if (handle == IntPtr.Zero || process == null)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            if (!AssignProcessToJobObject(handle, process.Handle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AssignProcessToJobObject failed");
            }
        }

        public bool Contains(Process process)
        {
            if (handle == IntPtr.Zero || process == null)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            bool result;
            if (!IsProcessInJob(process.Handle, handle, out result))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsProcessInJob failed");
            }
            return result;
        }

        public uint ActiveProcessCount
        {
            get
            {
                if (handle == IntPtr.Zero)
                {
                    throw new ObjectDisposedException(nameof(KillOnCloseJob));
                }
                BasicAccountingInformation information;
                if (!QueryInformationJobObject(
                        handle,
                        1,
                        out information,
                        (uint)Marshal.SizeOf<BasicAccountingInformation>(),
                        IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "QueryInformationJobObject failed");
                }
                return information.ActiveProcesses;
            }
        }

        public bool WaitForEmpty(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
            }
            var stopwatch = Stopwatch.StartNew();
            do
            {
                if (ActiveProcessCount == 0)
                {
                    return true;
                }
                Thread.Sleep(10);
            }
            while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds);
            return ActiveProcessCount == 0;
        }

        public void Terminate(uint exitCode)
        {
            if (handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            if (!TerminateJobObject(handle, exitCode))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed");
            }
        }

        public void Dispose()
        {
            IntPtr owned = handle;
            handle = IntPtr.Zero;
            if (owned != IntPtr.Zero && !CloseHandle(owned))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed");
            }
            GC.SuppressFinalize(this);
        }

        ~KillOnCloseJob()
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }
    }
}
'@
    }
    return [Ferrum2.HyperV.KillOnCloseJob]::new()
}

function Invoke-BoundedPwshFile {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][ValidateRange(1, 21600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9 -]{1,64}$')]
        [string]$Label,
        [Collections.IDictionary]$Environment = @{},
        [AllowNull()][Threading.EventWaitHandle]$StartGate = $null
    )

    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    $powerShellPath = [IO.Path]::GetFullPath([string]$currentProcess.Path)
    if ([IO.Path]::GetFileName($powerShellPath) -ine "pwsh.exe" -or
        -not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
        throw "$Label requires the current pwsh.exe"
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $powerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    foreach ($key in @($Environment.Keys)) {
        $name = [string]$key
        $value = [string]$Environment[$key]
        if ($name -cnotmatch '^FERRUM2_[A-Z0-9_]{1,63}$' -or
            $value.Length -gt 256 -or $value.IndexOf([char]0) -ge 0) {
            throw "$Label child environment is invalid"
        }
        $startInfo.Environment[$name] = $value
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = New-Ferrum2KillOnCloseJob
    $started = $false
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutBytes = [IO.MemoryStream]::new()
    $stderrBytes = [IO.MemoryStream]::new()
    $boundedResult = $null
    $primaryFailure = $null
    $finalizationIssues = [Collections.Generic.List[string]]::new()
    try {
        if (-not $process.Start()) {
            throw "$Label did not start"
        }
        $started = $true
        try {
            $job.Add($process)
            if (-not $job.Contains($process)) {
                throw "$Label job membership readback failed"
            }
            if ($null -ne $StartGate -and -not $StartGate.Set()) {
                throw "$Label worker start gate could not be released"
            }
        } catch {
            try { $process.Kill($true) } catch { }
            [void]$process.WaitForExit(30000)
            throw "$Label could not enter the kill-on-close job: $($_.Exception.Message)"
        }
        $stdoutStream = $process.StandardOutput.BaseStream
        $stderrStream = $process.StandardError.BaseStream
        [byte[]]$stdoutBuffer = [byte[]]::new(8192)
        [byte[]]$stderrBuffer = [byte[]]::new(8192)
        $stdoutTask = $stdoutStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderrTask = $stderrStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        $stdoutEof = $false
        $stderrEof = $false
        $streamFailure = $null
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $timeoutMilliseconds = [long]$TimeoutSeconds * 1000
        while ($stopwatch.ElapsedMilliseconds -lt $timeoutMilliseconds) {
            $madeProgress = $false
            if (-not $stdoutEof -and $stdoutTask.IsCompleted) {
                $madeProgress = $true
                try {
                    $count = [int]$stdoutTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stdoutEof = $true
                    } elseif ($stdoutBytes.Length + $count -gt 16777216) {
                        $streamFailure = "$Label stdout exceeded the 16 MiB boundary"
                    } else {
                        $stdoutBytes.Write($stdoutBuffer, 0, $count)
                        $stdoutTask = $stdoutStream.ReadAsync(
                            $stdoutBuffer,
                            0,
                            $stdoutBuffer.Length
                        )
                    }
                } catch {
                    $streamFailure = "$Label stdout read failed: $($_.Exception.Message)"
                }
            }
            if (-not $stderrEof -and $stderrTask.IsCompleted) {
                $madeProgress = $true
                try {
                    $count = [int]$stderrTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stderrEof = $true
                    } elseif ($stderrBytes.Length + $count -gt 16777216) {
                        $streamFailure = "$Label stderr exceeded the 16 MiB boundary"
                    } else {
                        $stderrBytes.Write($stderrBuffer, 0, $count)
                        $stderrTask = $stderrStream.ReadAsync(
                            $stderrBuffer,
                            0,
                            $stderrBuffer.Length
                        )
                    }
                } catch {
                    $streamFailure = "$Label stderr read failed: $($_.Exception.Message)"
                }
            }
            if ($null -ne $streamFailure -or
                ($process.HasExited -and $stdoutEof -and $stderrEof)) {
                break
            }
            if (-not $madeProgress) {
                Start-Sleep -Milliseconds 1
            }
        }
        $timedOut = $null -eq $streamFailure -and
            -not ($process.HasExited -and $stdoutEof -and $stderrEof)
        if ($null -ne $streamFailure -or $timedOut) {
            $terminationTrigger = if ($null -ne $streamFailure) {
                [string]$streamFailure
            } else {
                "$Label timed out after $TimeoutSeconds seconds"
            }
            $terminationIssues = [Collections.Generic.List[string]]::new()
            $jobHasActiveProcess = $true
            try {
                $jobHasActiveProcess = $job.ActiveProcessCount -ne 0
            } catch {
                $terminationIssues.Add(
                    "job accounting readback failed: $($_.Exception.Message)"
                )
            }
            if (-not $process.HasExited -or $jobHasActiveProcess) {
                try { $job.Terminate(57005) } catch {
                    $terminationIssues.Add("job termination failed: $($_.Exception.Message)")
                }
                if (-not $process.WaitForExit(30000)) {
                    try { $process.Kill($true) } catch {
                        $terminationIssues.Add("fallback tree kill failed: $($_.Exception.Message)")
                    }
                    if (-not $process.WaitForExit(10000)) {
                        $terminationIssues.Add("worker exit was not confirmed")
                    }
                }
            }
            foreach ($stream in @($stdoutStream, $stderrStream)) {
                try { $stream.Close() } catch {
                    $terminationIssues.Add("worker output close failed: $($_.Exception.Message)")
                }
            }
            if ($terminationIssues.Count -ne 0) {
                throw (
                    "$terminationTrigger; termination was not proven: " +
                    ($terminationIssues -join "; ")
                )
            }
            try {
                if (-not $job.WaitForEmpty(10000)) {
                    throw "termination left an active job process"
                }
            } catch {
                throw (
                    "$terminationTrigger; termination proof failed: " +
                        $_.Exception.Message
                )
            }
            throw "$terminationTrigger and was terminated"
        }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $stdout = $utf8.GetString($stdoutBytes.ToArray())
        # Native Windows and Hyper-V failures can contribute localized system-code-page bytes to
        # stderr. It is diagnostic-only and any non-empty value still fails the worker contract;
        # preserve strict UTF-8 for the accepted stdout terminal while retaining readable errors.
        $stderr = [Text.UTF8Encoding]::new($false, $false).GetString(
            $stderrBytes.ToArray()
        )
        if (-not $job.WaitForEmpty(5000)) {
            $job.Terminate(57005)
            if (-not $job.WaitForEmpty(10000)) {
                throw "$Label completed with an unreaped job process"
            }
            throw "$Label completed while a descendant process remained active"
        }
        $boundedResult = [pscustomobject][ordered]@{
            ExitCode = [int]$process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    } catch {
        $primaryFailure = $_
    } finally {
        try {
            $cancellationRequired = $false
            if ($started) {
                try {
                    $cancellationRequired = -not $process.HasExited
                } catch {
                    $cancellationRequired = $true
                    $finalizationIssues.Add(
                        "$Label cancellation process readback failed: " +
                            $_.Exception.Message
                    )
                }
            }
            if ($started -and -not $cancellationRequired) {
                try {
                    $cancellationRequired = $job.ActiveProcessCount -ne 0
                } catch {
                    $cancellationRequired = $true
                    $finalizationIssues.Add(
                        "$Label cancellation job accounting failed: " +
                            $_.Exception.Message
                    )
                }
            }
            if ($cancellationRequired) {
                try { $job.Terminate(57005) } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation job termination failed: " +
                            $_.Exception.Message
                    )
                }
                try {
                    if (-not $process.WaitForExit(30000)) {
                        $finalizationIssues.Add(
                            "$Label cancellation exit was not confirmed"
                        )
                    }
                } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation exit readback failed: " +
                            $_.Exception.Message
                    )
                }
                try {
                    if (-not $job.WaitForEmpty(10000)) {
                        $finalizationIssues.Add(
                            "$Label cancellation left an active job process"
                        )
                    }
                } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation job readback failed: " +
                            $_.Exception.Message
                    )
                }
            }
        } catch {
            $finalizationIssues.Add(
                "$Label cancellation finalization failed: $($_.Exception.Message)"
            )
        }
        foreach ($stream in @($stdoutStream, $stderrStream)) {
            if ($null -ne $stream) {
                try {
                    $stream.Dispose()
                } catch {
                    $finalizationIssues.Add(
                        "$Label worker output disposal failed: " +
                            $_.Exception.Message
                    )
                }
            }
        }
        foreach ($buffer in @($stdoutBytes, $stderrBytes)) {
            try {
                $buffer.Dispose()
            } catch {
                $finalizationIssues.Add(
                    "$Label worker buffer disposal failed: " +
                        $_.Exception.Message
                )
            }
        }
        try {
            $job.Dispose()
        } catch {
            $finalizationIssues.Add(
                "$Label worker job disposal failed: $($_.Exception.Message)"
            )
        }
        try {
            $process.Dispose()
        } catch {
            $finalizationIssues.Add(
                "$Label worker process disposal failed: $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $primaryFailure) {
        if ($finalizationIssues.Count -ne 0) {
            throw (
                "$Label failed: primary=$($primaryFailure.Exception.Message); " +
                    "finalization=$($finalizationIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($finalizationIssues.Count -ne 0) {
        throw "$Label finalization failed: $($finalizationIssues -join '; ')"
    }
    return $boundedResult
}

function Invoke-ApprovedVmWorkerEmergencyCleanup {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][ValidateRange(30, 900)]
        [int]$ShutdownTimeoutSeconds,
        [Parameter(Mandatory = $true)]
        [ValidateSet("StopOnly", "RestoreCheckpoint")]
        [string]$Mode
    )

    $issues = [Collections.Generic.List[string]]::new()
    $stopped = $false
    $restored = $false
    try {
        Stop-ApprovedVmEmergency -Authority $Authority `
            -TimeoutSeconds $ShutdownTimeoutSeconds
        $stopped = $true
    } catch {
        $issues.Add("initial exact-GUID stop failed: $($_.Exception.Message)")
    }
    if ($stopped -and $Mode -ceq "RestoreCheckpoint") {
        try {
            Restore-ApprovedCheckpointEmergency -Authority $Authority `
                -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds
            $restored = $true
        } catch {
            $issues.Add("exact-checkpoint restore failed: $($_.Exception.Message)")
        }
    } elseif ($Mode -ceq "RestoreCheckpoint") {
        $issues.Add("exact-checkpoint restore was skipped because Off was not proven")
    } else {
        $restored = $true
    }
    try {
        Stop-ApprovedVmEmergency -Authority $Authority `
            -TimeoutSeconds $ShutdownTimeoutSeconds
    } catch {
        $issues.Add("post-restore exact-GUID stop failed: $($_.Exception.Message)")
    }
    try {
        $finalState = [string](Get-ApprovedVmEmergencyState -Authority $Authority).State
        if ($finalState -cne "Off") {
            $issues.Add("final exact-GUID state is $finalState")
        }
    } catch {
        $issues.Add("final exact-GUID readback failed: $($_.Exception.Message)")
    }
    if (-not $restored) {
        $issues.Add("the approved checkpoint restore was not proven")
    }
    if ($issues.Count -ne 0) {
        throw "bounded worker emergency cleanup failed: $($issues -join '; ')"
    }
}

function Get-BoundedWorkerManifestFields([string]$Schema) {
    switch ($Schema) {
        "ferrum2.windows-tun.hyperv-host-run.v4" {
            return @(
                "schema", "status", "profile", "mode", "restart_cycles",
                "network_reset_cycles", "run_token", "vm_name", "vm_id",
                "checkpoint_name", "checkpoint_id", "candidate_sha",
                "identity_sha256", "staged_input_sha256",
                "topology_manifest_sha256", "topology_plan_sha256", "topology",
                "guest_network_path_sha256", "guest_network_path",
                "host_network_path_sha256", "support_listener",
                "protected_host_tun", "topology_runtime_sha256",
                "host_network_path_helper_sha256",
                "guest_network_path_probe_sha256", "rust_version",
                "fuzz_smoke_sha256", "fuzz_smoke_bytes", "guest_execution",
                "guest_build", "checkpoint_restored",
                "support_listener_unchanged", "host_tun_unchanged",
                "host_network_mutations", "started_utc", "finished_utc",
                "final_vm_state", "evidence_files"
            )
        }
        "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2" {
            return @(
                "schema", "status", "mode", "run_token", "vm_name", "vm_id",
                "checkpoint_name", "checkpoint_id", "topology", "support_listener",
                "candidate_sha", "identity_sha256", "controller_sha256",
                "guest_wrapper_sha256", "topology_runtime_sha256",
                "host_network_path_helper_sha256",
                "guest_network_path_probe_sha256", "staged_input_sha256",
                "rust_version", "guest_execution", "guest_build",
                "checkpoint_restored", "host_tun_unchanged",
                "host_support_unchanged", "host_network_mutations",
                "started_utc", "finished_utc", "final_vm_state",
                "evidence_files"
            )
        }
        default { throw "bounded worker manifest schema is invalid" }
    }
}

function Test-BoundedWorkerClosedProperties {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    return $null -ne $Value -and
        (@($Value.PSObject.Properties.Name) -join "|") -ceq ($Expected -join "|")
}

function Test-BoundedWorkerJsonInteger([AllowNull()][object]$Value) {
    return $Value -is [int] -or $Value -is [long]
}

function Test-BoundedWorkerCanonicalUtc([AllowNull()][object]$Value) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).Kind -eq [DateTimeKind]::Utc
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero
    }
    if ($Value -isnot [string]) { return $false }
    [DateTime]$parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact(
            [string]$Value,
            "o",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed
        )) {
        return $false
    }
    return $parsed.Kind -eq [DateTimeKind]::Utc -and
        $parsed.ToUniversalTime().ToString("o") -ceq [string]$Value
}

function Test-BoundedWorkerCanonicalListenerUtc([AllowNull()][object]$Value) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).Kind -eq [DateTimeKind]::Utc
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).Offset -eq [TimeSpan]::Zero
    }
    if ($Value -isnot [string]) { return $false }
    [DateTime]$parsed = [DateTime]::MinValue
    $format = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
    if (-not [DateTime]::TryParseExact(
            [string]$Value,
            $format,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed
        )) {
        return $false
    }
    return $parsed.Kind -eq [DateTimeKind]::Utc -and
        $parsed.ToString($format, [Globalization.CultureInfo]::InvariantCulture) -ceq
            [string]$Value
}

function Test-BoundedWorkerJsonHasUniqueProperties([object]$Element) {
    switch ([Text.Json.JsonValueKind]$Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add([string]$property.Name) -or
                    -not (Test-BoundedWorkerJsonHasUniqueProperties $property.Value)) {
                    return $false
                }
            }
        }
        ([Text.Json.JsonValueKind]::Array) {
            foreach ($item in $Element.EnumerateArray()) {
                if (-not (Test-BoundedWorkerJsonHasUniqueProperties $item)) {
                    return $false
                }
            }
        }
    }
    return $true
}

function Test-BoundedWorkerFailureEvidence([AllowNull()][object]$Rows) {
    if ($Rows -isnot [object[]]) { return $false }
    $paths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($row in @($Rows)) {
        if (-not (Test-BoundedWorkerClosedProperties -Value $row `
                -Expected @("path", "bytes", "sha256")) -or
            $row.path -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$row.path) -or
            [IO.Path]::IsPathFullyQualified([string]$row.path) -or
            [string]$row.path -match '(^|[\\/])\.\.([\\/]|$)' -or
            -not (Test-BoundedWorkerJsonInteger $row.bytes) -or
            [long]$row.bytes -lt 0 -or
            $row.sha256 -isnot [string] -or
            [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not $paths.Add([string]$row.path)) {
            return $false
        }
    }
    return $true
}

function Test-BoundedWorkerFailureTopology([AllowNull()][object]$Value) {
    $fields = @(
        "manifest_sha256", "plan_sha256", "support_switch_id", "support_host_ipv4",
        "support_network", "support_prefix_length", "guest_interface_alias",
        "guest_interface_guid", "guest_interface_index", "guest_mac_address", "guest_ipv4",
        "guest_mtu_bytes", "protected_host_tun_name", "protected_host_tun_guid",
        "protected_host_tun_index", "protected_host_tun_status"
    )
    if (-not (Test-BoundedWorkerClosedProperties -Value $Value -Expected $fields)) {
        return $false
    }
    foreach ($name in @("manifest_sha256", "plan_sha256")) {
        if ($Value.$name -isnot [string] -or
            [string]$Value.$name -cnotmatch '^[0-9a-f]{64}$') {
            return $false
        }
    }
    foreach ($name in @(
        "support_switch_id", "support_host_ipv4", "support_network",
        "guest_interface_alias", "guest_interface_guid", "guest_mac_address", "guest_ipv4",
        "protected_host_tun_name", "protected_host_tun_guid", "protected_host_tun_status"
    )) {
        if ($Value.$name -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Value.$name)) {
            return $false
        }
    }
    foreach ($name in @(
        "support_prefix_length", "guest_interface_index", "guest_mtu_bytes",
        "protected_host_tun_index"
    )) {
        if (-not (Test-BoundedWorkerJsonInteger $Value.$name) -or
            [long]$Value.$name -le 0) {
            return $false
        }
    }
    return $true
}

function Test-BoundedWorkerFailureListener([AllowNull()][object]$Value) {
    if (-not (Test-BoundedWorkerClosedProperties -Value $Value -Expected @(
            "ipv4", "tcp_port", "udp_port", "pid", "owner", "executable_sha256",
            "creation_utc"
        )) -or
        $Value.ipv4 -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Value.ipv4) -or
        $Value.owner -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Value.owner) -or
        $Value.executable_sha256 -isnot [string] -or
        [string]$Value.executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-BoundedWorkerCanonicalListenerUtc $Value.creation_utc)) {
        return $false
    }
    foreach ($name in @("tcp_port", "udp_port", "pid")) {
        if (-not (Test-BoundedWorkerJsonInteger $Value.$name) -or
            [long]$Value.$name -le 0) {
            return $false
        }
    }
    return [long]$Value.tcp_port -le 65535 -and
        [long]$Value.udp_port -le 65535 -and
        [long]$Value.pid -le [int]::MaxValue
}

function Test-BoundedWorkerManifestMinimum {
    param(
        [Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][string]$RawJson,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][ValidateSet("pass", "fail")]
        [string]$ExpectedStatus,
        [Parameter(Mandatory = $true)][string]$ExpectedRunToken,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)][string]$ExpectedVmName,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )

    $expectedFields = @(Get-BoundedWorkerManifestFields -Schema $ExpectedSchema)
    if (-not (Test-BoundedWorkerClosedProperties -Value $Document `
            -Expected $expectedFields)) {
        return $false
    }
    $rawDocument = $null
    try {
        $rawDocument = [Text.Json.JsonDocument]::Parse(
            $RawJson,
            [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 12
            }
        )
        $root = $rawDocument.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
            -not (Test-BoundedWorkerJsonHasUniqueProperties $root)) {
            return $false
        }
        $startedElement = $root.GetProperty("started_utc")
        $finishedElement = $root.GetProperty("finished_utc")
        $listenerElement = $root.GetProperty("support_listener").
            GetProperty("creation_utc")
        if ($startedElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            $finishedElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            $listenerElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or
            -not (Test-BoundedWorkerCanonicalUtc $startedElement.GetString()) -or
            -not (Test-BoundedWorkerCanonicalUtc $finishedElement.GetString()) -or
            -not (Test-BoundedWorkerCanonicalListenerUtc $listenerElement.GetString())) {
            return $false
        }
    } catch {
        return $false
    } finally {
        if ($null -ne $rawDocument) { $rawDocument.Dispose() }
    }
    try { $documentVmId = [Guid][string]$Document.vm_id } catch { return $false }
    try { $checkpointId = [Guid][string]$Document.checkpoint_id } catch { return $false }
    if ([string]$Document.schema -cne $ExpectedSchema -or
        [string]$Document.status -cne $ExpectedStatus -or
        $Document.run_token -isnot [string] -or
        [string]$Document.run_token -cne $ExpectedRunToken -or
        $documentVmId -ne $ExpectedVmId -or
        $checkpointId -eq [Guid]::Empty -or
        $Document.vm_name -isnot [string] -or
        [string]$Document.vm_name -cne $ExpectedVmName -or
        $Document.checkpoint_name -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Document.checkpoint_name) -or
        $Document.candidate_sha -isnot [string] -or
        [string]$Document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        $Document.identity_sha256 -isnot [string] -or
        [string]$Document.identity_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Document.checkpoint_restored -isnot [bool] -or
        $Document.host_tun_unchanged -isnot [bool] -or
        -not (Test-BoundedWorkerJsonInteger $Document.host_network_mutations) -or
        [long]$Document.host_network_mutations -ne 0 -or
        -not (Test-BoundedWorkerCanonicalUtc $Document.started_utc) -or
        -not (Test-BoundedWorkerCanonicalUtc $Document.finished_utc) -or
        -not (Test-BoundedWorkerFailureEvidence $Document.evidence_files)) {
        return $false
    }
    try {
        $recordedEvidence = ConvertTo-Json `
            -InputObject @($Document.evidence_files) -Compress -Depth 5
        $actualEvidence = ConvertTo-Json `
            -InputObject @(Get-EvidenceHashes -EvidenceRoot $EvidenceRoot) `
            -Compress -Depth 5
    } catch {
        return $false
    }
    if ($recordedEvidence -cne $actualEvidence) { return $false }
    if ($null -ne $Document.final_vm_state -and
        ($Document.final_vm_state -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.final_vm_state))) {
        return $false
    }
    if (-not (Test-BoundedWorkerFailureTopology $Document.topology) -or
        -not (Test-BoundedWorkerFailureListener $Document.support_listener)) {
        return $false
    }

    $requiredShaFields = @(
        "topology_runtime_sha256", "host_network_path_helper_sha256",
        "guest_network_path_probe_sha256"
    )
    if ($ExpectedSchema -ceq "ferrum2.windows-tun.hyperv-host-run.v4") {
        $requiredShaFields += @("topology_manifest_sha256", "topology_plan_sha256")
        if ($Document.profile -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.profile) -or
            $Document.mode -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.mode) -or
            $Document.support_listener_unchanged -isnot [bool] -or
            $Document.guest_execution -cne "host-built-precompiled-artifacts-only") {
            return $false
        }
        foreach ($name in @(
            "staged_input_sha256", "guest_network_path_sha256",
            "host_network_path_sha256", "fuzz_smoke_sha256"
        )) {
            if ($null -ne $Document.$name -and
                ($Document.$name -isnot [string] -or
                    [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$')) {
                return $false
            }
        }
        foreach ($name in @("restart_cycles", "network_reset_cycles", "fuzz_smoke_bytes")) {
            if ($null -ne $Document.$name -and
                -not (Test-BoundedWorkerJsonInteger $Document.$name)) {
                return $false
            }
        }
        foreach ($name in @("rust_version", "guest_build")) {
            if ($null -ne $Document.$name -and $Document.$name -isnot [string]) {
                return $false
            }
        }
        if ($null -ne $Document.protected_host_tun -and
            -not (Test-BoundedWorkerClosedProperties `
                -Value $Document.protected_host_tun `
                -Expected @("present", "name", "interface_guid", "interface_index", "status"))) {
            return $false
        }
        if ($ExpectedStatus -ceq "pass" -and
            ($Document.staged_input_sha256 -isnot [string] -or
                [string]$Document.staged_input_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.guest_network_path_sha256 -isnot [string] -or
                [string]$Document.guest_network_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $null -eq $Document.guest_network_path -or
                $Document.host_network_path_sha256 -isnot [string] -or
                [string]$Document.host_network_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.fuzz_smoke_sha256 -isnot [string] -or
                [string]$Document.fuzz_smoke_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                -not (Test-BoundedWorkerJsonInteger $Document.fuzz_smoke_bytes) -or
                [long]$Document.fuzz_smoke_bytes -le 0 -or
                $Document.rust_version -isnot [string] -or
                [string]$Document.rust_version -cnotmatch '^rustc 1\.97\.1 \(' -or
                $Document.guest_build -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$Document.guest_build) -or
                $null -eq $Document.protected_host_tun)) {
            return $false
        }
    } else {
        $requiredShaFields += "controller_sha256"
        if ($Document.mode -cne "hard-kill" -or
            $Document.guest_execution -cne "host-built-precompiled-artifacts-only" -or
            $Document.guest_build -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Document.guest_build) -or
            $Document.host_support_unchanged -isnot [bool]) {
            return $false
        }
        foreach ($name in @("guest_wrapper_sha256", "staged_input_sha256")) {
            if ($null -ne $Document.$name -and
                ($Document.$name -isnot [string] -or
                    [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$')) {
                return $false
            }
        }
        if ($null -ne $Document.rust_version -and
            $Document.rust_version -isnot [string]) {
            return $false
        }
        if ($ExpectedStatus -ceq "pass" -and
            ($Document.guest_wrapper_sha256 -isnot [string] -or
                [string]$Document.guest_wrapper_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.staged_input_sha256 -isnot [string] -or
                [string]$Document.staged_input_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $Document.rust_version -isnot [string] -or
                [string]$Document.rust_version -cnotmatch '^rustc 1\.97\.1 \(')) {
            return $false
        }
    }
    foreach ($name in $requiredShaFields) {
        if ($Document.$name -isnot [string] -or
            [string]$Document.$name -cnotmatch '^[0-9a-f]{64}$') {
            return $false
        }
    }
    if ($ExpectedStatus -ceq "pass") {
        $criticalEvidence = @(
            [ordered]@{ path = "identity-ledger.json"; sha256 = [string]$Document.identity_sha256 },
            [ordered]@{ path = "staged-input.json"; sha256 = [string]$Document.staged_input_sha256 },
            [ordered]@{ path = "topology-manifest.json"; sha256 = [string]$Document.topology.manifest_sha256 },
            [ordered]@{ path = "guest/export/identity-ledger.json"; sha256 = [string]$Document.identity_sha256 }
        )
        foreach ($critical in $criticalEvidence) {
            $matches = @($Document.evidence_files | Where-Object {
                [string]$_.path -ceq [string]$critical.path
            })
            if ($matches.Count -ne 1 -or
                [string]$matches[0].sha256 -cne [string]$critical.sha256) {
                return $false
            }
        }
    }
    return $true
}

function Assert-BoundedWorkerPassManifestAndTerminal {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$Terminal,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Qualification", "HardKill")]
        [string]$WorkerContract,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)][string]$ExpectedVmName
    )

    $fullPath = [IO.Path]::GetFullPath($ManifestPath)
    if (-not [IO.Path]::IsPathFullyQualified($ManifestPath) -or
        (Test-PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) -or
        [IO.Path]::GetFileName($fullPath) -cne "host-orchestration.json") {
        throw "bounded worker PASS manifest path is invalid"
    }
    Assert-NoReparsePointInExistingPath `
        -Path $fullPath -Label "bounded worker PASS manifest"
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 2 -or $item.Length -gt 4194304) {
        throw "bounded worker PASS manifest boundary is invalid"
    }
    $manifestText = Get-Content -LiteralPath $item.FullName -Raw -Encoding utf8
    $document = $manifestText | ConvertFrom-Json -Depth 10 -ErrorAction Stop
    $schema = if ($WorkerContract -ceq "Qualification") {
        "ferrum2.windows-tun.hyperv-host-run.v4"
    } else {
        "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2"
    }
    $runToken = [string]$BoundParameters["RunToken"]
    $evidenceRoot = [IO.Path]::GetFullPath((Split-Path -Parent $fullPath))
    if (-not (Test-BoundedWorkerManifestMinimum `
            -Document $document -RawJson $manifestText `
            -ExpectedSchema $schema -ExpectedStatus "pass" `
            -ExpectedRunToken $runToken -ExpectedVmId $ExpectedVmId `
            -ExpectedVmName $ExpectedVmName -EvidenceRoot $evidenceRoot) -or
        [string]$document.final_vm_state -cne "Off" -or
        $document.checkpoint_restored -ne $true -or
        $document.host_tun_unchanged -ne $true) {
        throw "bounded worker PASS manifest contract is invalid"
    }
    $expectedTerminal = if ($WorkerContract -ceq "Qualification") {
        $profile = [string]$BoundParameters["Profile"]
        if ([string]$document.profile -cne $profile -or
            $document.support_listener_unchanged -ne $true) {
            throw "bounded qualification PASS manifest profile is invalid"
        }
        "hyperv_windows_tun status=PASS profile=$profile run_token=$runToken " +
            "candidate_sha=$($document.candidate_sha) evidence=$evidenceRoot " +
            "final_vm_state=Off"
    } else {
        if ([string]$document.mode -cne "hard-kill" -or
            $document.host_support_unchanged -ne $true) {
            throw "bounded hard-kill PASS manifest mode is invalid"
        }
        "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill " +
            "run_token=$runToken candidate_sha=$($document.candidate_sha) " +
            "evidence=$evidenceRoot final_vm_state=Off"
    }
    if ($Terminal -cne $expectedTerminal) {
        throw "bounded worker terminal does not match its PASS manifest"
    }
}

function Invoke-BoundedHyperVWorkerSupervisor {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory = $true)][string[]]$ForwardedParameterNames,
        [Parameter(Mandatory = $true)][ValidateRange(30, 21600)]
        [int]$WorkerTimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(30, 900)]
        [int]$ShutdownTimeoutSeconds,
        [Parameter(Mandatory = $true)][Guid]$ExpectedVmId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$')]
        [string]$ExpectedVmName,
        [Parameter(Mandatory = $true)][ValidateSet("Off", "Running")]
        [string]$ExpectedFinalState,
        [AllowNull()][object]$CleanupAuthority,
        [Parameter(Mandatory = $true)]
        [ValidateSet("StopOnly", "RestoreCheckpoint")]
        [string]$CleanupMode,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Probe", "Qualification", "HardKill")]
        [string]$WorkerContract,
        [AllowNull()][string]$FailureManifestPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9 -]{1,64}$')]
        [string]$Label
    )

    if ($ExpectedVmId -eq [Guid]::Empty -or
        ($ExpectedFinalState -ceq "Off" -and $null -eq $CleanupAuthority)) {
        throw "$Label supervisor identity or cleanup authority is invalid"
    }
    if ($null -ne $CleanupAuthority) {
        Assert-ApprovedVmCleanupAuthority -Authority $CleanupAuthority
        if ([Guid]$CleanupAuthority.vm_id -ne $ExpectedVmId -or
            [string]$CleanupAuthority.vm_name -cne $ExpectedVmName) {
            throw "$Label supervisor cleanup authority VM is invalid"
        }
    }

    $workerToken = [Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")
    $supervisorProcess = Get-Process -Id $PID -ErrorAction Stop
    $arguments = @(New-BoundedPwshFileArguments `
        -ScriptPath $ScriptPath `
        -BoundParameters $BoundParameters `
        -ForwardedParameterNames $ForwardedParameterNames `
        -InternalWorkerToken $workerToken)
    $workerEnvironment = [ordered]@{
        FERRUM2_HYPERV_WORKER_TOKEN = $workerToken
        FERRUM2_HYPERV_SUPERVISOR_PID = [string]$PID
        FERRUM2_HYPERV_SUPERVISOR_START_TICKS = [string](
            $supervisorProcess.StartTime.ToUniversalTime().Ticks
        )
    }
    $workerGateName = "Local\Ferrum2-HyperV-Worker-" +
        [Guid]::NewGuid().ToString("N")
    $workerGateCreated = $false
    $workerStartGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $workerGateName,
        [ref]$workerGateCreated
    )
    if (-not $workerGateCreated) {
        $workerStartGate.Dispose()
        throw "$Label worker start gate identity already exists"
    }
    $workerEnvironment.FERRUM2_HYPERV_WORKER_GATE = $workerGateName
    $workerAccepted = $false
    $primaryFailure = $null
    $recoveryIssues = [Collections.Generic.List[string]]::new()
    try {
        try {
            $result = Invoke-BoundedPwshFile `
                -Arguments $arguments `
                -TimeoutSeconds $WorkerTimeoutSeconds `
                -Label $Label `
                -Environment $workerEnvironment `
                -StartGate $workerStartGate
            $combinedOutput = (($result.Stderr + "`n" + $result.Stdout).Trim() `
                -replace '[\r\n]+', ' | ')
            if ($combinedOutput.Length -gt 2048) {
                $combinedOutput = $combinedOutput.Substring(0, 2048)
            }
            if ($result.ExitCode -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($result.Stderr) -or
                [string]::IsNullOrWhiteSpace($result.Stdout)) {
                throw "$Label failed with exit code $($result.ExitCode): $combinedOutput"
            }
            $workerLines = @($result.Stdout -split '\r?\n' |
                Where-Object { $_.Length -gt 0 })
            if ($workerLines.Count -ne 1) {
                throw "$Label returned an invalid terminal record count"
            }
            switch ($WorkerContract) {
                "Probe" {
                    $probe = $workerLines[0] |
                        ConvertFrom-Json -Depth 8 -ErrorAction Stop
                    if ($probe.schema -cne "ferrum2.windows-tun.hyperv-probe.v2" -or
                        $probe.status -cne "pass" -or
                        [Guid][string]$probe.vm_id -ne $ExpectedVmId -or
                        [string]$probe.initial_vm_state -cne
                            $ExpectedFinalState.ToLowerInvariant() -or
                        [string]$probe.final_vm_state -cne $ExpectedFinalState -or
                        $probe.checkpoint_restored -ne $false -or
                        [long]$probe.host_network_mutations -ne 0) {
                        throw "$Label probe terminal contract is invalid"
                    }
                }
                "Qualification" {
                    Assert-BoundedWorkerPassManifestAndTerminal `
                        -ManifestPath $FailureManifestPath `
                        -Terminal $workerLines[0] `
                        -WorkerContract $WorkerContract `
                        -BoundParameters $BoundParameters `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                }
                "HardKill" {
                    Assert-BoundedWorkerPassManifestAndTerminal `
                        -ManifestPath $FailureManifestPath `
                        -Terminal $workerLines[0] `
                        -WorkerContract $WorkerContract `
                        -BoundParameters $BoundParameters `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                }
            }
            $finalState = Invoke-BoundedHyperVMutation `
                -Action Read -VmId $ExpectedVmId `
                -ExpectedVmName $ExpectedVmName -TimeoutSeconds 30
            if ([string]$finalState -cne $ExpectedFinalState) {
                throw (
                    "$Label changed the exact VM final state: " +
                    "expected=$ExpectedFinalState actual=$finalState"
                )
            }
        } catch {
            $primaryFailure = $_
        }
    } finally {
        try {
            $workerStartGate.Dispose()
        } catch {
            $recoveryIssues.Add(
                "worker start gate disposal failed: $($_.Exception.Message)"
            )
        }
        if ($null -eq $primaryFailure -and $recoveryIssues.Count -eq 0) {
            try {
                [Console]::Out.Write($result.Stdout)
                $workerAccepted = $true
            } catch {
                $primaryFailure = $_
            }
        }
        if (-not $workerAccepted) {
            if ($null -ne $CleanupAuthority) {
                try {
                    Invoke-ApprovedVmWorkerEmergencyCleanup `
                        -Authority $CleanupAuthority `
                        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
                        -Mode $CleanupMode
                } catch {
                    $recoveryIssues.Add($_.Exception.Message)
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($FailureManifestPath)) {
                try {
                    $failureManifestSchema = switch ($WorkerContract) {
                        "Qualification" {
                            "ferrum2.windows-tun.hyperv-host-run.v4"
                        }
                        "HardKill" {
                            "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2"
                        }
                        default { "" }
                    }
                    Remove-BoundedWorkerManifestIfPresent `
                        -Path $FailureManifestPath `
                        -ExpectedSchema $failureManifestSchema `
                        -ExpectedRunToken ([string]$BoundParameters["RunToken"]) `
                        -ExpectedVmId $ExpectedVmId `
                        -ExpectedVmName $ExpectedVmName
                } catch {
                    $recoveryIssues.Add(
                        "invalid worker manifest removal failed: $($_.Exception.Message)"
                    )
                }
            }
        }
    }
    if ($null -ne $primaryFailure) {
        if ($recoveryIssues.Count -ne 0) {
            throw (
                "$Label supervisor failed: primary=$($primaryFailure.Exception.Message); " +
                    "recovery=$($recoveryIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($recoveryIssues.Count -ne 0) {
        throw "$Label supervisor recovery failed: $($recoveryIssues -join '; ')"
    }
}

function Assert-BoundedHyperVInternalWorker {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
        [string]$Token
    )

    $environmentToken = [string]$env:FERRUM2_HYPERV_WORKER_TOKEN
    $supervisorPidText = [string]$env:FERRUM2_HYPERV_SUPERVISOR_PID
    $supervisorStartTicksText = [string]$env:FERRUM2_HYPERV_SUPERVISOR_START_TICKS
    $workerGateName = [string]$env:FERRUM2_HYPERV_WORKER_GATE
    $supervisorPid = 0
    $supervisorStartTicks = [long]0
    if ($Token -cne $environmentToken -or
        $supervisorPidText -cnotmatch '^[1-9][0-9]{0,9}$' -or
        -not [int]::TryParse(
            $supervisorPidText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$supervisorPid
        ) -or
        $supervisorPid -eq $PID -or
        $workerGateName -cnotmatch
            '^Local\\Ferrum2-HyperV-Worker-[0-9a-f]{32}$' -or
        $supervisorStartTicksText -cnotmatch '^[1-9][0-9]{0,18}$' -or
        -not [long]::TryParse(
            $supervisorStartTicksText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$supervisorStartTicks
        )) {
        throw "bounded Hyper-V worker capability is invalid"
    }
    $supervisor = Get-Process -Id $supervisorPid -ErrorAction Stop
    $current = Get-Process -Id $PID -ErrorAction Stop
    if ([IO.Path]::GetFullPath([string]$supervisor.Path) -ine
            [IO.Path]::GetFullPath([string]$current.Path) -or
        $supervisor.StartTime.ToUniversalTime().Ticks -ne $supervisorStartTicks) {
        throw "bounded Hyper-V worker supervisor identity is invalid"
    }
    $workerStartGate = [Threading.EventWaitHandle]::OpenExisting($workerGateName)
    foreach ($name in @(
        "FERRUM2_HYPERV_WORKER_TOKEN",
        "FERRUM2_HYPERV_SUPERVISOR_PID",
        "FERRUM2_HYPERV_SUPERVISOR_START_TICKS",
        "FERRUM2_HYPERV_WORKER_GATE"
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    try {
        if (-not $workerStartGate.WaitOne(30000)) {
            throw "bounded Hyper-V worker start gate timed out"
        }
    } finally {
        $workerStartGate.Dispose()
    }
}

function Remove-BoundedWorkerManifestIfPresent {
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
        (Test-PathWithinRoot -Path $fullPath -Root $script:repositoryRoot) -or
        [IO.Path]::GetFileName($fullPath) -cne "host-orchestration.json" -or
        $ExpectedSchema -notin @(
            "ferrum2.windows-tun.hyperv-host-run.v4",
            "ferrum2.windows-tun.hard-kill-hyperv-host-run.v2"
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
            [IO.File]::Delete($item.FullName)
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

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $context = Get-ApprovedVmContext
        if ([string]$context.Vm.State -cne "Running") {
            throw "approved VM left Running state before PowerShell Direct became ready"
        }

        $session = $null
        try {
            $session = New-PSSession `
                -VMId $script:approvedVmId `
                -Credential $Credential `
                -Name ("ferrum2-hyperv-" + [Guid]::NewGuid().ToString("N")) `
                -ErrorAction Stop
            $guestProbe = @(Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $currentVersion = Get-ItemProperty `
                    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    -ErrorAction Stop
                $principal = [Security.Principal.WindowsPrincipal]::new(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                )
                [pscustomobject]@{
                    Manufacturer = [string]$computer.Manufacturer
                    Model = [string]$computer.Model
                    Product = [string]$currentVersion.ProductName
                    Edition = [string]$currentVersion.EditionID
                    Version = [Environment]::OSVersion.Version.ToString()
                    Build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
                    OsBuildNumber = [string]$operatingSystem.BuildNumber
                    CurrentBuildNumber = [string]$currentVersion.CurrentBuildNumber
                    Architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    IsAdministrator = $principal.IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator
                    )
                }
            })
            if ($guestProbe.Count -ne 1 -or
                $guestProbe[0].Manufacturer -cne "Microsoft Corporation" -or
                $guestProbe[0].Model -cne "Virtual Machine" -or
                $guestProbe[0].OsBuildNumber -cne $guestProbe[0].CurrentBuildNumber -or
                $guestProbe[0].Architecture -cne "X64" -or
                $guestProbe[0].IsAdministrator -ne $true) {
                throw "PowerShell Direct reached an ineligible guest identity"
            }
            return [pscustomobject]@{
                Session = $session
                Probe = $guestProbe[0]
            }
        } catch {
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                break
            }
            Start-Sleep -Seconds 2
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not become ready before the bounded timeout"
}

function Read-IdentityLedger {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$CandidateSha,
        [Parameter(Mandatory = $true)]
        [string]$ControllerPath,
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
        "candidate_sha", "probe_sha256", "client_sha256", "server_sha256", "support_listener",
        "topology"
    )
    $actualKeys = @($ledger.PSObject.Properties.Name)
    $expectedKeys = @($baseKeys + "test_binaries")
    if (($actualKeys -join "|") -cne ($expectedKeys -join "|") -or
        ($ledger | ConvertTo-Json -Compress -Depth 8) -cne $json) {
        throw "identity ledger is not canonical or has an invalid property set"
    }
    if ($ledger.schema -isnot [long] -or $ledger.schema -ne 2 -or
        $ledger.vm_name -cne [string]$topologyDocument.Value.vm.name -or
        $ledger.vm_id -cne [string]$topologyDocument.Value.vm.id -or
        $ledger.checkpoint_name -cne
            [string]$topologyDocument.Value.qualification_checkpoint.name -or
        $ledger.checkpoint_id -cne
            [string]$topologyDocument.Value.qualification_checkpoint.id -or
        $ledger.guest_architecture -cne "AMD64" -or
        $ledger.candidate_sha -cne $CandidateSha) {
        throw "identity ledger does not bind the approved guest and candidate"
    }
    foreach ($name in @("probe_sha256", "client_sha256", "server_sha256")) {
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
    $testKeys = @("client", "tun", "wintun")
    if ((@($ledger.test_binaries.PSObject.Properties.Name) -join "|") -cne
        ($testKeys -join "|")) {
        throw "identity ledger test binary shape is invalid"
    }
    foreach ($name in $testKeys) {
        if ([string]$ledger.test_binaries.$name -cnotmatch '^[0-9a-f]{64}$') {
            throw "identity ledger contains an invalid test binary hash"
        }
    }

    $controllerHash = (Get-FileHash -LiteralPath $ControllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ledger.probe_sha256 -cne $controllerHash) {
        throw "identity ledger controller hash does not match the candidate"
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

function Get-CargoCompilerArtifacts {
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

    $matches = @($Messages | Where-Object {
        $_.target.name -ceq $TargetName -and
        @($_.target.kind) -ccontains $TargetKind -and
        [bool]$_.profile.test -eq $TestProfile
    })
    if ($matches.Count -ne 1) {
        throw "$Label build did not yield exactly one executable"
    }
    return Resolve-BoundedFile `
        -Path ([string]$matches[0].executable) `
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

function Build-CandidateArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [object]$Ledger
    )

    $rustup = (Get-Command rustup -CommandType Application -ErrorAction Stop).Source
    $versionDetails = Invoke-CapturedNativeCommand `
        -Executable $rustup `
        -Arguments @("run", "1.97.1", "rustc", "--version", "--verbose") `
        -Label "host Rust toolchain verification" `
        -MaximumOutputBytes 65536
    $versionLines = @($versionDetails | Where-Object { $_ -cmatch '^rustc 1\.97\.1 \(' })
    $hostLines = @($versionDetails | Where-Object {
        $_ -ceq "host: x86_64-pc-windows-msvc"
    })
    $releaseLines = @($versionDetails | Where-Object { $_ -ceq "release: 1.97.1" })
    if ($versionLines.Count -ne 1 -or $hostLines.Count -ne 1 -or $releaseLines.Count -ne 1) {
        throw "host Rust toolchain does not match Rust 1.97.1 x86_64-pc-windows-msvc"
    }

    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $common = @("run", "1.97.1", "cargo")
    $buildMessages = Get-CargoCompilerArtifacts (Invoke-CapturedNativeCommand `
        -Executable $rustup `
        -Arguments ($common + @(
            "build", "-p", "ferrum2-client", "-p", "ferrum2-server", "--bins",
            "--locked", "--message-format=json-render-diagnostics",
            "--manifest-path", (Join-Path $script:repositoryRoot "Cargo.toml")
        )) `
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

    $testBuilds = @(
        [ordered]@{
            Key = "client"
            File = "ferrum2-client-tests.exe"
            Package = "ferrum2-client"
            CargoTarget = @("--bin", "ferrum2-client")
            TargetName = "ferrum2-client"
            TargetKind = "bin"
        },
        [ordered]@{
            Key = "tun"
            File = "ferrum2-tun-tests.exe"
            Package = "ferrum2-tun"
            CargoTarget = @("--lib")
            TargetName = "ferrum2_tun"
            TargetKind = "lib"
        },
        [ordered]@{
            Key = "wintun"
            File = "ferrum2-wintun-tests.exe"
            Package = "ferrum2-wintun"
            CargoTarget = @("--lib")
            TargetName = "ferrum2_wintun"
            TargetKind = "lib"
        }
    )

    $client = Copy-CandidateArtifact `
        -Source $clientSource `
        -Destination (Join-Path $Destination "ferrum2-client.exe") `
        -Label "candidate client"
    $server = Copy-CandidateArtifact `
        -Source $serverSource `
        -Destination (Join-Path $Destination "ferrum2-server.exe") `
        -Label "candidate server"
    $tests = [ordered]@{}
    foreach ($spec in $testBuilds) {
        $messages = Get-CargoCompilerArtifacts (Invoke-CapturedNativeCommand `
            -Executable $rustup `
            -Arguments ($common + @(
                "test", "-p", $spec.Package, "--locked"
            ) + @($spec.CargoTarget) + @(
                "--no-run", "--message-format=json-render-diagnostics",
                "--manifest-path", (Join-Path $script:repositoryRoot "Cargo.toml")
            )) `
            -Label "host $($spec.Package) test build")
        $source = Select-CargoExecutable `
            -Messages $messages `
            -TargetName $spec.TargetName `
            -TargetKind $spec.TargetKind `
            -TestProfile $true `
            -Label "$($spec.Package) test binary"
        $tests[$spec.Key] = Copy-CandidateArtifact `
            -Source $source `
            -Destination (Join-Path $Destination $spec.File) `
            -Label "$($spec.Package) test binary"
    }

    $fuzzManifest = Join-Path $script:repositoryRoot "crates\ferrum2-tun\fuzz\Cargo.toml"
    $fuzzMessages = Get-CargoCompilerArtifacts (Invoke-CapturedNativeCommand `
        -Executable $rustup `
        -Arguments ($common + @(
            "build", "--manifest-path", $fuzzManifest, "--bin", "smoke",
            "--no-default-features", "--locked", "--target", "x86_64-pc-windows-msvc",
            "--message-format=json-render-diagnostics"
        )) `
        -Label "host Windows TUN fuzz smoke build")
    $fuzzSmokeSource = Select-CargoExecutable `
        -Messages $fuzzMessages `
        -TargetName "smoke" `
        -TargetKind "bin" `
        -TestProfile $false `
        -Label "Windows TUN fuzz smoke binary"
    $fuzzSmoke = Copy-CandidateArtifact `
        -Source $fuzzSmokeSource `
        -Destination (Join-Path $Destination "ferrum2-tun-fuzz-smoke.exe") `
        -Label "Windows TUN fuzz smoke binary"

    if ($client.Sha256 -cne [string]$Ledger.client_sha256 -or
        $server.Sha256 -cne [string]$Ledger.server_sha256) {
        throw "host-built candidate binary hashes do not match the identity ledger"
    }
    foreach ($key in @("client", "tun", "wintun")) {
        if ($tests[$key].Sha256 -cne [string]$Ledger.test_binaries.$key) {
            throw "host-built $key test hash does not match the identity ledger"
        }
    }
    return [pscustomobject]@{
        Client = $client
        Server = $server
        Tests = $tests
        FuzzSmoke = $fuzzSmoke
        RustVersion = $versionLines[0]
    }
}

function New-PortablePowerShellArchive {
    param(
        [Parameter(Mandatory = $true)][string]$SourceZip,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not [IO.Path]::IsPathFullyQualified($Destination)) {
        throw "portable PowerShell archive destination must be absolute"
    }
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    $destinationParent = [IO.Path]::GetDirectoryName($destinationPath)
    if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
        throw "portable PowerShell archive destination parent is absent"
    }
    Assert-NoReparsePointInExistingPath `
        -Path $destinationParent `
        -Label "portable PowerShell archive destination"
    if (Test-PathWithinRoot -Path $destinationPath -Root $script:repositoryRoot) {
        throw "portable PowerShell archive destination must remain outside the repository"
    }
    $source = Resolve-BoundedFile `
        -Path $SourceZip `
        -Label "portable PowerShell ZIP" `
        -MaximumBytes 536870912 `
        -RequireOutsideRepository
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "portable PowerShell ZIP hash mismatch"
    }
    if (Test-Path -LiteralPath $destinationPath) {
        throw "portable PowerShell archive destination baseline is not absent"
    }
    Copy-Item -LiteralPath $source -Destination $destinationPath -ErrorAction Stop
    $archive = Resolve-BoundedFile `
        -Path $destinationPath `
        -Label "portable PowerShell archive" `
        -MaximumBytes 536870912 `
        -RequireOutsideRepository
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "copied portable PowerShell ZIP hash mismatch"
    }
    $inspectionRoot = Join-Path (Split-Path -Parent $archive) "portable-pwsh-inspection"
    if (Test-Path -LiteralPath $inspectionRoot) {
        throw "portable PowerShell inspection baseline is not absent"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $inspectionRoot -ErrorAction Stop
    $items = @(Get-Item -LiteralPath $inspectionRoot -Force) + @(
        Get-ChildItem -LiteralPath $inspectionRoot -Force -Recurse
    )
    if (@($items | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0) {
        throw "portable PowerShell runtime cannot contain a reparse point"
    }
    $files = @($items | Where-Object { -not $_.PSIsContainer })
    $bytes = [long]($files | Measure-Object Length -Sum).Sum
    if ($files.Count -eq 0 -or $files.Count -gt 4096 -or
        $bytes -le 0 -or $bytes -gt 1073741824) {
        throw "portable PowerShell runtime exceeds its staging boundary"
    }
    $pwsh = Join-Path $inspectionRoot "pwsh.exe"
    $version = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1)
    if ($LASTEXITCODE -ne 0 -or $version.Count -ne 1 -or
        [string]$version[0] -cne $script:expectedPowerShellVersion) {
        throw "portable PowerShell version is not the pinned compatible release"
    }
    return [pscustomobject]@{
        Path = $archive
        Name = [IO.Path]::GetFileName($archive)
        Bytes = [long](Get-Item -LiteralPath $archive -Force).Length
        Sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        ExecutableSha256 = (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant()
        Version = [string]$version[0]
        FileCount = [long]$files.Count
        ExpandedBytes = $bytes
    }
}

function Stage-VisualCppRuntime {
    param([Parameter(Mandatory = $true)][string]$Destination)

    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")) {
        $source = Join-Path $system $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            if ($name -ceq "vcruntime140.dll") {
                throw "host Visual C++ runtime is missing vcruntime140.dll"
            }
            continue
        }
        $resolved = Resolve-BoundedFile `
            -Path $source `
            -Label "Visual C++ runtime $name" `
            -MaximumBytes 16777216
        $destinationPath = Join-Path $Destination $name
        Copy-Item -LiteralPath $resolved -Destination $destinationPath -ErrorAction Stop
        $files.Add([pscustomobject]@{
            Path = $destinationPath
            Name = $name
            Bytes = [long](Get-Item -LiteralPath $destinationPath -Force).Length
            Sha256 = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    return @($files)
}

function Write-JsonFileNew {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 8) + "`n"
    )
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $writeFailure = $null
    $disposeFailure = $null
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } catch {
        $writeFailure = $_
    } finally {
        try { $stream.Dispose() } catch { $disposeFailure = $_ }
    }
    if ($null -ne $writeFailure) {
        if ($null -ne $disposeFailure) {
            throw (
                "JSON create-new write failed: " +
                    "primary=$($writeFailure.Exception.Message); " +
                    "disposal=$($disposeFailure.Exception.Message)"
            )
        }
        throw $writeFailure
    }
    if ($null -ne $disposeFailure) {
        throw "JSON create-new disposal failed: $($disposeFailure.Exception.Message)"
    }
}

function New-StagedFileEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [long]$MaximumBytes = 536870912
    )

    $resolved = Resolve-BoundedFile `
        -Path $Path `
        -Label "staged input $Name" `
        -MaximumBytes $MaximumBytes
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    return [ordered]@{
        name = $Name
        bytes = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Copy-GuestEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$GuestExportPath,
        [Parameter(Mandatory = $true)]
        [string]$HostEvidencePath
    )

    $boundary = @(Invoke-Command -Session $Session -ArgumentList $GuestExportPath -ErrorAction Stop -ScriptBlock {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [pscustomobject]@{ Exists = $false; Safe = $false }
        }
        $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
        $files = @($items | Where-Object { -not $_.PSIsContainer })
        $directories = @($items | Where-Object { $_.PSIsContainer })
        $totalBytes = [long]($files | Measure-Object Length -Sum).Sum
        return [pscustomobject]@{
            Exists = $true
            Safe = @($items | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count -eq 0 -and
                $files.Count -le 512 -and
                $directories.Count -le 128 -and
                @($files | Where-Object { $_.Length -gt 67108864 }).Count -eq 0 -and
                $totalBytes -le 536870912
            Files = [long]$files.Count
            Directories = [long]$directories.Count
            Bytes = $totalBytes
        }
    })
    if ($boundary.Count -ne 1 -or $boundary[0].Exists -ne $true -or $boundary[0].Safe -ne $true) {
        throw "guest evidence boundary is missing or unsafe"
    }

    $guestDestination = Join-Path $HostEvidencePath "guest"
    [IO.Directory]::CreateDirectory($guestDestination) | Out-Null
    Copy-Item `
        -FromSession $Session `
        -LiteralPath $GuestExportPath `
        -Destination $guestDestination `
        -Recurse `
        -ErrorAction Stop
    Assert-NoReparsePointInExistingPath -Path $guestDestination -Label "exported evidence"
    $hostItems = @(Get-Item -LiteralPath $guestDestination -Force) + @(
        Get-ChildItem -LiteralPath $guestDestination -Force -Recurse
    )
    $hostFiles = @($hostItems | Where-Object { -not $_.PSIsContainer })
    $hostDirectories = @($hostItems | Where-Object { $_.PSIsContainer })
    $hostBytes = [long]($hostFiles | Measure-Object Length -Sum).Sum
    if ($hostFiles.Count -ne [long]$boundary[0].Files -or
        $hostDirectories.Count -gt ([long]$boundary[0].Directories + 1) -or
        $hostBytes -ne [long]$boundary[0].Bytes -or
        @($hostItems | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count -ne 0) {
        throw "exported evidence changed across the bounded copy"
    }
}

function Get-EvidenceHashes {
    param([string]$EvidenceRoot)

    $rows = [Collections.Generic.List[object]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $EvidenceRoot -File -Force -Recurse | Sort-Object FullName)) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "exported evidence cannot contain a reparse point"
        }
        $relative = [IO.Path]::GetRelativePath($EvidenceRoot, $file.FullName).Replace('\', '/')
        if ($relative -in @(
            "host-orchestration.json",
            "host-orchestration.pending.json"
        )) {
            continue
        }
        $rows.Add([ordered]@{
            path = $relative
            bytes = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    return @($rows)
}

# The independent hard-kill orchestrator imports the reviewed host-only safety primitives from this
# script in an isolated dynamic-module scope. LibraryOnly must return before platform, credential,
# VM, build, staging, or guest-execution work. It is intentionally not a qualification profile.
if ($LibraryOnly) {
    return
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the Hyper-V host orchestrator requires 64-bit Windows AMD64"
}
if ($InternalWorker) {
    if ([string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
        throw "bounded Hyper-V worker token is required"
    }
    Assert-BoundedHyperVInternalWorker -Token $InternalWorkerToken
} elseif (-not [string]::IsNullOrWhiteSpace($InternalWorkerToken)) {
    throw "bounded Hyper-V worker token is not valid outside the internal worker"
}
# Resolve both exact identities and the DPAPI credential before any VM lifecycle operation.
$topologyInitialization = Initialize-ApprovedHyperVTopology `
    -ManifestPath $TopologyManifestPath -ExpectedSha256 $TopologyManifestSha256
$topologyDocument = $topologyInitialization.Document
$initialTopologyState = [pscustomobject][ordered]@{
    Runtime = $topologyInitialization.Runtime
    VmNetwork = $topologyInitialization.VmNetwork
}
$supportAddress = [string]$topologyDocument.Value.support.switch.host_ipv4
$supportHostBaseline = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner
$initialContext = Get-ApprovedVmContext
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

# Keep the user-facing process outside the VM-active execution path. The hidden worker may use
# synchronous PowerShell Direct, but the supervisor has already captured exact-GUID cleanup authority
# and can terminate the entire worker tree before performing bounded Stop -> Restore -> Stop cleanup.
if (-not $InternalWorker) {
    $supervisorInitialState = [string]$initialContext.Vm.State
    if ($ProbeOnly) {
        if ($supervisorInitialState -notin @("Off", "Running")) {
            throw "ProbeOnly requires the approved VM to be Off or Running"
        }
    } elseif ($supervisorInitialState -cne "Off") {
        throw "approved VM must be Off at the full qualification supervisor baseline"
    }
    $supervisorCleanupAuthority = if ($supervisorInitialState -ceq "Off") {
        New-ApprovedVmCleanupAuthority -Context $initialContext
    } else {
        $null
    }
    $workerTimeoutSeconds = if ($ProbeOnly) {
        1800
    } elseif ($Profile -clike "*-1000") {
        10800
    } else {
        7200
    }
    $supervisorFailureManifestPath = $null
    if (-not $ProbeOnly) {
        $supervisorEvidenceDirectory = $EvidenceDirectory
        if ([string]::IsNullOrWhiteSpace($supervisorEvidenceDirectory)) {
            if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
                throw "LOCALAPPDATA is required for the default evidence directory"
            }
            $supervisorEvidenceDirectory = Join-Path $env:LOCALAPPDATA `
                "Ferrum2\windows-tun-evidence\$RunToken"
        }
        $supervisorEvidenceDirectory = Resolve-ExternalDirectoryTarget `
            -Path $supervisorEvidenceDirectory `
            -Label "supervised evidence directory"
        $supervisorFailureManifestPath = Join-Path `
            $supervisorEvidenceDirectory "host-orchestration.json"
    }
    Invoke-BoundedHyperVWorkerSupervisor `
        -ScriptPath $PSCommandPath `
        -BoundParameters $PSBoundParameters `
        -ForwardedParameterNames @(
            "ProbeOnly", "Profile", "RunToken", "IdentityLedger",
            "TopologyManifestPath", "TopologyManifestSha256",
            "SupportTcpPort", "SupportUdpPort", "SupportPid", "SupportOwner",
            "WintunZip", "PowerShellZip", "EvidenceDirectory", "CredentialPath",
            "ReadinessTimeoutSeconds", "ShutdownTimeoutSeconds"
        ) `
        -WorkerTimeoutSeconds $workerTimeoutSeconds `
        -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds `
        -ExpectedVmId $approvedVmId `
        -ExpectedVmName $approvedVmName `
        -ExpectedFinalState $supervisorInitialState `
        -CleanupAuthority $supervisorCleanupAuthority `
        -CleanupMode $(if ($ProbeOnly) { "StopOnly" } else { "RestoreCheckpoint" }) `
        -WorkerContract $(if ($ProbeOnly) { "Probe" } else { "Qualification" }) `
        -FailureManifestPath $supervisorFailureManifestPath `
        -Label "Windows TUN HyperV worker"
    return
}

if ($ProbeOnly) {
    $initialState = [string]$initialContext.Vm.State
    if ($initialState -notin @("Off", "Running")) {
        throw "ProbeOnly requires the approved VM to be Off or Running"
    }

    $probeStartedVm = $false
    $probeCleanupAuthority = $null
    $connection = $null
    $probeGuestTopology = $null
    $probeFailure = $null
    $probeFinalizationFailures = [Collections.Generic.List[string]]::new()
    try {
        if ($initialState -ceq "Off") {
            $probeCleanupAuthority = New-ApprovedVmCleanupAuthority `
                -Context (Get-ApprovedVmContext)
            $probeStartedVm = $true
            Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
        }
        $connection = Connect-ApprovedGuest `
            -Credential $guestCredential `
            -TimeoutSeconds $ReadinessTimeoutSeconds
        $probeGuestTopology = Get-ApprovedGuestSupportTopologyRuntimeState `
            -Session $connection.Session -TopologyDocument $topologyDocument
    } catch {
        $probeFailure = $_
    } finally {
        if ($probeStartedVm) {
            $probeVmConfirmedOff = $false
            try {
                Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $probeVmConfirmedOff = $true
            } catch {
                $probeFinalizationFailures.Add(
                    "probe emergency VM stop failed: $($_.Exception.Message)"
                )
            }
            if (-not $probeVmConfirmedOff) {
                $probeFinalizationFailures.Add("probe did not prove the temporarily started VM Off")
            }
        }
        if ($null -ne $connection) {
            Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
        }
    }

    $probeFinalVmState = $null
    $probeFinalTopologyState = $null
    $probeFinalSupport = $null
    try {
        $probeFinalVmState = [string](Get-ApprovedVmContext).Vm.State
        if ($probeFinalVmState -cne $initialState) {
            $probeFinalizationFailures.Add(
                "probe changed the approved VM state: expected=$initialState actual=$probeFinalVmState"
            )
            if ($probeStartedVm -and $null -ne $probeCleanupAuthority) {
                Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                    -TimeoutSeconds $ShutdownTimeoutSeconds
                $probeFinalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                ).State
                if ($probeFinalVmState -cne "Off") {
                    throw "probe emergency final VM state is $probeFinalVmState"
                }
            }
        }
    } catch {
        $probeFinalizationFailures.Add(
            "probe final VM state readback failed: $($_.Exception.Message)"
        )
        if ($probeStartedVm -and $null -ne $probeCleanupAuthority) {
            try {
                $probeFinalVmState = [string](
                    Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                ).State
                if ($probeFinalVmState -cne "Off") {
                    Stop-ApprovedVmEmergency -Authority $probeCleanupAuthority `
                        -TimeoutSeconds $ShutdownTimeoutSeconds
                    $probeFinalVmState = [string](
                        Get-ApprovedVmEmergencyState -Authority $probeCleanupAuthority
                    ).State
                }
                if ($probeFinalVmState -cne "Off") {
                    throw "probe emergency final VM state is $probeFinalVmState"
                }
            } catch {
                $probeFinalizationFailures.Add(
                    "probe emergency final VM state recovery failed: " +
                        $_.Exception.Message
                )
            }
        }
    }
    try {
        $probeFinalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
            -TopologyDocument $topologyDocument
        Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
            -Expected $initialTopologyState -Actual $probeFinalTopologyState
    } catch {
        $probeFinalizationFailures.Add(
            "probe final topology readback failed: $($_.Exception.Message)"
        )
    }
    try {
        $probeFinalSupport = Get-ApprovedHostSupportRuntimeState `
            -TopologyDocument $topologyDocument `
            -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
            -ProcessId $SupportPid -ProcessOwner $SupportOwner
        Assert-ApprovedHostSupportRuntimeStateUnchanged `
            -Expected $supportHostBaseline -Actual $probeFinalSupport
    } catch {
        $probeFinalizationFailures.Add(
            "probe final support-listener readback failed: $($_.Exception.Message)"
        )
    }
    try {
        Assert-ApprovedTopologyHelperSourcesUnchanged
    } catch {
        $probeFinalizationFailures.Add(
            "probe final helper-source readback failed: $($_.Exception.Message)"
        )
    }

    if ($null -ne $probeFailure -or $probeFinalizationFailures.Count -ne 0) {
        $messages = [Collections.Generic.List[string]]::new()
        if ($null -ne $probeFailure) {
            $messages.Add("probe failed: $($probeFailure.Exception.Message)")
        }
        foreach ($message in $probeFinalizationFailures) {
            $messages.Add($message)
        }
        throw [InvalidOperationException]::new(($messages -join "; "))
    }

    [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-probe.v2"
        status = "pass"
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        initial_vm_state = $initialState.ToLowerInvariant()
        final_vm_state = $probeFinalVmState
        guest_product = [string]$connection.Probe.Product
        guest_edition = [string]$connection.Probe.Edition
        guest_version = [string]$connection.Probe.Version
        guest_build = [string]$connection.Probe.Build
        guest_architecture = [string]$connection.Probe.Architecture
        powershell_version = [string]$connection.Probe.PowerShellVersion
        topology_manifest_sha256 = [string]$topologyDocument.Sha256
        topology_plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
        support_switch_id = [string]$topologyDocument.Value.support.switch.switch_id
        support_host_ipv4 = $supportAddress
        support_guest = $probeGuestTopology
        protected_host_tun = $probeFinalTopologyState.Runtime.ProtectedHostTun
        support_listener = $probeFinalSupport
        checkpoint_restored = $false
        files_staged = $false
        controller_invoked = $false
        host_tun_unchanged = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Compress
    return
}

$requestedMode = $Profile
$requestedRestartCycles = $null
$requestedNetworkResetCycles = $null
if ($Profile -cmatch '^restart-(10|100|1000)$') {
    $requestedMode = "restart-stress"
    $requestedRestartCycles = [int]$Matches[1]
} elseif ($Profile -cmatch '^network-reset-(10|100|1000)$') {
    $requestedMode = "network-reset"
    $requestedNetworkResetCycles = [int]$Matches[1]
}

$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\qualify_windows_tun.ps1") `
    -Label "qualification controller" `
    -MaximumBytes 4194304
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath `
    -TopologyDocument $topologyDocument `
    -ExpectedSupportContext $supportHostBaseline
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
$wintunHash = (Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($wintunHash -cne $expectedWintunZipSha256) {
    throw "Wintun archive hash mismatch"
}
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
    $EvidenceDirectory = Join-Path $env:LOCALAPPDATA "Ferrum2\windows-tun-evidence\$RunToken"
}
$hostEvidencePath = Resolve-ExternalDirectoryTarget `
    -Path $EvidenceDirectory `
    -Label "evidence directory"

$baselineContext = Get-ApprovedVmContext
if ([string]$baselineContext.Vm.State -cne "Off") {
    throw "approved VM must be Off at the full qualification baseline"
}
$baselineTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
    -TopologyDocument $topologyDocument
Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
    -Expected $initialTopologyState -Actual $baselineTopologyState
$baselineSupportState = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $topologyDocument `
    -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner
Assert-ApprovedHostSupportRuntimeStateUnchanged `
    -Expected $supportHostBaseline -Actual $baselineSupportState

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("ferrum2-hyperv-" + [Guid]::NewGuid().ToString("N"))
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$hostArtifactRoot = Join-Path $temporaryRoot "artifacts"
$hostRuntimeLibraryRoot = Join-Path $temporaryRoot "vc-runtime"
$hostPowerShellArchive = Join-Path $temporaryRoot "portable-pwsh.zip"
$stagedInputManifestPath = Join-Path $temporaryRoot "staged-input.json"
$hostTopologyManifestPath = Join-Path $hostEvidencePath "topology-manifest.json"
$hostNetworkPathPath = Join-Path $hostEvidencePath "host-network-path.json"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$cleanupAuthority = $null
$checkpointRestored = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$guestResult = $null
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null
$guestNetworkPath = $null
$guestNetworkPathPost = $null
$guestNetworkPathSha256 = $null
$hostNetworkPathSha256 = $null
$postGuestTopology = $null
$finalTopologyState = $null
$finalSupportState = $null

try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $topologyDocument
    Copy-Item -LiteralPath $topologyDocument.Path `
        -Destination $hostTopologyManifestPath -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $hostTopologyManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne [string]$topologyDocument.Sha256 -or
        (Get-Item -LiteralPath $hostTopologyManifestPath -Force).Length -ne
            [long]$topologyDocument.Length) {
        throw "evidence topology manifest copy changed"
    }
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )
    $candidateArtifacts = Build-CandidateArtifacts `
        -Destination $hostArtifactRoot `
        -Ledger $ledgerIdentity.Ledger
    $portablePowerShell = New-PortablePowerShellArchive `
        -SourceZip $PowerShellZip `
        -Destination $hostPowerShellArchive
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun.ps1" `
        -MaximumBytes 4194304
    $identityEntry = New-StagedFileEntry `
        -Path $ledgerIdentity.Path `
        -Name "identity-ledger.json" `
        -MaximumBytes 65536
    $topologyManifestEntry = New-StagedFileEntry `
        -Path $topologyDocument.Path `
        -Name "topology-manifest.json" `
        -MaximumBytes 131072
    $guestNetworkPathProbeEntry = New-StagedFileEntry `
        -Path $guestNetworkPathProbePath `
        -Name "get_windows_tun_guest_network_path.ps1" `
        -MaximumBytes 4194304
    $wintunEntry = New-StagedFileEntry `
        -Path $wintunPath `
        -Name "wintun-0.14.1.zip" `
        -MaximumBytes 16777216
    $vcEntries = @($runtimeLibraries | ForEach-Object {
        New-StagedFileEntry -Path $_.Path -Name $_.Name -MaximumBytes 16777216
    })
    if ($controllerEntry.sha256 -cne [string]$ledgerIdentity.Ledger.probe_sha256 -or
        $identityEntry.sha256 -cne $ledgerIdentity.Sha256 -or
        $topologyManifestEntry.sha256 -cne [string]$topologyDocument.Sha256 -or
        $guestNetworkPathProbeEntry.sha256 -cne $guestNetworkPathProbeSha256 -or
        [string]$ledgerIdentity.Ledger.topology.manifest_sha256 -cne
            [string]$topologyDocument.Sha256 -or
        $wintunEntry.sha256 -cne $expectedWintunZipSha256) {
        throw "host staged input identity changed after preflight"
    }
    $postBuildCandidate = Get-CandidateIdentity
    if ($postBuildCandidate.Sha -cne $candidate.Sha) {
        throw "candidate commit changed during host artifact preparation"
    }
    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-staged-input.v3"
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        topology_manifest_sha256 = [string]$topologyDocument.Sha256
        profile = $Profile
        mode = $requestedMode
        network_reset_cycles = $requestedNetworkResetCycles
        restart_cycles = $requestedRestartCycles
        files = [ordered]@{
            controller = $controllerEntry
            identity_ledger = $identityEntry
            topology_manifest = $topologyManifestEntry
            guest_network_path_probe = $guestNetworkPathProbeEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry -Path $candidateArtifacts.Client.Path -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry -Path $candidateArtifacts.Server.Path -Name "ferrum2-server.exe")
            client_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.client.Path -Name "ferrum2-client-tests.exe")
            tun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.tun.Path -Name "ferrum2-tun-tests.exe")
            wintun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.wintun.Path -Name "ferrum2-wintun-tests.exe")
            fuzz_smoke = $(New-StagedFileEntry -Path $candidateArtifacts.FuzzSmoke.Path -Name "ferrum2-tun-fuzz-smoke.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 536870912)
        }
        runtime = [ordered]@{
            rust_version = $candidateArtifacts.RustVersion
            powershell_version = $portablePowerShell.Version
            powershell_executable_sha256 = $portablePowerShell.ExecutableSha256
            powershell_file_count = $portablePowerShell.FileCount
            powershell_expanded_bytes = $portablePowerShell.ExpandedBytes
            vc_libraries = $vcEntries
        }
    }
    Write-JsonFileNew -Path $stagedInputManifestPath -Value $stagedInput
    $stagedInputSha256 = (Get-FileHash -LiteralPath $stagedInputManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item `
        -LiteralPath $stagedInputManifestPath `
        -Destination (Join-Path $hostEvidencePath "staged-input.json") `
        -ErrorAction Stop

    $preMutationTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $preMutationTopologyState
    $preMutationSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $preMutationSupportState

    # Capture fresh, GUID-only cleanup authority immediately before the first VM mutation. It is
    # used only if later manifest/name/inventory drift prevents the stricter normal cleanup path.
    $cleanupAuthority = New-ApprovedVmCleanupAuthority `
        -Context (Get-ApprovedVmContext)
    # From this point onward every exit path must leave the exact approved checkpoint restored Off.
    $restoreRequired = $true
    Restore-ApprovedCheckpoint -TimeoutSeconds $ShutdownTimeoutSeconds
    Start-ApprovedVm -TimeoutSeconds $ReadinessTimeoutSeconds
    $connection = Connect-ApprovedGuest `
        -Credential $guestCredential `
        -TimeoutSeconds $ReadinessTimeoutSeconds

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
                throw "guest staging baseline is not absent"
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
    if ($guestPaths.Count -ne 1) {
        throw "guest staging did not return one bounded path set"
    }
    $guestExportPath = [string]$guestPaths[0].Export
    $guestInputPath = [string]$guestPaths[0].Input
    $stagedFiles = @(
        [ordered]@{ Source = $controllerPath; Destination = $(Join-Path $guestInputPath "controller\qualify_windows_tun.ps1") },
        [ordered]@{ Source = $ledgerIdentity.Path; Destination = $(Join-Path $guestInputPath "identity-ledger.json") },
        [ordered]@{ Source = $topologyDocument.Path; Destination = $(Join-Path $guestInputPath "topology-manifest.json") },
        [ordered]@{ Source = $guestNetworkPathProbePath; Destination = $(Join-Path $guestInputPath "controller\get_windows_tun_guest_network_path.ps1") },
        [ordered]@{ Source = $wintunPath; Destination = $(Join-Path $guestInputPath "wintun-0.14.1.zip") },
        [ordered]@{ Source = $stagedInputManifestPath; Destination = $(Join-Path $guestInputPath "staged-input.json") },
        [ordered]@{ Source = $portablePowerShell.Path; Destination = $(Join-Path $guestInputPath "portable-pwsh.zip") },
        [ordered]@{ Source = $candidateArtifacts.Client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client.exe") },
        [ordered]@{ Source = $candidateArtifacts.Server.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-server.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.tun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-tun-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.wintun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-wintun-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.FuzzSmoke.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-tun-fuzz-smoke.exe") }
    )
    foreach ($library in $runtimeLibraries) {
        $stagedFiles += [ordered]@{
            Source = $library.Path
            Destination = $(Join-Path $guestInputPath ("runtime\vc-runtime\" + $library.Name))
        }
    }
    foreach ($file in $stagedFiles) {
        Copy-Item `
            -ToSession $connection.Session `
            -LiteralPath $file.Source `
            -Destination $file.Destination `
            -ErrorAction Stop
    }

    $guestNetworkPathEvidencePath = Join-Path $guestExportPath "guest-network-path.json"
    $guestManagedAdapterName = "F2-M17-$RunToken"
    $guestSupportTopologyBaseline = Get-ApprovedGuestSupportTopologyRuntimeState `
        -Session $connection.Session -TopologyDocument $topologyDocument
    $guestPathBootstrap = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName $guestManagedAdapterName `
        -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -OutputPath $guestNetworkPathEvidencePath `
        -TopologyDocument $topologyDocument
    $guestNetworkPath = $guestPathBootstrap.path
    $guestNetworkPathSha256 = [string]$guestPathBootstrap.evidence_sha256
    $pathTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $pathTopologyState
    $pathSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $pathSupportState
    $hostReturnPath = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPath `
        -VmNetworkContext $pathTopologyState.VmNetwork `
        -ExpectedSupportIpv4 $supportAddress
    $hostNetworkPathEvidence = [ordered]@{
        schema = 2
        kind = "windows_tun_host_network_path"
        topology = [ordered]@{
            manifest_sha256 = [string]$topologyDocument.Sha256
            plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
            support_switch_id = [string]$topologyDocument.Value.support.switch.switch_id
            qualification_checkpoint_id = $approvedCheckpointId.ToString("D")
        }
        support_listener = $pathSupportState
        approved_vm_network = $pathTopologyState.VmNetwork
        guest_forward_path = $guestNetworkPath
        host_return_path = $hostReturnPath
        guest_probe_sha256 = $guestNetworkPathProbeSha256
        host_helper_sha256 = $hostNetworkPathHelperSha256
        support_path_probe = [ordered]@{
            status = "PASS"
            tcp_echo = $true
            udp_echo = $true
            minimum_ipv4_packet_bytes = $minimumSupportIpv4PacketBytes
        }
        host_tun_bypassed = $true
        host_network_mutations = 0
    }
    Write-JsonFileNew -Path $hostNetworkPathPath -Value $hostNetworkPathEvidence
    $hostNetworkPathSha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()

    # BEGIN GUEST_ONLY_EXECUTION
    $guestResults = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList @(
            [string]$guestPaths[0].Root,
            $candidate.Sha,
            $Profile,
            $RunToken,
            $ledgerIdentity.Sha256,
            $expectedWintunZipSha256,
            $expectedWintunDllSha256,
            $expectedPowerShellZipSha256,
            $expectedPowerShellVersion,
            $stagedInputSha256,
            [string]$topologyDocument.Sha256,
            $guestNetworkPathProbeSha256,
            $guestNetworkPathSha256
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$RunRoot,
                [string]$CandidateSha,
                [string]$RequestedProfile,
                [string]$Token,
                [string]$ExpectedLedgerHash,
                [string]$ExpectedWintunHash,
                [string]$ExpectedWintunDllHash,
                [string]$ExpectedPowerShellZipHash,
                [string]$ExpectedPowerShellVersion,
                [string]$ExpectedInputManifestHash,
                [string]$ExpectedTopologyManifestHash,
                [string]$ExpectedGuestNetworkPathProbeHash,
                [string]$ExpectedGuestNetworkPathHash
            )

            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $ProgressPreference = "SilentlyContinue"

            function Invoke-LoggedCommand {
                param(
                    [string]$Executable,
                    [string[]]$Arguments,
                    [string]$StdoutPath,
                    [string]$StderrPath
                )
                & $Executable @Arguments 1>> $StdoutPath 2>> $StderrPath
                return [int]$LASTEXITCODE
            }

            function Write-GuestJsonNew {
                param([string]$Path, [object]$Value)
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
                    ($Value | ConvertTo-Json -Depth 6) + "`n"
                )
                $stream = [IO.FileStream]::new(
                    $Path,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None
                )
                try {
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush($true)
                } finally {
                    $stream.Dispose()
                }
            }

            function Assert-ClosedProperties {
                param([object]$Value, [string[]]$Expected, [string]$Label)
                if ((@($Value.PSObject.Properties.Name) -join "|") -cne ($Expected -join "|")) {
                    throw "$Label property set is invalid"
                }
            }

            function Test-JsonInteger {
                param([object]$Value)
                return $Value -is [int] -or $Value -is [long]
            }

            function Test-JsonNumber {
                param([object]$Value)
                return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or
                    $Value -is [long] -or $Value -is [single] -or $Value -is [double] -or
                    $Value -is [decimal]
            }

            function Test-Sha256 {
                param([object]$Value)
                return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
            }

            function Assert-NetworkResetEvidence {
                param(
                    [object]$Result,
                    [string]$ArtifactPath,
                    [int]$ExpectedCycles
                )
                if ($ExpectedCycles -notin @(10, 100, 1000)) {
                    throw "network-reset evidence cycle count is invalid"
                }
                $baselineRows = @($Result.live_checks | Where-Object {
                    $_.name -ceq "network-reset-baseline"
                })
                $summaryRows = @($Result.live_checks | Where-Object {
                    $_.name -ceq "network-reset-summary"
                })
                if ($baselineRows.Count -ne 1 -or $summaryRows.Count -ne 1) {
                    throw "network-reset WFP live evidence rows are not exact"
                }
                $baselineRow = $baselineRows[0]
                $summaryRow = $summaryRows[0]
                Assert-ClosedProperties $baselineRow @("name", "status", "evidence") "network-reset baseline row"
                Assert-ClosedProperties $summaryRow @("name", "status", "evidence") "network-reset summary row"
                if ($baselineRow.status -cne "pass" -or $summaryRow.status -cne "pass") {
                    throw "network-reset WFP live evidence did not pass"
                }

                $baseline = $baselineRow.evidence
                Assert-ClosedProperties $baseline @(
                    "process_id", "interface_guid", "interface_luid", "interface_index",
                    "managed_plane_sha256", "managed_plane", "strict_route_wfp_sha256",
                    "strict_route_filters", "strict_route_filter_ids", "strict_route_session_key",
                    "strict_route_sublayer_key", "session_generation", "network_generation"
                ) "network-reset baseline evidence"
                $filterIds = @($baseline.strict_route_filter_ids)
                if (-not (Test-JsonInteger $baseline.process_id) -or [long]$baseline.process_id -le 0 -or
                    $baseline.interface_guid -isnot [string] -or
                    [string]$baseline.interface_guid -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
                    $baseline.interface_luid -isnot [string] -or [string]$baseline.interface_luid -cnotmatch '^[1-9][0-9]*$' -or
                    -not (Test-JsonInteger $baseline.interface_index) -or [long]$baseline.interface_index -le 0 -or
                    -not (Test-Sha256 $baseline.managed_plane_sha256) -or
                    -not (Test-Sha256 $baseline.strict_route_wfp_sha256) -or
                    -not (Test-JsonInteger $baseline.strict_route_filters) -or
                    [long]$baseline.strict_route_filters -ne 8 -or $filterIds.Count -ne 8 -or
                    @($filterIds | Sort-Object -Unique).Count -ne 8 -or
                    @($filterIds | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[1-9][0-9]*$' }).Count -ne 0 -or
                    $baseline.strict_route_session_key -cne "8ea35b4e-6629-4e26-9776-95c5bf9c6b01" -or
                    $baseline.strict_route_sublayer_key -cne "ddbc2fa2-d52f-4a79-8a63-8446c308cf02" -or
                    -not (Test-JsonNumber $baseline.session_generation) -or
                    -not (Test-JsonNumber $baseline.network_generation)) {
                    throw "network-reset baseline WFP identity is invalid"
                }

                $summary = $summaryRow.evidence
                Assert-ClosedProperties $summary @(
                    "cycles", "process_id", "initial_session_generation", "final_session_generation",
                    "final_network_generation", "reset_started_delta", "reset_succeeded_delta",
                    "reset_failed_delta", "full_rebuild_delta",
                    "strict_route_filter_install_delta", "managed_plane_sha256",
                    "strict_route_wfp_sha256", "strict_route_filter_ids",
                    "strict_route_health_revalidations", "strict_route_wfp_samples",
                    "cycle_evidence", "cycle_evidence_bytes", "cycle_evidence_sha256"
                ) "network-reset summary evidence"
                $summaryFilterIds = @($summary.strict_route_filter_ids)
                $sampleStride = [Math]::Max(1, [int][Math]::Ceiling($ExpectedCycles / 10.0))
                $expectedWfpSamples = 1 + @(1..$ExpectedCycles | Where-Object {
                    $_ -eq 1 -or $_ -eq $ExpectedCycles -or ($_ % $sampleStride) -eq 0
                }).Count
                if (-not (Test-JsonInteger $summary.cycles) -or [long]$summary.cycles -ne $ExpectedCycles -or
                    -not (Test-JsonInteger $summary.process_id) -or
                    [long]$summary.process_id -ne [long]$baseline.process_id -or
                    -not (Test-JsonNumber $summary.initial_session_generation) -or
                    -not (Test-JsonNumber $summary.final_session_generation) -or
                    -not (Test-JsonNumber $summary.final_network_generation) -or
                    [double]$summary.final_session_generation -ne [double]$summary.initial_session_generation + $ExpectedCycles -or
                    [double]$summary.final_network_generation -ne [double]$summary.final_session_generation -or
                    -not (Test-JsonNumber $summary.reset_started_delta) -or
                    [double]$summary.reset_started_delta -ne $ExpectedCycles -or
                    -not (Test-JsonNumber $summary.reset_succeeded_delta) -or
                    [double]$summary.reset_succeeded_delta -ne $ExpectedCycles -or
                    -not (Test-JsonNumber $summary.reset_failed_delta) -or [double]$summary.reset_failed_delta -ne 0 -or
                    -not (Test-JsonNumber $summary.full_rebuild_delta) -or [double]$summary.full_rebuild_delta -ne 0 -or
                    -not (Test-JsonNumber $summary.strict_route_filter_install_delta) -or
                    [double]$summary.strict_route_filter_install_delta -ne 0 -or
                    $summary.managed_plane_sha256 -cne $baseline.managed_plane_sha256 -or
                    $summary.strict_route_wfp_sha256 -cne $baseline.strict_route_wfp_sha256 -or
                    ($summaryFilterIds -join "|") -cne ($filterIds -join "|") -or
                    -not (Test-JsonInteger $summary.strict_route_health_revalidations) -or
                    [long]$summary.strict_route_health_revalidations -ne $ExpectedCycles -or
                    -not (Test-JsonInteger $summary.strict_route_wfp_samples) -or
                    [long]$summary.strict_route_wfp_samples -ne $expectedWfpSamples -or
                    $summary.cycle_evidence -cne "network-reset-cycles.jsonl" -or
                    -not (Test-JsonInteger $summary.cycle_evidence_bytes) -or
                    [long]$summary.cycle_evidence_bytes -le 0 -or
                    [long]$summary.cycle_evidence_bytes -gt 1048576 -or
                    -not (Test-Sha256 $summary.cycle_evidence_sha256)) {
                    throw "network-reset summary WFP evidence is invalid"
                }

                $cyclePath = Join-Path $ArtifactPath "network-reset-cycles.jsonl"
                $cycleItem = Get-Item -LiteralPath $cyclePath -Force -ErrorAction Stop
                if ($cycleItem.PSIsContainer -or
                    ($cycleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $cycleItem.Length -ne [long]$summary.cycle_evidence_bytes -or
                    (Get-FileHash -LiteralPath $cyclePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$summary.cycle_evidence_sha256) {
                    throw "network-reset cycle evidence identity is invalid"
                }
                $cycleBytes = [IO.File]::ReadAllBytes($cyclePath)
                $lfCount = 0
                $crCount = 0
                foreach ($byte in $cycleBytes) {
                    if ($byte -eq 10) { $lfCount++ }
                    if ($byte -eq 13) { $crCount++ }
                }
                if ($cycleBytes.Length -eq 0 -or $cycleBytes[$cycleBytes.Length - 1] -ne 10 -or
                    $lfCount -ne $ExpectedCycles -or $crCount -ne 0) {
                    throw "network-reset cycle evidence framing is invalid"
                }
                $cycleText = [Text.UTF8Encoding]::new($false, $true).GetString($cycleBytes)
                $cycleLines = $cycleText.Split([char[]]@([char]10), [StringSplitOptions]::None)
                if ($cycleLines.Count -ne $ExpectedCycles + 1 -or $cycleLines[-1].Length -ne 0) {
                    throw "network-reset cycle evidence row count is invalid"
                }
                $cycleProperties = @(
                    "cycle", "mutation", "route_metric", "process_id", "interface_guid", "interface_luid",
                    "interface_index", "managed_plane_sha256", "strict_route_wfp_sha256", "wfp_sampled",
                    "session_generation", "network_generation", "reset_started", "reset_succeeded",
                    "reset_failed", "full_rebuild", "strict_route_effective"
                )
                $sampledRows = 0
                $resetStartedBaseline = $null
                $resetSucceededBaseline = $null
                $resetFailedBaseline = $null
                $fullRebuildBaseline = $null
                foreach ($offset in 0..($ExpectedCycles - 1)) {
                    $cycle = $offset + 1
                    $row = $cycleLines[$offset] | ConvertFrom-Json -ErrorAction Stop
                    Assert-ClosedProperties $row $cycleProperties "network-reset cycle evidence row"
                    $expectedMetric = if ($cycle -eq 1 -or ($cycle % 2) -ne 0) { 4094 } else { 4095 }
                    $expectedMutation = if ($cycle -eq 1) { "create" } else { "metric_toggle" }
                    $expectedSample = $cycle -eq 1 -or $cycle -eq $ExpectedCycles -or
                        ($cycle % $sampleStride) -eq 0
                    if ($row.wfp_sampled -eq $true) { $sampledRows++ }
                    if ($cycle -eq 1) {
                        $resetStartedBaseline = [double]$row.reset_started - 1
                        $resetSucceededBaseline = [double]$row.reset_succeeded - 1
                        $resetFailedBaseline = [double]$row.reset_failed
                        $fullRebuildBaseline = [double]$row.full_rebuild
                    }
                    if (-not (Test-JsonInteger $row.cycle) -or [long]$row.cycle -ne $cycle -or
                        $row.mutation -cne $expectedMutation -or
                        -not (Test-JsonInteger $row.route_metric) -or [long]$row.route_metric -ne $expectedMetric -or
                        -not (Test-JsonInteger $row.process_id) -or [long]$row.process_id -ne [long]$baseline.process_id -or
                        $row.interface_guid -cne $baseline.interface_guid -or
                        $row.interface_luid -cne $baseline.interface_luid -or
                        -not (Test-JsonInteger $row.interface_index) -or
                        [long]$row.interface_index -ne [long]$baseline.interface_index -or
                        $row.managed_plane_sha256 -cne $baseline.managed_plane_sha256 -or
                        $row.strict_route_wfp_sha256 -cne $baseline.strict_route_wfp_sha256 -or
                        $row.wfp_sampled -isnot [bool] -or $row.wfp_sampled -ne $expectedSample -or
                        -not (Test-JsonNumber $row.session_generation) -or
                        [double]$row.session_generation -ne [double]$summary.initial_session_generation + $cycle -or
                        -not (Test-JsonNumber $row.network_generation) -or
                        [double]$row.network_generation -ne [double]$row.session_generation -or
                        -not (Test-JsonNumber $row.reset_started) -or
                        [double]$row.reset_started -ne $resetStartedBaseline + $cycle -or
                        -not (Test-JsonNumber $row.reset_succeeded) -or
                        [double]$row.reset_succeeded -ne $resetSucceededBaseline + $cycle -or
                        -not (Test-JsonNumber $row.reset_failed) -or [double]$row.reset_failed -ne $resetFailedBaseline -or
                        -not (Test-JsonNumber $row.full_rebuild) -or [double]$row.full_rebuild -ne $fullRebuildBaseline -or
                        -not (Test-JsonNumber $row.strict_route_effective) -or
                        [double]$row.strict_route_effective -ne 1) {
                        throw "network-reset cycle evidence values are invalid: cycle=$cycle"
                    }
                }
                if ($sampledRows + 1 -ne [long]$summary.strict_route_wfp_samples) {
                    throw "network-reset WFP sample accounting is invalid"
                }
            }

            function Assert-StagedFileIdentity {
                param(
                    [string]$Path,
                    [object]$Entry,
                    [string]$ExpectedName,
                    [long]$MinimumBytes,
                    [long]$MaximumBytes
                )
                Assert-ClosedProperties $Entry @("name", "bytes", "sha256") "staged $ExpectedName identity"
                $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                if ($item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $Entry.name -cne $ExpectedName -or
                    -not (Test-JsonInteger $Entry.bytes) -or
                    [long]$Entry.bytes -ne [long]$item.Length -or
                    $item.Length -lt $MinimumBytes -or
                    $item.Length -gt $MaximumBytes -or
                    [string]$Entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$Entry.sha256) {
                    throw "staged $ExpectedName identity is invalid"
                }
            }

            $inputPath = Join-Path $RunRoot "input"
            $exportPath = Join-Path $RunRoot "export"
            $runtimePath = Join-Path $RunRoot "runtime"
            $artifactPath = Join-Path $exportPath "artifacts"
            $setupStdout = Join-Path $exportPath "setup.stdout.log"
            $setupStderr = Join-Path $exportPath "setup.stderr.log"
            $controllerStdout = Join-Path $artifactPath "controller.stdout.log"
            $controllerStderr = Join-Path $artifactPath "controller.stderr.log"
            $cleanupStdout = Join-Path $artifactPath "cleanup.stdout.log"
            $cleanupStderr = Join-Path $artifactPath "cleanup.stderr.log"
            $controllerPath = Join-Path $inputPath "controller\qualify_windows_tun.ps1"
            $ledgerPath = Join-Path $inputPath "identity-ledger.json"
            $topologyManifestPath = Join-Path $inputPath "topology-manifest.json"
            $guestNetworkPathProbe = Join-Path $inputPath `
                "controller\get_windows_tun_guest_network_path.ps1"
            $guestNetworkPathPath = Join-Path $exportPath "guest-network-path.json"
            $wintunPath = Join-Path $inputPath "wintun-0.14.1.zip"
            $inputManifestPath = Join-Path $inputPath "staged-input.json"
            $powerShellArchive = Join-Path $inputPath "portable-pwsh.zip"
            $candidateTestDirectory = Join-Path $inputPath "artifacts"
            $runtimeLibraryDirectory = Join-Path $inputPath "runtime\vc-runtime"
            $clientBinary = Join-Path $candidateTestDirectory "ferrum2-client.exe"
            $serverBinary = Join-Path $candidateTestDirectory "ferrum2-server.exe"
            $fuzzSmokeBinary = Join-Path $candidateTestDirectory "ferrum2-tun-fuzz-smoke.exe"
            New-Item -ItemType Directory -Path $artifactPath -ErrorAction Stop | Out-Null

            $mode = $RequestedProfile
            $restartCycles = $null
            $networkResetCycles = $null
            if ($RequestedProfile -cmatch '^restart-(10|100|1000)$') {
                $restartCycles = [int]$Matches[1]
                $mode = "restart-stress"
            } elseif ($RequestedProfile -cmatch '^network-reset-(10|100|1000)$') {
                $networkResetCycles = [int]$Matches[1]
                $mode = "network-reset"
            }
            $allowedModes = @(
                "network-reset", "restart-stress", "fragments", "dual-stack-dns",
                "udp-policy", "scheduler-ring-full", "fuzz-smoke"
            )
            if ($mode -notin $allowedModes) {
                throw "guest profile dispatch rejected"
            }

            $phase = "input"
            $qualificationExit = $null
            $cleanupExit = $null
            $controllerStarted = $false
            $fuzzSmokeResult = $null
            $failurePhase = $null
            try {
                $inputItems = @(Get-Item -LiteralPath $inputPath -Force) + @(
                    Get-ChildItem -LiteralPath $inputPath -Force -Recurse
                )
                $inputFiles = @($inputItems | Where-Object { -not $_.PSIsContainer })
                $inputDirectories = @($inputItems | Where-Object { $_.PSIsContainer })
                $inputBytes = [long]($inputFiles | Measure-Object Length -Sum).Sum
                if (@($inputItems | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0 -or
                    $inputFiles.Count -lt 14 -or $inputFiles.Count -gt 16 -or
                    $inputDirectories.Count -ne 5 -or
                    $inputBytes -le 0 -or $inputBytes -gt 2147483648) {
                    throw "guest staged input boundary is invalid"
                }
                $manifestItem = Get-Item -LiteralPath $inputManifestPath -Force -ErrorAction Stop
                if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 65536 -or
                    (Get-FileHash -LiteralPath $inputManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        $ExpectedInputManifestHash) {
                    throw "guest staged input manifest identity is invalid"
                }
                $manifest = Get-Content -LiteralPath $inputManifestPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                Assert-ClosedProperties $manifest @(
                    "schema", "candidate_sha", "identity_sha256", "topology_manifest_sha256",
                    "profile", "mode",
                    "network_reset_cycles", "restart_cycles", "files", "runtime"
                ) "staged input manifest"
                Assert-ClosedProperties $manifest.files @(
                    "controller", "identity_ledger", "topology_manifest",
                    "guest_network_path_probe", "wintun_zip", "client", "server",
                    "client_tests", "tun_tests", "wintun_tests", "fuzz_smoke", "powershell_archive"
                ) "staged input file manifest"
                Assert-ClosedProperties $manifest.runtime @(
                    "rust_version", "powershell_version", "powershell_executable_sha256",
                    "powershell_file_count", "powershell_expanded_bytes", "vc_libraries"
                ) "staged runtime manifest"
                if ($manifest.schema -cne "ferrum2.windows-tun.hyperv-staged-input.v3" -or
                    $manifest.candidate_sha -cne $CandidateSha -or
                    $manifest.identity_sha256 -cne $ExpectedLedgerHash -or
                    $manifest.topology_manifest_sha256 -cne $ExpectedTopologyManifestHash -or
                    $manifest.profile -cne $RequestedProfile -or $manifest.mode -cne $mode -or
                    ($null -eq $networkResetCycles -and $null -ne $manifest.network_reset_cycles) -or
                    ($null -ne $networkResetCycles -and
                        (-not (Test-JsonInteger $manifest.network_reset_cycles) -or
                            [long]$manifest.network_reset_cycles -ne [long]$networkResetCycles)) -or
                    ($null -eq $restartCycles -and $null -ne $manifest.restart_cycles) -or
                    ($null -ne $restartCycles -and
                        (-not (Test-JsonInteger $manifest.restart_cycles) -or
                            [long]$manifest.restart_cycles -ne [long]$restartCycles)) -or
                    [string]$manifest.runtime.rust_version -cnotmatch '^rustc 1\.97\.1 \(' -or
                    [string]$manifest.runtime.powershell_version -cne $ExpectedPowerShellVersion -or
                    [string]$manifest.runtime.powershell_executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-JsonInteger $manifest.runtime.powershell_file_count) -or
                    -not (Test-JsonInteger $manifest.runtime.powershell_expanded_bytes) -or
                    [long]$manifest.runtime.powershell_file_count -le 0 -or
                    [long]$manifest.runtime.powershell_file_count -gt 4096 -or
                    [long]$manifest.runtime.powershell_expanded_bytes -le 0 -or
                    [long]$manifest.runtime.powershell_expanded_bytes -gt 1073741824) {
                    throw "guest staged input manifest binding is invalid"
                }
                $fileChecks = @(
                    @($controllerPath, $manifest.files.controller, "qualify_windows_tun.ps1", 1, 4194304),
                    @($ledgerPath, $manifest.files.identity_ledger, "identity-ledger.json", 2, 65536),
                    @($topologyManifestPath, $manifest.files.topology_manifest, "topology-manifest.json", 2, 131072),
                    @($guestNetworkPathProbe, $manifest.files.guest_network_path_probe, "get_windows_tun_guest_network_path.ps1", 2, 4194304),
                    @($wintunPath, $manifest.files.wintun_zip, "wintun-0.14.1.zip", 1, 16777216),
                    @($clientBinary, $manifest.files.client, "ferrum2-client.exe", 4096, 536870912),
                    @($serverBinary, $manifest.files.server, "ferrum2-server.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-client-tests.exe"), $manifest.files.client_tests, "ferrum2-client-tests.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-tun-tests.exe"), $manifest.files.tun_tests, "ferrum2-tun-tests.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-wintun-tests.exe"), $manifest.files.wintun_tests, "ferrum2-wintun-tests.exe", 4096, 536870912),
                    @($fuzzSmokeBinary, $manifest.files.fuzz_smoke, "ferrum2-tun-fuzz-smoke.exe", 4096, 536870912),
                    @($powerShellArchive, $manifest.files.powershell_archive, "portable-pwsh.zip", 1, 536870912)
                )
                foreach ($check in $fileChecks) {
                    Assert-StagedFileIdentity $check[0] $check[1] $check[2] $check[3] $check[4]
                }
                if ([string]$manifest.files.identity_ledger.sha256 -cne $ExpectedLedgerHash -or
                    [string]$manifest.files.topology_manifest.sha256 -cne
                        $ExpectedTopologyManifestHash -or
                    [string]$manifest.files.guest_network_path_probe.sha256 -cne
                        $ExpectedGuestNetworkPathProbeHash -or
                    [string]$manifest.files.wintun_zip.sha256 -cne $ExpectedWintunHash -or
                    [string]$manifest.files.powershell_archive.sha256 -cne
                        $ExpectedPowerShellZipHash) {
                    throw "guest staged archive or identity hash mismatch"
                }
                $ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                if ($ledger.schema -ne 2 -or
                    $ledger.candidate_sha -cne $CandidateSha -or
                    $ledger.topology.manifest_sha256 -cne $ExpectedTopologyManifestHash -or
                    $ledger.probe_sha256 -cne [string]$manifest.files.controller.sha256 -or
                    $ledger.client_sha256 -cne [string]$manifest.files.client.sha256 -or
                    $ledger.server_sha256 -cne [string]$manifest.files.server.sha256 -or
                    $ledger.test_binaries.client -cne [string]$manifest.files.client_tests.sha256 -or
                    $ledger.test_binaries.tun -cne [string]$manifest.files.tun_tests.sha256 -or
                    $ledger.test_binaries.wintun -cne [string]$manifest.files.wintun_tests.sha256) {
                    throw "guest candidate ledger binding failed"
                }
                $guestNetworkPathItem = Get-Item -LiteralPath $guestNetworkPathPath `
                    -Force -ErrorAction Stop
                if ($guestNetworkPathItem.PSIsContainer -or
                    ($guestNetworkPathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $guestNetworkPathItem.Length -lt 2 -or
                    $guestNetworkPathItem.Length -gt 65536 -or
                    (Get-FileHash -LiteralPath $guestNetworkPathPath -Algorithm SHA256).
                        Hash.ToLowerInvariant() -cne $ExpectedGuestNetworkPathHash) {
                    throw "guest network-path evidence identity is invalid"
                }
                $guestNetworkPath = Get-Content -LiteralPath $guestNetworkPathPath `
                    -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
                Assert-ClosedProperties $guestNetworkPath @(
                    "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
                    "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
                    "guest_interface_mtu_bytes", "guest_mac_address", "guest_route_prefix",
                    "guest_route_next_hop", "guest_dns_servers"
                ) "guest network path"
                if ($guestNetworkPath.schema -ne 2 -or
                    [string]$guestNetworkPath.support_ipv4 -cne
                        [string]$ledger.topology.support_host_ipv4 -or
                    [string]$guestNetworkPath.guest_ipv4 -cne
                        [string]$ledger.topology.guest_ipv4 -or
                    [int]$guestNetworkPath.guest_prefix_length -ne
                        [int]$ledger.topology.support_prefix_length -or
                    [int]$guestNetworkPath.guest_interface_index -ne
                        [int]$ledger.topology.guest_interface_index -or
                    [string]$guestNetworkPath.guest_interface_alias -cne
                        [string]$ledger.topology.guest_interface_alias -or
                    [string]$guestNetworkPath.guest_interface_guid -cne
                        [string]$ledger.topology.guest_interface_guid -or
                    [int]$guestNetworkPath.guest_interface_mtu_bytes -ne
                        [int]$ledger.topology.guest_mtu_bytes -or
                    [string]$guestNetworkPath.guest_mac_address -cne
                        [string]$ledger.topology.guest_mac_address -or
                    [string]$guestNetworkPath.guest_route_prefix -cne
                        [string]$ledger.topology.support_network -or
                    [string]$guestNetworkPath.guest_route_next_hop -cne "0.0.0.0" -or
                    @($guestNetworkPath.guest_dns_servers).Count -ne 0) {
                    throw "guest network-path evidence does not match the identity ledger"
                }

                $vcEntries = @($manifest.runtime.vc_libraries)
                $allowedVcNames = @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
                if ($vcEntries.Count -lt 1 -or $vcEntries.Count -gt 3 -or
                    $vcEntries[0].name -cne "vcruntime140.dll" -or
                    (@($vcEntries | ForEach-Object { $_.name } | Select-Object -Unique)).Count -ne
                        $vcEntries.Count -or
                    @($vcEntries | Where-Object { $allowedVcNames -cnotcontains $_.name }).Count -ne 0) {
                    throw "guest Visual C++ runtime manifest is invalid"
                }
                foreach ($entry in $vcEntries) {
                    $vcPath = Join-Path $runtimeLibraryDirectory ([string]$entry.name)
                    Assert-StagedFileIdentity $vcPath $entry ([string]$entry.name) 1 16777216
                }
                $expectedInputFiles = @(
                    $controllerPath,
                    $ledgerPath,
                    $topologyManifestPath,
                    $guestNetworkPathProbe,
                    $wintunPath,
                    $inputManifestPath,
                    $powerShellArchive,
                    $clientBinary,
                    $serverBinary,
                    (Join-Path $candidateTestDirectory "ferrum2-client-tests.exe"),
                    (Join-Path $candidateTestDirectory "ferrum2-tun-tests.exe"),
                    (Join-Path $candidateTestDirectory "ferrum2-wintun-tests.exe"),
                    $fuzzSmokeBinary
                ) + @($vcEntries | ForEach-Object {
                    Join-Path $runtimeLibraryDirectory ([string]$_.name)
                })
                $expectedInputDirectories = @(
                    $inputPath,
                    (Join-Path $inputPath "controller"),
                    $candidateTestDirectory,
                    (Join-Path $inputPath "runtime"),
                    $runtimeLibraryDirectory
                )
                if ($inputFiles.Count -ne $expectedInputFiles.Count -or
                    @($inputFiles | Where-Object {
                        $actualPath = $_.FullName
                        @($expectedInputFiles | Where-Object {
                            $actualPath.Equals($_, [StringComparison]::OrdinalIgnoreCase)
                        }).Count -ne 1
                    }).Count -ne 0 -or
                    $inputDirectories.Count -ne $expectedInputDirectories.Count -or
                    @($inputDirectories | Where-Object {
                        $actualPath = $_.FullName.TrimEnd('\', '/')
                        @($expectedInputDirectories | Where-Object {
                            $actualPath.Equals(
                                ([IO.Path]::GetFullPath($_).TrimEnd('\', '/')),
                                [StringComparison]::OrdinalIgnoreCase
                            )
                        }).Count -ne 1
                    }).Count -ne 0) {
                    throw "guest staged input path set is not closed"
                }
                $env:Path = "$runtimeLibraryDirectory;$env:Path"

                $phase = "runtime"
                if (Test-Path -LiteralPath $runtimePath) {
                    throw "guest portable runtime baseline is not absent"
                }
                Expand-Archive `
                    -LiteralPath $powerShellArchive `
                    -DestinationPath (Join-Path $runtimePath "pwsh") `
                    -ErrorAction Stop
                $expandedItems = @(
                    Get-ChildItem -LiteralPath (Join-Path $runtimePath "pwsh") -Force -Recurse
                )
                $expandedFiles = @($expandedItems | Where-Object { -not $_.PSIsContainer })
                $expandedBytes = [long]($expandedFiles | Measure-Object Length -Sum).Sum
                if (@($expandedItems | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0 -or
                    $expandedFiles.Count -ne [long]$manifest.runtime.powershell_file_count -or
                    $expandedBytes -ne [long]$manifest.runtime.powershell_expanded_bytes) {
                    throw "expanded PowerShell runtime boundary is invalid"
                }
                $pwsh = Join-Path $runtimePath "pwsh\pwsh.exe"
                $pwshItem = Get-Item -LiteralPath $pwsh -Force -ErrorAction Stop
                if ($pwshItem.PSIsContainer -or
                    ($pwshItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$manifest.runtime.powershell_executable_sha256) {
                    throw "staged PowerShell executable identity is invalid"
                }
                $pwshVersion = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>> $setupStderr)
                if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
                    [string]$pwshVersion[0] -cne [string]$manifest.runtime.powershell_version -or
                    [string]$pwshVersion[0] -cne $ExpectedPowerShellVersion) {
                    throw "staged PowerShell runtime verification failed"
                }
                [IO.File]::WriteAllText(
                    $setupStdout,
                    "host_built_artifacts=verified`npowershell_version=$($pwshVersion[0])`n",
                    [Text.UTF8Encoding]::new($false)
                )

                if ($mode -ceq "fuzz-smoke") {
                    $phase = "fuzz-smoke"
                    $fuzzStdout = Join-Path $exportPath "fuzz-smoke.stdout.log"
                    $fuzzStderr = Join-Path $exportPath "fuzz-smoke.stderr.log"
                    $fuzzResultPath = Join-Path $exportPath "fuzz-smoke-result.json"
                    $qualificationExit = Invoke-LoggedCommand `
                        -Executable $fuzzSmokeBinary `
                        -Arguments @() `
                        -StdoutPath $fuzzStdout `
                        -StderrPath $fuzzStderr
                    $fuzzStdoutLines = @(Get-Content -LiteralPath $fuzzStdout -ErrorAction Stop)
                    $fuzzStderrItem = Get-Item -LiteralPath $fuzzStderr -Force -ErrorAction Stop
                    $expectedFuzzTerminal = "TUN state smoke corpora: 4 packet, 3 UDP reset, 8 config legacy, and 8 strict-route seeds passed"
                    if ($qualificationExit -ne 0 -or $fuzzStdoutLines.Count -ne 1 -or
                        [string]$fuzzStdoutLines[0] -cne $expectedFuzzTerminal -or
                        $fuzzStderrItem.Length -ne 0) {
                        throw "guest Windows TUN fuzz smoke evidence is invalid"
                    }
                    $fuzzSmokeResult = [ordered]@{
                        schema = "ferrum2.windows-tun.fuzz-smoke-result.v2"
                        status = "pass"
                        run_token = $Token
                        candidate_sha = $CandidateSha
                        identity_sha256 = $ExpectedLedgerHash
                        staged_input_sha256 = $ExpectedInputManifestHash
                        binary_sha256 = [string]$manifest.files.fuzz_smoke.sha256
                        binary_bytes = [long]$manifest.files.fuzz_smoke.bytes
                        packet_seed_count = 4
                        udp_reset_seed_count = 3
                        config_legacy_seed_count = 8
                        strict_route_seed_count = 8
                        terminal = $expectedFuzzTerminal
                        stdout_sha256 = (Get-FileHash -LiteralPath $fuzzStdout -Algorithm SHA256).Hash.ToLowerInvariant()
                        stderr_sha256 = (Get-FileHash -LiteralPath $fuzzStderr -Algorithm SHA256).Hash.ToLowerInvariant()
                        finished_utc = [DateTime]::UtcNow.ToString("o")
                    }
                    Write-GuestJsonNew -Path $fuzzResultPath -Value $fuzzSmokeResult
                    $fuzzSmokeResult = Get-Content -LiteralPath $fuzzResultPath -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    Assert-ClosedProperties $fuzzSmokeResult @(
                        "schema", "status", "run_token", "candidate_sha", "identity_sha256", "staged_input_sha256",
                        "binary_sha256", "binary_bytes", "packet_seed_count", "udp_reset_seed_count",
                        "config_legacy_seed_count", "strict_route_seed_count",
                        "terminal", "stdout_sha256", "stderr_sha256", "finished_utc"
                    ) "fuzz smoke result"
                    if ($fuzzSmokeResult.schema -cne "ferrum2.windows-tun.fuzz-smoke-result.v2" -or
                        $fuzzSmokeResult.status -cne "pass" -or $fuzzSmokeResult.run_token -cne $Token -or
                        $fuzzSmokeResult.candidate_sha -cne $CandidateSha -or
                        $fuzzSmokeResult.identity_sha256 -cne $ExpectedLedgerHash -or
                        $fuzzSmokeResult.staged_input_sha256 -cne $ExpectedInputManifestHash -or
                        $fuzzSmokeResult.binary_sha256 -cne [string]$manifest.files.fuzz_smoke.sha256 -or
                        -not (Test-JsonInteger $fuzzSmokeResult.binary_bytes) -or
                        [long]$fuzzSmokeResult.binary_bytes -ne [long]$manifest.files.fuzz_smoke.bytes -or
                        -not (Test-JsonInteger $fuzzSmokeResult.packet_seed_count) -or
                        [long]$fuzzSmokeResult.packet_seed_count -ne 4 -or
                        -not (Test-JsonInteger $fuzzSmokeResult.udp_reset_seed_count) -or
                        [long]$fuzzSmokeResult.udp_reset_seed_count -ne 3 -or
                        -not (Test-JsonInteger $fuzzSmokeResult.config_legacy_seed_count) -or
                        [long]$fuzzSmokeResult.config_legacy_seed_count -ne 8 -or
                        -not (Test-JsonInteger $fuzzSmokeResult.strict_route_seed_count) -or
                        [long]$fuzzSmokeResult.strict_route_seed_count -ne 8 -or
                        $fuzzSmokeResult.terminal -cne $expectedFuzzTerminal -or
                        $fuzzSmokeResult.stdout_sha256 -cne (Get-FileHash -LiteralPath $fuzzStdout -Algorithm SHA256).Hash.ToLowerInvariant() -or
                        $fuzzSmokeResult.stderr_sha256 -cne (Get-FileHash -LiteralPath $fuzzStderr -Algorithm SHA256).Hash.ToLowerInvariant()) {
                        throw "guest Windows TUN fuzz smoke result readback is invalid"
                    }
                } else {
                    $phase = "qualification"
                    $controllerArguments = @(
                        "-NoProfile", "-File", $controllerPath,
                        "-Mode", $mode,
                        "-RunToken", $Token,
                        "-IdentityLedger", $ledgerPath,
                        "-TopologyManifest", $topologyManifestPath,
                        "-GuestNetworkPath", $guestNetworkPathPath,
                        "-ClientBinary", $clientBinary,
                        "-ServerBinary", $serverBinary,
                        "-WintunZip", $wintunPath,
                        "-CandidateTestDirectory", $candidateTestDirectory,
                        "-RuntimeLibraryDirectory", $runtimeLibraryDirectory,
                        "-ProductRoot", $RunRoot,
                        "-ArtifactDirectory", $artifactPath
                    )
                    if ($mode -ceq "restart-stress") {
                        $controllerArguments += @("-RestartCycles", [string]$restartCycles)
                    } elseif ($mode -ceq "network-reset") {
                        $controllerArguments += @("-NetworkResetCycles", [string]$networkResetCycles)
                    }
                    $controllerStarted = $true
                    $qualificationExit = Invoke-LoggedCommand `
                        -Executable $pwsh `
                        -Arguments $controllerArguments `
                        -StdoutPath $controllerStdout `
                        -StderrPath $controllerStderr
                }
            } catch {
                $failurePhase = $phase
            } finally {
                if ($controllerStarted) {
                    $phase = "cleanup"
                    try {
                        $cleanupExit = Invoke-LoggedCommand `
                            -Executable $pwsh `
                            -Arguments @(
                                "-NoProfile", "-File", $controllerPath,
                                "-Mode", "cleanup",
                                "-RunToken", $Token,
                                "-ClientBinary", $clientBinary,
                                "-ServerBinary", $serverBinary,
                                "-ProductRoot", $RunRoot,
                                "-RuntimeLibraryDirectory", $runtimeLibraryDirectory,
                                "-ArtifactDirectory", $artifactPath
                            ) `
                            -StdoutPath $cleanupStdout `
                            -StderrPath $cleanupStderr
                    } catch {
                        $cleanupExit = -1
                        if ($null -eq $failurePhase) {
                            $failurePhase = "cleanup"
                        }
                    }
                }
            }

            $status = "fail"
            if ($mode -ceq "fuzz-smoke") {
                if ($null -eq $failurePhase -and $qualificationExit -eq 0 -and
                    $null -eq $cleanupExit -and $null -ne $fuzzSmokeResult -and
                    $fuzzSmokeResult.status -ceq "pass") {
                    $status = "pass"
                }
            } elseif ($null -eq $failurePhase -and $qualificationExit -eq 0 -and $cleanupExit -eq 0) {
                $requiredArtifacts = @(
                    "identity-ledger.json", "m17-contract.json", "m17-result.json", "external-cleanup.json"
                )
                $missing = @($requiredArtifacts | Where-Object {
                    -not (Test-Path -LiteralPath (Join-Path $artifactPath $_) -PathType Leaf)
                })
                if ($missing.Count -eq 0) {
                    $contract = Get-Content -LiteralPath (Join-Path $artifactPath "m17-contract.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    $result = Get-Content -LiteralPath (Join-Path $artifactPath "m17-result.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    $cleanup = Get-Content -LiteralPath (Join-Path $artifactPath "external-cleanup.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -ErrorAction Stop
                    Assert-ClosedProperties $contract @(
                        "schema", "status", "mode", "network_reset_cycles", "restart_cycles",
                        "approved_vm_name", "approved_vm_id", "approved_checkpoint_name",
                        "approved_checkpoint_id", "guest_build", "identity_sha256", "candidate_sha",
                        "client_sha256", "server_sha256", "controller_sha256", "wintun_zip_sha256",
                        "wintun_dll_sha256", "test_binaries", "topology", "guest_network_path",
                        "fixtures", "witnesses", "counters"
                    ) "M17 contract"
                    Assert-ClosedProperties $result @(
                        "schema", "status", "mode", "run_token", "network_reset_cycles", "restart_cycles",
                        "approved_vm_name", "approved_vm_id", "approved_checkpoint_name",
                        "approved_checkpoint_id", "guest_build", "identity_sha256", "candidate_sha",
                        "client_sha256", "server_sha256", "controller_sha256", "wintun_zip_sha256",
                        "wintun_dll_sha256", "test_binaries", "topology", "guest_network_path",
                        "started_utc", "finished_utc", "fixtures",
                        "processes", "live_checks", "deterministic_tests", "witnesses", "counters_before",
                        "counters_after", "cleanup", "failure"
                    ) "M17 result"
                    $expectedRestartCycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
                    $expectedNetworkResetCycles = if ($mode -ceq "network-reset") { [long]$networkResetCycles } else { $null }
                    $testKeys = @("client", "tun", "wintun")
                    Assert-ClosedProperties $contract.test_binaries $testKeys "M17 contract test binaries"
                    Assert-ClosedProperties $result.test_binaries $testKeys "M17 result test binaries"
                    $testHashesMatch = $true
                    foreach ($name in $testKeys) {
                        $manifestEntry = switch ($name) {
                            "client" { $manifest.files.client_tests }
                            "tun" { $manifest.files.tun_tests }
                            "wintun" { $manifest.files.wintun_tests }
                        }
                        if ([string]$contract.test_binaries.$name -cne [string]$manifestEntry.sha256 -or
                            [string]$result.test_binaries.$name -cne [string]$manifestEntry.sha256) {
                            $testHashesMatch = $false
                        }
                    }
                    $restartCyclesMatch = if ($null -eq $expectedRestartCycles) {
                        $null -eq $contract.restart_cycles -and $null -eq $result.restart_cycles
                    } else {
                        (Test-JsonInteger $contract.restart_cycles) -and
                        (Test-JsonInteger $result.restart_cycles) -and
                        [long]$contract.restart_cycles -eq $expectedRestartCycles -and
                        [long]$result.restart_cycles -eq $expectedRestartCycles
                    }
                    $networkResetCyclesMatch = if ($null -eq $expectedNetworkResetCycles) {
                        $null -eq $contract.network_reset_cycles -and $null -eq $result.network_reset_cycles
                    } else {
                        (Test-JsonInteger $contract.network_reset_cycles) -and
                        (Test-JsonInteger $result.network_reset_cycles) -and
                        [long]$contract.network_reset_cycles -eq $expectedNetworkResetCycles -and
                        [long]$result.network_reset_cycles -eq $expectedNetworkResetCycles
                    }
                    Assert-ClosedProperties $result.cleanup @(
                        "status", "processes", "adapters", "sibling_dll", "work_directory",
                        "cleanup_failure_type"
                    ) "M17 internal cleanup"
                    Assert-ClosedProperties $cleanup @(
                        "schema", "status", "run_token", "source_mode", "identity_sha256",
                        "processes", "adapters", "target_addresses", "target_routes",
                        "sibling_dll", "work_directories", "mutation_journals",
                        "identity_journal", "finished_utc"
                    ) "M17 external cleanup"
                    $internalCleanupZero = @(
                        "processes", "adapters", "sibling_dll", "work_directory"
                    ) | Where-Object {
                        -not (Test-JsonInteger $result.cleanup.$_) -or
                        [long]$result.cleanup.$_ -ne 0
                    }
                    $externalCleanupZero = @(
                        "processes", "adapters", "target_addresses", "target_routes",
                        "sibling_dll", "work_directories", "mutation_journals", "identity_journal"
                    ) | Where-Object {
                        -not (Test-JsonInteger $cleanup.$_) -or
                        [long]$cleanup.$_ -ne 0
                    }
                    $contractWitnesses = @($contract.witnesses | Sort-Object)
                    $resultWitnesses = @($result.witnesses)
                    $resultWitnessNames = @($resultWitnesses | ForEach-Object {
                        if ($_.status -cne "pass") { throw "M17 result contains a failed witness" }
                        [string]$_.name
                    } | Sort-Object)
                    $expectedWitnessCount = switch ($mode) {
                        "network-reset" { 15 }
                        "restart-stress" { 5 }
                        "fragments" { 9 }
                        "dual-stack-dns" { 7 }
                        "udp-policy" { 18 }
                        "scheduler-ring-full" { 8 }
                        default { throw "M17 result mode has no closed witness count" }
                    }
                    $networkResetWitnessesMatch = $true
                    if ($mode -ceq "network-reset") {
                        $expectedNetworkResetWitnesses = @(
                            "ordinary_route_notifications_reset_network_runtime",
                            "same_process_and_managed_adapter_identity",
                            "managed_addresses_routes_and_dns_are_unchanged",
                            "strict_route_is_effective_and_filter_identity_is_unchanged",
                            "network_generation_and_reset_metrics_advance",
                            "retry_reset_failure_and_full_rebuild_metrics_are_unchanged",
                            "fixed_and_direct_dual_stack_underlay_binding",
                            "multihoming_prefix_and_metric_selection",
                            "route_interface_and_address_notifications",
                            "foreign_route_state_survives_cleanup",
                            "foreign_address_state_survives_cleanup",
                            "dad_failure_rolls_back_in_reverse",
                            "owned_state_damage_is_the_only_full_rebuild_trigger",
                            "reset_retries_without_managed_teardown",
                            "network_reset_hooks_accept_each_generation_once"
                        ) | Sort-Object
                        $networkResetWitnessesMatch = ($contractWitnesses -join "|") -ceq
                            ($expectedNetworkResetWitnesses -join "|")
                    }
                    $witnessesMatch = $contractWitnesses.Count -eq $expectedWitnessCount -and
                        $resultWitnesses.Count -eq $expectedWitnessCount -and
                        $networkResetWitnessesMatch -and
                        ($contractWitnesses -join "|") -ceq ($resultWitnessNames -join "|")
                    $deterministicTests = @($result.deterministic_tests)
                    $expectedTestCount = switch ($mode) {
                        "network-reset" { 16 }
                        "restart-stress" { 4 }
                        "fragments" { 9 }
                        "dual-stack-dns" { 2 }
                        "udp-policy" { 9 }
                        "scheduler-ring-full" { 8 }
                        default { throw "M17 result mode has no closed exact-test count" }
                    }
                    foreach ($test in $deterministicTests) {
                        Assert-ClosedProperties $test @(
                            "package", "test", "status", "runner", "duration_ms",
                            "stdout_sha256", "stderr_sha256"
                        ) "M17 deterministic test"
                    }
                    $testsPassed = $deterministicTests.Count -eq $expectedTestCount -and
                        @($deterministicTests | Where-Object { $_.status -cne "pass" }).Count -eq 0
                    if ($mode -ceq "network-reset") {
                        $expectedNetworkResetTests = @(
                            "ferrum2-wintun|windows::tests::dual_stack_target_binding_selects_actual_target_and_rejects_tun",
                            "ferrum2-wintun|windows::tests::target_binding_excludes_tun_and_orders_prefix_then_effective_metric",
                            "ferrum2-wintun|windows::tests::network_change_notifications_cover_each_callback_and_runtime_owned_events",
                            "ferrum2-wintun|windows::tests::managed_route_cleanup_preserves_replacements_and_audits_every_delete",
                            "ferrum2-wintun|windows::tests::managed_address_readback_and_cleanup_are_exact_and_foreign_safe",
                            "ferrum2-wintun|windows::tests::dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit",
                            "ferrum2-wintun|windows::tests::managed_state_health_reports_owned_route_dns_and_strict_route_damage",
                            "ferrum2-wintun|windows::tests::strict_route_health_reads_every_exact_filter_id_and_rejects_damage",
                            "ferrum2-wintun|windows::tests::network_change_revalidates_underlay_and_owned_routes_before_shutdown",
                            "ferrum2-wintun|windows::tests::windows_catalog_is_family_aware_and_marks_the_exact_managed_tun",
                            "ferrum2-wintun|windows::tests::resolved_socket_binding_applies_interface_then_family_source",
                            "ferrum2-tun|tests::only_managed_damage_escalates_a_network_change_to_full_rebuild",
                            "ferrum2-tun|tests::reset_retries_transient_readback_errors_without_tearing_down_managed_state",
                            "ferrum2-tun|tests::network_lifecycle_bridge_reports_retry_before_completion",
                            "ferrum2-tun|tests::session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state",
                            "ferrum2-client|run::tun::tests::client_network_hook_retries_failure_and_accepts_each_generation_once"
                        ) | Sort-Object
                        $actualNetworkResetTests = @($deterministicTests | ForEach-Object {
                            "$($_.package)|$($_.test)"
                        } | Sort-Object)
                        if (($actualNetworkResetTests -join "`n") -cne
                            ($expectedNetworkResetTests -join "`n")) {
                            throw "network-reset exact test set is invalid"
                        }
                        Assert-NetworkResetEvidence `
                            -Result $result `
                            -ArtifactPath $artifactPath `
                            -ExpectedCycles ([int]$expectedNetworkResetCycles)
                    }
                    $terminalLines = @(Get-Content -LiteralPath $controllerStdout -ErrorAction Stop |
                        Where-Object { $_ -cmatch '^m17_windows_tun status=PASS ' })
                    $expectedTerminal = "m17_windows_tun status=PASS mode=$mode " +
                        "witnesses=$($resultWitnesses.Count)/$($contractWitnesses.Count) " +
                        "exact_tests=$($deterministicTests.Count) cleanup=PASS run_token=$Token " +
                        "candidate_sha=$CandidateSha artifact=$(Join-Path $artifactPath 'm17-result.json')"
                    $identityMatches = $contract.approved_vm_name -ceq $ledger.vm_name -and
                        $contract.approved_vm_id -ceq $ledger.vm_id -and
                        $contract.approved_checkpoint_name -ceq $ledger.checkpoint_name -and
                        $contract.approved_checkpoint_id -ceq $ledger.checkpoint_id -and
                        $result.approved_vm_name -ceq $ledger.vm_name -and
                        $result.approved_vm_id -ceq $ledger.vm_id -and
                        $result.approved_checkpoint_name -ceq $ledger.checkpoint_name -and
                        $result.approved_checkpoint_id -ceq $ledger.checkpoint_id
                    $binaryHashesMatch = $contract.candidate_sha -ceq $CandidateSha -and
                        $result.candidate_sha -ceq $CandidateSha -and
                        $contract.client_sha256 -ceq [string]$manifest.files.client.sha256 -and
                        $result.client_sha256 -ceq [string]$manifest.files.client.sha256 -and
                        $contract.server_sha256 -ceq [string]$manifest.files.server.sha256 -and
                        $result.server_sha256 -ceq [string]$manifest.files.server.sha256 -and
                        $contract.controller_sha256 -ceq [string]$manifest.files.controller.sha256 -and
                        $result.controller_sha256 -ceq [string]$manifest.files.controller.sha256 -and
                        $contract.wintun_zip_sha256 -ceq $ExpectedWintunHash -and
                        $result.wintun_zip_sha256 -ceq $ExpectedWintunHash -and
                        $contract.wintun_dll_sha256 -ceq $ExpectedWintunDllHash -and
                        $result.wintun_dll_sha256 -ceq $ExpectedWintunDllHash
                    $m17TopologyMatches =
                        ($contract.topology | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($ledger.topology | ConvertTo-Json -Compress -Depth 5) -and
                        ($result.topology | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($ledger.topology | ConvertTo-Json -Compress -Depth 5)
                    $m17GuestPathMatches =
                        ($contract.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5) -and
                        ($result.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
                            ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5)
                    if ($contract.schema -ceq "ferrum2.windows-tun.m17-contract.v2" -and
                        $contract.status -ceq "preflight_pass" -and $contract.mode -ceq $mode -and
                        $contract.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $contract.guest_build -ceq $ledger.guest_build -and
                        $result.schema -ceq "ferrum2.windows-tun.m17-result.v2" -and
                        $result.status -ceq "pass" -and $result.mode -ceq $mode -and
                        $result.run_token -ceq $Token -and
                        $result.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $result.guest_build -ceq $ledger.guest_build -and
                        $null -eq $result.failure -and $restartCyclesMatch -and $networkResetCyclesMatch -and
                        $identityMatches -and $binaryHashesMatch -and $testHashesMatch -and
                        $m17TopologyMatches -and $m17GuestPathMatches -and
                        $witnessesMatch -and $testsPassed -and
                        $result.cleanup.status -ceq "pass" -and
                        $null -eq $result.cleanup.cleanup_failure_type -and
                        @($internalCleanupZero).Count -eq 0 -and
                        $cleanup.schema -ceq "ferrum2.windows-tun.m17-external-cleanup.v1" -and
                        $cleanup.status -ceq "pass" -and $cleanup.run_token -ceq $Token -and
                        $cleanup.source_mode -ceq $mode -and
                        $cleanup.identity_sha256 -ceq $ExpectedLedgerHash -and
                        @($externalCleanupZero).Count -eq 0 -and
                        $terminalLines.Count -eq 1 -and $terminalLines[0] -ceq $expectedTerminal) {
                        $status = "pass"
                    } else {
                        $failurePhase = "evidence-readback"
                    }
                } else {
                    $failurePhase = "evidence-readback"
                }
            }
            if ($status -cne "pass" -and $null -eq $failurePhase) {
                $failurePhase = if ($mode -ceq "fuzz-smoke") {
                    "fuzz-smoke"
                } elseif ($qualificationExit -ne 0) {
                    "qualification"
                } else {
                    "cleanup"
                }
            }

            $guestResult = [ordered]@{
                schema = "ferrum2.windows-tun.hyperv-guest-run.v4"
                status = $status
                profile = $RequestedProfile
                mode = $mode
                restart_cycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
                network_reset_cycles = if ($mode -ceq "network-reset") { [long]$networkResetCycles } else { $null }
                run_token = $Token
                candidate_sha = $CandidateSha
                identity_sha256 = $ExpectedLedgerHash
                staged_input_sha256 = $ExpectedInputManifestHash
                topology_manifest_sha256 = $ExpectedTopologyManifestHash
                guest_network_path_sha256 = $ExpectedGuestNetworkPathHash
                topology = $ledger.topology
                guest_network_path = $guestNetworkPath
                qualification_exit = if ($null -eq $qualificationExit) { $null } else { [long]$qualificationExit }
                cleanup_exit = if ($null -eq $cleanupExit) { $null } else { [long]$cleanupExit }
                fuzz_smoke = if ($mode -ceq "fuzz-smoke") { $fuzzSmokeResult } else { $null }
                failure_phase = $failurePhase
                finished_utc = [DateTime]::UtcNow.ToString("o")
            }
            Write-GuestJsonNew -Path (Join-Path $exportPath "guest-run.json") -Value $guestResult
            [pscustomobject]$guestResult
        })
    # END GUEST_ONLY_EXECUTION
    if ($guestResults.Count -ne 1) {
        throw "guest execution did not return one result"
    }
    $guestResult = $guestResults[0]
    $expectedGuestMode = $requestedMode
    $expectedRestartCycles = if ($null -eq $requestedRestartCycles) {
        $null
    } else { [long]$requestedRestartCycles }
    $expectedNetworkResetCycles = if ($null -eq $requestedNetworkResetCycles) {
        $null
    } else { [long]$requestedNetworkResetCycles }
    $guestResultKeys = @(
        "schema", "status", "profile", "mode", "restart_cycles", "network_reset_cycles",
        "run_token", "candidate_sha", "identity_sha256", "staged_input_sha256",
        "topology_manifest_sha256", "guest_network_path_sha256", "topology",
        "guest_network_path",
        "qualification_exit", "cleanup_exit", "fuzz_smoke", "failure_phase", "finished_utc"
    )
    if ((@($guestResult.PSObject.Properties.Name) -join "|") -cne ($guestResultKeys -join "|")) {
        throw "guest qualification result property set is invalid"
    }
    $fuzzSmokeMatches = if ($expectedGuestMode -ceq "fuzz-smoke") {
        $fuzzResultKeys = @(
            "schema", "status", "run_token", "candidate_sha", "identity_sha256", "staged_input_sha256",
            "binary_sha256", "binary_bytes", "packet_seed_count", "udp_reset_seed_count",
            "config_legacy_seed_count", "strict_route_seed_count",
            "terminal", "stdout_sha256", "stderr_sha256", "finished_utc"
        )
        $null -ne $guestResult.fuzz_smoke -and
            (@($guestResult.fuzz_smoke.PSObject.Properties.Name) -join "|") -ceq ($fuzzResultKeys -join "|") -and
            $guestResult.fuzz_smoke.schema -ceq "ferrum2.windows-tun.fuzz-smoke-result.v2" -and
            $guestResult.fuzz_smoke.status -ceq "pass" -and
            $guestResult.fuzz_smoke.run_token -ceq $RunToken -and
            $guestResult.fuzz_smoke.candidate_sha -ceq $candidate.Sha -and
            $guestResult.fuzz_smoke.identity_sha256 -ceq $ledgerIdentity.Sha256 -and
            $guestResult.fuzz_smoke.staged_input_sha256 -ceq $stagedInputSha256 -and
            $guestResult.fuzz_smoke.binary_sha256 -ceq $candidateArtifacts.FuzzSmoke.Sha256 -and
            [long]$guestResult.fuzz_smoke.binary_bytes -eq [long]$candidateArtifacts.FuzzSmoke.Bytes -and
            [long]$guestResult.fuzz_smoke.packet_seed_count -eq 4 -and
            [long]$guestResult.fuzz_smoke.udp_reset_seed_count -eq 3 -and
            [long]$guestResult.fuzz_smoke.config_legacy_seed_count -eq 8 -and
            [long]$guestResult.fuzz_smoke.strict_route_seed_count -eq 8 -and
            $guestResult.fuzz_smoke.terminal -ceq "TUN state smoke corpora: 4 packet, 3 UDP reset, 8 config legacy, and 8 strict-route seeds passed" -and
            [string]$guestResult.fuzz_smoke.stdout_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$guestResult.fuzz_smoke.stderr_sha256 -cmatch '^[0-9a-f]{64}$'
    } else {
        $null -eq $guestResult.fuzz_smoke
    }
    $cleanupExitMatches = if ($expectedGuestMode -ceq "fuzz-smoke") {
        $null -eq $guestResult.cleanup_exit
    } else {
        $null -ne $guestResult.cleanup_exit -and [long]$guestResult.cleanup_exit -eq 0
    }
    $guestTopologyMatches = ($guestResult.topology | ConvertTo-Json -Compress -Depth 5) -ceq
        ($ledgerIdentity.Ledger.topology | ConvertTo-Json -Compress -Depth 5)
    $guestPathMatches = ($guestResult.guest_network_path | ConvertTo-Json -Compress -Depth 5) -ceq
        ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5)
    if ($guestResult.schema -cne "ferrum2.windows-tun.hyperv-guest-run.v4" -or
        $guestResult.profile -cne $Profile -or
        $guestResult.mode -cne $expectedGuestMode -or
        $guestResult.run_token -cne $RunToken -or
        $guestResult.candidate_sha -cne $candidate.Sha -or
        $guestResult.identity_sha256 -cne $ledgerIdentity.Sha256 -or
        $guestResult.staged_input_sha256 -cne $stagedInputSha256 -or
        $guestResult.topology_manifest_sha256 -cne [string]$topologyDocument.Sha256 -or
        $guestResult.guest_network_path_sha256 -cne $guestNetworkPathSha256 -or
        -not $guestTopologyMatches -or -not $guestPathMatches -or
        $null -eq $guestResult.qualification_exit -or [long]$guestResult.qualification_exit -ne 0 -or
        -not $cleanupExitMatches -or -not $fuzzSmokeMatches -or
        $null -ne $guestResult.failure_phase -or
        ($null -eq $expectedRestartCycles -and $null -ne $guestResult.restart_cycles) -or
        ($null -ne $expectedRestartCycles -and
            [long]$guestResult.restart_cycles -ne $expectedRestartCycles) -or
        ($null -eq $expectedNetworkResetCycles -and $null -ne $guestResult.network_reset_cycles) -or
        ($null -ne $expectedNetworkResetCycles -and
            [long]$guestResult.network_reset_cycles -ne $expectedNetworkResetCycles)) {
        throw "guest qualification result binding is invalid"
    }
    if ($guestResult.status -cne "pass") {
        throw "guest qualification failed in phase $($guestResult.failure_phase)"
    }
    $postGuestTopology = Get-ApprovedGuestSupportTopologyRuntimeState `
        -Session $connection.Session -TopologyDocument $topologyDocument
    if (($postGuestTopology | ConvertTo-Json -Compress -Depth 6) -cne
        ($guestSupportTopologyBaseline | ConvertTo-Json -Compress -Depth 6)) {
        throw "approved guest support topology changed during qualification"
    }
    $postPathProbe = Invoke-ApprovedGuestNetworkPathProbe `
        -Session $connection.Session `
        -GuestInputPath $guestInputPath `
        -ManagedAdapterName $guestManagedAdapterName `
        -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -RunToken $RunToken `
        -IdentityLedgerSha256 $ledgerIdentity.Sha256 `
        -TopologyDocument $topologyDocument
    $guestNetworkPathPost = $postPathProbe.path
    Assert-ApprovedGuestNetworkPathUnchanged `
        -Expected $guestNetworkPath -Actual $guestNetworkPathPost
    $postTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $postTopologyState
    $postSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $postSupportState
    $null = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPathPost `
        -VmNetworkContext $postTopologyState.VmNetwork `
        -ExpectedSupportIpv4 $supportAddress
} catch {
    $runFailure = $_
} finally {
    if ($null -ne $connection -and -not [string]::IsNullOrWhiteSpace($guestExportPath) -and
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
            if (-not (Test-PathWithinRoot -Path $resolvedTemporaryRoot -Root $temporaryBase) -or
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cnotmatch '^ferrum2-hyperv-[0-9a-f]{32}$') {
                throw "temporary staging cleanup boundary is invalid"
            }
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label "temporary staging cleanup"
            $temporaryItems = @(Get-Item -LiteralPath $resolvedTemporaryRoot -Force) + @(
                Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Force -Recurse
            )
            if (@($temporaryItems | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -ne 0) {
                throw "temporary staging cleanup cannot traverse a reparse point"
            }
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
            if ($finalVmState -cne "Off") {
                throw "approved emergency final VM state is $finalVmState"
            }
        }
    }
} catch {
    $finalizationFailures.Add("approved VM final state readback failed: $($_.Exception.Message)")
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
            if ($finalVmState -cne "Off") {
                throw "approved emergency final VM state is $finalVmState"
            }
        } catch {
            $finalizationFailures.Add(
                "approved emergency final VM state recovery failed: " +
                    $_.Exception.Message
            )
        }
    }
}
try {
    Assert-Ferrum2SupportTopologySourceUnchanged -Document $topologyDocument
    Assert-ApprovedTopologyHelperSourcesUnchanged
    $finalTopologyState = Get-ApprovedHyperVTopologyRuntimeState `
        -TopologyDocument $topologyDocument
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopologyState -Actual $finalTopologyState
} catch {
    $finalizationFailures.Add("approved topology final readback failed: $($_.Exception.Message)")
}
try {
    $finalSupportState = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $topologyDocument `
        -Address $supportAddress -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $supportHostBaseline -Actual $finalSupportState
} catch {
    $finalizationFailures.Add("support listener final readback failed: $($_.Exception.Message)")
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) { "pass" } else { "fail" }
try {
        $hostEvidenceItem = Get-Item -LiteralPath $hostEvidencePath `
            -Force -ErrorAction Stop
        if (-not $hostEvidenceItem.PSIsContainer -or
            ($hostEvidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "mandatory host evidence root is invalid"
        }
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-host-run.v4"
            status = $status
            profile = $Profile
            mode = $requestedMode
            restart_cycles = $requestedRestartCycles
            network_reset_cycles = $requestedNetworkResetCycles
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            staged_input_sha256 = $stagedInputSha256
            topology_manifest_sha256 = [string]$topologyDocument.Sha256
            topology_plan_sha256 = [string]$topologyDocument.PlanDocument.Sha256
            topology = $ledgerIdentity.Ledger.topology
            guest_network_path_sha256 = $guestNetworkPathSha256
            guest_network_path = $guestNetworkPath
            host_network_path_sha256 = $hostNetworkPathSha256
            support_listener = $ledgerIdentity.Ledger.support_listener
            protected_host_tun = if ($null -eq $finalTopologyState) {
                $null
            } else { $finalTopologyState.Runtime.ProtectedHostTun }
            topology_runtime_sha256 = $topologyRuntimeSha256
            host_network_path_helper_sha256 = $hostNetworkPathHelperSha256
            guest_network_path_probe_sha256 = $guestNetworkPathProbeSha256
            rust_version = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.RustVersion }
            fuzz_smoke_sha256 = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Sha256 }
            fuzz_smoke_bytes = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Bytes }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = if ($null -eq $guestResult) { $null } else { [string]$connection.Probe.Build }
            checkpoint_restored = $checkpointRestored -and $finalVmState -ceq "Off"
            support_listener_unchanged = $null -ne $finalSupportState
            host_tun_unchanged = $null -ne $finalTopologyState
            host_network_mutations = 0
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
            if ((Test-Path -LiteralPath $hostManifestPath) -or
                (Test-Path -LiteralPath $hostManifestPendingPath)) {
                throw "host manifest publication paths must be absent before publication"
            }
            Write-JsonFileNew -Path $hostManifestPendingPath -Value $manifest
            $expectedHostManifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                ($manifest | ConvertTo-Json -Depth 8) + "`n"
            )
            $actualHostManifestBytes = [IO.File]::ReadAllBytes($hostManifestPendingPath)
            if ([Convert]::ToBase64String($actualHostManifestBytes) -cne
                [Convert]::ToBase64String($expectedHostManifestBytes)) {
                throw "host manifest bytes differ from the expected closed document"
            }
            $hostManifestReadback = Get-Content -LiteralPath $hostManifestPendingPath `
                -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10 -ErrorAction Stop
        $hostManifestKeys = @(
            "schema", "status", "profile", "mode", "restart_cycles", "network_reset_cycles",
            "run_token", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
            "candidate_sha", "identity_sha256", "staged_input_sha256",
            "topology_manifest_sha256", "topology_plan_sha256", "topology",
            "guest_network_path_sha256", "guest_network_path", "host_network_path_sha256",
            "support_listener", "protected_host_tun", "topology_runtime_sha256",
            "host_network_path_helper_sha256", "guest_network_path_probe_sha256",
            "rust_version", "fuzz_smoke_sha256", "fuzz_smoke_bytes", "guest_execution",
            "guest_build", "checkpoint_restored", "support_listener_unchanged",
            "host_tun_unchanged", "host_network_mutations", "started_utc", "finished_utc",
            "final_vm_state", "evidence_files"
        )
        if ((@($hostManifestReadback.PSObject.Properties.Name) -join "|") -cne
                ($hostManifestKeys -join "|") -or
            $hostManifestReadback.schema -cne "ferrum2.windows-tun.hyperv-host-run.v4" -or
            $hostManifestReadback.identity_sha256 -cne $ledgerIdentity.Sha256 -or
            $hostManifestReadback.topology_manifest_sha256 -cne
                [string]$topologyDocument.Sha256 -or
            $hostManifestReadback.topology_plan_sha256 -cne
                [string]$topologyDocument.PlanDocument.Sha256 -or
            ($hostManifestReadback.topology | ConvertTo-Json -Compress -Depth 5) -cne
                ($ledgerIdentity.Ledger.topology | ConvertTo-Json -Compress -Depth 5) -or
            ($hostManifestReadback.support_listener | ConvertTo-Json -Compress -Depth 5) -cne
                ($ledgerIdentity.Ledger.support_listener | ConvertTo-Json -Compress -Depth 5) -or
            $hostManifestReadback.topology_runtime_sha256 -cne $topologyRuntimeSha256 -or
            $hostManifestReadback.host_network_path_helper_sha256 -cne
                $hostNetworkPathHelperSha256 -or
            $hostManifestReadback.guest_network_path_probe_sha256 -cne
                $guestNetworkPathProbeSha256 -or
            [long]$hostManifestReadback.host_network_mutations -ne 0 -or
            ($status -ceq "pass" -and
                ($hostManifestReadback.guest_network_path_sha256 -cne
                    $guestNetworkPathSha256 -or
                $hostManifestReadback.host_network_path_sha256 -cne
                    $hostNetworkPathSha256 -or
                ($hostManifestReadback.guest_network_path |
                    ConvertTo-Json -Compress -Depth 5) -cne
                    ($guestNetworkPath | ConvertTo-Json -Compress -Depth 5) -or
                ($hostManifestReadback.protected_host_tun |
                    ConvertTo-Json -Compress -Depth 5) -cne
                    ($finalTopologyState.Runtime.ProtectedHostTun |
                        ConvertTo-Json -Compress -Depth 5) -or
                [string]$hostManifestReadback.protected_host_tun.name -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_name -or
                [string]$hostManifestReadback.protected_host_tun.interface_guid -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_guid -or
                [long]$hostManifestReadback.protected_host_tun.interface_index -ne
                    [long]$ledgerIdentity.Ledger.topology.protected_host_tun_index -or
                [string]$hostManifestReadback.protected_host_tun.status -cne
                    [string]$ledgerIdentity.Ledger.topology.protected_host_tun_status -or
                $hostManifestReadback.checkpoint_restored -ne $true -or
                $hostManifestReadback.support_listener_unchanged -ne $true -or
                $hostManifestReadback.host_tun_unchanged -ne $true -or
                $hostManifestReadback.final_vm_state -cne "Off"))) {
            throw "host orchestration result closed binding is invalid"
        }
            $expectedEvidenceFilesJson = ConvertTo-Json `
                -InputObject @($manifest.evidence_files) -Compress -Depth 5
            $freshEvidenceFilesJson = ConvertTo-Json `
                -InputObject @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath) `
                -Compress -Depth 5
            if ($freshEvidenceFilesJson -cne $expectedEvidenceFilesJson) {
                throw "host evidence files changed before manifest publication"
            }
            [IO.File]::Move($hostManifestPendingPath, $hostManifestPath)
            $hostManifestFinalCreated = $true
            if (Test-Path -LiteralPath $hostManifestPendingPath) {
                throw "host manifest pending path survived atomic publication"
            }
            if ([Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($hostManifestPath)
                ) -cne [Convert]::ToBase64String($expectedHostManifestBytes)) {
                throw "host manifest changed during atomic publication"
            }
            $finalEvidenceFilesJson = ConvertTo-Json `
                -InputObject @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath) `
                -Compress -Depth 5
            if ($finalEvidenceFilesJson -cne $expectedEvidenceFilesJson) {
                throw "host evidence files changed during manifest publication"
            }
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
                    if ($ownedManifestItem.PSIsContainer -or
                        ($ownedManifestItem.Attributes -band
                            [IO.FileAttributes]::ReparsePoint)) {
                        throw "owned host manifest cleanup boundary is invalid"
                    }
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
        $messages.Add("qualification failed: $($runFailure.Exception.Message)")
    }
    foreach ($message in $finalizationFailures) {
        $messages.Add($message)
    }
    throw [InvalidOperationException]::new(($messages -join "; "))
}

Write-Output "hyperv_windows_tun status=PASS profile=$Profile run_token=$RunToken candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
