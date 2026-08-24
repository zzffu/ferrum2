#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Collects and reduces Windows TUN performance evidence in the approved local Hyper-V guest.

.DESCRIPTION
The host builds exact commits, stages portable dependencies through PowerShell Direct, exports raw
evidence, and runs the repository performance reducer. Every adapter, route, TUN, traffic, and
product-process operation runs inside the pinned guest. The host never changes a network adapter,
address, route, DNS setting, firewall rule, WFP object, or TUN session.

The default credential is the current-user DPAPI-protected PSCredential at
%LOCALAPPDATA%\Ferrum2\hyperv-ferrum2-test.credential.xml. The password is never accepted as a
parameter and the credential must remain outside this repository.

The portable guest controller defaults to the SHA-256-pinned PowerShell 7.4.19 win-x64 archive at
%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip. The archive must remain outside the repository.

Run mode requires the SHA-256-pinned external manifest created by the reviewed support-topology
provisioner and an already provisioned candidate qualification support listener. The listener
provides TCP echo, ordinary UDP echo, bounded fragment acknowledgements, and four contiguous UDP
ports, and must bind the manifest's dedicated host /30 address. Before any TUN session starts, the
runner proves that both directions use the isolated Internal switch and the exact manifest-bound
host and guest interfaces. The path and generated identities are retained as evidence.

PlanOnly validates repository lineage and emits the closed 90-trial plan without building, starting
the VM, loading a credential, staging files, or executing traffic.

DiagnosticTrialSequence runs exactly one canonical A/A trial while retaining the complete plan and
the ordinary evidence-export and VM-restore boundaries. Diagnostic evidence is explicitly not a
qualification result and cannot be used for comparison or calibration adoption.

DiagnosticProfile UdpFlowBoundary is restricted to calibration-aa sequence 31. It writes an
independent bounded guest/host flow diagnostic under udp-diagnostic and preserves the canonical
performance and diagnostic evidence paths unchanged.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseUsingScopeModifierInNewRunspaces",
    "",
    Justification = "All remoting values are bound through explicit ArgumentList and param blocks."
)]
[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [switch]$PlanOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateSet("calibration-aa", "comparison")]
    [string]$RunKind,

    [Parameter(Mandatory = $true, ParameterSetName = "Plan")]
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ParentSha,

    [Parameter(ParameterSetName = "Plan")]
    [Parameter(ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TopologyManifestPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TopologyManifestSha256,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65535)]
    [int]$SupportTcpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, 65532)]
    [int]$SupportUdpPort,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$SupportPid,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,127}$')]
    [string]$SupportOwner,

    [Parameter(ParameterSetName = "Run")]
    [string]$CredentialPath,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(1, 90)]
    [int]$DiagnosticTrialSequence,

    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("UdpFlowBoundary")]
    [string]$DiagnosticProfile,

    [Parameter(ParameterSetName = "Run")]
    [string]$SupportDiagnosticLedger,

    [Parameter(ParameterSetName = "Run")]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$SupportDiagnosticRunNonce,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(1, 65536)]
    [int]$SupportDiagnosticMaxEvents,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$diagnosticMode = $PSBoundParameters.ContainsKey("DiagnosticTrialSequence")
$instrumentedDiagnosticMode = $PSBoundParameters.ContainsKey("DiagnosticProfile")
if ($diagnosticMode -and $RunKind -cne "calibration-aa") {
    throw "DiagnosticTrialSequence is restricted to calibration-aa runs"
}
$supportDiagnosticParameterNames = @(
    "SupportDiagnosticLedger",
    "SupportDiagnosticRunNonce",
    "SupportDiagnosticMaxEvents"
)
$supportDiagnosticParametersSupplied = @($supportDiagnosticParameterNames | Where-Object {
    $PSBoundParameters.ContainsKey($_)
})
if ($instrumentedDiagnosticMode) {
    if (-not $diagnosticMode -or $DiagnosticTrialSequence -ne 31 -or
        $RunKind -cne "calibration-aa") {
        throw "UdpFlowBoundary requires calibration-aa and DiagnosticTrialSequence 31"
    }
    if ($supportDiagnosticParametersSupplied.Count -ne
        $supportDiagnosticParameterNames.Count) {
        throw "UdpFlowBoundary requires the complete support diagnostic ledger parameter group"
    }
    $parsedDiagnosticRunNonce = [uint64]0
    if (-not [uint64]::TryParse(
            $SupportDiagnosticRunNonce,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedDiagnosticRunNonce
        ) -or $parsedDiagnosticRunNonce -eq 0 -or
        $parsedDiagnosticRunNonce.ToString(
            [Globalization.CultureInfo]::InvariantCulture
        ) -cne $SupportDiagnosticRunNonce) {
        throw "support diagnostic run nonce must be a canonical nonzero u64"
    }
} elseif ($supportDiagnosticParametersSupplied.Count -ne 0) {
    throw "support diagnostic ledger parameters require DiagnosticProfile UdpFlowBoundary"
}

$approvedVmName = ""
$approvedVmId = [Guid]::Empty
$approvedCheckpointName = ""
$approvedCheckpointId = [Guid]::Empty
$approvedVmSwitchName = ""
$supportGuestIpv4 = ""
$supportGuestInterfaceAlias = ""
$supportNetwork = ""
$supportPrefixLength = 0
$supportVmMacAddress = ""
$topologyManifestDocument = $null
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$minimumSupportIpv4PacketBytes = 1468
$udpAssociationSourceIpv4 = "198.18.0.2"
$udpAssociationSourcePortFirst = 20000
$udpAssociationSourcePortLast = 28191
$udpAssociationCount = 8192
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") -ErrorAction Stop).Path
$approvedRustTarget = "x86_64-pc-windows-msvc"
$reproducibleRustSourceRoot = "C:\ferrum2-reproducible-source"
$policyPath = Join-Path $PSScriptRoot "windows_tun_performance_policy.json"
$controlPath = Join-Path $PSScriptRoot "performance_candidate.py"
$collectorPath = Join-Path $PSScriptRoot "collect_windows_tun_performance_trial.ps1"
$udpBoundaryCollectorPath = Join-Path $PSScriptRoot `
    "collect_windows_tun_udp_boundary_diagnostic.ps1"
$guestNetworkPathProbePath = Join-Path $PSScriptRoot `
    "get_windows_tun_guest_network_path.ps1"
$hostNetworkPathHelperPath = Join-Path $PSScriptRoot `
    "windows_tun_host_network_path.ps1"
$topologyRuntimePath = Join-Path $PSScriptRoot `
    "windows_tun_hyperv_support_topology_runtime.ps1"
$networkModelControllerPath = Join-Path $repositoryRoot `
    "tests\performance_candidate\windows_tun_network_model.py"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$runnerSourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
$topologyRuntimeSha256 = ""
$guestNetworkPathProbeSourceSha256 = ""
$udpBoundaryCollectorSourceSha256 = ""

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-NoReparsePointInExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label must use an absolute filesystem path"
    }
    $current = $root
    foreach ($segment in @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object Length)) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) { break }
        if ((Get-Item -LiteralPath $current -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw "$Label cannot traverse a reparse point"
        }
    }
}

function Resolve-ExternalFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 1073741824
    )
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Assert-NoReparsePointInExistingPath -Path $resolved -Label $Label
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label file boundary is invalid"
    }
    if (Test-PathWithinRoot -Path $resolved -Root $script:repositoryRoot) {
        throw "$Label must be stored outside the repository"
    }
    return $resolved
}

function Resolve-NewExternalDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
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
        if ($next -ceq $ancestor) { break }
        $ancestor = $next
    }
    if ([string]::IsNullOrWhiteSpace($ancestor) -or
        -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
        throw "$Label has no existing parent boundary"
    }
    Assert-NoReparsePointInExistingPath -Path $ancestor -Label $Label
    return $fullPath
}

function Import-ApprovedGuestCredential {
    param([string]$Path)
    $candidate = $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw "LOCALAPPDATA is unavailable for the default guest credential"
        }
        $candidate = Join-Path $env:LOCALAPPDATA "Ferrum2\hyperv-ferrum2-test.credential.xml"
    }
    $resolved = Resolve-ExternalFile -Path $candidate -Label "guest credential" -MaximumBytes 1048576
    $credential = Import-Clixml -LiteralPath $resolved -ErrorAction Stop
    if ($credential -isnot [Management.Automation.PSCredential] -or
        [string]$credential.UserName -cne "ferrum2-test") {
        throw "guest credential file does not contain the approved local PSCredential"
    }
    return $credential
}

function Get-ApprovedVmContext {
    if ($null -eq $script:topologyManifestDocument) {
        throw "support topology manifest is unavailable in run mode"
    }
    Assert-Ferrum2SupportTopologyManifestUnchanged `
        -Document $script:topologyManifestDocument
    $vm = Get-VM -Id $script:approvedVmId -ErrorAction Stop
    if ($vm.Name -cne $script:approvedVmName -or
        $vm.AutomaticCheckpointsEnabled -ne $false) {
        throw "approved VM identity mismatch"
    }
    $byName = @(Get-VM -Name $script:approvedVmName -ErrorAction Stop)
    if ($byName.Count -ne 1 -or $byName[0].Id -ne $script:approvedVmId) {
        throw "approved VM name does not resolve to the approved ID"
    }
    $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $checkpoint = @($checkpoints | Where-Object {
        $_.Id -eq $script:approvedCheckpointId
    })
    $sourceCheckpointId = [Guid][string]$script:topologyManifestDocument.Value.
        source_checkpoint.id
    $sourceCheckpoint = @($checkpoints | Where-Object { $_.Id -eq $sourceCheckpointId })
    if ($checkpoints.Count -ne 2 -or $sourceCheckpoint.Count -ne 1 -or
        $checkpoint.Count -ne 1 -or
        $checkpoint[0].Name -cne $script:approvedCheckpointName -or
        [Guid][string]$checkpoint[0].ParentCheckpointId -ne $sourceCheckpointId) {
        throw "approved checkpoint identity mismatch"
    }
    $checkpointByName = @(
        Get-VMSnapshot -VM $vm -Name $script:approvedCheckpointName -ErrorAction Stop
    )
    if ($checkpointByName.Count -ne 1 -or
        $checkpointByName[0].Id -ne $script:approvedCheckpointId) {
        throw "approved checkpoint name does not resolve to the approved ID"
    }
    return [pscustomobject]@{ Vm = $vm; Checkpoint = $checkpoint[0] }
}

function Stop-ApprovedVm {
    param([int]$TimeoutSeconds)
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        $context.Vm | Stop-VM -TurnOff -Force -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $context = Get-ApprovedVmContext
        if ([string]$context.Vm.State -ceq "Off") { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "approved VM did not become Off before the bounded timeout"
}

function Restore-ApprovedCheckpoint {
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before checkpoint restore"
    }
    $context.Checkpoint | Restore-VMSnapshot -Confirm:$false -ErrorAction Stop | Out-Null
    $restored = Get-ApprovedVmContext
    if ([string]$restored.Vm.State -cne "Off") {
        throw "checkpoint restore did not leave the approved VM Off"
    }
}

function Restore-ApprovedVmFinalState {
    param([int]$TimeoutSeconds)

    $stopFailures = [Collections.Generic.List[string]]::new()
    $offConfirmed = $false
    foreach ($attempt in 1..2) {
        try {
            Stop-ApprovedVm -TimeoutSeconds $TimeoutSeconds
        } catch {
            $stopFailures.Add("stop attempt ${attempt}: $($_.Exception.Message)")
        }
        try {
            if ([string](Get-ApprovedVmContext).Vm.State -ceq "Off") {
                $offConfirmed = $true
                break
            }
            $stopFailures.Add("Off readback attempt ${attempt}: state was not Off")
        } catch {
            $stopFailures.Add("Off readback attempt ${attempt}: $($_.Exception.Message)")
        }
    }
    if (-not $offConfirmed) {
        throw "approved VM Off state was not confirmed after two attempts: $($stopFailures -join ' | ')"
    }

    $restoreFailures = [Collections.Generic.List[string]]::new()
    foreach ($attempt in 1..2) {
        try {
            Restore-ApprovedCheckpoint
            if ([string](Get-ApprovedVmContext).Vm.State -cne "Off") {
                throw "approved VM final state is not Off"
            }
            return
        } catch {
            $restoreFailures.Add("restore attempt ${attempt}: $($_.Exception.Message)")
        }
    }
    throw "approved checkpoint restore failed after two attempts: $($restoreFailures -join ' | ')"
}

function Connect-ApprovedGuest {
    param(
        [Parameter(Mandatory = $true)][Management.Automation.PSCredential]$Credential,
        [int]$TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $session = $null
        try {
            if ([string](Get-ApprovedVmContext).Vm.State -cne "Running") {
                throw "approved VM left Running state before PowerShell Direct readiness"
            }
            $session = New-PSSession -VMId $script:approvedVmId -Credential $Credential `
                -ErrorAction Stop
            $session.Runspace.ConnectionInfo.OperationTimeout = 43200000
            if ($session.Runspace.ConnectionInfo.OperationTimeout -ne 43200000) {
                throw "PowerShell Direct operation timeout was not retained"
            }
            $probe = @(Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $version = Get-ItemProperty `
                    -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    -ErrorAction Stop
                $principal = New-Object Security.Principal.WindowsPrincipal(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                )
                [pscustomobject]@{
                    Manufacturer = [string]$computer.Manufacturer
                    Model = [string]$computer.Model
                    Product = [string]$version.ProductName
                    Edition = [string]$version.EditionID
                    Version = [Environment]::OSVersion.Version.ToString()
                    Build = "$($version.CurrentBuildNumber).$($version.UBR)"
                    OsBuild = [string]$os.BuildNumber
                    CurrentBuild = [string]$version.CurrentBuildNumber
                    Architecture = [string]$env:PROCESSOR_ARCHITECTURE
                    PowerShell = $PSVersionTable.PSVersion.ToString()
                    IsAdministrator = $principal.IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator
                    )
                }
            })
            if ($probe.Count -ne 1 -or
                $probe[0].Manufacturer -cne "Microsoft Corporation" -or
                $probe[0].Model -cne "Virtual Machine" -or
                $probe[0].Architecture -cne "AMD64" -or
                $probe[0].OsBuild -cne $probe[0].CurrentBuild -or
                $probe[0].IsAdministrator -ne $true) {
                throw "PowerShell Direct reached an ineligible guest identity"
            }
            return [pscustomobject]@{ Session = $session; Probe = $probe[0] }
        } catch {
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Seconds 2
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not become ready before the bounded timeout"
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$WorkingDirectory = $script:repositoryRoot
    )
    Push-Location $WorkingDirectory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

function ConvertTo-CanonicalUtcText {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $text = if ($Value -is [DateTime]) {
        $timestamp = [DateTime]$Value
        if ($timestamp.Kind -ne [DateTimeKind]::Utc) {
            throw "$Label DateTime value must be UTC"
        }
        $timestamp.ToString("o", [Globalization.CultureInfo]::InvariantCulture)
    } elseif ($Value -is [string]) {
        [string]$Value
    } else {
        throw "$Label must be a canonical UTC string or UTC DateTime"
    }
    if ($text -cnotmatch
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$') {
        throw "$Label is not canonical UTC"
    }
    $parsed = [DateTime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact(
            $text,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed
        ) -or $parsed.Kind -ne [DateTimeKind]::Utc) {
        throw "$Label is not a real UTC timestamp"
    }
    return $text
}

function Resolve-Commit {
    param([string]$Git, [string]$Sha, [string]$Label)
    $resolved = [string](& $Git -C $script:repositoryRoot rev-parse --verify "$Sha^{commit}" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $resolved -cne $Sha) { throw "$Label commit identity is invalid" }
    return $resolved
}

function Get-TreeSha {
    param([string]$Git, [string]$Sha)
    $tree = [string](& $Git -C $script:repositoryRoot rev-parse "$Sha^{tree}" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $tree -cnotmatch '^[0-9a-f]{40}$') {
        throw "unable to resolve tree for $Sha"
    }
    return $tree
}

function New-CanonicalPlan {
    param(
        [string]$Python,
        [string]$RunKindValue,
        [string]$Output
    )
    Invoke-NativeChecked -Executable $Python -Label "Windows TUN plan" -Arguments @(
        "-B", $script:controlPath, "windows-tun-plan",
        "--run-kind", $RunKindValue,
        "--policy", $script:policyPath,
        "--output", $Output
    )
    $plan = Get-Content -LiteralPath $Output -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30
    if ($plan.schema_version -ne 2 -or
        $plan.kind -cne "windows_tun_performance_plan" -or
        $plan.run_kind -cne $RunKindValue -or
        @($plan.trials).Count -ne 90 -or
        $null -eq $plan.scenarios."udp-route-once" -or
        $null -eq $plan.scenarios."udp-8192-association-lookup-expiry" -or
        $null -eq $plan.scenarios."network-lifecycle") {
        throw "canonical Windows TUN plan shape is invalid"
    }
    $plannedRunnerHashes = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [string]$_.Value.recipe.runner_source_sha256
    } | Sort-Object -Unique)
    if ($plannedRunnerHashes.Count -ne 1 -or
        $plannedRunnerHashes[0] -cne $script:runnerSourceSha256) {
        throw "canonical Windows TUN plan does not bind this runner source"
    }
    foreach ($binding in @(
        @("topology_plan_source_sha256", [string]$script:topologyPlanDocument.Sha256),
        @("topology_runtime_source_sha256", [string]$script:topologyRuntimeSha256),
        @("host_network_path_source_sha256", [string]$script:hostNetworkPathHelperSha256),
        @("guest_network_path_source_sha256", [string]$script:guestNetworkPathProbeSourceSha256)
    )) {
        $plannedHashes = @($plan.scenarios.PSObject.Properties | ForEach-Object {
            [string]$_.Value.recipe.($binding[0])
        } | Sort-Object -Unique)
        if ($plannedHashes.Count -ne 1 -or $plannedHashes[0] -cne $binding[1]) {
            throw "canonical Windows TUN plan does not bind $($binding[0])"
        }
    }
    $plannedRuntimeIdleTimeouts = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [int]$_.Value.recipe.client_runtime_idle_timeout_milliseconds
    } | Sort-Object -Unique)
    if ($plannedRuntimeIdleTimeouts.Count -ne 1 -or
        $plannedRuntimeIdleTimeouts[0] -ne 60000) {
        throw "canonical Windows TUN plan client runtime idle timeout is invalid"
    }
    $plannedTunRingCapacities = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [long]$_.Value.recipe.tun_ring_capacity_bytes
    } | Sort-Object -Unique)
    if ($plannedTunRingCapacities.Count -ne 1 -or
        $plannedTunRingCapacities[0] -ne 8388608) {
        throw "canonical Windows TUN plan ring capacity is invalid"
    }
    $udpBoundaryRecipe = $plan.scenarios.
        "udp-8192-association-lookup-expiry".recipe
    if ([string]$udpBoundaryRecipe.canonical_source_port_strategy -cne
            "explicit_tun_ipv4_contiguous" -or
        [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
            $script:udpAssociationSourceIpv4 -or
        [int]$udpBoundaryRecipe.canonical_source_port_first -ne
            $script:udpAssociationSourcePortFirst -or
        [int]$udpBoundaryRecipe.canonical_source_port_last -ne
            $script:udpAssociationSourcePortLast -or
        [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
            $script:udpAssociationSourceIpv4 -or
        [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
            $script:udpAssociationSourcePortFirst -or
        [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
            $script:udpAssociationSourcePortLast -or
        [int]$udpBoundaryRecipe.associations -ne
            $script:udpAssociationCount -or
        ([int]$udpBoundaryRecipe.canonical_source_port_last -
            [int]$udpBoundaryRecipe.canonical_source_port_first + 1) -ne
            [int]$udpBoundaryRecipe.associations -or
        ([int]$udpBoundaryRecipe.diagnostic_source_port_last -
            [int]$udpBoundaryRecipe.diagnostic_source_port_first + 1) -ne
            [int]$udpBoundaryRecipe.associations -or
        [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
            [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -or
        [int]$udpBoundaryRecipe.canonical_source_port_first -ne
            [int]$udpBoundaryRecipe.diagnostic_source_port_first -or
        [int]$udpBoundaryRecipe.canonical_source_port_last -ne
            [int]$udpBoundaryRecipe.diagnostic_source_port_last -or
        [string]$udpBoundaryRecipe.diagnostic_collector_source_sha256 -cne
            $script:udpBoundaryCollectorSourceSha256) {
        throw "canonical Windows TUN UDP source-port contract is invalid"
    }
    return $plan
}

function New-NetworkModelPlan {
    param([string]$Python, [string]$Output, [string]$ExpectedSha256)
    Invoke-NativeChecked -Executable $Python -Label "Windows TUN network-model plan" `
        -Arguments @(
            "-B", $script:networkModelControllerPath, "plan", "--output", $Output
        )
    $digest = (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne $ExpectedSha256) {
        throw "Windows TUN network-model plan identity mismatch"
    }
    $model = Get-Content -LiteralPath $Output -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 12
    if ($model.schema_version -ne 3 -or
        $model.execution -cne "local_hyperv_guest" -or
        $model.host_network_mutation -cne "forbidden" -or
        [int]$model.workloads."network-lifecycle".reset_network_cycles -ne 1000 -or
        [int]$model.workloads."udp-route-once".generations -ne 2 -or
        [int]$model.workloads."udp-route-once".source_slots -ne 64 -or
        [int]$model.workloads."udp-route-once".target_slots -ne 4) {
        throw "Windows TUN network-model plan shape is invalid"
    }
    return $model
}

function Export-CommitSource {
    param(
        [string]$Git,
        [string]$Tar,
        [string]$Sha,
        [string]$Destination,
        [string]$Archive
    )
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    Invoke-NativeChecked -Executable $Git -Label "git archive $Sha" -Arguments @(
        "-C", $script:repositoryRoot, "archive", "--format=tar", "--output=$Archive", $Sha
    )
    Invoke-NativeChecked -Executable $Tar -Label "extract source $Sha" -WorkingDirectory $Destination `
        -Arguments @("-xf", $Archive)
    if (-not (Test-Path -LiteralPath (Join-Path $Destination "Cargo.lock") -PathType Leaf)) {
        throw "archived source for $Sha is incomplete"
    }
    [IO.File]::Delete($Archive)
}

function Copy-BuiltBinary {
    param([string]$Source, [string]$Destination, [string]$Label)
    $item = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Label build output is invalid"
    }
    Copy-Item -LiteralPath $item.FullName -Destination $Destination -ErrorAction Stop
    return (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Build-MemberArtifacts {
    param(
        [string]$Cargo,
        [string]$Git,
        [string]$Tar,
        [string]$Sha,
        [string]$Member,
        [string]$TemporaryRoot,
        [string]$ArtifactRoot,
        [switch]$IncludeHarness
    )
    $source = Join-Path $TemporaryRoot "source-$Member"
    $archive = Join-Path $TemporaryRoot "source-$Member.tar"
    Export-CommitSource -Git $Git -Tar $Tar -Sha $Sha -Destination $source -Archive $archive
    $remapFlag = "--remap-path-prefix=$source=$script:reproducibleRustSourceRoot"
    if ($remapFlag -cmatch '[\r\n"]') {
        throw "host $Member build source remap cannot be encoded safely"
    }
    # /Brepro makes the PE timestamp and CodeView identity content-derived.
    $encodedRustFlags = @($remapFlag, "-C", "link-arg=/Brepro") -join [char]0x1f
    $targetRoot = Join-Path $source "target"
    $arguments = @(
        "+1.97.1", "build", "--target", $script:approvedRustTarget,
        "--target-dir", $targetRoot,
        "-p", "ferrum2-client", "-p", "ferrum2-server"
    )
    if ($IncludeHarness) { $arguments += @("-p", "ferrum2-m4-qualification") }
    $arguments += @("--bins", "--locked", "--profile", "profiling")
    $previousEncodedRustFlags = [Environment]::GetEnvironmentVariable(
        "CARGO_ENCODED_RUSTFLAGS",
        [EnvironmentVariableTarget]::Process
    )
    try {
        [Environment]::SetEnvironmentVariable(
            "CARGO_ENCODED_RUSTFLAGS",
            $encodedRustFlags,
            [EnvironmentVariableTarget]::Process
        )
        Invoke-NativeChecked -Executable $Cargo -Arguments $arguments `
            -Label "host $Member build" -WorkingDirectory $source
    } finally {
        [Environment]::SetEnvironmentVariable(
            "CARGO_ENCODED_RUSTFLAGS",
            $previousEncodedRustFlags,
            [EnvironmentVariableTarget]::Process
        )
    }
    $destination = Join-Path $ArtifactRoot $Member
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $profile = Join-Path (Join-Path $targetRoot $script:approvedRustTarget) "profiling"
    $client = Join-Path $destination "ferrum2-client.exe"
    $server = Join-Path $destination "ferrum2-server.exe"
    $clientHash = Copy-BuiltBinary -Source (Join-Path $profile "ferrum2-client.exe") `
        -Destination $client -Label "$Member client"
    $serverHash = Copy-BuiltBinary -Source (Join-Path $profile "ferrum2-server.exe") `
        -Destination $server -Label "$Member server"
    $harness = $null
    $harnessHash = $null
    if ($IncludeHarness) {
        $harness = Join-Path $ArtifactRoot "m4-qualification.exe"
        $harnessHash = Copy-BuiltBinary -Source (Join-Path $profile "m4-qualification.exe") `
            -Destination $harness -Label "candidate performance harness"
    }
    return [pscustomobject]@{
        Client = $client
        Server = $server
        ClientSha256 = $clientHash
        ServerSha256 = $serverHash
        Harness = $harness
        HarnessSha256 = $harnessHash
    }
}

function Write-Utf8FileNew {
    param([string]$Path, [string]$Text)
    $bytes = $script:utf8NoBom.GetBytes($Text)
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Invoke-BoundedNativeText {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$MaximumLines = 4096,
        [int]$MaximumBytes = 4194304,
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 60,
        [switch]$AllowFailure
    )
    foreach ($argument in $Arguments) {
        if ($argument -cmatch '["\r\n]') {
            throw "$Label contains an unsupported native argument"
        }
    }
    $temporaryName = "ferrum2-native-capture-$([Guid]::NewGuid().ToString('N'))"
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) $temporaryName
    $stdoutPath = Join-Path $temporaryDirectory "stdout.txt"
    $stderrPath = Join-Path $temporaryDirectory "stderr.txt"
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $process = $null
    try {
        $quotedArguments = @($Arguments | ForEach-Object {
            if ($_ -cmatch '\s') { '"{0}"' -f $_ } else { $_ }
        })
        $process = Start-Process -FilePath $Executable -ArgumentList $quotedArguments `
            -WindowStyle Hidden -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath -PassThru -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $boundaryExceeded = $false
        do {
            $stdoutBytes = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stdoutPath -Force).Length
            } else { [long]0 }
            $stderrBytes = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
                [long](Get-Item -LiteralPath $stderrPath -Force).Length
            } else { [long]0 }
            if ($stdoutBytes + $stderrBytes -gt $MaximumBytes) {
                $boundaryExceeded = $true
                try { $process.Kill($true) } catch { $process.Kill() }
                break
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $process.HasExited) {
            try { $process.Kill($true) } catch { $process.Kill() }
        }
        if (-not $process.WaitForExit(10000)) {
            throw "$Label process could not be reaped"
        }
        if ($boundaryExceeded) { throw "$Label output exceeded its byte boundary" }
        if ([DateTime]::UtcNow -ge $deadline) { throw "$Label exceeded its timeout" }
        $lines = [Collections.Generic.List[string]]::new()
        $totalLines = 0
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            foreach ($line in [IO.File]::ReadLines($path)) {
                $totalLines++
                if ($totalLines -le $MaximumLines) {
                    $lines.Add(([string]$line -replace '[\r\n]+', ' ').TrimEnd())
                }
            }
        }
        if ($totalLines -gt $MaximumLines) {
            throw "$Label output exceeded its line boundary"
        }
        $textValue = $lines.ToArray() -join "`n"
        if ($script:utf8NoBom.GetByteCount($textValue) -gt $MaximumBytes) {
            throw "$Label output exceeded its decoded byte boundary"
        }
        $exitCode = $process.ExitCode
        if (-not $AllowFailure -and $exitCode -ne 0) {
            $detail = if ($textValue.Length -gt 2048) {
                $textValue.Substring(0, 2048)
            } else {
                $textValue
            }
            throw "$Label failed with exit code ${exitCode}: $detail"
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Lines = $lines.ToArray()
            TotalLines = $totalLines
            Truncated = $false
            Text = $textValue
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [IO.File]::Delete($path)
            }
        }
        if ((Test-Path -LiteralPath $temporaryDirectory -PathType Container) -and
            [IO.Path]::GetFileName($temporaryDirectory) -ceq $temporaryName -and
            [IO.Path]::GetDirectoryName($temporaryDirectory).TrimEnd('\', '/') -ceq
                [IO.Path]::GetTempPath().TrimEnd('\', '/')) {
            [IO.Directory]::Delete($temporaryDirectory, $false)
        }
    }
}

function Complete-UdpSupportDiagnosticLedger {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$TargetIpv4,
        [ValidateRange(1, 65532)]
        [Parameter(Mandatory = $true)][int]$FirstUdpPort,
        [Parameter(Mandatory = $true)][string]$RunNonce
    )
    $result = Invoke-BoundedNativeText `
        -Executable $Executable `
        -Arguments @(
            "windows-tun-udp-diagnostic-finalize",
            "--target-ip", $TargetIpv4,
            "--udp-port", [string]$FirstUdpPort,
            "--diagnostic-run-nonce", $RunNonce
        ) `
        -Label "Windows TUN UDP diagnostic support ledger finalize" `
        -MaximumLines 1 -MaximumBytes 4096 -TimeoutSeconds 60
    $expected = "windows_tun_udp_diagnostic_finalize status=PASS " +
        "target=$TargetIpv4 udp_ports=$FirstUdpPort..$($FirstUdpPort + 3)"
    if ($result.ExitCode -ne 0 -or $result.Lines.Count -ne 1 -or
        [string]$result.Lines[0] -cne $expected) {
        throw "Windows TUN UDP diagnostic support ledger finalize result is invalid"
    }
}

function Write-HostUdpEndpointSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][int]$SupportProcessId
    )
    $dynamic = Invoke-BoundedNativeText -Executable "netsh.exe" -Arguments @(
        "interface", "ipv4", "show", "dynamicport", "udp"
    ) -Label "host UDP dynamic-port snapshot" -MaximumLines 512 -MaximumBytes 131072
    $excluded = Invoke-BoundedNativeText -Executable "netsh.exe" -Arguments @(
        "interface", "ipv4", "show", "excludedportrange", "protocol=udp"
    ) -Label "host UDP excluded-port snapshot" -MaximumLines 512 -MaximumBytes 131072
    $endpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $supportEndpoints = @($endpoints | Where-Object {
        [int]$_.OwningProcess -eq $SupportProcessId
    } | Sort-Object LocalAddress, LocalPort | ForEach-Object {
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            owning_process = [int]$_.OwningProcess
        }
    })
    $topOwners = @($endpoints | Group-Object OwningProcess | Sort-Object Count -Descending |
        Select-Object -First 64 | ForEach-Object {
            $ownerPid = [int]$_.Name
            $processName = $null
            try {
                $processName = [string](Get-Process -Id $ownerPid -ErrorAction Stop).ProcessName
            } catch {
                $processName = $null
            }
            [ordered]@{
                owning_process = $ownerPid
                process_name = $processName
                endpoint_count = $_.Count
                support_process = $ownerPid -eq $SupportProcessId
            }
        })
    $snapshot = [ordered]@{
        schema = "ferrum2.windows-tun.host-udp-endpoint-snapshot.v1"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        dynamic_port_udp = [ordered]@{
            exit_code = $dynamic.ExitCode
            total_lines = $dynamic.TotalLines
            truncated = $dynamic.Truncated
            lines = $dynamic.Lines
        }
        excluded_port_ranges_udp = [ordered]@{
            exit_code = $excluded.ExitCode
            total_lines = $excluded.TotalLines
            truncated = $excluded.Truncated
            lines = $excluded.Lines
        }
        endpoint_count = $endpoints.Count
        support_endpoints = $supportEndpoints
        top_endpoint_owners = $topOwners
    }
    $textValue = ($snapshot | ConvertTo-Json -Depth 8) + "`n"
    if ($script:utf8NoBom.GetByteCount($textValue) -gt 1048576) {
        throw "host UDP endpoint snapshot exceeded 1 MiB"
    }
    Write-Utf8FileNew -Path $Path -Text $textValue
}

function Write-HostUdpEndpointErrorSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][int]$SupportProcessId,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($existing.PSIsContainer -or
            $existing.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "host UDP endpoint error snapshot target is unsafe"
        }
        [IO.File]::Delete($existing.FullName)
    }
    $boundedFailure = ($Failure -replace '[\r\n]+', ' ').Trim()
    if ($boundedFailure.Length -gt 2048) {
        $boundedFailure = $boundedFailure.Substring(0, 2048)
    }
    $snapshot = [ordered]@{
        schema = "ferrum2.windows-tun.host-udp-endpoint-snapshot.v1"
        stage = $Stage
        captured_utc = [DateTime]::UtcNow.ToString("o")
        support_pid = $SupportProcessId
        state = "PARTIAL"
        error = $boundedFailure
    }
    Write-Utf8FileNew -Path $Path `
        -Text (($snapshot | ConvertTo-Json -Depth 4) + "`n")
}

function Assert-PktmonCaptureLifecycleState {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Running", "Stopped")]
        [string]$ExpectedState
    )
    $status = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @("status") `
        -Label "Pktmon lifecycle status" -MaximumLines 64 -MaximumBytes 16384 `
        -AllowFailure
    $session = Invoke-BoundedNativeText -Executable "logman.exe" `
        -Arguments @("query", "-ets", "PktMon") `
        -Label "Pktmon lifecycle ETW session query" `
        -MaximumLines 64 -MaximumBytes 16384 -AllowFailure
    $statusSaysStopped = $status.ExitCode -eq 0 -and
        $status.Text -cmatch '(?i)(not\s+running|没有运行)'
    $sessionSaysRunning = $session.ExitCode -eq 0
    if ($ExpectedState -ceq "Running") {
        if ($status.ExitCode -ne 0 -or $statusSaysStopped -or
            -not $sessionSaysRunning) {
            throw "Pktmon running state was not proven by status and ETW session readback"
        }
    } elseif (-not $statusSaysStopped -or $sessionSaysRunning) {
        throw "Pktmon stopped state was not proven by status and ETW session readback"
    }
}

function Stop-PktmonCaptureAndAssertStopped {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$OutputPath
    )
    $stop = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("stop") -Label $Label -MaximumLines 256 `
        -MaximumBytes 65536 -AllowFailure
    if (-not [string]::IsNullOrWhiteSpace($OutputPath) -and
        -not (Test-Path -LiteralPath $OutputPath)) {
        Write-Utf8FileNew -Path $OutputPath -Text ($stop.Text + "`n")
    }
    try {
        Assert-PktmonCaptureLifecycleState -ExpectedState "Stopped"
    } catch {
        throw "$Label did not prove Pktmon stopped (stop exit=$($stop.ExitCode)): $($_.Exception.Message)"
    }
}

function Assert-PktmonUnused {
    Assert-PktmonCaptureLifecycleState -ExpectedState "Stopped"
    $filters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "list") -Label "Pktmon filter list" `
        -MaximumLines 256 -MaximumBytes 65536
    if ($filters.Text -cnotmatch `
        '(?im)^\s*(none|无|No packet filters are specified\.|未指定数据包筛选器。)\s*$') {
        throw "Pktmon filter baseline is not empty"
    }
    return $filters.Text
}

function Get-PktmonFilterListText {
    $filters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "list") -Label "Pktmon owned filter readback" `
        -MaximumLines 512 -MaximumBytes 131072
    return $filters.Text
}

function Remove-OwnedPktmonFiltersSafely {
    param([Parameter(Mandatory = $true)][string]$ExpectedFilterListText)
    $actualFilterListText = Get-PktmonFilterListText
    if ($actualFilterListText -cne $ExpectedFilterListText) {
        throw "Pktmon filter set changed after Ferrum2 acquired ownership; filters were preserved"
    }
    [void](Invoke-BoundedNativeText -Executable "pktmon.exe" `
        -Arguments @("filter", "remove") -Label "Pktmon filter cleanup" `
        -MaximumLines 128 -MaximumBytes 32768)
    $remaining = Get-PktmonFilterListText
    if ($remaining -cnotmatch `
        '(?im)^\s*(none|无|No packet filters are specified\.|未指定数据包筛选器。)\s*$') {
        throw "Pktmon owned filter cleanup did not restore the empty baseline"
    }
}

function Start-HostUdpDiagnosticCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$SupportAddress,
        [Parameter(Mandatory = $true)][int]$FirstUdpPort
    )
    $mutex = [Threading.Mutex]::new(
        $false,
        "Global\Ferrum2WindowsTunUdpDiagnosticPktmon"
    )
    $mutexHeld = $false
    $filtersAdded = $false
    $captureStarted = $false
    $captureStartAttempted = $false
    $ownedFilterListText = $null
    try {
        try { $mutexHeld = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
        if (-not $mutexHeld) {
            throw "another Ferrum2 UDP diagnostic owns the global Pktmon mutex"
        }
        $ownedFilterListText = Assert-PktmonUnused
        $filterRows = [Collections.Generic.List[object]]::new()
        foreach ($port in $FirstUdpPort..($FirstUdpPort + 3)) {
            $filterName = "Ferrum2UdpDiagnostic-$port"
            $filterResult = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                "filter", "add", $filterName,
                "--ip", $SupportAddress,
                "--transport", "UDP",
                "--port", [string]$port
            ) -Label "Pktmon UDP filter $port" -MaximumLines 64 -MaximumBytes 16384
            $filterRows.Add([ordered]@{
                name = $filterName
                support_ipv4 = $SupportAddress
                protocol = "UDP"
                port = $port
                command_exit_code = $filterResult.ExitCode
            })
            $filtersAdded = $true
            $ownedFilterListText = Get-PktmonFilterListText
        }
        $etlPath = Join-Path $Directory "PktMon.etl"
        $captureStartAttempted = $true
        $startResult = Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
            "start", "--capture", "--comp", "all", "--type", "all",
            "--pkt-size", "128", "--file-name", $etlPath,
            "--file-size", "16", "--log-mode", "circular"
        ) -Label "Pktmon capture start" -MaximumLines 128 -MaximumBytes 32768
        Assert-PktmonCaptureLifecycleState -ExpectedState "Running"
        $captureStarted = $true
        return [pscustomobject]@{
            Mutex = $mutex
            MutexHeld = $mutexHeld
            FiltersAdded = $filtersAdded
            CaptureStarted = $captureStarted
            Directory = $Directory
            EtlPath = $etlPath
            Filters = $filterRows.ToArray()
            OwnedFilterListText = $ownedFilterListText
            StartOutput = $startResult.Lines
            StartedUtc = [DateTime]::UtcNow.ToString("o")
        }
    } catch {
        $startFailure = $_
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        $captureStopped = -not $captureStartAttempted
        if ($captureStartAttempted) {
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon failed-start stop"
                $captureStopped = $true
            } catch {
                $cleanupFailures.Add("capture stop: $($_.Exception.Message)")
            }
        }
        if ($filtersAdded -and $captureStopped) {
            try {
                Remove-OwnedPktmonFiltersSafely `
                    -ExpectedFilterListText $ownedFilterListText
            } catch {
                $cleanupFailures.Add("filter cleanup: $($_.Exception.Message)")
            }
        } elseif ($filtersAdded) {
            $cleanupFailures.Add(
                "filter cleanup skipped because stopped capture state was not proven; filters were preserved"
            )
        } elseif ($mutexHeld -and -not [string]::IsNullOrWhiteSpace(
            $ownedFilterListText
        )) {
            try {
                if ((Get-PktmonFilterListText) -cne $ownedFilterListText) {
                    $cleanupFailures.Add(
                        "filter mutation could not be attributed safely; filters were preserved"
                    )
                }
            } catch {
                $cleanupFailures.Add("filter readback: $($_.Exception.Message)")
            }
        }
        if ($mutexHeld) {
            try { $mutex.ReleaseMutex() }
            catch { $cleanupFailures.Add("mutex release: $($_.Exception.Message)") }
        }
        $mutex.Dispose()
        if ($cleanupFailures.Count -ne 0) {
            throw "$($startFailure.Exception.Message); Pktmon failed-start cleanup: $($cleanupFailures -join '; ')"
        }
        throw $startFailure
    }
}

function Complete-HostUdpDiagnosticCapture {
    param([Parameter(Mandatory = $true)][object]$State)
    $failures = [Collections.Generic.List[string]]::new()
    $captureStopStatus = "NOT_STARTED"
    try {
        if ($State.CaptureStarted) {
            try {
                $counters = Invoke-BoundedNativeText -Executable "pktmon.exe" `
                    -Arguments @("counters", "--json") -Label "Pktmon counters" `
                    -MaximumLines 65536 -MaximumBytes 8388608
                Write-Utf8FileNew -Path (Join-Path $State.Directory "pktmon-counters.json") `
                    -Text ($counters.Text + "`n")
            } catch {
                $failures.Add("counters: $($_.Exception.Message)")
            }
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon capture stop" `
                    -OutputPath (Join-Path $State.Directory "pktmon-stop.txt")
                $captureStopStatus = "PASS"
                $State.CaptureStarted = $false
            } catch {
                $captureStopStatus = "FAIL"
                $failures.Add("stop: $($_.Exception.Message)")
            }
        }
        if (-not $State.CaptureStarted -and
            (Test-Path -LiteralPath $State.EtlPath -PathType Leaf)) {
            try {
                $etl = Get-Item -LiteralPath $State.EtlPath -Force
                if ($etl.Length -le 0 -or $etl.Length -gt 33554432) {
                    throw "Pktmon ETL size is outside its boundary"
                }
                [void](Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                    "etl2txt", $State.EtlPath,
                    "--out", (Join-Path $State.Directory "PktMon.txt"),
                    "--hex"
                ) -Label "Pktmon ETL text conversion" -MaximumLines 256 `
                    -MaximumBytes 65536)
                [void](Invoke-BoundedNativeText -Executable "pktmon.exe" -Arguments @(
                    "etl2pcap", $State.EtlPath,
                    "--out", (Join-Path $State.Directory "PktMon.pcapng")
                ) -Label "Pktmon ETL pcap conversion" -MaximumLines 256 `
                    -MaximumBytes 65536)
                foreach ($captureFile in @(
                    (Join-Path $State.Directory "PktMon.txt"),
                    (Join-Path $State.Directory "PktMon.pcapng")
                )) {
                    $item = Get-Item -LiteralPath $captureFile -Force -ErrorAction Stop
                    if ($item.Length -le 0 -or $item.Length -gt 134217728) {
                        throw "converted Pktmon artifact size is outside its boundary"
                    }
                }
            } catch {
                $failures.Add("conversion: $($_.Exception.Message)")
            }
        }
    } finally {
        if ($State.CaptureStarted) {
            try {
                Stop-PktmonCaptureAndAssertStopped `
                    -Label "Pktmon final capture stop" `
                    -OutputPath (Join-Path $State.Directory "pktmon-stop.txt")
                $captureStopStatus = "PASS"
                $State.CaptureStarted = $false
            } catch {
                $captureStopStatus = "FAIL"
                $failures.Add("final stop: $($_.Exception.Message)")
            }
        }
        if ($State.FiltersAdded -and -not $State.CaptureStarted) {
            try {
                Remove-OwnedPktmonFiltersSafely `
                    -ExpectedFilterListText $State.OwnedFilterListText
                $State.FiltersAdded = $false
            } catch {
                $failures.Add("filter cleanup: $($_.Exception.Message)")
            }
        } elseif ($State.FiltersAdded) {
            $failures.Add(
                "filter cleanup skipped because stopped capture state was not proven; filters were preserved"
            )
        }
        if ($State.MutexHeld) {
            try { $State.Mutex.ReleaseMutex() }
            catch { $failures.Add("mutex release: $($_.Exception.Message)") }
            $State.MutexHeld = $false
        }
        $State.Mutex.Dispose()
    }
    return [pscustomobject]@{
        CaptureStopStatus = $captureStopStatus
        Status = if ($failures.Count -eq 0) { "PASS" } else { "FAIL" }
        Failures = $failures.ToArray()
    }
}

function New-SharedUdpDiagnosticLedgerReader {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
        4096,
        [IO.FileOptions]::SequentialScan
    )
    try {
        return [IO.StreamReader]::new(
            $stream,
            [Text.UTF8Encoding]::new($false, $true),
            $true,
            4096,
            $false
        )
    } catch {
        $stream.Dispose()
        throw
    }
}

function Get-SharedUdpDiagnosticLedgerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
        4096,
        [IO.FileOptions]::SequentialScan
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($stream)).
            Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Copy-SharedUdpDiagnosticLedgerFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $sourceStream = $null
    $destinationStream = $null
    try {
        $sourceStream = [IO.FileStream]::new(
            $Source,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete),
            81920,
            [IO.FileOptions]::SequentialScan
        )
        $destinationStream = [IO.FileStream]::new(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read,
            81920,
            [IO.FileOptions]::None
        )
        $sourceStream.CopyTo($destinationStream, 81920)
        $destinationStream.Flush()
    } finally {
        if ($null -ne $destinationStream) { $destinationStream.Dispose() }
        if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    }
}

function Get-UdpDiagnosticLedgerSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)][int]$ExpectedMaxEvents,
        [long]$MaximumBytes = 268451840
    )
    $resolved = Resolve-ExternalFile -Path $Path -Label "UDP diagnostic ledger" `
        -MaximumBytes $MaximumBytes
    $recordCount = 0
    $eventCount = 0
    $matchingRunNonceEvents = 0
    $headerRecord = $null
    $lastRecord = $null
    $truncationRecord = $null
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $resolved
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $recordCount++
            if ($recordCount -gt ($ExpectedMaxEvents + 3)) {
                throw "UDP diagnostic ledger exceeds its record boundary"
            }
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "UDP diagnostic ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.schema -cne $ExpectedSchema) {
                throw "UDP diagnostic ledger schema mismatch"
            }
            if ($recordCount -eq 1) {
                if ([string]$record.record_type -cne "header" -or
                    [string]$record.run_nonce -cne $ExpectedRunNonce -or
                    [int]$record.max_events -ne $ExpectedMaxEvents) {
                    throw "UDP diagnostic ledger header identity mismatch"
                }
                $headerRecord = $record
            } elseif ([string]$record.record_type -ceq "event") {
                $eventCount++
                if ($record.PSObject.Properties.Name -ccontains
                        "payload_run_nonce_match" -and
                    $record.payload_run_nonce_match -eq $true -and
                    [string]$record.payload_run_nonce -ceq $ExpectedRunNonce) {
                    $matchingRunNonceEvents++
                }
            } elseif ([string]$record.record_type -ceq "truncation") {
                $truncationRecord = $record
            }
            $lastRecord = $record
        }
    } finally {
        $reader.Dispose()
    }
    if ($recordCount -lt 1) { throw "UDP diagnostic ledger is empty" }
    $closed = [string]$lastRecord.record_type -ceq "footer" -and
        [string]$lastRecord.run_nonce -ceq $ExpectedRunNonce -and
        $lastRecord.closed -eq $true
    $droppedEvents = if ($closed) {
        [long]$lastRecord.dropped_events
    } elseif ($null -ne $truncationRecord) {
        [long]$truncationRecord.dropped_events_at_least
    } elseif ([string]$lastRecord.record_type -ceq "event" -and
        $null -ne $lastRecord.ledger_counters) {
        [long]$lastRecord.ledger_counters.dropped_events
    } else {
        [long]0
    }
    $writeFailures = if ($closed) {
        [long]$lastRecord.write_failures
    } elseif ($null -ne $truncationRecord) {
        [long]$truncationRecord.write_failures
    } elseif ([string]$lastRecord.record_type -ceq "event" -and
        $null -ne $lastRecord.ledger_counters) {
        [long]$lastRecord.ledger_counters.write_failures
    } else {
        [long]0
    }
    return [pscustomobject]@{
        Path = $resolved
        Bytes = [long](Get-Item -LiteralPath $resolved -Force).Length
        Sha256 = Get-SharedUdpDiagnosticLedgerSha256 -Path $resolved
        Records = $recordCount
        Events = $eventCount
        MatchingRunNonceEvents = $matchingRunNonceEvents
        Header = $headerRecord
        Closed = $closed
        DroppedEvents = $droppedEvents
        WriteFailures = $writeFailures
    }
}

function Get-StableUdpDiagnosticLedgerFileState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $before = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($before.PSIsContainer -or
        $before.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $before.Length -le 0 -or $before.Length -gt 268451840) {
        throw "$Label is outside its stable-copy boundary"
    }
    $beforeLength = [long]$before.Length
    $beforeWriteTicks = [long]$before.LastWriteTimeUtc.Ticks
    $sha256 = Get-SharedUdpDiagnosticLedgerSha256 -Path $before.FullName
    $afterHash = Get-Item -LiteralPath $before.FullName -Force -ErrorAction Stop
    if ([long]$afterHash.Length -ne $beforeLength -or
        [long]$afterHash.LastWriteTimeUtc.Ticks -ne $beforeWriteTicks) {
        throw "$Label changed while its hash was calculated"
    }
    return [pscustomobject]@{
        Path = $before.FullName
        Bytes = $beforeLength
        LastWriteTimeUtcTicks = $beforeWriteTicks
        Sha256 = $sha256
    }
}

function Copy-StableUdpDiagnosticLedger {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination) {
        throw "support diagnostic ledger copy baseline is not absent"
    }
    $sourceBefore = Get-StableUdpDiagnosticLedgerFileState `
        -Path $Source -Label "support diagnostic ledger before copy"
    Copy-SharedUdpDiagnosticLedgerFile -Source $sourceBefore.Path `
        -Destination $Destination
    $sourceAfter = Get-StableUdpDiagnosticLedgerFileState `
        -Path $sourceBefore.Path -Label "support diagnostic ledger after copy"
    $destinationState = Get-StableUdpDiagnosticLedgerFileState `
        -Path $Destination -Label "support diagnostic ledger copy"
    if ($sourceBefore.Bytes -ne $sourceAfter.Bytes -or
        $sourceBefore.LastWriteTimeUtcTicks -ne
            $sourceAfter.LastWriteTimeUtcTicks -or
        $sourceBefore.Sha256 -cne $sourceAfter.Sha256 -or
        $destinationState.Bytes -ne $sourceAfter.Bytes -or
        $destinationState.Sha256 -cne $sourceAfter.Sha256) {
        throw "support diagnostic ledger changed during its single stable-copy attempt"
    }
    return $destinationState
}

function New-UdpDiagnosticArtifactRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$LedgerSummary,
        [int]$MaxEvents = 0,
        [ValidateSet("COMPLETE", "PARTIAL")]
        [string]$StateOverride
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required UDP diagnostic artifact is missing: role=$Role"
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $item.Length -le 0 -or $item.Length -gt 134217728) {
        throw "UDP diagnostic artifact boundary is invalid: role=$Role"
    }
    return [ordered]@{
        role = $Role
        state = if (-not [string]::IsNullOrWhiteSpace($StateOverride)) {
            $StateOverride
        } elseif ($null -ne $LedgerSummary -and (
            -not $LedgerSummary.Closed -or
            $LedgerSummary.DroppedEvents -ne 0 -or
            $LedgerSummary.WriteFailures -ne 0
        )) { "PARTIAL" } else { "COMPLETE" }
        file = [IO.Path]::GetRelativePath($script:hostDiagnosticRoot, $item.FullName).
            Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).
            Hash.ToLowerInvariant()
        bytes = [long]$item.Length
        records = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.Events
        } else {
            $null
        }
        max_events = if ($MaxEvents -gt 0) { $MaxEvents } else { $null }
        dropped_events = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.DroppedEvents
        } else {
            [long]0
        }
        write_failures = if ($null -ne $LedgerSummary) {
            [long]$LedgerSummary.WriteFailures
        } else {
            [long]0
        }
    }
}

function Get-UdpDiagnosticArtifactTotalByteCount {
    param(
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[object]]$Artifacts
    )
    [long]$total = 0
    foreach ($artifact in $Artifacts) {
        if (-not ($artifact -is [Collections.IDictionary]) -or
            -not $artifact.Contains("bytes")) {
            throw "UDP diagnostic artifact record is missing its byte count"
        }
        [long]$artifactBytes = $artifact["bytes"]
        if ($artifactBytes -le 0 -or
            $total -gt ([long]::MaxValue - $artifactBytes)) {
            throw "UDP diagnostic artifact byte count is invalid"
        }
        $total += $artifactBytes
    }
    return $total
}

function Get-FirstFailedUdpDiagnosticFlow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$MaximumEvents
    )
    $eventCount = 0
    $firstNotObserved = $null
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $Path
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "workload flow ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.record_type -cne "event") { continue }
            $eventCount++
            if ($eventCount -gt $MaximumEvents) {
                throw "workload flow ledger exceeds its event boundary"
            }
            $sendResult = [string]$record.send_result
            $replyResult = [string]$record.reply_result
            if ($sendResult -cne "success" -or
                $replyResult -notin @("success", "not_observed") -or
                ($replyResult -ceq "success" -and $record.payload_match -ne $true)) {
                return $record
            }
            if ($replyResult -ceq "not_observed" -and $null -eq $firstNotObserved) {
                $firstNotObserved = $record
            }
        }
    } finally {
        $reader.Dispose()
    }
    return $firstNotObserved
}

function Get-SupportUdpBoundaryForFlow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][object]$Flow,
        [Parameter(Mandatory = $true)][int]$MaximumEvents
    )
    $rx = $null
    $tx = $null
    $eventCount = 0
    $reader = New-SharedUdpDiagnosticLedgerReader -Path $Path
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($script:utf8NoBom.GetByteCount($line) -gt 4096) {
                throw "support ledger line exceeds 4096 bytes"
            }
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$record.record_type -cne "event") { continue }
            $eventCount++
            if ($eventCount -gt $MaximumEvents) {
                throw "support ledger exceeds its event boundary"
            }
            if ([string]$record.payload_run_nonce -cne $RunNonce -or
                [string]$record.packet_nonce -cne [string]$Flow.packet_nonce -or
                [int]$record.trial_sequence -ne [int]$Flow.trial_sequence -or
                [string]$record.phase -cne [string]$Flow.phase -or
                [int]$record.association_index -ne [int]$Flow.association_index -or
                [int]$record.round -ne [int]$Flow.round) {
                continue
            }
            if ([string]$record.stage -ceq "rx" -and $null -eq $rx) { $rx = $record }
            if ([string]$record.stage -ceq "tx" -and $null -eq $tx) { $tx = $record }
        }
    } finally {
        $reader.Dispose()
    }
    return [pscustomobject]@{ Rx = $rx; Tx = $tx }
}

function Stage-PortableRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$Rustup,
        [Parameter(Mandatory = $true)][string]$PowerShellZip,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $rustc = [string](& $Rustup which --toolchain 1.97.1 rustc 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $rustc -PathType Leaf)) {
        throw "host Rust 1.97.1 compiler is unavailable"
    }
    $version = @(& $rustc --version 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($version -join "`n") -cnotmatch '^rustc 1\.97\.1 \(') {
        throw "host Rust toolchain does not match 1.97.1"
    }
    $rustDestination = Join-Path $Destination "rust"
    [IO.Directory]::CreateDirectory($rustDestination) | Out-Null
    $rustBin = Split-Path -Parent $rustc
    $rustFiles = @(
        Get-Item -LiteralPath $rustc -Force
        Get-ChildItem -LiteralPath $rustBin -File -Filter "rustc_driver-*.dll"
        Get-ChildItem -LiteralPath $rustBin -File -Filter "std-*.dll"
    )
    if ($rustFiles.Count -ne 3 -or ($rustFiles | Measure-Object Length -Sum).Sum -gt 536870912) {
        throw "minimal rustc runtime boundary is invalid"
    }
    foreach ($file in $rustFiles) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "minimal rustc runtime cannot contain a reparse point"
        }
        Copy-Item -LiteralPath $file.FullName -Destination $rustDestination -ErrorAction Stop
    }

    $powerShellArchive = Resolve-ExternalFile `
        -Path $PowerShellZip `
        -Label "portable PowerShell ZIP" `
        -MaximumBytes 536870912
    if ((Get-FileHash -LiteralPath $powerShellArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $script:expectedPowerShellZipSha256) {
        throw "portable PowerShell ZIP hash mismatch"
    }
    $stagedPowerShellArchive = Join-Path $Destination "portable-pwsh.zip"
    if (Test-Path -LiteralPath $stagedPowerShellArchive) {
        throw "portable PowerShell archive staging baseline is not absent"
    }
    Copy-Item -LiteralPath $powerShellArchive -Destination $stagedPowerShellArchive -ErrorAction Stop
    $stagedPowerShellHash = (Get-FileHash `
        -LiteralPath $stagedPowerShellArchive `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($stagedPowerShellHash -cne $script:expectedPowerShellZipSha256) {
        throw "copied portable PowerShell ZIP hash mismatch"
    }
    $pwshRoot = Join-Path $Destination "pwsh"
    if (Test-Path -LiteralPath $pwshRoot) {
        throw "portable PowerShell expansion baseline is not absent"
    }
    Expand-Archive -LiteralPath $stagedPowerShellArchive -DestinationPath $pwshRoot -ErrorAction Stop
    $pwshItems = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
        Get-ChildItem -LiteralPath $pwshRoot -Force -Recurse
    )
    if (@($pwshItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0) {
        throw "portable PowerShell runtime cannot contain a reparse point"
    }
    $pwshFiles = @($pwshItems | Where-Object { -not $_.PSIsContainer })
    $pwshBytes = [long]($pwshFiles | Measure-Object Length -Sum).Sum
    if ($pwshFiles.Count -le 0 -or $pwshFiles.Count -gt 4096 -or
        $pwshBytes -le 0 -or $pwshBytes -gt 1073741824) {
        throw "portable PowerShell runtime exceeds its staging boundary"
    }
    $pwsh = Join-Path $pwshRoot "pwsh.exe"
    $pwshVersion = @(& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1)
    if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
        [string]$pwshVersion[0] -cne $script:expectedPowerShellVersion) {
        throw "portable PowerShell version is not the pinned compatible release"
    }
    $pwshExecutableSha256 = (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::Delete($stagedPowerShellArchive)

    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $vcDestination = Join-Path $Destination "vc-runtime"
    [IO.Directory]::CreateDirectory($vcDestination) | Out-Null
    $copied = 0
    foreach ($name in @("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll")) {
        $source = Join-Path $system $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination $vcDestination -ErrorAction Stop
            $copied++
        }
    }
    if ($copied -eq 0) { throw "host Visual C++ runtime dependencies are unavailable" }
    return [pscustomobject]@{
        PowerShellVersion = [string]$pwshVersion[0]
        PowerShellExecutableSha256 = $pwshExecutableSha256
        PowerShellFileCount = [long]$pwshFiles.Count
        PowerShellExpandedBytes = $pwshBytes
    }
}

$git = @(Get-Command git -CommandType Application -ErrorAction Stop)[0].Source
$python = @(Get-Command python -CommandType Application -ErrorAction Stop)[0].Source
foreach ($required in @(
    $policyPath, $controlPath, $collectorPath, $guestNetworkPathProbePath,
    $hostNetworkPathHelperPath, $topologyRuntimePath, $networkModelControllerPath
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required performance controller file is missing: $required"
    }
}
if (-not (Test-Path -LiteralPath $udpBoundaryCollectorPath -PathType Leaf)) {
    throw "required UDP boundary collector file is missing: $udpBoundaryCollectorPath"
}
$udpBoundaryCollectorSourceSha256 = (Get-FileHash `
    -LiteralPath $udpBoundaryCollectorPath -Algorithm SHA256).Hash.ToLowerInvariant()
. $topologyRuntimePath -LibraryOnly
$topologyRuntimeSha256 = (Get-FileHash -LiteralPath $topologyRuntimePath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$guestNetworkPathProbeSourceSha256 = (Get-FileHash `
    -LiteralPath $guestNetworkPathProbePath -Algorithm SHA256).Hash.ToLowerInvariant()
$topologyPlanDocument = Read-Ferrum2SupportTopologyPlanDocument
$approvedVmName = [string]$topologyPlanDocument.Value.vm.name
$approvedVmId = [Guid][string]$topologyPlanDocument.Value.vm.id
$approvedCheckpointName = [string]$topologyPlanDocument.Value.
    qualification_checkpoint.name
$approvedVmSwitchName = [string]$topologyPlanDocument.Value.support.switch_name
$SupportIpv4 = [string]$topologyPlanDocument.Value.support.host_ipv4
$supportGuestIpv4 = [string]$topologyPlanDocument.Value.support.guest_ipv4
$supportGuestInterfaceAlias = [string]$topologyPlanDocument.Value.support.guest_interface_alias
$supportNetwork = [string]$topologyPlanDocument.Value.support.network
$supportPrefixLength = [int]$topologyPlanDocument.Value.support.prefix_length
$supportVmMacAddress = ConvertTo-Ferrum2CanonicalMacAddress `
    -Value ([string]$topologyPlanDocument.Value.support.vm_mac_address) `
    -Label "planned support VM adapter"
$supportGuestInterfaceGuid = [Guid]::Empty
$supportGuestMtuBytes = 0
if (-not $PlanOnly) {
    $topologyManifestDocument = Read-Ferrum2SupportTopologyManifest `
        -Path $TopologyManifestPath -ExpectedSha256 $TopologyManifestSha256 `
        -RepositoryRoot $repositoryRoot
    $approvedCheckpointId = [Guid][string]$topologyManifestDocument.Value.
        qualification_checkpoint.id
    $supportGuestInterfaceGuid = [Guid][string]$topologyManifestDocument.Value.support.guest.
        support_interface_guid
    $supportGuestMtuBytes = [int]$topologyManifestDocument.Value.support.guest.mtu_bytes
}
. $hostNetworkPathHelperPath
$hostNetworkPathHelperSha256 = (Get-FileHash -LiteralPath $hostNetworkPathHelperPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$head = [string](& $git -C $repositoryRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[0-9a-f]{40}$') {
    throw "repository HEAD identity is invalid"
}
if ([string]::IsNullOrWhiteSpace($CandidateSha)) { $CandidateSha = $head }
[void](Resolve-Commit -Git $git -Sha $CandidateSha -Label "candidate")
[void](Resolve-Commit -Git $git -Sha $ParentSha -Label "parent")
$parentTree = Get-TreeSha -Git $git -Sha $ParentSha
$candidateTree = Get-TreeSha -Git $git -Sha $CandidateSha
if ($RunKind -ceq "calibration-aa" -and $ParentSha -cne $CandidateSha) {
    throw "calibration-aa requires identical parent and candidate SHAs"
}
if ($instrumentedDiagnosticMode -and $ParentSha -cne $CandidateSha) {
    throw "UdpFlowBoundary requires identical parent and candidate SHAs"
}
if ($RunKind -ceq "comparison") {
    if ($ParentSha -ceq $CandidateSha) { throw "comparison requires distinct commits" }
    Invoke-NativeChecked -Executable $python -Label "parent/candidate ancestry validation" -Arguments @(
        "-B", $controlPath, "validate-git", "--repository", $repositoryRoot,
        "--parent-sha", $ParentSha, "--candidate-sha", $CandidateSha
    )
}

if ($PlanOnly) {
    $planRoot = Join-Path ([IO.Path]::GetTempPath()) ("ferrum2-tun-plan-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($planRoot) | Out-Null
    try {
        $planPath = Join-Path $planRoot "plan.json"
        $plan = New-CanonicalPlan -Python $python -RunKindValue $RunKind -Output $planPath
        $networkModelPlanPath = Join-Path $planRoot "network-model-plan.json"
        [void](New-NetworkModelPlan -Python $python -Output $networkModelPlanPath `
            -ExpectedSha256 ([string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256))
        [pscustomobject]@{
            schema = "ferrum2.windows-tun.hyperv-performance-plan.v2"
            run_kind = $RunKind
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            parent_tree = $parentTree
            candidate_tree = $candidateTree
            trials = @($plan.trials).Count
            recipe_sha256 = [string]$plan.recipe_sha256
            network_model_controller_sha256 = [string]$plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256
            network_model_plan_sha256 = [string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $null
            topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
            topology_manifest_required_at_run = $true
            host_actions = @(
                "validate manifest-bound isolated support binding", "archive exact commits",
                "build profiling binaries", "stage files",
                "validate direct Internal-switch return path", "reduce evidence"
            )
            guest_actions = @(
                "reject gateway and DNS support collisions", "probe support",
                "validate manifest-bound /30 underlay", "run 90 collector trials",
                "collect 10 raw route-once and 10 raw lifecycle sidecars",
                "clean each TUN session"
            )
            host_network_mutations = 0
        } | ConvertTo-Json -Depth 6
    } finally {
        if ((Test-Path -LiteralPath $planRoot -PathType Container) -and
            $planRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
            [IO.Directory]::Delete($planRoot, $true)
        }
    }
    exit 0
}

if ($CandidateSha -cne $head) { throw "run mode requires candidate SHA to equal repository HEAD" }
& $git -C $repositoryRoot diff --quiet --exit-code
if ($LASTEXITCODE -ne 0) { throw "run mode requires no unstaged tracked changes" }
& $git -C $repositoryRoot diff --cached --quiet --exit-code
if ($LASTEXITCODE -ne 0) { throw "run mode requires no staged changes" }
$supportHostBaseline = Get-HostSupportContext `
    -TopologyDocument $topologyManifestDocument `
    -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner `
    -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
$vmNetworkBaseline = Get-ApprovedVmNetworkContext `
    -TopologyDocument $topologyManifestDocument `
    -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes

if ([string]::IsNullOrWhiteSpace($PowerShellZip)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the default portable PowerShell ZIP"
    }
    $PowerShellZip = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\PowerShell-$expectedPowerShellVersion-win-x64.zip"
}
$resolvedPowerShellZip = Resolve-ExternalFile `
    -Path $PowerShellZip `
    -Label "portable PowerShell ZIP" `
    -MaximumBytes 536870912
if ((Get-FileHash -LiteralPath $resolvedPowerShellZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $expectedPowerShellZipSha256) {
    throw "portable PowerShell ZIP hash mismatch"
}
$resolvedWintunZip = Resolve-ExternalFile -Path $WintunZip -Label "Wintun ZIP"
if ((Get-FileHash -LiteralPath $resolvedWintunZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $expectedWintunZipSha256) {
    throw "Wintun ZIP hash mismatch"
}
$resolvedSupportDiagnosticLedger = $null
$supportDiagnosticBaseline = $null
if ($instrumentedDiagnosticMode) {
    $resolvedSupportDiagnosticLedger = Resolve-ExternalFile `
        -Path $SupportDiagnosticLedger -Label "support diagnostic ledger" `
        -MaximumBytes 268451840
    $supportDiagnosticBaseline = Get-UdpDiagnosticLedgerSummary `
        -Path $resolvedSupportDiagnosticLedger `
        -ExpectedSchema "ferrum2.windows-tun.udp-support-ledger.v2" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    $expectedSupportHeaderFields = @(
        "closure", "listen_ip", "max_events", "pid", "record_type",
        "run_nonce", "schema", "scope", "tcp_port", "timestamp_clock",
        "udp_ports"
    )
    $actualSupportHeaderFields = @(
        $supportDiagnosticBaseline.Header.PSObject.Properties.Name |
            Sort-Object
    )
    $supportHeaderPorts = @($supportDiagnosticBaseline.Header.udp_ports)
    $supportHeaderPortsMatch = $supportHeaderPorts.Count -eq 4
    if ($supportHeaderPortsMatch) {
        for ($portOffset = 0; $portOffset -lt 4; $portOffset++) {
            if ([int]$supportHeaderPorts[$portOffset] -ne
                ($SupportUdpPort + $portOffset)) {
                $supportHeaderPortsMatch = $false
                break
            }
        }
    }
    if (($actualSupportHeaderFields -join "`n") -cne
            ($expectedSupportHeaderFields -join "`n") -or
        [int]$supportDiagnosticBaseline.Header.pid -ne $SupportPid -or
        [string]$supportDiagnosticBaseline.Header.listen_ip -cne $SupportIpv4 -or
        [int]$supportDiagnosticBaseline.Header.tcp_port -ne $SupportTcpPort -or
        [string]$supportDiagnosticBaseline.Header.scope -cne "bootstrap" -or
        [string]$supportDiagnosticBaseline.Header.closure -cne
            "host_four_port_barrier_after_vm_off" -or
        -not $supportHeaderPortsMatch) {
        throw "support diagnostic ledger header does not match the pinned support process"
    }
    if ($supportDiagnosticBaseline.Closed -or
        $supportDiagnosticBaseline.DroppedEvents -ne 0 -or
        $supportDiagnosticBaseline.WriteFailures -ne 0 -or
        $supportDiagnosticBaseline.MatchingRunNonceEvents -ne 0) {
        throw "support diagnostic ledger baseline is stale, closed, or degraded"
    }
}
$hostEvidenceRoot = Resolve-NewExternalDirectory -Path $EvidenceDirectory -Label "evidence directory"
$credential = Import-ApprovedGuestCredential -Path $CredentialPath
$cargo = @(Get-Command cargo -CommandType Application -ErrorAction Stop)[0].Source
$rustup = @(Get-Command rustup -CommandType Application -ErrorAction Stop)[0].Source
$tar = @(Get-Command tar -CommandType Application -ErrorAction Stop)[0].Source
if (-not [string]::IsNullOrEmpty($env:RUSTFLAGS) -or
    -not [string]::IsNullOrEmpty($env:CARGO_ENCODED_RUSTFLAGS)) {
    throw "run mode requires empty host Rust flag environment variables"
}
$hostRustc = [string](& $rustup which --toolchain 1.97.1 rustc 2>$null)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostRustc -PathType Leaf)) {
    throw "host Rust 1.97.1 compiler is unavailable"
}
$hostRustIdentity = @(& $hostRustc -vV 2>&1)
$hostRustIdentityText = $hostRustIdentity -join "`n"
if ($LASTEXITCODE -ne 0 -or
    $hostRustIdentityText -cnotmatch '^rustc 1\.97\.1 \(' -or
    $hostRustIdentityText -cnotmatch '(?m)^host: x86_64-pc-windows-msvc$') {
    throw "host Rust toolchain must be Rust 1.97.1 x86_64-pc-windows-msvc"
}
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-tun-performance-" + [Guid]::NewGuid().ToString("N")
)
$artifactRoot = Join-Path $temporaryRoot "input\artifacts"
$runtimeRoot = Join-Path $temporaryRoot "input\runtime"
$hostPlanPath = Join-Path $hostEvidenceRoot "plan.json"
$hostTopologyManifestPath = Join-Path $hostEvidenceRoot "topology-manifest.json"
$hostNetworkModelPlanPath = Join-Path $hostEvidenceRoot "network-model-plan.json"
$hostNetworkPathPath = Join-Path $hostEvidenceRoot "host-network-path.json"
$hostSchedulePath = Join-Path $hostEvidenceRoot "trial-schedule.tsv"
$hostSummaryPath = Join-Path $hostEvidenceRoot "summary.json"
$hostMarkdownPath = Join-Path $hostEvidenceRoot "summary.md"
$hostCalibrationPath = Join-Path $hostEvidenceRoot "aa-calibration.json"
$hostDiagnosticRoot = Join-Path $hostEvidenceRoot "udp-diagnostic"
$hostDiagnosticGuestRoot = Join-Path $hostDiagnosticRoot "guest"
$hostDiagnosticHostRoot = Join-Path $hostDiagnosticRoot "host"
$hostDiagnosticSupportRoot = Join-Path $hostDiagnosticRoot "support"
$hostDiagnosticPath = Join-Path $hostDiagnosticRoot "udp-diagnostic.json"
$hostDiagnosticFailurePath = Join-Path $hostDiagnosticRoot "failure-summary.json"
$guestToken = [Guid]::NewGuid().ToString("N")
$guestRoot = "C:\Windows\Temp\ferrum2-tun-performance-$guestToken"
$session = $null
$vmWindowStarted = $false
$guestEvidenceAvailable = $false
$runFailure = $null
$restoreFailure = $null
$hostCaptureState = $null
$hostCaptureResult = $null
$hostCaptureFailure = $null
$hostEndpointSnapshotFailures = [Collections.Generic.List[string]]::new()
$diagnosticSourcePlan = $null

try {
    [IO.Directory]::CreateDirectory($hostEvidenceRoot) | Out-Null
    Copy-Item -LiteralPath $topologyManifestDocument.Path `
        -Destination $hostTopologyManifestPath -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $hostTopologyManifestPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $topologyManifestDocument.Sha256 -or
        (Get-Item -LiteralPath $hostTopologyManifestPath -Force).Length -ne
            $topologyManifestDocument.Length) {
        throw "evidence topology manifest copy changed"
    }
    [IO.Directory]::CreateDirectory($artifactRoot) | Out-Null
    [IO.Directory]::CreateDirectory($runtimeRoot) | Out-Null
    if ($instrumentedDiagnosticMode) {
        [IO.Directory]::CreateDirectory($hostDiagnosticRoot) | Out-Null
        [IO.Directory]::CreateDirectory($hostDiagnosticHostRoot) | Out-Null
        [IO.Directory]::CreateDirectory($hostDiagnosticSupportRoot) | Out-Null
    }
    $plan = New-CanonicalPlan -Python $python -RunKindValue $RunKind -Output $hostPlanPath
    $udpBoundaryRecipe = $plan.scenarios.
        "udp-8192-association-lookup-expiry".recipe
    $canonicalSourcePlan = [pscustomobject]@{
        Ipv4 = [string]$udpBoundaryRecipe.canonical_source_ipv4
        PortFirst = [int]$udpBoundaryRecipe.canonical_source_port_first
        PortLast = [int]$udpBoundaryRecipe.canonical_source_port_last
    }
    $diagnosticSourcePlan = [pscustomobject]@{
        Ipv4 = [string]$udpBoundaryRecipe.diagnostic_source_ipv4
        PortFirst = [int]$udpBoundaryRecipe.diagnostic_source_port_first
        PortLast = [int]$udpBoundaryRecipe.diagnostic_source_port_last
        CollectorSha256 = [string]$udpBoundaryRecipe.
            diagnostic_collector_source_sha256
    }
    $runtimeIdleTimeoutMilliseconds = [int]$plan.scenarios."tcp-single-flow".recipe.
        client_runtime_idle_timeout_milliseconds
    $tunRingCapacityBytes = [long]$plan.scenarios."tcp-single-flow".recipe.
        tun_ring_capacity_bytes
    [void](New-NetworkModelPlan -Python $python -Output $hostNetworkModelPlanPath `
        -ExpectedSha256 ([string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256))
    $executionTrials = @(if ($diagnosticMode) {
        $plan.trials | Where-Object {
            [int]$_.sequence -eq $DiagnosticTrialSequence
        } | Sort-Object sequence
    } else {
        $plan.trials | Sort-Object sequence
    })
    if (($diagnosticMode -and $executionTrials.Count -ne 1) -or
        (-not $diagnosticMode -and $executionTrials.Count -ne 90)) {
        throw "canonical Windows TUN execution selection is invalid"
    }
    if ($instrumentedDiagnosticMode -and (
        [string]$executionTrials[0].scenario -cne
            "udp-8192-association-lookup-expiry" -or
        [string]$executionTrials[0].member -cne "parent"
    )) {
        throw "UdpFlowBoundary trial identity is not canonical sequence 31 parent"
    }
    $expectedTrialCount = if ($instrumentedDiagnosticMode) {
        0
    } else {
        $executionTrials.Count
    }
    $expectedNetworkModelObservationCount = if ($instrumentedDiagnosticMode) {
        0
    } else {
        @($executionTrials | Where-Object {
            [string]$_.scenario -in @("udp-route-once", "network-lifecycle")
        }).Count
    }
    $expectedProcessLogCount = 4 * $expectedTrialCount
    $expectedDiagnosticProcessLogCount = if ($instrumentedDiagnosticMode) { 4 } else { 0 }
    $diagnosticTrial = if ($diagnosticMode) { $executionTrials[0] } else { $null }
    $diagnosticSequenceValue = if ($diagnosticMode) { $DiagnosticTrialSequence } else { 0 }
    $scheduleLines = @($plan.trials | ForEach-Object {
        "$($_.sequence)`t$($_.scenario)`t$($_.member)`t$($_.pair)`t$($_.order)"
    })
    Write-Utf8FileNew -Path $hostSchedulePath -Text (($scheduleLines -join "`n") + "`n")

    $candidateBuild = Build-MemberArtifacts -Cargo $cargo -Git $git -Tar $tar `
        -Sha $CandidateSha -Member "candidate" -TemporaryRoot $temporaryRoot `
        -ArtifactRoot $artifactRoot -IncludeHarness
    if ($ParentSha -ceq $CandidateSha) {
        $parentDirectory = Join-Path $artifactRoot "parent"
        [IO.Directory]::CreateDirectory($parentDirectory) | Out-Null
        Copy-Item -LiteralPath $candidateBuild.Client `
            -Destination (Join-Path $parentDirectory "ferrum2-client.exe") -ErrorAction Stop
        Copy-Item -LiteralPath $candidateBuild.Server `
            -Destination (Join-Path $parentDirectory "ferrum2-server.exe") -ErrorAction Stop
        $parentBuild = [pscustomobject]@{
            Client = Join-Path $parentDirectory "ferrum2-client.exe"
            Server = Join-Path $parentDirectory "ferrum2-server.exe"
            ClientSha256 = $candidateBuild.ClientSha256
            ServerSha256 = $candidateBuild.ServerSha256
        }
    } else {
        $parentBuild = Build-MemberArtifacts -Cargo $cargo -Git $git -Tar $tar `
            -Sha $ParentSha -Member "parent" -TemporaryRoot $temporaryRoot `
            -ArtifactRoot $artifactRoot
    }

    Copy-Item -LiteralPath $collectorPath -Destination (Join-Path $temporaryRoot "input") `
        -ErrorAction Stop
    $udpBoundaryCollectorSha256 = ""
    if ($instrumentedDiagnosticMode) {
        Copy-Item -LiteralPath $udpBoundaryCollectorPath `
            -Destination (Join-Path $temporaryRoot "input") -ErrorAction Stop
        $udpBoundaryCollectorSha256 = (Get-FileHash `
            -LiteralPath $udpBoundaryCollectorPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($udpBoundaryCollectorSha256 -cne
                $udpBoundaryCollectorSourceSha256 -or
            $udpBoundaryCollectorSha256 -cne
                [string]$diagnosticSourcePlan.CollectorSha256) {
            throw "UDP boundary collector source changed after plan generation"
        }
    }
    $guestNetworkPathProbeDestination = Join-Path $temporaryRoot `
        "input\get_windows_tun_guest_network_path.ps1"
    Copy-Item -LiteralPath $guestNetworkPathProbePath `
        -Destination $guestNetworkPathProbeDestination -ErrorAction Stop
    $guestNetworkPathProbeSha256 = (Get-FileHash -LiteralPath $guestNetworkPathProbePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($guestNetworkPathProbeSha256 -cne $guestNetworkPathProbeSourceSha256) {
        throw "guest network-path probe source changed after plan generation"
    }
    if ((Get-FileHash -LiteralPath $guestNetworkPathProbeDestination `
            -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $guestNetworkPathProbeSourceSha256) {
        throw "staged guest network-path probe identity mismatch"
    }
    Copy-Item -LiteralPath $networkModelControllerPath `
        -Destination (Join-Path $temporaryRoot "input\windows_tun_network_model.py") `
        -ErrorAction Stop
    Copy-Item -LiteralPath $resolvedWintunZip `
        -Destination (Join-Path $temporaryRoot "input\wintun-0.14.1.zip") -ErrorAction Stop
    Copy-Item -LiteralPath $hostPlanPath -Destination (Join-Path $temporaryRoot "input\plan.json") `
        -ErrorAction Stop
    Copy-Item -LiteralPath $hostNetworkModelPlanPath `
        -Destination (Join-Path $temporaryRoot "input\network-model-plan.json") `
        -ErrorAction Stop
    $portableRuntime = Stage-PortableRuntime `
        -Rustup $rustup `
        -PowerShellZip $resolvedPowerShellZip `
        -Destination $runtimeRoot

    $clientTemplate = @'
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "{{ADAPTER_NAME}}"
ipv4_address = "198.18.0.2/30"
mtu = 1420
auto_route = true
route_address = ["{{SUPPORT_IPV4}}/32"]
ring_capacity = {{TUN_RING_CAPACITY_BYTES}}
ready_timeout_ms = 30000
max_tcp_flows = 4096
tcp_buffer_bytes = 32768
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
[[outbounds]]
tag = "direct"
type = "direct"
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[[outbounds]]
tag = "proxy"
server = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[route]
auto_detect_interface = false
default_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
final = "proxy"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "{{SUPPORT_IPV4}}"
port = {{SUPPORT_UDP_PORT}}
action = "route"
outbound = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
idle_timeout_ms = {{RUNTIME_IDLE_TIMEOUT_MS}}
[metrics]
listen = "127.0.0.1:{{METRICS_PORT}}"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
'@
    $clientTemplate = $clientTemplate.Replace(
        "{{RUNTIME_IDLE_TIMEOUT_MS}}",
        [string]$runtimeIdleTimeoutMilliseconds
    )
    $clientTemplate = $clientTemplate.Replace(
        "{{TUN_RING_CAPACITY_BYTES}}",
        [string]$tunRingCapacityBytes
    )
    $serverTemplate = @'
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
[[outbounds]]
tag = "direct"
bind_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
inet4_bind_address = "{{GUEST_SUPPORT_IPV4}}"
[route]
auto_detect_interface = false
default_interface = "{{SUPPORT_INTERFACE_ALIAS}}"
final = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
[metrics]
listen = "127.0.0.1:{{SERVER_METRICS_PORT}}"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
'@
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\client.toml.template") `
        -Text ($clientTemplate.TrimStart([char[]]"`r`n") + "`n")
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\server.toml.template") `
        -Text ($serverTemplate.TrimStart([char[]]"`r`n") + "`n")

    $supportHostReadback = Get-HostSupportContext `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostReadback
    if ($instrumentedDiagnosticMode -and
        [string]$supportHostReadback.executable_sha256 -cne
            $candidateBuild.HarnessSha256) {
        throw "support diagnostic binary does not match the candidate harness"
    }
    $vmNetworkReadback = Get-ApprovedVmNetworkContext `
        -TopologyDocument $topologyManifestDocument `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $vmNetworkBaseline -Actual $vmNetworkReadback
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off at the performance-window baseline"
    }
    # From this point every exit path must restore the approved checkpoint, including a
    # Start-VM call that reports failure after partially transitioning the VM.
    $vmWindowStarted = $true
    Restore-ApprovedCheckpoint
    (Get-ApprovedVmContext).Vm | Start-VM -ErrorAction Stop | Out-Null
    if ([string](Get-ApprovedVmContext).Vm.State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
    $connection = Connect-ApprovedGuest -Credential $credential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    $session = $connection.Session

    Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
        param([string]$Root)
        if (Test-Path -LiteralPath $Root) { throw "guest staging baseline is not absent" }
        New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null
    }
    Copy-Item -ToSession $session -LiteralPath (Join-Path $temporaryRoot "input") `
        -Destination $guestRoot -Recurse -ErrorAction Stop

    $guestNetworkPathJsonRows = @(Invoke-Command -Session $session -ErrorAction Stop `
        -ArgumentList @(
            $guestRoot, $SupportIpv4, $SupportTcpPort, $SupportUdpPort,
            $supportGuestIpv4, $supportGuestInterfaceAlias, $supportNetwork,
            $supportPrefixLength, $supportVmMacAddress,
            $supportGuestInterfaceGuid.ToString("D"), $supportGuestMtuBytes,
            $guestNetworkPathProbeSha256, $candidateBuild.HarnessSha256,
            $portableRuntime.PowerShellExecutableSha256,
            $minimumSupportIpv4PacketBytes
        ) -ScriptBlock {
            param(
                [string]$Root,
                [string]$SupportAddress,
                [int]$SupportTcp,
                [int]$SupportUdp,
                [string]$ExpectedGuestAddress,
                [string]$ExpectedGuestInterfaceAlias,
                [string]$ExpectedSupportNetwork,
                [int]$ExpectedSupportPrefixLength,
                [string]$ExpectedSupportMacAddress,
                [string]$ExpectedSupportInterfaceGuid,
                [int]$ExpectedSupportMtuBytes,
                [string]$ExpectedNetworkPathProbeSha256,
                [string]$ExpectedHarnessSha256,
                [string]$ExpectedPowerShellSha256,
                [int]$MinimumSupportIpv4PacketBytes
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $inputRoot = Join-Path $Root "input"
            $networkPathProbe = Join-Path $inputRoot `
                "get_windows_tun_guest_network_path.ps1"
            $harness = Join-Path $inputRoot "artifacts\m4-qualification.exe"
            $powerShell = Join-Path $inputRoot "runtime\pwsh\pwsh.exe"
            if ((Get-FileHash -LiteralPath $networkPathProbe -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedNetworkPathProbeSha256 -or
                (Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedHarnessSha256 -or
                (Get-FileHash -LiteralPath $powerShell -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $ExpectedPowerShellSha256) {
                throw "guest network-path preflight executable identity mismatch"
            }
            $vcRuntimeRoot = Join-Path $inputRoot "runtime\vc-runtime"
            $vcRuntimeItems = @(Get-ChildItem -LiteralPath $vcRuntimeRoot -Force -ErrorAction Stop)
            $vcRuntimeDlls = @($vcRuntimeItems | Where-Object { -not $_.PSIsContainer })
            $allowedVcRuntimeNames = @(
                "VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"
            )
            if ($vcRuntimeDlls.Count -le 0 -or $vcRuntimeDlls.Count -gt 3 -or
                $vcRuntimeItems.Count -ne $vcRuntimeDlls.Count -or
                @($vcRuntimeDlls | Where-Object {
                    $_.Name -cnotin $allowedVcRuntimeNames -or
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $_.Length -le 0 -or $_.Length -gt 16777216
                }).Count -ne 0) {
                throw "guest preflight Visual C++ runtime boundary is invalid"
            }
            $harnessRoot = Split-Path -Parent $harness
            foreach ($runtimeDll in $vcRuntimeDlls) {
                $runtimeDestination = Join-Path $harnessRoot $runtimeDll.Name
                if (Test-Path -LiteralPath $runtimeDestination) {
                    throw "guest preflight Visual C++ runtime baseline is not absent"
                }
                Copy-Item -LiteralPath $runtimeDll.FullName -Destination $runtimeDestination `
                    -ErrorAction Stop
                if ((Get-FileHash -LiteralPath $runtimeDestination -Algorithm SHA256).Hash `
                        -cne (Get-FileHash -LiteralPath $runtimeDll.FullName -Algorithm SHA256).Hash) {
                    throw "guest preflight Visual C++ runtime copy changed"
                }
            }
            $pathOutput = @(& $powerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $networkPathProbe -SupportIpv4 $SupportAddress `
                -SupportPort $SupportUdp -ManagedAdapterName "Ferrum2Perf" `
                -ExpectedGuestIpv4 $ExpectedGuestAddress `
                -ExpectedInterfaceAlias $ExpectedGuestInterfaceAlias `
                -ExpectedNetwork $ExpectedSupportNetwork `
                -ExpectedPrefixLength $ExpectedSupportPrefixLength `
                -ExpectedMacAddress $ExpectedSupportMacAddress `
                -ExpectedInterfaceGuid $ExpectedSupportInterfaceGuid `
                -ExpectedMtuBytes $ExpectedSupportMtuBytes `
                -MinimumUnderlayIpv4PacketBytes $MinimumSupportIpv4PacketBytes `
                -AsJson 2>&1)
            if ($LASTEXITCODE -ne 0 -or $pathOutput.Count -ne 1) {
                throw "guest network-path preflight returned an invalid result count"
            }
            $path = [string]$pathOutput[0] | ConvertFrom-Json
            $probeOutput = @(& $harness windows-tun-probe `
                --target-ip $SupportAddress --tcp-port $SupportTcp --udp-port $SupportUdp 2>&1)
            $probeExitCode = $LASTEXITCODE
            if ($probeExitCode -ne 0 -or $probeOutput.Count -ne 1 -or
                [string]$probeOutput[0] -cne
                    "windows_tun_probe status=PASS protocols=tcp,udp") {
                $probeDiagnostic = @($probeOutput | Select-Object -First 4 | ForEach-Object {
                    ([string]$_ -replace '[\r\n]+', ' ').Trim()
                }) -join " | "
                if ($probeDiagnostic.Length -gt 2048) {
                    $probeDiagnostic = $probeDiagnostic.Substring(0, 2048)
                }
                if ([string]::IsNullOrWhiteSpace($probeDiagnostic)) {
                    $probeDiagnostic = "<no output>"
                }
                throw "guest support listener direct preflight failed: exit=$probeExitCode output=$probeDiagnostic"
            }
            return ($path | ConvertTo-Json -Compress -Depth 5)
        })
    if ($guestNetworkPathJsonRows.Count -ne 1) {
        throw "guest network-path preflight result is not unique"
    }
    $guestNetworkPathJson = [string]$guestNetworkPathJsonRows[0]
    $guestNetworkPath = $guestNetworkPathJson | ConvertFrom-Json -Depth 5
    $supportHostAfterProbe = Get-HostSupportContext `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostAfterProbe
    $vmNetworkAfterProbe = Get-ApprovedVmNetworkContext `
        -TopologyDocument $topologyManifestDocument `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $vmNetworkBaseline -Actual $vmNetworkAfterProbe
    $hostReturnPath = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPath -VmNetworkContext $vmNetworkAfterProbe `
        -ExpectedSupportIpv4 $SupportIpv4
    $networkPathEvidence = [ordered]@{
        schema = 2
        kind = "windows_tun_host_network_path"
        topology = [ordered]@{
            manifest_sha256 = [string]$topologyManifestDocument.Sha256
            plan_sha256 = [string]$topologyPlanDocument.Sha256
            support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
            qualification_checkpoint_id = $approvedCheckpointId.ToString("D")
        }
        support_listener = $supportHostAfterProbe
        approved_vm_network = $vmNetworkAfterProbe
        guest_forward_path = $guestNetworkPath
        host_return_path = $hostReturnPath
        guest_probe_sha256 = $guestNetworkPathProbeSha256
        host_helper_sha256 = $hostNetworkPathHelperSha256
        support_path_probe = [ordered]@{
            status = "PASS"
            harness_sha256 = $candidateBuild.HarnessSha256
            minimum_ipv4_packet_bytes = $minimumSupportIpv4PacketBytes
            fragment_payload_bytes = 1440
            fragment_ack_bytes = 24
        }
        host_tun_bypassed = $true
        host_network_mutations = 0
    }
    Write-Utf8FileNew -Path $hostNetworkPathPath `
        -Text (($networkPathEvidence | ConvertTo-Json -Depth 6) + "`n")

    if ($instrumentedDiagnosticMode) {
        $hostEndpointPrePath = Join-Path $hostDiagnosticHostRoot `
            "host-endpoints-pre.json"
        try {
            Write-HostUdpEndpointSnapshot -Path $hostEndpointPrePath `
                -Stage "pre_workload" -SupportProcessId $SupportPid
        } catch {
            $hostEndpointSnapshotFailures.Add("pre: $($_.Exception.Message)")
            Write-HostUdpEndpointErrorSnapshot -Path $hostEndpointPrePath `
                -Stage "pre_workload" -SupportProcessId $SupportPid `
                -Failure $_.Exception.Message
        }
        $hostCaptureState = Start-HostUdpDiagnosticCapture `
            -Directory $hostDiagnosticHostRoot `
            -SupportAddress $SupportIpv4 `
            -FirstUdpPort $SupportUdpPort
    }

    # BEGIN GUEST_ONLY_NETWORK_EXECUTION
    $guestResult = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @(
        $guestRoot,
        $approvedVmName,
        $approvedVmId.ToString("D"),
        $approvedCheckpointName,
        $approvedCheckpointId.ToString("D"),
        [string]$topologyManifestDocument.Sha256,
        [string]$topologyPlanDocument.Sha256,
        $approvedVmSwitchName,
        [string]$topologyManifestDocument.Value.support.switch.switch_id,
        $expectedWintunZipSha256,
        $expectedWintunDllSha256,
        $portableRuntime.PowerShellVersion,
        $portableRuntime.PowerShellExecutableSha256,
        $portableRuntime.PowerShellFileCount,
        $portableRuntime.PowerShellExpandedBytes,
        $RunKind,
        $ParentSha,
        $CandidateSha,
        $parentTree,
        $candidateTree,
        [string]$plan.recipe_sha256,
        [string]$plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256,
        [string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256,
        $guestNetworkPathProbeSha256,
        $guestNetworkPathJson,
        $SupportIpv4,
        $SupportTcpPort,
        $SupportUdpPort,
        $supportGuestIpv4,
        $supportGuestInterfaceAlias,
        $supportNetwork,
        $supportPrefixLength,
        $supportVmMacAddress,
        $supportGuestInterfaceGuid.ToString("D"),
        $supportGuestMtuBytes,
        $SupportPid,
        $SupportOwner,
        $minimumSupportIpv4PacketBytes,
        [string]$canonicalSourcePlan.Ipv4,
        [int]$canonicalSourcePlan.PortFirst,
        [int]$canonicalSourcePlan.PortLast,
        $diagnosticSequenceValue,
        $(if ($instrumentedDiagnosticMode) { $DiagnosticProfile } else { "" }),
        $(if ($instrumentedDiagnosticMode) { $SupportDiagnosticRunNonce } else { "" }),
        $(if ($instrumentedDiagnosticMode) { $SupportDiagnosticMaxEvents } else { 0 }),
        $udpBoundaryCollectorSha256,
        $(if ($instrumentedDiagnosticMode) {
            [string]$diagnosticSourcePlan.Ipv4
        } else { "" }),
        $(if ($instrumentedDiagnosticMode) {
            [int]$diagnosticSourcePlan.PortFirst
        } else { 0 }),
        $(if ($instrumentedDiagnosticMode) {
            [int]$diagnosticSourcePlan.PortLast
        } else { 0 })
    ) -ScriptBlock {
        param(
            [string]$Root,
            [string]$VmName,
            [string]$VmId,
            [string]$CheckpointName,
            [string]$CheckpointId,
            [string]$TopologyManifestSha256Value,
            [string]$TopologyPlanSha256Value,
            [string]$SupportSwitchName,
            [string]$SupportSwitchId,
            [string]$WintunZipSha256,
            [string]$WintunDllSha256,
            [string]$PowerShellVersion,
            [string]$PowerShellExecutableSha256,
            [long]$PowerShellFileCount,
            [long]$PowerShellExpandedBytes,
            [string]$RunKindValue,
            [string]$ParentCommit,
            [string]$CandidateCommit,
            [string]$ParentTree,
            [string]$CandidateTree,
            [string]$RecipeSha256,
            [string]$NetworkModelControllerSha256,
            [string]$NetworkModelPlanSha256,
            [string]$GuestNetworkPathProbeSha256,
            [string]$ExpectedGuestNetworkPathJson,
            [string]$SupportAddress,
            [int]$SupportTcp,
            [int]$SupportUdp,
            [string]$ExpectedGuestAddress,
            [string]$ExpectedGuestInterfaceAlias,
            [string]$ExpectedSupportNetwork,
            [int]$ExpectedSupportPrefixLength,
            [string]$ExpectedSupportMacAddress,
            [string]$ExpectedSupportInterfaceGuid,
            [int]$ExpectedSupportMtuBytes,
            [int]$SupportProcessId,
            [string]$SupportProcessOwner,
            [int]$MinimumSupportIpv4PacketBytes,
            [string]$CanonicalSourceIpv4,
            [int]$CanonicalSourcePortFirst,
            [int]$CanonicalSourcePortLast,
            [int]$DiagnosticTrialSequenceValue,
            [string]$DiagnosticProfileValue,
            [string]$DiagnosticRunNonce,
            [int]$DiagnosticMaxEvents,
            [string]$UdpBoundaryCollectorSha256,
            [string]$DiagnosticSourceIpv4,
            [int]$DiagnosticSourcePortFirst,
            [int]$DiagnosticSourcePortLast
        )
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"
        $ProgressPreference = "SilentlyContinue"
        $Utf8NoBom = New-Object Text.UTF8Encoding($false)
        $InputRoot = Join-Path $Root "input"
        $EvidenceRoot = Join-Path $Root "raw-evidence"
        $DiagnosticEvidenceRoot = Join-Path $Root "udp-diagnostic"
        $NetworkModelEvidenceRoot = Join-Path $EvidenceRoot "network-model"
        $InstrumentedDiagnostic = -not [string]::IsNullOrWhiteSpace(
            $DiagnosticProfileValue
        )
        $ProcessLogRoot = if ($InstrumentedDiagnostic) {
            Join-Path $DiagnosticEvidenceRoot "process-logs"
        } else {
            Join-Path $EvidenceRoot "process-logs"
        }
        $AdapterName = "Ferrum2Perf"
        if ($GuestNetworkPathProbeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace($ExpectedGuestNetworkPathJson) -or
            $ExpectedGuestNetworkPathJson.Length -gt 8192 -or
            $ExpectedGuestNetworkPathJson -cmatch '[\r\n]') {
            throw "expected guest network-path identity is invalid"
        }
        $ExpectedGuestNetworkPath = $ExpectedGuestNetworkPathJson | ConvertFrom-Json
        if (-not $Root.StartsWith("C:\Windows\Temp\ferrum2-tun-performance-", [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $InputRoot -PathType Container) -or
            (Test-Path -LiteralPath $EvidenceRoot) -or
            ($InstrumentedDiagnostic -and
                (Test-Path -LiteralPath $DiagnosticEvidenceRoot))) {
            throw "guest performance boundary is invalid"
        }
        if ($CanonicalSourceIpv4 -cne "198.18.0.2" -or
            $CanonicalSourcePortFirst -ne 20000 -or
            $CanonicalSourcePortLast -ne 28191 -or
            ($CanonicalSourcePortLast - $CanonicalSourcePortFirst + 1) -ne 8192) {
            throw "guest canonical UDP association source identity is invalid"
        }
        if ($InstrumentedDiagnostic) {
            if ($DiagnosticProfileValue -cne "UdpFlowBoundary" -or
                $DiagnosticTrialSequenceValue -ne 31 -or
                $RunKindValue -cne "calibration-aa" -or
                $ParentCommit -cne $CandidateCommit -or
                $DiagnosticRunNonce -cnotmatch '^[1-9][0-9]{0,19}$' -or
                $DiagnosticMaxEvents -lt 1 -or $DiagnosticMaxEvents -gt 65536 -or
                $UdpBoundaryCollectorSha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $DiagnosticSourceIpv4 -cne "198.18.0.2" -or
                $DiagnosticSourcePortFirst -ne 20000 -or
                $DiagnosticSourcePortLast -ne 28191 -or
                ($DiagnosticSourcePortLast - $DiagnosticSourcePortFirst + 1) -ne
                    8192) {
                throw "guest UdpFlowBoundary diagnostic identity is invalid"
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($DiagnosticRunNonce) -or
            $DiagnosticMaxEvents -ne 0 -or
            -not [string]::IsNullOrWhiteSpace($DiagnosticSourceIpv4) -or
            $DiagnosticSourcePortFirst -ne 0 -or
            $DiagnosticSourcePortLast -ne 0) {
            throw "guest support diagnostic arguments require UdpFlowBoundary"
        }
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $version = Get-ItemProperty `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -ErrorAction Stop
        if ($computer.Manufacturer -cne "Microsoft Corporation" -or
            $computer.Model -cne "Virtual Machine" -or
            [string]$env:PROCESSOR_ARCHITECTURE -cne "AMD64" -or
            [string]$os.BuildNumber -cne [string]$version.CurrentBuildNumber) {
            throw "guest identity changed after staging"
        }
        $allInput = @(Get-Item -LiteralPath $InputRoot -Force) + @(
            Get-ChildItem -LiteralPath $InputRoot -Force -Recurse
        )
        if (@($allInput | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count -ne 0) {
            throw "guest staging cannot contain a reparse point"
        }
        if ($InstrumentedDiagnostic) {
            New-Item -ItemType Directory -Path $DiagnosticEvidenceRoot | Out-Null
        } else {
            New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
            New-Item -ItemType Directory -Path $NetworkModelEvidenceRoot | Out-Null
        }
        New-Item -ItemType Directory -Path $ProcessLogRoot | Out-Null

        $RustRoot = Join-Path $InputRoot "runtime\rust"
        $PowerShell = Join-Path $InputRoot "runtime\pwsh\pwsh.exe"
        $env:PATH = "$RustRoot;$env:PATH"
        $rustVersion = @(& (Join-Path $RustRoot "rustc.exe") --version 2>&1)
        if ($LASTEXITCODE -ne 0 -or ($rustVersion -join "`n") -cnotmatch '^rustc 1\.97\.1 \(') {
            throw "staged Rust 1.97.1 runtime verification failed"
        }
        $pwshItems = @(Get-Item -LiteralPath (Split-Path -Parent $PowerShell) -Force) + @(
            Get-ChildItem -LiteralPath (Split-Path -Parent $PowerShell) -Force -Recurse
        )
        $pwshFiles = @($pwshItems | Where-Object { -not $_.PSIsContainer })
        $pwshBytes = [long]($pwshFiles | Measure-Object Length -Sum).Sum
        if (@($pwshItems | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count -ne 0 -or
            $pwshFiles.Count -ne $PowerShellFileCount -or
            $pwshBytes -ne $PowerShellExpandedBytes) {
            throw "staged PowerShell runtime boundary changed"
        }
        $pwshVersion = @(& $PowerShell -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
        if ($LASTEXITCODE -ne 0 -or $pwshVersion.Count -ne 1 -or
            [string]$pwshVersion[0] -cne $PowerShellVersion -or
            (Get-FileHash -LiteralPath $PowerShell -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $PowerShellExecutableSha256) {
            throw "staged PowerShell runtime identity verification failed"
        }
        $networkModelController = Join-Path $InputRoot "windows_tun_network_model.py"
        $networkModelPlan = Join-Path $InputRoot "network-model-plan.json"
        if (
            (Get-FileHash -LiteralPath $networkModelController -Algorithm SHA256).Hash.ToLowerInvariant() `
                -cne $NetworkModelControllerSha256 -or
            (Get-FileHash -LiteralPath $networkModelPlan -Algorithm SHA256).Hash.ToLowerInvariant() `
                -cne $NetworkModelPlanSha256
        ) {
            throw "staged network-model controller or plan identity changed"
        }

        $wintunZip = Join-Path $InputRoot "wintun-0.14.1.zip"
        if ((Get-FileHash -LiteralPath $wintunZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $WintunZipSha256) {
            throw "guest Wintun ZIP hash mismatch"
        }
        $wintunRoot = Join-Path $Root "wintun"
        Expand-Archive -LiteralPath $wintunZip -DestinationPath $wintunRoot -ErrorAction Stop
        $wintunDll = Join-Path $wintunRoot "wintun\bin\amd64\wintun.dll"
        if ((Get-FileHash -LiteralPath $wintunDll -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $WintunDllSha256 -or
            (Get-AuthenticodeSignature -LiteralPath $wintunDll).Status -ne "Valid") {
            throw "guest Wintun DLL trust boundary failed"
        }
        foreach ($member in @("parent", "candidate")) {
            $memberRoot = Join-Path $InputRoot "artifacts\$member"
            Copy-Item -LiteralPath $wintunDll -Destination (Join-Path $memberRoot "wintun.dll") `
                -ErrorAction Stop
            foreach ($runtimeDll in @(Get-ChildItem -LiteralPath (Join-Path $InputRoot "runtime\vc-runtime") -File)) {
                Copy-Item -LiteralPath $runtimeDll.FullName -Destination $memberRoot -ErrorAction Stop
            }
        }
        foreach ($runtimeDll in @(Get-ChildItem -LiteralPath (Join-Path $InputRoot "runtime\vc-runtime") -File)) {
            $harnessRuntimeDll = Join-Path (Join-Path $InputRoot "artifacts") $runtimeDll.Name
            if (-not (Test-Path -LiteralPath $harnessRuntimeDll -PathType Leaf) -or
                (Get-FileHash -LiteralPath $harnessRuntimeDll -Algorithm SHA256).Hash -cne
                    (Get-FileHash -LiteralPath $runtimeDll.FullName -Algorithm SHA256).Hash) {
                throw "guest preflight Visual C++ runtime identity changed"
            }
        }

        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Ferrum2PerfProcessGroup {
    private const uint CreateNewConsole = 0x00000010;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const int StartfUseShowWindow = 0x00000001;
    private const int StartfUseStdHandles = 0x00000100;
    private const uint FileAppendData = 0x00000004;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private static readonly IntPtr ProcThreadAttributeHandleList = new IntPtr(0x00020002);
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
    private static readonly Dictionary<uint, IntPtr> Handles = new Dictionary<uint, IntPtr>();
    private static readonly object Sync = new object();
    private static readonly ManualResetEvent ConsoleControlReceived = new ManualResetEvent(false);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ConsoleCtrlHandler(uint controlType);
    private static readonly ConsoleCtrlHandler IgnoreConsoleControl = IgnoreControl;

    private static bool IgnoreControl(uint controlType) {
        if (controlType == 1) ConsoleControlReceived.Set();
        return true;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars;
        public int yChars; public int fill; public int flags; public short show;
        public short reserved2; public IntPtr reservedBytes; public IntPtr stdin;
        public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx {
        public StartupInfo startup;
        public IntPtr attributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes {
        public int length;
        public IntPtr securityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr process; public IntPtr thread; public uint processId; public uint threadId;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessExtended(string application, StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
        IntPtr environment, string directory, ref StartupInfoEx startup,
        out ProcessInformation process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SecurityAttributes securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList,
        int attributeCount, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags,
        IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);

    private static IntPtr OpenInheritable(string path, uint access, uint disposition) {
        var security = new SecurityAttributes {
            length = Marshal.SizeOf(typeof(SecurityAttributes)),
            securityDescriptor = IntPtr.Zero,
            inheritHandle = true
        };
        var handle = CreateFileW(path, access,
            FileShareRead | FileShareWrite | FileShareDelete,
            ref security, disposition, FileAttributeNormal, IntPtr.Zero);
        if (handle == InvalidHandleValue)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW redirected stream");
        return handle;
    }

    public static int Start(string application, string arguments, string directory,
        string stdoutPath, string stderrPath) {
        if (String.IsNullOrWhiteSpace(stdoutPath) || String.IsNullOrWhiteSpace(stderrPath))
            throw new ArgumentException("stdout and stderr redirection paths are required");
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        ProcessInformation process;
        IntPtr stdoutHandle = IntPtr.Zero;
        IntPtr stderrHandle = IntPtr.Zero;
        IntPtr stdinHandle = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        var attributeListInitialized = false;
        try {
            stdoutHandle = OpenInheritable(stdoutPath, FileAppendData, CreateNew);
            stderrHandle = OpenInheritable(stderrPath, FileAppendData, CreateNew);
            stdinHandle = OpenInheritable("NUL", GenericRead, OpenExisting);
            var startup = new StartupInfoEx();
            startup.startup.cb = Marshal.SizeOf(typeof(StartupInfoEx));
            startup.startup.flags = StartfUseShowWindow | StartfUseStdHandles;
            startup.startup.show = 0;
            startup.startup.stdin = stdinHandle;
            startup.startup.stdout = stdoutHandle;
            startup.startup.stderr = stderrHandle;
            IntPtr attributeBytes = IntPtr.Zero;
            var sizeProbe = InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeBytes);
            var sizeProbeError = Marshal.GetLastWin32Error();
            if (sizeProbe || attributeBytes == IntPtr.Zero || sizeProbeError != 122)
                throw new Win32Exception(sizeProbeError,
                    "InitializeProcThreadAttributeList size");
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList");
            attributeListInitialized = true;
            startup.attributeList = attributeList;
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0 * IntPtr.Size, stdinHandle);
            Marshal.WriteIntPtr(handleList, 1 * IntPtr.Size, stdoutHandle);
            Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stderrHandle);
            if (!UpdateProcThreadAttribute(attributeList, 0,
                ProcThreadAttributeHandleList, handleList, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "UpdateProcThreadAttribute handle list");
            if (!CreateProcessExtended(application, command, IntPtr.Zero, IntPtr.Zero, true,
                CreateNewConsole | ExtendedStartupInfoPresent, IntPtr.Zero, directory,
                ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateProcessW redirected");
        } finally {
            if (attributeList != IntPtr.Zero) {
                if (attributeListInitialized) DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (stdinHandle != IntPtr.Zero && stdinHandle != InvalidHandleValue)
                CloseHandle(stdinHandle);
            if (stdoutHandle != IntPtr.Zero && stdoutHandle != InvalidHandleValue)
                CloseHandle(stdoutHandle);
            if (stderrHandle != IntPtr.Zero && stderrHandle != InvalidHandleValue)
                CloseHandle(stderrHandle);
        }
        CloseHandle(process.thread);
        lock (Sync) Handles.Add(process.processId, process.process);
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        return WaitForSingleObject(handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) throw new InvalidOperationException();
        uint code; if (!GetExitCodeProcess(handle, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)code);
    }
    public static bool Break(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        FreeConsole();
        if (!AttachConsole(processId)) return false;
        try {
            if (!SetConsoleCtrlHandler(IgnoreConsoleControl, true)) return false;
            try {
                ConsoleControlReceived.Reset();
                var sent = GenerateConsoleCtrlEvent(1, 0);
                var senderObserved = sent && ConsoleControlReceived.WaitOne(5000);
                Thread.Sleep(250);
                return sent && senderObserved;
            } finally {
                SetConsoleCtrlHandler(IgnoreConsoleControl, false);
            }
        } finally {
            FreeConsole();
        }
    }
    public static bool Terminate(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        return TerminateProcess(handle, 1);
    }
    public static void Close(uint processId) {
        IntPtr handle;
        lock (Sync) { if (!Handles.TryGetValue(processId, out handle)) return; Handles.Remove(processId); }
        CloseHandle(handle);
    }
}
'@

        function Invoke-NativeCapture([string]$Executable, [string[]]$Arguments) {
            $previousErrorActionPreference = $ErrorActionPreference
            $output = @()
            $exitCode = $null
            try {
                $ErrorActionPreference = "Continue"
                $output = @(& $Executable @Arguments 2>&1)
                $exitCode = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            return [pscustomobject]@{
                ExitCode = if ($null -eq $exitCode) { -1 } else { [int]$exitCode }
                Output = @($output)
            }
        }

        function Test-JsonInteger([object]$Value) {
            return $Value -is [int] -or $Value -is [long]
        }

        function Get-FreeTcpPort([string]$LocalAddress = "127.0.0.1") {
            $address = [Net.IPAddress]::Parse($LocalAddress)
            $listener = New-Object Net.Sockets.TcpListener($address, 0)
            try {
                $listener.Start()
                return [int]$listener.LocalEndpoint.Port
            } finally {
                $listener.Stop()
            }
        }
        function Get-FreeDualPort([string]$LocalAddress) {
            $address = [Net.IPAddress]::Parse($LocalAddress)
            foreach ($attempt in 1..100) {
                $port = Get-FreeTcpPort -LocalAddress $LocalAddress
                $udp = New-Object Net.Sockets.UdpClient
                try {
                    $udp.Client.Bind((New-Object Net.IPEndPoint($address, $port)))
                    return $port
                } catch {
                    if ($attempt -eq 100) { throw }
                } finally {
                    $udp.Dispose()
                }
            }
            throw "unable to reserve a dual TCP/UDP port"
        }
        function Get-GuestNetworkPath {
            $probe = Join-Path $InputRoot "get_windows_tun_guest_network_path.ps1"
            if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne $GuestNetworkPathProbeSha256) {
                throw "guest network-path probe identity changed"
            }
            $probeResult = Invoke-NativeCapture $PowerShell @(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", $probe, "-SupportIpv4", $SupportAddress,
                "-SupportPort", [string]$SupportUdp,
                "-ExpectedGuestIpv4", $ExpectedGuestAddress,
                "-ExpectedInterfaceAlias", $ExpectedGuestInterfaceAlias,
                "-ExpectedNetwork", $ExpectedSupportNetwork,
                "-ExpectedPrefixLength", [string]$ExpectedSupportPrefixLength,
                "-ExpectedMacAddress", $ExpectedSupportMacAddress,
                "-ExpectedInterfaceGuid", $ExpectedSupportInterfaceGuid,
                "-ExpectedMtuBytes", [string]$ExpectedSupportMtuBytes,
                "-ManagedAdapterName", $AdapterName,
                "-MinimumUnderlayIpv4PacketBytes",
                [string]$MinimumSupportIpv4PacketBytes, "-AsJson"
            )
            if ($probeResult.ExitCode -ne 0 -or @($probeResult.Output).Count -ne 1) {
                throw "guest network-path probe result is not unique"
            }
            $actual = [string]$probeResult.Output[0] | ConvertFrom-Json
            $fields = @(
                "schema", "support_ipv4", "guest_ipv4", "guest_prefix_length",
                "guest_interface_index", "guest_interface_alias", "guest_interface_guid",
                "guest_interface_mtu_bytes",
                "guest_mac_address",
                "guest_route_prefix", "guest_route_next_hop", "guest_dns_servers"
            )
            if ((@($actual.PSObject.Properties.Name) -join "|") -cne ($fields -join "|") -or
                (@($ExpectedGuestNetworkPath.PSObject.Properties.Name) -join "|") -cne
                    ($fields -join "|") -or
                [int]$actual.schema -ne 2 -or [int]$ExpectedGuestNetworkPath.schema -ne 2) {
                throw "guest network-path evidence shape is invalid"
            }
            foreach ($field in @(
                "support_ipv4", "guest_ipv4", "guest_prefix_length", "guest_interface_index",
                "guest_interface_alias", "guest_interface_guid", "guest_interface_mtu_bytes",
                "guest_mac_address",
                "guest_route_prefix",
                "guest_route_next_hop"
            )) {
                if ([string]$actual.$field -cne [string]$ExpectedGuestNetworkPath.$field) {
                    throw "guest network path changed: field=$field"
                }
            }
            if ((@($actual.guest_dns_servers) -join "|") -cne
                (@($ExpectedGuestNetworkPath.guest_dns_servers) -join "|")) {
                throw "guest network path changed: field=guest_dns_servers"
            }
            return $actual
        }
        function Wait-ProcessListener(
            [int]$ProcessId,
            [string]$LocalAddress,
            [int]$Port,
            [bool]$RequireUdp
        ) {
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            $tcp = @()
            $udp = @()
            do {
                if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
                    throw "server exited before listener readiness"
                }
                $tcp = @(Get-NetTCPConnection -State Listen -LocalPort $Port `
                    -ErrorAction SilentlyContinue | Where-Object {
                        [int]$_.OwningProcess -eq $ProcessId
                    })
                if ($RequireUdp) {
                    $udp = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue |
                        Where-Object {
                            [int]$_.OwningProcess -eq $ProcessId
                        })
                }
                $tcpExact = $tcp.Count -eq 1 -and
                    [string]$tcp[0].LocalAddress -ceq $LocalAddress
                $udpExact = -not $RequireUdp -or (
                    $udp.Count -eq 1 -and
                    [string]$udp[0].LocalAddress -ceq $LocalAddress
                )
                if ($tcpExact -and $udpExact) { return }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            throw "server listener readiness timed out: address=$LocalAddress port=$Port tcp=$($tcp.Count) udp=$($udp.Count) require_udp=$RequireUdp"
        }
        function Get-PrometheusIntegerMetric(
            [string]$Metrics,
            [string]$Name
        ) {
            $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)? (?<value>[0-9]+)$"
            $selected = @([regex]::Matches($Metrics, $pattern))
            if ($selected.Count -ne 1) {
                throw "missing or ambiguous integer server metric: $Name"
            }
            return [uint64]::Parse(
                $selected[0].Groups["value"].Value,
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        function Get-PrometheusLabeledIntegerMetric(
            [string]$Metrics,
            [string]$Name,
            [hashtable]$Labels,
            [bool]$AllowAbsent = $false
        ) {
            $pattern = "(?m)^$([regex]::Escape($Name))(?:_total)?\{(?<labels>[^}`r`n]*)\} (?<value>[0-9]+)$"
            $selected = @([regex]::Matches($Metrics, $pattern) | Where-Object {
                $encoded = $_.Groups["labels"].Value
                @($encoded.Split(',')).Count -eq $Labels.Count -and
                    @($Labels.GetEnumerator() | Where-Object {
                        $encoded -cnotmatch "(?:^|,)$([regex]::Escape([string]$_.Key))=`"$([regex]::Escape([string]$_.Value))`"(?:,|$)"
                    }).Count -eq 0
            })
            if ($selected.Count -eq 0 -and $AllowAbsent) { return [uint64]0 }
            if ($selected.Count -ne 1) {
                throw "missing or ambiguous labeled integer server metric: $Name"
            }
            return [uint64]::Parse(
                $selected[0].Groups["value"].Value,
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        function Get-ServerNetworkState([int]$ProcessId, [int]$MetricsPort) {
            if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
                throw "server exited while waiting for network stability"
            }
            $metrics = (Invoke-WebRequest -UseBasicParsing `
                -Uri "http://127.0.0.1:$MetricsPort/metrics" -TimeoutSec 2).Content
            if ($metrics -cnotmatch '(?m)^# TYPE ferrum2_network_generation gauge$') {
                throw "server network generation metric metadata is missing"
            }
            $resetFamilyPresent = $metrics -cmatch `
                '(?m)^(?:# (?:HELP|TYPE) )?ferrum2_network_reset(?:_total)?(?:[ {])'
            if ($resetFamilyPresent -and
                $metrics -cnotmatch '(?m)^# TYPE ferrum2_network_reset counter$') {
                throw "server network reset metric metadata is invalid"
            }
            $reset = @{}
            foreach ($reason in @("network_change", "retry")) {
                foreach ($result in @("started", "succeeded", "failed")) {
                    $reset["$reason.$result"] = Get-PrometheusLabeledIntegerMetric `
                        -Metrics $metrics -Name "ferrum2_network_reset" -Labels @{
                            reason = $reason
                            result = $result
                        } -AllowAbsent $true
                }
            }
            return [pscustomobject]@{
                Generation = Get-PrometheusIntegerMetric `
                    -Metrics $metrics -Name "ferrum2_network_generation"
                NetworkChangeStarted = $reset["network_change.started"]
                NetworkChangeSucceeded = $reset["network_change.succeeded"]
                NetworkChangeFailed = $reset["network_change.failed"]
                RetryStarted = $reset["retry.started"]
                RetrySucceeded = $reset["retry.succeeded"]
                RetryFailed = $reset["retry.failed"]
            }
        }
        function Wait-ServerNetworkStable(
            [int]$ProcessId,
            [int]$MetricsPort,
            [object]$Baseline,
            [bool]$RequireAdvance
        ) {
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            $stableSince = $null
            $lastSignature = $null
            $observedSignature = $null
            $state = $null
            do {
                $state = Get-ServerNetworkState `
                    -ProcessId $ProcessId -MetricsPort $MetricsPort
                $values = @(
                    $state.Generation,
                    $state.NetworkChangeStarted,
                    $state.NetworkChangeSucceeded,
                    $state.NetworkChangeFailed,
                    $state.RetryStarted,
                    $state.RetrySucceeded,
                    $state.RetryFailed
                )
                $observedSignature = $values -join "|"
                $totalStarted = $state.NetworkChangeStarted + $state.RetryStarted
                $totalFinished = $state.NetworkChangeSucceeded +
                    $state.NetworkChangeFailed + $state.RetrySucceeded + $state.RetryFailed
                $eligible = $totalStarted -eq $totalFinished
                if ($eligible -and $RequireAdvance) {
                    $monotonic = $state.Generation -ge $Baseline.Generation -and
                        $state.NetworkChangeStarted -ge $Baseline.NetworkChangeStarted -and
                        $state.NetworkChangeSucceeded -ge $Baseline.NetworkChangeSucceeded -and
                        $state.NetworkChangeFailed -ge $Baseline.NetworkChangeFailed -and
                        $state.RetryStarted -ge $Baseline.RetryStarted -and
                        $state.RetrySucceeded -ge $Baseline.RetrySucceeded -and
                        $state.RetryFailed -ge $Baseline.RetryFailed
                    if ($monotonic) {
                        $generationDelta = $state.Generation - $Baseline.Generation
                        $networkChangeStartedDelta = $state.NetworkChangeStarted -
                            $Baseline.NetworkChangeStarted
                        $startedDelta = $networkChangeStartedDelta +
                            ($state.RetryStarted - $Baseline.RetryStarted)
                        $succeededDelta = ($state.NetworkChangeSucceeded -
                            $Baseline.NetworkChangeSucceeded) +
                            ($state.RetrySucceeded - $Baseline.RetrySucceeded)
                        $failedDelta = ($state.NetworkChangeFailed -
                            $Baseline.NetworkChangeFailed) +
                            ($state.RetryFailed - $Baseline.RetryFailed)
                        $eligible = $networkChangeStartedDelta -ge 1 -and
                            $generationDelta -gt 0 -and
                            $startedDelta -eq $succeededDelta + $failedDelta -and
                            $generationDelta -eq $succeededDelta
                    } else {
                        $eligible = $false
                    }
                }
                if ($eligible) {
                    if ($observedSignature -cne $lastSignature) {
                        $lastSignature = $observedSignature
                        $stableSince = [DateTime]::UtcNow
                    } elseif (([DateTime]::UtcNow - $stableSince).TotalMilliseconds -ge 1500) {
                        return $state
                    }
                } else {
                    $stableSince = $null
                    $lastSignature = $null
                }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            $baselineSignature = if ($null -eq $Baseline) { "none" } else {
                @(
                    $Baseline.Generation,
                    $Baseline.NetworkChangeStarted,
                    $Baseline.NetworkChangeSucceeded,
                    $Baseline.NetworkChangeFailed,
                    $Baseline.RetryStarted,
                    $Baseline.RetrySucceeded,
                    $Baseline.RetryFailed
                ) -join "|"
            }
            throw "server network stability timed out: baseline=$baselineSignature last=$observedSignature require_advance=$RequireAdvance"
        }
        function Wait-TunReady([int]$ProcessId, [int]$Port) {
            $deadline = [DateTime]::UtcNow.AddSeconds(60)
            do {
                if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
                    throw "client exited before TUN readiness"
                }
                try {
                    $metrics = (Invoke-WebRequest -UseBasicParsing `
                        -Uri "http://127.0.0.1:$Port/metrics" -TimeoutSec 2).Content
                    if ($metrics -match '(?m)^ferrum2_tun_session_active(?:\{[^}]*\})? 1(?:\.0+)?$') {
                        return
                    }
                } catch { }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            throw "client TUN readiness timed out"
        }
        function Stop-OwnedProcess([int]$ProcessId, [string]$Label) {
            $confirmedExit = [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)
            try {
                $forced = $false
                if (-not $confirmedExit) {
                    $breakSent = [Ferrum2PerfProcessGroup]::Break([uint32]$ProcessId)
                    $confirmedExit = if ($breakSent) {
                        [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 60000)
                    } else {
                        [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)
                    }
                }
                if (-not $confirmedExit) {
                    $terminateRequested = [Ferrum2PerfProcessGroup]::Terminate(
                        [uint32]$ProcessId
                    )
                    $confirmedExit = [Ferrum2PerfProcessGroup]::Wait(
                        [uint32]$ProcessId,
                        10000
                    )
                    if (-not $confirmedExit) {
                        throw "$Label fallback termination was not confirmed"
                    }
                    $forced = $terminateRequested
                }
                if ($forced) {
                    throw "$Label did not stop gracefully"
                }
                $exit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$ProcessId)
                if ($exit -ne 0) { throw "$Label stopped with exit code $exit" }
            } finally {
                if ($confirmedExit) {
                    [Ferrum2PerfProcessGroup]::Close([uint32]$ProcessId)
                }
            }
        }
        function Wait-AdapterAbsent {
            $deadline = [DateTime]::UtcNow.AddSeconds(60)
            do {
                if (-not (Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction SilentlyContinue)) {
                    return
                }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            throw "managed performance adapter did not disappear"
        }
        function Write-CanonicalLedger(
            [string]$Path,
            [string]$MemberCommit,
            [string]$ClientHash,
            [string]$ServerHash,
            [string]$CollectorHash
        ) {
            $ledger = [ordered]@{
                schema = 1
                vm_name = $VmName
                vm_id = $VmId
                checkpoint_name = $CheckpointName
                checkpoint_id = $CheckpointId
                topology_manifest_sha256 = $TopologyManifestSha256Value
                topology_plan_sha256 = $TopologyPlanSha256Value
                support_switch_name = $SupportSwitchName
                support_switch_id = $SupportSwitchId
                guest_product = [string]$version.ProductName
                guest_edition = [string]$version.EditionID
                guest_architecture = "AMD64"
                guest_version = [Environment]::OSVersion.Version.ToString()
                guest_build = "$($version.CurrentBuildNumber).$($version.UBR)"
                candidate_sha = $MemberCommit
                probe_sha256 = $CollectorHash
                client_sha256 = $ClientHash
                server_sha256 = $ServerHash
                support_listener = [ordered]@{
                    ipv4 = $SupportAddress
                    tcp_port = $SupportTcp
                    udp_port = $SupportUdp
                    pid = $SupportProcessId
                    owner = $SupportProcessOwner
                }
            }
            [IO.File]::WriteAllText(
                $Path,
                (($ledger | ConvertTo-Json -Compress -Depth 4) + "`n"),
                $Utf8NoBom
            )
        }

        $collector = Join-Path $InputRoot "collect_windows_tun_performance_trial.ps1"
        $udpBoundaryCollector = Join-Path $InputRoot `
            "collect_windows_tun_udp_boundary_diagnostic.ps1"
        $harness = Join-Path $InputRoot "artifacts\m4-qualification.exe"
        $collectorHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($InstrumentedDiagnostic -and (
            -not (Test-Path -LiteralPath $udpBoundaryCollector -PathType Leaf) -or
            (Get-FileHash -LiteralPath $udpBoundaryCollector -Algorithm SHA256).
                Hash.ToLowerInvariant() -cne $UdpBoundaryCollectorSha256
        )) {
            throw "guest UDP boundary collector identity changed during staging"
        }
        $plan = Get-Content -LiteralPath (Join-Path $InputRoot "plan.json") -Raw -Encoding utf8 |
            ConvertFrom-Json
        if ($plan.schema_version -ne 2 -or
            @($plan.trials).Count -ne 90 -or
            $plan.recipe_sha256 -cne $RecipeSha256 -or
            $null -eq $plan.scenarios."udp-8192-association-lookup-expiry" -or
            $plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256 `
                -cne $NetworkModelControllerSha256 -or
            $plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256 `
                -cne $NetworkModelPlanSha256) {
            throw "guest trial plan changed during staging"
        }
        $udpBoundaryRecipe = $plan.scenarios.
            "udp-8192-association-lookup-expiry".recipe
        if ([string]$udpBoundaryRecipe.canonical_source_port_strategy -cne
                "explicit_tun_ipv4_contiguous" -or
            [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
                $CanonicalSourceIpv4 -or
            [int]$udpBoundaryRecipe.canonical_source_port_first -ne
                $CanonicalSourcePortFirst -or
            [int]$udpBoundaryRecipe.canonical_source_port_last -ne
                $CanonicalSourcePortLast -or
            [int]$udpBoundaryRecipe.associations -ne 8192 -or
            ($CanonicalSourcePortLast - $CanonicalSourcePortFirst + 1) -ne
                [int]$udpBoundaryRecipe.associations) {
            throw "guest canonical UDP source-port plan changed during staging"
        }
        if ($InstrumentedDiagnostic -and (
            [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
                $DiagnosticSourceIpv4 -or
            [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
                $DiagnosticSourcePortFirst -or
            [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
                $DiagnosticSourcePortLast -or
            [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
                [string]$udpBoundaryRecipe.canonical_source_ipv4 -or
            [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
                [int]$udpBoundaryRecipe.canonical_source_port_first -or
            [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
                [int]$udpBoundaryRecipe.canonical_source_port_last -or
            [string]$udpBoundaryRecipe.diagnostic_collector_source_sha256 -cne
                $UdpBoundaryCollectorSha256)) {
            throw "guest UDP diagnostic source-port plan changed during staging"
        }
        if ($DiagnosticTrialSequenceValue -lt 0 -or
            $DiagnosticTrialSequenceValue -gt 90 -or
            ($DiagnosticTrialSequenceValue -gt 0 -and $RunKindValue -cne "calibration-aa")) {
            throw "guest diagnostic trial selection is invalid"
        }
        $executionTrials = @(if ($DiagnosticTrialSequenceValue -gt 0) {
            $plan.trials | Where-Object {
                [int]$_.sequence -eq $DiagnosticTrialSequenceValue
            } | Sort-Object sequence
        } else {
            $plan.trials | Sort-Object sequence
        })
        if (($DiagnosticTrialSequenceValue -gt 0 -and $executionTrials.Count -ne 1) -or
            ($DiagnosticTrialSequenceValue -eq 0 -and $executionTrials.Count -ne 90)) {
            throw "guest canonical trial execution selection is invalid"
        }
        if ($InstrumentedDiagnostic -and (
            [string]$executionTrials[0].scenario -cne
                "udp-8192-association-lookup-expiry" -or
            [string]$executionTrials[0].member -cne "parent"
        )) {
            throw "guest UdpFlowBoundary trial identity mismatch"
        }
        $expectedTrialCount = if ($InstrumentedDiagnostic) { 0 } else {
            $executionTrials.Count
        }
        $expectedNetworkModelObservationCount = if ($InstrumentedDiagnostic) { 0 } else {
            @($executionTrials | Where-Object {
                [string]$_.scenario -in @("udp-route-once", "network-lifecycle")
            }).Count
        }
        $expectedProcessLogCount = if ($InstrumentedDiagnostic) { 4 } else {
            4 * $expectedTrialCount
        }
        $instrumentedTrialStatus = $null
        $instrumentedEvidenceStatus = $null
        $guestNetworkPath = Get-GuestNetworkPath
        $guestUnderlayAddress = [string]$guestNetworkPath.guest_ipv4
        $supportProbeResult = Invoke-NativeCapture $harness @(
            "windows-tun-probe", "--target-ip", $SupportAddress,
            "--tcp-port", [string]$SupportTcp, "--udp-port", [string]$SupportUdp
        )
        $supportProbe = @($supportProbeResult.Output)
        if ($supportProbeResult.ExitCode -ne 0 -or $supportProbe.Count -ne 1 -or
            [string]$supportProbe[0] -cne "windows_tun_probe status=PASS protocols=tcp,udp") {
            throw "guest support listener preflight failed"
        }

        foreach ($trial in $executionTrials) {
            if (Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
                throw "managed performance adapter baseline is not absent"
            }
            [void](Get-GuestNetworkPath)
            $member = [string]$trial.member
            $memberRoot = Join-Path $InputRoot "artifacts\$member"
            $client = Join-Path $memberRoot "ferrum2-client.exe"
            $server = Join-Path $memberRoot "ferrum2-server.exe"
            $memberCommit = if ($member -ceq "parent") { $ParentCommit } else { $CandidateCommit }
            $memberTree = if ($member -ceq "parent") { $ParentTree } else { $CandidateTree }
            $trialRoot = Join-Path $Root ("trial-{0:D3}" -f [int]$trial.sequence)
            New-Item -ItemType Directory -Path $trialRoot | Out-Null
            $metricsPort = Get-FreeTcpPort
            $serverPort = 0
            foreach ($attempt in 1..100) {
                $candidatePort = Get-FreeDualPort -LocalAddress $guestUnderlayAddress
                if ($candidatePort -ne $metricsPort) {
                    $serverPort = $candidatePort
                    break
                }
            }
            if ($serverPort -eq 0) { throw "unable to reserve a distinct server port" }
            $serverMetricsPort = 0
            foreach ($attempt in 1..100) {
                $candidatePort = Get-FreeTcpPort
                if ($candidatePort -ne $metricsPort -and $candidatePort -ne $serverPort) {
                    $serverMetricsPort = $candidatePort
                    break
                }
            }
            if ($serverMetricsPort -eq 0) {
                throw "unable to reserve a distinct server metrics port"
            }
            $clientConfig = Join-Path $trialRoot "client.toml"
            $serverConfig = Join-Path $trialRoot "server.toml"
            $ledger = Join-Path $trialRoot "identity-ledger.json"
            $logPrefix = "{0:D3}-{1}-{2}" -f @(
                [int]$trial.sequence,
                [string]$trial.scenario,
                $member
            )
            $clientStdout = Join-Path $ProcessLogRoot "$logPrefix-client.stdout.log"
            $clientStderr = Join-Path $ProcessLogRoot "$logPrefix-client.stderr.log"
            $serverStdout = Join-Path $ProcessLogRoot "$logPrefix-server.stdout.log"
            $serverStderr = Join-Path $ProcessLogRoot "$logPrefix-server.stderr.log"
            foreach ($logPath in @($clientStdout, $clientStderr, $serverStdout, $serverStderr)) {
                if (Test-Path -LiteralPath $logPath) {
                    throw "performance process log baseline is not absent"
                }
            }
            $clientText = Get-Content -LiteralPath (Join-Path $InputRoot "client.toml.template") -Raw
            $clientText = $clientText.Replace("{{ADAPTER_NAME}}", $AdapterName).
                Replace("{{SUPPORT_IPV4}}", $SupportAddress).
                Replace("{{SUPPORT_UDP_PORT}}", [string]$SupportUdp).
                Replace("{{SUPPORT_INTERFACE_ALIAS}}", $ExpectedGuestInterfaceAlias).
                Replace("{{GUEST_SUPPORT_IPV4}}", $ExpectedGuestAddress).
                Replace("{{SERVER_ADDRESS}}", $guestUnderlayAddress).
                Replace("{{SERVER_PORT}}", [string]$serverPort).
                Replace("{{METRICS_PORT}}", [string]$metricsPort)
            $serverText = (Get-Content -LiteralPath (Join-Path $InputRoot "server.toml.template") -Raw).
                Replace("{{SUPPORT_INTERFACE_ALIAS}}", $ExpectedGuestInterfaceAlias).
                Replace("{{GUEST_SUPPORT_IPV4}}", $ExpectedGuestAddress).
                Replace("{{SERVER_ADDRESS}}", $guestUnderlayAddress).
                Replace("{{SERVER_PORT}}", [string]$serverPort).
                Replace("{{SERVER_METRICS_PORT}}", [string]$serverMetricsPort)
            if ($clientText.Contains("{{") -or $serverText.Contains("{{")) {
                throw "configuration template substitution is incomplete"
            }
            [IO.File]::WriteAllText($clientConfig, $clientText, $Utf8NoBom)
            [IO.File]::WriteAllText($serverConfig, $serverText, $Utf8NoBom)
            $clientHash = (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash.ToLowerInvariant()
            $serverHash = (Get-FileHash -LiteralPath $server -Algorithm SHA256).Hash.ToLowerInvariant()
            Write-CanonicalLedger $ledger $memberCommit $clientHash $serverHash $collectorHash

            $clientCheckResult = Invoke-NativeCapture $client @(
                "--config", $clientConfig, "--check-config"
            )
            $clientCheck = @($clientCheckResult.Output)
            if ($clientCheckResult.ExitCode -ne 0 -or $clientCheck.Count -ne 1 -or
                [string]$clientCheck[0] -cne "configuration valid") {
                throw "client performance configuration is invalid"
            }
            $serverCheckResult = Invoke-NativeCapture $server @(
                "--config", $serverConfig, "--check-config"
            )
            $serverCheck = @($serverCheckResult.Output)
            if ($serverCheckResult.ExitCode -ne 0 -or $serverCheck.Count -ne 1 -or
                [string]$serverCheck[0] -cne "configuration valid") {
                throw "server performance configuration is invalid"
            }

            $serverPid = 0
            $clientPid = 0
            $trialFailure = $null
            try {
                $serverPid = [Ferrum2PerfProcessGroup]::Start(
                    $server, "--config `"$serverConfig`"", $memberRoot,
                    $serverStdout, $serverStderr
                )
                Wait-ProcessListener -ProcessId $serverPid `
                    -LocalAddress $guestUnderlayAddress -Port $serverPort -RequireUdp $true
                Wait-ProcessListener -ProcessId $serverPid `
                    -LocalAddress "127.0.0.1" -Port $serverMetricsPort -RequireUdp $false
                $serverNetworkBaseline = Wait-ServerNetworkStable `
                    -ProcessId $serverPid -MetricsPort $serverMetricsPort `
                    -Baseline $null -RequireAdvance $false
                $clientPid = [Ferrum2PerfProcessGroup]::Start(
                    $client, "--config `"$clientConfig`"", $memberRoot,
                    $clientStdout, $clientStderr
                )
                Wait-TunReady $clientPid $metricsPort
                [void](Wait-ServerNetworkStable `
                    -ProcessId $serverPid -MetricsPort $serverMetricsPort `
                    -Baseline $serverNetworkBaseline -RequireAdvance $true)
                Wait-ProcessListener -ProcessId $serverPid `
                    -LocalAddress $guestUnderlayAddress -Port $serverPort -RequireUdp $true
                Wait-ProcessListener -ProcessId $serverPid `
                    -LocalAddress "127.0.0.1" -Port $serverMetricsPort -RequireUdp $false
                Wait-TunReady $clientPid $metricsPort
                if ($InstrumentedDiagnostic) {
                    $diagnosticRawOutput = Join-Path $DiagnosticEvidenceRoot `
                        "guest-raw.json"
                    $boundaryArguments = @(
                        "-NoProfile", "-File", $udpBoundaryCollector,
                        "-Profile", $DiagnosticProfileValue,
                        "-RunKind", $RunKindValue,
                        "-Member", $member,
                        "-TrialSequence", [string]$trial.sequence,
                        "-ParentSha", $ParentCommit,
                        "-CandidateSha", $CandidateCommit,
                        "-Tree", $memberTree,
                        "-RecipeSha256", $RecipeSha256,
                        "-HarnessBinary", $harness,
                        "-TargetIpv4", $SupportAddress,
                        "-TargetTcpPort", [string]$SupportTcp,
                        "-TargetUdpPort", [string]$SupportUdp,
                        "-TunAdapterName", $AdapterName,
                        "-ClientPid", [string]$clientPid,
                        "-ServerPid", [string]$serverPid,
                        "-ClientMetricsPort", [string]$metricsPort,
                        "-DiagnosticRunNonce", $DiagnosticRunNonce,
                        "-DiagnosticMaxEvents", [string]$DiagnosticMaxEvents,
                        "-OutputDirectory", $DiagnosticEvidenceRoot,
                        "-Output", $diagnosticRawOutput
                    )
                    $boundaryResult = Invoke-NativeCapture $PowerShell $boundaryArguments
                    $boundaryLines = @($boundaryResult.Output | ForEach-Object {
                        if ($_ -is [Management.Automation.ErrorRecord]) {
                            [string]$_.Exception.Message
                        } else {
                            [string]$_
                        }
                    })
                    if ($boundaryResult.ExitCode -ne 0 -or
                        $boundaryLines.Count -ne 1 -or
                        [string]$boundaryLines[0] -cnotmatch
                            '^windows_tun_udp_boundary evidence=(COMPLETE|PARTIAL) trial=(PASS|FAIL) output=' -or
                        -not (Test-Path -LiteralPath $diagnosticRawOutput -PathType Leaf) -or
                        (Get-Item -LiteralPath $diagnosticRawOutput).Length -gt 1048576) {
                        throw "Windows TUN UDP boundary helper did not retain a valid raw result"
                    }
                    $diagnosticRaw = Get-Content -LiteralPath $diagnosticRawOutput `
                        -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
                    if ([string]$diagnosticRaw.schema -cne
                            "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v1" -or
                        $diagnosticRaw.qualification -ne $false -or
                        [string]$diagnosticRaw.profile -cne $DiagnosticProfileValue -or
                        [string]$diagnosticRaw.identity.run_kind -cne $RunKindValue -or
                        [string]$diagnosticRaw.identity.member -cne $member -or
                        [int]$diagnosticRaw.identity.trial_sequence -ne
                            [int]$trial.sequence -or
                        [string]$diagnosticRaw.identity.parent_sha -cne $ParentCommit -or
                        [string]$diagnosticRaw.identity.candidate_sha -cne
                            $CandidateCommit -or
                        [string]$diagnosticRaw.identity.collector_sha256 -cne
                            $UdpBoundaryCollectorSha256 -or
                        [string]$diagnosticRaw.identity.diagnostic_run_nonce -cne
                            $DiagnosticRunNonce -or
                        [int]$diagnosticRaw.identity.diagnostic_max_events -ne
                            $DiagnosticMaxEvents -or
                        [string]$diagnosticRaw.workload.source_ip -cne
                            $DiagnosticSourceIpv4 -or
                        [int]$diagnosticRaw.workload.source_port_first -ne
                            $DiagnosticSourcePortFirst -or
                        [int]$diagnosticRaw.workload.source_port_last -ne
                            $DiagnosticSourcePortLast -or
                        [string]$diagnosticRaw.evidence_status -cnotin
                            @("COMPLETE", "PARTIAL") -or
                        [string]$diagnosticRaw.trial_status -cnotin @("PASS", "FAIL")) {
                        throw "Windows TUN UDP boundary raw result identity mismatch"
                    }
                    $instrumentedTrialStatus = [string]$diagnosticRaw.trial_status
                    $instrumentedEvidenceStatus = [string]$diagnosticRaw.evidence_status
                } else {
                $outputName = "{0:D3}-{1}-{2}-pair-{3}.json" -f @(
                    [int]$trial.sequence, [string]$trial.scenario, $member, [int]$trial.pair
                )
                $output = Join-Path $EvidenceRoot $outputName
                $collectorArguments = @(
                    "-NoProfile", "-File", $collector,
                    "-Scenario", [string]$trial.scenario,
                    "-RunKind", $RunKindValue,
                    "-Member", $member,
                    "-Pair", [string]$trial.pair,
                    "-Order", [string]$trial.order,
                    "-Sequence", [string]$trial.sequence,
                    "-ParentSha", $ParentCommit,
                    "-CandidateSha", $CandidateCommit,
                    "-Tree", $memberTree,
                    "-RecipeSha256", $RecipeSha256,
                    "-ClientBinary", $client,
                    "-ServerBinary", $server,
                    "-HarnessBinary", $harness,
                    "-IdentityLedger", $ledger,
                    "-ExpectedCheckpointId", $CheckpointId,
                    "-ExpectedTopologyManifestSha256", $TopologyManifestSha256Value,
                    "-ExpectedTopologyPlanSha256", $TopologyPlanSha256Value,
                    "-ExpectedSupportSwitchId", $SupportSwitchId,
                    "-NetworkModelPlan", $networkModelPlan,
                    "-NetworkModelController", $networkModelController,
                    "-AdapterName", $AdapterName,
                    "-ClientPid", [string]$clientPid,
                    "-ServerPid", [string]$serverPid,
                    "-MetricsPort", [string]$metricsPort,
                    "-ServerMetricsPort", [string]$serverMetricsPort,
                    "-Output", $output
                )
                if ([string]$trial.scenario -ceq
                        "udp-8192-association-lookup-expiry") {
                    $collectorArguments += @(
                        "-UdpAssociationSourceIpv4", $CanonicalSourceIpv4,
                        "-UdpAssociationSourcePortFirst", [string]$CanonicalSourcePortFirst,
                        "-UdpAssociationSourcePortLast", [string]$CanonicalSourcePortLast
                    )
                }
                if ([string]$trial.scenario -in @("udp-route-once", "network-lifecycle")) {
                    $networkModelOutput = Join-Path $NetworkModelEvidenceRoot (
                        "{0:D3}-{1}-{2}-pair-{3}.network-model.json" -f `
                            [int]$trial.sequence, [string]$trial.scenario,
                            $member, [int]$trial.pair
                    )
                    $collectorArguments += @("-NetworkModelOutput", $networkModelOutput)
                }
                $collectorResult = Invoke-NativeCapture $PowerShell $collectorArguments
                $collectorOutput = @($collectorResult.Output)
                $collectorExit = $collectorResult.ExitCode
                $collectorLines = @($collectorOutput | ForEach-Object {
                    if ($_ -is [Management.Automation.ErrorRecord]) {
                        [string]$_.Exception.Message
                    } else {
                        [string]$_
                    }
                })
                $expectedCollectorOutput = "windows_tun_trial status=PASS " +
                    "scenario=$($trial.scenario) member=$member pair=$($trial.pair) " +
                    "order=$($trial.order) sequence=$($trial.sequence) output=$output"
                if ($collectorExit -ne 0 -or $collectorLines.Count -ne 1 -or
                    [string]$collectorLines[0] -cne $expectedCollectorOutput -or
                    -not (Test-Path -LiteralPath $output -PathType Leaf) -or
                    (Get-Item -LiteralPath $output).Length -gt 1048576) {
                    $snapshotFailures = New-Object Collections.Generic.List[string]
                    foreach ($snapshot in @(
                        [pscustomobject]@{ Name = "client"; Port = $metricsPort },
                        [pscustomobject]@{ Name = "server"; Port = $serverMetricsPort }
                    )) {
                        try {
                            $metricsText = [string](Invoke-WebRequest -UseBasicParsing `
                                -Uri "http://127.0.0.1:$($snapshot.Port)/metrics" `
                                -TimeoutSec 5 -ErrorAction Stop).Content
                            if ($Utf8NoBom.GetByteCount($metricsText) -gt 1048576) {
                                throw "$($snapshot.Name) failure metrics exceeded 1 MiB"
                            }
                            [IO.File]::WriteAllText(
                                (Join-Path $ProcessLogRoot `
                                    "$logPrefix-$($snapshot.Name).failure.metrics.txt"),
                                $metricsText,
                                $Utf8NoBom
                            )
                        } catch {
                            [void]$snapshotFailures.Add(
                                "$($snapshot.Name) metrics snapshot failed: $($_.Exception.Message)"
                            )
                        }
                    }
                    $failureText = (@($collectorLines) + @($snapshotFailures)) -join "`n"
                    if ($failureText.Length -gt 16384) {
                        $failureText = $failureText.Substring(0, 16384)
                    }
                    $failurePath = Join-Path $ProcessLogRoot `
                        "$logPrefix-collector.failure.txt"
                    [IO.File]::WriteAllText($failurePath, $failureText, $Utf8NoBom)
                    $failureDetail = if ($failureText.Length -gt 2048) {
                        $failureText.Substring(0, 2048)
                    } else {
                        $failureText
                    }
                    throw "Windows TUN collector trial failed: sequence=$($trial.sequence) detail=$failureDetail"
                }
                $trialEvidence = Get-Content -LiteralPath $output -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                if (-not (Test-JsonInteger -Value $trialEvidence.schema_version) -or
                    $trialEvidence.schema_version -ne 3 -or
                    $trialEvidence.kind -isnot [string] -or
                    $trialEvidence.kind -cne "windows_tun_performance_trial" -or
                    $trialEvidence.selection -isnot [string] -or
                    $trialEvidence.selection -cne [string]$plan.selection -or
                    $trialEvidence.run_kind -isnot [string] -or
                    $trialEvidence.run_kind -cne $RunKindValue -or
                    -not (Test-JsonInteger -Value $trialEvidence.sequence) -or
                    $trialEvidence.sequence -ne $trial.sequence -or
                    $trialEvidence.scenario -isnot [string] -or
                    $trialEvidence.scenario -cne [string]$trial.scenario -or
                    $trialEvidence.member -isnot [string] -or
                    $trialEvidence.member -cne $member -or
                    -not (Test-JsonInteger -Value $trialEvidence.pair) -or
                    $trialEvidence.pair -ne $trial.pair -or
                    -not (Test-JsonInteger -Value $trialEvidence.order) -or
                    $trialEvidence.order -ne $trial.order) {
                    throw "Windows TUN collector output identity does not match the planned trial"
                }
                }
            } catch {
                $trialFailure = $_
            } finally {
                $stopFailures = New-Object Collections.Generic.List[string]
                if ($clientPid -gt 0) {
                    try { Stop-OwnedProcess $clientPid "client" }
                    catch { [void]$stopFailures.Add($_.Exception.Message) }
                }
                try { Wait-AdapterAbsent }
                catch { [void]$stopFailures.Add($_.Exception.Message) }
                if ($serverPid -gt 0) {
                    try { Stop-OwnedProcess $serverPid "server" }
                    catch { [void]$stopFailures.Add($_.Exception.Message) }
                }
                if ($stopFailures.Count -ne 0) {
                    $cleanupFailure = $stopFailures -join "; "
                    $failureMessage = if ($null -eq $trialFailure) {
                        $cleanupFailure
                    } else {
                        "$($trialFailure.Exception.Message); cleanup: $cleanupFailure"
                    }
                    $trialFailure = [Management.Automation.ErrorRecord]::new(
                        [InvalidOperationException]::new($failureMessage),
                        "Ferrum2PerformanceCleanup",
                        [Management.Automation.ErrorCategory]::OperationStopped,
                        $trialRoot
                    )
                }
            }
            if ($null -ne $trialFailure) { throw $trialFailure }
        }
        $files = @(if ($InstrumentedDiagnostic) { @() } else {
            Get-ChildItem -LiteralPath $EvidenceRoot -File -Filter "*.json"
        })
        $networkModelFiles = @(if ($InstrumentedDiagnostic) { @() } else {
            Get-ChildItem -LiteralPath $NetworkModelEvidenceRoot -File `
                -Filter "*.network-model.json"
        })
        $processLogFiles = @(Get-ChildItem -LiteralPath $ProcessLogRoot -File -Filter "*.log")
        if ($files.Count -ne $expectedTrialCount -or
            $networkModelFiles.Count -ne $expectedNetworkModelObservationCount -or
            $processLogFiles.Count -ne $expectedProcessLogCount) {
            throw "guest evidence set is incomplete"
        }
        if ($InstrumentedDiagnostic) {
            $diagnosticFiles = @(Get-ChildItem -LiteralPath $DiagnosticEvidenceRoot `
                -File -Recurse -ErrorAction Stop)
            $diagnosticLengths = @($diagnosticFiles | ForEach-Object { [long]$_.Length })
            if ($instrumentedTrialStatus -cnotin @("PASS", "FAIL") -or
                $instrumentedEvidenceStatus -cnotin @("COMPLETE", "PARTIAL") -or
                $diagnosticFiles.Count -lt 8 -or $diagnosticFiles.Count -gt 32 -or
                [long]($diagnosticLengths | Measure-Object -Sum).Sum -gt 335544320 -or
                [long]($diagnosticLengths | Measure-Object -Maximum).Maximum -gt 268451840) {
                throw "guest UDP diagnostic evidence set exceeds its closed boundary"
            }
        }
        $guestControllerResult = [ordered]@{
            status = "PASS"
            trials = $files.Count
            network_model_observations = $networkModelFiles.Count
            process_logs = $processLogFiles.Count
            evidence_path = if ($InstrumentedDiagnostic) {
                $DiagnosticEvidenceRoot
            } else {
                $EvidenceRoot
            }
            powershell_version = [string]$pwshVersion[0]
            powershell_executable_sha256 = $PowerShellExecutableSha256
        }
        if ($InstrumentedDiagnostic) {
            $cpuRows = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
            if ($cpuRows.Count -le 0) { throw "guest CPU identity is unavailable" }
            $powerText = (& powercfg.exe /getactivescheme 2>&1 | Out-String)
            $powerMatch = [regex]::Match(
                $powerText,
                '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
            )
            if (-not $powerMatch.Success) {
                throw "guest active power plan identity is unavailable"
            }
            $guestControllerResult["diagnostic_profile"] = $DiagnosticProfileValue
            $guestControllerResult["diagnostic_evidence_status"] = `
                $instrumentedEvidenceStatus
            $guestControllerResult["diagnostic_trial_status"] = $instrumentedTrialStatus
            $guestControllerResult["guest_build"] = `
                "$($version.CurrentBuildNumber).$($version.UBR)"
            $guestControllerResult["cpu_model"] = `
                (@($cpuRows | ForEach-Object { $_.Name.Trim() }) -join " | ")
            $guestControllerResult["cpu_count"] = `
                [int]$computer.NumberOfLogicalProcessors
            $guestControllerResult["memory_bytes"] = `
                [uint64]$computer.TotalPhysicalMemory
            $guestControllerResult["power_plan_guid"] = `
                $powerMatch.Value.ToLowerInvariant()
        }
        [pscustomobject]$guestControllerResult
    }
    # END GUEST_ONLY_NETWORK_EXECUTION
    if (@($guestResult).Count -ne 1 -or $guestResult.status -cne "PASS" -or
        [int]$guestResult.trials -ne $expectedTrialCount -or
        [int]$guestResult.network_model_observations -ne
            $expectedNetworkModelObservationCount -or
        [int]$guestResult.process_logs -ne $(if ($instrumentedDiagnosticMode) {
            $expectedDiagnosticProcessLogCount
        } else {
            $expectedProcessLogCount
        }) -or
        [string]$guestResult.powershell_version -cne $portableRuntime.PowerShellVersion -or
        [string]$guestResult.powershell_executable_sha256 -cne
            $portableRuntime.PowerShellExecutableSha256) {
        throw "guest performance controller did not return a complete result"
    }
    if ($instrumentedDiagnosticMode -and (
        [string]$guestResult.diagnostic_profile -cne $DiagnosticProfile -or
        [string]$guestResult.diagnostic_evidence_status -cnotin @("COMPLETE", "PARTIAL") -or
        [string]$guestResult.diagnostic_trial_status -cnotin @("PASS", "FAIL")
    )) {
        throw "guest UDP diagnostic controller result is invalid"
    }
    $guestEvidenceAvailable = $true
} catch {
    $runFailure = $_
} finally {
    if ($instrumentedDiagnosticMode) {
        $hostEndpointPostPath = Join-Path $hostDiagnosticHostRoot `
            "host-endpoints-post.json"
        try {
            Write-HostUdpEndpointSnapshot `
                -Path $hostEndpointPostPath `
                -Stage "post_workload" -SupportProcessId $SupportPid
        } catch {
            $hostEndpointSnapshotFailures.Add("post: $($_.Exception.Message)")
            try {
                Write-HostUdpEndpointErrorSnapshot -Path $hostEndpointPostPath `
                    -Stage "post_workload" -SupportProcessId $SupportPid `
                    -Failure $_.Exception.Message
            } catch {
                $hostEndpointSnapshotFailures.Add(
                    "post error document: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $hostCaptureState) {
            try {
                $hostCaptureResult = Complete-HostUdpDiagnosticCapture `
                    -State $hostCaptureState
                if ($hostCaptureResult.Status -cne "PASS") {
                    throw "Pktmon completion failed: $($hostCaptureResult.Failures -join '; ')"
                }
            } catch {
                $hostCaptureFailure = $_
            }
        }
    }
    if ($null -ne $session) {
        $evidenceExportFailure = $null
        try {
            $guestEvidencePath = Join-Path $guestRoot $(if ($instrumentedDiagnosticMode) {
                "udp-diagnostic"
            } else {
                "raw-evidence"
            })
            $guestEvidenceDestination = if ($instrumentedDiagnosticMode) {
                $hostDiagnosticGuestRoot
            } else {
                $hostEvidenceRoot
            }
            $guestProductRoot = Join-Path $guestRoot "input\artifacts"
            $boundary = @(Invoke-Command -Session $session `
                -ArgumentList $guestEvidencePath, $guestProductRoot `
                -ErrorAction Stop -ScriptBlock {
                    param([string]$Path, [string]$ProductRoot)
                    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
                        return [pscustomobject]@{
                            Exists = $false
                            Safe = $false
                            Reason = "missing"
                            OwnedProcesses = 0
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $productPrefix = [IO.Path]::GetFullPath($ProductRoot).
                        TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                    function Get-OwnedProductProcessCount {
                        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
                                ([string]$_.ExecutablePath).StartsWith(
                                    $productPrefix,
                                    [StringComparison]::OrdinalIgnoreCase
                                ) -and
                                [IO.Path]::GetFileName([string]$_.ExecutablePath) -in @(
                                    "ferrum2-client.exe",
                                    "ferrum2-server.exe"
                                )
                            }).Count
                    }
                    $ownedProcessesBefore = Get-OwnedProductProcessCount
                    if ($ownedProcessesBefore -ne 0) {
                        return [pscustomobject]@{
                            Exists = $true
                            Safe = $false
                            Reason = "owned_process_before"
                            OwnedProcesses = $ownedProcessesBefore
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $items = @(Get-Item -LiteralPath $Path -Force -ErrorAction Stop) + @(
                        Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop
                    )
                    $hasReparsePoint = @($items | Where-Object {
                        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                    }).Count -ne 0
                    if ($hasReparsePoint) {
                        return [pscustomobject]@{
                            Exists = $true
                            Safe = $false
                            Reason = "reparse_point"
                            OwnedProcesses = 0
                            Files = 0
                            ModelFiles = 0
                            TotalFiles = 0
                            TotalBytes = 0
                            LargestFileBytes = 0
                        }
                    }
                    $artifactPaths = @([IO.Directory]::EnumerateFiles(
                        $Path,
                        "*",
                        [IO.SearchOption]::AllDirectories
                    ))
                    $fileLengths = @($artifactPaths | ForEach-Object {
                        [IO.FileInfo]::new([string]$_).Length
                    })
                    $ownedProcessesAfter = Get-OwnedProductProcessCount
                    [pscustomobject]@{
                        Exists = $true
                        Safe = $ownedProcessesAfter -eq 0
                        Reason = if ($ownedProcessesAfter -eq 0) {
                            "safe"
                        } else {
                            "owned_process_after"
                        }
                        OwnedProcesses = $ownedProcessesAfter
                        Files = @(Get-ChildItem -LiteralPath $Path -File -Filter "*.json" `
                            -ErrorAction Stop).Count
                        ModelFiles = @(if (
                            Test-Path -LiteralPath (Join-Path $Path "network-model") `
                                -PathType Container
                        ) {
                            Get-ChildItem -LiteralPath (Join-Path $Path "network-model") `
                                -File -Filter "*.network-model.json" -ErrorAction Stop
                        }).Count
                        TotalFiles = $artifactPaths.Count
                        TotalBytes = [long]($fileLengths | Measure-Object -Sum).Sum
                        LargestFileBytes = [long]($fileLengths | Measure-Object -Maximum).Maximum
                    }
                })
            if ($boundary.Count -ne 1) {
                throw "guest evidence export boundary result is not unique"
            }
            if ($boundary[0].Exists -ne $true) {
                if ($null -eq $runFailure) {
                    throw "guest evidence is absent without a prior run failure"
                }
            } elseif ($boundary[0].Safe -eq $true -and
                [int]$boundary[0].OwnedProcesses -eq 0 -and
                [int]$boundary[0].Files -le $(if ($instrumentedDiagnosticMode) { 8 } else { 90 }) -and
                [int]$boundary[0].ModelFiles -le $(if ($instrumentedDiagnosticMode) { 0 } else { 20 }) -and
                [int]$boundary[0].TotalFiles -le $(if ($instrumentedDiagnosticMode) { 32 } else { 512 }) -and
                [long]$boundary[0].TotalBytes -le $(if ($instrumentedDiagnosticMode) { 335544320 } else { 536870912 }) -and
                [long]$boundary[0].LargestFileBytes -le $(if ($instrumentedDiagnosticMode) { 268451840 } else { 8388608 })) {
                # WinPS 5.1's Copy-Item remoting helper reads Length from the source
                # DirectoryInfo. The guest controller leaves this persistent runspace in
                # strict mode, which turns that helper implementation detail into an error.
                Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    Set-StrictMode -Off
                }
                Copy-Item -FromSession $session -LiteralPath $guestEvidencePath `
                    -Destination $guestEvidenceDestination -Recurse -ErrorAction Stop
            } else {
                throw (
                    "guest evidence export boundary rejected: reason={0} owned={1} " +
                    "json={2} model={3} total_files={4} total_bytes={5} largest={6}"
                ) -f @(
                    [string]$boundary[0].Reason,
                    [int]$boundary[0].OwnedProcesses,
                    [int]$boundary[0].Files,
                    [int]$boundary[0].ModelFiles,
                    [int]$boundary[0].TotalFiles,
                    [long]$boundary[0].TotalBytes,
                    [long]$boundary[0].LargestFileBytes
                )
            }
        } catch {
            $evidenceExportFailure = $_
        }
        if ($null -ne $evidenceExportFailure) {
            if ($null -eq $runFailure) {
                $runFailure = $evidenceExportFailure
            } else {
                $runFailure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($runFailure.Exception.Message); evidence export: " +
                        "$($evidenceExportFailure.Exception.Message) " +
                        "at $($evidenceExportFailure.ScriptStackTrace)"
                    ),
                    "Ferrum2PerformanceEvidenceExport",
                    [Management.Automation.ErrorCategory]::OperationStopped,
                    $hostEvidenceRoot
                )
            }
        }
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        $session = $null
    }
    if ($vmWindowStarted) {
        try {
            Restore-ApprovedVmFinalState -TimeoutSeconds $ShutdownTimeoutSeconds
        } catch {
            $restoreFailure = $_
        }
    }
    if ((Test-Path -LiteralPath $temporaryRoot -PathType Container) -and
        $temporaryRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($temporaryRoot) -cmatch '^ferrum2-tun-performance-[0-9a-f]{32}$') {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
}

if ($null -ne $restoreFailure) {
    if ($null -ne $runFailure) {
        throw "performance run failed and final checkpoint restore failed: run=$($runFailure.Exception.Message); restore=$($restoreFailure.Exception.Message)"
    }
    throw $restoreFailure
}
if ($null -ne $runFailure) { throw $runFailure }
if (-not $guestEvidenceAvailable) { throw "guest evidence was not marked complete" }
$finalTopologyContext = Get-Ferrum2ApprovedHyperVTopologyContext `
    -Document $topologyManifestDocument -ReadinessTimeoutSeconds 10
if ([string]$finalTopologyContext.Vm.State -cne "Off") {
    throw "approved topology final VM state is not Off"
}

if ($instrumentedDiagnosticMode) {
    $finalVmState = [string](Get-ApprovedVmContext).Vm.State
    if ($finalVmState -cne "Off") {
        throw "approved VM final UDP diagnostic state is not Off"
    }
    if (-not (Test-Path -LiteralPath $hostDiagnosticGuestRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $hostDiagnosticHostRoot -PathType Container)) {
        throw "exported UDP diagnostic evidence roots are incomplete"
    }
    $supportFinalContext = Get-HostSupportContext `
        -TopologyDocument $topologyManifestDocument `
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportFinalContext
    if ([string]$supportFinalContext.executable_sha256 -cne
        $candidateBuild.HarnessSha256) {
        throw "support diagnostic binary does not match the candidate harness"
    }
    Complete-UdpSupportDiagnosticLedger `
        -Executable ([string]$supportFinalContext.executable) `
        -TargetIpv4 $SupportIpv4 -FirstUdpPort $SupportUdpPort `
        -RunNonce $SupportDiagnosticRunNonce

    $supportLedgerCopy = Join-Path $hostDiagnosticSupportRoot `
        "udp-support-ledger.ndjson"
    [void](Copy-StableUdpDiagnosticLedger `
        -Source $resolvedSupportDiagnosticLedger `
        -Destination $supportLedgerCopy)
    $supportLedgerSummary = Get-UdpDiagnosticLedgerSummary `
        -Path $supportLedgerCopy `
        -ExpectedSchema "ferrum2.windows-tun.udp-support-ledger.v2" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    if ($supportLedgerSummary.Events -lt $supportDiagnosticBaseline.Events) {
        throw "support diagnostic ledger regressed below its validated baseline"
    }

    $diagnosticNetworkPath = Join-Path $hostDiagnosticHostRoot `
        "host-network-path.json"
    Copy-Item -LiteralPath $hostNetworkPathPath -Destination $diagnosticNetworkPath `
        -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $diagnosticNetworkPath -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $hostNetworkPathPath -Algorithm SHA256).Hash) {
        throw "UDP diagnostic host network-path copy changed"
    }

    $guestRawPath = Join-Path $hostDiagnosticGuestRoot "guest-raw.json"
    $workloadLedgerPath = Join-Path $hostDiagnosticGuestRoot `
        "udp-workload-flow-ledger.ndjson"
    $guestRaw = Get-Content -LiteralPath $guestRawPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 12 -ErrorAction Stop
    if ([string]$guestRaw.schema -cne
            "ferrum2.windows-tun.hyperv-udp-diagnostic-guest-raw.v1" -or
        [string]$guestRaw.profile -cne $DiagnosticProfile -or
        [string]$guestRaw.identity.parent_sha -cne $ParentSha -or
        [string]$guestRaw.identity.candidate_sha -cne $CandidateSha -or
        [string]$guestRaw.identity.harness_sha256 -cne
            $candidateBuild.HarnessSha256 -or
        [string]$guestRaw.identity.collector_sha256 -cne
            $udpBoundaryCollectorSha256 -or
        [string]$guestRaw.identity.diagnostic_run_nonce -cne
            $SupportDiagnosticRunNonce -or
        [int]$guestRaw.identity.diagnostic_max_events -ne
            $SupportDiagnosticMaxEvents -or
        [string]$guestRaw.workload.source_ip -cne
            [string]$diagnosticSourcePlan.Ipv4 -or
        [int]$guestRaw.workload.source_port_first -ne
            [int]$diagnosticSourcePlan.PortFirst -or
        [int]$guestRaw.workload.source_port_last -ne
            [int]$diagnosticSourcePlan.PortLast) {
        throw "exported guest UDP diagnostic raw identity mismatch"
    }
    $workloadLedgerSummary = Get-UdpDiagnosticLedgerSummary `
        -Path $workloadLedgerPath `
        -ExpectedSchema "ferrum2.windows-tun.udp-workload-flow-ledger.v3" `
        -ExpectedRunNonce $SupportDiagnosticRunNonce `
        -ExpectedMaxEvents $SupportDiagnosticMaxEvents
    $expectedWorkloadHeaderFields = @(
        "closure", "max_events", "record_type", "run_nonce", "schema", "scope",
        "source_ip", "source_port_first", "source_port_last", "timestamp_clock",
        "trial_sequence"
    )
    $actualWorkloadHeaderFields = @(
        $workloadLedgerSummary.Header.PSObject.Properties.Name | Sort-Object
    )
    if (($actualWorkloadHeaderFields -join "`n") -cne
            ($expectedWorkloadHeaderFields -join "`n") -or
        [string]$workloadLedgerSummary.Header.scope -cne "bootstrap" -or
        [string]$workloadLedgerSummary.Header.closure -cne
            "workload_process_exit" -or
        [int]$workloadLedgerSummary.Header.trial_sequence -ne
            $DiagnosticTrialSequence -or
        [string]$workloadLedgerSummary.Header.source_ip -cne
            [string]$diagnosticSourcePlan.Ipv4 -or
        [int]$workloadLedgerSummary.Header.source_port_first -ne
            [int]$diagnosticSourcePlan.PortFirst -or
        [int]$workloadLedgerSummary.Header.source_port_last -ne
            [int]$diagnosticSourcePlan.PortLast -or
        ([int]$workloadLedgerSummary.Header.source_port_last -
            [int]$workloadLedgerSummary.Header.source_port_first + 1) -ne
            $udpAssociationCount) {
        throw "exported workload ledger source-port contract mismatch"
    }
    $firstFailedFlow = Get-FirstFailedUdpDiagnosticFlow `
        -Path $workloadLedgerPath -MaximumEvents $SupportDiagnosticMaxEvents
    $supportBoundary = if ($null -ne $firstFailedFlow) {
        Get-SupportUdpBoundaryForFlow `
            -Path $supportLedgerCopy `
            -RunNonce $SupportDiagnosticRunNonce `
            -Flow $firstFailedFlow `
            -MaximumEvents $SupportDiagnosticMaxEvents
    } else {
        [pscustomobject]@{ Rx = $null; Tx = $null }
    }

    $cleanupStatus = if ($null -ne $hostCaptureFailure -or
        $hostEndpointSnapshotFailures.Count -ne 0 -or
        $null -eq $hostCaptureResult -or
        [string]$hostCaptureResult.Status -cne "PASS") {
        "FAIL"
    } else {
        "PASS"
    }
    $trialStatus = [string]$guestRaw.trial_status
    $cleanup = [ordered]@{
        status = $cleanupStatus
        checkpoint_restored = $true
        final_vm_state = $finalVmState
        capture_stop_status = if ($null -ne $hostCaptureResult) {
            [string]$hostCaptureResult.CaptureStopStatus
        } elseif ($null -ne $hostCaptureState) {
            "FAIL"
        } else {
            "NOT_STARTED"
        }
        guest_owned_processes = 0
    }

    $captureManifestPath = Join-Path $hostDiagnosticHostRoot `
        "host-capture-manifest.json"
    $captureManifestFiles = @(
        "PktMon.etl", "PktMon.txt", "PktMon.pcapng",
        "pktmon-counters.json", "pktmon-stop.txt"
    )
    $captureManifestRows = [Collections.Generic.List[object]]::new()
    $captureManifestFailures = [Collections.Generic.List[string]]::new()
    if ($null -ne $hostCaptureFailure) {
        $captureManifestFailures.Add(
            "capture: $($hostCaptureFailure.Exception.Message)"
        )
    }
    if ($null -eq $hostCaptureResult) {
        $captureManifestFailures.Add("capture completion result is unavailable")
    } else {
        foreach ($failure in @($hostCaptureResult.Failures)) {
            $captureManifestFailures.Add([string]$failure)
        }
    }
    foreach ($failure in @($hostEndpointSnapshotFailures)) {
        $captureManifestFailures.Add("endpoint snapshot: $failure")
    }
    $hostCaptureNativeAvailable = $false
    foreach ($captureFileName in $captureManifestFiles) {
        $capturePath = Join-Path $hostDiagnosticHostRoot $captureFileName
        if (-not (Test-Path -LiteralPath $capturePath -PathType Leaf)) {
            $captureManifestFailures.Add("missing: $captureFileName")
            continue
        }
        try {
            $captureItem = Get-Item -LiteralPath $capturePath -Force `
                -ErrorAction Stop
            $maximumCaptureBytes = if ($captureFileName -ceq "PktMon.etl") {
                33554432
            } else {
                134217728
            }
            if ($captureItem.PSIsContainer -or $captureItem.Length -le 0 -or
                $captureItem.Length -gt $maximumCaptureBytes -or
                $captureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "size or file identity is outside its boundary"
            }
            $captureManifestRows.Add([ordered]@{
                file = $captureFileName
                bytes = [long]$captureItem.Length
                sha256 = (Get-FileHash -LiteralPath $capturePath `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
            })
            if ($captureFileName -ceq "PktMon.etl") {
                $hostCaptureNativeAvailable = $true
            }
        } catch {
            $captureManifestFailures.Add(
                "invalid ${captureFileName}: $($_.Exception.Message)"
            )
        }
    }
    if ($captureManifestFailures.Count -ne 0) {
        $cleanupStatus = "FAIL"
        $cleanup["status"] = "FAIL"
    }
    $boundedCaptureFailures = @($captureManifestFailures | Select-Object -First 32 |
        ForEach-Object {
            $value = ([string]$_ -replace '[\r\n]+', ' ').Trim()
            if ($value.Length -gt 2048) { $value.Substring(0, 2048) } else { $value }
        })
    Write-Utf8FileNew -Path $captureManifestPath -Text (([ordered]@{
        schema = "ferrum2.windows-tun.host-capture-manifest.v1"
        state = if ($captureManifestFailures.Count -eq 0) { "COMPLETE" } else { "PARTIAL" }
        filters = if ($null -ne $hostCaptureState) {
            @($hostCaptureState.Filters)
        } else {
            @()
        }
        started_utc = if ($null -ne $hostCaptureState) {
            [string]$hostCaptureState.StartedUtc
        } else {
            $null
        }
        stop_status = if ($null -ne $hostCaptureResult) {
            [string]$hostCaptureResult.CaptureStopStatus
        } elseif ($null -ne $hostCaptureState) {
            "FAIL"
        } else {
            "NOT_STARTED"
        }
        expected_files = $captureManifestFiles
        files = $captureManifestRows.ToArray()
        failures = $boundedCaptureFailures
    } | ConvertTo-Json -Depth 6) + "`n")

    $guestProcessLogPath = Join-Path $hostDiagnosticGuestRoot `
        "guest-process-logs.txt"
    $guestProcessLogText = [Text.StringBuilder]::new()
    foreach ($processLog in @(Get-ChildItem `
        -LiteralPath (Join-Path $hostDiagnosticGuestRoot "process-logs") `
        -File -Filter "*.log" -ErrorAction Stop | Sort-Object Name)) {
        [void]$guestProcessLogText.AppendLine("===== $($processLog.Name) =====")
        [void]$guestProcessLogText.AppendLine(
            (Get-Content -LiteralPath $processLog.FullName -Raw -Encoding utf8)
        )
        if ($utf8NoBom.GetByteCount($guestProcessLogText.ToString()) -gt 8388608) {
            throw "combined guest process log exceeded 8 MiB"
        }
    }
    Write-Utf8FileNew -Path $guestProcessLogPath `
        -Text $guestProcessLogText.ToString()

    $failureSummary = $null
    $failureSummaryReference = $null
    if ($trialStatus -ceq "FAIL") {
        $supportRx = $null -ne $supportBoundary.Rx
        $supportTxObserved = $null -ne $supportBoundary.Tx
        $supportTxSuccess = $supportTxObserved -and
            [string]$supportBoundary.Tx.send_result -ceq "success"
        $lastConfirmedStage = if ($supportTxObserved) {
            "support_tx"
        } elseif ($supportRx) {
            "support_rx"
        } elseif ($null -ne $firstFailedFlow -and
            [string]$firstFailedFlow.send_result -ceq "success") {
            "workload_send"
        } else {
            $null
        }
        $firstMissingStage = $null
        $workloadCoversNonce = $null -ne $firstFailedFlow -and
            $workloadLedgerSummary.Closed -and
            $workloadLedgerSummary.DroppedEvents -eq 0 -and
            $workloadLedgerSummary.WriteFailures -eq 0
        $supportAbsenceProvable = $null -ne $firstFailedFlow -and
            $supportLedgerSummary.Closed -and
            $supportLedgerSummary.DroppedEvents -eq 0 -and
            $supportLedgerSummary.WriteFailures -eq 0
        $failureFingerprint = if ($supportTxSuccess) {
            "udp/bootstrap/reply-missing-after-support-tx"
        } elseif ($supportTxObserved) {
            "udp/bootstrap/support-tx-not-success"
        } elseif ($supportRx) {
            if ($supportAbsenceProvable) {
                "udp/bootstrap/reply-missing-at-support-tx"
            } else {
                "udp/bootstrap/support-tx-boundary-unknown"
            }
        } elseif ($supportAbsenceProvable) {
            "udp/bootstrap/request-missing-before-support-rx"
        } else {
            "udp/bootstrap/support-boundary-unknown"
        }
        $workloadTuple = if ($null -eq $firstFailedFlow) { $null } else {
            [ordered]@{
                source_ip = [string]$firstFailedFlow.workload_local_ip
                source_port = [int]$firstFailedFlow.workload_local_port
                target_ip = [string]$firstFailedFlow.target_ip
                target_port = [int]$firstFailedFlow.target_port
            }
        }
        $physicalTuple = if ($null -eq $supportBoundary.Rx) { $null } else {
            [ordered]@{
                source_ip = [string]$supportBoundary.Rx.remote_ip
                source_port = [int]$supportBoundary.Rx.remote_port
                target_ip = [string]$supportBoundary.Rx.listen_ip
                target_port = [int]$supportBoundary.Rx.listen_port
            }
        }
        $workloadLedgerComplete = $workloadLedgerSummary.Closed -and
            $workloadLedgerSummary.DroppedEvents -eq 0 -and
            $workloadLedgerSummary.WriteFailures -eq 0
        $supportLedgerComplete = $supportLedgerSummary.Closed -and
            $supportLedgerSummary.DroppedEvents -eq 0 -and
            $supportLedgerSummary.WriteFailures -eq 0
        $observations = [ordered]@{}
        foreach ($stage in @(
            "workload_send", "direct_send", "guest_request", "host_request",
            "support_rx", "support_tx", "host_reply", "guest_reply",
            "ferrum_receive", "response_classified", "response_sink",
            "wintun_injection", "workload_reply"
        )) {
            $observations[$stage] = "UNKNOWN"
        }
        if ($null -ne $firstFailedFlow) {
            $observations.workload_send = if (
                [string]$firstFailedFlow.send_result -ceq "success"
            ) { "SEEN" } elseif ($workloadLedgerComplete) { "NOT_SEEN" } else { "UNKNOWN" }
            $observations.workload_reply = if (
                [string]$firstFailedFlow.reply_result -ceq "success"
            ) {
                "SEEN"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "not_observed") {
                "UNKNOWN"
            } elseif ($workloadLedgerComplete) {
                "NOT_SEEN"
            } else {
                "UNKNOWN"
            }
        }
        if ($supportRx) {
            $observations.support_rx = "SEEN"
        } elseif ($supportLedgerComplete -and $null -ne $firstFailedFlow) {
            $observations.support_rx = "NOT_SEEN"
        }
        if ($supportTxObserved) {
            $observations.support_tx = "SEEN"
        } elseif ($supportLedgerComplete -and $null -ne $firstFailedFlow) {
            $observations.support_tx = "NOT_SEEN"
        }
        $firstMissingStage = if ($observations.workload_send -ceq "NOT_SEEN") {
            "workload_send"
        } elseif ($observations.support_rx -ceq "SEEN" -and
            $observations.support_tx -ceq "NOT_SEEN") {
            "support_tx"
        } else {
            $null
        }
        $source = {
            param([string]$State, [long]$Records, [long]$Dropped,
                [long]$WriteFailures, [bool]$CoversNonce)
            [ordered]@{
                state = $State
                records = $Records
                dropped_events = $Dropped
                write_failures = $WriteFailures
                covers_packet_nonce = $CoversNonce
            }
        }
        $failureSummary = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-udp-failure-summary.v1"
            qualification = $false
            run_nonce = $SupportDiagnosticRunNonce
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            sha = $ParentSha
            tree = $parentTree
            client_sha256 = $parentBuild.ClientSha256
            server_sha256 = $parentBuild.ServerSha256
            harness_sha256 = $candidateBuild.HarnessSha256
            runner_sha256 = $runnerSourceSha256
            recipe_sha256 = [string]$plan.recipe_sha256
            vm_id = $approvedVmId.ToString("D")
            checkpoint_id = $approvedCheckpointId.ToString("D")
            support_pid = $SupportPid
            support_owner = $SupportOwner
            support_sha256 = [string]$supportFinalContext.executable_sha256
            trial_sequence = [int]$diagnosticTrial.sequence
            scenario = [string]$diagnosticTrial.scenario
            member = [string]$diagnosticTrial.member
            pair = [int]$diagnosticTrial.pair
            order = [int]$diagnosticTrial.order
            failure_kind = if ($null -eq $firstFailedFlow) {
                "other"
            } elseif ([string]$firstFailedFlow.send_result -in @(
                "error", "partial"
            )) {
                "send_error"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "timeout") {
                "timeout"
            } elseif ([string]$firstFailedFlow.reply_result -ceq "error") {
                "receive_error"
            } elseif ([string]$firstFailedFlow.reply_result -ceq
                "payload_mismatch") {
                "payload_mismatch"
            } else {
                "other"
            }
            phase = if ($null -ne $firstFailedFlow) {
                [string]$firstFailedFlow.phase
            } else {
                "bootstrap"
            }
            association_index = if ($null -ne $firstFailedFlow) {
                [int]$firstFailedFlow.association_index
            } else {
                $null
            }
            round = if ($null -ne $firstFailedFlow) {
                [int]$firstFailedFlow.round
            } else {
                $null
            }
            packet_nonce = if ($null -ne $firstFailedFlow) {
                [string]$firstFailedFlow.packet_nonce
            } else {
                $null
            }
            workload_tuple = $workloadTuple
            physical_tuple = $physicalTuple
            observation_sources = [ordered]@{
                workload_ledger = & $source `
                    $(if ($workloadLedgerComplete) { "COMPLETE" } else { "TRUNCATED" }) `
                    $workloadLedgerSummary.Events `
                    $workloadLedgerSummary.DroppedEvents `
                    $workloadLedgerSummary.WriteFailures $workloadCoversNonce
                support_ledger = & $source `
                    $(if ($supportLedgerComplete) { "COMPLETE" } else { "TRUNCATED" }) `
                    $supportLedgerSummary.Events `
                    $supportLedgerSummary.DroppedEvents `
                    $supportLedgerSummary.WriteFailures $supportAbsenceProvable
                host_capture = & $source `
                    $(if ($cleanupStatus -ceq "PASS") { "COMPLETE" } else { "ERROR" }) `
                    0 0 0 $false
                guest_capture = & $source "NOT_ENABLED" 0 0 0 $false
                ferrum_boundary = & $source "NOT_ENABLED" 0 0 0 $false
            }
            observations = $observations
            last_confirmed_stage = $lastConfirmedStage
            first_missing_stage = $firstMissingStage
            response_sink_outcome = $null
            failure_fingerprint = $failureFingerprint
            cleanup = $cleanup
        }
        Write-Utf8FileNew -Path $hostDiagnosticFailurePath `
            -Text (($failureSummary | ConvertTo-Json -Depth 10) + "`n")
        $failureSummaryReference = [ordered]@{
            file = [IO.Path]::GetRelativePath(
                $hostDiagnosticRoot,
                $hostDiagnosticFailurePath
            ).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $hostDiagnosticFailurePath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $artifacts = [Collections.Generic.List[object]]::new()
    $artifacts.Add((New-UdpDiagnosticArtifactRecord `
        -Role "workload_ledger" -Path $workloadLedgerPath `
        -LedgerSummary $workloadLedgerSummary -MaxEvents $SupportDiagnosticMaxEvents))
    $artifacts.Add((New-UdpDiagnosticArtifactRecord `
        -Role "support_ledger" -Path $supportLedgerCopy `
        -LedgerSummary $supportLedgerSummary -MaxEvents $SupportDiagnosticMaxEvents))
    foreach ($artifactSpec in @(
        @("host_capture", "host", "host-capture-manifest.json"),
        @("endpoint_snapshot_before", "guest", "guest-endpoints-pre.json"),
        @("endpoint_snapshot_after", "guest", "guest-endpoints-post.json"),
        @("dynamic_port_snapshot_before", "host", "host-endpoints-pre.json"),
        @("dynamic_port_snapshot_after", "host", "host-endpoints-post.json"),
        @("host_network_path", "host", "host-network-path.json"),
        @("runner_log", "guest", "guest-raw.json"),
        @("guest_process_log", "guest", "guest-process-logs.txt")
    )) {
        $artifactRoot = if ($artifactSpec[1] -ceq "host") {
            $hostDiagnosticHostRoot
        } else {
            $hostDiagnosticGuestRoot
        }
        $artifactState = if ($artifactSpec[0] -ceq "host_capture" -and
            $cleanupStatus -cne "PASS") {
            "PARTIAL"
        } elseif ($artifactSpec[0] -in @(
            "dynamic_port_snapshot_before", "dynamic_port_snapshot_after"
        ) -and $hostEndpointSnapshotFailures.Count -ne 0) {
            "PARTIAL"
        } elseif ($artifactSpec[0] -in @(
            "endpoint_snapshot_before", "endpoint_snapshot_after"
        ) -and @($guestRaw.snapshot_errors).Count -ne 0) {
            "PARTIAL"
        } elseif ($artifactSpec[0] -ceq "runner_log" -and
            [string]$guestRaw.evidence_status -cne "COMPLETE") {
            "PARTIAL"
        } else {
            "COMPLETE"
        }
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role $artifactSpec[0] `
            -Path (Join-Path $artifactRoot $artifactSpec[2]) `
            -StateOverride $artifactState))
    }
    if ($hostCaptureNativeAvailable) {
        $nativeCaptureState = if ($cleanupStatus -ceq "PASS") {
            "COMPLETE"
        } else {
            "PARTIAL"
        }
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role "host_capture_native" `
            -Path (Join-Path $hostDiagnosticHostRoot "PktMon.etl") `
            -StateOverride $nativeCaptureState))
    }
    if ($trialStatus -ceq "FAIL") {
        $artifacts.Add((New-UdpDiagnosticArtifactRecord `
            -Role "failure_summary" -Path $hostDiagnosticFailurePath))
    }
    if ($artifacts.Count -gt 16) {
        throw "UDP diagnostic artifact manifest exceeds its closed boundary"
    }
    $presentArtifactBytes = Get-UdpDiagnosticArtifactTotalByteCount -Artifacts $artifacts
    if ($presentArtifactBytes -gt 268435456) {
        throw "UDP diagnostic artifact manifest exceeds its total byte boundary"
    }
    $evidenceStatus = if (@($artifacts | Where-Object {
        $_.state -ceq "PARTIAL"
    }).Count -ne 0) { "PARTIAL" } else { "COMPLETE" }

    # PowerShell 7.6 materializes JSON ISO timestamps as DateTime; 7.4 retains strings.
    $guestRawStartedUtc = ConvertTo-CanonicalUtcText `
        -Value $guestRaw.started_utc -Label "guest raw started_utc"
    [void](ConvertTo-CanonicalUtcText `
        -Value $guestRaw.finished_utc -Label "guest raw finished_utc")
    $diagnosticDocument = [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-udp-diagnostic.v1"
        qualification = $false
        profile = $DiagnosticProfile
        evidence_status = $evidenceStatus
        trial_status = $trialStatus
        run_nonce = $SupportDiagnosticRunNonce
        started_utc = $guestRawStartedUtc
        finished_utc = [DateTime]::UtcNow.ToString("o")
        identity = [ordered]@{
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            sha = $ParentSha
            tree = $parentTree
            client_sha256 = $parentBuild.ClientSha256
            server_sha256 = $parentBuild.ServerSha256
            harness_sha256 = $candidateBuild.HarnessSha256
            runner_sha256 = $runnerSourceSha256
            recipe_sha256 = [string]$plan.recipe_sha256
            plan_sha256 = (Get-FileHash -LiteralPath $hostPlanPath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        trial = [ordered]@{
            selection = [string]$plan.selection
            run_kind = $RunKind
            sequence = [int]$diagnosticTrial.sequence
            scenario = [string]$diagnosticTrial.scenario
            member = [string]$diagnosticTrial.member
            pair = [int]$diagnosticTrial.pair
            order = [int]$diagnosticTrial.order
        }
        environment = [ordered]@{
            runner_os = "Windows"
            runner_arch = "X64"
            runner_label = "ferrum2-hyperv-guest"
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
            topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
            support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
            rust_toolchain = "1.97.1"
            cargo_profile = "profiling"
            pair_schedule = "alternating-parent-candidate"
            guest_build = [string]$guestResult.guest_build
            cpu_model = [string]$guestResult.cpu_model
            cpu_count = [int]$guestResult.cpu_count
            memory_bytes = [uint64]$guestResult.memory_bytes
            power_plan_guid = [string]$guestResult.power_plan_guid
        }
        support = [ordered]@{
            pid = $SupportPid
            owner = $SupportOwner
            binary_sha256 = [string]$supportFinalContext.executable_sha256
            listen_endpoints = @(
                [ordered]@{ protocol = "tcp"; ip = $SupportIpv4; port = $SupportTcpPort }
                $SupportUdpPort..($SupportUdpPort + 3) | ForEach-Object {
                    [ordered]@{ protocol = "udp"; ip = $SupportIpv4; port = [int]$_ }
                }
            )
        }
        topology = [ordered]@{
            support_ipv4 = $SupportIpv4
            guest_ipv4 = [string]$guestNetworkPath.guest_ipv4
            host_network_path_file = "host/host-network-path.json"
            host_network_path_sha256 = (Get-FileHash `
                -LiteralPath $diagnosticNetworkPath -Algorithm SHA256).Hash.ToLowerInvariant()
            host_tun_bypassed = $true
            host_network_mutations = @()
        }
        bounds = [ordered]@{
            max_artifacts = 16
            max_total_bytes = 268435456
            max_artifact_bytes = 134217728
            max_ndjson_line_bytes = 4096
            max_ledger_events = $SupportDiagnosticMaxEvents
        }
        artifacts = $artifacts.ToArray()
        failure_summary = $failureSummaryReference
        cleanup = $cleanup
    }
    Write-Utf8FileNew -Path $hostDiagnosticPath `
        -Text (($diagnosticDocument | ConvertTo-Json -Depth 10) + "`n")
    $diagnosticValidatorRows = @(& $python -B $controlPath `
        "windows-tun-validate-udp-diagnostic" `
        "--plan" $hostPlanPath `
        "--evidence-root" $hostDiagnosticRoot `
        "--parent-sha" $ParentSha `
        "--candidate-sha" $CandidateSha `
        "--policy" $policyPath 2>&1)
    $diagnosticValidatorExit = $LASTEXITCODE
    $diagnosticValidatorLines = @($diagnosticValidatorRows | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            [string]$_.Exception.Message
        } else {
            [string]$_
        }
    })
    $expectedDiagnosticValidatorLine = "{0}`t{1}`t{2}`t{3}`t{4}`tqualification=false" -f @(
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair,
        $trialStatus,
        $evidenceStatus
    )
    if ($diagnosticValidatorExit -ne 0 -or
        $diagnosticValidatorLines.Count -ne 1 -or
        [string]$diagnosticValidatorLines[0] -cne $expectedDiagnosticValidatorLine) {
        $validatorDetail = ($diagnosticValidatorLines -join " | ")
        if ($validatorDetail.Length -gt 2048) {
            $validatorDetail = $validatorDetail.Substring(0, 2048)
        }
        throw "UDP diagnostic validation failed: exit=$diagnosticValidatorExit detail=$validatorDetail"
    }
    [pscustomobject]@{
        schema = "ferrum2.windows-tun.hyperv-udp-diagnostic-result.v1"
        status = $trialStatus
        evidence_status = $evidenceStatus
        qualification = $false
        diagnostic = $hostDiagnosticPath
        failure_summary = if ($null -ne $failureSummary) {
            $hostDiagnosticFailurePath
        } else {
            $null
        }
        final_vm_state = $finalVmState
        checkpoint_restored = $true
        host_tun_bypassed = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Depth 4
    if ($trialStatus -ceq "PASS" -and $evidenceStatus -ceq "COMPLETE") {
        exit 0
    }
    exit 1
}

$rawEvidence = Join-Path $hostEvidenceRoot "raw-evidence"
$rawNetworkModelEvidence = Join-Path $rawEvidence "network-model"
$rawProcessLogs = Join-Path $rawEvidence "process-logs"
$rawTrialFiles = @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json" `
    -ErrorAction Stop)
$rawNetworkModelFiles = @(if (
    Test-Path -LiteralPath $rawNetworkModelEvidence -PathType Container
) {
    Get-ChildItem -LiteralPath $rawNetworkModelEvidence -File `
        -Filter "*.network-model.json" -ErrorAction Stop
})
$rawProcessLogFiles = @(Get-ChildItem -LiteralPath $rawProcessLogs -File -Filter "*.log" `
    -ErrorAction Stop)
if (-not (Test-Path -LiteralPath $hostNetworkPathPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $rawEvidence -PathType Container) -or
    $rawTrialFiles.Count -ne $expectedTrialCount -or
    ($expectedNetworkModelObservationCount -ne 0 -and
        -not (Test-Path -LiteralPath $rawNetworkModelEvidence -PathType Container)) -or
    $rawNetworkModelFiles.Count -ne $expectedNetworkModelObservationCount -or
    -not (Test-Path -LiteralPath $rawProcessLogs -PathType Container) -or
    $rawProcessLogFiles.Count -ne $expectedProcessLogCount) {
    throw "exported raw evidence is incomplete"
}
if ($diagnosticMode) {
    $diagnosticFileName = "{0:D3}-{1}-{2}-pair-{3}.json" -f @(
        [int]$diagnosticTrial.sequence,
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair
    )
    $diagnosticTrialPath = Join-Path $rawEvidence $diagnosticFileName
    $diagnosticTrialItem = Get-Item -LiteralPath $diagnosticTrialPath `
        -ErrorAction SilentlyContinue
    if ($rawTrialFiles.Count -ne 1 -or
        $null -eq $diagnosticTrialItem -or $diagnosticTrialItem.PSIsContainer -or
        -not $rawTrialFiles[0].FullName.Equals(
            $diagnosticTrialItem.FullName,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "diagnostic trial evidence identity is invalid"
    }
    $validatorRows = @(& $python -B $controlPath "windows-tun-validate-trial" `
        "--plan" $hostPlanPath `
        "--trial" $diagnosticTrialPath `
        "--parent-sha" $ParentSha `
        "--candidate-sha" $CandidateSha `
        "--policy" $policyPath 2>&1)
    $validatorExit = $LASTEXITCODE
    $validatorLines = @($validatorRows | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            [string]$_.Exception.Message
        } else {
            [string]$_
        }
    })
    $expectedValidatorLine = "{0}`t{1}`t{2}`t{3}" -f @(
        [string]$diagnosticTrial.scenario,
        [string]$diagnosticTrial.member,
        [int]$diagnosticTrial.pair,
        [int]$diagnosticTrial.order
    )
    if ($validatorExit -ne 0 -or $validatorLines.Count -ne 1 -or
        [string]$validatorLines[0] -cne $expectedValidatorLine) {
        $validatorDetail = ($validatorLines -join " | ")
        if ($validatorDetail.Length -gt 2048) {
            $validatorDetail = $validatorDetail.Substring(0, 2048)
        }
        throw "diagnostic trial validation failed: exit=$validatorExit detail=$validatorDetail"
    }
    $diagnosticFinalVmState = [string](Get-ApprovedVmContext).Vm.State
    if ($diagnosticFinalVmState -cne "Off") {
        throw "approved VM final diagnostic state is not Off"
    }
    [pscustomobject]@{
        schema = "ferrum2.windows-tun.hyperv-performance-diagnostic-result.v1"
        status = "PASS"
        qualification = $false
        run_kind = $RunKind
        diagnostic_trial_sequence = [int]$diagnosticTrial.sequence
        scenario = [string]$diagnosticTrial.scenario
        member = [string]$diagnosticTrial.member
        pair = [int]$diagnosticTrial.pair
        order = [int]$diagnosticTrial.order
        validator_status = "PASS"
        reducer_invoked = $false
        evidence_directory = $hostEvidenceRoot
        raw_trials = $rawTrialFiles.Count
        raw_network_model_observations = $rawNetworkModelFiles.Count
        process_logs = $rawProcessLogFiles.Count
        host_network_path = $hostNetworkPathPath
        host_network_path_sha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        topology_manifest = $hostTopologyManifestPath
        topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
        topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
        support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        final_vm_state = $diagnosticFinalVmState
        checkpoint_restored = $true
        host_tun_bypassed = $true
        host_network_mutations = 0
    } | ConvertTo-Json -Depth 4
    exit 0
}
$summaryArguments = @(
    "-B", $controlPath, "windows-tun-summarize",
    "--plan", $hostPlanPath,
    "--evidence-root", $rawEvidence,
    "--parent-sha", $ParentSha,
    "--candidate-sha", $CandidateSha,
    "--policy", $policyPath,
    "--output", $hostSummaryPath,
    "--markdown", $hostMarkdownPath
)
if ($RunKind -ceq "calibration-aa") {
    $summaryArguments += @("--calibration-output", $hostCalibrationPath)
}
& $python @summaryArguments
$summaryExit = $LASTEXITCODE
if (-not (Test-Path -LiteralPath $hostSummaryPath -PathType Leaf)) {
    throw "host reducer did not write a summary"
}
$summary = Get-Content -LiteralPath $hostSummaryPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30
[pscustomobject]@{
    schema = "ferrum2.windows-tun.hyperv-performance-result.v2"
    status = [string]$summary.status
    reducer_exit_code = $summaryExit
    evidence_directory = $hostEvidenceRoot
    raw_trials = $rawTrialFiles.Count
    raw_network_model_observations = $rawNetworkModelFiles.Count
    process_logs = $rawProcessLogFiles.Count
    host_network_path = $hostNetworkPathPath
    host_network_path_sha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    topology_manifest = $hostTopologyManifestPath
    topology_manifest_sha256 = [string]$topologyManifestDocument.Sha256
    topology_plan_sha256 = [string]$topologyPlanDocument.Sha256
    support_switch_id = [string]$topologyManifestDocument.Value.support.switch.switch_id
    vm_name = $approvedVmName
    vm_id = $approvedVmId.ToString("D")
    checkpoint_name = $approvedCheckpointName
    checkpoint_id = $approvedCheckpointId.ToString("D")
    final_vm_state = [string](Get-ApprovedVmContext).Vm.State
    checkpoint_restored = $true
    host_tun_bypassed = $true
    host_network_mutations = 0
} | ConvertTo-Json -Depth 4
exit $summaryExit
