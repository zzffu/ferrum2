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

Run mode requires an already provisioned candidate qualification support listener reachable from
the guest. It provides TCP echo, ordinary UDP echo, bounded fragment acknowledgements, and four
contiguous UDP ports. The listener must bind an existing, active physical host IPv4 address rather
than a host TUN or Hyper-V switch address. Before any TUN session starts, the runner proves that the
guest forward path uses its approved Default Switch underlay and that the host return path is the
same switch's direct local route. The path and listener identities are retained as evidence.

PlanOnly validates repository lineage and emits the closed 90-trial plan without building, starting
the VM, loading a credential, staging files, or executing traffic.
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

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateScript({
        $parsed = $null
        [Net.IPAddress]::TryParse($_, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            -not $parsed.Equals([Net.IPAddress]::Any) -and
            -not [Net.IPAddress]::IsLoopback($parsed) -and
            $parsed.GetAddressBytes()[0] -lt 224
    })]
    [string]$SupportIpv4,

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
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ShutdownTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$approvedVmName = "Windows 10 MSIX packaging environment"
$approvedVmId = [Guid]"82e20295-1d30-48e7-a751-e21d35d872d4"
$approvedCheckpointName = "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9"
$approvedCheckpointId = [Guid]"1e570209-faf7-4248-8167-aa0687cdb8cf"
$approvedVmSwitchName = "Default Switch"
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$minimumSupportIpv4PacketBytes = 1468
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") -ErrorAction Stop).Path
$policyPath = Join-Path $PSScriptRoot "windows_tun_performance_policy.json"
$controlPath = Join-Path $PSScriptRoot "performance_candidate.py"
$collectorPath = Join-Path $PSScriptRoot "collect_windows_tun_performance_trial.ps1"
$guestNetworkPathProbePath = Join-Path $PSScriptRoot `
    "get_windows_tun_guest_network_path.ps1"
$hostNetworkPathHelperPath = Join-Path $PSScriptRoot `
    "windows_tun_host_network_path.ps1"
$networkModelControllerPath = Join-Path $repositoryRoot `
    "tests\performance_candidate\windows_tun_network_model.py"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$runnerSourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).
    Hash.ToLowerInvariant()

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
        [string]::IsNullOrWhiteSpace($credential.UserName)) {
        throw "guest credential file does not contain a PSCredential"
    }
    return $credential
}

function Get-ApprovedVmContext {
    $vm = Get-VM -Id $script:approvedVmId -ErrorAction Stop
    if ($vm.Name -cne $script:approvedVmName) { throw "approved VM identity mismatch" }
    $byName = @(Get-VM -Name $script:approvedVmName -ErrorAction Stop)
    if ($byName.Count -ne 1 -or $byName[0].Id -ne $script:approvedVmId) {
        throw "approved VM name does not resolve to the approved ID"
    }
    $checkpoint = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
        $_.Id -eq $script:approvedCheckpointId
    })
    if ($checkpoint.Count -ne 1 -or $checkpoint[0].Name -cne $script:approvedCheckpointName) {
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
    $arguments = @(
        "+1.97.1", "build", "-p", "ferrum2-client", "-p", "ferrum2-server"
    )
    if ($IncludeHarness) { $arguments += @("-p", "ferrum2-m4-qualification") }
    $arguments += @("--bins", "--locked", "--profile", "profiling")
    Invoke-NativeChecked -Executable $Cargo -Arguments $arguments -Label "host $Member build" `
        -WorkingDirectory $source
    $destination = Join-Path $ArtifactRoot $Member
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $profile = Join-Path $source "target\profiling"
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
    $hostNetworkPathHelperPath, $networkModelControllerPath
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required performance controller file is missing: $required"
    }
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
            checkpoint_id = $approvedCheckpointId.ToString("D")
            host_actions = @(
                "validate physical support binding", "archive exact commits",
                "build profiling binaries", "stage files",
                "validate direct Default Switch return path", "reduce evidence"
            )
            guest_actions = @(
                "reject gateway and DNS support collisions", "probe support",
                "validate Default Switch underlay", "run 90 collector trials",
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
    -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
    -ProcessId $SupportPid -ProcessOwner $SupportOwner `
    -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
$vmNetworkBaseline = Get-ApprovedVmNetworkContext `
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
$hostEvidenceRoot = Resolve-NewExternalDirectory -Path $EvidenceDirectory -Label "evidence directory"
$credential = Import-ApprovedGuestCredential -Path $CredentialPath
$cargo = @(Get-Command cargo -CommandType Application -ErrorAction Stop)[0].Source
$rustup = @(Get-Command rustup -CommandType Application -ErrorAction Stop)[0].Source
$tar = @(Get-Command tar -CommandType Application -ErrorAction Stop)[0].Source
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-tun-performance-" + [Guid]::NewGuid().ToString("N")
)
$artifactRoot = Join-Path $temporaryRoot "input\artifacts"
$runtimeRoot = Join-Path $temporaryRoot "input\runtime"
$hostPlanPath = Join-Path $hostEvidenceRoot "plan.json"
$hostNetworkModelPlanPath = Join-Path $hostEvidenceRoot "network-model-plan.json"
$hostNetworkPathPath = Join-Path $hostEvidenceRoot "host-network-path.json"
$hostSchedulePath = Join-Path $hostEvidenceRoot "trial-schedule.tsv"
$hostSummaryPath = Join-Path $hostEvidenceRoot "summary.json"
$hostMarkdownPath = Join-Path $hostEvidenceRoot "summary.md"
$hostCalibrationPath = Join-Path $hostEvidenceRoot "aa-calibration.json"
$guestToken = [Guid]::NewGuid().ToString("N")
$guestRoot = "C:\Windows\Temp\ferrum2-tun-performance-$guestToken"
$session = $null
$vmWindowStarted = $false
$guestEvidenceAvailable = $false
$runFailure = $null
$restoreFailure = $null

try {
    [IO.Directory]::CreateDirectory($hostEvidenceRoot) | Out-Null
    [IO.Directory]::CreateDirectory($artifactRoot) | Out-Null
    [IO.Directory]::CreateDirectory($runtimeRoot) | Out-Null
    $plan = New-CanonicalPlan -Python $python -RunKindValue $RunKind -Output $hostPlanPath
    [void](New-NetworkModelPlan -Python $python -Output $hostNetworkModelPlanPath `
        -ExpectedSha256 ([string]$plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256))
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
    Copy-Item -LiteralPath $guestNetworkPathProbePath `
        -Destination (Join-Path $temporaryRoot "input") -ErrorAction Stop
    $guestNetworkPathProbeSha256 = (Get-FileHash -LiteralPath $guestNetworkPathProbePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
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
ring_capacity = 131072
ready_timeout_ms = 30000
max_tcp_flows = 4096
tcp_buffer_bytes = 32768
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
server = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
[route]
auto_detect_interface = true
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
idle_timeout_ms = 2000
[metrics]
listen = "127.0.0.1:{{METRICS_PORT}}"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
'@
    $serverTemplate = @'
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "{{SERVER_ADDRESS}}:{{SERVER_PORT}}"
[[outbounds]]
tag = "direct"
[route]
auto_detect_interface = true
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
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostReadback
    $vmNetworkReadback = Get-ApprovedVmNetworkContext `
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
            $guestNetworkPathProbeSha256, $candidateBuild.HarnessSha256,
            $portableRuntime.PowerShellExecutableSha256,
            $minimumSupportIpv4PacketBytes
        ) -ScriptBlock {
            param(
                [string]$Root,
                [string]$SupportAddress,
                [int]$SupportTcp,
                [int]$SupportUdp,
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
        -Address $SupportIpv4 -TcpPort $SupportTcpPort -UdpPort $SupportUdpPort `
        -ProcessId $SupportPid -ProcessOwner $SupportOwner `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-HostSupportContextUnchanged `
        -Expected $supportHostBaseline -Actual $supportHostAfterProbe
    $vmNetworkAfterProbe = Get-ApprovedVmNetworkContext `
        -MinimumIpv4PacketBytes $minimumSupportIpv4PacketBytes
    Assert-ApprovedVmNetworkContextUnchanged `
        -Expected $vmNetworkBaseline -Actual $vmNetworkAfterProbe
    $hostReturnPath = Get-HostGuestReturnPath `
        -GuestPath $guestNetworkPath -VmNetworkContext $vmNetworkAfterProbe `
        -ExpectedSupportIpv4 $SupportIpv4
    $networkPathEvidence = [ordered]@{
        schema = 1
        kind = "windows_tun_host_network_path"
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

    # BEGIN GUEST_ONLY_NETWORK_EXECUTION
    $guestResult = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @(
        $guestRoot,
        $approvedVmName,
        $approvedVmId.ToString("D"),
        $approvedCheckpointName,
        $approvedCheckpointId.ToString("D"),
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
        $SupportPid,
        $SupportOwner,
        $minimumSupportIpv4PacketBytes
    ) -ScriptBlock {
        param(
            [string]$Root,
            [string]$VmName,
            [string]$VmId,
            [string]$CheckpointName,
            [string]$CheckpointId,
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
            [int]$SupportProcessId,
            [string]$SupportProcessOwner,
            [int]$MinimumSupportIpv4PacketBytes
        )
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"
        $ProgressPreference = "SilentlyContinue"
        $Utf8NoBom = New-Object Text.UTF8Encoding($false)
        $InputRoot = Join-Path $Root "input"
        $EvidenceRoot = Join-Path $Root "raw-evidence"
        $NetworkModelEvidenceRoot = Join-Path $EvidenceRoot "network-model"
        $ProcessLogRoot = Join-Path $EvidenceRoot "process-logs"
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
            (Test-Path -LiteralPath $EvidenceRoot)) {
            throw "guest performance boundary is invalid"
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
        New-Item -ItemType Directory -Path $EvidenceRoot | Out-Null
        New-Item -ItemType Directory -Path $NetworkModelEvidenceRoot | Out-Null
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
                "guest_interface_index", "guest_interface_alias", "guest_interface_mtu_bytes",
                "guest_mac_address",
                "guest_route_prefix", "guest_route_next_hop", "guest_dns_ipv4"
            )
            if ((@($actual.PSObject.Properties.Name) -join "|") -cne ($fields -join "|") -or
                (@($ExpectedGuestNetworkPath.PSObject.Properties.Name) -join "|") -cne
                    ($fields -join "|") -or
                [int]$actual.schema -ne 1 -or [int]$ExpectedGuestNetworkPath.schema -ne 1) {
                throw "guest network-path evidence shape is invalid"
            }
            foreach ($field in @(
                "support_ipv4", "guest_ipv4", "guest_prefix_length", "guest_interface_index",
                "guest_interface_alias", "guest_interface_mtu_bytes", "guest_mac_address",
                "guest_route_prefix",
                "guest_route_next_hop"
            )) {
                if ([string]$actual.$field -cne [string]$ExpectedGuestNetworkPath.$field) {
                    throw "guest network path changed: field=$field"
                }
            }
            if ((@($actual.guest_dns_ipv4) -join "|") -cne
                (@($ExpectedGuestNetworkPath.guest_dns_ipv4) -join "|")) {
                throw "guest network path changed: field=guest_dns_ipv4"
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
        $harness = Join-Path $InputRoot "artifacts\m4-qualification.exe"
        $collectorHash = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToLowerInvariant()
        $plan = Get-Content -LiteralPath (Join-Path $InputRoot "plan.json") -Raw -Encoding utf8 |
            ConvertFrom-Json
        if ($plan.schema_version -ne 2 -or
            @($plan.trials).Count -ne 90 -or
            $plan.recipe_sha256 -cne $RecipeSha256 -or
            $plan.scenarios."network-lifecycle".recipe.network_model_controller_sha256 `
                -cne $NetworkModelControllerSha256 -or
            $plan.scenarios."network-lifecycle".recipe.network_model_plan_sha256 `
                -cne $NetworkModelPlanSha256) {
            throw "guest trial plan changed during staging"
        }
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

        foreach ($trial in @($plan.trials | Sort-Object sequence)) {
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
                Replace("{{SERVER_ADDRESS}}", $guestUnderlayAddress).
                Replace("{{SERVER_PORT}}", [string]$serverPort).
                Replace("{{METRICS_PORT}}", [string]$metricsPort)
            $serverText = (Get-Content -LiteralPath (Join-Path $InputRoot "server.toml.template") -Raw).
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
                    "-NetworkModelPlan", $networkModelPlan,
                    "-NetworkModelController", $networkModelController,
                    "-AdapterName", $AdapterName,
                    "-ClientPid", [string]$clientPid,
                    "-ServerPid", [string]$serverPid,
                    "-MetricsPort", [string]$metricsPort,
                    "-ServerMetricsPort", [string]$serverMetricsPort,
                    "-Output", $output
                )
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
        $files = @(Get-ChildItem -LiteralPath $EvidenceRoot -File -Filter "*.json")
        $networkModelFiles = @(
            Get-ChildItem -LiteralPath $NetworkModelEvidenceRoot -File `
                -Filter "*.network-model.json"
        )
        $processLogFiles = @(Get-ChildItem -LiteralPath $ProcessLogRoot -File -Filter "*.log")
        if ($files.Count -ne 90 -or $networkModelFiles.Count -ne 20 -or
            $processLogFiles.Count -ne 360) {
            throw "guest evidence set is incomplete"
        }
        [pscustomobject]@{
            status = "PASS"
            trials = $files.Count
            network_model_observations = $networkModelFiles.Count
            process_logs = $processLogFiles.Count
            evidence_path = $EvidenceRoot
            guest_build = "$($version.CurrentBuildNumber).$($version.UBR)"
            powershell_version = [string]$pwshVersion[0]
            powershell_executable_sha256 = $PowerShellExecutableSha256
        }
    }
    # END GUEST_ONLY_NETWORK_EXECUTION
    if (@($guestResult).Count -ne 1 -or $guestResult.status -cne "PASS" -or
        [int]$guestResult.trials -ne 90 -or
        [int]$guestResult.network_model_observations -ne 20 -or
        [int]$guestResult.process_logs -ne 360 -or
        [string]$guestResult.powershell_version -cne $portableRuntime.PowerShellVersion -or
        [string]$guestResult.powershell_executable_sha256 -cne
            $portableRuntime.PowerShellExecutableSha256) {
        throw "guest performance controller did not return a complete result"
    }
    $guestEvidenceAvailable = $true
} catch {
    $runFailure = $_
} finally {
    if ($null -ne $session) {
        $evidenceExportFailure = $null
        try {
            $guestEvidencePath = Join-Path $guestRoot "raw-evidence"
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
                        ModelFiles = @(
                            Get-ChildItem -LiteralPath (Join-Path $Path "network-model") `
                                -File -Filter "*.network-model.json" -ErrorAction Stop
                        ).Count
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
                [int]$boundary[0].Files -le 90 -and
                [int]$boundary[0].ModelFiles -le 20 -and
                [int]$boundary[0].TotalFiles -le 512 -and
                [long]$boundary[0].TotalBytes -le 536870912 -and
                [long]$boundary[0].LargestFileBytes -le 8388608) {
                # WinPS 5.1's Copy-Item remoting helper reads Length from the source
                # DirectoryInfo. The guest controller leaves this persistent runspace in
                # strict mode, which turns that helper implementation detail into an error.
                Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    Set-StrictMode -Off
                }
                Copy-Item -FromSession $session -LiteralPath $guestEvidencePath `
                    -Destination $hostEvidenceRoot -Recurse -ErrorAction Stop
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

$rawEvidence = Join-Path $hostEvidenceRoot "raw-evidence"
$rawNetworkModelEvidence = Join-Path $rawEvidence "network-model"
$rawProcessLogs = Join-Path $rawEvidence "process-logs"
if (-not (Test-Path -LiteralPath $hostNetworkPathPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $rawEvidence -PathType Container) -or
    @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json").Count -ne 90 -or
    -not (Test-Path -LiteralPath $rawNetworkModelEvidence -PathType Container) -or
    @(Get-ChildItem -LiteralPath $rawNetworkModelEvidence -File `
        -Filter "*.network-model.json").Count -ne 20 -or
    -not (Test-Path -LiteralPath $rawProcessLogs -PathType Container) -or
    @(Get-ChildItem -LiteralPath $rawProcessLogs -File -Filter "*.log").Count -ne 360) {
    throw "exported raw evidence is incomplete"
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
    raw_trials = @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json").Count
    raw_network_model_observations = @(
        Get-ChildItem -LiteralPath $rawNetworkModelEvidence -File `
            -Filter "*.network-model.json"
    ).Count
    process_logs = @(Get-ChildItem -LiteralPath $rawProcessLogs -File -Filter "*.log").Count
    host_network_path = $hostNetworkPathPath
    host_network_path_sha256 = (Get-FileHash -LiteralPath $hostNetworkPathPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    final_vm_state = [string](Get-ApprovedVmContext).Vm.State
    checkpoint_restored = $true
    host_tun_bypassed = $true
    host_network_mutations = 0
} | ConvertTo-Json -Depth 4
exit $summaryExit
