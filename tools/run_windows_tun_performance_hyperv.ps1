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

Run mode requires an already provisioned TCP/UDP echo listener reachable from the guest. Its
identity is recorded in each trial ledger. Ferrum2's candidate harness probes it from inside the
guest before any TUN session starts.

PlanOnly validates repository lineage and emits the closed 80-trial plan without building, starting
the VM, loading a credential, staging files, or executing traffic.
#>

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
    [ValidateRange(1, 65535)]
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
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..") -ErrorAction Stop).Path
$policyPath = Join-Path $PSScriptRoot "windows_tun_performance_policy.json"
$controlPath = Join-Path $PSScriptRoot "performance_candidate.py"
$collectorPath = Join-Path $PSScriptRoot "collect_windows_tun_performance_trial.ps1"
$utf8NoBom = [Text.UTF8Encoding]::new($false)

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
            $option = New-PSSessionOption -OperationTimeout 43200000
            $session = New-PSSession -VMId $script:approvedVmId -Credential $Credential `
                -SessionOption $option -ErrorAction Stop
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
    if ($plan.kind -cne "windows_tun_performance_plan" -or
        $plan.run_kind -cne $RunKindValue -or
        @($plan.trials).Count -ne 80) {
        throw "canonical Windows TUN plan shape is invalid"
    }
    return $plan
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
    param([string]$Rustup, [string]$Destination)
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

    $pwsh = (Get-Process -Id $PID -ErrorAction Stop).Path
    if ([IO.Path]::GetFileName($pwsh) -cne "pwsh.exe") {
        throw "the host runner must be PowerShell 7"
    }
    $pwshRoot = Split-Path -Parent $pwsh
    Assert-NoReparsePointInExistingPath -Path $pwshRoot -Label "portable PowerShell runtime"
    $pwshItems = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
        Get-ChildItem -LiteralPath $pwshRoot -Recurse -Force
    )
    if (@($pwshItems | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }).Count -ne 0) {
        throw "portable PowerShell runtime cannot contain a reparse point"
    }
    $pwshBytes = ($pwshItems | Where-Object { -not $_.PSIsContainer } |
        Measure-Object Length -Sum).Sum
    if ($pwshBytes -le 0 -or $pwshBytes -gt 1073741824) {
        throw "portable PowerShell runtime exceeds its staging boundary"
    }
    Copy-Item -LiteralPath $pwshRoot -Destination (Join-Path $Destination "pwsh") `
        -Recurse -ErrorAction Stop

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
}

$git = @(Get-Command git -CommandType Application -ErrorAction Stop)[0].Source
$python = @(Get-Command python -CommandType Application -ErrorAction Stop)[0].Source
foreach ($required in @($policyPath, $controlPath, $collectorPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required performance controller file is missing: $required"
    }
}
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
        [pscustomobject]@{
            schema = "ferrum2.windows-tun.hyperv-performance-plan.v1"
            run_kind = $RunKind
            parent_sha = $ParentSha
            candidate_sha = $CandidateSha
            parent_tree = $parentTree
            candidate_tree = $candidateTree
            trials = @($plan.trials).Count
            recipe_sha256 = [string]$plan.recipe_sha256
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            host_actions = @("archive exact commits", "build profiling binaries", "stage files", "reduce evidence")
            guest_actions = @("probe support", "run 80 collector trials", "clean each TUN session")
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
    Copy-Item -LiteralPath $resolvedWintunZip `
        -Destination (Join-Path $temporaryRoot "input\wintun-0.14.1.zip") -ErrorAction Stop
    Copy-Item -LiteralPath $hostPlanPath -Destination (Join-Path $temporaryRoot "input\plan.json") `
        -ErrorAction Stop
    Stage-PortableRuntime -Rustup $rustup -Destination $runtimeRoot

    $clientTemplate = @'
schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "{{ADAPTER_NAME}}"
ipv4_address = "198.18.0.2/30"
auto_route = true
route_address = ["{{SUPPORT_IPV4}}/32"]
ring_capacity = 131072
ready_timeout_ms = 30000
max_tcp_flows = 4096
tcp_buffer_bytes = 262144
max_udp_mappings = 8192
udp_filtering = "endpoint_independent"
outbound = "direct"
[[outbounds]]
tag = "direct"
type = "direct"
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
'@
    $serverTemplate = @'
schema_version = 2
[[inbounds]]
tag = "server-in"
listen = "127.0.0.1:{{SERVER_PORT}}"
outbound = "direct"
[[outbounds]]
tag = "direct"
type = "direct"
[udp]
enabled = true
max_sessions = 16384
max_buffered_bytes = 268435456
idle_timeout_ms = 60000
[runtime]
shutdown_grace_ms = 30000
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
'@
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\client.toml.template") `
        -Text ($clientTemplate.TrimStart([char[]]"`r`n") + "`n")
    Write-Utf8FileNew -Path (Join-Path $temporaryRoot "input\server.toml.template") `
        -Text ($serverTemplate.TrimStart([char[]]"`r`n") + "`n")

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

    # BEGIN GUEST_ONLY_NETWORK_EXECUTION
    $guestResult = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList @(
        $guestRoot,
        $approvedVmName,
        $approvedVmId.ToString("D"),
        $approvedCheckpointName,
        $approvedCheckpointId.ToString("D"),
        $expectedWintunZipSha256,
        $expectedWintunDllSha256,
        $RunKind,
        $ParentSha,
        $CandidateSha,
        $parentTree,
        $candidateTree,
        [string]$plan.recipe_sha256,
        $SupportIpv4,
        $SupportTcpPort,
        $SupportUdpPort,
        $SupportPid,
        $SupportOwner
    ) -ScriptBlock {
        param(
            [string]$Root,
            [string]$VmName,
            [string]$VmId,
            [string]$CheckpointName,
            [string]$CheckpointId,
            [string]$WintunZipSha256,
            [string]$WintunDllSha256,
            [string]$RunKindValue,
            [string]$ParentCommit,
            [string]$CandidateCommit,
            [string]$ParentTree,
            [string]$CandidateTree,
            [string]$RecipeSha256,
            [string]$SupportAddress,
            [int]$SupportTcp,
            [int]$SupportUdp,
            [int]$SupportProcessId,
            [string]$SupportProcessOwner
        )
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"
        $ProgressPreference = "SilentlyContinue"
        $Utf8NoBom = New-Object Text.UTF8Encoding($false)
        $InputRoot = Join-Path $Root "input"
        $EvidenceRoot = Join-Path $Root "raw-evidence"
        $AdapterName = "Ferrum2Perf"
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

        $RustRoot = Join-Path $InputRoot "runtime\rust"
        $PowerShell = Join-Path $InputRoot "runtime\pwsh\pwsh.exe"
        $env:PATH = "$RustRoot;$env:PATH"
        $rustVersion = @(& (Join-Path $RustRoot "rustc.exe") --version 2>&1)
        if ($LASTEXITCODE -ne 0 -or ($rustVersion -join "`n") -cnotmatch '^rustc 1\.97\.1 \(') {
            throw "staged Rust 1.97.1 runtime verification failed"
        }
        $pwshVersion = @(& $PowerShell -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
        if ($LASTEXITCODE -ne 0 -or [Version]$pwshVersion[0] -lt [Version]"7.4") {
            throw "staged PowerShell 7 runtime verification failed"
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
            Copy-Item -LiteralPath $runtimeDll.FullName `
                -Destination (Join-Path $InputRoot "artifacts") -ErrorAction Stop
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
    private const uint CreateNewProcessGroup = 0x00000200;
    private const int StartfUseShowWindow = 0x00000001;
    private static readonly Dictionary<uint, IntPtr> Handles = new Dictionary<uint, IntPtr>();
    private static readonly object Sync = new object();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars;
        public int yChars; public int fill; public int flags; public short show;
        public short reserved2; public IntPtr reservedBytes; public IntPtr stdin;
        public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr process; public IntPtr thread; public uint processId; public uint threadId;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
        IntPtr environment, string directory, ref StartupInfo startup,
        out ProcessInformation process);
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
    private static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);

    public static int Start(string application, string arguments, string directory) {
        var startup = new StartupInfo();
        startup.cb = Marshal.SizeOf(startup);
        startup.flags = StartfUseShowWindow;
        startup.show = 0;
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        ProcessInformation process;
        if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false,
            CreateNewConsole | CreateNewProcessGroup, IntPtr.Zero, directory,
            ref startup, out process)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
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
            if (!SetConsoleCtrlHandler(IntPtr.Zero, true)) return false;
            try {
                var sent = GenerateConsoleCtrlEvent(1, processId);
                Thread.Sleep(250);
                return sent;
            } finally {
                SetConsoleCtrlHandler(IntPtr.Zero, false);
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

        function Get-FreeTcpPort {
            $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
            try {
                $listener.Start()
                return [int]$listener.LocalEndpoint.Port
            } finally {
                $listener.Stop()
            }
        }
        function Get-FreeDualPort {
            foreach ($attempt in 1..100) {
                $port = Get-FreeTcpPort
                $udp = New-Object Net.Sockets.UdpClient
                try {
                    $udp.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, $port)))
                    return $port
                } catch {
                    if ($attempt -eq 100) { throw }
                } finally {
                    $udp.Dispose()
                }
            }
            throw "unable to reserve a dual TCP/UDP port"
        }
        function Wait-ProcessListener([int]$ProcessId, [int]$Port) {
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                if ([Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
                    throw "server exited before listener readiness"
                }
                $tcp = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
                    Where-Object { [int]$_.OwningProcess -eq $ProcessId })
                $udp = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue |
                    Where-Object { [int]$_.OwningProcess -eq $ProcessId })
                if ($tcp.Count -eq 1 -and $udp.Count -eq 1) { return }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            throw "server listener readiness timed out"
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
            if (-not [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 0)) {
                if (-not [Ferrum2PerfProcessGroup]::Break([uint32]$ProcessId) -or
                    -not [Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 60000)) {
                    [void][Ferrum2PerfProcessGroup]::Terminate([uint32]$ProcessId)
                    [void][Ferrum2PerfProcessGroup]::Wait([uint32]$ProcessId, 10000)
                    throw "$Label did not stop gracefully"
                }
            }
            $exit = [Ferrum2PerfProcessGroup]::ExitCode([uint32]$ProcessId)
            if ($exit -ne 0) { throw "$Label stopped with exit code $exit" }
            [Ferrum2PerfProcessGroup]::Close([uint32]$ProcessId)
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
        if (@($plan.trials).Count -ne 80 -or $plan.recipe_sha256 -cne $RecipeSha256) {
            throw "guest trial plan changed during staging"
        }
        & $harness "windows-tun-probe" "--target-ip" $SupportAddress `
            "--tcp-port" ([string]$SupportTcp) "--udp-port" ([string]$SupportUdp)
        if ($LASTEXITCODE -ne 0) { throw "guest support listener preflight failed" }

        foreach ($trial in @($plan.trials | Sort-Object sequence)) {
            if (Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction SilentlyContinue) {
                throw "managed performance adapter baseline is not absent"
            }
            $member = [string]$trial.member
            $memberRoot = Join-Path $InputRoot "artifacts\$member"
            $client = Join-Path $memberRoot "ferrum2-client.exe"
            $server = Join-Path $memberRoot "ferrum2-server.exe"
            $memberCommit = if ($member -ceq "parent") { $ParentCommit } else { $CandidateCommit }
            $memberTree = if ($member -ceq "parent") { $ParentTree } else { $CandidateTree }
            $trialRoot = Join-Path $Root ("trial-{0:D3}" -f [int]$trial.sequence)
            New-Item -ItemType Directory -Path $trialRoot | Out-Null
            $metricsPort = Get-FreeTcpPort
            $serverPort = Get-FreeDualPort
            $clientConfig = Join-Path $trialRoot "client.toml"
            $serverConfig = Join-Path $trialRoot "server.toml"
            $ledger = Join-Path $trialRoot "identity-ledger.json"
            $clientText = Get-Content -LiteralPath (Join-Path $InputRoot "client.toml.template") -Raw
            $clientText = $clientText.Replace("{{ADAPTER_NAME}}", $AdapterName).
                Replace("{{SUPPORT_IPV4}}", $SupportAddress).
                Replace("{{METRICS_PORT}}", [string]$metricsPort)
            $serverText = (Get-Content -LiteralPath (Join-Path $InputRoot "server.toml.template") -Raw).
                Replace("{{SERVER_PORT}}", [string]$serverPort)
            if ($clientText.Contains("{{") -or $serverText.Contains("{{")) {
                throw "configuration template substitution is incomplete"
            }
            [IO.File]::WriteAllText($clientConfig, $clientText, $Utf8NoBom)
            [IO.File]::WriteAllText($serverConfig, $serverText, $Utf8NoBom)
            $clientHash = (Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash.ToLowerInvariant()
            $serverHash = (Get-FileHash -LiteralPath $server -Algorithm SHA256).Hash.ToLowerInvariant()
            Write-CanonicalLedger $ledger $memberCommit $clientHash $serverHash $collectorHash

            & $client "--config" $clientConfig "--check-config"
            if ($LASTEXITCODE -ne 0) { throw "client performance configuration is invalid" }
            & $server "--config" $serverConfig "--check-config"
            if ($LASTEXITCODE -ne 0) { throw "server performance configuration is invalid" }

            $serverPid = 0
            $clientPid = 0
            $trialFailure = $null
            try {
                $serverPid = [Ferrum2PerfProcessGroup]::Start(
                    $server, "--config `"$serverConfig`"", $memberRoot
                )
                Wait-ProcessListener $serverPid $serverPort
                $clientPid = [Ferrum2PerfProcessGroup]::Start(
                    $client, "--config `"$clientConfig`"", $memberRoot
                )
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
                    "-ParentSha", $ParentCommit,
                    "-CandidateSha", $CandidateCommit,
                    "-Tree", $memberTree,
                    "-RecipeSha256", $RecipeSha256,
                    "-ClientBinary", $client,
                    "-ServerBinary", $server,
                    "-HarnessBinary", $harness,
                    "-IdentityLedger", $ledger,
                    "-ClientPid", [string]$clientPid,
                    "-ServerPid", [string]$serverPid,
                    "-MetricsPort", [string]$metricsPort,
                    "-Output", $output
                )
                & $PowerShell @collectorArguments
                if ($LASTEXITCODE -ne 0 -or
                    -not (Test-Path -LiteralPath $output -PathType Leaf) -or
                    (Get-Item -LiteralPath $output).Length -gt 1048576) {
                    throw "Windows TUN collector trial failed: sequence=$($trial.sequence)"
                }
            } catch {
                $trialFailure = $_
            } finally {
                $stopFailures = New-Object Collections.Generic.List[string]
                if ($clientPid -gt 0) {
                    try { Stop-OwnedProcess $clientPid "client" } catch { $stopFailures.Add($_.Exception.Message) }
                }
                try { Wait-AdapterAbsent } catch { $stopFailures.Add($_.Exception.Message) }
                if ($serverPid -gt 0) {
                    try { Stop-OwnedProcess $serverPid "server" } catch { $stopFailures.Add($_.Exception.Message) }
                }
                if ($stopFailures.Count -ne 0 -and $null -eq $trialFailure) {
                    $trialFailure = [Management.Automation.ErrorRecord]::new(
                        [InvalidOperationException]::new(($stopFailures -join "; ")),
                        "Ferrum2PerformanceCleanup",
                        [Management.Automation.ErrorCategory]::OperationStopped,
                        $trialRoot
                    )
                }
            }
            if ($null -ne $trialFailure) { throw $trialFailure }
        }
        $files = @(Get-ChildItem -LiteralPath $EvidenceRoot -File -Filter "*.json")
        if ($files.Count -ne 80) { throw "guest evidence set is incomplete" }
        [pscustomobject]@{
            status = "PASS"
            trials = $files.Count
            evidence_path = $EvidenceRoot
            guest_build = "$($version.CurrentBuildNumber).$($version.UBR)"
        }
    }
    # END GUEST_ONLY_NETWORK_EXECUTION
    if (@($guestResult).Count -ne 1 -or $guestResult.status -cne "PASS" -or
        [int]$guestResult.trials -ne 80) {
        throw "guest performance controller did not return a complete result"
    }
    $guestEvidenceAvailable = $true
} catch {
    $runFailure = $_
} finally {
    if ($null -ne $session) {
        try {
            $guestEvidencePath = Join-Path $guestRoot "raw-evidence"
            $boundary = @(Invoke-Command -Session $session -ArgumentList $guestEvidencePath `
                -ErrorAction Stop -ScriptBlock {
                    param([string]$Path)
                    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
                        return [pscustomobject]@{ Safe = $false; Files = 0 }
                    }
                    $items = @(Get-Item -LiteralPath $Path -Force) + @(
                        Get-ChildItem -LiteralPath $Path -Force -Recurse
                    )
                    [pscustomobject]@{
                        Safe = @($items | Where-Object {
                            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                        }).Count -eq 0
                        Files = @(Get-ChildItem -LiteralPath $Path -File -Filter "*.json").Count
                    }
                })
            if ($boundary.Count -eq 1 -and $boundary[0].Safe -eq $true) {
                Copy-Item -FromSession $session -LiteralPath $guestEvidencePath `
                    -Destination $hostEvidenceRoot -Recurse -ErrorAction Stop
            }
        } catch {
            if ($null -eq $runFailure) { $runFailure = $_ }
        }
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        $session = $null
    }
    if ($vmWindowStarted) {
        try {
            Stop-ApprovedVm -TimeoutSeconds $ShutdownTimeoutSeconds
            Restore-ApprovedCheckpoint
            if ([string](Get-ApprovedVmContext).Vm.State -cne "Off") {
                throw "approved VM final state is not Off"
            }
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
if (-not (Test-Path -LiteralPath $rawEvidence -PathType Container) -or
    @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json").Count -ne 80) {
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
    schema = "ferrum2.windows-tun.hyperv-performance-result.v1"
    status = [string]$summary.status
    reducer_exit_code = $summaryExit
    evidence_directory = $hostEvidenceRoot
    raw_trials = @(Get-ChildItem -LiteralPath $rawEvidence -File -Filter "*.json").Count
    final_vm_state = [string](Get-ApprovedVmContext).Vm.State
    checkpoint_restored = $true
    host_network_mutations = 0
} | ConvertTo-Json -Depth 4
exit $summaryExit
