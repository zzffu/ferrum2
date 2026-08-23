#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs the Windows TUN qualification controller only inside the approved Hyper-V guest.

.DESCRIPTION
The host side builds the exact clean candidate with Rust 1.97.1 and locked dependencies, then limits
itself to exact-identity VM lifecycle operations, PowerShell Direct, bounded file staging, and
evidence export. It stages precompiled client/server/test executables, a portable PowerShell runtime,
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
    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [switch]$ProbeOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidateSet(
        "route-detect",
        "restart-10",
        "restart-100",
        "restart-1000",
        "fragments",
        "dual-stack-dns",
        "udp-policy",
        "scheduler-ring-full"
    )]
    [string]$Profile,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

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

$approvedVmName = "Windows 10 MSIX packaging environment"
$approvedVmId = [Guid]"82e20295-1d30-48e7-a751-e21d35d872d4"
$approvedCheckpointName = "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9"
$approvedCheckpointId = [Guid]"1e570209-faf7-4248-8167-aa0687cdb8cf"
$expectedWintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$expectedWintunDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path

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
        [string]::IsNullOrWhiteSpace($credential.UserName)) {
        throw "guest credential file does not contain a PSCredential"
    }
    return $credential
}

function Get-ApprovedVmContext {
    $vm = Get-VM -Id $script:approvedVmId -ErrorAction Stop
    if ($vm.Name -cne $script:approvedVmName) {
        throw "approved VM identity mismatch"
    }
    $namedVm = @(Get-VM -Name $script:approvedVmName -ErrorAction Stop)
    if ($namedVm.Count -ne 1 -or $namedVm[0].Id -ne $script:approvedVmId) {
        throw "approved VM name does not resolve to the approved ID"
    }

    $checkpoint = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
        $_.Id -eq $script:approvedCheckpointId
    })
    if ($checkpoint.Count -ne 1 -or $checkpoint[0].Name -cne $script:approvedCheckpointName) {
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

function Start-ApprovedVm {
    $context = Get-ApprovedVmContext
    if ([string]$context.Vm.State -cne "Off") {
        throw "approved VM must be Off before start"
    }
    $context.Vm | Start-VM -ErrorAction Stop | Out-Null
    $started = Get-ApprovedVmContext
    if ([string]$started.Vm.State -cne "Running") {
        throw "approved VM did not enter Running state"
    }
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
        if ([string]$context.Vm.State -ceq "Off") {
            return
        }
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
        [string]$ControllerPath
    )

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
    $ledger = $json | ConvertFrom-Json -Depth 4 -ErrorAction Stop
    $baseKeys = @(
        "schema", "vm_name", "vm_id", "checkpoint_name", "checkpoint_id",
        "guest_product", "guest_edition", "guest_architecture", "guest_version", "guest_build",
        "candidate_sha", "probe_sha256", "client_sha256", "server_sha256", "support_listener"
    )
    $actualKeys = @($ledger.PSObject.Properties.Name)
    $expectedKeys = @($baseKeys + "test_binaries")
    if (($actualKeys -join "|") -cne ($expectedKeys -join "|") -or
        ($ledger | ConvertTo-Json -Compress -Depth 4) -cne $json) {
        throw "identity ledger is not canonical or has an invalid property set"
    }
    if ($ledger.schema -isnot [long] -or $ledger.schema -ne 1 -or
        $ledger.vm_name -cne $script:approvedVmName -or
        $ledger.vm_id -cne $script:approvedVmId.ToString("D") -or
        $ledger.checkpoint_name -cne $script:approvedCheckpointName -or
        $ledger.checkpoint_id -cne $script:approvedCheckpointId.ToString("D") -or
        $ledger.guest_architecture -cne "AMD64" -or
        $ledger.candidate_sha -cne $CandidateSha) {
        throw "identity ledger does not bind the approved guest and candidate"
    }
    foreach ($name in @("probe_sha256", "client_sha256", "server_sha256")) {
        if ([string]$ledger.$name -cnotmatch '^[0-9a-f]{64}$') {
            throw "identity ledger contains an invalid binary hash"
        }
    }
    $supportKeys = @("ipv4", "tcp_port", "udp_port", "pid", "owner")
    if ((@($ledger.support_listener.PSObject.Properties.Name) -join "|") -cne
        ($supportKeys -join "|")) {
        throw "identity ledger support listener shape is invalid"
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
        RustVersion = $versionLines[0]
    }
}

function New-PortablePowerShellArchive {
    param([Parameter(Mandatory = $true)][string]$Destination)

    $pwsh = (Get-Process -Id $PID -ErrorAction Stop).Path
    if ([IO.Path]::GetFileName($pwsh) -cne "pwsh.exe" -or
        $PSVersionTable.PSVersion -lt [Version]"7.4") {
        throw "the host runner requires PowerShell 7.4 or newer"
    }
    $root = Split-Path -Parent $pwsh
    Assert-NoReparsePointInExistingPath -Path $root -Label "portable PowerShell runtime"
    $items = @(Get-Item -LiteralPath $root -Force) + @(
        Get-ChildItem -LiteralPath $root -Force -Recurse
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

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $root,
        $Destination,
        [IO.Compression.CompressionLevel]::Optimal,
        $false
    )
    $archive = Resolve-BoundedFile `
        -Path $Destination `
        -Label "portable PowerShell archive" `
        -MaximumBytes 1073741824
    return [pscustomobject]@{
        Path = $archive
        Name = [IO.Path]::GetFileName($archive)
        Bytes = [long](Get-Item -LiteralPath $archive -Force).Length
        Sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        ExecutableSha256 = (Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash.ToLowerInvariant()
        Version = $PSVersionTable.PSVersion.ToString()
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
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
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
        if ($relative -ceq "host-orchestration.json") {
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

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the Hyper-V host orchestrator requires 64-bit Windows AMD64"
}
if (-not $ProbeOnly -and $Profile -ceq "route-detect") {
    throw "route-detect qualification is unsupported after removal of external route-conflict detection"
}

# Resolve both exact identities and the DPAPI credential before any VM lifecycle operation.
$initialContext = Get-ApprovedVmContext
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

if ($ProbeOnly) {
    $initialState = [string]$initialContext.Vm.State
    if ($initialState -notin @("Off", "Running")) {
        throw "ProbeOnly requires the approved VM to be Off or Running"
    }

    $probeStartedVm = $false
    $connection = $null
    $probeFailure = $null
    $probeCleanupFailure = $null
    try {
        if ($initialState -ceq "Off") {
            $probeStartedVm = $true
            Start-ApprovedVm
        }
        $connection = Connect-ApprovedGuest `
            -Credential $guestCredential `
            -TimeoutSeconds $ReadinessTimeoutSeconds
    } catch {
        $probeFailure = $_
    } finally {
        if ($null -ne $connection) {
            Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
        }
        if ($probeStartedVm) {
            try {
                Stop-ApprovedVm -TimeoutSeconds $ShutdownTimeoutSeconds
            } catch {
                $probeCleanupFailure = $_
            }
        }
    }

    if ($null -ne $probeFailure -or $null -ne $probeCleanupFailure) {
        $messages = [Collections.Generic.List[string]]::new()
        if ($null -ne $probeFailure) {
            $messages.Add("probe failed: $($probeFailure.Exception.Message)")
        }
        if ($null -ne $probeCleanupFailure) {
            $messages.Add("probe power-state cleanup failed: $($probeCleanupFailure.Exception.Message)")
        }
        throw [InvalidOperationException]::new(($messages -join "; "))
    }

    [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-probe.v1"
        status = "pass"
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        initial_vm_state = $initialState.ToLowerInvariant()
        final_vm_state = [string](Get-ApprovedVmContext).Vm.State
        guest_product = [string]$connection.Probe.Product
        guest_edition = [string]$connection.Probe.Edition
        guest_version = [string]$connection.Probe.Version
        guest_build = [string]$connection.Probe.Build
        guest_architecture = [string]$connection.Probe.Architecture
        powershell_version = [string]$connection.Probe.PowerShellVersion
        checkpoint_restored = $false
        files_staged = $false
        controller_invoked = $false
    } | ConvertTo-Json -Compress
    return
}

$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\qualify_windows_tun.ps1") `
    -Label "qualification controller" `
    -MaximumBytes 4194304
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
$wintunHash = (Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($wintunHash -cne $expectedWintunZipSha256) {
    throw "Wintun archive hash mismatch"
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

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("ferrum2-hyperv-" + [Guid]::NewGuid().ToString("N"))
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$hostArtifactRoot = Join-Path $temporaryRoot "artifacts"
$hostRuntimeLibraryRoot = Join-Path $temporaryRoot "vc-runtime"
$hostPowerShellArchive = Join-Path $temporaryRoot "portable-pwsh.zip"
$stagedInputManifestPath = Join-Path $temporaryRoot "staged-input.json"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$guestResult = $null
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null

try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )
    $candidateArtifacts = Build-CandidateArtifacts `
        -Destination $hostArtifactRoot `
        -Ledger $ledgerIdentity.Ledger
    $portablePowerShell = New-PortablePowerShellArchive -Destination $hostPowerShellArchive
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun.ps1" `
        -MaximumBytes 4194304
    $identityEntry = New-StagedFileEntry `
        -Path $ledgerIdentity.Path `
        -Name "identity-ledger.json" `
        -MaximumBytes 65536
    $wintunEntry = New-StagedFileEntry `
        -Path $wintunPath `
        -Name "wintun-0.14.1.zip" `
        -MaximumBytes 16777216
    $vcEntries = @($runtimeLibraries | ForEach-Object {
        New-StagedFileEntry -Path $_.Path -Name $_.Name -MaximumBytes 16777216
    })
    if ($controllerEntry.sha256 -cne [string]$ledgerIdentity.Ledger.probe_sha256 -or
        $identityEntry.sha256 -cne $ledgerIdentity.Sha256 -or
        $wintunEntry.sha256 -cne $expectedWintunZipSha256) {
        throw "host staged input identity changed after preflight"
    }
    $postBuildCandidate = Get-CandidateIdentity
    if ($postBuildCandidate.Sha -cne $candidate.Sha) {
        throw "candidate commit changed during host artifact preparation"
    }
    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hyperv-staged-input.v1"
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        files = [ordered]@{
            controller = $controllerEntry
            identity_ledger = $identityEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry -Path $candidateArtifacts.Client.Path -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry -Path $candidateArtifacts.Server.Path -Name "ferrum2-server.exe")
            client_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.client.Path -Name "ferrum2-client-tests.exe")
            tun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.tun.Path -Name "ferrum2-tun-tests.exe")
            wintun_tests = $(New-StagedFileEntry -Path $candidateArtifacts.Tests.wintun.Path -Name "ferrum2-wintun-tests.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 1073741824)
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

    # From this point onward every exit path must leave the exact approved checkpoint restored Off.
    $restoreRequired = $true
    Restore-ApprovedCheckpoint
    Start-ApprovedVm
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
        [ordered]@{ Source = $wintunPath; Destination = $(Join-Path $guestInputPath "wintun-0.14.1.zip") },
        [ordered]@{ Source = $stagedInputManifestPath; Destination = $(Join-Path $guestInputPath "staged-input.json") },
        [ordered]@{ Source = $portablePowerShell.Path; Destination = $(Join-Path $guestInputPath "portable-pwsh.zip") },
        [ordered]@{ Source = $candidateArtifacts.Client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client.exe") },
        [ordered]@{ Source = $candidateArtifacts.Server.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-server.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.client.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-client-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.tun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-tun-tests.exe") },
        [ordered]@{ Source = $candidateArtifacts.Tests.wintun.Path; Destination = $(Join-Path $guestInputPath "artifacts\ferrum2-wintun-tests.exe") }
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

    # BEGIN GUEST_ONLY_NETWORK_EXECUTION
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
            $stagedInputSha256
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
                [string]$ExpectedInputManifestHash
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
            $wintunPath = Join-Path $inputPath "wintun-0.14.1.zip"
            $inputManifestPath = Join-Path $inputPath "staged-input.json"
            $powerShellArchive = Join-Path $inputPath "portable-pwsh.zip"
            $candidateTestDirectory = Join-Path $inputPath "artifacts"
            $runtimeLibraryDirectory = Join-Path $inputPath "runtime\vc-runtime"
            $clientBinary = Join-Path $candidateTestDirectory "ferrum2-client.exe"
            $serverBinary = Join-Path $candidateTestDirectory "ferrum2-server.exe"
            New-Item -ItemType Directory -Path $artifactPath -ErrorAction Stop | Out-Null

            $mode = $RequestedProfile
            $restartCycles = 10
            if ($RequestedProfile -cmatch '^restart-(10|100|1000)$') {
                $restartCycles = [int]$Matches[1]
                $mode = "restart-stress"
            }
            $allowedModes = @(
                "restart-stress", "fragments", "dual-stack-dns", "udp-policy",
                "scheduler-ring-full"
            )
            if ($mode -notin $allowedModes) {
                throw "guest profile dispatch rejected"
            }

            $phase = "input"
            $qualificationExit = $null
            $cleanupExit = $null
            $controllerStarted = $false
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
                    $inputFiles.Count -lt 11 -or $inputFiles.Count -gt 13 -or
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
                    "schema", "candidate_sha", "identity_sha256", "files", "runtime"
                ) "staged input manifest"
                Assert-ClosedProperties $manifest.files @(
                    "controller", "identity_ledger", "wintun_zip", "client", "server",
                    "client_tests", "tun_tests", "wintun_tests", "powershell_archive"
                ) "staged input file manifest"
                Assert-ClosedProperties $manifest.runtime @(
                    "rust_version", "powershell_version", "powershell_executable_sha256",
                    "powershell_file_count", "powershell_expanded_bytes", "vc_libraries"
                ) "staged runtime manifest"
                if ($manifest.schema -cne "ferrum2.windows-tun.hyperv-staged-input.v1" -or
                    $manifest.candidate_sha -cne $CandidateSha -or
                    $manifest.identity_sha256 -cne $ExpectedLedgerHash -or
                    [string]$manifest.runtime.rust_version -cnotmatch '^rustc 1\.97\.1 \(' -or
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
                    @($wintunPath, $manifest.files.wintun_zip, "wintun-0.14.1.zip", 1, 16777216),
                    @($clientBinary, $manifest.files.client, "ferrum2-client.exe", 4096, 536870912),
                    @($serverBinary, $manifest.files.server, "ferrum2-server.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-client-tests.exe"), $manifest.files.client_tests, "ferrum2-client-tests.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-tun-tests.exe"), $manifest.files.tun_tests, "ferrum2-tun-tests.exe", 4096, 536870912),
                    @((Join-Path $candidateTestDirectory "ferrum2-wintun-tests.exe"), $manifest.files.wintun_tests, "ferrum2-wintun-tests.exe", 4096, 536870912),
                    @($powerShellArchive, $manifest.files.powershell_archive, "portable-pwsh.zip", 1, 1073741824)
                )
                foreach ($check in $fileChecks) {
                    Assert-StagedFileIdentity $check[0] $check[1] $check[2] $check[3] $check[4]
                }
                if ([string]$manifest.files.identity_ledger.sha256 -cne $ExpectedLedgerHash -or
                    [string]$manifest.files.wintun_zip.sha256 -cne $ExpectedWintunHash) {
                    throw "guest identity ledger or Wintun archive hash mismatch"
                }
                $ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -ErrorAction Stop
                if ($ledger.candidate_sha -cne $CandidateSha -or
                    $ledger.probe_sha256 -cne [string]$manifest.files.controller.sha256 -or
                    $ledger.client_sha256 -cne [string]$manifest.files.client.sha256 -or
                    $ledger.server_sha256 -cne [string]$manifest.files.server.sha256 -or
                    $ledger.test_binaries.client -cne [string]$manifest.files.client_tests.sha256 -or
                    $ledger.test_binaries.tun -cne [string]$manifest.files.tun_tests.sha256 -or
                    $ledger.test_binaries.wintun -cne [string]$manifest.files.wintun_tests.sha256) {
                    throw "guest candidate ledger binding failed"
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
                    $wintunPath,
                    $inputManifestPath,
                    $powerShellArchive,
                    $clientBinary,
                    $serverBinary,
                    (Join-Path $candidateTestDirectory "ferrum2-client-tests.exe"),
                    (Join-Path $candidateTestDirectory "ferrum2-tun-tests.exe"),
                    (Join-Path $candidateTestDirectory "ferrum2-wintun-tests.exe")
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
                    [Version]$pwshVersion[0] -lt [Version]"7.4") {
                    throw "staged PowerShell runtime verification failed"
                }
                [IO.File]::WriteAllText(
                    $setupStdout,
                    "host_built_artifacts=verified`npowershell_version=$($pwshVersion[0])`n",
                    [Text.UTF8Encoding]::new($false)
                )

                $phase = "qualification"
                $controllerArguments = @(
                    "-NoProfile", "-File", $controllerPath,
                    "-Mode", $mode,
                    "-RunToken", $Token,
                    "-IdentityLedger", $ledgerPath,
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
                }
                $controllerStarted = $true
                $qualificationExit = Invoke-LoggedCommand `
                    -Executable $pwsh `
                    -Arguments $controllerArguments `
                    -StdoutPath $controllerStdout `
                    -StderrPath $controllerStderr
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
                if ($null -eq $failurePhase -and $qualificationExit -eq 0 -and $cleanupExit -eq 0) {
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
                    $expectedCycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
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
                    $restartCyclesMatch = if ($null -eq $expectedCycles) {
                        $null -eq $contract.restart_cycles -and $null -eq $result.restart_cycles
                    } else {
                        (Test-JsonInteger $contract.restart_cycles) -and
                        (Test-JsonInteger $result.restart_cycles) -and
                        [long]$contract.restart_cycles -eq $expectedCycles -and
                        [long]$result.restart_cycles -eq $expectedCycles
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
                    $witnessesMatch = $contractWitnesses.Count -gt 0 -and
                        ($contractWitnesses -join "|") -ceq ($resultWitnessNames -join "|")
                    $deterministicTests = @($result.deterministic_tests)
                    $expectedTestCount = switch ($mode) {
                        "restart-stress" { 4 }
                        "fragments" { 9 }
                        "dual-stack-dns" { 2 }
                        "udp-policy" { 9 }
                        "scheduler-ring-full" { 8 }
                        default { throw "M17 result mode has no closed exact-test count" }
                    }
                    $testsPassed = $deterministicTests.Count -eq $expectedTestCount -and
                        @($deterministicTests | Where-Object { $_.status -cne "pass" }).Count -eq 0
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
                    if ($contract.schema -ceq "ferrum2.windows-tun.m17-contract.v1" -and
                        $contract.status -ceq "preflight_pass" -and $contract.mode -ceq $mode -and
                        $contract.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $contract.guest_build -ceq $ledger.guest_build -and
                        $result.schema -ceq "ferrum2.windows-tun.m17-result.v1" -and
                        $result.status -ceq "pass" -and $result.mode -ceq $mode -and
                        $result.run_token -ceq $Token -and
                        $result.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $result.guest_build -ceq $ledger.guest_build -and
                        $null -eq $result.failure -and $restartCyclesMatch -and
                        $identityMatches -and $binaryHashesMatch -and $testHashesMatch -and
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
                $failurePhase = if ($qualificationExit -ne 0) { "qualification" } else { "cleanup" }
            }

            $guestResult = [ordered]@{
                schema = "ferrum2.windows-tun.hyperv-guest-run.v2"
                status = $status
                profile = $RequestedProfile
                mode = $mode
                restart_cycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
                run_token = $Token
                candidate_sha = $CandidateSha
                identity_sha256 = $ExpectedLedgerHash
                staged_input_sha256 = $ExpectedInputManifestHash
                qualification_exit = if ($null -eq $qualificationExit) { $null } else { [long]$qualificationExit }
                cleanup_exit = if ($null -eq $cleanupExit) { $null } else { [long]$cleanupExit }
                failure_phase = $failurePhase
                finished_utc = [DateTime]::UtcNow.ToString("o")
            }
            Write-GuestJsonNew -Path (Join-Path $exportPath "guest-run.json") -Value $guestResult
            [pscustomobject]$guestResult
        })
    # END GUEST_ONLY_NETWORK_EXECUTION
    if ($guestResults.Count -ne 1) {
        throw "guest execution did not return one result"
    }
    $guestResult = $guestResults[0]
    $expectedGuestMode = if ($Profile -cmatch '^restart-(10|100|1000)$') {
        "restart-stress"
    } else {
        $Profile
    }
    $expectedRestartCycles = if ($expectedGuestMode -ceq "restart-stress") {
        [long]($Profile.Substring("restart-".Length))
    } else {
        $null
    }
    if ($guestResult.schema -cne "ferrum2.windows-tun.hyperv-guest-run.v2" -or
        $guestResult.profile -cne $Profile -or
        $guestResult.mode -cne $expectedGuestMode -or
        $guestResult.run_token -cne $RunToken -or
        $guestResult.candidate_sha -cne $candidate.Sha -or
        $guestResult.identity_sha256 -cne $ledgerIdentity.Sha256 -or
        $guestResult.staged_input_sha256 -cne $stagedInputSha256 -or
        [long]$guestResult.qualification_exit -ne 0 -or
        [long]$guestResult.cleanup_exit -ne 0 -or
        $null -ne $guestResult.failure_phase -or
        ($null -eq $expectedRestartCycles -and $null -ne $guestResult.restart_cycles) -or
        ($null -ne $expectedRestartCycles -and
            [long]$guestResult.restart_cycles -ne $expectedRestartCycles)) {
        throw "guest qualification result binding is invalid"
    }
    if ($guestResult.status -cne "pass") {
        throw "guest qualification failed in phase $($guestResult.failure_phase)"
    }
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
    if ($null -ne $connection) {
        Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
    }

    if ($restoreRequired) {
        try {
            Stop-ApprovedVm -TimeoutSeconds $ShutdownTimeoutSeconds
            Restore-ApprovedCheckpoint
        } catch {
            $finalizationFailures.Add("mandatory final checkpoint restore failed: $($_.Exception.Message)")
        }
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
    }
} catch {
    $finalizationFailures.Add("approved VM final state readback failed: $($_.Exception.Message)")
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) { "pass" } else { "fail" }
if (Test-Path -LiteralPath $hostEvidencePath -PathType Container) {
    try {
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-host-run.v2"
            status = $status
            profile = $Profile
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            staged_input_sha256 = $stagedInputSha256
            rust_version = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.RustVersion }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = if ($null -eq $guestResult) { $null } else { [string]$connection.Probe.Build }
            started_utc = $startedUtc
            finished_utc = [DateTime]::UtcNow.ToString("o")
            final_vm_state = $finalVmState
            evidence_files = @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath)
        }
        Write-JsonFileNew -Path (Join-Path $hostEvidencePath "host-orchestration.json") -Value $manifest
    } catch {
        $finalizationFailures.Add("host evidence manifest failed: $($_.Exception.Message)")
        $status = "fail"
    }
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
