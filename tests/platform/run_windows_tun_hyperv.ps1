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
        schema = "ferrum2.windows-tun.hyperv-staged-input.v2"
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        profile = $Profile
        mode = $requestedMode
        network_reset_cycles = $requestedNetworkResetCycles
        restart_cycles = $requestedRestartCycles
        files = [ordered]@{
            controller = $controllerEntry
            identity_ledger = $identityEntry
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
                    $inputFiles.Count -lt 12 -or $inputFiles.Count -gt 14 -or
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
                    "schema", "candidate_sha", "identity_sha256", "profile", "mode",
                    "network_reset_cycles", "restart_cycles", "files", "runtime"
                ) "staged input manifest"
                Assert-ClosedProperties $manifest.files @(
                    "controller", "identity_ledger", "wintun_zip", "client", "server",
                    "client_tests", "tun_tests", "wintun_tests", "fuzz_smoke", "powershell_archive"
                ) "staged input file manifest"
                Assert-ClosedProperties $manifest.runtime @(
                    "rust_version", "powershell_version", "powershell_executable_sha256",
                    "powershell_file_count", "powershell_expanded_bytes", "vc_libraries"
                ) "staged runtime manifest"
                if ($manifest.schema -cne "ferrum2.windows-tun.hyperv-staged-input.v2" -or
                    $manifest.candidate_sha -cne $CandidateSha -or
                    $manifest.identity_sha256 -cne $ExpectedLedgerHash -or
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
                    @($fuzzSmokeBinary, $manifest.files.fuzz_smoke, "ferrum2-tun-fuzz-smoke.exe", 4096, 536870912),
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
                    [Version]$pwshVersion[0] -lt [Version]"7.4") {
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
                    $expectedFuzzTerminal = "TUN state smoke corpora: 4 packet and 3 UDP reset seeds passed"
                    if ($qualificationExit -ne 0 -or $fuzzStdoutLines.Count -ne 1 -or
                        [string]$fuzzStdoutLines[0] -cne $expectedFuzzTerminal -or
                        $fuzzStderrItem.Length -ne 0) {
                        throw "guest Windows TUN fuzz smoke evidence is invalid"
                    }
                    $fuzzSmokeResult = [ordered]@{
                        schema = "ferrum2.windows-tun.fuzz-smoke-result.v1"
                        status = "pass"
                        run_token = $Token
                        candidate_sha = $CandidateSha
                        identity_sha256 = $ExpectedLedgerHash
                        staged_input_sha256 = $ExpectedInputManifestHash
                        binary_sha256 = [string]$manifest.files.fuzz_smoke.sha256
                        binary_bytes = [long]$manifest.files.fuzz_smoke.bytes
                        packet_seed_count = 4
                        udp_reset_seed_count = 3
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
                        "terminal", "stdout_sha256", "stderr_sha256", "finished_utc"
                    ) "fuzz smoke result"
                    if ($fuzzSmokeResult.schema -cne "ferrum2.windows-tun.fuzz-smoke-result.v1" -or
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
                        "wintun_dll_sha256", "test_binaries", "fixtures", "witnesses", "counters"
                    ) "M17 contract"
                    Assert-ClosedProperties $result @(
                        "schema", "status", "mode", "run_token", "network_reset_cycles", "restart_cycles",
                        "approved_vm_name", "approved_vm_id", "approved_checkpoint_name",
                        "approved_checkpoint_id", "guest_build", "identity_sha256", "candidate_sha",
                        "client_sha256", "server_sha256", "controller_sha256", "wintun_zip_sha256",
                        "wintun_dll_sha256", "test_binaries", "started_utc", "finished_utc", "fixtures",
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
                    if ($contract.schema -ceq "ferrum2.windows-tun.m17-contract.v1" -and
                        $contract.status -ceq "preflight_pass" -and $contract.mode -ceq $mode -and
                        $contract.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $contract.guest_build -ceq $ledger.guest_build -and
                        $result.schema -ceq "ferrum2.windows-tun.m17-result.v1" -and
                        $result.status -ceq "pass" -and $result.mode -ceq $mode -and
                        $result.run_token -ceq $Token -and
                        $result.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $result.guest_build -ceq $ledger.guest_build -and
                        $null -eq $result.failure -and $restartCyclesMatch -and $networkResetCyclesMatch -and
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
                $failurePhase = if ($mode -ceq "fuzz-smoke") {
                    "fuzz-smoke"
                } elseif ($qualificationExit -ne 0) {
                    "qualification"
                } else {
                    "cleanup"
                }
            }

            $guestResult = [ordered]@{
                schema = "ferrum2.windows-tun.hyperv-guest-run.v3"
                status = $status
                profile = $RequestedProfile
                mode = $mode
                restart_cycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
                network_reset_cycles = if ($mode -ceq "network-reset") { [long]$networkResetCycles } else { $null }
                run_token = $Token
                candidate_sha = $CandidateSha
                identity_sha256 = $ExpectedLedgerHash
                staged_input_sha256 = $ExpectedInputManifestHash
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
        "qualification_exit", "cleanup_exit", "fuzz_smoke", "failure_phase", "finished_utc"
    )
    if ((@($guestResult.PSObject.Properties.Name) -join "|") -cne ($guestResultKeys -join "|")) {
        throw "guest qualification result property set is invalid"
    }
    $fuzzSmokeMatches = if ($expectedGuestMode -ceq "fuzz-smoke") {
        $fuzzResultKeys = @(
            "schema", "status", "run_token", "candidate_sha", "identity_sha256", "staged_input_sha256",
            "binary_sha256", "binary_bytes", "packet_seed_count", "udp_reset_seed_count",
            "terminal", "stdout_sha256", "stderr_sha256", "finished_utc"
        )
        $null -ne $guestResult.fuzz_smoke -and
            (@($guestResult.fuzz_smoke.PSObject.Properties.Name) -join "|") -ceq ($fuzzResultKeys -join "|") -and
            $guestResult.fuzz_smoke.schema -ceq "ferrum2.windows-tun.fuzz-smoke-result.v1" -and
            $guestResult.fuzz_smoke.status -ceq "pass" -and
            $guestResult.fuzz_smoke.run_token -ceq $RunToken -and
            $guestResult.fuzz_smoke.candidate_sha -ceq $candidate.Sha -and
            $guestResult.fuzz_smoke.identity_sha256 -ceq $ledgerIdentity.Sha256 -and
            $guestResult.fuzz_smoke.staged_input_sha256 -ceq $stagedInputSha256 -and
            $guestResult.fuzz_smoke.binary_sha256 -ceq $candidateArtifacts.FuzzSmoke.Sha256 -and
            [long]$guestResult.fuzz_smoke.binary_bytes -eq [long]$candidateArtifacts.FuzzSmoke.Bytes -and
            [long]$guestResult.fuzz_smoke.packet_seed_count -eq 4 -and
            [long]$guestResult.fuzz_smoke.udp_reset_seed_count -eq 3 -and
            $guestResult.fuzz_smoke.terminal -ceq "TUN state smoke corpora: 4 packet and 3 UDP reset seeds passed" -and
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
    if ($guestResult.schema -cne "ferrum2.windows-tun.hyperv-guest-run.v3" -or
        $guestResult.profile -cne $Profile -or
        $guestResult.mode -cne $expectedGuestMode -or
        $guestResult.run_token -cne $RunToken -or
        $guestResult.candidate_sha -cne $candidate.Sha -or
        $guestResult.identity_sha256 -cne $ledgerIdentity.Sha256 -or
        $guestResult.staged_input_sha256 -cne $stagedInputSha256 -or
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
            schema = "ferrum2.windows-tun.hyperv-host-run.v3"
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
            rust_version = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.RustVersion }
            fuzz_smoke_sha256 = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Sha256 }
            fuzz_smoke_bytes = if ($null -eq $candidateArtifacts) { $null } else { $candidateArtifacts.FuzzSmoke.Bytes }
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
