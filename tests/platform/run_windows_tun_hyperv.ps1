#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs the Windows TUN qualification controller only inside the approved Hyper-V guest.

.DESCRIPTION
The host side is deliberately limited to exact-identity VM lifecycle operations, PowerShell Direct,
bounded file staging, and evidence export. It never changes a host adapter, address, route, DNS
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
    $expectedKeys = if ($actualKeys.Count -eq $baseKeys.Count + 1 -and
        $actualKeys[-1] -ceq "test_binaries") {
        @($baseKeys + "test_binaries")
    } else {
        $baseKeys
    }
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
    if ($expectedKeys.Count -ne $baseKeys.Count) {
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
        Git = $gitCommand
        Sha = $candidateSha
    }
}

function New-CandidateBundle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GitCommand,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $ignored = @(& $GitCommand -C $script:repositoryRoot bundle create $Destination HEAD 2>&1)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "unable to create the exact candidate bundle"
    }
    $ignored = @(& $GitCommand -C $script:repositoryRoot bundle verify $Destination 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "candidate bundle verification failed"
    }
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
        return [pscustomobject]@{
            Exists = $true
            Safe = @($items | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count -eq 0
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
)) {
    throw "the Hyper-V host orchestrator requires Windows"
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
$candidateBundle = Join-Path $temporaryRoot "candidate.bundle"
$connection = $null
$guestExportPath = $null
$restoreRequired = $false
$runFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
$guestResult = $null

try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    New-CandidateBundle -GitCommand $candidate.Git -Destination $candidateBundle
    [IO.Directory]::CreateDirectory($hostEvidencePath) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $hostEvidencePath "identity-ledger.json"),
        $ledgerIdentity.Bytes
    )

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
    $guestBundle = Join-Path ([string]$guestPaths[0].Input) "candidate.bundle"
    $guestLedger = Join-Path ([string]$guestPaths[0].Input) "identity-ledger.json"
    $guestWintun = Join-Path ([string]$guestPaths[0].Input) "wintun-0.14.1.zip"
    Copy-Item -ToSession $connection.Session -LiteralPath $candidateBundle -Destination $guestBundle -ErrorAction Stop
    Copy-Item -ToSession $connection.Session -LiteralPath $ledgerIdentity.Path -Destination $guestLedger -ErrorAction Stop
    Copy-Item -ToSession $connection.Session -LiteralPath $wintunPath -Destination $guestWintun -ErrorAction Stop

    $guestResults = @(Invoke-Command `
        -Session $connection.Session `
        -ArgumentList @(
            [string]$guestPaths[0].Root,
            $candidate.Sha,
            $Profile,
            $RunToken,
            $ledgerIdentity.Sha256,
            $expectedWintunZipSha256
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$RunRoot,
                [string]$CandidateSha,
                [string]$RequestedProfile,
                [string]$Token,
                [string]$ExpectedLedgerHash,
                [string]$ExpectedWintunHash
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

            $inputPath = Join-Path $RunRoot "input"
            $exportPath = Join-Path $RunRoot "export"
            $repositoryPath = Join-Path $RunRoot "repository"
            $artifactPath = Join-Path $exportPath "artifacts"
            $setupStdout = Join-Path $exportPath "setup.stdout.log"
            $setupStderr = Join-Path $exportPath "setup.stderr.log"
            $controllerStdout = Join-Path $artifactPath "controller.stdout.log"
            $controllerStderr = Join-Path $artifactPath "controller.stderr.log"
            $cleanupStdout = Join-Path $artifactPath "cleanup.stdout.log"
            $cleanupStderr = Join-Path $artifactPath "cleanup.stderr.log"
            $bundlePath = Join-Path $inputPath "candidate.bundle"
            $ledgerPath = Join-Path $inputPath "identity-ledger.json"
            $wintunPath = Join-Path $inputPath "wintun-0.14.1.zip"
            New-Item -ItemType Directory -Path $artifactPath -ErrorAction Stop | Out-Null

            $mode = $RequestedProfile
            $restartCycles = 10
            if ($RequestedProfile -cmatch '^restart-(10|100|1000)$') {
                $restartCycles = [int]$Matches[1]
                $mode = "restart-stress"
            }
            $allowedModes = @(
                "route-detect", "restart-stress", "fragments", "dual-stack-dns",
                "udp-policy", "scheduler-ring-full"
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
                foreach ($path in @($bundlePath, $ledgerPath, $wintunPath)) {
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw "guest input boundary is invalid"
                    }
                }
                if ((Get-FileHash -LiteralPath $ledgerPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                    $ExpectedLedgerHash) {
                    throw "guest identity ledger hash mismatch"
                }
                if ((Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                    $ExpectedWintunHash) {
                    throw "guest Wintun archive hash mismatch"
                }

                $phase = "checkout"
                $git = (Get-Command git -CommandType Application -ErrorAction Stop).Source
                if ((Invoke-LoggedCommand `
                        -Executable $git `
                        -Arguments @("init", $repositoryPath) `
                        -StdoutPath $setupStdout `
                        -StderrPath $setupStderr) -ne 0 -or
                    (Invoke-LoggedCommand `
                        -Executable $git `
                        -Arguments @("-C", $repositoryPath, "fetch", "--no-tags", $bundlePath, "HEAD") `
                        -StdoutPath $setupStdout `
                        -StderrPath $setupStderr) -ne 0 -or
                    (Invoke-LoggedCommand `
                        -Executable $git `
                        -Arguments @("-C", $repositoryPath, "checkout", "--detach", $CandidateSha) `
                        -StdoutPath $setupStdout `
                        -StderrPath $setupStderr) -ne 0) {
                    throw "candidate checkout failed"
                }
                $checkedOutSha = [string](& $git -C $repositoryPath rev-parse HEAD 2>> $setupStderr)
                $status = @(& $git -C $repositoryPath status --porcelain=v1 --untracked-files=all 2>> $setupStderr)
                if ($LASTEXITCODE -ne 0 -or $checkedOutSha -cne $CandidateSha -or $status.Count -ne 0) {
                    throw "candidate checkout identity is invalid"
                }

                $controllerPath = Join-Path $repositoryPath "tests\platform\qualify_windows_tun.ps1"
                $ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 |
                    ConvertFrom-Json -Depth 4 -ErrorAction Stop
                if ($ledger.candidate_sha -cne $CandidateSha -or
                    $ledger.probe_sha256 -cne
                        (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
                    throw "guest candidate ledger binding failed"
                }

                $phase = "build"
                $rustup = (Get-Command rustup -CommandType Application -ErrorAction Stop).Source
                if ((Invoke-LoggedCommand `
                        -Executable $rustup `
                        -Arguments @("toolchain", "install", "1.97.1", "--profile", "minimal") `
                        -StdoutPath $setupStdout `
                        -StderrPath $setupStderr) -ne 0) {
                    throw "pinned Rust installation failed"
                }
                $cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop).Source
                if ((Invoke-LoggedCommand `
                        -Executable $cargo `
                        -Arguments @(
                            "+1.97.1", "build", "-p", "ferrum2-client", "-p", "ferrum2-server",
                            "--bins", "--locked", "--manifest-path", (Join-Path $repositoryPath "Cargo.toml")
                        ) `
                        -StdoutPath $setupStdout `
                        -StderrPath $setupStderr) -ne 0) {
                    throw "candidate build failed"
                }
                $clientBinary = Join-Path $repositoryPath "target\debug\ferrum2-client.exe"
                $serverBinary = Join-Path $repositoryPath "target\debug\ferrum2-server.exe"
                if ((Get-FileHash -LiteralPath $clientBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$ledger.client_sha256 -or
                    (Get-FileHash -LiteralPath $serverBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                        [string]$ledger.server_sha256) {
                    throw "built candidate hashes do not match the identity ledger"
                }

                $phase = "qualification"
                $pwsh = (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
                $controllerArguments = @(
                    "-NoProfile", "-File", $controllerPath,
                    "-Mode", $mode,
                    "-RunToken", $Token,
                    "-IdentityLedger", $ledgerPath,
                    "-ClientBinary", $clientBinary,
                    "-ServerBinary", $serverBinary,
                    "-ArtifactDirectory", $artifactPath
                )
                if ($mode -ceq "restart-stress") {
                    $controllerArguments += @("-RestartCycles", [string]$restartCycles)
                }
                $previousWintunZip = $env:FERRUM2_WINTUN_ZIP
                try {
                    $env:FERRUM2_WINTUN_ZIP = $wintunPath
                    $controllerStarted = $true
                    $qualificationExit = Invoke-LoggedCommand `
                        -Executable $pwsh `
                        -Arguments $controllerArguments `
                        -StdoutPath $controllerStdout `
                        -StderrPath $controllerStderr
                } finally {
                    if ($null -eq $previousWintunZip) {
                        Remove-Item Env:FERRUM2_WINTUN_ZIP -ErrorAction SilentlyContinue
                    } else {
                        $env:FERRUM2_WINTUN_ZIP = $previousWintunZip
                    }
                }
            } catch {
                $failurePhase = $phase
            } finally {
                if ($controllerStarted) {
                    $phase = "cleanup"
                    try {
                        $pwsh = (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
                        $cleanupExit = Invoke-LoggedCommand `
                            -Executable $pwsh `
                            -Arguments @(
                                "-NoProfile", "-File", (Join-Path $repositoryPath "tests\platform\qualify_windows_tun.ps1"),
                                "-Mode", "cleanup",
                                "-RunToken", $Token,
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
                    $result = Get-Content -LiteralPath (Join-Path $artifactPath "m17-result.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -Depth 8 -ErrorAction Stop
                    $cleanup = Get-Content -LiteralPath (Join-Path $artifactPath "external-cleanup.json") -Raw -Encoding utf8 |
                        ConvertFrom-Json -Depth 8 -ErrorAction Stop
                    if ($result.status -ceq "pass" -and $result.run_token -ceq $Token -and
                        $result.identity_sha256 -ceq $ExpectedLedgerHash -and
                        $cleanup.status -ceq "pass" -and $cleanup.run_token -ceq $Token) {
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
                schema = "ferrum2.windows-tun.hyperv-guest-run.v1"
                status = $status
                profile = $RequestedProfile
                mode = $mode
                restart_cycles = if ($mode -ceq "restart-stress") { [long]$restartCycles } else { $null }
                run_token = $Token
                candidate_sha = $CandidateSha
                identity_sha256 = $ExpectedLedgerHash
                qualification_exit = if ($null -eq $qualificationExit) { $null } else { [long]$qualificationExit }
                cleanup_exit = if ($null -eq $cleanupExit) { $null } else { [long]$cleanupExit }
                failure_phase = $failurePhase
                finished_utc = [DateTime]::UtcNow.ToString("o")
            }
            Write-GuestJsonNew -Path (Join-Path $exportPath "guest-run.json") -Value $guestResult
            [pscustomobject]$guestResult
        })
    if ($guestResults.Count -ne 1) {
        throw "guest execution did not return one result"
    }
    $guestResult = $guestResults[0]
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
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction Stop
        } catch {
            $finalizationFailures.Add("temporary staging cleanup failed: $($_.Exception.Message)")
        }
    }
}

$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) { "pass" } else { "fail" }
if (Test-Path -LiteralPath $hostEvidencePath -PathType Container) {
    try {
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hyperv-host-run.v1"
            status = $status
            profile = $Profile
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            guest_build = if ($null -eq $guestResult) { $null } else { [string]$connection.Probe.Build }
            started_utc = $startedUtc
            finished_utc = [DateTime]::UtcNow.ToString("o")
            final_vm_state = [string](Get-ApprovedVmContext).Vm.State
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
