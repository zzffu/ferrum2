#requires -Version 7.4
#requires -Modules Hyper-V

<#
.SYNOPSIS
Runs the independently versioned M16 Windows TUN hard-kill gate in the approved Hyper-V guest.

.DESCRIPTION
The host builds and hash-binds a clean candidate, stages only precompiled artifacts and portable
runtime dependencies, invokes the dedicated guest hard-kill wrapper through PowerShell Direct,
exports bounded evidence, turns off the exact VM, restores the exact checkpoint, and leaves it Off.
It never changes host adapter, address, route, DNS, firewall, WFP, or TUN state.

The portable guest controller defaults to the SHA-256-pinned PowerShell 7.4.19 win-x64 archive at
%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip. The archive must remain outside the repository.

DescribeContract emits the closed static contract without resolving a credential, inspecting a VM,
building code, staging files, or invoking guest execution.
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Describe")]
    [switch]$DescribeContract,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')]
    [string]$RunToken,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$IdentityLedger,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$WintunZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$PowerShellZip,

    [Parameter(ParameterSetName = "Run")]
    [string]$EvidenceDirectory,

    [Parameter(ParameterSetName = "Run")]
    [string]$CredentialPath,

    [Parameter(ParameterSetName = "Run")]
    [ValidateRange(30, 900)]
    [int]$ReadinessTimeoutSeconds = 180,

    [Parameter(ParameterSetName = "Run")]
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
$expectedPowerShellVersion = "7.4.19"
$expectedPowerShellZipSha256 = "cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9"
$expectedArtifactFiles = @(
    "identity-ledger.json",
    "controller.stdout.log",
    "controller.stderr.log",
    "hard-kill-evidence.jsonl",
    "hard-kill-result.json",
    "cleanup.stdout.log",
    "cleanup.stderr.log",
    "hard-kill-cleanup.json"
)
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") -ErrorAction Stop).Path

if ($DescribeContract) {
    [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-static-contract.v1"
        mode = "hard-kill"
        controller_cases = @("auto-route", "auto-dns", "mixed")
        artifact_files = $expectedArtifactFiles
        staged_input_schema = "ferrum2.windows-tun.hard-kill-staged-input.v1"
        result_schema = "ferrum2.windows-tun.hard-kill-result.v1"
        cleanup_schema = "ferrum2.windows-tun.hard-kill-cleanup.v1"
        host_run_schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v1"
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        initial_vm_state = "Off"
        final_vm_state = "Off"
    } | ConvertTo-Json -Depth 5
    return
}

function Import-ReviewedHyperVCommon {
    $commonPath = Join-Path $PSScriptRoot "run_windows_tun_hyperv.ps1"
    $module = New-Module -Name (
        "Ferrum2WindowsTunHyperVCommon_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $commonPath -ScriptBlock {
        param([string]$Path)
        . $Path -LibraryOnly
        Export-ModuleMember -Function @(
            "Test-PathWithinRoot",
            "Assert-NoReparsePointInExistingPath",
            "Resolve-BoundedFile",
            "Resolve-ExternalDirectoryTarget",
            "Import-ApprovedGuestCredential",
            "Get-ApprovedVmContext",
            "Start-ApprovedVm",
            "Stop-ApprovedVm",
            "Restore-ApprovedCheckpoint",
            "Connect-ApprovedGuest",
            "Read-IdentityLedger",
            "Get-CandidateIdentity",
            "Build-CandidateArtifacts",
            "New-PortablePowerShellArchive",
            "Stage-VisualCppRuntime",
            "Write-JsonFileNew",
            "New-StagedFileEntry",
            "Copy-GuestEvidence",
            "Get-EvidenceHashes"
        )
    }
    Import-Module $module -Scope Local -Force
    return $module
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ClosedProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    Assert-True (
        (@($Value.PSObject.Properties.Name) -join "|") -ceq ($Expected -join "|")
    ) "$Label property set or order is invalid"
}

function Assert-UtcTimestamp([string]$Value, [string]$Label) {
    [DateTimeOffset]$timestamp = [DateTimeOffset]::MinValue
    $valid = [DateTimeOffset]::TryParseExact(
        $Value,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$timestamp
    ) -and $timestamp.Offset -eq [TimeSpan]::Zero
    Assert-True $valid "$Label is not a round-trip UTC timestamp"
}

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-HardKillEvidenceRows([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (-not $item.PSIsContainer -and $item.Length -ge 1 -and
        $item.Length -le 1048576 -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "exported hard-kill evidence boundary is invalid"
    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $expectedPhases = @("hard-kill-auto-route", "hard-kill-auto-dns", "hard-kill-mixed")
    Assert-True ($lines.Count -eq 3) "exported hard-kill evidence row count is invalid"
    for ($index = 0; $index -lt 3; $index++) {
        $document = [Text.Json.JsonDocument]::Parse($lines[$index])
        try {
            $properties = @($document.RootElement.EnumerateObject())
            Assert-True (
                ($properties.Name -join "|") -ceq "schema|phase|timestamp_utc|data" -and
                $properties[0].Value.ValueKind -eq [Text.Json.JsonValueKind]::Number -and
                $properties[0].Value.GetInt64() -eq 1 -and
                $properties[1].Value.GetString() -ceq $expectedPhases[$index] -and
                $properties[2].Value.ValueKind -eq [Text.Json.JsonValueKind]::String -and
                $properties[3].Value.ValueKind -eq [Text.Json.JsonValueKind]::Object
            ) "exported hard-kill evidence schema or phase is invalid"
            Assert-UtcTimestamp $properties[2].Value.GetString() "hard-kill evidence timestamp"
            $data = @($properties[3].Value.EnumerateObject())
            Assert-True (
                $data.Count -eq 5 -and
                (($data.Name | Sort-Object) -join "|") -ceq
                    "adapter|addresses|dns|process|routes" -and
                @($data | Where-Object {
                    $_.Value.ValueKind -ne [Text.Json.JsonValueKind]::String -or
                    $_.Value.GetString() -cne "absent"
                }).Count -eq 0
            ) "exported hard-kill evidence is not the closed all-absent set"
        } finally {
            $document.Dispose()
        }
    }
}

function Assert-HardKillExport(
    [string]$Path,
    [object]$Ledger,
    [string]$IdentitySha256,
    [string]$CandidateSha
) {
    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($directory.PSIsContainer -and
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        "hard-kill export directory is invalid"
    $items = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
    Assert-True (
        $items.Count -eq 8 -and
        (($items.Name | Sort-Object) -join "|") -ceq
            (($script:expectedArtifactFiles | Sort-Object) -join "|") -and
        @($items | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $_.Length -gt 67108864
        }).Count -eq 0
    ) "exported hard-kill artifact set is not the exact eight bounded files"

    $identityPath = Join-Path $Path "identity-ledger.json"
    $stdoutPath = Join-Path $Path "controller.stdout.log"
    $stderrPath = Join-Path $Path "controller.stderr.log"
    $evidencePath = Join-Path $Path "hard-kill-evidence.jsonl"
    $resultPath = Join-Path $Path "hard-kill-result.json"
    $cleanupPath = Join-Path $Path "hard-kill-cleanup.json"
    Assert-True ((Get-LowerSha256 $identityPath) -ceq $IdentitySha256) `
        "exported identity ledger hash changed"
    Assert-HardKillEvidenceRows $evidencePath

    $expectedTerminal = "m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS " +
        "adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT cleanup=PASS " +
        "guest_build=$($Ledger.guest_build) run_token=$($script:RunToken) " +
        "candidate_sha=$CandidateSha probe_sha256=$($Ledger.probe_sha256) " +
        "identity_sha256=$IdentitySha256"
    $stdoutLines = @(Get-Content -LiteralPath $stdoutPath -Encoding utf8 -ErrorAction Stop)
    $terminalLines = @($stdoutLines | Where-Object {
        $_.StartsWith("m16_windows_hard_kill ", [StringComparison]::Ordinal)
    })
    $nonempty = @($stdoutLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-True ($nonempty.Count -gt 0 -and
        $terminalLines.Count -eq 1 -and
        $terminalLines[0] -ceq $expectedTerminal -and
        $nonempty[-1] -ceq $expectedTerminal) "exported terminal marker is invalid"

    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-ClosedProperties $result @(
        "schema", "status", "mode", "run_token", "identity_sha256", "candidate_sha",
        "client_sha256", "server_sha256", "controller_sha256", "guest_build", "cases",
        "process_absent", "adapter_absent", "addresses_absent", "routes_absent", "dns_absent",
        "inner_cleanup", "evidence_sha256", "stdout_sha256", "stderr_sha256", "finished_utc"
    ) "hard-kill result"
    Assert-True (
        $result.schema -ceq "ferrum2.windows-tun.hard-kill-result.v1" -and
        $result.status -ceq "pass" -and
        $result.mode -ceq "hard-kill" -and
        $result.run_token -ceq $script:RunToken -and
        $result.identity_sha256 -ceq $IdentitySha256 -and
        $result.candidate_sha -ceq $CandidateSha -and
        $result.client_sha256 -ceq [string]$Ledger.client_sha256 -and
        $result.server_sha256 -ceq [string]$Ledger.server_sha256 -and
        $result.controller_sha256 -ceq [string]$Ledger.probe_sha256 -and
        $result.guest_build -ceq [string]$Ledger.guest_build -and
        ($result.cases -is [int] -or $result.cases -is [long]) -and
        [long]$result.cases -eq 3 -and
        $result.process_absent -is [bool] -and $result.process_absent -and
        $result.adapter_absent -is [bool] -and $result.adapter_absent -and
        $result.addresses_absent -is [bool] -and $result.addresses_absent -and
        $result.routes_absent -is [bool] -and $result.routes_absent -and
        $result.dns_absent -is [bool] -and $result.dns_absent -and
        $result.inner_cleanup -ceq "pass" -and
        $result.evidence_sha256 -ceq (Get-LowerSha256 $evidencePath) -and
        $result.stdout_sha256 -ceq (Get-LowerSha256 $stdoutPath) -and
        $result.stderr_sha256 -ceq (Get-LowerSha256 $stderrPath)
    ) "exported hard-kill result identity, types, status, or hashes are invalid"
    Assert-UtcTimestamp $result.finished_utc "hard-kill result finished_utc"

    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    $cleanupProperties = @(
        "schema", "status", "source_mode", "run_token", "identity_sha256",
        "qualification_outcome", "processes", "adapters", "target_addresses", "target_routes",
        "dns_rows", "sibling_dll", "work_directories", "mutation_journals", "firewall_rules",
        "identity_journal", "finished_utc"
    )
    Assert-ClosedProperties $cleanup $cleanupProperties "hard-kill cleanup"
    Assert-True (
        $cleanup.schema -ceq "ferrum2.windows-tun.hard-kill-cleanup.v1" -and
        $cleanup.status -ceq "pass" -and
        $cleanup.source_mode -ceq "hard-kill" -and
        $cleanup.run_token -ceq $script:RunToken -and
        $cleanup.identity_sha256 -ceq $IdentitySha256 -and
        $cleanup.qualification_outcome -ceq "success"
    ) "exported hard-kill cleanup identity or outcome is invalid"
    foreach ($name in $cleanupProperties[6..15]) {
        Assert-True (
            ($cleanup.$name -is [int] -or $cleanup.$name -is [long]) -and
            [long]$cleanup.$name -eq 0
        ) "exported cleanup residue is not integer zero: $name"
    }
    Assert-UtcTimestamp $cleanup.finished_utc "hard-kill cleanup finished_utc"
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne "X64" -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne "X64") {
    throw "the hard-kill Hyper-V orchestrator requires 64-bit Windows AMD64"
}

$commonModule = Import-ReviewedHyperVCommon
$candidate = Get-CandidateIdentity
$controllerPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\qualify_windows_tun.ps1") `
    -Label "qualification controller" `
    -MaximumBytes 4194304
$guestWrapperPath = Resolve-BoundedFile `
    -Path (Join-Path $repositoryRoot "tests\platform\invoke_windows_tun_hard_kill_guest.ps1") `
    -Label "hard-kill guest wrapper" `
    -MaximumBytes 2097152
$ledgerIdentity = Read-IdentityLedger `
    -Path $IdentityLedger `
    -CandidateSha $candidate.Sha `
    -ControllerPath $controllerPath
$wintunPath = Resolve-BoundedFile `
    -Path $WintunZip `
    -Label "Wintun archive" `
    -MaximumBytes 16777216
Assert-True ((Get-LowerSha256 $wintunPath) -ceq $expectedWintunZipSha256) `
    "Wintun archive hash mismatch"
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
    $EvidenceDirectory = Join-Path $env:LOCALAPPDATA `
        "Ferrum2\windows-tun-hard-kill-evidence\$RunToken"
}
$hostEvidencePath = Resolve-ExternalDirectoryTarget `
    -Path $EvidenceDirectory `
    -Label "hard-kill evidence directory"

# Resolve both exact VM/checkpoint identities and the DPAPI credential before any lifecycle action.
$baselineContext = Get-ApprovedVmContext
if ([string]$baselineContext.Vm.State -cne "Off") {
    throw "approved VM must be Off at the hard-kill qualification baseline"
}
$guestCredential = Import-ApprovedGuestCredential -Path $CredentialPath

$startedUtc = [DateTime]::UtcNow.ToString("o")
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-hard-kill-hyperv-" + [Guid]::NewGuid().ToString("N")
)
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
$candidateArtifacts = $null
$portablePowerShell = $null
$runtimeLibraries = @()
$stagedInputSha256 = $null
$wrapperEntry = $null
$guestResult = $null

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
    $portablePowerShell = New-PortablePowerShellArchive `
        -SourceZip $PowerShellZip `
        -Destination $hostPowerShellArchive
    Assert-True (
        $portablePowerShell.Sha256 -ceq $expectedPowerShellZipSha256 -and
        $portablePowerShell.Version -ceq $expectedPowerShellVersion
    ) "portable PowerShell identity changed after preflight"
    $runtimeLibraries = @(Stage-VisualCppRuntime -Destination $hostRuntimeLibraryRoot)
    $controllerEntry = New-StagedFileEntry `
        -Path $controllerPath `
        -Name "qualify_windows_tun.ps1" `
        -MaximumBytes 4194304
    $wrapperEntry = New-StagedFileEntry `
        -Path $guestWrapperPath `
        -Name "invoke_windows_tun_hard_kill_guest.ps1" `
        -MaximumBytes 2097152
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
    Assert-True (
        $controllerEntry.sha256 -ceq [string]$ledgerIdentity.Ledger.probe_sha256 -and
        $identityEntry.sha256 -ceq $ledgerIdentity.Sha256 -and
        $wintunEntry.sha256 -ceq $expectedWintunZipSha256
    ) "host staged input identity changed after preflight"
    $postBuildCandidate = Get-CandidateIdentity
    Assert-True ($postBuildCandidate.Sha -ceq $candidate.Sha) `
        "candidate commit changed during artifact preparation"

    $stagedInput = [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-staged-input.v1"
        mode = "hard-kill"
        run_token = $RunToken
        candidate_sha = $candidate.Sha
        identity_sha256 = $ledgerIdentity.Sha256
        vm_name = $approvedVmName
        vm_id = $approvedVmId.ToString("D")
        checkpoint_name = $approvedCheckpointName
        checkpoint_id = $approvedCheckpointId.ToString("D")
        guest_product = [string]$ledgerIdentity.Ledger.guest_product
        guest_edition = [string]$ledgerIdentity.Ledger.guest_edition
        guest_architecture = [string]$ledgerIdentity.Ledger.guest_architecture
        guest_version = [string]$ledgerIdentity.Ledger.guest_version
        guest_build = [string]$ledgerIdentity.Ledger.guest_build
        files = [ordered]@{
            guest_wrapper = $wrapperEntry
            controller = $controllerEntry
            identity_ledger = $identityEntry
            wintun_zip = $wintunEntry
            client = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Client.Path `
                -Name "ferrum2-client.exe")
            server = $(New-StagedFileEntry `
                -Path $candidateArtifacts.Server.Path `
                -Name "ferrum2-server.exe")
            powershell_archive = $(New-StagedFileEntry `
                -Path $portablePowerShell.Path `
                -Name "portable-pwsh.zip" `
                -MaximumBytes 536870912)
            vc_libraries = $vcEntries
        }
        runtime = [ordered]@{
            rust_version = $candidateArtifacts.RustVersion
            powershell_version = $portablePowerShell.Version
            powershell_executable_sha256 = $portablePowerShell.ExecutableSha256
            powershell_file_count = $portablePowerShell.FileCount
            powershell_expanded_bytes = $portablePowerShell.ExpandedBytes
        }
    }
    Write-JsonFileNew -Path $stagedInputManifestPath -Value $stagedInput
    $stagedInputSha256 = Get-LowerSha256 $stagedInputManifestPath
    Copy-Item `
        -LiteralPath $stagedInputManifestPath `
        -Destination (Join-Path $hostEvidencePath "staged-input.json") `
        -ErrorAction Stop

    # From this point every exit path must leave the exact checkpoint restored and the VM Off.
    $restoreRequired = $true
    Restore-ApprovedCheckpoint
    Start-ApprovedVm
    $connection = Connect-ApprovedGuest `
        -Credential $guestCredential `
        -TimeoutSeconds $ReadinessTimeoutSeconds
    Assert-True (
        [string]$connection.Probe.Product -ceq [string]$ledgerIdentity.Ledger.guest_product -and
        [string]$connection.Probe.Edition -ceq [string]$ledgerIdentity.Ledger.guest_edition -and
        [string]$connection.Probe.Version -ceq [string]$ledgerIdentity.Ledger.guest_version -and
        [string]$connection.Probe.Build -ceq [string]$ledgerIdentity.Ledger.guest_build -and
        [string]$connection.Probe.Architecture -ceq "X64"
    ) "live guest identity differs from the identity ledger"

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
                throw "guest hard-kill staging baseline is not absent"
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
    Assert-True ($guestPaths.Count -eq 1) `
        "guest staging did not return one bounded path set"
    $guestRoot = [string]$guestPaths[0].Root
    $guestInputPath = [string]$guestPaths[0].Input
    $guestExportPath = [string]$guestPaths[0].Export
    $stagedFiles = @(
        [ordered]@{
            Source = $controllerPath
            Destination = Join-Path $guestInputPath "controller\qualify_windows_tun.ps1"
        },
        [ordered]@{
            Source = $guestWrapperPath
            Destination = Join-Path $guestInputPath "invoke_windows_tun_hard_kill_guest.ps1"
        },
        [ordered]@{
            Source = $ledgerIdentity.Path
            Destination = Join-Path $guestInputPath "identity-ledger.json"
        },
        [ordered]@{
            Source = $wintunPath
            Destination = Join-Path $guestInputPath "wintun-0.14.1.zip"
        },
        [ordered]@{
            Source = $stagedInputManifestPath
            Destination = Join-Path $guestInputPath "staged-input.json"
        },
        [ordered]@{
            Source = $portablePowerShell.Path
            Destination = Join-Path $guestInputPath "portable-pwsh.zip"
        },
        [ordered]@{
            Source = $candidateArtifacts.Client.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-client.exe"
        },
        [ordered]@{
            Source = $candidateArtifacts.Server.Path
            Destination = Join-Path $guestInputPath "artifacts\ferrum2-server.exe"
        }
    )
    foreach ($library in $runtimeLibraries) {
        $stagedFiles += [ordered]@{
            Source = $library.Path
            Destination = Join-Path $guestInputPath ("runtime\vc-runtime\" + $library.Name)
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
            $guestRoot,
            $stagedInputSha256,
            $RunToken,
            $expectedPowerShellZipSha256,
            $expectedPowerShellVersion
        ) `
        -ErrorAction Stop `
        -ScriptBlock {
            param(
                [string]$Root,
                [string]$ExpectedManifestSha256,
                [string]$ExpectedRunToken,
                [string]$ExpectedPowerShellZipSha256,
                [string]$ExpectedPowerShellVersion
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = "Stop"
            $ProgressPreference = "SilentlyContinue"
            function Get-Sha256([string]$Path) {
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).
                    Hash.ToLowerInvariant()
            }
            function Assert-ManifestFile(
                [string]$Path,
                [object]$Entry,
                [string]$ExpectedName,
                [long]$MaximumBytes
            ) {
                $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                if ($item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
                    $Entry.name -cne $ExpectedName -or
                    [long]$Entry.bytes -ne [long]$item.Length -or
                    [string]$Entry.sha256 -cne (Get-Sha256 $Path)) {
                    throw "bootstrap staged file is invalid: $ExpectedName"
                }
            }
            $inputPath = Join-Path $Root "input"
            $manifestPath = Join-Path $inputPath "staged-input.json"
            if ((Get-Sha256 $manifestPath) -cne $ExpectedManifestSha256) {
                throw "bootstrap manifest hash changed"
            }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
                ConvertFrom-Json -ErrorAction Stop
            if ($manifest.schema -cne "ferrum2.windows-tun.hard-kill-staged-input.v1" -or
                $manifest.mode -cne "hard-kill" -or
                $manifest.run_token -cne $ExpectedRunToken -or
                [string]$manifest.files.powershell_archive.sha256 -cne
                    $ExpectedPowerShellZipSha256 -or
                [string]$manifest.runtime.powershell_version -cne $ExpectedPowerShellVersion -or
                [IO.Path]::GetFileName([IO.Path]::GetFullPath($Root).TrimEnd('\', '/')) -cne
                    $ExpectedRunToken) {
                throw "bootstrap staged identity is invalid"
            }
            $wrapperPath = Join-Path $inputPath "invoke_windows_tun_hard_kill_guest.ps1"
            $archivePath = Join-Path $inputPath "portable-pwsh.zip"
            Assert-ManifestFile $wrapperPath $manifest.files.guest_wrapper `
                "invoke_windows_tun_hard_kill_guest.ps1" 2097152
            Assert-ManifestFile $archivePath $manifest.files.powershell_archive `
                "portable-pwsh.zip" 536870912
            $pwshRoot = Join-Path $Root "pwsh74"
            if (Test-Path -LiteralPath $pwshRoot) {
                throw "portable PowerShell expansion baseline is not absent"
            }
            Expand-Archive -LiteralPath $archivePath -DestinationPath $pwshRoot -Force
            $items = @(Get-Item -LiteralPath $pwshRoot -Force) + @(
                Get-ChildItem -LiteralPath $pwshRoot -Force -Recurse
            )
            $files = @($items | Where-Object { -not $_.PSIsContainer })
            $bytes = [long]($files | Measure-Object Length -Sum).Sum
            if (@($items | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -ne 0 -or
                $files.Count -ne [long]$manifest.runtime.powershell_file_count -or
                $bytes -ne [long]$manifest.runtime.powershell_expanded_bytes) {
                throw "portable PowerShell expansion boundary changed"
            }
            $pwsh = Join-Path $pwshRoot "pwsh.exe"
            if ((Get-Sha256 $pwsh) -cne
                [string]$manifest.runtime.powershell_executable_sha256) {
                throw "portable PowerShell executable hash changed"
            }
            $output = @(& $pwsh -NoProfile -File $wrapperPath `
                -RunRoot $Root `
                -ExpectedManifestSha256 $ExpectedManifestSha256 2>&1)
            $exitCode = [int]$LASTEXITCODE
            $outputLines = @($output | ForEach-Object { [string]$_ })
            if ($exitCode -ne 0) {
                throw "guest hard-kill wrapper failed with exit code $exitCode; " +
                    (@($outputLines | Select-Object -Last 20) -join " | ")
            }
            $expectedMarker = "m16_product_hard_kill_wrapper status=PASS " +
                "run_token=$ExpectedRunToken files=8/8 cleanup=PASS"
            if ($outputLines.Count -ne 1 -or $outputLines[0] -cne $expectedMarker) {
                throw "guest hard-kill wrapper marker is invalid"
            }
            [pscustomobject][ordered]@{
                schema = "ferrum2.windows-tun.hard-kill-guest-bootstrap.v1"
                status = "pass"
                mode = "hard-kill"
                run_token = $ExpectedRunToken
                staged_input_sha256 = $ExpectedManifestSha256
                files = [long]8
                cleanup = "pass"
            }
        })
    # END GUEST_ONLY_EXECUTION
    Assert-True ($guestResults.Count -eq 1) "guest hard-kill returned an invalid result count"
    $guestResult = $guestResults[0]
    Assert-ClosedProperties $guestResult @(
        "schema", "status", "mode", "run_token", "staged_input_sha256", "files", "cleanup"
    ) "hard-kill guest bootstrap"
    Assert-True (
        $guestResult.schema -ceq "ferrum2.windows-tun.hard-kill-guest-bootstrap.v1" -and
        $guestResult.status -ceq "pass" -and
        $guestResult.mode -ceq "hard-kill" -and
        $guestResult.run_token -ceq $RunToken -and
        $guestResult.staged_input_sha256 -ceq $stagedInputSha256 -and
        ($guestResult.files -is [int] -or $guestResult.files -is [long]) -and
        [long]$guestResult.files -eq 8 -and
        $guestResult.cleanup -ceq "pass"
    ) "hard-kill guest bootstrap result is invalid"
} catch {
    $runFailure = $_
} finally {
    if ($null -ne $connection -and
        -not [string]::IsNullOrWhiteSpace($guestExportPath) -and
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
        $vmConfirmedOff = $false
        for ($attempt = 1; $attempt -le 2 -and -not $vmConfirmedOff; $attempt++) {
            try {
                Stop-ApprovedVm -TimeoutSeconds $ShutdownTimeoutSeconds
            } catch {
                $finalizationFailures.Add(
                    "mandatory final VM stop attempt $attempt failed: $($_.Exception.Message)"
                )
            }
            try {
                $stoppedState = [string](Get-ApprovedVmContext).Vm.State
                if ($stoppedState -ceq "Off") {
                    $vmConfirmedOff = $true
                } else {
                    $finalizationFailures.Add(
                        "mandatory final VM stop attempt $attempt left state $stoppedState"
                    )
                }
            } catch {
                $finalizationFailures.Add(
                    "mandatory final VM stop attempt $attempt readback failed: " +
                        $_.Exception.Message
                )
            }
        }
        if ($vmConfirmedOff) {
            $checkpointRestored = $false
            for ($attempt = 1; $attempt -le 2 -and -not $checkpointRestored; $attempt++) {
                try {
                    Restore-ApprovedCheckpoint
                    $checkpointRestored = $true
                } catch {
                    $finalizationFailures.Add(
                        "mandatory final checkpoint restore attempt $attempt failed: " +
                            $_.Exception.Message
                    )
                }
            }
        } else {
            $finalizationFailures.Add(
                "mandatory final checkpoint restore could not start because Off was not proven"
            )
        }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        try {
            $resolvedTemporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot -ErrorAction Stop).Path
            Assert-True (
                (Test-PathWithinRoot -Path $resolvedTemporaryRoot -Root $temporaryBase) -and
                [IO.Path]::GetFileName($resolvedTemporaryRoot) -cmatch
                    '^ferrum2-hard-kill-hyperv-[0-9a-f]{32}$'
            ) "temporary staging cleanup boundary is invalid"
            Assert-NoReparsePointInExistingPath `
                -Path $resolvedTemporaryRoot `
                -Label "temporary hard-kill staging cleanup"
            $temporaryItems = @(Get-Item -LiteralPath $resolvedTemporaryRoot -Force) + @(
                Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Force -Recurse
            )
            Assert-True (@($temporaryItems | Where-Object {
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                }).Count -eq 0) "temporary staging contains a reparse point"
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
    $finalizationFailures.Add("approved VM final-state readback failed: $($_.Exception.Message)")
}
if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    try {
        $finalCandidate = Get-CandidateIdentity
        Assert-True ($finalCandidate.Sha -ceq $candidate.Sha) `
            "candidate commit changed during hard-kill qualification"
        Assert-HardKillExport `
            -Path (Join-Path $hostEvidencePath "guest\export") `
            -Ledger $ledgerIdentity.Ledger `
            -IdentitySha256 $ledgerIdentity.Sha256 `
            -CandidateSha $candidate.Sha
    } catch {
        $runFailure = $_
    }
}
$status = if ($null -eq $runFailure -and $finalizationFailures.Count -eq 0) {
    "pass"
} else {
    "fail"
}
if (Test-Path -LiteralPath $hostEvidencePath -PathType Container) {
    try {
        $manifest = [ordered]@{
            schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v1"
            status = $status
            mode = "hard-kill"
            run_token = $RunToken
            vm_name = $approvedVmName
            vm_id = $approvedVmId.ToString("D")
            checkpoint_name = $approvedCheckpointName
            checkpoint_id = $approvedCheckpointId.ToString("D")
            candidate_sha = $candidate.Sha
            identity_sha256 = $ledgerIdentity.Sha256
            controller_sha256 = [string]$ledgerIdentity.Ledger.probe_sha256
            guest_wrapper_sha256 = if ($null -eq $wrapperEntry) {
                $null
            } else {
                [string]$wrapperEntry.sha256
            }
            staged_input_sha256 = $stagedInputSha256
            rust_version = if ($null -eq $candidateArtifacts) {
                $null
            } else {
                $candidateArtifacts.RustVersion
            }
            guest_execution = "host-built-precompiled-artifacts-only"
            guest_build = [string]$ledgerIdentity.Ledger.guest_build
            started_utc = $startedUtc
            finished_utc = [DateTime]::UtcNow.ToString("o")
            final_vm_state = $finalVmState
            evidence_files = @(Get-EvidenceHashes -EvidenceRoot $hostEvidencePath)
        }
        Write-JsonFileNew `
            -Path (Join-Path $hostEvidencePath "host-orchestration.json") `
            -Value $manifest
    } catch {
        $finalizationFailures.Add("host evidence manifest failed: $($_.Exception.Message)")
        $status = "fail"
    }
}

if ($null -ne $runFailure -or $finalizationFailures.Count -ne 0) {
    $messages = [Collections.Generic.List[string]]::new()
    if ($null -ne $runFailure) {
        $messages.Add("hard-kill qualification failed: $($runFailure.Exception.Message)")
    }
    foreach ($message in $finalizationFailures) { $messages.Add($message) }
    throw [InvalidOperationException]::new(($messages -join "; "))
}

Write-Output (
    "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill run_token=$RunToken " +
    "candidate_sha=$($candidate.Sha) evidence=$hostEvidencePath final_vm_state=Off"
)
