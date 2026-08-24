#requires -Version 7.4
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
Repairs the one legacy support-topology manifest that retained PowerShell remoting metadata.

.DESCRIPTION
This fail-closed transaction requires the exact legacy manifest SHA-256. It removes only the three
standard remoting note properties from support.guest, updates the provisioning-library hash, writes
an external candidate, validates that candidate against the complete live Hyper-V topology, and
atomically replaces the legacy manifest with rollback backup protection. It does not change Hyper-V
or network state.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [Parameter(Mandatory = $true)]
    [switch]$Apply,

    [Parameter(Mandatory = $true)]
    [ValidateSet("REPAIR-FERRUM2-REMOTING-METADATA-V1")]
    [string]$AuthorizationToken,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("af20783aba7f875bf81d4d990c31892142c3e590bf1658c67c272b91837e708b")]
    [string]$ExpectedLegacySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$inspectorPath = Join-Path $PSScriptRoot "inspect_windows_tun_hyperv_support_topology.ps1"
$libraryPath = Join-Path $PSScriptRoot "windows_tun_hyperv_support_topology_provisioning.ps1"
$driverPath = Join-Path $PSScriptRoot "provision_windows_tun_hyperv_support_topology.ps1"
$runtimePath = Join-Path $PSScriptRoot "windows_tun_hyperv_support_topology_runtime.ps1"
$repairPath = $PSCommandPath

foreach ($path in @($inspectorPath, $libraryPath, $driverPath, $runtimePath, $repairPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "manifest repair source is missing: $path"
    }
}

function Get-RepairFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

$sourceHashes = [pscustomobject][ordered]@{
    inspector = Get-RepairFileSha256 -Path $inspectorPath
    library = Get-RepairFileSha256 -Path $libraryPath
    driver = Get-RepairFileSha256 -Path $driverPath
    runtime = Get-RepairFileSha256 -Path $runtimePath
    repair = Get-RepairFileSha256 -Path $repairPath
}

$knownLegacyManifestSha256 =
    "af20783aba7f875bf81d4d990c31892142c3e590bf1658c67c272b91837e708b"
$knownLegacyLibrarySha256 =
    "83b91769f850e206a172431a9e2146a02577c7f841f359d422b29f720e523ca9"
$knownInspectorSha256 =
    "f8fbca3be22e4b6176ace9e6e7a8ddb6f720cdad04fb86ecfb47070e9bcf8318"
$knownDriverSha256 =
    "33e3e76340faac7c2c2fcddc2831a1309ab89dea1da82bee06bfe52365fb344c"

if ($ExpectedLegacySha256 -cne $knownLegacyManifestSha256 -or
    [string]$sourceHashes.inspector -cne $knownInspectorSha256 -or
    [string]$sourceHashes.driver -cne $knownDriverSha256) {
    throw "manifest repair is not bound to the reviewed legacy source set"
}

function Assert-RepairSourcesUnchanged {
    if ((Get-RepairFileSha256 -Path $script:inspectorPath) -cne $script:sourceHashes.inspector -or
        (Get-RepairFileSha256 -Path $script:libraryPath) -cne $script:sourceHashes.library -or
        (Get-RepairFileSha256 -Path $script:driverPath) -cne $script:sourceHashes.driver -or
        (Get-RepairFileSha256 -Path $script:runtimePath) -cne $script:sourceHashes.runtime -or
        (Get-RepairFileSha256 -Path $script:repairPath) -cne $script:sourceHashes.repair) {
        throw "manifest repair source changed during the transaction"
    }
}

function Get-RepairArtifactState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ReplacementSha256,
        [Parameter(Mandatory = $true)][string]$DestinationSha256
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return "absent"
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            return "foreign"
        }
        $sha256 = Get-RepairFileSha256 -Path $Path
        if ($sha256 -ceq $ReplacementSha256) {
            return "replacement"
        }
        if ($sha256 -ceq $DestinationSha256) {
            return "destination"
        }
        return "foreign"
    } catch {
        return "unreadable"
    }
}

function Get-RepairReplacementState {
    param(
        [Parameter(Mandatory = $true)][string]$ReplacementPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$ReplacementSha256,
        [Parameter(Mandatory = $true)][string]$DestinationSha256
    )

    return [pscustomobject][ordered]@{
        replacement = Get-RepairArtifactState -Path $ReplacementPath `
            -ReplacementSha256 $ReplacementSha256 -DestinationSha256 $DestinationSha256
        destination = Get-RepairArtifactState -Path $DestinationPath `
            -ReplacementSha256 $ReplacementSha256 -DestinationSha256 $DestinationSha256
        backup = Get-RepairArtifactState -Path $BackupPath `
            -ReplacementSha256 $ReplacementSha256 -DestinationSha256 $DestinationSha256
    }
}

function Format-RepairReplacementState {
    param([Parameter(Mandatory = $true)][object]$State)

    return "replacement=$($State.replacement),destination=$($State.destination)," +
        "backup=$($State.backup)"
}

function Invoke-ExactRepairFileReplacement {
    param(
        [Parameter(Mandatory = $true)][string]$ReplacementPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$ReplacementSha256,
        [Parameter(Mandatory = $true)][string]$DestinationSha256
    )

    $replaceError = $null
    $restoreError = $null
    try {
        [IO.File]::Replace($ReplacementPath, $DestinationPath, $BackupPath, $false)
    } catch {
        $replaceError = $_.Exception.Message
    }

    $state = Get-RepairReplacementState -ReplacementPath $ReplacementPath `
        -DestinationPath $DestinationPath -BackupPath $BackupPath `
        -ReplacementSha256 $ReplacementSha256 -DestinationSha256 $DestinationSha256
    if ($state.replacement -ceq "absent" -and
        $state.destination -ceq "replacement" -and $state.backup -ceq "destination") {
        return [pscustomobject][ordered]@{
            reconciled_after_error = $null -ne $replaceError
            replace_error = $replaceError
            restore_error = $null
        }
    }

    # ReplaceFile can report ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 after moving the destination to the
    # backup. Never complete that partial operation with a plain Move: doing so could bypass the
    # requested metadata checks. Restore the hash-proven original destination and fail closed.
    if ($state.destination -ceq "absent" -and $state.backup -ceq "destination") {
        try {
            [IO.File]::Move($BackupPath, $DestinationPath)
        } catch {
            $restoreError = $_.Exception.Message
        }
        $state = Get-RepairReplacementState -ReplacementPath $ReplacementPath `
            -DestinationPath $DestinationPath -BackupPath $BackupPath `
            -ReplacementSha256 $ReplacementSha256 -DestinationSha256 $DestinationSha256
    }

    $stateText = Format-RepairReplacementState -State $state
    $errorText = "replace_error=$replaceError"
    if ($null -ne $restoreError) {
        $errorText += ",restore_error=$restoreError"
    }
    if ($state.destination -ceq "destination") {
        throw "exact file replacement failed with the original destination intact " +
            "($stateText; $errorText)"
    }
    throw "exact file replacement failed and the original destination could not be restored " +
        "($stateText; $errorText)"
}

# Hash every source before loading code, then immediately prove that loading did not race a
# source replacement. The same snapshot is checked again at each transaction boundary below.
. $libraryPath -LibraryOnly
. $runtimePath -LibraryOnly
Assert-RepairSourcesUnchanged

if (-not $Apply -or
    $AuthorizationToken -cne "REPAIR-FERRUM2-REMOTING-METADATA-V1") {
    throw "the explicit manifest repair authorization contract is invalid"
}
if (-not [IO.Path]::IsPathFullyQualified($ManifestPath)) {
    throw "support topology manifest path must be absolute"
}
$resolvedManifestPath = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
Assert-Ferrum2NoReparsePointInExistingPath -Path $resolvedManifestPath `
    -Label "support topology manifest"
if (Test-Ferrum2PathWithinRoot -Path $resolvedManifestPath -Root $repositoryRoot) {
    throw "support topology manifest must remain outside the repository"
}
$manifestItem = Get-Item -LiteralPath $resolvedManifestPath -Force -ErrorAction Stop
if ($manifestItem.PSIsContainer -or $manifestItem.Length -lt 2 -or
    $manifestItem.Length -gt 131072) {
    throw "support topology manifest file boundary is invalid"
}

$mutex = [Threading.Mutex]::new($false, "Global\Ferrum2WindowsTunSupportTopologyV1")
$mutexOwned = $false
$candidatePath = $null
$backupPath = $null
$payload = $null
$replacementNeedsRollback = $false
try {
    try {
        $mutexOwned = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $mutexOwned = $true
        throw "a prior support-topology transaction abandoned its mutex"
    }
    if (-not $mutexOwned) {
        throw "another Ferrum2 support-topology transaction is active"
    }

    Assert-RepairSourcesUnchanged
    [byte[]]$legacyBytes = [IO.File]::ReadAllBytes($resolvedManifestPath)
    $legacySha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($legacyBytes)
    ).ToLowerInvariant()
    if ($legacySha256 -cne $ExpectedLegacySha256) {
        throw "legacy support topology manifest hash mismatch"
    }
    if ($legacyBytes[-1] -ne 10 -or
        @($legacyBytes | Where-Object { $_ -eq 10 }).Count -ne 1 -or
        @($legacyBytes | Where-Object { $_ -eq 13 }).Count -ne 0 -or
        ($legacyBytes.Length -ge 3 -and $legacyBytes[0] -eq 0xef -and
            $legacyBytes[1] -eq 0xbb -and $legacyBytes[2] -eq 0xbf)) {
        throw "legacy manifest is not canonical UTF-8 JSON"
    }
    $legacyJson = [Text.UTF8Encoding]::new($false, $true).GetString($legacyBytes)
    Assert-Ferrum2NoDuplicateJsonProperty -Json $legacyJson
    $manifest = $legacyJson | ConvertFrom-Json -Depth 12 -ErrorAction Stop

    $guestFields = @(
        "schema", "management_interface_alias", "management_interface_guid",
        "management_interface_index", "management_mac_address", "support_interface_alias",
        "support_interface_guid", "support_interface_index", "support_mac_address",
        "guest_ipv4", "prefix_length", "network", "gateway", "dns_servers", "mtu_bytes",
        "selected_source_ipv4", "selected_route_prefix", "selected_route_next_hop"
    )
    $legacyGuestFields = @(
        $guestFields
        "PSComputerName", "RunspaceId", "PSShowComputerName"
    )
    Assert-Ferrum2ExactPropertySet -Value $manifest.support.guest `
        -Expected $legacyGuestFields -Label "legacy manifest guest support topology"
    $legacyGuest = $manifest.support.guest
    $legacyRunspaceId = [Guid]::Empty
    if ([string]$legacyGuest.PSComputerName -cne [string]$manifest.vm.name -or
        -not [Guid]::TryParse([string]$legacyGuest.RunspaceId, [ref]$legacyRunspaceId) -or
        $legacyRunspaceId -eq [Guid]::Empty -or
        $legacyGuest.PSShowComputerName -isnot [bool] -or
        $legacyGuest.PSShowComputerName -ne $true) {
        throw "legacy manifest remoting metadata is invalid"
    }
    if ([string]$manifest.inspector_sha256 -cne $knownInspectorSha256 -or
        [string]$manifest.provisioning_library_sha256 -cne
            $knownLegacyLibrarySha256 -or
        [string]$manifest.provisioning_script_sha256 -cne $knownDriverSha256) {
        throw "legacy manifest provenance does not match the reviewed dirty artifact"
    }

    $cleanGuestFields = [ordered]@{}
    foreach ($field in $guestFields) {
        # Take the stored property value directly: this repair must not coerce a number, replace
        # an array, normalize a string, or otherwise repair any business field.
        $cleanGuestFields[$field] = $legacyGuest.PSObject.Properties[$field].Value
    }
    $manifest.support.guest = [pscustomobject]$cleanGuestFields
    $manifest.provisioning_library_sha256 = [string]$sourceHashes.library

    Assert-RepairSourcesUnchanged
    $planDocument = Read-Ferrum2SupportTopologyPlanDocument
    Assert-Ferrum2SupportTopologyManifestShape -Manifest $manifest `
        -PlanDocument $planDocument
    $payload = New-CanonicalJsonPayload -Value $manifest

    # Compare JSON trees after applying exactly the two authorized changes to the legacy tree.
    # This catches any accidental normalization outside removal of the three transport fields and
    # replacement of the provisioning-library provenance hash.
    $normalizedLegacyNode = [Text.Json.Nodes.JsonNode]::Parse($legacyJson)
    $candidateJson = [Text.UTF8Encoding]::new($false, $true).GetString(
        [byte[]]$payload.Bytes
    )
    $candidateNode = [Text.Json.Nodes.JsonNode]::Parse($candidateJson)
    $normalizedLegacyNode.AsObject()["provisioning_library_sha256"] =
        [Text.Json.Nodes.JsonValue]::Create([string]$sourceHashes.library)
    $normalizedLegacyGuest = $normalizedLegacyNode["support"]["guest"].AsObject()
    foreach ($field in @("PSComputerName", "RunspaceId", "PSShowComputerName")) {
        if (-not $normalizedLegacyGuest.Remove($field)) {
            throw "legacy manifest transport-field projection failed"
        }
    }
    if (-not [Text.Json.Nodes.JsonNode]::DeepEquals($normalizedLegacyNode, $candidateNode)) {
        throw "manifest repair candidate changes fields outside the authorized semantic delta"
    }
    Assert-RepairSourcesUnchanged

    $target = "support topology manifest $resolvedManifestPath"
    if (-not $PSCmdlet.ShouldProcess($target, "repair remoting metadata and source hash")) {
        [pscustomobject][ordered]@{
            schema = 1
            status = "not_applied"
            legacy_sha256 = $legacySha256
            repaired_sha256 = [string]$payload.Sha256
            manifest_path = $resolvedManifestPath
        } | ConvertTo-Json -Depth 3
        return
    }

    $candidatePath = "$resolvedManifestPath.$([Guid]::NewGuid().ToString('N')).repair"
    $backupPath = "$resolvedManifestPath.$([Guid]::NewGuid().ToString('N')).backup"
    foreach ($path in @($candidatePath, $backupPath)) {
        if (Test-Path -LiteralPath $path) {
            throw "manifest repair temporary path already exists"
        }
    }
    Write-NewCanonicalJson -Path $candidatePath -Payload $payload
    Assert-RepairSourcesUnchanged
    $candidateDocument = Read-Ferrum2SupportTopologyManifest -Path $candidatePath `
        -ExpectedSha256 ([string]$payload.Sha256) -RepositoryRoot $repositoryRoot
    $null = Get-Ferrum2ApprovedHyperVTopologyContext -Document $candidateDocument
    Assert-RepairSourcesUnchanged
    if ((Get-RepairFileSha256 -Path $resolvedManifestPath) -cne $ExpectedLegacySha256) {
        throw "legacy manifest changed before atomic replacement"
    }

    $forwardReplacement = Invoke-ExactRepairFileReplacement `
        -ReplacementPath $candidatePath -DestinationPath $resolvedManifestPath `
        -BackupPath $backupPath -ReplacementSha256 ([string]$payload.Sha256) `
        -DestinationSha256 $ExpectedLegacySha256
    $replacementNeedsRollback = $true
    if ($forwardReplacement.reconciled_after_error) {
        throw "the forward manifest replacement reported an error after reaching its exact " +
            "replacement state: $($forwardReplacement.replace_error)"
    }
    if ((Get-RepairFileSha256 -Path $backupPath) -cne $ExpectedLegacySha256) {
        throw "manifest repair backup does not match the legacy bytes"
    }
    $finalDocument = Read-Ferrum2SupportTopologyManifest -Path $resolvedManifestPath `
        -ExpectedSha256 ([string]$payload.Sha256) -RepositoryRoot $repositoryRoot
    $finalContext = Get-Ferrum2ApprovedHyperVTopologyContext -Document $finalDocument
    Assert-RepairSourcesUnchanged
    if ((Get-RepairFileSha256 -Path $backupPath) -cne $ExpectedLegacySha256) {
        throw "manifest repair backup changed before cleanup"
    }
    $replacementNeedsRollback = $false
    Remove-Item -LiteralPath $backupPath -Force -ErrorAction Stop
    $backupPath = $null

    [pscustomobject][ordered]@{
        schema = 1
        status = "repaired"
        manifest_path = $resolvedManifestPath
        legacy_sha256 = $legacySha256
        manifest_sha256 = [string]$payload.Sha256
        qualification_checkpoint_id = $finalContext.Checkpoint.Id.ToString("D")
        support_switch_id = $finalContext.SupportSwitch.Id.ToString("D")
        vm_state = [string]$finalContext.Vm.State
    } | ConvertTo-Json -Depth 3
} catch {
    $primaryFailure = $_
    if ($replacementNeedsRollback) {
        $rollbackDiagnostic = $null
        try {
            if ((Get-RepairFileSha256 -Path $backupPath) -cne $ExpectedLegacySha256 -or
                (Get-RepairFileSha256 -Path $resolvedManifestPath) -cne
                    ([string]$payload.Sha256)) {
                throw "repair backup hash changed"
            }
            $failedPath = "$resolvedManifestPath.$([Guid]::NewGuid().ToString('N')).failed"
            if (Test-Path -LiteralPath $failedPath) {
                throw "manifest rollback artifact path already exists"
            }
            $rollbackReplacement = Invoke-ExactRepairFileReplacement `
                -ReplacementPath $backupPath -DestinationPath $resolvedManifestPath `
                -BackupPath $failedPath -ReplacementSha256 $ExpectedLegacySha256 `
                -DestinationSha256 ([string]$payload.Sha256)
            if ((Get-RepairFileSha256 -Path $resolvedManifestPath) -cne
                    $ExpectedLegacySha256) {
                throw "legacy manifest restoration hash mismatch"
            }
            if ((Get-RepairFileSha256 -Path $failedPath) -cne ([string]$payload.Sha256)) {
                throw "failed repair artifact hash mismatch"
            }
            if ($rollbackReplacement.reconciled_after_error) {
                $rollbackDiagnostic = "rollback restored the legacy manifest after an exact-state " +
                    "reconciliation; preserved repaired artifact=$failedPath"
            } else {
                Remove-Item -LiteralPath $failedPath -Force -ErrorAction Stop
            }
            $backupPath = $null
            $replacementNeedsRollback = $false
        } catch {
            throw "manifest repair failed ($($primaryFailure.Exception.Message)); " +
                "rollback failed ($($_.Exception.Message))"
        }
        if ($null -ne $rollbackDiagnostic) {
            throw "manifest repair failed ($($primaryFailure.Exception.Message)); " +
                $rollbackDiagnostic
        }
    }
    throw $primaryFailure
} finally {
    if (-not [string]::IsNullOrWhiteSpace($candidatePath) -and
        (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
        try {
            if ($null -ne $payload -and
                (Get-RepairFileSha256 -Path $resolvedManifestPath) -ceq
                    $ExpectedLegacySha256 -and
                (Get-RepairFileSha256 -Path $candidatePath) -ceq
                    ([string]$payload.Sha256)) {
                Remove-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
            }
        } catch {
            Write-Warning "could not verify or remove the repair candidate: $($_.Exception.Message)"
        }
    }
    if ($mutexOwned) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
