[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') `
    -ErrorAction Stop).Path
$runner = Join-Path $PSScriptRoot 'run_windows_tun_qualification_host.ps1'
$moduleRoot = Join-Path $repositoryRoot 'tools\powershell\Ferrum2.Qualification.Host'
$moduleManifest = Join-Path $moduleRoot 'Ferrum2.Qualification.Host.psd1'
$bundlePath = Join-Path $moduleRoot 'bundle.json'
. (Join-Path $moduleRoot 'SourceBundle.ps1')
$bundle = Read-Ferrum2HostQualificationSourceBundle `
    -RepositoryRoot $repositoryRoot -ManifestPath $bundlePath

$manifest = Test-ModuleManifest -Path $moduleManifest -ErrorAction Stop
Assert-True (
    (@($manifest.ExportedFunctions.Keys) -join '|') -ceq
        'Invoke-Ferrum2HostQualification'
) 'host qualification module export contract changed'
$loadedModule = Import-Module -Name $moduleManifest -Force -PassThru -ErrorAction Stop
$multiRootState = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<wfpstate><sessions/></wfpstate><firewallState><dynamicKeywordAddresses/></firewallState>'
$parsedState = & $loadedModule {
    param([string]$Text)
    ConvertFrom-Ferrum2QualificationWfpStateXml -Text $Text
} $multiRootState
$parsedRootNames = @($parsedState.DocumentElement.ChildNodes | Where-Object {
    $_.NodeType -eq [Xml.XmlNodeType]::Element
} | ForEach-Object { $_.LocalName })
Assert-True ($parsedState.DocumentElement.LocalName -ceq 'ferrum2WfpState' -and
    ($parsedRootNames -join '|') -ceq 'wfpstate|firewallState') `
    'netsh multi-root WFP state parsing changed'


$candidateSha = (& git -C $repositoryRoot rev-parse HEAD).Trim()
Assert-True ($LASTEXITCODE -eq 0 -and $candidateSha -cmatch '^[0-9a-f]{40}$') `
    'current candidate SHA is unavailable'
$pwsh = [string](Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
$planOutput = & $pwsh -NoProfile -File $runner -PlanOnly -CandidateSha $candidateSha
Assert-True ($LASTEXITCODE -eq 0) 'host qualification PlanOnly failed'
$plan = ($planOutput -join "`n") | ConvertFrom-Json -Depth 12 -ErrorAction Stop
Assert-True ($plan.kind -ceq 'ferrum2.windows-tun.host-qualification-plan' -and
    $plan.execution -ceq 'explicit-authorized-windows-host' -and
    $plan.candidate_sha -ceq $candidateSha -and
    $plan.qualification_source_bundle_sha256 -ceq $bundle.sha256 -and
    [int]$plan.maximum_elapsed_seconds -eq 900 -and
    [int]$plan.worker_timeout_seconds -eq 840 -and
    [int]$plan.build_timeout_seconds -eq 600 -and
    @($plan.checks).Count -eq 8 -and
    $plan.safety.requires_elevation -eq $true -and
    $plan.safety.requires_explicit_acknowledgement -eq $true -and
    $plan.safety.automatic_elevation -eq $false -and
    $plan.safety.route_scope -ceq 'run-owned /32 only') `
    'host qualification plan contract changed'

$missingAckEvidence = Join-Path ([IO.Path]::GetTempPath()) (
    'ferrum2-qualification-missing-ack-' + [Guid]::NewGuid().ToString('N')
)
$missingAckOutput = @(& $pwsh -NoProfile -File $runner -CandidateSha $candidateSha `
    -EvidenceDirectory $missingAckEvidence 2>&1)
Assert-True ($LASTEXITCODE -ne 0 -and
    ($missingAckOutput -join "`n") -match 'requires -AcknowledgeHostNetworkMutation' -and
    -not (Test-Path -LiteralPath $missingAckEvidence)) `
    'host qualification did not reject missing mutation acknowledgement before effects'

$obsoletePlatformFiles = @(
    Get-ChildItem -LiteralPath $PSScriptRoot -File -ErrorAction Stop | Where-Object {
        $_.Name -match '^(?:Main\.|Hard\.|Guest\.)' -or
        $_.Name -match 'hyperv' -or
        $_.Name -in @(
            'qualify_windows_tun.ps1',
            'qualify_windows_tun_cleanup.ps1',
            'qualify_windows_tun_hard_kill.ps1'
        )
    }
)
Assert-True ($obsoletePlatformFiles.Count -eq 0) `
    'obsolete Hyper-V qualification sources remain'
foreach ($path in @(
    'tools\powershell\Ferrum2.WindowsTun.Lab',
    'tools\powershell\Ferrum2.Qualification.Evidence',
    'tools\powershell\Ferrum2.Qualification.HostHyperV',
    'tools\powershell\Ferrum2.Qualification.GuestController',
    'tools\windows-tun\lab'
)) {
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $path))) `
        "obsolete Hyper-V qualification module remains: $path"
}

Write-Output (
    'windows_tun_host_qualification_static status=PASS ' +
    "source_bundle_sha256=$($bundle.sha256) max_elapsed_seconds=900"
)
