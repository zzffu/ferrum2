[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Throws([scriptblock]$Action, [string]$Label) {
    $failure = $null
    try { & $Action } catch { $failure = $_ }
    Assert-True ($null -ne $failure) "$Label did not fail closed"
}

function Get-GitObjectId(
    [string]$GitPath,
    [string]$RepositoryRoot,
    [string[]]$Command,
    [string]$Label
) {
    $output = @(& $GitPath -C $RepositoryRoot @Command 2>&1)
    $exitCode = $LASTEXITCODE
    Assert-True ($exitCode -eq 0 -and $output.Count -eq 1 -and
        [string]$output[0] -cmatch '^[0-9a-f]{40,64}$') `
        "$Label Git object identity is unavailable"
    ([string]$output[0]).Trim()
}

function Assert-CanonicalSourceIdentity(
    [string]$RepositoryRoot,
    [string[]]$MemberPaths,
    [string[]]$ManifestPaths
) {
    $git = @(Get-Command git -CommandType Application -ErrorAction Stop)[0]
    $canonicalPaths = @($MemberPaths) + @($ManifestPaths)
    foreach ($relativePath in @($canonicalPaths | Sort-Object -Unique)) {
        $path = Join-Path $RepositoryRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-True (-not ($bytes -contains [byte]13)) `
            "identity-bound source is not canonical LF: $relativePath"
    }
    foreach ($relativePath in @($MemberPaths | Sort-Object -Unique)) {
        $workingObject = Get-GitObjectId $git.Source $RepositoryRoot `
            @('hash-object', '--no-filters', '--', $relativePath) `
            "identity-bound worktree source $relativePath"
        $indexObject = Get-GitObjectId $git.Source $RepositoryRoot `
            @('rev-parse', '--verify', ":$relativePath") `
            "identity-bound index source $relativePath"
        Assert-True ($workingObject -ceq $indexObject) `
            "identity-bound source differs between worktree and index: $relativePath"
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
$moduleRoot = Join-Path $repositoryRoot 'tools\powershell'
. (Join-Path $moduleRoot 'Ferrum2.Qualification.Common\BundleBootstrap.ps1')
$contracts = [ordered]@{
    'Ferrum2.Qualification.Common' = @(
        'Assert-Ferrum2ClosedProperties', 'Get-Ferrum2LowerSha256',
        'Resolve-Ferrum2OrdinaryFile', 'Test-Ferrum2PathWithinRoot',
        'Write-Ferrum2JsonCreateNew'
    )
    'Ferrum2.Qualification.HostHyperV' = @(
        'Invoke-Ferrum2HostControllerExtension', 'Initialize-Ferrum2HostHyperVModule',
        'Resolve-Ferrum2HostInput', 'New-Ferrum2HostVmIdentity',
        'Get-Ferrum2HostVmContext', 'Invoke-Ferrum2HostVmLifecycle',
        'Connect-Ferrum2HostGuest'
    )
    'Ferrum2.Qualification.GuestController' = @(
        'Get-Ferrum2QualificationProfiles', 'Resolve-Ferrum2QualificationProfile',
        'Assert-Ferrum2GuestQualificationMode',
        'Get-Ferrum2GuestQualificationModeContract'
    )
    'Ferrum2.Qualification.Evidence' = @(
        'New-Ferrum2ControllerBundleManifest', 'Assert-Ferrum2ControllerBundleManifest',
        'Copy-Ferrum2ControllerBundle', 'Write-Ferrum2ControllerBundleManifest',
        'Get-Ferrum2GuestControllerModuleFileMap',
        'Get-Ferrum2MainControllerBundleFileMap',
        'Get-Ferrum2HardKillControllerBundleFileMap'
    )
}

foreach ($name in $contracts.Keys) {
    $manifestPath = Join-Path $moduleRoot "$name\$name.psd1"
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Assert-True (
        (@($manifest.ExportedFunctions.Keys | Sort-Object) -join '|') -ceq
        (@($contracts[$name] | Sort-Object) -join '|')
    ) "$name export contract changed"
    Import-Module $manifestPath -Scope Local -Force -ErrorAction Stop
}

$expectedProfiles = @(
    'network-reset-10', 'network-reset-100', 'network-reset-1000',
    'restart-10', 'restart-100', 'restart-1000', 'fragments', 'dual-stack-dns',
    'udp-policy', 'scheduler-ring-full', 'fuzz-smoke'
)
Assert-True (
    (@(Get-Ferrum2QualificationProfiles) -join '|') -ceq ($expectedProfiles -join '|')
) 'the closed 11-profile set changed'
$restart = Resolve-Ferrum2QualificationProfile -Profile 'restart-1000'
Assert-True ($restart.mode -ceq 'restart-stress' -and $restart.restart_cycles -eq 1000 -and
    $restart.network_reset_cycles -eq 0) 'restart profile mapping changed'
$reset = Resolve-Ferrum2QualificationProfile -Profile 'network-reset-100'
Assert-True ($reset.mode -ceq 'network-reset' -and $reset.network_reset_cycles -eq 100 -and
    $reset.restart_cycles -eq 0) 'network-reset profile mapping changed'
Assert-Throws { Resolve-Ferrum2QualificationProfile -Profile 'hard-kill' } `
    'hard-kill main-profile separation'
Assert-Throws { Assert-Ferrum2GuestQualificationMode -Mode 'fuzz-smoke' } `
    'fuzz-smoke controller separation'
$m17Mode = Get-Ferrum2GuestQualificationModeContract -Mode 'scheduler-ring-full'
$hardKillMode = Get-Ferrum2GuestQualificationModeContract -Mode 'hard-kill'
$cleanupMode = Get-Ferrum2GuestQualificationModeContract -Mode 'cleanup'
Assert-True ($m17Mode.is_m17 -and $m17Mode.topology_bound -and
    $m17Mode.requires_candidate_tests -and -not $m17Mode.accepts_restart_cycles) `
    'M17 guest mode contract changed'
Assert-True (-not $hardKillMode.is_m17 -and $hardKillMode.topology_bound -and
    -not $hardKillMode.requires_candidate_tests) 'hard-kill guest mode contract changed'
Assert-True (-not $cleanupMode.is_m17 -and -not $cleanupMode.topology_bound) `
    'cleanup guest mode contract changed'

Assert-Throws {
    Assert-Ferrum2ClosedProperties ([pscustomobject][ordered]@{ a = 1; b = 2 }) @('a') 'synthetic'
} 'closed property set'

$fileMap = @(
    Get-Ferrum2MainControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controller = [string]@($fileMap | Where-Object {
    [string]$_.relative_path -ceq 'qualify_windows_tun.ps1'
})[0].source_path
$bundle = New-Ferrum2ControllerBundleManifest `
    -FileMap $fileMap -EntryPoint 'qualify_windows_tun.ps1'
Assert-True ($bundle.schema -ceq 'ferrum2.qualification-controller-bundle.v1' -and
    [string]$bundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    @($bundle.files).Count -eq 33) 'controller bundle identity is invalid'

$mainSourceBundle = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\main-source-bundle.json') -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$hardSourceBundle = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\hard-source-bundle.json') -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
[void](Assert-Ferrum2ControllerBundleManifest `
    -Manifest $mainSourceBundle -BundleRoot $repositoryRoot)
[void](Assert-Ferrum2ControllerBundleManifest `
    -Manifest $hardSourceBundle -BundleRoot $repositoryRoot)
Assert-True (
    @($mainSourceBundle.files).Count -eq 21 -and
    @($hardSourceBundle.files).Count -eq 18 -and
    [string]$mainSourceBundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    [string]$hardSourceBundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$'
) 'main or hard host source-bundle identity is invalid'
$mainExtensionRelative = 'tests/platform/Main.HostController.ps1'
$mainExtensionEntry = @($mainSourceBundle.files | Where-Object {
    [string]$_.path -ceq $mainExtensionRelative
})
Assert-True ($mainExtensionEntry.Count -eq 1) `
    'main host controller extension identity is absent'
Assert-Throws {
    Invoke-Ferrum2HostControllerExtension `
        -RepositoryRoot $repositoryRoot `
        -ExtensionPath (Join-Path $repositoryRoot $mainExtensionRelative) `
        -ExpectedSha256 ([string]$mainExtensionEntry[0].sha256) `
        -Context ([ordered]@{}) -RequiredModules @('Evidence', 'GuestController')
} 'closed main host controller extension context'

$mainControllerText = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\Main.GuestController.ps1') -Raw -Encoding utf8
$bootstrapHashOffset = $mainControllerText.IndexOf('$bootstrapEntry.Count -ne 1')
$bootstrapSourceOffset = $mainControllerText.IndexOf('. $bootstrapPath')
$bundleVerifyOffset = $mainControllerText.IndexOf(
    'Assert-Ferrum2BootstrapControllerBundle'
)
$firstImportOffset = $mainControllerText.IndexOf('Import-Module')
$firstOwnerOffset = $mainControllerText.IndexOf(". (Join-Path `$PSScriptRoot")
Assert-True ($bootstrapHashOffset -ge 0 -and
    $bootstrapHashOffset -lt $bootstrapSourceOffset -and
    $bootstrapSourceOffset -lt $bundleVerifyOffset -and
    $bundleVerifyOffset -lt $firstImportOffset -and
    $firstImportOffset -lt $firstOwnerOffset) `
    'main guest bootstrap/import/owner trust order changed'

foreach ($runnerName in @(
    'run_windows_tun_hyperv.ps1', 'run_windows_tun_hard_kill_hyperv.ps1'
)) {
    $runnerText = Get-Content -LiteralPath (Join-Path $PSScriptRoot $runnerName) `
        -Raw -Encoding utf8
    Assert-True (-not $runnerText.Contains('OperationSet') -and
        -not $runnerText.Contains('Function:') -and
        $runnerText.Contains('Invoke-Ferrum2HostControllerExtension')) `
        "host runner deep-interface contract changed: $runnerName"
}

$performanceOwners = [Collections.Generic.List[string]]::new()
foreach ($performanceFile in Get-ChildItem -LiteralPath (Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Performance') -Filter '*.ps1' -File) {
    $tokens = $null
    $errors = $null
    $performanceAst = [Management.Automation.Language.Parser]::ParseFile(
        $performanceFile.FullName, [ref]$tokens, [ref]$errors
    )
    Assert-True ($errors.Count -eq 0) `
        "performance PowerShell parser failed: $($performanceFile.Name)"
    foreach ($owner in $performanceAst.FindAll({
        param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) { $performanceOwners.Add($owner.Name) }
}
$forbiddenOwners = @(
    'Test-PathWithinRoot', 'Assert-NoReparsePointInExistingPath',
    'Resolve-ExternalFile', 'Resolve-NewExternalDirectory',
    'Import-ApprovedGuestCredential', 'Get-ApprovedVmContext', 'Stop-ApprovedVm',
    'Restore-ApprovedCheckpoint', 'Restore-ApprovedVmFinalState',
    'Connect-ApprovedGuest'
)
Assert-True (@($forbiddenOwners | Where-Object {
    $_ -cin $performanceOwners
}).Count -eq 0) 'performance PowerShell duplicated a HostHyperV owner'

$performanceRunnerPath = Join-Path $repositoryRoot `
    'tools\windows-tun\run_windows_tun_performance_hyperv.ps1'
$tokens = $null
$errors = $null
$performanceRunnerAst = [Management.Automation.Language.Parser]::ParseFile(
    $performanceRunnerPath, [ref]$tokens, [ref]$errors
)
Assert-True ($errors.Count -eq 0) 'performance runner parser failed'
$sourceAssignments = @($performanceRunnerAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$performanceSourcePaths'
}, $true))
Assert-True ($sourceAssignments.Count -eq 1) `
    'performance source-map owner is missing or duplicated'
$expectedPerformancePaths = @($sourceAssignments[0].Right.FindAll({
    param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]
}, $true) | ForEach-Object { $_.Value })
$performanceSourceBundlePath = Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Performance\bundle.json'
$performanceSourceBundle = Get-Content -LiteralPath $performanceSourceBundlePath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$actualPerformancePaths = @($performanceSourceBundle.files.path)
Assert-True ($expectedPerformancePaths.Count -eq 42 -and
    @($expectedPerformancePaths | Where-Object {
        $_ -cnotin $actualPerformancePaths
    }).Count -eq 0 -and @($actualPerformancePaths | Where-Object {
        $_ -cnotin $expectedPerformancePaths
    }).Count -eq 0) 'performance source bundle is not the exact 42-file set'
$performanceSourceBundleHash = Assert-Ferrum2BootstrapSourceManifest `
    -ManifestPath $performanceSourceBundlePath -RepositoryRoot $repositoryRoot `
    -ExpectedKind 'ferrum2.windows-tun-performance-source-bundle.v1' `
    -ExpectedEntrypoint 'tools/windows-tun/run_windows_tun_performance_hyperv.ps1' `
    -ExpectedPaths $expectedPerformancePaths
Assert-True ($performanceSourceBundleHash -cmatch '^[0-9a-f]{64}$') `
    'performance source-bundle identity is invalid'

$identityMemberPaths = @($mainSourceBundle.files.path) +
    @($hardSourceBundle.files.path) + @($performanceSourceBundle.files.path)
Assert-CanonicalSourceIdentity -RepositoryRoot $repositoryRoot `
    -MemberPaths $identityMemberPaths -ManifestPaths @(
        'tests/platform/main-source-bundle.json'
        'tests/platform/hard-source-bundle.json'
        'tools/powershell/Ferrum2.Performance/bundle.json'
    )

$hardFileMap = @(
    Get-Ferrum2HardKillControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$hardBundle = New-Ferrum2ControllerBundleManifest `
    -FileMap $hardFileMap -EntryPoint 'qualify_windows_tun_hard_kill.ps1'
Assert-True (@($hardBundle.files).Count -eq 20 -and
    [string]$hardBundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$') `
    'hard-kill controller bundle identity is invalid'
Assert-True (@($hardFileMap | Where-Object {
    [string]$_.relative_path -cmatch '^Main\.'
}).Count -eq 0) `
    'main-only owner leaked into the hard-kill bundle identity'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ferrum2-qualification-modules-' + [Guid]::NewGuid().ToString('N')
)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
$mismatchRoot = $temporaryRoot + '-mismatch'
Assert-True ($temporaryRoot.StartsWith(
    $temporaryBase + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase
)) 'temporary module root escaped TEMP'
try {
    $extraFileMap = @($fileMap) + @([pscustomobject][ordered]@{
        source_path = $controller
        relative_path = 'unexpected-controller.ps1'
    })
    Assert-Throws {
        Copy-Ferrum2ControllerBundle -FileMap $extraFileMap -Manifest $bundle `
            -DestinationRoot $mismatchRoot
    } 'controller bundle file-map mismatch'
    Assert-True (-not (Test-Path -LiteralPath $mismatchRoot)) `
        'bundle mismatch created a partial destination'
    Copy-Ferrum2ControllerBundle -FileMap $fileMap -Manifest $bundle `
        -DestinationRoot $temporaryRoot
    $manifestPath = Join-Path $temporaryRoot 'controller-bundle.json'
    Write-Ferrum2ControllerBundleManifest -Path $manifestPath -Manifest $bundle
    [void](Assert-Ferrum2ControllerBundleManifest -Manifest $bundle -BundleRoot $temporaryRoot)
    $readback = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-True ($readback.controller_bundle_sha256 -ceq $bundle.controller_bundle_sha256) `
        'controller bundle manifest readback changed'

    $tamperPath = Join-Path $temporaryRoot `
        'modules\Ferrum2.Qualification.Common\Ferrum2.Qualification.Common.psd1'
    [IO.File]::AppendAllText($tamperPath, "`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws {
        Assert-Ferrum2ControllerBundleManifest -Manifest $bundle -BundleRoot $temporaryRoot
    } 'controller bundle tamper'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
    if (Test-Path -LiteralPath $mismatchRoot) {
        [IO.Directory]::Delete($mismatchRoot, $true)
    }
}

Write-Output 'qualification_modules status=PASS profiles=11 bundle_files=33 hard_kill=independent'
