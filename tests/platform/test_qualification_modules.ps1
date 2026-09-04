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

function ConvertTo-TestJsonBytes([object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 12) -replace "`r`n", "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
}

function New-TestClosedSourceFixture(
    [string]$Root,
    [object[]]$Definitions
) {
    $requiredRoot = Join-Path $Root 'tools'
    $manifestRoot = Join-Path $requiredRoot 'lab'
    New-Item -ItemType Directory -Path $manifestRoot -Force -ErrorAction Stop |
        Out-Null
    $files = [Collections.Generic.List[object]]::new()
    $rootRows = [Collections.Generic.List[string]]::new()
    $schema = 'ferrum2.test-source-bundle.v1'
    $entrypoint = 'tools/lab/one.ps1'
    $rootRows.Add("schema=$schema")
    $rootRows.Add("entrypoint=$entrypoint")
    foreach ($definition in $Definitions) {
        $sourcePath = [IO.Path]::GetFullPath((Join-Path $Root $definition.path))
        $sourceParent = Split-Path -Parent $sourcePath
        New-Item -ItemType Directory -Path $sourceParent -Force -ErrorAction Stop |
            Out-Null
        [byte[]]$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
            [string]$definition.content + "`n"
        )
        [IO.File]::WriteAllBytes($sourcePath, $bytes)
        $sha = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
        $files.Add([pscustomobject][ordered]@{
            role = [string]$definition.role
            path = [string]$definition.path
            bytes = [long]$bytes.Length
            sha256 = $sha
        })
        $rootRows.Add(
            "role=$([string]$definition.role);path=$([string]$definition.path);" +
            "bytes=$([long]$bytes.Length);sha256=$sha"
        )
    }
    [byte[]]$rootBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($rootRows -join "`n") + "`n"
    )
    $bundleSha = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($rootBytes)
    ).ToLowerInvariant()
    $manifestPath = Join-Path $manifestRoot 'source.json'
    Write-Ferrum2JsonCreateNew -Path $manifestPath -Value (
        [pscustomobject][ordered]@{
            schema = $schema
            entrypoint = $entrypoint
            files = @($files)
            source_bundle_sha256 = $bundleSha
        }
    )
    [pscustomobject][ordered]@{
        RepositoryRoot = $Root
        RequiredRoot = $requiredRoot
        ManifestPath = $manifestPath
        Schema = $schema
        EntryPoint = $entrypoint
    }
}

function Get-ScriptAst([string]$Path) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors
    )
    Assert-True ($errors.Count -eq 0) "PowerShell parser failed: $Path"
    $ast
}

function Get-AstCommandName([object]$Ast) {
    @($Ast.FindAll({
        param($node) $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    })
}

function Get-AstStringValue([object]$Ast) {
    @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.StringConstantExpressionAst]
    }, $true) | ForEach-Object { $_.Value })
}

function Assert-CanonicalLf(
    [string]$RepositoryRoot,
    [string[]]$Paths
) {
    foreach ($relativePath in @($Paths | Sort-Object -Unique)) {
        $path = Join-Path $RepositoryRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-True (-not ($bytes -contains [byte]13)) `
            "identity-bound source is not canonical LF: $relativePath"
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
$moduleRoot = Join-Path $repositoryRoot 'tools\powershell'
. (Join-Path $moduleRoot 'Ferrum2.WindowsTun.Lab\BundleBootstrap.ps1')
$contracts = [ordered]@{
    'Ferrum2.WindowsTun.Lab' = @(
        'Assert-Ferrum2ClosedProperties', 'Get-Ferrum2LowerSha256',
        'Resolve-Ferrum2OrdinaryFile', 'Test-Ferrum2PathWithinRoot',
        'Assert-Ferrum2NoReparsePointInExistingPath',
        'Write-Ferrum2JsonCreateNew', 'New-Ferrum2ControllerBundleManifest',
        'Assert-Ferrum2ControllerBundleManifest', 'Copy-Ferrum2ControllerBundle',
        'Write-Ferrum2ControllerBundleManifest', 'Resolve-Ferrum2HostInput',
        'New-Ferrum2HostVmIdentity', 'Get-Ferrum2HostVmContext',
        'Invoke-Ferrum2HostVmLifecycle', 'Connect-Ferrum2HostGuest',
        'Get-Ferrum2WindowsTunLabBootstrapFileMap',
        'Get-Ferrum2WindowsTunLabRuntimeFileMap'
    )
    'Ferrum2.Qualification.HostHyperV' = @(
        'Invoke-Ferrum2QualificationHostController', 'Initialize-Ferrum2HostHyperVModule'
    )
    'Ferrum2.Qualification.GuestController' = @(
        'Get-Ferrum2QualificationProfiles', 'Get-Ferrum2QualificationSuiteProfiles',
        'Resolve-Ferrum2QualificationProfile'
    )
    'Ferrum2.Qualification.Evidence' = @(
        'Get-Ferrum2MainControllerBundleFileMap',
        'Get-Ferrum2HardKillControllerBundleFileMap'
    )
}

foreach ($name in $contracts.Keys) {
    $manifestPath = Join-Path $moduleRoot "$name\$name.psd1"
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Assert-True (@($contracts[$name] | Where-Object {
        $_ -cnotin @($manifest.ExportedFunctions.Keys)
    }).Count -eq 0) "$name required export contract changed"
    Import-Module $manifestPath -Scope Local -Force -ErrorAction Stop
}
$hostControllerApi = Get-Command Invoke-Ferrum2QualificationHostController `
    -ErrorAction Stop
$requiredHostControllerParameters = @('RepositoryRoot', 'Controller', 'Context')
$removedHostControllerParameters = @('ExtensionPath', 'ExpectedSha256', 'RequiredModules')
Assert-True (@($requiredHostControllerParameters | Where-Object {
        $_ -cnotin @($hostControllerApi.Parameters.Keys)
    }).Count -eq 0 -and @($removedHostControllerParameters | Where-Object {
        $_ -cin @($hostControllerApi.Parameters.Keys)
    }).Count -eq 0) `
    'HostHyperV exposes an arbitrary controller extension boundary'
$controllerSet = @($hostControllerApi.Parameters.Controller.Attributes |
    Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } |
    ForEach-Object { @($_.ValidValues) })
Assert-True (($controllerSet -join '|') -ceq
    'MainCampaign|MainProbe|MainProbeWorker|MainWorker|HardKill') `
    'HostHyperV fixed controller set changed'

$expectedProfiles = @(
    'fragments', 'dual-stack-dns', 'udp-policy', 'scheduler-ring-full',
    'network-reset', 'restart-stress'
)
Assert-True (
    (@(Get-Ferrum2QualificationProfiles) -join '|') -ceq ($expectedProfiles -join '|')
) 'the closed six-profile set changed'
Assert-True ((@(Get-Ferrum2QualificationSuiteProfiles -Suite Core) -join '|') -ceq
    'fragments|dual-stack-dns|udp-policy|scheduler-ring-full' -and
    (@(Get-Ferrum2QualificationSuiteProfiles -Suite Endurance) -join '|') -ceq
        'network-reset|restart-stress' -and
    (@(Get-Ferrum2QualificationSuiteProfiles -Suite Release) -join '|') -ceq
        ($expectedProfiles -join '|')) 'qualification suite order changed'
$restart = Resolve-Ferrum2QualificationProfile -Profile 'restart-stress'
Assert-True ((@($restart.PSObject.Properties.Name) -join '|') -ceq
        'profile|cycle_limit|release_milestones' -and
    $restart.profile -ceq 'restart-stress' -and $restart.cycle_limit -eq 1000 -and
    (@($restart.release_milestones) -join '|') -ceq '10|100|1000') `
    'restart profile mapping changed'
$reset = Resolve-Ferrum2QualificationProfile -Profile 'network-reset'
Assert-True ($reset.profile -ceq 'network-reset' -and $reset.cycle_limit -eq 1000 -and
    (@($reset.release_milestones) -join '|') -ceq '10|100|1000') 'network-reset profile mapping changed'
$validationReset = Resolve-Ferrum2QualificationProfile -Profile 'network-reset' `
    -ValidationCycleLimit 1
$validationRestart = Resolve-Ferrum2QualificationProfile -Profile 'restart-stress' `
    -ValidationCycleLimit 3
$validationCore = Resolve-Ferrum2QualificationProfile -Profile 'fragments' `
    -ValidationCycleLimit 3
Assert-True ($validationReset.cycle_limit -eq 1 -and
    (@($validationReset.release_milestones) -join '|') -ceq '1' -and
    $validationRestart.cycle_limit -eq 3 -and
    (@($validationRestart.release_milestones) -join '|') -ceq '1|3' -and
    $validationCore.cycle_limit -eq 0 -and
    @($validationCore.release_milestones).Count -eq 0) `
    'script-validation profile mapping changed'
Assert-Throws {
    Resolve-Ferrum2QualificationProfile -Profile 'network-reset' `
        -ValidationCycleLimit 11
} 'script-validation cycle boundary'
Assert-Throws { Resolve-Ferrum2QualificationProfile -Profile 'hard-kill' } `
    'hard-kill main-profile separation'

Assert-Throws {
    Assert-Ferrum2ClosedProperties ([pscustomobject][ordered]@{ a = 1; b = 2 }) @('a') 'synthetic'
} 'closed property set'

$sourceContractRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ferrum2-source-contract-' + [Guid]::NewGuid().ToString('N')
)
$sourceContractDefinitions = @(
    [pscustomobject][ordered]@{
        role = 'one'; path = 'tools/lab/one.ps1'; content = "'one'"
    }
    [pscustomobject][ordered]@{
        role = 'two'; path = 'tools/lab/two.ps1'; content = "'two'"
    }
)
try {
    $validFixture = New-TestClosedSourceFixture `
        -Root (Join-Path $sourceContractRoot 'valid') `
        -Definitions $sourceContractDefinitions
    $expectedSourceFiles = @($sourceContractDefinitions | ForEach-Object {
        [pscustomobject][ordered]@{ role = $_.role; path = $_.path }
    })
    $validIdentity = Read-Ferrum2ClosedSourceManifest `
        -Path $validFixture.ManifestPath `
        -RepositoryRoot $validFixture.RepositoryRoot `
        -RequiredRoot $validFixture.RequiredRoot `
        -Schema $validFixture.Schema -EntryPoint $validFixture.EntryPoint `
        -ExpectedFiles $expectedSourceFiles
    Assert-True ($validIdentity.SourceBundleSha256 -cmatch '^[0-9a-f]{64}$') `
        'closed source manifest did not validate its exact bytes'
    $bootstrapIdentity = Read-Ferrum2BootstrapSourceClosure `
        -ManifestPath $validFixture.ManifestPath `
        -BundleRoot $validFixture.RepositoryRoot `
        -RequiredRoot $validFixture.RequiredRoot `
        -ExpectedSchema $validFixture.Schema `
        -ExpectedEntrypoint $validFixture.EntryPoint `
        -Format Role -ExpectedMembers $expectedSourceFiles
    Assert-True ($bootstrapIdentity.Members.Count -eq 2 -and
        ($bootstrapIdentity.Sources.Keys -join '|') -ceq 'one|two' -and
        [string]$bootstrapIdentity.Sources['one'].Text -ceq "'one'`n" -and
        $bootstrapIdentity.Sources['one'].Bytes.Length -gt 0) `
        'bootstrap role closure did not return the verified bytes and text'

    $flatFiles = @($sourceContractDefinitions | ForEach-Object {
        $path = Join-Path $validFixture.RepositoryRoot `
            $_.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [byte[]]$bytes = [IO.File]::ReadAllBytes($path)
        [pscustomobject][ordered]@{
            path = [string]$_.path
            bytes = [long]$bytes.Length
            sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
        }
    })
    $flatManifest = [pscustomobject][ordered]@{
        schema_version = [long]1
        kind = 'ferrum2.test-flat-source-bundle.v1'
        entrypoint = $validFixture.EntryPoint
        files = $flatFiles
    }
    $flatManifestPath = Join-Path `
        (Split-Path -Parent $validFixture.ManifestPath) 'flat-source.json'
    [byte[]]$flatManifestBytes = ConvertTo-TestJsonBytes $flatManifest
    [IO.File]::WriteAllBytes($flatManifestPath, $flatManifestBytes)
    $flatExpectedPaths = @($flatFiles.path)
    $flatIdentity = Read-Ferrum2BootstrapFlatSourceClosure `
        -ManifestPath $flatManifestPath -ManifestBytes $flatManifestBytes `
        -RepositoryRoot $validFixture.RepositoryRoot `
        -RequiredRoot $validFixture.RequiredRoot `
        -ExpectedKind $flatManifest.kind `
        -ExpectedEntrypoint $flatManifest.entrypoint `
        -ExpectedPaths $flatExpectedPaths
    Assert-True ($flatIdentity.Members.Count -eq 2 -and
        $flatIdentity.ManifestBytes.Length -eq $flatManifestBytes.Length -and
        [string]$flatIdentity.Sources[$flatManifest.entrypoint].Text -ceq "'one'`n") `
        'flat source closure did not return the verified manifest and member bytes'

    $missingEntrypointManifest = [pscustomobject][ordered]@{
        schema_version = [long]1
        kind = $flatManifest.kind
        entrypoint = $flatManifest.entrypoint
        files = @($flatFiles | Where-Object {
            [string]$_.path -cne [string]$flatManifest.entrypoint
        })
    }
    Assert-Throws {
        Read-Ferrum2BootstrapFlatSourceClosure `
            -ManifestPath $flatManifestPath `
            -ManifestBytes (ConvertTo-TestJsonBytes $missingEntrypointManifest) `
            -RepositoryRoot $validFixture.RepositoryRoot `
            -RequiredRoot $validFixture.RequiredRoot `
            -ExpectedKind $flatManifest.kind `
            -ExpectedEntrypoint $flatManifest.entrypoint `
            -ExpectedPaths @($missingEntrypointManifest.files.path)
    } 'flat source missing entrypoint member'

    $replacementPath = 'tools/lab/replacement.ps1'
    $replacementSourcePath = Join-Path $validFixture.RepositoryRoot `
        $replacementPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    [byte[]]$replacementBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        "'replacement'`n"
    )
    [IO.File]::WriteAllBytes($replacementSourcePath, $replacementBytes)
    $replacementFiles = @($flatFiles | ForEach-Object {
        if ([string]$_.path -ceq [string]$flatManifest.entrypoint) {
            [pscustomobject][ordered]@{
                path = $replacementPath
                bytes = [long]$replacementBytes.Length
                sha256 = [Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($replacementBytes)
                ).ToLowerInvariant()
            }
        } else { $_ }
    })
    $replacedEntrypointManifest = [pscustomobject][ordered]@{
        schema_version = [long]1
        kind = $flatManifest.kind
        entrypoint = $flatManifest.entrypoint
        files = $replacementFiles
    }
    Assert-Throws {
        Read-Ferrum2BootstrapFlatSourceClosure `
            -ManifestPath $flatManifestPath `
            -ManifestBytes (ConvertTo-TestJsonBytes $replacedEntrypointManifest) `
            -RepositoryRoot $validFixture.RepositoryRoot `
            -RequiredRoot $validFixture.RequiredRoot `
            -ExpectedKind $flatManifest.kind `
            -ExpectedEntrypoint $flatManifest.entrypoint `
            -ExpectedPaths @($replacementFiles.path)
    } 'flat source replaced entrypoint member'

    [IO.File]::AppendAllText(
        (Join-Path $validFixture.RepositoryRoot 'tools/lab/two.ps1'),
        "tamper`n",
        [Text.UTF8Encoding]::new($false)
    )
    Assert-Throws {
        Read-Ferrum2ClosedSourceManifest -Path $validFixture.ManifestPath `
            -RepositoryRoot $validFixture.RepositoryRoot `
            -RequiredRoot $validFixture.RequiredRoot `
            -Schema $validFixture.Schema -EntryPoint $validFixture.EntryPoint `
            -ExpectedFiles $expectedSourceFiles
    } 'closed source byte tamper'
    Assert-Throws {
        Read-Ferrum2BootstrapSourceClosure `
            -ManifestPath $validFixture.ManifestPath `
            -BundleRoot $validFixture.RepositoryRoot `
            -RequiredRoot $validFixture.RequiredRoot `
            -ExpectedSchema $validFixture.Schema `
            -ExpectedEntrypoint $validFixture.EntryPoint `
            -Format Role -ExpectedMembers $expectedSourceFiles
    } 'bootstrap role source byte tamper'

    $escapeDefinitions = @([pscustomobject][ordered]@{
        role = 'one'; path = 'outside.ps1'; content = "'escape'"
    })
    $escapeFixture = New-TestClosedSourceFixture `
        -Root (Join-Path $sourceContractRoot 'escape') `
        -Definitions $escapeDefinitions
    Assert-Throws {
        Read-Ferrum2ClosedSourceManifest -Path $escapeFixture.ManifestPath `
            -RepositoryRoot $escapeFixture.RepositoryRoot `
            -RequiredRoot $escapeFixture.RequiredRoot `
            -Schema $escapeFixture.Schema -EntryPoint $escapeFixture.EntryPoint `
            -ExpectedFiles @([pscustomobject][ordered]@{
                role = 'one'; path = 'outside.ps1'
            })
    } 'closed source required-root escape'

    $traversalDefinitions = @([pscustomobject][ordered]@{
        role = 'one'; path = 'tools/lab/../outside.ps1'; content = "'traversal'"
    })
    $traversalFixture = New-TestClosedSourceFixture `
        -Root (Join-Path $sourceContractRoot 'traversal') `
        -Definitions $traversalDefinitions
    Assert-Throws {
        Read-Ferrum2ClosedSourceManifest -Path $traversalFixture.ManifestPath `
            -RepositoryRoot $traversalFixture.RepositoryRoot `
            -RequiredRoot $traversalFixture.RequiredRoot `
            -Schema $traversalFixture.Schema -EntryPoint $traversalFixture.EntryPoint `
            -ExpectedFiles @([pscustomobject][ordered]@{
                role = 'one'; path = 'tools/lab/../outside.ps1'
            })
    } 'closed source noncanonical traversal'

    $orderedFixture = New-TestClosedSourceFixture `
        -Root (Join-Path $sourceContractRoot 'order') `
        -Definitions @($sourceContractDefinitions[1], $sourceContractDefinitions[0])
    Assert-Throws {
        Read-Ferrum2ClosedSourceManifest -Path $orderedFixture.ManifestPath `
            -RepositoryRoot $orderedFixture.RepositoryRoot `
            -RequiredRoot $orderedFixture.RequiredRoot `
            -Schema $orderedFixture.Schema -EntryPoint $orderedFixture.EntryPoint `
            -ExpectedFiles $expectedSourceFiles
    } 'closed source role order'
} finally {
    if (Test-Path -LiteralPath $sourceContractRoot) {
        Remove-Item -LiteralPath $sourceContractRoot -Recurse -Force
    }
}

$labRuntimePath = Join-Path $repositoryRoot `
    'tools/windows-tun/lab/windows_tun_hyperv_support_topology_runtime.ps1'
$labRuntimeAst = Get-ScriptAst $labRuntimePath
$labRuntimeCommands = @(Get-AstCommandName $labRuntimeAst)
$forbiddenLabRuntimeCommands = @(
    'New-VMSwitch', 'Set-VMSwitch', 'Remove-VMSwitch',
    'Add-VMNetworkAdapter', 'Set-VMNetworkAdapter', 'Remove-VMNetworkAdapter',
    'Start-VM', 'Stop-VM', 'Restore-VMSnapshot', 'Checkpoint-VM',
    'New-NetIPAddress', 'Remove-NetIPAddress', 'New-NetRoute', 'Remove-NetRoute',
    'Set-DnsClientServerAddress'
)
Assert-True (@($forbiddenLabRuntimeCommands | Where-Object {
    $_ -cin $labRuntimeCommands
}).Count -eq 0) 'Lab runtime contains a topology mutation command'
$runtimeDotSources = @($labRuntimeAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Dot
}, $true))
Assert-True ($runtimeDotSources.Count -eq 1 -and
    $runtimeDotSources[0].Extent.Text -cmatch
        '^\.\s+\$script:ferrum2TopologyReadonlyPath\s+-LibraryOnly') `
    'Lab runtime loads an owner other than the pure read-only topology owner'

$provisioningDriverPath = Join-Path $repositoryRoot `
    'tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1'
$provisioningDriverText = Get-Content -LiteralPath $provisioningDriverPath -Raw -Encoding utf8
$bootstrapReadOffset = $provisioningDriverText.IndexOf(
    '[byte[]]$bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)'
)
$bootstrapHashOffset = $provisioningDriverText.IndexOf(
    '[Security.Cryptography.SHA256]::HashData($bootstrapBytes)'
)
$bootstrapLoadOffset = $provisioningDriverText.IndexOf(
    '[Text.UTF8Encoding]::new($false, $true).GetString($bootstrapBytes)'
)
$bootstrapIdentityOffset = $provisioningDriverText.IndexOf(
    '$script:provisioningSourceIdentity = Read-ProvisioningSourceIdentity'
)
$bootstrapSelfOffset = $provisioningDriverText.IndexOf(
    'Assert-Ferrum2BootstrapControllerSelfMember'
)
$bootstrapModuleOffset = $provisioningDriverText.IndexOf('$verifiedLabModule = New-Module')
$bootstrapImportOffset = $provisioningDriverText.IndexOf('Import-Module $verifiedLabModule')
$bootstrapOwnerOffset = $provisioningDriverText.IndexOf(
    ". ([scriptblock]::Create(`n    [string]`$script:provisioningSourceIdentity.Sources['readonly'].Text"
)
Assert-True ($bootstrapReadOffset -ge 0 -and
    $bootstrapReadOffset -lt $bootstrapHashOffset -and
    $bootstrapHashOffset -lt $bootstrapLoadOffset -and
    $bootstrapLoadOffset -lt $bootstrapIdentityOffset -and
    $bootstrapIdentityOffset -lt $bootstrapSelfOffset -and
    $bootstrapSelfOffset -lt $bootstrapModuleOffset -and
    $bootstrapIdentityOffset -lt $bootstrapModuleOffset -and
    $bootstrapModuleOffset -lt $bootstrapImportOffset -and
    $bootstrapImportOffset -lt $bootstrapOwnerOffset -and
    $provisioningDriverText -cnotmatch
        'Assert-ProvisioningBootstrap|Resolve-ProvisioningBootstrapSource|Read-ProvisioningBootstrapClosure') `
    'provisioning driver did not reduce to the raw bootstrap trust root and verified closure'

$fileMap = @(
    Get-Ferrum2MainControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
$controller = [string]@($fileMap | Where-Object {
    [string]$_.relative_path -ceq 'qualify_windows_tun.ps1'
})[0].source_path
$bundle = New-Ferrum2ControllerBundleManifest `
    -FileMap $fileMap -EntryPoint 'qualify_windows_tun.ps1'
Assert-True ($bundle.schema -ceq 'ferrum2.windows-tun-controller-bundle.v1' -and
    [string]$bundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    @($bundle.files.path | Where-Object {
        $_ -cin @('qualify_windows_tun_cleanup.ps1', 'Main.GuestCleanupController.ps1')
    }).Count -eq 2 -and
    @($fileMap | Where-Object {
        [string]$_.relative_path -cmatch 'Ferrum2\.Qualification\.Evidence'
    }).Count -eq 0) 'main runtime controller bundle identity is invalid'
$liveGuestEntryAst = Get-ScriptAst (Join-Path $PSScriptRoot `
    'qualify_windows_tun.ps1')
$cleanupGuestEntryAst = Get-ScriptAst (Join-Path $PSScriptRoot `
    'qualify_windows_tun_cleanup.ps1')
foreach ($entryAst in @($liveGuestEntryAst, $cleanupGuestEntryAst)) {
    $entryParameters = @($entryAst.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath })
    Assert-True ('Profile' -cin $entryParameters -and 'Mode' -cnotin $entryParameters) `
        'main guest entrypoint does not expose the single profile dimension'
}
$liveGuestProfile = @($liveGuestEntryAst.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -ceq 'Profile'
})[0]
$liveProfileSet = @($liveGuestProfile.Attributes | Where-Object {
    $_ -is [Management.Automation.Language.AttributeAst] -and
        $_.TypeName.Name -ceq 'ValidateSet'
} | ForEach-Object {
    @($_.PositionalArguments | ForEach-Object { $_.SafeGetValue() })
})
Assert-True ('cleanup' -cnotin $liveProfileSet -and
    (@($liveProfileSet | Sort-Object) -join '|') -ceq
        (@($expectedProfiles | Sort-Object) -join '|')) `
    'live guest entrypoint accepts cleanup or a non-profile value'
$guestControllerSource = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\Main.GuestController.ps1') -Raw
$hostStageSource = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\Main.HostStage.ps1') -Raw
$hostGuestTransactionSource = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    'tests\platform\Main.HostGuestTransaction.ps1') -Raw
Assert-True ($guestControllerSource -cnotmatch 'Ferrum2\.Qualification\.Evidence' -and
    $hostStageSource -cnotmatch 'Ferrum2\.Qualification\.Evidence' -and
    $hostGuestTransactionSource -cnotmatch '\$inputFiles\.Count\s+-lt' -and
    $hostGuestTransactionSource -cnotmatch '\$inputDirectories\.Count\s+-ne\s+9') `
    'main guest runtime still imports or stages host-only Evidence policy'

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
Assert-True ($mainSourceBundle.entrypoint -ceq
        'tests/platform/run_windows_tun_hyperv.ps1' -and
    $hardSourceBundle.entrypoint -ceq
        'tests/platform/run_windows_tun_hard_kill_hyperv.ps1') `
    'qualification host source-bundle entrypoint changed'
Assert-True (
    [string]$mainSourceBundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    [string]$hardSourceBundle.controller_bundle_sha256 -cmatch '^[0-9a-f]{64}$' -and
    @($mainSourceBundle.files.path + $hardSourceBundle.files.path | Where-Object {
        $_ -cmatch 'Ferrum2\.Qualification\.Common|private/Facade\.ps1'
    }).Count -eq 0 -and
    -not (Test-Path -LiteralPath (Join-Path $moduleRoot `
        'Ferrum2.Qualification.Common')) -and
    -not (Test-Path -LiteralPath (Join-Path $moduleRoot `
        'Ferrum2.Qualification.HostHyperV\private\Facade.ps1'))
) 'main or hard host source-bundle identity is invalid'
$fixedMainHostSources = @(
    'tests/platform/run_windows_tun_hyperv.ps1'
    'tests/platform/probe_windows_tun_hyperv.ps1'
    'tests/platform/invoke_windows_tun_hyperv_probe_worker.ps1'
    'tests/platform/invoke_windows_tun_hyperv_worker.ps1'
    'tests/platform/Main.CampaignController.ps1'
    'tests/platform/Main.ProbeController.ps1'
    'tests/platform/Main.ProbeWorkerController.ps1'
    'tests/platform/Main.HostController.ps1'
)
Assert-True (@($fixedMainHostSources | Where-Object {
    $_ -cnotin @($mainSourceBundle.files.path)
}).Count -eq 0) 'main source bundle omits a fixed host controller entrypoint'
$labSourcePaths = @(
    'tools/powershell/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
    'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psd1'
    'tools/powershell/Ferrum2.WindowsTun.Lab/Ferrum2.WindowsTun.Lab.psm1'
    'tools/powershell/Ferrum2.WindowsTun.Lab/private/JsonSource.ps1'
    'tools/powershell/Ferrum2.WindowsTun.Lab/private/BundleFileSystem.ps1'
    'tools/powershell/Ferrum2.WindowsTun.Lab/private/VmSession.ps1'
    'tools/windows-tun/lab/get_windows_tun_guest_network_path.ps1'
    'tools/windows-tun/lab/windows_tun_host_network_path.ps1'
    'tools/windows-tun/lab/windows_tun_hyperv_support_topology_readonly.ps1'
    'tools/windows-tun/lab/windows_tun_hyperv_support_topology_runtime.ps1'
)
foreach ($manifest in @($mainSourceBundle, $hardSourceBundle)) {
    Assert-True (@($labSourcePaths | Where-Object {
        $_ -cnotin @($manifest.files.path)
    }).Count -eq 0) 'qualification source bundle omits a directly loaded Lab source'
}
Assert-Throws {
    Invoke-Ferrum2QualificationHostController `
        -RepositoryRoot $repositoryRoot -Controller MainWorker `
        -Context ([ordered]@{})
} 'closed fixed main host controller context'

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

foreach ($runnerContract in @(
    @('run_windows_tun_hyperv.ps1', 'MainCampaign'),
    @('probe_windows_tun_hyperv.ps1', 'MainProbe'),
    @('invoke_windows_tun_hyperv_probe_worker.ps1', 'MainProbeWorker'),
    @('invoke_windows_tun_hyperv_worker.ps1', 'MainWorker'),
    @('run_windows_tun_hard_kill_hyperv.ps1', 'HardKill')
)) {
    $runnerAst = Get-ScriptAst (Join-Path $PSScriptRoot $runnerContract[0])
    $controllerArguments = @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandParameterAst] -and
            $node.ParameterName -ceq 'Controller'
    }, $true))
    Assert-True ($controllerArguments.Count -eq 1 -and
        $controllerArguments[0].Parent.Extent.Text -cmatch
            ("-Controller\s+" + [regex]::Escape($runnerContract[1]) + '(\s|$)')) `
        "host runner fixed-controller contract changed: $($runnerContract[0])"

    $runnerCommands = @($runnerAst.FindAll({
        param($node) $node -is [Management.Automation.Language.CommandAst]
    }, $true))
    $bundleVerifiers = @($runnerCommands | Where-Object {
        $_.GetCommandName() -ceq 'Read-Ferrum2BootstrapSourceClosure'
    })
    $selfVerifiers = @($runnerCommands | Where-Object {
        $_.GetCommandName() -ceq 'Assert-Ferrum2BootstrapControllerSelfMember'
    })
    $moduleImports = @($runnerCommands | Where-Object {
        $_.GetCommandName() -ceq 'Import-Module'
    })
    $runnerRelativeAssignments = @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$runnerRelative'
    }, $true))
    $expectedRunnerRelative = 'tests/platform/' + $runnerContract[0]
    $runnerRelativeValues = @($runnerRelativeAssignments | ForEach-Object {
        $_.Right.FindAll({
            param($node)
            $node -is [Management.Automation.Language.StringConstantExpressionAst]
        }, $true) | ForEach-Object { $_.Value }
    })
    $runnerText = Get-Content -LiteralPath (Join-Path $PSScriptRoot `
        $runnerContract[0]) -Raw -Encoding utf8
    $bootstrapReadOffset = $runnerText.IndexOf(
        '[byte[]]$bootstrapBytes = [IO.File]::ReadAllBytes($bootstrapPath)'
    )
    $bootstrapHashOffset = $runnerText.IndexOf(
        '[Security.Cryptography.SHA256]::HashData($bootstrapBytes)'
    )
    $bootstrapLoadOffset = $runnerText.IndexOf(
        '[Text.UTF8Encoding]::new($false, $true).GetString($bootstrapBytes)'
    )
    Assert-True ($bundleVerifiers.Count -eq 1 -and
        $selfVerifiers.Count -eq 1 -and $moduleImports.Count -eq 1 -and
        $runnerRelativeAssignments.Count -eq 1 -and
        $runnerRelativeValues.Count -eq 1 -and
        $runnerRelativeValues[0] -ceq $expectedRunnerRelative -and
        $bootstrapReadOffset -ge 0 -and
        $bootstrapReadOffset -lt $bootstrapHashOffset -and
        $bootstrapHashOffset -lt $bootstrapLoadOffset -and
        $bootstrapLoadOffset -lt
            $bundleVerifiers[0].Extent.StartOffset -and
        $bundleVerifiers[0].Extent.StartOffset -lt
            $selfVerifiers[0].Extent.StartOffset -and
        $selfVerifiers[0].Extent.StartOffset -lt
            $moduleImports[0].Extent.StartOffset) `
        "host runner bootstrap/source/import trust order changed: $($runnerContract[0])"
}

$mainInitializerOwners = [Collections.Generic.List[string]]::new()
foreach ($source in Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'Main.*.ps1' -File) {
    $ast = Get-ScriptAst $source.FullName
    if ('Build-Ferrum2CandidateArtifactBundle' -cin @(Get-AstCommandName $ast)) {
        $mainInitializerOwners.Add($source.Name)
    }
}
Assert-True (($mainInitializerOwners -join '|') -ceq 'Main.CampaignController.ps1') `
    'the main campaign is not the single Main candidate artifact initializer owner'

$mainRunnerPath = Join-Path $PSScriptRoot 'run_windows_tun_hyperv.ps1'
$mainRunnerAst = Get-ScriptAst $mainRunnerPath
$mainRunnerParameters = @($mainRunnerAst.ParamBlock.Parameters |
    ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-True ('Suite' -cin $mainRunnerParameters -and
    'ValidationOnly' -cin $mainRunnerParameters -and
    'ValidationCycleLimit' -cin $mainRunnerParameters -and
    'CampaignToken' -cin $mainRunnerParameters -and
    'TopologyPlanPath' -cin $mainRunnerParameters -and
    @('Profile', 'ProbeOnly', 'InternalWorker', 'CandidateArtifactManifest' |
        Where-Object { $_ -cin $mainRunnerParameters }).Count -eq 0) `
    'public main runner exposes a non-campaign operation'
$workerAst = Get-ScriptAst (Join-Path $PSScriptRoot `
    'invoke_windows_tun_hyperv_worker.ps1')
$workerParameters = @($workerAst.ParamBlock.Parameters |
    ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-True (@('InternalWorker', 'InternalWorkerToken', 'Profile',
        'ValidationOnly', 'ValidationCycleLimit', 'CandidateArtifactManifest',
        'TopologyPlanPath' | Where-Object {
            $_ -cnotin $workerParameters
        }).Count -eq 0) 'main capability worker contract is incomplete'

foreach ($configuredEntrypoint in @(
    'probe_windows_tun_hyperv.ps1',
    'invoke_windows_tun_hyperv_probe_worker.ps1',
    'run_windows_tun_hard_kill_hyperv.ps1'
)) {
    $configuredAst = Get-ScriptAst (Join-Path $PSScriptRoot $configuredEntrypoint)
    $configuredParameters = @($configuredAst.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath })
    Assert-True ('TopologyPlanPath' -cin $configuredParameters) `
        "configured topology plan parameter is absent: $configuredEntrypoint"
}
$performanceRunnerInterfaceAst = Get-ScriptAst (Join-Path $repositoryRoot `
    'tools\windows-tun\performance\run_windows_tun_performance_host.ps1')
$performanceRunnerInterfaceParameters = @(
    $performanceRunnerInterfaceAst.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath }
)
$expectedPerformanceRunnerParameters = @(
    'PlanOnly', 'RecoveryOnly', 'SafetyCheck', 'Mode', 'BaselineSha',
    'CandidateSha', 'EvidenceDirectory', 'AcknowledgeHostNetworkMutation'
)
Assert-True (
    $performanceRunnerInterfaceParameters.Count -eq
        $expectedPerformanceRunnerParameters.Count -and
    @($expectedPerformanceRunnerParameters | Where-Object {
        $_ -cnotin $performanceRunnerInterfaceParameters
    }).Count -eq 0
) 'host performance runner public interface changed'
$topologyReadonlyValues = @(Get-AstStringValue (Get-ScriptAst (Join-Path $repositoryRoot `
    'tools\windows-tun\lab\windows_tun_hyperv_support_topology_readonly.ps1')))
Assert-True (@(
    '82e20295-1d30-48e7-a751-e21d35d872d4',
    '1e570209-faf7-4248-8167-aa0687cdb8cf',
    'c08cb7b8-9b3c-408e-8e30-5e16a3aeb444',
    '192.168.250.0/30', '192.168.250.1', '192.168.250.2'
    | Where-Object { $_ -cin $topologyReadonlyValues }
).Count -eq 0) 'topology plan reader still pins one host identity or subnet'
$mainHostControllerAst = Get-ScriptAst (Join-Path $PSScriptRoot `
    'Main.HostController.ps1')
Assert-True (@(Get-AstCommandName $mainHostControllerAst | Where-Object {
    $_ -ceq 'Read-Ferrum2CandidateArtifactBundle'
}).Count -eq 1) 'main transaction does not read the campaign candidate manifest'

$hardControllerAst = Get-ScriptAst (Join-Path $PSScriptRoot 'Hard.HostController.ps1')
$hardCommands = @(Get-AstCommandName $hardControllerAst)
Assert-True (@($hardCommands | Where-Object {
    $_ -ceq 'Build-Ferrum2CandidateArtifactBundle'
}).Count -eq 1 -and @($hardCommands | Where-Object {
    $_ -ceq 'Read-Ferrum2CandidateArtifactBundle'
}).Count -eq 1) 'hard-kill build-once supervisor/worker artifact ownership changed'

$hardRuntimeFileMap = @(
    Get-Ferrum2HardKillControllerBundleFileMap -RepositoryRoot $repositoryRoot
)
Assert-True ($hardRuntimeFileMap.Count -eq 21 -and
    @($hardRuntimeFileMap | Where-Object {
        [string]$_.relative_path -cmatch 'Ferrum2\.Qualification\.Evidence'
    }).Count -eq 0) 'hard-kill runtime controller bundle identity is invalid'
$qualificationPaths = @($fileMap.source_path) + @($hardRuntimeFileMap.source_path) + @(
    $mainSourceBundle.files.path | ForEach-Object {
        Join-Path $repositoryRoot $_.Replace('/', [IO.Path]::DirectorySeparatorChar)
    }
) + @($hardSourceBundle.files.path | ForEach-Object {
    Join-Path $repositoryRoot $_.Replace('/', [IO.Path]::DirectorySeparatorChar)
})
foreach ($path in @($qualificationPaths | Sort-Object -Unique | Where-Object {
    $_ -match '\.(ps1|psm1)$' -and
    $_ -notmatch 'Ferrum2[./\\]WindowsTun[./\\]Lab'
})) {
    $commands = @(Get-AstCommandName (Get-ScriptAst $path))
    Assert-True ('Invoke-Ferrum2HostVmLifecycle' -cnotin $commands) `
        "qualification directly owns the Lab VM lifecycle: $path"
}

$schemaValues = @(
    'Main.HostStage.ps1', 'Main.HostController.ps1',
    'Hard.HostTransaction.ps1', 'run_windows_tun_hard_kill_hyperv.ps1'
    | ForEach-Object {
        Get-AstStringValue (Get-ScriptAst (Join-Path $PSScriptRoot $_))
    }
)
$topologyReaderValues = @(
    Get-AstStringValue (Get-ScriptAst (Join-Path $PSScriptRoot 'Guest.Topology.ps1'))
    Get-AstStringValue (Get-ScriptAst (Join-Path $PSScriptRoot 'Hard.GuestEvidence.ps1'))
)
$currentTopologyIdentityFields = @(
    'provisioning_source_manifest_sha256', 'provisioning_source_bundle_sha256'
)
$removedTopologyIdentityFields = @(
    'inspector_sha256', 'provisioning_library_sha256', 'provisioning_script_sha256'
)
Assert-True (@($currentTopologyIdentityFields | Where-Object {
        $_ -cnotin $topologyReaderValues
    }).Count -eq 0 -and @($removedTopologyIdentityFields | Where-Object {
        $_ -cin $topologyReaderValues
    }).Count -eq 0) `
    'guest topology readers do not use the closed provisioning source identity'
foreach ($schema in @(
    'ferrum2.windows-tun.hyperv-staged-input.v6',
    'ferrum2.windows-tun.hyperv-host-run.v7',
    'ferrum2.windows-tun.hard-kill-staged-input.v4',
    'ferrum2.windows-tun.hard-kill-hyperv-host-run.v4',
    'ferrum2.windows-tun.hard-kill-static-contract.v4'
)) {
    Assert-True ($schema -cin $schemaValues) "qualification schema is absent: $schema"
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
    'Connect-ApprovedGuest', 'Test-Ferrum2PathWithinRoot',
    'Assert-Ferrum2NoReparsePointInExistingPath', 'Resolve-Ferrum2OrdinaryFile',
    'Resolve-Ferrum2HostInput', 'New-Ferrum2HostVmIdentity',
    'Get-Ferrum2HostVmContext', 'Invoke-Ferrum2HostVmLifecycle',
    'Connect-Ferrum2HostGuest'
)
Assert-True (@($forbiddenOwners | Where-Object {
    $_ -cin $performanceOwners
}).Count -eq 0) 'performance PowerShell duplicated a HostHyperV owner'

$performanceRunnerPath = Join-Path $repositoryRoot `
    'tools\windows-tun\performance\run_windows_tun_performance_host.ps1'
$tokens = $null
$errors = $null
$performanceRunnerAst = [Management.Automation.Language.Parser]::ParseFile(
    $performanceRunnerPath, [ref]$tokens, [ref]$errors
)
Assert-True ($errors.Count -eq 0) 'performance runner parser failed'
$sourceAssignments = @($performanceRunnerAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$expectedPaths'
}, $true))
Assert-True ($sourceAssignments.Count -eq 1) `
    'performance source-map owner is missing or duplicated'
$expectedPerformancePaths = @($sourceAssignments[0].Right.FindAll({
    param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Value -cmatch '/'
}, $true) | ForEach-Object { $_.Value })
$performanceSourceBundlePath = Join-Path $repositoryRoot `
    'tools\powershell\Ferrum2.Performance\bundle.json'
$performanceSourceBundle = Get-Content -LiteralPath $performanceSourceBundlePath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 8 -ErrorAction Stop
$actualPerformancePaths = @($performanceSourceBundle.files.path)
Assert-True ($expectedPerformancePaths.Count -eq 9 -and
    @($expectedPerformancePaths | Where-Object {
        $_ -cnotin $actualPerformancePaths
    }).Count -eq 0 -and @($actualPerformancePaths | Where-Object {
        $_ -cnotin $expectedPerformancePaths
    }).Count -eq 0) 'performance source bundle is not the exact host-only set'
Assert-True (@($actualPerformancePaths | Where-Object {
    $_ -cmatch '(HyperV|Guest|Checkpoint|Topology|RuntimeStaging|Ferrum2\.WindowsTun\.Lab)'
}).Count -eq 0) 'performance source bundle retains a VM execution dependency'
$performanceSourceBundleHash = Assert-Ferrum2BootstrapSourceManifest `
    -ManifestPath $performanceSourceBundlePath -RepositoryRoot $repositoryRoot `
    -ExpectedKind 'ferrum2.windows-tun-performance-source-bundle.v2' `
    -ExpectedEntrypoint 'tools/windows-tun/performance/run_windows_tun_performance_host.ps1' `
    -ExpectedPaths $expectedPerformancePaths
Assert-True ($performanceSourceBundleHash -cmatch '^[0-9a-f]{64}$') `
    'performance source-bundle identity is invalid'

$identityPaths = @($mainSourceBundle.files.path) +
    @($hardSourceBundle.files.path) + @($performanceSourceBundle.files.path) + @(
        'tests/platform/main-source-bundle.json'
        'tests/platform/hard-source-bundle.json'
        'tools/powershell/Ferrum2.Performance/bundle.json'
    )
Assert-CanonicalLf -RepositoryRoot $repositoryRoot -Paths $identityPaths

$hardFileMap = @(
    $hardRuntimeFileMap
)
$hardBundle = New-Ferrum2ControllerBundleManifest `
    -FileMap $hardFileMap -EntryPoint 'qualify_windows_tun_hard_kill.ps1'
Assert-True (@($hardBundle.files).Count -eq 21 -and
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
        'modules\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1'
    [IO.File]::AppendAllText($tamperPath, "`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws {
        Assert-Ferrum2ControllerBundleManifest -Manifest $bundle -BundleRoot $temporaryRoot
    } 'controller bundle tamper'

    $hostSourceRoot = Join-Path $temporaryRoot 'host-source'
    foreach ($relativePath in @($mainSourceBundle.files.path)) {
        $source = Join-Path $repositoryRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $destination = Join-Path $hostSourceRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    $hostManifestPath = Join-Path $hostSourceRoot `
        'tests\platform\main-source-bundle.json'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $hostManifestPath)) | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot `
        'tests\platform\main-source-bundle.json') -Destination $hostManifestPath
    [void](Assert-Ferrum2BootstrapControllerBundle `
        -ManifestPath $hostManifestPath -BundleRoot $hostSourceRoot)

    foreach ($relativePath in @(
        'tools/powershell/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
        'tests/platform/run_windows_tun_hyperv.ps1'
        'tests/platform/probe_windows_tun_hyperv.ps1'
        'tests/platform/invoke_windows_tun_hyperv_probe_worker.ps1'
        'tests/platform/invoke_windows_tun_hyperv_worker.ps1'
    )) {
        $tamperedHostSource = Join-Path $hostSourceRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [IO.File]::AppendAllText(
            $tamperedHostSource,
            "`n# static tamper`n",
            [Text.UTF8Encoding]::new($false)
        )
        Assert-Throws {
            Assert-Ferrum2BootstrapControllerBundle `
                -ManifestPath $hostManifestPath -BundleRoot $hostSourceRoot
        } "host source-bundle tamper: $relativePath"
        Copy-Item -LiteralPath (Join-Path $repositoryRoot `
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)) `
            -Destination $tamperedHostSource -Force
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
    if (Test-Path -LiteralPath $mismatchRoot) {
        [IO.Directory]::Delete($mismatchRoot, $true)
    }
}

$nativeTypePaths = @(
    'Guest.NativeProcess.cs.ps1',
    'Guest.NativeTransport.cs.ps1',
    'Guest.NativeNetwork.cs.ps1'
) | ForEach-Object {
    (Join-Path $PSScriptRoot $_).Replace("'", "''")
}
$nativeTypeScript = @(
    "`$ErrorActionPreference = 'Stop'"
) + @($nativeTypePaths | ForEach-Object {
    ". '$_'"
}) + @("Write-Output 'native_types=PASS'")
$nativeTypeEncoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes(($nativeTypeScript -join "`n"))
)
$nativeTypeRows = @(& (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source `
    -NoProfile -NonInteractive -EncodedCommand $nativeTypeEncoded 2>&1)
$nativeTypeExit = $LASTEXITCODE
Assert-True ($nativeTypeExit -eq 0 -and $nativeTypeRows.Count -eq 1 -and
    [string]$nativeTypeRows[0] -ceq 'native_types=PASS') `
    'guest native helper C# sources do not compile as one controller load sequence'

Write-Output 'qualification_modules status=PASS profiles=6 cleanup=independent hard_kill=independent'
