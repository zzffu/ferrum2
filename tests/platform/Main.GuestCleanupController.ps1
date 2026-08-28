param(
    [Parameter(Mandatory)] [string]$Profile,
    [Parameter(Mandatory)] [string]$RunToken,
    [Parameter(Mandatory)] [string]$ClientBinary,
    [Parameter(Mandatory)] [string]$ServerBinary,
    [Parameter(Mandatory)] [string]$ProductRoot,
    [Parameter(Mandatory)] [string]$ArtifactDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$controllerBundleManifestPath = Join-Path $PSScriptRoot 'controller-bundle.json'
if (-not (Test-Path -LiteralPath $controllerBundleManifestPath -PathType Leaf)) {
    throw 'controller bundle manifest is required'
}
$controllerBundleManifest = Get-Content -LiteralPath $controllerBundleManifestPath `
    -Raw -Encoding utf8 | ConvertFrom-Json -Depth 8 -ErrorAction Stop
$bootstrapRelative = 'modules/Ferrum2.WindowsTun.Lab/BundleBootstrap.ps1'
$bootstrapEntry = @($controllerBundleManifest.files | Where-Object {
    [string]$_.path -ceq $bootstrapRelative
})
$bootstrapPath = Join-Path $PSScriptRoot `
    $bootstrapRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
if ($bootstrapEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).
        Hash.ToLowerInvariant() -cne [string]$bootstrapEntry[0].sha256) {
    throw 'main cleanup controller bundle bootstrap changed'
}
. $bootstrapPath
[void](Assert-Ferrum2BootstrapControllerBundle `
    -ManifestPath $controllerBundleManifestPath -BundleRoot $PSScriptRoot)
Import-Module (Join-Path $PSScriptRoot `
    'modules\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1') `
    -Scope Local -Force -ErrorAction Stop
$cleanupEntry = @($controllerBundleManifest.files | Where-Object {
    [string]$_.path -ceq 'qualify_windows_tun_cleanup.ps1'
})
if ($cleanupEntry.Count -ne 1) {
    throw 'main cleanup entrypoint is absent from the controller bundle'
}
if (-not $IsWindows -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Windows AMD64 is required'
}
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if ($computerSystem.Manufacturer -cne 'Microsoft Corporation' -or
    $computerSystem.Model -cne 'Virtual Machine') {
    throw 'Windows TUN cleanup must run inside the isolated Hyper-V guest'
}

$expectedDllHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$runIdentity = $RunToken
if ($runIdentity -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') {
    throw 'RunToken is invalid'
}
$resolvedProductRoot = [IO.Path]::GetFullPath($ProductRoot).TrimEnd('\', '/')
$binary = [IO.Path]::GetFullPath($ClientBinary).TrimEnd('\', '/')
$serverBinary = [IO.Path]::GetFullPath($ServerBinary).TrimEnd('\', '/')
$clientBinaryExplicit = $true
$serverBinaryExplicit = $true
$work = Join-Path ([IO.Path]::GetTempPath()) "ferrum2-m17-tun-$runIdentity"
$siblingDll = Join-Path (Split-Path -Parent $binary) 'wintun.dll'
$dllJournal = Join-Path $work 'owned-wintun-dll.txt'
$m17NetworkMutationJournal = Join-Path $work 'm17-network-mutations'
$m17UdpFirewallRuleName = "Ferrum2-M17-UDP-$runIdentity"
$controllerProgram = [IO.Path]::GetFullPath((Get-Process -Id $PID -ErrorAction Stop).Path)
$runIdentityJournalRoot = Join-Path `
    ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) `
    'Ferrum2\ControllerRunIdentities'
$runIdentityJournalPath = Join-Path $runIdentityJournalRoot "$runIdentity.json"

. (Join-Path $PSScriptRoot 'Guest.Identity.ps1')
. (Join-Path $PSScriptRoot 'Guest.Cleanup.ps1')

$cleanupWorks = @(Get-ControllerWorkPaths)
$identity = $null
if (Test-Path -LiteralPath $runIdentityJournalPath -PathType Leaf) {
    $identity = Read-RunIdentityJournal $runIdentityJournalPath $cleanupWorks
    Assert-True ($identity.Document.profile -ceq $Profile) `
        'cleanup journal profile differs from the requested profile'
}
$presentWorks = @($cleanupWorks | Where-Object { Test-Path -LiteralPath $_ })
Assert-True ($null -ne $identity -or $presentWorks.Count -eq 0) `
    'controller work exists without a durable identity journal'
$executables = if ($null -eq $identity) {
    @($binary, $serverBinary)
} else { @($identity.ClientPath, $identity.ServerPath) }
foreach ($cleanupWork in $cleanupWorks) {
    foreach ($process in @(Get-ExactRunProcesses $cleanupWork $executables)) {
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
    }
}
$deadline = [DateTime]::UtcNow.AddSeconds(20)
do {
    $processResidue = @($cleanupWorks | ForEach-Object {
        Get-ExactRunProcesses $_ $executables
    }).Count
    $adapterResidue = @(Get-NetAdapter -Name "F2-M17-$runIdentity" `
        -IncludeHidden -ErrorAction SilentlyContinue).Count
    if ($processResidue -eq 0 -and $adapterResidue -eq 0) { break }
    Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
Assert-True ($processResidue -eq 0 -and $adapterResidue -eq 0) `
    'controller process or adapter residue'

if ($null -ne $identity) {
    $addressJournal = Join-Path $identity.WorkPath 'owned-target-addresses.txt'
    if (Test-Path -LiteralPath $addressJournal -PathType Leaf) {
        foreach ($address in @(Get-Content -LiteralPath $addressJournal)) {
            if ($address -cnotin @('192.0.2.241', '192.0.2.242', '2001:db8::241')) {
                throw 'target address journal is invalid'
            }
            $prefix = if ($address.Contains(':')) { "$address/128" } else { "$address/32" }
            Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address `
                -ErrorAction SilentlyContinue |
                Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    Restore-M17NetworkMutationJournal `
        -WorkPath $identity.WorkPath `
        -JournalPath (Join-Path $identity.WorkPath 'm17-network-mutations')
    if (Test-Path -LiteralPath $identity.DllMarkerPath -PathType Leaf) {
        Remove-OwnedSiblingDll $identity
    }
    if (Test-Path -LiteralPath $identity.WorkPath) {
        Assert-NotReparsePoint $identity.WorkPath 'controller work directory'
        Remove-Item -LiteralPath $identity.WorkPath -Recurse -Force -ErrorAction Stop
    }
}
Assert-True (-not (Get-NetFirewallRule -Name $m17UdpFirewallRuleName `
    -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) `
    'controller UDP firewall rule residue'
Assert-True (@($cleanupWorks | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 0) `
    'controller work directory residue'
foreach ($address in @('192.0.2.241', '192.0.2.242', '2001:db8::241')) {
    $prefix = if ($address.Contains(':')) { "$address/128" } else { "$address/32" }
    Assert-True (-not (Get-NetIPAddress -InterfaceIndex 1 -IPAddress $address `
        -ErrorAction SilentlyContinue)) 'controller target address residue'
    Assert-True (-not (Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) `
        'controller target route residue'
}
if ($null -ne $identity) {
    Assert-True (-not (Test-Path -LiteralPath $identity.SiblingDllPath)) `
        'controller sibling DLL residue'
    Assert-True (-not (Test-Path -LiteralPath `
        (Join-Path $identity.WorkPath 'm17-network-mutations'))) `
        'controller mutation journal residue'
}

$artifactRoot = [IO.Path]::GetFullPath($ArtifactDirectory).TrimEnd('\', '/')
$artifactItem = Get-Item -LiteralPath $artifactRoot -Force -ErrorAction Stop
if (-not $artifactItem.PSIsContainer -or
    ($artifactItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'external cleanup artifact directory is invalid'
}
$identityLedgerPath = Join-Path $artifactRoot 'identity-ledger.json'
$resultPath = Join-Path $artifactRoot 'm17-result.json'
$result = Get-Content -LiteralPath $resultPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 10 -ErrorAction Stop
if ($result.schema -cne 'ferrum2.windows-tun.m17-result.v4' -or
    $result.profile -cne $Profile -or $result.run_token -cne $runIdentity -or
    $result.status -cne 'pass') {
    throw 'external cleanup result identity is invalid'
}
$identitySha256 = (Get-FileHash -LiteralPath $identityLedgerPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($result.identity_sha256 -cne $identitySha256) {
    throw 'external cleanup ledger identity changed'
}
$externalPath = Join-Path $artifactRoot 'external-cleanup.json'
$pendingExternalPath = "$externalPath.pending"
Assert-True (-not ((Test-Path -LiteralPath $externalPath) -and
    (Test-Path -LiteralPath $pendingExternalPath))) `
    'completed and pending external cleanup artifacts coexist'
$externalDocument = [ordered]@{
    schema = 'ferrum2.windows-tun.m17-external-cleanup.v1'
    status = 'pass'
    run_token = $runIdentity
    source_profile = $Profile
    identity_sha256 = $identitySha256
    processes = 0
    adapters = 0
    target_addresses = 0
    target_routes = 0
    sibling_dll = 0
    work_directories = 0
    mutation_journals = 0
    identity_journal = 0
    finished_utc = [DateTime]::UtcNow.ToString('o')
}
if (Test-Path -LiteralPath $externalPath -PathType Leaf) {
    $published = Get-Content -LiteralPath $externalPath -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 4 -ErrorAction Stop
    if ($published.schema -cne $externalDocument.schema -or
        $published.status -cne 'pass' -or
        $published.run_token -cne $runIdentity -or
        $published.source_profile -cne $Profile -or
        $published.identity_sha256 -cne $identitySha256) {
        throw 'published external cleanup artifact identity is invalid'
    }
    Assert-True (-not (Test-Path -LiteralPath $runIdentityJournalPath)) `
        'published external cleanup artifact coexists with its identity journal'
    return
}
if (-not (Test-Path -LiteralPath $pendingExternalPath)) {
    Write-Ferrum2JsonCreateNew `
        -Path $pendingExternalPath -Value $externalDocument -Depth 4
}
$pendingExternal = Get-Content -LiteralPath $pendingExternalPath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 4 -ErrorAction Stop
if ($pendingExternal.schema -cne $externalDocument.schema -or
    $pendingExternal.status -cne 'pass' -or
    $pendingExternal.run_token -cne $runIdentity -or
    $pendingExternal.source_profile -cne $Profile -or
    $pendingExternal.identity_sha256 -cne $identitySha256) {
    throw 'pending external cleanup artifact identity is invalid'
}
if (Test-Path -LiteralPath $runIdentityJournalPath) {
    Remove-Item -LiteralPath $runIdentityJournalPath -Force -ErrorAction Stop
}
Assert-True (-not (Test-Path -LiteralPath $runIdentityJournalPath)) `
    'run identity journal residue'
Move-Item -LiteralPath $pendingExternalPath -Destination $externalPath -ErrorAction Stop
