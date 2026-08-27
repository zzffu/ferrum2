[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ThrowsLike(
    [scriptblock]$Action,
    [string]$Pattern,
    [string]$Label
) {
    $failure = $null
    try { & $Action } catch { $failure = $_ }
    Assert-True ($null -ne $failure -and
        $failure.Exception.Message -match $Pattern) `
        "$Label did not fail with the expected message"
}

function New-HardKillWfpEvidence {
    $specs = @(
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701001"; Name = "Ferrum2 app permit IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701002"; Name = "Ferrum2 app permit IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701003"; Name = "Ferrum2 TUN permit IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701004"; Name = "Ferrum2 TUN permit IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_PERMIT" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701007"; Name = "Ferrum2 DNS TCP block IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701008"; Name = "Ferrum2 DNS UDP block IPv4"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e8701009"; Name = "Ferrum2 DNS TCP block IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK" },
        [pscustomobject]@{ Key = "a158b31d-7a59-40bc-9339-38b5e870100a"; Name = "Ferrum2 DNS UDP block IPv6"; Layer = "FWPM_LAYER_ALE_AUTH_CONNECT_V6"; Action = "FWP_ACTION_BLOCK" }
    )
    $ownerPid = [long]4242
    $interfaceLuid = "123456789"
    $appIdSha256 = "c" * 64
    $filters = [Collections.Generic.List[object]]::new()
    $rows = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $specs.Count; $index++) {
        $id = [string](10001 + $index)
        $spec = $specs[$index]
        $filters.Add([ordered]@{ key = $spec.Key; id = $id })
        $rows.Add(
            "$($spec.Name)|{$($spec.Key)}|$id|$($spec.Layer)|$($spec.Action)|" +
                "{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}"
        )
    }
    $sessionCanonical = (
        "session|{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}|" +
            "Ferrum2 strict route dynamic session|$ownerPid"
    )
    $canonical = (@(
        $sessionCanonical,
        "interface_luid|$interfaceLuid",
        "app_id_sha256|$appIdSha256"
    ) + @($rows)) -join "`n"
    $sha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.UTF8Encoding]::new($false).GetBytes($canonical)
        )
    ).ToLowerInvariant()
    return [ordered]@{
        applicable = $true
        before_kill = [ordered]@{
            session_key = "8ea35b4e-6629-4e26-9776-95c5bf9c6b01"
            sublayer_key = "ddbc2fa2-d52f-4a79-8a63-8446c308cf02"
            owner_pid = $ownerPid
            interface_luid = $interfaceLuid
            app_id_sha256 = $appIdSha256
            filters = @($filters)
            identity_sha256 = $sha256
        }
        after_kill = [ordered]@{
            session = "absent"
            sublayer = "absent"
            filters = "absent"
        }
    }
}

function Write-HardKillEvidence([string]$Path, [bool]$TamperHash = $false) {
    $wfp = New-HardKillWfpEvidence
    if ($TamperHash) {
        $wfp.before_kill.identity_sha256 = "0" * 64
    }
    $timestamp = "2026-08-25T00:00:00.0000000Z"
    $rows = @(
        [ordered]@{
            schema = 2
            phase = "hard-kill-auto-route"
            timestamp_utc = $timestamp
            data = [ordered]@{
                process = "absent"; adapter = "absent"; addresses = "absent"
                routes = "absent"; dns = "absent"
                strict_route_wfp = [ordered]@{ applicable = $false }
            }
        },
        [ordered]@{
            schema = 2
            phase = "hard-kill-auto-dns"
            timestamp_utc = $timestamp
            data = [ordered]@{
                process = "absent"; adapter = "absent"; addresses = "absent"
                routes = "absent"; dns = "absent"; strict_route_wfp = $wfp
            }
        },
        [ordered]@{
            schema = 2
            phase = "hard-kill-mixed"
            timestamp_utc = $timestamp
            data = [ordered]@{
                process = "absent"; adapter = "absent"; addresses = "absent"
                routes = "absent"; dns = "absent"
                strict_route_wfp = New-HardKillWfpEvidence
            }
        }
    )
    $text = (@($rows | ForEach-Object {
        $_ | ConvertTo-Json -Compress -Depth 12
    }) -join "`n") + "`n"
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..") `
    -ErrorAction Stop).Path
$mainRunnerPath = Join-Path $PSScriptRoot "run_windows_tun_hyperv.ps1"
$hardKillHostPath = Join-Path $PSScriptRoot "run_windows_tun_hard_kill_hyperv.ps1"
$guestWrapperPath = Join-Path $PSScriptRoot "invoke_windows_tun_hard_kill_guest.ps1"
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "ferrum2-hyperv-static-contract-" + [Guid]::NewGuid().ToString("N")
)
$temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
Assert-True ($temporaryRoot.StartsWith("$temporaryBase\", `
    [StringComparison]::OrdinalIgnoreCase)) "temporary test root escaped TEMP"

$labModule = $null
$guestModule = $null
$hostModule = $null
$supervisorModule = $null
try {
    New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
    $labModule = New-Module -Name (
        "Ferrum2HyperVStaticLab_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $mainRunnerPath -ScriptBlock {
        param([string]$Path)
        $root = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $Path) `
            '..\..') -ErrorAction Stop).Path
        $script:repositoryRoot = $root
        Import-Module (Join-Path $root `
            'tools\powershell\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1') `
            -Scope Local -Force -ErrorAction Stop
        foreach ($owner in @(
            'Paths.ps1', 'Process.ps1', 'Manifest.ps1', 'Artifacts.ps1', 'Evidence.ps1'
        )) {
            . (Join-Path $root `
                "tools\powershell\Ferrum2.Qualification.HostHyperV\private\$owner")
        }
        Export-ModuleMember -Function @(
            "Get-EvidenceHashes", "Remove-BoundedWorkerManifestIfPresent",
            "Invoke-BoundedPwshFile",
            "Assert-BoundedWorkerPassManifestAndTerminal"
        )
    }
    Import-Module $labModule -Scope Local -Force
    Import-Module (Join-Path $repositoryRoot `
        "tools\powershell\Ferrum2.WindowsTun.Lab\Ferrum2.WindowsTun.Lab.psd1") `
        -Scope Local -Force -ErrorAction Stop

    $evidenceRoot = Join-Path $temporaryRoot "evidence"
    New-Item -ItemType Directory -Path $evidenceRoot -ErrorAction Stop | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $evidenceRoot "artifact.txt"),
        "artifact",
        [Text.UTF8Encoding]::new($false)
    )
    $baselineHashes = @(Get-EvidenceHashes -EvidenceRoot $evidenceRoot)
    Assert-True ($baselineHashes.Count -eq 1 -and
        $baselineHashes[0].path -ceq "artifact.txt") `
        "baseline evidence hash set is invalid"
    $pendingPath = Join-Path $evidenceRoot "host-orchestration.pending.json"
    $finalPath = Join-Path $evidenceRoot "host-orchestration.json"
    Write-Ferrum2JsonCreateNew -Path $pendingPath `
        -Value ([ordered]@{ status = "pending" }) -Depth 8
    Assert-True (
        (@(Get-EvidenceHashes -EvidenceRoot $evidenceRoot) |
            ConvertTo-Json -Compress -Depth 5) -ceq
        ($baselineHashes | ConvertTo-Json -Compress -Depth 5)
    ) "pending manifest entered evidence_files"
    [IO.File]::Move($pendingPath, $finalPath)
    Assert-True (-not (Test-Path -LiteralPath $pendingPath) -and
        (@(Get-EvidenceHashes -EvidenceRoot $evidenceRoot) |
            ConvertTo-Json -Compress -Depth 5) -ceq
        ($baselineHashes | ConvertTo-Json -Compress -Depth 5)) `
        "atomic final manifest changed evidence_files"
    [IO.File]::Delete($finalPath)

    $runToken = "static-contract"
    $vmId = [Guid]::NewGuid()
    $vmName = "Static Contract VM"
    $checkpointId = [Guid]::NewGuid()
    $timestamp = "2026-08-25T00:00:00.0000000Z"
    $listenerTimestamp = "2026-08-25T00:00:00.000000Z"
    $topology = [ordered]@{
        manifest_sha256 = "2" * 64; plan_sha256 = "3" * 64
        support_switch_id = [Guid]::NewGuid().ToString("D")
        support_host_ipv4 = "192.168.250.1"; support_network = "192.168.250.0/30"
        support_prefix_length = [long]30; guest_interface_alias = "Ferrum2Support"
        guest_interface_guid = [Guid]::NewGuid().ToString("D")
        guest_interface_index = [long]3; guest_mac_address = "00155DFA2502"
        guest_ipv4 = "192.168.250.2"; guest_mtu_bytes = [long]1500
        protected_host_tun_name = "tun0"
        protected_host_tun_guid = [Guid]::NewGuid().ToString("D")
        protected_host_tun_index = [long]16; protected_host_tun_status = "Up"
    }
    $supportListener = [ordered]@{
        ipv4 = "192.168.250.1"; tcp_port = [long]31000; udp_port = [long]31001
        pid = [long]4242; owner = "static-test"; executable_sha256 = "4" * 64
        creation_utc = $listenerTimestamp
    }
    $validFailure = [ordered]@{
        schema = "ferrum2.windows-tun.hard-kill-hyperv-host-run.v4"
        status = "fail"; mode = "hard-kill"; run_token = $runToken
        vm_name = $vmName; vm_id = $vmId.ToString("D")
        checkpoint_name = "Static checkpoint"; checkpoint_id = $checkpointId.ToString("D")
        topology = $topology; support_listener = $supportListener
        candidate_sha = "5" * 40; candidate_artifact_manifest_sha256 = "d" * 64
        identity_sha256 = "6" * 64
        controller_sha256 = "7" * 64; controller_bundle_sha256 = "b" * 64
        guest_wrapper_sha256 = $null
        topology_runtime_sha256 = "8" * 64; host_network_path_helper_sha256 = "9" * 64
        guest_network_path_probe_sha256 = "a" * 64; staged_input_sha256 = $null
        rust_version = $null; guest_execution = $null; guest_build = $null
        checkpoint_restored = $false; host_tun_unchanged = $false
        host_support_unchanged = $false; host_network_mutations = [long]0
        started_utc = $timestamp; finished_utc = $timestamp; final_vm_state = $null
        evidence_files = @($baselineHashes)
    }
    $validFailure.guest_execution = "host-built-precompiled-artifacts-only"
    $validFailure.guest_build = "19045"
    Write-Ferrum2JsonCreateNew -Path $finalPath -Value $validFailure -Depth 8
    [IO.File]::WriteAllBytes($pendingPath, [byte[]]::new(0))
    Remove-BoundedWorkerManifestIfPresent -Path $finalPath `
        -ExpectedSchema $validFailure.schema -ExpectedRunToken $runToken `
        -ExpectedVmId $vmId -ExpectedVmName $vmName
    Assert-True ((Test-Path -LiteralPath $finalPath -PathType Leaf) -and
        -not (Test-Path -LiteralPath $pendingPath)) `
        "valid FAIL manifest was not retained or pending was not deleted"
    [IO.File]::Delete($finalPath)

    $invalidFailure = [ordered]@{}
    foreach ($key in $validFailure.Keys) {
        $invalidFailure[$key] = $validFailure[$key]
    }
    $invalidFailure.identity_sha256 = $null
    Write-Ferrum2JsonCreateNew -Path $finalPath -Value $invalidFailure -Depth 8
    Remove-BoundedWorkerManifestIfPresent -Path $finalPath `
        -ExpectedSchema $validFailure.schema -ExpectedRunToken $runToken `
        -ExpectedVmId $vmId -ExpectedVmName $vmName
    Assert-True (-not (Test-Path -LiteralPath $finalPath)) `
        "malformed FAIL manifest survived"

    $invalidPass = [ordered]@{} + $validFailure
    $invalidPass.status = "pass"
    Write-Ferrum2JsonCreateNew -Path $finalPath -Value $invalidPass -Depth 8
    [IO.File]::WriteAllBytes($pendingPath, [byte[]]::new(0))
    Remove-BoundedWorkerManifestIfPresent -Path $finalPath `
        -ExpectedSchema $validFailure.schema -ExpectedRunToken $runToken `
        -ExpectedVmId $vmId -ExpectedVmName $vmName
    Assert-True (-not (Test-Path -LiteralPath $finalPath) -and
        -not (Test-Path -LiteralPath $pendingPath)) `
        "rejected PASS or pending manifest survived"

    [IO.File]::WriteAllText($finalPath, "{}", [Text.UTF8Encoding]::new($false))
    Remove-BoundedWorkerManifestIfPresent -Path $finalPath `
        -ExpectedSchema $validFailure.schema -ExpectedRunToken $runToken `
        -ExpectedVmId $vmId -ExpectedVmName $vmName
    Assert-True (-not (Test-Path -LiteralPath $finalPath)) `
        "malformed final manifest survived"

    $validPass = [ordered]@{}
    foreach ($key in $validFailure.Keys) { $validPass[$key] = $validFailure[$key] }
    $validPass.status = "pass"
    $validPass.candidate_sha = "1" * 40
    $guestExportRoot = Join-Path $evidenceRoot "guest\export"
    [IO.Directory]::CreateDirectory($guestExportRoot) | Out-Null
    $identityPath = Join-Path $evidenceRoot "identity-ledger.json"
    $guestIdentityPath = Join-Path $guestExportRoot "identity-ledger.json"
    $candidateArtifactPath = Join-Path $evidenceRoot "candidate-artifacts.json"
    $stagedPath = Join-Path $evidenceRoot "staged-input.json"
    $topologyPath = Join-Path $evidenceRoot "topology-manifest.json"
    foreach ($entry in @(
        [ordered]@{ path = $identityPath; text = '{"schema":4}' },
        [ordered]@{ path = $guestIdentityPath; text = '{"schema":4}' },
        [ordered]@{ path = $candidateArtifactPath; text = "candidate" },
        [ordered]@{ path = $stagedPath; text = "staged" },
        [ordered]@{ path = $topologyPath; text = "topology" }
    )) {
        [IO.File]::WriteAllText(
            [string]$entry.path,
            [string]$entry.text,
            [Text.UTF8Encoding]::new($false)
        )
    }
    $validPass.identity_sha256 = (Get-FileHash -LiteralPath $identityPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $validPass.candidate_artifact_manifest_sha256 = (Get-FileHash `
        -LiteralPath $candidateArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $validPass.staged_input_sha256 = (Get-FileHash -LiteralPath $stagedPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $validPass.topology.manifest_sha256 = (Get-FileHash -LiteralPath $topologyPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $validPass.guest_wrapper_sha256 = "b" * 64
    $validPass.rust_version = "rustc 1.97.1 (static-contract)"
    $validPass.checkpoint_restored = $true
    $validPass.host_tun_unchanged = $true
    $validPass.host_support_unchanged = $true
    $validPass.final_vm_state = "Off"
    $validPass.evidence_files = @(Get-EvidenceHashes -EvidenceRoot $evidenceRoot)
    Write-Ferrum2JsonCreateNew -Path $finalPath -Value $validPass -Depth 8
    $validTerminal =
        "hyperv_windows_tun_hard_kill status=PASS mode=hard-kill " +
        "run_token=$runToken candidate_sha=$($validPass.candidate_sha) " +
        "evidence=$evidenceRoot final_vm_state=Off"
    Assert-BoundedWorkerPassManifestAndTerminal -ManifestPath $finalPath `
        -Terminal $validTerminal -WorkerContract "HardKill" `
        -BoundParameters ([ordered]@{ RunToken = $runToken }) `
        -ExpectedVmId $vmId -ExpectedVmName $vmName
    Assert-ThrowsLike {
        Assert-BoundedWorkerPassManifestAndTerminal -ManifestPath $finalPath `
            -Terminal ($validTerminal + " unexpected") -WorkerContract "HardKill" `
            -BoundParameters ([ordered]@{ RunToken = $runToken }) `
            -ExpectedVmId $vmId -ExpectedVmName $vmName
    } "terminal does not match" "PASS manifest terminal binding"
    [IO.File]::Delete($finalPath)

    $invalidContractPass = [ordered]@{}
    foreach ($key in $validPass.Keys) {
        $invalidContractPass[$key] = $validPass[$key]
    }
    $invalidContractPass.staged_input_sha256 = $null
    Write-Ferrum2JsonCreateNew -Path $finalPath -Value $invalidContractPass -Depth 8
    Assert-ThrowsLike {
        Assert-BoundedWorkerPassManifestAndTerminal -ManifestPath $finalPath `
            -Terminal $validTerminal -WorkerContract "HardKill" `
            -BoundParameters ([ordered]@{ RunToken = $runToken }) `
            -ExpectedVmId $vmId -ExpectedVmName $vmName
    } "PASS manifest contract is invalid" "incomplete PASS manifest rejection"
    [IO.File]::Delete($finalPath)

    $childResult = Invoke-BoundedPwshFile -Arguments @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        '[Console]::Out.Write("bounded-child-pass")'
    ) -TimeoutSeconds 30 -Label "Static child"
    Assert-True ($childResult.ExitCode -eq 0 -and
        $childResult.Stdout -ceq "bounded-child-pass" -and
        [string]::IsNullOrEmpty($childResult.Stderr)) `
        "bounded child normal path failed"

    $gateName = "Local\Ferrum2-Static-Gate-" + [Guid]::NewGuid().ToString("N")
    $gateCreated = $false
    $startGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $gateName,
        [ref]$gateCreated
    )
    Assert-True $gateCreated "static child gate identity already existed"
    try {
        $gatedResult = Invoke-BoundedPwshFile -Arguments @(
            "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            '$g=[Threading.EventWaitHandle]::OpenExisting($env:FERRUM2_STATIC_GATE);try{if(-not $g.WaitOne(30000)){exit 2};[Console]::Out.Write("gated-child-pass")}finally{$g.Dispose()}'
        ) -TimeoutSeconds 30 -Label "Static gated child" `
            -Environment ([ordered]@{ FERRUM2_STATIC_GATE = $gateName }) `
            -StartGate $startGate
    } finally {
        $startGate.Dispose()
    }
    Assert-True ($gatedResult.ExitCode -eq 0 -and
        $gatedResult.Stdout -ceq "gated-child-pass" -and
        [string]::IsNullOrEmpty($gatedResult.Stderr)) `
        "job-membership-gated child path failed"

    $closedGateName = "Local\Ferrum2-Static-Closed-Gate-" +
        [Guid]::NewGuid().ToString("N")
    $closedGateCreated = $false
    $closedGate = [Threading.EventWaitHandle]::new(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $closedGateName,
        [ref]$closedGateCreated
    )
    Assert-True $closedGateCreated "closed static child gate identity already existed"
    $closedGate.Dispose()
    Assert-ThrowsLike {
        Invoke-BoundedPwshFile -Arguments @(
            "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            'Start-Sleep -Seconds 30'
        ) -TimeoutSeconds 30 -Label "Static closed gate child" `
            -StartGate $closedGate
    } "could not enter the kill-on-close job" `
        "bounded child primary failure preservation"

    $guestModule = New-Module -Name (
        "Ferrum2GuestEvidenceStatic_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $guestWrapperPath -ScriptBlock {
        param([string]$Path)
        . $Path -LibraryOnly
        Export-ModuleMember -Function Assert-HardKillEvidence
    }
    Import-Module $guestModule -Scope Local -Prefix Guest -Force

    $hostModule = New-Module -Name (
        "Ferrum2HostEvidenceStatic_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $hardKillHostPath -ScriptBlock {
        param([string]$Path)
        . (Join-Path (Split-Path -Parent $Path) 'Hard.HostContract.ps1')
        Export-ModuleMember -Function Assert-HardKillEvidenceRows
    }
    Import-Module $hostModule -Scope Local -Prefix Host -Force

    $validEvidencePath = Join-Path $temporaryRoot "hard-kill-valid.jsonl"
    $tamperedEvidencePath = Join-Path $temporaryRoot "hard-kill-tampered.jsonl"
    $expectedAppIdSha256 = "c" * 64
    Write-HardKillEvidence $validEvidencePath
    $originalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    $originalUiCulture = [Threading.Thread]::CurrentThread.CurrentUICulture
    try {
        $adversarialCulture = [Globalization.CultureInfo]::GetCultureInfo("en-US-POSIX")
        [Threading.Thread]::CurrentThread.CurrentCulture = $adversarialCulture
        [Threading.Thread]::CurrentThread.CurrentUICulture = $adversarialCulture
        Assert-GuestHardKillEvidence $validEvidencePath $expectedAppIdSha256
        Assert-HostHardKillEvidenceRows $validEvidencePath
        Write-HardKillEvidence $tamperedEvidencePath $true
        Assert-ThrowsLike {
            Assert-GuestHardKillEvidence $tamperedEvidencePath $expectedAppIdSha256
        } "identity hash" "guest WFP hash tamper"
        Assert-ThrowsLike { Assert-HostHardKillEvidenceRows $tamperedEvidencePath } `
            "identity hash" "host WFP hash tamper"
    } finally {
        [Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        [Threading.Thread]::CurrentThread.CurrentUICulture = $originalUiCulture
    }

    $supervisorModule = New-Module -Name (
        "Ferrum2SupervisorStatic_" + [Guid]::NewGuid().ToString("N")
    ) -ArgumentList $mainRunnerPath -ScriptBlock {
        param([string]$Path)
        $root = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $Path) `
            '..\..') -ErrorAction Stop).Path
        . (Join-Path $root `
            'tools\powershell\Ferrum2.Qualification.HostHyperV\private\Manifest.ps1')
        $script:Scenario = "pass"
        $script:ExpectedVmId = [Guid]::Empty
        $script:ExpectedFinalState = "Running"
        $script:CleanupCalls = 0
        function Set-SupervisorScenario([string]$Scenario, [Guid]$VmId, [string]$FinalState) {
            $script:Scenario = $Scenario
            $script:ExpectedVmId = $VmId
            $script:ExpectedFinalState = $FinalState
            $script:CleanupCalls = 0
        }
        function Get-SupervisorCleanupCalls { return $script:CleanupCalls }
        function Assert-ApprovedVmCleanupAuthority { param([object]$Authority) }
        function New-BoundedPwshFileArguments {
            param($ScriptPath,$BoundParameters,$ForwardedParameterNames,$InternalWorkerToken)
            return @("stub")
        }
        function Invoke-BoundedPwshFile {
            param($Arguments,$TimeoutSeconds,$Label,$Environment,$StartGate)
            if ($script:Scenario -ceq "primary" -or $script:Scenario -ceq "primary-recovery") {
                throw "synthetic primary failure"
            }
            $stdout = [ordered]@{
                schema = "ferrum2.windows-tun.hyperv-probe.v2"
                status = "pass"
                vm_id = $script:ExpectedVmId.ToString("D")
                initial_vm_state = $script:ExpectedFinalState.ToLowerInvariant()
                final_vm_state = $script:ExpectedFinalState
                checkpoint_restored = $false
                host_network_mutations = [long]0
            } | ConvertTo-Json -Compress
            if ($script:Scenario -ceq "bad-terminal") { $stdout = "not-json" }
            return [pscustomobject]@{ ExitCode = 0; Stdout = $stdout; Stderr = "" }
        }
        function Invoke-BoundedHyperVMutation {
            param($Action,$VmId,$ExpectedVmName,$TimeoutSeconds)
            return $script:ExpectedFinalState
        }
        function Invoke-ApprovedVmWorkerEmergencyCleanup {
            param($Authority,$ShutdownTimeoutSeconds,$Mode)
            $script:CleanupCalls++
            if ($script:Scenario -ceq "primary-recovery") { throw "synthetic recovery failure" }
        }
        function Remove-BoundedWorkerManifestIfPresent {
            param($Path,$ExpectedSchema,$ExpectedRunToken,$ExpectedVmId,$ExpectedVmName)
        }
        Export-ModuleMember -Function `
            Invoke-BoundedHyperVWorkerSupervisor,Set-SupervisorScenario,Get-SupervisorCleanupCalls
    }
    Import-Module $supervisorModule -Scope Local -Force
    $supervisorVmId = [Guid]::NewGuid()
    $supervisorVmName = "Static Supervisor VM"
    $authority = [pscustomobject]@{
        vm_id = $supervisorVmId
        vm_name = $supervisorVmName
    }
    Set-SupervisorScenario "bad-terminal" $supervisorVmId "Off"
    Assert-ThrowsLike {
        Invoke-BoundedHyperVWorkerSupervisor -ScriptPath $PSCommandPath `
            -BoundParameters ([ordered]@{ RunToken = "static-contract" }) `
            -ForwardedParameterNames @("RunToken") -WorkerTimeoutSeconds 30 `
            -ShutdownTimeoutSeconds 30 -ExpectedVmId $supervisorVmId `
            -ExpectedVmName $supervisorVmName -ExpectedFinalState "Off" `
            -CleanupAuthority $authority -CleanupMode "StopOnly" `
            -WorkerContract "Probe" -FailureManifestPath $null `
            -Label "Static supervisor"
    } "invalid|JSON" "invalid terminal supervisor recovery"
    Assert-True ((Get-SupervisorCleanupCalls) -eq 1) `
        "invalid terminal did not invoke supervisor recovery"

    Set-SupervisorScenario "primary-recovery" $supervisorVmId "Off"
    Assert-ThrowsLike {
        Invoke-BoundedHyperVWorkerSupervisor -ScriptPath $PSCommandPath `
            -BoundParameters ([ordered]@{ RunToken = "static-contract" }) `
            -ForwardedParameterNames @("RunToken") -WorkerTimeoutSeconds 30 `
            -ShutdownTimeoutSeconds 30 -ExpectedVmId $supervisorVmId `
            -ExpectedVmName $supervisorVmName -ExpectedFinalState "Off" `
            -CleanupAuthority $authority -CleanupMode "StopOnly" `
            -WorkerContract "Probe" -FailureManifestPath $null `
            -Label "Static supervisor"
    } "primary=synthetic primary failure; recovery=synthetic recovery failure" `
        "primary and recovery aggregation"

    Set-SupervisorScenario "pass" $supervisorVmId "Off"
    $supervisorTerminal = Invoke-BoundedHyperVWorkerSupervisor -ScriptPath $PSCommandPath `
        -BoundParameters ([ordered]@{ RunToken = "static-contract" }) `
        -ForwardedParameterNames @("RunToken") -WorkerTimeoutSeconds 30 `
        -ShutdownTimeoutSeconds 30 -ExpectedVmId $supervisorVmId `
        -ExpectedVmName $supervisorVmName -ExpectedFinalState "Off" `
        -CleanupAuthority $authority -CleanupMode "StopOnly" `
        -WorkerContract "Probe" -FailureManifestPath $null `
        -Label "Static supervisor"
    $supervisorTerminalDocument = $supervisorTerminal |
        ConvertFrom-Json -Depth 8 -ErrorAction Stop
    Assert-True ($supervisorTerminalDocument.status -ceq 'pass' -and
        [Guid][string]$supervisorTerminalDocument.vm_id -eq $supervisorVmId -and
        (Get-SupervisorCleanupCalls) -eq 0) `
        "supervisor did not return its accepted terminal"

    Write-Output "Windows TUN Hyper-V static contract: PASS"
} finally {
    foreach ($module in @($supervisorModule, $hostModule, $guestModule, $labModule)) {
        if ($null -ne $module) { Remove-Module $module -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        if (-not $resolved.StartsWith("$temporaryBase\", [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -cnotmatch
                '^ferrum2-hyperv-static-contract-[0-9a-f]{32}$') {
            throw "temporary test cleanup boundary is invalid"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
}
