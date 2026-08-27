function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$WorkingDirectory = $script:repositoryRoot
    )
    Push-Location $WorkingDirectory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

function ConvertTo-CanonicalUtcText {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $text = if ($Value -is [DateTime]) {
        $timestamp = [DateTime]$Value
        if ($timestamp.Kind -ne [DateTimeKind]::Utc) {
            throw "$Label DateTime value must be UTC"
        }
        $timestamp.ToString("o", [Globalization.CultureInfo]::InvariantCulture)
    } elseif ($Value -is [string]) {
        [string]$Value
    } else {
        throw "$Label must be a canonical UTC string or UTC DateTime"
    }
    if ($text -cnotmatch
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$') {
        throw "$Label is not canonical UTC"
    }
    $parsed = [DateTime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact(
            $text,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed
        ) -or $parsed.Kind -ne [DateTimeKind]::Utc) {
        throw "$Label is not a real UTC timestamp"
    }
    return $text
}

function Resolve-Commit {
    param([string]$Git, [string]$Sha, [string]$Label)
    $resolved = [string](& $Git -C $script:repositoryRoot rev-parse --verify "$Sha^{commit}" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $resolved -cne $Sha) { throw "$Label commit identity is invalid" }
    return $resolved
}

function Get-TreeSha {
    param([string]$Git, [string]$Sha)
    $tree = [string](& $Git -C $script:repositoryRoot rev-parse "$Sha^{tree}" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $tree -cnotmatch '^[0-9a-f]{40}$') {
        throw "unable to resolve tree for $Sha"
    }
    return $tree
}

function New-CanonicalPlan {
    param(
        [string]$Python,
        [string]$RunKindValue,
        [string]$Output
    )
    Invoke-NativeChecked -Executable $Python -Label "Windows TUN plan" -Arguments @(
        "-B", "-m", $script:controlModule, "windows-tun-plan",
        "--run-kind", $RunKindValue,
        "--controller-bundle-sha256",
            [string]$script:performanceControllerBundleManifest.controller_bundle_sha256,
        "--policy", $script:policyPath,
        "--output", $Output
    )
    $plan = Get-Content -LiteralPath $Output -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30
    if ($plan.schema_version -ne 5 -or
        $plan.kind -cne "windows_tun_performance_plan" -or
        $plan.run_kind -cne $RunKindValue -or
        [string]$plan.controller_bundle_sha256 -cne
            [string]$script:performanceControllerBundleManifest.controller_bundle_sha256 -or
        @($plan.trials).Count -ne 108 -or
        $null -eq $plan.scenarios."udp-route-once" -or
        $null -eq $plan.scenarios."udp-8192-association-lookup-expiry" -or
        $null -eq $plan.scenarios."network-lifecycle" -or
        $null -eq $plan.diagnostic_profiles.UdpFlowBoundary) {
        throw "canonical Windows TUN plan shape is invalid"
    }
    $plannedRunnerHashes = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [string]$_.Value.recipe.runner_source_sha256
    } | Sort-Object -Unique)
    if ($plannedRunnerHashes.Count -ne 1 -or
        $plannedRunnerHashes[0] -cne $script:runnerSourceSha256) {
        throw "canonical Windows TUN plan does not bind this runner source"
    }
    foreach ($binding in @(
        @("performance_source_bundle_sha256", [string]$script:runnerSourceSha256),
        @("topology_runtime_source_sha256", [string]$script:topologyRuntimeSha256),
        @("host_network_path_source_sha256", [string]$script:hostNetworkPathHelperSha256),
        @("guest_network_path_source_sha256", [string]$script:guestNetworkPathProbeSourceSha256),
        @("collector_source_sha256", [string]$script:collectorSourceSha256)
    )) {
        $plannedHashes = @($plan.scenarios.PSObject.Properties | ForEach-Object {
            [string]$_.Value.recipe.($binding[0])
        } | Sort-Object -Unique)
        if ($plannedHashes.Count -ne 1 -or $plannedHashes[0] -cne $binding[1]) {
            throw "canonical Windows TUN plan does not bind $($binding[0])"
        }
    }
    $plannedRuntimeIdleTimeouts = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [int]$_.Value.recipe.client_runtime_idle_timeout_milliseconds
    } | Sort-Object -Unique)
    if ($plannedRuntimeIdleTimeouts.Count -ne 1 -or
        $plannedRuntimeIdleTimeouts[0] -ne 60000) {
        throw "canonical Windows TUN plan client runtime idle timeout is invalid"
    }
    $plannedTunRingCapacities = @($plan.scenarios.PSObject.Properties | ForEach-Object {
        [long]$_.Value.recipe.tun_ring_capacity_bytes
    } | Sort-Object -Unique)
    if ($plannedTunRingCapacities.Count -ne 1 -or
        $plannedTunRingCapacities[0] -ne 8388608) {
        throw "canonical Windows TUN plan ring capacity is invalid"
    }
    $udpBoundaryRecipe = $plan.scenarios.
        "udp-8192-association-lookup-expiry".recipe
    if ([string]$udpBoundaryRecipe.canonical_source_port_strategy -cne
            "explicit_tun_ipv4_contiguous" -or
        [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
            $script:udpAssociationSourceIpv4 -or
        [int]$udpBoundaryRecipe.canonical_source_port_first -ne
            $script:udpAssociationSourcePortFirst -or
        [int]$udpBoundaryRecipe.canonical_source_port_last -ne
            $script:udpAssociationSourcePortLast -or
        [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -cne
            $script:udpAssociationSourceIpv4 -or
        [int]$udpBoundaryRecipe.diagnostic_source_port_first -ne
            $script:udpAssociationSourcePortFirst -or
        [int]$udpBoundaryRecipe.diagnostic_source_port_last -ne
            $script:udpAssociationSourcePortLast -or
        [int]$udpBoundaryRecipe.associations -ne
            $script:udpAssociationCount -or
        ([int]$udpBoundaryRecipe.canonical_source_port_last -
            [int]$udpBoundaryRecipe.canonical_source_port_first + 1) -ne
            [int]$udpBoundaryRecipe.associations -or
        ([int]$udpBoundaryRecipe.diagnostic_source_port_last -
            [int]$udpBoundaryRecipe.diagnostic_source_port_first + 1) -ne
            [int]$udpBoundaryRecipe.associations -or
        [string]$udpBoundaryRecipe.canonical_source_ipv4 -cne
            [string]$udpBoundaryRecipe.diagnostic_source_ipv4 -or
        [int]$udpBoundaryRecipe.canonical_source_port_first -ne
            [int]$udpBoundaryRecipe.diagnostic_source_port_first -or
        [int]$udpBoundaryRecipe.canonical_source_port_last -ne
            [int]$udpBoundaryRecipe.diagnostic_source_port_last -or
        [string]$udpBoundaryRecipe.diagnostic_collector_source_sha256 -cne
            $script:udpBoundaryCollectorSourceSha256) {
        throw "canonical Windows TUN UDP source-port contract is invalid"
    }
    return $plan
}

function Resolve-CanonicalDiagnosticProfileTrial {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$Profile
    )
    $profileProperty = @($Plan.diagnostic_profiles.PSObject.Properties | Where-Object {
        $_.Name -ceq $Profile
    })
    if ($profileProperty.Count -ne 1 -or $null -eq $profileProperty[0].Value) {
        throw "Windows TUN diagnostic profile is unsupported"
    }
    $selector = $profileProperty[0].Value
    $selectorFields = @($selector.PSObject.Properties.Name | Sort-Object)
    if (($selectorFields -join "`n") -cne ((@(
        "member", "order", "pair", "scenario"
    ) | Sort-Object) -join "`n")) {
        throw "Windows TUN diagnostic profile selector is invalid"
    }
    $matches = @($Plan.trials | Where-Object {
        [string]$_.scenario -ceq [string]$selector.scenario -and
        [string]$_.member -ceq [string]$selector.member -and
        [int]$_.pair -eq [int]$selector.pair -and
        [int]$_.order -eq [int]$selector.order
    })
    if ($matches.Count -ne 1) {
        throw "Windows TUN diagnostic profile does not resolve to one canonical trial"
    }
    return $matches[0]
}

function New-NetworkModelPlan {
    param([string]$Python, [string]$Output, [string]$ExpectedSha256)
    $networkModelRoot = (Resolve-Path -LiteralPath (Join-Path `
        (Split-Path -Parent $script:networkModelControllerPath) '..\..\..') `
        -ErrorAction Stop).Path
    Invoke-NativeChecked -Executable $Python -Label "Windows TUN network-model plan" `
        -WorkingDirectory $networkModelRoot `
        -Arguments @(
            "-B", "-m", "tools.performance_candidate.windows_tun.network_model",
            "plan", "--output", $Output
        )
    $digest = (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne $ExpectedSha256) {
        throw "Windows TUN network-model plan identity mismatch"
    }
    $model = Get-Content -LiteralPath $Output -Raw -Encoding utf8 |
        ConvertFrom-Json -Depth 12
    $lifecycleModel = $model.workloads."network-lifecycle"
    if ($model.schema_version -ne 6 -or
        $model.execution -cne "local_hyperv_guest" -or
        $model.host_network_mutation -cne "forbidden" -or
        [int]$model.workloads."network-lifecycle".resource_warmup_reset_cycles -ne 12 -or
        [int]$model.workloads."network-lifecycle".resource_warmup_route_metric_states -ne 3 -or
        [int]$model.workloads."network-lifecycle".resource_quiescence_seconds -ne 30 -or
        [int]$model.workloads."network-lifecycle".reset_network_cycles -ne 1000 -or
        [int]$model.workloads."network-lifecycle".total_reset_network_cycles -ne 1012 -or
        [int]$model.workloads."network-lifecycle".interface_switch_trial_reset_ordinal -ne 512 -or
        [int]$lifecycleModel.interface_switch_recovery_timeout_seconds -ne 30 -or
        [int]$lifecycleModel.interface_switch_probe_retry_milliseconds -ne 250 -or
        $model.workloads."network-lifecycle".terminal_resource_convergence_excluded_from_elapsed `
            -ne $true -or
        (@($lifecycleModel.retained_resource_growth_enforced_operations) -join "|") -cne
            "reset_network" -or
        (@($lifecycleModel.diagnostic_resource_growth_operations) -join "|") -cne
            "full_rebuild" -or
        [int]$model.workloads."udp-route-once".generations -ne 2 -or
        [int]$model.workloads."udp-route-once".source_slots -ne 64 -or
        [int]$model.workloads."udp-route-once".target_slots -ne 4) {
        throw "Windows TUN network-model plan shape is invalid"
    }
    return $model
}

function Export-CommitSource {
    param(
        [string]$Git,
        [string]$Tar,
        [string]$Sha,
        [string]$Destination,
        [string]$Archive
    )
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    Invoke-NativeChecked -Executable $Git -Label "git archive $Sha" -Arguments @(
        "-C", $script:repositoryRoot, "archive", "--format=tar", "--output=$Archive", $Sha
    )
    Invoke-NativeChecked -Executable $Tar -Label "extract source $Sha" -WorkingDirectory $Destination `
        -Arguments @("-xf", $Archive)
    if (-not (Test-Path -LiteralPath (Join-Path $Destination "Cargo.lock") -PathType Leaf)) {
        throw "archived source for $Sha is incomplete"
    }
    [IO.File]::Delete($Archive)
}

function Copy-BuiltBinary {
    param([string]$Source, [string]$Destination, [string]$Label)
    $item = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Label build output is invalid"
    }
    Copy-Item -LiteralPath $item.FullName -Destination $Destination -ErrorAction Stop
    return (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Build-MemberArtifacts {
    param(
        [string]$Cargo,
        [string]$Git,
        [string]$Tar,
        [string]$Sha,
        [string]$Member,
        [string]$TemporaryRoot,
        [string]$ArtifactRoot,
        [switch]$IncludeHarness
    )
    $source = Join-Path $TemporaryRoot "source-$Member"
    $archive = Join-Path $TemporaryRoot "source-$Member.tar"
    Export-CommitSource -Git $Git -Tar $Tar -Sha $Sha -Destination $source -Archive $archive
    $remapFlag = "--remap-path-prefix=$source=$script:reproducibleRustSourceRoot"
    if ($remapFlag -cmatch '[\r\n"]') {
        throw "host $Member build source remap cannot be encoded safely"
    }
    # /Brepro makes the PE timestamp and CodeView identity content-derived.
    $encodedRustFlags = @($remapFlag, "-C", "link-arg=/Brepro") -join [char]0x1f
    $targetRoot = Join-Path $source "target"
    $arguments = @(
        "+1.97.1", "build", "--target", $script:approvedRustTarget,
        "--target-dir", $targetRoot,
        "-p", "ferrum2-client", "-p", "ferrum2-server"
    )
    if ($IncludeHarness) { $arguments += @("-p", "ferrum2-m4-qualification") }
    $arguments += @("--bins", "--locked", "--profile", "profiling")
    $previousEncodedRustFlags = [Environment]::GetEnvironmentVariable(
        "CARGO_ENCODED_RUSTFLAGS",
        [EnvironmentVariableTarget]::Process
    )
    try {
        [Environment]::SetEnvironmentVariable(
            "CARGO_ENCODED_RUSTFLAGS",
            $encodedRustFlags,
            [EnvironmentVariableTarget]::Process
        )
        Invoke-NativeChecked -Executable $Cargo -Arguments $arguments `
            -Label "host $Member build" -WorkingDirectory $source
    } finally {
        [Environment]::SetEnvironmentVariable(
            "CARGO_ENCODED_RUSTFLAGS",
            $previousEncodedRustFlags,
            [EnvironmentVariableTarget]::Process
        )
    }
    $destination = Join-Path $ArtifactRoot $Member
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $profile = Join-Path (Join-Path $targetRoot $script:approvedRustTarget) "profiling"
    $client = Join-Path $destination "ferrum2-client.exe"
    $server = Join-Path $destination "ferrum2-server.exe"
    $clientHash = Copy-BuiltBinary -Source (Join-Path $profile "ferrum2-client.exe") `
        -Destination $client -Label "$Member client"
    $serverHash = Copy-BuiltBinary -Source (Join-Path $profile "ferrum2-server.exe") `
        -Destination $server -Label "$Member server"
    $harness = $null
    $harnessHash = $null
    if ($IncludeHarness) {
        $harness = Join-Path $ArtifactRoot "m4-qualification.exe"
        $harnessHash = Copy-BuiltBinary -Source (Join-Path $profile "m4-qualification.exe") `
            -Destination $harness -Label "candidate performance harness"
    }
    return [pscustomobject]@{
        Client = $client
        Server = $server
        ClientSha256 = $clientHash
        ServerSha256 = $serverHash
        Harness = $harness
        HarnessSha256 = $harnessHash
    }
}
