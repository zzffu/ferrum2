Set-StrictMode -Version Latest

$script:HostQuickScenarios = @(
    [pscustomobject][ordered]@{
        name = "tcp-single-flow"; metric = "throughput"
        unit = "bytes_per_second"; direction = "higher_is_better"
    }
    [pscustomobject][ordered]@{
        name = "tcp-request-1k-p99"; metric = "p99_nanoseconds"
        unit = "nanoseconds"; direction = "lower_is_better"
    }
    [pscustomobject][ordered]@{
        name = "udp-packets-per-second"; metric = "packet_rate"
        unit = "packets_per_second"; direction = "higher_is_better"
    }
    [pscustomobject][ordered]@{
        name = "fragment-reassembly-throughput"; metric = "reassembly_rate"
        unit = "bytes_per_second"; direction = "higher_is_better"
    }
)

$script:HostProfileDefinitions = @{
    Quick = [pscustomobject][ordered]@{
        pair_count = 3
        warmup_seconds = 2
        active_seconds = 10
        scenarios = @($script:HostQuickScenarios)
        lifecycle_cycles = 0
    }
    Confirm = [pscustomobject][ordered]@{
        pair_count = 5
        warmup_seconds = 5
        active_seconds = 30
        scenarios = @($script:HostQuickScenarios) + @(
            [pscustomobject][ordered]@{
                name = "tcp-256-flow-fairness"; metric = "fairness"
                unit = "jain_ppb"; direction = "higher_is_better"
            }
        )
        lifecycle_cycles = 0
    }
    Lifecycle = [pscustomobject][ordered]@{
        pair_count = 0
        warmup_seconds = 0
        active_seconds = 0
        scenarios = @()
        lifecycle_cycles = 20
    }
}

function Get-HostProfileDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Quick", "Confirm", "Lifecycle")]
        [string]$Mode
    )
    return $script:HostProfileDefinitions[$Mode]
}

function New-HostPairTrials {
    param(
        [Parameter(Mandatory = $true)][string]$BaselineSha,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ClientDirect", "EndToEnd")]
        [string]$Topology
    )
    $trials = [Collections.Generic.List[object]]::new()
    [int]$sequence = 0
    foreach ($scenario in $Profile.scenarios) {
        foreach ($pair in 1..$Profile.pair_count) {
            $members = if (($pair % 2) -eq 1) {
                @(
                    [pscustomobject]@{ label = "baseline"; sha = $BaselineSha },
                    [pscustomobject]@{ label = "candidate"; sha = $CandidateSha }
                )
            } else {
                @(
                    [pscustomobject]@{ label = "candidate"; sha = $CandidateSha },
                    [pscustomobject]@{ label = "baseline"; sha = $BaselineSha }
                )
            }
            foreach ($member in $members) {
                $sequence += 1
                [void]$trials.Add([pscustomobject][ordered]@{
                    sequence = $sequence
                    pair = $pair
                    order = if (($pair % 2) -eq 1) { "baseline-candidate" } else { "candidate-baseline" }
                    scenario = $scenario.name
                    metric = $scenario.metric
                    unit = $scenario.unit
                    topology = $Topology
                    direction = $scenario.direction
                    member = $member.label
                    commit_sha = $member.sha
                    warmup_seconds = $Profile.warmup_seconds
                    active_seconds = $Profile.active_seconds
                    initial_product_state = "fresh-processes-and-adapter"
                })
            }
        }
    }
    return $trials.ToArray()
}

function New-Ferrum2HostPerformancePlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Quick", "Confirm", "Lifecycle")]
        [string]$Mode,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ClientDirect", "EndToEnd")]
        [string]$Topology,
        [Parameter(Mandatory = $true)][string]$BaselineSha,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$PerformanceSourceBundleSha256,
        [AllowNull()][object]$RunId = $null
    )
    if ($null -ne $RunId -and [string]$RunId -cnotmatch '^[0-9a-f]{12}$') {
        throw "host performance plan RunId is invalid"
    }
    $profile = Get-HostProfileDefinition -Mode $Mode
    $trials = @(
        if ($Mode -ceq "Lifecycle") {
            [pscustomobject][ordered]@{
                sequence = 1
                scenario = "product-lifecycle"
                topology = $Topology
                member = "candidate"
                commit_sha = $CandidateSha
                lifecycle_cycles = $profile.lifecycle_cycles
                action = "product-start-probe-stop"
            }
        } else {
            New-HostPairTrials -BaselineSha $BaselineSha -CandidateSha $CandidateSha `
                -Profile $profile -Topology $Topology
        }
    )
    return [pscustomobject][ordered]@{
        schema_version = 2
        kind = "ferrum2.windows-tun.host-performance-plan"
        run_id = $RunId
        execution = "explicit-authorized-windows-host"
        mode = $Mode
        topology = $Topology
        baseline_sha = $BaselineSha
        candidate_sha = $CandidateSha
        performance_source_bundle_sha256 = $PerformanceSourceBundleSha256
        pair_count = $profile.pair_count
        warmup_seconds = $profile.warmup_seconds
        active_seconds = $profile.active_seconds
        lifecycle_cycles = $profile.lifecycle_cycles
        scenario_count = $profile.scenarios.Count
        trial_count = $trials.Count
        scenarios = @($profile.scenarios)
        trials = $trials
        safety = [pscustomobject][ordered]@{
            requires_elevation = $true
            requires_explicit_acknowledgement = $true
            automatic_elevation = $false
            live_address_family = "IPv4 only (RFC2544 198.18.0.0/15)"
            route_scope = "run-owned /32 only"
            tcp_ingress_scope = "exact app, TCP, TUN LUID, local address/port, and remote peer"
            tcp_ingress_installation = "automatic after listener bind and before admission"
            mutations = @(
                "one run-owned Wintun adapter",
                "run-owned RFC2544 loopback support address",
                "run-owned narrow routes",
                "process-owned dynamic exact TCP ingress WFP session"
            )
            forbidden_mutations = @(
                "default route", "system DNS", "physical adapters", "WLAN",
                "persistent Windows Firewall rules", "unrelated WFP sessions", "sing-box"
            )
            cleanup = "exact RunId ledger identities in try/finally"
            recovery = "%PROGRAMDATA%/Ferrum2HostPerformance-v2/<RunId>/recovery.json"
        }
    }
}
