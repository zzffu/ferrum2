Set-StrictMode -Version Latest

$script:HostProfileDefinitions = @{
    Quick = [pscustomobject][ordered]@{
        pair_count = 3
        warmup_seconds = 2
        active_seconds = 10
        scenarios = @(
            [pscustomobject][ordered]@{ name = "udp-packets-per-second"; metric = "packet_rate"; unit = "packets_per_second" }
            [pscustomobject][ordered]@{ name = "fragment-reassembly-throughput"; metric = "reassembly_rate"; unit = "bytes_per_second" }
        )
        lifecycle_cycles = 0
    }
    Confirm = [pscustomobject][ordered]@{
        pair_count = 5
        warmup_seconds = 5
        active_seconds = 30
        scenarios = @(
            [pscustomobject][ordered]@{ name = "udp-packets-per-second"; metric = "packet_rate"; unit = "packets_per_second" }
            [pscustomobject][ordered]@{ name = "fragment-reassembly-throughput"; metric = "reassembly_rate"; unit = "bytes_per_second" }
            [pscustomobject][ordered]@{ name = "tcp-single-flow"; metric = "throughput"; unit = "bytes_per_second" }
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
        [Parameter(Mandatory = $true)][object]$Profile
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
        [Parameter(Mandatory = $true)][string]$BaselineSha,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$PerformanceSourceBundleSha256
    )
    $profile = Get-HostProfileDefinition -Mode $Mode
    $trials = @(
        if ($Mode -ceq "Lifecycle") {
            [pscustomobject][ordered]@{
                sequence = 1
                scenario = "product-lifecycle"
                member = "candidate"
                commit_sha = $CandidateSha
                lifecycle_cycles = $profile.lifecycle_cycles
                action = "product-start-probe-stop"
            }
        } else {
            New-HostPairTrials -BaselineSha $BaselineSha -CandidateSha $CandidateSha -Profile $profile
        }
    )
    return [pscustomobject][ordered]@{
        schema_version = 1
        kind = "ferrum2.windows-tun.host-performance-plan"
        execution = "explicit-authorized-windows-host"
        mode = $Mode
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
            address_family = "RFC2544 198.18.0.0/15"
            route_scope = "run-owned /32 only"
            mutations = @("one run-owned Wintun adapter", "run-owned RFC2544 loopback support address", "run-owned narrow routes")
            forbidden_mutations = @("default route", "system DNS", "physical adapters", "WLAN", "firewall", "WFP", "sing-box")
            cleanup = "exact RunId ledger identities in try/finally"
            recovery = "%PROGRAMDATA%/Ferrum2HostPerformance-v2/<RunId>/recovery.json"
        }
        qualification = [pscustomobject][ordered]@{
            product_lifecycle_cycles = $profile.lifecycle_cycles
            long_durability_soak = "excluded"
            vm_start = $false
            checkpoint_restore = $false
            guest_staging = $false
        }
    }
}
