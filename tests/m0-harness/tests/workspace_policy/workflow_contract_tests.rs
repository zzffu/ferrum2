use std::collections::BTreeSet;
use std::fs;

use super::*;
use crate::workspace_root;

fn mutate_first(source: &str, from: &str, to: &str) -> String {
    assert!(source.contains(from), "mutation source is absent: {from:?}");
    source.replacen(from, to, 1)
}

fn move_block_before(
    source: &str,
    block_start: &str,
    block_end: &str,
    destination: &str,
) -> String {
    let start = source.find(block_start).expect("moving block start");
    let end = start + source[start..].find(block_end).expect("moving block end");
    let block = &source[start..end];
    let mut remaining = String::with_capacity(source.len());
    remaining.push_str(&source[..start]);
    remaining.push_str(&source[end..]);
    let destination = remaining.find(destination).expect("move destination");
    let mut moved = String::with_capacity(source.len());
    moved.push_str(&remaining[..destination]);
    moved.push_str(block);
    moved.push_str(&remaining[destination..]);
    moved
}

fn dependencies(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn hosted_execution_mutations_fail_closed() {
    let main = fs::read_to_string(workspace_root().join(".github/workflows/m0.yml"))
        .expect("main workflow source");
    validate_workflow_permissions(".github/workflows/m0.yml", &main)
        .expect("current read-only permissions");
    validate_hosted_library_execution(&main).expect("current hosted library execution");

    let writable = mutate_first(&main, "contents: read", "contents: write");
    assert!(validate_workflow_permissions(".github/workflows/m0.yml", &writable).is_err());

    let extra_actions = mutate_first(
        &main,
        "permissions:\n  contents: read\n",
        "permissions:\n  actions: read\n  contents: read\n",
    );
    assert!(validate_workflow_permissions(".github/workflows/m0.yml", &extra_actions).is_err());

    let linux_compile_only = mutate_first(
        &main,
        "cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked",
        "cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --no-run --locked",
    );
    assert!(validate_hosted_library_execution(&linux_compile_only).is_err());

    let live_backend = mutate_first(
        &main,
        "--features fuzzing --locked",
        "--features fuzzing --features live-backend --locked",
    );
    assert!(validate_hosted_library_execution(&live_backend).is_err());

    let conditional_linux = mutate_first(
        &main,
        "      - name: Run portable TUN and Windows platform unit tests\n        shell: bash",
        "      - name: Run portable TUN and Windows platform unit tests\n        if: false\n        shell: bash",
    );
    assert!(validate_hosted_library_execution(&conditional_linux).is_err());

    let suppressed_linux = mutate_first(
        &main,
        "      - name: Run portable TUN and Windows platform unit tests\n        shell: bash",
        "      - name: Run portable TUN and Windows platform unit tests\n        continue-on-error: true\n        shell: bash",
    );
    assert!(validate_hosted_library_execution(&suppressed_linux).is_err());

    for (job, name) in [
        ("quality", "quality"),
        ("platform", "platform / ${{ matrix.profile }}"),
    ] {
        let job_suppressed = mutate_first(
            &main,
            &format!("  {job}:\n    name: {name}"),
            &format!("  {job}:\n    name: {name}\n    continue-on-error: true"),
        );
        assert!(
            validate_hosted_library_execution(&job_suppressed).is_err(),
            "{job} job-level failure suppression must fail closed"
        );
    }

    let wrong_windows_target = mutate_first(
        &main,
        "            target: x86_64-pc-windows-msvc",
        "            target: aarch64-pc-windows-msvc",
    );
    assert!(validate_hosted_library_execution(&wrong_windows_target).is_err());

    for corrupted_non_tun_gate in [
        mutate_first(
            &main,
            "cargo +1.97.1 check -p ferrum2-runtime -p ferrum2-net -p ferrum2-platform-windows -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked --target ${{ matrix.target }}",
            "cargo +1.97.1 check -p ferrum2-runtime -p ferrum2-platform-windows -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked --target ${{ matrix.target }}",
        ),
        mutate_first(
            &main,
            "cargo +1.97.1 check -p ferrum2-runtime -p ferrum2-net -p ferrum2-platform-windows -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked --target ${{ matrix.target }}",
            "cargo +1.97.1 check -p ferrum2-runtime -p ferrum2-net -p ferrum2-platform-windows -p ferrum2-client -p ferrum2-server --all-features --locked --target ${{ matrix.target }}",
        ),
        mutate_first(
            &main,
            "cargo +1.97.1 test -p ferrum2-runtime --test network_socket_service --all-features --locked --target ${{ matrix.target }}",
            "cargo +1.97.1 test -p ferrum2-runtime --test network_socket_service --all-features --no-run --locked --target ${{ matrix.target }}",
        ),
        mutate_first(
            &main,
            "cargo +1.97.1 test -p ferrum2-server --example windows_non_tun_gate06 --locked --target ${{ matrix.target }}",
            "cargo +1.97.1 test -p ferrum2-server --example windows_non_tun_gate06 --no-run --locked --target ${{ matrix.target }}",
        ),
        mutate_first(
            &main,
            "      - name: Compile and test Windows non-TUN generation surface\n        if: matrix.profile == 'windows-msvc'",
            "      - name: Compile and test Windows non-TUN generation surface\n        if: false",
        ),
        mutate_first(
            &main,
            "$amdPreferred = $env:FERRUM2_GATE06_CPU_VENDOR -eq \"AuthenticAMD\"",
            "$amdPreferred = $env:FERRUM2_GATE06_CPU_VENDOR -eq \"AuthenticAMD\"\n          if (-not $amdPreferred) { throw \"AMD required\" }",
        ),
        mutate_first(
            &main,
            "& $gate --output $evidence",
            "if ($amdPreferred) { & $gate --output $evidence }",
        ),
        mutate_first(
            &main,
            "        timeout-minutes: 15\n        shell: pwsh",
            "        shell: pwsh",
        ),
        mutate_first(
            &main,
            "        timeout-minutes: 15",
            "        timeout-minutes: 30",
        ),
        mutate_first(&main, "    timeout-minutes: 120", "    timeout-minutes: 60"),
        mutate_first(
            &main,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "actions/upload-artifact@v4",
        ),
        mutate_first(
            &main,
            "if: ${{ matrix.profile == 'windows-msvc' && always() }}",
            "if: matrix.profile == 'windows-msvc'",
        ),
        mutate_first(
            &main,
            "          retention-days: 90",
            "          retention-days: 30",
        ),
        mutate_first(
            &main,
            "          if-no-files-found: error",
            "          if-no-files-found: ignore",
        ),
    ] {
        assert!(
            validate_hosted_library_execution(&corrupted_non_tun_gate).is_err(),
            "Windows non-TUN gate mutations must fail closed"
        );
    }

    for (from, to) in [
        (
            "ferrum2.windows-non-tun-gate06.v2",
            "ferrum2.windows-non-tun-gate06.v1",
        ),
        (
            "sync_loopback_udp_bind_local_addr_drop_then_windows_catalog_snapshot_and_resolver_without_runtime_service_or_owner",
            "unspecified_network_warmup",
        ),
        ("$warmup.exact -ne $true", "$warmup.exact -ne $false"),
        ("$cleanup.exact -ne $true", "$cleanup.exact -ne $false"),
        (
            "$cleanup.predicates.handle_count_exact -ne $true",
            "$cleanup.predicates.handle_count_exact -ne $false",
        ),
        (
            "$cleanup.predicates.threads_exact -ne $true",
            "$cleanup.predicates.threads_exact -ne $false",
        ),
        (
            "$cleanup.predicates.physical_udp_endpoints_exact -ne $true",
            "$cleanup.predicates.physical_udp_endpoints_exact -ne $false",
        ),
        (
            "$cleanup.post.handle_count -ne $cleanup.pre.handle_count",
            "$cleanup.post.handle_count -lt $cleanup.pre.handle_count",
        ),
        (
            "$cleanup.post.threads -ne $cleanup.pre.threads",
            "$cleanup.post.threads -lt $cleanup.pre.threads",
        ),
        (
            "$cleanup.post.physical_udp_endpoints -ne $cleanup.pre.physical_udp_endpoints",
            "$cleanup.post.physical_udp_endpoints -lt $cleanup.pre.physical_udp_endpoints",
        ),
    ] {
        let weakened = mutate_first(&main, from, to);
        assert!(
            validate_hosted_library_execution(&weakened).is_err(),
            "Windows non-TUN v2 cleanup validation weakening must fail closed: {from}"
        );
    }

    for sample in [
        "$warmup.cold",
        "$warmup.first_post",
        "$warmup.second_post",
        "$cleanup.pre",
        "$cleanup.post",
    ] {
        let check = format!("-not (Test-Gate06ProcessSample {sample})");
        let weakened = mutate_first(&main, &check, "$false");
        assert!(
            validate_hosted_library_execution(&weakened).is_err(),
            "Windows non-TUN process sample cannot be omitted: {sample}"
        );
    }
    for field in ["handle_count", "threads", "physical_udp_endpoints"] {
        let check = format!("($Sample.{field} -is [long]) -and $Sample.{field} -ge 0");
        let weakened = mutate_first(&main, &check, "$true");
        assert!(
            validate_hosted_library_execution(&weakened).is_err(),
            "Windows non-TUN process sample field cannot be omitted: {field}"
        );
    }

    let deleted_stage = mutate_first(&main, "            \"dynamic_cleanup\",\n", "");
    assert!(
        validate_hosted_library_execution(&deleted_stage).is_err(),
        "Windows non-TUN stage closure cannot omit a stage"
    );
    for (from, to) in [
        (
            "$stage.stage_exact -ne $true",
            "$stage.stage_exact -ne $false",
        ),
        (
            "$stage.stage_predicates.owners_exact -ne $true",
            "$stage.stage_predicates.owners_exact -ne $false",
        ),
        (
            "$stage.stage_predicates.tasks_exact -ne $true",
            "$stage.stage_predicates.tasks_exact -ne $false",
        ),
        (
            "$stage.stage_predicates.physical_udp_endpoints_exact -ne $true",
            "$stage.stage_predicates.physical_udp_endpoints_exact -ne $false",
        ),
        (
            "$stage.stage_predicates.threads_at_or_below_baseline -ne $true",
            "$stage.stage_predicates.threads_at_or_below_baseline -ne $false",
        ),
        (
            "$cleanupExpected -and $stage.stage_cleanup_at_baseline -ne $true",
            "$cleanupExpected -and $stage.stage_cleanup_at_baseline -ne $false",
        ),
        (
            "$stage.PSObject.Properties.Name -notcontains \"stage_cleanup_at_baseline\"",
            "$false",
        ),
    ] {
        let weakened = mutate_first(&main, from, to);
        assert!(
            validate_hosted_library_execution(&weakened).is_err(),
            "Windows non-TUN stage validation weakening must fail closed: {from}"
        );
    }

    let upload_before_qualification = move_block_before(
        &main,
        "      - name: Upload Windows non-TUN generation evidence\n",
        "      - name: Run hosted-safe Windows TUN unit tests\n",
        "      - name: Run Windows non-TUN generation qualification\n",
    );
    assert!(
        validate_hosted_library_execution(&upload_before_qualification).is_err(),
        "Windows non-TUN evidence upload cannot precede qualification"
    );

    let excluded_windows = mutate_first(
        &main,
        "            target: x86_64-unknown-linux-musl\n    runs-on:",
        "            target: x86_64-unknown-linux-musl\n        exclude:\n          - profile: windows-msvc\n    runs-on:",
    );
    assert!(validate_hosted_library_execution(&excluded_windows).is_err());

    let conditional_windows = mutate_first(
        &main,
        "      - name: Run hosted-safe Windows TUN unit tests\n        if: matrix.profile == 'windows-msvc'",
        "      - name: Run hosted-safe Windows TUN unit tests\n        if: false",
    );
    assert!(validate_hosted_library_execution(&conditional_windows).is_err());

    let wrapped_linux_hosted = mutate_first(
        &main,
        "          cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked\n",
        "          if false; then\n            cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked\n          fi\n",
    );
    assert!(validate_hosted_library_execution(&wrapped_linux_hosted).is_err());

    let wrapped_windows_hosted = mutate_first(
        &main,
        "          cargo +1.97.1 test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked --target ${{ matrix.target }}\n",
        "          if ($false) {\n            cargo +1.97.1 test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked --target ${{ matrix.target }}\n          }\n",
    );
    assert!(validate_hosted_library_execution(&wrapped_windows_hosted).is_err());

    let detached_windows_target = mutate_first(
        &main,
        "cargo +1.97.1 test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked --target ${{ matrix.target }}",
        "cargo +1.97.1 test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked --target x86_64-pc-windows-msvc",
    );
    assert!(validate_hosted_library_execution(&detached_windows_target).is_err());

    let extra_related_test = mutate_first(
        &main,
        "          cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked\n",
        "          cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked\n          cargo test -p ferrum2-tun --all-features --no-run --locked\n",
    );
    assert!(validate_hosted_library_execution(&extra_related_test).is_err());

    let implicit_all_features_test = mutate_first(
        &main,
        "          cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked\n",
        "          cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked\n          cargo test --all-features --no-run --locked\n",
    );
    assert!(validate_hosted_library_execution(&implicit_all_features_test).is_err());

    let early_linux_return = mutate_first(
        &main,
        "          cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked\n",
        "          return 0\n          cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked\n",
    );
    assert!(validate_hosted_library_execution(&early_linux_return).is_err());

    let extra_resolver_build = mutate_first(
        &main,
        "            $events = & cargo +1.97.1 test -p $Package",
        "            $ignored = & cargo +1.97.1 test -p $Package --all-features --no-run\n            $events = & cargo +1.97.1 test -p $Package",
    );
    assert!(validate_hosted_library_execution(&extra_resolver_build).is_err());

    let extra_pe_readback = mutate_first(
        &main,
        "            $imports = & $dumpbin /imports $entry.Path 2>&1 | Out-String\n",
        "            $imports = & $dumpbin /imports $entry.Path 2>&1 | Out-String\n            $shadowImports = & $dumpbin /imports $entry.Path 2>&1 | Out-String\n",
    );
    assert!(validate_hosted_library_execution(&extra_pe_readback).is_err());

    let early_pe_return = mutate_first(
        &main,
        "            return $executable\n",
        "            return $executable\n            return $executable\n",
    );
    assert!(validate_hosted_library_execution(&early_pe_return).is_err());

    let inline_pe_exit = mutate_first(
        &main,
        "            $status = $LASTEXITCODE\n",
        "            if ($LASTEXITCODE -eq 0) { exit 0 }\n            $status = $LASTEXITCODE\n",
    );
    assert!(validate_hosted_library_execution(&inline_pe_exit).is_err());

    let extra_pe_pass = mutate_first(
        &main,
        "            Write-Output \"hosted_test_pe_imports status=PASS package=$($entry.Name) live_backend_imports=0\"\n",
        "            Write-Output \"hosted_test_pe_imports status=PASS package=$($entry.Name) live_backend_imports=0\"\n            Write-Output \"hosted_test_pe_imports status=PASS package=$($entry.Name) live_backend_imports=0\"\n",
    );
    assert!(validate_hosted_library_execution(&extra_pe_pass).is_err());

    for corrupted_pe_contract in [
        mutate_first(
            &main,
            "--no-run --message-format=json --target '${{ matrix.target }}'",
            "--no-run --target '${{ matrix.target }}'",
        ),
        mutate_first(
            &main,
            "-TargetName 'ferrum2_tun'",
            "-TargetName 'ferrum2_tun_wrong'",
        ),
        mutate_first(
            &main,
            "$event.profile.test -eq $true",
            "$event.profile.test -eq $false",
        ),
        mutate_first(
            &main,
            "if ($executables.Count -ne 1)",
            "if ($executables.Count -ne 2)",
        ),
        mutate_first(
            &main,
            "target\\${{ matrix.target }}\\debug\\deps",
            "target\\${{ matrix.target }}\\release",
        ),
        mutate_first(&main, "            '(?i)\\biphlpapi\\.dll\\b',\n", ""),
        mutate_first(
            &main,
            "$dumpbin /imports $entry.Path",
            "$dumpbin /headers $entry.Path",
        ),
    ] {
        assert!(validate_hosted_library_execution(&corrupted_pe_contract).is_err());
    }
}

#[test]
fn performance_rule_actions_read_permission_exception_is_exact() {
    let source =
        fs::read_to_string(workspace_root().join(".github/workflows/performance-rule.yml"))
            .expect("performance Rule workflow source");
    validate_workflow_permissions(".github/workflows/performance-rule.yml", &source)
        .expect("performance Rule cross-run artifact permissions");

    assert!(validate_workflow_permissions(".github/workflows/lookalike.yml", &source).is_err());
    let missing_actions = mutate_first(&source, "  actions: read\n", "");
    assert!(
        validate_workflow_permissions(".github/workflows/performance-rule.yml", &missing_actions)
            .is_err()
    );
    let writable_contents = mutate_first(&source, "  contents: read\n", "  contents: write\n");
    assert!(
        validate_workflow_permissions(
            ".github/workflows/performance-rule.yml",
            &writable_contents,
        )
        .is_err()
    );
    for replacement in ["  actions: write\n", "  checks: read\n"] {
        let mutated = mutate_first(&source, "  actions: read\n", replacement);
        assert!(
            validate_workflow_permissions(".github/workflows/performance-rule.yml", &mutated)
                .is_err()
        );
    }
}

#[test]
fn fuzz_execution_mutations_fail_closed() {
    let fuzz =
        fs::read_to_string(workspace_root().join(".github/workflows/tun-fuzz-deterministic.yml"))
            .expect("fuzz workflow source");
    validate_fuzz_workflow_execution(&fuzz).expect("current fuzz execution contract");

    let compile_only_smoke = mutate_first(
        &fuzz,
        "./target/debug/smoke",
        "test -x ./target/debug/smoke",
    );
    assert!(validate_fuzz_workflow_execution(&compile_only_smoke).is_err());

    let conditional_smoke = mutate_first(
        &fuzz,
        "      - name: Run deterministic TUN smoke corpus\n        shell: bash",
        "      - name: Run deterministic TUN smoke corpus\n        if: false\n        shell: bash",
    );
    assert!(validate_fuzz_workflow_execution(&conditional_smoke).is_err());

    let wrapped_smoke = mutate_first(
        &fuzz,
        "          ./target/debug/smoke\n",
        "          if false; then\n            ./target/debug/smoke\n          fi\n",
    );
    assert!(validate_fuzz_workflow_execution(&wrapped_smoke).is_err());

    let conditional_impact = mutate_first(
        &fuzz,
        "        id: classify\n        shell: bash",
        "        id: classify\n        if: false\n        shell: bash",
    );
    assert!(validate_fuzz_workflow_execution(&conditional_impact).is_err());

    let conditional_campaign = mutate_first(
        &fuzz,
        "      - name: Run target sanitizer fuzz campaign\n        shell: bash",
        "      - name: Run target sanitizer fuzz campaign\n        if: false\n        shell: bash",
    );
    assert!(validate_fuzz_workflow_execution(&conditional_campaign).is_err());

    let wrapped_campaign = mutate_first(
        &fuzz,
        "          timeout --signal=TERM --kill-after=30s \"${outer_timeout_seconds}s\" \\\n",
        "          if false; then\n            timeout --signal=TERM --kill-after=30s \"${outer_timeout_seconds}s\" \\\n",
    );
    let wrapped_campaign = mutate_first(
        &wrapped_campaign,
        "            2>&1 | tee \"$campaign_root/logs/$FUZZ_TARGET.log\"\n",
        "              2>&1 | tee \"$campaign_root/logs/$FUZZ_TARGET.log\"\n          fi\n",
    );
    assert!(validate_fuzz_workflow_execution(&wrapped_campaign).is_err());

    let detached_budget = mutate_first(
        &fuzz,
        "FUZZ_SECONDS_PER_TARGET: ${{ needs.impact.outputs.seconds_per_target }}",
        "FUZZ_SECONDS_PER_TARGET: 900",
    );
    assert!(validate_fuzz_workflow_execution(&detached_budget).is_err());

    let ignored_budget = mutate_first(
        &fuzz,
        "-max_total_time=\"$FUZZ_SECONDS_PER_TARGET\"",
        "-max_total_time=900",
    );
    assert!(validate_fuzz_workflow_execution(&ignored_budget).is_err());

    let extra_smoke = mutate_first(
        &fuzz,
        "          ./target/debug/smoke\n",
        "          ./target/debug/smoke\n          ./target/debug/smoke\n",
    );
    assert!(validate_fuzz_workflow_execution(&extra_smoke).is_err());

    let unbounded_extra_campaign = mutate_first(
        &fuzz,
        "          campaign_root=\"$RUNNER_TEMP/tun-fuzz-campaign\"\n          outer_timeout_seconds=",
        "          campaign_root=\"$RUNNER_TEMP/tun-fuzz-campaign\"\n          \"$RUNNER_TEMP/tun-fuzz-binaries/$FUZZ_TARGET\" \"$campaign_root/corpus/$FUZZ_TARGET\"\n          outer_timeout_seconds=",
    );
    assert!(validate_fuzz_workflow_execution(&unbounded_extra_campaign).is_err());

    let extra_cargo_fuzz_run = mutate_first(
        &fuzz,
        "            CARGO_NET_OFFLINE=true cargo +nightly-2026-07-10 fuzz build --features libfuzzer \"$target\"\n",
        "            CARGO_NET_OFFLINE=true cargo +nightly-2026-07-10 fuzz build --features libfuzzer \"$target\"\n            cargo +nightly-2026-07-10 fuzz run \"$target\"\n",
    );
    assert!(validate_fuzz_workflow_execution(&extra_cargo_fuzz_run).is_err());

    let early_fuzz_exit = mutate_first(
        &fuzz,
        "          ./target/debug/smoke\n",
        "          exit 0\n          ./target/debug/smoke\n",
    );
    assert!(validate_fuzz_workflow_execution(&early_fuzz_exit).is_err());

    let extra_classifier = mutate_first(
        &fuzz,
        "          python3 -B -m tools.ci.fuzz_contract \\\n",
        "          python3 -B -m tools.ci.fuzz_contract --help\n          python3 -B -m tools.ci.fuzz_contract \\\n",
    );
    assert!(validate_fuzz_workflow_execution(&extra_classifier).is_err());

    let filtered_pull_request = mutate_first(
        &fuzz,
        "  pull_request:\n",
        "  pull_request:\n    paths:\n      - crates/ferrum2-tun/**\n",
    );
    assert!(validate_fuzz_workflow_execution(&filtered_pull_request).is_err());

    let widened_branches = mutate_first(
        &fuzz,
        "      - \"codex/integration/**\"\n",
        "      - \"codex/integration/**\"\n      - feature/**\n",
    );
    assert!(validate_fuzz_workflow_execution(&widened_branches).is_err());

    let excluded_target = mutate_first(
        &fuzz,
        "        target: ${{ fromJSON(needs.impact.outputs.targets_json) }}\n    runs-on:",
        "        target: ${{ fromJSON(needs.impact.outputs.targets_json) }}\n        exclude:\n          - target: packet_reassembly\n    runs-on:",
    );
    assert!(validate_fuzz_workflow_execution(&excluded_target).is_err());

    for (job, name) in [
        ("impact", "impact"),
        ("deterministic-build", "deterministic-build"),
        ("libfuzzer-build", "libfuzzer-build"),
        ("fuzz-campaign", "fuzz-campaign (${{ matrix.target }})"),
    ] {
        let job_suppressed = mutate_first(
            &fuzz,
            &format!("  {job}:\n    name: {name}"),
            &format!("  {job}:\n    name: {name}\n    continue-on-error: true"),
        );
        assert!(
            validate_fuzz_workflow_execution(&job_suppressed).is_err(),
            "{job} job-level failure suppression must fail closed"
        );
    }
}

#[test]
fn required_job_mutations_fail_closed() {
    let workflow_root = workspace_root().join(".github/workflows");
    let main = fs::read_to_string(workflow_root.join("m0.yml")).expect("main workflow source");
    let main_dependencies = dependencies(&["changes", "quality", "platform", "interop"]);
    validate_required_job(&main, &main_dependencies).expect("current main required job");

    let fuzz = fs::read_to_string(workflow_root.join("tun-fuzz-deterministic.yml"))
        .expect("fuzz workflow source");
    let fuzz_dependencies = dependencies(&[
        "impact",
        "deterministic-build",
        "libfuzzer-build",
        "fuzz-campaign",
    ]);
    validate_required_job(&fuzz, &fuzz_dependencies).expect("current fuzz required job");

    let not_always = mutate_first(
        &main,
        "  required:\n    name: required\n    if: ${{ always() }}",
        "  required:\n    name: required\n    if: false",
    );
    assert!(validate_required_job(&not_always, &main_dependencies).is_err());

    let missing_need = mutate_first(&main, "      - quality\n", "");
    assert!(validate_required_job(&missing_need, &main_dependencies).is_err());

    let detached_result = mutate_first(
        &main,
        "QUALITY_RESULT: ${{ needs.quality.result }}",
        "QUALITY_RESULT: success",
    );
    assert!(validate_required_job(&detached_result, &main_dependencies).is_err());

    let missing_controller_dependency =
        mutate_first(&main, " --dependency \"quality=$QUALITY_RESULT\"", "");
    assert!(validate_required_job(&missing_controller_dependency, &main_dependencies).is_err());

    let wrong_mode = mutate_first(&main, "--mode ordinary", "--mode fuzz");
    assert!(validate_required_job(&wrong_mode, &main_dependencies).is_err());

    let early_success = mutate_first(
        &main,
        " --dependency \"interop=$INTEROP_RESULT\"",
        " --dependency \"interop=$INTEROP_RESULT\"; exit 0",
    );
    assert!(validate_required_job(&early_success, &main_dependencies).is_err());

    let conditional_step = mutate_first(
        &main,
        "      - name: Require every ordinary main gate\n        shell: bash",
        "      - name: Require every ordinary main gate\n        if: false\n        shell: bash",
    );
    assert!(validate_required_job(&conditional_step, &main_dependencies).is_err());

    let suppressed_step = mutate_first(
        &main,
        "      - name: Require every ordinary main gate\n        shell: bash",
        "      - name: Require every ordinary main gate\n        continue-on-error: true\n        shell: bash",
    );
    assert!(validate_required_job(&suppressed_step, &main_dependencies).is_err());

    let wrong_checkout = mutate_first(
        &main,
        "          fetch-depth: 1\n",
        "          fetch-depth: 0\n",
    );
    assert!(validate_required_job(&wrong_checkout, &main_dependencies).is_err());

    let extra_step = mutate_first(
        &main,
        "      - name: Require every ordinary main gate",
        "      - name: Early success\n        run: exit 0\n      - name: Require every ordinary main gate",
    );
    assert!(validate_required_job(&extra_step, &main_dependencies).is_err());

    for (source, expected) in [(&main, &main_dependencies), (&fuzz, &fuzz_dependencies)] {
        let suppressed_job = mutate_first(
            source,
            "  required:\n    name: required",
            "  required:\n    name: required\n    continue-on-error: true",
        );
        assert!(validate_required_job(&suppressed_job, expected).is_err());
    }
}

#[test]
fn lifecycle_trigger_mutations_fail_closed() {
    let lifecycle =
        fs::read_to_string(workspace_root().join(".github/workflows/lifecycle-stress.yml"))
            .expect("lifecycle workflow source");
    validate_lifecycle_triggers(&lifecycle).expect("current lifecycle triggers");

    let scheduled = mutate_first(&lifecycle, "  workflow_dispatch:\n", "  schedule:\n");
    assert!(validate_lifecycle_triggers(&scheduled).is_err());
    let filtered_push = mutate_first(
        &lifecycle,
        "  push:\n",
        "  push:\n    paths:\n      - crates/ferrum2-runtime/**\n",
    );
    assert!(validate_lifecycle_triggers(&filtered_push).is_err());
}
