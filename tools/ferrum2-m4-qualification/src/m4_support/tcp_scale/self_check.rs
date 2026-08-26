use super::contract::{
    ACTIVE_SAMPLE_SLOT_DENOMINATOR, CollectedPhase, FRAME_FLOW_OFFSET, FRAME_GENERATION_OFFSET,
    FRAME_HEADER_BYTES, FRAME_SEQUENCE_OFFSET, PARTIAL_ACTIVE_FLOWS, PARTIAL_SELECTOR_MODULUS,
    PARTIAL_SELECTOR_REMAINDER, RESOURCE_SAMPLES_PER_PHASE, RUNTIME_WORKER_THREADS,
    SCALE_PAYLOAD_BYTES, SCALE_SCHEMA_VERSION, SCALE_SETUP_IO_SLICE, SESSIONS, ScaleCorrectness,
    ScaleEvidence, ScaleFairness, ScalePairSample, ScaleRecipe, ScaleResource, ScaleTraffic,
    TOUCH_ROUNDS, encode_frame_header, fairness, initialize_payload, per_connection_increment,
    validate_frame,
};
use super::flow::validate_phase_accounting;
use super::setup::{
    bounded_parallel_setup, ensure_active_sample_before_deadline, scale_setup_io_timeout_at,
};
use crate::m4_support::SETUP_WORKERS;
use crate::m4_support::evidence_support::validate_evidence_line;
use crate::m4_support::process_support::{REAP_TIMEOUT, clean_io};
use crate::m4_support::profile_contract::{
    EVIDENCE_LINE_MAX_BYTES, PROFILE_TRIAL_SCHEMA_VERSION, TCP_SCALE_EVIDENCE_LINE_MAX_BYTES,
};
use crate::m4_support::self_check::expect_rejected;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

pub(crate) fn synthetic_sample(value: u64) -> ScalePairSample {
    ScalePairSample {
        client_active: value,
        server_active: value,
        client_fds: value,
        server_fds: value,
        client_tasks: value,
        server_tasks: value,
        client_rss_kib: value,
        server_rss_kib: value,
        client_smaps_rss_kib: value,
        server_smaps_rss_kib: value,
        client_anonymous_kib: value,
        server_anonymous_kib: value,
        client_anon_huge_pages_kib: value,
        server_anon_huge_pages_kib: value,
        harness_rss_kib: value,
    }
}

pub(crate) fn maximum_shape_evidence() -> ScaleEvidence {
    let sample = synthetic_sample(u64::MAX);
    ScaleEvidence {
        schema_version: SCALE_SCHEMA_VERSION,
        recipe: ScaleRecipe {
            sessions: SESSIONS as u64,
            setup_workers: SETUP_WORKERS as u64,
            runtime_worker_threads: RUNTIME_WORKER_THREADS as u64,
            application_futures: SESSIONS as u64,
            target_futures: SESSIONS as u64,
            payload_bytes: SCALE_PAYLOAD_BYTES as u64,
            touch_rounds: TOUCH_ROUNDS as u64,
            partial_active_flows: PARTIAL_ACTIVE_FLOWS as u64,
            partial_selector_modulus: PARTIAL_SELECTOR_MODULUS as u64,
            partial_selector_remainder: PARTIAL_SELECTOR_REMAINDER as u64,
            partial_seconds: 10,
            full_seconds: 30,
            resource_samples_per_phase: RESOURCE_SAMPLES_PER_PHASE as u64,
            quiescent_sample_interval_milliseconds: 1_000,
            active_sample_slot_denominator: ACTIVE_SAMPLE_SLOT_DENOMINATOR as u64,
        },
        correctness: ScaleCorrectness {
            target_accepted: u64::MAX,
            client_active: u64::MAX,
            server_active: u64::MAX,
            touch_completed_flows: u64::MAX,
            touch_completed_round_trips: u64::MAX,
            touch_checked_bytes: u64::MAX,
            payload_checks: u64::MAX,
            partial_nonzero_flows: u64::MAX,
            full_nonzero_flows: u64::MAX,
            application_tasks_joined: u64::MAX,
            target_tasks_joined: u64::MAX,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        traffic: ScaleTraffic {
            partial_checked_bytes: u64::MAX,
            partial_io_completions: u64::MAX,
            partial_discarded_tail_completions: u64::MAX,
            partial_flow_bytes: vec![u64::MAX; PARTIAL_ACTIVE_FLOWS],
            full_checked_bytes: u64::MAX,
            full_io_completions: u64::MAX,
            full_discarded_tail_completions: u64::MAX,
            full_elapsed_nanoseconds: u64::MAX,
            full_flow_bytes: vec![u64::MAX; SESSIONS],
            full_flow_completions: vec![u64::MAX; SESSIONS],
            aggregate_bytes_per_second: u64::MAX,
        },
        fairness: ScaleFairness {
            jain_ppb: u64::MAX,
            minimum_bytes: u64::MAX,
            p01_bytes: u64::MAX,
            p05_bytes: u64::MAX,
            median_bytes: u64::MAX,
            p95_bytes: u64::MAX,
            p99_bytes: u64::MAX,
            maximum_bytes: u64::MAX,
            p01_to_median_ppm: u64::MAX,
        },
        resource: ScaleResource {
            pre_load: vec![sample],
            established: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            touched: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            partial_active: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            full_active: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            post_full: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            drained: vec![sample],
            client_touched_increment_bytes_per_connection: i64::MAX,
            server_touched_increment_bytes_per_connection: i64::MAX,
            combined_touched_increment_bytes_per_connection: i64::MAX,
            harness_peak_rss_kib: u64::MAX,
            memory_available_kib: u64::MAX,
            nofile_soft: u64::MAX,
        },
    }
}

pub(crate) fn maximum_shape_trial() -> Result<String, String> {
    let scale = serde_json::to_value(maximum_shape_evidence())
        .map_err(|_| "maximum scale fixture could not be materialized".to_owned())?;
    serde_json::to_string(&serde_json::json!({
        "schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
        "kind": "m18_profile_trial",
        "parent_sha": "ffffffffffffffffffffffffffffffffffffffff",
        "candidate_sha": "ffffffffffffffffffffffffffffffffffffffff",
        "member": "candidate",
        "pair": u64::MAX,
        "order": u64::MAX,
        "build_profile": "current",
        "scenario": "tcp-scale-10k",
        "warmup_seconds": u64::MAX,
        "active_seconds": u64::MAX,
        "topology": "shadowsocks",
        "application_payload_bytes": u64::MAX,
        "socks_datagram_bytes": null,
        "upstream_wire_bytes": null,
        "sha": "ffffffffffffffffffffffffffffffffffffffff",
        "tree": "ffffffffffffffffffffffffffffffffffffffff",
        "runner_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "client_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "server_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "rustc": "rustc 1.97.1 maximum fixture",
        "kernel": "maximum fixture kernel",
        "cpu_model": "maximum fixture cpu",
        "cpu_count": u64::MAX,
        "memory_kib": u64::MAX,
        "metric": "bytes_per_second",
        "value": u64::MAX,
        "checked_units": u64::MAX,
        "p99_nanoseconds": null,
        "io_completions": u64::MAX,
        "scale": scale,
        "correctness": "PASS",
        "status": "PASS",
    }))
    .map_err(|_| "maximum scale trial fixture could not be encoded".to_owned())
}

pub(crate) async fn double_barrier_probe() -> Result<(), String> {
    const PROBE_TASKS: usize = 4;
    let first = Arc::new(Barrier::new(PROBE_TASKS + 1));
    let second = Arc::new(Barrier::new(PROBE_TASKS + 1));
    let start = Arc::new(OnceLock::new());
    let mut tasks = JoinSet::new();
    for _ in 0..PROBE_TASKS {
        let first = Arc::clone(&first);
        let second = Arc::clone(&second);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            first.wait().await;
            second.wait().await;
            let start = *start
                .get()
                .ok_or_else(|| "barrier probe omitted common start".to_owned())?;
            if Instant::now() >= start {
                return Err("barrier probe released late".to_owned());
            }
            tokio::time::sleep_until(start.into()).await;
            Ok::<(), String>(())
        });
    }
    first.wait().await;
    start
        .set(Instant::now() + Duration::from_millis(100))
        .map_err(|_| "barrier probe start collision".to_owned())?;
    second.wait().await;
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| "barrier probe task panicked".to_owned())??;
    }
    Ok(())
}

pub(crate) fn run_scale_self_check() -> Result<(), String> {
    let timeout_clock = Instant::now();
    if scale_setup_io_timeout_at(
        timeout_clock,
        timeout_clock + SCALE_SETUP_IO_SLICE + Duration::from_secs(1),
    )? != SCALE_SETUP_IO_SLICE
        || scale_setup_io_timeout_at(timeout_clock, timeout_clock + Duration::from_millis(1))?
            != Duration::from_millis(1)
    {
        return Err("scale setup I/O timeout did not preserve its absolute bound".to_owned());
    }
    expect_rejected("expired scale setup I/O deadline", || {
        scale_setup_io_timeout_at(timeout_clock, timeout_clock)
    })?;
    let ordered = bounded_parallel_setup(
        8,
        3,
        Instant::now() + Duration::from_secs(1),
        |index, _deadline| Ok(index),
    )?;
    if ordered != (0..8).collect::<Vec<_>>() {
        return Err("scale bounded setup did not preserve session order".to_owned());
    }
    let released = Arc::new(AtomicBool::new(false));
    let worker_released = Arc::clone(&released);
    let setup_error = bounded_parallel_setup(
        100,
        4,
        Instant::now() + Duration::from_secs(1),
        move |index, deadline| {
            if index == 0 {
                worker_released.store(true, Ordering::SeqCst);
                return Err("sentinel scale setup failure".to_owned());
            }
            while !worker_released.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    return Err("scale setup cancellation probe timed out".to_owned());
                }
                thread::yield_now();
            }
            Ok(index)
        },
    )
    .expect_err("scale setup probe must reject its sentinel failure");
    if setup_error != "sentinel scale setup failure" || !released.load(Ordering::SeqCst) {
        return Err("scale bounded setup did not cancel on its first failure".to_owned());
    }
    let clock = Instant::now();
    ensure_active_sample_before_deadline(clock, clock + Duration::from_nanos(1))?;
    expect_rejected("active sample at phase deadline", || {
        ensure_active_sample_before_deadline(clock, clock)
    })?;
    let body = initialize_payload();
    let mut frame = body.to_vec();
    encode_frame_header(&mut frame, 7, 2, 9)?;
    validate_frame(&frame, &body, 7, 2, 9)?;
    for (name, mutation) in [
        ("scale frame magic", 0_usize),
        ("scale frame flow", FRAME_FLOW_OFFSET),
        ("scale frame generation", FRAME_GENERATION_OFFSET),
        ("scale frame stale sequence", FRAME_SEQUENCE_OFFSET),
        ("scale frame body", FRAME_HEADER_BYTES),
    ] {
        let mut malformed = frame.clone();
        malformed[mutation] ^= 1;
        expect_rejected(name, || validate_frame(&malformed, &body, 7, 2, 9))?;
    }
    let equal = vec![32_768_u64; SESSIONS];
    let equal_fairness = fairness(&equal)?;
    if equal_fairness.jain_ppb != 1_000_000_000
        || equal_fairness.p01_bytes != 32_768
        || equal_fairness.median_bytes != 32_768
        || equal_fairness.p01_to_median_ppm != 1_000_000
    {
        return Err("scale integer fairness contract is invalid".to_owned());
    }
    let mut starved = equal;
    starved[0] = 0;
    let starved_fairness = fairness(&starved)?;
    if starved_fairness.minimum_bytes != 0 || starved_fairness.jain_ppb >= 1_000_000_000 {
        return Err("scale zero-flow fairness did not remain measurable".to_owned());
    }
    let phase = CollectedPhase {
        flow_bytes: vec![SCALE_PAYLOAD_BYTES as u64; PARTIAL_ACTIVE_FLOWS],
        flow_completions: vec![1; PARTIAL_ACTIVE_FLOWS],
        checked_bytes: (SCALE_PAYLOAD_BYTES * PARTIAL_ACTIVE_FLOWS) as u64,
        completions: PARTIAL_ACTIVE_FLOWS as u64,
        discarded_tail_completions: PARTIAL_ACTIVE_FLOWS as u64,
    };
    validate_phase_accounting(&phase, PARTIAL_ACTIVE_FLOWS, true)?;
    let mut malformed = phase.flow_bytes.clone();
    malformed.pop();
    expect_rejected("incomplete scale phase vector", || {
        validate_phase_accounting(
            &CollectedPhase {
                flow_bytes: malformed,
                flow_completions: phase.flow_completions.clone(),
                checked_bytes: phase.checked_bytes,
                completions: phase.completions,
                discarded_tail_completions: phase.discarded_tail_completions,
            },
            PARTIAL_ACTIVE_FLOWS,
            true,
        )
    })?;
    let established = vec![synthetic_sample(1_000); RESOURCE_SAMPLES_PER_PHASE];
    let touched = vec![synthetic_sample(990); RESOURCE_SAMPLES_PER_PHASE];
    if per_connection_increment(&established, &touched, |sample| sample.client_smaps_rss_kib)? != -1
    {
        return Err("scale signed RSS delta was not preserved".to_owned());
    }
    let maximum_json = maximum_shape_trial()?;
    if maximum_json.contains('\n')
        || maximum_json.len() <= EVIDENCE_LINE_MAX_BYTES
        || maximum_json.len() + 4_096 > TCP_SCALE_EVIDENCE_LINE_MAX_BYTES
    {
        return Err("maximum scale fixture violates the evidence envelope".to_owned());
    }
    validate_evidence_line(&maximum_json, TCP_SCALE_EVIDENCE_LINE_MAX_BYTES)?;
    expect_rejected("scale evidence above dedicated cap", || {
        validate_evidence_line(
            &"x".repeat(TCP_SCALE_EVIDENCE_LINE_MAX_BYTES + 1),
            TCP_SCALE_EVIDENCE_LINE_MAX_BYTES,
        )
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKER_THREADS)
        .enable_time()
        .build()
        .map_err(clean_io)?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), double_barrier_probe())
            .await
            .map_err(|_| "scale double-barrier probe timed out".to_owned())?
    })?;
    runtime.shutdown_timeout(REAP_TIMEOUT);
    Ok(())
}
