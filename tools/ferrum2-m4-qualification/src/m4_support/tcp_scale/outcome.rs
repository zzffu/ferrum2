use super::contract::{
    ACTIVE_SAMPLE_SLOT_DENOMINATOR, ExecutionResult, PARTIAL_ACTIVE_FLOWS,
    PARTIAL_SELECTOR_MODULUS, PARTIAL_SELECTOR_REMAINDER, RESOURCE_SAMPLE_INTERVAL,
    RESOURCE_SAMPLES_PER_PHASE, RUNTIME_WORKER_THREADS, SCALE_IO_TIMEOUT, SCALE_PAYLOAD_BYTES,
    SCALE_SCHEMA_VERSION, SESSIONS, ScaleCorrectness, ScaleEvidence, ScalePairSample, ScaleRecipe,
    ScaleResource, ScaleTraffic, TOUCH_ROUNDS, fairness, per_connection_increment,
};
use super::execution::execute;
use super::setup::{
    ScaleTargetAcceptor, establish_scale_sessions, memory_available_kib, profile_nofile_soft,
};
use crate::m4_support::dns_resource::prove_tcp_rebind;
use crate::m4_support::evidence_support::{PortReservation, profile_binary, spawn_proxy};
use crate::m4_support::host_identity::linux_capacity;
use crate::m4_support::process_support::{REAP_TIMEOUT, clean_io, remaining, v4, wait_for_metrics};
use crate::m4_support::profile_contract::{
    ProfileArgs, ProfileOutcome, TCP_SCALE_EVIDENCE_LINE_MAX_BYTES, Topology,
};
use crate::m4_support::profile_structural::StructuralMetrics;
use crate::m4_support::proxy_config::{ferrum_client_config, ferrum_server_config};
use crate::m4_support::resource_sampling::{
    PairSample, proc_sample, sample_pair, validate_drain, wait_for_sessions,
};
use crate::m4_support::self_check::assert_no_owners;
use crate::m4_support::throughput::rate_per_second;
use crate::m4_support::{DRAIN_TIMEOUT, SETUP_WORKERS};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn observed_pair(sample: PairSample) -> Result<ScalePairSample, String> {
    Ok(ScalePairSample::observed(
        sample,
        proc_sample(std::process::id())?.rss_kib,
    ))
}

pub(crate) fn staged_harness_peak(stages: &[&[ScalePairSample]]) -> Result<u64, String> {
    stages
        .iter()
        .flat_map(|stage| stage.iter())
        .map(|sample| sample.harness_rss_kib)
        .max()
        .ok_or_else(|| "scale resource observations are empty".to_owned())
}

pub(crate) fn build_outcome(
    arguments: &ProfileArgs,
    pre_load: ScalePairSample,
    owner_identity: PairSample,
    execution: ExecutionResult,
    drained: ScalePairSample,
    available_memory_kib: u64,
    nofile_soft: u64,
) -> Result<ProfileOutcome, String> {
    let fairness = fairness(&execution.full.flow_bytes)?;
    let full_elapsed_nanoseconds = u64::try_from(execution.full_elapsed.as_nanos())
        .map_err(|_| "scale full elapsed time exceeds u64".to_owned())?;
    let aggregate_bytes_per_second =
        rate_per_second(execution.full.checked_bytes, execution.full_elapsed)?;
    let client_increment =
        per_connection_increment(&execution.established, &execution.touched, |sample| {
            sample.client_smaps_rss_kib
        })?;
    let server_increment =
        per_connection_increment(&execution.established, &execution.touched, |sample| {
            sample.server_smaps_rss_kib
        })?;
    let combined_increment = client_increment
        .checked_add(server_increment)
        .ok_or_else(|| "scale combined per-connection RSS delta overflow".to_owned())?;
    let pre_load = vec![pre_load];
    let drained = vec![drained];
    let harness_peak_rss_kib = staged_harness_peak(&[
        &pre_load,
        &execution.established,
        &execution.touched,
        &execution.partial_active,
        &execution.full_active,
        &execution.post_full,
        &drained,
    ])?;
    if harness_peak_rss_kib
        != execution
            .harness_peak_rss_kib
            .max(pre_load[0].harness_rss_kib)
            .max(drained[0].harness_rss_kib)
    {
        return Err("scale harness RSS peak accounting is inconsistent".to_owned());
    }
    let touch_completed_flows = execution
        .touch
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    let partial_nonzero_flows = execution
        .partial
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    let full_nonzero_flows = execution
        .full
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    if touch_completed_flows != SESSIONS
        || owner_identity.client.active != SESSIONS as u64
        || owner_identity.server.active != SESSIONS as u64
        || execution.application_tasks_joined != SESSIONS
        || execution.target_tasks_joined != SESSIONS
    {
        return Err("scale lifecycle correctness is incomplete".to_owned());
    }
    let payload_checks = execution
        .touch
        .completions
        .checked_add(execution.partial.completions)
        .and_then(|value| value.checked_add(execution.partial.discarded_tail_completions))
        .and_then(|value| value.checked_add(execution.full.completions))
        .and_then(|value| value.checked_add(execution.full.discarded_tail_completions))
        .ok_or_else(|| "scale payload check count overflow".to_owned())?;
    let full_io_completions = execution.full.completions;
    let evidence = ScaleEvidence {
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
            partial_seconds: arguments.warmup_seconds,
            full_seconds: arguments.active_seconds,
            resource_samples_per_phase: RESOURCE_SAMPLES_PER_PHASE as u64,
            quiescent_sample_interval_milliseconds: u64::try_from(
                RESOURCE_SAMPLE_INTERVAL.as_millis(),
            )
            .expect("resource interval fits u64"),
            active_sample_slot_denominator: ACTIVE_SAMPLE_SLOT_DENOMINATOR as u64,
        },
        correctness: ScaleCorrectness {
            target_accepted: SESSIONS as u64,
            client_active: owner_identity.client.active,
            server_active: owner_identity.server.active,
            touch_completed_flows: touch_completed_flows as u64,
            touch_completed_round_trips: execution.touch.completions,
            touch_checked_bytes: execution.touch.checked_bytes,
            payload_checks,
            partial_nonzero_flows: partial_nonzero_flows as u64,
            full_nonzero_flows: full_nonzero_flows as u64,
            application_tasks_joined: execution.application_tasks_joined as u64,
            target_tasks_joined: execution.target_tasks_joined as u64,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        traffic: ScaleTraffic {
            partial_checked_bytes: execution.partial.checked_bytes,
            partial_io_completions: execution.partial.completions,
            partial_discarded_tail_completions: execution.partial.discarded_tail_completions,
            partial_flow_bytes: execution.partial.flow_bytes,
            full_checked_bytes: execution.full.checked_bytes,
            full_io_completions,
            full_discarded_tail_completions: execution.full.discarded_tail_completions,
            full_elapsed_nanoseconds,
            full_flow_bytes: execution.full.flow_bytes,
            full_flow_completions: execution.full.flow_completions,
            aggregate_bytes_per_second,
        },
        fairness,
        resource: ScaleResource {
            pre_load,
            established: execution.established,
            touched: execution.touched,
            partial_active: execution.partial_active,
            full_active: execution.full_active,
            post_full: execution.post_full,
            drained,
            client_touched_increment_bytes_per_connection: client_increment,
            server_touched_increment_bytes_per_connection: server_increment,
            combined_touched_increment_bytes_per_connection: combined_increment,
            harness_peak_rss_kib,
            memory_available_kib: available_memory_kib,
            nofile_soft,
        },
    };
    let scale_json = serde_json::to_string(&evidence)
        .map_err(|_| "scale evidence could not be encoded".to_owned())?;
    if scale_json.len() + 4_096 > TCP_SCALE_EVIDENCE_LINE_MAX_BYTES {
        return Err("scale evidence exceeds its bounded trial envelope".to_owned());
    }
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario=tcp-scale-10k \
             sessions={SESSIONS} partial_flows={PARTIAL_ACTIVE_FLOWS} bytes={} \
             jain_ppb={} drain=PASS rebind=PASS",
            evidence.traffic.full_checked_bytes, evidence.fairness.jain_ppb,
        ),
        metric: "bytes_per_second",
        value: aggregate_bytes_per_second,
        checked_units: evidence.traffic.full_checked_bytes,
        p99_nanoseconds: None,
        io_completions: full_io_completions
            .checked_mul(2)
            .ok_or_else(|| "scale I/O completion count overflow".to_owned())?,
        scale_json: Some(scale_json),
        structural_metrics: StructuralMetrics::unavailable(),
    })
}

pub(crate) fn run_scale(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    if arguments.warmup_seconds != 10 || arguments.active_seconds != 30 {
        return Err("tcp-scale-10k requires the fixed 10/30 second recipe".to_owned());
    }
    let cpu_count = thread::available_parallelism()
        .map_err(|_| "scale logical CPU count is unavailable".to_owned())?
        .get();
    let (memory_total_kib, _) = linux_capacity()?;
    if cpu_count < RUNTIME_WORKER_THREADS || memory_total_kib < 15_000_000 {
        return Err("scale host capacity is below the fixed recipe".to_owned());
    }
    let available_memory_kib = memory_available_kib()?;
    let nofile_soft = profile_nofile_soft()?;
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-tcp-scale-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let target_socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(clean_io)?;
    target_socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())
        .map_err(clean_io)?;
    target_socket
        .listen(i32::try_from(SESSIONS).expect("scale backlog fits i32"))
        .map_err(clean_io)?;
    let target_listener: TcpListener = target_socket.into();
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let mut server_reservation = Some(PortReservation::new()?);
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut client_metrics_reservation = Some(PortReservation::new()?);
    let mut server_metrics_reservation = Some(PortReservation::new()?);
    let server_address = server_reservation
        .as_ref()
        .expect("server reservation")
        .address;
    let proxy_address = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let client_metrics = client_metrics_reservation
        .as_ref()
        .expect("client metrics reservation")
        .address;
    let server_metrics = server_metrics_reservation
        .as_ref()
        .expect("server metrics reservation")
        .address;
    let client_config = directory
        .as_ref()
        .expect("scale directory")
        .path()
        .join("client.toml");
    let server_config = directory
        .as_ref()
        .expect("scale directory")
        .path()
        .join("server.toml");
    let mut target_acceptor = None;
    let mut server_process = None;
    let mut client_process = None;
    let mut completed = None;
    let mut errors = Vec::new();

    let execution = (|| -> Result<(), String> {
        fs::write(
            &client_config,
            ferrum_client_config(proxy_address, server_address, Some(client_metrics)),
        )
        .map_err(clean_io)?;
        fs::write(
            &server_config,
            ferrum_server_config(server_address, Some(server_metrics)),
        )
        .map_err(clean_io)?;
        target_acceptor = Some(ScaleTargetAcceptor::start(target_listener)?);
        server_reservation
            .take()
            .expect("server reservation")
            .release();
        server_metrics_reservation
            .take()
            .expect("server metrics reservation")
            .release();
        server_process = Some(spawn_proxy(
            Topology::Ferrum,
            "scale server",
            &profile_binary(&arguments.binary_dir, "ferrum2-server")?,
            &server_config,
        )?);
        wait_for_metrics(
            server_process.as_mut().expect("scale server process"),
            server_metrics,
        )?;
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        client_metrics_reservation
            .take()
            .expect("client metrics reservation")
            .release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "scale client",
            &profile_binary(&arguments.binary_dir, "ferrum2-client")?,
            &client_config,
        )?);
        wait_for_metrics(
            client_process.as_mut().expect("scale client process"),
            client_metrics,
        )?;
        let pre_load_pair = sample_pair(
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
            Instant::now() + SCALE_IO_TIMEOUT,
        )?;
        if pre_load_pair.client.active != 0 || pre_load_pair.server.active != 0 {
            return Err("scale pre-load active gauges are not zero".to_owned());
        }
        client_process
            .as_mut()
            .expect("scale client process")
            .ensure_running()?;
        server_process
            .as_mut()
            .expect("scale server process")
            .ensure_running()?;
        let pre_load = observed_pair(pre_load_pair)?;
        let applications = establish_scale_sessions(proxy_address, target)?;
        let targets = target_acceptor
            .take()
            .expect("scale target acceptor")
            .finish(Instant::now() + DRAIN_TIMEOUT)?;
        let owner_identity = wait_for_sessions(
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
        )?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(RUNTIME_WORKER_THREADS)
            .enable_io()
            .enable_time()
            .build()
            .map_err(clean_io)?;
        // `block_on` keeps this coordinator on the caller thread. Only socket futures run on the
        // four runtime workers; procfs/metrics/child probes below never enter the worker pool.
        let scale_execution = runtime.block_on(execute(
            applications,
            targets,
            arguments,
            ready_file,
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
            owner_identity,
        ));
        runtime.shutdown_timeout(REAP_TIMEOUT);
        let scale_execution = scale_execution?;
        let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
        let drained_pair = loop {
            let sample = sample_pair(
                client_process.as_mut().expect("scale client process"),
                server_process.as_mut().expect("scale server process"),
                client_metrics,
                server_metrics,
                drain_deadline,
            )?;
            client_process
                .as_mut()
                .expect("scale client process")
                .ensure_running()?;
            server_process
                .as_mut()
                .expect("scale server process")
                .ensure_running()?;
            if validate_drain(&sample, &pre_load_pair).is_ok() {
                break sample;
            }
            thread::sleep(remaining(drain_deadline)?.min(Duration::from_millis(100)));
        };
        completed = Some((
            pre_load,
            owner_identity,
            scale_execution,
            observed_pair(drained_pair)?,
        ));
        Ok(())
    })();
    if let Err(error) = execution {
        errors.push(error);
    }

    drop(target_acceptor.take());
    drop(server_reservation.take());
    drop(proxy_reservation.take());
    drop(client_metrics_reservation.take());
    drop(server_metrics_reservation.take());
    for (label, process) in [
        ("scale client", &mut client_process),
        ("scale server", &mut server_process),
    ] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("{label} cleanup failed: {error}"));
        }
    }
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("scale directory cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_rebind(proxy_address, "scale client"),
        prove_tcp_rebind(server_address, "scale server"),
        prove_tcp_rebind(client_metrics, "scale client metrics"),
        prove_tcp_rebind(server_metrics, "scale server metrics"),
        prove_tcp_rebind(target, "scale target"),
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    assert_no_owners()?;
    let (pre_load, owner_identity, scale_execution, drained) =
        completed.ok_or_else(|| "scale execution produced no completed evidence".to_owned())?;
    build_outcome(
        arguments,
        pre_load,
        owner_identity,
        scale_execution,
        drained,
        available_memory_kib,
        nofile_soft,
    )
}
