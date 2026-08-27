use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::dns_resource::prove_tcp_rebind;
use super::evidence_support::{PortReservation, profile_binary, spawn_proxy};
use super::process_support::{
    STARTUP_TIMEOUT, StartGate, TargetWorker, clean_io, join_worker, spawn_worker, v4,
    wait_for_listener,
};
use super::profile_contract::{
    PROFILE_TCP_LATENCY_SAMPLE_CAP, PROFILE_TCP_STREAM_BATCH, ProfileArgs, ProfileOutcome,
    ProfileScenario, ReadyFile, Topology,
};
use super::profile_output::{
    ProfileTcpWorkerResult, ensure_profile_workers_running, wait_for_profile_phase,
};
use super::proxy_config::{ferrum_client_config, ferrum_server_config};
use super::throughput::{
    load_stream, load_tcp_request_response, load_tcp_stream, percentile_99, rate_per_second,
};
use super::{PAYLOAD_BYTES, STREAMS};

pub(super) fn run_profile_tcp(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let tcp_workers = arguments
        .scenario
        .tcp_workers()
        .expect("TCP scenario has workers");
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-tcp-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let (target_listener, target, server_slot, proxy_slot) = (|| {
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
        let server = PortReservation::new()?;
        let proxy = PortReservation::new()?;
        Ok::<_, String>((target_listener, target, server, proxy))
    })()?;
    let mut target_listener = Some(target_listener);
    let mut server_reservation = Some(server_slot);
    let mut proxy_reservation = Some(proxy_slot);
    let server = server_reservation
        .as_ref()
        .expect("server reservation")
        .address;
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let client_config = directory
        .as_ref()
        .expect("profile config owner")
        .path()
        .join("client.toml");
    let server_config = directory
        .as_ref()
        .expect("profile config owner")
        .path()
        .join("server.toml");
    let mut target_worker = None;
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let mut server_process = None;
    let mut client_process = None;
    let mut workers = Vec::with_capacity(tcp_workers);
    let mut errors = Vec::new();
    let mut ready = None;
    let mut started = false;
    let execution = (|| -> Result<(), String> {
        fs::write(&client_config, ferrum_client_config(proxy, server, None)).map_err(clean_io)?;
        fs::write(&server_config, ferrum_server_config(server, None)).map_err(clean_io)?;
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        let server_binary = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
        target_worker = Some(TargetWorker::echo(
            target_listener.take().expect("target listener"),
            tcp_workers,
        )?);
        server_reservation
            .take()
            .expect("server reservation")
            .release();
        server_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile workload server",
            &server_binary,
            &server_config,
        )?);
        wait_for_listener(server_process.as_mut().expect("server process"), server)?;
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile workload client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), proxy)?;
        for _ in 0..tcp_workers {
            let worker_gate = Arc::clone(&gate);
            let worker_stop = Arc::clone(&stop);
            let failure_gate = Arc::clone(&gate);
            let failure_stop = Arc::clone(&stop);
            let scenario = arguments.scenario;
            workers.push(spawn_worker(move || {
                let result = match scenario {
                    ProfileScenario::TcpBulk => {
                        load_stream(proxy, target, worker_gate, worker_stop, warmup, active)
                            .map(ProfileTcpWorkerResult::Bytes)
                    }
                    ProfileScenario::TcpStream64k => {
                        load_tcp_stream(proxy, target, worker_gate, worker_stop, warmup, active)
                            .map(ProfileTcpWorkerResult::Bytes)
                    }
                    ProfileScenario::TcpRequest1k
                    | ProfileScenario::TcpRequest4k
                    | ProfileScenario::TcpRequest16k => load_tcp_request_response(
                        proxy,
                        target,
                        scenario.tcp_request_bytes().expect("request scenario"),
                        worker_gate,
                        worker_stop,
                        warmup,
                        active,
                    )
                    .map(ProfileTcpWorkerResult::Latencies),
                    ProfileScenario::TcpScale10k => {
                        unreachable!("dedicated scale runner reached ordinary TCP worker")
                    }
                    ProfileScenario::UdpSmallHigh
                    | ProfileScenario::UdpMtu1200
                    | ProfileScenario::UdpPayload1472
                    | ProfileScenario::UdpPayload1500
                    | ProfileScenario::UdpPayload8192
                    | ProfileScenario::UdpMaxWire65507
                    | ProfileScenario::UdpDirectSmall128
                    | ProfileScenario::UdpDirectMax65497 => {
                        unreachable!("TCP runner received UDP scenario")
                    }
                };
                if result.is_err() {
                    failure_stop.store(true, Ordering::SeqCst);
                    failure_gate.cancel();
                }
                result
            })?);
        }
        let start = gate.start_when_ready(tcp_workers, Instant::now() + STARTUP_TIMEOUT)?;
        started = true;
        let warm_end = start + warmup;
        let active_end = warm_end + active;
        wait_for_profile_phase(
            client_process.as_mut().expect("client process"),
            server_process.as_mut().expect("server process"),
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(tcp_workers)?;
        client_process
            .as_mut()
            .expect("client process")
            .ensure_running()?;
        server_process
            .as_mut()
            .expect("server process")
            .ensure_running()?;
        ensure_profile_workers_running(&gate, &workers)?;
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            client_process.as_ref().expect("client process").id(),
            Some(server_process.as_ref().expect("server process").id()),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        wait_for_profile_phase(
            client_process.as_mut().expect("client process"),
            server_process.as_mut().expect("server process"),
            &gate,
            &workers,
            active_end,
            false,
        )
    })();
    let execution_succeeded = execution.is_ok();
    if let Err(error) = execution {
        errors.push(error);
    }
    if let Some(owner) = ready.take()
        && let Err(error) = owner.remove()
    {
        errors.push(format!("ready cleanup failed: {error}"));
    }
    stop.store(true, Ordering::SeqCst);
    gate.cancel();
    let mut bytes = 0_u64;
    let mut latencies = Vec::new();
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(ProfileTcpWorkerResult::Bytes(count)) => match bytes.checked_add(count) {
                Some(total) => bytes = total,
                None => errors.push("profile TCP byte count overflow".to_owned()),
            },
            Ok(ProfileTcpWorkerResult::Latencies(mut worker_latencies)) => {
                if latencies.len().saturating_add(worker_latencies.len())
                    > PROFILE_TCP_LATENCY_SAMPLE_CAP
                {
                    errors.push("profile TCP latency sample cap exceeded".to_owned());
                } else {
                    latencies.append(&mut worker_latencies);
                }
            }
            Err(error) => errors.push(error),
        }
    }
    if execution_succeeded && bytes == 0 && latencies.is_empty() {
        errors.push("profile TCP completed no validated transactions".to_owned());
    }
    if started {
        if let Some(worker) = target_worker.take()
            && let Err(error) = worker.finish()
        {
            errors.push(format!("target cleanup failed: {error}"));
        }
    } else {
        drop(target_worker.take());
    }
    for process in [&mut client_process, &mut server_process] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("process cleanup failed: {error}"));
        }
    }
    drop((client_process.take(), server_process.take()));
    drop((proxy_reservation.take(), server_reservation.take()));
    drop(target_listener.take());
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("config cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_rebind(proxy, "profile TCP client"),
        prove_tcp_rebind(server, "profile TCP server"),
        prove_tcp_rebind(target, "profile TCP target"),
    ] {
        if let Err(error) = result {
            errors.push(format!("rebind failed: {error}"));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    if arguments.scenario == ProfileScenario::TcpBulk {
        let transactions = bytes / PAYLOAD_BYTES as u64;
        return Ok(ProfileOutcome {
            summary: format!(
                "m17_profile_workload_completion status=PASS scenario=tcp-bulk \
                 transactions={transactions} bytes={bytes} workers={STREAMS} warmup_seconds={} \
                 active_seconds={} drain=PASS rebind=PASS",
                arguments.warmup_seconds, arguments.active_seconds,
            ),
            metric: "bytes_per_second",
            value: rate_per_second(bytes, active)?,
            checked_units: bytes,
            p99_nanoseconds: None,
            io_completions: transactions.saturating_mul(2),
            scale_json: None,
        });
    }
    if arguments.scenario == ProfileScenario::TcpStream64k {
        let batches = bytes / (PAYLOAD_BYTES * PROFILE_TCP_STREAM_BATCH) as u64;
        return Ok(ProfileOutcome {
            summary: format!(
                "m18_profile_workload_completion status=PASS scenario=tcp-stream-64k \
                 batches={batches} bytes={bytes} workers={STREAMS} warmup_seconds={} \
                 active_seconds={} drain=PASS rebind=PASS",
                arguments.warmup_seconds, arguments.active_seconds,
            ),
            metric: "bytes_per_second",
            value: rate_per_second(bytes, active)?,
            checked_units: bytes,
            p99_nanoseconds: None,
            io_completions: batches.saturating_mul((PROFILE_TCP_STREAM_BATCH + 1) as u64),
            scale_json: None,
        });
    }
    let transactions = u64::try_from(latencies.len())
        .map_err(|_| "profile TCP transaction count overflow".to_owned())?;
    let p99_nanoseconds = percentile_99(latencies)?;
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario={} transactions={transactions} \
             p99_nanoseconds={p99_nanoseconds} workers={tcp_workers} warmup_seconds={} \
             active_seconds={} drain=PASS rebind=PASS",
            arguments.scenario.label(),
            arguments.warmup_seconds,
            arguments.active_seconds,
        ),
        metric: "p99_nanoseconds",
        value: p99_nanoseconds,
        checked_units: transactions,
        p99_nanoseconds: Some(p99_nanoseconds),
        io_completions: transactions.saturating_mul(2),
        scale_json: None,
    })
}
