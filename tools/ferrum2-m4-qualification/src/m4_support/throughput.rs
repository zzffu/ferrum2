use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::evidence_support::{
    Evidence, PortReservation, ferrum_binary, ferrum_client_config, ferrum_server_config,
    reference_client_config, reference_server_config, spawn_proxy,
};
use super::host_identity::HostedIdentity;
use super::process_support::{
    IO_TIMEOUT, PROBE_TIMEOUT, STARTUP_TIMEOUT, StartGate, TargetWorker, clean_io, join_worker,
    json, probe_text, sha256, socks_connect, spawn_worker, v4, wait_for_listener,
};
use super::profile_contract::{
    HostedArgs, PROFILE_TCP_LATENCY_SAMPLE_CAP, PROFILE_TCP_STREAM_BATCH, Topology,
};
use super::self_check::{assert_no_owners, validate_reference_identity};
use super::{MEASURE, PAYLOAD_BYTES, REFERENCE_SHA256, STREAMS, TRIALS, WARMUP};

pub(super) fn run_throughput(arguments: HostedArgs) -> Result<String, String> {
    let identity = HostedIdentity::load(&arguments.sha, &arguments.output)?;
    let sslocal = arguments.sslocal.expect("parsed reference client");
    let ssserver = arguments.ssserver.expect("parsed reference server");
    verify_reference(&sslocal, &ssserver, &arguments.output)?;
    let mut output = Evidence::create(&arguments.output)?;
    output.line(format!(
        "{{\"kind\":\"identity\",{}}}",
        identity.json_fields()
    ))?;
    let mut trials = Vec::with_capacity(TRIALS.len());
    for (index, topology) in TRIALS.into_iter().enumerate() {
        let trial = throughput_trial(index + 1, topology, &sslocal, &ssserver, output.parent())?;
        output.line(format!(
            "{{\"kind\":\"throughput_trial\",\"trial\":{},\"topology\":{},\
             \"streams\":{},\"payload_bytes\":{},\"warmup_seconds\":10,\
             \"measure_seconds\":30,\"bytes\":{},\"elapsed_ns\":{},\
             \"bytes_per_second\":{},\"client_config_sha256\":{},\
             \"server_config_sha256\":{}}}",
            trial.index,
            json(trial.topology.label()),
            STREAMS,
            PAYLOAD_BYTES,
            trial.bytes,
            trial.elapsed.as_nanos(),
            trial.bytes_per_second,
            json(&trial.client_config_hash),
            json(&trial.server_config_hash),
        ))?;
        trials.push(trial);
    }
    let ferrum = median(
        trials
            .iter()
            .filter(|trial| trial.topology == Topology::Ferrum)
            .map(|trial| trial.bytes_per_second),
    )?;
    let reference = median(
        trials
            .iter()
            .filter(|trial| trial.topology == Topology::Reference)
            .map(|trial| trial.bytes_per_second),
    )?;
    if ferrum == 0 || reference == 0 {
        return Err("throughput medians must be positive".to_owned());
    }
    let ratio = ferrum as f64 / reference as f64;
    let difference = (ferrum as f64 - reference as f64) * 100.0 / reference as f64;
    if !ratio.is_finite() || ratio.is_sign_negative() || !difference.is_finite() {
        return Err("throughput summary is not finite".to_owned());
    }
    output.line(format!(
        "{{\"kind\":\"throughput_summary\",\"ferrum_median_bytes_per_second\":{ferrum},\
         \"reference_median_bytes_per_second\":{reference},\"ratio\":{ratio:.9},\
         \"signed_difference_percent\":{difference:.9},\"trials\":10}}"
    ))?;
    output.finish()?;
    assert_no_owners()?;
    Ok(format!(
        "m4_throughput_completion status=PASS ferrum_median={ferrum} reference_median={reference} \
         ratio={ratio:.9} trials=10 sha={} run_id={} run_attempt={}",
        identity.sha, identity.run_id, identity.run_attempt
    ))
}

pub(super) struct TrialResult {
    pub(super) index: usize,
    pub(super) topology: Topology,
    pub(super) bytes: u64,
    pub(super) elapsed: Duration,
    pub(super) bytes_per_second: u64,
    pub(super) client_config_hash: String,
    pub(super) server_config_hash: String,
}

pub(super) fn throughput_trial(
    index: usize,
    topology: Topology,
    sslocal: &Path,
    ssserver: &Path,
    work: &Path,
) -> Result<TrialResult, String> {
    let directory = tempfile::Builder::new()
        .prefix("throughput-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let server_reservation = PortReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let client_config = directory.path().join("client.json");
    let server_config = directory.path().join("server.json");
    let (client_binary, server_binary, client_text, server_text) = match topology {
        Topology::Ferrum => (
            ferrum_binary("ferrum2-client")?,
            ferrum_binary("ferrum2-server")?,
            ferrum_client_config(proxy, server, None),
            ferrum_server_config(server, None),
        ),
        Topology::Reference => (
            sslocal.to_path_buf(),
            ssserver.to_path_buf(),
            reference_client_config(proxy, server),
            reference_server_config(server),
        ),
    };
    fs::write(&client_config, client_text).map_err(clean_io)?;
    fs::write(&server_config, server_text).map_err(clean_io)?;
    let client_hash = sha256("throughput client config SHA-256 probe", &client_config)?;
    let server_hash = sha256("throughput server config SHA-256 probe", &server_config)?;
    let target_worker = TargetWorker::echo(target_listener, STREAMS)?;
    server_reservation.release();
    let mut server_process = spawn_proxy(topology, "server", &server_binary, &server_config)?;
    wait_for_listener(&mut server_process, server)?;
    proxy_reservation.release();
    let mut client_process = spawn_proxy(topology, "client", &client_binary, &client_config)?;
    wait_for_listener(&mut client_process, proxy)?;
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let worker_gate = Arc::clone(&gate);
        let worker_stop = Arc::clone(&stop);
        match spawn_worker(move || {
            load_stream(proxy, target, worker_gate, worker_stop, WARMUP, MEASURE)
        }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                gate.cancel();
                for worker in workers {
                    let _ = join_worker(worker);
                }
                return Err(error);
            }
        }
    }
    if let Err(error) = gate.start_when_ready(STREAMS, Instant::now() + STARTUP_TIMEOUT) {
        stop.store(true, Ordering::SeqCst);
        gate.cancel();
        for worker in workers {
            let _ = join_worker(worker);
        }
        return Err(error);
    }
    let mut bytes = 0_u64;
    let mut worker_error = None;
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(worker_bytes) => {
                bytes = bytes
                    .checked_add(worker_bytes)
                    .ok_or_else(|| "throughput byte count overflow".to_owned())?;
            }
            Err(error) => {
                worker_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = worker_error {
        return Err(error);
    }
    let elapsed = MEASURE;
    target_worker.finish()?;
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    let bytes_per_second = u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos())
        .map_err(|_| "throughput value overflow".to_owned())?;
    Ok(TrialResult {
        index,
        topology,
        bytes,
        elapsed,
        bytes_per_second,
        client_config_hash: client_hash,
        server_config_hash: server_hash,
    })
}

pub(super) fn load_stream(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
) -> Result<u64, String> {
    let mut stream = match open_profile_stream(proxy, target) {
        Ok(stream) => stream,
        Err(error) => {
            gate.cancel();
            return Err(error);
        }
    };
    let started = gate.ready_and_wait()?;
    let payload = [0x5a; PAYLOAD_BYTES];
    let mut echoed = [0_u8; PAYLOAD_BYTES];
    let warm_end = started + warmup;
    let measure_end = warm_end + active;
    let mut measured = 0_u64;
    let mut reported_valid = false;
    while Instant::now() < measure_end && !stop.load(Ordering::SeqCst) {
        let transfer_start = Instant::now();
        stream.write_all(&payload).map_err(clean_io)?;
        stream.read_exact(&mut echoed).map_err(clean_io)?;
        if echoed != payload {
            return Err("echo payload mismatch".to_owned());
        }
        let completion = Instant::now();
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, measure_end) {
            measured = measured
                .checked_add(PAYLOAD_BYTES as u64)
                .ok_or_else(|| "throughput byte count overflow".to_owned())?;
        }
    }
    stream.shutdown(Shutdown::Both).map_err(clean_io)?;
    Ok(measured)
}

pub(super) fn open_profile_stream(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
) -> Result<TcpStream, String> {
    let stream = socks_connect(proxy, target, Instant::now() + STARTUP_TIMEOUT)?;
    stream.set_nodelay(true).map_err(clean_io)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    Ok(stream)
}

pub(super) fn load_tcp_stream(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
) -> Result<u64, String> {
    let mut stream = match open_profile_stream(proxy, target) {
        Ok(stream) => stream,
        Err(error) => {
            gate.cancel();
            return Err(error);
        }
    };
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let active_end = warm_end + active;
    let mut payload = [0x5a; PAYLOAD_BYTES];
    let mut expected = vec![0_u8; PAYLOAD_BYTES * PROFILE_TCP_STREAM_BATCH];
    let mut echoed = vec![0_u8; PAYLOAD_BYTES * PROFILE_TCP_STREAM_BATCH];
    let mut sequence = 0_u64;
    let mut measured = 0_u64;
    let mut reported_valid = false;
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        let transfer_start = Instant::now();
        for slot in expected.chunks_exact_mut(PAYLOAD_BYTES) {
            payload[..8].copy_from_slice(&sequence.to_be_bytes());
            slot.copy_from_slice(&payload);
            stream.write_all(&payload).map_err(clean_io)?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| "profile TCP stream sequence overflow".to_owned())?;
        }
        stream.read_exact(&mut echoed).map_err(clean_io)?;
        if echoed != expected {
            return Err("streaming echo payload mismatch".to_owned());
        }
        let completion = Instant::now();
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, active_end) {
            measured = measured
                .checked_add(expected.len() as u64)
                .ok_or_else(|| "profile TCP stream byte count overflow".to_owned())?;
        }
    }
    stream.shutdown(Shutdown::Both).map_err(clean_io)?;
    Ok(measured)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn load_tcp_request_response(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    payload_bytes: usize,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
) -> Result<Vec<u64>, String> {
    let mut stream = match open_profile_stream(proxy, target) {
        Ok(stream) => stream,
        Err(error) => {
            gate.cancel();
            return Err(error);
        }
    };
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let active_end = warm_end + active;
    let mut payload = vec![0x5a; payload_bytes];
    let mut echoed = vec![0_u8; payload_bytes];
    let mut sequence = 0_u64;
    let mut latencies = Vec::new();
    let mut reported_valid = false;
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let transfer_start = Instant::now();
        stream.write_all(&payload).map_err(clean_io)?;
        stream.read_exact(&mut echoed).map_err(clean_io)?;
        if echoed != payload {
            return Err("request-response echo payload mismatch".to_owned());
        }
        let completion = Instant::now();
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, active_end) {
            if latencies.len() == PROFILE_TCP_LATENCY_SAMPLE_CAP {
                return Err("profile TCP latency sample cap exceeded".to_owned());
            }
            latencies.push(
                u64::try_from(completion.duration_since(transfer_start).as_nanos())
                    .map_err(|_| "profile TCP latency overflow".to_owned())?,
            );
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "profile TCP request sequence overflow".to_owned())?;
    }
    stream.shutdown(Shutdown::Both).map_err(clean_io)?;
    Ok(latencies)
}

pub(super) fn rate_per_second(units: u64, active: Duration) -> Result<u64, String> {
    u64::try_from(u128::from(units) * 1_000_000_000 / active.as_nanos())
        .map_err(|_| "profile rate overflow".to_owned())
}

pub(super) fn percentile_99(mut values: Vec<u64>) -> Result<u64, String> {
    if values.is_empty() {
        return Err("profile p99 sample set is empty".to_owned());
    }
    values.sort_unstable();
    let rank = values
        .len()
        .checked_mul(99)
        .and_then(|value| value.checked_add(99))
        .ok_or_else(|| "profile p99 rank overflow".to_owned())?
        / 100;
    Ok(values[rank - 1])
}

pub(super) fn transfer_is_measured(
    transfer_start: Instant,
    completion: Instant,
    warm_end: Instant,
    measure_end: Instant,
) -> bool {
    transfer_start >= warm_end && completion <= measure_end
}

pub(super) fn median(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.len() != 5 {
        return Err("throughput topology must have five trials".to_owned());
    }
    values.sort_unstable();
    Ok(values[2])
}

pub(super) fn verify_reference(
    sslocal: &Path,
    ssserver: &Path,
    output: &Path,
) -> Result<(), String> {
    let local = sslocal
        .canonicalize()
        .map_err(|_| "sslocal is unavailable".to_owned())?;
    let server = ssserver
        .canonicalize()
        .map_err(|_| "ssserver is unavailable".to_owned())?;
    if local.parent() != server.parent() {
        return Err("reference binaries do not share one verified extraction root".to_owned());
    }
    let work = output
        .parent()
        .expect("validated output parent")
        .canonicalize()
        .map_err(clean_io)?;
    if !local.starts_with(&work) || !server.starts_with(&work) {
        return Err("reference binaries escaped RUNNER_TEMP/m4".to_owned());
    }
    let archive = work.join("shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz");
    if fs::metadata(&archive).map_err(clean_io)?.len() != 11_635_096
        || sha256("reference archive SHA-256 probe", &archive)? != REFERENCE_SHA256
    {
        return Err("reference archive identity mismatch".to_owned());
    }
    for (identity, binary) in [
        ("reference sslocal version probe", &local),
        ("reference ssserver version probe", &server),
    ] {
        let version = probe_text(identity, binary, ["--version"], PROBE_TIMEOUT)?;
        validate_reference_identity(&version, REFERENCE_SHA256)?;
    }
    Ok(())
}
