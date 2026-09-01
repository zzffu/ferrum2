use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::dns_resource::{prove_tcp_rebind, prove_tcp_udp_rebind, prove_udp_rebind};
use super::evidence_support::{PortReservation, TcpUdpReservation, profile_binary, spawn_proxy};
use super::process_support::{
    IO_TIMEOUT, ProcessGuard, STARTUP_TIMEOUT, StartGate, clean_io, join_worker, spawn_worker,
    wait_for_listener,
};
use super::profile_contract::{
    PROFILE_DNS_WORKERS, PROFILE_TCP_LATENCY_SAMPLE_CAP, PROFILE_UDP_MAX_BUFFERED_BYTES,
    ProfileArgs, ProfileOutcome, ProfileScenario, ReadyFile, Topology,
};
use super::profile_output::{
    ensure_profile_workers_running, wait_for_profile_phase_optional_server,
};
use super::proxy_config::{m14_udp_server_config, profile_dns_client_config};
use super::throughput::{percentile_99, rate_per_second, transfer_is_measured};

const PROFILE_DNS_NAME: &str = "profile.ferrum.test.";

pub(super) fn run_profile_dns(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let detoured = arguments.scenario == ProfileScenario::DnsDetoured;
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-dns-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut dns_reservation = Some(TcpUdpReservation::new()?);
    let mut server_reservation = detoured.then(TcpUdpReservation::new).transpose()?;
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let dns = dns_reservation.as_ref().expect("DNS reservation").address;
    let server = server_reservation
        .as_ref()
        .map(|reservation| reservation.address);
    let mut upstream = ProfileDnsResponder::start()?;
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
    let mut server_process = None;
    let mut client_process = None;
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let mut workers: Vec<JoinHandle<Result<DnsWorkerResult, String>>> =
        Vec::with_capacity(PROFILE_DNS_WORKERS);
    let mut errors = Vec::new();
    let mut ready = None;

    let execution = (|| -> Result<(), String> {
        fs::write(
            &client_config,
            profile_dns_client_config(proxy, dns, upstream.address, server),
        )
        .map_err(clean_io)?;
        if let Some(server) = server {
            fs::write(
                &server_config,
                m14_udp_server_config(server, PROFILE_UDP_MAX_BUFFERED_BYTES),
            )
            .map_err(clean_io)?;
            let server_binary = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
            server_reservation
                .take()
                .expect("server reservation")
                .release();
            server_process = Some(spawn_proxy(
                Topology::Ferrum,
                "profile DNS detour server",
                &server_binary,
                &server_config,
            )?);
            wait_for_listener(server_process.as_mut().expect("server process"), server)?;
        }
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        dns_reservation.take().expect("DNS reservation").release();
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile DNS client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), dns)?;

        for worker_index in 0..PROFILE_DNS_WORKERS {
            let worker_gate = Arc::clone(&gate);
            let worker_stop = Arc::clone(&stop);
            let failure_gate = Arc::clone(&gate);
            let failure_stop = Arc::clone(&stop);
            workers.push(spawn_worker(move || {
                let result =
                    profile_dns_load(worker_index, dns, worker_gate, worker_stop, warmup, active);
                if result.is_err() {
                    failure_stop.store(true, Ordering::SeqCst);
                    failure_gate.cancel();
                }
                result
            })?);
        }
        let start = gate.start_when_ready(PROFILE_DNS_WORKERS, Instant::now() + STARTUP_TIMEOUT)?;
        let warm_end = start + warmup;
        let active_end = warm_end + active;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(PROFILE_DNS_WORKERS)?;
        ensure_profile_workers_running(&gate, &workers)?;
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            client_process.as_ref().expect("client process").id(),
            server_process.as_ref().map(ProcessGuard::id),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
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
    let mut queries = 0_usize;
    let mut latencies = Vec::new();
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(result) => {
                queries = queries
                    .checked_add(result.queries)
                    .ok_or_else(|| "profile DNS query count overflow".to_owned())?;
                latencies.extend(result.latencies);
            }
            Err(error) => errors.push(error),
        }
    }
    if execution_succeeded && queries == 0 {
        errors.push("profile DNS completed no validated queries".to_owned());
    }
    for process in [&mut client_process, &mut server_process] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("process cleanup failed: {error}"));
        }
    }
    drop((client_process.take(), server_process.take()));
    drop((
        proxy_reservation.take(),
        dns_reservation.take(),
        server_reservation.take(),
    ));
    let upstream_address = upstream.address;
    if let Err(error) = upstream.finish() {
        errors.push(format!("DNS responder cleanup failed: {error}"));
    }
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("config cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_rebind(proxy, "profile DNS client"),
        prove_tcp_udp_rebind(dns, "profile DNS listener"),
        prove_udp_rebind(upstream_address, "profile DNS upstream"),
    ] {
        if let Err(error) = result {
            errors.push(format!("rebind failed: {error}"));
        }
    }
    if let Some(server) = server
        && let Err(error) = prove_tcp_udp_rebind(server, "profile DNS detour server")
    {
        errors.push(format!("rebind failed: {error}"));
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let checked_units =
        u64::try_from(queries).map_err(|_| "profile DNS query count overflow".to_owned())?;
    let p99_nanoseconds = percentile_99(latencies)?;
    let summary = format!(
        "m18_profile_workload_completion status=PASS scenario={} topology={} \
         queries={queries} p99_nanoseconds={p99_nanoseconds} workers={PROFILE_DNS_WORKERS} \
         warmup_seconds={} active_seconds={} drain=PASS rebind=PASS",
        arguments.scenario.label(),
        arguments.scenario.topology_label(),
        arguments.warmup_seconds,
        arguments.active_seconds,
    );
    Ok(ProfileOutcome {
        summary,
        metric: "queries_per_second",
        value: rate_per_second(checked_units, active)?,
        checked_units,
        p99_nanoseconds: Some(p99_nanoseconds),
        io_completions: checked_units.saturating_mul(if detoured { 6 } else { 4 }),
        scale_json: None,
    })
}

struct DnsWorkerResult {
    queries: usize,
    latencies: Vec<u64>,
}

fn profile_dns_load(
    worker_index: usize,
    dns: SocketAddrV4,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
) -> Result<DnsWorkerResult, String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    socket.connect(dns).map_err(clean_io)?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    let (mut request, expected_response) = dns_wire_templates()?;
    let mut response = [0_u8; 512];
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let active_end = warm_end + active;
    let sample_capacity = PROFILE_TCP_LATENCY_SAMPLE_CAP.div_ceil(PROFILE_DNS_WORKERS);
    let mut latencies = Vec::with_capacity(sample_capacity);
    let mut sequence = 0_u64;
    let mut queries = 0_usize;
    let mut reported_valid = false;
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        let id = (u16::try_from(worker_index).expect("DNS worker index") << 11)
            ^ u16::try_from(sequence & 0x07ff).expect("bounded DNS sequence")
            ^ 1;
        request[..2].copy_from_slice(&id.to_be_bytes());
        let transfer_start = Instant::now();
        socket.send(&request).map_err(clean_io)?;
        let length = socket.recv(&mut response).map_err(clean_io)?;
        let completion = Instant::now();
        if length != expected_response.len()
            || response[..2] != id.to_be_bytes()
            || response[2..length] != expected_response[2..]
        {
            return Err("profile DNS received an invalid response".to_owned());
        }
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, active_end) {
            queries = queries
                .checked_add(1)
                .ok_or_else(|| "profile DNS query count overflow".to_owned())?;
            if latencies.len() == sample_capacity {
                return Err("profile DNS latency sample cap exceeded".to_owned());
            }
            latencies.push(
                u64::try_from(completion.duration_since(transfer_start).as_nanos())
                    .map_err(|_| "profile DNS latency overflow".to_owned())?,
            );
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "profile DNS sequence overflow".to_owned())?;
    }
    Ok(DnsWorkerResult { queries, latencies })
}

struct ProfileDnsResponder {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl ProfileDnsResponder {
    fn start() -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = socket
            .local_addr()
            .map_err(clean_io)?
            .to_string()
            .parse::<SocketAddrV4>()
            .map_err(|_| "profile DNS upstream is not IPv4".to_owned())?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(clean_io)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = spawn_worker(move || {
            let (expected_request, mut response) = dns_wire_templates()?;
            let mut request = [0_u8; 512];
            while !worker_stop.load(Ordering::SeqCst) {
                let (length, peer) = match socket.recv_from(&mut request) {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(clean_io(error)),
                };
                if length != expected_request.len() || request[2..length] != expected_request[2..] {
                    return Err("profile DNS upstream received an invalid query".to_owned());
                }
                response[..2].copy_from_slice(&request[..2]);
                let sent = socket.send_to(&response, peer).map_err(clean_io)?;
                if sent != response.len() {
                    return Err("profile DNS upstream sent a short response".to_owned());
                }
            }
            Ok(())
        })?;
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        join_worker(
            self.worker
                .take()
                .ok_or_else(|| "profile DNS responder was already joined".to_owned())?,
        )?
    }
}

impl Drop for ProfileDnsResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn dns_wire_templates() -> Result<(Vec<u8>, Vec<u8>), String> {
    let name =
        Name::from_ascii(PROFILE_DNS_NAME).map_err(|_| "profile DNS name is invalid".to_owned())?;
    let query = Query::query(name.clone(), RecordType::A);
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    request.add_query(query.clone());
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(query);
    response.add_answer(Record::from_rdata(
        name,
        30,
        RData::A(A(Ipv4Addr::LOCALHOST)),
    ));
    Ok((
        request
            .to_vec()
            .map_err(|_| "profile DNS could not encode a query".to_owned())?,
        response
            .to_vec()
            .map_err(|_| "profile DNS could not encode a response".to_owned())?,
    ))
}
