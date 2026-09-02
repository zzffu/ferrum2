use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::dns_resource::{
    DNS_LOAD_WORKERS, DNS_UPSTREAM_DELAY, prove_tcp_rebind, prove_tcp_udp_rebind, prove_udp_rebind,
};
use super::evidence_support::{PortReservation, TcpUdpReservation, profile_binary, spawn_proxy};
use super::process_support::{
    IO_TIMEOUT, STARTUP_TIMEOUT, StartGate, clean_io, join_worker, spawn_worker, v4,
    wait_for_listener,
};
use super::profile_contract::{
    PROFILE_DNS_QUERY_WIRE_BYTES, ProfileArgs, ProfileOutcome, ReadyFile, Topology,
};
use super::profile_output::{
    ensure_profile_workers_running, wait_for_profile_phase_optional_server,
};
use super::proxy_config::profile_dns_client_config;
use super::throughput::{rate_per_second, transfer_is_measured};

const PROFILE_DNS_NAME: &str = "concurrency.performance.test.";

struct ProfileDnsResponder {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    observed: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<Result<usize, String>>>,
}

impl ProfileDnsResponder {
    fn start() -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = v4(socket.local_addr().map_err(clean_io)?)?;
        let expected = Name::from_ascii(PROFILE_DNS_NAME)
            .map_err(|_| "profile DNS responder name is invalid".to_owned())?;
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(DNS_LOAD_WORKERS);
        for _ in 0..DNS_LOAD_WORKERS {
            let socket = socket.try_clone().map_err(clean_io)?;
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .map_err(clean_io)?;
            let worker_stop = Arc::clone(&stop);
            let worker_observed = Arc::clone(&observed);
            let worker_expected = expected.clone();
            let worker = spawn_worker(move || {
                profile_dns_respond(socket, worker_expected, worker_stop, worker_observed)
            });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    stop.store(true, Ordering::SeqCst);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            address,
            stop,
            observed,
            workers,
        })
    }

    fn finish(&mut self) -> Result<usize, String> {
        self.stop.store(true, Ordering::SeqCst);
        let mut completed = 0_usize;
        for worker in std::mem::take(&mut self.workers) {
            let count = join_worker(worker)??;
            completed = completed
                .checked_add(count)
                .ok_or_else(|| "profile DNS response count overflow".to_owned())?;
        }
        if completed != self.observed.load(Ordering::SeqCst) {
            return Err("profile DNS observed count is inconsistent".to_owned());
        }
        Ok(completed)
    }
}

impl Drop for ProfileDnsResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in std::mem::take(&mut self.workers) {
            let _ = worker.join();
        }
    }
}

fn profile_dns_respond(
    socket: UdpSocket,
    expected: Name,
    stop: Arc<AtomicBool>,
    observed: Arc<AtomicUsize>,
) -> Result<usize, String> {
    let mut wire = [0_u8; 4096];
    let mut count = 0_usize;
    while !stop.load(Ordering::SeqCst) {
        let (length, peer) = match socket.recv_from(&mut wire) {
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
        let request = Message::from_vec(&wire[..length])
            .map_err(|_| "profile DNS responder received malformed wire".to_owned())?;
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
        {
            return Err("profile DNS responder received an invalid query shape".to_owned());
        }
        let query = request.queries[0].clone();
        if query.name() != &expected || query.query_type() != RecordType::A {
            return Err("profile DNS responder received the wrong query".to_owned());
        }
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            0,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        thread::sleep(DNS_UPSTREAM_DELAY);
        socket
            .send_to(
                &response
                    .to_vec()
                    .map_err(|_| "profile DNS responder could not encode a response".to_owned())?,
                peer,
            )
            .map_err(clean_io)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| "profile DNS response count overflow".to_owned())?;
        observed.fetch_add(1, Ordering::SeqCst);
    }
    Ok(count)
}

pub(super) fn run_profile_dns(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-dns-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut dns_reservation = Some(TcpUdpReservation::new()?);
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let dns = dns_reservation.as_ref().expect("DNS reservation").address;
    let mut upstream = Some(ProfileDnsResponder::start()?);
    let upstream_address = upstream.as_ref().expect("DNS upstream").address;
    let client_config = directory
        .as_ref()
        .expect("profile config owner")
        .path()
        .join("client.toml");
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let mut client_process = None;
    let mut workers = Vec::with_capacity(DNS_LOAD_WORKERS);
    let mut errors = Vec::new();
    let mut ready = None;
    let execution = (|| -> Result<(), String> {
        fs::write(
            &client_config,
            profile_dns_client_config(proxy, dns, upstream_address),
        )
        .map_err(clean_io)?;
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        dns_reservation.take().expect("DNS reservation").release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile DNS client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), dns)?;
        for worker_index in 0..DNS_LOAD_WORKERS {
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
        let start = gate.start_when_ready(DNS_LOAD_WORKERS, Instant::now() + STARTUP_TIMEOUT)?;
        let warm_end = start + warmup;
        let active_end = warm_end + active;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            None,
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(DNS_LOAD_WORKERS)?;
        client_process
            .as_mut()
            .expect("client process")
            .ensure_running()?;
        ensure_profile_workers_running(&gate, &workers)?;
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            client_process.as_ref().expect("client process").id(),
            None,
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            None,
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
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(count) => match queries.checked_add(count) {
                Some(total) => queries = total,
                None => errors.push("profile DNS query count overflow".to_owned()),
            },
            Err(error) => errors.push(error),
        }
    }
    if execution_succeeded && queries == 0 {
        errors.push("profile DNS completed no validated queries".to_owned());
    }
    if let Some(process) = client_process.as_mut()
        && let Err(error) = process.terminate()
    {
        errors.push(format!("process cleanup failed: {error}"));
    }
    drop(client_process.take());
    let upstream_queries = match upstream.as_mut() {
        Some(responder) => responder.finish(),
        None => unreachable!("profile DNS upstream owner"),
    };
    match upstream_queries {
        Ok(observed) if observed >= queries => {}
        Ok(_) => errors.push("profile DNS upstream observed fewer measured queries".to_owned()),
        Err(error) => errors.push(error),
    }
    drop(upstream.take());
    drop((proxy_reservation.take(), dns_reservation.take()));
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(error);
    }
    for result in [
        prove_tcp_rebind(proxy, "profile DNS proxy listener"),
        prove_tcp_udp_rebind(dns, "profile DNS listener"),
        prove_udp_rebind(upstream_address, "profile DNS upstream"),
    ] {
        if let Err(error) = result {
            errors.push(format!("rebind failed: {error}"));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let checked_units =
        u64::try_from(queries).map_err(|_| "profile DNS query count overflow".to_owned())?;
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario={} topology=dns-direct \
             queries={queries} workers={DNS_LOAD_WORKERS} \
             upstream_workers={DNS_LOAD_WORKERS} upstream_delay_ms={} \
             warmup_seconds={} active_seconds={} drain=PASS rebind=PASS",
            arguments.scenario.label(),
            DNS_UPSTREAM_DELAY.as_millis(),
            arguments.warmup_seconds,
            arguments.active_seconds,
        ),
        metric: "queries_per_second",
        value: rate_per_second(checked_units, active)?,
        checked_units,
        p99_nanoseconds: None,
        io_completions: checked_units.saturating_mul(2),
        scale_json: None,
    })
}

fn profile_dns_load(
    worker_index: usize,
    address: SocketAddrV4,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
) -> Result<usize, String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    socket.connect(address).map_err(clean_io)?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    let name = Name::from_ascii(PROFILE_DNS_NAME)
        .map_err(|_| "profile DNS load name is invalid".to_owned())?;
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(name, RecordType::A));
    let mut request_wire = request
        .to_vec()
        .map_err(|_| "profile DNS load could not encode a query".to_owned())?;
    if request_wire.len() != PROFILE_DNS_QUERY_WIRE_BYTES {
        return Err("profile DNS query wire length changed".to_owned());
    }
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let active_end = warm_end + active;
    let mut response_wire = [0_u8; 4096];
    let mut sequence = 0_u16;
    let mut counted = 0_usize;
    let mut reported_valid = false;
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        let id = (u16::try_from(worker_index).expect("profile DNS worker index") << 11)
            ^ (sequence & 0x07ff)
            ^ 1;
        request_wire[..2].copy_from_slice(&id.to_be_bytes());
        let transfer_start = Instant::now();
        socket.send(&request_wire).map_err(clean_io)?;
        let length = socket.recv(&mut response_wire).map_err(clean_io)?;
        let response = Message::from_vec(&response_wire[..length])
            .map_err(|_| "profile DNS load received malformed wire".to_owned())?;
        if response.metadata.id != id
            || response.metadata.message_type != MessageType::Response
            || response.answers.first().map(|record| &record.data)
                != Some(&RData::A(A(Ipv4Addr::LOCALHOST)))
        {
            return Err("profile DNS load received the wrong response".to_owned());
        }
        let completion = Instant::now();
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, active_end) {
            counted = counted
                .checked_add(1)
                .ok_or_else(|| "profile DNS query count overflow".to_owned())?;
        }
        sequence = sequence.wrapping_add(1);
    }
    Ok(counted)
}
