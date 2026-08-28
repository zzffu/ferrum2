use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::dns_resource::{DNS_LOAD_WORKERS, DNS_MAX_INFLIGHT, DNS_UPSTREAM_DELAY};
use super::process_support::{ProcessGuard, clean_io, join_worker, remaining, spawn_worker, v4};
use super::profile_contract::{EVIDENCE_LINE_MAX_BYTES, Topology};
use super::self_check::ensure_redacted;

pub(super) struct Evidence {
    pub(super) writer: BufWriter<File>,
    pub(super) parent: PathBuf,
    pub(super) finished: bool,
}

impl Evidence {
    pub(super) fn create(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(clean_io)?;
        Ok(Self {
            writer: BufWriter::new(file),
            parent: path
                .parent()
                .expect("validated output parent")
                .to_path_buf(),
            finished: false,
        })
    }

    pub(super) fn parent(&self) -> &Path {
        &self.parent
    }

    pub(super) fn line(&mut self, line: String) -> Result<(), String> {
        self.line_with_limit(line, EVIDENCE_LINE_MAX_BYTES)
    }

    pub(super) fn line_with_limit(&mut self, line: String, maximum: usize) -> Result<(), String> {
        validate_evidence_line(&line, maximum)?;
        self.writer.write_all(line.as_bytes()).map_err(clean_io)?;
        self.writer.write_all(b"\n").map_err(clean_io)
    }

    pub(super) fn finish(mut self) -> Result<(), String> {
        self.writer.flush().map_err(clean_io)?;
        self.finished = true;
        Ok(())
    }
}

pub(super) fn validate_evidence_line(line: &str, maximum: usize) -> Result<(), String> {
    if line.len() > maximum {
        return Err("evidence line exceeds bound".to_owned());
    }
    ensure_redacted(line)
}

impl Drop for Evidence {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.writer.flush();
        }
    }
}

pub(super) fn spawn_proxy(
    topology: Topology,
    role: &str,
    binary: &Path,
    config: &Path,
) -> Result<ProcessGuard, String> {
    let mut command = Command::new(binary);
    match topology {
        Topology::Ferrum => {
            command.args([OsStr::new("--config"), config.as_os_str()]);
        }
        Topology::Reference => {
            command.args([OsStr::new("-c"), config.as_os_str()]);
        }
    }
    ProcessGuard::spawn(&format!("{} {role}", topology.label()), &mut command)
}

pub(super) fn ferrum_binary(name: &str) -> Result<PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(clean_io)?
        .parent()
        .expect("qualification profile directory")
        .join(name);
    if !path.is_file() {
        return Err(format!("required release binary is missing: {name}"));
    }
    Ok(path)
}

pub(super) fn profile_binary(directory: &Path, name: &str) -> Result<PathBuf, String> {
    let path = directory.join(name);
    if !path.is_file() {
        return Err(format!("required profile binary is missing: {name}"));
    }
    Ok(path)
}

pub(super) struct PortReservation {
    pub(super) listener: TcpListener,
    pub(super) address: SocketAddrV4,
}

impl PortReservation {
    pub(super) fn new() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = v4(listener.local_addr().map_err(clean_io)?)?;
        Ok(Self { listener, address })
    }

    pub(super) fn release(self) {
        drop(self.listener);
    }
}

pub(super) struct TcpUdpReservation {
    pub(super) tcp: TcpListener,
    pub(super) udp: UdpSocket,
    pub(super) address: SocketAddrV4,
}

impl TcpUdpReservation {
    pub(super) fn new() -> Result<Self, String> {
        loop {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
            let address = v4(tcp.local_addr().map_err(clean_io)?)?;
            match UdpSocket::bind(address) {
                Ok(udp) => return Ok(Self { tcp, udp, address }),
                Err(_) => drop(tcp),
            }
        }
    }

    pub(super) fn release(self) {
        drop((self.tcp, self.udp));
    }
}

pub(super) struct DnsResponder {
    pub(super) address: SocketAddrV4,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) observed: Arc<AtomicUsize>,
    pub(super) worker: Option<JoinHandle<Result<usize, String>>>,
}

impl DnsResponder {
    pub(super) fn start(expected_name: &'static str) -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = v4(socket.local_addr().map_err(clean_io)?)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(clean_io)?;
        let expected = Name::from_ascii(expected_name)
            .map_err(|_| "DNS responder name is invalid".to_owned())?;
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_observed = Arc::clone(&observed);
        let worker = spawn_worker(move || {
            let mut buffer = [0_u8; 4096];
            let mut count = 0;
            while !worker_stop.load(Ordering::SeqCst) {
                let (length, peer) = match socket.recv_from(&mut buffer) {
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
                let request = Message::from_vec(&buffer[..length])
                    .map_err(|_| "DNS responder received malformed wire".to_owned())?;
                if request.metadata.message_type != MessageType::Query
                    || request.metadata.op_code != OpCode::Query
                    || request.queries.len() != 1
                {
                    return Err("DNS responder received an invalid query shape".to_owned());
                }
                let query = request.queries[0].clone();
                if query.name() != &expected || query.query_type() != RecordType::A {
                    return Err("DNS responder received the wrong query".to_owned());
                }
                let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
                thread::sleep(DNS_UPSTREAM_DELAY);
                socket
                    .send_to(
                        &response
                            .to_vec()
                            .map_err(|_| "DNS responder could not encode a response".to_owned())?,
                        peer,
                    )
                    .map_err(clean_io)?;
                count += 1;
                worker_observed.fetch_add(1, Ordering::SeqCst);
            }
            Ok(count)
        })?;
        Ok(Self {
            address,
            stop,
            observed,
            worker: Some(worker),
        })
    }

    pub(super) fn observed(&self) -> usize {
        self.observed.load(Ordering::SeqCst)
    }

    pub(super) fn finish(&mut self) -> Result<usize, String> {
        self.stop.store(true, Ordering::SeqCst);
        join_worker(
            self.worker
                .take()
                .ok_or_else(|| "DNS responder was already joined".to_owned())?,
        )?
    }
}

impl Drop for DnsResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) struct DnsLoad {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) completed: Arc<AtomicUsize>,
    pub(super) active: Arc<AtomicUsize>,
    pub(super) peak: Arc<AtomicUsize>,
    pub(super) expected_workers: usize,
    pub(super) workers: Vec<JoinHandle<Result<usize, String>>>,
}

struct DnsInflight<'a> {
    active: &'a AtomicUsize,
}

impl<'a> DnsInflight<'a> {
    fn start(active: &'a AtomicUsize, peak: &AtomicUsize) -> Self {
        let current = active
            .fetch_add(1, Ordering::SeqCst)
            .checked_add(1)
            .expect("bounded DNS inflight count");
        peak.fetch_max(current, Ordering::SeqCst);
        Self { active }
    }
}

impl Drop for DnsInflight<'_> {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "DNS inflight accounting underflowed");
    }
}

impl DnsLoad {
    pub(super) fn start(address: SocketAddrV4, name: &'static str) -> Result<Self, String> {
        Self::start_with_workers(address, name, DNS_LOAD_WORKERS, None)
    }

    pub(super) fn start_with_workers(
        address: SocketAddrV4,
        name: &'static str,
        worker_count: usize,
        expected_wire_bytes: Option<usize>,
    ) -> Result<Self, String> {
        if !(1..=usize::from(DNS_MAX_INFLIGHT)).contains(&worker_count) {
            return Err("DNS load worker count exceeds the bounded inflight limit".to_owned());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let typed_name =
            Name::from_ascii(name).map_err(|_| "DNS load name is invalid".to_owned())?;
        let mut workers = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let worker_stop = Arc::clone(&stop);
            let worker_completed = Arc::clone(&completed);
            let worker_active = Arc::clone(&active);
            let worker_peak = Arc::clone(&peak);
            let worker_name = typed_name.clone();
            let worker = spawn_worker(move || {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
                socket.connect(address).map_err(clean_io)?;
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(clean_io)?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .map_err(clean_io)?;
                let mut response_wire = [0_u8; 4096];
                let mut count = 0_usize;
                while !worker_stop.load(Ordering::SeqCst) {
                    let id = (u16::try_from(worker_index).expect("DNS worker index") << 11)
                        ^ u16::try_from(count & 0x07ff).expect("bounded DNS sequence")
                        ^ 1;
                    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
                    request.add_query(Query::query(worker_name.clone(), RecordType::A));
                    let request_wire = request
                        .to_vec()
                        .map_err(|_| "DNS load could not encode a query".to_owned())?;
                    if expected_wire_bytes.is_some_and(|expected| request_wire.len() != expected) {
                        return Err("DNS load query wire length changed".to_owned());
                    }
                    socket.send(&request_wire).map_err(clean_io)?;
                    let inflight = DnsInflight::start(&worker_active, &worker_peak);
                    let received = socket.recv(&mut response_wire);
                    drop(inflight);
                    let length = match received {
                        Ok(length) => length,
                        Err(error) => return Err(clean_io(error)),
                    };
                    let response = Message::from_vec(&response_wire[..length])
                        .map_err(|_| "DNS load received malformed wire".to_owned())?;
                    if response.metadata.id != id
                        || response.metadata.message_type != MessageType::Response
                        || response.answers.first().map(|record| &record.data)
                            != Some(&RData::A(A(Ipv4Addr::LOCALHOST)))
                    {
                        return Err("DNS load received the wrong response".to_owned());
                    }
                    count += 1;
                    worker_completed.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(count)
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
            stop,
            completed,
            active,
            peak,
            expected_workers: worker_count,
            workers,
        })
    }

    pub(super) fn wait_started(&self, deadline: Instant) -> Result<(), String> {
        while self.completed.load(Ordering::SeqCst) < self.expected_workers {
            if self.workers.iter().any(JoinHandle::is_finished) {
                return Err("DNS load worker ended before startup completed".to_owned());
            }
            thread::sleep(remaining(deadline)?.min(Duration::from_millis(20)));
        }
        Ok(())
    }

    pub(super) fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    pub(super) fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    pub(super) fn ensure_running(&self) -> Result<(), String> {
        if self.workers.iter().any(JoinHandle::is_finished) {
            return Err("DNS load worker ended early".to_owned());
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<usize, String> {
        self.stop.store(true, Ordering::SeqCst);
        let mut total = 0_usize;
        let mut first_error = None;
        for worker in std::mem::take(&mut self.workers) {
            match join_worker(worker).and_then(|result| result) {
                Ok(count) => total = total.saturating_add(count),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if self.active() != 0 {
            first_error
                .get_or_insert_with(|| "DNS load inflight accounting did not drain".to_owned());
        }
        if total != self.completed.load(Ordering::SeqCst) {
            first_error.get_or_insert_with(|| "DNS load completion accounting mismatch".to_owned());
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(total)
    }
}

impl Drop for DnsLoad {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in std::mem::take(&mut self.workers) {
            let _ = worker.join();
        }
    }
}
