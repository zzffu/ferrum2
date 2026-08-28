use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{PAYLOAD_BYTES, PSK};

const PROCESS_OUTPUT_CAP: usize = 64 * 1024;
pub(super) const IO_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const REAP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) static ACTIVE_PROCESSES: AtomicUsize = AtomicUsize::new(0);
pub(super) static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn v4(address: SocketAddr) -> Result<SocketAddrV4, String> {
    match address {
        SocketAddr::V4(address) => Ok(address),
        SocketAddr::V6(_) => Err("IPv4 loopback returned IPv6".to_owned()),
    }
}

pub(super) fn wait_for_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        child.ensure_running()?;
        if TcpStream::connect_timeout(&SocketAddr::V4(address), Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("listener readiness timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn wait_for_metrics(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        child.ensure_running()?;
        if active_metric(address, deadline).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("metrics readiness timed out".to_owned());
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(20)));
    }
}

pub(super) fn active_metric(address: SocketAddrV4, deadline: Instant) -> Result<u64, String> {
    let response = fetch_metrics_response(address, deadline)?;
    parse_active_metric_response(&response)
}

fn fetch_metrics_response(address: SocketAddrV4, deadline: Instant) -> Result<Vec<u8>, String> {
    let timeout = remaining(deadline)?.min(IO_TIMEOUT);
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(address), timeout)
        .map_err(|_| "metrics connection failed".to_owned())?;
    stream
        .set_write_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
        .map_err(clean_io)?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(clean_io)?;
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if response.len() >= 256 * 1024 {
            return Err("metrics response exceeded bound".to_owned());
        }
        stream
            .set_read_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
            .map_err(clean_io)?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error) => return Err(clean_io(error)),
        }
    }
    remaining(deadline)?;
    Ok(response)
}

pub(super) fn parse_active_metric_response(response: &[u8]) -> Result<u64, String> {
    const ACTIVE: &str = "ferrum2_tcp_connections_active";
    const CLIENT_ACTIVE: &str =
        "ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"}";
    const SERVER_ACTIVE: &str =
        "ferrum2_tcp_connections_active{role=\"server\",inbound=\"shadowsocks\"}";
    const REPLAY: &str = "ferrum2_tcp_replay_entries";
    const REPLAY_TYPE: &str = "# TYPE ferrum2_tcp_replay_entries gauge";

    let body = metrics_body(response)?;

    let mut active = None;
    let mut replay_type = 0;
    let mut replay_sample = false;
    for line in body.lines() {
        if line == REPLAY_TYPE {
            replay_type += 1;
        } else if !line.starts_with('#') && line.starts_with(ACTIVE) {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| "active metric is malformed".to_owned())?;
            if (name != CLIENT_ACTIVE && name != SERVER_ACTIVE) || active.is_some() {
                return Err("active metric is malformed or duplicated".to_owned());
            }
            active = Some(
                value
                    .parse()
                    .map_err(|_| "active metric is malformed".to_owned())?,
            );
        } else if !line.starts_with('#') && line.starts_with(REPLAY) {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| "metrics exposition identity is malformed".to_owned())?;
            if name != REPLAY || replay_sample || value.parse::<i64>().is_err() {
                return Err("metrics exposition identity is malformed".to_owned());
            }
            replay_sample = true;
        }
    }
    if replay_type > 1 {
        return Err("metrics exposition identity is malformed".to_owned());
    }
    active
        .or_else(|| (replay_type == 1 && replay_sample).then_some(0))
        .ok_or_else(|| "active metric is absent from an unidentified exposition".to_owned())
}

fn metrics_body(response: &[u8]) -> Result<&str, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "metrics response is malformed".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "metrics response is malformed".to_owned())?;
    let mut status = headers
        .lines()
        .next()
        .ok_or_else(|| "metrics response is malformed".to_owned())?
        .split_whitespace();
    if !status
        .next()
        .is_some_and(|value| value.starts_with("HTTP/"))
        || status.next() != Some("200")
    {
        return Err("metrics response status is not 200".to_owned());
    }
    let body = std::str::from_utf8(&response[header_end + 4..])
        .map_err(|_| "metrics body is not UTF-8".to_owned())?;
    if !body.ends_with("# EOF\n") || body.lines().filter(|line| *line == "# EOF").count() != 1 {
        return Err("metrics exposition is incomplete".to_owned());
    }

    Ok(body)
}

pub(super) fn socks_connect(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let timeout = remaining(deadline)?;
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::V4(proxy), timeout).map_err(clean_io)?;
    stream.set_read_timeout(Some(timeout)).map_err(clean_io)?;
    stream.set_write_timeout(Some(timeout)).map_err(clean_io)?;
    stream.write_all(&[5, 1, 0]).map_err(clean_io)?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).map_err(clean_io)?;
    if method != [5, 0] {
        return Err("SOCKS authentication negotiation failed".to_owned());
    }
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).map_err(clean_io)?;
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).map_err(clean_io)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("SOCKS CONNECT failed".to_owned());
    }
    stream.set_read_timeout(None).map_err(clean_io)?;
    stream.set_write_timeout(None).map_err(clean_io)?;
    Ok(stream)
}

pub(super) fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "operation deadline expired".to_owned())
}

#[derive(Default)]
pub(super) struct StartGate {
    pub(super) state: Mutex<StartState>,
    pub(super) changed: Condvar,
}

#[derive(Default)]
pub(super) struct StartState {
    pub(super) ready: usize,
    pub(super) validated: usize,
    pub(super) start: Option<Instant>,
    pub(super) cancelled: bool,
}

impl StartGate {
    pub(super) fn ready_and_wait(&self) -> Result<Instant, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        state.ready += 1;
        self.changed.notify_all();
        while state.start.is_none() && !state.cancelled {
            state = self
                .changed
                .wait(state)
                .map_err(|_| "load start gate is poisoned".to_owned())?;
        }
        state
            .start
            .ok_or_else(|| "load start was cancelled".to_owned())
    }

    pub(super) fn start_when_ready(
        &self,
        expected: usize,
        deadline: Instant,
    ) -> Result<Instant, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        while state.ready != expected && !state.cancelled {
            let timeout = remaining(deadline)?;
            let (next, result) = self
                .changed
                .wait_timeout(state, timeout)
                .map_err(|_| "load start gate is poisoned".to_owned())?;
            state = next;
            if result.timed_out() && state.ready != expected {
                state.cancelled = true;
                self.changed.notify_all();
                return Err("load workers did not become ready".to_owned());
            }
        }
        if state.cancelled {
            return Err("load start was cancelled".to_owned());
        }
        let start = Instant::now();
        state.start = Some(start);
        self.changed.notify_all();
        Ok(start)
    }

    pub(super) fn worker_validated(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        state.validated += 1;
        self.changed.notify_all();
        Ok(())
    }

    pub(super) fn require_validated(&self, expected: usize) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        if state.cancelled {
            return Err("profile load was cancelled".to_owned());
        }
        if state.validated != expected {
            return Err("profile load workers did not validate warm-up traffic".to_owned());
        }
        Ok(())
    }

    pub(super) fn require_active(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        if state.cancelled {
            return Err("profile load was cancelled".to_owned());
        }
        Ok(())
    }

    pub(super) fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
            self.changed.notify_all();
        }
    }
}

pub(super) struct TargetWorker {
    pub(super) cancel: Arc<AtomicBool>,
    pub(super) worker: Option<JoinHandle<Result<(), String>>>,
}

impl TargetWorker {
    pub(super) fn echo(listener: TcpListener, streams: usize) -> Result<Self, String> {
        listener.set_nonblocking(true).map_err(clean_io)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = spawn_worker(move || {
            let mut workers = Vec::with_capacity(streams);
            let accepted = (|| {
                for _ in 0..streams {
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                if worker_cancel.load(Ordering::SeqCst) {
                                    return Err("target accept cancelled".to_owned());
                                }
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(error) => return Err(clean_io(error)),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_millis(200)))
                        .map_err(clean_io)?;
                    stream
                        .set_write_timeout(Some(Duration::from_millis(200)))
                        .map_err(clean_io)?;
                    let stream_cancel = Arc::clone(&worker_cancel);
                    workers.push(spawn_worker(move || {
                        let mut buffer = [0_u8; PAYLOAD_BYTES];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(read) => stream.write_all(&buffer[..read]).map_err(clean_io)?,
                                Err(error)
                                    if error.kind() == io::ErrorKind::WouldBlock
                                        || error.kind() == io::ErrorKind::TimedOut =>
                                {
                                    if stream_cancel.load(Ordering::SeqCst) {
                                        break;
                                    }
                                }
                                Err(error)
                                    if error.kind() == io::ErrorKind::ConnectionReset
                                        || error.kind() == io::ErrorKind::ConnectionAborted =>
                                {
                                    break;
                                }
                                Err(error) => return Err(clean_io(error)),
                            }
                        }
                        Ok(())
                    })?);
                }
                Ok::<(), String>(())
            })();
            if let Err(error) = accepted {
                worker_cancel.store(true, Ordering::SeqCst);
                return match join_unit_workers(workers) {
                    Ok(()) => Err(error),
                    Err(_) => Err(format!("{error}; target worker cleanup failed")),
                };
            }
            join_unit_workers(workers)
        })?;
        Ok(Self {
            cancel,
            worker: Some(worker),
        })
    }

    pub(super) fn finish(mut self) -> Result<(), String> {
        join_worker(self.worker.take().expect("target worker owner"))?
    }
}

impl Drop for TargetWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) struct HoldingTarget {
    pub(super) accepted: mpsc::Receiver<Result<(), String>>,
    pub(super) close: mpsc::Sender<Instant>,
    pub(super) cancel: Arc<AtomicBool>,
    pub(super) worker: Option<JoinHandle<Result<(), String>>>,
}

impl HoldingTarget {
    pub(super) fn start(listener: TcpListener, sessions: usize) -> Result<Self, String> {
        listener.set_nonblocking(true).map_err(clean_io)?;
        let (accepted_sender, accepted) = mpsc::sync_channel(1);
        let (close, close_receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = spawn_worker(move || {
            let mut streams = Vec::with_capacity(sessions);
            for _ in 0..sessions {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            streams.push(stream);
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if worker_cancel.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            let message = clean_io(error);
                            let _ = accepted_sender.send(Err(message.clone()));
                            return Err(message);
                        }
                    }
                }
            }
            accepted_sender
                .send(Ok(()))
                .map_err(|_| "accepted signal lost".to_owned())?;
            let deadline = loop {
                match close_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(deadline) => break deadline,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if worker_cancel.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                }
            };
            for stream in &streams {
                stream.set_nonblocking(true).map_err(clean_io)?;
            }
            while !streams.is_empty() {
                streams.retain_mut(|stream| {
                    let mut byte = [0_u8; 1];
                    match stream.read(&mut byte) {
                        Ok(0) => false,
                        Err(error)
                            if error.kind() == io::ErrorKind::ConnectionReset
                                || error.kind() == io::ErrorKind::ConnectionAborted =>
                        {
                            false
                        }
                        Ok(_) => true,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
                        Err(_) => true,
                    }
                });
                if Instant::now() >= deadline {
                    return Err("target did not observe every closure".to_owned());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        })?;
        Ok(Self {
            accepted,
            close,
            cancel,
            worker: Some(worker),
        })
    }

    pub(super) fn wait_accepted(&self, deadline: Instant) -> Result<(), String> {
        self.accepted
            .recv_timeout(remaining(deadline)?)
            .map_err(|_| "target did not accept 10000 streams".to_owned())?
    }

    pub(super) fn wait_closed(&mut self, deadline: Instant) -> Result<(), String> {
        self.close
            .send(deadline)
            .map_err(|_| "target close owner ended early".to_owned())?;
        let worker = self
            .worker
            .take()
            .ok_or_else(|| "target worker already joined".to_owned())?;
        join_worker(worker)?
    }
}

impl Drop for HoldingTarget {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        let _ = self.close.send(Instant::now());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) struct ProcessGuard {
    pub(super) child: Child,
    pub(super) label: String,
    pub(super) stdout: Option<JoinHandle<Capture>>,
    pub(super) stderr: Option<JoinHandle<Capture>>,
    pub(super) reaped: bool,
}

pub(super) struct Capture {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
    pub(super) secret: bool,
}

impl ProcessGuard {
    pub(super) fn spawn(label: &str, command: &mut Command) -> Result<Self, String> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| format!("{label} did not start"))?;
        let stdout = capture(child.stdout.take().expect("stdout owner"));
        let stderr = capture(child.stderr.take().expect("stderr owner"));
        ACTIVE_PROCESSES.fetch_add(1, Ordering::SeqCst);
        Ok(Self {
            child,
            label: label.to_owned(),
            stdout: Some(stdout),
            stderr: Some(stderr),
            reaped: false,
        })
    }

    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(super) fn ensure_running(&mut self) -> Result<(), String> {
        if let Some(status) = self.child.try_wait().map_err(clean_io)? {
            let error = format!("{} exited early with {status}", self.label);
            self.reap()?;
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn terminate(&mut self) -> Result<(), String> {
        if self.reaped {
            return Ok(());
        }
        if self.child.try_wait().map_err(clean_io)?.is_none() {
            self.child.kill().map_err(clean_io)?;
        }
        let _exit = wait_child(&mut self.child, Instant::now() + REAP_TIMEOUT)?;
        self.reap()
    }

    pub(super) fn reap(&mut self) -> Result<(), String> {
        let _ = self.child.wait().map_err(clean_io)?;
        let stdout = join_capture(self.stdout.take().expect("stdout capture"))?;
        let stderr = join_capture(self.stderr.take().expect("stderr capture"))?;
        self.reaped = true;
        ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
        if stdout.truncated || stderr.truncated {
            return Err(format!("{} output exceeded bound", self.label));
        }
        if stdout.secret || stderr.secret {
            return Err(format!("{} emitted secret-bearing output", self.label));
        }
        Ok(())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
        self.reaped = true;
        ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) fn capture(mut reader: impl Read + Send + 'static) -> JoinHandle<Capture> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut scan = Vec::new();
        let mut truncated = false;
        let mut secret = false;
        let mut chunk = [0_u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    scan.extend_from_slice(&chunk[..read]);
                    secret |= scan
                        .windows(PSK.len())
                        .any(|window| window == PSK.as_bytes());
                    if scan.len() > PSK.len() {
                        scan.drain(..scan.len() - PSK.len());
                    }
                    let remaining = PROCESS_OUTPUT_CAP.saturating_sub(bytes.len());
                    let keep = remaining.min(read);
                    bytes.extend_from_slice(&chunk[..keep]);
                    truncated |= keep < read;
                }
            }
        }
        Capture {
            bytes,
            truncated,
            secret,
        }
    })
}

pub(super) fn join_capture(worker: JoinHandle<Capture>) -> Result<Capture, String> {
    worker
        .join()
        .map_err(|_| "capture worker panicked".to_owned())
}

pub(super) fn wait_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<(ExitStatus, bool), String> {
    loop {
        if let Some(status) = child.try_wait().map_err(clean_io)? {
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().map(|status| (status, true)).map_err(clean_io);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn probe_text<P, I, S>(
    identity: &'static str,
    program: P,
    arguments: I,
    timeout: Duration,
) -> Result<String, String>
where
    P: AsRef<OsStr>,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(arguments);
    let mut process = ProcessGuard::spawn(identity, &mut command)?;
    let (status, timed_out) = wait_child(&mut process.child, Instant::now() + timeout)
        .map_err(|_| format!("{identity} wait failed"))?;
    let stdout = join_capture(process.stdout.take().expect("probe stdout"))
        .map_err(|_| format!("{identity} stdout capture failed"))?;
    let stderr = join_capture(process.stderr.take().expect("probe stderr"))
        .map_err(|_| format!("{identity} stderr capture failed"))?;
    process.reaped = true;
    ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
    if timed_out {
        return Err(format!("{identity} timed out"));
    }
    if stdout.truncated || stderr.truncated {
        return Err(format!("{identity} output exceeded bound"));
    }
    if stdout.secret || stderr.secret {
        return Err(format!("{identity} emitted secret-bearing output"));
    }
    if !status.success() {
        return Err(format!("{identity} exited nonzero"));
    }
    let output =
        String::from_utf8(stdout.bytes).map_err(|_| format!("{identity} stdout is not UTF-8"))?;
    String::from_utf8(stderr.bytes).map_err(|_| format!("{identity} stderr is not UTF-8"))?;
    Ok(output)
}

pub(super) fn sha256(identity: &'static str, path: &Path) -> Result<String, String> {
    let output = probe_text(identity, "sha256sum", [path.as_os_str()], PROBE_TIMEOUT)?;
    let digest = output
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("{identity} output is empty"))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{identity} output is malformed"));
    }
    Ok(digest.to_ascii_lowercase())
}

pub(super) fn spawn_worker<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<JoinHandle<T>, String> {
    ACTIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
    thread::Builder::new()
        .spawn(move || {
            let _owner = WorkerOwner;
            operation()
        })
        .map_err(|error| {
            ACTIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
            clean_io(error)
        })
}

pub(super) struct WorkerOwner;

impl Drop for WorkerOwner {
    fn drop(&mut self) {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) fn join_worker<T>(worker: JoinHandle<T>) -> Result<T, String> {
    worker
        .join()
        .map_err(|_| "owned worker panicked".to_owned())
}

pub(super) fn join_unit_workers(
    workers: Vec<JoinHandle<Result<(), String>>>,
) -> Result<(), String> {
    let mut first_error = None;
    for worker in workers {
        if let Err(error) = join_worker(worker).and_then(|result| result) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(super) fn wait_for_sample_slot(slot: Instant, next_slot: Instant) -> Result<(), String> {
    let delay = sample_slot_delay(Instant::now(), slot, next_slot)?;
    thread::sleep(delay);
    remaining(next_slot).map(|_| ())
}

pub(super) fn sample_slot_delay(
    now: Instant,
    slot: Instant,
    next_slot: Instant,
) -> Result<Duration, String> {
    if slot < now || slot >= next_slot {
        return Err("resource sample slot was missed".to_owned());
    }
    Ok(slot.duration_since(now))
}

pub(super) fn repository_root() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(clean_io)?;
    executable
        .parent()
        .and_then(find_repository_root)
        .ok_or_else(|| "repository root is unavailable".to_owned())
}

pub(super) fn find_repository_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|candidate| is_repository_root(candidate))
        .map(Path::to_path_buf)
}

pub(super) fn is_repository_root(candidate: &Path) -> bool {
    candidate.join("Cargo.toml").is_file()
        && candidate.join("Cargo.lock").is_file()
        && candidate
            .join("tools/ferrum2-m4-qualification/Cargo.toml")
            .is_file()
}

pub(super) fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("required hosted identity is missing: {name}"))
}

pub(super) fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("missing")
        .chars()
        .take(512)
        .collect()
}

pub(super) fn json(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push('?'),
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

pub(super) fn clean_io(error: impl std::fmt::Display) -> String {
    format!("I/O operation failed: {error}")
}
