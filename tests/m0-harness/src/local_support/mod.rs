#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const METRICS_HEADER_CAP: usize = 4 * 1024;
const METRICS_RESPONSE_CAP: usize = 256 * 1024;
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_IO_CAP: Duration = Duration::from_millis(200);
const READINESS_POLL: Duration = Duration::from_millis(20);
const READINESS_CONFIRMATIONS: usize = 3;
static ACTIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);
static ISSUED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

pub fn binary_path(name: &str) -> PathBuf {
    let executable = std::env::current_exe().expect("test executable path");
    let profile = executable
        .parent()
        .and_then(Path::parent)
        .expect("target profile directory");
    let suffix = std::env::consts::EXE_SUFFIX;
    let path = profile.join(format!("{name}{suffix}"));
    assert!(
        path.is_file(),
        "required binary artifact is missing: {}",
        path.display()
    );
    path
}

pub fn run_binary(name: &str, arguments: &[&str]) -> Output {
    Command::new(binary_path(name))
        .args(arguments)
        .output()
        .expect("run binary")
}

pub struct ChildGuard {
    child: Child,
    binary: String,
    context: String,
    stdout: Option<thread::JoinHandle<OutputSummary>>,
    stderr: Option<thread::JoinHandle<OutputSummary>>,
    pending_status: Option<ExitStatus>,
    deferred_exit_checks: usize,
    reaped: bool,
}

impl ChildGuard {
    pub fn spawn(name: &str, config: &Path) -> Self {
        Self::spawn_with_context(name, config, "unclassified")
    }

    pub fn spawn_with_context(name: &str, config: &Path, context: impl Into<String>) -> Self {
        let mut child = Command::new(binary_path(name))
            .args(["--config", config.to_str().expect("UTF-8 config path")])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child process");
        let stdout = child.stdout.take().expect("child stdout pipe");
        let stderr = child.stderr.take().expect("child stderr pipe");
        ACTIVE_CHILDREN.fetch_add(1, Ordering::SeqCst);
        Self {
            child,
            binary: name.to_owned(),
            context: context.into(),
            stdout: Some(capture_output(stdout)),
            stderr: Some(capture_output(stderr)),
            pending_status: None,
            deferred_exit_checks: 0,
            reaped: false,
        }
    }

    pub fn defer_exit_observation_for_checks(&mut self, checks: usize) {
        self.deferred_exit_checks = checks;
    }

    pub fn assert_running(&mut self) {
        if let Err(exit) = self.check_running() {
            panic!("{exit}");
        }
    }

    pub fn check_running(&mut self) -> Result<(), ChildExit> {
        let status = match self.pending_status {
            Some(status) => Some(status),
            None => self.child.try_wait().expect("child status"),
        };
        match status {
            None => Ok(()),
            Some(status) if self.deferred_exit_checks > 0 => {
                self.pending_status = Some(status);
                self.deferred_exit_checks -= 1;
                Ok(())
            }
            Some(status) => {
                self.pending_status = None;
                Err(self.finish_reap(status))
            }
        }
    }

    pub fn terminate_and_reap(&mut self, timeout: Duration) {
        if self.reaped {
            return;
        }
        let _ = self.terminate_and_reap_with_exit(timeout);
    }

    pub fn terminate_and_reap_with_exit(&mut self, timeout: Duration) -> ChildExit {
        assert!(!self.reaped, "child already reaped");
        if let Some(status) = self.pending_status.take() {
            return self.finish_reap(status);
        }
        if self.child.try_wait().expect("child status").is_none() {
            self.child.kill().expect("terminate child");
        }
        self.wait_for_exit(timeout)
    }

    pub fn wait_and_reap(&mut self, timeout: Duration) {
        if self.reaped {
            return;
        }
        if let Some(status) = self.pending_status.take() {
            let _ = self.finish_reap(status);
            return;
        }
        let _ = self.wait_for_exit(timeout);
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ChildExit {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                return self.finish_reap(status);
            }
            assert!(Instant::now() < deadline, "child reap timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish_reap(&mut self, status: ExitStatus) -> ChildExit {
        debug_assert!(!self.reaped);
        let _ = self.child.wait().expect("reap child");
        let stdout = self
            .stdout
            .take()
            .expect("stdout capture owner")
            .join()
            .expect("join stdout capture");
        let stderr = self
            .stderr
            .take()
            .expect("stderr capture owner")
            .join()
            .expect("join stderr capture");
        self.reaped = true;
        let previous = ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 0, "child registry underflow");
        ChildExit {
            binary: self.binary.clone(),
            context: self.context.clone(),
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
        self.reaped = true;
        ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputSummary {
    captured_bytes: usize,
    hash: u64,
    truncated: bool,
}

#[derive(Debug)]
pub struct ChildExit {
    binary: String,
    context: String,
    status: ExitStatus,
    stdout: OutputSummary,
    stderr: OutputSummary,
}

#[derive(Debug)]
pub enum MetricsReadinessFailure {
    ChildExited(ChildExit),
    Deadline,
}

impl fmt::Display for ChildExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "child exited: binary={} context={} status={} \
             stdout_len={} stdout_hash={:016x} stdout_truncated={} \
             stderr_len={} stderr_hash={:016x} stderr_truncated={}",
            self.binary,
            self.context,
            self.status,
            self.stdout.captured_bytes,
            self.stdout.hash,
            self.stdout.truncated,
            self.stderr.captured_bytes,
            self.stderr.hash,
            self.stderr.truncated,
        )
    }
}

fn capture_output(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<OutputSummary> {
    thread::spawn(move || {
        let mut captured_bytes = 0_usize;
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        let mut truncated = false;
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    return OutputSummary {
                        captured_bytes,
                        hash,
                        truncated,
                    };
                }
                Ok(read) => {
                    let remaining = CHILD_OUTPUT_CAP.saturating_sub(captured_bytes);
                    let captured = read.min(remaining);
                    for byte in &chunk[..captured] {
                        hash ^= u64::from(*byte);
                        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                    captured_bytes += captured;
                    truncated |= captured < read;
                }
            }
        }
    })
}

pub fn wait_for_listener(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        child.assert_running();
        if std::net::TcpStream::connect(address).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn wait_for_bound(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut occupied_confirmations = 0_usize;
    loop {
        child.assert_running();
        match TcpListener::bind(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                occupied_confirmations += 1;
                if occupied_confirmations >= READINESS_CONFIRMATIONS {
                    thread::sleep(READINESS_POLL);
                    child.assert_running();
                    match TcpListener::bind(address) {
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
                        Ok(listener) => {
                            drop(listener);
                            occupied_confirmations = 0;
                        }
                        Err(error) => {
                            panic!("listener readiness confirmation failed: {error}");
                        }
                    }
                }
            }
            Ok(listener) => {
                drop(listener);
                occupied_confirmations = 0;
            }
            Err(error) => panic!("listener readiness bind probe failed: {error}"),
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(READINESS_POLL);
    }
}

pub fn wait_for_metrics_ready(
    child: &mut ChildGuard,
    proxy: SocketAddrV4,
    metrics: SocketAddrV4,
) -> Result<(), MetricsReadinessFailure> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let identity = match child.binary.as_str() {
        "ferrum2-client" => ReadinessIdentity::Client,
        "ferrum2-server" => ReadinessIdentity::Server,
        binary => panic!("unsupported readiness binary: {binary}"),
    };
    let initial = loop {
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        if let Some(body) = fetch_ferrum_metrics(metrics, deadline) {
            break metric_value(&body, identity.failure_metric()).unwrap_or(0);
        }
        let Some(sleep) = remaining_capped(deadline, READINESS_POLL) else {
            return Err(MetricsReadinessFailure::Deadline);
        };
        thread::sleep(sleep);
    };
    if initial != 0 || !send_identity_probe(proxy, identity, deadline) {
        return Err(MetricsReadinessFailure::Deadline);
    }

    loop {
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        if fetch_ferrum_metrics(metrics, deadline)
            .and_then(|body| metric_value(&body, identity.failure_metric()))
            == Some(1)
        {
            child
                .check_running()
                .map_err(MetricsReadinessFailure::ChildExited)?;
            return Ok(());
        }
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        let Some(sleep) = remaining_capped(deadline, READINESS_POLL) else {
            return Err(MetricsReadinessFailure::Deadline);
        };
        thread::sleep(sleep);
    }
}

#[derive(Clone, Copy)]
enum ReadinessIdentity {
    Client,
    Server,
}

impl ReadinessIdentity {
    fn probe(self) -> &'static [u8] {
        match self {
            Self::Client => &[4, 1, 0],
            Self::Server => &[0xa5; 43],
        }
    }

    fn failure_metric(self) -> &'static str {
        match self {
            Self::Client => {
                "ferrum2_tcp_failures_total{role=\"client\",stage=\"socks5\",reason=\"socks_protocol\"}"
            }
            Self::Server => {
                "ferrum2_tcp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"}"
            }
        }
    }
}

fn send_identity_probe(
    proxy: SocketAddrV4,
    identity: ReadinessIdentity,
    deadline: Instant,
) -> bool {
    let Some(connect_timeout) = remaining_capped(deadline, READINESS_IO_CAP) else {
        return false;
    };
    let Ok(mut stream) =
        TcpStream::connect_timeout(&std::net::SocketAddr::V4(proxy), connect_timeout)
    else {
        return false;
    };
    write_before_deadline(&mut stream, identity.probe(), deadline).is_ok()
        && stream.shutdown(std::net::Shutdown::Write).is_ok()
}

fn remaining_capped(deadline: Instant, cap: Duration) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(cap))
}

fn fetch_ferrum_metrics(address: SocketAddrV4, deadline: Instant) -> Option<Vec<u8>> {
    let connect_timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
    let mut stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::V4(address), connect_timeout).ok()?;
    if write_before_deadline(
        &mut stream,
        b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deadline,
    )
    .is_err()
    {
        return None;
    }

    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if response.len() >= METRICS_HEADER_CAP {
            return None;
        }
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
        if stream.set_read_timeout(Some(timeout)).is_err() {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
    };

    let content_length = metrics_content_length(&response[..header_end])?;
    let response_length = header_end.checked_add(content_length)?;
    if response_length > METRICS_RESPONSE_CAP {
        return None;
    }
    while response.len() < response_length {
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
        if stream.set_read_timeout(Some(timeout)).is_err() {
            return None;
        }
        let remaining = response_length - response.len();
        let read_length = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_length]) {
            Ok(0) | Err(_) => return None,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
    }

    let body = &response[header_end..response_length];
    (contains_bytes(body, b"# HELP ferrum2_tcp_replay_entries ")
        && contains_bytes(body, b"# TYPE ferrum2_tcp_replay_entries gauge"))
    .then(|| body.to_vec())
}

fn write_before_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "readiness deadline"))?;
        stream.set_write_timeout(Some(timeout))?;
        match stream.write(bytes)? {
            0 => return Err(io::Error::new(io::ErrorKind::WriteZero, "metrics request")),
            written => bytes = &bytes[written..],
        }
    }
    Ok(())
}

fn metrics_content_length(header: &[u8]) -> Option<usize> {
    let header = std::str::from_utf8(header).ok()?;
    let mut lines = header.split("\r\n");
    if lines.next()? != "HTTP/1.1 200 OK" {
        return None;
    }
    let mut content_type = false;
    let mut connection_close = false;
    let mut content_length = None;
    for line in lines {
        if line == "Content-Type: text/plain; version=0.0.4" {
            content_type = true;
        } else if line == "Connection: close" {
            connection_close = true;
        } else if let Some(value) = line.strip_prefix("Content-Length: ") {
            content_length = value.parse().ok();
        }
    }
    (content_type && connection_close)
        .then_some(content_length)
        .flatten()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn metric_value(body: &[u8], metric: &str) -> Option<u64> {
    let body = std::str::from_utf8(body).ok()?;
    body.lines().find_map(|line| {
        let (name, value) = line.rsplit_once(' ')?;
        (name == metric).then(|| value.parse().ok()).flatten()
    })
}

pub fn active_child_count() -> usize {
    ACTIVE_CHILDREN.load(Ordering::SeqCst)
}

pub struct LoopbackReservation {
    listener: TcpListener,
    address: SocketAddrV4,
}

impl LoopbackReservation {
    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn release(self) -> SocketAddrV4 {
        drop(self.listener);
        self.address
    }
}

pub fn reserve_loopback() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback port");
    let address = match listener.local_addr().expect("reserved address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind returned IPv6"),
    };
    (listener, address)
}

pub fn reserve_unused_loopback() -> LoopbackReservation {
    loop {
        let (listener, address) = reserve_loopback();
        let inserted = ISSUED_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("issued-port registry")
            .insert(address.port());
        if inserted {
            return LoopbackReservation { listener, address };
        }
    }
}

pub fn unused_loopback() -> SocketAddrV4 {
    reserve_unused_loopback().release()
}

pub fn write_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_client_config_with_psk(directory, listen, server, metrics, SYNTHETIC_PSK)
}

pub fn write_client_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 1\n\
         \n\
         [client]\n\
         listen = \"{listen}\"\n\
         server = \"{server}\"\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{psk}\"\n\
         {metrics}"
    );
    let path = directory.join("client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_server_config_with_psk(directory, listen, metrics, SYNTHETIC_PSK)
}

pub fn write_server_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 1\n\
         \n\
         [server]\n\
         listen = \"{listen}\"\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{psk}\"\n\
         {metrics}"
    );
    let path = directory.join("server.toml");
    fs::write(&path, config)?;
    Ok(path)
}
