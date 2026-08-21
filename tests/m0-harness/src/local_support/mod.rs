#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use socket2::{Domain, Protocol, Socket, Type};

pub const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
#[rustfmt::skip]
pub const TCP_METHOD_CONFIGS: [(&str, &str); 3] = [
    ("2022-blake3-aes-128-gcm", SYNTHETIC_PSK),
    ("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
    ("2022-blake3-chacha20-poly1305", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="),
];
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const METRICS_HEADER_CAP: usize = 4 * 1024;
const METRICS_RESPONSE_CAP: usize = 256 * 1024;
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_IO_CAP: Duration = Duration::from_millis(200);
const READINESS_POLL: Duration = Duration::from_millis(20);
const READINESS_CONFIRMATIONS: usize = 3;
static ACTIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);
static ISSUED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
// A concurrent fork inherits CLOEXEC sockets until exec; exact rebind probes hold this lock.
static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub fn hold_process_spawns() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_SPAWN_LOCK.lock().expect("process spawn lock")
}

pub fn hold_process_spawns_at_or_below(baseline: usize) -> std::sync::MutexGuard<'static, ()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let guard = hold_process_spawns();
        if active_child_count() <= baseline {
            return guard;
        }
        drop(guard);
        assert!(Instant::now() < deadline, "child baseline timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

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
    let _spawn_guard = hold_process_spawns();
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

    pub fn spawn_while_holding(
        name: &str,
        config: &Path,
        _spawn_guard: &std::sync::MutexGuard<'static, ()>,
    ) -> Self {
        Self::spawn_configured(name, config, "unclassified", false)
    }

    pub fn spawn_signallable_while_holding(
        name: &str,
        config: &Path,
        _spawn_guard: &std::sync::MutexGuard<'static, ()>,
    ) -> Self {
        Self::spawn_configured(name, config, "unclassified", true)
    }

    pub fn spawn_with_context(name: &str, config: &Path, context: impl Into<String>) -> Self {
        Self::spawn_with_context_and_signal_group(name, config, context, false)
    }

    pub fn spawn_signallable(name: &str, config: &Path, context: impl Into<String>) -> Self {
        Self::spawn_with_context_and_signal_group(name, config, context, true)
    }

    fn spawn_with_context_and_signal_group(
        name: &str,
        config: &Path,
        context: impl Into<String>,
        signal_group: bool,
    ) -> Self {
        let _spawn_guard = hold_process_spawns();
        Self::spawn_configured(name, config, context, signal_group)
    }

    fn spawn_configured(
        name: &str,
        config: &Path,
        context: impl Into<String>,
        signal_group: bool,
    ) -> Self {
        let mut command = Command::new(binary_path(name));
        command
            .args(["--config", config.to_str().expect("UTF-8 config path")])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        if signal_group {
            use std::os::windows::process::CommandExt as _;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            command.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }
        #[cfg(not(windows))]
        let _ = signal_group;
        let mut child = command.spawn().expect("spawn child process");
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

    pub fn request_graceful_shutdown(&mut self) {
        assert!(!self.reaped, "child already reaped");
        send_shutdown_signal(self.child.id());
    }

    pub fn wait_for_exit(&mut self, timeout: Duration) -> ChildExit {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                return self.finish_reap(status);
            }
            if Instant::now() >= deadline {
                self.child.kill().expect("kill child after reap deadline");
                let status = self.child.wait().expect("wait child after reap deadline");
                return self.finish_reap(status);
            }
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

struct OutputSummary {
    bytes: Box<[u8]>,
    hash: u64,
    truncated: bool,
}

impl fmt::Debug for OutputSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputSummary")
            .field("len", &self.bytes.len())
            .field("hash", &format_args!("{:016x}", self.hash))
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Debug)]
pub struct ChildExit {
    binary: String,
    context: String,
    pub status: ExitStatus,
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
            self.stdout.bytes.len(),
            self.stdout.hash,
            self.stdout.truncated,
            self.stderr.bytes.len(),
            self.stderr.hash,
            self.stderr.truncated,
        )
    }
}

impl ChildExit {
    pub fn assert_stderr_excludes(&self, sentinels: &[&str]) {
        assert!(
            !self.stderr.truncated,
            "stderr exclusion unavailable because capture was truncated"
        );
        for (index, sentinel) in sentinels.iter().enumerate() {
            assert!(
                !contains_bytes(&self.stderr.bytes, sentinel.as_bytes()),
                "stderr contained forbidden sentinel at index {index}"
            );
        }
    }
}

#[cfg(unix)]
fn send_shutdown_signal(process_id: u32) {
    let _spawn_guard = hold_process_spawns();
    let status = Command::new("kill")
        .args(["-INT", &process_id.to_string()])
        .status()
        .expect("send SIGINT");
    assert!(status.success(), "SIGINT sender failed: {status}");
}

#[cfg(windows)]
fn send_shutdown_signal(process_id: u32) {
    let script = format!(
        r#"Add-Type -Namespace Ferrum2 -Name ConsoleSignal -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool FreeConsole(); [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint processId); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr handler, bool add); [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint signal, uint processGroup);'; [void][Ferrum2.ConsoleSignal]::FreeConsole(); if (-not [Ferrum2.ConsoleSignal]::AttachConsole({process_id})) {{ exit 1 }}; [void][Ferrum2.ConsoleSignal]::SetConsoleCtrlHandler([System.IntPtr]::Zero, $true); $sent = [Ferrum2.ConsoleSignal]::GenerateConsoleCtrlEvent(1, {process_id}); [void][Ferrum2.ConsoleSignal]::FreeConsole(); if (-not $sent) {{ exit 1 }}"#
    );
    let _spawn_guard = hold_process_spawns();
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("send CTRL_BREAK_EVENT");
    const CONTROL_C_EXIT: i32 = -1_073_741_510;
    assert!(
        status.success() || status.code() == Some(CONTROL_C_EXIT),
        "Ctrl-Break sender failed before delivery: {status}"
    );
}

fn capture_output(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<OutputSummary> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        let mut truncated = false;
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    return OutputSummary {
                        bytes: bytes.into_boxed_slice(),
                        hash,
                        truncated,
                    };
                }
                Ok(read) => {
                    let remaining = CHILD_OUTPUT_CAP.saturating_sub(bytes.len());
                    let captured = read.min(remaining);
                    for byte in &chunk[..captured] {
                        hash ^= u64::from(*byte);
                        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                    bytes.extend_from_slice(&chunk[..captured]);
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
        match bind_loopback_listener(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                occupied_confirmations += 1;
                if occupied_confirmations >= READINESS_CONFIRMATIONS {
                    thread::sleep(READINESS_POLL);
                    child.assert_running();
                    match bind_loopback_listener(address) {
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

pub fn wait_for_tcp_udp_bound(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut occupied_confirmations = 0_usize;
    loop {
        child.assert_running();
        let tcp = bind_loopback_listener(address);
        let udp = UdpSocket::bind(address);
        match (tcp, udp) {
            (Err(tcp_error), Err(udp_error))
                if tcp_error.kind() == io::ErrorKind::AddrInUse
                    && udp_error.kind() == io::ErrorKind::AddrInUse =>
            {
                occupied_confirmations += 1;
                if occupied_confirmations >= READINESS_CONFIRMATIONS {
                    thread::sleep(READINESS_POLL);
                    child.assert_running();
                    let tcp_error =
                        bind_loopback_listener(address).expect_err("TCP readiness confirmation");
                    let udp_error =
                        UdpSocket::bind(address).expect_err("UDP readiness confirmation");
                    if tcp_error.kind() == io::ErrorKind::AddrInUse
                        && udp_error.kind() == io::ErrorKind::AddrInUse
                    {
                        return;
                    }
                    occupied_confirmations = 0;
                }
            }
            (Ok(tcp), Ok(udp)) => {
                drop((tcp, udp));
                occupied_confirmations = 0;
            }
            (Ok(tcp), Err(udp_error)) => {
                drop(tcp);
                assert_eq!(
                    udp_error.kind(),
                    io::ErrorKind::AddrInUse,
                    "UDP readiness bind probe failed: {udp_error}"
                );
                occupied_confirmations = 0;
            }
            (Err(tcp_error), Ok(udp)) => {
                drop(udp);
                assert_eq!(
                    tcp_error.kind(),
                    io::ErrorKind::AddrInUse,
                    "TCP readiness bind probe failed: {tcp_error}"
                );
                occupied_confirmations = 0;
            }
            (Err(tcp_error), Err(udp_error)) => {
                panic!("dual readiness bind probe failed: TCP={tcp_error}; UDP={udp_error}");
            }
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

pub fn wait_for_metrics(address: SocketAddrV4) -> Vec<u8> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(body) = fetch_ferrum_metrics(address, deadline) {
            return body;
        }
        assert!(Instant::now() < deadline, "metrics readiness timed out");
        thread::sleep(READINESS_POLL);
    }
}

pub fn wait_for_metrics_sample(address: SocketAddrV4, sample: &str) -> Vec<u8> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(body) = fetch_ferrum_metrics(address, deadline)
            && contains_bytes(&body, sample.as_bytes())
        {
            return body;
        }
        assert!(Instant::now() < deadline, "metrics sample timed out");
        thread::sleep(READINESS_POLL);
    }
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

pub(crate) fn metric_value(body: &[u8], metric: &str) -> Option<u64> {
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
    let listener = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port");
    let address = match listener.local_addr().expect("reserved address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind returned IPv6"),
    };
    (listener, address)
}

pub fn bind_loopback_listener(address: SocketAddrV4) -> io::Result<TcpListener> {
    loop {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::V4(address).into())?;
        socket.listen(128)?;
        let listener: TcpListener = socket.into();
        if address.port() != 0 {
            return Ok(listener);
        }
        let port = listener.local_addr()?.port();
        if ISSUED_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("issued-port registry")
            .insert(port)
        {
            return Ok(listener);
        }
    }
}

pub fn reserve_unused_loopback() -> LoopbackReservation {
    let (listener, address) = reserve_loopback();
    LoopbackReservation { listener, address }
}

pub fn unused_loopback() -> SocketAddrV4 {
    reserve_unused_loopback().release()
}

pub fn unused_tcp_udp_loopback() -> SocketAddrV4 {
    loop {
        let (tcp, address) = reserve_loopback();
        let Ok(udp) = UdpSocket::bind(address) else {
            drop(tcp);
            continue;
        };
        drop((tcp, udp));
        return address;
    }
}

pub struct DnsAnswerServer {
    address: SocketAddrV4,
    observations: mpsc::Receiver<RecordType>,
    pending_observations: Mutex<Vec<RecordType>>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<Vec<RecordType>>>,
}

impl DnsAnswerServer {
    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn wait_for_query(&self, expected: RecordType) {
        let mut pending = self
            .pending_observations
            .lock()
            .expect("pending DNS observations");
        if let Some(position) = pending.iter().position(|observed| *observed == expected) {
            pending.swap_remove(position);
            return;
        }
        loop {
            let observed = self
                .observations
                .recv_timeout(Duration::from_secs(5))
                .expect("DNS query observation");
            if observed == expected {
                return;
            }
            pending.push(observed);
        }
    }

    pub fn join(mut self) -> Vec<RecordType> {
        let _ = self.stop.send(());
        let observed = self
            .worker
            .take()
            .expect("DNS answer worker")
            .join()
            .expect("DNS answer worker join");
        let mut a = observed
            .iter()
            .filter(|record_type| **record_type == RecordType::A)
            .count();
        let mut aaaa = observed
            .iter()
            .filter(|record_type| **record_type == RecordType::AAAA)
            .count();
        let mut canonical = Vec::with_capacity(observed.len());
        while a != 0 || aaaa != 0 {
            if a != 0 {
                canonical.push(RecordType::A);
                a -= 1;
            }
            if aaaa != 0 {
                canonical.push(RecordType::AAAA);
                aaaa -= 1;
            }
        }
        canonical.extend(
            observed
                .into_iter()
                .filter(|record_type| !matches!(record_type, RecordType::A | RecordType::AAAA)),
        );
        canonical
    }
}

impl Drop for DnsAnswerServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.send(());
            let _ = worker.join();
        }
    }
}

pub enum DnsReply {
    Addresses(Vec<Ipv4Addr>),
    NoData,
    WrongId,
    Silence(Duration),
    DelayedNoData(Duration),
}

pub struct DnsStep {
    pub record_type: RecordType,
    pub reply: DnsReply,
}

pub fn start_dns_answer(answer: Ipv4Addr, expected_queries: usize) -> DnsAnswerServer {
    assert!(
        expected_queries != 0 && expected_queries.is_multiple_of(2),
        "address lookups contain A/AAAA pairs"
    );
    let mut script = Vec::with_capacity(expected_queries);
    for _ in 0..expected_queries / 2 {
        script.extend([
            DnsStep {
                record_type: RecordType::A,
                reply: DnsReply::Addresses(vec![answer]),
            },
            DnsStep {
                record_type: RecordType::AAAA,
                reply: DnsReply::NoData,
            },
        ]);
    }
    start_dns_script(script)
}

pub fn start_dns_script(script: Vec<DnsStep>) -> DnsAnswerServer {
    assert!(!script.is_empty(), "DNS script must not be empty");
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("DNS answer bind");
    let address = match socket.local_addr().expect("DNS answer address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 DNS answer"),
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("DNS answer timeout");
    let (observation, observations) = mpsc::channel();
    let (stop, stopped) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut script = script.into_iter().map(Some).collect::<Vec<_>>();
        let mut observed = Vec::with_capacity(script.len());
        let mut request = [0_u8; 4096];
        'steps: while script.iter().any(Option::is_some) {
            let (length, peer) = loop {
                match socket.recv_from(&mut request) {
                    Ok(received) => break received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if stopped.try_recv().is_ok() {
                            break 'steps;
                        }
                    }
                    Err(error) => panic!("DNS answer receive: {error}"),
                }
            };
            let request = Message::from_vec(&request[..length]).expect("DNS answer decode");
            let query = request.queries.first().expect("one DNS question").clone();
            let position = script
                .iter()
                .position(|step| {
                    step.as_ref()
                        .is_some_and(|step| step.record_type == query.query_type())
                })
                .expect("DNS script query type");
            let step = script[position].take().expect("pending DNS script step");
            observed.push(query.query_type());
            observation
                .send(query.query_type())
                .expect("DNS query observation receiver");
            match &step.reply {
                DnsReply::Silence(duration) => {
                    thread::sleep(*duration);
                    continue;
                }
                DnsReply::DelayedNoData(duration) => thread::sleep(*duration),
                _ => {}
            }
            let mut response = Message::new(request.id, MessageType::Response, request.op_code);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            match step.reply {
                DnsReply::Addresses(addresses) => {
                    for address in addresses {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            30,
                            RData::A(A(address)),
                        ));
                    }
                }
                DnsReply::WrongId => response.metadata.id = response.id.wrapping_add(1),
                DnsReply::NoData | DnsReply::DelayedNoData(_) => {}
                DnsReply::Silence(_) => unreachable!("silence continued"),
            }
            socket
                .send_to(&response.to_vec().expect("DNS answer encode"), peer)
                .expect("DNS answer response");
        }
        observed
    });
    DnsAnswerServer {
        address,
        observations,
        pending_observations: Mutex::new(Vec::new()),
        stop,
        worker: Some(worker),
    }
}

#[derive(Clone, Copy)]
pub enum ChainRoot {
    Static,
    RouteRule {
        target: SocketAddrV4,
        fallback_hop: usize,
    },
    RouteFinal,
    SelectorDefault,
}

#[allow(clippy::too_many_arguments)]
pub fn write_two_hop_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    servers: [SocketAddrV4; 2],
    inherited: (&str, &str),
    explicit: (&str, &str),
    root: ChainRoot,
    udp: bool,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let network = if udp { "udp" } else { "tcp" };
    let opposite_network = if udp { "tcp" } else { "udp" };
    let (inbound_outbound, selection) = match root {
        ChainRoot::Static => ("outbound = \"two-hop\"\n".to_owned(), String::new()),
        ChainRoot::RouteRule {
            target,
            fallback_hop,
        } => {
            let fallback = ["hop-a", "hop-b"][fallback_hop];
            (
                String::new(),
                format!(
                    "[route]\nfinal = \"{fallback}\"\n\
                     [[route.rules]]\nnetwork = \"{network}\"\ntarget = {{ host = \"{}\", port = {} }}\noutbound = \"two-hop\"\n\
                     [[route.rules]]\nnetwork = \"{network}\"\ntarget = {{ host = \"{}\", port = {} }}\noutbound = \"{fallback}\"\n",
                    target.ip(),
                    target.port(),
                    target.ip(),
                    target.port(),
                ),
            )
        }
        ChainRoot::RouteFinal => (
            String::new(),
            format!(
                "[route]\nfinal = \"two-hop\"\n\
                 [[route.rules]]\nnetwork = \"{opposite_network}\"\noutbound = \"hop-a\"\n"
            ),
        ),
        ChainRoot::SelectorDefault => (
            "outbound = \"manual\"\n".to_owned(),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"two-hop\", \"hop-a\"]\ndefault = \"two-hop\"\n".to_owned(),
        ),
    };
    let udp = if udp { "[udp]\n" } else { "" };
    let metrics = metrics
        .map(|address| format!("[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 1\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{listen}\"\n{inbound_outbound}\
         [[outbounds]]\ntag = \"hop-a\"\nserver = \"{}\"\n\
         [[outbounds]]\ntag = \"hop-b\"\nserver = \"{}\"\nmethod = \"{}\"\npsk = \"{}\"\n\
         [[chains]]\ntag = \"two-hop\"\nhops = [\"hop-a\", \"hop-b\"]\n\
         {selection}\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n\
         {udp}{metrics}",
        servers[0], servers[1], explicit.0, explicit.1, inherited.0, inherited.1,
    );
    let path = directory.join("two-hop-client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_client_config_with_psk(directory, listen, server, metrics, SYNTHETIC_PSK)
}

pub fn write_udp_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let path = write_client_config(directory, listen, server, metrics)?;
    let mut config = fs::read_to_string(&path)?;
    config.push_str("\n[udp]\n");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_tagged_client_config(
    directory: &Path,
    listens: [SocketAddrV4; 2],
    servers: [SocketAddrV4; 2],
    outbound_for_inbound: [usize; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    let udp = if udp { "\n[udp]\n" } else { "" };
    let outbound_one = if outbound_for_inbound.contains(&1) {
        format!(
            "\n[[outbounds]]\ntag = \"out-1\"\nserver = \"{}\"\n",
            servers[1]
        )
    } else {
        String::new()
    };
    let config = format!(
        "schema_version = 1\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-a\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-b\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"out-0\"\n\
         server = \"{}\"\n\
         {}\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{SYNTHETIC_PSK}\"\n\
         {udp}",
        listens[0],
        outbound_for_inbound[0],
        listens[1],
        outbound_for_inbound[1],
        servers[0],
        outbound_one,
    );
    let path = directory.join("tagged-client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_tagged_server_config(
    directory: &Path,
    listens: [SocketAddrV4; 2],
    outbound_for_inbound: [usize; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    let udp = if udp {
        ""
    } else {
        "\n[udp]\nenabled = false\n"
    };
    let outbound_one = if outbound_for_inbound.contains(&1) {
        "\n[[outbounds]]\ntag = \"out-1\"\n"
    } else {
        ""
    };
    let config = format!(
        "schema_version = 1\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-a\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-b\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"out-0\"\n\
         {}\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{SYNTHETIC_PSK}\"\n\
         {udp}",
        listens[0], outbound_for_inbound[0], listens[1], outbound_for_inbound[1], outbound_one,
    );
    let path = directory.join("tagged-server.toml");
    fs::write(&path, config)?;
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
pub fn write_tagged_dns_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    selected_name: &str,
    selected_port: u16,
    network: &str,
    upstreams: [SocketAddrV4; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    write_tagged_dns_server_matrix_config(
        directory,
        listen,
        network,
        &[("selected", upstreams[0]), ("final", upstreams[1])],
        &[(selected_name, selected_port, "selected")],
        "final",
        2_000,
        4,
        udp,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_tagged_dns_server_matrix_config(
    directory: &Path,
    listen: SocketAddrV4,
    network: &str,
    servers: &[(&str, SocketAddrV4)],
    rules: &[(&str, u16, &str)],
    final_server: &str,
    timeout_ms: u16,
    max_inflight: u16,
    udp: bool,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let udp = if udp {
        ""
    } else {
        "\n[udp]\nenabled = false\n"
    };
    let mut config = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"in\"\nlisten = \"{listen}\"\n"
    );
    for (tag, _) in servers {
        config.push_str(&format!(
            "[[outbounds]]\ntag = \"app-{tag}\"\ndomain_resolver = \"{tag}\"\n"
        ));
    }
    config.push_str(&format!(
        "[[outbounds]]\ntag = \"dns-direct\"\n\
         [route]\nfinal = \"app-{final_server}\"\n"
    ));
    for (name, port, server) in rules {
        config.push_str(&format!(
            "[[route.rules]]\ninbound = \"in\"\nnetwork = \"{network}\"\ndomain = \"{name}\"\nport = {port}\noutbound = \"app-{server}\"\n"
        ));
    }
    config.push_str(&format!(
        "[dns]\ntimeout_ms = {timeout_ms}\nmax_inflight = {max_inflight}\n"
    ));
    for (tag, address) in servers {
        config.push_str(&format!(
            "[[dns.servers]]\ntag = \"{tag}\"\ntransport = \"udp\"\naddress = \"{address}\"\ndetour = \"dns-direct\"\n"
        ));
    }
    config.push_str(&format!("[dns.route]\nfinal = \"{final_server}\"\n"));
    for (name, port, server) in rules {
        config.push_str(&format!(
            "[[dns.route.rules]]\ninbound = \"in\"\nnetwork = \"{network}\"\ntarget = {{ host = \"{name}\", port = {port} }}\nserver = \"{server}\"\n"
        ));
    }
    config.push_str(&format!(
        "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n{udp}"
    ));
    if let Some(metrics) = metrics {
        config.push_str(&format!("\n[metrics]\nlisten = \"{metrics}\"\n"));
    }
    let path = directory.join(format!("tagged-dns-server-{network}.toml"));
    fs::write(&path, config)?;
    Ok(path)
}

pub fn route_tagged_config(path: &Path, route: &str) -> io::Result<()> {
    let config = fs::read_to_string(path)?
        .replace("outbound = \"out-0\"\n", "")
        .replace("outbound = \"out-1\"\n", "");
    fs::write(path, config + route)
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
    write_server_config_variant(directory, listen, metrics, psk, "")
}

pub fn write_tcp_only_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_tcp_only_server_config_with_psk(directory, listen, metrics, SYNTHETIC_PSK)
}

pub fn write_tcp_only_server_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    write_server_config_variant(
        directory,
        listen,
        metrics,
        psk,
        "\n[udp]\nenabled = false\n",
    )
}

fn write_server_config_variant(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
    udp: &str,
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
         {udp}\
         {metrics}"
    );
    let path = directory.join("server.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn rewrite_config_method(path: &Path, method: (&str, &str)) -> io::Result<()> {
    let config = fs::read_to_string(path)?
        .replace(TCP_METHOD_CONFIGS[0].0, method.0)
        .replace(SYNTHETIC_PSK, method.1);
    fs::write(path, config)
}
