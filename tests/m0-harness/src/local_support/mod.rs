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
            reaped: false,
        }
    }

    pub fn assert_running(&mut self) {
        if let Err(exit) = self.check_running() {
            panic!("{exit}");
        }
    }

    pub fn check_running(&mut self) -> Result<(), ChildExit> {
        match self.child.try_wait().expect("child status") {
            None => Ok(()),
            Some(status) => Err(self.finish_reap(status)),
        }
    }

    pub fn terminate_and_reap(&mut self, timeout: Duration) {
        if self.reaped {
            return;
        }
        if self.child.try_wait().expect("child status").is_none() {
            self.child.kill().expect("terminate child");
        }
        self.wait_and_reap(timeout);
    }

    pub fn wait_and_reap(&mut self, timeout: Duration) {
        if self.reaped {
            return;
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                let _ = self.finish_reap(status);
                return;
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
    address: SocketAddrV4,
) -> Result<(), ChildExit> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        child.check_running()?;
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("metrics readiness read timeout");
            stream
                .set_write_timeout(Some(Duration::from_millis(200)))
                .expect("metrics readiness write timeout");
            if stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .is_ok()
            {
                let mut response = Vec::with_capacity(512);
                let mut chunk = [0_u8; 512];
                while response.len() < METRICS_HEADER_CAP
                    && !response.windows(4).any(|window| window == b"\r\n\r\n")
                {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => response.extend_from_slice(&chunk[..read]),
                    }
                }
                if response.windows(4).any(|window| window == b"\r\n\r\n")
                    && response.starts_with(
                        b"HTTP/1.1 200 OK\r\n\
                          Content-Type: text/plain; version=0.0.4\r\n\
                          Content-Length: ",
                    )
                    && response
                        .windows(b"\r\nConnection: close\r\n\r\n".len())
                        .any(|window| window == b"\r\nConnection: close\r\n\r\n")
                {
                    child.check_running()?;
                    return Ok(());
                }
            }
        }
        child.check_running()?;
        assert!(
            Instant::now() < deadline,
            "metrics identity readiness timed out"
        );
        thread::sleep(READINESS_POLL);
    }
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
