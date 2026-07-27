#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
static ACTIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);

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
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
    reaped: bool,
}

impl ChildGuard {
    pub fn spawn(name: &str, config: &Path) -> Self {
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
            stdout: Some(capture_output(stdout)),
            stderr: Some(capture_output(stderr)),
            reaped: false,
        }
    }

    pub fn assert_running(&mut self) {
        assert!(
            self.child.try_wait().expect("child status").is_none(),
            "child exited before readiness"
        );
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
            if self.child.try_wait().expect("child status").is_some() {
                self.finish_reap();
                return;
            }
            assert!(Instant::now() < deadline, "child reap timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish_reap(&mut self) {
        if self.reaped {
            return;
        }
        self.child.wait().expect("reap child");
        if let Some(stdout) = self.stdout.take() {
            stdout.join().expect("join stdout capture");
        }
        if let Some(stderr) = self.stderr.take() {
            stderr.join().expect("join stderr capture");
        }
        self.reaped = true;
        let previous = ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 0, "child registry underflow");
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

fn capture_output(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return captured,
                Ok(read) => {
                    let remaining = CHILD_OUTPUT_CAP.saturating_sub(captured.len());
                    captured.extend_from_slice(&chunk[..read.min(remaining)]);
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
    loop {
        child.assert_running();
        match TcpListener::bind(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
            Ok(listener) => drop(listener),
            Err(error) => panic!("listener readiness bind probe failed: {error}"),
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn active_child_count() -> usize {
    ACTIVE_CHILDREN.load(Ordering::SeqCst)
}

pub fn reserve_loopback() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback port");
    let address = match listener.local_addr().expect("reserved address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind returned IPv6"),
    };
    (listener, address)
}

pub fn unused_loopback() -> SocketAddrV4 {
    static ISSUED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    loop {
        let (listener, address) = reserve_loopback();
        let inserted = ISSUED_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("issued-port registry")
            .insert(address.port());
        drop(listener);
        if inserted {
            return address;
        }
    }
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
