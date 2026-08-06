use crate::qualification::{
    CaseFailure, CaseSpec, CleanupState, Direction, DnsCaseSpec, DnsPath, DnsQualificationOps,
    DnsReference, DnsUpstreamTransport, Method, QualificationOps, Reference, TcpApplicationGate,
    TcpExchangeEvent, TcpExchangeState, Transport, tcp_shutdown_gate,
};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const MAX_UDP_DATAGRAM: usize = 65_507;
const SESSION_DATAGRAMS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

static CLEANUP_STATE: OnceLock<Mutex<CleanupState>> = OnceLock::new();

type PendingOwners = (Vec<Child>, Vec<thread::JoinHandle<()>>);
static PENDING: OnceLock<Mutex<PendingOwners>> = OnceLock::new();

fn cleanup_state(operation: impl FnOnce(&mut CleanupState)) {
    operation(
        &mut CLEANUP_STATE
            .get_or_init(|| Mutex::new(CleanupState::default()))
            .lock()
            .expect("cleanup state lock"),
    );
}

fn pending() -> &'static Mutex<PendingOwners> {
    PENDING.get_or_init(|| Mutex::new((Vec::new(), Vec::new())))
}

fn retain_unconfirmed_worker(worker: thread::JoinHandle<()>) {
    pending().lock().expect("pending owner lock").1.push(worker);
}

struct Pin {
    version: String,
    source_commit: String,
    expected_version: String,
    asset: String,
    url: String,
    size: u64,
    sha256: String,
    license_review: String,
}

pub struct HostedOperations;

impl HostedOperations {
    pub const fn new() -> Self {
        Self
    }
}

impl QualificationOps for HostedOperations {
    fn provision(&mut self, reference: Reference) -> Result<(), CaseFailure> {
        match catch_sanitized(|| provision_reference(reference)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification provision failed: reference={reference:?}, diagnostic={}",
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(reference.provision_root()))
            }
        }
    }

    fn run_case(&mut self, case: CaseSpec) -> Result<(), CaseFailure> {
        match catch_sanitized(|| run_case(case)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification case failed: case_id={}, diagnostic={}",
                    case.id,
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(case.case_root()))
            }
        }
    }

    fn finish_cleanup(&mut self) -> Result<(), CaseFailure> {
        let owners_finished = {
            let pending = pending().lock().expect("pending owner lock");
            pending.0.is_empty() && pending.1.is_empty()
        };
        let state = *CLEANUP_STATE
            .get_or_init(|| Mutex::new(CleanupState::default()))
            .lock()
            .expect("cleanup state lock");
        if owners_finished && state.success() {
            Ok(())
        } else {
            Err(CaseFailure::new("cleanup"))
        }
    }
}

impl DnsQualificationOps for HostedOperations {
    fn provision_dns(&mut self, reference: DnsReference) -> Result<(), CaseFailure> {
        match catch_sanitized(|| provision_dns_reference(reference)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification DNS provision failed: reference={reference:?}, diagnostic={}",
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(reference.provision_root()))
            }
        }
    }

    fn run_dns_case(&mut self, case: DnsCaseSpec) -> Result<(), CaseFailure> {
        match catch_sanitized(|| run_external_dns_case(case)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification DNS case failed: case_id={}, diagnostic={}",
                    case.id,
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(case.case_root()))
            }
        }
    }

    fn finish_dns_cleanup(&mut self) -> Result<(), CaseFailure> {
        self.finish_cleanup()
    }
}

fn catch_sanitized<T>(operation: impl FnOnce() -> T) -> Result<T, Box<dyn std::any::Any + Send>> {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(operation));
    std::panic::set_hook(previous_hook);
    result
}

#[derive(Clone, Copy)]
struct CaseDeadline {
    end: Instant,
}

impl CaseDeadline {
    fn start() -> Self {
        Self {
            end: Instant::now() + CASE_TIMEOUT,
        }
    }

    fn remaining(self, label: &str) -> Duration {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .unwrap_or_else(|| panic!("{label}: absolute case deadline exceeded"))
    }

    fn bounded(self, requested: Duration, label: &str) -> Duration {
        requested.min(self.remaining(label))
    }

    fn check(self, label: &str) {
        let _ = self.remaining(label);
    }
}

struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

struct CaptureReader {
    result: Receiver<Capture>,
    worker: Option<thread::JoinHandle<()>>,
}

fn capture_output(mut stream: impl Read + Send + 'static) -> CaptureReader {
    let (sender, result) = mpsc::sync_channel(1);
    cleanup_state(CleanupState::worker_started);
    let worker = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(CHILD_OUTPUT_CAP.min(8 * 1024));
        let mut buffer = [0_u8; 4096];
        let mut truncated = false;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let retained = CHILD_OUTPUT_CAP.saturating_sub(bytes.len()).min(read);
                    bytes.extend_from_slice(&buffer[..retained]);
                    truncated |= retained != read;
                }
                Err(_) => break,
            }
        }
        let _ = sender.send(Capture { bytes, truncated });
    });
    CaptureReader {
        result,
        worker: Some(worker),
    }
}

impl CaptureReader {
    fn finish(mut self, deadline: CaseDeadline, label: &str) -> Capture {
        let capture = match self.result.recv_timeout(deadline.remaining(label)) {
            Ok(capture) => capture,
            Err(error) => {
                cleanup_state(CleanupState::fail);
                panic!("{label}: capture completion failed: {error}");
            }
        };
        let worker = self.worker.take().expect("capture worker owner");
        match worker.join() {
            Ok(()) => cleanup_state(CleanupState::worker_joined),
            Err(_) => {
                cleanup_state(CleanupState::fail);
                panic!("{label}: capture worker panicked");
            }
        }
        capture
    }
}

impl Drop for CaptureReader {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            cleanup_state(CleanupState::fail);
            retain_unconfirmed_worker(worker);
        }
    }
}

struct CancellableWorker<T> {
    cancelled: Arc<AtomicBool>,
    result: Receiver<T>,
    worker: Option<thread::JoinHandle<()>>,
}

impl<T: Send + 'static> CancellableWorker<T> {
    fn spawn(operation: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (sender, result) = mpsc::sync_channel(1);
        cleanup_state(CleanupState::worker_started);
        let worker = thread::spawn(move || {
            let _ = sender.send(operation(worker_cancelled));
        });
        Self {
            cancelled,
            result,
            worker: Some(worker),
        }
    }

    fn finish(mut self, deadline: CaseDeadline, label: &str) -> T {
        let result = self
            .result
            .recv_timeout(deadline.remaining(label))
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        self.join();
        result
    }
}

impl<T> CancellableWorker<T> {
    fn join(&mut self) {
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(()) => cleanup_state(CleanupState::worker_joined),
                Err(_) => {
                    cleanup_state(CleanupState::fail);
                    panic!("owned worker panicked");
                }
            }
        }
    }
}

impl<T> Drop for CancellableWorker<T> {
    fn drop(&mut self) {
        if self.worker.is_none() {
            return;
        }
        cleanup_state(CleanupState::fail);
        self.cancelled.store(true, Ordering::SeqCst);
        match self.result.recv_timeout(Duration::from_secs(2)) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = catch_unwind(AssertUnwindSafe(|| self.join()));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                retain_unconfirmed_worker(self.worker.take().expect("pending worker owner"));
            }
        }
    }
}

struct ProcessGuard {
    label: &'static str,
    child: Option<Child>,
    stdout: Option<CaptureReader>,
    stderr: Option<CaptureReader>,
    counted: bool,
}

impl ProcessGuard {
    fn spawn(label: &'static str, command: &mut Command, deadline: CaseDeadline) -> Self {
        deadline.check("before child spawn");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
        cleanup_state(CleanupState::child_started);
        let mut guard = Self {
            label,
            child: Some(child),
            stdout: None,
            stderr: None,
            counted: true,
        };
        let stdout = guard
            .child
            .as_mut()
            .expect("child owner")
            .stdout
            .take()
            .expect("captured child stdout");
        guard.stdout = Some(capture_output(stdout));
        let stderr = guard
            .child
            .as_mut()
            .expect("child owner")
            .stderr
            .take()
            .expect("captured child stderr");
        guard.stderr = Some(capture_output(stderr));
        guard
    }

    fn assert_running(&mut self, deadline: CaseDeadline, phase: &str) {
        deadline.check(phase);
        let status = match self.child.as_mut().expect("child owner").try_wait() {
            Ok(status) => status,
            Err(error) => {
                cleanup_state(CleanupState::fail);
                panic!("query child status: {error}");
            }
        };
        if let Some(status) = status {
            self.mark_reaped();
            let diagnostics = self.finish_capture(deadline);
            panic!(
                "{} exited during {phase} with {status}: {diagnostics}",
                self.label
            );
        }
    }

    fn wait_for_exit(&mut self, deadline: CaseDeadline, phase: &str) -> ExitStatus {
        loop {
            deadline.check(phase);
            match self.child.as_mut().expect("child owner").try_wait() {
                Ok(Some(status)) => {
                    self.mark_reaped();
                    return status;
                }
                Ok(None) => {}
                Err(error) => {
                    cleanup_state(CleanupState::fail);
                    panic!("query child status: {error}");
                }
            }
            thread::sleep(POLL_INTERVAL.min(deadline.remaining(phase)));
        }
    }

    fn terminate(&mut self, deadline: CaseDeadline) -> String {
        let (status, stdout, stderr) = self.terminate_captures(deadline);
        format!(
            "terminated_status={status}, stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }

    fn terminate_captures(&mut self, deadline: CaseDeadline) -> (ExitStatus, Capture, Capture) {
        self.assert_running(deadline, "pre-cleanup child status");
        self.child
            .as_mut()
            .expect("child owner")
            .kill()
            .unwrap_or_else(|error| panic!("terminate {}: {error}", self.label));
        let status = self.wait_for_exit(deadline, "intentional child cleanup");
        let (stdout, stderr) = self.finish_captures(deadline);
        (status, stdout, stderr)
    }

    fn finish_capture(&mut self, deadline: CaseDeadline) -> String {
        let (stdout, stderr) = self.finish_captures(deadline);
        format!(
            "stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }

    fn finish_captures(&mut self, deadline: CaseDeadline) -> (Capture, Capture) {
        (
            self.stdout
                .take()
                .expect("stdout capture consumed exactly once")
                .finish(deadline, "stdout capture"),
            self.stderr
                .take()
                .expect("stderr capture consumed exactly once")
                .finish(deadline, "stderr capture"),
        )
    }

    fn mark_reaped(&mut self) {
        if self.counted {
            cleanup_state(CleanupState::child_reaped);
            self.counted = false;
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.counted {
            cleanup_state(CleanupState::fail);
            let child = self.child.as_mut().expect("child owner");
            let _ = child.kill();
            let cleanup_end = Instant::now() + Duration::from_secs(2);
            let mut reaped = false;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        reaped = true;
                        break;
                    }
                    Ok(None) if Instant::now() < cleanup_end => thread::sleep(POLL_INTERVAL),
                    Ok(None) => break,
                    Err(_) => {
                        cleanup_state(CleanupState::fail);
                        break;
                    }
                }
            }
            if reaped {
                self.mark_reaped();
            } else {
                pending()
                    .lock()
                    .expect("pending owner lock")
                    .0
                    .push(self.child.take().expect("retain unconfirmed child"));
            }
        }
        if self.counted {
            cleanup_state(CleanupState::fail);
        } else {
            let capture_deadline = CaseDeadline {
                end: Instant::now() + Duration::from_secs(2),
            };
            if self.stdout.is_some() && self.stderr.is_some() {
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    let _ = self.finish_captures(capture_deadline);
                }));
            }
        }
    }
}

fn sanitize_capture(capture: Capture) -> String {
    let rendered = String::from_utf8_lossy(&capture.bytes);
    let redacted = redact_synthetic_psks(&rendered)
        .replace('\r', "\\r")
        .replace('\n', "\\n");
    if capture.truncated {
        format!("{redacted}[truncated]")
    } else {
        redacted
    }
}

fn redact_synthetic_psks(text: &str) -> String {
    text.replace(Method::Aes128Gcm.synthetic_psk(), "[redacted]")
        .replace(Method::Aes256Gcm.synthetic_psk(), "[redacted]")
}

fn provision_reference(reference: Reference) {
    let deadline = CaseDeadline::start();
    let pin = load_pin(reference);
    verify_pin(reference, &pin);
    let paths = reference_paths(reference, &pin);
    verify_archive(&paths.archive, &pin, deadline);
    verify_archive_members(reference, &paths.archive, &pin, deadline);
    verify_binary_location(&paths.server, &paths.extraction_root);
    verify_version(reference, &paths.server, &pin, deadline);
    if let Some(client) = &paths.client {
        verify_binary_location(client, &paths.extraction_root);
        if reference == Reference::ShadowsocksRust {
            verify_version(reference, client, &pin, deadline);
        }
    }
    if let Some(license) = &paths.license {
        verify_reviewed_license(license);
    }
    verify_transport_configs(reference, &paths, deadline);
    deadline.check("final reference provision verification");
}

fn provision_dns_reference(reference: DnsReference) {
    let deadline = CaseDeadline::start();
    let pin = load_dns_pin(reference);
    verify_dns_pin(reference, &pin);
    let paths = dns_reference_paths(reference, &pin);
    verify_archive(&paths.archive, &pin, deadline);
    verify_binary_location(&paths.binary, &paths.extraction_root);
    verify_reviewed_license(&paths.license);
    if reference == DnsReference::CoreDns {
        let values = load_pin_values("coredns");
        let license = fs::read(&paths.license).expect("read CoreDNS license");
        assert_eq!(
            license.len(),
            value(&values, "license_size")
                .parse::<usize>()
                .expect("numeric CoreDNS license size")
        );
        assert_eq!(
            sha256_bytes(&license),
            value(&values, "license_sha256"),
            "CoreDNS license hash mismatch"
        );
    }
    let mut command = Command::new(&paths.binary);
    match reference {
        DnsReference::CoreDns => {
            command.arg("-version");
        }
        DnsReference::Bind => {
            command.arg("-v");
        }
    }
    let rendered = run_dns_probe(&mut command, deadline, "DNS provider version");
    assert!(
        rendered
            .lines()
            .any(|line| line.contains(&pin.expected_version)),
        "DNS provider version mismatch"
    );
}

fn verify_dns_pin(reference: DnsReference, pin: &Pin) {
    let (version, commit, asset, url, license) = match reference {
        DnsReference::CoreDns => (
            "1.14.6",
            "424d125775cd70fa90dfc80bf0e52cc9a9aeb574",
            "coredns_1.14.6_linux_amd64.tgz",
            "https://github.com/coredns/coredns/releases/download/v1.14.6/",
            "Apache-2.0",
        ),
        DnsReference::Bind => (
            "9.20.26",
            "7e228e3ba7c2ca945b1c2a22ed2ef0aa9d7cab10",
            "bind-9.20.26.tar.xz",
            "https://downloads.isc.org/isc/bind9/9.20.26/",
            "MPL-2.0",
        ),
    };
    assert_eq!(pin.version, version, "DNS release pin changed");
    assert_eq!(pin.source_commit, commit, "DNS source pin changed");
    assert_eq!(pin.asset, asset, "DNS asset pin changed");
    assert_eq!(pin.url, format!("{url}{asset}"), "DNS provenance changed");
    assert!(
        pin.license_review.contains(license)
            && pin.license_review.contains("independent test process"),
        "DNS license boundary changed"
    );
}

fn run_external_dns_case(case: DnsCaseSpec) {
    let deadline = CaseDeadline::start();
    let coredns = dns_reference_paths(DnsReference::CoreDns, &load_dns_pin(DnsReference::CoreDns));
    let bind = dns_reference_paths(DnsReference::Bind, &load_dns_pin(DnsReference::Bind));
    let directory = tempfile::tempdir().expect("isolated DNS interop directory");
    let mut upstream = ReservedEndpoint::new();
    let mut dns_proxy = ReservedEndpoint::new();
    let mut socks = ReservedEndpoint::new();
    let mut shadowsocks = ReservedEndpoint::new();
    let upstream_address = upstream.address;
    let dns_address = dns_proxy.address;
    let socks_address = socks.address;
    let shadowsocks_address = shadowsocks.address;
    let large = "x".repeat(240);
    let zone = format!(
        concat!(
            "$ORIGIN qualification.test.\n",
            "@ 60 IN SOA ns hostmaster 1 60 60 60 60\n",
            "@ 60 IN NS ns\n",
            "ns 60 IN A 127.0.0.1\n",
            "answer 60 IN A 192.0.2.80\n",
            "answer 60 IN AAAA 2001:db8::80\n",
            "server-answer 60 IN A 127.0.0.1\n",
            "nodata 60 IN TXT \"present-without-address\"\n",
            "large 60 IN TXT \"{0}\" \"{0}\" \"{0}\"\n",
        ),
        large
    );
    let zone_path = write_config(directory.path(), "qualification.zone", &zone);
    let tls = matches!(
        case.upstream,
        DnsUpstreamTransport::Dot | DnsUpstreamTransport::Doh
    )
    .then(|| prepare_coredns_tls(directory.path(), deadline));
    let scheme = match case.upstream {
        DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => "",
        DnsUpstreamTransport::Dot => "tls://",
        DnsUpstreamTransport::Doh => "https://",
    };
    let tls_line = tls
        .as_ref()
        .map(|(cert, key)| format!("  tls {} {}\n", path_text(cert), path_text(key)))
        .unwrap_or_default();
    let corefile = format!(
        "{scheme}qualification.test.:{} {{\n  bind 127.0.0.1\n{tls_line}  file {} qualification.test.\n  errors\n}}\n",
        upstream_address.port(),
        path_text(&zone_path),
    );
    let corefile_path = write_config(directory.path(), "Corefile", &corefile);
    upstream.release();
    let mut command = Command::new(&coredns.binary);
    command.args(["-conf", path_text(&corefile_path)]);
    let mut coredns_process = ProcessGuard::spawn("pinned CoreDNS", &mut command, deadline);
    wait_for_stable_child(&mut coredns_process, deadline, "pinned CoreDNS");

    let mut server_process = None;
    if case.path == DnsPath::Detoured {
        let server_config = format!(
            "schema_version = 1\n[server]\nlisten = \"{shadowsocks_address}\"\n\
             [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n[udp]\n",
            Method::Aes128Gcm.canonical_name(),
            Method::Aes128Gcm.synthetic_psk(),
        );
        let server_path = write_config(directory.path(), "ferrum-server.toml", &server_config);
        shadowsocks.release();
        let mut command = Command::new(ferrum_binary("ferrum2-server"));
        command.args(["--config", path_text(&server_path)]);
        let mut process = ProcessGuard::spawn("ferrum DNS detour server", &mut command, deadline);
        wait_for_tcp_listener(
            &mut process,
            shadowsocks_address,
            deadline,
            "ferrum DNS detour server",
        );
        server_process = Some(process);
    }

    let transport = match case.upstream {
        DnsUpstreamTransport::Udp => "udp",
        DnsUpstreamTransport::Tcp => "tcp",
        DnsUpstreamTransport::Dot => "dot",
        DnsUpstreamTransport::Doh => "doh",
    };
    let encryption = match case.upstream {
        DnsUpstreamTransport::Dot => "server_name = \"resolver.test\"\n",
        DnsUpstreamTransport::Doh => "server_name = \"resolver.test\"\npath = \"/dns-query\"\n",
        DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => "",
    };
    let detour = if case.path == DnsPath::Detoured {
        "detour = \"dns-hop\"\n"
    } else {
        ""
    };
    let client_config = format!(
        "schema_version = 1\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{socks_address}\"\n\
         [[outbounds]]\ntag = \"dns-hop\"\nserver = \"{shadowsocks_address}\"\n\
         [route]\nfinal = \"dns-hop\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = 4\n\
         [[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"{dns_address}\"\n\
         [[dns.servers]]\ntag = \"core\"\ntransport = \"{transport}\"\naddress = \"{upstream_address}\"\n\
         {encryption}{detour}\
         [dns.route]\nfinal = \"core\"\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n[udp]\n",
        Method::Aes128Gcm.canonical_name(),
        Method::Aes128Gcm.synthetic_psk(),
    );
    let client_path = write_config(directory.path(), "ferrum-client.toml", &client_config);
    dns_proxy.release();
    socks.release();
    let mut command = Command::new(ferrum_binary("ferrum2-client"));
    command.args(["--config", path_text(&client_path)]);
    let mut client = ProcessGuard::spawn("ferrum DNS qualification client", &mut command, deadline);
    wait_for_tcp_listener(
        &mut client,
        dns_address,
        deadline,
        "ferrum DNS qualification client",
    );

    let tcp = case.bind_tcp;
    let query = |name: &str, record: &str, short: bool| {
        let mut command = Command::new(&bind.binary);
        let server_arg = format!("@{}", dns_address.ip());
        let port_arg = dns_address.port().to_string();
        command.args([
            server_arg.as_str(),
            "-p",
            port_arg.as_str(),
            name,
            record,
            "+time=2",
            "+tries=1",
        ]);
        if tcp {
            command.arg("+tcp");
        }
        if short {
            command.arg("+short");
        } else {
            command.args(["+noall", "+comments", "+answer"]);
        }
        run_dns_probe(&mut command, deadline, "bounded BIND query")
    };
    assert_eq!(
        query("answer.qualification.test.", "A", true).trim(),
        "192.0.2.80"
    );
    assert_eq!(
        query("answer.qualification.test.", "AAAA", true).trim(),
        "2001:db8::80"
    );
    assert!(query("missing.qualification.test.", "A", false).contains("status: NXDOMAIN"));
    let nodata = query("nodata.qualification.test.", "A", false);
    assert!(nodata.contains("status: NOERROR") && !nodata.contains(" IN A "));

    let mut server_target_sentinel = None;
    if case.reference == DnsReference::CoreDns
        && case.upstream == DnsUpstreamTransport::Dot
        && case.path == DnsPath::Direct
    {
        let (process, target) = start_server_resolution_witness(
            directory.path(),
            upstream_address,
            shadowsocks_address,
            socks_address,
            &mut shadowsocks,
            deadline,
        );
        server_process = Some(process);
        server_target_sentinel = Some(target);
    }

    if case.reference == DnsReference::Bind {
        let mut command = Command::new(&bind.binary);
        let server_arg = format!("@{}", dns_address.ip());
        let port_arg = dns_address.port().to_string();
        command.args([
            server_arg.as_str(),
            "-p",
            port_arg.as_str(),
            "large.qualification.test.",
            "TXT",
            "+bufsize=512",
            "+time=2",
            "+tries=1",
            "+noall",
            "+comments",
            "+answer",
        ]);
        if case.bind_tcp {
            command.arg("+tcp");
        } else {
            command.arg("+ignore");
        }
        let output = run_dns_probe(&mut command, deadline, "bounded BIND EDNS query");
        if case.bind_tcp {
            assert!(output.contains(&large));
        } else {
            assert!(output.contains(" flags: qr aa tc"));
        }
    }

    let mut earlier_client_stderr = String::new();
    if matches!(
        case.upstream,
        DnsUpstreamTransport::Dot | DnsUpstreamTransport::Doh
    ) {
        let (_, _, stderr) = client.terminate_captures(deadline);
        earlier_client_stderr = sanitize_capture(stderr);
        drop(UdpSocket::bind(dns_address).expect("encrypted-cycle DNS UDP rebind"));
        drop(TcpListener::bind(dns_address).expect("encrypted-cycle DNS TCP rebind"));
        drop(UdpSocket::bind(socks_address).expect("encrypted-cycle SOCKS UDP rebind"));
        drop(TcpListener::bind(socks_address).expect("encrypted-cycle SOCKS TCP rebind"));
        let negative_config = match case.upstream {
            DnsUpstreamTransport::Dot => client_config.replace(
                "server_name = \"resolver.test\"",
                "server_name = \"wrong.test\"",
            ),
            DnsUpstreamTransport::Doh => {
                client_config.replace("path = \"/dns-query\"", "path = \"/wrong\"")
            }
            DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => unreachable!(),
        };
        let negative_path = write_config(
            directory.path(),
            "ferrum-client-negative.toml",
            &negative_config,
        );
        let mut command = Command::new(ferrum_binary("ferrum2-client"));
        command.args(["--config", path_text(&negative_path)]);
        client = ProcessGuard::spawn("ferrum DNS negative client", &mut command, deadline);
        wait_for_tcp_listener(
            &mut client,
            dns_address,
            deadline,
            "ferrum DNS negative client",
        );
        assert!(
            query("answer.qualification.test.", "A", false).contains("status: SERVFAIL"),
            "encrypted DNS negative did not fail closed"
        );
    }

    let mut earlier_server_stderr = String::new();
    if case.path == DnsPath::Detoured
        && matches!(
            case.upstream,
            DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp
        )
    {
        let mut server = server_process.take().expect("detoured server owner");
        let (_, _, stderr) = server.terminate_captures(deadline);
        earlier_server_stderr = sanitize_capture(stderr);
        assert!(
            query("answer.qualification.test.", "A", false).contains("status: SERVFAIL"),
            "detour failure retried or fell back"
        );
    }

    let (_, _, client_stderr) = client.terminate_captures(deadline);
    let client_stderr = earlier_client_stderr + &sanitize_capture(client_stderr);
    let server_stderr = server_process
        .as_mut()
        .map(|server| {
            let (_, _, stderr) = server.terminate_captures(deadline);
            sanitize_capture(stderr)
        })
        .unwrap_or(earlier_server_stderr);
    let (_, _, coredns_stderr) = coredns_process.terminate_captures(deadline);
    let coredns_stderr = sanitize_capture(coredns_stderr);
    drop(shadowsocks);
    let addresses = [
        upstream_address.to_string(),
        dns_address.to_string(),
        socks_address.to_string(),
        shadowsocks_address.to_string(),
    ];
    for sentinel in [
        "qualification.test",
        "resolver.test",
        "dns-hop",
        "dns-in",
        "server-dns-direct",
        "server-app-direct",
    ]
    .into_iter()
    .chain(addresses.iter().map(String::as_str))
    .chain(server_target_sentinel.iter().map(String::as_str))
    {
        assert!(
            !client_stderr.contains(sentinel)
                && !server_stderr.contains(sentinel)
                && !coredns_stderr.contains(sentinel),
            "DNS child stderr leaked a sentinel"
        );
    }
    for address in [
        upstream_address,
        dns_address,
        socks_address,
        shadowsocks_address,
    ] {
        drop(UdpSocket::bind(address).expect("DNS qualification UDP rebind"));
        drop(TcpListener::bind(address).expect("DNS qualification TCP rebind"));
    }
    directory.close().expect("close DNS interop directory");
}

fn start_server_resolution_witness(
    directory: &Path,
    upstream: SocketAddrV4,
    shadowsocks: SocketAddrV4,
    socks: SocketAddrV4,
    shadowsocks_reservation: &mut ReservedEndpoint,
    deadline: CaseDeadline,
) -> (ProcessGuard, String) {
    let mut target = ReservedEndpoint::new();
    let target_address = target.address;
    let trace = Arc::new(Mutex::new(TcpExchangeState::default()));
    let (target_process, target_shutdown) = TcpTarget::start(
        target.tcp.take().expect("server witness TCP target"),
        deadline,
        Arc::clone(&trace),
    );
    let config = format!(
        "schema_version = 1\n\
         [[inbounds]]\ntag = \"server-in\"\nlisten = \"{shadowsocks}\"\n\
         [[outbounds]]\ntag = \"server-app-direct\"\n\
         [[outbounds]]\ntag = \"server-dns-direct\"\n\
         [route]\nfinal = \"server-app-direct\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = 4\n\
         [[dns.servers]]\ntag = \"core\"\ntransport = \"dot\"\naddress = \"{upstream}\"\n\
         server_name = \"resolver.test\"\ndetour = \"server-dns-direct\"\n\
         [dns.route]\nfinal = \"core\"\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n",
        Method::Aes128Gcm.canonical_name(),
        Method::Aes128Gcm.synthetic_psk(),
    );
    let config = write_config(directory, "ferrum-server-resolution.toml", &config);
    shadowsocks_reservation.release();
    let mut command = Command::new(ferrum_binary("ferrum2-server"));
    command.args(["--config", path_text(&config)]);
    let mut server =
        ProcessGuard::spawn("ferrum encrypted resolver server", &mut command, deadline);
    wait_for_tcp_listener(
        &mut server,
        shadowsocks,
        deadline,
        "ferrum encrypted resolver server",
    );
    exercise_socks_domain_tcp(
        socks,
        "server-answer.qualification.test.",
        target_address,
        deadline,
        &trace,
        target_shutdown,
    );
    let target_evidence = target_process.finish(deadline);
    assert!(
        target_evidence.contains("clean_eof=true"),
        "server resolution target evidence"
    );
    assert!(
        trace.lock().expect("server witness trace lock").success(),
        "server resolution exchange order is incomplete"
    );
    drop(target.udp.take().expect("server witness UDP reservation"));
    drop(UdpSocket::bind(target_address).expect("server witness target UDP rebind"));
    drop(TcpListener::bind(target_address).expect("server witness target TCP rebind"));
    (server, target_address.to_string())
}

fn prepare_coredns_tls(directory: &Path, deadline: CaseDeadline) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let fixtures = root.join("crates/ferrum2-dns/tests/fixtures");
    let certificate = directory.join("resolver.pem");
    let key = directory.join("resolver-key.pem");
    let mut command = Command::new("openssl");
    command.args([
        "x509",
        "-inform",
        "DER",
        "-in",
        path_text(&fixtures.join("m12-resolver-test.der")),
        "-out",
        path_text(&certificate),
    ]);
    let _ = run_dns_probe(&mut command, deadline, "certificate conversion");
    let mut command = Command::new("openssl");
    command.args([
        "pkey",
        "-inform",
        "DER",
        "-in",
        path_text(&fixtures.join("m12-resolver-test.pk8")),
        "-out",
        path_text(&key),
    ]);
    let _ = run_dns_probe(&mut command, deadline, "private-key conversion");
    (certificate, key)
}

fn run_dns_probe(command: &mut Command, deadline: CaseDeadline, label: &'static str) -> String {
    let mut process = ProcessGuard::spawn(label, command, deadline);
    let status = process.wait_for_exit(deadline, label);
    let (stdout, stderr) = process.finish_captures(deadline);
    if !status.success() || stdout.truncated || stderr.truncated || !stderr.bytes.is_empty() {
        panic!(
            "DNS probe failed: status={status}, stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        );
    }
    String::from_utf8(stdout.bytes).expect("DNS probe output must be UTF-8")
}

fn verify_pin(reference: Reference, pin: &Pin) {
    let (version, commit, asset, url_prefix, license_marker) = match reference {
        Reference::SingBox => (
            "1.13.14",
            "25a600db24f7680ad9806ce5427bd0ab8afe1114",
            "sing-box-1.13.14-linux-amd64-glibc.tar.gz",
            "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/",
            "NOASSERTION",
        ),
        Reference::ShadowsocksRust => (
            "1.24.0",
            "7ee1aa9223ed8f4d34734aac919036c8ad4502c2",
            "shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz",
            "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/",
            "MIT",
        ),
    };
    assert_eq!(pin.version, version, "reference release pin changed");
    assert_eq!(pin.source_commit, commit, "reference source pin changed");
    assert_eq!(pin.asset, asset, "reference host asset pin changed");
    assert!(
        pin.url.starts_with(url_prefix) && pin.url.ends_with(asset),
        "reference release provenance URL changed"
    );
    assert!(
        pin.license_review.contains(license_marker)
            && pin.license_review.contains("independent test process"),
        "reference license boundary changed"
    );
    assert!(
        pin.sha256.len() == 64
            && pin
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "reference SHA-256 pin is malformed"
    );
}

fn verify_reviewed_license(path: &Path) {
    let metadata = fs::metadata(path).expect("reviewed license metadata");
    assert!(
        metadata.is_file() && (1..=256 * 1024).contains(&metadata.len()),
        "reviewed license file bounds invalid"
    );
    let contents = fs::read(path).expect("read reviewed license file");
    assert!(!contents.is_empty(), "reviewed license file is empty");
}

fn verify_transport_configs(reference: Reference, paths: &ReferencePaths, deadline: CaseDeadline) {
    let directory = tempfile::tempdir().expect("isolated transport config verification directory");
    for transport in [Transport::Tcp, Transport::Udp] {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let mut ports = ReservedPorts::new();
            let server = ports.shadowsocks_address();
            let proxy = ports.proxy_address();
            let server_config = reference_server_config(method, reference, server, transport);
            assert_transport_config(&server_config, reference, transport);
            let server_path = write_config(directory.path(), "server.json", &server_config);
            ports.release_shadowsocks();
            run_config_check(reference, &paths.server, &server_path, deadline);

            let client_config =
                reference_client_config(method, reference, server, proxy, transport);
            assert_transport_config(&client_config, reference, transport);
            let client_path = write_config(directory.path(), "client.json", &client_config);
            ports.release_proxy();
            run_config_check(
                reference,
                paths.client.as_ref().unwrap_or(&paths.server),
                &client_path,
                deadline,
            );
        }
    }
    directory
        .close()
        .expect("close isolated transport config verification directory");
}

fn assert_transport_config(config: &str, reference: Reference, transport: Transport) {
    let marker = match (reference, transport) {
        (Reference::SingBox, Transport::Tcp) => "\"network\":\"tcp\"",
        (Reference::SingBox, Transport::Udp) => "\"network\":\"udp\"",
        (Reference::ShadowsocksRust, Transport::Tcp) => "\"mode\":\"tcp_only\"",
        (Reference::ShadowsocksRust, Transport::Udp) => "\"mode\":\"udp_only\"",
    };
    assert!(
        config.contains(marker)
            || (reference == Reference::ShadowsocksRust
                && transport == Transport::Udp
                && config.contains("\"mode\":\"tcp_and_udp\"")),
        "reference configuration is not explicitly transport-enabled"
    );
}

fn run_config_check(reference: Reference, binary: &Path, config: &Path, deadline: CaseDeadline) {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.args(["check", "-c", path_text(config)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-c", path_text(config)]);
        }
    }
    let mut process = ProcessGuard::spawn("reference config check", &mut command, deadline);
    match reference {
        Reference::SingBox => {
            let status = process.wait_for_exit(deadline, "bounded reference config check");
            let (stdout, stderr) = process.finish_captures(deadline);
            assert!(
                status.success() && !stdout.truncated && !stderr.truncated,
                "reference config check failed: status={status}, stdout={}, stderr={}",
                sanitize_capture(stdout),
                sanitize_capture(stderr)
            );
        }
        Reference::ShadowsocksRust => {
            wait_for_stable_child(&mut process, deadline, "reference config check");
            let _ = process.terminate(deadline);
        }
    }
}

fn run_case(case: CaseSpec) {
    let deadline = CaseDeadline::start();
    let pin = load_pin(case.reference);
    let paths = reference_paths(case.reference, &pin);
    let reference_binary = match case.direction {
        Direction::FerrumClient => &paths.server,
        Direction::ReferenceClient => paths.client.as_ref().unwrap_or(&paths.server),
    };
    let directory = tempfile::tempdir().expect("isolated interop directory");
    let directory_path = directory.path().to_path_buf();
    let mut ports = ReservedPorts::new();
    let target = ports.target_address();
    let proxy = ports.proxy_address();
    let shadowsocks = ports.shadowsocks_address();
    let (config_checksum, process_evidence, target_evidence) = match case.transport {
        Transport::Tcp => run_tcp_transport(
            case,
            reference_binary,
            directory.path(),
            &mut ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
        Transport::Udp => run_udp_transport(
            case,
            reference_binary,
            directory.path(),
            &mut ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
    };
    drop(ports);
    directory
        .close()
        .unwrap_or_else(|error| panic!("explicit temporary directory close: {error}"));
    assert!(
        !directory_path.exists(),
        "temporary interop directory remains"
    );
    deadline.check("final interop evidence");
    eprintln!(
        "{} interop evidence: case_id={}, method={}, reference={:?}, direction={:?}, \
         asset_sha256={}, config_sha256={config_checksum}, command_category=black-box-process, \
         process={process_evidence}, target={target_evidence}, result=success",
        case.transport.label(),
        case.id,
        case.method.canonical_name(),
        case.reference,
        case.direction,
        pin.sha256
    );
}

#[allow(clippy::too_many_arguments)]
fn run_tcp_transport(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String, String) {
    let trace = Arc::new(Mutex::new(TcpExchangeState::default()));
    let (target_process, target_shutdown) =
        TcpTarget::start(ports.take_target_tcp(), deadline, Arc::clone(&trace));
    let (config_checksum, process_evidence) = run_tcp_processes(
        case,
        reference_binary,
        directory,
        ports,
        shadowsocks,
        proxy,
        target,
        deadline,
        &trace,
        target_shutdown,
    );

    let target_evidence = target_process.finish(deadline);
    assert!(
        trace.lock().expect("TCP exchange trace lock").success(),
        "TCP exchange order is incomplete"
    );
    (config_checksum, process_evidence, target_evidence)
}

#[allow(clippy::too_many_arguments)]
fn run_tcp_processes(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) -> (String, String) {
    let config = match case.direction {
        Direction::FerrumClient => {
            reference_server_config(case.method, case.reference, shadowsocks, Transport::Tcp)
        }
        Direction::ReferenceClient => reference_client_config(
            case.method,
            case.reference,
            shadowsocks,
            proxy,
            Transport::Tcp,
        ),
    };
    let config_path = write_config(directory, "reference-tcp.json", &config);
    let ferrum_config = match case.direction {
        Direction::FerrumClient => format!(
            "schema_version = 1\n\n[client]\nlisten = \"{proxy}\"\nserver = \"{shadowsocks}\"\n\n\
             [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n",
            case.method.canonical_name(),
            case.method.synthetic_psk()
        ),
        Direction::ReferenceClient => format!(
            "schema_version = 1\n\n[server]\nlisten = \"{shadowsocks}\"\n\n\
             [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n",
            case.method.canonical_name(),
            case.method.synthetic_psk()
        ),
    };
    let (ferrum_name, ferrum_listen) = match case.direction {
        Direction::FerrumClient => ("ferrum2-client", proxy),
        Direction::ReferenceClient => ("ferrum2-server", shadowsocks),
    };
    let ferrum_path = write_config(directory, "ferrum-tcp.toml", &ferrum_config);
    ports.release_shadowsocks();
    ports.release_proxy();
    let mut ferrum_command = Command::new(ferrum_binary(ferrum_name));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum = ProcessGuard::spawn("ferrum TCP process", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, ferrum_listen, deadline, "ferrum TCP listener");
    let mut reference_command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference =
        ProcessGuard::spawn("reference TCP process", &mut reference_command, deadline);
    let reference_listen = match case.direction {
        Direction::FerrumClient => shadowsocks,
        Direction::ReferenceClient => proxy,
    };
    wait_for_tcp_listener(
        &mut reference,
        reference_listen,
        deadline,
        "reference TCP listener",
    );
    exercise_socks_tcp(proxy, target, deadline, trace, target_shutdown);
    let reference_evidence = reference.terminate(deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

fn exercise_socks_tcp(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    exercise_socks_tcp_request(proxy, &request, deadline, trace, target_shutdown);
}

fn exercise_socks_domain_tcp(
    proxy: SocketAddrV4,
    name: &str,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let length = u8::try_from(name.len()).expect("SOCKS domain length");
    let mut request = vec![5, 1, 0, 3, length];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&target.port().to_be_bytes());
    exercise_socks_tcp_request(proxy, &request, deadline, trace, target_shutdown);
}

fn exercise_socks_tcp_request(
    proxy: SocketAddrV4,
    request: &[u8],
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let mut stream = TcpStream::connect_timeout(
        &proxy.into(),
        deadline.bounded(IO_TIMEOUT, "connect SOCKS TCP"),
    )
    .expect("connect SOCKS TCP");
    set_stream_deadlines(&stream, deadline);
    write_all_case(&mut stream, &[5, 1, 0], deadline, "SOCKS TCP greeting");
    let mut method = [0_u8; 2];
    read_exact_case(&mut stream, &mut method, deadline, "SOCKS TCP method");
    assert_eq!(method, [5, 0], "SOCKS TCP no-auth selected");

    write_all_case(&mut stream, request, deadline, "SOCKS TCP connect request");
    let mut reply = [0_u8; 10];
    read_exact_case(&mut stream, &mut reply, deadline, "SOCKS TCP connect reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "SOCKS TCP connect failed");

    let forward = tcp_forward_payload();
    write_all_case(&mut stream, &forward, deadline, "TCP forward payload");
    let reverse = tcp_reverse_payload();
    let mut received = vec![0_u8; reverse.len()];
    read_exact_case(&mut stream, &mut received, deadline, "TCP reverse payload");
    assert_eq!(received, reverse, "TCP reverse payload mismatch");
    record_tcp_event(trace, TcpExchangeEvent::ReverseMatched);
    // Commit the application event before the target can record the resulting EOF.
    let application_shutdown = {
        let mut exchange = trace.lock().expect("TCP exchange trace lock");
        stream
            .shutdown(Shutdown::Write)
            .expect("application TCP write half-close");
        exchange.record(TcpExchangeEvent::ApplicationShutdown)
    };
    application_shutdown
        .unwrap_or_else(|error| panic!("{error}: {:?}", TcpExchangeEvent::ApplicationShutdown));
    let application_acknowledgement = target_shutdown
        .wait(deadline.remaining("TCP target shutdown synchronization"))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut extra = [0_u8; 1];
    assert_eq!(
        read_case(
            &mut stream,
            &mut extra,
            deadline,
            "TCP application clean EOF"
        ),
        0,
        "TCP application expected clean EOF"
    );
    record_tcp_event(trace, TcpExchangeEvent::ApplicationCleanEof);
    application_acknowledgement
        .send(Ok(()))
        .unwrap_or_else(|error| panic!("{error}"));
}

fn record_tcp_event(trace: &Arc<Mutex<TcpExchangeState>>, event: TcpExchangeEvent) {
    let result = trace.lock().expect("TCP exchange trace lock").record(event);
    result.unwrap_or_else(|error| panic!("{error}: {event:?}"));
}

fn tcp_forward_payload() -> Vec<u8> {
    let mut payload = vec![0x49];
    payload.extend(std::iter::repeat_n(0x5a, 16_385));
    payload
}

fn tcp_reverse_payload() -> Vec<u8> {
    let mut payload = vec![0xa6];
    payload.extend((0..16_385).map(|index| (index % 251) as u8));
    payload
}

fn write_all_case(stream: &mut TcpStream, mut bytes: &[u8], deadline: CaseDeadline, label: &str) {
    while !bytes.is_empty() {
        deadline.check(label);
        set_stream_deadlines(stream, deadline);
        let written = stream
            .write(bytes)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_ne!(written, 0, "{label}: write zero");
        bytes = &bytes[written..];
    }
}

fn read_exact_case(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: CaseDeadline,
    label: &str,
) {
    while !bytes.is_empty() {
        let read = read_case(stream, bytes, deadline, label);
        assert_ne!(read, 0, "{label}: premature EOF");
        bytes = &mut bytes[read..];
    }
}

fn read_case(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: CaseDeadline,
    label: &str,
) -> usize {
    deadline.check(label);
    set_stream_deadlines(stream, deadline);
    stream
        .read(bytes)
        .unwrap_or_else(|error| panic!("{label}: {error}"))
}

struct TcpTarget(CancellableWorker<Result<String, String>>);

impl TcpTarget {
    fn start(
        listener: TcpListener,
        deadline: CaseDeadline,
        trace: Arc<Mutex<TcpExchangeState>>,
    ) -> (Self, TcpApplicationGate) {
        listener
            .set_nonblocking(true)
            .expect("set TCP target listener nonblocking");
        let (target_gate, application_gate) = tcp_shutdown_gate();
        let worker = CancellableWorker::spawn(move |cancelled| {
            let (stream, evidence) = target_gate.finish(
                run_tcp_target(listener, deadline, &cancelled, &trace),
                deadline.remaining("TCP application acknowledgement"),
            )?;
            drop(stream);
            Ok(evidence)
        });
        (Self(worker), application_gate)
    }

    fn finish(self, deadline: CaseDeadline) -> String {
        self.0
            .finish(deadline, "TCP target completion")
            .unwrap_or_else(|error| panic!("TCP target failed: {error}"))
    }
}

fn run_tcp_target(
    listener: TcpListener,
    deadline: CaseDeadline,
    cancelled: &AtomicBool,
    trace: &Arc<Mutex<TcpExchangeState>>,
) -> Result<(TcpStream, String), String> {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, "TCP target accept");
    let mut stream = loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err("TCP target cancelled".to_owned());
        }
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                deadline.check("TCP target accept");
                if Instant::now() >= readiness_end {
                    return Err("TCP target accept deadline exceeded".to_owned());
                }
                thread::sleep(POLL_INTERVAL.min(deadline.remaining("TCP target accept")));
            }
            Err(error) => return Err(format!("TCP target accept failed: {error}")),
        }
    };
    let forward = tcp_forward_payload();
    let mut received = vec![0_u8; forward.len()];
    read_exact_case(
        &mut stream,
        &mut received,
        deadline,
        "TCP target forward payload",
    );
    if received != forward {
        return Err("TCP target forward payload mismatch".to_owned());
    }
    record_tcp_event(trace, TcpExchangeEvent::ForwardMatched);
    let reverse = tcp_reverse_payload();
    write_all_case(
        &mut stream,
        &reverse,
        deadline,
        "TCP target reverse payload",
    );
    let mut extra = [0_u8; 1];
    if read_case(&mut stream, &mut extra, deadline, "TCP target clean EOF") != 0 {
        return Err("TCP target received bytes after expected payload".to_owned());
    }
    record_tcp_event(trace, TcpExchangeEvent::TargetCleanEof);
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("TCP target write shutdown failed: {error}"))?;
    record_tcp_event(trace, TcpExchangeEvent::TargetShutdown);
    Ok((
        stream,
        format!(
            "forward_bytes={}, reverse_bytes={}, clean_eof=true",
            forward.len(),
            reverse.len()
        ),
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_udp_transport(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String, String) {
    let echo = EchoTarget::start(ports.take_target_udp(), deadline);
    let (config_checksum, process_evidence) = match case.direction {
        Direction::FerrumClient => run_udp_ferrum_client_case(
            case,
            reference_binary,
            directory,
            ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
        Direction::ReferenceClient => run_udp_reference_client_case(
            case,
            reference_binary,
            directory,
            ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
    };
    let target_evidence = echo.finish(deadline);
    (config_checksum, process_evidence, target_evidence)
}

#[allow(clippy::too_many_arguments)]
fn run_udp_ferrum_client_case(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String) {
    let config = reference_server_config(case.method, case.reference, shadowsocks, Transport::Udp);
    let config_path = write_config(directory, "reference-server.json", &config);
    ports.release_shadowsocks();
    let mut command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference =
        ProcessGuard::spawn("reference Shadowsocks UDP server", &mut command, deadline);
    wait_for_stable_child(&mut reference, deadline, "reference Shadowsocks UDP server");

    let ferrum_config = format!(
        "schema_version = 1\n\n[client]\nlisten = \"{proxy}\"\nserver = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n\n\
         [udp]\nenabled = true\nmax_sessions = 16\nmax_buffered_bytes = 1048576\n\
         idle_timeout_ms = 60000\n",
        case.method.canonical_name(),
        case.method.synthetic_psk()
    );
    let ferrum_path = write_config(directory, "ferrum-client.toml", &ferrum_config);
    ports.release_proxy();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-client"));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum =
        ProcessGuard::spawn("ferrum composed UDP client", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, proxy, deadline, "ferrum composed client");
    exercise_socks_udp(&mut ferrum, proxy, target, case.method, deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    let reference_evidence = reference.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_udp_reference_client_case(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String) {
    let ferrum_config = format!(
        "schema_version = 1\n\n[server]\nlisten = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n\n\
         [udp]\nenabled = true\nmax_sessions = 16\nmax_buffered_bytes = 1048576\n\
         idle_timeout_ms = 60000\n",
        case.method.canonical_name(),
        case.method.synthetic_psk()
    );
    let ferrum_path = write_config(directory, "ferrum-server.toml", &ferrum_config);
    ports.release_shadowsocks();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-server"));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum =
        ProcessGuard::spawn("ferrum composed UDP server", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, shadowsocks, deadline, "ferrum composed server");

    let config = reference_client_config(
        case.method,
        case.reference,
        shadowsocks,
        proxy,
        Transport::Udp,
    );
    let config_path = write_config(directory, "reference-client.json", &config);
    ports.release_proxy();
    let mut command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference = ProcessGuard::spawn("reference SOCKS UDP client", &mut command, deadline);
    exercise_socks_udp(&mut reference, proxy, target, case.method, deadline);
    let reference_evidence = reference.terminate(deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

fn wait_for_stable_child(child: &mut ProcessGuard, deadline: CaseDeadline, label: &'static str) {
    let readiness_end =
        Instant::now() + deadline.bounded(Duration::from_millis(500), "UDP readiness");
    while Instant::now() < readiness_end {
        child.assert_running(deadline, label);
        thread::sleep(POLL_INTERVAL.min(deadline.remaining(label)));
    }
}

fn wait_for_tcp_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    deadline: CaseDeadline,
    label: &str,
) {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, label);
    loop {
        child.assert_running(deadline, label);
        if TcpStream::connect_timeout(
            &address.into(),
            deadline.bounded(Duration::from_millis(200), label),
        )
        .is_ok()
        {
            return;
        }
        assert!(
            Instant::now() < readiness_end,
            "{label}: readiness deadline exceeded"
        );
        thread::sleep(POLL_INTERVAL.min(deadline.remaining(label)));
    }
}

fn exercise_socks_udp(
    child: &mut ProcessGuard,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    method: Method,
    deadline: CaseDeadline,
) {
    let (mut control, relay) = open_socks_udp_association(child, proxy, deadline);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind SOCKS UDP application socket");
    socket
        .set_read_timeout(Some(deadline.bounded(IO_TIMEOUT, "SOCKS UDP receive")))
        .expect("set SOCKS UDP read timeout");
    socket
        .set_write_timeout(Some(deadline.bounded(IO_TIMEOUT, "SOCKS UDP send")))
        .expect("set SOCKS UDP write timeout");
    socket.connect(relay).expect("connect SOCKS UDP relay");

    for sequence in 0..SESSION_DATAGRAMS {
        let payload = case_payload(method, sequence);
        let packet = encode_socks_udp(target, &payload);
        assert_eq!(
            socket.send(&packet).expect("send SOCKS UDP request"),
            packet.len(),
            "SOCKS UDP request short send"
        );
        let mut response = [0_u8; MAX_UDP_DATAGRAM];
        let received = socket
            .recv(&mut response)
            .expect("receive SOCKS UDP response");
        let (source, echoed) = decode_socks_udp(&response[..received]);
        assert_eq!(source, target, "SOCKS UDP observed source address mismatch");
        assert_eq!(echoed, payload, "SOCKS UDP payload mismatch");
        child.assert_running(deadline, "SOCKS UDP session traffic");
    }
    control
        .set_read_timeout(Some(Duration::from_millis(1)))
        .expect("set SOCKS control probe timeout");
    let mut unexpected = [0_u8; 1];
    match control.read(&mut unexpected) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => panic!("SOCKS UDP control channel closed during the session"),
        Ok(_) => panic!("SOCKS UDP control channel emitted unexpected bytes"),
        Err(error) => panic!("SOCKS UDP control channel failed: {error}"),
    }
}

fn open_socks_udp_association(
    child: &mut ProcessGuard,
    proxy: SocketAddrV4,
    deadline: CaseDeadline,
) -> (TcpStream, SocketAddr) {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, "SOCKS UDP readiness");
    loop {
        child.assert_running(deadline, "SOCKS UDP readiness");
        if let Ok(mut control) = TcpStream::connect_timeout(
            &proxy.into(),
            deadline.bounded(Duration::from_millis(200), "SOCKS UDP connect"),
        ) {
            set_stream_deadlines(&control, deadline);
            if control.write_all(&[5, 1, 0]).is_ok() {
                let mut method = [0_u8; 2];
                if control.read_exact(&mut method).is_ok() && method == [5, 0] {
                    control
                        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                        .expect("send SOCKS UDP ASSOCIATE");
                    let relay = read_socks_reply(&mut control, proxy);
                    return (control, relay);
                }
            }
        }
        assert!(
            Instant::now() < readiness_end,
            "SOCKS UDP readiness deadline exceeded"
        );
        thread::sleep(POLL_INTERVAL.min(deadline.remaining("SOCKS UDP readiness")));
    }
}

fn set_stream_deadlines(stream: &TcpStream, deadline: CaseDeadline) {
    let timeout = deadline.bounded(IO_TIMEOUT, "SOCKS control I/O");
    stream
        .set_read_timeout(Some(timeout))
        .expect("set SOCKS control read timeout");
    stream
        .set_write_timeout(Some(timeout))
        .expect("set SOCKS control write timeout");
}

fn read_socks_reply(stream: &mut TcpStream, proxy: SocketAddrV4) -> SocketAddr {
    let mut fixed = [0_u8; 4];
    stream
        .read_exact(&mut fixed)
        .expect("read SOCKS UDP ASSOCIATE reply");
    assert_eq!(&fixed[..3], &[5, 0, 0], "SOCKS UDP ASSOCIATE failed");
    let mut address = read_socks_address(stream, fixed[3]);
    if address.ip().is_unspecified() {
        address.set_ip(IpAddr::V4(*proxy.ip()));
    }
    address
}

fn read_socks_address(reader: &mut impl Read, atyp: u8) -> SocketAddr {
    let ip = match atyp {
        1 => {
            let mut bytes = [0_u8; 4];
            reader.read_exact(&mut bytes).expect("read SOCKS IPv4");
            IpAddr::V4(bytes.into())
        }
        4 => {
            let mut bytes = [0_u8; 16];
            reader.read_exact(&mut bytes).expect("read SOCKS IPv6");
            IpAddr::V6(bytes.into())
        }
        3 => {
            let mut length = [0_u8; 1];
            reader
                .read_exact(&mut length)
                .expect("read SOCKS domain length");
            let mut domain = vec![0_u8; usize::from(length[0])];
            reader.read_exact(&mut domain).expect("read SOCKS domain");
            panic!("SOCKS relay returned a domain instead of an IP address");
        }
        _ => panic!("SOCKS relay returned an unsupported address type"),
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port).expect("read SOCKS port");
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

fn encode_socks_udp(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn decode_socks_udp(packet: &[u8]) -> (SocketAddrV4, &[u8]) {
    assert!(packet.len() >= 10, "SOCKS UDP response is truncated");
    assert_eq!(&packet[..4], &[0, 0, 0, 1], "SOCKS UDP response header");
    let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    (SocketAddrV4::new(ip, port), &packet[10..])
}

fn case_payload(method: Method, sequence: usize) -> Vec<u8> {
    format!(
        "m2-udp-{}-datagram-{sequence}",
        match method {
            Method::Aes128Gcm => "aes128",
            Method::Aes256Gcm => "aes256",
            Method::ChaCha20Poly1305 => "chacha",
        }
    )
    .into_bytes()
}

struct EchoTarget(CancellableWorker<Result<Vec<Vec<u8>>, String>>);

impl EchoTarget {
    fn start(socket: UdpSocket, deadline: CaseDeadline) -> Self {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set echo target read timeout");
        socket
            .set_write_timeout(Some(deadline.bounded(IO_TIMEOUT, "echo target send")))
            .expect("set echo target write timeout");
        Self(CancellableWorker::spawn(move |cancelled| {
            let mut received_payloads = Vec::with_capacity(SESSION_DATAGRAMS);
            let mut buffer = [0_u8; MAX_UDP_DATAGRAM];
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    break Err("echo target cancelled".to_owned());
                }
                if received_payloads.len() == SESSION_DATAGRAMS {
                    break Ok(received_payloads);
                }
                match socket.recv_from(&mut buffer) {
                    Ok((received, peer)) => {
                        let payload = buffer[..received].to_vec();
                        match socket.send_to(&payload, peer) {
                            Ok(sent) if sent == payload.len() => received_payloads.push(payload),
                            Ok(_) => break Err("echo target short send".to_owned()),
                            Err(error) => break Err(format!("echo target send failed: {error}")),
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => break Err(format!("echo target receive failed: {error}")),
                }
            }
        }))
    }

    fn finish(self, deadline: CaseDeadline) -> String {
        let payloads = self
            .0
            .finish(deadline, "echo target completion")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            payloads.len(),
            SESSION_DATAGRAMS,
            "echo target datagram count mismatch"
        );
        assert_eq!(
            payloads.iter().collect::<HashSet<_>>().len(),
            SESSION_DATAGRAMS,
            "echo target request payloads were not distinct"
        );
        "three-distinct-request-reply-datagrams".to_owned()
    }
}

struct ReservedEndpoint {
    udp: Option<UdpSocket>,
    tcp: Option<TcpListener>,
    address: SocketAddrV4,
}

impl ReservedEndpoint {
    fn new() -> Self {
        for _ in 0..32 {
            let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .expect("reserve UDP endpoint");
            let address = ipv4_address(udp.local_addr().expect("reserved UDP address"));
            if let Ok(tcp) = TcpListener::bind(address) {
                return Self {
                    udp: Some(udp),
                    tcp: Some(tcp),
                    address,
                };
            }
        }
        panic!("could not reserve paired TCP/UDP endpoint");
    }

    fn release(&mut self) {
        drop(self.udp.take().expect("release UDP reservation once"));
        drop(self.tcp.take().expect("release TCP reservation once"));
    }
}

struct ReservedPorts {
    target: ReservedEndpoint,
    proxy: ReservedEndpoint,
    shadowsocks: ReservedEndpoint,
}

impl ReservedPorts {
    fn new() -> Self {
        let ports = Self {
            target: ReservedEndpoint::new(),
            proxy: ReservedEndpoint::new(),
            shadowsocks: ReservedEndpoint::new(),
        };
        let addresses = [
            ports.target.address,
            ports.proxy.address,
            ports.shadowsocks.address,
        ];
        assert_eq!(
            addresses.iter().collect::<HashSet<_>>().len(),
            addresses.len(),
            "reserved endpoint pool must be distinct"
        );
        ports
    }

    fn target_address(&self) -> SocketAddrV4 {
        self.target.address
    }

    fn proxy_address(&self) -> SocketAddrV4 {
        self.proxy.address
    }

    fn shadowsocks_address(&self) -> SocketAddrV4 {
        self.shadowsocks.address
    }

    fn take_target_udp(&mut self) -> UdpSocket {
        drop(
            self.target
                .tcp
                .take()
                .expect("release target TCP reservation once"),
        );
        self.target
            .udp
            .take()
            .expect("release target UDP reservation to echo owner")
    }

    fn take_target_tcp(&mut self) -> TcpListener {
        drop(
            self.target
                .udp
                .take()
                .expect("release target UDP reservation once"),
        );
        self.target
            .tcp
            .take()
            .expect("release target TCP reservation to target owner")
    }

    fn release_proxy(&mut self) {
        self.proxy.release();
    }

    fn release_shadowsocks(&mut self) {
        self.shadowsocks.release();
    }
}

fn ipv4_address(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 socket returned IPv6"),
    }
}

fn reference_server_config(
    method: Method,
    reference: Reference,
    address: SocketAddrV4,
    transport: Transport,
) -> String {
    let method_name = method.canonical_name();
    let psk = method.synthetic_psk();
    let network = transport.label();
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{},\"network\":\"{network}\",\
             \"method\":\"{method_name}\",\"password\":\"{psk}\"}}],\
             \"outbounds\":[{{\"type\":\"direct\",\"tag\":\"direct\"}}],\
             \"route\":{{\"final\":\"direct\"}}}}",
            address.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{psk}\",\"method\":\"{method_name}\",\
             \"mode\":\"{}_only\"}}",
            address.port(),
            transport.label()
        ),
    }
}

fn reference_client_config(
    method: Method,
    reference: Reference,
    server: SocketAddrV4,
    proxy: SocketAddrV4,
    transport: Transport,
) -> String {
    let method_name = method.canonical_name();
    let psk = method.synthetic_psk();
    let network = transport.label();
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"socks\",\"tag\":\"socks-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{}}}],\
             \"outbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-out\",\
             \"server\":\"127.0.0.1\",\"server_port\":{},\"method\":\"{method_name}\",\
             \"password\":\"{psk}\",\"network\":\"{network}\"}}],\
             \"route\":{{\"final\":\"ss-out\"}}}}",
            proxy.port(),
            server.port()
        ),
        Reference::ShadowsocksRust => {
            let mode = if transport == Transport::Udp {
                "tcp_and_udp"
            } else {
                "tcp_only"
            };
            format!(
                "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
             \"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{psk}\",\"method\":\"{method_name}\",\
             \"mode\":\"{mode}\"}}",
                proxy.port(),
                server.port()
            )
        }
    }
}

fn reference_command(reference: Reference, binary: &Path, config: &Path) -> Command {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.args(["run", "-c", path_text(config)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-c", path_text(config)]);
        }
    }
    command
}

fn write_config(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write isolated config");
    path
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 generated path")
}

fn target_profile_directory() -> PathBuf {
    std::env::current_exe()
        .expect("qualification executable")
        .parent()
        .expect("Cargo target profile directory")
        .to_path_buf()
}

fn ferrum_binary(name: &str) -> PathBuf {
    let path = target_profile_directory().join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "required current-worktree ferrum binary is missing"
    );
    path
}

struct ReferencePaths {
    archive: PathBuf,
    extraction_root: PathBuf,
    server: PathBuf,
    client: Option<PathBuf>,
    license: Option<PathBuf>,
}

struct DnsReferencePaths {
    archive: PathBuf,
    extraction_root: PathBuf,
    binary: PathBuf,
    license: PathBuf,
}

fn dns_reference_paths(reference: DnsReference, pin: &Pin) -> DnsReferencePaths {
    let runner_temp = PathBuf::from(
        std::env::var_os("RUNNER_TEMP")
            .expect("GitHub runner did not provide the fixed RUNNER_TEMP directory"),
    );
    match reference {
        DnsReference::CoreDns => {
            let extraction_root = runner_temp.join(format!("coredns-{}", pin.version));
            DnsReferencePaths {
                archive: runner_temp.join(&pin.asset),
                binary: extraction_root.join("coredns"),
                license: extraction_root.join("LICENSE"),
                extraction_root,
            }
        }
        DnsReference::Bind => {
            let extraction_root = runner_temp.join(format!("bind-{}", pin.version));
            DnsReferencePaths {
                archive: runner_temp.join(&pin.asset),
                binary: extraction_root.join("bin/dig/dig"),
                license: extraction_root.join("LICENSE"),
                extraction_root,
            }
        }
    }
}

fn reference_paths(reference: Reference, pin: &Pin) -> ReferencePaths {
    let runner_temp = PathBuf::from(
        std::env::var_os("RUNNER_TEMP")
            .expect("GitHub runner did not provide the fixed RUNNER_TEMP directory"),
    );
    let archive = runner_temp.join(&pin.asset);
    match reference {
        Reference::SingBox => {
            let extraction_root = runner_temp.join(format!("sing-box-{}", pin.version));
            let directory =
                extraction_root.join(format!("sing-box-{}-linux-amd64-glibc", pin.version));
            let binary = directory.join("sing-box");
            ReferencePaths {
                archive,
                extraction_root,
                server: binary.clone(),
                client: Some(binary),
                license: Some(directory.join("LICENSE")),
            }
        }
        Reference::ShadowsocksRust => {
            let extraction_root = runner_temp.join(format!("shadowsocks-rust-{}", pin.version));
            ReferencePaths {
                archive,
                server: extraction_root.join("ssserver"),
                client: Some(extraction_root.join("sslocal")),
                extraction_root,
                license: None,
            }
        }
    }
}

fn verify_binary_location(binary: &Path, extraction_root: &Path) {
    assert!(
        binary.is_file(),
        "required reviewed reference executable is missing"
    );
    let canonical_root = extraction_root
        .canonicalize()
        .expect("canonical reviewed extraction root");
    let canonical_binary = binary
        .canonicalize()
        .expect("canonical reviewed reference executable");
    assert!(
        canonical_binary.starts_with(&canonical_root),
        "reference executable escaped the reviewed extraction root"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&canonical_binary)
            .expect("reference executable metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "reviewed reference file is not executable");
    }
}

fn verify_archive_members(reference: Reference, archive: &Path, pin: &Pin, deadline: CaseDeadline) {
    let mut command = Command::new("tar");
    match reference {
        Reference::SingBox => {
            command.args(["-tzf", path_text(archive)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-tJf", path_text(archive)]);
        }
    }
    let mut process = ProcessGuard::spawn("reviewed archive member probe", &mut command, deadline);
    let status = process.wait_for_exit(deadline, "bounded archive member probe");
    let (stdout, stderr) = process.finish_captures(deadline);
    assert!(
        status.success() && !stdout.truncated && !stderr.truncated && stderr.bytes.is_empty(),
        "reviewed archive member probe failed: status={status}, stdout={}, stderr={}",
        sanitize_capture(stdout),
        sanitize_capture(stderr)
    );
    let members = String::from_utf8(stdout.bytes).expect("archive member list must be UTF-8 text");
    let actual: Vec<_> = members.lines().collect();
    let sing_root = format!("sing-box-{}-linux-amd64-glibc", pin.version);
    let expected = match reference {
        Reference::SingBox => vec![
            format!("{sing_root}/"),
            format!("{sing_root}/LICENSE"),
            format!("{sing_root}/sing-box"),
        ],
        Reference::ShadowsocksRust => ["sslocal", "ssserver", "ssurl", "ssmanager", "ssservice"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
    assert_eq!(actual, expected, "archive member allowlist mismatch");
    assert!(
        actual.iter().all(|member| {
            let normalized = member.trim_end_matches('/');
            !normalized.starts_with('/')
                && !normalized.split('/').any(|component| component == "..")
                && !normalized.contains('\\')
        }),
        "archive member escaped the safe extraction allowlist"
    );
}

fn load_pin(reference: Reference) -> Pin {
    let section = match reference {
        Reference::SingBox => "sing_box",
        Reference::ShadowsocksRust => "shadowsocks_rust",
    };
    pin_from_values(load_pin_values(section))
}

fn load_dns_pin(reference: DnsReference) -> Pin {
    pin_from_values(load_pin_values(match reference {
        DnsReference::CoreDns => "coredns",
        DnsReference::Bind => "bind",
    }))
}

fn load_pin_values(section: &str) -> HashMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let text = fs::read_to_string(root.join("tests/interop/versions.toml"))
        .expect("read interop version pins");
    parse_section(&text, section)
}

fn pin_from_values(values: HashMap<String, String>) -> Pin {
    Pin {
        version: value(&values, "version").to_owned(),
        source_commit: value(&values, "source_commit").to_owned(),
        expected_version: value(&values, "expected_version").to_owned(),
        asset: value(&values, "linux_asset").to_owned(),
        url: value(&values, "linux_url").to_owned(),
        size: value(&values, "linux_size")
            .parse()
            .expect("numeric asset size"),
        sha256: value(&values, "linux_sha256").to_owned(),
        license_review: value(&values, "license_review").to_owned(),
    }
}

fn panic_diagnostic(payload: Box<dyn std::any::Any + Send>) -> String {
    let text = if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-text panic".to_owned()
    };
    redact_synthetic_psks(&text)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .chars()
        .take(4096)
        .collect()
}

fn parse_section(text: &str, wanted: &str) -> HashMap<String, String> {
    let mut current = "";
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = &line[1..line.len() - 1];
            continue;
        }
        if current != wanted || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line.split_once('=').expect("pin key/value");
        values.insert(
            key.trim().to_owned(),
            raw_value.trim().trim_matches('"').to_owned(),
        );
    }
    values
}

fn value<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values
        .get(key)
        .unwrap_or_else(|| panic!("required pin field missing: {key}"))
}

fn verify_archive(path: &Path, pin: &Pin, deadline: CaseDeadline) {
    deadline.check("reference archive verification");
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(pin.asset.as_str()),
        "reference archive asset name mismatch"
    );
    let metadata = fs::metadata(path).expect("reference archive metadata");
    assert_eq!(metadata.len(), pin.size, "reference archive size mismatch");
    assert_eq!(
        sha256_file_with_deadline(path, deadline),
        pin.sha256,
        "reference archive SHA-256 mismatch"
    );
}

fn verify_version(reference: Reference, binary: &Path, pin: &Pin, deadline: CaseDeadline) {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.arg("version");
        }
        Reference::ShadowsocksRust => {
            command.arg("--version");
        }
    }
    let mut process = ProcessGuard::spawn("reference version probe", &mut command, deadline);
    let status = process.wait_for_exit(deadline, "bounded reference version probe");
    let (stdout, stderr) = process.finish_captures(deadline);
    assert!(
        status.success() && !stdout.truncated && !stderr.truncated && stderr.bytes.is_empty(),
        "reference version probe failed: status={status}, stdout={}, stderr={}",
        sanitize_capture(stdout),
        sanitize_capture(stderr)
    );
    let rendered = String::from_utf8(stdout.bytes).expect("reference version output must be UTF-8");
    match reference {
        Reference::SingBox => {
            assert!(
                rendered.lines().any(|line| line == pin.expected_version),
                "sing-box version line mismatch"
            );
            assert!(
                rendered
                    .lines()
                    .any(|line| line == format!("Revision: {}", pin.source_commit)),
                "sing-box source revision mismatch"
            );
        }
        Reference::ShadowsocksRust => assert_eq!(
            rendered.trim_end_matches(['\r', '\n']),
            pin.expected_version,
            "shadowsocks-rust version output mismatch"
        ),
    }
}

fn sha256_file_with_deadline(path: &Path, deadline: CaseDeadline) -> String {
    let mut file = File::open(path).expect("open reference archive");
    let mut sha = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        deadline.check("reference archive SHA-256");
        let read = file.read(&mut buffer).expect("read reference archive");
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
    }
    hex_digest(sha.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut sha = Sha256::new();
    sha.update(bytes);
    hex_digest(sha.finalize())
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len = self
            .total_len
            .checked_add(input.len() as u64)
            .expect("SHA-256 input length");
        if self.buffer_len != 0 {
            let fill = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + fill].copy_from_slice(&input[..fill]);
            self.buffer_len += fill;
            input = &input[fill..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        for block in input.chunks_exact(64) {
            let array: &[u8; 64] = block.try_into().expect("64-byte SHA block");
            self.compress(array);
        }
        let remainder = input.len() % 64;
        if remainder != 0 {
            let start = input.len() - remainder;
            self.buffer[..remainder].copy_from_slice(&input[start..]);
            self.buffer_len = remainder;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.checked_mul(8).expect("SHA-256 bit length");
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut output = [0_u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).take(16).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("SHA word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}
