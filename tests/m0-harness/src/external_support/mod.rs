#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const METHOD: &str = "2022-blake3-aes-128-gcm";
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

static ACTIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug)]
pub enum Reference {
    SingBox,
    ShadowsocksRust,
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    FerrumClient,
    ReferenceClient,
}

struct Pin {
    expected_version: String,
    asset: String,
    size: u64,
    sha256: String,
    license_review: String,
}

struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Clone, Copy)]
struct CaseDeadline {
    end: Instant,
}

impl CaseDeadline {
    fn start() -> Self {
        Self::after(CASE_TIMEOUT)
    }

    fn after(duration: Duration) -> Self {
        Self {
            end: Instant::now() + duration,
        }
    }

    fn remaining(self, label: &str) -> Duration {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .unwrap_or_else(|| panic!("{label}: absolute 60-second case deadline exceeded"))
    }

    fn bounded(self, requested: Duration, label: &str) -> Duration {
        requested.min(self.remaining(label))
    }

    fn check(self, label: &str) {
        let _ = self.remaining(label);
    }

    fn io_timeout(self, requested: Duration, label: &str) -> io::Result<Duration> {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| requested.min(remaining))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{label}: absolute 60-second case deadline exceeded"),
                )
            })
    }

    fn check_io(self, label: &str) -> io::Result<()> {
        self.io_timeout(Duration::MAX, label).map(|_| ())
    }
}

trait DeadlineIo: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn shutdown_write(&self) -> io::Result<()>;
}

impl DeadlineIo for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

fn read_exact_deadline<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: CaseDeadline,
    operation_timeout: Duration,
    label: &str,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream.set_read_timeout(Some(deadline.io_timeout(operation_timeout, label)?))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{label}: premature EOF"),
                ));
            }
            Ok(read) => {
                offset += read;
                deadline.check_io(label)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                deadline.check_io(label)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_deadline<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    buffer: &[u8],
    deadline: CaseDeadline,
    operation_timeout: Duration,
    label: &str,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream.set_write_timeout(Some(deadline.io_timeout(operation_timeout, label)?))?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("{label}: write returned zero"),
                ));
            }
            Ok(written) => {
                offset += written;
                deadline.check_io(label)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                deadline.check_io(label)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn flush_deadline<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    deadline: CaseDeadline,
    operation_timeout: Duration,
    label: &str,
) -> io::Result<()> {
    stream.set_write_timeout(Some(deadline.io_timeout(operation_timeout, label)?))?;
    stream.flush()?;
    deadline.check_io(label)
}

fn read_once_deadline<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: CaseDeadline,
    operation_timeout: Duration,
    label: &str,
) -> io::Result<usize> {
    loop {
        stream.set_read_timeout(Some(deadline.io_timeout(operation_timeout, label)?))?;
        match stream.read(buffer) {
            Ok(read) => {
                deadline.check_io(label)?;
                return Ok(read);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                deadline.check_io(label)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn shutdown_write_deadline<S: DeadlineIo + ?Sized>(
    stream: &S,
    deadline: CaseDeadline,
    label: &str,
) -> io::Result<()> {
    deadline.check_io(label)?;
    stream.shutdown_write()?;
    deadline.check_io(label)
}

struct CaptureReader {
    receiver: Receiver<Capture>,
    thread: Option<thread::JoinHandle<()>>,
}

struct ProcessGuard {
    label: &'static str,
    child: Child,
    stdout: Option<CaptureReader>,
    stderr: Option<CaptureReader>,
    reaped: bool,
}

impl ProcessGuard {
    fn spawn(label: &'static str, command: &mut Command, deadline: CaseDeadline) -> Self {
        deadline.check("before child spawn");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
        ACTIVE_CHILDREN.fetch_add(1, Ordering::SeqCst);
        let stdout = child.stdout.take().expect("captured stdout");
        let stderr = child.stderr.take().expect("captured stderr");
        let process = Self {
            label,
            child,
            stdout: Some(capture_output(stdout)),
            stderr: Some(capture_output(stderr)),
            reaped: false,
        };
        deadline.check("after child spawn");
        process
    }

    fn assert_running(&mut self, deadline: CaseDeadline, phase: &str) {
        deadline.check(phase);
        if let Some(status) = self.child.try_wait().expect("child status") {
            let diagnostics = self.finish_capture(deadline);
            self.reaped = true;
            ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
            panic!(
                "{} exited unexpectedly during {phase} with {status}: {diagnostics}",
                self.label,
            );
        }
    }

    fn wait_for_exit(&mut self, deadline: CaseDeadline, phase: &str) -> ExitStatus {
        loop {
            deadline.check(phase);
            if let Some(status) = self.child.try_wait().expect("child status") {
                self.reaped = true;
                ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
                return status;
            }
            thread::sleep(POLL_INTERVAL.min(deadline.remaining(phase)));
        }
    }

    fn finish_natural(&mut self, deadline: CaseDeadline, phase: &str) -> (ExitStatus, String) {
        let status = self.wait_for_exit(deadline, phase);
        let diagnostics = self.finish_capture(deadline);
        (status, diagnostics)
    }

    fn terminate(&mut self, deadline: CaseDeadline) -> String {
        if self.reaped {
            panic!(
                "{} was already reaped before intentional termination",
                self.label
            );
        }
        self.assert_running(deadline, "post-traffic child status check");
        self.child
            .kill()
            .unwrap_or_else(|error| panic!("kill {}: {error}", self.label));
        let status = self.wait_for_exit(deadline, "intentional child termination/reap");
        assert!(
            !status.success(),
            "{} reported success after intentional termination",
            self.label
        );
        let diagnostics = self.finish_capture(deadline);
        format!("intentional_status={status}, {diagnostics}")
    }

    fn finish_capture(&mut self, deadline: CaseDeadline) -> String {
        fn receive(reader: Option<CaptureReader>, deadline: CaseDeadline, label: &str) -> Capture {
            let Some(mut reader) = reader else {
                return Capture {
                    bytes: Vec::new(),
                    truncated: false,
                };
            };
            let capture = reader
                .receiver
                .recv_timeout(deadline.remaining(label))
                .unwrap_or_else(|error| panic!("{label}: bounded capture failed: {error}"));
            reader
                .thread
                .take()
                .expect("capture thread")
                .join()
                .expect("capture thread completed before channel delivery");
            capture
        }
        let stdout = receive(self.stdout.take(), deadline, "stdout capture");
        let stderr = receive(self.stderr.take(), deadline, "stderr capture");
        format!(
            "stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    ACTIVE_CHILDREN.fetch_sub(1, Ordering::SeqCst);
                    self.reaped = true;
                    break;
                }
                Ok(None) if Instant::now() < cleanup_deadline => thread::sleep(POLL_INTERVAL),
                _ => break,
            }
        }
        if thread::panicking() {
            eprintln!(
                "sanitized {} diagnostics unavailable during drop",
                self.label
            );
        }
    }
}

fn capture_output(mut stream: impl Read + Send + 'static) -> CaptureReader {
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut chunk = [0_u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    let _ = sender.send(Capture { bytes, truncated });
                    return;
                }
                Ok(read) => {
                    let remaining = CHILD_OUTPUT_CAP.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..read.min(remaining)]);
                    truncated |= read > remaining;
                }
            }
        }
    });
    CaptureReader {
        receiver,
        thread: Some(thread),
    }
}

fn sanitize_capture(capture: Capture) -> String {
    let text = String::from_utf8_lossy(&capture.bytes)
        .replace(SYNTHETIC_PSK, "[redacted]")
        .replace('\r', "\\r")
        .replace('\n', "\\n");
    if capture.truncated {
        format!("{text}[truncated at {CHILD_OUTPUT_CAP} bytes]")
    } else {
        text
    }
}

pub fn run_case(reference: Reference, direction: Direction) {
    let deadline = CaseDeadline::start();
    let child_baseline = ACTIVE_CHILDREN.load(Ordering::SeqCst);
    let pin = load_pin(reference);
    let archive = required_env(reference_archive_env(reference));
    verify_archive(&archive, &pin, deadline);

    let reference_binary = match (reference, direction) {
        (Reference::SingBox, _) => required_env("M0_SING_BOX_BIN"),
        (Reference::ShadowsocksRust, Direction::FerrumClient) => required_env("M0_SSSERVER_BIN"),
        (Reference::ShadowsocksRust, Direction::ReferenceClient) => required_env("M0_SSLOCAL_BIN"),
    };
    verify_version(
        reference,
        &reference_binary,
        &pin.expected_version,
        deadline,
    );

    let directory = tempfile::tempdir().expect("isolated interop directory");
    let directory_path = directory.path().to_path_buf();
    let mut ports = ReservedPorts::new();
    let target = ports.target_address();
    let proxy = ports.proxy_address();
    let shadowsocks = ports.shadowsocks_address();
    let trace = Arc::new(ExchangeTrace::default());
    let target_process = TargetProcess::start(ports.take_target(), deadline, Arc::clone(&trace));

    let context = CaseContext {
        directory: directory.path(),
        ports: &mut ports,
        shadowsocks,
        proxy,
        target,
        deadline,
        target_shutdown: &target_process.shutdown_gate,
        trace: Arc::clone(&trace),
    };
    let (config_checksum, process_evidence) = match direction {
        Direction::FerrumClient => run_ferrum_client_case(reference, &reference_binary, context),
        Direction::ReferenceClient => {
            run_reference_client_case(reference, &reference_binary, context)
        }
    };

    let target_evidence = target_process.finish(deadline);
    trace.assert_complete();
    drop(ports);
    assert_rebind_all([target, proxy, shadowsocks]);
    directory
        .close()
        .unwrap_or_else(|error| panic!("explicit temporary directory close: {error}"));
    assert!(
        !directory_path.exists(),
        "temporary interop directory remains after explicit close"
    );
    assert_eq!(
        ACTIVE_CHILDREN.load(Ordering::SeqCst),
        child_baseline,
        "external child registry did not return to baseline"
    );
    deadline.check("final interop evidence");
    eprintln!(
        "M0 interop evidence: reference={reference:?}, direction={direction:?}, \
         asset_sha256={}, config_sha256={config_checksum}, command_category=black-box-process, \
         process={process_evidence}, target={target_evidence}, result=success",
        pin.sha256
    );
}

struct CaseContext<'a> {
    directory: &'a Path,
    ports: &'a mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    target_shutdown: &'a Receiver<Result<(), String>>,
    trace: Arc<ExchangeTrace>,
}

fn run_ferrum_client_case(
    reference: Reference,
    reference_binary: &Path,
    context: CaseContext<'_>,
) -> (String, String) {
    let CaseContext {
        directory,
        ports,
        shadowsocks,
        proxy,
        target,
        deadline,
        target_shutdown,
        trace,
    } = context;
    let reference_config = reference_server_config(reference, shadowsocks);
    let reference_config_path = write_config(directory, "reference-server.json", &reference_config);
    ports.release_shadowsocks();
    let mut reference_command =
        reference_command(reference, reference_binary, &reference_config_path);
    let mut reference_process = ProcessGuard::spawn(
        "reference Shadowsocks server",
        &mut reference_command,
        deadline,
    );
    wait_for_tcp_listener(
        &mut reference_process,
        shadowsocks,
        deadline,
        "reference Shadowsocks server",
    );

    let ferrum_config = format!(
        "schema_version = 1\n\n[client]\nlisten = \"{proxy}\"\nserver = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{METHOD}\"\npsk = \"{SYNTHETIC_PSK}\"\n"
    );
    let ferrum_config_path = write_config(directory, "ferrum-client.toml", &ferrum_config);
    ports.release_proxy();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-client"));
    ferrum_command.args(["--config", path_text(&ferrum_config_path)]);
    let mut ferrum_process = ProcessGuard::spawn("ferrum client", &mut ferrum_command, deadline);
    wait_for_socks_listener(
        &mut ferrum_process,
        proxy,
        deadline,
        "ferrum SOCKS listener",
    );

    reference_process.assert_running(deadline, "pre-traffic reference check");
    ferrum_process.assert_running(deadline, "pre-traffic ferrum check");
    exercise_socks(proxy, target, deadline, target_shutdown, &trace);
    reference_process.assert_running(deadline, "post-traffic reference check");
    ferrum_process.assert_running(deadline, "post-traffic ferrum check");
    let ferrum_evidence = ferrum_process.terminate(deadline);
    let reference_evidence = reference_process.terminate(deadline);
    (
        sha256_bytes(reference_config.as_bytes()),
        format!("ferrum=[{ferrum_evidence}], reference=[{reference_evidence}]"),
    )
}

fn run_reference_client_case(
    reference: Reference,
    reference_binary: &Path,
    context: CaseContext<'_>,
) -> (String, String) {
    let CaseContext {
        directory,
        ports,
        shadowsocks,
        proxy,
        target,
        deadline,
        target_shutdown,
        trace,
    } = context;
    let ferrum_config = format!(
        "schema_version = 1\n\n[server]\nlisten = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{METHOD}\"\npsk = \"{SYNTHETIC_PSK}\"\n"
    );
    let ferrum_config_path = write_config(directory, "ferrum-server.toml", &ferrum_config);
    ports.release_shadowsocks();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-server"));
    ferrum_command.args(["--config", path_text(&ferrum_config_path)]);
    let mut ferrum_process = ProcessGuard::spawn("ferrum server", &mut ferrum_command, deadline);
    wait_for_tcp_listener(
        &mut ferrum_process,
        shadowsocks,
        deadline,
        "ferrum Shadowsocks listener",
    );

    let reference_config = reference_client_config(reference, shadowsocks, proxy);
    let reference_config_path = write_config(directory, "reference-client.json", &reference_config);
    ports.release_proxy();
    let mut reference_command =
        reference_command(reference, reference_binary, &reference_config_path);
    let mut reference_process =
        ProcessGuard::spawn("reference SOCKS client", &mut reference_command, deadline);
    wait_for_socks_listener(
        &mut reference_process,
        proxy,
        deadline,
        "reference SOCKS listener",
    );

    reference_process.assert_running(deadline, "pre-traffic reference check");
    ferrum_process.assert_running(deadline, "pre-traffic ferrum check");
    exercise_socks(proxy, target, deadline, target_shutdown, &trace);
    reference_process.assert_running(deadline, "post-traffic reference check");
    ferrum_process.assert_running(deadline, "post-traffic ferrum check");
    let reference_evidence = reference_process.terminate(deadline);
    let ferrum_evidence = ferrum_process.terminate(deadline);
    (
        sha256_bytes(reference_config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

fn exercise_socks(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    target_shutdown: &Receiver<Result<(), String>>,
    trace: &ExchangeTrace,
) {
    let mut stream =
        TcpStream::connect_timeout(&proxy.into(), deadline.bounded(IO_TIMEOUT, "connect SOCKS"))
            .expect("connect SOCKS");
    write_all_deadline(
        &mut stream,
        &[5, 1, 0],
        deadline,
        IO_TIMEOUT,
        "SOCKS greeting",
    )
    .expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    read_exact_deadline(
        &mut stream,
        &mut method,
        deadline,
        IO_TIMEOUT,
        "SOCKS method",
    )
    .expect("SOCKS method");
    assert_eq!(method, [5, 0], "SOCKS no-auth selected");

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    write_all_deadline(
        &mut stream,
        &request,
        deadline,
        IO_TIMEOUT,
        "SOCKS connect request",
    )
    .expect("SOCKS connect request");
    let mut reply = [0_u8; 10];
    read_exact_deadline(
        &mut stream,
        &mut reply,
        deadline,
        IO_TIMEOUT,
        "SOCKS connect reply",
    )
    .expect("SOCKS connect reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "SOCKS connect succeeded");

    run_application_exchange(&mut stream, deadline, target_shutdown, trace)
        .unwrap_or_else(|error| panic!("application exchange failed: {error}"));
}

fn run_application_exchange<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    deadline: CaseDeadline,
    target_shutdown: &Receiver<Result<(), String>>,
    trace: &ExchangeTrace,
) -> Result<(), String> {
    let forward = forward_payload();
    write_all_deadline(
        stream,
        &forward[..1],
        deadline,
        IO_TIMEOUT,
        "first forward byte",
    )
    .map_err(|error| format!("first forward byte: {error}"))?;
    write_all_deadline(
        stream,
        &forward[1..],
        deadline,
        IO_TIMEOUT,
        "remaining forward bytes",
    )
    .map_err(|error| format!("remaining forward bytes: {error}"))?;

    let reverse = reverse_payload();
    let mut received = vec![0_u8; reverse.len()];
    read_exact_deadline(
        stream,
        &mut received,
        deadline,
        IO_TIMEOUT,
        "complete reverse payload before application FIN",
    )
    .map_err(|error| format!("reverse premature EOF/error: {error}"))?;
    if received != reverse {
        return Err("reverse payload byte mismatch".into());
    }
    trace.record(ExchangeEvent::ReverseMatched)?;
    trace
        .record_after_io(ExchangeEvent::ApplicationShutdown, || {
            shutdown_write_deadline(stream, deadline, "client write half-close")
        })
        .map_err(|error| format!("client write half-close: {error}"))?;
    match target_shutdown.recv_timeout(deadline.remaining("target shutdown synchronization")) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(format!("target exchange failed before client EOF: {error}")),
        Err(error) => return Err(format!("target shutdown synchronization failed: {error}")),
    }
    expect_clean_eof(stream, deadline, "application client")?;
    trace.record(ExchangeEvent::ClientCleanEof)?;
    deadline
        .check_io("completed ordered clean-EOF exchange")
        .map_err(|error| error.to_string())
}

fn forward_payload() -> Vec<u8> {
    let mut payload = vec![0x49];
    payload.extend(std::iter::repeat_n(0x5a, 16_385));
    payload
}

fn reverse_payload() -> Vec<u8> {
    let mut payload = vec![0xa6];
    payload.extend((0..16_385).map(|index| (index % 251) as u8));
    assert_ne!(payload, forward_payload(), "payloads must remain distinct");
    payload
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeEvent {
    ForwardMatched,
    ReverseMatched,
    ApplicationShutdown,
    TargetCleanEof,
    TargetShutdown,
    ClientCleanEof,
}

const ORDERED_EXCHANGE: [ExchangeEvent; 6] = [
    ExchangeEvent::ForwardMatched,
    ExchangeEvent::ReverseMatched,
    ExchangeEvent::ApplicationShutdown,
    ExchangeEvent::TargetCleanEof,
    ExchangeEvent::TargetShutdown,
    ExchangeEvent::ClientCleanEof,
];

#[derive(Default)]
struct ExchangeTrace {
    events: Mutex<Vec<ExchangeEvent>>,
}

impl ExchangeTrace {
    fn record(&self, event: ExchangeEvent) -> Result<(), String> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| "exchange trace lock poisoned".to_owned())?;
        Self::require_next(&events, event)?;
        events.push(event);
        Ok(())
    }

    fn record_after_io(
        &self,
        event: ExchangeEvent,
        operation: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), String> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| "exchange trace lock poisoned".to_owned())?;
        Self::require_next(&events, event)?;
        operation().map_err(|error| error.to_string())?;
        events.push(event);
        Ok(())
    }

    fn require_next(events: &[ExchangeEvent], event: ExchangeEvent) -> Result<(), String> {
        let expected = ORDERED_EXCHANGE
            .get(events.len())
            .ok_or_else(|| format!("unexpected extra exchange event: {event:?}"))?;
        if *expected != event {
            return Err(format!(
                "exchange event out of order: actual={event:?}, expected={expected:?}"
            ));
        }
        Ok(())
    }

    fn snapshot(&self) -> Vec<ExchangeEvent> {
        self.events.lock().expect("exchange trace").clone()
    }

    fn assert_complete(&self) {
        assert_eq!(
            self.snapshot(),
            ORDERED_EXCHANGE,
            "live external I/O sequence is incomplete or reordered"
        );
    }
}

struct TargetProcess {
    result: Receiver<Result<String, String>>,
    shutdown_gate: Receiver<Result<(), String>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TargetProcess {
    fn start(listener: TcpListener, deadline: CaseDeadline, trace: Arc<ExchangeTrace>) -> Self {
        let (sender, result) = mpsc::channel();
        let (shutdown_sender, shutdown_gate) = mpsc::channel();
        let thread = thread::spawn(move || {
            let outcome = run_target(listener, deadline, &trace);
            let shutdown_result = outcome
                .as_ref()
                .map(|_| ())
                .map_err(std::clone::Clone::clone);
            let _ = shutdown_sender.send(shutdown_result);
            let _ = sender.send(outcome);
        });
        Self {
            result,
            shutdown_gate,
            thread: Some(thread),
        }
    }

    fn finish(mut self, deadline: CaseDeadline) -> String {
        let result = self
            .result
            .recv_timeout(deadline.remaining("target completion"))
            .unwrap_or_else(|error| panic!("target completion deadline: {error}"));
        self.thread
            .take()
            .expect("target thread")
            .join()
            .expect("target thread completed before channel delivery");
        result.unwrap_or_else(|error| panic!("target contract failed: {error}"))
    }
}

fn run_target(
    listener: TcpListener,
    deadline: CaseDeadline,
    trace: &ExchangeTrace,
) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("target nonblocking listener: {error}"))?;
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, "target accept");
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                deadline.check("target accept");
                if Instant::now() >= readiness_end {
                    return Err("target accept readiness deadline".into());
                }
                thread::sleep(POLL_INTERVAL.min(deadline.remaining("target accept")));
            }
            Err(error) => return Err(format!("target accept: {error}")),
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("target blocking stream: {error}"))?;
    run_target_exchange(&mut stream, deadline, trace)
}

fn run_target_exchange<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    deadline: CaseDeadline,
    trace: &ExchangeTrace,
) -> Result<String, String> {
    let expected = forward_payload();
    let mut received = vec![0_u8; expected.len()];
    read_exact_deadline(
        stream,
        &mut received,
        deadline,
        IO_TIMEOUT,
        "complete forward payload",
    )
    .map_err(|error| format!("forward premature EOF/error: {error}"))?;
    if received != expected {
        return Err("forward payload byte mismatch".into());
    }
    trace.record(ExchangeEvent::ForwardMatched)?;

    let reverse = reverse_payload();
    write_all_deadline(stream, &reverse, deadline, IO_TIMEOUT, "reverse payload")
        .map_err(|error| format!("reverse write: {error}"))?;
    flush_deadline(stream, deadline, IO_TIMEOUT, "reverse flush")
        .map_err(|error| format!("reverse flush: {error}"))?;
    expect_clean_eof(stream, deadline, "target")?;
    trace.record(ExchangeEvent::TargetCleanEof)?;
    trace
        .record_after_io(ExchangeEvent::TargetShutdown, || {
            shutdown_write_deadline(stream, deadline, "target write shutdown")
        })
        .map_err(|error| format!("target write shutdown failed: {error}"))?;
    Ok(format!(
        "forward_bytes={}, reverse_bytes={}, target_clean_eof=true, target_shutdown=true",
        expected.len(),
        reverse.len()
    ))
}

fn expect_clean_eof<S: DeadlineIo + ?Sized>(
    stream: &mut S,
    deadline: CaseDeadline,
    label: &str,
) -> Result<(), String> {
    let mut extra = [0_u8; 1];
    match read_once_deadline(stream, &mut extra, deadline, IO_TIMEOUT, label) {
        Ok(0) => Ok(()),
        Ok(_) => Err(format!(
            "{label} received an extra byte after expected payload"
        )),
        Err(error) => Err(format!(
            "{label} expected clean EOF, received error: {error}"
        )),
    }
}

fn wait_for_tcp_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    case_deadline: CaseDeadline,
    label: &str,
) {
    let readiness_end =
        Instant::now() + case_deadline.bounded(READINESS_TIMEOUT, "listener readiness");
    loop {
        child.assert_running(case_deadline, "listener readiness");
        if TcpStream::connect_timeout(
            &address.into(),
            case_deadline.bounded(Duration::from_millis(200), "listener readiness connect"),
        )
        .is_ok()
        {
            return;
        }
        assert!(
            Instant::now() < readiness_end,
            "{label} readiness timed out"
        );
        thread::sleep(POLL_INTERVAL.min(case_deadline.remaining("listener readiness")));
    }
}

fn wait_for_socks_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    case_deadline: CaseDeadline,
    label: &str,
) {
    let readiness_end =
        Instant::now() + case_deadline.bounded(READINESS_TIMEOUT, "SOCKS readiness");
    loop {
        child.assert_running(case_deadline, "SOCKS readiness");
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &address.into(),
            case_deadline.bounded(Duration::from_millis(200), "SOCKS readiness connect"),
        ) {
            if write_all_deadline(
                &mut stream,
                &[5, 1, 0],
                case_deadline,
                Duration::from_millis(500),
                "SOCKS readiness greeting",
            )
            .is_ok()
            {
                let mut response = [0_u8; 2];
                if read_exact_deadline(
                    &mut stream,
                    &mut response,
                    case_deadline,
                    Duration::from_millis(500),
                    "SOCKS readiness response",
                )
                .is_ok()
                    && response == [5, 0]
                {
                    return;
                }
            }
        }
        assert!(
            Instant::now() < readiness_end,
            "{label} readiness timed out"
        );
        thread::sleep(POLL_INTERVAL.min(case_deadline.remaining("SOCKS readiness")));
    }
}

struct ReservedPorts {
    target: Option<TcpListener>,
    proxy: Option<TcpListener>,
    shadowsocks: Option<TcpListener>,
}

impl ReservedPorts {
    fn new() -> Self {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve target");
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve proxy");
        let shadowsocks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve Shadowsocks");
        let addresses = [
            ipv4_address(&target),
            ipv4_address(&proxy),
            ipv4_address(&shadowsocks),
        ];
        assert!(
            addresses[0] != addresses[1]
                && addresses[0] != addresses[2]
                && addresses[1] != addresses[2],
            "reserved port pool must be distinct"
        );
        Self {
            target: Some(target),
            proxy: Some(proxy),
            shadowsocks: Some(shadowsocks),
        }
    }

    fn target_address(&self) -> SocketAddrV4 {
        ipv4_address(self.target.as_ref().expect("target reservation"))
    }

    fn proxy_address(&self) -> SocketAddrV4 {
        ipv4_address(self.proxy.as_ref().expect("proxy reservation"))
    }

    fn shadowsocks_address(&self) -> SocketAddrV4 {
        ipv4_address(self.shadowsocks.as_ref().expect("Shadowsocks reservation"))
    }

    fn take_target(&mut self) -> TcpListener {
        self.target.take().expect("release target only to target")
    }

    fn release_proxy(&mut self) {
        drop(
            self.proxy
                .take()
                .expect("release proxy only to proxy child"),
        );
    }

    fn release_shadowsocks(&mut self) {
        drop(
            self.shadowsocks
                .take()
                .expect("release Shadowsocks only to server child"),
        );
    }
}

fn assert_rebind_all(addresses: [SocketAddrV4; 3]) {
    let rebound = addresses
        .into_iter()
        .map(|address| {
            TcpListener::bind(address)
                .unwrap_or_else(|error| panic!("exact address did not rebind {address}: {error}"))
        })
        .collect::<Vec<_>>();
    assert_eq!(rebound.len(), 3);
}

fn ipv4_address(listener: &TcpListener) -> SocketAddrV4 {
    match listener.local_addr().expect("listener address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener returned IPv6"),
    }
}

fn reference_server_config(reference: Reference, address: SocketAddrV4) -> String {
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{},\"network\":\"tcp\",\
             \"method\":\"{METHOD}\",\"password\":\"{SYNTHETIC_PSK}\"}}],\
             \"outbounds\":[{{\"type\":\"direct\",\"tag\":\"direct\"}}],\
             \"route\":{{\"final\":\"direct\"}}}}",
            address.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{SYNTHETIC_PSK}\",\"method\":\"{METHOD}\",\
             \"mode\":\"tcp_only\"}}",
            address.port()
        ),
    }
}

fn reference_client_config(
    reference: Reference,
    server: SocketAddrV4,
    proxy: SocketAddrV4,
) -> String {
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"socks\",\"tag\":\"socks-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{}}}],\
             \"outbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-out\",\
             \"server\":\"127.0.0.1\",\"server_port\":{},\"method\":\"{METHOD}\",\
             \"password\":\"{SYNTHETIC_PSK}\",\"network\":\"tcp\"}}],\
             \"route\":{{\"final\":\"ss-out\"}}}}",
            proxy.port(),
            server.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
             \"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{SYNTHETIC_PSK}\",\"method\":\"{METHOD}\",\
             \"mode\":\"tcp_only\"}}",
            proxy.port(),
            server.port()
        ),
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

fn ferrum_binary(name: &str) -> PathBuf {
    let test_executable = std::env::current_exe().expect("test executable");
    let profile = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("Cargo target profile directory");
    let path = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "required current-worktree binary is missing: {}; run the required clean \
         `cargo build --workspace --bins --locked` immediately before interop",
        path.display()
    );
    path
}

fn reference_archive_env(reference: Reference) -> &'static str {
    match reference {
        Reference::SingBox => "M0_SING_BOX_ARCHIVE",
        Reference::ShadowsocksRust => "M0_SHADOWSOCKS_RUST_ARCHIVE",
    }
}

fn required_env(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| {
        panic!("required external process environment variable missing: {name}")
    });
    let path = PathBuf::from(value);
    assert!(path.is_file(), "required external file missing for {name}");
    path
}

fn load_pin(reference: Reference) -> Pin {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let text = fs::read_to_string(root.join("tests/interop/versions.toml"))
        .expect("read interop version pins");
    let section = match reference {
        Reference::SingBox => "sing_box",
        Reference::ShadowsocksRust => "shadowsocks_rust",
    };
    let values = parse_section(&text, section);
    let host = if cfg!(windows) { "windows" } else { "linux" };
    Pin {
        expected_version: value(&values, "expected_version").to_owned(),
        asset: value(&values, &format!("{host}_asset")).to_owned(),
        size: value(&values, &format!("{host}_size"))
            .parse()
            .expect("numeric asset size"),
        sha256: value(&values, &format!("{host}_sha256")).to_owned(),
        license_review: value(&values, "license_review").to_owned(),
    }
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
    let actual = sha256_file_with_deadline(path, Some(deadline));
    assert_eq!(actual, pin.sha256, "reference archive SHA-256 mismatch");
    assert!(
        !pin.license_review.trim().is_empty()
            && pin.license_review.contains("independent test process"),
        "reference license/non-redistribution review is required"
    );
}

fn verify_version(reference: Reference, binary: &Path, expected: &str, deadline: CaseDeadline) {
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
    let (status, rendered) = process.finish_natural(deadline, "bounded reference version probe");
    assert!(
        status.success(),
        "reference version probe failed: {rendered}"
    );
    assert!(
        rendered.contains(expected),
        "reference version mismatch: expected reviewed output"
    );
}

fn sha256_file(path: &Path) -> String {
    sha256_file_with_deadline(path, None)
}

fn sha256_file_with_deadline(path: &Path, deadline: Option<CaseDeadline>) -> String {
    let mut file = File::open(path).expect("open SHA-256 input");
    let mut state = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if let Some(deadline) = deadline {
            deadline.check("reference archive SHA-256");
        }
        let read = file.read(&mut buffer).expect("read SHA-256 input");
        if read == 0 {
            return hex_digest(state.finish());
        }
        state.update(&buffer[..read]);
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut state = Sha256::new();
    state.update(bytes);
    hex_digest(state.finish())
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length = self
            .length
            .checked_add(input.len() as u64)
            .expect("SHA-256 input length");
        if self.buffered != 0 {
            let take = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("64-byte SHA-256 block");
            self.compress(block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.checked_mul(8).expect("SHA-256 bit length");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0_u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("word"));
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

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_CHILDREN, CaseDeadline, DeadlineIo, ExchangeEvent, ExchangeTrace, IO_TIMEOUT,
        ProcessGuard, expect_clean_eof, forward_payload, read_exact_deadline, reverse_payload,
        run_application_exchange, run_target_exchange, sha256_bytes, sha256_file,
    };
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn sha256_matches_reviewed_known_answer() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("abc");
        fs::write(&path, b"abc").expect("write fixture");
        assert_eq!(sha256_file(&path), sha256_bytes(b"abc"));
    }

    #[test]
    fn live_exchange_records_ordered_eof_and_shutdown_operations() {
        let (mut target, mut application) = connected_pair();
        let trace = Arc::new(ExchangeTrace::default());
        let target_trace = Arc::clone(&trace);
        let (shutdown_sender, shutdown_receiver) = mpsc::channel();
        let deadline = CaseDeadline::after(Duration::from_secs(5));
        let target_thread = thread::spawn(move || {
            let result = run_target_exchange(&mut target, deadline, &target_trace);
            shutdown_sender
                .send(result.as_ref().map(|_| ()).map_err(Clone::clone))
                .expect("target shutdown gate");
            result
        });
        run_application_exchange(&mut application, deadline, &shutdown_receiver, &trace)
            .expect("live application exchange");
        target_thread
            .join()
            .expect("target thread")
            .expect("live target exchange");
        trace.assert_complete();
    }

    #[test]
    fn live_target_shutdown_failure_is_not_masked_by_stream_drop() {
        let (target, application) = connected_pair();
        let mut target = ShutdownFailureStream { inner: target };
        let trace = Arc::new(ExchangeTrace::default());
        let application_trace = Arc::clone(&trace);
        let (shutdown_sender, shutdown_receiver) = mpsc::channel();
        let deadline = CaseDeadline::after(Duration::from_secs(5));
        let application_thread = thread::spawn(move || {
            let mut application = application;
            let result = run_application_exchange(
                &mut application,
                deadline,
                &shutdown_receiver,
                &application_trace,
            );
            (result, application)
        });

        let target_error = run_target_exchange(&mut target, deadline, &trace)
            .expect_err("injected target write shutdown failure");
        assert!(target_error.contains("target write shutdown failed"));
        shutdown_sender
            .send(Err(target_error))
            .expect("target failure gate");
        let (application_result, mut application) =
            application_thread.join().expect("application thread");
        assert!(
            application_result
                .expect_err("target failure must block client EOF observation")
                .contains("target exchange failed before client EOF")
        );
        assert_eq!(
            trace.snapshot(),
            [
                ExchangeEvent::ForwardMatched,
                ExchangeEvent::ReverseMatched,
                ExchangeEvent::ApplicationShutdown,
                ExchangeEvent::TargetCleanEof,
            ],
            "failed shutdown must not record target shutdown or client EOF"
        );
        assert!(
            target.inner.peer_addr().is_ok(),
            "target stream must remain alive during the failure assertion"
        );
        application
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        let mut byte = [0_u8; 1];
        let error = application
            .read(&mut byte)
            .expect_err("live target stream must not masquerade as client EOF");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn payload_contract_is_fixed_complete_and_distinct() {
        let forward = forward_payload();
        let reverse = reverse_payload();
        assert_eq!(forward.len(), 16_386);
        assert_eq!(reverse.len(), 16_386);
        assert_ne!(forward, reverse);
    }

    #[test]
    fn clean_eof_rejects_extra_byte_and_accepts_only_zero() {
        let (mut reader, mut writer) = connected_pair();
        writer.write_all(&[0xa5]).expect("extra byte");
        writer.shutdown(Shutdown::Write).expect("writer shutdown");
        assert!(
            expect_clean_eof(
                &mut reader,
                CaseDeadline::after(Duration::from_secs(1)),
                "mutation",
            )
            .is_err()
        );

        let (mut reader, writer) = connected_pair();
        writer
            .shutdown(Shutdown::Write)
            .expect("clean writer shutdown");
        expect_clean_eof(
            &mut reader,
            CaseDeadline::after(Duration::from_secs(1)),
            "clean",
        )
        .expect("clean zero-length read");
    }

    #[test]
    fn absolute_deadline_and_nonzero_child_status_are_enforced() {
        let expired = CaseDeadline {
            end: Instant::now() - Duration::from_millis(1),
        };
        assert!(std::panic::catch_unwind(|| expired.check("mutation")).is_err());

        let deadline = CaseDeadline::start();
        let baseline = ACTIVE_CHILDREN.load(Ordering::SeqCst);
        let mut command = failing_command();
        let mut child = ProcessGuard::spawn("nonzero status mutation", &mut command, deadline);
        let (status, _) = child.finish_natural(deadline, "nonzero child");
        assert!(!status.success());
        assert_eq!(ACTIVE_CHILDREN.load(Ordering::SeqCst), baseline);
    }

    #[test]
    fn absolute_deadline_rejects_drip_progress() {
        let (mut reader, mut writer) = connected_pair();
        let drip = thread::spawn(move || {
            for byte in 0_u8..8 {
                thread::sleep(Duration::from_millis(30));
                if writer.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let deadline = CaseDeadline::after(Duration::from_millis(120));
        let mut received = [0_u8; 8];
        let error = read_exact_deadline(
            &mut reader,
            &mut received,
            deadline,
            IO_TIMEOUT,
            "drip mutation",
        )
        .expect_err("drip progress must not extend the absolute case deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drip.join().expect("drip writer");
    }

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("pair listener");
        let address = listener.local_addr().expect("pair address");
        let connector = thread::spawn(move || TcpStream::connect(address).expect("pair connect"));
        let (accepted, _) = listener.accept().expect("pair accept");
        (accepted, connector.join().expect("pair connector"))
    }

    struct ShutdownFailureStream {
        inner: TcpStream,
    }

    impl Read for ShutdownFailureStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Write for ShutdownFailureStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    impl DeadlineIo for ShutdownFailureStream {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
            self.inner.set_read_timeout(timeout)
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
            self.inner.set_write_timeout(timeout)
        }

        fn shutdown_write(&self) -> std::io::Result<()> {
            Err(std::io::Error::other("injected target shutdown failure"))
        }
    }

    fn failing_command() -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("cmd");
            command.args(["/c", "exit", "7"]);
            command
        }
        #[cfg(not(windows))]
        {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 7"]);
            command
        }
    }
}
