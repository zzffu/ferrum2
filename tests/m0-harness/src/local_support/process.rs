use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::readiness::active_child_count;
use super::{
    ACTIVE_CHILDREN, CHILD_OUTPUT_CAP, FORCED_REAP_TIMEOUT, PROCESS_POLL, PROCESS_RUN_TIMEOUT,
    PROCESS_SPAWN_LOCK, SIGNAL_DELIVERY_TIMEOUT, contains_bytes,
};

#[cfg(test)]
mod contract;
#[cfg(test)]
pub(crate) use contract::assert_process_support_contract;
#[cfg(test)]
const _: fn() = assert_process_support_contract;

static PENDING_PROCESSES: OnceLock<Mutex<Vec<ProcessInner>>> = OnceLock::new();
static PROCESS_CLEANUP_FAILURES: AtomicUsize = AtomicUsize::new(0);

struct ProcessRegistration {
    active: &'static AtomicUsize,
    failures: &'static AtomicUsize,
    released: bool,
}

impl ProcessRegistration {
    fn active() -> Self {
        Self::acquire(&ACTIVE_CHILDREN, &PROCESS_CLEANUP_FAILURES)
    }

    fn acquire(active: &'static AtomicUsize, failures: &'static AtomicUsize) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self {
            active,
            failures,
            released: false,
        }
    }

    fn release(mut self, cleanup_succeeded: bool) {
        if !cleanup_succeeded {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
        let previous = self.active.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 0, "child registry underflow");
        self.released = true;
    }
}

impl Drop for ProcessRegistration {
    fn drop(&mut self) {
        if !self.released {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn pending_processes() -> &'static Mutex<Vec<ProcessInner>> {
    PENDING_PROCESSES.get_or_init(|| Mutex::new(Vec::new()))
}

fn retain_pending_inner(process: ProcessInner) {
    pending_processes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(process);
}

fn retain_pending_process(mut process: OwnedProcess) {
    retain_pending_inner(process.take_inner());
}

fn retry_pending_processes(deadline: Instant) {
    let mut pending = pending_processes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < pending.len() {
        pending[index].request_kill();
        if !pending[index].complete_until(deadline) {
            index += 1;
            continue;
        }
        let process = pending.swap_remove(index);
        let _ = process.finish();
    }
}

pub fn hold_process_spawns() -> std::sync::MutexGuard<'static, ()> {
    let guard = PROCESS_SPAWN_LOCK.lock().expect("process spawn lock");
    retry_pending_processes(Instant::now() + FORCED_REAP_TIMEOUT);
    assert!(
        pending_processes()
            .lock()
            .expect("pending process lock")
            .is_empty(),
        "previous child cleanup remains unconfirmed"
    );
    assert_eq!(
        PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst),
        0,
        "previous child cleanup failed"
    );
    guard
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
    run_binary_configured(name, arguments)
}

pub fn run_binary_while_holding(
    name: &str,
    arguments: &[&str],
    _spawn_guard: &std::sync::MutexGuard<'static, ()>,
) -> Output {
    run_binary_configured(name, arguments)
}

fn run_binary_configured(name: &str, arguments: &[&str]) -> Output {
    let binary = binary_path(name);
    let child = Command::new(binary)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run binary");
    let mut process = OwnedProcess::tracked_child(child);
    process
        .attach_captures(&mut ThreadCaptureSpawner)
        .unwrap_or_else(|error| panic!("start binary capture workers: {error}"));
    if !process.wait_for_exit_until(Instant::now() + PROCESS_RUN_TIMEOUT) {
        process.request_kill();
        if !process.wait_for_exit_until(Instant::now() + FORCED_REAP_TIMEOUT) {
            retain_pending_process(process);
            panic!("binary did not exit after forced reap deadline: {name}");
        }
    }
    if !process.complete_until(Instant::now() + FORCED_REAP_TIMEOUT) {
        retain_pending_process(process);
        panic!("binary output capture did not finish after reap deadline: {name}");
    }
    let completed = process
        .finish()
        .unwrap_or_else(|()| panic!("binary output capture failed: {name}"));
    Output {
        status: completed.status,
        stdout: completed
            .stdout
            .expect("binary stdout capture")
            .bytes
            .into_vec(),
        stderr: completed
            .stderr
            .expect("binary stderr capture")
            .bytes
            .into_vec(),
    }
}

pub struct ChildGuard {
    process: Option<OwnedProcess>,
    pub(super) binary: String,
    context: String,
    deferred_exit_checks: usize,
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
        let binary = name.to_owned();
        let context = context.into();
        let executable = binary_path(name);
        let config = config.to_str().expect("UTF-8 config path");
        let mut command = Command::new(executable);
        command
            .args(["--config", config])
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
        let child = command.spawn().expect("spawn child process");
        let mut process = OwnedProcess::tracked_child(child);
        process
            .attach_captures(&mut ThreadCaptureSpawner)
            .unwrap_or_else(|error| panic!("start child capture workers: {error}"));
        Self {
            process: Some(process),
            binary,
            context,
            deferred_exit_checks: 0,
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
        let process = self.process.as_mut().expect("live child owner");
        let status = process.try_wait().expect("child status");
        match status {
            None => Ok(()),
            Some(_) if self.deferred_exit_checks > 0 => {
                self.deferred_exit_checks -= 1;
                Ok(())
            }
            Some(status) => Err(self.finish_reap(status)),
        }
    }

    pub fn terminate_and_reap(&mut self, timeout: Duration) {
        if self.process.is_none() {
            return;
        }
        let _ = self.terminate_and_reap_with_exit(timeout);
    }

    pub fn terminate_and_reap_with_exit(&mut self, timeout: Duration) -> ChildExit {
        let process = self.process.as_mut().expect("live child owner");
        if let Some(status) = process.try_wait().expect("child status") {
            return self.finish_reap(status);
        }
        process.request_kill();
        self.wait_for_exit(timeout)
    }

    pub fn wait_and_reap(&mut self, timeout: Duration) {
        if self.process.is_none() {
            return;
        }
        if let Some(status) = self
            .process
            .as_mut()
            .expect("live child owner")
            .try_wait()
            .expect("child status")
        {
            let _ = self.finish_reap(status);
            return;
        }
        let _ = self.wait_for_exit(timeout);
    }

    pub fn request_graceful_shutdown(&mut self) {
        let spawn_guard = hold_process_spawns();
        self.request_graceful_shutdown_while_holding(&spawn_guard);
    }

    pub fn request_graceful_shutdown_while_holding(
        &mut self,
        _spawn_guard: &std::sync::MutexGuard<'static, ()>,
    ) {
        let process_id = self.process.as_ref().expect("live child owner").id();
        send_shutdown_signal(process_id);
    }

    pub fn wait_for_exit(&mut self, timeout: Duration) -> ChildExit {
        let deadline = Instant::now() + timeout;
        let process = self.process.as_mut().expect("live child owner");
        if !process.wait_for_exit_until(deadline) {
            process.request_kill();
            if !process.wait_for_exit_until(Instant::now() + FORCED_REAP_TIMEOUT) {
                let process = self.process.take().expect("live child owner");
                retain_pending_process(process);
                panic!("child did not exit after forced reap deadline");
            }
        }
        let status = self
            .process
            .as_ref()
            .and_then(OwnedProcess::status)
            .expect("reaped child status");
        self.finish_reap(status)
    }

    fn finish_reap(&mut self, status: ExitStatus) -> ChildExit {
        let mut process = self.process.take().expect("live child owner");
        process.record_status(status);
        if !process.complete_until(Instant::now() + FORCED_REAP_TIMEOUT) {
            retain_pending_process(process);
            panic!("child output capture did not finish after reap deadline");
        }
        let completed = process
            .finish()
            .unwrap_or_else(|()| panic!("child output capture failed"));
        ChildExit {
            binary: self.binary.clone(),
            context: self.context.clone(),
            status: completed.status,
            stdout: completed.stdout.expect("child stdout capture"),
            stderr: completed.stderr.expect("child stderr capture"),
        }
    }
}

struct CompletedProcess {
    status: ExitStatus,
    stdout: Option<OutputSummary>,
    stderr: Option<OutputSummary>,
}

struct OwnedProcess {
    inner: Option<ProcessInner>,
}

struct ProcessInner {
    child: Child,
    status: Option<ExitStatus>,
    stdout: Option<CaptureOwner>,
    stderr: Option<CaptureOwner>,
    registration: Option<ProcessRegistration>,
    cleanup_failed: bool,
}

impl OwnedProcess {
    fn tracked_child(child: Child) -> Self {
        Self::tracked_child_with_registration(child, ProcessRegistration::active())
    }

    fn tracked_child_with_registration(child: Child, registration: ProcessRegistration) -> Self {
        Self {
            inner: Some(ProcessInner {
                child,
                status: None,
                stdout: None,
                stderr: None,
                registration: Some(registration),
                cleanup_failed: false,
            }),
        }
    }

    fn untracked_child(child: Child) -> Self {
        Self {
            inner: Some(ProcessInner {
                child,
                status: None,
                stdout: None,
                stderr: None,
                registration: None,
                cleanup_failed: false,
            }),
        }
    }

    fn attach_captures(&mut self, spawner: &mut impl CaptureSpawner) -> io::Result<()> {
        let inner = self.inner_mut();
        let Some(stdout) = inner.child.stdout.take() else {
            return Err(io::Error::other("missing child stdout capture"));
        };
        inner.stdout = Some(CaptureOwner::new(stdout, spawner)?);
        let Some(stderr) = inner.child.stderr.take() else {
            return Err(io::Error::other("missing child stderr capture"));
        };
        inner.stderr = Some(CaptureOwner::new(stderr, spawner)?);
        Ok(())
    }

    fn inner(&self) -> &ProcessInner {
        self.inner.as_ref().expect("live process owner")
    }

    fn inner_mut(&mut self) -> &mut ProcessInner {
        self.inner.as_mut().expect("live process owner")
    }

    fn take_inner(&mut self) -> ProcessInner {
        self.inner.take().expect("live process owner")
    }

    fn id(&self) -> u32 {
        self.inner().id()
    }

    fn status(&self) -> Option<ExitStatus> {
        self.inner().status()
    }

    fn record_status(&mut self, status: ExitStatus) {
        self.inner_mut().record_status(status);
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner_mut().try_wait()
    }

    fn wait_for_exit_until(&mut self, deadline: Instant) -> bool {
        self.inner_mut().wait_for_exit_until(deadline)
    }

    fn request_kill(&mut self) {
        self.inner_mut().request_kill();
    }

    fn complete_until(&mut self, deadline: Instant) -> bool {
        self.inner_mut().complete_until(deadline)
    }

    fn finish(mut self) -> Result<CompletedProcess, ()> {
        self.take_inner().finish()
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        inner.request_kill();
        let deadline = Instant::now() + FORCED_REAP_TIMEOUT;
        if inner.complete_until(deadline) {
            let _ = inner.finish();
        } else {
            retain_pending_inner(inner);
        }
    }
}

impl ProcessInner {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    fn record_status(&mut self, status: ExitStatus) {
        self.status = Some(status);
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    fn wait_for_exit_until(&mut self, deadline: Instant) -> bool {
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(_) => {
                    self.cleanup_failed = true;
                    return false;
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            thread::sleep(PROCESS_POLL.min(remaining));
        }
    }

    fn request_kill(&mut self) {
        if self.status.is_some() || self.child.kill().is_ok() {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(status)) => self.status = Some(status),
            Ok(None) | Err(_) => self.cleanup_failed = true,
        }
    }

    fn complete_until(&mut self, deadline: Instant) -> bool {
        if !self.wait_for_exit_until(deadline) {
            return false;
        }
        if self
            .stdout
            .as_mut()
            .is_some_and(|capture| !capture.complete_until(deadline))
        {
            return false;
        }
        if self
            .stderr
            .as_mut()
            .is_some_and(|capture| !capture.complete_until(deadline))
        {
            return false;
        }
        true
    }

    fn finish(mut self) -> Result<CompletedProcess, ()> {
        let status = self.status;
        let stdout = self.stdout.take().map(CaptureOwner::finish).transpose();
        let stderr = self.stderr.take().map(CaptureOwner::finish).transpose();
        self.cleanup_failed |= status.is_none() || stdout.is_err() || stderr.is_err();
        if let Some(registration) = self.registration.take() {
            registration.release(!self.cleanup_failed);
        }
        if self.cleanup_failed {
            return Err(());
        }
        Ok(CompletedProcess {
            status: status.expect("completed process status"),
            stdout: stdout.expect("completed stdout capture"),
            stderr: stderr.expect("completed stderr capture"),
        })
    }
}

type CaptureTask = Box<dyn FnOnce() + Send + 'static>;

trait CaptureSpawner {
    fn spawn(&mut self, task: CaptureTask) -> io::Result<thread::JoinHandle<()>>;
}

struct ThreadCaptureSpawner;

impl CaptureSpawner for ThreadCaptureSpawner {
    fn spawn(&mut self, task: CaptureTask) -> io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("ferrum2-m0-capture".to_owned())
            .spawn(task)
    }
}

struct CaptureOwner {
    result: mpsc::Receiver<OutputSummary>,
    worker: Option<thread::JoinHandle<()>>,
    received: Option<OutputSummary>,
    complete: bool,
    failed: bool,
}

impl CaptureOwner {
    fn new(
        mut stream: impl Read + Send + 'static,
        spawner: &mut impl CaptureSpawner,
    ) -> io::Result<Self> {
        let (sender, result) = mpsc::sync_channel(1);
        let worker = spawner.spawn(Box::new(move || {
            let mut bytes = Vec::new();
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            let mut truncated = false;
            let mut chunk = [0_u8; 8 * 1024];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(OutputSummary {
                            bytes: bytes.into_boxed_slice(),
                            hash,
                            truncated,
                        });
                        return;
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
        }))?;
        Ok(Self {
            result,
            worker: Some(worker),
            received: None,
            complete: false,
            failed: false,
        })
    }

    fn complete_until(&mut self, deadline: Instant) -> bool {
        if self.complete {
            return true;
        }
        if self.received.is_none() && !self.failed {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            match self.result.recv_timeout(remaining) {
                Ok(output) => self.received = Some(output),
                Err(mpsc::RecvTimeoutError::Timeout) => return false,
                Err(mpsc::RecvTimeoutError::Disconnected) => self.failed = true,
            }
        }
        let worker = self.worker.as_ref().expect("capture worker owner");
        while !worker.is_finished() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            thread::sleep(PROCESS_POLL.min(remaining));
        }
        let worker = self.worker.take().expect("capture worker owner");
        self.failed |= worker.join().is_err();
        self.complete = true;
        true
    }

    fn finish(mut self) -> Result<OutputSummary, ()> {
        if !self.complete || self.failed {
            return Err(());
        }
        self.received.take().ok_or(())
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
    pub fn shutdown_report_diagnostic(&self) -> String {
        if self.stderr.truncated {
            return "shutdown_report=truncated".to_owned();
        }
        let Some(report) = std::str::from_utf8(&self.stderr.bytes)
            .ok()
            .and_then(|stderr| {
                stderr.lines().find_map(|line| {
                    let report = serde_json::from_str::<serde_json::Value>(line).ok()?;
                    (report["event"] == "process_shutdown_report").then_some(report)
                })
            })
        else {
            return "shutdown_report=missing".to_owned();
        };
        let cleanup_owner_delta = report["cleanup_failure"]["owner_delta"]
            .as_object()
            .into_iter()
            .flat_map(|delta| delta.iter())
            .filter_map(|(name, value)| {
                let value = value.as_i64()?;
                (value != 0).then(|| format!("{name}:{value}"))
            })
            .collect::<Vec<_>>()
            .join(",");
        let root_events = report["root_exit_events"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|event| {
                format!(
                    "{}:{}:{}",
                    event["root"]["name"].as_str().unwrap_or("null"),
                    event["phase"].as_str().unwrap_or("null"),
                    event["exit_category"].as_str().unwrap_or("null"),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "termination_cause={} root_name={} root_id={} root_error_category={} root_exit_category={} cleanup_kind={} cleanup_root_name={} cleanup_root_id={} cleanup_root_error_category={} cleanup_owner_delta={} root_events={}",
            report["termination_cause"].as_str().unwrap_or("null"),
            report["root"]["name"].as_str().unwrap_or("null"),
            report["root"]["id"]
                .as_u64()
                .map_or_else(|| "null".to_owned(), |id| id.to_string(),),
            report["root_error_category"].as_str().unwrap_or("null"),
            report["root_exit_category"].as_str().unwrap_or("null"),
            report["cleanup_failure"]["kind"].as_str().unwrap_or("null"),
            report["cleanup_failure"]["root"]["name"]
                .as_str()
                .unwrap_or("null"),
            report["cleanup_failure"]["root"]["id"]
                .as_u64()
                .map_or_else(|| "null".to_owned(), |id| id.to_string()),
            report["cleanup_failure"]["root_error_category"]
                .as_str()
                .unwrap_or("null"),
            cleanup_owner_delta,
            root_events,
        )
    }

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
    let mut command = Command::new("kill");
    command.args(["-INT", &process_id.to_string()]);
    let status = run_signal_sender(&mut command, "SIGINT sender");
    assert!(status.success(), "SIGINT sender failed: {status}");
}

#[cfg(windows)]
fn send_shutdown_signal(process_id: u32) {
    let script = format!(
        r#"Add-Type -Namespace Ferrum2 -Name ConsoleSignal -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool FreeConsole(); [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint processId); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr handler, bool add); [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint signal, uint processGroup);'; [void][Ferrum2.ConsoleSignal]::FreeConsole(); if (-not [Ferrum2.ConsoleSignal]::AttachConsole({process_id})) {{ exit 1 }}; [void][Ferrum2.ConsoleSignal]::SetConsoleCtrlHandler([System.IntPtr]::Zero, $true); $sent = [Ferrum2.ConsoleSignal]::GenerateConsoleCtrlEvent(1, {process_id}); [void][Ferrum2.ConsoleSignal]::FreeConsole(); if (-not $sent) {{ exit 1 }}"#
    );
    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = run_signal_sender(&mut command, "Ctrl-Break sender");
    const CONTROL_C_EXIT: i32 = -1_073_741_510;
    assert!(
        status.success() || status.code() == Some(CONTROL_C_EXIT),
        "Ctrl-Break sender failed before delivery: {status}"
    );
}

fn run_signal_sender(command: &mut Command, label: &str) -> ExitStatus {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let mut process = OwnedProcess::untracked_child(child);
    if !process.wait_for_exit_until(Instant::now() + SIGNAL_DELIVERY_TIMEOUT) {
        process.request_kill();
        if !process.wait_for_exit_until(Instant::now() + FORCED_REAP_TIMEOUT) {
            retain_pending_process(process);
            panic!("{label} did not exit after forced reap deadline");
        }
    }
    process
        .finish()
        .unwrap_or_else(|()| panic!("{label} cleanup failed"))
        .status
}
