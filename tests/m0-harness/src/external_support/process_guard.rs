use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::qualification::{CleanupState, Method};

use super::{
    CASE_TIMEOUT, CHILD_OUTPUT_CAP, POLL_INTERVAL, cleanup_state, pending,
    retain_unconfirmed_worker,
};

pub(super) fn catch_sanitized<T>(
    operation: impl FnOnce() -> T,
) -> Result<T, Box<dyn std::any::Any + Send>> {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(operation));
    std::panic::set_hook(previous_hook);
    result
}

#[derive(Clone, Copy)]
pub(super) struct CaseDeadline {
    pub(super) end: Instant,
}

impl CaseDeadline {
    pub(super) fn start() -> Self {
        Self {
            end: Instant::now() + CASE_TIMEOUT,
        }
    }

    pub(super) fn remaining(self, label: &str) -> Duration {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .unwrap_or_else(|| panic!("{label}: absolute case deadline exceeded"))
    }

    pub(super) fn bounded(self, requested: Duration, label: &str) -> Duration {
        requested.min(self.remaining(label))
    }

    pub(super) fn check(self, label: &str) {
        let _ = self.remaining(label);
    }
}

pub(super) struct Capture {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

pub(super) struct CaptureReader {
    pub(super) result: Receiver<Capture>,
    pub(super) worker: Option<thread::JoinHandle<()>>,
}

pub(super) fn capture_output(mut stream: impl Read + Send + 'static) -> CaptureReader {
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
    pub(super) fn finish(mut self, deadline: CaseDeadline, label: &str) -> Capture {
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

pub(super) struct CancellableWorker<T> {
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) result: Receiver<T>,
    pub(super) worker: Option<thread::JoinHandle<()>>,
}

impl<T: Send + 'static> CancellableWorker<T> {
    pub(super) fn spawn(operation: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static) -> Self {
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

    pub(super) fn finish(mut self, deadline: CaseDeadline, label: &str) -> T {
        let result = self
            .result
            .recv_timeout(deadline.remaining(label))
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        self.join();
        result
    }
}

impl<T> CancellableWorker<T> {
    pub(super) fn join(&mut self) {
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

pub(super) struct ProcessGuard {
    pub(super) label: &'static str,
    pub(super) child: Option<Child>,
    pub(super) stdout: Option<CaptureReader>,
    pub(super) stderr: Option<CaptureReader>,
    pub(super) counted: bool,
}

impl ProcessGuard {
    pub(super) fn spawn(
        label: &'static str,
        command: &mut Command,
        deadline: CaseDeadline,
    ) -> Self {
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

    pub(super) fn assert_running(&mut self, deadline: CaseDeadline, phase: &str) {
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

    pub(super) fn wait_for_exit(&mut self, deadline: CaseDeadline, phase: &str) -> ExitStatus {
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

    pub(super) fn terminate(&mut self, deadline: CaseDeadline) -> String {
        let (status, stdout, stderr) = self.terminate_captures(deadline);
        format!(
            "terminated_status={status}, stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }

    pub(super) fn terminate_captures(
        &mut self,
        deadline: CaseDeadline,
    ) -> (ExitStatus, Capture, Capture) {
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

    pub(super) fn finish_capture(&mut self, deadline: CaseDeadline) -> String {
        let (stdout, stderr) = self.finish_captures(deadline);
        format!(
            "stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }

    pub(super) fn finish_captures(&mut self, deadline: CaseDeadline) -> (Capture, Capture) {
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

    pub(super) fn mark_reaped(&mut self) {
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

pub(super) fn sanitize_capture(capture: Capture) -> String {
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

pub(super) fn redact_synthetic_psks(text: &str) -> String {
    text.replace(Method::Aes128Gcm.synthetic_psk(), "[redacted]")
        .replace(Method::Aes256Gcm.synthetic_psk(), "[redacted]")
}
