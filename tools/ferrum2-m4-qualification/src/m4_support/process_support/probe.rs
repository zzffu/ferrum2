use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{ACTIVE_PROCESSES, Capture, ProcessGuard, clean_io, join_capture};

/// Operations on the existing owned child. A successful wait reaps the child;
/// this seam never transfers process ownership. Fake operations complete finitely.
trait ChildControl {
    type Status;
    fn try_wait(&mut self) -> io::Result<Option<Self::Status>>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<Self::Status>;
}

impl ChildControl for Child {
    type Status = ExitStatus;
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }
    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        Child::wait(self)
    }
}

fn wait_until<C: ChildControl>(
    child: &mut C,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut pause: impl FnMut(),
) -> io::Result<(C::Status, bool)> {
    loop {
        let expired = now() >= deadline;
        if let Some(status) = child.try_wait()? {
            return Ok((status, expired));
        }
        if expired {
            let killed = child.kill();
            let waited = child.wait();
            // Preserve the first error while still attempting the reap.
            killed?;
            return waited.map(|status| (status, true));
        }
        pause();
    }
}

pub(in crate::m4_support) fn wait_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<(ExitStatus, bool), String> {
    wait_until(child, deadline, Instant::now, || {
        std::thread::sleep(Duration::from_millis(10));
    })
    .map_err(clean_io)
}

pub(in crate::m4_support) struct ProbeOutput {
    pub(in crate::m4_support) status: ExitStatus,
    pub(in crate::m4_support) stdout: Vec<u8>,
    pub(in crate::m4_support) stderr: Vec<u8>,
}

impl ProcessGuard {
    pub(super) fn finish_output(&mut self, deadline: Instant) -> Result<ProbeOutput, String> {
        let waited = wait_child(&mut self.child, deadline);
        // A failed wait leaves the guard responsible for termination and capture
        // joins. Never wait on pipes before terminating a potentially live child.
        let (status, timed_out) = waited.map_err(|_| format!("{} wait failed", self.label))?;
        let stdout = join_capture(self.stdout.take().expect("probe stdout"));
        let stderr = join_capture(self.stderr.take().expect("probe stderr"));
        self.reaped = true;
        ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
        let (stdout, stderr) = validate_capture(&self.label, timed_out, stdout, stderr)?;
        Ok(ProbeOutput {
            status,
            stdout,
            stderr,
        })
    }
}

fn validate_capture(
    identity: &str,
    timed_out: bool,
    stdout: Result<Capture, String>,
    stderr: Result<Capture, String>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if timed_out {
        return Err(format!("{identity} timed out"));
    }
    let stdout = stdout.map_err(|_| format!("{identity} stdout capture failed"))?;
    let stderr = stderr.map_err(|_| format!("{identity} stderr capture failed"))?;
    if stdout.read_failed || stderr.read_failed {
        return Err(format!("{identity} output capture read failed"));
    }
    if stdout.truncated || stderr.truncated {
        return Err(format!("{identity} output exceeded bound"));
    }
    if stdout.secret || stderr.secret {
        return Err(format!("{identity} emitted secret-bearing output"));
    }
    Ok((stdout.bytes, stderr.bytes))
}

/// Completes one direct-child capture, accepting any exit status. Output bounds,
/// redaction and timeout are enforced before returning bytes to the caller.
pub(in crate::m4_support) fn probe_output(
    identity: &'static str,
    command: &mut Command,
    deadline: Instant,
) -> Result<ProbeOutput, String> {
    if Instant::now() >= deadline {
        return Err(format!("{identity} timed out"));
    }
    let mut process = ProcessGuard::spawn(identity, command)?;
    process.finish_output(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m4_support::PSK;
    use crate::m4_support::process_support::{PROCESS_OUTPUT_CAP, capture};
    use std::io::Cursor;

    struct FiniteChild {
        events: Vec<&'static str>,
        status: Option<i32>,
        kill_error: Option<io::ErrorKind>,
    }

    impl ChildControl for FiniteChild {
        type Status = i32;
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            self.events.push("poll");
            Ok(self.status.take())
        }
        fn kill(&mut self) -> io::Result<()> {
            self.events.push("kill");
            self.kill_error.map_or(Ok(()), |kind| Err(kind.into()))
        }
        fn wait(&mut self) -> io::Result<i32> {
            self.events.push("wait");
            Ok(2)
        }
    }

    #[test]
    fn bounded_probe_deadline_contract_timeout_reaps_and_preserves_kill_error() {
        let now = Instant::now();
        for error in [None, Some(io::ErrorKind::PermissionDenied)] {
            let mut child = FiniteChild {
                events: Vec::new(),
                status: None,
                kill_error: error,
            };
            let result = wait_until(
                &mut child,
                now,
                || now,
                || panic!("expired probe cannot pause"),
            );
            assert_eq!(child.events, ["poll", "kill", "wait"]);
            match error {
                None => assert_eq!(result.unwrap(), (2, true)),
                Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
            }
        }
        let mut child = FiniteChild {
            events: Vec::new(),
            status: Some(2),
            kill_error: None,
        };
        assert_eq!(
            wait_until(
                &mut child,
                now + Duration::from_secs(1),
                || now,
                || panic!("completed child cannot pause")
            )
            .unwrap(),
            (2, false)
        );
        assert_eq!(child.events, ["poll"]);
    }

    #[test]
    fn bounded_probe_deadline_contract_capture_rejects_excess_and_split_secret() {
        let oversized = capture(Cursor::new(vec![b'x'; PROCESS_OUTPUT_CAP + 1]));
        let mut secret = vec![b'x'; 4090];
        secret.extend_from_slice(PSK.as_bytes());
        let secret = capture(Cursor::new(secret));
        let oversized = join_capture(oversized).expect("finite capture");
        let secret = join_capture(secret).expect("finite capture");
        assert_eq!(oversized.bytes.len(), PROCESS_OUTPUT_CAP);
        assert!(oversized.truncated);
        assert!(secret.secret);
        assert_eq!(
            validate_capture("probe", false, Ok(oversized), Ok(secret)).unwrap_err(),
            "probe output exceeded bound"
        );
    }

    #[test]
    fn bounded_probe_deadline_contract_capture_read_failure_is_closed() {
        struct FailedReader;
        impl std::io::Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other(PSK))
            }
        }
        let stdout = join_capture(capture(FailedReader));
        let stderr = join_capture(capture(Cursor::new(Vec::new())));
        assert_eq!(
            validate_capture("probe", false, stdout, stderr).unwrap_err(),
            "probe output capture read failed"
        );
    }

    #[test]
    fn bounded_probe_deadline_contract_preserves_bytes_and_first_failure() {
        let capture = |bytes: &[u8]| {
            Ok(Capture {
                bytes: bytes.to_vec(),
                truncated: false,
                secret: false,
                read_failed: false,
            })
        };
        assert_eq!(
            validate_capture("probe", false, capture(b""), capture(b"rejected\n")).unwrap(),
            (Vec::new(), b"rejected\n".to_vec())
        );
        assert_eq!(
            validate_capture("probe", true, Err(PSK.to_owned()), Err(PSK.to_owned())).unwrap_err(),
            "probe timed out"
        );
        assert_eq!(
            validate_capture("probe", false, Err(PSK.to_owned()), Err(PSK.to_owned())).unwrap_err(),
            "probe stdout capture failed"
        );
    }
}
