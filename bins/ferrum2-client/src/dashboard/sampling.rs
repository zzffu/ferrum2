use std::io::{self, Write};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use ferrum2_dashboard::Dashboard;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::watch;

pub(super) fn log_level(value: &std::sync::atomic::AtomicU8) -> ferrum2_observability::LogLevel {
    use ferrum2_observability::LogLevel;
    match value.load(std::sync::atomic::Ordering::Relaxed) {
        level if level == LogLevel::Error as u8 => LogLevel::Error,
        level if level == LogLevel::Warn as u8 => LogLevel::Warn,
        level if level == LogLevel::Info as u8 => LogLevel::Info,
        level if level == LogLevel::Debug as u8 => LogLevel::Debug,
        level if level == LogLevel::Trace as u8 => LogLevel::Trace,
        _ => unreachable!("only validated log levels enter the process filter"),
    }
}

pub(super) async fn run(
    dashboard: Dashboard,
    snapshot: Arc<RwLock<Bytes>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    let mut system = System::new();
    let pid = sysinfo::get_current_pid().map_err(|_| "dashboard.process")?;
    let mut sample = tokio::time::interval(Duration::from_secs(1));
    sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut primed = false;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = sample.tick() => {
                system.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[pid]), true,
                    ProcessRefreshKind::nothing().with_cpu().with_memory(),
                );
                if let Some(process) = system.process(pid) {
                    dashboard.set_process(primed.then(|| f64::from(process.cpu_usage())), Some(process.memory()));
                    primed = true;
                } else { dashboard.set_process(None, None); }
                dashboard.sample();
                let encoded = Bytes::from(dashboard.snapshot().to_string());
                *snapshot.write().unwrap_or_else(std::sync::PoisonError::into_inner) = encoded;
            }
        }
    }
    Ok(())
}

/// Receives only the shared subscriber's already allowlisted JSON output.
/// The bounded tee never replaces or widens ordinary stderr diagnostics.
pub(super) struct LogWriter {
    dashboard: Dashboard,
    buffer: Vec<u8>,
    overflow: bool,
}

impl LogWriter {
    pub(super) fn new(dashboard: Dashboard) -> Self {
        Self {
            dashboard,
            buffer: Vec::new(),
            overflow: false,
        }
    }

    fn finish_line(&mut self) {
        if !self.overflow
            && let Ok(event) = serde_json::from_slice(&self.buffer)
        {
            self.dashboard.record_log(event);
        }
        self.buffer.clear();
        self.overflow = false;
    }
}

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // The in-memory sink remains useful when a detached launch has no writable stderr.
        let _ = io::stderr().write_all(bytes);
        for byte in bytes {
            if *byte == b'\n' {
                self.finish_line();
            } else if self.buffer.len() < 16 * 1024 {
                self.buffer.push(*byte);
            } else {
                self.overflow = true;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            self.finish_line();
        }
    }
}
