use std::fs::DirBuilder;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use zeroize::Zeroizing;

use crate::Direction;

mod probe;
mod writer;

const QUEUE_EVENTS: usize = 256;
const CHUNK_BYTES: usize = 32_768;
const RUNNING: u8 = 0;
const SHUTDOWN: u8 = 1;
const QUEUE_FULL: u8 = 2;
#[cfg(test)]
const SIZE_LIMIT: &str = "size_limit";
const WRITER_ERROR: u8 = 4;
const RESOURCE_LIMIT: u8 = 5;

/// Closed reason for the end of the network relay, not a free-form error chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndReason {
    Completed,
    Io,
    IdleTimeout,
    Cancelled,
}

impl EndReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Io => "io",
            Self::IdleTimeout => "idle_timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Final recording integrity, separate from whether the network relay succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingReport {
    pub complete: bool,
    pub reason: &'static str,
}

/// Owns one directory writer that opens a separate file for every matched flow.
/// Drop is a joining rollback safeguard, not a detached background worker.
pub struct Recording {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<io::Result<RecordingReport>>>,
    result: Option<Result<RecordingReport, io::ErrorKind>>,
}

impl Recording {
    pub fn start(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if max_bytes < 65_536 {
            return Err(closed_error(io::ErrorKind::InvalidInput));
        }
        let mut directory = DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            directory.mode(0o700);
        }
        directory
            .create(path)
            .map_err(|error| closed_error(error.kind()))?;
        let (sender, receiver) = sync_channel(QUEUE_EVENTS);
        let shared = Arc::new(Shared {
            sender,
            started: Instant::now(),
            status: AtomicU8::new(RUNNING),
            next_connection: AtomicU64::new(1),
        });
        let writer = writer::Writer::new(path.to_path_buf(), max_bytes, Arc::clone(&shared))?;
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("rocom-record".to_owned())
            .spawn(move || {
                let result = writer.run(receiver);
                if result.is_err() {
                    worker_shared.stop(WRITER_ERROR);
                }
                result
            })
            .map_err(|error| closed_error(error.kind()))?;
        Ok(Self {
            shared,
            worker: Some(worker),
            result: None,
        })
    }

    pub fn recorder(&self) -> Recorder {
        Recorder {
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn shutdown(&mut self) -> io::Result<RecordingReport> {
        self.shared.stop(SHUTDOWN);
        if let Some(worker) = self.worker.take() {
            self.result = Some(match worker.join() {
                Ok(Ok(report)) => Ok(report),
                Ok(Err(error)) => Err(error.kind()),
                Err(_) => Err(io::ErrorKind::Other),
            });
        }
        self.result
            .unwrap_or(Err(io::ErrorKind::Other))
            .map_err(closed_error)
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// A cheap handle; opening or observing after recording stops is a no-op.
#[derive(Clone)]
pub struct Recorder {
    shared: Arc<Shared>,
}

impl Recorder {
    pub fn open(&self, source: Option<String>, target: String) -> Capture {
        let connection_id = self.shared.next_connection.fetch_add(1, Ordering::Relaxed);
        if connection_id == u64::MAX
            || target.len() > 4096
            || source.as_ref().is_some_and(|value| value.len() > 4096)
        {
            self.shared.stop(RESOURCE_LIMIT);
        }
        let active = self.shared.active();
        Capture {
            shared: Arc::clone(&self.shared),
            connection_id,
            upload_offset: AtomicU64::new(0),
            download_offset: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            matched: AtomicBool::new(false),
            active: Arc::new(AtomicBool::new(active)),
            probe: Mutex::new(
                active.then(|| probe::Probe::new(source, target, self.shared.elapsed_us())),
            ),
        }
    }
}

/// One relay's bounded protocol probe and evidence producer. Finish only after
/// observations stop; same-direction observations must be serialized by its relay.
pub struct Capture {
    shared: Arc<Shared>,
    connection_id: u64,
    upload_offset: AtomicU64,
    download_offset: AtomicU64,
    finished: AtomicBool,
    matched: AtomicBool,
    active: Arc<AtomicBool>,
    probe: Mutex<Option<probe::Probe>>,
}

impl Capture {
    pub fn observe(&self, direction: Direction, bytes: &[u8]) {
        for chunk in bytes.chunks(CHUNK_BYTES) {
            if self.finished.load(Ordering::Acquire)
                || !self.active.load(Ordering::Acquire)
                || !self.shared.active()
            {
                return;
            }
            let offset = match direction {
                Direction::Upload => &self.upload_offset,
                Direction::Download => &self.download_offset,
            };
            let start = offset.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            if start.checked_add(chunk.len() as u64).is_none() {
                self.shared.stop(RESOURCE_LIMIT);
                return;
            }
            let elapsed_us = self.shared.elapsed_us();
            if self.matched.load(Ordering::Acquire) {
                self.shared.submit_at(
                    elapsed_us,
                    Event::Data {
                        connection_id: self.connection_id,
                        direction,
                        offset: start,
                        bytes: Zeroizing::new(chunk.to_vec()),
                    },
                );
                continue;
            }
            let mut state = self
                .probe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.finished.load(Ordering::Acquire) || !self.active.load(Ordering::Acquire) {
                return;
            }
            // The other direction may have completed classification while this
            // observation waited for the probe lock.
            if self.matched.load(Ordering::Acquire) {
                self.shared.submit_at(
                    elapsed_us,
                    Event::Data {
                        connection_id: self.connection_id,
                        direction,
                        offset: start,
                        bytes: Zeroizing::new(chunk.to_vec()),
                    },
                );
                continue;
            }
            let Some(probe) = state.as_mut() else {
                return;
            };
            match probe.observe(self.connection_id, direction, start, elapsed_us, chunk) {
                probe::Decision::Pending => {}
                probe::Decision::Rejected => {
                    self.active.store(false, Ordering::Release);
                    *state = None;
                    return;
                }
                probe::Decision::Matched => {
                    let probe = state.take().expect("matched probe owns prefix");
                    self.shared.submit_at(
                        probe.opened_us,
                        Event::Connection {
                            connection_id: self.connection_id,
                            source: probe.source,
                            target: probe.target,
                            active: Arc::clone(&self.active),
                        },
                    );
                    for queued in probe.pending {
                        self.shared.submit_at(queued.elapsed_us, queued.event);
                    }
                    self.matched.store(true, Ordering::Release);
                }
            }
        }
    }

    pub fn finish(&self, reason: EndReason) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            let mut probe = self
                .probe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *probe = None;
            if self.matched.load(Ordering::Acquire) {
                self.shared.submit_at(
                    self.shared.elapsed_us(),
                    Event::End {
                        connection_id: self.connection_id,
                        reason,
                    },
                );
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.finish(EndReason::Cancelled);
    }
}

struct Shared {
    sender: SyncSender<Queued>,
    started: Instant,
    status: AtomicU8,
    next_connection: AtomicU64,
}

impl Shared {
    fn active(&self) -> bool {
        self.status.load(Ordering::Acquire) == RUNNING
    }

    fn stop(&self, reason: u8) {
        let _ = self
            .status
            .compare_exchange(RUNNING, reason, Ordering::AcqRel, Ordering::Acquire);
    }

    fn elapsed_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn submit_at(&self, elapsed_us: u64, event: Event) {
        if !self.active() {
            return;
        }
        let queued = Queued { elapsed_us, event };
        match self.sender.try_send(queued) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.stop(QUEUE_FULL),
            Err(TrySendError::Disconnected(_)) => self.stop(WRITER_ERROR),
        }
    }
}

struct Queued {
    elapsed_us: u64,
    event: Event,
}

enum Event {
    Connection {
        connection_id: u64,
        source: Option<String>,
        target: String,
        active: Arc<AtomicBool>,
    },
    Data {
        connection_id: u64,
        direction: Direction,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    },
    End {
        connection_id: u64,
        reason: EndReason,
    },
}

fn closed_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "rocom recording failed")
}

#[cfg(test)]
mod tests;
