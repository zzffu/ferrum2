use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{KeyTracker, Record, RecordEvent};

use super::{Event, Queued, RecordingReport, Shared, closed_error};
use super::{QUEUE_FULL, RESOURCE_LIMIT, RUNNING, SHUTDOWN, WRITER_ERROR};

const FOOTER_RESERVE: u64 = 1024;
const MAX_CONNECTIONS: usize = 65_536;
const ENCODING_BYTES: usize = 65_536;
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub(super) struct Writer {
    directory: PathBuf,
    run: String,
    max_bytes: u64,
    shared: Arc<Shared>,
    encoded: Zeroizing<Vec<u8>>,
    // None is a small tombstone: queued data is ignored until End arrives.
    files: HashMap<u64, Option<Box<ConnectionFile>>>,
    incomplete: Option<&'static str>,
    first_error: Option<io::ErrorKind>,
}

struct ConnectionFile {
    output: File,
    active: Arc<AtomicBool>,
    bytes_written: u64,
    event_seq: u64,
    keys: KeyTracker,
}

impl Writer {
    pub(super) fn new(directory: PathBuf, max_bytes: u64, shared: Arc<Shared>) -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| closed_error(io::ErrorKind::Other))?
            .as_nanos();
        let process = std::process::id();
        let run = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            directory,
            run: format!("{timestamp}-{process}-{run}"),
            max_bytes,
            shared,
            encoded: Zeroizing::new(Vec::with_capacity(ENCODING_BYTES)),
            files: HashMap::new(),
            incomplete: None,
            first_error: None,
        })
    }

    pub(super) fn run(mut self, receiver: Receiver<Queued>) -> io::Result<RecordingReport> {
        loop {
            let queued = if self.shared.active() {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => Some(event),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => {
                        self.shared.stop(WRITER_ERROR);
                        None
                    }
                }
            } else {
                match receiver.try_recv() {
                    Ok(event) => Some(event),
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            };
            if let Some(queued) = queued {
                self.write_queued(queued);
            }
        }
        let reason = self.stop_reason();
        if reason != "shutdown" {
            self.incomplete.get_or_insert(reason);
        }
        let elapsed_us = self.shared.elapsed_us();
        for mut file in std::mem::take(&mut self.files).into_values().flatten() {
            let reason = if reason == "shutdown" {
                "open_connections"
            } else {
                reason
            };
            self.incomplete.get_or_insert(reason);
            self.close_file(&mut file, elapsed_us, false, reason);
        }
        if let Some(kind) = self.first_error {
            return Err(closed_error(kind));
        }
        Ok(RecordingReport {
            complete: self.incomplete.is_none(),
            reason: self.incomplete.unwrap_or("shutdown"),
        })
    }

    fn stop_reason(&self) -> &'static str {
        match self.shared.status.load(Ordering::Acquire) {
            RUNNING | SHUTDOWN => "shutdown",
            QUEUE_FULL => "queue_full",
            WRITER_ERROR => "writer_error",
            RESOURCE_LIMIT => "resource_limit",
            _ => unreachable!("closed recorder stop state"),
        }
    }

    fn open_file(&self, connection_id: u64, active: Arc<AtomicBool>) -> io::Result<ConnectionFile> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            options.share_mode(0);
        }
        // create_new is the final authority even after clock rollback/PID reuse,
        // or when a previous run's name was deliberately pre-created.
        let mut collision = 0u64;
        let output = loop {
            let name = format!("tsf4g-{}-{connection_id}-{collision}.jsonl", self.run);
            match options.open(self.directory.join(name)) {
                Ok(file) => break file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    collision = collision
                        .checked_add(1)
                        .ok_or_else(|| closed_error(io::ErrorKind::AlreadyExists))?;
                }
                Err(error) => return Err(closed_error(error.kind())),
            }
        };
        Ok(ConnectionFile {
            output,
            active,
            bytes_written: 0,
            event_seq: 0,
            keys: KeyTracker::new(),
        })
    }

    fn write_queued(&mut self, queued: Queued) {
        let elapsed_us = queued.elapsed_us;
        match queued.event {
            Event::Connection {
                connection_id,
                source,
                target,
                active,
            } => {
                if self.files.len() >= MAX_CONNECTIONS || self.files.try_reserve(1).is_err() {
                    active.store(false, Ordering::Release);
                    self.shared.stop(RESOURCE_LIMIT);
                    self.incomplete.get_or_insert("resource_limit");
                    return;
                }
                self.files.insert(connection_id, None);
                let mut file = match self.open_file(connection_id, Arc::clone(&active)) {
                    Ok(file) => Box::new(file),
                    Err(error) => {
                        active.store(false, Ordering::Release);
                        self.file_error(error);
                        return;
                    }
                };
                let max_bytes = self.max_bytes;
                if self.record(&mut file, 0, RecordEvent::Started { max_bytes })
                    && self.record(
                        &mut file,
                        elapsed_us,
                        RecordEvent::Connection {
                            connection_id,
                            source,
                            target,
                        },
                    )
                {
                    *self.files.get_mut(&connection_id).expect("registered file") = Some(file);
                }
            }
            Event::Data {
                connection_id,
                direction,
                offset,
                bytes,
            } => {
                let Some(mut file) = self.files.get_mut(&connection_id).and_then(Option::take)
                else {
                    return;
                };
                if !self.record(
                    &mut file,
                    elapsed_us,
                    RecordEvent::Data {
                        connection_id,
                        direction,
                        offset,
                        bytes: STANDARD.encode(&*bytes),
                    },
                ) {
                    return;
                }
                // Keep raw evidence before parser-derived metadata, even when
                // the parser permanently stops interpreting malformed traffic.
                for mut snapshot in file.keys.observe(direction, &bytes) {
                    if !self.record(
                        &mut file,
                        elapsed_us,
                        RecordEvent::Key {
                            connection_id,
                            direction: snapshot.direction,
                            offset: snapshot.offset,
                            key_method: snapshot.key_method,
                            enc_method: snapshot.enc_method,
                            source_sequence: snapshot.source_sequence,
                            key_hex: snapshot.key_hex.take(),
                        },
                    ) {
                        return;
                    }
                }
                *self.files.get_mut(&connection_id).expect("registered file") = Some(file);
            }
            Event::End {
                connection_id,
                reason,
            } => {
                let Some(Some(mut file)) = self.files.remove(&connection_id) else {
                    return;
                };
                if self.record(
                    &mut file,
                    elapsed_us,
                    RecordEvent::End {
                        connection_id,
                        reason: reason.as_str().to_owned(),
                    },
                ) {
                    let reason = self.stop_reason();
                    let complete = reason == "shutdown";
                    if !complete {
                        self.incomplete.get_or_insert(reason);
                    }
                    self.close_file(&mut file, elapsed_us, complete, reason);
                }
            }
        }
    }

    fn file_error(&mut self, error: io::Error) {
        self.first_error.get_or_insert(error.kind());
        self.incomplete.get_or_insert("writer_error");
    }

    fn record(&mut self, file: &mut ConnectionFile, elapsed_us: u64, event: RecordEvent) -> bool {
        match file.write_event(
            &mut self.encoded,
            elapsed_us,
            event,
            self.max_bytes - FOOTER_RESERVE,
        ) {
            Ok(true) => true,
            Ok(false) => {
                self.incomplete.get_or_insert("size_limit");
                self.close_file(file, elapsed_us, false, "size_limit");
                false
            }
            Err(error) => {
                file.active.store(false, Ordering::Release);
                // Never append a footer after a potentially torn JSON line.
                self.file_error(error);
                false
            }
        }
    }

    fn close_file(
        &mut self,
        file: &mut ConnectionFile,
        elapsed_us: u64,
        complete: bool,
        reason: &'static str,
    ) {
        file.active.store(false, Ordering::Release);
        let result = file.write_event(
            &mut self.encoded,
            elapsed_us,
            RecordEvent::Stopped {
                complete,
                reason: reason.to_owned(),
            },
            self.max_bytes,
        );
        match result {
            Ok(true) => {
                if let Err(error) = file.output.sync_all() {
                    self.file_error(error);
                }
            }
            Ok(false) => self.file_error(closed_error(io::ErrorKind::WriteZero)),
            Err(error) => self.file_error(error),
        }
    }
}

impl ConnectionFile {
    fn write_event(
        &mut self,
        encoded: &mut Vec<u8>,
        elapsed_us: u64,
        event: RecordEvent,
        limit: u64,
    ) -> io::Result<bool> {
        let next = self
            .event_seq
            .checked_add(1)
            .ok_or_else(|| closed_error(io::ErrorKind::Other))?;
        let mut record = Record {
            schema_version: 1,
            event_seq: next,
            elapsed_us,
            event,
        };
        encoded.zeroize();
        let result = serde_json::to_writer(&mut EncodingBuffer(encoded), &record);
        match &mut record.event {
            RecordEvent::Data { bytes, .. } => bytes.zeroize(),
            RecordEvent::Key {
                key_hex: Some(key), ..
            } => key.zeroize(),
            RecordEvent::Started { .. }
            | RecordEvent::Connection { .. }
            | RecordEvent::Key { key_hex: None, .. }
            | RecordEvent::End { .. }
            | RecordEvent::Stopped { .. } => {}
        }
        if result.is_err() {
            encoded.zeroize();
            return Err(closed_error(io::ErrorKind::InvalidData));
        }
        encoded.push(b'\n');
        let size = encoded.len() as u64;
        if size > limit.saturating_sub(self.bytes_written) {
            encoded.zeroize();
            return Ok(false);
        }
        let result = self.output.write_all(encoded);
        encoded.zeroize();
        result.map_err(|error| closed_error(error.kind()))?;
        self.bytes_written += size;
        self.event_seq = next;
        Ok(true)
    }
}

// One reusable, strictly bounded allocation for every connection's JSON.
// Reserve one byte for the newline appended after serialization.
struct EncodingBuffer<'a>(&'a mut Vec<u8>);

impl Write for EncodingBuffer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > (ENCODING_BYTES - 1).saturating_sub(self.0.len()) {
            return Err(closed_error(io::ErrorKind::InvalidData));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
