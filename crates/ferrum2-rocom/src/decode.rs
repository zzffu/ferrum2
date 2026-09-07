//! Offline, bounded replay of schema-1 captures. Raw handshakes, not derived
//! key records, drive crypto in observed byte order. Diagnostics are closed codes.
mod payload;
mod protobuf;
mod stream;

#[cfg(test)]
mod tests;

use crate::{Direction, KeySnapshot, KeyTracker, Record, RecordEvent, keys::KeyState};
use base64::{Engine, engine::general_purpose::STANDARD};
use protobuf::Schemas;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};
use stream::{Context, Stream};
use zeroize::Zeroizing;

const MAX_LINE: usize = 128 * 1024;
const MAX_ACTIVE: usize = 1024;
const MAX_BUFFERED: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Error(pub(crate) &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}

#[derive(Default, Debug)]
pub struct Report {
    pub records: u64,
    pub messages: u64,
    pub failed: u64,
    pub integrity_errors: u64,
    pub complete: bool,
}
impl Report {
    pub fn exit_code(&self) -> u8 {
        if self.complete && self.failed == 0 && self.integrity_errors == 0 {
            0
        } else {
            2
        }
    }
}
#[derive(Default)]
struct Session {
    upload: Stream,
    download: Stream,
    keys: KeyState,
    tracker: KeyTracker,
    offsets: [u64; 2],
    rejected: [bool; 2],
}
impl Session {
    fn finish(
        &mut self,
        id: u64,
        event: u64,
        schemas: Option<&Schemas>,
        output: &mut impl Write,
        report: &mut Report,
    ) -> Result<(), Error> {
        for (direction, stream) in [
            (Direction::Upload, &mut self.upload),
            (Direction::Download, &mut self.download),
        ] {
            stream.finish(
                &Context {
                    connection: id,
                    direction,
                    event,
                    schemas,
                    capacity_limit: 0,
                },
                output,
                report,
            )?;
        }
        Ok(())
    }
}

/// Input is read-only and output is create-new. Fatal errors never include paths,
/// schema diagnostics, keys, or payloads. A usable partial report has exit code 2.
pub fn run(input: &Path, output: &Path, proto_dir: Option<&Path>) -> Result<Report, Error> {
    let schemas = proto_dir.map(Schemas::load).transpose()?;
    let mut input = File::open(input).map_err(|_| Error("input_open"))?;
    if !input
        .metadata()
        .map_err(|_| Error("input_metadata"))?
        .is_file()
    {
        return Err(Error("input_not_regular"));
    }
    let (digest, size) = digest_file(&mut input)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error("input_seek"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(output).map_err(|_| Error("output_create"))?;
    let mut output = BufWriter::new(file);
    emit(
        &mut output,
        &json!({"kind":"decoder","decoder":"ferrum2-rocom-decode","decoder_version":env!("CARGO_PKG_VERSION"),
        "decoder_schema":1,"decoder_revision":"gcp21-method3-evidence-v1","source_schema":1,"input_sha256":digest,"input_bytes":size,
        "named_schemas":schemas.is_some(),"schema_sha256":schemas.as_ref().map(|schemas| &schemas.digest)}),
    )?;
    let mut reader = BufReader::new(input);
    let mut report = Report::default();
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let mut buffered_capacity = 0usize;
    let mut seen = HashSet::new();
    let mut expected = 1u64;
    let mut started = false;
    let mut stopped = false;
    let mut source_complete = false;
    let mut pending: VecDeque<(u64, KeySnapshot)> = VecDeque::new();
    let mut line = Zeroizing::new(Vec::new());
    let mut replay_digest = Sha256::new();
    loop {
        line.clear();
        let count = reader
            .by_ref()
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| Error("input_read"))?;
        if count == 0 {
            break;
        }
        replay_digest.update(&*line);
        if count > MAX_LINE {
            integrity(&mut output, &mut report, expected, "record_limit")?;
            break;
        }
        if line.last() != Some(&b'\n') {
            integrity(&mut output, &mut report, expected, "truncated_record")?;
            break;
        }
        let record: Record = match serde_json::from_slice(&line) {
            Ok(record) => record,
            Err(_) => {
                integrity(&mut output, &mut report, expected, "invalid_record")?;
                break;
            }
        };
        report.records += 1;
        if record.schema_version != 1 || record.event_seq != expected || stopped {
            integrity(&mut output, &mut report, expected, "record_order_or_schema")?;
            break;
        }
        expected = expected.checked_add(1).ok_or(Error("sequence_limit"))?;
        if !started && !matches!(&record.event, RecordEvent::Started { .. }) {
            integrity(&mut output, &mut report, record.event_seq, "missing_start")?;
            break;
        }
        if !pending.is_empty() && !matches!(&record.event, RecordEvent::Key { .. }) {
            integrity(
                &mut output,
                &mut report,
                record.event_seq,
                "missing_key_evidence",
            )?;
            pending.clear();
        }
        match record.event {
            RecordEvent::Started { max_bytes } => {
                if started || max_bytes < 65536 || size > max_bytes {
                    integrity(&mut output, &mut report, record.event_seq, "invalid_start")?;
                    break;
                }
                started = true;
            }
            RecordEvent::Connection {
                connection_id,
                source: _,
                target: _,
            } => {
                if connection_id == 0
                    || seen.len() >= 1_000_000
                    || !seen.insert(connection_id)
                    || sessions.len() >= MAX_ACTIVE
                {
                    integrity(
                        &mut output,
                        &mut report,
                        record.event_seq,
                        "connection_identity_or_limit",
                    )?;
                    break;
                }
                sessions.insert(connection_id, Session::default());
            }
            RecordEvent::Data {
                connection_id,
                direction,
                offset,
                bytes,
            } => {
                let Some(session) = sessions.get_mut(&connection_id) else {
                    integrity(&mut output, &mut report, record.event_seq, "data_lifecycle")?;
                    report.messages += 1;
                    report.failed += 1;
                    emit(
                        &mut output,
                        &json!({"kind":"message","connection_id":connection_id,"direction":direction,
                        "stream_offset":offset,"source_event":record.event_seq,"status":"failed","failure_stage":"source",
                        "failure_code":"data_lifecycle","raw_encoded":bytes}),
                    )?;
                    continue;
                };
                let index = match direction {
                    Direction::Upload => 0,
                    Direction::Download => 1,
                };
                let stream = match direction {
                    Direction::Upload => &mut session.upload,
                    Direction::Download => &mut session.download,
                };
                let before = stream.buffer.capacity();
                let context = Context {
                    connection: connection_id,
                    direction,
                    event: record.event_seq,
                    schemas: schemas.as_ref(),
                    capacity_limit: MAX_BUFFERED - (buffered_capacity - before),
                };
                let decoded = match STANDARD.decode(&bytes) {
                    Ok(bytes) if !bytes.is_empty() && bytes.len() <= 32768 => Zeroizing::new(bytes),
                    _ => {
                        integrity(
                            &mut output,
                            &mut report,
                            record.event_seq,
                            "invalid_data_bytes",
                        )?;
                        stream.reject(
                            &[],
                            offset,
                            "invalid_data_bytes",
                            &context,
                            &mut output,
                            &mut report,
                        )?;
                        emit(
                            &mut output,
                            &json!({"kind":"source_bytes","connection_id":connection_id,"direction":direction,
                            "stream_offset":offset,"source_event":record.event_seq,"raw_encoded":bytes}),
                        )?;
                        session.rejected[index] = true;
                        session.keys = KeyState::default();
                        buffered_capacity = buffered_capacity - before + stream.buffer.capacity();
                        continue;
                    }
                };
                if !session.rejected[index] && offset != session.offsets[index] {
                    integrity(&mut output, &mut report, record.event_seq, "offset_gap")?;
                    stream.reject(
                        &decoded,
                        offset,
                        "offset_gap",
                        &context,
                        &mut output,
                        &mut report,
                    )?;
                    session.rejected[index] = true;
                    session.keys = KeyState::default();
                } else {
                    if !session.rejected[index] {
                        pending.extend(
                            session
                                .tracker
                                .observe(direction, &decoded)
                                .into_iter()
                                .map(|key| (connection_id, key)),
                        );
                    }
                    if session.rejected[index] {
                        stream.offset = offset;
                    }
                    stream.feed(
                        &decoded,
                        &mut session.keys,
                        &context,
                        &mut output,
                        &mut report,
                    )?;
                }
                session.offsets[index] = offset
                    .checked_add(decoded.len() as u64)
                    .ok_or(Error("offset_limit"))?;
                buffered_capacity = buffered_capacity - before + stream.buffer.capacity();
            }
            RecordEvent::Key {
                connection_id,
                direction,
                offset,
                key_method,
                enc_method,
                source_sequence,
                key_hex,
            } => {
                let valid = pending.pop_front().is_some_and(|(id, key)| {
                    id == connection_id
                        && key.direction == direction
                        && key.offset == offset
                        && key.key_method == key_method
                        && key.enc_method == enc_method
                        && key.source_sequence == source_sequence
                        && key.key_hex == key_hex
                });
                if !valid {
                    integrity(
                        &mut output,
                        &mut report,
                        record.event_seq,
                        "key_evidence_mismatch",
                    )?;
                }
                emit(
                    &mut output,
                    &json!({"kind":"key_evidence","source_event":record.event_seq,"connection_id":connection_id,"direction":direction,"stream_offset":offset,"key_method":key_method,"enc_method":enc_method,"source_sequence":source_sequence,"key_hex":key_hex,"verified":valid}),
                )?;
            }
            RecordEvent::End {
                connection_id,
                reason,
            } => {
                if !["completed", "io", "idle_timeout", "cancelled"].contains(&reason.as_str()) {
                    integrity(
                        &mut output,
                        &mut report,
                        record.event_seq,
                        "invalid_end_reason",
                    )?;
                }
                let Some(mut session) = sessions.remove(&connection_id) else {
                    integrity(&mut output, &mut report, record.event_seq, "end_lifecycle")?;
                    break;
                };
                buffered_capacity -=
                    session.upload.buffer.capacity() + session.download.buffer.capacity();
                session.finish(
                    connection_id,
                    record.event_seq,
                    schemas.as_ref(),
                    &mut output,
                    &mut report,
                )?;
            }
            RecordEvent::Stopped { complete, reason } => {
                stopped = true;
                source_complete = complete && reason == "shutdown" && sessions.is_empty();
                if ![
                    "shutdown",
                    "queue_full",
                    "size_limit",
                    "writer_error",
                    "resource_limit",
                    "open_connections",
                ]
                .contains(&reason.as_str())
                    || (complete && !source_complete)
                {
                    integrity(&mut output, &mut report, record.event_seq, "invalid_footer")?;
                }
            }
        }
    }
    if hex::encode(replay_digest.finalize()) != digest {
        integrity(
            &mut output,
            &mut report,
            expected,
            "input_digest_mismatch_or_unread_tail",
        )?;
    }
    if !started || !stopped {
        integrity(&mut output, &mut report, expected, "missing_footer")?;
    }
    if !pending.is_empty() {
        integrity(&mut output, &mut report, expected, "missing_key_evidence")?;
    }
    for (id, mut session) in sessions {
        session.finish(id, expected, schemas.as_ref(), &mut output, &mut report)?;
    }
    report.complete = source_complete && report.integrity_errors == 0;
    emit(
        &mut output,
        &json!({"kind":"summary","records":report.records,"messages":report.messages,"failed":report.failed,
        "integrity_errors":report.integrity_errors,"source_complete":report.complete,"input_sha256":digest,"exit_code":report.exit_code()}),
    )?;
    output.flush().map_err(|_| Error("output_write"))?;
    output
        .get_ref()
        .sync_all()
        .map_err(|_| Error("output_sync"))?;
    Ok(report)
}
fn digest_file(file: &mut File) -> Result<(String, u64), Error> {
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; 32768]);
    let mut size = 0u64;
    loop {
        let count = file.read(&mut *buffer).map_err(|_| Error("input_read"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size = size.checked_add(count as u64).ok_or(Error("input_limit"))?;
    }
    Ok((hex::encode(digest.finalize()), size))
}
fn emit(output: &mut impl Write, value: &Value) -> Result<(), Error> {
    serde_json::to_writer(&mut *output, value).map_err(|_| Error("output_write"))?;
    output.write_all(b"\n").map_err(|_| Error("output_write"))
}
fn integrity(
    output: &mut impl Write,
    report: &mut Report,
    event: u64,
    code: &'static str,
) -> Result<(), Error> {
    report.integrity_errors += 1;
    emit(
        output,
        &json!({"kind":"source_integrity","source_event":event,"failure_code":code}),
    )
}
