use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::{ObservedIo, Record, RecordEvent};

fn packet(command: u16, extension: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for number in [0x3366_u16, 1, 1, command] {
        bytes.extend_from_slice(&number.to_be_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(21 + extension.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(extension);
    bytes
}

fn paths(directory: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect()
}

fn records(path: &Path) -> Vec<Record> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn recorded_bytes(records: &[Record], wanted: Direction) -> Vec<u8> {
    let mut output = Vec::new();
    for record in records {
        if let RecordEvent::Data {
            direction,
            offset,
            bytes,
            ..
        } = &record.event
            && *direction == wanted
        {
            assert_eq!(*offset, output.len() as u64);
            output.extend(STANDARD.decode(bytes).unwrap());
        }
    }
    output
}

fn complete_records(directory: &Path, count: usize) -> Vec<Vec<Record>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let paths = paths(directory);
        let parsed: Option<Vec<Vec<Record>>> = paths
            .iter()
            .map(|path| {
                let text = fs::read_to_string(path).ok()?;
                text.lines()
                    .map(|line| serde_json::from_str(line).ok())
                    .collect()
            })
            .collect();
        if let Some(parsed) = parsed
            && parsed.len() == count
            && parsed.iter().all(|records| {
                matches!(
                    records.last().map(|r| &r.event),
                    Some(RecordEvent::Stopped { .. })
                )
            })
        {
            return parsed;
        }
        assert!(
            Instant::now() < deadline,
            "matched connection files were not finalized"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test]
async fn observed_reads_preserve_half_close_and_both_direction_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("new/captures");
    let mut recording = Recording::start(&directory, 1_048_576).unwrap();
    let capture = recording.recorder().open(None, "synthetic".to_owned());
    let request = packet(0x1001, &[2, 3]);
    let response = packet(
        0x1002,
        &[2, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    );
    let (mut application, mut proxy) = tokio::io::duplex(32);
    let (mut upstream, mut server) = tokio::io::duplex(32);
    let application_exchange = async {
        application.write_all(&request[..1]).await.unwrap();
        application.write_all(&request[1..]).await.unwrap();
        application.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        application.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, response);
    };
    let server_exchange = async {
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, request);
        server.write_all(&response).await.unwrap();
        server.shutdown().await.unwrap();
    };
    let relay = async {
        tokio::io::copy_bidirectional(
            &mut ObservedIo::new(&mut proxy, &capture, Direction::Upload),
            &mut ObservedIo::new(&mut upstream, &capture, Direction::Download),
        )
        .await
        .unwrap();
    };
    tokio::join!(application_exchange, server_exchange, relay);
    capture.finish(EndReason::Completed);
    let files = complete_records(&directory, 1);
    assert_eq!(recorded_bytes(&files[0], Direction::Upload), request);
    assert_eq!(recorded_bytes(&files[0], Direction::Download), response);
    assert!(recording.shutdown().unwrap().complete);
}

#[test]
fn split_prefixes_and_subsequent_unknown_bytes_survive_for_every_matched_connection() {
    let directory = tempfile::tempdir().unwrap();
    let mut recording = Recording::start(directory.path(), 1_048_576).unwrap();
    let recorder = recording.recorder();
    let first = recorder.open(None, "first".to_owned());
    let second = recorder.open(None, "second".to_owned());
    let syn = packet(0x1001, &[2, 3]);
    let ack = packet(
        0x1002,
        &[2, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    );
    first.observe(Direction::Upload, &syn[..2]);
    first.observe(Direction::Download, &ack[..1]);
    assert!(paths(directory.path()).is_empty());
    second.observe(Direction::Download, &ack);
    first.observe(Direction::Upload, &syn[2..]);
    first.observe(Direction::Download, &ack[1..]);
    first.observe(Direction::Upload, b"unrecognized tail after identification");
    second.finish(EndReason::Completed);
    first.finish(EndReason::Completed);
    let files = complete_records(directory.path(), 2);
    assert_eq!(files.len(), 2);
    for records in files {
        let identities: Vec<_> = records
            .iter()
            .filter_map(|record| match &record.event {
                RecordEvent::Connection {
                    connection_id,
                    target,
                    ..
                } => Some((*connection_id, target.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(identities.len(), 1);
        let expected = if identities[0].1 == "first" {
            let mut bytes = syn.clone();
            bytes.extend_from_slice(b"unrecognized tail after identification");
            bytes
        } else {
            Vec::new()
        };
        assert_eq!(recorded_bytes(&records, Direction::Upload), expected);
        assert_eq!(recorded_bytes(&records, Direction::Download), ack);
        assert!(records.iter().any(|r| matches!(&r.event, RecordEvent::Key { key_hex: Some(key), .. } if key == "000102030405060708090a0b0c0d0e0f")));
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record.event_seq, index as u64 + 1);
        }
    }
    assert!(recording.shutdown().unwrap().complete);
}

#[test]
fn ordinary_invalid_and_unidentified_connections_never_create_files() {
    let directory = tempfile::tempdir().unwrap();
    let mut recording = Recording::start(directory.path(), 65_536).unwrap();
    let recorder = recording.recorder();
    let ordinary = recorder.open(None, "http".to_owned());
    ordinary.observe(Direction::Upload, b"GET / HTTP/1.1\r\n");
    ordinary.observe(Direction::Download, &packet(0x1002, &[2, 16]));
    ordinary.finish(EndReason::Completed);
    let invalid = recorder.open(None, "invalid".to_owned());
    let mut header = packet(0x1001, &[2, 3]);
    header[8] = 2;
    invalid.observe(Direction::Upload, &header);
    invalid.finish(EndReason::Completed);
    let incomplete = recorder.open(None, "incomplete".to_owned());
    incomplete.observe(Direction::Upload, &[0x33]);
    drop(incomplete);
    assert!(recording.shutdown().unwrap().complete);
    assert!(paths(directory.path()).is_empty());
}

#[test]
fn per_file_limit_does_not_stop_another_connection_or_overwrite_previous_runs() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = directory.path().join("existing.jsonl");
    fs::write(&sentinel, b"unrelated existing file").unwrap();
    let mut recording = Recording::start(directory.path(), 65_536).unwrap();
    let recorder = recording.recorder();
    let first = recorder.open(None, "capped".to_owned());
    let syn = packet(0x1001, &[2, 3]);
    first.observe(Direction::Upload, &syn);
    first.observe(Direction::Upload, &[0x5a; 65_536]);
    first.finish(EndReason::Completed);
    let second = recorder.open(None, "following".to_owned());
    second.observe(Direction::Upload, &syn);
    second.finish(EndReason::Completed);
    assert_eq!(
        recording.shutdown().unwrap(),
        RecordingReport {
            complete: false,
            reason: SIZE_LIMIT
        }
    );
    let files: Vec<_> = paths(directory.path())
        .into_iter()
        .filter(|path| *path != sentinel)
        .collect();
    assert_eq!(files.len(), 2);
    let mut saw_capped = false;
    let mut saw_following = false;
    for path in &files {
        assert!(fs::metadata(path).unwrap().len() <= 65_536);
        let records = records(path);
        match &records.last().unwrap().event {
            RecordEvent::Stopped {
                complete: false,
                reason,
            } if reason == "size_limit" => saw_capped = true,
            RecordEvent::Stopped { complete: true, .. } => {
                saw_following = true;
                assert_eq!(recorded_bytes(&records, Direction::Upload), syn);
            }
            _ => panic!("unexpected file integrity"),
        }
    }
    assert!(saw_capped && saw_following);
    let before: Vec<_> = files.iter().map(|path| fs::read(path).unwrap()).collect();
    let mut next = Recording::start(directory.path(), 65_536).unwrap();
    let third = next.recorder().open(None, "new run".to_owned());
    third.observe(Direction::Upload, &syn);
    third.finish(EndReason::Completed);
    assert!(next.shutdown().unwrap().complete);
    assert_eq!(paths(directory.path()).len(), 4);
    for (path, original) in files.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), original);
    }
    assert_eq!(fs::read(sentinel).unwrap(), b"unrelated existing file");
}

#[test]
fn bounded_queue_overflow_is_visible_for_selected_connection() {
    let directory = tempfile::tempdir().unwrap();
    let (sender, receiver) = sync_channel(2);
    let shared = Arc::new(Shared {
        sender,
        started: Instant::now(),
        status: AtomicU8::new(RUNNING),
        next_connection: AtomicU64::new(1),
    });
    let writer =
        writer::Writer::new(directory.path().to_path_buf(), 65_536, Arc::clone(&shared)).unwrap();
    let recorder = Recorder { shared };
    let capture = recorder.open(None, "synthetic".to_owned());
    let syn = packet(0x1001, &[2, 3]);
    capture.observe(Direction::Upload, &syn);
    capture.observe(Direction::Upload, b"lost");
    capture.finish(EndReason::Completed);
    let report = writer.run(receiver).unwrap();
    assert_eq!(
        report,
        RecordingReport {
            complete: false,
            reason: "queue_full"
        }
    );
    let paths = paths(directory.path());
    assert_eq!(paths.len(), 1);
    let records = records(&paths[0]);
    assert_eq!(recorded_bytes(&records, Direction::Upload), syn);
    assert!(
        matches!(&records.last().unwrap().event, RecordEvent::Stopped { complete: false, reason } if reason == "queue_full")
    );
}

#[test]
fn shutdown_marks_unfinished_selected_capture_and_rejects_file_as_directory() {
    let directory = tempfile::tempdir().unwrap();
    let existing = directory.path().join("not-a-directory");
    fs::write(&existing, b"untouched").unwrap();
    assert!(Recording::start(&existing, 65_536).is_err());
    assert_eq!(fs::read(&existing).unwrap(), b"untouched");
    let mut recording = Recording::start(directory.path(), 65_536).unwrap();
    let capture = recording.recorder().open(None, "synthetic".to_owned());
    capture.observe(Direction::Upload, &packet(0x1001, &[2, 3]));
    let report = recording.shutdown().unwrap();
    assert_eq!(
        report,
        RecordingReport {
            complete: false,
            reason: "open_connections"
        }
    );
    let path = paths(directory.path()).pop().unwrap();
    let before = fs::read(&path).unwrap();
    capture.observe(Direction::Upload, b"after shutdown");
    capture.finish(EndReason::Completed);
    assert_eq!(recording.shutdown().unwrap(), report);
    assert_eq!(fs::read(path).unwrap(), before);
}
