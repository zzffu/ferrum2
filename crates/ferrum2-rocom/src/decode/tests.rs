use super::*;
use crate::wire;
use aes::{
    Aes128,
    cipher::{Block, BlockCipherEncrypt, KeyInit},
};

fn packet(command: u16, extension: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x33, 0x66, 0, 1, 0, 1];
    bytes.extend_from_slice(&command.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&((21 + extension.len()) as u32).to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(extension);
    bytes.extend_from_slice(body);
    bytes
}
fn encrypted(payload: &[u8]) -> Vec<u8> {
    encrypted_key(payload, &[7; 16])
}
fn encrypted_key(payload: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes.extend_from_slice(payload);
    let trim = 6 + (16 - ((bytes.len() + 6) % 16)) % 16;
    bytes.resize(bytes.len() + trim, 0);
    let n = bytes.len();
    bytes[n - 6..n - 1].copy_from_slice(b"tsf4g");
    bytes[n - 1] = trim as u8;
    let cipher = Aes128::new(key.into());
    let mut previous = [0; 16];
    for chunk in bytes.chunks_exact_mut(16) {
        let mut block = Block::<Aes128>::default();
        for index in 0..16 {
            block[index] = chunk[index] ^ previous[index];
        }
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        previous.copy_from_slice(&block);
    }
    bytes
}
fn event(events: &mut Vec<Record>, value: RecordEvent) {
    events.push(Record {
        schema_version: 1,
        event_seq: events.len() as u64 + 1,
        elapsed_us: 0,
        event: value,
    });
}
fn data(
    events: &mut Vec<Record>,
    tracker: &mut KeyTracker,
    direction: Direction,
    offset: u64,
    bytes: &[u8],
) {
    event(
        events,
        RecordEvent::Data {
            connection_id: 1,
            direction,
            offset,
            bytes: STANDARD.encode(bytes),
        },
    );
    for mut key in tracker.observe(direction, bytes) {
        event(
            events,
            RecordEvent::Key {
                connection_id: 1,
                direction: key.direction,
                offset: key.offset,
                key_method: key.key_method,
                enc_method: key.enc_method,
                source_sequence: key.source_sequence,
                key_hex: key.key_hex.take(),
            },
        );
    }
}
#[test]
fn ciphertext_failure_keeps_next_boundary_and_nonstandard_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("capture");
    let output = temp.path().join("decoded");
    let mut records = Vec::new();
    let mut tracker = KeyTracker::new();
    event(&mut records, RecordEvent::Started { max_bytes: 65536 });
    event(
        &mut records,
        RecordEvent::Connection {
            connection_id: 1,
            source: None,
            target: "synthetic".into(),
        },
    );
    let syn = packet(wire::SYN, &[2, 3], &[]);
    data(&mut records, &mut tracker, Direction::Upload, 0, &syn[..7]);
    data(&mut records, &mut tracker, Direction::Upload, 7, &syn[7..]);
    let mut extension = vec![2, 16];
    extension.extend_from_slice(&[7; 16]);
    let ack = packet(wire::ACK, &extension, &[]);
    data(&mut records, &mut tracker, Direction::Download, 0, &ack);
    let invalid = packet(wire::DATA, &[], &[0; 17]);
    let good = packet(
        wire::DATA,
        &[],
        &encrypted(&[0, 0, 0, 0, 0, 0, 0, 1, 0x08, 0x2a]),
    );
    let nonstandard = packet(
        wire::DATA,
        &[],
        &encrypted(&[0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0]),
    );
    let bytes = [invalid, good, nonstandard].concat();
    data(
        &mut records,
        &mut tracker,
        Direction::Upload,
        syn.len() as u64,
        &bytes,
    );
    event(
        &mut records,
        RecordEvent::End {
            connection_id: 1,
            reason: "completed".into(),
        },
    );
    event(
        &mut records,
        RecordEvent::Stopped {
            complete: true,
            reason: "shutdown".into(),
        },
    );
    let mut file = File::create(&input).unwrap();
    for record in records {
        serde_json::to_writer(&mut file, &record).unwrap();
        file.write_all(b"\n").unwrap();
    }
    drop(file);
    let report = run(&input, &output, None).unwrap();
    assert!(report.complete);
    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.failed, 2);
    let lines: Vec<Value> = std::fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let messages: Vec<_> = lines
        .iter()
        .filter(|line| line["gcp_command"] == wire::DATA)
        .collect();
    assert_eq!(messages[0]["failure_code"], "ciphertext_alignment");
    assert_eq!(
        messages[1]["payload"]["fields"][0]["value"]["unsigned"],
        "42"
    );
    assert_eq!(messages[2]["payload"]["format"], "nonstandard_bytes");
    assert_eq!(messages[2]["payload_raw"], "/wA=");
    assert!(messages[2]["plaintext"].is_string());
    assert_eq!(run(&input, &output, None).unwrap_err().0, "output_create");
}
#[test]
fn missing_footer_and_offset_gap_are_not_complete() {
    for gap in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("capture");
        let output = temp.path().join("decoded");
        let mut records = Vec::new();
        event(&mut records, RecordEvent::Started { max_bytes: 65536 });
        event(
            &mut records,
            RecordEvent::Connection {
                connection_id: 1,
                source: None,
                target: "synthetic".into(),
            },
        );
        event(
            &mut records,
            RecordEvent::Data {
                connection_id: 1,
                direction: Direction::Upload,
                offset: u64::from(gap),
                bytes: STANDARD.encode([0x33, 0x66]),
            },
        );
        let mut file = File::create(&input).unwrap();
        for record in records {
            serde_json::to_writer(&mut file, &record).unwrap();
            file.write_all(b"\n").unwrap();
        }
        drop(file);
        let report = run(&input, &output, None).unwrap();
        assert!(!report.complete);
        assert_eq!(report.exit_code(), 2);
        assert!(report.integrity_errors > 0);
        let text = std::fs::read_to_string(&output).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(lines.iter().any(|line| line["failure_code"]
            == if gap {
                "offset_gap"
            } else {
                "truncated_packet"
            }));
    }
}

#[test]
fn rotation_during_split_data_uses_observed_header_key() {
    let mut upload = Stream::default();
    let mut download = Stream::default();
    let mut keys = KeyState::default();
    let mut output = Vec::new();
    let mut report = Report::default();
    let mut context = Context {
        connection: 1,
        direction: Direction::Upload,
        event: 1,
        schemas: None,
        capacity_limit: wire::MAX_PACKET,
    };
    upload
        .feed(
            &packet(wire::SYN, &[2, 3], &[]),
            &mut keys,
            &context,
            &mut output,
            &mut report,
        )
        .unwrap();
    let mut extension = vec![2, 16];
    extension.extend_from_slice(&[7; 16]);
    context.direction = Direction::Download;
    context.event = 2;
    let ack = packet(wire::ACK, &extension, &[]);
    download
        .feed(&ack, &mut keys, &context, &mut output, &mut report)
        .unwrap();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 1, 8, 42];
    let first = packet(wire::DATA, &[], &encrypted(&plaintext));
    context.direction = Direction::Upload;
    context.event = 3;
    upload
        .feed(&first[..26], &mut keys, &context, &mut output, &mut report)
        .unwrap();
    extension[2..].fill(9);
    context.direction = Direction::Download;
    context.event = 4;
    download
        .feed(
            &packet(wire::ACK, &extension, &[]),
            &mut keys,
            &context,
            &mut output,
            &mut report,
        )
        .unwrap();
    context.direction = Direction::Upload;
    context.event = 5;
    upload
        .feed(&first[26..], &mut keys, &context, &mut output, &mut report)
        .unwrap();
    upload
        .feed(
            &packet(wire::DATA, &[], &encrypted_key(&plaintext, &[9; 16])),
            &mut keys,
            &context,
            &mut output,
            &mut report,
        )
        .unwrap();
    let values: Vec<Value> = std::str::from_utf8(&output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let messages: Vec<_> = values
        .iter()
        .filter(|value| value["gcp_command"] == wire::DATA)
        .collect();
    assert_eq!(messages[0]["status"], "decoded");
    assert_eq!(messages[1]["status"], "decoded");
    assert_eq!(messages[0]["key_offset"], 0);
    assert_eq!(messages[1]["key_offset"], ack.len());
    assert_eq!(messages[0]["source_event"], 3);
    assert_eq!(upload.buffer.capacity(), 0);
    assert_eq!(download.buffer.capacity(), 0);
}

#[test]
fn offset_gap_preserves_other_connection_decoding() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("capture");
    let output = temp.path().join("decoded");
    let mut records = Vec::new();
    event(&mut records, RecordEvent::Started { max_bytes: 65536 });
    for connection_id in [1, 2] {
        event(
            &mut records,
            RecordEvent::Connection {
                connection_id,
                source: None,
                target: "synthetic".into(),
            },
        );
    }
    event(
        &mut records,
        RecordEvent::Data {
            connection_id: 2,
            direction: Direction::Upload,
            offset: 9,
            bytes: STANDARD.encode([0x33, 0x66]),
        },
    );
    let mut tracker = KeyTracker::new();
    let syn = packet(wire::SYN, &[2, 0], &[]);
    data(&mut records, &mut tracker, Direction::Upload, 0, &syn);
    data(
        &mut records,
        &mut tracker,
        Direction::Upload,
        syn.len() as u64,
        &packet(wire::DATA, &[], &[0, 0, 0, 0, 0, 0, 0, 1, 8, 42]),
    );
    for connection_id in [1, 2] {
        event(
            &mut records,
            RecordEvent::End {
                connection_id,
                reason: "completed".into(),
            },
        );
    }
    event(
        &mut records,
        RecordEvent::Stopped {
            complete: true,
            reason: "shutdown".into(),
        },
    );
    let mut file = File::create(&input).unwrap();
    for record in records {
        serde_json::to_writer(&mut file, &record).unwrap();
        file.write_all(b"\n").unwrap();
    }
    drop(file);
    let report = run(&input, &output, None).unwrap();
    assert_eq!(report.exit_code(), 2);
    let text = std::fs::read_to_string(&output).unwrap();
    let values: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let message = values
        .iter()
        .find(|value| value["gcp_command"] == wire::DATA)
        .unwrap();
    assert_eq!(message["connection_id"], 1);
    assert_eq!(message["status"], "decoded");
    assert!(values.iter().any(|value| value["connection_id"] == 2
        && value["raw"] == "M2Y="
        && value["failure_code"] == "offset_gap"));
}
