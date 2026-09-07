use serde::{Deserialize, Serialize};

/// Direction of application bytes, independent of transport encryption.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload,
    Download,
}

/// One sensitive research record. Deliberately has no Debug implementation.
#[derive(Deserialize, Serialize)]
pub struct Record {
    pub schema_version: u32,
    pub event_seq: u64,
    pub elapsed_us: u64,
    #[serde(flatten)]
    pub event: RecordEvent,
}

/// Immutable byte evidence and derived key observations. Never send to tracing.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordEvent {
    Started {
        max_bytes: u64,
    },
    Connection {
        connection_id: u64,
        source: Option<String>,
        target: String,
    },
    Data {
        connection_id: u64,
        direction: Direction,
        offset: u64,
        bytes: String,
    },
    Key {
        connection_id: u64,
        direction: Direction,
        offset: u64,
        key_method: u8,
        enc_method: Option<u8>,
        source_sequence: u32,
        key_hex: Option<String>,
    },
    End {
        connection_id: u64,
        reason: String,
    },
    Stopped {
        complete: bool,
        reason: String,
    },
}
