use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ferrum2_observability::{
    Event, LogLevel, Metrics, Outcome, Reason, Role, SniffOutcome, SniffProtocol, Stage,
    TraceRecord, Transport, json_subscriber,
};
use serde_json::Value;
use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for Captured {
    type Writer = CapturedWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedWriter(Arc::clone(&self.0))
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("UTF-8 JSON")
    }
}

#[test]
fn newline_json_uses_only_closed_fields_and_redacts_sentinels() {
    const RAW_PSK: &str = "M0_RAW_PSK_SENTINEL";
    const DECODED_KEY: &str = "00112233445566778899aabbccddeeff";
    const DERIVED_KEY: &str = "M0_DERIVED_KEY_SENTINEL";
    const SALT: &str = "M0_REQUEST_RESPONSE_SALT_SENTINEL";
    const NONCE: &str = "M0_NONCE_SENTINEL";
    const RAW_CONFIG: &str = "M0_RAW_CONFIG_SENTINEL";
    const DECODED_CONFIG: &str = "M0_DECODED_CONFIG_SENTINEL";
    const DESTINATION: &str = "192.0.2.231:65000";
    const FREE_MESSAGE: &str = "M0_FREE_MESSAGE_SENTINEL";
    const FREE_ERROR: &str = "M0_FREE_ERROR_SENTINEL";
    const ARBITRARY_FIELD: &str = "M0_ARBITRARY_FIELD_SENTINEL";
    const WIRE_ID: &str = "M0_WIRE_ID_SENTINEL";
    const SOURCE: &str = "198.51.100.11:41000";
    const PEER: &str = "198.51.100.12:42000";
    const TARGET: &str = "example.invalid:443";

    let capture = Captured::default();
    let subscriber = json_subscriber(capture.clone(), LogLevel::Trace);
    let dispatch = Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::event!(
            target: "ferrum2_observability::closed",
            tracing::Level::WARN,
            event = RAW_PSK,
            role = DECODED_KEY,
            transport = DERIVED_KEY,
            stage = SALT,
            outcome = NONCE,
            session_id = 1_u64,
            duration_ms = 2_u64,
            bytes = 3_u64,
        );
        tracing::event!(
            target: "ferrum2_observability::closed",
            tracing::Level::WARN,
            source = SOURCE,
            peer = PEER,
            target = TARGET,
            destination = DESTINATION,
            raw_config = RAW_CONFIG,
            config = DECODED_CONFIG,
            secret = RAW_PSK,
            wire_id = WIRE_ID,
            error = FREE_ERROR,
            arbitrary = ARBITRARY_FIELD,
            FREE_MESSAGE,
        );
        ferrum2_observability::emit(
            TraceRecord::new(
                LogLevel::Warn,
                Event::Connection,
                Role::Server,
                Stage::Shadowsocks,
                Outcome::Rejected,
            )
            .with_reason(Reason::Authentication)
            .with_session_id(42)
            .with_duration_ms(7)
            .with_bytes(0),
        );
    });

    let text = capture.text();
    assert!(text.ends_with('\n'));
    assert_eq!(text.lines().count(), 1);
    for sentinel in [
        RAW_PSK,
        DECODED_KEY,
        DERIVED_KEY,
        SALT,
        NONCE,
        RAW_CONFIG,
        DECODED_CONFIG,
        DESTINATION,
        FREE_MESSAGE,
        FREE_ERROR,
        ARBITRARY_FIELD,
        WIRE_ID,
        SOURCE,
        PEER,
        TARGET,
    ] {
        assert!(!text.contains(sentinel), "leaked sentinel {sentinel}");
    }

    let value: Value = serde_json::from_str(text.trim_end()).expect("one JSON object");
    let object = value.as_object().expect("JSON object");
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    let expected = BTreeSet::from([
        "bytes",
        "duration_ms",
        "event",
        "level",
        "outcome",
        "reason",
        "role",
        "session_id",
        "stage",
        "timestamp",
        "transport",
    ]);
    assert_eq!(actual, expected);
    assert_eq!(object["level"], "WARN");
    assert_eq!(object["event"], "connection");
    assert_eq!(object["role"], "server");
    assert_eq!(object["transport"], "tcp");
    assert_eq!(object["stage"], "shadowsocks");
    assert_eq!(object["outcome"], "rejected");
    assert_eq!(object["reason"], "authentication");
    assert_eq!(object["session_id"], 42);
    assert_eq!(object["duration_ms"], 7);
    assert_eq!(object["bytes"], 0);
    assert!(object["timestamp"].is_string());
}

#[test]
fn minimal_udp_record_omits_optional_fields_and_honors_level_filtering() {
    let capture = Captured::default();
    let subscriber = json_subscriber(capture.clone(), LogLevel::Info);
    let dispatch = Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        ferrum2_observability::emit(TraceRecord::new(
            LogLevel::Debug,
            Event::Lifecycle,
            Role::Client,
            Stage::Relay,
            Outcome::Completed,
        ));
        ferrum2_observability::emit(
            TraceRecord::new(
                LogLevel::Info,
                Event::Lifecycle,
                Role::Client,
                Stage::Relay,
                Outcome::Completed,
            )
            .udp(),
        );
    });

    let text = capture.text();
    assert_eq!(text.lines().count(), 1);
    let value: Value = serde_json::from_str(text.trim_end()).expect("minimal JSON");
    let actual: BTreeSet<_> = value
        .as_object()
        .expect("JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([
            "event",
            "level",
            "outcome",
            "role",
            "stage",
            "timestamp",
            "transport",
        ])
    );
    assert_eq!(value["transport"], "udp");
}

#[test]
fn sniff_trace_has_one_exact_closed_tuple_and_no_identity_channel() {
    let capture = Captured::default();
    let subscriber = json_subscriber(capture.clone(), LogLevel::Trace);
    let dispatch = Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        Metrics::new().sniff(
            Role::Server,
            Transport::Udp,
            SniffOutcome::Invalid,
            SniffProtocol::None,
        );
    });

    let text = capture.text();
    assert_eq!(text.lines().count(), 1);
    let value: Value = serde_json::from_str(text.trim_end()).expect("sniff JSON");
    let object = value.as_object().expect("sniff object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "event",
            "level",
            "outcome",
            "protocol",
            "role",
            "stage",
            "timestamp",
            "transport",
        ])
    );
    assert_eq!(object["event"], "sniff");
    assert_eq!(object["stage"], "sniff");
    assert_eq!(object["outcome"], "invalid");
    assert_eq!(object["protocol"], "none");
    assert_eq!(object["transport"], "udp");
}
