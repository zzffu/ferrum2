use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ferrum2_observability::{
    Event, InterfaceResolutionResult, InterfaceResolutionSource, LogLevel, Metrics,
    NetworkFullRebuildReason, NetworkLifecycleResult, NetworkResetReason, Outcome, Reason, Role,
    SniffOutcome, SniffProtocol, Stage, StrictRouteDiagnosticStatus, TraceRecord, Transport,
    TunDiagnosticReason, TunIpFamily, emit_interface_resolution_diagnostic,
    emit_network_full_rebuild_diagnostic, emit_network_reset_diagnostic,
    emit_strict_route_diagnostic, emit_tun_diagnostic, json_subscriber,
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

#[test]
fn tun_diagnostics_have_only_fixed_reason_and_family_fields() {
    let capture = Captured::default();
    let subscriber = json_subscriber(capture.clone(), LogLevel::Trace);
    let dispatch = Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        emit_tun_diagnostic(
            Role::Client,
            TunDiagnosticReason::WintunRingFull,
            TunIpFamily::Ipv4,
        );
    });

    let text = capture.text();
    let values = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("TUN diagnostic JSON"))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1);
    for value in &values {
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "event",
                "family",
                "level",
                "outcome",
                "reason",
                "role",
                "stage",
                "timestamp",
            ])
        );
        assert_eq!(value["event"], "tun");
        assert_eq!(value["role"], "client");
        assert_eq!(value["stage"], "tun");
    }
    assert_eq!(values[0]["outcome"], "dropped");
    assert_eq!(values[0]["reason"], "wintun_ring_full");
    assert_eq!(values[0]["family"], "ipv4");
    assert!(!text.contains("more_specific_route"));
    assert!(!text.contains("equal_prefix_preferred"));
    for sentinel in ["192.0.2.99", "[2001:db8::99]:443", "TUN_ADAPTER_SENTINEL"] {
        assert!(!text.contains(sentinel));
    }
}

#[test]
fn network_diagnostics_are_closed_numeric_and_identity_free() {
    const INTERFACE: &str = "ETHERNET_TRACE_SENTINEL";
    const DESTINATION: &str = "192.0.2.88:443";
    const PREFIX: &str = "10.0.0.0/8";
    const FILTER_ID: &str = "WFP_FILTER_TRACE_SENTINEL";
    const ADAPTER: &str = "WINTUN_ADAPTER_TRACE_SENTINEL";

    let capture = Captured::default();
    let subscriber = json_subscriber(capture.clone(), LogLevel::Trace);
    let dispatch = Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::event!(
            target: "ferrum2_observability::closed",
            tracing::Level::ERROR,
            interface = INTERFACE,
            destination = DESTINATION,
            prefix = PREFIX,
            filter_id = FILTER_ID,
            adapter = ADAPTER,
        );
        emit_network_reset_diagnostic(
            Role::Client,
            NetworkResetReason::NetworkChange,
            NetworkLifecycleResult::Failed,
            9,
            11,
            13,
        );
        emit_network_full_rebuild_diagnostic(
            Role::Client,
            NetworkFullRebuildReason::StrictRouteDamage,
            NetworkLifecycleResult::Started,
            10,
            0,
            0,
        );
        emit_strict_route_diagnostic(
            Role::Client,
            StrictRouteDiagnosticStatus::RequestedIneffective,
        );
        emit_interface_resolution_diagnostic(
            Role::Client,
            InterfaceResolutionSource::SystemBestRoute,
            InterfaceResolutionResult::Failure,
            true,
        );
    });

    let text = capture.text();
    let values = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("network diagnostic JSON"))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 4);

    for value in &values[..2] {
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "event",
                "generation",
                "level",
                "operation",
                "reason",
                "result",
                "role",
                "stage",
                "tcp_associations",
                "timestamp",
                "udp_associations",
            ])
        );
    }
    assert_eq!(values[0]["operation"], "reset_network");
    assert_eq!(values[0]["reason"], "network_change");
    assert_eq!(values[0]["result"], "failed");
    assert_eq!(values[0]["generation"], 9);
    assert_eq!(values[0]["tcp_associations"], 11);
    assert_eq!(values[0]["udp_associations"], 13);
    assert_eq!(values[1]["operation"], "full_rebuild");
    assert_eq!(values[1]["reason"], "strict_route_damage");
    assert_eq!(values[1]["result"], "started");

    assert_eq!(
        values[2]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "effective",
            "event",
            "level",
            "requested",
            "role",
            "stage",
            "status",
            "timestamp",
        ])
    );
    assert_eq!(values[2]["requested"], true);
    assert_eq!(values[2]["effective"], false);
    assert_eq!(values[2]["status"], "requested_ineffective");

    assert_eq!(
        values[3]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "cache_hit",
            "event",
            "level",
            "result",
            "role",
            "source",
            "stage",
            "timestamp",
        ])
    );
    assert_eq!(values[3]["source"], "system_best_route");
    assert_eq!(values[3]["result"], "failure");
    assert_eq!(values[3]["cache_hit"], true);

    for sentinel in [INTERFACE, DESTINATION, PREFIX, FILTER_ID, ADAPTER] {
        assert!(!text.contains(sentinel), "leaked sentinel {sentinel}");
    }
    for forbidden_field in ["interface", "destination", "prefix", "filter_id", "adapter"] {
        assert!(
            !values
                .iter()
                .any(|value| value.get(forbidden_field).is_some())
        );
    }
    assert!(!text.contains("route_conflict"));
    assert!(!text.contains("external_route"));
}
