use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::diagnostic::{
    BoundedUdpDiagnosticLedger, ROUTE_TARGET_SLOTS, SupportUdpDiagnostic,
    UDP_ASSOCIATION_SOURCE_IPV4, UDP_ASSOCIATION_SOURCE_PORT_FIRST,
    UDP_ASSOCIATION_SOURCE_PORT_LAST, UDP_DIAGNOSTIC_MAX_EVENT_BYTES, UDP_DIAGNOSTIC_PAYLOAD_LEN,
    UDP_DIAGNOSTIC_SCOPE, UDP_DIAGNOSTIC_VERSION, UDP_SUPPORT_DIAGNOSTIC_CLOSURE,
    UDP_SUPPORT_LEDGER_SCHEMA, UDP_WORKLOAD_DIAGNOSTIC_CLOSURE, UDP_WORKLOAD_LEDGER_SCHEMA,
    UdpAssociationSourceArgs, UdpDiagnosticLedgerArgs, UdpDiagnosticPayload, UdpDiagnosticPhase,
    UdpWorkloadDiagnosticArgs, is_udp_diagnostic_finalize_marker, udp_diagnostic_finalize_marker,
};
use super::super::support::{SupportUdpLedgerEvent, record_support_udp_event};
use super::super::workload::fragment_ack_for_request;
use super::super::workload_diagnostic::{
    UdpWorkloadDiagnosticRequest, UdpWorkloadDiagnosticSession, UdpWorkloadFlowOutcome,
    diagnostic_association_round,
};
use super::SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE;

pub(super) fn check() -> Result<(), String> {
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create Windows TUN self-check directory failed: {error}"))?;
    let diagnostic_identity = UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Bootstrap,
        trial_sequence: SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE,
        association_index: 85,
        round: 0,
        run_nonce: 0x0102_0304_0506_0708,
        packet_nonce: 0x1112_1314_1516_1718,
    };
    let diagnostic_payload = diagnostic_identity.encode();
    if UdpDiagnosticPayload::parse(&diagnostic_payload) != Some(diagnostic_identity)
        || fragment_ack_for_request(&diagnostic_payload)?.is_some()
    {
        return Err("Windows TUN tagged UDP diagnostic payload did not round-trip".to_owned());
    }
    let finalize_identity = udp_diagnostic_finalize_marker(
        diagnostic_identity.run_nonce,
        diagnostic_identity.trial_sequence,
    )?;
    let finalize_payload = finalize_identity.encode();
    if finalize_identity.phase != UdpDiagnosticPhase::Finalize
        || finalize_identity.trial_sequence != SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE
        || finalize_identity.association_index != u32::MAX
        || finalize_identity.round != u32::MAX
        || finalize_identity.packet_nonce != u64::MAX
        || UdpDiagnosticPayload::parse(&finalize_payload) != Some(finalize_identity)
        || !is_udp_diagnostic_finalize_marker(
            finalize_identity,
            diagnostic_identity.run_nonce,
            diagnostic_identity.trial_sequence,
        )
        || is_udp_diagnostic_finalize_marker(
            finalize_identity,
            diagnostic_identity.run_nonce.wrapping_add(1),
            diagnostic_identity.trial_sequence,
        )
        || is_udp_diagnostic_finalize_marker(
            finalize_identity,
            diagnostic_identity.run_nonce,
            diagnostic_identity.trial_sequence + 1,
        )
    {
        return Err("Windows TUN UDP diagnostic finalize marker identity is invalid".to_owned());
    }
    let mut invalid_magic = diagnostic_payload;
    invalid_magic[0] ^= 1;
    let mut invalid_version = diagnostic_payload;
    invalid_version[4] = UDP_DIAGNOSTIC_VERSION + 1;
    let mut invalid_phase = diagnostic_payload;
    invalid_phase[5] = 0;
    let mut zero_trial = diagnostic_payload;
    zero_trial[6..8].fill(0);
    let mut zero_run_nonce = diagnostic_payload;
    zero_run_nonce[16..24].fill(0);
    let mut extended_diagnostic_payload = diagnostic_payload.to_vec();
    extended_diagnostic_payload.push(0);
    if UdpDiagnosticPayload::parse(&invalid_magic).is_some()
        || UdpDiagnosticPayload::parse(&invalid_version).is_some()
        || UdpDiagnosticPayload::parse(&invalid_phase).is_some()
        || UdpDiagnosticPayload::parse(&zero_trial).is_some()
        || UdpDiagnosticPayload::parse(&zero_run_nonce).is_some()
        || UdpDiagnosticPayload::parse(&diagnostic_payload[..UDP_DIAGNOSTIC_PAYLOAD_LEN - 1])
            .is_some()
        || UdpDiagnosticPayload::parse(&extended_diagnostic_payload).is_some()
    {
        return Err("malformed Windows TUN tagged UDP diagnostic payload was accepted".to_owned());
    }
    let bounded_ledger_path = directory.path().join("bounded.ndjson");
    let bounded_ledger_arguments = UdpDiagnosticLedgerArgs {
        path: bounded_ledger_path.clone(),
        run_nonce: diagnostic_identity.run_nonce,
        max_events: 2,
    };
    let bounded_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &bounded_ledger_arguments,
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "pid": 123,
            "listen_ip": "192.0.2.10",
            "tcp_port": 443,
            "udp_ports": [53, 54, 55, 56],
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    bounded_ledger.record(json!({"stage": "rx"}));
    bounded_ledger.record(json!({"stage": "tx"}));
    bounded_ledger.record(json!({"stage": "rx"}));
    if bounded_ledger.is_closed() {
        return Err(
            "Windows TUN UDP diagnostic ledger closed without an explicit boundary".to_owned(),
        );
    }
    bounded_ledger.close();
    bounded_ledger.record(json!({"stage": "after_close"}));
    if !bounded_ledger.is_closed() || bounded_ledger.counters() != (3, 2, 1, 0) {
        return Err("Windows TUN UDP diagnostic ledger event bound is invalid".to_owned());
    }
    drop(bounded_ledger);
    let bounded_records = fs::read_to_string(&bounded_ledger_path)
        .map_err(|error| format!("read bounded UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse bounded UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if bounded_records.len() != 5
        || bounded_records[0]["schema"] != UDP_SUPPORT_LEDGER_SCHEMA
        || bounded_records[0]["record_type"] != "header"
        || bounded_records[0]["pid"] != 123
        || bounded_records[0]["scope"] != UDP_DIAGNOSTIC_SCOPE
        || bounded_records[0]["closure"] != UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        || bounded_records[1]["stage"] != "rx"
        || bounded_records[1]["ledger_counters"]["attempted_events"] != 1
        || bounded_records[2]["stage"] != "tx"
        || bounded_records[3]["record_type"] != "truncation"
        || bounded_records[3]["attempted_events"] != 3
        || bounded_records[3]["events_written"] != 2
        || bounded_records[3]["dropped_events_at_least"] != 1
        || bounded_records[3]["write_failures"] != 0
        || bounded_records[4]["record_type"] != "footer"
        || bounded_records[4]["attempted_events"] != 3
        || bounded_records[4]["events_written"] != 2
        || bounded_records[4]["dropped_events"] != 1
        || bounded_records[4]["write_failures"] != 0
    {
        return Err("Windows TUN UDP diagnostic ledger records are invalid".to_owned());
    }
    let barrier_ledger_path = directory.path().join("barrier.ndjson");
    let barrier_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &UdpDiagnosticLedgerArgs {
            path: barrier_ledger_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 4,
        },
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "pid": 123,
            "listen_ip": "192.0.2.10",
            "tcp_port": 443,
            "udp_ports": [53, 54, 55, 56],
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    let barrier_diagnostic = SupportUdpDiagnostic::new(barrier_ledger);
    let barrier_listen: SocketAddr = "192.0.2.10:53".parse().expect("literal");
    let barrier_peer: SocketAddr = "192.0.2.10:54321".parse().expect("literal");
    record_support_udp_event(
        Some(&barrier_diagnostic),
        SupportUdpLedgerEvent {
            stage: "rx",
            listen: barrier_listen,
            peer: barrier_peer,
            request: &diagnostic_payload,
            send_attempted: None,
            send_result: "pending",
            sent: None,
            error_kind: None,
        },
    );
    record_support_udp_event(
        Some(&barrier_diagnostic),
        SupportUdpLedgerEvent {
            stage: "tx",
            listen: barrier_listen,
            peer: barrier_peer,
            request: &diagnostic_payload,
            send_attempted: Some(true),
            send_result: "success",
            sent: Some(diagnostic_payload.len()),
            error_kind: None,
        },
    );
    let warmup_payload = UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Warmup,
        ..diagnostic_identity
    }
    .encode();
    let foreign_payload = UdpDiagnosticPayload {
        run_nonce: diagnostic_identity.run_nonce.wrapping_add(1),
        ..diagnostic_identity
    }
    .encode();
    let other_finalize_payload = udp_diagnostic_finalize_marker(
        diagnostic_identity.run_nonce,
        diagnostic_identity.trial_sequence + 1,
    )?
    .encode();
    for request in [
        &warmup_payload[..],
        &foreign_payload[..],
        b"ordinary UDP payload",
    ] {
        record_support_udp_event(
            Some(&barrier_diagnostic),
            SupportUdpLedgerEvent {
                stage: "rx",
                listen: barrier_listen,
                peer: barrier_peer,
                request,
                send_attempted: None,
                send_result: "pending",
                sent: None,
                error_kind: None,
            },
        );
    }
    barrier_diagnostic.observe_finalize_marker(
        0,
        barrier_listen,
        "198.51.100.10:54321".parse().expect("literal"),
        &finalize_payload,
    );
    for slot in 0..(ROUTE_TARGET_SLOTS - 1) {
        let listen = SocketAddr::new(
            barrier_listen.ip(),
            barrier_listen.port() + u16::try_from(slot).expect("slot fits u16"),
        );
        barrier_diagnostic.observe_finalize_marker(slot, listen, barrier_peer, &finalize_payload);
    }
    barrier_diagnostic.observe_finalize_marker(0, barrier_listen, barrier_peer, &finalize_payload);
    barrier_diagnostic.observe_finalize_marker(
        ROUTE_TARGET_SLOTS - 1,
        SocketAddr::new(
            barrier_listen.ip(),
            barrier_listen.port() + u16::try_from(ROUTE_TARGET_SLOTS - 1).expect("slot fits u16"),
        ),
        barrier_peer,
        &other_finalize_payload,
    );
    if barrier_diagnostic.ledger.is_closed() || barrier_diagnostic.ledger.counters() != (2, 2, 0, 0)
    {
        return Err(
            "Windows TUN UDP diagnostic finalize barrier closed before all slots".to_owned(),
        );
    }
    let final_slot = ROUTE_TARGET_SLOTS - 1;
    let final_listen = SocketAddr::new(
        barrier_listen.ip(),
        barrier_listen.port() + u16::try_from(final_slot).expect("slot fits u16"),
    );
    barrier_diagnostic.observe_finalize_marker(
        final_slot,
        final_listen,
        barrier_peer,
        &finalize_payload,
    );
    barrier_diagnostic.observe_finalize_marker(
        final_slot,
        final_listen,
        barrier_peer,
        &finalize_payload,
    );
    barrier_diagnostic
        .ledger
        .record(json!({"stage": "after_close"}));
    if !barrier_diagnostic.ledger.is_closed()
        || barrier_diagnostic.ledger.counters() != (2, 2, 0, 0)
    {
        return Err("Windows TUN UDP diagnostic finalize barrier is not idempotent".to_owned());
    }
    drop(barrier_diagnostic);
    let barrier_records = fs::read_to_string(&barrier_ledger_path)
        .map_err(|error| format!("read finalized UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse finalized UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if barrier_records.len() != 4
        || barrier_records[0]["closure"] != UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        || barrier_records[1]["stage"] != "rx"
        || barrier_records[2]["stage"] != "tx"
        || barrier_records[3]["record_type"] != "footer"
        || barrier_records[3]["attempted_events"] != 2
        || barrier_records[3]["events_written"] != 2
    {
        return Err("Windows TUN UDP diagnostic finalize barrier ledger is invalid".to_owned());
    }
    let degraded_ledger_path = directory.path().join("degraded.ndjson");
    let degraded_ledger_arguments = UdpDiagnosticLedgerArgs {
        path: degraded_ledger_path.clone(),
        run_nonce: diagnostic_identity.run_nonce,
        max_events: 2,
    };
    let degraded_ledger = BoundedUdpDiagnosticLedger::create_with_reporting(
        &degraded_ledger_arguments,
        UDP_SUPPORT_LEDGER_SCHEMA,
        json!({
            "scope": UDP_DIAGNOSTIC_SCOPE,
            "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
        }),
        false,
    )?;
    degraded_ledger.record(json!({
        "oversized": "x".repeat(UDP_DIAGNOSTIC_MAX_EVENT_BYTES + 1)
    }));
    degraded_ledger.record(json!({"stage": "rx"}));
    if degraded_ledger.counters() != (2, 1, 0, 1) {
        return Err("Windows TUN UDP diagnostic write-failure accounting is invalid".to_owned());
    }
    drop(degraded_ledger);
    let degraded_records = fs::read_to_string(&degraded_ledger_path)
        .map_err(|error| format!("read degraded UDP diagnostic ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse degraded UDP diagnostic ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if degraded_records.len() != 3
        || degraded_records[1]["stage"] != "rx"
        || degraded_records[1]["event_index"] != 1
        || degraded_records[2]["attempted_events"] != 2
        || degraded_records[2]["events_written"] != 1
        || degraded_records[2]["write_failures"] != 1
    {
        return Err(
            "Windows TUN UDP diagnostic logging failure altered later recording".to_owned(),
        );
    }
    let fixed_source_arguments = UdpAssociationSourceArgs {
        source_ip: IpAddr::V4(UDP_ASSOCIATION_SOURCE_IPV4),
        source_port_first: UDP_ASSOCIATION_SOURCE_PORT_FIRST,
        source_port_last: UDP_ASSOCIATION_SOURCE_PORT_LAST,
    };
    let failed_flow_path = directory.path().join("failed-flow.ndjson");
    let failed_flow_arguments = UdpWorkloadDiagnosticArgs {
        ledger: UdpDiagnosticLedgerArgs {
            path: failed_flow_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 3,
        },
        trial_sequence: diagnostic_identity.trial_sequence,
    };
    let failed_flow =
        UdpWorkloadDiagnosticSession::create(&failed_flow_arguments, &fixed_source_arguments)?;
    failed_flow.record_flow(
        UdpDiagnosticPayload {
            phase: UdpDiagnosticPhase::Warmup,
            ..diagnostic_identity
        },
        Some("198.18.0.2:54320".parse().expect("literal")),
        Some("192.0.2.10:53".parse().expect("literal")),
        UdpWorkloadFlowOutcome {
            send_result: "success",
            send_bytes: Some(UDP_DIAGNOSTIC_PAYLOAD_LEN),
            reply_result: "success",
            reply_source: Some("192.0.2.10:53".parse().expect("literal")),
            payload_match: true,
            error_kind: None,
        },
    );
    failed_flow.record_flow(
        diagnostic_identity,
        Some("198.18.0.2:20085".parse().expect("literal")),
        Some("192.0.2.10:53".parse().expect("literal")),
        UdpWorkloadFlowOutcome {
            send_result: "success",
            send_bytes: Some(UDP_DIAGNOSTIC_PAYLOAD_LEN),
            reply_result: "timeout",
            reply_source: None,
            payload_match: false,
            error_kind: Some("timeout"),
        },
    );
    let unobserved_identity = UdpDiagnosticPayload {
        association_index: diagnostic_identity.association_index + 1,
        packet_nonce: diagnostic_identity.packet_nonce + 1,
        ..diagnostic_identity
    };
    failed_flow.record_not_observed(&UdpWorkloadDiagnosticRequest {
        identity: unobserved_identity,
        payload: unobserved_identity.encode(),
        local: Some("198.18.0.2:20086".parse().expect("literal")),
        target: Some("192.0.2.10:53".parse().expect("literal")),
        sent: UDP_DIAGNOSTIC_PAYLOAD_LEN,
    });
    drop(failed_flow);
    let failed_flow_records = fs::read_to_string(&failed_flow_path)
        .map_err(|error| format!("read failed UDP flow ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse failed UDP flow ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unobserved_packet_nonce = unobserved_identity.packet_nonce.to_string();
    if failed_flow_records.len() != 4
        || failed_flow_records[0]["schema"] != UDP_WORKLOAD_LEDGER_SCHEMA
        || failed_flow_records[0]["scope"] != UDP_DIAGNOSTIC_SCOPE
        || failed_flow_records[0]["closure"] != UDP_WORKLOAD_DIAGNOSTIC_CLOSURE
        || failed_flow_records[0]["source_ip"] != UDP_ASSOCIATION_SOURCE_IPV4.to_string()
        || failed_flow_records[0]["source_port_first"] != UDP_ASSOCIATION_SOURCE_PORT_FIRST
        || failed_flow_records[0]["source_port_last"] != UDP_ASSOCIATION_SOURCE_PORT_LAST
        || failed_flow_records[1]["phase"] != "bootstrap"
        || failed_flow_records[1]["association_index"] != 85
        || failed_flow_records[1]["workload_local_port"] != 20085
        || failed_flow_records[1]["reply_result"] != "timeout"
        || failed_flow_records[1]["payload_match"] != false
        || failed_flow_records[2]["packet_nonce"].as_str() != Some(unobserved_packet_nonce.as_str())
        || failed_flow_records[2]["association_index"] != 86
        || failed_flow_records[2]["workload_local_port"] != 20086
        || failed_flow_records[2]["send_result"] != "success"
        || failed_flow_records[2]["reply_result"] != "not_observed"
        || failed_flow_records[2]["reply_source_ip"] != Value::Null
        || failed_flow_records[2]["payload_match"] != false
        || failed_flow_records[2]["error_kind"] != "prior_batch_failure"
        || failed_flow_records[3]["record_type"] != "footer"
    {
        return Err("Windows TUN UDP failed-flow diagnostic record is invalid".to_owned());
    }
    let batch_failure_ledger_path = directory.path().join("batch-failure.ndjson");
    let batch_failure_arguments = UdpWorkloadDiagnosticArgs {
        ledger: UdpDiagnosticLedgerArgs {
            path: batch_failure_ledger_path.clone(),
            run_nonce: diagnostic_identity.run_nonce,
            max_events: 2,
        },
        trial_sequence: diagnostic_identity.trial_sequence,
    };
    let server_a = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind first diagnostic batch server failed: {error}"))?;
    let server_b = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind second diagnostic batch server failed: {error}"))?;
    let client_a = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind first diagnostic batch client failed: {error}"))?;
    let client_b = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .map_err(|error| format!("bind second diagnostic batch client failed: {error}"))?;
    client_a
        .connect(
            server_a
                .local_addr()
                .map_err(|error| format!("read first diagnostic server address failed: {error}"))?,
        )
        .map_err(|error| format!("connect first diagnostic batch client failed: {error}"))?;
    client_b
        .connect(
            server_b.local_addr().map_err(|error| {
                format!("read second diagnostic server address failed: {error}")
            })?,
        )
        .map_err(|error| format!("connect second diagnostic batch client failed: {error}"))?;
    client_a
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|error| format!("set diagnostic batch receive timeout failed: {error}"))?;
    let mut batch_failure_session =
        UdpWorkloadDiagnosticSession::create(&batch_failure_arguments, &fixed_source_arguments)?;
    let mut batch_failure_reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    let batch_failure = diagnostic_association_round(
        &[client_a, client_b],
        &mut batch_failure_reply,
        2,
        UdpDiagnosticPhase::Bootstrap,
        1,
        &mut batch_failure_session,
    )
    .expect_err("first diagnostic batch receive must time out");
    if !batch_failure.contains("phase=bootstrap association_index=0") {
        return Err("Windows TUN UDP batch failure identity is invalid".to_owned());
    }
    drop(batch_failure_session);
    let batch_failure_records = fs::read_to_string(&batch_failure_ledger_path)
        .map_err(|error| format!("read batch-failure UDP ledger failed: {error}"))?
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("parse batch-failure UDP ledger failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if batch_failure_records.len() != 4
        || batch_failure_records[1]["association_index"] != 0
        || batch_failure_records[1]["send_result"] != "success"
        || batch_failure_records[1]["reply_result"] != "timeout"
        || batch_failure_records[2]["association_index"] != 1
        || batch_failure_records[2]["send_result"] != "success"
        || batch_failure_records[2]["reply_result"] != "not_observed"
        || batch_failure_records[2]["error_kind"] != "prior_batch_failure"
        || batch_failure_records[3]["record_type"] != "footer"
    {
        return Err("Windows TUN UDP batch-failure ledger is incomplete".to_owned());
    }
    Ok(())
}
