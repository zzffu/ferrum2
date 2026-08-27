use super::contract::{Scenario, parse_support, parse_udp_diagnostic_finalize, parse_workload};
use super::diagnostic::{
    ASSOCIATION_BOOTSTRAP_BATCH, ASSOCIATION_LOOKUP_BATCH, ASSOCIATION_LOOKUP_ROUNDS, ASSOCIATIONS,
    BoundedUdpDiagnosticLedger, FRAGMENT_ACK_LEN, FRAGMENT_ACK_WINDOW, FRAGMENT_BATCH,
    FRAGMENT_IPV4_RESPONSE_BOUND, FRAGMENT_PAYLOAD, FRAGMENT_REPLY_BUFFER,
    FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS, FragmentAckBatch, FragmentPhase,
    FragmentWorkloadAccounting, IPV4_HEADER_LEN, PERFORMANCE_TUN_MTU, ROUTE_TARGET_SLOTS,
    SUPPORT_UNDERLAY_IPV4_MTU, SupportUdpDiagnostic, UDP_ASSOCIATION_SOURCE_IPV4,
    UDP_ASSOCIATION_SOURCE_PORT_FIRST, UDP_ASSOCIATION_SOURCE_PORT_LAST, UDP_BATCH,
    UDP_DIAGNOSTIC_MAX_EVENT_BYTES, UDP_DIAGNOSTIC_MAX_EVENTS, UDP_DIAGNOSTIC_PAYLOAD_LEN,
    UDP_DIAGNOSTIC_SCOPE, UDP_DIAGNOSTIC_VERSION, UDP_HEADER_LEN, UDP_SUPPORT_DIAGNOSTIC_CLOSURE,
    UDP_SUPPORT_LEDGER_SCHEMA, UDP_WORKLOAD_DIAGNOSTIC_CLOSURE, UDP_WORKLOAD_LEDGER_SCHEMA,
    UdpAssociationSourceArgs, UdpDiagnosticFinalizeArgs, UdpDiagnosticLedgerArgs,
    UdpDiagnosticPayload, UdpDiagnosticPhase, UdpWorkloadDiagnosticArgs,
    is_udp_diagnostic_finalize_marker, udp_diagnostic_finalize_marker,
};
use super::support::{SupportUdpLedgerEvent, record_support_udp_event, self_check_support_backlog};
use super::workload::{
    elapsed_rate, fragment_ack, fragment_ack_for_request, fragment_ack_sequence,
    fragment_batch_failure, fragment_request, fragment_request_sequence, fragment_retry_budget,
    sequenced_payload, udp_association_source_endpoint,
};
use super::workload_diagnostic::{
    UdpWorkloadDiagnosticRequest, UdpWorkloadDiagnosticSession, UdpWorkloadFlowOutcome,
    diagnostic_association_round,
};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

pub(crate) fn run_self_check() -> Result<(), String> {
    const DIAGNOSTIC_TRIAL_SEQUENCE: u16 = 43;
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create Windows TUN self-check directory failed: {error}"))?;
    let output = directory.path().join("observation.json");
    let arguments: Vec<OsString> = [
        "--scenario".to_owned(),
        "tcp-single-flow".to_owned(),
        "--target-ip".to_owned(),
        "192.0.2.10".to_owned(),
        "--tcp-port".to_owned(),
        "443".to_owned(),
        "--udp-port".to_owned(),
        "53".to_owned(),
        "--output".to_owned(),
        output.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let parsed = parse_workload(&arguments)?;
    if parsed.scenario != Scenario::TcpSingle
        || parsed.target_ip != "192.0.2.10".parse::<IpAddr>().expect("literal")
        || parsed.tcp_port != 443
        || parsed.udp_port != 53
        || parsed.output != output
        || parsed.association_source.is_some()
        || parsed.diagnostic.is_some()
    {
        return Err("Windows TUN workload arguments were not preserved".to_owned());
    }
    let mut duplicate = arguments.clone();
    duplicate.extend([
        OsString::from("--scenario"),
        OsString::from("udp-packets-per-second"),
    ]);
    if parse_workload(&duplicate).is_ok() {
        return Err("Windows TUN duplicate option was accepted".to_owned());
    }
    let mut loopback = arguments.clone();
    loopback[3] = OsString::from("127.0.0.1");
    if parse_workload(&loopback).is_ok() {
        return Err("Windows TUN loopback target was accepted".to_owned());
    }
    let mut association_arguments = arguments.clone();
    association_arguments[1] = OsString::from("udp-8192-association-lookup-expiry");
    association_arguments.extend([
        OsString::from("--source-ip"),
        OsString::from("198.18.0.2"),
        OsString::from("--source-port-first"),
        OsString::from("20000"),
        OsString::from("--source-port-last"),
        OsString::from("28191"),
    ]);
    let association_parsed = parse_workload(&association_arguments)?;
    let association_source = association_parsed
        .association_source
        .as_ref()
        .ok_or_else(|| "Windows TUN UDP association source options were discarded".to_owned())?;
    if association_parsed.scenario != Scenario::UdpAssociations
        || association_parsed.diagnostic.is_some()
        || association_source.source_ip != IpAddr::V4(UDP_ASSOCIATION_SOURCE_IPV4)
        || association_source.source_port_first != UDP_ASSOCIATION_SOURCE_PORT_FIRST
        || association_source.source_port_last != UDP_ASSOCIATION_SOURCE_PORT_LAST
    {
        return Err(
            "canonical Windows TUN UDP association arguments were not preserved".to_owned(),
        );
    }
    let mut association_without_source = arguments.clone();
    association_without_source[1] = OsString::from("udp-8192-association-lookup-expiry");
    let mut source_on_other_scenario = arguments.clone();
    source_on_other_scenario.extend_from_slice(&association_arguments[10..]);
    let mut duplicate_source = association_arguments.clone();
    duplicate_source.extend([OsString::from("--source-ip"), OsString::from("198.18.0.2")]);
    let mut ipv6_association = association_arguments.clone();
    ipv6_association[3] = OsString::from("2001:db8::10");
    let mut legacy_diagnostic_source = association_arguments.clone();
    legacy_diagnostic_source.extend([
        OsString::from("--diagnostic-source-ip"),
        OsString::from("198.18.0.2"),
    ]);
    if parse_workload(&association_without_source).is_ok()
        || parse_workload(&source_on_other_scenario).is_ok()
        || parse_workload(&duplicate_source).is_ok()
        || parse_workload(&ipv6_association).is_ok()
        || parse_workload(&legacy_diagnostic_source).is_ok()
    {
        return Err(
            "invalid canonical Windows TUN UDP association options were accepted".to_owned(),
        );
    }
    for option_index in [10_usize, 12, 14] {
        let mut missing_source_option = association_arguments.clone();
        missing_source_option.drain(option_index..(option_index + 2));
        if parse_workload(&missing_source_option).is_ok() {
            return Err(
                "incomplete Windows TUN UDP association source options were accepted".to_owned(),
            );
        }
    }
    let mut wrong_source_ip = association_arguments.clone();
    wrong_source_ip[11] = OsString::from("198.18.0.3");
    let mut wrong_source_port_first = association_arguments.clone();
    wrong_source_port_first[13] = OsString::from("20001");
    let mut wrong_source_port_last = association_arguments.clone();
    wrong_source_port_last[15] = OsString::from("28190");
    if parse_workload(&wrong_source_ip).is_ok()
        || parse_workload(&wrong_source_port_first).is_ok()
        || parse_workload(&wrong_source_port_last).is_ok()
    {
        return Err("invalid Windows TUN UDP association source bounds were accepted".to_owned());
    }
    if usize::from(UDP_ASSOCIATION_SOURCE_PORT_LAST - UDP_ASSOCIATION_SOURCE_PORT_FIRST + 1)
        != ASSOCIATIONS
        || udp_association_source_endpoint(association_source, 0)?
            != "198.18.0.2:20000".parse().expect("literal")
        || udp_association_source_endpoint(association_source, 85)?
            != "198.18.0.2:20085".parse().expect("literal")
        || udp_association_source_endpoint(association_source, ASSOCIATIONS - 1)?
            != "198.18.0.2:28191".parse().expect("literal")
        || udp_association_source_endpoint(association_source, ASSOCIATIONS).is_ok()
    {
        return Err("Windows TUN UDP association source endpoint mapping is invalid".to_owned());
    }
    let short_source_range = UdpAssociationSourceArgs {
        source_port_last: UDP_ASSOCIATION_SOURCE_PORT_FIRST,
        ..*association_source
    };
    let overflowing_source_range = UdpAssociationSourceArgs {
        source_port_first: u16::MAX,
        source_port_last: u16::MAX,
        ..*association_source
    };
    if udp_association_source_endpoint(&short_source_range, 1).is_ok()
        || udp_association_source_endpoint(&overflowing_source_range, 1).is_ok()
    {
        return Err("invalid Windows TUN UDP association source range was mapped".to_owned());
    }

    let workload_ledger_path = directory.path().join("workload-flow.ndjson");
    let mut diagnostic_arguments = association_arguments.clone();
    diagnostic_arguments.extend([
        OsString::from("--diagnostic-ledger"),
        workload_ledger_path.as_os_str().to_owned(),
        OsString::from("--diagnostic-run-nonce"),
        OsString::from("72623859790382856"),
        OsString::from("--diagnostic-max-events"),
        OsString::from("16384"),
        OsString::from("--diagnostic-trial-sequence"),
        OsString::from(DIAGNOSTIC_TRIAL_SEQUENCE.to_string()),
    ]);
    let diagnostic_parsed = parse_workload(&diagnostic_arguments)?;
    let diagnostic = diagnostic_parsed
        .diagnostic
        .as_ref()
        .ok_or_else(|| "Windows TUN workload diagnostic options were discarded".to_owned())?;
    if diagnostic_parsed.association_source.as_ref() != Some(association_source)
        || diagnostic.ledger.path != workload_ledger_path
        || diagnostic.ledger.run_nonce != 0x0102_0304_0506_0708
        || diagnostic.ledger.max_events != 16_384
        || diagnostic.trial_sequence != DIAGNOSTIC_TRIAL_SEQUENCE
    {
        return Err("Windows TUN workload diagnostic arguments were not preserved".to_owned());
    }
    for option_index in [16_usize, 18, 20, 22] {
        let mut missing_diagnostic_option = diagnostic_arguments.clone();
        missing_diagnostic_option.drain(option_index..(option_index + 2));
        if parse_workload(&missing_diagnostic_option).is_ok() {
            return Err(
                "incomplete Windows TUN workload diagnostic options were accepted".to_owned(),
            );
        }
    }
    let mut wrong_scenario_diagnostic = diagnostic_arguments.clone();
    wrong_scenario_diagnostic[1] = OsString::from("udp-packets-per-second");
    let mut zero_nonce_diagnostic = diagnostic_arguments.clone();
    zero_nonce_diagnostic[19] = OsString::from("0");
    let mut noncanonical_nonce_diagnostic = diagnostic_arguments.clone();
    noncanonical_nonce_diagnostic[19] = OsString::from("01");
    let mut oversized_events_diagnostic = diagnostic_arguments.clone();
    oversized_events_diagnostic[21] = OsString::from((UDP_DIAGNOSTIC_MAX_EVENTS + 1).to_string());
    let mut zero_trial_diagnostic = diagnostic_arguments.clone();
    zero_trial_diagnostic[23] = OsString::from("0");
    let mut oversized_trial_diagnostic = diagnostic_arguments.clone();
    oversized_trial_diagnostic[23] = OsString::from("65536");
    if parse_workload(&wrong_scenario_diagnostic).is_ok()
        || parse_workload(&zero_nonce_diagnostic).is_ok()
        || parse_workload(&noncanonical_nonce_diagnostic).is_ok()
        || parse_workload(&oversized_events_diagnostic).is_ok()
        || parse_workload(&zero_trial_diagnostic).is_ok()
        || parse_workload(&oversized_trial_diagnostic).is_ok()
    {
        return Err("invalid Windows TUN workload diagnostic bounds were accepted".to_owned());
    }
    let mut relative_ledger_diagnostic = diagnostic_arguments.clone();
    relative_ledger_diagnostic[17] = OsString::from("workload-flow.ndjson");
    let mut wrong_extension_diagnostic = diagnostic_arguments.clone();
    wrong_extension_diagnostic[17] = directory.path().join("workload-flow.json").into_os_string();
    if parse_workload(&relative_ledger_diagnostic).is_ok()
        || parse_workload(&wrong_extension_diagnostic).is_ok()
    {
        return Err("unsafe Windows TUN workload diagnostic ledger path was accepted".to_owned());
    }
    let existing_ledger_path = directory.path().join("existing.ndjson");
    File::create(&existing_ledger_path)
        .map_err(|error| format!("create self-check existing ledger failed: {error}"))?;
    let mut existing_ledger_diagnostic = diagnostic_arguments.clone();
    existing_ledger_diagnostic[17] = existing_ledger_path.into_os_string();
    if parse_workload(&existing_ledger_diagnostic).is_ok() {
        return Err("existing Windows TUN workload diagnostic ledger was accepted".to_owned());
    }
    let support_ledger_path = directory.path().join("support.ndjson");
    let support_arguments: Vec<OsString> = [
        OsString::from("--listen-ip"),
        OsString::from("192.0.2.10"),
        OsString::from("--tcp-port"),
        OsString::from("443"),
        OsString::from("--udp-port"),
        OsString::from("53"),
        OsString::from("--diagnostic-ledger"),
        support_ledger_path.as_os_str().to_owned(),
        OsString::from("--diagnostic-run-nonce"),
        OsString::from("72623859790382856"),
        OsString::from("--diagnostic-max-events"),
        OsString::from("16384"),
    ]
    .into_iter()
    .collect();
    let support_parsed = parse_support(&support_arguments)?;
    let support_diagnostic = support_parsed
        .diagnostic
        .as_ref()
        .ok_or_else(|| "Windows TUN support diagnostic options were discarded".to_owned())?;
    if support_parsed.listen_ip != "192.0.2.10".parse::<IpAddr>().expect("literal")
        || support_parsed.tcp_port != 443
        || support_parsed.udp_port != 53
        || support_diagnostic.path != support_ledger_path
        || support_diagnostic.run_nonce != 0x0102_0304_0506_0708
        || support_diagnostic.max_events != 16_384
    {
        return Err("Windows TUN support diagnostic arguments were not preserved".to_owned());
    }
    let mut partial_support_diagnostic = support_arguments.clone();
    partial_support_diagnostic.truncate(partial_support_diagnostic.len() - 2);
    if parse_support(&partial_support_diagnostic).is_ok() {
        return Err("incomplete Windows TUN support diagnostic options were accepted".to_owned());
    }
    let finalize_arguments: Vec<OsString> = [
        "--target-ip",
        "192.0.2.10",
        "--udp-port",
        "53",
        "--diagnostic-run-nonce",
        "72623859790382856",
        "--diagnostic-trial-sequence",
        "43",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let finalize_parsed = parse_udp_diagnostic_finalize(&finalize_arguments)?;
    if finalize_parsed
        != (UdpDiagnosticFinalizeArgs {
            target_ip: "192.0.2.10".parse().expect("literal"),
            udp_port: 53,
            run_nonce: 0x0102_0304_0506_0708,
            trial_sequence: DIAGNOSTIC_TRIAL_SEQUENCE,
        })
    {
        return Err("Windows TUN UDP diagnostic finalize arguments were not preserved".to_owned());
    }
    let mut partial_finalize = finalize_arguments.clone();
    partial_finalize.truncate(partial_finalize.len() - 2);
    let mut missing_nonce_finalize = finalize_arguments.clone();
    missing_nonce_finalize.drain(4..6);
    let mut duplicate_finalize = finalize_arguments.clone();
    duplicate_finalize.extend([OsString::from("--udp-port"), OsString::from("54")]);
    let mut extra_finalize = finalize_arguments.clone();
    extra_finalize.extend([OsString::from("--tcp-port"), OsString::from("443")]);
    let mut zero_nonce_finalize = finalize_arguments.clone();
    zero_nonce_finalize[5] = OsString::from("0");
    let mut noncanonical_nonce_finalize = finalize_arguments.clone();
    noncanonical_nonce_finalize[5] = OsString::from("01");
    let mut zero_trial_finalize = finalize_arguments.clone();
    zero_trial_finalize[7] = OsString::from("0");
    let mut oversized_trial_finalize = finalize_arguments.clone();
    oversized_trial_finalize[7] = OsString::from("65536");
    let mut overflowing_port_finalize = finalize_arguments.clone();
    overflowing_port_finalize[3] = OsString::from("65535");
    if parse_udp_diagnostic_finalize(&partial_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&missing_nonce_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&duplicate_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&extra_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&zero_nonce_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&noncanonical_nonce_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&zero_trial_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&oversized_trial_finalize).is_ok()
        || parse_udp_diagnostic_finalize(&overflowing_port_finalize).is_ok()
    {
        return Err("Windows TUN UDP diagnostic finalize argument boundary is open".to_owned());
    }
    if elapsed_rate(10, Duration::from_secs(2), "self-check")? != 5 {
        return Err("Windows TUN integer rate calculation is invalid".to_owned());
    }
    let payload = sequenced_payload(32, 0x0102_0304_0506_0708)?;
    if payload[..8] != 0x0102_0304_0506_0708_u64.to_be_bytes()
        || payload == sequenced_payload(32, 0x0102_0304_0506_0709)?
    {
        return Err("Windows TUN sequenced UDP payload is invalid".to_owned());
    }
    let diagnostic_identity = UdpDiagnosticPayload {
        phase: UdpDiagnosticPhase::Bootstrap,
        trial_sequence: DIAGNOSTIC_TRIAL_SEQUENCE,
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
        || finalize_identity.trial_sequence != DIAGNOSTIC_TRIAL_SEQUENCE
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
    if UDP_BATCH != 8 {
        return Err("Windows TUN UDP packet-rate batch recipe is invalid".to_owned());
    }
    if ASSOCIATIONS != 8_192
        || ASSOCIATION_BOOTSTRAP_BATCH != 1
        || ASSOCIATION_LOOKUP_BATCH != 8
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_BOOTSTRAP_BATCH)
        || !ASSOCIATIONS.is_multiple_of(ASSOCIATION_LOOKUP_BATCH)
        || ASSOCIATION_LOOKUP_ROUNDS != 64
    {
        return Err("Windows TUN UDP association recipe is invalid".to_owned());
    }
    let fragment_sequence = 0x1112_1314_1516_1718_u64;
    let fragment_request = fragment_request(fragment_sequence);
    let expected_ack = fragment_ack(fragment_sequence);
    let support_ack = fragment_ack_for_request(&fragment_request)?
        .ok_or_else(|| "fragment request was classified as an ordinary echo".to_owned())?;
    if fragment_request.len() != FRAGMENT_PAYLOAD
        || fragment_request_sequence(&fragment_request)? != fragment_sequence
        || support_ack != expected_ack
        || fragment_ack_sequence(&support_ack)? != fragment_sequence
    {
        return Err("Windows TUN fragment request/ACK round trip is invalid".to_owned());
    }
    if fragment_ack_for_request(&payload)?.is_some() {
        return Err("ordinary UDP echo payload was classified as a fragment request".to_owned());
    }
    if FRAGMENT_ACK_LEN != 24
        || FRAGMENT_REPLY_BUFFER != FRAGMENT_ACK_LEN + 1
        || FRAGMENT_ACK_LEN > FRAGMENT_IPV4_RESPONSE_BOUND
    {
        return Err("Windows TUN fragment ACK bound is invalid".to_owned());
    }
    let fragment_data_capacity = ((PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN) / 8) * 8;
    let fragment_count = (FRAGMENT_PAYLOAD + UDP_HEADER_LEN).div_ceil(fragment_data_capacity);
    let fragment_ipv4_len = FRAGMENT_PAYLOAD + UDP_HEADER_LEN + IPV4_HEADER_LEN;
    if fragment_count != 2
        || fragment_ipv4_len <= PERFORMANCE_TUN_MTU
        || fragment_ipv4_len > SUPPORT_UNDERLAY_IPV4_MTU
    {
        return Err(
            "Windows TUN fragment request must split at the TUN MTU without fragmenting the support underlay"
                .to_owned(),
        );
    }
    if fragment_ack_for_request(&fragment_request[..FRAGMENT_PAYLOAD - 1]).is_ok() {
        return Err("truncated fragment request was accepted".to_owned());
    }
    let mut extended_request = fragment_request.clone();
    extended_request.push(0);
    if fragment_ack_for_request(&extended_request).is_ok() {
        return Err("extended fragment request was accepted".to_owned());
    }
    let mut corrupted_request = fragment_request.clone();
    corrupted_request[FRAGMENT_PAYLOAD - 1] ^= 1;
    if fragment_ack_for_request(&corrupted_request).is_ok() {
        return Err("corrupted fragment request was accepted".to_owned());
    }
    if fragment_ack_sequence(&expected_ack[..FRAGMENT_ACK_LEN - 1]).is_ok() {
        return Err("truncated fragment ACK was accepted".to_owned());
    }
    let mut extended_ack = expected_ack.to_vec();
    extended_ack.push(0);
    if fragment_ack_sequence(&extended_ack).is_ok() {
        return Err("extended fragment ACK was accepted".to_owned());
    }
    let mut invalid_ack_tag = expected_ack;
    invalid_ack_tag[0] ^= 1;
    if fragment_ack_sequence(&invalid_ack_tag).is_ok() {
        return Err("fragment ACK with an invalid tag was accepted".to_owned());
    }
    let mut invalid_ack_request_len = expected_ack;
    invalid_ack_request_len[16..24].copy_from_slice(&((FRAGMENT_PAYLOAD - 1) as u64).to_be_bytes());
    if fragment_ack_sequence(&invalid_ack_request_len).is_ok() {
        return Err("fragment ACK with an invalid request length was accepted".to_owned());
    }
    if FRAGMENT_BATCH != 8
        || FRAGMENT_ACK_WINDOW != Duration::from_millis(500)
        || fragment_retry_budget(0) != 1
        || fragment_retry_budget(1) != 1
        || fragment_retry_budget(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS) != 1
        || fragment_retry_budget(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS + 1) != 2
    {
        return Err("Windows TUN fragment retry recipe is invalid".to_owned());
    }
    let mut ordered_batch = FragmentAckBatch::new(100, FRAGMENT_BATCH)?;
    let mut ordered_accounting = FragmentWorkloadAccounting::default();
    for sequence in [107, 100, 106, 101, 105, 102, 104, 103] {
        ordered_accounting.observe_ack(&mut ordered_batch, sequence)?;
    }
    if !ordered_batch.complete()
        || ordered_batch.sole_missing_sequence().is_ok()
        || ordered_accounting.duplicate_or_stale_acks != 0
    {
        return Err("Windows TUN out-of-order fragment ACK accounting is invalid".to_owned());
    }
    let mut multiple_missing_batch = FragmentAckBatch::new(150, FRAGMENT_BATCH)?;
    let mut multiple_missing_accounting = FragmentWorkloadAccounting::default();
    for sequence in 150..156 {
        multiple_missing_accounting.observe_ack(&mut multiple_missing_batch, sequence)?;
    }
    if multiple_missing_batch.sole_missing_sequence().is_ok() {
        return Err("Windows TUN multiple missing fragment ACKs were recoverable".to_owned());
    }
    let mut retry_batch = FragmentAckBatch::new(200, FRAGMENT_BATCH)?;
    let mut retry_accounting = FragmentWorkloadAccounting::default();
    retry_accounting.record_initial_attempts(FragmentPhase::Warmup, FRAGMENT_BATCH as u64)?;
    for sequence in 200..208 {
        if sequence != 203 {
            retry_accounting.observe_ack(&mut retry_batch, sequence)?;
        }
    }
    let retry_diagnostic = fragment_batch_failure("self-check", &retry_batch, 1);
    if retry_batch.complete()
        || retry_batch.sole_missing_sequence()? != 203
        || !retry_diagnostic.contains("first=200")
        || !retry_diagnostic.contains("end=208")
        || !retry_diagnostic.contains("seen=")
        || !retry_diagnostic.contains("missing=1")
        || !retry_diagnostic.contains("missing_sequences=[203]")
        || !retry_diagnostic.contains("budget=1")
        || retry_accounting.observe_ack(&mut retry_batch, 200).is_ok()
        || retry_accounting.observe_ack(&mut retry_batch, 208).is_ok()
    {
        return Err("Windows TUN missing/future fragment ACK mutation was accepted".to_owned());
    }
    retry_accounting.record_ack_window_expiration()?;
    retry_accounting.record_retransmission(FragmentPhase::Warmup, 203, 1)?;
    retry_accounting.observe_ack(&mut retry_batch, 203)?;
    retry_accounting.observe_ack(&mut retry_batch, 203)?;
    if !retry_batch.complete()
        || retry_accounting.observe_ack(&mut retry_batch, 203).is_ok()
        || retry_accounting
            .record_retransmission(FragmentPhase::Warmup, 204, 1)
            .is_ok()
        || retry_accounting.warmup_request_attempts != 9
        || retry_accounting.retransmissions != 1
        || retry_accounting.ack_window_expirations != 1
        || retry_accounting.duplicate_or_stale_acks != 1
    {
        return Err("Windows TUN bounded fragment retransmission accounting is invalid".to_owned());
    }
    let mut stale_batch = FragmentAckBatch::new(300, FRAGMENT_BATCH)?;
    let mut stale_accounting = FragmentWorkloadAccounting::default();
    stale_accounting.record_retransmission(FragmentPhase::Warmup, 299, 1)?;
    stale_accounting.observe_ack(&mut stale_batch, 299)?;
    if stale_accounting.observe_ack(&mut stale_batch, 299).is_ok()
        || stale_accounting.duplicate_or_stale_acks != 1
    {
        return Err("Windows TUN stale fragment ACK bound is invalid".to_owned());
    }
    let labels = [
        "tcp-single-flow",
        "tcp-256-flow-fairness",
        "udp-packets-per-second",
        "udp-8192-association-lookup-expiry",
        "udp-route-once",
        "fragment-reassembly-throughput",
        "wintun-ring-full-drop-rate",
    ];
    for label in labels {
        if Scenario::parse(label)?.label() != label {
            return Err("Windows TUN scenario label did not round-trip".to_owned());
        }
    }
    self_check_support_backlog()?;
    Ok(())
}
