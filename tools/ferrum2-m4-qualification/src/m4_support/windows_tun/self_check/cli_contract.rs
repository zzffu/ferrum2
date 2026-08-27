use std::ffi::OsString;
use std::fs::File;
use std::net::IpAddr;

use super::super::contract::{
    Scenario, parse_support, parse_udp_diagnostic_finalize, parse_workload,
};
use super::super::diagnostic::{
    ASSOCIATIONS, UDP_ASSOCIATION_SOURCE_IPV4, UDP_ASSOCIATION_SOURCE_PORT_FIRST,
    UDP_ASSOCIATION_SOURCE_PORT_LAST, UDP_DIAGNOSTIC_MAX_EVENTS, UdpAssociationSourceArgs,
    UdpDiagnosticFinalizeArgs,
};
use super::super::workload::udp_association_source_endpoint;
use super::SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE;

pub(super) fn check() -> Result<(), String> {
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
        OsString::from(SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE.to_string()),
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
        || diagnostic.trial_sequence != SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE
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
            trial_sequence: SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE,
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
    Ok(())
}
