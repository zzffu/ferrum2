use super::diagnostic::{
    ROUTE_TARGET_SLOTS, UDP_ASSOCIATION_SOURCE_IPV4, UDP_ASSOCIATION_SOURCE_PORT_FIRST,
    UDP_ASSOCIATION_SOURCE_PORT_LAST, UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE,
    UDP_DIAGNOSTIC_MAX_EVENTS, UdpAssociationSourceArgs, UdpDiagnosticFinalizeArgs,
    UdpDiagnosticLedgerArgs, UdpWorkloadDiagnosticArgs,
};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Component, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scenario {
    TcpSingle,
    TcpFairness,
    UdpPackets,
    UdpAssociations,
    UdpRouteOnce,
    Fragments,
    RingFull,
}

impl Scenario {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "tcp-single-flow" => Ok(Self::TcpSingle),
            "tcp-256-flow-fairness" => Ok(Self::TcpFairness),
            "udp-packets-per-second" => Ok(Self::UdpPackets),
            "udp-8192-association-lookup-expiry" => Ok(Self::UdpAssociations),
            "udp-route-once" => Ok(Self::UdpRouteOnce),
            "fragment-reassembly-throughput" => Ok(Self::Fragments),
            "wintun-ring-full-drop-rate" => Ok(Self::RingFull),
            _ => Err("unsupported Windows TUN workload scenario".to_owned()),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::TcpSingle => "tcp-single-flow",
            Self::TcpFairness => "tcp-256-flow-fairness",
            Self::UdpPackets => "udp-packets-per-second",
            Self::UdpAssociations => "udp-8192-association-lookup-expiry",
            Self::UdpRouteOnce => "udp-route-once",
            Self::Fragments => "fragment-reassembly-throughput",
            Self::RingFull => "wintun-ring-full-drop-rate",
        }
    }
}

pub(crate) struct WorkloadArgs {
    pub(crate) scenario: Scenario,
    pub(crate) target_ip: IpAddr,
    pub(crate) tcp_port: u16,
    pub(crate) udp_port: u16,
    pub(crate) output: PathBuf,
    pub(crate) association_source: Option<UdpAssociationSourceArgs>,
    pub(crate) diagnostic: Option<UdpWorkloadDiagnosticArgs>,
}

pub(crate) struct ProbeArgs {
    pub(crate) target_ip: IpAddr,
    pub(crate) tcp_port: u16,
    pub(crate) udp_port: u16,
}

pub(crate) struct SupportArgs {
    pub(crate) listen_ip: IpAddr,
    pub(crate) tcp_port: u16,
    pub(crate) udp_port: u16,
    pub(crate) diagnostic: Option<UdpDiagnosticLedgerArgs>,
}

pub(crate) fn parse_pairs(arguments: &[OsString]) -> Result<Vec<(String, String)>, String> {
    let mut chunks = arguments.chunks_exact(2);
    let mut pairs = Vec::new();
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "Windows TUN option name is not UTF-8".to_owned())?;
        let value = pair[1]
            .to_str()
            .ok_or_else(|| format!("Windows TUN option {flag} is not UTF-8"))?;
        pairs.push((flag.to_owned(), value.to_owned()));
    }
    if !chunks.remainder().is_empty() {
        return Err("every Windows TUN option requires one value".to_owned());
    }
    Ok(pairs)
}

pub(crate) fn take_unique(
    slot: &mut Option<String>,
    value: String,
    flag: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate Windows TUN option: {flag}"));
    }
    Ok(())
}

pub(crate) fn parse_port(value: Option<String>, flag: &str) -> Result<u16, String> {
    let value = value.ok_or_else(|| format!("missing Windows TUN option: {flag}"))?;
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be a decimal TCP/UDP port"))?;
    if port == 0 || port.to_string() != value {
        return Err(format!("{flag} must be a canonical nonzero port"));
    }
    Ok(port)
}

pub(crate) fn parse_canonical_nonzero_u64(value: String, flag: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a canonical nonzero decimal integer"))?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(format!(
            "{flag} must be a canonical nonzero decimal integer"
        ));
    }
    Ok(parsed)
}

pub(crate) fn parse_diagnostic_max_events(value: String) -> Result<usize, String> {
    let parsed = parse_canonical_nonzero_u64(value, "--diagnostic-max-events")?;
    let parsed = usize::try_from(parsed)
        .map_err(|_| "--diagnostic-max-events is outside the supported range".to_owned())?;
    if parsed > UDP_DIAGNOSTIC_MAX_EVENTS {
        return Err(format!(
            "--diagnostic-max-events cannot exceed {UDP_DIAGNOSTIC_MAX_EVENTS}"
        ));
    }
    Ok(parsed)
}

pub(crate) fn parse_diagnostic_trial_sequence(value: String) -> Result<u16, String> {
    let parsed = parse_canonical_nonzero_u64(value, "--diagnostic-trial-sequence")?;
    u16::try_from(parsed)
        .map_err(|_| "--diagnostic-trial-sequence is outside the supported range".to_owned())
}

pub(crate) fn parse_association_source_ip(value: String) -> Result<IpAddr, String> {
    let expected = UDP_ASSOCIATION_SOURCE_IPV4.to_string();
    if value != expected {
        return Err(format!("--source-ip must be exactly {expected}"));
    }
    Ok(IpAddr::V4(UDP_ASSOCIATION_SOURCE_IPV4))
}

pub(crate) fn parse_association_source_port(
    value: String,
    flag: &str,
    expected: u16,
) -> Result<u16, String> {
    let parsed = parse_port(Some(value), flag)?;
    if parsed != expected {
        return Err(format!("{flag} must be exactly {expected}"));
    }
    Ok(parsed)
}

pub(crate) fn parse_association_source_args(
    source_ip: Option<String>,
    source_port_first: Option<String>,
    source_port_last: Option<String>,
) -> Result<Option<UdpAssociationSourceArgs>, String> {
    match (source_ip, source_port_first, source_port_last) {
        (None, None, None) => Ok(None),
        (Some(source_ip), Some(source_port_first), Some(source_port_last)) => {
            Ok(Some(UdpAssociationSourceArgs {
                source_ip: parse_association_source_ip(source_ip)?,
                source_port_first: parse_association_source_port(
                    source_port_first,
                    "--source-port-first",
                    UDP_ASSOCIATION_SOURCE_PORT_FIRST,
                )?,
                source_port_last: parse_association_source_port(
                    source_port_last,
                    "--source-port-last",
                    UDP_ASSOCIATION_SOURCE_PORT_LAST,
                )?,
            }))
        }
        _ => Err(
            "--source-ip, --source-port-first, and --source-port-last must be supplied together"
                .to_owned(),
        ),
    }
}

pub(crate) fn validate_diagnostic_ledger_path(value: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .extension()
            .is_none_or(|extension| extension != "ndjson")
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(
            "--diagnostic-ledger must be an absolute normalized .ndjson file path".to_owned(),
        );
    }
    if path.exists() {
        return Err("Windows TUN UDP diagnostic ledger baseline must be absent".to_owned());
    }
    if path.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err("Windows TUN UDP diagnostic ledger parent must exist".to_owned());
    }
    Ok(path)
}

pub(crate) fn parse_diagnostic_ledger_args(
    ledger: Option<String>,
    run_nonce: Option<String>,
    max_events: Option<String>,
) -> Result<Option<UdpDiagnosticLedgerArgs>, String> {
    let supplied = [ledger.is_some(), run_nonce.is_some(), max_events.is_some()];
    if supplied.iter().all(|supplied| !supplied) {
        return Ok(None);
    }
    if !supplied.iter().all(|supplied| *supplied) {
        return Err(
            "--diagnostic-ledger, --diagnostic-run-nonce, and --diagnostic-max-events must be supplied together"
                .to_owned(),
        );
    }
    Ok(Some(UdpDiagnosticLedgerArgs {
        path: validate_diagnostic_ledger_path(ledger.expect("checked diagnostic ledger"))?,
        run_nonce: parse_canonical_nonzero_u64(
            run_nonce.expect("checked diagnostic run nonce"),
            "--diagnostic-run-nonce",
        )?,
        max_events: parse_diagnostic_max_events(
            max_events.expect("checked diagnostic max events"),
        )?,
    }))
}

pub(crate) fn parse_workload(arguments: &[OsString]) -> Result<WorkloadArgs, String> {
    let mut scenario = None;
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut output = None;
    let mut diagnostic_ledger = None;
    let mut diagnostic_run_nonce = None;
    let mut diagnostic_max_events = None;
    let mut diagnostic_trial_sequence = None;
    let mut source_ip = None;
    let mut source_port_first = None;
    let mut source_port_last = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--scenario" => take_unique(&mut scenario, value, &flag)?,
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--output" => take_unique(&mut output, value, &flag)?,
            "--diagnostic-ledger" => take_unique(&mut diagnostic_ledger, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            "--diagnostic-max-events" => take_unique(&mut diagnostic_max_events, value, &flag)?,
            "--diagnostic-trial-sequence" => {
                take_unique(&mut diagnostic_trial_sequence, value, &flag)?
            }
            "--source-ip" => take_unique(&mut source_ip, value, &flag)?,
            "--source-port-first" => take_unique(&mut source_port_first, value, &flag)?,
            "--source-port-last" => take_unique(&mut source_port_last, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN option: {flag}")),
        }
    }
    let scenario = Scenario::parse(
        &scenario.ok_or_else(|| "missing Windows TUN option: --scenario".to_owned())?,
    )?;
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    let output =
        PathBuf::from(output.ok_or_else(|| "missing Windows TUN option: --output".to_owned())?);
    if output.as_os_str().is_empty() || output.exists() {
        return Err("Windows TUN workload output baseline must be absent".to_owned());
    }
    if output.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err("Windows TUN workload output parent must exist".to_owned());
    }
    let diagnostic_ledger = parse_diagnostic_ledger_args(
        diagnostic_ledger,
        diagnostic_run_nonce,
        diagnostic_max_events,
    )?;
    let association_source =
        parse_association_source_args(source_ip, source_port_first, source_port_last)?;
    let diagnostic = match (diagnostic_ledger, diagnostic_trial_sequence) {
        (None, None) => None,
        (Some(ledger), Some(trial_sequence)) => {
            let trial_sequence = parse_diagnostic_trial_sequence(trial_sequence)?;
            if trial_sequence != UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE {
                return Err(format!(
                    "--diagnostic-trial-sequence must be exactly {UDP_DIAGNOSTIC_FINALIZE_TRIAL_SEQUENCE}"
                ));
            }
            Some(UdpWorkloadDiagnosticArgs {
                ledger,
                trial_sequence,
            })
        }
        _ => {
            return Err(
                "workload UDP diagnostics require the ledger group and --diagnostic-trial-sequence together"
                    .to_owned(),
            );
        }
    };
    if scenario == Scenario::UdpAssociations && association_source.is_none() {
        return Err(
            "udp-8192-association-lookup-expiry requires the complete fixed source endpoint group"
                .to_owned(),
        );
    }
    if scenario != Scenario::UdpAssociations && association_source.is_some() {
        return Err(
            "fixed source endpoint options are only supported for udp-8192-association-lookup-expiry"
                .to_owned(),
        );
    }
    if diagnostic.is_some() && scenario != Scenario::UdpAssociations {
        return Err(
            "workload UDP diagnostics are only supported for udp-8192-association-lookup-expiry"
                .to_owned(),
        );
    }
    if scenario == Scenario::UdpAssociations && !target_ip.is_ipv4() {
        return Err("udp-8192-association-lookup-expiry requires an IPv4 target".to_owned());
    }
    if diagnostic
        .as_ref()
        .is_some_and(|diagnostic| diagnostic.ledger.path == output)
    {
        return Err("workload observation and diagnostic ledger paths must differ".to_owned());
    }
    Ok(WorkloadArgs {
        scenario,
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
        output,
        association_source,
        diagnostic,
    })
}

pub(crate) fn parse_probe(arguments: &[OsString]) -> Result<ProbeArgs, String> {
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN probe option: {flag}")),
        }
    }
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    Ok(ProbeArgs {
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
    })
}

pub(crate) fn parse_support(arguments: &[OsString]) -> Result<SupportArgs, String> {
    let mut listen_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut diagnostic_ledger = None;
    let mut diagnostic_run_nonce = None;
    let mut diagnostic_max_events = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--listen-ip" => take_unique(&mut listen_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--diagnostic-ledger" => take_unique(&mut diagnostic_ledger, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            "--diagnostic-max-events" => take_unique(&mut diagnostic_max_events, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN support option: {flag}")),
        }
    }
    let listen_ip = listen_ip
        .ok_or_else(|| "missing Windows TUN option: --listen-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--listen-ip must be an IP literal".to_owned())?;
    if listen_ip.is_multicast() {
        return Err("--listen-ip cannot be multicast".to_owned());
    }
    Ok(SupportArgs {
        listen_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
        diagnostic: parse_diagnostic_ledger_args(
            diagnostic_ledger,
            diagnostic_run_nonce,
            diagnostic_max_events,
        )?,
    })
}

pub(crate) fn parse_udp_diagnostic_finalize(
    arguments: &[OsString],
) -> Result<UdpDiagnosticFinalizeArgs, String> {
    let mut target_ip = None;
    let mut udp_port = None;
    let mut diagnostic_run_nonce = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--diagnostic-run-nonce" => take_unique(&mut diagnostic_run_nonce, value, &flag)?,
            _ => {
                return Err(format!(
                    "unsupported Windows TUN UDP diagnostic finalize option: {flag}"
                ));
            }
        }
    }
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    let udp_port = parse_port(udp_port, "--udp-port")?;
    udp_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .ok_or_else(|| "--udp-port cannot address four contiguous UDP listeners".to_owned())?;
    Ok(UdpDiagnosticFinalizeArgs {
        target_ip,
        udp_port,
        run_nonce: parse_canonical_nonzero_u64(
            diagnostic_run_nonce
                .ok_or_else(|| "missing Windows TUN option: --diagnostic-run-nonce".to_owned())?,
            "--diagnostic-run-nonce",
        )?,
    })
}
