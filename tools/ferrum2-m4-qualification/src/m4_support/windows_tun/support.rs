use super::contract::parse_support;
use super::diagnostic::{
    BoundedUdpDiagnosticLedger, IO_TIMEOUT, ROUTE_TARGET_SLOTS, SUPPORT_MAX_TCP_CONNECTIONS,
    SUPPORT_TCP_IDLE_TIMEOUT, SupportUdpDiagnostic, TCP_FAIRNESS_FLOWS, UDP_DIAGNOSTIC_SCOPE,
    UDP_SUPPORT_DIAGNOSTIC_CLOSURE, UDP_SUPPORT_LEDGER_SCHEMA, UdpDiagnosticPayload,
    UdpDiagnosticPhase,
};
use super::scenarios::route_target_addresses;
use super::workload::{configure_support_tcp, fragment_ack_for_request};
use super::workload_diagnostic::bounded_io_error_kind;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

pub(crate) fn serve_tcp(mut stream: TcpStream) -> Result<(), String> {
    configure_support_tcp(&stream)?;
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("support TCP read failed: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("support TCP write failed: {error}"))?;
    }
}

pub(crate) fn bind_support_tcp(address: SocketAddr) -> Result<TcpListener, String> {
    let backlog =
        i32::try_from(SUPPORT_MAX_TCP_CONNECTIONS).expect("Windows TUN support backlog fits i32");
    // Winsock uses a negative backlog as SOMAXCONN_HINT(n); a positive value
    // above its ordinary provider limit is silently capped below this burst.
    #[cfg(windows)]
    let backlog = -backlog;
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|error| format!("create Windows TUN support TCP socket failed: {error}"))?;
    socket
        .bind(&address.into())
        .map_err(|error| format!("bind Windows TUN support TCP failed: {error}"))?;
    socket
        .listen(backlog)
        .map_err(|error| format!("listen Windows TUN support TCP failed: {error}"))?;
    Ok(socket.into())
}

pub(crate) fn self_check_support_backlog() -> Result<(), String> {
    let listener = bind_support_tcp(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("read Windows TUN self-check TCP address failed: {error}"))?;
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
        return Err("Windows TUN support listener did not preserve its bind address".to_owned());
    }
    let clients = (0..TCP_FAIRNESS_FLOWS)
        .map(|index| {
            TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|error| {
                format!("queue Windows TUN support TCP burst {index} failed: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    listener.set_nonblocking(true).map_err(|error| {
        format!("set Windows TUN self-check listener nonblocking failed: {error}")
    })?;
    for index in 0..clients.len() {
        let (stream, _) = listener
            .accept()
            .map_err(|error| format!("accept Windows TUN support TCP burst failed: {error}"))?;
        if index == 0 {
            configure_support_tcp(&stream)?;
            let read_timeout = stream
                .read_timeout()
                .map_err(|error| format!("read support TCP read timeout failed: {error}"))?;
            let write_timeout = stream
                .write_timeout()
                .map_err(|error| format!("read support TCP write timeout failed: {error}"))?;
            if read_timeout != Some(SUPPORT_TCP_IDLE_TIMEOUT) || write_timeout != Some(IO_TIMEOUT) {
                return Err("Windows TUN support TCP timeouts are invalid".to_owned());
            }
        }
    }
    Ok(())
}

pub(crate) struct SupportUdpLedgerEvent<'a> {
    pub(crate) stage: &'a str,
    pub(crate) listen: SocketAddr,
    pub(crate) peer: SocketAddr,
    pub(crate) request: &'a [u8],
    pub(crate) send_attempted: Option<bool>,
    pub(crate) send_result: &'a str,
    pub(crate) sent: Option<usize>,
    pub(crate) error_kind: Option<&'a str>,
}

pub(crate) fn record_support_udp_event(
    diagnostic: Option<&SupportUdpDiagnostic>,
    event: SupportUdpLedgerEvent<'_>,
) {
    let Some(diagnostic) = diagnostic else {
        return;
    };
    let Some(identity) = UdpDiagnosticPayload::parse(event.request) else {
        return;
    };
    if identity.run_nonce != diagnostic.ledger.run_nonce
        || identity.phase != UdpDiagnosticPhase::Bootstrap
    {
        return;
    }
    diagnostic.ledger.record(json!({
        "stage": event.stage,
        "listen_ip": event.listen.ip().to_string(),
        "listen_port": event.listen.port(),
        "remote_ip": event.peer.ip().to_string(),
        "remote_port": event.peer.port(),
        "payload_run_nonce": identity.run_nonce.to_string(),
        "payload_run_nonce_match": true,
        "trial_sequence": identity.trial_sequence,
        "phase": identity.phase.label(),
        "association_index": identity.association_index,
        "round": identity.round,
        "packet_nonce": identity.packet_nonce.to_string(),
        "recv_bytes": event.request.len(),
        "send_attempted": event.send_attempted,
        "send_result": event.send_result,
        "send_bytes": event.sent,
        "error_kind": event.error_kind
    }));
}

pub(crate) fn run_support(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_support(arguments)?;
    let tcp_address = SocketAddr::new(arguments.listen_ip, arguments.tcp_port);
    let udp_addresses = route_target_addresses(arguments.listen_ip, arguments.udp_port)?;
    let tcp = bind_support_tcp(tcp_address)?;
    let udp_sockets = udp_addresses
        .iter()
        .map(|address| {
            UdpSocket::bind(address)
                .map_err(|error| format!("bind Windows TUN support UDP failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnostic = arguments
        .diagnostic
        .as_ref()
        .map(|arguments| {
            BoundedUdpDiagnosticLedger::create(
                arguments,
                UDP_SUPPORT_LEDGER_SCHEMA,
                json!({
                    "pid": std::process::id(),
                    "listen_ip": tcp_address.ip().to_string(),
                    "tcp_port": tcp_address.port(),
                    "udp_ports": udp_addresses.iter().map(|address| address.port()).collect::<Vec<_>>(),
                    "scope": UDP_DIAGNOSTIC_SCOPE,
                    "closure": UDP_SUPPORT_DIAGNOSTIC_CLOSURE
                }),
            )
            .map(SupportUdpDiagnostic::new)
            .map(Arc::new)
        })
        .transpose()?;
    let active = Arc::new(AtomicUsize::new(0));
    let udp_workers = udp_sockets
        .into_iter()
        .enumerate()
        .map(|(slot, udp)| {
            let listen = udp
                .local_addr()
                .map_err(|error| format!("read Windows TUN support UDP address failed: {error}"))?;
            let diagnostic = diagnostic.clone();
            thread::Builder::new()
                .name(format!("tun-support-udp-{slot}"))
                .spawn(move || -> Result<(), String> {
                    let mut buffer = vec![0_u8; 65_507];
                    loop {
                        let (read, peer) = udp
                            .recv_from(&mut buffer)
                            .map_err(|error| format!("support UDP receive failed: {error}"))?;
                        let request = &buffer[..read];
                        if let Some(diagnostic) = diagnostic.as_deref() {
                            diagnostic.observe_finalize_marker(slot, listen, peer, request);
                        }
                        record_support_udp_event(
                            diagnostic.as_deref(),
                            SupportUdpLedgerEvent {
                                stage: "rx",
                                listen,
                                peer,
                                request,
                                send_attempted: None,
                                send_result: "pending",
                                sent: None,
                                error_kind: None,
                            },
                        );
                        let ack;
                        let response = match fragment_ack_for_request(request) {
                            Ok(Some(value)) => {
                                ack = value;
                                &ack[..]
                            }
                            Ok(None) => request,
                            Err(_) => {
                                record_support_udp_event(
                                    diagnostic.as_deref(),
                                    SupportUdpLedgerEvent {
                                        stage: "tx",
                                        listen,
                                        peer,
                                        request,
                                        send_attempted: Some(false),
                                        send_result: "not_attempted",
                                        sent: None,
                                        error_kind: Some("invalid_fragment_request"),
                                    },
                                );
                                continue;
                            }
                        };
                        let response_len = response.len();
                        let sent = match udp.send_to(response, peer) {
                            Ok(sent) => sent,
                            Err(error) => {
                                record_support_udp_event(
                                    diagnostic.as_deref(),
                                    SupportUdpLedgerEvent {
                                        stage: "tx",
                                        listen,
                                        peer,
                                        request,
                                        send_attempted: Some(true),
                                        send_result: "error",
                                        sent: None,
                                        error_kind: Some(bounded_io_error_kind(error.kind())),
                                    },
                                );
                                return Err(format!("support UDP send failed: {error}"));
                            }
                        };
                        record_support_udp_event(
                            diagnostic.as_deref(),
                            SupportUdpLedgerEvent {
                                stage: "tx",
                                listen,
                                peer,
                                request,
                                send_attempted: Some(true),
                                send_result: if sent == response_len {
                                    "success"
                                } else {
                                    "partial"
                                },
                                sent: Some(sent),
                                error_kind: (sent != response_len).then_some("partial"),
                            },
                        );
                        if sent != response_len {
                            return Err("support UDP sent a partial datagram".to_owned());
                        }
                    }
                })
                .map_err(|error| format!("spawn support UDP worker failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "windows_tun_support status=READY tcp={} udp={}..={}",
        tcp.local_addr()
            .map_err(|error| format!("read support TCP address failed: {error}"))?,
        udp_addresses[0],
        udp_addresses[ROUTE_TARGET_SLOTS - 1],
    );
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flush support readiness failed: {error}"))?;
    for accepted in tcp.incoming() {
        let stream = accepted.map_err(|error| format!("support TCP accept failed: {error}"))?;
        if active.fetch_add(1, Ordering::AcqRel) >= SUPPORT_MAX_TCP_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        let active = Arc::clone(&active);
        thread::Builder::new()
            .name("tun-support-tcp".to_owned())
            .spawn(move || {
                let result = serve_tcp(stream);
                active.fetch_sub(1, Ordering::AcqRel);
                result
            })
            .map_err(|error| format!("spawn support TCP worker failed: {error}"))?;
    }
    for worker in udp_workers {
        let _ = worker.join();
    }
    Err("Windows TUN support listener stopped unexpectedly".to_owned())
}
