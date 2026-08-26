use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use crate::qualification::{CaseSpec, Direction, Method, Transport};

use super::config::{
    ReservedPorts, ferrum_binary, path_text, reference_client_config, reference_command,
    reference_server_config, write_config,
};
use super::pin_hash::sha256_bytes;
use super::process_guard::{CancellableWorker, CaseDeadline, ProcessGuard};
use super::{IO_TIMEOUT, MAX_UDP_DATAGRAM, POLL_INTERVAL, READINESS_TIMEOUT, SESSION_DATAGRAMS};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_udp_transport(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String, String) {
    let echo = EchoTarget::start(ports.take_target_udp(), deadline);
    let (config_checksum, process_evidence) = match case.direction {
        Direction::FerrumClient => run_udp_ferrum_client_case(
            case,
            reference_binary,
            directory,
            ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
        Direction::ReferenceClient => run_udp_reference_client_case(
            case,
            reference_binary,
            directory,
            ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
    };
    let target_evidence = echo.finish(deadline);
    (config_checksum, process_evidence, target_evidence)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_udp_ferrum_client_case(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String) {
    let config = reference_server_config(case.method, case.reference, shadowsocks, Transport::Udp);
    let config_path = write_config(directory, "reference-server.json", &config);
    ports.release_shadowsocks();
    let mut command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference =
        ProcessGuard::spawn("reference Shadowsocks UDP server", &mut command, deadline);
    wait_for_stable_child(&mut reference, deadline, "reference Shadowsocks UDP server");

    let ferrum_config = format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{proxy}\"\noutbound = \"proxy-out\"\n\n[[outbounds]]\ntag = \"proxy-out\"\ntype = \"shadowsocks\"\nserver = \"{shadowsocks}\"\nmethod = \"{}\"\npsk = \"{}\"\n\n\
         [udp]\nenabled = true\nmax_sessions = 16\nmax_buffered_bytes = 1048576\n\
         idle_timeout_ms = 60000\n",
        case.method.canonical_name(),
        case.method.synthetic_psk()
    );
    let ferrum_path = write_config(directory, "ferrum-client.toml", &ferrum_config);
    ports.release_proxy();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-client"));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum =
        ProcessGuard::spawn("ferrum composed UDP client", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, proxy, deadline, "ferrum composed client");
    exercise_socks_udp(&mut ferrum, proxy, target, case.method, deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    let reference_evidence = reference.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_udp_reference_client_case(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String) {
    let ferrum_config = format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{shadowsocks}\"\noutbound = \"direct\"\n\n[[outbounds]]\ntag = \"direct\"\n\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n\n\
         [udp]\nenabled = true\nmax_sessions = 16\nmax_buffered_bytes = 1048576\n\
         idle_timeout_ms = 60000\n",
        case.method.canonical_name(),
        case.method.synthetic_psk()
    );
    let ferrum_path = write_config(directory, "ferrum-server.toml", &ferrum_config);
    ports.release_shadowsocks();
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-server"));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum =
        ProcessGuard::spawn("ferrum composed UDP server", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, shadowsocks, deadline, "ferrum composed server");

    let config = reference_client_config(
        case.method,
        case.reference,
        shadowsocks,
        proxy,
        Transport::Udp,
    );
    let config_path = write_config(directory, "reference-client.json", &config);
    ports.release_proxy();
    let mut command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference = ProcessGuard::spawn("reference SOCKS UDP client", &mut command, deadline);
    exercise_socks_udp(&mut reference, proxy, target, case.method, deadline);
    let reference_evidence = reference.terminate(deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

pub(super) fn wait_for_stable_child(
    child: &mut ProcessGuard,
    deadline: CaseDeadline,
    label: &'static str,
) {
    let readiness_end =
        Instant::now() + deadline.bounded(Duration::from_millis(500), "UDP readiness");
    while Instant::now() < readiness_end {
        child.assert_running(deadline, label);
        thread::sleep(POLL_INTERVAL.min(deadline.remaining(label)));
    }
}

pub(super) fn wait_for_tcp_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    deadline: CaseDeadline,
    label: &str,
) {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, label);
    loop {
        child.assert_running(deadline, label);
        if TcpStream::connect_timeout(
            &address.into(),
            deadline.bounded(Duration::from_millis(200), label),
        )
        .is_ok()
        {
            return;
        }
        assert!(
            Instant::now() < readiness_end,
            "{label}: readiness deadline exceeded"
        );
        thread::sleep(POLL_INTERVAL.min(deadline.remaining(label)));
    }
}

pub(super) fn exercise_socks_udp(
    child: &mut ProcessGuard,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    method: Method,
    deadline: CaseDeadline,
) {
    let (mut control, relay) = open_socks_udp_association(child, proxy, deadline);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind SOCKS UDP application socket");
    socket
        .set_read_timeout(Some(deadline.bounded(IO_TIMEOUT, "SOCKS UDP receive")))
        .expect("set SOCKS UDP read timeout");
    socket
        .set_write_timeout(Some(deadline.bounded(IO_TIMEOUT, "SOCKS UDP send")))
        .expect("set SOCKS UDP write timeout");
    socket.connect(relay).expect("connect SOCKS UDP relay");

    for sequence in 0..SESSION_DATAGRAMS {
        let payload = case_payload(method, sequence);
        let packet = encode_socks_udp(target, &payload);
        assert_eq!(
            socket.send(&packet).expect("send SOCKS UDP request"),
            packet.len(),
            "SOCKS UDP request short send"
        );
        let mut response = [0_u8; MAX_UDP_DATAGRAM];
        let received = socket
            .recv(&mut response)
            .expect("receive SOCKS UDP response");
        let (source, echoed) = decode_socks_udp(&response[..received]);
        assert_eq!(source, target, "SOCKS UDP observed source address mismatch");
        assert_eq!(echoed, payload, "SOCKS UDP payload mismatch");
        child.assert_running(deadline, "SOCKS UDP session traffic");
    }
    control
        .set_read_timeout(Some(Duration::from_millis(1)))
        .expect("set SOCKS control probe timeout");
    let mut unexpected = [0_u8; 1];
    match control.read(&mut unexpected) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => panic!("SOCKS UDP control channel closed during the session"),
        Ok(_) => panic!("SOCKS UDP control channel emitted unexpected bytes"),
        Err(error) => panic!("SOCKS UDP control channel failed: {error}"),
    }
}

pub(super) fn open_socks_udp_association(
    child: &mut ProcessGuard,
    proxy: SocketAddrV4,
    deadline: CaseDeadline,
) -> (TcpStream, SocketAddr) {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, "SOCKS UDP readiness");
    loop {
        child.assert_running(deadline, "SOCKS UDP readiness");
        if let Ok(mut control) = TcpStream::connect_timeout(
            &proxy.into(),
            deadline.bounded(Duration::from_millis(200), "SOCKS UDP connect"),
        ) {
            set_stream_deadlines(&control, deadline);
            if control.write_all(&[5, 1, 0]).is_ok() {
                let mut method = [0_u8; 2];
                if control.read_exact(&mut method).is_ok() && method == [5, 0] {
                    control
                        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                        .expect("send SOCKS UDP ASSOCIATE");
                    let relay = read_socks_reply(&mut control, proxy);
                    return (control, relay);
                }
            }
        }
        assert!(
            Instant::now() < readiness_end,
            "SOCKS UDP readiness deadline exceeded"
        );
        thread::sleep(POLL_INTERVAL.min(deadline.remaining("SOCKS UDP readiness")));
    }
}

pub(super) fn set_stream_deadlines(stream: &TcpStream, deadline: CaseDeadline) {
    let timeout = deadline.bounded(IO_TIMEOUT, "SOCKS control I/O");
    stream
        .set_read_timeout(Some(timeout))
        .expect("set SOCKS control read timeout");
    stream
        .set_write_timeout(Some(timeout))
        .expect("set SOCKS control write timeout");
}

pub(super) fn read_socks_reply(stream: &mut TcpStream, proxy: SocketAddrV4) -> SocketAddr {
    let mut fixed = [0_u8; 4];
    stream
        .read_exact(&mut fixed)
        .expect("read SOCKS UDP ASSOCIATE reply");
    assert_eq!(&fixed[..3], &[5, 0, 0], "SOCKS UDP ASSOCIATE failed");
    let mut address = read_socks_address(stream, fixed[3]);
    if address.ip().is_unspecified() {
        address.set_ip(IpAddr::V4(*proxy.ip()));
    }
    address
}

pub(super) fn read_socks_address(reader: &mut impl Read, atyp: u8) -> SocketAddr {
    let ip = match atyp {
        1 => {
            let mut bytes = [0_u8; 4];
            reader.read_exact(&mut bytes).expect("read SOCKS IPv4");
            IpAddr::V4(bytes.into())
        }
        4 => {
            let mut bytes = [0_u8; 16];
            reader.read_exact(&mut bytes).expect("read SOCKS IPv6");
            IpAddr::V6(bytes.into())
        }
        3 => {
            let mut length = [0_u8; 1];
            reader
                .read_exact(&mut length)
                .expect("read SOCKS domain length");
            let mut domain = vec![0_u8; usize::from(length[0])];
            reader.read_exact(&mut domain).expect("read SOCKS domain");
            panic!("SOCKS relay returned a domain instead of an IP address");
        }
        _ => panic!("SOCKS relay returned an unsupported address type"),
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port).expect("read SOCKS port");
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

pub(super) fn encode_socks_udp(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub(super) fn decode_socks_udp(packet: &[u8]) -> (SocketAddrV4, &[u8]) {
    assert!(packet.len() >= 10, "SOCKS UDP response is truncated");
    assert_eq!(&packet[..4], &[0, 0, 0, 1], "SOCKS UDP response header");
    let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    (SocketAddrV4::new(ip, port), &packet[10..])
}

pub(super) fn case_payload(method: Method, sequence: usize) -> Vec<u8> {
    format!(
        "m2-udp-{}-datagram-{sequence}",
        match method {
            Method::Aes128Gcm => "aes128",
            Method::Aes256Gcm => "aes256",
            Method::ChaCha20Poly1305 => "chacha",
        }
    )
    .into_bytes()
}

pub(super) struct EchoTarget(pub(super) CancellableWorker<Result<Vec<Vec<u8>>, String>>);

impl EchoTarget {
    pub(super) fn start(socket: UdpSocket, deadline: CaseDeadline) -> Self {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set echo target read timeout");
        socket
            .set_write_timeout(Some(deadline.bounded(IO_TIMEOUT, "echo target send")))
            .expect("set echo target write timeout");
        Self(CancellableWorker::spawn(move |cancelled| {
            let mut received_payloads = Vec::with_capacity(SESSION_DATAGRAMS);
            let mut buffer = [0_u8; MAX_UDP_DATAGRAM];
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    break Err("echo target cancelled".to_owned());
                }
                if received_payloads.len() == SESSION_DATAGRAMS {
                    break Ok(received_payloads);
                }
                match socket.recv_from(&mut buffer) {
                    Ok((received, peer)) => {
                        let payload = buffer[..received].to_vec();
                        match socket.send_to(&payload, peer) {
                            Ok(sent) if sent == payload.len() => received_payloads.push(payload),
                            Ok(_) => break Err("echo target short send".to_owned()),
                            Err(error) => break Err(format!("echo target send failed: {error}")),
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => break Err(format!("echo target receive failed: {error}")),
                }
            }
        }))
    }

    pub(super) fn finish(self, deadline: CaseDeadline) -> String {
        let payloads = self
            .0
            .finish(deadline, "echo target completion")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            payloads.len(),
            SESSION_DATAGRAMS,
            "echo target datagram count mismatch"
        );
        assert_eq!(
            payloads.iter().collect::<HashSet<_>>().len(),
            SESSION_DATAGRAMS,
            "echo target request payloads were not distinct"
        );
        "three-distinct-request-reply-datagrams".to_owned()
    }
}
