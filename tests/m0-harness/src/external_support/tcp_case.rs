use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::qualification::{
    CaseSpec, Direction, TcpApplicationGate, TcpExchangeEvent, TcpExchangeState, Transport,
    tcp_shutdown_gate,
};

use super::config::{
    ReservedPorts, ferrum_binary, path_text, reference_client_config, reference_command,
    reference_server_config, write_config,
};
use super::pin_hash::sha256_bytes;
use super::process_guard::{CancellableWorker, CaseDeadline, ProcessGuard};
use super::udp_case::{set_stream_deadlines, wait_for_tcp_listener};
use super::{IO_TIMEOUT, POLL_INTERVAL, READINESS_TIMEOUT};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_tcp_transport(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
) -> (String, String, String) {
    let trace = Arc::new(Mutex::new(TcpExchangeState::default()));
    let (target_process, target_shutdown) =
        TcpTarget::start(ports.take_target_tcp(), deadline, Arc::clone(&trace));
    let (config_checksum, process_evidence) = run_tcp_processes(
        case,
        reference_binary,
        directory,
        ports,
        shadowsocks,
        proxy,
        target,
        deadline,
        &trace,
        target_shutdown,
    );

    let target_evidence = target_process.finish(deadline);
    assert!(
        trace.lock().expect("TCP exchange trace lock").success(),
        "TCP exchange order is incomplete"
    );
    (config_checksum, process_evidence, target_evidence)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_tcp_processes(
    case: CaseSpec,
    reference_binary: &Path,
    directory: &Path,
    ports: &mut ReservedPorts,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) -> (String, String) {
    let config = match case.direction {
        Direction::FerrumClient => {
            reference_server_config(case.method, case.reference, shadowsocks, Transport::Tcp)
        }
        Direction::ReferenceClient => reference_client_config(
            case.method,
            case.reference,
            shadowsocks,
            proxy,
            Transport::Tcp,
        ),
    };
    let config_path = write_config(directory, "reference-tcp.json", &config);
    let ferrum_config = match case.direction {
        Direction::FerrumClient => format!(
            "schema_version = 2\n\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{proxy}\"\noutbound = \"proxy-out\"\n\n[[outbounds]]\ntag = \"proxy-out\"\ntype = \"shadowsocks\"\nserver = \"{shadowsocks}\"\nmethod = \"{}\"\npsk = \"{}\"\n",
            case.method.canonical_name(),
            case.method.synthetic_psk()
        ),
        Direction::ReferenceClient => format!(
            "schema_version = 2\n\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{shadowsocks}\"\noutbound = \"direct\"\n\n[[outbounds]]\ntag = \"direct\"\n\n\
             [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n",
            case.method.canonical_name(),
            case.method.synthetic_psk()
        ),
    };
    let (ferrum_name, ferrum_listen) = match case.direction {
        Direction::FerrumClient => ("ferrum2-client", proxy),
        Direction::ReferenceClient => ("ferrum2-server", shadowsocks),
    };
    let ferrum_path = write_config(directory, "ferrum-tcp.toml", &ferrum_config);
    ports.release_shadowsocks();
    ports.release_proxy();
    let mut ferrum_command = Command::new(ferrum_binary(ferrum_name));
    ferrum_command.args(["--config", path_text(&ferrum_path)]);
    let mut ferrum = ProcessGuard::spawn("ferrum TCP process", &mut ferrum_command, deadline);
    wait_for_tcp_listener(&mut ferrum, ferrum_listen, deadline, "ferrum TCP listener");
    let mut reference_command = reference_command(case.reference, reference_binary, &config_path);
    let mut reference =
        ProcessGuard::spawn("reference TCP process", &mut reference_command, deadline);
    let reference_listen = match case.direction {
        Direction::FerrumClient => shadowsocks,
        Direction::ReferenceClient => proxy,
    };
    wait_for_tcp_listener(
        &mut reference,
        reference_listen,
        deadline,
        "reference TCP listener",
    );
    exercise_socks_tcp(proxy, target, deadline, trace, target_shutdown);
    let reference_evidence = reference.terminate(deadline);
    let ferrum_evidence = ferrum.terminate(deadline);
    (
        sha256_bytes(config.as_bytes()),
        format!("reference=[{reference_evidence}], ferrum=[{ferrum_evidence}]"),
    )
}

pub(super) fn exercise_socks_tcp(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    exercise_socks_tcp_request(proxy, &request, deadline, trace, target_shutdown);
}

pub(super) fn exercise_socks_domain_tcp(
    proxy: SocketAddrV4,
    name: &str,
    target: SocketAddrV4,
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let length = u8::try_from(name.len()).expect("SOCKS domain length");
    let mut request = vec![5, 1, 0, 3, length];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&target.port().to_be_bytes());
    exercise_socks_tcp_request(proxy, &request, deadline, trace, target_shutdown);
}

pub(super) fn exercise_socks_tcp_request(
    proxy: SocketAddrV4,
    request: &[u8],
    deadline: CaseDeadline,
    trace: &Arc<Mutex<TcpExchangeState>>,
    target_shutdown: TcpApplicationGate,
) {
    let mut stream = TcpStream::connect_timeout(
        &proxy.into(),
        deadline.bounded(IO_TIMEOUT, "connect SOCKS TCP"),
    )
    .expect("connect SOCKS TCP");
    set_stream_deadlines(&stream, deadline);
    write_all_case(&mut stream, &[5, 1, 0], deadline, "SOCKS TCP greeting");
    let mut method = [0_u8; 2];
    read_exact_case(&mut stream, &mut method, deadline, "SOCKS TCP method");
    assert_eq!(method, [5, 0], "SOCKS TCP no-auth selected");

    write_all_case(&mut stream, request, deadline, "SOCKS TCP connect request");
    let mut reply = [0_u8; 10];
    read_exact_case(&mut stream, &mut reply, deadline, "SOCKS TCP connect reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "SOCKS TCP connect failed");

    let forward = tcp_forward_payload();
    write_all_case(&mut stream, &forward, deadline, "TCP forward payload");
    let reverse = tcp_reverse_payload();
    let mut received = vec![0_u8; reverse.len()];
    read_exact_case(&mut stream, &mut received, deadline, "TCP reverse payload");
    assert_eq!(received, reverse, "TCP reverse payload mismatch");
    record_tcp_event(trace, TcpExchangeEvent::ReverseMatched);
    // Commit the application event before the target can record the resulting EOF.
    let application_shutdown = {
        let mut exchange = trace.lock().expect("TCP exchange trace lock");
        stream
            .shutdown(Shutdown::Write)
            .expect("application TCP write half-close");
        exchange.record(TcpExchangeEvent::ApplicationShutdown)
    };
    application_shutdown
        .unwrap_or_else(|error| panic!("{error}: {:?}", TcpExchangeEvent::ApplicationShutdown));
    let application_acknowledgement = target_shutdown
        .wait(deadline.remaining("TCP target shutdown synchronization"))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut extra = [0_u8; 1];
    assert_eq!(
        read_case(
            &mut stream,
            &mut extra,
            deadline,
            "TCP application clean EOF"
        ),
        0,
        "TCP application expected clean EOF"
    );
    record_tcp_event(trace, TcpExchangeEvent::ApplicationCleanEof);
    application_acknowledgement
        .send(Ok(()))
        .unwrap_or_else(|error| panic!("{error}"));
}

pub(super) fn record_tcp_event(trace: &Arc<Mutex<TcpExchangeState>>, event: TcpExchangeEvent) {
    let result = trace.lock().expect("TCP exchange trace lock").record(event);
    result.unwrap_or_else(|error| panic!("{error}: {event:?}"));
}

pub(super) fn tcp_forward_payload() -> Vec<u8> {
    let mut payload = vec![0x49];
    payload.extend(std::iter::repeat_n(0x5a, 16_385));
    payload
}

pub(super) fn tcp_reverse_payload() -> Vec<u8> {
    let mut payload = vec![0xa6];
    payload.extend((0..16_385).map(|index| (index % 251) as u8));
    payload
}

pub(super) fn write_all_case(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: CaseDeadline,
    label: &str,
) {
    while !bytes.is_empty() {
        deadline.check(label);
        set_stream_deadlines(stream, deadline);
        let written = stream
            .write(bytes)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_ne!(written, 0, "{label}: write zero");
        bytes = &bytes[written..];
    }
}

pub(super) fn read_exact_case(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: CaseDeadline,
    label: &str,
) {
    while !bytes.is_empty() {
        let read = read_case(stream, bytes, deadline, label);
        assert_ne!(read, 0, "{label}: premature EOF");
        bytes = &mut bytes[read..];
    }
}

pub(super) fn read_case(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: CaseDeadline,
    label: &str,
) -> usize {
    deadline.check(label);
    set_stream_deadlines(stream, deadline);
    stream
        .read(bytes)
        .unwrap_or_else(|error| panic!("{label}: {error}"))
}

pub(super) struct TcpTarget(pub(super) CancellableWorker<Result<String, String>>);

impl TcpTarget {
    pub(super) fn start(
        listener: TcpListener,
        deadline: CaseDeadline,
        trace: Arc<Mutex<TcpExchangeState>>,
    ) -> (Self, TcpApplicationGate) {
        listener
            .set_nonblocking(true)
            .expect("set TCP target listener nonblocking");
        let (target_gate, application_gate) = tcp_shutdown_gate();
        let worker = CancellableWorker::spawn(move |cancelled| {
            let (stream, evidence) = target_gate.finish(
                run_tcp_target(listener, deadline, &cancelled, &trace),
                deadline.remaining("TCP application acknowledgement"),
            )?;
            drop(stream);
            Ok(evidence)
        });
        (Self(worker), application_gate)
    }

    pub(super) fn finish(self, deadline: CaseDeadline) -> String {
        self.0
            .finish(deadline, "TCP target completion")
            .unwrap_or_else(|error| panic!("TCP target failed: {error}"))
    }
}

pub(super) fn run_tcp_target(
    listener: TcpListener,
    deadline: CaseDeadline,
    cancelled: &AtomicBool,
    trace: &Arc<Mutex<TcpExchangeState>>,
) -> Result<(TcpStream, String), String> {
    let readiness_end = Instant::now() + deadline.bounded(READINESS_TIMEOUT, "TCP target accept");
    let mut stream = loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err("TCP target cancelled".to_owned());
        }
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                deadline.check("TCP target accept");
                if Instant::now() >= readiness_end {
                    return Err("TCP target accept deadline exceeded".to_owned());
                }
                thread::sleep(POLL_INTERVAL.min(deadline.remaining("TCP target accept")));
            }
            Err(error) => return Err(format!("TCP target accept failed: {error}")),
        }
    };
    let forward = tcp_forward_payload();
    let mut received = vec![0_u8; forward.len()];
    read_exact_case(
        &mut stream,
        &mut received,
        deadline,
        "TCP target forward payload",
    );
    if received != forward {
        return Err("TCP target forward payload mismatch".to_owned());
    }
    record_tcp_event(trace, TcpExchangeEvent::ForwardMatched);
    let reverse = tcp_reverse_payload();
    write_all_case(
        &mut stream,
        &reverse,
        deadline,
        "TCP target reverse payload",
    );
    let mut extra = [0_u8; 1];
    if read_case(&mut stream, &mut extra, deadline, "TCP target clean EOF") != 0 {
        return Err("TCP target received bytes after expected payload".to_owned());
    }
    record_tcp_event(trace, TcpExchangeEvent::TargetCleanEof);
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("TCP target write shutdown failed: {error}"))?;
    record_tcp_event(trace, TcpExchangeEvent::TargetShutdown);
    Ok((
        stream,
        format!(
            "forward_bytes={}, reverse_bytes={}, clean_eof=true",
            forward.len(),
            reverse.len()
        ),
    ))
}
