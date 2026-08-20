#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use local_support::{
    ChildGuard, DnsReply, DnsStep, active_child_count, bind_loopback_listener,
    hold_process_spawns_at_or_below, start_dns_script, unused_loopback, unused_tcp_udp_loopback,
    wait_for_bound, wait_for_tcp_udp_bound,
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const NO_TRAFFIC_TIMEOUT: Duration = Duration::from_millis(500);

struct TcpEcho {
    address: SocketAddrV4,
    worker: Option<thread::JoinHandle<Vec<u8>>>,
}

impl TcpEcho {
    fn join(mut self) -> Vec<u8> {
        self.worker
            .take()
            .expect("TCP echo worker")
            .join()
            .expect("TCP echo worker join")
    }
}

impl Drop for TcpEcho {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = TcpStream::connect(self.address);
            let _ = worker.join();
        }
    }
}

struct UdpEcho {
    address: SocketAddrV4,
    worker: Option<thread::JoinHandle<Vec<u8>>>,
}

impl UdpEcho {
    fn join(mut self) -> Vec<u8> {
        self.worker
            .take()
            .expect("UDP echo worker")
            .join()
            .expect("UDP echo worker join")
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            if let Ok(wakeup) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
                let _ = wakeup.send_to(&[0], self.address);
            }
            let _ = worker.join();
        }
    }
}

fn paired_loopback_target() -> (TcpListener, UdpSocket, SocketAddrV4) {
    loop {
        let listener = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("paired target TCP bind");
        let address = match listener.local_addr().expect("paired target address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 target listener"),
        };
        match UdpSocket::bind(address) {
            Ok(socket) => return (listener, socket, address),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => panic!("paired target UDP bind failed: {error}"),
        }
    }
}

fn start_tcp_echo(listener: TcpListener, address: SocketAddrV4) -> TcpEcho {
    listener
        .set_nonblocking(true)
        .expect("TCP echo nonblocking listener");
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + IO_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "TCP echo accept timed out");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("TCP echo accept failed: {error}"),
            }
        };
        // Windows inherits the listener's nonblocking mode on accepted sockets.
        // The echo body deliberately uses bounded blocking I/O below.
        stream
            .set_nonblocking(false)
            .expect("TCP echo blocking stream");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("TCP echo read timeout");
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("TCP echo write timeout");
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).expect("TCP echo read");
        stream.write_all(&payload).expect("TCP echo write");
        stream
            .shutdown(Shutdown::Write)
            .expect("TCP echo half close");
        payload
    });
    TcpEcho {
        address,
        worker: Some(worker),
    }
}

fn start_udp_echo(socket: UdpSocket, address: SocketAddrV4) -> UdpEcho {
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("UDP echo read timeout");
    let worker = thread::spawn(move || {
        let mut payload = [0_u8; 512];
        let (length, peer) = socket.recv_from(&mut payload).expect("UDP echo receive");
        socket
            .send_to(&payload[..length], peer)
            .expect("UDP echo send");
        payload[..length].to_vec()
    });
    UdpEcho {
        address,
        worker: Some(worker),
    }
}

fn write_direct_client_config(
    directory: &Path,
    name: &str,
    listen: SocketAddrV4,
    dns: Option<(SocketAddrV4, SocketAddrV4)>,
) -> PathBuf {
    let dns = dns.map_or_else(String::new, |(dns_listen, upstream)| {
        format!(
            "[dns]\n\
             timeout_ms = 1000\n\
             max_inflight = 8\n\
             strategy = \"ipv4_only\"\n\
             [dns.cache]\n\
             enabled = true\n\
             max_entries = 16\n\
             [[dns.inbounds]]\n\
             tag = \"application-dns-in\"\n\
             listen = \"{dns_listen}\"\n\
             [[dns.servers]]\n\
             tag = \"application-upstream\"\n\
             transport = \"udp\"\n\
             address = \"{upstream}\"\n\
             [dns.route]\n\
             final = \"application-upstream\"\n"
        )
    });
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"proxy\"\n\
         listen = \"{listen}\"\n\
         outbound = \"direct\"\n\
         [[outbounds]]\n\
         tag = \"direct\"\n\
         type = \"direct\"\n\
         {dns}\
         [udp]\n\
         enabled = true\n\
         max_sessions = 8\n\
         max_buffered_bytes = 1048576\n\
         idle_timeout_ms = 60000\n"
    );
    let path = directory.join(format!("{name}.toml"));
    fs::write(&path, source).expect("write V2 direct client config");
    path
}

fn read_socks_reply(stream: &mut TcpStream) -> u8 {
    let mut fixed = [0_u8; 4];
    stream
        .read_exact(&mut fixed)
        .expect("SOCKS response header");
    assert_eq!(fixed[0], 5, "SOCKS response version");
    assert_eq!(fixed[2], 0, "SOCKS response reserved byte");
    let address_len = match fixed[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .expect("SOCKS response domain length");
            usize::from(length[0])
        }
        other => panic!("unsupported SOCKS response address type: {other}"),
    };
    let mut address_and_port = vec![0_u8; address_len + 2];
    stream
        .read_exact(&mut address_and_port)
        .expect("SOCKS response address");
    fixed[1]
}

fn domain_wire(name: &str, port: u16) -> Vec<u8> {
    let mut wire = vec![3, u8::try_from(name.len()).expect("SOCKS domain length")];
    wire.extend_from_slice(name.as_bytes());
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

fn socks_tcp_domain(client: SocketAddrV4, name: &str, port: u16) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(client).expect("connect SOCKS TCP client");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS TCP read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS TCP write timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS TCP greeting");
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .expect("SOCKS TCP method response");
    assert_eq!(method, [5, 0], "SOCKS TCP no-auth method");
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&domain_wire(name, port));
    stream.write_all(&request).expect("SOCKS TCP request");
    let result = read_socks_reply(&mut stream);
    (stream, result)
}

fn tcp_domain_round_trip(client: SocketAddrV4, name: &str, port: u16, payload: &[u8]) {
    let (mut stream, result) = socks_tcp_domain(client, name, port);
    assert_eq!(result, 0, "SOCKS TCP domain connect failed");
    stream.write_all(payload).expect("SOCKS TCP payload");
    stream
        .shutdown(Shutdown::Write)
        .expect("SOCKS TCP half close");
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).expect("SOCKS TCP echo");
    assert_eq!(echoed, payload, "SOCKS TCP payload mismatch");
}

fn assert_tcp_domain_failure(client: SocketAddrV4, name: &str, port: u16) {
    let (_stream, result) = socks_tcp_domain(client, name, port);
    assert_ne!(result, 0, "configured DNS failure used a fallback resolver");
}

fn udp_associate(client: SocketAddrV4) -> (TcpStream, UdpSocket, SocketAddrV4) {
    let mut control = TcpStream::connect(client).expect("connect SOCKS UDP control");
    control
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS UDP control timeout");
    control.write_all(&[5, 1, 0]).expect("SOCKS UDP greeting");
    let mut method = [0_u8; 2];
    control
        .read_exact(&mut method)
        .expect("SOCKS UDP method response");
    assert_eq!(method, [5, 0], "SOCKS UDP no-auth method");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .expect("SOCKS UDP associate request");
    let mut fixed = [0_u8; 4];
    control
        .read_exact(&mut fixed)
        .expect("SOCKS UDP associate header");
    assert_eq!(&fixed[..3], &[5, 0, 0], "SOCKS UDP associate failed");
    assert_eq!(fixed[3], 1, "SOCKS UDP relay must be IPv4");
    let mut address = [0_u8; 6];
    control
        .read_exact(&mut address)
        .expect("SOCKS UDP relay address");
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(address[0], address[1], address[2], address[3]),
        u16::from_be_bytes([address[4], address[5]]),
    );
    let application =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("SOCKS UDP application socket");
    application
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS UDP application timeout");
    (control, application, relay)
}

fn socks_udp_datagram(name: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0];
    wire.extend_from_slice(&domain_wire(name, port));
    wire.extend_from_slice(payload);
    wire
}

fn expected_udp_response(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0, 1];
    wire.extend_from_slice(&target.ip().octets());
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn udp_domain_round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    name: &str,
    target: SocketAddrV4,
    payload: &[u8],
) {
    let request = socks_udp_datagram(name, target.port(), payload);
    assert_eq!(
        application
            .send_to(&request, relay)
            .expect("SOCKS UDP domain send"),
        request.len()
    );
    let mut response = [0_u8; 1024];
    let (length, source) = application
        .recv_from(&mut response)
        .expect("SOCKS UDP domain response");
    assert_eq!(source, SocketAddr::V4(relay), "SOCKS UDP relay source");
    assert_eq!(
        &response[..length],
        expected_udp_response(target, payload),
        "SOCKS UDP domain payload mismatch"
    );
}

fn assert_no_udp_packet(socket: &UdpSocket, message: &str) {
    socket
        .set_read_timeout(Some(NO_TRAFFIC_TIMEOUT))
        .expect("no-traffic UDP timeout");
    let mut packet = [0_u8; 64];
    assert!(
        matches!(
            socket.recv_from(&mut packet),
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ),
        "{message}"
    );
}

fn stop_client_and_rebind(
    mut client: ChildGuard,
    client_address: SocketAddrV4,
    dns_listen: Option<SocketAddrV4>,
    relay: SocketAddrV4,
    forbidden_stderr: &[&str],
) {
    let exit = client.terminate_and_reap_with_exit(IO_TIMEOUT);
    exit.assert_stderr_excludes(forbidden_stderr);
    let _spawn_guard = hold_process_spawns_at_or_below(0);
    assert_eq!(active_child_count(), 0, "client process leaked");
    drop(bind_loopback_listener(client_address).expect("client listener exact rebind"));
    drop(UdpSocket::bind(relay).expect("SOCKS UDP relay exact rebind"));
    if let Some(dns_listen) = dns_listen {
        drop(bind_loopback_listener(dns_listen).expect("DNS TCP listener exact rebind"));
        drop(UdpSocket::bind(dns_listen).expect("DNS UDP listener exact rebind"));
    }
}

#[test]
fn v2_client_direct_application_resolution_obeys_configured_and_system_modes() {
    let _initial_spawn_guard = hold_process_spawns_at_or_below(0);
    assert_eq!(active_child_count(), 0, "unexpected process baseline");
    drop(_initial_spawn_guard);

    let directory = tempfile::tempdir().expect("client resolver E2E tempdir");

    // A configured resolver must handle an application-only `.test` name for
    // both Direct TCP and Direct UDP. Two scripted answers keep this assertion
    // independent of whether the shared TTL cache serves the second protocol.
    let configured_name = "client-resolver-success.test";
    let (tcp_target, udp_target, target_address) = paired_loopback_target();
    let tcp_echo = start_tcp_echo(tcp_target, target_address);
    let udp_echo = start_udp_echo(udp_target, target_address);
    let dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::Addresses(vec![Ipv4Addr::LOCALHOST]),
        },
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::Addresses(vec![Ipv4Addr::LOCALHOST]),
        },
    ]);
    let dns_address = dns.address();
    let client_address = unused_loopback();
    let dns_listen = unused_tcp_udp_loopback();
    let config = write_direct_client_config(
        directory.path(),
        "configured-success",
        client_address,
        Some((dns_listen, dns_address)),
    );
    let spawn_guard = hold_process_spawns_at_or_below(0);
    let mut client = ChildGuard::spawn_while_holding("ferrum2-client", &config, &spawn_guard);
    wait_for_bound(&mut client, client_address);
    wait_for_tcp_udp_bound(&mut client, dns_listen);
    drop(spawn_guard);
    let tcp_payload = b"configured-resolver-tcp";
    tcp_domain_round_trip(
        client_address,
        configured_name,
        target_address.port(),
        tcp_payload,
    );
    dns.wait_for_query(RecordType::A);
    let (udp_control, udp_application, relay) = udp_associate(client_address);
    let udp_payload = b"configured-resolver-udp";
    udp_domain_round_trip(
        &udp_application,
        relay,
        configured_name,
        target_address,
        udp_payload,
    );
    assert_eq!(tcp_echo.join(), tcp_payload, "configured TCP target");
    assert_eq!(udp_echo.join(), udp_payload, "configured UDP target");
    drop((udp_control, udp_application));
    let observations = dns.join();
    assert!(
        (1..=2).contains(&observations.len())
            && observations.iter().all(|query| *query == RecordType::A),
        "configured application resolver query evidence"
    );
    stop_client_and_rebind(
        client,
        client_address,
        Some(dns_listen),
        relay,
        &[
            configured_name,
            "application-upstream",
            "configured-resolver",
        ],
    );
    drop(bind_loopback_listener(target_address).expect("configured target TCP exact rebind"));
    drop(UdpSocket::bind(target_address).expect("configured target UDP exact rebind"));
    drop(UdpSocket::bind(dns_address).expect("configured upstream exact rebind"));

    // NODATA from a configured resolver is terminal. `localhost` would be
    // resolvable by the OS, so any implicit fallback would reach these sentinels.
    let (failed_tcp_target, failed_udp_target, failed_target_address) = paired_loopback_target();
    failed_tcp_target
        .set_nonblocking(true)
        .expect("failure TCP sentinel nonblocking");
    let failed_dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::NoData,
        },
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::NoData,
        },
    ]);
    let failed_dns_address = failed_dns.address();
    let failed_client_address = unused_loopback();
    let failed_dns_listen = unused_tcp_udp_loopback();
    let failed_config = write_direct_client_config(
        directory.path(),
        "configured-nodata",
        failed_client_address,
        Some((failed_dns_listen, failed_dns_address)),
    );
    let spawn_guard = hold_process_spawns_at_or_below(0);
    let mut failed_client =
        ChildGuard::spawn_while_holding("ferrum2-client", &failed_config, &spawn_guard);
    wait_for_bound(&mut failed_client, failed_client_address);
    wait_for_tcp_udp_bound(&mut failed_client, failed_dns_listen);
    drop(spawn_guard);
    assert_tcp_domain_failure(
        failed_client_address,
        "localhost",
        failed_target_address.port(),
    );
    failed_dns.wait_for_query(RecordType::A);
    assert!(
        matches!(
            failed_tcp_target.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "configured DNS failure reached the TCP target"
    );
    let (failed_control, failed_application, failed_relay) = udp_associate(failed_client_address);
    let failed_request = socks_udp_datagram(
        "localhost",
        failed_target_address.port(),
        b"must-not-arrive",
    );
    assert_eq!(
        failed_application
            .send_to(&failed_request, failed_relay)
            .expect("configured failure UDP send"),
        failed_request.len()
    );
    assert_no_udp_packet(
        &failed_udp_target,
        "configured DNS failure reached the UDP target",
    );
    assert_no_udp_packet(
        &failed_application,
        "configured DNS failure emitted a UDP response",
    );
    assert!(
        matches!(
            failed_tcp_target.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "configured DNS failure reached the TCP target late"
    );
    drop((failed_control, failed_application));
    let failed_observations = failed_dns.join();
    assert!(
        (1..=2).contains(&failed_observations.len())
            && failed_observations
                .iter()
                .all(|query| *query == RecordType::A),
        "configured NODATA query evidence"
    );
    drop((failed_tcp_target, failed_udp_target));
    stop_client_and_rebind(
        failed_client,
        failed_client_address,
        Some(failed_dns_listen),
        failed_relay,
        &["localhost", "application-upstream", "must-not-arrive"],
    );
    drop(bind_loopback_listener(failed_target_address).expect("failed target TCP exact rebind"));
    drop(UdpSocket::bind(failed_target_address).expect("failed target UDP exact rebind"));
    drop(UdpSocket::bind(failed_dns_address).expect("failed upstream exact rebind"));

    // With no `[dns]`, application resolution explicitly uses the OS resolver.
    let (system_tcp_target, system_udp_target, system_target_address) = paired_loopback_target();
    let system_tcp_echo = start_tcp_echo(system_tcp_target, system_target_address);
    let system_udp_echo = start_udp_echo(system_udp_target, system_target_address);
    let system_client_address = unused_loopback();
    let system_config =
        write_direct_client_config(directory.path(), "system-mode", system_client_address, None);
    let spawn_guard = hold_process_spawns_at_or_below(0);
    let mut system_client =
        ChildGuard::spawn_while_holding("ferrum2-client", &system_config, &spawn_guard);
    wait_for_bound(&mut system_client, system_client_address);
    drop(spawn_guard);
    let system_tcp_payload = b"system-resolver-tcp";
    tcp_domain_round_trip(
        system_client_address,
        "localhost",
        system_target_address.port(),
        system_tcp_payload,
    );
    let (system_control, system_application, system_relay) = udp_associate(system_client_address);
    let system_udp_payload = b"system-resolver-udp";
    udp_domain_round_trip(
        &system_application,
        system_relay,
        "localhost",
        system_target_address,
        system_udp_payload,
    );
    assert_eq!(
        system_tcp_echo.join(),
        system_tcp_payload,
        "system TCP target"
    );
    assert_eq!(
        system_udp_echo.join(),
        system_udp_payload,
        "system UDP target"
    );
    drop((system_control, system_application));
    stop_client_and_rebind(
        system_client,
        system_client_address,
        None,
        system_relay,
        &["localhost", "system-resolver"],
    );
    drop(bind_loopback_listener(system_target_address).expect("system target TCP exact rebind"));
    drop(UdpSocket::bind(system_target_address).expect("system target UDP exact rebind"));
    assert_eq!(active_child_count(), 0, "resolver E2E process leak");
}
