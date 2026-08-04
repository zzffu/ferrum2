#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use local_support::{
    ChainRoot, ChildGuard, TCP_METHOD_CONFIGS, active_child_count, bind_loopback_listener,
    rewrite_config_method, route_tagged_config, unused_loopback, unused_tcp_udp_loopback,
    wait_for_bound, wait_for_listener, wait_for_metrics, wait_for_metrics_sample,
    wait_for_tcp_udp_bound, write_client_config, write_server_config, write_server_config_with_psk,
    write_tagged_client_config, write_tagged_server_config, write_two_hop_client_config,
    write_udp_client_config,
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};

fn udp_associate(client: SocketAddrV4, hinted: bool) -> (TcpStream, UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("application UDP socket");
    let hint = if hinted {
        socket.local_addr().expect("application address").port()
    } else {
        0
    };
    let (control, reply) = udp_command_with_port(client, hint);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("application timeout");
    (control, socket, relay)
}

fn udp_command(client: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    udp_command_with_port(client, 0)
}

fn udp_command_with_port(client: SocketAddrV4, port: u16) -> (TcpStream, [u8; 10]) {
    let mut control = TcpStream::connect(client).expect("connect SOCKS control");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("control timeout");
    control.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let [high, low] = port.to_be_bytes();
    let hint = if port == 0 {
        [0, 0, 0, 0]
    } else {
        [192, 0, 2, 99]
    };
    control
        .write_all(&[5, 3, 0, 1, hint[0], hint[1], hint[2], hint[3], high, low])
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).expect("UDP command reply");
    (control, reply)
}

fn socks_datagram(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    socks_datagram_for_target(&target_wire(SocketAddr::V4(target)), payload)
}

fn socks_datagram_for_target(target: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0];
    wire.extend_from_slice(target);
    wire.extend_from_slice(payload);
    wire
}

fn target_wire(target: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::new();
    match target {
        SocketAddr::V4(target) => {
            wire.push(1);
            wire.extend_from_slice(&target.ip().octets());
            wire.extend_from_slice(&target.port().to_be_bytes());
        }
        SocketAddr::V6(target) => {
            wire.push(4);
            wire.extend_from_slice(&target.ip().octets());
            wire.extend_from_slice(&target.port().to_be_bytes());
        }
    }
    wire
}

fn domain_target_wire(domain: &str, port: u16) -> Vec<u8> {
    let mut wire = vec![3, u8::try_from(domain.len()).expect("test domain length")];
    wire.extend_from_slice(domain.as_bytes());
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

fn round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    request_target: &[u8],
    response_target: &[u8],
    payload: &[u8],
) {
    let request = socks_datagram_for_target(request_target, payload);
    assert_eq!(
        application
            .send_to(&request, relay)
            .expect("SOCKS UDP send"),
        request.len()
    );
    let mut response = [0_u8; 65_507];
    let (length, source) = application
        .recv_from(&mut response)
        .expect("SOCKS UDP response");
    assert_eq!(source, SocketAddr::V4(relay));
    assert_eq!(
        &response[..length],
        socks_datagram_for_target(response_target, payload)
    );
}

struct DatagramEcho {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl DatagramEcho {
    fn join(mut self) -> thread::Result<()> {
        self.task.take().expect("datagram echo worker").join()
    }
}

impl Drop for DatagramEcho {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.stop.store(true, Ordering::SeqCst);
            let wake = match self.address {
                SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)),
            };
            if let Ok(wake) = wake {
                let _ = wake.send_to(&[], self.address);
            }
            let _ = task.join();
        }
    }
}

fn echo_datagrams(socket: UdpSocket, count: usize) -> DatagramEcho {
    let address = socket.local_addr().expect("echo address");
    let stop = Arc::new(AtomicBool::new(false));
    let task_stop = Arc::clone(&stop);
    let task = thread::spawn(move || {
        let mut buffer = [0_u8; 65_507];
        for _ in 0..count {
            let (length, peer) = socket.recv_from(&mut buffer).expect("echo receive");
            if task_stop.load(Ordering::SeqCst) {
                return;
            }
            assert_eq!(
                socket.send_to(&buffer[..length], peer).expect("echo send"),
                length
            );
        }
    });
    DatagramEcho {
        address,
        stop,
        task: Some(task),
    }
}

#[test]
fn datagram_echo_drop_joins_and_releases_socket() {
    let _spawn_guard = local_support::hold_process_spawns();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("drop-test echo socket");
    let address = socket.local_addr().expect("drop-test echo address");
    drop(echo_datagrams(socket, 2));
    drop(UdpSocket::bind(address).expect("dropped datagram echo rebind"));
}

fn assert_no_datagram(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("short UDP timeout");
    let mut buffer = [0_u8; 1];
    let error = socket
        .recv_from(&mut buffer)
        .expect_err("datagram must drop");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore UDP timeout");
}

fn wait_udp_rebind(address: SocketAddrV4, label: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match UdpSocket::bind(address) {
            Ok(socket) => return drop(socket),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                assert!(std::time::Instant::now() < deadline, "{label}");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
}

struct Stack {
    _directory: tempfile::TempDir,
    server: ChildGuard,
    client: ChildGuard,
    client_address: SocketAddrV4,
    metrics_address: SocketAddrV4,
}

impl Stack {
    fn start(method: (&str, &str)) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let server_address = unused_tcp_udp_loopback();
        let client_address = unused_loopback();
        let metrics_address = unused_loopback();
        let server_config =
            write_server_config(directory.path(), server_address, None).expect("server config");
        let client_config = write_udp_client_config(
            directory.path(),
            client_address,
            server_address,
            Some(metrics_address),
        )
        .expect("client config");
        rewrite_config_method(&server_config, method).expect("server method");
        rewrite_config_method(&client_config, method).expect("client method");
        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        wait_for_tcp_udp_bound(&mut server, server_address);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_listener(&mut client, client_address);
        Self {
            _directory: directory,
            server,
            client,
            client_address,
            metrics_address,
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.client.terminate_and_reap(Duration::from_secs(5));
        self.server.terminate_and_reap(Duration::from_secs(5));
    }
}

#[test]
fn three_methods_cover_ipv4_with_three_public_datagrams() {
    for method in TCP_METHOD_CONFIGS {
        let stack = Stack::start(method);
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 echo bind");
        echo.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("echo timeout");
        let echo_address = echo.local_addr().expect("echo address");
        let target = target_wire(echo_address);
        let (_control, application, relay) = udp_associate(stack.client_address, true);
        let echo_worker = echo_datagrams(echo, 3);
        let mut byte_count = 0;
        for index in 0..3 {
            let payload = format!("m6-{}-ipv4-{index}", method.0);
            byte_count += payload.len();
            round_trip(&application, relay, &target, &target, payload.as_bytes());
        }
        echo_worker.join().expect("echo worker");
        let metrics =
            String::from_utf8(wait_for_metrics(stack.metrics_address)).expect("metrics UTF-8");
        for family in [
            "ferrum2_udp_sessions_active",
            "ferrum2_udp_buffered_bytes",
            "ferrum2_udp_datagrams",
            "ferrum2_udp_bytes",
        ] {
            assert!(metrics.contains(family), "{}: {family}", method.0);
        }
        let samples = [
            "ferrum2_udp_sessions_active{role=\"client\"} 1",
            "ferrum2_udp_buffered_bytes{role=\"client\"} 196521",
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 3",
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"accepted\"} 3",
        ];
        for sample in samples {
            assert!(metrics.contains(sample), "{}: {sample}", method.0);
        }
        for direction in ["client_to_target", "target_to_client"] {
            let sample = format!(
                "ferrum2_udp_bytes_total{{role=\"client\",direction=\"{direction}\"}} {byte_count}"
            );
            assert!(metrics.contains(&sample), "{}: {sample}", method.0);
        }
        for forbidden in [
            method.1,
            &stack.client_address.to_string(),
            &relay.to_string(),
            &echo_address.to_string(),
            "server=",
            "target=",
            "session_id=",
            "wire_id=",
            "raw_error=",
        ] {
            assert!(!metrics.contains(forbidden), "{}: {forbidden}", method.0);
        }
    }
}

#[test]
fn tagged_two_by_two_udp_matrix_covers_all_methods_and_exact_rebind() {
    for method in TCP_METHOD_CONFIGS {
        let directory = tempfile::tempdir().expect("tagged UDP tempdir");
        let servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
        let clients = [unused_loopback(), unused_loopback()];
        let server_config = write_tagged_server_config(directory.path(), servers, [0, 1], true)
            .expect("tagged UDP server config");
        let client_config =
            write_tagged_client_config(directory.path(), clients, servers, [0, 1], true)
                .expect("tagged UDP client config");
        rewrite_config_method(&server_config, method).expect("tagged UDP server method");
        rewrite_config_method(&client_config, method).expect("tagged UDP client method");

        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        for address in servers {
            wait_for_tcp_udp_bound(&mut server, address);
        }
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        for address in clients {
            wait_for_listener(&mut client, address);
        }

        let mut relays = Vec::new();
        for (mapping, client_address) in clients.into_iter().enumerate() {
            let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("tagged echo bind");
            echo.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("tagged echo timeout");
            let target = target_wire(echo.local_addr().expect("tagged echo address"));
            let (control, application, relay) = udp_associate(client_address, true);
            let echo_worker = echo_datagrams(echo, 1);
            let payload = format!("{}-mapping-{mapping}", method.0);
            round_trip(&application, relay, &target, &target, payload.as_bytes());
            echo_worker.join().expect("tagged echo worker");
            drop((control, application));
            relays.push(relay);
        }

        client.terminate_and_reap(Duration::from_secs(5));
        server.terminate_and_reap(Duration::from_secs(5));
        for relay in relays {
            wait_udp_rebind(relay, "tagged relay exact rebind");
        }
        for address in clients {
            drop(bind_loopback_listener(address).expect("tagged client exact rebind"));
        }
        for address in servers {
            let tcp = bind_loopback_listener(address).expect("tagged server TCP exact rebind");
            let udp = UdpSocket::bind(address).expect("tagged server UDP exact rebind");
            drop((tcp, udp));
        }
    }
}

#[test]
fn tagged_udp_shared_outbound_and_dead_reference_have_no_fallback() {
    let directory = tempfile::tempdir().expect("tagged focused UDP tempdir");
    let servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
    let clients = [unused_loopback(), unused_loopback()];
    let server_config = write_tagged_server_config(directory.path(), servers, [0, 0], true)
        .expect("shared UDP server config");
    let client_config = write_tagged_client_config(
        directory.path(),
        clients,
        [servers[0], unused_tcp_udp_loopback()],
        [0, 0],
        true,
    )
    .expect("shared UDP client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    for address in servers {
        wait_for_tcp_udp_bound(&mut server, address);
    }
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }
    let mut relays = Vec::new();
    for (mapping, client_address) in clients.into_iter().enumerate() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("shared UDP echo");
        let target = target_wire(echo.local_addr().expect("shared UDP echo address"));
        let (control, application, relay) = udp_associate(client_address, true);
        let worker = echo_datagrams(echo, 1);
        let payload = format!("shared-mapping-{mapping}");
        round_trip(&application, relay, &target, &target, payload.as_bytes());
        worker.join().expect("shared UDP echo worker");
        drop((control, application));
        relays.push(relay);
    }
    client.terminate_and_reap(Duration::from_secs(5));
    server.terminate_and_reap(Duration::from_secs(5));
    for relay in relays {
        wait_udp_rebind(relay, "shared UDP relay rebind");
    }
    for address in clients {
        drop(bind_loopback_listener(address).expect("shared UDP client rebind"));
    }
    for address in servers {
        drop(bind_loopback_listener(address).expect("shared UDP server TCP rebind"));
        drop(UdpSocket::bind(address).expect("shared UDP server UDP rebind"));
    }

    let live_servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
    let dead_server = unused_tcp_udp_loopback();
    let clients = [unused_loopback(), unused_loopback()];
    let server_config = write_tagged_server_config(directory.path(), live_servers, [0, 1], true)
        .expect("no-fallback UDP server config");
    let client_config = write_tagged_client_config(
        directory.path(),
        clients,
        [live_servers[0], dead_server],
        [0, 1],
        true,
    )
    .expect("no-fallback UDP client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    for address in live_servers {
        wait_for_tcp_udp_bound(&mut server, address);
    }
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }

    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("no-fallback UDP target");
    let target_address = match target.local_addr().expect("no-fallback target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let (dead_control, dead_application, dead_relay) = udp_associate(clients[1], true);
    let request = socks_datagram(target_address, b"dead-reference");
    assert_eq!(
        dead_application
            .send_to(&request, dead_relay)
            .expect("dead-reference send"),
        request.len()
    );
    assert_no_datagram(&target);
    client.assert_running();
    server.assert_running();

    let (live_control, live_application, live_relay) = udp_associate(clients[0], true);
    let target_wire = target_wire(SocketAddr::V4(target_address));
    let worker = echo_datagrams(target, 1);
    round_trip(
        &live_application,
        live_relay,
        &target_wire,
        &target_wire,
        b"live-reference",
    );
    worker.join().expect("live-reference echo worker");
    drop((
        dead_control,
        dead_application,
        live_control,
        live_application,
    ));
    client.terminate_and_reap(Duration::from_secs(5));
    server.terminate_and_reap(Duration::from_secs(5));
    for relay in [dead_relay, live_relay] {
        wait_udp_rebind(relay, "no-fallback UDP relay rebind");
    }
    for address in clients {
        drop(bind_loopback_listener(address).expect("no-fallback client rebind"));
    }
    for address in live_servers {
        drop(bind_loopback_listener(address).expect("no-fallback server TCP rebind"));
        drop(UdpSocket::bind(address).expect("no-fallback server UDP rebind"));
    }
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Windows normalizes 127/8 wildcard accepts to 127.0.0.1"
)]
fn wildcard_listener_reports_and_uses_the_accepted_127_0_0_2_address() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_tcp_udp_loopback();
    let reserved = unused_loopback();
    let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, reserved.port());
    let client_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), reserved.port());
    let server_config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let client_config = write_udp_client_config(directory.path(), wildcard, server_address, None)
        .expect("client config");
    rewrite_config_method(&server_config, TCP_METHOD_CONFIGS[0]).expect("server method");
    rewrite_config_method(&client_config, TCP_METHOD_CONFIGS[0]).expect("client method");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_tcp_udp_bound(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo bind");
    echo.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("echo timeout");
    let target = target_wire(echo.local_addr().expect("echo address"));
    let worker = echo_datagrams(echo, 1);
    let (_control, application, relay) = udp_associate(client_address, false);
    assert_eq!(*relay.ip(), Ipv4Addr::new(127, 0, 0, 2));
    round_trip(&application, relay, &target, &target, b"accepted-local-ip");
    worker.join().expect("echo worker");

    client.terminate_and_reap(Duration::from_secs(5));
    server.terminate_and_reap(Duration::from_secs(5));
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires a Linux release host with IPv6-only loopback UDP enabled"
)]
fn one_method_covers_ipv6_with_three_public_datagrams() {
    let stack = Stack::start(TCP_METHOD_CONFIGS[0]);

    let echo = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("IPv6 echo bind");
    echo.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("echo timeout");
    let target = target_wire(echo.local_addr().expect("echo address"));
    let echo_worker = echo_datagrams(echo, 3);
    let (_control, application, relay) = udp_associate(stack.client_address, false);

    for index in 0..3 {
        round_trip(
            &application,
            relay,
            &target,
            &target,
            format!("m6-ipv6-{index}").as_bytes(),
        );
    }
    echo_worker.join().expect("echo worker");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires a Linux release host with IPv6-only loopback UDP enabled"
)]
fn three_methods_compose_ipv4_ipv6_and_domain_through_the_real_relays() {
    for method in TCP_METHOD_CONFIGS {
        let stack = Stack::start(method);
        let ipv4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 echo");
        let ipv6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("IPv6 echo");
        for echo in [&ipv4, &ipv6] {
            echo.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("echo timeout");
        }
        let ipv4_address = ipv4.local_addr().expect("IPv4 address");
        let ipv6_address = ipv6.local_addr().expect("IPv6 address");
        let ipv4_target = target_wire(ipv4_address);
        let ipv6_target = target_wire(ipv6_address);
        let domain_target = domain_target_wire("127.0.0.1", ipv4_address.port());
        let ipv4_worker = echo_datagrams(ipv4, 2);
        let ipv6_worker = echo_datagrams(ipv6, 1);
        let (_control, application, relay) = udp_associate(stack.client_address, false);
        for (request, response, payload) in [
            (&ipv4_target, &ipv4_target, b"ipv4".as_slice()),
            (&ipv6_target, &ipv6_target, b"ipv6".as_slice()),
            (&domain_target, &ipv4_target, b"domain".as_slice()),
        ] {
            round_trip(&application, relay, request, response, payload);
        }
        assert_eq!(ipv6_target.len(), 19, "SIP022 IPv6 target width");
        assert_eq!(3 + ipv6_target.len(), 22, "SOCKS5 IPv6 header width");
        ipv4_worker.join().expect("IPv4 worker");
        ipv6_worker.join().expect("IPv6 worker");
    }
}

#[test]
fn one_association_alternates_two_targets_and_preserves_response_sources() {
    let directory = tempfile::tempdir().expect("routed association tempdir");
    let servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
    let clients = [unused_loopback(), unused_loopback()];
    let first_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("first echo bind");
    let second_echo =
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("second echo socket");
    second_echo.set_only_v6(false).expect("dual stack");
    second_echo
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
        .expect("second echo bind");
    let second_echo = UdpSocket::from(second_echo);
    for echo in [&first_echo, &second_echo] {
        echo.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("echo timeout");
    }
    let first_target = target_wire(first_echo.local_addr().expect("first echo address"));
    let second_port = second_echo.local_addr().expect("echo address").port();
    let second_target = domain_target_wire("localhost", second_port);
    let second_response = target_wire(
        ("localhost", second_port)
            .to_socket_addrs()
            .expect("second echo resolve")
            .next()
            .expect("second echo candidate"),
    );
    let first_worker = echo_datagrams(first_echo, 2);
    let second_worker = echo_datagrams(second_echo, 1);
    let configs = [0, 1].map(|index| {
        let path = directory.path().join(index.to_string());
        std::fs::create_dir(&path).expect("routed server directory");
        write_server_config(&path, servers[index], None).expect("routed server config")
    });
    let client_config =
        write_tagged_client_config(directory.path(), clients, servers, [0, 1], true)
            .expect("routed client config");
    for config in [&configs[0], &configs[1], &client_config] {
        rewrite_config_method(config, TCP_METHOD_CONFIGS[2]).expect("routed ChaCha method");
    }
    route_tagged_config(&client_config, &format!(
        "\n[route]\nfinal = \"out-0\"\n[[route.rules]]\ninbound = \"in-a\"\nnetwork = \"udp\"\ntarget = {{ host = \"LOCALHOST\", port = {} }}\noutbound = \"out-1\"\n[[route.rules]]\nnetwork = \"tcp\"\noutbound = \"out-0\"\n[[route.rules]]\ntarget = {{ host = \"LOCALHOST\", port = {} }}\noutbound = \"out-0\"\n",
        second_port, second_port
    )).expect("routed client rules");
    let mut server_a = ChildGuard::spawn("ferrum2-server", &configs[0]);
    wait_for_tcp_udp_bound(&mut server_a, servers[0]);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }

    let (_control, application, relay) = udp_associate(clients[0], false);

    round_trip(&application, relay, &first_target, &first_target, b"a");
    server_a.terminate_and_reap(Duration::from_secs(5));
    let mut server_b = ChildGuard::spawn("ferrum2-server", &configs[1]);
    wait_for_tcp_udp_bound(&mut server_b, servers[1]);
    round_trip(&application, relay, &second_target, &second_response, b"b");
    server_b.terminate_and_reap(Duration::from_secs(5));
    server_a = ChildGuard::spawn("ferrum2-server", &configs[0]);
    wait_for_tcp_udp_bound(&mut server_a, servers[0]);
    round_trip(&application, relay, &first_target, &first_target, b"c");
    first_worker.join().expect("first echo worker");
    second_worker.join().expect("second echo worker");
}

#[test]
fn fragment_does_not_pin_first_valid_source_wins_and_control_close_rebinds() {
    let stack = Stack::start(TCP_METHOD_CONFIGS[0]);
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo bind");
    echo.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("echo timeout");
    let echo_address = match echo.local_addr().expect("echo address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 echo"),
    };
    let echo_worker = thread::spawn(move || {
        let mut buffer = [0_u8; 64];
        for _ in 0..2 {
            let (length, peer) = echo.recv_from(&mut buffer).expect("echo receive");
            assert_eq!(
                echo.send_to(&buffer[..length], peer).expect("echo send"),
                length
            );
        }
    });

    let (control, first, relay) = udp_associate(stack.client_address, false);
    let winner = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("winning source");
    winner
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("winner timeout");
    let valid = socks_datagram(echo_address, b"winner");
    let over_capacity = socks_datagram(echo_address, &vec![0; 65_458]);
    first
        .send_to(&over_capacity, relay)
        .expect("over-capacity send");
    assert_no_datagram(&first);
    let mut fragment = valid.clone();
    fragment[2] = 1;
    first.send_to(&fragment, relay).expect("fragment send");
    assert_no_datagram(&first);

    let barrier = Arc::new(Barrier::new(3));
    let first_sender = first.try_clone().expect("clone first source");
    let winner_sender = winner.try_clone().expect("clone second source");
    let first_barrier = Arc::clone(&barrier);
    let winner_barrier = Arc::clone(&barrier);
    let first_valid = valid.clone();
    let winner_valid = valid.clone();
    let first_send = thread::spawn(move || {
        first_barrier.wait();
        first_sender.send_to(&first_valid, relay)
    });
    let winner_send = thread::spawn(move || {
        winner_barrier.wait();
        winner_sender.send_to(&winner_valid, relay)
    });
    barrier.wait();
    first_send
        .join()
        .expect("first sender")
        .expect("first send");
    winner_send
        .join()
        .expect("second sender")
        .expect("second send");

    let mut response = [0_u8; 64];
    first
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("first race timeout");
    winner
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("second race timeout");
    let first_result = first.recv_from(&mut response);
    let winner_result = winner.recv_from(&mut response);
    assert_ne!(first_result.is_ok(), winner_result.is_ok());
    let (pinned, losing, length) = if let Ok((length, _)) = first_result {
        (&first, &winner, length)
    } else {
        (&winner, &first, winner_result.expect("one source wins").0)
    };
    assert_eq!(&response[..length], valid);
    pinned
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore pinned timeout");
    losing.send_to(&valid, relay).expect("wrong-source send");
    assert_no_datagram(losing);
    let wrong_ip = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).expect("wrong-IP source");
    wrong_ip.send_to(&valid, relay).expect("wrong-IP send");
    assert_no_datagram(&wrong_ip);
    let second = socks_datagram(echo_address, b"still-pinned");
    pinned.send_to(&second, relay).expect("second winner send");
    let (length, _) = pinned.recv_from(&mut response).expect("second response");
    assert_eq!(&response[..length], second);
    echo_worker.join().expect("echo worker");
    let metrics =
        String::from_utf8(wait_for_metrics(stack.metrics_address)).expect("metrics UTF-8");
    let rejected = [
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 5",
        "ferrum2_udp_failures_total{role=\"client\",stage=\"shadowsocks\",reason=\"bounds\"} 1",
        "ferrum2_udp_failures_total{role=\"client\",stage=\"socks5\",reason=\"bounds\"} 1",
        "ferrum2_udp_failures_total{role=\"client\",stage=\"socks5\",reason=\"address\"} 3",
    ];
    for sample in rejected {
        assert!(metrics.contains(sample), "{sample}");
    }

    drop(control);
    wait_udp_rebind(relay, "control-close relay rebind");
}

#[test]
fn active_control_eof_write_half_and_reset_release_association_and_socket() {
    let stack = Stack::start(TCP_METHOD_CONFIGS[0]);
    for terminal in ["eof", "write-half", "reset"] {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo bind");
        echo.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("echo timeout");
        let target = target_wire(echo.local_addr().expect("echo address"));
        let worker = echo_datagrams(echo, 1);
        let (control, application, relay) = udp_associate(stack.client_address, false);
        round_trip(&application, relay, &target, &target, terminal.as_bytes());
        worker.join().expect("echo worker");
        match terminal {
            "eof" => drop(control),
            "write-half" => {
                control
                    .shutdown(Shutdown::Write)
                    .expect("control write half-close");
                wait_udp_rebind(relay, "write-half relay rebind");
                drop(control);
            }
            "reset" => {
                SockRef::from(&control)
                    .set_linger(Some(Duration::ZERO))
                    .expect("zero linger");
                drop(control);
            }
            _ => unreachable!("closed terminal table"),
        }
        wait_udp_rebind(relay, terminal);
    }
    let (control, _, relay) = udp_associate(stack.client_address, false);
    drop(control);
    wait_udp_rebind(relay, "post-terminal association");
}

#[test]
fn absent_disabled_saturation_release_and_restart_rebind_are_exact() {
    for explicit in [false, true] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let client_address = unused_loopback();
        let metrics_address = unused_loopback();
        let config = write_client_config(
            directory.path(),
            client_address,
            unused_loopback(),
            Some(metrics_address),
        )
        .expect("disabled config");
        if explicit {
            let mut source = std::fs::read_to_string(&config).expect("read config");
            source.push_str("\n[udp]\nenabled = false\n");
            std::fs::write(&config, source).expect("explicit disabled config");
        }
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);
        let metrics =
            String::from_utf8(wait_for_metrics(metrics_address)).expect("disabled metrics UTF-8");
        assert!(
            metrics.contains("ferrum2_udp_sessions_active{role=\"client\"} 0"),
            "disabled sessions zero"
        );
        assert!(
            metrics.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"),
            "disabled bytes zero"
        );
        let (_control, reply) = udp_command(client_address);
        assert_eq!(reply, [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        client.terminate_and_reap(Duration::from_secs(5));
        drop(TcpListener::bind(client_address).expect("disabled client rebind"));
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let client_address = unused_loopback();
    let config = write_udp_client_config(directory.path(), client_address, unused_loopback(), None)
        .expect("saturation config");
    let mut source = std::fs::read_to_string(&config).expect("read saturation config");
    source.push_str("max_sessions = 1\n");
    std::fs::write(&config, source).expect("write saturation config");
    let mut client = ChildGuard::spawn("ferrum2-client", &config);
    wait_for_listener(&mut client, client_address);
    let (first_control, _application, relay) = udp_associate(client_address, false);
    let (_second_control, second_reply) = udp_command(client_address);
    assert_eq!(second_reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(first_control);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (control, reply) = udp_command(client_address);
        if reply[1] == 0 {
            drop(control);
            break;
        }
        assert_eq!(reply[1], 1);
        drop(control);
        assert!(
            std::time::Instant::now() < deadline,
            "session permit release timeout"
        );
        thread::sleep(Duration::from_millis(10));
    }
    wait_udp_rebind(relay, "released relay rebind");
    client.terminate_and_reap(Duration::from_secs(5));
    drop(TcpListener::bind(client_address).expect("client restart rebind"));
}

#[test]
fn fixed_two_hop_udp_chain_uses_distinct_credentials_and_reaps() {
    const ZERO_SESSIONS: &str = "ferrum2_udp_sessions_active{role=\"client\"} 0";
    const ZERO_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"client\"} 0";
    const SERVER_ACCEPTED_THREE: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"} 3";
    const SERVER_ACCEPTED_ONE: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"} 1";
    const SERVER_AUTH_FAILED: &str = "ferrum2_udp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"} 1";

    for (index, (inherited, explicit)) in [
        (TCP_METHOD_CONFIGS[0], TCP_METHOD_CONFIGS[1]),
        (TCP_METHOD_CONFIGS[1], TCP_METHOD_CONFIGS[2]),
        (TCP_METHOD_CONFIGS[1], TCP_METHOD_CONFIGS[2]),
        (TCP_METHOD_CONFIGS[2], TCP_METHOD_CONFIGS[0]),
    ]
    .into_iter()
    .enumerate()
    {
        let baseline = {
            let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
            active_child_count()
        };
        let directory = tempfile::tempdir().expect("two-hop UDP tempdir");
        let a_dir = directory.path().join("a");
        let b_dir = directory.path().join("b");
        std::fs::create_dir_all(&a_dir).expect("server directory");
        std::fs::create_dir_all(&b_dir).expect("server directory");
        let servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
        let client_address = unused_loopback();
        let metrics = [unused_loopback(), unused_loopback(), unused_loopback()];
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("datagram target");
        let target_address = match target.local_addr().expect("target address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 target"),
        };
        let root = match index {
            0 => ChainRoot::Static,
            1 => ChainRoot::RouteRule {
                target: target_address,
                fallback_hop: 0,
            },
            2 => ChainRoot::RouteFinal,
            _ => ChainRoot::SelectorDefault,
        };
        let a_config =
            write_server_config(&a_dir, servers[0], Some(metrics[1])).expect("server config");
        let b_config =
            write_server_config(&b_dir, servers[1], Some(metrics[2])).expect("server config");
        rewrite_config_method(&a_config, inherited).expect("server method");
        rewrite_config_method(&b_config, explicit).expect("server method");
        let client_config = write_two_hop_client_config(
            directory.path(),
            client_address,
            servers,
            inherited,
            explicit,
            root,
            true,
            Some(metrics[0]),
        )
        .expect("client config");

        let mut server_a = ChildGuard::spawn("ferrum2-server", &a_config);
        wait_for_metrics(metrics[1]);
        wait_for_tcp_udp_bound(&mut server_a, servers[0]);
        let mut server_b = ChildGuard::spawn("ferrum2-server", &b_config);
        wait_for_metrics(metrics[2]);
        wait_for_tcp_udp_bound(&mut server_b, servers[1]);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_metrics(metrics[0]);
        wait_for_bound(&mut client, client_address);

        let (control, application, relay) = udp_associate(client_address, true);
        let target_wire = target_wire(SocketAddr::V4(target_address));
        let worker = echo_datagrams(target, 3);
        for datagram in [b"two-hop-a".as_slice(), b"two-hop-bb", b"two-hop-ccc"] {
            round_trip(&application, relay, &target_wire, &target_wire, datagram);
        }
        worker.join().expect("datagram worker");
        drop((control, application));
        wait_udp_rebind(relay, "two-hop relay close");

        let client_metrics = wait_for_metrics_sample(metrics[0], ZERO_SESSIONS);
        let client_metrics = if client_metrics
            .windows(ZERO_BUFFER.len())
            .any(|part| part == ZERO_BUFFER.as_bytes())
        {
            client_metrics
        } else {
            wait_for_metrics_sample(metrics[0], ZERO_BUFFER)
        };
        let a_metrics = wait_for_metrics(metrics[1]);
        let b_metrics = wait_for_metrics_sample(metrics[2], SERVER_ACCEPTED_THREE);
        for body in [&client_metrics, &a_metrics, &b_metrics] {
            for sentinel in [inherited.1, explicit.1] {
                assert!(
                    !body
                        .windows(sentinel.len())
                        .any(|part| part == sentinel.as_bytes())
                );
            }
        }
        let exits = [
            client.terminate_and_reap_with_exit(Duration::from_secs(5)),
            server_a.terminate_and_reap_with_exit(Duration::from_secs(5)),
            server_b.terminate_and_reap_with_exit(Duration::from_secs(5)),
        ];
        for exit in &exits {
            exit.assert_stderr_excludes(&[inherited.1, explicit.1]);
        }
        let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline);
        drop(bind_loopback_listener(client_address).expect("two-hop UDP client rebind"));
        for address in servers {
            drop(bind_loopback_listener(address).expect("two-hop UDP server TCP rebind"));
            drop(UdpSocket::bind(address).expect("two-hop UDP server UDP rebind"));
        }
        for address in [relay, target_address] {
            drop(UdpSocket::bind(address).expect("two-hop UDP exact rebind"));
        }
        for address in metrics {
            drop(bind_loopback_listener(address).expect("two-hop UDP metrics rebind"));
        }
        assert_eq!(active_child_count(), baseline);
    }

    enum Failure {
        FirstUnavailable,
        LaterUnavailable,
        FirstWrong,
        LaterWrong,
    }
    for failure in [
        Failure::FirstUnavailable,
        Failure::LaterUnavailable,
        Failure::FirstWrong,
        Failure::LaterWrong,
    ] {
        let baseline = {
            let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
            active_child_count()
        };
        let inherited = TCP_METHOD_CONFIGS[1];
        let explicit = TCP_METHOD_CONFIGS[2];
        let directory = tempfile::tempdir().expect("two-hop UDP failure tempdir");
        let a_dir = directory.path().join("a");
        let b_dir = directory.path().join("b");
        std::fs::create_dir_all(&a_dir).expect("server directory");
        std::fs::create_dir_all(&b_dir).expect("server directory");
        let servers = [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()];
        let client_address = unused_loopback();
        let metrics = [unused_loopback(), unused_loopback(), unused_loopback()];
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("recording target");
        let target_address = match target.local_addr().expect("target address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 target"),
        };
        let first_failure = matches!(failure, Failure::FirstUnavailable | Failure::FirstWrong);
        let client_config = write_two_hop_client_config(
            directory.path(),
            client_address,
            servers,
            inherited,
            explicit,
            ChainRoot::RouteRule {
                target: target_address,
                fallback_hop: usize::from(first_failure),
            },
            true,
            Some(metrics[0]),
        )
        .expect("client config");
        let mut server_a = if matches!(failure, Failure::FirstUnavailable) {
            None
        } else {
            let psk = if matches!(failure, Failure::FirstWrong) {
                explicit.1
            } else {
                inherited.1
            };
            let config = write_server_config_with_psk(&a_dir, servers[0], Some(metrics[1]), psk)
                .expect("server config");
            rewrite_config_method(&config, (inherited.0, psk)).expect("server method");
            let mut child = ChildGuard::spawn("ferrum2-server", &config);
            wait_for_metrics(metrics[1]);
            wait_for_tcp_udp_bound(&mut child, servers[0]);
            Some(child)
        };
        let mut server_b = if matches!(failure, Failure::LaterUnavailable) {
            None
        } else {
            let psk = if matches!(failure, Failure::LaterWrong) {
                inherited.1
            } else {
                explicit.1
            };
            let config = write_server_config_with_psk(&b_dir, servers[1], Some(metrics[2]), psk)
                .expect("server config");
            rewrite_config_method(&config, (explicit.0, psk)).expect("server method");
            let mut child = ChildGuard::spawn("ferrum2-server", &config);
            wait_for_metrics(metrics[2]);
            wait_for_tcp_udp_bound(&mut child, servers[1]);
            Some(child)
        };
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_metrics(metrics[0]);
        wait_for_bound(&mut client, client_address);

        let (control, application, relay) = udp_associate(client_address, true);
        let request = socks_datagram(target_address, b"two-hop-failure");
        assert_eq!(
            application.send_to(&request, relay).expect("failure send"),
            request.len()
        );
        assert_no_datagram(&target);
        assert_no_datagram(&application);
        drop((control, application));
        wait_udp_rebind(relay, "two-hop failure relay close");
        let client_metrics = wait_for_metrics_sample(metrics[0], ZERO_SESSIONS);
        let client_metrics = if client_metrics
            .windows(ZERO_BUFFER.len())
            .any(|part| part == ZERO_BUFFER.as_bytes())
        {
            client_metrics
        } else {
            wait_for_metrics_sample(metrics[0], ZERO_BUFFER)
        };
        let a_metrics = server_a.as_ref().map(|_| wait_for_metrics(metrics[1]));
        let b_metrics = server_b.as_ref().map(|_| wait_for_metrics(metrics[2]));
        if matches!(failure, Failure::LaterUnavailable | Failure::LaterWrong) {
            assert!(a_metrics.as_ref().is_some_and(|body| {
                body.windows(SERVER_ACCEPTED_ONE.len())
                    .any(|part| part == SERVER_ACCEPTED_ONE.as_bytes())
            }));
        }
        if matches!(failure, Failure::FirstWrong) {
            assert!(a_metrics.as_ref().is_some_and(|body| {
                body.windows(SERVER_AUTH_FAILED.len())
                    .any(|part| part == SERVER_AUTH_FAILED.as_bytes())
            }));
        }
        if matches!(failure, Failure::LaterWrong) {
            assert!(b_metrics.as_ref().is_some_and(|body| {
                body.windows(SERVER_AUTH_FAILED.len())
                    .any(|part| part == SERVER_AUTH_FAILED.as_bytes())
            }));
        }
        for body in std::iter::once(&client_metrics)
            .chain(a_metrics.iter())
            .chain(b_metrics.iter())
        {
            for sentinel in [inherited.1, explicit.1] {
                assert!(
                    !body
                        .windows(sentinel.len())
                        .any(|part| part == sentinel.as_bytes())
                );
            }
        }
        let mut exits = vec![client.terminate_and_reap_with_exit(Duration::from_secs(5))];
        if let Some(child) = server_a.as_mut() {
            exits.push(child.terminate_and_reap_with_exit(Duration::from_secs(5)));
        }
        if let Some(child) = server_b.as_mut() {
            exits.push(child.terminate_and_reap_with_exit(Duration::from_secs(5)));
        }
        for exit in &exits {
            exit.assert_stderr_excludes(&[inherited.1, explicit.1]);
        }
        drop(target);
        let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline);
        drop(bind_loopback_listener(client_address).expect("two-hop UDP failure client rebind"));
        for address in servers {
            drop(bind_loopback_listener(address).expect("two-hop UDP failure TCP rebind"));
            drop(UdpSocket::bind(address).expect("two-hop UDP failure UDP rebind"));
        }
        for address in [relay, target_address] {
            drop(UdpSocket::bind(address).expect("two-hop UDP failure exact rebind"));
        }
        for address in metrics {
            drop(bind_loopback_listener(address).expect("two-hop UDP failure metrics rebind"));
        }
        assert_eq!(active_child_count(), baseline);
    }
}
