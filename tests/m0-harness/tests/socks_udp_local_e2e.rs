#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use local_support::{
    ChainRoot, ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, TCP_METHOD_CONFIGS,
    active_child_count, bind_loopback_listener, rewrite_config_method, start_dns_script,
    unused_loopback, unused_tcp_udp_loopback, wait_for_bound, wait_for_listener, wait_for_metrics,
    wait_for_metrics_sample, wait_for_tcp_udp_bound, write_client_config, write_server_config,
    write_server_config_with_psk, write_tagged_client_config, write_tagged_server_config,
    write_two_hop_client_config, write_udp_client_config,
};
use socket2::SockRef;

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

#[test]
fn m14_client_udp_association_actions_route_once_and_reap() {
    const CLIENT_ZERO_SESSIONS: &str = "ferrum2_udp_sessions_active{role=\"client\"} 0";
    const CLIENT_ZERO_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"client\"} 0";
    const SERVER_ACCEPTED_TWO: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"} 2";

    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("M14 client UDP tempdir");
    let route_first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("first route target");
    let route_later = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("later route target");
    let address = |socket: &UdpSocket| match socket.local_addr().expect("UDP target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 M14 UDP target"),
    };
    let route_first_address = address(&route_first);
    let route_later_address = address(&route_later);
    let first_echo = echo_datagrams(route_first, 1);
    let later_echo = echo_datagrams(route_later, 1);
    let rejected_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("rejected UDP target");
    let rejected_address = address(&rejected_target);
    let hijack_fallback =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("hijack fallback target");
    let hijack_fallback_address = address(&hijack_fallback);
    let unselected_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("unselected server");
    let unselected_server_address = address(&unselected_server);
    let dns_upstream = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::Addresses(vec![Ipv4Addr::new(127, 0, 0, 14)]),
    }]);
    let dns_upstream_address = dns_upstream.address();

    let selected_server = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let dns_listen = unused_tcp_udp_loopback();
    let client_metrics = unused_loopback();
    let server_metrics = unused_loopback();
    let server_config =
        write_server_config(directory.path(), selected_server, Some(server_metrics))
            .expect("M14 selected server config");
    let client_config = directory.path().join("m14-client-udp.toml");
    std::fs::write(
        &client_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"in\"\nlisten = \"{client_address}\"\n\
             [[outbounds]]\ntag = \"selected\"\nserver = \"{selected_server}\"\n\
             [[outbounds]]\ntag = \"unselected\"\nserver = \"{unselected_server_address}\"\n\
             [[selectors]]\ntag = \"manual\"\noutbounds = [\"selected\", \"unselected\"]\ndefault = \"selected\"\n\
             [route]\nfinal = \"unselected\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\ntarget = {{ host = \"{}\", port = {} }}\naction = \"route\"\noutbound = \"manual\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\ntarget = {{ host = \"{}\", port = {} }}\naction = \"route\"\noutbound = \"unselected\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\ntarget = {{ host = \"{}\", port = {} }}\naction = \"reject\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\naction = \"sniff\"\nsniffers = \"dns\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\nprotocol = \"dns\"\naction = \"hijack-dns\"\n\
             [dns]\nmax_inflight = 4\n\
             [[dns.inbounds]]\ntag = \"dedicated\"\nlisten = \"{dns_listen}\"\n\
             [[dns.servers]]\ntag = \"dns\"\ntransport = \"udp\"\naddress = \"{dns_upstream_address}\"\n\
             [dns.route]\nfinal = \"dns\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [udp]\nmax_sessions = 8\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n\
             [metrics]\nlisten = \"{client_metrics}\"\n",
            route_first_address.ip(),
            route_first_address.port(),
            route_later_address.ip(),
            route_later_address.port(),
            rejected_address.ip(),
            rejected_address.port(),
        ),
    )
    .expect("M14 client UDP config");
    let checked = std::process::Command::new(local_support::binary_path("ferrum2-client"))
        .args([
            "--config",
            client_config.to_str().expect("UTF-8 M14 UDP config"),
        ])
        .arg("--check-config")
        .output()
        .expect("M14 client UDP config check process");
    assert!(
        checked.status.success(),
        "M14 client UDP config check: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

    let mut server =
        ChildGuard::spawn_while_holding("ferrum2-server", &server_config, &_spawn_guard);
    wait_for_tcp_udp_bound(&mut server, selected_server);
    wait_for_metrics(server_metrics);
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &_spawn_guard);
    wait_for_listener(&mut client, client_address);
    wait_for_tcp_udp_bound(&mut client, dns_listen);
    wait_for_metrics(client_metrics);
    drop(_spawn_guard);

    let (route_control, route_application, route_relay) = udp_associate(client_address, false);
    let mut fragmented = socks_datagram(route_first_address, b"invalid-first");
    fragmented[2] = 1;
    route_application
        .send_to(&fragmented, route_relay)
        .expect("fragmented first datagram");
    assert_no_datagram(&route_application);
    round_trip(
        &route_application,
        route_relay,
        &target_wire(SocketAddr::V4(route_first_address)),
        &target_wire(SocketAddr::V4(route_first_address)),
        b"first-route",
    );
    round_trip(
        &route_application,
        route_relay,
        &target_wire(SocketAddr::V4(route_later_address)),
        &target_wire(SocketAddr::V4(route_later_address)),
        b"later-target-same-outbound",
    );
    first_echo.join().expect("first route echo");
    later_echo.join().expect("later route echo");
    assert_no_datagram(&unselected_server);
    drop((route_application, route_control));

    let (hijack_control, hijack_application, hijack_relay) = udp_associate(client_address, false);
    let mut query = Message::new(0x1405, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("hijack-association.test.").expect("M14 UDP DNS name"),
        RecordType::A,
    ));
    let query = query.to_vec().expect("M14 UDP DNS query");
    let dns_target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
    let request = socks_datagram(dns_target, &query);
    hijack_application
        .send_to(&request, hijack_relay)
        .expect("M14 hijack datagram");
    let mut response = [0_u8; 65_507];
    let (length, source) = hijack_application
        .recv_from(&mut response)
        .expect("M14 hijack response");
    assert_eq!(source, SocketAddr::V4(hijack_relay));
    let prefix = socks_datagram(dns_target, &[]);
    assert_eq!(&response[..prefix.len()], prefix);
    let response =
        Message::from_vec(&response[prefix.len()..length]).expect("typed hijack response");
    assert_eq!(response.id, 0x1405);
    assert!(response.answers.iter().any(|record| {
        matches!(&record.data, RData::A(address) if address.0 == Ipv4Addr::new(127, 0, 0, 14))
    }));
    let later_non_dns = socks_datagram(hijack_fallback_address, b"not-dns");
    hijack_application
        .send_to(&later_non_dns, hijack_relay)
        .expect("later non-DNS hijack datagram");
    assert_no_datagram(&hijack_application);
    assert_no_datagram(&hijack_fallback);
    drop((hijack_application, hijack_control));
    assert_eq!(dns_upstream.join(), [RecordType::A]);

    let (reject_control, reject_application, reject_relay) = udp_associate(client_address, false);
    let rejected = socks_datagram(rejected_address, b"reject-association");
    reject_application
        .send_to(&rejected, reject_relay)
        .expect("M14 rejected datagram");
    assert_no_datagram(&reject_application);
    assert_no_datagram(&rejected_target);
    drop((reject_application, reject_control));

    let client_body = wait_for_metrics_sample(client_metrics, CLIENT_ZERO_SESSIONS);
    let client_body = if client_body
        .windows(CLIENT_ZERO_BUFFER.len())
        .any(|window| window == CLIENT_ZERO_BUFFER.as_bytes())
    {
        client_body
    } else {
        wait_for_metrics_sample(client_metrics, CLIENT_ZERO_BUFFER)
    };
    let server_body = wait_for_metrics_sample(server_metrics, SERVER_ACCEPTED_TWO);
    for sentinel in [
        "hijack-association.test",
        "selected",
        "unselected",
        "manual",
        SYNTHETIC_PSK,
    ] {
        for body in [&client_body, &server_body] {
            assert!(
                !body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "M14 UDP metrics exposed identity"
            );
        }
    }
    let exits = [
        client.terminate_and_reap_with_exit(Duration::from_secs(5)),
        server.terminate_and_reap_with_exit(Duration::from_secs(5)),
    ];
    for exit in &exits {
        exit.assert_stderr_excludes(&[
            "hijack-association.test",
            "selected",
            "unselected",
            "manual",
            SYNTHETIC_PSK,
        ]);
    }
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);

    drop((unselected_server, rejected_target, hijack_fallback));
    for relay in [route_relay, hijack_relay, reject_relay] {
        wait_udp_rebind(relay, "M14 association relay exact rebind");
    }
    for address in [
        route_first_address,
        route_later_address,
        rejected_address,
        hijack_fallback_address,
        unselected_server_address,
        dns_upstream_address,
    ] {
        drop(UdpSocket::bind(address).expect("M14 UDP endpoint exact rebind"));
    }
    drop(bind_loopback_listener(client_address).expect("M14 client exact rebind"));
    drop(bind_loopback_listener(selected_server).expect("M14 server TCP exact rebind"));
    drop(UdpSocket::bind(selected_server).expect("M14 server UDP exact rebind"));
    drop(bind_loopback_listener(dns_listen).expect("M14 DNS TCP exact rebind"));
    drop(UdpSocket::bind(dns_listen).expect("M14 DNS UDP exact rebind"));
    for metrics in [client_metrics, server_metrics] {
        drop(bind_loopback_listener(metrics).expect("M14 UDP metrics exact rebind"));
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
    wait_udp_rebind(relay, "released relay rebind");

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
        let a_metrics = wait_for_metrics_sample(metrics[1], SERVER_ACCEPTED_THREE);
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
        let client_config = write_two_hop_client_config(
            directory.path(),
            client_address,
            servers,
            inherited,
            explicit,
            ChainRoot::Static,
            true,
            Some(metrics[0]),
        )
        .expect("client config");
        let a_psk = if matches!(failure, Failure::FirstWrong) {
            explicit.1
        } else {
            inherited.1
        };
        let a_config = write_server_config_with_psk(&a_dir, servers[0], Some(metrics[1]), a_psk)
            .expect("server config");
        rewrite_config_method(&a_config, (inherited.0, a_psk)).expect("server method");
        let mut server_a = ChildGuard::spawn("ferrum2-server", &a_config);
        let a_ready_metrics = wait_for_metrics(metrics[1]);
        wait_for_tcp_udp_bound(&mut server_a, servers[0]);
        let mut server_a = Some(server_a);

        let b_psk = if matches!(failure, Failure::LaterWrong) {
            inherited.1
        } else {
            explicit.1
        };
        let b_config = write_server_config_with_psk(&b_dir, servers[1], Some(metrics[2]), b_psk)
            .expect("server config");
        rewrite_config_method(&b_config, (explicit.0, b_psk)).expect("server method");
        let mut server_b = ChildGuard::spawn("ferrum2-server", &b_config);
        let b_ready_metrics = wait_for_metrics(metrics[2]);
        wait_for_tcp_udp_bound(&mut server_b, servers[1]);
        let mut server_b = Some(server_b);
        let unavailable_exit = if matches!(failure, Failure::FirstUnavailable) {
            let mut child = server_a.take().expect("first server owner");
            Some(child.terminate_and_reap_with_exit(Duration::from_secs(5)))
        } else if matches!(failure, Failure::LaterUnavailable) {
            let mut child = server_b.take().expect("later server owner");
            Some(child.terminate_and_reap_with_exit(Duration::from_secs(5)))
        } else {
            None
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
        let a_metrics = server_a
            .as_ref()
            .map(|_| wait_for_metrics(metrics[1]))
            .unwrap_or(a_ready_metrics);
        let b_metrics = server_b
            .as_ref()
            .map(|_| wait_for_metrics(metrics[2]))
            .unwrap_or(b_ready_metrics);
        if matches!(failure, Failure::LaterUnavailable | Failure::LaterWrong) {
            assert!(
                a_metrics
                    .windows(SERVER_ACCEPTED_ONE.len())
                    .any(|part| part == SERVER_ACCEPTED_ONE.as_bytes())
            );
        }
        if matches!(failure, Failure::FirstWrong) {
            assert!(
                a_metrics
                    .windows(SERVER_AUTH_FAILED.len())
                    .any(|part| part == SERVER_AUTH_FAILED.as_bytes())
            );
        }
        if matches!(failure, Failure::LaterWrong) {
            assert!(
                b_metrics
                    .windows(SERVER_AUTH_FAILED.len())
                    .any(|part| part == SERVER_AUTH_FAILED.as_bytes())
            );
        }
        for body in [&client_metrics, &a_metrics, &b_metrics] {
            for sentinel in [inherited.1, explicit.1] {
                assert!(
                    !body
                        .windows(sentinel.len())
                        .any(|part| part == sentinel.as_bytes())
                );
            }
        }
        let mut exits: Vec<_> = unavailable_exit.into_iter().collect();
        exits.push(client.terminate_and_reap_with_exit(Duration::from_secs(5)));
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
