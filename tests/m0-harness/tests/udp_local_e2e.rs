#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use local_support::{
    ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, active_child_count, bind_loopback_listener,
    metric_value, run_binary, start_dns_answer, start_dns_script, unused_loopback,
    unused_tcp_udp_loopback, wait_for_bound, wait_for_listener, wait_for_metrics,
    wait_for_metrics_sample, wait_for_tcp_udp_bound, write_server_config,
    write_tagged_dns_server_config, write_udp_client_config,
};

// ponytail: file-wide lock; use socket inheritance if these tests need parallel throughput.
static UDP_LOCAL_E2E_TEST_LOCK: Mutex<()> = Mutex::new(());
use socket2::{Domain, Protocol, Socket, Type};

fn assert_startup_bind_failure(output: &Output, occupied: SocketAddrV4) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.starts_with(b"error[startup.bind]"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(&occupied.to_string()));
    assert!(!stderr.contains(SYNTHETIC_PSK));
}

fn udp_associate(client: SocketAddrV4) -> (TcpStream, UdpSocket, SocketAddrV4) {
    let mut control = TcpStream::connect(client).expect("connect SOCKS control");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("control timeout");
    control.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).expect("UDP command reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("application UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("application timeout");
    (control, socket, relay)
}

fn domain_target(name: &str, port: u16) -> Vec<u8> {
    let mut target = vec![3, u8::try_from(name.len()).expect("domain length")];
    target.extend_from_slice(name.as_bytes());
    target.extend_from_slice(&port.to_be_bytes());
    target
}

fn ip_target(target: SocketAddrV4) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend_from_slice(&target.ip().octets());
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire
}

fn dns_udp_round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    name: &str,
    target: SocketAddrV4,
    payload: &[u8],
) {
    let mut request = vec![0, 0, 0];
    request.extend_from_slice(&domain_target(name, target.port()));
    request.extend_from_slice(payload);
    assert_eq!(
        application.send_to(&request, relay).expect("UDP send"),
        request.len()
    );
    let mut response = [0_u8; 65_507];
    let (length, source) = application.recv_from(&mut response).expect("UDP response");
    assert_eq!(source, SocketAddr::V4(relay));
    let mut expected = vec![0, 0, 0];
    expected.extend_from_slice(&ip_target(target));
    expected.extend_from_slice(payload);
    assert_eq!(&response[..length], expected);
}

#[test]
fn m14_server_udp_freezes_first_terminal_per_identity_and_reaps() {
    const CLIENT_ZERO_SESSION: &str = "ferrum2_udp_sessions_active{role=\"client\"} 0";
    const CLIENT_ZERO_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"client\"} 0";
    const SERVER_ZERO_SESSION: &str = "ferrum2_udp_sessions_active{role=\"server\"} 0";
    const SERVER_ROOT_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"server\"}";
    const SERVER_ONE_SESSION: &str = "ferrum2_udp_sessions_active{role=\"server\"} 1";

    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("M14 server UDP tempdir");
    let route_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("route target");
    let malformed_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("malformed target");
    let rejected_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("rejected target");
    let v4 = |socket: &UdpSocket| match socket.local_addr().expect("target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let route_address = v4(&route_target);
    let malformed_address = v4(&malformed_target);
    let rejected_address = v4(&rejected_target);
    let echo_once = |socket: UdpSocket| {
        thread::spawn(move || {
            let mut packet = [0_u8; 512];
            let (length, peer) = socket
                .recv_from(&mut packet)
                .expect("M14 UDP target receive");
            socket
                .send_to(&packet[..length], peer)
                .expect("M14 UDP target echo");
            packet[..length].to_vec()
        })
    };
    let route_echo = echo_once(route_target);
    for target in [&malformed_target, &rejected_target] {
        target
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("rejected target timeout");
    }

    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let client_metrics = unused_loopback();
    let server_metrics = unused_loopback();
    let server_config = directory.path().join("m14-server-udp.toml");
    fs::write(
        &server_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"in\"\nlisten = \"{server_address}\"\n\
             [[outbounds]]\ntag = \"direct\"\n\
             [route]\nfinal = \"direct\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\naction = \"sniff\"\nsniffers = \"dns\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nprotocol = \"dns\"\ndomain = \"route.test\"\naction = \"route\"\noutbound = \"direct\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nprotocol = \"dns\"\ndomain = \"reject.test\"\naction = \"reject\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = {}\naction = \"route\"\noutbound = \"direct\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [udp]\nidle_timeout_ms = 60000\n\
             [metrics]\nlisten = \"{server_metrics}\"\n",
            rejected_address.port(),
        ),
    )
    .expect("M14 server UDP config");
    let client_config = write_udp_client_config(
        directory.path(),
        client_address,
        server_address,
        Some(client_metrics),
    )
    .expect("M14 server UDP client config");
    let mut server =
        ChildGuard::spawn_while_holding("ferrum2-server", &server_config, &_spawn_guard);
    wait_for_tcp_udp_bound(&mut server, server_address);
    let server_baseline = wait_for_metrics_sample(server_metrics, SERVER_ZERO_SESSION);
    let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
    let shard_target = parallelism.clamp(1, 4);
    let response_shards = 1_usize << shard_target.ilog2();
    let expected_root_bytes = (2 * response_shards + 1) * 65_507;
    assert_eq!(
        metric_value(&server_baseline, SERVER_ROOT_BUFFER),
        Some(expected_root_bytes as u64)
    );
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &_spawn_guard);
    wait_for_listener(&mut client, client_address);
    wait_for_metrics(client_metrics);
    drop(_spawn_guard);
    let (reject_control, reject_application, reject_relay) = udp_associate(client_address);

    let query = |id, name: &str| {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(name).expect("M14 DNS name"),
            RecordType::A,
        ));
        message.to_vec().expect("M14 DNS query")
    };
    let exchange = |application: &UdpSocket, relay, target, payload: &[u8]| {
        let mut request = vec![0, 0, 0];
        request.extend_from_slice(&ip_target(target));
        request.extend_from_slice(payload);
        assert_eq!(
            application.send_to(&request, relay).expect("M14 UDP send"),
            request.len()
        );
        let mut response = [0_u8; 65_507];
        let (length, source) = application
            .recv_from(&mut response)
            .expect("M14 UDP response");
        assert_eq!(source, SocketAddr::V4(relay));
        assert_eq!(&response[..length], request);
    };

    let rejected_query = query(0x1402, "reject.test.");
    let mut request = vec![0, 0, 0];
    request.extend_from_slice(&ip_target(rejected_address));
    request.extend_from_slice(&rejected_query);
    reject_application
        .send_to(&request, reject_relay)
        .expect("rejected UDP request");
    reject_application
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("rejected response timeout");
    assert!(matches!(
        reject_application.recv_from(&mut [0_u8; 1]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    assert!(matches!(
        rejected_target.recv_from(&mut [0_u8; 1]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));

    let malformed = b"not-a-dns-query";
    let mut frozen_reject = vec![0, 0, 0];
    frozen_reject.extend_from_slice(&ip_target(malformed_address));
    frozen_reject.extend_from_slice(malformed);
    reject_application
        .send_to(&frozen_reject, reject_relay)
        .expect("frozen reject UDP request");
    assert!(matches!(
        reject_application.recv_from(&mut [0_u8; 1]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    assert!(matches!(
        malformed_target.recv_from(&mut [0_u8; 1]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    reject_application
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore rejected application timeout");

    let (direct_control, direct_application, direct_relay) = udp_associate(client_address);
    let routed_query = query(0x1401, "route.test.");
    exchange(
        &direct_application,
        direct_relay,
        route_address,
        &routed_query,
    );
    assert_eq!(route_echo.join().expect("route target join"), routed_query);
    rejected_target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore frozen Direct target timeout");
    let frozen_direct_echo = echo_once(rejected_target);
    exchange(
        &direct_application,
        direct_relay,
        rejected_address,
        &rejected_query,
    );
    assert_eq!(
        frozen_direct_echo
            .join()
            .expect("frozen Direct target join"),
        rejected_query
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body = wait_for_metrics(server_metrics);
        let one_session = body
            .windows(SERVER_ONE_SESSION.len())
            .any(|window| window == SERVER_ONE_SESSION.as_bytes());
        let root_buffer = body
            .windows(SERVER_ROOT_BUFFER.len())
            .any(|window| window == SERVER_ROOT_BUFFER.as_bytes());
        if one_session && root_buffer {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "active idle server UDP session retained an extra receive buffer: {}",
            String::from_utf8_lossy(&body)
        );
        thread::sleep(Duration::from_millis(20));
    }
    drop((
        reject_application,
        reject_control,
        direct_application,
        direct_control,
    ));

    let deadline = Instant::now() + Duration::from_secs(10);
    let client_body = loop {
        let body = wait_for_metrics(client_metrics);
        let zero_sessions = body
            .windows(CLIENT_ZERO_SESSION.len())
            .any(|window| window == CLIENT_ZERO_SESSION.as_bytes());
        let zero_buffer = body
            .windows(CLIENT_ZERO_BUFFER.len())
            .any(|window| window == CLIENT_ZERO_BUFFER.as_bytes());
        if zero_sessions && zero_buffer {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "client UDP owners did not reap: {}",
            String::from_utf8_lossy(&body)
        );
        thread::sleep(Duration::from_millis(20));
    };
    thread::sleep(Duration::from_secs(61));
    let deadline = Instant::now() + Duration::from_secs(10);
    let server_body = loop {
        let body = wait_for_metrics(server_metrics);
        if body
            .windows(SERVER_ZERO_SESSION.len())
            .any(|window| window == SERVER_ZERO_SESSION.as_bytes())
            && body
                .windows(SERVER_ROOT_BUFFER.len())
                .any(|window| window == SERVER_ROOT_BUFFER.as_bytes())
        {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "server UDP owners did not reap: {}",
            String::from_utf8_lossy(&body)
        );
        thread::sleep(Duration::from_millis(20));
    };
    for sentinel in ["route.test", "reject.test", SYNTHETIC_PSK] {
        for body in [&client_body, &server_body] {
            assert!(
                !body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "metrics exposed M14 UDP identity"
            );
        }
    }
    let exits = [
        client.terminate_and_reap_with_exit(Duration::from_secs(5)),
        server.terminate_and_reap_with_exit(Duration::from_secs(5)),
    ];
    for exit in &exits {
        exit.assert_stderr_excludes(&["route.test", "reject.test", SYNTHETIC_PSK]);
    }
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);
    drop(malformed_target);
    for relay in [reject_relay, direct_relay] {
        drop(UdpSocket::bind(relay).expect("M14 client UDP relay exact rebind"));
    }
    for address in [route_address, malformed_address, rejected_address] {
        drop(UdpSocket::bind(address).expect("M14 UDP target exact rebind"));
    }
    drop(bind_loopback_listener(client_address).expect("M14 client TCP exact rebind"));
    drop(bind_loopback_listener(server_address).expect("M14 server TCP exact rebind"));
    drop(UdpSocket::bind(server_address).expect("M14 server UDP exact rebind"));
    for address in [client_metrics, server_metrics] {
        drop(bind_loopback_listener(address).expect("M14 UDP metrics exact rebind"));
    }
}

#[test]
fn tagged_dns_udp_resolution_uses_detour_and_reaps() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let selected_name = "selected-udp.test.";
    let final_name = "final-udp.test.";
    let selected_target = UdpSocket::bind("127.0.0.1:0").expect("selected target");
    let final_target = UdpSocket::bind("127.0.0.2:0").expect("final target");
    let failed_target = UdpSocket::bind("127.0.0.1:0").expect("no-fallback target");
    for target in [&selected_target, &final_target, &failed_target] {
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("target timeout");
    }
    let selected_address = match selected_target.local_addr().expect("selected address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 selected target"),
    };
    let final_address = match final_target.local_addr().expect("final address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 final target"),
    };
    let failed_address = match failed_target.local_addr().expect("failed address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 failed target"),
    };
    let selected_dns = start_dns_answer(Ipv4Addr::new(127, 0, 0, 1), 2);
    let final_dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::Addresses(vec![Ipv4Addr::new(127, 0, 0, 2)]),
        },
        DnsStep {
            record_type: RecordType::AAAA,
            reply: DnsReply::NoData,
        },
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::NoData,
        },
        DnsStep {
            record_type: RecordType::AAAA,
            reply: DnsReply::NoData,
        },
    ]);
    let dns_addresses = [selected_dns.address(), final_dns.address()];
    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let server_config = write_tagged_dns_server_config(
        directory.path(),
        server_address,
        selected_name,
        selected_address.port(),
        "udp",
        dns_addresses,
        true,
    )
    .expect("tagged DNS server config");
    let client_config =
        write_udp_client_config(directory.path(), client_address, server_address, None)
            .expect("UDP client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_tcp_udp_bound(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (selected_control, selected_application, selected_relay) = udp_associate(client_address);

    let selected_echo = thread::spawn(move || {
        let mut packet = [0_u8; 64];
        let (length, peer) = selected_target
            .recv_from(&mut packet)
            .expect("selected receive");
        selected_target
            .send_to(&packet[..length], peer)
            .expect("selected echo");
    });
    dns_udp_round_trip(
        &selected_application,
        selected_relay,
        selected_name,
        selected_address,
        b"selected",
    );
    selected_echo.join().expect("selected echo join");
    drop((selected_application, selected_control));
    let (control, application, relay) = udp_associate(client_address);
    let final_echo = thread::spawn(move || {
        let mut packet = [0_u8; 64];
        let (length, peer) = final_target.recv_from(&mut packet).expect("final receive");
        final_target
            .send_to(&packet[..length], peer)
            .expect("final echo");
    });
    dns_udp_round_trip(&application, relay, final_name, final_address, b"final");
    final_echo.join().expect("final echo join");
    let failed = {
        let mut request = vec![0, 0, 0];
        request.extend_from_slice(&domain_target(
            "failure-sentinel.test",
            failed_address.port(),
        ));
        request.extend_from_slice(b"must-not-arrive");
        request
    };
    assert_eq!(
        application
            .send_to(&failed, relay)
            .expect("no-fallback UDP send"),
        failed.len()
    );
    application
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("no-fallback application timeout");
    failed_target
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("no-fallback target timeout");
    for (socket, message) in [
        (&application, "configured DNS failure emitted a response"),
        (&failed_target, "configured DNS failure reached the target"),
    ] {
        assert!(
            matches!(
                socket.recv_from(&mut [0_u8; 64]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
            ),
            "{message}"
        );
    }
    assert_eq!(selected_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(
        final_dns.join(),
        [
            RecordType::A,
            RecordType::AAAA,
            RecordType::A,
            RecordType::AAAA
        ]
    );
    drop((application, control));
    let client_exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
    let server_exit = server.terminate_and_reap_with_exit(Duration::from_secs(5));
    for exit in [&client_exit, &server_exit] {
        exit.assert_stderr_excludes(&[
            selected_name,
            final_name,
            "selected",
            "final",
            "dns-direct",
            "app-direct",
            "failure-sentinel.test",
            "must-not-arrive",
        ]);
    }
    assert_eq!(active_child_count(), baseline_children);
    drop(bind_loopback_listener(client_address).expect("client exact rebind"));
    drop(bind_loopback_listener(server_address).expect("server TCP exact rebind"));
    drop(UdpSocket::bind(server_address).expect("server UDP exact rebind"));
    drop(UdpSocket::bind(selected_relay).expect("selected client relay exact rebind"));
    drop(UdpSocket::bind(relay).expect("client relay exact rebind"));
    drop(UdpSocket::bind(dns_addresses[0]).expect("selected DNS exact rebind"));
    drop(UdpSocket::bind(dns_addresses[1]).expect("final DNS exact rebind"));
    drop(failed_target);
    drop(UdpSocket::bind(failed_address).expect("failed target exact rebind"));
}

#[test]
fn v2_server_udp_without_dns_uses_system_resolver_and_reaps() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("system resolver tempdir");
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("system resolver target");
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("system resolver target timeout");
    let target_address = match target.local_addr().expect("system target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 system target"),
    };
    let echo = thread::spawn(move || {
        let mut packet = [0_u8; 64];
        let (length, peer) = target
            .recv_from(&mut packet)
            .expect("system target receive");
        target
            .send_to(&packet[..length], peer)
            .expect("system target echo");
        packet[..length].to_vec()
    });
    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let server_config = directory.path().join("v2-system-resolver-server.toml");
    fs::write(
        &server_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"in\"\nlisten = \"{server_address}\"\n\
             [[outbounds]]\ntag = \"direct\"\n\
             [route]\nfinal = \"direct\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [udp]\nenabled = true\n"
        ),
    )
    .expect("system resolver server config");
    let client_config =
        write_udp_client_config(directory.path(), client_address, server_address, None)
            .expect("system resolver client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_tcp_udp_bound(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (control, application, relay) = udp_associate(client_address);
    dns_udp_round_trip(
        &application,
        relay,
        "localhost",
        target_address,
        b"system-resolver-udp",
    );
    assert_eq!(
        echo.join().expect("system target join"),
        b"system-resolver-udp"
    );
    drop((application, control));
    let exits = [
        client.terminate_and_reap_with_exit(Duration::from_secs(5)),
        server.terminate_and_reap_with_exit(Duration::from_secs(5)),
    ];
    for exit in &exits {
        exit.assert_stderr_excludes(&["localhost", "system-resolver-udp", SYNTHETIC_PSK]);
    }
    assert_eq!(active_child_count(), baseline_children);
    drop(bind_loopback_listener(client_address).expect("system client exact rebind"));
    drop(bind_loopback_listener(server_address).expect("system server TCP exact rebind"));
    drop(UdpSocket::bind(server_address).expect("system server UDP exact rebind"));
    drop(UdpSocket::bind(relay).expect("system relay exact rebind"));
    drop(UdpSocket::bind(target_address).expect("system target exact rebind"));
}

fn disable_udp(path: &std::path::Path) {
    let mut source = fs::read_to_string(path).expect("server config");
    source.push_str("\n[udp]\nenabled = false\n");
    fs::write(path, source).expect("disable UDP");
}

fn bind_ipv6_only(address: SocketAddrV6) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.bind(&SocketAddr::V6(address).into())?;
    Ok(socket.into())
}

fn udp_protocol_example_path() -> std::path::PathBuf {
    let name = format!("udp_protocol_client{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo target profile directory")
        .join("examples")
        .join(name)
}

#[test]
fn portable_ipv4_live_udp_signal_exits_cleanly_and_rebinds() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_tcp_udp_loopback();
    let config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let mut source = fs::read_to_string(&config).expect("read server config");
    source.push_str("\n[runtime]\nshutdown_grace_ms = 0\n");
    fs::write(&config, source).expect("write zero signal grace");
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &config, "portable live UDP signal");
    wait_for_tcp_udp_bound(&mut server, server_address);

    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 target bind");
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("target read timeout");
    let mut example = Command::new(udp_protocol_example_path())
        .args([
            "2022-blake3-aes-128-gcm",
            &server_address.to_string(),
            &target.local_addr().expect("target address").to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn UDP protocol example");
    let mut payload = [0_u8; 64];
    let (received, _) = target
        .recv_from(&mut payload)
        .expect("observe admitted UDP");
    assert_eq!(&payload[..received], b"m2-udp-aes128-datagram-0");
    assert!(example.try_wait().expect("example status").is_none());

    server.request_graceful_shutdown();
    let exit = server.wait_for_exit(Duration::from_secs(5));
    if example
        .try_wait()
        .expect("example status after signal")
        .is_none()
    {
        example.kill().expect("stop blocked UDP example");
    }
    example.wait().expect("reap UDP example");

    assert_eq!(exit.status.code(), Some(0), "{exit}");
    let tcp = bind_loopback_listener(server_address).expect("TCP signal rebind");
    let udp = UdpSocket::bind(server_address).expect("UDP signal rebind");
    drop((tcp, udp));
}

#[test]
#[ignore = "requires a Linux release host with IPv6-only loopback UDP enabled"]
fn ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_tcp_udp_loopback();
    let config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let mut server =
        ChildGuard::spawn_with_context("ferrum2-server", &config, "IPv4 ingress to IPv6 target");
    wait_for_tcp_udp_bound(&mut server, server_address);

    let echo = bind_ipv6_only(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .expect("IPv6-only echo bind");
    let echo_address = match echo.local_addr().expect("IPv6 echo address") {
        SocketAddr::V6(address) => address,
        SocketAddr::V4(_) => unreachable!("IPv6-only echo address"),
    };
    const EXPECTED_PAYLOADS: [&[u8]; 3] = [
        b"m2-udp-aes128-datagram-0",
        b"m2-udp-aes128-datagram-1",
        b"m2-udp-aes128-datagram-2",
    ];
    echo.set_nonblocking(true).expect("nonblocking IPv6 echo");
    let mut example = Command::new(udp_protocol_example_path())
        .args([
            "2022-blake3-aes-128-gcm",
            &server_address.to_string(),
            &echo_address.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn UDP protocol example");

    let (cancel, cancelled) = std::sync::mpsc::channel();
    let echo_worker = thread::spawn(move || {
        let mut observed = Vec::with_capacity(EXPECTED_PAYLOADS.len());
        let mut buffer = [0_u8; 65_507];
        while cancelled.try_recv().is_err() {
            match echo.recv_from(&mut buffer) {
                Ok((received, peer)) => match echo.send_to(&buffer[..received], peer) {
                    Ok(sent) if sent == received => {
                        observed.push((buffer[..received].to_vec(), peer));
                        if observed.len() == EXPECTED_PAYLOADS.len() {
                            break;
                        }
                    }
                    _ => break,
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        observed
    });

    let deadline = Instant::now() + Duration::from_secs(40);
    let example_wait_error = loop {
        match example.try_wait() {
            Ok(Some(_)) => break None,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = example.kill();
                break Some("UDP protocol example timed out");
            }
            Err(_) => {
                let _ = example.kill();
                break Some("UDP protocol example status failed");
            }
        }
    };
    let example_output = example.wait_with_output();
    let _ = cancel.send(());
    let observed = echo_worker.join();
    server.terminate_and_reap(Duration::from_secs(5));
    let rebinds = (
        bind_loopback_listener(server_address),
        UdpSocket::bind(server_address),
        bind_ipv6_only(echo_address),
    );

    assert_eq!(example_wait_error, None);
    let output = example_output.expect("reap UDP protocol example");
    assert!(output.status.success(), "UDP protocol example failed");
    let observed = observed.expect("reap IPv6 echo owner");
    assert_eq!(observed.len(), EXPECTED_PAYLOADS.len());
    for ((payload, _), expected) in observed.iter().zip(EXPECTED_PAYLOADS) {
        assert_eq!(payload, expected);
    }
    assert!(observed.iter().all(|(_, peer)| *peer == observed[0].1));
    assert!(matches!(observed[0].1, SocketAddr::V6(peer) if peer.ip().is_loopback()));
    assert!(
        rebinds.0.is_ok() && rebinds.1.is_ok() && rebinds.2.is_ok(),
        "socket rebind failed"
    );
    assert_eq!(active_child_count(), baseline_children);
}

#[test]
fn default_startup_owns_same_tcp_udp_port_and_shutdown_rebinds_both() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = unused_tcp_udp_loopback();
    let config = write_server_config(directory.path(), address, None).expect("server config");
    let mut child = ChildGuard::spawn_with_context("ferrum2-server", &config, "UDP dual bind");
    wait_for_tcp_udp_bound(&mut child, address);

    let tcp_error = bind_loopback_listener(address).expect_err("TCP must be owned");
    assert_eq!(tcp_error.kind(), io::ErrorKind::AddrInUse);
    let udp_error = UdpSocket::bind(address).expect_err("UDP must be owned");
    assert_eq!(udp_error.kind(), io::ErrorKind::AddrInUse);

    child.terminate_and_reap(Duration::from_secs(5));
    let tcp = bind_loopback_listener(address).expect("TCP rebind");
    let udp = UdpSocket::bind(address).expect("UDP rebind");
    drop(udp);
    drop(tcp);
}

#[test]
fn either_bind_failure_leaves_the_other_protocol_rebindable_before_any_loop_runs() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");

    let udp_address = unused_tcp_udp_loopback();
    let udp_incumbent = UdpSocket::bind(udp_address).expect("occupy UDP");
    let udp_config =
        write_server_config(directory.path(), udp_address, None).expect("UDP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", udp_config.to_str().expect("UTF-8 config")],
    );
    assert_startup_bind_failure(&output, udp_address);
    let never_owned_tcp = bind_loopback_listener(udp_address).expect("TCP remained unbound");
    drop(never_owned_tcp);
    drop(udp_incumbent);

    let tcp_address = unused_tcp_udp_loopback();
    let tcp_incumbent = bind_loopback_listener(tcp_address).expect("occupy TCP");
    let tcp_config =
        write_server_config(directory.path(), tcp_address, None).expect("TCP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", tcp_config.to_str().expect("UTF-8 config")],
    );
    assert_startup_bind_failure(&output, tcp_address);
    let rolled_back_udp = UdpSocket::bind(tcp_address).expect("UDP bind rolled back");
    drop(rolled_back_udp);
    drop(tcp_incumbent);
}

#[test]
fn disabled_udp_creates_no_udp_owner_and_preserves_tcp_only_restart() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = unused_tcp_udp_loopback();
    let config = write_server_config(directory.path(), address, None).expect("server config");
    disable_udp(&config);

    for cycle in 0..2 {
        let mut child = ChildGuard::spawn_with_context(
            "ferrum2-server",
            &config,
            format!("UDP disabled cycle {cycle}"),
        );
        wait_for_bound(&mut child, address);
        let udp = UdpSocket::bind(address).expect("disabled UDP leaves port free");
        child.assert_running();
        drop(udp);
        child.terminate_and_reap(Duration::from_secs(5));
    }
}
