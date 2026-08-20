#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use local_support::{
    ChainRoot, ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, TCP_METHOD_CONFIGS,
    active_child_count, bind_loopback_listener, rewrite_config_method, route_tagged_config,
    start_dns_answer, start_dns_script, unused_loopback, unused_tcp_udp_loopback, wait_for_bound,
    wait_for_listener, wait_for_metrics, wait_for_metrics_sample, wait_for_tcp_udp_bound,
    write_client_config, write_client_config_with_psk, write_tagged_client_config,
    write_tagged_dns_server_matrix_config, write_tagged_server_config,
    write_tcp_only_server_config, write_tcp_only_server_config_with_psk,
    write_two_hop_client_config,
};

struct EchoWorker {
    address: SocketAddr,
    task: Option<thread::JoinHandle<Vec<u8>>>,
}

impl EchoWorker {
    fn join(mut self) -> thread::Result<Vec<u8>> {
        self.task.take().expect("echo worker").join()
    }
}

impl Drop for EchoWorker {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = TcpStream::connect(self.address);
            let _ = task.join();
        }
    }
}

fn start_echo() -> (SocketAddrV4, EchoWorker) {
    let (address, handle) =
        start_echo_at(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let address = match address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    (address, handle)
}

fn start_echo_at(bind: SocketAddr) -> (SocketAddr, EchoWorker) {
    let listener = match bind {
        SocketAddr::V4(address) if address.port() == 0 => {
            bind_loopback_listener(address).expect("echo listener")
        }
        _ => TcpListener::bind(bind).expect("echo listener"),
    };
    let address = listener.local_addr().expect("echo address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking echo listener");
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "echo accept timed out"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("echo accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking echo stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("echo timeout");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("echo read");
        stream.write_all(&received).expect("echo write");
        stream.shutdown(Shutdown::Write).expect("echo half close");
        received
    });
    (
        address,
        EchoWorker {
            address,
            task: Some(handle),
        },
    )
}

fn start_recording_bridge(
    upstream: SocketAddrV4,
) -> (
    SocketAddrV4,
    mpsc::Receiver<SocketAddrV4>,
    thread::JoinHandle<()>,
) {
    let listener =
        bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bridge listener");
    let address = match listener.local_addr().expect("bridge address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    listener
        .set_nonblocking(true)
        .expect("nonblocking bridge listener");
    let (peer_sender, peer_receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (client, peer) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "bridge accept timed out"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("bridge accept failed: {error}"),
            }
        };
        client
            .set_nonblocking(false)
            .expect("blocking bridge client");
        let peer = match peer {
            std::net::SocketAddr::V4(peer) => peer,
            std::net::SocketAddr::V6(_) => unreachable!("IPv4 bridge peer"),
        };
        peer_sender.send(peer).expect("record bridge peer");
        let server = TcpStream::connect(upstream).expect("bridge upstream");
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("bridge read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .expect("bridge write timeout");
        }
        let mut client_read = client.try_clone().expect("clone bridge client");
        let mut server_write = server.try_clone().expect("clone bridge server");
        let forward = thread::spawn(move || {
            std::io::copy(&mut client_read, &mut server_write).expect("bridge client to server");
            server_write
                .shutdown(Shutdown::Write)
                .expect("bridge upstream half close");
        });
        let mut server_read = server;
        let mut client_write = client;
        std::io::copy(&mut server_read, &mut client_write).expect("bridge server to client");
        client_write
            .shutdown(Shutdown::Write)
            .expect("bridge client half close");
        forward.join().expect("bridge forward thread");
    });
    (address, peer_receiver, handle)
}

fn socks_connect(client: SocketAddrV4, target: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    socks_connect_wire(client, &address_wire(SocketAddr::V4(target)))
}

fn address_wire(target: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::new();
    match target {
        SocketAddr::V4(target) => {
            wire.push(1);
            wire.extend_from_slice(&target.ip().octets());
        }
        SocketAddr::V6(target) => {
            wire.push(4);
            wire.extend_from_slice(&target.ip().octets());
        }
    }
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire
}

fn socks_connect_wire(client: SocketAddrV4, target: &[u8]) -> (TcpStream, [u8; 10]) {
    let mut stream = TcpStream::connect(client).expect("connect SOCKS client");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("SOCKS read timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(target);
    stream.write_all(&request).expect("SOCKS request");
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).expect("SOCKS reply");
    (stream, reply)
}

fn domain_wire(name: &str, port: u16) -> Vec<u8> {
    let mut wire = Vec::with_capacity(name.len() + 4);
    wire.extend_from_slice(&[3, name.len() as u8]);
    wire.extend_from_slice(name.as_bytes());
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

fn assert_socks_domain_failure(client: SocketAddrV4, name: &str, port: u16) {
    let (mut socks, reply) = socks_connect_wire(client, &domain_wire(name, port));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    socks
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("failed domain timeout");
    let mut byte = [0_u8; 1];
    match socks.read(&mut byte) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("failed domain forwarded {read} application bytes"),
    }
}

#[test]
fn m14_server_tcp_sniff_routes_rejects_and_replays_prefix() {
    const CLIENT_ZERO: &str =
        "ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"} 0";
    const SERVER_ZERO: &str =
        "ferrum2_tcp_connections_active{role=\"server\",inbound=\"shadowsocks\"} 0";

    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("M14 server TCP tempdir");
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let client_metrics = unused_loopback();
    let server_metrics = unused_loopback();
    let (route_target, route_echo) = start_echo();
    let (malformed_target, malformed_echo) = start_echo();
    let rejected =
        bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("rejected target");
    rejected
        .set_nonblocking(true)
        .expect("rejected target nonblocking");
    let rejected_target = match rejected.local_addr().expect("rejected target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 rejected target"),
    };
    let server_config = directory.path().join("m14-server-tcp.toml");
    std::fs::write(
        &server_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"in\"\nlisten = \"{server_address}\"\n\
             [[outbounds]]\ntag = \"direct\"\n\
             [route]\nfinal = \"direct\"\n\
             [route.sniff]\ntimeout_ms = 300\nmax_bytes = 8192\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"http\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nprotocol = \"http\"\ndomain = \"route.test\"\naction = \"route\"\noutbound = \"direct\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nprotocol = \"http\"\ndomain = \"reject.test\"\naction = \"reject\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nport = {}\naction = \"route\"\noutbound = \"direct\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [udp]\nenabled = false\n\
             [metrics]\nlisten = \"{server_metrics}\"\n",
            rejected_target.port(),
        ),
    )
    .expect("M14 server TCP config");
    let client_config = write_client_config(
        directory.path(),
        client_address,
        server_address,
        Some(client_metrics),
    )
    .expect("M14 server TCP client config");

    let mut server =
        ChildGuard::spawn_while_holding("ferrum2-server", &server_config, &_spawn_guard);
    wait_for_listener(&mut server, server_address);
    wait_for_metrics(server_metrics);
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &_spawn_guard);
    wait_for_listener(&mut client, client_address);
    wait_for_metrics(client_metrics);
    drop(_spawn_guard);

    let route_prefix = b"GET /route HTTP/1.1\r\nHost: route.test\r\n\r\nroute-body";
    let (mut routed, reply) = socks_connect_wire(
        client_address,
        &domain_wire("localhost", route_target.port()),
    );
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    routed.write_all(route_prefix).expect("routed prefix");
    routed.shutdown(Shutdown::Write).expect("routed half close");
    let mut echoed = Vec::new();
    routed.read_to_end(&mut echoed).expect("routed response");
    assert_eq!(echoed, route_prefix);
    assert_eq!(route_echo.join().expect("routed target"), route_prefix);

    let (mut denied, reply) = socks_connect(client_address, rejected_target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    denied
        .write_all(b"GET / HTTP/1.1\r\nHost: reject.test\r\n\r\n")
        .expect("rejected prefix");
    denied
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("rejected timeout");
    assert!(matches!(denied.read(&mut [0_u8; 1]), Ok(0) | Err(_)));
    thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(rejected.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "terminal reject evaluated its later route"
    );

    let malformed_prefix = b"G@T / HTTP/1.1\r\nHost: malformed.test\r\n\r\n";
    let (mut malformed, reply) = socks_connect(client_address, malformed_target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    malformed
        .write_all(malformed_prefix)
        .expect("malformed prefix");
    malformed
        .shutdown(Shutdown::Write)
        .expect("malformed half close");
    let mut echoed = Vec::new();
    malformed
        .read_to_end(&mut echoed)
        .expect("malformed response");
    assert_eq!(echoed, malformed_prefix);
    assert_eq!(
        malformed_echo.join().expect("malformed target"),
        malformed_prefix
    );
    drop((routed, denied, malformed));

    let client_body = wait_for_metrics_sample(client_metrics, CLIENT_ZERO);
    let server_body = wait_for_metrics_sample(server_metrics, SERVER_ZERO);
    for sentinel in ["route.test", "reject.test", "malformed.test", SYNTHETIC_PSK] {
        for body in [&client_body, &server_body] {
            assert!(
                !body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "metrics exposed M14 TCP identity"
            );
        }
    }
    let exits = [
        client.terminate_and_reap_with_exit(Duration::from_secs(5)),
        server.terminate_and_reap_with_exit(Duration::from_secs(5)),
    ];
    for exit in &exits {
        exit.assert_stderr_excludes(&[
            "route.test",
            "reject.test",
            "malformed.test",
            SYNTHETIC_PSK,
        ]);
    }
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);
    drop(rejected);
    for address in [
        client_address,
        server_address,
        client_metrics,
        server_metrics,
        route_target,
        malformed_target,
        rejected_target,
    ] {
        drop(bind_loopback_listener(address).expect("M14 server TCP exact rebind"));
    }
}

#[test]
fn m14_client_tcp_dns_hijack_reuses_policy_and_reaps() {
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("M14 client TCP tempdir");
    let selected_name = "selected-hijack.test.";
    let final_name = "final-hijack.test.";
    let selected_tag = "selected-hijack-upstream";
    let final_tag = "final-hijack-upstream";
    let selected_dns = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::Addresses(vec![Ipv4Addr::new(127, 0, 0, 11)]),
    }]);
    let final_dns = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::Addresses(vec![Ipv4Addr::new(127, 0, 0, 12)]),
    }]);
    let dns_addresses = [selected_dns.address(), final_dns.address()];
    let protected = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("protected upstream");
    protected
        .set_nonblocking(true)
        .expect("protected upstream nonblocking");
    let protected_address = match protected.local_addr().expect("protected upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 protected upstream"),
    };
    let client_address = unused_loopback();
    let dns_listen = unused_tcp_udp_loopback();
    let metrics_address = unused_loopback();
    let client_config = directory.path().join("m14-client-tcp-hijack.toml");
    std::fs::write(
        &client_config,
        format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"in\"\nlisten = \"{client_address}\"\n\
             [[outbounds]]\ntag = \"protected\"\nserver = \"{protected_address}\"\n\
             [route]\nfinal = \"protected\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nport = 53\naction = \"hijack-dns\"\n\
             [dns]\nmax_inflight = 4\n\
             [[dns.inbounds]]\ntag = \"dedicated\"\nlisten = \"{dns_listen}\"\n\
             [[dns.servers]]\ntag = \"{selected_tag}\"\ntransport = \"udp\"\naddress = \"{}\"\n\
             [[dns.servers]]\ntag = \"{final_tag}\"\ntransport = \"udp\"\naddress = \"{}\"\n\
             [dns.route]\nfinal = \"{final_tag}\"\n\
             [[dns.route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nqname = \"{selected_name}\"\nqtype = \"A\"\nserver = \"{selected_tag}\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [udp]\nenabled = false\n\
             [metrics]\nlisten = \"{metrics_address}\"\n",
            dns_addresses[0], dns_addresses[1],
        ),
    )
    .expect("M14 client TCP hijack config");
    let checked = std::process::Command::new(local_support::binary_path("ferrum2-client"))
        .args([
            "--config",
            client_config.to_str().expect("UTF-8 M14 client config"),
        ])
        .arg("--check-config")
        .output()
        .expect("M14 client config check process");
    assert!(
        checked.status.success(),
        "M14 client config check: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &_spawn_guard);
    wait_for_listener(&mut client, client_address);
    wait_for_tcp_udp_bound(&mut client, dns_listen);
    wait_for_metrics(metrics_address);
    drop(_spawn_guard);

    let (mut hijacked, reply) =
        socks_connect(client_address, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    for (id, name, answer) in [
        (0x1403, selected_name, Ipv4Addr::new(127, 0, 0, 11)),
        (0x1404, final_name, Ipv4Addr::new(127, 0, 0, 12)),
    ] {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(name).expect("M14 hijack DNS name"),
            RecordType::A,
        ));
        let query = query.to_vec().expect("M14 hijack DNS query");
        hijacked
            .write_all(&(query.len() as u16).to_be_bytes())
            .expect("M14 DNS frame length");
        hijacked.write_all(&query).expect("M14 DNS frame");
        let mut length = [0_u8; 2];
        hijacked
            .read_exact(&mut length)
            .expect("M14 DNS response length");
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        hijacked
            .read_exact(&mut response)
            .expect("M14 DNS response");
        let response = Message::from_vec(&response).expect("M14 typed DNS response");
        assert_eq!(response.id, id);
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(&record.data, RData::A(address) if address.0 == answer))
        );
    }
    drop(hijacked);
    assert_eq!(selected_dns.join(), [RecordType::A]);
    assert_eq!(final_dns.join(), [RecordType::A]);

    let (mut malformed, reply) =
        socks_connect(client_address, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    malformed
        .write_all(&[0, 3, b'b', b'a', b'd'])
        .expect("malformed hijack frame");
    malformed
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("malformed hijack timeout");
    assert!(matches!(malformed.read(&mut [0_u8; 1]), Ok(0) | Err(_)));
    drop(malformed);
    thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(protected.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "terminal DNS hijack fell back to its later outbound"
    );

    let metrics = wait_for_metrics(metrics_address);
    let active = String::from_utf8_lossy(&metrics)
        .lines()
        .filter(|line| line.starts_with("ferrum2_tcp_connections_active{"))
        .map(|line| {
            line.rsplit_once(' ')
                .expect("TCP active metric sample")
                .1
                .parse::<u64>()
                .expect("TCP active metric value")
        })
        .sum::<u64>();
    assert_eq!(active, 0, "hijacked TCP owner did not reap");
    for zero in [
        "ferrum2_udp_sessions_active{role=\"client\"} 0",
        "ferrum2_udp_buffered_bytes{role=\"client\"} 0",
    ] {
        assert!(
            metrics
                .windows(zero.len())
                .any(|window| window == zero.as_bytes())
        );
    }
    for sentinel in [
        selected_name,
        final_name,
        selected_tag,
        final_tag,
        SYNTHETIC_PSK,
    ] {
        assert!(
            !metrics
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes()),
            "metrics exposed M14 DNS hijack identity"
        );
    }
    let exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
    exit.assert_stderr_excludes(&[
        selected_name,
        final_name,
        selected_tag,
        final_tag,
        SYNTHETIC_PSK,
    ]);
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);
    drop(protected);
    for address in [client_address, metrics_address, protected_address] {
        drop(bind_loopback_listener(address).expect("M14 client TCP exact rebind"));
    }
    drop(bind_loopback_listener(dns_listen).expect("M14 DNS TCP exact rebind"));
    drop(UdpSocket::bind(dns_listen).expect("M14 DNS UDP exact rebind"));
    for address in dns_addresses {
        drop(UdpSocket::bind(address).expect("M14 hijack DNS exact rebind"));
    }
}

#[test]
fn tagged_dns_tcp_resolution_uses_detour_and_reaps() {
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let selected_name = "selected.test.";
    let final_name = "final.test.";
    let wrong_name = "wrong-id-sentinel.test.";
    let empty_name = "localhost";
    let timeout_name = "timeout-sentinel.test.";
    let many_name = "many-sentinel.test.";
    let delayed_name = "delayed-sentinel.test.";
    let busy_name = "busy-sentinel.test.";
    let loop_name = "loop-sentinel.test.";
    let (selected_target, selected_echo) =
        start_echo_at("127.0.0.1:0".parse().expect("selected target address"));
    let (final_target, final_echo) =
        start_echo_at("127.0.0.2:0".parse().expect("final target address"));
    let (bypass_target, bypass_echo) = start_echo();
    let protected = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("protected target");
    protected
        .set_nonblocking(true)
        .expect("protected target nonblocking");
    let protected_port = protected
        .local_addr()
        .expect("protected target address")
        .port();
    let many_target = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 17), 0))
        .expect("seventeenth candidate target");
    many_target
        .set_nonblocking(true)
        .expect("seventeenth candidate nonblocking");
    let many_port = many_target
        .local_addr()
        .expect("many target address")
        .port();

    let selected_dns = start_dns_answer(Ipv4Addr::new(127, 0, 0, 1), 2);
    let final_dns = start_dns_answer(Ipv4Addr::new(127, 0, 0, 2), 2);
    let wrong_dns = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::WrongId,
    }]);
    let empty_dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::NoData,
        },
        DnsStep {
            record_type: RecordType::AAAA,
            reply: DnsReply::NoData,
        },
    ]);
    let timeout_dns = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::Silence(Duration::from_millis(1_200)),
    }]);
    let many_dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::Addresses(
                (1..=17)
                    .map(|last| Ipv4Addr::new(127, 0, 0, last))
                    .collect(),
            ),
        },
        DnsStep {
            record_type: RecordType::AAAA,
            reply: DnsReply::NoData,
        },
    ]);
    let delayed_dns = start_dns_script(vec![
        DnsStep {
            record_type: RecordType::A,
            reply: DnsReply::DelayedNoData(Duration::from_millis(200)),
        },
        DnsStep {
            record_type: RecordType::AAAA,
            reply: DnsReply::Silence(Duration::from_millis(1_500)),
        },
    ]);
    let loop_dns = start_dns_script(vec![DnsStep {
        record_type: RecordType::A,
        reply: DnsReply::Silence(Duration::from_millis(1_200)),
    }]);
    let busy_probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("busy DNS probe");
    busy_probe
        .set_nonblocking(true)
        .expect("busy DNS probe nonblocking");
    let busy_address = match busy_probe.local_addr().expect("busy DNS probe address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 busy DNS probe"),
    };
    let dns_addresses = [
        selected_dns.address(),
        final_dns.address(),
        wrong_dns.address(),
        empty_dns.address(),
        timeout_dns.address(),
        many_dns.address(),
        delayed_dns.address(),
        loop_dns.address(),
    ];
    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let metrics_address = unused_loopback();
    let servers = [
        ("selected", dns_addresses[0]),
        ("final", dns_addresses[1]),
        ("wrong", dns_addresses[2]),
        ("empty", dns_addresses[3]),
        ("timeout", dns_addresses[4]),
        ("many", dns_addresses[5]),
        ("delayed", dns_addresses[6]),
        ("loop", dns_addresses[7]),
        ("busy", busy_address),
    ];
    let rules = [
        (selected_name, selected_target.port(), "selected"),
        (wrong_name, protected_port, "wrong"),
        (empty_name, protected_port, "empty"),
        (timeout_name, protected_port, "timeout"),
        (many_name, many_port, "many"),
        (delayed_name, protected_port, "delayed"),
        (busy_name, protected_port, "busy"),
        (loop_name, protected_port, "loop"),
    ];
    let server_config = write_tagged_dns_server_matrix_config(
        directory.path(),
        server_address,
        "tcp",
        &servers,
        &rules,
        "final",
        1_000,
        1,
        false,
        Some(metrics_address),
    )
    .expect("tagged DNS server config");
    let client_config = write_client_config(directory.path(), client_address, server_address, None)
        .expect("client config");
    let mut server = ChildGuard::spawn_signallable_while_holding(
        "ferrum2-server",
        &server_config,
        &_spawn_guard,
    );
    wait_for_listener(&mut server, server_address);
    wait_for_metrics(metrics_address);
    let mut client =
        ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &_spawn_guard);
    wait_for_listener(&mut client, client_address);
    drop(_spawn_guard);

    for (name, target, payload) in [
        (selected_name, selected_target, b"selected".as_slice()),
        (final_name, final_target, b"final".as_slice()),
    ] {
        let (mut socks, reply) =
            socks_connect_wire(client_address, &domain_wire(name, target.port()));
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        socks.write_all(payload).expect("domain payload");
        socks.shutdown(Shutdown::Write).expect("domain half close");
        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("domain response");
        assert_eq!(echoed, payload);
    }
    assert_eq!(selected_echo.join().expect("selected echo"), b"selected");
    selected_dns.wait_for_query(RecordType::A);
    selected_dns.wait_for_query(RecordType::AAAA);
    final_dns.wait_for_query(RecordType::A);
    final_dns.wait_for_query(RecordType::AAAA);
    let (mut bypass, reply) =
        socks_connect_wire(client_address, &address_wire(SocketAddr::V4(bypass_target)));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    bypass.write_all(b"bypass").expect("IP bypass payload");
    bypass.shutdown(Shutdown::Write).expect("IP bypass close");
    let mut bypassed = Vec::new();
    bypass
        .read_to_end(&mut bypassed)
        .expect("IP bypass response");
    assert_eq!(bypassed, b"bypass");

    assert_socks_domain_failure(client_address, wrong_name, protected_port);
    wrong_dns.wait_for_query(RecordType::A);
    assert_socks_domain_failure(client_address, empty_name, protected_port);
    empty_dns.wait_for_query(RecordType::A);
    empty_dns.wait_for_query(RecordType::AAAA);
    assert_socks_domain_failure(client_address, timeout_name, protected_port);
    timeout_dns.wait_for_query(RecordType::A);
    assert_socks_domain_failure(client_address, many_name, many_port);
    many_dns.wait_for_query(RecordType::A);
    many_dns.wait_for_query(RecordType::AAAA);
    assert_socks_domain_failure(client_address, loop_name, protected_port);
    loop_dns.wait_for_query(RecordType::A);

    let delayed_started = Instant::now();
    let (delayed, delayed_reply) =
        socks_connect_wire(client_address, &domain_wire(delayed_name, protected_port));
    assert_eq!(&delayed_reply[..4], &[5, 0, 0, 1]);
    delayed_dns.wait_for_query(RecordType::A);
    let (saturated, saturated_reply) =
        socks_connect_wire(client_address, &domain_wire(busy_name, protected_port));
    assert_eq!(&saturated_reply[..4], &[5, 0, 0, 1]);
    delayed_dns.wait_for_query(RecordType::AAAA);
    thread::sleep(Duration::from_millis(900));
    assert!(
        matches!(busy_probe.recv_from(&mut [0_u8; 64]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "saturated DNS request reached its selected upstream"
    );
    assert!(
        delayed_started.elapsed() < Duration::from_millis(1_800),
        "A/AAAA resolution exceeded one deadline"
    );
    drop((delayed, saturated));

    assert_eq!(final_echo.join().expect("final echo"), b"final");
    assert_eq!(bypass_echo.join().expect("bypass echo"), b"bypass");
    assert_eq!(selected_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(final_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(wrong_dns.join(), [RecordType::A]);
    assert_eq!(empty_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(timeout_dns.join(), [RecordType::A]);
    assert_eq!(many_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(delayed_dns.join(), [RecordType::A, RecordType::AAAA]);
    assert_eq!(loop_dns.join(), [RecordType::A]);
    for target in [&protected, &many_target] {
        assert!(
            matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "failed DNS path reached a protected TCP target"
        );
    }
    let metrics = wait_for_metrics(metrics_address);
    for sentinel in [
        wrong_name,
        empty_name,
        timeout_name,
        many_name,
        delayed_name,
        busy_name,
        loop_name,
    ] {
        assert!(
            !metrics
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes()),
            "metrics exposed DNS sentinel"
        );
    }
    let client_exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
    server.request_graceful_shutdown();
    let server_exit = server.wait_for_exit(Duration::from_secs(5));
    for exit in [&client_exit, &server_exit] {
        exit.assert_stderr_excludes(&[
            selected_name,
            final_name,
            "selected",
            "final",
            "dns-direct",
            "app-direct",
            wrong_name,
            empty_name,
            timeout_name,
            many_name,
            delayed_name,
            busy_name,
            loop_name,
        ]);
    }
    let _spawn_guard = local_support::hold_process_spawns_at_or_below(baseline_children);
    assert_eq!(active_child_count(), baseline_children);
    drop(bind_loopback_listener(client_address).expect("client exact rebind"));
    drop(bind_loopback_listener(server_address).expect("server TCP exact rebind"));
    drop(UdpSocket::bind(server_address).expect("server UDP exact rebind"));
    drop(bind_loopback_listener(metrics_address).expect("metrics exact rebind"));
    drop(busy_probe);
    drop(UdpSocket::bind(busy_address).expect("busy DNS exact rebind"));
    for address in dns_addresses {
        drop(UdpSocket::bind(address).expect("DNS exact rebind"));
    }
}

#[test]
fn echo_worker_drop_joins_and_releases_listener() {
    let _spawn_guard = local_support::hold_process_spawns();
    let (address, worker) = start_echo();
    drop(worker);
    drop(TcpListener::bind(address).expect("dropped echo listener rebind"));
}

#[test]
fn direct_tcp_real_process_preserves_raw_bytes_and_half_close() {
    for form in ["static", "rule", "final", "selector"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let client_address = unused_loopback();
        let (target, echo) = start_echo();
        let fallback = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("fallback sentinel");
        fallback
            .set_nonblocking(true)
            .expect("nonblocking fallback sentinel");
        let fallback_address = fallback.local_addr().expect("fallback address");
        let root = match form {
            "static" => "outbound = \"exit\"\n".to_owned(),
            "rule" => format!(
                "[route]\nfinal = \"fallback\"\n[[route.rules]]\ninbound = \"m16-tag-sentinel\"\nnetwork = \"tcp\"\nip = \"{}\"\nport = {}\noutbound = \"exit\"\n",
                target.ip(),
                target.port()
            ),
            "final" => "[route]\nfinal = \"exit\"\n".to_owned(),
            "selector" => "outbound = \"manual\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"exit\", \"fallback\"]\ndefault = \"exit\"\n".to_owned(),
            _ => unreachable!(),
        };
        let proxy = matches!(form, "rule" | "selector").then(|| {
            format!(
                "[[outbounds]]\ntag = \"fallback\"\nserver = \"{fallback_address}\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"bTE2LXNlY3JldC1rZXkhIQ==\"\n"
            )
        });
        let config = directory
            .path()
            .join(format!("m16-direct-{form}-client.toml"));
        std::fs::write(
            &config,
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"m16-tag-sentinel\"\nlisten = \"{client_address}\"\n{root}[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n{}",
                proxy.as_deref().unwrap_or_default(),
            ),
        )
        .expect("direct client config");
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);

        let (mut socks, reply) = socks_connect(client_address, target);
        assert_eq!(&reply[..2], &[5, 0], "{form}");
        socks.write_all(form.as_bytes()).expect("direct payload");
        socks.shutdown(Shutdown::Write).expect("direct half close");
        let mut response = Vec::new();
        socks.read_to_end(&mut response).expect("direct response");
        assert_eq!(response, form.as_bytes(), "{form}");
        assert_eq!(echo.join().expect("direct echo"), form.as_bytes(), "{form}");
        assert!(
            matches!(fallback.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "{form} selected the proxy fallback"
        );
        let exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
        exit.assert_stderr_excludes(&[
            "m16-tag-sentinel",
            &fallback_address.to_string(),
            "bTE2LXNlY3JldC1rZXkhIQ==",
            "m16-secret-key!!",
        ]);
    }

    let ipv6_loopback = TcpListener::bind("[::1]:0").is_ok_and(|listener| {
        TcpStream::connect(listener.local_addr().expect("IPv6 probe address")).is_ok()
    });
    if ipv6_loopback {
        let directory = tempfile::tempdir().expect("IPv6 temporary directory");
        let client_address = unused_loopback();
        let config = directory.path().join("m16-direct-ipv6-client.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"{client_address}\"\noutbound = \"exit\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n"
            ),
        )
        .expect("IPv6 direct config");
        let (target, echo) = start_echo_at("[::1]:0".parse().expect("IPv6 bind"));
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);
        let mut socks = TcpStream::connect(client_address).expect("IPv6 SOCKS client");
        socks
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("IPv6 SOCKS timeout");
        socks.write_all(&[5, 1, 0]).expect("IPv6 SOCKS greeting");
        let mut method = [0_u8; 2];
        socks.read_exact(&mut method).expect("IPv6 SOCKS method");
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&address_wire(target));
        socks.write_all(&request).expect("IPv6 SOCKS request");
        let mut reply = [0_u8; 22];
        socks.read_exact(&mut reply).expect("IPv6 SOCKS reply");
        assert_eq!(&reply[..4], &[5, 0, 0, 4]);
        assert_eq!(&reply[4..20], &Ipv6Addr::LOCALHOST.octets());
        socks.write_all(b"ipv6-direct").expect("IPv6 payload");
        socks.shutdown(Shutdown::Write).expect("IPv6 half close");
        let mut response = Vec::new();
        socks.read_to_end(&mut response).expect("IPv6 response");
        assert_eq!(response, b"ipv6-direct");
        assert_eq!(echo.join().expect("IPv6 direct echo"), b"ipv6-direct");
    }
}

#[test]
fn success_bounded_method_matrix_preserves_bytes_and_half_close() {
    let ipv6_loopback = TcpListener::bind("[::1]:0").is_ok_and(|listener| {
        TcpStream::connect(listener.local_addr().expect("IPv6 probe address")).is_ok()
    });
    if !ipv6_loopback {
        eprintln!("SKIP real-process IPv6 row: host IPv6 loopback connect unavailable");
    }
    for (address_class, method) in TCP_METHOD_CONFIGS.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let server_address = unused_loopback();
        let client_address = unused_loopback();
        let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
            .expect("server config");
        let client_config =
            write_client_config(directory.path(), client_address, server_address, None)
                .expect("client config");
        rewrite_config_method(&server_config, method).expect("server method");
        rewrite_config_method(&client_config, method).expect("client method");
        let (target, echo) = match address_class {
            0 => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
            1 => {
                let (target, echo) = start_echo();
                let mut wire = b"\x03\x09127.0.0.1".to_vec();
                wire.extend_from_slice(&target.port().to_be_bytes());
                (wire, echo)
            }
            _ if ipv6_loopback => {
                let (target, echo) =
                    start_echo_at("[::1]:0".parse().expect("IPv6 loopback address"));
                (address_wire(target), echo)
            }
            _ => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
        };

        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        wait_for_listener(&mut server, server_address);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_listener(&mut client, client_address);

        let (mut socks, reply) = socks_connect_wire(client_address, &target);
        assert_eq!(&reply[..4], &[5, 0, 0, 1], "{}", method.0);
        let first = method.0.as_bytes();
        let second = vec![0x5a; 16_385];
        socks.write_all(first).expect("first payload");
        socks.write_all(&second).expect("second payload");
        socks.shutdown(Shutdown::Write).expect("client half close");

        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("reverse drain");
        let mut expected = first.to_vec();
        expected.extend_from_slice(&second);
        assert_eq!(echoed, expected, "{}", method.0);
        assert_eq!(echo.join().expect("echo thread"), expected, "{}", method.0);
    }
}

#[test]
fn success_reply_uses_exact_opened_shadowsocks_socket_local_endpoint() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let (bridge_address, bridge_peer, bridge) = start_recording_bridge(server_address);
    let client_config = write_client_config(directory.path(), client_address, bridge_address, None)
        .expect("client config");
    let (echo_address, echo) = start_echo();

    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, echo_address);
    let opened_endpoint = bridge_peer
        .recv_timeout(Duration::from_secs(5))
        .expect("opened Shadowsocks endpoint");
    let mut expected = [0_u8; 6];
    expected[..4].copy_from_slice(&opened_endpoint.ip().octets());
    expected[4..].copy_from_slice(&opened_endpoint.port().to_be_bytes());
    assert_eq!(&reply[4..], &expected);

    socks.write_all(b"endpoint").expect("payload");
    socks.shutdown(Shutdown::Write).expect("client half close");
    let mut echoed = Vec::new();
    socks.read_to_end(&mut echoed).expect("reverse drain");
    assert_eq!(echoed, b"endpoint");
    assert_eq!(echo.join().expect("echo thread"), b"endpoint");
    bridge.join().expect("bridge thread");
}

#[test]
fn failures_unauthenticated_request_never_connects_target() {
    const DIFFERENT_SYNTHETIC_PSK: &str = "EBESExQVFhcYGRobHB0eHw==";

    let directory = tempfile::tempdir().expect("temporary directory");
    let target = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("recording target");
    target
        .set_nonblocking(true)
        .expect("nonblocking recording target");
    let target_address = match target.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config_with_psk(
        directory.path(),
        server_address,
        None,
        DIFFERENT_SYNTHETIC_PSK,
    )
    .expect("server config");
    let client_config = write_client_config_with_psk(
        directory.path(),
        client_address,
        server_address,
        None,
        local_support::SYNTHETIC_PSK,
    )
    .expect("client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, target_address);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected application byte count after authentication reject: {read}"),
    }
    match target.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("unauthenticated request connected to target"),
        Err(error) => panic!("recording target accept failed: {error}"),
    }
}

#[test]
fn failures_pre_success_connect_and_post_success_target_refusal() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let unavailable_server = unused_loopback();
    let client_address = unused_loopback();
    let client_config =
        write_client_config(directory.path(), client_address, unavailable_server, None)
            .expect("client config");
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (_socks, reply) = socks_connect(client_address, unused_loopback());
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(client);

    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let client_config = write_client_config(directory.path(), client_address, server_address, None)
        .expect("client config");
    let refused_target = unused_loopback();
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (mut socks, reply) = socks_connect(client_address, refused_target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected second SOCKS reply/application byte count: {read}"),
    }
}

#[test]
fn tagged_two_by_two_tcp_matrix_covers_all_methods_and_exact_rebind() {
    for (method, routed) in [
        (TCP_METHOD_CONFIGS[0], false),
        (TCP_METHOD_CONFIGS[1], false),
        (TCP_METHOD_CONFIGS[2], false),
        (TCP_METHOD_CONFIGS[1], true),
    ] {
        let directory = tempfile::tempdir().expect("tagged TCP tempdir");
        let servers = [unused_loopback(), unused_loopback()];
        let clients = [unused_loopback(), unused_loopback()];
        let (bridge_a, peer_a, task_a) = start_recording_bridge(servers[0]);
        let (bridge_b, peer_b, task_b) = start_recording_bridge(servers[1]);
        let bridges = [bridge_a, bridge_b];
        let peers = [peer_a, peer_b];
        let server_config = write_tagged_server_config(directory.path(), servers, [0, 1], false)
            .expect("tagged server config");
        let client_config =
            write_tagged_client_config(directory.path(), clients, bridges, [0, 1], false)
                .expect("tagged client config");
        if routed {
            route_tagged_config(&client_config, "\n[route]\nfinal = \"out-0\"\n[[route.rules]]\ninbound = \"in-a\"\nnetwork = \"tcp\"\noutbound = \"out-1\"\n[[route.rules]]\ninbound = \"in-a\"\noutbound = \"out-0\"\n").expect("routed client matrix");
            route_tagged_config(&server_config, "\n[route]\nfinal = \"out-1\"\n[[route.rules]]\ninbound = \"in-b\"\nnetwork = \"tcp\"\noutbound = \"out-0\"\n[[route.rules]]\ninbound = \"in-b\"\noutbound = \"out-1\"\n").expect("routed server matrix");
        }
        rewrite_config_method(&server_config, method).expect("tagged server method");
        rewrite_config_method(&client_config, method).expect("tagged client method");

        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        for address in servers {
            wait_for_listener(&mut server, address);
        }
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        for address in clients {
            wait_for_listener(&mut client, address);
        }

        for (mapping, client_address) in clients.into_iter().enumerate() {
            let (target, echo) = start_echo();
            let (mut socks, reply) = socks_connect(client_address, target);
            assert_eq!(&reply[..4], &[5, 0, 0, 1], "{} mapping {mapping}", method.0);
            peers[if routed { 1 - mapping } else { mapping }]
                .recv_timeout(Duration::from_secs(5))
                .expect("selected recording bridge");
            let payload = format!("{}-mapping-{mapping}", method.0);
            socks.write_all(payload.as_bytes()).expect("tagged payload");
            socks.shutdown(Shutdown::Write).expect("tagged half close");
            let mut echoed = Vec::new();
            socks.read_to_end(&mut echoed).expect("tagged echo");
            assert_eq!(echoed, payload.as_bytes());
            assert_eq!(echo.join().expect("tagged echo thread"), payload.as_bytes());
        }
        for task in [task_a, task_b] {
            task.join().expect("recording bridge");
        }

        client.terminate_and_reap(Duration::from_secs(5));
        server.terminate_and_reap(Duration::from_secs(5));
        for address in clients.into_iter().chain(servers).chain(bridges) {
            drop(bind_loopback_listener(address).expect("tagged exact rebind"));
        }
    }
}

#[test]
fn tagged_tcp_shared_outbound_no_fallback_and_aggregate_admission_are_process_visible() {
    let directory = tempfile::tempdir().expect("tagged focused tempdir");
    let servers = [unused_loopback(), unused_loopback()];
    let clients = [unused_loopback(), unused_loopback()];
    let server_config = write_tagged_server_config(directory.path(), servers, [0, 0], false)
        .expect("shared server config");
    let client_config =
        write_tagged_client_config(directory.path(), clients, servers, [0, 0], false)
            .expect("shared client config");
    let mut source = std::fs::read_to_string(&client_config).expect("read shared client config");
    source.push_str("\n[runtime]\nmax_connections = 1\n");
    std::fs::write(&client_config, source).expect("write aggregate limit");

    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    for address in servers {
        wait_for_listener(&mut server, address);
    }
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }

    for client_address in clients {
        let (target, echo) = start_echo();
        let (mut socks, reply) = socks_connect(client_address, target);
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        socks.write_all(b"shared").expect("shared payload");
        socks.shutdown(Shutdown::Write).expect("shared half close");
        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("shared echo");
        assert_eq!(echoed, b"shared");
        assert_eq!(echo.join().expect("shared echo thread"), b"shared");
    }

    let held = TcpStream::connect(clients[0]).expect("held aggregate flow");
    let mut contender = TcpStream::connect(clients[1]).expect("aggregate contender");
    contender
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("aggregate contender timeout");
    contender
        .write_all(&[5, 1, 0])
        .expect("aggregate contender greeting");
    let mut method = [0_u8; 2];
    assert!(matches!(
        contender.read_exact(&mut method),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    drop(held);
    contender
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore contender timeout");
    contender
        .read_exact(&mut method)
        .expect("aggregate permit release");
    assert_eq!(method, [5, 0]);
    drop(contender);

    client.terminate_and_reap(Duration::from_secs(5));
    server.terminate_and_reap(Duration::from_secs(5));
    for address in clients.into_iter().chain(servers) {
        drop(bind_loopback_listener(address).expect("shared exact rebind"));
    }

    let live_server = unused_loopback();
    let dead_server = unused_loopback();
    let clients = [unused_loopback(), unused_loopback()];
    let server_config =
        write_tcp_only_server_config(directory.path(), live_server, None).expect("live server");
    let client_config = write_tagged_client_config(
        directory.path(),
        clients,
        [live_server, dead_server],
        [0, 1],
        false,
    )
    .expect("no-fallback client");
    route_tagged_config(
        &client_config,
        "\n[route]\nfinal = \"out-0\"\n[[route.rules]]\ninbound = \"in-b\"\nnetwork = \"tcp\"\noutbound = \"out-1\"\n[[route.rules]]\ninbound = \"in-b\"\noutbound = \"out-0\"\n[[route.rules]]\nnetwork = \"udp\"\noutbound = \"out-0\"\n",
    )
    .expect("routed no-fallback client");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, live_server);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }
    let (_socks, reply) = socks_connect(clients[1], unused_loopback());
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    let (target, echo) = start_echo();
    let (mut socks, reply) = socks_connect(clients[0], target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    socks.write_all(b"live-only").expect("live payload");
    socks.shutdown(Shutdown::Write).expect("live half close");
    let mut echoed = Vec::new();
    socks.read_to_end(&mut echoed).expect("live echo");
    assert_eq!(echoed, b"live-only");
    assert_eq!(echo.join().expect("live echo thread"), b"live-only");
    client.terminate_and_reap(Duration::from_secs(5));
    server.terminate_and_reap(Duration::from_secs(5));
    for address in clients.into_iter().chain([live_server]) {
        drop(bind_loopback_listener(address).expect("no-fallback exact rebind"));
    }
}

#[test]
fn tagged_partial_bind_signal_shutdown_and_restart_release_every_listener() {
    let directory = tempfile::tempdir().expect("tagged lifecycle tempdir");

    let (clients, upstreams) = {
        let _spawn_guard = local_support::hold_process_spawns();
        (
            [unused_loopback(), unused_loopback()],
            [unused_loopback(), unused_loopback()],
        )
    };
    let client_config =
        write_tagged_client_config(directory.path(), clients, upstreams, [0, 1], false)
            .expect("tagged client lifecycle config");
    {
        let spawn_guard = local_support::hold_process_spawns();
        let occupied = bind_loopback_listener(clients[1]).expect("occupy middle client listener");
        let mut failed =
            ChildGuard::spawn_while_holding("ferrum2-client", &client_config, &spawn_guard);
        let exit = failed.wait_for_exit(Duration::from_secs(5));
        assert_eq!(exit.status.code(), Some(1), "{exit}");
        let released = bind_loopback_listener(clients[0]).expect("client partial rollback");
        drop(occupied);
        let previously_occupied =
            bind_loopback_listener(clients[1]).expect("client rollback exact rebind");
        drop((released, previously_occupied));
    }

    let servers = {
        let _spawn_guard = local_support::hold_process_spawns();
        [unused_tcp_udp_loopback(), unused_tcp_udp_loopback()]
    };
    let server_config = write_tagged_server_config(directory.path(), servers, [0, 1], true)
        .expect("tagged server lifecycle config");
    {
        let spawn_guard = local_support::hold_process_spawns();
        let occupied = bind_loopback_listener(servers[1]).expect("occupy middle server listener");
        let mut failed =
            ChildGuard::spawn_while_holding("ferrum2-server", &server_config, &spawn_guard);
        let exit = failed.wait_for_exit(Duration::from_secs(5));
        assert_eq!(exit.status.code(), Some(1), "{exit}");
        let released_tcp = bind_loopback_listener(servers[0]).expect("server TCP partial rollback");
        let released_udp = UdpSocket::bind(servers[0]).expect("server UDP partial rollback");
        drop(occupied);
        let previously_occupied_tcp =
            bind_loopback_listener(servers[1]).expect("server rollback TCP rebind");
        let previously_occupied_udp =
            UdpSocket::bind(servers[1]).expect("server rollback UDP rebind");
        drop((
            released_tcp,
            released_udp,
            previously_occupied_tcp,
            previously_occupied_udp,
        ));
    }

    let mut server = ChildGuard::spawn_signallable(
        "ferrum2-server",
        &server_config,
        "tagged server signal shutdown",
    );
    for address in servers {
        wait_for_tcp_udp_bound(&mut server, address);
    }
    server.request_graceful_shutdown();
    let exit = server.wait_for_exit(Duration::from_secs(5));
    assert_eq!(exit.status.code(), Some(0), "{exit}");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    for address in servers {
        wait_for_tcp_udp_bound(&mut server, address);
    }
    server.terminate_and_reap(Duration::from_secs(5));
    for address in servers {
        drop(bind_loopback_listener(address).expect("server restart TCP rebind"));
        drop(UdpSocket::bind(address).expect("server restart UDP rebind"));
    }

    let mut client = ChildGuard::spawn_signallable(
        "ferrum2-client",
        &client_config,
        "tagged client signal shutdown",
    );
    for address in clients {
        wait_for_listener(&mut client, address);
    }
    client.request_graceful_shutdown();
    let exit = client.wait_for_exit(Duration::from_secs(5));
    assert_eq!(exit.status.code(), Some(0), "{exit}");
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    for address in clients {
        wait_for_listener(&mut client, address);
    }
    client.terminate_and_reap(Duration::from_secs(5));
    for address in clients {
        drop(bind_loopback_listener(address).expect("client restart exact rebind"));
    }
}

#[test]
fn fixed_two_hop_tcp_chain_uses_distinct_credentials_and_reaps() {
    const ZERO_ACTIVE: &str =
        "ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"} 0";
    const ONE_ACTIVE: &str = "ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"} 1";
    const CLIENT_ACCEPTED: &str =
        "ferrum2_tcp_connections_total{role=\"client\",inbound=\"socks5\",outcome=\"accepted\"} 1";
    const SERVER_ACCEPTED: &str = "ferrum2_tcp_connections_total{role=\"server\",inbound=\"shadowsocks\",outcome=\"accepted\"} 1";
    const SERVER_AUTH_FAILED: &str = "ferrum2_tcp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"} 1";

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
        let directory = tempfile::tempdir().expect("two-hop TCP tempdir");
        let a_dir = directory.path().join("a");
        let b_dir = directory.path().join("b");
        std::fs::create_dir_all(&a_dir).expect("server directory");
        std::fs::create_dir_all(&b_dir).expect("server directory");
        let servers = [unused_loopback(), unused_loopback()];
        let client_address = unused_loopback();
        let metrics = [unused_loopback(), unused_loopback(), unused_loopback()];
        let (target, echo) = start_echo();
        let root = match index {
            0 => ChainRoot::Static,
            1 => ChainRoot::RouteRule {
                target,
                fallback_hop: 0,
            },
            2 => ChainRoot::RouteFinal,
            _ => ChainRoot::SelectorDefault,
        };
        let a_config = write_tcp_only_server_config(&a_dir, servers[0], Some(metrics[1]))
            .expect("server config");
        let b_config = write_tcp_only_server_config(&b_dir, servers[1], Some(metrics[2]))
            .expect("server config");
        rewrite_config_method(&a_config, inherited).expect("server method");
        rewrite_config_method(&b_config, explicit).expect("server method");
        let client_config = write_two_hop_client_config(
            directory.path(),
            client_address,
            servers,
            inherited,
            explicit,
            root,
            false,
            Some(metrics[0]),
        )
        .expect("client config");

        let mut server_a = ChildGuard::spawn("ferrum2-server", &a_config);
        wait_for_metrics(metrics[1]);
        wait_for_bound(&mut server_a, servers[0]);
        let mut server_b = ChildGuard::spawn("ferrum2-server", &b_config);
        wait_for_metrics(metrics[2]);
        wait_for_bound(&mut server_b, servers[1]);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_metrics(metrics[0]);
        wait_for_bound(&mut client, client_address);

        let (mut socks, reply) = socks_connect(client_address, target);
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let first = b"two-hop-tcp";
        let second = vec![0x5a; 16_385];
        socks.write_all(first).expect("first payload");
        socks.write_all(&second).expect("second payload");
        socks.shutdown(Shutdown::Write).expect("client half close");
        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("reverse drain");
        let mut expected = first.to_vec();
        expected.extend_from_slice(&second);
        assert_eq!(echoed, expected);
        assert_eq!(echo.join().expect("echo thread"), expected);
        drop(socks);

        let client_metrics = wait_for_metrics_sample(metrics[0], ZERO_ACTIVE);
        let a_metrics = wait_for_metrics_sample(metrics[1], SERVER_ACCEPTED);
        let b_metrics = wait_for_metrics_sample(metrics[2], SERVER_ACCEPTED);
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
        for address in [client_address, servers[0], servers[1], target]
            .into_iter()
            .chain(metrics)
        {
            drop(bind_loopback_listener(address).expect("two-hop TCP exact rebind"));
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
        let directory = tempfile::tempdir().expect("two-hop TCP failure tempdir");
        let a_dir = directory.path().join("a");
        let b_dir = directory.path().join("b");
        std::fs::create_dir_all(&a_dir).expect("server directory");
        std::fs::create_dir_all(&b_dir).expect("server directory");
        let servers = [unused_loopback(), unused_loopback()];
        let client_address = unused_loopback();
        let metrics = [unused_loopback(), unused_loopback(), unused_loopback()];
        let target = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("recording target");
        target.set_nonblocking(true).expect("nonblocking target");
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
            false,
            Some(metrics[0]),
        )
        .expect("client config");
        let a_psk = if matches!(failure, Failure::FirstWrong) {
            explicit.1
        } else {
            inherited.1
        };
        let a_config =
            write_tcp_only_server_config_with_psk(&a_dir, servers[0], Some(metrics[1]), a_psk)
                .expect("server config");
        rewrite_config_method(&a_config, (inherited.0, a_psk)).expect("server method");
        let mut server_a = ChildGuard::spawn("ferrum2-server", &a_config);
        let a_ready_metrics = wait_for_metrics(metrics[1]);
        wait_for_bound(&mut server_a, servers[0]);
        let mut server_a = Some(server_a);

        let b_psk = if matches!(failure, Failure::LaterWrong) {
            inherited.1
        } else {
            explicit.1
        };
        let b_config =
            write_tcp_only_server_config_with_psk(&b_dir, servers[1], Some(metrics[2]), b_psk)
                .expect("server config");
        rewrite_config_method(&b_config, (explicit.0, b_psk)).expect("server method");
        let mut server_b = ChildGuard::spawn("ferrum2-server", &b_config);
        let b_ready_metrics = wait_for_metrics(metrics[2]);
        wait_for_bound(&mut server_b, servers[1]);
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

        let (mut socks, reply) = socks_connect(client_address, target_address);
        if matches!(failure, Failure::FirstUnavailable) {
            assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        } else if reply[1] == 0 {
            socks.shutdown(Shutdown::Write).expect("failure half close");
            let mut byte = [0_u8; 1];
            assert!(matches!(socks.read(&mut byte), Ok(0) | Err(_)));
        }
        drop(socks);
        thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        let client_metrics = {
            let body = wait_for_metrics(metrics[0]);
            assert!(
                !body
                    .windows(ONE_ACTIVE.len())
                    .any(|part| part == ONE_ACTIVE.as_bytes())
            );
            if matches!(failure, Failure::FirstUnavailable) {
                assert!(
                    !body
                        .windows(CLIENT_ACCEPTED.len())
                        .any(|part| part == CLIENT_ACCEPTED.as_bytes())
                );
            }
            body
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
                    .windows(SERVER_ACCEPTED.len())
                    .any(|part| part == SERVER_ACCEPTED.as_bytes())
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
        for address in [client_address, servers[0], servers[1], target_address]
            .into_iter()
            .chain(metrics)
        {
            drop(bind_loopback_listener(address).expect("two-hop TCP failure exact rebind"));
        }
        assert_eq!(active_child_count(), baseline);
    }
}
