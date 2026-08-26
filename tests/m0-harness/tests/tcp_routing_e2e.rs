#[path = "local_e2e_support/mod.rs"]
mod support;

use support::*;

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
             [[outbounds]]\ntag = \"protected\"\ntype = \"shadowsocks\"\nserver = \"{protected_address}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [route]\nfinal = \"protected\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nport = 53\naction = \"hijack-dns\"\n\
             [dns]\nmax_inflight = 4\n\
             [[dns.inbounds]]\ntag = \"dedicated\"\nlisten = \"{dns_listen}\"\n\
             [[dns.servers]]\ntag = \"{selected_tag}\"\ntransport = \"udp\"\naddress = \"{}\"\n\
             [[dns.servers]]\ntag = \"{final_tag}\"\ntransport = \"udp\"\naddress = \"{}\"\n\
             [dns.route]\nfinal = \"{final_tag}\"\n\
             [[dns.route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nqname = \"{selected_name}\"\nqtype = \"A\"\naction = \"route\"\nserver = \"{selected_tag}\"\n\
             [udp]\nenabled = false\n\
             [metrics]\nlisten = \"{metrics_address}\"\n",
            dns_addresses[0], dns_addresses[1],
        ),
    )
    .expect("M14 client TCP hijack config");
    let checked = local_support::run_binary_while_holding(
        "ferrum2-client",
        &[
            "--config",
            client_config.to_str().expect("UTF-8 M14 client config"),
            "--check-config",
        ],
        &_spawn_guard,
    );
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
    let empty_name = "empty-sentinel.test.";
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
