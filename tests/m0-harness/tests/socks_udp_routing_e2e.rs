#[path = "socks_udp_support/mod.rs"]
mod support;

use support::*;

#[test]
fn m14_client_udp_association_actions_route_once_and_reap() {
    const CLIENT_ZERO_SESSIONS: &str = "ferrum2_udp_sessions_active{role=\"client\"} 0";
    const CLIENT_ZERO_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"client\"} 0";
    const CLIENT_ACCEPTED: &str = "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"}";
    const CLIENT_ACCEPTED_ONE: &str = "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 1";
    const CLIENT_REJECTED_ONE: &str = "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1";
    const CLIENT_REJECTED_TWO: &str = "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 2";
    const SERVER_ZERO_SESSIONS: &str = "ferrum2_udp_sessions_active{role=\"server\"} 0";
    const SERVER_BUFFER: &str = "ferrum2_udp_buffered_bytes{role=\"server\"}";
    const SERVER_ACCEPTED: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"}";
    const SERVER_ACCEPTED_TWO: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"} 2";

    let _spawn_guard = local_support::hold_process_spawns_at_or_below(0);
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("M14 client UDP tempdir");
    let selected_tag = "m14-selected-egress-secret";
    let unselected_tag = "m14-unselected-egress-secret";
    let selector_tag = "m14-selector-secret";
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
             [[outbounds]]\ntag = \"{selected_tag}\"\ntype = \"shadowsocks\"\nserver = \"{selected_server}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [[outbounds]]\ntag = \"{unselected_tag}\"\ntype = \"shadowsocks\"\nserver = \"{unselected_server_address}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n\
             [[selectors]]\ntag = \"{selector_tag}\"\noutbounds = [\"{selected_tag}\", \"{unselected_tag}\"]\ndefault = \"{selected_tag}\"\n\
             [route]\nfinal = \"{unselected_tag}\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"{selector_tag}\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"{unselected_tag}\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nip = \"{}\"\nport = {}\naction = \"reject\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\naction = \"sniff\"\nsniffers = \"dns\"\n\
             [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\nprotocol = \"dns\"\naction = \"hijack-dns\"\n\
             [dns]\nmax_inflight = 4\n\
             [[dns.inbounds]]\ntag = \"dedicated\"\nlisten = \"{dns_listen}\"\n\
             [[dns.servers]]\ntag = \"dns\"\ntransport = \"udp\"\naddress = \"{dns_upstream_address}\"\n\
             [dns.route]\nfinal = \"dns\"\n\
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
    let checked = local_support::run_binary_while_holding(
        "ferrum2-client",
        &[
            "--config",
            client_config.to_str().expect("UTF-8 M14 UDP config"),
            "--check-config",
        ],
        &_spawn_guard,
    );
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
    let before_zero_port = wait_for_metrics_sample(client_metrics, CLIENT_REJECTED_ONE);
    for owner in [CLIENT_ZERO_SESSIONS, CLIENT_ZERO_BUFFER] {
        assert!(
            before_zero_port
                .windows(owner.len())
                .any(|window| window == owner.as_bytes())
        );
    }
    assert_eq!(
        metric_value(&before_zero_port, CLIENT_ACCEPTED).unwrap_or(0),
        0
    );
    let before_server = wait_for_metrics_sample(server_metrics, SERVER_ZERO_SESSIONS);
    let server_buffer_before = metric_value(&before_server, SERVER_BUFFER).expect("server buffer");
    let server_accepted_before = metric_value(&before_server, SERVER_ACCEPTED).unwrap_or(0);
    assert_eq!(server_accepted_before, 0);
    let zero_port = socks_datagram(
        SocketAddrV4::new(*route_first_address.ip(), 0),
        b"invalid-zero-port",
    );
    route_application
        .send_to(&zero_port, route_relay)
        .expect("zero-port first datagram");
    assert_no_datagram(&route_application);
    let after_zero_port = wait_for_metrics_sample(client_metrics, CLIENT_REJECTED_TWO);
    for owner in [CLIENT_ZERO_SESSIONS, CLIENT_ZERO_BUFFER] {
        assert!(
            after_zero_port
                .windows(owner.len())
                .any(|window| window == owner.as_bytes())
        );
    }
    let after_server = wait_for_metrics(server_metrics);
    assert!(
        after_server
            .windows(SERVER_ZERO_SESSIONS.len())
            .any(|window| window == SERVER_ZERO_SESSIONS.as_bytes())
    );
    assert_eq!(
        metric_value(&after_server, SERVER_BUFFER),
        Some(server_buffer_before),
        "zero-port datagram changed server buffer ownership"
    );
    assert_eq!(
        metric_value(&after_server, SERVER_ACCEPTED).unwrap_or(0),
        server_accepted_before,
        "zero-port datagram reached the server upstream"
    );
    assert_eq!(
        metric_value(&after_zero_port, CLIENT_ACCEPTED).unwrap_or(0),
        0
    );
    round_trip(
        &route_application,
        route_relay,
        &target_wire(SocketAddr::V4(route_first_address)),
        &target_wire(SocketAddr::V4(route_first_address)),
        b"first-route",
    );
    let after_first_route = wait_for_metrics_sample(client_metrics, CLIENT_ACCEPTED_ONE);
    assert_eq!(metric_value(&after_first_route, CLIENT_ACCEPTED), Some(1));
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
        selected_tag,
        unselected_tag,
        selector_tag,
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
            selected_tag,
            unselected_tag,
            selector_tag,
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
            "ferrum2_udp_buffered_bytes{role=\"client\"} 65507",
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
