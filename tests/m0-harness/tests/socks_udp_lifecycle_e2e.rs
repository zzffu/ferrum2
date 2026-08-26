#[path = "socks_udp_support/mod.rs"]
mod support;

use support::*;

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
