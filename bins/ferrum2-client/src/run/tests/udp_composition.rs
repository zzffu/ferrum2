use super::*;

#[test]
fn dns_only_udp_budget_holds_multi_hop_fixed_wires_and_responses() {
    const MAX_INFLIGHT: usize = 16;

    let limit = dns_only_udp_buffered_bytes(MAX_INFLIGHT).expect("bounded DNS UDP budget");
    assert_eq!(limit, 3 * MAX_INFLIGHT * MAX_UDP_WIRE_LEN);
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(MAX_INFLIGHT, limit, MIN_UDP_IDLE_TIMEOUT).expect("DNS UDP limits"),
        OwnerRegistry::new(),
    );
    let budget = manager.buffer_budget();
    let fixed_wires = (0..2 * MAX_INFLIGHT)
        .map(|_| {
            budget
                .reserve(MAX_UDP_WIRE_LEN)
                .expect("persistent association wire")
        })
        .collect::<Vec<_>>();
    let sessions = (0..MAX_INFLIGHT)
        .map(|_| {
            manager
                .reserve_session(tokio::time::Instant::now())
                .expect("DNS UDP session")
        })
        .collect::<Vec<_>>();
    let responses = sessions
        .iter()
        .map(|session| {
            session
                .reserve_datagram(ferrum2_runtime::UdpDirection::ToClient, MAX_UDP_WIRE_LEN)
                .expect("simultaneous DNS UDP response")
        })
        .collect::<Vec<_>>();

    assert_eq!(budget.reserved_bytes(), limit);
    assert!(budget.reserve(1).is_err(), "modeled peak is exact");

    drop(responses);
    drop(sessions);
    drop(fixed_wires);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn dns_only_udp_budget_rejects_arithmetic_overflow_and_runtime_limit_overflow() {
    assert_eq!(
        dns_only_udp_buffered_bytes(usize::MAX),
        Err(RunError::StartupProtocol)
    );
    let first_over_limit = MAX_UDP_MAX_BUFFERED_BYTES / (3 * MAX_UDP_WIRE_LEN) + 1;
    assert_eq!(
        dns_only_udp_buffered_bytes(first_over_limit),
        Err(RunError::StartupProtocol)
    );
}

#[tokio::test]
async fn tagged_udp_uses_static_outbounds_and_no_fallback() {
    let listens = [reserve_address(), reserve_address()];
    let upstreams = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream A"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream B"),
    ];
    let servers: [SocketAddrV4; 2] = std::array::from_fn(|index| {
        match upstreams[index].local_addr().expect("upstream address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        }
    });
    let (path, mut config) =
        tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], true);
    config.udp.as_mut().expect("UDP config").max_sessions = 2;
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in listens {
        wait_until_bound(listen).await;
    }
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let mut owners = Vec::new();
    let mut relays = Vec::new();
    for index in 0..2 {
        let (control, application, relay) = udp_association(listens[index]).await;
        let length =
            encode_udp_datagram(&target, &[index as u8], &mut request).expect("SOCKS UDP request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("application send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        tokio::time::timeout(Duration::from_secs(1), upstreams[index].recv(&mut wire))
            .await
            .expect("mapped upstream timeout")
            .expect("mapped upstream request");
        owners.push((control, application));
        relays.push(relay);
    }
    stop.send(()).expect("stop mapped UDP client");
    assert_eq!(task.await.expect("mapped UDP client"), Ok(()));
    drop(owners);
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("mapped relay rebind"));
    }
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let dead = reserve_address();
    let dead_listens = [reserve_address(), reserve_address()];
    let (dead_path, config) = tagged_client_test_config(
        &[(dead_listens[0], servers[0]), (dead_listens[1], dead)],
        true,
    );
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in dead_listens {
        wait_until_bound(listen).await;
    }
    let (control, application, relay) = udp_association(dead_listens[1]).await;
    let length =
        encode_udp_datagram(&target, b"no-fallback", &mut request).expect("no-fallback request");
    application
        .send_to(&request[..length], relay)
        .await
        .expect("no-fallback send");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[0].recv(&mut wire))
            .await
            .is_err(),
        "dead UDP outbound fell back to live sibling"
    );
    stop.send(()).expect("stop no-fallback UDP client");
    assert_eq!(task.await.expect("no-fallback UDP client"), Ok(()));
    drop((control, application));
    drop(
        UdpSocket::bind(relay)
            .await
            .expect("no-fallback relay rebind"),
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove mapped UDP config");
    std::fs::remove_file(dead_path).expect("remove no-fallback UDP config");
}

#[tokio::test]
async fn tagged_udp_shares_byte_budget_across_listeners() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream");
    let SocketAddr::V4(server) = upstream.local_addr().expect("upstream address") else {
        unreachable!("IPv4 upstream")
    };
    let (path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    let udp = config.udp.as_mut().expect("UDP config");
    udp.max_sessions = 32;
    udp.max_buffered_bytes = 1024 * 1024;
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut controls = Vec::new();
    let mut applications = Vec::new();
    let mut relays = Vec::new();
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let request_len = encode_udp_datagram(&target, b"activate", &mut request).expect("request");
    let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
    for _ in 0..16 {
        let (control, application, relay) = udp_association(listens[0]).await;
        application
            .send_to(&request[..request_len], relay)
            .await
            .expect("activate association");
        tokio::time::timeout(Duration::from_secs(1), upstream.recv(&mut upstream_wire))
            .await
            .expect("activation timeout")
            .expect("activation request");
        controls.push(control);
        applications.push(application);
        relays.push(relay);
    }
    let saturated = registry.snapshot();
    assert_eq!(saturated.udp_sessions, baseline.udp_sessions + 16);
    assert_eq!(
        saturated.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 16 * MAX_UDP_WIRE_LEN
    );
    let (mut rejected, rejected_application, rejected_relay) = udp_association(listens[1]).await;
    rejected_application
        .send_to(&request[..request_len], rejected_relay)
        .await
        .expect("rejected activation attempt");
    let mut eof = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut eof))
            .await
            .expect("rejected control timeout")
            .expect("rejected control EOF"),
        0
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            upstream.recv(&mut upstream_wire)
        )
        .await
        .is_err(),
        "rejected association reached upstream"
    );
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 16);

    drop(controls.remove(0));
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let released = registry.snapshot();
        if released.udp_sessions == baseline.udp_sessions + 15
            && released.udp_buffered_bytes == baseline.udp_buffered_bytes + 15 * MAX_UDP_WIRE_LEN
        {
            break;
        }
        assert!(Instant::now() < deadline, "UDP byte owner did not release");
        tokio::task::yield_now().await;
    }
    let (control, application, relay) = udp_association(listens[1]).await;
    application
        .send_to(&request[..request_len], relay)
        .await
        .expect("replacement activation");
    tokio::time::timeout(Duration::from_secs(1), upstream.recv(&mut upstream_wire))
        .await
        .expect("replacement timeout")
        .expect("replacement request");
    controls.push(control);
    applications.push(application);
    relays.push(relay);

    stop.send(()).expect("stop byte-budget client");
    assert_eq!(task.await.expect("byte-budget client"), Ok(()));
    drop((controls, applications, rejected, rejected_application));
    relays.push(rejected_relay);
    for relay in relays {
        drop(
            UdpSocket::bind(relay)
                .await
                .expect("byte-budget relay rebind"),
        );
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(path).expect("remove byte-budget config");
}

#[tokio::test]
async fn tagged_udp_shares_live_id_collisions_across_listeners() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream");
    let SocketAddr::V4(server) = upstream.local_addr().expect("upstream address") else {
        unreachable!("IPv4 upstream")
    };
    let (path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.udp.as_mut().expect("UDP config").max_sessions = 3;
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let draws = [1]
        .into_iter()
        .chain(std::iter::repeat_n(1, 7))
        .chain([2])
        .chain(std::iter::repeat_n(1, 8));
    let (stop, task) =
        spawn_test_client_with_random(config, &registry, Arc::new(IdSequenceRandom::new(draws)));
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut socks = [0; 64];
    let length = encode_udp_datagram(&target, b"activate", &mut socks).expect("request");
    let first = udp_association(listens[0]).await;
    first
        .1
        .send_to(&socks[..length], first.2)
        .await
        .expect("first activation");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    upstream.recv(&mut wire).await.expect("first upstream");
    let second = udp_association(listens[1]).await;
    second
        .1
        .send_to(&socks[..length], second.2)
        .await
        .expect("second activation");
    upstream.recv(&mut wire).await.expect("second upstream");
    let activated = registry.snapshot();
    let third = udp_association(listens[1]).await;
    assert_eq!(
        registry.snapshot().udp_sessions,
        activated.udp_sessions,
        "association setup does not activate a session"
    );
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        activated.udp_buffered_bytes,
        "association setup does not allocate datagram buffers"
    );
    third
        .1
        .send_to(&socks[..length], third.2)
        .await
        .expect("third activation attempt");
    let mut rejected = third.0;
    let mut eof = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut eof))
            .await
            .expect("rejected control timeout")
            .expect("rejected control EOF"),
        0
    );
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.recv(&mut wire))
            .await
            .is_err(),
        "failed third activation reached the upstream"
    );

    stop.send(()).expect("stop live-ID client");
    assert_eq!(task.await.expect("live-ID client"), Ok(()));
    let relays = [first.2, second.2, third.2];
    drop((first, second, rejected, third.1));
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("live-ID relay rebind"));
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(path).expect("remove live-ID config");
}

#[tokio::test]
async fn tagged_prepare_failures_restore_full_baseline_and_exact_rebind() {
    for blocked in 0..3 {
        let listens = [reserve_address(), reserve_address(), reserve_address()];
        let metrics = reserve_address();
        let (path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, reserve_address())), false);
        config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
        let address = if blocked < 2 {
            listens[blocked]
        } else {
            metrics
        };
        let incumbent = std::net::TcpListener::bind(address).expect("occupy prepare position");
        let registry = OwnerRegistry::new();
        assert_eq!(
            run_with_registry(config, registry.clone(), std::future::pending()).await,
            Err(RunError::StartupBind)
        );
        drop(incumbent);
        for address in listens.into_iter().chain([metrics]) {
            drop(std::net::TcpListener::bind(address).expect("exact rollback rebind"));
        }
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove prepare config");
    }
}

#[test]
fn client_udp_route_publishes_program_and_match_observations() {
    use super::routing::ClientTerminalRoute;

    let listen = reserve_address();
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-udp-route-metrics-{}-{}.toml",
        std::process::id(),
        listen.port()
    ));
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"{listen}\"\n\
         [[outbounds]]\n\
         tag = \"direct\"\n\
         type = \"direct\"\n\
         [route]\n\
         final = \"direct\"\n\
         [[route.rules]]\n\
         network = \"udp\"\n\
         port = 53\n\
         action = \"reject\"\n"
    );
    std::fs::write(&path, source).expect("UDP route metrics config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare UDP route metrics config");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish UDP route metrics config");
    std::fs::remove_file(path).expect("remove UDP route metrics config");
    let metrics = Metrics::new();
    publish_rule_program_metadata(&config, &metrics);
    let selector = config.selector_control();
    let routing = ClientRouting {
        program: config.route,
        outbounds: Arc::from([]),
        selector,
    };
    let target = TargetAddr::ip("192.0.2.1:53".parse().expect("UDP route target"))
        .expect("validated UDP route target");
    let mut scratch = routing.route_scratch().expect("route scratch construction");
    let terminal = routing.select_terminal_with_scratch(
        0,
        ferrum2_core::route::Network::Udp,
        &target,
        Some(b"payload"),
        &metrics,
        &mut scratch,
    );
    assert!(matches!(terminal, Ok(ClientTerminalRoute::Reject)));
    let encoded = metrics.encode_text().expect("client UDP route metrics");
    for expected in [
        "ferrum2_rule_program_rules{program=\"route\"} 1",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }
}
