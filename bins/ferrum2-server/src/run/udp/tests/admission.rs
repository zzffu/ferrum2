use super::*;

#[test]
fn listener_fixed_capacity_is_validated_before_any_root_is_prepared() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, mut config) = server_test_config(listen);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();

    config.udp.receive_workers = ferrum2_config::MAX_UDP_RECEIVE_WORKERS;
    assert_eq!(
        validate_udp_listener_budget(&config.udp, 1),
        Err(crate::run::RunError::StartupProtocol)
    );
    assert_eq!(registry.snapshot(), baseline);

    config.udp.max_buffered_bytes = MAX_UDP_MAX_BUFFERED_BYTES;
    assert_eq!(validate_udp_listener_budget(&config.udp, 2), Ok(()));
    assert_eq!(registry.snapshot(), baseline);
    std::fs::remove_file(path).expect("remove listener budget config");
}

#[tokio::test]
async fn slow_socket_opens_for_distinct_sessions_run_concurrently() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, mut config) = server_test_config(listen);
    config.udp.max_sessions = 2;
    let target = udp_loopback().await;
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("numeric target");
    let keys = aes_keys();
    let clock = Arc::new(SystemClock::new());
    let mut first_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
    let mut second_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let first_wire = encoded_udp_request(
        &mut first_client,
        clock.as_ref(),
        target_address.clone(),
        b"first admission",
    );
    let second_wire = encoded_udp_request(
        &mut second_client,
        clock.as_ref(),
        target_address,
        b"second admission",
    );
    let first_listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            first_wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_101)),
        ))),
    });
    let second_listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            second_wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_102)),
        ))),
    });
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("two-session limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
    let metrics = Arc::new(Metrics::new());
    let shared = ServerUdpShared {
        routing: Arc::new(ServerRouting {
            program: config.route,
            outbound_count: config.outbounds.len(),
        }),
        protocol: Arc::clone(&protocol),
        clock,
        config: config.udp,
        sessions,
        mappings,
        admission: Arc::new(tokio::sync::Mutex::new(())),
        connect_timeout: config.runtime.connect_timeout,
        direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
        registry: registry.clone(),
        metrics,
    };
    let socket_factory = gated_socket_factory();
    let first = prepare_udp_server_with_socket_factory(
        0,
        first_listener,
        shared.clone(),
        socket_factory.clone(),
    )
    .expect("first prepared root");
    let second =
        prepare_udp_server_with_socket_factory(0, second_listener, shared, socket_factory.clone())
            .expect("second prepared root");
    let (stop_first, stopped_first) = tokio::sync::oneshot::channel::<()>();
    let (stop_second, stopped_second) = tokio::sync::oneshot::channel::<()>();
    let first_task = tokio::spawn(first.run_with_shutdown(
        async move {
            let _ = stopped_first.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));
    let second_task = tokio::spawn(second.run_with_shutdown(
        async move {
            let _ = stopped_second.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    wait_for_send_entries(&socket_factory.entered, &socket_factory.entry_changed, 2).await;
    assert_eq!(
        registry.snapshot().udp_sessions,
        2,
        "both provisional sessions coexist while both socket opens are stalled"
    );
    socket_factory.open_gate.add_permits(2);

    let mut received = [0_u8; 64];
    let (first_len, _) = recv_udp(&target, &mut received).await;
    let first_payload = received[..first_len].to_vec();
    let (second_len, _) = recv_udp(&target, &mut received).await;
    let second_payload = received[..second_len].to_vec();
    let mut payloads = [first_payload, second_payload];
    payloads.sort();
    assert_eq!(
        payloads,
        [b"first admission".to_vec(), b"second admission".to_vec()]
    );
    assert_eq!(protocol.session_count().expect("protocol count"), 2);
    assert_eq!(registry.snapshot().udp_sockets, 2);

    stop_first.send(()).expect("stop first root");
    stop_second.send(()).expect("stop second root");
    assert_eq!(first_task.await.expect("first root task"), Ok(()));
    assert_eq!(second_task.await.expect("second root task"), Ok(()));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove admission config");
}

#[tokio::test]
async fn shutdown_cancels_stalled_socket_open_and_rolls_back_provisional_session() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, config) = server_test_config(listen);
    let target = udp_loopback().await;
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("numeric target");
    let keys = aes_keys();
    let clock = Arc::new(SystemClock::new());
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let wire = encoded_udp_request(
        &mut client,
        clock.as_ref(),
        target_address,
        b"cancel stalled open",
    );
    let listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_105)),
        ))),
    });
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("single-session limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
    let socket_factory = gated_socket_factory();
    let prepared = prepare_udp_server_with_socket_factory(
        0,
        listener,
        ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol: Arc::clone(&protocol),
            clock,
            config: config.udp,
            sessions,
            mappings: Arc::clone(&mappings),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::new(Metrics::new()),
        },
        socket_factory.clone(),
    )
    .expect("prepared root");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    wait_for_send_entries(&socket_factory.entered, &socket_factory.entry_changed, 1).await;
    assert_eq!(registry.snapshot().udp_sessions, 1);
    stop.send(()).expect("stop stalled root");
    assert_eq!(task.await.expect("stalled root task"), Ok(()));
    assert_eq!(protocol.session_count().expect("protocol count"), 0);
    {
        let state = mappings.state.lock().expect("empty mappings");
        assert!(state.by_capability.is_empty());
    }
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove cancellation config");
}

#[tokio::test]
async fn post_open_session_limit_race_rolls_back_provisional_resources() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, mut config) = server_test_config(listen);
    config.udp.max_sessions = 1;
    let target = udp_loopback().await;
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("numeric target");
    let keys = aes_keys();
    let clock = Arc::new(SystemClock::new());
    let mut direct_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("direct client");
    let direct_wire = encoded_udp_request(
        &mut direct_client,
        clock.as_ref(),
        target_address.clone(),
        b"losing direct request",
    );
    let mut ceiling_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("ceiling client");
    let ceiling_wire = encoded_udp_request(
        &mut ceiling_client,
        clock.as_ref(),
        target_address,
        b"protocol ceiling owner",
    );
    let listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            direct_wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_106)),
        ))),
    });
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("single-session limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
    let admission = Arc::new(tokio::sync::Mutex::new(()));
    let metrics = Arc::new(Metrics::new());
    let socket_factory = gated_socket_factory();
    let prepared = prepare_udp_server_with_socket_factory(
        0,
        listener,
        ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol: Arc::clone(&protocol),
            clock: Arc::clone(&clock),
            config: config.udp,
            sessions,
            mappings: Arc::clone(&mappings),
            admission: Arc::clone(&admission),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        },
        socket_factory.clone(),
    )
    .expect("prepared root");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    wait_for_send_entries(&socket_factory.entered, &socket_factory.entry_changed, 1).await;
    {
        let _guard = admission.lock().await;
        let mut scratch = UdpPacketScratch::new();
        let pending = protocol
            .prepare_request(clock.as_ref(), &ceiling_wire, &mut scratch)
            .expect("prepare ceiling request");
        let (_datagram, commit) = pending.into_parts();
        let accepted = protocol
            .commit_request(
                commit,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_107)),
                clock.monotonic_now(),
                &SystemRandom,
            )
            .expect("commit ceiling owner");
        mappings.publish_rejected(accepted.capability(), 0);
    }
    socket_factory.open_gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if metrics.encode_text().expect("limit metrics").contains(
                "ferrum2_udp_failures_total{role=\"server\",stage=\"relay\",reason=\"session_limit\"} 1",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("post-open limit deadline");
    assert_eq!(protocol.session_count().expect("protocol count"), 1);
    assert_eq!(
        (
            registry.snapshot().udp_sessions,
            registry.snapshot().udp_sockets,
            registry.snapshot().udp_tasks,
        ),
        (0, 0, 0),
        "the losing admission leaves no runtime generation or socket"
    );
    let mut received = [0_u8; 64];
    assert_pending(target.recv_from(&mut received), "post-limit direct forward").await;

    stop.send(()).expect("stop limit root");
    assert_eq!(task.await.expect("limit root task"), Ok(()));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove limit config");
}

#[tokio::test]
async fn replacement_generation_wins_while_socket_open_is_stalled() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, mut config) = server_test_config(listen);
    config.udp.max_sessions = 2;
    let target = udp_loopback().await;
    let target_socket = target.local_addr().expect("target address");
    let target_address = TargetAddr::ip(target_socket).expect("numeric target");
    let keys = aes_keys();
    let clock = Arc::new(SystemClock::new());
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("replacement limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let mut scratch = UdpPacketScratch::new();
    let (capability, stale_handle) = commit_lifecycle_generation(
        &mut client,
        &protocol,
        &sessions,
        &mappings,
        &clock,
        target_socket,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_108)),
        b"stale generation",
        clock.monotonic_now(),
        &mut scratch,
    );
    assert!(sessions.remove(stale_handle));
    let request_wire = encoded_udp_request(
        &mut client,
        clock.as_ref(),
        target_address.clone(),
        b"replacement request",
    );
    let replacement_seed_wire = encoded_udp_request(
        &mut client,
        clock.as_ref(),
        target_address,
        b"replacement seed",
    );
    let listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            request_wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_108)),
        ))),
    });
    let socket_factory = gated_socket_factory();
    let prepared = prepare_udp_server_with_socket_factory(
        0,
        listener,
        ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol: Arc::clone(&protocol),
            clock: Arc::clone(&clock),
            config: config.udp,
            sessions: sessions.clone(),
            mappings: Arc::clone(&mappings),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::new(Metrics::new()),
        },
        socket_factory.clone(),
    )
    .expect("prepared root");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    wait_for_send_entries(&socket_factory.entered, &socket_factory.entry_changed, 1).await;
    assert_eq!(mappings.handle(capability), None);
    let pending_seed = protocol
        .prepare_request(clock.as_ref(), &replacement_seed_wire, &mut scratch)
        .expect("prepare replacement seed");
    let now = tokio::time::Instant::now();
    let replacement_session = sessions.reserve_session(now).expect("replacement session");
    let replacement_datagram = replacement_session
        .reserve_datagram(
            UdpDirection::ToTarget,
            pending_seed.datagram().allocated_capacity(),
        )
        .expect("replacement seed reservation");
    let (seed, _unused_protocol_commit) = pending_seed.into_parts();
    let replacement_handle = replacement_session
        .commit(replacement_datagram, seed, now)
        .expect("replacement generation commit");
    drop(
        sessions
            .pop(replacement_handle, UdpDirection::ToTarget)
            .expect("replacement seed queue")
            .expect("replacement seed datagram"),
    );
    assert_eq!(
        mappings.publish(
            capability,
            replacement_handle,
            0,
            ServerTerminalRoute::Direct(0),
        ),
        None
    );
    socket_factory.open_gate.add_permits(1);

    let forwarded = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(datagram) = sessions
                .pop(replacement_handle, UdpDirection::ToTarget)
                .expect("replacement request queue")
            {
                break datagram;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement request deadline");
    assert_eq!(forwarded.datagram().payload(), b"replacement request");
    drop(forwarded);
    assert_eq!(
        mappings
            .handle(capability)
            .expect("replacement mapping")
            .handle,
        replacement_handle
    );
    assert_eq!(protocol.session_count().expect("protocol count"), 1);
    assert_eq!(
        (
            registry.snapshot().udp_sessions,
            registry.snapshot().udp_sockets,
            registry.snapshot().udp_tasks,
        ),
        (1, 0, 0),
        "the provisional socket loses to the replacement runtime generation"
    );

    stop.send(()).expect("stop replacement root");
    assert_eq!(task.await.expect("replacement root task"), Ok(()));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove replacement config");
}

#[tokio::test]
async fn udp_real_socket_session_saturation_never_reaches_second_target() {
    let listen = reserve_address();
    let (path, _config) = server_test_config(listen);
    let mut source = std::fs::read_to_string(&path).expect("server config");
    source.push_str(
        "[udp]\nmax_sessions = 1\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n",
    );
    std::fs::write(&path, source).expect("bounded UDP config");
    let prepared = ferrum2_config::prepare_server(&path).expect("prepare bounded server config");
    let config =
        ferrum2_config::finish_server_v2(prepared, ferrum2_config::ServerV2Resources::default())
            .expect("finish bounded server config");
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let stalled_target = udp_loopback().await;
    let stalled_address = stalled_target.local_addr().expect("stalled address");
    let forbidden_target = udp_loopback().await;
    let forbidden_address = forbidden_target.local_addr().expect("forbidden address");
    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut first = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
    let mut second = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let first_socket = udp_loopback().await;
    let second_socket = udp_loopback().await;
    let wire = encoded_udp_request(
        &mut first,
        &clock,
        TargetAddr::ip(stalled_address).expect("stalled target"),
        b"occupy",
    );
    first_socket
        .send_to(&wire, listen)
        .await
        .expect("first send");
    let mut target_buffer = [0_u8; 32];
    let (received, _) = recv_udp(&stalled_target, &mut target_buffer).await;
    assert_eq!(&target_buffer[..received], b"occupy");

    let wire = encoded_udp_request(
        &mut second,
        &clock,
        TargetAddr::ip(forbidden_address).expect("forbidden target"),
        b"must-not-send",
    );
    second_socket
        .send_to(&wire, listen)
        .await
        .expect("second send");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            forbidden_target.recv_from(&mut target_buffer)
        )
        .await
        .is_err(),
        "saturated session reached the second target"
    );

    stop.send(()).expect("stop server");
    assert_eq!(server.await.expect("server task"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove saturation config");
}
