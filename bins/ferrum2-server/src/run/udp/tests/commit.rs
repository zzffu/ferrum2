use super::*;

#[tokio::test]
async fn concurrent_same_session_rolls_back_losing_socket_before_protocol_commit() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, mut config) = server_test_config(listen);
    config.udp.max_sessions = 2;
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
        b"one accepted datagram",
    );
    let first_listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            wire.clone(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_103)),
        ))),
    });
    let second_listener = Arc::new(AdmissionUdpListener {
        request: Mutex::new(Some((
            wire,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_104)),
        ))),
    });
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("two provisional limits"),
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
        mappings: Arc::clone(&mappings),
        admission: Arc::new(tokio::sync::Mutex::new(())),
        connect_timeout: config.runtime.connect_timeout,
        direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
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
    socket_factory.open_gate.add_permits(2);
    let mut received = [0_u8; 64];
    let (length, _) = recv_udp(&target, &mut received).await;
    assert_eq!(&received[..length], b"one accepted datagram");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if metrics.encode_text().expect("duplicate metrics").contains(
                "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"} 1",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("losing duplicate commit deadline");
    assert_pending(target.recv_from(&mut received), "duplicate target forward").await;
    assert_eq!(protocol.session_count().expect("protocol count"), 1);
    assert_eq!(
        (
            registry.snapshot().udp_sessions,
            registry.snapshot().udp_sockets,
            registry.snapshot().udp_tasks,
        ),
        (1, 1, 1),
        "the losing provisional generation and socket are fully rolled back"
    );
    {
        let state = mappings.state.lock().expect("winning mapping");
        assert_eq!((state.by_capability.len(), state.by_handle.len()), (1, 1));
        assert_eq!(
            state
                .by_capability
                .values()
                .next()
                .map(|binding| binding.terminal),
            Some(ServerTerminalRoute::Direct(0))
        );
    }

    stop_first.send(()).expect("stop first root");
    stop_second.send(()).expect("stop second root");
    assert_eq!(first_task.await.expect("first root task"), Ok(()));
    assert_eq!(second_task.await.expect("second root task"), Ok(()));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove same-session config");
}

#[tokio::test]
async fn udp_composition_three_methods_echo_and_deferred_client_commit_table() {
    let rows: [(MethodProfile, &str, &str, &[u8]); 3] = [
        (
            MethodProfile::Blake3Aes128Gcm2022,
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
            &PSK_BYTES,
        ),
        (
            MethodProfile::Blake3Aes256Gcm2022,
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            "2022-blake3-chacha20-poly1305",
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            &[
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ],
        ),
    ];
    for (profile, method, encoded_psk, psk) in rows {
        let listen = reserve_address();
        let echo = udp_loopback().await;
        let echo_target = echo.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            for _ in 0..3 {
                let (length, peer) = echo.recv_from(&mut buffer).await.expect("echo receive");
                echo.send_to(&buffer[..length], peer)
                    .await
                    .expect("echo reply");
            }
        });
        let (path, config) = server_test_config_for_method(listen, method, encoded_psk);
        let registry = OwnerRegistry::new();
        let (stop, mut server) = spawn_test_server(config, &registry);
        wait_until_bound(&mut server, listen).await;

        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, psk).expect("method key"),
        ));
        let clock = SystemClock::new();
        let mut client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
        let socket = udp_loopback().await;
        let mut response_scratch = UdpPacketScratch::new();
        let mut response_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        let client_registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), client_registry.clone());
        let mut handle = None;

        for (index, payload) in [b"one".as_slice(), b"two", b"three"]
            .into_iter()
            .enumerate()
        {
            let target = if profile == MethodProfile::Blake3Aes128Gcm2022 && index == 2 {
                TargetAddr::domain("127.0.0.1", echo_target.port()).expect("numeric domain target")
            } else {
                TargetAddr::ip(echo_target).expect("echo target")
            };
            let request_wire = encoded_udp_request(&mut client, &clock, target, payload);
            socket
                .send_to(&request_wire, listen)
                .await
                .expect("send request");
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response_wire))
                    .await
                    .expect("response deadline")
                    .expect("receive response");
            assert_eq!(source, SocketAddr::V4(listen));
            let pending = client
                .prepare_response(&clock, &response_wire[..length], &mut response_scratch)
                .expect("prepare response");
            let capacity = pending.datagram().allocated_capacity();
            let (datagram, commit) = pending.into_parts();
            let now = tokio::time::Instant::now();
            let accepted_handle = match handle {
                Some(handle) => {
                    manager
                        .reserve_datagram(handle, UdpDirection::ToClient, capacity)
                        .expect("response capacity")
                        .commit_with(datagram, now, || {
                            // The local client composition owns this call;
                            // it mirrors the same deferred T03 transition.
                            client.commit_response(commit, clock.monotonic_now())
                        })
                        .expect("deferred response commit");
                    handle
                }
                None => {
                    let session = manager.reserve_session(now).expect("client session");
                    let reserved = session
                        .reserve_datagram(UdpDirection::ToClient, capacity)
                        .expect("first response capacity");
                    session
                        .commit_with(reserved, datagram, now, || {
                            // The first client association is also deferred
                            // until session/bytes/queue capacity is reserved.
                            client.commit_response(commit, clock.monotonic_now())
                        })
                        .expect("deferred first response commit")
                }
            };
            handle = Some(accepted_handle);
            let accepted = manager
                .pop(accepted_handle, UdpDirection::ToClient)
                .expect("response queue")
                .expect("accepted response");
            assert_eq!(accepted.datagram().payload(), payload);
            assert_eq!(
                accepted.datagram().target(),
                &TargetAddr::ip(echo_target).expect("observed source target")
            );
        }

        echo_task.await.expect("echo task");
        stop.send(()).expect("stop server");
        assert_eq!(server.await.expect("server task"), Ok(()), "{method}");
        manager.cancel_all();
        assert_eq!(client_registry.snapshot().udp_sessions, 0);
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove UDP config");
    }
}
