use super::*;

#[tokio::test]
async fn direct_tun_udp_defers_adf_port_filtering_and_has_no_outstanding_send_gate() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
            .expect("test limits"),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let held_budget = exhaust_budget(&budget, budget_limit);
    assert_eq!(budget.reserved_bytes(), budget_limit);
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::direct(
            ferrum2_net::DialOptions::default(),
        )]
        .into(),
        TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager,
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        None,
    );
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("TUN target bind");
    let target_endpoint = target_socket.local_addr().expect("TUN target address");
    let target = TargetAddr::ip(target_endpoint).expect("TUN target");
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Tun,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&target),
        )
        .await
        .expect("direct TUN association");
    assert_eq!(budget.reserved_bytes(), budget_limit);
    association.activate(&engine).expect("direct activation");

    for sequence in 0..=UDP_SESSION_QUEUE_DEPTH {
        let payload = [u8::try_from(sequence).expect("bounded sequence")];
        let length = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target.clone(),
                &payload,
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("TUN direct request"));
        assert_eq!(association.send_encoded_request(length).await.unwrap(), 1);
        assert_eq!(budget.reserved_bytes(), budget_limit);
    }
    assert!(
        association.direct_peers.is_empty(),
        "TUN sends must not consume the SOCKS/DNS outstanding queue"
    );

    let mut wire = [0_u8; 8];
    let mut association_endpoint = None;
    let mut received_sequences = Vec::with_capacity(UDP_SESSION_QUEUE_DEPTH + 1);
    for _ in 0..=UDP_SESSION_QUEUE_DEPTH {
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(1), target_socket.recv_from(&mut wire))
                .await
                .expect("TUN target receive timeout")
                .expect("TUN target receive");
        assert_eq!(length, 1);
        received_sequences.push(wire[0]);
        match association_endpoint {
            Some(expected) => assert_eq!(peer, expected),
            None => association_endpoint = Some(peer),
        }
    }
    received_sequences.sort_unstable();
    assert_eq!(
        received_sequences,
        (0..=UDP_SESSION_QUEUE_DEPTH)
            .map(|sequence| u8::try_from(sequence).expect("bounded sequence"))
            .collect::<Vec<_>>()
    );
    let association_endpoint = association_endpoint.expect("direct association endpoint");

    for payload in [b"alternate-one".as_slice(), b"alternate-two".as_slice()] {
        let alternate = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("alternate source bind");
        let alternate_endpoint = alternate.local_addr().expect("alternate source address");
        assert_ne!(alternate_endpoint.port(), target_endpoint.port());
        alternate
            .send_to(payload, association_endpoint)
            .await
            .expect("alternate source send");

        let length =
            tokio::time::timeout(Duration::from_secs(1), association.receive_response_wire())
                .await
                .expect("same-family alternate-port response timeout")
                .expect("same-family alternate-port response");
        let response = association
            .prepare_application_response(&engine, &engine.outbounds, length)
            .unwrap_or_else(|_| panic!("TUN direct response"));
        assert_eq!(
            response.datagram().target(),
            &TargetAddr::ip(alternate_endpoint).expect("alternate target")
        );
        assert_eq!(response.datagram().payload(), payload);
        assert_eq!(budget.reserved_bytes(), budget_limit);
        association.recycle_application_response(response);
        assert_eq!(budget.reserved_bytes(), budget_limit);
    }

    drop(association);
    assert_eq!(budget.reserved_bytes(), budget_limit);
    drop(held_budget);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn one_proxy_tun_udp_association_serves_multiple_targets_without_global_budget() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
            .expect("test limits"),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let held_budget = exhaust_budget(&budget, budget_limit);
    let proxy_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("proxy bind");
    let proxy_endpoint = proxy_socket.local_addr().expect("proxy address");
    let outbounds = crate::run::egress::prepare_client_outbounds(vec![
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: proxy_endpoint,
            psk: Arc::new(default_test_psk()),
            dial_options: Default::default(),
        },
    ])
    .expect("proxy outbound");
    let engine = ClientEgressEngine::new(
        outbounds,
        TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager,
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        None,
    );
    let server_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
    let server = UdpServer::new(&server_keys).expect("proxy protocol");
    let server_clock = ferrum2_crypto::SystemClock::new();
    let server_random = ferrum2_crypto::SystemRandom;
    let targets = [
        TargetAddr::ip("192.0.2.25:53".parse().expect("first target address"))
            .expect("first target"),
        TargetAddr::ip("198.51.100.25:5353".parse().expect("second target address"))
            .expect("second target"),
    ];
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Tun,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&targets[0]),
        )
        .await
        .expect("proxy TUN association with exhausted budget");
    assert_eq!(budget.reserved_bytes(), budget_limit);
    association.activate(&engine).expect("proxy activation");

    let mut request_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let mut server_scratch = UdpPacketScratch::new();
    let mut response_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let mut association_peer = None;
    for (target, request_payload, expected_response) in [
        (
            &targets[0],
            b"first-request".as_slice(),
            b"first-response".as_slice(),
        ),
        (
            &targets[1],
            b"second-request".as_slice(),
            b"second-response".as_slice(),
        ),
    ] {
        let request_len = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target.clone(),
                request_payload,
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("proxy TUN request with exhausted budget"));
        assert_eq!(budget.reserved_bytes(), budget_limit);
        association
            .send_encoded_request(request_len)
            .await
            .expect("proxy request send");
        let (request_wire_len, peer) = proxy_socket
            .recv_from(&mut request_wire)
            .await
            .expect("proxy request receive");
        match association_peer {
            Some(expected) => assert_eq!(peer, expected, "one proxy socket serves all targets"),
            None => association_peer = Some(peer),
        }
        let pending = server
            .prepare_request(
                &server_clock,
                &request_wire[..request_wire_len],
                &mut server_scratch,
            )
            .expect("proxy request decode");
        let (request, commit) = pending.into_parts();
        assert_eq!(request.target(), target);
        assert_eq!(request.payload(), request_payload);
        let capability = server
            .commit_request(commit, peer, server_clock.monotonic_now(), &server_random)
            .expect("proxy request commit")
            .capability();

        let response_payload = BytesMut::from(expected_response);
        let response_capacity = response_payload.capacity();
        let response = Datagram::new(target.clone(), response_payload, response_capacity)
            .expect("proxy response datagram");
        let encoded = server
            .encode_response(
                capability,
                &server_clock,
                &server_random,
                &response,
                0,
                &mut response_wire,
            )
            .expect("proxy response encode");
        proxy_socket
            .send_to(&response_wire[..encoded.wire_len()], encoded.peer())
            .await
            .expect("proxy response send");
        let response_wire_len = association
            .receive_response_wire()
            .await
            .expect("proxy response receive");
        let response = association
            .prepare_application_response(&engine, &engine.outbounds, response_wire_len)
            .unwrap_or_else(|_| panic!("proxy TUN response with exhausted budget"));
        assert_eq!(response.datagram().target(), target);
        assert_eq!(response.datagram().payload(), expected_response);
        assert_eq!(budget.reserved_bytes(), budget_limit);
        association.recycle_application_response(response);
        assert_eq!(budget.reserved_bytes(), budget_limit);
    }

    drop(association);
    drop(held_budget);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn ordinary_udp_fixed_request_and_response_buffers_remain_globally_metered() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
            .expect("test limits"),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::direct(
            ferrum2_net::DialOptions::default(),
        )]
        .into(),
        TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager,
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        None,
    );
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("ordinary target bind");
    let target = TargetAddr::ip(echo.local_addr().expect("ordinary target address"))
        .expect("ordinary target");
    let direct_plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(direct_plan.clone()),
            Some(&target),
        )
        .await
        .expect("ordinary direct association");
    assert_eq!(
        budget.reserved_bytes(),
        MAX_UDP_WIRE_DATAGRAM_BYTES,
        "ordinary fixed buffer remains globally metered"
    );
    assert_eq!(
        association
            .direct_wire
            .as_ref()
            .expect("direct fixed wire")
            .capacity(),
        budget.reserved_bytes(),
        "fixed reservation exactly matches allocator capacity"
    );
    association.activate(&engine).expect("ordinary activation");
    let request_len = association
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            target.clone(),
            b"ordinary-request",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("ordinary request"));
    association
        .send_encoded_request(request_len)
        .await
        .expect("ordinary request send");
    let mut raw = [0_u8; 32];
    let (_, peer) = echo.recv_from(&mut raw).await.expect("ordinary receive");
    echo.send_to(b"ordinary-response", peer)
        .await
        .expect("ordinary response send");
    let held_budget = exhaust_budget(&budget, budget_limit);
    assert_eq!(budget.reserved_bytes(), budget_limit);
    let response_wire_len = association
        .receive_response_wire()
        .await
        .expect("ordinary response receive");
    assert!(
        association
            .direct_wire
            .as_ref()
            .expect("reservation failure retains reusable direct wire")
            .is_empty(),
        "reservation failure clears the received payload instead of preserving buffer contents"
    );
    for origin in [
        ClientRequestOrigin::Socks,
        ClientRequestOrigin::Dns,
        ClientRequestOrigin::RuleSet,
    ] {
        assert!(
            engine
                .prepare_udp_for_ingress(origin, 0, Some(direct_plan.clone()), Some(&target))
                .await
                .is_err(),
            "ordinary association fixed buffers bypassed the full budget for {origin:?}"
        );
        assert_eq!(budget.reserved_bytes(), budget_limit);
    }
    assert!(matches!(
        association.prepare_application_response(&engine, &engine.outbounds, response_wire_len,),
        Err(UdpPlanResponseError::Runtime(UdpRuntimeError::BufferLimit))
    ));
    assert!(matches!(
        association.prepare_application_request(
            &engine,
            &engine.outbounds,
            target,
            b"blocked-request",
            Instant::now(),
        ),
        Err(UdpPlanResponseError::Runtime(UdpRuntimeError::BufferLimit))
    ));
    assert_eq!(budget.reserved_bytes(), budget_limit);

    drop(held_budget);
    assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    drop(association);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test]
async fn direct_udp_socks_uses_raw_datagrams_and_no_sip022_state() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
    let live_ids = Arc::new(Mutex::new(HashSet::new()));
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::direct(
            ferrum2_net::DialOptions::default(),
        )]
        .into(),
        TokioConnector::new(ferrum2_runtime::TcpConnector::new(
            std::time::Duration::from_secs(1),
        )),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        ),
        Some(ClientUdpContext {
            manager,
            live_ids: Arc::clone(&live_ids),
        }),
        None,
    );
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("echo bind");
    let target = TargetAddr::ip(echo.local_addr().expect("echo address")).expect("target");
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&target),
        )
        .await
        .expect("direct association");
    let direct_scratch_identity = association
        .direct_wire
        .as_ref()
        .expect("direct receive scratch")
        .as_ptr();
    association.activate(&engine).expect("direct activation");
    let provisional = registry.snapshot();
    assert_eq!(
        provisional.udp_buffered_bytes,
        baseline.udp_buffered_bytes + MAX_UDP_WIRE_DATAGRAM_BYTES,
        "direct association owns only its request wire buffer"
    );
    assert_eq!(provisional.udp_queued_datagrams, 0);
    let maximum = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    assert_eq!(
        association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target.clone(),
                &maximum,
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("exact raw maximum")),
        MAX_UDP_WIRE_DATAGRAM_BYTES
    );
    assert!(matches!(
        association.prepare_application_request(
            &engine,
            &engine.outbounds,
            target.clone(),
            &vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES + 1],
            Instant::now(),
        ),
        Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds))
    ));
    assert_eq!(registry.snapshot(), provisional);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert!(live_ids.lock().expect("live IDs").is_empty());
    let wire_len = association
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            target,
            b"raw-udp",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("direct request"));
    assert_eq!(association.send_encoded_request(wire_len).await.unwrap(), 7);
    let mut raw = [0_u8; 32];
    let (length, peer) = echo.recv_from(&mut raw).await.expect("echo receive");
    assert_eq!(&raw[..length], b"raw-udp");
    let spoof = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("spoof bind");
    spoof.send_to(b"spoof", peer).await.expect("spoof response");
    echo.send_to(b"raw-reply", peer).await.expect("echo reply");
    let response_len = association
        .receive_response_wire()
        .await
        .expect("direct receive");
    assert!(
        association.direct_wire.is_none(),
        "successful receive transfers the original allocation into the pending response"
    );
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        provisional.udp_buffered_bytes + b"raw-reply".len(),
        "pending direct response reserves only its initialized length"
    );
    let response = association
        .prepare_application_response(&engine, &engine.outbounds, response_len)
        .unwrap_or_else(|_| panic!("direct response"));
    assert_eq!(
        response.datagram().target(),
        &TargetAddr::ip(echo.local_addr().unwrap()).unwrap()
    );
    assert_eq!(response.datagram().payload(), b"raw-reply");
    let response_owned = registry.snapshot();
    assert_eq!(response_owned.udp_queued_datagrams, 0);
    assert_eq!(
        response_owned.udp_buffered_bytes,
        provisional.udp_buffered_bytes + b"raw-reply".len(),
        "the direct response owns only its initialized prefix"
    );
    assert!(
        association.direct_wire.is_none(),
        "the accounted response retains the direct allocation until recycling"
    );
    association.recycle_application_response(response);
    assert_eq!(registry.snapshot(), provisional);
    let recycled = association
        .direct_wire
        .as_ref()
        .expect("recycled direct wire buffer");
    assert!(recycled.is_empty());
    assert_eq!(recycled.capacity(), MAX_UDP_WIRE_DATAGRAM_BYTES);
    assert_eq!(recycled.as_ptr(), direct_scratch_identity);

    let mismatch_target = TargetAddr::ip(echo.local_addr().unwrap()).unwrap();
    let mismatch_request_len = association
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            mismatch_target,
            b"mismatch-request",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("mismatch request"));
    association
        .send_encoded_request(mismatch_request_len)
        .await
        .expect("mismatch request send");
    let (_, peer) = echo
        .recv_from(&mut raw)
        .await
        .expect("mismatch request receive");
    echo.send_to(b"mismatch-response", peer)
        .await
        .expect("mismatch response send");
    let mismatch_response_len = association
        .receive_response_wire()
        .await
        .expect("mismatch response receive");
    assert!(association.direct_wire.is_none());
    assert!(matches!(
        association.prepare_application_response(
            &engine,
            &engine.outbounds,
            mismatch_response_len + 1,
        ),
        Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds))
    ));
    let restored_after_mismatch = association
        .direct_wire
        .as_ref()
        .expect("length mismatch restores the direct allocation");
    assert!(restored_after_mismatch.is_empty());
    assert_eq!(
        restored_after_mismatch.capacity(),
        MAX_UDP_WIRE_DATAGRAM_BYTES
    );
    assert_eq!(restored_after_mismatch.as_ptr(), direct_scratch_identity);
    assert_eq!(registry.snapshot(), provisional);
    assert!(live_ids.lock().expect("live IDs").is_empty());
    drop(association);
    assert_eq!(registry.snapshot(), baseline);

    for (case, plan) in [
        ("absent", None),
        (
            "explicit direct",
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
        ),
    ] {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS echo bind");
        let target = TargetAddr::ip(echo.local_addr().unwrap()).unwrap();
        let mut association = engine
            .prepare_udp_for_ingress(ClientRequestOrigin::Dns, 0, plan, Some(&target))
            .await
            .unwrap_or_else(|_| panic!("{case} direct association"));
        association.activate(&engine).unwrap();
        let length = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target,
                case.as_bytes(),
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("{case} request"));
        association.send_encoded_request(length).await.unwrap();
        let mut raw = [0_u8; 32];
        let (length, peer) = echo.recv_from(&mut raw).await.unwrap();
        assert_eq!(&raw[..length], case.as_bytes());
        echo.send_to(case.as_bytes(), peer).await.unwrap();
        let length = association.receive_response_wire().await.unwrap();
        let response = association
            .prepare_application_response(&engine, &engine.outbounds, length)
            .unwrap_or_else(|_| panic!("{case} response"));
        assert_eq!(response.datagram().payload(), case.as_bytes());
        association.recycle_application_response(response);
    }
    assert!(live_ids.lock().expect("live IDs").is_empty());

    if let Ok(echo) = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await {
        let echo_address = echo.local_addr().unwrap();
        let mut wire = [0_u8; 16];
        let ipv6_ready =
            if let Ok(probe) = UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).await {
                probe.send_to(b"probe", echo_address).await.is_ok()
                    && matches!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(200),
                            echo.recv_from(&mut wire),
                        )
                        .await,
                        Ok(Ok((5, _))) if &wire[..5] == b"probe"
                    )
            } else {
                false
            };
        if ipv6_ready {
            let target = TargetAddr::ip(echo_address).unwrap();
            let mut association = engine
                .prepare_udp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                    Some(&target),
                )
                .await
                .expect("SOCKS IPv6 direct association");
            association.activate(&engine).unwrap();
            let length = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target,
                    b"ipv6",
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("SOCKS IPv6 request"));
            association.send_encoded_request(length).await.unwrap();
            let (length, peer) =
                tokio::time::timeout(std::time::Duration::from_secs(2), echo.recv_from(&mut wire))
                    .await
                    .expect("SOCKS IPv6 raw receive timeout")
                    .unwrap();
            assert_eq!(&wire[..length], b"ipv6");
            echo.send_to(b"ipv6-reply", peer).await.unwrap();
            let length = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                association.receive_response_wire(),
            )
            .await
            .expect("SOCKS IPv6 response timeout")
            .unwrap();
            let response = association
                .prepare_application_response(&engine, &engine.outbounds, length)
                .unwrap_or_else(|_| panic!("SOCKS IPv6 response"));
            assert!(
                response
                    .datagram()
                    .target()
                    .as_socket_addr()
                    .unwrap()
                    .is_ipv6()
            );
            assert_eq!(response.datagram().payload(), b"ipv6-reply");
            association.recycle_application_response(response);
        }
    }

    let echo_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_a = TargetAddr::ip(echo_a.local_addr().unwrap()).unwrap();
    let target_b = TargetAddr::ip(echo_b.local_addr().unwrap()).unwrap();
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            None,
        )
        .await
        .unwrap();
    association.activate(&engine).unwrap();
    for (target, payload) in [
        (target_a.clone(), b"A".as_slice()),
        (target_b, b"B".as_slice()),
    ] {
        let length = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target,
                payload,
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("outstanding request"));
        association.send_encoded_request(length).await.unwrap();
    }
    let mut wire = [0_u8; 8];
    let (_, peer_a) = echo_a.recv_from(&mut wire).await.unwrap();
    let (_, peer_b) = echo_b.recv_from(&mut wire).await.unwrap();
    let spoof = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    spoof.send_to(b"spoof", peer_a).await.unwrap();
    echo_b.send_to(b"B", peer_b).await.unwrap();
    echo_a.send_to(b"A", peer_a).await.unwrap();
    for (expected_source, expected_payload) in [
        (echo_b.local_addr().unwrap(), b"B".as_slice()),
        (echo_a.local_addr().unwrap(), b"A".as_slice()),
    ] {
        let length = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            association.receive_response_wire(),
        )
        .await
        .unwrap_or_else(|_| panic!("out-of-order response"))
        .unwrap();
        let response = association
            .prepare_application_response(&engine, &engine.outbounds, length)
            .unwrap_or_else(|_| panic!("outstanding response"));
        assert_eq!(
            response.datagram().target(),
            &TargetAddr::ip(expected_source).unwrap()
        );
        assert_eq!(response.datagram().payload(), expected_payload);
        association.recycle_application_response(response);
    }

    for _ in 0..UDP_SESSION_QUEUE_DEPTH {
        let length = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target_a.clone(),
                b"queued",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("queued direct request"));
        association.send_encoded_request(length).await.unwrap();
    }
    assert_eq!(association.direct_peers.len(), UDP_SESSION_QUEUE_DEPTH);
    let length = association
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            target_a,
            b"overflow",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("depth+1 request encoding"));
    assert_eq!(
        association
            .send_encoded_request(length)
            .await
            .expect_err("depth+1 rejected before send")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(association.direct_peers.len(), UDP_SESSION_QUEUE_DEPTH);
    for _ in 0..UDP_SESSION_QUEUE_DEPTH {
        echo_a.recv_from(&mut wire).await.expect("queued datagram");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(200), echo_a.recv_from(&mut wire))
            .await
            .is_err(),
        "depth+1 never reaches the socket"
    );
    assert_eq!(registry.snapshot(), provisional);
    assert!(live_ids.lock().expect("live IDs").is_empty());
    drop(association);
    assert_eq!(registry.snapshot(), baseline);

    let domain = TargetAddr::domain("direct-candidates.invalid", 53).unwrap();
    for (name, candidate_count, succeed_at, expected_attempts, expected_ok) in [
        ("zero", 0, None, 0, false),
        ("one", 1, Some(1), 1, true),
        ("sixteen", 16, Some(16), 16, true),
        ("seventeen", 17, None, 16, false),
    ] {
        let candidates = (1..=candidate_count)
            .map(|octet| SocketAddr::from(([192, 0, 2, octet as u8], 53)))
            .collect::<Vec<_>>();
        let resolver = DirectTestResolver {
            candidates: Some(candidates.clone()),
            calls: AtomicUsize::new(0),
        };
        let socket = DirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            succeed_at,
        };
        let mut hints = DirectUdpCandidateHints::default();
        let result = send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &domain,
            b"candidate",
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result.is_ok(), expected_ok, "{name}");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1, "{name}");
        let attempts = socket.attempts.lock().expect("candidate attempts");
        assert_eq!(attempts.len(), expected_attempts, "{name}");
        assert_eq!(&attempts[..], &candidates[..expected_attempts], "{name}");
    }

    let resolver = DirectTestResolver {
        candidates: None,
        calls: AtomicUsize::new(0),
    };
    let socket = DirectTestSocket {
        attempts: Mutex::new(Vec::new()),
        succeed_at: Some(1),
    };
    let mut hints = DirectUdpCandidateHints::default();
    assert!(
        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &domain,
            b"resolver-error",
            Duration::from_secs(1),
        )
        .await
        .is_err()
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert!(
        socket
            .attempts
            .lock()
            .expect("resolver attempts")
            .is_empty()
    );
    assert_eq!(registry.snapshot(), baseline);
    assert_eq!(
        engine
            .udp
            .as_ref()
            .expect("UDP context")
            .manager
            .session_count(),
        0
    );
    assert!(live_ids.lock().expect("live IDs").is_empty());
}
