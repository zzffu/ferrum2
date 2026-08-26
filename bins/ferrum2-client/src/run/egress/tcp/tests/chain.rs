use super::*;

#[tokio::test]
async fn tcp_chain_opens_hops_in_order_with_distinct_credentials_and_no_fallback() {
    for (case, (first_method, second_method)) in [
        (
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
        ),
        (
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            MethodProfile::Blake3Aes128Gcm2022,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (outbounds, route, selector) = tcp_chain_test_setup(
            [first_method, second_method, second_method, first_method],
            42_001 + case as u16 * 10,
        );
        let application = TargetAddr::ipv4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 1),
            443 + case as u16,
        ))
        .expect("application target");
        let snapshot = selected_plan(&route, 0, Network::Tcp, &application);
        assert_eq!(snapshot.hops(), &[0, 1], "rotation {case}");
        selector.switch("manual", "c-d").expect("switch next flow");
        assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
        let next_snapshot = selected_plan(&route, 0, Network::Tcp, &application);
        assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
        let clock = SystemClock::new();
        let random = FixedRandom;
        for (label, plan) in [("captured", &snapshot), ("next", &next_snapshot)] {
            let [first, second] = *plan.hops() else {
                panic!("two-hop {label} plan")
            };
            let aborts = Arc::new(AtomicUsize::new(0));
            let (stream, mut peer) = tokio::io::duplex(65_536);
            let engine = ClientEgressEngine::new(
                Arc::clone(&outbounds),
                DeadlineConnector {
                    delay: Duration::ZERO,
                    targets: Mutex::new(Vec::new()),
                    stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                        stream,
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                        Arc::clone(&aborts),
                    )))),
                },
                SystemClock::new(),
                FixedRandom,
                (Duration::from_secs(1), Duration::from_secs(1)),
                None,
                None,
            );
            let observer = ChainObserver::default();
            let flow = engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(plan.clone()),
                    &application,
                    None,
                    Some((&observer, &observer)),
                )
                .await
                .expect("selected chain");
            assert_eq!(
                engine
                    .connector
                    .targets
                    .lock()
                    .expect("dial targets")
                    .as_slice(),
                &[outbounds[first].shadowsocks().unwrap().tcp_server.clone()],
                "sole {label} raw dial: rotation {case}"
            );
            assert_two_layer_buffers(&observer, format_args!("{label}: rotation {case}"));
            drop(flow);
            assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
            let mut raw = Vec::new();
            peer.read_to_end(&mut raw).await.expect("complete raw wire");

            let outer_replay = TcpReplayStore::new(1024).expect("outer replay");
            let outer_inbound = ShadowsocksTcpInbound::new(
                &outbounds[first].shadowsocks().unwrap().keys,
                &clock,
                &random,
                &outer_replay,
            );
            let outer = outer_inbound
                .accept_stream(scripted_input(&raw).await)
                .await
                .expect("configured outer credential");
            assert_eq!(
                outer.target,
                outbounds[second].shadowsocks().unwrap().tcp_server,
                "{label} first targets second: rotation {case}"
            );
            assert!(outer.initial_payload.is_empty(), "{label}: rotation {case}");
            let mut outer_stream = TokioFramed::new(outer.stream);
            let mut inner_wire = [0_u8; 4_096];
            let inner_len = outer_stream
                .read(&mut inner_wire)
                .await
                .expect("authenticated inner wire");

            let inner_replay = TcpReplayStore::new(1024).expect("inner replay");
            let inner_inbound = ShadowsocksTcpInbound::new(
                &outbounds[second].shadowsocks().unwrap().keys,
                &clock,
                &random,
                &inner_replay,
            );
            let inner = inner_inbound
                .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
                .await
                .expect("configured inner credential");
            assert_eq!(inner.target, application, "{label}: rotation {case}");
            assert!(inner.initial_payload.is_empty(), "{label}: rotation {case}");

            if case == 0 && label == "captured" {
                let wrong_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
                    ferrum2_crypto::MethodPsk::aes128([0x91; 16]),
                ));
                for keys in [&outbounds[second].shadowsocks().unwrap().keys, &wrong_keys] {
                    let replay = TcpReplayStore::new(1024).expect("invalid replay");
                    let inbound = ShadowsocksTcpInbound::new(keys, &clock, &random, &replay);
                    assert!(
                        inbound
                            .accept_stream(scripted_input(&raw).await)
                            .await
                            .is_err(),
                        "swapped/wrong outer credential"
                    );
                }
                let mut truncated = raw.clone();
                truncated.pop().expect("nonempty wire");
                let replay = TcpReplayStore::new(1024).expect("truncated replay");
                let inbound = ShadowsocksTcpInbound::new(
                    &outbounds[first].shadowsocks().unwrap().keys,
                    &clock,
                    &random,
                    &replay,
                );
                let truncated_outer = inbound
                    .accept_stream(scripted_input(&truncated).await)
                    .await
                    .expect("valid outer before truncated inner");
                let mut truncated_stream = TokioFramed::new(truncated_outer.stream);
                assert!(truncated_stream.read(&mut inner_wire).await.is_err());
            }
            assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}: rotation {case}");
        }
        assert_eq!(selector.selected("manual"), Ok("c-d"));
        assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
        assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_chain_failure_and_cancellation_drop_every_layer() {
    let (outbounds, route, selector) = tcp_chain_test_setup(
        [
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
        ],
        42_011,
    );
    let application = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 443))
        .expect("application target");
    let snapshot = selected_plan(&route, 0, Network::Tcp, &application);
    assert_eq!(snapshot.hops(), &[0, 1]);
    let clock = SystemClock::new();
    let random = FixedRandom;

    let calls = Arc::new(AtomicUsize::new(0));
    let unavailable = TokioConnector::new(FailingConnector {
        calls: Arc::clone(&calls),
    });
    let unavailable_engine = ClientEgressEngine::new(
        Arc::clone(&outbounds),
        unavailable,
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    let unavailable_observer = ChainObserver::default();
    assert!(matches!(
        unavailable_engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&unavailable_observer, &unavailable_observer)),
            )
            .await,
        Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
            ConnectErrorKind::Other
        )))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        unavailable_observer
            .buffers
            .lock()
            .expect("unavailable buffers")
            .is_empty()
    );
    assert_eq!(unavailable_observer.owner_drops.load(Ordering::SeqCst), 0);
    assert_eq!(selector.selected("manual"), Ok("a-b"));

    for cancel in [false, true] {
        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let observer = ChainObserver::default();
        let engine = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::stall_after(
                    1,
                    Arc::clone(&drops),
                    Arc::clone(&aborts),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_millis(10)),
            None,
            None,
        );
        let mut opened = Box::pin(engine.open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(snapshot.clone()),
            &application,
            None,
            Some((&observer, &observer)),
        ));
        assert_open_pending(&mut opened).await;
        assert_two_layer_buffers(&observer, format_args!("cancel={cancel}"));
        assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 0);
        if cancel {
            drop(opened);
        } else {
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(matches!(
                opened.await,
                Err(ClientOpenFailure::HandshakeTimeout)
            ));
        }
        assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
        assert!(
            observer
                .terminals
                .lock()
                .expect("pending terminals")
                .is_empty()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1, "cancel={cancel}");
        assert_eq!(aborts.load(Ordering::SeqCst), 0, "cancel={cancel}");
        assert_eq!(
            engine
                .connector
                .targets
                .lock()
                .expect("dial targets")
                .as_slice(),
            &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()],
            "cancel={cancel}"
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let aborts = Arc::new(AtomicUsize::new(0));
    let write_zero_wire = Arc::new(Mutex::new(Vec::new()));
    let write_zero_calls = Arc::new(AtomicUsize::new(0));
    let write_zero_observer = ChainObserver::default();
    let write_zero = ClientEgressEngine::new(
        Arc::clone(&outbounds),
        DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                1,
                0,
                Arc::clone(&write_zero_wire),
                Arc::clone(&write_zero_calls),
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        },
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    assert!(matches!(
        write_zero
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&write_zero_observer, &write_zero_observer)),
            )
            .await,
        Err(ClientOpenFailure::Protocol(ShadowsocksError::Transport(_)))
    ));
    assert_eq!(write_zero_observer.owner_drops.load(Ordering::SeqCst), 2);
    assert_two_layer_buffers(&write_zero_observer, "write zero");
    assert_eq!(
        write_zero_observer
            .terminals
            .lock()
            .expect("write-zero terminals")
            .len(),
        2
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
    assert_eq!(write_zero_calls.load(Ordering::SeqCst), 2);
    assert!(!write_zero_wire.lock().expect("write-zero wire").is_empty());
    assert_eq!(
        write_zero
            .connector
            .targets
            .lock()
            .expect("write-zero targets")
            .as_slice(),
        &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
    );
    assert_eq!(selector.selected("manual"), Ok("a-b"));

    let drops = Arc::new(AtomicUsize::new(0));
    let aborts = Arc::new(AtomicUsize::new(0));
    let partial_wire = Arc::new(Mutex::new(Vec::new()));
    let partial_calls = Arc::new(AtomicUsize::new(0));
    let partial_observer = ChainObserver::default();
    let partial = ClientEgressEngine::new(
        Arc::clone(&outbounds),
        DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                1,
                1,
                Arc::clone(&partial_wire),
                Arc::clone(&partial_calls),
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        },
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    let partial_flow = partial
        .open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(snapshot.clone()),
            &application,
            None,
            Some((&partial_observer, &partial_observer)),
        )
        .await
        .expect("nonzero partial raw write resumes");
    let mut partial_framed = TokioFramed::new(partial_flow);
    partial_framed
        .shutdown()
        .await
        .expect("partial recursive half-close");
    drop(partial_framed);
    assert_eq!(
        partial_calls.load(Ordering::SeqCst),
        3,
        "full initial, one-byte partial, resumed remainder"
    );
    assert_eq!(partial_observer.owner_drops.load(Ordering::SeqCst), 2);
    assert_two_layer_buffers(&partial_observer, "nonzero partial");
    assert!(
        partial_observer
            .terminals
            .lock()
            .expect("partial terminals")
            .is_empty()
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
    assert_eq!(
        partial
            .connector
            .targets
            .lock()
            .expect("partial targets")
            .as_slice(),
        &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
    );
    assert_eq!(selector.selected("manual"), Ok("a-b"));
    let raw = partial_wire.lock().expect("partial wire").clone();
    let outer_replay = TcpReplayStore::new(1024).expect("partial outer replay");
    let outer = ShadowsocksTcpInbound::new(
        &outbounds[0].shadowsocks().unwrap().keys,
        &clock,
        &random,
        &outer_replay,
    )
    .accept_stream(scripted_input(&raw).await)
    .await
    .expect("partial outer wire");
    assert_eq!(outer.target, outbounds[1].shadowsocks().unwrap().tcp_server);
    let mut outer_stream = TokioFramed::new(outer.stream);
    let mut inner_wire = [0_u8; 4_096];
    let inner_len = outer_stream
        .read(&mut inner_wire)
        .await
        .expect("partial inner wire");
    let inner_replay = TcpReplayStore::new(1024).expect("partial inner replay");
    let inner = ShadowsocksTcpInbound::new(
        &outbounds[1].shadowsocks().unwrap().keys,
        &clock,
        &random,
        &inner_replay,
    )
    .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
    .await
    .expect("partial complete inner wire");
    assert_eq!(inner.target, application);
    assert!(inner.initial_payload.is_empty());

    let aborts = Arc::new(AtomicUsize::new(0));
    let detection_observer = ChainObserver::default();
    let (detection_stream, mut detection_peer) = tokio::io::duplex(65_536);
    let detection_engine = ClientEgressEngine::new(
        Arc::clone(&outbounds),
        DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                detection_stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::clone(&aborts),
            )))),
        },
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    let detection_flow = detection_engine
        .open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(snapshot.clone()),
            &application,
            None,
            Some((&detection_observer, &detection_observer)),
        )
        .await
        .expect("opened detection chain");
    let request_salt = MethodTcpSalt::try_from_slice(
        outbounds[0].shadowsocks().unwrap().keys.tcp_profile(),
        &[0x42; 32],
    )
    .expect("outer request salt");
    let inner_request_salt = MethodTcpSalt::try_from_slice(
        outbounds[1].shadowsocks().unwrap().keys.tcp_profile(),
        &[0x42; 32],
    )
    .expect("inner request salt");
    let response_salt = MethodTcpSalt::try_from_slice(
        outbounds[0].shadowsocks().unwrap().keys.tcp_profile(),
        &[0x43; 32],
    )
    .expect("outer response salt");
    let inner_response_salt = MethodTcpSalt::try_from_slice(
        outbounds[1].shadowsocks().unwrap().keys.tcp_profile(),
        &[0x44; 32],
    )
    .expect("inner response salt");
    let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
        ferrum2_crypto::MethodPsk::chacha20_poly1305([0x99; 32]),
    ));
    let invalid_inner = encode_response_first_write(
        &wrong_inner_keys,
        &inner_response_salt,
        clock.unix_seconds().expect("response time"),
        &inner_request_salt,
        b"must not reach application",
    )
    .expect("wrong-key inner response");
    let authenticated_outer = encode_response_first_write(
        &outbounds[0].shadowsocks().unwrap().keys,
        &response_salt,
        clock.unix_seconds().expect("response time"),
        &request_salt,
        &invalid_inner,
    )
    .expect("authenticated outer response");
    detection_peer
        .write_all(&authenticated_outer)
        .await
        .expect("later-hop response");
    let mut detection_framed = TokioFramed::new(detection_flow);
    let mut application_output = [0x5a_u8; 1];
    assert!(
        detection_framed
            .read(&mut application_output)
            .await
            .is_err()
    );
    assert_eq!(application_output, [0x5a]);
    drop(detection_framed);
    assert_eq!(detection_observer.owner_drops.load(Ordering::SeqCst), 2);
    assert_two_layer_buffers(&detection_observer, "detection");
    assert_eq!(
        detection_observer
            .terminals
            .lock()
            .expect("detection terminals")
            .as_slice(),
        &[FlowTerminal::Detection(DetectionReason::Authentication)]
    );
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert_eq!(
        detection_engine
            .connector
            .targets
            .lock()
            .expect("detection targets")
            .as_slice(),
        &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
    );
    assert_eq!(selector.selected("manual"), Ok("a-b"));

    let valid_observer = ChainObserver::default();
    let (valid_stream, mut valid_peer) = tokio::io::duplex(65_536);
    let valid_engine = ClientEgressEngine::new(
        Arc::clone(&outbounds),
        DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                valid_stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::new(AtomicUsize::new(0)),
            )))),
        },
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        None,
        None,
    );
    let valid_flow = valid_engine
        .open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(snapshot.clone()),
            &application,
            None,
            Some((&valid_observer, &valid_observer)),
        )
        .await
        .expect("valid open after isolated failures");
    let mut valid_framed = TokioFramed::new(valid_flow);
    valid_framed.shutdown().await.expect("recursive half-close");
    drop(valid_framed);
    assert_eq!(valid_observer.owner_drops.load(Ordering::SeqCst), 2);
    assert_two_layer_buffers(&valid_observer, "valid half-close");
    let mut valid_wire = Vec::new();
    valid_peer
        .read_to_end(&mut valid_wire)
        .await
        .expect("recursive raw half-close");
    assert!(!valid_wire.is_empty());
    assert_eq!(
        valid_engine
            .connector
            .targets
            .lock()
            .expect("valid targets")
            .as_slice(),
        &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
    );
    assert_eq!(selector.selected("manual"), Ok("a-b"));
}

pub(in crate::run) async fn assert_open_pending<F>(future: &mut Pin<Box<F>>)
where
    F: std::future::Future,
{
    tokio::select! {
        biased;
        _ = future.as_mut() => panic!("open completed before its controlled phase"),
        _ = tokio::task::yield_now() => {}
    }
}
