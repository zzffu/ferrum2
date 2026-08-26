use super::*;

#[tokio::test]
async fn direct_udp_resolves_every_send_and_reuses_last_success_hint() {
    let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.2:53".parse().unwrap();
    let third: SocketAddr = "192.0.2.3:53".parse().unwrap();
    let resolver = DirectTestResolver {
        candidates: Some(vec![first, second, third]),
        calls: AtomicUsize::new(0),
    };
    let socket = SelectiveDirectTestSocket {
        attempts: Mutex::new(Vec::new()),
        successful: Mutex::new(HashSet::from([second])),
    };
    let target = TargetAddr::domain("hinted-direct.invalid", 53).unwrap();
    let mut hints = DirectUdpCandidateHints::default();

    let (_, peer) = send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"first",
        Duration::from_secs(1),
    )
    .await
    .expect("first resolved send");
    assert_eq!(peer, second);
    assert_eq!(socket.take_attempts(), [first, second]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"resolve-again",
        Duration::from_secs(1),
    )
    .await
    .expect("resolved last-success send");
    assert_eq!(socket.take_attempts(), [second]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

    socket.set_successful([third]);
    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"rotate",
        Duration::from_secs(1),
    )
    .await
    .expect("candidate rotation send");
    assert_eq!(socket.take_attempts(), [second, third]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);

    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"new-last-success",
        Duration::from_secs(1),
    )
    .await
    .expect("updated last-success send");
    assert_eq!(socket.take_attempts(), [third]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);

    socket.set_successful([first]);
    let ip_target = TargetAddr::ip(first).unwrap();
    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &ip_target,
        b"literal-ip",
        Duration::from_secs(1),
    )
    .await
    .expect("literal IP send");
    assert_eq!(socket.take_attempts(), [first]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
    assert_eq!(hints.entries.len(), 1);
    assert_eq!(hints.entries[0].last_successful_index, 2);
}

#[tokio::test]
async fn direct_udp_uses_fresh_resolver_results_and_never_falls_back() {
    let first: SocketAddr = "192.0.2.11:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.12:53".parse().unwrap();
    let refreshed: SocketAddr = "192.0.2.13:53".parse().unwrap();
    let resolver = SequencedDirectTestResolver {
        answers: Mutex::new(VecDeque::from([
            Ok(vec![first, second]),
            Ok(vec![refreshed]),
            Err(io::ErrorKind::ConnectionRefused),
        ])),
        calls: AtomicUsize::new(0),
    };
    let socket = SelectiveDirectTestSocket {
        attempts: Mutex::new(Vec::new()),
        successful: Mutex::new(HashSet::from([second])),
    };
    let target = TargetAddr::domain("fresh-direct.invalid", 53).unwrap();
    let mut hints = DirectUdpCandidateHints::default();

    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"prime",
        Duration::from_secs(1),
    )
    .await
    .expect("prime candidate hint");
    assert_eq!(socket.take_attempts(), [first, second]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

    socket.set_successful([refreshed]);
    send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"fresh-result",
        Duration::from_secs(1),
    )
    .await
    .expect("fresh resolver result");
    assert_eq!(socket.take_attempts(), [refreshed]);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

    let error = send_direct_target(
        &socket,
        &resolver,
        &mut hints,
        &target,
        b"configured-failure",
        Duration::from_secs(1),
    )
    .await
    .expect_err("resolver failure is terminal");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(socket.take_attempts().is_empty());
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn direct_udp_candidate_hints_are_bounded() {
    let candidate: SocketAddr = "192.0.2.21:53".parse().unwrap();
    let resolver = DirectTestResolver {
        candidates: Some(vec![candidate]),
        calls: AtomicUsize::new(0),
    };
    let socket = SelectiveDirectTestSocket {
        attempts: Mutex::new(Vec::new()),
        successful: Mutex::new(HashSet::from([candidate])),
    };
    let mut hints = DirectUdpCandidateHints::default();

    for index in 0..=DIRECT_UDP_CANDIDATE_HINT_CAPACITY {
        let domain = format!("hint-{index}.invalid");
        let target = TargetAddr::domain(&domain, 53).unwrap();
        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"bounded",
            Duration::from_secs(1),
        )
        .await
        .expect("bounded hinted send");
    }

    assert_eq!(hints.entries.len(), DIRECT_UDP_CANDIDATE_HINT_CAPACITY);
    assert!(
        hints
            .entries
            .iter()
            .all(|entry| entry.domain != "hint-0.invalid")
    );
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        DIRECT_UDP_CANDIDATE_HINT_CAPACITY + 1
    );
}

#[tokio::test]
async fn direct_tcp_and_udp_injection_share_configured_resolver_without_fallback() {
    let backend = Arc::new(FailingConfiguredApplicationBackend {
        calls: AtomicUsize::new(0),
    });
    let application_resolver = ferrum2_dns::ApplicationResolverAdapter::new(
        Arc::new(ferrum2_dns::ApplicationResolver::configured(
            backend.clone(),
        )),
        0,
        ferrum2_dns::DnsStrategy::PreferIpv4,
    );
    let connector = ferrum2_runtime::TcpConnector::with_resolution_adapters(
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        application_resolver.clone(),
        Duration::from_secs(1),
    );
    assert!(
        connector
            .resolver()
            .shares_resolver_with(&application_resolver)
    );
    let registry = OwnerRegistry::new();
    let engine = ClientEgressEngine::new_with_application_resolver(
        vec![ClientOutboundContext::direct(
            ferrum2_net::DialOptions::default(),
        )]
        .into(),
        TokioConnector::new(connector),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        application_resolver.clone(),
        None,
    );
    assert!(
        engine
            .application_resolver
            .shares_resolver_with(&application_resolver)
    );
    let target = TargetAddr::domain("configured-only.invalid", 53).expect("domain target");
    let mut association = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&target),
        )
        .await
        .expect("direct association");
    let Ok(wire_len) = association.prepare_application_request(
        &engine,
        &engine.outbounds,
        target,
        b"configured",
        Instant::now(),
    ) else {
        panic!("prepare direct request");
    };

    let error = association
        .send_encoded_request(wire_len)
        .await
        .expect_err("configured resolver failure must be terminal");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}
