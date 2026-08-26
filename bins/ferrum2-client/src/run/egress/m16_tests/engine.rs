use super::*;
use crate::run::egress::UdpPlanResponseError;
use ferrum2_dns::{ApplicationResolver, DnsStrategy};

#[tokio::test]
async fn missing_exact_direct_resolver_fails_closed_for_tcp_and_udp() {
    let backend = Arc::new(RoutedApplicationBackend {
        routes: vec![
            ApplicationRoute {
                ingress: 0,
                network: ferrum2_core::route::Network::Tcp,
                endpoint: "127.0.0.1:9".parse().unwrap(),
            },
            ApplicationRoute {
                ingress: 0,
                network: ferrum2_core::route::Network::Udp,
                endpoint: "127.0.0.1:9".parse().unwrap(),
            },
        ],
        observed: Mutex::new(Vec::new()),
    });
    let ambient = ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::configured(backend.clone())),
        0,
        DnsStrategy::PreferIpv4,
    );
    let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        ambient.clone(),
        Duration::from_secs(1),
    ));
    let engine = ClientEgressEngine::new_with_direct_resolvers(
        vec![ClientOutboundContext::direct(DialOptions::default())].into(),
        connector,
        SystemClock::new(),
        SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        ambient,
        vec![None].into(),
        None,
    );
    let target = TargetAddr::domain("missing-exact-resolver.invalid", 443).unwrap();
    let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();

    assert!(matches!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(direct.clone()),
                &target,
                None,
                None,
            )
            .await,
        Err(ClientOpenFailure::Connect(
            ConnectErrorKind::HostUnreachable
        ))
    ));
    assert!(matches!(
        engine
            .prepare_udp_for_ingress(ClientRequestOrigin::Socks, 0, Some(direct), Some(&target),)
            .await,
        Err(ClientUdpPrepareFailure::Unavailable)
    ));
    assert!(
        backend.observed.lock().unwrap().is_empty(),
        "malformed exact resolver table must never use the ambient resolver"
    );
}

#[tokio::test]
async fn application_dns_ingress_is_isolated_for_concurrent_tcp_and_udp() {
    let tcp_listener_3 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_listener_7 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_listener_3 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_listener_7 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend = Arc::new(RoutedApplicationBackend {
        routes: vec![
            ApplicationRoute {
                ingress: 3,
                network: ferrum2_core::route::Network::Tcp,
                endpoint: tcp_listener_3.local_addr().unwrap(),
            },
            ApplicationRoute {
                ingress: 7,
                network: ferrum2_core::route::Network::Tcp,
                endpoint: tcp_listener_7.local_addr().unwrap(),
            },
            ApplicationRoute {
                ingress: 3,
                network: ferrum2_core::route::Network::Udp,
                endpoint: udp_listener_3.local_addr().unwrap(),
            },
            ApplicationRoute {
                ingress: 7,
                network: ferrum2_core::route::Network::Udp,
                endpoint: udp_listener_7.local_addr().unwrap(),
            },
        ],
        observed: Mutex::new(Vec::new()),
    });
    let resolver = ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::configured(backend.clone())),
        0,
        DnsStrategy::PreferIpv4,
    );
    let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        resolver.clone(),
        Duration::from_secs(1),
    ));
    let registry = OwnerRegistry::new();
    let engine = ClientEgressEngine::new_with_application_resolver(
        vec![ClientOutboundContext::direct(DialOptions::default())].into(),
        connector,
        SystemClock::new(),
        SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        resolver,
        None,
    );
    let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    let tcp_target = TargetAddr::domain("tcp-ingress.invalid", 443).unwrap();
    let udp_target = TargetAddr::domain("udp-ingress.invalid", 5353).unwrap();
    let mut association_3 = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            3,
            Some(direct.clone()),
            Some(&udp_target),
        )
        .await
        .unwrap();
    let mut association_7 = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            7,
            Some(direct.clone()),
            Some(&udp_target),
        )
        .await
        .unwrap();
    let wire_3 = association_3
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            udp_target.clone(),
            b"ingress-3",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("prepare ingress 3 datagram"));
    let wire_7 = association_7
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            udp_target.clone(),
            b"ingress-7",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("prepare ingress 7 datagram"));

    let receive_3 = async {
        let mut bytes = [0_u8; 32];
        let (length, _) = udp_listener_3.recv_from(&mut bytes).await.unwrap();
        bytes[..length].to_vec()
    };
    let receive_7 = async {
        let mut bytes = [0_u8; 32];
        let (length, _) = udp_listener_7.recv_from(&mut bytes).await.unwrap();
        bytes[..length].to_vec()
    };
    let (tcp_3, tcp_7, udp_3, udp_7, accepted_3, accepted_7, payload_3, payload_7) = tokio::join!(
        engine.open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            3,
            Some(direct.clone()),
            &tcp_target,
            None,
            None,
        ),
        engine.open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            7,
            Some(direct.clone()),
            &tcp_target,
            None,
            None,
        ),
        association_3.send_encoded_request(wire_3),
        association_7.send_encoded_request(wire_7),
        tcp_listener_3.accept(),
        tcp_listener_7.accept(),
        receive_3,
        receive_7,
    );
    drop(tcp_3.unwrap());
    drop(tcp_7.unwrap());
    drop(accepted_3.unwrap());
    drop(accepted_7.unwrap());
    assert_eq!(udp_3.unwrap(), b"ingress-3".len());
    assert_eq!(udp_7.unwrap(), b"ingress-7".len());
    assert_eq!(payload_3, b"ingress-3");
    assert_eq!(payload_7, b"ingress-7");

    for (association, ingress, payload) in [
        (&mut association_3, 3, b"again-3".as_slice()),
        (&mut association_7, 7, b"again-7".as_slice()),
    ] {
        let wire = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target.clone(),
                payload,
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare repeated ingress {ingress} datagram"));
        association
            .send_encoded_request(wire)
            .await
            .unwrap_or_else(|_| panic!("send repeated ingress {ingress} datagram"));
    }

    assert!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                13,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            )
            .await
            .is_err(),
        "configured failure must not fall back"
    );
    assert!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            )
            .await
            .is_err(),
        "ingress zero must remain isolated from configured routes"
    );
    let mut failed_udp = engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Socks,
            13,
            Some(direct),
            Some(&udp_target),
        )
        .await
        .unwrap();
    let failed_wire = failed_udp
        .prepare_application_request(
            &engine,
            &engine.outbounds,
            udp_target,
            b"no-fallback",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("prepare failed-ingress datagram"));
    assert_eq!(
        failed_udp
            .send_encoded_request(failed_wire)
            .await
            .expect_err("configured UDP failure must not fall back")
            .kind(),
        io::ErrorKind::TimedOut
    );

    let observed = backend.observed.lock().unwrap();
    for (ingress, network, expected) in [
        (0, ferrum2_core::route::Network::Tcp, 1),
        (3, ferrum2_core::route::Network::Tcp, 1),
        (3, ferrum2_core::route::Network::Udp, 2),
        (7, ferrum2_core::route::Network::Tcp, 1),
        (7, ferrum2_core::route::Network::Udp, 2),
        (13, ferrum2_core::route::Network::Tcp, 1),
        (13, ferrum2_core::route::Network::Udp, 1),
    ] {
        assert_eq!(
            observed
                .iter()
                .filter(|actual| **actual == (ingress, network))
                .count(),
            expected,
            "ingress {ingress} {network:?}"
        );
    }
    assert_eq!(observed.len(), 9);
}

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for &TraceCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("trace capture")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn m16_direct_pre_socket_and_m16_redaction_classify_without_side_effects() {
    assert_eq!(
        prepare_client_outbounds(Vec::new()).err().unwrap(),
        RunError::StartupProtocol
    );
    let outbounds = prepare_client_outbounds(vec![
        ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: Default::default(),
        },
        ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: Default::default(),
        },
        proxy(),
    ])
    .expect("closed outbound catalog");
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let bind_calls = Arc::new(AtomicUsize::new(0));
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let engine = ClientEgressEngine::new(
        outbounds,
        TokioConnector::new(FailingConnector {
            calls: Arc::clone(&connector_calls),
        }),
        SystemClock::new(),
        FixedRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
        }),
        None,
    );
    let target = TargetAddr::domain("m16-target-sentinel.invalid", 443).unwrap();
    for (name, plan, expected) in [
        ("mixed", selected(vec![0, 2]), ClientPlanFailure::Invalid),
        (
            "multi direct",
            selected(vec![0, 1]),
            ClientPlanFailure::Invalid,
        ),
        (
            "out of range",
            ferrum2_core::route::EgressPlanHandle::direct(3).snapshot_owned(),
            ClientPlanFailure::Invalid,
        ),
    ] {
        assert!(
            matches!(
                engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                        Some(plan.clone()),
                        &target,
                        None,
                        None,
                    )
                    .await,
                Err(ClientOpenFailure::Plan(actual)) if actual == expected
            ),
            "TCP {name}"
        );
        let calls = Arc::clone(&bind_calls);
        assert_eq!(
            engine
                .prepare_udp_with(plan, move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err(io::Error::other("binder must not run")) }
                })
                .await
                .err(),
            Some(ClientUdpPrepareFailure::Plan(expected)),
            "UDP {name}"
        );
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0, "TCP {name}");
        assert_eq!(bind_calls.load(Ordering::SeqCst), 0, "UDP {name}");
        assert_eq!(registry.snapshot(), baseline, "owners {name}");
    }

    assert!(matches!(
        engine
            .open_tcp_for_ingress(ClientRequestOrigin::Socks, 0, None, &target, None, None)
            .await,
        Err(ClientOpenFailure::Plan(ClientPlanFailure::Invalid))
    ));
    assert_eq!(connector_calls.load(Ordering::SeqCst), 0);

    let mixed = selected(vec![0, 2]);
    let redacted_tcp = format!(
        "{:?}",
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(mixed.clone()),
                &target,
                None,
                None,
            )
            .await
            .err()
            .unwrap()
    );
    let redacted_udp = format!(
        "{:?}",
        engine
            .prepare_udp_for_ingress(ClientRequestOrigin::Socks, 0, Some(mixed), Some(&target),)
            .await
            .err()
            .unwrap()
    );
    let dns_target = TargetAddr::domain("m16-dns-sentinel.invalid", 53).unwrap();
    let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    let packet_registry = OwnerRegistry::new();
    let packet_live_ids = Arc::new(Mutex::new(HashSet::new()));
    let packet_engine = ClientEgressEngine::new(
        prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: Default::default(),
        }])
        .expect("packet direct outbound"),
        TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
        ferrum2_crypto::SystemClock::new(),
        ferrum2_crypto::SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), packet_registry.clone()),
            live_ids: Arc::clone(&packet_live_ids),
        }),
        None,
    );
    let mut association = packet_engine
        .prepare_udp_for_ingress(
            ClientRequestOrigin::Dns,
            0,
            Some(direct.clone()),
            Some(&dns_target),
        )
        .await
        .expect("redaction direct UDP association");
    let mut packet = vec![0_u8; ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES + 1];
    packet[..19].copy_from_slice(b"m16-packet-sentinel");
    let packet_error = match association.prepare_application_request(
        &packet_engine,
        &packet_engine.outbounds,
        dns_target.clone(),
        &packet,
        Instant::now(),
    ) {
        Err(UdpPlanResponseError::Packet(error)) => format!("{error:?}"),
        Err(UdpPlanResponseError::Runtime(_)) | Ok(_) => panic!("fixed packet bound error"),
    };
    drop(association);
    assert_eq!(packet_registry.snapshot(), OwnerSnapshot::default());
    assert!(
        packet_live_ids
            .lock()
            .expect("packet SIP022 IDs")
            .is_empty()
    );

    let dns_connect_target = TargetAddr::ip("192.0.2.53:53".parse().unwrap()).unwrap();
    let connect_kind = match engine
        .open_tcp_for_ingress(
            ClientRequestOrigin::Dns,
            0,
            Some(direct),
            &dns_connect_target,
            None,
            None,
        )
        .await
    {
        Err(ClientOpenFailure::Connect(kind)) => kind,
        _ => panic!("fixed direct connect failure"),
    };
    assert_eq!(connect_kind, ferrum2_core::ConnectErrorKind::Other);
    let reason = ferrum2_observability::Reason::RelayIo;
    let metrics = Metrics::new();
    metrics.failure(
        ferrum2_observability::Role::Client,
        ferrum2_observability::Stage::Relay,
        reason,
    );
    let trace = Arc::new(TraceCapture::default());
    let subscriber = ferrum2_observability::json_subscriber(
        Arc::clone(&trace),
        ferrum2_observability::LogLevel::Trace,
    );
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        ferrum2_observability::emit(
            ferrum2_observability::TraceRecord::new(
                ferrum2_observability::LogLevel::Warn,
                ferrum2_observability::Event::Failure,
                ferrum2_observability::Role::Client,
                ferrum2_observability::Stage::Relay,
                ferrum2_observability::Outcome::Failed,
            )
            .with_reason(reason),
        );
    });
    let trace = String::from_utf8(trace.0.lock().expect("trace capture").clone()).unwrap();
    let metrics = metrics.encode_text().expect("closed metrics");
    assert_eq!(redacted_tcp, "Plan(Invalid)");
    assert_eq!(redacted_udp, "Plan(Invalid)");
    assert_eq!(packet_error, "Bounds");
    for sentinel in [
        "m16-target-sentinel.invalid",
        "198.51.100.222:62016",
        "m16-dns-sentinel.invalid",
        "m16-tag-sentinel",
        "m16-packet-sentinel",
        "m16-secret-key!!",
    ] {
        for output in [
            &redacted_tcp,
            &redacted_udp,
            &packet_error,
            &trace,
            &metrics,
        ] {
            assert!(!output.contains(sentinel), "leaked sentinel in {output}");
        }
    }
    assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot(), baseline);

    let ipv6 = TargetAddr::ip("[2001:db8::1]:443".parse().unwrap()).unwrap();
    let plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    assert!(matches!(
        engine.classify_selected(ClientRequestOrigin::Tun, Some(&plan), Some(&ipv6)),
        Ok(SelectedEgress::Direct { .. })
    ));
    assert!(matches!(
        engine.classify_selected(ClientRequestOrigin::Dns, Some(&plan), Some(&ipv6)),
        Ok(SelectedEgress::Direct { .. })
    ));

    let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
    assert!(matches!(
        engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(direct),
                &TargetAddr::ip("[::1]:443".parse().unwrap()).unwrap(),
                None,
                None,
            )
            .await,
        Err(ClientOpenFailure::Connect(
            ferrum2_core::ConnectErrorKind::Other
        ))
    ));
    assert_eq!(connector_calls.load(Ordering::SeqCst), 2);
}
