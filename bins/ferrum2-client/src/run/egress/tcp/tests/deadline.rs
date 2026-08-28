use super::*;

#[tokio::test(start_paused = true)]
async fn phase_deadline_contract_table_preserves_defaults_overrides_and_first_write() {
    let defaults = RuntimeConfig {
        max_connections: std::num::NonZeroU16::new(4_096).expect("non-zero"),
        listen_backlog: std::num::NonZeroU16::new(1_024).expect("non-zero"),
        handshake_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(300),
        shutdown_grace: Duration::from_secs(30),
        network_generation: ferrum2_config::NetworkGenerationMode::Dynamic,
    };
    let custom = RuntimeConfig {
        connect_timeout: Duration::from_millis(2_300),
        handshake_timeout: Duration::from_millis(3_700),
        ..defaults
    };
    let actual = [
        (defaults.connect_timeout, defaults.handshake_timeout),
        (custom.connect_timeout, custom.handshake_timeout),
    ];
    let expected = [
        (Duration::from_secs(10), Duration::from_secs(5)),
        (Duration::from_millis(2_300), Duration::from_millis(3_700)),
    ];
    assert_eq!(actual, expected);
    let cases = [
        (
            "default connect",
            defaults,
            defaults.connect_timeout + Duration::from_secs(1),
            false,
            None,
            Duration::from_secs(10),
            0x11,
        ),
        (
            "fresh handshake",
            defaults,
            Duration::from_secs(9),
            true,
            None,
            Duration::from_secs(5),
            0x12,
        ),
        (
            "custom connect",
            custom,
            custom.connect_timeout + Duration::from_secs(1),
            false,
            None,
            Duration::from_millis(2_300),
            0x13,
        ),
        (
            "custom handshake",
            custom,
            Duration::from_secs(2),
            true,
            None,
            Duration::from_millis(3_700),
            0x14,
        ),
        (
            "DNS connect timeout cap",
            defaults,
            Duration::from_secs(1),
            false,
            Some(Duration::from_millis(700)),
            Duration::from_millis(700),
            0x16,
        ),
    ];
    for (label, runtime, delay, handshake, timeout_limit, expected_timeout, key) in cases {
        run_timeout_case(
            label,
            runtime,
            delay,
            handshake,
            timeout_limit,
            expected_timeout,
            key,
        )
        .await;
    }

    let aborts = Arc::new(AtomicUsize::new(0));
    let (stream, mut peer) = tokio::io::duplex(2_048);
    let connector = DeadlineConnector {
        delay: Duration::ZERO,
        targets: Mutex::new(Vec::new()),
        stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
            stream,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
            Arc::clone(&aborts),
        )))),
    };
    let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002);
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::Shadowsocks(
            ClientShadowsocksContext {
                tcp_server: TargetAddr::ipv4(server).expect("server"),
                udp_server: server.into(),
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                    ferrum2_crypto::MethodPsk::aes128([0x15; 16]),
                )),
                dial_options: ferrum2_net::DialOptions::default(),
            },
        )]
        .into(),
        connector,
        SystemClock::new(),
        FixedRandom,
        (custom.connect_timeout, custom.handshake_timeout),
        None,
        None,
    );
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
    let flow = engine
        .open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            &target,
            None,
            None,
        )
        .await
        .expect("first write");
    assert_eq!(
        flow.local_socket_addr(),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152))
    );
    let mut written = [0_u8; 2_048];
    assert!(peer.read(&mut written).await.expect("handshake wire") > 0);
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}
