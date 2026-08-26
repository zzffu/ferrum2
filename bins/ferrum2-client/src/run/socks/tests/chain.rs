use super::*;

#[tokio::test]
async fn udp_chain_layers_mixed_credentials_bounds_and_response_binding() {
    for methods in [
        [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
        ],
        [
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
        ],
        [
            MethodProfile::Blake3ChaCha20Poly13052022,
            MethodProfile::Blake3Aes128Gcm2022,
        ],
    ] {
        stock_udp_chain_case(methods, false).await;
    }
}

#[tokio::test]
async fn udp_chain_selector_snapshots_and_cross_plan_binding() {
    let upstreams = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("shared outer A"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("inner B"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("inner C"),
    ];
    let servers: [SocketAddrV4; 3] = upstreams.each_ref().map(|socket| {
        let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
            unreachable!("IPv4 upstream")
        };
        address
    });
    let methods = [
        MethodProfile::Blake3Aes128Gcm2022,
        MethodProfile::Blake3Aes256Gcm2022,
        MethodProfile::Blake3ChaCha20Poly13052022,
    ];
    let static_listen = reserve_address();
    let selector_source = |listen: SocketAddrV4, routed: bool| {
        let mut source = format!(
            r#"schema_version = 2
[runtime]
shutdown_grace_ms = 0
[udp]
max_sessions = 2
max_buffered_bytes = 1048576
[[inbounds]]
tag = "entry"
listen = "{listen}"
"#,
        );
        if !routed {
            source.push_str("outbound = \"manual\"\n");
        }
        for (tag, server) in ["a", "b", "c"].into_iter().zip(servers) {
            source.push_str(&test_shadowsocks_outbound_source(tag, server));
        }
        source.push_str(
            r#"
[[chains]]
tag = "a-b"
hops = ["a", "b"]
[[chains]]
tag = "a-c"
hops = ["a", "c"]
[[selectors]]
tag = "manual"
outbounds = ["a-b", "a-c"]
default = "a-b"
"#,
        );
        if routed {
            source.push_str(
                r#"[route]
final = "a-b"
[[route.rules]]
inbound = "entry"
network = "udp"
ip = "192.0.2.40"
port = 53
action = "route"
outbound = "manual"
"#,
            );
        }
        source
    };

    let static_path = write_client_test_source(&selector_source(static_listen, false));
    let prepared =
        ferrum2_config::prepare_client(&static_path).expect("prepare static chain selector");
    let mut static_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish static chain selector");
    static_config.outbounds = servers
        .into_iter()
        .zip(methods)
        .map(
            |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: server.into(),
                psk: Arc::new(psk_for_method(method)),
                dial_options: Default::default(),
            },
        )
        .collect();
    let static_selector = static_config.selector_control();
    static_config.udp.as_mut().expect("UDP config").max_sessions = 2;
    let static_registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(static_config, &static_registry);
    wait_until_bound(static_listen).await;
    let target = TargetAddr::ipv4("192.0.2.40:53".parse().expect("target")).expect("target");
    let mut socks = [0; 64];
    let length = encode_udp_datagram(&target, b"snapshot", &mut socks).expect("request");
    let outer_keys =
        MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(methods[0])));
    let outer_server = UdpServer::new(&outer_keys).expect("outer protocol");
    let clock = SystemClock::new();
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0; MAX_UDP_WIRE_LEN];
    let mut relays = Vec::new();
    for (selected, expected) in [("a-b", servers[1]), ("a-c", servers[2])] {
        static_selector
            .switch("manual", selected)
            .expect("switch static chain");
        let (control, application, relay) = udp_association(static_listen).await;
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("static chain send");
        let received = tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv(&mut wire))
            .await
            .expect("static chain timeout")
            .expect("static chain request");
        let actual = outer_server
            .prepare_request(&clock, &wire[..received], &mut scratch)
            .expect("static outer")
            .datagram()
            .target()
            .clone();
        assert_eq!(
            actual,
            TargetAddr::ipv4(expected).expect("expected inner"),
            "expected inner port {}, actual port {}",
            expected.port(),
            actual.port()
        );
        relays.push(relay);
        drop((control, application));
    }
    stop.send(()).expect("stop static selector client");
    assert_eq!(task.await.expect("static selector client"), Ok(()));
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("static relay rebind"));
    }
    assert_eq!(active(static_registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(static_path).expect("remove static config");

    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (path, mut context) = udp_test_context_for_psk(
        registry.clone(),
        servers[0],
        Some(psk_for_method(methods[0])),
    );
    let outbounds = prepare_client_outbounds(
        servers
            .into_iter()
            .zip(methods)
            .map(
                |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: server.into(),
                    psk: Arc::new(psk_for_method(method)),
                    dial_options: Default::default(),
                },
            )
            .collect(),
    )
    .expect("routed chain outbounds");
    let route_path = write_client_test_source(&selector_source(reserve_address(), true));
    let prepared =
        ferrum2_config::prepare_client(&route_path).expect("prepare routed chain selector");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish routed chain selector");
    std::fs::remove_file(route_path).expect("remove routed selector config");
    let selector = route_config.selector_control();
    let egress = Arc::get_mut(
        &mut Arc::get_mut(&mut context)
            .expect("unique routed context")
            .egress,
    )
    .expect("unique routed egress");
    egress.outbounds = Arc::clone(&outbounds);
    egress.udp_id_random = Some(Arc::new(IdSequenceRandom::new([0x41, 0x42])));
    let routing = Arc::new(ClientRouting {
        program: route_config.route,
        outbounds,
        selector: selector.clone(),
    });
    let mut route_scratch = routing.route_scratch().expect("routed route scratch");
    let ClientTerminalRoute::Route(selected) = routing
        .select_terminal_with_scratch(
            0,
            Network::Udp,
            &target,
            Some(b"snapshot"),
            &context.metrics,
            &mut route_scratch,
        )
        .expect("routed chain selection")
    else {
        panic!("routed chain terminal")
    };
    assert_eq!(selected.hops(), &[0, 1]);
    let endpoint = SocksUdpEndpoint::bind(
        Ipv4Addr::LOCALHOST,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        UdpSocket::bind,
    )
    .await
    .expect("routed SOCKS endpoint");
    let relay = endpoint.local_addr().expect("routed relay");
    let prepared = context
        .egress
        .prepare_udp_with(selected, UdpSocket::bind)
        .await
        .expect("routed chain preparation");
    let (association, peer) = parsed_udp_association().await;
    let running = start_udp_relay(
        endpoint,
        prepared,
        association.control,
        Arc::clone(&context),
        Arc::clone(&routing),
    )
    .await;
    drop(association.reply);
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("routed application");
    let routed_outer =
        UdpServer::new(&routing.outbounds[0].shadowsocks().unwrap().keys).expect("outer protocol");
    let random = SystemRandom;

    for label in ["before switch", "after switch"] {
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("routed chain send");
        let (received, peer) = upstreams[0]
            .recv_from(&mut wire)
            .await
            .expect("routed chain request");
        let pending = routed_outer
            .prepare_request(&clock, &wire[..received], &mut scratch)
            .expect("routed outer");
        assert_eq!(
            pending.datagram().target(),
            &TargetAddr::ipv4(servers[1]).expect("captured B target"),
            "{label}"
        );
        let (_, commit) = pending.into_parts();
        routed_outer
            .commit_request(commit, peer, clock.monotonic_now(), &random)
            .expect("commit routed outer");
        if label == "before switch" {
            selector
                .switch("manual", "a-c")
                .expect("switch routed selector");
        }
    }
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .len(),
        2
    );
    drop(peer);
    finish_udp_relay(running).await;
    assert_eq!(registry.snapshot(), baseline);
    drop(UdpSocket::bind(relay).await.expect("routed relay rebind"));
    std::fs::remove_file(path).expect("remove routed config");
}

#[tokio::test]
async fn udp_chain_invalid_inner_state_and_shutdown_are_atomic() {
    stock_udp_chain_case(
        [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
        ],
        true,
    )
    .await;
    eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers().await;
}
