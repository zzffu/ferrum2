use super::*;

#[test]
fn rule_scratch_failures_keep_closed_runtime_categories() {
    for error in [
        RuleCompileError::Allocation,
        RuleCompileError::IndexOverflow,
    ] {
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleAllocation);
    }
    for error in [
        RuleCompileError::EmptyMatcher,
        RuleCompileError::EmptyField,
        RuleCompileError::DuplicateField,
        RuleCompileError::DuplicateValue,
        RuleCompileError::ConflictingFields,
        RuleCompileError::InvalidDomain,
        RuleCompileError::NonCanonicalCidr,
        RuleCompileError::InvalidId,
        RuleCompileError::InvalidTag,
        RuleCompileError::DuplicateRuleSet,
        RuleCompileError::InvalidGeneration,
        RuleCompileError::Internal,
    ] {
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleCompile);
    }
}

#[tokio::test(start_paused = true)]
async fn tun_tcp_sniff_outcomes_are_fail_closed_and_replay_each_prefix_once() {
    use ferrum2_runtime::SniffPrefixOutcome;

    use super::routing::{ClientTerminalRoute, ReplayIo, TcpRoutePrefix};

    static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-tun-tcp-{}-{}.toml",
        std::process::id(),
        CONFIG_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let source = r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "192.0.2.10:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[route]
final = "proxy"
[route.sniff]
timeout_ms = 300
max_bytes = 8192
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "sniff"
sniffers = "http"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
protocol = "http"
action = "reject"
"#;
    std::fs::write(&path, source).expect("TUN TCP config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare TUN TCP config");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish TUN TCP config");
    std::fs::remove_file(path).expect("remove TUN TCP config");
    let metrics = Metrics::new();
    publish_rule_program_metadata(&config, &metrics);
    let selector = config.selector_control();
    let routing = ClientRouting {
        program: config.route,
        outbounds: Arc::from([]),
        selector,
    };
    let target = TargetAddr::ip("192.0.2.1:80".parse().expect("target")).expect("target");
    let wire = b"GET / HTTP/1.1\r\nHost: replay.test\r\n\r\n";
    let (mut flow, mut peer) = tokio::io::duplex(128);
    peer.write_all(wire).await.expect("write sniff prefix");
    peer.shutdown().await.expect("close sniff peer");
    let registry = OwnerRegistry::new();

    let selection = routing
        .select_tcp(
            0,
            &target,
            &mut flow,
            std::future::pending::<()>(),
            &registry,
            &metrics,
        )
        .await
        .expect("route scratch construction")
        .expect("sniff selection");
    assert!(matches!(selection.terminal, ClientTerminalRoute::Reject));
    assert!(matches!(
        &selection.prefix,
        TcpRoutePrefix::Collected(prefix) if prefix.outcome() == SniffPrefixOutcome::Complete
    ));
    let encoded = metrics.encode_text().expect("client route metrics");
    for expected in [
        "ferrum2_rule_program_mode{program=\"route\",mode=\"small_linear\"} 1",
        "ferrum2_rule_program_rules{program=\"route\"} 2",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_count{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }
    let mut replay = ReplayIo::new(flow, selection.prefix);
    let mut received = Vec::new();
    replay
        .read_to_end(&mut received)
        .await
        .expect("replay selected bytes");
    assert_eq!(received, wire, "collected bytes enter the terminal once");
    drop(replay);
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let mut limit_wire = b"GET / HTTP/1.1\r\nX: ".to_vec();
    limit_wire.resize(8_192, b'a');
    for (name, wire, outcome) in [
        ("limit", limit_wire, SniffPrefixOutcome::Limit),
        (
            "invalid",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            SniffPrefixOutcome::Complete,
        ),
    ] {
        let (mut flow, mut peer) = tokio::io::duplex(16_384);
        peer.write_all(&wire).await.expect("write sniff prefix");
        peer.shutdown().await.expect("close sniff peer");
        let selection = routing
            .select_tcp(
                0,
                &target,
                &mut flow,
                std::future::pending::<()>(),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .expect("sniff falls through to final route");
        assert!(
            matches!(&selection.terminal, ClientTerminalRoute::Route(_)),
            "{name}"
        );
        assert!(
            matches!(&selection.prefix, TcpRoutePrefix::Collected(prefix) if prefix.outcome() == outcome),
            "{name}"
        );
        let mut replay = ReplayIo::new(flow, selection.prefix);
        let mut received = Vec::new();
        replay.read_to_end(&mut received).await.expect("replay");
        assert_eq!(received, wire, "{name} prefix is replayed exactly once");
    }

    let (mut flow, mut peer) = tokio::io::duplex(128);
    peer.write_all(b"G").await.expect("timeout prefix");
    let mut selection = Box::pin(routing.select_tcp(
        0,
        &target,
        &mut flow,
        std::future::pending::<()>(),
        &registry,
        &metrics,
    ));
    tokio::select! {
        _ = &mut selection => panic!("sniff completed before its absolute timeout"),
        _ = tokio::task::yield_now() => {}
    }
    tokio::time::advance(Duration::from_millis(299)).await;
    tokio::select! {
        _ = &mut selection => panic!("sniff timeout was shortened"),
        _ = tokio::task::yield_now() => {}
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    let selection = selection
        .await
        .expect("route scratch construction")
        .expect("timeout falls through to final route");
    peer.shutdown().await.expect("timeout EOF");
    assert!(matches!(&selection.terminal, ClientTerminalRoute::Route(_)));
    assert!(matches!(
        &selection.prefix,
        TcpRoutePrefix::Collected(prefix) if prefix.outcome() == SniffPrefixOutcome::Timeout
    ));
    let mut replay = ReplayIo::new(flow, selection.prefix);
    let mut received = Vec::new();
    replay
        .read_to_end(&mut received)
        .await
        .expect("timeout replay");
    assert_eq!(received, b"G");
    drop(replay);

    let (mut cancelled, _) = tokio::io::duplex(1);
    assert!(
        routing
            .select_tcp(
                0,
                &target,
                &mut cancelled,
                std::future::ready(()),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .is_none(),
        "cancelled sniff cannot select a terminal"
    );
    let mut failed = ScriptedIo::failing();
    assert!(
        routing
            .select_tcp(
                0,
                &target,
                &mut failed,
                std::future::pending::<()>(),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .is_none(),
        "read failure cannot select a terminal"
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
}

#[tokio::test]
async fn tun_tcp_selector_is_snapshotted_once_before_open_and_never_reselected() {
    use super::routing::ClientTerminalRoute;

    let (outbounds, route, selector) = chain_test_setup(
        [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
            MethodProfile::Blake3Aes128Gcm2022,
        ],
        20_000,
    );
    let routing = ClientRouting {
        program: route,
        outbounds,
        selector: selector.clone(),
    };
    let target = TargetAddr::ip("192.0.2.1:443".parse().expect("target")).expect("target");
    let (mut first_flow, _) = tokio::io::duplex(1);
    let first = routing
        .select_tcp(
            0,
            &target,
            &mut first_flow,
            std::future::pending::<()>(),
            &OwnerRegistry::new(),
            &Metrics::new(),
        )
        .await
        .expect("route scratch construction")
        .expect("first selection");
    let ClientTerminalRoute::Route(first) = first.terminal else {
        panic!("selector routes");
    };
    assert_eq!(first.hops(), &[0, 1]);

    selector.switch("manual", "c-d").expect("selector switch");
    assert_eq!(first.hops(), &[0, 1], "live flow retains its snapshot");
    let (mut second_flow, _) = tokio::io::duplex(1);
    let second = routing
        .select_tcp(
            0,
            &target,
            &mut second_flow,
            std::future::pending::<()>(),
            &OwnerRegistry::new(),
            &Metrics::new(),
        )
        .await
        .expect("route scratch construction")
        .expect("second selection");
    let ClientTerminalRoute::Route(second) = second.terminal else {
        panic!("selector routes");
    };
    assert_eq!(second.hops(), &[2, 3]);
}

#[tokio::test]
async fn tagged_tcp_uses_static_outbounds_one_process_permit_and_no_fallback() {
    let listens = [reserve_address(), reserve_address()];
    let upstreams = [
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream A"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream B"),
    ];
    let servers: [SocketAddrV4; 2] =
        std::array::from_fn(
            |index| match upstreams[index].local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            },
        );
    let (path, mut config) =
        tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], false);
    config.runtime.max_connections = 1.try_into().expect("one connection");
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(listens[0]).await;
    wait_until_bound(listens[1]).await;

    let (first, reply) = socks_command(listens[0], 1).await;
    assert_eq!(&reply[..2], &[5, 0]);
    let (first_upstream, _) = upstreams[0].accept().await.expect("mapped upstream A");
    let second = tokio::spawn(socks_command(listens[1], 1));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[1].accept())
            .await
            .is_err(),
        "second listener multiplied the process permit"
    );
    drop((first, first_upstream));
    let (second, reply) = second.await.expect("second SOCKS task");
    assert_eq!(&reply[..2], &[5, 0]);
    let (second_upstream, _) = upstreams[1].accept().await.expect("mapped upstream B");
    stop.send(()).expect("stop mapped client");
    assert_eq!(task.await.expect("mapped client"), Ok(()));
    drop((second, second_upstream));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let shared_listens = [reserve_address(), reserve_address()];
    let (shared_path, config) =
        tagged_client_test_config(&shared_listens.map(|listen| (listen, servers[0])), false);
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in shared_listens {
        wait_until_bound(listen).await;
        let (control, reply) = socks_command(listen, 1).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (upstream, _) = upstreams[0].accept().await.expect("shared upstream");
        drop((control, upstream));
    }
    stop.send(()).expect("stop shared client");
    assert_eq!(task.await.expect("shared client"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let dead = reserve_address();
    let (dead_path, config) = tagged_client_test_config(
        &[(reserve_address(), servers[0]), (reserve_address(), dead)],
        false,
    );
    let dead_listen = config.inbounds[1].listen;
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(dead_listen).await;
    let (_, reply) = socks_command(dead_listen, 1).await;
    assert_eq!(reply[0], 5);
    assert_ne!(reply[1], 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[0].accept())
            .await
            .is_err(),
        "dead referenced server fell back to live sibling"
    );
    stop.send(()).expect("stop no-fallback client");
    assert_eq!(task.await.expect("no-fallback client"), Ok(()));
    std::fs::remove_file(path).expect("remove mapped config");
    std::fs::remove_file(shared_path).expect("remove shared config");
    std::fs::remove_file(dead_path).expect("remove no-fallback config");
}
