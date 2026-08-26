use super::*;

#[tokio::test]
async fn selector_switch_invalidates_the_frozen_tun_udp_association() {
    let (outbounds, route, selector) = chain_test_setup(
        [
            ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
            ferrum2_crypto::MethodProfile::Blake3Aes256Gcm2022,
            ferrum2_crypto::MethodProfile::Blake3ChaCha20Poly13052022,
            ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
        ],
        20_000,
    );
    let routing = ClientRouting {
        program: route,
        outbounds,
        selector: selector.clone(),
    };
    let target = TargetAddr::ip("192.0.2.8:53".parse().unwrap()).unwrap();
    let metrics = ferrum2_observability::Metrics::new();
    let mut scratch = routing.route_scratch().expect("route scratch");
    let (first_generation, first_plan) = select_udp_target_generation_stable(
        TunUdpRouteRequest {
            routing: &routing,
            inbound: 0,
            synthetic_dns: SyntheticDns::default(),
            target: &target,
            payload: b"first",
            metrics: &metrics,
        },
        &mut scratch,
    )
    .expect("first stable generation");
    let encoded = metrics.encode_text().expect("route result metrics");
    assert!(
        encoded.lines().any(|line| {
            line == "ferrum2_tun_udp_association_route_total{result=\"success\"} 1"
        })
    );
    let TunUdpPlan::Route {
        snapshot: first_snapshot,
        ..
    } = first_plan
    else {
        panic!("first route target");
    };
    let mut route_change = routing.watch_route_generation_from(first_generation);
    assert_eq!(first_snapshot.hops(), &[0, 1]);
    assert!(udp_route_generation_is_current(&routing, first_generation));

    selector.switch("manual", "a-b").expect("no-op switch");
    assert!(selector.switch("manual", "missing").is_err());
    assert!(udp_route_generation_is_current(&routing, first_generation));

    selector.switch("manual", "c-d").expect("effective switch");
    assert!(
        !udp_route_generation_is_current(&routing, first_generation),
        "the active association must terminate instead of selecting another route"
    );
    tokio::time::timeout(Duration::from_millis(50), &mut route_change)
        .await
        .expect("generation watcher must wake a blocked association");
    assert_eq!(
        first_snapshot.hops(),
        &[0, 1],
        "the frozen snapshot is never rewritten in place"
    );
}

#[test]
fn schema_v2_selector_switch_changes_composite_tun_udp_generation() {
    let (path, _) = client_test_config(reserve_address(), reserve_address());
    std::fs::write(
        &path,
        r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
type = "shadowsocks"
server = "192.0.2.10:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[selectors]]
tag = "manual"
outbounds = ["direct", "proxy"]
default = "direct"
[route]
final = "manual"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "route"
outbound = "direct"
"#,
    )
    .expect("schema-v2 selector config");
    let prepared =
        ferrum2_config::prepare_client(&path).expect("prepare schema-v2 selector config");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish schema-v2 selector config");
    std::fs::remove_file(path).expect("remove schema-v2 selector config");
    let inbound = config.inbounds.len();
    let selector = config.selector_control();
    let outbounds = prepare_client_outbounds(config.outbounds).expect("outbound contexts");
    let routing = ClientRouting {
        program: config.route,
        outbounds,
        selector: selector.clone(),
    };
    let target = TargetAddr::ip("192.0.2.8:53".parse().unwrap()).unwrap();
    let metrics = ferrum2_observability::Metrics::new();
    let mut scratch = routing.route_scratch().expect("route scratch");
    let select = |payload: &[u8], scratch: &mut ferrum2_rule::RuleEvaluationScratch| {
        select_udp_target_generation_stable(
            TunUdpRouteRequest {
                routing: &routing,
                inbound,
                synthetic_dns: SyntheticDns::default(),
                target: &target,
                payload,
                metrics: &metrics,
            },
            scratch,
        )
        .expect("stable schema-v2 selection")
    };

    let (first_generation, first_plan) = select(b"first", &mut scratch);
    let TunUdpPlan::Route {
        snapshot: first_snapshot,
        ..
    } = first_plan
    else {
        panic!("first schema-v2 route");
    };
    assert_eq!(first_snapshot.hops(), &[0]);

    selector.switch("manual", "proxy").expect("selector switch");
    let (second_generation, second_plan) = select(b"second", &mut scratch);
    let TunUdpPlan::Route {
        snapshot: second_snapshot,
        ..
    } = second_plan
    else {
        panic!("second schema-v2 route");
    };
    assert_ne!(second_generation, first_generation);
    assert_eq!(second_snapshot.hops(), &[1]);
}

#[tokio::test]
async fn tun_udp_route_snapshot_is_bounded_and_immutable_after_selection() {
    let (outbounds, route, selector) = chain_test_setup(
        [
            ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
            ferrum2_crypto::MethodProfile::Blake3Aes256Gcm2022,
            ferrum2_crypto::MethodProfile::Blake3ChaCha20Poly13052022,
            ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
        ],
        20_000,
    );
    let routing = ClientRouting {
        program: route,
        outbounds,
        selector: selector.clone(),
    };
    let target = TargetAddr::ip("192.0.2.1:53".parse().expect("target")).expect("target");
    let metrics = ferrum2_observability::Metrics::new();
    let first = select_udp_target(&routing, 0, None, None, &target, b"first", 1_392, &metrics)
        .expect("first selector snapshot");
    let TunUdpPlan::Route {
        snapshot: first_snapshot,
        request_payload_bound: bound,
        ..
    } = first
    else {
        panic!("route target plan");
    };
    assert_eq!(first_snapshot.hops(), &[0, 1]);
    assert!(
        bound > 1_392,
        "reassembled request inherited the response-injection MTU bound"
    );
    assert!(target_payload_within_bound(1_393, bound));
    let oversized = select_udp_target(
        &routing,
        0,
        None,
        None,
        &target,
        &vec![0; bound + 1],
        1_392,
        &metrics,
    )
    .expect("oversized datagram still snapshots its target plan");
    let TunUdpPlan::Route {
        snapshot: oversized_snapshot,
        request_payload_bound: oversized_bound,
        ..
    } = oversized
    else {
        panic!("route target plan");
    };
    assert_eq!(oversized_snapshot.hops(), &[0, 1]);
    assert_eq!(oversized_bound, bound);

    selector
        .switch("manual", "c-d")
        .expect("switch after rejected candidate");
    let selected = select_udp_target(&routing, 0, None, None, &target, b"valid", 1_392, &metrics)
        .expect("current association selector");
    let TunUdpPlan::Route { snapshot, .. } = selected else {
        panic!("route target plan");
    };
    assert_eq!(snapshot.hops(), &[2, 3]);
    selector
        .switch("manual", "a-b")
        .expect("switch after terminal snapshot");
    assert_eq!(
        snapshot.hops(),
        &[2, 3],
        "the selected association owns an immutable plan snapshot"
    );

    let registry = OwnerRegistry::new();
    let live_ids = Arc::new(Mutex::new(HashSet::new()));
    let outbounds = prepare_client_outbounds(vec![
        ferrum2_config::ClientOutboundConfig::Direct {
            domain_resolver: ferrum2_config::DirectDomainResolver::System,
            dial_options: Default::default(),
        },
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "192.0.2.77:8388".parse().unwrap(),
            psk: Arc::new(default_test_psk()),
            dial_options: Default::default(),
        },
    ])
    .expect("direct and proxy outbounds");
    let route_path = write_client_test_source(&format!(
        r#"schema_version = 2
[[inbounds]]
tag = "tun"
listen = "{}"
outbound = "manual"
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
type = "direct"
[[selectors]]
tag = "manual"
outbounds = ["direct", "proxy"]
default = "direct"
"#,
        reserve_address()
    ));
    let prepared =
        ferrum2_config::prepare_client(&route_path).expect("prepare direct selector route");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish direct selector route");
    std::fs::remove_file(route_path).expect("remove direct selector route config");
    let direct_selector = route_config.selector_control();
    let routing = ClientRouting {
        program: route_config.route,
        outbounds: Arc::clone(&outbounds),
        selector: direct_selector.clone(),
    };
    let first_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("first direct TUN UDP target");
    let second_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("second direct TUN UDP target");
    let target = TargetAddr::ip(first_echo.local_addr().unwrap()).unwrap();
    let second_target = TargetAddr::ip(second_echo.local_addr().unwrap()).unwrap();
    let selected = select_udp_target(
        &routing,
        0,
        None,
        None,
        &target,
        b"tun-direct",
        1_392,
        &Metrics::new(),
    )
    .expect("direct TUN UDP selection");
    let TunUdpPlan::Route {
        snapshot: direct,
        request_payload_bound: bound,
        ..
    } = selected
    else {
        panic!("direct route target plan");
    };
    assert!(
        bound > 1_392,
        "Direct request limit inherited the response-injection MTU bound"
    );
    assert!(target_payload_within_bound(1_393, bound));
    assert_eq!(direct.hops(), &[0]);
    let engine = ClientEgressEngine::new(
        outbounds,
        TokioConnector::new(TcpConnector::new(Duration::from_secs(1))),
        SystemClock::new(),
        SystemRandom,
        (Duration::from_secs(1), Duration::from_secs(1)),
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
            live_ids: Arc::clone(&live_ids),
        }),
        None,
    );
    let mut association = engine
        .prepare_udp_for_ingress(
            crate::run::egress::ClientRequestOrigin::Tun,
            0,
            Some(direct),
            Some(&target),
        )
        .await
        .expect("direct TUN UDP association");
    association.activate(&engine).expect("direct activation");
    let length = association
        .prepare_application_request(
            &engine,
            &routing.outbounds,
            target.clone(),
            b"tun-direct",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("direct TUN request"));
    association
        .send_encoded_request(length)
        .await
        .expect("direct TUN send");
    let mut raw = [0_u8; 32];
    let (length, peer) = first_echo
        .recv_from(&mut raw)
        .await
        .expect("first direct TUN receive");
    assert_eq!(&raw[..length], b"tun-direct");
    first_echo.send_to(b"tun-reply", peer).await.unwrap();
    let length = association.receive_response_wire().await.unwrap();
    let response = association
        .prepare_application_response(&engine, &routing.outbounds, length)
        .unwrap_or_else(|_| panic!("direct TUN response"));
    assert_eq!(response.datagram().target(), &target);
    assert_eq!(response.datagram().payload(), b"tun-reply");
    association.recycle_application_response(response);

    let length = association
        .prepare_application_request(
            &engine,
            &routing.outbounds,
            second_target.clone(),
            b"second-target",
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("second direct TUN request"));
    association
        .send_encoded_request(length)
        .await
        .expect("second direct TUN send");
    let (length, second_peer) = second_echo
        .recv_from(&mut raw)
        .await
        .expect("second direct TUN receive");
    assert_eq!(&raw[..length], b"second-target");
    assert_eq!(second_peer, peer, "one direct socket serves every target");
    second_echo
        .send_to(b"second-reply", second_peer)
        .await
        .unwrap();
    let length = association.receive_response_wire().await.unwrap();
    let response = association
        .prepare_application_response(&engine, &routing.outbounds, length)
        .unwrap_or_else(|_| panic!("second direct TUN response"));
    assert_eq!(response.datagram().target(), &second_target);
    assert_eq!(response.datagram().payload(), b"second-reply");
    association.recycle_application_response(response);
    assert!(live_ids.lock().expect("live SIP022 IDs").is_empty());
}
