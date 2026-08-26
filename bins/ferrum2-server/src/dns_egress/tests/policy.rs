use super::*;

pub(super) fn materialized_server_test_config_source(
    label: &str,
    source: &str,
) -> (std::path::PathBuf, ferrum2_config::ValidatedServerConfig) {
    let (path, _) = server_test_config_source(label, source);
    let prepared = prepare_server(&path).expect("prepare server test config");
    let config = finish_server_v2(prepared, ServerV2Resources::new(Vec::new(), None))
        .expect("finish server test config");
    (path, config)
}

#[tokio::test]
async fn materialized_policy_proxy_composes_reject_cnip_cache_generation_and_no_fallback() {
    let listen = reserve_address();
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("local DNS upstream");
    let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fallback DNS upstream");
    let dead = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("dead DNS upstream");
    let mut source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "app"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cnip"
type = "remote"
url = "https://rules.example.invalid/cnip.srs"
download_resolver = "system"

[dns]
timeout_ms = 100
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "dead"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "{}"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "app"
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
inbound = "app"
network = "tcp"
domain = "dead.example"
port = 443
action = "route"
server = "dead"

[[dns.route.rules]]
inbound = "app"
network = ["tcp", "udp"]
rule_set = "cnip"
port = 443
action = "route"
server = "local"
strategy = "ipv4_only"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        local.local_addr().unwrap(),
        dead.local_addr().unwrap(),
        fallback.local_addr().unwrap(),
    );
    for index in 0..62 {
        source.push_str(&format!(
                "\n[[dns.route.rules]]\ndomain = [\"unused-{index}.indexed.invalid\"]\naction = \"reject\"\n"
            ));
    }
    let path = std::env::temp_dir().join(format!(
        "ferrum2-server-policy-composition-{}-{}.toml",
        std::process::id(),
        listen.port()
    ));
    std::fs::write(&path, source).expect("write V2 server config");
    let prepared = prepare_server(&path).expect("prepare server config");
    let mut ads = MatchSetBuilder::new();
    ads.add_exact_domain("ads.example").unwrap();
    let mut cnip = MatchSetBuilder::new();
    cnip.add_ip("203.0.113.7".parse().unwrap()).unwrap();
    let mut snapshot = RuleEngineSnapshotBuilder::new(17);
    let ads = snapshot.add_match_set(ads.build().unwrap()).unwrap();
    let cnip = snapshot.add_match_set(cnip.build().unwrap()).unwrap();
    let rule_set_ids = [
        snapshot.add_rule_set("ads", ads).unwrap(),
        snapshot.add_rule_set("cnip", cnip).unwrap(),
    ];
    let rule_sets = CompiledRuleSetResource::new(
        Arc::new(RuleEngineRegistry::new(snapshot.build().unwrap())),
        Box::new(rule_set_ids),
    );
    let mut config = finish_server_v2(
        prepared,
        ServerV2Resources::new(Vec::new(), Some(rule_sets)),
    )
    .expect("finish V2 server config");
    let _ = std::fs::remove_file(path);
    let metrics = Arc::new(Metrics::new());
    crate::run::publish_rule_program_metadata(&config, &metrics);
    let dns = config.dns.take().expect("materialized DNS graph");
    let specs = dns_runtime_specs(&dns.servers);
    let state = Arc::new(
        ServerDnsState::try_new(
            config.dns_route.take().expect("compiled DNS policy"),
            dns.runtime,
        )
        .expect("policy DNS state")
        .with_policy_observer(dns_policy_observer(&metrics)),
    );
    let proxy = &state.proxy_runtime;
    assert_eq!(proxy.policy.registry.generation(), 17);
    assert_eq!(proxy.cache.as_ref().unwrap().capacity().unwrap(), 16);
    let (tagged, mut owner) = TaggedResolver::new(
        specs,
        dns.timeout,
        dns.max_inflight,
        Arc::new(ServerDnsEgress::test(config.outbounds.len())),
    )
    .expect("tagged DNS resolver");
    owner.ready().await.expect("tagged DNS ready");
    state
        .install(Arc::new(tagged))
        .expect("install policy DNS proxy");
    let tcp = ServerDnsResolver::new_observed(Some(Arc::clone(&state)), Arc::clone(&metrics))
        .for_inbound(0);
    let udp = tcp.for_inbound(0);
    assert_eq!(tcp.mode(), ApplicationResolverMode::Configured);
    assert!(tcp.shares_application_resolver_with(&udp));
    assert_eq!(tcp.adapter.strategy(), DnsStrategy::Ipv4Only);

    assert!(
        TcpResolver::resolve(&tcp, "ads.example", 443)
            .await
            .is_err()
    );
    assert_pending(
        local.recv_from(&mut [0_u8; 1]),
        "ads reached local upstream",
    )
    .await;
    assert_pending(
        fallback.recv_from(&mut [0_u8; 1]),
        "ads reached fallback upstream",
    )
    .await;

    let hit = TcpResolver::resolve(&tcp, "hit.example", 443);
    let response = answer_a(&local, "hit.example.", Ipv4Addr::new(203, 0, 113, 7));
    let (hit, ()) = tokio::join!(hit, response);
    assert_eq!(
        hit.unwrap(),
        [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
    );
    assert_eq!(
        UdpResolver::resolve(&udp, "hit.example", 443)
            .await
            .unwrap(),
        [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
    );
    assert_pending(
        local.recv_from(&mut [0_u8; 1]),
        "TCP/UDP shared cache missed",
    )
    .await;

    let miss = TcpResolver::resolve(&tcp, "miss.example", 443);
    let responses = async {
        answer_a(&local, "miss.example.", Ipv4Addr::new(198, 51, 100, 9)).await;
        answer_a(&fallback, "miss.example.", Ipv4Addr::new(192, 0, 2, 9)).await;
    };
    let (miss, ()) = tokio::join!(miss, responses);
    assert_eq!(
        miss.unwrap(),
        [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 443))]
    );

    let failure = TcpResolver::resolve(&tcp, "dead.example", 443);
    let observed_dead = async {
        let mut wire = [0_u8; 4096];
        let (length, _) = recv_udp(&dead, &mut wire).await;
        let request = Message::from_vec(&wire[..length]).unwrap();
        assert_eq!(request.queries[0].name().to_ascii(), "dead.example.");
    };
    let (failure, ()) = tokio::join!(failure, observed_dead);
    assert!(failure.is_err(), "selected failure must be terminal");
    assert_pending(
        fallback.recv_from(&mut [0_u8; 1]),
        "selected failure reached fallback",
    )
    .await;

    let encoded = metrics.encode_text().expect("server DNS policy metrics");
    for expected in [
        "ferrum2_rule_program_mode{program=\"dns_query\",mode=\"indexed\"} 1",
        "ferrum2_rule_program_mode{program=\"dns_response\",mode=\"indexed\"} 1",
        "ferrum2_rule_program_rules{program=\"dns_query\"} 65",
        "ferrum2_rule_program_rules{program=\"dns_response\"} 1",
        "ferrum2_dns_rule_query_match_total{source=\"rule_set\",type=\"domain\",result=\"matched\"} 1",
        "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"matched\"} 2",
        "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"missed\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"dns_query\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"dns_query\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"dns_query\"}",
        "ferrum2_rule_program_match_ns_count{program=\"dns_query\"}",
        "ferrum2_rule_program_candidate_count_sum{program=\"dns_response\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"dns_response\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"dns_response\"}",
        "ferrum2_rule_program_match_ns_count{program=\"dns_response\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }

    drop(tcp);
    drop(udp);
    drop(state.take());
    owner.shutdown().await.expect("tagged DNS shutdown");
}

#[tokio::test]
async fn tagged_dns_selection_uses_authenticated_original_context_and_final() {
    let listen = reserve_address();
    let selected_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("selected DNS upstream");
    let selected_address = selected_socket.local_addr().expect("selected DNS address");
    let final_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("final DNS upstream");
    let final_address = final_socket.local_addr().expect("final DNS address");
    let dead_address = reserve_address();
    let source = format!(
        "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{listen}\"\n\
             [[outbounds]]\n\
             tag = \"direct\"\n\
             [route]\n\
             final = \"direct\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [dns]\n\
             timeout_ms = 100\n\
             [[dns.servers]]\n\
             tag = \"selected\"\n\
             transport = \"udp\"\n\
             address = \"{selected_address}\"\n\
             [[dns.servers]]\n\
             tag = \"dead\"\n\
             transport = \"udp\"\n\
             address = \"{dead_address}\"\n\
             [[dns.servers]]\n\
             tag = \"final\"\n\
             transport = \"udp\"\n\
             address = \"{final_address}\"\n\
             [dns.route]\n\
             final = \"final\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"exact.test\"\n\
             port = 53\n\
             action = \"route\"\n\
             server = \"selected\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"dead.example.com\"\n\
             port = 443\n\
             action = \"route\"\n\
             server = \"dead\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = [\"tcp\", \"udp\"]\n\
             domain_suffix = \"example.com\"\n\
             port_range = \"443:8443\"\n\
             action = \"route\"\n\
             server = \"selected\"\n"
    );
    let (path, mut config) = materialized_server_test_config_source("dns-policy", &source);
    let dns = config.dns.expect("server DNS config");
    let specs = dns_runtime_specs(&dns.servers);
    let state = Arc::new(
        ServerDnsState::try_new(
            config.dns_route.take().expect("compiled DNS policy"),
            dns.runtime,
        )
        .expect("server DNS state"),
    );

    let selected_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for expected_qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::A,
            RecordType::AAAA,
        ] {
            let (length, peer) = recv_udp(&selected_socket, &mut wire).await;
            let request = Message::from_vec(&wire[..length]).expect("selected DNS query decode");
            assert_eq!(request.metadata.message_type, MessageType::Query);
            assert_eq!(request.metadata.op_code, OpCode::Query);
            let [query] = request.queries.as_slice() else {
                panic!("selected upstream must receive one DNS query");
            };
            assert_eq!(query.query_class(), DNSClass::IN);
            assert_eq!(query.query_type(), expected_qtype);
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            let response = response.to_vec().expect("selected DNS response encode");
            selected_socket
                .send_to(&response, peer)
                .await
                .expect("selected DNS response");
        }
    });
    let (check_final, start_final_check) = tokio::sync::oneshot::channel();
    let final_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for expected_qtype in [RecordType::A, RecordType::AAAA] {
            let (length, peer) = recv_udp(&final_socket, &mut wire).await;
            let request = Message::from_vec(&wire[..length]).expect("final DNS query decode");
            assert_eq!(request.metadata.message_type, MessageType::Query);
            assert_eq!(request.metadata.op_code, OpCode::Query);
            let [query] = request.queries.as_slice() else {
                panic!("final upstream must receive one DNS query");
            };
            assert_eq!(query.query_class(), DNSClass::IN);
            assert_eq!(query.query_type(), expected_qtype);
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            let response = response.to_vec().expect("final DNS response encode");
            final_socket
                .send_to(&response, peer)
                .await
                .expect("final DNS response");
        }
        start_final_check.await.expect("start no-fallback check");
        assert_pending(
            final_socket.recv_from(&mut wire),
            "selected DNS failure reached the healthy final server",
        )
        .await;
    });
    let egress = Arc::new(ServerDnsEgress::test(config.outbounds.len()));
    let (resolver, mut owner) = TaggedResolver::new(specs, dns.timeout, dns.max_inflight, egress)
        .expect("server DNS resolver");
    owner.ready().await.expect("server DNS resolver ready");
    state
        .install(Arc::new(resolver))
        .expect("install server DNS resolver");
    let resolver = ServerDnsResolver::new(Some(Arc::clone(&state))).for_inbound(0);
    let udp_resolver = resolver.for_inbound(0);

    assert_eq!(resolver.mode(), ApplicationResolverMode::Configured);
    assert!(resolver.shares_application_resolver_with(&udp_resolver));

    assert!(
        TcpResolver::resolve(&resolver, "EXACT.TEST.", 53)
            .await
            .is_err()
    );
    assert!(
        TcpResolver::resolve(&resolver, "api.example.com.", 443)
            .await
            .is_err()
    );
    assert!(
        TcpResolver::resolve(&resolver, "other.test.", 443)
            .await
            .is_err()
    );
    check_final.send(()).expect("arm no-fallback check");
    assert!(
        TcpResolver::resolve(&resolver, "dead.example.com.", 443)
            .await
            .is_err(),
        "selected DNS failure must remain terminal"
    );

    selected_task.await.expect("selected DNS upstream join");
    final_task.await.expect("final DNS upstream join");
    drop(resolver);
    drop(state.take());
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("server DNS resolver shutdown")
            .stats,
        ferrum2_dns::RuntimeStats::default()
    );
    std::fs::remove_file(path).expect("remove server DNS policy config");
}
