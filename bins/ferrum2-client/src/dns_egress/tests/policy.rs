use super::*;

async fn answer_policy_a(socket: &UdpSocket, expected: &str, address: Ipv4Addr) {
    let mut wire = [0_u8; 4096];
    let (length, peer) = socket.recv_from(&mut wire).await.expect("DNS query");
    let request = Message::from_vec(&wire[..length]).expect("DNS query decode");
    let [query] = request.queries.as_slice() else {
        panic!("one DNS question");
    };
    assert_eq!(query.name().to_ascii(), expected);
    assert_eq!(query.query_type(), RecordType::A);
    let mut response = Message::response(request.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    response.add_answer(Record::from_rdata(
        query.name().clone(),
        60,
        RData::A(A(address)),
    ));
    socket
        .send_to(&response.to_vec().expect("DNS response encode"), peer)
        .await
        .expect("DNS response send");
}

async fn assert_no_policy_udp(socket: &UdpSocket, message: &str) {
    let mut wire = [0_u8; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut wire))
            .await
            .is_err(),
        "{message}"
    );
}

#[tokio::test]
async fn materialized_client_policy_is_shared_by_wire_application_and_cache() {
    let socks = reserve_address();
    let dns_listen = reserve_address();
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("local DNS upstream");
    let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fallback DNS upstream");
    let mut source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{socks}"

[[outbounds]]
tag = "direct"
type = "direct"

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
timeout_ms = 200
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "{}"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "dns-in"
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
inbound = "proxy"
network = ["tcp", "udp"]
rule_set = "cnip"
action = "route"
server = "local"
strategy = "ipv4_only"
"#,
        local.local_addr().unwrap(),
        fallback.local_addr().unwrap(),
    );
    for index in 0..63 {
        source.push_str(&format!(
                "\n[[dns.route.rules]]\nqname = [\"unused-{index}.indexed.invalid\"]\naction = \"reject\"\n"
            ));
    }
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-policy-composition-{}-{}.toml",
        std::process::id(),
        socks.port()
    ));
    std::fs::write(&path, source).expect("write V2 client config");
    let prepared = prepare_client(&path).expect("prepare client config");
    let mut ads = MatchSetBuilder::new();
    ads.add_exact_domain("ads.example").unwrap();
    let mut cnip = MatchSetBuilder::new();
    cnip.add_ip("203.0.113.7".parse().unwrap()).unwrap();
    let mut registry = RuleEngineSnapshotBuilder::new(23);
    let ads = registry.add_match_set(ads.build().unwrap()).unwrap();
    let cnip = registry.add_match_set(cnip.build().unwrap()).unwrap();
    let rule_set_ids = [
        registry.add_rule_set("ads", ads).unwrap(),
        registry.add_rule_set("cnip", cnip).unwrap(),
    ];
    let rule_sets = CompiledRuleSetResource::new(
        Arc::new(RuleEngineRegistry::new(registry.build().unwrap())),
        Box::new(rule_set_ids),
    );
    let mut config = finish_client_v2(
        prepared,
        ClientV2Resources::new(Vec::new(), Vec::new(), Some(rule_sets)),
    )
    .expect("finish V2 client config");
    let _ = std::fs::remove_file(path);
    let metrics = Arc::new(Metrics::new());
    crate::run::publish_rule_program_metadata(&config, &metrics);
    let dns = config.dns.take().expect("materialized DNS graph");
    let runtime = crate::run::ClientDnsProxyRuntime::try_new(
        config
            .dns_route
            .as_mut()
            .expect("materialized client DNS policy"),
        dns.runtime,
        None,
        &metrics,
    )
    .expect("client proxy runtime");
    assert_eq!(runtime.contract_snapshot(), (23, 1, 1, Some(16)));
    let (resolver, mut owner) = TaggedResolver::new(
        dns_runtime_specs(&dns.servers),
        dns.timeout,
        dns.max_inflight,
        Arc::new(ferrum2_dns::SystemDnsEgress),
    )
    .expect("tagged DNS resolver");
    owner.ready().await.expect("tagged DNS ready");
    let proxy = Arc::new(runtime.bind(Arc::new(resolver)));

    let name: Name = "ads.example.".parse().unwrap();
    let mut request = Message::new(91, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(name, RecordType::A));
    let response = proxy
        .answer(
            ferrum2_dns::ProxyIngress::Listener(0),
            ferrum2_dns::ProxyTransport::Udp,
            &request.to_vec().unwrap(),
        )
        .await
        .expect("wire reject response");
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.metadata.id, 91);
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert_no_policy_udp(&local, "wire reject reached local upstream").await;
    assert_no_policy_udp(&fallback, "wire reject reached fallback upstream").await;

    let domain = CanonicalDomain::new("hit.example").unwrap();
    let tcp_request = ferrum2_dns::ApplicationResolveRequest::new(
        ferrum2_dns::ApplicationResolveContext::new(0, Network::Tcp),
        &domain,
        std::num::NonZeroU16::new(443).unwrap(),
        crate::run::dns_strategy(dns.runtime.strategy()),
    );
    let hit = proxy.resolve_application(tcp_request);
    let response = answer_policy_a(&local, "hit.example.", Ipv4Addr::new(203, 0, 113, 7));
    let (hit, ()) = tokio::join!(hit, response);
    assert_eq!(
        hit.unwrap(),
        [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
    );
    let udp_request = ferrum2_dns::ApplicationResolveRequest::new(
        ferrum2_dns::ApplicationResolveContext::new(0, Network::Udp),
        &domain,
        std::num::NonZeroU16::new(443).unwrap(),
        crate::run::dns_strategy(dns.runtime.strategy()),
    );
    assert_eq!(
        proxy.resolve_application(udp_request).await.unwrap(),
        [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
    );
    assert_no_policy_udp(&local, "TCP/UDP shared cache missed").await;

    let miss_domain = CanonicalDomain::new("miss.example").unwrap();
    let miss_request = ferrum2_dns::ApplicationResolveRequest::new(
        ferrum2_dns::ApplicationResolveContext::new(0, Network::Tcp),
        &miss_domain,
        std::num::NonZeroU16::new(443).unwrap(),
        crate::run::dns_strategy(dns.runtime.strategy()),
    );
    let miss = proxy.resolve_application(miss_request);
    let responses = async {
        answer_policy_a(&local, "miss.example.", Ipv4Addr::new(198, 51, 100, 9)).await;
        answer_policy_a(&fallback, "miss.example.", Ipv4Addr::new(192, 0, 2, 9)).await;
    };
    let (miss, ()) = tokio::join!(miss, responses);
    assert_eq!(
        miss.unwrap(),
        [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 443))]
    );
    let encoded = metrics.encode_text().expect("DNS policy metrics");
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
    owner.shutdown().await.expect("tagged DNS shutdown");
}
