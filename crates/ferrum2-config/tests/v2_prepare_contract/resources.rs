use super::support::*;

#[test]
fn client_prepare_retains_closed_resources_without_materializing() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client(&file.0).expect("prepare client V2");

    assert_eq!(
        prepared.rule_set_loader().cache_dir,
        PathBuf::from("./cache")
    );
    assert_eq!(
        prepared.rule_set_loader().download_timeout,
        Duration::from_secs(15)
    );
    assert_eq!(prepared.dns_strategy(), Some(DnsStrategy::PreferIpv6));
    assert_eq!(prepared.dns_cache().unwrap().max_entries, 8192);
    let dns_runtime = prepared.dns_runtime().expect("prepared DNS runtime");
    assert_eq!(dns_runtime.strategy(), DnsStrategy::PreferIpv6);
    assert_eq!(dns_runtime.cache(), prepared.dns_cache().unwrap());
    assert_eq!(prepared.dns_timeout(), Some(Duration::from_secs(5)));
    assert_eq!(prepared.dns_max_inflight().unwrap().get(), 256);
    assert_eq!(prepared.rule_sets().len(), 1);
    assert_eq!(
        prepared.rule_sets()[0].download_mode(),
        PreparedRuleSetDownloadMode::ClientResolved {
            resolver: ResolverRef::DnsServer(0),
        }
    );
    assert_eq!(
        prepared.rule_sets()[0].download_detour(),
        Some(PreparedEgressRef::Selector(0))
    );
    assert_eq!(prepared.route_rule_sets()[0].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[0].rule_sets, []);
    assert_eq!(
        prepared.dns_rules()[0].action,
        PreparedDnsAction::Route { server: 1 }
    );
    assert_eq!(prepared.dns_rules()[0].strategy, DnsStrategy::Ipv6Only);
    assert_eq!(prepared.dns_rules()[1].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[1].action, PreparedDnsAction::Reject);
    assert!(prepared.outbound_endpoints()[0].is_none());
    assert!(matches!(
        prepared.outbound_endpoints()[1],
        Some(DialEndpoint::Domain {
            resolver: ResolverRef::DnsServer(0),
            strategy: DnsStrategy::Ipv4Only,
            ..
        })
    ));
    assert_eq!(
        prepared.dns_endpoints()[0].mode(),
        PreparedDnsEndpointMode::Numeric
    );
    assert_eq!(
        prepared.dns_endpoints()[1].mode(),
        PreparedDnsEndpointMode::ClientResolved {
            resolver: ResolverRef::System,
            strategy: DnsStrategy::Ipv6Only,
        }
    );
    assert_eq!(prepared.dependency_node_count(), 7);
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("RuleSet detour plan")
            .snapshot()
            .hops(),
        &[0]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert!(prepared.download_detour_plan(1).is_none());
    assert_eq!(prepared.download_detour_is_direct(1), None);
    let order = prepared.materialization_order();
    let position = |node| {
        order
            .iter()
            .position(|candidate| *candidate == node)
            .unwrap()
    };
    assert!(
        position(PreparedDependencyNode::SystemResolver)
            < position(PreparedDependencyNode::DnsServer(1))
    );
    assert!(
        position(PreparedDependencyNode::DnsServer(0))
            < position(PreparedDependencyNode::Outbound(1))
    );
    assert!(
        position(PreparedDependencyNode::Outbound(1))
            < position(PreparedDependencyNode::Selector(0))
    );
    assert!(
        position(PreparedDependencyNode::Selector(0))
            < position(PreparedDependencyNode::RuleSet(0))
    );
}

#[test]
fn server_prepare_accepts_shared_rulesets_and_selector_detours() {
    let file = TempConfig::new(SERVER_V2);
    let prepared = prepare_server(&file.0).expect("prepare server V2");
    assert_eq!(
        prepared.outbound(0).unwrap().domain_resolver(),
        DirectDomainResolver::System
    );
    assert_eq!(prepared.dns_timeout(), Some(Duration::from_secs(5)));
    assert_eq!(prepared.dns_max_inflight().unwrap().get(), 256);
    assert_eq!(prepared.rule_sets().len(), 1);
    assert_eq!(
        prepared.rule_sets()[0].download_detour(),
        Some(PreparedEgressRef::Selector(0))
    );
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("server RuleSet detour plan")
            .snapshot()
            .hops(),
        &[0]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert_eq!(prepared.route_rule_sets()[0].rule_sets, [0]);
    assert_eq!(prepared.dns_rules()[0].action, PreparedDnsAction::Reject);
}

#[test]
fn direct_resolver_metadata_is_preserved_for_client_and_server() {
    let client_source = CLIENT_V2.replacen(
        "type = \"direct\"\n",
        concat!(
            "type = \"direct\"\n",
            "domain_resolver = \"local\"\n",
            "domain_strategy = \"ipv4_only\"\n",
        ),
        1,
    );
    let client_file = TempConfig::new(&client_source);
    let client = prepare_client(&client_file.0).expect("explicit client Direct resolver");
    assert_eq!(
        client.outbound(0).unwrap().domain_resolver(),
        Some(DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::Ipv4Only,
        })
    );
    assert_eq!(
        client.accepts_domain_target(PreparedEgressRef::Outbound(0)),
        Some(true)
    );
    let order = client.materialization_order();
    assert!(
        order
            .iter()
            .position(|node| *node == PreparedDependencyNode::DnsServer(0))
            < order
                .iter()
                .position(|node| *node == PreparedDependencyNode::Outbound(0))
    );

    let server_source = r#"
schema_version = 2

[[inbounds]]
tag = "ss-in"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"
domain_resolver = "local"
domain_strategy = "prefer_ipv6"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[dns.route]
final = "local"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let server_file = TempConfig::new(server_source);
    let server = prepare_server(&server_file.0).expect("explicit server Direct resolver");
    assert_eq!(server.outbound_count(), 1);
    assert_eq!(
        server.outbound(0).unwrap().domain_resolver(),
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::PreferIpv6,
        }
    );
    assert_eq!(
        server.accepts_domain_target(PreparedEgressRef::Outbound(0)),
        Some(true)
    );
    let finished = finish_server_v2(server, ServerV2Resources::default())
        .expect("finish server Direct resolver");
    assert_eq!(
        finished.outbounds[0].domain_resolver,
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: DnsStrategy::PreferIpv6,
        }
    );
}

#[test]
fn deferred_dns_and_ruleset_modes_keep_domains_and_need_no_resolver_resources() {
    let source = CLIENT_V2
        .replace(
            concat!(
                "domain_resolver = \"system\"\n",
                "domain_strategy = \"ipv6_only\"\n",
            ),
            "",
        )
        .replace("download_resolver = \"local\"\n", "");
    let file = TempConfig::new(&source);
    let prepared = prepare_client(&file.0).expect("deferred domain targets");
    assert_eq!(
        prepared.dns_endpoints()[1].mode(),
        PreparedDnsEndpointMode::DeferredToDetour
    );
    assert_eq!(
        prepared.dns_endpoints()[1]
            .target()
            .canonical_domain()
            .unwrap()
            .as_str(),
        "dns.example.test"
    );
    assert!(
        prepared
            .fixed_endpoint_for_node(PreparedDependencyNode::DnsServer(1))
            .is_none()
    );
    assert_eq!(
        prepared.rule_sets()[0].download_mode(),
        PreparedRuleSetDownloadMode::DeferredToDetour
    );
    let finished = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                7,
                &[("ads", exact_match_set("blocked.example"))],
            )),
        ),
    )
    .expect("finish deferred domain targets");
    let server = &finished.dns.as_ref().unwrap().servers[1];
    assert_eq!(server.endpoint_mode, DnsEndpointMode::DeferredToDetour);
    assert_eq!(
        server.target.canonical_domain().unwrap().as_str(),
        "dns.example.test"
    );
}

#[test]
fn direct_resolver_cycles_use_the_unified_dependency_cycle_code() {
    let source = CLIENT_V2
        .replacen(
            "type = \"direct\"\n",
            "type = \"direct\"\ndomain_resolver = \"local\"\n",
            1,
        )
        .replacen(
            "address = \"192.0.2.53:53\"\n",
            "address = \"192.0.2.53:53\"\ndetour = \"direct-out\"\n",
            1,
        );
    let file = TempConfig::new(&source);
    let error = prepare_client(&file.0).expect_err("Direct resolver cycle");
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "dns-server[0] -> outbound[0] -> dns-server[0]"
        )
    );
}

#[test]
fn nested_selectors_aggregate_domain_capability_and_cycles_fail_closed() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct-a"
type = "direct"

[[outbounds]]
tag = "direct-b"
type = "direct"

[[selectors]]
tag = "inner"
outbounds = ["direct-a", "direct-b"]
default = "direct-a"

[[selectors]]
tag = "outer"
outbounds = ["inner"]
default = "inner"

[route]
final = "outer"
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client(&file.0).expect("nested selectors");
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Selector(0)),
        Some(true)
    );
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Selector(1)),
        Some(true)
    );

    let cycle = source
        .replace(
            "outbounds = [\"direct-a\", \"direct-b\"]",
            "outbounds = [\"outer\"]",
        )
        .replace("default = \"direct-a\"", "default = \"outer\"");
    let file = TempConfig::new(&cycle);
    let error = prepare_client(&file.0).expect_err("nested selector cycle");
    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "selector[0] -> selector[1] -> selector[0]"
        )
    );
}

#[test]
fn selector_chain_cycle_reports_the_complete_closed_path() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"

[[chains]]
tag = "loop-chain"
hops = ["direct", "loop-selector"]

[[selectors]]
tag = "loop-selector"
outbounds = ["loop-chain"]
default = "loop-chain"

[route]
final = "loop-selector"
"#;
    let file = TempConfig::new(source);
    let error = prepare_client(&file.0).expect_err("selector/chain cycle");

    assert_eq!(error.code(), "config.dependency_cycle");
    assert_eq!(
        error.to_string(),
        concat!(
            "error[config.dependency_cycle] config.dependency_cycle: ",
            "the configuration dependency graph contains a cycle: ",
            "selector[0] -> chain[0] -> selector[0]"
        )
    );
}
