use super::support::*;

#[test]
fn finish_client_replaces_domain_endpoints_and_captures_one_registry() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client(&file.0).expect("prepare client V2");
    let config = finish_client_v2(prepared, valid_client_resources()).expect("finish client V2");

    assert_eq!(
        config.outbounds[1].server(),
        Some("198.51.100.10:8388".parse().unwrap())
    );
    let resolved_server = &config.dns.as_ref().unwrap().servers[1];
    assert_eq!(
        resolved_server.target.canonical_domain().unwrap().as_str(),
        "dns.example.test"
    );
    assert_eq!(
        resolved_server.resolved_targets.as_ref(),
        &[
            "[2001:db8::53]:443".parse().unwrap(),
            "[2001:db8::54]:443".parse().unwrap(),
        ]
    );
    assert_eq!(
        config.dns.as_ref().unwrap().servers[0].endpoint_mode,
        DnsEndpointMode::Numeric
    );
    assert_eq!(
        config.dns.as_ref().unwrap().servers[1].endpoint_mode,
        DnsEndpointMode::ClientResolved {
            resolver: ResolverRef::System,
            strategy: DnsStrategy::Ipv6Only,
        }
    );
    let dns_runtime = config.dns.as_ref().unwrap().runtime;
    assert_eq!(dns_runtime.strategy(), DnsStrategy::PreferIpv6);
    assert_eq!(dns_runtime.cache().max_entries, 8_192);
    let route = &config.route;
    let registry = route.rule_registry().expect("RuleSet registry");
    assert_eq!(registry.generation(), 7);
    assert_eq!(registry.snapshot().rule_set_count(), 1);

    let dns_route = config.dns_route.as_ref().expect("compiled DNS route");
    assert!(dns_route.policy_blueprint().is_some());
    let binding = dns_route
        .policy_blueprint()
        .expect("materialized DNS policy blueprint");
    let dns_registry = binding.registry();
    assert!(Arc::ptr_eq(&registry, &dns_registry));
    assert_eq!(binding.listener_count(), 1);
    assert_eq!(binding.ordinary_count(), 1);
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(0)), Some(0));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Ordinary(0)), Some(1));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(1)), None);

    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 2);
    let special = &blueprint.rules()[0];
    assert_eq!(
        special.action(),
        DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
            1,
            DnsPolicyAddressStrategy::Ipv6Only,
        ))
    );
    assert!(
        special.matcher().query_fields()[0]
            .matches_domain(&CanonicalDomain::new("very-special.example").expect("special probe"))
    );
    let ads = &blueprint.rules()[1];
    assert_eq!(ads.action(), DnsPolicyActionDescriptor::Reject);
    assert_eq!(
        ads.matcher().rule_sets(),
        [ferrum2_rule::RuleSetId::from_raw(0)]
    );

    let target = TargetAddr::domain("blocked.example", 443).unwrap();
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
    assert_eq!(evaluation.snapshot_generation(), Some(7));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));
}

#[test]
fn materialized_v2_dns_runtime_uses_configured_defaults() {
    let source = CLIENT_V2
        .replace("strategy = \"prefer_ipv6\"\n", "")
        .replace("\n[dns.cache]\nenabled = true\nmax_entries = 8192\n", "");
    assert!(!source.contains("[dns.cache]"));
    let file = TempConfig::new(&source);
    let prepared = prepare_client(&file.0).expect("prepare default DNS runtime");
    let prepared_runtime = prepared.dns_runtime().expect("prepared default runtime");
    assert_eq!(prepared_runtime.strategy(), DnsStrategy::PreferIpv4);
    assert_eq!(
        prepared_runtime.cache(),
        ferrum2_config::DnsCacheConfig {
            enabled: true,
            max_entries: 8_192,
        }
    );

    let config = finish_client_v2(prepared, valid_client_resources()).expect("finish defaults");
    let runtime = config.dns.as_ref().unwrap().runtime;
    assert_eq!(runtime, prepared_runtime);
}

#[test]
fn finish_server_rulesets_are_ored_anded_and_match_a_sniffed_domain() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "ss-in"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "first"
type = "remote"
url = "https://rules.example.test/first.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "second"
type = "remote"
url = "https://rules.example.test/second.srs"
download_resolver = "system"

[[route.rules]]
network = "tcp"
action = "sniff"
sniffers = "tls"

[[route.rules]]
network = "tcp"
rule_set = ["first", "second"]
action = "reject"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_server(&file.0).expect("prepare server RuleSets");
    let config = finish_server_v2(
        prepared,
        ServerV2Resources::new(
            vec![],
            Some(compiled_rule_sets(
                9,
                &[
                    ("first", exact_match_set("first.example")),
                    ("second", exact_match_set("sniffed.example")),
                ],
            )),
        ),
    )
    .expect("finish server RuleSets");
    let route = &config.route;
    let original = TargetAddr::ip("192.0.2.10:443".parse().unwrap()).unwrap();
    let sniffed = DomainName::new("SNIFFED.EXAMPLE.").unwrap();
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(0, Network::Tcp, &original, &mut scratch);
    assert_eq!(evaluation.snapshot_generation(), Some(9));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(RouteAction::Sniff(_)))
    ));
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, Some(&sniffed))),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));

    let target = TargetAddr::domain("sniffed.example", 443).unwrap();
    let mut wrong_scratch = route.evaluation_scratch().expect("route scratch");
    let mut wrong_network =
        route.evaluate_with_scratch(0, Network::Udp, &target, &mut wrong_scratch);
    assert!(matches!(
        wrong_network.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(RouteAction::Route(_)))
    ));
}

#[test]
fn server_dns_policy_uses_ruleset_or_external_and_application_namespace() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "app"
listen = "127.0.0.1:8388"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "first"
type = "remote"
url = "https://rules.example.test/first.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "second"
type = "remote"
url = "https://rules.example.test/second.srs"
download_resolver = "system"

[dns]

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "192.0.2.54:53"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "app"
network = "tcp"
domain_keyword = "service"
rule_set = ["first", "second"]
port = 443
port_range = "400:500"
action = "route"
server = "local"
strategy = "ipv6_only"

[[dns.route.rules]]
domain = "exact.invalid"
port = 8443
action = "route"
server = "local"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_server(&file.0).expect("prepare server DNS policy");
    let config = finish_server_v2(
        prepared,
        ServerV2Resources::new(
            vec![],
            Some(compiled_rule_sets(
                11,
                &[
                    ("first", exact_match_set("first.invalid")),
                    ("second", suffix_match_set("allowed.invalid")),
                ],
            )),
        ),
    )
    .expect("finish server DNS policy");
    let route_registry = config
        .route
        .rule_registry()
        .expect("ordinary route registry");
    let dns_route = config.dns_route.as_ref().expect("server DNS route");
    assert!(dns_route.policy_blueprint().is_some());
    let binding = dns_route
        .policy_blueprint()
        .expect("server DNS policy blueprint");
    let registry = binding.registry();
    assert!(Arc::ptr_eq(&route_registry, &registry));
    assert_eq!(registry.generation(), 11);
    assert_eq!(binding.listener_count(), 0);
    assert_eq!(binding.ordinary_count(), 1);
    assert_eq!(binding.resolve_ingress(DnsIngressId::Ordinary(0)), Some(0));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(0)), None);

    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 2);
    let matching = &blueprint.rules()[0];
    assert_eq!(matching.matcher().inbounds(), [0]);
    assert_eq!(matching.matcher().networks(), [Network::Tcp]);
    assert_eq!(matching.matcher().ports()[0].get(), 443);
    assert_eq!(matching.matcher().port_ranges()[0].first().get(), 400);
    assert_eq!(matching.matcher().port_ranges()[0].last().get(), 500);
    assert_eq!(matching.matcher().rule_sets().len(), 2);
    assert!(
        matching.matcher().query_fields()[0].matches_domain(
            &CanonicalDomain::new("service.allowed.invalid").expect("keyword probe")
        )
    );
    assert_eq!(
        matching.action(),
        DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
            0,
            DnsPolicyAddressStrategy::Ipv6Only,
        ))
    );
    let target = &blueprint.rules()[1];
    assert!(
        target.matcher().query_fields()[0]
            .matches_domain(&CanonicalDomain::new("exact.invalid").expect("target probe"))
    );
    assert_eq!(target.matcher().ports()[0].get(), 8443);
    assert_eq!(
        blueprint.final_route(),
        ferrum2_rule::DnsPolicyRouteDescriptor::new(1, DnsPolicyAddressStrategy::PreferIpv4,)
    );
}
