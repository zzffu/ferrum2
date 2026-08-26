use super::support::*;

#[test]
fn tracked_dns_ruleset_example_prepares_closed_query_and_response_blueprint() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/client-v2-dns-rulesets.toml");
    let prepared = prepare_client(&example).expect("prepare tracked DNS RuleSet example");
    let config = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                2,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                23,
                &[
                    ("ads", suffix_match_set("ads.invalid")),
                    ("ai", suffix_match_set("ai.invalid")),
                    ("cn", suffix_match_set("cn.invalid")),
                    ("cnip", ip_match_set(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))),
                ],
            )),
        ),
    )
    .expect("finish tracked DNS RuleSet example");
    let binding = config
        .dns_route
        .as_ref()
        .and_then(|route| route.policy_blueprint())
        .expect("tracked example policy");
    let registry = binding.registry();
    assert_eq!(registry.generation(), 23);
    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 5);
    assert_eq!(blueprint.response_rule_count(), 1);
    assert_eq!(
        blueprint.rules()[0].action(),
        DnsPolicyActionDescriptor::Reject
    );
    assert_eq!(blueprint.rules()[0].matcher().rule_sets()[0].raw(), 0);
    for (index, server) in [(2, 1), (3, 0), (4, 0)] {
        assert_eq!(
            blueprint.rules()[index].action(),
            DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
                server,
                DnsPolicyAddressStrategy::Ipv4Only,
            ))
        );
    }
    assert_eq!(blueprint.rules()[4].matcher().rule_sets()[0].raw(), 3);
    assert!(
        registry
            .snapshot()
            .rule_set(ferrum2_rule::RuleSetId::from_raw(3))
            .expect("CNIP descriptor")
            .capabilities()
            .ip_cidr
    );
    assert_eq!(
        blueprint.final_route(),
        ferrum2_rule::DnsPolicyRouteDescriptor::new(1, DnsPolicyAddressStrategy::Ipv4Only,)
    );
}

#[test]
fn response_dependent_ruleset_reject_is_closed_and_field_specific() {
    let file = TempConfig::new(CLIENT_V2);
    let prepared = prepare_client(&file.0).expect("prepare response reject case");
    let resources = ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::from_candidates(
            1,
            Box::new(["[2001:db8::53]:443".parse().unwrap()]),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        Some(compiled_rule_sets(
            7,
            &[("ads", ip_match_set(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))))],
        )),
    );
    let error = match finish_client_v2(prepared, resources) {
        Ok(_) => panic!("IP RuleSet reject was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsRouteRulesAction);
    assert!(!format!("{error:?} {error}").contains("blocked"));
}
