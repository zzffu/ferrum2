use super::support::*;

fn policy_source(rules: &str) -> String {
    let prefix = CLIENT_V2.split("[[dns.route.rules]]").next().unwrap();
    format!("{prefix}{rules}\n")
}

fn policy_resources(set: Arc<CompiledMatchSet>) -> ClientV2Resources {
    ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::from_candidates(
            1,
            Box::new(["[2001:db8::53]:443".parse().unwrap()]),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        Some(compiled_rule_sets(7, &[("ads", set)])),
    )
}

#[test]
fn explicit_policy_rejects_invalid_stages_and_action_fields_offline() {
    let evaluate = "[[dns.route.rules]]\naction = \"evaluate\"\nserver = \"bootstrap\"\n";
    let cases = [
        ("[[dns.route.rules]]\nmatch_response = true\naction = \"reject\"\n".to_owned(), ConfigField::DnsRouteRulesMatchResponse),
        ("[[dns.route.rules]]\naction = \"respond\"\n".to_owned(), ConfigField::DnsRouteRulesAction),
        ("[[dns.route.rules]]\nmatch_response = true\naction = \"evaluate\"\nserver = \"bootstrap\"\n".to_owned(), ConfigField::DnsRouteRulesMatchResponse),
        ("[[dns.route.rules]]\naction = \"evaluate\"\n".to_owned(), ConfigField::DnsRouteRulesServer),
        (format!("{evaluate}[[dns.route.rules]]\naction = \"respond\"\nserver = \"local\"\n"), ConfigField::DnsRouteRulesServer),
        (format!("{evaluate}[[dns.route.rules]]\naction = \"respond\"\nstrategy = \"ipv4_only\"\n"), ConfigField::DnsRouteRulesStrategy),
        (format!("{evaluate}[[dns.route.rules]]\naction = \"respond\"\noutbound = \"main\"\n"), ConfigField::DnsRouteRulesServer),
        ("[[dns.route.rules]]\naction = \"evaluate\"\nserver = \"bootstrap\"\noutbound = \"main\"\n".to_owned(), ConfigField::DnsRouteRulesServer),
        ("[[dns.route.rules]]\naction = \"reject\"\nstrategy = \"ipv4_only\"\n".to_owned(), ConfigField::DnsRouteRulesStrategy),
    ];
    for (rules, field) in cases {
        let file = TempConfig::new(&policy_source(&rules));
        let error = prepare_client(&file.0).expect_err("invalid explicit DNS policy accepted");
        assert_eq!(error.field(), field);
        assert!(!format!("{error:?} {error}").contains("bootstrap"));
    }
}

#[test]
fn materialization_rejects_implicit_cidr_and_non_address_response_sets() {
    let cases = [
        (
            "[[dns.route.rules]]\naction = \"route\"\nserver = \"bootstrap\"\nrule_set = \"ads\"\n",
            ip_match_set(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ),
        (
            "[[dns.route.rules]]\naction = \"evaluate\"\nserver = \"bootstrap\"\n[[dns.route.rules]]\nmatch_response = true\nrule_set = \"ads\"\naction = \"reject\"\n",
            suffix_match_set("blocked.invalid"),
        ),
    ];
    for (rules, set) in cases {
        let file = TempConfig::new(&policy_source(rules));
        let prepared =
            prepare_client(&file.0).expect("capabilities deferred until materialization");
        let error = match finish_client_v2(prepared, policy_resources(set)) {
            Ok(_) => panic!("incompatible RuleSet capability accepted"),
            Err(error) => error,
        };
        assert_eq!(error.field(), ConfigField::DnsRouteRulesRuleSet);
        assert!(!format!("{error:?} {error}").contains("blocked"));
    }
}

#[test]
fn unconditional_evaluation_response_reject_and_empty_response_constraints_materialize() {
    let source = policy_source(
        r#"
[[dns.route.rules]]
action = "evaluate"
server = "bootstrap"
strategy = "ipv6_only"

[[dns.route.rules]]
match_response = true
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
match_response = true
rule_set = []
action = "respond"
"#,
    );
    let file = TempConfig::new(&source);
    let prepared = prepare_client(&file.0).expect("prepare explicit response policy");
    let mut mixed = MatchSetBuilder::new();
    mixed.add_domain_suffix("blocked.invalid").unwrap();
    mixed.add_ip_cidr("10.0.0.0/8".parse().unwrap()).unwrap();
    let mixed = Arc::new(mixed.build().unwrap());
    finish_client_v2(prepared, policy_resources(Arc::clone(&mixed)))
        .expect("mixed CIDR-capable RuleSet is valid in response mode");

    let query_source = source.replace(
        "match_response = true\nrule_set = \"ads\"",
        "match_response = false\nrule_set = \"ads\"",
    );
    let file = TempConfig::new(&query_source);
    let prepared =
        prepare_client(&file.0).expect("query capabilities deferred until materialization");
    let error = match finish_client_v2(prepared, policy_resources(mixed)) {
        Ok(_) => panic!("same mixed RuleSet was accepted in query mode"),
        Err(error) => error,
    };
    assert_eq!(error.field(), ConfigField::DnsRouteRulesRuleSet);
}
