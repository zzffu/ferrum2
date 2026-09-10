use ferrum2_rule::{
    DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    DnsPolicyBlueprintError, DnsPolicyMatchMode, DnsPolicyMatcherDescriptor,
    DnsPolicyRouteDescriptor, DnsPolicyRuleDescriptor, MatchSetBuilder, RuleEngineSnapshotBuilder,
    RuleSetId,
};

fn route() -> DnsPolicyRouteDescriptor {
    DnsPolicyRouteDescriptor::new(0, DnsPolicyAddressStrategy::PreferIpv4)
}

fn rule(
    rule_sets: Vec<RuleSetId>,
    mode: DnsPolicyMatchMode,
    action: DnsPolicyActionDescriptor,
) -> DnsPolicyRuleDescriptor {
    DnsPolicyRuleDescriptor::new(
        DnsPolicyMatcherDescriptor::try_new(
            vec![],
            rule_sets,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap(),
        mode,
        action,
    )
}

#[test]
fn later_or_same_row_evaluation_does_not_authorize_response_use() {
    let snapshot = RuleEngineSnapshotBuilder::new(1).build().unwrap();
    for (mode, action, expected) in [
        (
            DnsPolicyMatchMode::Query,
            DnsPolicyActionDescriptor::Respond,
            DnsPolicyBlueprintError::RespondWithoutEvaluate,
        ),
        (
            DnsPolicyMatchMode::Response,
            DnsPolicyActionDescriptor::Reject,
            DnsPolicyBlueprintError::ResponseMatchWithoutEvaluate,
        ),
        (
            DnsPolicyMatchMode::Response,
            DnsPolicyActionDescriptor::Evaluate(route()),
            DnsPolicyBlueprintError::ResponseMatchWithoutEvaluate,
        ),
    ] {
        let rules = vec![
            rule(vec![], mode, action),
            rule(
                vec![],
                DnsPolicyMatchMode::Query,
                DnsPolicyActionDescriptor::Evaluate(route()),
            ),
        ];
        assert_eq!(
            DnsPolicyBlueprint::try_new(rules, route(), &snapshot).unwrap_err(),
            expected
        );
    }
}

#[test]
fn cidr_capability_is_explicit_even_for_mixed_rulesets() {
    let mut sets = RuleEngineSnapshotBuilder::new(1);
    let mut mixed = MatchSetBuilder::new();
    mixed.add_exact_domain("example.invalid").unwrap();
    mixed.add_ip_cidr("192.0.2.0/24".parse().unwrap()).unwrap();
    let mixed = sets.add_match_set(mixed.build().unwrap()).unwrap();
    let mixed = sets.add_rule_set("mixed", mixed).unwrap();
    let mut domains = MatchSetBuilder::new();
    domains.add_exact_domain("example.invalid").unwrap();
    let domains = sets.add_match_set(domains.build().unwrap()).unwrap();
    let domains = sets.add_rule_set("domains", domains).unwrap();
    let snapshot = sets.build().unwrap();
    for (id, mode, expected) in [
        (
            mixed,
            DnsPolicyMatchMode::Query,
            DnsPolicyBlueprintError::QueryModeCidrRuleSet,
        ),
        (
            domains,
            DnsPolicyMatchMode::Response,
            DnsPolicyBlueprintError::ResponseModeRequiresCidrRuleSet,
        ),
        (
            RuleSetId::from_raw(99),
            DnsPolicyMatchMode::Response,
            DnsPolicyBlueprintError::UnknownRuleSet,
        ),
    ] {
        let rules = vec![
            rule(
                vec![],
                DnsPolicyMatchMode::Query,
                DnsPolicyActionDescriptor::Evaluate(route()),
            ),
            rule(vec![id], mode, DnsPolicyActionDescriptor::Reject),
        ];
        assert_eq!(
            DnsPolicyBlueprint::try_new(rules, route(), &snapshot).unwrap_err(),
            expected
        );
    }
    let rules = vec![
        rule(
            vec![],
            DnsPolicyMatchMode::Query,
            DnsPolicyActionDescriptor::Evaluate(route()),
        ),
        rule(
            vec![mixed],
            DnsPolicyMatchMode::Response,
            DnsPolicyActionDescriptor::Reject,
        ),
        rule(
            vec![],
            DnsPolicyMatchMode::Response,
            DnsPolicyActionDescriptor::Respond,
        ),
    ];
    let policy = DnsPolicyBlueprint::try_new(rules, route(), &snapshot).unwrap();
    assert_eq!(policy.response_rule_count(), 2);
}
