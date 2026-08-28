use std::net::{IpAddr, Ipv4Addr};

use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_rule::{
    MatchSetBuilder, Network, OrderedRouteProgram, OrderedRouteRule, RouteMatchField,
    RouteMatchSource, RouteMatchType, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteRuleAction, RuleCompileError, RuleProgramMode,
};

fn domain(value: &str) -> DomainName {
    DomainName::new(value).expect("test domain")
}

fn target() -> TargetAddr {
    TargetAddr::domain("www.Example.Test.", 443).expect("test target")
}

#[test]
fn match_set_uses_one_canonical_algorithm_for_all_categories() {
    let mut builder = MatchSetBuilder::new();
    builder
        .add_exact_domain("Exact.Example.")
        .unwrap()
        .add_domain_suffix("suffix.example")
        .unwrap()
        .add_domain_keyword("TrAcKeR")
        .unwrap()
        .add_ip_cidr("192.0.2.0/24".parse().unwrap())
        .unwrap()
        .add_ip_cidr("2001:db8::/32".parse().unwrap())
        .unwrap();
    let set = builder.build().unwrap();
    assert_eq!(set.entry_counts().exact_domain, 1);
    assert_eq!(set.entry_counts().domain_suffix, 1);
    assert_eq!(set.entry_counts().domain_keyword, 1);
    assert_eq!(set.entry_counts().ip_cidr, 2);
    assert_eq!(set.entry_counts().total(), 5);

    for value in [
        "exact.example",
        "EXACT.EXAMPLE.",
        "suffix.example",
        "a.suffix.example",
        "cdn-tracker.example",
    ] {
        assert!(
            set.matches_domain(domain(value).canonical().unwrap()),
            "{value}"
        );
    }
    assert!(!set.matches_domain(domain("almostsuffix.example.net").canonical().unwrap()));
    assert!(set.matches_ip("192.0.2.99".parse().unwrap()));
    assert!(set.matches_ip("2001:db8:1::1".parse().unwrap()));
    assert!(!set.matches_ip("198.51.100.1".parse().unwrap()));
}

#[test]
fn match_set_and_matcher_accept_more_than_sixty_four_values() {
    let mut builder = MatchSetBuilder::new();
    for index in 0..1_000 {
        builder
            .add_exact_domain(&format!("host-{index}.example"))
            .unwrap();
    }
    let set = builder.build().unwrap();
    assert!(set.matches_domain(domain("HOST-999.EXAMPLE.").canonical().unwrap()));

    let values = (0..1_000)
        .map(|index| domain(&format!("host-{index}.example")))
        .collect();
    assert!(RouteMatcher::<()>::try_new(vec![RouteMatchField::Domain(values)]).is_ok());
}

#[test]
fn large_suffix_and_cidr_sets_preserve_label_and_address_family_semantics() {
    let mut suffixes = MatchSetBuilder::new();
    for index in 0..65 {
        suffixes
            .add_domain_suffix(&format!("suffix-{index}.example"))
            .unwrap();
    }
    let suffixes = suffixes.build().unwrap();
    assert!(suffixes.matches_domain(domain("child.suffix-64.example").canonical().unwrap()));
    assert!(!suffixes.matches_domain(domain("xsuffix-64.example").canonical().unwrap()));

    let mut v4 = MatchSetBuilder::new();
    for index in 0..65_u8 {
        v4.add_ip_cidr(format!("198.18.{index}.0/24").parse().unwrap())
            .unwrap();
    }
    let v4 = v4.build().unwrap();
    assert!(v4.matches_ip("198.18.64.7".parse().unwrap()));
    assert!(!v4.matches_ip("198.18.65.7".parse().unwrap()));
    assert!(!v4.matches_ip("::ffff:198.18.64.7".parse().unwrap()));

    let mut v6 = MatchSetBuilder::new();
    for index in 0..65_u16 {
        v6.add_ip_cidr(format!("2001:db8:{index:x}::/48").parse().unwrap())
            .unwrap();
    }
    let v6 = v6.build().unwrap();
    assert!(v6.matches_ip("2001:db8:40::7".parse().unwrap()));
    assert!(!v6.matches_ip("2001:db8:41::7".parse().unwrap()));
}

#[test]
fn ordinary_fields_are_anded_while_one_compiled_set_is_ored() {
    let matcher = RouteMatcher::<()>::try_new(vec![
        RouteMatchField::Domain(vec![domain("www.example.test")]),
        RouteMatchField::DomainSuffix(vec![domain("example.test")]),
        RouteMatchField::Port(vec![std::num::NonZeroU16::new(443).unwrap()]),
    ])
    .unwrap();
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal("and"),
        )],
        "miss",
    )
    .unwrap();
    let target = target();
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&"and"))
    );

    let mut builder = MatchSetBuilder::new();
    builder
        .add_exact_domain("different.test")
        .unwrap()
        .add_domain_keyword("example")
        .unwrap()
        .add_ip_cidr("192.0.2.0/24".parse().unwrap())
        .unwrap();
    let matcher =
        RouteMatcher::<()>::try_new(vec![RouteMatchField::MatchSet(builder.build().unwrap())])
            .unwrap();
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal("or"),
        )],
        "miss",
    )
    .unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&"or"))
    );
}

#[test]
fn constructors_report_closed_compile_errors_and_keep_final_explicit() {
    assert!(matches!(
        RouteMatcher::<()>::try_new(Vec::new()),
        Err(RuleCompileError::EmptyMatcher)
    ));
    assert!(matches!(
        RouteMatcher::<()>::try_new(vec![RouteMatchField::Inbound(Vec::new())]),
        Err(RuleCompileError::EmptyField)
    ));
    assert!(matches!(
        RouteMatcher::<()>::try_new(vec![
            RouteMatchField::Inbound(vec![1]),
            RouteMatchField::Inbound(vec![2]),
        ]),
        Err(RuleCompileError::DuplicateField)
    ));
    let program = OrderedRouteProgram::<(), _>::try_new(Vec::new(), 9).unwrap();
    let target = target();
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_scratch(0, Network::Udp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&9))
    );
}

fn reference_program(count: usize) -> OrderedRouteProgram<u16, usize> {
    let rules = (0..count)
        .map(|index| {
            OrderedRouteRule::new(
                RouteMatcher::try_new(vec![
                    RouteMatchField::Inbound(vec![index % 31]),
                    RouteMatchField::Protocol(vec![(index % 19) as u16]),
                    RouteMatchField::Network(vec![if index % 2 == 0 {
                        Network::Tcp
                    } else {
                        Network::Udp
                    }]),
                ])
                .unwrap(),
                RouteRuleAction::Terminal(index),
            )
        })
        .collect();
    OrderedRouteProgram::try_new(rules, usize::MAX).unwrap()
}

#[test]
fn indexed_programs_match_scalar_reference_at_one_and_ten_thousand_rules() {
    let target = target();
    for count in [1_000, 10_000] {
        let program = reference_program(count);
        assert_eq!(program.mode(), RuleProgramMode::Indexed);
        let mut scratch = program.evaluation_scratch().unwrap();
        for inbound in [0, 1, 7, 30, 31, 99] {
            for protocol in [0_u16, 3, 18, 25] {
                for network in [Network::Tcp, Network::Udp] {
                    let expected = (0..count)
                        .find(|index| {
                            index % 31 == inbound
                                && (index % 19) as u16 == protocol
                                && (index % 2 == 0) == (network == Network::Tcp)
                        })
                        .unwrap_or(usize::MAX);
                    let mut evaluation =
                        program.evaluate_with_scratch(inbound, network, &target, &mut scratch);
                    let actual = match evaluation.next(RouteMetadata::new(Some(protocol), None)) {
                        Some(RouteProgramAction::Terminal(action))
                        | Some(RouteProgramAction::Final(action)) => *action,
                        _ => panic!("terminal result"),
                    };
                    assert_eq!(actual, expected, "{count}/{inbound}/{protocol}/{network:?}");
                }
            }
        }
    }
}

#[test]
fn reusable_scratch_does_not_grow_on_the_evaluation_hot_path() {
    let program = reference_program(1_000);
    let target = target();
    let mut scratch = program.evaluation_scratch().unwrap();
    let reserved = scratch.reserved_words();
    for input in 0..1_000 {
        let mut evaluation = program.evaluate_with_scratch(
            input % 31,
            if input % 2 == 0 {
                Network::Tcp
            } else {
                Network::Udp
            },
            &target,
            &mut scratch,
        );
        let _ = evaluation.next(RouteMetadata::new(Some((input % 19) as u16), None));
    }
    assert_eq!(scratch.reserved_words(), reserved);
}

#[test]
fn ip_and_cidr_fields_share_the_compiled_ip_index() {
    let exact: IpAddr = "192.0.2.7".parse().unwrap();
    let matcher = RouteMatcher::<()>::try_new(vec![
        RouteMatchField::Ip(vec![exact]),
        RouteMatchField::Cidr(vec!["192.0.2.0/24".parse().unwrap()]),
    ])
    .unwrap();
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(true),
        )],
        false,
    )
    .unwrap();
    let target = TargetAddr::ip("192.0.2.7:443".parse().unwrap()).unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&true))
    );
}

#[test]
fn ten_thousand_exact_and_scalar_constraints_visit_only_matching_postings() {
    let rules = (0..10_000)
        .map(|index| {
            RouteMatcher::<()>::try_new(vec![
                RouteMatchField::Domain(vec![domain(&format!("host-{index}.example"))]),
                RouteMatchField::Inbound(vec![index]),
            ])
            .map(|matcher| OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(index)))
            .unwrap()
        })
        .collect();
    let program = OrderedRouteProgram::try_new(rules, usize::MAX).unwrap();
    assert_eq!(program.mode(), RuleProgramMode::Indexed);
    let mut scratch = program.evaluation_scratch().unwrap();

    let target = TargetAddr::domain("host-9999.example", 443).unwrap();
    let mut evaluation = program.evaluate_with_scratch(9_999, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&9_999))
    );
    drop(evaluation);
    assert_eq!(scratch.candidate_visits(), 2);

    let mut evaluation = program.evaluate_with_scratch(1, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&usize::MAX))
    );
    drop(evaluation);
    assert_eq!(scratch.candidate_visits(), 2);

    let miss = TargetAddr::domain("missing.example", 443).unwrap();
    let mut evaluation = program.evaluate_with_scratch(20_000, Network::Tcp, &miss, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&usize::MAX))
    );
    drop(evaluation);
    assert_eq!(scratch.candidate_visits(), 0);
}

#[test]
fn indexed_bitmap_work_is_limited_to_each_active_field_span() {
    let mut rules = Vec::new();
    for inbound in 0..64 {
        let matcher =
            RouteMatcher::<()>::try_new(vec![RouteMatchField::Inbound(vec![inbound])]).unwrap();
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(inbound),
        ));
    }
    for index in 64..128 {
        let matcher = RouteMatcher::<()>::try_new(vec![RouteMatchField::Domain(vec![domain(
            &format!("host-{index}.example"),
        )])])
        .unwrap();
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(index),
        ));
    }
    let program = OrderedRouteProgram::try_new(rules, usize::MAX).unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let target = TargetAddr::domain("host-127.example", 443).unwrap();

    let mut evaluation = program.evaluate_with_scratch(63, Network::Tcp, &target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&63))
    );
    drop(evaluation);

    assert_eq!(scratch.bitmap_word_operations(), (2, 2));
    assert_eq!(
        scratch.candidate_word_initializations(),
        2,
        "each candidate word is initialized exactly once"
    );
}

#[test]
fn indexed_suffix_keyword_cidr_and_port_range_use_value_postings() {
    let suffix_rules = (0..128)
        .map(|index| {
            let matcher =
                RouteMatcher::<()>::try_new(vec![RouteMatchField::DomainSuffix(vec![domain(
                    &format!("suffix-{index}.example"),
                )])])
                .unwrap();
            OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(index))
        })
        .collect();
    let suffix_program = OrderedRouteProgram::try_new(suffix_rules, usize::MAX).unwrap();
    let suffix_root = TargetAddr::domain("suffix-127.example", 443).unwrap();
    assert_selective_hit(&suffix_program, &suffix_root, 0, 127);
    let suffix_target = TargetAddr::domain("child.suffix-127.example", 443).unwrap();
    assert_selective_hit(&suffix_program, &suffix_target, 0, 127);

    let keyword_rules = (0..128)
        .map(|index| {
            let matcher =
                RouteMatcher::<()>::try_new(vec![RouteMatchField::DomainKeyword(vec![domain(
                    &format!("token-{index:03}-"),
                )])])
                .unwrap();
            OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(index))
        })
        .collect();
    let keyword_program = OrderedRouteProgram::try_new(keyword_rules, usize::MAX).unwrap();
    let keyword_target = TargetAddr::domain("prefix-token-127-.invalid", 443).unwrap();
    assert_selective_hit(&keyword_program, &keyword_target, 0, 127);

    let cidr_rules = (0..128)
        .map(|index| {
            let address = Ipv4Addr::new(198, 18, 0, index as u8);
            let matcher = RouteMatcher::<()>::try_new(vec![RouteMatchField::Cidr(vec![
                format!("{address}/32").parse().unwrap(),
            ])])
            .unwrap();
            OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(index as usize))
        })
        .collect();
    let cidr_program = OrderedRouteProgram::try_new(cidr_rules, usize::MAX).unwrap();
    let cidr_target = TargetAddr::ip("198.18.0.127:443".parse().unwrap()).unwrap();
    assert_selective_hit(&cidr_program, &cidr_target, 0, 127);

    let range_rules = (0..128)
        .map(|index| {
            let port = 10_000 + index as u16;
            let matcher = RouteMatcher::<()>::try_new(vec![RouteMatchField::PortRange(vec![
                ferrum2_rule::PortRange::try_new(port, port).unwrap(),
            ])])
            .unwrap();
            OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(index))
        })
        .collect();
    let range_program = OrderedRouteProgram::try_new(range_rules, usize::MAX).unwrap();
    let range_target = TargetAddr::domain("range.invalid", 10_127).unwrap();
    assert_selective_hit(&range_program, &range_target, 0, 127);
}

fn assert_selective_hit(
    program: &OrderedRouteProgram<(), usize>,
    target: &TargetAddr,
    inbound: usize,
    expected: usize,
) {
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_scratch(inbound, Network::Tcp, target, &mut scratch);
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&expected))
    );
    drop(evaluation);
    assert!(scratch.candidate_visits() <= 2);
}

#[test]
fn selected_rule_reports_closed_match_categories_without_allocation() {
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            RouteMatcher::<()>::try_new(vec![
                RouteMatchField::Domain(vec![domain("www.example.test")]),
                RouteMatchField::Network(vec![Network::Tcp]),
            ])
            .unwrap(),
            RouteRuleAction::Terminal(7),
        )],
        9,
    )
    .unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let selected_target = target();
    let mut evaluation =
        program.evaluate_with_scratch(0, Network::Tcp, &selected_target, &mut scratch);
    evaluation.enable_match_observation();
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&7))
    );
    let observation = evaluation.last_match_observation();
    assert!(observation.evaluated(RouteMatchSource::Inline, RouteMatchType::Domain));
    assert!(observation.evaluated(RouteMatchSource::Inline, RouteMatchType::Scalar));
    assert!(observation.matched(RouteMatchSource::Inline, RouteMatchType::Domain));
    assert!(observation.matched(RouteMatchSource::Inline, RouteMatchType::Scalar));
    assert!(!observation.evaluated(RouteMatchSource::RuleSet, RouteMatchType::Domain));
    assert!(!observation.matched(RouteMatchSource::RuleSet, RouteMatchType::Domain));
}

#[test]
fn selected_composite_reports_evaluated_categories_and_exact_misses() {
    let mut builder = MatchSetBuilder::new();
    builder
        .add_exact_domain("www.example.test")
        .unwrap()
        .add_domain_suffix("other.invalid")
        .unwrap()
        .add_domain_keyword("missing-token")
        .unwrap();
    let matcher =
        RouteMatcher::<()>::try_new(vec![RouteMatchField::MatchSet(builder.build().unwrap())])
            .unwrap();
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(matcher, RouteRuleAction::Terminal(7))],
        9,
    )
    .unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let selected_target = target();
    let mut evaluation =
        program.evaluate_with_scratch(0, Network::Tcp, &selected_target, &mut scratch);
    evaluation.enable_match_observation();
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&7))
    );
    let observation = evaluation.last_match_observation();
    for r#type in [
        RouteMatchType::Domain,
        RouteMatchType::DomainSuffix,
        RouteMatchType::DomainKeyword,
    ] {
        assert!(observation.evaluated(RouteMatchSource::Inline, r#type));
    }
    assert!(observation.matched(RouteMatchSource::Inline, RouteMatchType::Domain));
    assert!(!observation.matched(RouteMatchSource::Inline, RouteMatchType::DomainSuffix));
    assert!(!observation.matched(RouteMatchSource::Inline, RouteMatchType::DomainKeyword));
}
