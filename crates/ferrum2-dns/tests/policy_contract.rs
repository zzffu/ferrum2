use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_dns::{
    DnsPolicyAction, DnsPolicyCompileError, DnsPolicyMatchResult, DnsPolicyMatchSource,
    DnsPolicyMatchType, DnsPolicyMatcher, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute,
    DnsPolicyRule, DnsPolicyStage, DnsPolicyStateError, DnsPolicyStep, DnsPortRange, DnsServerId,
    DnsStrategy,
};
use ferrum2_rule::{
    CompiledMatchSet, MatchSetBuilder, RuleEngineRegistry, RuleEngineSnapshot,
    RuleEngineSnapshotBuilder, RuleProgramMode, RuleSetId,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const LOCAL: DnsPolicyRoute = DnsPolicyRoute::new(DnsServerId::new(0), DnsStrategy::Ipv4Only);
const GOOGLE: DnsPolicyRoute = DnsPolicyRoute::new(DnsServerId::new(1), DnsStrategy::PreferIpv4);

fn domain_set(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_exact_domain(value).expect("exact domain");
    builder.build().expect("domain set")
}

fn suffix_set(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_suffix(value).expect("domain suffix");
    builder.build().expect("suffix set")
}

fn keyword_set(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_keyword(value).expect("domain keyword");
    builder.build().expect("keyword set")
}

fn ip_set(addresses: &[IpAddr]) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    for address in addresses {
        builder.add_ip(*address).expect("IP matcher");
    }
    builder.build().expect("IP set")
}

fn snapshot(
    generation: u64,
    sets: Vec<(&str, CompiledMatchSet)>,
) -> (RuleEngineSnapshot, Vec<RuleSetId>) {
    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    let mut ids = Vec::new();
    for (tag, set) in sets {
        let match_set = builder.add_match_set(set).expect("snapshot match set");
        ids.push(
            builder
                .add_rule_set(tag, match_set)
                .expect("snapshot RuleSet"),
        );
    }
    (builder.build().expect("snapshot"), ids)
}

fn matcher(rule_sets: Vec<RuleSetId>) -> DnsPolicyMatcher {
    DnsPolicyMatcher::try_new(Vec::new(), rule_sets, Vec::new(), Vec::new(), Vec::new())
        .expect("RuleSet matcher")
}

fn query(name: &str, qtype: RecordType) -> DnsPolicyQuery {
    DnsPolicyQuery::new(
        0,
        Network::Udp,
        Name::from_str(name).expect("query name"),
        qtype,
    )
}

fn response(records: Vec<(&str, RData)>) -> Message {
    let mut message = Message::new(7, MessageType::Response, OpCode::Query);
    for (owner, data) in records {
        message.add_answer(Record::from_rdata(
            Name::from_str(owner).expect("answer owner"),
            60,
            data,
        ));
    }
    message
}

fn route_program(snapshot: &RuleEngineSnapshot, rules: Vec<DnsPolicyRule>) -> DnsPolicyProgram {
    DnsPolicyProgram::try_new(rules, GOOGLE, snapshot).expect("DNS policy")
}

fn inbound_program(snapshot: &RuleEngineSnapshot, rule_count: usize) -> DnsPolicyProgram {
    let rules = (0..rule_count)
        .map(|inbound| {
            let matcher = DnsPolicyMatcher::try_new(
                Vec::new(),
                Vec::new(),
                vec![inbound],
                Vec::new(),
                Vec::new(),
            )
            .expect("inbound matcher");
            DnsPolicyRule::new(matcher, DnsPolicyAction::Route(LOCAL))
        })
        .collect();
    route_program(snapshot, rules)
}

fn inbound_query(inbound: usize) -> DnsPolicyQuery {
    DnsPolicyQuery::new(
        inbound,
        Network::Udp,
        Name::from_str("scale.invalid.").expect("scale qname"),
        RecordType::A,
    )
}

#[test]
fn ads_reject_is_decided_before_any_upstream_response() {
    let (snapshot, ids) = snapshot(1, vec![("ads", suffix_set("ads.invalid"))]);
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(vec![ids[0]]),
            DnsPolicyAction::Reject,
        )],
    );
    assert_eq!(program.response_rule_count(), 0);
    let registry = RuleEngineRegistry::new(snapshot);
    let mut evaluation = program.evaluate(query("tracker.ads.invalid.", RecordType::A), &registry);

    assert_eq!(
        evaluation.next_step().expect("query stage"),
        Some(DnsPolicyStep::Reject)
    );
    assert_eq!(evaluation.next_step().expect("finished"), None);
    assert_eq!(
        evaluation.evaluate_response(&Message::new(7, MessageType::Response, OpCode::Query)),
        Err(DnsPolicyStateError::ResponseNotExpected)
    );
}

#[test]
fn cnip_response_hit_accepts_while_miss_and_empty_continue_to_final() {
    let cn = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let (snapshot, ids) = snapshot(4, vec![("cnip", ip_set(&[cn]))]);
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(vec![ids[0]]),
            DnsPolicyAction::Route(LOCAL),
        )],
    );
    assert_eq!(program.response_rule_count(), 1);
    let registry = RuleEngineRegistry::new(snapshot);

    let mut hit = program.evaluate(query("service.invalid.", RecordType::A), &registry);
    assert_eq!(
        hit.next_step().expect("hit query stage"),
        Some(DnsPolicyStep::EvaluateResponse {
            server: LOCAL.server(),
            strategy: LOCAL.strategy(),
        })
    );
    assert_eq!(
        hit.evaluate_response(&response(vec![(
            "service.invalid.",
            RData::A(A(Ipv4Addr::new(10, 1, 2, 3))),
        )]))
        .expect("hit response"),
        DnsPolicyStep::AcceptResponse {
            server: LOCAL.server(),
            strategy: LOCAL.strategy(),
        }
    );
    let observation = hit.observation();
    assert!(observation.query_evaluated());
    assert!(observation.response_evaluated());
    assert_eq!(observation.query_candidates(), 1);
    assert_eq!(observation.response_candidates(), 1);
    assert_eq!(
        observation.match_count(
            DnsPolicyStage::Response,
            DnsPolicyMatchSource::RuleSet,
            DnsPolicyMatchType::IpCidr,
            DnsPolicyMatchResult::Matched,
        ),
        1
    );

    for answer in [
        response(vec![(
            "service.invalid.",
            RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
        )]),
        response(Vec::new()),
    ] {
        let mut miss = program.evaluate(query("service.invalid.", RecordType::A), &registry);
        assert!(matches!(
            miss.next_step().expect("miss query stage"),
            Some(DnsPolicyStep::EvaluateResponse { .. })
        ));
        assert_eq!(
            miss.evaluate_response(&answer).expect("miss continuation"),
            DnsPolicyStep::Final {
                server: GOOGLE.server(),
                strategy: GOOGLE.strategy(),
            }
        );
    }
}

#[test]
fn cname_chain_uses_final_a_and_aaaa_and_ignores_unrelated_answers() {
    let matching_v6 = Ipv6Addr::from_str("2001:db8::44").expect("matching IPv6");
    let (snapshot, ids) = snapshot(2, vec![("cnip", ip_set(&[IpAddr::V6(matching_v6)]))]);
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(vec![ids[0]]),
            DnsPolicyAction::Route(LOCAL),
        )],
    );
    let registry = RuleEngineRegistry::new(snapshot);
    let mut evaluation = program.evaluate(query("alias.invalid.", RecordType::AAAA), &registry);
    assert!(matches!(
        evaluation.next_step().expect("query stage"),
        Some(DnsPolicyStep::EvaluateResponse { .. })
    ));

    let answer = response(vec![
        ("unrelated.invalid.", RData::AAAA(AAAA(matching_v6))),
        (
            "alias.invalid.",
            RData::CNAME(CNAME(Name::from_str("middle.invalid.").expect("middle"))),
        ),
        (
            "middle.invalid.",
            RData::CNAME(CNAME(Name::from_str("final.invalid.").expect("final"))),
        ),
        (
            "final.invalid.",
            RData::A(A(Ipv4Addr::new(198, 51, 100, 8))),
        ),
        ("final.invalid.", RData::AAAA(AAAA(matching_v6))),
    ]);
    assert!(matches!(
        evaluation
            .evaluate_response(&answer)
            .expect("CNAME response"),
        DnsPolicyStep::AcceptResponse { .. }
    ));

    let mut direct = program.evaluate(query("alias.invalid.", RecordType::A), &registry);
    direct.next_step().expect("direct query stage");
    let multiple = response(vec![
        (
            "alias.invalid.",
            RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
        ),
        ("alias.invalid.", RData::AAAA(AAAA(matching_v6))),
    ]);
    assert!(matches!(
        direct
            .evaluate_response(&multiple)
            .expect("multi-address response"),
        DnsPolicyStep::AcceptResponse { .. }
    ));
}

#[test]
fn multiple_rulesets_are_or_while_inline_and_scalar_fields_are_and() {
    let (snapshot, ids) = snapshot(
        3,
        vec![
            ("first", domain_set("first.invalid")),
            ("second", suffix_set("allowed.invalid")),
        ],
    );
    let inline = Arc::new(keyword_set("service"));
    let matcher = DnsPolicyMatcher::try_new(
        vec![inline],
        ids,
        vec![7],
        vec![Network::Udp],
        vec![RecordType::AAAA],
    )
    .expect("composite matcher");
    let override_route = DnsPolicyRoute::new(DnsServerId::new(8), DnsStrategy::Ipv6Only);
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher,
            DnsPolicyAction::Route(override_route),
        )],
    );
    let registry = RuleEngineRegistry::new(snapshot);

    let matching = DnsPolicyQuery::new(
        7,
        Network::Udp,
        Name::from_str("service.allowed.invalid.").expect("matching qname"),
        RecordType::AAAA,
    );
    let mut evaluation = program.evaluate(matching, &registry);
    assert_eq!(
        evaluation.next_step().expect("matching query"),
        Some(DnsPolicyStep::RouteImmediately {
            server: override_route.server(),
            strategy: override_route.strategy(),
        })
    );
    let observation = evaluation.observation();
    assert_eq!(observation.query_candidates(), 1);
    assert_eq!(
        observation.match_count(
            DnsPolicyStage::Query,
            DnsPolicyMatchSource::Inline,
            DnsPolicyMatchType::Scalar,
            DnsPolicyMatchResult::Matched,
        ),
        3
    );
    assert_eq!(
        observation.match_count(
            DnsPolicyStage::Query,
            DnsPolicyMatchSource::Inline,
            DnsPolicyMatchType::DomainKeyword,
            DnsPolicyMatchResult::Matched,
        ),
        1
    );
    assert_eq!(
        observation.match_count(
            DnsPolicyStage::Query,
            DnsPolicyMatchSource::RuleSet,
            DnsPolicyMatchType::Domain,
            DnsPolicyMatchResult::Missed,
        ),
        1
    );
    assert_eq!(
        observation.match_count(
            DnsPolicyStage::Query,
            DnsPolicyMatchSource::RuleSet,
            DnsPolicyMatchType::DomainSuffix,
            DnsPolicyMatchResult::Matched,
        ),
        1
    );

    for non_matching in [
        DnsPolicyQuery::new(
            6,
            Network::Udp,
            Name::from_str("service.allowed.invalid.").expect("wrong inbound"),
            RecordType::AAAA,
        ),
        DnsPolicyQuery::new(
            7,
            Network::Tcp,
            Name::from_str("service.allowed.invalid.").expect("wrong network"),
            RecordType::AAAA,
        ),
        DnsPolicyQuery::new(
            7,
            Network::Udp,
            Name::from_str("plain.allowed.invalid.").expect("wrong inline field"),
            RecordType::AAAA,
        ),
    ] {
        let mut evaluation = program.evaluate(non_matching, &registry);
        assert!(matches!(
            evaluation.next_step().expect("AND miss"),
            Some(DnsPolicyStep::Final { .. })
        ));
    }
}

#[test]
fn application_port_and_port_range_are_and_while_wire_queries_cannot_match_them() {
    let (snapshot, _) = snapshot(1, Vec::new());
    let matcher = DnsPolicyMatcher::try_new_with_application_constraints(
        vec![Arc::new(suffix_set("ports.invalid"))],
        Vec::new(),
        vec![4],
        vec![Network::Tcp],
        vec![RecordType::A],
        vec![
            NonZeroU16::new(443).expect("HTTPS port"),
            NonZeroU16::new(8443).expect("alternate HTTPS port"),
        ],
        vec![DnsPortRange::try_new(8_000, 9_000).expect("application port range")],
    )
    .expect("application matcher");
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(matcher, DnsPolicyAction::Route(LOCAL))],
    );
    let registry = RuleEngineRegistry::new(snapshot);
    let name = Name::from_str("service.ports.invalid.").expect("application qname");

    let mut matching = program.evaluate(
        DnsPolicyQuery::new_application(
            4,
            Network::Tcp,
            name.clone(),
            RecordType::A,
            NonZeroU16::new(8_443).expect("matching port"),
        ),
        &registry,
    );
    assert!(matches!(
        matching.next_step().expect("matching application query"),
        Some(DnsPolicyStep::RouteImmediately { .. })
    ));

    for port in [443, 8_500] {
        let mut non_matching = program.evaluate(
            DnsPolicyQuery::new_application(
                4,
                Network::Tcp,
                name.clone(),
                RecordType::A,
                NonZeroU16::new(port).expect("non-matching port"),
            ),
            &registry,
        );
        assert!(matches!(
            non_matching.next_step().expect("port AND miss"),
            Some(DnsPolicyStep::Final { .. })
        ));
    }

    let mut wire = program.evaluate(
        DnsPolicyQuery::new(4, Network::Tcp, name, RecordType::A),
        &registry,
    );
    assert!(matches!(
        wire.next_step().expect("wire port miss"),
        Some(DnsPolicyStep::Final { .. })
    ));
    assert_eq!(
        DnsPortRange::try_new(0, 443),
        Err(DnsPolicyCompileError::InvalidPortRange)
    );
    assert_eq!(
        DnsPortRange::try_new(9_000, 8_000),
        Err(DnsPolicyCompileError::InvalidPortRange)
    );
}

#[test]
fn one_cached_response_can_continue_across_same_server_rules() {
    let first_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let second_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (snapshot, ids) = snapshot(
        9,
        vec![
            ("first", ip_set(&[first_ip])),
            ("second", ip_set(&[second_ip])),
        ],
    );
    let rules = ids
        .into_iter()
        .map(|id| DnsPolicyRule::new(matcher(vec![id]), DnsPolicyAction::Route(LOCAL)))
        .collect();
    let program = route_program(&snapshot, rules);
    let registry = RuleEngineRegistry::new(snapshot);
    let mut evaluation = program.evaluate(query("reuse.invalid.", RecordType::A), &registry);
    let answer = response(vec![(
        "reuse.invalid.",
        RData::A(A(Ipv4Addr::new(10, 0, 0, 2))),
    )]);

    assert!(matches!(
        evaluation.next_step().expect("first response step"),
        Some(DnsPolicyStep::EvaluateResponse { .. })
    ));
    assert_eq!(
        evaluation
            .evaluate_response(&answer)
            .expect("first RuleSet miss"),
        DnsPolicyStep::EvaluateResponse {
            server: LOCAL.server(),
            strategy: LOCAL.strategy(),
        }
    );
    assert!(matches!(
        evaluation
            .evaluate_response(&answer)
            .expect("same cached response hits second RuleSet"),
        DnsPolicyStep::AcceptResponse { .. }
    ));
}

#[test]
fn non_address_qtype_never_enters_response_matching() {
    let (snapshot, ids) = snapshot(
        1,
        vec![("cnip", ip_set(&[IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]))],
    );
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(ids),
            DnsPolicyAction::Route(LOCAL),
        )],
    );
    let registry = RuleEngineRegistry::new(snapshot);
    let mut evaluation = program.evaluate(query("txt.invalid.", RecordType::TXT), &registry);
    assert!(matches!(
        evaluation.next_step().expect("TXT query"),
        Some(DnsPolicyStep::Final { .. })
    ));
}

#[test]
fn one_evaluation_keeps_its_generation_across_refresh() {
    let old_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let new_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let (snapshot, ids) = snapshot(10, vec![("cnip", ip_set(&[old_ip]))]);
    let cnip = ids[0];
    let program = route_program(
        &snapshot,
        vec![DnsPolicyRule::new(
            matcher(vec![cnip]),
            DnsPolicyAction::Route(LOCAL),
        )],
    );
    let registry = RuleEngineRegistry::new(snapshot);
    let mut old_evaluation =
        program.evaluate(query("generation.invalid.", RecordType::A), &registry);
    assert_eq!(old_evaluation.snapshot_generation(), 10);
    old_evaluation.next_step().expect("old response step");

    let current = registry.snapshot();
    let mut next = current
        .builder_for_next_generation()
        .expect("next generation builder");
    next.replace_rule_set(cnip, ip_set(&[new_ip]))
        .expect("replace cnip");
    registry
        .publish(next.build().expect("new snapshot"))
        .expect("publish generation");

    let old_answer = response(vec![(
        "generation.invalid.",
        RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
    )]);
    assert!(matches!(
        old_evaluation
            .evaluate_response(&old_answer)
            .expect("old snapshot response"),
        DnsPolicyStep::AcceptResponse { .. }
    ));

    let mut new_evaluation =
        program.evaluate(query("generation.invalid.", RecordType::A), &registry);
    assert_eq!(new_evaluation.snapshot_generation(), 11);
    new_evaluation.next_step().expect("new response step");
    assert!(matches!(
        new_evaluation
            .evaluate_response(&old_answer)
            .expect("new snapshot miss"),
        DnsPolicyStep::Final { .. }
    ));
}

#[test]
fn compilation_rejects_invalid_rows_without_fixed_rule_limits() {
    assert_eq!(
        DnsPolicyMatcher::try_new(Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(),)
            .expect_err("empty matcher"),
        DnsPolicyCompileError::EmptyRule
    );

    let (validation_snapshot, ids) = snapshot(
        1,
        vec![("cnip", ip_set(&[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]))],
    );
    assert_eq!(
        DnsPolicyProgram::try_new(
            vec![DnsPolicyRule::new(
                matcher(vec![ids[0]]),
                DnsPolicyAction::Reject,
            )],
            GOOGLE,
            &validation_snapshot,
        )
        .expect_err("response-dependent reject"),
        DnsPolicyCompileError::ResponseDependentReject
    );
    assert_eq!(
        DnsPolicyProgram::try_new(
            vec![DnsPolicyRule::new(
                matcher(vec![RuleSetId::from_raw(999)]),
                DnsPolicyAction::Route(LOCAL),
            )],
            GOOGLE,
            &validation_snapshot,
        )
        .expect_err("unknown RuleSet"),
        DnsPolicyCompileError::UnknownRuleSet
    );

    let (empty_snapshot, _) = snapshot(1, Vec::new());
    let shared = Arc::new(domain_set("never.invalid"));
    let rules = (0..130)
        .map(|inbound| {
            let matcher = DnsPolicyMatcher::try_new(
                vec![Arc::clone(&shared)],
                Vec::new(),
                vec![inbound],
                Vec::new(),
                Vec::new(),
            )
            .expect("large rule matcher");
            DnsPolicyRule::new(matcher, DnsPolicyAction::Route(LOCAL))
        })
        .collect::<Vec<_>>();
    let program = route_program(&empty_snapshot, rules);
    assert_eq!(program.len(), 130);
    let registry = RuleEngineRegistry::new(empty_snapshot);
    let mut evaluation = program.evaluate(query("other.invalid.", RecordType::A), &registry);
    assert!(matches!(
        evaluation.next_step().expect("large program"),
        Some(DnsPolicyStep::Final { .. })
    ));
}

#[test]
fn query_program_switches_at_shared_64_rule_boundary() {
    let (snapshot, _) = snapshot(1, Vec::new());
    assert_eq!(
        inbound_program(&snapshot, 64).mode(),
        RuleProgramMode::SmallLinear
    );
    assert_eq!(
        inbound_program(&snapshot, 65).mode(),
        RuleProgramMode::Indexed
    );
}

#[test]
fn indexed_1k_and_10k_last_and_miss_visit_only_sparse_candidates() {
    for rule_count in [1_000, 10_000] {
        let (snapshot, _) = snapshot(1, Vec::new());
        let program = inbound_program(&snapshot, rule_count);
        let registry = RuleEngineRegistry::new(snapshot);
        let mut scratch = program.evaluation_scratch();
        let mut last = program.evaluate_with_registry_and_scratch(
            inbound_query(rule_count - 1),
            &registry,
            &mut scratch,
        );
        assert!(matches!(
            last.next_step().expect("last candidate"),
            Some(DnsPolicyStep::RouteImmediately { .. })
        ));
        assert_eq!(last.observation().query_candidates(), 1, "{rule_count}");
        drop(last);

        let mut miss = program.evaluate_with_registry_and_scratch(
            inbound_query(rule_count + 1),
            &registry,
            &mut scratch,
        );
        assert!(matches!(
            miss.next_step().expect("sparse miss"),
            Some(DnsPolicyStep::Final { .. })
        ));
        assert_eq!(miss.observation().query_candidates(), 0, "{rule_count}");
    }
}

fn composite_program(
    snapshot: &RuleEngineSnapshot,
    rule_set: RuleSetId,
    filler_count: usize,
) -> DnsPolicyProgram {
    let mut rules = Vec::new();
    for inbound in 0..filler_count {
        rules.push(DnsPolicyRule::new(
            DnsPolicyMatcher::try_new(
                Vec::new(),
                Vec::new(),
                vec![inbound + 100],
                Vec::new(),
                Vec::new(),
            )
            .expect("filler matcher"),
            DnsPolicyAction::Route(LOCAL),
        ));
    }
    rules.push(DnsPolicyRule::new(
        DnsPolicyMatcher::try_new(
            vec![
                Arc::new(suffix_set("allowed.invalid")),
                Arc::new(keyword_set("service")),
            ],
            vec![rule_set],
            vec![7],
            vec![Network::Udp],
            vec![RecordType::A],
        )
        .expect("ordinary AND RuleSet matcher"),
        DnsPolicyAction::Route(LOCAL),
    ));
    route_program(snapshot, rules)
}

#[test]
fn linear_and_indexed_preserve_ordinary_and_ruleset_semantics() {
    let (snapshot, ids) = snapshot(1, vec![("selected", domain_set("service.allowed.invalid"))]);
    let linear = composite_program(&snapshot, ids[0], 63);
    let indexed = composite_program(&snapshot, ids[0], 64);
    assert_eq!(linear.mode(), RuleProgramMode::SmallLinear);
    assert_eq!(indexed.mode(), RuleProgramMode::Indexed);

    for name in [
        "service.allowed.invalid.",
        "plain.allowed.invalid.",
        "service.denied.invalid.",
    ] {
        let evaluate = |program: &DnsPolicyProgram| {
            let registry = RuleEngineRegistry::new(
                snapshot
                    .builder_for_next_generation()
                    .expect("equivalent snapshot builder")
                    .build()
                    .expect("equivalent snapshot"),
            );
            let query = DnsPolicyQuery::new(
                7,
                Network::Udp,
                Name::from_str(name).expect("composite qname"),
                RecordType::A,
            );
            let mut evaluation = program.evaluate(query, &registry);
            evaluation.next_step().expect("composite evaluation")
        };
        assert_eq!(evaluate(&linear), evaluate(&indexed), "{name}");
    }
}

#[test]
fn indexed_response_continuation_uses_captured_dynamic_capabilities_generation() {
    let (snapshot, ids) = snapshot(20, vec![("dynamic", domain_set("initial.invalid"))]);
    let dynamic = ids[0];
    let mut rules = (0..64)
        .map(|inbound| {
            DnsPolicyRule::new(
                DnsPolicyMatcher::try_new(
                    Vec::new(),
                    Vec::new(),
                    vec![inbound + 100],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("response filler"),
                DnsPolicyAction::Route(LOCAL),
            )
        })
        .collect::<Vec<_>>();
    rules.push(DnsPolicyRule::new(
        matcher(vec![dynamic]),
        DnsPolicyAction::Route(LOCAL),
    ));
    let program = route_program(&snapshot, rules);
    assert_eq!(program.mode(), RuleProgramMode::Indexed);
    let registry = RuleEngineRegistry::new(snapshot);

    let current = registry.snapshot();
    let mut next = current
        .builder_for_next_generation()
        .expect("IP generation builder");
    next.replace_rule_set(
        dynamic,
        ip_set(&[IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))]),
    )
    .expect("dynamic IP capability");
    registry
        .publish(next.build().expect("IP generation"))
        .expect("publish IP generation");

    let mut scratch = program.evaluation_scratch();
    let mut evaluation = program.evaluate_with_registry_and_scratch(
        query("dynamic.invalid.", RecordType::A),
        &registry,
        &mut scratch,
    );
    assert_eq!(evaluation.snapshot_generation(), 21);
    assert!(matches!(
        evaluation.next_step().expect("dynamic response candidate"),
        Some(DnsPolicyStep::EvaluateResponse { .. })
    ));
    assert_eq!(evaluation.observation().query_candidates(), 1);

    let current = registry.snapshot();
    let mut next = current
        .builder_for_next_generation()
        .expect("post-capture builder");
    next.replace_rule_set(dynamic, domain_set("after.invalid"))
        .expect("remove IP capability");
    registry
        .publish(next.build().expect("post-capture generation"))
        .expect("publish post-capture generation");

    assert!(matches!(
        evaluation
            .evaluate_response(&response(vec![(
                "dynamic.invalid.",
                RData::A(A(Ipv4Addr::new(10, 20, 30, 40))),
            )]))
            .expect("captured response"),
        DnsPolicyStep::AcceptResponse { .. }
    ));
    assert_eq!(evaluation.snapshot_generation(), 21);
}
