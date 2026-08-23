use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_rule::{
    CompiledMatchSet, GenerationChange, MatchSetBuilder, MatchSetCapabilities, MatchSetId, Network,
    OrderedRouteProgram, OrderedRouteRule, RegistryPublishError, RouteMatchField, RouteMatcher,
    RouteMetadata, RouteProgramAction, RouteRuleAction, RuleCompileError, RuleEngineRegistry,
    RuleEngineSnapshot, RuleEngineSnapshotBuilder, RuleProgramMode, RuleSetId,
};

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll_change(change: &mut GenerationChange, waker: &Waker) -> Poll<u64> {
    Future::poll(Pin::new(change), &mut Context::from_waker(waker))
}

fn exact(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_exact_domain(value).unwrap();
    builder.build().unwrap()
}

fn cidr(value: &str) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    builder.add_ip_cidr(value.parse().unwrap()).unwrap();
    builder.build().unwrap()
}

fn two_rule_sets(
    generation: u64,
    first: CompiledMatchSet,
    second: CompiledMatchSet,
) -> (RuleEngineSnapshot, RuleSetId, RuleSetId) {
    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    let first_match = builder.add_match_set(first).unwrap();
    let second_match = builder.add_match_set(second).unwrap();
    let first = builder.add_rule_set("first", first_match).unwrap();
    let second = builder.add_rule_set("second", second_match).unwrap();
    (builder.build().unwrap(), first, second)
}

#[test]
fn stable_ids_descriptors_and_capabilities_survive_refresh() {
    let (initial, first, second) = two_rule_sets(7, exact("first.example"), cidr("192.0.2.0/24"));
    assert_eq!((first.raw(), second.raw()), (0, 1));
    assert_eq!(initial.rule_set_id("first"), Some(first));
    assert_eq!(initial.rule_set_id("second"), Some(second));
    assert_eq!(initial.rule_set(first).unwrap().match_set().raw(), 0);
    assert_eq!(
        initial.rule_set(first).unwrap().capabilities(),
        MatchSetCapabilities {
            exact_domain: true,
            ..MatchSetCapabilities::default()
        }
    );
    assert!(initial.rule_set(RuleSetId::from_raw(99)).is_none());
    assert!(initial.match_set(MatchSetId::from_raw(99)).is_none());

    let mut refresh = initial.builder_for_next_generation().unwrap();
    refresh
        .replace_rule_set(first, exact("refreshed.example"))
        .unwrap();
    let third_match = refresh.add_match_set(exact("third.example")).unwrap();
    let third = refresh.add_rule_set("third", third_match).unwrap();
    let refreshed = refresh.build().unwrap();
    assert_eq!(refreshed.generation(), 8);
    assert_eq!(refreshed.rule_set_id("first"), Some(first));
    assert_eq!(refreshed.rule_set_id("second"), Some(second));
    assert_eq!(refreshed.rule_set_id("third"), Some(third));
    assert_eq!(third.raw(), 2);
}

#[test]
fn publication_is_monotonic_compatible_and_failure_keeps_the_old_snapshot() {
    let (initial, _, _) = two_rule_sets(4, exact("a.example"), exact("b.example"));
    let registry = RuleEngineRegistry::new(initial);
    let held = registry.snapshot();

    let stale = held.builder_for_generation(5).unwrap().build().unwrap();
    registry.publish(stale).unwrap();
    let current = registry.snapshot();
    assert_eq!(current.generation(), 5);
    assert_eq!(held.generation(), 4);

    let stale_again = held.builder_for_generation(5).unwrap().build().unwrap();
    assert_eq!(
        registry.publish(stale_again).unwrap_err(),
        RegistryPublishError::StaleGeneration
    );
    assert!(Arc::ptr_eq(&registry.snapshot(), &current));

    let mut incompatible_builder = RuleEngineSnapshotBuilder::new(6);
    let second = incompatible_builder
        .add_match_set(exact("other.example"))
        .unwrap();
    let first = incompatible_builder
        .add_match_set(exact("replacement.example"))
        .unwrap();
    incompatible_builder.add_rule_set("second", second).unwrap();
    incompatible_builder.add_rule_set("first", first).unwrap();
    let incompatible = incompatible_builder.build().unwrap();
    assert_eq!(
        registry.publish(incompatible).unwrap_err(),
        RegistryPublishError::IncompatibleLayout
    );
    assert!(Arc::ptr_eq(&registry.snapshot(), &current));
}

#[test]
fn registry_change_subscriptions_wake_only_after_successful_publication() {
    let (initial, _, _) = two_rule_sets(4, exact("a.example"), exact("b.example"));
    let registry = RuleEngineRegistry::new(initial);
    let held = registry.snapshot();
    let first_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let second_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let first_waker = Waker::from(Arc::clone(&first_wakes));
    let second_waker = Waker::from(Arc::clone(&second_wakes));
    let mut first = registry.watch_generation();
    let mut second = registry.watch_generation();
    assert_eq!(first.baseline(), 4);
    assert_eq!(poll_change(&mut first, &first_waker), Poll::Pending);
    assert_eq!(poll_change(&mut second, &second_waker), Poll::Pending);

    let successor = held.builder_for_generation(5).unwrap().build().unwrap();
    registry.publish(successor).unwrap();
    assert_eq!(first_wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(poll_change(&mut first, &first_waker), Poll::Ready(5));
    assert_eq!(poll_change(&mut second, &second_waker), Poll::Ready(5));

    let mut after_success = registry.watch_generation();
    assert_eq!(poll_change(&mut after_success, &first_waker), Poll::Pending);
    let stale = held.builder_for_generation(5).unwrap().build().unwrap();
    assert_eq!(
        registry.publish(stale).unwrap_err(),
        RegistryPublishError::StaleGeneration
    );
    assert_eq!(first_wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(poll_change(&mut after_success, &first_waker), Poll::Pending);

    let successor = registry
        .snapshot()
        .builder_for_generation(6)
        .unwrap()
        .build()
        .unwrap();
    registry.publish(successor).unwrap();
    assert_eq!(first_wakes.0.load(Ordering::SeqCst), 2);
    assert_eq!(
        poll_change(&mut after_success, &first_waker),
        Poll::Ready(6)
    );
}

#[test]
fn registry_publication_before_post_selection_subscription_is_observed() {
    let (initial, _, _) = two_rule_sets(8, exact("a.example"), exact("b.example"));
    let registry = RuleEngineRegistry::new(initial);
    let selected_generation = registry.generation();
    let next = registry
        .snapshot()
        .builder_for_next_generation()
        .unwrap()
        .build()
        .unwrap();
    registry.publish(next).unwrap();
    let mut change = registry.watch_generation_from(selected_generation);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));

    assert_eq!(poll_change(&mut change, &waker), Poll::Ready(9));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
}

#[test]
fn multiple_rule_sets_are_ored_and_external_fields_remain_anded() {
    let (snapshot, domains, networks) =
        two_rule_sets(1, exact("domain.example"), cidr("198.51.100.0/24"));
    let registry = RuleEngineRegistry::new(snapshot);
    let matcher = RouteMatcher::<()>::try_new(vec![
        RouteMatchField::Network(vec![Network::Tcp]),
        RouteMatchField::RuleSet(vec![domains, networks]),
    ])
    .unwrap();
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal("match"),
        )],
        "final",
    )
    .unwrap();

    for target in [
        TargetAddr::domain("DOMAIN.EXAMPLE.", 443).unwrap(),
        TargetAddr::ip("198.51.100.7:443".parse().unwrap()).unwrap(),
    ] {
        let mut evaluation = program.evaluate_with_registry(0, Network::Tcp, &target, &registry);
        assert_eq!(evaluation.snapshot_generation(), Some(1));
        assert_eq!(
            evaluation.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Terminal(&"match"))
        );
    }

    let target = TargetAddr::domain("domain.example", 443).unwrap();
    let mut wrong_network = program.evaluate_with_registry(0, Network::Udp, &target, &registry);
    assert_eq!(
        wrong_network.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&"final"))
    );
    let mut no_snapshot = program.evaluate(0, Network::Tcp, &target);
    assert_eq!(
        no_snapshot.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&"final")),
        "forged or absent snapshot state must fail closed"
    );
}

#[test]
fn one_composite_rule_set_ors_categories_and_uses_the_sniffed_domain() {
    let mut match_set = MatchSetBuilder::new();
    match_set
        .add_exact_domain("sniffed.example")
        .unwrap()
        .add_domain_suffix("suffix.example")
        .unwrap()
        .add_domain_keyword("keyword")
        .unwrap()
        .add_ip_cidr("203.0.113.0/24".parse().unwrap())
        .unwrap();
    let mut snapshot = RuleEngineSnapshotBuilder::new(3);
    let match_set = snapshot.add_match_set(match_set.build().unwrap()).unwrap();
    let rule_set = snapshot.add_rule_set("composite", match_set).unwrap();
    let registry = RuleEngineRegistry::new(snapshot.build().unwrap());
    let program = OrderedRouteProgram::try_new(
        vec![OrderedRouteRule::new(
            RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![rule_set])]).unwrap(),
            RouteRuleAction::Terminal(true),
        )],
        false,
    )
    .unwrap();

    let original_ip = TargetAddr::ip("192.0.2.1:443".parse().unwrap()).unwrap();
    let sniffed = DomainName::new("SNIFFED.EXAMPLE.").unwrap();
    let mut by_sniff = program.evaluate_with_registry(0, Network::Tcp, &original_ip, &registry);
    assert_eq!(
        by_sniff.next(RouteMetadata::new(None, Some(&sniffed))),
        Some(RouteProgramAction::Terminal(&true))
    );

    let matching_ip = TargetAddr::ip("203.0.113.9:443".parse().unwrap()).unwrap();
    let mut by_ip = program.evaluate_with_registry(0, Network::Tcp, &matching_ip, &registry);
    assert_eq!(
        by_ip.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&true))
    );
}

#[test]
fn one_evaluation_never_crosses_generation_during_continue() {
    let mut builder = RuleEngineSnapshotBuilder::new(1);
    let match_set = builder.add_match_set(exact("old.example")).unwrap();
    let rule_set = builder.add_rule_set("refreshable", match_set).unwrap();
    let registry = RuleEngineRegistry::new(builder.build().unwrap());
    let program = OrderedRouteProgram::try_new(
        vec![
            OrderedRouteRule::new(
                RouteMatcher::<()>::unconditional(),
                RouteRuleAction::Continue("continue"),
            ),
            OrderedRouteRule::new(
                RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![rule_set])])
                    .unwrap(),
                RouteRuleAction::Terminal("matched"),
            ),
        ],
        "final",
    )
    .unwrap();
    let old_target = TargetAddr::domain("old.example", 443).unwrap();
    let mut held = program.evaluate_with_registry(0, Network::Tcp, &old_target, &registry);
    assert_eq!(held.snapshot_generation(), Some(1));
    assert_eq!(
        held.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(&"continue"))
    );

    let current = registry.snapshot();
    let mut refresh = current.builder_for_next_generation().unwrap();
    refresh
        .replace_rule_set(rule_set, exact("new.example"))
        .unwrap();
    registry.publish(refresh.build().unwrap()).unwrap();
    assert_eq!(registry.generation(), 2);
    assert_eq!(held.snapshot_generation(), Some(1));
    assert_eq!(
        held.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&"matched"))
    );

    let mut fresh_old = program.evaluate_with_registry(0, Network::Tcp, &old_target, &registry);
    assert_eq!(
        fresh_old.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(&"continue"))
    );
    assert_eq!(
        fresh_old.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(&"final"))
    );
    let new_target = TargetAddr::domain("new.example", 443).unwrap();
    let mut fresh_new = program.evaluate_with_registry(0, Network::Tcp, &new_target, &registry);
    assert!(matches!(
        fresh_new.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(_))
    ));
    assert_eq!(
        fresh_new.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&"matched"))
    );
}

#[test]
fn concurrent_refresh_and_evaluation_observe_only_complete_generations() {
    let fixed = "fixed.example";
    let (snapshot, first, second) = two_rule_sets(0, exact(fixed), exact("miss.example"));
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let program = Arc::new(
        OrderedRouteProgram::try_new(
            vec![
                OrderedRouteRule::new(
                    RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![first])])
                        .unwrap(),
                    RouteRuleAction::Terminal(0_u8),
                ),
                OrderedRouteRule::new(
                    RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![second])])
                        .unwrap(),
                    RouteRuleAction::Terminal(1_u8),
                ),
            ],
            2_u8,
        )
        .unwrap(),
    );
    let target = TargetAddr::domain(fixed, 443).unwrap();
    let mut readers = Vec::new();
    for _ in 0..4 {
        let registry = Arc::clone(&registry);
        let program = Arc::clone(&program);
        let target = target.clone();
        readers.push(thread::spawn(move || {
            let mut scratch = program.evaluation_scratch().unwrap();
            for _ in 0..2_000 {
                let mut evaluation = program.evaluate_with_registry_and_scratch(
                    0,
                    Network::Tcp,
                    &target,
                    &registry,
                    &mut scratch,
                );
                let generation = evaluation.snapshot_generation().unwrap();
                let action = match evaluation.next(RouteMetadata::new(None, None)) {
                    Some(RouteProgramAction::Terminal(action)) => *action,
                    other => panic!("partial snapshot result: {other:?}"),
                };
                assert_eq!(action, (generation % 2) as u8);
            }
        }));
    }

    for generation in 1..=500 {
        let current = registry.snapshot();
        let mut refresh = current.builder_for_generation(generation).unwrap();
        let (first_value, second_value) = if generation % 2 == 0 {
            (fixed, "miss.example")
        } else {
            ("miss.example", fixed)
        };
        refresh.replace_rule_set(first, exact(first_value)).unwrap();
        refresh
            .replace_rule_set(second, exact(second_value))
            .unwrap();
        registry.publish(refresh.build().unwrap()).unwrap();
    }
    for reader in readers {
        reader.join().unwrap();
    }
}

#[test]
fn indexed_program_supports_more_than_sixty_four_rule_set_references_without_scratch_growth() {
    let mut builder = RuleEngineSnapshotBuilder::new(9);
    let mut ids = Vec::new();
    for index in 0..130 {
        let value = if index == 129 {
            "hit.example".to_owned()
        } else {
            format!("miss-{index}.example")
        };
        let match_set = builder.add_match_set(exact(&value)).unwrap();
        ids.push(
            builder
                .add_rule_set(&format!("set-{index}"), match_set)
                .unwrap(),
        );
    }
    let registry = RuleEngineRegistry::new(builder.build().unwrap());
    let rules = (0..100)
        .map(|inbound| {
            OrderedRouteRule::new(
                RouteMatcher::<()>::try_new(vec![
                    RouteMatchField::Inbound(vec![inbound]),
                    RouteMatchField::RuleSet(ids.clone()),
                ])
                .unwrap(),
                RouteRuleAction::Terminal(inbound),
            )
        })
        .collect();
    let program = OrderedRouteProgram::try_new(rules, usize::MAX).unwrap();
    assert_eq!(program.mode(), RuleProgramMode::Indexed);
    let target = TargetAddr::domain("HIT.EXAMPLE.", 443).unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let reserved = scratch.reserved_words();
    for _ in 0..100 {
        let mut evaluation = program.evaluate_with_registry_and_scratch(
            99,
            Network::Tcp,
            &target,
            &registry,
            &mut scratch,
        );
        assert_eq!(evaluation.snapshot_generation(), Some(9));
        assert_eq!(
            evaluation.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Terminal(&99))
        );
    }
    assert_eq!(scratch.reserved_words(), reserved);
}

#[test]
fn invalid_snapshot_inputs_fail_closed_without_disclosing_tags() {
    let mut builder = RuleEngineSnapshotBuilder::new(u64::MAX);
    let match_set = builder.add_match_set(exact("secret.example")).unwrap();
    assert_eq!(
        builder.add_rule_set("bad/tag", match_set).unwrap_err(),
        RuleCompileError::InvalidTag
    );
    assert_eq!(
        builder
            .add_rule_set("valid", MatchSetId::from_raw(99))
            .unwrap_err(),
        RuleCompileError::InvalidId
    );
    let id = builder.add_rule_set("secret-tag", match_set).unwrap();
    let snapshot = builder.build().unwrap();
    assert_eq!(
        snapshot.builder_for_next_generation().unwrap_err(),
        RuleCompileError::InvalidGeneration
    );
    let rendered = format!("{snapshot:?} {:?}", snapshot.rule_set(id).unwrap());
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("secret"));
}

#[test]
fn indexed_ruleset_lookup_visits_only_the_matching_id_posting() {
    let mut builder = RuleEngineSnapshotBuilder::new(41);
    let mut ids = Vec::new();
    for index in 0..1_000 {
        let set = builder
            .add_match_set(exact(&format!("set-{index}.example")))
            .unwrap();
        ids.push(builder.add_rule_set(&format!("set-{index}"), set).unwrap());
    }
    let snapshot = Arc::new(builder.build().unwrap());
    let rules = ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            OrderedRouteRule::new(
                RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![id])]).unwrap(),
                RouteRuleAction::Terminal(index),
            )
        })
        .collect();
    let program = OrderedRouteProgram::try_new(rules, usize::MAX).unwrap();
    let target = TargetAddr::domain("set-999.example", 443).unwrap();
    let mut scratch = program.evaluation_scratch().unwrap();
    let mut evaluation = program.evaluate_with_snapshot_and_scratch(
        0,
        Network::Tcp,
        &target,
        snapshot,
        &mut scratch,
    );
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&999))
    );
    drop(evaluation);
    assert_eq!(scratch.candidate_visits(), 1);
}
