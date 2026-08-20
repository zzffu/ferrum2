use std::alloc::System;

use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_rule::{
    Network, OrderedRouteProgram, OrderedRouteRule, RouteMatchField, RouteMatcher, RouteMetadata,
    RouteProgramAction, RouteRuleAction, RuleEngineRegistry, RuleEngineSnapshotBuilder,
};
use stats_alloc::{Region, StatsAlloc};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

#[test]
fn public_caller_owned_evaluate_entry_is_allocation_free() {
    let mut rules = Vec::new();
    rules.push(OrderedRouteRule::new(
        RouteMatcher::unconditional(),
        RouteRuleAction::Continue(50_000),
    ));
    for index in 0..128_u16 {
        let domain = DomainName::new(&format!("host-{index:03}.example"))
            .expect("generated domain is valid");
        let matcher = RouteMatcher::<()>::try_new(vec![RouteMatchField::Domain(vec![domain])])
            .expect("matcher compiles");
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(index),
        ));
    }
    let program = OrderedRouteProgram::try_new(rules, u16::MAX).expect("program compiles");
    let registry = RuleEngineRegistry::new(
        RuleEngineSnapshotBuilder::new(9)
            .build()
            .expect("empty snapshot compiles"),
    );
    let target = TargetAddr::domain("host-127.example", 443).expect("target is valid");
    let mut scratch = program.evaluation_scratch().expect("scratch allocates");

    for _ in 0..2 {
        let mut warmup = program.evaluate_with_registry_and_scratch(
            7,
            Network::Tcp,
            &target,
            &registry,
            &mut scratch,
        );
        assert_eq!(
            warmup.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Continue(&50_000))
        );
        assert_eq!(
            warmup.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Terminal(&127))
        );
    }

    let region = Region::new(&GLOBAL_ALLOCATOR);
    let mut evaluation = program.evaluate_with_registry_and_scratch(
        7,
        Network::Tcp,
        &target,
        &registry,
        &mut scratch,
    );
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Continue(&50_000))
    );
    assert_eq!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(&127))
    );
    drop(evaluation);
    let change = region.change();
    assert_eq!(change.allocations, 0, "evaluation allocated");
    assert_eq!(change.reallocations, 0, "evaluation reallocated");
}
