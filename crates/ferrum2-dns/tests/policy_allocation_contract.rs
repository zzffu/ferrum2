use std::alloc::System;
use std::str::FromStr;

use ferrum2_core::route::Network;
use ferrum2_dns::{
    DnsPolicyAction, DnsPolicyMatcher, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute,
    DnsPolicyRule, DnsPolicyStep, DnsServerId, DnsStrategy,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshotBuilder};
use hickory_proto::rr::{Name, RecordType};
use stats_alloc::{Region, StatsAlloc};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

#[test]
fn indexed_query_with_caller_owned_scratch_allocates_nothing() {
    let snapshot = RuleEngineSnapshotBuilder::new(1)
        .build()
        .expect("empty snapshot");
    let rules = (0..65)
        .map(|inbound| {
            let matcher = DnsPolicyMatcher::try_new(
                Vec::new(),
                Vec::new(),
                vec![inbound],
                Vec::new(),
                Vec::new(),
            )
            .expect("inbound matcher");
            DnsPolicyRule::new(
                matcher,
                DnsPolicyAction::Route(DnsPolicyRoute::new(
                    DnsServerId::new(1),
                    DnsStrategy::Ipv4Only,
                )),
            )
        })
        .collect();
    let program = DnsPolicyProgram::try_new(
        rules,
        DnsPolicyRoute::new(DnsServerId::new(2), DnsStrategy::PreferIpv4),
        &snapshot,
    )
    .expect("indexed DNS policy");
    let registry = RuleEngineRegistry::new(snapshot);
    let query = DnsPolicyQuery::new(
        64,
        Network::Udp,
        Name::from_str("allocation.invalid.").expect("query name"),
        RecordType::A,
    );
    let mut scratch = program.evaluation_scratch();

    let region = Region::new(&GLOBAL_ALLOCATOR);
    let mut evaluation = program.evaluate_with_registry_and_scratch(query, &registry, &mut scratch);
    assert!(matches!(
        evaluation.next_step().expect("query step"),
        Some(DnsPolicyStep::RouteImmediately { .. })
    ));
    drop(evaluation);
    let change = region.change();
    assert_eq!(change.allocations, 0, "indexed DNS evaluation allocated");
    assert_eq!(
        change.reallocations, 0,
        "indexed DNS evaluation reallocated"
    );
}
