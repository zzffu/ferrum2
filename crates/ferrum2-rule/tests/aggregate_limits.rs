use std::sync::Arc;

use ferrum2_core::CanonicalDomain;
use ferrum2_rule::{
    CompiledMatchSet, MatchSetBuilder, RuleCompileError, RuleEngineRegistry,
    RuleEngineSnapshotBuilder, RuleEngineSnapshotLimits,
};

fn keywords(values: &[&str]) -> CompiledMatchSet {
    let mut builder = MatchSetBuilder::new();
    for value in values {
        builder.add_domain_keyword(value).unwrap();
    }
    builder.build().unwrap()
}

fn snapshot(
    limits: RuleEngineSnapshotLimits,
    values: &[&str],
) -> Result<ferrum2_rule::RuleEngineSnapshot, RuleCompileError> {
    let mut builder = RuleEngineSnapshotBuilder::with_limits(1, limits);
    let set = builder.add_match_set(keywords(values)).unwrap();
    builder.add_rule_set("item", set).unwrap();
    builder.build()
}

#[test]
fn each_aggregate_dimension_accepts_its_boundary_and_rejects_excess() {
    for (limits, accepted, rejected) in [
        (
            RuleEngineSnapshotLimits::new(1, 8, 8).unwrap(),
            vec!["a"],
            vec!["a", "b"],
        ),
        (
            RuleEngineSnapshotLimits::new(8, 3, 8).unwrap(),
            vec!["abc"],
            vec!["abcd"],
        ),
        (
            RuleEngineSnapshotLimits::new(8, 8, 3).unwrap(),
            vec!["abc"],
            vec!["abcd"],
        ),
    ] {
        assert!(snapshot(limits, &accepted).is_ok());
        assert_eq!(
            snapshot(limits, &rejected).unwrap_err(),
            RuleCompileError::ResourceLimit
        );
    }
}

#[test]
fn aliases_are_charged_per_descriptor_and_orphans_per_retained_slot() {
    let limits = RuleEngineSnapshotLimits::new(1, 8, 8).unwrap();
    let shared = Arc::new(keywords(&["a"]));
    let mut aliases = RuleEngineSnapshotBuilder::with_limits(1, limits);
    let set = aliases.add_shared_match_set(Arc::clone(&shared)).unwrap();
    aliases.add_rule_set("first", set).unwrap();
    aliases.add_rule_set("second", set).unwrap();
    assert_eq!(
        aliases.build().unwrap_err(),
        RuleCompileError::ResourceLimit
    );

    let mut orphans = RuleEngineSnapshotBuilder::with_limits(1, limits);
    orphans.add_shared_match_set(Arc::clone(&shared)).unwrap();
    orphans.add_shared_match_set(shared).unwrap();
    assert_eq!(
        orphans.build().unwrap_err(),
        RuleCompileError::ResourceLimit
    );
}

#[test]
fn successors_reuse_limits_and_charge_replacement_instead_of_old_plus_new() {
    let limits = RuleEngineSnapshotLimits::new(1, 3, 3).unwrap();
    let initial = snapshot(limits, &["abc"]).unwrap();
    let id = initial.rule_set_id("item").unwrap();
    let registry = RuleEngineRegistry::new(initial);
    let current = registry.snapshot();
    let mut rejected = current.builder_for_next_generation().unwrap();
    rejected.replace_rule_set(id, keywords(&["abcd"])).unwrap();
    assert_eq!(
        rejected.build().unwrap_err(),
        RuleCompileError::ResourceLimit
    );
    assert!(Arc::ptr_eq(&current, &registry.snapshot()));
    let mut accepted = current.builder_for_next_generation().unwrap();
    accepted.replace_rule_set(id, keywords(&["xyz"])).unwrap();
    registry.publish(accepted.build().unwrap()).unwrap();
    let next = registry.snapshot();
    assert_eq!(next.generation(), 2);
    let set = next
        .match_set(next.rule_set(id).unwrap().match_set())
        .unwrap();
    assert!(set.matches_domain(&CanonicalDomain::new("xyz.example").unwrap()));
    assert!(!set.matches_domain(&CanonicalDomain::new("abc.example").unwrap()));
}

#[test]
fn usage_counts_text_bytes_and_ip_entries_without_exposing_values() {
    let mut set = MatchSetBuilder::new();
    set.add_exact_domain("a.example").unwrap();
    set.add_domain_suffix("example").unwrap();
    set.add_domain_keyword("amp").unwrap();
    set.add_ip("127.0.0.1".parse().unwrap()).unwrap();
    let usage = set.build().unwrap().resource_usage();
    assert_eq!(
        (
            usage.entries(),
            usage.expanded_bytes(),
            usage.keyword_bytes()
        ),
        (4, 19, 3)
    );
    let limits = RuleEngineSnapshotLimits::new(4, 19, 3).unwrap();
    assert_eq!(limits.admit(Default::default(), usage).unwrap(), usage);
    assert_eq!(
        limits.admit(usage, usage),
        Err(RuleCompileError::ResourceLimit)
    );
}

#[test]
fn overlapping_keywords_keep_every_snapshot_candidate() {
    let mut builder = RuleEngineSnapshotBuilder::new(1);
    let first_set = builder.add_match_set(keywords(&["he", "she"])).unwrap();
    let first = builder.add_rule_set("first", first_set).unwrap();
    let second_set = builder.add_match_set(keywords(&["hers", "ers"])).unwrap();
    let second = builder.add_rule_set("second", second_set).unwrap();
    let snapshot = builder.build().unwrap();
    let domain = CanonicalDomain::new("ushers.example").unwrap();
    let mut found = Vec::new();
    snapshot.visit_matching_rule_sets(Some(&domain), None, |id| found.push(id));
    found.sort();
    found.dedup();
    assert_eq!(found, [first, second]);
}

#[test]
fn keyword_length_is_admitted_before_automaton_construction() {
    let mut builder = MatchSetBuilder::new();
    builder.add_domain_keyword(&"a".repeat(256)).unwrap();
    assert_eq!(
        builder.build().unwrap_err(),
        RuleCompileError::ResourceLimit
    );
    assert!(
        !keywords(&[&"a".repeat(255)]).matches_domain(&CanonicalDomain::new("a.example").unwrap())
    );
}

#[test]
fn injected_limits_cannot_disable_the_product_policy() {
    for limits in [
        (0, 1, 1),
        (1, 0, 1),
        (1, 1, 0),
        (2_000_001, 1, 1),
        (1, 128 * 1024 * 1024 + 1, 1),
        (1, 1, 2 * 1024 * 1024 + 1),
    ] {
        assert_eq!(
            RuleEngineSnapshotLimits::new(limits.0, limits.1, limits.2),
            Err(RuleCompileError::ResourceLimit)
        );
    }
}
