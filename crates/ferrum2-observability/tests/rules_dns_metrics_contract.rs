use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread;

use ferrum2_observability::{
    CompiledMatchType, DnsQueryType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics,
    RuleMatchResult, RuleMatchType, RuleProgram, RuleProgramMode, RuleSetResult, RuleSource,
};

fn sample_value<'a>(output: &'a str, identity: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| {
            line.strip_prefix(identity)
                .and_then(|rest| rest.strip_prefix(' '))
        })
        .unwrap_or_else(|| panic!("missing sample {identity}"))
}

#[test]
fn rules_and_dns_families_encode_closed_low_cardinality_labels() {
    let metrics = Metrics::new();
    metrics.ruleset_load(RuleSetResult::Success);
    metrics.ruleset_refresh(RuleSetResult::Unchanged);
    metrics.set_ruleset_generation(42);
    metrics.set_ruleset_compiled_entries(CompiledMatchType::DomainSuffix, 10_000);
    metrics.set_ruleset_last_success_timestamp(1_900_000_000);
    metrics.set_rule_program_mode(RuleProgram::Route, RuleProgramMode::SmallLinear);
    metrics.set_rule_program_mode(RuleProgram::Route, RuleProgramMode::Indexed);
    metrics.set_rule_program_rules(RuleProgram::Route, 130);
    metrics.observe_rule_program_candidate_count(RuleProgram::Route, 17);
    metrics.observe_rule_program_match_ns(RuleProgram::Route, 5_000);
    metrics.route_match(
        RuleSource::RuleSet,
        RuleMatchType::DomainSuffix,
        RuleMatchResult::Matched,
    );
    metrics.dns_rule_query_match(
        RuleSource::Inline,
        RuleMatchType::DomainKeyword,
        RuleMatchResult::Missed,
    );
    metrics.dns_rule_query_matches(
        RuleSource::Inline,
        RuleMatchType::DomainKeyword,
        RuleMatchResult::Missed,
        4,
    );
    metrics.dns_rule_response_match(
        RuleSource::RuleSet,
        RuleMatchType::IpCidr,
        RuleMatchResult::Matched,
    );
    metrics.dns_rule_response_matches(
        RuleSource::RuleSet,
        RuleMatchType::IpCidr,
        RuleMatchResult::Matched,
        3,
    );
    metrics.dns_resolve(
        DnsResolverKind::Configured,
        DnsResolvePurpose::Application,
        DnsResolveResult::Success,
    );
    metrics.dns_cache_hit(DnsQueryType::A);
    metrics.dns_cache_miss(DnsQueryType::Aaaa);
    metrics.dns_explicit_system_resolve(DnsResolvePurpose::RuleSetDownload);

    let output = metrics.encode_text().expect("encode rules and DNS metrics");
    for expected in [
        "ferrum2_ruleset_load_total{result=\"success\"} 1",
        "ferrum2_ruleset_refresh_total{result=\"unchanged\"} 1",
        "ferrum2_ruleset_generation 42",
        "ferrum2_ruleset_compiled_entries{type=\"domain_suffix\"} 10000",
        "ferrum2_ruleset_last_success_timestamp 1900000000",
        "ferrum2_rule_program_mode{program=\"route\",mode=\"small_linear\"} 0",
        "ferrum2_rule_program_mode{program=\"route\",mode=\"indexed\"} 1",
        "ferrum2_rule_program_rules{program=\"route\"} 130",
        "ferrum2_route_match_total{source=\"rule_set\",type=\"domain_suffix\",result=\"matched\"} 1",
        "ferrum2_dns_rule_query_match_total{source=\"inline\",type=\"domain_keyword\",result=\"missed\"} 5",
        "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"matched\"} 4",
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"success\"} 1",
        "ferrum2_dns_cache_hit_total{qtype=\"a\"} 1",
        "ferrum2_dns_cache_miss_total{qtype=\"aaaa\"} 1",
        "ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(output.contains(expected), "missing `{expected}`\n{output}");
    }
    assert_eq!(
        sample_value(
            &output,
            "ferrum2_rule_program_candidate_count_count{program=\"route\"}"
        ),
        "1"
    );
    assert_eq!(
        sample_value(
            &output,
            "ferrum2_rule_program_match_ns_count{program=\"route\"}"
        ),
        "1"
    );

    for forbidden in ["tag=", "server=", "domain=", "url="] {
        assert!(!output.contains(forbidden), "forbidden label {forbidden}");
    }
}

#[test]
fn new_family_names_and_types_are_stable_additions() {
    let metrics = Metrics::new();
    metrics.ruleset_load(RuleSetResult::Success);
    metrics.ruleset_refresh(RuleSetResult::Success);
    metrics.set_ruleset_compiled_entries(CompiledMatchType::Domain, 1);
    metrics.set_rule_program_mode(RuleProgram::Route, RuleProgramMode::Indexed);
    metrics.set_rule_program_rules(RuleProgram::Route, 1);
    metrics.observe_rule_program_candidate_count(RuleProgram::Route, 1);
    metrics.observe_rule_program_match_ns(RuleProgram::Route, 1);
    metrics.route_match(
        RuleSource::RuleSet,
        RuleMatchType::Domain,
        RuleMatchResult::Matched,
    );
    metrics.dns_rule_query_match(
        RuleSource::RuleSet,
        RuleMatchType::Domain,
        RuleMatchResult::Matched,
    );
    metrics.dns_rule_response_match(
        RuleSource::RuleSet,
        RuleMatchType::IpCidr,
        RuleMatchResult::Matched,
    );
    metrics.dns_resolve(
        DnsResolverKind::Configured,
        DnsResolvePurpose::Application,
        DnsResolveResult::Success,
    );
    metrics.dns_cache_hit(DnsQueryType::A);
    metrics.dns_cache_miss(DnsQueryType::A);
    metrics.dns_explicit_system_resolve(DnsResolvePurpose::Application);
    let output = metrics.encode_text().expect("encode stable metrics");
    let types = output
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "ferrum2_dns_cache_hit counter",
        "ferrum2_dns_cache_miss counter",
        "ferrum2_dns_explicit_system_resolve counter",
        "ferrum2_dns_implicit_system_fallback counter",
        "ferrum2_dns_resolve counter",
        "ferrum2_dns_rule_query_match counter",
        "ferrum2_dns_rule_response_match counter",
        "ferrum2_route_match counter",
        "ferrum2_rule_program_candidate_count histogram",
        "ferrum2_rule_program_match_ns histogram",
        "ferrum2_rule_program_mode gauge",
        "ferrum2_rule_program_rules gauge",
        "ferrum2_ruleset_compiled_entries gauge",
        "ferrum2_ruleset_generation gauge",
        "ferrum2_ruleset_last_success_timestamp gauge",
        "ferrum2_ruleset_load counter",
        "ferrum2_ruleset_refresh counter",
    ]);
    assert!(
        expected.is_subset(&types),
        "missing types: {:?}",
        expected.difference(&types).collect::<Vec<_>>()
    );
    assert_eq!(
        sample_value(&output, "ferrum2_dns_implicit_system_fallback_total"),
        "0"
    );
}

#[test]
fn only_the_violation_api_increments_implicit_system_fallback() {
    let metrics = Metrics::new();
    metrics.dns_resolve(
        DnsResolverKind::Configured,
        DnsResolvePurpose::Application,
        DnsResolveResult::Failure,
    );
    metrics.dns_resolve(
        DnsResolverKind::System,
        DnsResolvePurpose::FixedEndpoint,
        DnsResolveResult::Success,
    );
    metrics.dns_explicit_system_resolve(DnsResolvePurpose::FixedEndpoint);
    metrics.dns_cache_miss(DnsQueryType::Other);

    let before = metrics.encode_text().expect("encode normal paths");
    assert_eq!(
        sample_value(&before, "ferrum2_dns_implicit_system_fallback_total"),
        "0"
    );

    metrics.record_dns_implicit_system_fallback_violation();
    let after = metrics.encode_text().expect("encode violation");
    assert_eq!(
        sample_value(&after, "ferrum2_dns_implicit_system_fallback_total"),
        "1"
    );
}

#[test]
fn concurrent_updates_preserve_exact_counts_and_closed_series() {
    const THREADS: usize = 8;
    const UPDATES: usize = 500;

    let metrics = Arc::new(Metrics::new());
    let workers = (0..THREADS)
        .map(|_| {
            let metrics = Arc::clone(&metrics);
            thread::spawn(move || {
                for _ in 0..UPDATES {
                    metrics.ruleset_refresh(RuleSetResult::Success);
                    metrics.route_match(
                        RuleSource::RuleSet,
                        RuleMatchType::Domain,
                        RuleMatchResult::Matched,
                    );
                    metrics.dns_resolve(
                        DnsResolverKind::Configured,
                        DnsResolvePurpose::Application,
                        DnsResolveResult::Success,
                    );
                    metrics.dns_cache_hit(DnsQueryType::A);
                    metrics.observe_rule_program_candidate_count(RuleProgram::Route, 4);
                    metrics.observe_rule_program_match_ns(RuleProgram::Route, 1_000);
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().expect("metrics worker");
    }

    let expected = (THREADS * UPDATES).to_string();
    let output = metrics.encode_text().expect("encode concurrent metrics");
    for identity in [
        "ferrum2_ruleset_refresh_total{result=\"success\"}",
        "ferrum2_route_match_total{source=\"rule_set\",type=\"domain\",result=\"matched\"}",
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"success\"}",
        "ferrum2_dns_cache_hit_total{qtype=\"a\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"route\"}",
        "ferrum2_rule_program_match_ns_count{program=\"route\"}",
    ] {
        assert_eq!(sample_value(&output, identity), expected);
    }
    assert_eq!(
        sample_value(&output, "ferrum2_dns_implicit_system_fallback_total"),
        "0"
    );
}

#[test]
fn identities_and_sensitive_inputs_cannot_create_metric_labels() {
    const SENTINELS: &[&str] = &[
        "ruleset-tag-secret",
        "dns-server-tag-secret",
        "https://token.invalid/private.srs",
        "private-domain.invalid",
        "192.0.2.44:53",
    ];
    let metrics = Metrics::new();
    for _sentinel in SENTINELS {
        metrics.ruleset_load(RuleSetResult::Failure);
        metrics.dns_cache_miss(DnsQueryType::A);
        metrics.route_match(
            RuleSource::RuleSet,
            RuleMatchType::Domain,
            RuleMatchResult::Missed,
        );
    }

    let output = metrics.encode_text().expect("encode redacted metrics");
    for sentinel in SENTINELS {
        assert!(!output.contains(sentinel));
    }
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("ferrum2_ruleset_load_total{"))
            .count(),
        1
    );
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("ferrum2_dns_cache_miss_total{"))
            .count(),
        1
    );
}
