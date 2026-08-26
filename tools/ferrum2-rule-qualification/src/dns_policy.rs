use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum2_core::route::Network;
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsPolicyAction,
    DnsPolicyMatcher, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute, DnsPolicyRule,
    DnsPolicyStep, DnsServerId, DnsStrategy, ResolverGeneration,
};
use ferrum2_rule::{
    MatchSetBuilder, RuleEngineSnapshot, RuleEngineSnapshotBuilder, RuleProgramMode,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::cli::{QualificationError, Result};
use crate::match_set::srs::canonical;
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::{benchmark, benchmark_operation_pair};
use crate::report::{BuildEvidence, Measurement};
use crate::route_program::scaled_iterations;

#[cfg(test)]
use crate::measurement::allocation::allocator_test_lock;

#[derive(Clone, Copy)]
pub(crate) enum DnsQuerySource {
    Ordinary,
    RuleSet,
}

#[cfg(test)]
impl DnsQuerySource {
    pub(crate) const ALL: [Self; 2] = [Self::Ordinary, Self::RuleSet];
}

pub(crate) struct DnsQnameFixture {
    pub(crate) program: DnsPolicyProgram,
    snapshot: Arc<RuleEngineSnapshot>,
    build: BuildEvidence,
}

pub(crate) fn run_dns_policy(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    run_dns_qname(rule_sizes, samples, base_iterations, measurements)?;
    // Response continuation deliberately visits each response-dependent row.
    // Keep those scenarios bounded while qname indexing carries the 10k scale.
    let response_sizes = rule_sizes
        .iter()
        .copied()
        .filter(|count| matches!(*count, 1 | 100 | 1_000))
        .collect::<Vec<_>>();
    run_dns_cnip(&response_sizes, samples, base_iterations, measurements)?;
    run_dns_cache(&response_sizes, samples, base_iterations, measurements)?;
    run_dns_continuation(&response_sizes, samples, base_iterations, measurements)
}

pub(crate) fn run_dns_qname(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let ordinary = build_dns_qname_fixture(count, DnsQuerySource::Ordinary)?;
        let ruleset = build_dns_qname_fixture(count, DnsQuerySource::RuleSet)?;
        let iterations = scaled_iterations(base_iterations, 1, count);
        for (case, position) in [
            ("first_hit", Some(0_usize)),
            ("last_hit", Some(count - 1)),
            ("miss", None),
        ] {
            let index = position.unwrap_or(count);
            let name = Name::from_str(&format!("dns-{index}.bench.invalid."))
                .map_err(|_| QualificationError::new("DNS qualification name is invalid"))?;
            let expected = position
                .and_then(|position| u32::try_from(position).ok())
                .unwrap_or(u32::MAX);
            let (ordinary_actual, ordinary_visits) = evaluate_dns_qname_evidence(&ordinary, &name);
            let (ruleset_actual, ruleset_visits) = evaluate_dns_qname_evidence(&ruleset, &name);
            if ordinary_actual != expected || ruleset_actual != expected {
                return Err(QualificationError::new(format!(
                    "DNS qname parity {count}/{case} returned ordinary={ordinary_actual}, RuleSet={ruleset_actual}, expected={expected}"
                )));
            }
            if ordinary.program.mode() == RuleProgramMode::Indexed
                && (ordinary_visits >= count || ruleset_visits >= count)
            {
                return Err(QualificationError::new(format!(
                    "DNS indexed qname {count}/{case} was not sublinear: ordinary={ordinary_visits}, RuleSet={ruleset_visits}"
                )));
            }
            let scenario = format!("qname_{case}");
            let (ordinary_result, ruleset_result) = benchmark_operation_pair(
                || u64::from(evaluate_dns_qname(&ordinary, &name)),
                || u64::from(evaluate_dns_qname(&ruleset, &name)),
                samples,
                iterations,
                format!("dns_policy/{count}/{scenario}"),
            );
            for (source, fixture, visits, result) in [
                (
                    "ordinary_inline",
                    &ordinary,
                    ordinary_visits,
                    ordinary_result,
                ),
                ("ruleset", &ruleset, ruleset_visits, ruleset_result),
            ] {
                let mut row = measurement(
                    format!("dns_policy/{source}/{count}/{scenario}"),
                    "dns_policy",
                    source,
                    scenario.clone(),
                    count,
                    None,
                    Some(fixture.program.mode()),
                    iterations,
                    fixture.build,
                    Some(count),
                    result,
                );
                row.query_candidate_visits = Some(visits);
                measurements.push(row);
            }
        }
    }
    Ok(())
}

pub(crate) fn build_dns_qname_fixture(
    count: usize,
    source: DnsQuerySource,
) -> Result<DnsQnameFixture> {
    let allocation_region = allocation_region();
    let started = Instant::now();
    let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| QualificationError::new("DNS policy fixture allocation failed"))?;
    for index in 0..count {
        let mut builder = MatchSetBuilder::new();
        builder
            .add_exact_domain(&format!("dns-{index}.bench.invalid"))
            .map_err(|error| QualificationError::new(format!("DNS qname value failed: {error}")))?;
        let set = builder.build().map_err(|error| {
            QualificationError::new(format!("DNS qname MatchSet failed: {error}"))
        })?;
        let matcher = match source {
            DnsQuerySource::Ordinary => DnsPolicyMatcher::try_new(
                vec![Arc::new(set)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            DnsQuerySource::RuleSet => {
                let match_set = snapshot_builder.add_match_set(set).map_err(|error| {
                    QualificationError::new(format!("DNS snapshot add failed: {error}"))
                })?;
                let rule_set = snapshot_builder
                    .add_rule_set(&format!("dns-{index}"), match_set)
                    .map_err(|error| {
                        QualificationError::new(format!("DNS RuleSet add failed: {error}"))
                    })?;
                DnsPolicyMatcher::try_new(
                    Vec::new(),
                    vec![rule_set],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            }
        }
        .map_err(|error| QualificationError::new(format!("DNS matcher build failed: {error}")))?;
        let server = DnsServerId::new(
            u32::try_from(index).map_err(|_| QualificationError::new("DNS server id overflow"))?,
        );
        rules.push(DnsPolicyRule::new(
            matcher,
            DnsPolicyAction::Route(DnsPolicyRoute::new(server, DnsStrategy::PreferIpv4)),
        ));
    }
    let snapshot =
        Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("DNS snapshot build failed: {error}"))
        })?);
    let final_route = DnsPolicyRoute::new(DnsServerId::new(u32::MAX), DnsStrategy::PreferIpv4);
    let program = DnsPolicyProgram::try_new(rules, final_route, &snapshot)
        .map_err(|error| QualificationError::new(format!("DNS policy build failed: {error}")))?;
    let build = finish_build(started, &allocation_region)?;
    Ok(DnsQnameFixture {
        program,
        snapshot,
        build,
    })
}

pub(crate) fn evaluate_dns_qname(fixture: &DnsQnameFixture, name: &Name) -> u32 {
    evaluate_dns_qname_evidence(fixture, name).0
}

pub(crate) fn evaluate_dns_qname_evidence(fixture: &DnsQnameFixture, name: &Name) -> (u32, usize) {
    let query = DnsPolicyQuery::new(0, Network::Udp, name.clone(), RecordType::A);
    let mut scratch = fixture.program.evaluation_scratch();
    let mut evaluation = fixture.program.evaluate_with_snapshot_and_scratch(
        query,
        Arc::clone(&fixture.snapshot),
        &mut scratch,
    );
    let selected = match evaluation.next_step() {
        Ok(Some(step)) => step
            .route()
            .map(|route| route.server().get())
            .unwrap_or(u32::MAX - 1),
        Ok(None) | Err(_) => u32::MAX - 2,
    };
    (selected, evaluation.observation().query_candidates())
}

pub(crate) fn run_dns_cnip(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let allocation_region = allocation_region();
        let started = Instant::now();
        let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(count)
            .map_err(|_| QualificationError::new("cnip rule allocation failed"))?;
        let local = DnsPolicyRoute::new(DnsServerId::new(7), DnsStrategy::Ipv4Only);
        let final_route = DnsPolicyRoute::new(DnsServerId::new(8), DnsStrategy::PreferIpv4);
        for index in 0..count {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_ip(IpAddr::V4(dns_bench_ip(index)))
                .map_err(|error| QualificationError::new(format!("cnip value failed: {error}")))?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("cnip MatchSet failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("cnip snapshot add failed: {error}"))
                })?;
            let rule_set = snapshot_builder
                .add_rule_set(&format!("cnip-{index}"), match_set)
                .map_err(|error| {
                    QualificationError::new(format!("cnip RuleSet add failed: {error}"))
                })?;
            let matcher = DnsPolicyMatcher::try_new(
                Vec::new(),
                vec![rule_set],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .map_err(|error| QualificationError::new(format!("cnip matcher failed: {error}")))?;
            rules.push(DnsPolicyRule::new(matcher, DnsPolicyAction::Route(local)));
        }
        let snapshot =
            Arc::new(snapshot_builder.build().map_err(|error| {
                QualificationError::new(format!("cnip snapshot failed: {error}"))
            })?);
        let program = DnsPolicyProgram::try_new(rules, final_route, &snapshot)
            .map_err(|error| QualificationError::new(format!("cnip program failed: {error}")))?;
        let name = Name::from_str("service.bench.invalid.")
            .map_err(|_| QualificationError::new("cnip qname is invalid"))?;
        let build = finish_build(started, &allocation_region)?;
        let fixture = DnsResponseFixture {
            program,
            snapshot,
            name,
            build,
        };
        let hit = dns_a_response("service.bench.invalid.", dns_bench_ip(count - 1))?;
        let miss = dns_a_response("service.bench.invalid.", Ipv4Addr::new(203, 0, 113, 3))?;
        let iterations = scaled_iterations(base_iterations, 1, count);
        for (case, response, expected) in [
            ("cnip_response_hit", &hit, local.server().get()),
            ("cnip_response_miss", &miss, final_route.server().get()),
        ] {
            let actual = evaluate_dns_response(&fixture, response);
            if actual != expected {
                return Err(QualificationError::new(format!(
                    "DNS {case}/{count} returned {actual}, expected {expected}"
                )));
            }
            let result = benchmark(
                || u64::from(evaluate_dns_response(&fixture, response)),
                samples,
                iterations,
            );
            measurements.push(measurement(
                format!("dns_policy/ruleset/{count}/{case}"),
                "dns_policy",
                "ruleset",
                case,
                count,
                None,
                Some(fixture.program.mode()),
                iterations,
                fixture.build,
                Some(count),
                result,
            ));
        }
    }
    Ok(())
}

pub(crate) fn dns_bench_ip(index: usize) -> Ipv4Addr {
    let value = u32::try_from(index).unwrap_or(u32::MAX);
    Ipv4Addr::new(
        10,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    )
}

pub(crate) struct DnsResponseFixture {
    program: DnsPolicyProgram,
    snapshot: Arc<RuleEngineSnapshot>,
    name: Name,
    build: BuildEvidence,
}

pub(crate) fn evaluate_dns_response(fixture: &DnsResponseFixture, response: &Message) -> u32 {
    let query = DnsPolicyQuery::new(0, Network::Udp, fixture.name.clone(), RecordType::A);
    let mut evaluation = fixture
        .program
        .evaluate_with_snapshot(query, Arc::clone(&fixture.snapshot));
    let mut step = match evaluation.next_step() {
        Ok(Some(step)) => step,
        Ok(None) | Err(_) => return u32::MAX - 2,
    };
    loop {
        match step {
            DnsPolicyStep::EvaluateResponse { .. } => {
                step = match evaluation.evaluate_response(response) {
                    Ok(step) => step,
                    Err(_) => return u32::MAX - 2,
                };
            }
            terminal => {
                return terminal
                    .route()
                    .map(|route| route.server().get())
                    .unwrap_or(u32::MAX - 1);
            }
        }
    }
}

pub(crate) fn dns_a_response(owner: &str, address: Ipv4Addr) -> Result<Message> {
    let mut response = Message::new(1, MessageType::Response, OpCode::Query);
    response.add_answer(Record::from_rdata(
        Name::from_str(owner)
            .map_err(|_| QualificationError::new("DNS response owner is invalid"))?,
        60,
        RData::A(A(address)),
    ));
    Ok(response)
}

pub(crate) fn run_dns_cache(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let allocation_region = allocation_region();
        let started = Instant::now();
        let capacity = NonZeroUsize::new(count.saturating_add(1))
            .ok_or_else(|| QualificationError::new("DNS cache capacity overflow"))?;
        let cache = DnsCache::try_new(capacity)
            .map_err(|error| QualificationError::new(format!("DNS cache build failed: {error}")))?;
        let now = Instant::now();
        let mut hit_key = None;
        for index in 0..count {
            let key = DnsCacheKey::new(
                DnsServerId::new(3),
                canonical(&format!("cache-{index}.bench.invalid"))?,
                DnsCacheQtype::A,
                ResolverGeneration::new(1),
            );
            cache
                .insert_positive(
                    key.clone(),
                    DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 9)])),
                    Duration::from_secs(60),
                    now,
                )
                .map_err(|error| {
                    QualificationError::new(format!("DNS cache insert failed: {error}"))
                })?;
            hit_key = Some(key);
        }
        let hit_key = hit_key.ok_or_else(|| QualificationError::new("empty DNS cache scale"))?;
        let miss_key = DnsCacheKey::new(
            DnsServerId::new(3),
            canonical("cache-miss.bench.invalid")?,
            DnsCacheQtype::A,
            ResolverGeneration::new(1),
        );
        let build = finish_build(started, &allocation_region)?;
        for (case, key, expected) in [
            ("cache_hit", &hit_key, 1_u64),
            ("cache_miss", &miss_key, 0_u64),
        ] {
            let read_cache = || match cache.get(key, now) {
                Ok(Some(DnsCacheAnswer::Positive(_))) => 1,
                Ok(Some(DnsCacheAnswer::Negative)) => 2,
                Ok(None) => 0,
                Err(_) => u64::MAX,
            };
            if read_cache() != expected {
                return Err(QualificationError::new(format!(
                    "DNS {case}/{count} correctness check failed"
                )));
            }
            let result = benchmark(read_cache, samples, base_iterations);
            measurements.push(measurement(
                format!("dns_policy/cache/{count}/{case}"),
                "dns_policy",
                "cache",
                case,
                count,
                None,
                None,
                base_iterations,
                build,
                Some(count),
                result,
            ));
        }
    }
    Ok(())
}

pub(crate) fn run_dns_continuation(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &continuations in rule_sizes {
        let rule_count = continuations.max(2);
        let allocation_region = allocation_region();
        let started = Instant::now();
        let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
        let mut ids = Vec::new();
        ids.try_reserve_exact(rule_count)
            .map_err(|_| QualificationError::new("continuation id allocation failed"))?;
        for index in 0..rule_count {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_ip(IpAddr::V4(dns_bench_ip(index.saturating_add(10_000))))
                .map_err(|error| {
                    QualificationError::new(format!("continuation IP failed: {error}"))
                })?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("continuation MatchSet failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("continuation snapshot add failed: {error}"))
                })?;
            ids.push(
                snapshot_builder
                    .add_rule_set(&format!("continuation-{index}"), match_set)
                    .map_err(|error| {
                        QualificationError::new(format!("continuation RuleSet add failed: {error}"))
                    })?,
            );
        }
        let local = DnsPolicyRoute::new(DnsServerId::new(11), DnsStrategy::Ipv4Only);
        let final_route = DnsPolicyRoute::new(DnsServerId::new(12), DnsStrategy::PreferIpv4);
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(rule_count)
            .map_err(|_| QualificationError::new("continuation rule allocation failed"))?;
        for id in ids {
            let matcher =
                DnsPolicyMatcher::try_new(Vec::new(), vec![id], Vec::new(), Vec::new(), Vec::new())
                    .map_err(|error| {
                        QualificationError::new(format!("continuation matcher failed: {error}"))
                    })?;
            rules.push(DnsPolicyRule::new(matcher, DnsPolicyAction::Route(local)));
        }
        let snapshot = Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("continuation snapshot failed: {error}"))
        })?);
        let program =
            DnsPolicyProgram::try_new(rules, final_route, &snapshot).map_err(|error| {
                QualificationError::new(format!("continuation program failed: {error}"))
            })?;
        let name = Name::from_str("continuation.bench.invalid.")
            .map_err(|_| QualificationError::new("continuation qname is invalid"))?;
        let build = finish_build(started, &allocation_region)?;
        let fixture = DnsResponseFixture {
            program,
            snapshot,
            name,
            build,
        };
        let response = dns_a_response(
            "continuation.bench.invalid.",
            dns_bench_ip(rule_count.saturating_sub(1).saturating_add(10_000)),
        )?;
        let evaluate = || evaluate_dns_response(&fixture, &response);
        if evaluate() != local.server().get() {
            return Err(QualificationError::new(format!(
                "DNS continuation/{continuations} correctness check failed"
            )));
        }
        let iterations = scaled_iterations(base_iterations, 1, rule_count);
        let result = benchmark(|| u64::from(evaluate()), samples, iterations);
        measurements.push(measurement(
            format!("dns_policy/ruleset/{continuations}/same_server_continuation"),
            "dns_policy",
            "ruleset",
            "same_server_continuation",
            continuations,
            None,
            Some(fixture.program.mode()),
            iterations,
            fixture.build,
            Some(rule_count),
            result,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_qname_sources_return_the_same_selected_rule() {
        let _guard = allocator_test_lock();
        let name = Name::from_str("dns-2.bench.invalid.").expect("name");
        for source in DnsQuerySource::ALL {
            let fixture = build_dns_qname_fixture(3, source).expect("DNS fixture");
            assert_eq!(evaluate_dns_qname(&fixture, &name), 2);
        }
    }

    #[test]
    fn dns_index_mode_and_candidate_evidence_cover_boundary_and_scale() {
        let _guard = allocator_test_lock();
        for (count, expected_mode) in [
            (64, RuleProgramMode::SmallLinear),
            (65, RuleProgramMode::Indexed),
            (1_000, RuleProgramMode::Indexed),
            (10_000, RuleProgramMode::Indexed),
        ] {
            let fixture = build_dns_qname_fixture(count, DnsQuerySource::Ordinary)
                .expect("DNS indexed evidence fixture");
            assert_eq!(fixture.program.mode(), expected_mode);
            let last = Name::from_str(&format!("dns-{}.bench.invalid.", count - 1))
                .expect("last DNS name");
            let (selected, visits) = evaluate_dns_qname_evidence(&fixture, &last);
            assert_eq!(selected, (count - 1) as u32);
            if expected_mode == RuleProgramMode::Indexed {
                assert!(visits < count, "{count} last-hit visits={visits}");
            }
            let miss =
                Name::from_str(&format!("dns-{count}.bench.invalid.")).expect("missing DNS name");
            let (_, visits) = evaluate_dns_qname_evidence(&fixture, &miss);
            if expected_mode == RuleProgramMode::Indexed {
                assert!(visits < count, "{count} miss visits={visits}");
            }
        }

        let mut rows = Vec::new();
        run_dns_qname(&[65], 5, 1, &mut rows).expect("DNS evidence rows");
        assert!(rows.iter().all(|row| {
            row.rule_program_mode == Some("indexed") && row.query_candidate_visits.is_some()
        }));
    }
}
