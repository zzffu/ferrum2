use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ferrum2_core::CanonicalDomain;
use ferrum2_rule::{CompiledMatchSet, MatchSetId, RuleEngineSnapshot};

use crate::cli::{QualificationError, Result};
use crate::match_set::generated::{build_generated_match_set_pair, generated_v4, generated_v6};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::benchmark_pair;
use crate::report::Measurement;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MatcherKind {
    Exact,
    Suffix,
    Keyword,
    CidrV4,
    CidrV6,
    Mixed,
}

impl MatcherKind {
    pub(crate) const ALL: [Self; 6] = [
        Self::Exact,
        Self::Suffix,
        Self::Keyword,
        Self::CidrV4,
        Self::CidrV6,
        Self::Mixed,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
            Self::Keyword => "keyword",
            Self::CidrV4 => "cidr_ipv4",
            Self::CidrV6 => "cidr_ipv6",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone)]
pub(crate) enum MatchProbe {
    Domain(CanonicalDomain),
    Ip(IpAddr),
}

pub(crate) struct ProbeCase {
    pub(crate) name: &'static str,
    pub(crate) probe: MatchProbe,
    pub(crate) expected: bool,
}

pub(crate) enum CompiledSetOwner {
    Direct(Arc<CompiledMatchSet>),
    Snapshot {
        snapshot: RuleEngineSnapshot,
        match_set: MatchSetId,
    },
}

impl CompiledSetOwner {
    pub(crate) fn compiled(&self) -> &CompiledMatchSet {
        match self {
            Self::Direct(set) => set,
            Self::Snapshot {
                snapshot,
                match_set,
            } => snapshot
                .match_set(*match_set)
                .expect("registered synthetic MatchSet"),
        }
    }
}

pub(crate) fn run_generated_match_sets(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &scale in sizes {
        for kind in MatcherKind::ALL {
            let (ordinary, synthetic) = build_generated_match_set_pair(kind, scale)?;
            for case in match_probe_cases(kind, scale)? {
                let ordinary_set = ordinary.0.compiled();
                let synthetic_set = synthetic.0.compiled();
                if probe_matches(ordinary_set, &case.probe) != case.expected {
                    return Err(QualificationError::new(format!(
                        "generated ordinary_inline {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                if probe_matches(synthetic_set, &case.probe) != case.expected {
                    return Err(QualificationError::new(format!(
                        "generated synthetic_ruleset {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                let scenario = format!("{}/{}", kind.name(), case.name);
                let pair_id = format!("match_set/{scale}/{scenario}");
                let (ordinary_result, synthetic_result) = benchmark_pair(
                    ordinary_set,
                    synthetic_set,
                    &case.probe,
                    samples,
                    base_iterations,
                    pair_id,
                );
                measurements.push(measurement(
                    format!("match_set/ordinary_inline/{scale}/{scenario}"),
                    "match_set",
                    "ordinary_inline",
                    scenario.clone(),
                    scale,
                    None,
                    None,
                    base_iterations,
                    ordinary.1,
                    Some(ordinary_set.entry_counts().total()),
                    ordinary_result,
                ));
                measurements.push(measurement(
                    format!("match_set/synthetic_ruleset/{scale}/{scenario}"),
                    "match_set",
                    "synthetic_ruleset",
                    scenario,
                    scale,
                    None,
                    None,
                    base_iterations,
                    synthetic.1,
                    Some(synthetic_set.entry_counts().total()),
                    synthetic_result,
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn match_probe_cases(kind: MatcherKind, scale: usize) -> Result<Vec<ProbeCase>> {
    let last = scale
        .checked_sub(1)
        .ok_or_else(|| QualificationError::new("MatchSet scale is zero"))?;
    let cases = match kind {
        MatcherKind::Exact => vec![
            domain_case("hit", &format!("exact-{last}.bench.invalid"), true)?,
            domain_case("miss", "exact-miss.bench.invalid", false)?,
        ],
        MatcherKind::Suffix => vec![
            domain_case("hit", &format!("child.suffix-{last}.bench.invalid"), true)?,
            domain_case("miss", "suffix-miss.example", false)?,
        ],
        MatcherKind::Keyword => vec![
            domain_case("hit", &format!("prefix-needle{last}x-suffix.invalid"), true)?,
            domain_case("miss", "keyword-miss.example", false)?,
        ],
        MatcherKind::CidrV4 => vec![
            ProbeCase {
                name: "hit",
                probe: MatchProbe::Ip(IpAddr::V4(generated_v4(last)?.addr())),
                expected: true,
            },
            ProbeCase {
                name: "miss",
                probe: MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                expected: false,
            },
        ],
        MatcherKind::CidrV6 => vec![
            ProbeCase {
                name: "hit",
                probe: MatchProbe::Ip(IpAddr::V6(generated_v6(last)?.addr())),
                expected: true,
            },
            ProbeCase {
                name: "miss",
                probe: MatchProbe::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                expected: false,
            },
        ],
        MatcherKind::Mixed => {
            let exact = last - (last % 5);
            let v4 = (0..scale).rev().find(|index| index % 5 == 3).unwrap_or(3);
            vec![
                domain_case("domain_hit", &format!("exact-{exact}.bench.invalid"), true)?,
                ProbeCase {
                    name: "ip_hit",
                    probe: MatchProbe::Ip(IpAddr::V4(generated_v4(v4)?.addr())),
                    expected: true,
                },
                domain_case("domain_miss", "mixed-miss.example", false)?,
                ProbeCase {
                    name: "ip_miss",
                    probe: MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))),
                    expected: false,
                },
            ]
        }
    };
    Ok(cases)
}

pub(crate) fn domain_case(name: &'static str, value: &str, expected: bool) -> Result<ProbeCase> {
    Ok(ProbeCase {
        name,
        probe: MatchProbe::Domain(
            CanonicalDomain::new(value)
                .map_err(|_| QualificationError::new("generated domain probe is invalid"))?,
        ),
        expected,
    })
}

pub(crate) fn probe_matches(set: &CompiledMatchSet, probe: &MatchProbe) -> bool {
    match probe {
        MatchProbe::Domain(domain) => set.matches_domain(domain),
        MatchProbe::Ip(address) => set.matches_ip(*address),
    }
}
