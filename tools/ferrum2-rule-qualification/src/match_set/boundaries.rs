use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use ferrum2_rule::{MatchSetBuilder, RuleEngineSnapshotBuilder};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::cli::{QualificationError, Result};
use crate::match_set::benchmark::{CompiledSetOwner, MatchProbe, probe_matches};
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::benchmark_pair;
use crate::report::{BuildEvidence, Measurement};

const CIDR_REFERENCE_PROBES: usize = 512;

pub(crate) struct CidrBoundaryCase {
    name: &'static str,
    probe: MatchProbe,
    expected: bool,
}

pub(crate) struct CidrBoundaryScenario {
    name: &'static str,
    networks: Vec<IpNet>,
    cases: Vec<CidrBoundaryCase>,
}

pub(crate) fn run_cidr_boundary_scenarios(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for scenario in cidr_boundary_scenarios(sizes)? {
        let ((ordinary, ordinary_build), (synthetic, synthetic_build)) =
            build_cidr_pair(&scenario.networks)?;
        let ordinary_set = ordinary.compiled();
        let synthetic_set = synthetic.compiled();
        verify_cidr_reference_matrix(&scenario.networks, ordinary_set, synthetic_set)?;
        let compiled_entries = ordinary_set.entry_counts().total();
        for case in scenario.cases {
            if probe_matches(ordinary_set, &case.probe) != case.expected
                || probe_matches(synthetic_set, &case.probe) != case.expected
            {
                return Err(QualificationError::new(
                    "CIDR boundary correctness check failed",
                ));
            }
            let pair_id = format!("match_set/cidr_boundary/{}/{}", scenario.name, case.name);
            let (ordinary_result, synthetic_result) = benchmark_pair(
                ordinary_set,
                synthetic_set,
                &case.probe,
                samples,
                base_iterations,
                pair_id,
            );
            let scenario_name = format!("cidr_boundary/{}/{}", scenario.name, case.name);
            for (source, build, result) in [
                ("ordinary_inline", ordinary_build, ordinary_result),
                ("synthetic_ruleset", synthetic_build, synthetic_result),
            ] {
                measurements.push(measurement(
                    format!("match_set/{source}/{scenario_name}"),
                    "match_set",
                    source,
                    scenario_name.clone(),
                    scenario.networks.len(),
                    None,
                    None,
                    base_iterations,
                    build,
                    Some(compiled_entries),
                    result,
                ));
            }
        }
    }
    Ok(())
}

fn verify_cidr_reference_matrix(
    networks: &[IpNet],
    ordinary: &ferrum2_rule::CompiledMatchSet,
    synthetic: &ferrum2_rule::CompiledMatchSet,
) -> Result<()> {
    let ipv4 = networks
        .iter()
        .filter_map(|network| match network {
            IpNet::V4(network) => Some(network),
            IpNet::V6(_) => None,
        })
        .collect::<Vec<_>>();
    let ipv6 = networks
        .iter()
        .filter_map(|network| match network {
            IpNet::V4(_) => None,
            IpNet::V6(network) => Some(network),
        })
        .collect::<Vec<_>>();
    if ipv4.is_empty() || ipv6.is_empty() {
        return Err(QualificationError::new(
            "CIDR reference matrix requires both address families",
        ));
    }

    let mut state = 0x6a09_e667_f3bc_c909_u64
        ^ u64::try_from(networks.len())
            .unwrap_or(u64::MAX)
            .rotate_left(17);
    for index in 0..CIDR_REFERENCE_PROBES {
        let address = match index % 4 {
            0 => IpAddr::V4(Ipv4Addr::from(next_reference_word(&mut state) as u32)),
            1 => IpAddr::V6(Ipv6Addr::from(reference_u128(&mut state))),
            2 => ipv4_address_in(
                ipv4[index % ipv4.len()],
                next_reference_word(&mut state) as u32,
            ),
            _ => ipv6_address_in(ipv6[index % ipv6.len()], reference_u128(&mut state)),
        };
        let expected = networks.iter().any(|network| network.contains(&address));
        let probe = MatchProbe::Ip(address);
        if probe_matches(ordinary, &probe) != expected
            || probe_matches(synthetic, &probe) != expected
        {
            return Err(QualificationError::new(
                "CIDR matcher diverged from the linear IpNet reference",
            ));
        }
    }
    Ok(())
}

fn next_reference_word(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn reference_u128(state: &mut u64) -> u128 {
    (u128::from(next_reference_word(state)) << 64) | u128::from(next_reference_word(state))
}

fn ipv4_address_in(network: &Ipv4Net, entropy: u32) -> IpAddr {
    let host_mask = match network.prefix_len() {
        0 => u32::MAX,
        32 => 0,
        prefix => u32::MAX >> prefix,
    };
    IpAddr::V4(Ipv4Addr::from(
        u32::from(network.network()) | (entropy & host_mask),
    ))
}

fn ipv6_address_in(network: &Ipv6Net, entropy: u128) -> IpAddr {
    let host_mask = match network.prefix_len() {
        0 => u128::MAX,
        128 => 0,
        prefix => u128::MAX >> prefix,
    };
    IpAddr::V6(Ipv6Addr::from(
        u128::from(network.network()) | (entropy & host_mask),
    ))
}

pub(crate) fn cidr_boundary_scenarios(sizes: &[usize]) -> Result<Vec<CidrBoundaryScenario>> {
    let small = sizes
        .first()
        .copied()
        .ok_or_else(|| QualificationError::new("CIDR boundary sizes are empty"))?;
    let large = sizes
        .iter()
        .copied()
        .filter(|size| *size <= 10_000)
        .max()
        .ok_or_else(|| QualificationError::new("CIDR boundary sizes are empty"))?;
    Ok(vec![
        default_routes()?,
        host_prefixes()?,
        overlapping_prefixes()?,
        prefix_distribution("prefix_distribution_small", small)?,
        prefix_distribution("prefix_distribution_large", large)?,
        deterministic_random_mixed("random_mixed_small", small)?,
        deterministic_random_mixed("random_mixed_large", large)?,
    ])
}

fn build_cidr_pair(
    networks: &[IpNet],
) -> Result<(
    (CompiledSetOwner, BuildEvidence),
    (CompiledSetOwner, BuildEvidence),
)> {
    let ordinary_region = allocation_region();
    let ordinary_started = Instant::now();
    let mut builder = MatchSetBuilder::new();
    for network in networks {
        builder.add_ip_cidr(*network).map_err(|error| {
            QualificationError::new(format!("CIDR boundary build failed: {error}"))
        })?;
    }
    let compiled = Arc::new(builder.build().map_err(|error| {
        QualificationError::new(format!("CIDR boundary build failed: {error}"))
    })?);
    let ordinary = CompiledSetOwner::Direct(Arc::clone(&compiled));
    let ordinary_build = finish_build(ordinary_started, &ordinary_region)?;

    let synthetic_region = allocation_region();
    let synthetic_started = Instant::now();
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let match_set = snapshot.add_shared_match_set(compiled).map_err(|error| {
        QualificationError::new(format!("CIDR boundary snapshot failed: {error}"))
    })?;
    snapshot
        .add_rule_set("cidr-boundary", match_set)
        .map_err(|error| {
            QualificationError::new(format!("CIDR boundary snapshot failed: {error}"))
        })?;
    let synthetic = CompiledSetOwner::Snapshot {
        snapshot: snapshot.build().map_err(|error| {
            QualificationError::new(format!("CIDR boundary snapshot failed: {error}"))
        })?,
        match_set,
    };
    let wrapper_build = finish_build(synthetic_started, &synthetic_region)?;
    Ok((
        (ordinary, ordinary_build),
        (synthetic, ordinary_build.combined(wrapper_build)),
    ))
}

fn default_routes() -> Result<CidrBoundaryScenario> {
    Ok(CidrBoundaryScenario {
        name: "default_routes",
        networks: vec![net("0.0.0.0/0")?, net("::/0")?],
        cases: vec![
            ip_case("ipv4_hit", "198.51.100.77", true)?,
            ip_case("ipv6_hit", "2001:db8:ffff::77", true)?,
        ],
    })
}

fn host_prefixes() -> Result<CidrBoundaryScenario> {
    Ok(CidrBoundaryScenario {
        name: "host_prefixes",
        networks: vec![net("192.0.2.7/32")?, net("2001:db8::7/128")?],
        cases: vec![
            ip_case("ipv4_32_hit", "192.0.2.7", true)?,
            ip_case("ipv4_32_miss", "192.0.2.8", false)?,
            ip_case("ipv6_128_hit", "2001:db8::7", true)?,
            ip_case("ipv6_128_miss", "2001:db8::8", false)?,
        ],
    })
}

fn overlapping_prefixes() -> Result<CidrBoundaryScenario> {
    Ok(CidrBoundaryScenario {
        name: "overlapping_prefixes",
        networks: vec![
            net("10.0.0.0/8")?,
            net("10.20.0.0/16")?,
            net("10.20.30.0/24")?,
            net("2001:db8::/32")?,
            net("2001:db8:1::/48")?,
            net("2001:db8:1:2::/64")?,
        ],
        cases: vec![
            ip_case("ipv4_deepest_hit", "10.20.30.9", true)?,
            ip_case("ipv4_parent_hit", "10.99.1.1", true)?,
            ip_case("ipv6_deepest_hit", "2001:db8:1:2::9", true)?,
            ip_case("mixed_miss", "203.0.113.9", false)?,
        ],
    })
}

fn prefix_distribution(name: &'static str, scale: usize) -> Result<CidrBoundaryScenario> {
    let mut networks = Vec::new();
    networks
        .try_reserve_exact(scale)
        .map_err(|_| QualificationError::new("CIDR distribution reservation failed"))?;
    for index in 0..scale {
        networks.push(distributed_network(index)?);
    }
    let (ipv4_hit, ipv6_hit) = representative_hits(&networks)?;
    Ok(CidrBoundaryScenario {
        name,
        networks,
        cases: vec![
            CidrBoundaryCase {
                name: "ipv4_varied_hit",
                probe: MatchProbe::Ip(ipv4_hit),
                expected: true,
            },
            CidrBoundaryCase {
                name: "ipv6_varied_hit",
                probe: MatchProbe::Ip(ipv6_hit),
                expected: true,
            },
            ip_case("ipv4_varied_miss", "203.0.113.251", false)?,
            ip_case("ipv6_varied_miss", "2001:dbf::251", false)?,
        ],
    })
}

fn deterministic_random_mixed(name: &'static str, scale: usize) -> Result<CidrBoundaryScenario> {
    let mut networks = Vec::new();
    networks
        .try_reserve_exact(scale)
        .map_err(|_| QualificationError::new("CIDR random reservation failed"))?;
    for index in 0..scale {
        let ordinal = u64::try_from(index / 2)
            .map_err(|_| QualificationError::new("CIDR random index overflow"))?;
        if index % 2 == 0 {
            let permuted =
                ordinal.wrapping_mul(0x00_9e_37_79).wrapping_add(0x12_34_57) & 0x00ff_ffff;
            let address = Ipv4Addr::from(0x6400_0000_u32 | permuted as u32);
            networks.push(IpNet::V4(Ipv4Net::new(address, 32).map_err(|_| {
                QualificationError::new("CIDR random IPv4 value is invalid")
            })?));
        } else {
            let permuted = ordinal
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0x517c_c1b7_2722_0a95);
            let address = Ipv6Addr::from(
                0x2001_0db9_0000_0000_0000_0000_0000_0000_u128 | u128::from(permuted),
            );
            networks.push(IpNet::V6(Ipv6Net::new(address, 128).map_err(|_| {
                QualificationError::new("CIDR random IPv6 value is invalid")
            })?));
        }
    }
    let (ipv4_hit, ipv6_hit) = representative_hits(&networks)?;
    Ok(CidrBoundaryScenario {
        name,
        networks,
        cases: vec![
            CidrBoundaryCase {
                name: "random_ipv4_hit",
                probe: MatchProbe::Ip(ipv4_hit),
                expected: true,
            },
            CidrBoundaryCase {
                name: "random_ipv6_hit",
                probe: MatchProbe::Ip(ipv6_hit),
                expected: true,
            },
            ip_case("random_ipv4_miss", "203.0.113.252", false)?,
            ip_case("random_ipv6_miss", "2001:dbf::252", false)?,
        ],
    })
}

fn distributed_network(index: usize) -> Result<IpNet> {
    let ordinal = u128::try_from(index / 7)
        .map_err(|_| QualificationError::new("CIDR distribution index overflow"))?;
    match index % 7 {
        0 => ipv4_network(0x0a00_0000, ordinal, 24),
        1 => ipv4_network(0x0b00_0000, ordinal, 28),
        2 => ipv4_network(0x0c00_0000, ordinal, 32),
        3 => ipv6_network(0x2001_0db8_1000_0000_0000_0000_0000_0000, ordinal, 48),
        4 => ipv6_network(0x2001_0db8_2000_0000_0000_0000_0000_0000, ordinal, 64),
        5 => ipv6_network(0x2001_0db8_3000_0000_0000_0000_0000_0000, ordinal, 96),
        _ => ipv6_network(0x2001_0db8_4000_0000_0000_0000_0000_0000, ordinal, 128),
    }
}

fn ipv4_network(base: u32, ordinal: u128, prefix: u8) -> Result<IpNet> {
    let ordinal = u32::try_from(ordinal)
        .map_err(|_| QualificationError::new("CIDR IPv4 distribution overflow"))?;
    let shift = u32::from(32_u8.saturating_sub(prefix));
    let address = base
        .checked_add(ordinal.checked_shl(shift).unwrap_or(0))
        .ok_or_else(|| QualificationError::new("CIDR IPv4 distribution overflow"))?;
    Ipv4Net::new(Ipv4Addr::from(address), prefix)
        .map(IpNet::V4)
        .map_err(|_| QualificationError::new("CIDR IPv4 distribution is invalid"))
}

fn ipv6_network(base: u128, ordinal: u128, prefix: u8) -> Result<IpNet> {
    let shift = u32::from(128_u8.saturating_sub(prefix));
    let address = base
        .checked_add(ordinal.checked_shl(shift).unwrap_or(0))
        .ok_or_else(|| QualificationError::new("CIDR IPv6 distribution overflow"))?;
    Ipv6Net::new(Ipv6Addr::from(address), prefix)
        .map(IpNet::V6)
        .map_err(|_| QualificationError::new("CIDR IPv6 distribution is invalid"))
}

fn representative_hits(networks: &[IpNet]) -> Result<(IpAddr, IpAddr)> {
    let ipv4 = networks
        .iter()
        .find_map(|network| match network {
            IpNet::V4(network) => Some(IpAddr::V4(network.network())),
            IpNet::V6(_) => None,
        })
        .ok_or_else(|| QualificationError::new("CIDR scenario has no IPv4 value"))?;
    let ipv6 = networks
        .iter()
        .rev()
        .find_map(|network| match network {
            IpNet::V4(_) => None,
            IpNet::V6(network) => Some(IpAddr::V6(network.network())),
        })
        .ok_or_else(|| QualificationError::new("CIDR scenario has no IPv6 value"))?;
    Ok((ipv4, ipv6))
}

fn net(value: &str) -> Result<IpNet> {
    value
        .parse()
        .map_err(|_| QualificationError::new("CIDR boundary network is invalid"))
}

fn ip_case(name: &'static str, value: &str, expected: bool) -> Result<CidrBoundaryCase> {
    Ok(CidrBoundaryCase {
        name,
        probe: MatchProbe::Ip(
            value
                .parse()
                .map_err(|_| QualificationError::new("CIDR boundary probe is invalid"))?,
        ),
        expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::allocation::allocator_test_lock;

    #[test]
    fn boundary_catalog_is_stable_and_covers_required_prefix_shapes() {
        let _guard = allocator_test_lock();
        let scenarios = cidr_boundary_scenarios(&[8, 10_000, 100_000]).expect("CIDR scenarios");
        assert_eq!(
            scenarios
                .iter()
                .map(|scenario| scenario.name)
                .collect::<Vec<_>>(),
            vec![
                "default_routes",
                "host_prefixes",
                "overlapping_prefixes",
                "prefix_distribution_small",
                "prefix_distribution_large",
                "random_mixed_small",
                "random_mixed_large",
            ]
        );
        let prefixes = scenarios
            .iter()
            .flat_map(|scenario| scenario.networks.iter().map(IpNet::prefix_len))
            .collect::<Vec<_>>();
        for required in [0, 32, 128] {
            assert!(prefixes.contains(&required));
        }
        assert_eq!(scenarios[3].networks.len(), 8);
        assert_eq!(scenarios[4].networks.len(), 10_000);
        assert_eq!(scenarios[5].networks.len(), 8);
        assert_eq!(scenarios[6].networks.len(), 10_000);
    }

    #[test]
    fn every_boundary_probe_matches_the_compiled_reference() {
        let _guard = allocator_test_lock();
        for scenario in cidr_boundary_scenarios(&[8, 128]).expect("CIDR scenarios") {
            let ((ordinary, _), (synthetic, _)) =
                build_cidr_pair(&scenario.networks).expect("compiled boundary");
            verify_cidr_reference_matrix(
                &scenario.networks,
                ordinary.compiled(),
                synthetic.compiled(),
            )
            .expect("linear IpNet reference matrix");
            for case in scenario.cases {
                assert_eq!(
                    probe_matches(ordinary.compiled(), &case.probe),
                    case.expected
                );
                assert_eq!(
                    probe_matches(synthetic.compiled(), &case.probe),
                    case.expected
                );
            }
        }
    }
}
