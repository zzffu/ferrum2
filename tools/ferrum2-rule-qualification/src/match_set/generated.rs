use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use ferrum2_rule::{CompiledMatchSet, MatchSetBuilder, RuleEngineSnapshotBuilder};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::cli::{QualificationError, Result};
use crate::match_set::benchmark::{CompiledSetOwner, MatcherKind};
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::report::BuildEvidence;

pub(crate) fn build_generated_match_set_pair(
    kind: MatcherKind,
    scale: usize,
) -> Result<(
    (CompiledSetOwner, BuildEvidence),
    (CompiledSetOwner, BuildEvidence),
)> {
    let ordinary_region = allocation_region();
    let ordinary_started = Instant::now();
    let compiled = Arc::new(compile_generated_match_set(kind, scale)?);
    let ordinary = CompiledSetOwner::Direct(Arc::clone(&compiled));
    let ordinary_build = finish_build(ordinary_started, &ordinary_region)?;

    let synthetic_region = allocation_region();
    let synthetic_started = Instant::now();
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let match_set = snapshot
        .add_shared_match_set(compiled)
        .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
    snapshot
        .add_rule_set("synthetic", match_set)
        .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
    let synthetic = CompiledSetOwner::Snapshot {
        snapshot: snapshot
            .build()
            .map_err(|error| QualificationError::new(format!("snapshot build failed: {error}")))?,
        match_set,
    };
    let wrapper_build = finish_build(synthetic_started, &synthetic_region)?;
    Ok((
        (ordinary, ordinary_build),
        (synthetic, ordinary_build.combined(wrapper_build)),
    ))
}

#[cfg(test)]
pub(crate) fn build_generated_match_set(
    kind: MatcherKind,
    scale: usize,
    synthetic: bool,
) -> Result<(CompiledSetOwner, BuildEvidence)> {
    let allocation_region = allocation_region();
    let started = Instant::now();
    let compiled = compile_generated_match_set(kind, scale)?;
    let owner = if synthetic {
        let mut snapshot = RuleEngineSnapshotBuilder::new(1);
        let match_set = snapshot
            .add_match_set(compiled)
            .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
        snapshot
            .add_rule_set("synthetic", match_set)
            .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
        CompiledSetOwner::Snapshot {
            snapshot: snapshot.build().map_err(|error| {
                QualificationError::new(format!("snapshot build failed: {error}"))
            })?,
            match_set,
        }
    } else {
        CompiledSetOwner::Direct(Arc::new(compiled))
    };
    let build = finish_build(started, &allocation_region)?;
    Ok((owner, build))
}

pub(crate) fn compile_generated_match_set(
    kind: MatcherKind,
    scale: usize,
) -> Result<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    for index in 0..scale {
        add_generated_value(&mut builder, kind, index)?;
    }
    builder
        .build()
        .map_err(|error| QualificationError::new(format!("MatchSet build failed: {error}")))
}

pub(crate) fn add_generated_value(
    builder: &mut MatchSetBuilder,
    kind: MatcherKind,
    index: usize,
) -> Result<()> {
    let selected = selected_matcher_kind(kind, index);
    let result = match selected {
        MatcherKind::Exact => builder.add_exact_domain(&format!("exact-{index}.bench.invalid")),
        MatcherKind::Suffix => builder.add_domain_suffix(&format!("suffix-{index}.bench.invalid")),
        MatcherKind::Keyword => builder.add_domain_keyword(&format!("needle{index}x")),
        MatcherKind::CidrV4 => builder.add_ip_cidr(IpNet::V4(generated_v4(index)?)),
        MatcherKind::CidrV6 => builder.add_ip_cidr(IpNet::V6(generated_v6(index)?)),
        MatcherKind::Mixed => unreachable!("mixed is reduced to one concrete category"),
    };
    result
        .map(|_| ())
        .map_err(|error| QualificationError::new(format!("MatchSet value failed: {error}")))
}

pub(crate) const fn selected_matcher_kind(kind: MatcherKind, index: usize) -> MatcherKind {
    match kind {
        MatcherKind::Mixed => match index % 5 {
            0 => MatcherKind::Exact,
            1 => MatcherKind::Suffix,
            2 => MatcherKind::Keyword,
            3 => MatcherKind::CidrV4,
            _ => MatcherKind::CidrV6,
        },
        other => other,
    }
}

pub(crate) fn generated_v4(index: usize) -> Result<Ipv4Net> {
    let index =
        u32::try_from(index).map_err(|_| QualificationError::new("IPv4 fixture index overflow"))?;
    let address = Ipv4Addr::from(0x0a00_0000_u32 | (index & 0x00ff_ffff));
    Ipv4Net::new(address, 32)
        .map_err(|_| QualificationError::new("generated IPv4 prefix is invalid"))
}

pub(crate) fn generated_v6(index: usize) -> Result<Ipv6Net> {
    let index = u128::try_from(index)
        .map_err(|_| QualificationError::new("IPv6 fixture index overflow"))?;
    let address = Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 | index);
    Ipv6Net::new(address, 128)
        .map_err(|_| QualificationError::new("generated IPv6 prefix is invalid"))
}
