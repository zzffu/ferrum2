use std::collections::VecDeque;
use std::fs;
use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ferrum2_core::CanonicalDomain;
use ferrum2_rule::srs::{SrsStatistics, decode_srs};
use ferrum2_rule::{MatchSetCapabilities, RuleEngineSnapshotBuilder};
use flate2::Compression;
use flate2::write::ZlibEncoder;

use crate::cli::{QualificationError, Result};
use crate::execute::sha256_bytes;
use crate::match_set::benchmark::{
    CompiledSetOwner, MatchProbe, MatcherKind, match_probe_cases, probe_matches,
};
use crate::match_set::generated::{
    compile_generated_match_set, generated_exact_domain, generated_suffix_domain, generated_v4,
    generated_v6, selected_matcher_kind,
};
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::benchmark_pair;
use crate::report::{BuildEvidence, FixtureEvidence, Measurement};

pub(crate) const SYNTHETIC_SRS_VERSION: u8 = 2;
pub(crate) const SRS_ITEM_DOMAIN: u8 = 2;
pub(crate) const SRS_ITEM_DOMAIN_KEYWORD: u8 = 3;
pub(crate) const SRS_ITEM_IP_CIDR: u8 = 6;
pub(crate) const SRS_ITEM_FINAL: u8 = 0xff;
pub(crate) const SRS_DOMAIN_SUFFIX_MARKER: u8 = b'\n';

pub(crate) fn run_generated_binary_srs(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<Vec<FixtureEvidence>> {
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(sizes.len().saturating_mul(MatcherKind::ALL.len()))
        .map_err(|_| QualificationError::new("generated SRS evidence allocation failed"))?;
    for &scale in sizes {
        for kind in MatcherKind::ALL {
            let fixture_name = format!("generated-{}-{scale}.srs", kind.name());
            let bytes = encode_generated_srs(kind, scale)?;
            let digest = sha256_bytes(&bytes);

            let binary_region = allocation_region();
            let binary_started = Instant::now();
            let decoded = decode_srs(Cursor::new(&bytes)).map_err(|error| {
                QualificationError::new(format!(
                    "generated SRS {}/{scale} decode failed: {error}",
                    kind.name()
                ))
            })?;
            let version = decoded.version();
            let statistics = decoded.statistics();
            let capabilities = decoded.capabilities();
            let binary_set = Arc::new(decoded.compile().map_err(|error| {
                QualificationError::new(format!(
                    "generated SRS {}/{scale} compile failed: {error}",
                    kind.name()
                ))
            })?);
            let binary_build = finish_build(binary_started, &binary_region)?;

            let (synthetic_reference, _) =
                build_synthetic_srs_match_set(kind, scale, &fixture_name)?;
            let reference_set = synthetic_reference.compiled();
            let expected_statistics = generated_srs_statistics(kind, scale);
            if version != SYNTHETIC_SRS_VERSION
                || statistics != expected_statistics
                || binary_set.entry_counts().total() != scale
                || reference_set.entry_counts().total() != scale
            {
                return Err(QualificationError::new(format!(
                    "generated SRS {}/{scale} structural evidence mismatch",
                    kind.name()
                )));
            }

            // Time the two source wrappers against the exact same compiled
            // object. The independently compiled synthetic reference above
            // proves data/decoder equivalence without letting allocator layout
            // masquerade as a matcher-backend performance difference.
            let synthetic_region = allocation_region();
            let synthetic_started = Instant::now();
            let mut snapshot = RuleEngineSnapshotBuilder::new(1);
            let synthetic_match_set = snapshot
                .add_shared_match_set(Arc::clone(&binary_set))
                .map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS snapshot add failed: {error}"
                    ))
                })?;
            snapshot
                .add_rule_set(&fixture_name, synthetic_match_set)
                .map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS registration failed: {error}"
                    ))
                })?;
            let synthetic_owner = CompiledSetOwner::Snapshot {
                snapshot: snapshot.build().map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS snapshot failed: {error}"
                    ))
                })?,
                match_set: synthetic_match_set,
            };
            let synthetic_build =
                binary_build.combined(finish_build(synthetic_started, &synthetic_region)?);
            let synthetic_set = synthetic_owner.compiled();
            if !std::ptr::eq(synthetic_set, binary_set.as_ref()) {
                return Err(QualificationError::new(
                    "generated SRS timing sources do not share one compiled matcher",
                ));
            }

            for case in match_probe_cases(kind, scale)? {
                if probe_matches(reference_set, &case.probe) != case.expected
                    || probe_matches(synthetic_set, &case.probe) != case.expected
                    || probe_matches(&binary_set, &case.probe) != case.expected
                {
                    return Err(QualificationError::new(format!(
                        "generated SRS {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                let scenario = format!("{}/{}", kind.name(), case.name);
                let pair_id = format!("match_set/srs/{fixture_name}/{scenario}");
                let (synthetic_result, binary_result) = benchmark_pair(
                    synthetic_set,
                    &binary_set,
                    &case.probe,
                    samples,
                    base_iterations,
                    pair_id,
                );
                measurements.push(measurement(
                    format!("match_set/synthetic_srs/{fixture_name}/{scenario}"),
                    "match_set",
                    "synthetic_srs",
                    scenario.clone(),
                    scale,
                    Some(fixture_name.clone()),
                    None,
                    base_iterations,
                    synthetic_build,
                    Some(scale),
                    synthetic_result,
                ));
                measurements.push(measurement(
                    format!("match_set/binary_srs/{fixture_name}/{scenario}"),
                    "match_set",
                    "binary_srs",
                    scenario,
                    scale,
                    Some(fixture_name.clone()),
                    None,
                    base_iterations,
                    binary_build,
                    Some(scale),
                    binary_result,
                ));
            }

            evidence.push(FixtureEvidence {
                name: fixture_name,
                provenance: "deterministic_runner_generated_canonical_srs_v2",
                bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                sha256: digest,
                srs_version: version,
                statistics: statistics.into(),
                capabilities: capabilities.into(),
            });
        }
    }
    Ok(evidence)
}

pub(crate) fn build_synthetic_srs_match_set(
    kind: MatcherKind,
    scale: usize,
    tag: &str,
) -> Result<(CompiledSetOwner, BuildEvidence)> {
    let region = allocation_region();
    let started = Instant::now();
    let compiled = Arc::new(compile_generated_match_set(kind, scale)?);
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let match_set = snapshot
        .add_shared_match_set(compiled)
        .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
    snapshot
        .add_rule_set(tag, match_set)
        .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
    let owner = CompiledSetOwner::Snapshot {
        snapshot: snapshot
            .build()
            .map_err(|error| QualificationError::new(format!("snapshot build failed: {error}")))?,
        match_set,
    };
    let build = finish_build(started, &region)?;
    Ok((owner, build))
}

pub(crate) fn generated_srs_statistics(kind: MatcherKind, scale: usize) -> SrsStatistics {
    let category_count = |category| match kind {
        MatcherKind::Mixed => count_modulo_class(scale, category, 5),
        selected if selected == category => scale,
        _ => 0,
    };
    SrsStatistics {
        rules: 1,
        exact_domains: category_count(MatcherKind::Exact),
        domain_suffixes: category_count(MatcherKind::Suffix),
        domain_keywords: category_count(MatcherKind::Keyword),
        ip_cidrs: category_count(MatcherKind::CidrV4)
            .saturating_add(category_count(MatcherKind::CidrV6)),
    }
}

pub(crate) const fn count_modulo_class(
    scale: usize,
    category: MatcherKind,
    divisor: usize,
) -> usize {
    let remainder = match category {
        MatcherKind::Exact => 0,
        MatcherKind::Suffix => 1,
        MatcherKind::Keyword => 2,
        MatcherKind::CidrV4 => 3,
        MatcherKind::CidrV6 => 4,
        MatcherKind::Mixed => return 0,
    };
    if scale <= remainder {
        0
    } else {
        1 + (scale - 1 - remainder) / divisor
    }
}

pub(crate) fn encode_generated_srs(kind: MatcherKind, scale: usize) -> Result<Vec<u8>> {
    if scale == 0 {
        return Err(QualificationError::new("generated SRS scale is zero"));
    }
    let statistics = generated_srs_statistics(kind, scale);
    let mut payload = Vec::new();
    write_uvarint(1, &mut payload);
    payload.push(0);

    if statistics.exact_domains != 0 || statistics.domain_suffixes != 0 {
        payload.push(SRS_ITEM_DOMAIN);
        let mut keys = Vec::new();
        keys.try_reserve_exact(
            statistics
                .exact_domains
                .saturating_add(statistics.domain_suffixes),
        )
        .map_err(|_| QualificationError::new("generated SRS domain allocation failed"))?;
        for index in 0..scale {
            let selected = selected_matcher_kind(kind, index);
            let value = match selected {
                MatcherKind::Exact => Some(generated_exact_domain(index)),
                MatcherKind::Suffix => Some(generated_suffix_domain(index)),
                _ => None,
            };
            if let Some(value) = value {
                let mut key = Vec::new();
                key.try_reserve_exact(value.len().saturating_add(1))
                    .map_err(|_| QualificationError::new("generated SRS key allocation failed"))?;
                key.extend(value.bytes().rev());
                if selected == MatcherKind::Suffix {
                    key.push(SRS_DOMAIN_SUFFIX_MARKER);
                }
                keys.push(key);
            }
        }
        append_succinct_set(keys, &mut payload)?;
    }

    if statistics.domain_keywords != 0 {
        payload.push(SRS_ITEM_DOMAIN_KEYWORD);
        write_usize_uvarint(statistics.domain_keywords, &mut payload)?;
        for index in 0..scale {
            if selected_matcher_kind(kind, index) == MatcherKind::Keyword {
                append_byte_slice(format!("needle{index}x").as_bytes(), &mut payload)?;
            }
        }
    }

    if statistics.ip_cidrs != 0 {
        payload.push(SRS_ITEM_IP_CIDR);
        payload.push(1);
        payload.extend_from_slice(
            &u64::try_from(statistics.ip_cidrs)
                .map_err(|_| QualificationError::new("generated SRS IP count overflow"))?
                .to_be_bytes(),
        );
        for selected in [MatcherKind::CidrV4, MatcherKind::CidrV6] {
            for index in 0..scale {
                if selected_matcher_kind(kind, index) == selected {
                    let address = match selected {
                        MatcherKind::CidrV4 => IpAddr::V4(generated_v4(index)?.addr()),
                        MatcherKind::CidrV6 => IpAddr::V6(generated_v6(index)?.addr()),
                        _ => unreachable!("only IP matcher kinds are enumerated"),
                    };
                    append_ip_point(address, &mut payload);
                }
            }
        }
    }

    payload.push(SRS_ITEM_FINAL);
    payload.push(0);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&payload).map_err(|error| {
        QualificationError::new(format!("generated SRS compression failed: {error}"))
    })?;
    let compressed = encoder.finish().map_err(|error| {
        QualificationError::new(format!("generated SRS compression failed: {error}"))
    })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(4_usize.saturating_add(compressed.len()))
        .map_err(|_| QualificationError::new("generated SRS output allocation failed"))?;
    encoded.extend_from_slice(b"SRS");
    encoded.push(SYNTHETIC_SRS_VERSION);
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
}

pub(crate) fn append_ip_point(address: IpAddr, output: &mut Vec<u8>) {
    match address {
        IpAddr::V4(address) => {
            write_uvarint(4, output);
            output.extend_from_slice(&address.octets());
            write_uvarint(4, output);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            write_uvarint(16, output);
            output.extend_from_slice(&address.octets());
            write_uvarint(16, output);
            output.extend_from_slice(&address.octets());
        }
    }
}

#[derive(Default)]
pub(crate) struct CanonicalTrieNode {
    first_child: Option<usize>,
    last_child: Option<usize>,
    next_sibling: Option<usize>,
    label: u8,
    terminal: bool,
}

pub(crate) struct CanonicalByteTrie {
    nodes: Vec<CanonicalTrieNode>,
}

impl CanonicalByteTrie {
    fn from_sorted_keys(mut keys: Vec<Vec<u8>>) -> Result<Self> {
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() || keys.iter().any(Vec::is_empty) {
            return Err(QualificationError::new(
                "generated SRS domain set contains no canonical key",
            ));
        }
        let estimated_nodes = keys
            .iter()
            .try_fold(1_usize, |total, key| total.checked_add(key.len()))
            .ok_or_else(|| QualificationError::new("generated SRS trie size overflow"))?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(estimated_nodes)
            .map_err(|_| QualificationError::new("generated SRS trie allocation failed"))?;
        nodes.push(CanonicalTrieNode::default());
        let mut previous = Vec::<u8>::new();
        let mut path = Vec::new();
        path.try_reserve_exact(
            keys.iter()
                .map(Vec::len)
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        )
        .map_err(|_| QualificationError::new("generated SRS trie path allocation failed"))?;
        path.push(0);

        for key in keys {
            let common = previous
                .iter()
                .zip(&key)
                .take_while(|(left, right)| left == right)
                .count();
            path.truncate(common.saturating_add(1));
            let mut parent = *path
                .last()
                .ok_or_else(|| QualificationError::new("generated SRS trie path is empty"))?;
            for &label in &key[common..] {
                let child = nodes.len();
                nodes.push(CanonicalTrieNode {
                    label,
                    ..CanonicalTrieNode::default()
                });
                if let Some(last_child) = nodes[parent].last_child {
                    nodes[last_child].next_sibling = Some(child);
                } else {
                    nodes[parent].first_child = Some(child);
                }
                nodes[parent].last_child = Some(child);
                parent = child;
                path.push(child);
            }
            nodes[parent].terminal = true;
            previous = key;
        }
        nodes.shrink_to_fit();
        Ok(Self { nodes })
    }

    fn append_encoded(&self, output: &mut Vec<u8>) -> Result<()> {
        let mut leaves = Vec::<u64>::new();
        let mut bitmap = Vec::<u64>::new();
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(self.nodes.len().saturating_sub(1))
            .map_err(|_| QualificationError::new("generated SRS label allocation failed"))?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| QualificationError::new("generated SRS trie queue allocation failed"))?;
        queue.push_back((0_usize, 0_usize));
        let mut next_node_id = 1_usize;
        let mut bitmap_position = 0_usize;
        while let Some((node_index, node_id)) = queue.pop_front() {
            let node = self
                .nodes
                .get(node_index)
                .ok_or_else(|| QualificationError::new("generated SRS trie node is invalid"))?;
            if node.terminal {
                set_word_bit(&mut leaves, node_id)?;
            }
            let mut child = node.first_child;
            while let Some(child_index) = child {
                append_bitmap_bit(&mut bitmap, &mut bitmap_position, false)?;
                let child_node = self.nodes.get(child_index).ok_or_else(|| {
                    QualificationError::new("generated SRS trie child is invalid")
                })?;
                labels.push(child_node.label);
                queue.push_back((child_index, next_node_id));
                next_node_id = next_node_id
                    .checked_add(1)
                    .ok_or_else(|| QualificationError::new("generated SRS node ID overflow"))?;
                child = child_node.next_sibling;
            }
            append_bitmap_bit(&mut bitmap, &mut bitmap_position, true)?;
        }
        if next_node_id != self.nodes.len() {
            return Err(QualificationError::new(
                "generated SRS trie serialization lost a node",
            ));
        }
        output.push(0);
        append_u64_words(&leaves, output)?;
        append_u64_words(&bitmap, output)?;
        append_byte_slice(&labels, output)
    }
}

pub(crate) fn append_succinct_set(keys: Vec<Vec<u8>>, output: &mut Vec<u8>) -> Result<()> {
    CanonicalByteTrie::from_sorted_keys(keys)?.append_encoded(output)
}

pub(crate) fn set_word_bit(words: &mut Vec<u64>, position: usize) -> Result<()> {
    let word = position / 64;
    if words.len() <= word {
        words
            .try_reserve(word.saturating_add(1).saturating_sub(words.len()))
            .map_err(|_| QualificationError::new("generated SRS bitset allocation failed"))?;
        words.resize(word.saturating_add(1), 0);
    }
    words[word] |= 1_u64 << (position % 64);
    Ok(())
}

pub(crate) fn append_bitmap_bit(
    words: &mut Vec<u64>,
    position: &mut usize,
    value: bool,
) -> Result<()> {
    let current = *position;
    let word = current / 64;
    if words.len() <= word {
        words
            .try_reserve(1)
            .map_err(|_| QualificationError::new("generated SRS bitmap allocation failed"))?;
        words.push(0);
    }
    if value {
        words[word] |= 1_u64 << (current % 64);
    }
    *position = current
        .checked_add(1)
        .ok_or_else(|| QualificationError::new("generated SRS bitmap size overflow"))?;
    Ok(())
}

pub(crate) fn append_u64_words(words: &[u64], output: &mut Vec<u8>) -> Result<()> {
    write_usize_uvarint(words.len(), output)?;
    for word in words {
        output.extend_from_slice(&word.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn append_byte_slice(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    write_usize_uvarint(bytes.len(), output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn write_usize_uvarint(value: usize, output: &mut Vec<u8>) -> Result<()> {
    write_uvarint(
        u64::try_from(value)
            .map_err(|_| QualificationError::new("generated SRS length overflow"))?,
        output,
    );
    Ok(())
}

pub(crate) fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

pub(crate) fn run_real_srs(
    workspace_root: &Path,
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<Vec<FixtureEvidence>> {
    let fixtures = [
        (
            "ads.srs",
            MatchProbe::Domain(canonical("x.0.myikas.com")?),
            MatchProbe::Domain(canonical("not-an-ad-fixture-match.invalid")?),
        ),
        (
            "ai.srs",
            MatchProbe::Domain(canonical("api.openai.example")?),
            MatchProbe::Domain(canonical("not-an-ai-fixture-match.invalid")?),
        ),
        (
            "cn.srs",
            MatchProbe::Domain(canonical("x.0.zone")?),
            MatchProbe::Domain(canonical("not-a-cn-fixture-match.invalid")?),
        ),
        (
            "cnip.srs",
            MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))),
            MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ),
    ];
    let mut evidence = Vec::new();
    for (name, hit, miss) in fixtures {
        let path = workspace_root.join("tests/fixtures/srs").join(name);
        let bytes = fs::read(&path).map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} could not be read: {error}"))
        })?;
        let digest = sha256_bytes(&bytes);
        let binary_region = allocation_region();
        let binary_started = Instant::now();
        let decoded = decode_srs(Cursor::new(&bytes)).map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} decode failed: {error}"))
        })?;
        let version = decoded.version();
        let statistics = decoded.statistics();
        let capabilities = decoded.capabilities();
        let binary_set = Arc::new(decoded.compile().map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} compile failed: {error}"))
        })?);
        let binary_build = finish_build(binary_started, &binary_region)?;

        let synthetic_region = allocation_region();
        let synthetic_started = Instant::now();
        let mut snapshot = RuleEngineSnapshotBuilder::new(1);
        let synthetic_match_set = snapshot
            .add_shared_match_set(Arc::clone(&binary_set))
            .map_err(|error| {
                QualificationError::new(format!("synthetic SRS snapshot add failed: {error}"))
            })?;
        snapshot
            .add_rule_set(name, synthetic_match_set)
            .map_err(|error| {
                QualificationError::new(format!("synthetic SRS registration failed: {error}"))
            })?;
        let synthetic_owner = CompiledSetOwner::Snapshot {
            snapshot: snapshot.build().map_err(|error| {
                QualificationError::new(format!("synthetic SRS snapshot failed: {error}"))
            })?,
            match_set: synthetic_match_set,
        };
        let synthetic_build =
            binary_build.combined(finish_build(synthetic_started, &synthetic_region)?);

        let synthetic_set = synthetic_owner.compiled();
        let scale = binary_set.entry_counts().total();
        let capability_name = capability_name(capabilities);
        for (case, probe, expected) in [("hit", &hit, true), ("miss", &miss, false)] {
            if probe_matches(&binary_set, probe) != expected
                || probe_matches(synthetic_set, probe) != expected
            {
                return Err(QualificationError::new(format!(
                    "SRS fixture {name} {case} probe failed"
                )));
            }
            let scenario = format!("{capability_name}/{case}");
            let (synthetic_result, binary_result) = benchmark_pair(
                synthetic_set,
                &binary_set,
                probe,
                samples,
                base_iterations,
                format!("match_set/srs/{name}/{scenario}"),
            );
            measurements.push(measurement(
                format!("match_set/synthetic_srs/{name}/{scenario}"),
                "match_set",
                "synthetic_srs",
                scenario.clone(),
                scale,
                Some(name.to_owned()),
                None,
                base_iterations,
                synthetic_build,
                Some(scale),
                synthetic_result,
            ));
            measurements.push(measurement(
                format!("match_set/binary_srs/{name}/{scenario}"),
                "match_set",
                "binary_srs",
                scenario,
                scale,
                Some(name.to_owned()),
                None,
                base_iterations,
                binary_build,
                Some(scale),
                binary_result,
            ));
        }
        evidence.push(FixtureEvidence {
            name: name.to_owned(),
            provenance: "pinned_repository_fixture",
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: digest,
            srs_version: version,
            statistics: statistics.into(),
            capabilities: capabilities.into(),
        });
    }
    Ok(evidence)
}

pub(crate) fn canonical(value: &str) -> Result<CanonicalDomain> {
    CanonicalDomain::new(value)
        .map_err(|_| QualificationError::new("qualification domain is invalid"))
}

pub(crate) fn capability_name(capabilities: MatchSetCapabilities) -> &'static str {
    let count = [
        capabilities.exact_domain,
        capabilities.domain_suffix,
        capabilities.domain_keyword,
        capabilities.ip_cidr,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if count > 1 {
        "mixed"
    } else if capabilities.exact_domain {
        "exact"
    } else if capabilities.domain_suffix {
        "suffix"
    } else if capabilities.domain_keyword {
        "keyword"
    } else if capabilities.ip_cidr {
        "cidr"
    } else {
        "empty"
    }
}
