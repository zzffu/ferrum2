use std::cmp::Ordering;
use std::net::IpAddr;
use std::num::NonZeroU16;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use ferrum2_core::CanonicalDomain;
use ipnet::IpNet;

use crate::hybrid_index::{RadixTrie, SuffixTrie, use_cidr_radix, use_suffix_trie};
use crate::{CompiledMatchSet, RuleCompileError};

#[derive(Clone, Copy)]
pub struct MatchCategories(u8);

impl MatchCategories {
    pub const EXACT: Self = Self(1 << 0);
    pub const SUFFIX: Self = Self(1 << 1);
    pub const KEYWORD: Self = Self(1 << 2);
    pub const IP: Self = Self(1 << 3);
    pub const DOMAIN: Self = Self(Self::EXACT.0 | Self::SUFFIX.0 | Self::KEYWORD.0);
    pub const ALL: Self = Self(Self::EXACT.0 | Self::SUFFIX.0 | Self::KEYWORD.0 | Self::IP.0);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

struct SparsePosting<K> {
    key: K,
    candidates: Box<[u32]>,
}

/// A compact value-to-candidate posting index. Candidate lists are sparse so
/// large sets with mostly unique values do not allocate one full bitmap per value.
pub struct SparseValueIndex<K> {
    postings: Box<[SparsePosting<K>]>,
}

impl<K: Ord> SparseValueIndex<K> {
    pub fn visit(&self, key: &K, visit: impl FnMut(u32)) {
        self.visit_by(|candidate| candidate.cmp(key), visit);
    }

    pub fn visit_by(&self, mut compare: impl FnMut(&K) -> Ordering, mut visit: impl FnMut(u32)) {
        if let Ok(index) = self
            .postings
            .binary_search_by(|posting| compare(&posting.key))
        {
            for candidate in self.postings[index].candidates.iter().copied() {
                visit(candidate);
            }
        }
    }

    /// Visits the immutable posting list for one exact key without copying it.
    pub fn visit_candidate_list(&self, key: &K, visit: impl FnMut(&[u32])) {
        self.visit_candidate_list_by(|candidate| candidate.cmp(key), visit);
    }

    /// Visits the immutable posting list selected by a custom comparison.
    pub fn visit_candidate_list_by(
        &self,
        mut compare: impl FnMut(&K) -> Ordering,
        mut visit: impl FnMut(&[u32]),
    ) {
        if let Ok(index) = self
            .postings
            .binary_search_by(|posting| compare(&posting.key))
        {
            visit(&self.postings[index].candidates);
        }
    }
}

pub struct SparseValueIndexBuilder<K> {
    entries: Vec<(K, u32)>,
}

impl<K> SparseValueIndexBuilder<K> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn try_add(&mut self, key: K, candidate: usize) -> Result<(), RuleCompileError> {
        let candidate = u32::try_from(candidate).map_err(|_| RuleCompileError::IndexOverflow)?;
        self.entries
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.entries.push((key, candidate));
        Ok(())
    }
}

impl<K> Default for SparseValueIndexBuilder<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone + Ord> SparseValueIndexBuilder<K> {
    pub fn build(mut self) -> Result<SparseValueIndex<K>, RuleCompileError> {
        self.entries
            .sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let mut postings = Vec::new();
        postings
            .try_reserve(self.entries.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        let mut cursor = 0;
        while cursor < self.entries.len() {
            let end = self.entries[cursor + 1..]
                .iter()
                .position(|entry| entry.0 != self.entries[cursor].0)
                .map_or(self.entries.len(), |offset| cursor + 1 + offset);
            let mut candidates = Vec::new();
            candidates
                .try_reserve(end - cursor)
                .map_err(|_| RuleCompileError::Allocation)?;
            for (_, candidate) in &self.entries[cursor..end] {
                if candidates.last() != Some(candidate) {
                    candidates.push(*candidate);
                }
            }
            postings.push(SparsePosting {
                key: self.entries[cursor].0.clone(),
                candidates: candidates.into_boxed_slice(),
            });
            cursor = end;
        }
        Ok(SparseValueIndex {
            postings: postings.into_boxed_slice(),
        })
    }
}

struct KeywordCandidateIndex {
    matcher: Option<AhoCorasick>,
    postings: Box<[SparsePosting<Box<str>>]>,
}

impl KeywordCandidateIndex {
    fn build(builder: SparseValueIndexBuilder<Box<str>>) -> Result<Self, RuleCompileError> {
        let postings = builder.build()?.postings;
        let matcher = if postings.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .build(postings.iter().map(|posting| posting.key.as_bytes()))
                    .map_err(|_| RuleCompileError::Internal)?,
            )
        };
        Ok(Self { matcher, postings })
    }

    fn visit(&self, domain: &str, mut visit: impl FnMut(u32)) {
        let Some(matcher) = &self.matcher else {
            return;
        };
        for matched in matcher.find_overlapping_iter(domain.as_bytes()) {
            for candidate in self.postings[matched.pattern().as_usize()]
                .candidates
                .iter()
                .copied()
            {
                visit(candidate);
            }
        }
    }

    fn visit_candidate_lists(&self, domain: &str, mut visit: impl FnMut(&[u32])) {
        let Some(matcher) = &self.matcher else {
            return;
        };
        for matched in matcher.find_overlapping_iter(domain.as_bytes()) {
            visit(&self.postings[matched.pattern().as_usize()].candidates);
        }
    }
}

enum SuffixCandidateIndex {
    Sorted(SparseValueIndex<CanonicalDomain>),
    Trie(SuffixTrie<Box<[u32]>>),
}

impl SuffixCandidateIndex {
    fn build(builder: SparseValueIndexBuilder<CanonicalDomain>) -> Result<Self, RuleCompileError> {
        let index = builder.build()?;
        if !use_suffix_trie(index.postings.len()) {
            return Ok(Self::Sorted(index));
        }
        let entries = index
            .postings
            .into_vec()
            .into_iter()
            .map(|posting| (Box::<str>::from(posting.key.as_str()), posting.candidates));
        Ok(Self::Trie(SuffixTrie::try_build(entries)?))
    }

    fn visit(&self, domain: &CanonicalDomain, mut visit: impl FnMut(u32)) {
        self.visit_candidate_lists(domain, |candidates| {
            for candidate in candidates.iter().copied() {
                visit(candidate);
            }
        });
    }

    fn visit_candidate_lists(&self, domain: &CanonicalDomain, mut visit: impl FnMut(&[u32])) {
        match self {
            Self::Sorted(index) => {
                let mut suffix = domain.as_str();
                loop {
                    index.visit_candidate_list_by(
                        |candidate| candidate.as_str().cmp(suffix),
                        &mut visit,
                    );
                    let Some(boundary) = suffix.find('.') else {
                        break;
                    };
                    suffix = &suffix[boundary + 1..];
                }
            }
            Self::Trie(trie) => trie.visit(domain.as_str(), |candidates| visit(candidates)),
        }
    }
}

enum IpCandidateV4 {
    Sorted(SparseValueIndex<(u8, u32)>),
    Radix(RadixTrie<Box<[u32]>, 32>),
}

enum IpCandidateV6 {
    Sorted(SparseValueIndex<(u8, u128)>),
    Radix(RadixTrie<Box<[u32]>, 128>),
}

struct IpCandidateIndex {
    v4: IpCandidateV4,
    v6: IpCandidateV6,
}

impl IpCandidateIndex {
    fn build(
        v4: SparseValueIndexBuilder<(u8, u32)>,
        v6: SparseValueIndexBuilder<(u8, u128)>,
    ) -> Result<Self, RuleCompileError> {
        let v4 = v4.build()?;
        let v4 = if use_cidr_radix(v4.postings.len()) {
            IpCandidateV4::Radix(RadixTrie::try_build(
                v4.postings
                    .into_vec()
                    .into_iter()
                    .map(|posting| (posting.key.0, u128::from(posting.key.1), posting.candidates)),
            )?)
        } else {
            IpCandidateV4::Sorted(v4)
        };
        let v6 = v6.build()?;
        let v6 = if use_cidr_radix(v6.postings.len()) {
            IpCandidateV6::Radix(RadixTrie::try_build(
                v6.postings
                    .into_vec()
                    .into_iter()
                    .map(|posting| (posting.key.0, posting.key.1, posting.candidates)),
            )?)
        } else {
            IpCandidateV6::Sorted(v6)
        };
        Ok(Self { v4, v6 })
    }

    fn visit(&self, address: IpAddr, mut visit: impl FnMut(u32)) {
        self.visit_candidate_lists(address, |candidates| {
            for candidate in candidates.iter().copied() {
                visit(candidate);
            }
        });
    }

    fn visit_candidate_lists(&self, address: IpAddr, mut visit: impl FnMut(&[u32])) {
        match (address, &self.v4, &self.v6) {
            (IpAddr::V4(address), IpCandidateV4::Sorted(index), _) => {
                let address = u32::from(address);
                for length in 0..=32 {
                    index.visit_candidate_list(&(length, address & mask_v4(length)), &mut visit);
                }
            }
            (IpAddr::V4(address), IpCandidateV4::Radix(trie), _) => {
                trie.visit(u128::from(u32::from(address)), |candidates| {
                    visit(candidates)
                });
            }
            (IpAddr::V6(address), _, IpCandidateV6::Sorted(index)) => {
                let address = u128::from(address);
                for length in 0..=128 {
                    index.visit_candidate_list(&(length, address & mask_v6(length)), &mut visit);
                }
            }
            (IpAddr::V6(address), _, IpCandidateV6::Radix(trie)) => {
                trie.visit(u128::from(address), |candidates| visit(candidates));
            }
        }
    }
}

/// Input-side index shared by inline composite match sets and snapshot RuleSets.
pub struct MatchCandidateIndex {
    exact: SparseValueIndex<CanonicalDomain>,
    suffix: SuffixCandidateIndex,
    keyword: KeywordCandidateIndex,
    ip: IpCandidateIndex,
}

impl MatchCandidateIndex {
    pub fn visit_matches(
        &self,
        domain: Option<&CanonicalDomain>,
        address: Option<IpAddr>,
        mut visit: impl FnMut(u32),
    ) {
        if let Some(domain) = domain {
            self.exact.visit(domain, &mut visit);
            self.suffix.visit(domain, &mut visit);
            self.keyword.visit(domain.as_str(), &mut visit);
        }
        if let Some(address) = address {
            self.ip.visit(address, visit);
        }
    }

    /// Visits each immutable posting list whose value matches the supplied input.
    pub fn visit_match_candidate_lists(
        &self,
        domain: Option<&CanonicalDomain>,
        address: Option<IpAddr>,
        mut visit: impl FnMut(&[u32]),
    ) {
        if let Some(domain) = domain {
            self.exact.visit_candidate_list(domain, &mut visit);
            self.suffix.visit_candidate_lists(domain, &mut visit);
            self.keyword
                .visit_candidate_lists(domain.as_str(), &mut visit);
        }
        if let Some(address) = address {
            self.ip.visit_candidate_lists(address, visit);
        }
    }
}

pub struct MatchCandidateIndexBuilder {
    exact: SparseValueIndexBuilder<CanonicalDomain>,
    suffix: SparseValueIndexBuilder<CanonicalDomain>,
    keyword: SparseValueIndexBuilder<Box<str>>,
    v4: SparseValueIndexBuilder<(u8, u32)>,
    v6: SparseValueIndexBuilder<(u8, u128)>,
}

impl MatchCandidateIndexBuilder {
    pub const fn new() -> Self {
        Self {
            exact: SparseValueIndexBuilder::new(),
            suffix: SparseValueIndexBuilder::new(),
            keyword: SparseValueIndexBuilder::new(),
            v4: SparseValueIndexBuilder::new(),
            v6: SparseValueIndexBuilder::new(),
        }
    }

    pub fn try_add_match_set(
        &mut self,
        candidate: usize,
        set: &CompiledMatchSet,
        categories: MatchCategories,
    ) -> Result<(), RuleCompileError> {
        if categories.contains(MatchCategories::EXACT) {
            for domain in set.exact_domains() {
                self.exact.try_add(domain.clone(), candidate)?;
            }
        }
        if categories.contains(MatchCategories::SUFFIX) {
            for domain in set.suffix_domains() {
                self.suffix.try_add(domain.clone(), candidate)?;
            }
        }
        if categories.contains(MatchCategories::KEYWORD) {
            for keyword in set.domain_keywords() {
                self.keyword.try_add(keyword.clone(), candidate)?;
            }
        }
        if categories.contains(MatchCategories::IP) {
            for network in set.ip_cidrs() {
                match network {
                    IpNet::V4(network) => self.v4.try_add(
                        (network.prefix_len(), u32::from(network.network())),
                        candidate,
                    )?,
                    IpNet::V6(network) => self.v6.try_add(
                        (network.prefix_len(), u128::from(network.network())),
                        candidate,
                    )?,
                }
            }
        }
        Ok(())
    }

    pub fn build(self) -> Result<MatchCandidateIndex, RuleCompileError> {
        Ok(MatchCandidateIndex {
            exact: self.exact.build()?,
            suffix: SuffixCandidateIndex::build(self.suffix)?,
            keyword: KeywordCandidateIndex::build(self.keyword)?,
            ip: IpCandidateIndex::build(self.v4, self.v6)?,
        })
    }
}

impl Default for MatchCandidateIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Sparse segment-tree posting index for inclusive non-zero port ranges.
pub struct PortRangeCandidateIndex {
    nodes: SparseValueIndex<u32>,
}

/// Fallible builder for [`PortRangeCandidateIndex`].
pub struct PortRangeCandidateIndexBuilder {
    nodes: SparseValueIndexBuilder<u32>,
}

impl PortRangeCandidateIndexBuilder {
    pub const fn new() -> Self {
        Self {
            nodes: SparseValueIndexBuilder::new(),
        }
    }

    pub fn try_add(
        &mut self,
        first: NonZeroU16,
        last: NonZeroU16,
        candidate: usize,
    ) -> Result<(), RuleCompileError> {
        if first > last {
            return Err(RuleCompileError::EmptyField);
        }
        self.try_add_inner(1, 1, u16::MAX, first.get(), last.get(), candidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_add_inner(
        &mut self,
        node: u32,
        first: u16,
        last: u16,
        query_first: u16,
        query_last: u16,
        candidate: usize,
    ) -> Result<(), RuleCompileError> {
        if query_first <= first && last <= query_last {
            return self.nodes.try_add(node, candidate);
        }
        let middle = first + (last - first) / 2;
        if query_first <= middle {
            self.try_add_inner(
                node.checked_mul(2).ok_or(RuleCompileError::IndexOverflow)?,
                first,
                middle,
                query_first,
                query_last,
                candidate,
            )?;
        }
        if query_last > middle {
            self.try_add_inner(
                node.checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(RuleCompileError::IndexOverflow)?,
                middle + 1,
                last,
                query_first,
                query_last,
                candidate,
            )?;
        }
        Ok(())
    }

    pub fn build(self) -> Result<PortRangeCandidateIndex, RuleCompileError> {
        Ok(PortRangeCandidateIndex {
            nodes: self.nodes.build()?,
        })
    }
}

impl Default for PortRangeCandidateIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PortRangeCandidateIndex {
    pub fn visit(&self, port: NonZeroU16, mut visit: impl FnMut(u32)) {
        self.visit_candidate_lists(port, |candidates| {
            for candidate in candidates.iter().copied() {
                visit(candidate);
            }
        });
    }

    pub fn visit_candidate_lists(&self, port: NonZeroU16, mut visit: impl FnMut(&[u32])) {
        let port = port.get();
        let mut node = 1_u32;
        let mut first = 1_u16;
        let mut last = u16::MAX;
        loop {
            self.nodes.visit_candidate_list(&node, &mut visit);
            if first == last {
                break;
            }
            let middle = first + (last - first) / 2;
            if port <= middle {
                node *= 2;
                last = middle;
            } else {
                node = node * 2 + 1;
                first = middle + 1;
            }
        }
    }
}

const fn mask_v4(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    }
}

const fn mask_v6(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - length)
    }
}
