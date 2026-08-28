use std::net::IpAddr;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use ferrum2_core::{CanonicalDomain, DomainName};
use ipnet::IpNet;

use crate::RuleCompileError;
use crate::hybrid_index::{RadixTrie, SuffixTrie, use_cidr_radix, use_suffix_trie};

/// Matcher categories present in one compiled set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MatchSetCapabilities {
    pub exact_domain: bool,
    pub domain_suffix: bool,
    pub domain_keyword: bool,
    pub ip_cidr: bool,
}

/// Stable per-category entry counts for diagnostics and bounded telemetry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MatchSetEntryCounts {
    pub exact_domain: usize,
    pub domain_suffix: usize,
    pub domain_keyword: usize,
    pub ip_cidr: usize,
}

/// First matching domain category in the compiled evaluation order.
///
/// This closed value lets telemetry report matcher categories without exposing
/// the matched domain or any configured rule value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainMatchType {
    Exact,
    Suffix,
    Keyword,
}

impl MatchSetEntryCounts {
    /// Returns the total number of unique compiled matcher values.
    pub const fn total(self) -> usize {
        self.exact_domain + self.domain_suffix + self.domain_keyword + self.ip_cidr
    }
}

/// Builder shared by inline fields, synthetic RuleSets, and decoded RuleSets.
#[derive(Default)]
pub struct MatchSetBuilder {
    exact_domains: Vec<CanonicalDomain>,
    suffix_domains: Vec<CanonicalDomain>,
    domain_keywords: Vec<Box<str>>,
    ip_cidrs: Vec<IpNet>,
}

impl MatchSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_exact_domain(&mut self, value: &str) -> Result<&mut Self, RuleCompileError> {
        let value = CanonicalDomain::new(value).map_err(|_| RuleCompileError::InvalidDomain)?;
        self.exact_domains
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.exact_domains.push(value);
        Ok(self)
    }

    pub fn add_domain(&mut self, value: &DomainName) -> Result<&mut Self, RuleCompileError> {
        let value = value
            .canonical()
            .cloned()
            .ok_or(RuleCompileError::InvalidDomain)?;
        self.exact_domains
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.exact_domains.push(value);
        Ok(self)
    }

    pub fn add_domain_suffix(&mut self, value: &str) -> Result<&mut Self, RuleCompileError> {
        let value = CanonicalDomain::new(value).map_err(|_| RuleCompileError::InvalidDomain)?;
        self.suffix_domains
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.suffix_domains.push(value);
        Ok(self)
    }

    pub fn add_domain_suffix_name(
        &mut self,
        value: &DomainName,
    ) -> Result<&mut Self, RuleCompileError> {
        let value = value
            .canonical()
            .cloned()
            .ok_or(RuleCompileError::InvalidDomain)?;
        self.suffix_domains
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.suffix_domains.push(value);
        Ok(self)
    }

    pub fn add_domain_keyword(&mut self, value: &str) -> Result<&mut Self, RuleCompileError> {
        if value.is_empty() || !value.is_ascii() {
            return Err(RuleCompileError::InvalidDomain);
        }
        self.domain_keywords
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.domain_keywords
            .push(value.to_ascii_lowercase().into_boxed_str());
        Ok(self)
    }

    pub fn add_ip(&mut self, value: IpAddr) -> Result<&mut Self, RuleCompileError> {
        let prefix = if value.is_ipv4() { 32 } else { 128 };
        let network = IpNet::new(value, prefix).map_err(|_| RuleCompileError::Internal)?;
        self.add_ip_cidr(network)
    }

    pub fn add_ip_cidr(&mut self, value: IpNet) -> Result<&mut Self, RuleCompileError> {
        if value.addr() != value.network() {
            return Err(RuleCompileError::NonCanonicalCidr);
        }
        self.ip_cidrs
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.ip_cidrs.push(value);
        Ok(self)
    }

    pub fn build(mut self) -> Result<CompiledMatchSet, RuleCompileError> {
        sort_unique(&mut self.exact_domains)?;
        sort_unique(&mut self.suffix_domains)?;
        sort_unique(&mut self.domain_keywords)?;
        self.ip_cidrs.sort_by_key(|network| match network {
            IpNet::V4(network) => (
                0,
                network.prefix_len(),
                u128::from(u32::from(network.network())),
            ),
            IpNet::V6(network) => (1, network.prefix_len(), u128::from(network.network())),
        });
        if self.ip_cidrs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RuleCompileError::DuplicateValue);
        }

        let keyword_matcher = if self.domain_keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .build(self.domain_keywords.iter().map(|value| value.as_bytes()))
                    .map_err(|_| RuleCompileError::Internal)?,
            )
        };
        let ip_prefixes = IpPrefixIndex::build(&self.ip_cidrs)?;
        let suffix_trie = if use_suffix_trie(self.suffix_domains.len()) {
            Some(SuffixTrie::try_build(
                self.suffix_domains
                    .iter()
                    .map(|domain| (domain.as_str(), ())),
            )?)
        } else {
            None
        };
        let capabilities = MatchSetCapabilities {
            exact_domain: !self.exact_domains.is_empty(),
            domain_suffix: !self.suffix_domains.is_empty(),
            domain_keyword: !self.domain_keywords.is_empty(),
            ip_cidr: !self.ip_cidrs.is_empty(),
        };
        let entry_counts = MatchSetEntryCounts {
            exact_domain: self.exact_domains.len(),
            domain_suffix: self.suffix_domains.len(),
            domain_keyword: self.domain_keywords.len(),
            ip_cidr: self.ip_cidrs.len(),
        };
        Ok(CompiledMatchSet {
            exact_domains: self.exact_domains.into_boxed_slice(),
            suffix_domains: self.suffix_domains.into_boxed_slice(),
            suffix_trie,
            domain_keywords: self.domain_keywords.into_boxed_slice(),
            keyword_matcher,
            ip_cidrs: self.ip_cidrs.into_boxed_slice(),
            ip_prefixes,
            capabilities,
            entry_counts,
        })
    }
}

fn sort_unique<T: Ord>(values: &mut [T]) -> Result<(), RuleCompileError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(RuleCompileError::DuplicateValue)
    } else {
        Ok(())
    }
}

/// One immutable composite set. Categories within the set are ORed.
pub struct CompiledMatchSet {
    exact_domains: Box<[CanonicalDomain]>,
    suffix_domains: Box<[CanonicalDomain]>,
    suffix_trie: Option<SuffixTrie<()>>,
    domain_keywords: Box<[Box<str>]>,
    keyword_matcher: Option<AhoCorasick>,
    ip_cidrs: Box<[IpNet]>,
    ip_prefixes: IpPrefixIndex,
    capabilities: MatchSetCapabilities,
    entry_counts: MatchSetEntryCounts,
}

impl CompiledMatchSet {
    pub const fn capabilities(&self) -> MatchSetCapabilities {
        self.capabilities
    }

    pub const fn entry_counts(&self) -> MatchSetEntryCounts {
        self.entry_counts
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities == MatchSetCapabilities::default()
    }

    pub fn matches_domain(&self, domain: &CanonicalDomain) -> bool {
        self.domain_match_type(domain).is_some()
    }

    /// Returns the first matching domain category without exposing its value.
    ///
    /// The order is identical to [`Self::matches_domain`], so callers can add
    /// closed observations without evaluating the matcher a second time.
    pub fn domain_match_type(&self, domain: &CanonicalDomain) -> Option<DomainMatchType> {
        let domain = domain.as_str();
        if self
            .exact_domains
            .binary_search_by(|candidate| candidate.as_str().cmp(domain))
            .is_ok()
        {
            return Some(DomainMatchType::Exact);
        }
        if self.matches_suffix(domain) {
            return Some(DomainMatchType::Suffix);
        }
        self.keyword_matcher
            .as_ref()
            .and_then(|matcher| matcher.is_match(domain).then_some(DomainMatchType::Keyword))
    }

    pub fn matches_ip(&self, address: IpAddr) -> bool {
        self.ip_prefixes.matches(address)
    }

    pub(crate) fn exact_domains(&self) -> &[CanonicalDomain] {
        &self.exact_domains
    }

    pub(crate) fn suffix_domains(&self) -> &[CanonicalDomain] {
        &self.suffix_domains
    }

    pub(crate) fn domain_keywords(&self) -> &[Box<str>] {
        &self.domain_keywords
    }

    pub(crate) fn ip_cidrs(&self) -> &[IpNet] {
        &self.ip_cidrs
    }

    pub(crate) fn matches(
        &self,
        domain: Option<&CanonicalDomain>,
        address: Option<IpAddr>,
    ) -> bool {
        domain.is_some_and(|domain| self.matches_domain(domain))
            || address.is_some_and(|address| self.matches_ip(address))
    }

    fn matches_suffix(&self, domain: &str) -> bool {
        if let Some(trie) = &self.suffix_trie {
            return trie.matches(domain);
        }
        let mut suffix = domain;
        loop {
            if self
                .suffix_domains
                .binary_search_by(|candidate| candidate.as_str().cmp(suffix))
                .is_ok()
            {
                return true;
            }
            let Some(boundary) = suffix.find('.') else {
                return false;
            };
            suffix = &suffix[boundary + 1..];
        }
    }
}

impl std::fmt::Debug for CompiledMatchSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CompiledMatchSet([redacted])")
    }
}

struct IpPrefixIndex {
    v4: IpPrefixV4,
    v6: IpPrefixV6,
}

enum IpPrefixV4 {
    Sorted(Box<[PrefixGroupV4]>),
    Radix(RadixTrie<(), 32>),
}

enum IpPrefixV6 {
    Sorted(Box<[PrefixGroupV6]>),
    Radix(RadixTrie<(), 128>),
}

struct PrefixGroupV4 {
    length: u8,
    networks: Box<[u32]>,
}

struct PrefixGroupV6 {
    length: u8,
    networks: Box<[u128]>,
}

impl IpPrefixIndex {
    fn build(networks: &[IpNet]) -> Result<Self, RuleCompileError> {
        let mut v4 = Vec::<(u8, u32)>::new();
        let mut v6 = Vec::<(u8, u128)>::new();
        v4.try_reserve(networks.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        v6.try_reserve(networks.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for network in networks {
            match network {
                IpNet::V4(network) => v4.push((network.prefix_len(), u32::from(network.network()))),
                IpNet::V6(network) => {
                    v6.push((network.prefix_len(), u128::from(network.network())))
                }
            }
        }
        let v4 = if use_cidr_radix(v4.len()) {
            IpPrefixV4::Radix(RadixTrie::try_build(
                v4.into_iter()
                    .map(|(prefix, network)| (prefix, u128::from(network), ())),
            )?)
        } else {
            IpPrefixV4::Sorted(group_v4(v4)?.into_boxed_slice())
        };
        let v6 = if use_cidr_radix(v6.len()) {
            IpPrefixV6::Radix(RadixTrie::try_build(
                v6.into_iter()
                    .map(|(prefix, network)| (prefix, network, ())),
            )?)
        } else {
            IpPrefixV6::Sorted(group_v6(v6)?.into_boxed_slice())
        };
        Ok(Self { v4, v6 })
    }

    fn matches(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                match &self.v4 {
                    IpPrefixV4::Sorted(groups) => groups.iter().any(|group| {
                        group
                            .networks
                            .binary_search(&(address & mask_v4(group.length)))
                            .is_ok()
                    }),
                    IpPrefixV4::Radix(trie) => trie.matches(u128::from(address)),
                }
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                match &self.v6 {
                    IpPrefixV6::Sorted(groups) => groups.iter().any(|group| {
                        group
                            .networks
                            .binary_search(&(address & mask_v6(group.length)))
                            .is_ok()
                    }),
                    IpPrefixV6::Radix(trie) => trie.matches(address),
                }
            }
        }
    }
}

fn group_v4(mut entries: Vec<(u8, u32)>) -> Result<Vec<PrefixGroupV4>, RuleCompileError> {
    entries.sort_unstable();
    let mut groups = Vec::new();
    let mut cursor = 0;
    while cursor < entries.len() {
        let length = entries[cursor].0;
        let end = entries[cursor..]
            .iter()
            .position(|entry| entry.0 != length)
            .map_or(entries.len(), |offset| cursor + offset);
        let mut values = Vec::new();
        values
            .try_reserve(end - cursor)
            .map_err(|_| RuleCompileError::Allocation)?;
        values.extend(entries[cursor..end].iter().map(|entry| entry.1));
        groups
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        groups.push(PrefixGroupV4 {
            length,
            networks: values.into_boxed_slice(),
        });
        cursor = end;
    }
    Ok(groups)
}

fn group_v6(mut entries: Vec<(u8, u128)>) -> Result<Vec<PrefixGroupV6>, RuleCompileError> {
    entries.sort_unstable();
    let mut groups = Vec::new();
    let mut cursor = 0;
    while cursor < entries.len() {
        let length = entries[cursor].0;
        let end = entries[cursor..]
            .iter()
            .position(|entry| entry.0 != length)
            .map_or(entries.len(), |offset| cursor + offset);
        let mut values = Vec::new();
        values
            .try_reserve(end - cursor)
            .map_err(|_| RuleCompileError::Allocation)?;
        values.extend(entries[cursor..end].iter().map(|entry| entry.1));
        groups
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        groups.push(PrefixGroupV6 {
            length,
            networks: values.into_boxed_slice(),
        });
        cursor = end;
    }
    Ok(groups)
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
