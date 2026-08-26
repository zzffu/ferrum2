use std::cmp::Ordering;
use std::io::Read;

use ipnet::IpNet;

use super::domain_set::{read_domain_set, read_succinct_set};
use super::ip_set::read_ip_set;
use super::primitives::{
    read_bool, read_byte, read_interface_address_map, read_prefix_slice, read_string_slice,
    read_u8_slice, read_u16_slice, read_uvarint,
};
use super::{DecodedSrsRuleSet, SrsStatistics};
use crate::srs::{SrsError, SrsErrorKind, UnsupportedSrsMatcher};

const MAX_LOGICAL_DEPTH: usize = 100;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
pub(super) const ITEM_DOMAIN_KEYWORD: u8 = 3;
pub(super) const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
pub(super) const ITEM_FINAL: u8 = 0xff;

pub(super) struct Parser {
    version: u8,
    exact_domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
    ip_cidrs: Vec<IpNet>,
    pub(super) first_unsupported: Option<(u64, UnsupportedSrsMatcher)>,
}

impl Parser {
    pub(super) const fn new(version: u8) -> Self {
        Self {
            version,
            exact_domains: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            ip_cidrs: Vec::new(),
            first_unsupported: None,
        }
    }

    pub(super) fn reserve_rules(&mut self, count: usize) -> Result<(), SrsError> {
        // A valid file may have no supported entries in many rules. Reserving a
        // small rule-correlated baseline keeps ordinary multi-rule files cheap
        // without treating rule count as an entry count or a configured limit.
        let baseline = count.min(1024);
        self.exact_domains
            .try_reserve(baseline)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        self.domain_suffixes
            .try_reserve(baseline)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        self.domain_keywords
            .try_reserve(baseline)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        self.ip_cidrs
            .try_reserve(baseline)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))
    }

    pub(super) fn read_rule<R: Read>(
        &mut self,
        reader: &mut R,
        rule_index: u64,
        depth: usize,
    ) -> Result<(), SrsError> {
        if depth > MAX_LOGICAL_DEPTH {
            return Err(SrsError::new(SrsErrorKind::LogicalDepth));
        }
        match read_byte(reader)? {
            0 => self.read_default_rule(reader, rule_index),
            1 => self.read_logical_rule(reader, rule_index, depth),
            _ => Err(SrsError::new(SrsErrorKind::InvalidRuleType)),
        }
    }

    fn read_logical_rule<R: Read>(
        &mut self,
        reader: &mut R,
        rule_index: u64,
        depth: usize,
    ) -> Result<(), SrsError> {
        self.mark_unsupported(rule_index, UnsupportedSrsMatcher::LogicalRule);
        match read_byte(reader)? {
            0 | 1 => {}
            _ => return Err(SrsError::new(SrsErrorKind::InvalidLogicalMode)),
        }
        let count = read_uvarint(reader)?;
        for _ in 0..count {
            self.read_rule(reader, rule_index, depth + 1)?;
        }
        let invert = read_bool(reader)?;
        if invert {
            self.mark_unsupported(rule_index, UnsupportedSrsMatcher::Invert);
        }
        Ok(())
    }

    fn read_default_rule<R: Read>(
        &mut self,
        reader: &mut R,
        rule_index: u64,
    ) -> Result<(), SrsError> {
        let mut seen = 0_u32;
        loop {
            let item = read_byte(reader)?;
            if item == ITEM_FINAL {
                let invert = read_bool(reader)?;
                if invert {
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::Invert);
                }
                return Ok(());
            }
            if item > ITEM_PACKAGE_NAME_REGEX {
                return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
            }
            let bit = 1_u32 << item;
            if seen & bit != 0 {
                return Err(SrsError::new(SrsErrorKind::DuplicateItem).at_item(item));
            }
            seen |= bit;

            match item {
                ITEM_QUERY_TYPE => {
                    read_u16_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::QueryType);
                }
                ITEM_NETWORK => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::Network);
                }
                ITEM_DOMAIN => {
                    let domains = read_domain_set(reader)?;
                    append(&mut self.exact_domains, domains.exact)?;
                    append(&mut self.domain_suffixes, domains.suffix)?;
                }
                ITEM_DOMAIN_KEYWORD => {
                    let keywords = read_string_slice(reader)?;
                    self.domain_keywords
                        .try_reserve(keywords.len())
                        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
                    for keyword in keywords {
                        self.domain_keywords.push(normalize_keyword(keyword)?);
                    }
                }
                ITEM_DOMAIN_REGEX => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::DomainRegex);
                }
                ITEM_SOURCE_IP_CIDR => {
                    read_ip_set(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::SourceIpCidr);
                }
                ITEM_IP_CIDR => append(&mut self.ip_cidrs, read_ip_set(reader)?)?,
                ITEM_SOURCE_PORT => {
                    read_u16_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::SourcePort);
                }
                ITEM_SOURCE_PORT_RANGE => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::SourcePortRange);
                }
                ITEM_PORT => {
                    read_u16_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::Port);
                }
                ITEM_PORT_RANGE => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::PortRange);
                }
                ITEM_PROCESS_NAME => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::ProcessName);
                }
                ITEM_PROCESS_PATH => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::ProcessPath);
                }
                ITEM_PACKAGE_NAME => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::PackageName);
                }
                ITEM_WIFI_SSID => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::WifiSsid);
                }
                ITEM_WIFI_BSSID => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::WifiBssid);
                }
                ITEM_ADGUARD_DOMAIN => {
                    read_succinct_set(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::AdGuardDomain);
                }
                ITEM_PROCESS_PATH_REGEX => {
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::ProcessPathRegex);
                }
                ITEM_NETWORK_TYPE => {
                    if self.version < 3 {
                        return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                    }
                    read_u8_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::NetworkType);
                }
                ITEM_NETWORK_IS_EXPENSIVE => {
                    if self.version < 3 {
                        return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                    }
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::NetworkIsExpensive);
                }
                ITEM_NETWORK_IS_CONSTRAINED => {
                    if self.version < 3 {
                        return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                    }
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::NetworkIsConstrained);
                }
                ITEM_NETWORK_INTERFACE_ADDRESS => {
                    if self.version < 4 {
                        return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                    }
                    read_interface_address_map(reader)?;
                    self.mark_unsupported(
                        rule_index,
                        UnsupportedSrsMatcher::NetworkInterfaceAddress,
                    );
                }
                ITEM_DEFAULT_INTERFACE_ADDRESS => {
                    if self.version < 4 {
                        return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                    }
                    read_prefix_slice(reader)?;
                    self.mark_unsupported(
                        rule_index,
                        UnsupportedSrsMatcher::DefaultInterfaceAddress,
                    );
                }
                ITEM_PACKAGE_NAME_REGEX => {
                    // Added in SRS v5, which is deliberately outside the
                    // repository-pinned sing-box 1.13 format range.
                    read_string_slice(reader)?;
                    self.mark_unsupported(rule_index, UnsupportedSrsMatcher::PackageNameRegex);
                    return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item));
                }
                _ => return Err(SrsError::new(SrsErrorKind::InvalidItem).at_item(item)),
            }
        }
    }

    fn mark_unsupported(&mut self, rule_index: u64, matcher: UnsupportedSrsMatcher) {
        if self.first_unsupported.is_none() {
            self.first_unsupported = Some((rule_index, matcher));
        }
    }

    pub(super) fn finish(mut self, rules: u64) -> Result<DecodedSrsRuleSet, SrsError> {
        self.exact_domains.sort_unstable();
        self.exact_domains.dedup();
        self.domain_suffixes.sort_unstable();
        self.domain_suffixes.dedup();
        self.domain_keywords.sort_unstable();
        self.domain_keywords.dedup();
        self.ip_cidrs.sort_unstable_by(ip_net_cmp);
        self.ip_cidrs.dedup();
        let statistics = SrsStatistics {
            rules,
            exact_domains: self.exact_domains.len(),
            domain_suffixes: self.domain_suffixes.len(),
            domain_keywords: self.domain_keywords.len(),
            ip_cidrs: self.ip_cidrs.len(),
        };
        if statistics.exact_domains == 0
            && statistics.domain_suffixes == 0
            && statistics.domain_keywords == 0
            && statistics.ip_cidrs == 0
        {
            return Err(SrsError::new(SrsErrorKind::Empty).with_version(self.version));
        }
        Ok(DecodedSrsRuleSet {
            version: self.version,
            exact_domains: self.exact_domains,
            domain_suffixes: self.domain_suffixes,
            domain_keywords: self.domain_keywords,
            ip_cidrs: self.ip_cidrs,
            statistics,
        })
    }
}

fn append<T>(target: &mut Vec<T>, values: Vec<T>) -> Result<(), SrsError> {
    target
        .try_reserve(values.len())
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    target.extend(values);
    Ok(())
}

fn normalize_keyword(mut value: String) -> Result<String, SrsError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    value.make_ascii_lowercase();
    Ok(value)
}

fn ip_net_cmp(left: &IpNet, right: &IpNet) -> Ordering {
    let key = |network: &IpNet| match network {
        IpNet::V4(network) => (
            0_u8,
            u128::from(u32::from(network.network())),
            network.prefix_len(),
        ),
        IpNet::V6(network) => (1_u8, u128::from(network.network()), network.prefix_len()),
    };
    key(left).cmp(&key(right))
}
