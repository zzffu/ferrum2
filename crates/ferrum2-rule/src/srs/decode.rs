use std::cmp::Ordering;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use flate2::{Decompress, FlushDecompress, Status};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::error::{SrsError, SrsErrorKind, UnsupportedSrsMatcher};
use crate::{CompiledMatchSet, MatchSetBuilder, MatchSetCapabilities};

const MAGIC: [u8; 3] = *b"SRS";
const MIN_VERSION: u8 = 1;
const MAX_VERSION: u8 = 4;
const MAX_LOGICAL_DEPTH: usize = 100;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
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
const ITEM_FINAL: u8 = 0xff;

const DOMAIN_PREFIX_LABEL: char = '\r';
const DOMAIN_ROOT_LABEL: char = '\n';

/// Counts recovered from a strict binary SRS before matcher compilation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SrsStatistics {
    pub rules: u64,
    pub exact_domains: usize,
    pub domain_suffixes: usize,
    pub domain_keywords: usize,
    pub ip_cidrs: usize,
}

/// Fully decoded supported subset of one sing-box binary RuleSet.
pub struct DecodedSrsRuleSet {
    version: u8,
    exact_domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
    ip_cidrs: Vec<IpNet>,
    statistics: SrsStatistics,
}

impl DecodedSrsRuleSet {
    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn statistics(&self) -> SrsStatistics {
        self.statistics
    }

    pub const fn capabilities(&self) -> MatchSetCapabilities {
        MatchSetCapabilities {
            exact_domain: self.statistics.exact_domains != 0,
            domain_suffix: self.statistics.domain_suffixes != 0,
            domain_keyword: self.statistics.domain_keywords != 0,
            ip_cidr: self.statistics.ip_cidrs != 0,
        }
    }

    /// Compiles through the same builder used by ordinary inline fields.
    pub fn compile(self) -> Result<CompiledMatchSet, SrsError> {
        let mut builder = MatchSetBuilder::new();
        for value in self.exact_domains {
            builder.add_exact_domain(&value)?;
        }
        for value in self.domain_suffixes {
            builder.add_domain_suffix(&value)?;
        }
        for value in self.domain_keywords {
            builder.add_domain_keyword(&value)?;
        }
        for value in self.ip_cidrs {
            builder.add_ip_cidr(value)?;
        }
        let compiled = builder.build()?;
        if compiled.is_empty() {
            Err(SrsError::new(SrsErrorKind::Empty).with_version(self.version))
        } else {
            Ok(compiled)
        }
    }
}

impl std::fmt::Debug for DecodedSrsRuleSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedSrsRuleSet")
            .field("version", &self.version)
            .field("statistics", &self.statistics)
            .finish_non_exhaustive()
    }
}

/// Strictly reads SRS versions emitted by the repository-pinned sing-box 1.13.x.
pub fn decode_srs<R: Read>(reader: R) -> Result<DecodedSrsRuleSet, SrsError> {
    let mut source = BufReader::new(reader);
    let mut magic = [0_u8; 3];
    read_exact(&mut source, &mut magic)?;
    if magic != MAGIC {
        return Err(SrsError::new(SrsErrorKind::InvalidMagic));
    }
    let version = read_byte(&mut source)?;
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(SrsError::new(SrsErrorKind::UnsupportedVersion).with_version(version));
    }

    let decoder = StrictZlibDecoder::new(source);
    let mut payload = BufReader::new(decoder);
    let rule_count = read_uvarint(&mut payload).map_err(|error| error.with_version(version))?;
    let rule_capacity = usize::try_from(rule_count)
        .map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow).with_version(version))?;

    let mut parser = Parser::new(version);
    parser.reserve_rules(rule_capacity)?;
    for rule_index in 0..rule_count {
        parser
            .read_rule(&mut payload, rule_index, 0)
            .map_err(|error| error.with_version(version).at_rule(rule_index))?;
    }

    let mut extra = [0_u8; 1];
    match payload.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => {
            return Err(SrsError::new(SrsErrorKind::TrailingPayload).with_version(version));
        }
        Err(error) => return Err(map_payload_io(error).with_version(version)),
    }
    let decoder = payload.into_inner();
    let mut source = decoder.into_inner();
    if !source.fill_buf().map_err(map_source_io)?.is_empty() {
        return Err(SrsError::new(SrsErrorKind::TrailingFileData).with_version(version));
    }

    if let Some((rule_index, matcher)) = parser.first_unsupported {
        return Err(SrsError::unsupported(matcher, version, rule_index));
    }
    parser.finish(rule_count)
}

/// `flate2`'s `Read` adapters intentionally treat a `BufError` at source EOF
/// as ordinary EOF.  That is convenient for best-effort decompression, but it
/// would accept a zlib stream with a truncated trailer.  SRS is configuration
/// input, so require the decoder to report an actual `StreamEnd`.
struct StrictZlibDecoder<R> {
    source: R,
    decoder: Decompress,
    ended: bool,
}

impl<R: BufRead> StrictZlibDecoder<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            decoder: Decompress::new(true),
            ended: false,
        }
    }

    fn into_inner(self) -> R {
        self.source
    }
}

impl<R: BufRead> Read for StrictZlibDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.ended || output.is_empty() {
            return Ok(0);
        }

        loop {
            let (consumed, written, status, source_eof) = {
                let input = self.source.fill_buf()?;
                let source_eof = input.is_empty();
                let before_in = self.decoder.total_in();
                let before_out = self.decoder.total_out();
                let flush = if source_eof {
                    FlushDecompress::Finish
                } else {
                    FlushDecompress::None
                };
                let status = self.decoder.decompress(input, output, flush).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid zlib stream")
                })?;
                let consumed = usize::try_from(self.decoder.total_in() - before_in)
                    .map_err(|_| io::Error::other("zlib input counter overflow"))?;
                let written = usize::try_from(self.decoder.total_out() - before_out)
                    .map_err(|_| io::Error::other("zlib output counter overflow"))?;
                (consumed, written, status, source_eof)
            };
            self.source.consume(consumed);

            if status == Status::StreamEnd {
                self.ended = true;
                return Ok(written);
            }
            if written != 0 {
                return Ok(written);
            }
            if source_eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated zlib stream",
                ));
            }
            if consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stalled zlib stream",
                ));
            }
        }
    }
}

struct Parser {
    version: u8,
    exact_domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
    ip_cidrs: Vec<IpNet>,
    first_unsupported: Option<(u64, UnsupportedSrsMatcher)>,
}

impl Parser {
    const fn new(version: u8) -> Self {
        Self {
            version,
            exact_domains: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            ip_cidrs: Vec::new(),
            first_unsupported: None,
        }
    }

    fn reserve_rules(&mut self, count: usize) -> Result<(), SrsError> {
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

    fn read_rule<R: Read>(
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

    fn finish(mut self, rules: u64) -> Result<DecodedSrsRuleSet, SrsError> {
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

fn normalize_domain(mut value: String) -> Result<String, SrsError> {
    if value.ends_with('.') {
        value.pop();
    }
    if value.is_empty() || value.len() > 255 || !value.is_ascii() {
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

struct DomainEntries {
    exact: Vec<String>,
    suffix: Vec<String>,
}

fn read_domain_set<R: Read>(reader: &mut R) -> Result<DomainEntries, SrsError> {
    let keys = read_succinct_set(reader)?;
    let mut exact = Vec::new();
    let mut suffix = Vec::new();
    exact
        .try_reserve(keys.len())
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    suffix
        .try_reserve(keys.len())
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for key in keys {
        let reversed =
            std::str::from_utf8(&key).map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?;
        let mut value = String::new();
        value
            .try_reserve_exact(reversed.len())
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        value.extend(reversed.chars().rev());
        match value.chars().next() {
            Some(DOMAIN_ROOT_LABEL) => {
                value.remove(0);
                suffix.push(normalize_domain(value)?);
            }
            Some(DOMAIN_PREFIX_LABEL) => {
                value.remove(0);
                if value.starts_with('.') {
                    value.remove(0);
                }
                suffix.push(normalize_domain(value)?);
            }
            Some(_) => exact.push(normalize_domain(value)?),
            None => return Err(SrsError::new(SrsErrorKind::InvalidDomainSet)),
        }
    }
    Ok(DomainEntries { exact, suffix })
}

fn read_succinct_set<R: Read>(reader: &mut R) -> Result<Vec<Vec<u8>>, SrsError> {
    if read_byte(reader)? != 0 {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let leaves = read_u64_words(reader)?;
    let bitmap = read_u64_words(reader)?;
    let labels = read_byte_vec(reader)?;
    if bitmap.is_empty() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }

    let Some((last_word, last_value)) = bitmap
        .iter()
        .copied()
        .enumerate()
        .rev()
        .find(|(_, word)| *word != 0)
    else {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    };
    if bitmap[last_word + 1..].iter().any(|word| *word != 0) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let last_one = last_word
        .checked_mul(64)
        .and_then(|base| base.checked_add(63 - last_value.leading_zeros() as usize))
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let ones = bitmap
        .iter()
        .try_fold(0_usize, |count, word| {
            count.checked_add(word.count_ones() as usize)
        })
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let used_bits = last_one
        .checked_add(1)
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let zeros = used_bits
        .checked_sub(ones)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
    if ones != zeros.saturating_add(1) || labels.len() != zeros {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    if has_set_bit_at_or_after(&leaves, ones) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }

    let mut selects = Vec::new();
    selects
        .try_reserve_exact(ones)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for position in 0..used_bits {
        if bit(&bitmap, position) {
            selects.push(position);
        }
    }
    if selects.len() != ones || bit(&leaves, 0) {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    let ranks = word_ranks(&bitmap)?;

    #[derive(Clone, Copy)]
    struct Frame {
        node: usize,
        bitmap: usize,
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(256)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    frames.push(Frame { node: 0, bitmap: 0 });
    let mut current = Vec::new();
    current
        .try_reserve_exact(256)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    let mut keys = Vec::new();
    keys.try_reserve_exact(ones.min(labels.len()))
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;

    while let Some(frame) = frames.last_mut() {
        if frame.bitmap > last_one {
            return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
        }
        if bit(&bitmap, frame.bitmap) {
            frames.pop();
            if !frames.is_empty() {
                current
                    .pop()
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
                frames
                    .last_mut()
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?
                    .bitmap += 1;
            }
            continue;
        }
        let label_index = frame
            .bitmap
            .checked_sub(frame.node)
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        let label = *labels
            .get(label_index)
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        current
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        current.push(label);
        let next_node = count_zeros(&bitmap, &ranks, frame.bitmap + 1)?;
        if next_node == 0 || next_node >= ones {
            return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
        }
        let next_bitmap = selects
            .get(next_node - 1)
            .and_then(|position| position.checked_add(1))
            .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
        if bit(&leaves, next_node) {
            let mut key = Vec::new();
            key.try_reserve_exact(current.len())
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            key.extend_from_slice(&current);
            keys.try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            keys.push(key);
        }
        frames
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        frames.push(Frame {
            node: next_node,
            bitmap: next_bitmap,
        });
    }
    if keys.is_empty() {
        return Err(SrsError::new(SrsErrorKind::InvalidDomainSet));
    }
    Ok(keys)
}

fn word_ranks(words: &[u64]) -> Result<Vec<usize>, SrsError> {
    let mut ranks = Vec::<usize>::new();
    ranks
        .try_reserve_exact(words.len() + 1)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    ranks.push(0);
    for word in words {
        let next = ranks
            .last()
            .copied()
            .and_then(|rank| rank.checked_add(word.count_ones() as usize))
            .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
        ranks.push(next);
    }
    Ok(ranks)
}

fn count_zeros(words: &[u64], ranks: &[usize], position: usize) -> Result<usize, SrsError> {
    let word = position / 64;
    let offset = position % 64;
    let base = *ranks
        .get(word)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))?;
    let partial = if offset == 0 {
        0
    } else {
        words
            .get(word)
            .map(|value| (value & ((1_u64 << offset) - 1)).count_ones() as usize)
            .unwrap_or(0)
    };
    let ones = base
        .checked_add(partial)
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    position
        .checked_sub(ones)
        .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidDomainSet))
}

fn bit(words: &[u64], position: usize) -> bool {
    words
        .get(position / 64)
        .is_some_and(|word| word & (1_u64 << (position % 64)) != 0)
}

fn has_set_bit_at_or_after(words: &[u64], position: usize) -> bool {
    let word = position / 64;
    let offset = position % 64;
    words.get(word).is_some_and(|value| {
        let mask = if offset == 0 {
            u64::MAX
        } else {
            u64::MAX << offset
        };
        value & mask != 0
    }) || words
        .get(word + 1..)
        .is_some_and(|tail| tail.iter().any(|value| *value != 0))
}

fn read_ip_set<R: Read>(reader: &mut R) -> Result<Vec<IpNet>, SrsError> {
    if read_byte(reader)? != 1 {
        return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
    }
    let range_count = read_be_u64(reader)?;
    let capacity =
        usize::try_from(range_count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut networks = Vec::new();
    networks
        .try_reserve(capacity)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    let mut previous: Option<IpNumber> = None;
    for _ in 0..range_count {
        let from = read_ip_number(reader)?;
        let to = read_ip_number(reader)?;
        if from.family() != to.family() || from > to {
            return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
        }
        if previous.is_some_and(|end| end.family() > from.family() || end >= from) {
            return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
        }
        decompose_ip_range(from, to, &mut networks)?;
        previous = Some(to);
    }
    Ok(networks)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpNumber {
    V4(u32),
    V6(u128),
}

impl IpNumber {
    const fn family(self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

fn read_ip_number<R: Read>(reader: &mut R) -> Result<IpNumber, SrsError> {
    match read_uvarint(reader)? {
        4 => {
            let mut bytes = [0_u8; 4];
            read_exact(reader, &mut bytes)?;
            Ok(IpNumber::V4(u32::from_be_bytes(bytes)))
        }
        16 => {
            let mut bytes = [0_u8; 16];
            read_exact(reader, &mut bytes)?;
            Ok(IpNumber::V6(u128::from_be_bytes(bytes)))
        }
        _ => Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
    }
}

fn decompose_ip_range(
    from: IpNumber,
    to: IpNumber,
    networks: &mut Vec<IpNet>,
) -> Result<(), SrsError> {
    match (from, to) {
        (IpNumber::V4(mut current), IpNumber::V4(end)) => loop {
            let alignment = current.trailing_zeros();
            let remaining = u64::from(end) - u64::from(current) + 1;
            let size = 63 - remaining.leading_zeros();
            let host_bits = alignment.min(size) as u8;
            networks
                .try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            let prefix = 32 - host_bits;
            let network = Ipv4Net::new(Ipv4Addr::from(current), prefix)
                .map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            networks.push(IpNet::V4(network));
            let step = 1_u64 << host_bits;
            let next = u64::from(current) + step;
            if next > u64::from(end) {
                break;
            }
            current = u32::try_from(next).map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
        },
        (IpNumber::V6(mut current), IpNumber::V6(end)) => loop {
            let alignment = current.trailing_zeros();
            let size = if current == 0 && end == u128::MAX {
                128
            } else {
                let remaining = end
                    .checked_sub(current)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidIpSet))?;
                127 - remaining.leading_zeros()
            };
            let host_bits = alignment.min(size) as u8;
            networks
                .try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            let prefix = 128 - host_bits;
            let network = Ipv6Net::new(Ipv6Addr::from(current), prefix)
                .map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            networks.push(IpNet::V6(network));
            if host_bits == 128 {
                break;
            }
            let next = current
                .checked_add(1_u128 << host_bits)
                .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            if next > end {
                break;
            }
            current = next;
        },
        _ => return Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
    }
    Ok(())
}

fn read_interface_address_map<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let size = read_uvarint(reader)?;
    for _ in 0..size {
        read_byte(reader)?;
        read_prefix_slice(reader)?;
    }
    Ok(())
}

fn read_prefix_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    for _ in 0..count {
        let length = read_uvarint(reader)?;
        match length {
            4 => {
                let mut bytes = [0_u8; 4];
                read_exact(reader, &mut bytes)?;
                if read_byte(reader)? > 32 {
                    return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
                }
            }
            16 => {
                let mut bytes = [0_u8; 16];
                read_exact(reader, &mut bytes)?;
                if read_byte(reader)? > 128 {
                    return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
                }
            }
            _ => return Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
        }
    }
    Ok(())
}

fn read_string_slice<R: Read>(reader: &mut R) -> Result<Vec<String>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for _ in 0..count {
        let value = read_byte_vec(reader)?;
        values
            .push(String::from_utf8(value).map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?);
    }
    Ok(values)
}

fn read_u8_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut buffer = [0_u8; 4096];
    let mut remaining = count;
    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        read_exact(reader, &mut buffer[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

fn read_u16_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let bytes = count
        .checked_mul(2)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut buffer = [0_u8; 4096];
    let mut remaining = bytes;
    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        read_exact(reader, &mut buffer[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

fn read_u64_words<R: Read>(reader: &mut R) -> Result<Vec<u64>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for _ in 0..count {
        values.push(read_be_u64(reader)?);
    }
    Ok(values)
}

fn read_byte_vec<R: Read>(reader: &mut R) -> Result<Vec<u8>, SrsError> {
    let length = read_uvarint(reader)?;
    let length =
        usize::try_from(length).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    value.resize(length, 0);
    read_exact(reader, &mut value)?;
    Ok(value)
}

fn read_bool<R: Read>(reader: &mut R) -> Result<bool, SrsError> {
    match read_byte(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SrsError::new(SrsErrorKind::InvalidBoolean)),
    }
}

fn read_uvarint<R: Read>(reader: &mut R) -> Result<u64, SrsError> {
    let mut value = 0_u64;
    for index in 0..10_u32 {
        let byte = read_byte(reader)?;
        if index == 9 && byte > 1 {
            return Err(SrsError::new(SrsErrorKind::IntegerOverflow));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            if index != 0 && byte == 0 {
                return Err(SrsError::new(SrsErrorKind::NonCanonicalVarint));
            }
            return Ok(value);
        }
    }
    Err(SrsError::new(SrsErrorKind::IntegerOverflow))
}

fn read_be_u64<R: Read>(reader: &mut R) -> Result<u64, SrsError> {
    let mut bytes = [0_u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_byte<R: Read>(reader: &mut R) -> Result<u8, SrsError> {
    let mut byte = [0_u8; 1];
    read_exact(reader, &mut byte)?;
    Ok(byte[0])
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), SrsError> {
    reader.read_exact(buffer).map_err(map_payload_io)
}

fn map_source_io(error: io::Error) -> SrsError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        _ => SrsError::new(SrsErrorKind::Io),
    }
}

fn map_payload_io(error: io::Error) -> SrsError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            SrsError::new(SrsErrorKind::Compression)
        }
        _ => SrsError::new(SrsErrorKind::Io),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};

    use ferrum2_core::CanonicalDomain;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;

    fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push((value as u8) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    fn srs(payload: &[u8], version: u8) -> Vec<u8> {
        let mut output = Vec::from([b'S', b'R', b'S', version]);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(payload).unwrap();
        output.extend(encoder.finish().unwrap());
        output
    }

    fn one_string_rule(item: u8, value: &str, invert: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        write_uvarint(1, &mut payload);
        append_string_rule(&mut payload, item, value, invert);
        srs(&payload, 2)
    }

    fn append_string_rule(payload: &mut Vec<u8>, item: u8, value: &str, invert: bool) {
        payload.push(0);
        payload.push(item);
        write_uvarint(1, payload);
        write_uvarint(value.len() as u64, payload);
        payload.extend_from_slice(value.as_bytes());
        payload.push(ITEM_FINAL);
        payload.push(u8::from(invert));
    }

    #[test]
    fn supported_keyword_compiles_through_the_shared_match_set() {
        let decoded = decode_srs(one_string_rule(ITEM_DOMAIN_KEYWORD, "OpenAI", false).as_slice())
            .expect("decode keyword");
        assert_eq!(decoded.version(), 2);
        assert_eq!(decoded.statistics().domain_keywords, 1);
        let compiled = decoded.compile().expect("compile keyword");
        assert!(compiled.matches_domain(&CanonicalDomain::new("api.openai.com").unwrap()));
        assert!(!compiled.matches_domain(&CanonicalDomain::new("example.com").unwrap()));
    }

    #[test]
    fn multiple_default_rules_merge_into_one_compiled_or_set() {
        let mut payload = Vec::new();
        write_uvarint(2, &mut payload);
        append_string_rule(&mut payload, ITEM_DOMAIN_KEYWORD, "first-token", false);
        append_string_rule(&mut payload, ITEM_DOMAIN_KEYWORD, "second-token", false);

        let decoded = decode_srs(srs(&payload, 2).as_slice()).expect("decode two defaults");
        assert_eq!(decoded.statistics().rules, 2);
        assert_eq!(decoded.statistics().domain_keywords, 2);
        let compiled = decoded.compile().expect("compile merged defaults");
        assert!(compiled.matches_domain(&CanonicalDomain::new("first-token.example").unwrap()));
        assert!(compiled.matches_domain(&CanonicalDomain::new("second-token.example").unwrap()));
    }

    #[test]
    fn unknown_item_fails_with_a_closed_malformed_item_error() {
        let unknown = 0x7f;
        let encoded = srs(&[1, 0, unknown], 2);
        let error = decode_srs(encoded.as_slice()).expect_err("unknown item accepted");
        assert_eq!(error.kind(), SrsErrorKind::InvalidItem);
        assert_eq!(error.rule_index(), Some(0));
        assert_eq!(error.item(), Some(unknown));
        assert_eq!(error.kind().code(), "ruleset.format.item");
    }

    #[test]
    fn unsupported_structures_are_fully_classified() {
        let regex =
            decode_srs(one_string_rule(ITEM_DOMAIN_REGEX, ".*", false).as_slice()).unwrap_err();
        assert_eq!(regex.kind(), SrsErrorKind::UnsupportedMatcher);
        assert_eq!(
            regex.unsupported_matcher(),
            Some(UnsupportedSrsMatcher::DomainRegex)
        );

        let invert =
            decode_srs(one_string_rule(ITEM_DOMAIN_KEYWORD, "x", true).as_slice()).unwrap_err();
        assert_eq!(
            invert.unsupported_matcher(),
            Some(UnsupportedSrsMatcher::Invert)
        );

        let logical = srs(&[1, 1, 0, 0, 0], 2);
        let logical = decode_srs(logical.as_slice()).unwrap_err();
        assert_eq!(
            logical.unsupported_matcher(),
            Some(UnsupportedSrsMatcher::LogicalRule)
        );
    }

    #[test]
    fn malformed_headers_versions_varints_and_tails_fail_closed() {
        assert_eq!(
            decode_srs(&b"bad"[..]).unwrap_err().kind(),
            SrsErrorKind::InvalidMagic
        );
        assert_eq!(
            decode_srs(&b"SRS\x05"[..]).unwrap_err().kind(),
            SrsErrorKind::UnsupportedVersion
        );

        let noncanonical = srs(&[0x81, 0x00], 2);
        assert_eq!(
            decode_srs(noncanonical.as_slice()).unwrap_err().kind(),
            SrsErrorKind::NonCanonicalVarint
        );

        let mut payload = Vec::new();
        write_uvarint(1, &mut payload);
        payload.extend([0, ITEM_DOMAIN_KEYWORD, 1, 1, b'x', ITEM_FINAL, 0, 7]);
        let trailing_payload = srs(&payload, 2);
        assert_eq!(
            decode_srs(trailing_payload.as_slice()).unwrap_err().kind(),
            SrsErrorKind::TrailingPayload
        );

        let mut trailing_file = one_string_rule(ITEM_DOMAIN_KEYWORD, "x", false);
        trailing_file.push(7);
        assert_eq!(
            decode_srs(trailing_file.as_slice()).unwrap_err().kind(),
            SrsErrorKind::TrailingFileData
        );

        let mut truncated = one_string_rule(ITEM_DOMAIN_KEYWORD, "x", false);
        truncated.truncate(truncated.len() - 2);
        assert!(matches!(
            decode_srs(truncated.as_slice()).unwrap_err().kind(),
            SrsErrorKind::Truncated | SrsErrorKind::Compression
        ));
    }

    #[test]
    fn pinned_real_rule_sets_decode_and_match() {
        let cases: &[(&[u8], usize, usize, usize, usize)] = &[
            (
                include_bytes!("../../../../tests/fixtures/srs/ads.srs"),
                0,
                101_049,
                0,
                0,
            ),
            (
                include_bytes!("../../../../tests/fixtures/srs/ai.srs"),
                24,
                160,
                3,
                0,
            ),
            (
                include_bytes!("../../../../tests/fixtures/srs/cn.srs"),
                6,
                110_866,
                0,
                0,
            ),
            (
                include_bytes!("../../../../tests/fixtures/srs/cnip.srs"),
                0,
                0,
                0,
                5_960,
            ),
        ];
        let mut compiled = Vec::new();
        for (fixture, exact, suffix, keyword, cidr) in cases {
            let decoded = decode_srs(*fixture).expect("decode pinned fixture");
            let stats = decoded.statistics();
            assert_eq!(decoded.version(), 2);
            assert_eq!(stats.rules, 1);
            assert_eq!(stats.exact_domains, *exact);
            assert_eq!(stats.domain_suffixes, *suffix);
            assert_eq!(stats.domain_keywords, *keyword);
            assert_eq!(stats.ip_cidrs, *cidr);
            compiled.push(decoded.compile().expect("compile pinned fixture"));
        }
        assert!(compiled[0].matches_domain(&CanonicalDomain::new("x.0.myikas.com").unwrap()));
        assert!(compiled[1].matches_domain(&CanonicalDomain::new("api.openai.example").unwrap()));
        assert!(compiled[2].matches_domain(&CanonicalDomain::new("x.0.zone").unwrap()));
        assert!(compiled[3].matches_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))));
        assert!(!compiled[3].matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
