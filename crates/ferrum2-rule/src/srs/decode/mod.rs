mod domain_set;
mod framing;
mod ip_set;
mod parser;
mod primitives;

use std::io::{BufRead, BufReader, Read};

use ipnet::IpNet;

use super::error::{SrsError, SrsErrorKind};
use crate::{CompiledMatchSet, MatchSetBuilder, MatchSetCapabilities};

use framing::StrictZlibDecoder;
use parser::Parser;
use primitives::{map_payload_io, map_source_io, read_byte, read_exact, read_uvarint};

#[cfg(test)]
use crate::srs::UnsupportedSrsMatcher;
#[cfg(test)]
use parser::{ITEM_DOMAIN_KEYWORD, ITEM_DOMAIN_REGEX, ITEM_FINAL};

const MAGIC: [u8; 3] = *b"SRS";
const MIN_VERSION: u8 = 1;
const MAX_VERSION: u8 = 4;

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
                include_bytes!("../../../../../tests/fixtures/srs/ads.srs"),
                0,
                101_049,
                0,
                0,
            ),
            (
                include_bytes!("../../../../../tests/fixtures/srs/ai.srs"),
                24,
                160,
                3,
                0,
            ),
            (
                include_bytes!("../../../../../tests/fixtures/srs/cn.srs"),
                6,
                110_866,
                0,
                0,
            ),
            (
                include_bytes!("../../../../../tests/fixtures/srs/cnip.srs"),
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
