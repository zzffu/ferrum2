use std::cell::Cell;
use std::io::{self, Read, Write};

use flate2::{Compression, write::ZlibEncoder};

use super::{DecodedSrsRuleSet, decode_srs};
use crate::srs::{SrsDecodeLimits, SrsErrorKind, SrsLimitKind, UnsupportedSrsMatcher};

fn encoded(payload: &[u8]) -> Vec<u8> {
    let mut compressor = ZlibEncoder::new(Vec::new(), Compression::fast());
    compressor
        .write_all(payload)
        .expect("small fixture compression");
    let mut bytes = b"SRS\x02".to_vec();
    bytes.extend(compressor.finish().expect("finish small fixture"));
    bytes
}

fn limits(kind: SrsLimitKind, maximum: u64) -> SrsDecodeLimits {
    SrsDecodeLimits::try_new(&[(kind, maximum)]).expect("tighter test limit")
}

fn reject(payload: &[u8], kind: SrsLimitKind, maximum: u64) {
    let error = decode_srs(encoded(payload).as_slice(), limits(kind, maximum)).expect_err("limit");
    assert_eq!(
        (error.kind(), error.limit_kind()),
        (SrsErrorKind::LimitExceeded, Some(kind))
    );
}

const KEYWORD: &[u8] = &[1, 0, 3, 1, 1, b'x', 0xff, 0];

#[test]
fn limits_are_positive_distinct_and_never_widen_defaults() {
    for overrides in [
        vec![(SrsLimitKind::Entries, 0)],
        vec![(SrsLimitKind::Entries, 1_000_001)],
        vec![(SrsLimitKind::Entries, 1), (SrsLimitKind::Entries, 1)],
    ] {
        assert_eq!(
            SrsDecodeLimits::try_new(&overrides).unwrap_err().kind(),
            SrsErrorKind::InvalidLimits
        );
    }
    assert_eq!(
        SrsDecodeLimits::try_new(&[]).unwrap(),
        SrsDecodeLimits::default()
    );
}

#[test]
fn exact_encoded_and_decoded_bounds_allow_only_the_eof_probe() {
    struct CountingRead<'a> {
        source: &'a [u8],
        consumed: &'a Cell<usize>,
    }
    impl Read for CountingRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.source.read(buffer)?;
            self.consumed.set(self.consumed.get() + count);
            Ok(count)
        }
    }
    let bytes = encoded(KEYWORD);
    let exact = SrsDecodeLimits::try_new(&[
        (SrsLimitKind::EncodedBytes, bytes.len() as u64),
        (SrsLimitKind::DecodedBytes, KEYWORD.len() as u64),
    ])
    .unwrap();
    let consumed = Cell::new(0);
    let decoded = decode_srs(
        CountingRead {
            source: &bytes,
            consumed: &consumed,
        },
        exact,
    )
    .expect("exact bounds");
    assert_eq!(consumed.get(), bytes.len());
    assert_eq!(decoded.statistics().domain_keywords, 1);
    let error = decode_srs(
        bytes.as_slice(),
        limits(SrsLimitKind::EncodedBytes, bytes.len() as u64 - 1),
    )
    .unwrap_err();
    assert_eq!(error.limit_kind(), Some(SrsLimitKind::EncodedBytes));
    reject(
        KEYWORD,
        SrsLimitKind::DecodedBytes,
        KEYWORD.len() as u64 - 1,
    );

    let mut extra_file = bytes.clone();
    extra_file.push(1);
    consumed.set(0);
    assert_eq!(
        decode_srs(
            CountingRead {
                source: &extra_file,
                consumed: &consumed
            },
            exact
        )
        .unwrap_err()
        .limit_kind(),
        Some(SrsLimitKind::EncodedBytes)
    );
    assert_eq!(consumed.get(), bytes.len() + 1);
    let mut extra_payload = KEYWORD.to_vec();
    extra_payload.push(1);
    reject(
        &extra_payload,
        SrsLimitKind::DecodedBytes,
        KEYWORD.len() as u64,
    );
}

#[test]
fn duplicates_consume_entry_expansion_and_keyword_budgets_before_dedup() {
    let duplicate = [1, 0, 3, 2, 1, b'x', 1, b'x', 0xff, 0];
    reject(&duplicate, SrsLimitKind::Entries, 1);
    reject(&duplicate, SrsLimitKind::ExpandedBytes, 1);
    reject(&duplicate, SrsLimitKind::KeywordBytes, 1);
    let decoded = decode_srs(encoded(&duplicate).as_slice(), SrsDecodeLimits::default()).unwrap();
    assert_eq!(decoded.statistics().domain_keywords, 1);
    reject(
        &[1, 0, 3, 1, 2, b'x', b'y', 0xff, 0],
        SrsLimitKind::KeywordLength,
        1,
    );
}

#[test]
fn collection_rules_and_work_are_independent_cumulative_limits() {
    reject(KEYWORD, SrsLimitKind::Collection, 1);
    reject(KEYWORD, SrsLimitKind::Work, 1);
    // One logical root containing one empty default rule is structurally small,
    // but both attempted rules consume the shared rule allowance.
    reject(&[1, 1, 0, 1, 0, 0xff, 0, 0], SrsLimitKind::Rules, 1);
    // Depth two with a tighter depth-one policy; no deep input is constructed.
    reject(
        &[1, 1, 0, 1, 1, 0, 1, 0, 0xff, 0, 0, 0],
        SrsLimitKind::LogicalDepth,
        1,
    );
}

#[test]
fn unsupported_strings_stay_strict_and_share_the_resource_budget() {
    let regex = [1, 0, 4, 1, 2, b'.', b'*', 0xff, 0];
    let error = decode_srs(encoded(&regex).as_slice(), SrsDecodeLimits::default()).unwrap_err();
    assert_eq!(
        error.unsupported_matcher(),
        Some(UnsupportedSrsMatcher::DomainRegex)
    );
    reject(&regex, SrsLimitKind::UnsupportedStringBytes, 1);
    let invalid_utf8 = [1, 0, 4, 1, 1, 0xff, 0xff, 0];
    assert_eq!(
        decode_srs(
            encoded(&invalid_utf8).as_slice(),
            SrsDecodeLimits::default()
        )
        .unwrap_err()
        .kind(),
        SrsErrorKind::InvalidUtf8
    );
}

fn domain_payload(key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty() && key.len() <= 4);
    let mut payload = vec![1, 0, 2, 0, 1];
    payload.extend((1_u64 << key.len()).to_be_bytes());
    payload.push(1);
    let mut bitmap = 1_u64 << (2 * key.len());
    for index in 0..key.len() {
        bitmap |= 1_u64 << (2 * index + 1);
    }
    payload.extend(bitmap.to_be_bytes());
    payload.push(key.len() as u8);
    payload.extend(key);
    payload.extend([0xff, 0]);
    payload
}

#[test]
fn succinct_nodes_wire_depth_and_emission_bytes_are_admitted_independently() {
    let payload = domain_payload(b"xy");
    let decoded = decode_srs(encoded(&payload).as_slice(), SrsDecodeLimits::default()).unwrap();
    assert_eq!(
        (
            decoded.statistics().exact_domains,
            decoded.statistics().domain_suffixes
        ),
        (1, 0)
    );
    reject(&payload, SrsLimitKind::DomainNodes, 2);
    reject(&payload, SrsLimitKind::DomainDepth, 1);
    reject(&payload, SrsLimitKind::ExpandedBytes, 1);
}

#[test]
fn ipv6_inclusive_maximum_terminates_without_successor_overflow() {
    for (first, prefix) in [(u128::MAX, 128), (u128::MAX - 1, 127), (0, 0)] {
        let mut payload = vec![1, 0, 6, 1];
        payload.extend(1_u64.to_be_bytes());
        for address in [first, u128::MAX] {
            payload.push(16);
            payload.extend(address.to_be_bytes());
        }
        payload.extend([0xff, 0]);
        let decoded: DecodedSrsRuleSet =
            decode_srs(encoded(&payload).as_slice(), SrsDecodeLimits::default()).unwrap();
        assert_eq!(
            decoded.ip_cidrs,
            vec![
                format!("{}/{prefix}", std::net::Ipv6Addr::from(first))
                    .parse::<ipnet::IpNet>()
                    .unwrap()
            ]
        );
    }
}

#[test]
fn small_truncation_and_injected_io_remain_distinct_from_policy_limits() {
    let short = [1, 0, 3, 1, 8, b'x'];
    assert_eq!(
        decode_srs(encoded(&short).as_slice(), SrsDecodeLimits::default())
            .unwrap_err()
            .kind(),
        SrsErrorKind::Truncated
    );
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected private text",
            ))
        }
    }
    let error = decode_srs(FailedRead, SrsDecodeLimits::default()).unwrap_err();
    assert_eq!(error.kind(), SrsErrorKind::Io);
    assert!(!error.to_string().contains("injected private text"));
}
