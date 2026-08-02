use ferrum2_core::TargetAddr;
use ferrum2_socks5::{
    MAX_SOCKS_UDP_DATAGRAM_BYTES as MAX, SocksUdpError as Error, decode_udp_datagram as decode,
    encode_udp_datagram as encode,
};

#[test]
#[rustfmt::skip]
fn round_trip_empty_maximum_domain_boundary_and_ipv6_erratum() {
    for (case, target, payload, header) in [
        ("ipv4-empty", ip("192.0.2.1:53"), &b""[..], 10),
        ("ipv6", ip("[2001:db8::7]:5353"), &b"ipv6"[..], 22),
        ("domain", TargetAddr::domain("example.test", 443).unwrap(), &b"domain payload"[..], 19),
    ] {
        let mut wire = [0xa5; 64]; let len = encode(&target, payload, &mut wire).unwrap();
        assert_eq!(len, header + payload.len(), "{case} length"); assert_eq!(&wire[..3], &[0, 0, 0], "{case} prefix");
        let packet = decode(&wire[..len]).unwrap();
        assert_eq!(packet.to_target_addr(), target, "{case} target"); assert_eq!(packet.payload(), payload, "{case} payload");
        assert_eq!(packet.payload().as_ptr(), wire[header..].as_ptr(), "{case} borrowed");
    }
    for (case, target, header) in [
        ("max-ipv4", ip("192.0.2.1:53"), 10),
        ("max-ipv6", ip("[2001:db8::1]:53"), 22),
        ("max-domain", TargetAddr::domain("a", 53).unwrap(), 8),
    ] {
        let payload = vec![0x5a; MAX - header]; let mut wire = vec![0; MAX];
        assert_eq!(encode(&target, &payload, &mut wire), Ok(MAX), "{case} encode");
        assert_eq!(decode(&wire).unwrap().payload(), payload, "{case} payload");
    }
    let maximum = "a".repeat(255); let target = TargetAddr::domain(&maximum, 53).unwrap();
    let mut wire = vec![0; 7 + maximum.len()]; let len = encode(&target, b"", &mut wire).unwrap();
    assert_eq!(decode(&wire[..len]).unwrap().to_target_addr(), target, "domain-255");
    assert_eq!(encode(&ip("192.0.2.1:53"), &[0; MAX - 9], &mut vec![0; MAX]), Err(Error::Bounds), "one-over");
    let mut ipv6 = [0; 23]; assert_eq!(encode(&ip("[2001:db8::1]:53"), b"x", &mut ipv6), Ok(23), "ipv6-22-byte-header");
    assert_eq!(decode(&ipv6).unwrap().payload(), b"x", "ipv6 payload offset");
}

#[test]
#[rustfmt::skip]
fn every_truncation_and_malformed_class_fails_closed() {
    for (case, target) in [
        ("prefix-ipv4", ip("192.0.2.1:53")),
        ("prefix-ipv6", ip("[2001:db8::1]:53")),
        ("prefix-domain", TargetAddr::domain("example.test", 53).unwrap()),
    ] {
        let mut wire = [0; 64]; let len = encode(&target, b"payload", &mut wire).unwrap();
        for end in 0..len - 7 { assert_eq!(decode(&wire[..end]).err(), Some(Error::Invalid), "{case}-{end}"); }
    }
    let valid = [0, 0, 0, 1, 192, 0, 2, 1, 0, 53, b'x'];
    for index in [0, 1] {
        let mut wire = valid; wire[index] = 1; assert_eq!(decode(&wire).err(), Some(Error::Invalid), "rsv-{index}");
    }
    for fragment in 1..=255 {
        let mut wire = valid; wire[2] = fragment; assert_eq!(decode(&wire).err(), Some(Error::Fragmented), "frag-{fragment}");
    }
    for (case, wire) in [
        ("bad-atyp", vec![0, 0, 0, 0x7f]),
        ("domain-empty", vec![0, 0, 0, 3, 0, 0, 53]),
        ("domain-nonascii", vec![0, 0, 0, 3, 2, 0xc3, 0xa9, 0, 53]),
        ("domain-truncated", vec![0, 0, 0, 3, 3, b'a', b'b']),
        ("port-zero", vec![0, 0, 0, 1, 192, 0, 2, 1, 0, 0]),
    ] { assert_eq!(decode(&wire).err(), Some(Error::Invalid), "{case}"); }
    assert_eq!(decode(&vec![0; MAX + 1]).err(), Some(Error::Bounds), "oversize");
}

#[test]
#[rustfmt::skip]
fn short_output_is_unchanged_and_errors_expose_no_values() {
    let mut output = [0xa5; 9];
    assert_eq!(encode(&ip("192.0.2.1:53"), b"", &mut output), Err(Error::Bounds)); assert_eq!(output, [0xa5; 9], "short-output unchanged");
    for error in [Error::Invalid, Error::Fragmented, Error::Bounds] {
        let text = format!("{error:?} {error}");
        assert!(!text.contains("sentinel.example"), "error-address-{error:?}"); assert!(!text.contains("secret payload"), "error-payload-{error:?}");
    }
}

#[rustfmt::skip]
fn ip(value: &str) -> TargetAddr { TargetAddr::ip(value.parse().unwrap()).unwrap() }
