use std::net::{Ipv4Addr, Ipv6Addr};

use super::control::CONTROL_ERROR_INTERVAL_MILLIS;
use super::test_support::{
    ipv4_tcp_with_options, ipv4_tcp_zero_checksum, ipv4_udp, ipv6_udp, repair_ipv4_header,
    repair_transport_checksum,
};
use super::{
    ControlRateLimiter, Families, IpFamily, LocalControlKind, PacketParser, PacketRejectReason,
    ParsedPacket, TransportMetadata, control_context, internet_checksum, ipv4_directed_broadcast,
    oversized_ingress_control, write_local_control_error,
};

#[test]
fn directed_broadcast_respects_prefix_31_and_32_host_semantics() {
    let interface = Ipv4Addr::new(198, 18, 0, 2);
    assert!(ipv4_directed_broadcast(
        Ipv4Addr::new(198, 18, 0, 3),
        (interface, 30)
    ));
    assert!(!ipv4_directed_broadcast(
        Ipv4Addr::new(198, 18, 0, 1),
        (interface, 30)
    ));
    assert!(!ipv4_directed_broadcast(
        Ipv4Addr::new(198, 18, 0, 3),
        (interface, 31)
    ));
    assert!(!ipv4_directed_broadcast(interface, (interface, 32)));
}

fn ipv4_icmp(icmp_type: u8, code: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20] = icmp_type;
    packet[21] = code;
    let checksum = internet_checksum(&[&packet[20..]]);
    packet[22..24].copy_from_slice(&checksum.to_be_bytes());
    repair_ipv4_header(&mut packet);
    packet
}

fn ipv6_icmp(icmp_type: u8, code: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    packet[23] = 2;
    packet[24..40]
        .copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    packet[40] = icmp_type;
    packet[41] = code;
    let length = 8_u32.to_be_bytes();
    let next = [0_u8, 0, 0, 58];
    let checksum = internet_checksum(&[
        &packet[8..24],
        &packet[24..40],
        &length,
        &next,
        &packet[40..],
    ]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn ipv6_udp_with_options_header(header_type: u8, options: &[u8]) -> Vec<u8> {
    let header_len = options.len() + 2;
    assert!(header_len >= 8);
    assert_eq!(header_len % 8, 0);
    let base = ipv6_udp(b"options");
    let mut packet = Vec::with_capacity(base.len() + header_len);
    packet.extend_from_slice(&base[..40]);
    packet[6] = header_type;
    packet.push(17);
    packet.push(u8::try_from(header_len / 8 - 1).expect("test extension length"));
    packet.extend_from_slice(options);
    packet.extend_from_slice(&base[40..]);
    let payload_len = u16::try_from(packet.len() - 40).expect("test IPv6 payload length");
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    repair_transport_checksum(&mut packet, 40 + header_len, 17);
    packet
}

#[test]
fn parses_valid_ipv4_options_and_ipv6_transport() {
    let ipv4 = ipv4_udp(b"abcd", &[1, 7, 2, 0]);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv4)
        .expect("valid IPv4 options")
    else {
        panic!("complete IPv4 packet expected")
    };
    assert_eq!(parsed.family, IpFamily::Ipv4);
    assert_eq!(parsed.transport_offset, 24);
    assert!(matches!(parsed.transport, TransportMetadata::Udp(_)));

    let ipv6 = ipv6_udp(b"abcd");
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv6)
        .expect("valid IPv6")
    else {
        panic!("complete IPv6 packet expected")
    };
    assert_eq!(parsed.family, IpFamily::Ipv6);
    assert_eq!(parsed.transport_offset, 40);
}

#[test]
fn tcp_option_tlvs_are_bounded_before_flow_metadata_is_returned() {
    let valid = ipv4_tcp_with_options(&[2, 4, 0x05, 0xb4]);
    assert!(matches!(
        PacketParser::new(Families::DUAL).parse(&valid),
        Ok(ParsedPacket::Complete(_))
    ));

    let invalid = ipv4_tcp_with_options(&[2, 1, 0, 0]);
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&invalid)
            .expect_err("TCP option length one")
            .reason,
        PacketRejectReason::InvalidTransport
    );
}

#[test]
fn tcp_zero_checksum_field_is_valid_only_when_full_checksum_matches() {
    let packet = ipv4_tcp_zero_checksum();
    assert_eq!(&packet[36..38], &[0, 0]);
    let transport = &packet[20..];
    let length = u16::try_from(transport.len())
        .expect("test TCP length")
        .to_be_bytes();
    assert_eq!(
        internet_checksum(&[
            &packet[12..16],
            &packet[16..20],
            &[0, 6],
            &length,
            transport,
        ]),
        0
    );
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&packet)
        .expect("a valid TCP checksum may be encoded as zero")
    else {
        panic!("complete TCP packet expected")
    };
    assert!(matches!(parsed.transport, TransportMetadata::Tcp(_)));

    let mut corrupted = packet;
    *corrupted.last_mut().expect("TCP payload") ^= 1;
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&corrupted)
            .expect_err("zero does not bypass TCP checksum validation")
            .reason,
        PacketRejectReason::InvalidTransportChecksum
    );
}

#[test]
fn walks_bounded_ipv6_extensions_and_rejects_active_routing() {
    let base = ipv6_udp(b"extension");
    let mut packet = Vec::with_capacity(base.len() + 16);
    packet.extend_from_slice(&base[..40]);
    packet[6] = 0;
    packet.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&base[40..]);
    let payload_len = packet.len() - 40;
    packet[4..6].copy_from_slice(&u16::try_from(payload_len).unwrap().to_be_bytes());
    repair_transport_checksum(&mut packet, 56, 17);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&packet)
        .expect("HBH and destination options")
    else {
        panic!("complete packet expected")
    };
    assert_eq!(parsed.transport_offset, 56);

    let mut routing = packet;
    routing[40] = 43;
    routing[48] = 17;
    assert!(
        PacketParser::new(Families::DUAL).parse(&routing).is_ok(),
        "routing header with zero segments left is inert"
    );
    routing[51] = 1;
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&routing)
            .expect_err("active source routing is rejected")
            .reason,
        PacketRejectReason::MalformedExtension
    );

    let base = ipv6_udp(b"limit");
    let mut too_many = base[..40].to_vec();
    too_many[6] = 60;
    for index in 0..9 {
        too_many.extend_from_slice(&[if index == 8 { 17 } else { 60 }, 0, 0, 0, 0, 0, 0, 0]);
    }
    too_many.extend_from_slice(&base[40..]);
    let payload_len = u16::try_from(too_many.len() - 40).unwrap();
    too_many[4..6].copy_from_slice(&payload_len.to_be_bytes());
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&too_many)
            .expect_err("ninth extension header")
            .reason,
        PacketRejectReason::MalformedExtension
    );
}

#[test]
fn ipv6_option_tlvs_are_bounded_inside_hbh_and_destination_headers() {
    let valid_options = [
        0, // Pad1
        1, 3, 0, 0, 0, // PadN
        0x22, 4, 1, 2, 3, 4, // unknown option with action 00 (skip)
        0, 0, // Pad1
    ];
    for header_type in [0, 60] {
        let valid = ipv6_udp_with_options_header(header_type, &valid_options);
        let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
            .parse(&valid)
            .expect("bounded IPv6 options")
        else {
            panic!("complete IPv6 packet expected")
        };
        assert_eq!(parsed.transport_offset, 56);

        let malformed = ipv6_udp_with_options_header(header_type, &[0x22, 5, 0, 0, 0, 0]);
        assert_eq!(
            PacketParser::new(Families::DUAL)
                .parse(&malformed)
                .expect_err("option data crosses its extension header")
                .reason,
            PacketRejectReason::MalformedExtension
        );
    }
}

#[test]
fn ipv6_option_discard_actions_fail_closed_in_hbh_and_destination_headers() {
    for header_type in [0, 60] {
        for option_type in [0x40, 0x80, 0xc0] {
            let packet = ipv6_udp_with_options_header(header_type, &[option_type, 0, 0, 0, 0, 0]);
            assert_eq!(
                PacketParser::new(Families::DUAL)
                    .parse(&packet)
                    .expect_err("IPv6 option discard action must fail closed")
                    .reason,
                PacketRejectReason::MalformedExtension
            );
        }
    }
}

#[test]
fn invalid_source_and_destination_are_reported_separately_for_each_family() {
    let parser = PacketParser::new(Families::DUAL);

    let mut ipv4_source = ipv4_udp(b"source", &[]);
    ipv4_source[12..16].fill(0);
    repair_ipv4_header(&mut ipv4_source);
    assert_eq!(
        parser
            .parse(&ipv4_source)
            .expect_err("unspecified IPv4 source")
            .reason,
        PacketRejectReason::InvalidSource
    );

    let mut ipv4_destination = ipv4_udp(b"destination", &[]);
    ipv4_destination[16..20].copy_from_slice(&[224, 0, 0, 1]);
    repair_ipv4_header(&mut ipv4_destination);
    assert_eq!(
        parser
            .parse(&ipv4_destination)
            .expect_err("multicast IPv4 destination")
            .reason,
        PacketRejectReason::InvalidDestination
    );

    let mut ipv6_source = ipv6_udp(b"source");
    ipv6_source[8..24].fill(0);
    assert_eq!(
        parser
            .parse(&ipv6_source)
            .expect_err("unspecified IPv6 source")
            .reason,
        PacketRejectReason::InvalidSource
    );

    let mut ipv6_destination = ipv6_udp(b"destination");
    ipv6_destination[24..40].copy_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets());
    assert_eq!(
        parser
            .parse(&ipv6_destination)
            .expect_err("multicast IPv6 destination")
            .reason,
        PacketRejectReason::InvalidDestination
    );
}

#[test]
fn family_enablement_and_malformed_inputs_fail_closed() {
    let ipv4 = ipv4_udp(b"x", &[]);
    let ipv6 = ipv6_udp(b"x");
    assert_eq!(
        PacketParser::new(Families::IPV6_ONLY)
            .parse(&ipv4)
            .expect_err("IPv4 disabled")
            .reason,
        PacketRejectReason::DisabledFamily
    );
    assert_eq!(
        PacketParser::new(Families::IPV4_ONLY)
            .parse(&ipv6)
            .expect_err("IPv6 disabled")
            .reason,
        PacketRejectReason::DisabledFamily
    );

    for length in 0..64 {
        for first in 0..=u8::MAX {
            let mut input = vec![0xa5; length];
            if let Some(byte) = input.first_mut() {
                *byte = first;
            }
            let _ = PacketParser::new(Families::DUAL).parse(&input);
        }
    }
    let mut malformed_option = ipv4_udp(b"x", &[1, 1, 1, 1]);
    malformed_option[20] = 2;
    malformed_option[21] = 1;
    super::test_support::repair_ipv4_header(&mut malformed_option);
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&malformed_option)
            .expect_err("option length one")
            .reason,
        PacketRejectReason::InvalidIpv4Options
    );

    let mut source_route = ipv4_udp(b"x", &[131, 3, 0, 0]);
    super::test_support::repair_ipv4_header(&mut source_route);
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&source_route)
            .expect_err("source route option")
            .reason,
        PacketRejectReason::SourceRouteOption
    );

    let mut unsupported = ipv6;
    unsupported[6] = 51;
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&unsupported)
            .expect_err("AH is outside the TCP/UDP pipeline")
            .reason,
        PacketRejectReason::UnsupportedProtocol
    );

    let mut bad_transport_checksum = ipv4_udp(b"checksum", &[]);
    *bad_transport_checksum.last_mut().unwrap() ^= 1;
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&bad_transport_checksum)
            .expect_err("transport checksum mismatch")
            .reason,
        PacketRejectReason::InvalidTransportChecksum
    );

    let mut zero_port = ipv6_udp(b"port");
    zero_port[40..42].fill(0);
    assert_eq!(
        PacketParser::new(Families::DUAL)
            .parse(&zero_port)
            .expect_err("port zero is invalid before checksum acceptance")
            .reason,
        PacketRejectReason::InvalidTransport
    );
}

#[test]
fn pmtu_builders_quote_safely_and_produce_valid_checksums() {
    let mtu = 1_280;
    let mut ipv4 = ipv4_udp(&vec![0x44; mtu], &[]);
    ipv4[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    repair_ipv4_header(&mut ipv4);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv4)
        .expect("oversized IPv4 remains canonically valid")
    else {
        panic!("complete packet expected")
    };
    let (context, kind) =
        oversized_ingress_control(&ipv4, parsed, mtu).expect("DF requires feedback");
    assert_eq!(kind, LocalControlKind::FragmentationNeeded);
    let mut output = vec![0_u8; mtu];
    let length = write_local_control_error(&mut output, &ipv4, context, kind, mtu)
        .expect("ICMP fragmentation needed");
    assert_eq!(&output[12..16], &ipv4[16..20]);
    assert_eq!(&output[16..20], &ipv4[12..16]);
    assert_eq!(&output[20..22], &[3, 4]);
    assert_eq!(u16::from_be_bytes([output[26], output[27]]), mtu as u16);
    assert_eq!(internet_checksum(&[&output[..20]]), 0);
    assert_eq!(internet_checksum(&[&output[20..length]]), 0);
    assert_eq!(&output[28..length], &ipv4[..28]);

    let ipv6 = ipv6_udp(&vec![0x66; mtu]);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv6)
        .expect("oversized IPv6 remains canonically valid")
    else {
        panic!("complete packet expected")
    };
    let (context, kind) = oversized_ingress_control(&ipv6, parsed, mtu).expect("IPv6 requires PTB");
    assert_eq!(kind, LocalControlKind::PacketTooBig);
    let length = write_local_control_error(&mut output, &ipv6, context, kind, mtu)
        .expect("ICMPv6 packet too big");
    assert_eq!(&output[40..42], &[2, 0]);
    assert_eq!(
        u32::from_be_bytes(output[44..48].try_into().unwrap()),
        1_280
    );
    assert_eq!(length, mtu);
    let payload_len = u32::try_from(length - 40).unwrap().to_be_bytes();
    let next = [0_u8, 0, 0, 58];
    assert_eq!(
        internet_checksum(&[
            &output[8..24],
            &output[24..40],
            &payload_len,
            &next,
            &output[40..length],
        ]),
        0
    );
}

#[test]
fn unreachable_builders_are_family_appropriate_and_echo_is_closed() {
    let ipv4 = ipv4_udp(b"declined", &[]);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv4)
        .expect("valid UDP")
    else {
        panic!("complete packet expected")
    };
    let mut output = vec![0_u8; 1_280];
    let length = write_local_control_error(
        &mut output,
        &ipv4,
        control_context(parsed),
        LocalControlKind::PortUnreachable,
        1_280,
    )
    .expect("IPv4 port unreachable");
    assert_eq!(&output[20..22], &[3, 3]);
    assert_eq!(internet_checksum(&[&output[20..length]]), 0);

    let ipv6 = ipv6_udp(b"declined");
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&ipv6)
        .expect("valid UDP")
    else {
        panic!("complete packet expected")
    };
    write_local_control_error(
        &mut output,
        &ipv6,
        control_context(parsed),
        LocalControlKind::AdministrativelyProhibited,
        1_280,
    )
    .expect("IPv6 administrative rejection");
    assert_eq!(&output[40..42], &[1, 1]);

    for echo in [ipv4_icmp(8, 0), ipv6_icmp(128, 0)] {
        let rejected = PacketParser::new(Families::DUAL)
            .parse(&echo)
            .expect_err("echo is never an outbound");
        assert_eq!(rejected.reason, PacketRejectReason::IcmpEchoUnsupported);
        assert!(
            write_local_control_error(
                &mut output,
                &echo,
                rejected.control.expect("closed control context"),
                LocalControlKind::ProtocolUnreachable,
                1_280,
            )
            .is_none()
        );
    }
}

#[test]
fn control_errors_do_not_answer_errors_multicast_or_nonfirst_fragments() {
    let mut output = vec![0_u8; 1_280];
    for error in [ipv4_icmp(3, 1), ipv6_icmp(1, 4)] {
        let rejected = PacketParser::new(Families::DUAL)
            .parse(&error)
            .expect_err("ICMP errors are outside the outbound pipeline");
        assert!(
            write_local_control_error(
                &mut output,
                &error,
                rejected.control.expect("suppression context"),
                LocalControlKind::ProtocolUnreachable,
                1_280,
            )
            .is_none()
        );
    }

    let mut multicast = ipv4_icmp(42, 0);
    multicast[16..20].copy_from_slice(&[224, 0, 0, 1]);
    repair_ipv4_header(&mut multicast);
    assert!(
        PacketParser::new(Families::DUAL)
            .parse(&multicast)
            .expect_err("multicast destination")
            .control
            .is_none()
    );

    let mut nonfirst = ipv4_udp(b"fragment", &[]);
    nonfirst[6..8].copy_from_slice(&1_u16.to_be_bytes());
    repair_ipv4_header(&mut nonfirst);
    let ParsedPacket::Fragment(fragment) = PacketParser::new(Families::DUAL)
        .parse(&nonfirst)
        .expect("well-formed non-first fragment")
    else {
        panic!("fragment expected")
    };
    assert_ne!(fragment.offset, 0);
}

#[test]
fn local_control_rate_is_fixed_and_does_not_burst_after_idle() {
    let mut limiter = ControlRateLimiter::new();
    assert!(limiter.allow(0));
    assert!(!limiter.allow(CONTROL_ERROR_INTERVAL_MILLIS - 1));
    assert!(limiter.allow(CONTROL_ERROR_INTERVAL_MILLIS));
    assert!(limiter.allow(10_000));
    assert!(!limiter.allow(10_000));
}
