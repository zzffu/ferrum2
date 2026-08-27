use super::{IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, internet_checksum};
use std::net::Ipv6Addr;

pub(crate) fn ipv4_udp(payload: &[u8], options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let header_len = 20 + options.len();
    let udp_len = 8 + payload.len();
    let total_len = header_len + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x40 | u8::try_from(header_len / 4).expect("test IHL");
    packet[2..4].copy_from_slice(&u16::try_from(total_len).expect("test length").to_be_bytes());
    packet[8] = 64;
    packet[9] = IP_PROTOCOL_UDP;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20..header_len].copy_from_slice(options);
    packet[header_len..header_len + 2].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[header_len + 2..header_len + 4].copy_from_slice(&53_u16.to_be_bytes());
    packet[header_len + 4..header_len + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("test UDP length")
            .to_be_bytes(),
    );
    packet[header_len + 8..].copy_from_slice(payload);
    repair_transport_checksum(&mut packet, header_len, IP_PROTOCOL_UDP);
    repair_ipv4_header(&mut packet);
    packet
}

pub(crate) fn ipv6_udp(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut packet = vec![0_u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(udp_len).expect("test length").to_be_bytes());
    packet[6] = IP_PROTOCOL_UDP;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&53_u16.to_be_bytes());
    packet[44..46].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("test UDP length")
            .to_be_bytes(),
    );
    packet[48..].copy_from_slice(payload);
    repair_transport_checksum(&mut packet, 40, IP_PROTOCOL_UDP);
    packet
}

pub(crate) fn ipv4_tcp_with_options(options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let tcp_len = 20 + options.len();
    let total_len = 20 + tcp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = IP_PROTOCOL_TCP;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20..22].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = u8::try_from(tcp_len / 4).unwrap() << 4;
    packet[33] = 0x02;
    packet[34..36].copy_from_slice(&8_192_u16.to_be_bytes());
    packet[40..].copy_from_slice(options);
    repair_transport_checksum(&mut packet, 20, IP_PROTOCOL_TCP);
    repair_ipv4_header(&mut packet);
    packet
}

pub(crate) fn ipv4_tcp_zero_checksum() -> Vec<u8> {
    let mut packet = vec![0_u8; 42];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&42_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = IP_PROTOCOL_TCP;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20..22].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    packet[34..36].copy_from_slice(&8_192_u16.to_be_bytes());
    packet[40..42].copy_from_slice(&[0xde, 0xea]);
    repair_ipv4_header(&mut packet);
    packet
}

pub(crate) fn repair_ipv4_header(packet: &mut [u8]) {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[10..12].fill(0);
    let checksum = internet_checksum(&[&packet[..header_len]]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

pub(crate) fn repair_transport_checksum(packet: &mut [u8], offset: usize, protocol: u8) {
    let checksum_offset = match protocol {
        IP_PROTOCOL_TCP => offset + 16,
        IP_PROTOCOL_UDP => offset + 6,
        _ => panic!("test protocol must be TCP or UDP"),
    };
    packet[checksum_offset..checksum_offset + 2].fill(0);
    let transport = &packet[offset..];
    let length = u32::try_from(transport.len())
        .expect("test transport length")
        .to_be_bytes();
    let next = [0_u8, 0, 0, protocol];
    let checksum = match packet[0] >> 4 {
        4 => internet_checksum(&[
            &packet[12..16],
            &packet[16..20],
            &next[2..],
            &length[2..],
            transport,
        ]),
        6 => internet_checksum(&[&packet[8..24], &packet[24..40], &length, &next, transport]),
        _ => unreachable!(),
    };
    let checksum = if protocol == IP_PROTOCOL_UDP && checksum == 0 {
        u16::MAX
    } else {
        checksum
    };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}
