use crate::packet::internet_checksum;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(super) const MTU: usize = 1500;
pub(super) fn endpoints(ipv6: bool, index: usize) -> (SocketAddr, SocketAddr) {
    let (source, target) = if ipv6 {
        (
            IpAddr::V6("2001:db8:1::10".parse::<Ipv6Addr>().expect("fixture")),
            IpAddr::V6("2001:db8:2::20".parse::<Ipv6Addr>().expect("fixture")),
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        )
    };
    (
        SocketAddr::new(
            source,
            10000 + u16::try_from(index).expect("bounded fixture"),
        ),
        SocketAddr::new(target, 443),
    )
}

pub(super) fn packet(
    source: SocketAddr,
    target: SocketAddr,
    tcp_flags: Option<u8>,
    payload: &[u8],
) -> Vec<u8> {
    let ip_len = if source.is_ipv4() { 20 } else { 40 };
    let transport_len = if tcp_flags.is_some() { 20 } else { 8 };
    let mut bytes = vec![0; ip_len + transport_len + payload.len()];
    let protocol = if tcp_flags.is_some() { 6 } else { 17 };
    let length = u16::try_from(bytes.len()).expect("fixture packet");
    match (source.ip(), target.ip()) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = protocol;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&target.octets());
            let checksum = internet_checksum(&[&bytes[..20]]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&(length - 40).to_be_bytes());
            bytes[6] = protocol;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&target.octets());
        }
        _ => panic!("fixture families"),
    }
    bytes[ip_len..ip_len + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[ip_len + 2..ip_len + 4].copy_from_slice(&target.port().to_be_bytes());
    let checksum_offset = if let Some(flags) = tcp_flags {
        bytes[ip_len + 4..ip_len + 8].copy_from_slice(&7_u32.to_be_bytes());
        bytes[ip_len + 12] = 0x50;
        bytes[ip_len + 13] = flags;
        bytes[ip_len + 14..ip_len + 16].copy_from_slice(&32768_u16.to_be_bytes());
        ip_len + 16
    } else {
        bytes[ip_len + 4..ip_len + 6].copy_from_slice(&(length - ip_len as u16).to_be_bytes());
        ip_len + 6
    };
    bytes[ip_len + transport_len..].copy_from_slice(payload);
    let transport_length = (length - ip_len as u16).to_be_bytes();
    let checksum = if source.is_ipv4() {
        internet_checksum(&[
            &bytes[12..20],
            &[0, protocol],
            &transport_length,
            &bytes[ip_len..],
        ])
    } else {
        internet_checksum(&[
            &bytes[8..40],
            &[0, 0],
            &transport_length,
            &[0, 0, 0, protocol],
            &bytes[ip_len..],
        ])
    };
    bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

pub(super) fn fragments(packet: &[u8]) -> [Vec<u8>; 2] {
    assert_eq!(packet[0], 0x45);
    let split = 32;
    std::array::from_fn(|index| {
        let payload = if index == 0 {
            &packet[20..20 + split]
        } else {
            &packet[20 + split..]
        };
        let mut fragment = packet[..20].to_vec();
        fragment.extend_from_slice(payload);
        let length = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&length.to_be_bytes());
        fragment[4..6].copy_from_slice(&packet[20..22]);
        fragment[6..8].copy_from_slice(
            &(if index == 0 {
                0x2000_u16
            } else {
                (split / 8) as u16
            })
            .to_be_bytes(),
        );
        fragment[10..12].fill(0);
        let checksum = internet_checksum(&[&fragment[..20]]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragment
    })
}
