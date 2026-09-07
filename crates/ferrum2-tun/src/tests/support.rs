pub(super) use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
pub(super) use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
pub(super) use std::sync::{Arc, Mutex};
pub(super) use std::time::Duration;

pub(super) use crate::lifecycle::{
    NetworkChangeErrorDisposition, NetworkChangeTransition, NetworkResetHealthDisposition,
    classify_network_change, classify_network_change_error, classify_network_reset_health,
    classify_network_reset_refresh_error, map_managed_state_damage,
};
pub(super) use crate::reassembly::REASSEMBLY_TIMEOUT_MILLIS;
pub(super) use crate::tcp::tcp_flow_for_test;
pub(super) use crate::{AdapterErrorDisposition, classify_adapter_error};
pub(super) use crate::{
    Families, GenerationTable, INGRESS_SLOTS, MemoryDevice, NativeLifecycleOwner,
    NetworkResetBridgeOutcome, OutputFlushOutcome, OutputSendOutcome, OwnerControl, OwnerExit,
    OwnerRegistry, OwnerWake, PacketParser, PacketValidator, ParsedPacket, SessionItem, Stack,
    TunEvent, TunEventSink, TunNetworkResetReason, TunRejectReason, TunRoot, UdpDatagramEndpoints,
    UdpFiltering, UdpInjectOutcome, UdpPeerAuthorization, UdpResponseDropReason,
    finish_stack_setup, map_owner_spawn, reconcile_owner_exit, reported_owner_exit,
};

pub(super) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(*byte) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn ipv4_udp_with_payload(payload: usize) -> Vec<u8> {
    let len = 28 + payload;
    let mut packet = vec![0_u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20..22].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    for (index, byte) in packet[28..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let header = checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
    let pseudo = [0_u8, 17];
    let length = ((8 + payload) as u16).to_be_bytes();
    let udp = checksum(&[
        &packet[12..16],
        &packet[16..20],
        &pseudo,
        &length,
        &packet[20..],
    ]);
    packet[26..28].copy_from_slice(&udp.to_be_bytes());
    packet
}

pub(super) fn ipv4_udp() -> Vec<u8> {
    ipv4_udp_with_payload(4)
}

pub(super) fn ipv4_udp_fragments() -> (Vec<u8>, Vec<u8>) {
    let packet = ipv4_udp();
    let mut first = packet[..20].to_vec();
    first.extend_from_slice(&packet[20..28]);
    first[2..4].copy_from_slice(&28_u16.to_be_bytes());
    first[4..6].copy_from_slice(&7_u16.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    first[10..12].fill(0);
    let first_checksum = checksum(&[&first[..20]]);
    first[10..12].copy_from_slice(&first_checksum.to_be_bytes());

    let mut second = packet[..20].to_vec();
    second.extend_from_slice(&packet[28..]);
    second[2..4].copy_from_slice(&24_u16.to_be_bytes());
    second[4..6].copy_from_slice(&7_u16.to_be_bytes());
    second[6..8].copy_from_slice(&1_u16.to_be_bytes());
    second[10..12].fill(0);
    let second_checksum = checksum(&[&second[..20]]);
    second[10..12].copy_from_slice(&second_checksum.to_be_bytes());
    (first, second)
}

pub(super) fn fragment_ipv4_packet(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let fragment_capacity = ((mtu - 20) / 8) * 8;
    let transport = &packet[20..];
    transport
        .chunks(fragment_capacity)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = index * fragment_capacity;
            let more = offset + chunk.len() < transport.len();
            let mut fragment = packet[..20].to_vec();
            fragment.extend_from_slice(chunk);
            let fragment_len = u16::try_from(fragment.len()).unwrap();
            fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
            fragment[4..6].copy_from_slice(&77_u16.to_be_bytes());
            let offset_field = u16::try_from(offset / 8).unwrap() | if more { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&offset_field.to_be_bytes());
            fragment[10..12].fill(0);
            let header = checksum(&[&fragment[..20]]);
            fragment[10..12].copy_from_slice(&header.to_be_bytes());
            fragment
        })
        .collect()
}

pub(super) fn fragment_ipv6_udp(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let fragment_capacity = ((mtu - 48) / 8) * 8;
    let transport = &packet[40..];
    transport
        .chunks(fragment_capacity)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = index * fragment_capacity;
            let more = offset + chunk.len() < transport.len();
            let mut fragment = packet[..40].to_vec();
            fragment[4..6].copy_from_slice(&u16::try_from(8 + chunk.len()).unwrap().to_be_bytes());
            fragment[6] = 44;
            fragment.push(17);
            fragment.push(0);
            let offset_field = u16::try_from(offset / 8).unwrap() << 3 | if more { 1 } else { 0 };
            fragment.extend_from_slice(&offset_field.to_be_bytes());
            fragment.extend_from_slice(&77_u32.to_be_bytes());
            fragment.extend_from_slice(chunk);
            fragment
        })
        .collect()
}

pub(super) fn ipv4_tcp() -> Vec<u8> {
    ipv4_tcp_from_source_port(10_000)
}

pub(super) fn ipv4_tcp_from_source_port(source_port: u16) -> Vec<u8> {
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x02;
    packet[34..36].copy_from_slice(&8192_u16.to_be_bytes());
    let pseudo = [0_u8, 6];
    let length = 20_u16.to_be_bytes();
    let tcp = checksum(&[
        &packet[12..16],
        &packet[16..20],
        &pseudo,
        &length,
        &packet[20..],
    ]);
    packet[36..38].copy_from_slice(&tcp.to_be_bytes());
    let header = checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
    packet
}

pub(super) fn ipv6_udp() -> Vec<u8> {
    let mut packet = vec![0_u8; 52];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&12_u16.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[23] = 2;
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&53_u16.to_be_bytes());
    packet[44..46].copy_from_slice(&12_u16.to_be_bytes());
    packet[48..].copy_from_slice(b"test");
    let length = 12_u32.to_be_bytes();
    let next = [0_u8, 0, 0, 17];
    let udp = checksum(&[
        &packet[8..24],
        &packet[24..40],
        &length,
        &next,
        &packet[40..],
    ]);
    packet[46..48].copy_from_slice(&udp.to_be_bytes());
    packet
}

pub(super) fn ipv6_tcp() -> Vec<u8> {
    let mut packet = vec![0_u8; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
    packet[52] = 0x50;
    packet[53] = 0x02;
    let length = 20_u32.to_be_bytes();
    let next = [0_u8, 0, 0, 6];
    let tcp = checksum(&[
        &packet[8..24],
        &packet[24..40],
        &length,
        &next,
        &packet[40..],
    ]);
    packet[56..58].copy_from_slice(&tcp.to_be_bytes());
    packet
}

pub(super) fn repair_ipv4_header(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let header = checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
}

pub(super) fn repair_ipv4_tcp_checksum(packet: &mut [u8]) {
    packet[36..38].fill(0);
    let pseudo = [0_u8, 6];
    let length = ((packet.len() - 20) as u16).to_be_bytes();
    let tcp = checksum(&[
        &packet[12..16],
        &packet[16..20],
        &pseudo,
        &length,
        &packet[20..],
    ]);
    packet[36..38].copy_from_slice(&tcp.to_be_bytes());
}

pub(super) fn assert_packet_validity(name: &str, packet: &[u8], mtu: usize, expected: bool) {
    assert_eq!(
        PacketValidator::new(mtu).accepts(packet),
        expected,
        "{name}"
    );
}
