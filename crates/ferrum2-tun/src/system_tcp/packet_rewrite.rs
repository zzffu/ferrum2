use std::net::IpAddr;

use super::{RewritePlan, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::TunRejectReason;
use crate::packet::{ParsedIpPacket, TcpMetadata};

pub(super) fn is_initial_syn(tcp: TcpMetadata) -> bool {
    tcp.flags & (TCP_FIN | TCP_SYN | TCP_RST | TCP_ACK) == TCP_SYN
}

pub(super) fn tcp_sequence(packet: &[u8], transport_offset: usize) -> Result<u32, TunRejectReason> {
    let sequence = packet
        .get(transport_offset + 4..transport_offset + 8)
        .ok_or(TunRejectReason::InvalidTransportLength)?;
    Ok(u32::from_be_bytes(
        sequence
            .try_into()
            .expect("TCP sequence range has exactly four bytes"),
    ))
}

pub(super) fn rewrite_tuple(
    packet: &mut [u8],
    parsed: ParsedIpPacket,
    plan: RewritePlan,
) -> Result<(), TunRejectReason> {
    if parsed.source.is_ipv4() != plan.source.is_ipv4()
        || parsed.destination.is_ipv4() != plan.destination.is_ipv4()
    {
        return Err(TunRejectReason::InvalidDestination);
    }
    let offset = parsed.transport_offset;
    let old_source_port = read_word(packet, offset)?;
    let old_destination_port = read_word(packet, offset + 2)?;
    let mut tcp_checksum = read_word(packet, offset + 16)?;
    tcp_checksum = replace_checksum_word(tcp_checksum, old_source_port, plan.source.port());
    tcp_checksum =
        replace_checksum_word(tcp_checksum, old_destination_port, plan.destination.port());

    match (
        parsed.source,
        parsed.destination,
        plan.source.ip(),
        plan.destination.ip(),
    ) {
        (
            IpAddr::V4(old_source),
            IpAddr::V4(old_destination),
            IpAddr::V4(new_source),
            IpAddr::V4(new_destination),
        ) => {
            let mut header_checksum = read_word(packet, 10)?;
            for (old, new) in old_source
                .octets()
                .chunks_exact(2)
                .zip(new_source.octets().chunks_exact(2))
            {
                let old = u16::from_be_bytes([old[0], old[1]]);
                let new = u16::from_be_bytes([new[0], new[1]]);
                header_checksum = replace_checksum_word(header_checksum, old, new);
                tcp_checksum = replace_checksum_word(tcp_checksum, old, new);
            }
            for (old, new) in old_destination
                .octets()
                .chunks_exact(2)
                .zip(new_destination.octets().chunks_exact(2))
            {
                let old = u16::from_be_bytes([old[0], old[1]]);
                let new = u16::from_be_bytes([new[0], new[1]]);
                header_checksum = replace_checksum_word(header_checksum, old, new);
                tcp_checksum = replace_checksum_word(tcp_checksum, old, new);
            }
            packet[12..16].copy_from_slice(&new_source.octets());
            packet[16..20].copy_from_slice(&new_destination.octets());
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        }
        (
            IpAddr::V6(old_source),
            IpAddr::V6(old_destination),
            IpAddr::V6(new_source),
            IpAddr::V6(new_destination),
        ) => {
            for (old, new) in old_source
                .octets()
                .chunks_exact(2)
                .zip(new_source.octets().chunks_exact(2))
            {
                tcp_checksum = replace_checksum_word(
                    tcp_checksum,
                    u16::from_be_bytes([old[0], old[1]]),
                    u16::from_be_bytes([new[0], new[1]]),
                );
            }
            for (old, new) in old_destination
                .octets()
                .chunks_exact(2)
                .zip(new_destination.octets().chunks_exact(2))
            {
                tcp_checksum = replace_checksum_word(
                    tcp_checksum,
                    u16::from_be_bytes([old[0], old[1]]),
                    u16::from_be_bytes([new[0], new[1]]),
                );
            }
            packet[8..24].copy_from_slice(&new_source.octets());
            packet[24..40].copy_from_slice(&new_destination.octets());
        }
        _ => return Err(TunRejectReason::InvalidDestination),
    }
    packet[offset..offset + 2].copy_from_slice(&plan.source.port().to_be_bytes());
    packet[offset + 2..offset + 4].copy_from_slice(&plan.destination.port().to_be_bytes());
    packet[offset + 16..offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(())
}

fn read_word(packet: &[u8], offset: usize) -> Result<u16, TunRejectReason> {
    let word = packet
        .get(offset..offset + 2)
        .ok_or(TunRejectReason::InvalidTransportLength)?;
    Ok(u16::from_be_bytes([word[0], word[1]]))
}

fn replace_checksum_word(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}
