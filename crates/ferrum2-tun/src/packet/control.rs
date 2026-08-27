use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    ControlContext, IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMPV6, IpFamily, MAX_REASSEMBLED_PACKET,
    PacketRejectReason, ParsedIpPacket, internet_checksum, ipv4_unicast, ipv6_unicast,
};

pub(crate) const fn map_packet_reject(reason: PacketRejectReason) -> crate::TunRejectReason {
    match reason {
        PacketRejectReason::Empty | PacketRejectReason::InvalidVersion => {
            crate::TunRejectReason::InvalidIpVersion
        }
        PacketRejectReason::DisabledFamily => crate::TunRejectReason::FamilyDisabled,
        PacketRejectReason::InvalidLength | PacketRejectReason::JumbogramUnsupported => {
            crate::TunRejectReason::InvalidIpLength
        }
        PacketRejectReason::InvalidHeaderChecksum => crate::TunRejectReason::InvalidIpChecksum,
        PacketRejectReason::InvalidSource => crate::TunRejectReason::InvalidSource,
        PacketRejectReason::InvalidDestination => crate::TunRejectReason::InvalidDestination,
        PacketRejectReason::InvalidIpv4Options
        | PacketRejectReason::SourceRouteOption
        | PacketRejectReason::ExtensionLimit
        | PacketRejectReason::MalformedExtension => crate::TunRejectReason::InvalidExtensionHeader,
        PacketRejectReason::InvalidFragment => crate::TunRejectReason::FragmentMalformed,
        PacketRejectReason::UnsupportedProtocol => crate::TunRejectReason::UnsupportedIpProtocol,
        PacketRejectReason::IcmpEchoUnsupported => crate::TunRejectReason::IcmpEchoUnsupported,
        PacketRejectReason::InvalidTransport => crate::TunRejectReason::InvalidTransportLength,
        PacketRejectReason::InvalidTransportChecksum => {
            crate::TunRejectReason::InvalidTransportChecksum
        }
    }
}

pub(crate) const CONTROL_ERROR_INTERVAL_MILLIS: i64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalControlKind {
    FragmentationNeeded,
    PacketTooBig,
    ProtocolUnreachable,
    PortUnreachable,
    AdministrativelyProhibited,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ControlRateLimiter {
    next_allowed_millis: Option<i64>,
}

impl ControlRateLimiter {
    pub(crate) const fn new() -> Self {
        Self {
            next_allowed_millis: None,
        }
    }

    pub(crate) fn allow(&mut self, now_millis: i64) -> bool {
        if self
            .next_allowed_millis
            .is_some_and(|next| now_millis < next)
        {
            return false;
        }
        self.next_allowed_millis = Some(now_millis.saturating_add(CONTROL_ERROR_INTERVAL_MILLIS));
        true
    }
}

pub(crate) const fn control_context(parsed: ParsedIpPacket) -> ControlContext {
    ControlContext {
        family: parsed.family,
        source: parsed.source,
        destination: parsed.destination,
        upper_protocol: parsed.upper_protocol,
        upper_protocol_field: parsed.upper_protocol_field,
        transport_offset: parsed.transport_offset,
        total_len: parsed.total_len,
        suppress_reply: false,
    }
}

pub(crate) fn oversized_ingress_control(
    packet: &[u8],
    parsed: ParsedIpPacket,
    mtu: usize,
) -> Option<(ControlContext, LocalControlKind)> {
    if packet.len() <= mtu || !parsed.metadata_matches(packet.len()) {
        return None;
    }
    let kind = match parsed.family {
        IpFamily::Ipv4 if u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]) & 0x4000 != 0 => {
            LocalControlKind::FragmentationNeeded
        }
        IpFamily::Ipv4 => return None,
        IpFamily::Ipv6 => LocalControlKind::PacketTooBig,
    };
    Some((control_context(parsed), kind))
}

pub(crate) fn write_local_control_error(
    output: &mut [u8],
    original: &[u8],
    context: ControlContext,
    kind: LocalControlKind,
    mtu: usize,
) -> Option<usize> {
    if context.suppress_reply
        || original.len() != context.total_len
        || context.upper_protocol_field >= context.transport_offset
        || original.get(context.upper_protocol_field) != Some(&context.upper_protocol)
        || mtu > u16::MAX as usize
    {
        return None;
    }
    match (context.family, context.source, context.destination) {
        (IpFamily::Ipv4, IpAddr::V4(source), IpAddr::V4(destination)) => {
            write_icmpv4_error(output, original, context, kind, mtu, source, destination)
        }
        (IpFamily::Ipv6, IpAddr::V6(source), IpAddr::V6(destination)) => {
            write_icmpv6_error(output, original, context, kind, mtu, source, destination)
        }
        _ => None,
    }
}

fn write_icmpv4_error(
    output: &mut [u8],
    original: &[u8],
    context: ControlContext,
    kind: LocalControlKind,
    mtu: usize,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> Option<usize> {
    if !ipv4_unicast(source) || !ipv4_unicast(destination) {
        return None;
    }
    let (icmp_type, code) = match kind {
        LocalControlKind::FragmentationNeeded => (3, 4),
        LocalControlKind::ProtocolUnreachable => (3, 2),
        LocalControlKind::PortUnreachable => (3, 3),
        LocalControlKind::AdministrativelyProhibited => (3, 13),
        LocalControlKind::PacketTooBig => return None,
    };
    let quote_len = original
        .len()
        .min(context.transport_offset.saturating_add(8));
    let total_len = 28_usize.checked_add(quote_len)?;
    if total_len > mtu || total_len > output.len() {
        return None;
    }
    let packet = &mut output[..total_len];
    packet.fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total_len).ok()?.to_be_bytes());
    packet[8] = 64;
    packet[9] = IP_PROTOCOL_ICMP;
    packet[12..16].copy_from_slice(&destination.octets());
    packet[16..20].copy_from_slice(&source.octets());
    packet[20] = icmp_type;
    packet[21] = code;
    if kind == LocalControlKind::FragmentationNeeded {
        packet[26..28].copy_from_slice(&u16::try_from(mtu).ok()?.to_be_bytes());
    }
    packet[28..].copy_from_slice(&original[..quote_len]);
    let icmp_checksum = internet_checksum(&[&packet[20..]]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let header_checksum = internet_checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Some(total_len)
}

fn write_icmpv6_error(
    output: &mut [u8],
    original: &[u8],
    context: ControlContext,
    kind: LocalControlKind,
    mtu: usize,
    source: Ipv6Addr,
    destination: Ipv6Addr,
) -> Option<usize> {
    if !ipv6_unicast(source) || !ipv6_unicast(destination) || mtu < 48 {
        return None;
    }
    let (icmp_type, code) = match kind {
        LocalControlKind::PacketTooBig => (2, 0),
        LocalControlKind::ProtocolUnreachable => (4, 1),
        LocalControlKind::PortUnreachable => (1, 4),
        LocalControlKind::AdministrativelyProhibited => (1, 1),
        LocalControlKind::FragmentationNeeded => return None,
    };
    let quote_len = original.len().min(mtu.saturating_sub(48));
    let total_len = 48_usize.checked_add(quote_len)?;
    if total_len > output.len() || total_len > MAX_REASSEMBLED_PACKET {
        return None;
    }
    let packet = &mut output[..total_len];
    packet.fill(0);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(total_len - 40).ok()?.to_be_bytes());
    packet[6] = IP_PROTOCOL_ICMPV6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&destination.octets());
    packet[24..40].copy_from_slice(&source.octets());
    packet[40] = icmp_type;
    packet[41] = code;
    match kind {
        LocalControlKind::PacketTooBig => {
            packet[44..48].copy_from_slice(&u32::try_from(mtu).ok()?.to_be_bytes());
        }
        LocalControlKind::ProtocolUnreachable => {
            packet[44..48].copy_from_slice(
                &u32::try_from(context.upper_protocol_field)
                    .ok()?
                    .to_be_bytes(),
            );
        }
        LocalControlKind::PortUnreachable | LocalControlKind::AdministrativelyProhibited => {}
        LocalControlKind::FragmentationNeeded => unreachable!("family checked above"),
    }
    packet[48..].copy_from_slice(&original[..quote_len]);
    let length = u32::try_from(total_len - 40).ok()?.to_be_bytes();
    let next = [0_u8, 0, 0, IP_PROTOCOL_ICMPV6];
    let checksum = internet_checksum(&[
        &packet[8..24],
        &packet[24..40],
        &length,
        &next,
        &packet[40..],
    ]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    Some(total_len)
}

pub(crate) fn ipv4_directed_broadcast(
    destination: Ipv4Addr,
    (interface, prefix): (Ipv4Addr, u8),
) -> bool {
    if prefix > 30 {
        return false;
    }
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    let broadcast = (u32::from(interface) & mask) | !mask;
    u32::from(destination) == broadcast
}
