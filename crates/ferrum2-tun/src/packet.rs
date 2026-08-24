use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const IP_PROTOCOL_TCP: u8 = 6;
pub(crate) const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_ESP: u8 = 50;
const IPV6_AH: u8 = 51;
const IPV6_NO_NEXT_HEADER: u8 = 59;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const MAX_EXTENSION_HEADERS: usize = 8;
const MAX_EXTENSION_BYTES: usize = 512;
pub(crate) const MAX_REASSEMBLED_PACKET: usize = 65_535;
pub(crate) const CONTROL_ERROR_INTERVAL_MILLIS: i64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Families {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
}

impl Families {
    #[cfg(test)]
    pub(crate) const DUAL: Self = Self {
        ipv4: true,
        ipv6: true,
    };

    #[cfg(test)]
    pub(crate) const IPV4_ONLY: Self = Self {
        ipv4: true,
        ipv6: false,
    };

    #[cfg(test)]
    pub(crate) const IPV6_ONLY: Self = Self {
        ipv4: false,
        ipv6: true,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalControlKind {
    FragmentationNeeded,
    PacketTooBig,
    ProtocolUnreachable,
    PortUnreachable,
    AdministrativelyProhibited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlContext {
    family: IpFamily,
    source: IpAddr,
    destination: IpAddr,
    upper_protocol: u8,
    upper_protocol_field: usize,
    transport_offset: usize,
    total_len: usize,
    suppress_reply: bool,
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Ipv4FragmentKey {
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: Ipv4Addr,
    pub(crate) protocol: u8,
    pub(crate) identification: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Ipv6FragmentKey {
    pub(crate) source: Ipv6Addr,
    pub(crate) destination: Ipv6Addr,
    pub(crate) next_header: u8,
    pub(crate) identification: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FragmentKey {
    Ipv4(Ipv4FragmentKey),
    Ipv6(Ipv6FragmentKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FragmentReconstruction {
    Ipv4 {
        header_len: usize,
    },
    Ipv6 {
        fragment_header_offset: usize,
        previous_next_header_offset: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedFragment {
    pub(crate) family: IpFamily,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) upper_protocol: u8,
    pub(crate) key: FragmentKey,
    pub(crate) offset: usize,
    pub(crate) more_fragments: bool,
    pub(crate) payload_offset: usize,
    pub(crate) payload_len: usize,
    pub(crate) reconstruction: FragmentReconstruction,
}

impl ParsedFragment {
    pub(crate) fn is_atomic(self) -> bool {
        self.family == IpFamily::Ipv6 && self.offset == 0 && !self.more_fragments
    }

    pub(crate) fn identity_matches_key(self) -> bool {
        match (self.key, self.source, self.destination, self.family) {
            (
                FragmentKey::Ipv4(key),
                IpAddr::V4(source),
                IpAddr::V4(destination),
                IpFamily::Ipv4,
            ) => {
                key.source == source
                    && key.destination == destination
                    && key.protocol == self.upper_protocol
            }
            (
                FragmentKey::Ipv6(key),
                IpAddr::V6(source),
                IpAddr::V6(destination),
                IpFamily::Ipv6,
            ) => {
                key.source == source
                    && key.destination == destination
                    && key.next_header == self.upper_protocol
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TcpMetadata {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) header_len: usize,
    pub(crate) flags: u8,
}

impl TcpMetadata {
    pub(crate) const fn is_initial_syn(self) -> bool {
        self.flags & 0x17 == 0x02
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpMetadata {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) payload_offset: usize,
    pub(crate) payload_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportMetadata {
    Tcp(TcpMetadata),
    Udp(UdpMetadata),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedIpPacket {
    pub(crate) family: IpFamily,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) upper_protocol: u8,
    pub(crate) upper_protocol_field: usize,
    pub(crate) transport_offset: usize,
    pub(crate) total_len: usize,
    pub(crate) transport: TransportMetadata,
}

impl ParsedIpPacket {
    pub(crate) fn metadata_matches(self, packet_len: usize) -> bool {
        let address_family_matches = matches!(
            (self.family, self.source, self.destination),
            (IpFamily::Ipv4, IpAddr::V4(_), IpAddr::V4(_))
                | (IpFamily::Ipv6, IpAddr::V6(_), IpAddr::V6(_))
        );
        let transport_matches = match self.transport {
            TransportMetadata::Tcp(tcp) => {
                self.upper_protocol == IP_PROTOCOL_TCP
                    && self
                        .transport_offset
                        .checked_add(tcp.header_len)
                        .is_some_and(|end| end <= self.total_len)
            }
            TransportMetadata::Udp(udp) => {
                self.upper_protocol == IP_PROTOCOL_UDP
                    && udp.payload_offset == self.transport_offset + 8
                    && udp
                        .payload_offset
                        .checked_add(udp.payload_len)
                        .is_some_and(|end| end == self.total_len)
            }
        };
        address_family_matches
            && transport_matches
            && self.upper_protocol_field < self.transport_offset
            && self.total_len == packet_len
    }

    pub(crate) const fn control_context(self) -> ControlContext {
        ControlContext {
            family: self.family,
            source: self.source,
            destination: self.destination,
            upper_protocol: self.upper_protocol,
            upper_protocol_field: self.upper_protocol_field,
            transport_offset: self.transport_offset,
            total_len: self.total_len,
            suppress_reply: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParsedPacket {
    Complete(ParsedIpPacket),
    Fragment(ParsedFragment),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketRejectReason {
    Empty,
    DisabledFamily,
    InvalidVersion,
    InvalidLength,
    InvalidHeaderChecksum,
    InvalidSource,
    InvalidDestination,
    InvalidIpv4Options,
    SourceRouteOption,
    InvalidFragment,
    ExtensionLimit,
    MalformedExtension,
    UnsupportedProtocol,
    IcmpEchoUnsupported,
    JumbogramUnsupported,
    InvalidTransport,
    InvalidTransportChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketReject {
    pub(crate) reason: PacketRejectReason,
    pub(crate) fragment_key: Option<FragmentKey>,
    pub(crate) control: Option<ControlContext>,
}

impl PacketReject {
    const fn new(reason: PacketRejectReason) -> Self {
        Self {
            reason,
            fragment_key: None,
            control: None,
        }
    }

    const fn fragment(reason: PacketRejectReason, key: FragmentKey) -> Self {
        Self {
            reason,
            fragment_key: Some(key),
            control: None,
        }
    }

    const fn control(reason: PacketRejectReason, control: ControlContext) -> Self {
        Self {
            reason,
            fragment_key: None,
            control: Some(control),
        }
    }
}

pub(crate) type ParseResult = Result<ParsedPacket, PacketReject>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketParser {
    families: Families,
}

impl PacketParser {
    pub(crate) const fn new(families: Families) -> Self {
        Self { families }
    }

    pub(crate) fn parse(self, bytes: &[u8]) -> ParseResult {
        self.parse_with_fragments(bytes, true)
    }

    pub(crate) fn parse_reassembled(self, bytes: &[u8]) -> ParseResult {
        self.parse_with_fragments(bytes, false)
    }

    fn parse_with_fragments(self, bytes: &[u8], fragments_allowed: bool) -> ParseResult {
        let Some(version) = bytes.first().map(|byte| byte >> 4) else {
            return Err(PacketReject::new(PacketRejectReason::Empty));
        };
        match version {
            4 if self.families.ipv4 => self.parse_ipv4(bytes, fragments_allowed),
            6 if self.families.ipv6 => self.parse_ipv6(bytes, fragments_allowed),
            4 | 6 => Err(PacketReject::new(PacketRejectReason::DisabledFamily)),
            _ => Err(PacketReject::new(PacketRejectReason::InvalidVersion)),
        }
    }

    fn parse_ipv4(self, bytes: &[u8], fragments_allowed: bool) -> ParseResult {
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        }
        let ihl_words = usize::from(bytes[0] & 0x0f);
        if !(5..=15).contains(&ihl_words) {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        }
        let header_len = ihl_words * 4;
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if header_len > bytes.len() || total_len != bytes.len() || total_len < header_len {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        }
        if internet_checksum(&[&bytes[..header_len]]) != 0 {
            return Err(PacketReject::new(PacketRejectReason::InvalidHeaderChecksum));
        }
        validate_ipv4_options(&bytes[20..header_len]).map_err(PacketReject::new)?;

        let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        if !ipv4_unicast(source) {
            return Err(PacketReject::new(PacketRejectReason::InvalidSource));
        }
        if !ipv4_unicast(destination) {
            return Err(PacketReject::new(PacketRejectReason::InvalidDestination));
        }
        let protocol = bytes[9];
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
        let key = FragmentKey::Ipv4(Ipv4FragmentKey {
            source,
            destination,
            protocol,
            identification,
        });
        let fragment_field = u16::from_be_bytes([bytes[6], bytes[7]]);
        let reserved = fragment_field & 0x8000 != 0;
        let dont_fragment = fragment_field & 0x4000 != 0;
        let more_fragments = fragment_field & 0x2000 != 0;
        let offset = usize::from(fragment_field & 0x1fff) * 8;
        let fragmented = more_fragments || offset != 0;
        if reserved || (dont_fragment && fragmented) {
            return Err(PacketReject::fragment(
                PacketRejectReason::InvalidFragment,
                key,
            ));
        }
        if fragmented {
            if !fragments_allowed || !matches!(protocol, IP_PROTOCOL_TCP | IP_PROTOCOL_UDP) {
                return Err(PacketReject::fragment(
                    PacketRejectReason::UnsupportedProtocol,
                    key,
                ));
            }
            let payload_len = total_len - header_len;
            if payload_len == 0 || (more_fragments && !payload_len.is_multiple_of(8)) {
                return Err(PacketReject::fragment(
                    PacketRejectReason::InvalidFragment,
                    key,
                ));
            }
            let Some(end) = offset.checked_add(payload_len) else {
                return Err(PacketReject::fragment(
                    PacketRejectReason::InvalidFragment,
                    key,
                ));
            };
            if end > MAX_REASSEMBLED_PACKET.saturating_sub(header_len) {
                return Err(PacketReject::fragment(
                    PacketRejectReason::InvalidFragment,
                    key,
                ));
            }
            return Ok(ParsedPacket::Fragment(ParsedFragment {
                family: IpFamily::Ipv4,
                source: IpAddr::V4(source),
                destination: IpAddr::V4(destination),
                upper_protocol: protocol,
                key,
                offset,
                more_fragments,
                payload_offset: header_len,
                payload_len,
                reconstruction: FragmentReconstruction::Ipv4 { header_len },
            }));
        }

        if !matches!(protocol, IP_PROTOCOL_TCP | IP_PROTOCOL_UDP) {
            return Err(unsupported_reject(
                ControlContext {
                    family: IpFamily::Ipv4,
                    source: IpAddr::V4(source),
                    destination: IpAddr::V4(destination),
                    upper_protocol: protocol,
                    upper_protocol_field: 9,
                    transport_offset: header_len,
                    total_len,
                    suppress_reply: false,
                },
                &bytes[header_len..],
            ));
        }

        let transport = validate_transport(
            IpAddr::V4(source),
            IpAddr::V4(destination),
            protocol,
            header_len,
            &bytes[header_len..],
        )?;
        Ok(ParsedPacket::Complete(ParsedIpPacket {
            family: IpFamily::Ipv4,
            source: IpAddr::V4(source),
            destination: IpAddr::V4(destination),
            upper_protocol: protocol,
            upper_protocol_field: 9,
            transport_offset: header_len,
            total_len,
            transport,
        }))
    }

    fn parse_ipv6(self, bytes: &[u8], fragments_allowed: bool) -> ParseResult {
        if bytes.len() < 40 || bytes[0] >> 4 != 6 {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        }
        let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if payload_len == 0 {
            return Err(PacketReject::new(PacketRejectReason::JumbogramUnsupported));
        }
        let Some(total_len) = 40_usize.checked_add(payload_len) else {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        };
        if total_len != bytes.len() || total_len > MAX_REASSEMBLED_PACKET {
            return Err(PacketReject::new(PacketRejectReason::InvalidLength));
        }
        let source =
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("fixed IPv6 source slice"));
        let destination = Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[24..40]).expect("fixed IPv6 destination slice"),
        );
        if !ipv6_unicast(source) {
            return Err(PacketReject::new(PacketRejectReason::InvalidSource));
        }
        if !ipv6_unicast(destination) {
            return Err(PacketReject::new(PacketRejectReason::InvalidDestination));
        }

        let mut next_header = bytes[6];
        let mut next_header_field = 6;
        let mut cursor = 40_usize;
        let mut extension_headers = 0_usize;
        let mut extension_bytes = 0_usize;
        let mut seen_hop_by_hop = false;
        let mut seen_routing = false;
        let mut destination_headers = 0_usize;
        let mut destination_after_routing = false;

        loop {
            match next_header {
                IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS => {
                    if extension_headers == MAX_EXTENSION_HEADERS {
                        return Err(PacketReject::new(PacketRejectReason::ExtensionLimit));
                    }
                    if cursor.checked_add(2).is_none_or(|end| end > total_len) {
                        return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                    }
                    if next_header == IPV6_HOP_BY_HOP {
                        if seen_hop_by_hop || cursor != 40 {
                            return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                        }
                        seen_hop_by_hop = true;
                    } else if next_header == IPV6_ROUTING {
                        if seen_routing || destination_after_routing {
                            return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                        }
                        seen_routing = true;
                    } else {
                        destination_headers += 1;
                        if destination_headers > 2 {
                            return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                        }
                        destination_after_routing |= seen_routing;
                    }
                    let length = (usize::from(bytes[cursor + 1]) + 1)
                        .checked_mul(8)
                        .ok_or_else(|| PacketReject::new(PacketRejectReason::MalformedExtension))?;
                    let Some(extension_end) = cursor.checked_add(length) else {
                        return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                    };
                    if length < 8
                        || extension_end > total_len
                        || extension_bytes
                            .checked_add(length)
                            .is_none_or(|total| total > MAX_EXTENSION_BYTES)
                    {
                        return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                    }
                    if matches!(next_header, IPV6_HOP_BY_HOP | IPV6_DESTINATION_OPTIONS) {
                        validate_ipv6_options(&bytes[cursor + 2..extension_end])
                            .map_err(PacketReject::new)?;
                    }
                    if next_header == IPV6_ROUTING && bytes[cursor + 3] != 0 {
                        return Err(PacketReject::new(PacketRejectReason::MalformedExtension));
                    }
                    extension_headers += 1;
                    extension_bytes += length;
                    next_header_field = cursor;
                    next_header = bytes[cursor];
                    cursor = extension_end;
                }
                IPV6_FRAGMENT => {
                    if extension_headers == MAX_EXTENSION_HEADERS
                        || destination_after_routing
                        || cursor.checked_add(8).is_none_or(|end| end > total_len)
                    {
                        return Err(PacketReject::new(PacketRejectReason::ExtensionLimit));
                    }
                    extension_bytes += 8;
                    if extension_bytes > MAX_EXTENSION_BYTES {
                        return Err(PacketReject::new(PacketRejectReason::ExtensionLimit));
                    }
                    let fragment_next = bytes[cursor];
                    let identification = u32::from_be_bytes(
                        bytes[cursor + 4..cursor + 8]
                            .try_into()
                            .expect("fixed fragment identifier slice"),
                    );
                    let key = FragmentKey::Ipv6(Ipv6FragmentKey {
                        source,
                        destination,
                        next_header: fragment_next,
                        identification,
                    });
                    if !fragments_allowed
                        || fragment_next == IPV6_FRAGMENT
                        || matches!(fragment_next, IPV6_ESP | IPV6_AH | IPV6_NO_NEXT_HEADER)
                    {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::UnsupportedProtocol,
                            key,
                        ));
                    }
                    if bytes[cursor + 1] != 0 {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::InvalidFragment,
                            key,
                        ));
                    }
                    let offset_flags = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
                    if offset_flags & 0x0006 != 0 {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::InvalidFragment,
                            key,
                        ));
                    }
                    let offset = usize::from((offset_flags & 0xfff8) >> 3) * 8;
                    let more_fragments = offset_flags & 1 != 0;
                    let payload_offset = cursor + 8;
                    let fragment_payload_len = total_len - payload_offset;
                    if fragment_payload_len == 0
                        || (more_fragments && !fragment_payload_len.is_multiple_of(8))
                    {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::InvalidFragment,
                            key,
                        ));
                    }
                    let Some(end) = offset.checked_add(fragment_payload_len) else {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::InvalidFragment,
                            key,
                        ));
                    };
                    if end > MAX_REASSEMBLED_PACKET {
                        return Err(PacketReject::fragment(
                            PacketRejectReason::InvalidFragment,
                            key,
                        ));
                    }
                    return Ok(ParsedPacket::Fragment(ParsedFragment {
                        family: IpFamily::Ipv6,
                        source: IpAddr::V6(source),
                        destination: IpAddr::V6(destination),
                        upper_protocol: fragment_next,
                        key,
                        offset,
                        more_fragments,
                        payload_offset,
                        payload_len: fragment_payload_len,
                        reconstruction: FragmentReconstruction::Ipv6 {
                            fragment_header_offset: cursor,
                            previous_next_header_offset: next_header_field,
                        },
                    }));
                }
                IP_PROTOCOL_TCP | IP_PROTOCOL_UDP => break,
                _ => {
                    return Err(unsupported_reject(
                        ControlContext {
                            family: IpFamily::Ipv6,
                            source: IpAddr::V6(source),
                            destination: IpAddr::V6(destination),
                            upper_protocol: next_header,
                            upper_protocol_field: next_header_field,
                            transport_offset: cursor,
                            total_len,
                            suppress_reply: false,
                        },
                        &bytes[cursor..],
                    ));
                }
            }
        }

        let transport = validate_transport(
            IpAddr::V6(source),
            IpAddr::V6(destination),
            next_header,
            cursor,
            &bytes[cursor..],
        )?;
        Ok(ParsedPacket::Complete(ParsedIpPacket {
            family: IpFamily::Ipv6,
            source: IpAddr::V6(source),
            destination: IpAddr::V6(destination),
            upper_protocol: next_header,
            upper_protocol_field: next_header_field,
            transport_offset: cursor,
            total_len,
            transport,
        }))
    }
}

fn unsupported_reject(mut context: ControlContext, transport: &[u8]) -> PacketReject {
    let icmp = matches!(
        (context.family, context.upper_protocol),
        (IpFamily::Ipv4, IP_PROTOCOL_ICMP) | (IpFamily::Ipv6, IP_PROTOCOL_ICMPV6)
    );
    let echo = matches!(
        (context.family, transport.first().copied()),
        (IpFamily::Ipv4, Some(8)) | (IpFamily::Ipv6, Some(128))
    );
    let no_payload =
        context.family == IpFamily::Ipv6 && context.upper_protocol == IPV6_NO_NEXT_HEADER;
    context.suppress_reply = icmp || no_payload;
    PacketReject::control(
        if echo {
            PacketRejectReason::IcmpEchoUnsupported
        } else {
            PacketRejectReason::UnsupportedProtocol
        },
        context,
    )
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
    Some((parsed.control_context(), kind))
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

fn validate_ipv4_options(options: &[u8]) -> Result<(), PacketRejectReason> {
    let mut cursor = 0;
    while cursor < options.len() {
        match options[cursor] {
            0 => {
                if options[cursor + 1..].iter().any(|byte| *byte != 0) {
                    return Err(PacketRejectReason::InvalidIpv4Options);
                }
                return Ok(());
            }
            1 => cursor += 1,
            option_type => {
                let Some(length) = options.get(cursor + 1).copied().map(usize::from) else {
                    return Err(PacketRejectReason::InvalidIpv4Options);
                };
                if length < 2
                    || cursor
                        .checked_add(length)
                        .is_none_or(|end| end > options.len())
                {
                    return Err(PacketRejectReason::InvalidIpv4Options);
                }
                if matches!(option_type, 131 | 137) {
                    return Err(PacketRejectReason::SourceRouteOption);
                }
                cursor += length;
            }
        }
    }
    Ok(())
}

fn validate_ipv6_options(options: &[u8]) -> Result<(), PacketRejectReason> {
    let mut cursor = 0_usize;
    while cursor < options.len() {
        let option_type = options[cursor];
        if option_type == 0 {
            cursor += 1;
            continue;
        }
        let Some(data_len) = options.get(cursor + 1).copied().map(usize::from) else {
            return Err(PacketRejectReason::MalformedExtension);
        };
        let Some(option_end) = cursor
            .checked_add(2)
            .and_then(|header_end| header_end.checked_add(data_len))
        else {
            return Err(PacketRejectReason::MalformedExtension);
        };
        if option_end > options.len() {
            return Err(PacketRejectReason::MalformedExtension);
        }
        // ICMP Parameter Problem responses are not emitted here, so unsupported
        // IPv6 option discard actions fail closed instead of reaching transport.
        if option_type & 0b1100_0000 != 0 {
            return Err(PacketRejectReason::MalformedExtension);
        }
        cursor = option_end;
    }
    Ok(())
}

fn validate_transport(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport_offset: usize,
    transport: &[u8],
) -> Result<TransportMetadata, PacketReject> {
    if transport.len() < 8 {
        return Err(PacketReject::new(PacketRejectReason::InvalidTransport));
    }
    let source_port = u16::from_be_bytes([transport[0], transport[1]]);
    let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
    if source_port == 0 || destination_port == 0 {
        return Err(PacketReject::new(PacketRejectReason::InvalidTransport));
    }
    let metadata = match protocol {
        IP_PROTOCOL_TCP => {
            if transport.len() < 20 {
                return Err(PacketReject::new(PacketRejectReason::InvalidTransport));
            }
            let header_len = usize::from(transport[12] >> 4) * 4;
            if header_len < 20 || header_len > transport.len() {
                return Err(PacketReject::new(PacketRejectReason::InvalidTransport));
            }
            validate_tcp_options(&transport[20..header_len]).map_err(PacketReject::new)?;
            TransportMetadata::Tcp(TcpMetadata {
                source_port,
                destination_port,
                header_len,
                flags: transport[13],
            })
        }
        IP_PROTOCOL_UDP => {
            let udp_len = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
            if udp_len < 8 || udp_len != transport.len() {
                return Err(PacketReject::new(PacketRejectReason::InvalidTransport));
            }
            TransportMetadata::Udp(UdpMetadata {
                source_port,
                destination_port,
                payload_offset: transport_offset + 8,
                payload_len: udp_len - 8,
            })
        }
        _ => {
            return Err(PacketReject::new(PacketRejectReason::UnsupportedProtocol));
        }
    };

    let checksum_field = match protocol {
        IP_PROTOCOL_TCP => [transport[16], transport[17]],
        IP_PROTOCOL_UDP => [transport[6], transport[7]],
        _ => unreachable!("transport protocol was closed above"),
    };
    // An all-zero field means "checksum omitted" only for IPv4 UDP. TCP still
    // validates the complete sum because its computed checksum may legitimately be zero.
    if protocol == IP_PROTOCOL_UDP && checksum_field == [0, 0] {
        if source.is_ipv4() {
            return Ok(metadata);
        }
        return Err(PacketReject::new(
            PacketRejectReason::InvalidTransportChecksum,
        ));
    }
    if transport_checksum(source, destination, protocol, transport) != 0 {
        return Err(PacketReject::new(
            PacketRejectReason::InvalidTransportChecksum,
        ));
    }
    Ok(metadata)
}

fn validate_tcp_options(options: &[u8]) -> Result<(), PacketRejectReason> {
    let mut cursor = 0;
    while cursor < options.len() {
        match options[cursor] {
            0 => {
                if options[cursor + 1..].iter().any(|byte| *byte != 0) {
                    return Err(PacketRejectReason::InvalidTransport);
                }
                return Ok(());
            }
            1 => cursor += 1,
            _ => {
                let Some(length) = options.get(cursor + 1).copied().map(usize::from) else {
                    return Err(PacketRejectReason::InvalidTransport);
                };
                if length < 2
                    || cursor
                        .checked_add(length)
                        .is_none_or(|end| end > options.len())
                {
                    return Err(PacketRejectReason::InvalidTransport);
                }
                cursor += length;
            }
        }
    }
    Ok(())
}

fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, transport: &[u8]) -> u16 {
    let length = u32::try_from(transport.len()).expect("IP packet bounds fit u32");
    let length_bytes = length.to_be_bytes();
    let next = [0_u8, 0, 0, protocol];
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => internet_checksum(&[
            &source.octets(),
            &destination.octets(),
            &next[2..],
            &length_bytes[2..],
            transport,
        ]),
        (IpAddr::V6(source), IpAddr::V6(destination)) => internet_checksum(&[
            &source.octets(),
            &destination.octets(),
            &length_bytes,
            &next,
            transport,
        ]),
        _ => u16::MAX,
    }
}

pub(crate) fn ipv4_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
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

pub(crate) fn ipv6_unicast(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast()
}

pub(crate) fn internet_checksum(parts: &[&[u8]]) -> u16 {
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

#[cfg(test)]
pub(crate) mod test_support {
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
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::test_support::{
        ipv4_tcp_with_options, ipv4_tcp_zero_checksum, ipv4_udp, ipv6_udp, repair_ipv4_header,
        repair_transport_checksum,
    };
    use super::{
        CONTROL_ERROR_INTERVAL_MILLIS, ControlRateLimiter, Families, IpFamily, LocalControlKind,
        PacketParser, PacketRejectReason, ParsedPacket, TransportMetadata, internet_checksum,
        ipv4_directed_broadcast, oversized_ingress_control, write_local_control_error,
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
                let packet =
                    ipv6_udp_with_options_header(header_type, &[option_type, 0, 0, 0, 0, 0]);
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
        ipv6_destination[24..40]
            .copy_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets());
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
        let (context, kind) =
            oversized_ingress_control(&ipv6, parsed, mtu).expect("IPv6 requires PTB");
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
            parsed.control_context(),
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
            parsed.control_context(),
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
}
