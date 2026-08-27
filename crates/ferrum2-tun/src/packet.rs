use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod control;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) use control::{
    ControlRateLimiter, LocalControlKind, control_context, ipv4_directed_broadcast,
    oversized_ingress_control, write_local_control_error,
};

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
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
