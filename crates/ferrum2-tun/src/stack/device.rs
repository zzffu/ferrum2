use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::packet::{
    self, ControlContext, ControlRateLimiter, Families, IpFamily, LocalControlKind, PacketParser,
    ParsedIpPacket, ParsedPacket, TransportMetadata, internet_checksum as checksum,
    write_local_control_error,
};
use crate::process::map_packet_reject;
use crate::udp::{InjectOutcome as UdpInjectOutcome, UdpDatagramEndpoints};
use crate::{INGRESS_SLOTS, TunRejectReason};

#[derive(Clone, Copy)]
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct PacketValidator {
    pub(crate) mtu: usize,
    pub(crate) parser: PacketParser,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl PacketValidator {
    #[cfg(test)]
    pub(crate) const fn new(mtu: usize) -> Self {
        Self::with_families(mtu, Families::DUAL)
    }

    pub(crate) const fn with_families(mtu: usize, families: Families) -> Self {
        Self {
            mtu,
            parser: PacketParser::new(families),
        }
    }

    pub(crate) fn accepts(self, packet: &[u8]) -> bool {
        packet.len() <= self.mtu
            && matches!(self.parser.parse(packet), Ok(ParsedPacket::Complete(_)))
    }

    pub(crate) fn parse_ingress(self, packet: &[u8]) -> packet::ParseResult {
        self.parser.parse(packet)
    }

    pub(crate) fn parse_reassembled(self, packet: &[u8]) -> packet::ParseResult {
        self.parser.parse_reassembled(packet)
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[cfg(test)]
pub(crate) fn udp_datagram(
    packet: &[u8],
    mtu: usize,
) -> Option<(UdpDatagramEndpoints, &[u8], usize)> {
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL).parse(packet).ok()?
    else {
        return None;
    };
    udp_datagram_from_parsed(packet, parsed, mtu)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) fn udp_datagram_from_parsed(
    packet: &[u8],
    parsed: ParsedIpPacket,
    mtu: usize,
) -> Option<(UdpDatagramEndpoints, &[u8], usize)> {
    let TransportMetadata::Udp(udp) = parsed.transport else {
        return None;
    };
    let payload_bound = match parsed.family {
        IpFamily::Ipv4 => mtu.checked_sub(28)?,
        IpFamily::Ipv6 => mtu.checked_sub(48)?,
    };
    Some((
        UdpDatagramEndpoints::new(
            SocketAddr::new(parsed.source, udp.source_port),
            SocketAddr::new(parsed.destination, udp.destination_port),
        ),
        packet.get(udp.payload_offset..udp.payload_offset + udp.payload_len)?,
        payload_bound,
    ))
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct OutputSlot {
    pub(crate) len: usize,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct MemoryDevice {
    ingress: [PacketSlot; INGRESS_SLOTS],
    ingress_head: usize,
    pub(crate) ingress_len: usize,
    output: Box<[OutputSlot]>,
    output_head: usize,
    pub(crate) output_count: usize,
    pub(crate) validator: PacketValidator,
    pub(crate) validated_output: usize,
    pub(crate) rejected_output: usize,
    pub(crate) foundation_input: usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl MemoryDevice {
    #[cfg(test)]
    pub(crate) fn new(mtu: usize, families: Families) -> Self {
        Self::with_output_slots(mtu, families, 1)
    }

    pub(crate) fn with_output_slots(mtu: usize, families: Families, output_slots: usize) -> Self {
        assert!(output_slots != 0, "memory device needs an output slot");
        Self {
            ingress: std::array::from_fn(|_| PacketSlot {
                len: 0,
                foundation: false,
                parsed: None,
                bytes: Vec::with_capacity(mtu),
            }),
            ingress_head: 0,
            ingress_len: 0,
            output: std::iter::repeat_with(|| OutputSlot {
                len: 0,
                bytes: Vec::new(),
            })
            .take(output_slots)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
            output_head: 0,
            output_count: 0,
            validator: PacketValidator::with_families(mtu, families),
            validated_output: 0,
            rejected_output: 0,
            foundation_input: 0,
        }
    }

    pub(crate) fn enqueue_parsed(&mut self, packet: &[u8], parsed: ParsedIpPacket) -> bool {
        if self.ingress_len == INGRESS_SLOTS {
            return false;
        }
        let tail = (self.ingress_head + self.ingress_len) % INGRESS_SLOTS;
        self.ingress[tail].bytes.clear();
        self.ingress[tail].bytes.extend_from_slice(packet);
        self.ingress[tail].len = packet.len();
        self.ingress[tail].foundation = matches!(parsed.transport, TransportMetadata::Udp(_));
        self.ingress[tail].parsed = Some(parsed);
        self.ingress_len += 1;
        true
    }

    pub(crate) fn ingress_available(&self) -> usize {
        INGRESS_SLOTS - self.ingress_len
    }

    pub(crate) fn has_output(&self) -> bool {
        self.output_count != 0
    }

    fn output_tail_index(&self) -> Option<usize> {
        (self.output_count != self.output.len())
            .then(|| (self.output_head + self.output_count) % self.output.len())
    }

    fn prepare_output_slot(&mut self, index: usize) {
        let slot = &mut self.output[index];
        slot.len = 0;
        if slot.bytes.len() != self.validator.mtu {
            slot.bytes.resize(self.validator.mtu, 0);
        }
    }

    pub(crate) fn front_output(&self) -> Option<&[u8]> {
        let slot = self.output.get(self.output_head)?;
        (self.output_count != 0).then_some(&slot.bytes[..slot.len])
    }

    fn pop_output(&mut self) {
        assert!(self.output_count != 0, "output queue is not empty");
        self.output[self.output_head].len = 0;
        self.output_head = (self.output_head + 1) % self.output.len();
        self.output_count -= 1;
        if self.output_count == 0 {
            self.output_head = 0;
        }
    }

    pub(crate) fn clear_session_buffers(&mut self) {
        for slot in &mut self.ingress {
            slot.bytes.clear();
            slot.len = 0;
            slot.foundation = false;
            slot.parsed = None;
        }
        self.ingress_head = 0;
        self.ingress_len = 0;
        for slot in &mut self.output {
            slot.len = 0;
        }
        self.output_head = 0;
        self.output_count = 0;
    }

    pub(crate) fn dequeue_index(&mut self) -> Option<usize> {
        if self.ingress_len == 0 || self.output_count != 0 {
            return None;
        }
        let index = self.ingress_head;
        self.foundation_input += usize::from(self.ingress[index].foundation);
        self.ingress_head = (self.ingress_head + 1) % INGRESS_SLOTS;
        self.ingress_len -= 1;
        Some(index)
    }

    pub(crate) fn flush_output(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        let Some(packet) = self.front_output() else {
            return OutputFlushOutcome::Empty;
        };
        match send(packet) {
            OutputSendOutcome::Sent => {
                self.pop_output();
                OutputFlushOutcome::Sent
            }
            OutputSendOutcome::DroppedRingFull => {
                self.pop_output();
                OutputFlushOutcome::DroppedRingFull
            }
            OutputSendOutcome::Fatal => OutputFlushOutcome::Fatal,
        }
    }

    pub(crate) fn inject_udp_response(
        &mut self,
        endpoints: UdpDatagramEndpoints,
        payload: &[u8],
    ) -> UdpInjectOutcome {
        if self.output_count != 0 {
            return UdpInjectOutcome::Backpressured;
        }
        let index = self
            .output_tail_index()
            .expect("empty output queue has a writable slot");
        self.prepare_output_slot(index);
        let length = match write_udp_response(&mut self.output[index].bytes, endpoints, payload) {
            Ok(length) => length,
            Err(reason) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(map_packet_reject(reason));
            }
        };
        match self
            .validator
            .parse_ingress(&self.output[index].bytes[..length])
        {
            Ok(ParsedPacket::Complete(_)) => {}
            Ok(ParsedPacket::Fragment(_)) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(TunRejectReason::FragmentMalformed);
            }
            Err(rejected) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(map_packet_reject(rejected.reason));
            }
        }
        self.validated_output += 1;
        self.output[index].len = length;
        self.output_count = 1;
        UdpInjectOutcome::Injected
    }

    pub(crate) fn inject_control_error(
        &mut self,
        original: &[u8],
        context: ControlContext,
        kind: LocalControlKind,
        now_millis: i64,
        limiter: &mut ControlRateLimiter,
    ) -> bool {
        if self.output_count != 0 {
            return false;
        }
        let index = self
            .output_tail_index()
            .expect("empty output queue has a writable slot");
        self.prepare_output_slot(index);
        let Some(length) = write_local_control_error(
            &mut self.output[index].bytes,
            original,
            context,
            kind,
            self.validator.mtu,
        ) else {
            return false;
        };
        if !limiter.allow(now_millis) {
            return false;
        }
        self.output[index].len = length;
        self.output_count = 1;
        true
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) fn write_udp_response(
    output: &mut [u8],
    endpoints: UdpDatagramEndpoints,
    payload: &[u8],
) -> Result<usize, packet::PacketRejectReason> {
    let (header, source, target) = match (endpoints.target().ip(), endpoints.source().ip()) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            let length = 28_usize
                .checked_add(payload.len())
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            let packet = output
                .get_mut(..length)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            packet.fill(0);
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(
                &u16::try_from(length)
                    .map_err(|_| packet::PacketRejectReason::InvalidLength)?
                    .to_be_bytes(),
            );
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&target.octets());
            (20, IpAddr::V4(source), IpAddr::V4(target))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let udp_len = 8_usize
                .checked_add(payload.len())
                .ok_or(packet::PacketRejectReason::InvalidTransport)?;
            let length = 40_usize
                .checked_add(udp_len)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            let packet = output
                .get_mut(..length)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            packet.fill(0);
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(
                &u16::try_from(udp_len)
                    .map_err(|_| packet::PacketRejectReason::InvalidTransport)?
                    .to_be_bytes(),
            );
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&target.octets());
            (40, IpAddr::V6(source), IpAddr::V6(target))
        }
        _ => return Err(packet::PacketRejectReason::InvalidDestination),
    };
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(packet::PacketRejectReason::InvalidTransport)?;
    output[header..header + 2].copy_from_slice(&endpoints.target().port().to_be_bytes());
    output[header + 2..header + 4].copy_from_slice(&endpoints.source().port().to_be_bytes());
    output[header + 4..header + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .map_err(|_| packet::PacketRejectReason::InvalidTransport)?
            .to_be_bytes(),
    );
    output[header + 8..header + udp_len].copy_from_slice(payload);
    let length = udp_len as u32;
    let length_bytes = length.to_be_bytes();
    let next = [0_u8, 0, 0, 17];
    let udp_checksum = match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => checksum(&[
            &source.octets(),
            &target.octets(),
            &next[2..],
            &length_bytes[2..],
            &output[header..header + udp_len],
        ]),
        (IpAddr::V6(source), IpAddr::V6(target)) => checksum(&[
            &source.octets(),
            &target.octets(),
            &length_bytes,
            &next,
            &output[header..header + udp_len],
        ]),
        _ => return Err(packet::PacketRejectReason::InvalidDestination),
    };
    output[header + 6..header + 8].copy_from_slice(
        &if udp_checksum == 0 {
            u16::MAX
        } else {
            udp_checksum
        }
        .to_be_bytes(),
    );
    if header == 20 {
        let header_checksum = checksum(&[&output[..20]]);
        output[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    }
    Ok(header + udp_len)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputSendOutcome {
    Sent,
    DroppedRingFull,
    Fatal,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputFlushOutcome {
    Empty,
    Sent,
    DroppedRingFull,
    Fatal,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct PacketSlot {
    len: usize,
    foundation: bool,
    parsed: Option<ParsedIpPacket>,
    bytes: Vec<u8>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct MemoryRx<'a>(&'a PacketSlot);

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl RxToken for MemoryRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0.bytes[..self.0.len])
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) struct MemoryTx<'a> {
    pub(crate) validator: PacketValidator,
    pub(crate) validated_output: &'a mut usize,
    pub(crate) rejected_output: &'a mut usize,
    pub(crate) output: &'a mut OutputSlot,
    pub(crate) output_count: &'a mut usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl TxToken for MemoryTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(
            len <= self.output.bytes.len(),
            "stack exceeded validated MTU"
        );
        self.output.bytes[..len].fill(0);
        let result = f(&mut self.output.bytes[..len]);
        if self.validator.accepts(&self.output.bytes[..len]) {
            *self.validated_output += 1;
            self.output.len = len;
            *self.output_count += 1;
        } else {
            *self.rejected_output += 1;
            self.output.len = 0;
        }
        result
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl Device for MemoryDevice {
    type RxToken<'a> = MemoryRx<'a>;
    type TxToken<'a> = MemoryTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let index = self.dequeue_index()?;
        let output_index = self
            .output_tail_index()
            .expect("ingress starts with an empty output queue");
        self.prepare_output_slot(output_index);
        Some((
            MemoryRx(&self.ingress[index]),
            MemoryTx {
                validator: self.validator,
                validated_output: &mut self.validated_output,
                rejected_output: &mut self.rejected_output,
                output: &mut self.output[output_index],
                output_count: &mut self.output_count,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let output_index = self.output_tail_index()?;
        self.prepare_output_slot(output_index);
        Some(MemoryTx {
            validator: self.validator,
            validated_output: &mut self.validated_output,
            rejected_output: &mut self.rejected_output,
            output: &mut self.output[output_index],
            output_count: &mut self.output_count,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.validator.mtu;
        capabilities
    }
}
