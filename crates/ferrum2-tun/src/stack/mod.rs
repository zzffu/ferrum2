mod device;
mod tcp;
mod udp;

pub(crate) use device::{MemoryDevice, OutputFlushOutcome, OutputSendOutcome};
#[cfg(test)]
pub(crate) use device::{MemoryTx, OutputSlot, PacketValidator, udp_datagram};
use tcp::initial_tcp_tuple;
pub(crate) use tcp::{TcpFlowEntry, TcpTuple};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use ferrum2_runtime::OwnerRegistry;
use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, Route, SocketSet,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

#[cfg(test)]
use crate::PACKET_QUANTUM;
use crate::packet::map_packet_reject;
use crate::packet::{
    ControlContext, ControlRateLimiter, Families, LocalControlKind, PacketRejectReason,
    ParsedIpPacket, ParsedPacket, control_context, ipv4_directed_broadcast,
    oversized_ingress_control,
};
use crate::reassembly::{ReassemblyDropReason, ReassemblyOutcome, ReassemblyTable};
use crate::udp::{Admission as UdpAdmission, GenerationId, GenerationTable, UdpTable};
use crate::{
    INGRESS_SLOTS, OwnerWake, TcpFlow, TunEvent, TunEventSink, TunRejectReason, UdpCandidate,
    UdpFiltering, UdpResponseDropReason,
};
use device::udp_datagram_from_parsed;

pub(crate) struct Stack {
    pub(crate) interface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) device: MemoryDevice,
    pub(crate) ipv4_interface: Option<(Ipv4Addr, u8)>,
    pub(crate) foundation_dropped: usize,
    pub(crate) flows: Box<[Option<TcpFlowEntry>]>,
    pub(crate) flow_index: HashMap<TcpTuple, GenerationId>,
    pub(crate) free_flow_slots: Vec<usize>,
    pub(crate) active_flow_head: Option<usize>,
    pub(crate) active_flow_tail: Option<usize>,
    pub(crate) live_tcp_flow_count: usize,
    pub(crate) generations: GenerationTable,
    pub(crate) tcp_buffer_bytes: usize,
    pub(crate) tcp_timeout_millis: u64,
    pub(crate) bridge_capacity: usize,
    pub(crate) next_flow_cursor: Option<usize>,
    pub(crate) next_reap_cursor: Option<usize>,
    pub(crate) packet_generation: u64,
    pub(crate) reassembly: ReassemblyTable,
    pub(crate) control_limiter: ControlRateLimiter,
    pub(crate) flow_sender: tokio::sync::mpsc::Sender<TcpFlow>,
    pub(crate) flow_count: Arc<AtomicUsize>,
    pub(crate) registry: OwnerRegistry,
    pub(crate) udp: UdpTable,
    pub(crate) owner_wake: OwnerWake,
    pub(crate) events: TunEventSink,
}

pub(crate) type StackReady = (
    Stack,
    tokio::sync::mpsc::Receiver<TcpFlow>,
    tokio::sync::mpsc::Receiver<UdpCandidate>,
);

pub(crate) type InterfaceAddresses = (Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StackPollOutcome {
    pub(crate) worked: bool,
    pub(crate) foundation_dropped: usize,
}

impl Stack {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_udp(
        addresses: InterfaceAddresses,
        mtu: usize,
        max_tcp_flows: usize,
        tcp_buffer_bytes: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
        registry: OwnerRegistry,
        max_udp_associations: usize,
        udp_timeout: Duration,
        udp_filtering: UdpFiltering,
        session_generation: u64,
        owner_wake: OwnerWake,
    ) -> Result<StackReady, ()> {
        let (ipv4, ipv6) = addresses;
        let families = Families {
            ipv4: ipv4.is_some(),
            ipv6: ipv6.is_some(),
        };
        if !families.ipv4 && !families.ipv6 {
            return Err(());
        }
        let output_slots = max_tcp_flows.checked_add(1).ok_or(())?;
        let mut device = MemoryDevice::with_output_slots(mtu, families, output_slots);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            if let Some((address, prefix)) = ipv4 {
                addresses
                    .push(IpCidr::new(IpAddress::from(IpAddr::V4(address)), prefix))
                    .expect("validated address capacity");
            }
            if let Some((address, prefix)) = ipv6 {
                addresses
                    .push(IpCidr::new(IpAddress::from(IpAddr::V6(address)), prefix))
                    .expect("validated address capacity");
            }
        });
        interface.set_any_ip(true);
        if let Some((address, _)) = ipv4 {
            interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(address.octets()))
                .map_err(|_| ())?;
        }
        if let Some((address, _)) = ipv6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::from(address.octets()))
                .map_err(|_| ())?;
        }
        if let (Some((ipv4, _)), Some(_)) = (ipv4, ipv6) {
            let mut third_rejected = false;
            interface.routes_mut().update(|routes| {
                third_rejected = routes.push(Route::new_ipv4_gateway(ipv4)).is_err();
            });
            if !third_rejected {
                return Err(());
            }
        }
        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(max_tcp_flows);
        let (udp, datagrams) = UdpTable::with_options(
            max_udp_associations,
            udp_timeout,
            udp_filtering,
            session_generation,
            owner_wake.clone(),
        );
        let tcp_timeout_millis = u64::try_from(tcp_timeout.as_millis()).map_err(|_| ())?;
        Ok((
            Self {
                interface,
                sockets: SocketSet::new(Vec::with_capacity(max_tcp_flows)),
                device,
                ipv4_interface: ipv4,
                foundation_dropped: 0,
                flows: std::iter::repeat_with(|| None)
                    .take(max_tcp_flows)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                flow_index: HashMap::with_capacity(max_tcp_flows),
                free_flow_slots: (0..max_tcp_flows).rev().collect(),
                active_flow_head: None,
                active_flow_tail: None,
                live_tcp_flow_count: 0,
                generations: GenerationTable::new(max_tcp_flows),
                tcp_buffer_bytes,
                tcp_timeout_millis,
                bridge_capacity: tcp_buffer_bytes,
                next_flow_cursor: None,
                next_reap_cursor: None,
                packet_generation: 0,
                reassembly: ReassemblyTable::new(0),
                control_limiter: ControlRateLimiter::new(),
                flow_sender,
                flow_count,
                registry,
                udp,
                owner_wake,
                events: TunEventSink::default(),
            },
            flow_receiver,
            datagrams,
        ))
    }

    pub(crate) fn set_event_sink(&mut self, events: TunEventSink) {
        self.udp.set_event_sink(events.clone());
        self.events = events;
    }

    pub(crate) fn enqueue_at(&mut self, packet: &[u8], admitting: bool, now_millis: i64) -> bool {
        let parsed = match self.device.validator.parse_ingress(packet) {
            Ok(ParsedPacket::Complete(parsed)) => {
                if self.is_ipv4_directed_broadcast(parsed.destination) {
                    self.reject(TunRejectReason::InvalidDestination);
                    return false;
                }
                parsed
            }
            Ok(ParsedPacket::Fragment(fragment)) => {
                if self.is_ipv4_directed_broadcast(fragment.destination) {
                    self.reject(TunRejectReason::InvalidDestination);
                    return false;
                }
                if packet.len() > self.device.validator.mtu {
                    if self.reassembly.drop_key(fragment.key) {
                        self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                        self.events
                            .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
                    }
                    self.reject(TunRejectReason::FragmentMalformed);
                    return false;
                }
                let before = self.reassembly.len();
                let accepted =
                    self.reassembly
                        .accept(packet, fragment, now_millis, self.packet_generation);
                let after = self.reassembly.len();
                self.record_reassembly_timeouts(accepted.expired);
                let live_before = before.saturating_sub(accepted.expired);
                for _ in live_before..after {
                    self.events.emit(TunEvent::ReassemblyStarted);
                }
                if accepted.expired != 0 || after != before {
                    self.events.emit(TunEvent::ReassemblyEntriesActive(after));
                }
                match accepted.outcome {
                    ReassemblyOutcome::Pending => return true,
                    ReassemblyOutcome::Dropped(reason) => {
                        let reject = match reason {
                            ReassemblyDropReason::Malformed => {
                                self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                                TunRejectReason::FragmentMalformed
                            }
                            ReassemblyDropReason::Overlap => {
                                self.events.emit(TunEvent::ReassemblyDroppedOverlap);
                                TunRejectReason::FragmentOverlap
                            }
                            ReassemblyDropReason::Limit => {
                                self.events.emit(TunEvent::ReassemblyDroppedLimit);
                                TunRejectReason::FragmentLimit
                            }
                        };
                        self.reject(reject);
                        return false;
                    }
                    ReassemblyOutcome::Atomic(normalized) => {
                        let Ok(ParsedPacket::Complete(parsed)) =
                            self.device.validator.parse_reassembled(&normalized)
                        else {
                            self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                            self.reject(TunRejectReason::FragmentMalformed);
                            return false;
                        };
                        return self.enqueue_complete(
                            &normalized,
                            parsed,
                            admitting,
                            now_millis,
                            false,
                        );
                    }
                    ReassemblyOutcome::Complete(reassembled) => {
                        self.events.emit(TunEvent::ReassemblyCompleted);
                        let Ok(ParsedPacket::Complete(parsed)) =
                            self.device.validator.parse_reassembled(&reassembled)
                        else {
                            self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                            self.reject(TunRejectReason::FragmentMalformed);
                            return false;
                        };
                        return self.enqueue_complete(
                            &reassembled,
                            parsed,
                            admitting,
                            now_millis,
                            true,
                        );
                    }
                }
            }
            Err(rejected) => {
                self.reject(map_packet_reject(rejected.reason));
                if let Some(key) = rejected.fragment_key
                    && self.reassembly.drop_key(key)
                {
                    self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                    self.events
                        .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
                }
                if rejected.reason == PacketRejectReason::UnsupportedProtocol
                    && let Some(context) = rejected.control
                {
                    self.emit_local_control(
                        packet,
                        context,
                        LocalControlKind::ProtocolUnreachable,
                        now_millis,
                    );
                }
                return false;
            }
        };
        self.enqueue_complete(packet, parsed, admitting, now_millis, false)
    }

    pub(crate) fn is_ipv4_directed_broadcast(&self, destination: IpAddr) -> bool {
        matches!(
            (destination, self.ipv4_interface),
            (IpAddr::V4(destination), Some(interface))
                if ipv4_directed_broadcast(destination, interface)
        )
    }

    pub(crate) fn enqueue_complete(
        &mut self,
        packet: &[u8],
        parsed: ParsedIpPacket,
        admitting: bool,
        now_millis: i64,
        reassembled: bool,
    ) -> bool {
        if !parsed.metadata_matches(packet.len()) {
            self.reject(TunRejectReason::InvalidIpLength);
            return false;
        }
        if !reassembled && packet.len() > self.device.validator.mtu {
            if let Some((context, kind)) =
                oversized_ingress_control(packet, parsed, self.device.validator.mtu)
            {
                self.emit_local_control(packet, context, kind, now_millis);
            }
            self.reject(TunRejectReason::InvalidIpLength);
            return false;
        }
        if let Some((tuple, payload, payload_bound)) =
            udp_datagram_from_parsed(packet, parsed, self.device.validator.mtu)
        {
            let admitted = if reassembled {
                self.udp
                    .admit_reassembled(tuple, payload, payload_bound, now_millis, admitting)
            } else {
                self.udp
                    .admit(tuple, payload, payload_bound, now_millis, admitting)
            };
            if admitted == UdpAdmission::Dropped {
                self.emit_local_control(
                    packet,
                    control_context(parsed),
                    LocalControlKind::PortUnreachable,
                    now_millis,
                );
                return false;
            }
            return true;
        }
        if self.device.ingress_len == INGRESS_SLOTS {
            self.emit_local_control(
                packet,
                control_context(parsed),
                LocalControlKind::AdministrativelyProhibited,
                now_millis,
            );
            self.reject(TunRejectReason::IngressFull);
            return false;
        }
        match initial_tcp_tuple(parsed) {
            Ok(Some(tuple)) if !self.admit_tcp(tuple, admitting) => {
                self.emit_local_control(
                    packet,
                    control_context(parsed),
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                return false;
            }
            Err(()) => {
                self.emit_local_control(
                    packet,
                    control_context(parsed),
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                return false;
            }
            Ok(Some(_)) | Ok(None) => {}
        }
        self.device.enqueue_parsed(packet, parsed)
    }

    pub(crate) fn emit_local_control(
        &mut self,
        original: &[u8],
        context: ControlContext,
        kind: LocalControlKind,
        now_millis: i64,
    ) {
        let _ = self.device.inject_control_error(
            original,
            context,
            kind,
            now_millis,
            &mut self.control_limiter,
        );
    }

    pub(crate) fn reject(&self, reason: TunRejectReason) {
        self.events.emit(TunEvent::PacketRejected(reason));
    }

    pub(crate) fn expire_deadlines(&mut self, now_millis: i64) -> bool {
        let udp = self.udp.expire(now_millis);
        let fragments = self.reassembly.expire(now_millis);
        if fragments != 0 {
            self.record_reassembly_timeouts(fragments);
            self.events
                .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
        }
        udp.candidates != 0 || udp.associations != 0 || fragments != 0
    }

    pub(crate) fn record_reassembly_timeouts(&self, count: usize) {
        for _ in 0..count {
            self.events.emit(TunEvent::ReassemblyDroppedTimeout);
            self.reject(TunRejectReason::FragmentTimeout);
        }
    }

    pub(crate) fn quiesce(
        &mut self,
        next_generation: u64,
        udp_response_drop_reason: UdpResponseDropReason,
    ) -> usize {
        let mut sockets = Vec::new();
        let mut reset = 0_usize;
        while let Some(slot) = self.active_flow_head {
            self.flows[slot]
                .as_mut()
                .expect("TCP active-list head is live")
                .owner
                .mark_reset();
            let entry = self
                .take_tcp_flow(slot)
                .expect("TCP active-list head remains removable");
            sockets.push(entry.socket);
            reset += 1;
        }
        for socket in sockets {
            self.sockets.remove(socket);
        }
        if reset != 0 {
            for _ in 0..reset {
                self.events.emit(TunEvent::TcpFlowResetRestart);
            }
        }
        self.udp
            .invalidate_session(next_generation, udp_response_drop_reason);
        self.reassembly.clear();
        self.device.clear_session_buffers();
        self.packet_generation = next_generation;
        self.events.emit(TunEvent::TcpFlowsActive(0));
        self.events.emit(TunEvent::UdpAssociationsActive(0));
        self.events.emit(TunEvent::UdpCandidatesActive(0));
        self.events.emit(TunEvent::ReassemblyEntriesActive(0));
        reset
    }

    pub(crate) fn next_wait_duration(&mut self, now_millis: i64) -> Duration {
        if self.device.ingress_len != 0 || self.has_output() || self.udp.has_pending_response() {
            return Duration::ZERO;
        }
        let now = Instant::from_millis(now_millis);
        let stack_delay = self
            .interface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()));
        let deadline_delay = [
            self.udp.next_deadline_millis(),
            self.reassembly.next_deadline_millis(),
        ]
        .into_iter()
        .flatten()
        .map(|deadline| {
            Duration::from_millis(
                u64::try_from(deadline.saturating_sub(now_millis).max(0)).unwrap_or(u64::MAX),
            )
        })
        .min();
        stack_delay
            .into_iter()
            .chain(deadline_delay)
            .min()
            .unwrap_or(Duration::from_millis(u64::from(u32::MAX - 1)))
    }

    #[cfg(test)]
    pub(crate) fn poll_quantum(&mut self, now: Instant) -> usize {
        let mut foundation = 0;
        for _ in 0..PACKET_QUANTUM {
            let outcome = self.poll_stack_once(now);
            foundation += outcome.foundation_dropped;
            if !outcome.worked {
                break;
            }
        }
        foundation
    }

    pub(crate) fn poll_stack_once(&mut self, now: Instant) -> StackPollOutcome {
        let foundation_before = self.device.foundation_input;
        let output_was_empty = !self.device.has_output();
        let ingress = self
            .interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        let mut worked = ingress != PollIngressSingleResult::None;
        worked |= self.drive_tcp();
        if output_was_empty {
            worked |= self
                .interface
                .poll_egress(now, &mut self.device, &mut self.sockets)
                != PollResult::None;
        }
        worked |= self.reap_tcp() != 0;
        let foundation_dropped = self.device.foundation_input - foundation_before;
        self.foundation_dropped += foundation_dropped;
        StackPollOutcome {
            worked,
            foundation_dropped,
        }
    }

    pub(crate) fn flush_output(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        let pending_fin = self.pending_tcp_fin_generation();
        let outcome = self.device.flush_output(send);
        if outcome == OutputFlushOutcome::Sent
            && let Some(generation) = pending_fin
        {
            self.complete_sent_tcp_fin(generation);
        }
        outcome
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.device.ingress_len
    }

    #[cfg(test)]
    pub(crate) fn discarded_packets(&self) -> usize {
        self.foundation_dropped
    }

    #[cfg(test)]
    pub(crate) fn validated_egress_packets(&self) -> usize {
        self.device.validated_output
    }

    #[cfg(test)]
    pub(crate) fn rejected_egress_packets(&self) -> usize {
        self.device.rejected_output
    }

    #[cfg(test)]
    pub(crate) fn has_exact_routes(&self) -> bool {
        self.interface.routes().get_default_ipv4_route().is_some()
            && self.interface.routes().get_default_ipv6_route().is_some()
    }
}

#[cfg(test)]
impl Stack {
    pub(crate) fn new(
        addresses: (Ipv4Addr, u8, Ipv6Addr, u8),
        mtu: usize,
        max_tcp_flows: usize,
        tcp_buffer_bytes: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
    ) -> Result<(Self, tokio::sync::mpsc::Receiver<TcpFlow>), ()> {
        let (stack, flows, _) = Stack::new_with_udp(
            (
                Some((addresses.0, addresses.1)),
                Some((addresses.2, addresses.3)),
            ),
            mtu,
            max_tcp_flows,
            tcp_buffer_bytes,
            tcp_timeout,
            flow_count,
            OwnerRegistry::new(),
            1,
            tcp_timeout,
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )?;
        Ok((stack, flows))
    }

    pub(crate) fn enqueue(&mut self, packet: &[u8], admitting: bool) -> bool {
        self.enqueue_at(packet, admitting, 0)
    }
}

pub(crate) fn ip_address(address: std::net::IpAddr) -> IpAddress {
    match address {
        std::net::IpAddr::V4(address) => IpAddress::Ipv4(Ipv4Address::from(address.octets())),
        std::net::IpAddr::V6(address) => IpAddress::Ipv6(Ipv6Address::from(address.octets())),
    }
}
