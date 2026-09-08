mod device;
mod lifecycle;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
mod live;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
mod teardown;
mod udp;
#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend", not(test)),
    feature = "benchmark"
))]
mod work;

pub(crate) use device::{MemoryDevice, OutputFlushOutcome, OutputSendOutcome};
#[cfg(test)]
pub(crate) use device::{PacketValidator, udp_datagram};

use std::net::IpAddr;
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_runtime::OwnerRegistry;

use crate::packet::map_packet_reject;
use crate::packet::{
    ControlContext, ControlRateLimiter, Families, LocalControlKind, PacketRejectReason,
    ParsedIpPacket, ParsedPacket, control_context, ipv4_directed_broadcast,
    oversized_ingress_control,
};
use crate::reassembly::{ReassemblyDropReason, ReassemblyOutcome, ReassemblyTable};
use crate::system_tcp::{InterfaceAddresses, PortQuarantine, SystemTcp};
use crate::udp::{Admission as UdpAdmission, UdpTable};
use crate::{
    INGRESS_SLOTS, OwnerWake, TcpFlow, TunEvent, TunEventSink, TunRejectReason, UdpCandidate,
    UdpFiltering,
};
use device::udp_datagram_from_parsed;

pub(crate) struct Stack {
    pub(crate) device: MemoryDevice,
    addresses: InterfaceAddresses,
    pub(crate) packet_generation: u64,
    session_generation: u64,
    fenced_generation: Option<u64>,
    pub(crate) reassembly: ReassemblyTable,
    pub(crate) control_limiter: ControlRateLimiter,
    pub(crate) udp: UdpTable,
    system_tcp: SystemTcp,
    pub(crate) events: TunEventSink,
}

pub(crate) type StackReady = (
    Stack,
    tokio::sync::mpsc::Receiver<TcpFlow>,
    tokio::sync::mpsc::Receiver<UdpCandidate>,
);

impl Stack {
    #[cfg(feature = "benchmark")]
    pub(crate) fn accept_packet_socket(
        &mut self,
        source: std::net::SocketAddr,
        target: std::net::SocketAddr,
        stream: tokio::io::DuplexStream,
    ) {
        self.system_tcp.accept_packet_socket(source, target, stream);
    }

    #[cfg(all(feature = "benchmark", not(test)))]
    pub(crate) fn configure_packet_bindings(&mut self) {
        self.system_tcp
            .configure_packet_bindings(
                self.addresses,
                (
                    self.addresses.0.map(|_| 20000),
                    self.addresses.1.map(|_| 20001),
                ),
            )
            .expect("bounded packet adapter identities");
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_udp(
        addresses: InterfaceAddresses,
        mtu: usize,
        max_tcp_flows: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
        registry: OwnerRegistry,
        max_udp_associations: usize,
        udp_timeout: Duration,
        udp_filtering: UdpFiltering,
        session_generation: u64,
        owner_wake: OwnerWake,
        port_quarantine: Arc<Mutex<PortQuarantine>>,
    ) -> Result<StackReady, ()> {
        let (ipv4, ipv6) = addresses;
        let families = Families {
            ipv4: ipv4.is_some(),
            ipv6: ipv6.is_some(),
        };
        if !families.ipv4 && !families.ipv6 {
            return Err(());
        }
        let device = MemoryDevice::with_output_slots(mtu, families, 1);
        let (system_tcp, flows) = SystemTcp::new(
            max_tcp_flows,
            tcp_timeout,
            session_generation,
            flow_count,
            registry,
            owner_wake.clone(),
            port_quarantine,
        );
        #[cfg(test)]
        let mut system_tcp = system_tcp;
        #[cfg(test)]
        let test_tcp_port = 20_000_u16 + 2 * (session_generation % 20_000) as u16;
        #[cfg(test)]
        system_tcp
            .configure_packet_bindings(
                addresses,
                (ipv4.map(|_| test_tcp_port), ipv6.map(|_| test_tcp_port + 1)),
            )
            .map_err(|_| ())?;
        let (udp, datagrams) = UdpTable::with_options(
            max_udp_associations,
            udp_timeout,
            udp_filtering,
            session_generation,
            owner_wake,
        );
        Ok((
            Self {
                device,
                addresses,
                packet_generation: session_generation,
                session_generation,
                fenced_generation: None,
                reassembly: ReassemblyTable::new(0),
                control_limiter: ControlRateLimiter::new(),
                udp,
                system_tcp,
                events: TunEventSink::default(),
            },
            flows,
            datagrams,
        ))
    }

    pub(crate) fn set_event_sink(&mut self, events: TunEventSink) {
        self.system_tcp.set_event_sink(events.clone());
        self.udp.set_event_sink(events.clone());
        self.events = events;
    }

    pub(crate) fn set_udp_buffer_budget(&mut self, budget: ferrum2_runtime::UdpBufferBudget) {
        self.udp.set_buffer_budget(budget);
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
            (destination, self.addresses.0),
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
        let context = control_context(parsed);
        match self
            .device
            .enqueue_rewritten(packet, parsed, |packet, parsed| {
                self.system_tcp
                    .rewrite(packet, parsed, admitting, now_millis)
            }) {
            Ok(true) => true,
            Ok(false) => {
                self.emit_local_control(
                    packet,
                    context,
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                self.reject(TunRejectReason::IngressFull);
                false
            }
            Err(reason) => {
                self.emit_local_control(
                    packet,
                    context,
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                self.reject(reason);
                false
            }
        }
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
        let tcp = self.system_tcp.expire(now_millis);
        let udp = self.udp.expire(now_millis);
        let fragments = self.reassembly.expire(now_millis);
        if fragments != 0 {
            self.record_reassembly_timeouts(fragments);
            self.events
                .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
        }
        tcp || udp.candidates != 0 || udp.associations != 0 || fragments != 0
    }

    pub(crate) fn record_reassembly_timeouts(&self, count: usize) {
        for _ in 0..count {
            self.events.emit(TunEvent::ReassemblyDroppedTimeout);
            self.reject(TunRejectReason::FragmentTimeout);
        }
    }

    pub(crate) fn next_wait_duration(&mut self, now_millis: i64) -> Duration {
        if self.device.ingress_len != 0 || self.has_output() || self.udp.has_pending_response() {
            return Duration::ZERO;
        }
        [
            self.system_tcp.next_deadline_millis(),
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
        .min()
        .unwrap_or(Duration::from_millis(u64::from(u32::MAX - 1)))
    }

    pub(crate) fn process_one_tcp_packet(&mut self) -> bool {
        self.device.promote_one_ingress()
    }

    pub(crate) fn flush_output(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        let terminal = if self.system_tcp.has_reset_output() {
            self.device.front_output().and_then(|packet| {
                match self.device.validator.parse_ingress(packet) {
                    Ok(ParsedPacket::Complete(parsed)) => Some(parsed),
                    Ok(ParsedPacket::Fragment(_)) | Err(_) => None,
                }
            })
        } else {
            None
        };
        let outcome = self.device.flush_output(send);
        if outcome == OutputFlushOutcome::Sent
            && let Some(parsed) = terminal
        {
            self.system_tcp.reset_output_sent(parsed);
        }
        outcome
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.device.ingress_len
    }

    #[cfg(test)]
    pub(crate) fn live_tcp_flows(&self) -> usize {
        self.system_tcp.live_flows()
    }
}

#[cfg(test)]
impl Stack {
    pub(crate) fn new(
        addresses: (Ipv4Addr, u8, Ipv6Addr, u8),
        mtu: usize,
        max_tcp_flows: usize,
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
            tcp_timeout,
            flow_count,
            OwnerRegistry::new(),
            1,
            tcp_timeout,
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
            Arc::new(Mutex::new(PortQuarantine::default())),
        )?;
        Ok((stack, flows))
    }

    pub(crate) fn enqueue(&mut self, packet: &[u8], admitting: bool) -> bool {
        self.enqueue_at(packet, admitting, 0)
    }
}
