mod listener;
mod packet_rewrite;
mod quarantine;
mod retirement;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_runtime::OwnerRegistry;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use self::listener::{AcceptedSocket, ListenerSet};
#[cfg(test)]
use self::listener::{derive_ipv4_peer, derive_ipv6_peer};
use self::packet_rewrite::{is_initial_syn, rewrite_tuple, tcp_sequence};
pub(crate) use self::quarantine::PortQuarantine;
use crate::packet::{IpFamily, ParsedIpPacket, TransportMetadata};
use crate::tcp::{TcpSocketLease, tcp_flow_from_stream};
use crate::{OwnerWake, TcpFlow, TunEvent, TunEventSink, TunRejectReason};
pub(crate) type InterfaceAddresses = (Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>);

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const MAX_RETIRED_IDENTITIES: usize = (u16::MAX as usize) * 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowTuple {
    source: SocketAddr,
    target: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReverseTuple {
    listener: SocketAddr,
    peer: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn from_ip_family(family: IpFamily) -> Self {
        match family {
            IpFamily::Ipv4 => Self::Ipv4,
            IpFamily::Ipv6 => Self::Ipv6,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Binding {
    family: AddressFamily,
    local: SocketAddr,
    peer: IpAddr,
    epoch: u64,
}

struct Mapping {
    forward: FlowTuple,
    reverse: ReverseTuple,
    family: AddressFamily,
    translated_port: u16,
    initial_isn: u32,
    deadline_millis: i64,
    established: bool,
    application_fin: bool,
    listener_fin: bool,
    closing: bool,
    socket: Option<TcpSocketLease>,
    pending_flow: Option<TcpFlow>,
}

#[derive(Clone, Copy)]
struct RetiredMapping {
    forward_plan: RewritePlan,
    reverse_plan: RewritePlan,
    reverse: ReverseTuple,
    expires_at: i64,
}

#[derive(Clone, Copy)]
struct RewritePlan {
    source: SocketAddr,
    destination: SocketAddr,
}

/// Owner-thread TCP tuple translation, listener ownership and flow publication.
///
/// All deadlines use the supervisor's process-long monotonic millisecond origin.
/// Listener and translated-peer ports remain unavailable for 240 seconds after
/// retirement, including across resets through the shared [`PortQuarantine`].
pub(crate) struct SystemTcp {
    max_flows: usize,
    timeout_millis: i64,
    generation: u64,
    next_epoch: u64,
    fenced: bool,
    active: usize,
    active_deadline_millis: Option<i64>,
    pending_slots: VecDeque<usize>,
    slots: Box<[Option<Mapping>]>,
    free_slots: Vec<usize>,
    forward: HashMap<FlowTuple, usize>,
    reverse: HashMap<ReverseTuple, usize>,
    retired_forward: HashMap<FlowTuple, RetiredMapping>,
    retired_reverse: HashMap<ReverseTuple, FlowTuple>,
    retired_deadline_millis: Option<i64>,
    bindings: Vec<Binding>,
    listener: Option<ListenerSet>,
    accepted_sender: mpsc::Sender<AcceptedSocket>,
    accepted_receiver: mpsc::Receiver<AcceptedSocket>,
    flow_sender: mpsc::Sender<TcpFlow>,
    flow_count: Arc<AtomicUsize>,
    registry: OwnerRegistry,
    owner_wake: OwnerWake,
    socket_wake: OwnerWake,
    flow_changed: Arc<AtomicBool>,
    quarantine: Arc<Mutex<PortQuarantine>>,
    events: TunEventSink,
    listener_failed: Arc<AtomicBool>,
    dropped_accepts: Arc<AtomicUsize>,
    last_now_millis: i64,
}

impl SystemTcp {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        max_flows: usize,
        timeout: Duration,
        generation: u64,
        flow_count: Arc<AtomicUsize>,
        registry: OwnerRegistry,
        owner_wake: OwnerWake,
        quarantine: Arc<Mutex<PortQuarantine>>,
    ) -> (Self, mpsc::Receiver<TcpFlow>) {
        let channel_capacity = max_flows.max(1);
        let (flow_sender, flows) = mpsc::channel(channel_capacity);
        let (accepted_sender, accepted_receiver) = mpsc::channel(channel_capacity);
        let timeout_millis = i64::try_from(timeout.as_millis()).unwrap_or(i64::MAX);
        let flow_changed = Arc::new(AtomicBool::new(false));
        let changed = Arc::clone(&flow_changed);
        let wake = owner_wake.clone();
        let socket_wake = OwnerWake::new(move || {
            changed.store(true, Ordering::Release);
            wake.signal();
        });
        (
            Self {
                max_flows,
                timeout_millis,
                generation,
                next_epoch: generation,
                fenced: false,
                active: 0,
                active_deadline_millis: None,
                pending_slots: VecDeque::with_capacity(max_flows),
                slots: std::iter::repeat_with(|| None)
                    .take(max_flows)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                free_slots: (0..max_flows).rev().collect(),
                forward: HashMap::with_capacity(max_flows),
                reverse: HashMap::with_capacity(max_flows),
                retired_forward: HashMap::with_capacity(max_flows),
                retired_reverse: HashMap::with_capacity(max_flows),
                retired_deadline_millis: None,
                bindings: Vec::with_capacity(2),
                listener: None,
                accepted_sender,
                accepted_receiver,
                flow_sender,
                flow_count,
                registry,
                owner_wake,
                socket_wake,
                flow_changed,
                quarantine,
                events: TunEventSink::default(),
                listener_failed: Arc::new(AtomicBool::new(false)),
                dropped_accepts: Arc::new(AtomicUsize::new(0)),
                last_now_millis: 0,
            },
            flows,
        )
    }

    pub(crate) fn start(
        &mut self,
        addresses: InterfaceAddresses,
        runtime: &Handle,
    ) -> io::Result<Vec<ferrum2_platform_windows::TcpIngressEndpoint>> {
        if self.fenced {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "system TCP generation is fenced",
            ));
        }
        if self.listener.is_some() || !self.bindings.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "system TCP listeners already started",
            ));
        }
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let listeners = ListenerSet::start(
            addresses,
            self.next_epoch,
            self.max_flows,
            runtime,
            self.accepted_sender.clone(),
            Arc::clone(&self.listener_failed),
            Arc::clone(&self.dropped_accepts),
            self.owner_wake.clone(),
            Arc::clone(&self.quarantine),
        )?;
        let endpoints = listeners
            .bindings
            .iter()
            .map(|binding| {
                ferrum2_platform_windows::TcpIngressEndpoint::new(binding.local, binding.peer)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
            })
            .collect::<io::Result<Vec<_>>>();
        self.bindings.extend(listeners.bindings.iter().copied());
        self.listener = Some(listeners);
        endpoints
    }

    #[cfg(test)]
    pub(crate) fn configure_bindings_for_test(
        &mut self,
        addresses: InterfaceAddresses,
        listener_ports: (Option<u16>, Option<u16>),
    ) -> io::Result<()> {
        if self.fenced {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "system TCP generation is fenced",
            ));
        }
        if self.listener.is_some() || !self.bindings.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "system TCP bindings already configured",
            ));
        }
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let mut bindings = Vec::with_capacity(2);
        match (addresses.0, listener_ports.0) {
            (Some((local, prefix)), Some(port)) if port != 0 => bindings.push(Binding {
                family: AddressFamily::Ipv4,
                local: SocketAddr::new(IpAddr::V4(local), port),
                peer: IpAddr::V4(derive_ipv4_peer(local, prefix)?),
                epoch: self.next_epoch,
            }),
            (None, None) => {}
            _ => return Err(invalid_test_binding()),
        }
        match (addresses.1, listener_ports.1) {
            (Some((local, prefix)), Some(port)) if port != 0 => bindings.push(Binding {
                family: AddressFamily::Ipv6,
                local: SocketAddr::new(IpAddr::V6(local), port),
                peer: IpAddr::V6(derive_ipv6_peer(local, prefix)?),
                epoch: self.next_epoch,
            }),
            (None, None) => {}
            _ => return Err(invalid_test_binding()),
        }
        if bindings.is_empty() {
            return Err(invalid_test_binding());
        }
        let mut claimed = 0;
        {
            let mut quarantine = self.quarantine.lock().expect("system TCP port quarantine");
            for binding in &bindings {
                if !quarantine.claim(binding.family, binding.local.port()) {
                    for binding in &bindings[..claimed] {
                        quarantine.unclaim(binding.family, binding.local.port());
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "system TCP test listener port is active or quarantined",
                    ));
                }
                claimed += 1;
            }
        }
        self.bindings = bindings;
        Ok(())
    }

    pub(crate) fn rewrite(
        &mut self,
        packet: &mut [u8],
        parsed: ParsedIpPacket,
        admitting: bool,
        now_millis: i64,
    ) -> Result<(), TunRejectReason> {
        let now_millis = self.observe_time(now_millis);
        // The owner services accepts, publication and quarantine once per control
        // rotation. Packets only force maintenance when a live mapping may have
        // expired or a socket was dropped; neither may be revived by traffic.
        if self
            .active_deadline_millis
            .is_some_and(|deadline| deadline <= now_millis)
            || self.flow_changed.load(Ordering::Acquire)
        {
            self.expire(now_millis);
        }
        if !parsed.metadata_matches(packet.len()) {
            return Err(TunRejectReason::InvalidIpLength);
        }
        let TransportMetadata::Tcp(tcp) = parsed.transport else {
            return Err(TunRejectReason::UnsupportedIpProtocol);
        };
        let family = AddressFamily::from_ip_family(parsed.family);
        let forward = FlowTuple {
            source: SocketAddr::new(parsed.source, tcp.source_port),
            target: SocketAddr::new(parsed.destination, tcp.destination_port),
        };
        let reverse = ReverseTuple {
            listener: forward.source,
            peer: forward.target,
        };
        let flags = tcp.flags;
        let initial_syn = is_initial_syn(tcp);
        let sequence = tcp_sequence(packet, parsed.transport_offset)?;

        if let Some(&slot) = self.reverse.get(&reverse) {
            return self.rewrite_active(
                packet, parsed, slot, /* application_direction: */ false, flags, now_millis,
            );
        }
        if let Some(&slot) = self.forward.get(&forward) {
            if initial_syn
                && self.slots[slot]
                    .as_ref()
                    .is_some_and(|mapping| mapping.initial_isn != sequence)
            {
                return Err(TunRejectReason::InvalidDestination);
            }
            return self.rewrite_active(
                packet, parsed, slot, /* application_direction: */ true, flags, now_millis,
            );
        }
        if let Some(plan) = self.retired_reverse_plan(reverse, now_millis) {
            return rewrite_tuple(packet, parsed, plan);
        }
        if let Some(plan) = self.retired_forward_plan(forward, now_millis) {
            if initial_syn {
                return Err(TunRejectReason::InvalidDestination);
            }
            return rewrite_tuple(packet, parsed, plan);
        }
        if !initial_syn {
            return Err(TunRejectReason::InvalidDestination);
        }
        if self.fenced || !admitting {
            return Err(TunRejectReason::StaleGeneration);
        }
        self.reap_retired(now_millis);
        if self.active >= self.max_flows {
            self.events.emit(TunEvent::TcpFlowRejectedLimit);
            return Err(TunRejectReason::TcpFlowLimit);
        }
        let Some(binding) = self.binding(family) else {
            return Err(TunRejectReason::InvalidDestination);
        };
        let Some(translated_port) = self
            .quarantine
            .lock()
            .expect("system TCP port quarantine")
            .allocate(family, now_millis)
        else {
            return Err(TunRejectReason::InvalidDestination);
        };
        let translated_peer = SocketAddr::new(binding.peer, translated_port);
        let reverse = ReverseTuple {
            listener: binding.local,
            peer: translated_peer,
        };
        let Some(slot) = self.free_slots.pop() else {
            self.quarantine
                .lock()
                .expect("system TCP port quarantine")
                .release(family, translated_port, now_millis);
            self.events.emit(TunEvent::TcpFlowRejectedLimit);
            return Err(TunRejectReason::TcpFlowLimit);
        };
        self.slots[slot] = Some(Mapping {
            forward,
            reverse,
            family,
            translated_port,
            initial_isn: sequence,
            deadline_millis: deadline(now_millis, self.timeout_millis),
            established: false,
            application_fin: false,
            listener_fin: false,
            closing: false,
            socket: None,
            pending_flow: None,
        });
        let mapping_deadline = deadline(now_millis, self.timeout_millis);
        self.active_deadline_millis = Some(
            self.active_deadline_millis
                .map_or(mapping_deadline, |current| current.min(mapping_deadline)),
        );
        let replaced_forward = self.forward.insert(forward, slot);
        let replaced_reverse = self.reverse.insert(reverse, slot);
        debug_assert!(replaced_forward.is_none());
        debug_assert!(replaced_reverse.is_none());
        self.active += 1;
        self.flow_count.fetch_add(1, Ordering::AcqRel);
        self.events.emit(TunEvent::TcpFlowsActive(self.active));
        rewrite_tuple(
            packet,
            parsed,
            RewritePlan {
                source: translated_peer,
                destination: binding.local,
            },
        )
    }

    pub(crate) fn expire(&mut self, now_millis: i64) -> bool {
        let now_millis = self.observe_time(now_millis);
        let mut worked = self.process_accepts(now_millis);
        worked |= self.drain_pending_flows(now_millis);
        let flow_changed = self.flow_changed.swap(false, Ordering::AcqRel);
        if flow_changed
            || self
                .active_deadline_millis
                .is_some_and(|due| due <= now_millis)
        {
            for slot in 0..self.slots.len() {
                let retire = self.slots[slot].as_ref().is_some_and(|mapping| {
                    mapping.deadline_millis <= now_millis
                        || mapping
                            .socket
                            .as_ref()
                            .is_some_and(TcpSocketLease::flow_dropped)
                });
                if retire {
                    self.retire_slot(slot, now_millis, true);
                    worked = true;
                }
            }
            self.active_deadline_millis = self
                .slots
                .iter()
                .flatten()
                .map(|mapping| mapping.deadline_millis)
                .min();
        }
        worked |= self.reap_retired(now_millis);
        worked |= self
            .quarantine
            .lock()
            .expect("system TCP port quarantine")
            .reap(now_millis);
        let dropped = self.dropped_accepts.swap(0, Ordering::AcqRel);
        for _ in 0..dropped {
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::IngressFull));
        }
        worked || dropped != 0
    }

    pub(crate) fn next_deadline_millis(&self) -> Option<i64> {
        let active = self.active_deadline_millis;
        let retired = self.retired_deadline_millis;
        let quarantine = self
            .quarantine
            .lock()
            .expect("system TCP port quarantine")
            .next_deadline_millis();
        [active, retired, quarantine].into_iter().flatten().min()
    }

    #[cfg(test)]
    pub(crate) const fn live_flows(&self) -> usize {
        self.active
    }

    #[cfg(test)]
    pub(crate) fn quarantine_counts(&self) -> ((usize, usize), (usize, usize)) {
        self.quarantine
            .lock()
            .expect("system TCP port quarantine")
            .counts()
    }

    pub(crate) fn set_event_sink(&mut self, events: TunEventSink) {
        self.events = events;
    }

    pub(crate) fn failed(&self) -> bool {
        self.listener_failed.load(Ordering::Acquire)
            || self.listener.as_ref().is_some_and(ListenerSet::failed)
    }

    pub(crate) fn fence(&mut self, next_generation: u64) -> Result<(), ()> {
        if next_generation <= self.generation
            && !(self.generation == u64::MAX && next_generation == 0)
        {
            return Err(());
        }
        self.fenced = true;
        for mapping in self.slots.iter().flatten() {
            if let Some(socket) = &mapping.socket {
                debug_assert_eq!(socket.generation(), self.generation);
                socket.fence();
            }
        }
        while self.accepted_receiver.try_recv().is_ok() {}
        Ok(())
    }

    pub(crate) fn retire(&mut self, next_generation: u64) -> usize {
        if next_generation <= self.generation
            && !(self.generation == u64::MAX && next_generation == 0 && self.fenced)
        {
            return 0;
        }
        let retired = self.retire_all(self.last_now_millis, false);
        self.generation = next_generation;
        self.fenced = true;
        self.retired_forward.clear();
        self.retired_reverse.clear();
        self.retired_deadline_millis = None;
        retired
    }

    pub(crate) fn stop_and_join(&mut self) -> Result<(), ()> {
        self.fenced = true;
        for mapping in self.slots.iter().flatten() {
            if let Some(socket) = &mapping.socket {
                socket.fence();
            }
        }
        let mut result = self
            .listener
            .as_mut()
            .map_or(Ok(()), ListenerSet::stop_and_join);
        self.listener = None;
        let bindings = std::mem::take(&mut self.bindings);
        match self.quarantine.lock() {
            Ok(mut quarantine) => {
                for binding in bindings {
                    quarantine.defer_release(binding.family, binding.local.port());
                }
            }
            Err(_) => {
                self.listener_failed.store(true, Ordering::Release);
                result = Err(());
            }
        }
        while self.accepted_receiver.try_recv().is_ok() {}
        result
    }

    fn rewrite_active(
        &mut self,
        packet: &mut [u8],
        parsed: ParsedIpPacket,
        slot: usize,
        application_direction: bool,
        flags: u8,
        now_millis: i64,
    ) -> Result<(), TunRejectReason> {
        if self.fenced {
            return Err(TunRejectReason::StaleGeneration);
        }
        let mapping = self.slots[slot]
            .as_mut()
            .expect("system TCP tuple index references a live mapping");
        if mapping.established && !mapping.closing {
            mapping.deadline_millis = deadline(now_millis, self.timeout_millis);
        }
        if flags & TCP_FIN != 0 {
            if application_direction {
                mapping.application_fin = true;
            } else {
                mapping.listener_fin = true;
            }
            mapping.closing = mapping.application_fin && mapping.listener_fin;
        }
        if flags & TCP_RST != 0 {
            mapping.closing = true;
            mapping.deadline_millis = now_millis.saturating_add(1);
        }
        self.active_deadline_millis = Some(
            self.active_deadline_millis
                .map_or(mapping.deadline_millis, |current| {
                    current.min(mapping.deadline_millis)
                }),
        );
        let plan = if application_direction {
            RewritePlan {
                source: mapping.reverse.peer,
                destination: mapping.reverse.listener,
            }
        } else {
            RewritePlan {
                source: mapping.forward.target,
                destination: mapping.forward.source,
            }
        };
        rewrite_tuple(packet, parsed, plan)?;
        Ok(())
    }

    fn process_accepts(&mut self, now_millis: i64) -> bool {
        let mut worked = false;
        for _ in 0..16 {
            let Ok(accepted) = self.accepted_receiver.try_recv() else {
                break;
            };
            worked = true;
            let key = ReverseTuple {
                listener: accepted.local,
                peer: accepted.peer,
            };
            let Some(&slot) = self.reverse.get(&key) else {
                continue;
            };
            let valid = self.slots[slot].as_ref().is_some_and(|mapping| {
                !self.fenced
                    && accepted.epoch
                        == self
                            .binding(mapping.family)
                            .map_or(0, |binding| binding.epoch)
                    && mapping.socket.is_none()
                    && mapping.pending_flow.is_none()
                    && !mapping.closing
                    && mapping.deadline_millis > now_millis
            });
            if !valid || accepted.stream.set_nodelay(true).is_err() {
                continue;
            }
            let target = self.slots[slot]
                .as_ref()
                .expect("accepted tuple mapping remains live")
                .forward
                .target;
            let (flow, socket) = tcp_flow_from_stream(
                accepted.stream,
                target,
                self.generation,
                &self.registry,
                self.socket_wake.clone(),
            );
            let mapping = self.slots[slot]
                .as_mut()
                .expect("accepted tuple mapping remains live");
            mapping.established = true;
            mapping.deadline_millis = deadline(now_millis, self.timeout_millis);
            mapping.socket = Some(socket);
            match self.flow_sender.try_send(flow) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(flow)) => {
                    mapping.pending_flow = Some(flow);
                    self.pending_slots.push_back(slot);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.retire_slot(slot, now_millis, true);
                }
            }
        }
        worked
    }

    fn drain_pending_flows(&mut self, now_millis: i64) -> bool {
        if self.fenced {
            return false;
        }
        let mut worked = false;
        for _ in 0..self.pending_slots.len().min(16) {
            let slot = self.pending_slots.pop_front().expect("pending flow slot");
            if self.slots[slot]
                .as_ref()
                .is_some_and(|mapping| mapping.deadline_millis <= now_millis)
            {
                self.retire_slot(slot, now_millis, true);
                worked = true;
                continue;
            }
            let Some(flow) = self.slots[slot]
                .as_mut()
                .and_then(|mapping| mapping.pending_flow.take())
            else {
                continue;
            };
            match self.flow_sender.try_send(flow) {
                Ok(()) => worked = true,
                Err(mpsc::error::TrySendError::Full(flow)) => {
                    self.slots[slot]
                        .as_mut()
                        .expect("pending flow mapping remains live")
                        .pending_flow = Some(flow);
                    self.pending_slots.push_front(slot);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.retire_slot(slot, now_millis, true);
                    worked = true;
                }
            }
        }
        worked
    }

    fn binding(&self, family: AddressFamily) -> Option<Binding> {
        self.bindings
            .iter()
            .copied()
            .find(|binding| binding.family == family)
    }

    fn observe_time(&mut self, now_millis: i64) -> i64 {
        self.last_now_millis = self.last_now_millis.max(now_millis);
        self.last_now_millis
    }
}

impl Drop for SystemTcp {
    fn drop(&mut self) {
        if self.listener.is_some() || !self.bindings.is_empty() {
            let _ = self.stop_and_join();
        }
        self.fenced = true;
        self.retire_all(self.last_now_millis, false);
    }
}

fn deadline(now_millis: i64, timeout_millis: i64) -> i64 {
    now_millis.saturating_add(timeout_millis)
}

#[cfg(test)]
fn invalid_test_binding() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "system TCP test binding families and non-zero ports must match",
    )
}
