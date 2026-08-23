use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
use ferrum2_crypto::{Clock, MethodKeyProvider, SecureRandom, UdpSessionId};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpSocket, DirectUdpSocketFactory, MAX_UDP_RESOLVED_CANDIDATES,
    MAX_UDP_WIRE_DATAGRAM_BYTES, PendingUdpDatagram, PendingUdpSession, SystemDirectUdpSocket,
    SystemDirectUdpSocketFactory, UDP_SESSION_QUEUE_DEPTH, UdpBufferReservation, UdpCommitError,
    UdpDirection, UdpResolver, UdpRuntimeError, UdpSessionHandle, UdpSessionManager,
};
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;
use ferrum2_shadowsocks::{
    BorrowedPendingUdpResponse, MAX_UDP_WIRE_LEN, UdpClientSession, UdpPacketError,
    UdpPacketScratch, UdpResponseCommit, max_udp_payload_len_for_encoded_target,
};
use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::{ClientEgressEngine, ClientOutboundContext, ClientRequestOrigin, SelectedEgress};

const MAX_DIRECT_UDP_READINESS_DRAIN: usize = 32;
const DIRECT_UDP_CANDIDATE_HINT_CAPACITY: usize = 16;

pub(in crate::run) struct ClientUdpContext {
    pub(in crate::run) manager: UdpSessionManager,
    pub(in crate::run) live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
}

impl ClientUdpContext {
    pub(in crate::run) fn cancel_all(&self) {
        self.manager.cancel_all();
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum UdpIoOperation {
    ApplicationRecv,
    ApplicationSend,
    UpstreamRecv,
    UpstreamSend,
}

#[cfg(test)]
pub(in crate::run) struct UdpIoFaultPlan {
    operation: UdpIoOperation,
    fail_at: usize,
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
pub(in crate::run) struct IdSequenceRandom(Mutex<VecDeque<u8>>);

#[cfg(test)]
impl IdSequenceRandom {
    pub(in crate::run) fn new(draws: impl IntoIterator<Item = u8>) -> Self {
        Self(Mutex::new(draws.into_iter().collect()))
    }
}

#[cfg(test)]
impl SecureRandom for IdSequenceRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ferrum2_crypto::RandomError> {
        let byte = self
            .0
            .lock()
            .expect("ID draw lock")
            .pop_front()
            .ok_or(ferrum2_crypto::RandomError::Unavailable)?;
        destination.fill(byte);
        Ok(())
    }
}

#[cfg(test)]
impl UdpIoFaultPlan {
    pub(in crate::run) fn new(operation: UdpIoOperation, fail_at: usize) -> Self {
        Self {
            operation,
            fail_at,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(in crate::run) fn fails(&self, operation: UdpIoOperation) -> bool {
        self.operation == operation
            && self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.fail_at
    }
}

pub(in crate::run) struct ClientUdpAssociation {
    plan: Option<EgressPlanSnapshot>,
    first_server: Option<SocketAddr>,
    protocol: Option<ClientUdpPlan>,
    pending_session: Option<PendingUdpSession>,
    manager: UdpSessionManager,
    handle: UdpSessionHandle,
    meter_global_buffers: bool,
    live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
    upstream: ClientUdpUpstream,
    direct_target: Option<TargetAddr>,
    direct_response_policy: DirectUdpResponsePolicy,
    direct_peers: VecDeque<SocketAddr>,
    direct_candidate_hints: DirectUdpCandidateHints,
    direct_resolver: ferrum2_runtime::ApplicationResolverAdapter,
    direct_timeout: std::time::Duration,
    pending_direct_response: Option<(BytesMut, SocketAddr)>,
    direct_wire: Option<BytesMut>,
    inner_wire: Option<Vec<u8>>,
    upstream_wire: Option<Vec<u8>>,
    scratch: Option<UdpPacketScratch>,
    _metered_fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

enum ClientUdpUpstream {
    Shadowsocks(UdpSocket),
    Direct(ClientDirectUdpSocket),
}

enum ClientDirectUdpSocket {
    System(SystemDirectUdpSocket),
    #[cfg(windows)]
    Managed(UdpSocket),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectUdpResponsePolicy {
    OutstandingPeers,
    TunSink(DirectUdpFamily),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectUdpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectUdpResponseMatch {
    OutstandingPeer(usize),
    TunSink,
}

impl DirectUdpFamily {
    fn matches(self, endpoint: SocketAddr) -> bool {
        matches!(
            (self, endpoint),
            (Self::Ipv4, SocketAddr::V4(_)) | (Self::Ipv6, SocketAddr::V6(_))
        )
    }
}

impl DirectUdpResponsePolicy {
    fn classify(
        self,
        expected_peers: &VecDeque<SocketAddr>,
        source: SocketAddr,
    ) -> Option<DirectUdpResponseMatch> {
        match self {
            Self::OutstandingPeers => expected_peers
                .iter()
                .position(|expected| *expected == source)
                .map(DirectUdpResponseMatch::OutstandingPeer),
            // TUN owns endpoint-independent mapping and its response sink owns
            // ADF/EIF source admission. The direct child only enforces the
            // socket family before handing the datagram to that policy owner.
            Self::TunSink(family) if family.matches(source) => {
                Some(DirectUdpResponseMatch::TunSink)
            }
            Self::TunSink(_) => None,
        }
    }
}

#[derive(Default)]
struct DirectUdpCandidateHints {
    entries: VecDeque<DirectUdpCandidateHint>,
}

struct DirectUdpCandidateHint {
    domain: String,
    port: u16,
    last_successful_index: usize,
}

impl DirectUdpCandidateHints {
    fn start_index(&self, domain: &str, port: u16) -> usize {
        self.entries
            .iter()
            .find(|entry| entry.domain == domain && entry.port == port)
            .map_or(0, |entry| entry.last_successful_index)
    }

    fn record_success(&mut self, domain: &str, port: u16, last_successful_index: usize) {
        if let Some(position) = self
            .entries
            .iter()
            .position(|entry| entry.domain == domain && entry.port == port)
        {
            self.entries.remove(position);
        } else if self.entries.len() >= DIRECT_UDP_CANDIDATE_HINT_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(DirectUdpCandidateHint {
            domain: domain.to_owned(),
            port,
            last_successful_index,
        });
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedUdpBinding {
    Fixed(SocketAddr),
    Target(SocketAddr),
}

#[cfg(all(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManagedUdpEvent {
    OpenV4,
    OpenV6,
    BindFixed(SocketAddr),
    BindTarget(SocketAddr),
    Connect(SocketAddr),
}

#[cfg(any(windows, test))]
fn managed_udp_binding(
    origin: ClientRequestOrigin,
    selected: SelectedEgress,
    auto_route: bool,
    target: Option<&TargetAddr>,
) -> Result<Option<ManagedUdpBinding>, ()> {
    match selected {
        SelectedEgress::Shadowsocks { first_server } if auto_route => {
            Ok(Some(ManagedUdpBinding::Fixed(first_server)))
        }
        SelectedEgress::Shadowsocks { .. } => Ok(None),
        SelectedEgress::Direct { .. } if auto_route && origin == ClientRequestOrigin::Dns => {
            match target.and_then(TargetAddr::as_socket_addr) {
                Some(endpoint) => Ok(Some(ManagedUdpBinding::Fixed(endpoint))),
                // There is no safe adapter-wide fallback: a deferred destination
                // must be resolved to a numeric bootstrap before opening its socket.
                None => Err(()),
            }
        }
        SelectedEgress::Direct { .. } if auto_route || origin == ClientRequestOrigin::Tun => target
            .and_then(TargetAddr::as_socket_addr)
            .map(ManagedUdpBinding::Target)
            .map(Some)
            .ok_or(()),
        SelectedEgress::Direct { .. } => Ok(None),
    }
}

#[cfg(any(windows, test))]
trait ManagedUdpOperations {
    type Socket;

    async fn open_v4(&mut self) -> io::Result<Self::Socket>;
    async fn open_v6(&mut self) -> io::Result<Self::Socket>;
    fn bind_fixed(&self, socket: &Self::Socket, endpoint: SocketAddr) -> Result<(), ()>;
    fn bind_target(&self, socket: &Self::Socket, target: SocketAddr) -> Result<(), ()>;
    async fn connect(&self, socket: &Self::Socket, endpoint: SocketAddr) -> io::Result<()>;
}

#[cfg(any(windows, test))]
async fn open_managed_udp<O: ManagedUdpOperations>(
    operations: &mut O,
    binding: ManagedUdpBinding,
    connect: Option<SocketAddr>,
) -> Result<O::Socket, ()> {
    let binding_endpoint = match binding {
        ManagedUdpBinding::Fixed(endpoint) | ManagedUdpBinding::Target(endpoint) => endpoint,
    };
    if connect.is_some_and(|endpoint| endpoint.is_ipv4() != binding_endpoint.is_ipv4()) {
        return Err(());
    }
    let socket = if binding_endpoint.is_ipv4() {
        operations.open_v4().await
    } else {
        operations.open_v6().await
    }
    .map_err(|_| ())?;
    match binding {
        ManagedUdpBinding::Fixed(endpoint) => operations.bind_fixed(&socket, endpoint)?,
        ManagedUdpBinding::Target(target) => operations.bind_target(&socket, target)?,
    }
    if let Some(endpoint) = connect {
        operations
            .connect(&socket, endpoint)
            .await
            .map_err(|_| ())?;
    }
    Ok(socket)
}

impl DirectUdpSocket for ClientDirectUdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::System(socket) => socket.send_to(payload, target).await,
            #[cfg(windows)]
            Self::Managed(socket) => socket.send_to(payload, target).await,
        }
    }

    async fn readable(&self) -> io::Result<()> {
        match self {
            Self::System(socket) => socket.readable().await,
            #[cfg(windows)]
            Self::Managed(socket) => socket.readable().await,
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.recv_buf_from(payload).await,
            #[cfg(windows)]
            Self::Managed(socket) => socket.recv_buf_from(payload).await,
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.try_recv_buf_from(payload),
            #[cfg(windows)]
            Self::Managed(socket) => socket.try_recv_buf_from(payload),
        }
    }
}

pub(in crate::run) struct ClientUdpLeg {
    protocol: UdpClientSession,
    id: UdpSessionId,
}

pub(in crate::run) struct ClientUdpPlan {
    legs: Vec<ClientUdpLeg>,
}

pub(in crate::run) const MAX_UDP_PLAN_HOPS: usize = 8;

impl Drop for ClientUdpAssociation {
    fn drop(&mut self) {
        self.manager.remove(self.handle);
        if let (Some(protocol), Ok(mut live_ids)) = (&self.protocol, self.live_ids.lock()) {
            for leg in &protocol.legs {
                live_ids.remove(&leg.id);
            }
        }
    }
}

impl ClientUdpAssociation {
    pub(in crate::run) fn activate<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
    ) -> Result<(), ()>
    where
        R: SecureRandom,
    {
        if matches!(self.upstream, ClientUdpUpstream::Direct(_)) {
            return Ok(());
        }
        if self.protocol.is_some() {
            return Ok(());
        }
        #[cfg(test)]
        let random = egress.udp_id_random.as_deref().unwrap_or(&egress.random);
        #[cfg(not(test))]
        let random = &egress.random;
        let legs = register_udp_plan(
            &egress.outbounds,
            self.plan.as_ref().ok_or(())?.hops(),
            random,
            &self.live_ids,
        )?;
        self.protocol = Some(ClientUdpPlan { legs });
        Ok(())
    }

    pub(in crate::run) fn cancellation(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<bool>, UdpRuntimeError> {
        self.manager.cancellation(self.handle)
    }

    pub(in crate::run) fn idle_deadline(&self) -> Result<Instant, UdpRuntimeError> {
        self.manager.idle_deadline(self.handle)
    }

    pub(in crate::run) fn idle_expired(&self, observed: Instant) -> bool {
        Instant::now() >= self.manager.idle_deadline(self.handle).unwrap_or(observed)
    }

    pub(in crate::run) fn encode_request<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        datagram: &Datagram,
    ) -> Result<usize, UdpPacketError>
    where
        T: Clock,
        R: SecureRandom,
    {
        let Self {
            plan,
            protocol,
            inner_wire,
            upstream_wire,
            scratch,
            ..
        } = self;
        let inner_wire = inner_wire
            .as_mut()
            .expect("proxy UDP association owns its inner wire buffer");
        let upstream_wire = upstream_wire
            .as_mut()
            .expect("proxy UDP association owns its upstream wire buffer");
        let scratch = scratch
            .as_mut()
            .expect("proxy UDP association owns its packet scratch");
        let hops = plan.as_ref().expect("proxy UDP plan").hops();
        let plan = protocol
            .as_mut()
            .expect("client UDP protocol is activated before encode");
        let mut wire_len = 0;
        let mut wire_in_upstream = false;
        for layer in (0..hops.len()).rev() {
            let intermediate;
            let target = if layer + 1 == hops.len() {
                datagram.target()
            } else {
                intermediate = TargetAddr::ip(
                    outbounds
                        .get(hops[layer + 1])
                        .and_then(ClientOutboundContext::shadowsocks)
                        .ok_or(UdpPacketError::StateUnavailable)?
                        .udp_server,
                )
                .map_err(|_| UdpPacketError::Bounds)?;
                &intermediate
            };
            wire_len = if layer + 1 == hops.len() {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    datagram.payload(),
                    0,
                    upstream_wire,
                    scratch,
                )?
            } else if wire_in_upstream {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    &upstream_wire[..wire_len],
                    0,
                    inner_wire,
                    scratch,
                )?
            } else {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    &inner_wire[..wire_len],
                    0,
                    upstream_wire,
                    scratch,
                )?
            };
            wire_in_upstream = layer + 1 == hops.len() || !wire_in_upstream;
        }
        if !wire_in_upstream {
            upstream_wire[..wire_len].copy_from_slice(&inner_wire[..wire_len]);
        }
        Ok(wire_len)
    }

    pub(in crate::run) fn accept_response<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError>
    where
        T: Clock,
    {
        let Self {
            plan,
            protocol,
            manager,
            handle,
            meter_global_buffers,
            inner_wire,
            upstream_wire,
            scratch,
            ..
        } = self;
        let inner_wire = inner_wire
            .as_mut()
            .expect("proxy UDP association owns its inner wire buffer");
        let upstream_wire = upstream_wire
            .as_mut()
            .expect("proxy UDP association owns its upstream wire buffer");
        let scratch = scratch
            .as_mut()
            .expect("proxy UDP association owns its packet scratch");
        let hops = plan.as_ref().expect("proxy UDP plan").hops();
        let plan = protocol
            .as_ref()
            .expect("client UDP protocol is activated before response");
        let outer = plan.legs[0]
            .protocol
            .prepare_response_borrowed(&egress.clock, &upstream_wire[..wire_len], scratch)
            .map_err(UdpPlanResponseError::Packet)?;
        let mut commits = Vec::with_capacity(hops.len());
        if hops.len() == 1 {
            return commit_final_udp_response(
                outer,
                plan,
                hops,
                outbounds,
                commits,
                manager,
                *handle,
                *meter_global_buffers,
                &egress.clock,
            );
        }
        let expected = TargetAddr::ip(
            outbounds
                .get(hops[1])
                .and_then(ClientOutboundContext::shadowsocks)
                .ok_or(UdpPlanResponseError::Packet(
                    UdpPacketError::StateUnavailable,
                ))?
                .udp_server,
        )
        .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        if !outer.target_matches(&expected) {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
        }
        let mut inner_len = outer
            .copy_payload_to(inner_wire)
            .map_err(UdpPlanResponseError::Packet)?;
        commits.push(outer.into_commit());
        let mut wire_in_inner = true;
        for layer in 1..hops.len() {
            let pending = if wire_in_inner {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    &egress.clock,
                    &inner_wire[..inner_len],
                    scratch,
                )
            } else {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    &egress.clock,
                    &upstream_wire[..inner_len],
                    scratch,
                )
            }
            .map_err(UdpPlanResponseError::Packet)?;
            if layer + 1 == hops.len() {
                return commit_final_udp_response(
                    pending,
                    plan,
                    hops,
                    outbounds,
                    commits,
                    manager,
                    *handle,
                    *meter_global_buffers,
                    &egress.clock,
                );
            }
            let expected = TargetAddr::ip(
                outbounds
                    .get(hops[layer + 1])
                    .and_then(ClientOutboundContext::shadowsocks)
                    .ok_or(UdpPlanResponseError::Packet(
                        UdpPacketError::StateUnavailable,
                    ))?
                    .udp_server,
            )
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
            if !pending.target_matches(&expected) {
                return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
            }
            inner_len = if wire_in_inner {
                pending.copy_payload_to(upstream_wire)
            } else {
                pending.copy_payload_to(inner_wire)
            }
            .map_err(UdpPlanResponseError::Packet)?;
            commits.push(pending.into_commit());
            wire_in_inner = !wire_in_inner;
        }
        unreachable!("validated UDP plan has a final layer")
    }

    pub(in crate::run) fn reserve_application_datagram(
        &self,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        match self.pending_session.as_ref() {
            Some(session) if self.meter_global_buffers => {
                session.reserve_datagram(UdpDirection::ToTarget, allocated_capacity)
            }
            Some(session) => {
                session.reserve_unmetered_datagram(UdpDirection::ToTarget, allocated_capacity)
            }
            None if self.meter_global_buffers => self.manager.reserve_datagram(
                self.handle,
                UdpDirection::ToTarget,
                allocated_capacity,
            ),
            None => self.manager.reserve_unmetered_datagram(
                self.handle,
                UdpDirection::ToTarget,
                allocated_capacity,
            ),
        }
    }

    fn reserve_response_datagram(
        &self,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        if self.meter_global_buffers {
            self.manager
                .reserve_datagram(self.handle, UdpDirection::ToClient, allocated_capacity)
        } else {
            self.manager.reserve_unmetered_datagram(
                self.handle,
                UdpDirection::ToClient,
                allocated_capacity,
            )
        }
    }

    pub(in crate::run) fn commit_application_datagram(
        &mut self,
        reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        match self.pending_session.take() {
            Some(session) => session
                .commit_immediate(reservation, datagram, now)
                .map(|(_, datagram)| datagram),
            None => reservation.commit_immediate(datagram, now),
        }
    }

    pub(in crate::run) fn payload_limit(
        &self,
        outbounds: &[ClientOutboundContext],
        response: bool,
        encoded_target_len: usize,
    ) -> usize {
        match &self.upstream {
            ClientUdpUpstream::Direct(_) => MAX_UDP_WIRE_DATAGRAM_BYTES,
            ClientUdpUpstream::Shadowsocks(_) => composed_udp_plan_limit(
                outbounds,
                self.plan.as_ref().expect("proxy UDP plan").hops(),
                response,
                encoded_target_len,
            ),
        }
    }

    pub(in crate::run) fn prepare_application_request<C, T, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError>
    where
        T: Clock,
        R: SecureRandom,
    {
        self.prepare_owned_application_request(
            engine,
            outbounds,
            target,
            BytesMut::from(payload),
            now,
        )
    }

    pub(in crate::run) fn prepare_owned_application_request<C, T, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: BytesMut,
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError>
    where
        T: Clock,
        R: SecureRandom,
    {
        let encoded_target_len = match target.host() {
            TargetHostRef::Ip(std::net::IpAddr::V4(_)) => 7,
            TargetHostRef::Ip(std::net::IpAddr::V6(_)) => 19,
            TargetHostRef::Domain(name) => 3_usize
                .checked_add(name.len())
                .ok_or(UdpPlanResponseError::Packet(UdpPacketError::Bounds))?,
        };
        if payload.len() > self.payload_limit(outbounds, false, encoded_target_len) {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        let payload_len = payload.len();
        let reservation = self
            .reserve_application_datagram(payload.capacity())
            .map_err(UdpPlanResponseError::Runtime)?;
        let datagram = Datagram::new(target, payload, payload_len)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        let datagram = self
            .commit_application_datagram(reservation, datagram, now)
            .map_err(UdpPlanResponseError::Runtime)?;
        let wire_len = if matches!(self.upstream, ClientUdpUpstream::Direct(_)) {
            self.direct_target = Some(datagram.datagram().target().clone());
            let direct_wire = self
                .direct_wire
                .as_mut()
                .expect("direct UDP association owns its request wire buffer");
            direct_wire.clear();
            direct_wire.extend_from_slice(datagram.datagram().payload());
            payload_len
        } else {
            self.encode_request(engine, outbounds, datagram.datagram())
                .map_err(UdpPlanResponseError::Packet)?
        };
        Ok(wire_len)
    }

    pub(in crate::run) fn prepare_application_response<C, T, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError>
    where
        T: Clock,
    {
        let response = if matches!(self.upstream, ClientUdpUpstream::Direct(_)) {
            let (payload, source) =
                self.pending_direct_response
                    .take()
                    .ok_or(UdpPlanResponseError::Packet(
                        UdpPacketError::StateUnavailable,
                    ))?;
            if payload.len() != wire_len {
                self.restore_direct_wire(payload);
                return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
            }
            let reservation = match self.reserve_response_datagram(payload.capacity()) {
                Ok(reservation) => reservation,
                Err(error) => {
                    self.restore_direct_wire(payload);
                    return Err(UdpPlanResponseError::Runtime(error));
                }
            };
            let target = TargetAddr::ip(source)
                .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
            let datagram = Datagram::new(target, payload, MAX_UDP_WIRE_DATAGRAM_BYTES)
                .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
            reservation
                .commit_immediate(datagram, Instant::now())
                .map_err(UdpPlanResponseError::Runtime)?
        } else {
            self.accept_response(engine, outbounds, wire_len)?
        };
        Ok(response)
    }

    fn restore_direct_wire(&mut self, mut wire: BytesMut) {
        wire.clear();
        if wire.capacity() < MAX_UDP_WIRE_DATAGRAM_BYTES {
            wire.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES);
        }
        debug_assert!(self.direct_wire.is_none());
        self.direct_wire = Some(wire);
    }

    pub(in crate::run) fn recycle_application_response(&mut self, response: AccountedDatagram) {
        if !matches!(self.upstream, ClientUdpUpstream::Direct(_)) {
            drop(response);
            return;
        }
        let (datagram, reservation) = response.into_parts();
        let (_, payload) = datagram.into_parts();
        let wire = match payload.try_into_mut() {
            Ok(wire) => wire,
            Err(payload) => payload.into(),
        };
        self.restore_direct_wire(wire);
        drop(reservation);
    }

    pub(in crate::run) async fn send_encoded_request(
        &mut self,
        wire_len: usize,
    ) -> io::Result<usize> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamSend))
        {
            return Err(io::Error::other("injected upstream send failure"));
        }
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => {
                let upstream_wire = self
                    .upstream_wire
                    .as_ref()
                    .expect("proxy UDP association owns its upstream wire buffer");
                socket.send(&upstream_wire[..wire_len]).await
            }
            ClientUdpUpstream::Direct(socket) => {
                let tracks_outstanding =
                    self.direct_response_policy == DirectUdpResponsePolicy::OutstandingPeers;
                if tracks_outstanding && self.direct_peers.len() >= UDP_SESSION_QUEUE_DEPTH {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "direct UDP outstanding queue is full",
                    ));
                }
                let target = self
                    .direct_target
                    .as_ref()
                    .ok_or_else(|| io::Error::other("direct UDP target unavailable"))?;
                let direct_wire = self
                    .direct_wire
                    .as_ref()
                    .expect("direct UDP association owns its request wire buffer");
                let (length, peer) = send_direct_target(
                    socket,
                    &self.direct_resolver,
                    &mut self.direct_candidate_hints,
                    target,
                    &direct_wire[..wire_len],
                    self.direct_timeout,
                )
                .await?;
                if tracks_outstanding {
                    self.direct_peers.push_back(peer);
                }
                Ok(length)
            }
        }
    }

    pub(in crate::run) async fn receive_response_wire(&mut self) -> io::Result<usize> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamRecv))
        {
            return Err(io::Error::other("injected upstream receive failure"));
        }
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => {
                let upstream_wire = self
                    .upstream_wire
                    .as_mut()
                    .expect("proxy UDP association owns its upstream wire buffer");
                socket.recv(upstream_wire).await
            }
            ClientUdpUpstream::Direct(socket) => {
                if self.pending_direct_response.is_some() {
                    return Err(io::Error::other("direct UDP response was not consumed"));
                }
                let (length, source, response_match) = receive_direct_response(
                    socket,
                    &self.direct_peers,
                    self.direct_response_policy,
                    self.direct_wire
                        .as_mut()
                        .ok_or_else(|| io::Error::other("direct UDP wire buffer unavailable"))?,
                )
                .await?;
                let mut payload = self
                    .direct_wire
                    .take()
                    .expect("direct UDP receive owns its wire buffer");
                let unused = payload.split_off(length);
                drop(unused);
                if let DirectUdpResponseMatch::OutstandingPeer(position) = response_match {
                    self.direct_peers.remove(position);
                }
                self.pending_direct_response = Some((payload, source));
                Ok(length)
            }
        }
    }

    #[cfg(test)]
    pub(in crate::run) fn upstream_local_addr(&self) -> io::Result<SocketAddr> {
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => socket.local_addr(),
            ClientUdpUpstream::Direct(_) => Err(io::Error::other("direct UDP socket is opaque")),
        }
    }

    #[cfg(test)]
    pub(in crate::run) fn handle(&self) -> UdpSessionHandle {
        self.handle
    }

    #[cfg(test)]
    pub(in crate::run) fn set_io_fault(&mut self, fault: Option<Arc<UdpIoFaultPlan>>) {
        self.io_fault = fault;
    }

    pub(in crate::run) async fn relay<C, T, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        plan: Option<&EgressPlanSnapshot>,
        destination: TargetAddr,
        packet: Vec<u8>,
    ) -> io::Result<(Vec<u8>, bool)>
    where
        T: Clock,
        R: SecureRandom,
    {
        if packet.len() > MAX_UDP_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP packet too large",
            ));
        }
        if self.plan.as_ref() != plan {
            return Err(invalid_dns_target());
        }
        let expected_response_target = destination.clone();
        self.activate(engine).map_err(|_| runtime_error(()))?;
        let wire_len = self
            .prepare_owned_application_request(
                engine,
                &engine.outbounds,
                destination,
                bytes::Bytes::from(packet).into(),
                Instant::now(),
            )
            .map_err(|_| io::Error::other("DNS UDP encode failed"))?;
        let sent = self.send_encoded_request(wire_len).await?;
        if sent != wire_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short DNS UDP send",
            ));
        }
        let mut reusable = self.first_server.is_some();
        loop {
            let length = self.receive_response_wire().await?;
            let response =
                match self.prepare_application_response(engine, &engine.outbounds, length) {
                    Ok(response) => response,
                    Err(_) => {
                        reusable = false;
                        continue;
                    }
                };
            if !dns_response_target_matches(&expected_response_target, response.datagram().target())
            {
                reusable = false;
                self.recycle_application_response(response);
                continue;
            }
            let payload = response.datagram().payload().to_vec();
            self.recycle_application_response(response);
            return Ok((payload, reusable));
        }
    }
}

/// Binds connected DNS UDP responses to the logical target selected for the
/// query. A numeric target is exact. A deferred domain may be returned either
/// verbatim or as the IP selected by the authenticated remote resolver, but it
/// must retain the requested port.
fn dns_response_target_matches(expected: &TargetAddr, actual: &TargetAddr) -> bool {
    if expected.port() != actual.port() {
        return false;
    }
    match (expected.host(), actual.host()) {
        (TargetHostRef::Ip(expected), TargetHostRef::Ip(actual)) => expected == actual,
        (TargetHostRef::Domain(expected), TargetHostRef::Domain(actual)) => {
            expected.eq_ignore_ascii_case(actual)
        }
        (TargetHostRef::Domain(_), TargetHostRef::Ip(_)) => true,
        (TargetHostRef::Ip(_), TargetHostRef::Domain(_)) => false,
    }
}

#[cfg(windows)]
struct ClientManagedUdpOperations<'a, C, T, R, F, Fut> {
    egress: &'a ClientEgressEngine<C, T, R>,
    bind: &'a mut F,
    _future: std::marker::PhantomData<fn() -> Fut>,
}

#[cfg(windows)]
impl<C, T, R, F, Fut> ManagedUdpOperations for ClientManagedUdpOperations<'_, C, T, R, F, Fut>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    type Socket = UdpSocket;

    async fn open_v4(&mut self) -> io::Result<Self::Socket> {
        #[cfg(test)]
        self.egress
            .record_managed_udp_event(ManagedUdpEvent::OpenV4)
            .map_err(|()| io::Error::other("injected managed UDP open failure"))?;
        (self.bind)(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await
    }

    async fn open_v6(&mut self) -> io::Result<Self::Socket> {
        #[cfg(test)]
        self.egress
            .record_managed_udp_event(ManagedUdpEvent::OpenV6)
            .map_err(|()| io::Error::other("injected managed UDP open failure"))?;
        (self.bind)(SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)).await
    }

    fn bind_fixed(&self, _socket: &Self::Socket, endpoint: SocketAddr) -> Result<(), ()> {
        #[cfg(test)]
        return self
            .egress
            .record_managed_udp_event(ManagedUdpEvent::BindFixed(endpoint));
        #[cfg(not(test))]
        self.egress
            .underlay
            .bind_fixed(_socket, endpoint)
            .map_err(|_| ())
    }

    fn bind_target(&self, _socket: &Self::Socket, target: SocketAddr) -> Result<(), ()> {
        #[cfg(test)]
        return self
            .egress
            .record_managed_udp_event(ManagedUdpEvent::BindTarget(target));
        #[cfg(not(test))]
        self.egress
            .underlay
            .bind_target(_socket, target)
            .map_err(|_| ())
    }

    async fn connect(&self, socket: &Self::Socket, endpoint: SocketAddr) -> io::Result<()> {
        #[cfg(test)]
        self.egress
            .record_managed_udp_event(ManagedUdpEvent::Connect(endpoint))
            .map_err(|()| io::Error::other("injected managed UDP connect failure"))?;
        socket.connect(endpoint).await
    }
}

pub(in crate::run) async fn prepare<C, T, R, F, Fut>(
    egress: &ClientEgressEngine<C, T, R>,
    origin: ClientRequestOrigin,
    ingress: usize,
    plan: Option<EgressPlanSnapshot>,
    selected: SelectedEgress,
    target: Option<&TargetAddr>,
    mut bind: F,
) -> Result<ClientUdpAssociation, ()>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    #[cfg(windows)]
    let managed_binding = managed_udp_binding(origin, selected, egress.auto_route, target)?;
    #[cfg(not(windows))]
    let _ = (origin, target);
    let udp = egress.udp.as_ref().ok_or(())?;
    let direct_resolver = match selected {
        SelectedEgress::Direct {
            outbound: Some(outbound),
        } => egress
            .direct_resolvers
            .get(outbound)
            .and_then(Option::as_ref)
            .ok_or(())?
            .for_ingress(ingress),
        SelectedEgress::Direct { outbound: None } | SelectedEgress::Shadowsocks { .. } => {
            egress.application_resolver.for_ingress(ingress)
        }
    };
    let pending_session = udp
        .manager
        .reserve_session(Instant::now())
        .map_err(|_| ())?;
    let handle = pending_session.handle();
    let meter_global_buffers = origin != ClientRequestOrigin::Tun;
    let budget = udp.manager.buffer_budget();
    let fixed_buffer_count = match selected {
        SelectedEgress::Direct { .. } => 1,
        SelectedEgress::Shadowsocks { .. } => 3,
    };
    let mut fixed_capacity = Vec::with_capacity(fixed_buffer_count);
    if meter_global_buffers {
        for _ in 0..fixed_buffer_count {
            let capacity = match selected {
                SelectedEgress::Direct { .. } => MAX_UDP_WIRE_DATAGRAM_BYTES,
                SelectedEgress::Shadowsocks { .. } => MAX_UDP_WIRE_LEN,
            };
            fixed_capacity.push(budget.reserve(capacity).map_err(|_| ())?);
        }
    }
    let inner_wire = matches!(selected, SelectedEgress::Shadowsocks { .. })
        .then(|| vec![0_u8; MAX_UDP_WIRE_LEN]);
    let upstream_wire = matches!(selected, SelectedEgress::Shadowsocks { .. })
        .then(|| vec![0_u8; MAX_UDP_WIRE_LEN]);
    let scratch =
        matches!(selected, SelectedEgress::Shadowsocks { .. }).then(UdpPacketScratch::new);
    let first_server = match selected {
        SelectedEgress::Shadowsocks { first_server } => Some(first_server),
        SelectedEgress::Direct { .. } => None,
    };
    let direct_response_policy = match (selected, origin) {
        (SelectedEgress::Direct { .. }, ClientRequestOrigin::Tun) => {
            let endpoint = target.and_then(TargetAddr::as_socket_addr).ok_or(())?;
            DirectUdpResponsePolicy::TunSink(if endpoint.is_ipv4() {
                DirectUdpFamily::Ipv4
            } else {
                DirectUdpFamily::Ipv6
            })
        }
        _ => DirectUdpResponsePolicy::OutstandingPeers,
    };
    let upstream = match selected {
        SelectedEgress::Shadowsocks { first_server } => {
            #[cfg(windows)]
            let upstream = if let Some(binding) = managed_binding {
                open_managed_udp(
                    &mut ClientManagedUdpOperations {
                        egress,
                        bind: &mut bind,
                        _future: std::marker::PhantomData,
                    },
                    binding,
                    Some(first_server),
                )
                .await?
            } else {
                let bind_address = if first_server.is_ipv4() {
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                } else {
                    SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
                };
                let upstream = bind(bind_address).await.map_err(|_| ())?;
                upstream.connect(first_server).await.map_err(|_| ())?;
                upstream
            };
            #[cfg(not(windows))]
            let upstream = {
                let bind_address = if first_server.is_ipv4() {
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                } else {
                    SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
                };
                let upstream = bind(bind_address).await.map_err(|_| ())?;
                upstream.connect(first_server).await.map_err(|_| ())?;
                upstream
            };
            ClientUdpUpstream::Shadowsocks(upstream)
        }
        SelectedEgress::Direct { .. } => {
            #[cfg(windows)]
            if let Some(binding) = managed_binding {
                let socket = open_managed_udp(
                    &mut ClientManagedUdpOperations {
                        egress,
                        bind: &mut bind,
                        _future: std::marker::PhantomData,
                    },
                    binding,
                    None,
                )
                .await?;
                ClientUdpUpstream::Direct(ClientDirectUdpSocket::Managed(socket))
            } else {
                ClientUdpUpstream::Direct(ClientDirectUdpSocket::System(
                    SystemDirectUdpSocketFactory.open().await.map_err(|_| ())?,
                ))
            }
            #[cfg(not(windows))]
            ClientUdpUpstream::Direct(ClientDirectUdpSocket::System(
                SystemDirectUdpSocketFactory.open().await.map_err(|_| ())?,
            ))
        }
    };
    Ok(ClientUdpAssociation {
        plan,
        first_server,
        protocol: None,
        pending_session: Some(pending_session),
        manager: udp.manager.clone(),
        handle,
        meter_global_buffers,
        live_ids: Arc::clone(&udp.live_ids),
        upstream,
        direct_target: None,
        direct_response_policy,
        direct_peers: VecDeque::with_capacity(UDP_SESSION_QUEUE_DEPTH),
        direct_candidate_hints: DirectUdpCandidateHints::default(),
        direct_resolver,
        direct_timeout: egress.phase_deadlines.0,
        pending_direct_response: None,
        direct_wire: matches!(selected, SelectedEgress::Direct { .. })
            .then(|| BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES)),
        inner_wire,
        upstream_wire,
        scratch,
        _metered_fixed_capacity: fixed_capacity,
        #[cfg(test)]
        io_fault: None,
    })
}

async fn send_direct_target(
    socket: &impl DirectUdpSocket,
    resolver: &impl UdpResolver,
    candidate_hints: &mut DirectUdpCandidateHints,
    target: &TargetAddr,
    payload: &[u8],
    timeout: std::time::Duration,
) -> io::Result<(usize, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    if let Some(target) = target.as_socket_addr() {
        let length = send_direct_candidate(socket, payload, target, deadline).await?;
        return Ok((length, target));
    }
    let TargetHostRef::Domain(host) = target.host() else {
        return Err(io::Error::other("direct UDP target unavailable"));
    };
    let port = target.port().get();
    let candidates = tokio::time::timeout_at(deadline, resolver.resolve(host, target.port().get()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP resolve timeout"))??;
    let candidates = candidates
        .into_iter()
        .take(MAX_UDP_RESOLVED_CANDIDATES)
        .collect::<Vec<_>>();
    let first_index = candidate_hints.start_index(host, port);
    let (length, peer, last_successful_index) =
        send_direct_candidates(socket, payload, &candidates, first_index, deadline).await?;
    candidate_hints.record_success(host, port, last_successful_index);
    Ok((length, peer))
}

async fn send_direct_candidates(
    socket: &impl DirectUdpSocket,
    payload: &[u8],
    candidates: &[SocketAddr],
    first_index: usize,
    deadline: Instant,
) -> io::Result<(usize, SocketAddr, usize)> {
    if candidates.is_empty() {
        return Err(io::Error::other("direct UDP resolution was empty"));
    }
    let mut last = None;
    for offset in 0..candidates.len() {
        let index = (first_index + offset) % candidates.len();
        let candidate = candidates[index];
        match send_direct_candidate(socket, payload, candidate, deadline).await {
            Ok(length) => return Ok((length, candidate, index)),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("direct UDP resolution was empty")))
}

async fn send_direct_candidate(
    socket: &impl DirectUdpSocket,
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
) -> io::Result<usize> {
    tokio::time::timeout_at(deadline, socket.send_to(payload, target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP send timeout"))?
}

async fn receive_direct_response(
    socket: &impl DirectUdpSocket,
    expected_peers: &VecDeque<SocketAddr>,
    policy: DirectUdpResponsePolicy,
    payload: &mut BytesMut,
) -> io::Result<(usize, SocketAddr, DirectUdpResponseMatch)> {
    loop {
        payload.clear();
        let mut received = socket.recv_buf_from(payload).await?;
        for drained in 1..=MAX_DIRECT_UDP_READINESS_DRAIN {
            if received.0 != payload.len() || received.0 > MAX_UDP_WIRE_DATAGRAM_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid direct UDP receive length",
                ));
            }
            if let Some(response_match) = policy.classify(expected_peers, received.1) {
                return Ok((received.0, received.1, response_match));
            }
            if drained == MAX_DIRECT_UDP_READINESS_DRAIN {
                tokio::task::yield_now().await;
                break;
            }
            payload.clear();
            match socket.try_recv_buf_from(payload) {
                Ok(next) => received = next,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
}

fn register_udp_plan(
    outbounds: &[ClientOutboundContext],
    hops: &[usize],
    random: &(impl SecureRandom + ?Sized),
    live_ids: &Mutex<HashSet<UdpSessionId>>,
) -> Result<Vec<ClientUdpLeg>, ()> {
    let mut live_ids = live_ids.lock().map_err(|_| ())?;
    let mut legs: Vec<ClientUdpLeg> = Vec::with_capacity(hops.len());
    for hop in hops {
        let Some(outbound) = outbounds.get(*hop) else {
            for leg in &legs {
                live_ids.remove(&leg.id);
            }
            return Err(());
        };
        let Some(outbound) = outbound.shadowsocks() else {
            for leg in &legs {
                live_ids.remove(&leg.id);
            }
            return Err(());
        };
        let protocol = match UdpClientSession::new(&outbound.keys, random, |candidate| {
            live_ids.contains(candidate)
        }) {
            Ok(protocol) => protocol,
            Err(_) => {
                for leg in &legs {
                    live_ids.remove(&leg.id);
                }
                return Err(());
            }
        };
        let id = protocol.session_id().clone();
        if !live_ids.insert(id.clone()) {
            for leg in &legs {
                live_ids.remove(&leg.id);
            }
            return Err(());
        }
        legs.push(ClientUdpLeg { protocol, id });
    }
    Ok(legs)
}

#[allow(clippy::too_many_arguments)]
fn commit_final_udp_response(
    pending: BorrowedPendingUdpResponse<'_>,
    plan: &ClientUdpPlan,
    hops: &[usize],
    outbounds: &[ClientOutboundContext],
    mut commits: Vec<UdpResponseCommit>,
    manager: &UdpSessionManager,
    handle: UdpSessionHandle,
    meter_global_buffers: bool,
    clock: &(impl Clock + ?Sized),
) -> Result<AccountedDatagram, UdpPlanResponseError> {
    let socks_len = 3_usize
        .checked_add(pending.encoded_target_len())
        .and_then(|len| len.checked_add(pending.payload().len()));
    if socks_len.is_none_or(|len| len > MAX_SOCKS_UDP_DATAGRAM_BYTES)
        || pending.payload().len()
            > composed_udp_plan_limit(outbounds, hops, true, pending.encoded_target_len())
    {
        return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
    }
    let reservation = if meter_global_buffers {
        manager.reserve_datagram(handle, UdpDirection::ToClient, pending.allocated_capacity())
    } else {
        manager.reserve_unmetered_datagram(
            handle,
            UdpDirection::ToClient,
            pending.allocated_capacity(),
        )
    }
    .map_err(UdpPlanResponseError::Runtime)?;
    let (datagram, commit) = pending.materialize().into_parts();
    commits.push(commit);
    let sessions = plan
        .legs
        .iter()
        .map(|leg| &leg.protocol)
        .collect::<Vec<_>>();
    reservation
        .commit_immediate_with(datagram, Instant::now(), || {
            UdpClientSession::commit_responses(&sessions, commits, clock.monotonic_now())
        })
        .map_err(|error| match error {
            UdpCommitError::Protocol(error) => UdpPlanResponseError::Packet(error),
            UdpCommitError::Runtime(error) => UdpPlanResponseError::Runtime(error),
        })
}

#[cfg(test)]
pub(in crate::run) fn register_udp_session<K: ferrum2_crypto::MethodKeyProvider>(
    keys: &MethodKeyAdapter<K>,
    random: &(impl SecureRandom + ?Sized),
    live_ids: &Mutex<HashSet<UdpSessionId>>,
) -> Result<(UdpClientSession, UdpSessionId), ()> {
    let mut live_ids = live_ids.lock().map_err(|_| ())?;
    let protocol = UdpClientSession::new(keys, random, |candidate| live_ids.contains(candidate))
        .map_err(|_| ())?;
    let id = protocol.session_id().clone();
    if !live_ids.insert(id.clone()) {
        return Err(());
    }
    Ok((protocol, id))
}

pub(in crate::run) async fn send_with_lifecycle(
    send: impl std::future::Future<Output = io::Result<usize>>,
    cancellation: &mut ferrum2_runtime::CancellationToken,
    session_cancellation: &mut tokio::sync::watch::Receiver<bool>,
    idle_deadline: Instant,
) -> Result<usize, UdpSendError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(UdpSendError::Cancelled),
        _ = session_cancellation.changed() => Err(UdpSendError::Cancelled),
        _ = tokio::time::sleep_until(idle_deadline) => Err(UdpSendError::Idle),
        sent = send => sent.map_err(|_| UdpSendError::Io),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum UdpSendError {
    Io,
    Cancelled,
    Idle,
}

#[cfg(test)]
pub(in crate::run) fn composed_udp_request_limit(
    method: MethodProfile,
    encoded_target_len: usize,
) -> usize {
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
    let request =
        max_udp_payload_len_for_encoded_target(method, false, encoded_target_len, 0).unwrap_or(0);
    socks.min(request)
}

#[cfg(test)]
pub(in crate::run) fn composed_udp_response_limit(
    method: MethodProfile,
    encoded_target_len: usize,
) -> usize {
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
    let response =
        max_udp_payload_len_for_encoded_target(method, true, encoded_target_len, 0).unwrap_or(0);
    socks.min(response)
}

pub(in crate::run) fn composed_udp_plan_limit(
    outbounds: &[ClientOutboundContext],
    hops: &[usize],
    response: bool,
    encoded_target_len: usize,
) -> usize {
    if hops.is_empty() || hops.len() > MAX_UDP_PLAN_HOPS {
        return 0;
    }
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
    if hops.len() == 1
        && outbounds
            .get(hops[0])
            .is_some_and(|outbound| matches!(outbound, ClientOutboundContext::Direct))
    {
        return socks;
    }
    let overhead = hops
        .iter()
        .enumerate()
        .try_fold(0_usize, |total, (layer, hop)| {
            let profile = outbounds.get(*hop)?.shadowsocks()?.keys.profile();
            let target_len = if layer + 1 == hops.len() {
                encoded_target_len
            } else {
                7
            };
            let payload =
                max_udp_payload_len_for_encoded_target(profile, response, target_len, 0).ok()?;
            total.checked_add(MAX_UDP_WIRE_LEN.checked_sub(payload)?)
        });
    overhead
        .and_then(|overhead| MAX_UDP_WIRE_LEN.checked_sub(overhead))
        .unwrap_or(0)
        .min(socks)
}

pub(in crate::run) enum UdpPlanResponseError {
    Packet(UdpPacketError),
    Runtime(UdpRuntimeError),
}

fn invalid_dns_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS egress target")
}

fn runtime_error(_error: impl Sized) -> io::Error {
    io::Error::other("DNS UDP runtime unavailable")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use ferrum2_crypto::{
        KeySelector, MethodKeyProvider, MethodPsk, MethodSecretKeyRef, MethodSinglePskProvider,
    };
    use ferrum2_runtime::{OwnerRegistry, UdpRuntimeLimits};
    use ferrum2_shadowsocks::UdpServer;

    use super::*;
    use crate::run::test_support::*;

    fn exhaust_budget(
        budget: &ferrum2_runtime::UdpBufferBudget,
        limit: usize,
    ) -> Vec<UdpBufferReservation> {
        let mut remaining = limit
            .checked_sub(budget.reserved_bytes())
            .expect("test budget is not overcommitted");
        let mut held = Vec::new();
        while remaining != 0 {
            let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            held.push(budget.reserve(capacity).expect("fill test budget"));
            remaining -= capacity;
        }
        held
    }

    struct FailingConfiguredApplicationBackend {
        calls: AtomicUsize,
    }

    impl ferrum2_dns::ApplicationResolveBackend for FailingConfiguredApplicationBackend {
        fn resolve<'a>(
            &'a self,
            _request: ferrum2_dns::ApplicationResolveRequest<'a>,
        ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(ferrum2_dns::DnsError::Timeout)
            })
        }
    }

    struct InjectedManagedUdp {
        events: Mutex<Vec<&'static str>>,
        fail_binding: bool,
    }

    impl ManagedUdpOperations for InjectedManagedUdp {
        type Socket = ();

        async fn open_v4(&mut self) -> io::Result<Self::Socket> {
            self.events.lock().unwrap().push("open-v4");
            Ok(())
        }

        async fn open_v6(&mut self) -> io::Result<Self::Socket> {
            self.events.lock().unwrap().push("open-v6");
            Ok(())
        }

        fn bind_fixed(&self, _socket: &Self::Socket, _endpoint: SocketAddr) -> Result<(), ()> {
            self.events.lock().unwrap().push("bind-fixed");
            if self.fail_binding { Err(()) } else { Ok(()) }
        }

        fn bind_target(&self, _socket: &Self::Socket, _target: SocketAddr) -> Result<(), ()> {
            self.events.lock().unwrap().push("bind-target");
            if self.fail_binding { Err(()) } else { Ok(()) }
        }

        async fn connect(&self, _socket: &Self::Socket, _endpoint: SocketAddr) -> io::Result<()> {
            self.events.lock().unwrap().push("connect");
            Ok(())
        }
    }

    #[tokio::test]
    async fn managed_udp_children_open_isolated_dual_stack_sockets_in_binding_order() {
        let endpoint: SocketAddr = "198.51.100.8:53".parse().unwrap();
        let mut fixed = InjectedManagedUdp {
            events: Mutex::new(Vec::new()),
            fail_binding: false,
        };
        open_managed_udp(
            &mut fixed,
            ManagedUdpBinding::Fixed(endpoint),
            Some(endpoint),
        )
        .await
        .unwrap();
        assert_eq!(
            *fixed.events.lock().unwrap(),
            ["open-v4", "bind-fixed", "connect"]
        );

        let ipv6: SocketAddr = "[2001:db8::8]:53".parse().unwrap();
        let mut fixed_ipv6 = InjectedManagedUdp {
            events: Mutex::new(Vec::new()),
            fail_binding: false,
        };
        open_managed_udp(&mut fixed_ipv6, ManagedUdpBinding::Fixed(ipv6), Some(ipv6))
            .await
            .unwrap();
        assert_eq!(
            *fixed_ipv6.events.lock().unwrap(),
            ["open-v6", "bind-fixed", "connect"]
        );

        let mut failed = InjectedManagedUdp {
            events: Mutex::new(Vec::new()),
            fail_binding: true,
        };
        assert!(
            open_managed_udp(&mut failed, ManagedUdpBinding::Target(ipv6), Some(ipv6),)
                .await
                .is_err()
        );
        assert_eq!(*failed.events.lock().unwrap(), ["open-v6", "bind-target"]);
    }

    #[test]
    fn dns_direct_fixed_binding_uses_the_numeric_bootstrap() {
        let endpoint: SocketAddr = "198.51.100.8:53".parse().unwrap();
        let target = TargetAddr::ip(endpoint).unwrap();
        let ipv6: SocketAddr = "[2001:db8::8]:53".parse().unwrap();
        let ipv6_target = TargetAddr::ip(ipv6).unwrap();
        let deferred = TargetAddr::domain("deferred-dns.invalid", 53).unwrap();
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct { outbound: None },
                true,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct { outbound: None },
                true,
                Some(&ipv6_target),
            ),
            Ok(Some(ManagedUdpBinding::Fixed(ipv6)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct { outbound: None },
                false,
                Some(&target),
            ),
            Ok(None)
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct { outbound: Some(0) },
                true,
                Some(&deferred),
            ),
            Err(())
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::RuleSet,
                SelectedEgress::Direct { outbound: Some(0) },
                true,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Target(endpoint)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Tun,
                SelectedEgress::Direct { outbound: None },
                false,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Target(endpoint)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Socks,
                SelectedEgress::Direct { outbound: None },
                true,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Target(endpoint)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Socks,
                SelectedEgress::Shadowsocks {
                    first_server: endpoint,
                },
                true,
                None,
            ),
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        );
    }

    #[test]
    fn dns_connected_response_binding_is_exact_or_a_port_preserving_remote_resolution() {
        let numeric = TargetAddr::ip("192.0.2.53:53".parse().unwrap()).unwrap();
        assert!(dns_response_target_matches(&numeric, &numeric));
        assert!(!dns_response_target_matches(
            &numeric,
            &TargetAddr::ip("192.0.2.54:53".parse().unwrap()).unwrap()
        ));
        assert!(!dns_response_target_matches(
            &numeric,
            &TargetAddr::ip("192.0.2.53:5353".parse().unwrap()).unwrap()
        ));
        assert!(!dns_response_target_matches(
            &numeric,
            &TargetAddr::domain("dns.example.test", 53).unwrap()
        ));

        let deferred = TargetAddr::domain("dns.example.test", 53).unwrap();
        assert!(dns_response_target_matches(
            &deferred,
            &TargetAddr::domain("DNS.EXAMPLE.TEST", 53).unwrap()
        ));
        assert!(dns_response_target_matches(
            &deferred,
            &TargetAddr::ip("198.51.100.53:53".parse().unwrap()).unwrap()
        ));
        assert!(!dns_response_target_matches(
            &deferred,
            &TargetAddr::ip("198.51.100.53:5353".parse().unwrap()).unwrap()
        ));
        assert!(!dns_response_target_matches(
            &deferred,
            &TargetAddr::domain("other.example.test", 53).unwrap()
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn dns_direct_fixed_binding_runs_in_the_real_prepare_order() {
        let make_engine = |auto_route| {
            let registry = OwnerRegistry::new();
            ClientEgressEngine::new(
                vec![ClientOutboundContext::Direct].into(),
                TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
                ferrum2_crypto::SystemClock::new(),
                ferrum2_crypto::SystemRandom,
                (Duration::from_secs(1), Duration::from_secs(1)),
                Some(ClientUdpContext {
                    manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
                    live_ids: Arc::new(Mutex::new(HashSet::new())),
                }),
                None,
            )
            .with_underlay(ferrum2_tun::UnderlayPublisher::new(), auto_route)
        };
        let endpoint: SocketAddr = "198.51.100.8:53".parse().unwrap();
        let target = TargetAddr::ip(endpoint).unwrap();

        let engine = make_engine(true);
        let association = engine
            .prepare_udp(ClientRequestOrigin::Dns, None, Some(&target))
            .await
            .unwrap();
        assert_eq!(
            engine.managed_udp_events(),
            [
                ManagedUdpEvent::OpenV4,
                ManagedUdpEvent::BindFixed(endpoint)
            ]
        );
        drop(association);

        let deferred = TargetAddr::domain("deferred-dns.invalid", 53).unwrap();
        let deferred_engine = make_engine(true);
        assert_eq!(
            deferred_engine
                .prepare_udp(
                    ClientRequestOrigin::Dns,
                    Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                    Some(&deferred),
                )
                .await
                .err(),
            Some(super::super::ClientUdpPrepareFailure::Unavailable)
        );
        assert!(deferred_engine.managed_udp_events().is_empty());

        let failed = make_engine(true);
        failed.fail_managed_udp_binding();
        assert_eq!(
            failed
                .prepare_udp(ClientRequestOrigin::Dns, None, Some(&target))
                .await
                .err(),
            Some(super::super::ClientUdpPrepareFailure::Unavailable)
        );
        assert_eq!(
            failed.managed_udp_events(),
            [
                ManagedUdpEvent::OpenV4,
                ManagedUdpEvent::BindFixed(endpoint)
            ]
        );

        let manual = make_engine(false);
        let association = manual
            .prepare_udp(ClientRequestOrigin::Dns, None, Some(&target))
            .await
            .unwrap();
        assert!(manual.managed_udp_events().is_empty());
        drop(association);

        let tun = make_engine(false);
        let association = tun
            .prepare_udp(
                ClientRequestOrigin::Tun,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&target),
            )
            .await
            .unwrap();
        assert_eq!(
            tun.managed_udp_events(),
            [
                ManagedUdpEvent::OpenV4,
                ManagedUdpEvent::BindTarget(endpoint)
            ]
        );
        drop(association);

        let ipv6: SocketAddr = "[2001:db8::8]:53".parse().unwrap();
        let ipv6_target = TargetAddr::ip(ipv6).unwrap();
        let tun_ipv6 = make_engine(false);
        let association = tun_ipv6
            .prepare_udp(
                ClientRequestOrigin::Tun,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&ipv6_target),
            )
            .await
            .unwrap();
        assert_eq!(
            tun_ipv6.managed_udp_events(),
            [ManagedUdpEvent::OpenV6, ManagedUdpEvent::BindTarget(ipv6)]
        );
        drop(association);
    }

    struct DirectTestResolver {
        candidates: Option<Vec<SocketAddr>>,
        calls: AtomicUsize,
    }

    impl UdpResolver for DirectTestResolver {
        type Candidates = Vec<SocketAddr>;

        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.candidates
                .clone()
                .ok_or_else(|| io::Error::other("injected resolver failure"))
        }
    }

    struct DirectTestSocket {
        attempts: Mutex<Vec<SocketAddr>>,
        succeed_at: Option<usize>,
    }

    impl DirectUdpSocket for DirectTestSocket {
        async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
            let mut attempts = self.attempts.lock().expect("direct send attempts");
            attempts.push(target);
            if self.succeed_at == Some(attempts.len()) {
                Ok(payload.len())
            } else {
                Err(io::Error::other("injected direct send failure"))
            }
        }

        async fn readable(&self) -> io::Result<()> {
            Ok(())
        }

        async fn recv_buf_from(&self, _payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("receive is unused"))
        }

        fn try_recv_buf_from(&self, _payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("receive is unused"))
        }
    }

    struct SequencedDirectTestResolver {
        answers: Mutex<VecDeque<Result<Vec<SocketAddr>, io::ErrorKind>>>,
        calls: AtomicUsize,
    }

    impl UdpResolver for SequencedDirectTestResolver {
        type Candidates = Vec<SocketAddr>;

        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self
                .answers
                .lock()
                .expect("sequenced resolver answers")
                .pop_front()
                .ok_or_else(|| io::Error::other("injected resolver exhaustion"))?
            {
                Ok(candidates) => Ok(candidates),
                Err(kind) => Err(io::Error::from(kind)),
            }
        }
    }

    struct SelectiveDirectTestSocket {
        attempts: Mutex<Vec<SocketAddr>>,
        successful: Mutex<HashSet<SocketAddr>>,
    }

    impl SelectiveDirectTestSocket {
        fn set_successful(&self, candidates: impl IntoIterator<Item = SocketAddr>) {
            *self.successful.lock().expect("successful candidates") =
                candidates.into_iter().collect();
        }

        fn take_attempts(&self) -> Vec<SocketAddr> {
            std::mem::take(&mut *self.attempts.lock().expect("selective attempts"))
        }
    }

    impl DirectUdpSocket for SelectiveDirectTestSocket {
        async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
            self.attempts
                .lock()
                .expect("selective attempts")
                .push(target);
            if self
                .successful
                .lock()
                .expect("successful candidates")
                .contains(&target)
            {
                Ok(payload.len())
            } else {
                Err(io::Error::other("injected direct send failure"))
            }
        }

        async fn readable(&self) -> io::Result<()> {
            Ok(())
        }

        async fn recv_buf_from(&self, _payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("receive is unused"))
        }

        fn try_recv_buf_from(&self, _payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("receive is unused"))
        }
    }

    struct ScriptedDirectUdpSocket {
        awaited: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        ready: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        awaited_calls: AtomicUsize,
        try_calls: AtomicUsize,
    }

    impl ScriptedDirectUdpSocket {
        fn receive(
            queue: &Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
            payload: &mut BytesMut,
        ) -> io::Result<(usize, SocketAddr)> {
            let (packet, source) = queue
                .lock()
                .expect("scripted receive queue")
                .pop_front()
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            let length = packet.len();
            payload.extend_from_slice(&packet);
            Ok((length, source))
        }
    }

    impl DirectUdpSocket for ScriptedDirectUdpSocket {
        async fn send_to(&self, payload: &[u8], _target: SocketAddr) -> io::Result<usize> {
            Ok(payload.len())
        }

        async fn readable(&self) -> io::Result<()> {
            Ok(())
        }

        async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            self.awaited_calls.fetch_add(1, Ordering::SeqCst);
            Self::receive(&self.awaited, payload)
        }

        fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            self.try_calls.fetch_add(1, Ordering::SeqCst);
            Self::receive(&self.ready, payload)
        }
    }

    #[test]
    fn direct_response_policies_separate_tun_family_from_exact_outstanding_peer() {
        let expected: SocketAddr = "192.0.2.8:53".parse().unwrap();
        let alternate_port: SocketAddr = "192.0.2.8:5353".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::8]:53".parse().unwrap();
        let peers = VecDeque::from([expected]);

        assert_eq!(
            DirectUdpResponsePolicy::OutstandingPeers.classify(&peers, expected),
            Some(DirectUdpResponseMatch::OutstandingPeer(0))
        );
        assert_eq!(
            DirectUdpResponsePolicy::OutstandingPeers.classify(&peers, alternate_port),
            None,
            "SOCKS and DNS remain bound to an exact outstanding endpoint"
        );
        assert_eq!(
            DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv4)
                .classify(&VecDeque::new(), alternate_port),
            Some(DirectUdpResponseMatch::TunSink),
            "TUN defers same-family source admission to its ADF/EIF sink"
        );
        assert_eq!(
            DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv4).classify(&peers, ipv6),
            None
        );
        assert_eq!(
            DirectUdpResponsePolicy::TunSink(DirectUdpFamily::Ipv6).classify(&peers, expected),
            None
        );
    }

    #[tokio::test]
    async fn direct_response_readiness_drain_is_bounded_and_yields() {
        let invalid: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let expected: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let socket = ScriptedDirectUdpSocket {
            awaited: Mutex::new(VecDeque::from([
                (b"first-spoof".to_vec(), invalid),
                (b"accepted".to_vec(), expected),
            ])),
            ready: Mutex::new(
                (1..MAX_DIRECT_UDP_READINESS_DRAIN)
                    .map(|_| (b"ready-spoof".to_vec(), invalid))
                    .collect(),
            ),
            awaited_calls: AtomicUsize::new(0),
            try_calls: AtomicUsize::new(0),
        };
        let scheduler_ran = Arc::new(AtomicBool::new(false));
        let scheduler_probe = Arc::clone(&scheduler_ran);
        let probe = tokio::spawn(async move {
            scheduler_probe.store(true, Ordering::SeqCst);
        });
        let mut payload = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
        let peers = VecDeque::from([expected]);

        let (length, source, response_match) = receive_direct_response(
            &socket,
            &peers,
            DirectUdpResponsePolicy::OutstandingPeers,
            &mut payload,
        )
        .await
        .expect("bounded drain response");

        assert!(scheduler_ran.load(Ordering::SeqCst));
        probe.await.expect("scheduler probe");
        assert_eq!(socket.awaited_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            socket.try_calls.load(Ordering::SeqCst),
            MAX_DIRECT_UDP_READINESS_DRAIN - 1
        );
        assert_eq!((length, source), (8, expected));
        assert_eq!(response_match, DirectUdpResponseMatch::OutstandingPeer(0));
        assert_eq!(&payload[..], b"accepted");
    }

    #[tokio::test]
    async fn direct_tun_udp_defers_adf_port_filtering_and_has_no_outstanding_send_gate() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
                .expect("test limits"),
            registry.clone(),
        );
        let budget = manager.buffer_budget();
        let held_budget = exhaust_budget(&budget, budget_limit);
        assert_eq!(budget.reserved_bytes(), budget_limit);
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Direct].into(),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager,
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("TUN target bind");
        let target_endpoint = target_socket.local_addr().expect("TUN target address");
        let target = TargetAddr::ip(target_endpoint).expect("TUN target");
        let mut association = engine
            .prepare_udp(
                ClientRequestOrigin::Tun,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&target),
            )
            .await
            .expect("direct TUN association");
        assert_eq!(budget.reserved_bytes(), budget_limit);
        association.activate(&engine).expect("direct activation");

        for sequence in 0..=UDP_SESSION_QUEUE_DEPTH {
            let payload = [u8::try_from(sequence).expect("bounded sequence")];
            let length = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target.clone(),
                    &payload,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("TUN direct request"));
            assert_eq!(association.send_encoded_request(length).await.unwrap(), 1);
            assert_eq!(budget.reserved_bytes(), budget_limit);
        }
        assert!(
            association.direct_peers.is_empty(),
            "TUN sends must not consume the SOCKS/DNS outstanding queue"
        );

        let mut wire = [0_u8; 8];
        let mut association_endpoint = None;
        let mut received_sequences = Vec::with_capacity(UDP_SESSION_QUEUE_DEPTH + 1);
        for _ in 0..=UDP_SESSION_QUEUE_DEPTH {
            let (length, peer) =
                tokio::time::timeout(Duration::from_secs(1), target_socket.recv_from(&mut wire))
                    .await
                    .expect("TUN target receive timeout")
                    .expect("TUN target receive");
            assert_eq!(length, 1);
            received_sequences.push(wire[0]);
            match association_endpoint {
                Some(expected) => assert_eq!(peer, expected),
                None => association_endpoint = Some(peer),
            }
        }
        received_sequences.sort_unstable();
        assert_eq!(
            received_sequences,
            (0..=UDP_SESSION_QUEUE_DEPTH)
                .map(|sequence| u8::try_from(sequence).expect("bounded sequence"))
                .collect::<Vec<_>>()
        );
        let association_endpoint = association_endpoint.expect("direct association endpoint");

        for payload in [b"alternate-one".as_slice(), b"alternate-two".as_slice()] {
            let alternate = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("alternate source bind");
            let alternate_endpoint = alternate.local_addr().expect("alternate source address");
            assert_ne!(alternate_endpoint.port(), target_endpoint.port());
            alternate
                .send_to(payload, association_endpoint)
                .await
                .expect("alternate source send");

            let length =
                tokio::time::timeout(Duration::from_secs(1), association.receive_response_wire())
                    .await
                    .expect("same-family alternate-port response timeout")
                    .expect("same-family alternate-port response");
            let response = association
                .prepare_application_response(&engine, &engine.outbounds, length)
                .unwrap_or_else(|_| panic!("TUN direct response"));
            assert_eq!(
                response.datagram().target(),
                &TargetAddr::ip(alternate_endpoint).expect("alternate target")
            );
            assert_eq!(response.datagram().payload(), payload);
            assert_eq!(budget.reserved_bytes(), budget_limit);
            association.recycle_application_response(response);
            assert_eq!(budget.reserved_bytes(), budget_limit);
        }

        drop(association);
        assert_eq!(budget.reserved_bytes(), budget_limit);
        drop(held_budget);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot(), baseline);
    }

    #[tokio::test]
    async fn one_proxy_tun_udp_association_serves_multiple_targets_without_global_budget() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
                .expect("test limits"),
            registry.clone(),
        );
        let budget = manager.buffer_budget();
        let held_budget = exhaust_budget(&budget, budget_limit);
        let proxy_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("proxy bind");
        let proxy_endpoint = proxy_socket.local_addr().expect("proxy address");
        let outbounds = super::super::prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: proxy_endpoint,
                psk: Arc::new(default_test_psk()),
                dial_options: Default::default(),
            },
        ])
        .expect("proxy outbound");
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager,
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        let server_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
        let server = UdpServer::new(&server_keys).expect("proxy protocol");
        let server_clock = ferrum2_crypto::SystemClock::new();
        let server_random = ferrum2_crypto::SystemRandom;
        let targets = [
            TargetAddr::ip("192.0.2.25:53".parse().expect("first target address"))
                .expect("first target"),
            TargetAddr::ip("198.51.100.25:5353".parse().expect("second target address"))
                .expect("second target"),
        ];
        let mut association = engine
            .prepare_udp(
                ClientRequestOrigin::Tun,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&targets[0]),
            )
            .await
            .expect("proxy TUN association with exhausted budget");
        assert_eq!(budget.reserved_bytes(), budget_limit);
        association.activate(&engine).expect("proxy activation");

        let mut request_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
        let mut server_scratch = UdpPacketScratch::new();
        let mut response_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
        let mut association_peer = None;
        for (target, request_payload, expected_response) in [
            (
                &targets[0],
                b"first-request".as_slice(),
                b"first-response".as_slice(),
            ),
            (
                &targets[1],
                b"second-request".as_slice(),
                b"second-response".as_slice(),
            ),
        ] {
            let request_len = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target.clone(),
                    request_payload,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("proxy TUN request with exhausted budget"));
            assert_eq!(budget.reserved_bytes(), budget_limit);
            association
                .send_encoded_request(request_len)
                .await
                .expect("proxy request send");
            let (request_wire_len, peer) = proxy_socket
                .recv_from(&mut request_wire)
                .await
                .expect("proxy request receive");
            match association_peer {
                Some(expected) => assert_eq!(peer, expected, "one proxy socket serves all targets"),
                None => association_peer = Some(peer),
            }
            let pending = server
                .prepare_request(
                    &server_clock,
                    &request_wire[..request_wire_len],
                    &mut server_scratch,
                )
                .expect("proxy request decode");
            let (request, commit) = pending.into_parts();
            assert_eq!(request.target(), target);
            assert_eq!(request.payload(), request_payload);
            let capability = server
                .commit_request(commit, peer, server_clock.monotonic_now(), &server_random)
                .expect("proxy request commit")
                .capability();

            let response_payload = BytesMut::from(expected_response);
            let response_capacity = response_payload.capacity();
            let response = Datagram::new(target.clone(), response_payload, response_capacity)
                .expect("proxy response datagram");
            let encoded = server
                .encode_response(
                    capability,
                    &server_clock,
                    &server_random,
                    &response,
                    0,
                    &mut response_wire,
                    &mut server_scratch,
                )
                .expect("proxy response encode");
            proxy_socket
                .send_to(&response_wire[..encoded.wire_len()], encoded.peer())
                .await
                .expect("proxy response send");
            let response_wire_len = association
                .receive_response_wire()
                .await
                .expect("proxy response receive");
            let response = association
                .prepare_application_response(&engine, &engine.outbounds, response_wire_len)
                .unwrap_or_else(|_| panic!("proxy TUN response with exhausted budget"));
            assert_eq!(response.datagram().target(), target);
            assert_eq!(response.datagram().payload(), expected_response);
            assert_eq!(budget.reserved_bytes(), budget_limit);
            association.recycle_application_response(response);
            assert_eq!(budget.reserved_bytes(), budget_limit);
        }

        drop(association);
        drop(held_budget);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot(), baseline);
    }

    #[tokio::test]
    async fn ordinary_udp_fixed_request_and_response_buffers_remain_globally_metered() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let budget_limit = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(8, budget_limit, ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT)
                .expect("test limits"),
            registry.clone(),
        );
        let budget = manager.buffer_budget();
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Direct].into(),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager,
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("ordinary target bind");
        let target = TargetAddr::ip(echo.local_addr().expect("ordinary target address"))
            .expect("ordinary target");
        let direct_plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let mut association = engine
            .prepare_udp(
                ClientRequestOrigin::Socks,
                Some(direct_plan.clone()),
                Some(&target),
            )
            .await
            .expect("ordinary direct association");
        assert_eq!(
            budget.reserved_bytes(),
            MAX_UDP_WIRE_DATAGRAM_BYTES,
            "ordinary fixed buffer remains globally metered"
        );
        association.activate(&engine).expect("ordinary activation");
        let request_len = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target.clone(),
                b"ordinary-request",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("ordinary request"));
        association
            .send_encoded_request(request_len)
            .await
            .expect("ordinary request send");
        let mut raw = [0_u8; 32];
        let (_, peer) = echo.recv_from(&mut raw).await.expect("ordinary receive");
        echo.send_to(b"ordinary-response", peer)
            .await
            .expect("ordinary response send");
        let response_wire_len = association
            .receive_response_wire()
            .await
            .expect("ordinary response receive");

        let held_budget = exhaust_budget(&budget, budget_limit);
        assert_eq!(budget.reserved_bytes(), budget_limit);
        for origin in [
            ClientRequestOrigin::Socks,
            ClientRequestOrigin::Dns,
            ClientRequestOrigin::RuleSet,
        ] {
            assert!(
                engine
                    .prepare_udp(origin, Some(direct_plan.clone()), Some(&target))
                    .await
                    .is_err(),
                "ordinary association fixed buffers bypassed the full budget for {origin:?}"
            );
            assert_eq!(budget.reserved_bytes(), budget_limit);
        }
        assert!(matches!(
            association
                .prepare_application_response(&engine, &engine.outbounds, response_wire_len,),
            Err(UdpPlanResponseError::Runtime(UdpRuntimeError::BufferLimit))
        ));
        assert!(matches!(
            association.prepare_application_request(
                &engine,
                &engine.outbounds,
                target,
                b"blocked-request",
                Instant::now(),
            ),
            Err(UdpPlanResponseError::Runtime(UdpRuntimeError::BufferLimit))
        ));
        assert_eq!(budget.reserved_bytes(), budget_limit);

        drop(held_budget);
        assert_eq!(budget.reserved_bytes(), MAX_UDP_WIRE_DATAGRAM_BYTES);
        drop(association);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot(), baseline);
    }

    #[tokio::test]
    async fn direct_udp_resolves_every_send_and_reuses_last_success_hint() {
        let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let third: SocketAddr = "192.0.2.3:53".parse().unwrap();
        let resolver = DirectTestResolver {
            candidates: Some(vec![first, second, third]),
            calls: AtomicUsize::new(0),
        };
        let socket = SelectiveDirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            successful: Mutex::new(HashSet::from([second])),
        };
        let target = TargetAddr::domain("hinted-direct.invalid", 53).unwrap();
        let mut hints = DirectUdpCandidateHints::default();

        let (_, peer) = send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"first",
            Duration::from_secs(1),
        )
        .await
        .expect("first resolved send");
        assert_eq!(peer, second);
        assert_eq!(socket.take_attempts(), [first, second]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"resolve-again",
            Duration::from_secs(1),
        )
        .await
        .expect("resolved last-success send");
        assert_eq!(socket.take_attempts(), [second]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

        socket.set_successful([third]);
        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"rotate",
            Duration::from_secs(1),
        )
        .await
        .expect("candidate rotation send");
        assert_eq!(socket.take_attempts(), [second, third]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);

        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"new-last-success",
            Duration::from_secs(1),
        )
        .await
        .expect("updated last-success send");
        assert_eq!(socket.take_attempts(), [third]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);

        socket.set_successful([first]);
        let ip_target = TargetAddr::ip(first).unwrap();
        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &ip_target,
            b"literal-ip",
            Duration::from_secs(1),
        )
        .await
        .expect("literal IP send");
        assert_eq!(socket.take_attempts(), [first]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
        assert_eq!(hints.entries.len(), 1);
        assert_eq!(hints.entries[0].last_successful_index, 2);
    }

    #[tokio::test]
    async fn direct_udp_uses_fresh_resolver_results_and_never_falls_back() {
        let first: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let second: SocketAddr = "192.0.2.12:53".parse().unwrap();
        let refreshed: SocketAddr = "192.0.2.13:53".parse().unwrap();
        let resolver = SequencedDirectTestResolver {
            answers: Mutex::new(VecDeque::from([
                Ok(vec![first, second]),
                Ok(vec![refreshed]),
                Err(io::ErrorKind::ConnectionRefused),
            ])),
            calls: AtomicUsize::new(0),
        };
        let socket = SelectiveDirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            successful: Mutex::new(HashSet::from([second])),
        };
        let target = TargetAddr::domain("fresh-direct.invalid", 53).unwrap();
        let mut hints = DirectUdpCandidateHints::default();

        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"prime",
            Duration::from_secs(1),
        )
        .await
        .expect("prime candidate hint");
        assert_eq!(socket.take_attempts(), [first, second]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        socket.set_successful([refreshed]);
        send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"fresh-result",
            Duration::from_secs(1),
        )
        .await
        .expect("fresh resolver result");
        assert_eq!(socket.take_attempts(), [refreshed]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

        let error = send_direct_target(
            &socket,
            &resolver,
            &mut hints,
            &target,
            b"configured-failure",
            Duration::from_secs(1),
        )
        .await
        .expect_err("resolver failure is terminal");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(socket.take_attempts().is_empty());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn direct_udp_candidate_hints_are_bounded() {
        let candidate: SocketAddr = "192.0.2.21:53".parse().unwrap();
        let resolver = DirectTestResolver {
            candidates: Some(vec![candidate]),
            calls: AtomicUsize::new(0),
        };
        let socket = SelectiveDirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            successful: Mutex::new(HashSet::from([candidate])),
        };
        let mut hints = DirectUdpCandidateHints::default();

        for index in 0..=DIRECT_UDP_CANDIDATE_HINT_CAPACITY {
            let domain = format!("hint-{index}.invalid");
            let target = TargetAddr::domain(&domain, 53).unwrap();
            send_direct_target(
                &socket,
                &resolver,
                &mut hints,
                &target,
                b"bounded",
                Duration::from_secs(1),
            )
            .await
            .expect("bounded hinted send");
        }

        assert_eq!(hints.entries.len(), DIRECT_UDP_CANDIDATE_HINT_CAPACITY);
        assert!(
            hints
                .entries
                .iter()
                .all(|entry| entry.domain != "hint-0.invalid")
        );
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            DIRECT_UDP_CANDIDATE_HINT_CAPACITY + 1
        );
    }

    #[tokio::test]
    async fn direct_tcp_and_udp_injection_share_configured_resolver_without_fallback() {
        let backend = Arc::new(FailingConfiguredApplicationBackend {
            calls: AtomicUsize::new(0),
        });
        let application_resolver = ferrum2_runtime::ApplicationResolverAdapter::new(
            Arc::new(ferrum2_dns::ApplicationResolver::configured(
                backend.clone(),
            )),
            0,
            ferrum2_dns::DnsStrategy::PreferIpv4,
        );
        let connector = ferrum2_runtime::TcpConnector::with_resolution_adapters(
            ferrum2_runtime::SystemSocketInspector,
            ferrum2_runtime::SystemTcpDialer,
            application_resolver.clone(),
            Duration::from_secs(1),
        );
        assert!(
            connector
                .resolver()
                .shares_resolver_with(&application_resolver)
        );
        let registry = OwnerRegistry::new();
        let engine = ClientEgressEngine::new_with_application_resolver(
            vec![ClientOutboundContext::Direct].into(),
            TokioConnector::new(connector),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            application_resolver.clone(),
            None,
        );
        assert!(
            engine
                .application_resolver
                .shares_resolver_with(&application_resolver)
        );
        let target = TargetAddr::domain("configured-only.invalid", 53).expect("domain target");
        let mut association = engine
            .prepare_udp(
                ClientRequestOrigin::Socks,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&target),
            )
            .await
            .expect("direct association");
        let Ok(wire_len) = association.prepare_application_request(
            &engine,
            &engine.outbounds,
            target,
            b"configured",
            Instant::now(),
        ) else {
            panic!("prepare direct request");
        };

        let error = association
            .send_encoded_request(wire_len)
            .await
            .expect_err("configured resolver failure must be terminal");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_udp_socks_uses_raw_datagrams_and_no_sip022_state() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let live_ids = Arc::new(Mutex::new(HashSet::new()));
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Direct].into(),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(
                std::time::Duration::from_secs(1),
            )),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            ),
            Some(ClientUdpContext {
                manager,
                live_ids: Arc::clone(&live_ids),
            }),
            None,
        );
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("echo bind");
        let target = TargetAddr::ip(echo.local_addr().expect("echo address")).expect("target");
        let mut association = engine
            .prepare_udp(
                super::super::ClientRequestOrigin::Socks,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                Some(&target),
            )
            .await
            .expect("direct association");
        association.activate(&engine).expect("direct activation");
        let provisional = registry.snapshot();
        assert_eq!(
            provisional.udp_buffered_bytes,
            baseline.udp_buffered_bytes + MAX_UDP_WIRE_DATAGRAM_BYTES,
            "direct association owns only its request wire buffer"
        );
        assert_eq!(provisional.udp_queued_datagrams, 0);
        let maximum = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        assert_eq!(
            association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target.clone(),
                    &maximum,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("exact raw maximum")),
            MAX_UDP_WIRE_DATAGRAM_BYTES
        );
        assert!(matches!(
            association.prepare_application_request(
                &engine,
                &engine.outbounds,
                target.clone(),
                &vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES + 1],
                Instant::now(),
            ),
            Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds))
        ));
        assert_eq!(registry.snapshot(), provisional);
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
        assert!(live_ids.lock().expect("live IDs").is_empty());
        let wire_len = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target,
                b"raw-udp",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("direct request"));
        assert_eq!(association.send_encoded_request(wire_len).await.unwrap(), 7);
        let mut raw = [0_u8; 32];
        let (length, peer) = echo.recv_from(&mut raw).await.expect("echo receive");
        assert_eq!(&raw[..length], b"raw-udp");
        let spoof = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("spoof bind");
        spoof.send_to(b"spoof", peer).await.expect("spoof response");
        echo.send_to(b"raw-reply", peer).await.expect("echo reply");
        let response_len = association
            .receive_response_wire()
            .await
            .expect("direct receive");
        let response = association
            .prepare_application_response(&engine, &engine.outbounds, response_len)
            .unwrap_or_else(|_| panic!("direct response"));
        assert_eq!(
            response.datagram().target(),
            &TargetAddr::ip(echo.local_addr().unwrap()).unwrap()
        );
        assert_eq!(response.datagram().payload(), b"raw-reply");
        let response_owned = registry.snapshot();
        assert_eq!(response_owned.udp_queued_datagrams, 0);
        assert_eq!(
            response_owned.udp_buffered_bytes,
            provisional.udp_buffered_bytes + b"raw-reply".len(),
            "the direct response owns only its initialized prefix"
        );
        association.recycle_application_response(response);
        assert_eq!(registry.snapshot(), provisional);
        let recycled = association
            .direct_wire
            .as_ref()
            .expect("recycled direct wire buffer");
        assert!(recycled.is_empty());
        assert_eq!(recycled.capacity(), MAX_UDP_WIRE_DATAGRAM_BYTES);
        assert!(live_ids.lock().expect("live IDs").is_empty());
        drop(association);
        assert_eq!(registry.snapshot(), baseline);

        for (case, plan) in [
            ("absent", None),
            (
                "explicit direct",
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            ),
        ] {
            let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("DNS echo bind");
            let target = TargetAddr::ip(echo.local_addr().unwrap()).unwrap();
            let mut association = engine
                .prepare_udp(super::super::ClientRequestOrigin::Dns, plan, Some(&target))
                .await
                .unwrap_or_else(|_| panic!("{case} direct association"));
            association.activate(&engine).unwrap();
            let length = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target,
                    case.as_bytes(),
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("{case} request"));
            association.send_encoded_request(length).await.unwrap();
            let mut raw = [0_u8; 32];
            let (length, peer) = echo.recv_from(&mut raw).await.unwrap();
            assert_eq!(&raw[..length], case.as_bytes());
            echo.send_to(case.as_bytes(), peer).await.unwrap();
            let length = association.receive_response_wire().await.unwrap();
            let response = association
                .prepare_application_response(&engine, &engine.outbounds, length)
                .unwrap_or_else(|_| panic!("{case} response"));
            assert_eq!(response.datagram().payload(), case.as_bytes());
            association.recycle_application_response(response);
        }
        assert!(live_ids.lock().expect("live IDs").is_empty());

        if let Ok(echo) = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await {
            let echo_address = echo.local_addr().unwrap();
            let mut wire = [0_u8; 16];
            let ipv6_ready =
                if let Ok(probe) = UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).await {
                    probe.send_to(b"probe", echo_address).await.is_ok()
                        && matches!(
                            tokio::time::timeout(
                                std::time::Duration::from_millis(200),
                                echo.recv_from(&mut wire),
                            )
                            .await,
                            Ok(Ok((5, _))) if &wire[..5] == b"probe"
                        )
                } else {
                    false
                };
            if ipv6_ready {
                let target = TargetAddr::ip(echo_address).unwrap();
                let mut association = engine
                    .prepare_udp(
                        super::super::ClientRequestOrigin::Socks,
                        Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                        Some(&target),
                    )
                    .await
                    .expect("SOCKS IPv6 direct association");
                association.activate(&engine).unwrap();
                let length = association
                    .prepare_application_request(
                        &engine,
                        &engine.outbounds,
                        target,
                        b"ipv6",
                        Instant::now(),
                    )
                    .unwrap_or_else(|_| panic!("SOCKS IPv6 request"));
                association.send_encoded_request(length).await.unwrap();
                let (length, peer) = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    echo.recv_from(&mut wire),
                )
                .await
                .expect("SOCKS IPv6 raw receive timeout")
                .unwrap();
                assert_eq!(&wire[..length], b"ipv6");
                echo.send_to(b"ipv6-reply", peer).await.unwrap();
                let length = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    association.receive_response_wire(),
                )
                .await
                .expect("SOCKS IPv6 response timeout")
                .unwrap();
                let response = association
                    .prepare_application_response(&engine, &engine.outbounds, length)
                    .unwrap_or_else(|_| panic!("SOCKS IPv6 response"));
                assert!(
                    response
                        .datagram()
                        .target()
                        .as_socket_addr()
                        .unwrap()
                        .is_ipv6()
                );
                assert_eq!(response.datagram().payload(), b"ipv6-reply");
                association.recycle_application_response(response);
            }
        }

        let echo_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_a = TargetAddr::ip(echo_a.local_addr().unwrap()).unwrap();
        let target_b = TargetAddr::ip(echo_b.local_addr().unwrap()).unwrap();
        let mut association = engine
            .prepare_udp(
                super::super::ClientRequestOrigin::Socks,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                None,
            )
            .await
            .unwrap();
        association.activate(&engine).unwrap();
        for (target, payload) in [
            (target_a.clone(), b"A".as_slice()),
            (target_b, b"B".as_slice()),
        ] {
            let length = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target,
                    payload,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("outstanding request"));
            association.send_encoded_request(length).await.unwrap();
        }
        let mut wire = [0_u8; 8];
        let (_, peer_a) = echo_a.recv_from(&mut wire).await.unwrap();
        let (_, peer_b) = echo_b.recv_from(&mut wire).await.unwrap();
        let spoof = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        spoof.send_to(b"spoof", peer_a).await.unwrap();
        echo_b.send_to(b"B", peer_b).await.unwrap();
        echo_a.send_to(b"A", peer_a).await.unwrap();
        for (expected_source, expected_payload) in [
            (echo_b.local_addr().unwrap(), b"B".as_slice()),
            (echo_a.local_addr().unwrap(), b"A".as_slice()),
        ] {
            let length = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                association.receive_response_wire(),
            )
            .await
            .unwrap_or_else(|_| panic!("out-of-order response"))
            .unwrap();
            let response = association
                .prepare_application_response(&engine, &engine.outbounds, length)
                .unwrap_or_else(|_| panic!("outstanding response"));
            assert_eq!(
                response.datagram().target(),
                &TargetAddr::ip(expected_source).unwrap()
            );
            assert_eq!(response.datagram().payload(), expected_payload);
            association.recycle_application_response(response);
        }

        for _ in 0..UDP_SESSION_QUEUE_DEPTH {
            let length = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    target_a.clone(),
                    b"queued",
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("queued direct request"));
            association.send_encoded_request(length).await.unwrap();
        }
        assert_eq!(association.direct_peers.len(), UDP_SESSION_QUEUE_DEPTH);
        let length = association
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                target_a,
                b"overflow",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("depth+1 request encoding"));
        assert_eq!(
            association
                .send_encoded_request(length)
                .await
                .expect_err("depth+1 rejected before send")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(association.direct_peers.len(), UDP_SESSION_QUEUE_DEPTH);
        for _ in 0..UDP_SESSION_QUEUE_DEPTH {
            echo_a.recv_from(&mut wire).await.expect("queued datagram");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), echo_a.recv_from(&mut wire))
                .await
                .is_err(),
            "depth+1 never reaches the socket"
        );
        assert_eq!(registry.snapshot(), provisional);
        assert!(live_ids.lock().expect("live IDs").is_empty());
        drop(association);
        assert_eq!(registry.snapshot(), baseline);

        let domain = TargetAddr::domain("direct-candidates.invalid", 53).unwrap();
        for (name, candidate_count, succeed_at, expected_attempts, expected_ok) in [
            ("zero", 0, None, 0, false),
            ("one", 1, Some(1), 1, true),
            ("sixteen", 16, Some(16), 16, true),
            ("seventeen", 17, None, 16, false),
        ] {
            let candidates = (1..=candidate_count)
                .map(|octet| SocketAddr::from(([192, 0, 2, octet as u8], 53)))
                .collect::<Vec<_>>();
            let resolver = DirectTestResolver {
                candidates: Some(candidates.clone()),
                calls: AtomicUsize::new(0),
            };
            let socket = DirectTestSocket {
                attempts: Mutex::new(Vec::new()),
                succeed_at,
            };
            let mut hints = DirectUdpCandidateHints::default();
            let result = send_direct_target(
                &socket,
                &resolver,
                &mut hints,
                &domain,
                b"candidate",
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.is_ok(), expected_ok, "{name}");
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1, "{name}");
            let attempts = socket.attempts.lock().expect("candidate attempts");
            assert_eq!(attempts.len(), expected_attempts, "{name}");
            assert_eq!(&attempts[..], &candidates[..expected_attempts], "{name}");
        }

        let resolver = DirectTestResolver {
            candidates: None,
            calls: AtomicUsize::new(0),
        };
        let socket = DirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            succeed_at: Some(1),
        };
        let mut hints = DirectUdpCandidateHints::default();
        assert!(
            send_direct_target(
                &socket,
                &resolver,
                &mut hints,
                &domain,
                b"resolver-error",
                Duration::from_secs(1),
            )
            .await
            .is_err()
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert!(
            socket
                .attempts
                .lock()
                .expect("resolver attempts")
                .is_empty()
        );
        assert_eq!(registry.snapshot(), baseline);
        assert_eq!(
            engine
                .udp
                .as_ref()
                .expect("UDP context")
                .manager
                .session_count(),
            0
        );
        assert!(live_ids.lock().expect("live IDs").is_empty());
    }

    #[test]
    fn live_udp_registry_accepts_zero_through_seven_collisions_and_rejects_eight() {
        let keys =
            MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([0x11; 16])));
        for collisions in 0..8 {
            let live = Mutex::new(HashSet::new());
            let (_first, first_id) =
                register_udp_session(&keys, &IdSequenceRandom::new([1]), &live)
                    .expect("first session");
            let draws = std::iter::repeat_n(1, collisions).chain([2]);
            let (_second, second_id) =
                register_udp_session(&keys, &IdSequenceRandom::new(draws), &live)
                    .expect("distinct draw within eight attempts");
            assert_ne!(first_id, second_id);
            assert_eq!(live.lock().expect("live IDs").len(), 2);
        }

        let live = Mutex::new(HashSet::new());
        let _ =
            register_udp_session(&keys, &IdSequenceRandom::new([1]), &live).expect("first session");
        assert!(
            register_udp_session(
                &keys,
                &IdSequenceRandom::new(std::iter::repeat_n(1, 8)),
                &live,
            )
            .is_err()
        );
        assert_eq!(live.lock().expect("live IDs").len(), 1);
    }

    struct MissingMethodKey;

    impl MethodKeyProvider for MissingMethodKey {
        type Error = ();

        fn profile(&self) -> MethodProfile {
            MethodProfile::Blake3Aes128Gcm2022
        }

        fn with_method_key<T>(
            &self,
            _selector: KeySelector<'_>,
            _use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
        ) -> Result<T, Self::Error> {
            Err(())
        }
    }

    async fn assert_registration_failure_rolls_back_setup<K: MethodKeyProvider>(
        keys: MethodKeyAdapter<K>,
        random: &impl SecureRandom,
    ) {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let session = manager
            .reserve_session(Instant::now())
            .expect("setup session");
        let budget = manager.buffer_budget();
        let fixed = (0..3)
            .map(|_| budget.reserve(MAX_UDP_WIRE_LEN).expect("fixed capacity"))
            .collect::<Vec<_>>();
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application socket");
        let upstream = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("upstream socket");
        upstream
            .connect((Ipv4Addr::LOCALHOST, 9))
            .await
            .expect("upstream connect");
        let application_address = application.local_addr().expect("application address");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let live_ids = Mutex::new(HashSet::new());
        assert!(register_udp_session(&keys, random, &live_ids).is_err());
        assert!(live_ids.lock().expect("live IDs").is_empty());
        assert_eq!(manager.session_count(), 1);
        assert_eq!(budget.reserved_bytes(), 3 * MAX_UDP_WIRE_LEN);

        drop((application, upstream, fixed, session));
        assert_eq!(manager.session_count(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot(), baseline);
        drop(
            UdpSocket::bind(application_address)
                .await
                .expect("application rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("upstream rebind"),
        );
    }

    #[tokio::test]
    async fn random_and_key_setup_failures_roll_back_every_prior_owner() {
        let keys =
            MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([0x11; 16])));
        assert_registration_failure_rolls_back_setup(keys, &IdSequenceRandom::new([])).await;
        assert_registration_failure_rolls_back_setup(
            MethodKeyAdapter::new(MissingMethodKey),
            &FixedRandom,
        )
        .await;
    }
}
