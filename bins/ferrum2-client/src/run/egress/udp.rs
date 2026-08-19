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
    SystemDirectUdpSocketFactory, SystemUdpResolver, UDP_SESSION_QUEUE_DEPTH, UdpBufferReservation,
    UdpCommitError, UdpDirection, UdpResolver, UdpRuntimeError, UdpSessionHandle,
    UdpSessionManager,
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
const DIRECT_UDP_DNS_CACHE_CAPACITY: usize = 16;
const DIRECT_UDP_DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

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
    live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
    upstream: ClientUdpUpstream,
    direct_target: Option<TargetAddr>,
    direct_peers: VecDeque<SocketAddr>,
    direct_dns_cache: DirectUdpDnsCache,
    direct_timeout: std::time::Duration,
    pending_direct_response: Option<(BytesMut, SocketAddr)>,
    direct_wire: Option<BytesMut>,
    inner_wire: Option<Vec<u8>>,
    upstream_wire: Option<Vec<u8>>,
    scratch: Option<UdpPacketScratch>,
    _fixed_capacity: Vec<UdpBufferReservation>,
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
    Managed {
        ipv4: UdpSocket,
        ipv6: Option<UdpSocket>,
    },
}

#[derive(Default)]
struct DirectUdpDnsCache {
    entries: VecDeque<DirectUdpResolvedTarget>,
}

struct DirectUdpResolvedTarget {
    domain: String,
    port: u16,
    ordered_addrs: Vec<SocketAddr>,
    expires_at: Instant,
    last_successful_index: usize,
}

impl DirectUdpDnsCache {
    fn take_valid(
        &mut self,
        domain: &str,
        port: u16,
        now: Instant,
    ) -> Option<DirectUdpResolvedTarget> {
        let position = self
            .entries
            .iter()
            .position(|entry| entry.domain == domain && entry.port == port)?;
        let entry = self.entries.remove(position)?;
        (entry.expires_at > now).then_some(entry)
    }

    fn insert(&mut self, entry: DirectUdpResolvedTarget) {
        if let Some(position) = self
            .entries
            .iter()
            .position(|cached| cached.domain == entry.domain && cached.port == entry.port)
        {
            self.entries.remove(position);
        } else if self.entries.len() >= DIRECT_UDP_DNS_CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }
}

#[cfg(windows)]
pub(super) const fn managed_direct_udp_ipv6_allowed(origin: ClientRequestOrigin) -> bool {
    matches!(origin, ClientRequestOrigin::Socks)
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedUdpBinding {
    Fixed(std::net::SocketAddrV4),
    Default,
}

#[cfg(all(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManagedUdpEvent {
    OpenV4,
    BindFixed(std::net::SocketAddrV4),
    BindDefault,
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
            let SocketAddr::V4(endpoint) = first_server else {
                return Err(());
            };
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        }
        SelectedEgress::Shadowsocks { .. } => Ok(None),
        SelectedEgress::Direct if auto_route && origin == ClientRequestOrigin::Dns => {
            let Some(SocketAddr::V4(endpoint)) = target.and_then(TargetAddr::as_socket_addr) else {
                return Err(());
            };
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        }
        SelectedEgress::Direct if auto_route || origin == ClientRequestOrigin::Tun => {
            Ok(Some(ManagedUdpBinding::Default))
        }
        SelectedEgress::Direct => Ok(None),
    }
}

#[cfg(any(windows, test))]
trait ManagedUdpOperations {
    type Socket;

    async fn open_v4(&mut self) -> io::Result<Self::Socket>;
    fn bind_fixed(
        &self,
        _socket: &Self::Socket,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), ()>;
    fn bind_default(&self, socket: &Self::Socket) -> Result<(), ()>;
    async fn connect(&self, socket: &Self::Socket, endpoint: SocketAddr) -> io::Result<()>;
}

#[cfg(any(windows, test))]
async fn open_managed_udp<O: ManagedUdpOperations>(
    operations: &mut O,
    binding: ManagedUdpBinding,
    connect: Option<SocketAddr>,
) -> Result<O::Socket, ()> {
    let socket = operations.open_v4().await.map_err(|_| ())?;
    match binding {
        ManagedUdpBinding::Fixed(endpoint) => operations.bind_fixed(&socket, endpoint)?,
        ManagedUdpBinding::Default => operations.bind_default(&socket)?,
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
            Self::Managed { ipv4, .. } if target.is_ipv4() => ipv4.send_to(payload, target).await,
            #[cfg(windows)]
            Self::Managed {
                ipv6: Some(ipv6), ..
            } => ipv6.send_to(payload, target).await,
            #[cfg(windows)]
            Self::Managed { ipv6: None, .. } => Err(io::Error::other("managed IPv4 required")),
        }
    }

    async fn readable(&self) -> io::Result<()> {
        match self {
            Self::System(socket) => socket.readable().await,
            #[cfg(windows)]
            Self::Managed {
                ipv4,
                ipv6: Some(ipv6),
            } => tokio::select! {
                result = ipv4.readable() => result,
                result = ipv6.readable() => result,
            },
            #[cfg(windows)]
            Self::Managed { ipv4, ipv6: None } => ipv4.readable().await,
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.recv_buf_from(payload).await,
            #[cfg(windows)]
            Self::Managed {
                ipv4,
                ipv6: Some(ipv6),
            } => loop {
                let ready = tokio::select! {
                    result = ipv4.readable() => {
                        result?;
                        ipv4
                    }
                    result = ipv6.readable() => {
                        result?;
                        ipv6
                    }
                };
                match ready.try_recv_buf_from(payload) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => break result,
                }
            },
            #[cfg(windows)]
            Self::Managed { ipv4, ipv6: None } => ipv4.recv_buf_from(payload).await,
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.try_recv_buf_from(payload),
            #[cfg(windows)]
            Self::Managed {
                ipv4,
                ipv6: Some(ipv6),
            } => match ipv4.try_recv_buf_from(payload) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ipv6.try_recv_buf_from(payload)
                }
                result => result,
            },
            #[cfg(windows)]
            Self::Managed { ipv4, ipv6: None } => ipv4.try_recv_buf_from(payload),
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
    pub(in crate::run) fn activate(&mut self, egress: &ClientEgressEngine) -> Result<(), ()> {
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

    pub(in crate::run) fn encode_request(
        &mut self,
        egress: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        datagram: &Datagram,
    ) -> Result<usize, UdpPacketError> {
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

    pub(in crate::run) fn accept_response(
        &mut self,
        egress: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
        let Self {
            plan,
            protocol,
            manager,
            handle,
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
            Some(session) => session.reserve_datagram(UdpDirection::ToTarget, allocated_capacity),
            None => self.manager.reserve_datagram(
                self.handle,
                UdpDirection::ToTarget,
                allocated_capacity,
            ),
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

    pub(in crate::run) fn prepare_application_request(
        &mut self,
        engine: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError> {
        self.prepare_owned_application_request(
            engine,
            outbounds,
            target,
            BytesMut::from(payload),
            now,
        )
    }

    pub(in crate::run) fn prepare_owned_application_request(
        &mut self,
        engine: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: BytesMut,
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError> {
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

    pub(in crate::run) fn prepare_application_response(
        &mut self,
        engine: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
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
            let reservation = match self.manager.reserve_datagram(
                self.handle,
                UdpDirection::ToClient,
                payload.capacity(),
            ) {
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
                if self.direct_peers.len() >= UDP_SESSION_QUEUE_DEPTH {
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
                    &SystemUdpResolver,
                    &mut self.direct_dns_cache,
                    target,
                    &direct_wire[..wire_len],
                    self.direct_timeout,
                )
                .await?;
                self.direct_peers.push_back(peer);
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
                let (length, source, position) = receive_expected_direct_response(
                    socket,
                    &self.direct_peers,
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
                self.direct_peers.remove(position);
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

    pub(in crate::run) async fn relay(
        &mut self,
        engine: &ClientEgressEngine,
        plan: Option<&EgressPlanSnapshot>,
        destination: SocketAddr,
        packet: Vec<u8>,
    ) -> io::Result<((Vec<u8>, SocketAddr), bool)> {
        if packet.len() > MAX_UDP_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP packet too large",
            ));
        }
        if self.plan.as_ref() != plan {
            return Err(invalid_dns_target());
        }
        let target = TargetAddr::ip(destination).map_err(|_| invalid_dns_target())?;
        self.activate(engine).map_err(|_| runtime_error(()))?;
        let wire_len = self
            .prepare_owned_application_request(
                engine,
                &engine.outbounds,
                target,
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
            let source = response
                .datagram()
                .target()
                .as_socket_addr()
                .ok_or_else(invalid_dns_target)?;
            let payload = response.datagram().payload().to_vec();
            self.recycle_application_response(response);
            return Ok(((payload, source), reusable));
        }
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

    fn bind_fixed(
        &self,
        _socket: &Self::Socket,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), ()> {
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

    fn bind_default(&self, _socket: &Self::Socket) -> Result<(), ()> {
        #[cfg(test)]
        return self
            .egress
            .record_managed_udp_event(ManagedUdpEvent::BindDefault);
        #[cfg(not(test))]
        self.egress.underlay.bind_default(_socket).map_err(|_| ())
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
    let pending_session = udp
        .manager
        .reserve_session(Instant::now())
        .map_err(|_| ())?;
    let handle = pending_session.handle();
    let budget = udp.manager.buffer_budget();
    let fixed_buffer_count = match selected {
        SelectedEgress::Direct => 1,
        SelectedEgress::Shadowsocks { .. } => 3,
    };
    let mut fixed_capacity = Vec::with_capacity(fixed_buffer_count);
    for _ in 0..fixed_buffer_count {
        let capacity = match selected {
            SelectedEgress::Direct => MAX_UDP_WIRE_DATAGRAM_BYTES,
            SelectedEgress::Shadowsocks { .. } => MAX_UDP_WIRE_LEN,
        };
        fixed_capacity.push(budget.reserve(capacity).map_err(|_| ())?);
    }
    let inner_wire = matches!(selected, SelectedEgress::Shadowsocks { .. })
        .then(|| vec![0_u8; MAX_UDP_WIRE_LEN]);
    let upstream_wire = matches!(selected, SelectedEgress::Shadowsocks { .. })
        .then(|| vec![0_u8; MAX_UDP_WIRE_LEN]);
    let scratch =
        matches!(selected, SelectedEgress::Shadowsocks { .. }).then(UdpPacketScratch::new);
    let first_server = match selected {
        SelectedEgress::Shadowsocks { first_server } => Some(first_server),
        SelectedEgress::Direct => None,
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
        SelectedEgress::Direct => {
            #[cfg(windows)]
            if let Some(binding) = managed_binding {
                let ipv4 = open_managed_udp(
                    &mut ClientManagedUdpOperations {
                        egress,
                        bind: &mut bind,
                        _future: std::marker::PhantomData,
                    },
                    binding,
                    None,
                )
                .await?;
                let ipv6 = if managed_direct_udp_ipv6_allowed(origin) {
                    Some(
                        bind(SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0))
                            .await
                            .map_err(|_| ())?,
                    )
                } else {
                    None
                };
                ClientUdpUpstream::Direct(ClientDirectUdpSocket::Managed { ipv4, ipv6 })
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
        live_ids: Arc::clone(&udp.live_ids),
        upstream,
        direct_target: None,
        direct_peers: VecDeque::with_capacity(UDP_SESSION_QUEUE_DEPTH),
        direct_dns_cache: DirectUdpDnsCache::default(),
        direct_timeout: egress.phase_deadlines.0,
        pending_direct_response: None,
        direct_wire: matches!(selected, SelectedEgress::Direct)
            .then(|| BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES)),
        inner_wire,
        upstream_wire,
        scratch,
        _fixed_capacity: fixed_capacity,
        #[cfg(test)]
        io_fault: None,
    })
}

async fn send_direct_target(
    socket: &impl DirectUdpSocket,
    resolver: &impl UdpResolver,
    cache: &mut DirectUdpDnsCache,
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
    if let Some(mut cached) = cache.take_valid(host, port, Instant::now())
        && let Ok((length, peer, index)) = send_direct_candidates(
            socket,
            payload,
            &cached.ordered_addrs,
            cached.last_successful_index,
            deadline,
        )
        .await
    {
        cached.last_successful_index = index;
        cache.insert(cached);
        return Ok((length, peer));
    }
    let candidates = tokio::time::timeout_at(deadline, resolver.resolve(host, target.port().get()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP resolve timeout"))??;
    let candidates = candidates
        .into_iter()
        .take(MAX_UDP_RESOLVED_CANDIDATES)
        .collect::<Vec<_>>();
    let (length, peer, last_successful_index) =
        send_direct_candidates(socket, payload, &candidates, 0, deadline).await?;
    cache.insert(DirectUdpResolvedTarget {
        domain: host.to_owned(),
        port,
        ordered_addrs: candidates,
        expires_at: Instant::now() + DIRECT_UDP_DNS_CACHE_TTL,
        last_successful_index,
    });
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

async fn receive_expected_direct_response(
    socket: &impl DirectUdpSocket,
    expected_peers: &VecDeque<SocketAddr>,
    payload: &mut BytesMut,
) -> io::Result<(usize, SocketAddr, usize)> {
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
            if let Some(position) = expected_peers
                .iter()
                .position(|expected| *expected == received.1)
            {
                return Ok((received.0, received.1, position));
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
    let reservation = manager
        .reserve_datagram(handle, UdpDirection::ToClient, pending.allocated_capacity())
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

    use super::*;
    use crate::run::test_support::*;

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

        fn bind_fixed(
            &self,
            _socket: &Self::Socket,
            _endpoint: std::net::SocketAddrV4,
        ) -> Result<(), ()> {
            self.events.lock().unwrap().push("bind-fixed");
            if self.fail_binding { Err(()) } else { Ok(()) }
        }

        fn bind_default(&self, _socket: &Self::Socket) -> Result<(), ()> {
            self.events.lock().unwrap().push("bind-default");
            if self.fail_binding { Err(()) } else { Ok(()) }
        }

        async fn connect(&self, _socket: &Self::Socket, _endpoint: SocketAddr) -> io::Result<()> {
            self.events.lock().unwrap().push("connect");
            Ok(())
        }
    }

    #[tokio::test]
    async fn managed_udp_binding_precedes_io_and_failure_has_no_retry() {
        let endpoint = "198.51.100.8:53".parse().unwrap();
        let mut fixed = InjectedManagedUdp {
            events: Mutex::new(Vec::new()),
            fail_binding: false,
        };
        open_managed_udp(
            &mut fixed,
            ManagedUdpBinding::Fixed(endpoint),
            Some(SocketAddr::V4(endpoint)),
        )
        .await
        .unwrap();
        assert_eq!(
            *fixed.events.lock().unwrap(),
            ["open-v4", "bind-fixed", "connect"]
        );

        let mut failed = InjectedManagedUdp {
            events: Mutex::new(Vec::new()),
            fail_binding: true,
        };
        assert!(
            open_managed_udp(
                &mut failed,
                ManagedUdpBinding::Default,
                Some(SocketAddr::V4(endpoint)),
            )
            .await
            .is_err()
        );
        assert_eq!(*failed.events.lock().unwrap(), ["open-v4", "bind-default"]);
    }

    #[test]
    fn dns_direct_fixed_binding_uses_the_numeric_bootstrap() {
        let endpoint = "198.51.100.8:53".parse().unwrap();
        let target = TargetAddr::ip(SocketAddr::V4(endpoint)).unwrap();
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct,
                true,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Dns,
                SelectedEgress::Direct,
                false,
                Some(&target),
            ),
            Ok(None)
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Tun,
                SelectedEgress::Direct,
                false,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Default))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Socks,
                SelectedEgress::Direct,
                true,
                Some(&target),
            ),
            Ok(Some(ManagedUdpBinding::Default))
        );
        assert_eq!(
            managed_udp_binding(
                ClientRequestOrigin::Socks,
                SelectedEgress::Shadowsocks {
                    first_server: SocketAddr::V4(endpoint),
                },
                true,
                None,
            ),
            Ok(Some(ManagedUdpBinding::Fixed(endpoint)))
        );
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
        let endpoint = "198.51.100.8:53".parse().unwrap();
        let target = TargetAddr::ip(SocketAddr::V4(endpoint)).unwrap();

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
            [ManagedUdpEvent::OpenV4, ManagedUdpEvent::BindDefault]
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
        answers: Mutex<VecDeque<Vec<SocketAddr>>>,
        calls: AtomicUsize,
    }

    impl UdpResolver for SequencedDirectTestResolver {
        type Candidates = Vec<SocketAddr>;

        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answers
                .lock()
                .expect("sequenced resolver answers")
                .pop_front()
                .ok_or_else(|| io::Error::other("injected resolver exhaustion"))
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

        let (length, source, position) =
            receive_expected_direct_response(&socket, &peers, &mut payload)
                .await
                .expect("bounded drain response");

        assert!(scheduler_ran.load(Ordering::SeqCst));
        probe.await.expect("scheduler probe");
        assert_eq!(socket.awaited_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            socket.try_calls.load(Ordering::SeqCst),
            MAX_DIRECT_UDP_READINESS_DRAIN - 1
        );
        assert_eq!((length, source, position), (8, expected, 0));
        assert_eq!(&payload[..], b"accepted");
    }

    #[tokio::test(start_paused = true)]
    async fn direct_udp_dns_cache_reuses_last_success_and_expires() {
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
        let target = TargetAddr::domain("cached-direct.invalid", 53).unwrap();
        let mut cache = DirectUdpDnsCache::default();

        let (_, peer) = send_direct_target(
            &socket,
            &resolver,
            &mut cache,
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
            &mut cache,
            &target,
            b"cached",
            Duration::from_secs(1),
        )
        .await
        .expect("cached last-success send");
        assert_eq!(socket.take_attempts(), [second]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        socket.set_successful([third]);
        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"fallback",
            Duration::from_secs(1),
        )
        .await
        .expect("cached fallback send");
        assert_eq!(socket.take_attempts(), [second, third]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"new-last-success",
            Duration::from_secs(1),
        )
        .await
        .expect("updated last-success send");
        assert_eq!(socket.take_attempts(), [third]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(DIRECT_UDP_DNS_CACHE_TTL + Duration::from_secs(1)).await;
        socket.set_successful([first]);
        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"expired",
            Duration::from_secs(1),
        )
        .await
        .expect("expired cache refresh");
        assert_eq!(socket.take_attempts(), [first]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

        let ip_target = TargetAddr::ip(first).unwrap();
        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &ip_target,
            b"literal-ip",
            Duration::from_secs(1),
        )
        .await
        .expect("literal IP send");
        assert_eq!(socket.take_attempts(), [first]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.entries.len(), 1);
    }

    #[tokio::test]
    async fn direct_udp_dns_cache_refreshes_early_after_cached_candidates_fail() {
        let first: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let second: SocketAddr = "192.0.2.12:53".parse().unwrap();
        let refreshed: SocketAddr = "192.0.2.13:53".parse().unwrap();
        let resolver = SequencedDirectTestResolver {
            answers: Mutex::new(VecDeque::from([vec![first, second], vec![refreshed]])),
            calls: AtomicUsize::new(0),
        };
        let socket = SelectiveDirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            successful: Mutex::new(HashSet::from([first])),
        };
        let target = TargetAddr::domain("refresh-direct.invalid", 53).unwrap();
        let mut cache = DirectUdpDnsCache::default();

        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"prime",
            Duration::from_secs(1),
        )
        .await
        .expect("prime DNS cache");
        assert_eq!(socket.take_attempts(), [first]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        socket.set_successful([refreshed]);
        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"early-refresh",
            Duration::from_secs(1),
        )
        .await
        .expect("early DNS refresh");
        assert_eq!(socket.take_attempts(), [first, second, refreshed]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);

        send_direct_target(
            &socket,
            &resolver,
            &mut cache,
            &target,
            b"refreshed-cache",
            Duration::from_secs(1),
        )
        .await
        .expect("refreshed cache send");
        assert_eq!(socket.take_attempts(), [refreshed]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn direct_udp_dns_cache_is_bounded() {
        let candidate: SocketAddr = "192.0.2.21:53".parse().unwrap();
        let resolver = DirectTestResolver {
            candidates: Some(vec![candidate]),
            calls: AtomicUsize::new(0),
        };
        let socket = SelectiveDirectTestSocket {
            attempts: Mutex::new(Vec::new()),
            successful: Mutex::new(HashSet::from([candidate])),
        };
        let mut cache = DirectUdpDnsCache::default();

        for index in 0..=DIRECT_UDP_DNS_CACHE_CAPACITY {
            let domain = format!("cache-{index}.invalid");
            let target = TargetAddr::domain(&domain, 53).unwrap();
            send_direct_target(
                &socket,
                &resolver,
                &mut cache,
                &target,
                b"bounded",
                Duration::from_secs(1),
            )
            .await
            .expect("bounded cache send");
        }

        assert_eq!(cache.entries.len(), DIRECT_UDP_DNS_CACHE_CAPACITY);
        assert!(
            cache
                .entries
                .iter()
                .all(|entry| entry.domain != "cache-0.invalid")
        );
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            DIRECT_UDP_DNS_CACHE_CAPACITY + 1
        );
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
            let mut cache = DirectUdpDnsCache::default();
            let result = send_direct_target(
                &socket,
                &resolver,
                &mut cache,
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
        let mut cache = DirectUdpDnsCache::default();
        assert!(
            send_direct_target(
                &socket,
                &resolver,
                &mut cache,
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
