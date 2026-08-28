use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::Clock;
use ferrum2_crypto::{SecureRandom, UdpSessionId};
use ferrum2_net::DialOptions;
use ferrum2_runtime::{
    AccountedDatagram, MAX_UDP_WIRE_DATAGRAM_BYTES, PendingUdpDatagram, PendingUdpSession,
    UDP_SESSION_QUEUE_DEPTH, UdpBufferBudget, UdpBufferReservation, UdpDirection, UdpRuntimeError,
    UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpClientSession, UdpPacketError};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::run::egress::context::{ClientOutboundContext, ClientRequestOrigin, SelectedEgress};
use crate::run::egress::engine::ClientEgressEngine;
use crate::run::egress::network::ClientPhysicalConnector;

use super::direct::{
    DirectUdpCandidateHints, DirectUdpFamily, DirectUdpResponseMatch, DirectUdpResponsePolicy,
    receive_direct_response, send_direct_target_lazy,
};
use super::request::{composed_udp_plan_limit, register_udp_plan};
use super::response::{
    UdpPlanResponseError, commit_composed_udp_response, commit_single_udp_response,
    dns_response_target_matches, invalid_dns_target, runtime_error,
};
use super::socket::{ClientDirectUdpSocket, ClientProxyUdpSocket, ClientUdpSocketFactory};
#[cfg(test)]
use super::socket::{UdpIoFaultPlan, UdpIoOperation};

pub(in crate::run) struct ClientUdpContext {
    pub(in crate::run) manager: UdpSessionManager,
    pub(in crate::run) live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
}

impl ClientUdpContext {
    pub(in crate::run) fn cancel_all(&self) {
        self.manager.cancel_all();
    }
}

pub(in crate::run) struct ClientUdpAssociation {
    plan: Option<EgressPlanSnapshot>,
    _network_generation: Option<u64>,
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
    pub(super) direct_peers: VecDeque<SocketAddr>,
    direct_candidate_hints: DirectUdpCandidateHints,
    direct_resolver: ferrum2_dns::ApplicationResolverAdapter,
    direct_timeout: std::time::Duration,
    pending_direct_response: Option<PendingDirectResponse>,
    pub(super) direct_wire: Option<BytesMut>,
    proxy_buffers: Option<ClientProxyBuffers>,
    _metered_fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

enum ClientUdpUpstream {
    Shadowsocks(ClientProxyUdpSocket),
    Direct {
        socket: Option<ClientDirectUdpSocket>,
        factory: ClientUdpSocketFactory,
    },
}

enum PendingDirectResponse {
    Ready {
        payload: BytesMut,
        source: SocketAddr,
        reservation: PendingUdpDatagram,
    },
    Rejected {
        wire_len: usize,
        error: UdpRuntimeError,
    },
}

pub(super) struct ClientUdpLeg {
    pub(super) protocol: UdpClientSession,
    pub(super) id: UdpSessionId,
}

pub(super) struct ClientUdpPlan {
    pub(super) legs: Vec<ClientUdpLeg>,
}

struct ProxyWireBuffer {
    wire: BytesMut,
    _reservation: Option<UdpBufferReservation>,
}

enum ClientProxyBuffers {
    Dormant {
        hop_count: usize,
        budget: UdpBufferBudget,
        meter_global_buffers: bool,
    },
    Single {
        upstream: ProxyWireBuffer,
    },
    Multi {
        upstream: ProxyWireBuffer,
        inner: ProxyWireBuffer,
    },
}

impl ProxyWireBuffer {
    fn allocate(
        budget: &UdpBufferBudget,
        meter_global_buffers: bool,
    ) -> Result<Self, UdpRuntimeError> {
        let reservation = meter_global_buffers
            .then(|| budget.reserve(MAX_UDP_WIRE_LEN))
            .transpose()?;
        let wire = BytesMut::with_capacity(MAX_UDP_WIRE_LEN);
        if wire.capacity() != MAX_UDP_WIRE_LEN {
            return Err(UdpRuntimeError::Bounds);
        }
        debug_assert!(
            reservation
                .as_ref()
                .is_none_or(|reservation| reservation.capacity() == wire.capacity())
        );
        Ok(Self {
            wire,
            _reservation: reservation,
        })
    }
}

impl ClientProxyBuffers {
    fn dormant(
        hop_count: usize,
        budget: UdpBufferBudget,
        meter_global_buffers: bool,
    ) -> Result<Self, UdpRuntimeError> {
        if !(1..=MAX_UDP_PLAN_HOPS).contains(&hop_count) {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self::Dormant {
            hop_count,
            budget,
            meter_global_buffers,
        })
    }

    fn ensure_ready(&mut self) -> Result<(), UdpRuntimeError> {
        let Some((hop_count, budget, meter_global_buffers)) = (match self {
            Self::Dormant {
                hop_count,
                budget,
                meter_global_buffers,
            } => Some((*hop_count, budget.clone(), *meter_global_buffers)),
            Self::Single { .. } | Self::Multi { .. } => None,
        }) else {
            return Ok(());
        };
        let upstream = ProxyWireBuffer::allocate(&budget, meter_global_buffers)?;
        *self = if hop_count == 1 {
            Self::Single { upstream }
        } else {
            let inner = ProxyWireBuffer::allocate(&budget, meter_global_buffers)?;
            Self::Multi { upstream, inner }
        };
        Ok(())
    }

    fn upstream(&self) -> &BytesMut {
        match self {
            Self::Single { upstream } | Self::Multi { upstream, .. } => &upstream.wire,
            Self::Dormant { .. } => panic!("proxy UDP wire buffers are allocated before use"),
        }
    }

    fn upstream_mut(&mut self) -> &mut BytesMut {
        match self {
            Self::Single { upstream } | Self::Multi { upstream, .. } => &mut upstream.wire,
            Self::Dormant { .. } => panic!("proxy UDP wire buffers are allocated before use"),
        }
    }

    fn pair_mut(&mut self) -> (&mut BytesMut, &mut BytesMut) {
        match self {
            Self::Multi { upstream, inner } => (&mut upstream.wire, &mut inner.wire),
            Self::Dormant { .. } | Self::Single { .. } => {
                panic!("multi-hop proxy UDP association owns two wire buffers")
            }
        }
    }

    #[cfg(test)]
    fn capacities(&self) -> Vec<usize> {
        match self {
            Self::Dormant { .. } => Vec::new(),
            Self::Single { upstream } => vec![upstream.wire.capacity()],
            Self::Multi { upstream, inner } => {
                vec![upstream.wire.capacity(), inner.wire.capacity()]
            }
        }
    }
}

pub(in crate::run::egress) const MAX_UDP_PLAN_HOPS: usize = 8;

fn expected_nested_target(
    outbounds: &[ClientOutboundContext],
    hop: usize,
) -> Result<TargetAddr, UdpPlanResponseError> {
    TargetAddr::ip(
        outbounds
            .get(hop)
            .and_then(ClientOutboundContext::shadowsocks)
            .ok_or(UdpPlanResponseError::Packet(
                UdpPacketError::StateUnavailable,
            ))?
            .udp_server,
    )
    .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))
}

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
    fn ensure_proxy_buffers(&mut self) -> Result<(), UdpRuntimeError> {
        self.proxy_buffers
            .as_mut()
            .expect("proxy UDP association owns its buffer lifecycle")
            .ensure_ready()
    }

    pub(in crate::run) fn activate<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
    ) -> Result<(), ()>
    where
        R: SecureRandom,
    {
        if matches!(self.upstream, ClientUdpUpstream::Direct { .. }) {
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
            proxy_buffers,
            ..
        } = self;
        let buffers = proxy_buffers
            .as_mut()
            .expect("proxy UDP association owns its wire buffers");
        let hops = plan.as_ref().expect("proxy UDP plan").hops();
        let plan = protocol
            .as_mut()
            .expect("client UDP protocol is activated before encode");
        if hops.len() == 1 {
            let upstream = buffers.upstream_mut();
            upstream.resize(MAX_UDP_WIRE_LEN, 0);
            return plan.legs[0].protocol.encode_request_parts(
                &egress.clock,
                &egress.random,
                datagram.target(),
                datagram.payload(),
                0,
                upstream,
            );
        }

        let (upstream, inner) = buffers.pair_mut();
        upstream.resize(MAX_UDP_WIRE_LEN, 0);
        inner.resize(MAX_UDP_WIRE_LEN, 0);
        let mut wire_len = 0;
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
            wire_len = if layer % 2 == 0 {
                let payload = if layer + 1 == hops.len() {
                    datagram.payload()
                } else {
                    &inner[..wire_len]
                };
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    payload,
                    0,
                    upstream,
                )?
            } else {
                let payload = if layer + 1 == hops.len() {
                    datagram.payload()
                } else {
                    &upstream[..wire_len]
                };
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    payload,
                    0,
                    inner,
                )?
            };
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
            proxy_buffers,
            ..
        } = self;
        let buffers = proxy_buffers
            .as_mut()
            .expect("proxy UDP association owns its wire buffers");
        let hops = plan.as_ref().expect("proxy UDP plan").hops();
        let plan = protocol
            .as_ref()
            .expect("client UDP protocol is activated before response");
        if hops.len() == 1 {
            let upstream = buffers.upstream_mut();
            if wire_len != upstream.len() {
                upstream.fill(0);
                upstream.clear();
                return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
            }
            let pending = match plan.legs[0]
                .protocol
                .prepare_response_in_place(&egress.clock, upstream)
            {
                Ok(pending) => pending,
                Err(error) => {
                    upstream.clear();
                    return Err(UdpPlanResponseError::Packet(error));
                }
            };
            let result = commit_single_udp_response(
                pending,
                &plan.legs[0].protocol,
                hops,
                outbounds,
                manager,
                *handle,
                *meter_global_buffers,
                &egress.clock,
            );
            upstream.fill(0);
            upstream.clear();
            return result;
        }

        let (upstream, inner) = buffers.pair_mut();
        if wire_len != upstream.len() {
            upstream.fill(0);
            upstream.clear();
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        let mut commits = Vec::with_capacity(hops.len());
        let mut source_is_upstream = true;
        for layer in 0..hops.len() {
            if source_is_upstream {
                let pending = match plan.legs[layer]
                    .protocol
                    .prepare_response_in_place(&egress.clock, upstream)
                {
                    Ok(pending) => pending,
                    Err(error) => {
                        upstream.clear();
                        return Err(UdpPlanResponseError::Packet(error));
                    }
                };
                if layer + 1 == hops.len() {
                    let result = commit_composed_udp_response(
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
                    upstream.fill(0);
                    upstream.clear();
                    return result;
                }
                let expected = match expected_nested_target(outbounds, hops[layer + 1]) {
                    Ok(expected) => expected,
                    Err(error) => {
                        drop(pending);
                        upstream.fill(0);
                        upstream.clear();
                        return Err(error);
                    }
                };
                if !pending.target_matches(&expected) {
                    drop(pending);
                    upstream.fill(0);
                    upstream.clear();
                    return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
                }
                inner.clear();
                inner.extend_from_slice(pending.payload());
                commits.push(pending.into_commit());
                upstream.fill(0);
                upstream.clear();
            } else {
                let pending = match plan.legs[layer]
                    .protocol
                    .prepare_response_in_place(&egress.clock, inner)
                {
                    Ok(pending) => pending,
                    Err(error) => {
                        inner.clear();
                        return Err(UdpPlanResponseError::Packet(error));
                    }
                };
                if layer + 1 == hops.len() {
                    let result = commit_composed_udp_response(
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
                    inner.fill(0);
                    inner.clear();
                    return result;
                }
                let expected = match expected_nested_target(outbounds, hops[layer + 1]) {
                    Ok(expected) => expected,
                    Err(error) => {
                        drop(pending);
                        inner.fill(0);
                        inner.clear();
                        return Err(error);
                    }
                };
                if !pending.target_matches(&expected) {
                    drop(pending);
                    inner.fill(0);
                    inner.clear();
                    return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
                }
                upstream.clear();
                upstream.extend_from_slice(pending.payload());
                commits.push(pending.into_commit());
                inner.fill(0);
                inner.clear();
            }
            source_is_upstream = !source_is_upstream;
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
            ClientUdpUpstream::Direct { .. } => MAX_UDP_WIRE_DATAGRAM_BYTES,
            ClientUdpUpstream::Shadowsocks { .. } => composed_udp_plan_limit(
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
        if matches!(&self.upstream, ClientUdpUpstream::Shadowsocks(_)) {
            self.ensure_proxy_buffers()
                .map_err(UdpPlanResponseError::Runtime)?;
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
        let wire_len = if matches!(self.upstream, ClientUdpUpstream::Direct { .. }) {
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
        let response = if matches!(self.upstream, ClientUdpUpstream::Direct { .. }) {
            let pending =
                self.pending_direct_response
                    .take()
                    .ok_or(UdpPlanResponseError::Packet(
                        UdpPacketError::StateUnavailable,
                    ))?;
            let (payload, source, reservation) = match pending {
                PendingDirectResponse::Ready {
                    payload,
                    source,
                    reservation,
                } if payload.len() == wire_len => (payload, source, reservation),
                PendingDirectResponse::Ready {
                    mut payload,
                    reservation,
                    ..
                } => {
                    payload.fill(0);
                    self.restore_direct_wire(payload);
                    drop(reservation);
                    return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
                }
                PendingDirectResponse::Rejected {
                    wire_len: rejected_len,
                    error,
                } if rejected_len == wire_len => {
                    return Err(UdpPlanResponseError::Runtime(error));
                }
                PendingDirectResponse::Rejected { .. } => {
                    return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
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

    fn clear_direct_wire(&mut self) {
        let wire = self
            .direct_wire
            .as_mut()
            .expect("direct UDP failure retains its wire buffer");
        wire.fill(0);
        wire.clear();
    }

    pub(in crate::run) fn recycle_application_response(&mut self, response: AccountedDatagram) {
        if !matches!(self.upstream, ClientUdpUpstream::Direct { .. }) {
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
        match &mut self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => {
                let upstream_wire = self
                    .proxy_buffers
                    .as_ref()
                    .expect("proxy UDP association owns its wire buffers")
                    .upstream();
                socket.send(&upstream_wire[..wire_len]).await
            }
            ClientUdpUpstream::Direct { socket, factory } => {
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
                let (length, peer) = send_direct_target_lazy(
                    socket,
                    factory,
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
        if matches!(&self.upstream, ClientUdpUpstream::Shadowsocks(_)) {
            self.ensure_proxy_buffers()
                .map_err(|_| io::Error::other("proxy UDP wire budget unavailable"))?;
        }
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => {
                let upstream_wire = self
                    .proxy_buffers
                    .as_mut()
                    .expect("proxy UDP association owns its wire buffers")
                    .upstream_mut();
                socket.receive(upstream_wire).await
            }
            ClientUdpUpstream::Direct {
                socket: Some(socket),
                ..
            } => {
                if self.pending_direct_response.is_some() {
                    return Err(io::Error::other("direct UDP response was not consumed"));
                }
                let received = receive_direct_response(
                    socket,
                    &self.direct_peers,
                    self.direct_response_policy,
                    self.direct_wire
                        .as_mut()
                        .ok_or_else(|| io::Error::other("direct UDP wire buffer unavailable"))?,
                )
                .await;
                let (length, source, response_match) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        self.clear_direct_wire();
                        return Err(error);
                    }
                };
                let reservation = self.reserve_response_datagram(length);
                let pending = match reservation {
                    Ok(reservation) => {
                        if !self
                            .direct_wire
                            .as_ref()
                            .is_some_and(|wire| wire.len() == length)
                        {
                            self.clear_direct_wire();
                            PendingDirectResponse::Rejected {
                                wire_len: length,
                                error: UdpRuntimeError::Bounds,
                            }
                        } else {
                            let mut payload = self
                                .direct_wire
                                .take()
                                .expect("direct UDP receive owns its wire buffer");
                            let unused = payload.split_off(length);
                            drop(unused);
                            if payload.capacity() != length {
                                payload.fill(0);
                                self.restore_direct_wire(payload);
                                PendingDirectResponse::Rejected {
                                    wire_len: length,
                                    error: UdpRuntimeError::Bounds,
                                }
                            } else {
                                PendingDirectResponse::Ready {
                                    payload,
                                    source,
                                    reservation,
                                }
                            }
                        }
                    }
                    Err(error) => {
                        self.clear_direct_wire();
                        PendingDirectResponse::Rejected {
                            wire_len: length,
                            error,
                        }
                    }
                };
                if let DirectUdpResponseMatch::OutstandingPeer(position) = response_match {
                    self.direct_peers.remove(position);
                }
                self.pending_direct_response = Some(pending);
                Ok(length)
            }
            ClientUdpUpstream::Direct { socket: None, .. } => {
                Err(io::Error::other("direct UDP socket unavailable"))
            }
        }
    }

    #[cfg(test)]
    pub(in crate::run) fn upstream_local_addr(&self) -> io::Result<SocketAddr> {
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks(socket) => socket.local_addr(),
            ClientUdpUpstream::Direct { .. } => Err(io::Error::other("UDP socket is opaque")),
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
    C: ClientPhysicalConnector,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let expected_network_generation = egress.connector.network_generation();
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
    let fixed_buffer_count = usize::from(matches!(selected, SelectedEgress::Direct { .. }));
    let mut fixed_capacity = Vec::with_capacity(fixed_buffer_count);
    if meter_global_buffers {
        for _ in 0..fixed_buffer_count {
            fixed_capacity.push(
                budget
                    .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
                    .map_err(|_| ())?,
            );
        }
    }
    let proxy_buffers = match selected {
        SelectedEgress::Shadowsocks { .. } => Some(
            ClientProxyBuffers::dormant(
                plan.as_ref().ok_or(())?.hops().len(),
                budget.clone(),
                meter_global_buffers,
            )
            .map_err(|_| ())?,
        ),
        SelectedEgress::Direct { .. } => None,
    };
    let direct_wire = match selected {
        SelectedEgress::Direct { .. } => {
            let wire = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
            if wire.capacity() != MAX_UDP_WIRE_DATAGRAM_BYTES {
                return Err(());
            }
            debug_assert!(
                !meter_global_buffers
                    || fixed_capacity
                        .first()
                        .is_some_and(|reservation| reservation.capacity() == wire.capacity())
            );
            Some(wire)
        }
        SelectedEgress::Shadowsocks { .. } => None,
    };
    let first_server = match selected {
        SelectedEgress::Shadowsocks { first_server, .. } => Some(first_server),
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
        SelectedEgress::Shadowsocks {
            first_outbound,
            first_server,
        } => {
            let dial_options = egress
                .outbounds
                .get(first_outbound)
                .ok_or(())?
                .dial_options();
            let factory = egress.connector.udp_socket_factory(
                expected_network_generation,
                dial_options,
                &egress.route_network,
            );
            ClientUdpUpstream::Shadowsocks(
                factory
                    .open_proxy(first_server, &mut bind)
                    .await
                    .map_err(|_| ())?,
            )
        }
        SelectedEgress::Direct { outbound } => {
            let default_dial_options = DialOptions::default();
            let dial_options = outbound
                .and_then(|index| egress.outbounds.get(index))
                .map_or(&default_dial_options, ClientOutboundContext::dial_options);
            ClientUdpUpstream::Direct {
                socket: None,
                factory: egress.connector.udp_socket_factory(
                    expected_network_generation,
                    dial_options,
                    &egress.route_network,
                ),
            }
        }
    };
    if !egress
        .connector
        .network_generation_is_admissible(expected_network_generation)
    {
        return Err(());
    }
    Ok(ClientUdpAssociation {
        plan,
        _network_generation: expected_network_generation,
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
        direct_wire,
        proxy_buffers,
        _metered_fixed_capacity: fixed_capacity,
        #[cfg(test)]
        io_fault: None,
    })
}

#[cfg(test)]
mod buffer_tests {
    use super::*;
    use ferrum2_runtime::{
        MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry, UdpRuntimeLimits,
    };

    fn budget() -> (UdpSessionManager, UdpBufferBudget) {
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(8, MIN_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT)
                .expect("buffer test limits"),
            OwnerRegistry::new(),
        );
        let budget = manager.buffer_budget();
        (manager, budget)
    }

    #[test]
    fn one_two_and_eight_hops_allocate_only_lazy_minimal_wire_capacity() {
        for (hop_count, expected_buffers) in [(1, 1), (2, 2), (8, 2)] {
            let (_manager, budget) = budget();
            let mut buffers = ClientProxyBuffers::dormant(hop_count, budget.clone(), true)
                .expect("valid hop count");
            assert!(buffers.capacities().is_empty());
            assert_eq!(budget.reserved_bytes(), 0, "{hop_count} hops stay lazy");

            buffers.ensure_ready().expect("wire capacity");
            assert_eq!(
                buffers.capacities(),
                vec![MAX_UDP_WIRE_LEN; expected_buffers]
            );
            assert_eq!(
                budget.reserved_bytes(),
                expected_buffers * MAX_UDP_WIRE_LEN,
                "budget exactly matches owned capacities for {hop_count} hops"
            );

            drop(buffers);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }

    #[test]
    fn ten_thousand_dormant_associations_touch_no_wire_capacity() {
        let (_manager, budget) = budget();
        let dormant = (0..10_000)
            .map(|_| ClientProxyBuffers::dormant(1, budget.clone(), true).expect("dormant"))
            .collect::<Vec<_>>();

        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            dormant
                .iter()
                .all(|buffers| buffers.capacities().is_empty())
        );
    }

    #[test]
    fn multi_hop_lazy_allocation_rolls_back_atomically_when_second_buffer_is_unfunded() {
        let (_manager, budget) = budget();
        let mut remaining_to_hold = MIN_UDP_MAX_BUFFERED_BYTES - MAX_UDP_WIRE_LEN;
        let mut held = Vec::new();
        while remaining_to_hold != 0 {
            let capacity = remaining_to_hold.min(MAX_UDP_WIRE_LEN);
            held.push(budget.reserve(capacity).expect("hold test budget"));
            remaining_to_hold -= capacity;
        }
        let baseline = budget.reserved_bytes();
        let mut buffers =
            ClientProxyBuffers::dormant(2, budget.clone(), true).expect("valid multi-hop buffers");

        assert_eq!(buffers.ensure_ready(), Err(UdpRuntimeError::BufferLimit));
        assert!(buffers.capacities().is_empty());
        assert_eq!(budget.reserved_bytes(), baseline);

        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
