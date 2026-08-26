use std::collections::{HashSet, VecDeque};
use std::io;
#[cfg(any(not(windows), test))]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::Clock;
use ferrum2_crypto::{SecureRandom, UdpSessionId};
use ferrum2_net::DialOptions;
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpSocket as _, MAX_UDP_WIRE_DATAGRAM_BYTES, PendingUdpDatagram,
    PendingUdpSession, UDP_SESSION_QUEUE_DEPTH, UdpBufferReservation, UdpDirection,
    UdpRuntimeError, UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpClientSession, UdpPacketError, UdpPacketScratch};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::run::egress::context::{ClientOutboundContext, ClientRequestOrigin, SelectedEgress};
use crate::run::egress::engine::ClientEgressEngine;
use crate::run::egress::network::ClientPhysicalConnector;

use super::direct::{
    DirectUdpCandidateHints, DirectUdpFamily, DirectUdpResponseMatch, DirectUdpResponsePolicy,
    receive_direct_response, receive_proxy_response, send_direct_target_lazy,
};
use super::request::{composed_udp_plan_limit, register_udp_plan};
use super::response::{
    UdpPlanResponseError, commit_final_udp_response, dns_response_target_matches,
    invalid_dns_target, runtime_error,
};
use super::socket::{ClientDirectUdpSocket, ClientUdpSocketFactory};
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
    pending_direct_response: Option<(BytesMut, SocketAddr)>,
    pub(super) direct_wire: Option<BytesMut>,
    inner_wire: Option<Vec<u8>>,
    upstream_wire: Option<BytesMut>,
    scratch: Option<UdpPacketScratch>,
    _metered_fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

enum ClientUdpUpstream {
    Shadowsocks {
        socket: ClientDirectUdpSocket,
        peer: SocketAddr,
    },
    Direct {
        socket: Option<ClientDirectUdpSocket>,
        factory: ClientUdpSocketFactory,
    },
}

pub(super) struct ClientUdpLeg {
    pub(super) protocol: UdpClientSession,
    pub(super) id: UdpSessionId,
}

pub(super) struct ClientUdpPlan {
    pub(super) legs: Vec<ClientUdpLeg>,
}

pub(in crate::run::egress) const MAX_UDP_PLAN_HOPS: usize = 8;

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
        upstream_wire.resize(MAX_UDP_WIRE_LEN, 0);
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
            ClientUdpUpstream::Shadowsocks { socket, peer } => {
                let upstream_wire = self
                    .upstream_wire
                    .as_ref()
                    .expect("proxy UDP association owns its upstream wire buffer");
                socket.send_to(&upstream_wire[..wire_len], *peer).await
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
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks { socket, peer } => {
                let upstream_wire = self
                    .upstream_wire
                    .as_mut()
                    .expect("proxy UDP association owns its upstream wire buffer");
                receive_proxy_response(socket, *peer, upstream_wire).await
            }
            ClientUdpUpstream::Direct {
                socket: Some(socket),
                ..
            } => {
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
            ClientUdpUpstream::Direct { socket: None, .. } => {
                Err(io::Error::other("direct UDP socket unavailable"))
            }
        }
    }

    #[cfg(test)]
    pub(in crate::run) fn upstream_local_addr(&self) -> io::Result<SocketAddr> {
        match &self.upstream {
            ClientUdpUpstream::Shadowsocks {
                socket: ClientDirectUdpSocket::Raw(socket),
                ..
            } => socket.local_addr(),
            ClientUdpUpstream::Shadowsocks { .. } | ClientUdpUpstream::Direct { .. } => {
                Err(io::Error::other("UDP socket is opaque"))
            }
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
    bind: F,
) -> Result<ClientUdpAssociation, ()>
where
    C: ClientPhysicalConnector,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    #[cfg(any(not(windows), test))]
    let mut bind = bind;
    #[cfg(all(windows, not(test)))]
    let _ = bind;
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
    let upstream_wire = matches!(selected, SelectedEgress::Shadowsocks { .. }).then(|| {
        let mut wire = BytesMut::with_capacity(MAX_UDP_WIRE_LEN);
        wire.resize(MAX_UDP_WIRE_LEN, 0);
        wire
    });
    let scratch =
        matches!(selected, SelectedEgress::Shadowsocks { .. }).then(UdpPacketScratch::new);
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
            #[cfg(all(windows, not(test)))]
            let socket = factory.open(first_server).await.map_err(|_| ())?;
            #[cfg(all(not(windows), not(test)))]
            let socket = {
                let _ = factory;
                let bind_address = if first_server.is_ipv4() {
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                } else {
                    SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
                };
                ClientDirectUdpSocket::Raw(bind(bind_address).await.map_err(|_| ())?)
            };
            #[cfg(test)]
            let socket = match &factory {
                ClientUdpSocketFactory::Injected { .. } => {
                    factory.open(first_server).await.map_err(|_| ())?
                }
                ClientUdpSocketFactory::System => {
                    let bind_address = if first_server.is_ipv4() {
                        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                    } else {
                        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
                    };
                    ClientDirectUdpSocket::Raw(bind(bind_address).await.map_err(|_| ())?)
                }
            };
            ClientUdpUpstream::Shadowsocks {
                socket,
                peer: first_server,
            }
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
