use std::collections::HashSet;
#[cfg(test)]
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
use ferrum2_crypto::{Clock, MethodKeyProvider, SecureRandom, UdpSessionId};
use ferrum2_runtime::{
    PendingUdpDatagram, PendingUdpSession, UdpBufferReservation, UdpCommitError, UdpDirection,
    UdpRuntimeError, UdpSessionHandle, UdpSessionManager,
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

use super::{ClientEgressEngine, ClientOutboundContext};

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
    plan: EgressPlanSnapshot,
    first_server: SocketAddrV4,
    protocol: Option<ClientUdpPlan>,
    pending_session: Option<PendingUdpSession>,
    manager: UdpSessionManager,
    handle: UdpSessionHandle,
    live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
    upstream: UdpSocket,
    inner_wire: Vec<u8>,
    upstream_wire: Vec<u8>,
    scratch: UdpPacketScratch,
    _fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
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
        if self.protocol.is_some() {
            return Ok(());
        }
        #[cfg(test)]
        let random = egress.udp_id_random.as_deref().unwrap_or(&egress.random);
        #[cfg(not(test))]
        let random = &egress.random;
        let legs = register_udp_plan(&egress.outbounds, self.plan.hops(), random, &self.live_ids)?;
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
        let hops = plan.hops();
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
                intermediate = TargetAddr::ipv4(
                    outbounds
                        .get(hops[layer + 1])
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
    ) -> Result<usize, UdpPlanResponseError> {
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
        let hops = plan.hops();
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
        let expected = TargetAddr::ipv4(
            outbounds
                .get(hops[1])
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
            let expected = TargetAddr::ipv4(
                outbounds
                    .get(hops[layer + 1])
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
        payload_len: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        match self.pending_session.as_ref() {
            Some(session) => session.reserve_datagram(UdpDirection::ToTarget, payload_len),
            None => self
                .manager
                .reserve_datagram(self.handle, UdpDirection::ToTarget, payload_len),
        }
    }

    pub(in crate::run) fn commit_application_datagram(
        &mut self,
        reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<(), UdpRuntimeError> {
        match self.pending_session.take() {
            Some(session) => session.commit(reservation, datagram, now).map(|_| ()),
            None => reservation.commit(datagram, now),
        }
    }

    pub(in crate::run) fn pop(
        &self,
        direction: UdpDirection,
    ) -> Result<Option<ferrum2_runtime::AccountedDatagram>, UdpRuntimeError> {
        self.manager.pop(self.handle, direction)
    }

    pub(in crate::run) fn payload_limit(
        &self,
        outbounds: &[ClientOutboundContext],
        response: bool,
        encoded_target_len: usize,
    ) -> usize {
        composed_udp_plan_limit(outbounds, self.plan.hops(), response, encoded_target_len)
    }

    pub(in crate::run) fn prepare_application_request(
        &mut self,
        engine: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: &[u8],
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
        let reservation = self
            .reserve_application_datagram(payload.len())
            .map_err(UdpPlanResponseError::Runtime)?;
        let datagram = Datagram::new(target, payload.into(), payload.len())
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        self.commit_application_datagram(reservation, datagram, now)
            .map_err(UdpPlanResponseError::Runtime)?;
        let datagram = self
            .pop(UdpDirection::ToTarget)
            .map_err(UdpPlanResponseError::Runtime)?
            .ok_or(UdpPlanResponseError::Runtime(UdpRuntimeError::Bounds))?;
        let wire_len = self
            .encode_request(engine, outbounds, datagram.datagram())
            .map_err(UdpPlanResponseError::Packet)?;
        drop(datagram);
        Ok(wire_len)
    }

    pub(in crate::run) fn prepare_application_response(
        &mut self,
        engine: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<(TargetAddr, Vec<u8>), UdpPlanResponseError> {
        let payload_len = self
            .accept_response(engine, outbounds, wire_len)
            .map_err(|error| match error {
                UdpPlanResponseError::Packet(error) => UdpPlanResponseError::Packet(error),
                UdpPlanResponseError::Runtime(error) => UdpPlanResponseError::Runtime(error),
            })?;
        let response = self
            .pop(UdpDirection::ToClient)
            .map_err(UdpPlanResponseError::Runtime)?
            .ok_or(UdpPlanResponseError::Runtime(UdpRuntimeError::Bounds))?;
        if response.datagram().payload().len() != payload_len {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        Ok((
            response.datagram().target().clone(),
            response.datagram().payload().to_vec(),
        ))
    }

    pub(in crate::run) async fn send_encoded_request(&self, wire_len: usize) -> io::Result<usize> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamSend))
        {
            return Err(io::Error::other("injected upstream send failure"));
        }
        self.upstream.send(&self.upstream_wire[..wire_len]).await
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
        self.upstream.recv(&mut self.upstream_wire).await
    }

    #[cfg(test)]
    pub(in crate::run) fn upstream_local_addr(&self) -> io::Result<SocketAddr> {
        self.upstream.local_addr()
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
        plan: &EgressPlanSnapshot,
        first_server: SocketAddrV4,
        destination: SocketAddr,
        packet: Vec<u8>,
    ) -> io::Result<((Vec<u8>, SocketAddr), bool)> {
        if packet.len() > MAX_UDP_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP packet too large",
            ));
        }
        if self.plan != *plan || self.first_server != first_server {
            return Err(invalid_dns_target());
        }
        let target = TargetAddr::ip(destination).map_err(|_| invalid_dns_target())?;
        self.activate(engine).map_err(|_| runtime_error(()))?;
        let wire_len = self
            .prepare_application_request(engine, &engine.outbounds, target, &packet, Instant::now())
            .map_err(|_| io::Error::other("DNS UDP encode failed"))?;
        let sent = self.send_encoded_request(wire_len).await?;
        if sent != wire_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short DNS UDP send",
            ));
        }
        let mut reusable = true;
        loop {
            let length = self.receive_response_wire().await?;
            let (source, payload) =
                match self.prepare_application_response(engine, &engine.outbounds, length) {
                    Ok(response) => response,
                    Err(_) => {
                        reusable = false;
                        continue;
                    }
                };
            let source = source.as_socket_addr().ok_or_else(invalid_dns_target)?;
            return Ok(((payload, source), reusable));
        }
    }
}

pub(in crate::run) async fn prepare<F, Fut>(
    egress: &ClientEgressEngine,
    plan: EgressPlanSnapshot,
    first_server: SocketAddrV4,
    mut bind: F,
) -> Result<ClientUdpAssociation, ()>
where
    F: FnMut(SocketAddrV4) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let udp = egress.udp.as_ref().ok_or(())?;
    if plan.hops().is_empty() || plan.hops().len() > MAX_UDP_PLAN_HOPS {
        return Err(());
    }
    let pending_session = udp
        .manager
        .reserve_session(Instant::now())
        .map_err(|_| ())?;
    let handle = pending_session.handle();
    let budget = udp.manager.buffer_budget();
    let mut fixed_capacity = Vec::with_capacity(3);
    for _ in 0..3 {
        fixed_capacity.push(budget.reserve(MAX_UDP_WIRE_LEN).map_err(|_| ())?);
    }
    let inner_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let upstream_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let scratch = UdpPacketScratch::new();
    let upstream = bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|_| ())?;
    upstream
        .connect(SocketAddr::V4(first_server))
        .await
        .map_err(|_| ())?;
    if std::env::var_os("FERRUM2_T05_UDP_SOCKET_PROBE").is_some_and(|value| value == "1") {
        let local = upstream.local_addr().map_err(|_| ())?;
        let peer = upstream.peer_addr().map_err(|_| ())?;
        let local_category = if local.ip().is_loopback() {
            "loopback"
        } else if local.ip().is_unspecified() {
            "unspecified"
        } else {
            "other"
        };
        let gate_port = std::env::var("FERRUM2_T05_UDP_GATE_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok());
        let peer_category = if gate_port.is_some_and(|gate_port| {
            peer.ip().is_loopback() && peer.port() == gate_port && first_server.port() == gate_port
        }) {
            "gate_a"
        } else {
            "other"
        };
        eprintln!("m15_udp_socket_diag local={local_category} peer={peer_category}");
        if peer_category == "gate_a" && !matches!(upstream.send(&[]).await, Ok(0)) {
            return Err(());
        }
    }
    Ok(ClientUdpAssociation {
        plan,
        first_server,
        protocol: None,
        pending_session: Some(pending_session),
        manager: udp.manager.clone(),
        handle,
        live_ids: Arc::clone(&udp.live_ids),
        upstream,
        inner_wire,
        upstream_wire,
        scratch,
        _fixed_capacity: fixed_capacity,
        #[cfg(test)]
        io_fault: None,
    })
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
) -> Result<usize, UdpPlanResponseError> {
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
    let payload_len = pending.payload().len();
    let (datagram, commit) = pending.materialize().into_parts();
    commits.push(commit);
    let sessions = plan
        .legs
        .iter()
        .map(|leg| &leg.protocol)
        .collect::<Vec<_>>();
    reservation
        .commit_with(datagram, Instant::now(), || {
            UdpClientSession::commit_responses(&sessions, commits, clock.monotonic_now())
        })
        .map_err(|error| match error {
            UdpCommitError::Protocol(error) => UdpPlanResponseError::Packet(error),
            UdpCommitError::Runtime(error) => UdpPlanResponseError::Runtime(error),
        })?;
    Ok(payload_len)
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
    let overhead = hops
        .iter()
        .enumerate()
        .try_fold(0_usize, |total, (layer, hop)| {
            let profile = outbounds.get(*hop)?.keys.profile();
            let target_len = if layer + 1 == hops.len() {
                encoded_target_len
            } else {
                7
            };
            let payload =
                max_udp_payload_len_for_encoded_target(profile, response, target_len, 0).ok()?;
            total.checked_add(MAX_UDP_WIRE_LEN.checked_sub(payload)?)
        });
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
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

    use ferrum2_crypto::{
        KeySelector, MethodKeyProvider, MethodPsk, MethodSecretKeyRef, MethodSinglePskProvider,
    };
    use ferrum2_runtime::{OwnerRegistry, UdpRuntimeLimits};

    use super::*;
    use crate::run::test_support::*;

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
