#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr};
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
    #[cfg(test)]
    pub(in crate::run) method: MethodProfile,
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
    pub(in crate::run) plans: HashMap<EgressPlanSnapshot, ClientUdpPlan>,
    pub(in crate::run) pending_session: Option<PendingUdpSession>,
    pub(in crate::run) manager: UdpSessionManager,
    pub(in crate::run) handle: UdpSessionHandle,
    live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
    pub(in crate::run) static_server: Option<SocketAddrV4>,
    pub(in crate::run) static_plan: Option<EgressPlanSnapshot>,
    pub(in crate::run) application: UdpSocket,
    pub(in crate::run) upstream: UdpSocket,
    pub(in crate::run) application_wire: Vec<u8>,
    pub(in crate::run) upstream_wire: Vec<u8>,
    scratch: UdpPacketScratch,
    pub(in crate::run) _fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    pub(in crate::run) io_fault: Option<Arc<UdpIoFaultPlan>>,
}

pub(in crate::run) struct ClientUdpLeg {
    protocol: UdpClientSession,
    id: UdpSessionId,
}

pub(in crate::run) struct ClientUdpPlan {
    legs: Vec<ClientUdpLeg>,
}

const MAX_ACTIVE_UDP_PLANS: usize = 128;
pub(in crate::run) const MAX_UDP_PLAN_HOPS: usize = 8;

impl Drop for ClientUdpAssociation {
    fn drop(&mut self) {
        self.manager.remove(self.handle);
        if let Ok(mut live_ids) = self.live_ids.lock() {
            for plan in self.plans.values() {
                for leg in &plan.legs {
                    live_ids.remove(&leg.id);
                }
            }
        }
    }
}

impl ClientUdpAssociation {
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

    pub(in crate::run) fn activate(
        &mut self,
        egress: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        snapshot: &EgressPlanSnapshot,
    ) -> Result<(), ()> {
        let hops = snapshot.hops();
        if hops.is_empty() || hops.len() > MAX_UDP_PLAN_HOPS {
            return Err(());
        }
        if !self.plans.contains_key(snapshot) {
            if self.plans.len() >= MAX_ACTIVE_UDP_PLANS {
                return Err(());
            }
            #[cfg(test)]
            let random = egress.udp_id_random.as_deref().unwrap_or(&egress.random);
            #[cfg(not(test))]
            let random = &egress.random;
            let legs = register_udp_plan(outbounds, hops, random, &self.live_ids)?;
            self.plans.insert(snapshot.clone(), ClientUdpPlan { legs });
        }
        Ok(())
    }

    pub(in crate::run) fn encode_request(
        &mut self,
        egress: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        snapshot: &EgressPlanSnapshot,
        datagram: &Datagram,
    ) -> Result<usize, UdpPacketError> {
        let plan = self
            .plans
            .get_mut(snapshot)
            .ok_or(UdpPacketError::StateUnavailable)?;
        let hops = snapshot.hops();
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
                    &mut self.upstream_wire,
                    &mut self.scratch,
                )?
            } else if wire_in_upstream {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    &self.upstream_wire[..wire_len],
                    0,
                    &mut self.application_wire,
                    &mut self.scratch,
                )?
            } else {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    &self.application_wire[..wire_len],
                    0,
                    &mut self.upstream_wire,
                    &mut self.scratch,
                )?
            };
            wire_in_upstream = layer + 1 == hops.len() || !wire_in_upstream;
        }
        if !wire_in_upstream {
            self.upstream_wire[..wire_len].copy_from_slice(&self.application_wire[..wire_len]);
        }
        Ok(wire_len)
    }

    pub(in crate::run) fn accept_response(
        &mut self,
        egress: &ClientEgressEngine,
        outbounds: &[ClientOutboundContext],
        source: SocketAddrV4,
        wire_len: usize,
    ) -> Result<Option<usize>, UdpPlanResponseError> {
        let mut candidate = false;
        let mut outer_error = UdpPacketError::Binding;
        // ponytail: scan at most 128 bounded plans; add an authenticated dispatch index if measured.
        for (snapshot, plan) in &self.plans {
            let hops = snapshot.hops();
            if outbounds
                .get(hops[0])
                .is_none_or(|outbound| outbound.udp_server != source)
            {
                continue;
            }
            candidate = true;
            let outer = match plan.legs[0].protocol.prepare_response_borrowed(
                &egress.clock,
                &self.upstream_wire[..wire_len],
                &mut self.scratch,
            ) {
                Ok(pending) => pending,
                Err(error) => {
                    if !matches!(
                        error,
                        UdpPacketError::Authentication | UdpPacketError::Binding
                    ) {
                        return Err(UdpPlanResponseError::Packet(error));
                    }
                    outer_error = error;
                    continue;
                }
            };
            let mut commits = Vec::with_capacity(hops.len());
            if hops.len() == 1 {
                return commit_final_udp_response(
                    outer,
                    plan,
                    hops,
                    outbounds,
                    commits,
                    &self.manager,
                    self.handle,
                    &egress.clock,
                )
                .map(Some);
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
                .copy_payload_to(&mut self.application_wire)
                .map_err(UdpPlanResponseError::Packet)?;
            commits.push(outer.into_commit());
            let mut wire_in_application = true;
            for layer in 1..hops.len() {
                let pending = if wire_in_application {
                    plan.legs[layer].protocol.prepare_response_borrowed(
                        &egress.clock,
                        &self.application_wire[..inner_len],
                        &mut self.scratch,
                    )
                } else {
                    plan.legs[layer].protocol.prepare_response_borrowed(
                        &egress.clock,
                        &self.upstream_wire[..inner_len],
                        &mut self.scratch,
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
                        &self.manager,
                        self.handle,
                        &egress.clock,
                    )
                    .map(Some);
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
                inner_len = if wire_in_application {
                    pending.copy_payload_to(&mut self.upstream_wire)
                } else {
                    pending.copy_payload_to(&mut self.application_wire)
                }
                .map_err(UdpPlanResponseError::Packet)?;
                commits.push(pending.into_commit());
                wire_in_application = !wire_in_application;
            }
        }
        if candidate {
            Err(UdpPlanResponseError::Packet(outer_error))
        } else {
            Ok(None)
        }
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
        self.activate(engine, &engine.outbounds, plan)
            .map_err(|_| invalid_dns_target())?;
        let target = TargetAddr::ip(destination).map_err(|_| invalid_dns_target())?;
        let payload_len = packet.len();
        let reservation = self
            .reserve_application_datagram(payload_len)
            .map_err(runtime_error)?;
        let datagram = Datagram::new(target, packet.as_slice().into(), payload_len)
            .map_err(|_| invalid_dns_target())?;
        let committed = match self.pending_session.take() {
            Some(session) => session.commit(reservation, datagram, Instant::now()),
            None => reservation
                .commit(datagram, Instant::now())
                .map(|()| self.handle),
        };
        committed.map_err(runtime_error)?;
        let datagram = self
            .manager
            .pop(self.handle, UdpDirection::ToTarget)
            .map_err(runtime_error)?
            .ok_or_else(|| io::Error::other("DNS UDP queue empty"))?;
        let wire_len = self
            .encode_request(engine, &engine.outbounds, plan, datagram.datagram())
            .map_err(|_| io::Error::other("DNS UDP encode failed"))?;
        drop(datagram);
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamSend))
        {
            return Err(io::Error::other("injected upstream send failure"));
        }
        let sent = self.upstream.send(&self.upstream_wire[..wire_len]).await?;
        if sent != wire_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short DNS UDP send",
            ));
        }
        let mut reusable = true;
        loop {
            #[cfg(test)]
            if self
                .io_fault
                .as_ref()
                .is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamRecv))
            {
                return Err(io::Error::other("injected upstream receive failure"));
            }
            let length = self.upstream.recv(&mut self.upstream_wire).await?;
            let payload_len =
                match self.accept_response(engine, &engine.outbounds, first_server, length) {
                    Ok(Some(payload_len)) => payload_len,
                    Ok(None) | Err(_) => {
                        reusable = false;
                        continue;
                    }
                };
            let response = self
                .manager
                .pop(self.handle, UdpDirection::ToClient)
                .map_err(runtime_error)?
                .ok_or_else(|| io::Error::other("DNS UDP response queue empty"))?;
            let source = response
                .datagram()
                .target()
                .as_socket_addr()
                .ok_or_else(invalid_dns_target)?;
            let payload = response.datagram().payload();
            if payload.len() != payload_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS UDP length mismatch",
                ));
            }
            return Ok(((payload.to_vec(), source), reusable));
        }
    }
}

pub(in crate::run) async fn prepare<F, Fut>(
    egress: &ClientEgressEngine,
    local_ip: Ipv4Addr,
    static_plan: Option<(EgressPlanSnapshot, SocketAddrV4)>,
    mut bind: F,
) -> Result<ClientUdpAssociation, ()>
where
    F: FnMut(SocketAddrV4) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let udp = egress.udp.as_ref().ok_or(())?;
    if static_plan
        .as_ref()
        .is_some_and(|(plan, _)| plan.hops().len() > MAX_UDP_PLAN_HOPS)
    {
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
    let application_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let upstream_wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let scratch = UdpPacketScratch::new();
    let application = bind(SocketAddrV4::new(local_ip, 0)).await.map_err(|_| ())?;
    let upstream = bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|_| ())?;
    let static_server = static_plan.as_ref().map(|(_, server)| *server);
    let prepared = ClientUdpAssociation {
        plans: HashMap::new(),
        pending_session: Some(pending_session),
        manager: udp.manager.clone(),
        handle,
        live_ids: Arc::clone(&udp.live_ids),
        static_server,
        static_plan: static_plan.map(|(plan, _)| plan),
        application,
        upstream,
        application_wire,
        upstream_wire,
        scratch,
        _fixed_capacity: fixed_capacity,
        #[cfg(test)]
        io_fault: None,
    };
    if let Some(server) = static_server {
        prepared
            .upstream
            .connect(SocketAddr::V4(server))
            .await
            .map_err(|_| ())?;
    }
    Ok(prepared)
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
