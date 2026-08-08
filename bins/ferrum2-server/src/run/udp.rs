use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use ferrum2_config::{RouteAction, UdpConfig};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{Network, RouteMetadata, RouteProgramAction};
use ferrum2_crypto::{Clock as _, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Metrics, Outcome, Reason, Role, Stage, Transport as ObservationTransport,
};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, MAX_UDP_WIRE_DATAGRAM_BYTES,
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture,
    SystemDirectUdpSocketFactory, UdpBufferReservation, UdpCommitError, UdpRuntimeError,
    UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpPacketError, UdpPacketScratch, UdpServer};
use ferrum2_sniff::Transport as SniffTransport;
use tokio::net::UdpSocket;

use super::RunError;
use super::dns_egress;
use super::observation::{
    record_sniff, record_udp_failure, record_udp_protocol_failure, record_udp_request_accepted,
    record_udp_runtime_failure, update_udp_resource_metrics,
};
use super::tcp::{ServerRouting, ServerTerminalRoute, route_metadata, sniff_order};

pub(super) fn udp_runtime_limits(config: &UdpConfig) -> Option<UdpRuntimeLimits> {
    UdpRuntimeLimits::new(
        config.max_sessions,
        config.max_buffered_bytes,
        config.idle_timeout,
    )
    .ok()
}

#[derive(Default)]
struct UdpMappingState {
    by_capability: HashMap<ServerResponseCapability, BoundUdpSession>,
    by_handle: BTreeMap<UdpSessionHandle, ServerResponseCapability>,
    orphaned: HashMap<ServerResponseCapability, usize>,
    retired: BTreeSet<UdpSessionHandle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundUdpSession {
    handle: UdpSessionHandle,
    inbound: usize,
}

pub(super) struct UdpMappings {
    state: Mutex<UdpMappingState>,
    published: tokio::sync::Notify,
    limit: usize,
}

impl UdpMappings {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(UdpMappingState::default()),
            published: tokio::sync::Notify::new(),
            limit,
        }
    }

    fn handle(&self, capability: ServerResponseCapability) -> Option<BoundUdpSession> {
        self.state
            .lock()
            .expect("UDP mapping lock poisoned")
            .by_capability
            .get(&capability)
            .copied()
    }

    fn inbound(&self, capability: ServerResponseCapability) -> Option<usize> {
        let state = self.state.lock().expect("UDP mapping lock poisoned");
        state
            .by_capability
            .get(&capability)
            .map(|binding| binding.inbound)
            .or_else(|| state.orphaned.get(&capability).copied())
    }

    fn orphan_count(&self) -> usize {
        self.state
            .lock()
            .expect("UDP mapping lock poisoned")
            .orphaned
            .len()
    }

    async fn capability(&self, handle: UdpSessionHandle) -> Option<ServerResponseCapability> {
        loop {
            let notified = self.published.notified();
            {
                let state = self.state.lock().expect("UDP mapping lock poisoned");
                if let Some(capability) = state.by_handle.get(&handle).copied() {
                    return Some(capability);
                }
                if state.retired.contains(&handle) {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn publish(
        &self,
        capability: ServerResponseCapability,
        handle: UdpSessionHandle,
        inbound: usize,
    ) -> Option<ServerResponseCapability> {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        if let Some(old) = state.by_capability.remove(&capability) {
            state.by_handle.remove(&old.handle);
            retire_mapping_handle(&mut state, old.handle, self.limit);
        }
        state.orphaned.remove(&capability);
        if let Some(old_capability) = state.by_handle.remove(&handle)
            && let Some(old) = state.by_capability.remove(&old_capability)
        {
            state.orphaned.insert(old_capability, old.inbound);
        }
        state.retired.remove(&handle);
        let evicted = if state.by_handle.len() == self.limit {
            state.by_handle.pop_first().map(|(old_handle, capability)| {
                if let Some(old) = state.by_capability.remove(&capability) {
                    state.orphaned.insert(capability, old.inbound);
                }
                retire_mapping_handle(&mut state, old_handle, self.limit);
                capability
            })
        } else {
            None
        };
        state
            .by_capability
            .insert(capability, BoundUdpSession { handle, inbound });
        state.by_handle.insert(handle, capability);
        drop(state);
        self.published.notify_waiters();
        evicted
    }

    fn publish_rejected(&self, capability: ServerResponseCapability, inbound: usize) {
        self.state
            .lock()
            .expect("UDP mapping lock poisoned")
            .orphaned
            .insert(capability, inbound);
    }

    fn invalidate_handle(&self, handle: UdpSessionHandle) {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        if let Some(capability) = state.by_handle.remove(&handle)
            && let Some(old) = state.by_capability.remove(&capability)
        {
            state.orphaned.insert(capability, old.inbound);
        }
        retire_mapping_handle(&mut state, handle, self.limit);
        drop(state);
        self.published.notify_waiters();
    }

    fn reconcile_runtime(&self, mut is_live: impl FnMut(UdpSessionHandle) -> bool) {
        let handles: Vec<_> = self
            .state
            .lock()
            .expect("UDP mapping lock poisoned")
            .by_handle
            .keys()
            .copied()
            .collect();
        for handle in handles {
            if !is_live(handle) {
                self.invalidate_handle(handle);
            }
        }
    }

    fn prune_protocol(&self, protocol: &UdpServer, now: ferrum2_crypto::MonotonicInstant) {
        let candidates: Vec<_> = self
            .state
            .lock()
            .expect("UDP mapping lock poisoned")
            .orphaned
            .keys()
            .copied()
            .collect();
        let removed: Vec<_> = candidates
            .into_iter()
            .filter(|capability| protocol.remove_session(*capability, now).unwrap_or(false))
            .collect();
        if removed.is_empty() {
            return;
        }
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        for capability in removed {
            state.orphaned.remove(&capability);
        }
    }
}

fn retire_mapping_handle(state: &mut UdpMappingState, handle: UdpSessionHandle, limit: usize) {
    if state.retired.len() == limit {
        state.retired.pop_first();
    }
    state.retired.insert(handle);
}

struct ResponseCodec {
    scratch: UdpPacketScratch,
    wire: Vec<u8>,
    _scratch_reservation: UdpBufferReservation,
    _wire_reservation: UdpBufferReservation,
}

#[derive(Clone, Copy)]
struct UdpAdapterError;

const UDP_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

pub(super) trait ServerUdpListener: Send + Sync + 'static {
    fn recv_from(
        &self,
        destination: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    fn send_to(
        &self,
        source: &[u8],
        peer: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

impl ServerUdpListener for UdpSocket {
    async fn recv_from(&self, destination: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, destination).await
    }

    async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, source, peer).await
    }
}

struct ServerUdpResponseHandler<L> {
    listener: Arc<L>,
    protocol: Arc<UdpServer>,
    mappings: Arc<UdpMappings>,
    clock: Arc<SystemClock>,
    codec: Arc<OnceLock<tokio::sync::Mutex<ResponseCodec>>>,
    metrics: Arc<Metrics>,
}

impl<L> DirectUdpPacketHandler for ServerUdpResponseHandler<L>
where
    L: ServerUdpListener,
{
    type Error = UdpAdapterError;

    async fn handle_target_response(
        &self,
        session: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        let capability = self
            .mappings
            .capability(session)
            .await
            .ok_or(UdpAdapterError)?;
        let codec = self.codec.get().ok_or(UdpAdapterError)?;
        let mut codec = codec.lock().await;
        let ResponseCodec { scratch, wire, .. } = &mut *codec;
        let encoded = self
            .protocol
            .encode_response(
                capability,
                self.clock.as_ref(),
                &SystemRandom,
                response.datagram(),
                0,
                wire,
                scratch,
            )
            .map_err(|error| {
                self.mappings.invalidate_handle(session);
                record_udp_protocol_failure(&self.metrics, error);
                UdpAdapterError
            })?;
        let wire_len = encoded.wire_len();
        let peer = encoded.peer();
        self.listener
            .send_to(&wire[..wire_len], peer)
            .await
            .map_err(|_| {
                record_udp_failure(&self.metrics, Stage::Direct, Reason::Send, Outcome::Failed);
                UdpAdapterError
            })?;
        self.metrics
            .udp_datagram(Role::Server, Direction::TargetToClient, Outcome::Completed);
        self.metrics
            .add_udp_bytes(Role::Server, Direction::TargetToClient, wire_len as u64);
        Ok(())
    }
}

type ProductionUdpRuntime<L> = DirectUdpRuntime<
    dns_egress::ServerDnsResolver,
    SystemDirectUdpSocketFactory,
    ServerUdpResponseHandler<L>,
>;

pub(super) struct PreparedUdpServer<L>
where
    L: ServerUdpListener,
{
    inbound: usize,
    routing: Arc<ServerRouting>,
    listener: Arc<L>,
    protocol: Arc<UdpServer>,
    clock: Arc<SystemClock>,
    config: UdpConfig,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
    runtime: ProductionUdpRuntime<L>,
    mappings: Arc<UdpMappings>,
    admission: Arc<tokio::sync::Mutex<()>>,
    scratch: UdpPacketScratch,
    wire: Vec<u8>,
    maintenance: tokio::time::Interval,
    _receive_scratch: UdpBufferReservation,
    _receive_wire: UdpBufferReservation,
}

#[derive(Clone)]
pub(super) struct ServerUdpShared {
    pub(super) routing: Arc<ServerRouting>,
    pub(super) protocol: Arc<UdpServer>,
    pub(super) clock: Arc<SystemClock>,
    pub(super) config: UdpConfig,
    pub(super) sessions: UdpSessionManager,
    pub(super) mappings: Arc<UdpMappings>,
    pub(super) admission: Arc<tokio::sync::Mutex<()>>,
    pub(super) connect_timeout: std::time::Duration,
    pub(super) dns: Option<Arc<dns_egress::ServerDnsState>>,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
}

pub(super) fn prepare_udp_server<L>(
    inbound: usize,
    listener: Arc<L>,
    shared: ServerUdpShared,
) -> Result<PreparedUdpServer<L>, RunError>
where
    L: ServerUdpListener,
{
    let ServerUdpShared {
        routing,
        protocol,
        clock,
        config,
        sessions,
        mappings,
        admission,
        connect_timeout,
        dns,
        registry,
        metrics,
    } = shared;
    let response_codec = Arc::new(OnceLock::new());
    let handler = ServerUdpResponseHandler {
        listener: Arc::clone(&listener),
        protocol: Arc::clone(&protocol),
        mappings: Arc::clone(&mappings),
        clock: Arc::clone(&clock),
        codec: Arc::clone(&response_codec),
        metrics: Arc::clone(&metrics),
    };
    let runtime = DirectUdpRuntime::with_shared_adapters(
        sessions,
        connect_timeout,
        dns_egress::ServerDnsResolver::new(dns, inbound, Network::Udp),
        SystemDirectUdpSocketFactory,
        handler,
        registry.clone(),
    );
    let budget = runtime.sessions().buffer_budget();
    let response_scratch = budget
        .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| RunError::StartupProtocol)?;
    let response_wire = budget
        .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| RunError::StartupProtocol)?;
    response_codec
        .set(tokio::sync::Mutex::new(ResponseCodec {
            scratch: UdpPacketScratch::new(),
            wire: vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES],
            _scratch_reservation: response_scratch,
            _wire_reservation: response_wire,
        }))
        .map_err(|_| RunError::StartupProtocol)?;
    let receive_scratch = budget
        .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| RunError::StartupProtocol)?;
    let receive_wire = budget
        .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| RunError::StartupProtocol)?;
    let mut maintenance = tokio::time::interval(UDP_RECONCILE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    Ok(PreparedUdpServer {
        inbound,
        routing,
        listener,
        protocol,
        clock,
        config,
        registry,
        metrics,
        runtime,
        mappings,
        admission,
        scratch: UdpPacketScratch::new(),
        wire: vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES],
        maintenance,
        _receive_scratch: receive_scratch,
        _receive_wire: receive_wire,
    })
}

impl<L> PreparedUdpServer<L>
where
    L: ServerUdpListener,
{
    async fn run_with_cancellation(
        self,
        mut cancellation: ProcessCancellation,
    ) -> Result<(), RunError> {
        let shutdown_cancellation = cancellation.clone();
        self.run_with_shutdown(
            async move { cancellation.cancelled().await },
            move |runtime| runtime.shutdown_with_cancellation(shutdown_cancellation),
        )
        .await
    }

    async fn run_with_shutdown<S, C, F>(
        self,
        shutdown: S,
        shutdown_runtime: C,
    ) -> Result<(), RunError>
    where
        S: std::future::Future<Output = ()>,
        C: FnOnce(ProductionUdpRuntime<L>) -> F,
        F: std::future::Future<Output = usize>,
    {
        let Self {
            inbound,
            routing,
            listener,
            protocol,
            clock,
            config,
            registry,
            metrics,
            mut runtime,
            mappings,
            admission,
            mut scratch,
            mut wire,
            mut maintenance,
            _receive_scratch,
            _receive_wire,
        } = self;
        maintenance.tick().await;
        tokio::pin!(shutdown);

        let terminal = loop {
            let received = tokio::select! {
                biased;
                _ = &mut shutdown => break Ok(()),
                _ = maintenance.tick() => {
                    reconcile_udp_generations(&runtime, &mappings);
                    mappings.prune_protocol(&protocol, clock.monotonic_now());
                    update_udp_resource_metrics(&metrics, &registry);
                    continue;
                }
                received = listener.recv_from(&mut wire) => received,
            };
            let (wire_len, peer) = match received {
                Ok(received) => received,
                Err(_) => {
                    record_udp_failure(&metrics, Stage::Listen, Reason::Receive, Outcome::Failed);
                    break Err(RunError::RuntimeListener);
                }
            };
            let wire = &wire[..wire_len];
            let pending = match protocol.prepare_request(clock.as_ref(), wire, &mut scratch) {
                Ok(pending) => pending,
                Err(error) => {
                    record_udp_protocol_failure(&metrics, error);
                    continue;
                }
            };
            // ponytail: one gate closes cross-inbound bind races; shard by session if UDP
            // admission throughput becomes measurable.
            let _admission = admission.lock().await;
            let existing = match protocol.existing_capability(&pending) {
                Ok(existing) => existing,
                Err(error) => {
                    record_udp_protocol_failure(&metrics, error);
                    break Err(RunError::RuntimeRoot);
                }
            };
            if existing
                .and_then(|capability| mappings.inbound(capability))
                .is_some_and(|bound_inbound| bound_inbound != inbound)
            {
                record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                continue;
            }
            let terminal = select_udp_route(
                &routing,
                inbound,
                pending.datagram().target(),
                pending.datagram().payload(),
                &metrics,
            );
            if terminal == ServerTerminalRoute::Reject {
                if routing.program().is_none() {
                    continue;
                }
                if existing.is_none() {
                    mappings.prune_protocol(&protocol, clock.monotonic_now());
                    if mappings.orphan_count() >= config.max_sessions {
                        record_udp_runtime_failure(&metrics, UdpRuntimeError::SessionLimit);
                        continue;
                    }
                }
                let (_datagram, commit) = pending.into_parts();
                match protocol.commit_request(commit, peer, clock.monotonic_now(), &SystemRandom) {
                    Ok(accepted)
                        if existing
                            .is_none_or(|capability| capability == accepted.capability()) =>
                    {
                        if existing.is_none() {
                            mappings.publish_rejected(accepted.capability(), inbound);
                        }
                        metrics.udp_datagram(
                            Role::Server,
                            Direction::ClientToTarget,
                            Outcome::Rejected,
                        );
                    }
                    Ok(_) => record_udp_protocol_failure(&metrics, UdpPacketError::Generation),
                    Err(error) => record_udp_protocol_failure(&metrics, error),
                }
                update_udp_resource_metrics(&metrics, &registry);
                continue;
            }
            if existing.is_none() {
                mappings.prune_protocol(&protocol, clock.monotonic_now());
                match protocol.session_count() {
                    Ok(count) if count >= config.max_sessions => {
                        record_udp_runtime_failure(&metrics, UdpRuntimeError::SessionLimit);
                        continue;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        record_udp_protocol_failure(&metrics, error);
                        break Err(RunError::RuntimeRoot);
                    }
                }
            }
            if let Some((capability, binding)) = existing.and_then(|capability| {
                mappings
                    .handle(capability)
                    .map(|binding| (capability, binding))
            }) {
                if binding.inbound != inbound {
                    record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                    continue;
                }
                let handle = binding.handle;
                let Some(reserved) = reserve_udp_direct(terminal, || {
                    std::future::ready(
                        runtime.reserve_datagram(handle, pending.datagram().allocated_capacity()),
                    )
                })
                .await
                else {
                    continue;
                };
                match reserved {
                    Ok(reservation) => {
                        let (datagram, commit) = pending.into_parts();
                        let committed =
                            reservation.commit_with(datagram, tokio::time::Instant::now(), || {
                                // QA-M2-T02-N01: replay/peer/activity advances only
                                // while T03 holds this generation/queue reservation.
                                let accepted = protocol.commit_request(
                                    commit,
                                    peer,
                                    clock.monotonic_now(),
                                    &SystemRandom,
                                )?;
                                if accepted.capability() == capability {
                                    Ok(())
                                } else {
                                    Err(UdpPacketError::Generation)
                                }
                            });
                        match committed {
                            Ok(()) => record_udp_request_accepted(&metrics, wire_len),
                            Err(UdpCommitError::Runtime(error)) => {
                                mappings.invalidate_handle(handle);
                                record_udp_runtime_failure(&metrics, error);
                            }
                            Err(UdpCommitError::Protocol(error)) => {
                                record_udp_protocol_failure(&metrics, error);
                            }
                        }
                        update_udp_resource_metrics(&metrics, &registry);
                        continue;
                    }
                    Err(UdpRuntimeError::Cancelled) => {
                        mappings.invalidate_handle(handle);
                    }
                    Err(error) => {
                        record_udp_runtime_failure(&metrics, error);
                        continue;
                    }
                }
            }

            let Some(admission) = reserve_udp_direct(terminal, || {
                runtime.reserve_session(
                    tokio::time::Instant::now(),
                    pending.datagram().allocated_capacity(),
                )
            })
            .await
            else {
                continue;
            };
            let admission = match admission {
                Ok(admission) => admission,
                Err(error) => {
                    record_udp_runtime_failure(&metrics, error);
                    continue;
                }
            };
            let (datagram, commit) = pending.into_parts();
            let mut committed_capability = None;
            let committed = runtime.commit_session_with(
                admission,
                datagram,
                tokio::time::Instant::now(),
                || {
                    // QA-M2-T02-N01: new protocol state is created only inside
                    // T03's reserved session/bytes/queue commit transition.
                    let accepted = protocol.commit_request(
                        commit,
                        peer,
                        clock.monotonic_now(),
                        &SystemRandom,
                    )?;
                    committed_capability = Some(accepted.capability());
                    Ok(())
                },
            );
            match committed {
                Ok(handle) => {
                    let Some(capability) = committed_capability else {
                        runtime.remove_session(handle);
                        record_udp_protocol_failure(&metrics, UdpPacketError::Generation);
                        break Err(RunError::RuntimeRoot);
                    };
                    if mappings.publish(capability, handle, inbound).is_some() {
                        mappings.prune_protocol(&protocol, clock.monotonic_now());
                    }
                    record_udp_request_accepted(&metrics, wire_len);
                }
                Err(UdpCommitError::Runtime(error)) => record_udp_runtime_failure(&metrics, error),
                Err(UdpCommitError::Protocol(error)) => {
                    record_udp_protocol_failure(&metrics, error)
                }
            }
            update_udp_resource_metrics(&metrics, &registry);
        };

        let forced = if terminal.is_err() {
            runtime.shutdown(std::time::Duration::ZERO).await
        } else {
            shutdown_runtime(runtime).await
        };
        for _ in 0..forced {
            metrics.udp_forced_shutdown(Role::Server);
        }
        update_udp_resource_metrics(&metrics, &registry);
        terminal
    }
}

impl<L> PreparedProcessRoot<RunError> for PreparedUdpServer<L>
where
    L: ServerUdpListener,
{
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.run_with_cancellation(cancellation).await })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

fn reconcile_udp_generations<R, F, H>(runtime: &DirectUdpRuntime<R, F, H>, mappings: &UdpMappings)
where
    R: ferrum2_runtime::UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    F: ferrum2_runtime::DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    mappings.reconcile_runtime(|handle| match runtime.reserve_datagram(handle, 0) {
        Ok(reservation) => {
            drop(reservation);
            true
        }
        Err(UdpRuntimeError::Cancelled) => false,
        Err(_) => true,
    });
}

fn select_udp_route(
    routing: &ServerRouting,
    inbound: usize,
    target: &TargetAddr,
    payload: &[u8],
    metrics: &Metrics,
) -> ServerTerminalRoute {
    let Some(program) = routing.program() else {
        return routing.legacy(inbound, Network::Udp, target);
    };
    let mut evaluation = program.evaluate(inbound, Network::Udp, target);
    let mut protocol = None;
    let mut domain = None;
    let mut sniffed = false;
    loop {
        match evaluation
            .next(RouteMetadata::new(protocol, domain.as_ref()))
            .expect("validated route program has one terminal action")
        {
            RouteProgramAction::Continue(RouteAction::Sniff(sniffers)) if !sniffed => {
                sniffed = true;
                let order = sniff_order(sniffers, Network::Udp);
                let progress = ferrum2_sniff::sniff(
                    payload,
                    program.sniff.max_bytes,
                    SniffTransport::Udp,
                    target.port().get(),
                    &order,
                );
                record_sniff(metrics, ObservationTransport::Udp, progress.clone(), None);
                (protocol, domain) = route_metadata(progress);
            }
            RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
            RouteProgramAction::Continue(_) => return ServerTerminalRoute::Reject,
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                return routing.terminal(action);
            }
        }
    }
}

async fn reserve_udp_direct<R, F>(
    terminal: ServerTerminalRoute,
    reserve: impl FnOnce() -> F,
) -> Option<R>
where
    F: std::future::Future<Output = R>,
{
    (terminal == ServerTerminalRoute::Direct).then_some(())?;
    Some(reserve().await)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use ferrum2_core::Datagram;
    use ferrum2_runtime::UdpDirection;
    use ferrum2_shadowsocks::{UdpClientSession, UdpPacketError};
    use tokio::sync::Notify;

    use super::*;
    use crate::run::test_support::*;

    struct ScriptedUdpListener {
        request: Mutex<Option<(Vec<u8>, SocketAddr)>>,
        terminal_gate: Arc<Notify>,
        handler_entered: Arc<Notify>,
        response_gate: Arc<Notify>,
        sent: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl ServerUdpListener for ScriptedUdpListener {
        async fn recv_from(&self, destination: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let request = self.request.lock().expect("scripted UDP request").take();
            let Some((wire, peer)) = request else {
                self.terminal_gate.notified().await;
                return Err(io::Error::other("listener terminal"));
            };
            destination[..wire.len()].copy_from_slice(&wire);
            Ok((wire.len(), peer))
        }

        async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
            self.handler_entered.notify_one();
            self.response_gate.notified().await;
            self.sent.lock().expect("scripted sends").push(peer);
            Ok(source.len())
        }
    }

    #[tokio::test]
    async fn udp_shared_roots_drain_external_and_force_fatal_without_early_cleanup() {
        for fatal in [false, true] {
            let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
            let (path, mut config) = server_test_config(listen);
            config.runtime.shutdown_grace = Duration::from_secs(u64::from(!fatal));
            let stalled_target = udp_loopback().await;
            let target = stalled_target.local_addr().expect("stalled target address");
            let keys = aes_keys();
            let mut c = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client");
            let wire = encoded_udp_request(
                &mut c,
                &SystemClock::new(),
                TargetAddr::ip(target).expect("target"),
                b"listener-failure",
            );
            let handler_entered = Arc::new(Notify::new());
            let response_gate = Arc::new(Notify::new());
            let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_089));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let listener = Arc::new(ScriptedUdpListener {
                request: Mutex::new(Some((wire, peer))),
                terminal_gate: Arc::new(Notify::new()),
                handler_entered: Arc::clone(&handler_entered),
                response_gate: Arc::clone(&response_gate),
                sent: Arc::clone(&sent),
            });
            let fatal_gate = Arc::new(Notify::new());
            let fatal_listener = Arc::new(ScriptedUdpListener {
                request: Mutex::new(None),
                terminal_gate: Arc::clone(&fatal_gate),
                handler_entered: Arc::clone(&handler_entered),
                response_gate: Arc::clone(&response_gate),
                sent: Arc::clone(&sent),
            });
            let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
            let registry = OwnerRegistry::new();
            let baseline = active(registry.snapshot());
            let metrics = Arc::new(Metrics::new());
            let shutdown_grace = config.runtime.shutdown_grace;
            let limits = udp_runtime_limits(&config.udp).expect("validated UDP limits");
            let sessions = UdpSessionManager::new(limits, registry.clone());
            let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
            let observed_mappings = Arc::clone(&mappings);
            let shared = ServerUdpShared {
                routing: Arc::new(ServerRouting {
                    legacy: config.route,
                    program: config.route_program,
                    outbound_count: config.outbounds.len(),
                }),
                protocol,
                clock: Arc::new(SystemClock::new()),
                config: config.udp,
                sessions,
                mappings,
                admission: Arc::new(tokio::sync::Mutex::new(())),
                connect_timeout: config.runtime.connect_timeout,
                dns: None,
                registry: registry.clone(),
                metrics: Arc::clone(&metrics),
            };
            let fatal_shared = shared.clone();
            let active_root =
                ProcessRoot::new(move || async move { prepare_udp_server(0, listener, shared) });
            let failed = ProcessRoot::new(move || async move {
                prepare_udp_server(1, fatal_listener, fatal_shared)
            });
            let supervisor =
                ProcessSupervisor::new(vec![active_root, failed], shutdown_grace, registry.clone())
                    .expect("two required UDP roots");
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let mut process = tokio::spawn(supervisor.run_until(async {
                let _ = stopped.await;
            }));

            let mut target_buffer = [0_u8; 32];
            let (received, source) = recv_udp(&stalled_target, &mut target_buffer).await;
            assert_eq!(&target_buffer[..received], b"listener-failure");
            let live = registry.snapshot();
            assert_eq!(
                (live.active_process_roots, live.udp_sessions, live.udp_tasks),
                (2, 1, 1)
            );
            stalled_target
                .send_to(b"blocked-response", source)
                .await
                .expect("target response");
            handler_entered.notified().await;
            if fatal {
                fatal_gate.notify_one();
            } else {
                stop.send(()).expect("external stop");
                tokio::time::timeout(Duration::from_secs(1), async {
                    while registry.snapshot().active_process_roots != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("empty UDP root reap");
                let state = observed_mappings.state.lock().expect("mapping lock");
                assert_eq!(state.by_capability.len(), 1);
                assert_eq!(state.by_capability.values().next().unwrap().inbound, 0);
                drop(state);
                response_gate.notify_one();
            }

            let report = match tokio::time::timeout(Duration::from_secs(2), &mut process).await {
                Ok(Ok(report)) => report,
                Ok(Err(error)) => panic!("process owner failed: {error}"),
                Err(_) => {
                    process.abort();
                    let _ = process.await;
                    panic!("terminal UDP root waited for process Forced before returning");
                }
            };
            assert_eq!(report.cleanup_failure(), None);
            assert_eq!(active(registry.snapshot()), baseline);
            assert_eq!(report.forced_roots(), usize::from(fatal));
            assert_eq!(registry.snapshot().udp_forced_shutdowns, usize::from(fatal));
            if fatal {
                assert!(matches!(
                    report.cause(),
                    ProcessCause::RootStopped {
                        root,
                        exit: ProcessRootExit::Failed(RunError::RuntimeListener),
                    } if root.get() == 1
                ));
                assert!(sent.lock().expect("scripted sends").is_empty());
                let encoded = metrics.encode_text().expect("metrics");
                assert!(encoded.contains("ferrum2_udp_forced_shutdown_total{role=\"server\"} 1"));
            } else {
                assert!(matches!(report.cause(), ProcessCause::ExternalShutdown));
                assert_eq!(&*sent.lock().expect("scripted sends"), &[peer]);
            }
            std::fs::remove_file(path).expect("remove terminal UDP config");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_lifecycle_generation(
        client: &mut UdpClientSession,
        protocol: &UdpServer,
        manager: &UdpSessionManager,
        mappings: &UdpMappings,
        clock: &SystemClock,
        target: SocketAddr,
        peer: SocketAddr,
        payload: &'static [u8],
        protocol_now: ferrum2_crypto::MonotonicInstant,
        scratch: &mut UdpPacketScratch,
    ) -> (ServerResponseCapability, UdpSessionHandle) {
        let wire = encoded_udp_request(
            client,
            clock,
            TargetAddr::ip(target).expect("lifecycle target"),
            payload,
        );
        let pending = protocol
            .prepare_request(clock, &wire, scratch)
            .expect("prepare lifecycle request");
        let now = tokio::time::Instant::now();
        let session = manager.reserve_session(now).expect("reserve generation");
        let reserved = session
            .reserve_datagram(
                UdpDirection::ToTarget,
                pending.datagram().allocated_capacity(),
            )
            .expect("reserve generation datagram");
        let (datagram, commit) = pending.into_parts();
        let mut capability = None;
        let handle = session
            .commit_with(reserved, datagram, now, || {
                // This witness preserves the production T03 reservation
                // boundary around the T02 protocol commit.
                let accepted =
                    protocol.commit_request(commit, peer, protocol_now, &SystemRandom)?;
                capability = Some(accepted.capability());
                Ok::<(), UdpPacketError>(())
            })
            .expect("commit lifecycle generation");
        let capability = capability.expect("lifecycle capability");
        assert_eq!(mappings.publish(capability, handle, 0), None);
        drop(
            manager
                .pop(handle, UdpDirection::ToTarget)
                .expect("lifecycle queue")
                .expect("lifecycle datagram"),
        );
        (capability, handle)
    }

    #[test]
    fn typed_reject_commits_only_replay_binding_while_direct_capacity_is_full() {
        const REJECT_DNS_QUERY: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'r',
            b'e', b'j', b'e', b'c', b't', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let listen = reserve_address();
        let route = "[route]\n\
            final = \"direct\"\n\
            [[route.rules]]\n\
            network = \"udp\"\n\
            action = \"sniff\"\n\
            sniffers = \"dns\"\n\
            [[route.rules]]\n\
            network = \"udp\"\n\
            protocol = \"dns\"\n\
            domain = \"reject.test\"\n\
            action = \"reject\"\n";
        let (path, mut config) = server_v2_test_config(listen, route);
        config.udp.max_sessions = 1;
        let routing = ServerRouting {
            legacy: config.route,
            program: config.route_program,
            outbound_count: config.outbounds.len(),
        };
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(
            udp_runtime_limits(&config.udp).expect("capacity-one limits"),
            registry.clone(),
        );
        let mappings = UdpMappings::new(1);
        let keys = aes_keys();
        let protocol = UdpServer::new(&keys).expect("server protocol");
        let clock = SystemClock::new();
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_089));
        let mut scratch = UdpPacketScratch::new();
        let mut direct_client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("direct client");
        let (_direct_capability, direct_handle) = commit_lifecycle_generation(
            &mut direct_client,
            &protocol,
            &manager,
            &mappings,
            &clock,
            target,
            peer,
            b"fill-direct-capacity",
            clock.monotonic_now(),
            &mut scratch,
        );
        assert!(matches!(
            manager.reserve_session(tokio::time::Instant::now()),
            Err(UdpRuntimeError::SessionLimit)
        ));

        let mut rejected_client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("rejected client");
        let rejected_wire = encoded_udp_request(
            &mut rejected_client,
            &clock,
            TargetAddr::ip(target).expect("reject target"),
            REJECT_DNS_QUERY,
        );
        let pending = protocol
            .prepare_request(&clock, &rejected_wire, &mut scratch)
            .expect("authenticated reject prepare");
        assert!(
            protocol
                .existing_capability(&pending)
                .expect("existing")
                .is_none()
        );
        assert_eq!(
            select_udp_route(
                &routing,
                0,
                pending.datagram().target(),
                pending.datagram().payload(),
                &Metrics::new(),
            ),
            ServerTerminalRoute::Reject
        );
        let (_datagram, commit) = pending.into_parts();
        let rejected = protocol
            .commit_request(commit, peer, clock.monotonic_now(), &SystemRandom)
            .expect("typed reject bounded commit");
        mappings.publish_rejected(rejected.capability(), 0);
        assert_eq!(mappings.inbound(rejected.capability()), Some(0));
        assert_ne!(mappings.inbound(rejected.capability()), Some(1));
        assert_eq!(mappings.orphan_count(), 1);
        let duplicate = protocol
            .prepare_request(&clock, &rejected_wire, &mut scratch)
            .expect("duplicate remains deferred until commit");
        let (_datagram, duplicate_commit) = duplicate.into_parts();
        assert!(matches!(
            protocol.commit_request(duplicate_commit, peer, clock.monotonic_now(), &SystemRandom,),
            Err(UdpPacketError::Duplicate)
        ));
        assert_eq!(registry.snapshot().udp_sessions, 1);

        mappings.prune_protocol(
            &protocol,
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(u64::MAX / 4)),
        );
        assert_eq!(mappings.inbound(rejected.capability()), None);
        assert_eq!(mappings.orphan_count(), 0);
        assert!(manager.remove(direct_handle));
        mappings.invalidate_handle(direct_handle);

        let later_wire = encoded_udp_request(
            &mut rejected_client,
            &clock,
            TargetAddr::ip(target).expect("later target"),
            b"later-direct",
        );
        let pending = protocol
            .prepare_request(&clock, &later_wire, &mut scratch)
            .expect("later legal prepare");
        assert_eq!(
            select_udp_route(
                &routing,
                0,
                pending.datagram().target(),
                pending.datagram().payload(),
                &Metrics::new(),
            ),
            ServerTerminalRoute::Direct
        );
        let admission = manager
            .reserve_session(tokio::time::Instant::now())
            .expect("released direct capacity");
        let reserved = admission
            .reserve_datagram(
                UdpDirection::ToTarget,
                pending.datagram().allocated_capacity(),
            )
            .expect("later datagram capacity");
        let (datagram, commit) = pending.into_parts();
        let mut later_capability = None;
        let handle = admission
            .commit_with(reserved, datagram, tokio::time::Instant::now(), || {
                let accepted =
                    protocol.commit_request(commit, peer, clock.monotonic_now(), &SystemRandom)?;
                later_capability = Some(accepted.capability());
                Ok::<(), UdpPacketError>(())
            })
            .expect("later direct commit");
        mappings.publish(later_capability.expect("later capability"), handle, 0);
        assert_eq!(registry.snapshot().udp_sessions, 1);
        std::fs::remove_file(path).expect("remove typed reject config");
    }

    #[tokio::test]
    async fn udp_generation_termination_retention_and_replacement_cleanup() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
        let client_clock = SystemClock::new();
        let lifecycle_keys = aes_keys();
        let lifecycle_protocol =
            UdpServer::new(&lifecycle_keys).expect("lifecycle server protocol");
        let manager_registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60))
                .expect("capacity-one limits"),
            manager_registry.clone(),
        );
        let mappings = UdpMappings::new(1);
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_091));
        let protocol_zero = ferrum2_crypto::MonotonicInstant::ZERO;
        let mut lifecycle_scratch = UdpPacketScratch::new();
        let mut lifecycle_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        let mut client_a =
            UdpClientSession::new(&lifecycle_keys, &SystemRandom, |_| false).expect("client A");
        let (capability_a, handle_a) = commit_lifecycle_generation(
            &mut client_a,
            &lifecycle_protocol,
            &manager,
            &mappings,
            &client_clock,
            target,
            peer,
            b"generation-a",
            protocol_zero,
            &mut lifecycle_scratch,
        );
        assert_eq!(
            lifecycle_protocol
                .session_count()
                .expect("protocol A count"),
            1
        );
        assert_eq!(manager_registry.snapshot().udp_sessions, 1);

        assert!(manager.remove(handle_a));
        mappings.reconcile_runtime(|handle| {
            match manager.reserve_datagram(handle, UdpDirection::ToTarget, 0) {
                Ok(reservation) => {
                    drop(reservation);
                    true
                }
                Err(UdpRuntimeError::Cancelled) => false,
                Err(_) => true,
            }
        });
        assert_eq!(mappings.handle(capability_a), None);
        assert_eq!(mappings.inbound(capability_a), Some(0));
        assert_eq!(mappings.capability(handle_a).await, None);
        assert_eq!(manager_registry.snapshot().udp_sessions, 0);
        mappings.prune_protocol(
            &lifecycle_protocol,
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_millis(59_999)),
        );
        assert_eq!(
            lifecycle_protocol
                .session_count()
                .expect("retained A count"),
            1
        );
        mappings.prune_protocol(
            &lifecycle_protocol,
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(60)),
        );
        assert_eq!(
            lifecycle_protocol.session_count().expect("retired A count"),
            0
        );
        assert_eq!(mappings.inbound(capability_a), None);
        let late_response = Datagram::new(
            TargetAddr::ip(target).expect("late target"),
            b"late".as_slice().into(),
            4,
        )
        .expect("late response");
        assert_eq!(
            lifecycle_protocol
                .encode_response(
                    capability_a,
                    &client_clock,
                    &SystemRandom,
                    &late_response,
                    0,
                    &mut lifecycle_wire,
                    &mut lifecycle_scratch,
                )
                .expect_err("retired A capability"),
            UdpPacketError::Generation
        );

        let mut client_b =
            UdpClientSession::new(&lifecycle_keys, &SystemRandom, |_| false).expect("client B");
        let (capability_b, handle_b) = commit_lifecycle_generation(
            &mut client_b,
            &lifecycle_protocol,
            &manager,
            &mappings,
            &client_clock,
            target,
            peer,
            b"generation-b",
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(60)),
            &mut lifecycle_scratch,
        );
        assert_ne!(capability_b, capability_a);
        assert_eq!(
            lifecycle_protocol
                .session_count()
                .expect("protocol B count"),
            1
        );
        assert_eq!(manager_registry.snapshot().udp_sessions, 1);

        assert!(manager.remove(handle_b));
        mappings.reconcile_runtime(|handle| {
            match manager.reserve_datagram(handle, UdpDirection::ToTarget, 0) {
                Ok(reservation) => {
                    drop(reservation);
                    true
                }
                Err(UdpRuntimeError::Cancelled) => false,
                Err(_) => true,
            }
        });
        mappings.prune_protocol(
            &lifecycle_protocol,
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(120)),
        );
        assert_eq!(
            lifecycle_protocol.session_count().expect("retired B count"),
            0
        );
        assert_eq!(manager_registry.snapshot().udp_sessions, 0);
        assert_eq!(manager_registry.snapshot().udp_buffered_bytes, 0);
    }

    #[tokio::test]
    async fn udp_composition_three_methods_echo_and_deferred_client_commit_table() {
        let rows: [(MethodProfile, &str, &str, &[u8]); 3] = [
            (
                MethodProfile::Blake3Aes128Gcm2022,
                "2022-blake3-aes-128-gcm",
                "AAECAwQFBgcICQoLDA0ODw==",
                &PSK_BYTES,
            ),
            (
                MethodProfile::Blake3Aes256Gcm2022,
                "2022-blake3-aes-256-gcm",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                &[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ],
            ),
            (
                MethodProfile::Blake3ChaCha20Poly13052022,
                "2022-blake3-chacha20-poly1305",
                "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
                &[
                    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
                ],
            ),
        ];
        for (profile, method, encoded_psk, psk) in rows {
            let listen = reserve_address();
            let echo = udp_loopback().await;
            let echo_target = echo.local_addr().expect("echo address");
            let echo_task = tokio::spawn(async move {
                let mut buffer = [0_u8; 64];
                for _ in 0..3 {
                    let (length, peer) = echo.recv_from(&mut buffer).await.expect("echo receive");
                    echo.send_to(&buffer[..length], peer)
                        .await
                        .expect("echo reply");
                }
            });
            let (path, config) = server_test_config_for_method(listen, method, encoded_psk);
            let registry = OwnerRegistry::new();
            let (stop, mut server) = spawn_test_server(config, &registry);
            wait_until_bound(&mut server, listen).await;

            let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
                MethodPsk::try_from_slice(profile, psk).expect("method key"),
            ));
            let clock = SystemClock::new();
            let mut client =
                UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
            let socket = udp_loopback().await;
            let mut response_scratch = UdpPacketScratch::new();
            let mut response_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
            let client_registry = OwnerRegistry::new();
            let manager =
                UdpSessionManager::new(UdpRuntimeLimits::default(), client_registry.clone());
            let mut handle = None;

            for (index, payload) in [b"one".as_slice(), b"two", b"three"]
                .into_iter()
                .enumerate()
            {
                let target = if profile == MethodProfile::Blake3Aes128Gcm2022 && index == 2 {
                    TargetAddr::domain("127.0.0.1", echo_target.port())
                        .expect("numeric domain target")
                } else {
                    TargetAddr::ip(echo_target).expect("echo target")
                };
                let request_wire = encoded_udp_request(&mut client, &clock, target, payload);
                socket
                    .send_to(&request_wire, listen)
                    .await
                    .expect("send request");
                let (length, source) = tokio::time::timeout(
                    Duration::from_secs(5),
                    socket.recv_from(&mut response_wire),
                )
                .await
                .expect("response deadline")
                .expect("receive response");
                assert_eq!(source, SocketAddr::V4(listen));
                let pending = client
                    .prepare_response(&clock, &response_wire[..length], &mut response_scratch)
                    .expect("prepare response");
                let capacity = pending.datagram().allocated_capacity();
                let (datagram, commit) = pending.into_parts();
                let now = tokio::time::Instant::now();
                let accepted_handle = match handle {
                    Some(handle) => {
                        manager
                            .reserve_datagram(handle, UdpDirection::ToClient, capacity)
                            .expect("response capacity")
                            .commit_with(datagram, now, || {
                                // The local client composition owns this call;
                                // it mirrors the same deferred T03 transition.
                                client.commit_response(commit, clock.monotonic_now())
                            })
                            .expect("deferred response commit");
                        handle
                    }
                    None => {
                        let session = manager.reserve_session(now).expect("client session");
                        let reserved = session
                            .reserve_datagram(UdpDirection::ToClient, capacity)
                            .expect("first response capacity");
                        session
                            .commit_with(reserved, datagram, now, || {
                                // The first client association is also deferred
                                // until session/bytes/queue capacity is reserved.
                                client.commit_response(commit, clock.monotonic_now())
                            })
                            .expect("deferred first response commit")
                    }
                };
                handle = Some(accepted_handle);
                let accepted = manager
                    .pop(accepted_handle, UdpDirection::ToClient)
                    .expect("response queue")
                    .expect("accepted response");
                assert_eq!(accepted.datagram().payload(), payload);
                assert_eq!(
                    accepted.datagram().target(),
                    &TargetAddr::ip(echo_target).expect("observed source target")
                );
            }

            echo_task.await.expect("echo task");
            stop.send(()).expect("stop server");
            assert_eq!(server.await.expect("server task"), Ok(()), "{method}");
            manager.cancel_all();
            assert_eq!(client_registry.snapshot().udp_sessions, 0);
            assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
            std::fs::remove_file(path).expect("remove UDP config");
        }
    }

    #[tokio::test]
    async fn udp_real_socket_session_saturation_never_reaches_second_target() {
        let listen = reserve_address();
        let (path, _config) = server_test_config(listen);
        let mut source = std::fs::read_to_string(&path).expect("server config");
        source.push_str(
            "[udp]\nmax_sessions = 1\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n",
        );
        std::fs::write(&path, source).expect("bounded UDP config");
        let config = ferrum2_config::load_server(&path).expect("bounded server config");
        let registry = OwnerRegistry::new();
        let (stop, mut server) = spawn_test_server(config, &registry);
        wait_until_bound(&mut server, listen).await;

        let stalled_target = udp_loopback().await;
        let stalled_address = stalled_target.local_addr().expect("stalled address");
        let forbidden_target = udp_loopback().await;
        let forbidden_address = forbidden_target.local_addr().expect("forbidden address");
        let keys = aes_keys();
        let clock = SystemClock::new();
        let mut first =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
        let mut second =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
        let first_socket = udp_loopback().await;
        let second_socket = udp_loopback().await;
        let wire = encoded_udp_request(
            &mut first,
            &clock,
            TargetAddr::ip(stalled_address).expect("stalled target"),
            b"occupy",
        );
        first_socket
            .send_to(&wire, listen)
            .await
            .expect("first send");
        let mut target_buffer = [0_u8; 32];
        let (received, _) = recv_udp(&stalled_target, &mut target_buffer).await;
        assert_eq!(&target_buffer[..received], b"occupy");

        let wire = encoded_udp_request(
            &mut second,
            &clock,
            TargetAddr::ip(forbidden_address).expect("forbidden target"),
            b"must-not-send",
        );
        second_socket
            .send_to(&wire, listen)
            .await
            .expect("second send");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                forbidden_target.recv_from(&mut target_buffer)
            )
            .await
            .is_err(),
            "saturated session reached the second target"
        );

        stop.send(()).expect("stop server");
        assert_eq!(server.await.expect("server task"), Ok(()));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove saturation config");
    }
}
