use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ferrum2_config::{RouteAction, UdpConfig};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{Network, RouteMetadata, RouteProgramAction};
use ferrum2_crypto::{Clock as _, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Metrics, Outcome, Reason, Role, Stage, Transport as ObservationTransport,
};
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, MAX_UDP_WIRE_DATAGRAM_BYTES,
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, SniffPrefixOutcome,
    SystemDirectUdpSocketFactory, UdpBufferBudget, UdpBufferReservation, UdpCommitError,
    UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpPacketError, UdpPacketScratch, UdpServer};
use ferrum2_sniff::{Progress as SniffProgress, Transport as SniffTransport};
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

    fn reconcile_runtime(&self, sessions: &UdpSessionManager) {
        let candidates: Vec<_> = self
            .state
            .lock()
            .expect("UDP mapping lock poisoned")
            .by_handle
            .keys()
            .copied()
            .collect();
        let mut live = candidates.clone();
        sessions.retain_live_sessions(&mut live);
        for handle in candidates {
            if live.binary_search(&handle).is_err() {
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
    available_wires: Vec<ResponseWire>,
    _scratch_reservation: UdpBufferReservation,
}

struct ResponseWire {
    wire: Vec<u8>,
    _wire_reservation: UdpBufferReservation,
}

impl ResponseWire {
    fn reserve(budget: &UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let reservation = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)?;
        let wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        if wire.capacity() != reservation.capacity() {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            wire,
            _wire_reservation: reservation,
        })
    }
}

struct ResponseCodecPool {
    state: Mutex<ResponseCodec>,
    budget: UdpBufferBudget,
    returned: tokio::sync::Notify,
}

impl ResponseCodecPool {
    fn new(budget: UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let scratch_reservation = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)?;
        let initial_wire = ResponseWire::reserve(&budget)?;
        Ok(Self {
            state: Mutex::new(ResponseCodec {
                scratch: UdpPacketScratch::new(),
                available_wires: vec![initial_wire],
                _scratch_reservation: scratch_reservation,
            }),
            budget,
            returned: tokio::sync::Notify::new(),
        })
    }

    fn try_encode(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &SystemClock,
        datagram: &ferrum2_core::Datagram,
    ) -> Result<Option<EncodedResponseWire>, ResponseEncodeError> {
        let mut codec = self
            .state
            .lock()
            .map_err(|_| ResponseEncodeError::Protocol(UdpPacketError::StateUnavailable))?;
        let mut response_wire = match codec.available_wires.pop() {
            Some(wire) => wire,
            None => match ResponseWire::reserve(&self.budget) {
                Ok(wire) => wire,
                Err(UdpRuntimeError::BufferLimit) => return Ok(None),
                Err(error) => return Err(ResponseEncodeError::Runtime(error)),
            },
        };
        let encoded = protocol.encode_response(
            capability,
            clock,
            &SystemRandom,
            datagram,
            0,
            &mut response_wire.wire,
            &mut codec.scratch,
        );
        drop(codec);
        match encoded {
            Ok(encoded) => Ok(Some(EncodedResponseWire {
                wire: ResponseWireLease {
                    pool: Arc::clone(self),
                    wire: Some(response_wire),
                },
                wire_len: encoded.wire_len(),
                peer: encoded.peer(),
            })),
            Err(error) => {
                self.release(response_wire);
                Err(ResponseEncodeError::Protocol(error))
            }
        }
    }

    fn release(&self, response_wire: ResponseWire) {
        let mut response_wire = Some(response_wire);
        if let Ok(mut codec) = self.state.lock()
            && codec.available_wires.is_empty()
        {
            codec
                .available_wires
                .push(response_wire.take().expect("response wire is available"));
        }
        drop(response_wire);
        self.returned.notify_waiters();
    }

    fn notify_capacity_change(&self) {
        self.returned.notify_waiters();
    }
}

struct ResponseWireLease {
    pool: Arc<ResponseCodecPool>,
    wire: Option<ResponseWire>,
}

impl ResponseWireLease {
    fn wire(&self, wire_len: usize) -> &[u8] {
        &self
            .wire
            .as_ref()
            .expect("response wire lease is live")
            .wire[..wire_len]
    }
}

impl Drop for ResponseWireLease {
    fn drop(&mut self) {
        if let Some(wire) = self.wire.take() {
            self.pool.release(wire);
        }
    }
}

struct EncodedResponseWire {
    wire: ResponseWireLease,
    wire_len: usize,
    peer: SocketAddr,
}

enum ResponseEncodeError {
    Protocol(UdpPacketError),
    Runtime(UdpRuntimeError),
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
    codec: Arc<ResponseCodecPool>,
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
        let encoded = loop {
            let returned = self.codec.returned.notified();
            match self.codec.try_encode(
                &self.protocol,
                capability,
                self.clock.as_ref(),
                response.datagram(),
            ) {
                Ok(Some(encoded)) => break encoded,
                Ok(None) => returned.await,
                Err(ResponseEncodeError::Protocol(error)) => {
                    self.mappings.invalidate_handle(session);
                    record_udp_protocol_failure(&self.metrics, error);
                    return Err(UdpAdapterError);
                }
                Err(ResponseEncodeError::Runtime(error)) => {
                    record_udp_runtime_failure(&self.metrics, error);
                    return Err(UdpAdapterError);
                }
            }
        };
        drop(response);
        self.codec.notify_capacity_change();
        let wire_len = encoded.wire_len;
        self.listener
            .send_to(encoded.wire.wire(wire_len), encoded.peer)
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
    let budget = sessions.buffer_budget();
    let response_codec =
        Arc::new(ResponseCodecPool::new(budget.clone()).map_err(|_| RunError::StartupProtocol)?);
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
            if terminal == ServerTerminalRoute::Reject && routing.program().is_none() {
                continue;
            }
            if existing.is_none() {
                reconcile_udp_generations(&runtime, &mappings);
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
            if terminal == ServerTerminalRoute::Reject {
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
                continue;
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
    mappings.reconcile_runtime(runtime.sessions());
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
                let (progress, collector) = if payload.len() > program.sniff.max_bytes {
                    (SniffProgress::NoMatch, Some(SniffPrefixOutcome::Limit))
                } else {
                    (
                        ferrum2_sniff::sniff(
                            payload,
                            program.sniff.max_bytes,
                            SniffTransport::Udp,
                            target.port().get(),
                            &order,
                        ),
                        None,
                    )
                };
                record_sniff(
                    metrics,
                    ObservationTransport::Udp,
                    progress.clone(),
                    collector,
                );
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferrum2_core::Datagram;
    use ferrum2_runtime::UdpDirection;
    use ferrum2_shadowsocks::{UdpClientSession, UdpPacketError};
    use tokio::sync::{Notify, Semaphore};

    use super::*;
    use crate::run::test_support::*;

    type CapturedSends = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

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

    struct ConcurrentSendListener {
        entered: Arc<AtomicUsize>,
        entry_changed: Arc<Notify>,
        send_gate: Arc<Semaphore>,
        sent: CapturedSends,
    }

    impl ServerUdpListener for ConcurrentSendListener {
        async fn recv_from(&self, _destination: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }

        async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.entry_changed.notify_waiters();
            let _permit = self
                .send_gate
                .acquire()
                .await
                .map_err(|_| io::Error::other("send gate closed"))?;
            self.sent
                .lock()
                .expect("concurrent sends")
                .push((peer, source.to_vec()));
            Ok(source.len())
        }
    }

    async fn wait_for_send_entries(entered: &AtomicUsize, entry_changed: &Notify, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = entry_changed.notified();
                if entered.load(Ordering::SeqCst) >= expected {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("response send entry deadline");
    }

    fn accounted_response(
        client: &mut UdpClientSession,
        protocol: &UdpServer,
        manager: &UdpSessionManager,
        clock: &SystemClock,
        handle: UdpSessionHandle,
        response: (SocketAddr, &'static [u8]),
        scratch: &mut UdpPacketScratch,
    ) -> AccountedDatagram {
        let (target, payload) = response;
        let wire = encoded_udp_request(
            client,
            clock,
            TargetAddr::ip(target).expect("response source target"),
            payload,
        );
        let pending = protocol
            .prepare_request(clock, &wire, scratch)
            .expect("prepare response payload");
        let (datagram, _commit) = pending.into_parts();
        let capacity = datagram.allocated_capacity();
        manager
            .reserve_datagram(handle, UdpDirection::ToClient, capacity)
            .expect("reserve response payload")
            .commit(datagram, tokio::time::Instant::now())
            .expect("commit response payload");
        manager
            .pop(handle, UdpDirection::ToClient)
            .expect("response generation")
            .expect("accounted response")
    }

    #[tokio::test]
    async fn response_codec_does_not_serialize_concurrent_sends() {
        let keys = aes_keys();
        let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
        let clock = Arc::new(SystemClock::new());
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(2, 1024 * 1024, Duration::from_secs(60))
                .expect("response limits"),
            registry.clone(),
        );
        let mappings = Arc::new(UdpMappings::new(2));
        let mut first_client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
        let mut second_client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let first_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001));
        let second_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_002));
        let mut request_scratch = UdpPacketScratch::new();
        let (_, first_handle) = commit_lifecycle_generation(
            &mut first_client,
            &protocol,
            &manager,
            &mappings,
            &clock,
            target,
            first_peer,
            b"first request",
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
            &mut request_scratch,
        );
        let (_, second_handle) = commit_lifecycle_generation(
            &mut second_client,
            &protocol,
            &manager,
            &mappings,
            &clock,
            target,
            second_peer,
            b"second request",
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
            &mut request_scratch,
        );
        let first_response = accounted_response(
            &mut first_client,
            &protocol,
            &manager,
            &clock,
            first_handle,
            (target, b"first response"),
            &mut request_scratch,
        );
        let second_response = accounted_response(
            &mut second_client,
            &protocol,
            &manager,
            &clock,
            second_handle,
            (target, b"second response"),
            &mut request_scratch,
        );
        let entered = Arc::new(AtomicUsize::new(0));
        let entry_changed = Arc::new(Notify::new());
        let send_gate = Arc::new(Semaphore::new(0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let listener = Arc::new(ConcurrentSendListener {
            entered: Arc::clone(&entered),
            entry_changed: Arc::clone(&entry_changed),
            send_gate: Arc::clone(&send_gate),
            sent: Arc::clone(&sent),
        });
        let handler = Arc::new(ServerUdpResponseHandler {
            listener,
            protocol: Arc::clone(&protocol),
            mappings,
            clock: Arc::clone(&clock),
            codec: Arc::new(
                ResponseCodecPool::new(manager.buffer_budget()).expect("response codec"),
            ),
            metrics: Arc::new(Metrics::new()),
        });

        let first_task = tokio::spawn({
            let handler = Arc::clone(&handler);
            async move {
                handler
                    .handle_target_response(first_handle, first_response)
                    .await
            }
        });
        wait_for_send_entries(&entered, &entry_changed, 1).await;
        let second_task = tokio::spawn({
            let handler = Arc::clone(&handler);
            async move {
                handler
                    .handle_target_response(second_handle, second_response)
                    .await
            }
        });

        wait_for_send_entries(&entered, &entry_changed, 2).await;
        assert_eq!(
            registry.snapshot().udp_buffered_bytes,
            3 * MAX_UDP_WIRE_DATAGRAM_BYTES,
            "two in-flight owned wires plus the shared codec scratch are charged"
        );
        send_gate.add_permits(2);
        assert!(first_task.await.expect("first response task").is_ok());
        assert!(second_task.await.expect("second response task").is_ok());
        assert_eq!(
            registry.snapshot().udp_buffered_bytes,
            2 * MAX_UDP_WIRE_DATAGRAM_BYTES,
            "the concurrency wire is released after the burst"
        );
        let idle_wire = {
            let codec = handler.codec.state.lock().expect("response codec");
            assert_eq!(codec.available_wires.len(), 1);
            codec.available_wires[0].wire.as_ptr()
        };

        {
            let sent = sent.lock().expect("concurrent sends");
            assert_eq!(sent.len(), 2);
            let mut response_scratch = UdpPacketScratch::new();
            for (peer, wire) in &*sent {
                let pending = if *peer == first_peer {
                    first_client
                        .prepare_response(clock.as_ref(), wire, &mut response_scratch)
                        .expect("first encoded response")
                } else {
                    assert_eq!(*peer, second_peer);
                    second_client
                        .prepare_response(clock.as_ref(), wire, &mut response_scratch)
                        .expect("second encoded response")
                };
                let expected = if *peer == first_peer {
                    b"first response".as_slice()
                } else {
                    b"second response".as_slice()
                };
                assert_eq!(pending.datagram().payload(), expected);
            }
        }

        let serial_response = accounted_response(
            &mut first_client,
            &protocol,
            &manager,
            &clock,
            first_handle,
            (target, b"serial response"),
            &mut request_scratch,
        );
        assert!(
            handler
                .handle_target_response(first_handle, serial_response)
                .await
                .is_ok()
        );
        let codec = handler.codec.state.lock().expect("response codec");
        assert_eq!(codec.available_wires.len(), 1);
        assert_eq!(codec.available_wires[0].wire.as_ptr(), idle_wire);
        drop(codec);
        assert_eq!(
            registry.snapshot().udp_buffered_bytes,
            2 * MAX_UDP_WIRE_DATAGRAM_BYTES,
            "steady-state serial responses reuse the same accounted wire"
        );

        manager.cancel_all();
        drop(handler);
        drop(manager);
        assert_eq!(active(registry.snapshot()), baseline);
    }

    #[tokio::test]
    async fn response_codec_budget_wakeup_grows_before_leased_wire_returns() {
        let keys = aes_keys();
        let protocol = UdpServer::new(&keys).expect("server protocol");
        let clock = SystemClock::new();
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        let byte_limit = 1024 * 1024;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(1, byte_limit, Duration::from_secs(60)).expect("response limits"),
            registry.clone(),
        );
        let budget = manager.buffer_budget();
        let codec = Arc::new(ResponseCodecPool::new(budget.clone()).expect("response codec"));
        let mappings = UdpMappings::new(1);
        let mut client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003));
        let mut scratch = UdpPacketScratch::new();
        let (capability, _handle) = commit_lifecycle_generation(
            &mut client,
            &protocol,
            &manager,
            &mappings,
            &clock,
            target,
            peer,
            b"request",
            ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
            &mut scratch,
        );
        let wire = encoded_udp_request(
            &mut client,
            &clock,
            TargetAddr::ip(target).expect("response source target"),
            b"response",
        );
        let pending = protocol
            .prepare_request(&clock, &wire, &mut scratch)
            .expect("prepare response datagram");

        let first_encoded =
            match codec.try_encode(&protocol, capability, &clock, pending.datagram()) {
                Ok(Some(encoded)) => encoded,
                Ok(None) => panic!("initial response wire is reserved"),
                Err(_) => panic!("initial response encoding succeeds"),
            };
        let mut pressure = Vec::new();
        let mut remaining = byte_limit - budget.reserved_bytes();
        while remaining != 0 {
            let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            pressure.push(budget.reserve(capacity).expect("budget pressure"));
            remaining -= capacity;
        }
        assert_eq!(budget.reserved_bytes(), byte_limit);
        assert!(matches!(
            codec.try_encode(&protocol, capability, &clock, pending.datagram()),
            Ok(None)
        ));

        let returned = codec.returned.notified();
        let released = pressure
            .iter()
            .position(|reservation| reservation.capacity() == MAX_UDP_WIRE_DATAGRAM_BYTES)
            .expect("full response-wire pressure chunk");
        drop(pressure.swap_remove(released));
        codec.notify_capacity_change();
        tokio::time::timeout(Duration::from_secs(1), returned)
            .await
            .expect("budget release notification");
        let second_encoded =
            match codec.try_encode(&protocol, capability, &clock, pending.datagram()) {
                Ok(Some(encoded)) => encoded,
                Ok(None) => panic!("released capacity funds a concurrent response wire"),
                Err(_) => panic!("concurrent response encoding succeeds"),
            };
        assert_eq!(
            budget.reserved_bytes(),
            byte_limit,
            "the second wire is fully budget-accounted while the first remains leased"
        );

        drop(second_encoded);
        drop(first_encoded);
        drop(pressure);
        assert_eq!(budget.reserved_bytes(), 2 * MAX_UDP_WIRE_DATAGRAM_BYTES);
        let state = codec.state.lock().expect("response codec");
        assert_eq!(state.available_wires.len(), 1);
        drop(state);
        manager.cancel_all();
        drop(codec);
        drop(manager);
        assert_eq!(active(registry.snapshot()), baseline);
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

    #[tokio::test]
    async fn authenticated_udp_identities_share_one_protocol_session_ceiling() {
        const REJECT_DNS_QUERY: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'r',
            b'e', b'j', b'e', b'c', b't', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let listener = Arc::new(udp_loopback().await);
        let listen = match listener.local_addr().expect("listener address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 listener"),
        };
        let route = "[route]\n\
            final = \"direct\"\n\
            [route.sniff]\n\
            max_bytes = 512\n\
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
        let sessions = UdpSessionManager::new(
            udp_runtime_limits(&config.udp).expect("capacity-one limits"),
            registry.clone(),
        );
        let mappings = Arc::new(UdpMappings::new(1));
        let keys = aes_keys();
        let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
        let clock = Arc::new(SystemClock::new());
        let metrics = Arc::new(Metrics::new());
        let prepared = prepare_udp_server(
            0,
            Arc::clone(&listener),
            ServerUdpShared {
                routing: Arc::new(routing),
                protocol: Arc::clone(&protocol),
                clock: Arc::clone(&clock),
                config: config.udp,
                sessions,
                mappings: Arc::clone(&mappings),
                admission: Arc::new(tokio::sync::Mutex::new(())),
                connect_timeout: config.runtime.connect_timeout,
                dns: None,
                registry: registry.clone(),
                metrics: Arc::clone(&metrics),
            },
        )
        .expect("prepare production UDP root");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(prepared.run_with_shutdown(
            async move {
                let _ = stopped.await;
            },
            |runtime| async move { runtime.shutdown(Duration::ZERO).await },
        ));

        let peer = udp_loopback().await;
        let target = udp_loopback().await;
        let target_address =
            TargetAddr::ip(target.local_addr().expect("target address")).expect("numeric target");
        let mut received = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        let mut first =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first identity");
        let rejected = encoded_udp_request(
            &mut first,
            clock.as_ref(),
            target_address.clone(),
            REJECT_DNS_QUERY,
        );
        peer.send_to(&rejected, listen)
            .await
            .expect("first typed reject");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if protocol.session_count().expect("first protocol count") == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first typed reject commit deadline");
        {
            let state = mappings.state.lock().expect("first mapping state");
            assert_eq!((state.by_capability.len(), state.orphaned.len()), (0, 1));
        }
        assert_eq!(registry.snapshot().udp_sessions, 0);
        assert_pending(target.recv_from(&mut received), "typed reject forwarded").await;

        peer.send_to(&rejected, listen)
            .await
            .expect("duplicate typed reject");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if metrics.encode_text().expect("duplicate metrics").contains(
                    "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"} 1",
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("duplicate rejection deadline");
        assert_eq!(protocol.session_count().expect("duplicate count"), 1);

        let first_direct = encoded_udp_request(
            &mut first,
            clock.as_ref(),
            target_address.clone(),
            b"first-direct",
        );
        peer.send_to(&first_direct, listen)
            .await
            .expect("first direct upgrade");
        let (length, _) = recv_udp(&target, &mut received).await;
        assert_eq!(&received[..length], b"first-direct");
        assert_eq!(protocol.session_count().expect("direct protocol count"), 1);
        assert_eq!(registry.snapshot().udp_sessions, 1);
        {
            let state = mappings.state.lock().expect("direct mapping state");
            assert_eq!((state.by_capability.len(), state.orphaned.len()), (1, 0));
        }

        let oversized_payload = vec![b'x'; 513];
        let oversized = encoded_udp_request(
            &mut first,
            clock.as_ref(),
            target_address.clone(),
            &oversized_payload,
        );
        peer.send_to(&oversized, listen)
            .await
            .expect("oversized authenticated datagram");
        let (length, _) = recv_udp(&target, &mut received).await;
        assert_eq!(&received[..length], oversized_payload);
        assert!(metrics.encode_text().expect("oversized metrics").contains(
            "ferrum2_sniff_total{role=\"server\",transport=\"udp\",stage=\"sniff\",outcome=\"limit\",protocol=\"none\"} 1"
        ));

        let mut second =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second identity");
        let over_capacity = encoded_udp_request(
            &mut second,
            clock.as_ref(),
            target_address.clone(),
            REJECT_DNS_QUERY,
        );
        for expected_limits in 1..=2 {
            peer.send_to(&over_capacity, listen)
                .await
                .expect("over-capacity typed reject");
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if metrics.encode_text().expect("session limit metrics").contains(&format!(
                        "ferrum2_udp_failures_total{{role=\"server\",stage=\"relay\",reason=\"session_limit\"}} {expected_limits}"
                    )) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("shared session ceiling deadline");
            assert_eq!(protocol.session_count().expect("shared ceiling count"), 1);
            assert_eq!(registry.snapshot().udp_sessions, 1);
            let state = mappings.state.lock().expect("shared ceiling mapping");
            assert_eq!((state.by_capability.len(), state.orphaned.len()), (1, 0));
        }
        assert_pending(
            target.recv_from(&mut received),
            "over-capacity reject forwarded",
        )
        .await;
        assert!(metrics.encode_text().expect("replay metrics").contains(
            "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"} 1"
        ));

        let still_direct =
            encoded_udp_request(&mut first, clock.as_ref(), target_address, b"still-direct");
        peer.send_to(&still_direct, listen)
            .await
            .expect("existing identity remains legal");
        let (length, _) = recv_udp(&target, &mut received).await;
        assert_eq!(&received[..length], b"still-direct");

        stop.send(()).expect("stop production UDP root");
        assert_eq!(server.await.expect("production UDP task"), Ok(()));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
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
        mappings.reconcile_runtime(&manager);
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
        mappings.reconcile_runtime(&manager);
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
