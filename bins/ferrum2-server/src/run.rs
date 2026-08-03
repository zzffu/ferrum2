use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use ferrum2_config::{LoggingLevel, RuntimeConfig, UdpConfig, ValidatedServerConfig};
use ferrum2_core::route::Network;
use ferrum2_core::{
    AbortiveClose, ConnectErrorKind, Inbound as _, LocalEndpoint, SessionReply as _, TargetAddr,
};
use ferrum2_crypto::{Clock as _, MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
    json_subscriber,
};
use ferrum2_runtime::{
    AcceptListener, AccountedDatagram, BoundedSupervisor, CancellationToken, DirectOutbound,
    DirectUdpPacketHandler, DirectUdpRuntime, MAX_UDP_WIRE_DATAGRAM_BYTES, MetricsEndpoint,
    MetricsEndpointError, OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessCause,
    ProcessFuture, ProcessReport, ProcessRoot, ProcessRootExit, ProcessSupervisor, RelayFailure,
    RelayRunError, RuntimeTcpStream, SupervisorError, SystemDirectUdpSocketFactory,
    SystemUdpResolver, TcpConnector, UdpBufferReservation, UdpCommitError, UdpRuntimeError,
    UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager, relay_lifecycle,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, MethodKeyAdapter, PlainDuplex, ProtocolReason,
    ServerResponseCapability, ShadowsocksError, ShadowsocksTcpInbound, TcpReplayStore, TransportIo,
    UdpPacketError, UdpPacketScratch, UdpServer,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
    RuntimeListener,
    RuntimeChild,
    RuntimeRoot,
    ShutdownCleanup,
}

fn udp_runtime_limits(config: &UdpConfig) -> Option<UdpRuntimeLimits> {
    UdpRuntimeLimits::new(
        config.max_sessions,
        config.max_buffered_bytes,
        config.idle_timeout,
    )
    .ok()
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StartupObservability => {
                "error[startup.observability] process: unable to initialize diagnostics"
            }
            Self::StartupRuntime => {
                "error[startup.runtime] process: unable to create asynchronous runtime"
            }
            Self::StartupBind => "error[startup.bind] process: unable to prepare required endpoint",
            Self::StartupProtocol => {
                "error[startup.protocol] process: unable to prepare protocol resources"
            }
            Self::RuntimeListener => "error[runtime.listener] process: required listener failed",
            Self::RuntimeChild => "error[runtime.child] process: required child failed",
            Self::RuntimeRoot => "error[runtime.root] process: required root stopped",
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

pub(crate) fn run(config: ValidatedServerConfig) -> Result<(), RunError> {
    let subscriber = json_subscriber(std::io::stderr, log_level(config.logging.level));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| RunError::StartupObservability)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(run_async(config))
}

async fn run_async(config: ValidatedServerConfig) -> Result<(), RunError> {
    run_with_registry(config, OwnerRegistry::new(), shutdown_signal()).await
}

async fn run_with_registry<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let metrics = Arc::new(Metrics::new());
    let replay = Arc::new(
        TcpReplayStore::new(config.replay.capacity).map_err(|_| RunError::StartupProtocol)?,
    );
    let keys = Arc::new(MethodKeyAdapter::new(MethodSinglePskProvider::new(
        config.psk,
    )));
    let udp_protocol = if config.udp.enabled {
        Some(Arc::new(
            UdpServer::new(keys.as_ref()).map_err(|_| RunError::StartupProtocol)?,
        ))
    } else {
        None
    };
    let listen_backlog = u32::from(config.runtime.listen_backlog.get());
    let max_connections = usize::from(config.runtime.max_connections.get());
    let shutdown_grace = config.runtime.shutdown_grace;
    let connect_timeout = config.runtime.connect_timeout;
    let udp_config = config.udp;
    let clock = Arc::new(SystemClock::new());
    let routing = Arc::new(ServerRouting {
        route: config.route,
        direct: config
            .outbounds
            .iter()
            .map(|_| Arc::new(DirectOutbound::new(TcpConnector::new(connect_timeout))))
            .collect(),
    });
    let mut roots = Vec::with_capacity(
        config.inbounds.len() * usize::from(config.udp.enabled)
            + 1
            + usize::from(config.metrics.is_some()),
    );
    let mut tcp_listens = Vec::with_capacity(config.inbounds.len());
    let mut tcp_contexts = Vec::with_capacity(config.inbounds.len());
    for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
        let listen = inbound.listen;
        tcp_listens.push(listen);
        let context = Arc::new(ServerContext {
            inbound: inbound_id,
            routing: Arc::clone(&routing),
            keys: Arc::clone(&keys),
            clock: Arc::clone(&clock),
            random: SystemRandom,
            replay: Arc::clone(&replay),
            runtime: config.runtime,
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        });
        tcp_contexts.push(context);
    }
    let tcp_registry = registry.clone();
    roots.push(ProcessRoot::new(move || async move {
        let mut listeners = Vec::with_capacity(tcp_listens.len());
        for listen in tcp_listens {
            listeners.push(bind_listener(listen, listen_backlog)?);
        }
        let supervisor = BoundedSupervisor::new(
            ServerTcpListeners {
                listeners,
                next: AtomicUsize::new(0),
            },
            max_connections,
            shutdown_grace,
            tcp_registry,
        )
        .map_err(|_| RunError::StartupProtocol)?;
        Ok(ServerTcpRoot {
            supervisor: Some(supervisor),
            contexts: Arc::new(tcp_contexts),
        })
    }));
    if let Some(protocol) = udp_protocol {
        let limits = udp_runtime_limits(&udp_config).ok_or(RunError::StartupProtocol)?;
        let sessions = UdpSessionManager::new(limits, registry.clone());
        let mappings = Arc::new(UdpMappings::new(udp_config.max_sessions));
        let admission = Arc::new(tokio::sync::Mutex::new(()));
        let shared = ServerUdpShared {
            routing: Arc::clone(&routing),
            protocol,
            clock: Arc::clone(&clock),
            config: udp_config,
            sessions,
            mappings,
            admission,
            connect_timeout,
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        };
        for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
            let listen = inbound.listen;
            let shared = shared.clone();
            roots.push(ProcessRoot::new(move || async move {
                let listener = Arc::new(
                    UdpSocket::bind(SocketAddr::V4(listen))
                        .await
                        .map_err(|_| RunError::StartupBind)?,
                );
                prepare_udp_server(inbound_id, listener, shared)
            }));
        }
    }
    if let Some(metrics_config) = config.metrics {
        let metrics_registry = registry.clone();
        roots.push(ProcessRoot::new(move || async move {
            let listener = bind_listener(metrics_config.listen, 16)?;
            Ok(ServerMetricsRoot {
                listener: Some(listener),
                metrics,
                registry: metrics_registry,
            })
        }));
    }
    let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry)
        .map_err(|_| RunError::StartupProtocol)?;
    report_result(supervisor.run_until(shutdown).await)
}

fn report_result(report: ProcessReport<RunError>) -> Result<(), RunError> {
    if report.cleanup_failure().is_some() {
        return Err(RunError::ShutdownCleanup);
    }
    match report.cause() {
        ProcessCause::ExternalShutdown => Ok(()),
        ProcessCause::PreparationFailed { error, .. }
        | ProcessCause::ActivationFailed { error, .. } => Err(*error),
        ProcessCause::PreparationPanicked { .. } | ProcessCause::ActivationPanicked { .. } => {
            Err(RunError::StartupProtocol)
        }
        ProcessCause::RootStopped { exit, .. } => match exit {
            ProcessRootExit::Failed(error) => Err(*error),
            ProcessRootExit::Panicked | ProcessRootExit::JoinFailed => Err(RunError::RuntimeChild),
            ProcessRootExit::Completed => Err(RunError::RuntimeRoot),
        },
    }
}

struct ServerTcpListeners {
    listeners: Vec<TcpListener>,
    next: AtomicUsize,
}

impl AcceptListener for ServerTcpListeners {
    type Stream = (usize, tokio::net::TcpStream);

    async fn accept(&self) -> io::Result<Self::Stream> {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.listeners.len();
        std::future::poll_fn(|context| {
            for offset in 0..self.listeners.len() {
                let inbound = (start + offset) % self.listeners.len();
                match self.listeners[inbound].poll_accept(context) {
                    Poll::Ready(Ok((stream, _))) => {
                        if stream.set_nodelay(true).is_err() {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::Other)));
                        }
                        return Poll::Ready(Ok((inbound, stream)));
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::Other)));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

struct ServerTcpRoot {
    supervisor: Option<BoundedSupervisor<ServerTcpListeners>>,
    contexts: Arc<Vec<Arc<ServerContext>>>,
}

impl PreparedProcessRoot<RunError> for ServerTcpRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let supervisor = self.supervisor.take().expect("prepared TCP root");
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            supervisor
                .run_with_cancellation(
                    move |(inbound, stream), cancellation| {
                        let contexts = Arc::clone(&contexts);
                        async move {
                            if let Some(context) = contexts.get(inbound) {
                                server_connection(stream, cancellation, Arc::clone(context)).await;
                            }
                        }
                    },
                    cancellation,
                )
                .await
                .map_err(run_error_for_supervisor)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

struct ServerMetricsRoot {
    listener: Option<TcpListener>,
    metrics: Arc<Metrics>,
    registry: OwnerRegistry,
}

impl PreparedProcessRoot<RunError> for ServerMetricsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let listener = self.listener.take().expect("prepared metrics root");
        let metrics = Arc::clone(&self.metrics);
        let registry = self.registry.clone();
        let endpoint = MetricsEndpoint::new(
            listener,
            move || {
                update_udp_resource_metrics(&metrics, &registry);
                metrics.encode_text().unwrap_or_default()
            },
            self.registry.clone(),
        );
        Box::pin(async move {
            endpoint
                .run_until(cancellation.cancelled())
                .await
                .map_err(run_error_for_metrics)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

fn run_error_for_supervisor(error: SupervisorError) -> RunError {
    match error {
        SupervisorError::ListenerFailure => RunError::RuntimeListener,
        SupervisorError::ChildFailure => RunError::RuntimeChild,
    }
}

fn run_error_for_metrics(error: MetricsEndpointError) -> RunError {
    match error {
        MetricsEndpointError::ListenerFailure => RunError::RuntimeListener,
        MetricsEndpointError::ChildFailure => RunError::RuntimeChild,
    }
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

struct UdpMappings {
    state: Mutex<UdpMappingState>,
    published: tokio::sync::Notify,
    limit: usize,
}

impl UdpMappings {
    fn new(limit: usize) -> Self {
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
        if let Some(old_capability) = state.by_handle.remove(&handle) {
            if let Some(old) = state.by_capability.remove(&old_capability) {
                state.orphaned.insert(old_capability, old.inbound);
            }
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

    fn invalidate_handle(&self, handle: UdpSessionHandle) {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        if let Some(capability) = state.by_handle.remove(&handle) {
            if let Some(old) = state.by_capability.remove(&capability) {
                state.orphaned.insert(capability, old.inbound);
            }
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

trait ServerUdpListener: Send + Sync + 'static {
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

type ProductionUdpRuntime<L> =
    DirectUdpRuntime<SystemUdpResolver, SystemDirectUdpSocketFactory, ServerUdpResponseHandler<L>>;

struct PreparedUdpServer<L>
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
struct ServerUdpShared {
    routing: Arc<ServerRouting>,
    protocol: Arc<UdpServer>,
    clock: Arc<SystemClock>,
    config: UdpConfig,
    sessions: UdpSessionManager,
    mappings: Arc<UdpMappings>,
    admission: Arc<tokio::sync::Mutex<()>>,
    connect_timeout: std::time::Duration,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
}

fn prepare_udp_server<L>(
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
    let runtime = DirectUdpRuntime::with_shared_capacity(
        sessions,
        connect_timeout,
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
                let Some(reserved) = reserve_udp_direct(
                    &routing.route,
                    &routing.direct,
                    inbound,
                    pending.datagram().target(),
                    |_| {
                        std::future::ready(
                            runtime
                                .reserve_datagram(handle, pending.datagram().allocated_capacity()),
                        )
                    },
                )
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

            let Some(admission) = reserve_udp_direct(
                &routing.route,
                &routing.direct,
                inbound,
                pending.datagram().target(),
                |_| {
                    runtime.reserve_session(
                        tokio::time::Instant::now(),
                        pending.datagram().allocated_capacity(),
                    )
                },
            )
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

fn record_udp_request_accepted(metrics: &Metrics, wire_len: usize) {
    metrics.udp_datagram(Role::Server, Direction::ClientToTarget, Outcome::Accepted);
    metrics.add_udp_bytes(Role::Server, Direction::ClientToTarget, wire_len as u64);
}

fn update_udp_resource_metrics(metrics: &Metrics, registry: &OwnerRegistry) {
    let snapshot = registry.snapshot();
    metrics.set_udp_sessions_active(Role::Server, snapshot.udp_sessions);
    metrics.set_udp_buffered_bytes(Role::Server, snapshot.udp_buffered_bytes);
}

fn record_udp_protocol_failure(metrics: &Metrics, error: UdpPacketError) {
    let reason = match error {
        UdpPacketError::Bounds => Reason::Bounds,
        UdpPacketError::Authentication => Reason::Authentication,
        UdpPacketError::Type => Reason::Type,
        UdpPacketError::Clock => Reason::Clock,
        UdpPacketError::Timestamp => Reason::Timestamp,
        UdpPacketError::Address => Reason::Address,
        UdpPacketError::Padding => Reason::Padding,
        UdpPacketError::Binding => Reason::Binding,
        UdpPacketError::Duplicate => Reason::Duplicate,
        UdpPacketError::TooOld => Reason::TooOld,
        UdpPacketError::AssociationLimit | UdpPacketError::Generation => Reason::SessionLimit,
        UdpPacketError::Key => Reason::Key,
        UdpPacketError::Random => Reason::Random,
        UdpPacketError::Counter => Reason::Counter,
        UdpPacketError::StateUnavailable => Reason::Cancelled,
    };
    let outcome = match error {
        UdpPacketError::Authentication
        | UdpPacketError::Type
        | UdpPacketError::Timestamp
        | UdpPacketError::Address
        | UdpPacketError::Padding
        | UdpPacketError::Binding
        | UdpPacketError::Duplicate
        | UdpPacketError::TooOld => Outcome::Rejected,
        _ => Outcome::Failed,
    };
    if matches!(error, UdpPacketError::Duplicate | UdpPacketError::TooOld) {
        metrics.udp_replay_rejection(Role::Server, Direction::ClientToTarget, reason);
    }
    record_udp_failure(metrics, Stage::Shadowsocks, reason, outcome);
}

fn record_udp_runtime_failure(metrics: &Metrics, error: UdpRuntimeError) {
    let reason = match error {
        UdpRuntimeError::Bounds => Reason::Bounds,
        UdpRuntimeError::SessionLimit => Reason::SessionLimit,
        UdpRuntimeError::BufferLimit => Reason::BufferLimit,
        UdpRuntimeError::QueueFull => Reason::QueueFull,
        UdpRuntimeError::Counter => Reason::Counter,
        UdpRuntimeError::Resolve => Reason::Resolve,
        UdpRuntimeError::Send => Reason::Send,
        UdpRuntimeError::Receive => Reason::Receive,
        UdpRuntimeError::Idle => Reason::Idle,
        UdpRuntimeError::Cancelled => Reason::Cancelled,
    };
    let stage = match error {
        UdpRuntimeError::Resolve | UdpRuntimeError::Send | UdpRuntimeError::Receive => {
            Stage::Direct
        }
        UdpRuntimeError::Idle | UdpRuntimeError::Cancelled => Stage::Shutdown,
        _ => Stage::Relay,
    };
    record_udp_failure(metrics, stage, reason, Outcome::Failed);
}

fn record_udp_failure(metrics: &Metrics, stage: Stage, reason: Reason, outcome: Outcome) {
    metrics.udp_failure(Role::Server, stage, reason);
    emit(
        TraceRecord::new(LogLevel::Warn, Event::Failure, Role::Server, stage, outcome)
            .udp()
            .with_reason(reason),
    );
}

fn bind_listener(address: std::net::SocketAddrV4, backlog: u32) -> Result<TcpListener, RunError> {
    let socket = TcpSocket::new_v4().map_err(|_| RunError::StartupBind)?;
    #[cfg(unix)]
    socket
        .set_reuseaddr(true)
        .map_err(|_| RunError::StartupBind)?;
    socket
        .bind(SocketAddr::V4(address))
        .map_err(|_| RunError::StartupBind)?;
    socket.listen(backlog).map_err(|_| RunError::StartupBind)
}

async fn shutdown_signal() {
    #[cfg(windows)]
    {
        let Ok(mut ctrl_break) = tokio::signal::windows::ctrl_break() else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            signal = ctrl_break.recv() => {
                if signal.is_none() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(windows))]
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

struct ServerRouting {
    route: ferrum2_core::route::RouteTable,
    direct: Vec<Arc<DirectOutbound<TcpConnector>>>,
}

async fn reserve_udp_direct<T, R, F>(
    route: &ferrum2_core::route::RouteTable,
    direct: &[T],
    inbound: usize,
    target: &TargetAddr,
    reserve: impl FnOnce(&T) -> F,
) -> Option<R>
where
    F: std::future::Future<Output = R>,
{
    let selected = route.select(inbound, Network::Udp, target);
    let direct = direct.get(selected)?;
    Some(reserve(direct).await)
}

#[derive(Debug)]
enum DirectFlowError<E> {
    CancelledBeforeOpen,
    Open(E),
    Prefix(PrefixFailure),
}

async fn open_and_prefix<O, C>(
    direct: &O,
    target: &TargetAddr,
    initial_payload: &[u8],
    idle_timeout: std::time::Duration,
    cancellation: C,
) -> Result<(O::Stream, u64), DirectFlowError<O::Error>>
where
    O: ferrum2_core::Outbound,
    O::Stream: AsyncWrite + Unpin,
    C: std::future::Future,
{
    tokio::pin!(cancellation);
    let mut stream = tokio::select! {
        _ = cancellation.as_mut() => return Err(DirectFlowError::CancelledBeforeOpen),
        result = direct.open(target) => result.map_err(DirectFlowError::Open)?,
    };
    let bytes = forward_initial_payload(
        &mut stream,
        initial_payload,
        idle_timeout,
        cancellation.as_mut(),
    )
    .await
    .map_err(DirectFlowError::Prefix)?;
    Ok((stream, bytes))
}

struct ServerContext {
    inbound: usize,
    routing: Arc<ServerRouting>,
    keys: Arc<MethodKeyAdapter<MethodSinglePskProvider>>,
    clock: Arc<SystemClock>,
    random: SystemRandom,
    replay: Arc<TcpReplayStore>,
    runtime: RuntimeConfig,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
}

async fn server_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ServerContext>,
) {
    let stream = match RuntimeTcpStream::from_connected(stream) {
        Ok(stream) => stream,
        Err(_) => {
            record_failure(&context, Stage::Listen, Reason::RelayIo, Outcome::Failed);
            return;
        }
    };
    let inbound = ShadowsocksTcpInbound::new(
        context.keys.as_ref(),
        context.clock.as_ref(),
        &context.random,
        context.replay.as_ref(),
    );
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            inbound.accept(TokioTransport::new(stream)),
        ) => result,
    };
    let session = match accepted {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            let (stage, outcome, reason) = observation_for_error(error);
            record_failure(&context, stage, reason, outcome);
            update_replay_metric(&context);
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::Shadowsocks,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    update_replay_metric(&context);
    context
        .metrics
        .connection(Role::Server, Inbound::Shadowsocks, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Server, Inbound::Shadowsocks);
    emit(TraceRecord::new(
        LogLevel::Info,
        Event::Connection,
        Role::Server,
        Stage::Shadowsocks,
        Outcome::Accepted,
    ));

    let ferrum2_core::Session {
        target,
        stream,
        initial_payload,
        reply,
    } = session;
    let Some(direct) = context.routing.direct.get(context.routing.route.select(
        context.inbound,
        Network::Tcp,
        &target,
    )) else {
        context
            .metrics
            .active_connections_dec(Role::Server, Inbound::Shadowsocks);
        return;
    };
    let opened = open_and_prefix(
        direct.as_ref(),
        &target,
        &initial_payload,
        context.runtime.idle_timeout,
        cancellation.cancelled(),
    )
    .await;
    let (mut target_stream, initial_payload_bytes) = match opened {
        Ok(opened) => opened,
        Err(DirectFlowError::CancelledBeforeOpen) => {
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(DirectFlowError::Open(error)) => {
            let kind = error.kind();
            let (stage, outcome, reason) = observation_for_direct_connect(kind);
            record_failure(&context, stage, reason, outcome);
            let _ = reply.failed(kind).await;
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(DirectFlowError::Prefix(failure)) => {
            context
                .metrics
                .add_bytes(Role::Server, Direction::InboundToOutbound, failure.bytes);
            let (reason, outcome) = match failure.kind {
                RelayRunError::Io => (Reason::RelayIo, Outcome::Failed),
                RelayRunError::IdleTimeout => (Reason::IdleTimeout, Outcome::Timeout),
                RelayRunError::Cancelled => (Reason::Cancelled, Outcome::Cancelled),
            };
            record_failure(&context, Stage::Direct, reason, outcome);
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
    };
    let _ = reply
        .succeeded_socket(target_stream.local_socket_addr())
        .await;
    let mut framed = TokioFramed::new(stream);
    let relay = relay_lifecycle(
        &mut framed,
        &mut target_stream,
        context.runtime.idle_timeout,
        &context.registry,
        cancellation.cancelled(),
    )
    .await;
    context
        .metrics
        .active_connections_dec(Role::Server, Inbound::Shadowsocks);
    finish_relay(&context, &framed, initial_payload_bytes, relay);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrefixFailure {
    kind: RelayRunError,
    bytes: u64,
}

async fn forward_initial_payload<W, C>(
    stream: &mut W,
    initial_payload: &[u8],
    idle_timeout: std::time::Duration,
    cancellation: C,
) -> Result<u64, PrefixFailure>
where
    W: AsyncWrite + Unpin,
    C: std::future::Future,
{
    let mut written = 0_usize;
    let mut deadline = tokio::time::Instant::now() + idle_timeout;
    tokio::pin!(cancellation);
    while written < initial_payload.len() {
        let result = tokio::select! {
            biased;
            _ = &mut cancellation => {
                return Err(PrefixFailure {
                    kind: RelayRunError::Cancelled,
                    bytes: written as u64,
                });
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(PrefixFailure {
                    kind: RelayRunError::IdleTimeout,
                    bytes: written as u64,
                });
            }
            result = stream.write(&initial_payload[written..]) => result,
        };
        match result {
            Ok(0) => {
                return Err(PrefixFailure {
                    kind: RelayRunError::Io,
                    bytes: written as u64,
                });
            }
            Ok(count) => {
                written += count;
                deadline = tokio::time::Instant::now() + idle_timeout;
            }
            Err(_) => {
                return Err(PrefixFailure {
                    kind: RelayRunError::Io,
                    bytes: written as u64,
                });
            }
        }
    }
    Ok(written as u64)
}

fn update_replay_metric(context: &ServerContext) {
    if let Ok(entries) = context.replay.entry_count() {
        if let Ok(entries) = u32::try_from(entries) {
            context.metrics.set_replay_entries(entries);
        }
    }
}

fn finish_relay(
    context: &ServerContext,
    framed: &TokioFramed<impl PlainDuplex>,
    initial_payload_bytes: u64,
    result: Result<ferrum2_runtime::RelayStats, RelayFailure>,
) {
    let stats = match result {
        Ok(stats) => stats,
        Err(failure) => failure.stats,
    };
    context.metrics.add_bytes(
        Role::Server,
        Direction::InboundToOutbound,
        initial_payload_bytes + stats.inbound_to_outbound,
    );
    context.metrics.add_bytes(
        Role::Server,
        Direction::OutboundToInbound,
        stats.outbound_to_inbound,
    );
    match result {
        Ok(_) => {
            context
                .metrics
                .connection(Role::Server, Inbound::Shadowsocks, Outcome::Completed);
            let (stage, outcome, reason) = framed
                .terminal()
                .map(observation_for_terminal)
                .unwrap_or((Stage::Relay, Outcome::Completed, None));
            emit_observation(Role::Server, stage, outcome, reason);
        }
        Err(RelayFailure {
            kind: RelayRunError::Cancelled,
            ..
        }) => {
            record_failure(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
        }
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            ..
        }) => {
            record_failure(context, Stage::Relay, Reason::IdleTimeout, Outcome::Timeout);
        }
        Err(RelayFailure {
            kind: RelayRunError::Io,
            ..
        }) => {
            if let Some(terminal) = framed.terminal() {
                let (stage, outcome, reason) = observation_for_terminal(terminal);
                emit_observation(Role::Server, stage, outcome, reason);
                if let Some(reason) = reason {
                    context.metrics.failure(Role::Server, stage, reason);
                }
            } else {
                record_failure(context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            }
        }
    }
}

fn record_failure(context: &ServerContext, stage: Stage, reason: Reason, outcome: Outcome) {
    context.metrics.failure(Role::Server, stage, reason);
    if matches!(reason, Reason::Replay | Reason::ReplayCapacity) {
        context.metrics.replay_rejection(reason);
    }
    emit_observation(Role::Server, stage, outcome, Some(reason));
}

fn emit_observation(role: Role, stage: Stage, outcome: Outcome, reason: Option<Reason>) {
    let record = TraceRecord::new(LogLevel::Warn, Event::Failure, role, stage, outcome);
    emit(match reason {
        Some(reason) => record.with_reason(reason),
        None => record,
    });
}

fn log_level(level: LoggingLevel) -> LogLevel {
    match level {
        LoggingLevel::Error => LogLevel::Error,
        LoggingLevel::Warn => LogLevel::Warn,
        LoggingLevel::Info => LogLevel::Info,
        LoggingLevel::Debug => LogLevel::Debug,
        LoggingLevel::Trace => LogLevel::Trace,
    }
}

fn observation_for_error(error: ShadowsocksError) -> (Stage, Outcome, Reason) {
    match error {
        ShadowsocksError::Connect(kind) => (
            Stage::Shadowsocks,
            Outcome::Failed,
            reason_for_connect(kind),
        ),
        ShadowsocksError::Detection(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            reason_for_detection(reason),
        ),
        ShadowsocksError::Protocol(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            reason_for_protocol(reason),
        ),
        ShadowsocksError::Transport(_) => (Stage::Relay, Outcome::Failed, Reason::RelayIo),
    }
}

fn observation_for_direct_connect(kind: ConnectErrorKind) -> (Stage, Outcome, Reason) {
    (Stage::Direct, Outcome::Failed, reason_for_connect(kind))
}

fn observation_for_terminal(terminal: FlowTerminal) -> (Stage, Outcome, Option<Reason>) {
    match terminal {
        FlowTerminal::Normal => (Stage::Relay, Outcome::Completed, None),
        FlowTerminal::Detection(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(reason_for_detection(reason)),
        ),
        FlowTerminal::Protocol(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(reason_for_protocol(reason)),
        ),
        FlowTerminal::Transport(_) => (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo)),
    }
}

fn reason_for_detection(reason: DetectionReason) -> Reason {
    match reason {
        DetectionReason::ShortRead
        | DetectionReason::ShortWrite
        | DetectionReason::Authentication
        | DetectionReason::KeyUnavailable => Reason::Authentication,
        DetectionReason::InvalidType => Reason::InvalidType,
        DetectionReason::TimestampSkew => Reason::TimestampSkew,
        DetectionReason::FrameBounds
        | DetectionReason::PaddingBounds
        | DetectionReason::EmptyRequest => Reason::FrameBounds,
        DetectionReason::AddressBounds => Reason::AddressBounds,
        DetectionReason::ResponseBinding => Reason::ResponseBinding,
        DetectionReason::ClockUnavailable => Reason::ClockUnavailable,
        DetectionReason::RandomUnavailable => Reason::RandomUnavailable,
        DetectionReason::Replay => Reason::Replay,
        DetectionReason::ReplayCapacity => Reason::ReplayCapacity,
        DetectionReason::ReplayUnavailable
        | DetectionReason::ReadFailed
        | DetectionReason::WriteFailed => Reason::RelayIo,
    }
}

fn reason_for_protocol(reason: ProtocolReason) -> Reason {
    match reason {
        ProtocolReason::Authentication => Reason::Authentication,
        ProtocolReason::FrameBounds => Reason::FrameBounds,
        ProtocolReason::NonceExhausted => Reason::NonceExhausted,
    }
}

fn reason_for_connect(kind: ConnectErrorKind) -> Reason {
    match kind {
        ConnectErrorKind::NetworkUnreachable => Reason::NetworkUnreachable,
        ConnectErrorKind::HostUnreachable => Reason::HostUnreachable,
        ConnectErrorKind::ConnectionRefused => Reason::ConnectionRefused,
        ConnectErrorKind::Timeout => Reason::ConnectTimeout,
        ConnectErrorKind::Other => Reason::RelayIo,
    }
}

pub(crate) struct TokioTransport<T> {
    inner: T,
}

impl<T> TokioTransport<T> {
    pub(crate) const fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> LocalEndpoint for TokioTransport<T>
where
    T: LocalEndpoint,
{
    fn local_endpoint(&self) -> std::net::SocketAddrV4 {
        self.inner.local_endpoint()
    }
}

impl<T> AbortiveClose for TokioTransport<T>
where
    T: AbortiveClose,
{
    type Error = T::Error;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive()
    }
}

impl<T> TransportIo for TokioTransport<T>
where
    T: AsyncRead + AsyncWrite + AbortiveClose + Send + Unpin,
{
    type IoError = io::Error;

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        let mut buffer = ReadBuf::new(destination);
        match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::Other))),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, source)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }
}

pub(crate) struct TokioFramed<F> {
    inner: F,
}

impl<F> TokioFramed<F> {
    pub(crate) const fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F> TokioFramed<F>
where
    F: PlainDuplex,
{
    pub(crate) fn terminal(&self) -> Option<FlowTerminal> {
        self.inner.terminal()
    }
}

impl<F> AsyncRead for TokioFramed<F>
where
    F: PlainDuplex,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = buffer.remaining();
        let result = {
            let destination = buffer.initialize_unfilled();
            Pin::new(&mut self.inner).poll_read_plain(cx, destination)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(read)) if read <= remaining => {
                buffer.advance(read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(framed_error(error))),
        }
    }
}

impl<F> AsyncWrite for TokioFramed<F>
where
    F: PlainDuplex,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner)
            .poll_write_plain(cx, source)
            .map_err(framed_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush_plain(cx)
            .map_err(framed_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_shutdown_plain(cx)
            .map_err(framed_error)
    }
}

fn framed_error(error: ShadowsocksError) -> io::Error {
    match error {
        ShadowsocksError::Detection(_) | ShadowsocksError::Protocol(_) => {
            io::Error::from(io::ErrorKind::InvalidData)
        }
        ShadowsocksError::Transport(_) | ShadowsocksError::Connect(_) => {
            io::Error::from(io::ErrorKind::Other)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;
    use std::time::Duration;

    use ferrum2_core::{ConnectError, Connector, Datagram, LocalEndpoint, Outbound, TargetAddr};
    use ferrum2_crypto::{
        Aes128Psk, MethodProfile, MethodPsk, MethodSinglePskProvider, MethodTcpSalt,
        SinglePskProvider,
    };
    use ferrum2_runtime::{OwnerSnapshot, UdpDirection, UdpSessionManager};
    use ferrum2_shadowsocks::TransportPhase;
    use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn listener_policy_rebinds_after_traffic_and_excludes_live_contender() {
        let address = reserve_address();
        let listener = bind_listener(address, 1).expect("initial listener");
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let mut client = client.expect("client connect");
        let (mut accepted, _) = accepted.expect("listener accept");
        client.write_all(b"x").await.expect("client traffic");
        let mut request = [0_u8; 1];
        accepted
            .read_exact(&mut request)
            .await
            .expect("accepted traffic");
        accepted.write_all(b"y").await.expect("server traffic");
        accepted.shutdown().await.expect("server active close");
        let mut response = [0_u8; 1];
        client
            .read_exact(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, *b"y");
        assert_eq!(client.read(&mut response).await.expect("client EOF"), 0);
        drop(accepted);
        drop(client);
        drop(listener);

        let rebound = bind_listener(address, 1).expect("exact listener restart");
        assert_eq!(
            bind_listener(address, 1).expect_err("live contender"),
            RunError::StartupBind
        );
        drop(rebound);
    }

    const PSK_BYTES: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    struct EndpointIo {
        inner: tokio::io::DuplexStream,
        endpoint: SocketAddrV4,
        aborts: Arc<AtomicUsize>,
    }

    impl AsyncRead for EndpointIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for EndpointIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, source)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl LocalEndpoint for EndpointIo {
        fn local_endpoint(&self) -> SocketAddrV4 {
            self.endpoint
        }
    }

    impl AbortiveClose for EndpointIo {
        type Error = io::Error;

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn adapter_contract_transport_delegates_io_and_abortive_close() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_002);
        let aborts = Arc::new(AtomicUsize::new(0));
        let (inner, mut peer) = tokio::io::duplex(32);
        let mut transport = TokioTransport::new(EndpointIo {
            inner,
            endpoint,
            aborts: Arc::clone(&aborts),
        });

        peer.write_all(b"abc").await.expect("peer write");
        let mut read = [0_u8; 3];
        let count = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read(cx, &mut read))
            .await
            .expect("transport read");
        assert_eq!(count, 3);
        assert_eq!(&read, b"abc");

        let written = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"xyz"))
            .await
            .expect("transport write");
        assert_eq!(written, 3);
        let mut received = [0_u8; 3];
        peer.read_exact(&mut received).await.expect("peer read");
        assert_eq!(&received, b"xyz");

        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_flush(cx))
            .await
            .expect("transport flush");
        transport.mark_abortive().expect("abortive delegation");
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
    }

    struct FailingIo;

    impl AsyncRead for FailingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }
    }

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _source: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }
    }

    impl AbortiveClose for FailingIo {
        type Error = io::Error;

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn assert_source_free(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.get_ref().is_none());
        assert!(!format!("{error:?}").contains("sentinel"));
    }

    #[tokio::test]
    async fn adapter_contract_transport_errors_are_fixed_and_source_free() {
        let mut transport = TokioTransport::new(FailingIo);
        let mut read = [0_u8; 1];
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read(cx, &mut read))
                .await
                .expect_err("read failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"x"))
                .await
                .expect_err("write failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_flush(cx))
                .await
                .expect_err("flush failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_shutdown(cx))
                .await
                .expect_err("shutdown failure"),
        );
    }

    struct OneReadFlow {
        data: Option<&'static [u8]>,
        terminal: Option<FlowTerminal>,
    }

    impl PlainDuplex for OneReadFlow {
        fn poll_read_plain(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            destination: &mut [u8],
        ) -> Poll<Result<usize, ShadowsocksError>> {
            let data = self.data.take().unwrap_or_default();
            destination[..data.len()].copy_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_write_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<Result<usize, ShadowsocksError>> {
            Poll::Ready(Ok(source.len()))
        }

        fn poll_flush_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), ShadowsocksError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), ShadowsocksError>> {
            Poll::Ready(Ok(()))
        }

        fn terminal(&self) -> Option<FlowTerminal> {
            self.terminal
        }
    }

    #[tokio::test]
    async fn adapter_contract_framed_uses_initialized_readbuf_and_fixed_mapping() {
        let mut framed = TokioFramed::new(OneReadFlow {
            data: Some(b"xyz"),
            terminal: Some(FlowTerminal::Normal),
        });
        let mut read = [0xa5_u8; 3];
        framed.read_exact(&mut read).await.expect("framed read");
        assert_eq!(&read, b"xyz");
        assert_eq!(framed.terminal(), Some(FlowTerminal::Normal));

        for error in [
            ShadowsocksError::Detection(DetectionReason::Authentication),
            ShadowsocksError::Protocol(ProtocolReason::FrameBounds),
        ] {
            let mapped = framed_error(error);
            assert_eq!(mapped.kind(), io::ErrorKind::InvalidData);
            assert!(mapped.get_ref().is_none());
            assert!(!format!("{mapped:?}").contains("sentinel"));
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            let mapped = framed_error(ShadowsocksError::Transport(phase));
            assert_eq!(mapped.kind(), io::ErrorKind::Other);
            assert!(mapped.get_ref().is_none());
            assert!(!format!("{mapped:?}").contains("sentinel"));
        }
    }

    #[test]
    fn adapter_contract_observability_mapping_is_exhaustive_and_call_site_specific() {
        for (kind, expected) in [
            (
                ConnectErrorKind::NetworkUnreachable,
                Reason::NetworkUnreachable,
            ),
            (ConnectErrorKind::HostUnreachable, Reason::HostUnreachable),
            (
                ConnectErrorKind::ConnectionRefused,
                Reason::ConnectionRefused,
            ),
            (ConnectErrorKind::Timeout, Reason::ConnectTimeout),
            (ConnectErrorKind::Other, Reason::RelayIo),
        ] {
            assert_eq!(reason_for_connect(kind), expected);
            assert_eq!(
                observation_for_direct_connect(kind),
                (Stage::Direct, Outcome::Failed, expected)
            );
        }
        for (reason, expected) in detection_cases() {
            assert_eq!(reason_for_detection(reason), expected);
            assert_eq!(
                observation_for_error(ShadowsocksError::Detection(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, expected)
            );
        }
        for (reason, expected) in [
            (ProtocolReason::Authentication, Reason::Authentication),
            (ProtocolReason::FrameBounds, Reason::FrameBounds),
            (ProtocolReason::NonceExhausted, Reason::NonceExhausted),
        ] {
            assert_eq!(reason_for_protocol(reason), expected);
            assert_eq!(
                observation_for_terminal(FlowTerminal::Protocol(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected))
            );
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            assert_eq!(
                observation_for_terminal(FlowTerminal::Transport(phase)),
                (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo))
            );
        }
        assert_eq!(
            observation_for_terminal(FlowTerminal::Normal),
            (Stage::Relay, Outcome::Completed, None)
        );
    }

    fn detection_cases() -> [(DetectionReason, Reason); 18] {
        [
            (DetectionReason::ShortRead, Reason::Authentication),
            (DetectionReason::ShortWrite, Reason::Authentication),
            (DetectionReason::Authentication, Reason::Authentication),
            (DetectionReason::InvalidType, Reason::InvalidType),
            (DetectionReason::TimestampSkew, Reason::TimestampSkew),
            (DetectionReason::FrameBounds, Reason::FrameBounds),
            (DetectionReason::AddressBounds, Reason::AddressBounds),
            (DetectionReason::PaddingBounds, Reason::FrameBounds),
            (DetectionReason::EmptyRequest, Reason::FrameBounds),
            (DetectionReason::ResponseBinding, Reason::ResponseBinding),
            (DetectionReason::KeyUnavailable, Reason::Authentication),
            (DetectionReason::ClockUnavailable, Reason::ClockUnavailable),
            (
                DetectionReason::RandomUnavailable,
                Reason::RandomUnavailable,
            ),
            (DetectionReason::Replay, Reason::Replay),
            (DetectionReason::ReplayCapacity, Reason::ReplayCapacity),
            (DetectionReason::ReplayUnavailable, Reason::RelayIo),
            (DetectionReason::ReadFailed, Reason::RelayIo),
            (DetectionReason::WriteFailed, Reason::RelayIo),
        ]
    }

    struct RecordingStream {
        bytes: Arc<Mutex<Vec<u8>>>,
        write_calls: Arc<AtomicUsize>,
        max_write: usize,
        fail_after: Option<usize>,
        stall_after: Option<usize>,
        endpoint: SocketAddrV4,
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            let call = self.write_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_after == Some(call) {
                return Poll::Ready(Err(io::Error::other("sentinel write failure")));
            }
            if self.stall_after.is_some_and(|after| call >= after) {
                return Poll::Pending;
            }
            let written = source.len().min(self.max_write);
            self.bytes
                .lock()
                .expect("recording bytes")
                .extend_from_slice(&source[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl LocalEndpoint for RecordingStream {
        fn local_endpoint(&self) -> SocketAddrV4 {
            self.endpoint
        }
    }

    struct ControlledOutbound {
        gate: Arc<Notify>,
        stream: Mutex<Option<RecordingStream>>,
        failure: Option<ConnectErrorKind>,
        calls: Arc<AtomicUsize>,
    }

    impl Outbound for ControlledOutbound {
        type Stream = RecordingStream;
        type Error = ConnectError;

        async fn open(&self, _target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.gate.notified().await;
            match self.failure {
                Some(kind) => Err(ConnectError::new(kind)),
                None => Ok(self
                    .stream
                    .lock()
                    .expect("recording stream")
                    .take()
                    .expect("one open")),
            }
        }
    }

    type ControlledParts = (
        Arc<ControlledOutbound>,
        Arc<Notify>,
        Arc<Mutex<Vec<u8>>>,
        Arc<AtomicUsize>,
    );

    fn controlled_outbound(
        max_write: usize,
        fail_after: Option<usize>,
        stall_after: Option<usize>,
        failure: Option<ConnectErrorKind>,
    ) -> ControlledParts {
        let gate = Arc::new(Notify::new());
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let write_calls = Arc::new(AtomicUsize::new(0));
        let outbound = Arc::new(ControlledOutbound {
            gate: Arc::clone(&gate),
            stream: Mutex::new(Some(RecordingStream {
                bytes: Arc::clone(&bytes),
                write_calls: Arc::clone(&write_calls),
                max_write,
                fail_after,
                stall_after,
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003),
            })),
            failure,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        (outbound, gate, bytes, write_calls)
    }

    #[tokio::test]
    async fn adapter_contract_connect_failure_never_reports_opened_stream() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let (outbound, gate, bytes, write_calls) =
            controlled_outbound(2, None, None, Some(ConnectErrorKind::ConnectionRefused));
        let task_outbound = Arc::clone(&outbound);
        let task_target = target.clone();
        let task = tokio::spawn(async move {
            open_and_prefix(
                task_outbound.as_ref(),
                &task_target,
                b"never",
                Duration::from_secs(5),
                std::future::pending::<()>(),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(bytes.lock().expect("recording bytes").is_empty());
        gate.notify_one();
        assert!(matches!(
            task.await.expect("connect task"),
            Err(DirectFlowError::Open(error))
                if error.kind() == ConnectErrorKind::ConnectionRefused
        ));
        assert_eq!(write_calls.load(Ordering::SeqCst), 0);
    }

    struct GatedPrefixWriter {
        ready: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        waker: Arc<Mutex<Option<Waker>>>,
        max_write: usize,
        fail_after: Option<usize>,
        zero_after: Option<usize>,
    }

    impl AsyncWrite for GatedPrefixWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_after == Some(call) {
                return Poll::Ready(Err(io::Error::other("prefix sentinel")));
            }
            if self.zero_after == Some(call) {
                return Poll::Ready(Ok(0));
            }
            if !self.ready.swap(false, Ordering::SeqCst) {
                *self.waker.lock().expect("prefix waker") = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(source.len().min(self.max_write)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn server_deadline_test_config(
        idle_timeout_ms: Option<u64>,
    ) -> (PathBuf, ValidatedServerConfig) {
        static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-server-deadline-{}-{}.toml",
            std::process::id(),
            CONFIG_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let mut runtime = String::from("[runtime]\n");
        if let Some(value) = idle_timeout_ms {
            runtime.push_str(&format!("idle_timeout_ms = {value}\n"));
        }
        let source = format!(
            "schema_version = 1\n\
             [server]\n\
             listen = \"127.0.0.1:42001\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             {runtime}"
        );
        std::fs::write(&path, source).expect("server deadline config");
        let config = ferrum2_config::load_server(&path).expect("validated server deadline config");
        (path, config)
    }

    async fn assert_prefix_pending<F>(future: &mut Pin<Box<F>>)
    where
        F: std::future::Future,
    {
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("prefix completed before its controlled deadline"),
            _ = tokio::task::yield_now() => {}
        }
    }

    fn release_prefix_writer(ready: &AtomicBool, waker: &Mutex<Option<Waker>>) {
        ready.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().expect("prefix waker").take() {
            waker.wake();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_composition_contract_default_prefix_idle_timeout_is_exact() {
        let (path, config) = server_deadline_test_config(None);
        assert_eq!(config.runtime.idle_timeout, Duration::from_secs(300));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut writer = GatedPrefixWriter {
            ready: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&calls),
            waker: Arc::new(Mutex::new(None)),
            max_write: 2,
            fail_after: None,
            zero_after: None,
        };
        let mut prefix = Box::pin(forward_initial_payload(
            &mut writer,
            b"four",
            config.runtime.idle_timeout,
            std::future::pending::<()>(),
        ));

        assert_prefix_pending(&mut prefix).await;
        tokio::time::advance(Duration::from_millis(299_999)).await;
        assert_prefix_pending(&mut prefix).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            prefix.await,
            Err(PrefixFailure {
                kind: RelayRunError::IdleTimeout,
                bytes: 0,
            })
        );
        assert!(calls.load(Ordering::SeqCst) >= 1);
        std::fs::remove_file(path).expect("remove server deadline config");
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_composition_contract_non_default_prefix_progress_resets_fresh_deadline() {
        let (path, config) = server_deadline_test_config(Some(3_700));
        assert_eq!(config.runtime.idle_timeout, Duration::from_millis(3_700));
        let ready = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(Mutex::new(None));
        let mut writer = GatedPrefixWriter {
            ready: Arc::clone(&ready),
            calls: Arc::clone(&calls),
            waker: Arc::clone(&waker),
            max_write: 2,
            fail_after: None,
            zero_after: None,
        };
        let mut prefix = Box::pin(forward_initial_payload(
            &mut writer,
            b"four",
            config.runtime.idle_timeout,
            std::future::pending::<()>(),
        ));

        assert_prefix_pending(&mut prefix).await;
        tokio::time::advance(Duration::from_millis(2_300)).await;
        assert_prefix_pending(&mut prefix).await;
        release_prefix_writer(&ready, &waker);
        assert_prefix_pending(&mut prefix).await;
        assert!(calls.load(Ordering::SeqCst) >= 2);
        tokio::time::advance(Duration::from_millis(3_699)).await;
        assert_prefix_pending(&mut prefix).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            prefix.await,
            Err(PrefixFailure {
                kind: RelayRunError::IdleTimeout,
                bytes: 2,
            })
        );
        std::fs::remove_file(path).expect("remove server deadline config");
    }

    #[tokio::test]
    async fn lifecycle_composition_contract_prefix_cancel_retains_partial_count() {
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        let (outbound, _gate, bytes, writes) = controlled_outbound(2, None, None, None);
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut prefix = Box::pin(open_and_prefix(
            outbound.as_ref(),
            &target,
            b"four",
            std::time::Duration::from_secs(5),
            cancelled,
        ));
        tokio::select! {
            biased;
            _ = &mut prefix => panic!("prefix ended before cancellation"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(outbound.calls.load(Ordering::SeqCst), 1);
        cancel.send(()).expect("cancel prefix");
        assert!(matches!(
            prefix.await,
            Err(DirectFlowError::CancelledBeforeOpen)
        ));
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert!(bytes.lock().expect("recorded prefix").is_empty());

        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        let (outbound, gate, bytes, _) = controlled_outbound(2, None, Some(1), None);
        gate.notify_one();
        let mut prefix = Box::pin(open_and_prefix(
            outbound.as_ref(),
            &target,
            b"four",
            std::time::Duration::from_secs(5),
            cancelled,
        ));
        tokio::select! {
            biased;
            _ = &mut prefix => panic!("prefix ended before cancellation"),
            _ = tokio::task::yield_now() => {}
        }
        cancel.send(()).expect("cancel prefix");
        assert!(matches!(
            prefix.await,
            Err(DirectFlowError::Prefix(PrefixFailure {
                kind: RelayRunError::Cancelled,
                bytes: 2,
            }))
        ));
        assert_eq!(bytes.lock().expect("recorded prefix").as_slice(), b"fo");
    }

    #[tokio::test]
    async fn lifecycle_composition_contract_prefix_write_zero_and_error_retain_counts() {
        for (fail_after, zero_after) in [(Some(1), None), (None, Some(1))] {
            let mut writer = GatedPrefixWriter {
                ready: Arc::new(AtomicBool::new(true)),
                calls: Arc::new(AtomicUsize::new(0)),
                waker: Arc::new(Mutex::new(None)),
                max_write: 2,
                fail_after,
                zero_after,
            };
            let result = forward_initial_payload(
                &mut writer,
                b"four",
                std::time::Duration::from_secs(5),
                std::future::pending::<()>(),
            )
            .await;
            assert_eq!(
                result,
                Err(PrefixFailure {
                    kind: RelayRunError::Io,
                    bytes: 2,
                })
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_composition_contract_empty_prefix_performs_no_write() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut writer = GatedPrefixWriter {
            ready: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&calls),
            waker: Arc::new(Mutex::new(None)),
            max_write: 1,
            fail_after: None,
            zero_after: None,
        };
        assert_eq!(
            forward_initial_payload(
                &mut writer,
                b"",
                std::time::Duration::from_secs(5),
                std::future::pending::<()>(),
            )
            .await,
            Ok(0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn reserve_address() -> SocketAddrV4 {
        static ISSUED_SERVER_PORTS: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();
        loop {
            let tcp =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve TCP address");
            let address = match tcp.local_addr().expect("reserved address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 reservation"),
            };
            let Ok(udp) = std::net::UdpSocket::bind(address) else {
                drop(tcp);
                continue;
            };
            let inserted = ISSUED_SERVER_PORTS
                .get_or_init(|| Mutex::new(BTreeSet::new()))
                .lock()
                .expect("issued server port registry")
                .insert(address.port());
            drop((tcp, udp));
            if inserted {
                return address;
            }
        }
    }

    async fn udp_loopback() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("UDP bind")
    }

    async fn recv_udp(socket: &UdpSocket, buffer: &mut [u8]) -> (usize, SocketAddr) {
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(buffer))
            .await
            .expect("UDP receive deadline")
            .expect("UDP receive")
    }

    async fn assert_pending<F: std::future::Future>(future: F, message: &str) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), future)
                .await
                .is_err(),
            "{message}"
        );
    }

    fn aes_keys() -> MethodKeyAdapter<MethodSinglePskProvider> {
        MethodKeyAdapter::new(MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &PSK_BYTES)
                .expect("AES-128 key"),
        ))
    }

    fn server_test_config(listen: SocketAddrV4) -> (PathBuf, ValidatedServerConfig) {
        server_test_config_for_method(
            listen,
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
        )
    }

    fn server_test_config_for_method(
        listen: SocketAddrV4,
        method: &str,
        psk: &str,
    ) -> (PathBuf, ValidatedServerConfig) {
        static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-server-composition-{}-{}.toml",
            std::process::id(),
            CONFIG_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let source = format!(
            "schema_version = 1\n\
             [server]\n\
             listen = \"{listen}\"\n\
             [shadowsocks]\n\
             method = \"{method}\"\n\
             psk = \"{psk}\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n"
        );
        std::fs::write(&path, source).expect("server test config");
        let config = ferrum2_config::load_server(&path).expect("validated server test config");
        (path, config)
    }

    fn tagged_server_test_config<const N: usize>(
        listens: [SocketAddrV4; N],
    ) -> (PathBuf, ValidatedServerConfig) {
        let (path, mut config) = server_test_config(listens[0]);
        config.inbounds.extend(
            listens[1..]
                .iter()
                .map(|listen| ferrum2_config::ServerInboundConfig { listen: *listen }),
        );
        config.runtime.max_connections = 1.try_into().expect("one connection");
        config.udp.max_sessions = 1;
        (path, config)
    }

    fn active(mut snapshot: OwnerSnapshot) -> OwnerSnapshot {
        snapshot.process_root_reaps = 0;
        snapshot.process_root_rollbacks = 0;
        snapshot.process_forced_roots = 0;
        snapshot.forced_shutdowns = 0;
        snapshot.udp_forced_shutdowns = 0;
        snapshot
    }

    type TestServerTask = tokio::task::JoinHandle<Result<(), RunError>>;

    fn spawn_test_server(
        config: ValidatedServerConfig,
        registry: &OwnerRegistry,
    ) -> (tokio::sync::oneshot::Sender<()>, TestServerTask) {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_with_registry(config, registry.clone(), async move {
            let _ = stopped.await;
        }));
        (stop, task)
    }

    fn encoded_udp_request(
        client: &mut UdpClientSession,
        clock: &SystemClock,
        target: TargetAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let request = Datagram::new(target, payload.into(), payload.len()).expect("UDP request");
        let mut scratch = UdpPacketScratch::new();
        let mut wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        let length = client
            .encode_request(clock, &SystemRandom, &request, 0, &mut wire, &mut scratch)
            .expect("encode UDP request");
        wire.truncate(length);
        wire
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

    #[tokio::test]
    async fn tagged_udp_is_process_bounded_and_bound_to_its_local_inbound() {
        let first_listen = reserve_address();
        let second_listen = reserve_address();
        let target = udp_loopback().await;
        let target_address = target.local_addr().expect("target address");
        let routed_target = udp_loopback().await;
        let routed_address = routed_target.local_addr().expect("routed target address");
        let routed_domain =
            TargetAddr::domain("127.0.0.1", routed_address.port()).expect("domain target");
        let poison_new = udp_loopback().await;
        let poison_new_address =
            TargetAddr::ip(poison_new.local_addr().expect("new poison address"))
                .expect("new poison target");
        let poison_existing = udp_loopback().await;
        let poison_existing_address = TargetAddr::domain(
            "127.0.0.1",
            poison_existing
                .local_addr()
                .expect("existing poison address")
                .port(),
        )
        .expect("existing poison target");
        let (path, mut config) = tagged_server_test_config([first_listen, second_listen]);
        config.outbounds.push(ferrum2_config::ServerOutboundConfig);
        let poison = config.outbounds.len();
        let rule = |target, outbound| {
            ferrum2_core::route::RouteRule::new(Some(1), Some(Network::Udp), Some(target), outbound)
        };
        config.route = ferrum2_core::route::RouteTable::routed(
            vec![
                rule(routed_domain.clone(), 1),
                rule(poison_new_address.clone(), poison),
                rule(poison_existing_address.clone(), poison),
            ],
            0,
        )
        .expect("routed UDP");
        let registry = OwnerRegistry::new();
        let (stop, mut server) = spawn_test_server(config, &registry);
        wait_until_bound(&mut server, first_listen).await;
        wait_until_bound(&mut server, second_listen).await;

        let keys = aes_keys();
        let clock = SystemClock::new();
        let mut client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
        let first_peer = udp_loopback().await;
        let roaming_peer = udp_loopback().await;
        let cross_peer = udp_loopback().await;
        let mut second =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
        let poison_wire =
            encoded_udp_request(&mut second, &clock, poison_new_address, b"new-poison");
        let baseline = registry.snapshot();
        cross_peer
            .send_to(&poison_wire, second_listen)
            .await
            .expect("new poison send");
        let mut payload = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        assert_pending(
            poison_new.recv_from(&mut payload),
            "new poison reached target",
        )
        .await;
        assert_eq!(registry.snapshot(), baseline);
        let first_wire = encoded_udp_request(
            &mut client,
            &clock,
            TargetAddr::ip(target_address).expect("target"),
            b"first",
        );
        first_peer
            .send_to(&first_wire, second_listen)
            .await
            .expect("first send");
        let (received, direct_peer) = recv_udp(&target, &mut payload).await;
        assert_eq!(&payload[..received], b"first");
        target
            .send_to(b"first-response", direct_peer)
            .await
            .expect("first target response");
        let (_, response_source) = recv_udp(&first_peer, &mut payload).await;
        assert_eq!(response_source, SocketAddr::V4(second_listen));
        let poison_wire = encoded_udp_request(
            &mut client,
            &clock,
            poison_existing_address,
            b"existing-poison",
        );
        let before_poison = registry.snapshot();
        first_peer
            .send_to(&poison_wire, second_listen)
            .await
            .expect("existing poison send");
        assert_pending(
            poison_existing.recv_from(&mut payload),
            "existing poison reached target",
        )
        .await;
        assert_eq!(registry.snapshot(), before_poison);
        let cross_wire = encoded_udp_request(&mut client, &clock, routed_domain, b"cross-fresh");
        let before_cross = registry.snapshot();

        cross_peer
            .send_to(&cross_wire, first_listen)
            .await
            .expect("cross-inbound send");
        assert_pending(
            routed_target.recv_from(&mut payload),
            "cross-inbound session reached target",
        )
        .await;
        let after_cross = registry.snapshot();
        assert_eq!(after_cross, before_cross);
        roaming_peer
            .send_to(&cross_wire, second_listen)
            .await
            .expect("same-inbound roaming send");
        let (received, direct_peer) = recv_udp(&routed_target, &mut payload).await;
        assert_eq!(&payload[..received], b"cross-fresh");
        routed_target
            .send_to(b"roaming-response", direct_peer)
            .await
            .expect("roaming target response");
        let (_, response_source) = recv_udp(&roaming_peer, &mut payload).await;
        assert_eq!(response_source, SocketAddr::V4(second_listen));
        let second_wire = encoded_udp_request(
            &mut second,
            &clock,
            TargetAddr::ip(target_address).expect("second target"),
            b"over-capacity",
        );
        roaming_peer
            .send_to(&second_wire, second_listen)
            .await
            .expect("second inbound capacity send");
        assert_pending(
            target.recv_from(&mut payload),
            "second inbound multiplied process session cap",
        )
        .await;
        stop.send(()).expect("stop tagged server");
        assert_eq!(server.await.expect("tagged server owner"), Ok(()));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove tagged config");
    }

    #[tokio::test]
    async fn tagged_tcp_shares_static_direct_mapping_and_one_replay_store() {
        let first_listen = reserve_address();
        let second_listen = reserve_address();
        let first_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("first target bind");
        let second_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("second target bind");
        let first_address =
            TargetAddr::ip(first_target.local_addr().expect("first target address"))
                .expect("first target");
        let second_address =
            TargetAddr::ip(second_target.local_addr().expect("second target address"))
                .expect("second target");
        let (path, mut config) = tagged_server_test_config([first_listen, second_listen]);
        let poison = config.outbounds.len();
        let rule = |inbound, outbound| {
            ferrum2_core::route::RouteRule::new(
                inbound,
                Some(Network::Tcp),
                Some(first_address.clone()),
                outbound,
            )
        };
        config.route = ferrum2_core::route::RouteTable::routed(
            vec![rule(Some(1), poison), rule(None, 0)],
            poison,
        )
        .expect("routed TCP");
        let registry = OwnerRegistry::new();
        let (stop, mut server) = spawn_test_server(config, &registry);
        wait_until_bound(&mut server, first_listen).await;
        wait_until_bound(&mut server, second_listen).await;

        let keys = aes_keys();
        let timestamp = SystemClock::new().unix_seconds().expect("wall clock");
        let request = |salt_byte, target: &TargetAddr, payload: &[u8]| {
            let salt =
                MethodTcpSalt::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &[salt_byte; 16])
                    .expect("request salt");
            encode_request_first_write(&keys, &salt, timestamp, target, &[0xa1], payload)
                .expect("request wire")
        };
        let mut invalid = tokio::net::TcpStream::connect(second_listen)
            .await
            .expect("invalid inbound connect");
        invalid
            .write_all(b"invalid")
            .await
            .expect("invalid request");
        invalid.shutdown().await.expect("invalid shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(5), invalid.read(&mut [0_u8; 1]))
            .await
            .expect("invalid close deadline");
        assert_pending(first_target.accept(), "invalid request reached target").await;

        let replayed = request(0x51, &first_address, b"first");
        let mut first = tokio::net::TcpStream::connect(first_listen)
            .await
            .expect("first inbound connect");
        first.write_all(&replayed).await.expect("first request");
        let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), first_target.accept())
            .await
            .expect("first direct deadline")
            .expect("first direct accept");
        let mut payload = [0_u8; 5];
        accepted
            .read_exact(&mut payload)
            .await
            .expect("first initial payload");
        assert_eq!(&payload, b"first");

        let mut replay = tokio::net::TcpStream::connect(second_listen)
            .await
            .expect("replay inbound connect");
        replay.write_all(&replayed).await.expect("replayed request");
        let poison = request(0x52, &first_address, b"poison");
        let mut second = tokio::net::TcpStream::connect(second_listen)
            .await
            .expect("second inbound connect");
        second.write_all(&poison).await.expect("poison request");
        assert_pending(
            first_target.accept(),
            "second listener bypassed process permit",
        )
        .await;
        assert_eq!(registry.snapshot().connection_tasks, 1);

        drop((first, accepted));
        for rejected in [&mut replay, &mut second] {
            let _ = tokio::time::timeout(Duration::from_secs(5), rejected.read(&mut payload))
                .await
                .expect("rejected deadline");
        }
        let final_poison = request(0x53, &second_address, b"final");
        let mut final_flow = tokio::net::TcpStream::connect(first_listen)
            .await
            .expect("final-route connect");
        final_flow
            .write_all(&final_poison)
            .await
            .expect("final request");
        let _ = tokio::time::timeout(Duration::from_secs(5), final_flow.read(&mut payload))
            .await
            .expect("final close deadline");
        assert_pending(second_target.accept(), "final poison reached target").await;
        assert_pending(
            first_target.accept(),
            "replay or inbound poison reached target",
        )
        .await;

        stop.send(()).expect("stop tagged server");
        assert_eq!(server.await.expect("tagged server owner"), Ok(()));
        assert_eq!(registry.snapshot().connection_tasks, 0);
        std::fs::remove_file(path).expect("remove tagged config");
    }

    #[tokio::test]
    async fn tagged_prepare_failure_positions_rollback_every_bound_address() {
        for block in 0..7 {
            let listens = [reserve_address(), reserve_address(), reserve_address()];
            let metrics = reserve_address();
            let (path, mut config) = tagged_server_test_config(listens);
            config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
            let incumbent: Box<dyn Send> = match block {
                0..=2 => Box::new(
                    std::net::TcpListener::bind(listens[block]).expect("occupy TCP position"),
                ),
                3..=5 => Box::new(
                    std::net::UdpSocket::bind(listens[block - 3]).expect("occupy UDP position"),
                ),
                _ => {
                    Box::new(std::net::TcpListener::bind(metrics).expect("occupy metrics position"))
                }
            };
            let registry = OwnerRegistry::new();
            let baseline = active(registry.snapshot());
            assert_eq!(
                run_with_registry(config, registry.clone(), std::future::pending()).await,
                Err(RunError::StartupBind)
            );
            drop(incumbent);
            for listen in listens {
                let tcp = std::net::TcpListener::bind(listen).expect("TCP rollback rebind");
                let udp = std::net::UdpSocket::bind(listen).expect("UDP rollback rebind");
                drop((tcp, udp));
            }
            drop(std::net::TcpListener::bind(metrics).expect("metrics rollback rebind"));
            assert_eq!(active(registry.snapshot()), baseline);
            std::fs::remove_file(path).expect("remove tagged failure config");
        }
    }

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
                    route: config.route,
                    direct: config
                        .outbounds
                        .iter()
                        .map(|_| {
                            Arc::new(DirectOutbound::new(TcpConnector::new(
                                config.runtime.connect_timeout,
                            )))
                        })
                        .collect(),
                }),
                protocol,
                clock: Arc::new(SystemClock::new()),
                config: config.udp,
                sessions,
                mappings,
                admission: Arc::new(tokio::sync::Mutex::new(())),
                connect_timeout: config.runtime.connect_timeout,
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

    async fn wait_until_bound(
        server: &mut tokio::task::JoinHandle<Result<(), RunError>>,
        address: SocketAddrV4,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if server.is_finished() {
                let result = (&mut *server).await.expect("server task before readiness");
                panic!("server exited before readiness: {result:?}");
            }
            match std::net::TcpListener::bind(address) {
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
                Ok(listener) => drop(listener),
                Err(error) => panic!("bind readiness failed: {error}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "listener readiness timed out"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    struct ProtocolClientConnector {
        inner: TcpConnector,
    }

    impl Connector for ProtocolClientConnector {
        type Stream = TokioTransport<RuntimeTcpStream>;

        async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.inner.connect(target).await.map(TokioTransport::new)
        }
    }

    #[tokio::test]
    async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
        let listen = reserve_address();
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener");
        let target_address = match target_listener.local_addr().expect("target address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 target"),
        };
        let (config_path, config) = server_test_config(listen);
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (shutdown_sender, mut run_task) = spawn_test_server(config, &registry);
        wait_until_bound(&mut run_task, listen).await;

        let target_accept =
            tokio::spawn(async move { target_listener.accept().await.expect("target accept").0 });
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes(PSK_BYTES));
        let connector = ProtocolClientConnector {
            inner: TcpConnector::new(Duration::from_secs(5)),
        };
        let server_target = TargetAddr::ipv4(listen).expect("server target");
        let application_target = TargetAddr::ipv4(target_address).expect("application target");
        let clock = SystemClock::new();
        let random = SystemRandom;
        let outbound = ClientTcpOutbound::new(server_target, &keys, &connector, &clock, &random);
        let flow = outbound
            .connect_server()
            .await
            .expect("connect server")
            .write_request(&application_target)
            .await
            .expect("write request");
        let target_stream = target_accept.await.expect("target accept task");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let live = registry.snapshot();
            if live.active_supervisor_children == 1
                && live.connection_tasks == 1
                && live.owned_buffers == 2
                && live.owned_permits >= 1
                && live.listeners == 1
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "registry never exposed the live production path: {live:?}"
            );
            tokio::task::yield_now().await;
        }

        shutdown_sender.send(()).expect("request shutdown");
        assert_eq!(run_task.await.expect("run task"), Ok(()));
        drop(flow);
        drop(target_stream);
        let final_snapshot = registry.snapshot();
        assert_eq!(
            final_snapshot.active_supervisor_children,
            baseline.active_supervisor_children
        );
        assert_eq!(final_snapshot.connection_tasks, baseline.connection_tasks);
        assert_eq!(final_snapshot.owned_buffers, baseline.owned_buffers);
        assert_eq!(final_snapshot.owned_permits, baseline.owned_permits);
        assert_eq!(final_snapshot.listeners, baseline.listeners);
        assert!(
            final_snapshot.process_forced_roots > baseline.process_forced_roots,
            "zero-grace process did not force any required root: {final_snapshot:?}"
        );
        assert_eq!(
            final_snapshot.forced_shutdowns,
            baseline.forced_shutdowns + 1,
            "phase-aware TCP root did not explicitly force and reap its child"
        );
        std::fs::remove_file(config_path).expect("remove server test config");
    }
}
