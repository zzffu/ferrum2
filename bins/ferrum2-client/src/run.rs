use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use ferrum2_config::{LoggingLevel, RuntimeConfig, ValidatedClientConfig};
use ferrum2_core::route::Network;
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, Datagram, Inbound as _,
    LocalEndpoint, SessionReply as _, TargetAddr,
};
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
use ferrum2_crypto::{
    Clock, MethodKeyProvider, MethodSinglePskProvider, SecureRandom, SystemClock, SystemRandom,
    UdpSessionId,
};
use ferrum2_dns::{
    DnsProxy, DnsProxyListeners, DnsProxySockets, ProxyTransport, TaggedResolver,
    TaggedResolverOwner,
};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
    json_subscriber,
};
use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, CancellationToken, MAX_UDP_MAX_BUFFERED_BYTES,
    MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, MetricsEndpoint, MetricsEndpointError,
    OwnerRegistry, PendingUdpDatagram, PendingUdpSession, PreparedProcessRoot, ProcessCancellation,
    ProcessCause, ProcessFuture, ProcessReport, ProcessRoot, ProcessRootExit, ProcessSupervisor,
    RelayFailure, RelayRunError, SupervisorError, TcpConnector, UdpBufferReservation,
    UdpCommitError, UdpDirection, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle,
    UdpSessionManager, relay_lifecycle,
};
use ferrum2_shadowsocks::{
    BorrowedPendingUdpResponse, BoxedClientFlow, ClientTcpOutbound, DetectionReason, FlowTerminal,
    MAX_UDP_WIRE_LEN, MethodKeyAdapter, PlainDuplex, ProtocolReason, ShadowsocksError, TransportIo,
    UdpClientSession, UdpPacketError, UdpPacketScratch, UdpResponseCommit,
    max_udp_payload_len_for_encoded_target,
};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, BufferRole, ClientFlow, FlowObserver, TcpKeyProvider};
use ferrum2_socks5::{
    MAX_SOCKS_UDP_DATAGRAM_BYTES, Socks5Inbound, SocksCommand, SocksStream, SocksUdpAssociate,
    decode_udp_datagram, encode_udp_datagram,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::time::Instant;

#[path = "dns_egress.rs"]
mod dns_egress;

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

pub(crate) fn run(config: ValidatedClientConfig) -> Result<(), RunError> {
    let subscriber = json_subscriber(std::io::stderr, log_level(config.logging.level));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| RunError::StartupObservability)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(run_async(config))
}

async fn run_async(config: ValidatedClientConfig) -> Result<(), RunError> {
    run_with_registry(config, OwnerRegistry::new(), shutdown_signal()).await
}

async fn run_with_registry<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    run_with_registry_and_metrics(config, registry, shutdown, Arc::new(Metrics::new())).await
}

async fn run_with_registry_and_metrics<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    run_with_registry_and_metrics_inner(
        config,
        registry,
        shutdown,
        metrics,
        None,
        #[cfg(test)]
        None,
    )
    .await
}

async fn run_with_registry_and_metrics_inner<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    _udp_id_random: Option<Arc<dyn SecureRandom>>,
    #[cfg(test)] mut dns_observer: Option<
        tokio::sync::oneshot::Sender<(Arc<ClientContext>, Arc<TaggedResolver>)>,
    >,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    metrics.set_udp_sessions_active(Role::Client, 0);
    metrics.set_udp_buffered_bytes(Role::Client, 0);
    #[cfg(test)]
    let method = config.method();
    let dns = config.dns;
    let public_udp_enabled = config.udp.is_some_and(|udp| udp.enabled);
    let internal_udp_needed = dns.as_ref().is_some_and(|dns| {
        dns.servers.iter().any(|server| {
            server.transport == ferrum2_config::DnsTransport::Udp && server.detour.is_some()
        })
    });
    let runtime = config.runtime;
    let outbounds = prepare_client_outbounds(config.outbounds, config.outbound_psks)?;
    let shutdown_grace = config.runtime.shutdown_grace;
    let listen_backlog = u32::from(config.runtime.listen_backlog.get());
    let max_connections = usize::from(config.runtime.max_connections.get());
    let udp = if public_udp_enabled || internal_udp_needed {
        let (max_sessions, max_buffered_bytes, idle_timeout) = match config.udp {
            Some(udp) => (udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout),
            None => {
                let dns = dns.as_ref().expect("internal UDP requires DNS config");
                let sessions = usize::from(dns.max_inflight.get());
                let bytes = sessions
                    .checked_mul(3 * MAX_UDP_WIRE_LEN)
                    .ok_or(RunError::StartupProtocol)?
                    .clamp(MIN_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_BUFFERED_BYTES);
                (sessions, bytes, dns.timeout.max(MIN_UDP_IDLE_TIMEOUT))
            }
        };
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(
                UdpRuntimeLimits::new(max_sessions, max_buffered_bytes, idle_timeout)
                    .map_err(|_| RunError::StartupProtocol)?,
                registry.clone(),
            ),
            live_ids: Arc::new(std::sync::Mutex::new(HashSet::new())),
            #[cfg(test)]
            method,
        })
    } else {
        None
    };
    let context = Arc::new(ClientContext {
        inbound: Socks5Inbound::new(),
        outbound_connector: TokioConnector::new(TcpConnector::new(config.runtime.connect_timeout)),
        #[cfg(test)]
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
        clock: SystemClock::new(),
        random: SystemRandom,
        #[cfg(test)]
        udp_id_random: _udp_id_random,
        runtime: config.runtime,
        udp,
        udp_associate_enabled: public_udp_enabled,
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
        #[cfg(test)]
        test_udp_server: config.server,
    });
    let mut listens = Vec::with_capacity(config.inbounds.len());
    let routing = Arc::new(ClientRouting {
        route: config.route,
        outbounds,
    });
    let dns_context = Arc::clone(&context);
    let dns_routing = Arc::clone(&routing);
    for inbound in &config.inbounds {
        listens.push(inbound.listen);
    }
    let tcp_registry = registry.clone();
    let tcp_context = Arc::clone(&context);
    let mut roots = vec![ProcessRoot::new(move || async move {
        let mut listeners = Vec::with_capacity(listens.len());
        for listen in listens {
            listeners.push(bind_listener(listen, listen_backlog)?);
        }
        let supervisor = BoundedSupervisor::new(
            ClientTcpListeners {
                listeners,
                next: AtomicUsize::new(0),
                #[cfg(test)]
                accept_errors: None,
            },
            max_connections,
            shutdown_grace,
            tcp_registry,
        )
        .map_err(|_| RunError::StartupProtocol)?;
        Ok(ClientTcpRoot {
            supervisor: Some(supervisor),
            context: tcp_context,
            routing,
        })
    })];
    if let Some(dns) = dns {
        let ferrum2_config::DnsConfig {
            inbounds,
            servers,
            route,
            timeout,
            max_inflight,
        } = dns;
        let addresses = inbounds.into_iter().map(|inbound| inbound.listen).collect();
        let route = Arc::new(route);
        roots.push(ProcessRoot::new(move || async move {
            let sockets = DnsProxySockets::bind(
                addresses,
                listen_backlog,
                runtime.max_connections,
                runtime.idle_timeout,
            )
            .await
            .map_err(|_| RunError::StartupBind)?;
            let egress = Arc::new(dns_egress::ClientDnsEgress::new(
                Arc::clone(&dns_context),
                Arc::clone(&dns_routing),
            ));
            let (resolver, owner) = TaggedResolver::new(servers, timeout, max_inflight, egress)
                .map_err(|_| RunError::StartupProtocol)?;
            let resolver = Arc::new(resolver);
            #[cfg(test)]
            if let Some(observer) = dns_observer.take() {
                let _ = observer.send((Arc::clone(&dns_context), Arc::clone(&resolver)));
            }
            let selection = Arc::clone(&route);
            let proxy = Arc::new(DnsProxy::new(
                Arc::clone(&resolver),
                move |inbound, transport, name| {
                    Some(match TargetAddr::domain(&name.to_ascii(), 53) {
                        Ok(target) => selection.select(
                            inbound,
                            match transport {
                                ProxyTransport::Udp => Network::Udp,
                                ProxyTransport::Tcp => Network::Tcp,
                            },
                            &target,
                        ),
                        Err(_) => selection.final_action(),
                    })
                },
            ));
            Ok(ClientDnsRoot {
                listeners: Some(sockets.with_proxy(proxy)),
                resolver: Some(resolver),
                owner: Some(owner),
                #[cfg(test)]
                readiness_gate: None,
            })
        }));
    }
    if let Some(metrics_config) = config.metrics {
        let metrics_registry = registry.clone();
        roots.push(ProcessRoot::new(move || async move {
            let listener = bind_listener(metrics_config.listen, 16)?;
            Ok(ClientMetricsRoot {
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

struct ClientDnsRoot {
    listeners: Option<DnsProxyListeners>,
    resolver: Option<Arc<TaggedResolver>>,
    owner: Option<TaggedResolverOwner>,
    #[cfg(test)]
    readiness_gate: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ClientDnsRoot {
    async fn close_resolver(&mut self) -> Result<(), RunError> {
        self.listeners.take();
        self.resolver.take();
        self.owner
            .as_mut()
            .expect("prepared DNS owner")
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| RunError::ShutdownCleanup)
    }
}

impl PreparedProcessRoot<RunError> for ClientDnsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            #[cfg(test)]
            if let Some(readiness_gate) = self.readiness_gate.take() {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        self.close_resolver().await?;
                        return Ok(());
                    }
                    _ = readiness_gate => {}
                }
            }
            let ready = {
                let owner = self.owner.as_mut().expect("prepared DNS owner");
                tokio::select! {
                    _ = cancellation.cancelled() => None,
                    result = owner.ready() => Some(result),
                }
            };
            match ready {
                None => {
                    self.close_resolver().await?;
                    return Ok(());
                }
                Some(Err(_)) => {
                    self.close_resolver().await?;
                    return Err(RunError::StartupProtocol);
                }
                Some(Ok(())) => {}
            }
            let listeners = self.listeners.take().expect("prepared DNS listeners");
            let result = listeners.run(cancellation.cancelled()).await;
            self.close_resolver().await?;
            result.map_err(|_| RunError::RuntimeListener)
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.close_resolver().await })
    }
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

struct ClientTcpListeners {
    listeners: Vec<TcpListener>,
    next: AtomicUsize,
    #[cfg(test)]
    accept_errors: Option<Arc<std::sync::Mutex<std::collections::VecDeque<io::ErrorKind>>>>,
}

impl AcceptListener for ClientTcpListeners {
    type Stream = (usize, tokio::net::TcpStream);

    async fn accept(&self) -> io::Result<Self::Stream> {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.listeners.len();
        std::future::poll_fn(|task| {
            #[cfg(test)]
            if let Some(kind) = self
                .accept_errors
                .as_ref()
                .and_then(|errors| errors.lock().expect("accept error lock").pop_front())
            {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            for offset in 0..self.listeners.len() {
                let inbound = (start + offset) % self.listeners.len();
                match self.listeners[inbound].poll_accept(task) {
                    Poll::Ready(Ok((stream, _))) => {
                        if let Err(error) = stream.set_nodelay(true) {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok((inbound, stream)));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

struct ClientOutboundContext {
    tcp_server: TargetAddr,
    udp_server: SocketAddrV4,
    keys: MethodKeyAdapter<MethodSinglePskProvider>,
}

fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
    psks: Vec<ferrum2_crypto::MethodPsk>,
) -> Result<Vec<ClientOutboundContext>, RunError> {
    if outbounds.len() != psks.len() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .zip(psks)
        .map(|(outbound, psk)| {
            Ok(ClientOutboundContext {
                tcp_server: TargetAddr::ipv4(outbound.server)
                    .map_err(|_| RunError::StartupProtocol)?,
                udp_server: outbound.server,
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk)),
            })
        })
        .collect()
}

struct ClientRouting {
    route: ferrum2_core::route::RouteTable,
    outbounds: Vec<ClientOutboundContext>,
}

struct ClientTcpRoot {
    supervisor: Option<BoundedSupervisor<ClientTcpListeners>>,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
}

impl PreparedProcessRoot<RunError> for ClientTcpRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let supervisor = self.supervisor.take().expect("prepared TCP root");
        let context = Arc::clone(&self.context);
        let routing = Arc::clone(&self.routing);
        let handler_context = Arc::clone(&context);
        let mut quiescing = cancellation.clone();
        let mut forced = cancellation.clone();
        Box::pin(async move {
            let running = supervisor.run_with_cancellation(
                move |(inbound, stream), cancellation| {
                    let context = Arc::clone(&handler_context);
                    let routing = Arc::clone(&routing);
                    async move {
                        client_connection(stream, cancellation, context, inbound, routing).await;
                    }
                },
                cancellation,
            );
            tokio::pin!(running);
            let result = tokio::select! {
                biased;
                _ = forced.forced() => {
                    record_forced_udp_sessions(&context);
                    if let Some(udp) = &context.udp {
                        udp.manager.cancel_all();
                    }
                    running.await
                }
                _ = quiescing.cancelled() => {
                    if context.runtime.shutdown_grace.is_zero() {
                        forced.forced().await;
                        record_forced_udp_sessions(&context);
                    }
                    if let Some(udp) = &context.udp {
                        udp.manager.cancel_all();
                    }
                    running.await
                }
                result = &mut running => result,
            };
            result.map_err(run_error_for_supervisor)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

fn record_forced_udp_sessions(context: &ClientContext) {
    for _ in 0..context.registry.snapshot().udp_sessions {
        context.metrics.udp_forced_shutdown(Role::Client);
    }
}

struct ClientMetricsRoot {
    listener: Option<TcpListener>,
    metrics: Arc<Metrics>,
    registry: OwnerRegistry,
}

impl PreparedProcessRoot<RunError> for ClientMetricsRoot {
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
            move || render_client_metrics(&metrics, &registry),
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

fn render_client_metrics(metrics: &Metrics, registry: &OwnerRegistry) -> String {
    let snapshot = registry.snapshot();
    metrics.set_udp_sessions_active(Role::Client, snapshot.udp_sessions);
    metrics.set_udp_buffered_bytes(Role::Client, snapshot.udp_buffered_bytes);
    metrics.encode_text().unwrap_or_default()
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

struct ClientContext {
    inbound: Socks5Inbound,
    outbound_connector: TokioConnector<TcpConnector>,
    #[cfg(test)]
    keys: MethodKeyAdapter<MethodSinglePskProvider>,
    clock: SystemClock,
    random: SystemRandom,
    #[cfg(test)]
    udp_id_random: Option<Arc<dyn SecureRandom>>,
    runtime: RuntimeConfig,
    udp: Option<ClientUdpContext>,
    udp_associate_enabled: bool,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
    #[cfg(test)]
    test_udp_server: SocketAddrV4,
}

struct ClientUdpContext {
    manager: UdpSessionManager,
    live_ids: Arc<std::sync::Mutex<HashSet<UdpSessionId>>>,
    #[cfg(test)]
    method: MethodProfile,
}

async fn client_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ClientContext>,
    inbound: usize,
    routing: Arc<ClientRouting>,
) {
    let peer_ip = stream.peer_addr().ok().map(|peer| peer.ip());
    let local_ip = match stream.local_addr() {
        Ok(SocketAddr::V4(local)) if !local.ip().is_unspecified() => Some(*local.ip()),
        Ok(SocketAddr::V4(_)) | Ok(SocketAddr::V6(_)) | Err(_) => None,
    };
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            async {
                if context.udp_associate_enabled {
                    context.inbound.accept_command(stream).await
                } else {
                    context.inbound.accept(stream).await.map(SocksCommand::Connect)
                }
            },
        ) => result,
    };
    let command = match accepted {
        Ok(Ok(command)) => command,
        Ok(Err(_)) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::SocksProtocol,
                Outcome::Rejected,
            );
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    let session = match command {
        SocksCommand::Connect(session) => session,
        SocksCommand::UdpAssociate(association) => {
            let (Some(peer_ip), Some(local_ip)) = (peer_ip, local_ip) else {
                let _ = association.reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            run_udp_association(
                association,
                peer_ip,
                local_ip,
                &mut cancellation,
                Arc::clone(&context),
                (inbound, &routing),
                UdpSocket::bind,
            )
            .await;
            return;
        }
    };
    let ferrum2_core::Session {
        target,
        mut stream,
        initial_payload: _,
        reply,
    } = session;
    let plan = routing.route.select_plan(inbound, Network::Tcp, &target);
    let opened = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = open_chain_with_deadlines(
            &routing.outbounds,
            plan.hops(),
            &context.outbound_connector,
            &context.clock,
            &context.random,
            &target,
            (
                context.runtime.connect_timeout,
                context.runtime.handshake_timeout,
            ),
            #[cfg(test)]
            None,
        ) => result,
    };
    let flow = match opened {
        Ok(flow) => flow,
        Err(ClientOpenFailure::Protocol(error)) => {
            let (stage, outcome, reason) = observation_for_error(error);
            record_failure(&context, stage, reason, outcome);
            let kind = match error {
                ShadowsocksError::Connect(kind) => kind,
                ShadowsocksError::Detection(_)
                | ShadowsocksError::Protocol(_)
                | ShadowsocksError::Transport(_) => ConnectErrorKind::Other,
            };
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::HandshakeTimeout) => {
            record_failure(
                &context,
                Stage::Shadowsocks,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = flow.local_socket_addr();
    if reply.succeeded_socket(bound).await.is_err() {
        record_failure(&context, Stage::Socks5, Reason::RelayIo, Outcome::Failed);
        return;
    }

    context
        .metrics
        .connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Client, Inbound::Socks5);
    emit(TraceRecord::new(
        LogLevel::Info,
        Event::Connection,
        Role::Client,
        Stage::Socks5,
        Outcome::Accepted,
    ));
    let mut framed = TokioFramed::new(flow);
    let relay = relay_lifecycle(
        &mut stream,
        &mut framed,
        context.runtime.idle_timeout,
        &context.registry,
        cancellation.cancelled(),
    )
    .await;
    context
        .metrics
        .active_connections_dec(Role::Client, Inbound::Socks5);
    finish_relay(&context, &framed, relay);
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpIoOperation {
    ApplicationRecv,
    ApplicationSend,
    UpstreamRecv,
    UpstreamSend,
}

#[cfg(test)]
struct UdpIoFaultPlan {
    operation: UdpIoOperation,
    fail_at: usize,
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl UdpIoFaultPlan {
    fn new(operation: UdpIoOperation, fail_at: usize) -> Self {
        Self {
            operation,
            fail_at,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn fails(&self, operation: UdpIoOperation) -> bool {
        self.operation == operation
            && self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.fail_at
    }
}

struct PreparedClientUdp {
    plans: HashMap<Box<[usize]>, ClientUdpPlan>,
    pending_session: Option<PendingUdpSession>,
    manager: UdpSessionManager,
    handle: UdpSessionHandle,
    live_ids: Arc<std::sync::Mutex<HashSet<UdpSessionId>>>,
    static_server: Option<SocketAddrV4>,
    static_plan: Option<Box<[usize]>>,
    application: UdpSocket,
    upstream: UdpSocket,
    application_wire: Vec<u8>,
    upstream_wire: Vec<u8>,
    scratch: UdpPacketScratch,
    _fixed_capacity: Vec<UdpBufferReservation>,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

struct ClientUdpLeg {
    protocol: UdpClientSession,
    id: UdpSessionId,
}

struct ClientUdpPlan {
    legs: Vec<ClientUdpLeg>,
}

const MAX_ACTIVE_UDP_PLANS: usize = 128;
const MAX_UDP_PLAN_HOPS: usize = 8;

impl Drop for PreparedClientUdp {
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

async fn run_udp_association<IO, F, Fut>(
    association: SocksUdpAssociate<IO>,
    peer_ip: IpAddr,
    local_ip: Ipv4Addr,
    cancellation: &mut CancellationToken,
    context: Arc<ClientContext>,
    route: (usize, &ClientRouting),
    bind: F,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(SocketAddrV4) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let requested_port = association.source_port();
    let SocksUdpAssociate {
        mut control, reply, ..
    } = association;
    let (inbound, routing) = route;
    let static_plan = if routing.route.is_routed() {
        None
    } else {
        let placeholder = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))
            .expect("fixed valid route target");
        let plan = routing
            .route
            .select_plan(inbound, Network::Udp, &placeholder);
        let hops: Box<[usize]> = plan.hops().into();
        let server = hops
            .first()
            .and_then(|hop| routing.outbounds.get(*hop))
            .map(|outbound| outbound.udp_server);
        server.map(|server| (hops, server))
    };
    if !routing.route.is_routed() && static_plan.is_none() {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    }
    let prepared = tokio::select! {
        _ = cancellation.cancelled() => return,
        prepared = prepare_udp_association_with_bind(&context, local_ip, static_plan, bind) => prepared,
    };
    let mut prepared = match prepared {
        Ok(prepared) => prepared,
        Err(()) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = match prepared.application.local_addr() {
        Ok(SocketAddr::V4(bound)) => bound,
        Ok(SocketAddr::V6(_)) | Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    if reply.succeeded(bound).await.is_err() {
        return;
    }

    relay_udp_association(
        &mut prepared,
        &mut control,
        peer_ip,
        requested_port,
        cancellation,
        &context,
        route,
    )
    .await;
}

async fn prepare_udp_association_with_bind<F, Fut>(
    context: &ClientContext,
    local_ip: Ipv4Addr,
    static_plan: Option<(Box<[usize]>, SocketAddrV4)>,
    mut bind: F,
) -> Result<PreparedClientUdp, ()>
where
    F: FnMut(SocketAddrV4) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let udp = context.udp.as_ref().ok_or(())?;
    if static_plan
        .as_ref()
        .is_some_and(|(plan, _)| plan.is_empty() || plan.len() > MAX_UDP_PLAN_HOPS)
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
    let prepared = PreparedClientUdp {
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

fn activate_udp_plan(
    prepared: &mut PreparedClientUdp,
    context: &ClientContext,
    outbounds: &[ClientOutboundContext],
    hops: &[usize],
) -> Result<(), ()> {
    if hops.is_empty() || hops.len() > MAX_UDP_PLAN_HOPS {
        return Err(());
    }
    if !prepared.plans.contains_key(hops) {
        if prepared.plans.len() >= MAX_ACTIVE_UDP_PLANS {
            return Err(());
        }
        #[cfg(test)]
        let random = context.udp_id_random.as_deref().unwrap_or(&context.random);
        #[cfg(not(test))]
        let random = &context.random;
        let legs = register_udp_plan(outbounds, hops, random, &prepared.live_ids)?;
        prepared.plans.insert(hops.into(), ClientUdpPlan { legs });
    }
    Ok(())
}

fn register_udp_plan(
    outbounds: &[ClientOutboundContext],
    hops: &[usize],
    random: &(impl SecureRandom + ?Sized),
    live_ids: &std::sync::Mutex<HashSet<UdpSessionId>>,
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

fn encode_udp_plan_request(
    prepared: &mut PreparedClientUdp,
    outbounds: &[ClientOutboundContext],
    hops: &[usize],
    datagram: &Datagram,
    clock: &(impl Clock + ?Sized),
    random: &(impl SecureRandom + ?Sized),
) -> Result<usize, UdpPacketError> {
    let PreparedClientUdp {
        plans,
        application_wire,
        upstream_wire,
        scratch,
        ..
    } = prepared;
    let plan = plans
        .get_mut(hops)
        .ok_or(UdpPacketError::StateUnavailable)?;
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
                clock,
                random,
                target,
                datagram.payload(),
                0,
                upstream_wire,
                scratch,
            )?
        } else if wire_in_upstream {
            plan.legs[layer].protocol.encode_request_parts(
                clock,
                random,
                target,
                &upstream_wire[..wire_len],
                0,
                application_wire,
                scratch,
            )?
        } else {
            plan.legs[layer].protocol.encode_request_parts(
                clock,
                random,
                target,
                &application_wire[..wire_len],
                0,
                upstream_wire,
                scratch,
            )?
        };
        wire_in_upstream = layer + 1 == hops.len() || !wire_in_upstream;
    }
    if !wire_in_upstream {
        upstream_wire[..wire_len].copy_from_slice(&application_wire[..wire_len]);
    }
    Ok(wire_len)
}

enum UdpPlanResponseError {
    Packet(UdpPacketError),
    Runtime(UdpRuntimeError),
}

fn accept_udp_plan_response(
    prepared: &mut PreparedClientUdp,
    outbounds: &[ClientOutboundContext],
    source: SocketAddrV4,
    wire_len: usize,
    clock: &(impl Clock + ?Sized),
) -> Result<Option<usize>, UdpPlanResponseError> {
    let PreparedClientUdp {
        plans,
        manager,
        handle,
        application_wire,
        upstream_wire,
        scratch,
        ..
    } = prepared;
    let mut candidate = false;
    let mut outer_error = UdpPacketError::Binding;
    // ponytail: scan at most 128 bounded plans; add an authenticated dispatch index if measured.
    for (hops, plan) in plans.iter() {
        if outbounds
            .get(hops[0])
            .is_none_or(|outbound| outbound.udp_server != source)
        {
            continue;
        }
        candidate = true;
        let outer = match plan.legs[0].protocol.prepare_response_borrowed(
            clock,
            &upstream_wire[..wire_len],
            scratch,
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
                outer, plan, hops, outbounds, commits, manager, *handle, clock,
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
            .copy_payload_to(application_wire)
            .map_err(UdpPlanResponseError::Packet)?;
        commits.push(outer.into_commit());
        let mut wire_in_application = true;
        for layer in 1..hops.len() {
            let pending = if wire_in_application {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    clock,
                    &application_wire[..inner_len],
                    scratch,
                )
            } else {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    clock,
                    &upstream_wire[..inner_len],
                    scratch,
                )
            }
            .map_err(UdpPlanResponseError::Packet)?;
            if layer + 1 == hops.len() {
                return commit_final_udp_response(
                    pending, plan, hops, outbounds, commits, manager, *handle, clock,
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
                pending.copy_payload_to(upstream_wire)
            } else {
                pending.copy_payload_to(application_wire)
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
fn register_udp_session<K: ferrum2_crypto::MethodKeyProvider>(
    keys: &MethodKeyAdapter<K>,
    random: &(impl SecureRandom + ?Sized),
    live_ids: &std::sync::Mutex<HashSet<UdpSessionId>>,
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

async fn relay_udp_association<IO>(
    prepared: &mut PreparedClientUdp,
    control: &mut SocksStream<IO>,
    peer_ip: IpAddr,
    requested_port: u16,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    route: (usize, &ClientRouting),
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (inbound, routing) = route;
    let mut endpoint_port = (requested_port != 0).then_some(requested_port);
    let mut session_cancellation = match prepared.manager.cancellation(prepared.handle) {
        Ok(cancellation) => cancellation,
        Err(_) => return,
    };
    let mut control_byte = [0_u8; 1];
    loop {
        let idle_deadline = match prepared.manager.idle_deadline(prepared.handle) {
            Ok(deadline) => deadline,
            Err(_) => return,
        };
        tokio::select! {
            _ = cancellation.cancelled() => return,
            changed = session_cancellation.changed() => {
                let _ = changed;
                return;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                if Instant::now() >= prepared.manager.idle_deadline(prepared.handle).unwrap_or(idle_deadline) {
                    return;
                }
            }
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
            }
            received = async {
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationRecv)) {
                    return Err(io::Error::other("injected application receive failure"));
                }
                prepared.application.recv_from(&mut prepared.application_wire).await
            } => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                if source.ip() != peer_ip || endpoint_port.is_some_and(|port| port != source.port()) {
                    record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Address);
                    continue;
                }
                let decoded = match decode_udp_datagram(&prepared.application_wire[..length]) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Bounds);
                        continue;
                    }
                };
                let payload_len = decoded.payload().len();
                let encoded_target_len = decoded.encoded_target_len();
                let target = decoded.to_target_addr();
                let hops: Box<[usize]> = match &prepared.static_plan {
                    Some(plan) => plan.clone(),
                    None => routing
                        .route
                        .select_plan(inbound, Network::Udp, &target)
                        .hops()
                        .into(),
                };
                let Some(server) = hops
                    .first()
                    .and_then(|hop| routing.outbounds.get(*hop))
                    .map(|outbound| outbound.udp_server)
                else {
                    return;
                };
                if payload_len > composed_udp_plan_limit(
                    &routing.outbounds,
                    &hops,
                    false,
                    encoded_target_len,
                ) {
                    record_udp_drop(context, Direction::ClientToTarget, Stage::Shadowsocks, Reason::Bounds);
                    continue;
                }
                let reservation = match reserve_application_datagram(prepared, payload_len) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        if record_udp_runtime_error(context, Direction::ClientToTarget, error) {
                            continue;
                        }
                        return;
                    }
                };
                let payload = decoded.payload().into();
                if activate_udp_plan(prepared, context, &routing.outbounds, &hops).is_err() {
                    record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
                    return;
                }
                let datagram = Datagram::new(target, payload, payload_len)
                    .expect("validated borrowed SOCKS payload");
                let first = prepared.pending_session.is_some();
                let committed = if first {
                    prepared.pending_session.take().expect("first admission").commit(
                        reservation,
                        datagram,
                        Instant::now(),
                    )
                } else {
                    reservation
                        .commit(datagram, Instant::now())
                        .map(|()| prepared.handle)
                };
                if let Err(error) = committed {
                    if record_udp_runtime_error(context, Direction::ClientToTarget, error) {
                        continue;
                    }
                    return;
                }
                if endpoint_port.is_none() {
                    endpoint_port = Some(source.port());
                }
                let Some(datagram) = prepared.manager.pop(prepared.handle, UdpDirection::ToTarget).ok().flatten() else {
                    return;
                };
                let wire_len = match encode_udp_plan_request(
                    prepared,
                    &routing.outbounds,
                    &hops,
                    datagram.datagram(),
                    &context.clock,
                    &context.random,
                ) {
                    Ok(length) => length,
                    Err(error) => {
                        if record_udp_packet_error(
                            context,
                            Direction::ClientToTarget,
                            UdpPacketPhase::RequestEncode,
                            error,
                        ) {
                            continue;
                        }
                        return;
                    }
                };
                let Ok(send_deadline) = prepared.manager.idle_deadline(prepared.handle) else { return };
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamSend)) {
                    record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                    return;
                }
                match udp_send_with_lifecycle(
                        async {
                            match prepared.static_server {
                                Some(_) => prepared.upstream.send(&prepared.upstream_wire[..wire_len]).await,
                                None => prepared.upstream.send_to(
                                    &prepared.upstream_wire[..wire_len],
                                    SocketAddr::V4(server),
                                ).await,
                            }
                        },
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(sent) if sent == wire_len => {}
                    Ok(_) | Err(UdpSendError::Io) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                        return;
                    }
                    Err(UdpSendError::Cancelled) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
                        return;
                    }
                    Err(UdpSendError::Idle) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
                        return;
                    }
                }
                context.metrics.udp_datagram(Role::Client, Direction::ClientToTarget, Outcome::Accepted);
                context.metrics.add_udp_bytes(Role::Client, Direction::ClientToTarget, payload_len as u64);
            }
            received = async {
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamRecv)) {
                    return Err(io::Error::other("injected upstream receive failure"));
                }
                match prepared.static_server {
                    Some(server) => prepared
                        .upstream
                        .recv(&mut prepared.upstream_wire)
                        .await
                        .map(|length| (length, SocketAddr::V4(server))),
                    None => prepared.upstream.recv_from(&mut prepared.upstream_wire).await,
                }
            } => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let SocketAddr::V4(source) = source else {
                    record_udp_drop(context, Direction::TargetToClient, Stage::Shadowsocks, Reason::Address);
                    continue;
                };
                let payload_len = match accept_udp_plan_response(
                    prepared,
                    &routing.outbounds,
                    source,
                    length,
                    &context.clock,
                ) {
                    Ok(Some(payload_len)) => payload_len,
                    Ok(None) => {
                        record_udp_drop(context, Direction::TargetToClient, Stage::Shadowsocks, Reason::Address);
                        continue;
                    }
                    Err(UdpPlanResponseError::Packet(error)) => {
                        if record_udp_packet_error(
                            context,
                            Direction::TargetToClient,
                            UdpPacketPhase::ResponsePrepare,
                            error,
                        ) {
                            continue;
                        }
                        return;
                    }
                    Err(UdpPlanResponseError::Runtime(error)) => {
                        if record_udp_runtime_error(context, Direction::TargetToClient, error) {
                            continue;
                        }
                        return;
                    }
                };
                let Some(datagram) = prepared.manager.pop(prepared.handle, UdpDirection::ToClient).ok().flatten() else {
                    return;
                };
                let wire_len = match encode_udp_datagram(
                    datagram.datagram().target(),
                    datagram.datagram().payload(),
                    &mut prepared.application_wire,
                ) {
                    Ok(length) => length,
                    Err(_) => return,
                };
                let Some(port) = endpoint_port else { return };
                let endpoint = SocketAddr::new(peer_ip, port);
                let Ok(send_deadline) = prepared.manager.idle_deadline(prepared.handle) else { return };
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationSend)) {
                    record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                    return;
                }
                match udp_send_with_lifecycle(
                        prepared.application.send_to(&prepared.application_wire[..wire_len], endpoint),
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(sent) if sent == wire_len => {}
                    Ok(_) | Err(UdpSendError::Io) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                        return;
                    }
                    Err(UdpSendError::Cancelled) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
                        return;
                    }
                    Err(UdpSendError::Idle) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
                        return;
                    }
                }
                context.metrics.udp_datagram(Role::Client, Direction::TargetToClient, Outcome::Accepted);
                context.metrics.add_udp_bytes(Role::Client, Direction::TargetToClient, payload_len as u64);
            }
        }
    }
}

fn reserve_application_datagram(
    prepared: &PreparedClientUdp,
    payload_len: usize,
) -> Result<PendingUdpDatagram, UdpRuntimeError> {
    match prepared.pending_session.as_ref() {
        Some(session) => session.reserve_datagram(UdpDirection::ToTarget, payload_len),
        None => {
            prepared
                .manager
                .reserve_datagram(prepared.handle, UdpDirection::ToTarget, payload_len)
        }
    }
}

async fn udp_send_with_lifecycle(
    send: impl std::future::Future<Output = io::Result<usize>>,
    cancellation: &mut CancellationToken,
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
enum UdpSendError {
    Io,
    Cancelled,
    Idle,
}

#[cfg(test)]
fn composed_udp_request_limit(method: MethodProfile, encoded_target_len: usize) -> usize {
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
    let request =
        max_udp_payload_len_for_encoded_target(method, false, encoded_target_len, 0).unwrap_or(0);
    socks.min(request)
}

#[cfg(test)]
fn composed_udp_response_limit(method: MethodProfile, encoded_target_len: usize) -> usize {
    let socks = MAX_SOCKS_UDP_DATAGRAM_BYTES.saturating_sub(3 + encoded_target_len);
    let response =
        max_udp_payload_len_for_encoded_target(method, true, encoded_target_len, 0).unwrap_or(0);
    socks.min(response)
}

fn composed_udp_plan_limit(
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

fn record_udp_drop(context: &ClientContext, direction: Direction, stage: Stage, reason: Reason) {
    context
        .metrics
        .udp_datagram(Role::Client, direction, Outcome::Rejected);
    context.metrics.udp_failure(Role::Client, stage, reason);
}

fn record_udp_terminal(context: &ClientContext, stage: Stage, reason: Reason, outcome: Outcome) {
    context.metrics.udp_failure(Role::Client, stage, reason);
    emit_observation(Role::Client, stage, outcome, Some(reason));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpPacketPhase {
    RequestEncode,
    ResponsePrepare,
    #[cfg(test)]
    ResponseCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpPacketPolicy {
    reason: Reason,
    terminal: bool,
    replay: bool,
}

fn udp_packet_policy(phase: UdpPacketPhase, error: UdpPacketError) -> UdpPacketPolicy {
    let (reason, terminal, replay) = match (phase, error) {
        (
            _,
            UdpPacketError::Bounds
            | UdpPacketError::Authentication
            | UdpPacketError::Type
            | UdpPacketError::Timestamp
            | UdpPacketError::Address
            | UdpPacketError::Padding
            | UdpPacketError::Binding,
        ) => (
            match error {
                UdpPacketError::Bounds => Reason::Bounds,
                UdpPacketError::Authentication => Reason::Authentication,
                UdpPacketError::Type => Reason::Type,
                UdpPacketError::Timestamp => Reason::Timestamp,
                UdpPacketError::Address => Reason::Address,
                UdpPacketError::Padding => Reason::Padding,
                UdpPacketError::Binding => Reason::Binding,
                UdpPacketError::Clock
                | UdpPacketError::Duplicate
                | UdpPacketError::TooOld
                | UdpPacketError::AssociationLimit
                | UdpPacketError::Generation
                | UdpPacketError::Key
                | UdpPacketError::Random
                | UdpPacketError::Counter
                | UdpPacketError::StateUnavailable => unreachable!("outer pattern is closed"),
            },
            false,
            false,
        ),
        (_, UdpPacketError::Duplicate) => (Reason::Duplicate, false, true),
        (_, UdpPacketError::TooOld) => (Reason::TooOld, false, true),
        (_, UdpPacketError::AssociationLimit) => (Reason::SessionLimit, false, false),
        (_, UdpPacketError::Clock) => (Reason::Clock, true, false),
        (_, UdpPacketError::Key) => (Reason::Key, true, false),
        (_, UdpPacketError::Random) => (Reason::Random, true, false),
        (_, UdpPacketError::Counter) => (Reason::Counter, true, false),
        (_, UdpPacketError::Generation | UdpPacketError::StateUnavailable) => {
            (Reason::RelayIo, true, false)
        }
    };
    UdpPacketPolicy {
        reason,
        terminal,
        replay,
    }
}

fn record_udp_packet_error(
    context: &ClientContext,
    direction: Direction,
    phase: UdpPacketPhase,
    error: UdpPacketError,
) -> bool {
    let policy = udp_packet_policy(phase, error);
    record_udp_packet_metrics(&context.metrics, direction, policy);
    if policy.terminal {
        emit_observation(
            Role::Client,
            Stage::Shadowsocks,
            Outcome::Failed,
            Some(policy.reason),
        );
    } else {
        emit_observation(
            Role::Client,
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(policy.reason),
        );
    }
    !policy.terminal
}

fn record_udp_packet_metrics(metrics: &Metrics, direction: Direction, policy: UdpPacketPolicy) {
    metrics.udp_failure(Role::Client, Stage::Shadowsocks, policy.reason);
    if !policy.terminal {
        metrics.udp_datagram(Role::Client, direction, Outcome::Rejected);
    }
    if policy.replay {
        metrics.udp_replay_rejection(Role::Client, direction, policy.reason);
    }
}

fn record_udp_runtime_error(
    context: &ClientContext,
    direction: Direction,
    error: UdpRuntimeError,
) -> bool {
    let (reason, terminal) = match error {
        UdpRuntimeError::Bounds => (Reason::Bounds, false),
        UdpRuntimeError::SessionLimit => (Reason::SessionLimit, false),
        UdpRuntimeError::BufferLimit => (Reason::BufferLimit, false),
        UdpRuntimeError::QueueFull => (Reason::QueueFull, false),
        UdpRuntimeError::Counter => (Reason::Counter, true),
        UdpRuntimeError::Resolve => (Reason::Resolve, true),
        UdpRuntimeError::Send => (Reason::Send, true),
        UdpRuntimeError::Receive => (Reason::Receive, true),
        UdpRuntimeError::Idle => (Reason::Idle, true),
        UdpRuntimeError::Cancelled => (Reason::Cancelled, true),
    };
    if terminal {
        record_udp_terminal(context, Stage::Relay, reason, Outcome::Failed);
    } else {
        record_udp_drop(context, direction, Stage::Relay, reason);
    }
    !terminal
}

fn finish_relay(
    context: &ClientContext,
    framed: &TokioFramed<impl PlainDuplex>,
    result: Result<ferrum2_runtime::RelayStats, RelayFailure>,
) {
    let stats = match result {
        Ok(stats) => stats,
        Err(failure) => failure.stats,
    };
    context.metrics.add_bytes(
        Role::Client,
        Direction::InboundToOutbound,
        stats.inbound_to_outbound,
    );
    context.metrics.add_bytes(
        Role::Client,
        Direction::OutboundToInbound,
        stats.outbound_to_inbound,
    );
    match result {
        Ok(_) => {
            context
                .metrics
                .connection(Role::Client, Inbound::Socks5, Outcome::Completed);
            let (stage, outcome, reason) = framed
                .terminal()
                .map(observation_for_terminal)
                .unwrap_or((Stage::Relay, Outcome::Completed, None));
            emit_observation(Role::Client, stage, outcome, reason);
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
                emit_observation(Role::Client, stage, outcome, reason);
                if let Some(reason) = reason {
                    context.metrics.failure(Role::Client, stage, reason);
                }
            } else {
                record_failure(context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            }
        }
    }
}

#[derive(Debug)]
enum ClientOpenFailure {
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[allow(clippy::too_many_arguments)]
async fn open_chain_with_deadlines<'a, C, T, R>(
    outbounds: &'a [ClientOutboundContext],
    plan: &[usize],
    connector: &'a C,
    clock: &'a T,
    random: &'a R,
    application_target: &TargetAddr,
    deadlines: (std::time::Duration, std::time::Duration),
    #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
) -> Result<BoxedClientFlow<'a>, ClientOpenFailure>
where
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint + 'a,
    T: Clock + Sync,
    R: SecureRandom,
{
    if plan.is_empty() || plan.iter().any(|index| *index >= outbounds.len()) {
        return Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
            ConnectErrorKind::Other,
        )));
    }
    let first = &outbounds[plan[0]];
    let outbound = ClientTcpOutbound::new(
        first.tcp_server.clone(),
        &first.keys,
        connector,
        clock,
        random,
    );
    #[cfg(test)]
    let outbound = match observers {
        Some((buffer, flow)) => outbound.with_observers(buffer, flow),
        None => outbound,
    };
    let connected = tokio::time::timeout(deadlines.0, outbound.connect_server())
        .await
        .map_err(|_| {
            ClientOpenFailure::Protocol(ShadowsocksError::Connect(ConnectErrorKind::Timeout))
        })?
        .map_err(ClientOpenFailure::Protocol)?;
    tokio::time::timeout(deadlines.1, async {
        let first_target = plan
            .get(1)
            .map_or(application_target, |next| &outbounds[*next].tcp_server);
        let mut flow = connected.write_request(first_target).await?.into_boxed();
        for (position, index) in plan.iter().copied().enumerate().skip(1) {
            let hop = &outbounds[index];
            let next_target = plan
                .get(position + 1)
                .map_or(application_target, |next| &outbounds[*next].tcp_server);
            let outbound =
                ClientTcpOutbound::new(hop.tcp_server.clone(), &hop.keys, connector, clock, random);
            #[cfg(test)]
            let outbound = match observers {
                Some((buffer, flow)) => outbound.with_observers(buffer, flow),
                None => outbound,
            };
            flow = outbound
                .write_request_on(flow, next_target)
                .await?
                .into_boxed();
        }
        if plan.len() > 1 {
            std::future::poll_fn(|cx| Pin::new(&mut flow).poll_flush_plain(cx)).await?;
        }
        Ok(flow)
    })
    .await
    .map_err(|_| ClientOpenFailure::HandshakeTimeout)?
    .map_err(ClientOpenFailure::Protocol)
}

#[cfg(test)]
async fn open_with_deadlines<'a, K, C, T, R>(
    outbound: &ClientTcpOutbound<'a, K, C, T, R>,
    application_target: &TargetAddr,
    connect_timeout: std::time::Duration,
    handshake_timeout: std::time::Duration,
) -> Result<ClientFlow<'a, C::Stream, K, T>, ClientOpenFailure>
where
    K: TcpKeyProvider + Sync,
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint,
    T: Clock + Sync,
    R: SecureRandom,
{
    let connected = tokio::time::timeout(connect_timeout, outbound.connect_server())
        .await
        .map_err(|_| {
            ClientOpenFailure::Protocol(ShadowsocksError::Connect(ConnectErrorKind::Timeout))
        })?
        .map_err(ClientOpenFailure::Protocol)?;
    tokio::time::timeout(
        handshake_timeout,
        connected.write_request(application_target),
    )
    .await
    .map_err(|_| ClientOpenFailure::HandshakeTimeout)?
    .map_err(ClientOpenFailure::Protocol)
}

fn record_failure(context: &ClientContext, stage: Stage, reason: Reason, outcome: Outcome) {
    context.metrics.failure(Role::Client, stage, reason);
    emit_observation(Role::Client, stage, outcome, Some(reason));
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

pub(crate) struct TokioConnector<C> {
    inner: C,
}

impl<C> TokioConnector<C> {
    pub(crate) const fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C> Connector for TokioConnector<C>
where
    C: Connector,
    C::Stream: AbortiveClose,
{
    type Stream = TokioTransport<C::Stream>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.inner.connect(target).await.map(TokioTransport::new)
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
    use std::collections::{HashSet, VecDeque};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferrum2_core::route::{
        compile_selector_plans, compile_selector_plans_with_roots, compile_selector_route,
    };
    use ferrum2_core::selector::{
        SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan, TaggedRoute,
        TaggedRouteRule, TaggedStaticBinding,
    };
    use ferrum2_core::{ConnectError, Connector};
    use ferrum2_crypto::{
        Aes128Psk, KeySelector, MethodKeyProvider, MethodSecretKeyRef, MethodTcpSalt, RandomError,
        SinglePskProvider,
    };
    use ferrum2_runtime::OwnerSnapshot;
    use ferrum2_shadowsocks::{
        ShadowsocksTcpInbound, TcpReplayStore, TransportPhase, UDP_REPLAY_LAG, UdpReplayWindow,
        UdpServer, encode_response_first_write, max_udp_payload_len,
    };
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    use super::*;

    static ISSUED_TEST_PORTS: std::sync::LazyLock<Mutex<HashSet<u16>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

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

    enum ScriptedMode {
        Duplex(tokio::io::DuplexStream),
        Fail,
        Pending(Arc<AtomicUsize>),
        StallAfter {
            writes: usize,
            drops: Arc<AtomicUsize>,
        },
        WriteLimitAfter {
            writes: usize,
            limit: Option<usize>,
            accepted: Arc<Mutex<Vec<u8>>>,
            calls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        },
    }

    struct ScriptedIo {
        mode: ScriptedMode,
        endpoint: SocketAddrV4,
        aborts: Arc<AtomicUsize>,
    }

    impl ScriptedIo {
        fn duplex(
            inner: tokio::io::DuplexStream,
            endpoint: SocketAddrV4,
            aborts: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                mode: ScriptedMode::Duplex(inner),
                endpoint,
                aborts,
            }
        }

        fn failing() -> Self {
            Self {
                mode: ScriptedMode::Fail,
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
                aborts: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn pending(drops: Arc<AtomicUsize>, aborts: Arc<AtomicUsize>) -> Self {
            Self {
                mode: ScriptedMode::Pending(drops),
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                aborts,
            }
        }

        fn stall_after(writes: usize, drops: Arc<AtomicUsize>, aborts: Arc<AtomicUsize>) -> Self {
            Self {
                mode: ScriptedMode::StallAfter { writes, drops },
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                aborts,
            }
        }

        fn write_limit_after(
            writes: usize,
            limit: usize,
            accepted: Arc<Mutex<Vec<u8>>>,
            calls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
            aborts: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                mode: ScriptedMode::WriteLimitAfter {
                    writes,
                    limit: Some(limit),
                    accepted,
                    calls,
                    drops,
                },
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                aborts,
            }
        }
    }

    impl Drop for ScriptedIo {
        fn drop(&mut self) {
            match &self.mode {
                ScriptedMode::Pending(drops)
                | ScriptedMode::StallAfter { drops, .. }
                | ScriptedMode::WriteLimitAfter { drops, .. } => {
                    drops.fetch_add(1, Ordering::SeqCst);
                }
                ScriptedMode::Duplex(_) | ScriptedMode::Fail => {}
            }
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match &mut self.mode {
                ScriptedMode::Duplex(inner) => Pin::new(inner).poll_read(cx, buffer),
                ScriptedMode::Fail => {
                    Poll::Ready(Err(io::Error::other("transport source sentinel")))
                }
                ScriptedMode::Pending(_)
                | ScriptedMode::StallAfter { .. }
                | ScriptedMode::WriteLimitAfter { .. } => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            match &mut self.mode {
                ScriptedMode::Duplex(inner) => Pin::new(inner).poll_write(cx, source),
                ScriptedMode::Fail => {
                    Poll::Ready(Err(io::Error::other("transport source sentinel")))
                }
                ScriptedMode::Pending(_) => Poll::Pending,
                ScriptedMode::StallAfter { writes, .. } if *writes == 0 => Poll::Pending,
                ScriptedMode::StallAfter { writes, .. } => {
                    *writes -= 1;
                    Poll::Ready(Ok(source.len()))
                }
                ScriptedMode::WriteLimitAfter {
                    writes,
                    limit,
                    accepted,
                    calls,
                    ..
                } => {
                    let written = if *writes == 0 {
                        limit
                            .take()
                            .map_or(source.len(), |limit| limit.min(source.len()))
                    } else {
                        *writes -= 1;
                        source.len()
                    };
                    accepted
                        .lock()
                        .expect("accepted raw wire")
                        .extend_from_slice(&source[..written]);
                    calls.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(Ok(written))
                }
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.mode {
                ScriptedMode::Duplex(inner) => Pin::new(inner).poll_flush(cx),
                ScriptedMode::Fail => {
                    Poll::Ready(Err(io::Error::other("transport source sentinel")))
                }
                ScriptedMode::Pending(_)
                | ScriptedMode::StallAfter { .. }
                | ScriptedMode::WriteLimitAfter { .. } => Poll::Ready(Ok(())),
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.mode {
                ScriptedMode::Duplex(inner) => Pin::new(inner).poll_shutdown(cx),
                ScriptedMode::Fail => {
                    Poll::Ready(Err(io::Error::other("transport source sentinel")))
                }
                ScriptedMode::Pending(_)
                | ScriptedMode::StallAfter { .. }
                | ScriptedMode::WriteLimitAfter { .. } => Poll::Ready(Ok(())),
            }
        }
    }

    impl LocalEndpoint for ScriptedIo {
        fn local_endpoint(&self) -> SocketAddrV4 {
            self.endpoint
        }
    }

    impl AbortiveClose for ScriptedIo {
        type Error = io::Error;
        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn assert_source_free(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.get_ref().is_none());
        assert!(!format!("{error:?}").contains("sentinel"));
    }

    #[tokio::test]
    async fn adapter_contract_transport_delegates_and_redacts_all_io_failures() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001);
        let aborts = Arc::new(AtomicUsize::new(0));
        let (inner, mut peer) = tokio::io::duplex(32);
        let mut delegated =
            TokioTransport::new(ScriptedIo::duplex(inner, endpoint, Arc::clone(&aborts)));
        peer.write_all(b"abc").await.expect("peer write");
        let mut data = [0_u8; 3];
        assert_eq!(
            std::future::poll_fn(|cx| Pin::new(&mut delegated).poll_read(cx, &mut data))
                .await
                .expect("read"),
            3
        );
        assert_eq!(&data, b"abc");
        assert_eq!(delegated.local_endpoint(), endpoint);
        delegated.mark_abortive().expect("abortive delegation");
        assert_eq!(aborts.load(Ordering::SeqCst), 1);

        let mut transport = TokioTransport::new(ScriptedIo::failing());
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

    struct GateConnector {
        gate: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<TargetAddr>>>,
        stream: Mutex<Option<ScriptedIo>>,
    }

    impl Connector for GateConnector {
        type Stream = ScriptedIo;

        async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.targets
                .lock()
                .expect("connector targets")
                .push(target.clone());
            self.gate.notified().await;
            Ok(self
                .stream
                .lock()
                .expect("connector stream")
                .take()
                .expect("one connect"))
        }
    }

    struct DeadlineConnector {
        delay: Duration,
        targets: Mutex<Vec<TargetAddr>>,
        stream: Mutex<Option<TokioTransport<ScriptedIo>>>,
    }

    impl Connector for DeadlineConnector {
        type Stream = TokioTransport<ScriptedIo>;

        async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.targets
                .lock()
                .expect("deadline targets")
                .push(target.clone());
            tokio::time::sleep(self.delay).await;
            Ok(self
                .stream
                .lock()
                .expect("deadline stream")
                .take()
                .expect("one deadline connect"))
        }
    }

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
            destination.fill(0x42);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ChainObserver {
        buffers: Mutex<Vec<(BufferRole, usize, usize)>>,
        terminals: Mutex<Vec<FlowTerminal>>,
        owner_drops: AtomicUsize,
    }

    impl BufferObserver for ChainObserver {
        fn allocated(&self, role: BufferRole, limit: usize, identity: usize) {
            self.buffers
                .lock()
                .expect("chain buffers")
                .push((role, limit, identity));
        }
    }

    impl FlowObserver for ChainObserver {
        fn terminal_installed(&self, terminal: FlowTerminal) {
            self.terminals
                .lock()
                .expect("chain terminals")
                .push(terminal);
        }

        fn owner_dropped(&self) {
            self.owner_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn chain_test_setup(
        methods: [MethodProfile; 4],
        first_port: u16,
    ) -> (
        Vec<ClientOutboundContext>,
        ferrum2_core::route::RouteTable,
        ferrum2_core::selector::SelectorControl,
    ) {
        let servers: [SocketAddrV4; 4] = std::array::from_fn(|hop| {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port + hop as u16)
        });
        let psks: [ferrum2_crypto::MethodPsk; 4] = std::array::from_fn(|hop| {
            let bytes = [0x41 + hop as u8; 32];
            ferrum2_crypto::MethodPsk::try_from_slice(
                methods[hop],
                &bytes[..methods[hop].key_bytes()],
            )
            .expect("hop PSK")
        });
        let outbounds = prepare_client_outbounds(
            servers
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .into(),
            psks.into(),
        )
        .expect("checked runtime outbounds");
        let (route, selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("a", 0),
                TaggedOutbound::new("b", 1),
                TaggedOutbound::new("c", 2),
                TaggedOutbound::new("d", 3),
            ],
            &[
                TaggedPlan::new("a-b", vec![0, 1]),
                TaggedPlan::new("c-d", vec![2, 3]),
            ],
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "c-d"],
                Some("a-b"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "manual")]),
        )
        .expect("chain selector");
        (outbounds, route, selector)
    }

    async fn scripted_input(bytes: &[u8]) -> TokioTransport<ScriptedIo> {
        let (io, mut source) = tokio::io::duplex(65_536);
        source.write_all(bytes).await.expect("scripted wire");
        source.shutdown().await.expect("scripted EOF");
        TokioTransport::new(ScriptedIo::duplex(
            io,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_153),
            Arc::new(AtomicUsize::new(0)),
        ))
    }

    fn assert_two_layer_buffers(observer: &ChainObserver, label: impl std::fmt::Display) {
        let buffers = observer.buffers.lock().expect("chain buffers");
        assert_eq!(buffers.len(), 4, "{label}");
        assert_eq!(
            buffers
                .iter()
                .map(|(_, _, identity)| identity)
                .collect::<HashSet<_>>()
                .len(),
            4,
            "{label}"
        );
    }

    struct IdSequenceRandom(Mutex<VecDeque<u8>>);

    impl IdSequenceRandom {
        fn new(draws: impl IntoIterator<Item = u8>) -> Self {
            Self(Mutex::new(draws.into_iter().collect()))
        }
    }

    impl SecureRandom for IdSequenceRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
            let byte = self
                .0
                .lock()
                .expect("ID draw lock")
                .pop_front()
                .ok_or(RandomError::Unavailable)?;
            destination.fill(byte);
            Ok(())
        }
    }

    #[test]
    fn live_udp_registry_accepts_zero_through_seven_collisions_and_rejects_eight() {
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            ferrum2_crypto::MethodPsk::aes128([0x11; 16]),
        ));
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
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            ferrum2_crypto::MethodPsk::aes128([0x11; 16]),
        ));
        assert_registration_failure_rolls_back_setup(keys, &IdSequenceRandom::new([])).await;
        assert_registration_failure_rolls_back_setup(
            MethodKeyAdapter::new(MissingMethodKey),
            &FixedRandom,
        )
        .await;
    }

    fn test_datagram(target: TargetAddr, payload: &[u8]) -> Datagram {
        Datagram::new(target, payload.into(), payload.len()).expect("test datagram")
    }

    #[test]
    fn udp_packet_error_policy_is_closed_for_every_phase_and_variant() {
        let rows = [
            (UdpPacketError::Bounds, Reason::Bounds, false, false),
            (
                UdpPacketError::Authentication,
                Reason::Authentication,
                false,
                false,
            ),
            (UdpPacketError::Type, Reason::Type, false, false),
            (UdpPacketError::Clock, Reason::Clock, true, false),
            (UdpPacketError::Timestamp, Reason::Timestamp, false, false),
            (UdpPacketError::Address, Reason::Address, false, false),
            (UdpPacketError::Padding, Reason::Padding, false, false),
            (UdpPacketError::Binding, Reason::Binding, false, false),
            (UdpPacketError::Duplicate, Reason::Duplicate, false, true),
            (UdpPacketError::TooOld, Reason::TooOld, false, true),
            (
                UdpPacketError::AssociationLimit,
                Reason::SessionLimit,
                false,
                false,
            ),
            (UdpPacketError::Generation, Reason::RelayIo, true, false),
            (UdpPacketError::Key, Reason::Key, true, false),
            (UdpPacketError::Random, Reason::Random, true, false),
            (UdpPacketError::Counter, Reason::Counter, true, false),
            (
                UdpPacketError::StateUnavailable,
                Reason::RelayIo,
                true,
                false,
            ),
        ];
        for phase in [
            UdpPacketPhase::RequestEncode,
            UdpPacketPhase::ResponsePrepare,
            UdpPacketPhase::ResponseCommit,
        ] {
            for (error, reason, terminal, replay) in rows {
                assert_eq!(
                    udp_packet_policy(phase, error),
                    UdpPacketPolicy {
                        reason,
                        terminal,
                        replay,
                    },
                    "{phase:?}/{error:?}"
                );
            }
        }
    }

    #[test]
    fn real_duplicate_and_too_old_errors_update_the_closed_replay_family() {
        let mut replay = UdpReplayWindow::new();
        replay.commit(UDP_REPLAY_LAG + 1).expect("highest");
        let too_old = replay.commit(0).expect_err("too old");
        replay.commit(UDP_REPLAY_LAG).expect("fresh lower packet");
        let duplicate = replay.commit(UDP_REPLAY_LAG).expect_err("duplicate packet");
        assert_eq!(too_old, UdpPacketError::TooOld);
        assert_eq!(duplicate, UdpPacketError::Duplicate);

        let metrics = Metrics::new();
        for error in [duplicate, too_old] {
            record_udp_packet_metrics(
                &metrics,
                Direction::TargetToClient,
                udp_packet_policy(UdpPacketPhase::ResponseCommit, error),
            );
        }
        let text = metrics.encode_text().expect("metrics");
        for reason in ["duplicate", "too_old"] {
            assert!(text.contains(&format!(
                "ferrum2_udp_replay_rejections_total{{role=\"client\",direction=\"target_to_client\",reason=\"{reason}\"}} 1"
            )));
        }
    }

    #[test]
    fn metrics_render_tracks_provisional_temporary_rollback_and_closed_owners() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(
                1,
                ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES,
                ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT,
            )
            .expect("limits"),
            registry.clone(),
        );
        let metrics = Metrics::new();
        let provisional = manager.reserve_session(Instant::now()).expect("session");
        let temporary = provisional
            .reserve_datagram(UdpDirection::ToTarget, 777)
            .expect("temporary reservation");
        let live = render_client_metrics(&metrics, &registry);
        assert!(live.contains("ferrum2_udp_sessions_active{role=\"client\"} 1"));
        assert!(live.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 777"));
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
        drop(temporary);
        let rolled_back = render_client_metrics(&metrics, &registry);
        assert!(rolled_back.contains("ferrum2_udp_sessions_active{role=\"client\"} 1"));
        assert!(rolled_back.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"));
        drop(provisional);
        let closed = render_client_metrics(&metrics, &registry);
        assert!(closed.contains("ferrum2_udp_sessions_active{role=\"client\"} 0"));
        assert!(closed.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"));
    }

    #[tokio::test]
    async fn udp_send_lifecycle_covers_socket_io_session_idle_and_process_cancel() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let supervisor =
            BoundedSupervisor::new(listener, 1, Duration::from_secs(1), OwnerRegistry::new())
                .expect("supervisor");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel::<()>();
        let ready_sender = Arc::new(Mutex::new(Some(ready_sender)));
        let run_task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let ready_sender = Arc::clone(&ready_sender);
                async move {
                    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("UDP receiver");
                    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("UDP sender");
                    let (_session_sender, mut session) = tokio::sync::watch::channel(false);
                    let sent = udp_send_with_lifecycle(
                        sender.send_to(b"ok", receiver.local_addr().expect("receiver address")),
                        &mut cancellation,
                        &mut session,
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .expect("send completed");
                    assert_eq!(sent, 2);
                    let mut received = [0; 2];
                    assert_eq!(receiver.recv(&mut received).await.expect("receive"), 2);

                    let unconnected = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("unconnected UDP");
                    assert_eq!(
                        udp_send_with_lifecycle(
                            unconnected.send(b"failure"),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Io)
                    );

                    let (session_sender, mut session) = tokio::sync::watch::channel(false);
                    session_sender.send_replace(true);
                    assert_eq!(
                        udp_send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Cancelled)
                    );
                    let (_idle_sender, mut session) = tokio::sync::watch::channel(false);
                    assert_eq!(
                        udp_send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now(),
                        )
                        .await,
                        Err(UdpSendError::Idle)
                    );

                    ready_sender
                        .lock()
                        .expect("ready sender")
                        .take()
                        .expect("one handler")
                        .send(())
                        .expect("ready");
                    let (_process_sender, mut session) = tokio::sync::watch::channel(false);
                    assert_eq!(
                        udp_send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Cancelled)
                    );
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let _client = tokio::net::TcpStream::connect(address)
            .await
            .expect("start handler");
        ready_receiver.await.expect("handler ready");
        shutdown_sender.send(()).expect("shutdown");
        assert_eq!(run_task.await.expect("supervisor task"), Ok(()));
    }

    struct RunningUdpRelay {
        task: tokio::task::JoinHandle<Result<(), SupervisorError>>,
        done: tokio::sync::oneshot::Receiver<()>,
        shutdown: tokio::sync::oneshot::Sender<()>,
        _trigger: tokio::net::TcpStream,
    }

    async fn start_udp_relay(
        prepared: PreparedClientUdp,
        control: SocksStream<tokio::io::DuplexStream>,
        context: Arc<ClientContext>,
        routing: Arc<ClientRouting>,
        inbound: usize,
    ) -> RunningUdpRelay {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("relay owner listener");
        let address = listener.local_addr().expect("relay owner address");
        let supervisor = BoundedSupervisor::new(
            listener,
            1,
            Duration::from_secs(1),
            context.registry.clone(),
        )
        .expect("relay owner supervisor");
        let prepared = Arc::new(Mutex::new(Some(prepared)));
        let control = Arc::new(Mutex::new(Some(control)));
        let (done_sender, done) = tokio::sync::oneshot::channel();
        let done_sender = Arc::new(Mutex::new(Some(done_sender)));
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let mut prepared = prepared
                    .lock()
                    .expect("prepared")
                    .take()
                    .expect("one relay");
                let mut control = control
                    .lock()
                    .expect("control")
                    .take()
                    .expect("one control");
                let context = Arc::clone(&context);
                let routing = Arc::clone(&routing);
                let done_sender = Arc::clone(&done_sender);
                async move {
                    relay_udp_association(
                        &mut prepared,
                        &mut control,
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        0,
                        &mut cancellation,
                        &context,
                        (inbound, &routing),
                    )
                    .await;
                    let _ = done_sender
                        .lock()
                        .expect("done")
                        .take()
                        .expect("one done")
                        .send(());
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let trigger = tokio::net::TcpStream::connect(address)
            .await
            .expect("relay owner trigger");
        RunningUdpRelay {
            task,
            done,
            shutdown,
            _trigger: trigger,
        }
    }

    async fn finish_udp_relay(running: RunningUdpRelay) {
        tokio::time::timeout(Duration::from_secs(2), running.done)
            .await
            .expect("relay completion timeout")
            .expect("relay completion");
        running.shutdown.send(()).expect("relay owner shutdown");
        assert_eq!(running.task.await.expect("relay owner task"), Ok(()));
    }

    async fn receive_request_and_send_response(
        socket: &UdpSocket,
        server: &UdpServer,
        scratch: &mut UdpPacketScratch,
        payload: &[u8],
    ) -> SocketAddr {
        let (peer, wire, _) =
            receive_request_and_encode_response(socket, server, scratch, payload, 0).await;
        socket
            .send_to(&wire, peer)
            .await
            .expect("upstream response");
        peer
    }

    async fn receive_request_and_encode_response(
        socket: &UdpSocket,
        server: &UdpServer,
        scratch: &mut UdpPacketScratch,
        payload: &[u8],
        advance: u64,
    ) -> (SocketAddr, Vec<u8>, Vec<u8>) {
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
                .await
                .expect("upstream request timeout")
                .expect("upstream request");
        let clock = SystemClock::new();
        let random = SystemRandom;
        let pending = server
            .prepare_request(&clock, &wire[..length], scratch)
            .expect("authenticated request");
        let target = pending.datagram().target().clone();
        let (_, commit) = pending.into_parts();
        let accepted = server
            .commit_request(commit, peer, clock.monotonic_now(), &random)
            .expect("request commit");
        let response = test_datagram(target, payload);
        let mut first = Vec::new();
        let mut last = Vec::new();
        for index in 0..=advance {
            let encoded = server
                .encode_response(
                    accepted.capability(),
                    &clock,
                    &random,
                    &response,
                    0,
                    &mut wire,
                    scratch,
                )
                .expect("response encode");
            if index == 0 {
                first = wire[..encoded.wire_len()].to_vec();
            }
            if index == advance {
                last = wire[..encoded.wire_len()].to_vec();
            }
        }
        (peer, first, last)
    }

    #[tokio::test]
    async fn routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let mut upstreams = Vec::new();
        for _ in 0..5 {
            upstreams.push(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("upstream"),
            );
        }
        let servers: Vec<SocketAddrV4> = upstreams
            .iter()
            .map(|socket| match socket.local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            })
            .collect();
        let static_listen = reserve_address();
        let (static_path, mut static_config) = tagged_client_test_config(
            &[(static_listen, servers[0]), (reserve_address(), servers[1])],
            true,
        );
        static_config.inbounds.truncate(1);
        static_config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let (route, _) = compile_selector_route(
            &[TaggedInbound::new("i0", 0)],
            &[TaggedOutbound::new("o0", 0), TaggedOutbound::new("o1", 1)],
            &[SelectorDefinition::new(
                "manual",
                vec!["o0", "o1"],
                Some("o0"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("i0", "manual")]),
        )
        .expect("static selector route");
        static_config.route = route;
        let selector = static_config.selector_control();
        let static_registry = OwnerRegistry::new();
        let (static_stop, static_task) = spawn_test_client(static_config, &static_registry);
        wait_until_bound(static_listen).await;
        let first = udp_association(static_listen).await;
        selector.switch("manual", "o1").expect("switch to B");
        let second = udp_association(static_listen).await;
        let static_target =
            TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut static_wire = [0; 64];
        let length = encode_udp_datagram(&static_target, b"snapshot", &mut static_wire)
            .expect("static request");
        let mut received = [0; MAX_UDP_WIRE_LEN];
        for ((control, application, relay), upstream) in
            [(first, &upstreams[0]), (second, &upstreams[1])]
        {
            application
                .send_to(&static_wire[..length], relay)
                .await
                .expect("static association send");
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut received))
                .await
                .expect("static association timeout")
                .expect("static association snapshot");
            drop(control);
        }
        static_stop.send(()).expect("stop static client");
        assert_eq!(static_task.await.expect("static client"), Ok(()));
        std::fs::remove_file(static_path).expect("remove static config");

        let (path, context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(MethodProfile::Blake3Aes128Gcm2022)),
        );
        let targets: Vec<TargetAddr> = (0..5)
            .map(|index| {
                TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53 + index))
                    .expect("target")
            })
            .collect();
        let outbound = |server| ClientOutboundContext {
            tcp_server: TargetAddr::ipv4(server).expect("server"),
            udp_server: server,
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(
                MethodProfile::Blake3Aes128Gcm2022,
            ))),
        };
        let tags = ["o0", "o1", "o2", "o3", "o4", "o5"];
        let outbounds: [_; 6] =
            std::array::from_fn(|index| TaggedOutbound::new(tags[index], index));
        let (route, selector) = compile_selector_route(
            &[TaggedInbound::new("i1", 1)],
            &outbounds,
            &[
                SelectorDefinition::new("manual", vec!["o4", "o5"], Some("o4")),
                SelectorDefinition::new("nested", vec!["manual"], Some("manual")),
            ],
            TaggedRoute::Routed {
                rules: targets
                    .iter()
                    .enumerate()
                    .map(|(index, target)| {
                        TaggedRouteRule::new(
                            Some("i1"),
                            Some(Network::Udp),
                            Some(target.clone()),
                            Some(if index == 4 {
                                "nested"
                            } else {
                                ["o0", "o1", "o2", "o3"][index]
                            }),
                        )
                    })
                    .collect(),
                final_outbound: Some("o5"),
            },
        )
        .expect("routed selector route");
        let routing = Arc::new(ClientRouting {
            route,
            outbounds: vec![
                outbound(servers[0]),
                outbound(servers[1]),
                outbound(servers[2]),
                outbound(servers[0]),
                outbound(servers[4]),
                outbound(servers[3]),
            ],
        });
        let prepared =
            prepare_udp_association_with_bind(&context, Ipv4Addr::LOCALHOST, None, UdpSocket::bind)
                .await
                .expect("routed preparation");
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        let handle = prepared.handle;
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            1,
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let protocol_servers: Vec<UdpServer> = (0..5)
            .map(|_| UdpServer::new(&context.keys).expect("server protocol"))
            .collect();
        let udp = context.udp.as_ref().expect("UDP");
        let state = || {
            (
                udp.manager.idle_deadline(handle).expect("deadline"),
                udp.live_ids.lock().expect("IDs").len(),
                registry.snapshot(),
            )
        };
        macro_rules! reject {
            ($direction:literal, $source:expr, $wire:expr, $peer:expr, $count:expr, $label:expr) => {{
                let before = state();
                $source.send_to($wire, $peer).await.expect($label);
                wait_for_metric(&context.metrics, &format!(
                    "ferrum2_udp_datagrams_total{{role=\"client\",direction=\"{}\",outcome=\"rejected\"}} {}",
                    $direction, $count,
                )).await;
                assert_eq!(state(), before, "{} mutated state", $label);
                for socket in [&application, &upstreams[4], &upstreams[3]] {
                    let mut byte = [0];
                    assert_eq!(socket.try_recv(&mut byte).expect_err($label).kind(), io::ErrorKind::WouldBlock);
                }
            }};
        }
        let application_wrong = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("wrong source");
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let valid = encode_udp_datagram(&targets[4], b"invalid", &mut socks).expect("request");

        let request_limit =
            composed_udp_request_limit(context.udp.as_ref().expect("UDP").method, 7);
        for (index, label) in [
            "wrong-source request",
            "fragment request",
            "over-bound request",
        ]
        .into_iter()
        .enumerate()
        {
            socks[2] = u8::from(index == 1);
            let length = if index == 2 {
                encode_udp_datagram(&targets[4], &vec![0; request_limit + 1], &mut socks)
                    .expect("SOCKS-valid over-bound request")
            } else {
                valid
            };
            let source = if index == 0 {
                &application_wrong
            } else {
                &application
            };
            reject!(
                "client_to_target",
                source,
                &socks[..length],
                relay,
                index + 1,
                label
            );
        }
        socks[2] = 0;

        let budget = udp.manager.buffer_budget();
        let mut saturation = Vec::new();
        let mut available = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES - budget.reserved_bytes();
        while available != 0 {
            let capacity = available.min(MAX_UDP_WIRE_LEN);
            saturation.push(budget.reserve(capacity).expect("saturate byte budget"));
            available -= capacity;
        }
        let valid = encode_udp_datagram(&targets[4], b"saturated", &mut socks).expect("request");
        reject!(
            "client_to_target",
            &application,
            &socks[..valid],
            relay,
            4,
            "capacity rejection"
        );
        drop(saturation);

        let mut scratch: Vec<UdpPacketScratch> = (0..5).map(|_| UdpPacketScratch::new()).collect();
        for (index, target) in targets.iter().take(4).enumerate() {
            let length = encode_udp_datagram(target, &[index as u8], &mut socks).expect("request");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("send");
            let endpoint = if index == 3 { 0 } else { index };
            receive_request_and_send_response(
                &upstreams[endpoint],
                &protocol_servers[endpoint],
                &mut scratch[endpoint],
                &[index as u8],
            )
            .await;
            let received =
                tokio::time::timeout(Duration::from_secs(1), application.recv(&mut socks))
                    .await
                    .expect("response timeout")
                    .expect("response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("decode")
                    .payload(),
                &[index as u8]
            );
        }
        assert_eq!(
            udp.live_ids.lock().expect("IDs").len(),
            4,
            "different concrete plans keep isolated sessions"
        );

        for (count, (target, source, advance, pre_accept, restore, tamper, label)) in [
            (0, 4, 0, false, true, false, "inactive response"),
            (0, 0, 0, false, true, true, "tampered response"),
            (1, 0, 0, false, true, false, "wrong-leg response"),
            (1, 1, 0, true, false, false, "duplicate response"),
            (2, 2, UDP_REPLAY_LAG + 1, true, false, false, "stale"),
        ]
        .into_iter()
        .enumerate()
        {
            let length = encode_udp_datagram(&targets[target], label.as_bytes(), &mut socks)
                .expect("request");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("send");
            let (peer, mut rejected, newest) = receive_request_and_encode_response(
                &upstreams[target],
                &protocol_servers[target],
                &mut scratch[target],
                label.as_bytes(),
                advance,
            )
            .await;
            if tamper {
                rejected[0] ^= 1;
            }
            if pre_accept {
                let accepted = if advance == 0 { &rejected } else { &newest };
                upstreams[target]
                    .send_to(accepted, peer)
                    .await
                    .expect("response");
                application.recv(&mut socks).await.expect("response");
            }
            reject!(
                "target_to_client",
                &upstreams[source],
                &rejected,
                peer,
                count + 1,
                label
            );
            if restore {
                upstreams[target]
                    .send_to(&newest, peer)
                    .await
                    .expect("response");
                application.recv(&mut socks).await.expect("response");
            }
        }

        let length = encode_udp_datagram(&targets[4], b"before-switch", &mut socks)
            .expect("selector request");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("selector send A");
        let (peer_a, delayed_a, _) = receive_request_and_encode_response(
            &upstreams[4],
            &protocol_servers[4],
            &mut scratch[4],
            b"before-switch",
            0,
        )
        .await;
        selector.switch("manual", "o5").expect("switch UDP leg");
        let length = encode_udp_datagram(&targets[4], b"after-switch", &mut socks)
            .expect("selector request");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("selector send B");
        receive_request_and_send_response(
            &upstreams[3],
            &protocol_servers[3],
            &mut scratch[3],
            b"after-switch",
        )
        .await;
        application.recv(&mut socks).await.expect("B response");
        upstreams[4]
            .send_to(&delayed_a, peer_a)
            .await
            .expect("delayed A response");
        application
            .recv(&mut socks)
            .await
            .expect("captured A response");
        assert_eq!(udp.live_ids.lock().expect("IDs").len(), 6);

        drop(peer);
        finish_udp_relay(running).await;
        assert!(udp.live_ids.lock().expect("IDs").is_empty());
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn concrete_udp_socket_faults_release_every_owner_and_endpoint() {
        for (operation, fail_at) in [
            (UdpIoOperation::ApplicationRecv, 3),
            (UdpIoOperation::ApplicationSend, 2),
            (UdpIoOperation::UpstreamRecv, 3),
            (UdpIoOperation::UpstreamSend, 2),
        ] {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream server socket");
            let server_address = match upstream.local_addr().expect("upstream address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            };
            let (path, context) = udp_test_context_for_server(registry.clone(), server_address);
            let mut prepared = prepare_udp_association_with_bind(
                &context,
                Ipv4Addr::LOCALHOST,
                Some((Box::from([0]), server_address)),
                UdpSocket::bind,
            )
            .await
            .expect("prepared concrete relay");
            let relay = prepared.application.local_addr().expect("relay address");
            let upstream_client = prepared.upstream.local_addr().expect("upstream client");
            prepared.io_fault = Some(Arc::new(UdpIoFaultPlan::new(operation, fail_at)));
            let server = UdpServer::new(&context.keys).expect("protocol server");
            let (association, peer) = parsed_udp_association().await;
            let running = start_udp_relay(
                prepared,
                association.control,
                Arc::clone(&context),
                Arc::new(test_routing(server_address, default_test_psk())),
                0,
            )
            .await;
            drop(association.reply);
            let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("application socket");
            let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
            let mut socks = [0; 128];
            let request_len =
                encode_udp_datagram(&target, b"first", &mut socks).expect("first request");
            application
                .send_to(&socks[..request_len], relay)
                .await
                .expect("first application send");
            let mut scratch = UdpPacketScratch::new();
            receive_request_and_send_response(&upstream, &server, &mut scratch, b"first-response")
                .await;
            let mut response = [0; 128];
            tokio::time::timeout(Duration::from_secs(2), application.recv(&mut response))
                .await
                .expect("first response timeout")
                .expect("first response");

            if matches!(
                operation,
                UdpIoOperation::ApplicationSend | UdpIoOperation::UpstreamSend
            ) {
                let request_len =
                    encode_udp_datagram(&target, b"second", &mut socks).expect("second request");
                application
                    .send_to(&socks[..request_len], relay)
                    .await
                    .expect("second application send");
                if operation == UdpIoOperation::ApplicationSend {
                    receive_request_and_send_response(
                        &upstream,
                        &server,
                        &mut scratch,
                        b"second-response",
                    )
                    .await;
                }
            }
            finish_udp_relay(running).await;
            drop(peer);
            let expected_reason = if matches!(
                operation,
                UdpIoOperation::ApplicationRecv | UdpIoOperation::UpstreamRecv
            ) {
                "receive"
            } else {
                "send"
            };
            let metrics = context.metrics.encode_text().expect("metrics");
            assert!(metrics.contains(&format!(
                "ferrum2_udp_failures_total{{role=\"client\",stage=\"relay\",reason=\"{expected_reason}\"}} 1"
            )), "{operation:?}: {metrics}");
            let udp = context.udp.as_ref().expect("UDP context");
            assert_eq!(udp.manager.session_count(), 0, "{operation:?}");
            assert_eq!(
                udp.manager.buffer_budget().reserved_bytes(),
                0,
                "{operation:?}"
            );
            assert!(
                udp.live_ids.lock().expect("live IDs").is_empty(),
                "{operation:?}"
            );
            assert_eq!(registry.snapshot(), baseline, "{operation:?}");
            drop(UdpSocket::bind(relay).await.expect("relay rebind"));
            drop(
                UdpSocket::bind(upstream_client)
                    .await
                    .expect("upstream client rebind"),
            );
            std::fs::remove_file(path).expect("remove config");
        }
    }

    async fn wait_for_metric(metrics: &Metrics, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let text = metrics.encode_text().expect("metrics");
            if text.contains(needle) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "metric not observed: {needle}\n{text}"
            );
            tokio::task::yield_now().await;
        }
    }

    fn psk_for_method(method: MethodProfile) -> ferrum2_crypto::MethodPsk {
        match method {
            MethodProfile::Blake3Aes128Gcm2022 => ferrum2_crypto::MethodPsk::aes128([0x31; 16]),
            MethodProfile::Blake3Aes256Gcm2022 => ferrum2_crypto::MethodPsk::aes256([0x32; 32]),
            MethodProfile::Blake3ChaCha20Poly13052022 => {
                ferrum2_crypto::MethodPsk::chacha20_poly1305([0x33; 32])
            }
        }
    }

    fn other_psk_for_method(method: MethodProfile) -> ferrum2_crypto::MethodPsk {
        match method {
            MethodProfile::Blake3Aes128Gcm2022 => ferrum2_crypto::MethodPsk::aes128([0xa1; 16]),
            MethodProfile::Blake3Aes256Gcm2022 => ferrum2_crypto::MethodPsk::aes256([0xa2; 32]),
            MethodProfile::Blake3ChaCha20Poly13052022 => {
                ferrum2_crypto::MethodPsk::chacha20_poly1305([0xa3; 32])
            }
        }
    }

    #[tokio::test]
    async fn composed_udp_boundaries_are_real_and_sequential_for_every_method_and_target() {
        let targets = [
            (
                "IPv4",
                TargetAddr::ipv4("192.0.2.1:53".parse().expect("IPv4")).expect("target"),
                7,
            ),
            (
                "IPv6",
                TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
                19,
            ),
            (
                "domain",
                TargetAddr::domain("example.test", 53).expect("domain"),
                16,
            ),
        ];
        for method in MethodProfile::ALL {
            for (kind, target, target_len) in &targets {
                let label = format!("{method:?}/{kind}");
                let registry = OwnerRegistry::new();
                let baseline = registry.snapshot();
                let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("upstream socket");
                let server_address = match upstream.local_addr().expect("upstream address") {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
                };
                let (path, context) = udp_test_context_for_psk(
                    registry.clone(),
                    server_address,
                    Some(psk_for_method(method)),
                );
                let prepared = prepare_udp_association_with_bind(
                    &context,
                    Ipv4Addr::LOCALHOST,
                    Some((Box::from([0]), server_address)),
                    UdpSocket::bind,
                )
                .await
                .expect("prepared relay");
                let relay = prepared.application.local_addr().expect("relay address");
                let handle = prepared.handle;
                let manager = prepared.manager.clone();
                let (association, peer) = parsed_udp_association().await;
                let running = start_udp_relay(
                    prepared,
                    association.control,
                    Arc::clone(&context),
                    Arc::new(test_routing(server_address, psk_for_method(method))),
                    0,
                )
                .await;
                drop(association.reply);
                let source_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("source A");
                let source_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("source B");
                let owner_deadline = Instant::now() + Duration::from_secs(2);
                while registry.snapshot().active_supervisor_children != 1 {
                    assert!(
                        Instant::now() < owner_deadline,
                        "relay owner startup: {label}"
                    );
                    tokio::task::yield_now().await;
                }
                let request_limit = composed_udp_request_limit(method, *target_len);
                assert_eq!(
                    request_limit,
                    max_udp_payload_len(method, false, target, 0).expect("request limit"),
                    "Shadowsocks is the request bound for {label}"
                );
                let stable_before = registry.snapshot();
                let deadline_before = manager.idle_deadline(handle).expect("pending deadline");
                let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
                let one_over =
                    encode_udp_datagram(target, &vec![0xa5; request_limit + 1], &mut socks)
                        .expect("SOCKS-valid one-over request");
                source_a
                    .send_to(&socks[..one_over], relay)
                    .await
                    .expect("one-over enters concrete relay socket");
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
                )
                .await;
                assert_eq!(
                    registry.snapshot(),
                    stable_before,
                    "one-over owners: {label}"
                );
                assert_eq!(manager.session_count(), 1, "one-over session: {label}");
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(deadline_before),
                    "one-over activity: {label}"
                );
                let mut absent = [0; 1];
                assert_eq!(
                    upstream
                        .try_recv_from(&mut absent)
                        .expect_err("one-over not emitted")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                let exact_payload = vec![0x5a; request_limit];
                let exact = encode_udp_datagram(target, &exact_payload, &mut socks)
                    .expect("exact SOCKS request");
                source_b
                    .send_to(&socks[..exact], relay)
                    .await
                    .expect("exact source B request");
                let mut request_wire = [0; MAX_UDP_WIRE_LEN];
                let (request_len, upstream_client) = tokio::time::timeout(
                    Duration::from_secs(2),
                    upstream.recv_from(&mut request_wire),
                )
                .await
                .expect("exact upstream timeout")
                .expect("exact upstream request");
                let server = UdpServer::new(&context.keys).expect("protocol server");
                let clock = SystemClock::new();
                let random = SystemRandom;
                let mut scratch = UdpPacketScratch::new();
                let pending = server
                    .prepare_request(&clock, &request_wire[..request_len], &mut scratch)
                    .expect("exact authenticated request");
                assert_eq!(pending.datagram().target(), target, "target: {label}");
                assert_eq!(
                    pending.datagram().payload(),
                    exact_payload,
                    "payload: {label}"
                );
                let (_, commit) = pending.into_parts();
                let request_activity = clock.monotonic_now();
                let accepted = server
                    .commit_request(commit, upstream_client, request_activity, &random)
                    .expect("exact request commit");
                let server_snapshot = server
                    .session_snapshot(accepted.capability())
                    .expect("server snapshot")
                    .expect("server session");
                assert_eq!(
                    server_snapshot.highest_packet_id(),
                    Some(0),
                    "packet ID: {label}"
                );
                assert_eq!(server_snapshot.peer(), upstream_client, "pin: {label}");
                assert_eq!(
                    server_snapshot.last_activity(),
                    request_activity,
                    "server activity: {label}"
                );
                let committed_deadline = manager.idle_deadline(handle).expect("committed deadline");
                assert!(
                    committed_deadline >= deadline_before,
                    "request activity: {label}"
                );
                assert_eq!(
                    registry.snapshot().udp_queued_datagrams,
                    0,
                    "request queue: {label}"
                );

                let response_limit = composed_udp_response_limit(method, *target_len);
                assert_eq!(
                    response_limit,
                    max_udp_payload_len(method, true, target, 0).expect("response limit"),
                    "Shadowsocks is the response bound for {label}"
                );
                let response_payload = vec![0x6b; response_limit];
                let response = test_datagram(target.clone(), &response_payload);
                let mut response_wire = vec![0; MAX_UDP_WIRE_LEN];
                let encoded = server
                    .encode_response(
                        accepted.capability(),
                        &clock,
                        &random,
                        &response,
                        0,
                        &mut response_wire,
                        &mut scratch,
                    )
                    .expect("exact response encode");
                let response_wire_len = encoded.wire_len();
                upstream
                    .send_to(&response_wire[..response_wire_len], encoded.peer())
                    .await
                    .expect("exact response send");
                let mut emitted = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
                let emitted_len =
                    tokio::time::timeout(Duration::from_secs(2), source_b.recv(&mut emitted))
                        .await
                        .expect("SOCKS response timeout")
                        .expect("SOCKS response");
                let decoded =
                    decode_udp_datagram(&emitted[..emitted_len]).expect("SOCKS response decode");
                assert_eq!(
                    decoded.to_target_addr(),
                    *target,
                    "response target: {label}"
                );
                assert_eq!(
                    decoded.payload(),
                    response_payload,
                    "response payload: {label}"
                );
                assert_eq!(
                    emitted_len,
                    response_limit + 3 + target_len,
                    "emission bound: {label}"
                );
                if *kind == "IPv6" {
                    assert_eq!(emitted_len - response_limit, 22, "IPv6 SOCKS header");
                }
                assert_eq!(
                    source_a
                        .try_recv(&mut absent)
                        .expect_err("source A stays unpinned")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"accepted\"} 1",
                )
                .await;
                let client_deadline = manager.idle_deadline(handle).expect("response activity");
                let client_state = registry.snapshot();
                assert_eq!(
                    client_state.udp_queued_datagrams, 0,
                    "response queue: {label}"
                );
                assert_eq!(
                    client_state.udp_buffered_bytes,
                    3 * MAX_UDP_WIRE_LEN,
                    "allocation: {label}"
                );

                let oversized = test_datagram(target.clone(), &vec![0x7c; response_limit + 1]);
                assert_eq!(
                    server
                        .encode_response(
                            accepted.capability(),
                            &clock,
                            &random,
                            &oversized,
                            0,
                            &mut response_wire,
                            &mut scratch,
                        )
                        .expect_err("SS response max+1 rejected before emission"),
                    UdpPacketError::Bounds,
                    "{label}"
                );
                assert_eq!(
                    registry.snapshot(),
                    client_state,
                    "max+1 client owners: {label}"
                );
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(client_deadline),
                    "max+1 client activity: {label}"
                );
                assert_eq!(
                    source_b
                        .try_recv(&mut absent)
                        .expect_err("max+1 has no wire emission")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                upstream
                    .send_to(&response_wire[..response_wire_len], upstream_client)
                    .await
                    .expect("duplicate response send");
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_replay_rejections_total{role=\"client\",direction=\"target_to_client\",reason=\"duplicate\"} 1",
                )
                .await;
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(client_deadline),
                    "replay activity: {label}"
                );
                assert_eq!(registry.snapshot(), client_state, "replay owners: {label}");
                assert_eq!(
                    source_b
                        .try_recv(&mut absent)
                        .expect_err("replay has no emission")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                drop(peer);
                finish_udp_relay(running).await;
                assert_eq!(registry.snapshot(), baseline, "closed: {label}");
                std::fs::remove_file(path).expect("remove config");
            }
        }
    }

    async fn assert_open_pending<F>(future: &mut Pin<Box<F>>)
    where
        F: std::future::Future,
    {
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("open completed before its controlled phase"),
            _ = tokio::task::yield_now() => {}
        }
    }

    async fn run_timeout_case(
        label: &str,
        runtime: RuntimeConfig,
        connect_delay: Duration,
        handshake: bool,
        key: u8,
    ) {
        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let connector = DeadlineConnector {
            delay: connect_delay,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::pending(
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        };
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([key; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let server = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002)).expect(label);
        let outbound = ClientTcpOutbound::new(server.clone(), &keys, &connector, &clock, &random);
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect(label);
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &target,
            runtime.connect_timeout,
            runtime.handshake_timeout,
        ));
        assert_open_pending(&mut opened).await;
        if handshake {
            tokio::time::advance(connect_delay).await;
            assert_open_pending(&mut opened).await;
        }
        let timeout = if handshake {
            runtime.handshake_timeout
        } else {
            runtime.connect_timeout
        };
        tokio::time::advance(timeout - Duration::from_millis(1)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        let error = match opened.await {
            Ok(_) => panic!("{label}"),
            Err(error) => error,
        };
        assert!(
            if handshake {
                matches!(error, ClientOpenFailure::HandshakeTimeout)
            } else {
                matches!(
                    error,
                    ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                        ConnectErrorKind::Timeout
                    ))
                )
            },
            "{label}"
        );
        assert_eq!(
            connector
                .targets
                .lock()
                .expect("deadline targets")
                .as_slice(),
            &[server]
        );
        drop(outbound);
        drop(connector);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "{label}");
        assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_table_preserves_defaults_overrides_and_first_write() {
        let defaults = RuntimeConfig {
            max_connections: std::num::NonZeroU16::new(4_096).expect("non-zero"),
            listen_backlog: std::num::NonZeroU16::new(1_024).expect("non-zero"),
            handshake_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            shutdown_grace: Duration::from_secs(30),
        };
        let custom = RuntimeConfig {
            connect_timeout: Duration::from_millis(2_300),
            handshake_timeout: Duration::from_millis(3_700),
            ..defaults
        };
        let actual = [
            (defaults.connect_timeout, defaults.handshake_timeout),
            (custom.connect_timeout, custom.handshake_timeout),
        ];
        let expected = [
            (Duration::from_secs(10), Duration::from_secs(5)),
            (Duration::from_millis(2_300), Duration::from_millis(3_700)),
        ];
        assert_eq!(actual, expected);
        let cases = [
            (
                "default connect",
                defaults,
                defaults.connect_timeout + Duration::from_secs(1),
                false,
                0x11,
            ),
            (
                "fresh handshake",
                defaults,
                Duration::from_secs(9),
                true,
                0x12,
            ),
            (
                "custom connect",
                custom,
                custom.connect_timeout + Duration::from_secs(1),
                false,
                0x13,
            ),
            (
                "custom handshake",
                custom,
                Duration::from_secs(2),
                true,
                0x14,
            ),
        ];
        for (label, runtime, delay, handshake, key) in cases {
            run_timeout_case(label, runtime, delay, handshake, key).await;
        }

        let aborts = Arc::new(AtomicUsize::new(0));
        let (stream, mut peer) = tokio::io::duplex(2_048);
        let connector = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::clone(&aborts),
            )))),
        };
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x15; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = ClientTcpOutbound::new(
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002)).expect("server"),
            &keys,
            &connector,
            &clock,
            &random,
        );
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let flow = open_with_deadlines(
            &outbound,
            &target,
            custom.connect_timeout,
            custom.handshake_timeout,
        )
        .await
        .expect("first write");
        assert_eq!(
            flow.local_endpoint(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152)
        );
        let mut written = [0_u8; 2_048];
        assert!(peer.read(&mut written).await.expect("handshake wire") > 0);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tcp_chain_opens_hops_in_order_with_distinct_credentials_and_no_fallback() {
        for (case, (first_method, second_method)) in [
            (
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ),
            (
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
            ),
            (
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (outbounds, route, selector) = chain_test_setup(
                [first_method, second_method, second_method, first_method],
                42_001 + case as u16 * 10,
            );
            let application = TargetAddr::ipv4(SocketAddrV4::new(
                Ipv4Addr::new(192, 0, 2, 1),
                443 + case as u16,
            ))
            .expect("application target");
            let snapshot = route.select_plan(0, Network::Tcp, &application);
            assert_eq!(snapshot.hops(), &[0, 1], "rotation {case}");
            selector.switch("manual", "c-d").expect("switch next flow");
            assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
            let next_snapshot = route.select_plan(0, Network::Tcp, &application);
            assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
            let clock = SystemClock::new();
            let random = FixedRandom;
            for (label, plan) in [("captured", &snapshot), ("next", &next_snapshot)] {
                let [first, second] = *plan.hops() else {
                    panic!("two-hop {label} plan")
                };
                let aborts = Arc::new(AtomicUsize::new(0));
                let (stream, mut peer) = tokio::io::duplex(65_536);
                let connector = DeadlineConnector {
                    delay: Duration::ZERO,
                    targets: Mutex::new(Vec::new()),
                    stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                        stream,
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                        Arc::clone(&aborts),
                    )))),
                };
                let observer = ChainObserver::default();
                let flow = open_chain_with_deadlines(
                    &outbounds,
                    plan.hops(),
                    &connector,
                    &clock,
                    &random,
                    &application,
                    (Duration::from_secs(1), Duration::from_secs(1)),
                    Some((&observer, &observer)),
                )
                .await
                .expect("selected chain");
                assert_eq!(
                    connector.targets.lock().expect("dial targets").as_slice(),
                    &[outbounds[first].tcp_server.clone()],
                    "sole {label} raw dial: rotation {case}"
                );
                assert_two_layer_buffers(&observer, format_args!("{label}: rotation {case}"));
                drop(flow);
                assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
                let mut raw = Vec::new();
                peer.read_to_end(&mut raw).await.expect("complete raw wire");

                let outer_replay = TcpReplayStore::new(1024).expect("outer replay");
                let outer_inbound = ShadowsocksTcpInbound::new(
                    &outbounds[first].keys,
                    &clock,
                    &random,
                    &outer_replay,
                );
                let outer = outer_inbound
                    .accept_stream(scripted_input(&raw).await)
                    .await
                    .expect("configured outer credential");
                assert_eq!(
                    outer.target, outbounds[second].tcp_server,
                    "{label} first targets second: rotation {case}"
                );
                assert!(outer.initial_payload.is_empty(), "{label}: rotation {case}");
                let mut outer_stream = TokioFramed::new(outer.stream);
                let mut inner_wire = [0_u8; 4_096];
                let inner_len = outer_stream
                    .read(&mut inner_wire)
                    .await
                    .expect("authenticated inner wire");

                let inner_replay = TcpReplayStore::new(1024).expect("inner replay");
                let inner_inbound = ShadowsocksTcpInbound::new(
                    &outbounds[second].keys,
                    &clock,
                    &random,
                    &inner_replay,
                );
                let inner = inner_inbound
                    .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
                    .await
                    .expect("configured inner credential");
                assert_eq!(inner.target, application, "{label}: rotation {case}");
                assert!(inner.initial_payload.is_empty(), "{label}: rotation {case}");

                if case == 0 && label == "captured" {
                    let wrong_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
                        ferrum2_crypto::MethodPsk::aes128([0x91; 16]),
                    ));
                    for keys in [&outbounds[second].keys, &wrong_keys] {
                        let replay = TcpReplayStore::new(1024).expect("invalid replay");
                        let inbound = ShadowsocksTcpInbound::new(keys, &clock, &random, &replay);
                        assert!(
                            inbound
                                .accept_stream(scripted_input(&raw).await)
                                .await
                                .is_err(),
                            "swapped/wrong outer credential"
                        );
                    }
                    let mut truncated = raw.clone();
                    truncated.pop().expect("nonempty wire");
                    let replay = TcpReplayStore::new(1024).expect("truncated replay");
                    let inbound = ShadowsocksTcpInbound::new(
                        &outbounds[first].keys,
                        &clock,
                        &random,
                        &replay,
                    );
                    let truncated_outer = inbound
                        .accept_stream(scripted_input(&truncated).await)
                        .await
                        .expect("valid outer before truncated inner");
                    let mut truncated_stream = TokioFramed::new(truncated_outer.stream);
                    assert!(truncated_stream.read(&mut inner_wire).await.is_err());
                }
                assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}: rotation {case}");
            }
            assert_eq!(selector.selected("manual"), Ok("c-d"));
            assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
            assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_chain_failure_and_cancellation_drop_every_layer() {
        let (outbounds, route, selector) = chain_test_setup(
            [
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            42_011,
        );
        let application = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 443))
            .expect("application target");
        let snapshot = route.select_plan(0, Network::Tcp, &application);
        assert_eq!(snapshot.hops(), &[0, 1]);
        let clock = SystemClock::new();
        let random = FixedRandom;

        let calls = Arc::new(AtomicUsize::new(0));
        let unavailable = TokioConnector::new(FailingConnector {
            calls: Arc::clone(&calls),
        });
        let unavailable_observer = ChainObserver::default();
        assert!(matches!(
            open_chain_with_deadlines(
                &outbounds,
                snapshot.hops(),
                &unavailable,
                &clock,
                &random,
                &application,
                (Duration::from_secs(1), Duration::from_secs(1)),
                Some((&unavailable_observer, &unavailable_observer)),
            )
            .await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                ConnectErrorKind::Other
            )))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            unavailable_observer
                .buffers
                .lock()
                .expect("unavailable buffers")
                .is_empty()
        );
        assert_eq!(unavailable_observer.owner_drops.load(Ordering::SeqCst), 0);
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        for cancel in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let aborts = Arc::new(AtomicUsize::new(0));
            let observer = ChainObserver::default();
            let connector = DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::stall_after(
                    1,
                    Arc::clone(&drops),
                    Arc::clone(&aborts),
                )))),
            };
            let mut opened = Box::pin(open_chain_with_deadlines(
                &outbounds,
                snapshot.hops(),
                &connector,
                &clock,
                &random,
                &application,
                (Duration::from_secs(1), Duration::from_millis(10)),
                Some((&observer, &observer)),
            ));
            assert_open_pending(&mut opened).await;
            assert_two_layer_buffers(&observer, format_args!("cancel={cancel}"));
            assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 0);
            if cancel {
                drop(opened);
            } else {
                tokio::time::advance(Duration::from_millis(10)).await;
                assert!(matches!(
                    opened.await,
                    Err(ClientOpenFailure::HandshakeTimeout)
                ));
            }
            assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
            assert!(
                observer
                    .terminals
                    .lock()
                    .expect("pending terminals")
                    .is_empty()
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1, "cancel={cancel}");
            assert_eq!(aborts.load(Ordering::SeqCst), 0, "cancel={cancel}");
            assert_eq!(
                connector.targets.lock().expect("dial targets").as_slice(),
                &[outbounds[0].tcp_server.clone()],
                "cancel={cancel}"
            );
            assert_eq!(selector.selected("manual"), Ok("a-b"));
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let write_zero_wire = Arc::new(Mutex::new(Vec::new()));
        let write_zero_calls = Arc::new(AtomicUsize::new(0));
        let write_zero_observer = ChainObserver::default();
        let write_zero = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                1,
                0,
                Arc::clone(&write_zero_wire),
                Arc::clone(&write_zero_calls),
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        };
        assert!(matches!(
            open_chain_with_deadlines(
                &outbounds,
                snapshot.hops(),
                &write_zero,
                &clock,
                &random,
                &application,
                (Duration::from_secs(1), Duration::from_secs(1)),
                Some((&write_zero_observer, &write_zero_observer)),
            )
            .await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Transport(_)))
        ));
        assert_eq!(write_zero_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&write_zero_observer, "write zero");
        assert_eq!(
            write_zero_observer
                .terminals
                .lock()
                .expect("write-zero terminals")
                .len(),
            2
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
        assert_eq!(write_zero_calls.load(Ordering::SeqCst), 2);
        assert!(!write_zero_wire.lock().expect("write-zero wire").is_empty());
        assert_eq!(
            write_zero
                .targets
                .lock()
                .expect("write-zero targets")
                .as_slice(),
            &[outbounds[0].tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let partial_wire = Arc::new(Mutex::new(Vec::new()));
        let partial_calls = Arc::new(AtomicUsize::new(0));
        let partial_observer = ChainObserver::default();
        let partial = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                1,
                1,
                Arc::clone(&partial_wire),
                Arc::clone(&partial_calls),
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        };
        let partial_flow = open_chain_with_deadlines(
            &outbounds,
            snapshot.hops(),
            &partial,
            &clock,
            &random,
            &application,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some((&partial_observer, &partial_observer)),
        )
        .await
        .expect("nonzero partial raw write resumes");
        let mut partial_framed = TokioFramed::new(partial_flow);
        partial_framed
            .shutdown()
            .await
            .expect("partial recursive half-close");
        drop(partial_framed);
        assert_eq!(
            partial_calls.load(Ordering::SeqCst),
            3,
            "full initial, one-byte partial, resumed remainder"
        );
        assert_eq!(partial_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&partial_observer, "nonzero partial");
        assert!(
            partial_observer
                .terminals
                .lock()
                .expect("partial terminals")
                .is_empty()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
        assert_eq!(
            partial.targets.lock().expect("partial targets").as_slice(),
            &[outbounds[0].tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));
        let raw = partial_wire.lock().expect("partial wire").clone();
        let outer_replay = TcpReplayStore::new(1024).expect("partial outer replay");
        let outer = ShadowsocksTcpInbound::new(&outbounds[0].keys, &clock, &random, &outer_replay)
            .accept_stream(scripted_input(&raw).await)
            .await
            .expect("partial outer wire");
        assert_eq!(outer.target, outbounds[1].tcp_server);
        let mut outer_stream = TokioFramed::new(outer.stream);
        let mut inner_wire = [0_u8; 4_096];
        let inner_len = outer_stream
            .read(&mut inner_wire)
            .await
            .expect("partial inner wire");
        let inner_replay = TcpReplayStore::new(1024).expect("partial inner replay");
        let inner = ShadowsocksTcpInbound::new(&outbounds[1].keys, &clock, &random, &inner_replay)
            .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
            .await
            .expect("partial complete inner wire");
        assert_eq!(inner.target, application);
        assert!(inner.initial_payload.is_empty());

        let aborts = Arc::new(AtomicUsize::new(0));
        let detection_observer = ChainObserver::default();
        let (detection_stream, mut detection_peer) = tokio::io::duplex(65_536);
        let detection_connector = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                detection_stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::clone(&aborts),
            )))),
        };
        let detection_flow = open_chain_with_deadlines(
            &outbounds,
            snapshot.hops(),
            &detection_connector,
            &clock,
            &random,
            &application,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some((&detection_observer, &detection_observer)),
        )
        .await
        .expect("opened detection chain");
        let request_salt =
            MethodTcpSalt::try_from_slice(outbounds[0].keys.tcp_profile(), &[0x42; 32])
                .expect("outer request salt");
        let inner_request_salt =
            MethodTcpSalt::try_from_slice(outbounds[1].keys.tcp_profile(), &[0x42; 32])
                .expect("inner request salt");
        let response_salt =
            MethodTcpSalt::try_from_slice(outbounds[0].keys.tcp_profile(), &[0x43; 32])
                .expect("outer response salt");
        let inner_response_salt =
            MethodTcpSalt::try_from_slice(outbounds[1].keys.tcp_profile(), &[0x44; 32])
                .expect("inner response salt");
        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            ferrum2_crypto::MethodPsk::chacha20_poly1305([0x99; 32]),
        ));
        let invalid_inner = encode_response_first_write(
            &wrong_inner_keys,
            &inner_response_salt,
            clock.unix_seconds().expect("response time"),
            &inner_request_salt,
            b"must not reach application",
        )
        .expect("wrong-key inner response");
        let authenticated_outer = encode_response_first_write(
            &outbounds[0].keys,
            &response_salt,
            clock.unix_seconds().expect("response time"),
            &request_salt,
            &invalid_inner,
        )
        .expect("authenticated outer response");
        detection_peer
            .write_all(&authenticated_outer)
            .await
            .expect("later-hop response");
        let mut detection_framed = TokioFramed::new(detection_flow);
        let mut application_output = [0x5a_u8; 1];
        assert!(
            detection_framed
                .read(&mut application_output)
                .await
                .is_err()
        );
        assert_eq!(application_output, [0x5a]);
        drop(detection_framed);
        assert_eq!(detection_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&detection_observer, "detection");
        assert_eq!(
            detection_observer
                .terminals
                .lock()
                .expect("detection terminals")
                .as_slice(),
            &[FlowTerminal::Detection(DetectionReason::Authentication)]
        );
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
        assert_eq!(
            detection_connector
                .targets
                .lock()
                .expect("detection targets")
                .as_slice(),
            &[outbounds[0].tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        let valid_observer = ChainObserver::default();
        let (valid_stream, mut valid_peer) = tokio::io::duplex(65_536);
        let valid_connector = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                valid_stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::new(AtomicUsize::new(0)),
            )))),
        };
        let valid_flow = open_chain_with_deadlines(
            &outbounds,
            snapshot.hops(),
            &valid_connector,
            &clock,
            &random,
            &application,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some((&valid_observer, &valid_observer)),
        )
        .await
        .expect("valid open after isolated failures");
        let mut valid_framed = TokioFramed::new(valid_flow);
        valid_framed.shutdown().await.expect("recursive half-close");
        drop(valid_framed);
        assert_eq!(valid_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&valid_observer, "valid half-close");
        let mut valid_wire = Vec::new();
        valid_peer
            .read_to_end(&mut valid_wire)
            .await
            .expect("recursive raw half-close");
        assert!(!valid_wire.is_empty());
        assert_eq!(
            valid_connector
                .targets
                .lock()
                .expect("valid targets")
                .as_slice(),
            &[outbounds[0].tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));
    }

    #[tokio::test]
    async fn adapter_contract_connector_preserves_pending_target_and_endpoint() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_004);
        let requested = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388))
            .expect("configured server target");
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let (inner, _peer) = tokio::io::duplex(32);
        let connector = TokioConnector::new(GateConnector {
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            targets: Arc::clone(&targets),
            stream: Mutex::new(Some(ScriptedIo::duplex(
                inner,
                endpoint,
                Arc::new(AtomicUsize::new(0)),
            ))),
        });
        let task_target = requested.clone();
        let task = tokio::spawn(async move { connector.connect(&task_target).await });

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            targets.lock().expect("connector targets").as_slice(),
            &[requested]
        );
        assert!(!task.is_finished(), "connector Pending must be preserved");

        gate.notify_one();
        let stream = task.await.expect("connector task").expect("connected");
        assert_eq!(stream.local_endpoint(), endpoint);
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
    fn adapter_contract_observability_mapping_is_closed_and_call_site_specific() {
        let connect_cases = [
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
        ];
        for (kind, expected) in connect_cases {
            let oracle = (
                observation_for_error(ShadowsocksError::Connect(kind)),
                (Stage::Shadowsocks, Outcome::Failed, expected),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        let oracle = (
            observation_for_terminal(FlowTerminal::Normal),
            (Stage::Relay, Outcome::Completed, None),
        );
        assert_eq!(oracle.0, oracle.1);
        for (reason, expected) in detection_cases() {
            assert_eq!(reason_for_detection(reason), expected);
            let oracle = (
                observation_for_terminal(FlowTerminal::Detection(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected)),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        for (reason, expected) in [
            (ProtocolReason::Authentication, Reason::Authentication),
            (ProtocolReason::FrameBounds, Reason::FrameBounds),
            (ProtocolReason::NonceExhausted, Reason::NonceExhausted),
        ] {
            assert_eq!(reason_for_protocol(reason), expected);
            let oracle = (
                observation_for_terminal(FlowTerminal::Protocol(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected)),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            let oracle = (
                observation_for_terminal(FlowTerminal::Transport(phase)),
                (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo)),
            );
            assert_eq!(oracle.0, oracle.1);
        }
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

    struct FailingConnector {
        calls: Arc<AtomicUsize>,
    }

    impl Connector for FailingConnector {
        type Stream = ScriptedIo;

        async fn connect(&self, _target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ConnectError::new(ConnectErrorKind::Other))
        }
    }

    #[tokio::test]
    async fn local_endpoint_failure_sends_one_general_failure_and_has_no_transport() {
        let calls = Arc::new(AtomicUsize::new(0));
        let connector = TokioConnector::new(FailingConnector {
            calls: Arc::clone(&calls),
        });
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        assert!(connector.connect(&target).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (mut peer, application) = tokio::io::duplex(64);
        let peer_task = tokio::spawn(async move {
            peer.write_all(&[5, 1, 0]).await.expect("greeting");
            let mut method = [0_u8; 2];
            peer.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [5, 0]);
            peer.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .expect("request");
            let mut reply = [0_u8; 10];
            peer.read_exact(&mut reply).await.expect("failure reply");
            reply
        });
        let session = Socks5Inbound::new()
            .accept(application)
            .await
            .expect("accepted SOCKS request");
        session
            .reply
            .failed(ConnectErrorKind::Other)
            .await
            .expect("failure reply");
        assert_eq!(
            peer_task.await.expect("peer task"),
            [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    fn reserve_address() -> SocketAddrV4 {
        let mut issued = ISSUED_TEST_PORTS.lock().expect("issued test ports");
        for port in 10_000..30_000 {
            if issued.contains(&port) {
                continue;
            }
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            if let (Ok(_tcp), Ok(_udp)) = (
                std::net::TcpListener::bind(address),
                std::net::UdpSocket::bind(address),
            ) {
                issued.insert(port);
                return address;
            }
        }
        panic!("no paired test address available")
    }

    fn client_test_config(
        listen: SocketAddrV4,
        server: SocketAddrV4,
    ) -> (PathBuf, ValidatedClientConfig) {
        static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-client-composition-{}-{}.toml",
            std::process::id(),
            CONFIG_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let source = format!(
            "schema_version = 1\n[client]\nlisten = \"{listen}\"\nserver = \"{server}\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[runtime]\nshutdown_grace_ms = 0\n"
        );
        std::fs::write(&path, source).expect("client test config");
        let config = ferrum2_config::load_client(&path).expect("validated client test config");
        (path, config)
    }

    fn client_udp_test_config(
        listen: SocketAddrV4,
        server: SocketAddrV4,
    ) -> (PathBuf, ValidatedClientConfig) {
        let (path, _) = client_test_config(listen, server);
        let mut source = std::fs::read_to_string(&path).expect("client test config");
        source.push_str("[udp]\nmax_sessions = 1\nmax_buffered_bytes = 1048576\n");
        std::fs::write(&path, source).expect("client UDP test config");
        let config = ferrum2_config::load_client(&path).expect("validated client UDP config");
        (path, config)
    }

    fn client_udp_chain_test_config(
        listen: SocketAddrV4,
        servers: [SocketAddrV4; 2],
        methods: [MethodProfile; 2],
    ) -> (PathBuf, ValidatedClientConfig) {
        let (path, mut config) = client_udp_test_config(listen, servers[0]);
        config.outbounds = servers
            .map(|server| ferrum2_config::ClientOutboundConfig { server })
            .into();
        config.outbound_psks = methods.map(psk_for_method).into();
        config.route = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("outer", 0),
                TaggedOutbound::new("inner", 1),
            ],
            &[TaggedPlan::new("chain", vec![0, 1])],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "chain")]),
        )
        .expect("static chain")
        .0;
        (path, config)
    }

    fn tagged_client_test_config(
        mappings: &[(SocketAddrV4, SocketAddrV4)],
        udp: bool,
    ) -> (PathBuf, ValidatedClientConfig) {
        let (path, mut config) = if udp {
            client_udp_test_config(mappings[0].0, mappings[0].1)
        } else {
            client_test_config(mappings[0].0, mappings[0].1)
        };
        config.inbounds = mappings
            .iter()
            .map(|(listen, _)| ferrum2_config::ClientInboundConfig { listen: *listen })
            .collect();
        config.outbounds = mappings
            .iter()
            .map(|(_, server)| ferrum2_config::ClientOutboundConfig { server: *server })
            .collect();
        config.outbound_psks = (0..mappings.len())
            .map(|_| psk_for_method(MethodProfile::Blake3Aes128Gcm2022))
            .collect();
        config.route =
            ferrum2_core::route::RouteTable::static_bindings((0..mappings.len()).collect())
                .expect("bounded test mappings");
        (path, config)
    }

    fn default_test_psk() -> ferrum2_crypto::MethodPsk {
        ferrum2_crypto::MethodPsk::aes128([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    }

    fn test_routing(server: SocketAddrV4, psk: ferrum2_crypto::MethodPsk) -> ClientRouting {
        ClientRouting {
            route: ferrum2_core::route::RouteTable::static_bindings(vec![0]).expect("test route"),
            outbounds: vec![ClientOutboundContext {
                tcp_server: TargetAddr::ipv4(server).expect("server target"),
                udp_server: server,
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk)),
            }],
        }
    }

    fn active(mut snapshot: OwnerSnapshot) -> OwnerSnapshot {
        snapshot.process_root_reaps = 0;
        snapshot.process_root_rollbacks = 0;
        snapshot.process_forced_roots = 0;
        snapshot.forced_shutdowns = 0;
        snapshot.udp_forced_shutdowns = 0;
        snapshot
    }

    type TestClientTask = tokio::task::JoinHandle<Result<(), RunError>>;

    fn spawn_test_client(
        config: ValidatedClientConfig,
        registry: &OwnerRegistry,
    ) -> (tokio::sync::oneshot::Sender<()>, TestClientTask) {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_registry(config, registry.clone(), async move {
            let _ = stopped.await;
        }));
        (stop, task)
    }

    fn spawn_test_client_with_random(
        config: ValidatedClientConfig,
        registry: &OwnerRegistry,
        random: Arc<dyn SecureRandom>,
    ) -> (tokio::sync::oneshot::Sender<()>, TestClientTask) {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_registry_and_metrics_inner(
            config,
            registry.clone(),
            async move {
                let _ = stopped.await;
            },
            Arc::new(Metrics::new()),
            Some(random),
            None,
        ));
        (stop, task)
    }

    async fn socks_command(listen: SocketAddrV4, command: u8) -> (tokio::net::TcpStream, [u8; 10]) {
        let mut stream = tokio::net::TcpStream::connect(listen)
            .await
            .expect("SOCKS connect");
        stream.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [5, 0]);
        let request = if command == 3 {
            [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        } else {
            [5, command, 0, 1, 127, 0, 0, 1, 0, 80]
        };
        stream.write_all(&request).await.expect("command");
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.expect("reply");
        (stream, reply)
    }

    async fn socks_connect_port(
        listen: SocketAddrV4,
        port: u16,
    ) -> (tokio::net::TcpStream, [u8; 10]) {
        let mut stream = tokio::net::TcpStream::connect(listen)
            .await
            .expect("SOCKS connect");
        stream.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.expect("method");
        let [high, low] = port.to_be_bytes();
        stream
            .write_all(&[5, 1, 0, 1, 192, 0, 2, 1, high, low])
            .await
            .expect("request");
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.expect("reply");
        (stream, reply)
    }

    async fn udp_association(
        listen: SocketAddrV4,
    ) -> (tokio::net::TcpStream, UdpSocket, SocketAddrV4) {
        let (control, reply) = socks_command(listen, 3).await;
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application socket");
        (control, application, relay)
    }

    async fn dns_tcp_detour_once(
        listener: TcpListener,
        expected_target: SocketAddr,
        opened: Option<tokio::sync::oneshot::Sender<()>>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> usize {
        let (stream, _) = listener.accept().await.expect("DNS detour accept");
        let stream = ferrum2_runtime::RuntimeTcpStream::from_connected(stream)
            .expect("DNS detour runtime stream");
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
        let clock = SystemClock::new();
        let random = SystemRandom;
        let replay = TcpReplayStore::new(1024).expect("DNS detour replay");
        let ferrum2_core::Session {
            target,
            stream,
            initial_payload,
            ..
        } = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
            .accept(TokioTransport::new(stream))
            .await
            .expect("authenticated DNS detour");
        assert_eq!(target.as_socket_addr(), Some(expected_target));
        if let Some(opened) = opened {
            let _ = opened.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
        let mut upstream = tokio::net::TcpStream::connect(expected_target)
            .await
            .expect("DNS detour target");
        upstream
            .write_all(&initial_payload)
            .await
            .expect("DNS detour initial payload");
        let mut stream = TokioFramed::new(stream);
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        1 + usize::from(
            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok(),
        )
    }

    #[tokio::test]
    async fn dns_proxy_prepare_cancellation_awaits_owner_and_rebinds() {
        let dns = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("readiness upstream");
        let upstream_address = upstream.local_addr().expect("readiness upstream address");
        let sockets = DnsProxySockets::bind(
            vec![SocketAddr::V4(dns)],
            16,
            std::num::NonZeroU16::new(1).expect("one DNS connection"),
            Duration::from_secs(1),
        )
        .await
        .expect("prepared paired DNS sockets");
        let (resolver, owner) = TaggedResolver::new(
            vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Udp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: None,
            }],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(1).expect("one DNS query"),
            Arc::new(ferrum2_dns::SystemDnsEgress),
        )
        .expect("resolver owner handoff");
        let resolver = Arc::new(resolver);
        let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), |_, _, _| Some(0)));
        let (readiness_sender, readiness_gate) = tokio::sync::oneshot::channel();
        let root = ProcessRoot::new(move || async move {
            Ok(ClientDnsRoot {
                listeners: Some(sockets.with_proxy(proxy)),
                resolver: Some(resolver),
                owner: Some(owner),
                readiness_gate: Some(readiness_gate),
            })
        });
        let registry = OwnerRegistry::new();
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
                .expect("readiness supervisor");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            report_result(
                supervisor
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await,
            )
        });
        for _ in 0..100 {
            if registry.snapshot().active_process_roots == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.snapshot().active_process_roots, 1);
        stop.send(()).expect("cancel during readiness");
        assert_eq!(task.await.expect("readiness client join"), Ok(()));
        drop(readiness_sender);
        drop(upstream);
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        drop(
            UdpSocket::bind(dns)
                .await
                .expect("readiness DNS UDP rebind"),
        );
        drop(
            TcpListener::bind(dns)
                .await
                .expect("readiness DNS TCP rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("readiness upstream rebind"),
        );

        let first_address = SocketAddr::V4(reserve_address());
        let occupied_address = SocketAddr::V4(reserve_address());
        let occupied = TcpListener::bind(occupied_address)
            .await
            .expect("rollback occupied TCP");
        assert!(
            DnsProxySockets::bind(
                vec![first_address, occupied_address],
                8,
                std::num::NonZeroU16::new(1).expect("rollback connection"),
                Duration::from_secs(1),
            )
            .await
            .is_err(),
            "paired DNS preparation unexpectedly succeeded"
        );
        drop(
            UdpSocket::bind(first_address)
                .await
                .expect("rollback first UDP rebind"),
        );
        drop(
            TcpListener::bind(first_address)
                .await
                .expect("rollback first TCP rebind"),
        );
        drop(
            UdpSocket::bind(occupied_address)
                .await
                .expect("rollback occupied UDP rebind"),
        );
        drop(occupied);
    }

    #[tokio::test]
    async fn dns_proxy_selector_snapshot_and_no_fallback() {
        let socks = reserve_address();
        let dns = reserve_address();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("TCP DNS upstream");
        let upstream_address = upstream.local_addr().expect("TCP DNS upstream address");
        let detours = [
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("outer DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("later DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("selected dead detour"),
        ];
        let detour_addresses: [SocketAddrV4; 4] = detours.each_ref().map(|listener| match listener
            .local_addr()
            .expect("detour address")
        {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 DNS detour"),
        });
        let [outer, inner, later, dead] = detours;
        let (path, mut config) = client_test_config(socks, detour_addresses[3]);
        config.outbounds = detour_addresses
            .map(|server| ferrum2_config::ClientOutboundConfig { server })
            .into();
        config.outbound_psks = (0..4).map(|_| default_test_psk()).collect();
        let (route, selector, mut dns_roots) = compile_selector_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("outer", 0),
                TaggedOutbound::new("inner", 1),
                TaggedOutbound::new("later", 2),
                TaggedOutbound::new("dead", 3),
            ],
            &[TaggedPlan::new("chain", vec![0, 1])],
            &[SelectorDefinition::new(
                "dns-manual",
                vec!["chain", "later", "dead"],
                Some("chain"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "dead")]),
            &["dns-manual"],
        )
        .expect("DNS selector graph");
        config.route = route;
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: vec![ferrum2_config::DnsInboundConfig {
                listen: SocketAddr::V4(dns),
            }],
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Tcp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(dns_roots.remove(0)),
            }],
            route: ferrum2_core::route::ActionTable::new(Vec::new(), 0)
                .expect("selector DNS final"),
            timeout: Duration::from_millis(150),
            max_inflight: std::num::NonZeroU16::new(1).expect("selector DNS admission"),
        });

        let upstream_task = tokio::spawn(async move {
            for answer in [
                Ipv4Addr::new(203, 0, 113, 50),
                Ipv4Addr::new(203, 0, 113, 51),
            ] {
                let (mut stream, _) = upstream.accept().await.expect("TCP DNS connection");
                let length = stream.read_u16().await.expect("TCP DNS request length");
                let mut wire = vec![0_u8; usize::from(length)];
                stream.read_exact(&mut wire).await.expect("TCP DNS request");
                let request = Message::from_vec(&wire).expect("typed TCP DNS request");
                let question = request
                    .queries
                    .first()
                    .expect("one TCP DNS question")
                    .clone();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response
                    .add_query(question.clone())
                    .add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                let response = response.to_vec().expect("typed TCP DNS response");
                stream
                    .write_u16(u16::try_from(response.len()).expect("bounded TCP DNS response"))
                    .await
                    .expect("TCP DNS response length");
                stream.write_all(&response).await.expect("TCP DNS response");
            }
        });
        let outer_target = SocketAddr::V4(detour_addresses[1]);
        let (opened, opened_inner) = tokio::sync::oneshot::channel();
        let (release_inner, release) = tokio::sync::oneshot::channel();
        let outer_task = tokio::spawn(dns_tcp_detour_once(outer, outer_target, None, None));
        let inner_task = tokio::spawn(dns_tcp_detour_once(
            inner,
            upstream_address,
            Some(opened),
            Some(release),
        ));
        let later_task = tokio::spawn(dns_tcp_detour_once(later, upstream_address, None, None));
        let registry = OwnerRegistry::new();
        let metrics = Arc::new(Metrics::new());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_registry_and_metrics(
            config,
            registry.clone(),
            async move {
                let _ = stopped.await;
            },
            Arc::clone(&metrics),
        ));
        wait_until_bound(dns).await;
        let mut client = tokio::net::TcpStream::connect(dns)
            .await
            .expect("selector DNS client");
        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("selector query name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed selector query")
        };
        let write_query = async |client: &mut tokio::net::TcpStream, query: &[u8]| {
            client
                .write_u16(u16::try_from(query.len()).expect("bounded selector query"))
                .await
                .expect("selector query length");
            client.write_all(query).await.expect("selector query");
        };
        let read_response = async |client: &mut tokio::net::TcpStream| {
            let length = client.read_u16().await.expect("selector response length");
            let mut wire = vec![0_u8; usize::from(length)];
            client
                .read_exact(&mut wire)
                .await
                .expect("selector response");
            Message::from_vec(&wire).expect("typed selector response")
        };

        write_query(&mut client, &query(0x4401, "held.selector.example.")).await;
        tokio::time::timeout(Duration::from_secs(2), opened_inner)
            .await
            .expect("held chain open timeout")
            .expect("held chain opened");
        selector
            .switch("dns-manual", "later")
            .expect("switch later DNS member");
        release_inner.send(()).expect("release held chain");
        let first = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("held selector response timeout");
        assert_eq!(first.metadata.id, 0x4401);
        assert_eq!(
            first.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 50))))
        );

        write_query(&mut client, &query(0x4402, "later.selector.example.")).await;
        let second = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("later selector response timeout");
        assert_eq!(second.metadata.id, 0x4402);
        assert_eq!(
            second.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 51))))
        );

        selector
            .switch("dns-manual", "dead")
            .expect("switch selected failure");
        write_query(&mut client, &query(0x4403, "dead.selector.example.")).await;
        let failed = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("selected failure response timeout");
        assert_eq!(failed.metadata.id, 0x4403);
        assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(outer_task.await.expect("outer detour join"), 1);
        assert_eq!(inner_task.await.expect("inner detour join"), 1);
        assert_eq!(later_task.await.expect("later detour join"), 1);
        let (selected_dead, _) = tokio::time::timeout(Duration::from_secs(1), dead.accept())
            .await
            .expect("selected dead timeout")
            .expect("selected dead connection");
        drop(selected_dead);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), dead.accept())
                .await
                .is_err(),
            "selected failure retried"
        );
        upstream_task.await.expect("TCP DNS upstream join");
        let telemetry = metrics.encode_text().expect("selector metrics");
        let bootstrap_sentinel = upstream_address.to_string();
        for sentinel in [
            "held.selector.example.",
            "later.selector.example.",
            "dead.selector.example.",
            "dns-manual",
            bootstrap_sentinel.as_str(),
        ] {
            assert!(
                !telemetry.contains(sentinel),
                "DNS sentinel leaked: {sentinel}"
            );
        }
        drop(client);
        stop.send(()).expect("stop selector client");
        assert_eq!(task.await.expect("selector client join"), Ok(()));
        drop(dead);
        drop(UdpSocket::bind(dns).await.expect("selector DNS UDP rebind"));
        drop(
            TcpListener::bind(dns)
                .await
                .expect("selector DNS TCP rebind"),
        );
        for address in detour_addresses {
            drop(
                TcpListener::bind(address)
                    .await
                    .expect("selector detour rebind"),
            );
        }
        drop(
            TcpListener::bind(upstream_address)
                .await
                .expect("selector upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove selector config");
    }

    #[tokio::test]
    async fn dns_proxy_first_match_direct_and_detoured_transports() {
        let socks = reserve_address();
        let shadowsocks = reserve_address();
        let dns = reserve_address();
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("rule DNS upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("final DNS upstream"),
        ];
        let upstream_addresses = upstreams
            .each_ref()
            .map(|upstream| upstream.local_addr().expect("upstream address"));
        let (path, mut config) = client_test_config(socks, shadowsocks);
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: vec![ferrum2_config::DnsInboundConfig {
                listen: SocketAddr::V4(dns),
            }],
            servers: upstream_addresses
                .into_iter()
                .map(|address| ferrum2_config::DnsServerConfig {
                    transport: ferrum2_config::DnsTransport::Udp,
                    address,
                    server_name: None,
                    path: None,
                    detour: None,
                })
                .collect(),
            route: ferrum2_core::route::ActionTable::new(
                vec![ferrum2_core::route::ActionRule::new(
                    Some(0),
                    Some(Network::Udp),
                    Some(TargetAddr::domain("selected.example.", 53).expect("rule DNS target")),
                    0,
                )],
                1,
            )
            .expect("DNS rule and final actions"),
            timeout: Duration::from_secs(1),
            max_inflight: std::num::NonZeroU16::new(1).expect("DNS admission"),
        });
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        let upstream_tasks: Vec<_> = upstreams
            .into_iter()
            .zip([Ipv4Addr::new(192, 0, 2, 44), Ipv4Addr::new(192, 0, 2, 45)])
            .map(|(upstream, answer)| {
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    let (length, peer) =
                        upstream.recv_from(&mut request).await.expect("DNS request");
                    let request = Message::from_vec(&request[..length]).expect("typed DNS request");
                    assert_eq!(request.metadata.message_type, MessageType::Query);
                    assert_eq!(request.metadata.op_code, OpCode::Query);
                    let question = request.queries.first().expect("one question").clone();
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.metadata.recursion_available = true;
                    response
                        .add_query(question.clone())
                        .add_answer(Record::from_rdata(
                            question.name().clone(),
                            30,
                            RData::A(A(answer)),
                        ));
                    upstream
                        .send_to(&response.to_vec().expect("typed DNS response"), peer)
                        .await
                        .expect("DNS response");
                })
            })
            .collect();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS client");
        let binary_name = Name::from_labels([
            vec![0x80; 63],
            vec![0x81; 63],
            vec![0x82; 63],
            vec![0x83; 61],
        ])
        .expect("valid maximum wire name");
        assert!(binary_name.to_ascii().len() > 255);
        wait_until_bound(dns).await;
        for (id, name, expected) in [
            (
                0x1234,
                Name::from_ascii("SeLeCtEd.ExAmPlE.").expect("absolute query name"),
                Ipv4Addr::new(192, 0, 2, 44),
            ),
            (0x1235, binary_name, Ipv4Addr::new(192, 0, 2, 45)),
        ] {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(name, RecordType::A));
            let query = query.to_vec().expect("typed query");
            let mut response = [0_u8; 4096];
            client.send_to(&query, dns).await.expect("proxy query");
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                    .await
                    .expect("DNS proxy response timeout")
                    .expect("DNS proxy response");
            let response = Message::from_vec(&response[..length]).expect("typed proxy response");
            assert_eq!(response.metadata.id, id);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.op_code, OpCode::Query);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.queries.len(), 1);
            assert_eq!(
                response.answers.first().map(|record| &record.data),
                Some(&RData::A(A(expected)))
            );
        }
        for upstream_task in upstream_tasks {
            upstream_task.await.expect("upstream task");
        }
        stop.send(()).expect("stop client");
        assert_eq!(task.await.expect("client task"), Ok(()));
        drop(client);
        drop(UdpSocket::bind(dns).await.expect("DNS UDP rebind"));
        drop(TcpListener::bind(dns).await.expect("DNS TCP rebind"));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove config");

        dns_proxy_detoured_udp_with_public_associate_off().await;
    }

    async fn dns_proxy_detoured_udp_with_public_associate_off() {
        let socks = reserve_address();
        let shadowsocks_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("Shadowsocks UDP hop");
        let shadowsocks = match shadowsocks_socket
            .local_addr()
            .expect("Shadowsocks hop address")
        {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 Shadowsocks hop"),
        };
        let dns = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("detoured DNS upstream");
        let upstream_address = upstream.local_addr().expect("detoured upstream address");
        let (path, mut config) = client_test_config(socks, shadowsocks);
        config.udp = None;
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: vec![ferrum2_config::DnsInboundConfig {
                listen: SocketAddr::V4(dns),
            }],
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Udp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(ferrum2_core::route::EgressPlanHandle::direct(0)),
            }],
            route: ferrum2_core::route::ActionTable::new(Vec::new(), 0)
                .expect("detoured DNS final action"),
            timeout: Duration::from_secs(1),
            max_inflight: std::num::NonZeroU16::new(1).expect("detoured DNS admission"),
        });
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);

        let upstream_task = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            for answer in [
                Ipv4Addr::new(198, 51, 100, 41),
                Ipv4Addr::new(198, 51, 100, 42),
            ] {
                let (length, peer) = upstream
                    .recv_from(&mut wire)
                    .await
                    .expect("plain DNS query");
                let request = Message::from_vec(&wire[..length]).expect("typed detoured request");
                let question = request.queries.first().expect("detoured question").clone();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response
                    .add_query(question.clone())
                    .add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                upstream
                    .send_to(&response.to_vec().expect("typed detoured response"), peer)
                    .await
                    .expect("plain DNS response");
            }
        });

        let hop_task = tokio::spawn(async move {
            let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
            let server = UdpServer::new(&keys).expect("Shadowsocks UDP server");
            let clock = SystemClock::new();
            let random = SystemRandom;
            let mut scratch = UdpPacketScratch::new();
            let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
            let mut plain = [0_u8; 4096];
            for _ in 0..2 {
                let (length, peer) = shadowsocks_socket
                    .recv_from(&mut wire)
                    .await
                    .expect("encrypted DNS query");
                let pending = server
                    .prepare_request(&clock, &wire[..length], &mut scratch)
                    .expect("authenticated DNS query");
                assert_eq!(
                    pending.datagram().target().as_socket_addr(),
                    Some(upstream_address)
                );
                let request = pending.datagram().payload().to_vec();
                let (_, commit) = pending.into_parts();
                let accepted = server
                    .commit_request(commit, peer, clock.monotonic_now(), &random)
                    .expect("commit DNS query");
                shadowsocks_socket
                    .send_to(&request, upstream_address)
                    .await
                    .expect("forward plain DNS query");
                let (length, source) = shadowsocks_socket
                    .recv_from(&mut plain)
                    .await
                    .expect("plain DNS response");
                assert_eq!(source, upstream_address);
                let response = server
                    .encode_response(
                        accepted.capability(),
                        &clock,
                        &random,
                        &test_datagram(
                            TargetAddr::ip(upstream_address).expect("numeric DNS target"),
                            &plain[..length],
                        ),
                        0,
                        &mut wire,
                        &mut scratch,
                    )
                    .expect("encrypt DNS response");
                shadowsocks_socket
                    .send_to(&wire[..response.wire_len()], peer)
                    .await
                    .expect("encrypted DNS response");
            }
            assert_eq!(
                server.session_count().expect("DNS UDP session count"),
                1,
                "sequential DNS queries must reuse one SIP022 UDP session"
            );
        });

        wait_until_bound(socks).await;
        wait_until_bound(dns).await;
        let mut rejected = tokio::net::TcpStream::connect(socks)
            .await
            .expect("SOCKS public-off connect");
        rejected
            .write_all(&[5, 1, 0])
            .await
            .expect("SOCKS public-off greeting");
        let mut method = [0_u8; 2];
        rejected
            .read_exact(&mut method)
            .await
            .expect("SOCKS public-off method");
        rejected
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("SOCKS public-off UDP request");
        let mut reply = [0_u8; 10];
        assert!(
            rejected.read_exact(&mut reply).await.is_err() || reply[..2] != [5, 0],
            "internal DNS enabled public UDP"
        );
        drop(rejected);

        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("absolute detoured name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed detoured query")
        };
        let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("detoured UDP client");
        let udp_query = query(0x2201, "udp.detoured.example.");
        let mut response = [0_u8; 4096];
        udp_client
            .send_to(&udp_query, dns)
            .await
            .expect("detoured UDP query");
        let (udp_length, _) =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                .await
                .expect("detoured DNS response timeout")
                .expect("detoured DNS response");
        let udp_response =
            Message::from_vec(&response[..udp_length]).expect("detoured UDP response");
        assert_eq!(udp_response.metadata.id, 0x2201);
        assert_eq!(
            udp_response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 41))))
        );

        let mut tcp_client = tokio::net::TcpStream::connect(dns)
            .await
            .expect("detoured TCP client");
        let tcp_query = query(0x2202, "tcp.detoured.example.");
        tcp_client
            .write_u16(u16::try_from(tcp_query.len()).expect("bounded TCP query"))
            .await
            .expect("detoured TCP length");
        tcp_client
            .write_all(&tcp_query)
            .await
            .expect("detoured TCP query");
        let length = tcp_client
            .read_u16()
            .await
            .expect("detoured TCP response length");
        let mut response = vec![0_u8; usize::from(length)];
        tcp_client
            .read_exact(&mut response)
            .await
            .expect("detoured TCP response");
        let response = Message::from_vec(&response).expect("typed detoured TCP response");
        assert_eq!(response.metadata.id, 0x2202);
        assert_eq!(
            response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 42))))
        );

        upstream_task.await.expect("detoured upstream task");
        hop_task.await.expect("detoured hop task");
        stop.send(()).expect("stop detoured client");
        assert_eq!(task.await.expect("detoured client task"), Ok(()));
        drop((tcp_client, udp_client));
        drop(UdpSocket::bind(dns).await.expect("detoured DNS UDP rebind"));
        drop(
            TcpListener::bind(dns)
                .await
                .expect("detoured DNS TCP rebind"),
        );
        drop(
            UdpSocket::bind(shadowsocks)
                .await
                .expect("Shadowsocks hop rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("DNS upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove detoured config");
    }

    #[tokio::test]
    async fn dns_proxy_detour_saturation_shutdown_and_exact_rebind() {
        let socks = reserve_address();
        let hop = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stalled Shadowsocks hop");
        let shadowsocks = match hop.local_addr().expect("stalled Shadowsocks hop address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 stalled Shadowsocks hop"),
        };
        let dns = [reserve_address(), reserve_address()];
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stalled DNS upstream");
        let upstream_address = upstream.local_addr().expect("stalled upstream address");
        let (seen, mut received) = tokio::sync::oneshot::channel();
        let hop_task = tokio::spawn(async move {
            let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
            let _ = hop
                .recv_from(&mut wire)
                .await
                .expect("stalled encrypted query");
            let _ = seen.send(());
            std::future::pending::<()>().await;
        });

        let (path, mut config) = client_udp_test_config(socks, shadowsocks);
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: dns
                .into_iter()
                .map(|listen| ferrum2_config::DnsInboundConfig {
                    listen: SocketAddr::V4(listen),
                })
                .collect(),
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Udp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(ferrum2_core::route::EgressPlanHandle::direct(0)),
            }],
            route: ferrum2_core::route::ActionTable::new(Vec::new(), 0)
                .expect("stalled DNS final action"),
            timeout: Duration::from_secs(5),
            max_inflight: std::num::NonZeroU16::new(1).expect("one DNS admission"),
        });
        let registry = OwnerRegistry::new();
        let (observed, resolver) = tokio::sync::oneshot::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_registry_and_metrics_inner(
            config,
            registry.clone(),
            async move {
                let _ = stopped.await;
            },
            Arc::new(Metrics::new()),
            None,
            Some(observed),
        ));
        let (context, resolver) = resolver.await.expect("observed DNS resolver");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("saturation DNS client");
        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("absolute saturation name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed saturation query")
        };
        let first = query(0x3301, "held.detoured.example.");
        wait_until_bound(dns[0]).await;
        client
            .send_to(&first, dns[0])
            .await
            .expect("held detoured query");
        tokio::time::timeout(Duration::from_secs(1), &mut received)
            .await
            .expect("detoured hop receive timeout")
            .expect("detoured hop receive signal");
        let held = active(registry.snapshot());
        assert_eq!(held.udp_sessions, 1);
        assert_eq!(held.udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
        let dns_held = resolver.stats();
        assert_eq!(dns_held.queries, 1);
        assert_eq!(dns_held.udp_sockets, 1);
        assert_eq!(dns_held.bridge_tasks, 1);
        assert_eq!(dns_held.sessions, 1);
        assert_eq!(dns_held.queues, 4);
        assert_eq!(dns_held.buffers, 1);
        assert_eq!(
            context
                .udp
                .as_ref()
                .expect("shared DNS/public UDP manager")
                .manager
                .session_count(),
            1
        );
        let (public_control, public_reply) = socks_command(socks, 3).await;
        assert_ne!(public_reply[1], 0, "public UDP used a second manager");
        drop(public_control);
        assert_eq!(active(registry.snapshot()), held);

        let second = query(0x3302, "busy.detoured.example.");
        client
            .send_to(&second, dns[1])
            .await
            .expect("saturated DNS query");
        let mut wire = [0_u8; 4096];
        let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut wire))
            .await
            .expect("saturated response timeout")
            .expect("saturated response");
        let response = Message::from_vec(&wire[..length]).expect("typed saturated response");
        assert_eq!(response.metadata.id, 0x3302);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(active(registry.snapshot()), held);

        stop.send(()).expect("stop saturated client");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("bounded saturated shutdown")
                .expect("saturated client task"),
            Ok(())
        );
        hop_task.abort();
        assert!(
            hop_task
                .await
                .expect_err("stalled hop cancellation")
                .is_cancelled()
        );
        assert_eq!(resolver.stats(), ferrum2_dns::RuntimeStats::default());
        drop((context, resolver));
        drop((client, upstream));
        for listen in dns {
            drop(
                UdpSocket::bind(listen)
                    .await
                    .expect("saturated DNS UDP rebind"),
            );
            drop(
                TcpListener::bind(listen)
                    .await
                    .expect("saturated DNS TCP rebind"),
            );
        }
        drop(
            UdpSocket::bind(shadowsocks)
                .await
                .expect("stalled hop rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("stalled upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove saturation config");
    }

    #[tokio::test]
    async fn routed_tcp_selects_after_target_and_never_falls_back() {
        let upstreams = [
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("A"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("B"),
        ];
        let servers: Vec<SocketAddrV4> = upstreams
            .iter()
            .map(|socket| match socket.local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            })
            .collect();
        let target = TargetAddr::ipv4("192.0.2.1:80".parse().expect("target")).expect("target");
        let listens = [reserve_address(), reserve_address()];
        let mappings = [(listens[0], servers[0]), (listens[1], servers[1])];
        let (path, mut config) = tagged_client_test_config(&mappings, false);
        let dead = reserve_address();
        config
            .outbounds
            .push(ferrum2_config::ClientOutboundConfig { server: dead });
        config
            .outbound_psks
            .push(psk_for_method(MethodProfile::Blake3Aes128Gcm2022));
        let rule = |inbound, target, outbound| {
            TaggedRouteRule::new(inbound, Some(Network::Tcp), target, Some(outbound))
        };
        let (route, _) = compile_selector_route(
            &[TaggedInbound::new("i0", 0), TaggedInbound::new("i1", 1)],
            &[
                TaggedOutbound::new("o0", 0),
                TaggedOutbound::new("o1", 1),
                TaggedOutbound::new("dead", 2),
            ],
            &[SelectorDefinition::new(
                "manual",
                vec!["o0", "o1", "dead"],
                Some("o0"),
            )],
            TaggedRoute::Routed {
                rules: vec![
                    rule(Some("i1"), None, "manual"),
                    rule(None, Some(target), "manual"),
                ],
                final_outbound: Some("manual"),
            },
        )
        .expect("selector route");
        config.route = route;
        let selector = config.selector_control();
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in listens {
            wait_until_bound(listen).await;
        }
        let (mut first, reply) = socks_connect_port(listens[0], 80).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (mut first_upstream, _) = upstreams[0].accept().await.expect("selected A");
        let mut wire = [0; 256];
        assert!(
            first_upstream
                .read(&mut wire)
                .await
                .expect("initial A wire")
                > 0
        );
        while first_upstream.try_read(&mut wire).is_ok() {}
        selector.switch("manual", "o1").expect("switch to B");
        first
            .write_all(b"captured A")
            .await
            .expect("open flow write");
        assert!(
            tokio::time::timeout(Duration::from_secs(2), first_upstream.read(&mut wire))
                .await
                .expect("captured A timeout")
                .expect("captured A wire")
                > 0
        );
        for (inbound, port) in [(1, 81), (0, 80), (0, 81)] {
            let (control, reply) = socks_connect_port(listens[inbound], port).await;
            assert_eq!(&reply[..2], &[5, 0]);
            let (selected, _) = tokio::time::timeout(Duration::from_secs(2), upstreams[1].accept())
                .await
                .expect("selected B timeout")
                .expect("selected B");
            drop((control, selected));
        }
        drop((first, first_upstream));
        selector
            .switch("manual", "dead")
            .expect("switch to unavailable member");
        let (_, reply) = socks_connect_port(listens[0], 82).await;
        assert_ne!(reply[1], 0);
        assert_eq!(selector.selected("manual"), Ok("dead"));
        let fallback = tokio::join!(
            tokio::time::timeout(Duration::from_millis(50), upstreams[0].accept()),
            tokio::time::timeout(Duration::from_millis(50), upstreams[1].accept()),
        );
        assert!(fallback.0.is_err() && fallback.1.is_err());
        stop.send(()).expect("stop");
        assert_eq!(task.await.expect("client"), Ok(()));
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn tagged_tcp_uses_static_outbounds_one_process_permit_and_no_fallback() {
        let listens = [reserve_address(), reserve_address()];
        let upstreams = [
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream A"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream B"),
        ];
        let servers: [SocketAddrV4; 2] =
            std::array::from_fn(
                |index| match upstreams[index].local_addr().expect("upstream") {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
                },
            );
        let (path, mut config) =
            tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], false);
        config.runtime.max_connections = 1.try_into().expect("one connection");
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        wait_until_bound(listens[0]).await;
        wait_until_bound(listens[1]).await;

        let (first, reply) = socks_command(listens[0], 1).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (first_upstream, _) = upstreams[0].accept().await.expect("mapped upstream A");
        let second = tokio::spawn(socks_command(listens[1], 1));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstreams[1].accept())
                .await
                .is_err(),
            "second listener multiplied the process permit"
        );
        drop((first, first_upstream));
        let (second, reply) = second.await.expect("second SOCKS task");
        assert_eq!(&reply[..2], &[5, 0]);
        let (second_upstream, _) = upstreams[1].accept().await.expect("mapped upstream B");
        stop.send(()).expect("stop mapped client");
        assert_eq!(task.await.expect("mapped client"), Ok(()));
        drop((second, second_upstream));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        let shared_listens = [reserve_address(), reserve_address()];
        let (shared_path, config) =
            tagged_client_test_config(&shared_listens.map(|listen| (listen, servers[0])), false);
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in shared_listens {
            wait_until_bound(listen).await;
            let (control, reply) = socks_command(listen, 1).await;
            assert_eq!(&reply[..2], &[5, 0]);
            let (upstream, _) = upstreams[0].accept().await.expect("shared upstream");
            drop((control, upstream));
        }
        stop.send(()).expect("stop shared client");
        assert_eq!(task.await.expect("shared client"), Ok(()));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        let dead = reserve_address();
        let (dead_path, config) = tagged_client_test_config(
            &[(reserve_address(), servers[0]), (reserve_address(), dead)],
            false,
        );
        let dead_listen = config.inbounds[1].listen;
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        wait_until_bound(dead_listen).await;
        let (_, reply) = socks_command(dead_listen, 1).await;
        assert_eq!(reply[0], 5);
        assert_ne!(reply[1], 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstreams[0].accept())
                .await
                .is_err(),
            "dead referenced server fell back to live sibling"
        );
        stop.send(()).expect("stop no-fallback client");
        assert_eq!(task.await.expect("no-fallback client"), Ok(()));
        std::fs::remove_file(path).expect("remove mapped config");
        std::fs::remove_file(shared_path).expect("remove shared config");
        std::fs::remove_file(dead_path).expect("remove no-fallback config");
    }

    #[tokio::test]
    async fn udp_chain_layers_mixed_credentials_bounds_and_response_binding() {
        for methods in [
            [
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            [
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
            ],
            [
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
            ],
        ] {
            stock_udp_chain_case(methods, false).await;
        }
        udp_chain_selector_snapshots_and_cross_plan_binding().await;
    }

    async fn udp_chain_selector_snapshots_and_cross_plan_binding() {
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("shared outer A"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner B"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner C"),
        ];
        let servers: [SocketAddrV4; 3] = upstreams.each_ref().map(|socket| {
            let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                unreachable!("IPv4 upstream")
            };
            address
        });
        let methods = [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
        ];
        let tagged = [
            TaggedOutbound::new("a", 0),
            TaggedOutbound::new("b", 1),
            TaggedOutbound::new("c", 2),
        ];
        let plans = [
            TaggedPlan::new("a-b", vec![0, 1]),
            TaggedPlan::new("a-c", vec![0, 2]),
        ];

        let static_listen = reserve_address();
        let (static_path, mut static_config) = client_udp_test_config(static_listen, servers[0]);
        static_config.outbounds = servers
            .map(|server| ferrum2_config::ClientOutboundConfig { server })
            .into();
        static_config.outbound_psks = methods.map(psk_for_method).into();
        let (static_route, static_selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged,
            &plans,
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "a-c"],
                Some("a-b"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "manual")]),
        )
        .expect("static chain selector");
        static_config.route = static_route;
        static_config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let static_registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(static_config, &static_registry);
        wait_until_bound(static_listen).await;
        let first = udp_association(static_listen).await;
        static_selector
            .switch("manual", "a-c")
            .expect("switch static chain");
        let second = udp_association(static_listen).await;
        let target = TargetAddr::ipv4("192.0.2.40:53".parse().expect("target")).expect("target");
        let mut socks = [0; 64];
        let length = encode_udp_datagram(&target, b"snapshot", &mut socks).expect("request");
        let outer_keys =
            MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(methods[0])));
        let outer_server = UdpServer::new(&outer_keys).expect("outer protocol");
        let clock = SystemClock::new();
        let mut scratch = UdpPacketScratch::new();
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let mut relays = Vec::new();
        for ((control, application, relay), expected) in [(first, servers[1]), (second, servers[2])]
        {
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("static chain send");
            let received =
                tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv(&mut wire))
                    .await
                    .expect("static chain timeout")
                    .expect("static chain request");
            assert_eq!(
                outer_server
                    .prepare_request(&clock, &wire[..received], &mut scratch)
                    .expect("static outer")
                    .datagram()
                    .target(),
                &TargetAddr::ipv4(expected).expect("expected inner")
            );
            relays.push(relay);
            drop((control, application));
        }
        stop.send(()).expect("stop static selector client");
        assert_eq!(task.await.expect("static selector client"), Ok(()));
        for relay in relays {
            drop(UdpSocket::bind(relay).await.expect("static relay rebind"));
        }
        assert_eq!(active(static_registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(static_path).expect("remove static config");

        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, mut context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(methods[0])),
        );
        Arc::get_mut(&mut context)
            .expect("unique routed context")
            .udp_id_random = Some(Arc::new(IdSequenceRandom::new([0x41, 0x42, 0x43, 0x44])));
        let outbounds = prepare_client_outbounds(
            servers
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .into(),
            methods.map(psk_for_method).into(),
        )
        .expect("routed chain outbounds");
        let (route, selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged,
            &plans,
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "a-c"],
                Some("a-b"),
            )],
            TaggedRoute::Routed {
                rules: vec![TaggedRouteRule::new(
                    Some("entry"),
                    Some(Network::Udp),
                    Some(target.clone()),
                    Some("manual"),
                )],
                final_outbound: Some("a-b"),
            },
        )
        .expect("routed chain selector");
        let routing = Arc::new(ClientRouting { route, outbounds });
        let prepared =
            prepare_udp_association_with_bind(&context, Ipv4Addr::LOCALHOST, None, UdpSocket::bind)
                .await
                .expect("routed chain preparation");
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        let handle = prepared.handle;
        let manager = prepared.manager.clone();
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            0,
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("routed application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let protocol_servers = routing
            .outbounds
            .iter()
            .map(|outbound| UdpServer::new(&outbound.keys).expect("protocol server"))
            .collect::<Vec<_>>();
        let random = SystemRandom;

        application
            .send_to(&socks[..length], relay)
            .await
            .expect("routed AB send");
        let (ab_len, upstream_peer) = upstreams[0]
            .recv_from(&mut wire)
            .await
            .expect("routed AB request");
        let ab_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..ab_len], &mut scratch)
            .expect("AB outer");
        assert_eq!(
            ab_outer.datagram().target(),
            &TargetAddr::ipv4(servers[1]).expect("B target")
        );
        let ab_inner_wire = ab_outer.datagram().payload().to_vec();
        let (_, commit) = ab_outer.into_parts();
        let ab_outer = protocol_servers[0]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AB outer commit");
        let ab_inner = protocol_servers[1]
            .prepare_request(&clock, &ab_inner_wire, &mut scratch)
            .expect("AB inner");
        let (_, commit) = ab_inner.into_parts();
        let ab_inner = protocol_servers[1]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AB inner commit");

        selector
            .switch("manual", "a-c")
            .expect("switch routed chain");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("routed AC send");
        let (ac_len, _) = upstreams[0]
            .recv_from(&mut wire)
            .await
            .expect("routed AC request");
        let ac_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..ac_len], &mut scratch)
            .expect("AC outer");
        assert_eq!(
            ac_outer.datagram().target(),
            &TargetAddr::ipv4(servers[2]).expect("C target")
        );
        let ac_inner_wire = ac_outer.datagram().payload().to_vec();
        let (_, commit) = ac_outer.into_parts();
        let ac_outer = protocol_servers[0]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AC outer commit");
        let ac_inner = protocol_servers[2]
            .prepare_request(&clock, &ac_inner_wire, &mut scratch)
            .expect("AC inner");
        let (_, commit) = ac_inner.into_parts();
        let ac_inner = protocol_servers[2]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AC inner commit");

        let wrong_outer_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[0]),
        ));
        let wrong_outer_id = IdSequenceRandom::new([0x43]);
        let mut wrong_outer_client =
            UdpClientSession::new(&wrong_outer_keys, &wrong_outer_id, |_| false)
                .expect("same-ID wrong-PSK outer client");
        let wrong_outer_server = UdpServer::new(&wrong_outer_keys).expect("wrong outer server");
        let wrong_request = wrong_outer_client
            .encode_request(
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong outer request"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("wrong outer request");
        let wrong_request = wrong_outer_server
            .prepare_request(&clock, &wire[..wrong_request], &mut scratch)
            .expect("wrong outer request credential");
        let (_, commit) = wrong_request.into_parts();
        let wrong_outer_capability = wrong_outer_server
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("wrong outer request commit");
        let wrong_outer = wrong_outer_server
            .encode_response(
                wrong_outer_capability.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    b"wrong outer response",
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("same-ID wrong-PSK outer response");
        let wrong_outer = wire[..wrong_outer.wire_len()].to_vec();

        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[2]),
        ));
        let wrong_inner_id = IdSequenceRandom::new([0x44]);
        let mut wrong_inner_client =
            UdpClientSession::new(&wrong_inner_keys, &wrong_inner_id, |_| false)
                .expect("same-ID wrong-PSK inner client");
        let wrong_inner_server = UdpServer::new(&wrong_inner_keys).expect("wrong inner server");
        let wrong_request = wrong_inner_client
            .encode_request(
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong inner request"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("wrong inner request");
        let wrong_request = wrong_inner_server
            .prepare_request(&clock, &wire[..wrong_request], &mut scratch)
            .expect("wrong inner request credential");
        let (_, commit) = wrong_request.into_parts();
        let wrong_inner_capability = wrong_inner_server
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("wrong inner request commit");
        let wrong_inner = wrong_inner_server
            .encode_response(
                wrong_inner_capability.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong inner response"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("same-ID wrong-PSK inner response");
        let wrong_inner = wire[..wrong_inner.wire_len()].to_vec();

        let stable = registry.snapshot();
        let deadline = manager.idle_deadline(handle).expect("deadline");
        let live_ids = context
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .len();
        upstreams[0]
            .send_to(&wrong_outer, upstream_peer)
            .await
            .expect("wrong outer response send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 1",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            live_ids
        );
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("wrong outer response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        let wrong_inner_outer = protocol_servers[0]
            .encode_response(
                ac_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    &wrong_inner,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("correct outer wrapping wrong-PSK inner");
        let wrong_inner_outer = wire[..wrong_inner_outer.wire_len()].to_vec();
        upstreams[0]
            .send_to(&wrong_inner_outer, upstream_peer)
            .await
            .expect("wrong inner response send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 2",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            live_ids
        );
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("wrong inner response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        let correct_inner = protocol_servers[2]
            .encode_response(
                ac_inner.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"AC valid after wrong PSKs"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("fresh correct AC inner");
        let correct_inner = wire[..correct_inner.wire_len()].to_vec();
        let correct_outer = protocol_servers[0]
            .encode_response(
                ac_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    &correct_inner,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("fresh correct AC outer");
        let correct_outer = wire[..correct_outer.wire_len()].to_vec();
        upstreams[0]
            .send_to(&correct_outer, upstream_peer)
            .await
            .expect("valid-after wrong PSKs send");
        let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
            .await
            .expect("valid-after wrong PSKs timeout")
            .expect("valid-after wrong PSKs response");
        assert_eq!(
            decode_udp_datagram(&socks[..received])
                .expect("valid-after wrong PSKs SOCKS response")
                .payload(),
            b"AC valid after wrong PSKs"
        );

        let encoded = protocol_servers[1]
            .encode_response(
                ab_inner.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"AB"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("AB inner response");
        let ab_response = wire[..encoded.wire_len()].to_vec();
        let crossed = protocol_servers[0]
            .encode_response(
                ab_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("crossed C target"),
                    &ab_response,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("cross-plan wrapper");
        let stable = registry.snapshot();
        let deadline = manager.idle_deadline(handle).expect("deadline");
        upstreams[0]
            .send_to(&wire[..crossed.wire_len()], upstream_peer)
            .await
            .expect("cross-plan response");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 3",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("cross-plan response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(selector.selected("manual"), Ok("a-c"));

        let selected_payload = b"AC remains selected after rejection";
        let selected_length = encode_udp_datagram(&target, selected_payload, &mut socks)
            .expect("post-rejection routed request");
        application
            .send_to(&socks[..selected_length], relay)
            .await
            .expect("post-rejection routed send");
        let (selected_wire_len, _) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("post-rejection outer A timeout")
                .expect("post-rejection outer A request");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 3",
        )
        .await;
        let selected_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..selected_wire_len], &mut scratch)
            .expect("post-rejection outer credential");
        assert_eq!(
            selected_outer.datagram().target(),
            &TargetAddr::ipv4(servers[2]).expect("C target")
        );
        let selected_inner_wire = selected_outer.datagram().payload().to_vec();
        drop(selected_outer);
        let selected_inner = protocol_servers[2]
            .prepare_request(&clock, &selected_inner_wire, &mut scratch)
            .expect("post-rejection inner credential");
        assert_eq!(selected_inner.datagram().target(), &target);
        assert_eq!(selected_inner.datagram().payload(), selected_payload);
        drop(selected_inner);
        for (socket, label) in [
            (&upstreams[0], "second outer A packet"),
            (&upstreams[1], "fallback B packet"),
            (&upstreams[2], "direct C packet"),
        ] {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut [0]))
                    .await
                    .is_err(),
                "{label} followed rejected response"
            );
        }

        for (outer, inner, next, payload) in [
            (&ab_outer, &ab_inner, servers[1], b"AB".as_slice()),
            (&ac_outer, &ac_inner, servers[2], b"AC".as_slice()),
        ] {
            let encoded = protocol_servers[if next == servers[1] { 1 } else { 2 }]
                .encode_response(
                    inner.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), payload),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("inner response");
            let inner_wire = wire[..encoded.wire_len()].to_vec();
            let encoded = protocol_servers[0]
                .encode_response(
                    outer.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(next).expect("intermediate target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("outer response");
            upstreams[0]
                .send_to(&wire[..encoded.wire_len()], upstream_peer)
                .await
                .expect("valid plan response");
            let received =
                tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
                    .await
                    .expect("plan response timeout")
                    .expect("plan response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("plan SOCKS response")
                    .payload(),
                payload
            );
        }
        assert_eq!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            4
        );
        drop(peer);
        finish_udp_relay(running).await;
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("routed relay rebind"));
        std::fs::remove_file(path).expect("remove routed config");
    }

    #[tokio::test]
    async fn udp_chain_invalid_inner_state_and_shutdown_are_atomic() {
        stock_udp_chain_case(
            [
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            true,
        )
        .await;
        eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers().await;
    }

    async fn eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let mut upstreams = Vec::new();
        for _ in 0..MAX_UDP_PLAN_HOPS {
            upstreams.push(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("eight-hop upstream"),
            );
        }
        let servers = upstreams
            .iter()
            .map(
                |socket| match socket.local_addr().expect("upstream address") {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
                },
            )
            .collect::<Vec<_>>();
        let methods = (0..MAX_UDP_PLAN_HOPS)
            .map(|hop| MethodProfile::ALL[hop % MethodProfile::ALL.len()])
            .collect::<Vec<_>>();
        let outbounds = prepare_client_outbounds(
            servers
                .iter()
                .copied()
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .collect(),
            methods.iter().copied().map(psk_for_method).collect(),
        )
        .expect("eight-hop outbounds");
        let tags = ["o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7"];
        let tagged_outbounds = tags
            .iter()
            .enumerate()
            .map(|(hop, tag)| TaggedOutbound::new(tag, hop))
            .collect::<Vec<_>>();
        let hops = (0..MAX_UDP_PLAN_HOPS).collect::<Vec<_>>();
        let (route, _) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged_outbounds,
            &[TaggedPlan::new("chain", hops.clone())],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "chain")]),
        )
        .expect("eight-hop route");
        let routing = Arc::new(ClientRouting { route, outbounds });
        let (path, context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(methods[0])),
        );
        let prepared = prepare_udp_association_with_bind(
            &context,
            Ipv4Addr::LOCALHOST,
            Some((hops.clone().into_boxed_slice(), servers[0])),
            UdpSocket::bind,
        )
        .await
        .expect("eight-hop preparation");
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        assert!(prepared.plans.is_empty());
        assert!(prepared.pending_session.is_some());
        assert_eq!(prepared._fixed_capacity.len(), 3);
        assert_eq!(
            prepared.application_wire.len(),
            MAX_SOCKS_UDP_DATAGRAM_BYTES
        );
        assert_eq!(prepared.upstream_wire.len(), MAX_UDP_WIRE_LEN);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
        let handle = prepared.handle;
        let manager = prepared.manager.clone();
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            0,
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let target =
            TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6 target")).expect("target");
        let limit = composed_udp_plan_limit(&routing.outbounds, &hops, false, 19);
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let one_over = encode_udp_datagram(&target, &vec![0x5a; limit + 1], &mut socks)
            .expect("SOCKS-valid eight-hop maximum+1");
        let stable = registry.snapshot();
        let deadline = manager.idle_deadline(handle).expect("pending deadline");
        application
            .send_to(&socks[..one_over], relay)
            .await
            .expect("maximum+1 send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(manager.session_count(), 1);
        assert!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .is_empty()
        );
        for socket in &upstreams {
            assert_eq!(
                socket
                    .try_recv(&mut [0])
                    .expect_err("maximum+1 emitted no hop")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }

        let payload = vec![0x6b; limit];
        let exact =
            encode_udp_datagram(&target, &payload, &mut socks).expect("exact eight-hop maximum");
        application
            .send_to(&socks[..exact], relay)
            .await
            .expect("exact send");
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let (wire_len, request_peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("eight-hop request timeout")
                .expect("eight-hop request");
        assert_eq!(wire_len, MAX_UDP_WIRE_LEN);
        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut nested = wire[..wire_len].to_vec();
        for layer in 0..MAX_UDP_PLAN_HOPS {
            let server = UdpServer::new(&routing.outbounds[layer].keys).expect("hop server");
            let mut scratch = UdpPacketScratch::new();
            let pending = server
                .prepare_request(&clock, &nested, &mut scratch)
                .expect("hop credential");
            let expected = if layer + 1 == MAX_UDP_PLAN_HOPS {
                target.clone()
            } else {
                TargetAddr::ipv4(servers[layer + 1]).expect("next hop")
            };
            assert_eq!(pending.datagram().target(), &expected, "hop {layer}");
            let next = pending.datagram().payload().to_vec();
            let (_, commit) = pending.into_parts();
            let accepted = server
                .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                .expect("hop commit");
            assert_eq!(
                server
                    .session_snapshot(accepted.capability())
                    .expect("hop snapshot")
                    .expect("hop session")
                    .highest_packet_id(),
                Some(0),
                "hop {layer} packet ID"
            );
            nested = next;
        }
        assert_eq!(nested, payload);
        for socket in upstreams.iter().skip(1) {
            assert_eq!(
                socket
                    .try_recv(&mut [0])
                    .expect_err("only hop A receives")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            MAX_UDP_PLAN_HOPS
        );
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);

        drop(peer);
        finish_udp_relay(running).await;
        assert!(
            context
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .is_empty()
        );
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        std::fs::remove_file(path).expect("remove config");
    }

    async fn stock_udp_chain_case(methods: [MethodProfile; 2], invalid_inner: bool) {
        let listen = reserve_address();
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("outer upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner upstream"),
        ];
        let servers: [SocketAddrV4; 2] = upstreams.each_ref().map(|socket| {
            let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                unreachable!("IPv4 upstream")
            };
            address
        });
        let (path, config) = client_udp_chain_test_config(listen, servers, methods);
        let bound_outbounds = prepare_client_outbounds(
            servers
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .into(),
            methods.map(psk_for_method).into(),
        )
        .expect("bound outbounds");
        let keys = methods.map(|method| {
            MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(method)))
        });
        let protocols = keys
            .each_ref()
            .map(|keys| UdpServer::new(keys).expect("protocol server"));
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        wait_until_bound(listen).await;
        let (control, application, relay) = udp_association(listen).await;
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let socks_len = encode_udp_datagram(&target, b"ping", &mut socks).expect("SOCKS request");
        application
            .send_to(&socks[..socks_len], relay)
            .await
            .expect("application send");

        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut scratch = UdpPacketScratch::new();
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let (outer_len, peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("outer request timeout")
                .expect("outer request");
        let outer = protocols[0]
            .prepare_request(&clock, &wire[..outer_len], &mut scratch)
            .expect("outer credential");
        let wrong_outer_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[0]),
        ));
        assert!(
            UdpServer::new(&wrong_outer_keys)
                .expect("wrong outer server")
                .prepare_request(&clock, &wire[..outer_len], &mut scratch)
                .is_err(),
            "wrong outer PSK authenticated"
        );
        assert_eq!(
            outer.datagram().target(),
            &TargetAddr::ipv4(servers[1]).expect("inner target")
        );
        let inner_wire = outer.datagram().payload().to_vec();
        let (_, outer_commit) = outer.into_parts();
        let outer_accepted = protocols[0]
            .commit_request(outer_commit, peer, clock.monotonic_now(), &random)
            .expect("outer commit");
        let inner = protocols[1]
            .prepare_request(&clock, &inner_wire, &mut scratch)
            .expect("inner credential");
        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[1]),
        ));
        assert!(
            UdpServer::new(&wrong_inner_keys)
                .expect("wrong inner server")
                .prepare_request(&clock, &inner_wire, &mut scratch)
                .is_err(),
            "wrong inner PSK authenticated"
        );
        assert_eq!(inner.datagram().target(), &target);
        assert_eq!(inner.datagram().payload(), b"ping");
        assert_eq!(
            upstreams[1]
                .try_recv(&mut [0])
                .expect_err("only first hop receives network traffic")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let (_, inner_commit) = inner.into_parts();
        let inner_accepted = protocols[1]
            .commit_request(inner_commit, peer, clock.monotonic_now(), &random)
            .expect("inner commit");

        let inner_response = protocols[1]
            .encode_response(
                inner_accepted.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"pong"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("inner response");
        let inner_wire = wire[..inner_response.wire_len()].to_vec();
        if invalid_inner {
            let stable = active(registry.snapshot());
            let wrong_intermediate = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), &inner_wire),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("wrong intermediate wrapper");
            upstreams[0]
                .send_to(&wire[..wrong_intermediate.wire_len()], peer)
                .await
                .expect("wrong intermediate send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "wrong intermediate reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let mut tampered = inner_wire.clone();
            *tampered.last_mut().expect("inner wire") ^= 1;
            let invalid_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &tampered,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("invalid inner wrapper");
            upstreams[0]
                .send_to(&wire[..invalid_outer.wire_len()], peer)
                .await
                .expect("invalid response send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "invalid inner reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let outer_tamper = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("outer tamper wrapper");
            let mut outer_tamper = wire[..outer_tamper.wire_len()].to_vec();
            *outer_tamper.last_mut().expect("outer wire") ^= 1;
            upstreams[0]
                .send_to(&outer_tamper, peer)
                .await
                .expect("outer tamper send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "tampered outer reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);
        }
        let outer_response = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &inner_wire,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("outer response");
        upstreams[0]
            .send_to(&wire[..outer_response.wire_len()], peer)
            .await
            .expect("outer response send");
        let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
            .await
            .expect("application response timeout")
            .expect("application response");
        let response = decode_udp_datagram(&socks[..received]).expect("SOCKS response");
        assert_eq!(response.to_target_addr(), target);
        assert_eq!(response.payload(), b"pong");

        if invalid_inner {
            let stable = active(registry.snapshot());
            upstreams[0]
                .send_to(&wire[..outer_response.wire_len()], peer)
                .await
                .expect("outer replay send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "outer replay reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let fresh_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("fresh outer replayed inner");
            upstreams[0]
                .send_to(&wire[..fresh_outer.wire_len()], peer)
                .await
                .expect("fresh outer send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "fresh outer replayed inner reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let next_inner = protocols[1]
                .encode_response(
                    inner_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), b"next"),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("next inner response");
            let next_inner = wire[..next_inner.wire_len()].to_vec();
            let next_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &next_inner,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("next outer response");
            upstreams[0]
                .send_to(&wire[..next_outer.wire_len()], peer)
                .await
                .expect("next response send");
            let received =
                tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
                    .await
                    .expect("next response timeout")
                    .expect("next response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("next SOCKS response")
                    .payload(),
                b"next"
            );
        }

        if !invalid_inner {
            for (case, (target, encoded_target_len)) in [
                (
                    TargetAddr::ipv4("192.0.2.2:53".parse().expect("IPv4")).expect("target"),
                    7,
                ),
                (TargetAddr::domain("example.test", 53).expect("domain"), 16),
                (
                    TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
                    19,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let limit =
                    composed_udp_plan_limit(&bound_outbounds, &[0, 1], false, encoded_target_len);
                let before = protocols[0]
                    .session_snapshot(outer_accepted.capability())
                    .expect("outer snapshot")
                    .expect("outer generation")
                    .highest_packet_id();
                let too_large = vec![0; limit + 1];
                let length = encode_udp_datagram(&target, &too_large, &mut socks)
                    .expect("SOCKS-valid nested maximum+1");
                application
                    .send_to(&socks[..length], relay)
                    .await
                    .expect("maximum+1 send");
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), upstreams[0].recv(&mut wire))
                        .await
                        .is_err(),
                    "nested maximum+1 reached outer hop"
                );
                assert_eq!(
                    protocols[0]
                        .session_snapshot(outer_accepted.capability())
                        .expect("outer snapshot")
                        .expect("outer generation")
                        .highest_packet_id(),
                    before
                );

                let exact = vec![case as u8; limit];
                let length =
                    encode_udp_datagram(&target, &exact, &mut socks).expect("exact nested maximum");
                application
                    .send_to(&socks[..length], relay)
                    .await
                    .expect("exact send");
                let (length, request_peer) =
                    tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                        .await
                        .expect("exact request timeout")
                        .expect("exact request");
                let outer = protocols[0]
                    .prepare_request(&clock, &wire[..length], &mut scratch)
                    .expect("exact outer");
                assert_eq!(
                    outer.datagram().target(),
                    &TargetAddr::ipv4(servers[1]).expect("inner target")
                );
                let inner_wire = outer.datagram().payload().to_vec();
                let (_, commit) = outer.into_parts();
                protocols[0]
                    .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                    .expect("exact outer commit");
                let inner = protocols[1]
                    .prepare_request(&clock, &inner_wire, &mut scratch)
                    .expect("exact inner");
                assert_eq!(inner.datagram().target(), &target);
                assert_eq!(inner.datagram().payload(), exact);
                let (_, commit) = inner.into_parts();
                protocols[1]
                    .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                    .expect("exact inner commit");
                assert_eq!(
                    protocols[0]
                        .session_snapshot(outer_accepted.capability())
                        .expect("outer snapshot")
                        .expect("outer generation")
                        .highest_packet_id(),
                    Some(case as u64 + 1)
                );
            }
        }

        stop.send(()).expect("stop client");
        assert_eq!(task.await.expect("client"), Ok(()));
        drop((control, application));
        std::fs::remove_file(path).expect("remove chain config");
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    }

    #[tokio::test]
    async fn tagged_udp_uses_static_outbounds_and_no_fallback() {
        let listens = [reserve_address(), reserve_address()];
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream A"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream B"),
        ];
        let servers: [SocketAddrV4; 2] = std::array::from_fn(|index| {
            match upstreams[index].local_addr().expect("upstream address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            }
        });
        let (path, mut config) =
            tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], true);
        config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in listens {
            wait_until_bound(listen).await;
        }
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut request = [0; 64];
        let mut owners = Vec::new();
        let mut relays = Vec::new();
        for index in 0..2 {
            let (control, application, relay) = udp_association(listens[index]).await;
            let length = encode_udp_datagram(&target, &[index as u8], &mut request)
                .expect("SOCKS UDP request");
            application
                .send_to(&request[..length], relay)
                .await
                .expect("application send");
            let mut wire = [0; MAX_UDP_WIRE_LEN];
            tokio::time::timeout(Duration::from_secs(1), upstreams[index].recv(&mut wire))
                .await
                .expect("mapped upstream timeout")
                .expect("mapped upstream request");
            owners.push((control, application));
            relays.push(relay);
        }
        stop.send(()).expect("stop mapped UDP client");
        assert_eq!(task.await.expect("mapped UDP client"), Ok(()));
        drop(owners);
        for relay in relays {
            drop(UdpSocket::bind(relay).await.expect("mapped relay rebind"));
        }
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        let dead = reserve_address();
        let dead_listens = [reserve_address(), reserve_address()];
        let (dead_path, config) = tagged_client_test_config(
            &[(dead_listens[0], servers[0]), (dead_listens[1], dead)],
            true,
        );
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in dead_listens {
            wait_until_bound(listen).await;
        }
        let (control, application, relay) = udp_association(dead_listens[1]).await;
        let length = encode_udp_datagram(&target, b"no-fallback", &mut request)
            .expect("no-fallback request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("no-fallback send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstreams[0].recv(&mut wire))
                .await
                .is_err(),
            "dead UDP outbound fell back to live sibling"
        );
        stop.send(()).expect("stop no-fallback UDP client");
        assert_eq!(task.await.expect("no-fallback UDP client"), Ok(()));
        drop((control, application));
        drop(
            UdpSocket::bind(relay)
                .await
                .expect("no-fallback relay rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove mapped UDP config");
        std::fs::remove_file(dead_path).expect("remove no-fallback UDP config");
    }

    #[tokio::test]
    async fn tagged_udp_shares_byte_budget_across_listeners() {
        let listens = [reserve_address(), reserve_address()];
        let server = reserve_address();
        let (path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
        let udp = config.udp.as_mut().expect("UDP config");
        udp.max_sessions = 8;
        udp.max_buffered_bytes = 1024 * 1024;
        config.runtime.shutdown_grace = Duration::from_secs(1);
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in listens {
            wait_until_bound(listen).await;
        }

        let mut controls = Vec::new();
        let mut applications = Vec::new();
        let mut relays = Vec::new();
        for _ in 0..5 {
            let (control, application, relay) = udp_association(listens[0]).await;
            controls.push(control);
            applications.push(application);
            relays.push(relay);
        }
        let saturated = registry.snapshot();
        assert_eq!(saturated.udp_sessions, baseline.udp_sessions + 5);
        assert_eq!(
            saturated.udp_buffered_bytes,
            baseline.udp_buffered_bytes + 15 * MAX_UDP_WIRE_LEN
        );
        let (rejected, reply) = socks_command(listens[1], 3).await;
        assert_eq!(&reply[..2], &[5, 1]);
        drop(rejected);
        assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 5);

        drop(controls.remove(0));
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let released = registry.snapshot();
            if released.udp_sessions == baseline.udp_sessions + 4
                && released.udp_buffered_bytes
                    == baseline.udp_buffered_bytes + 12 * MAX_UDP_WIRE_LEN
            {
                break;
            }
            assert!(Instant::now() < deadline, "UDP byte owner did not release");
            tokio::task::yield_now().await;
        }
        let (control, application, relay) = udp_association(listens[1]).await;
        controls.push(control);
        applications.push(application);
        relays.push(relay);

        stop.send(()).expect("stop byte-budget client");
        assert_eq!(task.await.expect("byte-budget client"), Ok(()));
        drop((controls, applications));
        for relay in relays {
            drop(
                UdpSocket::bind(relay)
                    .await
                    .expect("byte-budget relay rebind"),
            );
        }
        for listen in listens {
            drop(TcpListener::bind(listen).await.expect("listener rebind"));
        }
        assert_eq!(active(registry.snapshot()), active(baseline));
        std::fs::remove_file(path).expect("remove byte-budget config");
    }

    #[tokio::test]
    async fn tagged_udp_shares_live_id_collisions_across_listeners() {
        let listens = [reserve_address(), reserve_address()];
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream");
        let SocketAddr::V4(server) = upstream.local_addr().expect("upstream address") else {
            unreachable!("IPv4 upstream")
        };
        let (path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
        config.udp.as_mut().expect("UDP config").max_sessions = 3;
        config.runtime.shutdown_grace = Duration::from_secs(1);
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let draws = [1]
            .into_iter()
            .chain(std::iter::repeat_n(1, 7))
            .chain([2])
            .chain(std::iter::repeat_n(1, 8));
        let (stop, task) = spawn_test_client_with_random(
            config,
            &registry,
            Arc::new(IdSequenceRandom::new(draws)),
        );
        for listen in listens {
            wait_until_bound(listen).await;
        }

        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut socks = [0; 64];
        let length = encode_udp_datagram(&target, b"activate", &mut socks).expect("request");
        let first = udp_association(listens[0]).await;
        first
            .1
            .send_to(&socks[..length], first.2)
            .await
            .expect("first activation");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        upstream.recv(&mut wire).await.expect("first upstream");
        let second = udp_association(listens[1]).await;
        second
            .1
            .send_to(&socks[..length], second.2)
            .await
            .expect("second activation");
        upstream.recv(&mut wire).await.expect("second upstream");
        let (mut rejected, rejected_application, rejected_relay) =
            udp_association(listens[1]).await;
        rejected_application
            .send_to(&socks[..length], rejected_relay)
            .await
            .expect("rejected activation");
        let mut eof = [0];
        tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut eof))
            .await
            .expect("rejected control timeout")
            .expect("rejected control EOF");
        assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 2);

        stop.send(()).expect("stop live-ID client");
        assert_eq!(task.await.expect("live-ID client"), Ok(()));
        let relays = [first.2, second.2, rejected_relay];
        drop((first, second, rejected, rejected_application));
        for relay in relays {
            drop(UdpSocket::bind(relay).await.expect("live-ID relay rebind"));
        }
        for listen in listens {
            drop(TcpListener::bind(listen).await.expect("listener rebind"));
        }
        assert_eq!(active(registry.snapshot()), active(baseline));
        std::fs::remove_file(path).expect("remove live-ID config");
    }

    #[tokio::test]
    async fn tagged_prepare_failures_restore_full_baseline_and_exact_rebind() {
        for blocked in 0..3 {
            let listens = [reserve_address(), reserve_address(), reserve_address()];
            let metrics = reserve_address();
            let (path, mut config) = tagged_client_test_config(
                &listens.map(|listen| (listen, reserve_address())),
                false,
            );
            config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
            let address = if blocked < 2 {
                listens[blocked]
            } else {
                metrics
            };
            let incumbent = std::net::TcpListener::bind(address).expect("occupy prepare position");
            let registry = OwnerRegistry::new();
            assert_eq!(
                run_with_registry(config, registry.clone(), std::future::pending()).await,
                Err(RunError::StartupBind)
            );
            drop(incumbent);
            for address in listens.into_iter().chain([metrics]) {
                drop(std::net::TcpListener::bind(address).expect("exact rollback rebind"));
            }
            assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
            std::fs::remove_file(path).expect("remove prepare config");
        }
    }

    fn udp_test_context(registry: OwnerRegistry) -> (PathBuf, Arc<ClientContext>) {
        udp_test_context_for_server(registry, reserve_address())
    }

    fn udp_test_context_for_server(
        registry: OwnerRegistry,
        server: SocketAddrV4,
    ) -> (PathBuf, Arc<ClientContext>) {
        udp_test_context_for_psk(registry, server, None)
    }

    fn udp_test_context_for_psk(
        registry: OwnerRegistry,
        server: SocketAddrV4,
        psk: Option<ferrum2_crypto::MethodPsk>,
    ) -> (PathBuf, Arc<ClientContext>) {
        let (path, mut config) = client_udp_test_config(reserve_address(), server);
        if let Some(psk) = psk {
            config.psk = psk;
        }
        let method = config.method();
        let udp = config.udp.expect("enabled UDP");
        let server = config.server;
        let runtime = config.runtime;
        let context = ClientContext {
            inbound: Socks5Inbound::new(),
            outbound_connector: TokioConnector::new(TcpConnector::new(runtime.connect_timeout)),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
            clock: SystemClock::new(),
            random: SystemRandom,
            udp_id_random: None,
            runtime,
            udp: Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::new(
                        udp.max_sessions,
                        udp.max_buffered_bytes,
                        udp.idle_timeout,
                    )
                    .expect("UDP limits"),
                    registry.clone(),
                ),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
                method,
            }),
            udp_associate_enabled: true,
            registry,
            metrics: Arc::new(Metrics::new()),
            test_udp_server: server,
        };
        (path, Arc::new(context))
    }

    async fn parsed_udp_association() -> (
        SocksUdpAssociate<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    ) {
        let (mut peer, application) = tokio::io::duplex(128);
        let peer_task = tokio::spawn(async move {
            peer.write_all(&[5, 1, 0]).await.expect("greeting");
            let mut method = [0; 2];
            peer.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [5, 0]);
            peer.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("UDP request");
            peer
        });
        let command = Socks5Inbound::new()
            .accept_command(application)
            .await
            .expect("parsed command");
        let SocksCommand::UdpAssociate(association) = command else {
            panic!("UDP association")
        };
        (association, peer_task.await.expect("peer task"))
    }

    async fn execute_test_udp_association<IO, F, Fut>(
        association: SocksUdpAssociate<IO>,
        context: Arc<ClientContext>,
        bind: F,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnMut(SocketAddrV4) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = io::Result<UdpSocket>> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("token listener");
        let address = listener.local_addr().expect("token address");
        let supervisor = BoundedSupervisor::new(
            listener,
            1,
            Duration::from_secs(1),
            context.registry.clone(),
        )
        .expect("token supervisor");
        let association = Arc::new(Mutex::new(Some(association)));
        let bind = Arc::new(Mutex::new(Some(bind)));
        let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
        let done_sender = Arc::new(Mutex::new(Some(done_sender)));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let run_task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let association = association
                    .lock()
                    .expect("association")
                    .take()
                    .expect("one handler");
                let bind = bind.lock().expect("bind").take().expect("one binder");
                let context = Arc::clone(&context);
                let server = context.test_udp_server;
                let routing = test_routing(server, default_test_psk());
                let done_sender = Arc::clone(&done_sender);
                async move {
                    run_udp_association(
                        association,
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        Ipv4Addr::LOCALHOST,
                        &mut cancellation,
                        context,
                        (0, &routing),
                        bind,
                    )
                    .await;
                    done_sender
                        .lock()
                        .expect("done sender")
                        .take()
                        .expect("one completion")
                        .send(())
                        .expect("completion receiver");
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let _trigger = tokio::net::TcpStream::connect(address)
            .await
            .expect("token handler");
        done_receiver.await.expect("association completion");
        shutdown_sender.send(()).expect("token shutdown");
        assert_eq!(run_task.await.expect("token supervisor"), Ok(()));
    }

    #[tokio::test]
    async fn first_and_second_socket_setup_failures_reply_once_and_roll_back() {
        for fail_at in 0..2 {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let (path, context) = udp_test_context(registry.clone());
            let (association, mut peer) = parsed_udp_association().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let bound = Arc::new(Mutex::new(Vec::new()));
            let bind_calls = Arc::clone(&calls);
            let bound_addresses = Arc::clone(&bound);
            execute_test_udp_association(association, Arc::clone(&context), move |address| {
                let call = bind_calls.fetch_add(1, Ordering::SeqCst);
                let bound_addresses = Arc::clone(&bound_addresses);
                async move {
                    if call == fail_at {
                        return Err(io::Error::other("injected bind failure"));
                    }
                    let socket = UdpSocket::bind(address).await?;
                    bound_addresses
                        .lock()
                        .expect("bound addresses")
                        .push(socket.local_addr()?);
                    Ok(socket)
                }
            })
            .await;
            let mut reply = [0; 10];
            peer.read_exact(&mut reply).await.expect("failure reply");
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(peer.read(&mut reply).await.expect("single reply EOF"), 0);
            assert_eq!(calls.load(Ordering::SeqCst), fail_at + 1);
            let udp = context.udp.as_ref().expect("UDP context");
            assert_eq!(udp.manager.session_count(), 0);
            assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
            assert!(udp.live_ids.lock().expect("live IDs").is_empty());
            assert_eq!(registry.snapshot(), baseline);
            let bound = bound.lock().expect("bound addresses").clone();
            for address in bound {
                drop(UdpSocket::bind(address).await.expect("setup socket rebind"));
            }
            std::fs::remove_file(path).expect("remove config");
        }
    }

    #[tokio::test]
    async fn success_reply_write_failure_rolls_back_and_next_setup_rebinds() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context) = udp_test_context(registry.clone());
        let (association, peer) = parsed_udp_association().await;
        drop(peer);
        execute_test_udp_association(association, Arc::clone(&context), |address| {
            UdpSocket::bind(address)
        })
        .await;
        let udp = context.udp.as_ref().expect("UDP context");
        assert_eq!(udp.manager.session_count(), 0);
        assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());
        assert_eq!(registry.snapshot(), baseline);

        let prepared = prepare_udp_association_with_bind(
            &context,
            Ipv4Addr::LOCALHOST,
            Some((Box::from([0]), context.test_udp_server)),
            UdpSocket::bind,
        )
        .await
        .expect("next setup");
        let application = prepared
            .application
            .local_addr()
            .expect("application address");
        let upstream = prepared.upstream.local_addr().expect("upstream address");
        drop(prepared);
        assert_eq!(registry.snapshot(), baseline);
        drop(
            UdpSocket::bind(application)
                .await
                .expect("application rebind"),
        );
        drop(UdpSocket::bind(upstream).await.expect("upstream rebind"));
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn application_binder_receives_the_accepted_concrete_local_ip() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context) = udp_test_context(registry.clone());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&calls);
        let prepared = prepare_udp_association_with_bind(
            &context,
            Ipv4Addr::new(127, 0, 0, 2),
            Some((Box::from([0]), context.test_udp_server)),
            move |address| {
                observed.lock().expect("bind calls").push(address);
                UdpSocket::bind(address)
            },
        )
        .await
        .expect("setup");
        assert_eq!(
            *calls.lock().expect("bind calls"),
            [
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            ]
        );
        assert_eq!(
            prepared.application.local_addr().expect("relay").ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
        );
        drop(prepared);
        assert_eq!(registry.snapshot(), baseline);
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test(start_paused = true)]
    async fn active_idle_and_generation_cancel_return_every_owner_and_socket() {
        for terminal in ["idle", "generation-cancel"] {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream receiver");
            let server = match upstream.local_addr().expect("upstream address") {
                SocketAddr::V4(server) => server,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            };
            let (path, context) = udp_test_context_for_server(registry.clone(), server);
            let (association, mut peer) = parsed_udp_association().await;
            let task = tokio::spawn(execute_test_udp_association(
                association,
                Arc::clone(&context),
                UdpSocket::bind,
            ));
            let mut reply = [0; 10];
            peer.read_exact(&mut reply).await.expect("success reply");
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            let relay = SocketAddrV4::new(
                Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
                u16::from_be_bytes([reply[8], reply[9]]),
            );
            let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("application socket");
            let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
            let mut request = [0; 64];
            let request_len =
                encode_udp_datagram(&target, b"committed", &mut request).expect("SOCKS request");
            application
                .send_to(&request[..request_len], relay)
                .await
                .expect("application send");
            let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
            tokio::time::timeout(Duration::from_secs(1), upstream.recv(&mut upstream_wire))
                .await
                .expect("committed request timeout")
                .expect("committed request");
            let live = registry.snapshot();
            let actual = (
                live.udp_sessions,
                live.udp_buffered_bytes,
                live.udp_queued_datagrams,
                live.active_supervisor_children,
                live.connection_tasks,
            );
            let expected = (1, 3 * MAX_UDP_WIRE_LEN, 0, 1, 1);
            assert_eq!(actual, expected, "{terminal}");
            if terminal == "idle" {
                tokio::time::advance(Duration::from_secs(300)).await;
            } else {
                context
                    .udp
                    .as_ref()
                    .expect("UDP context")
                    .manager
                    .cancel_all();
            }
            task.await.expect("association task");
            assert_eq!(peer.read(&mut reply).await.expect("control EOF"), 0);
            assert!(
                context
                    .udp
                    .as_ref()
                    .expect("UDP context")
                    .live_ids
                    .lock()
                    .expect("live IDs")
                    .is_empty()
            );
            assert_eq!(registry.snapshot(), baseline, "{terminal}");
            drop(UdpSocket::bind(relay).await.expect("relay rebind"));
            std::fs::remove_file(path).expect("remove config");
        }
    }

    async fn wait_until_bound(address: SocketAddrV4) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
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

    #[tokio::test]
    async fn udp_process_shutdown_drains_an_active_association_without_forcing() {
        let listens = [reserve_address(), reserve_address()];
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream receiver");
        let server = match upstream.local_addr().expect("upstream address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        };
        let (config_path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
        config.runtime.shutdown_grace = Duration::from_secs(1);
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let metrics = Arc::new(Metrics::new());
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task_registry = registry.clone();
        let task_metrics = Arc::clone(&metrics);
        let run_task = tokio::spawn(async move {
            run_with_registry_and_metrics(
                config,
                task_registry,
                async {
                    let _ = shutdown_receiver.await;
                },
                task_metrics,
            )
            .await
        });
        for listen in listens {
            wait_until_bound(listen).await;
        }

        let mut control = tokio::net::TcpStream::connect(listens[0])
            .await
            .expect("SOCKS control");
        control.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut reply = [0_u8; 10];
        control.read_exact(&mut reply).await.expect("success reply");
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application socket");
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut request = [0; 64];
        let request_len =
            encode_udp_datagram(&target, b"graceful-active", &mut request).expect("request");
        application
            .send_to(&request[..request_len], relay)
            .await
            .expect("application send");
        let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
        let (_, upstream_client) = tokio::time::timeout(
            Duration::from_secs(2),
            upstream.recv_from(&mut upstream_wire),
        )
        .await
        .expect("committed request timeout")
        .expect("committed request");
        let live = registry.snapshot();
        assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
        assert_eq!(
            live.udp_buffered_bytes,
            baseline.udp_buffered_bytes + 3 * MAX_UDP_WIRE_LEN
        );
        assert_eq!(
            live.active_supervisor_children,
            baseline.active_supervisor_children + 1
        );
        assert_eq!(live.connection_tasks, baseline.connection_tasks + 1);
        let (_, saturated) = socks_command(listens[1], 3).await;
        assert_eq!(&saturated[..2], &[5, 1]);
        assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 1);

        shutdown_sender
            .send(())
            .expect("request graceful shutdown first");
        let mut eof = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
                .await
                .expect("control EOF timeout")
                .expect("control EOF"),
            0
        );
        assert_eq!(run_task.await.expect("run task"), Ok(()));
        let closed = registry.snapshot();
        let actual = (
            closed.process_supervisors,
            closed.prepared_process_roots,
            closed.active_process_roots,
            closed.active_supervisor_children,
            closed.connection_tasks,
            closed.owned_permits,
            closed.listeners,
            closed.udp_sessions,
            closed.udp_queued_datagrams,
            closed.udp_buffered_bytes,
        );
        let expected = (
            baseline.process_supervisors,
            baseline.prepared_process_roots,
            baseline.active_process_roots,
            baseline.active_supervisor_children,
            baseline.connection_tasks,
            baseline.owned_permits,
            baseline.listeners,
            baseline.udp_sessions,
            baseline.udp_queued_datagrams,
            baseline.udp_buffered_bytes,
        );
        assert_eq!(actual, expected);
        assert!(
            !metrics
                .encode_text()
                .expect("metrics")
                .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
        );
        drop(application);
        drop(upstream);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        drop(
            UdpSocket::bind(upstream_client)
                .await
                .expect("upstream client rebind"),
        );
        for listen in listens {
            drop(TcpListener::bind(listen).await.expect("listener rebind"));
        }
        std::fs::remove_file(config_path).expect("remove client UDP test config");
    }
    #[tokio::test]
    async fn zero_grace_counts_each_of_two_forced_udp_associations_once() {
        let listens = [reserve_address(), reserve_address()];
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream receiver");
        let server = match upstream.local_addr().expect("upstream address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        };
        let (config_path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
        config.runtime.shutdown_grace = Duration::ZERO;
        config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let metrics = Arc::new(Metrics::new());
        let task_metrics = Arc::clone(&metrics);
        let task_registry = registry.clone();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let run_task = tokio::spawn(async move {
            run_with_registry_and_metrics(
                config,
                task_registry,
                async {
                    let _ = shutdown_receiver.await;
                },
                task_metrics,
            )
            .await
        });
        for listen in listens {
            wait_until_bound(listen).await;
        }

        let mut controls = Vec::new();
        let mut relays = Vec::new();
        let mut applications = Vec::new();
        let mut upstream_clients = Vec::new();
        for (listen, payload) in listens
            .into_iter()
            .zip([b"active-one".as_slice(), b"active-two".as_slice()])
        {
            let mut control = tokio::net::TcpStream::connect(listen)
                .await
                .expect("SOCKS control");
            control.write_all(&[5, 1, 0]).await.expect("greeting");
            let mut method = [0; 2];
            control.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("UDP ASSOCIATE");
            let mut reply = [0; 10];
            control.read_exact(&mut reply).await.expect("success reply");
            let relay = SocketAddrV4::new(
                Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
                u16::from_be_bytes([reply[8], reply[9]]),
            );
            let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("application");
            let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
            let mut request = [0; 64];
            let length = encode_udp_datagram(&target, payload, &mut request).expect("request");
            application
                .send_to(&request[..length], relay)
                .await
                .expect("application send");
            let mut wire = [0; MAX_UDP_WIRE_LEN];
            let (_, upstream_client) =
                tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut wire))
                    .await
                    .expect("upstream timeout")
                    .expect("upstream request");
            controls.push(control);
            relays.push(relay);
            applications.push(application);
            upstream_clients.push(upstream_client);
        }
        let active = registry.snapshot();
        assert_eq!(active.udp_sessions, baseline.udp_sessions + 2);
        assert_eq!(
            active.udp_buffered_bytes,
            baseline.udp_buffered_bytes + 6 * MAX_UDP_WIRE_LEN
        );
        assert_eq!(
            active.active_supervisor_children,
            baseline.active_supervisor_children + 2
        );
        assert_eq!(active.connection_tasks, baseline.connection_tasks + 2);

        shutdown_sender.send(()).expect("zero-grace shutdown");
        for control in &mut controls {
            let mut eof = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
                    .await
                    .expect("control EOF timeout")
                    .expect("control EOF"),
                0
            );
        }
        assert_eq!(run_task.await.expect("run task"), Ok(()));
        assert!(
            metrics
                .encode_text()
                .expect("metrics")
                .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"} 2")
        );
        let closed = registry.snapshot();
        let actual = (
            closed.process_supervisors,
            closed.prepared_process_roots,
            closed.active_process_roots,
            closed.active_supervisor_children,
            closed.connection_tasks,
            closed.owned_permits,
            closed.listeners,
            closed.udp_sessions,
            closed.udp_queued_datagrams,
            closed.udp_buffered_bytes,
        );
        let expected = (
            baseline.process_supervisors,
            baseline.prepared_process_roots,
            baseline.active_process_roots,
            baseline.active_supervisor_children,
            baseline.connection_tasks,
            baseline.owned_permits,
            baseline.listeners,
            baseline.udp_sessions,
            baseline.udp_queued_datagrams,
            baseline.udp_buffered_bytes,
        );
        assert_eq!(actual, expected);
        drop(controls);
        drop(applications);
        drop(upstream);
        for relay in relays {
            drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        }
        for upstream_client in upstream_clients {
            drop(
                UdpSocket::bind(upstream_client)
                    .await
                    .expect("upstream client rebind"),
            );
        }
        for listen in listens {
            drop(TcpListener::bind(listen).await.expect("listener rebind"));
        }
        std::fs::remove_file(config_path).expect("remove config");
    }
    #[tokio::test]
    async fn listener_fatal_cancels_udp_without_forced_shutdown() {
        let listens = [reserve_address(), reserve_address()];
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream receiver");
        let server = match upstream.local_addr().expect("upstream address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        };
        let (path, mut context) = udp_test_context_for_server(registry.clone(), server);
        Arc::get_mut(&mut context)
            .expect("unique test context")
            .runtime
            .shutdown_grace = Duration::from_secs(1);
        let metrics = Arc::clone(&context.metrics);
        let accept_errors = Arc::new(Mutex::new(VecDeque::from([io::ErrorKind::Interrupted])));
        let tcp_registry = registry.clone();
        let tcp_context = Arc::clone(&context);
        let tcp_accept_errors = Arc::clone(&accept_errors);
        let tcp_root = ProcessRoot::new(move || async move {
            let listeners = listens
                .into_iter()
                .map(|listen| bind_listener(listen, 16))
                .collect::<Result<Vec<_>, _>>()?;
            let supervisor = BoundedSupervisor::new(
                ClientTcpListeners {
                    listeners,
                    next: AtomicUsize::new(0),
                    accept_errors: Some(tcp_accept_errors),
                },
                4,
                Duration::from_secs(1),
                tcp_registry,
            )
            .map_err(|_| RunError::StartupProtocol)?;
            Ok(ClientTcpRoot {
                supervisor: Some(supervisor),
                context: tcp_context,
                routing: Arc::new(ClientRouting {
                    route: ferrum2_core::route::RouteTable::static_bindings(vec![0, 1])
                        .expect("test routes"),
                    outbounds: listens
                        .map(|_| ClientOutboundContext {
                            tcp_server: TargetAddr::ipv4(server).expect("server target"),
                            udp_server: server,
                            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                                psk_for_method(MethodProfile::Blake3Aes128Gcm2022),
                            )),
                        })
                        .into(),
                }),
            })
        });
        let supervisor =
            ProcessSupervisor::new(vec![tcp_root], Duration::from_secs(1), registry.clone())
                .expect("process supervisor");
        let run_task = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
        for listen in listens {
            wait_until_bound(listen).await;
        }

        let mut control = tokio::net::TcpStream::connect(listens[0])
            .await
            .expect("SOCKS control");
        control.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        control.read_exact(&mut method).await.expect("method");
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.expect("success reply");
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut request = [0; 64];
        let length = encode_udp_datagram(&target, b"sibling", &mut request).expect("request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("application send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        let (_, upstream_client) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut wire))
                .await
                .expect("upstream timeout")
                .expect("committed upstream request");
        let live = registry.snapshot();
        assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
        assert_eq!(live.udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
        assert_eq!(live.active_supervisor_children, 1);
        assert_eq!(live.connection_tasks, 1);
        assert_eq!(live.owned_permits, 2);
        assert_eq!(
            context.udp.as_ref().expect("UDP").manager.session_count(),
            1
        );

        accept_errors
            .lock()
            .expect("accept errors")
            .push_back(io::ErrorKind::PermissionDenied);
        drop(
            tokio::net::TcpStream::connect(listens[1])
                .await
                .expect("wake fatal listener"),
        );
        let mut eof = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), control.read(&mut eof))
                .await
                .expect("control EOF timeout")
                .expect("control EOF"),
            0
        );
        let report = run_task.await.expect("process task");
        assert!(matches!(
            report.cause(),
            ProcessCause::RootStopped {
                root,
                exit: ProcessRootExit::Failed(RunError::RuntimeListener),
            } if root.get() == 0
        ));
        assert_eq!(report.forced_roots(), 0);
        let udp = context.udp.as_ref().expect("UDP");
        assert_eq!(udp.manager.session_count(), 0);
        assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());
        assert_eq!(active(registry.snapshot()), active(baseline));
        assert!(
            !metrics
                .encode_text()
                .expect("metrics")
                .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
        );
        drop(application);
        drop(upstream);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        drop(
            UdpSocket::bind(upstream_client)
                .await
                .expect("upstream client rebind"),
        );
        for listen in listens {
            drop(TcpListener::bind(listen).await.expect("listener rebind"));
        }
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
        let shadowsocks_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fake Shadowsocks listener");
        let server = match shadowsocks_listener.local_addr().expect("server address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 server"),
        };
        let listen = reserve_address();
        let (config_path, config) = client_test_config(listen, server);
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task_registry = registry.clone();
        let run_task = tokio::spawn(async move {
            run_with_registry(config, task_registry, async {
                let _ = shutdown_receiver.await;
            })
            .await
        });
        wait_until_bound(listen).await;

        let accept_task = tokio::spawn(async move {
            shadowsocks_listener
                .accept()
                .await
                .expect("fake Shadowsocks accept")
                .0
        });
        let mut socks = tokio::net::TcpStream::connect(listen)
            .await
            .expect("SOCKS client connect");
        socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
        let mut method = [0_u8; 2];
        socks.read_exact(&mut method).await.expect("SOCKS method");
        assert_eq!(method, [5, 0]);
        socks
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .expect("SOCKS request");
        let mut reply = [0_u8; 10];
        socks.read_exact(&mut reply).await.expect("SOCKS success");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let shadowsocks_stream = accept_task.await.expect("fake Shadowsocks task");

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
        assert_eq!(
            run_task.await.expect("run task"),
            Ok(()),
            "production run_with_registry path"
        );
        drop(socks);
        drop(shadowsocks_stream);
        let final_snapshot = registry.snapshot();
        let actual = (
            final_snapshot.active_supervisor_children,
            final_snapshot.connection_tasks,
            final_snapshot.owned_buffers,
            final_snapshot.owned_permits,
            final_snapshot.listeners,
            final_snapshot.process_forced_roots,
            final_snapshot.forced_shutdowns,
        );
        let expected = (
            baseline.active_supervisor_children,
            baseline.connection_tasks,
            baseline.owned_buffers,
            baseline.owned_permits,
            baseline.listeners,
            baseline.process_forced_roots + 1,
            baseline.forced_shutdowns + 1,
        );
        assert_eq!(actual, expected, "TCP root cleanup");
        std::fs::remove_file(config_path).expect("remove client test config");
    }
}
