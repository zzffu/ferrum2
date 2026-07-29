use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ferrum2_config::{LoggingLevel, RuntimeConfig, ValidatedClientConfig};
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, Inbound as _, LocalEndpoint,
    SessionReply as _, TargetAddr,
};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
    json_subscriber,
};
use ferrum2_runtime::{
    BoundedSupervisor, CancellationToken, MetricsEndpoint, MetricsEndpointError, OwnerRegistry,
    PreparedProcessRoot, ProcessCancellation, ProcessCause, ProcessFuture, ProcessReport,
    ProcessRoot, ProcessRootExit, ProcessSupervisor, RelayFailure, RelayRunError, SupervisorError,
    TcpConnector, relay_lifecycle,
};
use ferrum2_shadowsocks::{
    ClientFlow, ClientTcpOutbound, DetectionReason, FlowTerminal, MethodKeyAdapter, PlainDuplex,
    ProtocolReason, ShadowsocksError, TcpKeyProvider, TransportIo,
};
use ferrum2_socks5::Socks5Inbound;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket};

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
    let metrics = Arc::new(Metrics::new());
    let server = TargetAddr::ipv4(config.server).map_err(|_| RunError::StartupProtocol)?;
    let shutdown_grace = config.runtime.shutdown_grace;
    let listen = config.listen;
    let listen_backlog = u32::from(config.runtime.listen_backlog.get());
    let max_connections = usize::from(config.runtime.max_connections.get());
    let context = Arc::new(ClientContext {
        inbound: Socks5Inbound::new(),
        outbound_connector: TokioConnector::new(TcpConnector::new(config.runtime.connect_timeout)),
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
        clock: SystemClock::new(),
        random: SystemRandom,
        server,
        runtime: config.runtime,
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
    });
    let tcp_registry = registry.clone();
    let tcp_context = Arc::clone(&context);
    let mut roots = vec![ProcessRoot::new(move || async move {
        let listener = bind_listener(listen, listen_backlog)?;
        let supervisor =
            BoundedSupervisor::new(listener, max_connections, shutdown_grace, tcp_registry)
                .map_err(|_| RunError::StartupProtocol)?;
        Ok(ClientTcpRoot {
            supervisor: Some(supervisor),
            context: tcp_context,
        })
    })];
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

struct ClientTcpRoot {
    supervisor: Option<BoundedSupervisor<TcpListener>>,
    context: Arc<ClientContext>,
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
        Box::pin(async move {
            supervisor
                .run_with_cancellation(
                    move |stream, cancellation| {
                        let context = Arc::clone(&context);
                        async move {
                            client_connection(stream, cancellation, context).await;
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
        let endpoint = MetricsEndpoint::new(
            listener,
            move || metrics.encode_text().unwrap_or_default(),
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

struct ClientContext {
    inbound: Socks5Inbound,
    outbound_connector: TokioConnector<TcpConnector>,
    keys: MethodKeyAdapter<MethodSinglePskProvider>,
    clock: SystemClock,
    random: SystemRandom,
    server: TargetAddr,
    runtime: RuntimeConfig,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
}

async fn client_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ClientContext>,
) {
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            context.inbound.accept(stream),
        ) => result,
    };
    let session = match accepted {
        Ok(Ok(session)) => session,
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
    let ferrum2_core::Session {
        target,
        mut stream,
        initial_payload: _,
        reply,
    } = session;
    let outbound = ClientTcpOutbound::new(
        context.server.clone(),
        &context.keys,
        &context.outbound_connector,
        &context.clock,
        &context.random,
    );
    let opened = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = open_with_deadlines(
            &outbound,
            &target,
            context.runtime.connect_timeout,
            context.runtime.handshake_timeout,
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
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;
    use std::time::Duration;

    use ferrum2_core::{ConnectError, Connector};
    use ferrum2_crypto::{Aes128Psk, RandomError, SinglePskProvider};
    use ferrum2_shadowsocks::TransportPhase;
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
    async fn adapter_contract_transport_delegates_io_endpoint_and_abortive_close() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001);
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
        assert_eq!(transport.local_endpoint(), endpoint);
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

    struct GateConnector {
        gate: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<TargetAddr>>>,
        stream: Mutex<Option<EndpointIo>>,
    }

    impl Connector for GateConnector {
        type Stream = EndpointIo;

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

    #[derive(Default)]
    struct PhaseDeadlineControl {
        connect_ready: std::sync::atomic::AtomicBool,
        write_ready: std::sync::atomic::AtomicBool,
        connect_waker: Mutex<Option<Waker>>,
        write_waker: Mutex<Option<Waker>>,
        write_polls: AtomicUsize,
        completed_writes: AtomicUsize,
        abortive_calls: AtomicUsize,
        dropped_streams: AtomicUsize,
        targets: Mutex<Vec<TargetAddr>>,
    }

    impl PhaseDeadlineControl {
        fn release_connect(&self) {
            self.connect_ready.store(true, Ordering::SeqCst);
            if let Some(waker) = self.connect_waker.lock().expect("connect waker").take() {
                waker.wake();
            }
        }

        fn release_write(&self) {
            self.write_ready.store(true, Ordering::SeqCst);
            if let Some(waker) = self.write_waker.lock().expect("write waker").take() {
                waker.wake();
            }
        }
    }

    struct PhaseDeadlineTransport {
        control: Arc<PhaseDeadlineControl>,
    }

    impl Drop for PhaseDeadlineTransport {
        fn drop(&mut self) {
            self.control.dropped_streams.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl LocalEndpoint for PhaseDeadlineTransport {
        fn local_endpoint(&self) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152)
        }
    }

    impl AbortiveClose for PhaseDeadlineTransport {
        type Error = io::Error;

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.control.abortive_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl TransportIo for PhaseDeadlineTransport {
        type IoError = io::Error;

        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _destination: &mut [u8],
        ) -> Poll<Result<usize, Self::IoError>> {
            Poll::Pending
        }

        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<Result<usize, Self::IoError>> {
            self.control.write_polls.fetch_add(1, Ordering::SeqCst);
            if !self.control.write_ready.load(Ordering::SeqCst) {
                *self.control.write_waker.lock().expect("write waker") = Some(cx.waker().clone());
                return Poll::Pending;
            }
            self.control.completed_writes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(source.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::IoError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::IoError>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PhaseDeadlineConnector {
        control: Arc<PhaseDeadlineControl>,
        stream: Mutex<Option<PhaseDeadlineTransport>>,
    }

    impl PhaseDeadlineConnector {
        fn new(control: Arc<PhaseDeadlineControl>) -> Self {
            Self {
                stream: Mutex::new(Some(PhaseDeadlineTransport {
                    control: Arc::clone(&control),
                })),
                control,
            }
        }
    }

    impl Connector for PhaseDeadlineConnector {
        type Stream = PhaseDeadlineTransport;

        async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.control
                .targets
                .lock()
                .expect("phase targets")
                .push(target.clone());
            let stream = self
                .stream
                .lock()
                .expect("phase stream")
                .take()
                .expect("one phase connect");
            std::future::poll_fn(|cx| {
                if self.control.connect_ready.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    *self.control.connect_waker.lock().expect("connect waker") =
                        Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            Ok(stream)
        }
    }

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
            destination.fill(0x42);
            Ok(())
        }
    }

    fn client_deadline_test_config(
        connect_timeout_ms: Option<u64>,
        handshake_timeout_ms: Option<u64>,
    ) -> (PathBuf, ValidatedClientConfig) {
        static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrum2-client-deadline-{}-{}.toml",
            std::process::id(),
            CONFIG_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let mut runtime = String::from("[runtime]\n");
        if let Some(value) = connect_timeout_ms {
            runtime.push_str(&format!("connect_timeout_ms = {value}\n"));
        }
        if let Some(value) = handshake_timeout_ms {
            runtime.push_str(&format!("handshake_timeout_ms = {value}\n"));
        }
        let source = format!(
            "schema_version = 1\n\
             [client]\n\
             listen = \"127.0.0.1:41001\"\n\
             server = \"127.0.0.1:41002\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             {runtime}"
        );
        std::fs::write(&path, source).expect("client deadline config");
        let config = ferrum2_config::load_client(&path).expect("validated deadline config");
        (path, config)
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

    fn phase_outbound<'a>(
        server: SocketAddrV4,
        keys: &'a SinglePskProvider,
        connector: &'a PhaseDeadlineConnector,
        clock: &'a SystemClock,
        random: &'a FixedRandom,
    ) -> ClientTcpOutbound<'a, SinglePskProvider, PhaseDeadlineConnector, SystemClock, FixedRandom>
    {
        ClientTcpOutbound::new(
            TargetAddr::ipv4(server).expect("configured server"),
            keys,
            connector,
            clock,
            random,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_default_connect_timeout_is_exact() {
        let (path, config) = client_deadline_test_config(None, None);
        assert_eq!(config.runtime.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.runtime.handshake_timeout, Duration::from_secs(5));
        let control = Arc::new(PhaseDeadlineControl::default());
        let connector = PhaseDeadlineConnector::new(Arc::clone(&control));
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x11; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = phase_outbound(config.server, &keys, &connector, &clock, &random);
        let application_target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &application_target,
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ));

        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(9_999)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            opened.await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                ConnectErrorKind::Timeout
            )))
        ));
        assert_eq!(control.write_polls.load(Ordering::SeqCst), 0);
        assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);
        assert_eq!(control.abortive_calls.load(Ordering::SeqCst), 0);
        control.release_connect();
        tokio::task::yield_now().await;
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);
        std::fs::remove_file(path).expect("remove deadline config");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_default_handshake_budget_is_fresh_after_slow_connect() {
        let (path, config) = client_deadline_test_config(None, None);
        let control = Arc::new(PhaseDeadlineControl::default());
        let connector = PhaseDeadlineConnector::new(Arc::clone(&control));
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x12; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = phase_outbound(config.server, &keys, &connector, &clock, &random);
        let application_target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &application_target,
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ));

        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert_open_pending(&mut opened).await;
        control.release_connect();
        assert_open_pending(&mut opened).await;
        assert!(control.write_polls.load(Ordering::SeqCst) >= 1);
        tokio::time::advance(Duration::from_millis(4_999)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            opened.await,
            Err(ClientOpenFailure::HandshakeTimeout)
        ));
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);
        assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);
        assert_eq!(control.abortive_calls.load(Ordering::SeqCst), 0);
        control.release_write();
        tokio::task::yield_now().await;
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);
        std::fs::remove_file(path).expect("remove deadline config");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_non_default_connect_value_is_not_hardcoded() {
        let (path, config) = client_deadline_test_config(Some(2_300), Some(3_700));
        let control = Arc::new(PhaseDeadlineControl::default());
        let connector = PhaseDeadlineConnector::new(Arc::clone(&control));
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x13; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = phase_outbound(config.server, &keys, &connector, &clock, &random);
        let application_target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &application_target,
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ));

        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(2_299)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            opened.await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                ConnectErrorKind::Timeout
            )))
        ));
        assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);
        assert_eq!(control.abortive_calls.load(Ordering::SeqCst), 0);
        std::fs::remove_file(path).expect("remove deadline config");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_non_default_handshake_value_is_not_hardcoded() {
        let (path, config) = client_deadline_test_config(Some(2_300), Some(3_700));
        let control = Arc::new(PhaseDeadlineControl::default());
        let connector = PhaseDeadlineConnector::new(Arc::clone(&control));
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x14; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = phase_outbound(config.server, &keys, &connector, &clock, &random);
        let application_target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &application_target,
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ));

        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        control.release_connect();
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(3_699)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            opened.await,
            Err(ClientOpenFailure::HandshakeTimeout)
        ));
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);
        assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);
        assert_eq!(control.abortive_calls.load(Ordering::SeqCst), 0);
        std::fs::remove_file(path).expect("remove deadline config");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_open_completes_only_after_request_first_write() {
        let (path, config) = client_deadline_test_config(Some(2_300), Some(3_700));
        let control = Arc::new(PhaseDeadlineControl::default());
        control.release_connect();
        let connector = PhaseDeadlineConnector::new(Arc::clone(&control));
        let keys = SinglePskProvider::new(Aes128Psk::from_bytes([0x15; 16]));
        let clock = SystemClock::new();
        let random = FixedRandom;
        let outbound = phase_outbound(config.server, &keys, &connector, &clock, &random);
        let application_target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let mut opened = Box::pin(open_with_deadlines(
            &outbound,
            &application_target,
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ));

        assert_open_pending(&mut opened).await;
        assert!(control.write_polls.load(Ordering::SeqCst) >= 1);
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 0);
        control.release_write();
        let flow = opened.await.expect("first-write completion opens flow");
        assert_eq!(control.completed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            flow.local_endpoint(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152)
        );
        drop(flow);
        assert_eq!(control.dropped_streams.load(Ordering::SeqCst), 1);
        assert_eq!(control.abortive_calls.load(Ordering::SeqCst), 0);
        std::fs::remove_file(path).expect("remove deadline config");
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
            stream: Mutex::new(Some(EndpointIo {
                inner,
                endpoint,
                aborts: Arc::new(AtomicUsize::new(0)),
            })),
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
            assert_eq!(
                observation_for_error(ShadowsocksError::Connect(kind)),
                (Stage::Shadowsocks, Outcome::Failed, expected)
            );
        }
        assert_eq!(
            observation_for_terminal(FlowTerminal::Normal),
            (Stage::Relay, Outcome::Completed, None)
        );
        for (reason, expected) in detection_cases() {
            assert_eq!(reason_for_detection(reason), expected);
            assert_eq!(
                observation_for_terminal(FlowTerminal::Detection(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected))
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
        type Stream = EndpointIo;

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
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve address");
        let address = match listener.local_addr().expect("reserved address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 reservation"),
        };
        drop(listener);
        address
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
            "schema_version = 1\n\
             [client]\n\
             listen = \"{listen}\"\n\
             server = \"{server}\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n"
        );
        std::fs::write(&path, source).expect("client test config");
        let config = ferrum2_config::load_client(&path).expect("validated client test config");
        (path, config)
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
        assert_eq!(
            final_snapshot.active_supervisor_children,
            baseline.active_supervisor_children
        );
        assert_eq!(final_snapshot.connection_tasks, baseline.connection_tasks);
        assert_eq!(final_snapshot.owned_buffers, baseline.owned_buffers);
        assert_eq!(final_snapshot.owned_permits, baseline.owned_permits);
        assert_eq!(final_snapshot.listeners, baseline.listeners);
        assert_eq!(
            final_snapshot.process_forced_roots,
            baseline.process_forced_roots + 1
        );
        assert_eq!(
            final_snapshot.forced_shutdowns,
            baseline.forced_shutdowns + 1,
            "phase-aware TCP root did not explicitly force and reap its child"
        );
        std::fs::remove_file(config_path).expect("remove client test config");
    }
}
