use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ferrum2_config::{LoggingLevel, RuntimeConfig, ValidatedServerConfig};
use ferrum2_core::{
    AbortiveClose, ConnectErrorKind, Inbound as _, LocalEndpoint, Outbound as _, SessionReply as _,
};
use ferrum2_crypto::{SinglePskProvider, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
    json_subscriber,
};
use ferrum2_runtime::{
    BoundedSupervisor, CancellationToken, DirectOutbound, OwnerRegistry, RelayFailure,
    RelayRunError, RuntimeTcpStream, TcpConnector, relay_lifecycle,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, PlainDuplex, ProtocolReason, ShadowsocksError,
    ShadowsocksTcpInbound, TcpReplayStore, TransportIo,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpSocket};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    Observability,
    Runtime,
    Listener,
    Replay,
    Supervisor,
}

pub(crate) fn run(config: ValidatedServerConfig) -> Result<(), RunError> {
    let subscriber = json_subscriber(std::io::stderr, log_level(config.logging.level));
    tracing::subscriber::set_global_default(subscriber).map_err(|_| RunError::Observability)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::Runtime)?;
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
    let listener = bind_listener(
        config.listen,
        u32::from(config.runtime.listen_backlog.get()),
    )?;
    let metrics = Arc::new(Metrics::new());
    let replay = TcpReplayStore::new(config.replay.capacity).map_err(|_| RunError::Replay)?;
    let context = Arc::new(ServerContext {
        direct: DirectOutbound::new(TcpConnector::new(config.runtime.connect_timeout)),
        keys: SinglePskProvider::new(config.psk),
        clock: SystemClock::new(),
        random: SystemRandom,
        replay,
        runtime: config.runtime,
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
    });
    let supervisor = BoundedSupervisor::new(
        listener,
        usize::from(config.runtime.max_connections.get()),
        config.runtime.shutdown_grace,
        registry.clone(),
    )
    .map_err(|_| RunError::Supervisor)?;
    let handler = move |stream, cancellation| {
        let context = Arc::clone(&context);
        async move {
            server_connection(stream, cancellation, context).await;
        }
    };

    if let Some(metrics_config) = config.metrics {
        let metrics_listener = bind_listener(metrics_config.listen, 16)?;
        let rendered_metrics = Arc::clone(&metrics);
        let endpoint = ferrum2_runtime::MetricsEndpoint::new(
            metrics_listener,
            move || rendered_metrics.encode_text().unwrap_or_default(),
            registry,
        );
        let (shutdown_sender, proxy_shutdown) = tokio::sync::watch::channel(false);
        let metrics_shutdown = proxy_shutdown.clone();
        let proxy = supervisor.run_until(handler, wait_for_shutdown(proxy_shutdown));
        let metrics_server = endpoint.run_until(wait_for_shutdown(metrics_shutdown));
        tokio::pin!(proxy);
        tokio::pin!(metrics_server);
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {
                shutdown_sender.send_replace(true);
                let (proxy_result, metrics_result) = tokio::join!(proxy, metrics_server);
                proxy_result.map_err(|_| RunError::Supervisor)?;
                metrics_result.map_err(|_| RunError::Supervisor)?;
            }
            proxy_result = &mut proxy => {
                shutdown_sender.send_replace(true);
                let metrics_result = metrics_server.await;
                proxy_result.map_err(|_| RunError::Supervisor)?;
                metrics_result.map_err(|_| RunError::Supervisor)?;
            }
            metrics_result = &mut metrics_server => {
                shutdown_sender.send_replace(true);
                let proxy_result = proxy.await;
                metrics_result.map_err(|_| RunError::Supervisor)?;
                proxy_result.map_err(|_| RunError::Supervisor)?;
            }
        }
    } else {
        supervisor
            .run_until(handler, shutdown)
            .await
            .map_err(|_| RunError::Supervisor)?;
    }
    Ok(())
}

fn bind_listener(address: std::net::SocketAddrV4, backlog: u32) -> Result<TcpListener, RunError> {
    let socket = TcpSocket::new_v4().map_err(|_| RunError::Listener)?;
    socket
        .bind(SocketAddr::V4(address))
        .map_err(|_| RunError::Listener)?;
    socket.listen(backlog).map_err(|_| RunError::Listener)
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

struct ServerContext {
    direct: DirectOutbound<TcpConnector>,
    keys: SinglePskProvider,
    clock: SystemClock,
    random: SystemRandom,
    replay: TcpReplayStore,
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
        &context.keys,
        &context.clock,
        &context.random,
        &context.replay,
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
    let opened = tokio::select! {
        _ = cancellation.cancelled() => {
            context.metrics.active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        result = context.direct.open(&target) => result,
    };
    let mut target_stream = match opened {
        Ok(stream) => stream,
        Err(error) => {
            let kind = error.kind();
            let (stage, outcome, reason) = observation_for_direct_connect(kind);
            record_failure(&context, stage, reason, outcome);
            let _ = reply.failed(kind).await;
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
    };
    let initial_payload_bytes = match forward_initial_payload(
        &mut target_stream,
        &initial_payload,
        context.runtime.idle_timeout,
        cancellation.cancelled(),
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(failure) => {
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
    let _ = reply.succeeded(target_stream.local_endpoint()).await;
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
    C: std::future::Future<Output = ()>,
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
    if let Ok(entries) = context.replay.entry_count()
        && let Ok(entries) = u32::try_from(entries)
    {
        context.metrics.set_replay_entries(entries);
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

    use ferrum2_core::{ConnectError, Connector, LocalEndpoint, Outbound, TargetAddr};
    use ferrum2_crypto::Aes128Psk;
    use ferrum2_shadowsocks::ClientTcpOutbound;
    use ferrum2_shadowsocks::TransportPhase;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    use super::*;

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
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003),
            })),
            failure,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        (outbound, gate, bytes, write_calls)
    }

    #[tokio::test]
    async fn adapter_contract_direct_connect_precedes_exact_partial_initial_payload_forward() {
        let (outbound, gate, bytes, write_calls) = controlled_outbound(2, None, None);
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let task_outbound = Arc::clone(&outbound);
        let task = tokio::spawn(async move {
            let mut stream = task_outbound.open(&target).await?;
            let bytes = forward_initial_payload(
                &mut stream,
                b"initial",
                std::time::Duration::from_secs(5),
                std::future::pending(),
            )
            .await
            .expect("prefix");
            Ok::<_, ConnectError>((stream, bytes))
        });

        tokio::task::yield_now().await;
        assert_eq!(outbound.calls.load(Ordering::SeqCst), 1);
        assert!(bytes.lock().expect("recording bytes").is_empty());
        assert_eq!(write_calls.load(Ordering::SeqCst), 0);

        gate.notify_one();
        let (opened, initial_payload_bytes) = task
            .await
            .expect("open task")
            .expect("connect and initial payload");
        assert_eq!(
            bytes.lock().expect("recording bytes").as_slice(),
            b"initial"
        );
        assert!(write_calls.load(Ordering::SeqCst) > 1);
        assert_eq!(initial_payload_bytes, 7);
        assert_eq!(
            opened.local_endpoint(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003)
        );
    }

    #[tokio::test]
    async fn adapter_contract_connect_and_prefix_failures_never_report_opened_stream() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let (outbound, gate, bytes, write_calls) =
            controlled_outbound(2, None, Some(ConnectErrorKind::ConnectionRefused));
        let task_outbound = Arc::clone(&outbound);
        let task_target = target.clone();
        let task = tokio::spawn(async move { task_outbound.open(&task_target).await });
        tokio::task::yield_now().await;
        assert!(bytes.lock().expect("recording bytes").is_empty());
        gate.notify_one();
        assert!(matches!(
            task.await.expect("connect task"),
            Err(error) if error.kind() == ConnectErrorKind::ConnectionRefused
        ));
        assert_eq!(write_calls.load(Ordering::SeqCst), 0);

        let (outbound, gate, bytes, _write_calls) = controlled_outbound(2, Some(1), None);
        let task = tokio::spawn(async move {
            let mut stream = outbound.open(&target).await.expect("connected");
            forward_initial_payload(
                &mut stream,
                b"initial",
                std::time::Duration::from_secs(5),
                std::future::pending(),
            )
            .await
        });
        gate.notify_one();
        assert!(matches!(
            task.await.expect("prefix task"),
            Err(PrefixFailure {
                kind: RelayRunError::Io,
                bytes: 2,
            })
        ));
        assert_eq!(bytes.lock().expect("recording bytes").as_slice(), b"in");
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

    #[tokio::test]
    async fn lifecycle_composition_contract_prefix_cancel_retains_partial_count() {
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        let ready = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(Mutex::new(None));
        let mut writer = GatedPrefixWriter {
            ready,
            calls,
            waker,
            max_write: 2,
            fail_after: None,
            zero_after: None,
        };
        let mut prefix = Box::pin(forward_initial_payload(
            &mut writer,
            b"four",
            std::time::Duration::from_secs(5),
            async {
                let _ = cancelled.await;
            },
        ));
        tokio::select! {
            biased;
            result = &mut prefix => panic!("prefix ended before cancellation: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        cancel.send(()).expect("cancel prefix");
        assert_eq!(
            prefix.await,
            Err(PrefixFailure {
                kind: RelayRunError::Cancelled,
                bytes: 2,
            })
        );
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
                std::future::pending(),
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
                std::future::pending(),
            )
            .await,
            Ok(0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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

    fn server_test_config(listen: SocketAddrV4) -> (PathBuf, ValidatedServerConfig) {
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
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n"
        );
        std::fs::write(&path, source).expect("server test config");
        let config = ferrum2_config::load_server(&path).expect("validated server test config");
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
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task_registry = registry.clone();
        let run_task = tokio::spawn(async move {
            run_with_registry(config, task_registry, async {
                let _ = shutdown_receiver.await;
            })
            .await
        });
        wait_until_bound(listen).await;

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
        assert_eq!(
            final_snapshot.forced_shutdowns,
            baseline.forced_shutdowns + 1
        );
        std::fs::remove_file(config_path).expect("remove server test config");
    }
}
