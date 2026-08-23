use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use ferrum2_config::{CompiledRoute, RouteAction, RouteProtocol, RuntimeConfig, Sniffers};
use ferrum2_core::route::Network;
use ferrum2_core::{
    ConnectError, ConnectErrorKind, DomainName, Inbound as _, LocalEndpoint, SessionReply as _,
    TargetAddr, TargetHostRef,
};
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_observability::{
    Direction, Event, Inbound, InterfaceResolutionResult, InterfaceResolutionSource, LogLevel,
    Metrics, Outcome, Reason, Role, RuleMatchResult, RuleMatchType, RuleProgram, RuleSource, Stage,
    TraceRecord, Transport as ObservationTransport, emit,
};
use ferrum2_rule::{
    RouteMatchObservation as EngineMatchObservation, RouteMatchSource as EngineMatchSource,
    RouteMatchType as EngineMatchType, RouteMetadata, RouteProgramAction, RouteTable,
    RuleCompileError, RuleEvaluationScratch,
};
#[cfg(not(test))]
use ferrum2_runtime::SystemNetworkSocketOperations;
use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, CancellationToken, DialOptions, GenerationBoundTcpStream,
    InterfaceResolutionErrorKind, InterfaceSelectionSource, MAX_RESOLVED_CANDIDATES,
    NetworkInterfaceResolver, NetworkResetCoordinator, NetworkResetLimits,
    NetworkRuntimeResourceAdmissionError, NetworkSnapshot, NetworkSnapshotPublisher,
    NetworkSocketService, NetworkSocketServiceError, OwnerRegistry, PrefixDecision,
    PreparedProcessRoot, ProcessCancellation, ProcessFuture, RelayRunError, RouteNetworkOptions,
    RuntimeTcpStream, SniffPrefix, SniffPrefixOutcome, SystemNetworkSocketError, TcpResolver,
    collect_sniff_prefix, relay_lifecycle,
};
use ferrum2_shadowsocks::{MethodKeyAdapter, PlainDuplex, ShadowsocksTcpInbound, TcpReplayStore};
use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress, Protocol, Transport};
#[cfg(not(test))]
use ferrum2_wintun::{WindowsNetworkInterfaceCatalog, WindowsResolvedSocketBinder};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::RunError;
use super::dns_egress;
use super::observation::{
    finish_relay, observation_for_direct_connect, observation_for_error, record_failure,
    record_sniff, run_error_for_supervisor, update_replay_metric,
};
use super::tokio_io::{TokioFramed, TokioTransport};

#[cfg(not(test))]
pub(super) type ServerNetworkSocketService = NetworkSocketService<
    WindowsNetworkInterfaceCatalog,
    SystemNetworkSocketOperations<WindowsResolvedSocketBinder>,
>;

#[cfg(test)]
pub(super) type ServerNetworkSocketService =
    NetworkSocketService<TestNetworkCatalog, TestNetworkSocketOperations>;

#[cfg(not(test))]
pub(super) fn prepare_server_network_socket_service(
    registry: &OwnerRegistry,
    metrics: &Metrics,
) -> Result<Arc<ServerNetworkSocketService>, RunError> {
    let catalog = WindowsNetworkInterfaceCatalog::system();
    let initial =
        Arc::new(NetworkSnapshot::capture(1, &catalog).map_err(|_| RunError::StartupRuntime)?);
    metrics.set_network_generation(initial.generation());
    let coordinator = NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(initial),
        NetworkResetLimits::default(),
        registry.clone(),
    );
    Ok(Arc::new(ServerNetworkSocketService::new(
        coordinator,
        NetworkInterfaceResolver::new(catalog),
        SystemNetworkSocketOperations::new(WindowsResolvedSocketBinder),
    )))
}

#[cfg(test)]
pub(super) fn prepare_server_network_socket_service(
    registry: &OwnerRegistry,
    metrics: &Metrics,
) -> Result<Arc<ServerNetworkSocketService>, RunError> {
    let binding = ferrum2_runtime::InterfaceBinding::new(
        "test-loopback",
        1,
        1,
        [
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ],
    )
    .map_err(|_| RunError::StartupRuntime)?;
    let initial = Arc::new(
        NetworkSnapshot::new(1, Some(binding.clone()), Some(binding))
            .map_err(|_| RunError::StartupRuntime)?,
    );
    metrics.set_network_generation(initial.generation());
    let coordinator = NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(initial),
        NetworkResetLimits::default(),
        registry.clone(),
    );
    Ok(Arc::new(ServerNetworkSocketService::new(
        coordinator,
        NetworkInterfaceResolver::new(TestNetworkCatalog),
        TestNetworkSocketOperations,
    )))
}

#[cfg(test)]
pub(super) struct TestNetworkCatalog;

#[cfg(test)]
impl ferrum2_runtime::NetworkInterfaceCatalog for TestNetworkCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<
        Vec<ferrum2_runtime::NetworkInterfaceObservation>,
        ferrum2_runtime::NetworkInterfaceCatalogError,
    > {
        Err(ferrum2_runtime::NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        _: std::net::SocketAddr,
    ) -> Result<ferrum2_runtime::SystemBestRoute, ferrum2_runtime::NetworkInterfaceCatalogError>
    {
        ferrum2_runtime::SystemBestRoute::new(1, 1)
            .map_err(|_| ferrum2_runtime::NetworkInterfaceCatalogError)
    }
}

#[cfg(test)]
pub(super) struct TestNetworkSocketOperations;

#[cfg(test)]
impl ferrum2_runtime::NetworkSocketOperations for TestNetworkSocketOperations {
    type TcpSocket = tokio::net::TcpSocket;
    type TcpStream = RuntimeTcpStream;
    type UdpSocket = tokio::net::UdpSocket;
    type Error = SystemNetworkSocketError<ferrum2_wintun::Error>;

    fn prepare_tcp(
        &self,
        destination: std::net::SocketAddr,
        _: &ferrum2_runtime::ResolvedInterface,
    ) -> Result<Self::TcpSocket, Self::Error> {
        match destination {
            std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }
        .map_err(SystemNetworkSocketError::Socket)
    }

    async fn connect_tcp(
        &self,
        socket: Self::TcpSocket,
        destination: std::net::SocketAddr,
    ) -> Result<Self::TcpStream, Self::Error> {
        let stream = socket
            .connect(destination)
            .await
            .map_err(SystemNetworkSocketError::Socket)?;
        RuntimeTcpStream::from_connected(stream).map_err(SystemNetworkSocketError::Socket)
    }

    fn prepare_udp(
        &self,
        destination: std::net::SocketAddr,
        _: &ferrum2_runtime::ResolvedInterface,
    ) -> Result<Self::UdpSocket, Self::Error> {
        let local = match destination {
            std::net::SocketAddr::V4(_) => {
                std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
            std::net::SocketAddr::V6(_) => {
                std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
            }
        };
        let socket = std::net::UdpSocket::bind(local).map_err(SystemNetworkSocketError::Socket)?;
        socket
            .set_nonblocking(true)
            .map_err(SystemNetworkSocketError::Socket)?;
        tokio::net::UdpSocket::from_std(socket).map_err(SystemNetworkSocketError::Socket)
    }

    async fn connect_udp(
        &self,
        socket: Self::UdpSocket,
        destination: std::net::SocketAddr,
    ) -> Result<Self::UdpSocket, Self::Error> {
        socket
            .connect(destination)
            .await
            .map_err(SystemNetworkSocketError::Socket)?;
        Ok(socket)
    }
}

pub(super) struct ServerRouting {
    pub(super) legacy: RouteTable,
    pub(super) program: Option<CompiledRoute>,
    pub(super) outbound_count: usize,
}

pub(super) struct RouteProgramObservation<'a> {
    metrics: &'a Metrics,
    candidates: usize,
    match_ns: u64,
}

impl<'a> RouteProgramObservation<'a> {
    pub(super) const fn new(metrics: &'a Metrics) -> Self {
        Self {
            metrics,
            candidates: 0,
            match_ns: 0,
        }
    }

    pub(super) fn record_step(&mut self, candidates: usize, elapsed: Duration) {
        self.candidates = self.candidates.saturating_add(candidates);
        self.match_ns = self
            .match_ns
            .saturating_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
    }

    pub(super) fn record_matches(&self, observation: EngineMatchObservation) {
        for source in EngineMatchSource::ALL {
            for r#type in EngineMatchType::ALL {
                if !observation.evaluated(source, r#type) {
                    continue;
                }
                let result = if observation.matched(source, r#type) {
                    RuleMatchResult::Matched
                } else {
                    RuleMatchResult::Missed
                };
                let source = match source {
                    EngineMatchSource::Inline => RuleSource::Inline,
                    EngineMatchSource::RuleSet => RuleSource::RuleSet,
                };
                let r#type = match r#type {
                    EngineMatchType::Domain => RuleMatchType::Domain,
                    EngineMatchType::DomainSuffix => RuleMatchType::DomainSuffix,
                    EngineMatchType::DomainKeyword => RuleMatchType::DomainKeyword,
                    EngineMatchType::IpCidr => RuleMatchType::IpCidr,
                    EngineMatchType::Scalar => RuleMatchType::Scalar,
                };
                self.metrics.route_match(source, r#type, result);
            }
        }
    }
}

impl Drop for RouteProgramObservation<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_rule_program_candidate_count(RuleProgram::Route, self.candidates);
        self.metrics
            .observe_rule_program_match_ns(RuleProgram::Route, self.match_ns);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerTerminalRoute {
    Direct(usize),
    Reject,
}

impl ServerRouting {
    pub(super) fn program(&self) -> Option<&CompiledRoute> {
        self.program.as_ref()
    }

    pub(super) fn route_scratch(&self) -> Result<Option<RuleEvaluationScratch>, RuleCompileError> {
        self.program
            .as_ref()
            .map(CompiledRoute::evaluation_scratch)
            .transpose()
    }

    pub(super) fn legacy(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> ServerTerminalRoute {
        let outbound = self.legacy.select(inbound, network, target);
        if outbound < self.outbound_count {
            ServerTerminalRoute::Direct(outbound)
        } else {
            ServerTerminalRoute::Reject
        }
    }

    pub(super) fn terminal(&self, action: &RouteAction) -> ServerTerminalRoute {
        match action {
            RouteAction::Route(handle) => match handle.snapshot().hops() {
                [outbound] if *outbound < self.outbound_count => {
                    ServerTerminalRoute::Direct(*outbound)
                }
                _ => ServerTerminalRoute::Reject,
            },
            RouteAction::Sniff(_) | RouteAction::HijackDns | RouteAction::Reject => {
                ServerTerminalRoute::Reject
            }
        }
    }
}

pub(super) fn sniff_order(sniffers: &Sniffers, network: Network) -> Vec<Protocol> {
    match sniffers {
        Sniffers::Default => match network {
            Network::Tcp => vec![Protocol::Dns, Protocol::Tls, Protocol::Http],
            Network::Udp => vec![Protocol::Dns],
        },
        Sniffers::Explicit(protocols) => protocols
            .iter()
            .copied()
            .map(|protocol| match protocol {
                RouteProtocol::Dns => Protocol::Dns,
                RouteProtocol::Tls => Protocol::Tls,
                RouteProtocol::Http => Protocol::Http,
            })
            .collect(),
    }
}

pub(super) fn route_metadata(
    progress: SniffProgress,
) -> (Option<RouteProtocol>, Option<DomainName>) {
    let (protocol, domain) = match progress {
        SniffProgress::Matched(SniffMetadata::Dns { domain }) => (RouteProtocol::Dns, Some(domain)),
        SniffProgress::Matched(SniffMetadata::Tls { domain }) => (RouteProtocol::Tls, domain),
        SniffProgress::Matched(SniffMetadata::Http { domain }) => (RouteProtocol::Http, domain),
        SniffProgress::NeedMore | SniffProgress::NoMatch | SniffProgress::Invalid => {
            return (None, None);
        }
    };
    match domain.map(|domain| DomainName::new(&domain)).transpose() {
        Ok(domain) => (Some(protocol), domain),
        Err(_) => (None, None),
    }
}

pub(super) struct ServerTcpListeners {
    pub(super) listeners: Vec<TcpListener>,
    pub(super) next: AtomicUsize,
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

pub(super) struct ServerTcpRoot {
    pub(super) supervisor: Option<BoundedSupervisor<ServerTcpListeners>>,
    pub(super) contexts: Arc<Vec<Arc<ServerContext>>>,
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

pub(super) struct ServerContext {
    pub(super) inbound: usize,
    pub(super) routing: Arc<ServerRouting>,
    pub(super) keys: Arc<MethodKeyAdapter<MethodSinglePskProvider>>,
    pub(super) clock: Arc<SystemClock>,
    pub(super) random: SystemRandom,
    pub(super) replay: Arc<TcpReplayStore>,
    pub(super) runtime: RuntimeConfig,
    pub(super) direct_resolvers: Arc<[dns_egress::ServerDnsResolver]>,
    pub(super) outbound_dial_options: Arc<[DialOptions]>,
    pub(super) route_network: Arc<RouteNetworkOptions>,
    pub(super) network_sockets: Arc<ServerNetworkSocketService>,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
}

struct ServerNetworkTcpOutbound {
    sockets: Arc<ServerNetworkSocketService>,
    resolver: dns_egress::ServerDnsResolver,
    outbound: DialOptions,
    route: Arc<RouteNetworkOptions>,
    connect_timeout: Duration,
    metrics: Arc<Metrics>,
}

impl ferrum2_core::Outbound for ServerNetworkTcpOutbound {
    type Stream = GenerationBoundTcpStream<RuntimeTcpStream>;
    type Error = ConnectError;

    async fn open(&self, target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        if let Some(address) = target.as_socket_addr() {
            return self.connect_candidate(address, deadline).await;
        }

        let TargetHostRef::Domain(host) = target.host() else {
            return Err(ConnectError::new(ConnectErrorKind::Other));
        };
        let candidates = match tokio::time::timeout_at(
            deadline,
            self.resolver.resolve(host, target.port().get()),
        )
        .await
        {
            Ok(Ok(candidates)) => candidates,
            Ok(Err(_)) => {
                return Err(ConnectError::new(ConnectErrorKind::HostUnreachable));
            }
            Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
        };

        let mut attempted = false;
        let mut last_error = ConnectError::new(ConnectErrorKind::HostUnreachable);
        for address in candidates.into_iter().take(MAX_RESOLVED_CANDIDATES) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectError::new(ConnectErrorKind::Timeout));
            }
            attempted = true;
            match self.connect_candidate(address, deadline).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        if attempted {
            Err(last_error)
        } else {
            Err(ConnectError::new(ConnectErrorKind::HostUnreachable))
        }
    }
}

impl ServerNetworkTcpOutbound {
    async fn connect_candidate(
        &self,
        address: std::net::SocketAddr,
        deadline: tokio::time::Instant,
    ) -> Result<GenerationBoundTcpStream<RuntimeTcpStream>, ConnectError> {
        let result = match tokio::time::timeout_at(
            deadline,
            self.sockets
                .connect_tcp(&self.outbound, self.route.as_ref(), address),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
        };
        match result {
            Ok(stream) => {
                self.metrics.outbound_interface_resolution(
                    interface_resolution_source(stream.resolved_interface().selection_source()),
                    InterfaceResolutionResult::Success,
                );
                Ok(stream)
            }
            Err(error) => {
                self.metrics.outbound_interface_resolution(
                    interface_resolution_source(error.attempted_source()),
                    interface_resolution_result(&error),
                );
                Err(connect_error_from_network_service(error))
            }
        }
    }
}

pub(super) fn interface_resolution_source(
    source: InterfaceSelectionSource,
) -> InterfaceResolutionSource {
    match source {
        InterfaceSelectionSource::OutboundExplicit => InterfaceResolutionSource::OutboundExplicit,
        InterfaceSelectionSource::AutoDetected => InterfaceResolutionSource::AutoDetected,
        InterfaceSelectionSource::RouteDefault => InterfaceResolutionSource::RouteDefault,
        InterfaceSelectionSource::SystemBestRoute => InterfaceResolutionSource::SystemBestRoute,
    }
}

pub(super) fn interface_resolution_result(
    error: &NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_wintun::Error>>,
) -> InterfaceResolutionResult {
    match error {
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::InterfaceResolution(_)
            | NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged { .. },
        ) => InterfaceResolutionResult::Failure,
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::Preparation { .. }
            | NetworkRuntimeResourceAdmissionError::RuntimeOwnerRegistration { .. },
        )
        | NetworkSocketServiceError::Connection { .. }
        | NetworkSocketServiceError::Cancelled { .. } => InterfaceResolutionResult::Success,
    }
}

fn connect_error_from_network_service(
    error: NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_wintun::Error>>,
) -> ConnectError {
    let kind = match error {
        NetworkSocketServiceError::Connection {
            error: SystemNetworkSocketError::Socket(error),
            ..
        }
        | NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::Preparation {
                error: SystemNetworkSocketError::Socket(error),
                ..
            },
        ) => connect_error_kind_from_io(&error),
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::InterfaceResolution(error),
        ) => match error.kind() {
            InterfaceResolutionErrorKind::ExplicitInterfaceMissing
            | InterfaceResolutionErrorKind::ExplicitInterfaceAmbiguous
            | InterfaceResolutionErrorKind::ExplicitInterfaceUnavailable
            | InterfaceResolutionErrorKind::ExplicitInterfaceWrongFamily
            | InterfaceResolutionErrorKind::SelectedInterfaceWrongFamily
            | InterfaceResolutionErrorKind::SourceAddressUnavailable => {
                ConnectErrorKind::PolicyDenied
            }
            InterfaceResolutionErrorKind::SystemBestRouteUnavailable => {
                ConnectErrorKind::NetworkUnreachable
            }
        },
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged { .. },
        ) => ConnectErrorKind::NetworkUnreachable,
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::Preparation {
                error: SystemNetworkSocketError::Binding(_),
                ..
            }
            | NetworkRuntimeResourceAdmissionError::RuntimeOwnerRegistration { .. },
        )
        | NetworkSocketServiceError::Connection {
            error: SystemNetworkSocketError::Binding(_),
            ..
        }
        | NetworkSocketServiceError::Cancelled { .. } => ConnectErrorKind::Other,
    };
    ConnectError::new(kind)
}

fn connect_error_kind_from_io(error: &io::Error) -> ConnectErrorKind {
    match error.kind() {
        io::ErrorKind::NetworkUnreachable => ConnectErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => ConnectErrorKind::HostUnreachable,
        io::ErrorKind::ConnectionRefused => ConnectErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut => ConnectErrorKind::Timeout,
        io::ErrorKind::PermissionDenied => ConnectErrorKind::PolicyDenied,
        _ => ConnectErrorKind::Other,
    }
}

#[derive(Debug)]
enum TcpRouteFailure {
    Cancelled,
    Read,
    Rule(RuleCompileError),
}

struct TcpRouteSelection<P> {
    terminal: ServerTerminalRoute,
    prefix: TcpRoutePrefix<P>,
}

enum TcpRoutePrefix<P> {
    Initial(P),
    Collected(SniffPrefix<P>),
}

impl<P: AsRef<[u8]>> AsRef<[u8]> for TcpRoutePrefix<P> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Initial(prefix) => prefix.as_ref(),
            Self::Collected(prefix) => prefix.as_ref(),
        }
    }
}

async fn select_tcp_route<F, C, P>(
    context: &ServerContext,
    target: &TargetAddr,
    stream: &mut F,
    initial_payload: P,
    cancellation: C,
) -> Result<TcpRouteSelection<P>, TcpRouteFailure>
where
    F: PlainDuplex + Unpin,
    C: std::future::Future,
    P: AsRef<[u8]>,
{
    let mut prefix = TcpRoutePrefix::Initial(initial_payload);
    let Some(program) = context.routing.program() else {
        return Ok(TcpRouteSelection {
            terminal: context
                .routing
                .legacy(context.inbound, Network::Tcp, target),
            prefix,
        });
    };
    let mut scratch = match program.evaluation_scratch() {
        Ok(scratch) => scratch,
        Err(error) => {
            let _ = stream.mark_abortive_plain();
            return Err(TcpRouteFailure::Rule(error));
        }
    };
    let mut evaluation =
        program.evaluate_with_scratch(context.inbound, Network::Tcp, target, &mut scratch);
    evaluation.enable_match_observation();
    let mut protocol = None;
    let mut domain = None;
    let mut sniffed = false;
    let mut observation = RouteProgramObservation::new(&context.metrics);
    tokio::pin!(cancellation);

    loop {
        let started = Instant::now();
        let action = evaluation
            .next(RouteMetadata::new(protocol, domain.as_ref()))
            .expect("validated route program has one terminal action");
        observation.record_step(evaluation.candidate_visits(), started.elapsed());
        observation.record_matches(evaluation.last_match_observation());
        match action {
            RouteProgramAction::Continue(RouteAction::Sniff(sniffers)) if !sniffed => {
                sniffed = true;
                let order = sniff_order(sniffers, Network::Tcp);
                let max_bytes = program.sniff.max_bytes;
                let classification_horizon = max_bytes
                    .checked_add(1)
                    .expect("validated sniff maximum has one-byte horizon");
                let mut progress = if prefix.as_ref().len() > max_bytes {
                    SniffProgress::NeedMore
                } else {
                    ferrum2_sniff::sniff(
                        prefix.as_ref(),
                        classification_horizon,
                        Transport::Tcp,
                        target.port().get(),
                        &order,
                    )
                };
                let mut collector = None;
                if progress == SniffProgress::NeedMore {
                    let initial = match prefix {
                        TcpRoutePrefix::Initial(initial) => initial,
                        TcpRoutePrefix::Collected(_) => {
                            unreachable!("validated route program sniffs at most once")
                        }
                    };
                    let collected = collect_sniff_prefix(
                        initial,
                        max_bytes,
                        program.sniff.max_aggregate_bytes,
                        &context.registry,
                        program.sniff.timeout,
                        cancellation.as_mut(),
                        |context, destination| {
                            Pin::new(&mut *stream).poll_read_plain(context, destination)
                        },
                        |bytes| {
                            if ferrum2_sniff::sniff(
                                bytes,
                                classification_horizon,
                                Transport::Tcp,
                                target.port().get(),
                                &order,
                            ) == SniffProgress::NeedMore
                            {
                                PrefixDecision::ReadMore
                            } else {
                                PrefixDecision::Complete
                            }
                        },
                    )
                    .await;
                    let outcome = collected.outcome();
                    match outcome {
                        SniffPrefixOutcome::Complete => {
                            progress = ferrum2_sniff::sniff(
                                collected.as_ref(),
                                max_bytes,
                                Transport::Tcp,
                                target.port().get(),
                                &order,
                            );
                        }
                        SniffPrefixOutcome::Timeout
                        | SniffPrefixOutcome::Limit
                        | SniffPrefixOutcome::Unavailable => {
                            progress = SniffProgress::NoMatch;
                        }
                        SniffPrefixOutcome::Cancelled | SniffPrefixOutcome::ReadError => {
                            record_sniff(
                                &context.metrics,
                                ObservationTransport::Tcp,
                                progress,
                                Some(outcome),
                            );
                            let _ = stream.mark_abortive_plain();
                            return Err(match outcome {
                                SniffPrefixOutcome::Cancelled => TcpRouteFailure::Cancelled,
                                SniffPrefixOutcome::ReadError => TcpRouteFailure::Read,
                                _ => unreachable!("closed terminal prefix outcome"),
                            });
                        }
                    }
                    collector = Some(outcome);
                    prefix = TcpRoutePrefix::Collected(collected);
                }
                record_sniff(
                    &context.metrics,
                    ObservationTransport::Tcp,
                    progress.clone(),
                    collector,
                );
                (protocol, domain) = route_metadata(progress);
            }
            RouteProgramAction::Continue(RouteAction::Sniff(_)) => {}
            RouteProgramAction::Continue(_) => {
                let _ = stream.mark_abortive_plain();
                return Ok(TcpRouteSelection {
                    terminal: ServerTerminalRoute::Reject,
                    prefix,
                });
            }
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => {
                let terminal = context.routing.terminal(action);
                if terminal == ServerTerminalRoute::Reject {
                    let _ = stream.mark_abortive_plain();
                }
                return Ok(TcpRouteSelection { terminal, prefix });
            }
        }
    }
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
        mut stream,
        initial_payload,
        reply,
    } = session;
    let selection = select_tcp_route(
        &context,
        &target,
        &mut stream,
        initial_payload,
        cancellation.cancelled(),
    )
    .await;
    let selection = match selection {
        Ok(selection) => selection,
        Err(TcpRouteFailure::Cancelled) => {
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(TcpRouteFailure::Read) => {
            record_failure(&context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
        Err(TcpRouteFailure::Rule(error)) => {
            let _category = super::run_error_for_rule_compile(error);
            record_failure(
                &context,
                Stage::Config,
                Reason::ConfigSemantic,
                Outcome::Failed,
            );
            context
                .metrics
                .active_connections_dec(Role::Server, Inbound::Shadowsocks);
            return;
        }
    };
    let ServerTerminalRoute::Direct(outbound) = selection.terminal else {
        context
            .metrics
            .active_connections_dec(Role::Server, Inbound::Shadowsocks);
        return;
    };
    let (Some(resolver), Some(dial_options)) = (
        context.direct_resolvers.get(outbound).cloned(),
        context.outbound_dial_options.get(outbound).cloned(),
    ) else {
        record_failure(
            &context,
            Stage::Config,
            Reason::ConfigSemantic,
            Outcome::Failed,
        );
        let _ = reply.failed(ConnectErrorKind::PolicyDenied).await;
        context
            .metrics
            .active_connections_dec(Role::Server, Inbound::Shadowsocks);
        return;
    };
    let prefix = selection.prefix;
    let direct = ServerNetworkTcpOutbound {
        sockets: Arc::clone(&context.network_sockets),
        resolver: resolver.for_inbound(context.inbound),
        outbound: dial_options,
        route: Arc::clone(&context.route_network),
        connect_timeout: context.runtime.connect_timeout,
        metrics: Arc::clone(&context.metrics),
    };
    let opened = open_and_prefix(
        &direct,
        &target,
        prefix.as_ref(),
        context.runtime.idle_timeout,
        cancellation.cancelled(),
    )
    .await;
    drop(prefix);
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::task::Waker;
    use std::time::Duration;

    use ferrum2_core::{ConnectError, Outbound};
    use tokio::sync::Notify;

    use super::*;
    use crate::run::test_support::*;

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
        let mut runtime = String::from("[runtime]\n");
        if let Some(value) = idle_timeout_ms {
            runtime.push_str(&format!("idle_timeout_ms = {value}\n"));
        }
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"proxy\"\n\
             listen = \"127.0.0.1:42001\"\n\
             outbound = \"direct\"\n\
             [[outbounds]]\n\
             tag = \"direct\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             {runtime}"
        );
        server_test_config_source("deadline", &source)
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
}
