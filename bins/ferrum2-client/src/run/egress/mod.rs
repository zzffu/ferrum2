mod tcp;
mod udp;

#[cfg(any(windows, test))]
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{
    ConnectError, ConnectErrorKind, Connector, LocalEndpoint, TargetAddr, TargetHostRef,
};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom};
#[cfg(test)]
use ferrum2_dns::{ApplicationResolver, DnsStrategy};
#[cfg(any(windows, test))]
use ferrum2_observability::{InterfaceResolutionResult, InterfaceResolutionSource, Metrics};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::NetworkResetCoordinator;
use ferrum2_runtime::{
    ApplicationResolverAdapter, DialOptions, MAX_RESOLVED_CANDIDATES, RouteNetworkOptions,
    TcpResolver,
};
#[cfg(any(windows, test))]
use ferrum2_runtime::{
    InterfaceResolutionErrorKind, InterfaceSelectionSource, NetworkRuntimeResourceAdmissionError,
    NetworkSocketServiceError, SystemNetworkSocketError,
};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};
use ferrum2_shadowsocks::{MethodKeyAdapter, ShadowsocksError, TransportIo};

use super::RunError;
#[cfg(any(not(windows), test))]
use super::tokio_io::TokioConnector;

pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    composed_udp_request_limit, composed_udp_response_limit,
};

pub(super) enum ClientOutboundContext {
    Shadowsocks(ClientShadowsocksContext),
    Direct { dial_options: DialOptions },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientRequestOrigin {
    Socks,
    Tun,
    Dns,
    RuleSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedEgress {
    Direct {
        outbound: Option<usize>,
    },
    Shadowsocks {
        first_outbound: usize,
        first_server: SocketAddr,
    },
}

const MAX_CLIENT_EGRESS_RESET_TARGETS: usize = ferrum2_runtime::MAX_NETWORK_RESET_HOOKS;
const MAX_CLIENT_DNS_RESET_ACTIONS: usize = 8;

pub(super) type ClientDnsResetAction = dyn Fn() -> usize + Send + Sync;

struct ClientEgressNetworkResetState {
    udp_manager: Option<ferrum2_runtime::UdpSessionManager>,
    dns_actions: std::sync::Mutex<Vec<std::sync::Weak<ClientDnsResetAction>>>,
}

impl ClientEgressNetworkResetState {
    fn new(udp: Option<&ClientUdpContext>) -> Self {
        Self {
            udp_manager: udp.map(|udp| udp.manager.clone()),
            dns_actions: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn register_dns_action(&self, action: &Arc<ClientDnsResetAction>) -> Result<(), ()> {
        let mut actions = self
            .dns_actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        actions.retain(|registered| registered.strong_count() != 0);
        if actions.len() >= MAX_CLIENT_DNS_RESET_ACTIONS {
            return Err(());
        }
        actions.push(Arc::downgrade(action));
        Ok(())
    }

    fn reset(&self) -> usize {
        let actions = {
            let mut registered = self
                .dns_actions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut actions = Vec::with_capacity(registered.len());
            registered.retain(|action| match action.upgrade() {
                Some(action) => {
                    actions.push(action);
                    true
                }
                None => false,
            });
            actions
        };
        let pooled = actions
            .into_iter()
            .fold(0_usize, |total, action| total.saturating_add(action()));
        pooled.saturating_add(
            self.udp_manager
                .as_ref()
                .map_or(0, ferrum2_runtime::UdpSessionManager::reset_all),
        )
    }
}

#[derive(Clone, Default)]
struct ClientNetworkResetHub {
    inner: Arc<std::sync::Mutex<ClientNetworkResetHubState>>,
}

#[derive(Default)]
struct ClientNetworkResetHubState {
    next_id: u64,
    targets: std::collections::BTreeMap<u64, std::sync::Weak<ClientEgressNetworkResetState>>,
}

impl ClientNetworkResetHub {
    fn register(
        &self,
        target: &Arc<ClientEgressNetworkResetState>,
    ) -> Result<ClientNetworkResetTargetRegistration, ()> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.targets.retain(|_, target| target.strong_count() != 0);
        if state.targets.len() >= MAX_CLIENT_EGRESS_RESET_TARGETS {
            return Err(());
        }
        let id = state.next_id;
        state.next_id = state.next_id.checked_add(1).ok_or(())?;
        state.targets.insert(id, Arc::downgrade(target));
        Ok(ClientNetworkResetTargetRegistration {
            hub: Arc::downgrade(&self.inner),
            id,
        })
    }

    fn reset(&self) -> usize {
        let targets = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut targets = Vec::with_capacity(state.targets.len());
            state.targets.retain(|_, target| match target.upgrade() {
                Some(target) => {
                    targets.push(target);
                    true
                }
                None => false,
            });
            targets
        };
        targets.into_iter().fold(0_usize, |total, target| {
            total.saturating_add(target.reset())
        })
    }
}

struct ClientNetworkResetTargetRegistration {
    hub: std::sync::Weak<std::sync::Mutex<ClientNetworkResetHubState>>,
    id: u64,
}

impl Drop for ClientNetworkResetTargetRegistration {
    fn drop(&mut self) {
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        hub.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .targets
            .remove(&self.id);
    }
}

#[cfg(all(windows, not(test)))]
type ClientPlatformNetworkSocketService = ferrum2_runtime::NetworkSocketService<
    ferrum2_wintun::WindowsNetworkInterfaceCatalog,
    ferrum2_runtime::SystemNetworkSocketOperations<ferrum2_wintun::WindowsResolvedSocketBinder>,
>;

#[cfg(all(windows, not(test)))]
pub(super) struct ClientNetworkSocketService {
    inner: ClientPlatformNetworkSocketService,
    metrics: Arc<Metrics>,
    reset_hub: ClientNetworkResetHub,
}

#[cfg(all(windows, not(test)))]
impl ClientNetworkSocketService {
    pub(super) fn new(
        coordinator: NetworkResetCoordinator,
        catalog: ferrum2_wintun::WindowsNetworkInterfaceCatalog,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            inner: ferrum2_runtime::NetworkSocketService::new(
                coordinator,
                ferrum2_runtime::NetworkInterfaceResolver::new(catalog),
                ferrum2_runtime::SystemNetworkSocketOperations::new(
                    ferrum2_wintun::WindowsResolvedSocketBinder,
                ),
            ),
            metrics,
            reset_hub: ClientNetworkResetHub::default(),
        }
    }

    fn published_generation(&self) -> u64 {
        self.inner.published_generation()
    }

    fn generation_is_admissible(&self, expected_generation: u64) -> bool {
        let status = self.inner.coordinator().status();
        status.admission_open() && status.published_generation() == expected_generation
    }

    fn reset_hub(&self) -> ClientNetworkResetHub {
        self.reset_hub.clone()
    }

    async fn connect_tcp(
        &self,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<
        ferrum2_runtime::GenerationBoundTcpStream<ferrum2_runtime::RuntimeTcpStream>,
        NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_wintun::Error>>,
    > {
        let result = self
            .inner
            .connect_tcp(dial_options, route_network, destination)
            .await;
        match &result {
            Ok(stream) => {
                record_interface_resolution_success(&self.metrics, stream.resolved_interface())
            }
            Err(error) => record_interface_resolution(
                &self.metrics,
                error.attempted_source(),
                interface_resolution_result(error),
            ),
        }
        result
    }

    fn open_udp(
        &self,
        expected_generation: u64,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
        selection_destination: SocketAddr,
    ) -> Result<
        ferrum2_runtime::GenerationBoundUdpSocket<tokio::net::UdpSocket>,
        NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_wintun::Error>>,
    > {
        let result = self.inner.open_udp_for_generation(
            expected_generation,
            dial_options,
            route_network,
            selection_destination,
        );
        match &result {
            Ok(socket) => {
                record_interface_resolution_success(&self.metrics, socket.resolved_interface())
            }
            Err(error) => record_interface_resolution(
                &self.metrics,
                error.attempted_source(),
                interface_resolution_result(error),
            ),
        }
        result
    }
}

#[cfg(all(windows, not(test)))]
#[derive(Clone)]
pub(super) struct NetworkServiceConnector {
    service: Arc<ClientNetworkSocketService>,
}

#[cfg(all(windows, not(test)))]
impl NetworkServiceConnector {
    pub(super) const fn new(service: Arc<ClientNetworkSocketService>) -> Self {
        Self { service }
    }
}

pub(super) trait ClientPhysicalConnector: Send + Sync {
    type Stream: LocalEndpoint;

    fn connect_physical(
        &self,
        target: &TargetAddr,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> impl std::future::Future<Output = Result<Self::Stream, ConnectError>> + Send;

    fn udp_socket_factory(
        &self,
        expected_generation: Option<u64>,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> udp::ClientUdpSocketFactory;

    fn network_generation(&self) -> Option<u64> {
        None
    }

    fn network_generation_is_admissible(&self, expected_generation: Option<u64>) -> bool {
        expected_generation.is_none()
    }
}

impl<C> ClientPhysicalConnector for C
where
    C: Connector,
{
    type Stream = C::Stream;

    async fn connect_physical(
        &self,
        target: &TargetAddr,
        _dial_options: &DialOptions,
        _route_network: &RouteNetworkOptions,
    ) -> Result<Self::Stream, ConnectError> {
        self.connect(target).await
    }

    fn udp_socket_factory(
        &self,
        _expected_generation: Option<u64>,
        _dial_options: &DialOptions,
        _route_network: &RouteNetworkOptions,
    ) -> udp::ClientUdpSocketFactory {
        udp::ClientUdpSocketFactory::system()
    }
}

#[cfg(all(windows, not(test)))]
impl ClientPhysicalConnector for NetworkServiceConnector {
    type Stream = super::tokio_io::TokioTransport<
        ferrum2_runtime::GenerationBoundTcpStream<ferrum2_runtime::RuntimeTcpStream>,
    >;

    async fn connect_physical(
        &self,
        target: &TargetAddr,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> Result<Self::Stream, ConnectError> {
        let destination = target
            .as_socket_addr()
            .ok_or_else(|| ConnectError::new(ConnectErrorKind::HostUnreachable))?;
        self.service
            .connect_tcp(dial_options, route_network, destination)
            .await
            .map(super::tokio_io::TokioTransport::new)
            .map_err(connect_error_from_network_service)
    }

    fn udp_socket_factory(
        &self,
        expected_generation: Option<u64>,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
    ) -> udp::ClientUdpSocketFactory {
        udp::ClientUdpSocketFactory::network(
            Arc::clone(&self.service),
            expected_generation.expect("production UDP associations freeze a network generation"),
            dial_options.clone(),
            route_network.clone(),
        )
    }

    fn network_generation(&self) -> Option<u64> {
        Some(self.service.published_generation())
    }

    fn network_generation_is_admissible(&self, expected_generation: Option<u64>) -> bool {
        expected_generation
            .is_some_and(|generation| self.service.generation_is_admissible(generation))
    }
}

#[cfg(all(windows, not(test)))]
fn record_interface_resolution_success(
    metrics: &Metrics,
    resolved: &ferrum2_runtime::ResolvedInterface,
) {
    // Publish the denominator before its hit subset so concurrent scrapes cannot observe
    // cache hits greater than completed interface resolutions.
    record_interface_resolution(
        metrics,
        resolved.selection_source(),
        InterfaceResolutionResult::Success,
    );
    if resolved.cache_hit() {
        metrics.outbound_interface_resolution_cache_hit();
    }
}

#[cfg(any(windows, test))]
fn record_interface_resolution(
    metrics: &Metrics,
    source: InterfaceSelectionSource,
    result: InterfaceResolutionResult,
) {
    metrics.outbound_interface_resolution(interface_resolution_source(source), result);
}

#[cfg(any(windows, test))]
const fn interface_resolution_source(
    source: InterfaceSelectionSource,
) -> InterfaceResolutionSource {
    match source {
        InterfaceSelectionSource::OutboundExplicit => InterfaceResolutionSource::OutboundExplicit,
        InterfaceSelectionSource::AutoDetected => InterfaceResolutionSource::AutoDetected,
        InterfaceSelectionSource::RouteDefault => InterfaceResolutionSource::RouteDefault,
        InterfaceSelectionSource::SystemBestRoute => InterfaceResolutionSource::SystemBestRoute,
    }
}

#[cfg(any(windows, test))]
fn interface_resolution_result<E>(
    error: &NetworkSocketServiceError<E>,
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

#[cfg(any(windows, test))]
fn connect_error_from_network_service<E>(
    error: NetworkSocketServiceError<SystemNetworkSocketError<E>>,
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

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
fn io_error_from_network_service<E>(
    error: NetworkSocketServiceError<SystemNetworkSocketError<E>>,
) -> io::Error {
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
        ) => error.kind(),
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::InterfaceResolution(error),
        ) => match error.kind() {
            InterfaceResolutionErrorKind::ExplicitInterfaceMissing
            | InterfaceResolutionErrorKind::ExplicitInterfaceAmbiguous
            | InterfaceResolutionErrorKind::ExplicitInterfaceUnavailable
            | InterfaceResolutionErrorKind::ExplicitInterfaceWrongFamily
            | InterfaceResolutionErrorKind::SelectedInterfaceWrongFamily
            | InterfaceResolutionErrorKind::SourceAddressUnavailable => {
                io::ErrorKind::PermissionDenied
            }
            InterfaceResolutionErrorKind::SystemBestRouteUnavailable => {
                io::ErrorKind::NetworkUnreachable
            }
        },
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged { .. },
        ) => io::ErrorKind::NetworkUnreachable,
        NetworkSocketServiceError::Cancelled { .. } => io::ErrorKind::ConnectionAborted,
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
        } => io::ErrorKind::Other,
    };
    io::Error::new(kind, "network UDP socket unavailable")
}

struct PolicyConnector<C> {
    connector: Arc<C>,
    dial_options: DialOptions,
    route_network: RouteNetworkOptions,
}

impl<C> Connector for PolicyConnector<C>
where
    C: ClientPhysicalConnector,
{
    type Stream = C::Stream;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.connector
            .connect_physical(target, &self.dial_options, &self.route_network)
            .await
    }
}

#[cfg(all(windows, not(test)))]
type DefaultClientConnector = NetworkServiceConnector;

#[cfg(any(not(windows), test))]
type DefaultClientConnector = TokioConnector<
    ferrum2_runtime::TcpConnector<
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        ApplicationResolverAdapter,
    >,
>;

#[cfg(test)]
pub(super) fn system_application_resolver() -> ApplicationResolverAdapter {
    ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::system_default()),
        0,
        DnsStrategy::PreferIpv4,
    )
}

pub(super) struct ClientShadowsocksContext {
    pub(super) tcp_server: TargetAddr,
    pub(super) udp_server: SocketAddr,
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
    pub(super) dial_options: DialOptions,
}

impl ClientOutboundContext {
    pub(super) fn direct(dial_options: DialOptions) -> Self {
        Self::Direct { dial_options }
    }

    pub(super) fn shadowsocks(&self) -> Option<&ClientShadowsocksContext> {
        match self {
            Self::Shadowsocks(outbound) => Some(outbound),
            Self::Direct { .. } => None,
        }
    }

    pub(super) fn dial_options(&self) -> &DialOptions {
        match self {
            Self::Shadowsocks(outbound) => &outbound.dial_options,
            Self::Direct { dial_options } => dial_options,
        }
    }
}

pub(super) fn runtime_dial_options(options: &ferrum2_config::OutboundDialOptions) -> DialOptions {
    DialOptions::new(
        options.bind_interface(),
        options.inet4_bind_address(),
        options.inet6_bind_address(),
    )
}

pub(super) fn runtime_route_network(
    route: &ferrum2_config::RouteNetworkConfig,
) -> RouteNetworkOptions {
    RouteNetworkOptions::new(route.auto_detect_interface, route.default_interface())
}

pub(super) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.is_empty() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .map(|outbound| {
            Ok(match outbound {
                ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server,
                    psk,
                    dial_options,
                } => ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                    tcp_server: TargetAddr::ip(server).map_err(|_| RunError::StartupProtocol)?,
                    udp_server: server,
                    keys: MethodKeyAdapter::new(MethodSinglePskProvider::from_shared(psk)),
                    dial_options: runtime_dial_options(&dial_options),
                }),
                ferrum2_config::ClientOutboundConfig::Direct { dial_options, .. } => {
                    ClientOutboundContext::direct(runtime_dial_options(&dial_options))
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}

pub(super) struct ClientEgressEngine<
    C = DefaultClientConnector,
    T = ferrum2_crypto::SystemClock,
    R = ferrum2_crypto::SystemRandom,
> {
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    connector: Arc<C>,
    proxy_connectors: Arc<[PolicyConnector<C>]>,
    pub(super) clock: T,
    pub(super) random: R,
    phase_deadlines: (Duration, Duration),
    pub(super) udp: Option<ClientUdpContext>,
    pub(super) application_resolver: ApplicationResolverAdapter,
    direct_resolvers: Arc<[Option<ApplicationResolverAdapter>]>,
    pub(super) route_network: RouteNetworkOptions,
    network_reset_state: Arc<ClientEgressNetworkResetState>,
    network_reset_hub: ClientNetworkResetHub,
    _network_reset_registration: ClientNetworkResetTargetRegistration,
    #[cfg(test)]
    pub(super) udp_id_random: Option<Arc<dyn SecureRandom>>,
}

impl<C, T, R> ClientEgressEngine<C, T, R> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(super) fn new(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self::new_with_application_resolver(
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            system_application_resolver(),
            #[cfg(test)]
            udp_id_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(super) fn new_with_application_resolver(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        application_resolver: ApplicationResolverAdapter,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        let direct_resolvers = outbounds
            .iter()
            .map(|outbound| {
                matches!(outbound, ClientOutboundContext::Direct { .. })
                    .then(|| application_resolver.clone())
            })
            .collect::<Vec<_>>()
            .into();
        Self::new_with_direct_resolvers(
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            application_resolver,
            direct_resolvers,
            #[cfg(test)]
            udp_id_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_direct_resolvers(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        application_resolver: ApplicationResolverAdapter,
        direct_resolvers: Arc<[Option<ApplicationResolverAdapter>]>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        debug_assert_eq!(outbounds.len(), direct_resolvers.len());
        let connector = Arc::new(connector);
        let route_network = RouteNetworkOptions::default();
        let network_reset_state = Arc::new(ClientEgressNetworkResetState::new(udp.as_ref()));
        let network_reset_hub = ClientNetworkResetHub::default();
        let network_reset_registration = network_reset_hub
            .register(&network_reset_state)
            .expect("a private client reset hub always accepts its only engine");
        let proxy_connectors = outbounds
            .iter()
            .map(|outbound| PolicyConnector {
                connector: Arc::clone(&connector),
                dial_options: outbound.dial_options().clone(),
                route_network: route_network.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        Self {
            outbounds,
            connector,
            proxy_connectors,
            clock,
            random,
            phase_deadlines,
            udp,
            application_resolver,
            direct_resolvers,
            route_network,
            network_reset_state,
            network_reset_hub,
            _network_reset_registration: network_reset_registration,
            #[cfg(test)]
            udp_id_random,
        }
    }

    pub(super) fn with_route_network(mut self, route_network: RouteNetworkOptions) -> Self {
        self.proxy_connectors = self
            .outbounds
            .iter()
            .map(|outbound| PolicyConnector {
                connector: Arc::clone(&self.connector),
                dial_options: outbound.dial_options().clone(),
                route_network: route_network.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        self.route_network = route_network;
        self
    }

    #[cfg(all(windows, not(test)))]
    pub(super) fn with_shared_network_reset(
        mut self,
        service: &ClientNetworkSocketService,
    ) -> Result<Self, RunError> {
        let hub = service.reset_hub();
        let registration = hub
            .register(&self.network_reset_state)
            .map_err(|()| RunError::StartupProtocol)?;
        self._network_reset_registration = registration;
        self.network_reset_hub = hub;
        Ok(self)
    }

    pub(super) fn register_dns_reset_action(
        &self,
        action: &Arc<ClientDnsResetAction>,
    ) -> Result<(), ()> {
        self.network_reset_state.register_dns_action(action)
    }

    pub(super) fn reset_network(&self) -> usize {
        self.network_reset_hub.reset()
    }

    fn classify_selected(
        &self,
        origin: ClientRequestOrigin,
        plan: Option<&EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<SelectedEgress, ClientPlanFailure> {
        if origin != ClientRequestOrigin::Socks && target.is_none() {
            return Err(ClientPlanFailure::Invalid);
        }
        let Some(plan) = plan else {
            return if matches!(
                origin,
                ClientRequestOrigin::Dns | ClientRequestOrigin::RuleSet
            ) && target.and_then(TargetAddr::as_socket_addr).is_some()
            {
                Ok(SelectedEgress::Direct { outbound: None })
            } else {
                Err(ClientPlanFailure::Invalid)
            };
        };
        let hops = plan.hops();
        if hops.is_empty() || hops.len() > udp::MAX_UDP_PLAN_HOPS {
            return Err(ClientPlanFailure::Invalid);
        }
        let mut direct = 0;
        for hop in hops {
            match self.outbounds.get(*hop) {
                Some(ClientOutboundContext::Shadowsocks(_)) => {}
                Some(ClientOutboundContext::Direct { .. }) => direct += 1,
                None => return Err(ClientPlanFailure::Invalid),
            }
        }
        if direct == 1 && hops.len() == 1 {
            return Ok(SelectedEgress::Direct {
                outbound: Some(hops[0]),
            });
        }
        if direct != 0 {
            return Err(ClientPlanFailure::Invalid);
        }
        Ok(SelectedEgress::Shadowsocks {
            first_outbound: hops[0],
            first_server: self.outbounds[hops[0]]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .udp_server,
        })
    }

    pub(super) async fn open_tcp_for_ingress<'a>(
        &'a self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<tcp::ClientTcpFlow<'a, C::Stream>, ClientOpenFailure>
    where
        C: ClientPhysicalConnector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), Some(application_target))
            .map_err(ClientOpenFailure::Plan)?;
        if let SelectedEgress::Direct { outbound } = selected {
            let deadline = timeout_limit
                .unwrap_or(self.phase_deadlines.0)
                .min(self.phase_deadlines.0);
            let deadline = tokio::time::Instant::now() + deadline;
            let candidates = match application_target.host() {
                TargetHostRef::Ip(_) => vec![application_target.clone()],
                TargetHostRef::Domain(host) => {
                    let resolver = match outbound {
                        Some(outbound) => self
                            .direct_resolvers
                            .get(outbound)
                            .and_then(Option::as_ref)
                            .ok_or(ClientOpenFailure::Connect(
                                ConnectErrorKind::HostUnreachable,
                            ))?,
                        None => &self.application_resolver,
                    }
                    .for_ingress(ingress);
                    let resolved = match tokio::time::timeout_at(
                        deadline,
                        TcpResolver::resolve(&resolver, host, application_target.port().get()),
                    )
                    .await
                    {
                        Ok(Ok(resolved)) => resolved,
                        Ok(Err(_)) => {
                            return Err(ClientOpenFailure::Connect(
                                ConnectErrorKind::HostUnreachable,
                            ));
                        }
                        Err(_) => {
                            return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                        }
                    };
                    resolved
                        .into_iter()
                        .take(MAX_RESOLVED_CANDIDATES)
                        .filter_map(|candidate| TargetAddr::ip(candidate).ok())
                        .collect()
                }
            };
            let default_dial_options = DialOptions::default();
            let dial_options = outbound
                .and_then(|index| self.outbounds.get(index))
                .map_or(&default_dial_options, ClientOutboundContext::dial_options);
            let mut attempted = false;
            let mut last = ConnectErrorKind::HostUnreachable;
            for target in candidates {
                if tokio::time::Instant::now() >= deadline {
                    return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                }
                attempted = true;
                let connect =
                    self.connector
                        .connect_physical(&target, dial_options, &self.route_network);
                match tokio::time::timeout_at(deadline, connect).await {
                    Ok(Ok(stream)) => return Ok(tcp::ClientTcpFlow::Direct(stream)),
                    Ok(Err(error)) => last = error.kind(),
                    Err(_) => {
                        return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                    }
                }
            }
            return Err(ClientOpenFailure::Connect(if attempted {
                last
            } else {
                ConnectErrorKind::HostUnreachable
            }));
        }
        let plan = plan.expect("classified proxy plan has a snapshot");
        let SelectedEgress::Shadowsocks { first_outbound, .. } = selected else {
            unreachable!("classified proxy plan")
        };
        let deadlines = timeout_limit.map_or(self.phase_deadlines, |limit| {
            (
                limit.min(self.phase_deadlines.0),
                limit.min(self.phase_deadlines.1),
            )
        });
        let open = tcp::open(
            &self.outbounds,
            plan.hops(),
            &self.proxy_connectors[first_outbound],
            &self.clock,
            &self.random,
            application_target,
            deadlines,
            #[cfg(test)]
            observers,
        );
        open.await.map(tcp::ClientTcpFlow::Proxy)
    }

    pub(super) async fn prepare_udp_for_ingress(
        &self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        C: ClientPhysicalConnector,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), target)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            origin,
            ingress,
            plan,
            selected,
            target,
            tokio::net::UdpSocket::bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }

    #[cfg(test)]
    pub(super) async fn prepare_udp_with<F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        bind: F,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        C: ClientPhysicalConnector,
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        let selected = self
            .classify_selected(ClientRequestOrigin::Socks, Some(&plan), None)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            ClientRequestOrigin::Socks,
            0,
            Some(plan),
            selected,
            None,
            bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientPlanFailure {
    Invalid,
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Plan(ClientPlanFailure),
    Connect(ferrum2_core::ConnectErrorKind),
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientUdpPrepareFailure {
    Plan(ClientPlanFailure),
    Unavailable,
}

#[cfg(test)]
mod m16_tests {
    use super::*;
    use crate::run::test_support::*;

    #[test]
    fn shared_network_reset_hub_resets_all_live_engines_and_drops_registration_exactly() {
        let hub = ClientNetworkResetHub::default();
        let first = Arc::new(ClientEgressNetworkResetState::new(None));
        let second = Arc::new(ClientEgressNetworkResetState::new(None));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let first_action: Arc<ClientDnsResetAction> = {
            let calls = Arc::clone(&first_calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                2
            })
        };
        let second_action: Arc<ClientDnsResetAction> = {
            let calls = Arc::clone(&second_calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                3
            })
        };
        first.register_dns_action(&first_action).unwrap();
        second.register_dns_action(&second_action).unwrap();
        let _first_registration = hub.register(&first).unwrap();
        let second_registration = hub.register(&second).unwrap();

        assert_eq!(hub.reset(), 5);
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);

        drop(second_registration);
        assert_eq!(hub.reset(), 2);
        assert_eq!(first_calls.load(Ordering::SeqCst), 2);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn validated_network_policies_are_retained_per_outbound_and_route() {
        let explicit = ferrum2_config::OutboundDialOptions {
            bind_interface: Some("policy-interface".into()),
            inet4_bind_address: Some("192.0.2.44".parse().unwrap()),
            inet6_bind_address: Some("2001:db8::44".parse().unwrap()),
        };
        let expected = DialOptions::new(
            Some("policy-interface"),
            Some("192.0.2.44".parse().unwrap()),
            Some("2001:db8::44".parse().unwrap()),
        );
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: explicit.clone(),
            },
            ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: "198.51.100.44:443".parse().unwrap(),
                psk: Arc::new(ferrum2_crypto::MethodPsk::aes128([0x44; 16])),
                dial_options: explicit,
            },
        ])
        .unwrap();
        assert_eq!(outbounds[0].dial_options(), &expected);
        assert_eq!(outbounds[1].dial_options(), &expected);

        let route = ferrum2_config::RouteNetworkConfig {
            auto_detect_interface: true,
            default_interface: Some("route-interface".into()),
        };
        assert_eq!(
            runtime_route_network(&route),
            RouteNetworkOptions::new(true, Some("route-interface"))
        );
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct PhysicalPolicyAttempt {
        target: TargetAddr,
        dial_options: DialOptions,
        route_network: RouteNetworkOptions,
    }

    #[derive(Default)]
    struct PhysicalPolicyTrace {
        tcp: Mutex<Vec<PhysicalPolicyAttempt>>,
        udp: Mutex<Vec<(DialOptions, RouteNetworkOptions)>>,
        udp_socket: Arc<udp::InjectedUdpSocketTrace>,
    }

    struct RecordingPhysicalConnector {
        trace: Arc<PhysicalPolicyTrace>,
    }

    impl ClientPhysicalConnector for RecordingPhysicalConnector {
        type Stream = crate::run::tokio_io::TokioTransport<ScriptedIo>;

        async fn connect_physical(
            &self,
            target: &TargetAddr,
            dial_options: &DialOptions,
            route_network: &RouteNetworkOptions,
        ) -> Result<Self::Stream, ConnectError> {
            self.trace
                .tcp
                .lock()
                .expect("physical TCP attempts")
                .push(PhysicalPolicyAttempt {
                    target: target.clone(),
                    dial_options: dial_options.clone(),
                    route_network: route_network.clone(),
                });
            Err(ConnectError::new(ConnectErrorKind::ConnectionRefused))
        }

        fn udp_socket_factory(
            &self,
            _expected_generation: Option<u64>,
            dial_options: &DialOptions,
            route_network: &RouteNetworkOptions,
        ) -> udp::ClientUdpSocketFactory {
            self.trace
                .udp
                .lock()
                .expect("physical UDP policies")
                .push((dial_options.clone(), route_network.clone()));
            udp::ClientUdpSocketFactory::injected(Arc::clone(&self.trace.udp_socket))
        }
    }

    #[tokio::test]
    async fn physical_connector_receives_selected_policy_and_first_concrete_target() {
        let direct_dial = DialOptions::new(
            Some("direct-interface"),
            Some("192.0.2.10".parse().unwrap()),
            None,
        );
        let proxy_dial = DialOptions::new(
            Some("proxy-interface"),
            Some("192.0.2.20".parse().unwrap()),
            None,
        );
        let route_network = RouteNetworkOptions::new(true, Some("route-interface"));
        let proxy_server: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let trace = Arc::new(PhysicalPolicyTrace::default());
        let engine = ClientEgressEngine::new(
            vec![
                ClientOutboundContext::direct(direct_dial.clone()),
                ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                    tcp_server: TargetAddr::ip(proxy_server).unwrap(),
                    udp_server: proxy_server,
                    keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                        ferrum2_crypto::MethodPsk::aes128([0x20; 16]),
                    )),
                    dial_options: proxy_dial.clone(),
                }),
            ]
            .into(),
            RecordingPhysicalConnector {
                trace: Arc::clone(&trace),
            },
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        )
        .with_route_network(route_network.clone());
        let direct_plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let proxy_plan = ferrum2_core::route::EgressPlanHandle::direct(1).snapshot_owned();
        let direct_target = TargetAddr::ip("203.0.113.10:8443".parse().unwrap()).unwrap();
        let application_target = TargetAddr::ip("203.0.113.30:5353".parse().unwrap()).unwrap();

        assert!(matches!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(direct_plan.clone()),
                    &direct_target,
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Connect(
                ConnectErrorKind::ConnectionRefused
            ))
        ));
        assert!(matches!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(proxy_plan.clone()),
                    &application_target,
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                ConnectErrorKind::ConnectionRefused
            )))
        ));

        let mut direct_udp = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(direct_plan),
                Some(&direct_target),
            )
            .await
            .unwrap();
        let wire_length = match direct_udp.prepare_application_request(
            &engine,
            &engine.outbounds,
            direct_target.clone(),
            b"first",
            Instant::now(),
        ) {
            Ok(length) => length,
            Err(_) => panic!("direct UDP request should encode"),
        };
        assert!(matches!(
            direct_udp.send_encoded_request(wire_length).await,
            Ok(length) if length == wire_length
        ));
        let _proxy_udp = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(proxy_plan),
                Some(&application_target),
            )
            .await
            .unwrap();

        assert_eq!(
            trace.tcp.lock().unwrap().as_slice(),
            &[
                PhysicalPolicyAttempt {
                    target: direct_target.clone(),
                    dial_options: direct_dial.clone(),
                    route_network: route_network.clone(),
                },
                PhysicalPolicyAttempt {
                    target: TargetAddr::ip(proxy_server).unwrap(),
                    dial_options: proxy_dial.clone(),
                    route_network: route_network.clone(),
                },
            ]
        );
        assert_eq!(
            trace.udp.lock().unwrap().as_slice(),
            &[
                (direct_dial, route_network.clone()),
                (proxy_dial, route_network),
            ]
        );
        assert_eq!(
            trace.udp_socket.opened(),
            vec![direct_target.as_socket_addr().unwrap(), proxy_server]
        );
        assert_eq!(
            trace.udp_socket.sent(),
            vec![direct_target.as_socket_addr().unwrap()]
        );
    }

    struct EmptyNetworkCatalog;

    impl ferrum2_runtime::NetworkInterfaceCatalog for EmptyNetworkCatalog {
        fn read_interfaces(
            &self,
        ) -> Result<
            Vec<ferrum2_runtime::NetworkInterfaceObservation>,
            ferrum2_runtime::NetworkInterfaceCatalogError,
        > {
            Ok(Vec::new())
        }

        fn system_best_route(
            &self,
            _destination: SocketAddr,
        ) -> Result<ferrum2_runtime::SystemBestRoute, ferrum2_runtime::NetworkInterfaceCatalogError>
        {
            Err(ferrum2_runtime::NetworkInterfaceCatalogError)
        }
    }

    fn explicit_interface_error() -> NetworkSocketServiceError<SystemNetworkSocketError<()>> {
        let snapshot = ferrum2_runtime::NetworkSnapshot::new(1, None, None).unwrap();
        let resolver = ferrum2_runtime::NetworkInterfaceResolver::new(EmptyNetworkCatalog);
        let resolution = resolver
            .resolve(
                &DialOptions::new(Some("missing-interface"), None, None),
                &RouteNetworkOptions::default(),
                "203.0.113.1:443".parse().unwrap(),
                &snapshot,
            )
            .unwrap_err();
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::InterfaceResolution(resolution),
        )
    }

    #[test]
    fn generation_bound_socket_errors_and_interface_metrics_keep_closed_categories() {
        let refused = NetworkSocketServiceError::Connection {
            attempted_source: InterfaceSelectionSource::SystemBestRoute,
            error: SystemNetworkSocketError::<()>::Socket(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            )),
        };
        assert_eq!(
            interface_resolution_result(&refused),
            InterfaceResolutionResult::Success
        );
        assert_eq!(
            connect_error_from_network_service(refused).kind(),
            ConnectErrorKind::ConnectionRefused
        );

        let denied = explicit_interface_error();
        assert_eq!(
            interface_resolution_result(&denied),
            InterfaceResolutionResult::Failure
        );
        assert_eq!(
            connect_error_from_network_service(denied).kind(),
            ConnectErrorKind::PolicyDenied
        );
        assert_eq!(
            io_error_from_network_service(explicit_interface_error()).kind(),
            io::ErrorKind::PermissionDenied
        );

        let stale = NetworkSocketServiceError::Admission(NetworkRuntimeResourceAdmissionError::<
            SystemNetworkSocketError<()>,
        >::NetworkGenerationChanged {
            attempted_source: InterfaceSelectionSource::AutoDetected,
        });
        assert_eq!(
            interface_resolution_result(&stale),
            InterfaceResolutionResult::Failure
        );
        assert_eq!(
            connect_error_from_network_service(stale).kind(),
            ConnectErrorKind::NetworkUnreachable
        );

        let metrics = Metrics::new();
        record_interface_resolution(
            &metrics,
            InterfaceSelectionSource::OutboundExplicit,
            InterfaceResolutionResult::Success,
        );
        record_interface_resolution(
            &metrics,
            InterfaceSelectionSource::SystemBestRoute,
            InterfaceResolutionResult::Failure,
        );
        let encoded = metrics.encode_text().unwrap();
        assert!(encoded.contains(
            "ferrum2_outbound_interface_resolution_total{source=\"outbound_explicit\",result=\"success\"} 1"
        ));
        assert!(encoded.contains(
            "ferrum2_outbound_interface_resolution_total{source=\"system_best_route\",result=\"failure\"} 1"
        ));
    }

    #[derive(Clone, Copy)]
    struct ApplicationRoute {
        ingress: usize,
        network: ferrum2_core::route::Network,
        endpoint: SocketAddr,
    }

    struct RoutedApplicationBackend {
        routes: Vec<ApplicationRoute>,
        observed: Mutex<Vec<(usize, ferrum2_core::route::Network)>>,
    }

    impl ferrum2_dns::ApplicationResolveBackend for RoutedApplicationBackend {
        fn resolve<'a>(
            &'a self,
            request: ferrum2_dns::ApplicationResolveRequest<'a>,
        ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
            let context = request.context();
            self.observed
                .lock()
                .expect("application observations")
                .push((context.ingress(), context.network()));
            let endpoint = self
                .routes
                .iter()
                .find(|route| {
                    route.ingress == context.ingress() && route.network == context.network()
                })
                .map(|route| route.endpoint);
            Box::pin(async move {
                endpoint
                    .map(|endpoint| vec![endpoint])
                    .ok_or(ferrum2_dns::DnsError::Timeout)
            })
        }
    }

    #[tokio::test]
    async fn missing_exact_direct_resolver_fails_closed_for_tcp_and_udp() {
        let backend = Arc::new(RoutedApplicationBackend {
            routes: vec![
                ApplicationRoute {
                    ingress: 0,
                    network: ferrum2_core::route::Network::Tcp,
                    endpoint: "127.0.0.1:9".parse().unwrap(),
                },
                ApplicationRoute {
                    ingress: 0,
                    network: ferrum2_core::route::Network::Udp,
                    endpoint: "127.0.0.1:9".parse().unwrap(),
                },
            ],
            observed: Mutex::new(Vec::new()),
        });
        let ambient = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::configured(backend.clone())),
            0,
            DnsStrategy::PreferIpv4,
        );
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                ambient.clone(),
                Duration::from_secs(1),
            ));
        let engine = ClientEgressEngine::new_with_direct_resolvers(
            vec![ClientOutboundContext::direct(DialOptions::default())].into(),
            connector,
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            ambient,
            vec![None].into(),
            None,
        );
        let target = TargetAddr::domain("missing-exact-resolver.invalid", 443).unwrap();
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();

        assert!(matches!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(direct.clone()),
                    &target,
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Connect(
                ConnectErrorKind::HostUnreachable
            ))
        ));
        assert!(matches!(
            engine
                .prepare_udp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(direct),
                    Some(&target),
                )
                .await,
            Err(ClientUdpPrepareFailure::Unavailable)
        ));
        assert!(
            backend.observed.lock().unwrap().is_empty(),
            "malformed exact resolver table must never use the ambient resolver"
        );
    }

    #[tokio::test]
    async fn application_dns_ingress_is_isolated_for_concurrent_tcp_and_udp() {
        let tcp_listener_3 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_listener_7 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_listener_3 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_listener_7 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend = Arc::new(RoutedApplicationBackend {
            routes: vec![
                ApplicationRoute {
                    ingress: 3,
                    network: ferrum2_core::route::Network::Tcp,
                    endpoint: tcp_listener_3.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 7,
                    network: ferrum2_core::route::Network::Tcp,
                    endpoint: tcp_listener_7.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 3,
                    network: ferrum2_core::route::Network::Udp,
                    endpoint: udp_listener_3.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 7,
                    network: ferrum2_core::route::Network::Udp,
                    endpoint: udp_listener_7.local_addr().unwrap(),
                },
            ],
            observed: Mutex::new(Vec::new()),
        });
        let resolver = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::configured(backend.clone())),
            0,
            DnsStrategy::PreferIpv4,
        );
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                resolver.clone(),
                Duration::from_secs(1),
            ));
        let registry = OwnerRegistry::new();
        let engine = ClientEgressEngine::new_with_application_resolver(
            vec![ClientOutboundContext::direct(DialOptions::default())].into(),
            connector,
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            resolver,
            None,
        );
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let tcp_target = TargetAddr::domain("tcp-ingress.invalid", 443).unwrap();
        let udp_target = TargetAddr::domain("udp-ingress.invalid", 5353).unwrap();
        let mut association_3 = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                3,
                Some(direct.clone()),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let mut association_7 = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                7,
                Some(direct.clone()),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let wire_3 = association_3
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target.clone(),
                b"ingress-3",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare ingress 3 datagram"));
        let wire_7 = association_7
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target.clone(),
                b"ingress-7",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare ingress 7 datagram"));

        let receive_3 = async {
            let mut bytes = [0_u8; 32];
            let (length, _) = udp_listener_3.recv_from(&mut bytes).await.unwrap();
            bytes[..length].to_vec()
        };
        let receive_7 = async {
            let mut bytes = [0_u8; 32];
            let (length, _) = udp_listener_7.recv_from(&mut bytes).await.unwrap();
            bytes[..length].to_vec()
        };
        let (tcp_3, tcp_7, udp_3, udp_7, accepted_3, accepted_7, payload_3, payload_7) = tokio::join!(
            engine.open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                3,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            ),
            engine.open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                7,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            ),
            association_3.send_encoded_request(wire_3),
            association_7.send_encoded_request(wire_7),
            tcp_listener_3.accept(),
            tcp_listener_7.accept(),
            receive_3,
            receive_7,
        );
        drop(tcp_3.unwrap());
        drop(tcp_7.unwrap());
        drop(accepted_3.unwrap());
        drop(accepted_7.unwrap());
        assert_eq!(udp_3.unwrap(), b"ingress-3".len());
        assert_eq!(udp_7.unwrap(), b"ingress-7".len());
        assert_eq!(payload_3, b"ingress-3");
        assert_eq!(payload_7, b"ingress-7");

        for (association, ingress, payload) in [
            (&mut association_3, 3, b"again-3".as_slice()),
            (&mut association_7, 7, b"again-7".as_slice()),
        ] {
            let wire = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    udp_target.clone(),
                    payload,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("prepare repeated ingress {ingress} datagram"));
            association
                .send_encoded_request(wire)
                .await
                .unwrap_or_else(|_| panic!("send repeated ingress {ingress} datagram"));
        }

        assert!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    13,
                    Some(direct.clone()),
                    &tcp_target,
                    None,
                    None,
                )
                .await
                .is_err(),
            "configured failure must not fall back"
        );
        assert!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(direct.clone()),
                    &tcp_target,
                    None,
                    None,
                )
                .await
                .is_err(),
            "ingress zero must remain isolated from configured routes"
        );
        let mut failed_udp = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                13,
                Some(direct),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let failed_wire = failed_udp
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target,
                b"no-fallback",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare failed-ingress datagram"));
        assert_eq!(
            failed_udp
                .send_encoded_request(failed_wire)
                .await
                .expect_err("configured UDP failure must not fall back")
                .kind(),
            io::ErrorKind::TimedOut
        );

        let observed = backend.observed.lock().unwrap();
        for (ingress, network, expected) in [
            (0, ferrum2_core::route::Network::Tcp, 1),
            (3, ferrum2_core::route::Network::Tcp, 1),
            (3, ferrum2_core::route::Network::Udp, 2),
            (7, ferrum2_core::route::Network::Tcp, 1),
            (7, ferrum2_core::route::Network::Udp, 2),
            (13, ferrum2_core::route::Network::Tcp, 1),
            (13, ferrum2_core::route::Network::Udp, 1),
        ] {
            assert_eq!(
                observed
                    .iter()
                    .filter(|actual| **actual == (ingress, network))
                    .count(),
                expected,
                "ingress {ingress} {network:?}"
            );
        }
        assert_eq!(observed.len(), 9);
    }

    #[derive(Clone, Default)]
    struct TraceCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for &TraceCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("trace capture")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn proxy() -> ferrum2_config::ClientOutboundConfig {
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "198.51.100.222:62016".parse().unwrap(),
            psk: Arc::new(ferrum2_crypto::MethodPsk::aes128(*b"m16-secret-key!!")),
            dial_options: Default::default(),
        }
    }

    fn selected(hops: Vec<usize>) -> EgressPlanSnapshot {
        let (_, handles) = ferrum2_core::route::compile_egress_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("direct-a", 0),
                TaggedOutbound::new("direct-b", 1),
                TaggedOutbound::new("m16-tag-sentinel", 2),
            ],
            &[TaggedPlan::new("selected", hops)],
            &[],
            &["selected", "direct-a", "direct-b", "m16-tag-sentinel"],
        )
        .expect("selected plan");
        handles[0].snapshot_owned()
    }

    #[tokio::test]
    async fn m16_direct_pre_socket_and_m16_redaction_classify_without_side_effects() {
        assert_eq!(
            prepare_client_outbounds(Vec::new()).err().unwrap(),
            RunError::StartupProtocol
        );
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: Default::default(),
            },
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: Default::default(),
            },
            proxy(),
        ])
        .expect("closed outbound catalog");
        let connector_calls = Arc::new(AtomicUsize::new(0));
        let bind_calls = Arc::new(AtomicUsize::new(0));
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(FailingConnector {
                calls: Arc::clone(&connector_calls),
            }),
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        let target = TargetAddr::domain("m16-target-sentinel.invalid", 443).unwrap();
        for (name, plan, expected) in [
            ("mixed", selected(vec![0, 2]), ClientPlanFailure::Invalid),
            (
                "multi direct",
                selected(vec![0, 1]),
                ClientPlanFailure::Invalid,
            ),
            (
                "out of range",
                ferrum2_core::route::EgressPlanHandle::direct(3).snapshot_owned(),
                ClientPlanFailure::Invalid,
            ),
        ] {
            assert!(
                matches!(
                    engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                            Some(plan.clone()),
                            &target,
                            None,
                            None,
                        )
                        .await,
                    Err(ClientOpenFailure::Plan(actual)) if actual == expected
                ),
                "TCP {name}"
            );
            let calls = Arc::clone(&bind_calls);
            assert_eq!(
                engine
                    .prepare_udp_with(plan, move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Err(io::Error::other("binder must not run")) }
                    })
                    .await
                    .err(),
                Some(ClientUdpPrepareFailure::Plan(expected)),
                "UDP {name}"
            );
            assert_eq!(connector_calls.load(Ordering::SeqCst), 0, "TCP {name}");
            assert_eq!(bind_calls.load(Ordering::SeqCst), 0, "UDP {name}");
            assert_eq!(registry.snapshot(), baseline, "owners {name}");
        }

        assert!(matches!(
            engine
                .open_tcp_for_ingress(ClientRequestOrigin::Socks, 0, None, &target, None, None)
                .await,
            Err(ClientOpenFailure::Plan(ClientPlanFailure::Invalid))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);

        let mixed = selected(vec![0, 2]);
        let redacted_tcp = format!(
            "{:?}",
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(mixed.clone()),
                    &target,
                    None,
                    None,
                )
                .await
                .err()
                .unwrap()
        );
        let redacted_udp = format!(
            "{:?}",
            engine
                .prepare_udp_for_ingress(ClientRequestOrigin::Socks, 0, Some(mixed), Some(&target),)
                .await
                .err()
                .unwrap()
        );
        let dns_target = TargetAddr::domain("m16-dns-sentinel.invalid", 53).unwrap();
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let packet_registry = OwnerRegistry::new();
        let packet_live_ids = Arc::new(Mutex::new(HashSet::new()));
        let packet_engine = ClientEgressEngine::new(
            prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: Default::default(),
            }])
            .expect("packet direct outbound"),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::default(),
                    packet_registry.clone(),
                ),
                live_ids: Arc::clone(&packet_live_ids),
            }),
            None,
        );
        let mut association = packet_engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Dns,
                0,
                Some(direct.clone()),
                Some(&dns_target),
            )
            .await
            .expect("redaction direct UDP association");
        let mut packet = vec![0_u8; ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES + 1];
        packet[..19].copy_from_slice(b"m16-packet-sentinel");
        let packet_error = match association.prepare_application_request(
            &packet_engine,
            &packet_engine.outbounds,
            dns_target.clone(),
            &packet,
            Instant::now(),
        ) {
            Err(UdpPlanResponseError::Packet(error)) => format!("{error:?}"),
            Err(UdpPlanResponseError::Runtime(_)) | Ok(_) => panic!("fixed packet bound error"),
        };
        drop(association);
        assert_eq!(packet_registry.snapshot(), OwnerSnapshot::default());
        assert!(
            packet_live_ids
                .lock()
                .expect("packet SIP022 IDs")
                .is_empty()
        );

        let dns_connect_target = TargetAddr::ip("192.0.2.53:53".parse().unwrap()).unwrap();
        let connect_kind = match engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Dns,
                0,
                Some(direct),
                &dns_connect_target,
                None,
                None,
            )
            .await
        {
            Err(ClientOpenFailure::Connect(kind)) => kind,
            _ => panic!("fixed direct connect failure"),
        };
        assert_eq!(connect_kind, ferrum2_core::ConnectErrorKind::Other);
        let reason = ferrum2_observability::Reason::RelayIo;
        let metrics = Metrics::new();
        metrics.failure(
            ferrum2_observability::Role::Client,
            ferrum2_observability::Stage::Relay,
            reason,
        );
        let trace = Arc::new(TraceCapture::default());
        let subscriber = ferrum2_observability::json_subscriber(
            Arc::clone(&trace),
            ferrum2_observability::LogLevel::Trace,
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            ferrum2_observability::emit(
                ferrum2_observability::TraceRecord::new(
                    ferrum2_observability::LogLevel::Warn,
                    ferrum2_observability::Event::Failure,
                    ferrum2_observability::Role::Client,
                    ferrum2_observability::Stage::Relay,
                    ferrum2_observability::Outcome::Failed,
                )
                .with_reason(reason),
            );
        });
        let trace = String::from_utf8(trace.0.lock().expect("trace capture").clone()).unwrap();
        let metrics = metrics.encode_text().expect("closed metrics");
        assert_eq!(redacted_tcp, "Plan(Invalid)");
        assert_eq!(redacted_udp, "Plan(Invalid)");
        assert_eq!(packet_error, "Bounds");
        for sentinel in [
            "m16-target-sentinel.invalid",
            "198.51.100.222:62016",
            "m16-dns-sentinel.invalid",
            "m16-tag-sentinel",
            "m16-packet-sentinel",
            "m16-secret-key!!",
        ] {
            for output in [
                &redacted_tcp,
                &redacted_udp,
                &packet_error,
                &trace,
                &metrics,
            ] {
                assert!(!output.contains(sentinel), "leaked sentinel in {output}");
            }
        }
        assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
        assert_eq!(registry.snapshot(), baseline);

        let ipv6 = TargetAddr::ip("[2001:db8::1]:443".parse().unwrap()).unwrap();
        let plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        assert!(matches!(
            engine.classify_selected(ClientRequestOrigin::Tun, Some(&plan), Some(&ipv6)),
            Ok(SelectedEgress::Direct { .. })
        ));
        assert!(matches!(
            engine.classify_selected(ClientRequestOrigin::Dns, Some(&plan), Some(&ipv6)),
            Ok(SelectedEgress::Direct { .. })
        ));

        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        assert!(matches!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(direct),
                    &TargetAddr::ip("[::1]:443".parse().unwrap()).unwrap(),
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Connect(
                ferrum2_core::ConnectErrorKind::Other
            ))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 2);
    }
}
