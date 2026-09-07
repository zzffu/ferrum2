#[cfg(any(windows, test))]
use std::io;
#[cfg(all(windows, not(test)))]
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(any(windows, test))]
use ferrum2_core::ConnectErrorKind;
use ferrum2_core::{ConnectError, Connector, LocalEndpoint, TargetAddr};
#[cfg(any(not(windows), test))]
use ferrum2_dns::ApplicationResolverAdapter;
#[cfg(test)]
use ferrum2_dns::{ApplicationResolver, DnsStrategy};
use ferrum2_net::{DialOptions, RouteNetworkOptions};
#[cfg(any(windows, test))]
use ferrum2_net::{InterfaceResolutionErrorKind, InterfaceSelectionSource};
#[cfg(any(windows, test))]
use ferrum2_observability::{
    InterfaceResolutionCache, InterfaceResolutionResult, InterfaceResolutionSource, Metrics,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::NetworkResetCoordinator;
#[cfg(any(windows, test))]
use ferrum2_runtime::{
    NetworkRuntimeResourceAdmissionError, NetworkSocketServiceError, SystemNetworkSocketError,
};
#[cfg(any(not(windows), test))]
use ferrum2_shadowsocks::tokio::TokioConnector;
#[cfg(all(windows, not(test)))]
use ferrum2_shadowsocks::tokio::TokioTransport;

use super::udp;

mod reset;
pub(in crate::run) use reset::{
    ClientDnsResetAction, ClientEgressNetworkResetState, ClientNetworkResetHub,
    ClientNetworkResetTargetRegistration,
};

#[cfg(all(windows, not(test)))]
type ClientPlatformNetworkSocketService = ferrum2_runtime::NetworkSocketService<
    ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    ferrum2_runtime::SystemNetworkSocketOperations<
        ferrum2_platform_windows::WindowsResolvedSocketBinder,
    >,
>;

#[cfg(all(windows, not(test)))]
pub(in crate::run) struct ClientNetworkSocketService {
    inner: ClientPlatformNetworkSocketService,
    retirement: std::sync::Weak<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    metrics: Arc<Metrics>,
    reset_hub: ClientNetworkResetHub,
}

#[cfg(all(windows, not(test)))]
impl ClientNetworkSocketService {
    pub(in crate::run) fn new(
        coordinator: NetworkResetCoordinator,
        catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
        metrics: Arc<Metrics>,
        registry: ferrum2_runtime::OwnerRegistry,
    ) -> (
        Self,
        Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    ) {
        let (inner, owner) = ferrum2_runtime::NetworkSocketService::new(
            coordinator,
            ferrum2_net::NetworkInterfaceResolver::new(catalog),
            ferrum2_runtime::SystemNetworkSocketOperations::new(
                ferrum2_platform_windows::WindowsResolvedSocketBinder,
            ),
            ferrum2_runtime::NetworkResetLimits::default(),
            registry,
        );
        let owner = Arc::new(tokio::sync::Mutex::new(owner));
        (
            Self {
                inner,
                retirement: Arc::downgrade(&owner),
                metrics,
                reset_hub: ClientNetworkResetHub::default(),
            },
            owner,
        )
    }

    pub(in crate::run) async fn capture_snapshot(
        &self,
        generation: u64,
    ) -> Result<ferrum2_net::NetworkSnapshot, ferrum2_runtime::NetworkSocketOwnerError> {
        self.inner.capture_snapshot(generation).await
    }

    pub(in crate::run) async fn retire_generation(
        &self,
        generation: u64,
    ) -> Result<(), ferrum2_runtime::NetworkSocketOwnerError> {
        let owner = self
            .retirement
            .upgrade()
            .ok_or(ferrum2_runtime::NetworkSocketOwnerError::Closed)?;
        owner.lock().await.retire_generation(generation).await
    }

    fn published_generation(&self) -> u64 {
        self.inner.published_generation()
    }

    fn generation_is_admissible(&self, expected_generation: u64) -> bool {
        let status = self.inner.coordinator().status();
        status.admission_open() && status.published_generation() == expected_generation
    }

    pub(in crate::run) fn reset_hub(&self) -> ClientNetworkResetHub {
        self.reset_hub.clone()
    }

    async fn connect_tcp(
        &self,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<
        ferrum2_runtime::GenerationBoundTcpStream<ferrum2_runtime::RuntimeTcpStream>,
        NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_platform_windows::Error>>,
    > {
        let result = self
            .inner
            .connect_tcp(dial_options, route_network, destination)
            .await;
        match &result {
            Ok(stream) => {
                record_interface_resolution_success(&self.metrics, stream.resolved_interface())
            }
            Err(error) => {
                if let Some(source) = error.attempted_source() {
                    record_interface_resolution(
                        &self.metrics,
                        source,
                        interface_resolution_result(error),
                        InterfaceResolutionCache::Unobserved,
                    );
                }
            }
        }
        result
    }

    pub(in crate::run::egress) fn open_udp(
        &self,
        expected_generation: u64,
        dial_options: &DialOptions,
        route_network: &RouteNetworkOptions,
        selection_destination: SocketAddr,
    ) -> Result<
        ferrum2_runtime::GenerationBoundUdpSocket<tokio::net::UdpSocket>,
        NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_platform_windows::Error>>,
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
            Err(error) => {
                if let Some(source) = error.attempted_source() {
                    record_interface_resolution(
                        &self.metrics,
                        source,
                        interface_resolution_result(error),
                        InterfaceResolutionCache::Unobserved,
                    );
                }
            }
        }
        result
    }
}

#[cfg(all(windows, not(test)))]
#[derive(Clone)]
pub(in crate::run) struct NetworkServiceConnector {
    service: Arc<ClientNetworkSocketService>,
}

#[cfg(all(windows, not(test)))]
impl NetworkServiceConnector {
    pub(in crate::run) const fn new(service: Arc<ClientNetworkSocketService>) -> Self {
        Self { service }
    }
}

pub(in crate::run) trait ClientPhysicalConnector: Send + Sync {
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
    type Stream = TokioTransport<
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
            .map(TokioTransport::new)
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
    resolved: &ferrum2_net::ResolvedInterface,
) {
    // Publish the denominator before its hit subset so concurrent scrapes cannot observe
    // cache hits greater than completed interface resolutions.
    record_interface_resolution(
        metrics,
        resolved.selection_source(),
        InterfaceResolutionResult::Success,
        if resolved.cache_hit() {
            InterfaceResolutionCache::Hit
        } else {
            InterfaceResolutionCache::Miss
        },
    );
}

#[cfg(any(windows, test))]
pub(in crate::run) fn record_interface_resolution(
    metrics: &Metrics,
    source: InterfaceSelectionSource,
    result: InterfaceResolutionResult,
    cache: InterfaceResolutionCache,
) {
    let source = interface_resolution_source(source);
    metrics.outbound_interface_resolution(source, result);
    if cache == InterfaceResolutionCache::Hit {
        metrics.outbound_interface_resolution_cache_hit();
    }
    ferrum2_observability::emit_interface_resolution_diagnostic(
        ferrum2_observability::Role::Client,
        source,
        result,
        cache,
    );
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
pub(in crate::run) fn interface_resolution_result<E>(
    error: &NetworkSocketServiceError<E>,
) -> InterfaceResolutionResult {
    match error {
        NetworkSocketServiceError::Owner(_) => InterfaceResolutionResult::Failure,
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
pub(in crate::run) fn connect_error_from_network_service<E>(
    error: NetworkSocketServiceError<SystemNetworkSocketError<E>>,
) -> ConnectError {
    let kind = match error {
        NetworkSocketServiceError::Owner(_) => ConnectErrorKind::Other,
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
pub(in crate::run) fn io_error_from_network_service<E>(
    error: NetworkSocketServiceError<SystemNetworkSocketError<E>>,
) -> io::Error {
    let kind = match error {
        NetworkSocketServiceError::Owner(_) => io::ErrorKind::Other,
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

pub(in crate::run) struct PolicyConnector<C> {
    pub(in crate::run) connector: Arc<C>,
    pub(in crate::run) dial_options: DialOptions,
    pub(in crate::run) route_network: RouteNetworkOptions,
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
pub(in crate::run) type DefaultClientConnector = NetworkServiceConnector;

#[cfg(any(not(windows), test))]
pub(in crate::run) type DefaultClientConnector = TokioConnector<
    ferrum2_runtime::TcpConnector<
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        ApplicationResolverAdapter,
    >,
>;

#[cfg(test)]
pub(in crate::run) fn test_application_resolver() -> ApplicationResolverAdapter {
    ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::system(Arc::new(
            crate::run::test_support::TestApplicationBackend,
        ))),
        0,
        DnsStrategy::PreferIpv4,
    )
}
