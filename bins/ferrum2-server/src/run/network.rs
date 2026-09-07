use std::io;
#[cfg(all(windows, not(test)))]
use std::sync::Arc;
#[cfg(all(windows, not(test)))]
use std::time::Duration;

#[cfg(any(windows, test))]
use ferrum2_core::ConnectError;
use ferrum2_core::ConnectErrorKind;
#[cfg(any(windows, test))]
use ferrum2_net::{InterfaceResolutionErrorKind, InterfaceSelectionSource};
use ferrum2_observability::Metrics;
#[cfg(any(windows, test))]
use ferrum2_observability::{InterfaceResolutionResult, InterfaceResolutionSource};
#[cfg(all(windows, not(test)))]
use ferrum2_observability::{NetworkLifecycleResult, NetworkResetReason};
#[cfg(all(windows, not(test)))]
use ferrum2_platform_windows::{
    NetworkChangeWaitOutcome, WindowsNetworkInterfaceCatalog, WindowsResolvedSocketBinder,
};
use ferrum2_runtime::RuntimeTcpStream;
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::SystemNetworkSocketOperations;
#[cfg(any(windows, test))]
use ferrum2_runtime::{
    GenerationBoundTcpStream, NetworkRuntimeResourceAdmissionError, NetworkSocketService,
    NetworkSocketServiceError, SystemNetworkSocketError,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::{
    NetworkResetHookRegistration, NetworkResetHookStage, NetworkResetIntent, NetworkResetOutcome,
    NetworkResetReason as RuntimeNetworkResetReason, ProcessRoot,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

#[cfg(all(windows, not(test)))]
use super::RunError;

#[cfg(all(windows, not(test)))]
pub(super) type ServerNetworkSocketService = NetworkSocketService<
    WindowsNetworkInterfaceCatalog,
    SystemNetworkSocketOperations<WindowsResolvedSocketBinder>,
>;

#[cfg(test)]
pub(super) type ServerNetworkSocketService =
    NetworkSocketService<TestNetworkCatalog, TestNetworkSocketOperations>;

/// Non-Windows servers retain the portable Tokio socket path. The marker keeps
/// composition shared without consulting the Windows-only catalog or binder.
#[cfg(all(not(windows), not(test)))]
pub(super) struct ServerNetworkSocketService;

#[cfg(any(windows, test))]
pub(super) type ServerPhysicalTcpStream = GenerationBoundTcpStream<RuntimeTcpStream>;
#[cfg(all(not(windows), not(test)))]
pub(super) type ServerPhysicalTcpStream = RuntimeTcpStream;

#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_QUIET_PERIOD: Duration = Duration::from_millis(350);
#[cfg(all(windows, not(test)))]
const NETWORK_RESET_RETRY_DELAY: Duration = Duration::from_millis(250);
#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_WAIT_BOUND: Duration = Duration::from_secs(1);

#[cfg(all(windows, not(test)))]
pub(super) fn network_change_process_root(
    monitor: super::network_wait::NativeNetworkChangeWait,
    sockets: Arc<ServerNetworkSocketService>,
    owner: Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    metrics: Arc<Metrics>,
    udp_reset: Option<Arc<super::udp::ServerUdpNetworkReset>>,
) -> ProcessRoot<RunError> {
    ProcessRoot::new_cancellable(move |_| async move {
        let coordinator = sockets.coordinator().clone();
        let registration = match &udp_reset {
            Some(hook) => Some(
                coordinator
                    .register_reset_hook(NetworkResetHookStage::Outbound, hook.clone())
                    .map_err(|_| RunError::StartupRuntime)?,
            ),
            None => None,
        };
        Ok(Some(ServerNetworkChangeRoot {
            monitor,
            sockets,
            owner,
            metrics,
            _udp_reset_registration: registration,
            udp_reset,
        }))
    })
}
#[cfg(all(windows, not(test)))]
struct ServerNetworkChangeRoot {
    monitor: super::network_wait::NativeNetworkChangeWait,
    sockets: Arc<ServerNetworkSocketService>,
    owner: Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    metrics: Arc<Metrics>,
    _udp_reset_registration: Option<NetworkResetHookRegistration>,
    udp_reset: Option<Arc<super::udp::ServerUdpNetworkReset>>,
}
#[cfg(all(windows, not(test)))]
impl PreparedProcessRoot<RunError> for ServerNetworkChangeRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }
    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            loop {
                let outcome = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(()),
                    result = self.monitor.wait(NETWORK_CHANGE_WAIT_BOUND) => result?,
                };
                match outcome {
                    NetworkChangeWaitOutcome::Stopped => return Ok(()),
                    NetworkChangeWaitOutcome::TimedOut => continue,
                    NetworkChangeWaitOutcome::Changed => {}
                }
                loop {
                    let outcome = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Ok(()),
                        result = self.monitor.wait(NETWORK_CHANGE_QUIET_PERIOD) => result?,
                    };
                    match outcome {
                        NetworkChangeWaitOutcome::Stopped => return Ok(()),
                        NetworkChangeWaitOutcome::TimedOut => break,
                        NetworkChangeWaitOutcome::Changed => {}
                    }
                }
                let mut retry = false;
                loop {
                    let metric_reason = if retry {
                        NetworkResetReason::Retry
                    } else {
                        NetworkResetReason::NetworkChange
                    };
                    self.metrics
                        .network_reset(metric_reason, NetworkLifecycleResult::Started);
                    let reason = if retry {
                        RuntimeNetworkResetReason::ExplicitRequest
                    } else {
                        RuntimeNetworkResetReason::InterfaceChanged
                    };
                    let result = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            self.metrics.network_reset(metric_reason, NetworkLifecycleResult::Failed);
                            return Ok(());
                        }
                        result = reset_server_network(&self.sockets, &self.owner, self.udp_reset.as_deref(), reason) => result,
                    };
                    match result {
                        Ok(generation) => {
                            self.metrics.set_network_generation(generation);
                            self.metrics
                                .network_reset(metric_reason, NetworkLifecycleResult::Succeeded);
                            break;
                        }
                        Err(()) => self
                            .metrics
                            .network_reset(metric_reason, NetworkLifecycleResult::Failed),
                    }
                    retry = true;
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(NETWORK_RESET_RETRY_DELAY) => {},
                    }
                }
            }
        })
    }
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            drop(self);
            Ok(())
        })
    }
}
#[cfg(all(windows, not(test)))]
async fn reset_server_network(
    sockets: &ServerNetworkSocketService,
    owner: &tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>,
    udp_reset: Option<&super::udp::ServerUdpNetworkReset>,
    reason: RuntimeNetworkResetReason,
) -> Result<u64, ()> {
    let coordinator = sockets.coordinator();
    let status = coordinator.status();
    let report = if status.pending_generation().is_some()
        || udp_reset
            .and_then(super::udp::ServerUdpNetworkReset::pending_generation)
            .is_some()
    {
        coordinator.retry_reset().await.map_err(|_| ())?
    } else {
        let generation = status.published_generation().checked_add(1).ok_or(())?;
        let snapshot = sockets
            .capture_snapshot(generation)
            .await
            .map(Arc::new)
            .map_err(|_| ())?;
        if coordinator.status().published_generation() != status.published_generation() {
            return Err(());
        }
        coordinator
            .reset_network(snapshot, NetworkResetIntent::Ordinary(reason))
            .await
            .map_err(|_| ())?
    };
    if !matches!(
        report.outcome(),
        NetworkResetOutcome::ResetCompleted | NetworkResetOutcome::Noop
    ) {
        return Err(());
    }
    let generation = report.published_generation();
    owner
        .lock()
        .await
        .retire_generation(generation.saturating_sub(1))
        .await
        .map_err(|_| ())?;
    if let Some(reset) = udp_reset {
        reset.finish_generation(generation).await?;
    }
    Ok(generation)
}

#[cfg(test)]
pub(super) struct TestNetworkCatalog;

#[cfg(test)]
impl ferrum2_net::NetworkInterfaceCatalog for TestNetworkCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<
        Vec<ferrum2_net::NetworkInterfaceObservation>,
        ferrum2_net::NetworkInterfaceCatalogError,
    > {
        Err(ferrum2_net::NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        _: std::net::SocketAddr,
    ) -> Result<ferrum2_net::SystemBestRoute, ferrum2_net::NetworkInterfaceCatalogError> {
        ferrum2_net::SystemBestRoute::new(1, 1)
            .map_err(|_| ferrum2_net::NetworkInterfaceCatalogError)
    }
}

#[cfg(test)]
pub(super) struct TestNetworkSocketOperations;

#[cfg(test)]
impl ferrum2_runtime::NetworkSocketOperations for TestNetworkSocketOperations {
    type TcpSocket = tokio::net::TcpSocket;
    type TcpStream = RuntimeTcpStream;
    type UdpSocket = tokio::net::UdpSocket;
    type Error = SystemNetworkSocketError<ferrum2_platform_windows::Error>;

    fn prepare_tcp(
        &self,
        destination: std::net::SocketAddr,
        _: &ferrum2_net::ResolvedInterface,
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
        _: &ferrum2_net::ResolvedInterface,
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

#[cfg(any(windows, test))]
pub(super) fn record_interface_resolution_success(
    metrics: &Metrics,
    resolved: &ferrum2_net::ResolvedInterface,
) {
    // Publish the denominator before its hit subset so concurrent scrapes cannot observe
    // cache hits greater than completed interface resolutions.
    metrics.outbound_interface_resolution(
        interface_resolution_source(resolved.selection_source()),
        InterfaceResolutionResult::Success,
    );
    if resolved.cache_hit() {
        metrics.outbound_interface_resolution_cache_hit();
    }
}

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
pub(super) fn interface_resolution_result(
    error: &NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_platform_windows::Error>>,
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
pub(super) fn connect_error_from_network_service(
    error: NetworkSocketServiceError<SystemNetworkSocketError<ferrum2_platform_windows::Error>>,
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

pub(super) fn connect_error_kind_from_io(error: &io::Error) -> ConnectErrorKind {
    match error.kind() {
        io::ErrorKind::NetworkUnreachable => ConnectErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => ConnectErrorKind::HostUnreachable,
        io::ErrorKind::ConnectionRefused => ConnectErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut => ConnectErrorKind::Timeout,
        io::ErrorKind::PermissionDenied => ConnectErrorKind::PolicyDenied,
        _ => ConnectErrorKind::Other,
    }
}
