use std::io;
use std::sync::Arc;
#[cfg(all(windows, not(test)))]
use std::time::Duration;

use ferrum2_core::{ConnectError, ConnectErrorKind};
#[cfg(any(windows, test))]
use ferrum2_net::{
    InterfaceResolutionErrorKind, InterfaceSelectionSource, NetworkInterfaceResolver,
    NetworkSnapshot,
};
use ferrum2_observability::Metrics;
#[cfg(any(windows, test))]
use ferrum2_observability::{InterfaceResolutionResult, InterfaceResolutionSource};
#[cfg(all(windows, not(test)))]
use ferrum2_observability::{NetworkLifecycleResult, NetworkResetReason};
#[cfg(all(windows, not(test)))]
use ferrum2_platform_windows::{
    NetworkChangeWaitOutcome, WindowsNetworkChangeMonitor, WindowsNetworkInterfaceCatalog,
    WindowsResolvedSocketBinder,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::SystemNetworkSocketOperations;
#[cfg(any(windows, test))]
use ferrum2_runtime::{
    GenerationBoundTcpStream, NetworkResetCoordinator, NetworkResetLimits,
    NetworkRuntimeResourceAdmissionError, NetworkSnapshotPublisher, NetworkSocketService,
    NetworkSocketServiceError, SystemNetworkSocketError,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::{
    NetworkResetHookRegistration, NetworkResetHookStage, NetworkResetIntent, NetworkResetOutcome,
    NetworkResetReason as RuntimeNetworkResetReason, ProcessRoot,
};
use ferrum2_runtime::{OwnerRegistry, RuntimeTcpStream};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

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
pub(super) fn prepare_server_network_runtime(
    registry: &OwnerRegistry,
    metrics: &Metrics,
) -> Result<(Arc<ServerNetworkSocketService>, WindowsNetworkChangeMonitor), RunError> {
    // Subscribe before generation 1 is captured so changes racing startup remain observable.
    let monitor = WindowsNetworkChangeMonitor::new().map_err(|_| RunError::StartupRuntime)?;
    let catalog = WindowsNetworkInterfaceCatalog::system();
    let initial = match NetworkSnapshot::capture(1, &catalog) {
        Ok(initial) => Arc::new(initial),
        Err(_) => {
            close_server_network_change_monitor(monitor)?;
            return Err(RunError::StartupRuntime);
        }
    };
    metrics.set_network_generation(initial.generation());
    let coordinator = NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(initial),
        NetworkResetLimits::default(),
        registry.clone(),
    );
    Ok((
        Arc::new(ServerNetworkSocketService::new(
            coordinator,
            NetworkInterfaceResolver::new(catalog),
            SystemNetworkSocketOperations::new(WindowsResolvedSocketBinder),
        )),
        monitor,
    ))
}

#[cfg(all(windows, not(test)))]
pub(super) fn close_server_network_change_monitor(
    monitor: WindowsNetworkChangeMonitor,
) -> Result<(), RunError> {
    monitor.close().map_err(|_| RunError::ShutdownCleanup)
}

#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_QUIET_PERIOD: Duration = Duration::from_millis(350);
#[cfg(all(windows, not(test)))]
const NETWORK_RESET_RETRY_DELAY: Duration = Duration::from_millis(250);
#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_WAIT_BOUND: Duration = Duration::from_secs(1);

#[cfg(all(windows, not(test)))]
pub(super) fn network_change_process_root(
    monitor: WindowsNetworkChangeMonitor,
    sockets: Arc<ServerNetworkSocketService>,
    metrics: Arc<Metrics>,
    udp_reset: Option<Arc<super::udp::ServerUdpNetworkReset>>,
) -> ProcessRoot<RunError> {
    // The monitor predates the process supervisor, so even cancellation racing
    // root preparation must await this factory and drive explicit rollback.
    ProcessRoot::new_cancellable(move |_| async move {
        let coordinator = sockets.coordinator().clone();
        let udp_reset_registration = match udp_reset {
            Some(hook) => {
                match coordinator.register_reset_hook(NetworkResetHookStage::Outbound, hook) {
                    Ok(registration) => Some(registration),
                    Err(_) => {
                        close_server_network_change_monitor(monitor)?;
                        return Err(RunError::StartupRuntime);
                    }
                }
            }
            None => None,
        };
        Ok(Some(ServerNetworkChangeRoot {
            monitor,
            catalog: sockets.resolver().catalog().clone(),
            coordinator,
            metrics,
            _udp_reset_registration: udp_reset_registration,
        }))
    })
}

#[cfg(all(windows, not(test)))]
struct ServerNetworkChangeRoot {
    monitor: ferrum2_platform_windows::WindowsNetworkChangeMonitor,
    catalog: WindowsNetworkInterfaceCatalog,
    coordinator: NetworkResetCoordinator,
    metrics: Arc<Metrics>,
    _udp_reset_registration: Option<NetworkResetHookRegistration>,
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
            let Self {
                mut monitor,
                catalog,
                coordinator,
                metrics,
                _udp_reset_registration,
            } = *self;
            loop {
                match wait_for_network_change(monitor, NETWORK_CHANGE_WAIT_BOUND, &mut cancellation)
                    .await?
                {
                    ServerNetworkChangeWait::Changed(next_monitor) => {
                        monitor = next_monitor;
                    }
                    ServerNetworkChangeWait::TimedOut(next_monitor) => {
                        monitor = next_monitor;
                        continue;
                    }
                    ServerNetworkChangeWait::Closed => return Ok(()),
                }
                loop {
                    match wait_for_network_change(
                        monitor,
                        NETWORK_CHANGE_QUIET_PERIOD,
                        &mut cancellation,
                    )
                    .await?
                    {
                        ServerNetworkChangeWait::Changed(next_monitor) => {
                            monitor = next_monitor;
                        }
                        ServerNetworkChangeWait::TimedOut(next_monitor) => {
                            monitor = next_monitor;
                            break;
                        }
                        ServerNetworkChangeWait::Closed => return Ok(()),
                    }
                }
                let mut retry = false;
                loop {
                    let metric_reason = if retry {
                        NetworkResetReason::Retry
                    } else {
                        NetworkResetReason::NetworkChange
                    };
                    metrics.network_reset(metric_reason, NetworkLifecycleResult::Started);
                    let runtime_reason = if retry {
                        RuntimeNetworkResetReason::ExplicitRequest
                    } else {
                        RuntimeNetworkResetReason::InterfaceChanged
                    };
                    let reset = reset_server_network(&catalog, &coordinator, runtime_reason);
                    tokio::pin!(reset);
                    let reset_result = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            metrics.network_reset(
                                metric_reason,
                                NetworkLifecycleResult::Failed,
                            );
                            return close_server_network_change_monitor(monitor);
                        }
                        result = &mut reset => result,
                    };
                    match reset_result {
                        Ok(generation) => {
                            metrics.set_network_generation(generation);
                            metrics.network_reset(metric_reason, NetworkLifecycleResult::Succeeded);
                            break;
                        }
                        Err(()) => {
                            metrics.network_reset(metric_reason, NetworkLifecycleResult::Failed);
                            retry = true;
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => {
                                    return close_server_network_change_monitor(monitor);
                                }
                                _ = tokio::time::sleep(NETWORK_RESET_RETRY_DELAY) => {}
                            }
                        }
                    }
                }
            }
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { close_server_network_change_monitor(self.monitor) })
    }
}

#[cfg(all(windows, not(test)))]
enum ServerNetworkChangeWait {
    Changed(WindowsNetworkChangeMonitor),
    TimedOut(WindowsNetworkChangeMonitor),
    Closed,
}

#[cfg(all(windows, not(test)))]
async fn reset_server_network(
    catalog: &WindowsNetworkInterfaceCatalog,
    coordinator: &NetworkResetCoordinator,
    reason: RuntimeNetworkResetReason,
) -> Result<u64, ()> {
    let status = coordinator.status();
    let report = if status.pending_generation().is_some() {
        coordinator.retry_reset().await.map_err(|_| ())?
    } else {
        let generation = status.published_generation().checked_add(1).ok_or(())?;
        let catalog = catalog.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            NetworkSnapshot::capture(generation, &catalog).map(Arc::new)
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        coordinator
            .reset_network(snapshot, NetworkResetIntent::Ordinary(reason))
            .await
            .map_err(|_| ())?
    };
    (report.outcome() == NetworkResetOutcome::ResetCompleted)
        .then_some(report.published_generation())
        .ok_or(())
}

#[cfg(all(windows, not(test)))]
async fn wait_for_network_change(
    mut monitor: WindowsNetworkChangeMonitor,
    timeout: Duration,
    cancellation: &mut ProcessCancellation,
) -> Result<ServerNetworkChangeWait, RunError> {
    let stop = monitor.stop_signal();
    let mut waiting = tokio::task::spawn_blocking(move || {
        let result = monitor.wait(timeout);
        (monitor, result)
    });
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            let stop_failed = stop.signal().is_err();
            let joined = (&mut waiting).await;
            let Ok((monitor, outcome)) = joined else {
                return Err(RunError::ShutdownCleanup);
            };
            let wait_failed = match outcome {
                Ok(NetworkChangeWaitOutcome::Changed
                    | NetworkChangeWaitOutcome::TimedOut
                    | NetworkChangeWaitOutcome::Stopped) => false,
                Err(_) => true,
            };
            let close_failed = monitor.close().is_err();
            if stop_failed || wait_failed || close_failed {
                Err(RunError::ShutdownCleanup)
            } else {
                Ok(ServerNetworkChangeWait::Closed)
            }
        }
        result = &mut waiting => {
            let (monitor, outcome) = result.map_err(|_| RunError::ShutdownCleanup)?;
            match outcome {
                Ok(NetworkChangeWaitOutcome::Changed) => {
                    Ok(ServerNetworkChangeWait::Changed(monitor))
                }
                Ok(NetworkChangeWaitOutcome::TimedOut) => {
                    Ok(ServerNetworkChangeWait::TimedOut(monitor))
                }
                Ok(NetworkChangeWaitOutcome::Stopped) | Err(_) => {
                    close_server_network_change_monitor(monitor)?;
                    Err(RunError::RuntimeRoot)
                }
            }
        }
    }
}

#[cfg(all(not(windows), not(test)))]
pub(super) fn prepare_server_network_socket_service(
    _: &OwnerRegistry,
    metrics: &Metrics,
) -> Result<Arc<ServerNetworkSocketService>, RunError> {
    // Portable servers do not have a platform network-change catalog. Their
    // sockets remain owned by Tokio and keep the single startup generation.
    metrics.set_network_generation(1);
    Ok(Arc::new(ServerNetworkSocketService))
}

#[cfg(test)]
pub(super) fn prepare_server_network_socket_service(
    registry: &OwnerRegistry,
    metrics: &Metrics,
) -> Result<Arc<ServerNetworkSocketService>, RunError> {
    let binding = ferrum2_net::InterfaceBinding::new(
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
