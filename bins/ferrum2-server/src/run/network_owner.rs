use super::{RunError, network::ServerNetworkSocketService};
use ferrum2_observability::Metrics;
use ferrum2_runtime::OwnerRegistry;
use std::sync::Arc;

/// Process-wide physical work owner, retained beyond individual root futures.
pub(super) struct ServerNetworkRuntime {
    baseline: ferrum2_runtime::OwnerSnapshot,
    pub(super) sockets: Arc<ServerNetworkSocketService>,
    #[cfg(any(windows, test))]
    pub(super) owner: Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    #[cfg(all(windows, not(test)))]
    native: (
        Arc<tokio::sync::Mutex<super::network_wait::NativeNetworkChangeOwner>>,
        super::network_wait::NativeNetworkChangeWait,
    ),
}
pub(super) struct ServerNetworkRunParts {
    pub(super) sockets: Arc<ServerNetworkSocketService>,
    pub(super) process_resources: ferrum2_runtime::ProcessResources<RunError>,
    #[cfg(all(windows, not(test)))]
    pub(super) waiter: super::network_wait::NativeNetworkChangeWait,
    #[cfg(all(windows, not(test)))]
    pub(super) retirement: Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
}
impl ServerNetworkRuntime {
    pub(super) fn run_parts(&self) -> ServerNetworkRunParts {
        ServerNetworkRunParts {
            sockets: Arc::clone(&self.sockets),
            process_resources: self.process_resources(),
            #[cfg(all(windows, not(test)))]
            waiter: self.waiter(),
            #[cfg(all(windows, not(test)))]
            retirement: Arc::clone(&self.owner),
        }
    }

    pub(super) fn prepare(registry: &OwnerRegistry, metrics: &Metrics) -> Result<Self, RunError> {
        let baseline = registry.snapshot();
        #[cfg(all(windows, not(test)))]
        let monitor = ferrum2_platform_windows::WindowsNetworkChangeMonitor::new()
            .map_err(|_| RunError::StartupRuntime)?;
        #[cfg(all(windows, not(test)))]
        let catalog = ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
        #[cfg(all(windows, not(test)))]
        let initial = match ferrum2_net::NetworkSnapshot::capture(1, &catalog) {
            Ok(initial) => Arc::new(initial),
            Err(_) => {
                monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
                return Err(RunError::StartupRuntime);
            }
        };
        #[cfg(test)]
        let catalog = super::network::TestNetworkCatalog;
        #[cfg(test)]
        let initial = {
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
            Arc::new(
                ferrum2_net::NetworkSnapshot::new(1, Some(binding.clone()), Some(binding))
                    .map_err(|_| RunError::StartupRuntime)?,
            )
        };
        metrics.set_network_generation(1);
        #[cfg(any(windows, test))]
        {
            let limits = ferrum2_runtime::NetworkResetLimits::default();
            let coordinator = ferrum2_runtime::NetworkResetCoordinator::new(
                ferrum2_runtime::NetworkSnapshotPublisher::new(initial),
                limits,
                registry.clone(),
            );
            #[cfg(all(windows, not(test)))]
            let operations = ferrum2_runtime::SystemNetworkSocketOperations::new(
                ferrum2_platform_windows::WindowsResolvedSocketBinder,
            );
            #[cfg(test)]
            let operations = super::network::TestNetworkSocketOperations;
            let (sockets, owner) = ServerNetworkSocketService::new(
                coordinator,
                ferrum2_net::NetworkInterfaceResolver::new(catalog),
                operations,
                limits,
                registry.clone(),
            );
            Ok(Self {
                baseline,
                sockets: Arc::new(sockets),
                owner: Arc::new(tokio::sync::Mutex::new(owner)),
                #[cfg(all(windows, not(test)))]
                native: {
                    let (owner, waiter) =
                        super::network_wait::NativeNetworkChangeOwner::new(monitor);
                    (Arc::new(tokio::sync::Mutex::new(owner)), waiter)
                },
            })
        }
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = registry;
            Ok(Self {
                baseline,
                sockets: Arc::new(ServerNetworkSocketService),
            })
        }
    }
    #[cfg(all(windows, not(test)))]
    pub(super) fn waiter(&self) -> super::network_wait::NativeNetworkChangeWait {
        self.native.1.clone()
    }
    pub(super) fn process_resources(&self) -> ferrum2_runtime::ProcessResources<RunError> {
        ferrum2_runtime::ProcessResources {
            baseline: self.baseline,
            cleanup: self.cleanup(),
        }
    }
    pub(super) fn cleanup(&self) -> ferrum2_runtime::ProcessFuture<Result<(), RunError>> {
        #[cfg(all(windows, not(test)))]
        let native = Arc::clone(&self.native.0);
        #[cfg(any(windows, test))]
        let sockets = Arc::clone(&self.owner);
        Box::pin(async move {
            #[cfg(all(windows, not(test)))]
            let native = native.lock().await.shutdown().await;
            #[cfg(any(windows, test))]
            let sockets = sockets
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|_| RunError::ShutdownCleanup);
            #[cfg(all(windows, not(test)))]
            native?;
            #[cfg(any(windows, test))]
            sockets?;
            Ok(())
        })
    }
    pub(super) async fn shutdown(&mut self) -> Result<(), RunError> {
        self.cleanup().await
    }
}
