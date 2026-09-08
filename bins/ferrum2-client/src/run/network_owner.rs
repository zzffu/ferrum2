use super::{RunError, egress, network_wait, tun};
use ferrum2_observability::Metrics;
use ferrum2_runtime::OwnerRegistry;
use std::sync::Arc;

/// Owns all process-wide physical network work beyond any process-root future.
pub(super) struct ClientNetworkRuntime {
    baseline: ferrum2_runtime::OwnerSnapshot,
    pub(super) coordinator: ferrum2_runtime::NetworkResetCoordinator,
    pub(super) catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    pub(super) sockets: Arc<egress::ClientNetworkSocketService>,
    owner: Arc<tokio::sync::Mutex<ferrum2_runtime::NetworkSocketOwner>>,
    native: Option<(
        Arc<tokio::sync::Mutex<network_wait::NativeNetworkChangeOwner>>,
        network_wait::NativeNetworkChangeWait,
    )>,
}
impl ClientNetworkRuntime {
    pub(super) fn prepare_generation(
        registry: OwnerRegistry,
        metrics: Arc<Metrics>,
        has_tun: bool,
    ) -> Result<Self, RunError> {
        let monitor = if has_tun {
            None
        } else {
            Some(
                ferrum2_platform_windows::WindowsNetworkChangeMonitor::new()
                    .map_err(|_| RunError::StartupRuntime)?,
            )
        };
        Self::prepare(registry, metrics, monitor)
    }
    pub(super) fn prepare(
        registry: OwnerRegistry,
        metrics: Arc<Metrics>,
        monitor: Option<ferrum2_platform_windows::WindowsNetworkChangeMonitor>,
    ) -> Result<Self, RunError> {
        let baseline = registry.snapshot();
        let catalog = ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
        let snapshot = match ferrum2_net::NetworkSnapshot::capture(1, &catalog) {
            Ok(snapshot) => Arc::new(snapshot),
            Err(_) => {
                if let Some(monitor) = monitor {
                    monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
                }
                return Err(RunError::StartupProtocol);
            }
        };
        let coordinator = tun::network_reset_coordinator(snapshot, registry.clone());
        metrics.set_network_generation(coordinator.status().published_generation());
        let (sockets, owner) = egress::ClientNetworkSocketService::new(
            coordinator.clone(),
            catalog.clone(),
            metrics,
            registry,
        );
        Ok(Self {
            baseline,
            coordinator,
            catalog,
            sockets: Arc::new(sockets),
            owner,
            native: monitor.map(|monitor| {
                let (owner, waiter) = network_wait::NativeNetworkChangeOwner::new(monitor);
                (Arc::new(tokio::sync::Mutex::new(owner)), waiter)
            }),
        })
    }
    pub(super) fn resources(&self) -> super::ClientNetworkResources {
        super::ClientNetworkResources {
            process: ferrum2_runtime::ProcessResources {
                baseline: self.baseline,
                cleanup: self.cleanup(),
            },
            coordinator: self.coordinator.clone(),
            catalog: self.catalog.clone(),
            sockets: Arc::clone(&self.sockets),
            change_monitor: self.native.as_ref().map(|(_, waiter)| waiter.clone()),
        }
    }
    pub(super) fn cleanup(&self) -> ferrum2_runtime::ProcessFuture<Result<(), RunError>> {
        let native = self.native.as_ref().map(|(owner, _)| Arc::clone(owner));
        let sockets = Arc::clone(&self.owner);
        let reset_hub = self.sockets.reset_hub();
        Box::pin(async move {
            let reset = reset_hub.stop().map_err(|()| RunError::ShutdownCleanup);
            let native = match native {
                Some(owner) => owner.lock().await.shutdown().await,
                None => Ok(()),
            };
            let sockets = sockets
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|_| RunError::ShutdownCleanup);
            reset.and(native).and(sockets)
        })
    }
    pub(super) async fn shutdown(&mut self) -> Result<(), RunError> {
        self.cleanup().await
    }
}
