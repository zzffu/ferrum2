use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(all(windows, not(test)))]
use std::time::Duration;

use ferrum2_net::NetworkSnapshot;
use ferrum2_observability::{Metrics, NetworkLifecycleOperation, Transport};
#[cfg(all(windows, not(test)))]
use ferrum2_observability::{NetworkLifecycleResult, NetworkResetReason};
use ferrum2_runtime::{
    NetworkResetCoordinator, NetworkResetHookRegistration, NetworkResetHookStage,
    NetworkResetIntent, NetworkResetLimits, NetworkResetOutcome,
    NetworkResetReason as RuntimeNetworkResetReason, NetworkSnapshotPublisher, OwnerRegistry,
    ResetNetwork,
};
#[cfg(all(windows, not(test)))]
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot};

#[cfg(all(windows, not(test)))]
use crate::run::RunError;
use crate::run::context::ClientContext;

use super::observation::map_runtime_full_rebuild_reason;

#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_QUIET_PERIOD: Duration = Duration::from_millis(350);
#[cfg(all(windows, not(test)))]
const NETWORK_RESET_RETRY_DELAY: Duration = Duration::from_millis(250);
#[cfg(all(windows, not(test)))]
const NETWORK_CHANGE_WAIT_BOUND: Duration = Duration::from_secs(1);

pub(in crate::run) fn network_reset_coordinator(
    initial_snapshot: Arc<NetworkSnapshot>,
    registry: OwnerRegistry,
) -> NetworkResetCoordinator {
    NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(initial_snapshot),
        NetworkResetLimits::default(),
        registry,
    )
}

pub(in crate::run) struct TunNetworkServices {
    #[cfg(all(windows, not(test)))]
    pub(in crate::run) network_socket_service: Arc<crate::run::egress::ClientNetworkSocketService>,
    pub(in crate::run) coordinator: NetworkResetCoordinator,
    pub(in crate::run) underlay: ferrum2_tun::UnderlayPublisher,
    pub(in crate::run) network_interface_catalog:
        ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
}

#[cfg(all(windows, not(test)))]
pub(in crate::run) fn network_change_process_root(
    context: Arc<ClientContext>,
    coordinator: NetworkResetCoordinator,
    sockets: Arc<crate::run::egress::ClientNetworkSocketService>,
    monitor: crate::run::network_wait::NativeNetworkChangeWait,
) -> ProcessRoot<RunError> {
    ProcessRoot::new_cancellable(move |_| async move {
        Ok(Some(ClientNetworkChangeRoot {
            monitor,
            sockets: Arc::clone(&sockets),
            reset: Arc::new(ClientNetworkResetRuntime::new(
                &context,
                coordinator,
                sockets,
            )),
        }))
    })
}

#[cfg(all(windows, not(test)))]
pub(super) struct ClientNetworkChangeRoot {
    monitor: crate::run::network_wait::NativeNetworkChangeWait,
    sockets: Arc<crate::run::egress::ClientNetworkSocketService>,
    reset: Arc<ClientNetworkResetRuntime>,
}

#[cfg(all(windows, not(test)))]
impl PreparedProcessRoot<RunError> for ClientNetworkChangeRoot {
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
                    ferrum2_platform_windows::NetworkChangeWaitOutcome::Stopped => return Ok(()),
                    ferrum2_platform_windows::NetworkChangeWaitOutcome::TimedOut => continue,
                    ferrum2_platform_windows::NetworkChangeWaitOutcome::Changed => {}
                }
                loop {
                    let outcome = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Ok(()),
                        result = self.monitor.wait(NETWORK_CHANGE_QUIET_PERIOD) => result?,
                    };
                    match outcome {
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::Stopped => {
                            return Ok(());
                        }
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::TimedOut => break,
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::Changed => {}
                    }
                }
                let mut retry = false;
                loop {
                    let reason = if retry {
                        NetworkResetReason::Retry
                    } else {
                        NetworkResetReason::NetworkChange
                    };
                    self.reset
                        .record_reset(reason, NetworkLifecycleResult::Started);
                    let result = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            self.reset.record_reset(reason, NetworkLifecycleResult::Failed);
                            return Ok(());
                        }
                        result = reset_client_network(&self.sockets, &self.reset, retry) => result,
                    };
                    if result.is_ok() {
                        self.reset
                            .record_reset(reason, NetworkLifecycleResult::Succeeded);
                        break;
                    }
                    self.reset
                        .record_reset(reason, NetworkLifecycleResult::Failed);
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
        // The external network owner retains and joins any native wait even if this
        // root's factory/run future is cancelled or aborted.
        Box::pin(async move {
            drop(self);
            Ok(())
        })
    }
}

#[cfg(all(windows, not(test)))]
async fn reset_client_network(
    sockets: &crate::run::egress::ClientNetworkSocketService,
    reset: &ClientNetworkResetRuntime,
    retry: bool,
) -> Result<(), ferrum2_tun::TunNetworkResetError> {
    let _driver = reset.driver.lock().await;
    if reset.coordinator.status().pending_generation().is_some()
        || reset.hub.pending_generation().is_some()
    {
        return reset.retry_locked().await;
    }
    let generation = reset
        .coordinator
        .status()
        .published_generation()
        .checked_add(1)
        .ok_or(ferrum2_tun::TunNetworkResetError)?;
    let snapshot = sockets
        .capture_snapshot(generation)
        .await
        .map(Arc::new)
        .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
    let reason = if retry {
        RuntimeNetworkResetReason::ExplicitRequest
    } else {
        RuntimeNetworkResetReason::InterfaceChanged
    };
    if reset
        .coordinator
        .status()
        .published_generation()
        .checked_add(1)
        != Some(generation)
    {
        return Err(ferrum2_tun::TunNetworkResetError);
    }
    reset
        .reset_locked(snapshot, reason, ResetObservation::NetworkChange)
        .await
}

pub(super) type ClientNetworkResetAction = Arc<dyn Fn(u64) -> Result<(), ()> + Send + Sync>;

pub(super) struct ClientNetworkResetHook {
    pub(super) accepted_generation: AtomicU64,
    action: ClientNetworkResetAction,
}

impl ClientNetworkResetHook {
    pub(super) fn new(initial_generation: u64, action: ClientNetworkResetAction) -> Self {
        Self {
            accepted_generation: AtomicU64::new(initial_generation),
            action,
        }
    }
}

impl ResetNetwork for ClientNetworkResetHook {
    fn reset_network(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> ferrum2_runtime::NetworkResetFuture<'_> {
        Box::pin(async move {
            let generation = snapshot.generation();
            let current = self.accepted_generation.load(Ordering::Acquire);
            if generation < current {
                return Err(ferrum2_runtime::NetworkResetError);
            }
            if generation == current {
                return Ok(());
            }
            (self.action)(generation).map_err(|()| ferrum2_runtime::NetworkResetError)?;
            self.accepted_generation
                .store(generation, Ordering::Release);
            Ok(())
        })
    }
}

enum ResetObservation {
    Initialize,
    NetworkChange,
}

pub(super) struct ClientNetworkResetRuntime {
    #[cfg(all(windows, not(test)))]
    sockets: Arc<crate::run::egress::ClientNetworkSocketService>,
    pub(super) coordinator: NetworkResetCoordinator,
    pub(super) hooks: [Arc<ClientNetworkResetHook>; 4],
    registrations: Mutex<Option<[NetworkResetHookRegistration; 4]>>,
    hub: crate::run::egress::ClientNetworkResetHub,
    driver: Arc<tokio::sync::Mutex<()>>,
    metrics: Arc<Metrics>,
}

impl ClientNetworkResetRuntime {
    #[cfg(all(windows, not(test)))]
    fn record_reset(&self, reason: NetworkResetReason, result: NetworkLifecycleResult) {
        self.metrics.network_reset(reason, result);
        match result {
            NetworkLifecycleResult::Started => {}
            NetworkLifecycleResult::Succeeded | NetworkLifecycleResult::Failed => {
                ferrum2_observability::emit_network_reset_diagnostic(
                    ferrum2_observability::Role::Client,
                    reason,
                    result,
                    self.coordinator.snapshots().generation(),
                )
            }
        }
    }

    pub(super) fn new(
        context: &Arc<ClientContext>,
        coordinator: NetworkResetCoordinator,
        #[cfg(all(windows, not(test)))] sockets: Arc<
            crate::run::egress::ClientNetworkSocketService,
        >,
    ) -> Self {
        let initial_generation = coordinator.status().published_generation();
        let accept: ClientNetworkResetAction = Arc::new(|_| Ok(()));
        // Native packet polling is paused across the bridge. These hooks accept the
        // published generation; outbound fences capabilities without retiring storage.
        let stack = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let router = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let hub = context.egress.network_reset_hub();
        let outbound_hub = hub.clone();
        let outbound = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::new(move |generation| outbound_hub.fence(generation)),
        ));
        let inbound_dns = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let hooks = [stack, router, outbound, inbound_dns];
        Self {
            #[cfg(all(windows, not(test)))]
            sockets,
            coordinator,
            hooks,
            registrations: Mutex::new(None),
            driver: hub.driver(),
            hub,
            metrics: Arc::clone(&context.metrics),
        }
    }

    fn register_hooks(&self) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let mut registrations = self
            .registrations
            .lock()
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        if registrations.is_some() {
            return Ok(());
        }
        let registered = [
            self.coordinator
                .register_reset_hook(NetworkResetHookStage::Stack, self.hooks[0].clone())
                .map_err(|_| ferrum2_tun::TunNetworkResetError)?,
            self.coordinator
                .register_reset_hook(NetworkResetHookStage::Router, self.hooks[1].clone())
                .map_err(|_| ferrum2_tun::TunNetworkResetError)?,
            self.coordinator
                .register_reset_hook(NetworkResetHookStage::Outbound, self.hooks[2].clone())
                .map_err(|_| ferrum2_tun::TunNetworkResetError)?,
            self.coordinator
                .register_reset_hook(NetworkResetHookStage::Inbound, self.hooks[3].clone())
                .map_err(|_| ferrum2_tun::TunNetworkResetError)?,
        ];
        *registrations = Some(registered);
        Ok(())
    }

    fn require_next_generation(
        &self,
        snapshot: &NetworkSnapshot,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let Some(expected) = self
            .coordinator
            .status()
            .published_generation()
            .checked_add(1)
        else {
            return Err(ferrum2_tun::TunNetworkResetError);
        };
        if snapshot.generation() == expected {
            Ok(())
        } else {
            Err(ferrum2_tun::TunNetworkResetError)
        }
    }

    pub(super) async fn initialize(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let _driver = self.driver.lock().await;
        self.reset_locked(
            snapshot,
            RuntimeNetworkResetReason::ExplicitRequest,
            ResetObservation::Initialize,
        )
        .await
    }

    pub(super) async fn reset(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        reason: ferrum2_tun::TunNetworkResetReason,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let _driver = self.driver.lock().await;
        let reason = match reason {
            ferrum2_tun::TunNetworkResetReason::NetworkChange => {
                RuntimeNetworkResetReason::InterfaceChanged
            }
            ferrum2_tun::TunNetworkResetReason::Retry => RuntimeNetworkResetReason::ExplicitRequest,
        };
        self.reset_locked(snapshot, reason, ResetObservation::NetworkChange)
            .await
    }

    async fn reset_locked(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        reason: RuntimeNetworkResetReason,
        observation: ResetObservation,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        if self
            .hub
            .pending_generation()
            .is_some_and(|generation| generation != snapshot.generation())
        {
            return Err(ferrum2_tun::TunNetworkResetError);
        }
        let current = self.coordinator.snapshots().snapshot();
        if *snapshot != *current
            && current.generation().checked_add(1) != Some(snapshot.generation())
        {
            return Err(ferrum2_tun::TunNetworkResetError);
        }
        self.register_hooks()?;
        let report = self
            .coordinator
            .reset_network(Arc::clone(&snapshot), NetworkResetIntent::Ordinary(reason))
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::ResetCompleted | NetworkResetOutcome::Noop => {
                let count = self
                    .finish_generation(report.published_generation())
                    .await?;
                if matches!(observation, ResetObservation::NetworkChange) {
                    self.metrics.network_associations_reset(
                        NetworkLifecycleOperation::ResetNetwork,
                        Transport::Udp,
                        count,
                    );
                }
                self.metrics
                    .set_network_generation(report.published_generation());
                Ok(())
            }
            NetworkResetOutcome::FullRebuildRequired(_)
            | NetworkResetOutcome::FullRebuildAcknowledged => {
                Err(ferrum2_tun::TunNetworkResetError)
            }
        }
    }

    async fn finish_generation(
        &self,
        generation: u64,
    ) -> Result<usize, ferrum2_tun::TunNetworkResetError> {
        #[cfg(all(windows, not(test)))]
        self.sockets
            .retire_generation(generation.saturating_sub(1))
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        self.hub
            .complete(generation)
            .map_err(|()| ferrum2_tun::TunNetworkResetError)
    }

    #[cfg(all(windows, not(test)))]
    async fn retry_locked(&self) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        self.register_hooks()?;
        let report = self
            .coordinator
            .retry_reset()
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::ResetCompleted | NetworkResetOutcome::Noop => {
                let count = self
                    .finish_generation(report.published_generation())
                    .await?;
                self.metrics.network_associations_reset(
                    NetworkLifecycleOperation::ResetNetwork,
                    Transport::Udp,
                    count,
                );
                self.metrics
                    .set_network_generation(report.published_generation());
                Ok(())
            }
            NetworkResetOutcome::FullRebuildRequired(_)
            | NetworkResetOutcome::FullRebuildAcknowledged => {
                Err(ferrum2_tun::TunNetworkResetError)
            }
        }
    }

    async fn start_full_rebuild(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        reason: ferrum2_tun::TunNetworkFullRebuildReason,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let _driver = self.driver.lock().await;
        self.require_next_generation(&snapshot)?;
        let target_generation = snapshot.generation();
        let report = self
            .coordinator
            .reset_network(
                snapshot,
                NetworkResetIntent::FullRebuild(map_runtime_full_rebuild_reason(reason)),
            )
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::FullRebuildRequired(_) => {
                #[cfg(all(windows, not(test)))]
                self.sockets
                    .retire_generation(report.published_generation())
                    .await
                    .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
                self.hub
                    .fence(target_generation)
                    .map_err(|()| ferrum2_tun::TunNetworkResetError)?;
                self.hub
                    .retire(target_generation)
                    .map_err(|()| ferrum2_tun::TunNetworkResetError)?;
                Ok(())
            }
            NetworkResetOutcome::Noop
            | NetworkResetOutcome::ResetCompleted
            | NetworkResetOutcome::FullRebuildAcknowledged => {
                Err(ferrum2_tun::TunNetworkResetError)
            }
        }
    }

    async fn complete_full_rebuild(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let _driver = self.driver.lock().await;
        self.require_next_generation(&snapshot)?;
        for hook in &self.hooks {
            hook.reset_network(Arc::clone(&snapshot))
                .await
                .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        }
        let report = self
            .coordinator
            .acknowledge_full_rebuild(Arc::clone(&snapshot))
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        if report.outcome() != NetworkResetOutcome::FullRebuildAcknowledged {
            return Err(ferrum2_tun::TunNetworkResetError);
        }
        let udp_associations = self
            .hub
            .complete(snapshot.generation())
            .map_err(|()| ferrum2_tun::TunNetworkResetError)?;
        self.metrics.network_associations_reset(
            NetworkLifecycleOperation::FullRebuild,
            Transport::Udp,
            udp_associations,
        );
        self.metrics.set_network_generation(snapshot.generation());
        Ok(())
    }

    pub(super) async fn transition(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        lifecycle: ferrum2_tun::TunNetworkLifecycle,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        match lifecycle {
            ferrum2_tun::TunNetworkLifecycle::Initialize => self.initialize(snapshot).await,
            ferrum2_tun::TunNetworkLifecycle::ResetNetwork(reason) => {
                self.reset(snapshot, reason).await
            }
            ferrum2_tun::TunNetworkLifecycle::FullRebuildStarted(reason) => {
                self.start_full_rebuild(snapshot, reason).await
            }
            ferrum2_tun::TunNetworkLifecycle::FullRebuildCompleted(_) => {
                self.complete_full_rebuild(snapshot).await
            }
        }
    }
}

impl Drop for ClientNetworkResetRuntime {
    fn drop(&mut self) {
        // Final process resources observe the hub's sticky cleanup outcome.
        let _ = self.hub.stop();
    }
}
