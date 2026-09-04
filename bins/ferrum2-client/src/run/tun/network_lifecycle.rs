use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    pub(in crate::run) coordinator: NetworkResetCoordinator,
    pub(in crate::run) underlay: ferrum2_tun::UnderlayPublisher,
    pub(in crate::run) network_interface_catalog:
        ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
}

#[cfg(all(windows, not(test)))]
pub(in crate::run) fn network_change_process_root(
    context: Arc<ClientContext>,
    coordinator: NetworkResetCoordinator,
    catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    monitor: ferrum2_platform_windows::WindowsNetworkChangeMonitor,
) -> ProcessRoot<RunError> {
    ProcessRoot::new_cancellable(move |_| async move {
        Ok(Some(ClientNetworkChangeRoot {
            monitor,
            catalog,
            reset: Arc::new(ClientNetworkResetRuntime::new(&context, coordinator)),
        }))
    })
}

#[cfg(all(windows, not(test)))]
pub(super) struct ClientNetworkChangeRoot {
    monitor: ferrum2_platform_windows::WindowsNetworkChangeMonitor,
    catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
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
            let Self {
                monitor,
                catalog,
                reset,
            } = *self;
            let mut monitor = Some(monitor);
            let run_result = async {
                loop {
                    let current = monitor.take().ok_or(RunError::ShutdownCleanup)?;
                    let (returned, outcome) = wait_for_network_change(
                        current,
                        NETWORK_CHANGE_WAIT_BOUND,
                        &mut cancellation,
                    )
                    .await?;
                    monitor = Some(returned);
                    match outcome? {
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::Stopped => {
                            return Ok(());
                        }
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::TimedOut => continue,
                        ferrum2_platform_windows::NetworkChangeWaitOutcome::Changed => {}
                    }
                    loop {
                        let current = monitor.take().ok_or(RunError::ShutdownCleanup)?;
                        let (returned, outcome) = wait_for_network_change(
                            current,
                            NETWORK_CHANGE_QUIET_PERIOD,
                            &mut cancellation,
                        )
                        .await?;
                        monitor = Some(returned);
                        match outcome? {
                            ferrum2_platform_windows::NetworkChangeWaitOutcome::Stopped => {
                                return Ok(());
                            }
                            ferrum2_platform_windows::NetworkChangeWaitOutcome::TimedOut => break,
                            ferrum2_platform_windows::NetworkChangeWaitOutcome::Changed => {}
                        }
                    }
                    let mut retry = false;
                    loop {
                        let metric_reason = if retry {
                            NetworkResetReason::Retry
                        } else {
                            NetworkResetReason::NetworkChange
                        };
                        reset
                            .metrics
                            .network_reset(metric_reason, NetworkLifecycleResult::Started);
                        let reset_result = tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                reset.metrics.network_reset(
                                    metric_reason,
                                    NetworkLifecycleResult::Failed,
                                );
                                return Ok(());
                            }
                            result = reset_client_network(&catalog, &reset, retry) => result,
                        };
                        match reset_result {
                            Ok(()) => {
                                reset.metrics.network_reset(
                                    metric_reason,
                                    NetworkLifecycleResult::Succeeded,
                                );
                                break;
                            }
                            Err(_) => {
                                reset
                                    .metrics
                                    .network_reset(metric_reason, NetworkLifecycleResult::Failed);
                                retry = true;
                                tokio::select! {
                                    biased;
                                    _ = cancellation.cancelled() => return Ok(()),
                                    _ = tokio::time::sleep(NETWORK_RESET_RETRY_DELAY) => {}
                                }
                            }
                        }
                    }
                }
            }
            .await;
            let cleanup = match monitor {
                Some(monitor) => monitor.close().map_err(|_| RunError::ShutdownCleanup),
                None => Err(RunError::ShutdownCleanup),
            };
            match cleanup {
                Ok(()) => run_result,
                Err(error) => Err(error),
            }
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            let Self { monitor, .. } = *self;
            monitor.close().map_err(|_| RunError::ShutdownCleanup)
        })
    }
}

#[cfg(all(windows, not(test)))]
async fn reset_client_network(
    catalog: &ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    reset: &ClientNetworkResetRuntime,
    retry: bool,
) -> Result<(), ferrum2_tun::TunNetworkResetError> {
    if reset.coordinator.status().pending_generation().is_some() {
        return reset.retry().await;
    }
    let snapshot = capture_next_network_snapshot(catalog, &reset.coordinator)
        .await
        .map_err(|()| ferrum2_tun::TunNetworkResetError)?;
    let reason = if retry {
        ferrum2_tun::TunNetworkResetReason::Retry
    } else {
        ferrum2_tun::TunNetworkResetReason::NetworkChange
    };
    reset.reset(snapshot, reason).await
}

#[cfg(all(windows, not(test)))]
async fn wait_for_network_change(
    mut monitor: ferrum2_platform_windows::WindowsNetworkChangeMonitor,
    timeout: Duration,
    cancellation: &mut ProcessCancellation,
) -> Result<
    (
        ferrum2_platform_windows::WindowsNetworkChangeMonitor,
        Result<ferrum2_platform_windows::NetworkChangeWaitOutcome, RunError>,
    ),
    RunError,
> {
    let stop = monitor.stop_signal();
    let mut waiting = tokio::task::spawn_blocking(move || {
        let result = monitor.wait(timeout);
        (monitor, result)
    });
    tokio::select! {
        biased;
        result = &mut waiting => {
            let (monitor, outcome) = result.map_err(|_| RunError::RuntimeRoot)?;
            Ok((monitor, outcome.map_err(|_| RunError::RuntimeRoot)))
        }
        _ = cancellation.cancelled() => {
            let stopped = stop.signal();
            let (monitor, outcome) = (&mut waiting)
                .await
                .map_err(|_| RunError::ShutdownCleanup)?;
            let outcome = match (stopped, outcome) {
                (Ok(()), Ok(_)) => Ok(ferrum2_platform_windows::NetworkChangeWaitOutcome::Stopped),
                _ => Err(RunError::ShutdownCleanup),
            };
            Ok((monitor, outcome))
        }
    }
}

#[cfg(all(windows, not(test)))]
async fn capture_next_network_snapshot(
    catalog: &ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    coordinator: &NetworkResetCoordinator,
) -> Result<Arc<NetworkSnapshot>, ()> {
    let generation = coordinator
        .status()
        .published_generation()
        .checked_add(1)
        .ok_or(())?;
    let catalog = catalog.clone();
    tokio::task::spawn_blocking(move || {
        NetworkSnapshot::capture(generation, &catalog).map(Arc::new)
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
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

pub(super) struct ClientNetworkResetRuntime {
    pub(super) coordinator: NetworkResetCoordinator,
    pub(super) hooks: [Arc<ClientNetworkResetHook>; 4],
    registrations: Mutex<Option<[NetworkResetHookRegistration; 4]>>,
    hook_udp_associations: Arc<AtomicUsize>,
    pending_full_rebuild_udp_associations: AtomicUsize,
    egress: Arc<crate::run::egress::ClientEgressEngine>,
    metrics: Arc<Metrics>,
}

impl ClientNetworkResetRuntime {
    pub(super) fn new(context: &Arc<ClientContext>, coordinator: NetworkResetCoordinator) -> Self {
        let initial_generation = coordinator.status().published_generation();
        let accept: ClientNetworkResetAction = Arc::new(|_| Ok(()));
        // The owner has already constructed the stack when it crosses the bounded bridge.
        // Router and inbound listeners retain no interface-bound cache today, so their hooks are
        // generation acceptance barriers. Outbound owns the shared UDP sessions (including DNS
        // UDP egress) and cancels them below; TUN TCP work is acknowledged by runtime owners.
        let stack = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let router = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let egress = Arc::clone(&context.egress);
        let hook_udp_associations = Arc::new(AtomicUsize::new(0));
        let reset_associations = Arc::clone(&hook_udp_associations);
        let outbound_egress = Arc::clone(&egress);
        let outbound = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::new(move |_| {
                let udp_associations = outbound_egress.reset_network();
                reset_associations.fetch_add(udp_associations, Ordering::AcqRel);
                Ok(())
            }),
        ));
        let inbound_dns = Arc::new(ClientNetworkResetHook::new(
            initial_generation,
            Arc::clone(&accept),
        ));
        let hooks = [stack, router, outbound, inbound_dns];
        Self {
            coordinator,
            hooks,
            registrations: Mutex::new(None),
            hook_udp_associations,
            pending_full_rebuild_udp_associations: AtomicUsize::new(0),
            egress,
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

    fn require_current_or_next_generation(
        &self,
        snapshot: &NetworkSnapshot,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let published = self.coordinator.snapshots().snapshot();
        if snapshot == published.as_ref() {
            return Ok(());
        }
        let Some(expected) = published.generation().checked_add(1) else {
            return Err(ferrum2_tun::TunNetworkResetError);
        };
        if snapshot.generation() == expected {
            Ok(())
        } else {
            Err(ferrum2_tun::TunNetworkResetError)
        }
    }

    fn snapshot_is_applied(&self, snapshot: &NetworkSnapshot) -> bool {
        snapshot == self.coordinator.snapshots().snapshot().as_ref()
            && self.hooks.iter().all(|hook| {
                hook.accepted_generation.load(Ordering::Acquire) == snapshot.generation()
            })
    }

    fn take_hook_udp_associations(&self) -> usize {
        self.hook_udp_associations.swap(0, Ordering::AcqRel)
    }

    pub(super) async fn initialize(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        self.require_next_generation(&snapshot)?;
        self.register_hooks()?;
        let report = self
            .coordinator
            .reset_network(
                Arc::clone(&snapshot),
                NetworkResetIntent::Ordinary(RuntimeNetworkResetReason::ExplicitRequest),
            )
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        if report.outcome() != NetworkResetOutcome::ResetCompleted {
            return Err(ferrum2_tun::TunNetworkResetError);
        }
        let _ = self.take_hook_udp_associations();
        self.metrics.set_network_generation(snapshot.generation());
        Ok(())
    }

    pub(super) async fn reset(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        reason: ferrum2_tun::TunNetworkResetReason,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        self.register_hooks()?;
        self.require_current_or_next_generation(&snapshot)?;
        let reason = match reason {
            ferrum2_tun::TunNetworkResetReason::NetworkChange => {
                RuntimeNetworkResetReason::InterfaceChanged
            }
            ferrum2_tun::TunNetworkResetReason::Retry => RuntimeNetworkResetReason::ExplicitRequest,
        };
        let report = self
            .coordinator
            .reset_network(Arc::clone(&snapshot), NetworkResetIntent::Ordinary(reason))
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::ResetCompleted => {
                self.metrics.network_associations_reset(
                    NetworkLifecycleOperation::ResetNetwork,
                    Transport::Udp,
                    self.take_hook_udp_associations(),
                );
                self.metrics.set_network_generation(snapshot.generation());
                Ok(())
            }
            NetworkResetOutcome::Noop if self.snapshot_is_applied(&snapshot) => Ok(()),
            NetworkResetOutcome::Noop
            | NetworkResetOutcome::FullRebuildRequired(_)
            | NetworkResetOutcome::FullRebuildAcknowledged => {
                Err(ferrum2_tun::TunNetworkResetError)
            }
        }
    }

    #[cfg(all(windows, not(test)))]
    async fn retry(&self) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        self.register_hooks()?;
        let report = self
            .coordinator
            .retry_reset()
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::ResetCompleted => {
                self.metrics.network_associations_reset(
                    NetworkLifecycleOperation::ResetNetwork,
                    Transport::Udp,
                    self.take_hook_udp_associations(),
                );
                self.metrics
                    .set_network_generation(report.published_generation());
                Ok(())
            }
            NetworkResetOutcome::Noop
            | NetworkResetOutcome::FullRebuildRequired(_)
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
        self.require_next_generation(&snapshot)?;
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
                let udp_associations = self.egress.reset_network();
                self.pending_full_rebuild_udp_associations
                    .fetch_add(udp_associations, Ordering::AcqRel);
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
            .pending_full_rebuild_udp_associations
            .swap(0, Ordering::AcqRel)
            .saturating_add(self.take_hook_udp_associations());
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
