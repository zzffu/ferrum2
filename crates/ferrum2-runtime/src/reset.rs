use std::fmt;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use ferrum2_net::{
    DialOptions, NetworkInterfaceCatalog, NetworkInterfaceResolver, NetworkSnapshot,
    ResolvedInterface, RouteNetworkOptions,
};
use futures_util::FutureExt;
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::network::{NetworkSnapshotPublisher, ResetNetwork};
use crate::owner::OwnerRegistry;

mod admission;
mod report;
mod transition;

pub use admission::{
    AdmittedNetworkRuntimeResource, NetworkResetHookRegistration, NetworkResetSignal,
    NetworkRuntimeCancellation, NetworkRuntimeOwner, NetworkRuntimeOwnerCancellation,
    NetworkRuntimeResourceAdmissionError,
};
pub use report::{
    NetworkResetCoordinatorError, NetworkResetHookRegistrationError, NetworkResetOutcome,
    NetworkResetReport, NetworkResetRequestDisposition, NetworkResetState, NetworkResetStatus,
    NetworkRuntimeOwnerRegistrationError,
};
use transition::{
    ActiveReset, CoordinatorInner, CoordinatorState, HookEntry, PendingReset, ResetAttemptGuard,
    RuntimeOwnerEntry, lock_unpoisoned, merge_pending, owner_is_stale, publish_snapshot,
    queue_pending,
};

/// Default maximum number of registered reset hooks.
pub const DEFAULT_NETWORK_RESET_HOOKS: usize = 16;
/// Default maximum number of generation-bound runtime owners.
pub const DEFAULT_NETWORK_RUNTIME_OWNERS: usize = 65_536;
/// Hard upper bound for reset hooks accepted by one coordinator.
pub const MAX_NETWORK_RESET_HOOKS: usize = 64;
/// Hard upper bound for runtime owners accepted by one coordinator.
pub const MAX_NETWORK_RUNTIME_OWNERS: usize = 1_048_576;

/// Bounded registration limits for one network reset coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetLimits {
    max_hooks: usize,
    max_runtime_owners: usize,
}

impl NetworkResetLimits {
    /// Validates explicit hook and runtime-owner capacities.
    pub const fn new(
        max_hooks: usize,
        max_runtime_owners: usize,
    ) -> Result<Self, NetworkResetLimitsError> {
        if max_hooks == 0 {
            return Err(NetworkResetLimitsError::ZeroHooks);
        }
        if max_hooks > MAX_NETWORK_RESET_HOOKS {
            return Err(NetworkResetLimitsError::TooManyHooks);
        }
        if max_runtime_owners == 0 {
            return Err(NetworkResetLimitsError::ZeroRuntimeOwners);
        }
        if max_runtime_owners > MAX_NETWORK_RUNTIME_OWNERS {
            return Err(NetworkResetLimitsError::TooManyRuntimeOwners);
        }
        Ok(Self {
            max_hooks,
            max_runtime_owners,
        })
    }

    /// Returns the reset-hook registration bound.
    pub const fn max_hooks(self) -> usize {
        self.max_hooks
    }

    /// Returns the generation-bound owner registration bound.
    pub const fn max_runtime_owners(self) -> usize {
        self.max_runtime_owners
    }
}

impl Default for NetworkResetLimits {
    fn default() -> Self {
        Self {
            max_hooks: DEFAULT_NETWORK_RESET_HOOKS,
            max_runtime_owners: DEFAULT_NETWORK_RUNTIME_OWNERS,
        }
    }
}

/// Closed validation failure for coordinator capacities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetLimitsError {
    ZeroHooks,
    TooManyHooks,
    ZeroRuntimeOwners,
    TooManyRuntimeOwners,
}

/// Ordinary network-semantic event that requests a lightweight reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetReason {
    RouteChanged,
    InterfaceChanged,
    UnicastAddressChanged,
    DefaultInterfaceChanged,
    SourceAddressInvalid,
    ExplicitRequest,
    GenerationChangedDuringBind,
}

/// Closed managed-plane damage classification that permits a full rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedNetworkDamage {
    AdapterInvalid,
    DeviceSessionFatal,
    InterfaceIdentityMismatch,
    ManagedAddressDamaged,
    ManagedRouteDamaged,
    ManagedDnsDamaged,
    StrictRouteDamaged,
    OwnershipLedgerUntrusted,
    ManagedObjectMissing,
}

/// Whether one request is an ordinary runtime reset or an externally completed full rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetIntent {
    Ordinary(NetworkResetReason),
    FullRebuild(ManagedNetworkDamage),
}

impl NetworkResetIntent {
    const fn full_rebuild_damage(self) -> Option<ManagedNetworkDamage> {
        match self {
            Self::Ordinary(_) => None,
            Self::FullRebuild(damage) => Some(damage),
        }
    }
}

/// Fixed order for generation-bound task and connection cancellation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkRuntimeOwnerKind {
    /// Background work that must stop before active connections are closed.
    GenerationTask,
    /// Active TCP connection or flow.
    TcpConnection,
    /// Active UDP association.
    UdpAssociation,
}

/// Synchronous close target retained by the coordinator's central socket registry.
pub(crate) trait NetworkRuntimeOwnerCloser: Send + Sync {
    fn close(&self, cancellation: NetworkRuntimeOwnerCancellation);
}

const OWNER_RESET_ORDER: [NetworkRuntimeOwnerKind; 3] = [
    NetworkRuntimeOwnerKind::GenerationTask,
    NetworkRuntimeOwnerKind::TcpConnection,
    NetworkRuntimeOwnerKind::UdpAssociation,
];

/// Fixed hook order around atomic snapshot publication.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkResetHookStage {
    /// Replace stack-owned packet state before publishing the new snapshot.
    Stack,
    /// Accept the published generation in the router.
    Router,
    /// Replace outbound binders, DNS sockets, and other generation-bound state.
    Outbound,
    /// Replace inbound generation-bound state last.
    Inbound,
}

const POST_PUBLISH_HOOK_ORDER: [NetworkResetHookStage; 3] = [
    NetworkResetHookStage::Router,
    NetworkResetHookStage::Outbound,
    NetworkResetHookStage::Inbound,
];

#[derive(Clone)]
pub struct NetworkResetCoordinator {
    inner: Arc<CoordinatorInner>,
}

impl fmt::Debug for NetworkResetCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkResetCoordinator")
            .field("status", &self.status())
            .finish()
    }
}

impl NetworkResetCoordinator {
    /// Creates an active coordinator around an already-published initial snapshot.
    pub fn new(
        snapshots: NetworkSnapshotPublisher,
        limits: NetworkResetLimits,
        owners: OwnerRegistry,
    ) -> Self {
        let (owner_changes, _receiver) = watch::channel(0_u64);
        Self {
            inner: Arc::new(CoordinatorInner {
                snapshots,
                limits,
                owners,
                state: Mutex::new(CoordinatorState::new()),
                owner_changes,
                driver: AsyncMutex::new(()),
            }),
        }
    }

    /// Returns the shared immutable snapshot publisher controlled by this coordinator.
    pub fn snapshots(&self) -> NetworkSnapshotPublisher {
        self.inner.snapshots.clone()
    }

    /// Returns current state without exposing registered hooks or owner values.
    pub fn status(&self) -> NetworkResetStatus {
        let state = lock_unpoisoned(&self.inner.state);
        NetworkResetStatus {
            state: state.phase,
            admission_open: state.admission_open(),
            published_generation: self.inner.snapshots.generation(),
            active_generation: state
                .active
                .as_ref()
                .map(|active| active.snapshot.generation()),
            pending_generation: state
                .full_rebuild
                .as_ref()
                .or(state.pending.as_ref())
                .map(|pending| pending.snapshot.generation()),
            registered_hooks: state.hooks.len(),
            registered_runtime_owners: state.runtime_owner_count(),
        }
    }

    /// Registers one bounded hook. Hooks execute by stage and then registration order.
    pub fn register_reset_hook(
        &self,
        stage: NetworkResetHookStage,
        hook: Arc<dyn ResetNetwork>,
    ) -> Result<NetworkResetHookRegistration, NetworkResetHookRegistrationError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if !state.admission_open() {
            return Err(NetworkResetHookRegistrationError::AdmissionClosed);
        }
        if state.hooks.len() >= self.inner.limits.max_hooks {
            return Err(NetworkResetHookRegistrationError::CapacityExhausted);
        }
        let id = state.next_hook_id;
        state.next_hook_id = state
            .next_hook_id
            .checked_add(1)
            .ok_or(NetworkResetHookRegistrationError::IdentifierExhausted)?;
        state.hooks.insert(id, HookEntry { stage, hook });
        Ok(NetworkResetHookRegistration {
            coordinator: Arc::downgrade(&self.inner),
            id,
            stage,
            _owner: self.inner.owners.track_network_reset_hook(),
        })
    }

    /// Admits one generation-bound task or connection under the current open generation.
    ///
    /// Dropping the returned owner is the acknowledgement observed by reset ordering.
    pub fn register_runtime_owner(
        &self,
        generation: u64,
        kind: NetworkRuntimeOwnerKind,
    ) -> Result<NetworkRuntimeOwner, NetworkRuntimeOwnerRegistrationError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if !state.admission_open() {
            return Err(NetworkRuntimeOwnerRegistrationError::AdmissionClosed);
        }
        if generation != self.inner.snapshots.generation() {
            return Err(NetworkRuntimeOwnerRegistrationError::StaleGeneration);
        }
        if state.runtime_owner_count() >= self.inner.limits.max_runtime_owners {
            return Err(NetworkRuntimeOwnerRegistrationError::CapacityExhausted);
        }
        let registration_generation = state
            .next_runtime_owner_generation
            .checked_add(1)
            .ok_or(NetworkRuntimeOwnerRegistrationError::IdentifierExhausted)?;
        state.next_runtime_owner_generation = registration_generation;
        let (cancellation, receiver) = watch::channel(None);
        let handle = state
            .insert_runtime_owner(
                registration_generation,
                RuntimeOwnerEntry {
                    network_generation: generation,
                    kind,
                    cancellation,
                    closer: None,
                },
            )
            .ok_or(NetworkRuntimeOwnerRegistrationError::IdentifierExhausted)?;
        Ok(NetworkRuntimeOwner {
            coordinator: Arc::downgrade(&self.inner),
            handle,
            generation,
            kind,
            cancellation: receiver,
            _owner: self.inner.owners.track_network_runtime_owner(),
        })
    }

    /// Resolves, prepares, and admits one resource under an exact network generation.
    ///
    /// Preparation is never performed while holding the snapshot publisher or coordinator state
    /// lock. After preparation, the generation is checked explicitly and runtime-owner
    /// registration is the final admission step. A stale generation drops the prepared resource
    /// and retries the complete operation at most once.
    pub fn prepare_and_admit_runtime_resource<C, T, E>(
        &self,
        resolver: &NetworkInterfaceResolver<C>,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        kind: NetworkRuntimeOwnerKind,
        mut prepare: impl FnMut(&ResolvedInterface) -> Result<T, E>,
    ) -> Result<AdmittedNetworkRuntimeResource<T>, NetworkRuntimeResourceAdmissionError<E>>
    where
        C: NetworkInterfaceCatalog,
    {
        for attempt in 0..2 {
            let snapshot = self.inner.snapshots.snapshot();
            let resolved = match resolver.resolve(outbound, route, destination, &snapshot) {
                Ok(resolved) => resolved,
                Err(error) => {
                    if !self.inner.snapshots.is_current(snapshot.generation()) {
                        if attempt == 0 {
                            continue;
                        }
                        return Err(
                            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                                attempted_source: error.attempted_source(),
                            },
                        );
                    }
                    return Err(NetworkRuntimeResourceAdmissionError::InterfaceResolution(
                        error,
                    ));
                }
            };
            let attempted_source = resolved.selection_source();
            let resource = match prepare(&resolved) {
                Ok(resource) => resource,
                Err(error) => {
                    if !self
                        .inner
                        .snapshots
                        .is_current(resolved.snapshot_generation())
                    {
                        if attempt == 0 {
                            continue;
                        }
                        return Err(
                            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                                attempted_source,
                            },
                        );
                    }
                    return Err(NetworkRuntimeResourceAdmissionError::Preparation {
                        attempted_source,
                        error,
                    });
                }
            };

            if !self
                .inner
                .snapshots
                .is_current(resolved.snapshot_generation())
            {
                drop(resource);
                if attempt == 0 {
                    continue;
                }
                return Err(
                    NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                        attempted_source,
                    },
                );
            }

            match self.register_runtime_owner(resolved.snapshot_generation(), kind) {
                Ok(owner) => {
                    return Ok(AdmittedNetworkRuntimeResource {
                        resource,
                        resolved_interface: resolved,
                        owner,
                    });
                }
                Err(NetworkRuntimeOwnerRegistrationError::StaleGeneration) => {
                    drop(resource);
                    if attempt == 0 {
                        continue;
                    }
                    return Err(
                        NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                            attempted_source,
                        },
                    );
                }
                Err(error) => {
                    drop(resource);
                    return Err(
                        NetworkRuntimeResourceAdmissionError::RuntimeOwnerRegistration {
                            attempted_source,
                            error,
                        },
                    );
                }
            }
        }
        unreachable!("generation-bound admission has exactly two complete attempts")
    }

    /// Resolves, prepares, and admits one resource only if `expected_generation` is still active.
    ///
    /// Unlike [`Self::prepare_and_admit_runtime_resource`], this method never follows a network
    /// change to a newer generation. It is intended for a logical owner that already froze its
    /// network generation before the physical resource is created lazily. Any generation change
    /// drops the prepared resource and returns the existing closed generation-change category.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_and_admit_runtime_resource_for_generation<C, T, E>(
        &self,
        expected_generation: u64,
        resolver: &NetworkInterfaceResolver<C>,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        kind: NetworkRuntimeOwnerKind,
        prepare: impl FnOnce(&ResolvedInterface) -> Result<T, E>,
    ) -> Result<AdmittedNetworkRuntimeResource<T>, NetworkRuntimeResourceAdmissionError<E>>
    where
        C: NetworkInterfaceCatalog,
    {
        let snapshot = self.inner.snapshots.snapshot();
        let resolved = match resolver.resolve(outbound, route, destination, &snapshot) {
            Ok(resolved) => {
                if snapshot.generation() != expected_generation {
                    return Err(
                        NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                            attempted_source: resolved.selection_source(),
                        },
                    );
                }
                resolved
            }
            Err(error) => {
                if snapshot.generation() != expected_generation
                    || !self.inner.snapshots.is_current(expected_generation)
                {
                    return Err(
                        NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                            attempted_source: error.attempted_source(),
                        },
                    );
                }
                return Err(NetworkRuntimeResourceAdmissionError::InterfaceResolution(
                    error,
                ));
            }
        };
        let attempted_source = resolved.selection_source();
        let resource = match prepare(&resolved) {
            Ok(resource) => resource,
            Err(error) => {
                if !self.inner.snapshots.is_current(expected_generation) {
                    return Err(
                        NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                            attempted_source,
                        },
                    );
                }
                return Err(NetworkRuntimeResourceAdmissionError::Preparation {
                    attempted_source,
                    error,
                });
            }
        };

        if !self.inner.snapshots.is_current(expected_generation) {
            drop(resource);
            return Err(
                NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged { attempted_source },
            );
        }

        match self.register_runtime_owner(expected_generation, kind) {
            Ok(owner) => Ok(AdmittedNetworkRuntimeResource {
                resource,
                resolved_interface: resolved,
                owner,
            }),
            Err(NetworkRuntimeOwnerRegistrationError::StaleGeneration) => {
                drop(resource);
                Err(
                    NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                        attempted_source,
                    },
                )
            }
            Err(error) => {
                drop(resource);
                Err(
                    NetworkRuntimeResourceAdmissionError::RuntimeOwnerRegistration {
                        attempted_source,
                        error,
                    },
                )
            }
        }
    }

    /// Queues and serially drives one ordinary reset or full-rebuild intent.
    ///
    /// Newer queued generations replace older pending generations. A full-rebuild intent is never
    /// downgraded by a later ordinary notification. Hook failure and future cancellation preserve
    /// the pending request and keep admission closed for [`Self::retry_reset`].
    pub async fn reset_network(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        intent: NetworkResetIntent,
    ) -> Result<NetworkResetReport, NetworkResetCoordinatorError> {
        self.queue_reset(snapshot, intent)?;
        self.drive_reset().await
    }

    /// Places a notification into one bounded pending slot without spawning a driver task.
    ///
    /// A notification source can keep calling this method while one dedicated task runs
    /// [`Self::drive_reset`]. Only the newest pending generation is retained.
    pub fn queue_reset(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        intent: NetworkResetIntent,
    ) -> Result<NetworkResetRequestDisposition, NetworkResetCoordinatorError> {
        self.submit(snapshot, intent)
    }

    /// Serially drains all currently pending work, including work queued during a reset.
    pub async fn drive_reset(&self) -> Result<NetworkResetReport, NetworkResetCoordinatorError> {
        self.drive_pending().await
    }

    /// Retries preserved work after hook failure or cancellation.
    pub async fn retry_reset(&self) -> Result<NetworkResetReport, NetworkResetCoordinatorError> {
        self.drive_reset().await
    }

    /// Reopens admission after an external full rebuild and managed readback have completed.
    ///
    /// The external rebuild owns managed teardown/recreation and all component activation. This
    /// acknowledgement only validates/publishes its final snapshot and clears the held intent.
    pub async fn acknowledge_full_rebuild(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> Result<NetworkResetReport, NetworkResetCoordinatorError> {
        let _driver = self.inner.driver.lock().await;
        let _driver_owner = self.inner.owners.track_network_reset_driver();
        let mut state = lock_unpoisoned(&self.inner.state);
        let requested = state
            .full_rebuild
            .as_ref()
            .ok_or(NetworkResetCoordinatorError::FullRebuildNotPending)?;
        if state.runtime_owner_count() != 0 {
            return Err(NetworkResetCoordinatorError::FullRebuildOwnersRemain);
        }
        if snapshot.generation() < requested.snapshot.generation() {
            return Err(NetworkResetCoordinatorError::FullRebuildGenerationTooOld);
        }
        publish_snapshot(&self.inner.snapshots, &snapshot)?;
        state.full_rebuild = None;
        state.pending = None;
        state.active = None;
        state.phase = NetworkResetState::Active;
        Ok(NetworkResetReport {
            outcome: NetworkResetOutcome::FullRebuildAcknowledged,
            published_generation: snapshot.generation(),
            completed_resets: 0,
            cancelled_runtime_owners: 0,
        })
    }

    fn submit(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        intent: NetworkResetIntent,
    ) -> Result<NetworkResetRequestDisposition, NetworkResetCoordinatorError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        let current = self.inner.snapshots.snapshot();
        if snapshot.generation() < current.generation() {
            return Err(NetworkResetCoordinatorError::StaleRequestGeneration);
        }
        if snapshot.generation() == current.generation() && *snapshot != *current {
            return Err(NetworkResetCoordinatorError::ConflictingGenerationSnapshot);
        }
        let incoming = PendingReset { snapshot, intent };

        if let Some(rebuild) = state.full_rebuild.as_mut() {
            merge_pending(rebuild, incoming)?;
            rebuild.intent = NetworkResetIntent::FullRebuild(
                rebuild
                    .intent
                    .full_rebuild_damage()
                    .or(intent.full_rebuild_damage())
                    .expect("a held full rebuild remains a full rebuild"),
            );
            return Ok(NetworkResetRequestDisposition::Coalesced);
        }

        if let Some(active) = state.active.clone() {
            match incoming
                .snapshot
                .generation()
                .cmp(&active.snapshot.generation())
            {
                std::cmp::Ordering::Less => {
                    if let Some(damage) = incoming.intent.full_rebuild_damage() {
                        return queue_pending(
                            &mut state,
                            PendingReset {
                                snapshot: Arc::clone(&active.snapshot),
                                intent: NetworkResetIntent::FullRebuild(damage),
                            },
                        );
                    }
                    return Ok(NetworkResetRequestDisposition::Coalesced);
                }
                std::cmp::Ordering::Equal => {
                    if *incoming.snapshot != *active.snapshot {
                        return Err(NetworkResetCoordinatorError::ConflictingGenerationSnapshot);
                    }
                    if let Some(damage) = incoming.intent.full_rebuild_damage() {
                        return queue_pending(
                            &mut state,
                            PendingReset {
                                snapshot: Arc::clone(&active.snapshot),
                                intent: NetworkResetIntent::FullRebuild(damage),
                            },
                        );
                    }
                    return Ok(NetworkResetRequestDisposition::Coalesced);
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        if state.active.is_none()
            && state.pending.is_none()
            && incoming.snapshot.generation() == current.generation()
            && matches!(incoming.intent, NetworkResetIntent::Ordinary(_))
        {
            return Ok(NetworkResetRequestDisposition::Noop);
        }

        queue_pending(&mut state, incoming)
    }

    async fn drive_pending(&self) -> Result<NetworkResetReport, NetworkResetCoordinatorError> {
        let _driver = self.inner.driver.lock().await;
        let _driver_owner = self.inner.owners.track_network_reset_driver();
        let mut completed_resets = 0_usize;
        let mut cancelled_runtime_owners = 0_usize;

        loop {
            if let Some(damage) = self.pending_full_rebuild_damage() {
                return Ok(NetworkResetReport {
                    outcome: NetworkResetOutcome::FullRebuildRequired(damage),
                    published_generation: self.inner.snapshots.generation(),
                    completed_resets,
                    cancelled_runtime_owners,
                });
            }

            let Some(target) = self.take_pending() else {
                let mut state = lock_unpoisoned(&self.inner.state);
                if state.full_rebuild.is_some() {
                    continue;
                }
                if state.pending.is_some() {
                    continue;
                }
                state.phase = NetworkResetState::Active;
                return Ok(NetworkResetReport {
                    outcome: if completed_resets == 0 {
                        NetworkResetOutcome::Noop
                    } else {
                        NetworkResetOutcome::ResetCompleted
                    },
                    published_generation: self.inner.snapshots.generation(),
                    completed_resets,
                    cancelled_runtime_owners,
                });
            };

            let mut attempt = ResetAttemptGuard::new(Arc::clone(&self.inner), target);
            let signal = NetworkResetSignal {
                target_generation: attempt.target().snapshot.generation(),
                intent: attempt.target().intent,
            };
            cancelled_runtime_owners += self.cancel_runtime_owners(signal).await;

            if let Some(damage) = attempt.target().intent.full_rebuild_damage() {
                let target = attempt.complete();
                let mut state = lock_unpoisoned(&self.inner.state);
                state.active = None;
                let mut rebuild = target;
                if let Some(pending) = state.pending.take() {
                    merge_pending(&mut rebuild, pending)?;
                }
                rebuild.intent = NetworkResetIntent::FullRebuild(
                    rebuild.intent.full_rebuild_damage().unwrap_or(damage),
                );
                state.full_rebuild = Some(rebuild);
                state.phase = NetworkResetState::ManagedDamaged;
                return Ok(NetworkResetReport {
                    outcome: NetworkResetOutcome::FullRebuildRequired(damage),
                    published_generation: self.inner.snapshots.generation(),
                    completed_resets,
                    cancelled_runtime_owners,
                });
            }

            let hooks = self.snapshot_hooks();
            self.run_hook_stage(
                NetworkResetHookStage::Stack,
                &hooks,
                &attempt.target().snapshot,
            )
            .await?;
            publish_snapshot(&self.inner.snapshots, &attempt.target().snapshot)?;
            for stage in POST_PUBLISH_HOOK_ORDER {
                self.run_hook_stage(stage, &hooks, &attempt.target().snapshot)
                    .await?;
            }

            attempt.complete();
            let mut state = lock_unpoisoned(&self.inner.state);
            state.active = None;
            completed_resets += 1;
            if state.pending.is_some() {
                state.phase = NetworkResetState::ResetPending;
            } else {
                state.phase = NetworkResetState::Active;
            }
        }
    }

    fn pending_full_rebuild_damage(&self) -> Option<ManagedNetworkDamage> {
        lock_unpoisoned(&self.inner.state)
            .full_rebuild
            .as_ref()
            .and_then(|pending| pending.intent.full_rebuild_damage())
    }

    fn take_pending(&self) -> Option<PendingReset> {
        let mut state = lock_unpoisoned(&self.inner.state);
        let pending = state.pending.take()?;
        state.active = Some(ActiveReset {
            snapshot: Arc::clone(&pending.snapshot),
        });
        state.phase = NetworkResetState::Resetting;
        Some(pending)
    }

    fn snapshot_hooks(&self) -> Vec<(NetworkResetHookStage, u64, Arc<dyn ResetNetwork>)> {
        let state = lock_unpoisoned(&self.inner.state);
        let mut hooks = state
            .hooks
            .iter()
            .map(|(id, entry)| (entry.stage, *id, Arc::clone(&entry.hook)))
            .collect::<Vec<_>>();
        hooks.sort_by_key(|(stage, id, _)| (*stage, *id));
        hooks
    }

    async fn run_hook_stage(
        &self,
        stage: NetworkResetHookStage,
        hooks: &[(NetworkResetHookStage, u64, Arc<dyn ResetNetwork>)],
        snapshot: &Arc<NetworkSnapshot>,
    ) -> Result<(), NetworkResetCoordinatorError> {
        for (_, _, hook) in hooks
            .iter()
            .filter(|(hook_stage, _, _)| *hook_stage == stage)
        {
            let future = catch_unwind(AssertUnwindSafe(|| {
                hook.reset_network(Arc::clone(snapshot))
            }))
            .map_err(|_| NetworkResetCoordinatorError::HookPanicked(stage))?;
            match AssertUnwindSafe(future).catch_unwind().await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(NetworkResetCoordinatorError::HookFailed(stage)),
                Err(_) => return Err(NetworkResetCoordinatorError::HookPanicked(stage)),
            }
        }
        Ok(())
    }

    async fn cancel_runtime_owners(&self, signal: NetworkResetSignal) -> usize {
        let mut cancelled = 0_usize;
        for kind in OWNER_RESET_ORDER {
            let closers = {
                let state = lock_unpoisoned(&self.inner.state);
                let mut closers = Vec::new();
                for owner in state
                    .runtime_owners()
                    .filter(|owner| owner.kind == kind && owner_is_stale(owner, signal))
                {
                    // Delivery and closer discovery share this state-lock linearization point.
                    // A concurrently attached closer therefore either appears here or observes
                    // the already-delivered cancellation and closes itself before returning.
                    owner.cancellation.send_replace(Some(signal));
                    if let Some(closer) = owner.closer.as_ref() {
                        closers.push(Arc::clone(closer));
                    }
                    cancelled += 1;
                }
                closers
            };
            for closer in closers {
                closer.close(NetworkRuntimeOwnerCancellation::Reset(signal));
            }
            self.wait_for_runtime_owner_kind(kind, signal).await;
        }
        cancelled
    }

    async fn wait_for_runtime_owner_kind(
        &self,
        kind: NetworkRuntimeOwnerKind,
        signal: NetworkResetSignal,
    ) {
        let mut changes = self.inner.owner_changes.subscribe();
        loop {
            let remaining = lock_unpoisoned(&self.inner.state)
                .runtime_owners()
                .any(|owner| owner.kind == kind && owner_is_stale(owner, signal));
            if !remaining {
                return;
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for CoordinatorInner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for closer in state.take_runtime_owner_closers() {
            closer.close(NetworkRuntimeOwnerCancellation::CoordinatorDropped);
        }
    }
}
