use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ferrum2_net::NetworkSnapshot;
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::network::{NetworkSnapshotPublishError, NetworkSnapshotPublisher, ResetNetwork};
use crate::owner::OwnerRegistry;

use super::{
    NetworkResetCoordinatorError, NetworkResetHookStage, NetworkResetIntent, NetworkResetLimits,
    NetworkResetRequestDisposition, NetworkResetSignal, NetworkResetState, NetworkRuntimeOwnerKind,
};

pub(super) fn owner_is_stale(owner: &RuntimeOwnerEntry, signal: NetworkResetSignal) -> bool {
    owner.generation < signal.target_generation
        || (owner.generation == signal.target_generation
            && matches!(signal.intent, NetworkResetIntent::FullRebuild(_)))
}

pub(super) fn publish_snapshot(
    publisher: &NetworkSnapshotPublisher,
    snapshot: &Arc<NetworkSnapshot>,
) -> Result<(), NetworkResetCoordinatorError> {
    let current = publisher.snapshot();
    match snapshot.generation().cmp(&current.generation()) {
        std::cmp::Ordering::Less => Err(NetworkResetCoordinatorError::SnapshotPublicationStale),
        std::cmp::Ordering::Equal => {
            if **snapshot == *current {
                Ok(())
            } else {
                Err(NetworkResetCoordinatorError::ConflictingGenerationSnapshot)
            }
        }
        std::cmp::Ordering::Greater => publisher
            .publish_if_current(current.generation(), Arc::clone(snapshot))
            .map(|_| ())
            .map_err(|error| match error {
                NetworkSnapshotPublishError::StaleExpectedGeneration => {
                    NetworkResetCoordinatorError::SnapshotPublicationStale
                }
                NetworkSnapshotPublishError::NonMonotonicGeneration => {
                    NetworkResetCoordinatorError::SnapshotPublicationNonMonotonic
                }
            }),
    }
}

pub(super) fn queue_pending(
    state: &mut CoordinatorState,
    incoming: PendingReset,
) -> Result<NetworkResetRequestDisposition, NetworkResetCoordinatorError> {
    let disposition = if state.pending.is_some() {
        NetworkResetRequestDisposition::Coalesced
    } else {
        NetworkResetRequestDisposition::Queued
    };
    if let Some(pending) = state.pending.as_mut() {
        merge_pending(pending, incoming)?;
    } else {
        state.pending = Some(incoming);
    }
    state.phase = NetworkResetState::ResetPending;
    Ok(disposition)
}

pub(super) fn merge_pending(
    pending: &mut PendingReset,
    incoming: PendingReset,
) -> Result<(), NetworkResetCoordinatorError> {
    let existing_damage = pending.intent.full_rebuild_damage();
    let incoming_damage = incoming.intent.full_rebuild_damage();
    match incoming
        .snapshot
        .generation()
        .cmp(&pending.snapshot.generation())
    {
        std::cmp::Ordering::Less => {}
        std::cmp::Ordering::Equal => {
            if *incoming.snapshot != *pending.snapshot {
                return Err(NetworkResetCoordinatorError::ConflictingGenerationSnapshot);
            }
            if existing_damage.is_none() {
                pending.intent = incoming.intent;
            }
        }
        std::cmp::Ordering::Greater => {
            pending.snapshot = incoming.snapshot;
            pending.intent = incoming.intent;
        }
    }
    if let Some(damage) = existing_damage.or(incoming_damage) {
        pending.intent = NetworkResetIntent::FullRebuild(damage);
    }
    Ok(())
}

pub(super) struct CoordinatorInner {
    pub(super) snapshots: NetworkSnapshotPublisher,
    pub(super) limits: NetworkResetLimits,
    pub(super) owners: OwnerRegistry,
    pub(super) state: Mutex<CoordinatorState>,
    pub(super) owner_changes: watch::Sender<u64>,
    pub(super) driver: AsyncMutex<()>,
}

pub(super) struct CoordinatorState {
    pub(super) phase: NetworkResetState,
    pub(super) hooks: BTreeMap<u64, HookEntry>,
    pub(super) runtime_owners: BTreeMap<u64, RuntimeOwnerEntry>,
    pub(super) next_hook_id: u64,
    pub(super) next_runtime_owner_id: u64,
    pub(super) pending: Option<PendingReset>,
    pub(super) active: Option<ActiveReset>,
    pub(super) full_rebuild: Option<PendingReset>,
}

impl CoordinatorState {
    pub(super) fn new() -> Self {
        Self {
            phase: NetworkResetState::Active,
            hooks: BTreeMap::new(),
            runtime_owners: BTreeMap::new(),
            next_hook_id: 1,
            next_runtime_owner_id: 1,
            pending: None,
            active: None,
            full_rebuild: None,
        }
    }

    pub(super) fn admission_open(&self) -> bool {
        self.phase == NetworkResetState::Active
    }
}

pub(super) struct HookEntry {
    pub(super) stage: NetworkResetHookStage,
    pub(super) hook: Arc<dyn ResetNetwork>,
}

pub(super) struct RuntimeOwnerEntry {
    pub(super) generation: u64,
    pub(super) kind: NetworkRuntimeOwnerKind,
    pub(super) cancellation: watch::Sender<Option<NetworkResetSignal>>,
}

#[derive(Clone)]
pub(super) struct PendingReset {
    pub(super) snapshot: Arc<NetworkSnapshot>,
    pub(super) intent: NetworkResetIntent,
}

#[derive(Clone)]
pub(super) struct ActiveReset {
    pub(super) snapshot: Arc<NetworkSnapshot>,
}

pub(super) struct ResetAttemptGuard {
    pub(super) coordinator: Arc<CoordinatorInner>,
    pub(super) target: Option<PendingReset>,
}

impl ResetAttemptGuard {
    pub(super) fn new(coordinator: Arc<CoordinatorInner>, target: PendingReset) -> Self {
        Self {
            coordinator,
            target: Some(target),
        }
    }

    pub(super) fn target(&self) -> &PendingReset {
        self.target.as_ref().expect("active reset target")
    }

    pub(super) fn complete(&mut self) -> PendingReset {
        self.target.take().expect("active reset target")
    }
}

impl Drop for ResetAttemptGuard {
    fn drop(&mut self) {
        let Some(target) = self.target.take() else {
            return;
        };
        let mut state = lock_unpoisoned(&self.coordinator.state);
        state.active = None;
        if let Some(pending) = state.pending.as_mut() {
            if merge_pending(pending, target).is_err() {
                debug_assert!(
                    false,
                    "validated reset targets cannot conflict during retry"
                );
            }
        } else {
            state.pending = Some(target);
        }
        state.phase = NetworkResetState::RetryReset;
    }
}

pub(super) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
