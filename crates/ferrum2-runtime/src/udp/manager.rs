use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{Notify, Semaphore, broadcast, watch};
use tokio::time::Instant;

use crate::OwnerRegistry;
use crate::owner::OwnerGuard;

use super::reservation::{AccountedDatagram, UdpBufferBudget};
use super::session::{DatagramQueue, PendingUdpDatagram, PendingUdpSession, reserve_datagram};
use super::{
    UDP_SESSION_QUEUE_DEPTH, UdpDirection, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle,
};

mod reset;
use reset::NetworkFence;

pub(super) struct SessionEntry {
    pub(super) generation: u64,
    pub(super) last_activity: Instant,
    pub(super) committed: bool,
    pub(super) pending: [usize; 2],
    pub(super) queues: [DatagramQueue; 2],
    pub(super) notify: Arc<Notify>,
    pub(super) cancellation: watch::Sender<bool>,
    pub(super) _guard: OwnerGuard,
}

#[derive(Default)]
pub(super) struct SessionState {
    pub(super) entries: BTreeMap<u32, SessionEntry>,
    pub(super) next_generation: u64,
    pub(super) shutting_down: bool,
    pub(super) cleanup_failed: bool,
    network_fence: Option<NetworkFence>,
    completed_network_generation: u64,
}

pub(super) struct UdpSessionManagerInner {
    pub(super) limits: UdpRuntimeLimits,
    pub(super) budget: UdpBufferBudget,
    pub(super) owner_slots: Arc<Semaphore>,
    pub(super) runtime_owners: AtomicUsize,
    pub(super) running_runtimes: AtomicUsize,
    pub(super) state: Mutex<SessionState>,
    pub(super) removal_events: broadcast::Sender<UdpSessionHandle>,
    pub(super) registry: OwnerRegistry,
}

/// Protocol-neutral owner of generation, capacity, queues, and byte reservations.
#[derive(Clone)]
pub struct UdpSessionManager {
    pub(super) inner: Arc<UdpSessionManagerInner>,
}

impl UdpSessionManager {
    /// Creates an empty manager without allocating per-session state.
    pub fn new(limits: UdpRuntimeLimits, registry: OwnerRegistry) -> Self {
        let budget = UdpBufferBudget::new(limits.max_buffered_bytes(), registry.clone());
        let (removal_events, _) = broadcast::channel(limits.max_sessions());
        Self {
            inner: Arc::new(UdpSessionManagerInner {
                limits,
                budget,
                owner_slots: Arc::new(Semaphore::new(limits.max_sessions())),
                runtime_owners: AtomicUsize::new(0),
                running_runtimes: AtomicUsize::new(0),
                state: Mutex::new(SessionState::default()),
                removal_events,
                registry,
            }),
        }
    }

    /// Returns the global allocated-capacity reservation owner.
    pub fn buffer_budget(&self) -> UdpBufferBudget {
        self.inner.budget.clone()
    }

    pub(super) fn owner_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.inner.owner_slots)
    }

    pub(super) fn runtime_owner(&self) -> UdpRuntimeOwner {
        self.inner.runtime_owners.fetch_add(1, Ordering::Relaxed);
        self.inner.running_runtimes.fetch_add(1, Ordering::Relaxed);
        UdpRuntimeOwner {
            manager: self.clone(),
            shutdown_started: false,
        }
    }

    /// Returns the number of live committed and provisional session owners.
    pub fn session_count(&self) -> usize {
        lock_state(&self.inner).entries.len()
    }

    /// Reports a sticky contained protocol panic or internal cleanup invariant failure.
    pub fn cleanup_failed(&self) -> bool {
        lock_state(&self.inner).cleanup_failed
    }

    /// Subscribes to exact generation removals for event-driven mapping
    /// invalidation. A lagged receiver must fall back to a batch liveness pass.
    pub fn subscribe_removals(&self) -> broadcast::Receiver<UdpSessionHandle> {
        self.inner.removal_events.subscribe()
    }

    /// Retains only committed live generations using one read-only state lock.
    ///
    /// Shutdown, missing or stale generations, and provisional sessions are
    /// not live. Queue and buffer capacity do not affect liveness, and this
    /// check does not reserve capacity, refresh activity, or wake workers.
    pub fn retain_live_sessions(&self, handles: &mut Vec<UdpSessionHandle>) {
        let state = lock_state(&self.inner);
        if state.shutting_down || state.network_fence.is_some() {
            handles.clear();
            return;
        }
        handles.retain(|handle| {
            state
                .entries
                .get(&handle.slot)
                .is_some_and(|entry| entry.generation == handle.generation && entry.committed)
        });
    }

    /// Reserves a new generation without committing protocol activity.
    ///
    /// At capacity, exactly the deterministic oldest committed idle-expired
    /// entry is removed. Active and provisional state is never evicted.
    pub fn reserve_session(&self, now: Instant) -> Result<PendingUdpSession, UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        if state.shutting_down || state.network_fence.is_some() {
            return Err(UdpRuntimeError::Cancelled);
        }
        if state.entries.len() == self.inner.limits.max_sessions() {
            let expired = state
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.committed
                        && now.saturating_duration_since(entry.last_activity)
                            >= self.inner.limits.idle_timeout()
                })
                .min_by_key(|(slot, entry)| (entry.last_activity, **slot))
                .map(|(slot, _)| *slot);
            if let Some(slot) = expired
                && let Some(handle) = remove_entry(&mut state, slot)
            {
                publish_removal(&self.inner, handle);
            }
        }
        if state.entries.len() == self.inner.limits.max_sessions() {
            return Err(UdpRuntimeError::SessionLimit);
        }

        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or(UdpRuntimeError::Counter)?;
        state.next_generation = generation;
        let slot = (0..self.inner.limits.max_sessions() as u32)
            .find(|slot| !state.entries.contains_key(slot))
            .ok_or(UdpRuntimeError::SessionLimit)?;
        let handle = UdpSessionHandle { slot, generation };
        let (cancellation, _) = watch::channel(false);
        state.entries.insert(
            slot,
            SessionEntry {
                generation,
                last_activity: now,
                committed: false,
                pending: [0; 2],
                queues: std::array::from_fn(|_| DatagramQueue::new()),
                notify: Arc::new(Notify::new()),
                cancellation,
                _guard: self.inner.registry.track_udp_session(),
            },
        );
        let pending = PendingUdpSession {
            manager: Arc::clone(&self.inner),
            handle,
            committed: false,
        };
        Ok(pending)
    }

    /// Reserves one queue slot and its exact backing capacity for a live session.
    pub fn reserve_datagram(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.inner,
            handle,
            direction,
            allocated_capacity,
            true,
            true,
        )
    }

    /// Reserves one queue slot without charging the global UDP byte budget.
    ///
    /// This is only for callers whose datagrams remain structurally bounded by
    /// independent packet, queue, and owner-count limits. Bounds, queue depth,
    /// session generation, cancellation, and reserve-then-commit checks remain
    /// identical to [`Self::reserve_datagram`].
    pub fn reserve_unmetered_datagram(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.inner,
            handle,
            direction,
            allocated_capacity,
            true,
            false,
        )
    }

    /// Removes one exact generation and invalidates every late capability.
    pub fn remove(&self, handle: UdpSessionHandle) -> bool {
        let mut state = lock_state(&self.inner);
        let removed = if entry_matches(&state, handle) {
            remove_entry(&mut state, handle.slot)
        } else {
            None
        };
        drop(state);
        if let Some(handle) = removed {
            publish_removal(&self.inner, handle);
            true
        } else {
            false
        }
    }

    /// Removes every session and wakes every owned worker.
    pub fn cancel_all(&self) {
        let mut state = lock_state(&self.inner);
        state.shutting_down = true;
        let slots: Vec<_> = state.entries.keys().copied().collect();
        let removed: Vec<_> = slots
            .into_iter()
            .filter_map(|slot| remove_entry(&mut state, slot))
            .collect();
        drop(state);
        for handle in removed {
            publish_removal(&self.inner, handle);
        }
    }

    /// Requests shutdown without discarding already admitted queue entries.
    pub fn signal_all(&self) {
        let mut state = lock_state(&self.inner);
        state.shutting_down = true;
        for entry in state.entries.values() {
            entry.cancellation.send_replace(true);
            entry.notify.notify_waiters();
        }
    }

    /// Pops one queued datagram without changing accepted activity.
    pub fn pop(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
    ) -> Result<Option<AccountedDatagram>, UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        let entry = matching_entry_mut(&mut state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        Ok(entry.queues[direction.index()]
            .pop_front()
            .map(|queued| queued.datagram))
    }

    pub(super) fn validate_direct_response(
        &self,
        handle: UdpSessionHandle,
    ) -> Result<(), UdpRuntimeError> {
        let state = lock_state(&self.inner);
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        let entry = matching_entry(&state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        let index = UdpDirection::ToClient.index();
        if entry.pending[index] + entry.queues[index].len() >= UDP_SESSION_QUEUE_DEPTH {
            return Err(UdpRuntimeError::QueueFull);
        }
        Ok(())
    }

    pub(super) fn commit_activity(
        &self,
        handle: UdpSessionHandle,
        now: Instant,
    ) -> Result<(), UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        let entry = matching_entry_mut(&mut state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        entry.last_activity = entry.last_activity.max(now);
        Ok(())
    }

    /// Subscribes to cancellation for one exact live generation.
    pub fn cancellation(
        &self,
        handle: UdpSessionHandle,
    ) -> Result<watch::Receiver<bool>, UdpRuntimeError> {
        let state = lock_state(&self.inner);
        let entry = matching_entry(&state, handle)?;
        Ok(entry.cancellation.subscribe())
    }

    pub(super) fn notify(&self, handle: UdpSessionHandle) -> Result<Arc<Notify>, UdpRuntimeError> {
        let state = lock_state(&self.inner);
        Ok(Arc::clone(&matching_entry(&state, handle)?.notify))
    }

    /// Returns the manager-owned idle deadline for one exact live generation.
    pub fn idle_deadline(&self, handle: UdpSessionHandle) -> Result<Instant, UdpRuntimeError> {
        let state = lock_state(&self.inner);
        Ok(matching_entry(&state, handle)?.last_activity + self.inner.limits.idle_timeout())
    }
}

pub(super) struct UdpRuntimeOwner {
    pub(super) manager: UdpSessionManager,
    pub(super) shutdown_started: bool,
}

impl UdpRuntimeOwner {
    pub(super) fn begin_shutdown(&mut self) {
        if !self.shutdown_started {
            self.shutdown_started = true;
            if self
                .manager
                .inner
                .running_runtimes
                .fetch_sub(1, Ordering::AcqRel)
                == 1
            {
                self.manager.signal_all();
            }
        }
    }
}

impl Drop for UdpRuntimeOwner {
    fn drop(&mut self) {
        self.begin_shutdown();
        if self
            .manager
            .inner
            .runtime_owners
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            self.manager.cancel_all();
        }
    }
}

pub(super) fn entry_matches(state: &SessionState, handle: UdpSessionHandle) -> bool {
    state
        .entries
        .get(&handle.slot)
        .is_some_and(|entry| entry.generation == handle.generation)
}

pub(super) fn matching_entry(
    state: &SessionState,
    handle: UdpSessionHandle,
) -> Result<&SessionEntry, UdpRuntimeError> {
    if state
        .network_fence
        .is_some_and(|fence| handle.generation <= fence.cutoff)
    {
        return Err(UdpRuntimeError::Cancelled);
    }
    state
        .entries
        .get(&handle.slot)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

pub(super) fn matching_entry_mut(
    state: &mut SessionState,
    handle: UdpSessionHandle,
) -> Result<&mut SessionEntry, UdpRuntimeError> {
    if state
        .network_fence
        .is_some_and(|fence| handle.generation <= fence.cutoff)
    {
        return Err(UdpRuntimeError::Cancelled);
    }
    state
        .entries
        .get_mut(&handle.slot)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

pub(super) fn remove_entry(state: &mut SessionState, slot: u32) -> Option<UdpSessionHandle> {
    if let Some(entry) = state.entries.remove(&slot) {
        let handle = UdpSessionHandle {
            slot,
            generation: entry.generation,
        };
        entry.cancellation.send_replace(true);
        entry.notify.notify_waiters();
        Some(handle)
    } else {
        None
    }
}

pub(super) fn publish_removal(manager: &UdpSessionManagerInner, handle: UdpSessionHandle) {
    let _ = manager.removal_events.send(handle);
}

/// A poisoned manager is destructively retired, never restored for ordinary use.
pub(super) fn lock_state(manager: &UdpSessionManagerInner) -> MutexGuard<'_, SessionState> {
    match manager.state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            state.shutting_down = true;
            state.cleanup_failed = true;
            for (slot, entry) in std::mem::take(&mut state.entries) {
                entry.cancellation.send_replace(true);
                entry.notify.notify_waiters();
                publish_removal(
                    manager,
                    UdpSessionHandle {
                        slot,
                        generation: entry.generation,
                    },
                );
            }
            state
        }
    }
}

pub(super) fn retire_exact(
    manager: &UdpSessionManagerInner,
    state: &mut SessionState,
    handle: UdpSessionHandle,
) {
    if entry_matches(state, handle)
        && let Some(removed) = remove_entry(state, handle.slot)
    {
        publish_removal(manager, removed);
    }
}

pub(super) fn release_pending(
    manager: &UdpSessionManagerInner,
    state: &mut SessionState,
    handle: UdpSessionHandle,
    direction: UdpDirection,
) {
    // Rollback still owns its exact entry after capability fencing.
    if let Some(entry) = state
        .entries
        .get_mut(&handle.slot)
        .filter(|entry| entry.generation == handle.generation)
    {
        let pending = &mut entry.pending[direction.index()];
        if let Some(remaining) = pending.checked_sub(1) {
            *pending = remaining;
        } else {
            state.cleanup_failed = true;
            retire_exact(manager, state, handle);
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn unexpected_manager_poison_closes_admission_and_pending_drop_only_retires() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let pending = manager
            .reserve_session(Instant::now())
            .expect("pending session");
        let datagram = pending
            .reserve_datagram(UdpDirection::ToTarget, 7)
            .expect("pending datagram");
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _guard = manager.inner.state.lock().expect("healthy lock");
                panic!("closed internal fault");
            }))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| drop((datagram, pending)))).is_ok());
        assert!(manager.cleanup_failed());
        assert!(matches!(
            manager.reserve_session(Instant::now()),
            Err(UdpRuntimeError::Cancelled)
        ));
        assert_eq!(manager.session_count(), 0);
        assert_eq!(registry.snapshot(), baseline);
    }
}
