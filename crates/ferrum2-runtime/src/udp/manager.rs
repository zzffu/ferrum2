use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{Notify, Semaphore, broadcast, watch};
use tokio::time::Instant;

use crate::OwnerRegistry;
use crate::owner::OwnerGuard;

use super::reservation::{AccountedDatagram, UdpBufferBudget};
use super::session::{DatagramQueue, PendingUdpDatagram, PendingUdpSession, reserve_datagram};
use super::{
    UDP_EXPIRY_REBUILD_MIN_NODES, UDP_EXPIRY_STALE_FACTOR, UDP_SESSION_QUEUE_DEPTH,
    UDP_SESSION_SHARD_COUNT, UdpDirection, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle,
};

pub(super) struct SessionEntry {
    pub(super) generation: u64,
    pub(super) last_activity: Instant,
    pub(super) expiry_version: u64,
    pub(super) committed: bool,
    pub(super) pending: [usize; 2],
    pub(super) queues: [DatagramQueue; 2],
    pub(super) notify: Arc<Notify>,
    pub(super) cancellation: watch::Sender<bool>,
    pub(super) _guard: OwnerGuard,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ExpiryEntry {
    deadline: Instant,
    slot: u32,
    generation: u64,
    version: u64,
}

pub(super) struct SessionShard {
    entries: Vec<Option<SessionEntry>>,
    free_local_slots: Vec<usize>,
    expiry: BinaryHeap<Reverse<ExpiryEntry>>,
    committed_entries: usize,
}

impl SessionShard {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            free_local_slots: Vec::new(),
            expiry: BinaryHeap::new(),
            committed_entries: 0,
        }
    }
}

struct RemovedSession {
    handle: UdpSessionHandle,
    entry: SessionEntry,
}

pub(super) struct UdpSessionManagerInner {
    pub(super) limits: UdpRuntimeLimits,
    pub(super) budget: UdpBufferBudget,
    pub(super) owner_slots: Arc<Semaphore>,
    pub(super) runtime_owners: AtomicUsize,
    pub(super) running_runtimes: AtomicUsize,
    pub(super) shutting_down: AtomicBool,
    session_count: AtomicUsize,
    next_generation: AtomicU64,
    next_shard: AtomicUsize,
    admission: Mutex<()>,
    pub(super) shards: Box<[Mutex<SessionShard>]>,
    pub(super) removal_events: broadcast::Sender<UdpSessionHandle>,
    pub(super) registry: OwnerRegistry,
}

/// Protocol-neutral owner of generation, capacity, queues, and byte reservations.
///
/// Lock order is `admission` followed by session shards in ascending index order.
/// Single-session operations never take `admission` and lock exactly the shard
/// selected by the low bits of the opaque slot.
#[derive(Clone)]
pub struct UdpSessionManager {
    pub(super) inner: Arc<UdpSessionManagerInner>,
}

impl UdpSessionManager {
    /// Creates an empty manager with lazily grown per-shard slabs.
    pub fn new(limits: UdpRuntimeLimits, registry: OwnerRegistry) -> Self {
        let budget = UdpBufferBudget::new(limits.max_buffered_bytes(), registry.clone());
        let (removal_events, _) = broadcast::channel(limits.max_sessions());
        let shards = (0..UDP_SESSION_SHARD_COUNT)
            .map(|_| Mutex::new(SessionShard::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            inner: Arc::new(UdpSessionManagerInner {
                limits,
                budget,
                owner_slots: Arc::new(Semaphore::new(limits.max_sessions())),
                runtime_owners: AtomicUsize::new(0),
                running_runtimes: AtomicUsize::new(0),
                shutting_down: AtomicBool::new(false),
                session_count: AtomicUsize::new(0),
                next_generation: AtomicU64::new(0),
                next_shard: AtomicUsize::new(0),
                admission: Mutex::new(()),
                shards,
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
        self.inner.session_count.load(Ordering::Acquire)
    }

    /// Subscribes to exact generation removals for event-driven mapping
    /// invalidation. A lagged receiver must fall back to a batch liveness pass.
    pub fn subscribe_removals(&self) -> broadcast::Receiver<UdpSessionHandle> {
        self.inner.removal_events.subscribe()
    }

    /// Retains only committed live generations using one ordered shard snapshot.
    pub fn retain_live_sessions(&self, handles: &mut Vec<UdpSessionHandle>) {
        let shards = lock_all_shards(&self.inner);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            handles.clear();
            return;
        }
        handles.retain(|handle| {
            matching_entry(&shards[shard_index(handle.slot)], *handle)
                .is_ok_and(|entry| entry.committed)
        });
    }

    /// Reserves a new generation without committing protocol activity.
    ///
    /// At capacity, exactly the deterministic oldest committed idle-expired
    /// entry is removed. Active and provisional state is never evicted.
    pub fn reserve_session(&self, now: Instant) -> Result<PendingUdpSession, UdpRuntimeError> {
        let _admission = lock_unpoisoned(&self.inner.admission);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(UdpRuntimeError::Cancelled);
        }
        if self.session_count() == self.inner.limits.max_sessions() {
            self.evict_oldest_expired(now);
        }
        if self.session_count() == self.inner.limits.max_sessions() {
            return Err(UdpRuntimeError::SessionLimit);
        }

        let previous_generation = self
            .inner
            .next_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| UdpRuntimeError::Counter)?;
        let generation = previous_generation + 1;
        let start =
            self.inner.next_shard.fetch_add(1, Ordering::Relaxed) & (UDP_SESSION_SHARD_COUNT - 1);
        for offset in 0..UDP_SESSION_SHARD_COUNT {
            let shard_index = (start + offset) & (UDP_SESSION_SHARD_COUNT - 1);
            let capacity = shard_slot_capacity(self.inner.limits.max_sessions(), shard_index);
            if capacity == 0 {
                continue;
            }
            let mut shard = lock_unpoisoned(&self.inner.shards[shard_index]);
            let local_slot = if let Some(local_slot) = shard.free_local_slots.pop() {
                local_slot
            } else if shard.entries.len() < capacity {
                shard.entries.push(None);
                shard.entries.len() - 1
            } else {
                continue;
            };
            debug_assert!(shard.entries[local_slot].is_none());
            let slot = full_slot(shard_index, local_slot);
            let handle = UdpSessionHandle { slot, generation };
            let (cancellation, _) = watch::channel(false);
            shard.entries[local_slot] = Some(SessionEntry {
                generation,
                last_activity: now,
                expiry_version: 0,
                committed: false,
                pending: [0; 2],
                queues: std::array::from_fn(|_| DatagramQueue::new()),
                notify: Arc::new(Notify::new()),
                cancellation,
                _guard: self.inner.registry.track_udp_session(),
            });
            let previous = self.inner.session_count.fetch_add(1, Ordering::Release);
            debug_assert!(previous < self.inner.limits.max_sessions());
            return Ok(PendingUdpSession {
                manager: Arc::clone(&self.inner),
                handle,
                committed: false,
            });
        }
        Err(UdpRuntimeError::SessionLimit)
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
        let removed = {
            let mut shard = lock_session_shard(&self.inner, handle);
            let removed = take_exact_entry(&mut shard, handle);
            if removed.is_some() {
                decrement_session_count(&self.inner, 1);
            }
            removed
        };
        if let Some(removed) = removed {
            finish_removal(&self.inner, removed);
            true
        } else {
            false
        }
    }

    /// Removes every session for a network-generation transition while keeping admission open.
    pub fn reset_all(&self) -> usize {
        let _admission = lock_unpoisoned(&self.inner.admission);
        let removed = self.drain_all_shards();
        let removed_count = removed.len();
        for removed in removed {
            finish_removal(&self.inner, removed);
        }
        removed_count
    }

    /// Removes every session and wakes every owned worker.
    pub fn cancel_all(&self) {
        let _admission = lock_unpoisoned(&self.inner.admission);
        let removed = {
            let mut shards = lock_all_shards(&self.inner);
            self.inner.shutting_down.store(true, Ordering::Release);
            drain_locked_shards(&mut shards)
        };
        decrement_session_count(&self.inner, removed.len());
        for removed in removed {
            finish_removal(&self.inner, removed);
        }
    }

    /// Requests shutdown without discarding already admitted queue entries.
    pub fn signal_all(&self) {
        let _admission = lock_unpoisoned(&self.inner.admission);
        let shards = lock_all_shards(&self.inner);
        self.inner.shutting_down.store(true, Ordering::Release);
        for shard in shards.iter() {
            for entry in shard.entries.iter().flatten() {
                entry.cancellation.send_replace(true);
                entry.notify.notify_waiters();
            }
        }
    }

    /// Pops one queued datagram without changing accepted activity.
    pub fn pop(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
    ) -> Result<Option<AccountedDatagram>, UdpRuntimeError> {
        let mut shard = lock_session_shard(&self.inner, handle);
        let entry = matching_entry_mut(&mut shard, handle)?;
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
        let shard = lock_session_shard(&self.inner, handle);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(UdpRuntimeError::Cancelled);
        }
        let entry = matching_entry(&shard, handle)?;
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
        let mut shard = lock_session_shard(&self.inner, handle);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(UdpRuntimeError::Cancelled);
        }
        if !matching_entry(&shard, handle)?.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        update_session_activity(
            &mut shard,
            handle,
            now,
            self.inner.limits.idle_timeout(),
            false,
        );
        Ok(())
    }

    /// Subscribes to cancellation for one exact live generation.
    pub fn cancellation(
        &self,
        handle: UdpSessionHandle,
    ) -> Result<watch::Receiver<bool>, UdpRuntimeError> {
        let shard = lock_session_shard(&self.inner, handle);
        Ok(matching_entry(&shard, handle)?.cancellation.subscribe())
    }

    pub(super) fn notify(&self, handle: UdpSessionHandle) -> Result<Arc<Notify>, UdpRuntimeError> {
        let shard = lock_session_shard(&self.inner, handle);
        Ok(Arc::clone(&matching_entry(&shard, handle)?.notify))
    }

    /// Returns the manager-owned idle deadline for one exact live generation.
    pub fn idle_deadline(&self, handle: UdpSessionHandle) -> Result<Instant, UdpRuntimeError> {
        let shard = lock_session_shard(&self.inner, handle);
        Ok(matching_entry(&shard, handle)?.last_activity + self.inner.limits.idle_timeout())
    }

    fn evict_oldest_expired(&self, now: Instant) {
        let removed = {
            let mut shards = lock_all_shards(&self.inner);
            let (candidate, _) = oldest_expiry_candidate(&mut shards);
            let Some(candidate) = candidate.filter(|candidate| candidate.deadline <= now) else {
                return;
            };
            let shard = &mut shards[shard_index(candidate.slot)];
            let top = shard.expiry.pop().expect("selected expiry heap entry").0;
            debug_assert_eq!(top, candidate);
            let handle = UdpSessionHandle {
                slot: candidate.slot,
                generation: candidate.generation,
            };
            let removed = take_exact_entry(shard, handle);
            if removed.is_some() {
                decrement_session_count(&self.inner, 1);
            }
            removed
        };
        if let Some(removed) = removed {
            finish_removal(&self.inner, removed);
        }
    }

    fn drain_all_shards(&self) -> Vec<RemovedSession> {
        let mut shards = lock_all_shards(&self.inner);
        let removed = drain_locked_shards(&mut shards);
        decrement_session_count(&self.inner, removed.len());
        removed
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

pub(super) fn lock_session_shard<'a>(
    manager: &'a UdpSessionManagerInner,
    handle: UdpSessionHandle,
) -> MutexGuard<'a, SessionShard> {
    lock_unpoisoned(&manager.shards[shard_index(handle.slot)])
}

pub(super) fn matching_entry(
    shard: &SessionShard,
    handle: UdpSessionHandle,
) -> Result<&SessionEntry, UdpRuntimeError> {
    shard
        .entries
        .get(local_slot(handle.slot))
        .and_then(Option::as_ref)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

pub(super) fn matching_entry_mut(
    shard: &mut SessionShard,
    handle: UdpSessionHandle,
) -> Result<&mut SessionEntry, UdpRuntimeError> {
    shard
        .entries
        .get_mut(local_slot(handle.slot))
        .and_then(Option::as_mut)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

pub(super) fn update_session_activity(
    shard: &mut SessionShard,
    handle: UdpSessionHandle,
    now: Instant,
    idle_timeout: std::time::Duration,
    activate: bool,
) {
    let (version, deadline) = {
        let entry = matching_entry_mut(shard, handle).expect("validated UDP session entry");
        if activate {
            debug_assert!(!entry.committed);
            entry.committed = true;
        } else {
            debug_assert!(entry.committed);
        }
        entry.last_activity = now;
        entry.expiry_version = entry.expiry_version.wrapping_add(1);
        (entry.expiry_version, now + idle_timeout)
    };
    if activate {
        shard.committed_entries += 1;
    }
    shard.expiry.push(Reverse(ExpiryEntry {
        deadline,
        slot: handle.slot,
        generation: handle.generation,
        version,
    }));
    maybe_rebuild_expiry(shard);
}

fn lock_all_shards(manager: &UdpSessionManagerInner) -> Vec<MutexGuard<'_, SessionShard>> {
    manager.shards.iter().map(lock_unpoisoned).collect()
}

fn shard_index(slot: u32) -> usize {
    slot as usize & (UDP_SESSION_SHARD_COUNT - 1)
}

fn local_slot(slot: u32) -> usize {
    slot as usize / UDP_SESSION_SHARD_COUNT
}

fn full_slot(shard_index: usize, local_slot: usize) -> u32 {
    u32::try_from(local_slot * UDP_SESSION_SHARD_COUNT + shard_index)
        .expect("configured UDP session slot fits u32")
}

fn shard_slot_capacity(max_sessions: usize, shard_index: usize) -> usize {
    if shard_index >= max_sessions {
        0
    } else {
        (max_sessions - 1 - shard_index) / UDP_SESSION_SHARD_COUNT + 1
    }
}

fn take_exact_entry(shard: &mut SessionShard, handle: UdpSessionHandle) -> Option<RemovedSession> {
    let local_slot = local_slot(handle.slot);
    let entry = shard.entries.get(local_slot)?.as_ref()?;
    if entry.generation != handle.generation {
        return None;
    }
    let entry = shard.entries[local_slot]
        .take()
        .expect("validated UDP session entry");
    if entry.committed {
        shard.committed_entries -= 1;
    }
    shard.free_local_slots.push(local_slot);
    maybe_rebuild_expiry(shard);
    Some(RemovedSession { handle, entry })
}

fn finish_removal(manager: &UdpSessionManagerInner, removed: RemovedSession) {
    removed.entry.cancellation.send_replace(true);
    removed.entry.notify.notify_waiters();
    let handle = removed.handle;
    drop(removed.entry);
    publish_removal(manager, handle);
}

fn decrement_session_count(manager: &UdpSessionManagerInner, removed: usize) {
    if removed == 0 {
        return;
    }
    let previous = manager.session_count.fetch_sub(removed, Ordering::AcqRel);
    debug_assert!(previous >= removed, "UDP session count underflow");
}

fn drain_locked_shards(shards: &mut [MutexGuard<'_, SessionShard>]) -> Vec<RemovedSession> {
    let mut removed = Vec::new();
    for (shard_index, shard) in shards.iter_mut().enumerate() {
        for local_slot in 0..shard.entries.len() {
            if let Some(entry) = shard.entries[local_slot].take() {
                removed.push(RemovedSession {
                    handle: UdpSessionHandle {
                        slot: full_slot(shard_index, local_slot),
                        generation: entry.generation,
                    },
                    entry,
                });
            }
        }
        shard.free_local_slots = (0..shard.entries.len()).rev().collect();
        shard.expiry.clear();
        shard.committed_entries = 0;
    }
    removed.sort_unstable_by_key(|removed| removed.handle.slot);
    removed
}

fn expiry_is_current(shard: &SessionShard, expiry: ExpiryEntry) -> bool {
    shard
        .entries
        .get(local_slot(expiry.slot))
        .and_then(Option::as_ref)
        .is_some_and(|entry| {
            entry.generation == expiry.generation
                && entry.committed
                && entry.expiry_version == expiry.version
        })
}

fn prune_stale_expiry(shard: &mut SessionShard) -> usize {
    let mut popped = 0;
    loop {
        let Some(expiry) = shard.expiry.peek().map(|expiry| expiry.0) else {
            return popped;
        };
        if expiry_is_current(shard, expiry) {
            return popped;
        }
        shard.expiry.pop();
        popped += 1;
    }
}

fn oldest_expiry_candidate(
    shards: &mut [MutexGuard<'_, SessionShard>],
) -> (Option<ExpiryEntry>, usize) {
    let mut candidate: Option<ExpiryEntry> = None;
    let mut inspected = 0;
    for shard in shards.iter_mut() {
        inspected += prune_stale_expiry(shard);
        if let Some(expiry) = shard.expiry.peek().map(|expiry| expiry.0) {
            inspected += 1;
            if candidate.is_none_or(|candidate| expiry < candidate) {
                candidate = Some(expiry);
            }
        }
    }
    (candidate, inspected)
}

fn maybe_rebuild_expiry(shard: &mut SessionShard) {
    let bound = shard
        .committed_entries
        .saturating_mul(UDP_EXPIRY_STALE_FACTOR)
        .saturating_add(UDP_EXPIRY_REBUILD_MIN_NODES);
    if shard.expiry.len() > bound {
        rebuild_expiry(shard);
    }
}

fn rebuild_expiry(shard: &mut SessionShard) -> usize {
    let previous = std::mem::take(&mut shard.expiry);
    let inspected = previous.len();
    let mut expiry = BinaryHeap::with_capacity(shard.committed_entries);
    for Reverse(candidate) in previous {
        if expiry_is_current(shard, candidate) {
            expiry.push(Reverse(candidate));
        }
    }
    shard.expiry = expiry;
    inspected
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn publish_removal(manager: &UdpSessionManagerInner, handle: UdpSessionHandle) {
    let _ = manager.removal_events.send(handle);
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant as StdInstant};

    use bytes::BytesMut;
    use ferrum2_core::{Datagram, TargetAddr};

    use super::*;
    use crate::udp::{MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, UdpDirection};

    fn limits(max_sessions: usize) -> UdpRuntimeLimits {
        UdpRuntimeLimits::new(
            max_sessions,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT,
        )
        .expect("valid UDP test limits")
    }

    fn datagram(payload: &[u8]) -> Datagram {
        Datagram::new(
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("valid target"),
            BytesMut::from(payload),
            payload.len(),
        )
        .expect("bounded datagram")
    }

    fn activate_session(manager: &UdpSessionManager, now: Instant) -> UdpSessionHandle {
        let mut pending = manager.reserve_session(now).expect("session capacity");
        let handle = pending.handle();
        let mut shard = lock_session_shard(&manager.inner, handle);
        update_session_activity(
            &mut shard,
            handle,
            now,
            manager.inner.limits.idle_timeout(),
            true,
        );
        pending.committed = true;
        handle
    }

    fn commit_session(
        manager: &UdpSessionManager,
        now: Instant,
        payload: &[u8],
    ) -> UdpSessionHandle {
        let pending = manager.reserve_session(now).expect("session capacity");
        let reservation = pending
            .reserve_datagram(UdpDirection::ToTarget, payload.len())
            .expect("first datagram capacity");
        pending
            .commit(reservation, datagram(payload), now)
            .expect("session commit")
    }

    #[test]
    fn slab_churn_reuses_one_slot_and_rejects_stale_generations() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(1), registry.clone());
        let now = Instant::now();
        let first = manager.reserve_session(now).expect("first generation");
        let stale = first.handle();
        drop(first);

        for _ in 0..4_096 {
            let replacement = manager
                .reserve_session(now)
                .expect("replacement generation");
            assert_eq!(replacement.handle().slot, stale.slot);
            assert_ne!(replacement.handle().generation, stale.generation);
            assert!(matches!(
                manager.cancellation(stale),
                Err(UdpRuntimeError::Cancelled)
            ));
            drop(replacement);
        }

        let shard = lock_unpoisoned(&manager.inner.shards[0]);
        assert_eq!(shard.entries.len(), 1);
        assert_eq!(shard.free_local_slots, [0]);
        assert_eq!(manager.session_count(), 0);
        assert_eq!(registry.snapshot().udp_sessions, 0);
    }

    #[test]
    fn activity_heap_rebuilds_after_its_bounded_stale_threshold() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(1), registry);
        let start = Instant::now();
        let handle = activate_session(&manager, start);
        let refreshes = UDP_EXPIRY_REBUILD_MIN_NODES + UDP_EXPIRY_STALE_FACTOR;
        let mut latest = start;
        for step in 1..=refreshes {
            latest = start + Duration::from_millis(step as u64);
            manager
                .commit_activity(handle, latest)
                .expect("live activity");
        }

        let shard = lock_session_shard(&manager.inner, handle);
        assert_eq!(shard.expiry.len(), 1, "stale nodes were rebuilt");
        assert_eq!(
            shard.expiry.peek().expect("current deadline").0.deadline,
            latest + MIN_UDP_IDLE_TIMEOUT
        );
        drop(shard);
        assert!(manager.remove(handle));
    }

    #[test]
    fn expiry_rebuild_filters_bounded_heap_not_historical_slab_high_water() {
        const HISTORICAL_SESSIONS: usize = 4_096;

        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(HISTORICAL_SESSIONS), registry);
        let start = Instant::now();
        let handles: Vec<_> = (0..HISTORICAL_SESSIONS)
            .map(|_| activate_session(&manager, start))
            .collect();
        let retained = handles[0];
        for handle in handles.into_iter().skip(1) {
            assert!(manager.remove(handle));
        }
        for step in 1..=8 {
            manager
                .commit_activity(retained, start + Duration::from_millis(step))
                .expect("retained session activity");
        }

        let mut shard = lock_session_shard(&manager.inner, retained);
        let historical_slots = shard.entries.len();
        let heap_nodes = shard.expiry.len();
        assert!(historical_slots > heap_nodes);
        assert_eq!(rebuild_expiry(&mut shard), heap_nodes);
        assert_eq!(shard.expiry.len(), 1);
        drop(shard);
        assert!(manager.remove(retained));
    }

    #[test]
    fn oldest_expiry_selection_inspects_one_live_head_per_shard() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(64), registry);
        let now = Instant::now();
        let handles: Vec<_> = (0..64).map(|_| activate_session(&manager, now)).collect();

        let mut shards = lock_all_shards(&manager.inner);
        let (candidate, inspected) = oldest_expiry_candidate(&mut shards);
        assert_eq!(inspected, UDP_SESSION_SHARD_COUNT);
        assert_eq!(candidate.expect("oldest deadline").slot, handles[0].slot);
        drop(shards);
        assert_eq!(manager.reset_all(), handles.len());
    }

    #[test]
    fn different_session_shards_progress_independently() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(2), registry);
        let now = Instant::now();
        let first = activate_session(&manager, now);
        let second = activate_session(&manager, now);
        assert_ne!(shard_index(first.slot), shard_index(second.slot));

        let held_first_shard = lock_session_shard(&manager.inner, first);
        let (result_tx, result_rx) = mpsc::channel();
        let worker_manager = manager.clone();
        let worker = thread::spawn(move || {
            result_tx
                .send(worker_manager.commit_activity(second, now + Duration::from_secs(1)))
                .expect("test receiver remains alive");
        });
        assert_eq!(result_rx.recv_timeout(Duration::from_secs(1)), Ok(Ok(())));
        drop(held_first_shard);
        worker.join().expect("activity worker");
        assert_eq!(manager.reset_all(), 2);
    }

    #[test]
    fn queue_order_survives_sharded_commit_and_pop() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(1), registry);
        let now = Instant::now();
        let handle = commit_session(&manager, now, b"first");
        for payload in [b"second".as_slice(), b"third"] {
            manager
                .reserve_datagram(handle, UdpDirection::ToTarget, payload.len())
                .expect("queue capacity")
                .commit(datagram(payload), now)
                .expect("queue commit");
        }

        for expected in [b"first".as_slice(), b"second", b"third"] {
            let queued = manager
                .pop(handle, UdpDirection::ToTarget)
                .expect("live generation")
                .expect("queued datagram");
            assert_eq!(queued.datagram().payload(), expected);
        }
        assert!(manager.remove(handle));
    }

    #[test]
    fn shutdown_linearizes_after_an_inflight_atomic_commit() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(limits(1), registry.clone());
        let now = Instant::now();
        let pending = manager.reserve_session(now).expect("session capacity");
        let handle = pending.handle();
        let reservation = pending
            .reserve_datagram(UdpDirection::ToTarget, 1)
            .expect("first datagram capacity");
        let (commit_entered_tx, commit_entered_rx) = mpsc::channel();
        let (release_commit_tx, release_commit_rx) = mpsc::channel();
        let commit = thread::spawn(move || {
            pending.commit_with(reservation, datagram(b"x"), now, || {
                commit_entered_tx
                    .send(())
                    .expect("test receiver remains alive");
                release_commit_rx.recv().expect("commit release");
                Ok::<(), ()>(())
            })
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("commit holds its session shard");

        let (signal_started_tx, signal_started_rx) = mpsc::channel();
        let shutdown_manager = manager.clone();
        let shutdown = thread::spawn(move || {
            signal_started_tx
                .send(())
                .expect("test receiver remains alive");
            shutdown_manager.signal_all();
        });
        signal_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown worker started");
        let wait_deadline = StdInstant::now() + Duration::from_secs(1);
        loop {
            if manager.inner.admission.try_lock().is_err() {
                break;
            }
            assert!(StdInstant::now() < wait_deadline, "shutdown took admission");
            thread::yield_now();
        }
        assert!(!manager.inner.shutting_down.load(Ordering::Acquire));

        release_commit_tx.send(()).expect("commit is waiting");
        assert!(matches!(
            commit.join().expect("commit worker"),
            Ok(handle_result) if handle_result == handle
        ));
        shutdown.join().expect("shutdown worker");
        assert!(manager.inner.shutting_down.load(Ordering::Acquire));
        assert!(matches!(
            manager.reserve_session(now),
            Err(UdpRuntimeError::Cancelled)
        ));
        let queued = manager
            .pop(handle, UdpDirection::ToTarget)
            .expect("committed generation survives signaling")
            .expect("committed datagram remains queued");
        assert_eq!(queued.datagram().payload(), b"x");
        drop(queued);
        assert!(manager.remove(handle));
        assert_eq!(registry.snapshot().udp_sessions, 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }
}
