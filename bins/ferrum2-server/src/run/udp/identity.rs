#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ferrum2_runtime::{UdpSessionHandle, UdpSessionManager};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpServer};

use crate::run::routing::ServerTerminalRoute;

pub(super) const UDP_MAPPING_SHARD_COUNT: usize = 16;
const _: () = assert!(UDP_MAPPING_SHARD_COUNT.is_power_of_two());

#[derive(Default)]
struct CapabilityMappingShard {
    by_capability: HashMap<ServerResponseCapability, BoundUdpSession>,
    orphaned: HashMap<ServerResponseCapability, FrozenUdpIdentity>,
}

#[derive(Default)]
struct HandleMappingShard {
    by_handle: BTreeMap<UdpSessionHandle, ServerResponseCapability>,
    retired: BTreeMap<UdpSessionHandle, u64>,
    publications: BTreeMap<UdpSessionHandle, Arc<HandlePublication>>,
    publishing: BTreeMap<UdpSessionHandle, u64>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct UdpMappingState {
    pub(super) by_capability: HashMap<ServerResponseCapability, BoundUdpSession>,
    pub(super) by_handle: BTreeMap<UdpSessionHandle, ServerResponseCapability>,
    pub(super) orphaned: HashMap<ServerResponseCapability, FrozenUdpIdentity>,
    pub(super) retired: BTreeSet<UdpSessionHandle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrozenUdpIdentity {
    pub(super) inbound: usize,
    pub(super) terminal: ServerTerminalRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BoundUdpSession {
    pub(super) handle: UdpSessionHandle,
    pub(super) inbound: usize,
    pub(super) terminal: ServerTerminalRoute,
    publication: u64,
}

pub(in crate::run) struct UdpMappings {
    capability_shards: [Mutex<CapabilityMappingShard>; UDP_MAPPING_SHARD_COUNT],
    handle_shards: [Mutex<HandleMappingShard>; UDP_MAPPING_SHARD_COUNT],
    publication_owners: AtomicUsize,
    active_handles: AtomicUsize,
    retired_handles: AtomicUsize,
    trimming_retired: AtomicBool,
    next_retirement: AtomicU64,
    next_publication: AtomicU64,
    #[cfg(test)]
    publish_phase_one_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    pub(super) limit: usize,
}

struct HandlePublication {
    signal: tokio::sync::watch::Sender<bool>,
    waiters: AtomicUsize,
}

struct HandlePublicationWaiter<'a> {
    mappings: &'a UdpMappings,
    handle: UdpSessionHandle,
    publication: Arc<HandlePublication>,
}

impl Drop for HandlePublicationWaiter<'_> {
    fn drop(&mut self) {
        if self.publication.waiters.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let mut shard = self.mappings.lock_handle_shard(self.handle);
        if shard
            .publications
            .get(&self.handle)
            .is_some_and(|current| Arc::ptr_eq(current, &self.publication))
            && self.publication.waiters.load(Ordering::Acquire) == 0
        {
            shard.publications.remove(&self.handle);
            self.mappings.release_publication_owner();
        }
    }
}

impl UdpMappings {
    pub(in crate::run) fn new(limit: usize) -> Self {
        Self {
            capability_shards: std::array::from_fn(|_| {
                Mutex::new(CapabilityMappingShard::default())
            }),
            handle_shards: std::array::from_fn(|_| Mutex::new(HandleMappingShard::default())),
            publication_owners: AtomicUsize::new(0),
            active_handles: AtomicUsize::new(0),
            retired_handles: AtomicUsize::new(0),
            trimming_retired: AtomicBool::new(false),
            next_retirement: AtomicU64::new(1),
            next_publication: AtomicU64::new(1),
            #[cfg(test)]
            publish_phase_one_barrier: Mutex::new(None),
            limit,
        }
    }

    pub(super) fn handle(&self, capability: ServerResponseCapability) -> Option<BoundUdpSession> {
        self.lock_capability_shard(capability)
            .by_capability
            .get(&capability)
            .copied()
    }

    pub(super) fn identity(
        &self,
        capability: ServerResponseCapability,
    ) -> Option<FrozenUdpIdentity> {
        let shard = self.lock_capability_shard(capability);
        shard
            .by_capability
            .get(&capability)
            .map(|binding| FrozenUdpIdentity {
                inbound: binding.inbound,
                terminal: binding.terminal,
            })
            .or_else(|| shard.orphaned.get(&capability).copied())
    }

    pub(super) async fn capability(
        &self,
        handle: UdpSessionHandle,
    ) -> Option<ServerResponseCapability> {
        loop {
            let (publication, mut receiver) = {
                let mut shard = self.lock_handle_shard(handle);
                if let Some(capability) = shard.by_handle.get(&handle).copied() {
                    return Some(capability);
                }
                if shard.retired.contains_key(&handle) {
                    return None;
                }
                let publication = match shard.publications.get(&handle) {
                    Some(publication) => Arc::clone(publication),
                    None => {
                        if !self.try_acquire_publication_owner() {
                            return None;
                        }
                        let (signal, _) = tokio::sync::watch::channel(false);
                        let publication = Arc::new(HandlePublication {
                            signal,
                            waiters: AtomicUsize::new(0),
                        });
                        shard.publications.insert(handle, Arc::clone(&publication));
                        publication
                    }
                };
                publication.waiters.fetch_add(1, Ordering::Relaxed);
                let receiver = publication.signal.subscribe();
                (publication, receiver)
            };
            let waiter = HandlePublicationWaiter {
                mappings: self,
                handle,
                publication,
            };
            if !*receiver.borrow_and_update() {
                let _ = receiver.changed().await;
            }
            drop(waiter);
        }
    }

    pub(super) fn publish(
        &self,
        capability: ServerResponseCapability,
        handle: UdpSessionHandle,
        inbound: usize,
        terminal: ServerTerminalRoute,
    ) -> Option<ServerResponseCapability> {
        let publication = match self.begin_publication(handle) {
            Some(publication) => publication,
            None => return Some(capability),
        };

        // Phase one publishes the frozen capability identity. No handle shard is
        // held while this capability shard is locked.
        let old_binding = {
            let mut shard = self.lock_capability_shard(capability);
            shard.orphaned.remove(&capability);
            shard.by_capability.insert(
                capability,
                BoundUdpSession {
                    handle,
                    inbound,
                    terminal,
                    publication,
                },
            )
        };

        #[cfg(test)]
        self.wait_after_publish_phase_one();

        // Phase two retires a replaced reverse handle, if any. Compare the
        // capability before removing so a concurrently rebound handle survives.
        if let Some(old) = old_binding.filter(|old| old.handle != handle) {
            self.remove_reverse_if_matches(old.handle, capability, true);
        }

        // Phase three publishes the exact reverse handle and wakes only its
        // publication waiters. This is the response-visible publication point.
        let phase_three = {
            let mut shard = self.lock_handle_shard(handle);
            if shard.publishing.get(&handle).copied() != Some(publication)
                || shard.retired.contains_key(&handle)
            {
                if shard.publishing.get(&handle).copied() == Some(publication) {
                    shard.publishing.remove(&handle);
                }
                None
            } else {
                shard.publishing.remove(&handle);
                let old_capability = shard.by_handle.insert(handle, capability);
                if old_capability.is_none() {
                    self.active_handles.fetch_add(1, Ordering::AcqRel);
                }
                let waiter = self.take_publication(&mut shard, handle);
                Some((old_capability, waiter))
            }
        };
        let Some((old_capability, waiter)) = phase_three else {
            self.rollback_publication(capability, handle, publication);
            return Some(capability);
        };
        signal_handle_publications(waiter);

        // A process-local handle must name one capability. If a caller replaces
        // that reverse edge, freeze the displaced capability as an orphan only
        // after the handle shard is released.
        if let Some(old_capability) = old_capability.filter(|old| *old != capability) {
            self.orphan_capability_if_bound(old_capability, handle);
        }

        let mut evicted = None;
        while self.active_handles.load(Ordering::Acquire) > self.limit {
            let Some(capability) = self.evict_oldest_handle_except(handle) else {
                break;
            };
            evicted.get_or_insert(capability);
        }
        evicted
    }

    pub(super) fn publish_rejected(&self, capability: ServerResponseCapability, inbound: usize) {
        self.lock_capability_shard(capability).orphaned.insert(
            capability,
            FrozenUdpIdentity {
                inbound,
                terminal: ServerTerminalRoute::Reject,
            },
        );
    }

    pub(super) fn invalidate_handle(&self, handle: UdpSessionHandle) {
        // Retire the response-visible handle first. The capability phase below
        // validates the exact handle before turning its frozen identity orphaned.
        let (capability, publication) = {
            let mut shard = self.lock_handle_shard(handle);
            let capability = shard.by_handle.remove(&handle);
            if capability.is_some() {
                self.release_active_handle();
            }
            shard.publishing.remove(&handle);
            self.retire_mapping_handle(&mut shard, handle);
            let publication = self.take_publication(&mut shard, handle);
            (capability, publication)
        };
        self.trim_retired_handles();
        signal_handle_publications(publication);
        if let Some(capability) = capability {
            self.orphan_capability_if_bound(capability, handle);
        }
    }

    #[cfg(any(windows, test))]
    pub(super) fn reset_runtime(&self) -> usize {
        let mut publications = Vec::new();
        let mut removed_handles = 0;
        for shard in &self.handle_shards {
            {
                let mut shard = shard.lock().expect("UDP mapping shard lock poisoned");
                let handles = std::mem::take(&mut shard.by_handle);
                removed_handles += handles.len();
                for (handle, _) in handles {
                    self.retire_mapping_handle(&mut shard, handle);
                }
                let publishing = std::mem::take(&mut shard.publishing);
                for handle in publishing.keys().copied() {
                    self.retire_mapping_handle(&mut shard, handle);
                }
                let pending = std::mem::take(&mut shard.publications);
                for handle in pending.keys().copied() {
                    self.retire_mapping_handle(&mut shard, handle);
                }
                self.release_publication_owners(pending.len());
                publications.extend(pending.into_values());
            }
            self.trim_retired_handles();
        }
        self.release_active_handles(removed_handles);

        let mut removed = 0;
        for shard in &self.capability_shards {
            let mut shard = shard.lock().expect("UDP mapping shard lock poisoned");
            let active = std::mem::take(&mut shard.by_capability);
            removed += active.len();
            for (capability, binding) in active {
                shard.orphaned.insert(
                    capability,
                    FrozenUdpIdentity {
                        inbound: binding.inbound,
                        terminal: binding.terminal,
                    },
                );
            }
        }
        signal_handle_publications(publications);
        removed
    }

    pub(super) fn reconcile_runtime(&self, sessions: &UdpSessionManager) {
        for shard in &self.handle_shards {
            let candidates: Vec<_> = shard
                .lock()
                .expect("UDP mapping shard lock poisoned")
                .by_handle
                .keys()
                .copied()
                .collect();
            let mut live = candidates.clone();
            sessions.retain_live_sessions(&mut live);
            for handle in candidates {
                if live.binary_search(&handle).is_err() {
                    self.invalidate_handle(handle);
                }
            }
        }
    }

    pub(super) fn prune_protocol(
        &self,
        protocol: &UdpServer,
        now: ferrum2_crypto::MonotonicInstant,
    ) {
        for shard in &self.capability_shards {
            let candidates: Vec<_> = shard
                .lock()
                .expect("UDP mapping shard lock poisoned")
                .orphaned
                .keys()
                .copied()
                .collect();
            let removed = candidates
                .into_iter()
                .filter(|capability| protocol.remove_session(*capability, now).unwrap_or(false));
            for capability in removed {
                self.lock_capability_shard(capability)
                    .orphaned
                    .remove(&capability);
            }
        }
    }

    fn orphan_capability_if_bound(
        &self,
        capability: ServerResponseCapability,
        handle: UdpSessionHandle,
    ) {
        let mut shard = self.lock_capability_shard(capability);
        let Some(binding) = shard
            .by_capability
            .get(&capability)
            .copied()
            .filter(|binding| binding.handle == handle)
        else {
            return;
        };
        shard.by_capability.remove(&capability);
        shard.orphaned.insert(
            capability,
            FrozenUdpIdentity {
                inbound: binding.inbound,
                terminal: binding.terminal,
            },
        );
    }

    fn remove_reverse_if_matches(
        &self,
        handle: UdpSessionHandle,
        capability: ServerResponseCapability,
        retire: bool,
    ) -> bool {
        let publication = {
            let mut shard = self.lock_handle_shard(handle);
            if shard.by_handle.get(&handle).copied() != Some(capability) {
                return false;
            }
            shard.by_handle.remove(&handle);
            self.release_active_handle();
            if retire {
                shard.publishing.remove(&handle);
                self.retire_mapping_handle(&mut shard, handle);
            }
            self.take_publication(&mut shard, handle)
        };
        if retire {
            self.trim_retired_handles();
        }
        signal_handle_publications(publication);
        true
    }

    fn evict_oldest_handle_except(
        &self,
        excluded: UdpSessionHandle,
    ) -> Option<ServerResponseCapability> {
        loop {
            let mut oldest = None;
            for shard in &self.handle_shards {
                let shard = shard.lock().expect("UDP mapping shard lock poisoned");
                let candidate = shard
                    .by_handle
                    .iter()
                    .find(|(handle, _)| **handle != excluded)
                    .map(|(handle, capability)| (*handle, *capability));
                if candidate.is_some_and(|candidate| {
                    oldest.is_none_or(|current: (UdpSessionHandle, _)| candidate.0 < current.0)
                }) {
                    oldest = candidate;
                }
            }
            let (handle, capability) = oldest?;
            if self.remove_reverse_if_matches(handle, capability, true) {
                self.orphan_capability_if_bound(capability, handle);
                return Some(capability);
            }
        }
    }

    fn begin_publication(&self, handle: UdpSessionHandle) -> Option<u64> {
        let publication = self
            .next_publication
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?;
        let waiter = {
            let mut shard = self.lock_handle_shard(handle);
            if shard.retired.contains_key(&handle) {
                self.take_publication(&mut shard, handle)
            } else {
                shard.publishing.insert(handle, publication);
                return Some(publication);
            }
        };
        signal_handle_publications(waiter);
        None
    }

    fn rollback_publication(
        &self,
        capability: ServerResponseCapability,
        handle: UdpSessionHandle,
        publication: u64,
    ) {
        let mut shard = self.lock_capability_shard(capability);
        let Some(binding) = shard
            .by_capability
            .get(&capability)
            .copied()
            .filter(|binding| binding.handle == handle && binding.publication == publication)
        else {
            return;
        };
        shard.by_capability.remove(&capability);
        shard.orphaned.insert(
            capability,
            FrozenUdpIdentity {
                inbound: binding.inbound,
                terminal: binding.terminal,
            },
        );
    }

    fn retire_mapping_handle(&self, shard: &mut HandleMappingShard, handle: UdpSessionHandle) {
        let retirement = self.next_retirement.fetch_add(1, Ordering::AcqRel);
        if shard.retired.insert(handle, retirement).is_none() {
            self.retired_handles.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn trim_retired_handles(&self) {
        loop {
            if self.retired_handles.load(Ordering::Acquire) <= self.limit {
                return;
            }
            if self
                .trimming_retired
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                std::hint::spin_loop();
                std::thread::yield_now();
                continue;
            }
            while self.retired_handles.load(Ordering::Acquire) > self.limit {
                if !self.remove_oldest_retired_handle() {
                    break;
                }
            }
            self.trimming_retired.store(false, Ordering::Release);
        }
    }

    fn remove_oldest_retired_handle(&self) -> bool {
        loop {
            let oldest = self
                .handle_shards
                .iter()
                .filter_map(|shard| {
                    shard
                        .lock()
                        .expect("UDP mapping shard lock poisoned")
                        .retired
                        .iter()
                        .map(|(handle, retirement)| (*retirement, *handle))
                        .min()
                })
                .min();
            let Some((retirement, oldest)) = oldest else {
                return false;
            };
            let mut shard = self.lock_handle_shard(oldest);
            if shard.retired.get(&oldest).copied() == Some(retirement) {
                shard.retired.remove(&oldest);
                let previous = self.retired_handles.fetch_sub(1, Ordering::AcqRel);
                debug_assert!(previous > 0);
                return true;
            }
        }
    }

    fn try_acquire_publication_owner(&self) -> bool {
        self.publication_owners
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.limit).then_some(current + 1)
            })
            .is_ok()
    }

    fn take_publication(
        &self,
        shard: &mut HandleMappingShard,
        handle: UdpSessionHandle,
    ) -> Option<Arc<HandlePublication>> {
        let publication = shard.publications.remove(&handle);
        if publication.is_some() {
            self.release_publication_owner();
        }
        publication
    }

    fn release_publication_owner(&self) {
        self.release_publication_owners(1);
    }

    fn release_publication_owners(&self, count: usize) {
        if count == 0 {
            return;
        }
        let previous = self.publication_owners.fetch_sub(count, Ordering::AcqRel);
        debug_assert!(previous >= count);
    }

    fn release_active_handle(&self) {
        self.release_active_handles(1);
    }

    fn release_active_handles(&self, count: usize) {
        if count == 0 {
            return;
        }
        let previous = self.active_handles.fetch_sub(count, Ordering::AcqRel);
        debug_assert!(previous >= count);
    }

    fn lock_capability_shard(
        &self,
        capability: ServerResponseCapability,
    ) -> std::sync::MutexGuard<'_, CapabilityMappingShard> {
        self.capability_shards[shard_index(&capability)]
            .lock()
            .expect("UDP mapping shard lock poisoned")
    }

    fn lock_handle_shard(
        &self,
        handle: UdpSessionHandle,
    ) -> std::sync::MutexGuard<'_, HandleMappingShard> {
        self.handle_shards[shard_index(&handle)]
            .lock()
            .expect("UDP mapping shard lock poisoned")
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> UdpMappingState {
        let mut snapshot = UdpMappingState::default();
        for shard in &self.capability_shards {
            let shard = shard.lock().expect("UDP mapping shard lock poisoned");
            snapshot.by_capability.extend(
                shard
                    .by_capability
                    .iter()
                    .map(|(key, value)| (*key, *value)),
            );
            snapshot
                .orphaned
                .extend(shard.orphaned.iter().map(|(key, value)| (*key, *value)));
        }
        for shard in &self.handle_shards {
            let shard = shard.lock().expect("UDP mapping shard lock poisoned");
            snapshot
                .by_handle
                .extend(shard.by_handle.iter().map(|(key, value)| (*key, *value)));
            snapshot.retired.extend(shard.retired.keys().copied());
        }
        snapshot
    }

    #[cfg(test)]
    pub(super) fn publication_signal(
        &self,
        handle: UdpSessionHandle,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.lock_handle_shard(handle)
            .publications
            .get(&handle)
            .map(|publication| publication.signal.subscribe())
    }

    #[cfg(test)]
    pub(super) fn publication_owner_count(&self) -> usize {
        self.publication_owners.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn retired_handle_count(&self) -> usize {
        self.retired_handles.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn set_publish_phase_one_barrier(&self, barrier: Option<Arc<std::sync::Barrier>>) {
        *self
            .publish_phase_one_barrier
            .lock()
            .expect("UDP publish test barrier lock poisoned") = barrier;
    }

    #[cfg(test)]
    fn wait_after_publish_phase_one(&self) {
        let barrier = self
            .publish_phase_one_barrier
            .lock()
            .expect("UDP publish test barrier lock poisoned")
            .clone();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
    }

    #[cfg(test)]
    pub(super) fn capability_shard_index(capability: ServerResponseCapability) -> usize {
        shard_index(&capability)
    }

    #[cfg(test)]
    pub(super) fn handle_shard_index(handle: UdpSessionHandle) -> usize {
        shard_index(&handle)
    }

    #[cfg(test)]
    pub(super) fn with_capability_shard_locked<R>(
        &self,
        capability: ServerResponseCapability,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _shard = self.lock_capability_shard(capability);
        operation()
    }

    #[cfg(test)]
    pub(super) fn with_handle_shard_locked<R>(
        &self,
        handle: UdpSessionHandle,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _shard = self.lock_handle_shard(handle);
        operation()
    }
}

fn shard_index(value: &impl Hash) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as usize & (UDP_MAPPING_SHARD_COUNT - 1)
}

fn signal_handle_publications(publications: impl IntoIterator<Item = Arc<HandlePublication>>) {
    for publication in publications {
        publication.signal.send_replace(true);
    }
}

#[cfg(any(windows, test))]
pub(in crate::run) struct ServerUdpNetworkReset {
    pub(super) accepted_generation: std::sync::atomic::AtomicU64,
    pub(super) sessions: UdpSessionManager,
    pub(super) mappings: Arc<UdpMappings>,
    pub(super) admission: Arc<tokio::sync::Mutex<()>>,
}

#[cfg(any(windows, test))]
impl ServerUdpNetworkReset {
    pub(in crate::run) fn new(
        initial_generation: u64,
        sessions: UdpSessionManager,
        mappings: Arc<UdpMappings>,
        admission: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            accepted_generation: std::sync::atomic::AtomicU64::new(initial_generation),
            sessions,
            mappings,
            admission,
        }
    }
}

#[cfg(any(windows, test))]
impl ferrum2_runtime::ResetNetwork for ServerUdpNetworkReset {
    fn reset_network(
        &self,
        snapshot: Arc<ferrum2_net::NetworkSnapshot>,
    ) -> ferrum2_runtime::NetworkResetFuture<'_> {
        Box::pin(async move {
            let generation = snapshot.generation();
            // New mappings are published only from the slow path, which holds
            // this same gate. That serializes its two shard phases with reset;
            // established fast-path traffic only reads existing mappings.
            let _admission = self.admission.lock().await;
            let current = self
                .accepted_generation
                .load(std::sync::atomic::Ordering::Acquire);
            if generation < current {
                return Err(ferrum2_runtime::NetworkResetError);
            }
            if generation == current {
                return Ok(());
            }
            self.sessions.reset_all();
            self.mappings.reset_runtime();
            self.accepted_generation
                .store(generation, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    }
}
