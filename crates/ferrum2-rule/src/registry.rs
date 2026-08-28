use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use ferrum2_core::{CanonicalDomain, GenerationChange, GenerationSignal};

use crate::candidate::{MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories};
use crate::{CompiledMatchSet, MatchSetCapabilities, RuleCompileError};

/// Stable array index for one compiled match set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MatchSetId(u32);

impl MatchSetId {
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    fn from_index(index: usize) -> Result<Self, RuleCompileError> {
        u32::try_from(index)
            .map(Self)
            .map_err(|_| RuleCompileError::IndexOverflow)
    }

    fn index(self) -> usize {
        self.0 as usize
    }
}

/// Stable array index for one configured RuleSet descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleSetId(u32);

impl RuleSetId {
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    fn from_index(index: usize) -> Result<Self, RuleCompileError> {
        u32::try_from(index)
            .map(Self)
            .map_err(|_| RuleCompileError::IndexOverflow)
    }

    fn index(self) -> usize {
        self.0 as usize
    }
}

/// Immutable metadata for one RuleSet slot.
#[derive(Clone)]
pub struct RuleSetDescriptor {
    tag: Box<str>,
    match_set: MatchSetId,
    capabilities: MatchSetCapabilities,
}

impl RuleSetDescriptor {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub const fn match_set(&self) -> MatchSetId {
        self.match_set
    }

    pub const fn capabilities(&self) -> MatchSetCapabilities {
        self.capabilities
    }
}

impl fmt::Debug for RuleSetDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleSetDescriptor([redacted])")
    }
}

/// Complete immutable matcher view captured by one evaluation.
pub struct RuleEngineSnapshot {
    match_sets: Arc<[Arc<CompiledMatchSet>]>,
    rule_sets: Arc<[RuleSetDescriptor]>,
    ip_rule_sets: Box<[RuleSetId]>,
    candidates: MatchCandidateIndex,
    generation: u64,
}

impl RuleEngineSnapshot {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn match_set(&self, id: MatchSetId) -> Option<&CompiledMatchSet> {
        self.match_sets.get(id.index()).map(Arc::as_ref)
    }

    pub fn shared_match_set(&self, id: MatchSetId) -> Option<&Arc<CompiledMatchSet>> {
        self.match_sets.get(id.index())
    }

    pub fn rule_set(&self, id: RuleSetId) -> Option<&RuleSetDescriptor> {
        self.rule_sets.get(id.index())
    }

    pub fn rule_set_id(&self, tag: &str) -> Option<RuleSetId> {
        self.rule_sets
            .iter()
            .position(|descriptor| descriptor.tag.as_ref() == tag)
            .and_then(|index| RuleSetId::from_index(index).ok())
    }

    pub fn match_set_count(&self) -> usize {
        self.match_sets.len()
    }

    pub fn rule_set_count(&self) -> usize {
        self.rule_sets.len()
    }

    pub fn builder_for_generation(
        &self,
        generation: u64,
    ) -> Result<RuleEngineSnapshotBuilder, RuleCompileError> {
        if generation <= self.generation {
            return Err(RuleCompileError::InvalidGeneration);
        }
        let mut match_sets = Vec::new();
        match_sets
            .try_reserve_exact(self.match_sets.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        match_sets.extend(self.match_sets.iter().cloned());

        let mut rule_sets = Vec::new();
        rule_sets
            .try_reserve_exact(self.rule_sets.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for descriptor in self.rule_sets.iter() {
            rule_sets.push(RuleSetDraft {
                tag: descriptor.tag.clone(),
                match_set: descriptor.match_set,
            });
        }
        Ok(RuleEngineSnapshotBuilder {
            match_sets,
            rule_sets,
            generation,
        })
    }

    pub fn builder_for_next_generation(
        &self,
    ) -> Result<RuleEngineSnapshotBuilder, RuleCompileError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(RuleCompileError::InvalidGeneration)?;
        self.builder_for_generation(generation)
    }

    pub(crate) fn matches_rule_set(
        &self,
        id: RuleSetId,
        domain: Option<&CanonicalDomain>,
        address: Option<IpAddr>,
    ) -> bool {
        self.rule_set(id)
            .and_then(|descriptor| self.match_set(descriptor.match_set))
            .is_some_and(|match_set| match_set.matches(domain, address))
    }

    /// Visits RuleSet IDs whose current-generation contents match the input.
    pub fn visit_matching_rule_sets(
        &self,
        domain: Option<&CanonicalDomain>,
        address: Option<IpAddr>,
        mut visit: impl FnMut(RuleSetId),
    ) {
        self.candidates.visit_matches(domain, address, |candidate| {
            visit(RuleSetId::from_raw(candidate));
        });
    }

    /// Visits RuleSet IDs whose current-generation contents contain IP CIDRs.
    pub fn visit_ip_rule_sets(&self, mut visit: impl FnMut(RuleSetId)) {
        for rule_set in self.ip_rule_sets.iter().copied() {
            visit(rule_set);
        }
    }

    fn is_compatible_successor(&self, next: &Self) -> bool {
        next.match_sets.len() >= self.match_sets.len()
            && next.rule_sets.len() >= self.rule_sets.len()
            && self
                .rule_sets
                .iter()
                .zip(next.rule_sets.iter())
                .all(|(current, next)| {
                    current.tag == next.tag && current.match_set == next.match_set
                })
    }
}

impl fmt::Debug for RuleEngineSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleEngineSnapshot([redacted])")
    }
}

struct RuleSetDraft {
    tag: Box<str>,
    match_set: MatchSetId,
}

/// Fallible construction and refresh builder for immutable snapshots.
pub struct RuleEngineSnapshotBuilder {
    match_sets: Vec<Arc<CompiledMatchSet>>,
    rule_sets: Vec<RuleSetDraft>,
    generation: u64,
}

impl fmt::Debug for RuleEngineSnapshotBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleEngineSnapshotBuilder([redacted])")
    }
}

impl RuleEngineSnapshotBuilder {
    pub const fn new(generation: u64) -> Self {
        Self {
            match_sets: Vec::new(),
            rule_sets: Vec::new(),
            generation,
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn add_match_set(
        &mut self,
        match_set: CompiledMatchSet,
    ) -> Result<MatchSetId, RuleCompileError> {
        self.add_shared_match_set(Arc::new(match_set))
    }

    pub fn add_shared_match_set(
        &mut self,
        match_set: Arc<CompiledMatchSet>,
    ) -> Result<MatchSetId, RuleCompileError> {
        if match_set.is_empty() {
            return Err(RuleCompileError::EmptyField);
        }
        let id = MatchSetId::from_index(self.match_sets.len())?;
        self.match_sets
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.match_sets.push(match_set);
        Ok(id)
    }

    pub fn replace_match_set(
        &mut self,
        id: MatchSetId,
        match_set: CompiledMatchSet,
    ) -> Result<(), RuleCompileError> {
        self.replace_shared_match_set(id, Arc::new(match_set))
    }

    pub fn replace_shared_match_set(
        &mut self,
        id: MatchSetId,
        match_set: Arc<CompiledMatchSet>,
    ) -> Result<(), RuleCompileError> {
        if match_set.is_empty() {
            return Err(RuleCompileError::EmptyField);
        }
        let slot = self
            .match_sets
            .get_mut(id.index())
            .ok_or(RuleCompileError::InvalidId)?;
        *slot = match_set;
        Ok(())
    }

    pub fn replace_rule_set(
        &mut self,
        id: RuleSetId,
        match_set: CompiledMatchSet,
    ) -> Result<(), RuleCompileError> {
        self.replace_shared_rule_set(id, Arc::new(match_set))
    }

    pub fn replace_shared_rule_set(
        &mut self,
        id: RuleSetId,
        match_set: Arc<CompiledMatchSet>,
    ) -> Result<(), RuleCompileError> {
        let match_set_id = self
            .rule_sets
            .get(id.index())
            .map(|descriptor| descriptor.match_set)
            .ok_or(RuleCompileError::InvalidId)?;
        self.replace_shared_match_set(match_set_id, match_set)
    }

    pub fn add_rule_set(
        &mut self,
        tag: &str,
        match_set: MatchSetId,
    ) -> Result<RuleSetId, RuleCompileError> {
        if !valid_tag(tag) {
            return Err(RuleCompileError::InvalidTag);
        }
        if self
            .rule_sets
            .iter()
            .any(|descriptor| descriptor.tag.as_ref() == tag)
        {
            return Err(RuleCompileError::DuplicateRuleSet);
        }
        if self.match_sets.get(match_set.index()).is_none() {
            return Err(RuleCompileError::InvalidId);
        }
        let id = RuleSetId::from_index(self.rule_sets.len())?;
        self.rule_sets
            .try_reserve(1)
            .map_err(|_| RuleCompileError::Allocation)?;
        self.rule_sets.push(RuleSetDraft {
            tag: tag.into(),
            match_set,
        });
        Ok(id)
    }

    pub fn build(self) -> Result<RuleEngineSnapshot, RuleCompileError> {
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(self.rule_sets.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for draft in self.rule_sets {
            let capabilities = self
                .match_sets
                .get(draft.match_set.index())
                .ok_or(RuleCompileError::InvalidId)?
                .capabilities();
            descriptors.push(RuleSetDescriptor {
                tag: draft.tag,
                match_set: draft.match_set,
                capabilities,
            });
        }
        let mut candidates = MatchCandidateIndexBuilder::new();
        let mut ip_rule_sets = Vec::new();
        ip_rule_sets
            .try_reserve_exact(descriptors.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for (index, descriptor) in descriptors.iter().enumerate() {
            let match_set = self
                .match_sets
                .get(descriptor.match_set.index())
                .ok_or(RuleCompileError::InvalidId)?;
            candidates.try_add_match_set(index, match_set, MatchCategories::ALL)?;
            if descriptor.capabilities.ip_cidr {
                ip_rule_sets.push(RuleSetId::from_index(index)?);
            }
        }
        Ok(RuleEngineSnapshot {
            match_sets: self.match_sets.into(),
            rule_sets: descriptors.into(),
            ip_rule_sets: ip_rule_sets.into_boxed_slice(),
            candidates: candidates.build()?,
            generation: self.generation,
        })
    }
}

fn valid_tag(tag: &str) -> bool {
    (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Closed publication failures that never expose tags or rule contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryPublishError {
    StaleGeneration,
    IncompatibleLayout,
}

impl fmt::Display for RegistryPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StaleGeneration => "rule snapshot generation is stale",
            Self::IncompatibleLayout => "rule snapshot ID layout changed",
        })
    }
}

impl Error for RegistryPublishError {}

fn validate_successor(
    current: &RuleEngineSnapshot,
    next: &RuleEngineSnapshot,
) -> Result<(), RegistryPublishError> {
    if next.generation <= current.generation {
        return Err(RegistryPublishError::StaleGeneration);
    }
    if !current.is_compatible_successor(next) {
        return Err(RegistryPublishError::IncompatibleLayout);
    }
    Ok(())
}

#[cfg(not(feature = "candidate-atomic-snapshot"))]
mod snapshot_store {
    use std::sync::{Arc, RwLock};

    use ferrum2_core::{GenerationChange, GenerationSignal};

    use super::{RegistryPublishError, RuleEngineSnapshot, validate_successor};

    pub(super) struct SnapshotStore {
        current: RwLock<Arc<RuleEngineSnapshot>>,
    }

    impl SnapshotStore {
        pub(super) fn new(initial: RuleEngineSnapshot) -> Self {
            Self {
                current: RwLock::new(Arc::new(initial)),
            }
        }

        pub(super) fn load(&self) -> Arc<RuleEngineSnapshot> {
            Arc::clone(
                &self
                    .current
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        }

        pub(super) fn watch_generation(&self, changes: &GenerationSignal) -> GenerationChange {
            let current = self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let change = changes.watch_from(current.generation());
            drop(current);
            change
        }

        pub(super) fn watch_generation_from(
            &self,
            generation: u64,
            changes: &GenerationSignal,
        ) -> GenerationChange {
            let current = self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let change = changes.watch_from(generation);
            drop(current);
            change
        }

        pub(super) fn publish(
            &self,
            next: RuleEngineSnapshot,
            changes: &GenerationSignal,
        ) -> Result<Arc<RuleEngineSnapshot>, RegistryPublishError> {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            validate_successor(&current, &next)?;
            let generation = next.generation();
            let previous = std::mem::replace(&mut *current, Arc::new(next));
            let notification = changes.prepare_notification(generation);
            drop(current);
            notification.wake();
            Ok(previous)
        }
    }
}

#[cfg(feature = "candidate-atomic-snapshot")]
mod snapshot_store {
    use std::sync::{Arc, Mutex};

    use arc_swap::ArcSwap;
    use ferrum2_core::{GenerationChange, GenerationSignal};

    use super::{RegistryPublishError, RuleEngineSnapshot, validate_successor};

    pub(super) struct SnapshotStore {
        current: ArcSwap<RuleEngineSnapshot>,
        publication: Mutex<()>,
    }

    impl SnapshotStore {
        pub(super) fn new(initial: RuleEngineSnapshot) -> Self {
            let current = ArcSwap::from_pointee(initial);
            // Prime the per-thread ArcSwap loading strategy before evaluations.
            drop(current.load_full());
            Self {
                current,
                publication: Mutex::new(()),
            }
        }

        pub(super) fn load(&self) -> Arc<RuleEngineSnapshot> {
            self.current.load_full()
        }

        pub(super) fn watch_generation(&self, changes: &GenerationSignal) -> GenerationChange {
            let publication = self
                .publication
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let change = changes.watch_from(self.current.load().generation());
            drop(publication);
            change
        }

        pub(super) fn watch_generation_from(
            &self,
            generation: u64,
            changes: &GenerationSignal,
        ) -> GenerationChange {
            let publication = self
                .publication
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let change = changes.watch_from(generation);
            drop(publication);
            change
        }

        pub(super) fn publish(
            &self,
            next: RuleEngineSnapshot,
            changes: &GenerationSignal,
        ) -> Result<Arc<RuleEngineSnapshot>, RegistryPublishError> {
            self.publish_with_hook(next, changes, || {})
        }

        fn publish_with_hook(
            &self,
            next: RuleEngineSnapshot,
            changes: &GenerationSignal,
            after_swap: impl FnOnce(),
        ) -> Result<Arc<RuleEngineSnapshot>, RegistryPublishError> {
            let publication = self
                .publication
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let current = self.current.load_full();
            validate_successor(&current, &next)?;
            let generation = next.generation();
            let previous = self.current.swap(Arc::new(next));
            after_swap();
            let notification = changes.prepare_notification(generation);
            drop(publication);
            notification.wake();
            Ok(previous)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::{Arc, mpsc};
        use std::task::{Context, Poll, Waker};
        use std::thread;
        use std::time::Duration;

        use ferrum2_core::GenerationChange;

        use super::*;
        use crate::RuleEngineSnapshotBuilder;

        fn poll_change(change: &mut GenerationChange) -> Poll<u64> {
            Future::poll(Pin::new(change), &mut Context::from_waker(Waker::noop()))
        }

        #[test]
        fn subscriptions_cannot_enter_between_snapshot_swap_and_signal_update() {
            let initial = RuleEngineSnapshotBuilder::new(1).build().unwrap();
            let next = initial.builder_for_generation(2).unwrap().build().unwrap();
            let store = Arc::new(SnapshotStore::new(initial));
            let changes = GenerationSignal::new(1);
            let (started_tx, started_rx) = mpsc::sync_channel(2);
            let (current_tx, current_rx) = mpsc::sync_channel(1);
            let (selected_tx, selected_rx) = mpsc::sync_channel(1);

            store
                .publish_with_hook(next, &changes, || {
                    let current_store = Arc::clone(&store);
                    let current_changes = changes.clone();
                    let started = started_tx.clone();
                    thread::spawn(move || {
                        started.send(()).unwrap();
                        current_tx
                            .send(current_store.watch_generation(&current_changes))
                            .unwrap();
                    });

                    let selected_store = Arc::clone(&store);
                    let selected_changes = changes.clone();
                    thread::spawn(move || {
                        started_tx.send(()).unwrap();
                        selected_tx
                            .send(selected_store.watch_generation_from(1, &selected_changes))
                            .unwrap();
                    });

                    started_rx.recv().unwrap();
                    started_rx.recv().unwrap();
                    thread::yield_now();
                    assert!(matches!(
                        current_rx.try_recv(),
                        Err(mpsc::TryRecvError::Empty)
                    ));
                    assert!(matches!(
                        selected_rx.try_recv(),
                        Err(mpsc::TryRecvError::Empty)
                    ));
                })
                .unwrap();

            let mut current = current_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            let mut selected = selected_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(current.baseline(), 2);
            assert_eq!(poll_change(&mut current), Poll::Pending);
            assert_eq!(selected.baseline(), 1);
            assert_eq!(poll_change(&mut selected), Poll::Ready(2));

            let next = store
                .load()
                .builder_for_generation(3)
                .unwrap()
                .build()
                .unwrap();
            store.publish(next, &changes).unwrap();
            assert_eq!(poll_change(&mut current), Poll::Ready(3));
        }
    }
}

use snapshot_store::SnapshotStore;

/// Lock-safe atomic publication point for complete immutable snapshots.
pub struct RuleEngineRegistry {
    current: SnapshotStore,
    changes: GenerationSignal,
}

impl RuleEngineRegistry {
    pub fn new(initial: RuleEngineSnapshot) -> Self {
        let generation = initial.generation();
        Self {
            current: SnapshotStore::new(initial),
            changes: GenerationSignal::new(generation),
        }
    }

    /// Captures exactly one complete generation.
    pub fn snapshot(&self) -> Arc<RuleEngineSnapshot> {
        self.current.load()
    }

    pub fn generation(&self) -> u64 {
        self.snapshot().generation()
    }

    /// Subscribes to the next successfully published snapshot generation.
    ///
    /// The returned runtime-neutral future is independent from every other
    /// subscriber and completes with the newly published generation.
    pub fn watch_generation(&self) -> GenerationChange {
        self.current.watch_generation(&self.changes)
    }

    /// Subscribes from a generation captured by an earlier route evaluation.
    ///
    /// If a successful publication has already replaced that generation, the
    /// returned future is immediately ready. This closes the interval between
    /// route selection and subscription construction.
    pub fn watch_generation_from(&self, generation: u64) -> GenerationChange {
        self.current
            .watch_generation_from(generation, &self.changes)
    }

    /// Publishes a complete compatible successor or leaves the old snapshot untouched.
    pub fn publish(
        &self,
        next: RuleEngineSnapshot,
    ) -> Result<Arc<RuleEngineSnapshot>, RegistryPublishError> {
        self.current.publish(next, &self.changes)
    }
}

impl fmt::Debug for RuleEngineRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleEngineRegistry([redacted])")
    }
}
