use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};

use ferrum2_rule::{RuleEngineRegistry, RuleSetId};
use tokio::time::Instant;

use crate::download::RuleSetDownloader;
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::loader::{RuleSetLoadDisposition, RuleSetLoader};
use crate::snapshot::{MaterializedRuleSets, RuleSetEntry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetRefreshOutcome {
    Updated {
        previous_generation: u64,
        generation: u64,
    },
    NotModified,
    RetainedCache(RuleSetLoadDisposition),
    Failed(RuleSetLoadErrorKind),
}

/// Source-free status from the refresh owner and its current compiled registry.
pub struct RuleSetRefreshSnapshot {
    pub index: usize,
    pub name: String,
    pub generation: u64,
    pub initial: RuleSetLoadDisposition,
    pub initial_failure: Option<RuleSetLoadErrorKind>,
    pub last_refresh: Option<RuleSetRefreshOutcome>,
}

/// Identity-free observer seam for refresh telemetry.
pub trait RuleSetRefreshObserver: Send + Sync {
    fn record(&self, outcome: RuleSetRefreshOutcome);
}

impl<F> RuleSetRefreshObserver for F
where
    F: Fn(RuleSetRefreshOutcome) + Send + Sync,
{
    fn record(&self, outcome: RuleSetRefreshOutcome) {
        self(outcome);
    }
}

#[derive(Debug)]
struct NoopRuleSetRefreshObserver;

impl RuleSetRefreshObserver for NoopRuleSetRefreshObserver {
    fn record(&self, _outcome: RuleSetRefreshOutcome) {}
}

/// Single-owner refresh loop. Successful resources are compiled before a full
/// compatible snapshot is published; every failure leaves the current Arc
/// untouched.
pub struct RuleSetRefreshService<D> {
    loader: Arc<RuleSetLoader<D>>,
    registry: Arc<RuleEngineRegistry>,
    entries: Box<[RuleSetEntry]>,
    observer: Arc<dyn RuleSetRefreshObserver>,
    initial: Box<[(RuleSetLoadDisposition, Option<RuleSetLoadErrorKind>)]>,
    outcomes: Mutex<Box<[Option<RuleSetRefreshOutcome>]>>,
}

impl<D> RuleSetRefreshService<D>
where
    D: RuleSetDownloader + 'static,
{
    fn from_materialized(
        loader: Arc<RuleSetLoader<D>>,
        materialized: MaterializedRuleSets,
    ) -> Result<Self, RuleSetLoadError> {
        let initial = materialized
            .dispositions()
            .iter()
            .copied()
            .zip(materialized.degraded_failures().iter().copied())
            .collect();
        let outcomes = Mutex::new(vec![None; materialized.rule_set_ids().len()].into_boxed_slice());
        let registry = materialized.registry;
        let entries = materialized.entries;
        if !refresh_identities_match(&registry, &entries, &materialized.rule_set_ids) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile));
        }
        Ok(Self {
            loader,
            registry,
            entries,
            observer: Arc::new(NoopRuleSetRefreshObserver),
            initial,
            outcomes,
        })
    }

    pub fn with_observer(mut self, observer: Arc<dyn RuleSetRefreshObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Joins cache/compiler work even when its refresh future was cancelled.
    pub async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.loader.shutdown().await
    }

    /// Refreshes through the shared loader and records each completed attempt once.
    pub async fn refresh_once(&self, index: usize) -> RuleSetRefreshOutcome {
        let outcome = match self.entries.get(index) {
            Some(entry) => {
                self.loader
                    .refresh(&entry.source, Arc::clone(&self.registry), entry.rule_set)
                    .await
            }
            None => RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile),
        };
        if let Some(slot) = self
            .outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(index)
        {
            *slot = Some(outcome);
        }
        self.observer.record(outcome);
        outcome
    }

    /// Captures declaration-order identities without exposing source URLs or paths.
    pub fn snapshot(&self) -> Vec<RuleSetRefreshSnapshot> {
        let outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.registry.snapshot();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let descriptor = snapshot.rule_set(entry.rule_set)?;
                Some(RuleSetRefreshSnapshot {
                    index,
                    name: descriptor.tag().to_owned(),
                    generation: snapshot.generation(),
                    initial: self.initial[index].0,
                    initial_failure: self.initial[index].1,
                    last_refresh: outcomes[index],
                })
            })
            .collect()
    }

    /// Runs until process quiescing. Dropping an in-flight download future
    /// signals cancellation; the loader retains body/worker cleanup until its
    /// retryable shutdown joins it. Completed refreshes publish complete snapshots.
    pub async fn run_until<F>(&self, stop: F) -> Result<(), RuleSetLoadError>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(stop);
        let mut due = Vec::new();
        due.try_reserve_exact(self.entries.len())
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
        let now = Instant::now();
        for entry in &self.entries {
            due.push(refresh_deadline(now, entry.source.update_interval)?);
        }

        loop {
            let Some(next_due) = due.iter().flatten().copied().min() else {
                stop.await;
                return Ok(());
            };
            tokio::select! {
                () = &mut stop => return Ok(()),
                () = tokio::time::sleep_until(next_due) => {}
            }
            let now = Instant::now();
            for (index, deadline) in due.iter_mut().enumerate() {
                if deadline.is_some_and(|deadline| deadline <= now) {
                    // Refresh failures are degraded resource state, not a
                    // process-root failure. The old registry remains live.
                    let refresh = self.refresh_once(index);
                    tokio::pin!(refresh);
                    tokio::select! {
                        () = &mut stop => return Ok(()),
                        _ = &mut refresh => {},
                    }
                    *deadline = refresh_deadline(
                        Instant::now(),
                        self.entries[index].source.update_interval,
                    )?;
                }
            }
        }
    }
}

fn refresh_deadline(
    now: Instant,
    interval: Option<std::time::Duration>,
) -> Result<Option<Instant>, RuleSetLoadError> {
    interval
        .map(|interval| {
            now.checked_add(interval)
                .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::InvalidSource))
        })
        .transpose()
}

fn refresh_identities_match(
    registry: &RuleEngineRegistry,
    entries: &[RuleSetEntry],
    declared: &[RuleSetId],
) -> bool {
    if entries.len() != declared.len() {
        return false;
    }
    let snapshot = registry.snapshot();
    entries.iter().zip(declared).all(|(entry, declared)| {
        entry.rule_set == *declared
            && snapshot
                .rule_set(entry.rule_set)
                .is_some_and(|descriptor| descriptor.tag() == entry.source.cache_name.as_str())
    })
}

impl MaterializedRuleSets {
    /// Consumes the initial materialization and activates refresh over the exact
    /// source/identity pairs bound while its registry was built.
    pub fn into_refresh_service<D>(
        self,
        loader: Arc<RuleSetLoader<D>>,
    ) -> Result<RuleSetRefreshService<D>, RuleSetLoadError>
    where
        D: RuleSetDownloader + 'static,
    {
        RuleSetRefreshService::from_materialized(loader, self)
    }
}

impl<D> fmt::Debug for RuleSetRefreshService<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetRefreshService")
            .field("entries", &self.entries.len())
            .field("generation", &self.registry.generation())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod identity_tests {
    use ferrum2_rule::{MatchSetBuilder, RuleEngineRegistry, RuleEngineSnapshotBuilder};

    use super::refresh_identities_match;
    use crate::snapshot::RuleSetEntry;
    use crate::{
        RuleSetCacheName, RuleSetDownloadMode, RuleSetDownloadResolver, RuleSetRemoteSource,
    };

    #[test]
    fn refresh_scheduling_is_checked_on_every_platform() {
        use ferrum2_rule::{MAX_RULE_SET_REFRESH_INTERVAL, MIN_RULE_SET_REFRESH_INTERVAL};
        use std::time::Duration;
        let now = tokio::time::Instant::now();
        for interval in [MIN_RULE_SET_REFRESH_INTERVAL, MAX_RULE_SET_REFRESH_INTERVAL] {
            assert_eq!(
                super::refresh_deadline(now, Some(interval)).unwrap(),
                now.checked_add(interval)
            );
        }
        // Huge instants are representable on Windows but not necessarily Unix.
        // The contract is checked arithmetic, not a platform-specific overflow.
        let huge = Duration::from_secs(i64::MAX as u64);
        match now.checked_add(huge) {
            Some(expected) => assert_eq!(
                super::refresh_deadline(now, Some(huge)).unwrap(),
                Some(expected)
            ),
            None => assert!(super::refresh_deadline(now, Some(huge)).is_err()),
        }
    }

    #[test]
    fn refresh_rejects_a_source_bound_to_another_registry_tag() {
        let mut match_set = MatchSetBuilder::new();
        match_set.add_exact_domain("rules.example").unwrap();
        let mut snapshot = RuleEngineSnapshotBuilder::new(1);
        let matcher = snapshot.add_match_set(match_set.build().unwrap()).unwrap();
        let rule_set = snapshot.add_rule_set("declared", matcher).unwrap();
        let registry = RuleEngineRegistry::new(snapshot.build().unwrap());
        let source = RuleSetRemoteSource::new(
            RuleSetCacheName::new("different").unwrap(),
            "https://rules.example/rules.srs",
            RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
            None,
            None,
        )
        .unwrap();
        let entries = [RuleSetEntry { source, rule_set }];
        assert!(!refresh_identities_match(&registry, &entries, &[rule_set],));
    }
}
