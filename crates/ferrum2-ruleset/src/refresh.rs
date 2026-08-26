use std::fmt;
use std::future::Future;
use std::sync::Arc;

use ferrum2_rule::{RuleEngineRegistry, RuleSetId};
use tokio::time::Instant;

use crate::download::RuleSetDownloader;
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind, rule_compile_load_error_kind};
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
}

impl<D> RuleSetRefreshService<D>
where
    D: RuleSetDownloader,
{
    fn from_materialized(
        loader: Arc<RuleSetLoader<D>>,
        materialized: MaterializedRuleSets,
    ) -> Result<Self, RuleSetLoadError> {
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

    pub async fn refresh_once(&self, index: usize) -> RuleSetRefreshOutcome {
        let Some(entry) = self.entries.get(index) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let current = self.registry.snapshot();
        let Some(descriptor) = current.rule_set(entry.rule_set) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let expected_capabilities = descriptor.capabilities();
        let Some(generation) = current.generation().checked_add(1) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let loaded = match self
            .loader
            .load_with_capabilities(&entry.source, generation, Some(expected_capabilities))
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => return RuleSetRefreshOutcome::Failed(error.kind()),
        };
        match loaded.disposition {
            RuleSetLoadDisposition::NotModified => return RuleSetRefreshOutcome::NotModified,
            RuleSetLoadDisposition::OfflineCache | RuleSetLoadDisposition::StaleCache => {
                return RuleSetRefreshOutcome::RetainedCache(loaded.disposition);
            }
            RuleSetLoadDisposition::Downloaded => {}
        }

        let mut builder = match current.builder_for_generation(generation) {
            Ok(builder) => builder,
            Err(error) => {
                return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
            }
        };
        if let Err(error) = builder.replace_shared_rule_set(entry.rule_set, loaded.match_set) {
            return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
        }
        let next = match builder.build() {
            Ok(next) => next,
            Err(error) => {
                return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
            }
        };
        match self.registry.publish(next) {
            Ok(previous) => RuleSetRefreshOutcome::Updated {
                previous_generation: previous.generation(),
                generation,
            },
            Err(_) => RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryPublish),
        }
    }

    /// Runs until process quiescing. Dropping an in-flight download future
    /// closes its body and removes its `NamedTempFile`; all completed refreshes
    /// were already atomically published.
    pub async fn run_until<F>(&self, stop: F) -> Result<(), RuleSetLoadError>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(stop);
        let mut due = Vec::new();
        due.try_reserve_exact(self.entries.len())
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
        let now = Instant::now();
        due.extend(
            self.entries
                .iter()
                .map(|entry| entry.source.update_interval.map(|interval| now + interval)),
        );

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
                    let outcome = tokio::select! {
                        () = &mut stop => return Ok(()),
                        outcome = &mut refresh => outcome,
                    };
                    self.observer.record(outcome);
                    *deadline = self.entries[index]
                        .source
                        .update_interval
                        .map(|interval| Instant::now() + interval);
                }
            }
        }
    }
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
        D: RuleSetDownloader,
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
