use std::fmt;
use std::sync::Arc;

use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshotBuilder, RuleSetId};

use crate::download::RuleSetDownloader;
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind, rule_compile_load_error};
use crate::loader::{RuleSetLoadDisposition, RuleSetLoader};
use crate::source::RuleSetRemoteSource;

pub(crate) struct RuleSetEntry {
    pub(crate) source: RuleSetRemoteSource,
    pub(crate) rule_set: RuleSetId,
}

/// One complete initial registry together with its refresh identities.
///
/// Source declarations and `RuleSetId`s are bound while the registry is built,
/// so callers cannot accidentally reorder them before refresh activation.
pub struct MaterializedRuleSets {
    pub(crate) registry: Arc<RuleEngineRegistry>,
    pub(crate) rule_set_ids: Arc<[RuleSetId]>,
    pub(crate) entries: Box<[RuleSetEntry]>,
    dispositions: Box<[RuleSetLoadDisposition]>,
    degraded_failures: Box<[Option<RuleSetLoadErrorKind>]>,
}

impl MaterializedRuleSets {
    /// Returns the immutable registry owner shared with configuration and refresh.
    pub fn registry(&self) -> &Arc<RuleEngineRegistry> {
        &self.registry
    }

    /// Clones the registry owner without rebuilding its snapshot.
    pub fn shared_registry(&self) -> Arc<RuleEngineRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn rule_set_ids(&self) -> &[RuleSetId] {
        &self.rule_set_ids
    }

    /// Clones the declaration-order identity owner without copying IDs.
    pub fn shared_rule_set_ids(&self) -> Arc<[RuleSetId]> {
        Arc::clone(&self.rule_set_ids)
    }

    pub fn dispositions(&self) -> &[RuleSetLoadDisposition] {
        &self.dispositions
    }

    pub fn degraded_failures(&self) -> &[Option<RuleSetLoadErrorKind>] {
        &self.degraded_failures
    }
}

impl fmt::Debug for MaterializedRuleSets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedRuleSets")
            .field("generation", &self.registry.generation())
            .field("rule_set_count", &self.rule_set_ids.len())
            .finish()
    }
}

/// Materializes all configured resources and then builds exactly one snapshot.
/// Cache writes may complete independently, but a partially built matcher view
/// can never become observable.
pub async fn materialize_rule_sets<D>(
    loader: &RuleSetLoader<D>,
    sources: Vec<RuleSetRemoteSource>,
    generation: u64,
) -> Result<MaterializedRuleSets, RuleSetLoadError>
where
    D: RuleSetDownloader,
{
    let mut loaded = Vec::new();
    loaded
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    for source in &sources {
        loaded.push(loader.load(source, generation).await?);
    }

    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    let mut rule_set_ids = Vec::new();
    let mut dispositions = Vec::new();
    let mut degraded_failures = Vec::new();
    let mut entries = Vec::new();
    rule_set_ids
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    dispositions
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    degraded_failures
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    entries
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    for (source, loaded) in sources.into_iter().zip(loaded) {
        dispositions.push(loaded.disposition);
        degraded_failures.push(loaded.degraded_failure);
        let match_set = builder
            .add_shared_match_set(loaded.match_set)
            .map_err(rule_compile_load_error)?;
        let rule_set = builder
            .add_rule_set(source.cache_name.as_str(), match_set)
            .map_err(rule_compile_load_error)?;
        rule_set_ids.push(rule_set);
        entries.push(RuleSetEntry { source, rule_set });
    }
    let snapshot = builder.build().map_err(rule_compile_load_error)?;
    Ok(MaterializedRuleSets {
        registry: Arc::new(RuleEngineRegistry::new(snapshot)),
        rule_set_ids: Arc::from(rule_set_ids.into_boxed_slice()),
        entries: entries.into_boxed_slice(),
        dispositions: dispositions.into_boxed_slice(),
        degraded_failures: degraded_failures.into_boxed_slice(),
    })
}
