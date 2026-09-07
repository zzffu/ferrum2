use std::fmt;
use std::sync::Arc;

use ferrum2_rule::{CompiledMatchSet, MatchSetCapabilities, RuleEngineRegistry, RuleSetId};

use crate::cache_work::{Operation, OperationOutput, RuleSetCacheWork};
use crate::download::RuleSetDownloader;
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::refresh::RuleSetRefreshOutcome;
use crate::snapshot::MaterializedRuleSets;
use crate::source::{RuleSetLoaderConfig, RuleSetRemoteSource};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetLoadDisposition {
    Downloaded,
    NotModified,
    OfflineCache,
    StaleCache,
}

/// One complete, publishable resource. A value is produced only after the
/// binary has been fully downloaded, decoded, and compiled.
#[derive(Clone)]
pub struct LoadedRuleSet {
    pub(crate) match_set: Arc<CompiledMatchSet>,
    pub(crate) capabilities: MatchSetCapabilities,
    pub(crate) srs_version: u8,
    pub(crate) generation: u64,
    pub(crate) disposition: RuleSetLoadDisposition,
    pub(crate) degraded_failure: Option<RuleSetLoadErrorKind>,
}

impl LoadedRuleSet {
    pub fn match_set(&self) -> &Arc<CompiledMatchSet> {
        &self.match_set
    }

    pub const fn capabilities(&self) -> MatchSetCapabilities {
        self.capabilities
    }

    pub const fn srs_version(&self) -> u8 {
        self.srs_version
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn disposition(&self) -> RuleSetLoadDisposition {
        self.disposition
    }

    pub const fn degraded_failure(&self) -> Option<RuleSetLoadErrorKind> {
        self.degraded_failure
    }
}

impl fmt::Debug for LoadedRuleSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedRuleSet")
            .field("capabilities", &self.capabilities)
            .field("srs_version", &self.srs_version)
            .field("generation", &self.generation)
            .field("disposition", &self.disposition)
            .field("degraded_failure", &self.degraded_failure)
            .finish_non_exhaustive()
    }
}

/// Remote loader with an injected network path and a loader-exclusive cache
/// directory. Up to two registered operations retain real-work permits; file
/// transactions serialize. Call shutdown to confirm all work and lock release.
pub struct RuleSetLoader<D> {
    config: RuleSetLoaderConfig,
    downloader: Arc<D>,
    work: RuleSetCacheWork,
}

impl<D: RuleSetDownloader + 'static> RuleSetLoader<D> {
    pub fn new(config: RuleSetLoaderConfig, downloader: D) -> Self {
        let work = RuleSetCacheWork::new(&config);
        Self {
            config,
            downloader: Arc::new(downloader),
            work,
        }
    }

    /// Cancels admission/downloads, joins every accepted operation and child,
    /// then releases the cache lock. Cancelling shutdown preserves owned joins
    /// for retry; pending OS calls cannot be forcibly interrupted.
    pub async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.work.shutdown().await
    }

    pub async fn load(
        &self,
        source: &RuleSetRemoteSource,
        next_generation: u64,
    ) -> Result<LoadedRuleSet, RuleSetLoadError> {
        match self
            .work
            .execute(
                Operation::Load {
                    source: source.clone(),
                    generation: next_generation,
                },
                Arc::clone(&self.downloader),
                self.config.clone(),
            )
            .await?
        {
            OperationOutput::Loaded(value) => Ok(value),
            OperationOutput::Materialized(_) | OperationOutput::Refreshed(_) => {
                Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task))
            }
        }
    }

    pub(crate) async fn materialize(
        &self,
        sources: Vec<RuleSetRemoteSource>,
        generation: u64,
    ) -> Result<MaterializedRuleSets, RuleSetLoadError> {
        crate::cache_work::admit_sources(&sources)?;
        match self
            .work
            .execute(
                Operation::Materialize {
                    sources,
                    generation,
                },
                Arc::clone(&self.downloader),
                self.config.clone(),
            )
            .await?
        {
            OperationOutput::Materialized(value) => Ok(value),
            OperationOutput::Loaded(_) | OperationOutput::Refreshed(_) => {
                Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task))
            }
        }
    }

    pub(crate) async fn refresh(
        &self,
        source: &RuleSetRemoteSource,
        registry: Arc<RuleEngineRegistry>,
        rule_set: RuleSetId,
    ) -> RuleSetRefreshOutcome {
        match self
            .work
            .execute(
                Operation::Refresh {
                    source: source.clone(),
                    registry,
                    rule_set,
                },
                Arc::clone(&self.downloader),
                self.config.clone(),
            )
            .await
        {
            Ok(OperationOutput::Refreshed(value)) => value,
            Ok(OperationOutput::Loaded(_) | OperationOutput::Materialized(_)) => {
                RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::Task)
            }
            Err(error) => RuleSetRefreshOutcome::Failed(error.kind()),
        }
    }
}
