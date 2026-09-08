mod download;
mod session;

use std::sync::Arc;

use ferrum2_rule::{RuleEngineRegistry, RuleSetId};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::cache::{CacheDirectory, WorkStop};
use crate::download::RuleSetDownloader;
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::loader::{LoadedRuleSet, RuleSetLoadDisposition};
use crate::refresh::RuleSetRefreshOutcome;
use crate::snapshot::{MaterializedRuleSets, build_materialized};
use crate::source::{RuleSetCacheName, RuleSetLoaderConfig, RuleSetRemoteSource};

use session::{RefreshBuild, SessionInput};

const MAX_OPERATIONS: usize = 2;

pub(crate) enum Operation {
    Load {
        source: RuleSetRemoteSource,
        generation: u64,
    },
    Materialize {
        sources: Vec<RuleSetRemoteSource>,
        generation: u64,
    },
    Refresh {
        source: RuleSetRemoteSource,
        registry: Arc<RuleEngineRegistry>,
        rule_set: RuleSetId,
    },
}

pub(crate) enum OperationOutput {
    Loaded(LoadedRuleSet),
    Materialized(MaterializedRuleSets),
    Refreshed(RuleSetRefreshOutcome),
}

/// Admission belongs to retained records, not result waiters or child tasks.
/// Records hold permits until the operation join is consumed. Overlapping keys
/// and refreshes serialize; unrelated downloads may occupy both slots.
pub(crate) struct RuleSetCacheWork {
    state: Mutex<WorkState>,
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    directory: Arc<CacheDirectory>,
    snapshot_limits: ferrum2_rule::RuleEngineSnapshotLimits,
}

struct WorkState {
    accepting: bool,
    failure: Option<RuleSetLoadErrorKind>,
    tasks: Vec<OperationRecord>,
    release: Option<tokio::task::JoinHandle<Result<(), RuleSetLoadError>>>,
    released: bool,
}

struct OperationRecord {
    task: tokio::task::JoinHandle<Option<RuleSetLoadErrorKind>>,
    _permit: OwnedSemaphorePermit,
    keys: Vec<RuleSetCacheName>,
    refresh: bool,
    gate: Arc<Mutex<()>>,
}

struct CancelWaiter(CancellationToken);
impl Drop for CancelWaiter {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl RuleSetCacheWork {
    pub(crate) fn new(config: &RuleSetLoaderConfig) -> Self {
        Self {
            state: Mutex::new(WorkState {
                accepting: true,
                failure: None,
                tasks: Vec::with_capacity(MAX_OPERATIONS),
                release: None,
                released: false,
            }),
            slots: Arc::new(Semaphore::new(MAX_OPERATIONS)),
            cancel: CancellationToken::new(),
            directory: Arc::new(CacheDirectory::new(config.cache_dir.clone())),
            snapshot_limits: ferrum2_rule::RuleEngineSnapshotLimits::DEFAULT,
        }
    }

    pub(crate) async fn execute<D: RuleSetDownloader + 'static>(
        &self,
        operation: Operation,
        downloader: Arc<D>,
        config: RuleSetLoaderConfig,
    ) -> Result<OperationOutput, RuleSetLoadError> {
        let keys = operation.keys()?;
        let refresh = matches!(&operation, Operation::Refresh { .. });
        let cancel = self.cancel.child_token();
        let _waiter = CancelWaiter(cancel.clone());
        let (result, receiver) = tokio::sync::oneshot::channel();
        {
            let mut state = self.state.lock().await;
            let mut cursor = 0;
            while cursor < state.tasks.len() {
                if state.tasks[cursor].task.is_finished() {
                    let completed = (&mut state.tasks[cursor].task).await;
                    record_completion(&mut state, completed);
                    state.tasks.swap_remove(cursor);
                } else {
                    cursor += 1;
                }
            }
            if state.tasks.len() == MAX_OPERATIONS {
                // Borrow the retained join. Cancelling this admission future
                // leaves both the handle and its permit in the owner.
                let completed = (&mut state.tasks[0].task).await;
                record_completion(&mut state, completed);
                state.tasks.swap_remove(0);
            }
            if !state.accepting || self.cancel.is_cancelled() {
                return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled));
            }
            let permit = Arc::clone(&self.slots)
                .try_acquire_owned()
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled))?;
            let gate = state
                .tasks
                .iter()
                .find(|record| {
                    (refresh && record.refresh) || keys.iter().any(|key| record.keys.contains(key))
                })
                .map_or_else(
                    || Arc::new(Mutex::new(())),
                    |record| Arc::clone(&record.gate),
                );
            let task_gate = Arc::clone(&gate);
            let directory = Arc::clone(&self.directory);
            let snapshot_limits = self.snapshot_limits;
            let task = tokio::spawn(async move {
                let gate = tokio::select! {
                    () = cancel.cancelled() => None,
                    gate = task_gate.lock_owned() => Some(gate),
                };
                let (output, failure) = if let Some(_gate) = gate {
                    run_operation(
                        operation,
                        downloader,
                        config,
                        directory,
                        cancel,
                        snapshot_limits,
                    )
                    .await
                } else {
                    (
                        Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
                        None,
                    )
                };
                let _ = result.send(output);
                failure
            });
            state.tasks.push(OperationRecord {
                task,
                _permit: permit,
                keys,
                refresh,
                gate,
            });
        }
        receiver
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))?
    }

    pub(crate) async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.cancel.cancel();
        self.slots.close();
        let mut state = self.state.lock().await;
        state.accepting = false;
        while let Some(task) = state.tasks.last_mut() {
            let completed = (&mut task.task).await;
            state.tasks.pop();
            record_completion(&mut state, completed);
        }
        if !state.released {
            if state.release.is_none() {
                let directory = Arc::clone(&self.directory);
                state.release = Some(tokio::task::spawn_blocking(move || directory.release()));
            }
            let completed = state.release.as_mut().expect("owned release task").await;
            state.release = None;
            state.released = true;
            if !matches!(completed, Ok(Ok(()))) {
                state
                    .failure
                    .get_or_insert(RuleSetLoadErrorKind::CacheCleanup);
            }
        }
        state
            .failure
            .map_or(Ok(()), |kind| Err(RuleSetLoadError::new(kind)))
    }
}

impl Drop for RuleSetCacheWork {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.slots.close();
        // Drop signals stop only. It does not claim an uninterruptible worker
        // joined; workers retain their directory lease until actual completion.
    }
}

fn record_completion(
    state: &mut WorkState,
    completed: Result<Option<RuleSetLoadErrorKind>, tokio::task::JoinError>,
) {
    match completed {
        Ok(Some(failure)) => {
            state.failure.get_or_insert(failure);
        }
        Ok(None) => {}
        Err(_) => {
            state.failure.get_or_insert(RuleSetLoadErrorKind::Task);
        }
    }
}

impl Operation {
    fn keys(&self) -> Result<Vec<RuleSetCacheName>, RuleSetLoadError> {
        match self {
            Self::Load { source, .. } | Self::Refresh { source, .. } => {
                Ok(vec![source.cache_name.clone()])
            }
            Self::Materialize { sources, .. } => {
                admit_sources(sources)?;
                Ok(sources
                    .iter()
                    .map(|source| source.cache_name.clone())
                    .collect())
            }
        }
    }
}

/// Admission precedes derived identities, downloads and snapshot allocation.
pub(crate) fn admit_sources(sources: &[RuleSetRemoteSource]) -> Result<(), RuleSetLoadError> {
    if sources.len() > 64 {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheLimit));
    }
    for (index, source) in sources.iter().enumerate() {
        if sources[..index]
            .iter()
            .any(|earlier| earlier.cache_name == source.cache_name)
        {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile));
        }
    }
    Ok(())
}

async fn run_operation<D: RuleSetDownloader + 'static>(
    operation: Operation,
    downloader: Arc<D>,
    config: RuleSetLoaderConfig,
    directory: Arc<CacheDirectory>,
    cancel: CancellationToken,
    snapshot_limits: ferrum2_rule::RuleEngineSnapshotLimits,
) -> (
    Result<OperationOutput, RuleSetLoadError>,
    Option<RuleSetLoadErrorKind>,
) {
    let stop = WorkStop {
        cancel: cancel.clone(),
        deadline: None,
    };
    let (result, cleanup_failed) = match operation {
        Operation::Load { source, generation } => {
            let loaded = download::load(
                SessionInput {
                    directory,
                    source,
                    generation,
                    expected_capabilities: None,
                    refresh: None,
                    stop,
                },
                downloader,
                config,
            )
            .await;
            (
                loaded
                    .result
                    .map(|download| OperationOutput::Loaded(download.loaded)),
                loaded.cleanup_failed,
            )
        }
        Operation::Refresh {
            source,
            registry,
            rule_set,
        } => {
            let current = registry.snapshot();
            let Some(descriptor) = current.rule_set(rule_set) else {
                return (
                    Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile)),
                    None,
                );
            };
            let expected_capabilities = Some(descriptor.capabilities());
            let Some(generation) = current.generation().checked_add(1) else {
                return (
                    Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile)),
                    None,
                );
            };
            let loaded = download::load(
                SessionInput {
                    directory,
                    source,
                    generation,
                    expected_capabilities,
                    refresh: Some(RefreshBuild { current, rule_set }),
                    stop,
                },
                downloader,
                config,
            )
            .await;
            let result = loaded.result.and_then(|download| {
                if cancel.is_cancelled() {
                    return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled));
                }
                let outcome = if let Some(next) = download.successor {
                    let previous = registry.publish(next).map_err(|_| {
                        RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryPublish)
                    })?;
                    RuleSetRefreshOutcome::Updated {
                        previous_generation: previous.generation(),
                        generation,
                    }
                } else {
                    match download.loaded.disposition {
                        RuleSetLoadDisposition::Downloaded
                        | RuleSetLoadDisposition::NotModified => RuleSetRefreshOutcome::NotModified,
                        disposition => RuleSetRefreshOutcome::RetainedCache(disposition),
                    }
                };
                Ok(OperationOutput::Refreshed(outcome))
            });
            (result, loaded.cleanup_failed)
        }
        Operation::Materialize {
            sources,
            generation,
        } => {
            let mut values = Vec::new();
            let mut usage = ferrum2_rule::MatchSetResourceUsage::default();
            if values.try_reserve_exact(sources.len()).is_err() {
                return (
                    Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation)),
                    None,
                );
            }
            for source in &sources {
                let loaded = download::load(
                    SessionInput {
                        directory: Arc::clone(&directory),
                        source: source.clone(),
                        generation,
                        expected_capabilities: None,
                        refresh: None,
                        stop: stop.clone(),
                    },
                    Arc::clone(&downloader),
                    config.clone(),
                )
                .await;
                match loaded.result {
                    Ok(value) => {
                        usage = match snapshot_limits
                            .admit(usage, value.loaded.match_set.resource_usage())
                        {
                            Ok(usage) => usage,
                            Err(error) => {
                                return (Err(crate::error::rule_compile_load_error(error)), None);
                            }
                        };
                        values.push(value.loaded);
                    }
                    Err(error) => {
                        return (
                            Err(error),
                            if loaded.cleanup_failed {
                                Some(RuleSetLoadErrorKind::CacheCleanup)
                            } else if error.kind() == RuleSetLoadErrorKind::Task {
                                Some(RuleSetLoadErrorKind::Task)
                            } else {
                                None
                            },
                        );
                    }
                }
            }
            let built = tokio::task::spawn_blocking(move || {
                let _directory = directory;
                stop.check()?;
                let built = build_materialized(sources, values, generation, snapshot_limits);
                stop.check()?;
                built
            })
            .await;
            match built {
                Ok(result) => (result.map(OperationOutput::Materialized), false),
                Err(_) => (Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task)), true),
            }
        }
    };
    let failure = if cleanup_failed {
        Some(RuleSetLoadErrorKind::CacheCleanup)
    } else if result
        .as_ref()
        .is_err_and(|error| error.kind() == RuleSetLoadErrorKind::Task)
    {
        Some(RuleSetLoadErrorKind::Task)
    } else {
        None
    };
    (result, failure)
}

#[cfg(test)]
mod tests;
