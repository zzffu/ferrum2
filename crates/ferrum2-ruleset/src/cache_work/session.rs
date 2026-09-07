use std::sync::Arc;

use ferrum2_rule::{MatchSetCapabilities, RuleEngineSnapshot, RuleSetId};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::cache::{
    CacheCommit, CacheDirectory, CacheTransaction, CachedRuleSet, DownloadMetadata, WorkStop,
    read_cache_sync,
};
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind, rule_compile_load_error};
use crate::loader::{LoadedRuleSet, RuleSetLoadDisposition};
use crate::source::RuleSetRemoteSource;

pub(super) enum Command {
    Begin { deadline: Instant },
    Chunk(Vec<u8>),
    Finish(DownloadMetadata),
    Abort,
}

pub(super) struct CacheState {
    pub(super) cached: Option<CachedRuleSet>,
    pub(super) failure: Option<RuleSetLoadErrorKind>,
}

pub(super) struct RefreshBuild {
    pub(super) current: Arc<RuleEngineSnapshot>,
    pub(super) rule_set: RuleSetId,
}

pub(super) struct PreparedDownload {
    pub(super) loaded: LoadedRuleSet,
    pub(super) successor: Option<RuleEngineSnapshot>,
}

pub(super) struct SessionInput {
    pub(super) directory: Arc<CacheDirectory>,
    pub(super) source: RuleSetRemoteSource,
    pub(super) generation: u64,
    pub(super) expected_capabilities: Option<MatchSetCapabilities>,
    pub(super) refresh: Option<RefreshBuild>,
    pub(super) stop: WorkStop,
}

pub(super) struct SessionCompletion {
    pub(super) result: Result<Option<PreparedDownload>, RuleSetLoadError>,
    pub(super) cleanup_failed: bool,
}

pub(super) fn run_session(
    mut input: SessionInput,
    mut commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<Result<CacheState, RuleSetLoadError>>,
) -> SessionCompletion {
    if let Err(error) = input.stop.check().and_then(|()| input.directory.acquire()) {
        let _ = ready.send(Err(error));
        return SessionCompletion {
            result: Err(error),
            cleanup_failed: false,
        };
    }
    #[cfg(test)]
    input.directory.worker_checkpoint();
    let mut state = match read_cache_sync(
        &input.directory,
        &input.source.cache_name,
        &input.source.url,
        &input.stop,
    ) {
        Ok(cached) => CacheState {
            cached,
            failure: None,
        },
        Err(error) => CacheState {
            cached: None,
            failure: Some(error.kind()),
        },
    };
    if input.expected_capabilities.is_some_and(|expected| {
        state
            .cached
            .as_ref()
            .is_some_and(|cached| cached.loaded.capabilities != expected)
    }) {
        state.cached = None;
        state.failure = Some(RuleSetLoadErrorKind::RegistryCompile);
    }
    if ready.send(Ok(state)).is_err() {
        return SessionCompletion {
            result: Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
            cleanup_failed: false,
        };
    }
    let mut transaction = None;
    let result = accept_commands(&mut input, &mut commands, &mut transaction);
    let cleanup_failed = transaction
        .as_mut()
        .is_some_and(|transaction: &mut CacheTransaction| transaction.cleanup().is_err());
    SessionCompletion {
        result,
        cleanup_failed,
    }
}

fn accept_commands(
    input: &mut SessionInput,
    commands: &mut mpsc::Receiver<Command>,
    transaction: &mut Option<CacheTransaction>,
) -> Result<Option<PreparedDownload>, RuleSetLoadError> {
    loop {
        input.stop.check()?;
        let command = tokio::runtime::Handle::current().block_on(async {
            tokio::select! {
                biased;
                () = input.stop.cancel.cancelled() => None,
                () = tokio::time::sleep_until(input.stop.deadline.unwrap_or_else(Instant::now)), if input.stop.deadline.is_some() => None,
                command = commands.recv() => command,
            }
        });
        input.stop.check()?;
        match command {
            Some(Command::Begin { deadline }) if input.stop.deadline.is_none() => {
                input.stop.deadline = Some(deadline)
            }
            Some(Command::Begin { .. }) => {
                return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task));
            }
            Some(Command::Chunk(bytes)) => {
                if input.stop.deadline.is_none()
                    || bytes.is_empty()
                    || bytes.len() > crate::cache::COPY_BUFFER_BYTES
                {
                    return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody));
                }
                if transaction.is_none() {
                    *transaction = Some(CacheTransaction::begin(&input.directory, &input.stop)?);
                }
                transaction
                    .as_mut()
                    .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))?
                    .write_chunk(&bytes, &input.stop)?;
            }
            Some(Command::Finish(metadata)) => {
                let transaction = transaction
                    .as_mut()
                    .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody))?;
                let compiled = transaction.compile(&input.stop)?;
                if input
                    .expected_capabilities
                    .is_some_and(|expected| expected != compiled.capabilities)
                {
                    return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile));
                }
                // Registry preparation belongs to work orchestration, not the
                // file-format owner, and finishes before the disk commit point.
                let successor = input
                    .refresh
                    .as_ref()
                    .map(|refresh| {
                        let mut builder = refresh
                            .current
                            .builder_for_generation(input.generation)
                            .map_err(rule_compile_load_error)?;
                        builder
                            .replace_shared_rule_set(
                                refresh.rule_set,
                                Arc::clone(&compiled.match_set),
                            )
                            .map_err(rule_compile_load_error)?;
                        builder.build().map_err(rule_compile_load_error)
                    })
                    .transpose()?;
                input.stop.check()?;
                transaction.commit(CacheCommit {
                    directory: &input.directory,
                    name: &input.source.cache_name,
                    url: &input.source.url,
                    metadata,
                    compiled: &compiled,
                    generation: input.generation,
                    stop: &input.stop,
                })?;
                input.stop.check()?;
                return Ok(Some(PreparedDownload {
                    loaded: LoadedRuleSet {
                        match_set: compiled.match_set,
                        capabilities: compiled.capabilities,
                        srs_version: compiled.srs_version,
                        generation: input.generation,
                        disposition: RuleSetLoadDisposition::Downloaded,
                        degraded_failure: None,
                    },
                    successor,
                }));
            }
            Some(Command::Abort) => return Ok(None),
            None => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
        }
    }
}
