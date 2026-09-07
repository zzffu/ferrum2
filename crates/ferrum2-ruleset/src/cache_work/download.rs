use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use ferrum2_core::route::EgressPlanHandle;
use futures_util::FutureExt;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::cache::{
    COPY_BUFFER_BYTES, DownloadMetadata, MAX_PAYLOAD_BYTES, stale_or_error, validators_valid,
};
use crate::download::{RuleSetDownloadRequest, RuleSetDownloadStatus, RuleSetDownloader};
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::source::RuleSetLoaderConfig;

use super::session::{CacheState, Command, PreparedDownload, SessionInput, run_session};

pub(super) struct LoadCompletion {
    pub(super) result: Result<PreparedDownload, RuleSetLoadError>,
    pub(super) cleanup_failed: bool,
}

#[derive(Clone, Copy)]
enum TransferOutcome {
    Downloaded,
    NotModified,
    FetchFailed(RuleSetLoadErrorKind),
    BodyFailed(RuleSetLoadErrorKind),
}

pub(super) async fn load<D: RuleSetDownloader + 'static>(
    input: SessionInput,
    downloader: Arc<D>,
    config: RuleSetLoaderConfig,
) -> LoadCompletion {
    let source = input.source.clone();
    let cancel = input.stop.cancel.clone();
    let (sender, receiver) = mpsc::channel(2);
    let (ready, current) = oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || run_session(input, receiver, ready));
    // Keep the child JoinHandle outside the unwind boundary. An injected
    // downloader panic cannot detach the real file/temp worker.
    let transferred = AssertUnwindSafe(async {
        let state = tokio::select! {
            () = cancel.cancelled() => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
            state = current => state.map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))??,
        };
        let deadline = Instant::now() + config.download_timeout;
        sender.send(Command::Begin { deadline }).await.map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))?;
        let request = RuleSetDownloadRequest {
            url: source.url.clone(), mode: source.mode, detour: source.detour.as_ref().map(EgressPlanHandle::snapshot_owned),
            if_none_match: state.cached.as_ref().and_then(|cache| cache.etag.clone()),
            if_modified_since: state.cached.as_ref().and_then(|cache| cache.last_modified.clone()),
            deadline, max_redirects: config.max_redirects,
        };
        let fetched = tokio::select! {
            () = cancel.cancelled() => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
            result = tokio::time::timeout_at(deadline, downloader.fetch(request)) => result,
        };
        let mut response = match fetched {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Ok((state, TransferOutcome::FetchFailed(RuleSetLoadErrorKind::Download(error.kind())))),
            Err(_) => return Ok((state, TransferOutcome::FetchFailed(RuleSetLoadErrorKind::DownloadTimeout))),
        };
        if response.status == RuleSetDownloadStatus::NotModified {
            let _ = sender.send(Command::Abort).await;
            return Ok((state, TransferOutcome::NotModified));
        }
        if !validators_valid(response.etag.as_deref(), response.last_modified.as_deref()) {
            return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::CacheLimit)));
        }
        let Some(mut body) = response.body.take() else {
            return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadBody)));
        };
        let mut buffer = [0; COPY_BUFFER_BYTES];
        let mut total = 0_u64;
        loop {
            let result = tokio::select! {
                () = cancel.cancelled() => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
                result = tokio::time::timeout_at(deadline, body.read(&mut buffer)) => result,
            };
            let count = match result {
                Ok(Ok(count)) => count,
                Ok(Err(_)) => return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadBody))),
                Err(_) => return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadTimeout))),
            };
            if count == 0 { break; }
            total = total.checked_add(count as u64).ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadOverflow))?;
            if total > MAX_PAYLOAD_BYTES { return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::CacheLimit))); }
            let mut chunk = Vec::new();
            chunk.try_reserve_exact(count).map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
            chunk.extend_from_slice(&buffer[..count]);
            let sent = tokio::select! {
                () = cancel.cancelled() => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
                sent = tokio::time::timeout_at(deadline, sender.send(Command::Chunk(chunk))) => sent,
            };
            match sent {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadBody))),
                Err(_) => return Ok((state, TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadTimeout))),
            }
        }
        drop(body);
        let finish = Command::Finish(DownloadMetadata { etag: response.etag, last_modified: response.last_modified });
        let sent = tokio::select! {
            () = cancel.cancelled() => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
            sent = tokio::time::timeout_at(deadline, sender.send(finish)) => sent,
        };
        Ok((state, match sent {
            Ok(Ok(())) => TransferOutcome::Downloaded,
            Ok(Err(_)) => TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadBody),
            Err(_) => TransferOutcome::BodyFailed(RuleSetLoadErrorKind::DownloadTimeout),
        }))
    }).catch_unwind().await;
    if transferred.is_err() || matches!(&transferred, Ok(Err(_))) {
        cancel.cancel();
    }
    drop(sender); // Disconnect is abort, never implicit successful EOF.
    let joined = worker.await;
    let (session, cleanup_failed) = match joined {
        Ok(session) => {
            let failed = session.cleanup_failed;
            (session.result, failed)
        }
        Err(_) => {
            return LoadCompletion {
                result: Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task)),
                cleanup_failed: true,
            };
        }
    };
    let result = match transferred {
        Err(_) => Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task)),
        Ok(Err(error)) => Err(error),
        Ok(Ok((state, outcome))) if !cancel.is_cancelled() => complete(state, outcome, session),
        Ok(Ok(_)) => Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled)),
    };
    LoadCompletion {
        result: if cleanup_failed {
            Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheCleanup))
        } else {
            result
        },
        cleanup_failed,
    }
}

fn complete(
    mut state: CacheState,
    outcome: TransferOutcome,
    session: Result<Option<PreparedDownload>, RuleSetLoadError>,
) -> Result<PreparedDownload, RuleSetLoadError> {
    match outcome {
        TransferOutcome::Downloaded => match session {
            Ok(Some(download)) => Ok(download),
            Ok(None) => Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task)),
            Err(error) => {
                stale_or_error(state.cached, error.kind(), None).map(|loaded| PreparedDownload {
                    loaded,
                    successor: None,
                })
            }
        },
        TransferOutcome::NotModified => {
            session?;
            let mut cached = state.cached.take().ok_or_else(|| {
                RuleSetLoadError::new(
                    state
                        .failure
                        .unwrap_or(RuleSetLoadErrorKind::NotModifiedWithoutCache),
                )
            })?;
            cached.loaded.disposition = crate::loader::RuleSetLoadDisposition::NotModified;
            Ok(PreparedDownload {
                loaded: cached.loaded,
                successor: None,
            })
        }
        TransferOutcome::FetchFailed(failure) | TransferOutcome::BodyFailed(failure) => {
            let use_invalid_cache = matches!(outcome, TransferOutcome::FetchFailed(_));
            let failure = match session {
                Err(error) if error.kind() != RuleSetLoadErrorKind::Cancelled => error.kind(),
                Ok(_) | Err(_) => failure,
            };
            stale_or_error(
                state.cached,
                failure,
                if use_invalid_cache {
                    state.failure
                } else {
                    None
                },
            )
            .map(|loaded| PreparedDownload {
                loaded,
                successor: None,
            })
        }
    }
}
