use std::fs::{File, OpenOptions, TryLockError};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};

/// Kept by the loader and each accepted real worker. Only worker operations
/// acquire/release the held lock; an OS call still in flight retains this owner.
pub(crate) struct CacheDirectory {
    pub(crate) path: PathBuf,
    lease: Mutex<Option<File>>,
    commit: Mutex<()>,
    #[cfg(test)]
    checkpoint: Mutex<Option<WorkerCheckpoint>>,
}

impl CacheDirectory {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            lease: Mutex::new(None),
            commit: Mutex::new(()),
            #[cfg(test)]
            checkpoint: Mutex::new(None),
        }
    }

    pub(crate) fn acquire(&self) -> Result<(), RuleSetLoadError> {
        let mut lease = self
            .lease
            .lock()
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory))?;
        if lease.is_some() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.path)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory))?;
        if !std::fs::metadata(&self.path).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory));
        }
        let path = self.path.join(".ferrum2-ruleset.lock");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => {
                return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory))?;
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory));
        }
        file.try_lock().map_err(|error| {
            RuleSetLoadError::new(match error {
                TryLockError::WouldBlock => RuleSetLoadErrorKind::CacheBusy,
                TryLockError::Error(_) => RuleSetLoadErrorKind::CacheDirectory,
            })
        })?;
        *lease = Some(file);
        Ok(())
    }

    pub(crate) fn commit_guard(&self) -> Result<MutexGuard<'_, ()>, RuleSetLoadError> {
        self.commit
            .lock()
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))
    }

    pub(crate) fn release(&self) -> Result<(), RuleSetLoadError> {
        let mut lease = self
            .lease
            .lock()
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheCleanup))?;
        if let Some(file) = lease.take() {
            file.unlock()
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheCleanup))?;
        }
        Ok(())
    }
}

#[cfg(test)]
struct WorkerCheckpoint {
    entered: tokio::sync::oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl CacheDirectory {
    pub(crate) fn pause_next_worker(
        &self,
        entered: tokio::sync::oneshot::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        *self.checkpoint.lock().expect("checkpoint lock") =
            Some(WorkerCheckpoint { entered, resume });
    }

    pub(crate) fn worker_checkpoint(&self) {
        let checkpoint = self.checkpoint.lock().expect("checkpoint lock").take();
        if let Some(checkpoint) = checkpoint {
            let _ = checkpoint.entered.send(());
            // A bounded stand-in for an OS call which cancellation cannot end.
            let _ = checkpoint
                .resume
                .recv_timeout(std::time::Duration::from_secs(2));
        }
    }
}
