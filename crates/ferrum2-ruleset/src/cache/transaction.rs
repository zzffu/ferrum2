use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, PersistError};

use super::format::{
    CacheMetadata, HEADER_BYTES, Header, MAX_METADATA_BYTES, SerializableCapabilities,
};
use super::{
    CacheDirectory, CompiledFile, MAX_PAYLOAD_BYTES, WorkStop, cache_path, compile_payload,
    validators_valid,
};
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::source::RuleSetCacheName;

pub(crate) struct DownloadMetadata {
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
}

pub(crate) struct CacheCommit<'a> {
    pub(crate) directory: &'a CacheDirectory,
    pub(crate) name: &'a RuleSetCacheName,
    pub(crate) url: &'a str,
    pub(crate) metadata: DownloadMetadata,
    pub(crate) compiled: &'a CompiledFile,
    pub(crate) generation: u64,
    pub(crate) stop: &'a WorkStop,
}

/// Transaction-local file operations. Implementations must operate on the
/// supplied owned file/temp, preserve failure ownership and never remove a
/// committed target on failure. This seam permits ordinary injected IO failures.
pub(super) trait TransactionIo {
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()>;
    fn flush(&self, file: &mut File) -> std::io::Result<()>;
    fn sync(&self, file: &File) -> std::io::Result<()>;
    fn persist(&self, temp: NamedTempFile, path: &Path) -> Result<File, PersistError>;
    fn sync_directory(&self, directory: &Path) -> std::io::Result<()>;
    fn close(&self, temp: NamedTempFile) -> std::io::Result<()>;
}

pub(super) struct SystemTransactionIo;
impl TransactionIo for SystemTransactionIo {
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)
    }
    fn flush(&self, file: &mut File) -> std::io::Result<()> {
        file.flush()
    }
    fn sync(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
    fn persist(&self, temp: NamedTempFile, path: &Path) -> Result<File, PersistError> {
        temp.persist(path)
    }
    fn sync_directory(&self, directory: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            File::open(directory)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Ok(())
        }
    }
    fn close(&self, temp: NamedTempFile) -> std::io::Result<()> {
        temp.close()
    }
}

/// Never leaves its registered blocking session. No file/path handle is handed
/// to an async producer; explicit cleanup reports failures before completion.
pub(crate) struct CacheTransaction {
    temp: Option<NamedTempFile>,
    length: u64,
    digest: Sha256,
}

impl CacheTransaction {
    pub(crate) fn begin(
        directory: &CacheDirectory,
        stop: &WorkStop,
    ) -> Result<Self, RuleSetLoadError> {
        stop.check()?;
        let temp = NamedTempFile::new_in(&directory.path).map_err(|_| write_error())?;
        Ok(Self {
            temp: Some(temp),
            length: 0,
            digest: Sha256::new(),
        })
    }

    pub(crate) fn write_chunk(
        &mut self,
        bytes: &[u8],
        stop: &WorkStop,
    ) -> Result<(), RuleSetLoadError> {
        self.write_with(bytes, stop, &SystemTransactionIo)
    }

    fn write_with(
        &mut self,
        bytes: &[u8],
        stop: &WorkStop,
        io: &impl TransactionIo,
    ) -> Result<(), RuleSetLoadError> {
        stop.check()?;
        let next = self
            .length
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadOverflow))?;
        if next > MAX_PAYLOAD_BYTES {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheLimit));
        }
        let file = self.temp.as_mut().ok_or_else(write_error)?.as_file_mut();
        if self.length == 0 {
            io.write(file, &[0; HEADER_BYTES])
                .map_err(|_| write_error())?;
        }
        io.write(file, bytes).map_err(|_| write_error())?;
        self.digest.update(bytes);
        self.length = next;
        Ok(())
    }

    pub(crate) fn compile(&mut self, stop: &WorkStop) -> Result<CompiledFile, RuleSetLoadError> {
        if self.length == 0 {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody));
        }
        compile_payload(
            self.temp.as_mut().ok_or_else(write_error)?.as_file_mut(),
            self.length,
            stop,
        )
    }

    pub(crate) fn commit(&mut self, input: CacheCommit<'_>) -> Result<(), RuleSetLoadError> {
        self.commit_with(input, &SystemTransactionIo)
    }

    fn commit_with(
        &mut self,
        input: CacheCommit<'_>,
        io: &impl TransactionIo,
    ) -> Result<(), RuleSetLoadError> {
        let CacheCommit {
            directory,
            name,
            url,
            metadata,
            compiled,
            generation,
            stop,
        } = input;
        stop.check()?;
        if !validators_valid(metadata.etag.as_deref(), metadata.last_modified.as_deref()) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheLimit));
        }
        let metadata = CacheMetadata {
            schema: 1,
            url: url.to_owned(),
            etag: metadata.etag.map(Into::into),
            last_modified: metadata.last_modified.map(Into::into),
            downloaded_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            sha256: hex::encode(self.digest.clone().finalize()),
            srs_version: compiled.srs_version,
            capabilities: SerializableCapabilities::from(compiled.capabilities),
            generation,
        };
        if !metadata.valid(url) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
        }
        let encoded = serde_json::to_vec(&metadata).map_err(|_| write_error())?;
        if encoded.len() > MAX_METADATA_BYTES {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheLimit));
        }
        let file = self.temp.as_mut().ok_or_else(write_error)?.as_file_mut();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + self.length))
            .map_err(|_| write_error())?;
        io.write(file, &encoded).map_err(|_| write_error())?;
        file.seek(SeekFrom::Start(0)).map_err(|_| write_error())?;
        io.write(file, &Header::encode(self.length, &encoded))
            .map_err(|_| write_error())?;
        io.flush(file).map_err(|_| write_error())?;
        io.sync(file).map_err(|_| write_error())?;
        stop.check()?;
        let _commit = directory.commit_guard()?;
        stop.check()?;
        let temp = self.temp.take().ok_or_else(write_error)?;
        match io.persist(temp, &cache_path(&directory.path, name)) {
            Ok(file) => drop(file),
            Err(error) => {
                self.temp = Some(error.file);
                return Err(write_error());
            }
        }
        // The replacement has committed. A durability error does not delete the
        // complete new container or pretend an old on-disk generation survived.
        io.sync_directory(&directory.path)
            .map_err(|_| write_error())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), RuleSetLoadError> {
        self.cleanup_with(&SystemTransactionIo)
    }

    fn cleanup_with(&mut self, io: &impl TransactionIo) -> Result<(), RuleSetLoadError> {
        if let Some(temp) = self.temp.take() {
            io.close(temp)
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheCleanup))?;
        }
        Ok(())
    }
}

fn write_error() -> RuleSetLoadError {
    RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite)
}

#[cfg(test)]
mod tests;
