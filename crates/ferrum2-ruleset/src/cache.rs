mod directory;
mod format;
mod transaction;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ferrum2_rule::srs::{SrsDecodeLimits, decode_srs};
use ferrum2_rule::{CompiledMatchSet, MatchSetCapabilities};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::loader::{LoadedRuleSet, RuleSetLoadDisposition};
use crate::source::RuleSetCacheName;

pub(crate) use directory::CacheDirectory;
use format::{CacheMetadata, HEADER_BYTES, Header, SerializableCapabilities};
pub(crate) use format::{MAX_PAYLOAD_BYTES, MAX_URL_BYTES, validators_valid};
pub(crate) use transaction::{CacheCommit, CacheTransaction, DownloadMetadata};
pub(crate) const COPY_BUFFER_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub(crate) struct WorkStop {
    pub(crate) cancel: CancellationToken,
    pub(crate) deadline: Option<Instant>,
}

impl WorkStop {
    pub(crate) fn check(&self) -> Result<(), RuleSetLoadError> {
        if self.cancel.is_cancelled() {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Cancelled));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadTimeout));
        }
        Ok(())
    }
}

pub(crate) fn stale_or_error(
    cached: Option<CachedRuleSet>,
    failure: RuleSetLoadErrorKind,
    invalid_cache: Option<RuleSetLoadErrorKind>,
) -> Result<LoadedRuleSet, RuleSetLoadError> {
    if failure == RuleSetLoadErrorKind::Cancelled {
        return Err(RuleSetLoadError::new(failure));
    }
    if let Some(mut cached) = cached {
        cached.loaded.disposition = if matches!(
            failure,
            RuleSetLoadErrorKind::Download(_)
                | RuleSetLoadErrorKind::DownloadTimeout
                | RuleSetLoadErrorKind::DownloadBody
        ) {
            RuleSetLoadDisposition::OfflineCache
        } else {
            RuleSetLoadDisposition::StaleCache
        };
        cached.loaded.degraded_failure = Some(failure);
        Ok(cached.loaded)
    } else {
        Err(RuleSetLoadError::new(invalid_cache.unwrap_or(failure)))
    }
}

pub(crate) struct CachedRuleSet {
    pub(crate) loaded: LoadedRuleSet,
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
}

pub(crate) struct CompiledFile {
    pub(crate) match_set: Arc<CompiledMatchSet>,
    pub(crate) capabilities: MatchSetCapabilities,
    pub(crate) srs_version: u8,
}

struct CheckedReader<'a, R> {
    reader: R,
    stop: &'a WorkStop,
}
impl<R: Read> Read for CheckedReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stop
            .check()
            .map_err(|_| std::io::Error::other("RuleSet work stopped"))?;
        self.reader.read(bytes)
    }
}

fn compile_payload(
    file: &mut File,
    length: u64,
    stop: &WorkStop,
) -> Result<CompiledFile, RuleSetLoadError> {
    stop.check()?;
    file.seek(SeekFrom::Start(HEADER_BYTES as u64))
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let decoded = decode_srs(
        CheckedReader {
            reader: file.take(length),
            stop,
        },
        SrsDecodeLimits::default(),
    );
    stop.check()?;
    let decoded = decoded
        .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?;
    let capabilities = decoded.capabilities();
    let srs_version = decoded.version();
    let compiled = decoded.compile();
    stop.check()?;
    let match_set = Arc::new(
        compiled
            .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?,
    );
    Ok(CompiledFile {
        match_set,
        capabilities,
        srs_version,
    })
}

pub(crate) fn read_cache_sync(
    directory: &CacheDirectory,
    name: &RuleSetCacheName,
    expected_url: &str,
    stop: &WorkStop,
) -> Result<Option<CachedRuleSet>, RuleSetLoadError> {
    stop.check()?;
    let path = cache_path(&directory.path, name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead)),
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead)),
    };
    read_held_cache(&mut file, expected_url, stop).map(Some)
}

fn read_held_cache(
    file: &mut File,
    expected_url: &str,
    stop: &WorkStop,
) -> Result<CachedRuleSet, RuleSetLoadError> {
    let attributes = file
        .metadata()
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    if !attributes.is_file() {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    let mut bytes = [0; HEADER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata))?;
    let header = Header::decode(bytes, attributes.len())?;
    file.seek(SeekFrom::Start(HEADER_BYTES as u64 + header.payload_bytes))
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let mut metadata_bytes = Vec::new();
    metadata_bytes
        .try_reserve_exact(header.metadata_bytes)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    metadata_bytes.resize(header.metadata_bytes, 0);
    file.read_exact(&mut metadata_bytes)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata))?;
    if Sha256::digest(&metadata_bytes).as_slice() != header.metadata_digest {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDigest));
    }
    let metadata: CacheMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata))?;
    if !metadata.valid(expected_url) {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    file.seek(SeekFrom::Start(HEADER_BYTES as u64))
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let mut payload = (&mut *file).take(header.payload_bytes);
    let mut hasher = Sha256::new();
    let mut buffer = [0; COPY_BUFFER_BYTES];
    loop {
        stop.check()?;
        let count = payload
            .read(&mut buffer)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if payload.limit() != 0 {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    if hex::encode(hasher.finalize()) != metadata.sha256 {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDigest));
    }
    let compiled = compile_payload(file, header.payload_bytes, stop)?;
    if metadata.srs_version != compiled.srs_version
        || metadata.capabilities != SerializableCapabilities::from(compiled.capabilities)
    {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    Ok(CachedRuleSet {
        loaded: LoadedRuleSet {
            match_set: compiled.match_set,
            capabilities: compiled.capabilities,
            srs_version: compiled.srs_version,
            generation: metadata.generation,
            disposition: RuleSetLoadDisposition::OfflineCache,
            degraded_failure: None,
        },
        etag: metadata.etag.map(Into::into),
        last_modified: metadata.last_modified.map(Into::into),
    })
}

fn cache_path(directory: &Path, name: &RuleSetCacheName) -> PathBuf {
    directory.join(format!(
        "rs-{}.frs-cache",
        hex::encode(Sha256::digest(name.as_str().as_bytes()))
    ))
}
