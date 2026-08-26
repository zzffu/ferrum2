use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ferrum2_rule::srs::decode_srs;
use ferrum2_rule::{CompiledMatchSet, MatchSetCapabilities};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
use crate::loader::{LoadedRuleSet, RuleSetLoadDisposition};
use crate::source::RuleSetCacheName;

pub(crate) const CACHE_SCHEMA: u8 = 1;
pub(crate) const COPY_BUFFER_BYTES: usize = 32 * 1024;

pub(crate) fn stale_or_error(
    cached: Option<CachedRuleSet>,
    failure: RuleSetLoadErrorKind,
    invalid_cache: Option<RuleSetLoadErrorKind>,
) -> Result<LoadedRuleSet, RuleSetLoadError> {
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

#[derive(Debug)]
pub(crate) struct CachedRuleSet {
    pub(crate) loaded: LoadedRuleSet,
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
}

#[derive(Debug)]
pub(crate) struct CompiledFile {
    pub(crate) match_set: Arc<CompiledMatchSet>,
    pub(crate) capabilities: MatchSetCapabilities,
    pub(crate) srs_version: u8,
}

pub(crate) fn compile_file(path: &Path) -> Result<CompiledFile, RuleSetLoadError> {
    let file =
        File::open(path).map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let decoded = decode_srs(file)
        .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?;
    let capabilities = decoded.capabilities();
    let srs_version = decoded.version();
    let match_set = Arc::new(
        decoded
            .compile()
            .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?,
    );
    Ok(CompiledFile {
        match_set,
        capabilities,
        srs_version,
    })
}

pub(crate) fn read_cache_sync(
    cache_dir: &Path,
    cache_name: &RuleSetCacheName,
    expected_url: &str,
) -> Result<Option<CachedRuleSet>, RuleSetLoadError> {
    let srs_path = cache_path(cache_dir, cache_name, "srs");
    let meta_path = cache_path(cache_dir, cache_name, "meta");
    let srs_exists = srs_path.exists();
    let meta_exists = meta_path.exists();
    if !srs_exists && !meta_exists {
        return Ok(None);
    }
    if !srs_exists || !meta_exists {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    let metadata_file = File::open(meta_path)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let metadata: CacheMetadata = serde_json::from_reader(metadata_file)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata))?;
    if metadata.schema != CACHE_SCHEMA
        || metadata.url != expected_url
        || metadata.sha256.len() != 64
    {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }

    let mut file = File::open(&srs_path)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hex::encode(hasher.finalize()) != metadata.sha256 {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDigest));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheRead))?;
    let decoded = decode_srs(file)
        .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?;
    let capabilities = decoded.capabilities();
    let srs_version = decoded.version();
    if metadata.srs_version != srs_version
        || metadata.capabilities != SerializableCapabilities::from(capabilities)
    {
        return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata));
    }
    let match_set = Arc::new(
        decoded
            .compile()
            .map_err(|error| RuleSetLoadError::new(RuleSetLoadErrorKind::Decode(error.kind())))?,
    );
    Ok(Some(CachedRuleSet {
        loaded: LoadedRuleSet {
            match_set,
            capabilities,
            srs_version,
            generation: metadata.generation,
            disposition: RuleSetLoadDisposition::OfflineCache,
            degraded_failure: None,
        },
        etag: metadata.etag.map(Into::into),
        last_modified: metadata.last_modified.map(Into::into),
    }))
}

pub(crate) fn commit_cache(
    cache_dir: &Path,
    cache_name: &RuleSetCacheName,
    srs_temp: NamedTempFile,
    metadata: &CacheMetadata,
) -> Result<(), RuleSetLoadError> {
    let mut meta_temp = NamedTempFile::new_in(cache_dir)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    serde_json::to_writer(meta_temp.as_file_mut(), metadata)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    meta_temp
        .as_file_mut()
        .flush()
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    meta_temp
        .as_file()
        .sync_all()
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    srs_temp
        .as_file()
        .sync_all()
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;

    let srs_path = cache_path(cache_dir, cache_name, "srs");
    let meta_path = cache_path(cache_dir, cache_name, "meta");
    srs_temp
        .persist(&srs_path)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    meta_temp
        .persist(&meta_path)
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
    sync_cache_directory(cache_dir)?;
    Ok(())
}

#[cfg(unix)]
fn sync_cache_directory(cache_dir: &Path) -> Result<(), RuleSetLoadError> {
    File::open(cache_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))
}

#[cfg(not(unix))]
fn sync_cache_directory(_cache_dir: &Path) -> Result<(), RuleSetLoadError> {
    Ok(())
}

fn cache_path(cache_dir: &Path, cache_name: &RuleSetCacheName, extension: &str) -> PathBuf {
    cache_dir.join(format!("{}.{}", cache_name.as_str(), extension))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheMetadata {
    pub(crate) schema: u8,
    pub(crate) url: String,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
    pub(crate) downloaded_unix_seconds: u64,
    pub(crate) sha256: String,
    pub(crate) srs_version: u8,
    pub(crate) capabilities: SerializableCapabilities,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SerializableCapabilities {
    exact_domain: bool,
    domain_suffix: bool,
    domain_keyword: bool,
    ip_cidr: bool,
}

impl From<MatchSetCapabilities> for SerializableCapabilities {
    fn from(value: MatchSetCapabilities) -> Self {
        Self {
            exact_domain: value.exact_domain,
            domain_suffix: value.domain_suffix,
            domain_keyword: value.domain_keyword,
            ip_cidr: value.ip_cidr,
        }
    }
}
