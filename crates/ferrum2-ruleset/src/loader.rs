use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_core::route::EgressPlanHandle;
use ferrum2_rule::{CompiledMatchSet, MatchSetCapabilities};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::blocking::BlockingTaskOwner;
use crate::cache::{
    CACHE_SCHEMA, COPY_BUFFER_BYTES, CacheMetadata, SerializableCapabilities, commit_cache,
    compile_file, read_cache_sync, stale_or_error,
};
use crate::download::{
    RuleSetDownloadRequest, RuleSetDownloadResponse, RuleSetDownloadStatus, RuleSetDownloader,
};
use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};
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

/// Remote loader with an injected network path. It never constructs or falls
/// back to a system HTTP client.
/// Cache/compiler work admits at most two blocking operations per loader;
/// concurrent callers wait for capacity, including after waiter cancellation.
pub struct RuleSetLoader<D> {
    config: RuleSetLoaderConfig,
    downloader: D,
    blocking: BlockingTaskOwner,
}

impl<D> RuleSetLoader<D>
where
    D: RuleSetDownloader,
{
    pub fn new(config: RuleSetLoaderConfig, downloader: D) -> Self {
        Self {
            config,
            downloader,
            blocking: BlockingTaskOwner::new(),
        }
    }

    /// Stops accepting blocking cache/compiler work and joins every operation,
    /// including work whose async refresh future was cancelled.
    /// Cancellation leaves joins owned for a subsequent call; concurrent calls
    /// cannot report completion before the same outstanding work has joined.
    pub async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.blocking.shutdown().await
    }

    pub async fn load(
        &self,
        source: &RuleSetRemoteSource,
        next_generation: u64,
    ) -> Result<LoadedRuleSet, RuleSetLoadError> {
        self.load_with_capabilities(source, next_generation, None)
            .await
    }

    pub(crate) async fn load_with_capabilities(
        &self,
        source: &RuleSetRemoteSource,
        next_generation: u64,
        expected_capabilities: Option<MatchSetCapabilities>,
    ) -> Result<LoadedRuleSet, RuleSetLoadError> {
        tokio::fs::create_dir_all(&self.config.cache_dir)
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheDirectory))?;

        let cache_dir = self.config.cache_dir.clone();
        let cache_name = source.cache_name.clone();
        let expected_url = source.url.clone();
        let cache_result = self
            .blocking
            .run(move || read_cache_sync(&cache_dir, &cache_name, &expected_url))
            .await?;
        let (mut cached, mut cache_failure) = match cache_result {
            Ok(cached) => (cached, None),
            Err(error) => (None, Some(error.kind())),
        };
        if expected_capabilities.is_some_and(|expected| {
            cached
                .as_ref()
                .is_some_and(|cached| cached.loaded.capabilities != expected)
        }) {
            cached = None;
            cache_failure = Some(RuleSetLoadErrorKind::RegistryCompile);
        }
        let deadline = Instant::now() + self.config.download_timeout;
        let request = RuleSetDownloadRequest {
            url: source.url.clone(),
            mode: source.mode,
            detour: source.detour.as_ref().map(EgressPlanHandle::snapshot_owned),
            if_none_match: cached.as_ref().and_then(|cache| cache.etag.clone()),
            if_modified_since: cached
                .as_ref()
                .and_then(|cache| cache.last_modified.clone()),
            deadline,
            max_redirects: self.config.max_redirects,
        };

        let response = match tokio::time::timeout_at(deadline, self.downloader.fetch(request)).await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return stale_or_error(
                    cached,
                    RuleSetLoadErrorKind::Download(error.kind()),
                    cache_failure,
                );
            }
            Err(_) => {
                return stale_or_error(
                    cached,
                    RuleSetLoadErrorKind::DownloadTimeout,
                    cache_failure,
                );
            }
        };

        match response.status {
            RuleSetDownloadStatus::NotModified => {
                let mut cached = cached.ok_or_else(|| {
                    RuleSetLoadError::new(
                        cache_failure.unwrap_or(RuleSetLoadErrorKind::NotModifiedWithoutCache),
                    )
                })?;
                cached.loaded.disposition = RuleSetLoadDisposition::NotModified;
                Ok(cached.loaded)
            }
            RuleSetDownloadStatus::Downloaded => {
                match self
                    .accept_download(
                        source,
                        response,
                        deadline,
                        next_generation,
                        expected_capabilities,
                    )
                    .await
                {
                    Ok(loaded) => Ok(loaded),
                    Err(error) => stale_or_error(cached, error.kind(), None),
                }
            }
        }
    }

    async fn accept_download(
        &self,
        source: &RuleSetRemoteSource,
        mut response: RuleSetDownloadResponse,
        deadline: Instant,
        generation: u64,
        expected_capabilities: Option<MatchSetCapabilities>,
    ) -> Result<LoadedRuleSet, RuleSetLoadError> {
        let mut body = response
            .body
            .take()
            .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody))?;
        let temp_dir = self.config.cache_dir.clone();
        let (temp, writer) = self
            .blocking
            .run(move || {
                let temp = NamedTempFile::new_in(temp_dir)
                    .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
                let writer = temp
                    .reopen()
                    .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
                Ok::<_, RuleSetLoadError>((temp, writer))
            })
            .await??;
        let mut writer = tokio::fs::File::from_std(writer);
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(COPY_BUFFER_BYTES)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
        buffer.resize(COPY_BUFFER_BYTES, 0);

        loop {
            let read = tokio::time::timeout_at(deadline, body.read(&mut buffer))
                .await
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadTimeout))?
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody))?;
            if read == 0 {
                break;
            }
            total =
                total
                    .checked_add(u64::try_from(read).map_err(|_| {
                        RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadOverflow)
                    })?)
                    .ok_or_else(|| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadOverflow))?;
            hasher.update(&buffer[..read]);
            tokio::time::timeout_at(deadline, writer.write_all(&buffer[..read]))
                .await
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadTimeout))?
                .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
        }
        tokio::time::timeout_at(deadline, writer.flush())
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadTimeout))?
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
        tokio::time::timeout_at(deadline, writer.sync_all())
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadTimeout))?
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::CacheWrite))?;
        drop(writer);
        if total == 0 {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::DownloadBody));
        }

        let temp_path = temp.path().to_path_buf();
        let compiled = self
            .blocking
            .run(move || compile_file(&temp_path))
            .await??;
        if expected_capabilities.is_some_and(|expected| expected != compiled.capabilities) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile));
        }
        let digest = hex::encode(hasher.finalize());
        let downloaded_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let metadata = CacheMetadata {
            schema: CACHE_SCHEMA,
            url: source.url.to_string(),
            etag: response.etag.map(Into::into),
            last_modified: response.last_modified.map(Into::into),
            downloaded_unix_seconds,
            sha256: digest,
            srs_version: compiled.srs_version,
            capabilities: SerializableCapabilities::from(compiled.capabilities),
            generation,
        };
        let cache_dir = self.config.cache_dir.clone();
        let cache_name = source.cache_name.clone();
        self.blocking
            .run(move || commit_cache(&cache_dir, &cache_name, temp, &metadata))
            .await??;

        Ok(LoadedRuleSet {
            match_set: compiled.match_set,
            capabilities: compiled.capabilities,
            srs_version: compiled.srs_version,
            generation,
            disposition: RuleSetLoadDisposition::Downloaded,
            degraded_failure: None,
        })
    }
}
