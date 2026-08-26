use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot};
use ferrum2_dns::DnsServerId;
use ferrum2_rule::srs::{SrsErrorKind, decode_srs};
use ferrum2_rule::{
    CompiledMatchSet, MatchSetCapabilities, RuleCompileError, RuleEngineRegistry,
    RuleEngineSnapshot, RuleEngineSnapshotBuilder, RuleSetId,
};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use url::{Host, Url};

const CACHE_SCHEMA: u8 = 1;
const COPY_BUFFER_BYTES: usize = 32 * 1024;

/// A body returned by the explicit RuleSet transport.
pub trait RuleSetBody: AsyncRead + Send + Unpin {}

impl<T> RuleSetBody for T where T: AsyncRead + Send + Unpin {}

/// Type-erased streaming response body.
pub type BoxedRuleSetBody = Box<dyn RuleSetBody>;

/// One asynchronous explicit-download operation.
pub type RuleSetDownloadFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RuleSetDownloadResponse, RuleSetDownloadError>> + Send + 'a>,
>;

/// Resolver selected explicitly for a remote RuleSet URL host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetDownloadResolver {
    System,
    DnsServer(DnsServerId),
}

/// The validated location at which a remote RuleSet URL host is resolved.
///
/// Deferred downloads deliberately carry no resolver. Their URL host is
/// delivered as a domain target to the configured immutable detour instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetDownloadMode {
    ClientResolved(RuleSetDownloadResolver),
    DeferredToDetour,
}

impl RuleSetDownloadMode {
    /// Returns the explicit client-side resolver, if this mode has one.
    pub const fn resolver(self) -> Option<RuleSetDownloadResolver> {
        match self {
            Self::ClientResolved(resolver) => Some(resolver),
            Self::DeferredToDetour => None,
        }
    }
}

/// A cache filename component already proven safe against path traversal.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RuleSetCacheName(Box<str>);

impl RuleSetCacheName {
    pub fn new(value: &str) -> Result<Self, RuleSetLoadError> {
        let valid = (1..=64).contains(&value.len())
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if valid {
            Ok(Self(value.into()))
        } else {
            Err(RuleSetLoadError::new(
                RuleSetLoadErrorKind::InvalidCacheName,
            ))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RuleSetCacheName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleSetCacheName([redacted])")
    }
}

/// Fully validated remote resource declaration consumed by the loader.
#[derive(Clone)]
pub struct RuleSetRemoteSource {
    cache_name: RuleSetCacheName,
    url: Box<str>,
    mode: RuleSetDownloadMode,
    detour: Option<EgressPlanHandle>,
    update_interval: Option<Duration>,
}

impl RuleSetRemoteSource {
    pub fn new(
        cache_name: RuleSetCacheName,
        url: &str,
        mode: RuleSetDownloadMode,
        detour: Option<EgressPlanHandle>,
        update_interval: Option<Duration>,
    ) -> Result<Self, RuleSetLoadError> {
        if update_interval.is_some_and(|interval| interval.is_zero()) {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::InvalidSource));
        }
        if mode == RuleSetDownloadMode::DeferredToDetour && detour.is_none() {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::InvalidSource));
        }
        let parsed = Url::parse(url)
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::InvalidSource))?;
        if parsed.scheme() != "https"
            || !matches!(parsed.host(), Some(Host::Domain(_)))
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::InvalidSource));
        }
        Ok(Self {
            cache_name,
            url: parsed.as_str().into(),
            mode,
            detour,
            update_interval,
        })
    }

    pub fn update_interval(&self) -> Option<Duration> {
        self.update_interval
    }
}

impl fmt::Debug for RuleSetRemoteSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetRemoteSource")
            .field("cache_name", &self.cache_name)
            .field("url", &"[redacted]")
            .field("mode", &self.mode)
            .field("detour", &self.detour)
            .field("update_interval", &self.update_interval)
            .finish()
    }
}

/// Operational settings for RuleSet downloads and the local cache.
#[derive(Clone)]
pub struct RuleSetLoaderConfig {
    cache_dir: PathBuf,
    download_timeout: Duration,
    max_redirects: u8,
}

impl RuleSetLoaderConfig {
    pub fn new(
        cache_dir: PathBuf,
        download_timeout: Duration,
        max_redirects: u8,
    ) -> Result<Self, RuleSetLoadError> {
        if cache_dir.as_os_str().is_empty() || download_timeout.is_zero() {
            return Err(RuleSetLoadError::new(
                RuleSetLoadErrorKind::InvalidLoaderConfig,
            ));
        }
        Ok(Self {
            cache_dir,
            download_timeout,
            max_redirects,
        })
    }
}

impl fmt::Debug for RuleSetLoaderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetLoaderConfig")
            .field("cache_dir", &"[redacted]")
            .field("download_timeout", &self.download_timeout)
            .field("max_redirects", &self.max_redirects)
            .finish()
    }
}

/// Request delivered to an injected downloader that is forbidden from choosing
/// a resolver or detour on its own.
#[derive(Clone)]
pub struct RuleSetDownloadRequest {
    url: Box<str>,
    mode: RuleSetDownloadMode,
    detour: Option<EgressPlanSnapshot>,
    if_none_match: Option<Box<str>>,
    if_modified_since: Option<Box<str>>,
    deadline: Instant,
    max_redirects: u8,
}

impl RuleSetDownloadRequest {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub const fn mode(&self) -> RuleSetDownloadMode {
        self.mode
    }

    pub fn detour(&self) -> Option<&EgressPlanSnapshot> {
        self.detour.as_ref()
    }

    pub fn if_none_match(&self) -> Option<&str> {
        self.if_none_match.as_deref()
    }

    pub fn if_modified_since(&self) -> Option<&str> {
        self.if_modified_since.as_deref()
    }

    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub const fn max_redirects(&self) -> u8 {
        self.max_redirects
    }
}

impl fmt::Debug for RuleSetDownloadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetDownloadRequest")
            .field("url", &"[redacted]")
            .field("mode", &self.mode)
            .field("detour", &self.detour)
            .field(
                "conditional",
                &(self.if_none_match.is_some() || self.if_modified_since.is_some()),
            )
            .field("deadline", &self.deadline)
            .field("max_redirects", &self.max_redirects)
            .finish()
    }
}

/// Closed transport failure category. Injected I/O and resolver details never
/// cross this crate boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetDownloadErrorKind {
    Resolution,
    Connect,
    Tls,
    Http,
    Redirect,
    Timeout,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSetDownloadError {
    kind: RuleSetDownloadErrorKind,
}

impl RuleSetDownloadError {
    pub const fn new(kind: RuleSetDownloadErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> RuleSetDownloadErrorKind {
        self.kind
    }
}

impl fmt::Display for RuleSetDownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote RuleSet transport failed")
    }
}

impl std::error::Error for RuleSetDownloadError {}

/// Downloader seam. Implementations must apply the supplied resolution mode
/// and immutable detour to the original host and every redirect host.
pub trait RuleSetDownloader: Send + Sync {
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_>;
}

impl<D> RuleSetDownloader for Arc<D>
where
    D: RuleSetDownloader + ?Sized,
{
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        (**self).fetch(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetDownloadStatus {
    Downloaded,
    NotModified,
}

pub struct RuleSetDownloadResponse {
    status: RuleSetDownloadStatus,
    etag: Option<Box<str>>,
    last_modified: Option<Box<str>>,
    body: Option<BoxedRuleSetBody>,
}

impl RuleSetDownloadResponse {
    pub fn downloaded(
        body: BoxedRuleSetBody,
        etag: Option<Box<str>>,
        last_modified: Option<Box<str>>,
    ) -> Self {
        Self {
            status: RuleSetDownloadStatus::Downloaded,
            etag,
            last_modified,
            body: Some(body),
        }
    }

    pub const fn not_modified() -> Self {
        Self {
            status: RuleSetDownloadStatus::NotModified,
            etag: None,
            last_modified: None,
            body: None,
        }
    }
}

impl fmt::Debug for RuleSetDownloadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetDownloadResponse")
            .field("status", &self.status)
            .field("etag", &self.etag.is_some())
            .field("last_modified", &self.last_modified.is_some())
            .field("body", &self.body.is_some())
            .finish()
    }
}

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
    match_set: Arc<CompiledMatchSet>,
    capabilities: MatchSetCapabilities,
    srs_version: u8,
    generation: u64,
    disposition: RuleSetLoadDisposition,
    degraded_failure: Option<RuleSetLoadErrorKind>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetLoadErrorKind {
    InvalidCacheName,
    InvalidSource,
    InvalidLoaderConfig,
    CacheDirectory,
    CacheRead,
    CacheMetadata,
    CacheDigest,
    Download(RuleSetDownloadErrorKind),
    DownloadTimeout,
    DownloadBody,
    DownloadOverflow,
    Allocation,
    Decode(SrsErrorKind),
    CacheWrite,
    Task,
    NotModifiedWithoutCache,
    RegistryCompile,
    RegistryPublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSetLoadError {
    kind: RuleSetLoadErrorKind,
}

impl RuleSetLoadError {
    const fn new(kind: RuleSetLoadErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> RuleSetLoadErrorKind {
        self.kind
    }
}

impl fmt::Display for RuleSetLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleSet materialization failed")
    }
}

impl std::error::Error for RuleSetLoadError {}

const fn rule_compile_load_error_kind(error: RuleCompileError) -> RuleSetLoadErrorKind {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => {
            RuleSetLoadErrorKind::Allocation
        }
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidId
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => RuleSetLoadErrorKind::RegistryCompile,
    }
}

const fn rule_compile_load_error(error: RuleCompileError) -> RuleSetLoadError {
    RuleSetLoadError::new(rule_compile_load_error_kind(error))
}

/// Remote loader with an injected network path. It never constructs or falls
/// back to a system HTTP client.
pub struct RuleSetLoader<D> {
    config: RuleSetLoaderConfig,
    downloader: D,
    blocking: BlockingTaskOwner,
}

struct BlockingTaskOwner {
    state: Mutex<BlockingTaskState>,
}

struct BlockingTaskState {
    accepting: bool,
    failed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl BlockingTaskOwner {
    fn new() -> Self {
        Self {
            state: Mutex::new(BlockingTaskState {
                accepting: true,
                failed: false,
                tasks: Vec::new(),
            }),
        }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, RuleSetLoadError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.accepting {
                return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task));
            }
            let mut cursor = 0;
            while cursor < state.tasks.len() {
                if state.tasks[cursor].is_finished() {
                    let task = state.tasks.swap_remove(cursor);
                    if task.now_or_never().is_some_and(|result| result.is_err()) {
                        state.failed = true;
                    }
                } else {
                    cursor += 1;
                }
            }
            let task = tokio::task::spawn_blocking(move || {
                let _ = sender.send(operation());
            });
            state.tasks.push(task);
        }
        receiver
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))
    }

    async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        let (tasks, previously_failed) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.accepting = false;
            (std::mem::take(&mut state.tasks), state.failed)
        };
        let mut failure =
            previously_failed.then(|| RuleSetLoadError::new(RuleSetLoadErrorKind::Task));
        for task in tasks {
            if task.await.is_err() && failure.is_none() {
                failure = Some(RuleSetLoadError::new(RuleSetLoadErrorKind::Task));
            }
        }
        failure.map_or(Ok(()), Err)
    }
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

    async fn load_with_capabilities(
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

/// All resources compiled into one immutable initial snapshot. No snapshot is
/// exposed until every declared resource has completed successfully.
pub struct RuleSetSnapshotMaterialization {
    snapshot: RuleEngineSnapshot,
    rule_set_ids: Box<[RuleSetId]>,
    dispositions: Box<[RuleSetLoadDisposition]>,
    degraded_failures: Box<[Option<RuleSetLoadErrorKind>]>,
}

pub type RuleSetSnapshotParts = (
    RuleEngineSnapshot,
    Box<[RuleSetId]>,
    Box<[RuleSetLoadDisposition]>,
    Box<[Option<RuleSetLoadErrorKind>]>,
);

impl RuleSetSnapshotMaterialization {
    pub fn snapshot(&self) -> &RuleEngineSnapshot {
        &self.snapshot
    }

    pub fn rule_set_ids(&self) -> &[RuleSetId] {
        &self.rule_set_ids
    }

    pub fn dispositions(&self) -> &[RuleSetLoadDisposition] {
        &self.dispositions
    }

    pub fn degraded_failures(&self) -> &[Option<RuleSetLoadErrorKind>] {
        &self.degraded_failures
    }

    pub fn into_parts(self) -> RuleSetSnapshotParts {
        (
            self.snapshot,
            self.rule_set_ids,
            self.dispositions,
            self.degraded_failures,
        )
    }
}

impl fmt::Debug for RuleSetSnapshotMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetSnapshotMaterialization")
            .field("generation", &self.snapshot.generation())
            .field("rule_set_count", &self.rule_set_ids.len())
            .finish()
    }
}

/// Materializes all configured resources and then builds exactly one snapshot.
/// Cache writes may complete independently, but a partially built matcher view
/// can never become observable.
pub async fn materialize_rule_set_snapshot<D>(
    loader: &RuleSetLoader<D>,
    sources: &[RuleSetRemoteSource],
    generation: u64,
) -> Result<RuleSetSnapshotMaterialization, RuleSetLoadError>
where
    D: RuleSetDownloader,
{
    let mut loaded = Vec::new();
    loaded
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    for source in sources {
        loaded.push(loader.load(source, generation).await?);
    }

    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    let mut rule_set_ids = Vec::new();
    let mut dispositions = Vec::new();
    let mut degraded_failures = Vec::new();
    rule_set_ids
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    dispositions
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    degraded_failures
        .try_reserve_exact(sources.len())
        .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
    for (source, loaded) in sources.iter().zip(loaded) {
        dispositions.push(loaded.disposition);
        degraded_failures.push(loaded.degraded_failure);
        let match_set = builder
            .add_shared_match_set(loaded.match_set)
            .map_err(rule_compile_load_error)?;
        let rule_set = builder
            .add_rule_set(source.cache_name.as_str(), match_set)
            .map_err(rule_compile_load_error)?;
        rule_set_ids.push(rule_set);
    }
    let snapshot = builder.build().map_err(rule_compile_load_error)?;
    Ok(RuleSetSnapshotMaterialization {
        snapshot,
        rule_set_ids: rule_set_ids.into_boxed_slice(),
        dispositions: dispositions.into_boxed_slice(),
        degraded_failures: degraded_failures.into_boxed_slice(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetRefreshOutcome {
    Updated {
        previous_generation: u64,
        generation: u64,
    },
    NotModified,
    RetainedCache(RuleSetLoadDisposition),
    Failed(RuleSetLoadErrorKind),
}

/// Identity-free observer seam for refresh telemetry.
pub trait RuleSetRefreshObserver: Send + Sync {
    fn record(&self, outcome: RuleSetRefreshOutcome);
}

impl<F> RuleSetRefreshObserver for F
where
    F: Fn(RuleSetRefreshOutcome) + Send + Sync,
{
    fn record(&self, outcome: RuleSetRefreshOutcome) {
        self(outcome);
    }
}

#[derive(Debug)]
struct NoopRuleSetRefreshObserver;

impl RuleSetRefreshObserver for NoopRuleSetRefreshObserver {
    fn record(&self, _outcome: RuleSetRefreshOutcome) {}
}

/// Single-owner refresh loop. Successful resources are compiled before a full
/// compatible snapshot is published; every failure leaves the current Arc
/// untouched.
pub struct RuleSetRefreshService<D> {
    loader: Arc<RuleSetLoader<D>>,
    registry: Arc<RuleEngineRegistry>,
    entries: Box<[RefreshEntry]>,
    observer: Arc<dyn RuleSetRefreshObserver>,
}

#[derive(Clone)]
struct RefreshEntry {
    source: RuleSetRemoteSource,
    rule_set: RuleSetId,
}

impl<D> RuleSetRefreshService<D>
where
    D: RuleSetDownloader,
{
    pub fn new(
        loader: Arc<RuleSetLoader<D>>,
        registry: Arc<RuleEngineRegistry>,
        sources: Vec<RuleSetRemoteSource>,
        rule_set_ids: Vec<RuleSetId>,
    ) -> Result<Self, RuleSetLoadError> {
        if sources.len() != rule_set_ids.len() {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::RegistryCompile));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(sources.len())
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
        entries.extend(
            sources
                .into_iter()
                .zip(rule_set_ids)
                .map(|(source, rule_set)| RefreshEntry { source, rule_set }),
        );
        Ok(Self {
            loader,
            registry,
            entries: entries.into_boxed_slice(),
            observer: Arc::new(NoopRuleSetRefreshObserver),
        })
    }

    pub fn with_observer(mut self, observer: Arc<dyn RuleSetRefreshObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Joins cache/compiler work even when its refresh future was cancelled.
    pub async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.loader.shutdown().await
    }

    pub fn registry(&self) -> &Arc<RuleEngineRegistry> {
        &self.registry
    }

    pub async fn refresh_once(&self, index: usize) -> RuleSetRefreshOutcome {
        let Some(entry) = self.entries.get(index) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let current = self.registry.snapshot();
        let Some(descriptor) = current.rule_set(entry.rule_set) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let expected_capabilities = descriptor.capabilities();
        let Some(generation) = current.generation().checked_add(1) else {
            return RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryCompile);
        };
        let loaded = match self
            .loader
            .load_with_capabilities(&entry.source, generation, Some(expected_capabilities))
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => return RuleSetRefreshOutcome::Failed(error.kind()),
        };
        match loaded.disposition {
            RuleSetLoadDisposition::NotModified => return RuleSetRefreshOutcome::NotModified,
            RuleSetLoadDisposition::OfflineCache | RuleSetLoadDisposition::StaleCache => {
                return RuleSetRefreshOutcome::RetainedCache(loaded.disposition);
            }
            RuleSetLoadDisposition::Downloaded => {}
        }

        let mut builder = match current.builder_for_generation(generation) {
            Ok(builder) => builder,
            Err(error) => {
                return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
            }
        };
        if let Err(error) = builder.replace_shared_rule_set(entry.rule_set, loaded.match_set) {
            return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
        }
        let next = match builder.build() {
            Ok(next) => next,
            Err(error) => {
                return RuleSetRefreshOutcome::Failed(rule_compile_load_error_kind(error));
            }
        };
        match self.registry.publish(next) {
            Ok(previous) => RuleSetRefreshOutcome::Updated {
                previous_generation: previous.generation(),
                generation,
            },
            Err(_) => RuleSetRefreshOutcome::Failed(RuleSetLoadErrorKind::RegistryPublish),
        }
    }

    /// Runs until process quiescing. Dropping an in-flight download future
    /// closes its body and removes its `NamedTempFile`; all completed refreshes
    /// were already atomically published.
    pub async fn run(
        &self,
        mut cancellation: crate::ProcessCancellation,
    ) -> Result<(), RuleSetLoadError> {
        let mut due = Vec::new();
        due.try_reserve_exact(self.entries.len())
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Allocation))?;
        let now = Instant::now();
        due.extend(
            self.entries
                .iter()
                .map(|entry| entry.source.update_interval.map(|interval| now + interval)),
        );

        loop {
            let Some(next_due) = due.iter().flatten().copied().min() else {
                cancellation.cancelled().await;
                return Ok(());
            };
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep_until(next_due) => {}
            }
            let now = Instant::now();
            for (index, deadline) in due.iter_mut().enumerate() {
                if deadline.is_some_and(|deadline| deadline <= now) {
                    // Refresh failures are degraded resource state, not a
                    // process-root failure. The old registry remains live.
                    let refresh = self.refresh_once(index);
                    tokio::pin!(refresh);
                    let outcome = tokio::select! {
                        () = cancellation.cancelled() => return Ok(()),
                        outcome = &mut refresh => outcome,
                    };
                    self.observer.record(outcome);
                    *deadline = self.entries[index]
                        .source
                        .update_interval
                        .map(|interval| Instant::now() + interval);
                }
            }
        }
    }
}

impl<D> fmt::Debug for RuleSetRefreshService<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSetRefreshService")
            .field("entries", &self.entries.len())
            .field("generation", &self.registry.generation())
            .finish_non_exhaustive()
    }
}

/// Process-root adapter that makes the refresh loop participate in the same
/// quiesce/force/join lifecycle as listeners and DNS owners.
pub struct PreparedRuleSetRefreshRoot<D> {
    service: Arc<RuleSetRefreshService<D>>,
}

impl<D> PreparedRuleSetRefreshRoot<D> {
    pub const fn new(service: Arc<RuleSetRefreshService<D>>) -> Self {
        Self { service }
    }
}

impl<D> crate::PreparedProcessRoot<RuleSetLoadError> for PreparedRuleSetRefreshRoot<D>
where
    D: RuleSetDownloader + 'static,
{
    fn activate(&mut self) -> Result<(), RuleSetLoadError> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        cancellation: crate::ProcessCancellation,
    ) -> crate::ProcessFuture<Result<(), RuleSetLoadError>> {
        Box::pin(async move {
            let result = self.service.run(cancellation).await;
            result.and(self.service.shutdown().await)
        })
    }

    fn rollback(self: Box<Self>) -> crate::ProcessFuture<Result<(), RuleSetLoadError>> {
        Box::pin(async move { self.service.shutdown().await })
    }
}

impl<D> fmt::Debug for PreparedRuleSetRefreshRoot<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedRuleSetRefreshRoot([redacted])")
    }
}

#[cfg(test)]
mod blocking_owner_tests {
    use std::sync::{Arc, Barrier};

    use super::BlockingTaskOwner;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_leaves_blocking_work_owned_until_shutdown_joins_it() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let waiter = tokio::spawn({
            let owner = Arc::clone(&owner);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                owner
                    .run(move || {
                        entered.wait();
                        release.wait();
                    })
                    .await
            }
        });
        entered.wait();
        waiter.abort();
        assert!(waiter.await.is_err());

        let shutdown = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        release.wait();
        shutdown
            .await
            .expect("shutdown task")
            .expect("blocking task joined");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_remaining_work_after_an_earlier_worker_panics() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let panic_entered = Arc::new(Barrier::new(2));
        let release_panic = Arc::new(Barrier::new(2));
        let panicking = tokio::spawn({
            let owner = Arc::clone(&owner);
            let panic_entered = Arc::clone(&panic_entered);
            let release_panic = Arc::clone(&release_panic);
            async move {
                owner
                    .run(move || {
                        panic_entered.wait();
                        release_panic.wait();
                        panic!("controlled blocking worker failure");
                    })
                    .await
            }
        });
        panic_entered.wait();

        let blocked_entered = Arc::new(Barrier::new(2));
        let release_blocked = Arc::new(Barrier::new(2));
        let blocked = tokio::spawn({
            let owner = Arc::clone(&owner);
            let blocked_entered = Arc::clone(&blocked_entered);
            let release_blocked = Arc::clone(&release_blocked);
            async move {
                owner
                    .run(move || {
                        blocked_entered.wait();
                        release_blocked.wait();
                    })
                    .await
            }
        });
        blocked_entered.wait();
        release_panic.wait();
        assert!(panicking.await.expect("panicking waiter task").is_err());
        blocked.abort();
        assert!(blocked.await.is_err());

        let mut shutdown = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned before the remaining blocking worker completed"
        );
        release_blocked.wait();
        assert!(
            shutdown.await.expect("shutdown task").is_err(),
            "the first worker failure must remain observable after all workers join"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaping_a_finished_panicked_worker_preserves_the_shutdown_failure() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let waiter = tokio::spawn({
            let owner = Arc::clone(&owner);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                owner
                    .run(move || {
                        entered.wait();
                        release.wait();
                        panic!("controlled reaped worker failure");
                    })
                    .await
            }
        });
        entered.wait();
        waiter.abort();
        assert!(waiter.await.is_err());
        release.wait();
        loop {
            let finished = owner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .tasks
                .first()
                .is_some_and(tokio::task::JoinHandle::is_finished);
            if finished {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(owner.run(|| 7_u8).await.expect("later worker"), 7);
        assert!(
            owner.shutdown().await.is_err(),
            "reaping a finished JoinHandle must not erase its panic"
        );
    }
}

#[cfg(test)]
mod rule_compile_error_tests {
    use super::*;

    #[test]
    fn allocation_and_index_overflow_keep_the_allocation_category() {
        for error in [
            RuleCompileError::Allocation,
            RuleCompileError::IndexOverflow,
        ] {
            assert_eq!(
                rule_compile_load_error_kind(error),
                RuleSetLoadErrorKind::Allocation
            );
        }
    }

    #[test]
    fn remaining_compiler_failures_are_registry_compile_failures() {
        for error in [
            RuleCompileError::EmptyMatcher,
            RuleCompileError::EmptyField,
            RuleCompileError::DuplicateField,
            RuleCompileError::DuplicateValue,
            RuleCompileError::ConflictingFields,
            RuleCompileError::InvalidDomain,
            RuleCompileError::NonCanonicalCidr,
            RuleCompileError::InvalidId,
            RuleCompileError::InvalidTag,
            RuleCompileError::DuplicateRuleSet,
            RuleCompileError::InvalidGeneration,
            RuleCompileError::Internal,
        ] {
            assert_eq!(
                rule_compile_load_error_kind(error),
                RuleSetLoadErrorKind::RegistryCompile
            );
        }
    }
}

fn stale_or_error(
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
struct CachedRuleSet {
    loaded: LoadedRuleSet,
    etag: Option<Box<str>>,
    last_modified: Option<Box<str>>,
}

#[derive(Debug)]
struct CompiledFile {
    match_set: Arc<CompiledMatchSet>,
    capabilities: MatchSetCapabilities,
    srs_version: u8,
}

fn compile_file(path: &Path) -> Result<CompiledFile, RuleSetLoadError> {
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

fn read_cache_sync(
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

fn commit_cache(
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
struct CacheMetadata {
    schema: u8,
    url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    downloaded_unix_seconds: u64,
    sha256: String,
    srs_version: u8,
    capabilities: SerializableCapabilities,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializableCapabilities {
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
