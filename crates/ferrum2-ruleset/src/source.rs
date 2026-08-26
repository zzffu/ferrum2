use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use ferrum2_core::route::EgressPlanHandle;
use ferrum2_dns::DnsServerId;
use url::{Host, Url};

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};

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

    pub(crate) fn as_str(&self) -> &str {
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
    pub(crate) cache_name: RuleSetCacheName,
    pub(crate) url: Box<str>,
    pub(crate) mode: RuleSetDownloadMode,
    pub(crate) detour: Option<EgressPlanHandle>,
    pub(crate) update_interval: Option<Duration>,
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
    pub(crate) cache_dir: PathBuf,
    pub(crate) download_timeout: Duration,
    pub(crate) max_redirects: u8,
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
