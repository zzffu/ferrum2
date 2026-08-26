use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ferrum2_core::route::EgressPlanSnapshot;
use tokio::io::AsyncRead;
use tokio::time::Instant;

use crate::source::RuleSetDownloadMode;

pub trait RuleSetBody: AsyncRead + Send + Unpin {}

impl<T> RuleSetBody for T where T: AsyncRead + Send + Unpin {}

/// Type-erased streaming response body.
pub type BoxedRuleSetBody = Box<dyn RuleSetBody>;

/// One asynchronous explicit-download operation.
pub type RuleSetDownloadFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RuleSetDownloadResponse, RuleSetDownloadError>> + Send + 'a>,
>;

/// Request delivered to an injected downloader that is forbidden from choosing
/// a resolver or detour on its own.
#[derive(Clone)]
pub struct RuleSetDownloadRequest {
    pub(crate) url: Box<str>,
    pub(crate) mode: RuleSetDownloadMode,
    pub(crate) detour: Option<EgressPlanSnapshot>,
    pub(crate) if_none_match: Option<Box<str>>,
    pub(crate) if_modified_since: Option<Box<str>>,
    pub(crate) deadline: Instant,
    pub(crate) max_redirects: u8,
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
    pub(crate) status: RuleSetDownloadStatus,
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
    pub(crate) body: Option<BoxedRuleSetBody>,
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
