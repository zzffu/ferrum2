#![forbid(unsafe_code)]

mod cache;
mod download;
mod error;
mod https;
mod loader;
mod refresh;
mod snapshot;
mod source;

pub use download::{
    BoxedRuleSetBody, RuleSetBody, RuleSetDownloadError, RuleSetDownloadErrorKind,
    RuleSetDownloadFuture, RuleSetDownloadRequest, RuleSetDownloadResponse, RuleSetDownloadStatus,
    RuleSetDownloader,
};
pub use error::{RuleSetLoadError, RuleSetLoadErrorKind};
pub use https::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, RuleSetDialTargets, RuleSetDialer,
    RuleSetHostResolveObserver, RuleSetHostResolveOutcome, RuleSetHostResolver,
    RuleSetHostResolverKind, SystemRuleSetDialer, SystemRuleSetHostResolver,
};
pub use loader::{LoadedRuleSet, RuleSetLoadDisposition, RuleSetLoader};
pub use refresh::{RuleSetRefreshObserver, RuleSetRefreshOutcome, RuleSetRefreshService};
pub use snapshot::{MaterializedRuleSets, materialize_rule_sets};
pub use source::{
    RuleSetCacheName, RuleSetDownloadMode, RuleSetDownloadResolver, RuleSetLoaderConfig,
    RuleSetRemoteSource,
};

const MAX_RESOLVED_CANDIDATES: usize = 16;
