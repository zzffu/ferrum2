//! Side-effect-free schema-v2 preparation.

const DEFAULT_RULE_SET_CACHE_DIR: &str = "./rule-set-cache";
const DEFAULT_RULE_SET_DOWNLOAD_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_RULE_SET_MAX_REDIRECTS: u8 = 5;
const PLACEHOLDER_ENDPOINT: &str = "192.0.2.254:9";
const PLACEHOLDER_DOMAIN: &str = "prepared.invalid";
const MAX_RESOLVED_DNS_CANDIDATES: usize = 16;

mod access;
mod finish;
mod model;
mod prepare;
mod resources;

pub use finish::{finish_client_v2, finish_server_v2};
pub use model::{
    DialEndpoint, PreparedClientOutboundDescriptor, PreparedClientOutboundKind, PreparedClientV2,
    PreparedDependencyNode, PreparedDnsAction, PreparedDnsEndpoint, PreparedDnsEndpointMode,
    PreparedDnsRule, PreparedDnsServerDescriptor, PreparedEgressRef,
    PreparedFixedEndpointDescriptor, PreparedFixedEndpointTarget, PreparedRouteRuleSets,
    PreparedRuleSet, PreparedRuleSetDownloadMode, PreparedServerOutboundDescriptor,
    PreparedServerV2, RuleSetLoaderConfig,
};
pub use prepare::{prepare_client, prepare_server};
pub use resources::{
    ClientV2Resources, CompiledRuleSetResource, ResolvedDnsEndpoint, ResolvedOutboundEndpoint,
    ServerV2Resources,
};

pub(crate) use prepare::{
    ClientOutboundDraft, ClientPreparationDraft, PreparedDnsDraft, ServerOutboundDraft,
    ServerPreparationDraft,
};
#[cfg(feature = "fuzzing")]
pub(super) use prepare::{validate_client_source, validate_server_source};
