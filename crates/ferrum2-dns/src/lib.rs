#![forbid(unsafe_code)]

//! Bounded tagged DNS composition backed by Hickory.

mod application;
mod cache;
mod endpoint;
mod error;
mod policy;
mod policy_candidate;
mod proxy;
mod resolver;
mod runtime_owner;
mod runtime_provider;

pub use application::{
    ApplicationResolveBackend, ApplicationResolveContext, ApplicationResolveFuture,
    ApplicationResolveObserver, ApplicationResolveOutcome, ApplicationResolveRequest,
    ApplicationResolver, ApplicationResolverMode, DnsStrategy, DnsStrategyParseError,
    MAX_APPLICATION_RESOLVED_CANDIDATES, SystemApplicationResolveBackend,
};
pub use cache::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheError, DnsCacheKey, DnsCacheLookup,
    DnsCacheObserver, DnsCacheQtype, DnsServerId, ResolverGeneration,
};
pub use endpoint::{
    FixedEndpointKind, FixedEndpointLookup, FixedEndpointMaterializeError, FixedEndpointPlanEntry,
    FixedEndpointResolveBackend, FixedEndpointResolveFuture, FixedEndpointResolveRequest,
    FixedEndpointSpec, FixedEndpointSpecError, MaterializedFixedEndpoint, ResolverRef,
    materialize_fixed_endpoints, materialize_fixed_endpoints_with_clock,
    validate_fixed_endpoint_order,
};
pub use error::DnsError;
pub use policy::{
    DnsPolicyAction, DnsPolicyCompileError, DnsPolicyEvaluation, DnsPolicyEvaluationWithScratch,
    DnsPolicyMatchResult, DnsPolicyMatchSource, DnsPolicyMatchType, DnsPolicyMatcher,
    DnsPolicyObservation, DnsPolicyObserver, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute,
    DnsPolicyRule, DnsPolicyScratch, DnsPolicyStage, DnsPolicyStateError, DnsPolicyStep,
    DnsPortRange,
};
pub use proxy::{DnsProxy, DnsProxyListeners, DnsProxySockets, ProxyIngress, ProxyTransport};
pub use resolver::{DnsUpstreamSpec, DnsUpstreamTransport};
pub use runtime_owner::{RuntimeStats, ShutdownReport, TaggedResolver, TaggedResolverOwner};
pub use runtime_provider::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsIoFuture, DnsResourceGuard, DnsTaskRegistrar, DnsTcpIo, SystemDnsEgress,
};
