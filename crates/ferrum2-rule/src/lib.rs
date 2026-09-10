#![forbid(unsafe_code)]

mod candidate;
mod compiled_program;
mod dns_blueprint;
mod error;
mod keyword;
mod match_set;
mod program;
mod registry;
pub mod srs;

/// Refresh scheduling policy shared by configuration and resource loaders.
/// A year is ample for infrequently changing resources while excluding
/// platform-dependent `Instant` overflow from unbounded configuration values.
pub const MAX_RULE_SET_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(365 * 24 * 60 * 60);
pub const MIN_RULE_SET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
pub use candidate::{
    MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories, PortRangeCandidateIndex,
    PortRangeCandidateIndexBuilder, SparseValueIndex, SparseValueIndexBuilder,
};
pub use compiled_program::{CompiledRuleProgram, RuleProgramMode};
pub use dns_blueprint::{
    DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    DnsPolicyBlueprintError, DnsPolicyMatchMode, DnsPolicyMatcherDescriptor,
    DnsPolicyMatcherDescriptorParts, DnsPolicyRouteDescriptor, DnsPolicyRuleDescriptor,
};
pub use error::RuleCompileError;
pub use match_set::{
    CompiledMatchSet, DomainMatchType, MatchSetBuilder, MatchSetCapabilities, MatchSetEntryCounts,
    MatchSetResourceUsage,
};
pub use program::{
    OrderedRouteProgram, OrderedRouteRule, PortRange, RouteMatchField, RouteMatchObservation,
    RouteMatchSource, RouteMatchType, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteProgramEvaluationWithScratch, RouteRuleAction, RuleEvaluationScratch,
};
pub use registry::{
    MatchSetId, RegistryPublishError, RuleEngineRegistry, RuleEngineSnapshot,
    RuleEngineSnapshotBuilder, RuleEngineSnapshotLimits, RuleSetDescriptor, RuleSetId,
};

pub use ferrum2_core::GenerationChange;
pub use ferrum2_core::route::{EgressPlan, EgressPlanHandle, EgressPlanSnapshot, Network};
pub use ferrum2_core::selector::{
    SelectorCompileError, SelectorControl, SelectorDefinition, SelectorError, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};
