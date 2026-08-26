#![forbid(unsafe_code)]

mod candidate;
mod compiled_program;
mod dns_blueprint;
mod error;
mod match_set;
mod program;
mod registry;
pub mod srs;

pub use candidate::{
    MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories, PortRangeCandidateIndex,
    PortRangeCandidateIndexBuilder, SparseValueIndex, SparseValueIndexBuilder,
};
pub use compiled_program::{CompiledRuleProgram, RuleProgramMode};
pub use dns_blueprint::{
    DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    DnsPolicyBlueprintError, DnsPolicyMatcherDescriptor, DnsPolicyMatcherDescriptorParts,
    DnsPolicyRouteDescriptor, DnsPolicyRuleDescriptor,
};
pub use error::RuleCompileError;
pub use match_set::{
    CompiledMatchSet, DomainMatchType, MatchSetBuilder, MatchSetCapabilities, MatchSetEntryCounts,
};
pub use program::{
    OrderedRouteProgram, OrderedRouteRule, PortRange, RouteMatchField, RouteMatchObservation,
    RouteMatchSource, RouteMatchType, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteProgramEvaluationWithScratch, RouteRuleAction, RuleEvaluationScratch,
};
pub use registry::{
    MatchSetId, RegistryPublishError, RuleEngineRegistry, RuleEngineSnapshot,
    RuleEngineSnapshotBuilder, RuleSetDescriptor, RuleSetId,
};

pub use ferrum2_core::GenerationChange;
pub use ferrum2_core::route::{EgressPlan, EgressPlanHandle, EgressPlanSnapshot, Network};
pub use ferrum2_core::selector::{
    SelectorCompileError, SelectorControl, SelectorDefinition, SelectorError, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};

/// Largest ordered rule program compiled in linear mode.
pub const SMALL_LINEAR_RULE_LIMIT: usize = 64;
