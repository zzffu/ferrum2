mod compiler;
mod evaluation;
mod model;

pub use compiler::DnsPolicyProgram;
pub use evaluation::{
    DnsPolicyEvaluation, DnsPolicyEvaluationWithScratch, DnsPolicyScratch, DnsPolicyStateError,
    DnsPolicyStep,
};
pub use model::{
    DnsPolicyAction, DnsPolicyCompileError, DnsPolicyMatchResult, DnsPolicyMatchSource,
    DnsPolicyMatchType, DnsPolicyMatcher, DnsPolicyObservation, DnsPolicyObserver, DnsPolicyQuery,
    DnsPolicyRoute, DnsPolicyRule, DnsPolicyStage, DnsPortRange,
};

pub(crate) use evaluation::is_address_qtype;
