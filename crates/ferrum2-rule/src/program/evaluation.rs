use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;

use crate::RuleEngineSnapshot;

use super::{
    OrderedRouteProgram, RouteMatchObservation, RouteMetadata, RouteRuleAction,
    RuleEvaluationScratch,
};

/// Observable result of advancing an ordered route program.
#[derive(Eq, PartialEq)]
pub enum RouteProgramAction<'a, A> {
    Continue(&'a A),
    Terminal(&'a A),
    Final(&'a A),
}

impl<A> std::fmt::Debug for RouteProgramAction<'_, A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Continue(_) => "RouteProgramAction::Continue([redacted])",
            Self::Terminal(_) => "RouteProgramAction::Terminal([redacted])",
            Self::Final(_) => "RouteProgramAction::Final([redacted])",
        })
    }
}

/// Evaluation borrowing caller-owned reusable bitmap scratch.
pub struct RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, P, A> {
    pub(in crate::program) program: &'program OrderedRouteProgram<P, A>,
    pub(in crate::program) inbound: usize,
    pub(in crate::program) network: Network,
    pub(in crate::program) original: &'target TargetAddr,
    pub(in crate::program) cursor: usize,
    pub(in crate::program) finished: bool,
    pub(in crate::program) snapshot: Option<Arc<RuleEngineSnapshot>>,
    pub(in crate::program) scratch: &'scratch mut RuleEvaluationScratch,
    pub(in crate::program) observe_matches: bool,
    pub(in crate::program) last_match: RouteMatchObservation,
}

impl<'program, P: Ord, A> RouteProgramEvaluationWithScratch<'program, '_, '_, P, A> {
    /// Returns the single captured generation, or `None` for a registry-free program.
    pub fn snapshot_generation(&self) -> Option<u64> {
        self.snapshot.as_ref().map(|snapshot| snapshot.generation())
    }

    /// Returns the sparse posting/rule visits performed by the most recent step.
    pub const fn candidate_visits(&self) -> usize {
        self.scratch.candidate_visits()
    }

    /// Returns the categories evaluated by the rule selected by the latest step.
    pub const fn last_match_observation(&self) -> RouteMatchObservation {
        self.last_match
    }

    /// Enables allocation-free category telemetry for subsequent steps.
    pub fn enable_match_observation(&mut self) {
        self.observe_matches = true;
    }

    pub fn next(
        &mut self,
        metadata: RouteMetadata<'_, P>,
    ) -> Option<RouteProgramAction<'program, A>> {
        next_action(
            self.program,
            self.inbound,
            self.network,
            self.original,
            &mut self.cursor,
            &mut self.finished,
            &metadata,
            self.snapshot.as_deref(),
            self.scratch,
            self.observe_matches,
            &mut self.last_match,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn next_action<'program, P: Ord, A>(
    program: &'program OrderedRouteProgram<P, A>,
    inbound: usize,
    network: Network,
    original: &TargetAddr,
    cursor: &mut usize,
    finished: &mut bool,
    metadata: &RouteMetadata<'_, P>,
    snapshot: Option<&RuleEngineSnapshot>,
    scratch: &mut RuleEvaluationScratch,
    observe_matches: bool,
    last_match: &mut RouteMatchObservation,
) -> Option<RouteProgramAction<'program, A>> {
    if *finished {
        return None;
    }
    if let Some(index) = program.find_next(
        *cursor, inbound, network, original, metadata, snapshot, scratch,
    ) {
        *cursor = index + 1;
        *last_match = if observe_matches {
            program.compiled.rules()[index]
                .matcher
                .observation(original, metadata, snapshot)
        } else {
            RouteMatchObservation::default()
        };
        return match &program.compiled.rules()[index].action {
            RouteRuleAction::Continue(action) => Some(RouteProgramAction::Continue(action)),
            RouteRuleAction::Terminal(action) => {
                *finished = true;
                Some(RouteProgramAction::Terminal(action))
            }
        };
    }
    *finished = true;
    *last_match = RouteMatchObservation::default();
    Some(RouteProgramAction::Final(&program.final_action))
}
