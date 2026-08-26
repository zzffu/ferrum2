mod evaluation;
mod index;
mod matcher;

use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;

use crate::{
    CompiledRuleProgram, RuleCompileError, RuleEngineRegistry, RuleEngineSnapshot, RuleProgramMode,
};

pub use evaluation::{RouteProgramAction, RouteProgramEvaluationWithScratch};
pub use index::RuleEvaluationScratch;
use index::{ConstraintIndex, build_constraints, words_for};
pub use matcher::{
    PortRange, RouteMatchField, RouteMatchObservation, RouteMatchSource, RouteMatchType,
    RouteMatcher, RouteMetadata,
};

/// Generic continuation or terminal behavior attached to one matched rule.
pub enum RouteRuleAction<A> {
    Continue(A),
    Terminal(A),
}

/// One ordered generic rule.
pub struct OrderedRouteRule<P, A> {
    pub(in crate::program) matcher: RouteMatcher<P>,
    pub(in crate::program) action: RouteRuleAction<A>,
}

impl<P, A> OrderedRouteRule<P, A> {
    pub const fn new(matcher: RouteMatcher<P>, action: RouteRuleAction<A>) -> Self {
        Self { matcher, action }
    }
}

/// One reusable ordered program with a mandatory final action.
pub struct OrderedRouteProgram<P, A> {
    pub(in crate::program) compiled:
        CompiledRuleProgram<OrderedRouteRule<P, A>, ConstraintIndex<P>>,
    pub(in crate::program) final_action: A,
}

impl<P: Clone + Ord, A> OrderedRouteProgram<P, A> {
    pub fn try_new(
        rules: Vec<OrderedRouteRule<P, A>>,
        final_action: A,
    ) -> Result<Self, RuleCompileError> {
        let mode = RuleProgramMode::for_rule_count(rules.len());
        Self::try_new_in_mode(rules, final_action, mode)
    }

    fn try_new_in_mode(
        rules: Vec<OrderedRouteRule<P, A>>,
        final_action: A,
        mode: RuleProgramMode,
    ) -> Result<Self, RuleCompileError> {
        let compiled = CompiledRuleProgram::try_new_in_mode(rules, mode, build_constraints)?;
        Ok(Self {
            compiled,
            final_action,
        })
    }

    pub const fn mode(&self) -> RuleProgramMode {
        self.compiled.mode()
    }

    pub const fn len(&self) -> usize {
        self.compiled.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    pub fn evaluation_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        RuleEvaluationScratch::try_for_program(self)
    }

    /// Starts an allocation-free evaluation using caller-owned reusable scratch
    /// obtained from [`Self::evaluation_scratch`].
    pub fn evaluate_with_scratch<'program, 'target, 'scratch>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
        scratch: &'scratch mut RuleEvaluationScratch,
    ) -> RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, P, A> {
        self.evaluate_captured_with_scratch(inbound, network, original, None, scratch)
    }

    /// Uses scratch obtained from [`Self::evaluation_scratch`] and one already
    /// captured immutable snapshot without allocating.
    pub fn evaluate_with_snapshot_and_scratch<'program, 'target, 'scratch>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
        snapshot: Arc<RuleEngineSnapshot>,
        scratch: &'scratch mut RuleEvaluationScratch,
    ) -> RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, P, A> {
        self.evaluate_captured_with_scratch(inbound, network, original, Some(snapshot), scratch)
    }

    /// Captures the registry once and evaluates without allocation using scratch
    /// obtained from [`Self::evaluation_scratch`].
    pub fn evaluate_with_registry_and_scratch<'program, 'target, 'scratch>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
        registry: &RuleEngineRegistry,
        scratch: &'scratch mut RuleEvaluationScratch,
    ) -> RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, P, A> {
        self.evaluate_captured_with_scratch(
            inbound,
            network,
            original,
            Some(registry.snapshot()),
            scratch,
        )
    }

    fn evaluate_captured_with_scratch<'program, 'target, 'scratch>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
        snapshot: Option<Arc<RuleEngineSnapshot>>,
        scratch: &'scratch mut RuleEvaluationScratch,
    ) -> RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, P, A> {
        if self.compiled.mode() == RuleProgramMode::Indexed {
            scratch.assert_words(words_for(self.compiled.len()));
        }
        RouteProgramEvaluationWithScratch {
            program: self,
            inbound,
            network,
            original,
            cursor: 0,
            finished: false,
            snapshot,
            scratch,
            observe_matches: false,
            last_match: RouteMatchObservation::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ferrum2_core::TargetAddr;

    use super::*;

    fn forced_program(mode: RuleProgramMode) -> OrderedRouteProgram<u16, usize> {
        let mut rules = Vec::new();
        rules.push(OrderedRouteRule::new(
            RouteMatcher::try_new(vec![
                RouteMatchField::Inbound(vec![7]),
                RouteMatchField::Network(vec![Network::Tcp]),
            ])
            .unwrap(),
            RouteRuleAction::Continue(10_000),
        ));
        for index in 0..128 {
            rules.push(OrderedRouteRule::new(
                RouteMatcher::try_new(vec![
                    RouteMatchField::Inbound(vec![index % 17]),
                    RouteMatchField::Network(vec![if index % 2 == 0 {
                        Network::Tcp
                    } else {
                        Network::Udp
                    }]),
                    RouteMatchField::Protocol(vec![(index % 5) as u16]),
                ])
                .unwrap(),
                RouteRuleAction::Terminal(index),
            ));
        }
        OrderedRouteProgram::try_new_in_mode(rules, usize::MAX, mode).unwrap()
    }

    fn actions(
        program: &OrderedRouteProgram<u16, usize>,
        inbound: usize,
        network: Network,
        protocol: u16,
    ) -> Vec<(u8, usize)> {
        let target = TargetAddr::domain("mode-equivalence.invalid", 443).unwrap();
        let mut scratch = program.evaluation_scratch().unwrap();
        let mut evaluation = program.evaluate_with_scratch(inbound, network, &target, &mut scratch);
        let mut actions = Vec::new();
        loop {
            match evaluation.next(RouteMetadata::new(Some(protocol), None)) {
                Some(RouteProgramAction::Continue(action)) => actions.push((0, *action)),
                Some(RouteProgramAction::Terminal(action)) => {
                    actions.push((1, *action));
                    break;
                }
                Some(RouteProgramAction::Final(action)) => {
                    actions.push((2, *action));
                    break;
                }
                None => break,
            }
        }
        actions
    }

    #[test]
    fn forced_small_linear_and_indexed_modes_are_exactly_equivalent() {
        let linear = forced_program(RuleProgramMode::SmallLinear);
        let indexed = forced_program(RuleProgramMode::Indexed);
        for inbound in [0, 1, 7, 16, 99] {
            for network in [Network::Tcp, Network::Udp] {
                for protocol in 0..7 {
                    assert_eq!(
                        actions(&linear, inbound, network, protocol),
                        actions(&indexed, inbound, network, protocol),
                        "{inbound}/{network:?}/{protocol}"
                    );
                }
            }
        }
    }
}
