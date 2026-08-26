use std::fmt;
use std::sync::Arc;

use ferrum2_rule::{
    CompiledRuleProgram, DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    RuleCompileError, RuleEngineRegistry, RuleEngineSnapshot, RuleProgramMode,
};

use super::evaluation::{
    DnsPolicyEvaluation, DnsPolicyEvaluationState, DnsPolicyEvaluationWithScratch, DnsPolicyScratch,
};
use super::model::{
    DnsPolicyAction, DnsPolicyCompileError, DnsPolicyMatcher, DnsPolicyQuery, DnsPolicyRoute,
    DnsPolicyRule,
};
use crate::policy_candidate::DnsQueryCandidateIndex;
use crate::{DnsServerId, DnsStrategy};

/// Immutable ordered DNS policy with one mandatory final upstream.
pub struct DnsPolicyProgram {
    pub(super) compiled: CompiledRuleProgram<DnsPolicyRule, DnsQueryCandidateIndex>,
    pub(super) response_rules: usize,
    pub(super) final_route: DnsPolicyRoute,
}

impl DnsPolicyProgram {
    /// Consumes one runtime-neutral, snapshot-validated blueprint and builds
    /// the sole DNS execution program before any listener starts.
    pub fn try_from_blueprint(
        blueprint: DnsPolicyBlueprint,
        validation_snapshot: &RuleEngineSnapshot,
    ) -> Result<Self, DnsPolicyCompileError> {
        let (descriptors, final_route) = blueprint.into_parts();
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(descriptors.len())
            .map_err(|_| DnsPolicyCompileError::Allocation)?;
        for descriptor in descriptors {
            let (matcher, action) = descriptor.into_parts();
            let matcher = DnsPolicyMatcher::try_from_descriptor(matcher)?;
            let action = match action {
                DnsPolicyActionDescriptor::Route(route) => {
                    DnsPolicyAction::Route(DnsPolicyRoute::new(
                        DnsServerId::new(route.server()),
                        dns_strategy_from_blueprint(route.strategy()),
                    ))
                }
                DnsPolicyActionDescriptor::Reject => DnsPolicyAction::Reject,
            };
            rules.push(DnsPolicyRule::new(matcher, action));
        }
        Self::try_new(
            rules,
            DnsPolicyRoute::new(
                DnsServerId::new(final_route.server()),
                dns_strategy_from_blueprint(final_route.strategy()),
            ),
            validation_snapshot,
        )
    }

    pub fn try_new(
        rules: Vec<DnsPolicyRule>,
        final_route: DnsPolicyRoute,
        validation_snapshot: &RuleEngineSnapshot,
    ) -> Result<Self, DnsPolicyCompileError> {
        let mut response_rules = 0_usize;
        for rule in &rules {
            let mut response_dependent = false;
            for rule_set in rule.matcher.rule_sets.iter().copied() {
                let descriptor = validation_snapshot
                    .rule_set(rule_set)
                    .ok_or(DnsPolicyCompileError::UnknownRuleSet)?;
                if rule.action == DnsPolicyAction::Reject && descriptor.capabilities().ip_cidr {
                    return Err(DnsPolicyCompileError::ResponseDependentReject);
                }
                response_dependent |= descriptor.capabilities().ip_cidr;
            }
            response_rules = response_rules.saturating_add(usize::from(response_dependent));
        }
        let compiled = CompiledRuleProgram::try_new(rules, DnsQueryCandidateIndex::try_build)
            .map_err(map_candidate_compile_error)?;
        Ok(Self {
            compiled,
            response_rules,
            final_route,
        })
    }

    pub const fn len(&self) -> usize {
        self.compiled.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// Returns the actual query-stage compilation strategy.
    pub const fn mode(&self) -> RuleProgramMode {
        self.compiled.mode()
    }

    /// Creates one caller-owned allocation-free query workspace.
    pub const fn evaluation_scratch(&self) -> DnsPolicyScratch {
        DnsPolicyScratch::new()
    }

    /// Returns rows which can evaluate address records from an upstream response.
    pub const fn response_rule_count(&self) -> usize {
        self.response_rules
    }

    /// Captures exactly one registry generation for the complete continuation.
    pub fn evaluate<'program>(
        &'program self,
        query: DnsPolicyQuery,
        registry: &RuleEngineRegistry,
    ) -> DnsPolicyEvaluation<'program> {
        self.evaluate_with_snapshot(query, registry.snapshot())
    }

    /// Starts an evaluation with one already captured immutable snapshot.
    pub fn evaluate_with_snapshot<'program>(
        &'program self,
        query: DnsPolicyQuery,
        snapshot: Arc<RuleEngineSnapshot>,
    ) -> DnsPolicyEvaluation<'program> {
        DnsPolicyEvaluation {
            program: self,
            state: DnsPolicyEvaluationState::new(query, snapshot),
            scratch: self.evaluation_scratch(),
        }
    }

    /// Captures one registry generation and evaluates with caller-owned scratch.
    pub fn evaluate_with_registry_and_scratch<'program, 'scratch>(
        &'program self,
        query: DnsPolicyQuery,
        registry: &RuleEngineRegistry,
        scratch: &'scratch mut DnsPolicyScratch,
    ) -> DnsPolicyEvaluationWithScratch<'program, 'scratch> {
        self.evaluate_with_snapshot_and_scratch(query, registry.snapshot(), scratch)
    }

    /// Evaluates one captured generation with caller-owned reusable scratch.
    pub fn evaluate_with_snapshot_and_scratch<'program, 'scratch>(
        &'program self,
        query: DnsPolicyQuery,
        snapshot: Arc<RuleEngineSnapshot>,
        scratch: &'scratch mut DnsPolicyScratch,
    ) -> DnsPolicyEvaluationWithScratch<'program, 'scratch> {
        scratch.reset();
        DnsPolicyEvaluationWithScratch {
            program: self,
            state: DnsPolicyEvaluationState::new(query, snapshot),
            scratch,
        }
    }
}

const fn dns_strategy_from_blueprint(strategy: DnsPolicyAddressStrategy) -> DnsStrategy {
    match strategy {
        DnsPolicyAddressStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        DnsPolicyAddressStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        DnsPolicyAddressStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        DnsPolicyAddressStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}

const fn map_candidate_compile_error(error: RuleCompileError) -> DnsPolicyCompileError {
    match error {
        RuleCompileError::Allocation => DnsPolicyCompileError::Allocation,
        RuleCompileError::IndexOverflow => DnsPolicyCompileError::IndexOverflow,
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet
        | RuleCompileError::InvalidId
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => DnsPolicyCompileError::Internal,
    }
}

impl fmt::Debug for DnsPolicyProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyProgram([redacted])")
    }
}
