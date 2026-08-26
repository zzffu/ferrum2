use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use ferrum2_core::CanonicalDomain;
use ferrum2_rule::{CompiledMatchSet, RuleEngineSnapshot, RuleProgramMode, RuleSetId};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};

use super::compiler::DnsPolicyProgram;
use super::model::{
    DnsPolicyAction, DnsPolicyMatchSource, DnsPolicyMatchType, DnsPolicyObservation,
    DnsPolicyQuery, DnsPolicyRoute, DnsPolicyStage, observe_domain_match,
};
use crate::policy_candidate::QueryCandidateDriver;
use crate::{DnsServerId, DnsStrategy};

/// One state-machine step for query selection and response continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyStep {
    Reject,
    RouteImmediately {
        server: DnsServerId,
        strategy: DnsStrategy,
    },
    EvaluateResponse {
        server: DnsServerId,
        strategy: DnsStrategy,
    },
    AcceptResponse {
        server: DnsServerId,
        strategy: DnsStrategy,
    },
    Final {
        server: DnsServerId,
        strategy: DnsStrategy,
    },
}

impl DnsPolicyStep {
    /// Returns the upstream metadata for non-reject steps.
    pub const fn route(self) -> Option<DnsPolicyRoute> {
        match self {
            Self::Reject => None,
            Self::RouteImmediately { server, strategy }
            | Self::EvaluateResponse { server, strategy }
            | Self::AcceptResponse { server, strategy }
            | Self::Final { server, strategy } => Some(DnsPolicyRoute::new(server, strategy)),
        }
    }
}

/// Invalid sequencing of the response-driven policy state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyStateError {
    ResponseRequired,
    ResponseNotExpected,
}

impl fmt::Display for DnsPolicyStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResponseRequired => "DNS policy response evaluation is required",
            Self::ResponseNotExpected => "DNS policy response evaluation is not expected",
        })
    }
}

impl Error for DnsPolicyStateError {}

/// Caller-owned allocation-free query-stage workspace.
pub struct DnsPolicyScratch {
    driver: Option<QueryCandidateDriver>,
    candidate_visits: usize,
}

impl DnsPolicyScratch {
    pub(super) const fn new() -> Self {
        Self {
            driver: None,
            candidate_visits: 0,
        }
    }

    /// Returns the number of complete candidate rows checked by the last query step.
    pub const fn candidate_visits(&self) -> usize {
        self.candidate_visits
    }

    pub(super) fn reset(&mut self) {
        self.driver = None;
        self.candidate_visits = 0;
    }
}

pub(super) struct DnsPolicyEvaluationState {
    query: DnsPolicyQuery,
    snapshot: Arc<RuleEngineSnapshot>,
    cursor: usize,
    pending_rule: Option<usize>,
    finished: bool,
    observation: DnsPolicyObservation,
}

impl DnsPolicyEvaluationState {
    pub(super) fn new(query: DnsPolicyQuery, snapshot: Arc<RuleEngineSnapshot>) -> Self {
        Self {
            query,
            snapshot,
            cursor: 0,
            pending_rule: None,
            finished: false,
            observation: DnsPolicyObservation::default(),
        }
    }
}

/// One private-cursor DNS evaluation retaining a single snapshot generation.
pub struct DnsPolicyEvaluation<'program> {
    pub(super) program: &'program DnsPolicyProgram,
    pub(super) state: DnsPolicyEvaluationState,
    pub(super) scratch: DnsPolicyScratch,
}

impl DnsPolicyEvaluation<'_> {
    pub fn snapshot_generation(&self) -> u64 {
        self.state.snapshot.generation()
    }

    pub const fn query(&self) -> &DnsPolicyQuery {
        &self.state.query
    }

    /// Returns the cumulative closed observation for this continuation.
    pub const fn observation(&self) -> DnsPolicyObservation {
        self.state.observation
    }

    /// Returns complete candidate rows checked by the most recent query step.
    pub const fn candidate_visits(&self) -> usize {
        self.scratch.candidate_visits()
    }

    /// Advances query-stage matching until a terminal, response, or final step.
    pub fn next_step(&mut self) -> Result<Option<DnsPolicyStep>, DnsPolicyStateError> {
        next_policy_step(self.program, &mut self.state, &mut self.scratch)
    }

    /// Applies one upstream response to the pending response-dependent row.
    ///
    /// A miss resumes at the following row. If that row asks for the same
    /// server, callers may submit the same cached `(server, qname, qtype)`
    /// response again instead of performing another upstream query.
    pub fn evaluate_response(
        &mut self,
        response: &Message,
    ) -> Result<DnsPolicyStep, DnsPolicyStateError> {
        evaluate_policy_response(self.program, &mut self.state, &mut self.scratch, response)
    }
}

/// DNS continuation borrowing caller-owned reusable query scratch.
pub struct DnsPolicyEvaluationWithScratch<'program, 'scratch> {
    pub(super) program: &'program DnsPolicyProgram,
    pub(super) state: DnsPolicyEvaluationState,
    pub(super) scratch: &'scratch mut DnsPolicyScratch,
}

impl DnsPolicyEvaluationWithScratch<'_, '_> {
    pub fn snapshot_generation(&self) -> u64 {
        self.state.snapshot.generation()
    }

    pub const fn query(&self) -> &DnsPolicyQuery {
        &self.state.query
    }

    pub const fn observation(&self) -> DnsPolicyObservation {
        self.state.observation
    }

    pub const fn candidate_visits(&self) -> usize {
        self.scratch.candidate_visits()
    }

    pub fn next_step(&mut self) -> Result<Option<DnsPolicyStep>, DnsPolicyStateError> {
        next_policy_step(self.program, &mut self.state, self.scratch)
    }

    pub fn evaluate_response(
        &mut self,
        response: &Message,
    ) -> Result<DnsPolicyStep, DnsPolicyStateError> {
        evaluate_policy_response(self.program, &mut self.state, self.scratch, response)
    }
}

impl fmt::Debug for DnsPolicyEvaluation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsPolicyEvaluation")
            .field("snapshot_generation", &self.state.snapshot.generation())
            .field("cursor", &self.state.cursor)
            .field("pending", &self.state.pending_rule.is_some())
            .field("finished", &self.state.finished)
            .finish()
    }
}

impl fmt::Debug for DnsPolicyEvaluationWithScratch<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsPolicyEvaluationWithScratch")
            .field("snapshot_generation", &self.state.snapshot.generation())
            .field("cursor", &self.state.cursor)
            .field("pending", &self.state.pending_rule.is_some())
            .field("finished", &self.state.finished)
            .finish()
    }
}

fn next_policy_step(
    program: &DnsPolicyProgram,
    state: &mut DnsPolicyEvaluationState,
    scratch: &mut DnsPolicyScratch,
) -> Result<Option<DnsPolicyStep>, DnsPolicyStateError> {
    if state.pending_rule.is_some() {
        return Err(DnsPolicyStateError::ResponseRequired);
    }
    Ok(advance_observed(program, state, scratch))
}

fn evaluate_policy_response(
    program: &DnsPolicyProgram,
    state: &mut DnsPolicyEvaluationState,
    scratch: &mut DnsPolicyScratch,
    response: &Message,
) -> Result<DnsPolicyStep, DnsPolicyStateError> {
    let rule_index = state
        .pending_rule
        .take()
        .ok_or(DnsPolicyStateError::ResponseNotExpected)?;
    let rule = &program.compiled.rules()[rule_index];
    let DnsPolicyAction::Route(route) = rule.action else {
        return Err(DnsPolicyStateError::ResponseNotExpected);
    };
    let started = Instant::now();
    let matched = response_matches_rule_sets(
        &state.snapshot,
        &rule.matcher.rule_sets,
        &state.query,
        response,
    );
    let elapsed = elapsed_ns(started);
    state.observation.record_response(elapsed);
    state.observation.record_match(
        DnsPolicyStage::Response,
        DnsPolicyMatchSource::RuleSet,
        DnsPolicyMatchType::IpCidr,
        matched,
    );
    if matched {
        state.finished = true;
        return Ok(DnsPolicyStep::AcceptResponse {
            server: route.server,
            strategy: route.strategy,
        });
    }
    advance_observed(program, state, scratch).ok_or(DnsPolicyStateError::ResponseNotExpected)
}

fn advance_observed(
    program: &DnsPolicyProgram,
    state: &mut DnsPolicyEvaluationState,
    scratch: &mut DnsPolicyScratch,
) -> Option<DnsPolicyStep> {
    let started = Instant::now();
    scratch.candidate_visits = 0;
    let result = advance(program, state, scratch);
    state
        .observation
        .record_query(scratch.candidate_visits, elapsed_ns(started));
    result
}

fn advance(
    program: &DnsPolicyProgram,
    state: &mut DnsPolicyEvaluationState,
    scratch: &mut DnsPolicyScratch,
) -> Option<DnsPolicyStep> {
    if state.finished {
        return None;
    }
    while let Some(rule_index) =
        program.next_query_candidate(state.cursor, &state.query, &state.snapshot, scratch)
    {
        let rule = &program.compiled.rules()[rule_index];
        state.cursor = rule_index.saturating_add(1);
        scratch.candidate_visits = scratch.candidate_visits.saturating_add(1);
        if !rule
            .matcher
            .matches_query_fields(&state.query, &mut state.observation)
        {
            continue;
        }
        if rule.matcher.rule_sets.is_empty()
            || matches_query_rule_sets(
                &state.snapshot,
                &rule.matcher.rule_sets,
                state.query.canonical_qname.as_ref(),
                &mut state.observation,
            )
        {
            state.finished = true;
            return Some(immediate_step(rule.action));
        }
        if let DnsPolicyAction::Route(route) = rule.action
            && is_address_qtype(state.query.qtype)
            && rule.matcher.rule_sets.iter().copied().any(|rule_set| {
                rule_set_match_set(&state.snapshot, rule_set)
                    .is_some_and(|set| set.capabilities().ip_cidr)
            })
        {
            state.pending_rule = Some(rule_index);
            return Some(DnsPolicyStep::EvaluateResponse {
                server: route.server,
                strategy: route.strategy,
            });
        }
    }
    state.finished = true;
    Some(DnsPolicyStep::Final {
        server: program.final_route.server,
        strategy: program.final_route.strategy,
    })
}

impl DnsPolicyProgram {
    fn next_query_candidate(
        &self,
        cursor: usize,
        query: &DnsPolicyQuery,
        snapshot: &RuleEngineSnapshot,
        scratch: &mut DnsPolicyScratch,
    ) -> Option<usize> {
        if self.compiled.mode() == RuleProgramMode::SmallLinear {
            return (cursor < self.compiled.len()).then_some(cursor);
        }
        let candidates = self.compiled.index()?;
        let field = match scratch.driver {
            Some(field) => field,
            None => {
                let Some(field) = candidates.select_driver(query, snapshot) else {
                    return (cursor < self.compiled.len()).then_some(cursor);
                };
                scratch.driver = Some(field);
                field
            }
        };
        candidates.next_candidate(field, cursor, query, snapshot)
    }
}

fn immediate_step(action: DnsPolicyAction) -> DnsPolicyStep {
    match action {
        DnsPolicyAction::Reject => DnsPolicyStep::Reject,
        DnsPolicyAction::Route(route) => DnsPolicyStep::RouteImmediately {
            server: route.server,
            strategy: route.strategy,
        },
    }
}

fn rule_set_match_set(
    snapshot: &RuleEngineSnapshot,
    rule_set: RuleSetId,
) -> Option<&CompiledMatchSet> {
    let descriptor = snapshot.rule_set(rule_set)?;
    snapshot.match_set(descriptor.match_set())
}

fn matches_query_rule_sets(
    snapshot: &RuleEngineSnapshot,
    rule_sets: &[RuleSetId],
    domain: Option<&CanonicalDomain>,
    observation: &mut DnsPolicyObservation,
) -> bool {
    rule_sets.iter().copied().any(|rule_set| {
        rule_set_match_set(snapshot, rule_set).is_some_and(|set| {
            observe_domain_match(set, domain, DnsPolicyMatchSource::RuleSet, observation)
        })
    })
}

fn response_matches_rule_sets<'a>(
    snapshot: &RuleEngineSnapshot,
    rule_sets: &[RuleSetId],
    query: &'a DnsPolicyQuery,
    response: &'a Message,
) -> bool {
    let mut matched = false;
    visit_response_addresses(&query.qname, query.qtype, response, |address| {
        matched |= rule_sets.iter().copied().any(|rule_set| {
            rule_set_match_set(snapshot, rule_set).is_some_and(|set| set.matches_ip(address))
        });
    });
    matched
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn visit_response_addresses<'a>(
    qname: &'a Name,
    qtype: RecordType,
    response: &'a Message,
    mut visit: impl FnMut(IpAddr),
) {
    if !is_address_qtype(qtype) {
        return;
    }
    let answers = &response.answers;
    let mut owner = qname;
    for _ in 0..=answers.len() {
        if let Some(next) = answers.iter().find_map(|record| {
            if &record.name != owner {
                return None;
            }
            match &record.data {
                RData::CNAME(cname) => Some(&cname.0),
                _ => None,
            }
        }) {
            owner = next;
            continue;
        }
        for record in answers {
            if &record.name != owner {
                continue;
            }
            match &record.data {
                RData::A(address) => visit(IpAddr::V4(address.0)),
                RData::AAAA(address) => visit(IpAddr::V6(address.0)),
                _ => {}
            }
        }
        return;
    }
}

pub(crate) const fn is_address_qtype(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::A | RecordType::AAAA)
}

pub(super) fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
