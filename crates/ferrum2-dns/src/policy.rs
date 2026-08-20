use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Instant;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;
use ferrum2_rule::{
    CompiledMatchSet, CompiledRuleProgram, DnsPolicyActionDescriptor, DnsPolicyAddressStrategy,
    DnsPolicyBlueprint, DnsPolicyMatcherDescriptor, DnsPolicyMatcherDescriptorParts,
    DomainMatchType, RuleCompileError, RuleEngineRegistry, RuleEngineSnapshot, RuleProgramMode,
    RuleSetId,
};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::policy_candidate::{DnsQueryCandidateIndex, QueryCandidateDriver};
use crate::{DnsServerId, DnsStrategy};

/// One DNS upstream selection together with its address-family policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPolicyRoute {
    server: DnsServerId,
    strategy: DnsStrategy,
}

impl DnsPolicyRoute {
    pub const fn new(server: DnsServerId, strategy: DnsStrategy) -> Self {
        Self { server, strategy }
    }

    pub const fn server(self) -> DnsServerId {
        self.server
    }

    pub const fn strategy(self) -> DnsStrategy {
        self.strategy
    }
}

/// Closed action attached to one compiled DNS policy row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyAction {
    Route(DnsPolicyRoute),
    Reject,
}

/// Closed DNS policy evaluation stages exposed to an identity-free observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyStage {
    Query,
    Response,
}

impl DnsPolicyStage {
    pub const ALL: [Self; 2] = [Self::Query, Self::Response];

    const fn index(self) -> usize {
        match self {
            Self::Query => 0,
            Self::Response => 1,
        }
    }
}

/// Closed origin of one DNS policy matcher observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyMatchSource {
    Inline,
    RuleSet,
}

impl DnsPolicyMatchSource {
    pub const ALL: [Self; 2] = [Self::Inline, Self::RuleSet];

    const fn index(self) -> usize {
        match self {
            Self::Inline => 0,
            Self::RuleSet => 1,
        }
    }
}

/// Closed matcher category. No configured value is retained or exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Scalar,
}

impl DnsPolicyMatchType {
    pub const ALL: [Self; 5] = [
        Self::Domain,
        Self::DomainSuffix,
        Self::DomainKeyword,
        Self::IpCidr,
        Self::Scalar,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Domain => 0,
            Self::DomainSuffix => 1,
            Self::DomainKeyword => 2,
            Self::IpCidr => 3,
            Self::Scalar => 4,
        }
    }
}

/// Closed result of one DNS matcher category evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyMatchResult {
    Matched,
    Missed,
}

impl DnsPolicyMatchResult {
    pub const ALL: [Self; 2] = [Self::Matched, Self::Missed];

    const fn index(self) -> usize {
        match self {
            Self::Matched => 0,
            Self::Missed => 1,
        }
    }
}

const DNS_POLICY_MATCH_SERIES: usize = 2 * 2 * 5 * 2;

/// One complete, identity-free DNS policy evaluation observation.
///
/// Counts are accumulated in a fixed array so the policy hot path performs no
/// telemetry allocation and invokes an observer only once after evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPolicyObservation {
    query_evaluated: bool,
    response_evaluated: bool,
    query_candidates: usize,
    response_candidates: usize,
    query_match_ns: u64,
    response_match_ns: u64,
    matches: [u64; DNS_POLICY_MATCH_SERIES],
}

impl Default for DnsPolicyObservation {
    fn default() -> Self {
        Self {
            query_evaluated: false,
            response_evaluated: false,
            query_candidates: 0,
            response_candidates: 0,
            query_match_ns: 0,
            response_match_ns: 0,
            matches: [0; DNS_POLICY_MATCH_SERIES],
        }
    }
}

impl DnsPolicyObservation {
    pub const fn query_evaluated(self) -> bool {
        self.query_evaluated
    }

    pub const fn response_evaluated(self) -> bool {
        self.response_evaluated
    }

    pub const fn query_candidates(self) -> usize {
        self.query_candidates
    }

    pub const fn response_candidates(self) -> usize {
        self.response_candidates
    }

    pub const fn query_match_ns(self) -> u64 {
        self.query_match_ns
    }

    pub const fn response_match_ns(self) -> u64 {
        self.response_match_ns
    }

    /// Returns the number of matcher checks in one closed label tuple.
    pub const fn match_count(
        self,
        stage: DnsPolicyStage,
        source: DnsPolicyMatchSource,
        r#type: DnsPolicyMatchType,
        result: DnsPolicyMatchResult,
    ) -> u64 {
        self.matches[policy_match_index(stage, source, r#type, result)]
    }

    fn record_match(
        &mut self,
        stage: DnsPolicyStage,
        source: DnsPolicyMatchSource,
        r#type: DnsPolicyMatchType,
        matched: bool,
    ) {
        let result = if matched {
            DnsPolicyMatchResult::Matched
        } else {
            DnsPolicyMatchResult::Missed
        };
        let count = &mut self.matches[policy_match_index(stage, source, r#type, result)];
        *count = count.saturating_add(1);
    }

    fn record_query(&mut self, candidates: usize, elapsed_ns: u64) {
        self.query_evaluated = true;
        self.query_candidates = self.query_candidates.saturating_add(candidates);
        self.query_match_ns = self.query_match_ns.saturating_add(elapsed_ns);
    }

    fn record_response(&mut self, elapsed_ns: u64) {
        self.response_evaluated = true;
        self.response_candidates = self.response_candidates.saturating_add(1);
        self.response_match_ns = self.response_match_ns.saturating_add(elapsed_ns);
    }
}

const fn policy_match_index(
    stage: DnsPolicyStage,
    source: DnsPolicyMatchSource,
    r#type: DnsPolicyMatchType,
    result: DnsPolicyMatchResult,
) -> usize {
    (((stage.index() * 2 + source.index()) * 5 + r#type.index()) * 2) + result.index()
}

/// Optional low-overhead observer invoked once for each completed proxy policy evaluation.
pub trait DnsPolicyObserver: Send + Sync {
    fn observe(&self, observation: DnsPolicyObservation);
}

impl<F> DnsPolicyObserver for F
where
    F: Fn(DnsPolicyObservation) + Send + Sync,
{
    fn observe(&self, observation: DnsPolicyObservation) {
        self(observation);
    }
}

/// One inclusive non-zero application target-port interval.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsPortRange {
    first: NonZeroU16,
    last: NonZeroU16,
}

impl DnsPortRange {
    /// Creates a validated inclusive port interval.
    pub fn try_new(first: u16, last: u16) -> Result<Self, DnsPolicyCompileError> {
        let first = NonZeroU16::new(first).ok_or(DnsPolicyCompileError::InvalidPortRange)?;
        let last = NonZeroU16::new(last).ok_or(DnsPolicyCompileError::InvalidPortRange)?;
        if first > last {
            return Err(DnsPolicyCompileError::InvalidPortRange);
        }
        Ok(Self { first, last })
    }

    /// Returns the inclusive lower endpoint.
    pub const fn first(self) -> NonZeroU16 {
        self.first
    }

    /// Returns the inclusive upper endpoint.
    pub const fn last(self) -> NonZeroU16 {
        self.last
    }

    /// Tests one non-zero application target port.
    pub fn contains(self, port: NonZeroU16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

/// Immutable query inputs used by both policy stages.
pub struct DnsPolicyQuery {
    inbound: usize,
    network: Network,
    qname: Name,
    canonical_qname: Option<CanonicalDomain>,
    qtype: RecordType,
    port: Option<NonZeroU16>,
}

impl DnsPolicyQuery {
    /// Creates policy input from one already validated DNS question.
    pub fn new(inbound: usize, network: Network, qname: Name, qtype: RecordType) -> Self {
        Self::with_port(inbound, network, qname, qtype, None)
    }

    /// Creates policy input for one application domain and target port.
    pub fn new_application(
        inbound: usize,
        network: Network,
        qname: Name,
        qtype: RecordType,
        port: NonZeroU16,
    ) -> Self {
        Self::with_port(inbound, network, qname, qtype, Some(port))
    }

    fn with_port(
        inbound: usize,
        network: Network,
        qname: Name,
        qtype: RecordType,
        port: Option<NonZeroU16>,
    ) -> Self {
        let canonical_qname = CanonicalDomain::new(&qname.to_ascii()).ok();
        Self {
            inbound,
            network,
            qname,
            canonical_qname,
            qtype,
            port,
        }
    }

    pub const fn inbound(&self) -> usize {
        self.inbound
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    pub const fn qname(&self) -> &Name {
        &self.qname
    }

    pub const fn canonical_qname(&self) -> Option<&CanonicalDomain> {
        self.canonical_qname.as_ref()
    }

    pub const fn qtype(&self) -> RecordType {
        self.qtype
    }

    /// Returns the application target port, absent for wire DNS questions.
    pub const fn port(&self) -> Option<NonZeroU16> {
        self.port
    }
}

impl fmt::Debug for DnsPolicyQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsPolicyQuery")
            .field("inbound", &self.inbound)
            .field("network", &self.network)
            .field("qname", &"[redacted]")
            .field("qtype", &self.qtype)
            .finish()
    }
}

/// Query-stage fields for one DNS policy row.
///
/// Each ordinary compiled match set is a distinct field and is therefore ANDed
/// with the others. Values inside a compiled set retain their shared OR
/// semantics. RuleSet references form one OR field which is ANDed with the
/// ordinary and scalar fields.
pub struct DnsPolicyMatcher {
    pub(super) query_fields: Arc<[Arc<CompiledMatchSet>]>,
    pub(super) rule_sets: Arc<[RuleSetId]>,
    pub(super) inbounds: Box<[usize]>,
    pub(super) networks: Box<[Network]>,
    pub(super) qtypes: Box<[RecordType]>,
    pub(super) ports: Box<[NonZeroU16]>,
    pub(super) port_ranges: Box<[DnsPortRange]>,
}

impl DnsPolicyMatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        query_fields: Vec<Arc<CompiledMatchSet>>,
        rule_sets: Vec<RuleSetId>,
        inbounds: Vec<usize>,
        networks: Vec<Network>,
        qtypes: Vec<RecordType>,
    ) -> Result<Self, DnsPolicyCompileError> {
        Self::try_new_with_application_constraints(
            query_fields,
            rule_sets,
            inbounds,
            networks,
            qtypes,
            Vec::new(),
            Vec::new(),
        )
    }

    /// Compiles query fields together with optional application-port fields.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_application_constraints(
        query_fields: Vec<Arc<CompiledMatchSet>>,
        rule_sets: Vec<RuleSetId>,
        inbounds: Vec<usize>,
        networks: Vec<Network>,
        qtypes: Vec<RecordType>,
        ports: Vec<NonZeroU16>,
        port_ranges: Vec<DnsPortRange>,
    ) -> Result<Self, DnsPolicyCompileError> {
        if query_fields.is_empty()
            && rule_sets.is_empty()
            && inbounds.is_empty()
            && networks.is_empty()
            && qtypes.is_empty()
            && ports.is_empty()
            && port_ranges.is_empty()
        {
            return Err(DnsPolicyCompileError::EmptyRule);
        }
        if query_fields.iter().any(|field| {
            let capabilities = field.capabilities();
            field.is_empty()
                || capabilities.ip_cidr
                || !(capabilities.exact_domain
                    || capabilities.domain_suffix
                    || capabilities.domain_keyword)
        }) {
            return Err(DnsPolicyCompileError::InvalidQueryMatchSet);
        }
        if has_duplicate(&rule_sets)
            || has_duplicate(&inbounds)
            || has_duplicate(&networks)
            || has_duplicate(&qtypes)
            || has_duplicate(&ports)
            || has_duplicate(&port_ranges)
        {
            return Err(DnsPolicyCompileError::DuplicateConstraint);
        }
        Ok(Self {
            query_fields: query_fields.into(),
            rule_sets: rule_sets.into(),
            inbounds: inbounds.into_boxed_slice(),
            networks: networks.into_boxed_slice(),
            qtypes: qtypes.into_boxed_slice(),
            ports: ports.into_boxed_slice(),
            port_ranges: port_ranges.into_boxed_slice(),
        })
    }

    fn try_from_descriptor(
        descriptor: DnsPolicyMatcherDescriptor,
    ) -> Result<Self, DnsPolicyCompileError> {
        let DnsPolicyMatcherDescriptorParts {
            query_fields,
            rule_sets,
            inbounds,
            networks,
            qtypes,
            ports,
            port_ranges,
        } = descriptor.into_parts();
        let mut runtime_qtypes = Vec::new();
        runtime_qtypes
            .try_reserve_exact(qtypes.len())
            .map_err(|_| DnsPolicyCompileError::Allocation)?;
        runtime_qtypes.extend(qtypes.iter().copied().map(RecordType::from));
        let mut runtime_port_ranges = Vec::new();
        runtime_port_ranges
            .try_reserve_exact(port_ranges.len())
            .map_err(|_| DnsPolicyCompileError::Allocation)?;
        runtime_port_ranges.extend(port_ranges.iter().copied().map(|range| DnsPortRange {
            first: range.first(),
            last: range.last(),
        }));
        Ok(Self {
            query_fields,
            rule_sets,
            inbounds,
            networks,
            qtypes: runtime_qtypes.into_boxed_slice(),
            ports,
            port_ranges: runtime_port_ranges.into_boxed_slice(),
        })
    }

    pub fn rule_sets(&self) -> &[RuleSetId] {
        &self.rule_sets
    }

    fn matches_query_fields(
        &self,
        query: &DnsPolicyQuery,
        observation: &mut DnsPolicyObservation,
    ) -> bool {
        if !observe_scalar(
            !self.inbounds.is_empty(),
            self.inbounds.contains(&query.inbound),
            observation,
        ) || !observe_scalar(
            !self.networks.is_empty(),
            self.networks.contains(&query.network),
            observation,
        ) || !observe_scalar(
            !self.qtypes.is_empty(),
            self.qtypes.contains(&query.qtype),
            observation,
        ) || !observe_scalar(
            !self.ports.is_empty(),
            query.port.is_some_and(|port| self.ports.contains(&port)),
            observation,
        ) || !observe_scalar(
            !self.port_ranges.is_empty(),
            query
                .port
                .is_some_and(|port| self.port_ranges.iter().any(|range| range.contains(port))),
            observation,
        ) {
            return false;
        }
        if self.query_fields.is_empty() {
            return true;
        }
        let domain = query.canonical_qname.as_ref();
        self.query_fields.iter().all(|field| {
            observe_domain_match(field, domain, DnsPolicyMatchSource::Inline, observation)
        })
    }
}

fn observe_scalar(configured: bool, matched: bool, observation: &mut DnsPolicyObservation) -> bool {
    if configured {
        observation.record_match(
            DnsPolicyStage::Query,
            DnsPolicyMatchSource::Inline,
            DnsPolicyMatchType::Scalar,
            matched,
        );
    }
    !configured || matched
}

fn observe_domain_match(
    set: &CompiledMatchSet,
    domain: Option<&CanonicalDomain>,
    source: DnsPolicyMatchSource,
    observation: &mut DnsPolicyObservation,
) -> bool {
    let capabilities = set.capabilities();
    let matched = domain.and_then(|domain| set.domain_match_type(domain));
    if capabilities.exact_domain {
        let is_match = matched == Some(DomainMatchType::Exact);
        observation.record_match(
            DnsPolicyStage::Query,
            source,
            DnsPolicyMatchType::Domain,
            is_match,
        );
        if is_match {
            return true;
        }
    }
    if capabilities.domain_suffix {
        let is_match = matched == Some(DomainMatchType::Suffix);
        observation.record_match(
            DnsPolicyStage::Query,
            source,
            DnsPolicyMatchType::DomainSuffix,
            is_match,
        );
        if is_match {
            return true;
        }
    }
    if capabilities.domain_keyword {
        let is_match = matched == Some(DomainMatchType::Keyword);
        observation.record_match(
            DnsPolicyStage::Query,
            source,
            DnsPolicyMatchType::DomainKeyword,
            is_match,
        );
        if is_match {
            return true;
        }
    }
    false
}

impl fmt::Debug for DnsPolicyMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyMatcher([redacted])")
    }
}

/// One ordered DNS policy row.
pub struct DnsPolicyRule {
    pub(super) matcher: DnsPolicyMatcher,
    action: DnsPolicyAction,
}

impl DnsPolicyRule {
    pub const fn new(matcher: DnsPolicyMatcher, action: DnsPolicyAction) -> Self {
        Self { matcher, action }
    }
}

impl fmt::Debug for DnsPolicyRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyRule([redacted])")
    }
}

/// Fallible DNS policy compilation failures without rule contents or names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyCompileError {
    EmptyRule,
    InvalidQueryMatchSet,
    DuplicateConstraint,
    InvalidPortRange,
    UnknownRuleSet,
    ResponseDependentReject,
    Allocation,
    IndexOverflow,
    Internal,
}

impl fmt::Display for DnsPolicyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyRule => "DNS policy rule has no matcher",
            Self::InvalidQueryMatchSet => "DNS query field has an unsupported matcher",
            Self::DuplicateConstraint => "DNS policy field contains a duplicate constraint",
            Self::InvalidPortRange => "DNS policy port range is invalid",
            Self::UnknownRuleSet => "DNS policy references an unknown RuleSet",
            Self::ResponseDependentReject => {
                "DNS reject policy cannot depend on response address matching"
            }
            Self::Allocation => "DNS policy allocation failed",
            Self::IndexOverflow => "DNS policy index capacity was exceeded",
            Self::Internal => "DNS policy compilation failed",
        })
    }
}

impl Error for DnsPolicyCompileError {}

/// Immutable ordered DNS policy with one mandatory final upstream.
pub struct DnsPolicyProgram {
    compiled: CompiledRuleProgram<DnsPolicyRule, DnsQueryCandidateIndex>,
    response_rules: usize,
    final_route: DnsPolicyRoute,
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
    const fn new() -> Self {
        Self {
            driver: None,
            candidate_visits: 0,
        }
    }

    /// Returns the number of complete candidate rows checked by the last query step.
    pub const fn candidate_visits(&self) -> usize {
        self.candidate_visits
    }

    fn reset(&mut self) {
        self.driver = None;
        self.candidate_visits = 0;
    }
}

struct DnsPolicyEvaluationState {
    query: DnsPolicyQuery,
    snapshot: Arc<RuleEngineSnapshot>,
    cursor: usize,
    pending_rule: Option<usize>,
    finished: bool,
    observation: DnsPolicyObservation,
}

impl DnsPolicyEvaluationState {
    fn new(query: DnsPolicyQuery, snapshot: Arc<RuleEngineSnapshot>) -> Self {
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
    program: &'program DnsPolicyProgram,
    state: DnsPolicyEvaluationState,
    scratch: DnsPolicyScratch,
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
    program: &'program DnsPolicyProgram,
    state: DnsPolicyEvaluationState,
    scratch: &'scratch mut DnsPolicyScratch,
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

pub(super) const fn is_address_qtype(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::A | RecordType::AAAA)
}

fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
