use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;
use std::sync::Arc;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;
use ferrum2_rule::{
    CompiledMatchSet, DnsPolicyMatcherDescriptor, DnsPolicyMatcherDescriptorParts, DomainMatchType,
    RuleSetId,
};
use hickory_proto::rr::{Name, RecordType};

use super::evaluation::has_duplicate;
use crate::{DnsServerId, DnsStrategy};

/// One DNS upstream selection together with its address-family policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPolicyRoute {
    pub(super) server: DnsServerId,
    pub(super) strategy: DnsStrategy,
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

    pub(super) fn record_match(
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

    pub(super) fn record_query(&mut self, candidates: usize, elapsed_ns: u64) {
        self.query_evaluated = true;
        self.query_candidates = self.query_candidates.saturating_add(candidates);
        self.query_match_ns = self.query_match_ns.saturating_add(elapsed_ns);
    }

    pub(super) fn record_response(&mut self, elapsed_ns: u64) {
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
    pub(super) qname: Name,
    pub(super) canonical_qname: Option<CanonicalDomain>,
    pub(super) qtype: RecordType,
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
    pub(crate) query_fields: Arc<[Arc<CompiledMatchSet>]>,
    pub(crate) rule_sets: Arc<[RuleSetId]>,
    pub(crate) inbounds: Box<[usize]>,
    pub(crate) networks: Box<[Network]>,
    pub(crate) qtypes: Box<[RecordType]>,
    pub(crate) ports: Box<[NonZeroU16]>,
    pub(crate) port_ranges: Box<[DnsPortRange]>,
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

    pub(super) fn try_from_descriptor(
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

    pub(super) fn matches_query_fields(
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

pub(super) fn observe_domain_match(
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
    pub(crate) matcher: DnsPolicyMatcher,
    pub(super) action: DnsPolicyAction,
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
