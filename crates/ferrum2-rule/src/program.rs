use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr, TargetHostRef};
use ipnet::IpNet;

use crate::candidate::{
    MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories, PortRangeCandidateIndex,
    PortRangeCandidateIndexBuilder, SparseValueIndex, SparseValueIndexBuilder,
};
use crate::{
    CompiledMatchSet, CompiledRuleProgram, MatchSetBuilder, RuleCompileError, RuleEngineRegistry,
    RuleEngineSnapshot, RuleProgramMode, RuleSetId,
};

const FIELD_KIND_COUNT: usize = 12;

/// One validated inclusive non-zero port interval.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortRange {
    first: NonZeroU16,
    last: NonZeroU16,
}

impl PortRange {
    pub fn try_new(first: u16, last: u16) -> Result<Self, RuleCompileError> {
        let first = NonZeroU16::new(first).ok_or(RuleCompileError::EmptyField)?;
        let last = NonZeroU16::new(last).ok_or(RuleCompileError::EmptyField)?;
        if first > last {
            return Err(RuleCompileError::EmptyField);
        }
        Ok(Self { first, last })
    }

    pub const fn first(self) -> NonZeroU16 {
        self.first
    }

    pub const fn last(self) -> NonZeroU16 {
        self.last
    }

    pub fn contains(self, port: NonZeroU16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

/// One matcher field. Values within a field are ORed; distinct fields are ANDed.
pub enum RouteMatchField<P> {
    Inbound(Vec<usize>),
    Network(Vec<Network>),
    Protocol(Vec<P>),
    Domain(Vec<DomainName>),
    DomainSuffix(Vec<DomainName>),
    DomainKeyword(Vec<DomainName>),
    Ip(Vec<IpAddr>),
    Cidr(Vec<IpNet>),
    Port(Vec<NonZeroU16>),
    PortRange(Vec<PortRange>),
    /// A synthetic or decoded RuleSet whose internal categories are ORed.
    MatchSet(CompiledMatchSet),
    /// Stable RuleSet references. Multiple references within this field are ORed.
    RuleSet(Vec<RuleSetId>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FieldKind {
    Inbound = 0,
    Network = 1,
    Protocol = 2,
    Domain = 3,
    DomainSuffix = 4,
    DomainKeyword = 5,
    Ip = 6,
    Cidr = 7,
    Port = 8,
    PortRange = 9,
    MatchSet = 10,
    RuleSet = 11,
}

impl FieldKind {
    const ALL: [Self; FIELD_KIND_COUNT] = [
        Self::Inbound,
        Self::Network,
        Self::Protocol,
        Self::Domain,
        Self::DomainSuffix,
        Self::DomainKeyword,
        Self::Ip,
        Self::Cidr,
        Self::Port,
        Self::PortRange,
        Self::MatchSet,
        Self::RuleSet,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

enum CompiledField<P> {
    Inbound(Box<[usize]>),
    Network(Box<[Network]>),
    Protocol(Box<[P]>),
    Domain(CompiledMatchSet),
    DomainSuffix(CompiledMatchSet),
    DomainKeyword(CompiledMatchSet),
    Ip(CompiledMatchSet),
    Cidr(CompiledMatchSet),
    Port(Box<[NonZeroU16]>),
    PortRange(Box<[PortRange]>),
    MatchSet(CompiledMatchSet),
    RuleSet(Box<[RuleSetId]>),
}

/// Closed source of a matcher category reported for one selected route row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMatchSource {
    Inline,
    RuleSet,
}

impl RouteMatchSource {
    pub const ALL: [Self; 2] = [Self::Inline, Self::RuleSet];

    const fn index(self) -> u16 {
        match self {
            Self::Inline => 0,
            Self::RuleSet => 1,
        }
    }
}

/// Closed matcher category reported for one selected route row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Scalar,
}

impl RouteMatchType {
    pub const ALL: [Self; 5] = [
        Self::Domain,
        Self::DomainSuffix,
        Self::DomainKeyword,
        Self::IpCidr,
        Self::Scalar,
    ];

    const fn index(self) -> u16 {
        match self {
            Self::Domain => 0,
            Self::DomainSuffix => 1,
            Self::DomainKeyword => 2,
            Self::IpCidr => 3,
            Self::Scalar => 4,
        }
    }
}

/// Allocation-free evaluated/matched category summary for the rule selected by the latest step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteMatchObservation {
    evaluated: u16,
    matched: u16,
}

impl RouteMatchObservation {
    pub const fn is_empty(self) -> bool {
        self.evaluated == 0
    }

    /// Returns whether the selected rule configured this closed matcher category.
    pub const fn evaluated(self, source: RouteMatchSource, r#type: RouteMatchType) -> bool {
        let bit = source.index() * 5 + r#type.index();
        self.evaluated & (1 << bit) != 0
    }

    pub const fn matched(self, source: RouteMatchSource, r#type: RouteMatchType) -> bool {
        let bit = source.index() * 5 + r#type.index();
        self.matched & (1 << bit) != 0
    }

    fn record(&mut self, source: RouteMatchSource, r#type: RouteMatchType) {
        let bit = source.index() * 5 + r#type.index();
        self.evaluated |= 1 << bit;
        self.matched |= 1 << bit;
    }

    fn record_evaluated(&mut self, source: RouteMatchSource, r#type: RouteMatchType) {
        let bit = source.index() * 5 + r#type.index();
        self.evaluated |= 1 << bit;
    }
}

impl<P> CompiledField<P> {
    const fn kind(&self) -> FieldKind {
        match self {
            Self::Inbound(_) => FieldKind::Inbound,
            Self::Network(_) => FieldKind::Network,
            Self::Protocol(_) => FieldKind::Protocol,
            Self::Domain(_) => FieldKind::Domain,
            Self::DomainSuffix(_) => FieldKind::DomainSuffix,
            Self::DomainKeyword(_) => FieldKind::DomainKeyword,
            Self::Ip(_) => FieldKind::Ip,
            Self::Cidr(_) => FieldKind::Cidr,
            Self::Port(_) => FieldKind::Port,
            Self::PortRange(_) => FieldKind::PortRange,
            Self::MatchSet(_) => FieldKind::MatchSet,
            Self::RuleSet(_) => FieldKind::RuleSet,
        }
    }
}

/// One immutable conjunction of compiled matcher fields.
pub struct RouteMatcher<P> {
    fields: Box<[CompiledField<P>]>,
}

impl<P: Eq> RouteMatcher<P> {
    pub fn try_new(fields: Vec<RouteMatchField<P>>) -> Result<Self, RuleCompileError> {
        if fields.is_empty() {
            return Err(RuleCompileError::EmptyMatcher);
        }
        Self::compile(fields)
    }

    /// Creates an explicit unconditional matcher for ordered continuation rules.
    pub fn unconditional() -> Self {
        Self {
            fields: Box::new([]),
        }
    }

    fn compile(fields: Vec<RouteMatchField<P>>) -> Result<Self, RuleCompileError> {
        let mut seen = [false; FIELD_KIND_COUNT];
        let mut compiled = Vec::new();
        compiled
            .try_reserve(fields.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for field in fields {
            let field = compile_field(field)?;
            let kind = field.kind().index();
            if seen[kind] {
                return Err(RuleCompileError::DuplicateField);
            }
            seen[kind] = true;
            compiled.push(field);
        }
        Ok(Self {
            fields: compiled.into_boxed_slice(),
        })
    }

    pub(crate) fn matches(
        &self,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
    ) -> bool {
        self.fields
            .iter()
            .all(|field| matches_field(field, inbound, network, original, metadata, snapshot))
    }

    fn observation(
        &self,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
    ) -> RouteMatchObservation {
        let domain = selected_domain(original, metadata);
        let address = match original.host() {
            TargetHostRef::Ip(address) => Some(address),
            TargetHostRef::Domain(_) => None,
        };
        let mut observation = RouteMatchObservation::default();
        for field in &self.fields {
            match field {
                CompiledField::Domain(_) => {
                    observation.record(RouteMatchSource::Inline, RouteMatchType::Domain);
                }
                CompiledField::DomainSuffix(_) => {
                    observation.record(RouteMatchSource::Inline, RouteMatchType::DomainSuffix);
                }
                CompiledField::DomainKeyword(_) => {
                    observation.record(RouteMatchSource::Inline, RouteMatchType::DomainKeyword);
                }
                CompiledField::Ip(_) | CompiledField::Cidr(_) => {
                    observation.record(RouteMatchSource::Inline, RouteMatchType::IpCidr);
                }
                CompiledField::MatchSet(set) => observe_match_set(
                    set,
                    domain,
                    address,
                    RouteMatchSource::Inline,
                    &mut observation,
                ),
                CompiledField::RuleSet(rule_sets) => {
                    if let Some(snapshot) = snapshot {
                        for rule_set in rule_sets {
                            if let Some(set) = snapshot
                                .rule_set(*rule_set)
                                .and_then(|descriptor| snapshot.match_set(descriptor.match_set()))
                            {
                                observe_match_set(
                                    set,
                                    domain,
                                    address,
                                    RouteMatchSource::RuleSet,
                                    &mut observation,
                                );
                            }
                        }
                    }
                }
                CompiledField::Inbound(_)
                | CompiledField::Network(_)
                | CompiledField::Protocol(_)
                | CompiledField::Port(_)
                | CompiledField::PortRange(_) => {
                    observation.record(RouteMatchSource::Inline, RouteMatchType::Scalar);
                }
            }
        }
        observation
    }
}

fn observe_match_set(
    set: &CompiledMatchSet,
    domain: Option<&CanonicalDomain>,
    address: Option<IpAddr>,
    source: RouteMatchSource,
    observation: &mut RouteMatchObservation,
) {
    let capabilities = set.capabilities();
    if capabilities.exact_domain {
        observation.record_evaluated(source, RouteMatchType::Domain);
    }
    if capabilities.domain_suffix {
        observation.record_evaluated(source, RouteMatchType::DomainSuffix);
    }
    if capabilities.domain_keyword {
        observation.record_evaluated(source, RouteMatchType::DomainKeyword);
    }
    if capabilities.ip_cidr {
        observation.record_evaluated(source, RouteMatchType::IpCidr);
    }
    if let Some(domain) = domain {
        match set.domain_match_type(domain) {
            Some(crate::DomainMatchType::Exact) => {
                observation.record(source, RouteMatchType::Domain)
            }
            Some(crate::DomainMatchType::Suffix) => {
                observation.record(source, RouteMatchType::DomainSuffix);
            }
            Some(crate::DomainMatchType::Keyword) => {
                observation.record(source, RouteMatchType::DomainKeyword);
            }
            None => {}
        }
    }
    if address.is_some_and(|address| set.matches_ip(address)) {
        observation.record(source, RouteMatchType::IpCidr);
    }
}

fn compile_field<P: Eq>(field: RouteMatchField<P>) -> Result<CompiledField<P>, RuleCompileError> {
    Ok(match field {
        RouteMatchField::Inbound(mut values) => {
            validate_unique(&mut values)?;
            CompiledField::Inbound(values.into_boxed_slice())
        }
        RouteMatchField::Network(mut values) => {
            validate_unique(&mut values)?;
            CompiledField::Network(values.into_boxed_slice())
        }
        RouteMatchField::Protocol(values) => {
            validate_unique_eq(&values)?;
            CompiledField::Protocol(values.into_boxed_slice())
        }
        RouteMatchField::Domain(values) => {
            let mut builder = MatchSetBuilder::new();
            for value in &values {
                builder.add_domain(value)?;
            }
            CompiledField::Domain(builder.build()?)
        }
        RouteMatchField::DomainSuffix(values) => {
            let mut builder = MatchSetBuilder::new();
            for value in &values {
                builder.add_domain_suffix_name(value)?;
            }
            CompiledField::DomainSuffix(builder.build()?)
        }
        RouteMatchField::DomainKeyword(values) => {
            let mut builder = MatchSetBuilder::new();
            for value in &values {
                builder.add_domain_keyword(value.as_str())?;
            }
            CompiledField::DomainKeyword(builder.build()?)
        }
        RouteMatchField::Ip(values) => {
            if values.is_empty() {
                return Err(RuleCompileError::EmptyField);
            }
            let mut builder = MatchSetBuilder::new();
            for value in values {
                builder.add_ip(value)?;
            }
            CompiledField::Ip(builder.build()?)
        }
        RouteMatchField::Cidr(values) => {
            if values.is_empty() {
                return Err(RuleCompileError::EmptyField);
            }
            let mut builder = MatchSetBuilder::new();
            for value in values {
                builder.add_ip_cidr(value)?;
            }
            CompiledField::Cidr(builder.build()?)
        }
        RouteMatchField::Port(mut values) => {
            validate_unique(&mut values)?;
            CompiledField::Port(values.into_boxed_slice())
        }
        RouteMatchField::PortRange(mut values) => {
            validate_unique(&mut values)?;
            CompiledField::PortRange(values.into_boxed_slice())
        }
        RouteMatchField::MatchSet(values) => {
            if values.is_empty() {
                return Err(RuleCompileError::EmptyField);
            }
            CompiledField::MatchSet(values)
        }
        RouteMatchField::RuleSet(mut values) => {
            validate_unique(&mut values)?;
            CompiledField::RuleSet(values.into_boxed_slice())
        }
    })
}

fn validate_unique<T: Ord>(values: &mut [T]) -> Result<(), RuleCompileError> {
    if values.is_empty() {
        return Err(RuleCompileError::EmptyField);
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(RuleCompileError::DuplicateValue)
    } else {
        Ok(())
    }
}

fn validate_unique_eq<T: Eq>(values: &[T]) -> Result<(), RuleCompileError> {
    if values.is_empty() {
        return Err(RuleCompileError::EmptyField);
    }
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        Err(RuleCompileError::DuplicateValue)
    } else {
        Ok(())
    }
}

fn matches_field<P: Eq>(
    field: &CompiledField<P>,
    inbound: usize,
    network: Network,
    original: &TargetAddr,
    metadata: &RouteMetadata<'_, P>,
    snapshot: Option<&RuleEngineSnapshot>,
) -> bool {
    let domain = selected_domain(original, metadata);
    let address = match original.host() {
        TargetHostRef::Ip(address) => Some(address),
        TargetHostRef::Domain(_) => None,
    };
    match field {
        CompiledField::Inbound(values) => values.contains(&inbound),
        CompiledField::Network(values) => values.contains(&network),
        CompiledField::Protocol(values) => metadata
            .protocol
            .as_ref()
            .is_some_and(|protocol| values.contains(protocol)),
        CompiledField::Domain(values)
        | CompiledField::DomainSuffix(values)
        | CompiledField::DomainKeyword(values) => {
            domain.is_some_and(|domain| values.matches_domain(domain))
        }
        CompiledField::Ip(values) | CompiledField::Cidr(values) => {
            address.is_some_and(|address| values.matches_ip(address))
        }
        CompiledField::Port(values) => values.contains(&original.port()),
        CompiledField::PortRange(values) => {
            values.iter().any(|range| range.contains(original.port()))
        }
        CompiledField::MatchSet(values) => values.matches(domain, address),
        CompiledField::RuleSet(values) => snapshot.is_some_and(|snapshot| {
            values
                .iter()
                .any(|rule_set| snapshot.matches_rule_set(*rule_set, domain, address))
        }),
    }
}

fn selected_domain<'a, P>(
    original: &'a TargetAddr,
    metadata: &'a RouteMetadata<'_, P>,
) -> Option<&'a CanonicalDomain> {
    match metadata.detected_domain {
        Some(domain) => domain.canonical(),
        None => original.canonical_domain(),
    }
}

/// Caller-owned recognized metadata used by one ordered evaluation step.
pub struct RouteMetadata<'a, P> {
    protocol: Option<P>,
    detected_domain: Option<&'a DomainName>,
}

impl<'a, P> RouteMetadata<'a, P> {
    pub const fn new(protocol: Option<P>, detected_domain: Option<&'a DomainName>) -> Self {
        Self {
            protocol,
            detected_domain,
        }
    }
}

/// Generic continuation or terminal behavior attached to one matched rule.
pub enum RouteRuleAction<A> {
    Continue(A),
    Terminal(A),
}

/// One ordered generic rule.
pub struct OrderedRouteRule<P, A> {
    matcher: RouteMatcher<P>,
    action: RouteRuleAction<A>,
}

impl<P, A> OrderedRouteRule<P, A> {
    pub const fn new(matcher: RouteMatcher<P>, action: RouteRuleAction<A>) -> Self {
        Self { matcher, action }
    }
}

struct ConstraintIndex<P> {
    masks: [Box<[u64]>; FIELD_KIND_COUNT],
    inbound: SparseValueIndex<usize>,
    network: SparseValueIndex<Network>,
    protocol: SparseValueIndex<P>,
    domain: MatchCandidateIndex,
    suffix: MatchCandidateIndex,
    keyword: MatchCandidateIndex,
    ip: MatchCandidateIndex,
    cidr: MatchCandidateIndex,
    port: SparseValueIndex<NonZeroU16>,
    port_range: PortRangeCandidateIndex,
    match_set: MatchCandidateIndex,
    rule_set: SparseValueIndex<RuleSetId>,
}

/// One reusable ordered program with a mandatory final action.
pub struct OrderedRouteProgram<P, A> {
    compiled: CompiledRuleProgram<OrderedRouteRule<P, A>, ConstraintIndex<P>>,
    final_action: A,
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

impl<P: Ord, A> OrderedRouteProgram<P, A> {
    #[allow(clippy::too_many_arguments)]
    fn find_next(
        &self,
        cursor: usize,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
        scratch: &mut RuleEvaluationScratch,
    ) -> Option<usize> {
        scratch.candidate_visits = 0;
        if self.compiled.mode() == RuleProgramMode::SmallLinear {
            for (offset, rule) in self.compiled.rules()[cursor..].iter().enumerate() {
                scratch.candidate_visits = scratch.candidate_visits.saturating_add(1);
                if rule
                    .matcher
                    .matches(inbound, network, original, metadata, snapshot)
                {
                    return Some(cursor + offset);
                }
            }
            return None;
        }

        let constraints = self.compiled.index().expect("indexed constraints");
        scratch.fill_candidates(self.compiled.len(), cursor);
        for kind in FieldKind::ALL {
            let mask = &constraints.masks[kind.index()];
            if mask.iter().all(|word| *word == 0) {
                continue;
            }
            scratch.matched.fill(0);
            constraints.visit_matches(
                kind,
                inbound,
                network,
                original,
                metadata,
                snapshot,
                &mut scratch.matched,
                &mut scratch.candidate_visits,
            );
            for ((candidate, constraint), matched) in scratch
                .candidates
                .iter_mut()
                .zip(mask.iter())
                .zip(scratch.matched.iter())
            {
                *candidate &= !constraint | matched;
            }
            if scratch.candidates.iter().all(|word| *word == 0) {
                return None;
            }
        }
        first_set_bit(&scratch.candidates, cursor)
    }
}

#[allow(clippy::too_many_lines)]
fn build_constraints<P: Clone + Ord, A>(
    rules: &[OrderedRouteRule<P, A>],
) -> Result<ConstraintIndex<P>, RuleCompileError> {
    let words = words_for(rules.len());
    let mut masks: [Vec<u64>; FIELD_KIND_COUNT] = std::array::from_fn(|_| Vec::new());
    for mask in &mut masks {
        mask.try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        mask.resize(words, 0);
    }
    let mut inbound = SparseValueIndexBuilder::new();
    let mut network = SparseValueIndexBuilder::new();
    let mut protocol = SparseValueIndexBuilder::new();
    let mut domain = MatchCandidateIndexBuilder::new();
    let mut suffix = MatchCandidateIndexBuilder::new();
    let mut keyword = MatchCandidateIndexBuilder::new();
    let mut ip = MatchCandidateIndexBuilder::new();
    let mut cidr = MatchCandidateIndexBuilder::new();
    let mut port = SparseValueIndexBuilder::new();
    let mut port_range = PortRangeCandidateIndexBuilder::new();
    let mut match_set = MatchCandidateIndexBuilder::new();
    let mut rule_set = SparseValueIndexBuilder::new();
    for (index, rule) in rules.iter().enumerate() {
        for field in &rule.matcher.fields {
            set_bit(&mut masks[field.kind().index()], index);
            match field {
                CompiledField::Inbound(values) => {
                    for value in values {
                        inbound.try_add(*value, index)?;
                    }
                }
                CompiledField::Network(values) => {
                    for value in values {
                        network.try_add(*value, index)?;
                    }
                }
                CompiledField::Protocol(values) => {
                    for value in values {
                        protocol.try_add(value.clone(), index)?;
                    }
                }
                CompiledField::Domain(values) => {
                    domain.try_add_match_set(index, values, MatchCategories::EXACT)?;
                }
                CompiledField::DomainSuffix(values) => {
                    suffix.try_add_match_set(index, values, MatchCategories::SUFFIX)?;
                }
                CompiledField::DomainKeyword(values) => {
                    keyword.try_add_match_set(index, values, MatchCategories::KEYWORD)?;
                }
                CompiledField::Ip(values) => {
                    ip.try_add_match_set(index, values, MatchCategories::IP)?;
                }
                CompiledField::Cidr(values) => {
                    cidr.try_add_match_set(index, values, MatchCategories::IP)?;
                }
                CompiledField::Port(values) => {
                    for value in values {
                        port.try_add(*value, index)?;
                    }
                }
                CompiledField::PortRange(values) => {
                    for value in values {
                        port_range.try_add(value.first, value.last, index)?;
                    }
                }
                CompiledField::MatchSet(values) => {
                    match_set.try_add_match_set(index, values, MatchCategories::ALL)?;
                }
                CompiledField::RuleSet(values) => {
                    for value in values {
                        rule_set.try_add(*value, index)?;
                    }
                }
            }
        }
    }
    Ok(ConstraintIndex {
        masks: masks.map(Vec::into_boxed_slice),
        inbound: inbound.build()?,
        network: network.build()?,
        protocol: protocol.build()?,
        domain: domain.build()?,
        suffix: suffix.build()?,
        keyword: keyword.build()?,
        ip: ip.build()?,
        cidr: cidr.build()?,
        port: port.build()?,
        port_range: port_range.build()?,
        match_set: match_set.build()?,
        rule_set: rule_set.build()?,
    })
}

impl<P: Ord> ConstraintIndex<P> {
    #[allow(clippy::too_many_arguments)]
    fn visit_matches(
        &self,
        kind: FieldKind,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
        matched: &mut [u64],
        visits: &mut usize,
    ) {
        let domain = selected_domain(original, metadata);
        let address = match original.host() {
            TargetHostRef::Ip(address) => Some(address),
            TargetHostRef::Domain(_) => None,
        };
        let mut mark = |candidate| {
            *visits = visits.saturating_add(1);
            set_bit(matched, candidate as usize);
        };
        match kind {
            FieldKind::Inbound => self.inbound.visit(&inbound, mark),
            FieldKind::Network => self.network.visit(&network, mark),
            FieldKind::Protocol => {
                if let Some(protocol) = metadata.protocol.as_ref() {
                    self.protocol.visit(protocol, mark);
                }
            }
            FieldKind::Domain => self.domain.visit_matches(domain, None, mark),
            FieldKind::DomainSuffix => self.suffix.visit_matches(domain, None, mark),
            FieldKind::DomainKeyword => self.keyword.visit_matches(domain, None, mark),
            FieldKind::Ip => self.ip.visit_matches(None, address, mark),
            FieldKind::Cidr => self.cidr.visit_matches(None, address, mark),
            FieldKind::Port => self.port.visit(&original.port(), mark),
            FieldKind::PortRange => self.port_range.visit(original.port(), mark),
            FieldKind::MatchSet => self.match_set.visit_matches(domain, address, mark),
            FieldKind::RuleSet => {
                if let Some(snapshot) = snapshot {
                    snapshot.visit_matching_rule_sets(domain, address, |rule_set| {
                        self.rule_set.visit(&rule_set, &mut mark);
                    });
                }
            }
        }
    }
}

/// Reusable bitmap workspace for indexed evaluation.
pub struct RuleEvaluationScratch {
    candidates: Vec<u64>,
    matched: Vec<u64>,
    candidate_visits: usize,
}

impl RuleEvaluationScratch {
    pub fn try_for_program<P, A>(
        program: &OrderedRouteProgram<P, A>,
    ) -> Result<Self, RuleCompileError> {
        let words = if program.compiled.mode() == RuleProgramMode::Indexed {
            words_for(program.compiled.len())
        } else {
            0
        };
        let mut candidates = Vec::new();
        let mut matched = Vec::new();
        candidates
            .try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        matched
            .try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        candidates.resize(words, 0);
        matched.resize(words, 0);
        Ok(Self {
            candidates,
            matched,
            candidate_visits: 0,
        })
    }

    /// Returns the retained bitmap capacities for allocation-regression tests.
    pub fn reserved_words(&self) -> (usize, usize) {
        (self.candidates.capacity(), self.matched.capacity())
    }

    /// Returns the number of sparse posting candidates visited by the last step.
    /// This is a deterministic benchmark and selectivity-regression seam.
    pub const fn candidate_visits(&self) -> usize {
        self.candidate_visits
    }

    fn assert_words(&self, words: usize) {
        assert!(
            self.candidates.len() >= words && self.matched.len() >= words,
            "rule evaluation scratch is undersized for this program"
        );
    }

    fn fill_candidates(&mut self, rules: usize, cursor: usize) {
        let words = words_for(rules);
        self.candidates.fill(0);
        self.candidates[..words].fill(u64::MAX);
        if let Some(last) = self.candidates.get_mut(words.saturating_sub(1)) {
            let used = rules % 64;
            if used != 0 {
                *last &= (1_u64 << used) - 1;
            }
        }
        let whole_words = cursor / 64;
        self.candidates[..whole_words.min(words)].fill(0);
        if whole_words < words {
            self.candidates[whole_words] &= u64::MAX << (cursor % 64);
        }
    }
}

fn words_for(bits: usize) -> usize {
    bits.div_ceil(64)
}

fn set_bit(words: &mut [u64], index: usize) {
    words[index / 64] |= 1_u64 << (index % 64);
}

fn first_set_bit(words: &[u64], cursor: usize) -> Option<usize> {
    for (word_index, word) in words.iter().copied().enumerate().skip(cursor / 64) {
        let mut word = word;
        if word_index == cursor / 64 {
            word &= u64::MAX << (cursor % 64);
        }
        if word != 0 {
            return Some(word_index * 64 + word.trailing_zeros() as usize);
        }
    }
    None
}

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
    program: &'program OrderedRouteProgram<P, A>,
    inbound: usize,
    network: Network,
    original: &'target TargetAddr,
    cursor: usize,
    finished: bool,
    snapshot: Option<Arc<RuleEngineSnapshot>>,
    scratch: &'scratch mut RuleEvaluationScratch,
    observe_matches: bool,
    last_match: RouteMatchObservation,
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
