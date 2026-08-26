use std::net::IpAddr;
use std::num::NonZeroU16;

use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr, TargetHostRef};
use ipnet::IpNet;

use crate::{CompiledMatchSet, MatchSetBuilder, RuleCompileError, RuleEngineSnapshot, RuleSetId};

pub(super) const FIELD_KIND_COUNT: usize = 12;

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
pub(super) enum FieldKind {
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
    pub(super) const ALL: [Self; FIELD_KIND_COUNT] = [
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

    pub(super) const fn index(self) -> usize {
        self as usize
    }
}

pub(super) enum CompiledField<P> {
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
    pub(super) const fn kind(&self) -> FieldKind {
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
    pub(super) fields: Box<[CompiledField<P>]>,
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

    pub(super) fn observation(
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

pub(super) fn selected_domain<'a, P>(
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
    pub(super) protocol: Option<P>,
    pub(super) detected_domain: Option<&'a DomainName>,
}

impl<'a, P> RouteMetadata<'a, P> {
    pub const fn new(protocol: Option<P>, detected_domain: Option<&'a DomainName>) -> Self {
        Self {
            protocol,
            detected_domain,
        }
    }
}
