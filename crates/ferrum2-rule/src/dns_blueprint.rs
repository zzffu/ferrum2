use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;
use std::sync::Arc;

use ferrum2_core::route::Network;

use crate::{CompiledMatchSet, PortRange, RuleEngineSnapshot, RuleSetId};

/// Runtime-neutral address-family preference attached to one DNS policy route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyAddressStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

/// Runtime-neutral DNS upstream identity and address-family strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPolicyRouteDescriptor {
    server: u32,
    strategy: DnsPolicyAddressStrategy,
}

impl DnsPolicyRouteDescriptor {
    pub const fn new(server: u32, strategy: DnsPolicyAddressStrategy) -> Self {
        Self { server, strategy }
    }

    pub const fn server(self) -> u32 {
        self.server
    }

    pub const fn strategy(self) -> DnsPolicyAddressStrategy {
        self.strategy
    }
}

/// Closed action retained by a runtime-neutral DNS policy row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyActionDescriptor {
    Route(DnsPolicyRouteDescriptor),
    Evaluate(DnsPolicyRouteDescriptor),
    Respond,
    Reject,
}

/// Selects query matching or matching against the latest evaluated response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyMatchMode {
    Query,
    Response,
}

/// One validated conjunction of DNS query fields and RuleSet references.
///
/// Query types are their stable DNS wire codes. No Hickory or resolver type is
/// retained here, keeping the rule/configuration layer runtime-neutral.
#[derive(Clone)]
pub struct DnsPolicyMatcherDescriptor {
    query_fields: Arc<[Arc<CompiledMatchSet>]>,
    rule_sets: Arc<[RuleSetId]>,
    inbounds: Box<[usize]>,
    networks: Box<[Network]>,
    qtypes: Box<[u16]>,
    ports: Box<[NonZeroU16]>,
    port_ranges: Box<[PortRange]>,
}

/// Owned fields transferred from a validated matcher descriptor to an
/// execution adapter without retaining a second copy.
pub struct DnsPolicyMatcherDescriptorParts {
    pub query_fields: Arc<[Arc<CompiledMatchSet>]>,
    pub rule_sets: Arc<[RuleSetId]>,
    pub inbounds: Box<[usize]>,
    pub networks: Box<[Network]>,
    pub qtypes: Box<[u16]>,
    pub ports: Box<[NonZeroU16]>,
    pub port_ranges: Box<[PortRange]>,
}

impl DnsPolicyMatcherDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        query_fields: Vec<Arc<CompiledMatchSet>>,
        rule_sets: Vec<RuleSetId>,
        inbounds: Vec<usize>,
        networks: Vec<Network>,
        qtypes: Vec<u16>,
        ports: Vec<NonZeroU16>,
        port_ranges: Vec<PortRange>,
    ) -> Result<Self, DnsPolicyBlueprintError> {
        if query_fields.iter().any(|field| {
            let capabilities = field.capabilities();
            field.is_empty()
                || capabilities.ip_cidr
                || !(capabilities.exact_domain
                    || capabilities.domain_suffix
                    || capabilities.domain_keyword)
        }) {
            return Err(DnsPolicyBlueprintError::InvalidQueryMatchSet);
        }
        if has_duplicate(&rule_sets)
            || has_duplicate(&inbounds)
            || has_duplicate(&networks)
            || has_duplicate(&qtypes)
            || has_duplicate(&ports)
            || has_duplicate(&port_ranges)
        {
            return Err(DnsPolicyBlueprintError::DuplicateConstraint);
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

    pub fn query_fields(&self) -> &[Arc<CompiledMatchSet>] {
        &self.query_fields
    }

    pub fn rule_sets(&self) -> &[RuleSetId] {
        &self.rule_sets
    }

    pub fn inbounds(&self) -> &[usize] {
        &self.inbounds
    }

    pub fn networks(&self) -> &[Network] {
        &self.networks
    }

    pub fn qtypes(&self) -> &[u16] {
        &self.qtypes
    }

    pub fn ports(&self) -> &[NonZeroU16] {
        &self.ports
    }

    pub fn port_ranges(&self) -> &[PortRange] {
        &self.port_ranges
    }

    pub fn into_parts(self) -> DnsPolicyMatcherDescriptorParts {
        DnsPolicyMatcherDescriptorParts {
            query_fields: self.query_fields,
            rule_sets: self.rule_sets,
            inbounds: self.inbounds,
            networks: self.networks,
            qtypes: self.qtypes,
            ports: self.ports,
            port_ranges: self.port_ranges,
        }
    }
}

impl fmt::Debug for DnsPolicyMatcherDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyMatcherDescriptor([redacted])")
    }
}

/// One ordered, statically validated DNS policy row.
#[derive(Clone)]
pub struct DnsPolicyRuleDescriptor {
    matcher: DnsPolicyMatcherDescriptor,
    mode: DnsPolicyMatchMode,
    action: DnsPolicyActionDescriptor,
}

impl DnsPolicyRuleDescriptor {
    pub const fn new(
        matcher: DnsPolicyMatcherDescriptor,
        mode: DnsPolicyMatchMode,
        action: DnsPolicyActionDescriptor,
    ) -> Self {
        Self {
            matcher,
            mode,
            action,
        }
    }

    pub const fn matcher(&self) -> &DnsPolicyMatcherDescriptor {
        &self.matcher
    }

    pub const fn mode(&self) -> DnsPolicyMatchMode {
        self.mode
    }

    pub const fn action(&self) -> DnsPolicyActionDescriptor {
        self.action
    }

    pub fn into_parts(
        self,
    ) -> (
        DnsPolicyMatcherDescriptor,
        DnsPolicyMatchMode,
        DnsPolicyActionDescriptor,
    ) {
        (self.matcher, self.mode, self.action)
    }
}

impl fmt::Debug for DnsPolicyRuleDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyRuleDescriptor([redacted])")
    }
}

/// Closed runtime-neutral DNS policy ready for the DNS execution adapter.
#[derive(Clone)]
pub struct DnsPolicyBlueprint {
    rules: Box<[DnsPolicyRuleDescriptor]>,
    response_rules: usize,
    final_route: DnsPolicyRouteDescriptor,
}

impl DnsPolicyBlueprint {
    /// Validates stage ordering and RuleSet capabilities against the exact
    /// initial snapshot that will also back ordinary Route matching.
    pub fn try_new(
        rules: Vec<DnsPolicyRuleDescriptor>,
        final_route: DnsPolicyRouteDescriptor,
        validation_snapshot: &RuleEngineSnapshot,
    ) -> Result<Self, DnsPolicyBlueprintError> {
        if rules.len() > u32::MAX as usize {
            return Err(DnsPolicyBlueprintError::IndexOverflow);
        }
        let mut response_rules = 0_usize;
        let mut evaluated = false;
        for rule in &rules {
            if rule.mode == DnsPolicyMatchMode::Response && !evaluated {
                return Err(DnsPolicyBlueprintError::ResponseMatchWithoutEvaluate);
            }
            if rule.action == DnsPolicyActionDescriptor::Respond && !evaluated {
                return Err(DnsPolicyBlueprintError::RespondWithoutEvaluate);
            }
            for rule_set in rule.matcher.rule_sets.iter().copied() {
                let descriptor = validation_snapshot
                    .rule_set(rule_set)
                    .ok_or(DnsPolicyBlueprintError::UnknownRuleSet)?;
                match rule.mode {
                    DnsPolicyMatchMode::Query => {
                        if descriptor.capabilities().ip_cidr {
                            return Err(DnsPolicyBlueprintError::QueryModeCidrRuleSet);
                        }
                    }
                    DnsPolicyMatchMode::Response => {
                        if !descriptor.capabilities().ip_cidr {
                            return Err(DnsPolicyBlueprintError::ResponseModeRequiresCidrRuleSet);
                        }
                    }
                }
            }
            response_rules += usize::from(rule.mode == DnsPolicyMatchMode::Response);
            evaluated |= matches!(rule.action, DnsPolicyActionDescriptor::Evaluate(_));
        }
        Ok(Self {
            rules: rules.into_boxed_slice(),
            response_rules,
            final_route,
        })
    }

    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub const fn response_rule_count(&self) -> usize {
        self.response_rules
    }

    pub const fn final_route(&self) -> DnsPolicyRouteDescriptor {
        self.final_route
    }

    pub fn rules(&self) -> &[DnsPolicyRuleDescriptor] {
        &self.rules
    }

    pub fn into_parts(self) -> (Box<[DnsPolicyRuleDescriptor]>, DnsPolicyRouteDescriptor) {
        (self.rules, self.final_route)
    }
}

impl fmt::Debug for DnsPolicyBlueprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyBlueprint([redacted])")
    }
}

/// Closed validation failures for runtime-neutral DNS policy blueprints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicyBlueprintError {
    InvalidQueryMatchSet,
    DuplicateConstraint,
    UnknownRuleSet,
    QueryModeCidrRuleSet,
    ResponseModeRequiresCidrRuleSet,
    ResponseMatchWithoutEvaluate,
    RespondWithoutEvaluate,
    IndexOverflow,
}

impl fmt::Display for DnsPolicyBlueprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidQueryMatchSet => "DNS query field has an unsupported matcher",
            Self::DuplicateConstraint => "DNS policy field contains a duplicate constraint",
            Self::UnknownRuleSet => "DNS policy references an unknown RuleSet",
            Self::QueryModeCidrRuleSet => {
                "DNS query matching cannot reference a CIDR-capable RuleSet"
            }
            Self::ResponseModeRequiresCidrRuleSet => {
                "DNS response matching requires a CIDR-capable RuleSet"
            }
            Self::ResponseMatchWithoutEvaluate => {
                "DNS response matching requires a preceding evaluate action"
            }
            Self::RespondWithoutEvaluate => "DNS respond requires a preceding evaluate action",
            Self::IndexOverflow => "DNS policy index capacity was exceeded",
        })
    }
}

impl Error for DnsPolicyBlueprintError {}

fn has_duplicate<T: Ord + Copy>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
