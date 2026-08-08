use super::selector::{
    MAX_SELECTOR_MEMBERS, MAX_SELECTORS, OutboundAction, Selector, SelectorCompileError,
    SelectorControl, SelectorDefinition, SelectorMember, SelectorState, TaggedInbound,
    TaggedOutbound, TaggedPlan, TaggedRoute,
};
use super::{TargetAddr, TargetHost};
use ipnet::IpNet;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// Maximum number of rules retained by one route table.
pub const MAX_ROUTE_RULES: usize = 64;
/// Maximum total matcher values retained by one ordered route rule.
pub const MAX_ROUTE_VALUES: usize = 64;

/// One selected immutable ordered plan of concrete outbound identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressPlan<'a> {
    hops: &'a [usize],
}

impl<'a> EgressPlan<'a> {
    /// Returns every concrete outbound in configured traversal order.
    pub const fn hops(self) -> &'a [usize] {
        self.hops
    }
}

/// One owned immutable ordered plan of concrete outbound identities.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EgressPlanSnapshot {
    hops: Arc<[usize]>,
}

impl EgressPlanSnapshot {
    /// Returns every concrete outbound in configured traversal order.
    pub fn hops(&self) -> &[usize] {
        &self.hops
    }
}

impl std::fmt::Debug for EgressPlanSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EgressPlanSnapshot([redacted])")
    }
}

/// Transport network presented to route selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

/// One validated inclusive non-zero port interval.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PortRange {
    first: NonZeroU16,
    last: NonZeroU16,
}

impl PortRange {
    /// Validates an inclusive non-zero port interval.
    pub fn new(first: u16, last: u16) -> Option<Self> {
        let (first, last) = (NonZeroU16::new(first)?, NonZeroU16::new(last)?);
        (first <= last).then_some(Self { first, last })
    }

    fn contains(self, port: NonZeroU16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

/// One matcher field. Values within a field are ORed; distinct fields are ANDed.
pub enum RouteMatchField<P> {
    Inbound(Vec<usize>),
    Network(Vec<Network>),
    Protocol(Vec<P>),
    Domain(Vec<super::DomainName>),
    DomainSuffix(Vec<super::DomainName>),
    Ip(Vec<IpAddr>),
    Cidr(Vec<IpNet>),
    Port(Vec<NonZeroU16>),
    PortRange(Vec<PortRange>),
    Target(Vec<TargetAddr>),
}

impl<P: Eq> RouteMatchField<P> {
    fn values_are_valid(&self) -> bool {
        fn unique<T: Eq>(values: &[T]) -> bool {
            !values.is_empty()
                && !values
                    .iter()
                    .enumerate()
                    .any(|(index, value)| values[..index].contains(value))
        }

        match self {
            Self::Inbound(values) => unique(values),
            Self::Network(values) => unique(values),
            Self::Protocol(values) => unique(values),
            Self::Domain(values) | Self::DomainSuffix(values) => {
                !values.is_empty()
                    && values.iter().enumerate().all(|(index, value)| {
                        let value = normalized_domain(value.as_str());
                        !value.is_empty()
                            && !values[..index].iter().any(|other| {
                                normalized_domain(other.as_str()).eq_ignore_ascii_case(value)
                            })
                    })
            }
            Self::Ip(values) => unique(values),
            Self::Cidr(values) => {
                unique(values)
                    && values
                        .iter()
                        .all(|network| network.addr() == network.network())
            }
            Self::Port(values) => unique(values),
            Self::PortRange(values) => unique(values),
            Self::Target(values) => unique(values),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Inbound(values) => values.len(),
            Self::Network(values) => values.len(),
            Self::Protocol(values) => values.len(),
            Self::Domain(values) | Self::DomainSuffix(values) => values.len(),
            Self::Ip(values) => values.len(),
            Self::Cidr(values) => values.len(),
            Self::Port(values) => values.len(),
            Self::PortRange(values) => values.len(),
            Self::Target(values) => values.len(),
        }
    }
}

/// One bounded conjunction of generic route matcher fields.
pub struct RouteMatcher<P> {
    fields: Vec<RouteMatchField<P>>,
}

impl<P: Eq> RouteMatcher<P> {
    /// Validates one matcher, including the 64-value bound and one occurrence per field.
    pub fn new(fields: Vec<RouteMatchField<P>>) -> Option<Self> {
        let total = fields.iter().map(RouteMatchField::len).sum::<usize>();
        let distinct = !fields.iter().enumerate().any(|(index, field)| {
            fields[..index]
                .iter()
                .any(|other| std::mem::discriminant(other) == std::mem::discriminant(field))
        });
        let mixes_legacy_target = fields
            .iter()
            .any(|field| matches!(field, RouteMatchField::Target(_)))
            && fields.iter().any(|field| {
                matches!(
                    field,
                    RouteMatchField::Domain(_)
                        | RouteMatchField::DomainSuffix(_)
                        | RouteMatchField::Ip(_)
                        | RouteMatchField::Cidr(_)
                        | RouteMatchField::Port(_)
                        | RouteMatchField::PortRange(_)
                )
            });
        (total <= MAX_ROUTE_VALUES
            && distinct
            && !mixes_legacy_target
            && fields.iter().all(RouteMatchField::values_are_valid))
        .then_some(Self { fields })
    }

    fn legacy(
        inbound: Option<usize>,
        network: Option<Network>,
        target: Option<TargetAddr>,
    ) -> Self {
        let mut fields = Vec::with_capacity(3);
        if let Some(inbound) = inbound {
            fields.push(RouteMatchField::Inbound(vec![inbound]));
        }
        if let Some(network) = network {
            fields.push(RouteMatchField::Network(vec![network]));
        }
        if let Some(target) = target {
            fields.push(RouteMatchField::Target(vec![target]));
        }
        Self::new(fields).expect("legacy matcher is bounded")
    }

    fn matches(
        &self,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
    ) -> bool {
        self.fields.iter().all(|field| match field {
            RouteMatchField::Inbound(values) => values.contains(&inbound),
            RouteMatchField::Network(values) => values.contains(&network),
            RouteMatchField::Protocol(values) => metadata
                .protocol
                .as_ref()
                .is_some_and(|protocol| values.contains(protocol)),
            RouteMatchField::Domain(values) => selected_domain(original, metadata)
                .is_some_and(|actual| values.iter().any(|value| domain_eq(value.as_str(), actual))),
            RouteMatchField::DomainSuffix(values) => selected_domain(original, metadata)
                .is_some_and(|actual| {
                    values
                        .iter()
                        .any(|value| domain_suffix(value.as_str(), actual))
                }),
            RouteMatchField::Ip(values) => match original.host {
                TargetHost::Ip(actual) => values.contains(&actual),
                TargetHost::Domain(_) => false,
            },
            RouteMatchField::Cidr(values) => match original.host {
                TargetHost::Ip(actual) => values.iter().any(|network| network.contains(&actual)),
                TargetHost::Domain(_) => false,
            },
            RouteMatchField::Port(values) => values.contains(&original.port),
            RouteMatchField::PortRange(values) => {
                values.iter().any(|range| range.contains(original.port))
            }
            RouteMatchField::Target(values) => values
                .iter()
                .any(|expected| legacy_target_matches(expected, original)),
        })
    }
}

fn selected_domain<'a, P>(
    original: &'a TargetAddr,
    metadata: &'a RouteMetadata<'_, P>,
) -> Option<&'a str> {
    metadata
        .detected_domain
        .map(super::DomainName::as_str)
        .or_else(|| match &original.host {
            TargetHost::Domain(domain) => Some(domain.as_str()),
            TargetHost::Ip(_) => None,
        })
}

fn normalized_domain(value: &str) -> &str {
    value.strip_suffix('.').unwrap_or(value)
}

fn domain_eq(expected: &str, actual: &str) -> bool {
    normalized_domain(expected).eq_ignore_ascii_case(normalized_domain(actual))
}

fn domain_suffix(expected: &str, actual: &str) -> bool {
    let (expected, actual) = (normalized_domain(expected), normalized_domain(actual));
    actual.eq_ignore_ascii_case(expected)
        || actual
            .len()
            .checked_sub(expected.len() + 1)
            .is_some_and(|boundary| {
                actual.as_bytes()[boundary] == b'.'
                    && actual[boundary + 1..].eq_ignore_ascii_case(expected)
            })
}

fn legacy_target_matches(expected: &TargetAddr, actual: &TargetAddr) -> bool {
    expected.port == actual.port
        && match (&expected.host, &actual.host) {
            (TargetHost::Ip(expected), TargetHost::Ip(actual)) => expected == actual,
            (TargetHost::Domain(expected), TargetHost::Domain(actual)) => {
                expected.as_str().eq_ignore_ascii_case(actual.as_str())
            }
            _ => false,
        }
}

/// Caller-owned recognized metadata used by one ordered evaluation step.
pub struct RouteMetadata<'a, P> {
    protocol: Option<P>,
    detected_domain: Option<&'a super::DomainName>,
}

impl<'a, P> RouteMetadata<'a, P> {
    pub const fn new(protocol: Option<P>, detected_domain: Option<&'a super::DomainName>) -> Self {
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

/// One reusable bounded ordered program with a mandatory final action.
pub struct OrderedRouteProgram<P, A> {
    rules: Vec<OrderedRouteRule<P, A>>,
    final_action: A,
}

impl<P, A> OrderedRouteProgram<P, A> {
    pub fn new(rules: Vec<OrderedRouteRule<P, A>>, final_action: A) -> Option<Self> {
        (rules.len() <= MAX_ROUTE_RULES).then_some(Self {
            rules,
            final_action,
        })
    }

    /// Starts one evaluation with an immutable original target and private cursor.
    pub fn evaluate<'program, 'target>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
    ) -> RouteProgramEvaluation<'program, 'target, P, A> {
        RouteProgramEvaluation {
            program: self,
            inbound,
            network,
            original,
            cursor: 0,
            finished: false,
        }
    }
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

/// One private-cursor evaluation borrowing a reusable ordered program.
pub struct RouteProgramEvaluation<'program, 'target, P, A> {
    program: &'program OrderedRouteProgram<P, A>,
    inbound: usize,
    network: Network,
    original: &'target TargetAddr,
    cursor: usize,
    finished: bool,
}

impl<'program, P: Eq, A> RouteProgramEvaluation<'program, '_, P, A> {
    /// Returns the next matching action, or the mandatory final exactly once.
    pub fn next(
        &mut self,
        metadata: RouteMetadata<'_, P>,
    ) -> Option<RouteProgramAction<'program, A>> {
        if self.finished {
            return None;
        }
        while let Some(rule) = self.program.rules.get(self.cursor) {
            self.cursor += 1;
            if rule
                .matcher
                .matches(self.inbound, self.network, self.original, &metadata)
            {
                return match &rule.action {
                    RouteRuleAction::Continue(action) => Some(RouteProgramAction::Continue(action)),
                    RouteRuleAction::Terminal(action) => {
                        self.finished = true;
                        Some(RouteProgramAction::Terminal(action))
                    }
                };
            }
        }
        self.finished = true;
        Some(RouteProgramAction::Final(&self.program.final_action))
    }
}

/// One runtime-neutral first-match rule with a resolved action.
pub struct ActionRule<A> {
    inbound: Option<usize>,
    network: Option<Network>,
    target: Option<TargetAddr>,
    action: A,
}

impl<A> ActionRule<A> {
    pub fn new(
        inbound: Option<usize>,
        network: Option<Network>,
        target: Option<TargetAddr>,
        action: A,
    ) -> Self {
        Self {
            inbound,
            network,
            target,
            action,
        }
    }

    fn matches(&self, inbound: usize, network: Network, target: &TargetAddr) -> bool {
        self.inbound.is_none_or(|expected| expected == inbound)
            && self.network.is_none_or(|expected| expected == network)
            && self
                .target
                .as_ref()
                .is_none_or(|expected| legacy_target_matches(expected, target))
    }
}

/// One bounded ordered first-match table with a mandatory final action.
pub struct ActionTable<A> {
    rules: Vec<ActionRule<A>>,
    final_action: A,
}

impl<A> ActionTable<A> {
    pub fn new(rules: Vec<ActionRule<A>>, final_action: A) -> Option<Self> {
        (rules.len() <= MAX_ROUTE_RULES).then_some(Self {
            rules,
            final_action,
        })
    }
}

impl<A: Copy> ActionTable<A> {
    /// Returns the mandatory action used when no rule can be evaluated or matched.
    pub const fn final_action(&self) -> A {
        self.final_action
    }

    /// Selects the first matching action or the mandatory final action.
    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> A {
        self.rules
            .iter()
            .find(|rule| rule.matches(inbound, network, target))
            .map_or(self.final_action, |rule| rule.action)
    }
}

/// One ordinary direct outbound rule retained for API compatibility.
pub struct RouteRule {
    matcher: RouteMatcher<()>,
    outbound: usize,
}

impl RouteRule {
    pub fn new(
        inbound: Option<usize>,
        network: Option<Network>,
        target: Option<TargetAddr>,
        outbound: usize,
    ) -> Self {
        Self {
            matcher: RouteMatcher::legacy(inbound, network, target),
            outbound,
        }
    }

    fn into_ordered(self, action: OutboundAction) -> OrderedRouteRule<(), OutboundAction> {
        OrderedRouteRule::new(self.matcher, RouteRuleAction::Terminal(action))
    }
}

/// A resolved egress action that snapshots one complete immutable plan when selected.
#[derive(Clone)]
pub struct EgressPlanHandle {
    action: OutboundAction,
    selectors: Arc<SelectorState>,
    plans: Arc<Vec<Arc<[usize]>>>,
}

impl EgressPlanHandle {
    /// Constructs one immutable single-outbound action.
    pub fn direct(outbound: usize) -> Self {
        Self {
            action: OutboundAction::Plan(0),
            selectors: Arc::default(),
            plans: Arc::new(vec![Arc::from([outbound])]),
        }
    }

    /// Selects the current concrete plan without changing selector state.
    pub fn snapshot(&self) -> EgressPlan<'_> {
        EgressPlan {
            hops: self.plans[self.selectors.resolve(self.action)].as_ref(),
        }
    }

    /// Selects the current concrete plan as an owned immutable snapshot.
    pub fn snapshot_owned(&self) -> EgressPlanSnapshot {
        EgressPlanSnapshot {
            hops: Arc::clone(&self.plans[self.selectors.resolve(self.action)]),
        }
    }
}

impl std::fmt::Debug for EgressPlanHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EgressPlanHandle([redacted])")
    }
}

/// A compiled route table whose selection always returns an outbound identity.
pub struct RouteTable {
    program: OrderedRouteProgram<(), OutboundAction>,
    final_plan: usize,
    final_outbound: usize,
    routed: bool,
    selectors: Arc<SelectorState>,
    plans: Arc<Vec<Arc<[usize]>>>,
}

impl RouteTable {
    /// Compiles static inbound bindings into the shared selection path.
    pub fn static_bindings(bindings: Vec<usize>) -> Option<Self> {
        let final_outbound = bindings.first().copied()?;
        if bindings.len() > MAX_ROUTE_RULES {
            return None;
        }
        let plans = bindings
            .iter()
            .map(|outbound| Arc::from([*outbound]))
            .collect();
        let rules = bindings
            .into_iter()
            .enumerate()
            .map(|(inbound, _)| {
                OrderedRouteRule::new(
                    RouteMatcher::legacy(Some(inbound), None, None),
                    RouteRuleAction::Terminal(OutboundAction::Plan(inbound)),
                )
            })
            .collect();
        Some(Self {
            program: OrderedRouteProgram::new(rules, OutboundAction::Plan(0))?,
            final_plan: 0,
            final_outbound,
            routed: false,
            selectors: Arc::default(),
            plans: Arc::new(plans),
        })
    }

    /// Stores an already validated routed table and its mandatory final outbound.
    pub fn routed(rules: Vec<RouteRule>, final_outbound: usize) -> Option<Self> {
        if rules.len() > MAX_ROUTE_RULES {
            return None;
        }
        let mut plans = Vec::with_capacity(rules.len() + 1);
        let rules = rules
            .into_iter()
            .map(|rule| {
                let outbound = rule.outbound;
                let action = OutboundAction::Plan(plans.len());
                plans.push(Arc::from([outbound]));
                rule.into_ordered(action)
            })
            .collect();
        let final_action = OutboundAction::Plan(plans.len());
        plans.push(Arc::from([final_outbound]));
        Some(Self {
            program: OrderedRouteProgram::new(rules, final_action)?,
            final_plan: plans.len() - 1,
            final_outbound,
            routed: true,
            selectors: Arc::default(),
            plans: Arc::new(plans),
        })
    }

    /// Returns whether this table came from an explicit routed document.
    pub const fn is_routed(&self) -> bool {
        self.routed
    }

    /// Returns the first outbound in the configured-default no-match plan.
    pub const fn final_outbound(&self) -> usize {
        self.final_outbound
    }

    /// Returns a control handle sharing this route table's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        SelectorControl {
            state: Arc::clone(&self.selectors),
        }
    }

    /// Selects the first matching rule or the mandatory final outbound.
    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        let plan = self.select_plan(inbound, network, target);
        assert_eq!(plan.hops.len(), 1, "multi-hop route requires select_plan");
        plan.hops[0]
    }

    /// Selects one complete immutable plan at the first matching rule or final action.
    pub fn select_plan(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> EgressPlan<'_> {
        let action = self.select_action(inbound, network, target);
        EgressPlan {
            hops: self.plans[self.selectors.resolve(action)].as_ref(),
        }
    }

    /// Selects one complete owned immutable plan at the first matching rule or final action.
    pub fn select_plan_snapshot(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> EgressPlanSnapshot {
        let action = self.select_action(inbound, network, target);
        EgressPlanSnapshot {
            hops: Arc::clone(&self.plans[self.selectors.resolve(action)]),
        }
    }

    /// Returns the complete configured-default plan snapshot.
    pub fn final_plan(&self) -> EgressPlan<'_> {
        EgressPlan {
            hops: self.plans[self.final_plan].as_ref(),
        }
    }

    /// Returns the complete configured-default plan as an owned immutable snapshot.
    pub fn final_plan_snapshot(&self) -> EgressPlanSnapshot {
        EgressPlanSnapshot {
            hops: Arc::clone(&self.plans[self.final_plan]),
        }
    }

    fn select_action(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> OutboundAction {
        let mut evaluation = self.program.evaluate(inbound, network, target);
        match evaluation
            .next(RouteMetadata::new(None, None))
            .expect("new route evaluation returns one terminal action")
        {
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => *action,
            RouteProgramAction::Continue(_) => {
                unreachable!("legacy route rules are always terminal")
            }
        }
    }
}

impl std::fmt::Debug for RouteTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RouteTable([redacted])")
    }
}

/// Compiles a validated tagged selector graph and tagged route actions atomically.
pub fn compile_selector_route(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    definitions: &[SelectorDefinition<'_>],
    route: TaggedRoute<'_>,
) -> Result<(RouteTable, SelectorControl), SelectorCompileError> {
    if definitions.is_empty() {
        return Err(SelectorCompileError::Selectors);
    }
    compile_selector_plans(inbounds, outbounds, &[], definitions, route)
}

/// Compiles concrete outbounds, immutable multi-hop plans, selectors and route actions atomically.
pub fn compile_selector_plans(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
    route: TaggedRoute<'_>,
) -> Result<(RouteTable, SelectorControl), SelectorCompileError> {
    compile_selector_plans_with_roots(inbounds, outbounds, plans, definitions, route, &[])
        .map(|(route, control, _)| (route, control))
}

/// Compiles selector-aware routing plus additional resolved egress roots atomically.
pub fn compile_selector_plans_with_roots(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
    route: TaggedRoute<'_>,
    extra_roots: &[&str],
) -> Result<(RouteTable, SelectorControl, Vec<EgressPlanHandle>), SelectorCompileError> {
    validate_identities(inbounds, outbounds, plans, definitions)?;

    let compiled_plans = outbounds
        .iter()
        .map(|outbound| Arc::from([outbound.outbound]))
        .chain(plans.iter().map(|plan| Arc::from(plan.hops.as_slice())))
        .collect::<Vec<_>>();

    let mut selectors = Vec::with_capacity(definitions.len());
    for definition in definitions {
        if !(1..=MAX_SELECTOR_MEMBERS).contains(&definition.outbounds.len()) {
            return Err(SelectorCompileError::SelectorOutbounds);
        }
        let mut members = Vec::with_capacity(definition.outbounds.len());
        for (index, tag) in definition.outbounds.iter().enumerate() {
            if !valid_tag(tag) || definition.outbounds[..index].contains(tag) {
                return Err(SelectorCompileError::SelectorOutbounds);
            }
            let action = resolve_tag(tag, outbounds, plans, definitions)
                .ok_or(SelectorCompileError::SelectorOutbounds)?;
            members.push(SelectorMember {
                tag: (*tag).into(),
                action,
            });
        }
        let default = definition
            .default
            .filter(|tag| valid_tag(tag))
            .and_then(|default| definition.outbounds.iter().position(|tag| *tag == default))
            .ok_or(SelectorCompileError::SelectorDefault)?;
        selectors.push(Selector {
            tag: definition.tag.into(),
            members,
            selected: AtomicUsize::new(default),
        });
    }
    validate_acyclic(&selectors)?;

    let (rules, final_action, routed, mut roots) =
        compile_actions(inbounds, outbounds, plans, definitions, route)?;
    let extra_roots = extra_roots
        .iter()
        .map(|tag| {
            resolve_tag(tag, outbounds, plans, definitions).ok_or(SelectorCompileError::ExtraRoot)
        })
        .collect::<Result<Vec<_>, _>>()?;
    roots.extend(extra_roots.iter().copied());
    validate_reachability(&selectors, outbounds, &compiled_plans, &roots)?;
    let state = Arc::new(SelectorState { selectors });
    let final_plan = state.resolve(final_action);
    let final_outbound = compiled_plans[final_plan][0];
    let plans = Arc::new(compiled_plans);
    let control = SelectorControl {
        state: Arc::clone(&state),
    };
    let handles = extra_roots
        .into_iter()
        .map(|action| EgressPlanHandle {
            action,
            selectors: Arc::clone(&state),
            plans: Arc::clone(&plans),
        })
        .collect();
    Ok((
        RouteTable {
            program: OrderedRouteProgram::new(rules, final_action)
                .expect("compiled action count was validated"),
            final_plan,
            final_outbound,
            routed,
            selectors: state,
            plans,
        },
        control,
        handles,
    ))
}

fn validate_identities(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
) -> Result<(), SelectorCompileError> {
    if !(1..=MAX_ROUTE_RULES).contains(&inbounds.len())
        || inbounds.iter().enumerate().any(|(index, inbound)| {
            !valid_tag(inbound.tag)
                || inbounds[..index]
                    .iter()
                    .any(|other| other.tag == inbound.tag || other.inbound == inbound.inbound)
        })
    {
        return Err(SelectorCompileError::Inbounds);
    }
    if !(1..=MAX_ROUTE_RULES).contains(&outbounds.len())
        || outbounds.iter().enumerate().any(|(index, outbound)| {
            !valid_tag(outbound.tag)
                || inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
                || outbounds[..index]
                    .iter()
                    .any(|other| other.tag == outbound.tag || other.outbound == outbound.outbound)
        })
    {
        return Err(SelectorCompileError::Outbounds);
    }
    if plans.len() > MAX_SELECTORS {
        return Err(SelectorCompileError::Plans);
    }
    for (index, plan) in plans.iter().enumerate() {
        if !valid_tag(plan.tag)
            || inbounds.iter().any(|inbound| inbound.tag == plan.tag)
            || outbounds.iter().any(|outbound| outbound.tag == plan.tag)
            || plans[..index].iter().any(|other| other.tag == plan.tag)
        {
            return Err(SelectorCompileError::PlanTag);
        }
        if !(2..=8).contains(&plan.hops.len())
            || plan.hops.iter().enumerate().any(|(hop, outbound)| {
                !outbounds
                    .iter()
                    .any(|candidate| candidate.outbound == *outbound)
                    || plan.hops[..hop].contains(outbound)
            })
        {
            return Err(SelectorCompileError::PlanHops);
        }
    }
    if definitions.len() > MAX_SELECTORS {
        return Err(SelectorCompileError::Selectors);
    }
    if definitions.iter().enumerate().any(|(index, selector)| {
        !valid_tag(selector.tag)
            || inbounds.iter().any(|inbound| inbound.tag == selector.tag)
            || outbounds
                .iter()
                .any(|outbound| outbound.tag == selector.tag)
            || plans.iter().any(|plan| plan.tag == selector.tag)
            || definitions[..index]
                .iter()
                .any(|other| other.tag == selector.tag)
    }) {
        return Err(SelectorCompileError::SelectorTag);
    }
    Ok(())
}

fn valid_tag(tag: &str) -> bool {
    (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn resolve_tag(
    tag: &str,
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
) -> Option<OutboundAction> {
    outbounds
        .iter()
        .position(|outbound| outbound.tag == tag)
        .map(OutboundAction::Plan)
        .or_else(|| {
            plans
                .iter()
                .position(|plan| plan.tag == tag)
                .map(|plan| OutboundAction::Plan(outbounds.len() + plan))
        })
        .or_else(|| {
            definitions
                .iter()
                .position(|selector| selector.tag == tag)
                .map(OutboundAction::Selector)
        })
}

fn validate_acyclic(selectors: &[Selector]) -> Result<(), SelectorCompileError> {
    fn visit(
        selector: usize,
        selectors: &[Selector],
        marks: &mut [u8],
    ) -> Result<(), SelectorCompileError> {
        if marks[selector] == 1 {
            return Err(SelectorCompileError::SelectorOutbounds);
        }
        if marks[selector] == 2 {
            return Ok(());
        }
        marks[selector] = 1;
        for member in &selectors[selector].members {
            if let OutboundAction::Selector(next) = member.action {
                visit(next, selectors, marks)?;
            }
        }
        marks[selector] = 2;
        Ok(())
    }

    let mut marks = vec![0; selectors.len()];
    for selector in 0..selectors.len() {
        visit(selector, selectors, &mut marks)?;
    }
    Ok(())
}

type CompiledActions = (
    Vec<OrderedRouteRule<(), OutboundAction>>,
    OutboundAction,
    bool,
    Vec<OutboundAction>,
);

fn compile_actions(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
    route: TaggedRoute<'_>,
) -> Result<CompiledActions, SelectorCompileError> {
    match route {
        TaggedRoute::Static(bindings) => {
            if bindings.len() != inbounds.len() {
                return Err(SelectorCompileError::StaticBinding);
            }
            let mut seen = vec![false; inbounds.len()];
            let mut rules = Vec::with_capacity(bindings.len());
            let mut roots = Vec::with_capacity(bindings.len());
            for binding in bindings {
                let inbound = inbounds
                    .iter()
                    .position(|inbound| inbound.tag == binding.inbound)
                    .ok_or(SelectorCompileError::StaticBinding)?;
                if seen[inbound] {
                    return Err(SelectorCompileError::StaticBinding);
                }
                seen[inbound] = true;
                let action = resolve_tag(binding.outbound, outbounds, plans, definitions)
                    .ok_or(SelectorCompileError::StaticBinding)?;
                roots.push(action);
                rules.push(OrderedRouteRule::new(
                    RouteMatcher::legacy(Some(inbounds[inbound].inbound), None, None),
                    RouteRuleAction::Terminal(action),
                ));
            }
            let final_action = roots[0];
            Ok((rules, final_action, false, roots))
        }
        TaggedRoute::Routed {
            rules: tagged_rules,
            final_outbound,
        } => {
            if tagged_rules.len() > MAX_ROUTE_RULES {
                return Err(SelectorCompileError::RouteRules);
            }
            let final_action = final_outbound
                .filter(|tag| valid_tag(tag))
                .and_then(|tag| resolve_tag(tag, outbounds, plans, definitions))
                .ok_or(SelectorCompileError::RouteFinal)?;
            let mut roots = vec![final_action];
            let mut rules = Vec::with_capacity(tagged_rules.len());
            for rule in tagged_rules {
                if rule.inbound.is_none() && rule.network.is_none() && rule.target.is_none() {
                    return Err(SelectorCompileError::RouteRules);
                }
                let inbound = rule
                    .inbound
                    .map(|tag| {
                        inbounds
                            .iter()
                            .find(|inbound| inbound.tag == tag)
                            .map(|inbound| inbound.inbound)
                            .ok_or(SelectorCompileError::RouteRuleInbound)
                    })
                    .transpose()?;
                let action = rule
                    .outbound
                    .filter(|tag| valid_tag(tag))
                    .and_then(|tag| resolve_tag(tag, outbounds, plans, definitions))
                    .ok_or(SelectorCompileError::RouteRuleOutbound)?;
                roots.push(action);
                rules.push(OrderedRouteRule::new(
                    RouteMatcher::legacy(inbound, rule.network, rule.target),
                    RouteRuleAction::Terminal(action),
                ));
            }
            Ok((rules, final_action, true, roots))
        }
    }
}

fn validate_reachability(
    selectors: &[Selector],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[Arc<[usize]>],
    roots: &[OutboundAction],
) -> Result<(), SelectorCompileError> {
    fn visit(
        action: OutboundAction,
        selectors: &[Selector],
        reached_plans: &mut [bool],
        reached_selectors: &mut [bool],
    ) {
        match action {
            OutboundAction::Plan(plan) => reached_plans[plan] = true,
            OutboundAction::Selector(selector) if !reached_selectors[selector] => {
                reached_selectors[selector] = true;
                for member in &selectors[selector].members {
                    visit(member.action, selectors, reached_plans, reached_selectors);
                }
            }
            OutboundAction::Selector(_) => {}
        }
    }

    let mut reached_selectors = vec![false; selectors.len()];
    let mut reached_plans = vec![false; plans.len()];
    for root in roots {
        visit(*root, selectors, &mut reached_plans, &mut reached_selectors);
    }
    if reached_selectors.contains(&false) {
        return Err(SelectorCompileError::UnreachableSelector);
    }
    if reached_plans[outbounds.len()..].contains(&false) {
        return Err(SelectorCompileError::UnreachablePlan);
    }
    let mut reached_outbounds = vec![false; outbounds.len()];
    for (plan, reached) in plans.iter().zip(reached_plans) {
        if reached {
            for outbound in plan.iter() {
                let index = outbounds
                    .iter()
                    .position(|candidate| candidate.outbound == *outbound)
                    .expect("validated plan hop");
                reached_outbounds[index] = true;
            }
        }
    }
    reached_outbounds
        .contains(&false)
        .then_some(SelectorCompileError::UnreachableOutbound)
        .map_or(Ok(()), Err)
}
