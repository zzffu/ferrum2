#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;

use bytes::{Bytes, BytesMut};

const MAX_DOMAIN_NAME_BYTES: usize = 255;

/// A domain name whose storage is bounded before allocation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Validates and stores a domain name.
    pub fn new(value: &str) -> Result<Self, DomainNameError> {
        match value.len() {
            0 => Err(DomainNameError::Empty),
            1..=MAX_DOMAIN_NAME_BYTES if value.is_ascii() => Ok(Self(value.into())),
            1..=MAX_DOMAIN_NAME_BYTES => Err(DomainNameError::NonAscii),
            _ => Err(DomainNameError::TooLong),
        }
    }

    /// Returns the validated domain name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DomainName([redacted])")
    }
}

/// Failure to construct a bounded domain name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainNameError {
    /// An empty domain is not a target.
    Empty,
    /// The encoded domain exceeds the protocol's 255-byte bound.
    TooLong,
    /// M1 preserves only ASCII domain bytes and does not perform IDNA.
    NonAscii,
}

impl fmt::Display for DomainNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("domain name is empty"),
            Self::TooLong => formatter.write_str("domain name exceeds 255 bytes"),
            Self::NonAscii => formatter.write_str("domain name is not ASCII"),
        }
    }
}

impl Error for DomainNameError {}

#[derive(Clone, Eq, Hash, PartialEq)]
enum TargetHost {
    Ip(IpAddr),
    Domain(DomainName),
}

/// A validated IP or bounded-domain target.
///
/// The type intentionally has no `Display` implementation so target values are
/// not accidentally included in operator-facing diagnostics.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TargetAddr {
    host: TargetHost,
    port: NonZeroU16,
}

impl TargetAddr {
    /// Constructs an IP target and rejects port zero.
    pub fn ip(address: SocketAddr) -> Result<Self, TargetAddrError> {
        let port = NonZeroU16::new(address.port()).ok_or(TargetAddrError::PortZero)?;
        Ok(Self {
            host: TargetHost::Ip(address.ip()),
            port,
        })
    }

    /// Constructs an IPv4 target and rejects port zero.
    pub fn ipv4(address: SocketAddrV4) -> Result<Self, TargetAddrError> {
        Self::ip(SocketAddr::V4(address))
    }

    /// Constructs a bounded-domain target and rejects port zero.
    pub fn domain(host: &str, port: u16) -> Result<Self, TargetAddrError> {
        let port = NonZeroU16::new(port).ok_or(TargetAddrError::PortZero)?;
        let host = DomainName::new(host).map_err(TargetAddrError::Domain)?;
        Ok(Self {
            host: TargetHost::Domain(host),
            port,
        })
    }

    /// Returns a non-secret view of the target host for protocol adapters.
    pub fn host(&self) -> TargetHostRef<'_> {
        match &self.host {
            TargetHost::Ip(address) => TargetHostRef::Ip(*address),
            TargetHost::Domain(domain) => TargetHostRef::Domain(domain.as_str()),
        }
    }

    /// Returns the validated non-zero target port.
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// Returns a socket address when the target is already an IP literal.
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self.host {
            TargetHost::Ip(address) => Some(SocketAddr::new(address, self.port.get())),
            TargetHost::Domain(_) => None,
        }
    }
}

impl fmt::Debug for TargetAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetAddr([redacted])")
    }
}

/// A borrowed view of a target host.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TargetHostRef<'a> {
    /// An IP-literal target.
    Ip(IpAddr),
    /// A bounded domain target.
    Domain(&'a str),
}

impl fmt::Debug for TargetHostRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetHostRef([redacted])")
    }
}

/// Failure to construct a normalized target address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetAddrError {
    /// Domain validation failed.
    Domain(DomainNameError),
    /// Port zero is never a connect target.
    PortZero,
}

impl fmt::Display for TargetAddrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => error.fmt(formatter),
            Self::PortZero => formatter.write_str("target port is zero"),
        }
    }
}

impl Error for TargetAddrError {}

/// Runtime-neutral manual outbound selector state and public control.
pub mod selector {
    use super::TargetAddr;
    use super::route::Network;
    use std::error::Error;
    use std::fmt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Maximum number of selectors retained by one route table.
    pub const MAX_SELECTORS: usize = 64;
    /// Maximum number of immediate members retained by one selector.
    pub const MAX_SELECTOR_MEMBERS: usize = 64;

    /// One tagged inbound identity supplied to selector-aware compilation.
    #[derive(Clone, Copy)]
    pub struct TaggedInbound<'a> {
        pub(super) tag: &'a str,
        pub(super) inbound: usize,
    }

    impl<'a> TaggedInbound<'a> {
        pub const fn new(tag: &'a str, inbound: usize) -> Self {
            Self { tag, inbound }
        }
    }

    /// One tagged concrete outbound identity supplied to selector-aware compilation.
    #[derive(Clone, Copy)]
    pub struct TaggedOutbound<'a> {
        pub(super) tag: &'a str,
        pub(super) outbound: usize,
    }

    impl<'a> TaggedOutbound<'a> {
        pub const fn new(tag: &'a str, outbound: usize) -> Self {
            Self { tag, outbound }
        }
    }

    /// One tagged immutable multi-hop egress plan supplied to selector-aware compilation.
    pub struct TaggedPlan<'a> {
        pub(super) tag: &'a str,
        pub(super) hops: Vec<usize>,
    }

    impl<'a> TaggedPlan<'a> {
        pub fn new(tag: &'a str, hops: Vec<usize>) -> Self {
            Self { tag, hops }
        }
    }

    /// One fixed-member selector definition supplied to selector-aware compilation.
    pub struct SelectorDefinition<'a> {
        pub(super) tag: &'a str,
        pub(super) outbounds: Vec<&'a str>,
        pub(super) default: Option<&'a str>,
    }

    impl<'a> SelectorDefinition<'a> {
        pub fn new(tag: &'a str, outbounds: Vec<&'a str>, default: Option<&'a str>) -> Self {
            Self {
                tag,
                outbounds,
                default,
            }
        }
    }

    /// One tagged static binding supplied to selector-aware compilation.
    pub struct TaggedStaticBinding<'a> {
        pub(super) inbound: &'a str,
        pub(super) outbound: &'a str,
    }

    impl<'a> TaggedStaticBinding<'a> {
        pub const fn new(inbound: &'a str, outbound: &'a str) -> Self {
            Self { inbound, outbound }
        }
    }

    /// One tagged routed rule supplied to selector-aware compilation.
    pub struct TaggedRouteRule<'a> {
        pub(super) inbound: Option<&'a str>,
        pub(super) network: Option<Network>,
        pub(super) target: Option<TargetAddr>,
        pub(super) outbound: Option<&'a str>,
    }

    impl<'a> TaggedRouteRule<'a> {
        pub fn new(
            inbound: Option<&'a str>,
            network: Option<Network>,
            target: Option<TargetAddr>,
            outbound: Option<&'a str>,
        ) -> Self {
            Self {
                inbound,
                network,
                target,
                outbound,
            }
        }
    }

    /// Tagged static or routed actions supplied to selector-aware compilation.
    pub enum TaggedRoute<'a> {
        Static(Vec<TaggedStaticBinding<'a>>),
        Routed {
            rules: Vec<TaggedRouteRule<'a>>,
            final_outbound: Option<&'a str>,
        },
    }

    /// Closed selector compilation failures.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum SelectorCompileError {
        Inbounds,
        Outbounds,
        Plans,
        PlanTag,
        PlanHops,
        Selectors,
        SelectorTag,
        SelectorOutbounds,
        SelectorDefault,
        StaticBinding,
        RouteRules,
        RouteRuleInbound,
        RouteRuleOutbound,
        RouteFinal,
        UnreachableOutbound,
        UnreachablePlan,
        UnreachableSelector,
    }

    impl fmt::Display for SelectorCompileError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("selector graph is invalid")
        }
    }

    impl Error for SelectorCompileError {}

    /// Closed selector control failures.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum SelectorError {
        UnknownSelector,
        UnknownMember,
    }

    impl fmt::Display for SelectorError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnknownSelector => formatter.write_str("unknown selector"),
                Self::UnknownMember => formatter.write_str("unknown selector member"),
            }
        }
    }

    impl Error for SelectorError {}

    #[derive(Clone, Copy)]
    pub(super) enum OutboundAction {
        Plan(usize),
        Selector(usize),
    }

    pub(super) struct SelectorMember {
        pub(super) tag: Box<str>,
        pub(super) action: OutboundAction,
    }

    pub(super) struct Selector {
        pub(super) tag: Box<str>,
        pub(super) members: Vec<SelectorMember>,
        pub(super) selected: AtomicUsize,
    }

    #[derive(Default)]
    pub(super) struct SelectorState {
        pub(super) selectors: Vec<Selector>,
    }

    impl SelectorState {
        pub(super) fn resolve(&self, mut action: OutboundAction) -> usize {
            for _ in 0..=self.selectors.len() {
                match action {
                    OutboundAction::Plan(plan) => return plan,
                    OutboundAction::Selector(selector) => {
                        let selector = &self.selectors[selector];
                        action = selector.members[selector.selected.load(Ordering::SeqCst)].action;
                    }
                }
            }
            unreachable!("validated selector graph does not terminate")
        }
    }

    /// Cloneable public control over one compiled selector graph.
    #[derive(Clone)]
    pub struct SelectorControl {
        pub(super) state: Arc<SelectorState>,
    }

    impl SelectorControl {
        /// Returns a selector's current immediate member tag.
        pub fn selected<'a>(&'a self, selector_tag: &str) -> Result<&'a str, SelectorError> {
            let selector = self
                .state
                .selectors
                .iter()
                .find(|selector| selector.tag.as_ref() == selector_tag)
                .ok_or(SelectorError::UnknownSelector)?;
            Ok(&selector.members[selector.selected.load(Ordering::SeqCst)].tag)
        }

        /// Atomically selects one configured immediate member.
        pub fn switch(&self, selector_tag: &str, member_tag: &str) -> Result<(), SelectorError> {
            let selector = self
                .state
                .selectors
                .iter()
                .find(|selector| selector.tag.as_ref() == selector_tag)
                .ok_or(SelectorError::UnknownSelector)?;
            let member = selector
                .members
                .iter()
                .position(|member| member.tag.as_ref() == member_tag)
                .ok_or(SelectorError::UnknownMember)?;
            if selector.selected.load(Ordering::SeqCst) != member {
                selector.selected.store(member, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    impl fmt::Debug for SelectorControl {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SelectorControl([redacted])")
        }
    }
}

/// Runtime-neutral, total first-match routing.
pub mod route {
    use super::selector::{
        MAX_SELECTOR_MEMBERS, MAX_SELECTORS, OutboundAction, Selector, SelectorCompileError,
        SelectorControl, SelectorDefinition, SelectorMember, SelectorState, TaggedInbound,
        TaggedOutbound, TaggedPlan, TaggedRoute,
    };
    use super::{TargetAddr, TargetHost};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// Maximum number of rules retained by one route table.
    pub const MAX_ROUTE_RULES: usize = 64;

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

    /// Transport network presented to route selection.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Network {
        Tcp,
        Udp,
    }

    /// One compiled route rule with resolved inbound and outbound identities.
    pub struct RouteRule {
        inbound: Option<usize>,
        network: Option<Network>,
        target: Option<TargetAddr>,
        outbound: OutboundAction,
    }

    impl RouteRule {
        pub fn new(
            inbound: Option<usize>,
            network: Option<Network>,
            target: Option<TargetAddr>,
            outbound: usize,
        ) -> Self {
            Self {
                inbound,
                network,
                target,
                outbound: OutboundAction::Plan(outbound),
            }
        }

        fn matches(&self, inbound: usize, network: Network, target: &TargetAddr) -> bool {
            self.inbound.is_none_or(|expected| expected == inbound)
                && self.network.is_none_or(|expected| expected == network)
                && self.target.as_ref().is_none_or(|expected| {
                    expected.port == target.port
                        && match (&expected.host, &target.host) {
                            (TargetHost::Ip(expected), TargetHost::Ip(actual)) => {
                                expected == actual
                            }
                            (TargetHost::Domain(expected), TargetHost::Domain(actual)) => {
                                expected.as_str().eq_ignore_ascii_case(actual.as_str())
                            }
                            _ => false,
                        }
                })
        }
    }

    /// A compiled route table whose selection always returns an outbound identity.
    pub struct RouteTable {
        rules: Vec<RouteRule>,
        final_action: OutboundAction,
        final_plan: usize,
        final_outbound: usize,
        routed: bool,
        selectors: Arc<SelectorState>,
        plans: Vec<Box<[usize]>>,
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
                .map(|outbound| Box::from([*outbound]))
                .collect();
            let rules = bindings
                .into_iter()
                .enumerate()
                .map(|(inbound, _)| RouteRule {
                    inbound: Some(inbound),
                    network: None,
                    target: None,
                    outbound: OutboundAction::Plan(inbound),
                })
                .collect();
            Some(Self {
                rules,
                final_action: OutboundAction::Plan(0),
                final_plan: 0,
                final_outbound,
                routed: false,
                selectors: Arc::default(),
                plans,
            })
        }

        /// Stores an already validated routed table and its mandatory final outbound.
        pub fn routed(mut rules: Vec<RouteRule>, final_outbound: usize) -> Option<Self> {
            if rules.len() > MAX_ROUTE_RULES {
                return None;
            }
            let mut plans = Vec::with_capacity(rules.len() + 1);
            for rule in &mut rules {
                let OutboundAction::Plan(outbound) = rule.outbound else {
                    unreachable!("public route rules are direct")
                };
                rule.outbound = OutboundAction::Plan(plans.len());
                plans.push(Box::from([outbound]));
            }
            let final_action = OutboundAction::Plan(plans.len());
            plans.push(Box::from([final_outbound]));
            Some(Self {
                rules,
                final_action,
                final_plan: plans.len() - 1,
                final_outbound,
                routed: true,
                selectors: Arc::default(),
                plans,
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
            let action = self
                .rules
                .iter()
                .find(|rule| rule.matches(inbound, network, target))
                .map_or(self.final_action, |rule| rule.outbound);
            EgressPlan {
                hops: &self.plans[self.selectors.resolve(action)],
            }
        }

        /// Returns the complete configured-default plan snapshot.
        pub fn final_plan(&self) -> EgressPlan<'_> {
            EgressPlan {
                hops: &self.plans[self.final_plan],
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
        validate_identities(inbounds, outbounds, plans, definitions)?;

        let compiled_plans = outbounds
            .iter()
            .map(|outbound| Box::from([outbound.outbound]))
            .chain(
                plans
                    .iter()
                    .map(|plan| plan.hops.clone().into_boxed_slice()),
            )
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

        let (rules, final_action, routed, roots) =
            compile_actions(inbounds, outbounds, plans, definitions, route)?;
        validate_reachability(&selectors, outbounds, &compiled_plans, &roots)?;
        let state = Arc::new(SelectorState { selectors });
        let final_plan = state.resolve(final_action);
        let final_outbound = compiled_plans[final_plan][0];
        let control = SelectorControl {
            state: Arc::clone(&state),
        };
        Ok((
            RouteTable {
                rules,
                final_action,
                final_plan,
                final_outbound,
                routed,
                selectors: state,
                plans: compiled_plans,
            },
            control,
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
                    || outbounds[..index].iter().any(|other| {
                        other.tag == outbound.tag || other.outbound == outbound.outbound
                    })
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

    fn compile_actions(
        inbounds: &[TaggedInbound<'_>],
        outbounds: &[TaggedOutbound<'_>],
        plans: &[TaggedPlan<'_>],
        definitions: &[SelectorDefinition<'_>],
        route: TaggedRoute<'_>,
    ) -> Result<(Vec<RouteRule>, OutboundAction, bool, Vec<OutboundAction>), SelectorCompileError>
    {
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
                    rules.push(RouteRule {
                        inbound: Some(inbounds[inbound].inbound),
                        network: None,
                        target: None,
                        outbound: action,
                    });
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
                    rules.push(RouteRule {
                        inbound,
                        network: rule.network,
                        target: rule.target,
                        outbound: action,
                    });
                }
                Ok((rules, final_action, true, roots))
            }
        }
    }

    fn validate_reachability(
        selectors: &[Selector],
        outbounds: &[TaggedOutbound<'_>],
        plans: &[Box<[usize]>],
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
}

/// A runtime-neutral datagram with a validated target and owned payload.
///
/// Construction applies the caller's complete payload bound before the value
/// can cross a protocol/runtime seam. Buffer-capacity accounting remains a
/// runtime concern and is intentionally not represented here.
pub struct Datagram {
    target: TargetAddr,
    payload: Bytes,
    allocated_capacity: usize,
}

impl Datagram {
    /// Constructs an owned datagram whose payload does not exceed `max_payload_bytes`.
    pub fn new(
        target: TargetAddr,
        payload: BytesMut,
        max_payload_bytes: usize,
    ) -> Result<Self, DatagramError> {
        if payload.len() > max_payload_bytes {
            return Err(DatagramError::Bounds);
        }
        let allocated_capacity = payload.capacity();
        Ok(Self {
            target,
            payload: payload.freeze(),
            allocated_capacity,
        })
    }

    /// Returns the normalized target without exposing it through formatting.
    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    /// Returns the owned payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the owned backing capacity captured before the payload was frozen.
    pub const fn allocated_capacity(&self) -> usize {
        self.allocated_capacity
    }

    /// Consumes the datagram into its normalized target and owned payload.
    pub fn into_parts(self) -> (TargetAddr, Bytes) {
        (self.target, self.payload)
    }
}

impl fmt::Debug for Datagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Datagram")
            .field("target", &"[redacted]")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Failure to construct a caller-bounded datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramError {
    /// The owned payload exceeds the caller's complete payload bound.
    Bounds,
}

impl fmt::Display for DatagramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounds")
    }
}

impl Error for DatagramError {}

/// A normalized accepted session passed from an inbound to an outbound.
pub struct Session<S, R> {
    /// The validated destination.
    pub target: TargetAddr,
    /// The application-facing stream.
    pub stream: S,
    /// Bytes accepted with the session before relay starts.
    pub initial_payload: Bytes,
    /// The one-shot reply capability owned by this session.
    pub reply: R,
}

/// Application-facing traffic that produces normalized sessions.
pub trait Inbound<IO>: Send + Sync {
    /// Stream type yielded to the runtime.
    type Stream;
    /// One-shot session response.
    type Reply: SessionReply;
    /// Closed inbound error.
    type Error;

    /// Accepts one application-facing flow.
    fn accept(
        &self,
        io: IO,
    ) -> impl Future<Output = Result<Session<Self::Stream, Self::Reply>, Self::Error>> + Send;
}

/// A destination-facing session opener.
pub trait Outbound: Send + Sync {
    /// Opened stream with an already stored local socket endpoint.
    type Stream: LocalEndpoint;
    /// Closed outbound error.
    type Error;

    /// Opens a stream for a validated target.
    fn open(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;
}

/// Establishes a protocol-neutral stream for a validated target.
pub trait Connector: Send + Sync {
    /// Connected stream with an already stored local socket endpoint.
    type Stream: LocalEndpoint;

    /// Connects or returns a closed connect error.
    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send;
}

/// Access to a local endpoint captured before a stream is returned.
pub trait LocalEndpoint {
    /// Returns the stored legacy IPv4 endpoint without a socket query.
    fn local_endpoint(&self) -> SocketAddrV4;

    /// Returns the complete stored endpoint without a socket query.
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local_endpoint())
    }
}

/// A one-shot response to an accepted application session.
pub trait SessionReply: Sized {
    /// Closed response error.
    type Error;

    /// Consumes the reply owner and reports success using the opened stream's endpoint.
    fn succeeded(self, bound: SocketAddrV4)
    -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Consumes the reply owner and reports success for either socket family.
    ///
    /// Legacy reply owners retain their IPv4 behavior and fail closed for IPv6.
    fn succeeded_socket(
        self,
        bound: SocketAddr,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self: Send,
    {
        async move {
            match bound {
                SocketAddr::V4(bound) => self.succeeded(bound).await,
                SocketAddr::V6(_) => self.failed(ConnectErrorKind::Other).await,
            }
        }
    }

    /// Consumes the reply owner and reports a pre-success connect failure.
    fn failed(self, kind: ConnectErrorKind)
    -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Protocol-neutral capability for marking an owned transport abortive on drop.
pub trait AbortiveClose {
    /// Socket-adapter error.
    type Error;

    /// Marks the transport for abortive close.
    fn mark_abortive(&mut self) -> Result<(), Self::Error>;
}

/// Stable pre-success connection failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectErrorKind {
    /// No route exists to the destination network.
    NetworkUnreachable,
    /// The destination host cannot be reached.
    HostUnreachable,
    /// The destination refused the connection.
    ConnectionRefused,
    /// The connection attempt exceeded its deadline.
    Timeout,
    /// A closed implementation error that does not expose its source.
    Other,
}

/// A closed connection error that never retains or displays a raw source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectError {
    kind: ConnectErrorKind,
}

impl ConnectError {
    /// Constructs a closed connection error.
    pub const fn new(kind: ConnectErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable category used by a one-shot session reply.
    pub const fn kind(&self) -> ConnectErrorKind {
        self.kind
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ConnectErrorKind::NetworkUnreachable => "network unreachable",
            ConnectErrorKind::HostUnreachable => "host unreachable",
            ConnectErrorKind::ConnectionRefused => "connection refused",
            ConnectErrorKind::Timeout => "connection timed out",
            ConnectErrorKind::Other => "connection failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ConnectError {}

#[cfg(test)]
mod tests {
    use std::future::ready;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn domain_names_are_bounded_before_storage() {
        assert_eq!(DomainName::new("").unwrap_err(), DomainNameError::Empty);
        assert!(DomainName::new(&"a".repeat(255)).is_ok());
        assert_eq!(
            DomainName::new("é.example").unwrap_err(),
            DomainNameError::NonAscii
        );
        assert_eq!(
            DomainName::new(&"a".repeat(256)).unwrap_err(),
            DomainNameError::TooLong
        );
        assert_eq!(
            TargetAddr::domain("example.test", 0).unwrap_err(),
            TargetAddrError::PortZero
        );
    }

    #[test]
    fn target_debug_does_not_disclose_the_address() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443))
            .expect("non-zero port");

        let rendered = format!("{target:?}");
        assert!(!rendered.contains("192.0.2.9"));
        assert!(!rendered.contains("443"));
    }

    #[test]
    fn route_table_is_ordered_conjunctive_exact_and_total() {
        use route::{MAX_ROUTE_RULES, Network, RouteRule, RouteTable};

        let domain = TargetAddr::domain("example.test", 443).expect("domain");
        let ipv4 =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443)).expect("IPv4");
        let different_ipv4 =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443)).expect("IPv4");
        let ipv6 = TargetAddr::ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        )))
        .expect("IPv6");
        let route = RouteTable::routed(
            vec![
                RouteRule::new(Some(0), Some(Network::Tcp), Some(domain.clone()), 1),
                RouteRule::new(Some(0), None, None, 2),
                RouteRule::new(None, Some(Network::Udp), None, 3),
                RouteRule::new(None, None, Some(ipv4.clone()), 4),
                RouteRule::new(None, None, Some(ipv6.clone()), 5),
            ],
            6,
        )
        .expect("bounded route");
        #[rustfmt::skip]
        let cases = [
            (0, Network::Tcp, domain.clone(), 1),
            (0, Network::Tcp, TargetAddr::domain("EXAMPLE.TEST", 443).expect("case"), 1),
            (0, Network::Udp, domain.clone(), 2),
            (1, Network::Udp, domain.clone(), 3),
            (1, Network::Tcp, ipv4, 4),
            (1, Network::Tcp, different_ipv4, 6),
            (1, Network::Tcp, ipv6, 5),
            (1, Network::Tcp, TargetAddr::domain("example.test.", 443).expect("dot"), 6),
            (1, Network::Tcp, TargetAddr::domain("example.test", 80).expect("port"), 6),
        ];
        assert!(route.is_routed());
        for (inbound, network, target, expected) in cases {
            assert_eq!(route.select(inbound, network, &target), expected);
        }
        let static_route = RouteTable::static_bindings(vec![7, 8]).expect("static route");
        assert!(!static_route.is_routed());
        assert_eq!(static_route.select(1, Network::Udp, &domain), 8);
        assert_eq!(format!("{route:?}"), "RouteTable([redacted])");
        #[rustfmt::skip]
        let oversized = (0..=MAX_ROUTE_RULES).map(|_| RouteRule::new(Some(0), None, None, 0)).collect();
        assert!(RouteTable::routed(oversized, 0).is_none());
    }

    #[test]
    fn datagram_owns_a_caller_bounded_payload_without_disclosing_values() {
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 443))
            .expect("non-zero port");
        let datagram =
            Datagram::new(target, BytesMut::from(&b"owned payload"[..]), 13).expect("at bound");

        assert_eq!(datagram.payload(), b"owned payload");
        assert_eq!(datagram.allocated_capacity(), 13);
        assert_eq!(datagram.target().port().get(), 443);
        assert_eq!(
            Datagram::new(
                TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero port"),
                BytesMut::from(&b"too large"[..]),
                8,
            )
            .unwrap_err(),
            DatagramError::Bounds
        );
        let rendered = format!("{datagram:?}");
        assert!(!rendered.contains("192.0.2.9"));
        assert!(!rendered.contains("owned payload"));
    }

    struct StoredEndpoint(SocketAddrV4);

    impl LocalEndpoint for StoredEndpoint {
        fn local_endpoint(&self) -> SocketAddrV4 {
            self.0
        }
    }

    struct PendingReply;

    impl SessionReply for PendingReply {
        type Error = ();

        fn succeeded(
            self,
            _bound: SocketAddrV4,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }

        fn failed(
            self,
            _kind: ConnectErrorKind,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }
    }

    struct TestConnector;

    impl Connector for TestConnector {
        type Stream = StoredEndpoint;

        fn connect(
            &self,
            _target: &TargetAddr,
        ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
            let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152);
            ready(Ok(StoredEndpoint(endpoint)))
        }
    }

    fn assert_send_future<T: Send>(_future: T) {}

    #[test]
    fn connector_stream_carries_an_infallible_stored_socket_endpoint() {
        let target =
            TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("non-zero port");
        let connector = TestConnector;
        assert_send_future(connector.connect(&target));
    }

    #[test]
    fn reply_contract_requires_the_opened_stream_endpoint() {
        let bound = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 49152, 0, 0));
        struct Ipv6Endpoint(SocketAddr);
        impl LocalEndpoint for Ipv6Endpoint {
            fn local_endpoint(&self) -> SocketAddrV4 {
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.0.port())
            }

            fn local_socket_addr(&self) -> SocketAddr {
                self.0
            }
        }
        let stream = Ipv6Endpoint(bound);
        let reply = PendingReply;
        assert_send_future(reply.succeeded_socket(stream.local_socket_addr()));
    }
}
