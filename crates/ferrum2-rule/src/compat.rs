use ferrum2_core::TargetAddr;
use ferrum2_core::route::{
    EgressPlan, EgressPlanHandle, EgressPlanSnapshot, Network, compile_egress_plans_with_roots,
};
use ferrum2_core::selector::{
    SelectorCompileError, SelectorControl, SelectorDefinition, TaggedInbound, TaggedOutbound,
    TaggedPlan,
};

use crate::{
    OrderedRouteProgram, OrderedRouteRule, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteRuleAction, RuleCompileError,
};

/// One tagged static binding supplied to selector-aware compilation.
pub struct TaggedStaticBinding<'a> {
    inbound: &'a str,
    outbound: &'a str,
}

impl<'a> TaggedStaticBinding<'a> {
    pub const fn new(inbound: &'a str, outbound: &'a str) -> Self {
        Self { inbound, outbound }
    }
}

/// One tagged routed rule supplied to selector-aware compilation.
pub struct TaggedRouteRule<'a> {
    inbound: Option<&'a str>,
    network: Option<Network>,
    target: Option<TargetAddr>,
    outbound: Option<&'a str>,
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

/// One runtime-neutral first-match rule with a resolved action.
pub struct ActionRule<A> {
    matcher: RouteMatcher<()>,
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
            matcher: RouteMatcher::legacy(inbound, network, target),
            action,
        }
    }
}

/// Compatibility first-match table backed by the shared matcher implementation.
pub struct ActionTable<A> {
    rules: Box<[ActionRule<A>]>,
    final_action: A,
}

impl<A> ActionTable<A> {
    pub fn try_new(rules: Vec<ActionRule<A>>, final_action: A) -> Result<Self, RuleCompileError> {
        Ok(Self {
            rules: rules.into_boxed_slice(),
            final_action,
        })
    }

    /// Compatibility shim for callers migrating to [`Self::try_new`].
    pub fn new(rules: Vec<ActionRule<A>>, final_action: A) -> Option<Self> {
        Self::try_new(rules, final_action).ok()
    }
}

impl<A: Copy> ActionTable<A> {
    pub const fn final_action(&self) -> A {
        self.final_action
    }

    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> A {
        let metadata = RouteMetadata::new(None, None);
        self.rules
            .iter()
            .find(|rule| {
                rule.matcher
                    .matches(inbound, network, target, &metadata, None)
            })
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
}

/// A compiled compatibility route table whose selection is total.
pub struct RouteTable {
    program: OrderedRouteProgram<(), EgressPlanHandle>,
    final_snapshot: EgressPlanSnapshot,
    final_outbound: usize,
    routed: bool,
    control: SelectorControl,
}

impl RouteTable {
    pub fn try_static_bindings(bindings: Vec<usize>) -> Result<Self, RuleCompileError> {
        let final_outbound = bindings
            .first()
            .copied()
            .ok_or(RuleCompileError::EmptyField)?;
        let mut rules = Vec::new();
        rules
            .try_reserve(bindings.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for (inbound, outbound) in bindings.into_iter().enumerate() {
            rules.push(OrderedRouteRule::new(
                RouteMatcher::legacy(Some(inbound), None, None),
                RouteRuleAction::Terminal(EgressPlanHandle::direct(outbound)),
            ));
        }
        let final_handle = EgressPlanHandle::direct(final_outbound);
        let final_snapshot = final_handle.snapshot_owned();
        Ok(Self {
            program: OrderedRouteProgram::try_new(rules, final_handle.clone())?,
            final_snapshot,
            final_outbound,
            routed: false,
            control: SelectorControl::empty(),
        })
    }

    pub fn static_bindings(bindings: Vec<usize>) -> Option<Self> {
        Self::try_static_bindings(bindings).ok()
    }

    pub fn try_routed(
        rules: Vec<RouteRule>,
        final_outbound: usize,
    ) -> Result<Self, RuleCompileError> {
        let mut ordered = Vec::new();
        ordered
            .try_reserve(rules.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for rule in rules {
            ordered.push(OrderedRouteRule::new(
                rule.matcher,
                RouteRuleAction::Terminal(EgressPlanHandle::direct(rule.outbound)),
            ));
        }
        let final_handle = EgressPlanHandle::direct(final_outbound);
        let final_snapshot = final_handle.snapshot_owned();
        Ok(Self {
            program: OrderedRouteProgram::try_new(ordered, final_handle.clone())?,
            final_snapshot,
            final_outbound,
            routed: true,
            control: SelectorControl::empty(),
        })
    }

    pub fn routed(rules: Vec<RouteRule>, final_outbound: usize) -> Option<Self> {
        Self::try_routed(rules, final_outbound).ok()
    }

    pub const fn is_routed(&self) -> bool {
        self.routed
    }

    pub const fn final_outbound(&self) -> usize {
        self.final_outbound
    }

    pub fn selector_control(&self) -> SelectorControl {
        self.control.clone()
    }

    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        let plan = self.select_plan(inbound, network, target);
        assert_eq!(plan.hops().len(), 1, "multi-hop route requires select_plan");
        plan.hops()[0]
    }

    pub fn select_plan(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> EgressPlan<'_> {
        self.select_handle(inbound, network, target).snapshot()
    }

    pub fn select_plan_snapshot(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> EgressPlanSnapshot {
        self.select_handle(inbound, network, target)
            .snapshot_owned()
    }

    pub fn final_plan(&self) -> EgressPlan<'_> {
        self.final_snapshot.as_plan()
    }

    pub fn final_plan_snapshot(&self) -> EgressPlanSnapshot {
        self.final_snapshot.clone()
    }

    fn select_handle(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> &EgressPlanHandle {
        let mut evaluation = self.program.evaluate(inbound, network, target);
        match evaluation
            .next(RouteMetadata::new(None, None))
            .expect("new route evaluation returns one terminal action")
        {
            RouteProgramAction::Terminal(action) | RouteProgramAction::Final(action) => action,
            RouteProgramAction::Continue(_) => unreachable!("compatibility rules are terminal"),
        }
    }

    fn compiled(
        rules: Vec<(RouteMatcher<()>, EgressPlanHandle)>,
        final_handle: EgressPlanHandle,
        routed: bool,
        control: SelectorControl,
    ) -> Result<Self, RuleCompileError> {
        let mut ordered = Vec::new();
        ordered
            .try_reserve(rules.len())
            .map_err(|_| RuleCompileError::Allocation)?;
        for (matcher, action) in rules {
            ordered.push(OrderedRouteRule::new(
                matcher,
                RouteRuleAction::Terminal(action),
            ));
        }
        let final_outbound = final_handle.snapshot().hops()[0];
        let final_snapshot = final_handle.snapshot_owned();
        Ok(Self {
            program: OrderedRouteProgram::try_new(ordered, final_handle.clone())?,
            final_snapshot,
            final_outbound,
            routed,
            control,
        })
    }
}

impl std::fmt::Debug for RouteTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RouteTable([redacted])")
    }
}

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

pub fn compile_selector_plans_with_roots(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
    route: TaggedRoute<'_>,
    extra_roots: &[&str],
) -> Result<(RouteTable, SelectorControl, Vec<EgressPlanHandle>), SelectorCompileError> {
    enum RouteDraft {
        Static(Vec<usize>),
        Routed(Vec<RouteMatcher<()>>),
    }

    let route_root_count = match &route {
        TaggedRoute::Static(bindings) => bindings.len(),
        TaggedRoute::Routed { rules, .. } => rules
            .len()
            .checked_add(1)
            .ok_or(SelectorCompileError::Allocation)?,
    };
    let root_capacity = route_root_count
        .checked_add(extra_roots.len())
        .ok_or(SelectorCompileError::Allocation)?;
    let mut roots = Vec::<&str>::new();
    roots
        .try_reserve_exact(root_capacity)
        .map_err(|_| SelectorCompileError::Allocation)?;
    let (draft, routed, final_index) = match route {
        TaggedRoute::Static(bindings) => {
            if bindings.len() != inbounds.len() || bindings.is_empty() {
                return Err(SelectorCompileError::StaticBinding);
            }
            let mut seen = Vec::new();
            seen.try_reserve_exact(inbounds.len())
                .map_err(|_| SelectorCompileError::Allocation)?;
            seen.resize(inbounds.len(), false);
            let mut identities = Vec::new();
            identities
                .try_reserve_exact(bindings.len())
                .map_err(|_| SelectorCompileError::Allocation)?;
            for binding in bindings {
                let inbound = inbounds
                    .iter()
                    .position(|candidate| candidate.tag() == binding.inbound)
                    .ok_or(SelectorCompileError::StaticBinding)?;
                if seen[inbound] {
                    return Err(SelectorCompileError::StaticBinding);
                }
                seen[inbound] = true;
                identities.push(inbounds[inbound].inbound());
                roots.push(binding.outbound);
            }
            (RouteDraft::Static(identities), false, 0)
        }
        TaggedRoute::Routed {
            rules,
            final_outbound,
        } => {
            let final_outbound = final_outbound.ok_or(SelectorCompileError::RouteFinal)?;
            roots.push(final_outbound);
            let mut matchers = Vec::new();
            matchers
                .try_reserve_exact(rules.len())
                .map_err(|_| SelectorCompileError::Allocation)?;
            for rule in rules {
                if rule.inbound.is_none() && rule.network.is_none() && rule.target.is_none() {
                    return Err(SelectorCompileError::RouteRules);
                }
                let inbound = rule
                    .inbound
                    .map(|tag| {
                        inbounds
                            .iter()
                            .find(|candidate| candidate.tag() == tag)
                            .map(TaggedInbound::inbound)
                            .ok_or(SelectorCompileError::RouteRuleInbound)
                    })
                    .transpose()?;
                let outbound = rule
                    .outbound
                    .ok_or(SelectorCompileError::RouteRuleOutbound)?;
                roots.push(outbound);
                matchers.push(RouteMatcher::legacy(inbound, rule.network, rule.target));
            }
            (RouteDraft::Routed(matchers), true, 0)
        }
    };
    let extra_start = roots.len();
    roots.extend(extra_roots.iter().copied());

    let (control, handles) =
        compile_egress_plans_with_roots(inbounds, outbounds, plans, definitions, &roots).map_err(
            |error| {
                if error != SelectorCompileError::ExtraRoot {
                    return error;
                }
                let invalid = roots
                    .iter()
                    .position(|root| !resolvable(root, outbounds, plans, definitions))
                    .unwrap_or(extra_start);
                if invalid >= extra_start {
                    SelectorCompileError::ExtraRoot
                } else if !routed {
                    SelectorCompileError::StaticBinding
                } else if invalid == 0 {
                    SelectorCompileError::RouteFinal
                } else {
                    SelectorCompileError::RouteRuleOutbound
                }
            },
        )?;
    let mut extra_handles = Vec::new();
    extra_handles
        .try_reserve_exact(handles.len().saturating_sub(extra_start))
        .map_err(|_| SelectorCompileError::Allocation)?;
    extra_handles.extend(handles[extra_start..].iter().cloned());
    let table = match draft {
        RouteDraft::Static(identities) => {
            let mut rules = Vec::new();
            rules
                .try_reserve_exact(identities.len())
                .map_err(|_| SelectorCompileError::Allocation)?;
            for (inbound, handle) in identities
                .into_iter()
                .zip(handles[..extra_start].iter().cloned())
            {
                rules.push((RouteMatcher::legacy(Some(inbound), None, None), handle));
            }
            RouteTable::compiled(rules, handles[final_index].clone(), routed, control.clone())
        }
        RouteDraft::Routed(matchers) => {
            let mut rules = Vec::new();
            rules
                .try_reserve_exact(matchers.len())
                .map_err(|_| SelectorCompileError::Allocation)?;
            rules.extend(
                matchers
                    .into_iter()
                    .zip(handles[1..extra_start].iter().cloned()),
            );
            RouteTable::compiled(rules, handles[final_index].clone(), routed, control.clone())
        }
    }
    .map_err(map_route_compile_error)?;
    Ok((table, control, extra_handles))
}

const fn map_route_compile_error(error: RuleCompileError) -> SelectorCompileError {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => {
            SelectorCompileError::Allocation
        }
        RuleCompileError::InvalidId
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => SelectorCompileError::RuleCompile,
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet => SelectorCompileError::RouteRules,
    }
}

fn resolvable(
    tag: &str,
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
) -> bool {
    outbounds.iter().any(|candidate| candidate.tag() == tag)
        || plans.iter().any(|candidate| candidate.tag() == tag)
        || definitions.iter().any(|candidate| candidate.tag() == tag)
}

#[cfg(test)]
mod tests {
    use super::{RuleCompileError, SelectorCompileError, map_route_compile_error};

    #[test]
    fn compatibility_compiler_preserves_closed_allocation_and_internal_categories() {
        assert_eq!(
            map_route_compile_error(RuleCompileError::Allocation),
            SelectorCompileError::Allocation
        );
        assert_eq!(
            map_route_compile_error(RuleCompileError::IndexOverflow),
            SelectorCompileError::Allocation
        );
        assert_eq!(
            map_route_compile_error(RuleCompileError::Internal),
            SelectorCompileError::RuleCompile
        );
        assert_eq!(
            map_route_compile_error(RuleCompileError::DuplicateValue),
            SelectorCompileError::RouteRules
        );
    }
}
