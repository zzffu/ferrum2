use super::selector::{
    MAX_SELECTOR_MEMBERS, MAX_SELECTORS, OutboundAction, Selector, SelectorCompileError,
    SelectorControl, SelectorDefinition, SelectorMember, SelectorState, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// Maximum number of inbound or outbound identities in one egress graph.
///
/// This resource bound is intentionally independent from rule-program size.
pub const MAX_EGRESS_IDENTITIES: usize = 64;

/// Transport network presented to route selection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Network {
    Tcp,
    Udp,
}

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

    /// Borrows this immutable snapshot as an egress plan.
    pub fn as_plan(&self) -> EgressPlan<'_> {
        EgressPlan { hops: &self.hops }
    }
}

impl std::fmt::Debug for EgressPlanSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EgressPlanSnapshot([redacted])")
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

/// Compiles an egress-plan and selector graph, returning one handle per root tag.
///
/// Routing predicates deliberately live outside `ferrum2-core`; callers supply
/// every action root so reachability can still be validated atomically.
pub fn compile_egress_plans_with_roots(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
    roots: &[&str],
) -> Result<(SelectorControl, Vec<EgressPlanHandle>), SelectorCompileError> {
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

    let root_actions = roots
        .iter()
        .map(|tag| {
            tag_is_resolvable(tag, outbounds, plans, definitions)
                .then(|| resolve_tag(tag, outbounds, plans, definitions))
                .flatten()
                .ok_or(SelectorCompileError::ExtraRoot)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_reachability(&selectors, outbounds, &compiled_plans, &root_actions)?;

    let state = Arc::new(SelectorState { selectors });
    let plans = Arc::new(compiled_plans);
    let control = SelectorControl {
        state: Arc::clone(&state),
    };
    let handles = root_actions
        .into_iter()
        .map(|action| EgressPlanHandle {
            action,
            selectors: Arc::clone(&state),
            plans: Arc::clone(&plans),
        })
        .collect();
    Ok((control, handles))
}

fn validate_identities(
    inbounds: &[TaggedInbound<'_>],
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
) -> Result<(), SelectorCompileError> {
    if !(1..=MAX_EGRESS_IDENTITIES).contains(&inbounds.len())
        || inbounds.iter().enumerate().any(|(index, inbound)| {
            !valid_tag(inbound.tag)
                || inbounds[..index]
                    .iter()
                    .any(|other| other.tag == inbound.tag || other.inbound == inbound.inbound)
        })
    {
        return Err(SelectorCompileError::Inbounds);
    }
    if !(1..=MAX_EGRESS_IDENTITIES).contains(&outbounds.len())
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

fn tag_is_resolvable(
    tag: &str,
    outbounds: &[TaggedOutbound<'_>],
    plans: &[TaggedPlan<'_>],
    definitions: &[SelectorDefinition<'_>],
) -> bool {
    valid_tag(tag)
        && (outbounds.iter().any(|candidate| candidate.tag == tag)
            || plans.iter().any(|candidate| candidate.tag == tag)
            || definitions.iter().any(|candidate| candidate.tag == tag))
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
