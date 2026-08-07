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
    ExtraRoot,
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
