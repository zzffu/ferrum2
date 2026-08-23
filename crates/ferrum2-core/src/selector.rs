use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{GenerationChange, GenerationSignal};

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

    pub const fn tag(&self) -> &'a str {
        self.tag
    }

    pub const fn inbound(&self) -> usize {
        self.inbound
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

    pub const fn tag(&self) -> &'a str {
        self.tag
    }

    pub const fn outbound(&self) -> usize {
        self.outbound
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

    pub const fn tag(&self) -> &'a str {
        self.tag
    }

    pub fn hops(&self) -> &[usize] {
        &self.hops
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

    pub const fn tag(&self) -> &'a str {
        self.tag
    }

    pub fn outbounds(&self) -> &[&'a str] {
        &self.outbounds
    }

    pub const fn default(&self) -> Option<&'a str> {
        self.default
    }
}

/// Closed selector compilation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorCompileError {
    Allocation,
    RuleCompile,
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
    generation: AtomicU64,
    update: Mutex<()>,
    changes: GenerationSignal,
}

impl SelectorState {
    pub(super) fn new(selectors: Vec<Selector>) -> Self {
        Self {
            selectors,
            generation: AtomicU64::new(0),
            update: Mutex::new(()),
            changes: GenerationSignal::default(),
        }
    }

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

    fn generation(&self) -> u64 {
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            if generation & 1 == 0 {
                return generation;
            }
            std::hint::spin_loop();
        }
    }

    fn begin_change(&self) -> SelectorChange<'_> {
        let update = self
            .update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            if generation & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            if self
                .generation
                .compare_exchange(
                    generation,
                    generation.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return SelectorChange {
                    generation: &self.generation,
                    changes: &self.changes,
                    update: Some(update),
                    baseline: generation,
                    changed: false,
                };
            }
        }
    }
}

struct SelectorChange<'a> {
    generation: &'a AtomicU64,
    changes: &'a GenerationSignal,
    update: Option<MutexGuard<'a, ()>>,
    baseline: u64,
    changed: bool,
}

impl SelectorChange<'_> {
    fn mark_changed(&mut self) {
        self.changed = true;
    }
}

impl Drop for SelectorChange<'_> {
    fn drop(&mut self) {
        let generation = self.baseline.wrapping_add(if self.changed { 2 } else { 0 });
        self.generation.store(generation, Ordering::Release);
        let notification = self
            .changed
            .then(|| self.changes.prepare_notification(generation));
        drop(self.update.take());
        if let Some(notification) = notification {
            notification.wake();
        }
    }
}

/// Cloneable public control over one compiled selector graph.
#[derive(Clone)]
pub struct SelectorControl {
    pub(super) state: Arc<SelectorState>,
}

impl SelectorControl {
    /// Constructs an empty selector control for direct, non-selector routes.
    pub fn empty() -> Self {
        Self {
            state: Arc::default(),
        }
    }

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

    /// Returns the last complete selector generation.
    ///
    /// Successful switches to a different immediate member advance this value.
    /// Failed and no-op switches leave it unchanged.
    pub fn generation(&self) -> u64 {
        self.state.generation()
    }

    /// Subscribes to the next successful switch away from the current generation.
    ///
    /// Each returned future is independent. An empty selector control never
    /// changes, so its subscription remains pending.
    pub fn watch_generation(&self) -> GenerationChange {
        let _update = self
            .state
            .update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.state.changes.watch()
    }

    /// Subscribes from a generation captured together with an earlier route
    /// selection.
    ///
    /// If an effective switch has already completed, the returned future is
    /// immediately ready. This closes the interval between selecting a route
    /// and constructing its change subscription.
    pub fn watch_generation_from(&self, generation: u64) -> GenerationChange {
        let _update = self
            .state
            .update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.state.changes.watch_from(generation)
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
        if selector.selected.load(Ordering::SeqCst) == member {
            return Ok(());
        }
        let mut change = self.state.begin_change();
        if selector.selected.load(Ordering::SeqCst) != member {
            selector.selected.store(member, Ordering::SeqCst);
            change.mark_changed();
        }
        Ok(())
    }
}

impl fmt::Debug for SelectorControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorControl([redacted])")
    }
}
