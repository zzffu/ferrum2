use std::time::Duration;

use tokio::time::Instant;

use crate::OwnerSnapshot;

/// Stable insertion-order identity of one required root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessRootId(pub(super) usize);

impl ProcessRootId {
    /// Returns the zero-based insertion position.
    pub fn get(self) -> usize {
        self.0
    }
}

/// Observable process lifecycle outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Validated,
    Preparing,
    Prepared,
    Active,
    Rollback,
    Fatal,
    Quiescing,
    Draining,
    Forced,
    Stopped,
}

/// Terminal result returned by a required root while the process was active.
#[derive(Debug, Eq, PartialEq)]
pub enum ProcessRootExit<E> {
    Completed,
    Failed(E),
    Panicked,
    JoinFailed,
}

/// Deterministic first cause that triggered process termination.
#[derive(Debug, Eq, PartialEq)]
pub enum ProcessCause<E> {
    ExternalShutdown,
    PreparationFailed {
        root: ProcessRootId,
        error: E,
    },
    PreparationPanicked {
        root: ProcessRootId,
    },
    ActivationFailed {
        root: ProcessRootId,
        error: E,
    },
    ActivationPanicked {
        root: ProcessRootId,
    },
    RootStopped {
        root: ProcessRootId,
        exit: ProcessRootExit<E>,
    },
}

/// Closed cleanup outcome observed after the primary process cause.
#[derive(Debug, Eq, PartialEq)]
pub enum ProcessCleanupFailure<E> {
    RootFailed {
        root: ProcessRootId,
        error: E,
    },
    RootPanicked {
        root: ProcessRootId,
    },
    RootJoinFailed {
        root: ProcessRootId,
    },
    /// Forced roots did not prove cooperative reap before the fixed cleanup bound.
    ForceReapTimedOut {
        roots: Vec<ProcessRootId>,
        /// Earlier cleanup failure retained when the watchdog takes precedence.
        prior: Option<Box<ProcessCleanupFailure<E>>>,
    },
    OwnerMismatch {
        baseline: Box<OwnerSnapshot>,
        stopped: Box<OwnerSnapshot>,
    },
}

/// Closed high-level result classification for process adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExitKind {
    Graceful,
    Forced,
    Failed,
}

/// One immutable process-state observation on the supervisor's monotonic clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessTransition {
    state: ProcessState,
    elapsed: Duration,
}

impl ProcessTransition {
    /// Returns the state entered by this transition.
    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// Returns monotonic time elapsed since this supervisor run began.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

/// Shutdown phase in which one active root was observed to have been reaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRootEventPhase {
    /// The root stopped before process quiescing began and became the primary cause.
    Active,
    /// The root stopped while the process was inside its graceful drain bound.
    Draining,
    /// The root stopped after the grace deadline and cooperative force signal.
    Forced,
    /// The fixed force-reap watchdog expired and the root task was aborted.
    WatchdogAbort,
}

/// Closed root outcome used by the shutdown timeline.
///
/// Unlike [`ProcessRootExit`], this category never retains a root error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRootExitCategory {
    Completed,
    Failed,
    Panicked,
    JoinFailed,
    Aborted,
}

/// One immutable, secret-free root exit observation on the supervisor clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRootEvent {
    root: ProcessRootId,
    phase: ProcessRootEventPhase,
    exit: ProcessRootExitCategory,
    elapsed: Duration,
}

impl ProcessRootEvent {
    /// Returns the insertion-order identity of the reaped root.
    pub fn root(&self) -> ProcessRootId {
        self.root
    }

    /// Returns the shutdown phase in which the exit was observed.
    pub fn phase(&self) -> ProcessRootEventPhase {
        self.phase
    }

    /// Returns the closed root outcome without retaining the root error value.
    pub fn exit(&self) -> ProcessRootExitCategory {
        self.exit
    }

    /// Returns monotonic time elapsed since this supervisor run began.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

/// Bounded lifecycle report returned only after rollback or root reaping.
#[derive(Debug, Eq, PartialEq)]
pub struct ProcessReport<E> {
    pub(super) states: Vec<ProcessState>,
    pub(super) transitions: Vec<ProcessTransition>,
    pub(super) root_events: Vec<ProcessRootEvent>,
    pub(super) grace_deadline_elapsed: Option<Duration>,
    pub(super) cause: ProcessCause<E>,
    pub(super) forced_roots: usize,
    pub(super) cleanup_failure: Option<ProcessCleanupFailure<E>>,
}

impl<E> ProcessReport<E> {
    /// Returns the complete bounded state sequence.
    pub fn states(&self) -> &[ProcessState] {
        &self.states
    }

    /// Returns the complete bounded state timeline on Tokio's monotonic clock.
    pub fn transitions(&self) -> &[ProcessTransition] {
        &self.transitions
    }

    /// Returns the ordered, bounded root exit timeline.
    ///
    /// Each active root contributes at most one event, including a root reaped
    /// by the fixed watchdog, so the slice can never exceed the configured root
    /// count. Root error values are deliberately excluded.
    pub fn root_events(&self) -> &[ProcessRootEvent] {
        &self.root_events
    }

    /// Returns the runtime-created grace deadline relative to this run's
    /// monotonic start, or `None` when shutdown ended during rollback before a
    /// drain deadline was created.
    pub fn grace_deadline_elapsed(&self) -> Option<Duration> {
        self.grace_deadline_elapsed
    }

    /// Returns the deterministic first termination cause.
    pub fn cause(&self) -> &ProcessCause<E> {
        &self.cause
    }

    /// Returns the first cleanup failure, if cleanup was not proven.
    pub fn cleanup_failure(&self) -> Option<&ProcessCleanupFailure<E>> {
        self.cleanup_failure.as_ref()
    }

    /// Returns the number of roots force-cancelled after the grace deadline.
    pub fn forced_roots(&self) -> usize {
        self.forced_roots
    }

    /// Returns a closed classification suitable for a binary adapter.
    pub fn exit_kind(&self) -> ProcessExitKind {
        if self.cleanup_failure.is_some() || !matches!(self.cause, ProcessCause::ExternalShutdown) {
            ProcessExitKind::Failed
        } else if self.states.contains(&ProcessState::Forced) {
            ProcessExitKind::Forced
        } else {
            ProcessExitKind::Graceful
        }
    }
}

#[derive(Debug)]
pub(super) struct ProcessTimeline {
    pub(super) started_at: Instant,
    pub(super) states: Vec<ProcessState>,
    pub(super) transitions: Vec<ProcessTransition>,
    pub(super) root_events: Vec<ProcessRootEvent>,
    pub(super) root_event_limit: usize,
    pub(super) grace_deadline_elapsed: Option<Duration>,
}

impl ProcessTimeline {
    pub(super) fn new(root_count: usize) -> Self {
        let mut timeline = Self {
            started_at: Instant::now(),
            states: Vec::new(),
            transitions: Vec::new(),
            root_events: Vec::with_capacity(root_count),
            root_event_limit: root_count,
            grace_deadline_elapsed: None,
        };
        timeline.push(ProcessState::Validated);
        timeline.push(ProcessState::Preparing);
        timeline
    }

    pub(super) fn push(&mut self, state: ProcessState) {
        self.states.push(state);
        self.transitions.push(ProcessTransition {
            state,
            elapsed: Instant::now().duration_since(self.started_at),
        });
    }

    pub(super) fn record_grace_deadline(&mut self, deadline: Instant) {
        debug_assert!(self.grace_deadline_elapsed.is_none());
        self.grace_deadline_elapsed = Some(deadline.duration_since(self.started_at));
    }

    pub(super) fn push_root_event(
        &mut self,
        root: ProcessRootId,
        phase: ProcessRootEventPhase,
        exit: ProcessRootExitCategory,
    ) {
        let root_is_new = self.root_events.iter().all(|event| event.root != root);
        let within_bound =
            root.get() < self.root_event_limit && self.root_events.len() < self.root_event_limit;
        debug_assert!(
            root_is_new && within_bound,
            "an active process root is reaped exactly once",
        );
        if !root_is_new || !within_bound {
            return;
        }
        self.root_events.push(ProcessRootEvent {
            root,
            phase,
            exit,
            elapsed: Instant::now().duration_since(self.started_at),
        });
    }
}
