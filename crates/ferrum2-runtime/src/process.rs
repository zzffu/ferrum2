use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, OwnerSnapshot};

const FORCE_REAP_WATCHDOG: Duration = Duration::from_secs(5);

/// Owned future used by topology-neutral process-root adapters.
pub type ProcessFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Monotonic process cancellation phase shared by every required root.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcessCancellationPhase {
    /// Public roots may admit work.
    #[default]
    Active,
    /// Admission must stop and accepted work may drain.
    Quiescing,
    /// The grace deadline elapsed and remaining work must terminate.
    Forced,
}

/// Cloneable view of one process cancellation lineage.
#[derive(Clone, Debug)]
pub struct ProcessCancellation {
    receiver: watch::Receiver<ProcessCancellationPhase>,
}

impl ProcessCancellation {
    /// Returns the current monotonic cancellation phase.
    pub fn phase(&self) -> ProcessCancellationPhase {
        *self.receiver.borrow()
    }

    /// Returns whether admission must stop.
    pub fn is_cancelled(&self) -> bool {
        self.phase() >= ProcessCancellationPhase::Quiescing
    }

    /// Returns whether the process grace deadline elapsed.
    pub fn is_forced(&self) -> bool {
        self.phase() == ProcessCancellationPhase::Forced
    }

    /// Waits until this lineage enters quiescing or forced shutdown.
    pub async fn cancelled(&mut self) {
        self.wait_for(ProcessCancellationPhase::Quiescing).await;
    }

    /// Waits until this lineage enters forced shutdown.
    pub async fn forced(&mut self) {
        self.wait_for(ProcessCancellationPhase::Forced).await;
    }

    async fn wait_for(&mut self, expected: ProcessCancellationPhase) {
        while *self.receiver.borrow_and_update() < expected {
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Debug)]
struct ProcessCancellationSource {
    sender: watch::Sender<ProcessCancellationPhase>,
}

impl ProcessCancellationSource {
    fn new() -> (Self, ProcessCancellation) {
        let (sender, receiver) = watch::channel(ProcessCancellationPhase::Active);
        (Self { sender }, ProcessCancellation { receiver })
    }

    fn quiesce(&self) {
        self.advance(ProcessCancellationPhase::Quiescing);
    }

    fn force(&self) {
        self.advance(ProcessCancellationPhase::Forced);
    }

    fn advance(&self, phase: ProcessCancellationPhase) {
        if *self.sender.borrow() < phase {
            self.sender.send_replace(phase);
        }
    }
}

/// Fallibly prepared process root at the process-supervisor seam.
pub trait PreparedProcessRoot<E>: Send + 'static {
    /// Completes the synchronous activation position without polling the service loop.
    ///
    /// The root must remain safe for `rollback` after either success, failure, or
    /// unwind from this method.
    fn activate(&mut self) -> Result<(), E>;

    /// Consumes the activated root into its public service future.
    ///
    /// The returned future owns the root and all of its children. It must complete
    /// only after its transitive children have been reaped. Per-flow and per-session
    /// failures stay inside the adapter; only terminal required-root outcomes return.
    fn run(self: Box<Self>, cancellation: ProcessCancellation) -> ProcessFuture<Result<(), E>>;

    /// Explicitly releases a prepared or synchronously activated root.
    ///
    /// Completion must mean the root's owned resources have been released; returning
    /// an error reports cleanup failure rather than substituting owner drop for reap.
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), E>>;
}

type PreparedRootBox<E> = Box<dyn PreparedProcessRoot<E>>;
type PrepareFuture<E> = ProcessFuture<Result<PreparedRootBox<E>, E>>;
type PrepareFactory<E> = Box<dyn FnOnce() -> PrepareFuture<E> + Send + 'static>;

/// One required root's fallible preparation seam.
pub struct ProcessRoot<E> {
    prepare: PrepareFactory<E>,
}

impl<E> ProcessRoot<E> {
    /// Creates a root adapter without polling or creating public service work.
    ///
    /// The preparation future must own any partially constructed state so either
    /// cancellation or `Err` releases it. Successfully returned roots are rolled
    /// back by the process supervisor in deterministic reverse order.
    pub fn new<P, F, R>(prepare: P) -> Self
    where
        P: FnOnce() -> F + Send + 'static,
        F: Future<Output = Result<R, E>> + Send + 'static,
        R: PreparedProcessRoot<E>,
    {
        Self {
            prepare: Box::new(move || {
                Box::pin(async move {
                    prepare()
                        .await
                        .map(|root| Box::new(root) as PreparedRootBox<E>)
                })
            }),
        }
    }

    fn into_prepare_future(self) -> PrepareFuture<E> {
        (self.prepare)()
    }
}

impl<E> std::fmt::Debug for ProcessRoot<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProcessRoot([prepare])")
    }
}

/// Stable insertion-order identity of one required root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessRootId(usize);

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

/// Bounded lifecycle report returned only after rollback or root reaping.
#[derive(Debug, Eq, PartialEq)]
pub struct ProcessReport<E> {
    states: Vec<ProcessState>,
    cause: ProcessCause<E>,
    forced_roots: usize,
    cleanup_failure: Option<ProcessCleanupFailure<E>>,
}

impl<E> ProcessReport<E> {
    /// Returns the complete bounded state sequence.
    pub fn states(&self) -> &[ProcessState] {
        &self.states
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

/// Invalid process-supervisor construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSupervisorConfigError {
    NoRequiredRoots,
}

impl std::fmt::Display for ProcessSupervisorConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("process has no required roots")
    }
}

impl std::error::Error for ProcessSupervisorConfigError {}

/// Topology-neutral transaction over all required process roots.
#[derive(Debug)]
pub struct ProcessSupervisor<E> {
    roots: Vec<ProcessRoot<E>>,
    shutdown_grace: Duration,
    registry: OwnerRegistry,
}

impl<E> ProcessSupervisor<E>
where
    E: Send + 'static,
{
    /// Creates a validated supervisor over at least one required root.
    pub fn new(
        roots: Vec<ProcessRoot<E>>,
        shutdown_grace: Duration,
        registry: OwnerRegistry,
    ) -> Result<Self, ProcessSupervisorConfigError> {
        if roots.is_empty() {
            return Err(ProcessSupervisorConfigError::NoRequiredRoots);
        }
        Ok(Self {
            roots,
            shutdown_grace,
            registry,
        })
    }

    /// Prepares every root, activates them atomically, then supervises until stop.
    pub async fn run_until<S>(self, shutdown: S) -> ProcessReport<E>
    where
        S: Future<Output = ()> + Send,
    {
        let Self {
            roots,
            shutdown_grace,
            registry,
        } = self;
        let baseline = registry.snapshot();
        let process_guard = registry.track_process_supervisor();
        let (cancellation_source, cancellation) = ProcessCancellationSource::new();
        let mut states = vec![ProcessState::Validated, ProcessState::Preparing];
        let mut prepared = Vec::with_capacity(roots.len());
        tokio::pin!(shutdown);

        for (index, root) in roots.into_iter().enumerate() {
            let root_id = ProcessRootId(index);
            let preparation = catch_unwind(AssertUnwindSafe(|| root.into_prepare_future()));
            let preparation = match preparation {
                Ok(future) => {
                    let preparation = catch_process_future(future);
                    tokio::pin!(preparation);
                    tokio::select! {
                        biased;
                        () = &mut shutdown => {
                            cancellation_source.quiesce();
                            states.push(ProcessState::Rollback);
                            let cleanup_failure = rollback_prepared(prepared, &registry).await;
                            return finish_report(
                                states,
                                ProcessCause::ExternalShutdown,
                                0,
                                cleanup_failure,
                                FinishContext {
                                    process_guard,
                                    baseline,
                                    registry: &registry,
                                },
                            );
                        }
                        result = &mut preparation => result,
                    }
                }
                Err(_) => Err(()),
            };
            match preparation {
                Ok(Ok(root)) => prepared.push(PreparedEntry {
                    id: root_id,
                    root,
                    guard: registry.track_prepared_process_root(),
                }),
                Ok(Err(error)) => {
                    cancellation_source.quiesce();
                    states.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        states,
                        ProcessCause::PreparationFailed {
                            root: root_id,
                            error,
                        },
                        0,
                        cleanup_failure,
                        FinishContext {
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    );
                }
                Err(()) => {
                    cancellation_source.quiesce();
                    states.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        states,
                        ProcessCause::PreparationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    );
                }
            }
        }

        states.push(ProcessState::Prepared);
        for position in 0..prepared.len() {
            if future_is_ready(shutdown.as_mut()).await {
                cancellation_source.quiesce();
                states.push(ProcessState::Rollback);
                let cleanup_failure = rollback_prepared(prepared, &registry).await;
                return finish_report(
                    states,
                    ProcessCause::ExternalShutdown,
                    0,
                    cleanup_failure,
                    FinishContext {
                        process_guard,
                        baseline,
                        registry: &registry,
                    },
                );
            }
            let root_id = prepared[position].id;
            let activation = catch_unwind(AssertUnwindSafe(|| prepared[position].root.activate()));
            match activation {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    cancellation_source.quiesce();
                    states.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        states,
                        ProcessCause::ActivationFailed {
                            root: root_id,
                            error,
                        },
                        0,
                        cleanup_failure,
                        FinishContext {
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    );
                }
                Err(_) => {
                    cancellation_source.quiesce();
                    states.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        states,
                        ProcessCause::ActivationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    );
                }
            }
        }

        if future_is_ready(shutdown.as_mut()).await {
            cancellation_source.quiesce();
            states.push(ProcessState::Rollback);
            let cleanup_failure = rollback_prepared(prepared, &registry).await;
            return finish_report(
                states,
                ProcessCause::ExternalShutdown,
                0,
                cleanup_failure,
                FinishContext {
                    process_guard,
                    baseline,
                    registry: &registry,
                },
            );
        }

        let mut prepared = prepared.into_iter();
        let mut unstarted = Vec::with_capacity(prepared.len());
        while let Some(entry) = prepared.next() {
            let PreparedEntry {
                id: root_id,
                root,
                guard,
            } = entry;
            match catch_unwind(AssertUnwindSafe(|| root.run(cancellation.clone()))) {
                Ok(future) => unstarted.push(UnstartedEntry {
                    id: root_id,
                    future,
                    guard,
                }),
                Err(_) => {
                    drop(guard);
                    cancellation_source.quiesce();
                    states.push(ProcessState::Rollback);
                    let mut cleanup_failure =
                        rollback_prepared(prepared.collect(), &registry).await;
                    let handoff_cleanup = rollback_unstarted(unstarted, &registry).await;
                    if cleanup_failure.is_none() {
                        cleanup_failure = handoff_cleanup;
                    }
                    return finish_report(
                        states,
                        ProcessCause::ActivationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    );
                }
            }
        }

        let mut active = unstarted
            .into_iter()
            .map(|entry| {
                let active_guard = registry.track_active_process_root();
                drop(entry.guard);
                ActiveEntry {
                    id: entry.id,
                    task: Some(tokio::spawn(entry.future)),
                    guard: Some(active_guard),
                }
            })
            .collect::<Vec<_>>();
        states.push(ProcessState::Active);
        tokio::task::yield_now().await;

        let cause = tokio::select! {
            biased;
            () = &mut shutdown => ProcessCause::ExternalShutdown,
            event = next_root_event(&mut active, &registry) => {
                states.push(ProcessState::Fatal);
                ProcessCause::RootStopped {
                    root: event.root,
                    exit: event.exit,
                }
            }
        };

        cancellation_source.quiesce();
        states.push(ProcessState::Quiescing);
        states.push(ProcessState::Draining);
        let deadline = Instant::now() + shutdown_grace;
        let mut cleanup_failure = None;
        let mut forced_roots = 0;
        let mut force_reap_deadline = None;

        while active.iter().any(ActiveEntry::is_running) {
            if let Some(force_reap_deadline) = force_reap_deadline {
                let timed_out = tokio::select! {
                    biased;
                    event = next_root_event(&mut active, &registry) => {
                        record_cleanup_event(event, &mut cleanup_failure);
                        false
                    }
                    () = tokio::time::sleep_until(force_reap_deadline) => true,
                };
                if timed_out {
                    let roots = abort_and_reap_remaining(&mut active, &registry).await;
                    cleanup_failure = Some(ProcessCleanupFailure::ForceReapTimedOut {
                        roots,
                        prior: cleanup_failure.take().map(Box::new),
                    });
                }
                continue;
            }
            let timed_out = tokio::select! {
                biased;
                event = next_root_event(&mut active, &registry) => {
                    record_cleanup_event(event, &mut cleanup_failure);
                    false
                }
                () = tokio::time::sleep_until(deadline) => true,
            };
            if timed_out {
                states.push(ProcessState::Forced);
                cancellation_source.force();
                forced_roots = active.iter().filter(|entry| entry.is_running()).count();
                registry.record_process_forced_roots(forced_roots);
                force_reap_deadline = Some(Instant::now() + FORCE_REAP_WATCHDOG);
            }
        }

        finish_report(
            states,
            cause,
            forced_roots,
            cleanup_failure,
            FinishContext {
                process_guard,
                baseline,
                registry: &registry,
            },
        )
    }
}

struct PreparedEntry<E> {
    id: ProcessRootId,
    root: PreparedRootBox<E>,
    guard: OwnerGuard,
}

struct UnstartedEntry<E> {
    id: ProcessRootId,
    future: ProcessFuture<Result<(), E>>,
    guard: OwnerGuard,
}

struct ActiveEntry<E> {
    id: ProcessRootId,
    task: Option<JoinHandle<Result<(), E>>>,
    guard: Option<OwnerGuard>,
}

impl<E> ActiveEntry<E> {
    fn is_running(&self) -> bool {
        self.task.is_some()
    }
}

impl<E> Drop for ActiveEntry<E> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct RootEvent<E> {
    root: ProcessRootId,
    exit: ProcessRootExit<E>,
}

async fn rollback_prepared<E: 'static>(
    mut prepared: Vec<PreparedEntry<E>>,
    registry: &OwnerRegistry,
) -> Option<ProcessCleanupFailure<E>> {
    let mut cleanup_failure = None;
    while let Some(entry) = prepared.pop() {
        let PreparedEntry {
            id: root_id,
            root,
            guard,
        } = entry;
        let rollback = catch_unwind(AssertUnwindSafe(|| root.rollback()));
        let rollback = match rollback {
            Ok(future) => catch_process_future(future).await,
            Err(_) => Err(()),
        };
        drop(guard);
        registry.record_process_root_rollback();
        let failure = match rollback {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(ProcessCleanupFailure::RootFailed {
                root: root_id,
                error,
            }),
            Err(()) => Some(ProcessCleanupFailure::RootPanicked { root: root_id }),
        };
        if cleanup_failure.is_none() {
            cleanup_failure = failure;
        }
    }
    cleanup_failure
}

async fn rollback_unstarted<E: Send + 'static>(
    mut unstarted: Vec<UnstartedEntry<E>>,
    registry: &OwnerRegistry,
) -> Option<ProcessCleanupFailure<E>> {
    let mut cleanup_failure = None;
    while let Some(entry) = unstarted.pop() {
        let task = tokio::spawn(entry.future);
        task.abort();
        let result = task.await;
        drop(entry.guard);
        registry.record_process_root_rollback();
        let failure = match result {
            Err(error) if error.is_cancelled() => None,
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(ProcessCleanupFailure::RootFailed {
                root: entry.id,
                error,
            }),
            Err(error) if error.is_panic() => {
                Some(ProcessCleanupFailure::RootPanicked { root: entry.id })
            }
            Err(_) => Some(ProcessCleanupFailure::RootJoinFailed { root: entry.id }),
        };
        if cleanup_failure.is_none() {
            cleanup_failure = failure;
        }
    }
    cleanup_failure
}

async fn catch_process_future<T>(mut future: ProcessFuture<T>) -> Result<T, ()> {
    std::future::poll_fn(|context| {
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    })
    .await
}

async fn future_is_ready<F>(mut future: Pin<&mut F>) -> bool
where
    F: Future + ?Sized,
{
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_ready())).await
}

async fn next_root_event<E>(
    active: &mut [ActiveEntry<E>],
    registry: &OwnerRegistry,
) -> RootEvent<E> {
    std::future::poll_fn(|context| poll_next_root(active, registry, context)).await
}

fn poll_next_root<E>(
    active: &mut [ActiveEntry<E>],
    registry: &OwnerRegistry,
    context: &mut Context<'_>,
) -> Poll<RootEvent<E>> {
    for entry in active {
        let Some(task) = entry.task.as_mut() else {
            continue;
        };
        let result = match Pin::new(task).poll(context) {
            Poll::Ready(result) => result,
            Poll::Pending => continue,
        };
        let exit = root_exit(result);
        entry.task.take();
        entry.guard.take();
        registry.record_process_root_reap();
        return Poll::Ready(RootEvent {
            root: entry.id,
            exit,
        });
    }
    Poll::Pending
}

fn root_exit<E>(result: Result<Result<(), E>, JoinError>) -> ProcessRootExit<E> {
    match result {
        Ok(Ok(())) => ProcessRootExit::Completed,
        Ok(Err(error)) => ProcessRootExit::Failed(error),
        Err(error) if error.is_panic() => ProcessRootExit::Panicked,
        Err(_) => ProcessRootExit::JoinFailed,
    }
}

fn record_cleanup_event<E>(
    event: RootEvent<E>,
    cleanup_failure: &mut Option<ProcessCleanupFailure<E>>,
) {
    if cleanup_failure.is_some() {
        return;
    }
    *cleanup_failure = match event.exit {
        ProcessRootExit::Completed => None,
        ProcessRootExit::Failed(error) => Some(ProcessCleanupFailure::RootFailed {
            root: event.root,
            error,
        }),
        ProcessRootExit::Panicked => Some(ProcessCleanupFailure::RootPanicked { root: event.root }),
        ProcessRootExit::JoinFailed => {
            Some(ProcessCleanupFailure::RootJoinFailed { root: event.root })
        }
    };
}

async fn abort_and_reap_remaining<E>(
    active: &mut [ActiveEntry<E>],
    registry: &OwnerRegistry,
) -> Vec<ProcessRootId> {
    let roots = active
        .iter()
        .filter(|entry| entry.is_running())
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    for entry in active.iter() {
        if let Some(task) = &entry.task {
            task.abort();
        }
    }
    for entry in active {
        if let Some(task) = entry.task.take() {
            let _ = task.await;
            entry.guard.take();
            registry.record_process_root_reap();
        }
    }
    roots
}

struct FinishContext<'a> {
    process_guard: OwnerGuard,
    baseline: OwnerSnapshot,
    registry: &'a OwnerRegistry,
}

fn finish_report<E>(
    mut states: Vec<ProcessState>,
    cause: ProcessCause<E>,
    forced_roots: usize,
    mut cleanup_failure: Option<ProcessCleanupFailure<E>>,
    finish: FinishContext<'_>,
) -> ProcessReport<E> {
    states.push(ProcessState::Stopped);
    drop(finish.process_guard);
    let stopped = finish.registry.snapshot();
    if cleanup_failure.is_none() && !finish.baseline.has_same_active_owners(stopped) {
        cleanup_failure = Some(ProcessCleanupFailure::OwnerMismatch {
            baseline: Box::new(finish.baseline),
            stopped: Box::new(stopped),
        });
    }
    ProcessReport {
        states,
        cause,
        forced_roots,
        cleanup_failure,
    }
}
