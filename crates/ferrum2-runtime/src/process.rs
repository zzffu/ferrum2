use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::{OwnerRegistry, OwnerSnapshot};

mod entry;
mod report;
mod shutdown;
mod transaction;

use entry::{ActiveEntry, RootEvent, poll_cleanup};
use report::ProcessTimeline;
pub use report::{
    ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessReport, ProcessRootEvent,
    ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory, ProcessRootId, ProcessState,
    ProcessTransition,
};
use shutdown::{FinishContext, abort_and_reap_remaining, finish_report};
use transaction::{
    PreparedEntry, UnstartedEntry, catch_process_future, future_is_ready, next_root_event,
    record_cleanup_event, rollback_prepared, rollback_unstarted, root_exit_category,
};

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

    /// Transfers an optional final cleanup future to the process supervisor.
    ///
    /// Called once before `run` is constructed. Use this when independently
    /// scheduled children or native resources must survive cancellation or panic
    /// of the run future. The returned future must retain their unique join
    /// custody and finish only after all of them are reaped; it must tolerate
    /// polling after run construction panics or before the run future is polled.
    /// A pending poll waiter may be dropped and retried without dropping this
    /// retained future. `None` means the root needs no separate cleanup owner.
    /// This does not guarantee cleanup if the entire supervisor is dropped.
    fn take_run_cleanup(&mut self) -> Option<ProcessFuture<Result<(), E>>> {
        None
    }

    /// Consumes the activated root into its public service future.
    ///
    /// The returned future owns the root and its children unless their join custody
    /// was transferred by `take_run_cleanup`. Other children must be reaped before
    /// it completes. The supervisor also awaits transferred cleanup before it
    /// reports the root reaped. Per-flow and per-session
    /// failures stay inside the adapter; only terminal required-root outcomes return.
    fn run(self: Box<Self>, cancellation: ProcessCancellation) -> ProcessFuture<Result<(), E>>;

    /// Explicitly releases a prepared or synchronously activated root.
    ///
    /// Completion must mean the root's owned resources have been released; returning
    /// an error reports cleanup failure rather than substituting owner drop for reap.
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), E>>;
}

type PreparedRootBox<E> = Box<dyn PreparedProcessRoot<E>>;
enum PrepareOutcome<E> {
    Prepared(PreparedRootBox<E>),
    Failed(E),
    Cancelled,
}

type PrepareFuture<E> = ProcessFuture<PrepareOutcome<E>>;
type PrepareFactory<E> = Box<dyn FnOnce(ProcessCancellation) -> PrepareFuture<E> + Send + 'static>;

/// One required root's fallible preparation seam.
pub struct ProcessRoot<E> {
    prepare: PrepareFactory<E>,
    reap_on_cancellation: bool,
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
            prepare: Box::new(move |_| {
                Box::pin(async move {
                    match prepare().await {
                        Ok(root) => PrepareOutcome::Prepared(Box::new(root) as PreparedRootBox<E>),
                        Err(error) => PrepareOutcome::Failed(error),
                    }
                })
            }),
            reap_on_cancellation: false,
        }
    }

    /// Creates a root whose in-flight preparation explicitly reaps on cancellation.
    ///
    /// `Ok(None)` acknowledges clean cancellation. Once cancellation is signalled,
    /// `Err` is recorded as cleanup failure and `Ok(Some(root))` is rolled back.
    pub fn new_cancellable<P, F, R>(prepare: P) -> Self
    where
        P: FnOnce(ProcessCancellation) -> F + Send + 'static,
        F: Future<Output = Result<Option<R>, E>> + Send + 'static,
        R: PreparedProcessRoot<E>,
    {
        Self {
            prepare: Box::new(move |cancellation| {
                Box::pin(async move {
                    match prepare(cancellation).await {
                        Ok(Some(root)) => {
                            PrepareOutcome::Prepared(Box::new(root) as PreparedRootBox<E>)
                        }
                        Ok(None) => PrepareOutcome::Cancelled,
                        Err(error) => PrepareOutcome::Failed(error),
                    }
                })
            }),
            reap_on_cancellation: true,
        }
    }

    fn into_prepare_future(self, cancellation: ProcessCancellation) -> (PrepareFuture<E>, bool) {
        ((self.prepare)(cancellation), self.reap_on_cancellation)
    }
}

impl<E> std::fmt::Debug for ProcessRoot<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProcessRoot([prepare])")
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

/// Shared process resources handed off with their original registry baseline.
///
/// Capture `baseline` from the same [`OwnerRegistry`] used by the supervisor,
/// before creating the first resource owned by `cleanup`. The cleanup future must
/// close admission and join actual work after all roots stop. Never substitute a
/// later snapshot to hide resources that were not reaped.
pub struct ProcessResources<E> {
    pub baseline: OwnerSnapshot,
    pub cleanup: ProcessFuture<Result<(), E>>,
}

/// Topology-neutral transaction over all required process roots.
pub struct ProcessSupervisor<E> {
    roots: Vec<ProcessRoot<E>>,
    shutdown_grace: Duration,
    registry: OwnerRegistry,
    resources: Option<ProcessResources<E>>,
}

impl<E> std::fmt::Debug for ProcessSupervisor<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessSupervisor")
            .field("roots", &self.roots)
            .field("shutdown_grace", &self.shutdown_grace)
            .field("registry", &self.registry)
            .field("has_process_resources", &self.resources.is_some())
            .finish()
    }
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
            resources: None,
        })
    }

    /// Takes ownership of shared resources and their pre-materialization baseline.
    ///
    /// Register once before preparation. Resource cleanup runs after every root
    /// has rolled back or been reaped, including startup failures, and before the
    /// final registry comparison against the supplied baseline. Cleanup failure
    /// preserves earlier root/watchdog failures. Actual joins are not aborted to
    /// simulate a hard cleanup deadline.
    pub fn with_process_resources(mut self, resources: ProcessResources<E>) -> Self {
        assert!(self.resources.is_none(), "one process resource handoff");
        self.resources = Some(resources);
        self
    }

    /// Prepares every root, activates them atomically, then supervises until stop.
    ///
    /// Drive this future to completion to obtain the transitive cleanup guarantee.
    /// Dropping the whole supervisor aborts roots, but cannot asynchronously join
    /// them or their separately retained cleanup futures from synchronous Drop.
    pub async fn run_until<S>(self, shutdown: S) -> ProcessReport<E>
    where
        S: Future<Output = ()> + Send,
    {
        let Self {
            roots,
            shutdown_grace,
            registry,
            resources,
        } = self;
        let (baseline, final_cleanup) = match resources {
            Some(ProcessResources { baseline, cleanup }) => (baseline, Some(cleanup)),
            None => (registry.snapshot(), None),
        };
        let process_guard = registry.track_process_supervisor();
        let (cancellation_source, cancellation) = ProcessCancellationSource::new();
        let root_count = roots.len();
        let mut timeline = ProcessTimeline::new(root_count);
        let mut prepared = Vec::with_capacity(root_count);
        tokio::pin!(shutdown);

        for (index, root) in roots.into_iter().enumerate() {
            let root_id = ProcessRootId(index);
            let preparation = catch_unwind(AssertUnwindSafe(|| {
                root.into_prepare_future(cancellation.clone())
            }));
            let preparation = match preparation {
                Ok((future, reap_on_cancellation)) => {
                    let preparation = catch_process_future(future);
                    tokio::pin!(preparation);
                    tokio::select! {
                        biased;
                        () = &mut shutdown => {
                            cancellation_source.quiesce();
                            timeline.push(ProcessState::Rollback);
                            let mut cleanup_failure = None;
                            if reap_on_cancellation {
                                match preparation.await {
                                    Ok(PrepareOutcome::Cancelled) => {}
                                    Ok(PrepareOutcome::Failed(error)) => {
                                        cleanup_failure = Some(ProcessCleanupFailure::RootFailed {
                                            root: root_id,
                                            error,
                                        });
                                    }
                                    Ok(PrepareOutcome::Prepared(root)) => {
                                        prepared.push(PreparedEntry {
                                            id: root_id,
                                            root,
                                            guard: registry.track_prepared_process_root(),
                                        });
                                    }
                                    Err(()) => {
                                        cleanup_failure = Some(ProcessCleanupFailure::RootPanicked {
                                            root: root_id,
                                        });
                                    }
                                }
                            }
                            let rollback_failure = rollback_prepared(prepared, &registry).await;
                            if cleanup_failure.is_none() {
                                cleanup_failure = rollback_failure;
                            }
                            return finish_report(
                                timeline,
                                ProcessCause::ExternalShutdown,
                                0,
                                cleanup_failure,
                                FinishContext {
                    final_cleanup,
                                    process_guard,
                                    baseline,
                                    registry: &registry,
                                },
                            ).await;
                        }
                        result = &mut preparation => result,
                    }
                }
                Err(_) => Err(()),
            };
            match preparation {
                Ok(PrepareOutcome::Prepared(root)) => prepared.push(PreparedEntry {
                    id: root_id,
                    root,
                    guard: registry.track_prepared_process_root(),
                }),
                Ok(PrepareOutcome::Failed(error)) => {
                    cancellation_source.quiesce();
                    timeline.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        timeline,
                        ProcessCause::PreparationFailed {
                            root: root_id,
                            error,
                        },
                        0,
                        cleanup_failure,
                        FinishContext {
                            final_cleanup,
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    )
                    .await;
                }
                Ok(PrepareOutcome::Cancelled) | Err(()) => {
                    cancellation_source.quiesce();
                    timeline.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        timeline,
                        ProcessCause::PreparationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            final_cleanup,
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    )
                    .await;
                }
            }
        }

        timeline.push(ProcessState::Prepared);
        for position in 0..prepared.len() {
            if future_is_ready(shutdown.as_mut()).await {
                cancellation_source.quiesce();
                timeline.push(ProcessState::Rollback);
                let cleanup_failure = rollback_prepared(prepared, &registry).await;
                return finish_report(
                    timeline,
                    ProcessCause::ExternalShutdown,
                    0,
                    cleanup_failure,
                    FinishContext {
                        final_cleanup,
                        process_guard,
                        baseline,
                        registry: &registry,
                    },
                )
                .await;
            }
            let root_id = prepared[position].id;
            let activation = catch_unwind(AssertUnwindSafe(|| prepared[position].root.activate()));
            match activation {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    cancellation_source.quiesce();
                    timeline.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        timeline,
                        ProcessCause::ActivationFailed {
                            root: root_id,
                            error,
                        },
                        0,
                        cleanup_failure,
                        FinishContext {
                            final_cleanup,
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    )
                    .await;
                }
                Err(_) => {
                    cancellation_source.quiesce();
                    timeline.push(ProcessState::Rollback);
                    let cleanup_failure = rollback_prepared(prepared, &registry).await;
                    return finish_report(
                        timeline,
                        ProcessCause::ActivationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            final_cleanup,
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    )
                    .await;
                }
            }
        }

        if future_is_ready(shutdown.as_mut()).await {
            cancellation_source.quiesce();
            timeline.push(ProcessState::Rollback);
            let cleanup_failure = rollback_prepared(prepared, &registry).await;
            return finish_report(
                timeline,
                ProcessCause::ExternalShutdown,
                0,
                cleanup_failure,
                FinishContext {
                    final_cleanup,
                    process_guard,
                    baseline,
                    registry: &registry,
                },
            )
            .await;
        }

        let mut prepared = prepared.into_iter();
        let mut unstarted = Vec::with_capacity(prepared.len());
        while let Some(entry) = prepared.next() {
            let PreparedEntry {
                id: root_id,
                mut root,
                guard,
            } = entry;
            let mut cleanup = None;
            match catch_unwind(AssertUnwindSafe(|| {
                cleanup = root.take_run_cleanup();
                root.run(cancellation.clone())
            })) {
                Ok(future) => unstarted.push(UnstartedEntry {
                    id: root_id,
                    future,
                    cleanup,
                    guard,
                }),
                Err(_) => {
                    cancellation_source.quiesce();
                    timeline.push(ProcessState::Rollback);
                    let owned_cleanup = std::future::poll_fn(|context| {
                        poll_cleanup(root_id, &mut cleanup, context)
                    })
                    .await;
                    drop(guard);
                    let mut cleanup_failure =
                        rollback_prepared(prepared.collect(), &registry).await;
                    if owned_cleanup.is_some() {
                        cleanup_failure = owned_cleanup;
                    }
                    let handoff_cleanup = rollback_unstarted(unstarted, &registry).await;
                    if cleanup_failure.is_none() {
                        cleanup_failure = handoff_cleanup;
                    }
                    return finish_report(
                        timeline,
                        ProcessCause::ActivationPanicked { root: root_id },
                        0,
                        cleanup_failure,
                        FinishContext {
                            final_cleanup,
                            process_guard,
                            baseline,
                            registry: &registry,
                        },
                    )
                    .await;
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
                    cleanup: entry.cleanup,
                    guard: Some(active_guard),
                }
            })
            .collect::<Vec<_>>();
        timeline.push(ProcessState::Active);
        tokio::task::yield_now().await;

        let cause = tokio::select! {
            biased;
            () = &mut shutdown => ProcessCause::ExternalShutdown,
            event = next_root_event(&mut active, &registry) => {
                let RootEvent::Exited { root, exit } = event else {
                    unreachable!("cleanup cannot precede the first root exit");
                };
                timeline.push_root_event(root, ProcessRootEventPhase::Active, root_exit_category(&exit));
                timeline.push(ProcessState::Fatal);
                ProcessCause::RootStopped { root, exit }
            }
        };
        let mut cleanup_failure = None;

        cancellation_source.quiesce();
        timeline.push(ProcessState::Quiescing);
        timeline.push(ProcessState::Draining);
        let deadline = Instant::now() + shutdown_grace;
        timeline.record_grace_deadline(deadline);
        let mut forced_roots = 0;
        let mut force_reap_deadline = None;

        while active.iter().any(ActiveEntry::is_running) {
            if let Some(force_reap_deadline) = force_reap_deadline {
                let timed_out = tokio::select! {
                    biased;
                    event = next_root_event(&mut active, &registry) => {
                        if let RootEvent::Exited { root, exit } = &event {
                            timeline.push_root_event(*root, ProcessRootEventPhase::Forced, root_exit_category(exit));
                        }
                        record_cleanup_event(event, &mut cleanup_failure);
                        false
                    }
                    () = tokio::time::sleep_until(force_reap_deadline) => true,
                };
                if timed_out {
                    let (roots, owned_cleanup) =
                        abort_and_reap_remaining(&mut active, &registry, &mut timeline).await;
                    cleanup_failure = Some(ProcessCleanupFailure::ForceReapTimedOut {
                        roots,
                        prior: owned_cleanup
                            .or_else(|| cleanup_failure.take())
                            .map(Box::new),
                    });
                }
                continue;
            }
            let timed_out = tokio::select! {
                biased;
                event = next_root_event(&mut active, &registry) => {
                    if let RootEvent::Exited { root, exit } = &event {
                        timeline.push_root_event(*root, ProcessRootEventPhase::Draining, root_exit_category(exit));
                    }
                    record_cleanup_event(event, &mut cleanup_failure);
                    false
                }
                () = tokio::time::sleep_until(deadline) => true,
            };
            if timed_out {
                timeline.push(ProcessState::Forced);
                cancellation_source.force();
                forced_roots = active.iter().filter(|entry| entry.is_running()).count();
                registry.record_process_forced_roots(forced_roots);
                force_reap_deadline = Some(Instant::now() + FORCE_REAP_WATCHDOG);
            }
        }

        finish_report(
            timeline,
            cause,
            forced_roots,
            cleanup_failure,
            FinishContext {
                final_cleanup,
                process_guard,
                baseline,
                registry: &registry,
            },
        )
        .await
    }
}
