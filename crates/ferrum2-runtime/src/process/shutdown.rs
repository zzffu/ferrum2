use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, OwnerSnapshot};

use super::entry::{ActiveEntry, RootEvent};
use super::report::ProcessTimeline;
use super::transaction::{
    catch_process_future, next_root_event, record_cleanup_event, root_exit_category,
};
use super::{
    ProcessCause, ProcessCleanupFailure, ProcessReport, ProcessRootEventPhase, ProcessRootExit,
    ProcessRootExitCategory, ProcessRootId, ProcessState,
};

pub(super) async fn abort_and_reap_remaining<E>(
    active: &mut [ActiveEntry<E>],
    registry: &OwnerRegistry,
    timeline: &mut ProcessTimeline,
) -> (Vec<ProcessRootId>, Option<ProcessCleanupFailure<E>>) {
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
    let mut cleanup_failure = None;
    while active.iter().any(ActiveEntry::is_running) {
        let mut event = next_root_event(active, registry).await;
        if let RootEvent::Exited { root, exit } = &mut event {
            let category = match &exit {
                ProcessRootExit::JoinFailed => ProcessRootExitCategory::Aborted,
                exit => root_exit_category(exit),
            };
            timeline.push_root_event(*root, ProcessRootEventPhase::WatchdogAbort, category);
            if matches!(exit, ProcessRootExit::JoinFailed) {
                *exit = ProcessRootExit::Completed;
            }
        }
        record_cleanup_event(event, &mut cleanup_failure);
    }
    (roots, cleanup_failure)
}

pub(super) struct FinishContext<'a, E> {
    pub(super) final_cleanup: Option<super::ProcessFuture<Result<(), E>>>,
    pub(super) process_guard: OwnerGuard,
    pub(super) baseline: OwnerSnapshot,
    pub(super) registry: &'a OwnerRegistry,
}

pub(super) async fn finish_report<E>(
    mut timeline: ProcessTimeline,
    cause: ProcessCause<E>,
    forced_roots: usize,
    mut cleanup_failure: Option<ProcessCleanupFailure<E>>,
    finish: FinishContext<'_, E>,
) -> ProcessReport<E> {
    if let Some(cleanup) = finish.final_cleanup {
        match catch_process_future(cleanup).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                cleanup_failure = Some(ProcessCleanupFailure::FinalCleanupFailed {
                    error,
                    prior: cleanup_failure.take().map(Box::new),
                });
            }
            Err(()) => {
                cleanup_failure = Some(ProcessCleanupFailure::FinalCleanupPanicked {
                    prior: cleanup_failure.take().map(Box::new),
                });
            }
        }
    }
    timeline.push(ProcessState::Stopped);
    drop(finish.process_guard);
    let stopped = finish.registry.snapshot();
    if cleanup_failure.is_none() && !finish.baseline.has_same_active_owners(stopped) {
        cleanup_failure = Some(ProcessCleanupFailure::OwnerMismatch {
            baseline: Box::new(finish.baseline),
            stopped: Box::new(stopped),
        });
    }
    ProcessReport {
        states: timeline.states,
        transitions: timeline.transitions,
        root_events: timeline.root_events,
        grace_deadline_elapsed: timeline.grace_deadline_elapsed,
        cause,
        forced_roots,
        cleanup_failure,
    }
}
