use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, OwnerSnapshot};

use super::report::ProcessTimeline;
use super::transaction::{ActiveEntry, root_exit, root_exit_category};
use super::{
    ProcessCause, ProcessCleanupFailure, ProcessReport, ProcessRootEventPhase,
    ProcessRootExitCategory, ProcessRootId, ProcessState,
};

pub(super) async fn abort_and_reap_remaining<E>(
    active: &mut [ActiveEntry<E>],
    registry: &OwnerRegistry,
    timeline: &mut ProcessTimeline,
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
            let result = task.await;
            let exit = match result {
                Err(error) if error.is_cancelled() => ProcessRootExitCategory::Aborted,
                result => root_exit_category(&root_exit(result)),
            };
            timeline.push_root_event(entry.id, ProcessRootEventPhase::WatchdogAbort, exit);
            entry.guard.take();
            registry.record_process_root_reap();
        }
    }
    roots
}

pub(super) struct FinishContext<'a> {
    pub(super) process_guard: OwnerGuard,
    pub(super) baseline: OwnerSnapshot,
    pub(super) registry: &'a OwnerRegistry,
}

pub(super) fn finish_report<E>(
    mut timeline: ProcessTimeline,
    cause: ProcessCause<E>,
    forced_roots: usize,
    mut cleanup_failure: Option<ProcessCleanupFailure<E>>,
    finish: FinishContext<'_>,
) -> ProcessReport<E> {
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
