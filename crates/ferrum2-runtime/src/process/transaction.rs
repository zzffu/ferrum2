use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::task::{JoinError, JoinHandle};

use crate::OwnerRegistry;
use crate::owner::OwnerGuard;

use super::{
    PreparedRootBox, ProcessCleanupFailure, ProcessFuture, ProcessRootExit,
    ProcessRootExitCategory, ProcessRootId,
};

pub(super) struct PreparedEntry<E> {
    pub(super) id: ProcessRootId,
    pub(super) root: PreparedRootBox<E>,
    pub(super) guard: OwnerGuard,
}

pub(super) struct UnstartedEntry<E> {
    pub(super) id: ProcessRootId,
    pub(super) future: ProcessFuture<Result<(), E>>,
    pub(super) guard: OwnerGuard,
}

pub(super) struct ActiveEntry<E> {
    pub(super) id: ProcessRootId,
    pub(super) task: Option<JoinHandle<Result<(), E>>>,
    pub(super) guard: Option<OwnerGuard>,
}

impl<E> ActiveEntry<E> {
    pub(super) fn is_running(&self) -> bool {
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

pub(super) struct RootEvent<E> {
    pub(super) root: ProcessRootId,
    pub(super) exit: ProcessRootExit<E>,
}

pub(super) async fn rollback_prepared<E: 'static>(
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

pub(super) async fn rollback_unstarted<E: Send + 'static>(
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

pub(super) async fn catch_process_future<T>(mut future: ProcessFuture<T>) -> Result<T, ()> {
    std::future::poll_fn(|context| {
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    })
    .await
}

pub(super) async fn future_is_ready<F>(mut future: Pin<&mut F>) -> bool
where
    F: Future + ?Sized,
{
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_ready())).await
}

pub(super) async fn next_root_event<E>(
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

pub(super) fn root_exit<E>(result: Result<Result<(), E>, JoinError>) -> ProcessRootExit<E> {
    match result {
        Ok(Ok(())) => ProcessRootExit::Completed,
        Ok(Err(error)) => ProcessRootExit::Failed(error),
        Err(error) if error.is_panic() => ProcessRootExit::Panicked,
        Err(_) => ProcessRootExit::JoinFailed,
    }
}

pub(super) fn root_exit_category<E>(exit: &ProcessRootExit<E>) -> ProcessRootExitCategory {
    match exit {
        ProcessRootExit::Completed => ProcessRootExitCategory::Completed,
        ProcessRootExit::Failed(_) => ProcessRootExitCategory::Failed,
        ProcessRootExit::Panicked => ProcessRootExitCategory::Panicked,
        ProcessRootExit::JoinFailed => ProcessRootExitCategory::JoinFailed,
    }
}

pub(super) fn record_cleanup_event<E>(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_join_uses_closed_join_failed_category() {
        let task = tokio::spawn(std::future::pending::<Result<(), &'static str>>());
        tokio::task::yield_now().await;
        task.abort();

        let exit = root_exit(task.await);

        assert!(matches!(&exit, ProcessRootExit::JoinFailed));
        assert_eq!(
            root_exit_category(&exit),
            ProcessRootExitCategory::JoinFailed
        );
    }
}
