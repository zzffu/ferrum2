use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::task::JoinHandle;

use super::transaction::root_exit;
use super::{ProcessCleanupFailure, ProcessFuture, ProcessRootExit, ProcessRootId};
use crate::owner::OwnerGuard;

pub(super) struct ActiveEntry<E> {
    pub(super) id: ProcessRootId,
    pub(super) task: Option<JoinHandle<Result<(), E>>>,
    pub(super) cleanup: Option<ProcessFuture<Result<(), E>>>,
    pub(super) guard: Option<OwnerGuard>,
}

pub(super) enum RootEvent<E> {
    Exited {
        root: ProcessRootId,
        exit: ProcessRootExit<E>,
    },
    Cleaned {
        failure: Option<ProcessCleanupFailure<E>>,
    },
}

impl<E> ActiveEntry<E> {
    pub(super) fn is_running(&self) -> bool {
        self.guard.is_some()
    }

    /// Report task exit before polling cleanup, so the supervisor can cancel
    /// peers whose completion may be required by this root's final join.
    pub(super) fn poll_event(&mut self, context: &mut Context<'_>) -> Poll<RootEvent<E>> {
        if let Some(task) = self.task.as_mut() {
            let result = match Pin::new(task).poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            self.task.take();
            if self.cleanup.is_none() {
                self.guard.take();
            }
            return Poll::Ready(RootEvent::Exited {
                root: self.id,
                exit: root_exit(result),
            });
        }
        if self.guard.is_none() {
            return Poll::Pending;
        }
        let failure = match poll_cleanup(self.id, &mut self.cleanup, context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(failure) => failure,
        };
        self.guard.take();
        Poll::Ready(RootEvent::Cleaned { failure })
    }
}

impl<E> Drop for ActiveEntry<E> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(super) fn poll_cleanup<E>(
    id: ProcessRootId,
    cleanup: &mut Option<ProcessFuture<Result<(), E>>>,
    context: &mut Context<'_>,
) -> Poll<Option<ProcessCleanupFailure<E>>> {
    let Some(future) = cleanup.as_mut() else {
        return Poll::Ready(None);
    };
    let result = match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
        Ok(Poll::Pending) => return Poll::Pending,
        Ok(Poll::Ready(Ok(()))) => None,
        Ok(Poll::Ready(Err(error))) => Some(ProcessCleanupFailure::RootFailed { root: id, error }),
        Err(_) => Some(ProcessCleanupFailure::RootPanicked { root: id }),
    };
    cleanup.take();
    Poll::Ready(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnerRegistry;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn cancelled_cleanup_poll_retains_join_custody_after_pre_first_poll_abort() {
        let registry = OwnerRegistry::new();
        let ran = Arc::new(AtomicBool::new(false));
        let run_flag = Arc::clone(&ran);
        let task = tokio::spawn(async move {
            run_flag.store(true, Ordering::Release);
            std::future::pending::<Result<(), &'static str>>().await
        });
        task.abort();
        let (release, released) = tokio::sync::oneshot::channel();
        let child = tokio::spawn(async move {
            released.await.expect("bounded test release");
        });
        let (started, cleanup_started) = tokio::sync::oneshot::channel();
        let mut entry = ActiveEntry {
            id: ProcessRootId(0),
            task: Some(task),
            cleanup: Some(Box::pin(async move {
                let _ = started.send(());
                child.await.expect("child is joined");
                Err("cleanup")
            })),
            guard: Some(registry.track_active_process_root()),
        };
        tokio::task::yield_now().await;
        let event = std::future::poll_fn(|context| entry.poll_event(context)).await;
        assert!(matches!(
            event,
            RootEvent::Exited {
                exit: ProcessRootExit::JoinFailed,
                ..
            }
        ));
        let mut waiter = Box::pin(std::future::poll_fn(|context| entry.poll_event(context)));
        assert!(
            std::future::poll_fn(|context| Poll::Ready(waiter.as_mut().poll(context).is_pending()))
                .await
        );
        cleanup_started.await.unwrap();
        drop(waiter);
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(registry.snapshot().active_process_roots, 1);
        release.send(()).unwrap();
        let event = std::future::poll_fn(|context| entry.poll_event(context)).await;
        assert!(matches!(
            event,
            RootEvent::Cleaned {
                failure: Some(ProcessCleanupFailure::RootFailed {
                    error: "cleanup",
                    ..
                })
            }
        ));
        assert_eq!(registry.snapshot().active_process_roots, 0);
        assert!(!entry.is_running());
    }
}
