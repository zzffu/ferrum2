use std::sync::Arc;

use futures_util::FutureExt;
use tokio::sync::{Mutex, Semaphore};

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};

// Per loader, including workers whose async caller has been cancelled. Normal
// materialization/refresh is sequential; concurrent callers share this bound.
const MAX_BLOCKING_OPERATIONS: usize = 2;

/// Owns admission and retryable joins for cache I/O and compiler workers.
/// Permits live in blocking closures, so cancellation cannot admit replacement
/// work while the original operation is still running.
pub(crate) struct BlockingTaskOwner {
    state: Mutex<BlockingTaskState>,
    slots: Arc<Semaphore>,
}

struct BlockingTaskState {
    accepting: bool,
    failed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl BlockingTaskOwner {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(BlockingTaskState {
                accepting: true,
                failed: false,
                tasks: Vec::new(),
            }),
            slots: Arc::new(Semaphore::new(MAX_BLOCKING_OPERATIONS)),
        }
    }

    pub(crate) async fn run<T, F>(&self, operation: F) -> Result<T, RuleSetLoadError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut state = self.state.lock().await;
            if !state.accepting {
                return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task));
            }
            let mut cursor = 0;
            while cursor < state.tasks.len() {
                if state.tasks[cursor].is_finished() {
                    let task = state.tasks.swap_remove(cursor);
                    if task.now_or_never().is_some_and(|result| result.is_err()) {
                        state.failed = true;
                    }
                } else {
                    cursor += 1;
                }
            }
            // A closure can release its permit just before Tokio publishes its
            // JoinHandle as finished. Bound retained handles through that race
            // as well as bounding the actual blocking operations.
            if state.tasks.len() == MAX_BLOCKING_OPERATIONS {
                let failed = (&mut state.tasks[0]).await.is_err();
                state.tasks.swap_remove(0);
                state.failed |= failed;
            }
            state.tasks.push(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let _ = sender.send(operation());
            }));
        }
        receiver
            .await
            .map_err(|_| RuleSetLoadError::new(RuleSetLoadErrorKind::Task))
    }

    pub(crate) async fn shutdown(&self) -> Result<(), RuleSetLoadError> {
        self.slots.close();
        let mut state = self.state.lock().await;
        state.accepting = false;
        // Keep each handle in the owner while awaiting it. Cancelling this
        // future releases the async lock, but leaves the handle for a retry.
        // Concurrent shutdown calls wait on the same lock and see the same
        // sticky failure result only after all workers have joined.
        while let Some(task) = state.tasks.last_mut() {
            let failed = task.await.is_err();
            state.tasks.pop();
            state.failed |= failed;
        }
        if state.failed {
            Err(RuleSetLoadError::new(RuleSetLoadErrorKind::Task))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::BlockingTaskOwner;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiters_do_not_release_running_worker_capacity() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let mut releases = Vec::new();
        for _ in 0..super::MAX_BLOCKING_OPERATIONS {
            let (entered, entering) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::channel();
            releases.push(release);
            let waiter = tokio::spawn({
                let owner = Arc::clone(&owner);
                async move {
                    owner
                        .run(move || {
                            let _ = entered.send(());
                            released
                                .recv_timeout(std::time::Duration::from_secs(2))
                                .unwrap();
                        })
                        .await
                }
            });
            entering.await.unwrap();
            waiter.abort();
            assert!(waiter.await.unwrap_err().is_cancelled());
        }
        let mut extra = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.run(|| 7).await }
        });
        let early = tokio::time::timeout(std::time::Duration::from_millis(20), &mut extra).await;
        for release in releases {
            release.send(()).unwrap();
        }
        if early.is_err() {
            assert_eq!(extra.await.unwrap().unwrap(), 7);
        }
        owner.shutdown().await.unwrap();
        assert!(
            early.is_err(),
            "cancelled waiters must not admit unbounded blocking work"
        );
        assert!(owner.run(|| ()).await.is_err(), "shutdown closes admission");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_shutdown_can_be_retried_without_losing_running_work() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let (entered, entering) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let worker = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move {
                owner
                    .run(move || {
                        let _ = entered.send(());
                        released
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .unwrap();
                    })
                    .await
            }
        });
        entering.await.unwrap();
        let mut shutdown = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut shutdown)
                .await
                .is_err()
        );
        shutdown.abort();
        assert!(shutdown.await.unwrap_err().is_cancelled());
        let mut retry = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        let early = tokio::time::timeout(std::time::Duration::from_millis(20), &mut retry).await;
        release.send(()).unwrap();
        worker.await.unwrap().unwrap();
        if early.is_err() {
            retry.await.unwrap().unwrap();
        }
        assert!(
            early.is_err(),
            "retry must still wait for the original blocking worker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_leaves_blocking_work_owned_until_shutdown_joins_it() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let waiter = tokio::spawn({
            let owner = Arc::clone(&owner);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                owner
                    .run(move || {
                        entered.wait();
                        release.wait();
                    })
                    .await
            }
        });
        entered.wait();
        waiter.abort();
        assert!(waiter.await.is_err());

        let shutdown = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        release.wait();
        shutdown
            .await
            .expect("shutdown task")
            .expect("blocking task joined");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_remaining_work_after_an_earlier_worker_panics() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let panic_entered = Arc::new(Barrier::new(2));
        let release_panic = Arc::new(Barrier::new(2));
        let panicking = tokio::spawn({
            let owner = Arc::clone(&owner);
            let panic_entered = Arc::clone(&panic_entered);
            let release_panic = Arc::clone(&release_panic);
            async move {
                owner
                    .run(move || {
                        panic_entered.wait();
                        release_panic.wait();
                        panic!("controlled blocking worker failure");
                    })
                    .await
            }
        });
        panic_entered.wait();

        let blocked_entered = Arc::new(Barrier::new(2));
        let release_blocked = Arc::new(Barrier::new(2));
        let blocked = tokio::spawn({
            let owner = Arc::clone(&owner);
            let blocked_entered = Arc::clone(&blocked_entered);
            let release_blocked = Arc::clone(&release_blocked);
            async move {
                owner
                    .run(move || {
                        blocked_entered.wait();
                        release_blocked.wait();
                    })
                    .await
            }
        });
        blocked_entered.wait();
        release_panic.wait();
        assert!(panicking.await.expect("panicking waiter task").is_err());
        blocked.abort();
        assert!(blocked.await.is_err());

        let mut shutdown = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned before the remaining blocking worker completed"
        );
        release_blocked.wait();
        assert!(
            shutdown.await.expect("shutdown task").is_err(),
            "the first worker failure must remain observable after all workers join"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaping_a_finished_panicked_worker_preserves_the_shutdown_failure() {
        let owner = Arc::new(BlockingTaskOwner::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let waiter = tokio::spawn({
            let owner = Arc::clone(&owner);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                owner
                    .run(move || {
                        entered.wait();
                        release.wait();
                        panic!("controlled reaped worker failure");
                    })
                    .await
            }
        });
        entered.wait();
        waiter.abort();
        assert!(waiter.await.is_err());
        release.wait();
        loop {
            let finished = owner
                .state
                .lock()
                .await
                .tasks
                .first()
                .is_some_and(tokio::task::JoinHandle::is_finished);
            if finished {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(owner.run(|| 7_u8).await.expect("later worker"), 7);
        assert!(
            owner.shutdown().await.is_err(),
            "reaping a finished JoinHandle must not erase its panic"
        );
    }
}
