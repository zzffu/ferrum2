use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

use super::{OwnerControl, OwnerExit};
use crate::OwnerWake;

pub(crate) struct OwnerThread {
    pub(crate) control: OwnerControl,
    pub(crate) work: OwnerWake,
    pub(crate) thread: Option<std::thread::JoinHandle<OwnerExit>>,
}

impl OwnerThread {
    fn signal(&self) {
        self.control.stop.store(true, Ordering::Release);
        self.work.signal();
    }

    pub(crate) async fn reap(mut self) -> OwnerExit {
        self.signal();
        let Some(thread) = self.thread.take() else {
            return OwnerExit::CleanupFailed;
        };
        PendingThreadJoin::new(thread).complete().await
    }
}

impl Drop for OwnerThread {
    fn drop(&mut self) {
        self.signal();
        if let Some(thread) = self.thread.take() {
            drop(PendingThreadJoin::new(thread));
        }
    }
}

type JoinState = Mutex<Option<std::thread::JoinHandle<OwnerExit>>>;

/// Retains the native join across cancellation of its async waiter. The mutex
/// stays locked until join completes: an empty slot alone must never be mistaken
/// for completed cleanup while a blocking worker still owns the thread.
struct PendingThreadJoin {
    state: Arc<JoinState>,
}

impl PendingThreadJoin {
    fn new(thread: std::thread::JoinHandle<OwnerExit>) -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(thread))),
        }
    }

    async fn complete(self) -> OwnerExit {
        let state = Arc::clone(&self.state);
        match tokio::task::spawn_blocking(move || join_thread(&state)).await {
            Ok(exit) => exit,
            Err(_) => OwnerExit::CleanupFailed,
        }
    }
}

impl Drop for PendingThreadJoin {
    fn drop(&mut self) {
        // Product callers use the multi-thread runtime. Hand off its worker
        // before waiting for the native cleanup; other callers retain the
        // existing synchronous Drop contract.
        let join = || {
            let _ = join_thread(&self.state);
        };
        if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            tokio::task::block_in_place(join);
        } else {
            join();
        }
    }
}

fn join_thread(state: &JoinState) -> OwnerExit {
    let mut pending = state.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(thread) = pending.take() else {
        return OwnerExit::CleanupFailed;
    };
    let exit = match thread.join() {
        Ok(exit) => exit,
        Err(_) => OwnerExit::CleanupFailed,
    };
    // Keep the handoff locked through native cleanup, including panic unwind.
    drop(pending);
    exit
}
