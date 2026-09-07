use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

use super::{LifecycleLink, OwnerControl, OwnerExit};
use crate::OwnerWake;

/// One finite native operation, shared by production and hosted lifecycle tests.
pub(crate) type NativeJob = Box<dyn FnOnce(LifecycleLink, OwnerControl) -> OwnerExit + Send>;

pub(crate) struct NativeLifecycleOwner {
    pub(crate) link: LifecycleLink,
    pub(crate) control: OwnerControl,
    pub(crate) work: OwnerWake,
    pub(crate) thread: Option<std::thread::JoinHandle<OwnerExit>>,
}

impl NativeLifecycleOwner {
    pub(crate) fn spawn(
        control: OwnerControl,
        job: NativeJob,
    ) -> std::io::Result<(Self, tokio::sync::oneshot::Receiver<OwnerExit>)> {
        let link = LifecycleLink::default();
        let native_link = link.clone();
        let native_control = control.clone();
        let (done, completed) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("ferrum2-tun-owner".into())
            .spawn(move || {
                let exit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    job(native_link.clone(), native_control)
                }))
                .unwrap_or(OwnerExit::CleanupFailed);
                native_link.close();
                let _ = done.send(exit);
                exit
            })?;
        Ok((
            Self {
                link,
                control,
                work: OwnerWake::default(),
                thread: Some(thread),
            },
            completed,
        ))
    }

    pub(crate) fn signal(&self) {
        self.control.admitting.store(false, Ordering::Release);
        self.link.close();
        self.control.stop.store(true, Ordering::Release);
        self.work.signal();
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }

    pub(crate) async fn reap(mut self) -> OwnerExit {
        self.signal();
        let Some(thread) = self.thread.take() else {
            return OwnerExit::CleanupFailed;
        };
        PendingThreadJoin::new(thread).complete().await
    }
}

impl Drop for NativeLifecycleOwner {
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
