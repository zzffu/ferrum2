use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::task::{JoinError, JoinSet};

use super::{LifecycleLink, NativeLifecycleOwner, OwnerControl, OwnerExit, reconcile_owner_exit};
use crate::OwnerWake;

/// The process supervisor retains the unique cleanup future; the run task only
/// borrows this owner. Aborting that task cannot drop handler or native custody.
pub(crate) struct RunOwner {
    pub(crate) control: OwnerControl,
    pub(crate) work: OwnerWake,
    pub(crate) link: LifecycleLink,
    native_thread: std::thread::Thread,
    cleanup_taken: AtomicBool,
    state: Mutex<State>,
}

struct State {
    native: Option<NativeLifecycleOwner>,
    handlers: JoinSet<()>,
    reported: OwnerExit,
}

impl RunOwner {
    pub(crate) fn new(native: NativeLifecycleOwner) -> Arc<Self> {
        Arc::new(Self {
            control: native.control.clone(),
            work: native.work.clone(),
            link: native.link.clone(),
            native_thread: native
                .thread
                .as_ref()
                .expect("prepared native thread")
                .thread()
                .clone(),
            cleanup_taken: AtomicBool::new(false),
            state: Mutex::new(State {
                native: Some(native),
                handlers: JoinSet::new(),
                reported: OwnerExit::Stopped,
            }),
        })
    }

    pub(crate) fn take_cleanup(self: &Arc<Self>) -> Arc<Self> {
        assert!(
            !self.cleanup_taken.swap(true, Ordering::AcqRel),
            "one run cleanup owner"
        );
        Arc::clone(self)
    }

    pub(crate) fn signal(&self) {
        self.control.admitting.store(false, Ordering::Release);
        self.link.close();
        self.control.stop.store(true, Ordering::Release);
        self.work.signal();
        self.native_thread.unpark();
    }

    pub(crate) fn spawn(&self, handler: impl Future<Output = ()> + Send + 'static) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .spawn(handler);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .is_empty()
    }

    pub(crate) fn try_join_next(&self) -> Option<Result<(), JoinError>> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .try_join_next()
    }

    pub(crate) async fn join_next(&self) -> Option<Result<(), JoinError>> {
        std::future::poll_fn(|context| {
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handlers
                .poll_join_next(context)
        })
        .await
    }

    pub(crate) fn report(&self, exit: OwnerExit) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.reported = reconcile_owner_exit(state.reported, exit);
    }

    pub(crate) async fn reap(&self) -> OwnerExit {
        self.signal();
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .abort_all();
        while let Some(result) = self.join_next().await {
            if result.is_err_and(|error| error.is_panic()) {
                self.report(OwnerExit::RuntimeFailed);
            }
        }
        let native = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .native
            .take();
        let reaped = match native {
            Some(native) => native.reap().await,
            None => OwnerExit::CleanupFailed,
        };
        self.report(reaped);
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reported
    }
}

impl Drop for RunOwner {
    fn drop(&mut self) {
        // Prepared rollback has no handlers. Once handed off, the supervisor's
        // cleanup future keeps this owner alive through the actual joins. Full
        // supervisor-future Drop retains only the existing synchronous fallback.
        self.signal();
        self.state
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TunRoot;
    use ferrum2_runtime::{OwnerRegistry, PreparedProcessRoot, ProcessRoot, ProcessSupervisor};
    use std::time::{Duration, Instant};

    struct HandlerDrop {
        started: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Drop for HandlerDrop {
        fn drop(&mut self) {
            let _ = self.started.take().unwrap().send(());
            self.release
                .recv_timeout(Duration::from_secs(3))
                .expect("bounded handler cleanup release");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_run_retains_real_handler_and_native_joins_in_parent_cleanup() {
        let registry = OwnerRegistry::new();
        let outer_registry = registry.clone();
        let root = ProcessRoot::new_cancellable(move |cancellation| async move {
            let control = OwnerControl::new();
            let (native, done) = NativeLifecycleOwner::spawn(
                control.clone(),
                Box::new(|_, control| {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    while !control.stop.load(Ordering::Acquire) && Instant::now() < deadline {
                        std::thread::park_timeout(Duration::from_millis(100));
                    }
                    assert!(control.stop.load(Ordering::Acquire));
                    OwnerExit::CleanupFailed
                }),
            )
            .unwrap();
            let owner = RunOwner::new(native);
            let (started, handler_started) = tokio::sync::oneshot::channel();
            let (dropping, handler_dropping) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let tracked = registry.track_tun_handler_task();
            owner.spawn(async move {
                let _tracked = tracked;
                let _drop = HandlerDrop {
                    started: Some(dropping),
                    release: released,
                };
                let _ = started.send(());
                std::future::pending::<()>().await;
            });
            handler_started.await.unwrap();
            let (_tcp, flows) = tokio::sync::mpsc::channel(1);
            let (_udp, datagrams) = tokio::sync::mpsc::channel(1);
            let mut tun = Box::new(TunRoot {
                owner,
                done,
                runtime: Some("runtime"),
                cleanup: Some("cleanup"),
                flows,
                datagrams,
                flow_count: Arc::clone(&control.flow_count),
                association_count: Arc::clone(&control.association_count),
                registry: registry.clone(),
                handle_tcp: Arc::new(|_, _, _| Box::pin(async {})),
                handle_udp: Arc::new(|_, _, _| Box::pin(async {})),
                handle_network_lifecycle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
            });
            let cleanup = tun.take_run_cleanup().unwrap();
            let task = tokio::spawn(tun.run(cancellation));
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);
            let cleanup = tokio::spawn(cleanup);
            handler_dropping.await.unwrap();
            assert!(!cleanup.is_finished());
            assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);
            release.send(()).unwrap();
            assert_eq!(cleanup.await.unwrap(), Err("cleanup"));
            assert_eq!(registry.snapshot().active_tun_handler_tasks, 0);
            Err::<Option<TunRoot<&'static str>>, _>("test complete")
        });
        ProcessSupervisor::new(vec![root], Duration::from_secs(1), outer_registry)
            .unwrap()
            .run_until(std::future::pending::<()>())
            .await;
    }
}
