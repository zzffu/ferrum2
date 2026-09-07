use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessCause, ProcessCleanupFailure,
    ProcessFuture, ProcessRoot, ProcessSupervisor,
};
use tokio::sync::{Notify, oneshot};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Watchdog,
    Construction,
    Poll,
    LaterConstruction,
}

struct OwnedCleanupRoot {
    cleanup: Option<ProcessFuture<Result<(), &'static str>>>,
    run_dropped: Arc<AtomicBool>,
    failure: Failure,
    run_started: Arc<Notify>,
}

struct RunDrop(Arc<AtomicBool>);
impl Drop for RunDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl PreparedProcessRoot<&'static str> for OwnedCleanupRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn take_run_cleanup(&mut self) -> Option<ProcessFuture<Result<(), &'static str>>> {
        self.cleanup.take()
    }

    fn run(self: Box<Self>, _: ProcessCancellation) -> ProcessFuture<Result<(), &'static str>> {
        let guard = RunDrop(Arc::clone(&self.run_dropped));
        assert!(
            self.failure != Failure::Construction,
            "injected run construction panic"
        );
        Box::pin(async move {
            let _guard = guard;
            self.run_started.notify_one();
            assert!(self.failure != Failure::Poll, "injected run poll panic");
            pending().await
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        self.cleanup.take().expect("prepared root retains cleanup")
    }
}

#[tokio::test(start_paused = true)]
async fn watchdog_preserves_child_join_and_cleanup_error_after_root_abort() {
    check_owned_cleanup(Failure::Watchdog).await;
}

#[tokio::test(start_paused = true)]
async fn run_construction_panic_still_joins_transferred_child_before_releasing_root() {
    check_owned_cleanup(Failure::Construction).await;
}

#[tokio::test(start_paused = true)]
async fn run_poll_panic_preserves_primary_cause_and_child_cleanup_failure() {
    check_owned_cleanup(Failure::Poll).await;
}

#[tokio::test(start_paused = true)]
async fn later_run_construction_panic_reaps_unstarted_root_children() {
    check_owned_cleanup(Failure::LaterConstruction).await;
}

async fn check_owned_cleanup(failure: Failure) {
    let registry = OwnerRegistry::new();
    let run_dropped = Arc::new(AtomicBool::new(false));
    let child_finished = Arc::new(AtomicBool::new(false));
    let child_flag = Arc::clone(&child_finished);
    let (release, released) = oneshot::channel();
    let child = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(30), released)
            .await
            .unwrap()
            .unwrap();
        child_flag.store(true, Ordering::Release);
    });
    let (cleanup_started, started) = oneshot::channel();
    let cleanup: ProcessFuture<Result<(), &'static str>> = Box::pin(async move {
        let _ = cleanup_started.send(());
        child.await.unwrap();
        Err("cleanup")
    });
    let run_started = Arc::new(Notify::new());
    let root = OwnedCleanupRoot {
        cleanup: Some(cleanup),
        run_dropped: Arc::clone(&run_dropped),
        failure,
        run_started: Arc::clone(&run_started),
    };
    let mut roots = vec![ProcessRoot::new(|| async move { Ok(root) })];
    if failure == Failure::LaterConstruction {
        roots.push(ProcessRoot::new(|| async {
            Ok(OwnedCleanupRoot {
                cleanup: None,
                run_dropped: Arc::new(AtomicBool::new(false)),
                failure: Failure::Construction,
                run_started: Arc::new(Notify::new()),
            })
        }));
    }
    let supervisor =
        ProcessSupervisor::new(roots, Duration::from_secs(1), registry.clone()).unwrap();
    let run = tokio::spawn(supervisor.run_until(async move {
        if failure == Failure::Watchdog {
            run_started.notified().await;
        } else {
            pending::<()>().await;
        }
    }));
    started.await.unwrap();
    assert!(run_dropped.load(Ordering::Acquire));
    assert!(!child_finished.load(Ordering::Acquire));
    assert!(!run.is_finished());
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot.active_process_roots + snapshot.prepared_process_roots,
        1
    );
    assert_eq!(snapshot.process_root_reaps, 0);
    release.send(()).unwrap();
    let report = run.await.unwrap();
    assert!(child_finished.load(Ordering::Acquire));
    if failure != Failure::Watchdog {
        match failure {
            Failure::Construction | Failure::LaterConstruction => assert!(matches!(
                report.cause(),
                ProcessCause::ActivationPanicked { .. }
            )),
            Failure::Poll => assert!(matches!(
                report.cause(),
                ProcessCause::RootStopped {
                    exit: ferrum2_runtime::ProcessRootExit::Panicked,
                    ..
                }
            )),
            Failure::Watchdog => unreachable!(),
        }
        assert!(matches!(
            report.cleanup_failure(),
            Some(ProcessCleanupFailure::RootFailed {
                error: "cleanup",
                ..
            })
        ));
    } else {
        assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
        let Some(ProcessCleanupFailure::ForceReapTimedOut {
            prior: Some(prior), ..
        }) = report.cleanup_failure()
        else {
            panic!("watchdog retains cleanup failure");
        };
        assert!(matches!(
            prior.as_ref(),
            ProcessCleanupFailure::RootFailed {
                error: "cleanup",
                ..
            }
        ));
    }
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.active_process_roots, 0);
    assert_eq!(snapshot.prepared_process_roots, 0);
    assert_eq!(snapshot.process_supervisors, 0);
}

struct DependentRoot {
    cleanup: Option<ProcessFuture<Result<(), &'static str>>>,
    release_on_cancellation: Option<oneshot::Sender<()>>,
}

impl PreparedProcessRoot<&'static str> for DependentRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn take_run_cleanup(&mut self) -> Option<ProcessFuture<Result<(), &'static str>>> {
        self.cleanup.take()
    }
    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            if let Some(release) = self.release_on_cancellation {
                cancellation.cancelled().await;
                let _ = release.send(());
                Ok(())
            } else {
                Err("primary")
            }
        })
    }
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test(start_paused = true)]
async fn first_root_exit_cancels_peer_before_waiting_for_dependent_cleanup() {
    let (release, released) = oneshot::channel();
    let failed = DependentRoot {
        cleanup: Some(Box::pin(async move {
            tokio::time::timeout(Duration::from_millis(100), released)
                .await
                .map_err(|_| "peer cancellation was delayed by cleanup")?
                .map_err(|_| "peer disappeared")?;
            Ok(())
        })),
        release_on_cancellation: None,
    };
    let peer = DependentRoot {
        cleanup: None,
        release_on_cancellation: Some(release),
    };
    let registry = OwnerRegistry::new();
    let report = ProcessSupervisor::new(
        vec![
            ProcessRoot::new(|| async move { Ok(failed) }),
            ProcessRoot::new(|| async move { Ok(peer) }),
        ],
        Duration::from_secs(1),
        registry.clone(),
    )
    .unwrap()
    .run_until(pending::<()>())
    .await;
    assert!(matches!(
        report.cause(),
        ProcessCause::RootStopped {
            exit: ferrum2_runtime::ProcessRootExit::Failed("primary"),
            ..
        }
    ));
    assert!(
        report.cleanup_failure().is_none(),
        "dependent cleanup runs after peer cancellation"
    );
    assert_eq!(registry.snapshot().active_process_roots, 0);
    assert_eq!(registry.snapshot().process_root_reaps, 2);
}

#[tokio::test(start_paused = true)]
async fn watchdog_polls_peer_cleanups_while_waiting_for_dependent_join() {
    let (release, released) = oneshot::channel();
    let started = Arc::new(Notify::new());
    let first = OwnedCleanupRoot {
        cleanup: Some(Box::pin(async move {
            tokio::time::timeout(Duration::from_millis(100), released)
                .await
                .map_err(|_| "peer cleanup was not polled")?
                .map_err(|_| "peer cleanup disappeared")?;
            Ok(())
        })),
        run_dropped: Arc::new(AtomicBool::new(false)),
        failure: Failure::Watchdog,
        run_started: Arc::clone(&started),
    };
    let second = OwnedCleanupRoot {
        cleanup: Some(Box::pin(async move {
            let _ = release.send(());
            Ok(())
        })),
        run_dropped: Arc::new(AtomicBool::new(false)),
        failure: Failure::Watchdog,
        run_started: Arc::new(Notify::new()),
    };
    let registry = OwnerRegistry::new();
    let report = ProcessSupervisor::new(
        vec![
            ProcessRoot::new(|| async move { Ok(first) }),
            ProcessRoot::new(|| async move { Ok(second) }),
        ],
        Duration::from_secs(1),
        registry.clone(),
    )
    .unwrap()
    .run_until(async move {
        started.notified().await;
    })
    .await;
    assert!(matches!(
        report.cleanup_failure(),
        Some(ProcessCleanupFailure::ForceReapTimedOut { prior: None, .. })
    ));
    assert_eq!(registry.snapshot().process_root_reaps, 2);
    assert_eq!(registry.snapshot().active_process_roots, 0);
}
