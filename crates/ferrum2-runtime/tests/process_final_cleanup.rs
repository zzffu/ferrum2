use std::future::pending;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_runtime::{
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessCause, ProcessCleanupFailure,
    ProcessFuture, ProcessResources, ProcessRoot, ProcessSupervisor,
};
use tokio::sync::{Notify, oneshot};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Exit {
    PrepareFailed,
    PrepareCancelled,
    ActivateFailed,
    RunConstructionPanicked,
    RunFailed,
    Shutdown,
    Watchdog,
}

struct Root {
    exit: Exit,
    started: Arc<Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl PreparedProcessRoot<&'static str> for Root {
    fn activate(&mut self) -> Result<(), &'static str> {
        if self.exit == Exit::ActivateFailed {
            Err("activate")
        } else {
            Ok(())
        }
    }
    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        self.events.lock().unwrap().push("run construction");
        assert!(
            self.exit != Exit::RunConstructionPanicked,
            "injected construction panic"
        );
        Box::pin(async move {
            self.started.notify_one();
            if self.exit == Exit::Watchdog {
                return pending().await;
            }
            if self.exit == Exit::Shutdown {
                cancellation.cancelled().await;
            }
            self.events.lock().unwrap().push("run finished");
            if self.exit == Exit::RunFailed {
                Err("run")
            } else {
                Ok(())
            }
        })
    }
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("rollback");
            Err("rollback")
        })
    }
}

#[tokio::test(start_paused = true)]
async fn final_shared_cleanup_runs_after_every_root_exit_before_registry_snapshot() {
    for exit in [
        Exit::PrepareFailed,
        Exit::PrepareCancelled,
        Exit::ActivateFailed,
        Exit::RunConstructionPanicked,
        Exit::RunFailed,
        Exit::Shutdown,
        Exit::Watchdog,
    ] {
        check_final_cleanup(exit, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn final_cleanup_failure_preserves_primary_and_prior_root_or_watchdog_failure() {
    for exit in [Exit::ActivateFailed, Exit::Watchdog] {
        check_final_cleanup(exit, true).await;
    }
}

async fn check_final_cleanup(exit: Exit, fail_final: bool) {
    let registry = OwnerRegistry::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let root_events = Arc::clone(&events);
    let final_events = Arc::clone(&events);
    let preparation_registry = registry.clone();
    let (resource, owned_resource) = oneshot::channel();
    let started = Arc::new(Notify::new());
    let root_started = Arc::clone(&started);
    let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
        // Registration deliberately happens after the process baseline snapshot.
        let _ = resource.send(preparation_registry.track_tun_handler_task());
        if exit == Exit::PrepareFailed {
            return Err("prepare");
        }
        if exit == Exit::PrepareCancelled {
            root_started.notify_one();
            cancellation.cancelled().await;
            root_events.lock().unwrap().push("prepare cleanup");
            return Ok(None);
        }
        Ok(Some(Root {
            exit,
            started: root_started,
            events: root_events,
        }))
    });
    let final_registry = registry.clone();
    let baseline = registry.snapshot();
    let supervisor = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
        .unwrap()
        .with_process_resources(ProcessResources {
            baseline,
            cleanup: Box::pin(async move {
                let resource = owned_resource.await.unwrap();
                let snapshot = final_registry.snapshot();
                assert_eq!(snapshot.active_process_roots, 0);
                assert_eq!(snapshot.prepared_process_roots, 0);
                assert_eq!(snapshot.active_tun_handler_tasks, 1);
                final_events.lock().unwrap().push("final cleanup");
                drop(resource);
                if fail_final { Err("final") } else { Ok(()) }
            }),
        });
    let report = supervisor
        .run_until(async move {
            if matches!(
                exit,
                Exit::PrepareCancelled | Exit::Shutdown | Exit::Watchdog
            ) {
                started.notified().await;
            } else {
                pending::<()>().await;
            }
        })
        .await;
    assert_eq!(events.lock().unwrap().last(), Some(&"final cleanup"));
    assert_eq!(registry.snapshot().active_tun_handler_tasks, 0);
    assert_eq!(registry.snapshot().process_supervisors, 0);
    if fail_final {
        let Some(ProcessCleanupFailure::FinalCleanupFailed {
            error: "final",
            prior: Some(prior),
        }) = report.cleanup_failure()
        else {
            panic!("final cleanup retains previous failure");
        };
        match exit {
            Exit::ActivateFailed => {
                assert!(matches!(
                    report.cause(),
                    ProcessCause::ActivationFailed {
                        error: "activate",
                        ..
                    }
                ));
                assert!(matches!(
                    prior.as_ref(),
                    ProcessCleanupFailure::RootFailed {
                        error: "rollback",
                        ..
                    }
                ));
            }
            Exit::Watchdog => {
                assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
                assert!(matches!(
                    prior.as_ref(),
                    ProcessCleanupFailure::ForceReapTimedOut { .. }
                ));
            }
            Exit::PrepareFailed
            | Exit::PrepareCancelled
            | Exit::RunConstructionPanicked
            | Exit::RunFailed
            | Exit::Shutdown => unreachable!(),
        }
    } else {
        assert!(!matches!(
            report.cleanup_failure(),
            Some(
                ProcessCleanupFailure::OwnerMismatch { .. }
                    | ProcessCleanupFailure::FinalCleanupFailed { .. }
                    | ProcessCleanupFailure::FinalCleanupPanicked { .. }
            )
        ));
    }
}

#[tokio::test]
async fn final_cleanup_panic_is_classified_without_erasing_primary_failure() {
    let root = ProcessRoot::new(|| async { Err::<Root, _>("prepare") });
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let report = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry)
        .unwrap()
        .with_process_resources(ProcessResources {
            baseline,
            cleanup: Box::pin(async {
                panic!("injected final cleanup panic");
            }),
        })
        .run_until(pending::<()>())
        .await;
    assert!(matches!(
        report.cause(),
        ProcessCause::PreparationFailed {
            error: "prepare",
            ..
        }
    ));
    assert!(matches!(
        report.cleanup_failure(),
        Some(ProcessCleanupFailure::FinalCleanupPanicked { prior: None })
    ));
}

#[tokio::test]
async fn supplied_baseline_precedes_materialization_and_still_detects_residue() {
    for release_owned_resource in [false, true] {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let resource = Arc::new(Mutex::new(Some(registry.track_tun_handler_task())));
        let cleanup_resource = Arc::clone(&resource);
        let root = ProcessRoot::new(|| async { Err::<Root, _>("prepare") });
        let report = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
            .unwrap()
            .with_process_resources(ProcessResources {
                baseline,
                cleanup: Box::pin(async move {
                    if release_owned_resource {
                        cleanup_resource.lock().unwrap().take();
                    }
                    Ok(())
                }),
            })
            .run_until(pending::<()>())
            .await;
        assert_eq!(report.cleanup_failure().is_none(), release_owned_resource);
        if !release_owned_resource {
            assert!(matches!(
                report.cleanup_failure(),
                Some(ProcessCleanupFailure::OwnerMismatch { .. })
            ));
        }
        resource.lock().unwrap().take();
        assert_eq!(registry.snapshot().active_tun_handler_tasks, 0);
    }
}
