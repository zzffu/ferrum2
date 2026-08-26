#![allow(dead_code, unused_imports)]

use std::collections::VecDeque;
use std::future::{pending, ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DEFAULT_HANDSHAKE_TIMEOUT, DeadlineError, OwnerRegistry,
    PreparedProcessRoot, ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessFuture,
    ProcessRoot, ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory, ProcessState,
    ProcessSupervisor, RelayFailure, RelayRunError, RelayStats, SupervisorError,
    relay_bidirectional_with_idle_timeout, relay_lifecycle, with_deadline,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

const REQUIRED_ROOT_COUNT: usize = 3;

mod lifecycle_support;
use lifecycle_support::*;

#[tokio::test]
async fn process_startup_failure_positions_roll_back_in_reverse_without_polling_roots() {
    for failure in [
        StartupFailure::Prepare(0),
        StartupFailure::Prepare(1),
        StartupFailure::Prepare(2),
        StartupFailure::Activate(0),
        StartupFailure::Activate(1),
        StartupFailure::Activate(2),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let polls = Arc::new(AtomicUsize::new(0));
        let registry = OwnerRegistry::new();
        let supervisor = ProcessSupervisor::new(
            fake_process_roots(failure, Arc::clone(&events), Arc::clone(&polls)),
            Duration::from_secs(5),
            registry.clone(),
        )
        .expect("three required roots");

        let report = supervisor.run_until(pending::<()>()).await;

        assert_eq!(report.exit_kind(), ProcessExitKind::Failed);
        assert!(report.cleanup_failure().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        match failure {
            StartupFailure::Prepare(failed) => {
                assert!(matches!(
                    report.cause(),
                    ProcessCause::PreparationFailed { root, error: "preparation" }
                        if root.get() == failed
                ));
                let mut expected = (0..=failed)
                    .map(|index| format!("prepare:{index}"))
                    .collect::<Vec<_>>();
                expected.extend((0..failed).rev().map(|index| format!("rollback:{index}")));
                assert_eq!(*events.lock().expect("event lock"), expected);
                assert_eq!(
                    report.states(),
                    &[
                        ProcessState::Validated,
                        ProcessState::Preparing,
                        ProcessState::Rollback,
                        ProcessState::Stopped,
                    ]
                );
                assert_eq!(registry.snapshot().process_root_rollbacks, failed);
            }
            StartupFailure::Activate(failed) => {
                assert!(matches!(
                    report.cause(),
                    ProcessCause::ActivationFailed { root, error: "activation" }
                        if root.get() == failed
                ));
                let mut expected = (0..REQUIRED_ROOT_COUNT)
                    .map(|index| format!("prepare:{index}"))
                    .collect::<Vec<_>>();
                expected.extend((0..=failed).map(|index| format!("activate:{index}")));
                expected.extend(
                    (0..REQUIRED_ROOT_COUNT)
                        .rev()
                        .map(|index| format!("rollback:{index}")),
                );
                assert_eq!(*events.lock().expect("event lock"), expected);
                assert_eq!(
                    report.states(),
                    &[
                        ProcessState::Validated,
                        ProcessState::Preparing,
                        ProcessState::Prepared,
                        ProcessState::Rollback,
                        ProcessState::Stopped,
                    ]
                );
                assert_eq!(
                    registry.snapshot().process_root_rollbacks,
                    REQUIRED_ROOT_COUNT
                );
            }
        }
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.process_supervisors, 0);
        assert_eq!(snapshot.prepared_process_roots, 0);
        assert_eq!(snapshot.active_process_roots, 0);
        assert_eq!(snapshot.process_root_reaps, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn external_shutdown_during_preparation_cancels_the_same_transaction_and_rolls_back() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let polls = Arc::new(AtomicUsize::new(0));
    let preparing_second = Arc::new(Notify::new());
    let first_events = Arc::clone(&events);
    let first_polls = Arc::clone(&polls);
    let second_events = Arc::clone(&events);
    let second_preparing = Arc::clone(&preparing_second);
    let registry = OwnerRegistry::new();
    let supervisor = ProcessSupervisor::new(
        vec![
            ProcessRoot::new(move || async move {
                first_events
                    .lock()
                    .expect("event lock")
                    .push("prepare:0".to_owned());
                Ok(FakeProcessRoot {
                    index: 0,
                    activation_failure: None,
                    events: first_events,
                    polls: first_polls,
                })
            }),
            ProcessRoot::new(move || async move {
                second_events
                    .lock()
                    .expect("event lock")
                    .push("prepare:1".to_owned());
                second_preparing.notify_one();
                pending::<Result<FakeProcessRoot, &'static str>>().await
            }),
        ],
        Duration::from_secs(5),
        registry.clone(),
    )
    .expect("two required roots");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(tokio::time::timeout(
        Duration::from_secs(1),
        supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }),
    ));

    preparing_second.notified().await;
    shutdown_tx.send(()).expect("request startup shutdown");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let report = run
        .await
        .expect("process owner")
        .expect("startup shutdown must not wait for preparation");

    assert_eq!(report.exit_kind(), ProcessExitKind::Graceful);
    assert!(matches!(report.cause(), ProcessCause::ExternalShutdown));
    assert_eq!(
        report.states(),
        &[
            ProcessState::Validated,
            ProcessState::Preparing,
            ProcessState::Rollback,
            ProcessState::Stopped,
        ]
    );
    assert_eq!(
        *events.lock().expect("event lock"),
        ["prepare:0", "prepare:1", "rollback:0"]
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.process_root_rollbacks, 1);
    assert_eq!(snapshot.prepared_process_roots, 0);
    assert_eq!(snapshot.active_process_roots, 0);
}

#[tokio::test]
async fn cancellation_aware_preparation_is_reaped_and_reports_cleanup_failure() {
    for (cleanup_error, expected_failure) in [(None, None), (Some("cleanup"), Some("cleanup"))] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let polls = Arc::new(AtomicUsize::new(0));
        let preparing_second = Arc::new(Notify::new());
        let first_events = Arc::clone(&events);
        let first_polls = Arc::clone(&polls);
        let second_events = Arc::clone(&events);
        let second_preparing = Arc::clone(&preparing_second);
        let registry = OwnerRegistry::new();
        let supervisor = ProcessSupervisor::new(
            vec![
                ProcessRoot::new(move || async move {
                    first_events
                        .lock()
                        .expect("event lock")
                        .push("prepare:0".to_owned());
                    Ok(FakeProcessRoot {
                        index: 0,
                        activation_failure: None,
                        events: first_events,
                        polls: first_polls,
                    })
                }),
                ProcessRoot::new_cancellable(move |mut cancellation| async move {
                    second_events
                        .lock()
                        .expect("event lock")
                        .push("prepare:1".to_owned());
                    second_preparing.notify_one();
                    cancellation.cancelled().await;
                    second_events
                        .lock()
                        .expect("event lock")
                        .push("reap:1".to_owned());
                    match cleanup_error {
                        Some(error) => Err(error),
                        None => Ok(None::<FakeProcessRoot>),
                    }
                }),
            ],
            Duration::from_secs(5),
            registry.clone(),
        )
        .expect("two required roots");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        preparing_second.notified().await;
        shutdown_tx.send(()).expect("request startup shutdown");
        let report = run.await.expect("process owner");

        assert!(matches!(report.cause(), ProcessCause::ExternalShutdown));
        match expected_failure {
            Some(error) => assert!(matches!(
                report.cleanup_failure(),
                Some(ProcessCleanupFailure::RootFailed { root, error: actual })
                    if root.get() == 1 && *actual == error
            )),
            None => assert!(report.cleanup_failure().is_none()),
        }
        assert_eq!(
            *events.lock().expect("event lock"),
            ["prepare:0", "prepare:1", "reap:1", "rollback:0"]
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.process_root_rollbacks, 1);
        assert_eq!(snapshot.prepared_process_roots, 0);
        assert_eq!(snapshot.active_process_roots, 0);
    }
}

#[tokio::test]
async fn synchronous_run_panic_cleans_handed_off_and_remaining_roots_in_reverse_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let roots = (0..REQUIRED_ROOT_COUNT)
        .map(|index| {
            let events = Arc::clone(&events);
            ProcessRoot::new(move || async move {
                Ok(HandoffRoot {
                    index,
                    panic_on_run: index == 1,
                    events,
                })
            })
        })
        .collect();
    let registry = OwnerRegistry::new();
    let supervisor =
        ProcessSupervisor::new(roots, Duration::ZERO, registry.clone()).expect("three roots");

    let report = supervisor.run_until(pending::<()>()).await;

    assert_eq!(report.exit_kind(), ProcessExitKind::Failed);
    assert!(matches!(
        report.cause(),
        ProcessCause::ActivationPanicked { root } if root.get() == 1
    ));
    assert!(report.cleanup_failure().is_none());
    assert_eq!(
        report.states(),
        &[
            ProcessState::Validated,
            ProcessState::Preparing,
            ProcessState::Prepared,
            ProcessState::Rollback,
            ProcessState::Stopped,
        ]
    );
    assert_eq!(
        *events.lock().expect("event lock"),
        [
            "handoff:0",
            "handoff:1",
            "terminal:1",
            "rollback:2",
            "terminal:2",
            "terminal:0",
        ]
    );
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.process_root_rollbacks, REQUIRED_ROOT_COUNT - 1);
    assert_eq!(snapshot.process_root_reaps, 0);
    assert_eq!(snapshot.prepared_process_roots, 0);
    assert_eq!(snapshot.active_process_roots, 0);
}
