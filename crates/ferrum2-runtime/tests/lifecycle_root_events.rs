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
async fn required_root_completion_arbitration_and_panic_reap_every_owner_exactly_once() {
    for (first, second) in [
        (RootRun::Complete, RootRun::Complete),
        (RootRun::Fail, RootRun::Fail),
        (RootRun::Panic, RootRun::AwaitCancellation),
    ] {
        let registry = OwnerRegistry::new();
        let supervisor = ProcessSupervisor::new(
            vec![
                running_root(first),
                running_root(second),
                running_root(RootRun::AwaitCancellation),
            ],
            Duration::from_secs(1),
            registry.clone(),
        )
        .expect("three required roots");

        let report = supervisor.run_until(pending::<()>()).await;

        assert_eq!(report.exit_kind(), ProcessExitKind::Failed);
        assert_eq!(
            report.states(),
            &[
                ProcessState::Validated,
                ProcessState::Preparing,
                ProcessState::Prepared,
                ProcessState::Active,
                ProcessState::Fatal,
                ProcessState::Quiescing,
                ProcessState::Draining,
                ProcessState::Stopped,
            ]
        );
        match first {
            RootRun::Complete => assert!(matches!(
                report.cause(),
                ProcessCause::RootStopped {
                    root,
                    exit: ProcessRootExit::Completed,
                } if root.get() == 0
            )),
            RootRun::Fail => {
                assert!(matches!(
                    report.cause(),
                    ProcessCause::RootStopped {
                        root,
                        exit: ProcessRootExit::Failed("root"),
                    } if root.get() == 0
                ));
                assert!(matches!(
                    report.cleanup_failure(),
                    Some(ProcessCleanupFailure::RootFailed { root, error: "root" })
                        if root.get() == 1
                ));
            }
            RootRun::Panic => assert!(matches!(
                report.cause(),
                ProcessCause::RootStopped {
                    root,
                    exit: ProcessRootExit::Panicked,
                } if root.get() == 0
            )),
            RootRun::AwaitCancellation => unreachable!(),
        }
        assert_eq!(
            report
                .root_events()
                .iter()
                .map(|event| event.root().get())
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(
            report.root_events()[0].phase(),
            ProcessRootEventPhase::Active
        );
        assert!(
            report.root_events()[1..]
                .iter()
                .all(|event| event.phase() == ProcessRootEventPhase::Draining)
        );
        let expected_exits = match first {
            RootRun::Complete => [
                ProcessRootExitCategory::Completed,
                ProcessRootExitCategory::Completed,
                ProcessRootExitCategory::Completed,
            ],
            RootRun::Fail => [
                ProcessRootExitCategory::Failed,
                ProcessRootExitCategory::Failed,
                ProcessRootExitCategory::Completed,
            ],
            RootRun::Panic => [
                ProcessRootExitCategory::Panicked,
                ProcessRootExitCategory::Completed,
                ProcessRootExitCategory::Completed,
            ],
            RootRun::AwaitCancellation => unreachable!(),
        };
        assert_eq!(
            report
                .root_events()
                .iter()
                .map(|event| event.exit())
                .collect::<Vec<_>>(),
            expected_exits
        );
        assert!(
            report
                .root_events()
                .windows(2)
                .all(|pair| pair[0].elapsed() <= pair[1].elapsed())
        );
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.process_supervisors, 0);
        assert_eq!(snapshot.prepared_process_roots, 0);
        assert_eq!(snapshot.active_process_roots, 0);
        assert_eq!(snapshot.process_root_reaps, REQUIRED_ROOT_COUNT);
    }
}
