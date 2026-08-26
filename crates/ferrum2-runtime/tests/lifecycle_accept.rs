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
async fn permit_is_owned_before_accept_and_caps_connection_tasks() {
    let (listener, accept_calls) = ScriptedListener::new([Ok(1), Ok(2)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        |_stream, mut cancellation| async move { cancellation.cancelled().await },
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    for _ in 0..100 {
        if registry.snapshot().connection_tasks == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(accept_calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().owned_permits, 1);
    assert_eq!(registry.snapshot().connection_tasks, 1);

    shutdown_tx.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task")
        .expect("operator shutdown succeeds");
    assert_eq!(registry.snapshot().owned_permits, 0);
    assert_eq!(registry.snapshot().connection_tasks, 0);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().listeners, 0);
}

#[tokio::test]
async fn listener_failure_is_process_fatal_and_reaps_children() {
    let (listener, _accept_calls) = ScriptedListener::new([Err(io::ErrorKind::PermissionDenied)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");

    let result = supervisor
        .run_until(|_stream, _cancellation| async {}, pending::<()>())
        .await;

    assert_eq!(result, Err(SupervisorError::ListenerFailure));
    assert_eq!(registry.snapshot().owned_permits, 0);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().listeners, 0);
}

#[tokio::test]
async fn ready_shutdown_prevents_every_simultaneously_ready_accept() {
    let post_shutdown_accepts = Arc::new(AtomicUsize::new(0));

    for iteration in 0..512 {
        let listener = ScriptedListener {
            accepts: Arc::clone(&post_shutdown_accepts),
            responses: Mutex::new([Ok(iteration)].into_iter().collect()),
            available: Notify::new(),
        };
        let supervisor = BoundedSupervisor::new(listener, 1, Duration::ZERO, OwnerRegistry::new())
            .expect("valid cap");

        supervisor
            .run_until(|_stream, _cancellation| async {}, ready(()))
            .await
            .expect("ready shutdown is controlled");
    }

    assert_eq!(post_shutdown_accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn transient_accept_failure_yields_then_accepts_the_next_stream() {
    let (listener, accept_calls) = ScriptedListener::new([Err(io::ErrorKind::Interrupted), Ok(7)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");
    let completed = Arc::new(Notify::new());
    let completed_by_handler = Arc::clone(&completed);
    let handled = Arc::new(AtomicUsize::new(0));
    let handled_by_handler = Arc::clone(&handled);

    supervisor
        .run_until(
            move |stream, _cancellation| {
                let completed = Arc::clone(&completed_by_handler);
                let handled = Arc::clone(&handled_by_handler);
                async move {
                    assert_eq!(stream, 7);
                    handled.fetch_add(1, Ordering::SeqCst);
                    completed.notify_one();
                }
            },
            completed.notified(),
        )
        .await
        .expect("transient accept error is retried");

    assert_eq!(accept_calls.load(Ordering::SeqCst), 2);
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().owned_permits, 0);
}

#[tokio::test]
async fn non_transient_accept_failure_cancels_and_reaps_a_live_child() {
    let (listener, accept_calls) =
        ScriptedListener::new([Ok(1), Err(io::ErrorKind::PermissionDenied)]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new(listener, 2, Duration::from_secs(1), registry.clone())
        .expect("valid cap");
    let cancellation_observed = Arc::new(AtomicUsize::new(0));
    let observed_by_handler = Arc::clone(&cancellation_observed);

    let result = supervisor
        .run_until(
            move |_stream, mut cancellation| {
                let observed = Arc::clone(&observed_by_handler);
                async move {
                    cancellation.cancelled().await;
                    observed.fetch_add(1, Ordering::SeqCst);
                }
            },
            pending::<()>(),
        )
        .await;

    assert_eq!(result, Err(SupervisorError::ListenerFailure));
    assert_eq!(accept_calls.load(Ordering::SeqCst), 2);
    assert_eq!(cancellation_observed.load(Ordering::SeqCst), 1);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.active_supervisor_children, 0);
    assert_eq!(snapshot.connection_tasks, 0);
    assert_eq!(snapshot.owned_buffers, 0);
    assert_eq!(snapshot.owned_permits, 0);
    assert_eq!(snapshot.listeners, 0);
    assert_eq!(snapshot.forced_shutdowns, 0);
}
