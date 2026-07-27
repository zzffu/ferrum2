use std::collections::VecDeque;
use std::future::{pending, ready};
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DEFAULT_HANDSHAKE_TIMEOUT, DeadlineError, OwnerRegistry,
    RelayRunError, SupervisorError, relay_bidirectional_with_idle_timeout, relay_lifecycle,
    with_deadline,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

struct ScriptedListener {
    accepts: Arc<AtomicUsize>,
    responses: Mutex<VecDeque<Result<usize, io::ErrorKind>>>,
    available: Notify,
}

impl ScriptedListener {
    fn new(
        responses: impl IntoIterator<Item = Result<usize, io::ErrorKind>>,
    ) -> (Self, Arc<AtomicUsize>) {
        let accepts = Arc::new(AtomicUsize::new(0));
        (
            Self {
                accepts: Arc::clone(&accepts),
                responses: Mutex::new(responses.into_iter().collect()),
                available: Notify::new(),
            },
            accepts,
        )
    }
}

impl AcceptListener for ScriptedListener {
    type Stream = usize;

    async fn accept(&self) -> io::Result<Self::Stream> {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        loop {
            if let Some(result) = self.responses.lock().expect("response lock").pop_front() {
                return result.map_err(|kind| io::Error::new(kind, "scripted accept failure"));
            }
            self.available.notified().await;
        }
    }
}

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

#[tokio::test(start_paused = true)]
async fn handshake_timeout_uses_the_five_second_monotonic_deadline() {
    assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(5));
    let task = tokio::spawn(with_deadline(
        DEFAULT_HANDSHAKE_TIMEOUT,
        pending::<Result<(), io::Error>>(),
    ));
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert!(matches!(
        task.await.expect("deadline task"),
        Err(DeadlineError::Timeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn idle_relay_times_out_without_forwarded_bytes() {
    let (_application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, _target) = tokio::io::duplex(64);
    let relay = tokio::spawn(async move {
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert!(matches!(
        relay.await.expect("relay task"),
        Err(RelayRunError::IdleTimeout)
    ));
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

#[tokio::test(start_paused = true)]
async fn relay_lifecycle_resets_idle_and_returns_buffers_after_cooperative_cancel() {
    let (mut application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, mut target) = tokio::io::duplex(64);
    let registry = OwnerRegistry::new();
    let registry_for_relay = registry.clone();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        relay_lifecycle(
            &mut inbound,
            &mut outbound,
            Duration::from_secs(5),
            &registry_for_relay,
            async move {
                let _ = cancel_rx.await;
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    assert_eq!(registry.snapshot().owned_buffers, 2);

    tokio::time::advance(Duration::from_secs(4)).await;
    application.write_all(b"x").await.expect("write one byte");
    let mut forwarded = [0_u8; 1];
    target
        .read_exact(&mut forwarded)
        .await
        .expect("byte is forwarded");
    assert_eq!(forwarded, *b"x");

    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(
        !relay.is_finished(),
        "forwarded byte reset the idle deadline"
    );

    cancel_tx
        .send(())
        .expect("request cooperative cancellation");
    assert!(matches!(
        relay.await.expect("relay owner"),
        Err(RelayRunError::Cancelled)
    ));
    assert_eq!(registry.snapshot().owned_buffers, 0);
}
