use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DeadlineError, OwnerRegistry, RelayRunError,
    SupervisorError, relay_bidirectional_with_idle_timeout, with_deadline,
};
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
    let (listener, _accept_calls) = ScriptedListener::new([Err(io::ErrorKind::ConnectionAborted)]);
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
async fn monotonic_deadline_expires_deterministically() {
    let task = tokio::spawn(with_deadline(
        Duration::from_secs(5),
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
