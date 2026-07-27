use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

use ferrum2_runtime::{AcceptListener, BoundedSupervisor, DEFAULT_SHUTDOWN_GRACE, OwnerRegistry};
use tokio::sync::Notify;

struct QueueListener {
    streams: Mutex<VecDeque<usize>>,
    available: Notify,
}

impl QueueListener {
    fn one() -> Self {
        Self {
            streams: Mutex::new([1].into_iter().collect()),
            available: Notify::new(),
        }
    }
}

impl AcceptListener for QueueListener {
    type Stream = usize;

    async fn accept(&self) -> io::Result<Self::Stream> {
        loop {
            if let Some(stream) = self.streams.lock().expect("stream lock").pop_front() {
                return Ok(stream);
            }
            self.available.notified().await;
        }
    }
}

async fn wait_for_connection(registry: &OwnerRegistry) {
    for _ in 0..100 {
        if registry.snapshot().connection_tasks == 1 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("connection owner did not start");
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_drains_before_deadline() {
    assert_eq!(DEFAULT_SHUTDOWN_GRACE, Duration::from_secs(30));
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new(
        QueueListener::one(),
        1,
        Duration::from_secs(5),
        registry.clone(),
    )
    .expect("valid supervisor");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(supervisor.run_until(
        |_stream, _cancellation| async {
            tokio::time::sleep(Duration::from_secs(2)).await;
        },
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_connection(&registry).await;

    shutdown_tx.send(()).expect("request shutdown");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;

    run.await
        .expect("supervisor task")
        .expect("graceful shutdown");
    assert_eq!(registry.snapshot().forced_shutdowns, 0);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
}

#[tokio::test(start_paused = true)]
async fn shutdown_deadline_forces_and_reaps_remaining_owner() {
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new(
        QueueListener::one(),
        1,
        Duration::from_secs(5),
        registry.clone(),
    )
    .expect("valid supervisor");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(supervisor.run_until(
        |_stream, _cancellation| pending::<()>(),
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    wait_for_connection(&registry).await;

    shutdown_tx.send(()).expect("request shutdown");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;

    run.await
        .expect("supervisor task")
        .expect("forced shutdown is controlled");
    assert_eq!(registry.snapshot().forced_shutdowns, 1);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().connection_tasks, 0);
    assert_eq!(registry.snapshot().owned_permits, 0);
}

#[tokio::test]
async fn shutdown_releases_listener_for_rebind() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry).expect("valid supervisor");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(
        supervisor.run_until(|_stream, _cancellation| async {}, async move {
            let _ = shutdown_rx.await;
        }),
    );
    tokio::task::yield_now().await;

    shutdown_tx.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task")
        .expect("operator shutdown");

    let rebound = tokio::net::TcpListener::bind(address)
        .await
        .expect("listener address is reusable");
    drop(rebound);
}
