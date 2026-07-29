use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DEFAULT_SHUTDOWN_GRACE, OwnerRegistry, PreparedProcessRoot,
    ProcessCancellation, ProcessCancellationPhase, ProcessCause, ProcessCleanupFailure,
    ProcessExitKind, ProcessFuture, ProcessRoot, ProcessState, ProcessSupervisor,
};
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

#[derive(Clone, Copy)]
enum ProcessShutdownBehavior {
    Drain(Duration),
    AwaitForce,
    CleanupFailure,
    Uncooperative,
}

struct ShutdownProcessRoot {
    behavior: ProcessShutdownBehavior,
    phases: std::sync::Arc<Mutex<Vec<ProcessCancellationPhase>>>,
    terminal_markers: std::sync::Arc<AtomicUsize>,
}

impl Drop for ShutdownProcessRoot {
    fn drop(&mut self) {
        self.terminal_markers.fetch_add(1, Ordering::SeqCst);
    }
}

impl PreparedProcessRoot<&'static str> for ShutdownProcessRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            cancellation.cancelled().await;
            self.phases
                .lock()
                .expect("phase lock")
                .push(cancellation.phase());
            match self.behavior {
                ProcessShutdownBehavior::Drain(duration) => {
                    tokio::time::sleep(duration).await;
                    Ok(())
                }
                ProcessShutdownBehavior::AwaitForce => {
                    cancellation.forced().await;
                    self.phases
                        .lock()
                        .expect("phase lock")
                        .push(cancellation.phase());
                    Ok(())
                }
                ProcessShutdownBehavior::CleanupFailure => Err("cleanup"),
                ProcessShutdownBehavior::Uncooperative => pending().await,
            }
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async { Ok(()) })
    }
}

fn shutdown_process_root(
    behavior: ProcessShutdownBehavior,
    phases: &std::sync::Arc<Mutex<Vec<ProcessCancellationPhase>>>,
    terminal_markers: &std::sync::Arc<AtomicUsize>,
) -> ProcessRoot<&'static str> {
    let phases = std::sync::Arc::clone(phases);
    let terminal_markers = std::sync::Arc::clone(terminal_markers);
    ProcessRoot::new(move || async move {
        Ok(ShutdownProcessRoot {
            behavior,
            phases,
            terminal_markers,
        })
    })
}

async fn start_process_shutdown_case(
    behavior: ProcessShutdownBehavior,
    grace: Duration,
) -> (
    tokio::task::JoinHandle<ferrum2_runtime::ProcessReport<&'static str>>,
    tokio::sync::oneshot::Sender<()>,
    OwnerRegistry,
    std::sync::Arc<Mutex<Vec<ProcessCancellationPhase>>>,
    std::sync::Arc<AtomicUsize>,
) {
    let phases = std::sync::Arc::new(Mutex::new(Vec::new()));
    let terminal_markers = std::sync::Arc::new(AtomicUsize::new(0));
    let registry = OwnerRegistry::new();
    let supervisor = ProcessSupervisor::new(
        vec![shutdown_process_root(behavior, &phases, &terminal_markers)],
        grace,
        registry.clone(),
    )
    .expect("one required root");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_rx.await;
    }));
    for _ in 0..100 {
        if registry.snapshot().active_process_roots == 1 {
            return (run, shutdown_tx, registry, phases, terminal_markers);
        }
        tokio::task::yield_now().await;
    }
    panic!("process root did not become active");
}

#[tokio::test(start_paused = true)]
async fn process_shutdown_table_drains_forces_and_reports_cleanup_failure() {
    let (graceful, graceful_tx, graceful_registry, graceful_phases, graceful_terminal_markers) =
        start_process_shutdown_case(
            ProcessShutdownBehavior::Drain(Duration::from_secs(2)),
            Duration::from_secs(5),
        )
        .await;
    graceful_tx.send(()).expect("request graceful shutdown");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let graceful = graceful.await.expect("graceful process owner");
    assert_eq!(graceful.exit_kind(), ProcessExitKind::Graceful);
    assert_eq!(
        graceful.states(),
        &[
            ProcessState::Validated,
            ProcessState::Preparing,
            ProcessState::Prepared,
            ProcessState::Active,
            ProcessState::Quiescing,
            ProcessState::Draining,
            ProcessState::Stopped,
        ]
    );
    assert_eq!(
        *graceful_phases.lock().expect("phase lock"),
        [ProcessCancellationPhase::Quiescing]
    );
    assert_eq!(graceful_registry.snapshot().process_root_reaps, 1);
    assert_eq!(graceful_terminal_markers.load(Ordering::SeqCst), 1);

    let (forced, forced_tx, forced_registry, forced_phases, forced_terminal_markers) =
        start_process_shutdown_case(ProcessShutdownBehavior::AwaitForce, Duration::from_secs(5))
            .await;
    forced_tx.send(()).expect("request forced shutdown");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    let forced = forced.await.expect("forced process owner");
    assert_eq!(forced.exit_kind(), ProcessExitKind::Forced);
    assert_eq!(forced.forced_roots(), 1);
    assert_eq!(
        forced.states(),
        &[
            ProcessState::Validated,
            ProcessState::Preparing,
            ProcessState::Prepared,
            ProcessState::Active,
            ProcessState::Quiescing,
            ProcessState::Draining,
            ProcessState::Forced,
            ProcessState::Stopped,
        ]
    );
    assert_eq!(
        *forced_phases.lock().expect("phase lock"),
        [
            ProcessCancellationPhase::Quiescing,
            ProcessCancellationPhase::Forced,
        ]
    );
    let forced_snapshot = forced_registry.snapshot();
    assert_eq!(forced_snapshot.process_root_reaps, 1);
    assert_eq!(forced_snapshot.process_forced_roots, 1);
    assert_eq!(forced_snapshot.active_process_roots, 0);
    assert_eq!(forced_terminal_markers.load(Ordering::SeqCst), 1);

    let (failed, failed_tx, failed_registry, _failed_phases, failed_terminal_markers) =
        start_process_shutdown_case(
            ProcessShutdownBehavior::CleanupFailure,
            Duration::from_secs(5),
        )
        .await;
    failed_tx.send(()).expect("request cleanup failure");
    let failed = failed.await.expect("failed process owner");
    assert_eq!(failed.exit_kind(), ProcessExitKind::Failed);
    assert!(matches!(
        failed.cleanup_failure(),
        Some(ProcessCleanupFailure::RootFailed { root, error: "cleanup" })
            if root.get() == 0
    ));
    assert_eq!(failed_registry.snapshot().active_process_roots, 0);
    assert_eq!(failed_registry.snapshot().process_root_reaps, 1);
    assert_eq!(failed_terminal_markers.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn uncooperative_forced_root_is_aborted_and_reports_cleanup_failure() {
    let phases = std::sync::Arc::new(Mutex::new(Vec::new()));
    let terminal_markers = std::sync::Arc::new(AtomicUsize::new(0));
    let roots = [
        ProcessShutdownBehavior::Uncooperative,
        ProcessShutdownBehavior::Uncooperative,
        ProcessShutdownBehavior::CleanupFailure,
    ]
    .into_iter()
    .map(|behavior| shutdown_process_root(behavior, &phases, &terminal_markers))
    .collect();
    let registry = OwnerRegistry::new();
    let supervisor = ProcessSupervisor::new(roots, Duration::ZERO, registry.clone())
        .expect("three required roots");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let process = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_rx.await;
    }));

    for _ in 0..100 {
        if registry.snapshot().active_process_roots == 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    shutdown_tx.send(()).expect("request zero-grace shutdown");
    tokio::task::yield_now().await;
    assert!(registry.snapshot().process_forced_roots >= 2);
    assert!(!process.is_finished());
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert!(!process.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    if !process.is_finished() {
        process.abort();
        let _ = process.await;
        panic!("forced roots were not reaped by the fixed five-second watchdog");
    }
    let report = process.await.expect("bounded forced reap");

    assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
    assert!(matches!(
        report.cleanup_failure(),
        Some(ProcessCleanupFailure::ForceReapTimedOut {
            roots,
            prior: Some(prior),
        })
            if roots.iter().map(|root| root.get()).collect::<Vec<_>>() == [0, 1]
                && matches!(
                    prior.as_ref(),
                    ProcessCleanupFailure::RootFailed { root, error: "cleanup" }
                        if root.get() == 2
                )
    ));
    assert!(report.forced_roots() >= 2);
    assert_eq!(terminal_markers.load(Ordering::SeqCst), 3);
    assert_eq!(registry.snapshot().active_process_roots, 0);
    assert_eq!(registry.snapshot().process_root_reaps, 3);
}
