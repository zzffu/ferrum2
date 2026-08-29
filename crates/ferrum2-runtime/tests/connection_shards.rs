use std::{
    collections::VecDeque,
    future::pending,
    io,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, ConnectionRuntimePool, OwnerRegistry, SupervisorError,
};
use tokio::sync::{Notify, mpsc, oneshot};

#[tokio::test]
async fn supervisor_round_robins_whole_connections_onto_stable_threads() {
    let shard_count = test_shard_count(2);
    let pool = ConnectionRuntimePool::new(shard_count).expect("pool starts");
    let (listener, _accept_calls) = QueueListener::with_cpu_hints([
        (0, None),
        (1, Some(usize::MAX)),
        (2, Some(usize::MAX)),
        (3, None),
    ]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new_on_connection_runtime(
        listener,
        4,
        Duration::ZERO,
        registry.clone(),
        pool.dispatcher(),
    )
    .expect("valid supervisor");
    let (observed_sender, mut observed_receiver) = mpsc::channel(4);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        move |stream, _cancellation| {
            let observed_sender = observed_sender.clone();
            async move {
                let thread_id = thread::current().id();
                let mut stayed_on_thread = true;
                for _ in 0..32 {
                    tokio::task::yield_now().await;
                    stayed_on_thread &= thread::current().id() == thread_id;
                }
                observed_sender
                    .send((stream.id, thread_id, stayed_on_thread))
                    .await
                    .expect("observation receiver remains open");
            }
        },
        async move {
            let _closed = shutdown_receiver.await;
        },
    ));

    let mut observations = Vec::with_capacity(4);
    for _ in 0..4 {
        observations.push(
            tokio::time::timeout(Duration::from_secs(2), observed_receiver.recv())
                .await
                .expect("connection finishes before timeout")
                .expect("observation channel remains open"),
        );
    }
    observations.sort_unstable_by_key(|observation| observation.0);

    assert!(observations.iter().all(|observation| observation.2));
    if shard_count.get() == 1 {
        assert!(
            observations
                .iter()
                .all(|observation| observation.1 == observations[0].1)
        );
    } else {
        assert_ne!(observations[0].1, observations[1].1);
        assert_eq!(observations[0].1, observations[2].1);
        assert_eq!(observations[1].1, observations[3].1);
    }
    assert_ne!(observations[0].1, thread::current().id());

    shutdown_sender.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task joins")
        .expect("operator shutdown succeeds");
    assert_owner_baseline(&registry);
    drop(pool);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cpu_hints_select_the_matching_singleton_affinity_shard() {
    let cpu_ids = allowed_cpu_ids();
    let selected_cpu_ids = cpu_ids.into_iter().take(2).collect::<Vec<_>>();
    let shard_count = NonZeroUsize::new(selected_cpu_ids.len()).expect("Linux has an allowed CPU");
    let pool = ConnectionRuntimePool::new(shard_count).expect("pinned pool starts");
    let streams = selected_cpu_ids
        .iter()
        .copied()
        .rev()
        .chain(selected_cpu_ids.iter().copied())
        .enumerate()
        .map(|(id, cpu_id)| (id, Some(cpu_id)));
    let expected = streams.clone().collect::<Vec<_>>();
    let (listener, _accept_calls) = QueueListener::with_cpu_hints(streams);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new_on_connection_runtime(
        listener,
        expected.len(),
        Duration::ZERO,
        registry.clone(),
        pool.dispatcher(),
    )
    .expect("valid supervisor");
    let (observed_sender, mut observed_receiver) = mpsc::channel(expected.len());
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        move |stream, _cancellation| {
            let observed_sender = observed_sender.clone();
            async move {
                let observed_cpu = singleton_affinity_cpu();
                observed_sender
                    .send((stream.id, stream.cpu_hint, observed_cpu))
                    .await
                    .expect("observation receiver remains open");
            }
        },
        async move {
            let _closed = shutdown_receiver.await;
        },
    ));

    let mut observations = Vec::with_capacity(expected.len());
    for _ in 0..expected.len() {
        observations.push(
            tokio::time::timeout(Duration::from_secs(2), observed_receiver.recv())
                .await
                .expect("connection finishes before timeout")
                .expect("observation channel remains open"),
        );
    }
    observations.sort_unstable_by_key(|observation| observation.0);
    assert!(
        observations
            .iter()
            .all(|observation| observation.1 == Some(observation.2))
    );

    shutdown_sender.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task joins")
        .expect("operator shutdown succeeds");
    assert_owner_baseline(&registry);
    drop(pool);
}

#[tokio::test]
async fn sharded_supervisor_keeps_one_global_permit_before_accept() {
    let pool = ConnectionRuntimePool::new(NonZeroUsize::new(2).expect("non-zero shard count"))
        .expect("pool starts");
    let (listener, accept_calls) = QueueListener::new([1, 2]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new_on_connection_runtime(
        listener,
        1,
        Duration::ZERO,
        registry.clone(),
        pool.dispatcher(),
    )
    .expect("valid supervisor");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        |_stream, mut cancellation| async move { cancellation.cancelled().await },
        async move {
            let _closed = shutdown_receiver.await;
        },
    ));

    wait_for_connection_count(&registry, 1).await;
    assert_eq!(accept_calls.load(Ordering::Acquire), 1);
    assert_eq!(registry.snapshot().owned_permits, 1);
    assert_eq!(registry.snapshot().connection_tasks, 1);

    shutdown_sender.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task joins")
        .expect("operator shutdown succeeds");
    assert_owner_baseline(&registry);
    drop(pool);
}

#[tokio::test]
async fn remote_panic_is_child_failure_and_releases_every_owner() {
    let pool = ConnectionRuntimePool::new(NonZeroUsize::new(1).expect("non-zero shard count"))
        .expect("pool starts");
    let (listener, _accept_calls) = QueueListener::new([1]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new_on_connection_runtime(
        listener,
        1,
        Duration::ZERO,
        registry.clone(),
        pool.dispatcher(),
    )
    .expect("valid supervisor");

    let result = supervisor
        .run_until(
            |_stream, _cancellation| async move {
                panic!("private remote panic payload");
            },
            pending::<()>(),
        )
        .await;

    assert_eq!(result, Err(SupervisorError::ChildFailure));
    assert_owner_baseline(&registry);
    drop(pool);
}

#[tokio::test]
async fn forced_shutdown_aborts_and_reaps_each_remote_child() {
    let pool = ConnectionRuntimePool::new(NonZeroUsize::new(2).expect("non-zero shard count"))
        .expect("pool starts");
    let (listener, _accept_calls) = QueueListener::new([1, 2]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new_on_connection_runtime(
        listener,
        2,
        Duration::ZERO,
        registry.clone(),
        pool.dispatcher(),
    )
    .expect("valid supervisor");
    let dropped = Arc::new(AtomicUsize::new(0));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        {
            let dropped = Arc::clone(&dropped);
            move |_stream, _cancellation| {
                let dropped = Arc::clone(&dropped);
                async move {
                    let _drop_marker = DropMarker(dropped);
                    pending::<()>().await;
                }
            }
        },
        async move {
            let _closed = shutdown_receiver.await;
        },
    ));

    wait_for_connection_count(&registry, 2).await;
    shutdown_sender.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task joins")
        .expect("forced shutdown is controlled");

    assert_eq!(dropped.load(Ordering::Acquire), 2);
    assert_eq!(registry.snapshot().forced_shutdowns, 2);
    assert_owner_baseline(&registry);
    drop(pool);
}

struct QueueListener {
    streams: Mutex<VecDeque<QueuedStream>>,
    available: Notify,
    accept_calls: Arc<AtomicUsize>,
}

impl QueueListener {
    fn new(streams: impl IntoIterator<Item = usize>) -> (Self, Arc<AtomicUsize>) {
        Self::with_cpu_hints(streams.into_iter().map(|id| (id, None)))
    }

    fn with_cpu_hints(
        streams: impl IntoIterator<Item = (usize, Option<usize>)>,
    ) -> (Self, Arc<AtomicUsize>) {
        let accept_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                streams: Mutex::new(
                    streams
                        .into_iter()
                        .map(|(id, cpu_hint)| QueuedStream { id, cpu_hint })
                        .collect(),
                ),
                available: Notify::new(),
                accept_calls: Arc::clone(&accept_calls),
            },
            accept_calls,
        )
    }
}

impl AcceptListener for QueueListener {
    type Stream = QueuedStream;

    async fn accept(&self) -> io::Result<Self::Stream> {
        self.accept_calls.fetch_add(1, Ordering::AcqRel);
        loop {
            if let Some(stream) = self.streams.lock().expect("stream lock").pop_front() {
                return Ok(stream);
            }
            self.available.notified().await;
        }
    }

    fn connection_runtime_cpu_hint(&self, stream: &Self::Stream) -> Option<usize> {
        stream.cpu_hint
    }
}

#[derive(Clone, Copy)]
struct QueuedStream {
    id: usize,
    cpu_hint: Option<usize>,
}

struct DropMarker(Arc<AtomicUsize>);

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

async fn wait_for_connection_count(registry: &OwnerRegistry, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while registry.snapshot().connection_tasks != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection owners reach expected count");
}

fn assert_owner_baseline(registry: &OwnerRegistry) {
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.active_supervisor_children, 0);
    assert_eq!(snapshot.connection_tasks, 0);
    assert_eq!(snapshot.owned_permits, 0);
    assert_eq!(snapshot.listeners, 0);
}

fn test_shard_count(max_shards: usize) -> NonZeroUsize {
    #[cfg(target_os = "linux")]
    let count = allowed_cpu_ids().len().min(max_shards);
    #[cfg(not(target_os = "linux"))]
    let count = max_shards;
    NonZeroUsize::new(count).expect("at least one test shard")
}

#[cfg(target_os = "linux")]
fn allowed_cpu_ids() -> Vec<usize> {
    let affinity = rustix::thread::sched_getaffinity(None).expect("read test affinity");
    let cpu_ids = (0..rustix::thread::CpuSet::MAX_CPU)
        .filter(|cpu_id| affinity.is_set(*cpu_id))
        .collect::<Vec<_>>();
    assert!(!cpu_ids.is_empty());
    cpu_ids
}

#[cfg(target_os = "linux")]
fn singleton_affinity_cpu() -> usize {
    let cpu_ids = allowed_cpu_ids();
    assert_eq!(cpu_ids.len(), 1);
    cpu_ids[0]
}
