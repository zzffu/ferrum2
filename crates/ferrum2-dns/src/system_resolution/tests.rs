use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, mpsc as sync_mpsc};

struct GatedLookup {
    started: Notify,
    release: Mutex<sync_mpsc::Receiver<()>>,
    calls: AtomicUsize,
}
impl NativeLookup for GatedLookup {
    fn resolve(&self, _host: &str, port: u16) -> Result<Candidates, SystemResolutionError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.started.notify_one();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        Ok(Candidates::collect([SocketAddr::from((
            [192, 0, 2, 1],
            port,
        ))]))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn abandoned_native_call_keeps_capacity_and_shutdown_join_is_retryable() {
    let (release, receive) = sync_mpsc::channel();
    let native = Arc::new(GatedLookup {
        started: Notify::new(),
        release: Mutex::new(receive),
        calls: AtomicUsize::new(0),
    });
    let (resolver, mut owner) = start(
        NonZeroU16::new(1).unwrap(),
        Duration::from_secs(1),
        native.clone(),
    );
    let mut request =
        Box::pin(resolver.resolve("native.test", 80, Instant::now() + Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut request).is_pending());
    native.started.notified().await;
    drop(request);
    assert_eq!(
        resolver
            .resolve(
                "replacement.test",
                80,
                Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(SystemResolutionError::Busy)
    );
    assert_eq!(native.calls.load(Ordering::Acquire), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(5), owner.shutdown())
            .await
            .is_err()
    );
    assert_eq!(
        resolver
            .resolve(
                "replacement.test",
                80,
                Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(SystemResolutionError::Shutdown)
    );
    release.send(()).unwrap();
    let report = tokio::time::timeout(Duration::from_secs(2), owner.shutdown())
        .await
        .unwrap();
    assert_eq!(report, Ok(SystemResolutionReport::default()));
    assert_eq!(owner.shutdown().await, report);
}

struct DispatchWake(Notify);
impl std::task::Wake for DispatchWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn completed_but_unjoined_work_retains_its_slot() {
    let (release, receive_native) = sync_mpsc::channel();
    let native = Arc::new(GatedLookup {
        started: Notify::new(),
        release: Mutex::new(receive_native),
        calls: AtomicUsize::new(0),
    });
    let shared = Arc::new(Shared {
        slots: Arc::new(Semaphore::new(1)),
        stop: Notify::new(),
        timeout: Duration::from_secs(1),
    });
    let (send, receive) = mpsc::channel(1);
    let resolver = SystemResolver {
        send,
        shared: shared.clone(),
    };
    let mut dispatcher = Box::pin(dispatch(receive, shared.clone(), native.clone()));
    let wake = Arc::new(DispatchWake(Notify::new()));
    let waker = std::task::Waker::from(wake.clone());
    let mut request =
        Box::pin(resolver.resolve("native.test", 80, Instant::now() + Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut request).is_pending());
    // Advance the real dispatcher only until the gated native task is pending.
    assert!(
        dispatcher
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
            .is_pending()
    );
    native.started.notified().await;
    // Discard any insertion wake; after release, only task completion can wake it.
    let _ = futures_util::FutureExt::now_or_never(wake.0.notified());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), wake.0.notified())
        .await
        .unwrap();
    // Native completion has woken the dispatcher, but it has not been polled to join.
    assert_eq!(
        resolver
            .resolve(
                "replacement.test",
                80,
                Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(SystemResolutionError::Busy)
    );
    let (answers, report) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            async {
                let first = request.await;
                release.send(()).unwrap();
                let second = resolver
                    .resolve(
                        "replacement.test",
                        81,
                        Instant::now() + Duration::from_secs(1),
                    )
                    .await;
                shared.close();
                (first, second)
            },
            dispatcher
        )
    })
    .await
    .unwrap();
    assert_eq!(
        answers,
        (
            Ok(vec![SocketAddr::from(([192, 0, 2, 1], 80))]),
            Ok(vec![SocketAddr::from(([192, 0, 2, 1], 81))]),
        )
    );
    assert_eq!(report, Ok(SystemResolutionReport::default()));
}

struct PanickingLookup;
impl NativeLookup for PanickingLookup {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Candidates, SystemResolutionError> {
        panic!("injected native failure")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_panic_is_closed_and_sticky_after_join() {
    let (resolver, mut owner) = start(
        NonZeroU16::new(1).unwrap(),
        Duration::from_secs(1),
        Arc::new(PanickingLookup),
    );
    assert_eq!(
        resolver
            .resolve("native.test", 80, Instant::now() + Duration::from_secs(1))
            .await,
        Err(SystemResolutionError::WorkerFailed)
    );
    assert_eq!(resolver.shared.slots.available_permits(), 1);
    assert_eq!(
        owner.shutdown().await,
        Err(SystemResolutionError::WorkerFailed)
    );
    assert_eq!(
        owner.shutdown().await,
        Err(SystemResolutionError::WorkerFailed)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn queued_shutdown_rejects_without_native_execution_and_numeric_lookup_bypasses_admission() {
    let (resolver, mut owner) = start(
        NonZeroU16::new(1).unwrap(),
        Duration::from_secs(1),
        Arc::new(PanickingLookup),
    );
    let mut request =
        Box::pin(resolver.resolve("native.test", 80, Instant::now() + Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut request).is_pending());
    assert_eq!(
        resolver
            .resolve("192.0.2.3", 0, Instant::now() + Duration::from_secs(1))
            .await,
        Ok(vec![SocketAddr::from(([192, 0, 2, 3], 0))])
    );
    assert_eq!(
        owner.shutdown().await,
        Ok(SystemResolutionReport::default())
    );
    assert_eq!(request.await, Err(SystemResolutionError::Shutdown));
}

#[test]
fn candidate_collection_preserves_os_order_and_bounds_each_family() {
    let addresses = (1..=20)
        .map(|n| SocketAddr::from(([192, 0, 2, n], 0)))
        .chain((1..=20).map(|n| {
            SocketAddr::new(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n).into(),
                0,
            )
        }));
    let candidates = Candidates::collect(addresses.clone());
    assert_eq!(
        candidates.ordered,
        addresses.clone().take(16).collect::<Vec<_>>()
    );
    assert_eq!(
        candidates.families,
        addresses
            .take(16)
            .chain((1..=16).map(|n| SocketAddr::new(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n).into(),
                0
            )))
            .map(|address| address.ip())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn invalid_limits_and_input_never_start_native_work() {
    assert!(matches!(
        SystemResolution::start(NonZeroU16::new(4097).unwrap(), Duration::from_secs(1)),
        Err(SystemResolutionError::InvalidLimits)
    ));
    assert!(matches!(
        SystemResolution::start(NonZeroU16::new(1).unwrap(), Duration::ZERO),
        Err(SystemResolutionError::InvalidLimits)
    ));
    let (resolver, mut owner) = start(
        NonZeroU16::new(1).unwrap(),
        Duration::from_secs(1),
        Arc::new(PanickingLookup),
    );
    for host in [String::new(), "x".repeat(254), "bad\0host".into()] {
        assert_eq!(
            resolver
                .resolve(&host, 80, Instant::now() + Duration::from_secs(1))
                .await,
            Err(SystemResolutionError::Resolution)
        );
    }
    assert_eq!(
        owner.shutdown().await,
        Ok(SystemResolutionReport::default())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn deadline_abandons_only_the_waiter_until_native_completion_is_joined() {
    let (release, receive) = sync_mpsc::channel();
    let native = Arc::new(GatedLookup {
        started: Notify::new(),
        release: Mutex::new(receive),
        calls: AtomicUsize::new(0),
    });
    let (resolver, mut owner) = start(
        NonZeroU16::new(1).unwrap(),
        Duration::from_secs(1),
        native.clone(),
    );
    let mut request =
        Box::pin(resolver.resolve("native.test", 80, Instant::now() + Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut request).is_pending());
    native.started.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(request.await, Err(SystemResolutionError::Timeout));
    assert_eq!(
        resolver
            .resolve(
                "replacement.test",
                80,
                Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(SystemResolutionError::Busy)
    );
    tokio::time::resume();
    release.send(()).unwrap();
    assert_eq!(
        owner.shutdown().await,
        Ok(SystemResolutionReport::default())
    );
}

#[test]
fn cancelled_work_waiting_for_native_worker_never_calls_the_os_adapter() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release, receive) = sync_mpsc::channel();
        let (started, waiting) = oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            receive.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        waiting.await.unwrap();
        let (resolver, mut owner) = start(
            NonZeroU16::new(1).unwrap(),
            Duration::from_secs(1),
            Arc::new(PanickingLookup),
        );
        let mut request =
            Box::pin(resolver.resolve("native.test", 80, Instant::now() + Duration::from_secs(1)));
        assert!(futures_util::poll!(&mut request).is_pending());
        tokio::task::yield_now().await;
        drop(request);
        release.send(()).unwrap();
        blocker.await.unwrap();
        assert_eq!(
            owner.shutdown().await,
            Ok(SystemResolutionReport::default())
        );
    });
}
