use super::*;
use std::time::Duration;

#[tokio::test]
async fn monitor_capacity_precedes_physical_prepare_and_survives_unpolled_drop() {
    let owners = OwnerRegistry::new();
    let limits = NetworkResetLimits::new(16, 1).unwrap();
    let coordinator = NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(snapshot(1)),
        limits,
        owners.clone(),
    );
    let state = Arc::new(FakeState::default());
    let (service, mut owner) = NetworkSocketService::new(
        coordinator,
        NetworkInterfaceResolver::new(Catalog),
        FakeOperations {
            state: Arc::clone(&state),
        },
        limits,
        owners.clone(),
    );
    let first = service
        .open_udp(&DialOptions::default(), &route(), destination(53))
        .unwrap();
    assert!(matches!(
        service.open_udp(&DialOptions::default(), &route(), destination(54)),
        Err(NetworkSocketServiceError::Owner(
            NetworkSocketOwnerError::Busy
        ))
    ));
    assert_eq!(state.calls.lock().unwrap().len(), 1);
    drop(first);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    // The current-thread executor has not polled the monitor yet: physical
    // release alone cannot authorize a replacement monitor slot.
    assert!(matches!(
        service.open_udp(&DialOptions::default(), &route(), destination(54)),
        Err(NetworkSocketServiceError::Owner(
            NetworkSocketOwnerError::Busy
        ))
    ));
    owner.shutdown().await.unwrap();
    assert_eq!(owners.snapshot(), Default::default());
    assert!(matches!(
        service.open_udp(&DialOptions::default(), &route(), destination(54)),
        Err(NetworkSocketServiceError::Owner(
            NetworkSocketOwnerError::Closed
        ))
    ));
}

#[tokio::test]
async fn retired_generation_fence_does_not_wait_for_new_generation_monitors() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service, mut owner) = service(&owners, Arc::clone(&state));
    let first = service
        .open_udp(&DialOptions::default(), &route(), destination(53))
        .unwrap();
    coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .await
        .unwrap();
    let second = service
        .clone()
        .open_udp(&DialOptions::default(), &route(), destination(54))
        .unwrap();
    owner.retire_generation(1).await.unwrap();
    assert!(first.is_closed().await);
    assert!(!second.is_closed().await);
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    owner.shutdown().await.unwrap();
    assert!(second.is_closed().await);
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

struct BlockingCatalog {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
    calls: Arc<AtomicUsize>,
}
impl NetworkInterfaceCatalog for BlockingCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        self.resume
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        Ok(Vec::new())
    }
    fn system_best_route(
        &self,
        _: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_capture_and_shutdown_retain_the_one_actual_native_slot() {
    let owners = OwnerRegistry::new();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let (service, mut owner) = NetworkSocketService::new(
        coordinator(&owners),
        NetworkInterfaceResolver::new(BlockingCatalog {
            entered: Mutex::new(Some(entered)),
            resume: Mutex::new(wait),
            calls: Arc::clone(&calls),
        }),
        FakeOperations {
            state: Arc::new(FakeState::default()),
        },
        NetworkResetLimits::default(),
        owners.clone(),
    );
    let request_service = service.clone();
    let request = tokio::spawn(async move { request_service.capture_snapshot(2).await });
    ready.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert_eq!(
        service.capture_snapshot(3).await,
        Err(NetworkSocketOwnerError::Busy)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_snapshot_captures, 1);
    {
        let shutdown = tokio::time::timeout(Duration::from_millis(20), owner.shutdown());
        tokio::pin!(shutdown);
        let pending = std::future::poll_fn(|context| {
            Poll::Ready(std::future::Future::poll(shutdown.as_mut(), context))
        })
        .await;
        assert!(pending.is_pending());
        // Native blocking work prevents Tokio's automatic clock advance; drive
        // the logical timeout explicitly while the finite fake call stays held.
        tokio::time::advance(Duration::from_millis(20)).await;
        assert!(shutdown.await.is_err());
    }
    assert_eq!(owners.snapshot().network_snapshot_captures, 1);
    assert_eq!(
        service.capture_snapshot(3).await,
        Err(NetworkSocketOwnerError::Closed)
    );
    resume.send(()).unwrap();
    owner.shutdown().await.unwrap();
    assert_eq!(owners.snapshot().network_snapshot_captures, 0);
    assert_eq!(service.published_generation(), 1);
}

struct FailedCatalog;
impl NetworkInterfaceCatalog for FailedCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
    fn system_best_route(
        &self,
        _: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}
#[tokio::test]
async fn failed_capture_releases_its_joined_slot_without_publishing() {
    let owners = OwnerRegistry::new();
    let (service, mut owner) = NetworkSocketService::new(
        coordinator(&owners),
        NetworkInterfaceResolver::new(FailedCatalog),
        FakeOperations {
            state: Arc::new(FakeState::default()),
        },
        NetworkResetLimits::default(),
        owners.clone(),
    );
    assert_eq!(
        service.capture_snapshot(2).await,
        Err(NetworkSocketOwnerError::Capture)
    );
    assert_eq!(
        service.capture_snapshot(3).await,
        Err(NetworkSocketOwnerError::Capture)
    );
    assert_eq!(service.published_generation(), 1);
    assert_eq!(owners.snapshot().network_snapshot_captures, 0);
    owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_inflight_connect_reservations_before_joining_zero() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.tcp_connect_pending.store(1, Ordering::SeqCst);
    let (_coordinator, service, mut owner) = service(&owners, Arc::clone(&state));
    let operation = tokio::spawn(async move {
        service
            .connect_tcp(&DialOptions::default(), &route(), destination(443))
            .await
    });
    state.connect_started.notified().await;
    owner.shutdown().await.unwrap();
    assert!(matches!(
        operation.await.unwrap(),
        Err(NetworkSocketServiceError::Owner(
            NetworkSocketOwnerError::Closed
        ))
    ));
    assert_eq!(state.tcp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

struct PanickingCatalog;
impl NetworkInterfaceCatalog for PanickingCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        panic!("controlled catalog failure")
    }
    fn system_best_route(
        &self,
        _: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}
#[tokio::test]
async fn capture_panic_is_closed_sticky_join_failure() {
    let owners = OwnerRegistry::new();
    let (service, mut owner) = NetworkSocketService::new(
        coordinator(&owners),
        NetworkInterfaceResolver::new(PanickingCatalog),
        FakeOperations {
            state: Arc::new(FakeState::default()),
        },
        NetworkResetLimits::default(),
        owners.clone(),
    );
    assert_eq!(
        service.capture_snapshot(2).await,
        Err(NetworkSocketOwnerError::WorkerFailed)
    );
    assert_eq!(owners.snapshot().network_snapshot_captures, 0);
    assert_eq!(
        owner.shutdown().await,
        Err(NetworkSocketOwnerError::WorkerFailed)
    );
    assert_eq!(
        owner.shutdown().await,
        Err(NetworkSocketOwnerError::WorkerFailed)
    );
    assert_eq!(service.published_generation(), 1);
}

#[tokio::test]
async fn next_admission_consumes_only_completed_monitor_notifications() {
    let owners = OwnerRegistry::new();
    let limits = NetworkResetLimits::new(16, 1).unwrap();
    let coordinator = NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(snapshot(1)),
        limits,
        owners.clone(),
    );
    let (service, mut owner) = NetworkSocketService::new(
        coordinator,
        NetworkInterfaceResolver::new(Catalog),
        FakeOperations {
            state: Arc::new(FakeState::default()),
        },
        limits,
        owners.clone(),
    );
    for port in [53, 54, 55] {
        let socket = service
            .open_udp(&DialOptions::default(), &route(), destination(port))
            .unwrap();
        assert_eq!(owners.snapshot().network_socket_monitors, 1);
        drop(socket);
        tokio::task::yield_now().await;
    }
    owner.shutdown().await.unwrap();
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
}
