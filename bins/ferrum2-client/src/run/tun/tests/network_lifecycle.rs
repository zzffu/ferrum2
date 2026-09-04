use super::*;

#[tokio::test]
async fn client_network_hook_retries_failure_and_accepts_each_generation_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ferrum2_net::NetworkSnapshot;
    use ferrum2_runtime::ResetNetwork;

    let attempts = Arc::new(AtomicUsize::new(0));
    let action_attempts = Arc::clone(&attempts);
    let hook = ClientNetworkResetHook::new(
        1,
        Arc::new(move |generation| {
            assert_eq!(generation, 2);
            if action_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(())
            } else {
                Ok(())
            }
        }),
    );
    let second = Arc::new(NetworkSnapshot::new(2, None, None).unwrap());
    assert!(hook.reset_network(Arc::clone(&second)).await.is_err());
    assert!(hook.reset_network(Arc::clone(&second)).await.is_ok());
    assert!(hook.reset_network(second).await.is_ok());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    let stale = Arc::new(NetworkSnapshot::new(1, None, None).unwrap());
    assert!(hook.reset_network(stale).await.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn client_network_hooks_are_owned_only_during_tun_prepare_lifetime() {
    use ferrum2_net::NetworkSnapshot;

    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (path, context) = udp_test_context_for_server(registry.clone(), reserve_address());
    let initial = Arc::new(NetworkSnapshot::new(1, None, None).expect("initial snapshot"));
    let coordinator = network_reset_coordinator(initial, registry.clone());
    let runtime = ClientNetworkResetRuntime::new(&context, coordinator);

    assert_eq!(
        registry.snapshot().network_reset_hooks,
        baseline.network_reset_hooks
    );
    runtime
        .initialize(Arc::new(
            NetworkSnapshot::new(2, None, None).expect("next snapshot"),
        ))
        .await
        .expect("initialize reset hooks");
    assert_eq!(registry.snapshot().network_reset_hooks, 4);

    drop(runtime);
    assert_eq!(
        registry.snapshot().network_reset_hooks,
        baseline.network_reset_hooks
    );
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn non_tun_network_reset_registers_hooks_before_publishing_generation() {
    use ferrum2_net::NetworkSnapshot;

    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (path, context) = udp_test_context_for_server(registry.clone(), reserve_address());
    let initial = Arc::new(NetworkSnapshot::new(1, None, None).expect("initial snapshot"));
    let coordinator = network_reset_coordinator(initial, registry.clone());
    let runtime = ClientNetworkResetRuntime::new(&context, coordinator);

    assert_eq!(
        registry.snapshot().network_reset_hooks,
        baseline.network_reset_hooks
    );
    runtime
        .reset(
            Arc::new(NetworkSnapshot::new(2, None, None).expect("next snapshot")),
            ferrum2_tun::TunNetworkResetReason::NetworkChange,
        )
        .await
        .expect("non-TUN reset");
    assert_eq!(registry.snapshot().network_reset_hooks, 4);
    assert!(
        runtime
            .hooks
            .iter()
            .all(|hook| { hook.accepted_generation.load(Ordering::Acquire) == 2 })
    );

    drop(runtime);
    assert_eq!(
        registry.snapshot().network_reset_hooks,
        baseline.network_reset_hooks
    );
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn tun_reset_accepts_snapshot_already_published_by_concurrent_notifier() {
    use ferrum2_net::NetworkSnapshot;
    use ferrum2_runtime::{NetworkResetIntent, NetworkResetReason as RuntimeNetworkResetReason};

    let registry = OwnerRegistry::new();
    let (path, context) = udp_test_context_for_server(registry.clone(), reserve_address());
    let initial = Arc::new(NetworkSnapshot::new(1, None, None).expect("initial snapshot"));
    let coordinator = network_reset_coordinator(initial, registry);
    let runtime = ClientNetworkResetRuntime::new(&context, coordinator);
    runtime
        .initialize(Arc::new(
            NetworkSnapshot::new(2, None, None).expect("initial TUN snapshot"),
        ))
        .await
        .expect("initialize TUN network lifecycle");

    let concurrent = Arc::new(NetworkSnapshot::new(3, None, None).expect("concurrent snapshot"));
    runtime
        .coordinator
        .reset_network(
            Arc::clone(&concurrent),
            NetworkResetIntent::Ordinary(RuntimeNetworkResetReason::InterfaceChanged),
        )
        .await
        .expect("concurrent notifier reset");
    runtime
        .reset(
            Arc::clone(&concurrent),
            ferrum2_tun::TunNetworkResetReason::NetworkChange,
        )
        .await
        .expect("coalesced TUN reset");

    assert_eq!(runtime.coordinator.status().published_generation(), 3);
    assert!(
        runtime
            .hooks
            .iter()
            .all(|hook| hook.accepted_generation.load(Ordering::Acquire) == 3)
    );

    drop(runtime);
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn managed_tun_lifecycle_cancelled_prepare_cleanup_failure_maps_to_shutdown_cleanup() {
    let entered = Arc::new(Notify::new());
    let prepare_entered = Arc::clone(&entered);
    let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
        prepare_entered.notify_one();
        cancellation.cancelled().await;
        Err::<Option<NeverPrepared>, _>(RunError::ShutdownCleanup)
    });
    let supervisor =
        ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
            .expect("one required root");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_rx.await;
    }));

    entered.notified().await;
    shutdown_tx.send(()).expect("shutdown");
    let report = run.await.expect("process owner");
    assert_eq!(report_result(report), Err(RunError::ShutdownCleanup));
}
