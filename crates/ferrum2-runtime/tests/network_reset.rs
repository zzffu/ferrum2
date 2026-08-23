use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ferrum2_runtime::{
    ManagedNetworkDamage, NetworkResetCoordinator, NetworkResetCoordinatorError, NetworkResetError,
    NetworkResetFuture, NetworkResetHookRegistrationError, NetworkResetHookStage,
    NetworkResetIntent, NetworkResetLimits, NetworkResetOutcome, NetworkResetReason,
    NetworkResetState, NetworkRuntimeOwnerCancellation, NetworkRuntimeOwnerKind,
    NetworkRuntimeOwnerRegistrationError, NetworkSnapshot, NetworkSnapshotPublisher, OwnerRegistry,
    ResetNetwork,
};
use tokio::sync::{Semaphore, mpsc, oneshot};

fn snapshot(generation: u64) -> Arc<NetworkSnapshot> {
    Arc::new(NetworkSnapshot::new(generation, None, None).expect("valid snapshot"))
}

fn coordinator(
    generation: u64,
    limits: NetworkResetLimits,
    owners: &OwnerRegistry,
) -> NetworkResetCoordinator {
    NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(snapshot(generation)),
        limits,
        owners.clone(),
    )
}

#[derive(Debug)]
struct RecordingHook {
    label: &'static str,
    events: Arc<Mutex<Vec<(u64, &'static str)>>>,
}

impl ResetNetwork for RecordingHook {
    fn reset_network(&self, snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("event lock")
                .push((snapshot.generation(), self.label));
            Ok(())
        })
    }
}

#[tokio::test]
async fn current_generation_is_a_noop_and_registrations_are_bounded_and_drop_owned() {
    let owners = OwnerRegistry::new();
    let baseline = owners.snapshot();
    let coordinator = coordinator(1, NetworkResetLimits::new(1, 1).unwrap(), &owners);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let hook = Arc::new(RecordingHook {
        label: "first",
        events: Arc::clone(&calls),
    });
    let registration = coordinator
        .register_reset_hook(NetworkResetHookStage::Stack, hook)
        .unwrap();
    assert_eq!(owners.snapshot().network_reset_hooks, 1);
    assert_eq!(
        coordinator
            .register_reset_hook(
                NetworkResetHookStage::Router,
                Arc::new(RecordingHook {
                    label: "overflow",
                    events: Arc::clone(&calls),
                }),
            )
            .unwrap_err(),
        NetworkResetHookRegistrationError::CapacityExhausted
    );

    let owner = coordinator
        .register_runtime_owner(1, NetworkRuntimeOwnerKind::TcpConnection)
        .unwrap();
    assert_eq!(owners.snapshot().network_runtime_owners, 1);
    assert_eq!(
        coordinator
            .register_runtime_owner(1, NetworkRuntimeOwnerKind::UdpAssociation)
            .unwrap_err(),
        NetworkRuntimeOwnerRegistrationError::CapacityExhausted
    );
    assert_eq!(
        coordinator
            .register_runtime_owner(0, NetworkRuntimeOwnerKind::UdpAssociation)
            .unwrap_err(),
        NetworkRuntimeOwnerRegistrationError::StaleGeneration
    );

    let report = coordinator
        .reset_network(
            snapshot(1),
            NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest),
        )
        .await
        .unwrap();
    assert_eq!(report.outcome(), NetworkResetOutcome::Noop);
    assert_eq!(report.completed_resets(), 0);
    assert!(calls.lock().unwrap().is_empty());
    assert!(coordinator.status().admission_open());

    drop(owner);
    drop(registration);
    drop(coordinator);
    assert_eq!(owners.snapshot(), baseline);
}

#[derive(Debug)]
struct BlockingRecordingHook {
    label: &'static str,
    events: Arc<Mutex<Vec<(u64, &'static str)>>>,
    block_generation: u64,
    entered: mpsc::UnboundedSender<()>,
    gate: Arc<Semaphore>,
}

impl ResetNetwork for BlockingRecordingHook {
    fn reset_network(&self, snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("event lock")
                .push((snapshot.generation(), self.label));
            if snapshot.generation() == self.block_generation {
                self.entered.send(()).expect("entry receiver");
                self.gate
                    .acquire()
                    .await
                    .expect("gate remains open")
                    .forget();
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn notification_burst_keeps_only_latest_pending_generation_and_hook_order_is_fixed() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let events = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let gate = Arc::new(Semaphore::new(0));
    let mut registrations = Vec::new();

    for (stage, label) in [
        (NetworkResetHookStage::Inbound, "inbound"),
        (NetworkResetHookStage::Stack, "stack-a"),
        (NetworkResetHookStage::Router, "router"),
        (NetworkResetHookStage::Stack, "stack-b"),
        (NetworkResetHookStage::Outbound, "outbound"),
    ] {
        let hook: Arc<dyn ResetNetwork> = if label == "stack-a" {
            Arc::new(BlockingRecordingHook {
                label,
                events: Arc::clone(&events),
                block_generation: 2,
                entered: entered_tx.clone(),
                gate: Arc::clone(&gate),
            })
        } else {
            Arc::new(RecordingHook {
                label,
                events: Arc::clone(&events),
            })
        };
        registrations.push(coordinator.register_reset_hook(stage, hook).unwrap());
    }

    let first = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .reset_network(
                    snapshot(2),
                    NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
                )
                .await
        })
    };
    entered_rx.recv().await.expect("generation two entered");

    let third = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .reset_network(
                    snapshot(3),
                    NetworkResetIntent::Ordinary(NetworkResetReason::InterfaceChanged),
                )
                .await
        })
    };
    wait_for_pending_generation(&coordinator, 3).await;
    let fourth = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .reset_network(
                    snapshot(4),
                    NetworkResetIntent::Ordinary(NetworkResetReason::UnicastAddressChanged),
                )
                .await
        })
    };
    wait_for_pending_generation(&coordinator, 4).await;
    gate.add_permits(1);

    let first_report = first.await.unwrap().unwrap();
    let third_report = third.await.unwrap().unwrap();
    let fourth_report = fourth.await.unwrap().unwrap();
    assert_eq!(first_report.outcome(), NetworkResetOutcome::ResetCompleted);
    assert_eq!(first_report.completed_resets(), 2);
    assert_eq!(third_report.outcome(), NetworkResetOutcome::Noop);
    assert_eq!(fourth_report.outcome(), NetworkResetOutcome::Noop);
    assert_eq!(coordinator.status().published_generation(), 4);
    assert!(coordinator.status().admission_open());

    let expected_for = |generation| {
        ["stack-a", "stack-b", "router", "outbound", "inbound"]
            .into_iter()
            .map(move |label| (generation, label))
    };
    let expected = expected_for(2).chain(expected_for(4)).collect::<Vec<_>>();
    assert_eq!(*events.lock().unwrap(), expected);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|(generation, _)| *generation != 3)
    );
    drop(registrations);
}

async fn wait_for_pending_generation(coordinator: &NetworkResetCoordinator, generation: u64) {
    for _ in 0..1_000 {
        if coordinator.status().pending_generation() == Some(generation) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("pending generation {generation} was not observed");
}

#[derive(Debug)]
struct FailOnceHook {
    attempts: AtomicUsize,
}

impl ResetNetwork for FailOnceHook {
    fn reset_network(&self, _snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_> {
        Box::pin(async move {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(NetworkResetError)
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn hook_failure_keeps_admission_closed_and_same_generation_retry_is_idempotent() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let hook = Arc::new(FailOnceHook {
        attempts: AtomicUsize::new(0),
    });
    let registration = coordinator
        .register_reset_hook(NetworkResetHookStage::Outbound, hook.clone())
        .unwrap();

    assert_eq!(
        coordinator
            .reset_network(
                snapshot(2),
                NetworkResetIntent::Ordinary(NetworkResetReason::DefaultInterfaceChanged),
            )
            .await
            .unwrap_err(),
        NetworkResetCoordinatorError::HookFailed(NetworkResetHookStage::Outbound)
    );
    let failed = coordinator.status();
    assert_eq!(failed.state(), NetworkResetState::RetryReset);
    assert!(!failed.admission_open());
    assert_eq!(failed.published_generation(), 2);
    assert_eq!(failed.pending_generation(), Some(2));
    assert_eq!(owners.snapshot().network_reset_drivers, 0);
    assert_eq!(
        coordinator
            .register_runtime_owner(2, NetworkRuntimeOwnerKind::TcpConnection)
            .unwrap_err(),
        NetworkRuntimeOwnerRegistrationError::AdmissionClosed
    );
    assert_eq!(
        coordinator
            .register_reset_hook(
                NetworkResetHookStage::Inbound,
                Arc::new(RecordingHook {
                    label: "late",
                    events: Arc::new(Mutex::new(Vec::new())),
                }),
            )
            .unwrap_err(),
        NetworkResetHookRegistrationError::AdmissionClosed
    );

    let retried = coordinator.retry_reset().await.unwrap();
    assert_eq!(retried.outcome(), NetworkResetOutcome::ResetCompleted);
    assert_eq!(retried.published_generation(), 2);
    assert_eq!(hook.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(coordinator.status().state(), NetworkResetState::Active);
    assert!(coordinator.status().admission_open());
    drop(registration);
}

#[derive(Debug)]
struct PanickingHook;

impl ResetNetwork for PanickingHook {
    fn reset_network(&self, _snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_> {
        panic!("private injected hook detail")
    }
}

#[tokio::test]
async fn hook_panic_is_closed_redacted_and_retryable() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let registration = coordinator
        .register_reset_hook(NetworkResetHookStage::Router, Arc::new(PanickingHook))
        .unwrap();

    let error = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        NetworkResetCoordinatorError::HookPanicked(NetworkResetHookStage::Router)
    );
    assert!(!format!("{error:?}").contains("private injected hook detail"));
    assert_eq!(coordinator.status().state(), NetworkResetState::RetryReset);
    assert!(!coordinator.status().admission_open());

    drop(registration);
    assert_eq!(
        coordinator.retry_reset().await.unwrap().outcome(),
        NetworkResetOutcome::ResetCompleted
    );
}

#[tokio::test]
async fn runtime_owners_cancel_and_acknowledge_in_generation_tcp_udp_order() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let mut acknowledgements = Vec::new();

    for kind in [
        NetworkRuntimeOwnerKind::GenerationTask,
        NetworkRuntimeOwnerKind::TcpConnection,
        NetworkRuntimeOwnerKind::UdpAssociation,
    ] {
        let mut owner = coordinator.register_runtime_owner(1, kind).unwrap();
        let events = events_tx.clone();
        let (ack_tx, ack_rx) = oneshot::channel();
        acknowledgements.push(ack_tx);
        tokio::spawn(async move {
            let cancellation = owner.cancelled().await;
            events.send((kind, cancellation)).expect("event receiver");
            let _ = ack_rx.await;
            drop(owner);
        });
    }
    drop(events_tx);

    let reset = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .reset_network(
                    snapshot(2),
                    NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest),
                )
                .await
        })
    };

    for (position, expected_kind) in [
        NetworkRuntimeOwnerKind::GenerationTask,
        NetworkRuntimeOwnerKind::TcpConnection,
        NetworkRuntimeOwnerKind::UdpAssociation,
    ]
    .into_iter()
    .enumerate()
    {
        let (kind, cancellation) = events_rx.recv().await.expect("cancellation event");
        assert_eq!(kind, expected_kind);
        let NetworkRuntimeOwnerCancellation::Reset(signal) = cancellation else {
            panic!("coordinator remained alive");
        };
        assert_eq!(signal.target_generation(), 2);
        assert_eq!(
            signal.intent(),
            NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest)
        );
        assert!(events_rx.try_recv().is_err(), "next stage waits for ack");
        acknowledgements.remove(0).send(()).expect("owner waits");
        if position != 2 {
            tokio::task::yield_now().await;
        }
    }

    let report = reset.await.unwrap().unwrap();
    assert_eq!(report.cancelled_runtime_owners(), 3);
    assert_eq!(report.outcome(), NetworkResetOutcome::ResetCompleted);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(owners.snapshot().network_reset_drivers, 0);
}

#[derive(Debug)]
struct PendingHookState {
    blocked: AtomicBool,
    polled: AtomicUsize,
    live_waiters: AtomicUsize,
    stored_waker: Mutex<Option<Waker>>,
}

#[derive(Debug)]
struct PendingHook {
    state: Arc<PendingHookState>,
}

impl ResetNetwork for PendingHook {
    fn reset_network(&self, _snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_> {
        Box::pin(PendingHookFuture {
            state: Arc::clone(&self.state),
            registered: false,
        })
    }
}

struct PendingHookFuture {
    state: Arc<PendingHookState>,
    registered: bool,
}

impl Future for PendingHookFuture {
    type Output = Result<(), NetworkResetError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.state.polled.fetch_add(1, Ordering::SeqCst);
        if !self.state.blocked.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        if !self.registered {
            self.registered = true;
            self.state.live_waiters.fetch_add(1, Ordering::SeqCst);
        }
        *self.state.stored_waker.lock().unwrap() = Some(context.waker().clone());
        Poll::Pending
    }
}

impl Drop for PendingHookFuture {
    fn drop(&mut self) {
        if self.registered {
            self.state.live_waiters.fetch_sub(1, Ordering::SeqCst);
        }
        self.state.stored_waker.lock().unwrap().take();
    }
}

#[tokio::test]
async fn cancelled_reset_drops_hook_waker_preserves_retry_and_returns_owner_baseline() {
    let owners = OwnerRegistry::new();
    let baseline = owners.snapshot();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let state = Arc::new(PendingHookState {
        blocked: AtomicBool::new(true),
        polled: AtomicUsize::new(0),
        live_waiters: AtomicUsize::new(0),
        stored_waker: Mutex::new(None),
    });
    let registration = coordinator
        .register_reset_hook(
            NetworkResetHookStage::Stack,
            Arc::new(PendingHook {
                state: Arc::clone(&state),
            }),
        )
        .unwrap();
    let task = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .reset_network(
                    snapshot(2),
                    NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
                )
                .await
        })
    };
    for _ in 0..1_000 {
        if state.live_waiters.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(state.live_waiters.load(Ordering::SeqCst), 1);
    assert!(state.stored_waker.lock().unwrap().is_some());
    assert_eq!(owners.snapshot().network_reset_drivers, 1);

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(state.live_waiters.load(Ordering::SeqCst), 0);
    assert!(state.stored_waker.lock().unwrap().is_none());
    assert_eq!(owners.snapshot().network_reset_drivers, 0);
    assert_eq!(coordinator.status().state(), NetworkResetState::RetryReset);
    assert!(!coordinator.status().admission_open());

    state.blocked.store(false, Ordering::SeqCst);
    let report = coordinator.retry_reset().await.unwrap();
    assert_eq!(report.outcome(), NetworkResetOutcome::ResetCompleted);
    assert!(state.polled.load(Ordering::SeqCst) >= 2);
    drop(registration);
    drop(coordinator);
    assert_eq!(owners.snapshot(), baseline);
}

#[tokio::test]
async fn full_rebuild_intent_closes_owners_skips_reset_hooks_and_requires_acknowledgement() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let events = Arc::new(Mutex::new(Vec::new()));
    let registration = coordinator
        .register_reset_hook(
            NetworkResetHookStage::Stack,
            Arc::new(RecordingHook {
                label: "ordinary-only",
                events: Arc::clone(&events),
            }),
        )
        .unwrap();
    let mut owner = coordinator
        .register_runtime_owner(1, NetworkRuntimeOwnerKind::TcpConnection)
        .unwrap();
    let owner_task = tokio::spawn(async move {
        let result = owner.cancelled().await;
        drop(owner);
        result
    });

    let report = coordinator
        .reset_network(
            snapshot(1),
            NetworkResetIntent::FullRebuild(ManagedNetworkDamage::AdapterInvalid),
        )
        .await
        .unwrap();
    assert_eq!(
        report.outcome(),
        NetworkResetOutcome::FullRebuildRequired(ManagedNetworkDamage::AdapterInvalid)
    );
    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert!(matches!(
        owner_task.await.unwrap(),
        NetworkRuntimeOwnerCancellation::Reset(_)
    ));
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(
        coordinator.status().state(),
        NetworkResetState::ManagedDamaged
    );
    assert!(!coordinator.status().admission_open());
    assert_eq!(
        coordinator.acknowledge_full_rebuild(snapshot(0)).await,
        Err(NetworkResetCoordinatorError::FullRebuildGenerationTooOld)
    );

    let acknowledged = coordinator
        .acknowledge_full_rebuild(snapshot(2))
        .await
        .unwrap();
    assert_eq!(
        acknowledged.outcome(),
        NetworkResetOutcome::FullRebuildAcknowledged
    );
    assert_eq!(coordinator.status().published_generation(), 2);
    assert!(coordinator.status().admission_open());
    drop(registration);
}

#[tokio::test]
async fn dropping_coordinator_wakes_runtime_owner_without_extending_coordinator_lifetime() {
    let owners = OwnerRegistry::new();
    let baseline = owners.snapshot();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let mut owner = coordinator
        .register_runtime_owner(1, NetworkRuntimeOwnerKind::GenerationTask)
        .unwrap();
    drop(coordinator);
    assert_eq!(
        owner.cancelled().await,
        NetworkRuntimeOwnerCancellation::CoordinatorDropped
    );
    drop(owner);
    assert_eq!(owners.snapshot(), baseline);
}

#[tokio::test]
async fn one_thousand_resets_reuse_bounded_owners_and_return_to_baseline() {
    let owners = OwnerRegistry::new();
    let baseline = owners.snapshot();
    let coordinator = coordinator(1, NetworkResetLimits::default(), &owners);
    let events = Arc::new(Mutex::new(Vec::new()));
    let registration = coordinator
        .register_reset_hook(
            NetworkResetHookStage::Stack,
            Arc::new(RecordingHook {
                label: "stack",
                events: Arc::clone(&events),
            }),
        )
        .unwrap();
    let steady = owners.snapshot();

    for generation in 2..=1_001 {
        let report = coordinator
            .reset_network(
                snapshot(generation),
                NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest),
            )
            .await
            .unwrap();
        assert_eq!(report.completed_resets(), 1);
        assert_eq!(owners.snapshot(), steady);
    }
    assert_eq!(events.lock().unwrap().len(), 1_000);
    assert_eq!(coordinator.status().published_generation(), 1_001);
    drop(registration);
    drop(coordinator);
    assert_eq!(owners.snapshot(), baseline);
}
