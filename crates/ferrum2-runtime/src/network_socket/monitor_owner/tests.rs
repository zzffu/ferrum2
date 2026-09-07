use super::*;

#[tokio::test]
async fn notification_before_join_readiness_retains_the_slot_for_retry() {
    let owners = OwnerRegistry::new();
    let (registrar, mut owner) =
        NetworkSocketOwner::new(NonZeroUsize::new(1).unwrap(), owners.clone());
    let reservation = registrar.reserve().unwrap();
    let (resume, pending) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        pending.await.unwrap();
        Ok(())
    });
    let task = Arc::new(TrackedTask::new(
        join,
        reservation.accounting,
        reservation.stop,
        Arc::clone(&owner.shared.failure),
    ));
    lock(&owner.shared.state).monitors.insert(
        0,
        MonitorRecord {
            generation: 1,
            task,
        },
    );
    // Model the scheduler boundary after completion notification but before the
    // JoinHandle becomes ready. A notification alone must not release admission.
    owner.shared.completed.try_send(0).unwrap();
    assert!(matches!(
        registrar.reserve(),
        Err(NetworkSocketOwnerError::Busy)
    ));
    assert!(matches!(
        registrar.reserve(),
        Err(NetworkSocketOwnerError::Busy)
    ));
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    resume.send(()).unwrap();
    tokio::task::yield_now().await;
    let next = registrar.reserve().unwrap();
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    drop(next);
    owner.shutdown().await.unwrap();
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
}

#[tokio::test]
async fn abort_before_first_poll_still_enqueues_completion_and_reports_failed_join() {
    let owners = OwnerRegistry::new();
    let (registrar, mut owner) =
        NetworkSocketOwner::new(NonZeroUsize::new(1).unwrap(), owners.clone());
    registrar
        .reserve()
        .unwrap()
        .spawn(1, std::future::pending())
        .unwrap();
    let task = Arc::clone(&lock(&owner.shared.state).monitors.get(&0).unwrap().task);
    task.task.lock().await.as_ref().unwrap().join.abort();
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    tokio::task::yield_now().await;
    assert!(matches!(
        registrar.reserve(),
        Err(NetworkSocketOwnerError::WorkerFailed)
    ));
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
    assert_eq!(
        owner.shutdown().await,
        Err(NetworkSocketOwnerError::WorkerFailed)
    );
}
