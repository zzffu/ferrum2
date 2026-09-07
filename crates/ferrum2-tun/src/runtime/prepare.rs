use std::time::Instant;

use ferrum2_runtime::ProcessCancellation;

use super::{LifecycleEvent, NativeLifecycleOwner, NetworkResetBridgeOutcome};
use crate::process::NetworkLifecycleHandler;
use crate::{OwnerWake, TunNetworkResetError};

pub(crate) enum PreparationFailure {
    Stopped,
    Failed,
}

impl NativeLifecycleOwner {
    pub(crate) async fn prepare(
        &self,
        handler: &NetworkLifecycleHandler,
        mut cancellation: ProcessCancellation,
        deadline: Instant,
    ) -> Result<OwnerWake, PreparationFailure> {
        loop {
            let event = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(PreparationFailure::Stopped),
                () = tokio::time::sleep_until(deadline.into()) => return Err(PreparationFailure::Failed),
                event = self.link.receive() => event,
            };
            match event {
                Some(LifecycleEvent::Request(request)) => {
                    let outcome = tokio::select! {
                        biased;
                        () = cancellation.cancelled() => NetworkResetBridgeOutcome::Stopped,
                        () = tokio::time::sleep_until(deadline.into()) => NetworkResetBridgeOutcome::Stopped,
                        result = handler(request.snapshot, request.lifecycle) => match result {
                            Ok(()) if Instant::now() < deadline => NetworkResetBridgeOutcome::Completed,
                            Ok(()) => NetworkResetBridgeOutcome::Stopped,
                            Err(TunNetworkResetError) => NetworkResetBridgeOutcome::Retry,
                        },
                    };
                    request.completion.complete(outcome);
                    if outcome != NetworkResetBridgeOutcome::Completed {
                        return Err(if cancellation.is_cancelled() {
                            PreparationFailure::Stopped
                        } else {
                            PreparationFailure::Failed
                        });
                    }
                }
                Some(LifecycleEvent::Prepared(work)) => {
                    if cancellation.is_cancelled() {
                        return Err(PreparationFailure::Stopped);
                    }
                    if Instant::now() >= deadline {
                        return Err(PreparationFailure::Failed);
                    }
                    return Ok(work);
                }
                None => return Err(PreparationFailure::Failed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnerControl, OwnerExit, TunNetworkLifecycle, TunRoot};
    use ferrum2_net::NetworkSnapshot;
    use ferrum2_runtime::{OwnerRegistry, ProcessRoot, ProcessSupervisor};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn initialization_and_prepared_share_one_deadline_and_cleanup_failure_wins() {
        for stall_callback in [false, true] {
            let root = ProcessRoot::new_cancellable(move |cancellation| async move {
                let (owner, done) = NativeLifecycleOwner::spawn(
                    OwnerControl::new(),
                    Box::new(move |link, _| {
                        let outcome = link.request(
                            Arc::new(NetworkSnapshot::new(1, None, None).unwrap()),
                            TunNetworkLifecycle::Initialize,
                        );
                        if !stall_callback {
                            assert_eq!(outcome, NetworkResetBridgeOutcome::Completed);
                            std::thread::sleep(Duration::from_millis(500));
                            link.prepared(OwnerWake::default());
                        } else {
                            assert_eq!(outcome, NetworkResetBridgeOutcome::Stopped);
                        }
                        OwnerExit::CleanupFailed
                    }),
                )
                .unwrap();
                let handler: NetworkLifecycleHandler = Arc::new(move |_, _| {
                    Box::pin(async move {
                        if stall_callback {
                            std::future::pending::<()>().await;
                        }
                        Ok(())
                    })
                });
                let result = owner
                    .prepare(
                        &handler,
                        cancellation,
                        Instant::now() + Duration::from_millis(300),
                    )
                    .await;
                assert!(matches!(result, Err(PreparationFailure::Failed)));
                assert_eq!(owner.reap().await, OwnerExit::CleanupFailed);
                assert_eq!(done.await.unwrap(), OwnerExit::CleanupFailed);
                Err::<Option<TunRoot<&'static str>>, _>("cleanup")
            });
            let report =
                ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
                    .unwrap()
                    .run_until(std::future::pending::<()>())
                    .await;
            assert!(matches!(
                report.cause(),
                ferrum2_runtime::ProcessCause::PreparationFailed {
                    error: "cleanup",
                    ..
                }
            ));
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_preparation_during_callback_closes_and_joins_native_job() {
        let root = ProcessRoot::new_cancellable(move |cancellation| async move {
            let (entered, entering) = tokio::sync::oneshot::channel();
            let entered = std::sync::Mutex::new(Some(entered));
            let (owner, done) = NativeLifecycleOwner::spawn(
                OwnerControl::new(),
                Box::new(|link, _| {
                    assert_eq!(
                        link.request(
                            Arc::new(NetworkSnapshot::new(1, None, None).unwrap()),
                            TunNetworkLifecycle::Initialize
                        ),
                        NetworkResetBridgeOutcome::Stopped
                    );
                    OwnerExit::CleanupFailed
                }),
            )
            .unwrap();
            let handler: NetworkLifecycleHandler = Arc::new(move |_, _| {
                let _ = entered.lock().unwrap().take().unwrap().send(());
                Box::pin(std::future::pending())
            });
            let task = tokio::spawn(async move {
                let _ = owner
                    .prepare(
                        &handler,
                        cancellation,
                        Instant::now() + Duration::from_secs(2),
                    )
                    .await;
                owner.reap().await
            });
            entering.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(done.await.unwrap(), OwnerExit::CleanupFailed);
            Err::<Option<TunRoot<&'static str>>, _>("cleanup")
        });
        ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
            .unwrap()
            .run_until(std::future::pending::<()>())
            .await;
    }

    #[tokio::test]
    async fn native_prepared_is_required_before_success_and_panic_closes_preparation() {
        for panic_native in [false, true] {
            let root = ProcessRoot::new_cancellable(move |cancellation| async move {
                let (owner, done) = NativeLifecycleOwner::spawn(
                    OwnerControl::new(),
                    Box::new(move |link, _| {
                        assert!(!panic_native, "injected native panic");
                        assert_eq!(
                            link.request(
                                Arc::new(NetworkSnapshot::new(1, None, None).unwrap()),
                                TunNetworkLifecycle::Initialize
                            ),
                            NetworkResetBridgeOutcome::Completed
                        );
                        link.prepared(OwnerWake::default());
                        assert_eq!(
                            link.request(
                                Arc::new(NetworkSnapshot::new(1, None, None).unwrap()),
                                TunNetworkLifecycle::Initialize
                            ),
                            NetworkResetBridgeOutcome::Stopped
                        );
                        OwnerExit::Stopped
                    }),
                )
                .unwrap();
                let handler: NetworkLifecycleHandler = Arc::new(|_, _| Box::pin(async { Ok(()) }));
                let result = owner
                    .prepare(
                        &handler,
                        cancellation,
                        Instant::now() + Duration::from_secs(2),
                    )
                    .await;
                assert_eq!(result.is_ok(), !panic_native);
                let expected = if panic_native {
                    OwnerExit::CleanupFailed
                } else {
                    OwnerExit::Stopped
                };
                assert_eq!(owner.reap().await, expected);
                assert_eq!(done.await.unwrap(), expected);
                Err::<Option<TunRoot<&'static str>>, _>("test complete")
            });
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
                .unwrap()
                .run_until(std::future::pending::<()>())
                .await;
        }
    }
}
