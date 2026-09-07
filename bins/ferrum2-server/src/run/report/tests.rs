use super::*;
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

enum TestRoot {
    RollbackFailure,
    RunFailure,
}

impl PreparedProcessRoot<RunError> for TestRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }
    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            match *self {
                Self::RollbackFailure => {
                    cancellation.cancelled().await;
                    Ok(())
                }
                Self::RunFailure => Err(RunError::RuntimeListener),
            }
        })
    }
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            match *self {
                Self::RollbackFailure => Err(RunError::ShutdownCleanup),
                Self::RunFailure => Ok(()),
            }
        })
    }
}

#[tokio::test]
async fn later_endpoint_failure_keeps_root_identity_and_every_cleanup_failure() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let listener = RootDescriptor {
        role: RootRole::TcpInbound,
        declaration_index: Some(2),
    };
    let rules = RootDescriptor {
        #[cfg(windows)]
        role: RootRole::Network,
        #[cfg(not(windows))]
        role: RootRole::Rules,
        declaration_index: None,
    };
    let acquisition = super::super::error::EndpointAcquireError::new(
        super::super::error::EndpointAcquireStage::Bind,
        std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "private injected address and key",
        ),
    );
    let mut roots = ServerRoots::with_capacity(2);
    roots.push(
        listener,
        ProcessRoot::new_cancellable(move |_| async move {
            Err::<Option<TestRoot>, _>(RunError::StartupBind {
                descriptor: listener,
                acquisition,
            })
        }),
    );
    roots.prepend(
        rules,
        ProcessRoot::new(|| async { Ok(TestRoot::RollbackFailure) }),
    );
    let error = roots
        .run_until(
            Duration::from_secs(1),
            registry.clone(),
            ProcessResources {
                baseline,
                cleanup: Box::pin(async { Err(RunError::ShutdownCleanup) }),
            },
            std::future::pending(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RunError::ProcessFailure(Box::new(ServerRunFailure {
            primary: Some(RootFailure {
                descriptor: listener,
                phase: "prepare",
                category: "startup.bind",
                acquisition: Some(acquisition)
            }),
            cleanup: vec![
                CleanupDiagnostic {
                    kind: "root_failed",
                    root: Some(rules),
                    error: Some("shutdown.cleanup")
                },
                CleanupDiagnostic {
                    kind: "final_failed",
                    root: None,
                    error: Some("shutdown.cleanup")
                },
            ],
        }))
    );
    let mut stopped = baseline;
    stopped.process_root_rollbacks = 1;
    assert_eq!(registry.snapshot(), stopped);
    let text = format!("{error} {error:?}");
    assert!(!text.contains("private injected"));
    assert!(text.contains("root=tcp_inbound[2] phase=prepare cause=startup.bind"));
    assert!(text.contains(&format!("cleanup_root={rules}")));
}

#[tokio::test]
async fn active_root_failure_keeps_run_phase_after_successful_reaping() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let descriptor = RootDescriptor {
        role: RootRole::Dns,
        declaration_index: None,
    };
    let mut roots = ServerRoots::with_capacity(1);
    roots.push(
        descriptor,
        ProcessRoot::new(|| async { Ok(TestRoot::RunFailure) }),
    );
    let error = roots
        .run_until(
            Duration::from_secs(1),
            registry.clone(),
            ProcessResources {
                baseline,
                cleanup: Box::pin(async { Ok(()) }),
            },
            std::future::pending(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RunError::ProcessFailure(Box::new(ServerRunFailure {
            primary: Some(RootFailure {
                descriptor,
                phase: "run",
                category: "runtime.listener",
                acquisition: None
            }),
            cleanup: Vec::new(),
        }))
    );
    let mut stopped = baseline;
    stopped.process_root_reaps = 1;
    assert_eq!(registry.snapshot(), stopped);
}
