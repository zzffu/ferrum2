use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
    ProcessSupervisor,
};

use super::*;
use crate::run::{ClientProcessRoots, report_result};

#[derive(Clone, Copy, Debug)]
enum DiagnosticTestRun {
    AwaitCancellation,
    AwaitForce,
    Fail(RunError),
}

#[derive(Debug)]
struct DiagnosticTestRoot {
    run: DiagnosticTestRun,
    quiescing_observed: Option<Arc<AtomicBool>>,
}

impl PreparedProcessRoot<RunError> for DiagnosticTestRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            match self.run {
                DiagnosticTestRun::AwaitCancellation => {
                    cancellation.cancelled().await;
                    if let Some(observed) = &self.quiescing_observed {
                        observed.store(true, Ordering::Release);
                    }
                    Ok(())
                }
                DiagnosticTestRun::AwaitForce => {
                    cancellation.cancelled().await;
                    if let Some(observed) = &self.quiescing_observed {
                        observed.store(true, Ordering::Release);
                    }
                    cancellation.forced().await;
                    Ok(())
                }
                DiagnosticTestRun::Fail(error) => Err(error),
            }
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

fn diagnostic_test_root(run: DiagnosticTestRun) -> ProcessRoot<RunError> {
    diagnostic_test_root_with_quiescing_observer(run, None)
}

fn diagnostic_test_root_with_quiescing_observer(
    run: DiagnosticTestRun,
    quiescing_observed: Option<Arc<AtomicBool>>,
) -> ProcessRoot<RunError> {
    ProcessRoot::new(move || async move {
        Ok(DiagnosticTestRoot {
            run,
            quiescing_observed,
        })
    })
}

async fn named_failure_report(
    failing_root: usize,
) -> (
    ProcessReport<RunError>,
    ClientRootNames,
    OwnerSnapshot,
    OwnerSnapshot,
) {
    let mut roots = ClientProcessRoots::default();
    for (index, name) in [
        ClientRootName::Socks,
        ClientRootName::Dns,
        ClientRootName::Metrics,
        ClientRootName::Tun,
    ]
    .into_iter()
    .enumerate()
    {
        let run = if index == failing_root {
            DiagnosticTestRun::Fail(RunError::RuntimeListener)
        } else {
            DiagnosticTestRun::AwaitCancellation
        };
        roots.push(name, diagnostic_test_root(run));
    }
    let (roots, names) = roots.into_parts();
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let report = ProcessSupervisor::new(roots, Duration::from_secs(1), registry.clone())
        .expect("four diagnostic roots")
        .run_until(std::future::pending::<()>())
        .await;
    let stopped = registry.snapshot();
    (report, names, baseline, stopped)
}

fn parse_shutdown_diagnostic(diagnostic: &ShutdownDiagnostic) -> serde_json::Value {
    serde_json::from_str(&diagnostic.to_string()).expect("valid closed shutdown diagnostic JSON")
}

fn transition_elapsed_ns(document: &serde_json::Value, state: &str) -> u64 {
    document["process_transitions"]
        .as_array()
        .expect("process transition array")
        .iter()
        .find(|transition| transition["state"] == state)
        .and_then(|transition| transition["elapsed_ns"].as_u64())
        .unwrap_or_else(|| panic!("missing {state} transition"))
}

fn diagnostic_with_cleanup(
    cleanup_failure: CleanupDiagnostic,
    owner_baseline: OwnerSnapshot,
    owner_stopped: OwnerSnapshot,
) -> ShutdownDiagnostic {
    ShutdownDiagnostic {
        states: vec![ProcessState::Stopped],
        transitions: vec![DiagnosticTransition {
            state: ProcessState::Stopped,
            elapsed_ns: 1,
        }],
        root_exit_events: Vec::new(),
        shutdown_grace_ns: 0,
        actual_grace_deadline_elapsed_ns: None,
        termination_cause: TerminationCauseKind::ExternalShutdown,
        root: None,
        root_exit_category: None,
        root_error_category: None,
        forced_root_count: 0,
        owner_baseline,
        owner_stopped,
        owner_delta: OwnerDelta::between(owner_baseline, owner_stopped),
        cleanup_failure: Some(cleanup_failure),
    }
}

#[test]
fn root_exit_event_schema_uses_closed_phase_and_category_sets() {
    assert_eq!(
        [
            ProcessRootEventPhase::Active,
            ProcessRootEventPhase::Draining,
            ProcessRootEventPhase::Forced,
            ProcessRootEventPhase::WatchdogAbort,
        ]
        .map(process_root_event_phase_name),
        ["Active", "Draining", "Forced", "WatchdogAbort"]
    );
    assert_eq!(
        [
            ProcessRootExitCategory::Completed,
            ProcessRootExitCategory::Failed,
            ProcessRootExitCategory::Panicked,
            ProcessRootExitCategory::JoinFailed,
            ProcessRootExitCategory::Aborted,
        ]
        .map(process_root_exit_category_name),
        ["Completed", "Failed", "Panicked", "JoinFailed", "Aborted"]
    );
}

#[tokio::test]
async fn shutdown_diagnostic_uses_composed_stable_root_names_and_preserves_result_mapping() {
    let expected_names = [
        ClientRootName::Socks,
        ClientRootName::Dns,
        ClientRootName::Metrics,
        ClientRootName::Tun,
    ];
    for (index, expected_name) in expected_names.into_iter().enumerate() {
        let (report, names, baseline, stopped) = named_failure_report(index).await;
        let actual_grace_deadline_elapsed_ns = report
            .grace_deadline_elapsed()
            .expect("active process shutdown creates a grace deadline")
            .as_nanos();
        let diagnostic = ShutdownDiagnostic::classify(
            &report,
            &names,
            Duration::from_secs(1),
            baseline,
            stopped,
        );

        assert_eq!(
            diagnostic.states,
            [
                ProcessState::Validated,
                ProcessState::Preparing,
                ProcessState::Prepared,
                ProcessState::Active,
                ProcessState::Fatal,
                ProcessState::Quiescing,
                ProcessState::Draining,
                ProcessState::Stopped,
            ]
        );
        assert_eq!(
            diagnostic.termination_cause,
            TerminationCauseKind::RootStopped
        );
        assert_eq!(
            diagnostic.root,
            Some(DiagnosticRoot {
                id: index,
                name: expected_name,
            })
        );
        assert_eq!(
            diagnostic.root_exit_category,
            Some(RootExitCategory::Failed)
        );
        assert_eq!(
            diagnostic.root_error_category,
            Some(RunError::RuntimeListener)
        );
        assert_eq!(diagnostic.forced_root_count, 0);
        assert!(diagnostic.cleanup_failure.is_none());
        let document = parse_shutdown_diagnostic(&diagnostic);
        assert_eq!(document["event"], "process_shutdown_report");
        assert_eq!(document["role"], "client");
        assert_eq!(document["root"]["name"], expected_name.as_str());
        assert_eq!(document["root"]["id"], index);
        assert_eq!(document["root_exit_category"], "Failed");
        assert_eq!(document["root_error_category"], "runtime.listener");
        let root_events = document["root_exit_events"]
            .as_array()
            .expect("root exit event array");
        assert_eq!(root_events.len(), 4);
        assert_eq!(root_events[0]["root"]["name"], expected_name.as_str());
        assert_eq!(root_events[0]["root"]["id"], index);
        assert_eq!(root_events[0]["phase"], "Active");
        assert_eq!(root_events[0]["exit_category"], "Failed");
        assert!(root_events[0].get("error").is_none());
        assert_eq!(
            root_events
                .iter()
                .map(|event| event["root"]["name"].as_str().expect("stable root name"))
                .collect::<std::collections::BTreeSet<_>>(),
            ["dns", "metrics", "socks", "tun"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        assert_eq!(document["shutdown_grace_ns"], 1_000_000_000_u64);
        assert_eq!(
            document["actual_grace_deadline_elapsed_ns"].as_u64(),
            Some(
                u64::try_from(actual_grace_deadline_elapsed_ns)
                    .expect("test deadline fits JSON integer"),
            )
        );
        assert_eq!(
            document["actual_grace_deadline_source"],
            "runtime_process_supervisor"
        );
        assert!(document["owner_baseline"].is_object());
        assert!(document["owner_stopped"].is_object());
        assert!(document["owner_delta"].is_object());
        assert!(document["cleanup_failure"].is_null());
        assert_eq!(report_result(report), Err(RunError::RuntimeListener));
    }
}

#[tokio::test]
async fn shutdown_cleanup_diagnostic_serializes_all_closed_kinds_and_owner_delta() {
    let (report, names, _, _) = named_failure_report(2).await;
    let root = match report.cause() {
        ProcessCause::RootStopped { root, .. } => *root,
        cause => panic!("unexpected test cause: {cause:?}"),
    };
    let expected_root = DiagnosticRoot {
        id: 2,
        name: ClientRootName::Metrics,
    };

    let root_failed = CleanupDiagnostic::classify(
        &ProcessCleanupFailure::RootFailed {
            root,
            error: RunError::RuntimeChild,
        },
        &names,
    );
    assert_eq!(root_failed.kind, CleanupFailureKind::RootFailed);
    assert_eq!(root_failed.root, Some(expected_root));
    assert_eq!(root_failed.error_category, Some(RunError::RuntimeChild));

    let root_panicked =
        CleanupDiagnostic::classify(&ProcessCleanupFailure::RootPanicked { root }, &names);
    assert_eq!(root_panicked.kind, CleanupFailureKind::RootPanicked);
    assert_eq!(root_panicked.root, Some(expected_root));

    let root_join_failed =
        CleanupDiagnostic::classify(&ProcessCleanupFailure::RootJoinFailed { root }, &names);
    assert_eq!(root_join_failed.kind, CleanupFailureKind::RootJoinFailed);
    assert_eq!(root_join_failed.root, Some(expected_root));

    let force_reap_timed_out = CleanupDiagnostic::classify(
        &ProcessCleanupFailure::ForceReapTimedOut {
            roots: vec![root],
            prior: Some(Box::new(ProcessCleanupFailure::RootPanicked { root })),
        },
        &names,
    );
    assert_eq!(
        force_reap_timed_out.kind,
        CleanupFailureKind::ForceReapTimedOut
    );
    assert_eq!(force_reap_timed_out.roots, [expected_root]);
    assert_eq!(
        force_reap_timed_out
            .prior
            .as_deref()
            .map(|prior| (prior.kind, prior.root)),
        Some((CleanupFailureKind::RootPanicked, Some(expected_root)))
    );

    let baseline = OwnerSnapshot {
        active_process_roots: 1,
        process_root_reaps: 4,
        active_tun_tcp_flows: 1,
        active_tun_handler_tasks: 2,
        listeners: 2,
        ..OwnerSnapshot::default()
    };
    let stopped = OwnerSnapshot {
        process_root_reaps: 5,
        listeners: 1,
        ..OwnerSnapshot::default()
    };
    let owner_mismatch = CleanupDiagnostic::classify(
        &ProcessCleanupFailure::OwnerMismatch {
            baseline: Box::new(baseline),
            stopped: Box::new(stopped),
        },
        &names,
    );
    assert_eq!(owner_mismatch.kind, CleanupFailureKind::OwnerMismatch);
    assert_eq!(owner_mismatch.owner_baseline, Some(baseline));
    assert_eq!(owner_mismatch.owner_stopped, Some(stopped));
    let delta = owner_mismatch.owner_delta.expect("owner mismatch delta");
    assert_eq!(delta.active_process_roots, -1);
    assert_eq!(delta.process_root_reaps, 1);
    assert_eq!(delta.active_tun_tcp_flows, -1);
    assert_eq!(delta.active_tun_handler_tasks, -2);
    assert_eq!(delta.listeners, -1);
    assert_eq!(delta, OwnerDelta::between(baseline, stopped));

    let cases = [
        ("RootFailed", root_failed),
        ("RootPanicked", root_panicked),
        ("RootJoinFailed", root_join_failed),
        ("ForceReapTimedOut", force_reap_timed_out),
        ("OwnerMismatch", owner_mismatch),
    ];
    for (expected_kind, cleanup) in cases {
        let document = parse_shutdown_diagnostic(&diagnostic_with_cleanup(
            cleanup,
            OwnerSnapshot::default(),
            OwnerSnapshot::default(),
        ));
        assert_eq!(document["cleanup_failure"]["kind"], expected_kind);
        assert!(document["actual_grace_deadline_elapsed_ns"].is_null());
        assert!(document["actual_grace_deadline_source"].is_null());
        assert!(document["owner_baseline"].is_object());
        assert!(document["owner_stopped"].is_object());
        assert!(document["owner_delta"].is_object());
        match expected_kind {
            "RootFailed" => {
                assert_eq!(document["cleanup_failure"]["root"]["name"], "metrics");
                assert_eq!(document["cleanup_failure"]["root"]["id"], 2);
                assert_eq!(
                    document["cleanup_failure"]["root_error_category"],
                    "runtime.child"
                );
            }
            "RootPanicked" | "RootJoinFailed" => {
                assert_eq!(document["cleanup_failure"]["root"]["name"], "metrics");
                assert_eq!(document["cleanup_failure"]["root"]["id"], 2);
            }
            "ForceReapTimedOut" => {
                assert_eq!(document["cleanup_failure"]["roots"][0]["name"], "metrics");
                assert_eq!(document["cleanup_failure"]["roots"][0]["id"], 2);
                assert_eq!(document["cleanup_failure"]["prior"]["kind"], "RootPanicked");
            }
            "OwnerMismatch" => {
                assert!(document["cleanup_failure"]["owner_baseline"].is_object());
                assert!(document["cleanup_failure"]["owner_stopped"].is_object());
                assert!(document["cleanup_failure"]["owner_delta"].is_object());
            }
            _ => unreachable!("closed cleanup kind"),
        }
    }

    let owner_document = parse_shutdown_diagnostic(&diagnostic_with_cleanup(
        CleanupDiagnostic::classify(
            &ProcessCleanupFailure::OwnerMismatch {
                baseline: Box::new(baseline),
                stopped: Box::new(stopped),
            },
            &names,
        ),
        baseline,
        stopped,
    ));
    assert_eq!(
        owner_document["cleanup_failure"]["owner_delta"]["active_process_roots"],
        -1
    );
    assert_eq!(
        owner_document["cleanup_failure"]["owner_delta"]["active_tun_tcp_flows"],
        -1
    );
    assert_eq!(
        owner_document["cleanup_failure"]["owner_delta"]["active_tun_handler_tasks"],
        -2
    );
    assert_eq!(owner_document["owner_delta"]["active_tun_tcp_flows"], -1);
    assert_eq!(
        owner_document["owner_delta"]["active_tun_handler_tasks"],
        -2
    );
}

#[tokio::test]
async fn graceful_external_shutdown_has_timeline_and_top_level_owner_triplet() {
    let registry = OwnerRegistry::new();
    let mut roots = ClientProcessRoots::default();
    roots.push(
        ClientRootName::Tun,
        diagnostic_test_root(DiagnosticTestRun::AwaitCancellation),
    );
    let (roots, names) = roots.into_parts();
    let baseline = registry.snapshot();
    let supervisor = ProcessSupervisor::new(roots, Duration::from_secs(2), registry.clone())
        .expect("graceful diagnostic root");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_receiver.await;
    }));
    for _ in 0..100 {
        if registry.snapshot().active_process_roots == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.snapshot().active_process_roots, 1);

    shutdown_sender.send(()).expect("request graceful shutdown");
    let report = task.await.expect("graceful process report");
    let actual_grace_deadline_elapsed_ns = report
        .grace_deadline_elapsed()
        .expect("active process shutdown creates a grace deadline")
        .as_nanos();
    let stopped = registry.snapshot();
    let diagnostic =
        ShutdownDiagnostic::classify(&report, &names, Duration::from_secs(2), baseline, stopped);
    let document = parse_shutdown_diagnostic(&diagnostic);

    assert_eq!(document["termination_cause"], "ExternalShutdown");
    assert_eq!(document["forced_root_count"], 0);
    assert!(document["cleanup_failure"].is_null());
    assert_eq!(
        document["root_exit_events"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(document["root_exit_events"][0]["root"]["name"], "tun");
    assert_eq!(document["root_exit_events"][0]["root"]["id"], 0);
    assert_eq!(document["root_exit_events"][0]["phase"], "Draining");
    assert_eq!(
        document["root_exit_events"][0]["exit_category"],
        "Completed"
    );
    assert_eq!(document["shutdown_grace_ns"], 2_000_000_000_u64);
    assert_eq!(
        document["actual_grace_deadline_elapsed_ns"].as_u64(),
        Some(
            u64::try_from(actual_grace_deadline_elapsed_ns)
                .expect("test deadline fits JSON integer"),
        )
    );
    assert_eq!(
        document["actual_grace_deadline_source"],
        "runtime_process_supervisor"
    );
    assert_eq!(document["owner_baseline"]["active_process_roots"], 0);
    assert_eq!(document["owner_stopped"]["active_process_roots"], 0);
    assert_eq!(document["owner_delta"]["active_process_roots"], 0);
    assert_eq!(document["owner_delta"]["process_root_reaps"], 1);
    assert_eq!(document["owner_delta"]["active_tun_tcp_flows"], 0);
    assert_eq!(document["owner_delta"]["active_tun_handler_tasks"], 0);
    assert_eq!(report_result(report), Ok(()));
}

#[tokio::test(start_paused = true)]
async fn forced_shutdown_diagnostic_reports_timeline_owner_triplet_and_success() {
    let registry = OwnerRegistry::new();
    let quiescing_observed = Arc::new(AtomicBool::new(false));
    let mut roots = ClientProcessRoots::default();
    roots.push(
        ClientRootName::Tun,
        diagnostic_test_root_with_quiescing_observer(
            DiagnosticTestRun::AwaitForce,
            Some(Arc::clone(&quiescing_observed)),
        ),
    );
    let (roots, names) = roots.into_parts();
    let baseline = registry.snapshot();
    let supervisor = ProcessSupervisor::new(roots, Duration::from_secs(5), registry.clone())
        .expect("forced diagnostic root");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_receiver.await;
    }));
    for _ in 0..100 {
        if registry.snapshot().active_process_roots == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.snapshot().active_process_roots, 1);

    shutdown_sender.send(()).expect("request forced shutdown");
    for _ in 0..100 {
        if quiescing_observed.load(Ordering::Acquire) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        quiescing_observed.load(Ordering::Acquire),
        "the fake root observes quiescing before paused time advances",
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    let report = task.await.expect("forced process report");
    let stopped = registry.snapshot();
    let diagnostic =
        ShutdownDiagnostic::classify(&report, &names, Duration::from_secs(5), baseline, stopped);
    let document = parse_shutdown_diagnostic(&diagnostic);

    assert_eq!(
        diagnostic.termination_cause,
        TerminationCauseKind::ExternalShutdown
    );
    assert_eq!(diagnostic.forced_root_count, 1);
    assert!(diagnostic.states.contains(&ProcessState::Forced));
    assert!(diagnostic.cleanup_failure.is_none());
    let quiescing_ns = transition_elapsed_ns(&document, "Quiescing");
    let forced_ns = transition_elapsed_ns(&document, "Forced");
    assert_eq!(quiescing_ns, 0);
    assert_eq!(document["shutdown_grace_ns"], 5_000_000_000_u64);
    assert_eq!(
        document["actual_grace_deadline_elapsed_ns"].as_u64(),
        Some(5_000_000_000)
    );
    assert_eq!(
        document["actual_grace_deadline_source"],
        "runtime_process_supervisor"
    );
    assert!(forced_ns >= 5_000_000_000);
    assert_eq!(
        document["root_exit_events"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(document["root_exit_events"][0]["root"]["name"], "tun");
    assert_eq!(document["root_exit_events"][0]["root"]["id"], 0);
    assert_eq!(document["root_exit_events"][0]["phase"], "Forced");
    assert_eq!(
        document["root_exit_events"][0]["exit_category"],
        "Completed"
    );
    assert!(
        document["root_exit_events"][0]["elapsed_ns"]
            .as_u64()
            .is_some_and(|elapsed| elapsed >= 5_000_000_000)
    );
    assert_eq!(document["owner_baseline"]["active_process_roots"], 0);
    assert_eq!(document["owner_stopped"]["active_process_roots"], 0);
    assert_eq!(document["owner_delta"]["active_process_roots"], 0);
    assert_eq!(document["owner_delta"]["process_forced_roots"], 1);
    assert_eq!(document["owner_delta"]["process_root_reaps"], 1);
    assert_eq!(document["owner_delta"]["active_tun_tcp_flows"], 0);
    assert_eq!(document["owner_delta"]["active_tun_handler_tasks"], 0);
    assert_eq!(report_result(report), Ok(()));
}
