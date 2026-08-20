use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{OwnerSnapshot, PreparedProcessRoot, ProcessCancellation, ProcessFuture};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::run::test_support::*;

#[test]
fn rule_scratch_failures_keep_closed_runtime_categories() {
    for error in [
        RuleCompileError::Allocation,
        RuleCompileError::IndexOverflow,
    ] {
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleAllocation);
    }
    for error in [
        RuleCompileError::EmptyMatcher,
        RuleCompileError::EmptyField,
        RuleCompileError::DuplicateField,
        RuleCompileError::DuplicateValue,
        RuleCompileError::ConflictingFields,
        RuleCompileError::InvalidDomain,
        RuleCompileError::NonCanonicalCidr,
        RuleCompileError::InvalidId,
        RuleCompileError::InvalidTag,
        RuleCompileError::DuplicateRuleSet,
        RuleCompileError::InvalidGeneration,
        RuleCompileError::Internal,
    ] {
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleCompile);
    }
}

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

#[tokio::test(start_paused = true)]
async fn tun_tcp_sniff_outcomes_are_fail_closed_and_replay_each_prefix_once() {
    use ferrum2_runtime::SniffPrefixOutcome;

    use super::routing::{ClientTerminalRoute, ReplayIo, TcpRoutePrefix};

    static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-tun-tcp-{}-{}.toml",
        std::process::id(),
        CONFIG_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let source = r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[route]
final = "proxy"
[route.sniff]
timeout_ms = 300
max_bytes = 8192
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "sniff"
sniffers = "http"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
protocol = "http"
action = "reject"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    std::fs::write(&path, source).expect("TUN TCP config");
    let config = ferrum2_config::load_client(&path).expect("validated TUN TCP config");
    std::fs::remove_file(path).expect("remove TUN TCP config");
    let metrics = Metrics::new();
    publish_rule_program_metadata(&config, &metrics);
    let routing = ClientRouting {
        legacy: config.route,
        program: config.route_program,
        outbounds: Arc::from([]),
    };
    let target = TargetAddr::ip("192.0.2.1:80".parse().expect("target")).expect("target");
    let wire = b"GET / HTTP/1.1\r\nHost: replay.test\r\n\r\n";
    let (mut flow, mut peer) = tokio::io::duplex(128);
    peer.write_all(wire).await.expect("write sniff prefix");
    peer.shutdown().await.expect("close sniff peer");
    let registry = OwnerRegistry::new();

    let selection = routing
        .select_tcp(
            0,
            &target,
            &mut flow,
            std::future::pending::<()>(),
            &registry,
            &metrics,
        )
        .await
        .expect("route scratch construction")
        .expect("sniff selection");
    assert!(matches!(selection.terminal, ClientTerminalRoute::Reject));
    assert!(matches!(
        &selection.prefix,
        TcpRoutePrefix::Collected(prefix) if prefix.outcome() == SniffPrefixOutcome::Complete
    ));
    let encoded = metrics.encode_text().expect("client route metrics");
    for expected in [
        "ferrum2_rule_program_mode{program=\"route\",mode=\"small_linear\"} 1",
        "ferrum2_rule_program_rules{program=\"route\"} 2",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_count{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }
    let mut replay = ReplayIo::new(flow, selection.prefix);
    let mut received = Vec::new();
    replay
        .read_to_end(&mut received)
        .await
        .expect("replay selected bytes");
    assert_eq!(received, wire, "collected bytes enter the terminal once");
    drop(replay);
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let mut limit_wire = b"GET / HTTP/1.1\r\nX: ".to_vec();
    limit_wire.resize(8_192, b'a');
    for (name, wire, outcome) in [
        ("limit", limit_wire, SniffPrefixOutcome::Limit),
        (
            "invalid",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            SniffPrefixOutcome::Complete,
        ),
    ] {
        let (mut flow, mut peer) = tokio::io::duplex(16_384);
        peer.write_all(&wire).await.expect("write sniff prefix");
        peer.shutdown().await.expect("close sniff peer");
        let selection = routing
            .select_tcp(
                0,
                &target,
                &mut flow,
                std::future::pending::<()>(),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .expect("sniff falls through to final route");
        assert!(
            matches!(&selection.terminal, ClientTerminalRoute::Route(_)),
            "{name}"
        );
        assert!(
            matches!(&selection.prefix, TcpRoutePrefix::Collected(prefix) if prefix.outcome() == outcome),
            "{name}"
        );
        let mut replay = ReplayIo::new(flow, selection.prefix);
        let mut received = Vec::new();
        replay.read_to_end(&mut received).await.expect("replay");
        assert_eq!(received, wire, "{name} prefix is replayed exactly once");
    }

    let (mut flow, mut peer) = tokio::io::duplex(128);
    peer.write_all(b"G").await.expect("timeout prefix");
    let mut selection = Box::pin(routing.select_tcp(
        0,
        &target,
        &mut flow,
        std::future::pending::<()>(),
        &registry,
        &metrics,
    ));
    tokio::select! {
        _ = &mut selection => panic!("sniff completed before its absolute timeout"),
        _ = tokio::task::yield_now() => {}
    }
    tokio::time::advance(Duration::from_millis(299)).await;
    tokio::select! {
        _ = &mut selection => panic!("sniff timeout was shortened"),
        _ = tokio::task::yield_now() => {}
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    let selection = selection
        .await
        .expect("route scratch construction")
        .expect("timeout falls through to final route");
    peer.shutdown().await.expect("timeout EOF");
    assert!(matches!(&selection.terminal, ClientTerminalRoute::Route(_)));
    assert!(matches!(
        &selection.prefix,
        TcpRoutePrefix::Collected(prefix) if prefix.outcome() == SniffPrefixOutcome::Timeout
    ));
    let mut replay = ReplayIo::new(flow, selection.prefix);
    let mut received = Vec::new();
    replay
        .read_to_end(&mut received)
        .await
        .expect("timeout replay");
    assert_eq!(received, b"G");
    drop(replay);

    let (mut cancelled, _) = tokio::io::duplex(1);
    assert!(
        routing
            .select_tcp(
                0,
                &target,
                &mut cancelled,
                std::future::ready(()),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .is_none(),
        "cancelled sniff cannot select a terminal"
    );
    let mut failed = ScriptedIo::failing();
    assert!(
        routing
            .select_tcp(
                0,
                &target,
                &mut failed,
                std::future::pending::<()>(),
                &registry,
                &metrics,
            )
            .await
            .expect("route scratch construction")
            .is_none(),
        "read failure cannot select a terminal"
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
}

#[tokio::test]
async fn tun_tcp_selector_is_snapshotted_once_before_open_and_never_reselected() {
    use super::routing::ClientTerminalRoute;

    let (outbounds, route, selector) = chain_test_setup(
        [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
            MethodProfile::Blake3Aes128Gcm2022,
        ],
        20_000,
    );
    let routing = ClientRouting {
        legacy: route,
        program: None,
        outbounds,
    };
    let target = TargetAddr::ip("192.0.2.1:443".parse().expect("target")).expect("target");
    let (mut first_flow, _) = tokio::io::duplex(1);
    let first = routing
        .select_tcp(
            0,
            &target,
            &mut first_flow,
            std::future::pending::<()>(),
            &OwnerRegistry::new(),
            &Metrics::new(),
        )
        .await
        .expect("route scratch construction")
        .expect("first selection");
    let ClientTerminalRoute::Route(first) = first.terminal else {
        panic!("selector routes");
    };
    assert_eq!(first.hops(), &[0, 1]);

    selector.switch("manual", "c-d").expect("selector switch");
    assert_eq!(first.hops(), &[0, 1], "live flow retains its snapshot");
    let (mut second_flow, _) = tokio::io::duplex(1);
    let second = routing
        .select_tcp(
            0,
            &target,
            &mut second_flow,
            std::future::pending::<()>(),
            &OwnerRegistry::new(),
            &Metrics::new(),
        )
        .await
        .expect("route scratch construction")
        .expect("second selection");
    let ClientTerminalRoute::Route(second) = second.terminal else {
        panic!("selector routes");
    };
    assert_eq!(second.hops(), &[2, 3]);
}

#[tokio::test]
async fn tagged_tcp_uses_static_outbounds_one_process_permit_and_no_fallback() {
    let listens = [reserve_address(), reserve_address()];
    let upstreams = [
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream A"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream B"),
    ];
    let servers: [SocketAddrV4; 2] =
        std::array::from_fn(
            |index| match upstreams[index].local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            },
        );
    let (path, mut config) =
        tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], false);
    config.runtime.max_connections = 1.try_into().expect("one connection");
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(listens[0]).await;
    wait_until_bound(listens[1]).await;

    let (first, reply) = socks_command(listens[0], 1).await;
    assert_eq!(&reply[..2], &[5, 0]);
    let (first_upstream, _) = upstreams[0].accept().await.expect("mapped upstream A");
    let second = tokio::spawn(socks_command(listens[1], 1));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[1].accept())
            .await
            .is_err(),
        "second listener multiplied the process permit"
    );
    drop((first, first_upstream));
    let (second, reply) = second.await.expect("second SOCKS task");
    assert_eq!(&reply[..2], &[5, 0]);
    let (second_upstream, _) = upstreams[1].accept().await.expect("mapped upstream B");
    stop.send(()).expect("stop mapped client");
    assert_eq!(task.await.expect("mapped client"), Ok(()));
    drop((second, second_upstream));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let shared_listens = [reserve_address(), reserve_address()];
    let (shared_path, config) =
        tagged_client_test_config(&shared_listens.map(|listen| (listen, servers[0])), false);
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in shared_listens {
        wait_until_bound(listen).await;
        let (control, reply) = socks_command(listen, 1).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (upstream, _) = upstreams[0].accept().await.expect("shared upstream");
        drop((control, upstream));
    }
    stop.send(()).expect("stop shared client");
    assert_eq!(task.await.expect("shared client"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let dead = reserve_address();
    let (dead_path, config) = tagged_client_test_config(
        &[(reserve_address(), servers[0]), (reserve_address(), dead)],
        false,
    );
    let dead_listen = config.inbounds[1].listen;
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(dead_listen).await;
    let (_, reply) = socks_command(dead_listen, 1).await;
    assert_eq!(reply[0], 5);
    assert_ne!(reply[1], 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[0].accept())
            .await
            .is_err(),
        "dead referenced server fell back to live sibling"
    );
    stop.send(()).expect("stop no-fallback client");
    assert_eq!(task.await.expect("no-fallback client"), Ok(()));
    std::fs::remove_file(path).expect("remove mapped config");
    std::fs::remove_file(shared_path).expect("remove shared config");
    std::fs::remove_file(dead_path).expect("remove no-fallback config");
}

#[tokio::test]
async fn tagged_udp_uses_static_outbounds_and_no_fallback() {
    let listens = [reserve_address(), reserve_address()];
    let upstreams = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream A"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream B"),
    ];
    let servers: [SocketAddrV4; 2] = std::array::from_fn(|index| {
        match upstreams[index].local_addr().expect("upstream address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        }
    });
    let (path, mut config) =
        tagged_client_test_config(&[(listens[0], servers[0]), (listens[1], servers[1])], true);
    config.udp.as_mut().expect("UDP config").max_sessions = 2;
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in listens {
        wait_until_bound(listen).await;
    }
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let mut owners = Vec::new();
    let mut relays = Vec::new();
    for index in 0..2 {
        let (control, application, relay) = udp_association(listens[index]).await;
        let length =
            encode_udp_datagram(&target, &[index as u8], &mut request).expect("SOCKS UDP request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("application send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        tokio::time::timeout(Duration::from_secs(1), upstreams[index].recv(&mut wire))
            .await
            .expect("mapped upstream timeout")
            .expect("mapped upstream request");
        owners.push((control, application));
        relays.push(relay);
    }
    stop.send(()).expect("stop mapped UDP client");
    assert_eq!(task.await.expect("mapped UDP client"), Ok(()));
    drop(owners);
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("mapped relay rebind"));
    }
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

    let dead = reserve_address();
    let dead_listens = [reserve_address(), reserve_address()];
    let (dead_path, config) = tagged_client_test_config(
        &[(dead_listens[0], servers[0]), (dead_listens[1], dead)],
        true,
    );
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in dead_listens {
        wait_until_bound(listen).await;
    }
    let (control, application, relay) = udp_association(dead_listens[1]).await;
    let length =
        encode_udp_datagram(&target, b"no-fallback", &mut request).expect("no-fallback request");
    application
        .send_to(&request[..length], relay)
        .await
        .expect("no-fallback send");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstreams[0].recv(&mut wire))
            .await
            .is_err(),
        "dead UDP outbound fell back to live sibling"
    );
    stop.send(()).expect("stop no-fallback UDP client");
    assert_eq!(task.await.expect("no-fallback UDP client"), Ok(()));
    drop((control, application));
    drop(
        UdpSocket::bind(relay)
            .await
            .expect("no-fallback relay rebind"),
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove mapped UDP config");
    std::fs::remove_file(dead_path).expect("remove no-fallback UDP config");
}

#[tokio::test]
async fn tagged_udp_shares_byte_budget_across_listeners() {
    let listens = [reserve_address(), reserve_address()];
    let server = reserve_address();
    let (path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    let udp = config.udp.as_mut().expect("UDP config");
    udp.max_sessions = 8;
    udp.max_buffered_bytes = 1024 * 1024;
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut controls = Vec::new();
    let mut applications = Vec::new();
    let mut relays = Vec::new();
    for _ in 0..5 {
        let (control, application, relay) = udp_association(listens[0]).await;
        controls.push(control);
        applications.push(application);
        relays.push(relay);
    }
    let saturated = registry.snapshot();
    assert_eq!(saturated.udp_sessions, baseline.udp_sessions + 5);
    assert_eq!(
        saturated.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 15 * MAX_UDP_WIRE_LEN
    );
    let (rejected, reply) = socks_command(listens[1], 3).await;
    assert_eq!(&reply[..2], &[5, 1]);
    drop(rejected);
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 5);

    drop(controls.remove(0));
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let released = registry.snapshot();
        if released.udp_sessions == baseline.udp_sessions + 4
            && released.udp_buffered_bytes == baseline.udp_buffered_bytes + 12 * MAX_UDP_WIRE_LEN
        {
            break;
        }
        assert!(Instant::now() < deadline, "UDP byte owner did not release");
        tokio::task::yield_now().await;
    }
    let (control, application, relay) = udp_association(listens[1]).await;
    controls.push(control);
    applications.push(application);
    relays.push(relay);

    stop.send(()).expect("stop byte-budget client");
    assert_eq!(task.await.expect("byte-budget client"), Ok(()));
    drop((controls, applications));
    for relay in relays {
        drop(
            UdpSocket::bind(relay)
                .await
                .expect("byte-budget relay rebind"),
        );
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(path).expect("remove byte-budget config");
}

#[tokio::test]
async fn tagged_udp_shares_live_id_collisions_across_listeners() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream");
    let SocketAddr::V4(server) = upstream.local_addr().expect("upstream address") else {
        unreachable!("IPv4 upstream")
    };
    let (path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.udp.as_mut().expect("UDP config").max_sessions = 3;
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let draws = [1]
        .into_iter()
        .chain(std::iter::repeat_n(1, 7))
        .chain([2])
        .chain(std::iter::repeat_n(1, 8));
    let (stop, task) =
        spawn_test_client_with_random(config, &registry, Arc::new(IdSequenceRandom::new(draws)));
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut socks = [0; 64];
    let length = encode_udp_datagram(&target, b"activate", &mut socks).expect("request");
    let first = udp_association(listens[0]).await;
    first
        .1
        .send_to(&socks[..length], first.2)
        .await
        .expect("first activation");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    upstream.recv(&mut wire).await.expect("first upstream");
    let second = udp_association(listens[1]).await;
    second
        .1
        .send_to(&socks[..length], second.2)
        .await
        .expect("second activation");
    upstream.recv(&mut wire).await.expect("second upstream");
    let activated = registry.snapshot();
    let third = udp_association(listens[1]).await;
    assert_eq!(
        registry.snapshot().udp_sessions,
        activated.udp_sessions + 1,
        "association setup must own its pending session"
    );
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        activated.udp_buffered_bytes + 3 * MAX_UDP_WIRE_LEN,
        "association setup must own its fixed buffers"
    );
    third
        .1
        .send_to(&socks[..length], third.2)
        .await
        .expect("third activation attempt");
    let mut rejected = third.0;
    let mut eof = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut eof))
            .await
            .expect("rejected control timeout")
            .expect("rejected control EOF"),
        0
    );
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.recv(&mut wire))
            .await
            .is_err(),
        "failed third activation reached the upstream"
    );

    stop.send(()).expect("stop live-ID client");
    assert_eq!(task.await.expect("live-ID client"), Ok(()));
    let relays = [first.2, second.2, third.2];
    drop((first, second, rejected, third.1));
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("live-ID relay rebind"));
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(path).expect("remove live-ID config");
}

#[tokio::test]
async fn tagged_prepare_failures_restore_full_baseline_and_exact_rebind() {
    for blocked in 0..3 {
        let listens = [reserve_address(), reserve_address(), reserve_address()];
        let metrics = reserve_address();
        let (path, mut config) =
            tagged_client_test_config(&listens.map(|listen| (listen, reserve_address())), false);
        config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
        let address = if blocked < 2 {
            listens[blocked]
        } else {
            metrics
        };
        let incumbent = std::net::TcpListener::bind(address).expect("occupy prepare position");
        let registry = OwnerRegistry::new();
        assert_eq!(
            run_with_registry(config, registry.clone(), std::future::pending()).await,
            Err(RunError::StartupBind)
        );
        drop(incumbent);
        for address in listens.into_iter().chain([metrics]) {
            drop(std::net::TcpListener::bind(address).expect("exact rollback rebind"));
        }
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove prepare config");
    }
}

#[test]
fn client_udp_route_publishes_program_and_match_observations() {
    use super::routing::ClientTerminalRoute;

    let listen = reserve_address();
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-udp-route-metrics-{}-{}.toml",
        std::process::id(),
        listen.port()
    ));
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"{listen}\"\n\
         [[outbounds]]\n\
         tag = \"direct\"\n\
         type = \"direct\"\n\
         [route]\n\
         final = \"direct\"\n\
         [[route.rules]]\n\
         network = \"udp\"\n\
         port = 53\n\
         action = \"reject\"\n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    );
    std::fs::write(&path, source).expect("UDP route metrics config");
    let config = ferrum2_config::load_client(&path).expect("validated UDP route metrics config");
    std::fs::remove_file(path).expect("remove UDP route metrics config");
    let metrics = Metrics::new();
    publish_rule_program_metadata(&config, &metrics);
    let routing = ClientRouting {
        legacy: config.route,
        program: config.route_program,
        outbounds: Arc::from([]),
    };
    let target = TargetAddr::ip("192.0.2.1:53".parse().expect("UDP route target"))
        .expect("validated UDP route target");
    let mut scratch = routing.route_scratch().expect("route scratch construction");
    let terminal = routing.select_terminal_with_scratch(
        0,
        Network::Udp,
        &target,
        Some(b"payload"),
        &metrics,
        scratch.as_mut(),
    );
    assert!(matches!(terminal, Ok(ClientTerminalRoute::Reject)));
    assert!(matches!(
        routing.select_terminal_with_scratch(
            0,
            Network::Udp,
            &target,
            Some(b"payload"),
            &metrics,
            None,
        ),
        Err(RuleCompileError::Internal)
    ));
    let encoded = metrics.encode_text().expect("client UDP route metrics");
    for expected in [
        "ferrum2_rule_program_rules{program=\"route\"} 1",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }
}

#[tokio::test]
async fn udp_process_shutdown_drains_an_active_association_without_forcing() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (config_path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let metrics = Arc::new(Metrics::new());
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let task_registry = registry.clone();
    let task_metrics = Arc::clone(&metrics);
    let run_task = tokio::spawn(async move {
        run_with_registry_and_metrics(
            config,
            task_registry,
            async {
                let _ = shutdown_receiver.await;
            },
            task_metrics,
        )
        .await
    });
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut control = tokio::net::TcpStream::connect(listens[0])
        .await
        .expect("SOCKS control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).await.expect("success reply");
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application socket");
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let request_len =
        encode_udp_datagram(&target, b"graceful-active", &mut request).expect("request");
    application
        .send_to(&request[..request_len], relay)
        .await
        .expect("application send");
    let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
    let (_, upstream_client) = tokio::time::timeout(
        Duration::from_secs(2),
        upstream.recv_from(&mut upstream_wire),
    )
    .await
    .expect("committed request timeout")
    .expect("committed request");
    let live = registry.snapshot();
    assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
    assert_eq!(
        live.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 3 * MAX_UDP_WIRE_LEN
    );
    assert_eq!(
        live.active_supervisor_children,
        baseline.active_supervisor_children + 1
    );
    assert_eq!(live.connection_tasks, baseline.connection_tasks + 1);
    let (_, saturated) = socks_command(listens[1], 3).await;
    assert_eq!(&saturated[..2], &[5, 1]);
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 1);

    shutdown_sender
        .send(())
        .expect("request graceful shutdown first");
    let mut eof = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
            .await
            .expect("control EOF timeout")
            .expect("control EOF"),
        0
    );
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    let closed = registry.snapshot();
    let actual = (
        closed.process_supervisors,
        closed.prepared_process_roots,
        closed.active_process_roots,
        closed.active_supervisor_children,
        closed.connection_tasks,
        closed.owned_permits,
        closed.listeners,
        closed.udp_sessions,
        closed.udp_queued_datagrams,
        closed.udp_buffered_bytes,
    );
    let expected = (
        baseline.process_supervisors,
        baseline.prepared_process_roots,
        baseline.active_process_roots,
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_permits,
        baseline.listeners,
        baseline.udp_sessions,
        baseline.udp_queued_datagrams,
        baseline.udp_buffered_bytes,
    );
    assert_eq!(actual, expected);
    assert!(
        !metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
    );
    drop(application);
    drop(upstream);
    drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    drop(
        UdpSocket::bind(upstream_client)
            .await
            .expect("upstream client rebind"),
    );
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(config_path).expect("remove client UDP test config");
}
#[tokio::test]
async fn zero_grace_counts_each_of_two_forced_udp_associations_once() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (config_path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.runtime.shutdown_grace = Duration::ZERO;
    config.udp.as_mut().expect("UDP config").max_sessions = 2;
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let metrics = Arc::new(Metrics::new());
    let task_metrics = Arc::clone(&metrics);
    let task_registry = registry.clone();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let run_task = tokio::spawn(async move {
        run_with_registry_and_metrics(
            config,
            task_registry,
            async {
                let _ = shutdown_receiver.await;
            },
            task_metrics,
        )
        .await
    });
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut controls = Vec::new();
    let mut relays = Vec::new();
    let mut applications = Vec::new();
    let mut upstream_clients = Vec::new();
    for (listen, payload) in listens
        .into_iter()
        .zip([b"active-one".as_slice(), b"active-two".as_slice()])
    {
        let mut control = tokio::net::TcpStream::connect(listen)
            .await
            .expect("SOCKS control");
        control.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        control.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.expect("success reply");
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut request = [0; 64];
        let length = encode_udp_datagram(&target, payload, &mut request).expect("request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("application send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        let (_, upstream_client) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut wire))
                .await
                .expect("upstream timeout")
                .expect("upstream request");
        controls.push(control);
        relays.push(relay);
        applications.push(application);
        upstream_clients.push(upstream_client);
    }
    let active = registry.snapshot();
    assert_eq!(active.udp_sessions, baseline.udp_sessions + 2);
    assert_eq!(
        active.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 6 * MAX_UDP_WIRE_LEN
    );
    assert_eq!(
        active.active_supervisor_children,
        baseline.active_supervisor_children + 2
    );
    assert_eq!(active.connection_tasks, baseline.connection_tasks + 2);

    shutdown_sender.send(()).expect("zero-grace shutdown");
    for control in &mut controls {
        let mut eof = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
                .await
                .expect("control EOF timeout")
                .expect("control EOF"),
            0
        );
    }
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    assert!(
        metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"} 2")
    );
    let closed = registry.snapshot();
    let actual = (
        closed.process_supervisors,
        closed.prepared_process_roots,
        closed.active_process_roots,
        closed.active_supervisor_children,
        closed.connection_tasks,
        closed.owned_permits,
        closed.listeners,
        closed.udp_sessions,
        closed.udp_queued_datagrams,
        closed.udp_buffered_bytes,
    );
    let expected = (
        baseline.process_supervisors,
        baseline.prepared_process_roots,
        baseline.active_process_roots,
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_permits,
        baseline.listeners,
        baseline.udp_sessions,
        baseline.udp_queued_datagrams,
        baseline.udp_buffered_bytes,
    );
    assert_eq!(actual, expected);
    drop(controls);
    drop(applications);
    drop(upstream);
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    }
    for upstream_client in upstream_clients {
        drop(
            UdpSocket::bind(upstream_client)
                .await
                .expect("upstream client rebind"),
        );
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(config_path).expect("remove config");
}
#[tokio::test]
async fn listener_fatal_cancels_udp_without_forced_shutdown() {
    let listens = [reserve_address(), reserve_address()];
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (path, mut context) = udp_test_context_for_server(registry.clone(), server);
    Arc::get_mut(&mut context)
        .expect("unique test context")
        .runtime
        .shutdown_grace = Duration::from_secs(1);
    let metrics = Arc::clone(&context.metrics);
    let accept_errors = Arc::new(Mutex::new(VecDeque::from([io::ErrorKind::Interrupted])));
    let tcp_registry = registry.clone();
    let tcp_context = Arc::clone(&context);
    let tcp_accept_errors = Arc::clone(&accept_errors);
    let tcp_root = ProcessRoot::new(move || async move {
        let listeners = listens
            .into_iter()
            .map(|listen| bind_listener(listen, 16))
            .collect::<Result<Vec<_>, _>>()?;
        let supervisor = BoundedSupervisor::new(
            ClientTcpListeners {
                listeners,
                next: AtomicUsize::new(0),
                accept_errors: Some(tcp_accept_errors),
            },
            4,
            Duration::from_secs(1),
            tcp_registry,
        )
        .map_err(|_| RunError::StartupProtocol)?;
        Ok(ClientTcpRoot {
            supervisor: Some(supervisor),
            context: tcp_context,
            routing: Arc::new(ClientRouting {
                legacy: ferrum2_rule::RouteTable::static_bindings(vec![0, 1]).expect("test routes"),
                program: None,
                outbounds: listens
                    .map(|_| {
                        ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                            tcp_server: TargetAddr::ipv4(server).expect("server target"),
                            udp_server: server.into(),
                            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                                psk_for_method(MethodProfile::Blake3Aes128Gcm2022),
                            )),
                        })
                    })
                    .into(),
            }),
        })
    });
    let supervisor =
        ProcessSupervisor::new(vec![tcp_root], Duration::from_secs(1), registry.clone())
            .expect("process supervisor");
    let run_task = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut control = tokio::net::TcpStream::connect(listens[0])
        .await
        .expect("SOCKS control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0; 2];
    control.read_exact(&mut method).await.expect("method");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("UDP ASSOCIATE");
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.expect("success reply");
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application");
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let length = encode_udp_datagram(&target, b"sibling", &mut request).expect("request");
    application
        .send_to(&request[..length], relay)
        .await
        .expect("application send");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    let (_, upstream_client) =
        tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut wire))
            .await
            .expect("upstream timeout")
            .expect("committed upstream request");
    let live = registry.snapshot();
    assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
    assert_eq!(live.udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
    assert_eq!(live.active_supervisor_children, 1);
    assert_eq!(live.connection_tasks, 1);
    assert_eq!(live.owned_permits, 2);
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .manager
            .session_count(),
        1
    );

    accept_errors
        .lock()
        .expect("accept errors")
        .push_back(io::ErrorKind::PermissionDenied);
    drop(
        tokio::net::TcpStream::connect(listens[1])
            .await
            .expect("wake fatal listener"),
    );
    let mut eof = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), control.read(&mut eof))
            .await
            .expect("control EOF timeout")
            .expect("control EOF"),
        0
    );
    let report = run_task.await.expect("process task");
    assert!(matches!(
        report.cause(),
        ProcessCause::RootStopped {
            root,
            exit: ProcessRootExit::Failed(RunError::RuntimeListener),
        } if root.get() == 0
    ));
    assert_eq!(report.forced_roots(), 0);
    let udp = context.egress.udp.as_ref().expect("UDP");
    assert_eq!(udp.manager.session_count(), 0);
    assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
    assert!(udp.live_ids.lock().expect("live IDs").is_empty());
    assert_eq!(active(registry.snapshot()), active(baseline));
    assert!(
        !metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
    );
    drop(application);
    drop(upstream);
    drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    drop(
        UdpSocket::bind(upstream_client)
            .await
            .expect("upstream client rebind"),
    );
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
    let shadowsocks_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fake Shadowsocks listener");
    let server = match shadowsocks_listener.local_addr().expect("server address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 server"),
    };
    let listen = reserve_address();
    let (config_path, config) = client_test_config(listen, server);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let task_registry = registry.clone();
    let run_task = tokio::spawn(async move {
        run_with_registry(config, task_registry, async {
            let _ = shutdown_receiver.await;
        })
        .await
    });
    wait_until_bound(listen).await;

    let accept_task = tokio::spawn(async move {
        shadowsocks_listener
            .accept()
            .await
            .expect("fake Shadowsocks accept")
            .0
    });
    let mut socks = tokio::net::TcpStream::connect(listen)
        .await
        .expect("SOCKS client connect");
    socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    socks.read_exact(&mut method).await.expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .expect("SOCKS request");
    let mut reply = [0_u8; 10];
    socks.read_exact(&mut reply).await.expect("SOCKS success");
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let shadowsocks_stream = accept_task.await.expect("fake Shadowsocks task");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let live = registry.snapshot();
        if live.active_supervisor_children == 1
            && live.connection_tasks == 1
            && live.owned_buffers == 2
            && live.owned_permits >= 1
            && live.listeners == 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "registry never exposed the live production path: {live:?}"
        );
        tokio::task::yield_now().await;
    }

    shutdown_sender.send(()).expect("request shutdown");
    assert_eq!(
        run_task.await.expect("run task"),
        Ok(()),
        "production run_with_registry path"
    );
    drop(socks);
    drop(shadowsocks_stream);
    let final_snapshot = registry.snapshot();
    let actual = (
        final_snapshot.active_supervisor_children,
        final_snapshot.connection_tasks,
        final_snapshot.owned_buffers,
        final_snapshot.owned_permits,
        final_snapshot.listeners,
        final_snapshot.process_forced_roots,
        final_snapshot.forced_shutdowns,
    );
    let expected = (
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_buffers,
        baseline.owned_permits,
        baseline.listeners,
        baseline.process_forced_roots + 1,
        baseline.forced_shutdowns + 1,
    );
    assert_eq!(actual, expected, "TCP root cleanup");
    std::fs::remove_file(config_path).expect("remove client test config");
}

#[tokio::test]
async fn application_resolver_observer_records_explicit_system_without_fallback() {
    struct OutcomeBackend(Result<Vec<std::net::SocketAddr>, ferrum2_dns::DnsError>);

    impl ferrum2_dns::ApplicationResolveBackend for OutcomeBackend {
        fn resolve<'a>(
            &'a self,
            _request: ferrum2_dns::ApplicationResolveRequest<'a>,
        ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
            let outcome = self.0.clone();
            Box::pin(async move { outcome })
        }
    }

    let metrics = Arc::new(Metrics::new());
    let system = observed_application_resolver(
        ferrum2_dns::ApplicationResolver::system(Arc::new(OutcomeBackend(Ok(vec![
            "192.0.2.10:443".parse().expect("test address"),
        ])))),
        &metrics,
    );
    let configured = observed_application_resolver(
        ferrum2_dns::ApplicationResolver::configured(Arc::new(OutcomeBackend(Err(
            ferrum2_dns::DnsError::NoData,
        )))),
        &metrics,
    );
    let domain = ferrum2_core::CanonicalDomain::new("application.example")
        .expect("canonical application domain");
    let request = ferrum2_dns::ApplicationResolveRequest::new(
        ferrum2_dns::ApplicationResolveContext::new(0, ferrum2_core::route::Network::Tcp),
        &domain,
        std::num::NonZeroU16::new(443).expect("non-zero port"),
        ferrum2_dns::DnsStrategy::Ipv4Only,
    );

    assert!(system.resolve(request).await.is_ok());
    assert_eq!(
        configured.resolve(request).await,
        Err(ferrum2_dns::DnsError::NoData)
    );
    let encoded = metrics
        .encode_text()
        .expect("encode application DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"application\",result=\"success\"} 1",
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"failure\"} 1",
        "ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
}

#[test]
fn configured_dns_cache_does_not_require_a_ruleset_policy() {
    let metrics = Arc::new(Metrics::new());
    let runtime = ClientDnsProxyRuntime::try_new(
        None,
        ferrum2_config::DnsRuntimeConfig::default(),
        None,
        &metrics,
    )
    .expect("standalone configured DNS cache");

    assert!(runtime.policy.is_none());
    assert_eq!(
        runtime
            .cache
            .as_ref()
            .map(|cache| cache.capacity().expect("cache capacity")),
        Some(8_192)
    );
    assert_eq!(runtime.generation, ferrum2_dns::ResolverGeneration::new(0));
}
