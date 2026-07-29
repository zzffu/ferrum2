#[path = "../src/qualification/mod.rs"]
mod qualification;

use qualification::{
    CaseFailure, CaseSpec, CleanupState, Direction, HostedContext, Method, QualificationOps,
    Reference, SetupAvailability, TCP_CASES, TCP_EXCHANGE_ORDER, TcpExchangeEvent,
    TcpExchangeState, TcpTargetShutdownNotifier, Transport, UDP_CASES, execute_hosted,
    execute_with_setup, tcp_target_shutdown_gate, validate_hosted,
};
use std::thread;
use std::time::Duration;

#[derive(Default)]
struct FakeOps {
    fail_provision: Option<Reference>,
    fail_case: Option<&'static str>,
    panic_case: Option<&'static str>,
    fail_cleanup: bool,
    provisioned: Vec<Reference>,
    attempted: Vec<&'static str>,
    cleanup_calls: usize,
}

fn all_ready() -> SetupAvailability {
    SetupAvailability::from_provider_status(Some("0"), Some("0"))
}

fn valid_context() -> HostedContext<'static> {
    HostedContext {
        argument_count: 1,
        github_actions: Some("true"),
        runner_os: Some("Linux"),
        run_id: Some("123456"),
        run_attempt: Some("1"),
        github_sha: Some("0123456789abcdef0123456789abcdef01234567"),
        head_sha: "0123456789abcdef0123456789abcdef01234567",
        checkout_clean: true,
    }
}

fn case_ids_for(reference: Reference) -> Vec<&'static str> {
    TCP_CASES
        .iter()
        .chain(UDP_CASES.iter())
        .filter(|case| case.reference == reference)
        .map(|case| case.id)
        .collect()
}

fn assert_setup_root(report: &qualification::QualificationReport, failed: Reference, root: &str) {
    for (transport, cases) in [(Transport::Tcp, TCP_CASES), (Transport::Udp, UDP_CASES)] {
        for (case, line) in cases.iter().zip(report.summary_lines(transport)) {
            let suffix = if case.reference == failed {
                format!("FAIL canonical_root={root}")
            } else {
                "PASS".to_owned()
            };
            assert_eq!(
                line,
                format!(
                    "transport={} case_id={} status={suffix}",
                    transport.label(),
                    case.id
                )
            );
        }
    }
}

impl QualificationOps for FakeOps {
    fn provision(&mut self, reference: Reference) -> Result<(), CaseFailure> {
        self.provisioned.push(reference);
        if self.fail_provision == Some(reference) {
            Err(CaseFailure::new(reference.provision_root()))
        } else {
            Ok(())
        }
    }

    fn run_case(&mut self, case: CaseSpec) -> Result<(), CaseFailure> {
        self.attempted.push(case.id);
        assert_ne!(self.panic_case, Some(case.id), "injected case panic");
        if self.fail_case == Some(case.id) {
            Err(CaseFailure::new(case.case_root()))
        } else {
            Ok(())
        }
    }

    fn finish_cleanup(&mut self) -> Result<(), CaseFailure> {
        self.cleanup_calls += 1;
        if self.fail_cleanup {
            Err(CaseFailure::new("cleanup"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn both_active_transport_plans_are_frozen_twelve_tuple_matrices() {
    use Direction::{FerrumClient as Ferrum, ReferenceClient as Client};
    use Method::{Aes128Gcm as Aes128, Aes256Gcm as Aes256, ChaCha20Poly1305 as ChaCha};
    use Reference::{ShadowsocksRust, SingBox};
    use Transport::{Tcp, Udp};

    let tuple = |case: CaseSpec| {
        (
            case.id,
            case.method,
            case.reference,
            case.direction,
            case.transport,
        )
    };
    assert_eq!(
        TCP_CASES.map(tuple),
        [
            ("M1-INT-001", Aes128, SingBox, Ferrum, Tcp),
            ("M1-INT-002", Aes128, ShadowsocksRust, Ferrum, Tcp),
            ("M1-INT-003", Aes128, SingBox, Client, Tcp),
            ("M1-INT-004", Aes128, ShadowsocksRust, Client, Tcp),
            ("M1-INT-005", Aes256, SingBox, Ferrum, Tcp),
            ("M1-INT-006", Aes256, ShadowsocksRust, Ferrum, Tcp),
            ("M1-INT-007", Aes256, SingBox, Client, Tcp),
            ("M1-INT-008", Aes256, ShadowsocksRust, Client, Tcp),
            ("M1-INT-009", ChaCha, SingBox, Ferrum, Tcp),
            ("M1-INT-010", ChaCha, ShadowsocksRust, Ferrum, Tcp),
            ("M1-INT-011", ChaCha, SingBox, Client, Tcp),
            ("M1-INT-012", ChaCha, ShadowsocksRust, Client, Tcp),
        ]
    );
    assert_eq!(
        UDP_CASES.map(tuple),
        [
            ("M2-UDP-INT-001", Aes128, SingBox, Ferrum, Udp),
            ("M2-UDP-INT-002", Aes128, ShadowsocksRust, Ferrum, Udp),
            ("M2-UDP-INT-003", Aes128, SingBox, Client, Udp),
            ("M2-UDP-INT-004", Aes128, ShadowsocksRust, Client, Udp),
            ("M2-UDP-INT-005", Aes256, SingBox, Ferrum, Udp),
            ("M2-UDP-INT-006", Aes256, ShadowsocksRust, Ferrum, Udp),
            ("M2-UDP-INT-007", Aes256, SingBox, Client, Udp),
            ("M2-UDP-INT-008", Aes256, ShadowsocksRust, Client, Udp),
            ("M2-UDP-INT-009", ChaCha, SingBox, Ferrum, Udp),
            ("M2-UDP-INT-010", ChaCha, ShadowsocksRust, Ferrum, Udp),
            ("M2-UDP-INT-011", ChaCha, SingBox, Client, Udp),
            ("M2-UDP-INT-012", ChaCha, ShadowsocksRust, Client, Udp),
        ]
    );
    for (method, name, psk) in [
        (
            Aes128,
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
        ),
        (
            Aes256,
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            ChaCha,
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ] {
        assert_eq!(
            (method.canonical_name(), method.synthetic_psk()),
            (name, psk)
        );
    }
}

#[test]
fn hosted_guard_rejects_every_unqualified_context() {
    let valid = valid_context();
    assert!(validate_hosted(&valid).is_ok());

    let mutations = [
        HostedContext {
            argument_count: 2,
            ..valid
        },
        HostedContext {
            github_actions: None,
            ..valid
        },
        HostedContext {
            github_actions: Some("false"),
            ..valid
        },
        HostedContext {
            runner_os: Some("Windows"),
            ..valid
        },
        HostedContext {
            run_id: None,
            ..valid
        },
        HostedContext {
            run_attempt: Some("0"),
            ..valid
        },
        HostedContext {
            github_sha: Some("short"),
            ..valid
        },
        HostedContext {
            head_sha: "1123456789abcdef0123456789abcdef01234567",
            ..valid
        },
        HostedContext {
            checkout_clean: false,
            ..valid
        },
    ];

    for mutation in mutations {
        assert!(validate_hosted(&mutation).is_err());
    }
}

#[test]
fn rejected_hosted_context_never_reaches_provision_or_case_operations() {
    let invalid = HostedContext {
        head_sha: "1123456789abcdef0123456789abcdef01234567",
        ..valid_context()
    };
    let mut ops = FakeOps::default();

    assert!(execute_hosted(&invalid, all_ready(), &mut ops).is_err());
    assert!(ops.provisioned.is_empty());
    assert!(ops.attempted.is_empty());
}

#[test]
fn only_exact_zero_marks_provider_setup_ready() {
    assert!(
        SetupAvailability::from_provider_status(Some("0"), Some("0")).is_ready(Reference::SingBox)
    );
    for unavailable in [
        None,
        Some(""),
        Some("1"),
        Some("00"),
        Some("+0"),
        Some("-0"),
        Some(" 0"),
        Some("0 "),
        Some("0\n"),
        Some("0x0"),
        Some("ok"),
        Some("success"),
        Some("zero"),
        Some("０"),
    ] {
        let availability = SetupAvailability::from_provider_status(unavailable, Some("0"));
        assert!(!availability.is_ready(Reference::SingBox));
        assert!(availability.is_ready(Reference::ShadowsocksRust));

        let availability = SetupAvailability::from_provider_status(Some("0"), unavailable);
        assert!(availability.is_ready(Reference::SingBox));
        assert!(!availability.is_ready(Reference::ShadowsocksRust));
    }
}

#[test]
fn unavailable_setup_skips_that_reference_and_continues_the_ready_reference() {
    let availability = SetupAvailability::from_provider_status(Some("7"), Some("0"));
    let mut ops = FakeOps::default();

    let report = execute_with_setup(availability, &mut ops);

    assert_eq!(ops.provisioned, [Reference::ShadowsocksRust]);
    assert_eq!(ops.attempted, case_ids_for(Reference::ShadowsocksRust));
    assert_setup_root(&report, Reference::SingBox, "provision-sing-box");
    assert!(!report.success());
}

#[test]
fn provision_failure_marks_only_that_reference_and_does_not_mask_the_other() {
    let mut ops = FakeOps {
        fail_provision: Some(Reference::SingBox),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_eq!(
        ops.provisioned,
        [Reference::SingBox, Reference::ShadowsocksRust]
    );
    assert_eq!(ops.attempted, case_ids_for(Reference::ShadowsocksRust));
    assert_setup_root(&report, Reference::SingBox, "provision-sing-box");
    assert!(!report.success());
}

#[test]
fn one_case_failure_does_not_prevent_later_cases() {
    let mut ops = FakeOps {
        fail_case: Some("M1-INT-001"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    let expected = TCP_CASES.into_iter().chain(UDP_CASES).map(|case| case.id);
    assert!(ops.attempted.iter().copied().eq(expected));
    let lines = report.summary_lines(Transport::Tcp);
    assert_eq!(
        lines[0],
        "transport=tcp case_id=M1-INT-001 status=FAIL canonical_root=case-M1-INT-001"
    );
    assert_eq!(lines[11], "transport=tcp case_id=M1-INT-012 status=PASS");
    assert!(report.transport_success(Transport::Udp));
    assert!(!report.success());
}

#[test]
fn case_panic_fails_that_row_and_does_not_prevent_later_cases() {
    let mut ops = FakeOps {
        panic_case: Some("M2-UDP-INT-006"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_eq!(
        report.summary_lines(Transport::Udp)[5],
        "transport=udp case_id=M2-UDP-INT-006 status=FAIL \
         canonical_root=case-M2-UDP-INT-006"
    );
    assert_eq!(
        report.summary_lines(Transport::Udp)[11],
        "transport=udp case_id=M2-UDP-INT-012 status=PASS"
    );
    assert!(!report.success());
}

#[test]
fn both_twelve_row_gates_are_required_and_have_transport_specific_summaries() {
    let mut ops = FakeOps::default();
    let report = execute_with_setup(all_ready(), &mut ops);

    assert!(report.success());
    assert_eq!(
        report.summary_lines(Transport::Tcp),
        TCP_CASES.map(|case| format!("transport=tcp case_id={} status=PASS", case.id))
    );
    assert_eq!(
        report.summary_lines(Transport::Udp),
        UDP_CASES.map(|case| format!("transport=udp case_id={} status=PASS", case.id))
    );
    assert!(report.cleanup_success());
    assert_eq!(ops.cleanup_calls, 1);
    let context = HostedContext {
        run_attempt: Some("2"),
        ..valid_context()
    };
    assert_eq!(
        report.completion_line(Transport::Tcp, &context),
        "qualification transport=tcp status=PASS cases=12/12 cleanup=PASS \
         sha=0123456789abcdef0123456789abcdef01234567 run_id=123456 run_attempt=2"
    );
    assert_eq!(
        report.completion_line(Transport::Udp, &context),
        "qualification transport=udp status=PASS cases=12/12 cleanup=PASS \
         sha=0123456789abcdef0123456789abcdef01234567 run_id=123456 run_attempt=2"
    );
}

#[test]
fn cleanup_failure_can_never_produce_success() {
    let mut ops = FakeOps {
        fail_cleanup: true,
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_eq!(
        report.summary_lines(Transport::Udp)[11],
        "transport=udp case_id=M2-UDP-INT-012 status=PASS"
    );
    assert!(!report.cleanup_success());
    assert!(!report.success());
    assert_eq!(ops.cleanup_calls, 1);
}

#[test]
fn never_confirmed_child_or_capture_worker_keeps_cleanup_failed() {
    let mut child_unreaped = CleanupState::default();
    child_unreaped.child_started();
    assert!(!child_unreaped.success());

    let mut capture_unjoined = CleanupState::default();
    capture_unjoined.worker_started();
    assert!(!capture_unjoined.success());
}

#[test]
fn tcp_exchange_accepts_only_the_adr_0014_observable_order() {
    use TcpExchangeEvent as E;

    let mut exchange = TcpExchangeState::default();
    assert!(exchange.record(E::ReverseMatched).is_err());
    for event in TCP_EXCHANGE_ORDER {
        exchange.record(event).expect("approved event order");
    }
    assert!(exchange.success());
    assert!(exchange.record(E::ApplicationShutdown).is_err());
}

#[test]
fn tcp_exchange_accepts_hosted_sing_box_reference_client_observation_order() {
    use Direction::ReferenceClient;
    use TcpExchangeEvent as E;

    let wait = Duration::from_millis(10);
    let bounded = Duration::from_millis(100);
    let affected: Vec<_> = TCP_CASES
        .into_iter()
        .filter(|case| case.reference == Reference::SingBox && case.direction == ReferenceClient)
        .collect();
    assert_eq!(
        affected.iter().map(|case| case.id).collect::<Vec<_>>(),
        ["M1-INT-003", "M1-INT-007", "M1-INT-011"]
    );
    let mut raw_exchange = TcpExchangeState::default();
    for event in TCP_EXCHANGE_ORDER[..3].iter().copied() {
        raw_exchange.record(event).expect("ordered exchange prefix");
    }
    assert!(raw_exchange.record(E::ApplicationCleanEof).is_err());

    let start_target =
        |target: TcpTargetShutdownNotifier, result: Result<(), String>, timeout: Duration| {
            thread::spawn(move || target.synchronize(result, timeout))
        };

    for case in affected {
        let (target_shutdown, application_gate) = tcp_target_shutdown_gate();
        let target = start_target(target_shutdown, Ok(()), bounded);
        let mut exchange = TcpExchangeState::default();
        for event in TCP_EXCHANGE_ORDER[..5].iter().copied() {
            exchange.record(event).expect("ordered exchange prefix");
        }
        let acknowledgement = application_gate
            .wait(wait)
            .expect("application observes target shutdown");
        assert!(
            !target.is_finished(),
            "{} target owner completed before application acknowledgement",
            case.id
        );
        exchange.record(E::ApplicationCleanEof).expect("clean EOF");
        acknowledgement
            .complete(Ok(()))
            .expect("application success acknowledgement");
        target
            .join()
            .expect("target owner")
            .expect("target success");
        assert!(exchange.success());
    }

    for (target_result, acknowledgement, timeout, expected) in [
        (
            Err("target probe failed"),
            None,
            bounded,
            "target probe failed",
        ),
        (
            Ok(()),
            Some(Err("application probe failed")),
            bounded,
            "application probe failed",
        ),
        (Ok(()), None, bounded, "acknowledgement omitted"),
        (Ok(()), Some(Ok(())), Duration::ZERO, "timed out"),
    ] {
        let (target_shutdown, application_gate) = tcp_target_shutdown_gate();
        let target = start_target(
            target_shutdown,
            target_result.map_err(str::to_owned),
            timeout,
        );
        if let Ok(application) = application_gate.wait(wait) {
            match acknowledgement {
                Some(result) => {
                    let _ = application.complete(result.map_err(str::to_owned));
                }
                None => drop(application),
            }
        }
        let error = target
            .join()
            .expect("target owner")
            .expect_err("handshake failure must block target success");
        assert!(error.contains(expected));
    }

    let (target_shutdown, application_gate) = tcp_target_shutdown_gate();
    drop(application_gate);
    assert!(target_shutdown.synchronize(Ok(()), wait).is_err());

    let (target_shutdown, application_gate) = tcp_target_shutdown_gate();
    drop(target_shutdown);
    assert!(application_gate.wait(wait).is_err());
}
