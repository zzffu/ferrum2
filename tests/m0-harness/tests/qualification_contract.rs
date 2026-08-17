#[path = "../src/qualification/mod.rs"]
mod qualification;

use qualification::{
    CaseFailure, CaseSpec, CleanupState, DNS_CASES, Direction, DnsCaseSpec, DnsPath,
    DnsQualificationOps, DnsReference, DnsSetupAvailability, DnsUpstreamTransport, HostedContext,
    Method, QualificationOps, Reference, SetupAvailability, TCP_CASES, TCP_EXCHANGE_ORDER,
    TcpExchangeEvent, TcpExchangeState, TcpTargetGate, Transport, UDP_CASES, execute_dns_hosted,
    execute_dns_with_setup, execute_hosted, execute_with_setup, tcp_shutdown_gate,
    validate_dns_hosted, validate_hosted,
};
use std::collections::BTreeSet;
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

#[derive(Default)]
struct FakeDnsOps {
    fail_provision: Option<DnsReference>,
    provisioned: Vec<DnsReference>,
    attempted: Vec<&'static str>,
    cleanup_calls: usize,
}

impl DnsQualificationOps for FakeDnsOps {
    fn provision_dns(&mut self, reference: DnsReference) -> Result<(), CaseFailure> {
        self.provisioned.push(reference);
        (self.fail_provision != Some(reference))
            .then_some(())
            .ok_or_else(|| CaseFailure::new(reference.provision_root()))
    }

    fn run_dns_case(&mut self, case: DnsCaseSpec) -> Result<(), CaseFailure> {
        self.attempted.push(case.id);
        Ok(())
    }

    fn finish_dns_cleanup(&mut self) -> Result<(), CaseFailure> {
        self.cleanup_calls += 1;
        Ok(())
    }
}

#[test]
fn dns_matrix_is_unique_and_covers_every_external_path() {
    let ids: BTreeSet<_> = DNS_CASES.iter().map(|case| case.id).collect();
    assert_eq!(ids.len(), DNS_CASES.len());
    assert_eq!(DNS_CASES.len(), 12);
    for transport in [
        DnsUpstreamTransport::Udp,
        DnsUpstreamTransport::Tcp,
        DnsUpstreamTransport::Dot,
        DnsUpstreamTransport::Doh,
    ] {
        for path in [DnsPath::Direct, DnsPath::Detoured] {
            assert!(DNS_CASES.iter().any(|case| {
                case.reference == DnsReference::CoreDns
                    && case.upstream == transport
                    && case.path == path
            }));
        }
    }
    for marker in [
        "udp-direct",
        "tcp-direct",
        "dot-direct",
        "doh-direct",
        "udp-detour",
        "tcp-detour",
        "dot-detour",
        "doh-detour",
        "dig-udp-direct",
        "dig-tcp-direct",
        "dig-udp-detour",
        "dig-tcp-detour",
    ] {
        assert!(ids.iter().any(|id| id.contains(marker)), "missing {marker}");
    }
}

#[test]
fn dns_setup_failures_are_canonical_and_cleanup_still_runs() {
    let setup = DnsSetupAvailability::from_provider_status(Some("0"), Some("0"));
    let mut ops = FakeDnsOps {
        fail_provision: Some(DnsReference::Bind),
        ..FakeDnsOps::default()
    };
    let report = execute_dns_with_setup(setup, &mut ops);

    assert_eq!(ops.provisioned, [DnsReference::CoreDns, DnsReference::Bind]);
    assert_eq!(ops.cleanup_calls, 1);
    assert!(!report.success());
    assert!(report.summary_lines().iter().any(|line| {
        line.contains("dig-udp-direct") && line.ends_with("FAIL canonical_root=provision-bind")
    }));
}

#[test]
fn dns_hosted_report_has_one_exact_completion_contract() {
    let mut context = valid_context();
    context.argument_count = 2;
    assert!(validate_dns_hosted(&context).is_ok());
    let mut ops = FakeDnsOps::default();
    let report = execute_dns_hosted(
        &context,
        DnsSetupAvailability::from_provider_status(Some("0"), Some("0")),
        &mut ops,
    )
    .expect("hosted DNS plan");
    assert!(report.success());
    assert_eq!(ops.attempted, DNS_CASES.map(|case| case.id));
    assert_eq!(
        report.completion_line(&context),
        "qualification transport=dns status=PASS cleanup=PASS \
         sha=0123456789abcdef0123456789abcdef01234567 run_id=123456 run_attempt=1"
    );
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

fn case_ids_for(reference: Reference) -> BTreeSet<&'static str> {
    TCP_CASES
        .iter()
        .chain(UDP_CASES.iter())
        .filter(|case| case.reference == reference)
        .map(|case| case.id)
        .collect()
}

fn assert_attempted_once(
    attempted: &[&'static str],
    expected: impl IntoIterator<Item = &'static str>,
) {
    let actual: BTreeSet<_> = attempted.iter().copied().collect();
    let expected: BTreeSet<_> = expected.into_iter().collect();
    assert_eq!(actual.len(), attempted.len(), "duplicate case execution");
    assert_eq!(actual, expected);
}

fn summary_line_set(
    report: &qualification::QualificationReport,
    transport: Transport,
) -> BTreeSet<String> {
    let lines = report.summary_lines(transport);
    let expected_len = match transport {
        Transport::Tcp => TCP_CASES.len(),
        Transport::Udp => UDP_CASES.len(),
    };
    assert_eq!(lines.len(), expected_len, "unexpected summary row count");
    let unique = BTreeSet::from(lines);
    assert_eq!(unique.len(), expected_len, "duplicate summary row");
    unique
}

fn assert_setup_root(report: &qualification::QualificationReport, failed: Reference, root: &str) {
    for (transport, cases) in [(Transport::Tcp, TCP_CASES), (Transport::Udp, UDP_CASES)] {
        let expected = cases
            .into_iter()
            .map(|case| {
                let suffix = if case.reference == failed {
                    format!("FAIL canonical_root={root}")
                } else {
                    "PASS".to_owned()
                };
                format!(
                    "transport={} case_id={} status={suffix}",
                    transport.label(),
                    case.id
                )
            })
            .collect();
        assert_eq!(summary_line_set(report, transport), expected);
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
fn active_transport_plans_cover_the_method_reference_direction_cartesian_product() {
    use Direction::{FerrumClient as Ferrum, ReferenceClient as Client};
    use Method::{Aes128Gcm as Aes128, Aes256Gcm as Aes256, ChaCha20Poly1305 as ChaCha};
    use Reference::{ShadowsocksRust, SingBox};
    use Transport::{Tcp, Udp};

    let methods = [Aes128, Aes256, ChaCha];
    let references = [SingBox, ShadowsocksRust];
    let directions = [Ferrum, Client];
    let expected_case_count = methods.len() * references.len() * directions.len();

    for (transport, cases) in [(Tcp, TCP_CASES.as_slice()), (Udp, UDP_CASES.as_slice())] {
        assert_eq!(cases.len(), expected_case_count, "incomplete case matrix");
        assert_eq!(
            cases
                .iter()
                .map(|case| case.id)
                .collect::<BTreeSet<_>>()
                .len(),
            cases.len(),
            "duplicate case id"
        );
        assert!(
            cases.iter().all(|case| case.transport == transport),
            "case assigned to the wrong transport"
        );

        for method in methods {
            for reference in references {
                for direction in directions {
                    assert_eq!(
                        cases
                            .iter()
                            .filter(|case| {
                                case.method == method
                                    && case.reference == reference
                                    && case.direction == direction
                            })
                            .count(),
                        1,
                        "missing or duplicate semantic case: {transport:?} {method:?} \
                         {reference:?} {direction:?}"
                    );
                }
            }
        }
    }

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
    assert_attempted_once(&ops.attempted, case_ids_for(Reference::ShadowsocksRust));
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
    assert_attempted_once(&ops.attempted, case_ids_for(Reference::ShadowsocksRust));
    assert_setup_root(&report, Reference::SingBox, "provision-sing-box");
    assert!(!report.success());
}

#[test]
fn one_case_failure_does_not_prevent_other_cases() {
    let mut ops = FakeOps {
        fail_case: Some("M1-INT-001"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_attempted_once(
        &ops.attempted,
        TCP_CASES.into_iter().chain(UDP_CASES).map(|case| case.id),
    );
    assert!(
        summary_line_set(&report, Transport::Tcp).contains(
            "transport=tcp case_id=M1-INT-001 status=FAIL canonical_root=case-M1-INT-001"
        )
    );
    assert_eq!(report.pass_count(Transport::Tcp), 11);
    assert!(report.transport_success(Transport::Udp));
    assert!(!report.success());
}

#[test]
fn case_panic_fails_that_row_and_does_not_prevent_other_cases() {
    let mut ops = FakeOps {
        panic_case: Some("M2-UDP-INT-006"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_attempted_once(
        &ops.attempted,
        TCP_CASES.into_iter().chain(UDP_CASES).map(|case| case.id),
    );
    assert!(summary_line_set(&report, Transport::Udp).contains(
        "transport=udp case_id=M2-UDP-INT-006 status=FAIL \
         canonical_root=case-M2-UDP-INT-006"
    ));
    assert_eq!(report.pass_count(Transport::Udp), 11);
    assert!(!report.success());
}

#[test]
fn active_transport_plans_execute_each_case_once_and_report_dynamic_counts() {
    let mut ops = FakeOps::default();
    let report = execute_with_setup(all_ready(), &mut ops);

    assert!(report.success());
    assert_attempted_once(
        &ops.attempted,
        TCP_CASES.into_iter().chain(UDP_CASES).map(|case| case.id),
    );
    assert!(report.cleanup_success());
    assert_eq!(ops.cleanup_calls, 1);
    let context = HostedContext {
        run_attempt: Some("2"),
        ..valid_context()
    };

    for (transport, cases) in [
        (Transport::Tcp, TCP_CASES.as_slice()),
        (Transport::Udp, UDP_CASES.as_slice()),
    ] {
        assert_eq!(
            summary_line_set(&report, transport),
            cases
                .iter()
                .map(|case| {
                    format!(
                        "transport={} case_id={} status=PASS",
                        transport.label(),
                        case.id
                    )
                })
                .collect()
        );
        let case_count = cases.len();
        assert_eq!(
            report.completion_line(transport, &context),
            format!(
                "qualification transport={} status=PASS cases={case_count}/{case_count} \
                 cleanup=PASS sha=0123456789abcdef0123456789abcdef01234567 run_id=123456 \
                 run_attempt=2",
                transport.label()
            )
        );
    }
}

#[test]
fn cleanup_failure_can_never_produce_success() {
    let mut ops = FakeOps {
        fail_cleanup: true,
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert!(report.transport_success(Transport::Udp));
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
fn tcp_exchange_accepts_only_the_observable_order() {
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

    let bounded = Duration::from_millis(100);
    let affected: BTreeSet<_> = TCP_CASES
        .into_iter()
        .filter(|case| case.reference == Reference::SingBox && case.direction == ReferenceClient)
        .map(|case| case.id)
        .collect();
    assert_eq!(
        affected,
        BTreeSet::from(["M1-INT-003", "M1-INT-007", "M1-INT-011"])
    );
    let mut raw_exchange = TcpExchangeState::default();
    for event in TCP_EXCHANGE_ORDER[..3].iter().copied() {
        raw_exchange.record(event).expect("ordered exchange prefix");
    }
    assert!(raw_exchange.record(E::ApplicationCleanEof).is_err());

    let start_target = |target: TcpTargetGate, result: Result<(), String>, timeout: Duration| {
        thread::spawn(move || target.finish(result, timeout))
    };

    let (target_shutdown, application_gate) = tcp_shutdown_gate();
    let target = start_target(target_shutdown, Ok(()), bounded);
    let mut exchange = TcpExchangeState::default();
    for event in TCP_EXCHANGE_ORDER[..5].iter().copied() {
        exchange.record(event).expect("ordered exchange prefix");
    }
    let acknowledgement = application_gate.wait(bounded).expect("target shutdown");
    assert!(!target.is_finished());
    exchange.record(E::ApplicationCleanEof).expect("clean EOF");
    acknowledgement.send(Ok(())).expect("application ack");
    target.join().unwrap().unwrap();
    assert!(exchange.success());

    let assert_failed = |target_result: Result<(), &str>,
                         acknowledgement: Option<Result<(), &str>>,
                         timeout: Duration,
                         expected: &str| {
        let target_failed = target_result.is_err();
        let (owner, application_gate) = tcp_shutdown_gate();
        let target = start_target(owner, target_result.map_err(str::to_owned), timeout);
        let application = application_gate.wait(bounded);
        assert_eq!(application.is_err(), target_failed);
        if let (Ok(application), Some(result)) = (&application, acknowledgement) {
            let _ = application.send(result.map_err(str::to_owned));
        }
        let error = target.join().unwrap().unwrap_err();
        assert!(error.contains(expected));
    };
    assert_failed(Err("target probe failed"), None, bounded, "target probe");
    assert_failed(Ok(()), Some(Err("app failed")), bounded, "app failed");
    assert_failed(Ok(()), None, Duration::ZERO, "timed out");

    let (target_shutdown, application_gate) = tcp_shutdown_gate();
    drop(application_gate);
    let error = target_shutdown.finish(Ok(()), bounded).unwrap_err();
    assert!(error.contains("closed"));

    let (target_shutdown, application_gate) = tcp_shutdown_gate();
    drop(target_shutdown);
    assert!(application_gate.wait(bounded).is_err());
}
