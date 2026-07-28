#[path = "../src/qualification/mod.rs"]
mod qualification;

use qualification::{
    CaseFailure, CaseSpec, CleanupState, Direction, HostedContext, Method, QualificationOps,
    Reference, SetupAvailability, TCP_CASES, Transport, UDP_CASES, execute_hosted,
    execute_with_setup, validate_hosted,
};

// This table is the explicit disposition for the 15 OS/process/socket helper tests
// removed from libtest discovery. "hosted" means the claim is observed by every
// historical M1 hosted cases; "quality" means the same-SHA local lifecycle gate owns it;
// "discarded-mechanic" means the assertion described an implementation detail
// rather than a release outcome.
const REMOVED_HELPER_CLAIMS: [(&str, &str); 15] = [
    ("sha256_matches_reviewed_known_answer", "hosted:asset-pin"),
    (
        "live_exchange_records_ordered_eof_and_shutdown_operations",
        "hosted:payload-eof-cleanup",
    ),
    (
        "live_target_shutdown_failure_is_not_masked_by_stream_drop",
        "hosted:eof-cleanup",
    ),
    (
        "omitted_application_eof_observation_sends_failure_acknowledgement",
        "hosted:eof-cleanup",
    ),
    (
        "client_extra_byte_prevents_eof_event_and_success_acknowledgement",
        "hosted:eof",
    ),
    (
        "client_read_error_prevents_eof_event_and_success_acknowledgement",
        "hosted:eof",
    ),
    (
        "target_extra_byte_and_read_error_prevent_clean_eof_event",
        "hosted:eof",
    ),
    (
        "target_stream_is_held_until_application_acknowledgement",
        "hosted:eof-cleanup",
    ),
    (
        "missing_application_acknowledgement_times_out_under_case_deadline",
        "hosted:absolute-deadline",
    ),
    (
        "payload_contract_is_fixed_complete_and_distinct",
        "hosted:payload",
    ),
    (
        "clean_eof_rejects_extra_byte_and_accepts_only_zero",
        "hosted:eof",
    ),
    (
        "absolute_deadline_and_nonzero_child_status_are_enforced",
        "hosted:absolute-deadline-cleanup",
    ),
    (
        "absolute_deadline_rejects_drip_progress",
        "hosted:absolute-deadline",
    ),
    (
        "fixed_operation_deadline_rejects_drip_before_longer_case_deadline",
        "hosted:absolute-deadline",
    ),
    (
        "fixed_write_deadline_rejects_partial_progress_before_case_deadline",
        "discarded-mechanic:synthetic-write-shim",
    ),
];

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

fn case_ids_for(reference: Reference) -> Vec<&'static str> {
    TCP_CASES
        .iter()
        .chain(UDP_CASES.iter())
        .filter(|case| case.reference == reference)
        .map(|case| case.id)
        .collect()
}

fn assert_setup_root(
    cases: [CaseSpec; 12],
    lines: [String; 12],
    transport: Transport,
    failed: Reference,
    root: &str,
) {
    for (case, line) in cases.iter().zip(lines) {
        let expected = if case.reference == failed {
            format!(
                "transport={} case_id={} status=FAIL canonical_root={root}",
                transport.label(),
                case.id
            )
        } else {
            format!(
                "transport={} case_id={} status=PASS",
                transport.label(),
                case.id
            )
        };
        assert_eq!(line, expected);
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

    let tuple = |case: CaseSpec| (case.id, case.method, case.reference, case.direction);
    assert!(
        TCP_CASES
            .iter()
            .all(|case| case.transport == Transport::Tcp)
    );
    assert!(
        UDP_CASES
            .iter()
            .all(|case| case.transport == Transport::Udp)
    );
    assert_eq!(
        TCP_CASES.map(tuple),
        [
            ("M1-INT-001", Aes128, SingBox, Ferrum),
            ("M1-INT-002", Aes128, ShadowsocksRust, Ferrum),
            ("M1-INT-003", Aes128, SingBox, Client),
            ("M1-INT-004", Aes128, ShadowsocksRust, Client),
            ("M1-INT-005", Aes256, SingBox, Ferrum),
            ("M1-INT-006", Aes256, ShadowsocksRust, Ferrum),
            ("M1-INT-007", Aes256, SingBox, Client),
            ("M1-INT-008", Aes256, ShadowsocksRust, Client),
            ("M1-INT-009", ChaCha, SingBox, Ferrum),
            ("M1-INT-010", ChaCha, ShadowsocksRust, Ferrum),
            ("M1-INT-011", ChaCha, SingBox, Client),
            ("M1-INT-012", ChaCha, ShadowsocksRust, Client),
        ]
    );
    assert_eq!(
        UDP_CASES.map(tuple),
        [
            ("M2-UDP-INT-001", Aes128, SingBox, Ferrum),
            ("M2-UDP-INT-002", Aes128, ShadowsocksRust, Ferrum),
            ("M2-UDP-INT-003", Aes128, SingBox, Client),
            ("M2-UDP-INT-004", Aes128, ShadowsocksRust, Client),
            ("M2-UDP-INT-005", Aes256, SingBox, Ferrum),
            ("M2-UDP-INT-006", Aes256, ShadowsocksRust, Ferrum),
            ("M2-UDP-INT-007", Aes256, SingBox, Client),
            ("M2-UDP-INT-008", Aes256, ShadowsocksRust, Client),
            ("M2-UDP-INT-009", ChaCha, SingBox, Ferrum),
            ("M2-UDP-INT-010", ChaCha, ShadowsocksRust, Ferrum),
            ("M2-UDP-INT-011", ChaCha, SingBox, Client),
            ("M2-UDP-INT-012", ChaCha, ShadowsocksRust, Client),
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
    let valid = HostedContext {
        argument_count: 1,
        github_actions: Some("true"),
        runner_os: Some("Linux"),
        run_id: Some("123456"),
        run_attempt: Some("1"),
        github_sha: Some("0123456789abcdef0123456789abcdef01234567"),
        head_sha: "0123456789abcdef0123456789abcdef01234567",
        checkout_clean: true,
    };
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
        argument_count: 1,
        github_actions: Some("true"),
        runner_os: Some("Linux"),
        run_id: Some("123456"),
        run_attempt: Some("1"),
        github_sha: Some("0123456789abcdef0123456789abcdef01234567"),
        head_sha: "1123456789abcdef0123456789abcdef01234567",
        checkout_clean: true,
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
    assert_setup_root(
        TCP_CASES,
        report.summary_lines(Transport::Tcp),
        Transport::Tcp,
        Reference::SingBox,
        "provision-sing-box",
    );
    assert_setup_root(
        UDP_CASES,
        report.summary_lines(Transport::Udp),
        Transport::Udp,
        Reference::SingBox,
        "provision-sing-box",
    );
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
    assert_setup_root(
        TCP_CASES,
        report.summary_lines(Transport::Tcp),
        Transport::Tcp,
        Reference::SingBox,
        "provision-sing-box",
    );
    assert_setup_root(
        UDP_CASES,
        report.summary_lines(Transport::Udp),
        Transport::Udp,
        Reference::SingBox,
        "provision-sing-box",
    );
    assert!(!report.success());
}

#[test]
fn one_case_failure_does_not_prevent_later_cases() {
    let mut ops = FakeOps {
        fail_case: Some("M1-INT-001"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_eq!(
        ops.attempted,
        TCP_CASES
            .into_iter()
            .chain(UDP_CASES)
            .map(|case| case.id)
            .collect::<Vec<_>>()
    );
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
        argument_count: 1,
        github_actions: Some("true"),
        runner_os: Some("Linux"),
        run_id: Some("123456"),
        run_attempt: Some("2"),
        github_sha: Some("0123456789abcdef0123456789abcdef01234567"),
        head_sha: "0123456789abcdef0123456789abcdef01234567",
        checkout_clean: true,
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
    child_unreaped.worker_started();
    child_unreaped.worker_joined();
    assert!(!child_unreaped.success());

    let mut capture_unjoined = CleanupState::default();
    capture_unjoined.child_started();
    capture_unjoined.child_reaped();
    capture_unjoined.worker_started();
    assert!(!capture_unjoined.success());

    let mut observed_failure = CleanupState::default();
    observed_failure.child_started();
    observed_failure.child_reaped();
    observed_failure.worker_started();
    observed_failure.worker_joined();
    observed_failure.fail();
    assert!(!observed_failure.success());
}

#[test]
fn removed_helper_claims_have_an_explicit_non_local_disposition() {
    let names: std::collections::BTreeSet<_> = REMOVED_HELPER_CLAIMS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(names.len(), 15);
    assert!(
        REMOVED_HELPER_CLAIMS
            .iter()
            .any(|(_, disposition)| disposition.contains("payload"))
    );
    assert!(
        REMOVED_HELPER_CLAIMS
            .iter()
            .any(|(_, disposition)| disposition.contains("eof"))
    );
    assert!(
        REMOVED_HELPER_CLAIMS
            .iter()
            .any(|(_, disposition)| disposition.contains("absolute-deadline"))
    );
    assert!(
        REMOVED_HELPER_CLAIMS
            .iter()
            .any(|(_, disposition)| disposition.contains("cleanup"))
    );
    assert!(REMOVED_HELPER_CLAIMS.iter().all(
        |(_, disposition)| disposition.starts_with("hosted:")
            || disposition.starts_with("quality:")
            || disposition.starts_with("discarded-mechanic:")
    ));
}
