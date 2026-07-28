#[path = "../src/qualification/mod.rs"]
mod qualification;

use qualification::{
    CaseFailure, CaseSpec, HostedContext, QualificationOps, Reference, SetupAvailability,
    execute_hosted, execute_with_setup, validate_hosted,
};

// This table is the explicit disposition for the 15 OS/process/socket helper tests
// removed from libtest discovery. "hosted" means the claim is observed by every
// runnable M0-INT case; "quality" means the same-SHA local lifecycle gate owns it;
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
    provisioned: Vec<Reference>,
    attempted: Vec<&'static str>,
}

fn all_ready() -> SetupAvailability {
    SetupAvailability::from_provider_status(Some("0"), Some("0"))
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
        if self.fail_case == Some(case.id) {
            Err(CaseFailure::new(case.case_root()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn hosted_guard_rejects_every_unqualified_context() {
    let valid = HostedContext {
        argument_count: 1,
        github_actions: Some("true"),
        runner_os: Some("Linux"),
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
    assert_eq!(ops.attempted, ["M0-INT-002", "M0-INT-004"]);
    assert_eq!(
        report.summary_lines(),
        [
            "case_id=M0-INT-001 status=FAIL canonical_root=provision-sing-box",
            "case_id=M0-INT-002 status=PASS",
            "case_id=M0-INT-003 status=FAIL canonical_root=provision-sing-box",
            "case_id=M0-INT-004 status=PASS",
        ]
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
    assert_eq!(ops.attempted, ["M0-INT-002", "M0-INT-004"]);
    assert_eq!(
        report.summary_lines(),
        [
            "case_id=M0-INT-001 status=FAIL canonical_root=provision-sing-box",
            "case_id=M0-INT-002 status=PASS",
            "case_id=M0-INT-003 status=FAIL canonical_root=provision-sing-box",
            "case_id=M0-INT-004 status=PASS",
        ]
    );
    assert!(!report.success());
}

#[test]
fn one_case_failure_does_not_prevent_later_cases() {
    let mut ops = FakeOps {
        fail_case: Some("M0-INT-001"),
        ..FakeOps::default()
    };

    let report = execute_with_setup(all_ready(), &mut ops);

    assert_eq!(
        ops.attempted,
        ["M0-INT-001", "M0-INT-002", "M0-INT-003", "M0-INT-004"]
    );
    assert_eq!(
        report.summary_lines(),
        [
            "case_id=M0-INT-001 status=FAIL canonical_root=case-M0-INT-001",
            "case_id=M0-INT-002 status=PASS",
            "case_id=M0-INT-003 status=PASS",
            "case_id=M0-INT-004 status=PASS",
        ]
    );
    assert!(!report.success());
}

#[test]
fn four_passes_are_required_for_success_and_summary_is_minimal() {
    let mut ops = FakeOps::default();
    let report = execute_with_setup(all_ready(), &mut ops);

    assert!(report.success());
    assert_eq!(
        report.summary_lines(),
        [
            "case_id=M0-INT-001 status=PASS",
            "case_id=M0-INT-002 status=PASS",
            "case_id=M0-INT-003 status=PASS",
            "case_id=M0-INT-004 status=PASS",
        ]
    );
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
