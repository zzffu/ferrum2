use std::io::Cursor;

use ferrum2_rule::srs::decode_srs;

use crate::match_set::benchmark::{MatchProbe, MatcherKind, match_probe_cases, probe_matches};
use crate::match_set::generated::{build_generated_match_set, compile_generated_match_set};
use crate::match_set::srs::{
    SYNTHETIC_SRS_VERSION, canonical, encode_generated_srs, generated_srs_statistics,
    run_generated_binary_srs,
};
use crate::measurement::allocation::allocator_test_lock;
use crate::measurement::statistics::collect_parity_observations;
use crate::measurement::timing::{MIN_SAMPLE_WINDOW_NANOSECONDS, benchmark, benchmark_pair};

#[test]
fn ordinary_and_synthetic_sources_use_equivalent_compiled_matchers() {
    let _guard = allocator_test_lock();
    for synthetic in [false, true] {
        let (owner, build) = build_generated_match_set(MatcherKind::Mixed, 100, synthetic)
            .expect("generated MatchSet");
        assert!(build.allocations > 0);
        assert!(build.net_retained_bytes > 0);
        let cases = match_probe_cases(MatcherKind::Mixed, 100).expect("probes");
        for case in cases {
            assert_eq!(probe_matches(owner.compiled(), &case.probe), case.expected);
            let measured = benchmark(
                || u64::from(probe_matches(owner.compiled(), &case.probe)),
                5,
                32,
            );
            assert_eq!(measured.samples.len(), 5);
            assert_eq!(measured.allocation_samples.len(), 5);
            assert!(
                measured
                    .sample_batch_nanoseconds
                    .iter()
                    .all(|elapsed| *elapsed >= MIN_SAMPLE_WINDOW_NANOSECONDS)
            );
            assert!(
                measured
                    .allocation_samples
                    .iter()
                    .all(|sample| sample.iterations == 1)
            );
        }
    }
}

#[test]
fn generated_binary_srs_matrix_is_deterministic_and_strictly_decoded() {
    let _guard = allocator_test_lock();
    let scale = 25;
    for kind in MatcherKind::ALL {
        let first = encode_generated_srs(kind, scale).expect("encode generated SRS");
        let second = encode_generated_srs(kind, scale).expect("repeat generated SRS");
        assert_eq!(first, second);
        assert_eq!(&first[..4], b"SRS\x02");

        let decoded = decode_srs(Cursor::new(&first)).expect("strictly decode generated SRS");
        assert_eq!(decoded.version(), SYNTHETIC_SRS_VERSION);
        assert_eq!(decoded.statistics(), generated_srs_statistics(kind, scale));
        let binary = decoded.compile().expect("compile decoded SRS");
        let synthetic = compile_generated_match_set(kind, scale).expect("compile synthetic");
        assert_eq!(binary.entry_counts().total(), scale);
        assert_eq!(synthetic.entry_counts().total(), scale);
        for case in match_probe_cases(kind, scale).expect("generated probes") {
            assert_eq!(probe_matches(&binary, &case.probe), case.expected);
            assert_eq!(probe_matches(&synthetic, &case.probe), case.expected);
        }
    }
}

#[test]
fn generated_binary_srs_rows_are_paired_and_gated() {
    let _guard = allocator_test_lock();
    let mut measurements = Vec::new();
    let evidence = run_generated_binary_srs(&[10], 5, 1, &mut measurements)
        .expect("run generated binary SRS matrix");
    assert_eq!(evidence.len(), MatcherKind::ALL.len());
    assert_eq!(measurements.len(), 28);
    assert!(measurements.iter().all(|row| {
        row.suite == "match_set"
            && row.fixture.is_some()
            && row.compiled_entries == Some(10)
            && row.allocation_gate_applicable
            && row.allocation_gate_passed == Some(true)
            && row.timing_pair_id.is_some()
    }));
    let parity = collect_parity_observations(&measurements).expect("collect SRS parity");
    assert_eq!(parity.len(), 14);
    assert!(parity.iter().all(|row| {
        row.performance_gate_applicable
            && matches!(row.decision, "passed" | "failed")
            && row.baseline_id.contains("/synthetic_srs/")
            && row.candidate_id.contains("/binary_srs/")
    }));
}

#[test]
fn paired_matchers_share_operation_counts_and_alternate_start_order() {
    let _guard = allocator_test_lock();
    let (ordinary, _) =
        build_generated_match_set(MatcherKind::Suffix, 100, false).expect("ordinary set");
    let (synthetic, _) =
        build_generated_match_set(MatcherKind::Suffix, 100, true).expect("synthetic set");
    let probe = MatchProbe::Domain(canonical("x.suffix-99.bench.invalid").expect("probe"));
    let (baseline, candidate) = benchmark_pair(
        ordinary.compiled(),
        synthetic.compiled(),
        &probe,
        5,
        1,
        "unit/paired-order".to_owned(),
    );
    assert_eq!(
        baseline.actual_iterations_per_sample,
        candidate.actual_iterations_per_sample
    );
    assert_eq!(baseline.paired_sample_order, candidate.paired_sample_order);
    let order = baseline.paired_sample_order.expect("paired order");
    assert!(order.windows(2).all(|pair| pair[0] != pair[1]));
    assert!(
        baseline
            .sample_batch_nanoseconds
            .iter()
            .chain(&candidate.sample_batch_nanoseconds)
            .all(|elapsed| *elapsed >= MIN_SAMPLE_WINDOW_NANOSECONDS)
    );
}
